#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy Web 部署引擎：把生成器产物落到路由器
#
# 用法：apply.sh <产物目录>
#
# 产物目录（luci-app-tkproxy 生成，与 tk-standalone/gen.py 同构）：
#   xray.json        Xray 配置              必填
#   tkproxy.nft      nftables 规则          必填
#   manifest.json    SSID ↔ 网段 ↔ 端口     必填（status.sh 也依赖它）
#   wifi.key         必选，WiFi 密码；也可用环境变量 TK_WIFI_KEY
#   dns              可选，DHCP 下发的公网 DNS；也可用环境变量 TK_DNS
#
# 安全约束（Codex 审查后加固）：
#   - 配置目录 / init 路径只允许白名单，且拒绝相对路径、..、符号链接；
#   - 所有生成的 uci 段都带 tkproxy=1 标记，删除前必须校验标记；
#   - 设备/接口名用 brtkNN / tkpNN，断言 <= 15 字节；SSID 按 UTF-8 字节数
#     断言 <= 32；
#   - 容量无法确定时拒绝部署（exit 3），生效后再复核实际 BSS 数；
#   - uci 逐条 set/add_list（不拼 batch 文本），所有输入做白名单校验；
#   - 先备份、再原子替换文件、再改 uci，任一步失败自动回滚；
#   - nft / 端口 / 进程同步校验，失败返回非零，不再吞错；
#   - 策略路由用专属 mark 0x8000/0x8000 + table 51820，绝不 flush 整表。

# 辅助函数（供 diag/selftest 使用，需在 case 语句之前定义）
say() { printf '%s\n' "$*"; }
warn() { printf '%s: 警告：%s\n' "tkproxy-apply" "$*" >&2; }
die() { printf '%s: 错误：%s\n' "tkproxy-apply" "$*" >&2; exit 1; }

# run_with_timeout <秒> <日志文件> <命令...>
# 后台运行命令并轮询超时；超时返回 124，否则返回命令退出码
run_with_timeout() {
	_timeout=$1
	_log=$2
	shift 2
	"$@" >"$_log" 2>&1 &
	_pid=$!
	_i=0
	while kill -0 "$_pid" 2>/dev/null && [ "$_i" -lt "$_timeout" ]; do
		_i=$((_i + 1))
		sleep 1
	done
	if kill -0 "$_pid" 2>/dev/null; then
		kill -9 "$_pid" 2>/dev/null || true
		wait "$_pid" 2>/dev/null || true
		return 124
	else
		wait "$_pid" 2>/dev/null || return $?
		return 0
	fi
}

# 需要 tkp_literal_replace 函数（在 selftest 里调用）
tkp_literal_replace() {
	_f=$1
	_from=$2
	_to=$3
	_out=$4
	[ -n "$_from" ] || die "内部错误：替换源为空"
	if [ "$_from" = "$_to" ]; then
		cp "$_f" "$_out" 2>/dev/null || die "tkp_literal_replace cp $_f -> $_out 失败"
		return 0
	fi
	awk -v from="$_from" -v to="$_to" '
		{
			line = $0; out = ""; flen = length(from)
			while ((i = index(line, from)) > 0) {
				out = out substr(line, 1, i - 1) to
				line = substr(line, i + flen)
			}
			print out line
		}' "$_f" >"$_out"
}

# SEP 和设备名函数（供 selftest 和主流程使用，必须在 case 语句之前定义）
SEP=$(printf '\037')
tkp_ifname() { printf 'tkp%02d' "$1"; }
tkp_brname() { printf 'brtk%02d' "$1"; }

# tkp_generate_nft_rules: 生成隔离、input、forward 规则并注入到 nft 文件
# 参数：
#   $1 = nft 文件路径
#   $2 = 工作目录（用于临时文件）
#   $3 = PLAN 内容（多行，每行格式：idx\037ssid\037slug\037br\037subnet\037gw\037port\037band\037ntype）
# 返回：0=成功 1=失败
tkp_generate_nft_rules() {
	_nft_file=$1
	_work_dir=$2
	_plan_content=$3

	# 构建所有 tkp 桥名列表
	_all_brtkNN=""
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		_brn=$(tkp_brname "$idx")
		_all_brtkNN="$_all_brtkNN $_brn"
	done <<PLANEOF
$_plan_content
PLANEOF

	# 生成 forward 链规则：SSID 间隔离 + IPv6 防泄漏 + fail-closed（顺序严格控制）
	_isolation_rules=$_work_dir/isolation-rules.nft
	: >"$_isolation_rules"

	# ==== 段1：SSID 间隔离（必须在 fail-closed 之前，避免误伤已 accept 的流量）====
	# 逐线路生成同接口隔离规则 iifname "brtkNN" oifname "brtkNN" drop
	for _brn in $_all_brtkNN; do
		cat >>"$_isolation_rules" <<ISOEOF2
		# SSID 间隔离：同接口内互访禁止 ($_brn)
		iifname "$_brn" oifname "$_brn" drop
ISOEOF2
	done

	# 跨线路隔离规则（多 SSID 场景下生成所有桥对的显式规则）
	_br_count=0
	for _brn in $_all_brtkNN; do
		_br_count=$((_br_count + 1))
	done

	if [ "$_br_count" -gt 1 ]; then
		cat >>"$_isolation_rules" <<'ISOEOF3'
		# SSID 间隔离：禁止跨线路转发（不同桥之间）
ISOEOF3
		for _src_br in $_all_brtkNN; do
			for _dst_br in $_all_brtkNN; do
				[ "$_src_br" != "$_dst_br" ] || continue
				cat >>"$_isolation_rules" <<ISOEOF4
		iifname "$_src_br" oifname "$_dst_br" drop
ISOEOF4
			done
		done
	fi

	# ==== 段2：IPv6 防泄漏（forward，必须在 fail-closed 之前）====
	cat >>"$_isolation_rules" <<'ISOEOF5'
		# IPv6 防泄漏（forward）
		iifname "brtk*" meta nfproto ipv6 drop

ISOEOF5

	# ==== 段3：fail-closed 兜底（必须最后，在 tproxy accept 之后）====
	# 注意：gen.lua 生成的 tproxy accept 规则会被注入到 prerouting 链，
	# 而这里的 fail-closed 规则注入到 forward 链，两者不在同一条链路上。
	# forward 链的 fail-closed 需要放在 SSID 间隔离之后，避免误伤已 accept 的转发流量。
	cat >>"$_isolation_rules" <<'FAILCLOSED'
		# ==== 段3：fail-closed 兜底（必须最后）====
		# 1. 放行访问网关必要服务（DHCP 等，目标 10.11.N.1）
		iifname "brtk*" ip daddr 10.11.0.0/16 udp dport { 53, 67, 68 } accept
		iifname "brtk*" ip daddr 10.11.0.0/16 tcp dport { 53 } accept
		# 2. 禁止目标端口 53 且目的地址不在 10.11.0.0/16（防泄漏到公网 DNS）
		iifname "brtk*" ip daddr != 10.11.0.0/16 th dport 53 drop
		# 3. 禁止访问国内管理面 192.168.1.1
		iifname "brtk*" ip daddr 192.168.1.1 drop
		# 4. 禁止访问国内私网段（192.168/172.16/10.非10.11）
		iifname "brtk*" ip daddr { 192.168.0.0/16, 172.16.0.0/12 } drop
		iifname "brtk*" ip daddr 10.0.0.0/8 ip daddr != 10.11.0.0/16 drop
		# 5. 兜底：来自 brtk* 且未被标记的流量全 drop（EOTKPROXY_DROP）
		iifname "brtk*" meta mark != 0x8000 drop comment "EOTKPROXY_DROP"

FAILCLOSED

	# 确保 table inet tkproxy 内有 forward 和 input 链，并插入隔离规则
	# 1. 创建 forward 链（如果不存在）
	if ! grep -q "chain forward {" "$_nft_file"; then
		sed '/^[[:space:]]*table inet tkproxy {/,/^}$/{
			/^}$/i\
\
	chain forward {\
		type filter hook forward priority filter; policy accept;\
	}
		}' "$_nft_file" >"$_nft_file.fwd.$$"
		mv -f "$_nft_file.fwd.$$" "$_nft_file" || { warn "创建 forward 链失败"; return 1; }
	fi

	# 2. 生成 NAT 链规则（DNS redirect）
	_nat_rules=$_work_dir/nat-rules.nft
	: >"$_nat_rules"
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		_brn=$(tkp_brname "$idx")
		_dns_port=$((5300 + idx))
		cat >>"$_nat_rules" <<NATEOF
	# $_brn DNS 重定向到本地 :$_dns_port
	iifname "$_brn" meta l4proto { tcp, udp } th dport 53 redirect to :$_dns_port
NATEOF
	done <<NATPLAN
$_plan_content
NATPLAN

	# 3. 生成 input 链规则（filter 类型，只放 drop/accept）
	_input_rules=$_work_dir/input-rules.nft
	: >"$_input_rules"
	# 收集所有端口列表
	_all_ports=""
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		_all_ports="$_all_ports $port"
	done <<PORTSEOF2
$_plan_content
PORTSEOF2

	# 为每个 bridge 生成 input 规则
	for _src in $_all_brtkNN; do
		_src_gw=""
		_src_dns_port=""
		_src_port=""
		_src_idx=""
		while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
			[ -n "$idx" ] || continue
			_brn=$(tkp_brname "$idx")
			if [ "$_brn" = "$_src" ]; then
				_src_gw=$gw
				_src_dns_port=$((5300 + idx))
				_src_port=$port
				_src_idx=$idx
				break
			fi
		done <<SRCEOF2
$_plan_content
SRCEOF2
		[ -n "$_src_gw" ] || continue
		# 构造其他线路端口列表
		_other_ports=""
		for _p in $_all_ports; do
			[ "$_p" != "$_src_port" ] && _other_ports="$_other_ports, $_p"
		done
		_other_ports=${_other_ports#, }

		# 构造其他线路网关地址列表
		_other_gws=""
		while IFS="$SEP" read -r _oi _os _ol _ob _on _og _op _oba _ont; do
			[ -n "$_oi" ] || continue
			_obrn=$(tkp_brname "$_oi")
			[ "$_obrn" != "$_src" ] && [ -n "$_og" ] && _other_gws="$_other_gws, $_og"
		done <<GWSEOF2
$_plan_content
GWSEOF2
		_other_gws=${_other_gws#, }

		# M3: 空集合保护 —— 单 SSID 场景下 _other_gws / _other_ports 可能为空
		cat >>"$_input_rules" <<INPUTEOF2
	# $_src 隔离规则
	# 1. 放行本线路 tproxy 流量（mark 0x8000 优先）
	iifname "$_src" meta mark 0x8000 accept
INPUTEOF2
		if [ -n "$_other_gws" ]; then
			cat >>"$_input_rules" <<INPUTEOF3
	# 2. 禁止访问其他线路网关地址（阻止跨线路访问）
	iifname "$_src" ip daddr { $_other_gws } drop
INPUTEOF3
		else
			printf '\t# 2. 跳过（无其他线路网关，单 SSID 场景）\n' >>"$_input_rules"
		fi
		if [ -n "$_other_ports" ]; then
			cat >>"$_input_rules" <<INPUTEOF4
	# 3. 按自身网关地址丢弃其他线路 tproxy 端口（避免串线）
	iifname "$_src" ip daddr $_src_gw meta l4proto { tcp, udp } th dport { $_other_ports } drop
INPUTEOF4
		else
			printf '\t# 3. 跳过（无其他线路端口，单 SSID 场景）\n' >>"$_input_rules"
		fi
		cat >>"$_input_rules" <<INPUTEOF5
	# 4. 放行 DHCP（客户端 → 本线路 DHCP 服务器）
	#    DISCOVER/REQUEST 是广播(255.255.255.255:67)，不会命中下面的 ip daddr 规则，
	#    若不在这里放行就会被结尾的兜底 drop 吃掉 → 客户端永远拿不到 IP（连不上）
	iifname "$_src" udp dport 67 accept
	iifname "$_src" udp sport 67 accept
	# 5. 禁止访问其他 DNS（NAT 链已 redirect 本线路 53 → :$_src_dns_port）
	iifname "$_src" meta l4proto { tcp, udp } th dport 53 drop
	# 6. 禁止访问国内 DNS（即使端口非 53）
	iifname "$_src" ip daddr { 223.5.5.5, 114.114.114.114, 119.29.29.29, 180.76.76.76, 1.2.4.8 } drop
	# 7. 放行访问自身网关 $_src_gw
	iifname "$_src" ip daddr $_src_gw accept
	# 8. 兜底 drop 该源桥所有其他流量（禁止访问路由器其他地址）
	iifname "$_src" drop

INPUTEOF5
	done

	# 追加 IPv6 防泄漏规则到 input 链
	cat >>"$_input_rules" <<'IPV6INEOF2'
	# IPv6 防泄漏（input）：来自 brtk* 桥的 v6 入站全 drop
	iifname "brtk*" meta nfproto ipv6 drop

IPV6INEOF2

	# 4. 创建 NAT 链用于 DNS 重定向（type nat hook prerouting priority dstnat）
	if ! grep -q "chain dns_redirect {" "$_nft_file"; then
		sed '/^[[:space:]]*table inet tkproxy {/a\
\
	chain dns_redirect {\
		type nat hook prerouting priority dstnat; policy accept;\
	}\
' "$_nft_file" >"$_nft_file.nat.$$"
		mv -f "$_nft_file.nat.$$" "$_nft_file" || { warn "创建 dns_redirect NAT 链失败"; return 1; }
	fi

	# 5. 创建 input 链（如果不存在）
	if ! grep -q "chain input {" "$_nft_file"; then
		sed '/^[[:space:]]*chain forward {/i\
\
	chain input {\
		type filter hook input priority filter; policy accept;\
	}\
' "$_nft_file" >"$_nft_file.inp.$$"
		mv -f "$_nft_file.inp.$$" "$_nft_file" || { warn "创建 input 链失败"; return 1; }
	fi

	# 6. 注入 NAT 链规则（DNS redirect）
	if [ -s "$_nat_rules" ]; then
		awk -v rules_file="$_nat_rules" '
			/chain dns_redirect \{/ {
				print
				print ""
				print "\t\t# ========== DNS 重定向（由 apply.sh 注入）=========="
				while ((getline line < rules_file) > 0) print line
				close(rules_file)
				print "\t\t# ========== DNS 重定向结束 =========="
				next
			}
			{ print }
		' "$_nft_file" >"$_nft_file.nat.$$"
		mv -f "$_nft_file.nat.$$" "$_nft_file" || { warn "注入 NAT 规则失败"; return 1; }
	fi

	# 7. 注入 input 规则（M3: 规则文件非空时才注入）
	if [ -s "$_input_rules" ]; then
		awk -v rules_file="$_input_rules" '
			/chain input \{/ {
				print
				print ""
				print "\t\t# ========== tkp 网关访问控制（由 apply.sh 注入）=========="
				while ((getline line < rules_file) > 0) print line
				close(rules_file)
				print "\t\t# ========== tkp 网关访问控制结束 =========="
				next
			}
			{ print }
		' "$_nft_file" >"$_nft_file.inp2.$$"
		mv -f "$_nft_file.inp2.$$" "$_nft_file" || { warn "注入 input 规则失败"; return 1; }
	fi

	# 8. 注入 forward 隔离和 IPv6 规则（M3: 规则文件非空时才注入）
	if [ -s "$_isolation_rules" ]; then
		awk -v rules_file="$_isolation_rules" '
			/chain forward \{/ {
				print
				print ""
				print "\t\t# ========== SSID 间隔离 + IPv6 防泄漏（由 apply.sh 注入）=========="
				while ((getline line < rules_file) > 0) print line
				close(rules_file)
				print "\t\t# ========== SSID 间隔离 + IPv6 防泄漏结束 =========="
				next
			}
			{ print }
		' "$_nft_file" >"$_nft_file.iso.$$"
		mv -f "$_nft_file.iso.$$" "$_nft_file" || { warn "注入隔离和 IPv6 规则失败"; return 1; }
	fi

	return 0
}

# 自测/诊断入口（脚本最开始检查，避免触发任何初始化）
# 函数直接内嵌在分支里，避免顺序依赖
case "${1:-}" in
	diag)
		# tkp_diag 内嵌定义
		say "== tkproxy 部署诊断 =="
		say "版本：$(sed -n 's/^Version: //p' /usr/lib/opkg/info/luci-app-tkproxy.control 2>/dev/null)"
		say "系统：$(. /etc/openwrt_release 2>/dev/null; echo "$DISTRIB_ID $DISTRIB_RELEASE") / $(uname -m)"
		command -v fw4 >/dev/null 2>&1 && say "防火墙：fw4" || say "防火墙：fw3/iptables"
		say ""
		say "-- fw4 check --"
		if command -v fw4 >/dev/null 2>&1; then
			# set -e 安全写法：fw4 check 失败时命令替换整体返回非零，
			# 不能让 set -e 在这里直接杀掉 diag（t_3dfd2e0c）
			_rc=0
			_out=$(fw4 check 2>&1) || _rc=$?
			printf '%s\n' "$_out" | sed 's/^/    /'
			say "    退出码 $_rc（0=正常，非 0 就是本机防火墙有问题）"
		else
			say "    无 fw4"
		fi
		say ""
		say "-- 遗留段（passwall / shadowsocksr / 其它带 reload 选项的）--"
		uci show firewall 2>/dev/null | grep -E '(passwall|shadowsocksr|ssr|clash|bypass)' | head -n 20 | sed 's/^/    /' || say "    无"
		say ""
		say "-- 本插件写入的段 --"
		for _t in network dhcp firewall; do
			_n=$(uci show "$_t" 2>/dev/null | grep -c "=.*'tkp" || true)
			_m=$(uci show "$_t" 2>/dev/null | grep -cE "\.tkproxy='1'" || true)
			say "    $_t：名字含 tkp 的段 ${_n:-0}，带 tkproxy 标记 ${_m:-0}"
		done
		say ""
		say "-- 我方接口/桥是否存在 --"
		for _d in $(uci show network 2>/dev/null | sed -n "s/^network\.\(tkp[0-9]*\)=interface/\1/p" | head -n 8); do
			_br=$(uci -q get "network.$_d.device")
			if [ -n "$_br" ] && [ -d "/sys/class/net/$_br" ]; then
				say "    $_d -> $_br 存在"
			else
				say "    $_d -> ${_br:-?} 缺失（桥还没建起来，firewall reload 会报错）"
			fi
		done
		say ""
		say "-- 上次部署日志尾部 --"
		tail -n 15 /tmp/tkproxy/web/deploy.log 2>/dev/null | sed 's/^/    /' || say "    无日志"
		exit 0
		;;
	selftest)
		# tkp_selftest 内嵌定义（由于太长，拆分为多次 cat heredoc）
		say "== tkproxy apply.sh 自测 =="

		# 检查 nft 是否可用
		if ! command -v nft >/dev/null 2>&1; then
			say "[SKIP] 缺少 nft 命令，无法自测"
			exit 1
		fi

		# 构造最小 nft 输入（含 table / prerouting / forward 链，模拟 gen 产物）
		_test_work=/tmp/tkproxy-selftest.$$
		mkdir -p "$_test_work" || die "创建自测工作目录失败"
		_test_nft=$_test_work/tkproxy.nft
		cat >"$_test_nft" <<'TESTNFT'
table inet tkproxy {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		# Test line -> 127.0.0.1:10801 (br-test)
		iifname "br-test" meta nfproto ipv4 meta l4proto { tcp, udp } tproxy ip to :10801 meta mark set 0x1 accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
TESTNFT

		# 用 apply.sh 同一段逻辑生成完整 nft 文件
		say "  构造最小输入 → 应用 apply.sh 的改写/注入逻辑"

		# 1. 改写桥名 br-test → brtk00
		_brn=brtk00
		tkp_literal_replace "$_test_nft" "iifname \"br-test\"" "iifname \"$_brn\"" "$_test_nft.tmp"
		mv -f "$_test_nft.tmp" "$_test_nft" || die "改写桥名失败"

		# 2. 改写 mark 0x1 → 0x8000
		tkp_literal_replace "$_test_nft" 'meta mark set 0x1 ' 'meta mark set 0x8000 ' "$_test_nft.tmp"
		mv -f "$_test_nft.tmp" "$_test_nft" || die "改写 mark 失败"

		# 3. M11c: 已移除旧 DNS 劫持注入步骤（新设计使用 127.0.0.1:53NN dokodemo 入站 + nft input tproxy）

		# 4. 构造单 SSID 场景的 PLAN（用 \037 分隔字段）
		_test_plan=$(printf '0\037Test\037test\037br-test\03710.99.0.0/24\03710.99.0.1\03710801\037both\037vless')

		# 5. 调用提取的规则生成函数（覆盖主流程的空集合保护分支）
		say "  调用 tkp_generate_nft_rules（单 SSID 输入，覆盖空集合分支）"
		if ! tkp_generate_nft_rules "$_test_nft" "$_test_work" "$_test_plan"; then
			rm -rf "$_test_work"
			say "[FAIL] tkp_generate_nft_rules 调用失败"
			exit 1
		fi

		# 6. 执行 nft -c 语法检查
		say "  执行 nft -c -f $_test_nft"
		if ! _nftchk=$(nft -c -f "$_test_nft" 2>&1); then
			warn "nft -c 输出：$_nftchk"
			warn "  文件：$_test_nft（行数 $(wc -l <"$_test_nft" 2>/dev/null | tr -d ' ')，字节 $(wc -c <"$_test_nft" 2>/dev/null | tr -d ' ')）"
			warn "  ===== $_test_nft 前 40 行（带行号） ====="
			sed -n '1,40p' "$_test_nft" 2>/dev/null | cat -n | while IFS= read -r _dl; do warn "    $_dl"; done
			warn "  ===== 前 40 行结束 ====="
			rm -rf "$_test_work"
			say "[FAIL] nft 语法检查未通过"
			exit 1
		fi

		say "  [PASS] nft 语法检查通过"
		say "  生成的完整 nft 文件行数：$(wc -l <"$_test_nft" | tr -d ' ')"

		# 清理
		rm -rf "$_test_work"
		say "== 自测通过 =="
		exit 0
		;;
esac

set -e

PROG=tkproxy-apply
# 当前步骤名（供 trap 打印失败定位）
TKP_STEP="初始化"
STATUS_FILE=/tmp/tkproxy/web/status.json

# ---- 部署互斥锁：同一时刻只允许一个 apply 在跑（防止连点两次互相踩） ----
TKP_LOCK=/tmp/tkproxy/web/deploy.lock
TKP_LOCK_PID=/tmp/tkproxy/web/deploy.lock.pid
USE_FLOCK=0
WORK=""
ROLLBACK_ARMED=0

warn() { printf '%s: 警告：%s\n' "$PROG" "$*" >&2; }
die() { printf '%s: 错误：%s\n' "$PROG" "$*" >&2; exit 1; }
die_code() { _c=$1; shift; printf '%s: 错误：%s\n' "$PROG" "$*" >&2; exit "$_c"; }
say() { printf '%s\n' "$*"; }

# step_run <步骤名> <命令...>
# 执行前打印 [step <名称>]，设置 TKP_STEP；
# 失败时打印：失败命令行、输出末 10 行、/overlay 空间、目标路径 ls -ld，然后 die。
# M1: 禁用命令替换，改用临时文件 + 后台 + 超时保护（防止 init 调用管道死锁）
step_run() {
	_sr_name=$1; shift
	TKP_STEP=$_sr_name
	say "[step $_sr_name]"
	mkdir -p /tmp/tkproxy 2>/dev/null || true
	_sr_log=/tmp/tkproxy/step_run.$$.log
	"$@" >"$_sr_log" 2>&1 &
	_sr_pid=$!
	_sr_i=0
	while kill -0 "$_sr_pid" 2>/dev/null && [ "$_sr_i" -lt 45 ]; do
		_sr_i=$((_sr_i + 1))
		sleep 1
	done
	if kill -0 "$_sr_pid" 2>/dev/null; then
		kill -9 "$_sr_pid" 2>/dev/null || true
		warn "step_run 超过 45s 未返回，已强制终止"
		warn "失败命令：$*"
		printf '%s\n' "$(tail -20 "$_sr_log" 2>/dev/null)" | sed 's/^/    /' >&2
		rm -f "$_sr_log"
		die "步骤 [$_sr_name] 超时"
	fi
	if wait "$_sr_pid" 2>/dev/null; then
		_sr_rc=0
	else
		_sr_rc=$?
	fi
	if [ "$_sr_rc" = "0" ]; then
		[ -s "$_sr_log" ] && sed 's/^/    /' "$_sr_log"
		rm -f "$_sr_log"
		return 0
	fi
	warn "失败命令：$*"
	warn "退出码：$_sr_rc"
	printf '%s\n' "$(tail -10 "$_sr_log" 2>/dev/null)" | sed 's/^/    /' >&2
	warn "/overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	warn "目标路径：$(ls -ld "${1:-/}" 2>&1)"
	rm -f "$_sr_log"
	die "步骤 [$_sr_name] 失败"
}

# 运行状态管理：写入 status.json 的 state 字段
tkp_set_state() {
	_state=$1
	mkdir -p "$(dirname "$STATUS_FILE")" 2>/dev/null || return 1
	printf '{"state":"%s","updated":%d}\n' "$_state" "$(date +%s)" > "$STATUS_FILE.tmp" && \
		mv -f "$STATUS_FILE.tmp" "$STATUS_FILE" 2>/dev/null || return 1
}

tkp_on_exit() {
	_rc=$?
	trap - EXIT INT TERM HUP
	if [ "$_rc" -ne 0 ]; then
		[ -n "$TKP_STEP" ] && printf '%s: 失败步骤：%s\n' "$PROG" "$TKP_STEP" >&2
		[ "$ROLLBACK_ARMED" = "1" ] && tkp_rollback || true
		if ! tkp_set_state "idle" 2>/dev/null; then
			warn "退出时写入 idle 状态失败"
		fi
	else
		if ! tkp_set_state "idle" 2>/dev/null; then
			warn "退出时写入 idle 状态失败"
		fi
	fi
	# 清理锁和 PID 文件
	if [ "$USE_FLOCK" = "1" ]; then
		exec 9>&- 2>/dev/null || true
	fi
	rm -f "$TKP_LOCK_PID" 2>/dev/null || true
	[ -n "$WORK" ] && rm -rf "$WORK"
	exit "$_rc"
}
trap 'tkp_on_exit' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

say "  mkdir -p /var/lock"
if ! mkdir -p /var/lock 2>/dev/null; then
	warn "mkdir -p /var/lock 失败"
	warn "  目标路径：/var/lock"
	warn "  ls -l：$(ls -ld /var/lock 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建 /var/lock 失败"
fi

# 关锁 fd 派生长生命周期进程（xray / init start / dnsmasq）
# 这些进程若继承锁 fd 9，会把 deploy.lock 一直占着，导致下一次部署被
# flock 误判「已有部署正在执行」（t_3dfd2e0c 缺陷 1 根因）。
# 【重要】必须在每个调用点内联 (exec 9>&- …; exec …) &，不能包装成 shell 函数：
# busybox ash 下「函数内的 ()」配合 & 会多 fork 一层不 exec 的副本进程，
# 副本 wait 内层（= xray），部署脚本退出后副本仍持锁不退（真机复现确诊）。
# tkp_drop_lock_exec() { if [ "$USE_FLOCK" = "1" ]; then (exec 9>&- 2>/dev/null; exec "$@"); else "$@"; fi }
if [ -z "$TKP_NO_LOCK" ]; then
	if command -v flock >/dev/null 2>&1; then
		USE_FLOCK=1
		mkdir -p "$(dirname "$TKP_LOCK")" 2>/dev/null || true
		eval "exec 9>\"$TKP_LOCK\""
		if ! flock -n 9; then
			# t_3dfd2e0c 缺陷 1：锁 fd（fd 9）会被 xray 等后台进程继承，
			# 部署结束后锁仍被持有 → 后续部署永远被误判「已有部署正在执行」。
			# 自愈：/proc 里没有真正在跑的 apply.sh / clean.sh（排除自己 $$ 和父进程
			# $PPID，避免误判）就说明锁是历史泄漏，重建锁文件强制接管。
			if ! ls /proc/*/cmdline >/dev/null 2>&1; then
				printf '%s: 已有部署正在执行，本次跳过（等它跑完再点）\n' "${0##*/}" >&2
				TKP_STEP=""
				exit 4
			fi
			_leak=1
			for _fd in /proc/[0-9]*/cmdline; do
				_lpid=${_fd#/proc/}; _lpid=${_lpid%/cmdline}
				case "$_lpid" in
					"$$"|"$PPID") continue ;;   # 排除自己和父进程（cmdline 带脚本名会自匹配）
				esac
				[ -r "$_fd" ] || continue   # 进程可能恰好退出，避免重定向报错噪声
				_lcmd=$(tr '\0' ' ' <"$_fd" 2>/dev/null || true)
				case "$_lcmd" in
					*apply.sh*|*clean.sh*) _leak=0; break ;;
				esac
			done
			if [ "$_leak" = "0" ]; then
				printf '%s: 已有部署正在执行，本次跳过（等它跑完再点）\n' "${0##*/}" >&2
				TKP_STEP=""
				exit 4
			fi
			warn "deploy.lock 被残留进程持有（历史泄漏，无 apply.sh/clean.sh 在跑），重建锁文件接管"
			rm -f "$TKP_LOCK"
			eval "exec 9>\"$TKP_LOCK\""
			if ! flock -n 9; then
				printf '%s: 已有部署正在执行，本次跳过（等它跑完再点）\n' "${0##*/}" >&2
				TKP_STEP=""
				exit 4
			fi
		fi
		echo $$ > "$TKP_LOCK_PID"
	else
		if [ -e "$TKP_LOCK_PID" ] && kill -0 "$(cat "$TKP_LOCK_PID" 2>/dev/null)" 2>/dev/null; then
			printf '%s: 已有部署正在执行（pid %s）\n' "${0##*/}" "$(cat "$TKP_LOCK_PID")" >&2
			TKP_STEP=""
			exit 4
		fi
		echo $$ > "$TKP_LOCK_PID"
	fi
fi

# 部署入口尽早写入 running 状态（EXIT trap 统一写回 idle）
say "  写入运行状态 running（入口）"
if ! tkp_set_state "running"; then
	warn "动作：写入运行状态 running"
	warn "  目标路径：$STATUS_FILE"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "无法写入运行状态"
fi

# nft 规则文件路径（主流程与生成的 init 脚本共用；原先只在 heredoc 里定义导致主流程为空串）
NFT_FILE=${TKP_NFT:-/etc/tkproxy/tkproxy.nft}
CONF_DIR=${TKP_CONF_DIR:-/etc/tkproxy}
INIT_FILE=${TKP_INIT:-/etc/init.d/tkproxy}
XRAY=${TKP_XRAY:-$(command -v xray 2>/dev/null || echo /usr/bin/xray)}
PHY_DIR=${TKP_PHY_DIR:-/sys/class/ieee80211}
SEP=$(printf '\037')
DEFAULT_KEY=tk-2026-wifi
DEFAULT_DNS=1.1.1.1,8.8.8.8
MARK=0x8000/0x8000
RT_TABLE=51820
TKP_WIFI_WAIT_MAX=${TKP_WIFI_WAIT_MAX:-120}

ONLY_IDX=""
if [ "${1:-}" = "--only" ]; then
	ONLY_IDX="${2:-}"
	case "$ONLY_IDX" in
		''|*[!0-9]*)
			# 此时锁尚未获取，禁用 EXIT trap：避免误打「失败步骤：初始化」
			# 以及 trap 里 rm $TKP_LOCK_PID 误删真正持锁进程的 PID 文件
			trap - EXIT INT TERM HUP
			echo "tkproxy-apply: 错误：--only 需要一个线路序号（正整数），实际：'${ONLY_IDX:-<空>}'" >&2
			exit 2
			;;
	esac
	shift 2
fi
D=${1:-}

# 自测/诊断入口（需在所有初始化之前，避免触发 trap/lock/mkdir）
case "$D" in
	diag) tkp_diag; exit 0 ;;
	selftest) tkp_selftest; exit $? ;;
esac

usage() {
	cat <<'USAGE'
apply.sh <产物目录>

产物目录至少包含 xray.json、tkproxy.nft、manifest.json。
可选：dns（tkproxy.init 会被忽略，始终写入内置安全版本）。
必选：wifi.key（WiFi 密码，缺失会导致部署失败）。

环境变量：
  TK_WIFI_KEY     WiFi 密码（优先从环境变量读取，次选 <产物目录>/wifi.key，无则 die）
  TK_DNS          DHCP 下发的公网 DNS（默认读 <产物目录>/dns，再缺省 1.1.1.1,8.8.8.8）
  TK_RADIO_2G     指定 2.4G 射频段名（默认自动探测）
  TK_RADIO_5G     指定 5G 射频段名（默认自动探测）
  TKP_CONF_DIR    仅测试用，只允许 /etc/tkproxy 或 /tmp/tkproxy*
  TKP_INIT        仅测试用，只允许 /etc/init.d/tkproxy 或 /tmp/tkproxy*
USAGE
}

case "$D" in
	-h|--help|help) usage; exit 0 ;;
	"") usage >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# 路径白名单：拒绝相对路径、..、控制字符、符号链接
# 结果放在 TKP_NORM（不用命令替换，保证 exit 能退出主脚本）
# ---------------------------------------------------------------------------
TKP_NORM=""
tkp_reject_path() {
	printf '%s: 拒绝执行：%s\n' "$PROG" "$*" >&2
	exit 2
}

tkp_check_path() {
	_var=$1
	_p=$2
	case "$_p" in
		/*) ;;
		*) tkp_reject_path "$_var 必须是绝对路径，实际值：$_p" ;;
	esac
	case "$_p" in
		*[[:cntrl:]]*|*' '*) tkp_reject_path "$_var 含控制字符或空格，实际值：$_p" ;;
	esac
	case "$_p" in
		*"/../"*|*/..|*"/./"*|*/.|*"//"*) tkp_reject_path "$_var 含 . / .. 或重复斜杠，实际值：$_p" ;;
	esac
	while [ "${_p%/}" != "$_p" ]; do _p=${_p%/}; done
	_t=$_p
	while [ -n "$_t" ] && [ "$_t" != "/" ]; do
		[ -L "$_t" ] && tkp_reject_path "$_var 是符号链接（或路径中含符号链接），实际值：$_p"
		_t=${_t%/*}
		[ -n "$_t" ] || _t=/
	done
	case "$_var" in
		CONF_DIR)
			case "$_p" in
				/etc/tkproxy|/tmp/tkproxy*) ;;
				*) tkp_reject_path "CONF_DIR 只允许 /etc/tkproxy 或 /tmp/tkproxy*，实际值：$_p" ;;
			esac
			;;
		INIT_FILE)
			case "$_p" in
				/etc/init.d/tkproxy|/tmp/tkproxy*) ;;
				*) tkp_reject_path "INIT_FILE 只允许 /etc/init.d/tkproxy 或 /tmp/tkproxy*，实际值：$_p" ;;
			esac
			;;
	esac
	TKP_NORM=$_p
}

tkp_check_path CONF_DIR "$CONF_DIR"
CONF_DIR=$TKP_NORM
tkp_check_path INIT_FILE "$INIT_FILE"
INIT_FILE=$TKP_NORM

# 测试目录必须成对出现，避免 TKP_CONF_DIR=/tmp/... 时误删真实 init
case "$CONF_DIR" in
	/tmp/*)
		case "$INIT_FILE" in
			/tmp/tkproxy*) ;;
			*) tkp_reject_path "CONF_DIR 在 /tmp 时 INIT_FILE 也必须在 /tmp/tkproxy*，实际值：$INIT_FILE" ;;
		esac
		;;
esac

TKP_STEP="检查工具与产物"
say "[step $TKP_STEP]"
for tool in uci awk sed cp chmod mkdir mv rm wc tr grep nft; do
	command -v "$tool" >/dev/null 2>&1 || die "缺少命令：$tool"
done

[ -d "$D" ] || die "产物目录不存在：$D"
D=$(cd "$D" && pwd)
[ -f "$D/xray.json" ] || die "产物目录缺少 xray.json：$D"
[ -f "$D/tkproxy.nft" ] || die "产物目录缺少 tkproxy.nft：$D"
[ -f "$D/manifest.json" ] || die "产物目录缺少 manifest.json（Web 生成时必须一并写入）"

TKP_STEP="创建工作目录"
say "[step $TKP_STEP]"
WORK=${TMPDIR:-/tmp}/tkproxy-apply.$$
PERSISTENT_BACKUP_BASE=/root/tkproxy-backup   # 必须在 CONF_DIR 之外：放在 /etc/tkproxy 内会递归自我复制导致备份失败
BACKUP_DIR=$PERSISTENT_BACKUP_BASE/$(date +%Y%m%d-%H%M%S)
say "  mkdir -p $WORK"
if ! mkdir -p "$WORK" 2>/dev/null; then
	warn "mkdir 失败"
	warn "  动作：创建临时工作目录"
	warn "  目标路径：$WORK"
	warn "  ls -l：$(ls -ld "$(dirname "$WORK")" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建临时目录失败：$WORK"
fi
say "  mkdir -p $BACKUP_DIR"
if ! mkdir -p "$BACKUP_DIR" 2>/dev/null; then
	warn "mkdir 失败"
	warn "  动作：创建持久备份目录"
	warn "  目标路径：$BACKUP_DIR"
	warn "  父目录 ls -l：$(ls -ld "$PERSISTENT_BACKUP_BASE" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建持久备份目录失败：$BACKUP_DIR"
fi
echo "deploy_start=$(date -Iseconds)" >"$BACKUP_DIR/.txn.log"
ls -1dt "$PERSISTENT_BACKUP_BASE"/*/ 2>/dev/null | tail -n +6 | while IFS= read -r _d; do rm -rf "$_d" 2>/dev/null; done

# ---------------------------------------------------------------------------
# 回滚：恢复 uci 备份、文件备份，然后重启旧服务
# 只由 EXIT trap 在失败时调用；自身绝不 die
# ---------------------------------------------------------------------------
tkp_restore_pkg() {
	_p=$1
	if [ -s "$BACKUP_DIR/uci.$_p" ]; then
		if uci import "$_p" <"$BACKUP_DIR/uci.$_p" >/dev/null 2>&1; then
			uci commit "$_p" >/dev/null 2>&1 || warn "回滚时提交 uci $_p 失败"
			return 0
		fi
	fi
	if [ -s "$BACKUP_DIR/raw.$_p" ]; then
		warn "  回滚 cp $BACKUP_DIR/raw.$_p -> /etc/config/$_p.tkp.$$"
		if cp "$BACKUP_DIR/raw.$_p" "/etc/config/$_p.tkp.$$" 2>/dev/null; then
			warn "  回滚 mv /etc/config/$_p.tkp.$$ -> /etc/config/$_p"
			if mv -f "/etc/config/$_p.tkp.$$" "/etc/config/$_p" 2>/dev/null; then
				return 0
			fi
			warn "  mv 失败：目标路径 /etc/config/$_p"
			warn "  ls -l：$(ls -l "/etc/config/$_p.tkp.$$" "/etc/config/$_p" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		else
			warn "  cp 失败：目标路径 /etc/config/$_p.tkp.$$"
			warn "  ls -l：$(ls -l "$BACKUP_DIR/raw.$_p" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		fi
	fi
	warn "恢复 uci $_p 失败，请人工检查 /etc/config/$_p"
	return 1
}

tkp_rollback() {
	[ "$ROLLBACK_ARMED" = "1" ] || return 0
	ROLLBACK_ARMED=0
	warn "部署失败，开始自动回滚……"
	if [ -x "$INIT_FILE" ]; then
		# stop 带 20s 超时
		"$INIT_FILE" stop >/tmp/tkproxy/init.log 2>&1 &
		_p=$!; _i=0
		while kill -0 "$_p" 2>/dev/null && [ "$_i" -lt 20 ]; do _i=$((_i+1)); sleep 1; done
		if kill -0 "$_p" 2>/dev/null; then
			kill -9 "$_p" 2>/dev/null || true
			warn "回滚 stop 超时（20s）"
			tail -20 /tmp/tkproxy/init.log 2>/dev/null | sed 's/^/    /' >&2
		fi
	fi
	for _p in network dhcp firewall wireless; do
		tkp_restore_pkg "$_p" || true
	done
	if [ -d "$BACKUP_DIR/conf" ]; then
		rm -rf "$CONF_DIR" 2>/dev/null || true
		warn "  回滚 cp -R $BACKUP_DIR/conf -> $CONF_DIR"
		if ! cp -R "$BACKUP_DIR/conf" "$CONF_DIR" 2>/dev/null; then
			warn "  cp -R 失败：目标路径 $CONF_DIR"
			warn "  ls -l：$(ls -ld "$BACKUP_DIR/conf" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
			warn "恢复 $CONF_DIR 失败"
		fi
	else
		rm -rf "$CONF_DIR" 2>/dev/null || true
	fi
	if [ -f "$BACKUP_DIR/init" ]; then
		warn "  回滚 cp $BACKUP_DIR/init -> $INIT_FILE"
		if ! cp "$BACKUP_DIR/init" "$INIT_FILE" 2>/dev/null; then
			warn "  cp 失败：目标路径 $INIT_FILE"
			warn "  ls -l：$(ls -l "$BACKUP_DIR/init" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
			warn "恢复 $INIT_FILE 失败"
		fi
		chmod 0755 "$INIT_FILE" 2>/dev/null || true
	else
		rm -f "$INIT_FILE" 2>/dev/null || true
	fi
	[ -x /etc/init.d/network ] && /etc/init.d/network reload >/dev/null 2>&1 || true
	if command -v wifi >/dev/null 2>&1; then
		wifi reload >/dev/null 2>&1 || true
	elif [ -x /sbin/wifi ]; then
		/sbin/wifi reload >/dev/null 2>&1 || true
	fi
	[ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
	[ -x /etc/init.d/firewall ] && /etc/init.d/firewall reload >/dev/null 2>&1 || true
	if [ -x "$INIT_FILE" ]; then
		# t_3dfd2e0c 缺陷 1：init start 会拉起 xray，必须先关锁 fd（内联 ()，理由见上）
		if [ "$USE_FLOCK" = "1" ]; then
			(exec 9>&- 2>/dev/null; exec "$INIT_FILE" start) >/tmp/tkproxy/init.log 2>&1 &
		else
			"$INIT_FILE" start >/tmp/tkproxy/init.log 2>&1 &
		fi
		_p=$!; _i=0
		while kill -0 "$_p" 2>/dev/null && [ "$_i" -lt 45 ]; do _i=$((_i+1)); sleep 1; done
		if kill -0 "$_p" 2>/dev/null; then
			kill -9 "$_p"
			warn "回滚 start 超时"
			tail -20 /tmp/tkproxy/init.log 2>/dev/null | sed 's/^/    /' >&2
		else
			if ! wait "$_p" 2>/dev/null; then
				warn "回滚后旧 tkproxy 服务未能启动"
				tail -10 /tmp/tkproxy/init.log 2>/dev/null | sed 's/^/    /' >&2
			fi
		fi
	fi
	warn "回滚完成；已恢复部署前的 uci 与文件"
}

# ---------------------------------------------------------------- 防火墙兼容
# 部署前体检：本机原有防火墙若已坏（passwall/shadowsocksr 等遗留段），
# fw4 会直接失败。这时必须「先不动配置、直接报清楚」，而不是装完再回滚。
# 自动修复：只清理第三方（passwall/passwall2/shadowsocksr/clash）遗留段里
# fw4 不认的东西 —— reload 选项、指向不存在文件的 include 段。绝不碰系统自身规则。
tkp_firewall_autofix() {
	local secs sec typ path fixed=0 backup_file
	backup_file="/tmp/tkproxy-fw-backup.$$.uci"

	# 备份当前 firewall 配置
	uci export firewall >"$backup_file" 2>/dev/null || {
		warn "备份 firewall 配置失败，跳过自动修复"
		rm -f "$backup_file"
		return 1
	}

	secs=$(uci show firewall 2>/dev/null | sed -n 's/^firewall\.\([^.=]*\)=.*/\1/p' | sort -u)
	for sec in $secs; do
		case "$sec" in
			passwall*|passwall2*|shadowsocksr*|ssr*|clash*|openclash*|ssrplus*|bypass*) ;;
			*) continue ;;
		esac
		if uci -q get "firewall.$sec.reload" >/dev/null 2>&1; then
			if ! uci delete "firewall.$sec.reload" 2>/dev/null; then
				warn "删除 firewall.$sec.reload 失败，恢复备份"
				uci import firewall <"$backup_file" 2>/dev/null || die "恢复 firewall 备份失败"
				rm -f "$backup_file"
				return 1
			fi
			warn "自动修复：删除 firewall.$sec.reload（fw4 不支持该选项）"
			fixed=1
		fi
		typ=$(uci -q get "firewall.$sec" 2>/dev/null)
		if [ "$typ" = "include" ]; then
			path=$(uci -q get "firewall.$sec.path" 2>/dev/null)
			case "$path" in
				/*)
					if [ ! -e "$path" ]; then
						if ! uci delete "firewall.$sec" 2>/dev/null; then
							warn "删除 firewall.$sec 失败，恢复备份"
							uci import firewall <"$backup_file" 2>/dev/null || die "恢复 firewall 备份失败"
							rm -f "$backup_file"
							return 1
						fi
						warn "自动修复：删除 firewall.$sec（include 文件不存在：$path）"
						fixed=1
					fi
					;;
			esac
		fi
	done
	if [ "$fixed" = "1" ]; then
		if ! uci commit firewall 2>/dev/null; then
			warn "提交 firewall 修改失败，恢复备份"
			uci import firewall <"$backup_file" 2>/dev/null || die "恢复 firewall 备份失败"
			rm -f "$backup_file"
			return 1
		fi
		rm -f "$backup_file"
		say "  已自动清理第三方遗留防火墙段（passwall/passwall2/shadowsocksr/openclash 等）"
		return 0
	fi
	# 无需清理（幂等成功）
	rm -f "$backup_file"
	return 2
}

tkp_firewall_precheck() {
	command -v fw4 >/dev/null 2>&1 || return 0   # fw3/iptables 老系统跳过
	local out rc bad _rc
	# set -e 安全写法：`out=$(cmd); rc=$?` 在 cmd 失败时会被 set -e 直接杀掉脚本，
	# 日志只剩「失败步骤」却没有任何错误行（t_3dfd2e0c 缺陷 2 根因）
	rc=0
	out=$(fw4 check 2>&1) || rc=$?
	[ "$rc" = "0" ] && return 0
	# 只挑真正的错误行，避免把 [!] 告警当失败
	bad=$(printf '%s\n' "$out" | grep -viE '^\[!\]' | grep -iE 'error|fail|invalid|unexpected|not found' | head -n 5)
	# 先尝试自动修复（第三方遗留段），再复查一次（安全捕获三态）
	warn "本机防火墙自检未通过（fw4 check 退出码 $rc），尝试自动修复第三方遗留段……"
	_rc=0
	tkp_firewall_autofix >/dev/null 2>&1 || _rc=$?
	case "$_rc" in
		0|2)
			# 0=有改动成功、2=无需清理，都继续
			rc=0
			out=$(fw4 check 2>&1) || rc=$?
			if [ "$rc" = "0" ]; then
				say "  自动修复后防火墙自检通过，继续部署"
				return 0
			fi
			;;
		*)
			# 1=失败，中止部署
			warn "自动修复失败（rc=$_rc），拒绝部署"
			die "防火墙遗留段清理失败，已中止部署"
			;;
	esac
	warn "自动修复后仍不通过，拒绝部署（防止隔离规则无法生效）"
	printf '%s\n' "$out" | sed 's/^/    /' >&2
	[ -n "$bad" ] && printf '    关键错误：%s\n' "$bad" >&2
	cat >&2 <<'EOF'
    常见原因与修法：
      1) passwall / passwall2 / shadowsocksr 遗留段带 fw3 的选项：
           uci -q delete firewall.passwall.reload
           uci -q delete firewall.passwall_server.reload
           uci -q delete firewall.passwall2.reload
           uci -q delete firewall.passwall2_server.reload
           uci -q delete firewall.shadowsocksr
           uci commit firewall && fw4 check
      2) 段里 include 指向不存在的文件：删掉那个段或修路径
      3) 修到 fw4 check 返回 0 后，再回页面点「保存并部署」
EOF
	die "防火墙预检失败，已中止部署"
}

# firewall reload：失败时 autofix → 无条件重试 → 仍失败 die 回滚
tkp_firewall_reload() {
	local out rc _rc
	if out=$(/etc/init.d/firewall reload 2>&1); then
		rc=0
	else
		rc=$?
	fi
	printf '%s\n' "$out" | grep -v 'udhcpc:' | sed 's/^/    /'
	[ "$rc" = "0" ] && return 0

	# 保存诊断快照（用于排障，不影响决策）
	mkdir -p /tmp/tkproxy 2>/dev/null
	{ echo "# tkproxy firewall reload 失败快照 $(date)"; echo "rc=$rc"; echo; echo "## 输出"; printf '%s\n' "$out"; echo; command -v fw4 >/dev/null 2>&1 && { echo "## fw4 check"; fw4 check 2>&1; }; echo; echo "## 遗留段"; uci show firewall 2>/dev/null | grep -E "(passwall|shadowsocksr|clash)" | head -20; } > /tmp/tkproxy/fw-fail.txt 2>/dev/null

	# 固定失败处理：autofix（0/2 成功继续，1 必须中止）→ 再 reload → 仍非 0 → die
	warn "firewall reload 失败（退出码 $rc），尝试自动修复第三方遗留段后重试……"
	_rc=0
	tkp_firewall_autofix >/dev/null 2>&1 || _rc=$?
	case "$_rc" in
		0|2)
			# 0=有改动成功、2=无需清理，都继续尝试 reload
			if out=$(/etc/init.d/firewall reload 2>&1); then
				rc=0
			else
				rc=$?
			fi
			printf '%s\n' "$out" | grep -v 'udhcpc:' | sed 's/^/    /'
			[ "$rc" = "0" ] && return 0
			die "firewall reload 失败，已保存诊断快照 /tmp/tkproxy/fw-fail.txt（自动回滚）"
			;;
		*)
			# 1=失败，必须中止部署
			die "防火墙遗留段清理失败（rc=$_rc），必须中止部署（自动回滚）"
			;;
	esac
}


# ---------------------------------------------------------------------------
# JSON 读取
#
# 生成器输出的是两空格缩进的固定结构（gen.py / gen.lua 同构），这里用
# 一个只认「目标数组里的扁平对象」的小解析器读取，不依赖 jq/jsonfilter。
# 只处理生成器自己的产物，不追求通用 JSON。
# ---------------------------------------------------------------------------

# tkp_json_rows <文件> <数组名> <逗号分隔的键>
# 每个数组元素输出一行，字段用 \037 分隔；缺失键输出空。
tkp_json_rows() {
	awk -v want="$2" -v keys="$3" -v OFS="$SEP" '
	function unesc(v,   i, c, e, s, out) {
		if (v == "null") return ""
		if (substr(v, 1, 1) != "\"") return v
		s = substr(v, 2, length(v) - 2)
		out = ""
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (c != "\\") { out = out c; continue }
			i++
			e = substr(s, i, 1)
			if (e == "n") out = out "\n"
			else if (e == "t") out = out "\t"
			else if (e == "r") out = out "\r"
			else if (e == "u") { i += 4 }   # 控制字符：SSID 里不会出现，丢弃
			else out = out e
		}
		return out
	}
	function emit(   i, o) {
		o = ""
		for (i = 1; i <= n; i++) o = o (i > 1 ? OFS : "") F[K[i]]
		print o
	}
	BEGIN {
		n = split(keys, K, ",")
		inside = 0
		depth = 0
	}
	{
		line = $0
		if (!inside) {
			if (line ~ ("^[ \t]*\"" want "\"[ \t]*:[ \t]*\\[[ \t]*$")) inside = 1
			next
		}
		t = line
		sub(/^[ \t]+/, "", t)
		sub(/[ \t]+$/, "", t)
		sub(/,$/, "", t)
		if (depth == 0) {
			if (t == "]") { inside = 0; next }
			if (t == "{") { depth = 1; split("", F); }
			next
		}
		if (t == "{" || t == "[") { depth++; next }
		if (t == "}" || t == "]") {
			depth--
			if (depth == 0) emit()
			next
		}
		if (depth >= 1) {
			q = index(line, "\": ")
			if (q > 0) {
				k = substr(line, 1, q - 1)
				gsub(/^[ \t]*"/, "", k)
				v = substr(line, q + 3)
				sub(/,[ \t]*$/, "", v)
				# 嵌套对象/数组要计深，否则 headers/utls 这类内层
				# 的 } 会被误当成当前对象的结束
				if (v == "{" || v == "[") { depth++; next }
				if (depth == 1) F[k] = unesc(v)
			}
		}
	}' "$1"
}

# ---------------------------------------------------------------------------
# 输入白名单校验
# ---------------------------------------------------------------------------

tkp_is_ipv4() {
	case "$1" in ''|*[!0-9.]*|*..*|.*|*.) return 1 ;; esac
	_oifs=$IFS
	IFS=.
	set -- $1
	IFS=$_oifs
	[ $# -eq 4 ] || return 1
	for _o in "$@"; do
		case "$_o" in ''|*[!0-9]*) return 1 ;; esac
		[ "$_o" -ge 0 ] 2>/dev/null && [ "$_o" -le 255 ] || return 1
	done
	return 0
}

# 只接受生成器的 a.b.c.0/24 形式
tkp_is_cidr24() {
	case "$1" in */*) ;; *) return 1 ;; esac
	_ip=${1%/*}
	_bits=${1#*/}
	tkp_is_ipv4 "$_ip" || return 1
	[ "$_bits" = "24" ] || return 1
	case "$_ip" in *.0) ;; *) return 1 ;; esac
	return 0
}

tkp_gw_in_subnet() {
	_net=${2%/*}
	[ "${1%.*}" = "${_net%.*}" ] || return 1
	_last=${1##*.}
	[ "$_last" -ge 1 ] 2>/dev/null && [ "$_last" -le 254 ] || return 1
	return 0
}

tkp_is_public_ipv4() {
	tkp_is_ipv4 "$1" || return 1
	case "$1" in
		0.*|10.*|127.*|169.254.*|192.168.*) return 1 ;;
		172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
		100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
		22[4-9].*|2[3-5][0-9].*) return 1 ;;
	esac
	return 0
}

tkp_assert_devname() {
	case "$1" in ''|*[!A-Za-z0-9_.-]*) die "非法设备/接口名：$1" ;; esac
	[ "${#1}" -le 15 ] || die "设备/接口名超过 15 字节：$1（${#1} 字节）"
}

tkp_validate_ssid() {
	_s=$1
	_where=$2
	case "$_s" in *[[:cntrl:]]*) die "manifest 第 $_where 条 SSID 含换行/控制字符，拒绝部署" ;; esac
	case "$_s" in *"'"*|*'"'*) die "manifest 第 $_where 条 SSID 含引号，拒绝部署" ;; esac
	_n=$(printf '%s' "$_s" | wc -c | tr -d ' ')
	[ "$_n" -gt 0 ] || die "manifest 第 $_where 条 SSID 为空"
	[ "$_n" -le 32 ] || die "manifest 第 $_where 条 SSID 的 UTF-8 字节数 $_n 超过 32"
}

tkp_validate_slug() {
	case "$1" in ''|*[!A-Za-z0-9_]*) die "manifest 第 $2 条 slug 含非法字符：$1" ;; esac
	[ "${#1}" -le 64 ] || die "manifest 第 $2 条 slug 过长（>64）：$1"
}

tkp_valid_radio_name() {
	case "$1" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
	[ "${#1}" -le 15 ] || return 1
	return 0
}

# 短且稳定的设备名：brtkNN（bridge）/ tkpNN（netifd interface）
tkp_ifname() { printf 'tkp%02d' "$1"; }
tkp_brname() { printf 'brtk%02d' "$1"; }

# 部署计划：index ssid slug br subnet gateway port band node_type
PLAN=$(tkp_json_rows "$D/manifest.json" ssids "index,ssid,slug,br,subnet,gateway,port,band,node_type")
[ -n "$PLAN" ] || die "manifest.json 里没有任何 SSID"

# 单条部署：--only 指定的 index 必须真实存在于 manifest，否则直接拒绝
# （防止把越界序号静默部署成「什么都不做」）
if [ -n "$ONLY_IDX" ]; then
	_only_ok=0
	while IFS="$SEP" read -r _oidx _orest; do
		[ "$_oidx" = "$ONLY_IDX" ] && { _only_ok=1; break; }
	done <<EOF
$PLAN
EOF
	[ "$_only_ok" = "1" ] || die "--only $ONLY_IDX 不在 manifest.json 里（有效 index：$(printf '%s\n' "$PLAN" | cut -d"$SEP" -f1 | tr '\n' ' ')）"
	say "单条部署模式：只重建 index=$ONLY_IDX，其它线路不动"
fi

# 单条模式专用的裁剪后计划（只含目标行，供步骤 3/4/5 使用）
# 用纯 shell 裁剪：awk -v 传 \037 控制字符在部分实现（Windows gawk）下会报 usage
PLAN_ONLY=""
if [ -n "$ONLY_IDX" ]; then
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		[ "$idx" = "$ONLY_IDX" ] || continue
		PLAN_ONLY="${PLAN_ONLY}${idx}${SEP}${ssid}${SEP}${slug}${SEP}${br}${SEP}${subnet}${SEP}${gw}${SEP}${port}${SEP}${band}${SEP}${ntype}
"
	done <<EOF
$PLAN
EOF
	[ -n "$PLAN_ONLY" ] || die "内部错误：--only 裁剪结果为空（idx=$ONLY_IDX）"
fi

TKP_STEP="== 1. 校验产物 =="
say "[step $TKP_STEP]"
say "$TKP_STEP"

SLUGS=""
USED_IDX=""
USED_SLUGS=""
USED_PORTS=""
SSID_COUNT=0
NEED_2G=0
NEED_5G=0
COUNT_2G=0
COUNT_5G=0
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	case "$idx" in ''|*[!0-9]*) die "manifest.json 条目缺少合法的 index：$idx" ;; esac
	case "$idx" in 0|[1-9]*) ;; *) die "manifest.json 的 index 不能有前导零：$idx" ;; esac
	[ "$idx" -le 9999 ] || die "manifest.json 的 index 过大（>9999）：$idx"
	case " $USED_IDX " in *" $idx "*) die "manifest.json 的 index 重复：$idx" ;; esac
	USED_IDX="$USED_IDX $idx"

	[ -n "$slug" ] || die "manifest.json 第 $idx 条缺少 slug"
	tkp_validate_slug "$slug" "$idx"
	case " $USED_SLUGS " in *" $slug "*) die "manifest.json 的 slug 重复：$slug" ;; esac
	USED_SLUGS="$USED_SLUGS $slug"
	[ -n "$ssid" ] || die "manifest.json 第 $idx 条缺少 ssid"
	tkp_validate_ssid "$ssid" "$idx"
	[ -n "$subnet" ] || die "manifest.json 第 $idx 条缺少 subnet"
	tkp_is_cidr24 "$subnet" || die "manifest.json 第 $idx 条 subnet 必须是 a.b.c.0/24：$subnet"
	[ -n "$gw" ] || die "manifest.json 第 $idx 条缺少 gateway"
	tkp_is_ipv4 "$gw" || die "manifest.json 第 $idx 条 gateway 不是合法 IPv4：$gw"
	tkp_gw_in_subnet "$gw" "$subnet" || die "manifest.json 第 $idx 条 gateway $gw 不在 $subnet 内"
	case "$port" in ''|*[!0-9]*) die "manifest.json 第 $idx 条端口非法：$port" ;; esac
	case "$port" in 0|[1-9]*) ;; *) die "manifest.json 第 $idx 条端口不能有前导零：$port" ;; esac
	[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "manifest.json 第 $idx 条端口越界：$port"
	case " $USED_PORTS " in *" $port "*) die "manifest.json 端口重复：$port" ;; esac
	USED_PORTS="$USED_PORTS $port"

	[ -n "$band" ] || band=both
	case "$band" in
		both|2g|5g) ;;
		*) die "manifest.json 第 $idx 条 band 非法：$band（只支持 both/2g/5g）" ;;
	esac

	[ -n "$br" ] || br="br-$slug"
	case "$br" in *'"'*|*[[:cntrl:]]*) die "manifest.json 第 $idx 条 br 字段非法：$br" ;; esac

	_if=$(tkp_ifname "$idx")
	_brn=$(tkp_brname "$idx")
	tkp_assert_devname "$_if"
	tkp_assert_devname "$_brn"

	SLUGS="$SLUGS $slug"
	SSID_COUNT=$((SSID_COUNT + 1))
	case "$band" in
		both) NEED_2G=1; NEED_5G=1; COUNT_2G=$((COUNT_2G + 1)); COUNT_5G=$((COUNT_5G + 1)) ;;
		2g) NEED_2G=1; COUNT_2G=$((COUNT_2G + 1)) ;;
		5g) NEED_5G=1; COUNT_5G=$((COUNT_5G + 1)) ;;
	esac
done <<EOF
$PLAN
EOF

# 单条部署：统计口径只算这一条，容量校验/生效等待都不受其它线路影响
if [ -n "$ONLY_IDX" ]; then
	SLUGS=$(printf '%s' "$PLAN_ONLY" | cut -d"$SEP" -f3)
	SSID_COUNT=1
	NEED_2G=0; NEED_5G=0; COUNT_2G=0; COUNT_5G=0
	_only_band=""
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		_only_band=$band
		case "$band" in
			both) NEED_2G=1; NEED_5G=1; COUNT_2G=$((COUNT_2G + 1)); COUNT_5G=$((COUNT_5G + 1)) ;;
			2g) NEED_2G=1; COUNT_2G=$((COUNT_2G + 1)) ;;
			5g) NEED_5G=1; COUNT_5G=$((COUNT_5G + 1)) ;;
		esac
	done <<EOF
$PLAN_ONLY
EOF
	say "  单条部署口径：SSID 1 条（index=$ONLY_IDX，band=${_only_band:-both}），容量校验只算这一条"
fi

# 显式指定的射频名也要做白名单校验（还必须真实存在）
if [ -n "${TK_RADIO_2G:-}" ]; then
	tkp_valid_radio_name "$TK_RADIO_2G" || die "TK_RADIO_2G 不是合法设备名：$TK_RADIO_2G"
	uci -q get "wireless.$TK_RADIO_2G" >/dev/null 2>&1 \
		|| die "TK_RADIO_2G 指向的射频不存在：$TK_RADIO_2G"
fi
if [ -n "${TK_RADIO_5G:-}" ]; then
	tkp_valid_radio_name "$TK_RADIO_5G" || die "TK_RADIO_5G 不是合法设备名：$TK_RADIO_5G"
	uci -q get "wireless.$TK_RADIO_5G" >/dev/null 2>&1 \
		|| die "TK_RADIO_5G 指向的射频不存在：$TK_RADIO_5G"
fi

if [ ! -x "$XRAY" ]; then
	die "未找到 xray 二进制（查找路径：$XRAY）"
fi
# Xray 使用 run -test 参数进行配置校验（完整输出写日志，方便排障）
_xray_test_out=$("$XRAY" run -test -c "$D/xray.json" 2>&1) || {
	printf '%s\n' "$_xray_test_out" >&2
	die "xray.json 未通过 xray run -test 校验：$D/xray.json"
}

TK_WIFI_KEY=${TK_WIFI_KEY:-}
if [ -z "$TK_WIFI_KEY" ] && [ -f "$D/wifi.key" ]; then
	TK_WIFI_KEY=$(sed -n '1p' "$D/wifi.key" 2>/dev/null | tr -d '\r' || true)
fi
if [ -z "$TK_WIFI_KEY" ]; then
	die "WiFi 密码未配置（产物目录缺失 wifi.key 且环境变量 TK_WIFI_KEY 未设置）"
fi
_keylen=$(printf '%s' "$TK_WIFI_KEY" | wc -c | tr -d ' ')
[ "$_keylen" -ge 8 ] && [ "$_keylen" -le 63 ] || die "WiFi 密码长度必须是 8-63 字节（实际 $_keylen）"
# 检查 ASCII 可见字符（0x20-0x7E），排除控制字符和引号
case "$TK_WIFI_KEY" in
	*[[:cntrl:]]*) die "WiFi 密码含换行/控制字符" ;;
	*"'"*|*'"'*) die "WiFi 密码不能包含引号" ;;
esac
# 验证所有字符在 ASCII 可见范围（0x20-0x7E）
if ! printf '%s' "$TK_WIFI_KEY" | LC_ALL=C grep -q '^[ -~]*$'; then
	die "WiFi 密码只能包含 ASCII 可见字符（0x20-0x7E）"
fi

TK_DNS=${TK_DNS:-}
if [ -z "$TK_DNS" ] && [ -f "$D/dns" ]; then
	TK_DNS=$(sed -n '1p' "$D/dns" 2>/dev/null | tr -d '\r' || true)
fi
[ -n "$TK_DNS" ] || TK_DNS=$DEFAULT_DNS
TK_DNS=$(printf '%s' "$TK_DNS" | sed 's/[[:space:]]//g')
[ -n "$TK_DNS" ] || die "DHCP DNS 为空"
_oldifs=$IFS
IFS=,
for dnsip in $TK_DNS; do
	if ! tkp_is_public_ipv4 "$dnsip"; then
		IFS=$_oldifs
		die "DHCP DNS 必须是公网 IPv4（$dnsip 非法或属于内网/保留地址）"
	fi
done
IFS=$_oldifs

TK_ADMIN_IP=${TK_ADMIN_IP:-}
if [ -z "$TK_ADMIN_IP" ]; then
	TK_ADMIN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null || true)
	TK_ADMIN_IP=${TK_ADMIN_IP%% *}
	TK_ADMIN_IP=${TK_ADMIN_IP%%/*}
fi
[ -n "$TK_ADMIN_IP" ] || TK_ADMIN_IP=192.168.8.1
tkp_is_ipv4 "$TK_ADMIN_IP" || die "管理地址不是合法 IPv4：$TK_ADMIN_IP"

say "  SSID 数：$(printf '%s\n' "$SLUGS" | wc -w | tr -d ' ')"
say "  WiFi 密码：$(printf '%s' "$TK_WIFI_KEY" | sed 's/./*/g')"
say "  DHCP DNS：$TK_DNS"
say "  接口命名：$(tkp_ifname 0)/$(tkp_brname 0) 起（<=15 字节）"

# ---------------------------------------------------------------------------
# 射频探测与容量校验（fail-closed）
# ---------------------------------------------------------------------------

tkp_radios_all() {
	uci -q show wireless 2>/dev/null | sed -n 's/^wireless\.\([^.=]*\)=wifi-device$/\1/p'
}

# 返回 2g / 5g / 6g / other
tkp_radio_band() {
	local d band ch hw
	d=$1
	band=$(uci -q get "wireless.$d.band" 2>/dev/null || true)
	case "$band" in
		2g|5g|6g) printf '%s' "$band"; return 0 ;;
	esac
	ch=$(uci -q get "wireless.$d.channel" 2>/dev/null || true)
	case "$ch" in
		1|2|3|4|5|6|7|8|9|10|11|12|13|14) printf '2g'; return 0 ;;
		auto|0|"") ;;
		*) printf '5g'; return 0 ;;
	esac
	hw=$(uci -q get "wireless.$d.hwmode" 2>/dev/null || true)
	case "$hw" in
		11g|11b|11ng) printf '2g' ;;
		11a|11ac|11ax) printf '5g' ;;
		*) printf 'other' ;;
	esac
}

# radioX → phyN；查不到返回 1
tkp_radio_phy() {
	local dev p want real d
	dev=$1
	[ -n "$dev" ] || return 1
	[ -d "/sys/class/net/$dev" ] || [ -n "$(uci -q get "wireless.$dev" 2>/dev/null || true)" ] || return 1

	p=$(ubus call network.wireless status 2>/dev/null \
		| jsonfilter -e "@.$dev.interfaces[*].ifname" 2>/dev/null | head -n 1 || true)
	if [ -n "$p" ] && [ -e "/sys/class/net/$p/phy80211/name" ]; then
		real=$(cat "/sys/class/net/$p/phy80211/name" 2>/dev/null || true)
		[ -n "$real" ] && { printf '%s' "$real"; return 0; }
	fi
	case "$p" in
		phy*-*) printf '%s' "${p%%-*}"; return 0 ;;
	esac
	want=$(uci -q get "wireless.$dev.path" 2>/dev/null || true)
	if [ -n "$want" ]; then
		for d in "$PHY_DIR"/*; do
			[ -e "$d" ] || continue
			real=$(readlink -f "$d/device" 2>/dev/null || true)
			case "$real" in
				*/devices/"$want"|*/devices/"$want"/*)
					basename "$d"; return 0 ;;
			esac
		done
	fi
	return 1
}

# 单颗 PHY 的 AP 组合上限（#{ AP ... } <= N）；查不到返回 1
tkp_phy_ap_limit() {
	local p v
	p=$1
	case "$p" in phy[0-9]*) ;; *) return 1 ;; esac
	v=$(iw phy "$p" info 2>/dev/null \
		| sed -n 's/.*#{ *AP[^}]*}[[:space:]]*<=[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
		| sort -n | head -n 1 || true)
	case "$v" in ''|*[!0-9]*) return 1 ;; esac
	[ "$v" -gt 0 ] || return 1
	printf '%s' "$v"
}

# 映射不到单颗 PHY 时的保守兜底：取所有 PHY 的最小值
tkp_phy_min_ap_limit() {
	local d n v min
	min=""
	for d in "$PHY_DIR"/*; do
		[ -e "$d" ] || continue
		n=$(basename "$d")
		v=$(tkp_phy_ap_limit "$n" 2>/dev/null || true)
		[ -n "$v" ] || continue
		if [ -z "$min" ] || [ "$v" -lt "$min" ]; then min=$v; fi
	done
	[ -n "$min" ] || return 1
	printf '%s' "$min"
}

tkp_radio_for() {
	local role envdev cand n dev
	role=$1
	case "$role" in
		2g) envdev=${TK_RADIO_2G:-} ;;
		5g) envdev=${TK_RADIO_5G:-} ;;
		*) return 1 ;;
	esac
	if [ -n "$envdev" ]; then printf '%s' "$envdev"; return 0; fi
	n=0
	dev=""
	for cand in $(tkp_radios_all); do
		[ "$(tkp_radio_band "$cand")" = "$role" ] || continue
		n=$((n + 1))
		dev=$cand
	done
	[ "$n" -eq 1 ] || return 1
	printf '%s' "$dev"
}

# 旧部署的段名（升级时也要算作「本方案的 AP」，否则容量会被高估）
OLD_SLUGS=""
if [ -s "$CONF_DIR/manifest.json" ]; then
	OLD_ROWS=$(tkp_json_rows "$CONF_DIR/manifest.json" ssids "slug")
	while IFS="$SEP" read -r oldslug; do
		[ -n "$oldslug" ] && OLD_SLUGS="$OLD_SLUGS $oldslug"
	done <<EOF
$OLD_ROWS
EOF
fi
OUR_SLUGS="$SLUGS $OLD_SLUGS"

tkp_is_ours() {
	local sec s
	sec=$1
	[ "$(uci -q get "wireless.$sec.tkproxy" 2>/dev/null || true)" = "1" ] && return 0
	for s in $OUR_SLUGS; do
		case "$sec" in
			"${s}_2g"|"${s}_5g"|"${s}_0"|"${s}_1") return 0 ;;
		esac
	done
	return 1
}

# 打印某颗射频上所有启用的 wifi-iface 段名
tkp_enabled_sections_on() {
	local dev sec
	dev=$1
	for sec in $(uci -q show wireless 2>/dev/null | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface$/\1/p'); do
		[ "$(uci -q get "wireless.$sec.device" 2>/dev/null || true)" = "$dev" ] || continue
		[ "$(uci -q get "wireless.$sec.disabled" 2>/dev/null || true)" = "1" ] && continue
		printf '%s\n' "$sec"
	done
}

CAP_FILE=$WORK/capacity
: >"$CAP_FILE"

tkp_capacity_check() {
	local role dev phy lim used sec ours other add total
	if ! command -v iw >/dev/null 2>&1; then
		die_code 3 "缺少 iw，无法读取射频 AP 上限；请先安装 iw 再部署"
	fi
	for role in ${NEED_2G:+2g} ${NEED_5G:+5g}; do
		dev=$(tkp_radio_for "$role" 2>/dev/null || true)
		if [ -z "$dev" ]; then
			die_code 3 "无法确定 ${role} 射频：需要恰好一颗 ${role} 射频，或用 TK_RADIO_2G/TK_RADIO_5G 指定"
		fi
		phy=$(tkp_radio_phy "$dev" 2>/dev/null || true)
		lim=""
		if [ -n "$phy" ]; then
			lim=$(tkp_phy_ap_limit "$phy" 2>/dev/null || true)
		fi
		if [ -z "$lim" ]; then
			lim=$(tkp_phy_min_ap_limit 2>/dev/null || true)
		fi
		if [ -z "$lim" ]; then
			die_code 3 "无法确定 $dev ($role) 的 AP 上限（iw phy 未给出 #{ AP ... } <= N）；拒绝部署"
		fi
		used=0
		ours=0
		for sec in $(tkp_enabled_sections_on "$dev"); do
			used=$((used + 1))
			if tkp_is_ours "$sec"; then ours=$((ours + 1)); fi
		done
		other=$((used - ours))
		if [ "$role" = "2g" ]; then add=$COUNT_2G; else add=$COUNT_5G; fi
		total=$((other + add))
		if [ "$total" -gt "$lim" ]; then
			die_code 3 "射频 $dev ($role) 的 AP 上限是 $lim：现有非本方案 AP $other 个 + 本次 $add 个 = $total 个，拒绝部署（超过上限会让整颗射频崩到只剩一个接口）"
		fi
		printf '%s %s %s %s %s\n' "$role" "$dev" "$phy" "$lim" "$total" >>"$CAP_FILE"
		say "  容量校验 $dev ($role)：$other + $add <= $lim，通过"
	done
}

tkp_actual_ap_count() { # <phyN>  统计该射频上已启用的 AP 接口数
	_p=$1
	[ -n "$_p" ] || { printf '0'; return 0; }
	_a=$(iw dev 2>/dev/null | grep -cE "[[:space:]]+Interface ${_p}-ap[0-9]+")
	if [ "${_a:-0}" = "0" ]; then
		_a=$(iw dev 2>/dev/null | grep -cE "[[:space:]]+Interface ${_p}ap[0-9]+")
	fi
	printf '%s' "${_a:-0}"
}

tkp_capacity_postcheck() {
	[ -s "$CAP_FILE" ] || return 0
	while read -r role dev phy lim expected; do
		[ -n "$role" ] || continue
		_i=0
		_actual=0
		while [ "$_i" -lt 15 ]; do
			_actual=$(tkp_actual_ap_count "$phy")
			[ "$_actual" -ge "$expected" ] && break
			_i=$((_i + 1))
			sleep 1
		done
		if [ "$_actual" -gt "$lim" ]; then
			die "部署后复核失败：射频 $dev ($role) 实际 AP 数 $_actual 超过上限 $lim，自动回滚"
		fi
		if [ "$_actual" -lt "$expected" ]; then
			warn "部署后复核：$dev ($role) 实际 AP 数 $_actual 少于预期 $expected（可能射频未完全起来）"
		fi
		say "  复核 $dev ($role)：实际 AP $_actual <= 上限 $lim"
	done <"$CAP_FILE"
}

TKP_STEP="== 2. 容量校验 =="
say "[step $TKP_STEP]"
say "$TKP_STEP"
tkp_capacity_check

# 写 uci 前必须先确定射频（后面 wireless 段要用）
RADIO_2G=""
RADIO_5G=""
if [ "$NEED_2G" = "1" ]; then
	RADIO_2G=$(tkp_radio_for 2g 2>/dev/null || true)
	[ -n "$RADIO_2G" ] || die "无法确定 2.4G 射频"
	tkp_valid_radio_name "$RADIO_2G" || die "2.4G 射频名非法：$RADIO_2G"
fi
if [ "$NEED_5G" = "1" ]; then
	RADIO_5G=$(tkp_radio_for 5g 2>/dev/null || true)
	[ -n "$RADIO_5G" ] || die "无法确定 5G 射频"
	tkp_valid_radio_name "$RADIO_5G" || die "5G 射频名非法：$RADIO_5G"
fi

# ---------------------------------------------------------------------------
# 生成并校验 nft（桥名改成 brtkNN，mark 改成 0x8000）
# ---------------------------------------------------------------------------

tkp_literal_replace() {
	_f=$1
	_from=$2
	_to=$3
	_out=$4
	[ -n "$_from" ] || die "内部错误：替换源为空"
	# from == to 时不需要替换；直接把原文搬过去，避免无意义遍历
	if [ "$_from" = "$_to" ]; then
		say "  cp $_f -> $_out（from==to，原样复制）"
		if ! cp "$_f" "$_out" 2>/dev/null; then
			warn "cp 失败"
			warn "  动作：tkp_literal_replace 原样复制"
			warn "  目标路径：$_out"
			warn "  ls -l：$(ls -l "$_f" "$_out" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
			die "tkp_literal_replace cp $_f -> $_out 失败"
		fi
		return 0
	fi
	# 边消费边拼接：每次替换后把已处理的前缀切掉，保证即使 to 里含 from 也能终止
	awk -v from="$_from" -v to="$_to" '
		{
			line = $0; out = ""; flen = length(from)
			while ((i = index(line, from)) > 0) {
				out = out substr(line, 1, i - 1) to
				line = substr(line, i + flen)
			}
			print out line
		}' "$_f" >"$_out"
}

Nft=$WORK/tkproxy.nft
say "  复制 nft 规则到工作目录"
if ! cp "$D/tkproxy.nft" "$Nft" 2>/dev/null; then
	warn "cp nft 规则失败"
	warn "  源：$D/tkproxy.nft"
	warn "  目标：$Nft"
	warn "  工作目录 ls -l：$(ls -ld "$WORK" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "复制 tkproxy.nft 失败"
fi
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	[ -n "$br" ] || br="br-$slug"
	_brn=$(tkp_brname "$idx")
	tkp_literal_replace "$Nft" "iifname \"$br\"" "iifname \"$_brn\"" "$Nft.tmp"
	if ! mv -f "$Nft.tmp" "$Nft" 2>/dev/null; then
		warn "mv 改写桥名失败"
		warn "  源：$Nft.tmp"
		warn "  目标：$Nft"
		warn "  ls -l：$(ls -l "$Nft" "$Nft.tmp" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "改写 tkproxy.nft 桥名失败"
	fi
done <<EOF
$PLAN
EOF
# 改写 mark 0x1 → 0x8000
tkp_literal_replace "$Nft" 'meta mark set 0x1 ' 'meta mark set 0x8000 ' "$Nft.tmp"
say "  mv nft mark 改写结果"
if ! mv -f "$Nft.tmp" "$Nft" 2>/dev/null; then
	warn "mv 失败"
	warn "  动作：改写 tkproxy.nft mark 0x1 → 0x8000"
	warn "  目标路径：$Nft"
	warn "  ls -l：$(ls -l "$Nft" "$Nft.tmp" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "改写 tkproxy.nft mark 失败"
fi

	# M11c: 已移除旧 53 端口 tproxy 劫持（改用 127.0.0.1:53NN DNS 入口）

grep -q 'meta mark set 0x8000' "$Nft" \
	|| die "tkproxy.nft 中找不到 mark 0x8000，拒绝部署（请重新生成产物）"
if grep -q 'meta mark set 0x1 ' "$Nft"; then
	die "tkproxy.nft 仍含旧 mark 0x1，拒绝部署"
fi

# M11c: 校验新 DNS 入口设计（DNS 改监听 127.0.0.1:53NN，避开 dnsmasq 53 端口冲突）
# 每条线路需确认：
#   1. 存在全流量 tproxy 规则
#   2. DNS 入口在 gen.lua 生成的 127.0.0.1:53NN dokodemo 入站，客户端 DNS 通过 nft input 链 tproxy 到该端口
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	_brn=$(tkp_brname "$idx")
	# 校验桥名出现在规则中
	grep -q "iifname \"$_brn\"" "$Nft" \
		|| die "tkproxy.nft 中缺少桥 $_brn 的规则，拒绝部署"
	# 校验全流量 tproxy：{ tcp, udp } tproxy … :$port
	grep -E "iifname \"$_brn\".*meta nfproto ipv4 meta l4proto.*tproxy ip to :$port" "$Nft" >/dev/null \
		|| die "tkproxy.nft 中缺少桥 $_brn 的全流量 tproxy 规则（:$port），拒绝部署"
done <<EOF
$PLAN
EOF

# ---------------------------------------------------------------------------
# tkp 间隔离 + IPv6 防泄漏
# ---------------------------------------------------------------------------

# 调用提取的规则生成函数
say "  生成隔离、input、forward 规则并注入到 nft 文件"
if ! tkp_generate_nft_rules "$Nft" "$WORK" "$PLAN"; then
	die "生成并注入隔离规则失败"
fi

if ! _nftchk=$(nft -c -f "$Nft" 2>&1); then
	warn "nft -c 输出：$_nftchk"
	warn "  文件：$Nft（行数 $(wc -l <"$Nft" 2>/dev/null | tr -d ' ')，字节 $(wc -c <"$Nft" 2>/dev/null | tr -d ' ')）"
	# M3 自测：语法检查失败时打印出问题文件前 40 行，便于按报错行列定位
	warn "  ===== $Nft 前 40 行（带行号） ====="
	sed -n '1,40p' "$Nft" 2>/dev/null | cat -n | while IFS= read -r _dl; do warn "    $_dl"; done
	warn "  ===== 前 40 行结束 ====="
	die "tkproxy.nft 未通过 nft -c 语法检查"
fi
say "  nft 规则已改写为 brtkNN + mark 0x8000 + DNS劫持 + SSID间隔离(brtk*) + IPv6防泄漏(nfproto ipv6 drop)，并通过语法检查"

# ---------------------------------------------------------------------------
# 内置 init（忽略产物里的旧 init，避免 table 100 / flush / 后台吞错）
# ---------------------------------------------------------------------------
INIT_SRC=$WORK/tkproxy.init
cat >"$INIT_SRC" <<'INITEOF'
#!/bin/sh /etc/rc.common
# 由 tkproxy apply.sh 写入：/etc/init.d/tkproxy
# 策略路由：专属 mark 0x8000/0x8000 + table 51820；绝不 flush 整表。
START=99
STOP=15
# 不用 procd 托管：xray 由 start_service 自己 fork 管理。
# 用 USE_PROCD=1 却没调 procd_run 会出两个问题：procd 反复 respawn 出一堆
# /etc/init.d/tkproxy 实例（实测堆到 13 个），且 stop 永远等不到实例退出，
# 表现为 opkg remove / init stop 卡死十几分钟。
# 关键：不能用 USE_PROCD=0。rc.common 只判断这个变量「非空」，"0" 也算非空，
# 于是会走 procd 分支（rc_procd start_service），而本脚本没有注册 procd 实例，
# 结果是 start_service 永远不被调用 —— 重启后 DNS 桥不启动、看门狗不驻留。
# 实测：重启后 AP/桥/xray 都回来了，唯独客户端 DNS 全断。
# 改为「不声明 USE_PROCD」+ 自己实现 start/stop/restart，走 rc.common 的传统路径。
start() { start_service "$@"; }
stop() { stop_service "$@"; }
restart() {
	stop_service "$@"
	sleep 2
	start_service "$@"
}

NFT_FILE=/etc/tkproxy/tkproxy.nft
CFG=/etc/tkproxy/xray.json
MARK=0x8000/0x8000
RT_TABLE=51820

policy_down() {
	nft delete table inet tkproxy 2>/dev/null
	ip rule del fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table "$RT_TABLE" 2>/dev/null
	# 旧版遗留：只删本方案的精确条目，绝不 flush 整表
	ip rule del fwmark 0x1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
}

policy_up() {
	ip rule del fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table "$RT_TABLE" 2>/dev/null
	ip rule add fwmark "$MARK" lookup "$RT_TABLE" || return 1
	ip route add local 0.0.0.0/0 dev lo table "$RT_TABLE" || return 1
}

port_up() {
	if command -v netstat >/dev/null 2>&1; then
		netstat -ln 2>/dev/null | grep -q ":$1 "
	elif command -v ss >/dev/null 2>&1; then
		ss -ln 2>/dev/null | grep -q ":$1 "
	else
		return 1
	fi
}

watchdog() {
	# 守护进程独立成脚本 + setsid 启动：原来的 `( ... ) &` 和 procd 服务在同一
	# 进程组，服务 restart 时被连带杀掉，重启后 DNS 桥就再没人拉起来。
	if [ -s /var/run/tkproxy-watchdog.pid ] && kill -0 "$(cat /var/run/tkproxy-watchdog.pid 2>/dev/null)" 2>/dev/null; then
		return 0
	fi
	if [ ! -x /usr/libexec/tkproxy/watchdog.sh ]; then
		logger -t tkproxy "watchdog.sh 缺失（或没执行权限），跳过守护"
		return 0
	fi
	if command -v setsid >/dev/null 2>&1; then
		setsid sh /usr/libexec/tkproxy/watchdog.sh >/dev/null 2>&1 &
	else
		sh /usr/libexec/tkproxy/watchdog.sh >/dev/null 2>&1 &
	fi
	echo $! > /var/run/tkproxy-watchdog.pid
}

boot() {
	# 开机：先起服务；若 nft 表没加载成功则 60 秒后重试一次（rc.local 还有一层兜底）
	start "$@"
	(
		sleep 60
		if ! nft list table inet tkproxy >/dev/null 2>&1; then
			logger -t tkproxy "boot: 60 秒后仍无 inet tkproxy 表，重试一次"
			/etc/init.d/tkproxy restart >/dev/null 2>&1
		fi
	) &
	# DNS 桥兜底：start 在 procd 认为服务已运行时是空操作，桥必须单独再拉一次，
	# 否则重启后客户端能连 WiFi 但所有域名解析不了（网页打不开）。
	(
		sleep 45
		if ip -4 addr show 2>/dev/null | grep -q "10\.11\.[0-9]*\.1/" && \
		   ! netstat -lnup 2>/dev/null | grep -q ":5301"; then
			logger -t tkproxy "boot: 45s 后 DNS 桥未监听，兜底拉起"
			start_dnsbridge
		fi
	) &
	# 开箱自检：开机 90s 后异步跑一次（有 24h 节流，不是每次开机都真跑）
	(
		sleep 90
		bootcheck_kick
	) &
}

# 开箱自检（t_d32788de）：结果落盘 /etc/tkproxy/bootcheck.json，
# 概览页据此显示「待机 · 可直接使用」状态条。后台异步跑，不阻塞启动；
# 脚本内部有 24h 节流与并发锁，这里只管拉起，失败不影响任何流程（但留痕可查）。
bootcheck_kick() {
	if [ ! -f /usr/libexec/tkproxy/bootcheck.sh ]; then
		logger -t tkproxy "bootcheck_kick：/usr/libexec/tkproxy/bootcheck.sh 不存在，跳过开箱自检"
		return 0
	fi
	( sh /usr/libexec/tkproxy/bootcheck.sh >>/tmp/tkproxy/bootcheck.log 2>&1 & ) 2>/dev/null \
		|| ( sh /usr/libexec/tkproxy/bootcheck.sh >>/tmp/tkproxy/bootcheck.log 2>&1 & ) 2>/dev/null \
		|| logger -t tkproxy "bootcheck_kick：后台拉起失败（见 /tmp/tkproxy/bootcheck.log）"
	return 0
}

start_dnsbridge() {
	[ -f /usr/libexec/tkproxy/dnsbridge.lua ] || return 0
	# 开机阶段网桥可能还没拿到 10.11.x.1（netifd 还在建桥），先等最多 40 秒，
	# 否则绑定全失败、客户端 DNS 全断（表现为 WiFi 连上、网页打不开）。
	_w=0
	while [ "$_w" -lt 40 ]; do
		if ip -4 addr show 2>/dev/null | grep -q "10\.11\.[0-9]*\.1/"; then break; fi
		_w=$((_w + 1))
		sleep 1
	done
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	if [ -n "$_pid" ] && [ -d "/proc/$_pid" ]; then
		case "$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null || true)" in
			*dnsbridge.lua*) return 0 ;;
		esac
	fi
	for _p in $(pgrep -f "dnsbridge.lua" 2>/dev/null || true); do
		case "$(tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null || true)" in
			*tkproxy*dnsbridge.lua*) kill -9 "$_p" 2>/dev/null || true ;;
		esac
	done
	sleep 1
	mkdir -p /tmp/tkproxy 2>/dev/null || true
	# nohup 在 25.12 里被裁掉了（busybox applet 不全），缺了它桥根本起不来，
	# 而且因为 || true 会静默失败 —— 客户端表现就是「WiFi 连上、网页打不开」。
	if command -v setsid >/dev/null 2>&1; then
		setsid lua /usr/libexec/tkproxy/dnsbridge.lua >>/tmp/tkproxy/dnsbridge.log 2>&1 &
	else
		lua /usr/libexec/tkproxy/dnsbridge.lua >>/tmp/tkproxy/dnsbridge.log 2>&1 &
	fi
	echo $! > /var/run/tkproxy-dnsbridge.pid
	sleep 1
	# 起没起来必须验一次：进程在且端口在才算成功，否则写日志（部署日志里能看到）
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	if [ -n "$_pid" ] && [ -d "/proc/$_pid" ]; then
		netstat -lnup 2>/dev/null | grep -q ":5301" || \
			logger -t tkproxy "DNS 桥进程在但 5301 未监听（见 dnsbridge.log）"
		return 0
	fi
	logger -t tkproxy "DNS 桥启动失败（见 /tmp/tkproxy/dnsbridge.log）"
	return 0
}

start_service() {
	logger -t tkproxy "init: start_service 被调用（参数：${1:-none}）"
	# 串行化：开机时 boot()、rc.local 兜底、看门狗重启可能同时进来，
	# 各自都会「先杀旧 xray 再起新的」，结果留下两个 xray 实例抢同一批端口。
	_LOCK=/var/lock/tkproxy-start.lock
	if ! mkdir "$_LOCK" 2>/dev/null; then
		logger -t tkproxy "init: 已有 start 在进行，跳过本次"
		return 0
	fi
	trap 'rmdir "$_LOCK" 2>/dev/null' EXIT INT TERM
	# 清掉维护标记，让看门狗恢复值守
	rm -f /tmp/tkproxy/.paused 2>/dev/null
	policy_down
	policy_up || { logger -t tkproxy "策略路由添加失败"; return 1; }
	watchdog

	# DNS 桥：只依赖网桥 IP，不依赖 xray 是否就绪，开机必须拉起来。
	# 历史 bug：函数有定义但没有任何调用点 → 重启后桥不启动，客户端能连 WiFi 但网页全打不开。
	start_dnsbridge

	# 解析 xray 二进制路径
	XRAY=$(command -v xray 2>/dev/null || echo /usr/bin/xray)
	if [ ! -x "$XRAY" ]; then
		logger -t tkproxy "未找到 xray 二进制（查找路径：$XRAY）"
		return 1
	fi

	# DNS 桥：把客户端 UDP DNS 转成 TCP DNS 经该线路出口出去
# 为什么需要：很多机场节点只转发 TCP 不转发 UDP，原来 xray 的 dokodemo DNS 入站
# 把客户端的 UDP 原样发给上游会被节点吞掉，客户端表现为「连上 WiFi 打不开网页」。

# 配置校验（run -test）
	_test_out=$("$XRAY" run -test -c "$CFG" 2>&1) || {
		logger -t tkproxy "xray.json 未通过 run -test 校验："
		printf '%s\n' "$_test_out" | logger -t tkproxy
		printf '%s\n' "$_test_out" >&2
		return 1
	}

	# 启动前先清掉所有指向本方案配置的旧 xray 进程。
	# 坑：升级/重复部署时旧进程可能不在 pidfile 里，会继续占着 5301-5330（DNS 口），
	# 导致 DNS 桥绑定失败 → 客户端 DNS 全断。实测踩过。
	for _p in $(pidof xray 2>/dev/null); do
		_cmd=$(tr ' ' ' ' < "/proc/$_p/cmdline" 2>/dev/null || true)
		case "$_cmd" in
			*/etc/tkproxy/xray.json*) kill -9 "$_p" 2>/dev/null && logger -t tkproxy "已清理旧 xray 进程 $_p" || true ;;
		esac
	done
	sleep 1

	# 后台启动 Xray，生成 PID 文件和日志
	mkdir -p /tmp/tkproxy 2>/dev/null
	"$XRAY" run -c "$CFG" >>/tmp/tkproxy/xray.log 2>&1 &
	XRAY_PID=$!
	echo "$XRAY_PID" > /var/run/xray.pid

	# 3 秒内轮询进程是否存活
	_alive=0
	_i=0
	while [ "$_i" -lt 6 ]; do
		sleep 0.5 2>/dev/null || sleep 1
		if pgrep -f "xray run -c $CFG" >/dev/null 2>&1; then
			_alive=1
			break
		fi
		_i=$((_i + 1))
	done
	if [ "$_alive" != "1" ]; then
		logger -t tkproxy "Xray 进程在启动后 3 秒内退出，xray.log 尾部："
		tail -20 /tmp/tkproxy/xray.log 2>/dev/null | logger -t tkproxy
		stop_xray
		return 1
	fi

	# 从 manifest.json 获取所有端口（tproxy + probe + DNS）
	MANIFEST=/etc/tkproxy/manifest.json
	if [ ! -s "$MANIFEST" ]; then
		logger -t tkproxy "manifest.json 缺失，无法获取端口"
		stop_xray
		return 1
	fi
	# 按 manifest 每项的 port（tproxy）、index（22000+index probe、5300+index DNS）逐项取端口
	PORTS=$(awk '
		/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
		in_arr && /^[[:space:]]*\]/ { in_arr=0 }
		in_arr && /"port"[[:space:]]*:/ {
			v=$0; sub(/.*"port"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 > 0) tproxy[v+0]=1
		}
		in_arr && /"index"[[:space:]]*:/ {
			v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 >= 0) { probe[22000 + v+0]=1; dns[5300 + v+0]=1 }
		}
		END {
			for (p in tproxy) printf "%s ", p
			for (p in probe) printf "%s ", p
			for (p in dns) printf "%s ", p
		}
	' "$MANIFEST" 2>/dev/null)
	if [ -z "$PORTS" ]; then
		logger -t tkproxy "manifest.json 里没有 ssids 端口配置"
		stop_xray
		return 1
	fi
	[ -n "$PORTS" ] || { logger -t tkproxy "未能生成端口列表"; stop_xray; return 1; }
	# 先加载 nft 规则，再等端口：
	#   - 隔离/tproxy 规则必须尽早到位，宁可端口没起来时流量被丢弃（fail closed），
	#     也不能出现"WiFi 能用但流量直连出去"的裸奔窗口
	#   - 之前是等端口 15s → 超时直接 stop_xray 且不加载 nft，导致开机后
	#     30 条线路全部变成直连（TikTok 环境被污染），日志里也只剩一句超时
	nft delete table inet tkproxy >/dev/null 2>&1 || true
	if ! nft -f "$NFT_FILE"; then
		logger -t tkproxy "nft 加载失败，确认已装 kmod-nft-tproxy"
		stop_xray
		return 1
	fi
	# 端口就绪检查：30 条线路 = 60 个端口，开机时 15s 往往不够，放宽到 60s
	i=0
	ok=0
	while [ "$i" -lt 60 ]; do
		ok=1
		for p in $PORTS; do
			port_up "$p" || { ok=0; break; }
		done
		[ "$ok" = "1" ] && break
		i=$((i + 1))
		sleep 1
	done
	if [ "$ok" != "1" ]; then
		logger -t tkproxy "等待 Xray 端口监听超时（60s），转后台复查（规则已加载，不会直连泄漏）"
		(
			_j=0
			while [ "$_j" -lt 60 ]; do
				sleep 5
				_j=$((_j + 1))
				_bad=0
				for p in $PORTS; do
					port_up "$p" || { _bad=1; break; }
				done
				if [ "$_bad" = "0" ]; then
					logger -t tkproxy "后台复查：全部端口已就绪（约 $_j x 5s）"
					exit 0
				fi
			done
			logger -t tkproxy "后台复查：5 分钟内端口仍未全部就绪，请检查 /tmp/tkproxy/xray.log"
		) &
		# 开箱自检：xray 就绪路径同样拉起（有 24h 节流与并发锁，重复拉起无害）
		bootcheck_kick
		return 0
	fi
	# 开箱自检：xray 就绪后异步拉起（t_d32788de）
	bootcheck_kick
	return 0
}

stop_xray() {
	# 解析 xray 二进制路径（与 start_service 一致）
	XRAY=$(command -v xray 2>/dev/null || echo /usr/bin/xray)
	# 读取 PID 文件，校验进程是 $XRAY run -c $CFG，然后终止
	if [ -f /var/run/xray.pid ]; then
		XRAY_PID=$(cat /var/run/xray.pid 2>/dev/null || true)
		if [ -n "$XRAY_PID" ] && [ "$XRAY_PID" -gt 0 ] 2>/dev/null; then
			# 校验 PID 对应的进程是否是 $XRAY run -c $CFG
			if kill -0 "$XRAY_PID" 2>/dev/null; then
				# 发信号前必须验证为目标 Xray
				if [ ! -f "/proc/$XRAY_PID/cmdline" ]; then
					# cmdline 不存在，只清理失效 PID 文件，禁止发送信号
					rm -f /var/run/xray.pid
					return 0
				fi
				_cmdline=$(tr '\0' ' ' < "/proc/$XRAY_PID/cmdline" 2>/dev/null || true)
				if [ -z "$_cmdline" ]; then
					# cmdline 读取失败，只清理失效 PID 文件，禁止发送信号
					rm -f /var/run/xray.pid
					return 0
				fi
				_cmdline_trimmed=$(printf '%s' "$_cmdline" | sed 's/[[:space:]]*$//')
				_expected="$XRAY run -c $CFG"
				if [ "$_cmdline_trimmed" != "$_expected" ]; then
					# 完整 argv 不匹配，只清理失效 PID 文件，禁止发送信号
					rm -f /var/run/xray.pid
					return 0
				fi
				# 先尝试 TERM
				kill -TERM "$XRAY_PID" 2>/dev/null || true
				_i=0
				while [ "$_i" -lt 3 ]; do
					kill -0 "$XRAY_PID" 2>/dev/null || break
					_i=$((_i + 1))
					sleep 1
				done
				# 如果还在，KILL 前重新校验 cmdline（PID 可能已被复用）
				if kill -0 "$XRAY_PID" 2>/dev/null; then
					if [ -f "/proc/$XRAY_PID/cmdline" ]; then
						_cmdline=$(tr '\0' ' ' < "/proc/$XRAY_PID/cmdline" 2>/dev/null || true)
						_cmdline_trimmed=$(printf '%s' "$_cmdline" | sed 's/[[:space:]]*$//')
						if [ -n "$_cmdline" ] && [ "$_cmdline_trimmed" = "$_expected" ]; then
							kill -KILL "$XRAY_PID" 2>/dev/null || true
							sleep 1
						fi
					fi
				fi
			fi
		fi
		rm -f /var/run/xray.pid
	fi
}

stop_service() {
	# 关键：先落「维护中」标记。看门狗发现 xray 没了会立刻把服务重新拉起来，
	# 直接和 stop 互斗——现象就是 opkg remove / init stop 卡住十几分钟不返回。
	mkdir -p /tmp/tkproxy 2>/dev/null
	: > /tmp/tkproxy/.paused
	# 再收掉看门狗，并等它真正退出（它可能正睡在 sleep 60 里）
	if [ -s /var/run/tkproxy-watchdog.pid ]; then
		_wd=$(cat /var/run/tkproxy-watchdog.pid 2>/dev/null)
		kill "$_wd" 2>/dev/null || true
		_i=0
		while kill -0 "$_wd" 2>/dev/null && [ "$_i" -lt 6 ]; do
			_i=$((_i + 1))
			sleep 0.5 2>/dev/null || sleep 1
		done
		kill -9 "$_wd" 2>/dev/null || true
		rm -f /var/run/tkproxy-watchdog.pid
	fi
	stop_xray
	policy_down
}
INITEOF

# apply.sh 运行时的 DNS 桥启动器。
# 注意：上面 1774-2121 行那段 start_dnsbridge 是写进 /etc/init.d/tkproxy 的
# INITEOF heredoc 内容，对 apply.sh 自己不可见（以前调用直接 "not found"，
# 靠 service restart 兜底；25.12 上兜底那条 nohup 也没了就成了真故障）。
# 这里给 apply.sh 运行时补一份同逻辑实现。
start_dnsbridge() {
	[ -f /usr/libexec/tkproxy/dnsbridge.lua ] || return 0
	# 开机阶段网桥可能还没拿到 10.11.x.1（netifd 还在建桥），先等最多 40 秒，
	# 否则绑定全失败、客户端 DNS 全断（表现为 WiFi 连上、网页打不开）。
	_w=0
	while [ "$_w" -lt 40 ]; do
		if ip -4 addr show 2>/dev/null | grep -q "10\.11\.[0-9]*\.1/"; then break; fi
		_w=$((_w + 1))
		sleep 1
	done
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	if [ -n "$_pid" ] && [ -d "/proc/$_pid" ]; then
		case "$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null || true)" in
			*dnsbridge.lua*) return 0 ;;
		esac
	fi
	for _p in $(pgrep -f "dnsbridge.lua" 2>/dev/null || true); do
		case "$(tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null || true)" in
			*tkproxy*dnsbridge.lua*) kill -9 "$_p" 2>/dev/null || true ;;
		esac
	done
	mkdir -p /tmp/tkproxy 2>/dev/null || true
	if command -v setsid >/dev/null 2>&1; then
		setsid lua /usr/libexec/tkproxy/dnsbridge.lua >>/tmp/tkproxy/dnsbridge.log 2>&1 &
	else
		lua /usr/libexec/tkproxy/dnsbridge.lua >>/tmp/tkproxy/dnsbridge.log 2>&1 &
	fi
	echo $! > /var/run/tkproxy-dnsbridge.pid
	sleep 1
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	[ -n "$_pid" ] && [ -d "/proc/$_pid" ] && return 0
	logger -t tkproxy "DNS 桥启动失败（见 /tmp/tkproxy/dnsbridge.log）"
	return 0
}


# ---------------------------------------------------------------------------
# uci 标记校验 / 删除
# ---------------------------------------------------------------------------

# 返回 0=存在 1=不存在 2=读取失败（权限/锁）
tkp_sec_exists() {
	if _out=$(uci get "$1" 2>&1 >/dev/null); then
		return 0
	fi
	case "$_out" in
		*"not found"*|*"Entry not found"*|*"No such"*|"") return 1 ;;
		*) printf '%s: 错误：读取 uci %s 失败：%s\n' "$PROG" "$1" "$_out" >&2; return 2 ;;
	esac
}

tkp_marker() {
	uci -q get "$1.tkproxy" 2>/dev/null || true
}

tkp_del_marked() {
	_sec=$1
	if tkp_sec_exists "$_sec"; then
		:
	else
		_st=$?
		if [ "$_st" -eq 1 ]; then return 0; fi
		die "读取 $_sec 失败，无法确认 tkproxy 标记，拒绝删除"
	fi
	_m=$(tkp_marker "$_sec")
	if [ "$_m" != "1" ]; then
		# firewall 段不再打 tkproxy 标记（fw4 会报 unknown option），按段名前缀放行
		_t=${_sec%%.*}
		_n=${_sec#*.}
		case "$_t:$_n" in
			firewall:tkp[0-9]*) uci delete "$_sec" 2>/dev/null || die "删除 $_sec 失败（权限/锁）"; return 0 ;;
		esac
		die "拒绝删除 $_sec：该段已存在但缺少 tkproxy=1 标记（实际：${_m:-<空>}）"
	fi
	uci delete "$_sec" 2>/dev/null || die "删除 $_sec 失败（权限/锁）"
}

# 新部署要用的段名：已存在且没有我们的标记就立即中止
tkp_new_names() {
	_if=$(tkp_ifname "$1")
	_brn=$(tkp_brname "$1")
	printf '%s\n' \
		"network.$_brn" "network.$_if" "dhcp.$_if" "firewall.$_if" \
		"firewall.${_if}_dns" "firewall.${_if}_admin" \
		"wireless.${_if}_2g" "wireless.${_if}_5g"
}

tkp_legacy_names() {
	_s=$1
	printf '%s\n' \
		"network.$_s" "network.br_$_s" "dhcp.$_s" "firewall.$_s" \
		"firewall.${_s}_dns" "firewall.${_s}_admin" \
		"wireless.${_s}_2g" "wireless.${_s}_5g" "wireless.${_s}_0" "wireless.${_s}_1"
}

say "  uci 标记预检"
_NEW_NAMES=$WORK/new_names
: >"$_NEW_NAMES"
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	tkp_new_names "$idx" >>"$_NEW_NAMES"
done <<EOF
$PLAN
EOF
while read -r _n; do
	[ -n "$_n" ] || continue
	if tkp_sec_exists "$_n"; then
		_m=$(tkp_marker "$_n")
		# firewall 段不再打 tkproxy 标记（fw4 会报 unknown option），按段名前缀放行
		case "${_n%%.*}:${_n#*.}" in
			firewall:tkp[0-9]*) _m=1 ;;
		esac
		[ "$_m" = "1" ] || die "拒绝覆盖 $_n：该段已存在且缺少 tkproxy=1 标记（疑似系统配置，已中止）"
	else
		_st=$?
		[ "$_st" -eq 1 ] || die "读取 $_n 失败，拒绝继续"
	fi
done <"$_NEW_NAMES"
for _s in $OLD_SLUGS; do
	for _n in $(tkp_legacy_names "$_s"); do
		if tkp_sec_exists "$_n"; then
			_m=$(tkp_marker "$_n")
			[ "$_m" = "1" ] || warn "旧段 $_n 缺少 tkproxy=1 标记，跳过（不会删除）"
		else
			_st=$?
			[ "$_st" -eq 1 ] || die "读取 $_n 失败，拒绝继续"
		fi
	done
done
say "  标记预检通过"

# ---------------------------------------------------------------------------
# 备份 → 原子替换文件 → 写 uci
# ---------------------------------------------------------------------------

TKP_STEP="== 3. 安装文件（先备份，再原子替换）=="
say "[step $TKP_STEP]"
say "$TKP_STEP"
say "  mkdir -p $BACKUP_DIR"
if ! mkdir -p "$BACKUP_DIR" 2>/dev/null; then
	warn "mkdir 失败"
	warn "  动作：创建备份目录"
	warn "  目标路径：$BACKUP_DIR"
	warn "  ls -l：$(ls -ld "$(dirname "$BACKUP_DIR")" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建备份目录失败"
fi

for _p in network dhcp firewall wireless; do
	say "  备份 uci $_p -> $BACKUP_DIR/uci.$_p"
	uci export "$_p" >"$BACKUP_DIR/uci.$_p" 2>/dev/null || die "备份 uci $_p 失败"
	[ -s "$BACKUP_DIR/uci.$_p" ] || die "uci $_p 备份为空，拒绝部署"
	if [ -f "/etc/config/$_p" ]; then
		say "  cp /etc/config/$_p -> $BACKUP_DIR/raw.$_p"
		if ! cp "/etc/config/$_p" "$BACKUP_DIR/raw.$_p" 2>/dev/null; then
			warn "cp 失败"
			warn "  动作：备份 /etc/config/$_p"
			warn "  目标路径：$BACKUP_DIR/raw.$_p"
			warn "  ls -l：$(ls -l "/etc/config/$_p" 2>&1)"
			warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
			die "备份 /etc/config/$_p 失败"
		fi
	fi
done
if [ -d "$CONF_DIR" ]; then
	say "  cp -R $CONF_DIR -> $BACKUP_DIR/conf"
	if ! cp -R "$CONF_DIR" "$BACKUP_DIR/conf" 2>/dev/null; then
		warn "cp -R 失败"
		warn "  动作：备份 $CONF_DIR"
		warn "  目标路径：$BACKUP_DIR/conf"
		warn "  ls -l：$(ls -ld "$CONF_DIR" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "备份 $CONF_DIR 失败"
	fi
fi
if [ -f "$INIT_FILE" ]; then
	say "  cp $INIT_FILE -> $BACKUP_DIR/init"
	if ! cp "$INIT_FILE" "$BACKUP_DIR/init" 2>/dev/null; then
		warn "cp 失败"
		warn "  动作：备份 $INIT_FILE"
		warn "  目标路径：$BACKUP_DIR/init"
		warn "  ls -l：$(ls -l "$INIT_FILE" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "备份 $INIT_FILE 失败"
	fi
fi
ROLLBACK_ARMED=1
say "  已备份 uci 与 $CONF_DIR"

# 新用户机器上常见 fw3 时代遗留段（passwall/passwall2/shadowsocksr/clash/openclash）：
# 它们不会让 fw4 check 失败（只告警），所以在备份后、文件安装前无条件清一遍（幂等、可回滚）
	_rc=0
	tkp_firewall_autofix >/dev/null 2>&1 || _rc=$?
case "$_rc" in
	0) say "  防火墙遗留段已清理" ;;
	2) say "  防火墙配置干净，无需清理" ;;
	*)
		warn "防火墙遗留段清理失败（rc=$_rc），恢复备份并中止部署"
		tkp_rollback
		die "请手动清理第三方防火墙段或检查权限"
		;;
esac
tkp_firewall_precheck

say "  mkdir -p $CONF_DIR"
if ! mkdir -p "$CONF_DIR" 2>/dev/null; then
	warn "mkdir 失败"
	warn "  动作：创建配置目录"
	warn "  目标路径：$CONF_DIR"
	warn "  ls -l：$(ls -ld "$(dirname "$CONF_DIR")" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建 $CONF_DIR 失败"
fi

# 生成 dnsmasq 配置：为每个接口指定上游 DNS 为该线路落地侧的公网 DNS
# 1. 确保 dnsmasq confdir 存在并已加载
_dnsmasq_confdir="/etc/dnsmasq.d"
if ! uci -q get dhcp.@dnsmasq[0].confdir 2>/dev/null | grep -qE "^/etc/dnsmasq\.d$|,/etc/dnsmasq\.d,|,/etc/dnsmasq\.d$|^/etc/dnsmasq\.d,"; then
	# UCI 未配置 /etc/dnsmasq.d，明确设置
	say "  mkdir -p $_dnsmasq_confdir（UCI 未配置分支）"
	if ! mkdir -p "$_dnsmasq_confdir" 2>/dev/null; then
		warn "mkdir 失败"
		warn "  动作：创建 dnsmasq confdir（UCI 未配置分支）"
		warn "  目标路径：$_dnsmasq_confdir"
		warn "  ls -l：$(ls -ld "$(dirname "$_dnsmasq_confdir")" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "创建 $_dnsmasq_confdir 失败"
	fi
	if ! uci -q get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
		uci add dhcp dnsmasq >/dev/null 2>&1 || die "创建 dhcp.@dnsmasq[0] 失败"
	fi
	uci add_list dhcp.@dnsmasq[0].confdir="$_dnsmasq_confdir" || die "设置 dnsmasq confdir 失败"
	uci commit dhcp || die "提交 dhcp 配置失败"
fi
say "  mkdir -p $_dnsmasq_confdir（兜底确保存在）"
if ! mkdir -p "$_dnsmasq_confdir" 2>/dev/null; then
	warn "mkdir 失败"
	warn "  动作：兜底创建 dnsmasq confdir"
	warn "  目标路径：$_dnsmasq_confdir"
	warn "  ls -l：$(ls -ld "$(dirname "$_dnsmasq_confdir")" 2>&1)"
	warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
	die "创建 $_dnsmasq_confdir 失败"
fi

# 2. 清理旧配置：删除不在当前 PLAN 中的 tkproxy-*.conf
# 注意：白名单必须永远用全量 $PLAN（单条部署时也不例外）——
# 否则其它 29 条线路的 conf 会被误判成孤儿删掉。
_CURRENT_FILES=$WORK/current-dnsmasq-files
: >"$_CURRENT_FILES"
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	_if=$(tkp_ifname "$idx")
	echo "tkproxy-${_if}.conf" >>"$_CURRENT_FILES"
done <<EOF
$PLAN
EOF
for _f in "$_dnsmasq_confdir"/tkproxy-*.conf; do
	[ -e "$_f" ] || continue
	_basename=$(basename "$_f")
	if ! grep -qxF "$_basename" "$_CURRENT_FILES"; then
		rm -f "$_f" 2>/dev/null || warn "清理旧 dnsmasq 配置失败：$_f"
		say "  清理旧 dnsmasq 配置：$_basename"
	fi
done

# 3. 生成每个接口的 dnsmasq 配置（单条部署只重写这一条，其它行的 conf 保持原样）
if [ -n "$ONLY_IDX" ]; then _dnsmasq_plan=$PLAN_ONLY; else _dnsmasq_plan=$PLAN; fi
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	_if=$(tkp_ifname "$idx")
	_brn=$(tkp_brname "$idx")
	_dnsmasq_conf="$_dnsmasq_confdir/tkproxy-${_if}.conf"
	# 按逗号拆分 TK_DNS，每个 DNS 写一行 server=<DNS_IP>
	say "  写入 ${_dnsmasq_conf}.tmp"
	if ! {
		echo "# tkproxy 线路 $_if：DNS 查询经该线路出口解析，禁止回落"
		echo "# 由 apply.sh 生成，不可手工编辑"
		_oldifs=$IFS
		IFS=,
		for _dns_ip in $TK_DNS; do
			IFS=$_oldifs
			echo "server=$_dns_ip"
		done
		IFS=$_oldifs
		echo "no-resolv"
	} >"${_dnsmasq_conf}.tmp" 2>/dev/null; then
		warn "写入失败"
		warn "  动作：生成 dnsmasq 临时配置"
		warn "  目标路径：${_dnsmasq_conf}.tmp"
		warn "  ls -l：$(ls -ld "$_dnsmasq_confdir" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "写入 $_dnsmasq_conf 临时文件失败"
	fi
	say "  mv ${_dnsmasq_conf}.tmp -> $_dnsmasq_conf"
	if ! mv -f "${_dnsmasq_conf}.tmp" "$_dnsmasq_conf" 2>/dev/null; then
		warn "mv 失败"
		warn "  动作：原子替换 dnsmasq 配置"
		warn "  目标路径：$_dnsmasq_conf"
		warn "  ls -l：$(ls -l "${_dnsmasq_conf}.tmp" "$_dnsmasq_conf" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "写入 $_dnsmasq_conf 失败"
	fi
	say "  chmod 0644 $_dnsmasq_conf"
	if ! chmod 0644 "$_dnsmasq_conf" 2>/dev/null; then
		warn "chmod 失败"
		warn "  动作：设置 dnsmasq 配置权限"
		warn "  目标路径：$_dnsmasq_conf"
		warn "  ls -l：$(ls -l "$_dnsmasq_conf" 2>&1)"
		die "设置 $_dnsmasq_conf 权限失败"
	fi
done <<EOF
$_dnsmasq_plan
EOF

tkp_install_file() {
	_src=$1
	_dst=$2
	_mode=$3
	say "  安装 $_dst"
	if [ -L "$_dst" ]; then die "拒绝写入符号链接：$_dst"; fi
	_tmp="${_dst}.new.$$"
	if ! cp "$_src" "$_tmp" 2>/dev/null; then
		warn "cp 失败"
		warn "  目标路径：$_dst"
		warn "  目标目录 ls -l：$(ls -ld "$(dirname "$_dst")" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "cp $_src -> $_dst 失败"
	fi
	# chmod 前采集 ls（失败后才删临时文件，确保诊断有效）
	_tmp_ls=$(ls -l "$_tmp" 2>&1)
	if ! chmod "$_mode" "$_tmp" 2>/dev/null; then
		warn "chmod 失败"
		warn "  目标路径：$_dst"
		warn "  临时文件 ls -l：$_tmp_ls"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		rm -f "$_tmp"
		die "chmod $_mode $_dst 失败"
	fi
	if ! mv -f "$_tmp" "$_dst" 2>/dev/null; then
		warn "mv 失败"
		warn "  目标路径：$_dst"
		warn "  目标目录 ls -l：$(ls -ld "$(dirname "$_dst")" 2>&1)"
		warn "  /overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		rm -f "$_tmp"
		die "mv $_tmp -> $_dst 失败"
	fi
}

# 单条部署优化：安装前先记录"当前已部署"的产物哈希，供安装后比对
_old_xray_md5=$(md5sum "$CONF_DIR/xray.json" 2>/dev/null | cut -d' ' -f1)
_old_nft_md5=$(md5sum "$CONF_DIR/tkproxy.nft" 2>/dev/null | cut -d' ' -f1)

tkp_install_file "$D/xray.json" "$CONF_DIR/xray.json" 0600
tkp_install_file "$Nft" "$CONF_DIR/tkproxy.nft" 0644
tkp_install_file "$D/manifest.json" "$CONF_DIR/manifest.json" 0644
tkp_install_file "$INIT_SRC" "$INIT_FILE" 0755

# 单条部署优化：安装完成后比对产物哈希。xray.json / nft 都没变化时（典型场景：
# 只改了 WiFi 名称或密码），跳过重启 xray 和重载 nft —— 这样"点某一行保存并部署"
# 不会把其它线路的 TikTok 连接一起断掉。
SKIP_XRAY_RESTART=0
SKIP_NFT_RELOAD=0
if [ -n "$ONLY_IDX" ]; then
	_new_xray_md5=$(md5sum "$CONF_DIR/xray.json" 2>/dev/null | cut -d' ' -f1)
	_new_nft_md5=$(md5sum "$CONF_DIR/tkproxy.nft" 2>/dev/null | cut -d' ' -f1)
	if [ -n "$_old_xray_md5" ] && [ "$_old_xray_md5" = "$_new_xray_md5" ]; then
		SKIP_XRAY_RESTART=1
	fi
	if [ -n "$_old_nft_md5" ] && [ "$_old_nft_md5" = "$_new_nft_md5" ]; then
		SKIP_NFT_RELOAD=1
	fi
	[ "$SKIP_XRAY_RESTART" = "1" ] && say "  产物未变化：本次跳过 xray 重启（其它线路不断）"
	[ "$SKIP_NFT_RELOAD" = "1" ] && say "  产物未变化：本次跳过 nft 重载"
fi

# rc.local 兜底：部分固件开机不会执行 S99 脚本，或规则被后续服务清掉。
# 在系统启动末尾再兜一次（幂等：表已存在就什么都不做）。
tkp_rc_local_hook() {
	_h=/etc/rc.local
	[ -f "$_h" ] || return 0
	_line='( sleep 20; [ -f /etc/tkproxy/manifest.json ] || exit 0; pidof xray >/dev/null 2>&1 || /etc/init.d/tkproxy start >/dev/null 2>&1; nft list table inet tkproxy >/dev/null 2>&1 || nft -f /etc/tkproxy/tkproxy.nft >/dev/null 2>&1 ) \& # tkproxy boot-fallback'
	# 幂等：先剔掉旧兜底行，再在 exit 0 之前插入（升级时也能把旧写法换掉）
	awk -v line="$_line" '
		BEGIN { d = 0 }
		index($0, "tkproxy boot-fallback") { next }
		{ if (!d && $0 ~ /^[[:space:]]*exit[[:space:]]+0[[:space:]]*$/) { print line; d = 1 } print }
		END { if (!d) print line }
	' "$_h" > "$_h.tknew" && mv "$_h.tknew" "$_h"
	chmod 755 "$_h" 2>/dev/null
	say "  /etc/rc.local 已加开机兜底"
}
tkp_rc_local_hook

say "  $CONF_DIR/xray.json (0600)"
say "  $CONF_DIR/tkproxy.nft (0644)"
say "  $CONF_DIR/manifest.json (0644)"
say "  $INIT_FILE (0755，内置安全版本)"

# ---------------------------------------------------------------------------
# 写 uci：先删所有带标记的段，再逐条 set/add_list
# ---------------------------------------------------------------------------

tkp_set() {
	uci set "$1=$2" >/dev/null 2>&1 || die "uci set $1 失败"
}
tkp_add_list() {
	uci add_list "$1=$2" >/dev/null 2>&1 || die "uci add_list $1 失败"
}

TKP_STEP="== 4. 写 network / dhcp / firewall / wireless =="
say "[step $TKP_STEP]"
say "$TKP_STEP"

# 记录改动前的 DHCP/DNS 配置指纹：部署完如果一模一样，就不用重启 dnsmasq。
# 只有「改名字/改密码/换节点」这类不动网段的操作才会命中；加删线路必然变化，照旧重启。
tkp_dhcp_fp() {
	{
		uci -q export dhcp 2>/dev/null
		uci -q export network 2>/dev/null | grep -E "^(network\.(br_|tkp|brtk))"
		for _f in /etc/dnsmasq.d/tkproxy-*.conf; do
			[ -f "$_f" ] && { printf '%s|' "$_f"; cat "$_f"; }
		done
	} | sort | md5sum | cut -d' ' -f1
}
_OLD_DHCP_FP=$(tkp_dhcp_fp)

if [ -z "$ONLY_IDX" ]; then  # 单条部署时不做全局清理
# 4a. 先删所有打了 tkproxy=1 的段（只认标记，绝不按名字猜）
for _cfg in network dhcp firewall wireless; do
	uci -q show "$_cfg" >/dev/null 2>&1 || die "读取 uci $_cfg 失败"
	for _sec in $(uci -q show "$_cfg" 2>/dev/null \
		| sed -n "s/^\(${_cfg}\.[^.=]*\)\.tkproxy=[']*1[']*$/\1/p"); do
		tkp_del_marked "$_sec"
	done
done

# 4a-2. firewall 段不再带 tkproxy 标记（会被 fw4 报 unknown option），
#        这里按段名前缀清理「本次清单里没有」的孤儿段，避免删线路后规则残留。
KEEP_FW=""
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	_keep=$(tkp_ifname "$idx")
	KEEP_FW="$KEEP_FW ${_keep} ${_keep}_dns ${_keep}_admin"
done <<EOF
$PLAN
EOF
for _sec in $(uci -q show firewall 2>/dev/null | sed -n 's/^firewall\.\([^.=]*\)=.*/\1/p'); do
	case "$_sec" in
		tkp[0-9]*)
			case " $KEEP_FW " in
				*" $_sec "*) ;;
				*) uci -q delete "firewall.$_sec" && say "  清理孤儿防火墙段：$_sec" ;;
			esac
			;;
	esac
done

# 4b. 新部署的段名再做一次严格删除（存在但无标记会直接中止）
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	for _n in $(tkp_new_names "$idx"); do
		tkp_del_marked "$_n"
	done
done <<EOF
$PLAN
EOF

fi

# 4c. 逐条写入；所有值都来自上面已校验的变量
# 单条部署直接用裁剪后的计划，从源头保证其它线路不被触碰
if [ -n "$ONLY_IDX" ]; then _uci_plan=$PLAN_ONLY; else _uci_plan=$PLAN; fi
while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
	[ -n "$idx" ] || continue
	if [ -n "$ONLY_IDX" ] && [ "$idx" != "$ONLY_IDX" ]; then continue; fi
	_if=$(tkp_ifname "$idx")
	_brn=$(tkp_brname "$idx")
	_dns_port=$((5300 + idx))

	# network：桥设备 + 静态接口（只配置网关地址）
	tkp_set "network.$_brn" device
	tkp_set "network.$_brn.name" "$_brn"
	tkp_set "network.$_brn.type" bridge
	tkp_set "network.$_brn.stp" 0
	tkp_set "network.$_brn.tkproxy" 1
	tkp_set "network.$_if" interface
	tkp_set "network.$_if.device" "$_brn"
	tkp_set "network.$_if.proto" static
	tkp_set "network.$_if.ipaddr" "$gw/24"
	tkp_set "network.$_if.delegate" 0
	tkp_set "network.$_if.metric" "$((100 + idx))"
	tkp_set "network.$_if.tkproxy" 1

	# dhcp：DNS 下发网关地址（由 dnsmasq 在该接口提供 DNS 服务）；IPv6 全关
	tkp_set "dhcp.$_if" dhcp
	tkp_set "dhcp.$_if.interface" "$_if"
	tkp_set "dhcp.$_if.start" 100
	tkp_set "dhcp.$_if.limit" 50
	tkp_set "dhcp.$_if.leasetime" 12h
	tkp_set "dhcp.$_if.dhcpv4" server
	tkp_set "dhcp.$_if.dhcpv6" disabled
	tkp_set "dhcp.$_if.ra" disabled
	tkp_set "dhcp.$_if.ndp" disabled
	tkp_set "dhcp.$_if.tkproxy" 1

	# firewall：独立 zone，SSID 之间三层隔离
	tkp_set "firewall.$_if" zone
	tkp_set "firewall.$_if.name" "$_if"
	tkp_set "firewall.$_if.input" ACCEPT
	tkp_set "firewall.$_if.output" ACCEPT
	tkp_set "firewall.$_if.forward" REJECT
	tkp_set "firewall.$_if.masq" 0
	tkp_set "firewall.$_if.mtu_fix" 0
	tkp_add_list "firewall.$_if.network" "$_if"
	tkp_set "firewall.${_if}_dns" rule
	tkp_set "firewall.${_if}_dns.name" "${_if}-block-local-dns"
	tkp_set "firewall.${_if}_dns.src" "$_if"
	tkp_set "firewall.${_if}_dns.dest_ip" "$gw"
	tkp_set "firewall.${_if}_dns.dest_port" 53
	tkp_set "firewall.${_if}_dns.proto" "tcp udp"
	tkp_set "firewall.${_if}_dns.target" REJECT
	tkp_set "firewall.${_if}_admin" rule
	tkp_set "firewall.${_if}_admin.name" "${_if}-block-admin"
	tkp_set "firewall.${_if}_admin.src" "$_if"
	tkp_set "firewall.${_if}_admin.dest_ip" "$gw $TK_ADMIN_IP"
	tkp_set "firewall.${_if}_admin.dest_port" "22 80 443"
	tkp_set "firewall.${_if}_admin.proto" tcp
	tkp_set "firewall.${_if}_admin.target" REJECT

	# wireless：按每条 SSID 的 band 决定落哪颗射频
	case "$band" in
		both) _bands="2g 5g" ;;
		2g) _bands="2g" ;;
		5g) _bands="5g" ;;
	esac
	for _b in $_bands; do
		case "$_b" in
			2g) _dev=$RADIO_2G ;;
			5g) _dev=$RADIO_5G ;;
		esac
		tkp_set "wireless.${_if}_$_b" wifi-iface
		tkp_set "wireless.${_if}_$_b.device" "$_dev"
		tkp_set "wireless.${_if}_$_b.network" "$_if"
		tkp_set "wireless.${_if}_$_b.mode" ap
		tkp_set "wireless.${_if}_$_b.ssid" "$ssid"
		tkp_set "wireless.${_if}_$_b.encryption" psk2
		# 这条线路自己的 WiFi 密码优先（产物 wifi.keys：<idx> <key>），没有才用全局 wifi.key
		_ifkey=$TK_WIFI_KEY
		if [ -f "$D/wifi.keys" ]; then
			_k=$(awk -v i="$idx" '$1==i{print $2; exit}' "$D/wifi.keys" 2>/dev/null)
			[ -n "$_k" ] && _ifkey="$_k"
		fi
		tkp_set "wireless.${_if}_$_b.key" "$_ifkey"
		tkp_set "wireless.${_if}_$_b.isolate" 1
		tkp_set "wireless.${_if}_$_b.disabled" 0
		tkp_set "wireless.${_if}_$_b.tkproxy" 1
	done

	# bridge isolate：AP 间客户端互访禁止
	tkp_set "network.$_if.type" bridge
	tkp_set "network.$_if.isolate" 1

	# IPv6 防泄漏：禁用 tkpNN 接口的 IPv6
	tkp_set "network.$_if.ipv6" 0
done <<EOF
$_uci_plan
EOF

for _p in network dhcp firewall wireless; do
	uci commit "$_p" || die "uci commit $_p 失败"
done
# 单条部署时 SLUGS 已在步骤 1 被裁成 1 条，这里如实反映实际写入数
say "  已写入 $(printf '%s\n' "$SLUGS" | wc -w | tr -d ' ') 个 SSID 的 network/dhcp/firewall/wireless"

# ---------------------------------------------------------------------------
# 生效 + 健康检查（失败自动回滚）
# ---------------------------------------------------------------------------

if [ "${TKP_NO_RELOAD:-0}" = "1" ]; then
	TKP_STEP="== 5. 生效（TKP_NO_RELOAD=1，跳过）=="
	say "[step $TKP_STEP]"
	say "$TKP_STEP"
	ROLLBACK_ARMED=0
	exit 0
fi

TKP_STEP="== 5. 生效 =="
say "[step $TKP_STEP]"
say "$TKP_STEP"
if [ -x /etc/init.d/network ]; then
	TKP_STEP="生效:network reload"
	say "[step $TKP_STEP]"
	if _out=$(/etc/init.d/network reload 2>&1); then
		_rc=0
	else
		_rc=$?
	fi
	printf '%s\n' "$_out" | grep -v 'udhcpc:' | sed 's/^/    /'
	if [ "$_rc" != "0" ]; then
		warn "失败命令：/etc/init.d/network reload"
		warn "退出码：$_rc"
		printf '%s\n' "$_out" | tail -10 | sed 's/^/    /' >&2
		warn "/overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		warn "目标路径：$(ls -ld /etc/config/network 2>&1)"
		die "步骤 [生效:network reload] 失败"
	fi
fi
	TKP_STEP="生效:wireless reload"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	_wifi_log=/tmp/tkproxy/wifi-reload.log
	_rc=0
	_wifi_action=reload
	# 单条部署用 reconf 增量生效：netifd 只重建有变化的无线接口，其它 SSID 不掉线
	# （reload 会把整颗射频拉掉再拉起，30 条线路时 = 全部 SSID 断一次，t_3dfd2e0c 缺陷 3）
	if [ -n "$ONLY_IDX" ]; then _wifi_plan=$PLAN_ONLY; else _wifi_plan=$PLAN; fi
	if [ -n "$ONLY_IDX" ]; then
		# 只探测 reconf 子命令是否存在（wifi --help 2>&1 里找 reconf），不真跑
		if wifi --help 2>&1 | grep -qw reconf; then
			_wifi_action=reconf
		else
			warn "本机 wifi 不支持 reconf，退回 reload（其它 SSID 会短暂掉线）"
		fi
	fi
	say "  无线生效方式：wifi $_wifi_action"
	if [ "$_wifi_action" = "reconf" ]; then
		run_with_timeout 45 "$_wifi_log" wifi reconf || _rc=$?
	elif command -v wifi >/dev/null 2>&1; then
		run_with_timeout 45 "$_wifi_log" wifi reload || _rc=$?
	elif [ -x /sbin/wifi ]; then
		run_with_timeout 45 "$_wifi_log" /sbin/wifi reload || _rc=$?
	else
		die "找不到 wifi 命令，无法让无线配置生效"
	fi

	# wifi reload 在部分机型即使成功也返回非零；改为宽松判定：
	# 超时 124 → 失败；其他退出码 → 继续轮询等待
	if [ "$_rc" = "124" ]; then
		warn "失败命令：wifi $_wifi_action"
		warn "退出码：$_rc（超时）"
		tail -20 "$_wifi_log" 2>/dev/null | sed 's/^/    /' >&2
		warn "/overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "步骤 [生效:wireless reload] 超时"
	fi

	# 无线重建后 netifd 可能把桥的 IPv4 地址丢掉（真机实测：单条部署后 brtk01 只剩
	# IPv6 link-local，dnsmasq 因此没有 10.11.1.0/24 可服务 → 客户端关联成功却拿不到 IP）。
	# 这里逐条校验桥地址并补回，避免"能连上但上不了网/连不上"的静默故障。
	_ipfix=0
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		[ -n "$gw" ] || continue
		# 桥名一律按 tkp_brname 归一（brtk01 补零）；计划里若给的是 brtk1，
		# 直接拿它去查会永远查不到地址，自愈就成了空转（25.12 实测踩过）。
		br=$(tkp_brname "$idx")
		ip -4 addr show dev "$br" 2>/dev/null | grep -q "inet $gw/" && continue
		warn "  $br 缺少地址 $gw，重新拉起 interface tkp$idx"
		ifup "tkp$idx" >/dev/null 2>&1 || true
		sleep 1
		if ip -4 addr show dev "$br" 2>/dev/null | grep -q "inet $gw/"; then
			_ipfix=$((_ipfix + 1))
		else
			warn "  $br 仍无地址，请检查 /etc/config/network 的 network.tkp$idx"
		fi
	done <<PLANIPEOF
$_wifi_plan
PLANIPEOF
	[ "$_ipfix" -gt 0 ] && say "  已补回 $_ipfix 个桥地址"

	# 统计期望 AP 数（计划里每条 band=both 算 2 个，2g/5g 各算 1 个）
	# 全量部署期望的是「全机 AP 总数」；单条部署只等这条线自己的 AP 起来
	_expected_ap=0
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		case "$band" in
			both) _expected_ap=$((_expected_ap + 2)) ;;
			2g|5g) _expected_ap=$((_expected_ap + 1)) ;;
		esac
	done <<WIFIPLAN
$_wifi_plan
WIFIPLAN

	# 轮询等待：最多 TKP_WIFI_WAIT_MAX 秒，每 3 秒检测一次 AP 数量
	_i=0
	_actual_ap=0
	_last_have=-1
	while [ "$_i" -lt "$TKP_WIFI_WAIT_MAX" ]; do
		_actual_ap=$(iw dev 2>/dev/null | grep -cE "phy[01]-ap[0-9]+")
		_actual_ap=${_actual_ap:-0}
		# 仅当数值变化时打印，避免刷屏
		if [ "$_actual_ap" != "$_last_have" ]; then
			say "  等待无线就绪 ${_i}s（当前 AP ${_actual_ap} / 期望 ${_expected_ap}）"
			_last_have=$_actual_ap
		fi
		if [ "$_actual_ap" -ge "$_expected_ap" ]; then
			say "  无线已就绪：${_actual_ap} 个 AP"
			break
		fi
		sleep 3
		_i=$((_i + 3))
	done

	# 等待上限后最后一次统计（避免错过最后时间窗口内达标的情况）
	if [ "$_i" -ge "$TKP_WIFI_WAIT_MAX" ]; then
		_actual_ap=$(iw dev 2>/dev/null | grep -cE "phy[01]-ap[0-9]+")
		_actual_ap=${_actual_ap:-0}
	fi

	# 超时仍未达到期望
	if [ "$_actual_ap" -lt "$_expected_ap" ]; then
		warn "失败命令：wifi $_wifi_action + 轮询等待（超时 ${TKP_WIFI_WAIT_MAX}s）"
		warn "  期望 AP 数：$_expected_ap"
		warn "  实际 AP 数：$_actual_ap"
		warn "  ===== wifi $_wifi_action 日志尾 20 行 ====="
		tail -20 "$_wifi_log" 2>/dev/null | sed 's/^/    /' >&2
		warn "  ===== 日志结束 ====="
		warn "/overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		die "步骤 [生效:wireless reload] 失败（等待 ${TKP_WIFI_WAIT_MAX}s 后 AP 数量仍不足）"
	fi

	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  耗时：${_elapsed}s"
if [ -z "$ONLY_IDX" ]; then  # 单条部署无需重启 dnsmasq
if [ -x /etc/init.d/dnsmasq ]; then
	TKP_STEP="生效:dnsmasq restart"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	_rc=0
	_NEW_DHCP_FP=$(tkp_dhcp_fp)
	if [ -n "$_OLD_DHCP_FP" ] && [ "$_NEW_DHCP_FP" = "$_OLD_DHCP_FP" ]; then
		# DHCP/网段/每线路 DNS 一项都没变（改 SSID 名、改密码、换节点就是这种）：
		# 只让 dnsmasq 重读配置，不整体重启——省掉 100 秒，客户端也不会掉 IP。
		if command -v killall >/dev/null 2>&1; then
			killall -HUP dnsmasq 2>/dev/null || true
		fi
		say "  DHCP/DNS 配置未变化：不重启 dnsmasq（已发 SIGHUP 重读，约 1 秒）"
		say "  指纹：$_NEW_DHCP_FP"
		_end=$(date +%s)
		say "  耗时：$((_end - _start))s"
		_rc=0
		_dnsmasq_skipped=1
	else
	say "  DHCP/DNS 配置有变化（或首次部署）：正常重启 dnsmasq"
	# t_3dfd2e0c 缺陷 1：dnsmasq restart 产生新守护进程，不能继承锁 fd
	# 内联 ()（理由见 tkp_drop_lock_exec 注释）；dnsmasq restart 是前台命令，直接跑不会留副本
	if [ "$USE_FLOCK" = "1" ]; then
		if ! _out=$( (exec 9>&- 2>/dev/null; /etc/init.d/dnsmasq restart) 2>&1 ); then
			_rc=$?
		fi
	else
		if ! _out=$(/etc/init.d/dnsmasq restart 2>&1); then
			_rc=$?
		fi
	fi
	fi
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	printf '%s\n' "$_out" | grep -v 'udhcpc:' | sed 's/^/    /'
	say "  耗时：${_elapsed}s"
	if [ "$_rc" != "0" ]; then
		warn "失败命令：/etc/init.d/dnsmasq restart"
		warn "退出码：$_rc"
		printf '%s\n' "$_out" | tail -10 | sed 's/^/    /' >&2
		warn "/overlay 可用空间：$(df -h /overlay 2>&1 | tail -1)"
		warn "目标路径：$(ls -ld /etc/init.d/dnsmasq 2>&1)"
		die "步骤 [生效:dnsmasq restart] 失败"
	fi
fi
fi

# ---- d2. 网桥地址自愈公共函数（xray 启动前自愈 / 绑定失败重试 / e1b 二次核对共用）----
# 真机实测：netifd 抖动（单条部署 wifi reconf、临时加线路）会让 brtkNN 短暂丢失
# 10.11.N.1/24；xray 这时启动会 bind 失败（cannot assign requested address）→ 部署回滚。
# 这里在启动 xray 之前强制保证所有 tkp* 网桥都有地址；
# 自愈任何一步失败都只 warn + 继续（set -e 下不能把部署弄死）。
tkp_secs() {           # 输出所有 tkpNN 段名（不带 network. 前缀）
	uci -q show network 2>/dev/null | sed -n 's/=interface$//p' | cut -d. -f2 | grep -E '^tkp[0-9]+$' || true
}
tkp_bridge_ip_of() {   # <device> → 期望的 ipaddr（来自 uci）
	local d="$1" sec ipa
	for sec in $(tkp_secs); do
		if [ "$(uci -q get "network.$sec.device" 2>/dev/null)" = "$d" ]; then
			ipa=$(uci -q get "network.$sec.ipaddr" 2>/dev/null) || true
			printf '%s' "$ipa"
			return 0
		fi
	done
	return 0
}
tkp_bridge_ok() {      # <device> → 0=地址在
	local d="$1" ipa
	ipa=$(tkp_bridge_ip_of "$d")
	[ -n "$ipa" ] || return 0
	ip -4 addr show "$d" 2>/dev/null | grep -q "inet ${ipa}"
}
tkp_bridge_missing() { # → 输出缺地址的设备列表
	local _dev _out=""
	for _dev in $1; do
		tkp_bridge_ok "$_dev" || _out="$_out $_dev"
	done
	printf '%s' "$_out"
}
# tkp_bridge_heal [<设备列表>] → 自愈到全部有地址或超时（约 20s），返回 0=全部齐 1=仍缺
tkp_bridge_heal() {
	local _devs="$1" _miss _still _dev _sec _wait=0
	[ -n "$_devs" ] || return 0
	_miss=$(tkp_bridge_missing "$_devs")
	if [ -z "$_miss" ]; then
		return 0
	fi
	say "  缺地址的网桥：$_miss → network reload 自愈"
	ubus call network reload >/dev/null 2>&1 || true
	while [ "$_wait" -lt 20 ]; do
		sleep 2
		_wait=$((_wait + 2))
		_still=$(tkp_bridge_missing "$_devs")
		if [ -z "$_still" ]; then
			say "  已通过 network reload 补回（${_wait}s）"
			return 0
		fi
	done
	say "  reload 后 20s 仍缺：$_still → 逐条 ifup"
	for _dev in $_still; do
		for _sec in $(tkp_secs); do
			if [ "$(uci -q get "network.$_sec.device" 2>/dev/null)" = "$_dev" ]; then
				ifup "$_sec" >/dev/null 2>&1 || true
				break
			fi
		done
	done
	_wait=0
	while [ "$_wait" -lt 20 ]; do
		sleep 2
		_wait=$((_wait + 2))
		_still=$(tkp_bridge_missing "$_devs")
		if [ -z "$_still" ]; then
			say "  已通过 ifup 补回（${_wait}s）"
			return 0
		fi
	done
	# 终极手段：/etc/init.d/network restart。真机实测（t_d1519957）：接口被
	# DEVICE_CLAIM_FAILED 卡死时 reload / ifup / ubus up 都无效，只有整体 restart
	# 能让 netifd 重新接管桥设备并配回地址。代价是全部 WAN/LAN 短暂抖动，放在最后。
	if [ -x /etc/init.d/network ]; then
		say "  ifup 后仍缺：$_still → /etc/init.d/network restart（终极手段）"
		/etc/init.d/network restart >/dev/null 2>&1 || true
		_wait=0
		while [ "$_wait" -lt 20 ]; do
			sleep 2
			_wait=$((_wait + 2))
			_still=$(tkp_bridge_missing "$_devs")
			if [ -z "$_still" ]; then
				say "  已通过 network restart 补回（${_wait}s）"
				return 0
			fi
		done
	fi
	warn "  自愈后仍缺地址：$_still（这些 WiFi 的客户端会拿不到 IP，请查 netifd 日志）"
	return 1
}

if [ -x /etc/init.d/firewall ]; then
	# ---- e1b. 网桥地址自愈（wireless reload 之后二次核对；公共函数在 d2 节定义）----
# 真机实测：单条部署（wifi reconf）之后，部分网桥会因 netifd 争用设备
# （DEVICE_CLAIM_FAILED）丢掉 10.11.N.1/24，客户端表现为「WiFi 连上了但拿不到 IP」。
# 这里逐条核对网关地址，缺了就自愈（network reload → 仍缺则逐条 ifup）。
TKP_STEP="生效:网桥地址自愈"
say "[step $TKP_STEP]"
_start=$(date +%s)
_brlist=""
for _sec in $(tkp_secs); do
	_dev=$(uci -q get "network.$_sec.device" 2>/dev/null) || true
	if [ -n "$_dev" ]; then _brlist="$_brlist $_dev"; fi
done
if [ -z "$_brlist" ]; then
	say "  未发现 tkp* 网络接口，跳过"
else
	_miss=$(tkp_bridge_missing "$_brlist")
	if [ -z "$_miss" ]; then
		say "  全部网桥地址齐全"
	else
		tkp_bridge_heal "$_brlist" || true
	fi
fi
_end=$(date +%s)
say "  耗时：$((_end - _start))s"

TKP_STEP="生效:firewall reload"
	say "[step $TKP_STEP]"
	tkp_firewall_reload
fi
	# ---- tkproxy 开机自启（直接建软链）----
	TKP_STEP="生效:tkproxy 开机自启"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	mkdir -p /etc/rc.d 2>/dev/null || die "创建 /etc/rc.d 失败"
	ln -sf "$INIT_FILE" /etc/rc.d/S99tkproxy || die "创建开机自启软链 /etc/rc.d/S99tkproxy 失败"
	if [ ! -L /etc/rc.d/S99tkproxy ]; then
		warn "软链校验失败：/etc/rc.d/S99tkproxy 不存在或不是符号链接"
		warn "  ls -l /etc/rc.d/S99tkproxy：$(ls -l /etc/rc.d/S99tkproxy 2>&1)"
		warn "  INIT_FILE：$INIT_FILE"
		die "开机自启软链创建失败"
	fi
	_target=$(readlink /etc/rc.d/S99tkproxy 2>/dev/null || true)
	if [ "$_target" != "$INIT_FILE" ]; then
		warn "软链目标不符：期望 $INIT_FILE，实际 $_target"
		die "开机自启软链目标错误"
	fi
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  已建开机自启软链：/etc/rc.d/S99tkproxy -> $INIT_FILE"
	say "  耗时：${_elapsed}s"

	# ---- c. nft 加载 ----
	TKP_STEP="生效:nft 加载"
	if [ "$SKIP_NFT_RELOAD" = "1" ]; then
		say "  已跳过 nft 重载（规则未变化，其它线路不受影响）"
	else
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	mkdir -p /tmp/tkproxy 2>/dev/null || true
	# 幂等：先删除已存在的 inet tkproxy 表
	nft delete table inet tkproxy 2>/dev/null || true
	if ! _nft_out=$(nft -f /etc/tkproxy/tkproxy.nft 2>&1); then
		warn "nft 加载失败"
		warn "  命令：nft -f /etc/tkproxy/tkproxy.nft"
		warn "  ===== nft 报错前 40 行 ====="
		printf '%s\n' "$_nft_out" | head -40 | sed 's/^/    /' >&2
		warn "  ===== nft 报错结束 ====="
		warn "  ===== 输出尾 10 行 ====="
		printf '%s\n' "$_nft_out" | tail -10 | sed 's/^/    /' >&2
		warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
		die "步骤 [生效:nft 加载] 失败"
	fi
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  nft 表 inet tkproxy 已加载"
	say "  耗时：${_elapsed}s"
	fi

	# ---- d. 策略路由（幂等：先 del 再 add，忽略 del 失败）----
	TKP_STEP="生效:策略路由"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	ip rule del fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || true
	ip route del local 0.0.0.0/0 dev lo table "$RT_TABLE" 2>/dev/null || true
	_rule_out=$(ip rule add fwmark "$MARK" lookup "$RT_TABLE" 2>&1) || {
		echo "$_rule_out" | grep -q "File exists" || {
			warn "  命令：ip rule add fwmark $MARK lookup $RT_TABLE"
			warn "  输出：$_rule_out"
			warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
			die "添加 ip rule fwmark $MARK lookup $RT_TABLE 失败"
		}
	}
	_route_out=$(ip route add local 0.0.0.0/0 dev lo table "$RT_TABLE" 2>&1) || {
		echo "$_route_out" | grep -q "File exists" || {
			warn "  命令：ip route add local 0.0.0.0/0 dev lo table $RT_TABLE"
			warn "  输出：$_route_out"
			warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
			die "添加 ip route local 0.0.0.0/0 dev lo table $RT_TABLE 失败"
		}
	}
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  策略路由已配置：fwmark $MARK lookup $RT_TABLE"
	say "  耗时：${_elapsed}s"

	# 部署行里出现的网桥设备列表（单条部署 = 本线路的桥；全量 = 全部 tkp*）
	_brlist=""
	for _sec in $(tkp_secs); do
		_dev=$(uci -q get "network.$_sec.device" 2>/dev/null) || true
		if [ -n "$_dev" ]; then _brlist="$_brlist $_dev"; fi
	done

	# ---- e. 停止旧 xray（pidfile + cmdline 精确匹配 → TERM → 最多 3s → KILL）----
	if [ "$SKIP_XRAY_RESTART" = "1" ] && kill -0 "$(cat /var/run/xray.pid 2>/dev/null)" 2>/dev/null; then
		say "  xray.json 未变化且进程存活：跳过停止/重启，其它线路连接不受影响"
	else
	TKP_STEP="生效:停止旧 xray"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	_expected="$XRAY run -c $CONF_DIR/xray.json"

	# 辅助函数：检查 PID 是否匹配预期 cmdline
	_check_xray_cmdline() {
		_pid=$1
		[ -f "/proc/$_pid/cmdline" ] || return 1
		_cmd=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//')
		[ "$_cmd" = "$_expected" ]
	}

	if [ -f /var/run/xray.pid ]; then
		_old_pid=$(cat /var/run/xray.pid 2>/dev/null || true)
		# 合并前置条件：pidfile 有效 && 进程存活 && cmdline 匹配
		if [ -n "$_old_pid" ] && [ "$_old_pid" -gt 0 ] 2>/dev/null && \
		   kill -0 "$_old_pid" 2>/dev/null && _check_xray_cmdline "$_old_pid"; then
			say "  发现旧 xray 进程 $_old_pid，发送 TERM"
			kill -TERM "$_old_pid" 2>/dev/null || true
			_i=0
			while [ "$_i" -lt 3 ]; do
				kill -0 "$_old_pid" 2>/dev/null || break
				_i=$((_i + 1))
				sleep 1
			done
			# TERM 后仍存活且 cmdline 仍匹配 → 发送 KILL
			if kill -0 "$_old_pid" 2>/dev/null && _check_xray_cmdline "$_old_pid"; then
				say "  TERM 未生效，发送 KILL"
				if ! kill -KILL "$_old_pid" 2>/dev/null; then
					warn "失败命令：kill -KILL $_old_pid"
					warn "  ===== xray 日志尾 10 行 ====="
					tail -10 /tmp/tkproxy/xray.log 2>/dev/null | sed 's/^/    /' >&2
					warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
					die "KILL 旧 xray 进程失败"
				fi
				sleep 1
				# 复查：KILL 后仍存活且 cmdline 仍匹配 → 失败
				if kill -0 "$_old_pid" 2>/dev/null && _check_xray_cmdline "$_old_pid"; then
					warn "失败命令：kill -KILL $_old_pid"
					warn "  进程仍存在：$_old_pid"
					warn "  ===== xray 日志尾 10 行 ====="
					tail -10 /tmp/tkproxy/xray.log 2>/dev/null | sed 's/^/    /' >&2
					warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
					die "KILL 后旧 xray 进程仍未退出"
				fi
			fi
		else
			say "  PID $_old_pid 无效或 cmdline 不符（跳过）"
		fi
		rm -f /var/run/xray.pid
	fi
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  旧 xray 已停止"
	say "  耗时：${_elapsed}s"

	# ---- e2. xray 启动前网桥自愈（只在实际要（重）启 xray 时跑；SKIP_XRAY_RESTART 路径不受影响）----
	if [ -n "$_brlist" ]; then
		TKP_STEP="生效:xray 启动前网桥自愈"
		say "[step $TKP_STEP]"
		_start=$(date +%s)
		_miss=$(tkp_bridge_missing "$_brlist")
		if [ -n "$_miss" ]; then
			tkp_bridge_heal "$_brlist" || true
		else
			say "  全部网桥地址齐全"
		fi
		_end=$(date +%s)
		say "  耗时：$((_end - _start))s"
	fi

	# ---- f. 直接启动 xray（绑定失败时自愈网桥后重试一次，t_d1519957 坑 2）----
	TKP_STEP="生效:启动 xray"
	say "[step $TKP_STEP]"
	_start=$(date +%s)
	_xray_bind_retry=0
	while : ; do
	# 先关锁 fd 再启动：否则 xray 继承 fd 9，部署结束后锁仍被持有（t_3dfd2e0c 缺陷 1）
	# 内联 ()：不能用函数包装（busybox ash 函数内 () + & 会多 fork 一层持锁不退的副本，见上方说明）
	if [ "$USE_FLOCK" = "1" ]; then
		(exec 9>&- 2>/dev/null; exec "$XRAY" run -c "$CONF_DIR/xray.json") >>/tmp/tkproxy/xray.log 2>&1 &
	else
		"$XRAY" run -c "$CONF_DIR/xray.json" >>/tmp/tkproxy/xray.log 2>&1 &
	fi
	_xray_pid=$!
	if ! echo "$_xray_pid" > /var/run/xray.pid 2>/dev/null; then
		warn "失败命令：写入 PID 文件 /var/run/xray.pid"
		kill -KILL "$_xray_pid" 2>/dev/null || true
		warn "  ===== xray 日志尾 10 行 ====="
		tail -10 /tmp/tkproxy/xray.log 2>/dev/null | sed 's/^/    /' >&2
		warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
		die "写入 xray PID 文件失败，已终止新进程"
	fi
	say "  xray 已后台启动，PID: $_xray_pid"

	# ---- g. 就绪校验：轮询最多 15s，检查 ①进程 ②tproxy 口数 ③probe 口数 ----
	# 进程提前退出且日志是绑定失败（网桥地址缺失）→ 自愈网桥后重试启动一次
	TKP_STEP="生效:就绪校验"
	say "[step $TKP_STEP]"
	_manifest="$CONF_DIR/manifest.json"
	if [ ! -s "$_manifest" ]; then
		warn "失败命令：检查 manifest.json 是否存在"
		warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
		die "manifest.json 缺失，无法校验端口"
	fi
	_tproxy_ports=$(awk '
		/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
		in_arr && /^[[:space:]]*\]/ { in_arr=0 }
		in_arr && /"port"[[:space:]]*:/ {
			v=$0; sub(/.*"port"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 > 0) print v
		}
	' "$_manifest" 2>/dev/null | wc -l | tr -d ' ')
	_probe_ports=$(awk '
		/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
		in_arr && /^[[:space:]]*\]/ { in_arr=0 }
		in_arr && /"index"[[:space:]]*:/ {
			v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 >= 0) print v
		}
	' "$_manifest" 2>/dev/null | wc -l | tr -d ' ')

	_xray_dead=0
	_i=0
	_ready=0
	while [ "$_i" -lt 15 ]; do
		# ① 进程存在
		if ! kill -0 "$_xray_pid" 2>/dev/null; then
			_xray_dead=1
			break
		fi

		# ② tproxy 口数
		_tproxy_up=0
		if command -v netstat >/dev/null 2>&1; then
			_tproxy_up=$(awk '
				/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
				in_arr && /^[[:space:]]*\]/ { in_arr=0 }
				in_arr && /"port"[[:space:]]*:/ {
					v=$0; sub(/.*"port"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
					if (v+0 > 0) print v
				}
			' "$_manifest" 2>/dev/null | while read -r _p; do
				netstat -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && echo 1
			done | wc -l | tr -d ' ')
		elif command -v ss >/dev/null 2>&1; then
			_tproxy_up=$(awk '
				/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
				in_arr && /^[[:space:]]*\]/ { in_arr=0 }
				in_arr && /"port"[[:space:]]*:/ {
					v=$0; sub(/.*"port"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
					if (v+0 > 0) print v
				}
			' "$_manifest" 2>/dev/null | while read -r _p; do
				ss -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && echo 1
			done | wc -l | tr -d ' ')
		fi

		# ③ probe 口数
		_probe_up=0
		if command -v netstat >/dev/null 2>&1; then
			_probe_up=$(awk '
				/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
				in_arr && /^[[:space:]]*\]/ { in_arr=0 }
				in_arr && /"index"[[:space:]]*:/ {
					v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
					if (v+0 >= 0) print 22000 + v+0
				}
			' "$_manifest" 2>/dev/null | while read -r _p; do
				netstat -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && echo 1
			done | wc -l | tr -d ' ')
		elif command -v ss >/dev/null 2>&1; then
			_probe_up=$(awk '
				/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
				in_arr && /^[[:space:]]*\]/ { in_arr=0 }
				in_arr && /"index"[[:space:]]*:/ {
					v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
					if (v+0 >= 0) print 22000 + v+0
				}
			' "$_manifest" 2>/dev/null | while read -r _p; do
				ss -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && echo 1
			done | wc -l | tr -d ' ')
		fi

		say "  [${_i}s] 进程:活 tproxy口:${_tproxy_up}/${_tproxy_ports} probe口:${_probe_up}/${_probe_ports}"

		if [ "$_tproxy_up" = "$_tproxy_ports" ] && [ "$_probe_up" = "$_probe_ports" ]; then
			_ready=1
			break
		fi

		_i=$((_i + 1))
		sleep 1
	done

	# 绑定失败判定：进程已退出 + 日志尾部是 cannot assign requested address / failed to listen
	# → 网桥地址大概率还没就绪：自愈 → 重试启动一次（只重试一次，仍失败才回滚）
	if [ "$_xray_dead" = "1" ]; then
		_log_tail=$(tail -10 /tmp/tkproxy/xray.log 2>/dev/null || true)
		warn "失败命令：$XRAY run -c $CONF_DIR/xray.json"
		warn "  ===== xray 日志尾 10 行 ====="
		printf '%s\n' "$_log_tail" | sed 's/^/    /' >&2
		warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
		if [ "$_xray_bind_retry" = "0" ] && printf '%s\n' "$_log_tail" | grep -qE "cannot assign requested address|failed to listen"; then
			_xray_bind_retry=1
			warn "  检测到端口绑定失败（网桥地址缺失特征）→ 网桥自愈后重试启动 xray（1 次）"
			tkp_bridge_heal "$_brlist" || true
			# 清掉残留 pidfile，回到启动循环
			rm -f /var/run/xray.pid
			continue
		fi
		die "xray 启动失败（进程退出）"
	fi

	if [ "$_ready" != "1" ]; then
		say "  就绪校验超时（15s）"
		warn "失败命令：就绪校验（tproxy 口 ${_tproxy_up}/${_tproxy_ports}，probe 口 ${_probe_up}/${_probe_ports}）"
		warn "  ===== xray 日志尾 10 行 ====="
		tail -10 /tmp/tkproxy/xray.log 2>/dev/null | sed 's/^/    /' >&2
		warn "  df -h /overlay：$(df -h /overlay 2>&1 | tail -1)"
		die "xray 就绪校验失败（tproxy 口 ${_tproxy_up}/${_tproxy_ports}，probe 口 ${_probe_up}/${_probe_ports}）"
	fi
	break
	done
	_end=$(date +%s)
	_elapsed=$((_end - _start))
	say "  xray 已就绪（tproxy 口 ${_tproxy_ports}，probe 口 ${_probe_ports}）"
	# DNS 桥（UDP→TCP），随 xray 一起拉起
	start_dnsbridge || true
	if [ "$_xray_bind_retry" = "1" ]; then
		say "  经历过一次绑定失败重试"
	fi
	say "  耗时：${_elapsed}s"
	fi

# 单飞健康检查：端口 → 进程 → nft 表 → 实际 BSS 数
tkp_health_ports() {
	if ! command -v netstat >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1; then
		echo "TOOL_MISSING:netstat/ss"
		return 1
	fi
	# 按 manifest 每项的 port（tproxy）和 index（22000+index probe）逐项取端口
	_manifest="$CONF_DIR/manifest.json"
	if [ ! -s "$_manifest" ]; then
		echo "MANIFEST_MISSING"
		return 1
	fi
	_ports=$(awk '
		/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
		in_arr && /^[[:space:]]*\]/ { in_arr=0 }
		in_arr && /"port"[[:space:]]*:/ {
			v=$0; sub(/.*"port"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 > 0) tproxy[v+0]=1
		}
		in_arr && /"index"[[:space:]]*:/ {
			v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
			if (v+0 >= 0) probe[22000 + v+0]=1
		}
		END {
			for (p in tproxy) printf "%s ", p
			for (p in probe) printf "%s ", p
		}
	' "$_manifest" 2>/dev/null)
	if [ -z "$_ports" ]; then
		echo "NO_PORTS_CONFIG"
		return 1
	fi

	_retry=0
	while [ "$_retry" -lt 60 ]; do
		_ok=1
		for _p in $_ports; do
			if command -v netstat >/dev/null 2>&1; then
				netstat -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" || { _ok=0; break; }
			else
				ss -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" || { _ok=0; break; }
			fi
		done
		[ "$_ok" = "1" ] && return 0
		_retry=$((_retry + 1))
		sleep 1
	done
	echo "$_ports"
	return 1
}

tkp_health_xray() {
	if command -v pgrep >/dev/null 2>&1; then
		_pids=$(pgrep -f "xray run -c /etc/tkproxy/xray.json" 2>/dev/null || true)
	elif command -v pidof >/dev/null 2>&1; then
		_pids=$(pidof xray 2>/dev/null || true)
	else
		echo "TOOL_MISSING:pgrep/pidof"
		return 1
	fi
	set -- $_pids
	_n=$#
	[ "$_n" -ge 1 ] || return 1
	[ "$_n" -le 4 ] || warn "Xray 进程数异常：$_n"
	echo "$_n"
	return 0
}

tkp_health_nft() {
	if ! command -v nft >/dev/null 2>&1; then
		echo "TOOL_MISSING:nft"
		return 1
	fi
	_out=$(nft list table inet tkproxy 2>/dev/null) || {
		echo "TOOL_MISSING:nft"
		return 1
	}

	# 计算实际 tproxy 规则数（固定单一模式：'tproxy ip to :'）
	_n=$(printf '%s\n' "$_out" | grep -c 'tproxy ip to :' || true)

	# 期望值：优先从 manifest.json 读取线路条数，取不到则退回 SSID_COUNT
	# 注意：单条部署（--only）时 SSID_COUNT=1 但产物 manifest/xray/nft 仍是全量重载，
	# 这里必须按 manifest 全量条数校验（校验重载没有丢其它线路的 tproxy 规则），
	# 不能按 SSID_COUNT 裁剪期望值。
	_want="$SSID_COUNT"
	if [ -s "$CONF_DIR/manifest.json" ]; then
		_manifest_count=$(awk '
			/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
			in_arr && /^[[:space:]]*\]/ { in_arr=0 }
			in_arr && /"index"[[:space:]]*:/ { cnt++ }
			END { print cnt+0 }
		' "$CONF_DIR/manifest.json" 2>/dev/null || echo "0")
		[ "$_manifest_count" -gt 0 ] && _want="$_manifest_count"
	fi

	# 判定：实际数量 >= 期望值
	if [ "$_n" -ge "$_want" ]; then
		echo "ok:$_n/$_want"
		return 0
	else
		# 失败时输出期望值、实际值，以及前 3 行样本
		echo "count:$_n/$_want"
		warn "nft 健康检查失败：期望 tproxy 规则数 >= $_want，实际 $_n"
		warn "  ===== nft 表中 'tproxy ip to :' 规则（前 3 行样本）====="
		printf '%s\n' "$_out" | grep 'tproxy ip to :' | head -3 >&2
		warn "  ===== 样本结束 ====="
		return 1
	fi
}

tkp_health_policy() {
	if ! command -v ip >/dev/null 2>&1; then
		echo "TOOL_MISSING:ip"
		return 1
	fi
	ip rule show 2>/dev/null \
		| grep -Eq "fwmark[[:space:]]+0x8000/0x8000[[:space:]]+lookup[[:space:]]+$RT_TABLE" || return 1
	ip route show table "$RT_TABLE" 2>/dev/null \
		| grep -Eq 'local[[:space:]]+(default|0\.0\.0\.0/0)[[:space:]]+dev[[:space:]]+lo' || return 1
	return 0
}

TKP_STEP="== 6. 健康检查 =="
say "[step $TKP_STEP]"
say "$TKP_STEP"
_hc_fail=""

# 6a. 进程
if _xray_result=$(tkp_health_xray); then
	_xray_rc=0
else
	_xray_rc=$?
fi
if [ "$_xray_rc" = "0" ]; then
	say "  [PASS] Xray 进程：期望 >=1，实际 $_xray_result 个"
else
	if echo "$_xray_result" | grep -q "^TOOL_MISSING:"; then
		say "  [FAIL] Xray 进程：期望 >=1，实际无法获取（$(echo "$_xray_result" | cut -d: -f2) 工具缺失）"
	else
		say "  [FAIL] Xray 进程：期望 >=1，实际 0 个"
	fi
	_hc_fail="${_hc_fail}进程 "
fi

# 6b. 端口
if _port_result=$(tkp_health_ports); then
	_port_rc=0
else
	_port_rc=$?
fi
if [ "$_port_rc" = "0" ]; then
	say "  [PASS] 端口监听：全部就绪"
else
	if echo "$_port_result" | grep -q "^TOOL_MISSING:"; then
		say "  [FAIL] 端口监听：期望全部就绪，实际无法获取（$(echo "$_port_result" | cut -d: -f2) 工具缺失）"
	elif echo "$_port_result" | grep -q "^MANIFEST_MISSING"; then
		say "  [FAIL] 端口监听：期望全部就绪，实际无法获取（manifest.json 缺失）"
	elif echo "$_port_result" | grep -q "^NO_PORTS_CONFIG"; then
		say "  [FAIL] 端口监听：期望全部就绪，实际无法获取（manifest.json 里没有端口配置）"
	else
		# 列出哪些端口没起来
		_ports="$_port_result"
		_missing=""
		for _p in $_ports; do
			_up=0
			if command -v netstat >/dev/null 2>&1; then
				netstat -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && _up=1
			elif command -v ss >/dev/null 2>&1; then
				ss -ln 2>/dev/null | grep -Eq "[:.]${_p}[[:space:]]" && _up=1
			fi
			[ "$_up" = "1" ] || _missing="${_missing}${_p} "
		done
		say "  [FAIL] 端口监听：期望全部就绪，未监听的端口：${_missing:-?}"
	fi
	_hc_fail="${_hc_fail}端口 "
fi

# 6c. nft 表
if _nft_result=$(tkp_health_nft); then
	_nft_rc=0
else
	_nft_rc=$?
fi
if [ "$_nft_rc" = "0" ]; then
	say "  [PASS] nft 表 inet tkproxy：$_nft_result"
else
	if echo "$_nft_result" | grep -q "^TOOL_MISSING:"; then
		say "  [FAIL] nft 表：期望 tproxy 规则数达标，实际无法获取（$(echo "$_nft_result" | cut -d: -f2) 工具缺失）"
	elif echo "$_nft_result" | grep -q "^count:"; then
		say "  [FAIL] nft 表 inet tkproxy：$_nft_result"
	else
		say "  [FAIL] nft 表 inet tkproxy：查询失败"
	fi
	_hc_fail="${_hc_fail}nft "
fi

# 6d. 策略路由（ip rule + ip route）
if _policy_result=$(tkp_health_policy); then
	_policy_rc=0
else
	_policy_rc=$?
fi
if [ "$_policy_rc" = "0" ]; then
	say "  [PASS] 策略路由：fwmark 0x8000/0x8000 lookup $RT_TABLE"
else
	if echo "$_policy_result" | grep -q "^TOOL_MISSING:"; then
		say "  [FAIL] 策略路由：期望 fwmark 0x8000/0x8000 lookup $RT_TABLE，实际无法获取（$(echo "$_policy_result" | cut -d: -f2) 工具缺失）"
	else
		# 打印实际 rule/route 内容，不只是统计数量
		_rule_lines=$(ip rule show 2>/dev/null | grep "0x8000" || true)
		_route_lines=$(ip route show table "$RT_TABLE" 2>/dev/null | grep "local" || true)
		say "  [FAIL] 策略路由：期望 fwmark 0x8000/0x8000 lookup $RT_TABLE"
		if [ -n "$_rule_lines" ]; then
			say "         实际 ip rule 匹配行："
			printf '%s
' "$_rule_lines" | sed 's/^/           /'
		else
			say "         实际 ip rule 无匹配"
		fi
		if [ -n "$_route_lines" ]; then
			say "         实际 ip route table $RT_TABLE 匹配行："
			printf '%s
' "$_route_lines" | sed 's/^/           /'
		else
			say "         实际 ip route table $RT_TABLE 无匹配"
		fi
	fi
	_hc_fail="${_hc_fail}ip-rule "
fi

# 6e. M11e: DNS 重定向校验（NAT 链 redirect 设计）
_dns_check_pass=1
_dns_check_msg=""
if ! command -v nft >/dev/null 2>&1; then
	_dns_check_pass=0
	_dns_check_msg="nft 工具缺失"
else
	_nft_out=$(nft list table inet tkproxy 2>/dev/null) || {
		_dns_check_pass=0
		_dns_check_msg="无法读取 inet tkproxy 表"
	}
	if [ "$_dns_check_pass" = "1" ]; then
		# 检查是否存在 NAT 链
		if ! printf "%s\n" "$_nft_out" | grep -q "type nat hook prerouting"; then
			_dns_check_pass=0
			_dns_check_msg="缺少 NAT 链（type nat hook prerouting）; "
		fi
		# 按 PLAN 逐线路检查 redirect 规则
		while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
			[ -n "$idx" ] || continue
			_dns_port=$((5300 + idx))
			_brn=$(tkp_brname "$idx")
			# 检查 iifname "brtkNN" ... th dport 53 redirect to :53NN
			if ! printf "%s\n" "$_nft_out" | grep -qE "iifname \"$_brn\".*th dport 53.*redirect to :$_dns_port"; then
				_dns_check_pass=0
				_dns_check_msg="${_dns_check_msg}缺少 $_brn 的 DNS redirect 规则（:$_dns_port）; "
			fi
		done <<DNSPLAN
$PLAN
DNSPLAN
	fi
fi

if [ "$_dns_check_pass" = "1" ]; then
	# 构造所有 DNS 端口列表用于日志
	_dns_port_list=""
	while IFS="$SEP" read -r idx ssid slug br subnet gw port band ntype; do
		[ -n "$idx" ] || continue
		_dns_port_list="${_dns_port_list}$((5300 + idx)) "
	done <<DNSGWLIST
$PLAN
DNSGWLIST
	say "  [PASS] DNS 重定向（NAT 链）：${_dns_port_list}已就绪"
else
	say "  [FAIL] DNS 重定向（NAT 链）：$_dns_check_msg"
	_hc_fail="${_hc_fail}dns-rule "
fi

# 任一项失败则打印 xray.log 尾部（过滤 udhcpc 噪声）并 die
if [ -n "$_hc_fail" ]; then
	say "  ---- xray.log 最后 20 行（已过滤 udhcpc 噪声）----"
	tail -40 /tmp/tkproxy/xray.log 2>/dev/null | grep -v 'udhcpc:' | tail -20 | sed 's/^/    /' >&2
	say "  ---- logread 最后 10 行 ----"
	logread 2>/dev/null | grep -v 'udhcpc:' | grep -iE 'tkproxy|xray' | tail -10 | sed 's/^/    /' >&2
	die "健康检查未通过：${_hc_fail}（自动回滚）"
fi
say "  全部通过"
# 复核前等无线稳定（最多 90s），避免刚 reload 就误报「实际 AP 0 少于预期」
# 期望口径：全量部署 = uci 清单行数；单条部署 = 本线路自己的 AP 数（band 折算）
if [ -n "$ONLY_IDX" ]; then
	_want=0
	case "$_only_band" in
		both) _want=2 ;;
		2g|5g) _want=1 ;;
		*) _want=2 ;;
	esac
else
	_want=$(uci -q get tkproxy.main.line 2>/dev/null | tr ' ' '\n' | grep -c '|')
fi
_w=0
_have=0
while [ "$_w" -lt 90 ]; do
	_have=$(iw dev 2>/dev/null | grep -cE 'phy[01]-ap[0-9]+')
	if [ -n "$_want" ] && [ "$_have" -ge "$_want" ]; then break; fi
	sleep 10
	_w=$((_w + 10))
done
[ "$_w" -gt 0 ] && say "  等待无线就绪 ${_w}s（当前 AP $_have / 期望 $_want）"
tkp_capacity_postcheck

ROLLBACK_ARMED=0
echo "deploy_end=$(date -Iseconds)" >>"$BACKUP_DIR/.txn.log"
say '部署完成。'

# 部署成功后后台体检"当前线路在用"的节点（只测绑定节点，约 1-2 分钟），
# 结果并入 /tmp/tkproxy/nodetest.txt；前端顶栏据此提示"能连 WiFi 但上不了网"的死线。
if [ -x /usr/libexec/tkproxy/nodetest.sh ]; then
	( setsid sh /usr/libexec/tkproxy/nodetest.sh --bound-only >/tmp/tkproxy/nodetest-bound.log 2>&1 & ) 2>/dev/null \
		|| ( sh /usr/libexec/tkproxy/nodetest.sh --bound-only >/tmp/tkproxy/nodetest-bound.log 2>&1 & ) 2>/dev/null \
		|| true
	say '  已在后台启动绑定节点体检'
fi

# 开箱自检（t_d32788de）：部署完成后异步刷新一次（脚本内有 24h 节流，
# 24h 内已跑过就跳过；刚装/刚升级的场景这里就是首次落盘点）
if [ -f /usr/libexec/tkproxy/bootcheck.sh ]; then
	( setsid sh /usr/libexec/tkproxy/bootcheck.sh >>/tmp/tkproxy/bootcheck.log 2>&1 & ) 2>/dev/null \
		|| ( sh /usr/libexec/tkproxy/bootcheck.sh >>/tmp/tkproxy/bootcheck.log 2>&1 & ) 2>/dev/null \
		|| true
	say '  已在后台刷新开箱自检结果'
fi
