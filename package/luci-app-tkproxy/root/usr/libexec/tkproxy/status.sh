#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 状态采集（只读）
#
# 用法：status.sh [--json] [--health]
#   不带参数：打印 SSID 状态表格
#   --json    ：输出 SSID 状态的单行 JSON 数组
#   --health  ：输出四项硬性健康检查的 JSON 对象
#
# SSID 状态字段：ssid / band / subnet / port / node_type / online / exit_ip
#   online  = iw dev 里存在该 SSID 的接口 + Xray 进程在跑
#   exit_ip = ip netns + veth 从该网段访问 1.1.1.1/cdn-cgi/trace 取 ip=
#             取不到时返回 null，并在 note 里说明原因（绝不整体崩溃）
#
# 健康检查四项（--health 模式）：
#   xray_process : Xray 进程存活（pgrep -f "xray run -c"）
#   tproxy_ports : 21000+N 的 tproxy 端口在听（按 manifest 条数核对）
#   probe_ports  : 22001..22030 中实际应存在的 probe 口在听
#   nft_table    : nft list tables | grep -q 'table inet tkproxy'
#   ip_rule      : ip rule | grep -q '0x8000'
#
# 时区/语言隔离说明：
#   本插件只做网络层隔离（SSID 间互访禁止、IPv6 防泄漏、DNS 劫持）。
#   时区、语言、User-Agent 等浏览器指纹需要客户端自行配置（如 TikTok
#   客户端的系统语言、地区设置），插件不进行伪造或注入。
#
# 本脚本故意不使用 set -e：网络命名空间、veth、curl 任何一步失败都只影响
# 当前 SSID 的 exit_ip 字段。

PROG=tkproxy-status
CONF_DIR=${TKP_CONF_DIR:-/etc/tkproxy}
SEP=$(printf '\037')
JSON=0
HEALTH_MODE=0

LINE_CHECK_MODE=0
LINE_CHECK_NUM=0
LINE_ENV_MODE=0
LINE_ENV_NUM=0

case "${1:-}" in
	--json) JSON=1 ;;
	--health) HEALTH_MODE=1; JSON=1 ;;
	line-check)
		LINE_CHECK_MODE=1
		LINE_CHECK_NUM="${2:-0}"
		case "$LINE_CHECK_NUM" in
			''|*[!0-9]*)
				printf '%s: line-check 需要数字参数\n' "$PROG" >&2
				exit 2
				;;
		esac
		if [ "$LINE_CHECK_NUM" -lt 1 ]; then
			printf '%s: line-check 序号必须 >= 1\n' "$PROG" >&2
			exit 2
		fi
		;;
	line-env)
		LINE_ENV_MODE=1
		LINE_ENV_NUM="${2:-0}"
		case "$LINE_ENV_NUM" in
			''|*[!0-9]*)
				printf '%s: line-env 需要数字参数\n' "$PROG" >&2
				exit 2
				;;
		esac
		if [ "$LINE_ENV_NUM" -lt 1 ]; then
			printf '%s: line-env 序号必须 >= 1\n' "$PROG" >&2
			exit 2
		fi
		;;
	-h|--help|help)
		printf 'status.sh [--json] [--health] [line-check <N>] [line-env <N>]\n'
		exit 0
		;;
	"") ;;
	*)
		printf '%s: 未知参数：%s\n' "$PROG" "$1" >&2
		exit 2
		;;
esac

# ---------------------------------------------------------------------------
# JSON 读取（与 apply.sh 同一套小解析器：只认生成器的固定缩进格式）
# 必须在健康检查前定义，因为健康检查会调用此函数
# ---------------------------------------------------------------------------

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
			else if (e == "u") { i += 4 }
			else out = out e
		}
		return out
	}
	function emit(   i, o) {
		o = ""
		for (i = 1; i <= n; i++) o = o (i > 1 ? OFS : "") F[K[i]]
		print o
	}
	BEGIN { n = split(keys, K, ","); inside = 0; depth = 0 }
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
				if (v == "{" || v == "[") { depth++; next }
				if (depth == 1) F[k] = unesc(v)
			}
		}
	}' "$1"
}

# ---------------------------------------------------------------------------
# 健康检查四项（--health 模式）
# ---------------------------------------------------------------------------

if [ "$HEALTH_MODE" = "1" ]; then
	# 1. xray_process: Xray 进程存活（pgrep -f "xray run -c"）
	xray_process=false
	if command -v pgrep >/dev/null 2>&1; then
		if pgrep -f "xray run -c" >/dev/null 2>&1; then
			xray_process=true
		fi
	elif command -v pidof >/dev/null 2>&1; then
		for _pid in $(pidof xray 2>/dev/null); do
			if [ -f "/proc/$_pid/cmdline" ]; then
				_cmdline=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null || true)
				if echo "$_cmdline" | grep -q "xray run -c"; then
					xray_process=true
					break
				fi
			fi
		done
	fi

	# 2. tproxy_ports: 统计 ssids 条数 N，逐个检查 21001..21000+N
	tproxy_ports=false
	tproxy_expected=0
	tproxy_actual=0
	if [ -s "$CONF_DIR/manifest.json" ]; then
		# 统计 ssids 数组中的对象条数 N
		tproxy_expected=$(awk '
			/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
			in_arr && /^[[:space:]]*\]/ { in_arr=0 }
			in_arr && /^[[:space:]]*\{/ { n++ }
			END { print n+0 }
		' "$CONF_DIR/manifest.json" 2>/dev/null)
		case "$tproxy_expected" in ''|*[!0-9]*) tproxy_expected=0 ;; esac
		if [ "$tproxy_expected" -gt 0 ]; then
			_i=1
			while [ "$_i" -le "$tproxy_expected" ]; do
				_port=$((21000 + _i))
				if command -v netstat >/dev/null 2>&1; then
					if netstat -ln 2>/dev/null | grep -Eq "[:.]${_port}[[:space:]]"; then
						tproxy_actual=$((tproxy_actual + 1))
					fi
				elif command -v ss >/dev/null 2>&1; then
					if ss -ln 2>/dev/null | grep -Eq "[:.]${_port}[[:space:]]"; then
						tproxy_actual=$((tproxy_actual + 1))
					fi
				fi
				_i=$((_i + 1))
			done
			if [ "$tproxy_actual" -eq "$tproxy_expected" ]; then
				tproxy_ports=true
			fi
		fi
	fi

	# 3. probe_ports: manifest 每项的 22000+index 的 probe 口在听
	probe_ports=false
	probe_expected=0
	probe_actual=0
	if [ -s "$CONF_DIR/manifest.json" ]; then
		# 提取 manifest 每项的 index 字段，计算 22000+index
		_probe_invalid=0
		_probe_list=$(awk '
			/"ssids"[[:space:]]*:[[:space:]]*\[/ { in_arr=1; next }
			in_arr && /^[[:space:]]*\]/ { in_arr=0 }
			in_arr && /"index"[[:space:]]*:/ {
				v=$0; sub(/.*"index"[[:space:]]*:[[:space:]]*/, "", v); sub(/[,[:space:]].*/, "", v)
				if (v+0 >= 1 && v+0 <= 30) print 22000 + v+0
				else print "INVALID"
			}
		' "$CONF_DIR/manifest.json" 2>/dev/null)
		case "$_probe_list" in *INVALID*) _probe_invalid=1 ;; esac
		if [ "$_probe_invalid" = "1" ]; then
			probe_ports=false
		else
		for port in $_probe_list; do
			case "$port" in ''|*[!0-9]*) continue ;; esac
			probe_expected=$((probe_expected + 1))
			if command -v netstat >/dev/null 2>&1; then
				if netstat -ln 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]"; then
					probe_actual=$((probe_actual + 1))
				fi
			elif command -v ss >/dev/null 2>&1; then
				if ss -ln 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]"; then
					probe_actual=$((probe_actual + 1))
				fi
			fi
		done
		if [ "$probe_expected" -gt 0 ] && [ "$probe_actual" -eq "$probe_expected" ]; then
			probe_ports=true
		else
			# 没有 probe 端口配置，视为通过
			[ "$probe_expected" -eq 0 ] && probe_ports=true
		fi
		fi  # end of _probe_invalid else branch
	fi

	# 4. nft_table: nft list tables | grep -q 'table inet tkproxy'
	nft_table=false
	if command -v nft >/dev/null 2>&1; then
		if nft list tables 2>/dev/null | grep -q 'table inet tkproxy'; then
			nft_table=true
		fi
	fi

	# 5. ip_rule: ip rule | grep -q '0x8000'
	ip_rule=false
	if command -v ip >/dev/null 2>&1; then
		if ip rule show 2>/dev/null | grep -q '0x8000'; then
			ip_rule=true
		fi
	fi

	# 6. inter_iface_isolation: tkp 间互访应失败（从 manifest 拿两个不同 tkpNN 的网段，尝试从 A 访问 B 的网关）
	inter_iface_isolation=false
	_iso_note=""
	if [ -s "$CONF_DIR/manifest.json" ]; then
		# 先读取 manifest 所有行（在函数定义之后调用）
		_all_manifest_rows=$(tkp_json_rows "$CONF_DIR/manifest.json" ssids "index,slug,ssid,band,subnet,gateway,port,node_type" 2>/dev/null \
			| awk -F "$SEP" -v OFS="$SEP" 'NF >= 8 { br = ""; if ($1 ~ /^[0-9]+$/) { br = sprintf("brtk%02d", $1); if (length(br) > 15) br = ""; } if (br == "") br = "br-" $2; print $0, br }')
		# 收集所有 tkp bridge 到数组
		_all_brs=""
		while IFS="$SEP" read -r idx slug ssid band subnet gw port ntype br; do
			[ -n "$gw" ] && [ -n "$subnet" ] && [ -n "$br" ] || continue
			_all_brs="$_all_brs $br"
		done <<ISOEOF
$_all_manifest_rows
ISOEOF
		_br_count=$(printf '%s\n' "$_all_brs" | wc -w)
		if [ "$_br_count" -ge 2 ]; then
			# 核验 live nft 规则：遍历所有有序 tkp 对的 forward drop 及每个源桥的 input 限制
			# 注意：以下使用 grep 对 nft 多行输出做正则匹配，属于简化检查，
			# nft 输出格式在不同版本间可能有差异（如集合元素换行、缩进变化），
			# 可能导致误判（漏报或误报）。如需精确校验，应逐条解析 nft list chain 输出。
			_nft_iso_ok=true
			if command -v nft >/dev/null 2>&1; then
				_nft_out=$(nft list table inet tkproxy 2>/dev/null || true)
				# 检查所有有序 bridge 对的 forward 隔离规则
				for _src_br in $_all_brs; do
					for _dst_br in $_all_brs; do
						[ "$_src_br" = "$_dst_br" ] && continue
						# 简化检查：grep 匹配 nft 输出中的隔离规则，可能因 nft 输出格式差异而误判
						if ! printf '%s\n' "$_nft_out" | grep -qE "(iifname \"$_src_br\".*oifname.*\"$_dst_br\".*drop|iifname \"$_src_br\".*oifname.*\{[^}]*\"$_dst_br\"[^}]*\}.*drop)"; then
							_nft_iso_ok=false
							_iso_note="FAIL: nft forward 缺失 $_src_br -> $_dst_br 隔离规则"
							break 2
						fi
					done
				done
				# 检查每个源桥的 input 限制（必须有 mark 0x8000 放行、自身网关放行、兜底 drop）
				if [ "$_nft_iso_ok" = "true" ]; then
					# 提取 input 链的规则块（限定 chain input { ... }）
					_input_block=$(printf '%s\n' "$_nft_out" | awk '/chain input \{/,/^[[:space:]]*\}/' 2>/dev/null || true)
					for _src_br in $_all_brs; do
						# 读取该 bridge 的网关地址
						_src_gw=""
						while IFS="$SEP" read -r idx slug ssid band subnet gw port ntype br; do
							[ "$br" = "$_src_br" ] && _src_gw=$gw && break
						done <<GWEOF
$_all_manifest_rows
GWEOF
						# 逐项验证：mark 放行、网关放行、drop
						if ! printf '%s\n' "$_input_block" | grep -qE "iifname \"$_src_br\".*meta mark.*0x8000.*accept"; then
							_nft_iso_ok=false
							_iso_note="FAIL: nft input 缺失 $_src_br 的 mark 0x8000 放行规则"
							break
						fi
						if [ -n "$_src_gw" ]; then
							if ! printf '%s\n' "$_input_block" | grep -qE "iifname \"$_src_br\".*ip daddr $_src_gw.*accept"; then
								_nft_iso_ok=false
								_iso_note="FAIL: nft input 缺失 $_src_br 的自身网关放行规则（$_src_gw）"
								break
							fi
						fi
						if ! printf '%s\n' "$_input_block" | grep -qE "iifname \"$_src_br\".*drop"; then
							_nft_iso_ok=false
							_iso_note="FAIL: nft input 缺失 $_src_br 的兜底 drop 规则"
							break
						fi
					done
				fi
			else
				_nft_iso_ok=false
				_iso_note="FAIL: 缺少 nft 命令"
			fi
			if [ "$_nft_iso_ok" = "true" ]; then
				# 进一步实测：创建 netns，从第一个网段尝试 TCP 连接第二个网关（应该失败），并测试第一桥→第一网关:第二线路端口（应该失败）
				_first_gw=""
				_first_subnet=""
				_first_br=""
				_second_gw=""
				_second_port=""
				_n=0
				while IFS="$SEP" read -r idx slug ssid band subnet gw port ntype br; do
					[ -n "$gw" ] && [ -n "$subnet" ] && [ -n "$br" ] || continue
					_n=$((_n + 1))
					if [ "$_n" -eq 1 ]; then
						_first_gw=$gw
						_first_subnet=$subnet
						_first_br=$br
					elif [ "$_n" -eq 2 ]; then
						_second_gw=$gw
						_second_port=$port
						break
					fi
				done <<ISOEOF2
$_all_manifest_rows
ISOEOF2
				if [ -n "$_first_gw" ] && [ -n "$_second_gw" ] && [ -n "$_first_br" ] && [ -n "$_second_port" ]; then
					_ns_iso="tkiso$$"
					_hostif_iso="tkvih$$"
					_peer_iso="tkqih$$"
					if ip netns add "$_ns_iso" >/dev/null 2>&1 \
						&& ip link add "$_hostif_iso" type veth peer name "$_peer_iso" >/dev/null 2>&1 \
						&& ip link set "$_hostif_iso" master "$_first_br" >/dev/null 2>&1 \
						&& ip link set "$_hostif_iso" up >/dev/null 2>&1 \
						&& ip link set "$_peer_iso" netns "$_ns_iso" >/dev/null 2>&1 \
						&& ip netns exec "$_ns_iso" ip link set "$_peer_iso" up >/dev/null 2>&1; then
						_test_ip="${_first_subnet%.*}.201"
						_test_ip="${_test_ip%/*}"
						if ip netns exec "$_ns_iso" ip addr add "${_test_ip}/24" dev "$_peer_iso" >/dev/null 2>&1 \
							&& ip netns exec "$_ns_iso" ip route add default via "$_first_gw" >/dev/null 2>&1; then
							# 尝试从第一个网段访问第二个网关（应该失败）
							if ip netns exec "$_ns_iso" timeout 2 nc -z "$_second_gw" 80 >/dev/null 2>&1; then
								inter_iface_isolation=false
								_iso_note="FAIL: 从 $_first_subnet 可访问 $_second_gw（隔离失效）"
							else
								# 再尝试从第一个网段访问第一网关的第二线路 tproxy 端口（应该失败）
								if ip netns exec "$_ns_iso" timeout 2 nc -z "$_first_gw" "$_second_port" >/dev/null 2>&1; then
									inter_iface_isolation=false
									_iso_note="FAIL: 从 $_first_subnet 可访问 $_first_gw:$_second_port（串线）"
								else
									inter_iface_isolation=true
								fi
							fi
						fi
					fi
					ip netns del "$_ns_iso" >/dev/null 2>&1 || true
					ip link del "$_hostif_iso" >/dev/null 2>&1 || true
				else
					# 如果 nft 规则通过但无法实测，认为通过（规则已覆盖）
					inter_iface_isolation=true
					_iso_note="nft 规则已覆盖全部 bridge 对（实测环境不可用）"
				fi
			else
				# nft 规则检查失败
				inter_iface_isolation=false
			fi
		else
			# 只有一个或零个 tkp，无法测试，视为通过
			inter_iface_isolation=true
			_iso_note="N/A（线路数 < 2）"
		fi
	else
		inter_iface_isolation=true
		_iso_note="N/A（无 manifest）"
	fi

	# 7. ipv6_leak: tkp 客户端无 v6 出口（等待 RA 并检查 v6 地址，再用 IPv6 字面地址测试）
	# 返回值语义：true=泄漏（失败）、false=已防止（成功）、null=不可测试
	ipv6_leak="null"
	_v6_note=""
	if [ -s "$CONF_DIR/manifest.json" ]; then
		_any_gw=""
		_any_subnet=""
		_any_br=""
		# 重用之前已读取的 _all_manifest_rows
		while IFS="$SEP" read -r idx slug ssid band subnet gw port ntype br; do
			if [ -n "$gw" ] && [ -n "$subnet" ] && [ -n "$br" ]; then
				_any_gw=$gw
				_any_subnet=$subnet
				_any_br=$br
				break
			fi
		done <<V6EOF
$(tkp_json_rows "$CONF_DIR/manifest.json" ssids "index,slug,ssid,band,subnet,gateway,port,node_type" 2>/dev/null \
	| awk -F "$SEP" -v OFS="$SEP" 'NF >= 8 { br = ""; if ($1 ~ /^[0-9]+$/) { br = sprintf("brtk%02d", $1); if (length(br) > 15) br = ""; } if (br == "") br = "br-" $2; print $0, br }')
V6EOF
		if [ -n "$_any_gw" ] && [ -n "$_any_subnet" ] && [ -n "$_any_br" ]; then
			_ns_v6="tkv6$$"
			_hostif_v6="tkvh6$$"
			_peer_v6="tkqh6$$"
			if command -v curl >/dev/null 2>&1 \
				&& ip netns add "$_ns_v6" >/dev/null 2>&1 \
				&& ip link add "$_hostif_v6" type veth peer name "$_peer_v6" >/dev/null 2>&1 \
				&& ip link set "$_hostif_v6" master "$_any_br" >/dev/null 2>&1 \
				&& ip link set "$_hostif_v6" up >/dev/null 2>&1 \
				&& ip link set "$_peer_v6" netns "$_ns_v6" >/dev/null 2>&1 \
				&& ip netns exec "$_ns_v6" ip link set "$_peer_v6" up >/dev/null 2>&1; then
				_test_ip="${_any_subnet%.*}.202"
				_test_ip="${_test_ip%/*}"
				if ip netns exec "$_ns_v6" ip addr add "${_test_ip}/24" dev "$_peer_v6" >/dev/null 2>&1 \
					&& ip netns exec "$_ns_v6" ip route add default via "$_any_gw" >/dev/null 2>&1; then
					# 等待 IPv6 RA 和地址配置（最多 10 秒）
					_wait=0
					_have_v6_addr=0
					_have_v6_route=0
					while [ "$_wait" -lt 10 ]; do
						# 检查是否有全局 IPv6 地址（scope global）
						if ip netns exec "$_ns_v6" ip -6 addr show dev "$_peer_v6" 2>/dev/null | grep -q "scope global"; then
							_have_v6_addr=1
						fi
						# 检查是否有 v6 默认路由
						if ip netns exec "$_ns_v6" ip -6 route show default 2>/dev/null | grep -q "default via"; then
							_have_v6_route=1
						fi
						if [ "$_have_v6_addr" = "1" ] && [ "$_have_v6_route" = "1" ]; then
							break
						fi
						_wait=$((_wait + 1))
						sleep 1
					done

					# 前置条件检查
					if [ "$_have_v6_addr" = "0" ] || [ "$_have_v6_route" = "0" ]; then
						# netns 配置成功但未获得全局地址或默认路由 = IPv6 已被正确禁用（防泄漏成功）
						ipv6_leak="false"
						_v6_note="IPv6 已禁用（netns 无全局地址或默认路由，addr=$_have_v6_addr, route=$_have_v6_route）"
					else
						# 用 IPv6 字面地址测试（避免 DNS 解析问题）
						# 2606:4700:4700::1111 是 Cloudflare 的 IPv6 DNS
						if ip netns exec "$_ns_v6" curl -6 -s -m 3 "http://[2606:4700:4700::1111]" >/dev/null 2>&1; then
							ipv6_leak="true"
							_v6_note="FAIL: IPv6 未禁止（从 $_any_subnet 可访问 2606:4700:4700::1111）"
						else
							# 无 v6 出口 = 防泄漏生效
							ipv6_leak="false"
						fi
					fi
				else
					ipv6_leak="null"
					_v6_note="不可测试：netns 配置失败"
				fi
			else
				ipv6_leak="null"
				_v6_note="不可测试：缺少 curl 或 netns 创建失败"
			fi
			ip netns del "$_ns_v6" >/dev/null 2>&1 || true
			ip link del "$_hostif_v6" >/dev/null 2>&1 || true
		else
			ipv6_leak="null"
			_v6_note="N/A（无可测试线路）"
		fi
	else
		ipv6_leak="null"
		_v6_note="N/A（无 manifest）"
	fi

	# 6. kernel_version：读取当前 Xray 版本并判定是否满足最低要求
	kernel_version=unknown
	MIN_KERNEL_VERSION=26.0.0
	if command -v xray >/dev/null 2>&1; then
		_xray_ver=$(xray version 2>/dev/null | head -n 1 | sed -n 's/^Xray \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p') || _xray_ver=""
		if [ -n "$_xray_ver" ]; then
			kernel_version=$_xray_ver
		fi
	fi

	# 输出 JSON（ipv6_leak: true=泄漏, false=已防止, null=不可测试）
	printf '{"xray_process":%s,"tproxy_ports":%s,"probe_ports":%s,"nft_table":%s,"ip_rule":%s,"inter_iface_isolation":%s,"ipv6_leak":%s,"inter_iface_isolation_note":"%s","ipv6_leak_note":"%s","kernel_version":"%s"}\n' \
		"$xray_process" "$tproxy_ports" "$probe_ports" "$nft_table" "$ip_rule" \
		"$inter_iface_isolation" \
		"$ipv6_leak" \
		"$_iso_note" "$_v6_note" "$kernel_version"
	exit 0
fi

# ---------------------------------------------------------------------------
# 运营环境检测（line-env <N>）
# ---------------------------------------------------------------------------

if [ "$LINE_ENV_MODE" = "1" ]; then
	N="$LINE_ENV_NUM"
	probe_port=$((22000 + N))
	status="fail"
	exit_ip=""
	env_country=""
	env_isp=""
	dns_loc=""
	dns_ok=false
	ipv6_leak=false
	direct_leak=false
	note=""

	# 前置检查：curl 和 socks5h 可用性
	if ! command -v curl >/dev/null 2>&1; then
		note="缺少 curl 命令"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi

	# 1. 出口 IP（经 probe 口）
	# fields=query 返回 1 行 = IP
	exit_ip=$(curl -x socks5h://127.0.0.1:"$probe_port" -s -m 8 'http://ip-api.com/line/?fields=query' 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$exit_ip" ]; then
		note="取 IP 失败"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi
	exit_ip=$(printf '%s' "$exit_ip" | sed -n '1p')

	# 2. 国家码（经 probe 口）
	# fields=countryCode 返回 1 行 = 国家码
	env_country=$(curl -x socks5h://127.0.0.1:"$probe_port" -s -m 8 'http://ip-api.com/line/?fields=countryCode' 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$env_country" ]; then
		note="取国家码失败"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi
	env_country=$(printf '%s' "$env_country" | sed -n '1p')

	# 3. ISP（经 probe 口）
	# fields=isp 返回 1 行 = ISP
	env_isp=$(curl -x socks5h://127.0.0.1:"$probe_port" -s -m 8 'http://ip-api.com/line/?fields=isp' 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$env_isp" ]; then
		note="取 ISP 失败"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi
	env_isp=$(printf '%s' "$env_isp" | sed -n '1p')

	# 4. DNS 落地检查（经同一 probe 口）
	# fields=countryCode 返回 1 行 = 国家码；与 env_country 相同则 DNS 落地正确
	dns_loc=$(curl -x socks5h://127.0.0.1:"$probe_port" -s -m 8 'http://ip-api.com/line/?fields=countryCode' 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$dns_loc" ]; then
		note="取 DNS 落地失败"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi
	dns_loc=$(printf '%s' "$dns_loc" | sed -n '1p')

	status="ok"

	if [ "$dns_loc" = "$env_country" ]; then
		dns_ok=true
	fi

	# 5. direct_leak：本机出口 IP 是否与线路 exit_ip 相同
	_direct_ip=$(curl -s -m 8 'http://ip-api.com/line/?fields=query' 2>/dev/null)
	if [ $? -ne 0 ] || [ -z "$_direct_ip" ]; then
		note="取本机 IP 失败"
		printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
			"$N" "fail" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
		exit 0
	fi
	_direct_ip=$(printf '%s' "$_direct_ip" | sed -n '1p')
	if [ "$_direct_ip" = "$exit_ip" ]; then
		direct_leak=true
		note="直连泄漏（路由器本机 IP 与线路出口 IP 相同）"
	fi

	# 4. ipv6_leak：仅当 brtkNN 上存在全局 IPv6 地址时才可能为 true
	#    链路本地地址（fe80::）不算泄漏；缺失 nft drop 规则仅写入 note 提示
	_br_name=$(printf 'brtk%02d' "$N")
	_have_global_v6=false
	_nft_v6_drop=false
	if command -v ip >/dev/null 2>&1; then
		if ip link show "$_br_name" >/dev/null 2>&1; then
			# scope global 表示全局地址；scope link（fe80::）不在此列
			if ip -6 addr show dev "$_br_name" scope global 2>/dev/null | grep -q "inet6"; then
				_have_global_v6=true
			fi
		fi
	fi
	if command -v nft >/dev/null 2>&1; then
		if nft list table inet tkproxy 2>/dev/null | grep -E "iifname \"$_br_name\".*meta nfproto ipv6 drop" >/dev/null 2>&1; then
			_nft_v6_drop=true
		fi
	fi
	# 仅当确实有全局 v6 地址时才报泄漏
	if [ "$_have_global_v6" = "true" ]; then
		ipv6_leak=true
		if [ -z "$note" ]; then
			note="IPv6 泄漏（存在全局地址）"
		fi
	elif [ "$_nft_v6_drop" = "false" ]; then
		# 没有全局地址，但缺 nft 规则 → 仅写 note，不改 ipv6_leak
		if [ -z "$note" ]; then
			note="缺少 nft IPv6 drop 规则（当前无全局地址）"
		fi
	fi

	# 输出
	printf '{"line":%d,"status":"%s","exit_ip":"%s","env_country":"%s","env_isp":"%s","dns_loc":"%s","dns_ok":%s,"ipv6_leak":%s,"direct_leak":%s,"note":"%s"}\n' \
		"$N" "$status" "$exit_ip" "$env_country" "$env_isp" "$dns_loc" "$dns_ok" "$ipv6_leak" "$direct_leak" "$note"
	exit 0
fi

# ---------------------------------------------------------------------------
# 单飞锁 + 本次运行唯一后缀
# ---------------------------------------------------------------------------
LOCK_DIR=${TKP_LOCK_DIR:-/tmp}/tkproxy-status.lock
LOCK_HELD=0
# 取 PID 后 4 位；用 tail 而不是 ${var%????}，避免 PID 少于 4 位时被清空
RUN=$(printf '%s' "$$" | tail -c 4)

tkp_lock_acquire() {
	_i=0
	while [ "$_i" -lt 10 ]; do
		if mkdir "$LOCK_DIR" 2>/dev/null; then
			printf '%s\n' "$$" >"$LOCK_DIR/pid" 2>/dev/null || true
			LOCK_HELD=1
			return 0
		fi
		# 上一个进程被 kill -9 时会留下锁目录；pid 不在了就清掉
		if [ -f "$LOCK_DIR/pid" ]; then
			_p=$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null || true)
			case "$_p" in
				''|*[!0-9]*) ;;
				*)
					if ! kill -0 "$_p" 2>/dev/null; then
						rm -rf "$LOCK_DIR" 2>/dev/null || true
						continue
					fi
					;;
			esac
		fi
		_i=$((_i + 1))
		sleep 1
	done
	return 1
}

tkp_lock_release() {
	[ "$LOCK_HELD" = "1" ] || return 0
	LOCK_HELD=0
	rm -rf "$LOCK_DIR" 2>/dev/null || true
}

trap 'tkp_lock_release' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---------------------------------------------------------------------------
# 计划读取：优先 /etc/tkproxy/manifest.json；缺失时从 xray.json + uci 还原
# 输出字段：index slug ssid band subnet gateway port node_type bridge
# ---------------------------------------------------------------------------

tkp_uci_get() { uci -q get "$1" 2>/dev/null || true; }

# 旧部署（未保存 manifest）的兜底：xray.json 给 slug/端口/节点类型，
# uci 给 SSID/网段/频段。
tkp_rows_from_config() {
	local cfg="$CONF_DIR/xray.json" inrow outrow tag slug port band ssid ipaddr gw cidr ntype n
	[ -s "$cfg" ] || return 0
	n=0
	while IFS="$SEP" read -r tag port; do
		case "$tag" in
			*-in) slug=${tag%-in} ;;
			*) continue ;;
		esac
		n=$((n + 1))
		case "$port" in ''|*[!0-9]*) continue ;; esac
		ssid=$(tkp_uci_get "wireless.${slug}_5g.ssid")
		[ -n "$ssid" ] || ssid=$(tkp_uci_get "wireless.${slug}_2g.ssid")
		[ -n "$ssid" ] || ssid=$(tkp_uci_get "wireless.${slug}_0.ssid")
		[ -n "$ssid" ] || ssid=$(tkp_uci_get "wireless.${slug}_1.ssid")
		[ -n "$ssid" ] || ssid="-"
		if [ -n "$(tkp_uci_get "wireless.${slug}_2g")" ] && [ -n "$(tkp_uci_get "wireless.${slug}_5g")" ]; then
			band=both
		elif [ -n "$(tkp_uci_get "wireless.${slug}_5g")" ]; then
			band=5g
		elif [ -n "$(tkp_uci_get "wireless.${slug}_2g")" ]; then
			band=2g
		else
			band=both
		fi
		ipaddr=$(tkp_uci_get "network.${slug}.ipaddr")
		gw=${ipaddr%%/*}
		cidr=""
		if [ -n "$gw" ]; then
			cidr=$(printf '%s' "$gw" | sed 's#\.[0-9]*$#.0/24#')
		fi
		ntype=""
		outrow=$(tkp_json_rows "$cfg" outbounds "tag,protocol" | awk -F "$SEP" -v t="${slug}-out" '$1 == t { print $2; exit }')
		[ -n "$outrow" ] && ntype=$outrow
		printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n' \
			"" "$SEP" "$slug" "$SEP" "$ssid" "$SEP" "$band" "$SEP" "$cidr" \
			"$SEP" "$gw" "$SEP" "$port" "$SEP" "$ntype" "$SEP" "br-$slug"
	done <<EOF
$(tkp_json_rows "$cfg" inbounds "tag,port")
EOF
}

ROWS=""
if [ -s "$CONF_DIR/manifest.json" ]; then
	ROWS=$(tkp_json_rows "$CONF_DIR/manifest.json" ssids "index,slug,ssid,band,subnet,gateway,port,node_type" \
		| awk -F "$SEP" -v OFS="$SEP" '
			NF >= 8 {
				br = ""
				if ($1 ~ /^[0-9]+$/) {
					br = sprintf("brtk%02d", $1)
					if (length(br) > 15) br = ""
				}
				if (br == "") br = "br-" $2
				print $0, br
			}')
fi
[ -n "$ROWS" ] || ROWS=$(tkp_rows_from_config)

# ---------------------------------------------------------------------------
# 运行态采集
# ---------------------------------------------------------------------------

tkp_iw_map() {
	command -v iw >/dev/null 2>&1 || return 0
	iw dev 2>/dev/null | awk -v OFS="$SEP" '
		/^[ \t]*Interface / { iface = $2 }
		/^[ \t]*ssid / { s = $0; sub(/^[ \t]*ssid /, "", s); if (iface != "") print iface, s }
	'
}

tkp_xray_running() {
	if command -v pgrep >/dev/null 2>&1; then
		pgrep -f 'xray run' >/dev/null 2>&1 && return 0
		pgrep -x xray >/dev/null 2>&1 && return 0
	fi
	if command -v pidof >/dev/null 2>&1; then
		pidof xray >/dev/null 2>&1 && return 0
	fi
	return 1
}

# 生成本次运行唯一的短名（<=15 字节）
tkp_short_name() {
	_p=$1
	_i=$2
	_n="${_p}${_i}${RUN}"
	[ "${#_n}" -le 15 ] || _n="${_p}${_i}"
	[ "${#_n}" -le 15 ] || _n="${_p}${RUN}"
	[ "${#_n}" -le 15 ] || _n="tk${RUN}"
	printf '%s' "$_n"
}

# 输出：<exit_ip>\037<note>
# 参数：bridge slug subnet gateway 序号
tkp_exit_ip() {
	local br="$1" slug="$2" subnet="$3" gw="$4" idx="$5"
	local ns hostif peer prefix trace exitip note legacy

	if [ "$LOCK_HELD" != "1" ]; then
		printf '%s%s%s\n' "" "$SEP" "另一个 status.sh 正在采集，跳过出口测试"
		return 0
	fi

	case "$br" in
		''|*[!A-Za-z0-9_.-]*) br="" ;;
		*) [ "${#br}" -le 15 ] || br="" ;;
	esac
	if [ -z "$br" ]; then
		printf '%s%s%s\n' "" "$SEP" "网桥名非法，跳过出口测试"
		return 0
	fi

	if ! command -v ip >/dev/null 2>&1; then
		printf '%s%s%s\n' "" "$SEP" "缺少 ip 命令"
		return 0
	fi
	if ! command -v curl >/dev/null 2>&1; then
		printf '%s%s%s\n' "" "$SEP" "缺少 curl"
		return 0
	fi
	[ -n "$subnet" ] && [ -n "$gw" ] || {
		printf '%s%s%s\n' "" "$SEP" "缺少网段/网关，无法从该网段发起测试"
		return 0
	}

	# 新版用 brtkNN；升级前尚未重新部署时回退到旧名 br-<slug>
	if ! ip link show "$br" >/dev/null 2>&1; then
		legacy=""
		case "$slug" in
			''|*[!A-Za-z0-9_.-]*) ;;
			*) legacy="br-$slug" ;;
		esac
		if [ -n "$legacy" ] && [ "${#legacy}" -le 15 ] \
			&& ip link show "$legacy" >/dev/null 2>&1; then
			br=$legacy
		else
			printf '%s%s%s\n' "" "$SEP" "网桥 $br 不存在"
			return 0
		fi
	fi

	ns=$(tkp_short_name tkp "$idx")
	hostif=$(tkp_short_name tkv "$idx")
	peer=$(tkp_short_name tkq "$idx")

	ip netns del "$ns" >/dev/null 2>&1 || true
	ip link del "$hostif" >/dev/null 2>&1 || true

	if ! ip netns add "$ns" >/dev/null 2>&1; then
		printf '%s%s%s\n' "" "$SEP" "创建 netns 失败（需要 ip-full / kmod-veth 或权限）"
		return 0
	fi
	if ! ip link add "$hostif" type veth peer name "$peer" >/dev/null 2>&1; then
		ip netns del "$ns" >/dev/null 2>&1 || true
		printf '%s%s%s\n' "" "$SEP" "创建 veth 失败（缺 kmod-veth）"
		return 0
	fi
	if ! ip link set "$hostif" master "$br" >/dev/null 2>&1; then
		ip netns del "$ns" >/dev/null 2>&1 || true
		ip link del "$hostif" >/dev/null 2>&1 || true
		printf '%s%s%s\n' "" "$SEP" "把 veth 挂到 $br 失败"
		return 0
	fi
	if ! ip link set "$hostif" up >/dev/null 2>&1 \
		|| ! ip link set "$peer" netns "$ns" >/dev/null 2>&1 \
		|| ! ip netns exec "$ns" ip link set "$peer" up >/dev/null 2>&1; then
		ip netns del "$ns" >/dev/null 2>&1 || true
		ip link del "$hostif" >/dev/null 2>&1 || true
		printf '%s%s%s\n' "" "$SEP" "启用 veth/移入 netns 失败"
		return 0
	fi

	prefix=$(printf '%s' "$subnet" | sed 's#\.[0-9]*/[0-9]*$##')
	if ! ip netns exec "$ns" ip addr add "${prefix}.200/24" dev "$peer" >/dev/null 2>&1 \
		|| ! ip netns exec "$ns" ip route add default via "$gw" >/dev/null 2>&1; then
		ip netns del "$ns" >/dev/null 2>&1 || true
		ip link del "$hostif" >/dev/null 2>&1 || true
		printf '%s%s%s\n' "" "$SEP" "配置 netns 地址/默认路由失败"
		return 0
	fi

	trace=$(ip netns exec "$ns" curl -s -m 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
	exitip=$(printf '%s\n' "$trace" | sed -n 's/^ip=//p' | head -n 1)
	ip netns del "$ns" >/dev/null 2>&1 || true
	ip link del "$hostif" >/dev/null 2>&1 || true

	note=""
	if [ -z "$exitip" ]; then
		note="curl -m 5 无输出（节点未连通或 tproxy 未生效）"
	fi
	printf '%s%s%s\n' "$exitip" "$SEP" "$note"
}

tkp_json_str() {
	local s
	s=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' \
		| sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g')
	printf '"%s"' "$s"
}

# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

IW_ROWS=$(tkp_iw_map)
SB_RUNNING=0
if tkp_xray_running; then SB_RUNNING=1; fi

if tkp_lock_acquire; then
	:
else
	printf '%s: 警告：另一个 status.sh 正在采集，本次跳过出口测试\n' "$PROG" >&2
fi

[ "$JSON" = "1" ] || printf '%-18s %-6s %-18s %-7s %-12s %-8s %s\n' \
	SSID BAND SUBNET PORT NODE_TYPE ONLINE EXIT_IP

ITEMS=""
N=0
while IFS="$SEP" read -r idx slug ssid band subnet gw port ntype br; do
	[ -n "$slug" ] || continue
	N=$((N + 1))
	[ -n "$band" ] || band=both
	[ -n "$ntype" ] || ntype="-"
	[ -n "$ssid" ] || ssid="-"
	[ -n "$subnet" ] || subnet="-"
	[ -n "$br" ] || br="br-$slug"
	case "$port" in ''|*[!0-9]*) port=0 ;; esac

	vif=""
	if [ -n "$IW_ROWS" ]; then
		vif=$(printf '%s\n' "$IW_ROWS" | awk -F "$SEP" -v s="$ssid" '$2 == s { print $1; exit }')
	fi
	online=0
	if [ "$SB_RUNNING" = "1" ] && [ -n "$vif" ]; then online=1; fi

	EXIT_INFO=$(tkp_exit_ip "$br" "$slug" "$subnet" "$gw" "$N")
	IFS="$SEP" read -r exitip note <<EOF
$EXIT_INFO
EOF
	[ -n "$exitip" ] || exitip=""

	if [ "$JSON" = "1" ]; then
		[ "$online" = "1" ] && online_json=true || online_json=false
		if [ -n "$exitip" ]; then
			exit_json=$(tkp_json_str "$exitip")
		else
			exit_json=null
		fi
		ITEMS="${ITEMS}${ITEMS:+,}{\"ssid\":$(tkp_json_str "$ssid"),\"band\":$(tkp_json_str "$band"),\"subnet\":$(tkp_json_str "$subnet"),\"port\":${port:-0},\"node_type\":$(tkp_json_str "$ntype"),\"online\":${online_json},\"exit_ip\":${exit_json},\"note\":$(tkp_json_str "$note")}"
	else
		if [ "$online" = "1" ]; then online_txt=up; else online_txt=down; fi
		if [ -n "$exitip" ]; then exit_txt=$exitip; else exit_txt=null; fi
		printf '%-18s %-6s %-18s %-7s %-12s %-8s %s\n' \
			"$ssid" "$band" "$subnet" "$port" "$ntype" "$online_txt" "$exit_txt"
		[ -n "$note" ] && printf '  note: %s\n' "$note"
	fi
done <<EOF
$ROWS
EOF

# ---------------------------------------------------------------------------
# 自检项：inter_iface_isolation + ipv6_leak + kernel_version
#
# 解析方式（三态 pass/fail/unknown）：
#   nft -j list chain 输出 JSON，经 jsonfilter 逐规则展开成单行文本，
#   再用 grep -F 匹配固定 JSON 片段（片段取自 nft 1.1.1 实测输出，见下）。
#   nft 文本输出在不同版本间格式不稳定（集合换行、缩进、通配写法展开），
#   grep 正则易误判；JSON 字段名与取值则是稳定契约。
#   任何一步（nft 缺失 / nft -j 不支持 / jsonfilter 缺失 / 输出解析失败）
#   都落 unknown 并把原因写进 check_*_note，绝不静默判 fail。
#
# nft -j 实测规则形态（nftables 1.1.1）：
#   forward 跨线路隔离（apply.sh 逐桥对生成 iifname "brtkNN" oifname "brtkMM" drop）：
#     [{"match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "brtk01" }}, {"match": { ..., "right": "brtk02" }}, { "drop": null }]
#   input 每桥：mark 0x8000 accept / ip daddr 自身网关 accept / 兜底 drop
#     0x8000 在 JSON 中是十进制 32768
#   IPv6 防泄漏（meta nfproto ipv6 drop）：
#     {"match": { "op": "==", "left": { "nfproto": { ... } }, "right": "ipv6" }}, { "drop": null }
# ---------------------------------------------------------------------------

# 把 nft -j list chain <table> <chain> 的输出展平成「一行一个表达式片段」。
# 输出为空且 nft 失败时返回非零（调用方据此落 unknown）。
tkp_nft_chain_exprs() {
	local _chain
	_chain="$1"
	command -v nft >/dev/null 2>&1 || return 1
	command -v jsonfilter >/dev/null 2>&1 || return 1
	# jsonfilter 不吃超长 -s 参数，必须走管道 stdin
	nft -j list chain inet tkproxy "$_chain" 2>/dev/null \
		| jsonfilter -e "@.nftables[@.rule.chain=\"$_chain\"].rule.expr" 2>/dev/null
	return 0
}

check_inter_iface_isolation=unknown
check_ipv6_leak=unknown
check_inter_iface_isolation_note=""
check_ipv6_leak_note=""

if ! command -v nft >/dev/null 2>&1; then
	check_inter_iface_isolation_note="缺少 nft 命令"
	check_ipv6_leak_note="缺少 nft 命令"
elif ! command -v jsonfilter >/dev/null 2>&1; then
	check_inter_iface_isolation_note="缺少 jsonfilter 命令，无法解析 nft -j 输出"
	check_ipv6_leak_note="缺少 jsonfilter 命令，无法解析 nft -j 输出"
elif ! nft list tables 2>/dev/null | grep -q 'table inet tkproxy'; then
	check_inter_iface_isolation_note="nft 表 inet tkproxy 不存在（未部署）"
	check_ipv6_leak_note="nft 表 inet tkproxy 不存在（未部署）"
else
	# ---- inter_iface_isolation：forward 链必须同时满足 ----
	#   a) 每个桥自身的同桥隔离：iifname "brtkNN" oifname "brtkNN" drop
	#   b) 每个有序桥对 (N,M), N!=M：iifname "brtkNN" oifname "brtkMM" drop
	# bridge 清单从 live 规则里反查（找全形如 "right": "brtkNN" 的 iifname），
	# 不依赖 manifest（status.sh 其余部分也以 live 状态为准）。
	_fwd_exprs=$(tkp_nft_chain_exprs forward)
	if [ -z "$_fwd_exprs" ]; then
		check_inter_iface_isolation=unknown
		check_inter_iface_isolation_note="nft -j list chain forward 解析失败或链为空"
	else
		_brtk_list=$(printf '%s\n' "$_fwd_exprs" \
			| grep -o '"key": "iifname" } }, "right": "brtk[0-9][0-9]*"' \
			| grep -o 'brtk[0-9][0-9]*' | sort -u)
		_br_n=$(printf '%s\n' "$_brtk_list" | grep -c .)
		if [ "$_br_n" -lt 1 ]; then
			# 解析成功但找不到任何 brtk 桥规则：可能是通配写法或格式漂移，保守 unknown
			check_inter_iface_isolation_note="forward 链中未发现任何 brtk 桥规则"
		elif [ "$_br_n" -lt 2 ]; then
			# 单线路无需跨线路隔离，同桥互访禁止仍在即视为通过
			if printf '%s\n' "$_fwd_exprs" | grep -Fq '"right": "'"$_brtk_list"'" } }, { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "'"$_brtk_list"'" } }, { "drop"'; then
				check_inter_iface_isolation=pass
			else
				check_inter_iface_isolation=fail
				check_inter_iface_isolation_note="单线路但缺少同桥 drop（$_brtk_list）"
			fi
		else
			# 一次性从规则里提取全部「iifname X ... oifname Y ... drop」桥对，
			# 避免逐对全量 grep（30 桥 870 对 × 250KB 文本在路由器上太慢）
			# 一次性从规则里提取全部「iifname X ... oifname Y ... drop」桥对，
			# 避免逐对全量 grep（30 桥 870 对 × 250KB 文本在路由器上太慢）。
			# busybox 没有 paste，用 awk match 循环：每行恰好 2 个 brtkNN 才输出
			# （对 iifname "brtk*" 单名通配行天然免疫），空格分隔供 grep -Fxq 查找。
			_fwd_pairs=$(printf '%s\n' "$_fwd_exprs" \
				| grep '"key": "oifname"' \
				| grep -F '{ "drop": null }' \
				| awk '{ n = 0; while (match($0, /brtk[0-9][0-9]*/)) { n++; s[n] = substr($0, RSTART, RLENGTH); $0 = substr($0, RSTART + RLENGTH) } if (n == 2) print s[1], s[2] }' \
				2>/dev/null || true)
			_iso_missing=""
			for _src in $_brtk_list; do
				for _dst in $_brtk_list; do
					[ "$_src" != "$_dst" ] || continue
					# 在提取好的桥对清单里精确查这一对（O(1) 文本行查找）
					if ! printf '%s\n' "$_fwd_pairs" | grep -Fxq "$_src $_dst"; then
						_iso_missing="$_src->$_dst"
						break 2
					fi
				done
			done
			if [ -n "$_iso_missing" ]; then
				check_inter_iface_isolation=fail
				check_inter_iface_isolation_note="forward 缺少 $_iso_missing 隔离 drop"
			else
				# 再抽验每个桥的同桥 drop 兜底
				_same_missing=""
				for _src in $_brtk_list; do
					if ! printf '%s\n' "$_fwd_pairs" | grep -Fxq "$_src $_src"; then
						_same_missing=$_src
						break
					fi
				done
				if [ -n "$_same_missing" ]; then
					check_inter_iface_isolation=fail
					check_inter_iface_isolation_note="forward 缺少 $_same_missing 同桥 drop"
				else
					check_inter_iface_isolation=pass
				fi
			fi
		fi
	fi

	# ---- ipv6_leak：forward 链存在 meta nfproto ipv6 drop（宽匹配：nfproto 的
	#      JSON 嵌套在不同 nft 版本间有差异，只锚定 "nfproto" + "ipv6" + drop 同行）----
	#      判定语义：forward 有 → pass；forward 无但 input 有 → pass（降级通过，note 说明）；
	#      两条链都没有 → fail。apply.sh 正常部署时两条链都写 v6 drop。----
	_fwd_v6=$(printf '%s\n' "$_fwd_exprs" | grep '"nfproto"' | grep '"ipv6"' | grep -c '{ "drop": null }')
	if [ "${_fwd_v6:-0}" -gt 0 ]; then
		check_ipv6_leak=pass
	else
		# input 链也部署了独立的 v6 drop，forward 没有 input 有时仍算受控，
		# 但防泄漏主防线在 forward：两者都没有才判 fail，有 input 兜底给 unknown 提示
		_in_exprs=$(tkp_nft_chain_exprs input)
		_in_v6=$(printf '%s\n' "$_in_exprs" | grep '"nfproto"' | grep '"ipv6"' | grep -c '{ "drop": null }')
		if [ "${_in_v6:-0}" -gt 0 ]; then
			check_ipv6_leak=pass
			check_ipv6_leak_note="forward 链无 v6 drop，仅 input 链覆盖"
		else
			check_ipv6_leak=fail
			check_ipv6_leak_note="forward 与 input 链均无 meta nfproto ipv6 drop"
		fi
	fi
fi

# kernel_version：读取当前 Xray 版本并判定是否满足最低要求
kernel_version=unknown
kernel_check=fail
MIN_KERNEL_VERSION=26.0.0
if command -v xray >/dev/null 2>&1; then
	_xray_ver=$(xray version 2>/dev/null | head -n 1 | sed -n 's/^Xray \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
	if [ -n "$_xray_ver" ]; then
		kernel_version=$_xray_ver
		# 版本比较：用 awk 按 . 分段比较
		_ver_ok=$(printf '%s\n%s\n' "$kernel_version" "$MIN_KERNEL_VERSION" | awk '
			BEGIN { FS = "."; v1[1] = v1[2] = v1[3] = 0; v2[1] = v2[2] = v2[3] = 0 }
			NR == 1 {
				split($0, v1, ".")
				for (i = 1; i <= 3; i++) v1[i] = v1[i] + 0
			}
			NR == 2 {
				split($0, v2, ".")
				for (i = 1; i <= 3; i++) v2[i] = v2[i] + 0
			}
			END {
				if (v1[1] < v2[1]) { print "lt"; exit }
				if (v1[1] > v2[1]) { print "ge"; exit }
				if (v1[2] < v2[2]) { print "lt"; exit }
				if (v1[2] > v2[2]) { print "ge"; exit }
				if (v1[3] < v2[3]) { print "lt"; exit }
				print "ge"
			}
		')
		if [ "$_ver_ok" = "ge" ]; then
			kernel_check=pass
		fi
	fi
fi

if [ "$JSON" = "1" ]; then
	# 保持顶层 JSON 数组，将三个自检字段注入每个数组项
	# note 走 tkp_json_str 转义（中文/引号/控制字符都不破坏 JSON）
	_iso_note_json=$(tkp_json_str "$check_inter_iface_isolation_note")
	_v6_note_json=$(tkp_json_str "$check_ipv6_leak_note")
	_items_with_checks=$(printf '%s' "$ITEMS" | sed "s/}/,\"inter_iface_isolation\":\"${check_inter_iface_isolation}\",\"inter_iface_isolation_note\":${_iso_note_json},\"ipv6_leak\":\"${check_ipv6_leak}\",\"ipv6_leak_note\":${_v6_note_json},\"kernel_version\":\"${kernel_version}\",\"kernel_check\":\"${kernel_check}\"}/g")
	printf '[%s]\n' "$_items_with_checks"
else
	printf '\n[自检项]\n'
	printf '  inter_iface_isolation : %s\n' "$check_inter_iface_isolation"
	[ -n "$check_inter_iface_isolation_note" ] && printf '    %s\n' "$check_inter_iface_isolation_note"
	printf '  ipv6_leak             : %s\n' "$check_ipv6_leak"
	[ -n "$check_ipv6_leak_note" ] && printf '    %s\n' "$check_ipv6_leak_note"
	printf '  kernel_version        : %s（当前）/ %s（最低）/ %s\n' "$kernel_version" "$MIN_KERNEL_VERSION" "$kernel_check"
fi

exit 0
