#!/bin/sh

# 停掉 DNS 桥
for _p in $(pgrep -f "dnsbridge.lua" 2>/dev/null || true); do
	case "$(tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null || true)" in
		*tkproxy*dnsbridge.lua*) kill -9 "$_p" 2>/dev/null || true ;;
	esac
done
rm -f /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true
# SPDX-License-Identifier: GPL-3.0
# tkproxy 一键拆除
#
# 用法：clean.sh [--keep-config]
#   默认        ：停服务、删 nft 表/策略路由、删本方案建的全部 uci 段、
#                 删 /etc/tkproxy 与 /etc/init.d/tkproxy
#   --keep-config：只停服务、清运行时（nft/策略路由），保留 uci 段和配置文件
#
# 安全约束（Codex 审查后加固）：
#   - CONF_DIR / INIT_FILE 只允许白名单，拒绝相对路径、..、符号链接；
#   - 只删带 tkproxy=1 标记的段；manifest 里的 slug 若指向已存在但没有
#     标记的段，立即中止并保留所有配置，绝不盲删系统段；
#   - uci delete 只容忍「段不存在」，权限/锁失败中止；
#   - uci commit 失败保留 manifest 并以非 0 退出；
#   - 策略路由只删本方案的 rule 与 local 路由，绝不 flush 整表。
set -e

PROG=tkproxy-clean
CONF_DIR=${TKP_CONF_DIR:-/etc/tkproxy}
INIT_FILE=${TKP_INIT:-/etc/init.d/tkproxy}
SEP=$(printf '\037')
MARK=0x8000/0x8000
RT_TABLE=51820
KEEP=0

say() { printf '%s\n' "$*"; }
warn() { printf '%s: 警告：%s\n' "$PROG" "$*" >&2; }
die() { printf '%s: 错误：%s\n' "$PROG" "$*" >&2; exit 1; }
die_code() { _c=$1; shift; printf '%s: 错误：%s\n' "$PROG" "$*" >&2; exit "$_c"; }
refuse() { printf '%s: 拒绝执行：%s\n' "$PROG" "$*" >&2; }

case "${1:-}" in
	--keep-config) KEEP=1 ;;
	-h|--help|help)
		printf 'clean.sh [--keep-config]\n'
		exit 0
		;;
	"") ;;
	*)
		printf '%s: 未知参数：%s\n' "$PROG" "$1" >&2
		exit 2
		;;
esac

# ---------------------------------------------------------------------------
# 路径白名单（与 apply.sh 一致）
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

case "$CONF_DIR" in
	/tmp/*)
		case "$INIT_FILE" in
			/tmp/tkproxy*) ;;
			*) tkp_reject_path "CONF_DIR 在 /tmp 时 INIT_FILE 也必须在 /tmp/tkproxy*，实际值：$INIT_FILE" ;;
		esac
		;;
esac

# ---------------------------------------------------------------------------
# JSON 读取（与 apply.sh 同一套小解析器）
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
# uci 标记校验
# ---------------------------------------------------------------------------

# 返回 0=存在 1=不存在 2=读取失败（权限/锁）
# firewall 段不再打 tkproxy 标记（fw4 会报 unknown option），按段名前缀 tkpNN 识别
tkp_fw_section_is_ours() { # <section>
	case "$1" in
		tkp[0-9]*) return 0 ;;
	esac
	return 1
}

# 拆除后确认主 WiFi 没被带下去：任一射频 AP 数为 0 就补一次
tkp_ensure_wifi_up() {
	local phy n bad=0 still_bad=0 all_phys
	# 首次检查：从 iwinfo 获取射频列表
	all_phys=$(iwinfo 2>/dev/null | sed -n 's/^\([a-z0-9]*\)[[:space:]].*/\1/p')
	for phy in $all_phys; do
		n=$(iw dev 2>/dev/null | grep -c "Interface ${phy}-ap\|Interface ${phy}ap" || true)
		[ -z "$n" ] && n=0
		[ "$n" = "0" ] && bad=1
	done
	[ "$bad" = "0" ] && return 0
	warn "检测到有射频没有 AP，补一次 wifi up"
	if ! wifi up >/dev/null 2>&1 && ! /sbin/wifi up >/dev/null 2>&1; then
		warn "wifi up 命令执行失败"
		return 1
	fi
	sleep 6
	# 复查：只要整机还有 AP 在广播就算恢复成功。
	# 某颗射频没有 AP 只警告——部署时那颗射频可能被线路占满、本来就没留主 WiFi，
	# 不能因此判定「拆除失败」（否则清理永远报错，用户看到的就是「回滚失败」）。
	total=0
	for phy in $all_phys; do
		n=$(iw dev 2>/dev/null | grep -c "Interface ${phy}-ap\|Interface ${phy}ap" || true)
		[ -z "$n" ] && n=0
		total=$((total + n))
		if [ "$n" = "0" ]; then
			warn "  $phy 清理后没有 AP（该射频原本可能被线路占满，需要的话请在「网络-无线」手动加一个）"
		fi
	done
	if [ "$total" = "0" ]; then
		warn "清理后没有任何 AP 在广播"
		return 1
	fi
	return 0
}

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
		# firewall 段不再打 tkproxy 标记（fw4 会报 unknown option），按段名前缀判定
		_t=${_sec%%.*}
		_n=${_sec#*.}
		if [ "$_t" = "firewall" ] && tkp_fw_section_is_ours "$_n"; then
			uci delete "$_sec" 2>/dev/null || die "删除 $_sec 失败（权限/锁）"
			return 0
		fi
		die "拒绝删除 $_sec：该段已存在但缺少 tkproxy=1 标记（实际：${_m:-<空>}）"
	fi
	uci delete "$_sec" 2>/dev/null || die "删除 $_sec 失败（权限/锁）"
}

tkp_ifname() { printf 'tkp%02d' "$1"; }
tkp_brname() { printf 'brtk%02d' "$1"; }

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

# 该 manifest 条目是否为新版短命名部署（任一段带标记即认定）
tkp_is_new_deploy() {
	_idx=$1
	[ -n "$_idx" ] || return 1
	_if=$(tkp_ifname "$_idx")
	_brn=$(tkp_brname "$_idx")
	for _n in "network.$_if" "network.$_brn" "wireless.${_if}_2g" "wireless.${_if}_5g"; do
		if tkp_sec_exists "$_n"; then
			[ "$(tkp_marker "$_n")" = "1" ] && return 0
		fi
	done
	return 1
}

# ---------------------------------------------------------------------------
# 预检：manifest 指向的段只要已存在，就必须带 tkproxy=1；否则整体中止
# 此时尚未停服务、尚未删任何东西。
# ---------------------------------------------------------------------------
REFUSED=0
tkp_refuse_if_unmarked() {
	_n=$1
	if tkp_sec_exists "$_n"; then
		_m=$(tkp_marker "$_n")
		if [ "$_m" != "1" ]; then
			# firewall 段按段名前缀识别（新版不再打 tkproxy 标记，避免 fw4 告警）
			if [ "${_n%%.*}" = "firewall" ] && tkp_fw_section_is_ours "${_n#*.}"; then
				return 0
			fi
			printf '%s: 拒绝删除 %s：缺少 tkproxy=1 标记（实际：%s），疑似系统配置\n' \
				"$PROG" "$_n" "${_m:-<空>}" >&2
			REFUSED=1
		fi
	else
		_st=$?
		if [ "$_st" -ne 1 ]; then
			printf '%s: 拒绝继续：读取 uci %s 失败（权限/锁）\n' "$PROG" "$_n" >&2
			REFUSED=1
		fi
	fi
}

MANIFEST_ROWS=""
if [ -s "$CONF_DIR/manifest.json" ]; then
	MANIFEST_ROWS=$(tkp_json_rows "$CONF_DIR/manifest.json" ssids "index,slug")
fi

# ---------------------------------------------------------------------------
# 0. 授权与配置保护：拆除只清「部署产物」，绝不碰授权
#    授权文件一旦被删，用户就要重新激活（还可能浪费机器码绑定次数）
# ---------------------------------------------------------------------------
TKP_KEEP_DIR=/etc/tkproxy-backup/$(date +%Y%m%d-%H%M%S)
mkdir -p "$TKP_KEEP_DIR" 2>/dev/null
KEPT=""
for _f in license.json license-verify license-ticket device.json; do
	if [ -s "$CONF_DIR/$_f" ]; then
		cp -f "$CONF_DIR/$_f" "$TKP_KEEP_DIR/$_f" 2>/dev/null && KEPT="$KEPT $_f"
	fi
done
uci -q export tkproxy > "$TKP_KEEP_DIR/uci-tkproxy.txt" 2>/dev/null && KEPT="$KEPT uci-tkproxy.txt"
if [ -n "$KEPT" ]; then
	say "  已备份并保留：$KEPT（$TKP_KEEP_DIR）"
fi

say "== 0. uci 标记预检 =="
# 预检时就把「新版短名 / 旧版 slug 名」判定固化下来：
# 2a 删除之后短名就不存在了，不能那时再判断，否则会误入旧名分支。
CLEAN_PLAN=""
if [ -n "$MANIFEST_ROWS" ]; then
	while IFS="$SEP" read -r _idx _slug; do
		[ -n "$_idx$_slug" ] || continue
		if [ -n "$_slug" ]; then
			case "$_slug" in
				*[!A-Za-z0-9_]*)
					printf '%s: 拒绝继续：manifest 里的 slug 含非法字符：%s\n' "$PROG" "$_slug" >&2
					REFUSED=1
					continue
					;;
			esac
		fi
		# 只接受生成器会产生的 index 形式，避免 printf/算术被奇怪输入影响
		case "$_idx" in
			0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]) ;;
			*) _idx="" ;;
		esac
		if [ "$(tkp_is_new_deploy "$_idx" && printf 1 || printf 0)" = "1" ]; then
			_mode=new
			# 新版短命名部署：只校验它自己的短名，不碰任何 slug 同名段
			for _n in $(tkp_new_names "$_idx"); do
				tkp_refuse_if_unmarked "$_n"
			done
		else
			_mode=legacy
			# 旧版按 slug 命名的部署：逐个校验，缺少标记就整体中止
			[ -n "$_slug" ] || continue
			for _n in $(tkp_legacy_names "$_slug"); do
				tkp_refuse_if_unmarked "$_n"
			done
		fi
		CLEAN_PLAN="${CLEAN_PLAN}${_mode}${SEP}${_idx}${SEP}${_slug}
"
	done <<EOF
$MANIFEST_ROWS
EOF
fi

if [ "$REFUSED" != "0" ]; then
	printf '%s: 已中止：未停止服务、未删除任何 uci 段或文件。\n' "$PROG" >&2
	exit 4
fi
say "  标记预检通过"

# ---------------------------------------------------------------------------
# 运行时清理
# ---------------------------------------------------------------------------
tkp_nft_delete() {
	if ! command -v nft >/dev/null 2>&1; then
		warn "缺少 nft，跳过 nft 表清理"
		return 0
	fi
	if _e=$(nft delete table inet tkproxy 2>&1 >/dev/null); then
		return 0
	fi
	case "$_e" in
		*"No such file"*|*"does not exist"*|*"No such"*) return 0 ;;
		*) warn "删除 nft 表失败：$_e"; return 1 ;;
	esac
}

tkp_ip_del() {
	if ! command -v ip >/dev/null 2>&1; then
		warn "缺少 ip，跳过策略路由清理"
		return 0
	fi
	if _e=$(ip "$@" 2>&1 >/dev/null); then
		return 0
	fi
	case "$_e" in
		*"No such file"*|*"No such process"*|*"Cannot find"*|*"not found"*) return 0 ;;
		# 表/规则本来就不存在（iproute2 的两种报法）：清理必须幂等，不能当失败
		*"FIB table does not exist"*|*"Table does not exist"*|*"table does not exist"*) return 0 ;;
		*"does not exist"*) return 0 ;;
		*) warn "ip $* 失败：$_e"; return 1 ;;
	esac
}

say "== 1. 停服务 =="
if [ -x "$INIT_FILE" ]; then
	if ! "$INIT_FILE" stop 2>/dev/null; then
		warn "停止 $INIT_FILE 失败，继续清理（可能仍有进程占用配置）"
	fi
	if [ "$KEEP" = "0" ]; then
		if ! "$INIT_FILE" disable 2>/dev/null; then
			warn "禁用 $INIT_FILE 失败"
		fi
	fi
fi
tkp_nft_delete || die_code 5 "nft 表清理失败，已停止（未删除配置）"
# 只删本方案自己的 rule 与 local 路由，绝不 flush 整表
tkp_ip_del rule del fwmark "$MARK" lookup "$RT_TABLE" || die_code 5 "策略路由 rule 清理失败"
tkp_ip_del route del local 0.0.0.0/0 dev lo table "$RT_TABLE" || die_code 5 "策略路由 route 清理失败"
# 旧版本遗留：精确删除，不 flush。
# 这些是老版本写过的东西，现在多半不存在了；清不掉也只警告，绝不能因此中止整场清理。
tkp_ip_del rule del fwmark 0x1 lookup 100 || warn "旧策略路由 rule 清理未完成（继续）"
tkp_ip_del route del local 0.0.0.0/0 dev lo table 100 || warn "旧策略路由 route 清理未完成（继续）"
say "  服务与运行时已清理"

if [ "$KEEP" = "1" ]; then
	say "== 2. --keep-config：保留 uci 段与 $CONF_DIR =="
	say '已停止服务，配置保留。'
	exit 0
fi

# 删除 uci 段：只认 tkproxy=1 标记
# ---------------------------------------------------------------------------
say "== 2. 删除 uci 段 =="

# 2a. 所有带标记的段（新/旧命名都覆盖）
for _cfg in network dhcp firewall wireless; do
	uci -q show "$_cfg" >/dev/null 2>&1 || die "读取 uci $_cfg 失败"
	for _sec in $(uci -q show "$_cfg" 2>/dev/null \
		| sed -n "s/^\(${_cfg}\.[^.=]*\)\.tkproxy=[']*1[']*$/\1/p"); do
		tkp_del_marked "$_sec"
	done
done

# 2b. 按预检时固定的计划精确删除（每个段仍会再校验一次标记）
while IFS="$SEP" read -r _mode _idx _slug; do
	[ -n "$_mode" ] || continue
	if [ "$_mode" = "new" ]; then
		for _n in $(tkp_new_names "$_idx"); do
			tkp_del_marked "$_n"
		done
	else
		[ -n "$_slug" ] || continue
		for _n in $(tkp_legacy_names "$_slug"); do
			tkp_del_marked "$_n"
		done
	fi
done <<EOF
$CLEAN_PLAN
EOF

for _p in network dhcp firewall wireless; do
	uci commit "$_p" || die_code 6 "提交 uci $_p 失败；保留 $CONF_DIR/manifest.json，请检查权限/锁后重试"
done
say "  uci 段已删除并提交"

# ---------------------------------------------------------------------------
# 删除文件
# ---------------------------------------------------------------------------
say "== 3. 删除文件 =="
if [ -e "$CONF_DIR" ]; then
	# 只删部署产物；授权相关文件（license.json 等）必须保留
for _a in config.json tkproxy.nft manifest.json deploy-state.json; do
	rm -f "$CONF_DIR/$_a" 2>/dev/null
done
# 兜底：把备份里的授权文件放回
for _f in license.json license-verify license-ticket device.json; do
	if [ -s "$TKP_KEEP_DIR/$_f" ] && [ ! -s "$CONF_DIR/$_f" ]; then
		mkdir -p "$CONF_DIR" 2>/dev/null
		cp -f "$TKP_KEEP_DIR/$_f" "$CONF_DIR/$_f" 2>/dev/null
		chmod 600 "$CONF_DIR/$_f" 2>/dev/null
		say "  授权文件已保留：$_f"
	fi
done
rmdir "$CONF_DIR" 2>/dev/null || true
fi
if [ -e "$INIT_FILE" ]; then
	rm -f "$INIT_FILE" || die "删除 $INIT_FILE 失败"
fi
say "  $CONF_DIR 已删除"
say "  $INIT_FILE 已删除"

# ---------------------------------------------------------------------------
# 生效
# ---------------------------------------------------------------------------
say "== 4. 生效 =="
if [ -x /etc/init.d/network ]; then
	/etc/init.d/network reload || die "network reload 失败，拆除未完成"
fi
if command -v wifi >/dev/null 2>&1; then
	wifi reload || die "wifi reload 失败，拆除未完成"
elif [ -x /sbin/wifi ]; then
	/sbin/wifi reload || die "wifi reload 失败，拆除未完成"
else
	die "找不到 wifi 命令，拆除未完成"
fi
if [ -x /etc/init.d/dnsmasq ]; then
	/etc/init.d/dnsmasq restart || die "dnsmasq restart 失败，拆除未完成"
fi
if [ -x /etc/init.d/firewall ]; then
	/etc/init.d/firewall reload || die "firewall reload 失败，拆除未完成"
fi

# 确保主 WiFi 恢复（检查 phy0/phy1 的 AP 数，缺主 AP 视为失败）
say "  校验主 WiFi 恢复状态"
if ! tkp_ensure_wifi_up; then
	die "主 WiFi 未完全恢复，拆除失败"
fi

# 校验无线恢复：整机至少还有一个 AP 即算恢复；某颗射频没有 AP 只警告
sleep 2
total_ap=$(iw dev 2>/dev/null | grep -c 'ssid ' || true)
[ -z "$total_ap" ] && total_ap=0
if [ "$total_ap" = "0" ]; then
	die "清理后没有任何 AP 在广播，拆除失败（需手动恢复无线配置）"
fi
for phy in phy0 phy1; do
	if [ -d "/sys/class/ieee80211/$phy" ]; then
		ap_count=$(iw dev 2>/dev/null | grep -c "Interface ${phy}-ap\|Interface ${phy}ap" || true)
		[ -z "$ap_count" ] && ap_count=0
		if [ "$ap_count" = "0" ]; then
			warn "$phy 清理后没有 AP（该射频原本可能被线路占满，需要的话请手动加一个主 WiFi）"
		else
			say "  $phy: $ap_count AP 已恢复"
		fi
	fi
done

say '已拆除，主 WiFi 已恢复。'
