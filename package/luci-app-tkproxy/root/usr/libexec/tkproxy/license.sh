#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 卡密门禁（移植自 ssidproxy license.sh，接口/字段保持一致）
#
# 用法：
#   license.sh status            # 输出状态 JSON（给页面用）
#   license.sh activate <卡密>    # 首次激活
#   license.sh verify            # 立即联网校验（更新到期时间/票据）
#   license.sh reset             # 清除本地授权（换卡/排障）
#   license.sh machine           # 只输出机器码
#   license.sh gate              # 门禁：未激活返回非 0
#
# 授权文件：/etc/tkproxy/license.json（600）
#
# 门禁判定（lic_judge，状态展示与写入门禁共用同一份）：
#   license.json 带 signature 字段 → 必须通过 usign 验签
#   （kid 可信 + 签名有效 + device_id 是本机 + 未过期）才放行；
#   无 signature 的老票 → 宽限截止前放行（legacy=true）；
#   验签不过 → 锁定并在 status JSON 里给出准确 reason。

# 路径可用环境变量覆盖（tests/test-tk-license.sh 用它指向临时授权文件）
LIC_DIR="${TK_LIC_DIR:-/etc/tkproxy}"
LIC_FILE="${TK_LIC_FILE:-${LIC_DIR}/license.json}"
LIC_PRIMARY="https://02.lkkami.top/api"
LIC_BACKUP="https://autocut.webbj.cn/api"
LIC_APPID_DEFAULT="4b03dda5-ea11-4a00-9651-e2ed985b5803"
LIC_DNS_RESOLVER="223.5.5.5"
LIC_KID_TRUSTED="license-key-2026-06"
LIC_KEYNUM="12345678"
LIC_PUBKEY="${TK_LIC_PUBKEY:-2hITlqAUX_kswyDynm09Yk6iokSC0jxa3wO6YkyV9rw}"
# 签名原文规范化器（与服务端 serde_json 输出逐字节一致；验签的硬前提）
LIC_CANON="${TK_CANON:-/usr/libexec/tkproxy/canon.lua}"
# 老格式（license.json 里没有票据）的宽限截止：1801497600 = 2027-02-01 16:00:00 UTC。
# 在此之前老用户无票据也放行（legacy=true）；之后必须联网激活一次拿到票据。
# 可用 TK_LIC_LEGACY_DEADLINE 环境变量覆盖（测试注入用）。
TMPD="${TK_TMP:-/tmp/tkproxy}"
LOG="${TK_LOG:-/tmp/tkproxy/license.log}"

B64LUA="$(dirname "$0")/b64.lua"
# 纯 Lua base64：25.12 起 busybox 没有 base64 applet，外部命令不可依赖
b64e() { lua "$B64LUA" enc; }
b64d() { lua "$B64LUA" dec; }

mkdir -p "$TMPD" "$LIC_DIR" 2>/dev/null

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null; }

lic_appid() {
	local v
	v=$(uci -q get tkproxy.main.license_appid 2>/dev/null)
	[ -n "$v" ] || v="$LIC_APPID_DEFAULT"
	printf '%s' "$v"
}

lic_version() {
	local v
	v=$(sed -n 's/^Version:[[:space:]]*//p' /usr/lib/opkg/info/luci-app-tkproxy.control 2>/dev/null | head -n1)
	# 25.12 起是 apk 系统：已装版本在 /lib/apk/db/installed（P:/V: 两行）
	if [ -z "$v" ] && [ -f /lib/apk/db/installed ]; then
		v=$(awk '/^P:luci-app-tkproxy$/{f=1;next} f&&/^V:/{print substr($0,3);exit}' /lib/apk/db/installed 2>/dev/null)
	fi
	[ -n "$v" ] || v="0"
	v=$(printf '%s' "$v" | sed 's/-r[0-9][0-9]*$//; s/-[0-9][0-9]*$//')
	printf 'v%s' "$v"
}

lic_nonce() { head -c 16 /dev/urandom 2>/dev/null | md5sum | cut -d' ' -f1; }

# 机器码：SHA256(板型|LAN MAC|WAN MAC) 前 32 位大写
lic_machine() {
	local board p0 p1 raw
	board=$(cat /tmp/sysinfo/board_name 2>/dev/null)
	[ -n "$board" ] || board=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\000')
	[ -n "$board" ] || board="generic"
	# 无线 EEPROM MAC 写在出厂校准分区里，uci / ifconfig 改不了，改了就没有无线信号，
	# 是这台机器上最难伪造的标识——防「把固件备份搬到另一台机器」主要靠它
	p0=$(cat /sys/class/ieee80211/phy0/macaddress 2>/dev/null)
	p1=$(cat /sys/class/ieee80211/phy1/macaddress 2>/dev/null)
	# 只取出厂硬标识：客户在 uci 里改 br-lan/wan 的 MAC 不会导致换机误判
	raw="${board}|${p0}|${p1}"
	if command -v sha256sum >/dev/null 2>&1; then
		printf '%s' "$raw" | sha256sum | cut -c1-32 | tr 'a-f' 'A-F'
	else
		printf '%s' "$raw" | md5sum | cut -c1-32 | tr 'a-f' 'A-F'
	fi
}

# 旧算法（board + br-lan + wan，不含无线 MAC）：老客户升级后票据仍按旧指纹签发，
# 这里保留一份用于兼容，避免升级插件后所有人被判定「换机」。
lic_machine_legacy() {
	local board lan wan raw
	board=$(cat /tmp/sysinfo/board_name 2>/dev/null)
	[ -n "$board" ] || board=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\000')
	[ -n "$board" ] || board="generic"
	lan=$(cat /sys/class/net/br-lan/address 2>/dev/null)
	[ -n "$lan" ] || lan=$(cat "/sys/class/net/$(uci -q get network.lan.ifname 2>/dev/null | awk '{print $1}')/address" 2>/dev/null)
	wan=$(uci -q get network.wan.device 2>/dev/null)
	[ -n "$wan" ] || wan=$(uci -q get network.wan.ifname 2>/dev/null)
	wan=$(printf '%s' "$wan" | awk '{print $1}')
	[ -n "$wan" ] && wan=$(cat "/sys/class/net/${wan}/address" 2>/dev/null)
	raw="${board}|${lan}|${wan}"
	if command -v sha256sum >/dev/null 2>&1; then
		printf '%s' "$raw" | sha256sum | cut -c1-32 | tr 'a-f' 'A-F'
	else
		printf '%s' "$raw" | md5sum | cut -c1-32 | tr 'a-f' 'A-F'
	fi
}

lic_machine_pretty() {
	local m; m=$(lic_machine)
	printf '%s-%s-%s-%s' "$(printf '%s' "$m" | cut -c1-8)" "$(printf '%s' "$m" | cut -c9-16)" \
		"$(printf '%s' "$m" | cut -c17-24)" "$(printf '%s' "$m" | cut -c25-32)"
}

lic_device_name() {
	local model lan
	model=$(cat /tmp/sysinfo/model 2>/dev/null)
	[ -n "$model" ] || model="OpenWrt"
	lan=$(cat /sys/class/net/br-lan/address 2>/dev/null | tr -d ':' | tail -c 5)
	printf '%s-%s' "$(printf '%s' "$model" | tr ' ' '_')" "$(printf '%s' "$lan" | tr 'a-f' 'A-F')"
}

# 服务器时间（HTTP Date）。
# 注意：客户设备没有 RTC，首次开机时钟停在固件编译日期，此时服务器证书
# 「尚未生效」，curl 校验必失败，连 Date 头都读不到。所以拿不到时用 -k 兜底——
# 这里只取时间，真正的安全保证是票据的 usign 验签（见 lic_judge）。
lic_server_time() {
	local url="$1" hdr srv
	hdr=$(curl -m 5 --connect-timeout 3 -sSI "$url" 2>/dev/null | sed -n 's/^[Dd]ate: //p' | head -n1 | tr -d '\r')
	[ -n "$hdr" ] || hdr=$(curl -k -m 5 --connect-timeout 3 -sSI "$url" 2>/dev/null | sed -n 's/^[Dd]ate: //p' | head -n1 | tr -d '\r')
	[ -n "$hdr" ] || return 1
	srv=$(date -u -D '%a, %d %b %Y %H:%M:%S GMT' -d "$hdr" +%s 2>/dev/null)
	[ -n "$srv" ] || return 1
	echo "$srv"
}

# 服务器时间差（HTTP Date），防止本机时间不准导致判决错误
lic_time_offset() {
	local srv now
	srv=$(lic_server_time "$1") || return 1
	now=$(date +%s)
	echo $((srv - now))
}

# 本机时钟偏差超过一天就用服务器时间校正系统时钟。
# 现场症状：客户说明明有网，插件却报「无法连接卡密服务器」——其实是时钟错、证书校不过。
lic_fix_clock() {
	local srv now off
	srv=$(lic_server_time "$1") || return 1
	now=$(date +%s)
	off=$((srv - now))
	if [ "$off" -gt 86400 ] || [ "$off" -lt -86400 ]; then
		date -s "@$srv" >/dev/null 2>&1 || date -u -D '%s' -d "@$srv" >/dev/null 2>&1
		log "系统时钟偏差 ${off}s，已按服务器时间校正"
		return 0
	fi
	return 1
}

# 直连 POST（不走代理；域名用国内 DNS 解析后 --resolve，避免被本机分流影响）
lic_post() {
	local base="$1" path="$2" body="$3" host ip resolve=""
	host=$(printf '%s' "$base" | sed 's#^https\?://##; s#/.*##')
	ip=$(nslookup "$host" "$LIC_DNS_RESOLVER" 2>/dev/null | awk '/^Address: /{a=$2} END{print a}')
	[ -n "$ip" ] && resolve="--resolve ${host}:443:${ip}"
	curl -m 8 --connect-timeout 4 -s -X POST ${resolve} \
		-H 'Content-Type: application/json' \
		--data "$body" "${base}${path}" 2>/dev/null
}

lic_body() { # <card> [offset]
	local card="$1" off="${2:-0}"
	printf '{"app_id":"%s","license_scope":"main","card_code":"%s","device_id":"%s","device_name":"%s","client_version":"%s","nonce":"%s","timestamp":%s}' \
		"$(lic_appid)" "$card" "$(lic_machine)" "$(lic_device_name)" "$(lic_version)" "$(lic_nonce)" "$(( $(date +%s) + off ))"
}

# 解析响应：ok|code|message|expires_at|card_mask
lic_parse() {
	lua - "$1" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then print("false|||0|") os.exit(0) end
local o = jsonc.parse(arg[1] or "")
if type(o) ~= "table" then print("false||parse_error|0|") os.exit(0) end
local d = o.data or {}
local e = d.entitlement or {}
print(table.concat({
  tostring(o.success == true and o.valid == true),
  tostring(o.code or ""),
  tostring(o.message or ""),
  tostring(e.expires_at or 0),
  tostring(e.card_mask or ""),
}, "|"))
LUA
}

lic_b64url_to_b64() {
	local s; s=$(printf '%s' "$1" | tr '_-' '/+')
	case $(( ${#s} % 4 )) in
		2) s="${s}==" ;;
		3) s="${s}=" ;;
	esac
	printf '%s' "$s"
}

# usign 验签：<canonical_msg_file> <sig_b64url>
# 没有 usign 时必须判失败（return 1）而不是跳过：
# 门禁依赖验签结论，放行等于「无验签工具的机器全部免检」。
lic_usign_verify() {
	local msg="$1" sig="$2" d rc
	[ -s "$msg" ] || return 1
	[ -n "$sig" ] || return 1
	command -v usign >/dev/null 2>&1 || { log "usign 不存在，验签失败"; return 1; }

	d="${TMPD}/licsig.$$"
	# 不用 -p：目录已存在（可能被预置）就视为失败，防止竞态借用别人的目录
	mkdir "$d" 2>/dev/null || return 1
	{ printf 'Ed%s' "$LIC_KEYNUM"; printf '%s' "$(lic_b64url_to_b64 "$LIC_PUBKEY")" | b64d; } > "$d/pub.bin" 2>/dev/null || { rm -rf "$d"; return 1; }
	printf 'untrusted comment: tkproxy\n' > "$d/pub.txt"
	b64e < "$d/pub.bin" >> "$d/pub.txt"; printf '\n' >> "$d/pub.txt"

	{ printf 'Ed%s' "$LIC_KEYNUM"; printf '%s' "$(lic_b64url_to_b64 "$sig")" | b64d; } > "$d/sig.bin" 2>/dev/null || { rm -rf "$d"; return 1; }
	# 签名必须是 64 字节（74 = 10 字节 signify 头 + 64），短了说明被截断或本来就是垃圾
	if [ "$(wc -c <"$d/sig.bin" 2>/dev/null)" != "74" ]; then rm -rf "$d"; return 1; fi
	printf 'untrusted comment: tkproxy\n' > "$d/sig.txt"
	b64e < "$d/sig.bin" >> "$d/sig.txt"; printf '\n' >> "$d/sig.txt"

	usign -V -m "$msg" -x "$d/sig.txt" -p "$d/pub.txt" >/dev/null 2>&1
	rc=$?
	rm -rf "$d"
	return $rc
}

# 从本地授权文件取出 entitlement 的 JSON（没有就输出空）
lic_entitlement_json() {
	[ -f "$LIC_FILE" ] || return 0
	lua - "$LIC_FILE" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(0) end
local fh = io.open(arg[1], "r")
if not fh then os.exit(0) end
local o = jsonc.parse(fh:read("*a") or "")
fh:close()
if type(o) == "table" and type(o.entitlement) == "table" then
	print(jsonc.stringify(o.entitlement))
end
LUA
}

# 校验一张票据：<entitlement_json> <signature> <kid>
# 打印状态词并返回 0（valid）/ 非 0（具体原因）：
#   missing / untrusted_kid / canon_failed / bad_signature /
#   foreign_device / expired / bad_expiry
lic_ticket_check() {
	local ent="$1" sig="$2" kid="$3" d canon dev exp now

	[ -n "$ent" ] && [ -n "$sig" ] || { printf 'missing'; return 1; }
	# kid 必须是我们信任的那把密钥，否则是别的密钥签的票
	if [ -n "$kid" ] && [ "$kid" != "$LIC_KID_TRUSTED" ]; then
		printf 'untrusted_kid'; return 1
	fi

	d="${TMPD}/lictick.$$"
	# 不用 -p：目录已存在（可能被预置）就视为失败，防止竞态借用别人的目录
	mkdir "$d" 2>/dev/null || { printf 'io_error'; return 1; }
	printf '%s' "$ent" > "$d/e.json"
	# 规范化必须与签名时逐字节一致，否则真票也验不过
	canon=$(lua "$LIC_CANON" < "$d/e.json" 2>/dev/null)
	rm -rf "$d"
	[ -n "$canon" ] || { printf 'canon_failed'; return 1; }

	d="${TMPD}/lictick2.$$"
	mkdir "$d" 2>/dev/null || { printf 'io_error'; return 1; }
	printf '%s' "$canon" > "$d/msg"
	if ! lic_usign_verify "$d/msg" "$sig"; then
		rm -rf "$d"
		printf 'bad_signature'; return 1
	fi
	rm -rf "$d"

	# 票据必须属于本机：把票据拷到别的路由器上不能用
	dev=$(printf '%s' "$ent" | jsonfilter -e '@.device_id' 2>/dev/null)
	if [ -n "$dev" ]; then
		if [ "$dev" != "$(lic_machine)" ] && [ "$dev" != "$(lic_machine_legacy)" ]; then
			printf 'foreign_device'; return 1
		fi
	fi

	# 授权是永久的：激活之后不再按时间判定。
	# 卡密唯一作用是绑定本机（device_id 来自由出厂校准数据算出的机器指纹），
	# 把固件/备份搬到别的机器时 device_id 不同，判 foreign_device。

	printf 'valid'
	return 0
}

lic_ticket_write() { # <ent_json> <sig> <kid>
	local ent="$1" sig="$2" kid="$3"
	[ -n "$ent" ] && [ -n "$sig" ] || return 1
	lua - "$LIC_FILE" "$ent" "$sig" "$kid" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(1) end
local path, ent_s, sig, kid = arg[1], arg[2], arg[3], arg[4]
local fh = io.open(path, "r")
if not fh then os.exit(1) end
local o = jsonc.parse(fh:read("*a") or "")
fh:close()
if type(o) ~= "table" or o.machine == nil then os.exit(1) end
local e = jsonc.parse(ent_s or "")
if type(e) ~= "table" then os.exit(1) end
o.entitlement = e
o.signature = sig
o.ticket_kid = kid or ""
o.ticket_expires_at = tonumber(e.expires_at) or 0
o.ticket_issued_at = tonumber(e.issued_at) or 0
local tmp = path .. ".tk"
local w = io.open(tmp, "w")
if not w then os.exit(1) end
w:write(jsonc.stringify(o))
w:close()
os.execute("chmod 600 '" .. tmp .. "' 2>/dev/null")
os.rename(tmp, path)
os.exit(0)
LUA
}

lic_ticket_extract() { # <response> → ent \t sig \t kid
	lua - "$1" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then print("") os.exit(0) end
local o = jsonc.parse(arg[1] or "")
if type(o) ~= "table" or type(o.data) ~= "table" then print("") os.exit(0) end
local d = o.data
if type(d.entitlement) ~= "table" or type(d.signature) ~= "string" or d.signature == "" then print("") os.exit(0) end
print(jsonc.stringify(d.entitlement) .. "\t" .. d.signature .. "\t" .. tostring(d.kid or ""))
LUA
}

# 保存授权（原子写 + 回读校验）
lic_save() { # <card> <expires_at> <card_mask>
	local card="$1" exp="${2:-0}" mask="$3"
	mkdir -p "$LIC_DIR" 2>/dev/null
	lua - "$LIC_FILE" "$(lic_machine)" "$(lic_machine_pretty)" "$(lic_device_name)" "$card" "$exp" "$mask" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(1) end
local path, machine, pretty, dname, card, exp, mask = arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7]
local card_b64 = ""
if card and card ~= "" then
  local p = io.popen("printf '%s' " .. string.format("%q", card) .. " | lua '" .. (os.getenv("TK_B64LUA") or "/usr/libexec/tkproxy/b64.lua") .. "' enc")
  card_b64 = p and p:read("*a") or ""
  if p then p:close() end
end
local masked = mask
if (not masked or masked == "") and card and #card > 8 then
  masked = card:sub(1,4) .. "****" .. card:sub(-4)
end
local o = {
  machine = machine, machine_pretty = pretty, device_name = dname,
  card_b64 = card_b64, card_mask = masked ~= "" and masked or "****",
  activated = true, expires_at = tonumber(exp) or 0,
  activated_at = os.time(), last_check = os.time(), need_reactivate = false,
}
local tmp = path .. ".tmp"
local w = io.open(tmp, "w")
if not w then os.exit(1) end
w:write(jsonc.stringify(o))
w:close()
os.execute("chmod 600 '" .. tmp .. "' 2>/dev/null")
os.rename(tmp, path)
local chk = io.open(path, "r")
if not chk then os.exit(1) end
local got = jsonc.parse(chk:read("*a") or "")
chk:close()
if type(got) ~= "table" or got.machine ~= machine or got.activated ~= true then os.exit(1) end
os.exit(0)
LUA
}

lic_field() { # <name>
	[ -f "$LIC_FILE" ] || return 0
	lua - "$LIC_FILE" "$1" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(0) end
local fh = io.open(arg[1], "r"); if not fh then os.exit(0) end
local o = jsonc.parse(fh:read("*a") or ""); fh:close()
if type(o) ~= "table" then os.exit(0) end
local v = o[arg[2]]
if v == nil then os.exit(0) end
if type(v) == "boolean" then print(v and "1" or "0") else print(tostring(v)) end
LUA
}

lic_stored_card() {
	[ -f "$LIC_FILE" ] || return 0
	lua - "$LIC_FILE" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(0) end
local fh = io.open(arg[1], "r"); if not fh then os.exit(0) end
local o = jsonc.parse(fh:read("*a") or ""); fh:close()
if type(o) ~= "table" or type(o.card_b64) ~= "string" or o.card_b64 == "" then os.exit(0) end
local p = io.popen("printf '%s' '" .. o.card_b64 .. "' | lua '" .. (os.getenv("TK_B64LUA") or "/usr/libexec/tkproxy/b64.lua") .. "' dec 2>/dev/null")
local card = p and p:read("*a") or ""
if p then p:close() end
io.write(card)
LUA
}

# 统一判决：状态展示与写入门禁必须用同一份判定，避免「页面显示已激活、
# 门禁判定却是另一套」。三输出：
#   LIC_J_STATE=activated | locked
#   LIC_J_REASON=ok | not_activated | sig_invalid | foreign_device |
#                expired | legacy_expired | usign_missing | missing |
#                untrusted_kid | canon_failed | bad_expiry | io_error
#   LIC_J_LEGACY=1        老票（无票据）在宽限期内放行
# 判定树（与 ssidproxy 真机验证过的三分支一致）：
#   1) 无授权文件 / activated 非 1        → 未激活
#   2) 有 signature 字段 → 必须整票验签通过（kid/签名/本机/到期）
#   3) 无 signature（老票）→ 宽限截止前放行并标 legacy；之后锁
lic_judge() {
	local act sig kid ent st
	LIC_J_STATE=locked
	LIC_J_REASON=not_activated
	LIC_J_LEGACY=0

	[ -f "$LIC_FILE" ] || return 1
	act=$(lic_field activated)
	[ "$act" = "1" ] || return 1

	sig=$(lic_field signature)
	if [ -n "$sig" ]; then
		# 带票据的文件：整票校验，任何一环不过都给准确原因
		kid=$(lic_field ticket_kid)
		ent=$(lic_entitlement_json)
		st=$(lic_ticket_check "$ent" "$sig" "$kid")
		case "$st" in
			valid)
				LIC_J_STATE=activated; LIC_J_REASON=ok; return 0 ;;
			missing|bad_signature|canon_failed|untrusted_kid|io_error)
				# 签名在文件里却在本地验不过：票据字段被改坏，或真票被篡改
				LIC_J_REASON=sig_invalid; return 1 ;;
			foreign_device)
				LIC_J_REASON=foreign_device; return 1 ;;
			expired)
				LIC_J_REASON=expired; return 1 ;;
			bad_expiry)
				LIC_J_REASON=bad_expiry; return 1 ;;
			*)
				LIC_J_REASON=sig_invalid; return 1 ;;
		esac
	fi

	# 老票（无票据）：宽限期内放行，过期截止后必须联网激活拿新票
	# 每次判决时现取覆盖值（默认 1801497600 = 2027-02-01 16:00 UTC），便于测试注入
	local now deadline
	now=$(date +%s)
	deadline="${TK_LIC_LEGACY_DEADLINE:-1801497600}"
	if [ "$now" -lt "$deadline" ]; then
		LIC_J_STATE=activated
		LIC_J_REASON=ok
		LIC_J_LEGACY=1
		return 0
	fi
	LIC_J_REASON=legacy_expired
	return 1
}

# 统一判决的机器可读版（status JSON 用）：reason / legacy 两个字段
lic_judge_01() {
	lic_judge >/dev/null 2>&1
	printf '%s %s %s' "$( [ "$LIC_J_STATE" = "activated" ] && echo 1 || echo 0 )" \
		"$LIC_J_REASON" "$LIC_J_LEGACY"
}

lic_state_json() {
	local act machine mask exp now left need lc j st reason legacy ent_exp
	j=$(lic_judge_01)
	st=$(printf '%s' "$j" | cut -d' ' -f1)
	reason=$(printf '%s' "$j" | cut -d' ' -f2)
	legacy=$(printf '%s' "$j" | cut -d' ' -f3)
	machine=$(lic_machine_pretty)
	mask=$(lic_field card_mask); [ -n "$mask" ] || mask=""
	# 展示用的到期时间取签名票据里的 expires_at（顶层字段可被改，不可信）；
	# 无票据的老票才退回顶层字段（它本来就无签名，展示仅参考）
	ent_exp=$(lic_entitlement_json | jsonfilter -e '@.expires_at' 2>/dev/null)
	case "$ent_exp" in ''|*[!0-9]*) ent_exp="" ;; esac
	exp="${ent_exp:-$(lic_field expires_at)}"; [ -n "$exp" ] || exp=0
	need=$(lic_field need_reactivate); [ -n "$need" ] || need=0
	lc=$(lic_field last_check); [ -n "$lc" ] || lc=0
	now=$(date +%s)
	left=0
	if [ "$exp" -gt 0 ] 2>/dev/null; then
		left=$(( (exp - now) / 86400 ))
		[ "$left" -lt 0 ] && left=0
	fi
	local expired=false   # 永久授权：没有到期概念
	printf '{"activated":%s,"machine":"%s","card_mask":"%s","expires_at":%s,"days_left":%s,"expired":%s,"need_reactivate":%s,"last_check":%s,"reason":"%s","legacy":%s,"app_id":"%s","version":"%s","usign":%s}' \
		"$( [ "$st" = "1" ] && echo true || echo false )" "$machine" "$mask" "$exp" "$left" \
		"$expired" "$( [ "$need" = "1" ] && echo true || echo false )" "$lc" \
		"$reason" "$( [ "$legacy" = "1" ] && echo true || echo false )" \
		"$(lic_appid)" "$(lic_version)" \
		"$( command -v usign >/dev/null 2>&1 && echo true || echo false )"
}

lic_gate() {
	local j st reason
	j=$(lic_judge_01)
	st=$(printf '%s' "$j" | cut -d' ' -f1)
	reason=$(printf '%s' "$j" | cut -d' ' -f2)
	[ "$st" = "1" ] && return 0
	case "$reason" in
		not_activated)    echo "未激活：请先输入卡密" ;;
		sig_invalid)      echo "授权文件被修改过：请重新输入卡密" ;;
		foreign_device)   echo "这张授权票据不属于本机：请重新输入卡密" ;;
		expired)          echo "授权已到期：请续费后重新激活" ;;
		bad_expiry)       echo "授权文件被修改过：请重新输入卡密" ;;
		legacy_expired)   echo "授权需要升级：请联网一次完成票据更新" ;;
		*)                echo "授权校验异常（$reason）：请重新激活" ;;
	esac
	return 1
}

lic_activate() {
	local card="$1" off resp res ok code msg exp mask
	[ -n "$card" ] || { echo "ERR 请输入卡密"; return 1; }
	# 快速失败：没有默认路由就立刻给明确提示，别让前端白等 20~40 秒
	if ! ip route 2>/dev/null | grep -q '^default'; then
		echo "ERR 网络未就绪：请先把网线插到路由器的 WAN 口（或检查上游是否给地址）"
		return 1
	fi
	# 时钟明显不对时先校正，否则 HTTPS 证书校验必失败（客户机无 RTC 的常见故障）
	lic_fix_clock "$LIC_PRIMARY" >/dev/null 2>&1
	off=$(lic_time_offset "$LIC_PRIMARY")
	off=${off:-0}
	resp=$(lic_post "$LIC_PRIMARY" "/v2/license/activate" "$(lic_body "$card" "$off")")
	if [ -z "$resp" ]; then
		# 再兜一次：可能刚接入网络时时钟仍偏，校正后重试
		lic_fix_clock "$LIC_PRIMARY" >/dev/null 2>&1
		off=$(lic_time_offset "$LIC_PRIMARY")
		off=${off:-0}
		resp=$(lic_post "$LIC_PRIMARY" "/v2/license/activate" "$(lic_body "$card" "$off")")
	fi
	if [ -z "$resp" ]; then
		off=$(lic_time_offset "$LIC_BACKUP")
		off=${off:-0}
		resp=$(lic_post "$LIC_BACKUP" "/v2/license/activate" "$(lic_body "$card" "$off")")
	fi
	[ -n "$resp" ] || { echo "ERR 无法连接卡密服务器（网络或 DNS 异常）"; return 1; }
	res=$(lic_parse "$resp")
	ok=$(printf '%s' "$res" | cut -d'|' -f1)
	code=$(printf '%s' "$res" | cut -d'|' -f2)
	msg=$(printf '%s' "$res" | cut -d'|' -f3)
	exp=$(printf '%s' "$res" | cut -d'|' -f4)
	mask=$(printf '%s' "$res" | cut -d'|' -f5)
	if [ "$ok" = "true" ]; then
		if ! lic_save "$card" "$exp" "$mask"; then
			echo "ERR 授权写入失败：本地保存未通过校验（磁盘满或目录不可写）"
			return 1
		fi
		local tick ent sig kid
		tick=$(lic_ticket_extract "$resp")
		if [ -n "$tick" ]; then
			ent=$(printf '%s' "$tick" | cut -f1)
			sig=$(printf '%s' "$tick" | cut -f2)
			kid=$(printf '%s' "$tick" | cut -f3)
			lic_ticket_write "$ent" "$sig" "$kid" || log "票据写入失败（不影响激活）"
		fi
		log "激活成功 mask=$mask exp=$exp"
		printf 'OK 激活成功（%s）\n' "$mask"
		return 0
	fi
	log "激活失败 code=$code msg=$msg"
	printf 'ERR %s %s\n' "$code" "$msg"
	return 1
}

# 静默核验（每天一次）：只记录，不改变授权状态、不阻塞任何功能。
# 作用：确认「这台的票据确实属于这台机器」，为售后排查和盗版追踪留证据。
lic_dailycheck() {
	local j st reason card resp ok
	j=$(lic_judge_01)
	st=$(printf '%s' "$j" | cut -d' ' -f1)
	reason=$(printf '%s' "$j" | cut -d' ' -f2)
	log "dailycheck: local state=$st reason=$reason"
	printf '%s local=%s reason=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$st" "$reason"

	card=$(lic_stored_card)
	[ -n "$card" ] || return 0
	# 联网确认只做记录：连不上就跳过，绝不影响已经激活的机器
	resp=$(lic_post "$LIC_PRIMARY" "/v2/license/verify" "$(lic_body "$card" 0)")
	if [ -z "$resp" ]; then
		log "dailycheck: 服务器不可达（不影响使用）"
		printf '  server=unreachable\n'
		return 0
	fi
	ok=$(lic_parse "$resp" | cut -d'|' -f1)
	log "dailycheck: server ok=$ok"
	printf '  server_ok=%s\n' "$ok"
	return 0
}

lic_verify() {
	local card off resp res ok code msg exp mask
	lic_gate >/dev/null 2>&1 || :  # 校验不改变门禁结论
	card=$(lic_stored_card)
	[ -n "$card" ] || { echo "ERR 本机尚未激活"; return 1; }
	off=$(lic_time_offset "$LIC_PRIMARY")
	off=${off:-0}
	resp=$(lic_post "$LIC_PRIMARY" "/v2/license/verify" "$(lic_body "$card" "$off")")
	if [ -z "$resp" ]; then
		off=$(lic_time_offset "$LIC_BACKUP")
		off=${off:-0}
		resp=$(lic_post "$LIC_BACKUP" "/v2/license/verify" "$(lic_body "$card" "$off")")
	fi
	[ -n "$resp" ] || { echo "ERR 网络不可用：连不上卡密服务器（本地票据仍然有效，不影响使用）"; return 1; }
	res=$(lic_parse "$resp")
	ok=$(printf '%s' "$res" | cut -d'|' -f1)
	code=$(printf '%s' "$res" | cut -d'|' -f2)
	msg=$(printf '%s' "$res" | cut -d'|' -f3)
	exp=$(printf '%s' "$res" | cut -d'|' -f4)
	mask=$(printf '%s' "$res" | cut -d'|' -f5)
	if [ "$ok" = "true" ]; then
		lic_save "$card" "$exp" "$mask" >/dev/null 2>&1
		local tick ent sig kid
		tick=$(lic_ticket_extract "$resp")
		if [ -n "$tick" ]; then
			ent=$(printf '%s' "$tick" | cut -f1); sig=$(printf '%s' "$tick" | cut -f2); kid=$(printf '%s' "$tick" | cut -f3)
			lic_ticket_write "$ent" "$sig" "$kid" >/dev/null 2>&1
		fi
		# 服务端校验通过后本地票据必须也过得了验签，门禁结论以本地验签为准：
		# 服务端说 ok 但本地票被篡改/写坏时，这里如实报告而不是假报成功
		local j st reason
		j=$(lic_judge_01)
		st=$(printf '%s' "$j" | cut -d' ' -f1)
		reason=$(printf '%s' "$j" | cut -d' ' -f2)
		if [ "$st" != "1" ]; then
			log "校验后本地验签未通过 reason=$reason"
			printf 'ERR 本地票据校验未通过（%s），请重新激活\n' "$reason"
			return 1
		fi
		log "校验通过 exp=$exp"
		printf 'OK 校验通过\n'
		return 0
	fi
	log "校验未通过 code=$code msg=$msg"
	printf 'ERR %s %s\n' "$code" "$msg"
	return 1
}

lic_reset() {
	local f n=0
	for f in "$LIC_FILE" "${LIC_FILE}.bak" "${LIC_FILE}".tmp.* "${LIC_FILE}".tk; do
		[ -e "$f" ] || continue
		rm -f "$f" 2>/dev/null
		[ -e "$f" ] && continue
		n=$((n + 1))
	done
	if [ -e "$LIC_FILE" ]; then
		echo "ERR 清除失败：${LIC_FILE} 无法删除"
		return 1
	fi
	log "已清除本机授权（$n 个文件）"
	echo "OK 已清除本地授权"
	return 0
}

# 被 source（tests/test-tk-license.sh）时只加载函数，不触发命令分发
if [ -n "${TK_LIC_SOURCED:-}" ]; then
	return 0 2>/dev/null || :
fi

case "$1" in
	status)   lic_state_json ;;
	machine)  lic_machine_pretty ;;
	activate) lic_activate "$2" ;;
	verify)   lic_verify ;;
	dailycheck) lic_dailycheck ;;
	fixclock) # 校正系统时钟（无 RTC 设备首次开机时钟停在编译日期，会让 HTTPS 全部校验失败）
		if lic_fix_clock "$LIC_PRIMARY"; then echo "OK 时钟已校正：$(date '+%Y-%m-%d %H:%M:%S')"
		elif srv=$(lic_server_time "$LIC_PRIMARY"); then echo "OK 时钟正常：$(date '+%Y-%m-%d %H:%M:%S')"
		else echo "ERR 取不到服务器时间（网络未就绪）"; exit 1; fi ;;
	reset)    lic_reset ;;
	gate)     lic_gate ;;
	ticket)   # 调试口：输出整票校验状态词（与 lic_gate 同一判定核心）
		st=$(lic_ticket_check "$(lic_entitlement_json)" "$(lic_field signature)" "$(lic_field ticket_kid)")
		printf '%s\n' "$st" ;;
	*)
		echo "用法: license.sh status|machine|activate <卡密>|verify|reset|gate|ticket" ;;
esac
