#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 云端更新（带 Ed25519 签名校验）
#
# 为什么这样设计（老插件当初就是因此删掉了在线更新）：
#   1) 清单必须走 HTTPS
#   2) 包体必须有 SHA256，且清单必须能通过内嵌公钥的 Ed25519 验签
#   3) 装之前校验 包名/版本/架构/包管理器，任何一步不过就不装
#
# 用法：
#   update.sh check      # 查最新版（输出 JSON）
#   update.sh install    # 下载并安装已验证的新版（输出 JSON）
#   update.sh version    # 只输出当前版本
#
# 更新源：uci get tkproxy.main.update_url
#   推荐：.../manifest.json（同目录需有 manifest.json.sig，Ed25519 签名）
#   兼容：.../version.json（老插件格式 {"version","url","notes"}）
#         老格式没有签名；若连 sha256 都没有，必须显式开：
#           uci set tkproxy.main.update_allow_unsigned=1


TK_UPD_KEYNUM="12345678"
TK_UPD_PUBKEY="${TK_UPD_PUBKEY:-0Fqi3kSkPgjUY63m+CsUtQwWykniYj2hkPuJxJArVRE=}"
PKG="luci-app-tkproxy"
# 内置更新源（不对外显示；uci tkproxy.main.update_url 可覆盖）
TK_UPD_DEFAULT="https://up.lkkami.top/tkproxy/manifest.json"
WORK="/tmp/tkproxy/update"
LOG="/tmp/tkproxy/update.log"

B64LUA="$(dirname "$0")/b64.lua"
# 25.12 起 busybox 无 base64 applet，统一走纯 Lua 实现
b64e() { lua "$B64LUA" enc; }
b64d() { lua "$B64LUA" dec; }

mkdir -p "$WORK" 2>/dev/null
rm -rf "$LOG" 2>/dev/null
: > "$LOG" 2>/dev/null

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >> "$LOG" 2>/dev/null; }

json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }

# apk 的版本写法是 3.13.5-r1，opkg 是 3.13.5-1：比较前统一成 3.13.5-1
norm_ver() { printf '%s' "$1" | sed 's/-r\([0-9][0-9]*\)$/ -\1/; s/ //g'; }

installed_version() {
	local v
	v=$(sed -n 's/^Version:[[:space:]]*//p' /usr/lib/opkg/info/"$PKG".control 2>/dev/null | head -n1)
	if [ -z "$v" ] && command -v apk >/dev/null 2>&1; then
		# apk 系统（25.12+）：从已装数据库读版本
		v=$(awk -v p="$PKG" '/^P:/{cur=substr($0,3)} /^V:/{if(cur==p){print substr($0,3); exit}}' /lib/apk/db/installed 2>/dev/null)
	fi
	[ -n "$v" ] || v="0"
	printf '%s' "$v"
}

upstream() { printf '%s' "$1" | sed 's/-r[0-9][0-9]*$//; s/-[0-9][0-9]*$//'; }

# 版本比较：$1 > $2 返回 0
ver_gt() {
	local a b i x y
	a=$(upstream "$1"); b=$(upstream "$2")
	[ "$a" = "$b" ] && return 1
	local IFS=.
	set -- $a
	local A1=$1 A2=$2 A3=$3
	set -- $b
	local B1=$1 B2=$2 B3=$3
	A1=${A1:-0}; A2=${A2:-0}; A3=${A3:-0}
	B1=${B1:-0}; B2=${B2:-0}; B3=${B3:-0}
	[ "$A1" -gt "$B1" ] 2>/dev/null && return 0
	[ "$A1" -lt "$B1" ] 2>/dev/null && return 1
	[ "$A2" -gt "$B2" ] 2>/dev/null && return 0
	[ "$A2" -lt "$B2" ] 2>/dev/null && return 1
	[ "$A3" -gt "$B3" ] 2>/dev/null && return 0
	return 1
}

url_ok() {
	case "$1" in
		https://*) return 0 ;;
		http://127.0.0.1*|http://localhost*) return 0 ;;   # 本机自测
		*) return 1 ;;
	esac
}

b64url_to_b64() {
	local s; s=$(printf '%s' "$1" | tr '_-' '/+')
	case $(( ${#s} % 4 )) in
		2) s="${s}==" ;;
		3) s="${s}=" ;;
	esac
	printf '%s' "$s"
}

# 用内嵌公钥验签：<msg> <sigfile>
verify_sig() {
	local msg="$1" sigf="$2" d="$WORK/verify.$$" rc
	command -v usign >/dev/null 2>&1 || { log "缺少 usign，拒绝无签名更新"; return 2; }
	mkdir -p "$d" 2>/dev/null || return 1

	# 公钥：Ed + keynum + 32 字节
	{ printf 'Ed%s' "$TK_UPD_KEYNUM"; printf '%s' "$(b64url_to_b64 "$TK_UPD_PUBKEY")" | b64d 2>/dev/null; } > "$d/pub.bin" || { rm -rf "$d"; return 1; }
	[ "$(wc -c < "$d/pub.bin")" = "42" ] || { log "公钥长度异常"; rm -rf "$d"; return 1; }
	printf 'untrusted comment: tkproxy update\n' > "$d/pub.txt"
	b64e < "$d/pub.bin" >> "$d/pub.txt"; printf '\n' >> "$d/pub.txt"

	# 签名文件本身是 signify 文本（untrusted comment + base64），但要确认 keynum 一致
	local body
	body=$(sed -n '2p' "$sigf" 2>/dev/null | tr -d '\r\n')
	[ -n "$body" ] || { log "签名文件为空"; rm -rf "$d"; return 1; }
	printf '%s' "$(b64url_to_b64 "$body")" | b64d > "$d/sig.bin" 2>/dev/null
	if [ "$(wc -c < "$d/sig.bin" 2>/dev/null)" != "74" ]; then
		log "签名长度异常（应 74 字节）"
		rm -rf "$d"; return 1
	fi
	# keynum 必须一致，否则是别的密钥签的
	if [ "$(dd if="$d/sig.bin" bs=1 skip=2 count=8 2>/dev/null)" != "$TK_UPD_KEYNUM" ]; then
		log "keynum 不匹配"
		rm -rf "$d"; return 1
	fi

	usign -V -m "$msg" -x "$sigf" -p "$d/pub.txt" >/dev/null 2>&1
	rc=$?
	rm -rf "$d"
	[ "$rc" = "0" ] || log "验签失败（清单可能被篡改）"
	return $rc
}

# 取清单字段
mf() { lua - "$WORK/manifest.json" "$1" <<'LUA' 2>/dev/null
local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then os.exit(0) end
local fh = io.open(arg[1], "r"); if not fh then os.exit(0) end
local o = jsonc.parse(fh:read("*a") or ""); fh:close()
if type(o) ~= "table" then os.exit(0) end
local v = o[arg[2]]
if v == nil then os.exit(0) end
io.write(tostring(v))
LUA
}

fail() { printf '{"ok":false,"msg":"%s"}\n' "$(json_esc "$1")"; exit 1; }

cmd="${1:-check}"

if [ "$cmd" = "version" ]; then
	printf '{"ok":true,"current":"%s"}\n' "$(installed_version)"
	exit 0
fi

UPD_URL=$(uci -q get tkproxy.main.update_url 2>/dev/null)
[ -n "$UPD_URL" ] || UPD_URL="$TK_UPD_DEFAULT"
url_ok "$UPD_URL" || fail "更新源必须使用 HTTPS"
command -v curl >/dev/null 2>&1 || fail "缺少 curl"

BASE=$(printf '%s' "$UPD_URL" | sed 's#/[^/]*$##')
CUR=$(installed_version)
LEGACY=0
case "$UPD_URL" in
	*version.json*) LEGACY=1 ;;
esac

if [ "$LEGACY" = "0" ]; then
	log "拉取签名清单：$UPD_URL"
	if curl -fsS -m 20 "$UPD_URL" -o "$WORK/manifest.json" 2>>"$LOG"; then
		curl -fsS -m 20 "${UPD_URL}.sig" -o "$WORK/manifest.json.sig" 2>>"$LOG" \
			|| fail "清单存在但缺少签名文件（${UPD_URL}.sig），已拒绝更新"
		verify_sig "$WORK/manifest.json" "$WORK/manifest.json.sig" || fail "清单签名校验失败，已拒绝更新"
	else
		# 回退：老插件的 version.json 格式
		log "没有 manifest.json，尝试老格式 version.json"
		if curl -fsS -m 20 "$BASE/version.json" -o "$WORK/version.json" 2>>"$LOG"; then
			LEGACY=1
			log "检测到老格式 version.json"
		else
			fail "下载清单失败（既没有 manifest.json 也没有 version.json，检查更新源地址）"
		fi
	fi
fi

if [ "$LEGACY" = "1" ]; then
	[ -s "$WORK/version.json" ] || curl -fsS -m 20 "$UPD_URL" -o "$WORK/version.json" 2>>"$LOG" \
		|| fail "下载 version.json 失败（网络或地址错误）"
	cp "$WORK/version.json" "$WORK/manifest.json" 2>/dev/null
	ALLOW_UNSIGNED=$(uci -q get tkproxy.main.update_allow_unsigned 2>/dev/null)
	M_SHA=$(mf sha256)
	if [ -z "$M_SHA" ] && [ "$ALLOW_UNSIGNED" != "1" ]; then
		fail "老格式 version.json 既没有签名也没有 sha256，已按安全策略拒绝。解决办法：①上传 manifest.json + manifest.json.sig；②或临时允许：uci set tkproxy.main.update_allow_unsigned=1 && uci commit tkproxy"
	fi
	log "老格式模式：来源 $UPD_URL（签名缺失，已按开关放行）"
fi

M_PKG=$(mf package); M_VER=$(mf version); M_REL=$(mf release)
M_ARCH=$(mf arch); M_FILE=$(mf file); M_URL=$(mf url)
M_SHA=$(mf sha256); M_SIZE=$(mf size); M_NOTES=$(mf notes)

# 老格式没有 package/file 字段，按规则补齐并做后续强校验
[ -n "$M_PKG" ] || M_PKG="$PKG"
[ -n "$M_FILE" ] || M_FILE=$(printf '%s' "$M_URL" | sed 's#.*/##')
[ -n "$M_ARCH" ] || M_ARCH="all"

[ "$M_PKG" = "$PKG" ] || fail "清单包名不是 $PKG（收到：$M_PKG）"
[ -n "$M_VER" ] || fail "清单缺少 version"
[ -n "$M_FILE" ] || fail "清单缺少 file"

LATEST="$M_VER${M_REL:+-$M_REL}"
HAS=false
if ver_gt "$M_VER" "$CUR"; then HAS=true; fi

if [ "$cmd" = "check" ]; then
	printf '{"ok":true,"current":"%s","latest":"%s","has_update":%s,"notes":"%s","size":"%s","arch":"%s"}\n' \
		"$(json_esc "$CUR")" "$(json_esc "$LATEST")" "$HAS" "$(json_esc "$M_NOTES")" "$(json_esc "$M_SIZE")" "$(json_esc "$M_ARCH")"
	log "检查完成：当前 $CUR，云端 $LATEST，has_update=$HAS"
	exit 0
fi

# ---------------- install ----------------
[ "$HAS" = "true" ] || fail "当前已是最新版本（$CUR）"

case "$M_URL" in
	http*) DL="$M_URL" ;;
	*) DL="$BASE/$M_FILE" ;;
esac
url_ok "$DL" || fail "下载地址必须使用 HTTPS（当前：$DL）"

log "下载：$DL"
curl -fsS -m 300 "$DL" -o "$WORK/$M_FILE" 2>>"$LOG" || fail "下载安装包失败"

if [ -n "$M_SHA" ]; then
	GOT=$(sha256sum "$WORK/$M_FILE" 2>/dev/null | cut -d' ' -f1)
	[ -n "$GOT" ] || fail "无法计算 SHA256（缺少 sha256sum）"
	[ "$GOT" = "$M_SHA" ] || fail "SHA256 不匹配（包体被改动，已拒绝安装）"
else
	log "注意：本次来源没有 sha256，仅靠包内 control 校验"
fi

# 校验包内元数据：包名 / 版本 / 架构（.ipk 与 .apk 两种封装都认）
case "$M_FILE" in
*.apk)
	DUMP=$(apk adbdump "$WORK/$M_FILE" 2>/dev/null)
	[ -n "$DUMP" ] || fail "安装包结构异常（apk adbdump 读不出元数据）"
	C_PKG=$(printf '%s\n' "$DUMP" | sed -n 's/^  name: //p' | head -n1)
	C_VER=$(printf '%s\n' "$DUMP" | sed -n 's/^  version: //p' | head -n1)
	C_ARCH=$(printf '%s\n' "$DUMP" | sed -n 's/^  arch: //p' | head -n1)
	;;
*)
	CTRL=$(tar -xzf "$WORK/$M_FILE" -O ./control.tar.gz 2>/dev/null | tar -xzO ./control 2>/dev/null)
	[ -n "$CTRL" ] || fail "安装包结构异常（读不到 control）"
	C_PKG=$(printf '%s' "$CTRL" | sed -n 's/^Package:[[:space:]]*//p' | head -n1 | tr -d '\r')
	C_VER=$(printf '%s' "$CTRL" | sed -n 's/^Version:[[:space:]]*//p' | head -n1 | tr -d '\r')
	C_ARCH=$(printf '%s' "$CTRL" | sed -n 's/^Architecture:[[:space:]]*//p' | head -n1 | tr -d '\r')
	;;
esac
[ "$C_PKG" = "$PKG" ] || fail "包内 Package 不符（$C_PKG）"
[ "$(norm_ver "$C_VER")" = "$(norm_ver "$LATEST")" ] || fail "包内版本与清单不一致（包 $C_VER / 清单 $LATEST）"

MACHINE_ARCH=$(apk --print-arch 2>/dev/null || uname -m 2>/dev/null)
case "$C_ARCH" in
all|noarch|"$MACHINE_ARCH") ;;
*) fail "架构不匹配（包 $C_ARCH / 本机 $MACHINE_ARCH）" ;;
esac

# 用哪一个包管理器
if command -v opkg >/dev/null 2>&1; then
	# 不能用 --force-reinstall：opkg 会走「先卸载再安装」，prerm 按 remove 清理运行时，
	# 结果客户点一次在线升级，30 个 AP / nft / xray 全被拆掉（实测 AP 30→0）。
	# 升级到更高版本时普通 install 会走 upgrade 路径，prerm 保留运行时。
	PM="opkg install $WORK/$M_FILE"
elif command -v apk >/dev/null 2>&1; then
	PM="apk add --allow-untrusted --force-overwrite $WORK/$M_FILE"
else
	fail "找不到 opkg / apk"
fi

log "开始安装：$PM"
OUT=$($PM 2>&1)
RC=$?
printf '%s\n' "$OUT" >> "$LOG"
if [ "$RC" != "0" ]; then
	printf '{"ok":false,"msg":"安装失败：%s","log":"%s"}\n' "$(json_esc "$(printf '%s' "$OUT" | tail -n 2 | tr '\n' ' ')")" "$(json_esc "$LOG")"
	exit 1
fi

rm -rf /tmp/luci-indexcache* 2>/dev/null
/etc/init.d/rpcd restart >/dev/null 2>&1

NEWVER=$(installed_version)
printf '{"ok":true,"msg":"已更新到 %s","from":"%s","to":"%s","log":"%s"}\n' \
	"$(json_esc "$NEWVER")" "$(json_esc "$CUR")" "$(json_esc "$NEWVER")" "$(json_esc "$LOG")"
log "更新完成：$CUR -> $NEWVER"
exit 0
