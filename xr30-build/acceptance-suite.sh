#!/bin/sh
# tkproxy 出货验收（设备侧，只读检查 + 每条线路 DHCP 实测）
# 用法：sh acceptance-suite.sh [--no-dhcp]
# 输出：每行 "PASS/FAIL|项目|证据"，最后一行 "SUMMARY|PASS=n FAIL=m"
# 设计原则：只做可复现的硬检查；任何一项 FAIL 都不算合格，改完必须重跑同一套。

NO_DHCP=0
[ "$1" = "--no-dhcp" ] && NO_DHCP=1

P=0
F=0
say() { echo "$1|$2|$3"; case "$1" in PASS) P=$((P+1));; FAIL) F=$((F+1));; esac }

# 1) 无线：TK SSID 数量
ap=$(iwinfo 2>/dev/null | grep -c 'ESSID: "TK')
tk5=$(iwinfo 2>/dev/null | grep -c 'ESSID: "TK5G-')
tk2=$(iwinfo 2>/dev/null | grep -c 'ESSID: "TK2.4G-')
if [ "$tk2" = "15" ] && [ "$tk5" = "15" ]; then
	say PASS "无线 AP 数量" "2.4G=$tk2 5G=$tk5"
else
	say FAIL "无线 AP 数量" "2.4G=$tk2 5G=$tk5（应为 15/15）"
fi

# 2) 桥与网关
br=$(ip -o -4 addr show 2>/dev/null | grep -c '10\.11\.[0-9]*\.1/')
[ "$br" = "30" ] && say PASS "线路网关" "30 个 10.11.N.1/24" || say FAIL "线路网关" "只有 $br 个"

# 3) DNS 桥端口
dns=$(netstat -lnup 2>/dev/null | grep -c ':53[0-9][0-9] ')
[ "$dns" = "30" ] && say PASS "DNS 桥监听" "30 个端口" || say FAIL "DNS 桥监听" "只有 $dns 个"

# 4) 进程单实例
xr=$(ps | grep -c '[x]ray run -c /etc/tkproxy/xray.json')
wd=$(ps | grep -c '[w]atchdog.sh')
db=$(ps | grep -c '[d]nsbridge.lua')
[ "$xr" = "1" ] && say PASS "xray 单实例" "1 个" || say FAIL "xray 单实例" "$xr 个"
[ "$wd" = "1" ] && say PASS "守护单实例" "1 个" || say FAIL "守护单实例" "$wd 个"
[ "$db" = "1" ] && say PASS "DNS 桥单实例" "1 个" || say FAIL "DNS 桥单实例" "$db 个"

# 5) nft 规则表
nft list table inet tkproxy >/dev/null 2>&1 && say PASS "nft 规则表" "inet tkproxy 存在" || say FAIL "nft 规则表" "缺失"

# 6) 默认路由（整机出网的命脉）
ip route show default 2>/dev/null | grep -q '^default' && say PASS "默认路由" "$(ip route show default | head -1)" || say FAIL "默认路由" "主表无默认路由"

# 7) DHCP 地址池
pool=$(grep -h 'set:tkp' /var/etc/dnsmasq.conf.* 2>/dev/null | grep -oE 'set:tkp[0-9]+' | sort -u | grep -c .)
[ "$pool" = "30" ] && say PASS "DHCP 地址池" "30 条" || say FAIL "DHCP 地址池" "$pool 条"

# 8) 授权
lic=$(sh /usr/libexec/tkproxy/license.sh status 2>/dev/null)
echo "$lic" | grep -q '"activated":true' && say PASS "授权状态" "已激活" || say FAIL "授权状态" "$(echo $lic | head -c 80)"

# 9) 残留探针网卡（会把 hostapd 事件 socket 撑爆）
orph=$(ip -o link show 2>/dev/null | grep -oE '(tkv|ck|cx)[0-9]+' | sort -u | grep -c .)
[ "$orph" = "0" ] && say PASS "残留探针网卡" "无" || say FAIL "残留探针网卡" "$orph 个残留"

# 10) hostapd VLAN 事件溢出（BSS 数据面坏掉的前兆）
nerr=$(logread | grep -c 'vlan_event_receive: recvfrom failed' 2>/dev/null)
say PASS "hostapd 事件溢出计数" "$nerr（仅记录，持续增长即为隐患）"

# 11) 外网
code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' https://02.lkkami.top/api 2>/dev/null)
case "$code" in 000|"") say FAIL "外网连通" "code=$code" ;; *) say PASS "外网连通" "code=$code" ;; esac

# 12) 每条线路 DHCP 实测（veth 模拟客户端）
if [ "$NO_DHCP" = "0" ]; then
	i=1
	while [ "$i" -le 30 ]; do
		br="brtk$(printf %02d $i)"
		a="ac$(printf %02d $i)"; b="ac$(printf %02d $i)c"
		ip link del "$a" 2>/dev/null
		ip link add "$a" type veth peer name "$b" 2>/dev/null
		ip link set "$a" master "$br" 2>/dev/null
		ip link set "$a" up 2>/dev/null
		ip link set "$b" up 2>/dev/null
		sleep 2
		got=$(udhcpc -i "$b" -t 3 -T 2 -f -q -n 2>&1 | grep -c 'lease of')
		ip link del "$a" 2>/dev/null
		[ "$got" = "1" ] && say PASS "线路 $i DHCP" "拿到地址" || say FAIL "线路 $i DHCP" "未拿到地址"
		i=$((i + 1))
	done
fi

echo "SUMMARY|PASS=$P|FAIL=$F"
[ "$F" = "0" ] && exit 0 || exit 1
