#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 守护进程（独立进程，setsid 启动）
#
# 为什么独立成脚本：原来这段循环写成 init 脚本里的 `( ... ) &`，和 procd 的服务在
# 同一个进程组里，服务一旦 restart/stop 就被连带杀掉。实测重启后守护进程消失，
# DNS 桥再也没人拉起来 → 客户端能连 WiFi、所有域名解析不了（网页打不开）。
# 现在由 init 用 setsid 起这个脚本，pgid 独立，procd 动不了它。
#
# 每 60 秒检查一次，坏了就修：
#   1. DNS 桥没在监听 5301 → 重新拉起
#   2. nft 表丢了 → 重新加载
#   3. xray 进程没了 → 重启服务
#   4. 每 24 小时做一次静默授权核验（失败只写日志，不影响本地授权）

NFT_FILE=/etc/tkproxy/tkproxy.nft
CONF_DIR=/etc/tkproxy
LOG_DIR=/tmp/tkproxy

# 单实例保护：init/apply/手动都可能各起一个，多个守护会同时 ifup 打架
_pidf=/var/run/tkproxy-watchdog.pid
# 单实例：pidfile 指向的另一个存活实例存在就退出。
# 只在启动时检查不够——服务 restart 时可能出现：旧实例还活着但 pidfile 已被新实例覆盖，
# 于是两个都在跑（实测过 2 个），会互相重复杀/拉 DNS 桥。每轮也复查一次。
dedupe_or_exit() {
	_oldpid=$(cat "$_pidf" 2>/dev/null)
	if [ -n "$_oldpid" ] && [ "$_oldpid" != "$$" ] && [ -d "/proc/$_oldpid" ]; then
		case "$(tr '\0' ' ' < "/proc/$_oldpid/cmdline" 2>/dev/null || true)" in
			*watchdog.sh*)
				logger -t tkproxy "守护：发现重复实例 $_oldpid，本实例($$)退出"
				exit 0
				;;
		esac
	fi
	echo $$ > "$_pidf"
}
dedupe_or_exit

# 开机校时（一次性，后台）：无 RTC 的机器首次开机时钟停在固件编译日期，
# 会让所有 HTTPS（含卡密服务器）证书校验失败，用户看到的是「无法连接卡密服务器」。
# WAN 可能比本脚本晚就绪，重试 10 次、每次 30 秒，最多等 5 分钟。
(
	i=0
	while [ "$i" -lt 10 ]; do
		sh /usr/libexec/tkproxy/license.sh fixclock >/dev/null 2>&1 && break
		i=$((i + 1))
		sleep 30
	done
) >/dev/null 2>&1 &

start_dnsbridge() {
	[ -f /usr/libexec/tkproxy/dnsbridge.lua ] || return 0
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	if [ -n "$_pid" ] && [ -d "/proc/$_pid" ]; then
		case "$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null || true)" in
			*dnsbridge.lua*) return 0 ;;
		esac
	fi
	_w=0
	while [ "$_w" -lt 40 ]; do
		if ip -4 addr show 2>/dev/null | grep -q "10\.11\.[0-9]*\.1/"; then break; fi
		_w=$((_w + 1))
		sleep 1
	done
	mkdir -p "$LOG_DIR" 2>/dev/null || true
	if command -v setsid >/dev/null 2>&1; then
		setsid lua /usr/libexec/tkproxy/dnsbridge.lua >>"$LOG_DIR/dnsbridge.log" 2>&1 &
	else
		lua /usr/libexec/tkproxy/dnsbridge.lua >>"$LOG_DIR/dnsbridge.log" 2>&1 &
	fi
	echo $! > /var/run/tkproxy-dnsbridge.pid
	sleep 1
	_pid=$(cat /var/run/tkproxy-dnsbridge.pid 2>/dev/null || true)
	if [ -n "$_pid" ] && [ -d "/proc/$_pid" ]; then
		netstat -lnup 2>/dev/null | grep -q ":5301" || \
			logger -t tkproxy "守护：DNS 桥进程在但 5301 未监听"
		return 0
	fi
	logger -t tkproxy "守护：DNS 桥启动失败（见 $LOG_DIR/dnsbridge.log）"
}

# 线路接口自愈：开机时多个桥并发拉起，netifd 偶发 DEVICE_CLAIM_FAILED（up=false，
# 重试几次就能成功）。没有 10.11.N.1 网关 → 对应 WiFi 连得上但上不了网。
heal_ifaces() {
	command -v ifstatus >/dev/null 2>&1 || return 0
	for _i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
		ifstatus "tkp$_i" >/dev/null 2>&1 || continue
		_u=$(ifstatus "tkp$_i" 2>/dev/null | jsonfilter -e '@.up' 2>/dev/null)
		[ "$_u" = "true" ] && continue
		logger -t tkproxy "守护：tkp$_i 未启动（up=$_u），执行 ifup"
		ifup "tkp$_i" >/dev/null 2>&1
	done
}

# DNS 桥自愈：按「现有桥网关数」核对监听数，缺任何一个都要重拉
# （只查 5301 会漏：实测 4 条线路时第 4 条的 5304 没起来，那条 WiFi 能连不能上网）
heal_dns() {
	# 注意：`ip -4 addr show 10.11.N.1/24` 这种写法 busybox ip 不认（恒失败 → 之前
	# 这函数一直算出 0 条，等于没修）。统一从完整地址表里数。
	_exp=$(ip -4 addr show 2>/dev/null | grep -oE '10\.11\.[0-9]+\.1/' | sort -u | grep -c .)
	[ "${_exp:-0}" -gt 0 ] || return 0
	_act=$(netstat -lnup 2>/dev/null | grep -c ':53[0-9][0-9] ')
	if [ "${_act:-0}" -lt "$_exp" ]; then
		logger -t tkproxy "守护：DNS 监听 $_act/$_exp 不足，重拉 DNS 桥"
		for _p in $(ps w 2>/dev/null | awk '/[d]nsbridge.lua/{print $1}'); do kill -9 "$_p" 2>/dev/null; done
		sleep 1
		start_dnsbridge
	fi
}

# DHCP 自愈：dnsmasq 的 dhcp_check 一旦误判「本接口已有 DHCP 服务器」，
# 该线路就永久发不出地址（手机连上没 IP）。这里核对「地址池条数 vs 桥网关数」，
# 不足就清探测缓存 + 给每条线路的 dhcp 段加 force=1 + 重载 dnsmasq。
heal_dhcp() {
	_exp=$(ip -4 addr show 2>/dev/null | grep -oE '10\.11\.[0-9]+\.1/' | sort -u | grep -c .)
	[ "${_exp:-0}" -gt 0 ] || return 0
	_n=$(cat /var/etc/dnsmasq.conf.* 2>/dev/null | grep -oE 'set:tkp[0-9]+' | sort -u | grep -c .)
	if [ "${_n:-0}" -lt "$_exp" ]; then
		logger -t tkproxy "守护：DHCP 地址池 $_n/$_exp 不足，清探测缓存并重载"
		rm -f /tmp/*.dhcp /tmp/dhcp.*.dhcp 2>/dev/null
		for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
			_if=$(printf 'tkp%02d' "$_i")
			uci -q get "dhcp.$_if" >/dev/null 2>&1 || continue
			uci -q set "dhcp.$_if.force=1"
		done
		uci -q commit dhcp
		/etc/init.d/dnsmasq reload >/dev/null 2>&1
	fi
}

# 默认路由自愈：WAN 拿到地址、但内核主表里没有默认路由时，整机都出不了网，
# 客户看到的是「所有 WiFi 都连上、但网页打不开」。真机实测出现过：netifd 的
# ubus 状态里明明有 0.0.0.0/0 → 192.168.100.1，内核 `ip route` 却是空的。
# 这里每轮核对，缺了就按 ubus 里的网关补上，补不上就重拨 WAN。
heal_route() {
	_wan=$(uci -q get network.wan.device)
	[ -n "$_wan" ] || _wan=eth1
	ip -4 addr show dev "$_wan" 2>/dev/null | grep -q 'inet ' || return 0
	ip route show default 2>/dev/null | grep -q '^default' && return 0
	_gw=$(ubus call network.interface.wan status 2>/dev/null | \
		jsonfilter -e '@.route[@.target="0.0.0.0"].nexthop' 2>/dev/null)
	if [ -n "$_gw" ]; then
		ip route add default via "$_gw" dev "$_wan" 2>/dev/null
	fi
	if ! ip route show default 2>/dev/null | grep -q '^default'; then
		logger -t tkproxy "守护：WAN 无默认路由且补不回来，重拨 $_wan"
		ifup wan >/dev/null 2>&1
		return 0
	fi
	# 手动加的路由 netifd 不认，界面/接口一 reload 就会被清掉（实测：频繁探测时
	# 每 1~2 分钟丢一次）。同一问题 5 分钟内出现第 2 次，就让 netifd 重新接管
	# （重拨 wan），之后它自己会维护这条路由，不用我们反复补。
	_cnt_file=/tmp/tkproxy/.route_heal_cnt
	_now=$(date +%s)
	_cnt=0
	_last=0
	[ -f "$_cnt_file" ] && { _cnt=$(cut -d' ' -f1 "$_cnt_file" 2>/dev/null); _last=$(cut -d' ' -f2 "$_cnt_file" 2>/dev/null); }
	case "$_cnt" in ''|*[!0-9]*) _cnt=0 ;; esac
	case "$_last" in ''|*[!0-9]*) _last=0 ;; esac
	[ $((_now - _last)) -gt 300 ] && _cnt=0
	_cnt=$((_cnt + 1))
	echo "$_cnt $_now" > "$_cnt_file"
	if [ "$_cnt" -ge 2 ]; then
		logger -t tkproxy "守护：默认路由反复丢失（$_cnt 次/5 分钟），重拨 wan 交回 netifd 维护"
		rm -f "$_cnt_file"
		ifdown wan >/dev/null 2>&1
		sleep 2
		ifup wan >/dev/null 2>&1
	fi
}

# 探针网卡清理：status.sh / line-audit 会用 tkv* 虚拟网卡临时挂到线路桥上测出口，
# 本该测完就删。残留的坏处是实打实的：每张网卡进/出网桥都会给 hostapd 发 netlink 事件，
# 堆多了会把它的事件 socket 撑爆（日志 `VLAN: vlan_event_receive: recv failed: No buffer
# space available`），一旦爆掉，某条 BSS 就可能只建控制面、不建数据面 —— 表现为手机
# 能关联、能过四次握手，但 rx/tx 全是 0 字节，拿不到 DHCP，2 秒后自己断开。
# 这里在没有任何探测进程在跑时才清理，避免把正在用的探针网卡删掉。
heal_probe_leftover() {
	pgrep -f 'line-audit|portprobe|status\.sh|nodetest' >/dev/null 2>&1 && return 0
	_left=$(ip -o link show 2>/dev/null | grep -o 'tkv[0-9]\+' | sort -u | tr '\n' ' ')
	[ -n "$_left" ] || return 0
	for _l in $_left; do
		ip link del "$_l" 2>/dev/null
	done
	logger -t tkproxy "守护：清理残留探针网卡：$_left"
}

# 死节点自动替换：每 30 分钟跑一次，把出口取不到 IP 的线路换到体检 OK 的空闲节点。
# 节点（尤其免费/机场节点）会不定时失效，客户看到的就是「某条 WiFi 连上打不开网页」。
# 放后台跑，避免阻塞其它自愈；用时间戳限流，失败也不会刷屏。
heal_nodes() {
	_stamp=/tmp/tkproxy/.node_heal
	if [ -f "$_stamp" ]; then
		_last=$(stat -c %Y "$_stamp" 2>/dev/null || echo 0)
		[ $(( $(date +%s) - ${_last:-0} )) -lt 1800 ] && return 0
	fi
	touch "$_stamp"
	logger -t tkproxy "守护：开始死节点自动替换"
	( lua /usr/libexec/tkproxy/node-heal.lua >>/tmp/tkproxy/node-heal.log 2>&1 ) &
}

_fixed=0
# 开机头 1 分钟：每 10 秒拉一次接口和 DNS，抢在客户拿手机之前就绪
# （netifd 并发建桥会抢设备失败，隔几秒重试就成；DNS 桥也可能先起来但绑不到晚到的桥）
_boot=0
while [ "$_boot" -lt 6 ]; do
	_boot=$((_boot + 1))
	dedupe_or_exit
	heal_route
	heal_ifaces
	heal_dns
	heal_dhcp
	sleep 10
done

# 常驻：不能写 while [ -f "$NFT_FILE" ]。
# 开机时规则文件还没生成（要等第一次部署），那样循环会立刻退出，
# 之后部署完也没人再拉起守护进程 —— 真机实测：部署成功但 watchdog 不在。
while true; do
	dedupe_or_exit
	sleep 60
	# 默认路由与部署无关：没部署过也要能上网（激活、升级都要它）
	heal_route
	heal_probe_leftover
	heal_nodes
	[ -f "$NFT_FILE" ] || continue

	# 维护中（stop/卸载/升级）：不要和 stop 互斗
	# 但 .paused 可能因部署被中断而残留（实测：残留后守护永久躺平，DNS 桥死了没人拉，
	# 表现就是「WiFi 连得上、上不了网」）。超过 10 分钟一律当作过期标记清掉。
	if [ -f "$LOG_DIR/.paused" ]; then
		_pt=$(cat "$LOG_DIR/.paused" 2>/dev/null | tr -dc '0-9')
		_now=$(date +%s)
		case "$_pt" in ''|*[!0-9]*) _pt=0 ;; esac
		if [ "$_pt" -gt 0 ] && [ $((_now - _pt)) -le 600 ]; then
			continue
		fi
		logger -t tkproxy "守护：清除过期/无效的 .paused 标记（内容=${_pt}）"
		rm -f "$LOG_DIR/.paused"
	fi
	# 部署进行中：apply.sh 自己会重建，别插手
	pgrep -f 'apply\.sh' >/dev/null 2>&1 && continue

	# 1) DNS 桥（见 heal_dns）
	heal_dns

	# 1.2) DHCP 地址池（见 heal_dhcp）
	heal_dhcp

	# 1.5) 线路接口：开机偶发 tkp01/02/03/05 等几个桥 up=false（netifd 报
	# DEVICE_CLAIM_FAILED，重试可成功），没有 10.11.N.1 网关 → 对应 WiFi 上不了网
	heal_ifaces

	# 2) nft 表
	if ! nft list table inet tkproxy >/dev/null 2>&1; then
		logger -t tkproxy "守护：inet tkproxy 表丢失，重新加载"
		if nft -f "$NFT_FILE"; then
			_fixed=$((_fixed + 1))
			logger -t tkproxy "守护：规则已恢复（累计 $_fixed 次）"
		else
			logger -t tkproxy "守护：规则重新加载失败"
		fi
	fi

	# 3) xray
	# 先清重复实例：并发 start 会留下两个 xray 抢同一批端口（实测开机后出现 5302/5336 两个）
	_dup=$(ps w 2>/dev/null | grep -c '[x]ray run -c /etc/tkproxy/xray.json')
	if [ "${_dup:-0}" -gt 1 ]; then
		_keep=$(cat /var/run/xray.pid 2>/dev/null)
		for _p in $(ps w 2>/dev/null | awk '/[x]ray run -c \/etc\/tkproxy\/xray.json/{print $1}'); do
			[ "$_p" = "$_keep" ] && continue
			kill -9 "$_p" 2>/dev/null && logger -t tkproxy "守护：清理重复 xray 进程 $_p（保留 $_keep）"
		done
	fi
	if [ ! -s /var/run/xray.pid ] || ! kill -0 "$(cat /var/run/xray.pid 2>/dev/null)" 2>/dev/null; then
		logger -t tkproxy "守护：xray 已退出，重启服务"
		( sleep 1; /etc/init.d/tkproxy restart >/dev/null 2>&1 ) &
		# 重启服务会经 stop_service 写一个 .paused（当前时间），若不清理，
		# 守护接下来 10 分钟都会跳过自愈。这里等重启跑完后主动清掉。
		( sleep 90; rm -f "$LOG_DIR/.paused" ) &
		# 不要 exit：退出后若 init 没有重新拉起（25.12 的 start_service 时机不可靠），
		# 守护就永远消失，后面 DNS 桥再死也没人管。继续循环，下一轮自会看到服务已恢复。
		continue
	fi

	# 4) 每日静默核验
	_now=$(date +%s)
	_last=$(cat "$LOG_DIR/license-daily.last" 2>/dev/null)
	case "$_last" in ''|*[!0-9]*) _last=0 ;; esac
	if [ $((_now - _last)) -gt 86400 ]; then
		echo "$_now" > "$LOG_DIR/license-daily.last"
		( sh /usr/libexec/tkproxy/license.sh dailycheck >>"$LOG_DIR/license-daily.log" 2>&1 ) &
	fi
done
