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

_fixed=0
# 常驻：不能写 while [ -f "$NFT_FILE" ]。
# 开机时规则文件还没生成（要等第一次部署），那样循环会立刻退出，
# 之后部署完也没人再拉起守护进程 —— 真机实测：部署成功但 watchdog 不在。
while true; do
	sleep 60
	[ -f "$NFT_FILE" ] || continue

	# 维护中（stop/卸载/升级）：不要和 stop 互斗
	[ -f "$LOG_DIR/.paused" ] && continue
	# 部署进行中：apply.sh 自己会重建，别插手
	pgrep -f 'apply\.sh' >/dev/null 2>&1 && continue

	# 1) DNS 桥
	if ip -4 addr show 2>/dev/null | grep -q "10\.11\.[0-9]*\.1/"; then
		if ! netstat -lnup 2>/dev/null | grep -q ":5301"; then
			logger -t tkproxy "守护：DNS 桥未监听，自动拉起"
			start_dnsbridge
		fi
	fi

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
		exit 0
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
