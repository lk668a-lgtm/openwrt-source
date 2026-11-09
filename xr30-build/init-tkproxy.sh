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
	# 已经由 procd 托管的 tkheal 看护时，这里不再自己起，避免跑两份互相抢
	if [ -x /etc/rc.d/S99tkheal ]; then
		return 0
	fi
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
		_cmd=$(tr '' ' ' < "/proc/$_p/cmdline" 2>/dev/null || true)
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
