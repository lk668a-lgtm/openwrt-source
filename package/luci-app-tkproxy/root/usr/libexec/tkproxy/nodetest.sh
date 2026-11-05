#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 节点真实可用性体检
#
# 用法：nodetest.sh [--prune] [--bound-only]
#   不带参数      ：逐个节点实拨取出口 IP，输出可用/失败列表，结果写 /tmp/tkproxy/nodetest.txt
#   --prune       ：剔除失败节点（从 uci 节点池中删除，删除前备份到 /root/tkproxy-backup/nodes-<ts>.txt）
#   --bound-only  ：只体检「当前线路正在使用」的节点（部署后自动调用，几十秒完成），
#                   结果并入 nodetest.txt，不清掉其它节点的已有结果
#
# 实现：
#   1. 通过 Lua UCI cursor:get_list 读取节点池（每条 名称|链接）
#   2. 为每个节点生成临时 Xray socks5 outbound 配置，端口 23001+序号
#   3. 启动 xray run -c <临时配置>，用 curl -x socks5h://127.0.0.1:<端口> http://ip-api.com/line/?fields=query,countryCode,isp 探测
#   4. 输出每行：名称|出口IP|国家|OK/FAIL；汇总可用 X / 总数 N
#   5. --prune：把 FAIL 的从 uci 池中删除（删除前备份）
#   6. 结束必须清理所有临时配置与 xray 进程

set -e

PROG=tkproxy-nodetest
PRUNE=0
BOUND_ONLY=0
TMP_DIR=/tmp/tkproxy
RESULT_FILE=$TMP_DIR/nodetest.txt
BACKUP_DIR=/root/tkproxy-backup
BASE_PORT=23000

case "${1:-}" in
	--prune) PRUNE=1 ;;
	--bound-only) BOUND_ONLY=1 ;;
	-h|--help|help)
		printf 'nodetest.sh [--prune]\n'
		exit 0
		;;
	"") ;;
	*)
		printf '%s: 未知参数：%s\n' "$PROG" "$1" >&2
		exit 2
		;;
esac

say() { logger -t "$PROG" "$*"; printf '%s\n' "$*"; }

# 前置检查
if ! command -v xray >/dev/null 2>&1; then
	say "错误：未安装 xray"
	exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
	say "错误：未安装 curl"
	exit 1
fi

mkdir -p "$TMP_DIR"
mkdir -p "$BACKUP_DIR"

# 单实例锁：部署后的自动体检与手动体检会同时触发，并发跑会互相抢端口/打分失真
LOCK_DIR=$TMP_DIR/nodetest.lock
acquire_lock() {
	mkdir "$LOCK_DIR" 2>/dev/null && return 0
	# 锁超过 30 分钟视为残留（上次被 kill 没清掉）
	if [ -d "$LOCK_DIR" ] && [ -n "$(find "$LOCK_DIR" -mmin +30 2>/dev/null)" ]; then
		rmdir "$LOCK_DIR" 2>/dev/null || true
		mkdir "$LOCK_DIR" 2>/dev/null && return 0
	fi
	return 1
}
if ! acquire_lock; then
	say "另一次体检正在进行，跳过本次"
	exit 0
fi

# 清掉上次残留的临时 xray 测试进程（异常退出会留下，长期占 CPU）
if command -v pgrep >/dev/null 2>&1; then
	for _pid in $(pgrep -f "xray run -c $TMP_DIR/nodetest-" 2>/dev/null || true); do
		kill "$_pid" 2>/dev/null || true
	done
fi

# 清理函数：杀掉所有临时 xray 进程、删除临时配置
cleanup() {
	say "清理临时进程与配置..."
	rmdir "$LOCK_DIR" 2>/dev/null || true
	# 杀掉所有端口 23001..23000+N 的 xray 进程（通过配置文件特征）
	if command -v pgrep >/dev/null 2>&1; then
		for _pid in $(pgrep -f "xray run -c $TMP_DIR/nodetest-" 2>/dev/null || true); do
			kill "$_pid" 2>/dev/null || true
		done
	elif command -v pidof >/dev/null 2>&1; then
		for _pid in $(pidof xray 2>/dev/null || true); do
			if [ -f "/proc/$_pid/cmdline" ]; then
				_cmdline=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null || true)
				if echo "$_cmdline" | grep -q "nodetest-"; then
					kill "$_pid" 2>/dev/null || true
				fi
			fi
		done
	fi
	# 删除临时配置
	rm -f "$TMP_DIR"/nodetest-*.json 2>/dev/null || true
}

trap cleanup EXIT INT TERM HUP

# 读取节点池（uci -q show tkproxy.main.node 逐行读取 list）
say "== 节点体检开始 =="
POOL_FILE=$TMP_DIR/nodetest-pool.txt
> "$POOL_FILE"

# 使用 Lua 正确读取 UCI list（避免 uci show 单行合并问题）
lua -e 'for _,v in ipairs((require("luci.model.uci").cursor()):get_list("tkproxy","main","node") or {}) do print(v) end' > "$POOL_FILE"
# --bound-only：只保留"当前线路在用"的节点
if [ "$BOUND_ONLY" = "1" ]; then
	lua -e '
local c = require("luci.model.uci").cursor()
local used = {}
for _, l in ipairs(c:get_list("tkproxy", "main", "line") or {}) do
	local n = l:match("^[^|]*|[^|]*|@?([^|]*)")
	if n and n ~= "" then used[n] = true end
end
for _, v in ipairs(c:get_list("tkproxy", "main", "node") or {}) do
	local nm = v:match("^([^|]*)")
	if nm and used[nm] then print(v) end
end' > "$POOL_FILE.bound" 2>/dev/null && mv "$POOL_FILE.bound" "$POOL_FILE"
	RESULT_FILE=$TMP_DIR/nodetest-bound.txt
fi

TOTAL=$(wc -l < "$POOL_FILE" 2>/dev/null | tr -d ' ' || echo 0)
if [ "$TOTAL" -eq 0 ]; then
	say "节点池为空"
	printf 'available=0\ntotal=0\n' > "$RESULT_FILE"
	rm -f "$POOL_FILE"
	exit 0
fi
say "节点总数: $TOTAL"

# 体检主循环
FAILED_NAMES_FILE=$TMP_DIR/nodetest-failed.txt
> "$RESULT_FILE"
> "$FAILED_NAMES_FILE"

IDX=0
# 用 while read 但避免管道子 shell：读取临时池文件
while IFS='|' read -r NAME LINK; do
	[ -n "$NAME" ] || continue
	[ -n "$LINK" ] || continue
	IDX=$((IDX + 1))
	PORT=$((BASE_PORT + IDX))
	DPORT=$((BASE_PORT + 500 + IDX))
	CFG="$TMP_DIR/nodetest-$IDX.json"

	say "[$IDX/$TOTAL] 测试节点: $NAME"

	# 生成临时 Xray 配置（通过 gen.lua 转换为规范 outbound）
	# 支持所有格式（vmess/vless/trojan/ss/ssr/json:），统一经过 Xray outbound 转换器
	# 使用 stdin 传入链接避免注入
	# socks5 带前置（?front=名字）：先从节点池取前置链接，落地出站在前、前置出站在后
	OUTBOUND_JSON=$(printf '%s' "$LINK" | FRONT_NAME="$NAME" lua -e "
		local gen = require('luci.model.tkproxy.gen')
		local link = io.read('*a')
		-- 前置节点名来自链接里的 ?front=，先解析出来再查池子
		local parsed0 = gen.parse_node(link)
		if not parsed0 then print('null'); os.exit(0) end
		local front_link = nil
		if parsed0.type == 'socks' and parsed0.front and parsed0.front ~= '' then
			-- uci 节点池：'名称|链接' 逐行
			local c = require('luci.model.uci').cursor()
			for _, v in ipairs(c:get_list('tkproxy', 'main', 'node') or {}) do
				local nm, lk = v:match('^([^|]*)|(.+)$')
				if nm == parsed0.front then front_link = lk end
			end
			if not front_link then
				io.stderr:write('前置节点 ' .. parsed0.front .. ' 不存在\n')
				print('null'); os.exit(0)
			end
		end
		-- 带前置时返回 (落地, 前置)；否则 (落地, nil)
		local ob, fob = gen.outbound_with_front(link, front_link)
		if not ob then print('null'); os.exit(0) end
		local json = require('luci.jsonc')
		-- 落地出站必须先 build 成规范 Xray outbound（outbound_with_front 返回的是解析结果）
		local landing, lerr = gen.build_xray_outbound(ob, 'test')
		if not landing then
			io.stderr:write('落地出站构建失败：' .. tostring(lerr) .. '\n')
			print('null'); os.exit(0)
		end
		-- 前置出站 tag：front-<名字slug>，与 gen.build() 的约定一致
		local ftag = 'front-test'
		if fob then
			local fslug = tostring(parsed0.front):gsub('[^%w]', ''):lower()
			if fslug == '' then
				-- 与 gen.slugify 的语义一致：纯汉字/无字母数字的前置名无法生成 tag，
				-- 部署阶段就会报错；体检这里提前给出同样的提示，避免静默生成 'front-'
				io.stderr:write('前置节点名 ' .. parsed0.front .. ' 里没有可用的字母数字\n')
				print('null'); os.exit(0)
			end
			ftag = 'front-' .. fslug
			local fout, ferr = gen.build_xray_outbound(fob, ftag)
			if not fout then
				io.stderr:write('前置出站构建失败：' .. tostring(ferr) .. '\n')
				print('null'); os.exit(0)
			end
			fout.tag = ftag
			-- 落地出站挂 dialerProxy（合并进已有 sockopt）
			if not landing.streamSettings then landing.streamSettings = {} end
			if not landing.streamSettings.sockopt then landing.streamSettings.sockopt = {} end
			landing.streamSettings.sockopt.dialerProxy = ftag
			io.stderr:write('FRONTJSON:' .. json.stringify(fout) .. '\n')
		end
		io.stderr:write('LANDJSON:' .. json.stringify(landing) .. '\n')
		print('ok')
	" 2>"$TMP_DIR/nodetest-$IDX.out" || true)
	# 从 stderr 里取两段 JSON（stdout 只用来传状态，避免 Lua print 与 shell 混流）
	LAND_JSON=$(sed -n 's/^LANDJSON://p' "$TMP_DIR/nodetest-$IDX.out" 2>/dev/null | tail -1)
	FRONT_JSON=$(sed -n 's/^FRONTJSON://p' "$TMP_DIR/nodetest-$IDX.out" 2>/dev/null | tail -1)
	rm -f "$TMP_DIR/nodetest-$IDX.out"
	OUTBOUND_JSON="$LAND_JSON"

	if [ "$OUTBOUND_JSON" = "null" ] || [ -z "$OUTBOUND_JSON" ]; then
		say "  解析失败：无法解析节点链接"
		printf '%s|%s|%s|%s\n' "$NAME" "" "" "FAIL" >> "$RESULT_FILE"
		printf '%s\n' "$NAME" >> "$FAILED_NAMES_FILE"
		continue
	fi

	# 生成 Xray 配置（socks5 inbound + DNS 探测 inbound + parsed outbound）
	# 带前置时：落地出站在前、前置出站在后（顺序反了流量会从前置直接出去）
	if [ -n "$FRONT_JSON" ]; then
		cat > "$CFG" <<CFGEOF
{
  "log": { "loglevel": "error" },
  "inbounds": [{
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "port": $PORT,
    "protocol": "socks",
    "settings": { "udp": false }
  }, {
    "tag": "dns-in",
    "listen": "127.0.0.1",
    "port": $DPORT,
    "protocol": "dokodemo-door",
    "settings": { "address": "1.1.1.1", "port": 53, "network": "tcp,udp", "timeout": 5 }
  }],
  "outbounds": [$OUTBOUND_JSON, $FRONT_JSON]
}
CFGEOF
	else
		cat > "$CFG" <<CFGEOF
{
  "log": { "loglevel": "error" },
  "inbounds": [{
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "port": $PORT,
    "protocol": "socks",
    "settings": { "udp": false }
  }, {
    "tag": "dns-in",
    "listen": "127.0.0.1",
    "port": $DPORT,
    "protocol": "dokodemo-door",
    "settings": { "address": "1.1.1.1", "port": 53, "network": "tcp,udp", "timeout": 5 }
  }],
  "outbounds": [$OUTBOUND_JSON]
}
CFGEOF
	fi

	# 启动 xray（后台，5 秒后自动杀掉）
	xray run -c "$CFG" >/dev/null 2>&1 &
	XRAY_PID=$!
	sleep 2  # 等待 xray 启动

	# curl 探测（8 秒超时，获取 HTTP 响应）
	PROBE=$(curl -m 8 -w '\n%{http_code}' -x "socks5h://127.0.0.1:$PORT" \
		"http://ip-api.com/line/?fields=query,countryCode,isp" 2>/dev/null || true)

	# DNS 探测：经节点向 1.1.1.1:53 发一个真实的 A 查询，看有没有应答。
	# 客户端的 DNS 就是走这条路径（线路 DNS 入站 → 节点 → 上游解析器），
	# 节点封 UDP 53 时表现为"WiFi 能连、网页打不开"，HTTP 探测测不出来。
	# 用 lua+nixio 发真实 DNS 查询（TCP）：busybox nc 做不了 DNS 交换，实测恒为 0 字节
	DNS_PROBE=/usr/libexec/tkproxy/dnsprobe.lua
	if [ -f "$DNS_PROBE" ] && command -v lua >/dev/null 2>&1; then
		if lua "$DNS_PROBE" 127.0.0.1 "$DPORT" 4 2>/dev/null; then DNS_OK=1; else DNS_OK=0; fi
	else
		DNS_OK=1  # 探针不可用时不做判定，避免误报
	fi

	# 杀掉 xray
	kill "$XRAY_PID" 2>/dev/null || true
	wait "$XRAY_PID" 2>/dev/null || true
	rm -f "$CFG"

	# 解析结果（4 行：IP / 国家 / ISP / HTTP_CODE）
	HTTP_CODE=$(printf '%s\n' "$PROBE" | tail -n 1)
	BODY=$(printf '%s\n' "$PROBE" | sed '$d')

	if [ "$HTTP_CODE" = "200" ] && [ -n "$BODY" ]; then
		EXIT_IP=$(printf '%s\n' "$BODY" | sed -n '1p')
		COUNTRY=$(printf '%s\n' "$BODY" | sed -n '2p')
		# 验证 IP 格式（简单校验：非空且不含 error/limit 等关键词）
		if [ -n "$EXIT_IP" ] && [ -n "$COUNTRY" ] && \
		   ! printf '%s' "$EXIT_IP" | grep -qiE 'error|limit|invalid|null'; then
			if [ "$DNS_OK" = "1" ]; then
				say "  成功: $EXIT_IP ($COUNTRY)"
				printf '%s|%s|%s|%s\n' "$NAME" "$EXIT_IP" "$COUNTRY" "OK" >> "$RESULT_FILE"
			else
				say "  部分可用: $EXIT_IP ($COUNTRY)，但 DNS 不通（客户会连上却打不开网页）"
				printf '%s|%s|%s|%s\n' "$NAME" "$EXIT_IP" "$COUNTRY" "DNSFAIL" >> "$RESULT_FILE"
				printf '%s\n' "$NAME" >> "$FAILED_NAMES_FILE"
			fi
		else
			say "  失败: 响应无效 (IP=$EXIT_IP)"
			printf '%s|%s|%s|%s\n' "$NAME" "" "" "FAIL" >> "$RESULT_FILE"
			printf '%s\n' "$NAME" >> "$FAILED_NAMES_FILE"
		fi
	else
		say "  失败: HTTP $HTTP_CODE 或无响应"
		printf '%s|%s|%s|%s\n' "$NAME" "" "" "FAIL" >> "$RESULT_FILE"
		printf '%s\n' "$NAME" >> "$FAILED_NAMES_FILE"
	fi
done < "$POOL_FILE"

# --bound-only：把本次结果并回 nodetest.txt（同名覆盖，其它节点结果保留）
if [ "$BOUND_ONLY" = "1" ]; then
	if [ -s "$RESULT_FILE" ]; then
		_merge=$TMP_DIR/nodetest.merge.$$
		awk -F'|' 'NR==FNR { seen[$1]=1; next } !($1 in seen)' "$RESULT_FILE" "$TMP_DIR/nodetest.txt" > "$_merge" 2>/dev/null || true
		cat "$RESULT_FILE" >> "$_merge"
		mv "$_merge" "$TMP_DIR/nodetest.txt"
	fi
	RESULT_FILE=$TMP_DIR/nodetest.txt
fi

# 统计
AVAILABLE=$(grep -c '|OK$' "$RESULT_FILE" 2>/dev/null || printf '0')

# 汇总
say "== 体检完成 =="
say "可用: $AVAILABLE / $TOTAL"

# --prune：剔除失败节点
if [ "$PRUNE" = "1" ] && [ -s "$FAILED_NAMES_FILE" ]; then
	say "== 剔除失败节点 =="
	TS=$(date +%s)
	BACKUP_FILE="$BACKUP_DIR/nodes-$TS.txt"

	# 备份当前节点池（使用 Lua 正确读取 UCI list，避免单行合并问题）
	lua -e 'for _,v in ipairs((require("luci.model.uci").cursor()):get_list("tkproxy","main","node") or {}) do print(v) end' > "$BACKUP_FILE" || { say "错误：备份节点池失败"; exit 1; }
	say "已备份节点池到: $BACKUP_FILE ($(wc -l < "$BACKUP_FILE") 条)"

	# 删除整个 node list（一次性清空，再重建存活节点）
	uci -q delete tkproxy.main.node 2>/dev/null || true

	# 重新添加非失败节点（按行读取备份，排除失败名称）
	KEPT=0
	while IFS='|' read -r _name _link; do
		_should_keep=1
		# 精确匹配失败名称（按行读取失败列表）
		while IFS= read -r _fail_name; do
			if [ "$_name" = "$_fail_name" ]; then
				_should_keep=0
				break
			fi
		done < "$FAILED_NAMES_FILE"

		if [ "$_should_keep" = "1" ]; then
			uci add_list "tkproxy.main.node=$_name|$_link"
			KEPT=$((KEPT + 1))
		fi
	done < "$BACKUP_FILE"

	uci commit tkproxy
	say "已删除 $((TOTAL - KEPT)) 个失败节点，保留 $KEPT 个"
fi

rm -f "$POOL_FILE"
printf 'available=%d\ntotal=%d\n' "$AVAILABLE" "$TOTAL" >> "$RESULT_FILE"
say "结果已写入: $RESULT_FILE"
exit 0
