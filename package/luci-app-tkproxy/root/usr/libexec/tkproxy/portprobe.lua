#!/usr/bin/lua
-- portprobe.lua <host> <port> [timeout_ms]
-- 判断 TCP 端口能否连通，带超时。
-- 为什么不用 nc/timeout：25.12 的 busybox 把 timeout 裁掉了，nc 也只剩
-- 「nc [IPADDR PORT]」一种用法（没有 -z/-w），拿它做探测会一直卡住或者恒判失败。
-- 这里用 nixio 非阻塞 connect + poll，2 秒拿不到结果就判不通。
local ok_nixio, nixio = pcall(require, "nixio")
if not ok_nixio then os.exit(2) end

local host = arg[1]
local port = tonumber(arg[2] or "80")
local tmo = tonumber(arg[3] or "2000")
if not host or not port then
	io.stderr:write("usage: portprobe.lua host port [timeout_ms]\n")
	os.exit(2)
end

local s = nixio.socket("inet", "stream")
if not s then os.exit(1) end
s:setblocking(false)

local ok, err, code = s:connect(host, port)
if ok then os.exit(0) end
-- 非阻塞 connect 在这版 nixio 上返回 nil, 115, "Operation in progress"（是文本不是 "inprogress"），
-- 所以这里不能按字符串判断：只要不是「立即被拒」（111 = ECONNREFUSED）就交给 poll 判定。
if tostring(err) == "111" then os.exit(1) end

-- 注意：这版 nixio 的 poll 是「传表」形式：nixio.poll({ {fd=s, events=...} }, timeout)
-- （nixio.poll() 返回 0、p:add 不存在，试过都不行）
local fds = { { fd = s, events = nixio.poll_flags("out") } }
local n = nixio.poll(fds, math.floor(tmo / 1000))
local connected = false
if n and n > 0 then
	local serr = s:getopt("socket", "error")
	if not serr or serr == 0 or serr == "0" then connected = true end
end
s:close()
os.exit(connected and 0 or 1)
