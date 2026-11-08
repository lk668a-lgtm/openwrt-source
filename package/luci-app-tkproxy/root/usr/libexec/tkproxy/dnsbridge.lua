#!/usr/bin/lua
-- tkproxy DNS 桥：客户端 UDP DNS → 经该线路 SOCKS 口转成 TCP DNS
--
-- 为什么要它：很多机场节点只转发 TCP，不转发 UDP。原来 xray 的 dokodemo DNS 入站
-- 把客户端的 UDP 查询原样用 UDP 发出去，被节点吞掉，客户端表现为
-- 「WiFi 连上了但网页打不开」。本进程在路由器本机把 UDP 转成 TCP，客户无感知。
--
-- 实现：poll 监听 10.11.N.1:530N（每条线路一个），收到查询就 fork 一个短命子进程
-- 走 SOCKS5(127.0.0.1:220NN) → 1.1.1.1:53（TCP），拿到应答后用同一个 UDP socket 回包。
--
-- 用法：dnsbridge.lua [--base-port 5300] [--socks-base 22000] [--lines 30] [--debug]

local nixio = require("nixio")

local BASE_PORT = 5300
local SOCKS_BASE = 22000
local LINES = 30
local DEBUG = false
local UPSTREAM_IP = "1.1.1.1"
local UPSTREAM_PORT = 53
local TMO = 8

local i = 1
while arg and arg[i] do
	local a = arg[i]
	if a == "--base-port" then i = i + 1; BASE_PORT = tonumber(arg[i]) or BASE_PORT
	elseif a == "--socks-base" then i = i + 1; SOCKS_BASE = tonumber(arg[i]) or SOCKS_BASE
	elseif a == "--lines" then i = i + 1; LINES = tonumber(arg[i]) or LINES
	elseif a == "--upstream" then i = i + 1; UPSTREAM_IP = arg[i] or UPSTREAM_IP
	elseif a == "--upstream-port" then i = i + 1; UPSTREAM_PORT = tonumber(arg[i]) or UPSTREAM_PORT
	elseif a == "--debug" then DEBUG = true
	end
	i = i + 1
end

local function log(fmt, ...)
	if DEBUG then io.stderr:write(string.format("[dnsbridge] " .. fmt .. "\n", ...)) end
end

local function ipbytes(ip)
	local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return nil end
	return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

local UPB = ipbytes(UPSTREAM_IP) or string.char(1, 1, 1, 1)
local UP_PORT_HI, UP_PORT_LO = math.floor(UPSTREAM_PORT / 256), UPSTREAM_PORT % 256

local listeners = {}
local bound = {}
local function try_bind_missing()
	for n = 1, LINES do
		if not bound[n] then
			local ip = "10.11." .. n .. ".1"
			local s = nixio.socket("inet", "dgram")
			-- 不要设 SO_REUSEADDR：UDP 上它允许多个进程绑同一地址端口，
			-- 结果数据包被「另一个」实例收走，本实例永远收不到（25.12 实测踩过）。
			-- 保持阻塞模式：25.12 的 nixio 上 setblocking(false) 会让 recvfrom
			-- 即使有数据也返回 (false, EAGAIN)，数据被吃掉却拿不到内容，
			-- 表现就是桥在监听、DNS 全超时。这里用 poll 等可读，不做非阻塞自旋。
			if s:bind(ip, BASE_PORT + n) then
				bound[n] = true
				listeners[#listeners + 1] = { sock = s, line = n }
			else
				io.stderr:write("bind 失败 " .. ip .. ":" .. (BASE_PORT + n) .. "\n")
			end
		end
	end
end

-- 期望绑定数 = 当前真实存在 10.11.N.1 的桥数量（线路可能少于 LINES）
-- 注意：busybox 的 `ip -4 addr show 10.11.N.1/24` 恒失败，必须从完整地址表里数，
-- 否则这里恒为 0 → 绑好之后还会空转 40 轮（200 秒）才开始服务，期间 DNS 全超时。
local function expected_ports()
	local f = io.popen("ip -4 addr show 2>/dev/null | grep -oE '10\\.11\\.[0-9]+\\.1/' | sort -u | wc -l")
	local n = 0
	if f then
		n = tonumber((f:read("*l") or "0")) or 0
		f:close()
	end
	return n
end

try_bind_missing()
-- 服务重启/开机时桥 IP 可能还没就位：**逐条补绑**，不能只在一条都没绑上时重试
-- （实测：4 条线路里第 4 条的桥晚到，它永远拿不到 DNS 监听 → 那个 WiFi 能连不能上网）
local tries = 0
while tries < 40 do
	local exp = expected_ports()
	if exp > 0 and #listeners >= exp then break end
	tries = tries + 1
	io.stderr:write(string.format("待补绑 %d/%d 条，5 秒后重试（第 %d 次）\n", #listeners, exp, tries))
	os.execute("sleep 5")
	try_bind_missing()
end

if #listeners == 0 then
	io.stderr:write("没有可用监听端口，退出\n")
	os.exit(1)
end
log("监听 %d 条线路，上游 %s:%d（TCP）", #listeners, UPSTREAM_IP, UPSTREAM_PORT)

-- 子进程：阻塞完成一次 TCP DNS 查询
local function serve_one(sock, cli_addr, cli_port, line, query)
	local tcp = nixio.socket("inet", "stream")
	tcp:setopt("socket", "rcvtimeo", TMO)
	tcp:setopt("socket", "sndtimeo", TMO)
	if not tcp:connect("127.0.0.1", SOCKS_BASE + line) then
		log("第%d条 SOCKS 连接失败", line); tcp:close(); return false
	end
	if not tcp:send(string.char(5, 1, 0)) then tcp:close(); return false end
	local r = tcp:recv(2)
	if not r or #r < 2 or r:byte(1) ~= 5 then tcp:close(); return false end
	local req = string.char(5, 1, 0, 1) .. UPB .. string.char(UP_PORT_HI, UP_PORT_LO)
	if not tcp:send(req) then tcp:close(); return false end
	local rep = tcp:recv(10)
	if not rep or #rep < 10 or rep:byte(2) ~= 0 then tcp:close(); return false end
	local ln = string.char(math.floor(#query / 256), #query % 256)
	if not tcp:send(ln .. query) then tcp:close(); return false end
	local head = tcp:recv(2)
	if not head or #head < 2 then tcp:close(); return false end
	local want = head:byte(1) * 256 + head:byte(2)
	local body = ""
	while #body < want do
		local chunk = tcp:recv(want - #body)
		if not chunk or #chunk == 0 then break end
		body = body .. chunk
	end
	tcp:close()
	if #body < 12 then return false end
	sock:sendto(body, cli_addr, cli_port)
	return true
end

-- 用 poll 等可读，而不是「非阻塞 recvfrom + 20ms 空转」。
-- 25.12 的 nixio 上，非阻塞 dgram socket 的 recvfrom 会一直返回
-- (false, EAGAIN, "Resource temporarily unavailable")，即使数据已经在队列里，
-- 结果桥在监听、端口在、CPU 100%，但一个 DNS 查询都不回。改成 poll 等就正常。
local pfds = {}
for i, L in ipairs(listeners) do
	pfds[i] = { fd = L.sock, events = nixio.poll_flags("in") }
end

while true do
	local ready = nixio.poll(pfds, 500)
	if ready and ready > 0 then
		for i, L in ipairs(listeners) do
			local rev = pfds[i].revents
			if rev and rev > 0 then
				local data, addr, port = L.sock:recvfrom(2048)
				if data and type(data) ~= "boolean" and #data > 0 and addr then
					local pid = nixio.fork()
					if pid == 0 then
						for _, other in ipairs(listeners) do
							if other.sock ~= L.sock then pcall(function() other.sock:close() end) end
						end
						local ok = serve_one(L.sock, addr, port, L.line, data)
						os.exit(ok and 0 or 1)
					end
				end
			end
		end
	end

	-- 回收子进程。不同 nixio 版本 waitpid 返回值不一样（0 / nil / table / -1），
	-- 只判断 r == 0 会在新版本上死循环。
	for _ = 1, 64 do
		local ok, r = pcall(function() return nixio.waitpid(-1, "nohang") end)
		if not ok or r == nil then break end
		if type(r) == "table" then
			if not r.pid or tonumber(r.pid) == nil or tonumber(r.pid) <= 0 then break end
		elseif type(r) == "number" then
			if r <= 0 then break end
		else
			break
		end
	end
end
