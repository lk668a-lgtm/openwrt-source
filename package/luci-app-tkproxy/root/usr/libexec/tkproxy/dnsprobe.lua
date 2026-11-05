-- dnsprobe.lua <host> <port> [timeout]
-- 发一个真实的 DNS A 查询（TCP，带 2 字节长度前缀），收到应答退出 0，否则退出 1。
-- 用于体检判断"节点的 DNS 出口通不通"：客户端的 DNS 就是这条路径
-- （线路 DNS 入站 → 节点 → 上游 1.1.1.1:53）。
local host = arg[1] or "127.0.0.1"
local port = tonumber(arg[2] or "53") or 53
local tmo = tonumber(arg[3] or "4") or 4

local ok_nixio, nixio = pcall(require, "nixio")
if not ok_nixio then os.exit(2) end

-- 查询 www.google.com A
local q = "\18\52\1\0\0\1\0\0\0\0\0\0" ..
	"\3www\6google\3com\0" ..
	"\0\1\0\1"
local pkt = string.char(math.floor(#q / 256), #q % 256) .. q

local s = nixio.socket("inet", "stream")
if not s then os.exit(1) end
s:setopt("socket", "rcvtimeo", tmo)
s:setopt("socket", "sndtimeo", tmo)

local connected = s:connect(host, port)
if not connected then s:close(); os.exit(1) end

local sent = s:send(pkt)
if not sent or sent < #pkt then s:close(); os.exit(1) end

local head = s:recv(2)
if not head or #head < 2 then s:close(); os.exit(1) end
local want = head:byte(1) * 256 + head:byte(2)
local body = ""
while #body < want do
	local chunk = s:recv(want - #body)
	if not chunk or #chunk == 0 then break end
	body = body .. chunk
end
s:close()

-- 应答至少要有 DNS 头（12 字节）且与查询 ID 一致
if #body >= 12 and body:byte(1) == 18 and body:byte(2) == 52 then
	os.exit(0)
end
os.exit(1)
