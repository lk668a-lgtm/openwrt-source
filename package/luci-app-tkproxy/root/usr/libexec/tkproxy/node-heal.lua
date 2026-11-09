#!/usr/bin/lua
-- 死节点自动替换：出口取不到 IP 的线路，自动换到「体检 OK 且未被占用」的节点，然后部署。
-- 由 watchdog 每 30 分钟调用一次；也可手动执行：lua /usr/libexec/tkproxy/node-heal.lua
local util = require("luci.model.tkproxy.util")
local fs = require("nixio.fs")

local STATUS = "/tmp/tkproxy/status.txt"
local NT = "/tmp/tkproxy/nodetest.txt"

-- 1) 取当前出口表（status.sh 每行：SSID band subnet port type up exitip）
os.execute("sh /usr/libexec/tkproxy/status.sh > " .. STATUS .. " 2>&1")

local bad = {}
for line in io.lines(STATUS) do
	if line:match("^TK") then
		local ssid, _, _, _, _, up, exitip = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
		if ssid and (exitip == "null" or exitip == nil) then
			bad[ssid] = true
		end
	end
end

local nbad = 0
for _ in pairs(bad) do nbad = nbad + 1 end
if nbad == 0 then
	print("OK 所有线路出口正常")
	return 0
end

-- 2) 体检 OK 的节点
local ok = {}
if fs.access(NT) then
	for l in io.lines(NT) do
		local name, flag = l:match("^([^|]+)|.*|([A-Z]+)$")
		if name and flag == "OK" then ok[name] = true end
	end
end

-- 3) 已占用节点
local lines = util.lines()
local used = {}
for _, ln in ipairs(lines) do
	local node = ln:match("|@([^|]+)|")
	if node then used[node] = true end
end

-- 4) 空闲可用池
local free = {}
for _, n in ipairs(util.nodes()) do
	if ok[n.name] and not used[n.name] then free[#free + 1] = n.name end
end

if #free == 0 then
	print("WARN 有 " .. nbad .. " 条线路不通，但节点池里没有空闲可用节点")
	return 1
end

-- 5) 重写线路
local changed, fi = 0, 0
for i, ln in ipairs(lines) do
	local ssid = ln:match("^([^|]+)")
	if ssid and bad[ssid] then
		fi = fi + 1
		local node = free[fi]
		if node then
			lines[i] = ln:gsub("|@[^|]+|", "|@" .. node .. "|", 1)
			changed = changed + 1
		end
	end
end

if changed == 0 then
	print("WARN 需要换 " .. nbad .. " 条，但空闲节点只有 " .. #free .. " 个")
	return 1
end

local ok2, serr = util.save_lines(lines)
if not ok2 then
	print("ERR 保存线路失败：" .. tostring(serr))
	return 1
end

local dok, dmsg = util.start_deploy(lines)
print(string.format("INFO 已替换 %d 条线路并%s", changed, dok and "开始部署" or ("部署启动失败：" .. tostring(dmsg))))
return dok and 0 or 1
