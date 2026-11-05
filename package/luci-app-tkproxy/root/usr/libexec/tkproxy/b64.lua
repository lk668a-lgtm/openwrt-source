-- SPDX-License-Identifier: GPL-3.0
-- 纯 Lua base64（编/解），替代 busybox base64。
-- 用法： lua b64.lua enc < in > out
--        lua b64.lua dec < in > out
-- 存在原因：ImmortalWrt 25.12 起 busybox 不再提供 base64 applet，
-- 老脚本直接调 base64 会让验签静默失败（真票被判 sig_invalid）。

local B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local R = {}
for i = 1, 64 do R[B:sub(i, i)] = i - 1 end

local mode = arg[1] or "enc"
local s = io.read("*a") or ""

local function encode(s)
	local out = {}
	for i = 1, #s, 3 do
		local a, b, c = s:byte(i, i + 2)
		local n = a * 65536 + (b or 0) * 256 + (c or 0)
		local c1 = math.floor(n / 262144) % 64
		local c2 = math.floor(n / 4096) % 64
		local c3 = math.floor(n / 64) % 64
		local c4 = n % 64
		out[#out + 1] = B:sub(c1 + 1, c1 + 1) .. B:sub(c2 + 1, c2 + 1) ..
			(b and B:sub(c3 + 1, c3 + 1) or "=") ..
			(c and B:sub(c4 + 1, c4 + 1) or "=")
	end
	io.write(table.concat(out))
end

local function decode(s)
	s = s:gsub("[^" .. "A-Za-z0-9%+/" .. "=]", "")
	local out = {}
	for i = 1, #s, 4 do
		local q = s:sub(i, i + 3)
		if #q < 4 then q = q .. string.rep("=", 4 - #q) end
		local v1, v2 = R[q:sub(1, 1)], R[q:sub(2, 2)]
		local v3, v4 = R[q:sub(3, 3)] or 0, R[q:sub(4, 4)] or 0
		if v1 and v2 then
			local n = v1 * 262144 + v2 * 4096 + v3 * 64 + v4
			out[#out + 1] = string.char(math.floor(n / 65536) % 256)
			if q:sub(3, 3) ~= "=" then
				out[#out + 1] = string.char(math.floor(n / 256) % 256)
			end
			if q:sub(4, 4) ~= "=" then
				out[#out + 1] = string.char(n % 256)
			end
		end
	end
	io.write(table.concat(out))
end

if mode == "dec" then decode(s) else encode(s) end
