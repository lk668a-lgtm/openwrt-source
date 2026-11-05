-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 纯 Lua 生成器（Web 端不依赖 python）
--
-- 输入清单（一行一个 SSID）：
--   # 注释
--   TK-01|vless://uuid@203.0.113.11:443?security=reality&sni=...&pbk=...&sid=...&flow=xtls-rprx-vision
--   TK-02|2g|trojan://pass@203.0.113.12:443?sni=example.com&type=ws&path=/ws
--   TK-03|5g|ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@203.0.113.10:8388
--   TK-04|json:{"type":"shadowsocks","server":"...","server_port":8388,...}
--
-- 产物与 tk-standalone/gen.py 完全同构（同名键 / 同结构）：
--   xray.json      Xray（N 个 tproxy inbound + N 个出站 + direct + 按 inbound 路由）
--   tkproxy.nft    nftables（按源网桥分流到各自的本地端口）
--   manifest.json  SSID ↔ 网段 ↔ 端口 ↔ 出站标签 对照表
--
-- 只用 Lua 5.1 标准库：LuCI / 路由器 / 本地 lua 都能直接跑。
-- 不生成 urltest / fallback / loadbalance（IP 稳定性红线）。

local M = {}

-- ---------------------------------------------------------------------------
-- 基础工具
-- ---------------------------------------------------------------------------

local function trim(s)
	return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function split_first(s, sep)
	local i = s:find(sep, 1, true)
	if not i then return s, nil end
	return s:sub(1, i - 1), s:sub(i + #sep)
end

local function unquote(s)
	if s == nil then return "" end
	return (s:gsub("%%(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end))
end

local function unquote_plus(s)
	return unquote((s:gsub("%+", " ")))
end

local function nz(v)
	if v == nil or v == "" then return nil end
	return v
end

local function split_csv(s)
	local out = {}
	for part in tostring(s or ""):gmatch("[^,]+") do out[#out + 1] = part end
	return out
end

-- 保持与 gen.py 相同的键顺序（JSON 对象本身无序，这里只为产物可读、可比对）
local function ordered(t, keys)
	return setmetatable(t, { __json_order = keys })
end

local function order_add(t, key)
	local mt = getmetatable(t)
	if mt and mt.__json_order then
		mt.__json_order[#mt.__json_order + 1] = key
		return
	end
	local keys = {}
	for k in pairs(t) do
		if type(k) == "string" then keys[#keys + 1] = k end
	end
	table.sort(keys)
	setmetatable(t, { __json_order = keys })
end

local ARRAY_MT = { __json_array = true }

local function arr(t)
	return setmetatable(t or {}, ARRAY_MT)
end

-- ---------------------------------------------------------------------------
-- base64（SIP002 / vmess 用）
-- ---------------------------------------------------------------------------

local B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_MAP = {}
for i = 1, #B64_ALPHABET do
	B64_MAP[B64_ALPHABET:sub(i, i)] = i - 1
end

local function b64decode(s)
	if type(s) ~= "string" then return nil end
	s = s:gsub("%s+", ""):gsub("-", "+"):gsub("_", "/")
	local eq = s:find("=", 1, true)
	if eq then s = s:sub(1, eq - 1) end
	local clean = {}
	for i = 1, #s do
		local c = s:sub(i, i)
		if B64_MAP[c] then clean[#clean + 1] = c end
	end
	s = table.concat(clean)
	local rem = #s % 4
	if rem == 1 then return nil end
	if rem > 0 then s = s .. string.rep("=", 4 - rem) end
	local out = {}
	for i = 1, #s, 4 do
		local c1, c2, c3, c4 = s:sub(i, i), s:sub(i + 1, i + 1), s:sub(i + 2, i + 2), s:sub(i + 3, i + 3)
		local n1, n2 = B64_MAP[c1], B64_MAP[c2]
		if not n1 or not n2 then return nil end
		local n3 = (c3 ~= "=") and B64_MAP[c3] or 0
		local n4 = (c4 ~= "=") and B64_MAP[c4] or 0
		local n = n1 * 262144 + n2 * 4096 + n3 * 64 + n4
		out[#out + 1] = string.char(math.floor(n / 65536) % 256)
		if c3 ~= "=" then out[#out + 1] = string.char(math.floor(n / 256) % 256) end
		if c4 ~= "=" then out[#out + 1] = string.char(n % 256) end
	end
	return table.concat(out)
end

-- 导出 Base64 解码函数供订阅使用（BLK-11）
-- 支持标准 Base64、URL-safe（- _ 替换）、无填充
M.b64decode_for_subscription = function(s)
	if type(s) ~= "string" or s == "" then
		return ""
	end
	-- 验证输入只包含合法 Base64 字符（标准 + URL-safe）
	if not s:match("^[A-Za-z0-9+/_-]+=*$") then
		return ""
	end
	local ok, result = pcall(b64decode, s)
	if not ok or not result or result == "" then
		return ""
	end
	return result
end

-- ---------------------------------------------------------------------------
-- 字段校验（节点凭据 / 端口 / 算法白名单）
-- ---------------------------------------------------------------------------

local UUID_PAT = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

local function valid_uuid(s)
	return type(s) == "string" and s:match(UUID_PAT) ~= nil
end

local function valid_port(p)
	local n = tonumber(p)
	return n ~= nil and n % 1 == 0 and n >= 1 and n <= 65535
end

local SS_METHODS = {
	["aes-128-gcm"] = true,
	["aes-256-gcm"] = true,
	["chacha20-ietf-poly1305"] = true,
	["2022-blake3-aes-128-gcm"] = true,
	["2022-blake3-aes-256-gcm"] = true,
	["none"] = true,
}

local VMESS_SECURITY = {
	auto = true,
	["aes-128-gcm"] = true,
	["chacha20-poly1305"] = true,
	none = true,
	zero = true,
}

local VLESS_FP = {
	chrome = true, safari = true, ios = true,
	android = true, firefox = true, edge = true,
}

local function valid_ss_method(m)
	return type(m) == "string" and SS_METHODS[m:lower()] == true
end

local function ss_method_list()
	return "aes-128-gcm/aes-256-gcm/chacha20-ietf-poly1305/"
		.. "2022-blake3-aes-128-gcm/2022-blake3-aes-256-gcm/none"
end

-- reality 公钥：43 字符无 padding base64url，解码后必须正好 32 字节
local function valid_reality_pbk(s)
	if type(s) ~= "string" or #s ~= 43 or not s:match("^[A-Za-z0-9_-]+$") then
		return false
	end
	local raw = b64decode(s)
	return raw ~= nil and #raw == 32
end

-- ---------------------------------------------------------------------------
-- IPv4 / CIDR（网段冲突检查与 LAN 探测）
-- ---------------------------------------------------------------------------

local function ipv4_num(s)
	local a, b, c, d = tostring(s or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return nil end
	a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
	if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
	return ((a * 256 + b) * 256 + c) * 256 + d
end

local function num_ipv4(n)
	n = math.floor(n)
	return table.concat({
		math.floor(n / 16777216) % 256,
		math.floor(n / 65536) % 256,
		math.floor(n / 256) % 256,
		n % 256,
	}, ".")
end

-- 返回 网络地址数字, 前缀长度；输入非法返回 nil
local function parse_cidr(c)
	local ip, pfx = tostring(c or ""):match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
	if not ip then return nil end
	local n = ipv4_num(ip)
	pfx = tonumber(pfx)
	if n == nil or pfx == nil or pfx > 32 then return nil end
	local block = 2 ^ (32 - pfx)
	return math.floor(n / block) * block, pfx
end

local function cidr_overlap(a, b)
	local na, pa = parse_cidr(a)
	local nb, pb = parse_cidr(b)
	if not na or not nb then return false end
	local block = 2 ^ (32 - math.min(pa, pb))
	return math.floor(na / block) == math.floor(nb / block)
end

local function canon_cidr(c)
	local n, pfx = parse_cidr(c)
	if not n then return nil end
	return num_ipv4(n) .. "/" .. pfx
end

-- 兼容 string / table；逗号和空白都可分隔。第二个返回值是第一个非法项
local function normalize_lans(v)
	local out, seen, bad = {}, {}, nil
	local function add(x)
		x = trim(x)
		if x == "" then return end
		local c = canon_cidr(x)
		if not c then
			bad = bad or x
			return
		end
		if not seen[c] then
			seen[c] = true
			out[#out + 1] = c
		end
	end
	if type(v) == "table" then
		for _, x in ipairs(v) do add(x) end
	elseif type(v) == "string" then
		for x in v:gmatch("[^,%s]+") do add(x) end
	elseif v ~= nil then
		bad = tostring(v)
	end
	return out, bad
end

-- 解析 `ip -4 addr`：只取 scope global 的 IPv4 /24
local function parse_ip_addr(text)
	local out, seen = {}, {}
	local ifname = ""
	for line in tostring(text or ""):gmatch("[^\r\n]+") do
		local no, name = line:match("^%s*(%d+):%s*([%w%-%._]+):")
		if no and name then ifname = name end
		local ip, pfx = line:match("%f[%w]inet%s+(%d+%.%d+%.%d+%.%d+)/(%d+)")
		if ip and tonumber(pfx) == 24 and line:find("scope global", 1, true) then
			local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
			local net = a .. "." .. b .. "." .. c .. ".0/24"
			-- 排除本插件自己建的分流网桥及其网段：
			-- 否则已部署过 30 条线路后，下一次生成会把 brtk1 的 10.11.1.0/24
			-- 误判成「主 LAN」，再与自己冲突而拒绝生成。
			local own_if = ifname:match("^brtk%d+$") or ifname:match("^br%-tk%d+$")
			local self_net = (a == "10" and b == "11")
			if not own_if and not self_net and not seen[net] then
				seen[net] = true
				out[#out + 1] = net
			end
		end
	end
	return out
end

-- 探测本机直连网段；raw 为测试/离线注入的 `ip -4 addr` 输出。
-- 返回 网段列表, "detected" | "fallback"
local function detect_lan(raw)
	local text = raw
	if text == nil then
		local devnull = package.config:sub(1, 1) == "\\" and "2>NUL" or "2>/dev/null"
		local ok, fh = pcall(io.popen, "ip -4 addr " .. devnull)
		if ok and fh then
			text = fh:read("*a")
			fh:close()
		end
	end
	local out = parse_ip_addr(text)
	if #out == 0 then
		return { "192.168.8.0/24" }, "fallback"
	end
	return out, "detected"
end

-- ---------------------------------------------------------------------------
-- SHA-256（纯 Lua，5.1 没有位运算；只为 gen.py 的 bssid 派生保持一致）
-- ---------------------------------------------------------------------------

local U32 = 4294967296

local function u32(x)
	return x % U32
end

local function u32add(...)
	local s = 0
	for i = 1, select("#", ...) do s = s + select(i, ...) end
	return s % U32
end

local function band(a, b)
	local r, bit = 0, 1
	for _ = 1, 32 do
		local x, y = a % 2, b % 2
		if x == 1 and y == 1 then r = r + bit end
		a, b, bit = (a - x) / 2, (b - y) / 2, bit * 2
	end
	return r
end

local function bxor(a, b)
	local r, bit = 0, 1
	for _ = 1, 32 do
		local x, y = a % 2, b % 2
		if x ~= y then r = r + bit end
		a, b, bit = (a - x) / 2, (b - y) / 2, bit * 2
	end
	return r
end

local function bnot(a)
	return U32 - 1 - a
end

local function rshift(a, n)
	return math.floor(a / 2 ^ n) % U32
end

local function ror(a, n)
	local d = 2 ^ n
	return (math.floor(a / d) + (a % d) * 2 ^ (32 - n)) % U32
end

local SHA_K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function be32s(v)
	return string.char(
		math.floor(v / 16777216) % 256,
		math.floor(v / 65536) % 256,
		math.floor(v / 256) % 256,
		v % 256)
end

local function hex32(v)
	local b = {}
	for i = 4, 1, -1 do
		b[i] = v % 256
		v = math.floor(v / 256)
	end
	return string.format("%02x%02x%02x%02x", b[1], b[2], b[3], b[4])
end

local function sha256(msg)
	msg = tostring(msg)
	local bitlen = #msg * 8
	local pad = (55 - #msg) % 64
	msg = msg .. "\128" .. string.rep("\0", pad) ..
		be32s(math.floor(bitlen / U32)) .. be32s(bitlen % U32)

	local H = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	local bytes = { msg:byte(1, -1) }
	local w = {}

	for off = 1, #bytes, 64 do
		local function word(i)
			return ((bytes[off + i] * 256 + bytes[off + i + 1]) * 256 + bytes[off + i + 2]) * 256 + bytes[off + i + 3]
		end
		for i = 0, 15 do w[i] = word(i * 4) end
		for i = 16, 63 do
			local x, y = w[i - 15], w[i - 2]
			local s0 = bxor(bxor(ror(x, 7), ror(x, 18)), rshift(x, 3))
			local s1 = bxor(bxor(ror(y, 17), ror(y, 19)), rshift(y, 10))
			w[i] = u32add(w[i - 16], s0, w[i - 7], s1)
		end

		local a, b, c, d = H[1], H[2], H[3], H[4]
		local e, f, g, h = H[5], H[6], H[7], H[8]
		for i = 0, 63 do
			local S1 = bxor(bxor(ror(e, 6), ror(e, 11)), ror(e, 25))
			local ch = bxor(band(e, f), band(bnot(e), g))
			local t1 = u32add(h, S1, ch, SHA_K[i + 1], w[i])
			local S0 = bxor(bxor(ror(a, 2), ror(a, 13)), ror(a, 22))
			local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
			local t2 = u32add(S0, maj)
			h, g, f, e = g, f, e, u32add(d, t1)
			d, c, b, a = c, b, a, u32add(t1, t2)
		end
		H[1], H[2], H[3], H[4] = u32add(H[1], a), u32add(H[2], b), u32add(H[3], c), u32add(H[4], d)
		H[5], H[6], H[7], H[8] = u32add(H[5], e), u32add(H[6], f), u32add(H[7], g), u32add(H[8], h)
	end
	return table.concat({
		hex32(H[1]), hex32(H[2]), hex32(H[3]), hex32(H[4]),
		hex32(H[5]), hex32(H[6]), hex32(H[7]), hex32(H[8]),
	})
end

local function mac_for(slug)
	local h = sha256("tk-bssid:" .. slug)
	return "02:" .. h:sub(1, 2) .. ":" .. h:sub(3, 4) .. ":" .. h:sub(5, 6) ..
		":" .. h:sub(7, 8) .. ":" .. h:sub(9, 10)
end

-- ---------------------------------------------------------------------------
-- JSON（解析保留键顺序；数组带标记，空数组也能正确编码）
-- ---------------------------------------------------------------------------

local JSON_NULL = setmetatable({}, { __json_null = true })

local function utf8_char(cp)
	if cp < 0x80 then
		return string.char(cp)
	elseif cp < 0x800 then
		return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
	elseif cp < 0x10000 then
		return string.char(
			0xE0 + math.floor(cp / 0x1000),
			0x80 + math.floor(cp / 0x40) % 0x40,
			0x80 + cp % 0x40)
	end
	return string.char(
		0xF0 + math.floor(cp / 0x40000),
		0x80 + math.floor(cp / 0x1000) % 0x40,
		0x80 + math.floor(cp / 0x40) % 0x40,
		0x80 + cp % 0x40)
end

local function json_decode(text)
	if type(text) ~= "string" then return nil, "JSON 输入不是字符串" end
	local pos = 1

	local function fail(msg)
		error(msg .. " (位置 " .. pos .. ")", 0)
	end

	local function skip_ws()
		while true do
			local c = text:sub(pos, pos)
			if c == " " or c == "\t" or c == "\n" or c == "\r" then
				pos = pos + 1
			else
				return
			end
		end
	end

	local parse_value

	local function parse_string()
		pos = pos + 1
		local buf = {}
		while true do
			local c = text:sub(pos, pos)
			if c == "" then fail("字符串未闭合") end
			if c == '"' then
				pos = pos + 1
				return table.concat(buf)
			elseif c == "\\" then
				local e = text:sub(pos + 1, pos + 1)
				pos = pos + 2
				if e == '"' then buf[#buf + 1] = '"'
				elseif e == "\\" then buf[#buf + 1] = "\\"
				elseif e == "/" then buf[#buf + 1] = "/"
				elseif e == "b" then buf[#buf + 1] = "\b"
				elseif e == "f" then buf[#buf + 1] = "\f"
				elseif e == "n" then buf[#buf + 1] = "\n"
				elseif e == "r" then buf[#buf + 1] = "\r"
				elseif e == "t" then buf[#buf + 1] = "\t"
				elseif e == "u" then
					local hex = text:sub(pos, pos + 3)
					if not hex:match("^%x%x%x%x$") then fail("\\u 转义非法") end
					pos = pos + 4
					local cp = tonumber(hex, 16)
					if cp >= 0xD800 and cp <= 0xDBFF then
						if text:sub(pos, pos + 1) == "\\u" then
							local hex2 = text:sub(pos + 2, pos + 5)
							if hex2:match("^%x%x%x%x$") then
								local lo = tonumber(hex2, 16)
								if lo >= 0xDC00 and lo <= 0xDFFF then
									pos = pos + 6
									cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
								end
							end
						end
					end
					buf[#buf + 1] = utf8_char(cp)
				else
					fail("未知转义 \\" .. tostring(e))
				end
			else
				if c:byte() < 0x20 then fail("字符串里有未转义的控制字符") end
				buf[#buf + 1] = c
				pos = pos + 1
			end
		end
	end

	local function parse_number()
		local s = text:sub(pos):match("^-?%d+%.?%d*[eE]?[-+]?%d*")
		if not s or s == "" then fail("数字非法") end
		local n = tonumber(s)
		if n == nil then fail("数字非法：" .. s) end
		pos = pos + #s
		return n
	end

	local function parse_array()
		pos = pos + 1
		local out = arr({})
		skip_ws()
		if text:sub(pos, pos) == "]" then
			pos = pos + 1
			return out
		end
		while true do
			out[#out + 1] = parse_value()
			skip_ws()
			local c = text:sub(pos, pos)
			if c == "," then
				pos = pos + 1
				skip_ws()
			elseif c == "]" then
				pos = pos + 1
				return out
			else
				fail("数组语法错误")
			end
		end
	end

	local function parse_object()
		pos = pos + 1
		local out, keys, seen = {}, {}, {}
		skip_ws()
		if text:sub(pos, pos) == "}" then
			pos = pos + 1
			return ordered(out, keys)
		end
		while true do
			skip_ws()
			if text:sub(pos, pos) ~= '"' then fail("对象键必须是字符串") end
			local k = parse_string()
			skip_ws()
			if text:sub(pos, pos) ~= ":" then fail("缺少冒号") end
			pos = pos + 1
			out[k] = parse_value()
			if not seen[k] then
				seen[k] = true
				keys[#keys + 1] = k
			end
			skip_ws()
			local c = text:sub(pos, pos)
			if c == "," then
				pos = pos + 1
			elseif c == "}" then
				pos = pos + 1
				return ordered(out, keys)
			else
				fail("对象语法错误")
			end
		end
	end

	parse_value = function()
		skip_ws()
		local c = text:sub(pos, pos)
		if c == "{" then return parse_object() end
		if c == "[" then return parse_array() end
		if c == '"' then return parse_string() end
		if text:sub(pos, pos + 3) == "true" then pos = pos + 4; return true end
		if text:sub(pos, pos + 4) == "false" then pos = pos + 5; return false end
		if text:sub(pos, pos + 3) == "null" then pos = pos + 4; return JSON_NULL end
		return parse_number()
	end

	local ok, res = pcall(parse_value)
	if not ok then return nil, tostring(res) end
	skip_ws()
	if pos <= #text then return nil, "JSON 尾部有多余内容 (位置 " .. pos .. ")" end
	return res
end

local function is_array(t)
	local mt = getmetatable(t)
	if mt and mt.__json_array then return true end
	if mt and mt.__json_null then return false end
	local n = #t
	if n == 0 then return false end
	local count = 0
	for k in pairs(t) do
		if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then return false end
		count = count + 1
	end
	return count == n
end

local function ordered_keys(t)
	local keys, seen = {}, {}
	local mt = getmetatable(t)
	if mt and mt.__json_order then
		for _, k in ipairs(mt.__json_order) do
			if t[k] ~= nil and not seen[k] then
				seen[k] = true
				keys[#keys + 1] = k
			end
		end
	end
	local rest = {}
	for k in pairs(t) do
		if type(k) == "string" and not seen[k] then rest[#rest + 1] = k end
	end
	table.sort(rest)
	for _, k in ipairs(rest) do keys[#keys + 1] = k end
	return keys
end

local INDENT = "  "

local function enc_string(s)
	s = tostring(s):gsub('[%z\1-\31\\"]', function(c)
		if c == '"' then return '\\"'
		elseif c == "\\" then return "\\\\"
		elseif c == "\b" then return "\\b"
		elseif c == "\f" then return "\\f"
		elseif c == "\n" then return "\\n"
		elseif c == "\r" then return "\\r"
		elseif c == "\t" then return "\\t"
		end
		return string.format("\\u%04x", c:byte())
	end)
	return '"' .. s .. '"'
end

local function enc_number(n)
	if n ~= n or n == math.huge or n == -math.huge then
		error("无法序列化非有限数字", 0)
	end
	if n % 1 == 0 then
		if n >= -2147483648 and n <= 2147483647 then
			return string.format("%d", n)
		end
		return string.format("%.0f", n)
	end
	return tostring(n)
end

local encode_value

encode_value = function(v, level)
	if v == JSON_NULL or v == nil then return "null" end
	local t = type(v)
	if t == "string" then return enc_string(v) end
	if t == "number" then return enc_number(v) end
	if t == "boolean" then return v and "true" or "false" end
	if t ~= "table" then error("无法序列化类型 " .. t, 0) end

	local pad = INDENT:rep(level + 1)
	local close = INDENT:rep(level)

	if is_array(v) then
		if #v == 0 then return "[]" end
		local parts = {}
		for i = 1, #v do parts[i] = pad .. encode_value(v[i], level + 1) end
		return "[\n" .. table.concat(parts, ",\n") .. "\n" .. close .. "]"
	end

	local keys = ordered_keys(v)
	if #keys == 0 then return "{}" end
	local parts = {}
	for i, k in ipairs(keys) do
		parts[i] = pad .. enc_string(k) .. ": " .. encode_value(v[k], level + 1)
	end
	return "{\n" .. table.concat(parts, ",\n") .. "\n" .. close .. "}"
end

local function json_encode(v)
	return encode_value(v, 0)
end

-- ---------------------------------------------------------------------------
-- URL / 协议解析
-- ---------------------------------------------------------------------------

-- Python urlsplit 的最小等价实现：fragment / query / userinfo / host / port
local function url_parts(u)
	local scheme, rest = u:match("^([%a][%w+.-]*)://(.*)$")
	if not scheme then return nil, "链接缺少 scheme://" end
	local fragment
	rest, fragment = split_first(rest, "#")
	local query
	rest, query = split_first(rest, "?")
	local authority = rest:match("^([^/]*)") or ""

	local at = authority:match("^.*()@")
	local userinfo, hostport
	if at then
		userinfo = authority:sub(1, at - 1)
		hostport = authority:sub(at + 1)
	else
		hostport = authority
	end

	local host, portstr
	if hostport:sub(1, 1) == "[" then
		host, portstr = hostport:match("^%[([^%]]+)%]:(.+)$")
		if not host then host = hostport:match("^%[([^%]]+)%]$") end
	else
		host, portstr = hostport:match("^(.+):([^:]*)$")
		if not host then host = hostport end
	end
	if host then host = host:lower() end

	local port
	if portstr ~= nil and portstr ~= "" then
		if not portstr:match("^%d+$") then return nil, "端口非法：" .. portstr end
		port = tonumber(portstr)
		if not port or port < 1 or port > 65535 then return nil, "端口超出范围：" .. portstr end
	end

	return {
		scheme = scheme:lower(),
		userinfo = userinfo,
		host = host,
		port = port,
		query = query,
		fragment = fragment,
	}
end

local function userinfo_parts(ui)
	if not ui then return nil, nil end
	local eq = ui:find(":", 1, true)
	if not eq then return ui, nil end
	return ui:sub(1, eq - 1), ui:sub(eq + 1)
end

-- Python urlsplit().username 的语义：只取第一个 ':' 之前的部分
local function url_username(ui)
	return (userinfo_parts(ui))
end

-- Python parse_qs 的语义：空值丢弃、重复键取第一个、'+' 当空格
local function parse_qs(q)
	local out = {}
	if not q or q == "" then return out end
	for pair in q:gmatch("[^&]+") do
		local eq = pair:find("=", 1, true)
		local k, v
		if eq then
			k, v = pair:sub(1, eq - 1), pair:sub(eq + 1)
		else
			k, v = pair, ""
		end
		k, v = unquote_plus(k), unquote_plus(v)
		if v ~= "" and out[k] == nil then out[k] = v end
	end
	return out
end

-- 与 gen.py transport() 一致：ws / grpc / http，tcp/raw 不加 transport。
-- 未实现的 transport 必须报错，不能静默降级成直连。
local TRANSPORT_HINTS = {
	quic = "请改用 tls+ws/grpc，或用 json: 直贴 Xray 出站",
	httpupgrade = "请改用 ws，或用 json: 直贴 Xray 出站",
	kcp = "请改用 tcp/ws，或用 json: 直贴 Xray 出站",
	xhttp = "请改用 ws/grpc，或用 json: 直贴 Xray 出站",
}

local function make_transport(net, host, path)
	net = (net or "tcp"):lower()
	if net == "" then net = "tcp" end
	if net == "tcp" or net == "raw" then
		return nil
	end
	if net == "ws" then
		local tr = ordered({ type = "ws" }, { "type" })
		if nz(path) then tr.path = path; order_add(tr, "path") end
		if nz(host) then
			tr.headers = ordered({ Host = host }, { "Host" })
			order_add(tr, "headers")
		end
		return tr
	elseif net == "grpc" or net == "gun" then
		local tr = ordered({ type = "grpc" }, { "type" })
		if nz(path) then tr.service_name = path; order_add(tr, "service_name") end
		return tr
	elseif net == "h2" or net == "http" then
		local tr = ordered({ type = "http" }, { "type" })
		if nz(host) then tr.host = arr(split_csv(host)); order_add(tr, "host") end
		if nz(path) then tr.path = path; order_add(tr, "path") end
		return tr
	end
	local hint = TRANSPORT_HINTS[net]
		or "请改用 tcp/ws/grpc/http，或用 json: 直贴 Xray 出站"
	return nil, ("不支持 transport=%s，%s"):format(net, hint)
end

local function parse_ss(u)
	local body = u:sub(6) -- 去掉 "ss://"
	body = split_first(body, "#")
	local rest, query = split_first(body, "?")
	body = rest
	-- Xray 的 shadowsocks 出站没有 plugin 字段；带插件的链接不能静默丢参数
	if query and query:find("plugin=", 1, true) then
		return nil, "不支持带插件的 SS，请用 json: 直贴 Xray 出站"
	end
	local method, pw, hostport

	if body:find("@", 1, true) then
		local at = body:match("^.*()@")
		local userinfo = body:sub(1, at - 1)
		hostport = body:sub(at + 1)
		local dec = b64decode(unquote(userinfo))
		-- SIP002 允许 userinfo 直接写 method:password（百分号编码）
		if not dec or not dec:find(":", 1, true) then dec = unquote(userinfo) end
		local eq = dec:find(":", 1, true)
		if eq then
			method, pw = dec:sub(1, eq - 1), dec:sub(eq + 1)
		else
			method, pw = dec, ""
		end
	else
		local dec = b64decode(body)
		if not dec then return nil, "ss 链接 base64 解码失败" end
		local at = dec:match("^.*()@")
		local userinfo
		if at then
			userinfo = dec:sub(1, at - 1)
			hostport = dec:sub(at + 1)
		else
			userinfo, hostport = "", dec
		end
		local eq = userinfo:find(":", 1, true)
		if eq then
			method, pw = userinfo:sub(1, eq - 1), userinfo:sub(eq + 1)
		else
			method, pw = userinfo, ""
		end
	end

	if not method or method == "" then return nil, "ss 缺少 method/password" end
	if not valid_ss_method(method) then
		return nil, ("ss method 不支持：%s（可选 %s）"):format(tostring(method), ss_method_list())
	end
	if pw == nil or pw == "" then return nil, "ss password 不能为空" end
	if hostport == nil then return nil, "ss 缺少服务器地址" end

	local host, portstr = hostport:match("^(.+):([^:]*)$")
	if not host then host, portstr = "", hostport end
	host = host:gsub("^[%[%]]+", ""):gsub("[%[%]]+$", "")
	if host == "" then return nil, "ss 缺少服务器地址" end
	if not portstr:match("^%d+$") then return nil, "ss 端口非法：" .. tostring(portstr) end
	local port = tonumber(portstr)
	if not valid_port(port) then
		return nil, "ss 端口超出范围（1-65535）：" .. tostring(portstr)
	end

	local ob = ordered({
		type = "shadowsocks",
		server = host,
		server_port = port,
		method = method:lower(),
		password = pw,
	}, { "type", "server", "server_port", "method", "password" })
	return ob
end

local function parse_vmess(u)
	local raw = split_first(u:sub(9), "#") -- 去掉 "vmess://"
	local dec = b64decode(raw)
	if not dec then return nil, "vmess 链接 base64 解码失败" end
	local j, jerr = json_decode(dec)
	if not j then return nil, "vmess JSON 解析失败：" .. tostring(jerr) end
	if type(j) ~= "table" or is_array(j) then return nil, "vmess JSON 不是对象" end
	if j.id == nil or tostring(j.id) == "" then return nil, "vmess 缺少 id" end
	if j.add == nil or tostring(j.add) == "" then return nil, "vmess 缺少 add" end
	if not valid_uuid(tostring(j.id)) then
		return nil, "vmess uuid 格式非法：" .. tostring(j.id)
	end
	local port = tonumber(j.port)
	if not port or port % 1 ~= 0 or port < 1 or port > 65535 then
		return nil, "vmess port 非法：" .. tostring(j.port)
	end
	local aid = tonumber(j.aid or 0)
	if not aid or aid % 1 ~= 0 then return nil, "vmess aid 非法：" .. tostring(j.aid) end
	local scy = tostring(nz(j.scy) or "auto")
	if not VMESS_SECURITY[scy] then
		return nil, ("vmess security 不支持：%s（可选 auto/aes-128-gcm/"
			.. "chacha20-poly1305/none/zero）"):format(scy)
	end
	local host = tostring(j.host or "")
	local path = tostring(j.path or "")

	local ob = ordered({
		type = "vmess",
		server = tostring(j.add),
		server_port = port,
		uuid = tostring(j.id),
		security = scy,
		alter_id = aid,
	}, { "type", "server", "server_port", "uuid", "security", "alter_id" })

	local tr, terr = make_transport(nz(j.net) or "tcp", host, path)
	if terr then return nil, terr end
	if tr then ob.transport = tr; order_add(ob, "transport") end

	if nz(j.tls) == "tls" then
		local sni = nz(j.sni) or nz(host) or tostring(j.add)
		ob.tls = ordered({ enabled = true, server_name = sni }, { "enabled", "server_name" })
		order_add(ob, "tls")
	end
	return ob
end

local function parse_vless(u)
	local p, perr = url_parts(u)
	if not p then return nil, perr end
	local q = parse_qs(p.query)
	local uuid = unquote(url_username(p.userinfo) or "")
	if uuid == "" then return nil, "vless 缺少 uuid" end
	if not valid_uuid(uuid) then return nil, "vless uuid 格式非法：" .. uuid end
	if not p.host or p.host == "" then return nil, "vless 缺少服务器地址" end
	if not p.port then return nil, "vless 端口非法" end

	local sec = (q.security or "none"):lower()
	local net = (q.type or "tcp"):lower()
	if q.fp and not VLESS_FP[q.fp] then
		return nil, ("vless fp 不支持：%s（可选 chrome/safari/ios/android/firefox/edge）"):format(q.fp)
	end
	if q.flow and q.flow ~= "xtls-rprx-vision" then
		return nil, "vless flow 只支持 xtls-rprx-vision：" .. q.flow
	end
	if q.flow then
		if net ~= "tcp" and net ~= "raw" then
			return nil, ("vless flow=xtls-rprx-vision 需要 transport=tcp（当前 %s）"):format(net)
		end
		if sec ~= "reality" and sec ~= "tls" and sec ~= "xtls" then
			return nil, ("vless flow=xtls-rprx-vision 需要 security=reality 或 tls（当前 %s）"):format(sec)
		end
	end
	if sec == "reality" then
		if not valid_reality_pbk(q.pbk) then
			return nil, "vless reality pbk 必须是 43 字符 base64url（32 字节）"
		end
		if q.sid and (#q.sid > 16 or not q.sid:match("^%x+$")) then
			return nil, "vless reality sid 必须是 <=16 位十六进制"
		end
	end

	local ob = ordered({
		type = "vless",
		server = p.host,
		server_port = p.port,
		uuid = uuid,
	}, { "type", "server", "server_port", "uuid" })

	if q.flow then ob.flow = q.flow; order_add(ob, "flow") end

	if sec == "tls" or sec == "reality" or sec == "xtls" then
		local tls = ordered({
			enabled = true,
			server_name = q.sni or q.host or p.host,
		}, { "enabled", "server_name" })
		if q.fp then
			tls.utls = ordered({ enabled = true, fingerprint = q.fp }, { "enabled", "fingerprint" })
			order_add(tls, "utls")
		end
		-- ALPN 处理：ws 始终输出 ["http/1.1"]，其它传输保持原链接列表
		local _net = (q.type or q.network or "tcp"):lower()
		if _net == "ws" or _net == "websocket" then
			tls.alpn = arr({ "http/1.1" })
			order_add(tls, "alpn")
		elseif q.alpn then
			local _al = split_csv(q.alpn)
			if #_al > 0 then
				tls.alpn = arr(_al)
				order_add(tls, "alpn")
			end
		end
		if sec == "reality" then
			local reality_obj = ordered({
				enabled = true,
				public_key = q.pbk or "",
				short_id = q.sid or "",
			}, { "enabled", "public_key", "short_id" })
			local spx = q.spx or q.spiderX
			if spx and spx ~= "" then
				reality_obj.spiderX = spx
				order_add(reality_obj, "spiderX")
			end
			tls.reality = reality_obj
			order_add(tls, "reality")
		end
		-- allowInsecure 已从 Xray 26 移除：写了会让 xray run -test 直接报错，
		-- 导致整条线路（乃至整次部署）失败。这里忽略该参数，节点仍可正常连接。
		ob.tls = tls
		order_add(ob, "tls")
	end

	local tr, terr = make_transport(q.type, q.host or "", q.path or q.serviceName or "")
	if terr then return nil, terr end
	if tr then ob.transport = tr; order_add(ob, "transport") end
	return ob
end

local function parse_trojan(u)
	local p, perr = url_parts(u)
	if not p then return nil, perr end
	local q = parse_qs(p.query)
	local password = unquote(url_username(p.userinfo) or "")
	if password == "" then return nil, "trojan 缺少 password" end
	if not p.host or p.host == "" then return nil, "trojan 缺少服务器地址" end
	if not p.port then return nil, "trojan 端口非法" end

	local ob = ordered({
		type = "trojan",
		server = p.host,
		server_port = p.port,
		password = password,
	}, { "type", "server", "server_port", "password" })

	local tls = ordered({
		enabled = true,
		server_name = q.sni or q.peer or p.host,
	}, { "enabled", "server_name" })
	-- allowInsecure 已从 Xray 26 移除，忽略（原因见上）
	-- ALPN 处理：WebSocket 传输只认 http/1.1，若声明 h2/h3 会导致协商到 h2 被服务端断开（EOF）
		if q.alpn then
			local _al = split_csv(q.alpn)
			local _net = (q.type or q.network or "tcp"):lower()
			if _net == "ws" or _net == "websocket" then
				local _keep = {}
				for _i = 1, #_al do
					local _v = tostring(_al[_i]):lower()
					if _v == "http/1.1" or _v == "http/1.0" then table.insert(_keep, _v) end
				end
				if #_keep == 0 then _keep = { "http/1.1" } end
				_al = _keep
			end
			if #_al > 0 then
				tls.alpn = arr(_al)
				order_add(tls, "alpn")
			end
		end
	ob.tls = tls
	order_add(ob, "tls")

	local tr, terr = make_transport(q.type, q.host or "", q.path or "")
	if terr then return nil, terr end
	if tr then ob.transport = tr; order_add(ob, "transport") end
	return ob
end

local JSON_NODE_TYPES = {
	vless = true, vmess = true, trojan = true, shadowsocks = true,
	hysteria2 = true, tuic = true, direct = true,
}

local function parse_json_node(s)
	local j, jerr = json_decode(s:sub(6))
	if not j then return nil, "json 节点解析失败：" .. tostring(jerr) end
	if type(j) ~= "table" or is_array(j) then return nil, "json 节点必须是对象" end
	if j.type == nil then return nil, "json 节点缺少 type" end
	-- IP 稳定性红线：即使直贴 JSON 也不接受会漂移出口的负载均衡类出站
	local t = tostring(j.type)
	if t == "urltest" or t == "fallback" or t == "loadbalance" then
		return nil, "json 节点禁止使用 " .. t
	end
	if not JSON_NODE_TYPES[t] then
		return nil, ("json 节点不支持 type=%s，仅支持 vless/vmess/trojan/"
			.. "shadowsocks/hysteria2/tuic/direct"):format(t)
	end

	local function need(field)
		if j[field] == nil or tostring(j[field]) == "" then
			return ("json %s 缺少 %s"):format(t, field)
		end
	end

	local err
	if t ~= "direct" then
		err = need("server")
		if err then return nil, err end
		if not valid_port(j.server_port) then
			return nil, ("json %s 的 server_port 端口非法（1-65535）：%s"):format(
				t, tostring(j.server_port))
		end
	end

	if t == "vless" or t == "vmess" then
		err = need("uuid")
		if err then return nil, err end
		if not valid_uuid(tostring(j.uuid)) then
			return nil, ("json %s 的 uuid 格式非法：%s"):format(t, tostring(j.uuid))
		end
	elseif t == "trojan" or t == "hysteria2" then
		err = need("password")
		if err then return nil, err end
	elseif t == "shadowsocks" then
		err = need("method")
		if err then return nil, err end
		if not valid_ss_method(tostring(j.method)) then
			return nil, ("json shadowsocks 的 method 不支持：%s（可选 %s）"):format(
				tostring(j.method), ss_method_list())
		end
		err = need("password")
		if err then return nil, err end
	elseif t == "tuic" then
		err = need("uuid")
		if err then return nil, err end
		if not valid_uuid(tostring(j.uuid)) then
			return nil, ("json tuic 的 uuid 格式非法：%s"):format(tostring(j.uuid))
		end
		err = need("password")
		if err then return nil, err end
	end

	-- 适配 JSON 节点的 Xray 原生字段到内部 transport 结构
	if not j.transport and (j.network or j.wsSettings or j.grpcSettings or j.security) then
		-- 将 Xray 原生结构转为内部 transport 格式
		local net = j.network or "tcp"
		if net == "ws" then
			local ws_cfg = j.wsSettings or {}
			j.transport = {
				type = "ws",
				path = ws_cfg.path,
				headers = ws_cfg.headers
			}
		elseif net == "grpc" then
			local grpc_cfg = j.grpcSettings or {}
			j.transport = {
				type = "grpc",
				service_name = grpc_cfg.serviceName
			}
		end

		-- 处理 TLS/Reality
		if j.security == "tls" or j.security == "reality" then
			local tls_src = (j.security == "tls") and j.tlsSettings or j.realitySettings
			if tls_src then
				j.tls = {
					enabled = true,
					server_name = tls_src.serverName or j.server
				}
				if tls_src.fingerprint then
					j.tls.utls = { enabled = true, fingerprint = tls_src.fingerprint }
				end
				if tls_src.alpn then
					j.tls.alpn = tls_src.alpn
				end
				-- allowInsecure 已废弃，忽略
				if j.security == "reality" then
					j.tls.reality = {
						enabled = true,
						public_key = tls_src.publicKey or "",
						short_id = tls_src.shortId or "",
						spiderX = tls_src.spiderX
					}
				end
			end
		end
	end

	return j
end

-- percent 解码（只处理 %XX 与 +，够用且不引入依赖）
local function urldecode_soft(v)
	if not v then return v end
	v = tostring(v):gsub("%+", " ")
	return (v:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

-- socks5://user:pass@host:port?front=前置节点名#名字
-- 兼容四段写法 host:port:user:pass（老插件就是这个格式）
local function parse_socks(src)
	local s = trim(src)
	local front = nil
	-- 取 ?front=NAME（在 # 之前）
	local q = s:match("%?([^#]+)")
	if q then
		for kv in (q .. "&"):gmatch("([^&]*)&") do
			local k, v = kv:match("^([^=]+)=(.*)$")
			if k and k:lower() == "front" then front = trim(urldecode_soft(v)) end
		end
	end
	s = s:gsub("#.*$", ""):gsub("%?.*$", "")
	local body = s:gsub("^[Ss][Oo][Cc][Kk][Ss]5?://", "")
	if body == s then return nil, "不是 socks5 链接" end

	local auth, hostport = body:match("^(.+)@(.+)$")
	if not hostport then hostport = body end
	local host, port = hostport:match("^%[([^%]]+)%]:(%d+)$")
	if not host then host, port = hostport:match("^([^:]+):(%d+)$") end
	if not port then return nil, "socks5 缺少 host:port" end
	local user, pass = nil, nil
	if auth then
		user, pass = auth:match("^([^:]*):(.*)$")
		if user then user = urldecode_soft(user) end
		if pass then pass = urldecode_soft(pass) end
	end
	return {
		type = "socks",
		server = host,
		server_port = tonumber(port),
		username = user,
		password = pass,
		front = (front and front ~= "") and front or nil,
	}
end

local function parse_socks_four(src)
	-- host:port:user:pass（老格式，没有协议头）
	local h, p, u2, pw = trim(src):match("^([%w%.%-]+):(%d+):([^:]*):(.*)$")
	if not h or not p then return nil, "四段格式应为 host:port:用户名:密码" end
	return { type = "socks", server = h, server_port = tonumber(p),
		username = (u2 ~= "" and u2 or nil), password = (pw ~= "" and pw or nil) }
end

local PARSERS = {
	{ "socks5://", parse_socks },
	{ "socks://", parse_socks },
	{ "ss://", parse_ss },
	{ "vmess://", parse_vmess },
	{ "vless://", parse_vless },
	{ "trojan://", parse_trojan },
}

local function parse_node(src)
	local s = trim(src)
	if s:sub(1, 5) == "json:" then return parse_json_node(s) end
	for _, p in ipairs(PARSERS) do
		if s:sub(1, #p[1]) == p[1] then return p[2](s) end
	end
	return nil, "不认识的节点链接：" .. s:sub(1, 40)
end

local function slugify(ssid)
	local s = tostring(ssid or ""):gsub("[^A-Za-z0-9]+", ""):lower()
	if s == "" then
		return nil, "SSID 里没有可用的字母数字：" .. tostring(ssid)
	end
	return s
end

-- ---------------------------------------------------------------------------
-- 清单解析
-- ---------------------------------------------------------------------------

-- 最多切 4 段：SSID|频段|链接|启用(1/0)
-- 链接里不会出现 '|'，所以第 3 段之后再切一次就是启用位
local function split_max3(line)
	local p1 = line:find("|", 1, true)
	if not p1 then return nil end
	local p2 = line:find("|", p1 + 1, true)
	if not p2 then
		return { line:sub(1, p1 - 1), line:sub(p1 + 1) }
	end
	local f2 = line:sub(p1 + 1, p2 - 1)
	local rest = line:sub(p2 + 1)
	local p3 = rest:find("|", 1, true)
	if p3 then
		return { line:sub(1, p1 - 1), f2, rest:sub(1, p3 - 1), rest:sub(p3 + 1) }
	end
	return { line:sub(1, p1 - 1), f2, rest }
end

local function parse_nodes(text, _opts)
	if type(text) ~= "string" then return nil, "清单内容不是字符串" end
	local items = {}
	local ln = 0
	local node_pool = (_opts and _opts.node_pool) or {}

	for raw in (text .. "\n"):gmatch("([^\n]*)\n") do
		ln = ln + 1
		local line = trim(raw)
		if line ~= "" and line:sub(1, 1) ~= "#" then
			if not line:find("|", 1, true) then
				return nil, ("第 %d 行缺少 '|'：%s"):format(ln, line:sub(1, 60))
			end
			local parts = split_max3(line)
			local ssid, band, src, en
			local maybe_band = #parts >= 3 and parts[2]:lower()
			if maybe_band == "2g" or maybe_band == "5g" or maybe_band == "both" then
				ssid, band, src = trim(parts[1]), maybe_band, trim(parts[3])
				en = parts[4] and trim(parts[4]) or nil
			else
				ssid, src = trim(parts[1]), trim(parts[2])
				en = parts[3] and trim(parts[3]) or nil
			end
			-- 启用位：缺省=启用；"0"=禁用（禁用行不生成任何产物，但保留序号）
			local enabled = not (en == "0" or en == "false" or en == "off")

			-- SSID 按 UTF-8 字节数限制（不是码点）：WiFi 规范上限 32 字节
			if ssid:find("[\"']") or #ssid > 32 then
				return nil, ("第 %d 行 SSID 不合法（不能带引号，长度 <=32 字节）：%q"):format(ln, ssid)
			end

			-- BLK-11：禁用且未绑定的行跳过（不进入生成器）
			local should_process = true
			if not enabled and (src == nil or src == "") then
				-- 跳过此行，不增加序号，不生成任何配置
				should_process = false
			end

			if should_process then
				-- 启用中的线路必须有节点链接
				if enabled and (src == nil or src == "") then
					return nil, ("第 %d 行：启用中的线路必须绑定节点"):format(ln)
				end

				-- @节点名 引用解析
				local actual_src = src
				if src:sub(1, 1) == "@" then
					local node_name = trim(src:sub(2))
					if node_name == "" then
						return nil, ("第 %d 行引用格式错误：@后面必须跟节点名"):format(ln)
					end
					local found = false
					for _, n in ipairs(node_pool) do
						if n.name == node_name then
							actual_src = n.link
							found = true
							break
						end
					end
					if not found then
						return nil, ("第 %d 行引用的节点 %s 不存在"):format(ln, node_name)
					end
				end

				local ob, oerr = parse_node(actual_src)
				if not ob then
					return nil, ("第 %d 行 %s"):format(ln, tostring(oerr))
				end

				-- socks5 前置解析：?front=名字 必须能在节点池里找到，且前置不能又是 socks5
				-- （Xray 26 的 dialerProxy 只支持一层链式；静默直连等于出口泄漏，必须报错）
				if ob.type == "socks" and ob.front and ob.front ~= "" then
					local fname = ob.front
					local flink
					for _, n in ipairs(node_pool) do
						if n.name == fname then
							flink = n.link
							break
						end
					end
					if not flink then
						return nil, ("第 %d 行 socks5 的前置节点 %s 不存在"):format(ln, fname)
					end
					local fob, ferr = parse_node(flink)
					if not fob then
						return nil, ("第 %d 行 socks5 的前置节点 %s 链接无法解析：%s")
							:format(ln, fname, tostring(ferr))
					end
					if fob.type == "socks" then
						return nil, ("第 %d 行 socks5 的前置不能又是 socks5（只支持一层）"):format(ln)
					end
					ob._front_src = flink
					ob._front_name = fname
				end

				local slug, serr = slugify(ssid)
				if not slug then
					return nil, ("第 %d 行 %s"):format(ln, tostring(serr))
				end

				ob._ssid = ssid
				ob._band = band
				ob._slug = slug
				ob._enabled = enabled
				items[#items + 1] = ob
			end
		end
	end

	-- BLK-11：禁用且未绑定行跳过后，若 items 为空是合法的空生成结果，不是错误
	if #items == 0 then
		return {}
	end

	local seen, dup = {}, {}
	for _, it in ipairs(items) do
		local s = it._slug
		if seen[s] then
			dup[#dup + 1] = s
		else
			seen[s] = true
		end
	end
	if #dup > 0 then
		return nil, "SSID 生成的 slug 重复：" .. table.concat(dup, ", ")
	end
	return items
end

-- ---------------------------------------------------------------------------
-- 生成器（Xray 配置输出）
-- ---------------------------------------------------------------------------

-- 从输入 item 构建 Xray streamSettings
local function build_xray_stream(item)
	local stream = ordered({}, {})
	local transport = item.transport

	-- 处理 JSON 节点的 network 字段（Xray 原生）
	local net_type = nil
	if transport then
		net_type = transport.type
	elseif item.network then
		net_type = item.network
	end

	if net_type == "ws" then
		stream.network = "ws"
		order_add(stream, "network")
		local ws = ordered({}, {})
		-- 从 transport 或 wsSettings 读取
		local ws_src = item.wsSettings or transport or {}
		local path_val = nz(ws_src.path) or "/"
		ws.path = path_val
		order_add(ws, "path")
		-- Host 优先级：链接 host 参数 → tls.server_name → server
		local host_val = nz(ws_src.headers and ws_src.headers.Host) or nz(item.tls and item.tls.server_name) or nz(item.server)
		if host_val then
			ws.headers = ordered({ Host = host_val }, { "Host" })
			order_add(ws, "headers")
		end
		stream.wsSettings = ws
		order_add(stream, "wsSettings")
	elseif net_type == "grpc" then
		stream.network = "grpc"
		order_add(stream, "network")
		local grpc = ordered({}, {})
		local grpc_src = item.grpcSettings or transport or {}
		if grpc_src.serviceName then
			grpc.serviceName = grpc_src.serviceName
			order_add(grpc, "serviceName")
		elseif grpc_src.service_name then
			grpc.serviceName = grpc_src.service_name
			order_add(grpc, "serviceName")
		end
		stream.grpcSettings = grpc
		order_add(stream, "grpcSettings")
	elseif net_type == "http" then
		stream.network = "http"
		order_add(stream, "network")
		local http = ordered({}, {})
		local http_src = item.httpSettings or transport or {}
		if http_src.host then http.host = http_src.host; order_add(http, "host") end
		if http_src.path then http.path = http_src.path; order_add(http, "path") end
		stream.httpSettings = http
		order_add(stream, "httpSettings")
	else
		-- tcp 或未知
		stream.network = "tcp"
		order_add(stream, "network")
	end

	-- TLS/Reality 处理
	if item.tls and item.tls.enabled then
		local tls_cfg = ordered({}, {})
		local sni = item.tls.server_name

		if item.tls.reality and item.tls.reality.enabled then
			stream.security = "reality"
			order_add(stream, "security")
			tls_cfg.serverName = sni
			order_add(tls_cfg, "serverName")
			if item.tls.utls and item.tls.utls.fingerprint then
				tls_cfg.fingerprint = item.tls.utls.fingerprint
				order_add(tls_cfg, "fingerprint")
			end
			tls_cfg.publicKey = item.tls.reality.public_key
			order_add(tls_cfg, "publicKey")
			tls_cfg.shortId = item.tls.reality.short_id or ""
			order_add(tls_cfg, "shortId")
			if item.tls.reality.spiderX and item.tls.reality.spiderX ~= "" then
				tls_cfg.spiderX = item.tls.reality.spiderX
				order_add(tls_cfg, "spiderX")
			end
			stream.realitySettings = tls_cfg
			order_add(stream, "realitySettings")
		else
			stream.security = "tls"
			order_add(stream, "security")
			tls_cfg.serverName = sni
			order_add(tls_cfg, "serverName")
			if item.tls.utls and item.tls.utls.fingerprint then
				tls_cfg.fingerprint = item.tls.utls.fingerprint
				order_add(tls_cfg, "fingerprint")
			end
			-- ALPN 处理：ws 始终输出 ["http/1.1"]，其它传输保持原链接列表
			if stream.network == "ws" then
				tls_cfg.alpn = arr({ "http/1.1" })
				order_add(tls_cfg, "alpn")
			elseif item.tls.alpn then
				tls_cfg.alpn = item.tls.alpn
				order_add(tls_cfg, "alpn")
			end
			-- 不再输出 allowInsecure（Xray 26 已移除该字段，输出会导致校验失败）
			stream.tlsSettings = tls_cfg
			order_add(stream, "tlsSettings")
		end
	end

	return stream
end

-- 构建 Xray outbound
local function build_xray_outbound(item, slug)
	local protocol = item.type
	local ob = ordered({}, {})

	if protocol == "vless" then
		ob.protocol = "vless"
		ob.tag = slug .. "-out"
		order_add(ob, "protocol")
		order_add(ob, "tag")

		local user = ordered({ id = item.uuid, encryption = "none" }, { "id", "encryption" })
		if item.flow then
			user.flow = item.flow
			order_add(user, "flow")
		end

		ob.settings = ordered({
			vnext = arr({
				ordered({
					address = item.server,
					port = item.server_port,
					users = arr({ user })
				}, { "address", "port", "users" })
			})
		}, { "vnext" })
		order_add(ob, "settings")

		ob.streamSettings = build_xray_stream(item)
		-- 添加 sockopt.domainStrategy 以确保域名在落地侧解析
		if not ob.streamSettings.sockopt then
			ob.streamSettings.sockopt = ordered({}, {})
		end
		ob.streamSettings.sockopt.domainStrategy = "UseIP"
		order_add(ob.streamSettings.sockopt, "domainStrategy")
		order_add(ob.streamSettings, "sockopt")
		order_add(ob, "streamSettings")

	elseif protocol == "vmess" then
		ob.protocol = "vmess"
		ob.tag = slug .. "-out"
		order_add(ob, "protocol")
		order_add(ob, "tag")

		local user = ordered({
			id = item.uuid,
			alterId = item.alter_id or 0,
			security = item.security or "auto"
		}, { "id", "alterId", "security" })

		ob.settings = ordered({
			vnext = arr({
				ordered({
					address = item.server,
					port = item.server_port,
					users = arr({ user })
				}, { "address", "port", "users" })
			})
		}, { "vnext" })
		order_add(ob, "settings")

		ob.streamSettings = build_xray_stream(item)
		-- 添加 sockopt.domainStrategy 以确保域名在落地侧解析
		if not ob.streamSettings.sockopt then
			ob.streamSettings.sockopt = ordered({}, {})
		end
		ob.streamSettings.sockopt.domainStrategy = "UseIP"
		order_add(ob.streamSettings.sockopt, "domainStrategy")
		order_add(ob.streamSettings, "sockopt")
		order_add(ob, "streamSettings")

	elseif protocol == "trojan" then
		ob.protocol = "trojan"
		ob.tag = slug .. "-out"
		order_add(ob, "protocol")
		order_add(ob, "tag")

		ob.settings = ordered({
			servers = arr({
				ordered({
					address = item.server,
					port = item.server_port,
					password = item.password
				}, { "address", "port", "password" })
			})
		}, { "servers" })
		order_add(ob, "settings")

		ob.streamSettings = build_xray_stream(item)
		-- 添加 sockopt.domainStrategy 以确保域名在落地侧解析
		if not ob.streamSettings.sockopt then
			ob.streamSettings.sockopt = ordered({}, {})
		end
		ob.streamSettings.sockopt.domainStrategy = "UseIP"
		order_add(ob.streamSettings.sockopt, "domainStrategy")
		order_add(ob.streamSettings, "sockopt")
		order_add(ob, "streamSettings")

	elseif protocol == "shadowsocks" then
		ob.protocol = "shadowsocks"
		ob.tag = slug .. "-out"
		order_add(ob, "protocol")
		order_add(ob, "tag")

		ob.settings = ordered({
			servers = arr({
				ordered({
					address = item.server,
					port = item.server_port,
					method = item.method,
					password = item.password
				}, { "address", "port", "method", "password" })
			})
		}, { "servers" })
		order_add(ob, "settings")

		ob.streamSettings = ordered({}, {})
		-- 添加 sockopt.domainStrategy 以确保域名在落地侧解析
		ob.streamSettings.sockopt = ordered({}, {})
		ob.streamSettings.sockopt.domainStrategy = "UseIP"
		order_add(ob.streamSettings.sockopt, "domainStrategy")
		order_add(ob.streamSettings, "sockopt")
		order_add(ob, "streamSettings")

	elseif protocol == "socks" then
		-- socks5 落地节点（可带前置：由 build() 挂 dialerProxy，这里只描述落地本身）
		ob.protocol = "socks"
		ob.tag = slug .. "-out"
		order_add(ob, "protocol")
		order_add(ob, "tag")

		local srv = ordered({
			address = item.server,
			port = item.server_port,
		}, { "address", "port" })
		if item.username and item.username ~= "" then
			srv.users = arr({ ordered({
				user = item.username,
				pass = item.password or "",
			}, { "user", "pass" }) })
			order_add(srv, "users")
		end
		ob.settings = ordered({ servers = arr({ srv }) }, { "servers" })
		order_add(ob, "settings")

	else
		return nil, "不支持的协议类型：" .. tostring(protocol)
	end

	return ob
end

local function build(items, opts)
	opts = opts or {}
	local base = opts.subnet or "10.11"
	local bands = opts.bands or "both"
	local port_base = tonumber(opts.port_base) or 21000

	-- 主 LAN：优先调用方传入；否则探测本机直连 /24；探测失败才回退
	local lans, lan_source
	if opts.lan ~= nil and opts.lan ~= "" then
		local bad
		lans, bad = normalize_lans(opts.lan)
		if bad then return nil, "lan 不是合法 CIDR：" .. tostring(bad) end
		if #lans == 0 then return nil, "lan 不能为空" end
		lan_source = "opts"
	else
		lans, lan_source = detect_lan(opts.ip_addr_output)
	end

	if not parse_cidr(base .. ".0.0/16") then
		return nil, "subnet 非法：" .. tostring(base)
	end

	-- 网段冲突：10.11.N.0/24 不能与已用网段或主 LAN 重叠
	local used, used_bad = normalize_lans(opts.used_subnets)
	if used_bad then
		return nil, "used_subnets 里有非法 CIDR：" .. tostring(used_bad)
	end
	for idx = 1, #items do
		local cidr = base .. "." .. idx .. ".0/24"
		for _, u in ipairs(used) do
			if cidr_overlap(cidr, u) then
				return nil, ("网段冲突：%s 与已占用网段 %s 重叠"):format(cidr, u)
			end
		end
		for _, l in ipairs(lans) do
			if cidr_overlap(cidr, l) then
				return nil, ("网段冲突：%s 与主网段 %s 重叠"):format(cidr, l)
			end
		end
	end

	local excl, seen = {}, {}
	local excl_all = { base .. ".0.0/16" }
	for _, l in ipairs(lans) do excl_all[#excl_all + 1] = l end
	for _, c in ipairs({
		"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
		"255.255.255.255", "0.0.0.0/8",
	}) do
		excl_all[#excl_all + 1] = c
	end
	for _, c in ipairs(excl_all) do
		if not seen[c] then
			seen[c] = true
			excl[#excl + 1] = c
		end
	end

	local inbounds, outbounds, rules, plan = {}, {}, {}, {}
	-- 前置出站：按前置节点名去重（多条线路共用同一前置时只生成一份），
	-- 循环结束后追加到 outbounds 末尾 —— 落地出站必须在前、前置在后，
	-- 顺序反了流量会从前置节点直接出去（真机实测踩过）。
	local fronts, front_outbounds = {}, {}

	-- 只生成启用的线路；idx 仍按清单顺序，禁用后再启用网段/端口不变
	local active = {}
	for idx, it in ipairs(items) do
		if it._enabled ~= false then
			active[#active + 1] = { idx = idx, it = it }
		end
	end

	for _, pair in ipairs(active) do
		local idx, it = pair.idx, pair.it
		local slug = it._slug
		local ssid = it._ssid
		-- Linux 接口名上限 15 字节：统一用 brtk+序号，绝不用 SSID/slug
		local br = "brtk" .. idx
		if #br > 15 then return nil, "网桥名超过 15 字节：" .. br end
		local gw = base .. "." .. idx .. ".1"
		local dns_gw = gw  -- DNS 监听该线路网关地址（匹配 nft redirect 目标）
		local probe_listen = "127" .. ".0.0.1"  -- probe 仅本机访问
		local cidr = base .. "." .. idx .. ".0/24"
		local port = port_base + idx
		local probe_port = 22000 + idx

		local out, order = build_xray_outbound(it, slug)
		if not out then return nil, order end

		-- socks5 带前置：给该线路出站挂 streamSettings.sockopt.dialerProxy = front-<slug>
		-- dialerProxy 必须合并进已有 sockopt（domainStrategy=UseIP 不能被覆盖）
		if it._front_src and it._front_name then
			local tag = fronts[it._front_name]
			if not tag then
				local fob, ferr = parse_node(it._front_src)
				if not fob then
					return nil, ("前置节点出站构建失败：%s（%s）")
						:format(it._front_name, tostring(ferr))
				end
				local fslug, fslug_err = slugify(it._front_name)
				if not fslug then
					return nil, ("前置节点出站构建失败：%s（%s）")
						:format(it._front_name, tostring(fslug_err))
				end
				local fout, fberr = build_xray_outbound(fob, "front-" .. fslug)
				if not fout then
					return nil, ("前置节点出站构建失败：%s（%s）")
						:format(it._front_name, tostring(fberr))
				end
				-- build_xray_outbound 的 tag 固定为 <slug>.."-out"，统一改成本卡约定的 front-<slug>
				fout.tag = "front-" .. fslug
				tag = fout.tag
				fronts[it._front_name] = tag
				front_outbounds[#front_outbounds + 1] = fout
			end
			if not out.streamSettings then
				out.streamSettings = ordered({}, {})
			end
			if not out.streamSettings.sockopt then
				out.streamSettings.sockopt = ordered({}, {})
			end
			out.streamSettings.sockopt.dialerProxy = tag
			order_add(out.streamSettings.sockopt, "dialerProxy")
			order_add(out.streamSettings, "sockopt")
			order_add(out, "streamSettings")
		end

		-- Xray dokodemo-door 入站（tproxy 模式 + sniffing）
		inbounds[#inbounds + 1] = ordered({
			protocol = "dokodemo-door",
			tag = slug .. "-in",
			listen = "0.0.0.0",
			port = port,
			settings = ordered({
				network = "tcp,udp",
				followRedirect = true
			}, { "network", "followRedirect" }),
			sniffing = ordered({
				enabled = true,
				destOverride = arr({ "http", "tls", "quic" })
			}, { "enabled", "destOverride" }),
			streamSettings = ordered({
				sockopt = ordered({
					tproxy = "tproxy"
				}, { "tproxy" })
			}, { "sockopt" })
		}, { "protocol", "tag", "listen", "port", "settings", "sniffing", "streamSettings" })
		-- probe socks 入站（用于体检，只监听本机）
		inbounds[#inbounds + 1] = ordered({
			protocol = "socks",
			tag = slug .. "-probe",
			listen = probe_listen,
			port = probe_port,
			settings = ordered({
				udp = true
			}, { "udp" })
		}, { "protocol", "tag", "listen", "port", "settings" })
		outbounds[#outbounds + 1] = out
		-- Xray 路由规则：tproxy 和 probe 入站 -> 出站
		rules[#rules + 1] = ordered({
			type = "field",
			inboundTag = arr({ slug .. "-in", slug .. "-probe" }),
			outboundTag = slug .. "-out"
		}, { "type", "inboundTag", "outboundTag" })
		plan[#plan + 1] = ordered({
			index = idx,
			ssid = ssid,
			slug = slug,
			br = br,
			subnet = cidr,
			gateway = gw,
			port = port,
			band = it._band or bands,
			enabled = (it._enabled ~= false),
			outbound = slug .. "-out",
			bssid = mac_for(slug),
			bssid_5g = mac_for(slug .. "5"),
			bssid_2g = mac_for(slug .. "2"),
			node_type = it.type or JSON_NULL,
			node_server = it.server or JSON_NULL,
			node_port = it.server_port or JSON_NULL,
		}, {
			"index", "ssid", "slug", "br", "subnet", "gateway", "port", "band",
			"outbound", "bssid", "bssid_5g", "bssid_2g", "node_type", "node_server", "node_port",
		})
	end

	-- 前置出站追加到末尾：Xray 按顺序解析出站，落地必须先于前置出现，
	-- 否则流量会从前置节点直接出去（不走落地）
	for _, fout in ipairs(front_outbounds) do
		outbounds[#outbounds + 1] = fout
	end

	-- Xray 配置结构
	local cfg = ordered({
		log = ordered({ loglevel = "warning" }, { "loglevel" }),
		inbounds = arr(inbounds),
		outbounds = arr(outbounds),
		routing = ordered({
			rules = arr(rules)
		}, { "rules" })
	}, { "log", "inbounds", "outbounds", "routing" })

	return cfg, plan, excl, { lans = lans, lan_source = lan_source }
end

-- ---------------------------------------------------------------------------
-- nftables（与 gen.py nft_text() 逐行一致）
-- ---------------------------------------------------------------------------

local function nft_text(plan, excl)
	local L = {
		"#!/usr/sbin/nft -f",
		"# 由 gen.py 生成：按源网桥把 TCP+UDP 全部 tproxy 到各自端口。",
		"# 加载前必须有：ip rule add fwmark 0x8000 lookup 51820",
		"#               ip route add local 0.0.0.0/0 dev lo table 51820",
		"table inet tkproxy {",
		"\tchain prerouting {",
		"\t\ttype filter hook prerouting priority mangle; policy accept;",
	}
	for _, p in ipairs(plan) do
		local br, port = p.br, p.port
		L[#L + 1] = ""
		L[#L + 1] = ("\t\t# %s  ->  127.0.0.1:%d  (%s)"):format(p.ssid, port, br)
		L[#L + 1] = ('\t\tiifname "%s" ip6 daddr != { fe80::/10 } drop'):format(br)
		L[#L + 1] = ('		iifname "%s" ip daddr { %s } return'):format(br, table.concat(excl, ", "))
		-- 放行发往「本线路网关」的 ICMP echo：部分 App/系统用 ping 网关判断"有没有网络"，
		-- 全丢会被误判成断网。仅放行到网关这一跳（本地投递、不出机），
		-- 其它 echo / timestamp 仍然丢弃：ICMP 无法经 tproxy 代理，放出去等于本地宽带直连泄漏。
		if p.gateway and p.gateway ~= "" then
			L[#L + 1] = ('		iifname "%s" meta nfproto ipv4 ip daddr %s icmp type echo-request accept'):format(br, p.gateway)
		end
		L[#L + 1] = ('		iifname "%s" meta nfproto ipv4 icmp type { echo-request, timestamp-request } drop'):format(br)
		-- 上面放行了 fe80::/10，这里必须显式限定 IPv4，避免 IPv6 链路本地被 tproxy
		L[#L + 1] = ('\t\tiifname "%s" meta nfproto ipv4 meta l4proto { tcp, udp } tproxy ip to :%d meta mark set 0x8000 accept'):format(br, port)
	end
	L[#L + 1] = "\t}"
	L[#L + 1] = "}"
	L[#L + 1] = ""
	return table.concat(L, "\n")
end

local function manifest(plan, opts, meta)
	opts = opts or {}
	meta = meta or {}
	local lans, lan_source = meta.lans, meta.lan_source
	if not lans then
		-- 直接调用 M.manifest 时没有 build 的探测结果：按同样的优先级补上
		if opts.lan ~= nil and opts.lan ~= "" then
			lans, lan_source = normalize_lans(opts.lan), "opts"
		else
			lans, lan_source = { "192.168.8.0/24" }, "fallback"
		end
	end
	return ordered({
		subnet = opts.subnet or "10.11",
		lan = table.concat(lans, ","),
		lan_source = lan_source,
		bands = opts.bands or "both",
		ssids = arr(plan),
	}, { "subnet", "lan", "lan_source", "bands", "ssids" })
end

-- ---------------------------------------------------------------------------
-- 对外 API
-- ---------------------------------------------------------------------------

-- 清单文本 -> { config=JSON, nft=文本, manifest=JSON, cfg=表, plan=表,
--               lans=实际排除的 LAN, lan_source="opts"|"detected"|"fallback" }
--           | nil, 错误
function M.render(text, opts)
	local items, perr = parse_nodes(text, opts)
	if not items then return nil, perr end
	local cfg, plan, excl, meta = build(items, opts)
	if not cfg then return nil, plan end
	return {
		config = json_encode(cfg) .. "\n",
		nft = nft_text(plan, excl),
		manifest = json_encode(manifest(plan, opts, meta)) .. "\n",
		cfg = cfg,
		plan = plan,
		lans = meta.lans,
		lan_source = meta.lan_source,
	}
end

M.parse_nodes = parse_nodes
M.parse_node = parse_node
M.build_xray_outbound = build_xray_outbound

-- 单节点体检用：解析落地 socks5 链接及其前置链接，返回 (landing_ob, front_ob_or_nil)
-- 前置出站由调用方放在 outbounds 后面（落地在前），并自己挂 dialerProxy
function M.outbound_with_front(link, front_link)
	local ob, err = parse_node(link)
	if not ob then return nil, err end
	if not front_link or front_link == "" then
		return ob, nil
	end
	local fob, ferr = parse_node(front_link)
	if not fob then
		return nil, "前置节点链接无法解析：" .. tostring(ferr)
	end
	if fob.type == "socks" then
		return nil, "前置不能又是 socks5（只支持一层）"
	end
	return ob, fob
end

M.detect_lan = detect_lan
M.slugify = slugify
M.build = build
M.nft_text = nft_text
M.manifest = manifest
M.json_encode = json_encode
M.json_decode = json_decode
M.mac_for = mac_for
M.sha256 = sha256

return M
