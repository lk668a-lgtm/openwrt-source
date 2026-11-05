-- canonical JSON 规范化器（与 kamism 服务端 serde_json 输出逐字节一致）
--
-- 服务端签名原文的生成规则（src-tauri/src/utils/license.rs:132-154）：
--   1. 对象键按字典序重排（BTreeMap），递归
--   2. 数组保持原序
--   3. 紧凑输出，无空格、无换行
--   4. 非 ASCII 原样输出 UTF-8 字节（serde_json 默认不转义中文）
--
-- 客户端必须一字不差地重建这段字节，否则 Ed25519 验签必然失败。
-- ucode 的 sprintf("%J") 会输出 `{ "a": 1 }`（带空格），不能用；
-- 所以这里自带一个最小解析器 + 序列化器，只依赖 lua 5.1 标准库。
--
-- 用法：
--   lua canon.lua < input.json        # 输出规范字节到 stdout
--   lua canon.lua < input.json -c     # 顺便报告用的摘要（调试）

local src = io.read("*a")
if not src or src == "" then
	io.stderr:write("canon.lua: 输入为空\n")
	os.exit(2)
end

-- ---------------------------------------------------------------------------
-- 解析
-- ---------------------------------------------------------------------------
local pos = 1
local function err(msg)
	io.stderr:write("canon.lua: " .. msg .. " (位置 " .. pos .. ")\n")
	os.exit(3)
end

local function skip_ws()
	while true do
		local c = src:sub(pos, pos)
		if c == " " or c == "\t" or c == "\n" or c == "\r" then
			pos = pos + 1
		else
			break
		end
	end
end

local parse_value

local function parse_string()
	-- 前导 " 已由调用方检查
	pos = pos + 1
	local buf = {}
	while true do
		local c = src:sub(pos, pos)
		if c == "" then err("字符串未闭合") end
		if c == '"' then
			pos = pos + 1
			break
		elseif c == "\\" then
			local e = src:sub(pos + 1, pos + 1)
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
				local hex = src:sub(pos, pos + 3)
				if not hex:match("^%x%x%x%x$") then err("\\u 转义非法") end
				pos = pos + 4
				local cp = tonumber(hex, 16)
				-- 代理对（U+D800..U+DFFF）要合成真实码点
				if cp >= 0xD800 and cp <= 0xDBFF then
					if src:sub(pos, pos + 1) == "\\u" then
						local hex2 = src:sub(pos + 2, pos + 5)
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
				err("未知转义 \\" .. e)
			end
		else
			buf[#buf + 1] = c
			pos = pos + 1
		end
	end
	return table.concat(buf)
end

-- 码点 → UTF-8 字节（lua 5.1 没有 utf8 库）
function utf8_char(cp)
	if cp < 0x80 then
		return string.char(cp)
	elseif cp < 0x800 then
		return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
	elseif cp < 0x10000 then
		return string.char(
			0xE0 + math.floor(cp / 0x1000),
			0x80 + math.floor(cp / 0x40) % 0x40,
			0x80 + cp % 0x40)
	else
		return string.char(
			0xF0 + math.floor(cp / 0x40000),
			0x80 + math.floor(cp / 0x1000) % 0x40,
			0x80 + math.floor(cp / 0x40) % 0x40,
			0x80 + cp % 0x40)
	end
end

local function parse_number()
	local s = src:sub(pos):match("^-?%d+%.?%d*[eE]?[-+]?%d*")
	if not s or s == "" then err("数字非法") end
	pos = pos + #s
	-- 服务端字段都是 i64，这里统一按整数输出；
	-- 带小数点/指数的字段在 entitlement 里不会出现
	return tonumber(s), s
end

local function parse_array()
	pos = pos + 1
	local arr = {}
	skip_ws()
	if src:sub(pos, pos) == "]" then pos = pos + 1; return arr end
	while true do
		arr[#arr + 1] = parse_value()
		skip_ws()
		local c = src:sub(pos, pos)
		if c == "," then pos = pos + 1; skip_ws()
		elseif c == "]" then pos = pos + 1; break
		else err("数组语法错误") end
	end
	return arr
end

local function parse_object()
	pos = pos + 1
	local obj = { [0] = {} }   -- [0] 存放键集合（lua 5.1 无法有序遍历）
	skip_ws()
	if src:sub(pos, pos) == "}" then pos = pos + 1; return obj end
	while true do
		skip_ws()
		if src:sub(pos, pos) ~= '"' then err("对象键必须是字符串") end
		local k = parse_string()
		skip_ws()
		if src:sub(pos, pos) ~= ":" then err("缺少冒号") end
		pos = pos + 1
		obj[k] = parse_value()
		obj[0][#obj[0] + 1] = k
		skip_ws()
		local c = src:sub(pos, pos)
		if c == "," then pos = pos + 1
		elseif c == "}" then pos = pos + 1; break
		else err("对象语法错误") end
	end
	return obj
end

function parse_value()
	skip_ws()
	local c = src:sub(pos, pos)
	if c == "{" then return parse_object() end
	if c == "[" then return parse_array() end
	if c == '"' then return parse_string() end
	if src:sub(pos, pos + 3) == "true" then pos = pos + 4; return true end
	if src:sub(pos, pos + 4) == "false" then pos = pos + 5; return false end
	if src:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil end
	return parse_number()
end

local root = parse_value()

-- ---------------------------------------------------------------------------
-- 序列化（键按字典序、紧凑、UTF-8 保真）
-- ---------------------------------------------------------------------------
local function esc(s)
	-- 必须与 serde_json 的字符串转义一致
	s = s:gsub('[%z\1-\31\\"]', function(c)
		if c == '"' then return '\\"'
		elseif c == "\\" then return "\\\\"
		elseif c == "\b" then return "\\b"
		elseif c == "\f" then return "\\f"
		elseif c == "\n" then return "\\n"
		elseif c == "\r" then return "\\r"
		elseif c == "\t" then return "\\t"
		else return string.format("\\u%04x", c:byte()) end
	end)
	return '"' .. s .. '"'
end

local function num(v)
	-- 整数原样输出；serde_json 对 i64 输出不带小数点。
	-- 注意 lua 5.1 的 %d 只吃 32 位 int，而卡密到期时间戳可能是
	-- 4387302673（2109 年）这种超出 int32 的值 —— 用 %d 会直接报错，
	-- 所以大数走 %.0f（double 精确到 2^53，足够表示 i64 时间戳）。
	if v == math.floor(v) then
		if v >= -2147483648 and v <= 2147483647 then
			return string.format("%d", v)
		end
		return string.format("%.0f", v)
	end
	return tostring(v)
end

local emit

emit = function(v)
	local t = type(v)
	if t == "string" then
		return esc(v)
	elseif t == "number" then
		return num(v)
	elseif t == "boolean" then
		return v and "true" or "false"
	elseif t == "table" then
		if v[0] then
			-- 对象：键排序
			local ks = {}
			for i, k in ipairs(v[0]) do ks[i] = k end
			table.sort(ks)
			local out = {}
			for _, k in ipairs(ks) do
				out[#out + 1] = esc(k) .. ":" .. emit(v[k])
			end
			return "{" .. table.concat(out, ",") .. "}"
		else
			-- 数组
			local out = {}
			for i = 1, #v do out[i] = emit(v[i]) end
			return "[" .. table.concat(out, ",") .. "]"
		end
	elseif t == "nil" then
		return "null"
	end
	error("无法序列化类型 " .. t)
end

io.write(emit(root))
