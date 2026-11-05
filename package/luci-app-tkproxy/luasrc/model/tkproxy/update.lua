-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 云端更新（签名校验在 update.sh 里做，这里只做封装）

local sys = require "luci.sys"
local jsonc = require "luci.jsonc"

local M = {}

M.SCRIPT = "/usr/libexec/tkproxy/update.sh"

local function run(arg)
	local out = sys.exec("sh " .. M.SCRIPT .. " " .. (arg or "") .. " 2>&1") or ""
	local o = jsonc.parse(out or "")
	if type(o) ~= "table" then
		-- 输出不是 JSON：说明脚本异常（多半是缺依赖），把原文带回去便于排查
		return { ok = false, msg = (out ~= "" and out:sub(1, 200) or "update.sh 无输出") }
	end
	return o
end

function M.check()
	return run("check")
end

function M.install()
	return run("install")
end

function M.current()
	local o = run("version")
	return (type(o) == "table" and o.current) or ""
end

-- 读写更新源（uci tkproxy.main.update_url）
function M.get_url()
	local uci = require "luci.model.uci".cursor()
	return tostring(uci:get("tkproxy", "main", "update_url") or "")
end

function M.set_url(url)
	url = (url or ""):gsub("^%s+", ""):gsub("%s+$", "")
	if url == "" then
		local uci = require "luci.model.uci".cursor()
		uci:delete("tkproxy", "main", "update_url")
		uci:commit("tkproxy")
		return true, "已清空更新源"
	end
	-- 只接受 https；本机自测允许 http://127.0.0.1、http://localhost
	local ok = url:match("^https://[%w%-%._~:/%?#%[%]@!%$&'%(%)%*%+,;=]+$")
		or url:match("^http://127%.0%.0%.1[:/]")
		or url:match("^http://localhost[:/]")
	if not ok then
		return nil, "更新源必须是 https:// 开头（本机测试可用 http://127.0.0.1）"
	end
	if not url:match("%.json$") then
		url = url:gsub("/+$", "") .. "/manifest.json"
	end
	local uci = require "luci.model.uci".cursor()
	uci:set("tkproxy", "main", "update_url", url)
	uci:commit("tkproxy")
	return true, "已保存更新源"
end

return M
