-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 卡密门禁（Lua 封装，逻辑与接口对齐老插件 ssidproxy）

local sys = require "luci.sys"
local jsonc = require "luci.jsonc"

local M = {}

M.SCRIPT = "/usr/libexec/tkproxy/license.sh"

local function run(args)
	local cmd = "sh " .. M.SCRIPT .. " " .. (args or "")
	local out = sys.exec(cmd .. " 2>&1") or ""
	return out
end

-- 状态：{activated, machine, card_mask, expires_at, days_left, expired, reason, legacy, ...}
function M.status()
	local out = run("status")
	local o = jsonc.parse(out or "")
	if type(o) ~= "table" then
		return {
			activated = false, machine = "", card_mask = "", expires_at = 0,
			days_left = 0, expired = false, reason = "not_activated", legacy = false,
			error = (out ~= "" and out:sub(1, 120) or "license.sh 无输出"),
		}
	end
	return o
end

local function one_line(out)
	out = (out or ""):gsub("\r", "")
	local err = out:match("ERR%s*(.*)")
	if err then return nil, (err ~= "" and err or "失败") end
	local ok = out:match("OK%s*(.*)")
	if ok then return true, ok end
	return nil, out ~= "" and out:sub(1, 160) or "无响应"
end

-- 激活：返回 (ok, msg)
function M.activate(card)
	card = (card or ""):gsub("^%s+", ""):gsub("%s+$", "")
	if card == "" then return nil, "请输入卡密" end
	-- 只允许字母数字与常见分隔符，避免把怪字符带进命令
	if not card:match("^[%w%-_%.]+$") then
		return nil, "卡密格式不正确（只允许字母、数字、- _ .）"
	end
	return one_line(run("activate " .. card))
end

function M.verify()
	return one_line(run("verify"))
end

function M.reset()
	return one_line(run("reset"))
end

function M.machine()
	local out = run("machine") or ""
	return (out:gsub("%s+$", ""))
end

-- 门禁：未激活/验签不过/过期返回 false
-- 判定与 license.sh 的 lic_judge 是同一份（status JSON 带 reason 字段），
-- 这里只做 reason → 人话的映射，不再有本地逃生开关：
-- 任何绕过都必须先过 usign 验签那一关。
local REASON_TEXT = {
	not_activated  = "本机尚未激活卡密",
	sig_invalid    = "授权文件被修改过，请重新输入卡密",
	foreign_device = "这张授权票据不属于本机，请重新输入卡密",
	expired        = "卡密已过期，请续费后重新激活",
	bad_expiry     = "授权文件被修改过，请重新输入卡密",
	legacy_expired = "授权需要升级：请联网一次完成票据更新",
	usign_missing  = "本机缺少验签工具，请重新安装插件",
}

function M.licensed()
	local st = M.status()
	if st.activated ~= true then
		local why = REASON_TEXT[st.reason]
		if not why then
			why = "授权校验异常（" .. tostring(st.reason or "unknown") .. "），请重新激活"
		end
		return false, why
	end
	return true
end

-- 给写操作用的统一拦截：返回 (ok, err)
function M.gate()
	local ok, why = M.licensed()
	if ok then return true end
	return false, (why or "未授权") .. "（在「概览 → 授权」里激活）"
end

return M
