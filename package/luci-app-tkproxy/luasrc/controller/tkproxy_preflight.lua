-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 预检控制器

module("luci.controller.tkproxy_preflight", package.seeall)

local jsonc = require "luci.jsonc"
local http = require "luci.http"
local preflight = require "luci.model.tkproxy.preflight"

function index()
	-- 预检页已并入「概览 → 插件可用性自检」，这里只保留 POST 端点
	entry({"admin", "services", "tkproxy", "preflight"}, call("action_preflight")).leaf = true
	entry({"admin", "services", "tkproxy", "preflight_op"}, post("action_op")).leaf = true
end

function action_preflight()
	-- 页面已下线（功能在概览卡片里）
	http.redirect(require("luci.dispatcher").build_url("admin/services/tkproxy/dashboard"))
end

function action_op()
	-- 授权门禁：与主控制器一致，未激活不允许跑预检/修复
	local licensed = true
	local okreq, lic = pcall(require, "luci.model.tkproxy.license")
	if okreq and lic then
		licensed = lic.licensed() and true or false
	end
	if not licensed then
		http.prepare_content("application/json")
		http.write_json({ success = false, error = "本机尚未激活卡密", need_license = true })
		return
	end

	local req = http.formvalue()
	local cmd = req.cmd or ""

	if cmd == "preflight_run" then
		local result, err = preflight.run()
		if not result then
			http.prepare_content("application/json")
			http.write_json({ success = false, error = err })
			return
		end
		http.prepare_content("application/json")
		http.write_json({ success = true, data = result })

	elseif cmd == "preflight_fix" and (req.actions or "") ~= "" then
		-- 统一修复入口（opkg:/svc:/trim/clean 动作串）
		local results = preflight.fix_actions(req.actions or "")
		http.prepare_content("application/json")
		http.write_json({ success = true, results = results })
		return

	elseif cmd == "preflight_fix" then
		local pkgs_str = req.pkgs or ""
		local pkgs = {}
		for pkg in pkgs_str:gmatch("[^,]+") do
			local trimmed = pkg:match("^%s*(.-)%s*$")
			if trimmed ~= "" then
				table.insert(pkgs, trimmed)
			end
		end

		local results = preflight.fix(pkgs)
		http.prepare_content("application/json")
		http.write_json({ success = true, results = results })

	else
		http.prepare_content("application/json")
		http.write_json({ success = false, error = "未知命令" })
	end
end
