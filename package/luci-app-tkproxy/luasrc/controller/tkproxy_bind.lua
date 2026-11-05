-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 绑定控制器：SSID → 节点 的行内绑定接口

module("luci.controller.tkproxy_bind", package.seeall)

local http = require "luci.http"
local disp = require "luci.dispatcher"
local bind = require "luci.model.tkproxy.bind"
local util = require "luci.model.tkproxy.util"

function index()
	-- 绑定页已下线；这个 URL 只保留给「概览」的 POST（bind_set / bind_toggle / nodes_import / line_delete）
	-- BLK-09：所有写操作必须声明为 POST，防止 CSRF
	entry({"admin", "services", "tkproxy", "bind"}, post("action_bind"), nil).leaf = true
end

local function send_json(t)
	http.header("Cache-Control", "no-store")
	http.write_json(t)
end

local function base_env()
	return {
		token = disp.context.authsession or "",
		urlbase = disp.build_url("admin/services/tkproxy"),
		resource = disp.media,
	}
end

function action_bind()
	local cmd = http.formvalue("cmd")
	if not cmd then
		-- 未授权先看锁屏，已授权回概览
		local licm = require "luci.model.tkproxy.license"
		if not licm.licensed() then
			local env = base_env()
			env.machine = licm.machine()
			env.resource = "/luci-static/resources"
			luci.template.render("tkproxy/lock", env)
			return
		end
		http.redirect(disp.build_url("admin/services/tkproxy/dashboard"))
		return
	end

	-- POST 命令处理
	-- 授权硬锁：未授权时连读接口也不给数据（仅 license_* 放行）
	if cmd:sub(1, 8) ~= "license_" then
		local gok, why = require("luci.model.tkproxy.license").gate()
		if not gok then
			return send_json({ ok = false, need_license = true, msg = why })
		end
	end

	if cmd == "bind_rows" then
		local rows = bind.rows()
		local pool = bind.pool()
		local stats = bind.stats()
		return send_json({ ok = true, rows = rows, pool = pool, stats = stats })
	end

	if cmd == "bind_set" then
		local idx = tonumber(http.formvalue("idx")) or 0
		local node = http.formvalue("node") or ""
		local line, err = bind.set_bind(idx, node)
		if not line then
			return send_json({ ok = false, msg = err or "设置失败" })
		end
		-- 一并回传统计与节点池，页面就地刷新（不整页重载）
		return send_json({
			ok = true, msg = "已保存",
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "bind_toggle" then
		local idx = tonumber(http.formvalue("idx")) or 0
		local enabled = http.formvalue("enabled") == "1"
		local line, err = bind.toggle(idx, enabled)
		if not line then
			return send_json({ ok = false, msg = err or "切换失败" })
		end
		return send_json({
			ok = true, msg = "已保存",
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "line_info" then
		local idx = tonumber(http.formvalue("idx")) or 0
		local info, err = bind.line_info(idx)
		if not info then
			return send_json({ ok = false, msg = err or "读取失败" })
		end
		info.ok = true
		return send_json(info)
	end

	if cmd == "line_update" then
		local idx = tonumber(http.formvalue("idx")) or 0
		local pw = http.formvalue("password")
		local line, err = bind.update_line(idx, {
			ssid = http.formvalue("ssid"),
			band = http.formvalue("band"),
			enabled = http.formvalue("enabled"),
			-- 该行自己的 WiFi 密码：undefined 表示不改
			password = (pw ~= nil and pw ~= "") and pw or nil,
		})
		if not line then
			return send_json({ ok = false, msg = err or "保存失败" })
		end
		return send_json({
			ok = true, msg = "已保存：" .. tostring(line),
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "line_delete" then
		local idx = tonumber(http.formvalue("idx")) or 0
		local ok, ssid = bind.remove_line(idx)
		if not ok then
			return send_json({ ok = false, msg = ssid or "删除失败" })
		end
		return send_json({
			ok = true, msg = "已删除线路 " .. tostring(ssid),
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "line_clear" then
		local ok, n = bind.clear_lines()
		if not ok then
			return send_json({ ok = false, msg = n or "清空失败" })
		end
		return send_json({
			ok = true, msg = "已清空 " .. tostring(n) .. " 条线路",
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "nodes_clear" then
		local ok, n = bind.clear_nodes()
		if not ok then
			return send_json({ ok = false, msg = n or "清空失败" })
		end
		return send_json({
			ok = true, msg = "已清空 " .. tostring(n) .. " 个节点",
			rows = bind.rows(), pool = bind.pool(), stats = bind.stats(),
		})
	end

	if cmd == "bind_auto" then
		local res, err = bind.auto_bind()
		if not res then
			return send_json({ ok = false, msg = err or "自动绑定失败" })
		end
		if not res.ok then
			return send_json({ ok = false, msg = res.msg or "自动绑定失败" })
		end
		local msg = string.format("已绑定 %d 条线路", res.bound)
		if #res.shared > 0 then
			msg = msg .. string.format("（其中 %d 条共用节点，因池不足）", #res.shared)
		end
		if (res.dead_bound or 0) > 0 then
			msg = msg .. string.format("；警告：本次绑定了 %d 个已知不通的节点（节点池可用节点已耗尽），建议先跑节点体检", res.dead_bound)
		end
		return send_json({ ok = true, msg = msg, bound = res.bound, shared = res.shared, dead_bound = res.dead_bound or 0 })
	end

	if cmd == "nodes_import" then
		local text = http.formvalue("text") or ""
		local new_nodes = {}
		local bad_lines = {}
		local ln = 0
		for raw in (text .. "\n"):gmatch("([^\n]*)\n") do
			ln = ln + 1
			local line = raw:gsub("^%s+", ""):gsub("%s+$", "")
			if line ~= "" and line:sub(1, 1) ~= "#" then
				local n = util.parse_node_entry(line)
				if n then
					new_nodes[#new_nodes + 1] = n
				else
					local why = util.node_reject_reason(line)
					bad_lines[#bad_lines + 1] = { line = ln, text = line:sub(1, 60), reason = why or "格式无法识别" }
				end
			end
		end
		if #new_nodes == 0 then
			local unsup = 0
			for _, b in ipairs(bad_lines) do
				if b.reason and b.reason:find("不支持", 1, true) then unsup = unsup + 1 end
			end
			local m = "没有识别到合法节点链接"
			if unsup > 0 then
				m = ("没有可用节点：%d 行的协议不支持"):format(unsup)
			end
			return send_json({ ok = false, msg = m, bad_lines = bad_lines })
		end
		local ok, err = util.add_nodes(new_nodes)
		if not ok then
			return send_json({ ok = false, msg = err or "导入失败", bad_lines = bad_lines })
		end
		return send_json({
			ok = true,
			imported = #new_nodes,
			msg = string.format("已导入 %d 个节点", #new_nodes),
			bad_lines = bad_lines,
		})
	end

	if cmd == "nodes_delete" then
		local name = http.formvalue("name") or ""
		local using = util.lines_using_node(name)
		if #using > 0 then
			return send_json({
				ok = false,
				msg = string.format("节点 %s 正被第 %s 行使用，请先解绑", name, table.concat(using, "、"))
			})
		end
		local ok, err = util.remove_node(name)
		if not ok then
			return send_json({ ok = false, msg = err or "删除失败" })
		end
		return send_json({ ok = true, msg = string.format("已删除节点 %s", name) })
	end

	return send_json({ ok = false, msg = "未知命令：" .. tostring(cmd) })
end
