-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 预检模型层

local sys = require "luci.sys"
local jsonc = require "luci.jsonc"

local M = {}

M.SCRIPT = "/usr/libexec/tkproxy/preflight.sh"

-- 允许自动安装的包白名单
M.FIX_ALLOW = {
	["xray-core"] = true,
	["kmod-nft-tproxy"] = true,
	["nftables"] = true,
	["curl"] = true,
	["ca-bundle"] = true,
	["kmod-veth"] = true,
}

-- 执行预检脚本并解析结果
function M.run()
	local cmd = M.SCRIPT .. " --json"
	local raw = sys.exec(cmd)
	if not raw or raw == "" then
		return nil, "预检脚本执行失败"
	end

	local items = jsonc.parse(raw)
	if not items or type(items) ~= "table" then
		return nil, "预检输出解析失败"
	end

	local summary = { block = 0, warn = 0, pass = 0 }
	for _, item in ipairs(items) do
		local lv = item.level or "pass"
		summary[lv] = (summary[lv] or 0) + 1
	end

	return {
		items = items,
		summary = summary
	}
end

-- 修复缺失依赖（仅限白名单内）
function M.fix(pkgs)
	if type(pkgs) ~= "table" then
		return { { pkg = "", success = false, msg = "参数必须为数组" } }
	end

	local results = {}
	for _, pkg in ipairs(pkgs) do
		local res = { pkg = pkg, success = false, msg = "" }

		if not M.FIX_ALLOW[pkg] then
			res.msg = "不在白名单"
			table.insert(results, res)
		else
			local cmd = "opkg install " .. pkg .. " 2>&1"
			local out = sys.exec(cmd)
			if out:match("Configuring " .. pkg) or out:match("installed in root") then
				res.success = true
				res.msg = "安装成功"
			else
				res.msg = out:match("^(.-)%s*$") or "安装失败"
			end
			table.insert(results, res)
		end
	end

	return results
end


-- 允许重启的服务白名单（只允许这几个，避免被当成任意命令执行入口）
local SVC_ALLOW = {
	dnsmasq = true, sysntpd = true, network = true, firewall = true,
}

-- 统一修复入口：接收动作数组/逗号串，逐个执行并返回逐项结果
-- 支持的动作：
--   opkg:<包名>[,<包名>...]   安装白名单内的包
--   svc:<服务名>              重启并启用白名单内的服务
--   trim                      把超出射频名额的线路自动停用
--   clean                     清理残留（旧 nft 表/网桥/失效 UCI）
-- 防火墙兼容修复：只动 passwall/passwall2/shadowsocksr 这些第三方遗留段里的
-- 过时选项（fw4 不认的 reload），以及指向不存在文件的 include，不碰系统自身规则。
function M.fw_fix()
	local uci = require "luci.model.uci".cursor()
	local legacy = { "passwall", "passwall2", "shadowsocksr", "ssr", "clash" }
	local removed = {}
	for _, sec in ipairs(uci:get_all("firewall") or {}) do
		local name = sec[".name"] or ""
		local base = name:gsub("_server$", "")
		local is_legacy = false
		for _, key in ipairs(legacy) do
			if base == key or name:sub(1, #key + 1) == key .. "_" then is_legacy = true break end
		end
		if is_legacy and sec.reload ~= nil then
			uci:delete("firewall", name, "reload")
			removed[#removed + 1] = name .. ".reload"
		end
		-- 遗留 include 段指向不存在的文件：fw4 只会告警并忽略，留着碍事，直接删段
		if is_legacy and sec[".type"] == "include" then
			local pa = sec.path or ""
			if pa ~= "" and pa:sub(1, 1) == "/" then
				local fh = io.open(pa, "r")
				if fh then fh:close() else
					uci:delete("firewall", name)
					removed[#removed + 1] = name .. "（include 文件缺失，已删段）"
				end
			end
		end
	end
	uci:commit("firewall")
	return removed
end

function M.fix_actions(actions)
	local list = {}
	if type(actions) == "string" then
		for a in actions:gmatch("[^,%s]+") do list[#list + 1] = a end
	elseif type(actions) == "table" then
		list = actions
	end

	local results = {}
	for _, act in ipairs(list) do
		local res = { action = act, success = false, msg = "" }

		if act == "fwfix" then
			local okf, removed = pcall(M.fw_fix)
			if okf then
				res.success = true
				res.msg = (removed and #removed > 0)
					and ("已清理 " .. table.concat(removed, ", "))
					or "没有需要清理的遗留选项"
			else
				res.msg = "清理失败：" .. tostring(removed)
			end
			results[#results + 1] = res

		elseif act:sub(1, 5) == "opkg:" then
			local pkgs = act:sub(6)
			local bad = {}
			for pkg in pkgs:gmatch("[^,%s]+") do
				if not M.FIX_ALLOW[pkg] then bad[#bad + 1] = pkg end
			end
			if #bad > 0 then
				res.msg = "不在白名单：" .. table.concat(bad, ",")
			else
				local sub = M.fix({})
				local all_ok = true
				local msgs = {}
				for pkg in pkgs:gmatch("[^,%s]+") do
					local one = M.fix({ pkg })
					if not one[1] or not one[1].success then
						all_ok = false
						msgs[#msgs + 1] = pkg .. "：" .. tostring(one[1] and one[1].msg or "失败")
					else
						msgs[#msgs + 1] = pkg .. "：ok"
					end
				end
				res.success = all_ok
				res.msg = table.concat(msgs, "；")
				sub = nil
			end

		elseif act:sub(1, 4) == "svc:" then
			local svc = act:sub(5)
			if not SVC_ALLOW[svc] then
				res.msg = "不允许该服务：" .. tostring(svc)
			else
				sys.exec("/etc/init.d/" .. svc .. " enable 2>&1")
				local out = sys.exec("/etc/init.d/" .. svc .. " restart 2>&1") or ""
				res.success = true
				res.msg = "已重启 " .. svc .. (out ~= "" and ("（" .. out:gsub("%s+$", ""):sub(1, 80) .. "）") or "")
			end

		elseif act == "trim" then
			-- 超出射频名额时：把 2.4G / 5G 里多出来的线路停用（保留前面的）
			local ok, util = pcall(require, "luci.model.tkproxy.util")
			if not ok or not util then
				res.msg = "无法加载 util 模块"
			else
				local lines = util.lines()
				local cap = util.LIMIT or 16
				local cnt = { ["2g"] = 0, ["5g"] = 0 }
				local disabled = 0
				for i, line in ipairs(lines) do
					local ssid, band, link, en = util.split_line(line)
					if ssid then
						local b = (band == "5g") and "5g" or "2g"
						local enabled = not (en == "0")
						if enabled then
							cnt[b] = cnt[b] + 1
							if cnt[b] > cap then
								local kp = util.line_key(line)
								local nlp = string.format("%s|%s|%s|0", ssid, band or "2g", link or "")
								if kp ~= "" then nlp = nlp .. "|" .. kp end
								lines[i] = nlp
								disabled = disabled + 1
							end
						end
					end
				end
				if disabled > 0 then
					local sok, serr = util.save_lines(lines)
					res.success = sok and true or false
					res.msg = sok and string.format("已停用 %d 条超出名额的线路（每射频上限 %d）", disabled, cap)
						or tostring(serr)
				else
					res.success = true
					res.msg = "没有超出名额的线路，无需处理"
				end
			end

		elseif act == "clean" then
			local ok, util = pcall(require, "luci.model.tkproxy.util")
			if ok and util and util.start_clean then
				local sok, serr = util.start_clean()
				res.success = sok and true or false
				res.msg = sok and "已启动清理任务" or tostring(serr)
			else
				res.msg = "无法启动清理"
			end

		else
			res.msg = "未知动作"
		end

		results[#results + 1] = res
	end

	return results
end

return M
