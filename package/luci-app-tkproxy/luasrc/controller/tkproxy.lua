-- SPDX-License-Identifier: GPL-3.0
-- tkproxy LuCI 控制器
--
-- 页面：概览 / 节点列表
-- 所有写操作统一 POST 到 action，由 Dispatcher 校验 CSRF token。
-- 命令白名单之外一律拒绝。

module("luci.controller.tkproxy", package.seeall)

local http = require "luci.http"
local disp = require "luci.dispatcher"
local util = require "luci.model.tkproxy.util"

function index()
	local root = entry({ "admin", "services", "tkproxy" }, call("action_dashboard"), "多线路分流", 61)
	root.dependent = false
	entry({ "admin", "services", "tkproxy", "dashboard" }, call("action_dashboard"), "概览", 10).leaf = true
	entry({ "admin", "services", "tkproxy", "nodes" }, call("action_nodes"), "节点列表", 25).leaf = true
	-- t_299f5f62：SOCKS5 独立分类页，排在节点列表之后
	entry({ "admin", "services", "tkproxy", "socks5" }, call("action_socks5"), "SOCKS5 代理", 27).leaf = true
	entry({ "admin", "services", "tkproxy", "action" }, post("action_op")).leaf = true
	entry({ "admin", "services", "tkproxy", "state" }, call("action_state"), nil, 40).leaf = true
end

-- 读本包版本号，用于给静态资源加 ?v= 打缓存（升级/强刷后不吃旧 css/js）
-- 25.12 起系统切到 apk，已装信息在 /lib/apk/db/installed（没有 /usr/lib/opkg/info），两处都认
local function apk_version()
	local f = io.open("/lib/apk/db/installed", "r")
	if not f then return nil end
	local cur, ver = "", nil
	for line in f:lines() do
		if line:match("^P:") then
			cur = line:sub(3)
		elseif line:match("^V:") and cur == "luci-app-tkproxy" then
			ver = line:sub(3):gsub("^%s+", ""):gsub("%s+$", "")
			break
		end
	end
	f:close()
	return ver
end

local function pkg_version()
	local f = io.open("/usr/lib/opkg/info/luci-app-tkproxy.control", "r")
	local ver = nil
	if f then
		for line in f:lines() do
			local v = line:match("^Version:%s*(.+)$")
			if v then ver = v break end
		end
		f:close()
	end
	if not ver then ver = apk_version() end
	if not ver or ver == "" then
		-- 固件里插件是文件注入（不是 apk 包），没有包数据库记录，
		-- 兜底读随包写下的 VERSION 文件，避免界面显示 v0
		local fv = io.open("/usr/share/tkproxy/VERSION", "r")
		if fv then
			ver = (fv:read("*l") or ""):gsub("%s+", "")
			fv:close()
		end
	end
	if not ver or ver == "" then ver = "0" end
	-- opkg: 3.13.5-1 / apk: 3.13.5-r1 —— 统一显示成 3.13.5
	ver = ver:gsub("[^%w%.%-]", ""):gsub("%-r?%d+$", "")
	return ver
end

local function base_env()
	return {
		token = disp.context.authsession or "",
		urlbase = disp.build_url("admin/services/tkproxy"),
		ver = pkg_version(),
	}
end

-- 授权硬锁：未激活/已过期时，页面一律渲染锁屏，接口一律拒绝（仅放行 license_*）
local function lic()
	return require "luci.model.tkproxy.license"
end

local function locked()
	return (not lic().licensed())
end

local function render_lock(rebind)
	-- 锁屏页必须禁缓存：旧版本页面（fetch 版）被缓存会让人以为"按钮没反应"
	http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	http.header("Pragma", "no-cache")
	http.header("Expires", "0")
	local env = base_env()
	env.machine = lic().machine()
	env.rebind = rebind and true or false
	env.resource = "/luci-static/resources"
	env.licmsg = http.formvalue("licmsg") or ""
	luci.template.render("tkproxy/lock", env)
end

local function send_json(t)
	http.header("Cache-Control", "no-store")
	http.write_json(t)
end

local function busy()
	return util.job_running("deploy") or util.job_running("clean")
end

-- ---------------------------------------------------------------------------
-- 页面
-- ---------------------------------------------------------------------------

function action_dashboard()
	if locked() then return render_lock() end
	local v = util.overview()
	local env = base_env()
	env.rows = v.rows
	env.errors = v.errors
	env.quota = v.quota
	env.has_lines = v.has_lines
	env.deployed = v.deployed
	env.can_deploy = v.ok and not busy()
	env.job_running = busy()
	-- 首页工作台需要节点池选项与绑定统计
	local okb, bind = pcall(require, "luci.model.tkproxy.bind")
	if okb and bind then
		local okp, pool = pcall(bind.pool)
		env.pool = okp and pool or {}
		local oks, st = pcall(bind.stats)
		env.bind_stats = oks and st or nil
	else
		env.pool = {}
	end
	luci.template.render("tkproxy/dashboard", env)
end

-- 节点行渲染数据：节点列表页与 SOCKS5 独立页共用（避免两处拼表逻辑漂移）
local function node_rows()
	local gen_mod = require "luci.model.tkproxy.gen"
	local nodes = util.nodes()
	local node_list = {}
	for _, n in ipairs(nodes) do
		local ob = gen_mod.parse_node(n.link)
		local using = util.lines_using_node(n.name)
		node_list[#node_list + 1] = {
			name = n.name,
			protocol = ob and tostring(ob.type or "") or "",
			server = ob and tostring(ob.server or "") or "",
			port = ob and (ob.server_port or "") or "",
			used_by = using,
			valid = (ob ~= nil),
			-- t_309a22f3：socks5 的前置节点名（gen.parse_socks 从 ?front= 解出），
			-- 仅供 SOCKS5 页面展示，不影响任何 cmd 行为
			front = (ob ~= nil and type(ob.front) == "string" and ob.front ~= "") and ob.front or nil,
		}
	end
	return node_list, nodes
end

function action_nodes()
	if locked() then return render_lock() end
	local node_list, nodes = node_rows()
	local env = base_env()
	env.nodes = node_list
	env.has_nodes = (#nodes > 0)
	env.job_running = busy()
	luci.template.render("tkproxy/nodes", env)
end

-- t_299f5f62：SOCKS5 独立分类页（复用节点池数据与 import_nodes/delete_node 接口）
function action_socks5()
	if locked() then return render_lock() end
	local node_list, nodes = node_rows()
	local env = base_env()
	env.nodes = node_list
	env.has_nodes = (#nodes > 0)
	env.job_running = busy()
	luci.template.render("tkproxy/socks5", env)
end

function action_state()
	if locked() then
		http.prepare_content("application/json")
		return http.write_json({ ok = false, need_license = true, msg = "本机尚未授权" })
	end
	local what = http.formvalue("what") or "deploy"
	local out
	if what == "status" then
		out = util.status_state()
	elseif what == "deploy" then
		out = util.job_state("deploy")
		out.deployed = util.is_deployed()
	elseif what == "clean" then
		out = util.job_state("clean")
		out.deployed = util.is_deployed()
	else
		out = { state = "idle" }
	end
	send_json(out)
end

-- ---------------------------------------------------------------------------
-- 开箱自检（t_d32788de）：读 /etc/tkproxy/bootcheck.json / 立即重跑
-- ---------------------------------------------------------------------------

local BOOTCHECK_JSON = "/etc/tkproxy/bootcheck.json"
local BOOTCHECK_SH = "/usr/libexec/tkproxy/bootcheck.sh"

-- 读开箱自检结果文件并解析为固定结构；没跑过返回 { ran = false }
local function bootcheck_read()
	local fh = io.open(BOOTCHECK_JSON, "r")
	if not fh then
		return { ran = false }
	end
	local raw = fh:read("*a")
	fh:close()
	local ok, data = pcall(require("luci.jsonc").parse, raw)
	if not ok or type(data) ~= "table" or type(data.items) ~= "table" then
		-- 文件存在但解析失败：区分于「没跑过」，前端提示用户重跑（bootcheck.sh 会重写）
		return { ran = false, corrupted = true }
	end
	local items = {}
	for _, it in ipairs(data.items or {}) do
		items[#items + 1] = {
			id = tostring(it.id or ""),
			title = tostring(it.title or ""),
			level = tostring(it.level or "pass"),
			detail = tostring(it.detail or ""),
			fix = tostring(it.fix or ""),
		}
	end
	return {
		ran = true,
		ts = tonumber(data.ts) or 0,
		ver = tostring(data.ver or ""),
		block = tonumber(data.block) or 0,
		warn = tonumber(data.warn) or 0,
		pass = tonumber(data.pass) or 0,
		items = items,
	}
end

local function bootcheck_state()
	local st = bootcheck_read()
	st.ok = true
	return send_json(st)
end

-- 立即重跑：--force 跳过 24h 节流，同步执行（约 10-20s，出网探测最多 5s x N），
-- 完成后返回最新结果，前端无需二次拉取
local function bootcheck_run()
	local fh = io.popen("sh " .. BOOTCHECK_SH .. " --force 2>&1")
	if not fh then
		return send_json({ ok = false, msg = "无法执行自检脚本" })
	end
	fh:read("*a")
	local ok_exec = fh:close()
	local st = bootcheck_read()
	st.ok = ok_exec and st.ran and true or false
	if not st.ran then
		st.ok = false
		st.msg = "自检完成但结果未落盘，请稍后重试"
	end
	return send_json(st)
end

-- ---------------------------------------------------------------------------
-- 写操作（POST）
-- ---------------------------------------------------------------------------

local function save_and_deploy(text)
	local v = util.validate(text)
	if not v.ok then
		v.deployed = util.is_deployed()
		return v
	end
	local lines = util.data_lines(text)
	-- 锁内「先确认可启动再写 UCI」，失败时 util 会回滚到保存前快照
	local started, serr = util.save_and_deploy(lines)
	if not started then
		return { ok = false, errors = { { line = 0, idx = 0, msg = serr or "无法保存并启动部署" } } }
	end
	return {
		ok = true,
		count = #lines,
		msg = string.format("已保存 %d 条线路，正在部署", #lines),
	}
end

function action_op()
	local cmd = http.formvalue("cmd") or ""

	-- 授权硬锁：除 license_* 外一律拒绝（未授权时连预览/校验都不给）
	if cmd:sub(1, 8) ~= "license_" then
		local gok, why = lic().gate()
		if not gok then
			return send_json({ ok = false, need_license = true, msg = why })
		end
	end


	if cmd == "validate" then
		local v = util.validate(http.formvalue("text") or "")
		v.deployed = util.is_deployed()
		return send_json(v)
	end

	-- 开箱自检（t_d32788de）：概览页状态条数据源 + 立即自检按钮
	if cmd == "bootcheck_state" then
		return bootcheck_state()
	end
	if cmd == "bootcheck_run" then
		return bootcheck_run()
	end

	if cmd == "save" then
		return send_json(save_and_deploy(http.formvalue("text") or ""))
	end

	-- ---------------- 卡密授权（不走门禁） ----------------
	if cmd == "license_status" then
		local lic = require "luci.model.tkproxy.license"
		return send_json({ ok = true, data = lic.status() })
	end

	if cmd == "license_activate" then
		local okl, msg = lic().activate(http.formvalue("card") or "")
		-- 锁屏页用原生表单提交：重定向回去并把消息带回，避免依赖前端 JS
		if http.formvalue("from") == "lock" then
			local base = disp.build_url("admin/services/tkproxy/dashboard")
			msg = (msg or ""):gsub("%s+", " ")
			local enc = tostring(msg):gsub("([^%w%.%-_~ ])", function(ch)
				return string.format("%%%02X", ch:byte())
			end)
			return http.redirect(base .. "?licmsg=" .. enc:gsub(" ", "+"))
		end
		return send_json({ ok = okl and true or false, msg = msg or "", data = lic().status() })
	end

	if cmd == "license_verify" then
		local lic = require "luci.model.tkproxy.license"
		local ok, msg = lic.verify()
		return send_json({ ok = ok and true or false, msg = msg or "", data = lic.status() })
	end

	if cmd == "update_cfg" then
		local upd = require "luci.model.tkproxy.update"
		return send_json({ ok = true, url = upd.get_url(), current = upd.current() })
	end

	if cmd == "update_url_save" then
		local upd = require "luci.model.tkproxy.update"
		local ok, msg = upd.set_url(http.formvalue("url") or "")
		return send_json({ ok = ok and true or false, msg = msg or "", url = upd.get_url() })
	end

	if cmd == "update_check" then
		local upd = require "luci.model.tkproxy.update"
		return send_json(upd.check())
	end

	if cmd == "update_install" then
		local upd = require "luci.model.tkproxy.update"
		return send_json(upd.install())
	end

	if cmd == "license_reset" then
		local lic = require "luci.model.tkproxy.license"
		local ok, msg = lic.reset()
		return send_json({ ok = ok and true or false, msg = msg or "", data = lic.status() })
	end

	if cmd == "batch_preview" then
		local lines = util.lines()
		local v = util.validate(table.concat(lines, "\n"))
		local opts = {
			count = tonumber(http.formvalue("count")) or 0,
			mode = http.formvalue("mode") or "auto",
			count_2g = tonumber(http.formvalue("count_2g")) or 0,
			count_5g = tonumber(http.formvalue("count_5g")) or 0,
			limit_2g = 16,
			limit_5g = 16,
			used_2g = (v.quota and v.quota.g2) or 0,
			-- radio1 上还有主 WiFi 占 1 个 AP，必须计入
			used_5g = ((v.quota and v.quota.g5) or 0) + 1,
		}
		local preview = util.batch_capacity_preview(opts)
		return send_json(preview)
	end

	if cmd == "batch_generate" then
		local lines = util.lines()
		local v = util.validate(table.concat(lines, "\n"))
		local opts = {
			count = tonumber(http.formvalue("count")) or 0,
			prefix = http.formvalue("prefix") or "TK-",
			start_seq = tonumber(http.formvalue("start_seq")) or 1,
			password = http.formvalue("password") or "",
			mode = http.formvalue("mode") or "auto",
			count_2g = tonumber(http.formvalue("count_2g")) or 0,
			count_5g = tonumber(http.formvalue("count_5g")) or 0,
			limit_2g = 16,
			limit_5g = 16,
			used_2g = (v.quota and v.quota.g2) or 0,
			-- radio1 上还有主 WiFi 占 1 个 AP，必须计入
			used_5g = ((v.quota and v.quota.g5) or 0) + 1,
		}
		local res = util.batch_generate(opts)
		if not res.ok then
			return send_json({ ok = false, msg = res.error or "生成失败" })
		end
		-- 追加到现有清单（只保存，部署由用户在概览页手动触发）
		for _, line in ipairs(res.lines) do
			table.insert(lines, line)
		end
		local ok2, err2 = util.save_lines(lines)
		if not ok2 then
			return send_json({ ok = false, msg = err2 or "保存失败" })
		end
		local msg = string.format("已生成 %d 条线路（2.4G:%d / 5G:%d），已保存待部署",
			res.count, res.final_2g, res.final_5g)
		if (res.unbound or 0) > 0 then
			msg = msg .. string.format("；其中 %d 条还没有节点（节点池不足），请在节点页补充后点「自动匹配」", res.unbound)
		end
		return send_json({
			ok = true,
			count = res.count,
			unbound = res.unbound or 0,
			assigned = res.assigned or {},
			msg = msg,
		})
	end

	if cmd == "deploy" then
		local lines = util.lines()
		-- 清单为空：不是错误，而是「拆除全部已部署 WiFi」的合法动作
		if #lines == 0 then
			local started, err = util.start_clean()
			return send_json({
				ok = started,
				count = 0,
				msg = started and "清单为空：正在拆除全部已部署 WiFi 与规则" or (err or "无法启动拆除"),
			})
		end
		local v = util.validate(table.concat(lines, "\n"))
		if not v.ok then
			v.deployed = util.is_deployed()
			return send_json(v)
		end
		local started, err = util.start_deploy(lines)
		-- 只有部署任务真的启动成功，才把本次清单记为「已部署基准」；
		-- 否则（被拒/启动失败）保留旧基准，提醒条才不会误消失。
		if started then
			do
				local fs = require "nixio.fs"
				if fs and fs.mkdirr then pcall(fs.mkdirr, "/tmp/tkproxy/web") end
				local fh = io.open("/tmp/tkproxy/web/deploy-target.txt", "w")
				if fh then
					fh:write(table.concat(lines, "\n") .. "\n")
					fh:close()
				end
			end
		end
		return send_json({
			ok = started,
			msg = started and "部署已开始" or (err or "无法启动部署"),
		})
	end

	if cmd == "rollback" then
		local started, err = util.start_clean()
		return send_json({
			ok = started,
			msg = started and "回滚已开始" or (err or "无法启动回滚"),
		})
	end

	if cmd == "save_edit" then
		local idx = tonumber(http.formvalue("i") or "") or 0
		if idx % 1 ~= 0 then
			return send_json({ ok = false, errors = { { line = 0, idx = 0, msg = "线路序号必须是整数" } } })
		end
		local ssid = http.formvalue("ssid") or ""
		local band = (http.formvalue("band") or "both"):lower()
		local link = http.formvalue("link") or ""
		local lines = util.lines()

		if idx < 1 or idx > #lines then
			return send_json({ ok = false, errors = { { line = 0, idx = 0, msg = "线路不存在（可能已被删除）" } } })
		end
		if band ~= "2g" and band ~= "5g" and band ~= "both" then
			return send_json({ ok = false, errors = { { line = 0, idx = 0, msg = "频段只能是 2g / 5g / both" } } })
		end
		if ssid:find("|", 1, true) then
			return send_json({ ok = false, errors = { { line = 0, idx = 0, msg = "SSID 不能包含 |" } } })
		end

		local newline = ssid:gsub("^%s+", ""):gsub("%s+$", "") .. "|" .. band .. "|"
			.. link:gsub("^%s+", ""):gsub("%s+$", "")
		local _, perr = util.parse_line(newline, idx)
		if perr then
			return send_json({ ok = false, errors = { { line = 0, idx = idx, msg = tostring(perr) } } })
		end

		lines[idx] = newline
		local v = util.validate(table.concat(lines, "\n"))
		if not v.ok then
			v.deployed = util.is_deployed()
			return send_json(v)
		end
		local started, derr = util.save_and_deploy(lines)
		if not started then
			return send_json({ ok = false, errors = { { line = 0, idx = idx, msg = derr or "无法保存并启动部署" } } })
		end
		return send_json({
			ok = true,
			msg = string.format("已保存第 %d 条，正在重建（其他线路配置不变）", idx),
		})
	end

	if cmd == "import_nodes" then
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
			if unsup > 0 then m = ("没有可用节点：%d 行的协议不支持（详见下方列表）"):format(unsup) end
			return send_json({ ok = false, msg = m, bad_lines = bad_lines, imported = 0 })
		end
		local before = #(util.nodes() or {})
		local ok, err = util.add_nodes(new_nodes)
		if not ok then
			return send_json({ ok = false, msg = err or "导入失败", bad_lines = bad_lines, imported = 0 })
		end
		local after = #(util.nodes() or {})
		local added = after - before
		local dup = #new_nodes - added
		-- 报「实际新增」而不是「解析成功」，否则全是重复时用户会以为导入成功却看不到新节点
		local msg = string.format("新增 %d 个节点", added)
		if dup > 0 then msg = msg .. string.format("，重复跳过 %d 个", dup) end
		if #bad_lines > 0 then msg = msg .. string.format("，%d 行无法识别", #bad_lines) end
		return send_json({
			ok = true,
			imported = added,
			count = #new_nodes,
			duplicated = dup,
			msg = msg,
			bad_lines = bad_lines,
		})
	end

	if cmd == "delete_node" then
		local name = http.formvalue("name") or ""
		local using = util.lines_using_node(name)
		if #using > 0 then
			return send_json({
				ok = false,
				msg = string.format("节点 %s 正被第 %s 行使用，请先修改线路", name, table.concat(using, "、"))
			})
		end
		local ok, err = util.remove_node(name)
		if not ok then
			return send_json({ ok = false, msg = err or "删除失败" })
		end
		return send_json({ ok = true, msg = string.format("已删除节点 %s", name) })
	end

	if cmd == "run_purity_check" then
		local purity_mod = require "luci.model.tkproxy.purity"
		if not util.is_deployed() then
			return send_json({ ok = false, msg = "尚未部署，请先部署线路" })
		end
		local items, err = purity_mod.run_check()
		if not items then
			return send_json({ ok = false, msg = err or "体检失败" })
		end
		local summary = purity_mod.summarize(items)
		return send_json({
			ok = true,
			items = items,
			summary = summary,
		})
	end

	if cmd == "save_purity_rules" then
		local purity_mod = require "luci.model.tkproxy.purity"
		local rules = {}
		for k in pairs(purity_mod.DEFAULTS) do
			local v = http.formvalue(k)
			if v ~= nil then
				rules[k] = v
			end
		end
		local ok = purity_mod.save_rules(rules)
		if not ok then
			return send_json({ ok = false, msg = "保存规则失败" })
		end
		return send_json({ ok = true, msg = "规则已保存" })
	end

	if cmd == "fetch_subscription" then
		local url = http.formvalue("url") or ""
		if url == "" then
			return send_json({ ok = false, msg = "订阅 URL 不能为空" })
		end

		-- 安全性检查：仅允许 https
		if not url:match("^https://") then
			return send_json({ ok = false, msg = "仅支持 https:// 订阅链接" })
		end

		-- 拉取：OpenWrt/ImmortalWrt 的 wget 通常是 uclient-fetch 的软链，
		-- 不支持 --max-redirect/--tries/--max-filesize/-i（直接报 unrecognized option，
		-- URL 都发不出去），所以优先用 curl，失败再回退到只带 --timeout 的 wget。
		local text, ok_fetch = nil, false
		local function has_bin(bin)
			local p = io.popen("command -v " .. bin .. " 2>/dev/null")
			local path = p and p:read("*l") or nil
			if p then p:close() end
			return path ~= nil and path ~= ""
		end
		if has_bin("curl") then
			-- 用 curl 配置文件传 URL，避免 shell 注入
			local cfgfile = "/tmp/tkproxy-sub." .. os.time() .. "." .. math.random(10000, 99999) .. ".curl"
			local cf = io.open(cfgfile, "w")
			if cf then
				cf:write(string.format('url = "%s"\n', url:gsub("\\", "\\\\"):gsub('"', '\\"')))
				cf:close()
				local cmd = string.format(
					"curl -q -sS -L --config %s --max-time 30 --max-redirs 3 --max-filesize 2097152 2>&1",
					string.format("%q", cfgfile)
				)
				local fh = io.popen(cmd)
				text = fh and fh:read("*a") or ""
				ok_fetch = fh and fh:close() and true or false
				os.remove(cfgfile)
			end
		end
		if not text or text == "" then
			-- 回退：uclient-fetch 只认 --timeout
			local cmd = string.format("wget -q -O- --timeout=30 %s 2>&1", string.format("%q", url))
			local fh = io.popen(cmd)
			text = fh and fh:read("*a") or ""
			ok_fetch = fh and fh:close() and true or false
		end

		if not text or text == "" or text:find("curl:", 1, true) or text:find("wget:", 1, true) or not ok_fetch then
			return send_json({ ok = false, msg = "拉取失败：" .. ((text and text:sub(1, 100)) or "无响应或超时") })
		end

		-- 限制响应大小（防御性二次检查）
		if #text > 2 * 1024 * 1024 then
			return send_json({ ok = false, msg = "订阅响应过大（超过 2MB 限制）" })
		end

		-- BLK-11：订阅内容为 Base64 时自动解码
		-- 检测逻辑：去空白后，内容看起来像纯 Base64（字符集 A-Za-z0-9+/=，长度是 4 的倍数）
		local trimmed = text:gsub("%s+", "")
		local looks_like_base64 = false
		if #trimmed > 0 and not trimmed:find("://") then
			-- 不含 ://（排除明文链接），且符合 Base64 字符集和长度约束
			if trimmed:match("^[A-Za-z0-9+/]+=*$") and #trimmed % 4 == 0 then
				looks_like_base64 = true
			end
		end

		if looks_like_base64 then
			-- 尝试 Base64 解码
			local ok_decode, decoded = pcall(function()
				local gen = require "luci.model.tkproxy.gen"
				-- 使用 gen.lua 的 b64decode 并验证解码结果
				return gen.b64decode_for_subscription(trimmed)
			end)
			if ok_decode and decoded and decoded ~= "" and #decoded > 0 then
				-- 验证解码结果是否包含合法链接或节点信息
				if decoded:match("://") or decoded:match("%w+") then
					text = decoded
				end
			end
			-- 解码失败或无效时保留原文（可能是误判或损坏的 Base64）
		end

		return send_json({ ok = true, text = text })
	end

	if cmd == "nodetest" then
		local prune = (http.formvalue("prune") == "1")
		local script = "/usr/libexec/tkproxy/nodetest.sh"
		local args = prune and "--prune" or ""
		local cmd_str = string.format("%s %s 2>&1", script, args)
		local fh = io.popen(cmd_str)
		if not fh then
			return send_json({ ok = false, msg = "无法执行体检脚本" })
		end
		local output = fh:read("*a")
		local ok_exec = fh:close()

		-- 解析结果文件
		local result_file = "/tmp/tkproxy/nodetest.txt"
		local rf = io.open(result_file, "r")
		local lines = {}
		local available = 0
		local total = 0
		if rf then
			for line in rf:lines() do
				if line:match("^available=") then
					available = tonumber(line:match("^available=(%d+)")) or 0
				elseif line:match("^total=") then
					total = tonumber(line:match("^total=(%d+)")) or 0
				else
					-- 格式：名称|IP|国家|OK/FAIL
					local name, ip, country, status = line:match("^([^|]+)|([^|]*)|([^|]*)|([^|]+)$")
					if name and status then
						table.insert(lines, {
							name = name,
							ip = (ip ~= "" and ip) or "",
							country = (country ~= "" and country) or "",
							status = status,
						})
					end
				end
			end
			rf:close()
		end

		return send_json({
			ok = ok_exec and true or false,
			available = available,
			total = total,
			lines = lines,
			msg = string.format("体检完成：可用 %d / 总数 %d", available, total),
		})
	end

	if cmd == "kernel_check" then
		local script = "/usr/libexec/tkproxy/xray-upgrade.sh"
		local fh = io.popen(script .. " check 2>&1")
		if not fh then
			return send_json({ ok = false, msg = "无法执行版本检查脚本" })
		end
		local output = fh:read("*a")
		fh:close()
		-- 脚本输出 JSON，直接透传
		http.header("Cache-Control", "no-store")
		http.prepare_content("application/json")
		http.write(output)
		return
	end

	if cmd == "kernel_upgrade" then
		local script = "/usr/libexec/tkproxy/xray-upgrade.sh"
		local fh = io.popen(script .. " upgrade 2>&1")
		if not fh then
			return send_json({ ok = false, msg = "无法执行升级脚本" })
		end
		local output = fh:read("*a")
		local exit_ok = fh:close()
		-- 提取末行 JSON
		local lines_arr = {}
		for line in (output .. "\n"):gmatch("([^\n]*)\n") do
			if line ~= "" then
				table.insert(lines_arr, line)
			end
		end
		local json_line = lines_arr[#lines_arr] or ""
		-- 如果脚本退出失败或末行不是合法 JSON，统一返回失败
		if not exit_ok or not json_line:match('^%s*{') then
			-- 尝试从输出中提取错误信息
			local err_msg = output:match("%[ERROR%]%s*(.-)%s*$") or output:match("%[ERROR%]%s*(.-)\n") or "升级失败"
			return send_json({ ok = false, msg = err_msg })
		end
		http.header("Cache-Control", "no-store")
		http.prepare_content("application/json")
		http.write(json_line)
		return
	end

	if cmd == "purity_check" then
		if not util.is_deployed() then
			return send_json({ ok = false, msg = "尚未部署，请先部署线路" })
		end

		local script = "/usr/libexec/tkproxy/purity.sh"
		local mode = http.formvalue("mode") or "all"
		local line_num = http.formvalue("line") or ""

		local cmd_str = ""
		if mode == "line" and line_num ~= "" then
			cmd_str = string.format("%s --line %s 2>&1", script, line_num)
		else
			cmd_str = string.format("%s --all 2>&1", script)
		end

		local fh = io.popen(cmd_str)
		if not fh then
			return send_json({ ok = false, msg = "无法执行纯净度自检脚本" })
		end

		local output = fh:read("*a")
		local exit_ok = fh:close()

		if not exit_ok or output == "" then
			return send_json({ ok = false, msg = "自检失败：" .. (output or "无输出") })
		end

		-- 解析 TSV 输出（line, dns, ipv6, direct, evidence）
		local lines = {}
		for line in (output .. "\n"):gmatch("([^\n]*)\n") do
			if line ~= "" and not line:match("^#") then
				local idx, dns, ipv6, direct, evidence = line:match("^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t(.*)$")
				if idx then
					table.insert(lines, {
						line = tonumber(idx) or 0,
						dns = dns or "UNKNOWN",
						ipv6 = ipv6 or "UNKNOWN",
						direct = direct or "UNKNOWN",
						evidence = evidence or "",
					})
				end
			end
		end

		-- 汇总统计
		local summary = {
			total = #lines,
			dns_pass = 0,
			dns_fail = 0,
			ipv6_pass = 0,
			ipv6_fail = 0,
			direct_pass = 0,
			direct_fail = 0,
			all_pass = 0,
		}

		for _, l in ipairs(lines) do
			if l.dns == "PASS" then summary.dns_pass = summary.dns_pass + 1 end
			if l.dns == "FAIL" then summary.dns_fail = summary.dns_fail + 1 end
			if l.ipv6 == "PASS" then summary.ipv6_pass = summary.ipv6_pass + 1 end
			if l.ipv6 == "FAIL" then summary.ipv6_fail = summary.ipv6_fail + 1 end
			if l.direct == "PASS" then summary.direct_pass = summary.direct_pass + 1 end
			if l.direct == "FAIL" then summary.direct_fail = summary.direct_fail + 1 end

			if l.dns == "PASS" and l.ipv6 == "PASS" and l.direct == "PASS" then
				summary.all_pass = summary.all_pass + 1
			end
		end

		return send_json({
			ok = true,
			lines = lines,
			summary = summary,
		})
	end

	if cmd == "line_check" then
		if not util.is_deployed() then
			return send_json({ ok = false, msg = "尚未部署" })
		end

		local line_str = http.formvalue("line") or ""
		local line = tonumber(line_str)
		if not line or line < 1 then
			return send_json({ ok = false, msg = "line 参数必须是正整数" })
		end

		-- 读取 manifest.json 获取该线路信息（复用现有探测口）
		local jsonc = require "luci.jsonc"
		local f = io.open("/etc/tkproxy/manifest.json", "r")
		if not f then
			return send_json({ ok = false, line = line, status = "fail", exit_ip = "", country = "", isp = "", dns_loc = "", note = "manifest 不存在" })
		end

		local ok_parse, data = pcall(function()
			local raw = f:read("*a")
			f:close()
			return jsonc.parse(raw or "")
		end)

		if not ok_parse or type(data) ~= "table" then
			return send_json({ ok = false, line = line, status = "fail", exit_ip = "", country = "", isp = "", dns_loc = "", note = "manifest 解析失败" })
		end

		local ssids = data.ssids or data
		local item = nil
		for _, s in ipairs(ssids) do
			if type(s) == "table" and tonumber(s.index) == line then
				item = s
				break
			end
		end

		if not item then
			return send_json({ ok = false, line = line, status = "fail", exit_ip = "", country = "", isp = "", dns_loc = "", note = "线路不存在" })
		end

		local probe_port = 22000 + line
		local sys = require "luci.sys"

		-- 通过探测口检测：出口 IP/国家/ISP
		local cmd_ip = string.format("curl -x socks5h://127.0.0.1:%d -s -m 8 'http://ip-api.com/line/?fields=query,countryCode,isp' 2>&1", probe_port)
		local out_ip = sys.exec(cmd_ip) or ""
		local exit_ip, country, org = out_ip:match("^([^\n]+)\n([^\n]+)\n([^\n]+)")

		local status = "fail"
		local note = ""

		if not exit_ip or exit_ip == "" then
			note = "节点未连通"
		else
			status = "ok"
		end

		-- DNS 落地检查
		local dns_loc = ""
		if status == "ok" then
			local cmd_dns = string.format("curl -x socks5h://127.0.0.1:%d -s -m 8 'https://1.1.1.1/cdn-cgi/trace' 2>&1 | grep '^loc=' | cut -d= -f2", probe_port)
			dns_loc = (sys.exec(cmd_dns) or ""):gsub("%s+$", "")
		end

		return send_json({
			ok = true,
			line = line,
			status = status,
			exit_ip = exit_ip or "",
			country = country or "",
			org = org or "",
			dns_loc = dns_loc,
			note = note,
		})
	end

	if cmd == "env_check" then
		if not util.is_deployed() then
			return send_json({ ok = false, msg = "尚未部署" })
		end

		local line_str = http.formvalue("line") or ""
		local line = tonumber(line_str)
		if not line or line < 1 then
			return send_json({ ok = false, msg = "line 参数必须是正整数" })
		end

		local script = "/usr/libexec/tkproxy/status.sh"
		-- 确保每条 curl 使用 -m6，整体在 20 秒内返回（由 lua timeout 限制不超过 20s）
        local cmd_str = string.format("%s line-env %d 2>&1", script, line)
		local sys = require "luci.sys"
		local output = sys.exec(cmd_str) or ""

		-- 解析 JSON 结果
		local jsonc = require "luci.jsonc"
		local ok_parse, data = pcall(function()
			return jsonc.parse(output)
		end)

		if not ok_parse or type(data) ~= "table" then
			return send_json({ ok = false, note = "解析 line-env 输出失败：" .. (output:sub(1, 100) or ""), line = line })
		end

		-- 确保返回含 ok=true/false 与 line
		data.ok = (data.status == "ok")
		data.line = line
		return send_json(data)
	end

	if cmd == "purity_override" then
		local line_str = http.formvalue("line") or ""
		local line_num = tonumber(line_str)
		local value = http.formvalue("value") or ""

		if not line_num or line_num < 1 or line_num ~= math.floor(line_num) then
			return send_json({ ok = false, msg = "line 参数必须是正整数" })
		end

		if value ~= "1" and value ~= "0" then
			return send_json({ ok = false, msg = "value 参数必须是 1 或 0" })
		end

		-- 校验该线路存在
		local jsonc = require "luci.jsonc"
		local f = io.open("/etc/tkproxy/manifest.json", "r")
		if not f then
			return send_json({ ok = false, msg = "manifest.json 无法读取" })
		end
		local ok_parse, data = pcall(function()
			local raw = f:read("*a")
			f:close()
			return jsonc.parse(raw or "")
		end)
		if not ok_parse or type(data) ~= "table" then
			return send_json({ ok = false, msg = "manifest.json 解析失败" })
		end
		local ssids = data.ssids or data
		if type(ssids) ~= "table" then
			return send_json({ ok = false, msg = "manifest 结构异常：ssids 不是数组" })
		end
		local found = false
		for _, s in ipairs(ssids) do
			if type(s) == "table" and tonumber(s.index) == line_num then
				found = true
				break
			end
		end
		if not found then
			return send_json({ ok = false, msg = "线路不存在" })
		end

		local uci = require "luci.model.uci".cursor()
		local key = "res_override_" .. line_num

		if value == "1" then
			uci:set("tkproxy", "main", key, "1")
			uci:commit("tkproxy")
			return send_json({ ok = true, line = line_num, override = 1 })
		else
			uci:delete("tkproxy", "main", key)
			uci:commit("tkproxy")
			return send_json({ ok = true, line = line_num, override = 0 })
		end
	end

	if cmd == "purity_line" then
		if not util.is_deployed() then
			return send_json({ ok = false, msg = "尚未部署" })
		end

		local line_str = http.formvalue("line") or ""
		local line_num = tonumber(line_str)
		if not line_num or line_num < 1 then
			return send_json({ ok = false, msg = "line 参数必须是正整数" })
		end

		-- 读取覆盖标志
		local uci = require "luci.model.uci".cursor()
		local override_key = "res_override_" .. line_num
		local is_override = (uci:get("tkproxy", "main", override_key) == "1")

		-- 读取 manifest.json 获取该线路信息
		local jsonc = require "luci.jsonc"
		local f = io.open("/etc/tkproxy/manifest.json", "r")
		if not f then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"manifest 不存在"} })
		end

		local ok_parse, data = pcall(function()
			local raw = f:read("*a")
			f:close()
			return jsonc.parse(raw or "")
		end)

		if not ok_parse or type(data) ~= "table" then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"manifest 解析失败"} })
		end

		local ssids = data.ssids or data
		if type(ssids) ~= "table" then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"manifest 结构异常：ssids 不是数组"} })
		end
		local item = nil
		for _, s in ipairs(ssids) do
			if type(s) == "table" and tonumber(s.index) == line_num then
				item = s
				break
			end
		end

		if not item then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"线路不存在"} })
		end

		-- 准备输入 TSV
		local purity_mod = require "luci.model.tkproxy.purity"
		pcall(require("nixio.fs").mkdirr, "/tmp/tkproxy")
		local in_path = "/tmp/tkproxy/purity-line" .. line_num .. ".tsv"
		local pf = io.open(in_path, "w")
		if not pf then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"无法创建临时文件"} })
		end
		-- probe 口 = tproxy 端口 + 1000
		local probe_port = (item.port or (21000 + line_num)) + 1000
		pf:write(string.format("%d\t%s\t%d\n", line_num, item.ssid or "", probe_port))
		pf:close()

		-- 执行 purity.sh
		local sys = require "luci.sys"
		local out = sys.exec("sh " .. purity_mod.PURITY_SCRIPT .. " " .. in_path .. " 2>/dev/null") or ""
		os.remove(in_path)

		if out == "" then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"体检脚本未返回结果"} })
		end

		-- 解析 TSV 输出（line, exit_ip, country, org, asn, dns_country, ipv6_leak, proxy_ok, error, hosting, proxy, mobile, reverse, dns_upstream, trace_country）
		local parts = {}
		for v in (out .. "\t"):gmatch("([^\t]*)\t") do
			table.insert(parts, v)
		end

		local idx = tonumber(parts[1])
		if not idx or idx ~= line_num then
			return send_json({ ok = false, line = line_num, verdict = "fail", verdict_text = "不可用",
				reasons = {"解析体检输出失败"} })
		end

		local metric = {
			exit_ip = parts[2] or "",
			country = parts[3] or "",
			org = parts[4] or "",
			asn = parts[5] or "",
			dns_loc = parts[6] or "",
			ipv6_leak = (parts[7] == "1"),
			proxy_ok = tonumber(parts[8]) or -1,
			err = parts[9] or "",
			hosting = (parts[10] == "true"),
			proxy_flag = (parts[11] == "true"),
			mobile = (parts[12] == "true"),
			reverse = parts[13] or "",
			dns_upstream = parts[14] or "",
			trace_country = parts[15] or "",
			-- 老版「线路体检」语义（purity.sh 第 16..21 列）
			hosting_state = parts[16] or "unknown",
			proxy_state = parts[17] or "unknown",
			latency_ms = tonumber(parts[18]),
			http_s = tonumber(parts[19]),
			channel_ok = (parts[20] == "1"),
			source = parts[21] or "",
		}
		if metric.hosting_state ~= "true" and metric.hosting_state ~= "false" then
			metric.hosting_state = "unknown"
		end
		if metric.proxy_state ~= "true" and metric.proxy_state ~= "false" then
			metric.proxy_state = "unknown"
		end

		-- ipinfo 的 org 形如「AS2914 NTT America, Inc.」、ip-api 的 as 也带公司名：
		-- ASN 只留编号，运营商只留公司名
		do
			metric.org = (metric.org:gsub("%s+$", ""))
			local asnum = metric.asn:match("^(AS%d+)")
			if asnum then metric.asn = asnum end
			local a, rest = metric.org:match("^(AS%d+)%s+(.+)$")
			if a then
				if metric.asn == "" then metric.asn = a end
				metric.org = rest
			end
		end
		metric.source = metric.source:gsub("%s+$", "")

		-- 判定（对齐 purity.lua 的逻辑）
		local rules = purity_mod.get_rules()
		-- 使用 purity 模块的统一判定逻辑，传入 ip-api.com 的字段
		local quality, kw = purity_mod.classify_ip(metric.org, metric.asn, {
			hosting = metric.hosting,
			proxy = metric.proxy_flag,
			mobile = metric.mobile,
			reverse = metric.reverse
		})
		local dns_ok = (metric.dns_loc or "") ~= "" and (metric.country or "") ~= ""
			and string.lower(metric.dns_loc) == string.lower(metric.country)

		-- 解析侧国家 vs 出口国：三态（true / false / unknown），照老版口径
		local dns_match = "unknown"
		if (metric.country or "") ~= "" and (metric.trace_country or "") ~= "" then
			if string.lower(metric.country) == string.lower(metric.trace_country) then
				dns_match = "true"
			else
				dns_match = "false"
			end
		end

		local raw_quality = quality
		local raw_ip_type = (quality == "cloud" and "云机房IP")
			or (quality == "transit" and "企业骨干IP")
			or (quality == "residential" and "住宅IP")
			or "未知"

		-- 如果已标记覆盖，强制判为 residential
		if is_override then
			quality = "residential"
		end

		local row = {
			exit_ip = metric.exit_ip,
			country = metric.country,
			isp = metric.org,
			asn = metric.asn,
			ip_type = (quality == "cloud" and "云机房IP")
				or (quality == "transit" and "企业骨干IP")
				or (quality == "residential" and "住宅IP")
				or "未知",
			ip_quality = quality,
			hosting = metric.hosting,
			proxy = metric.proxy_flag,
			mobile = metric.mobile,
			reverse = metric.reverse,
			dns_upstream = metric.dns_upstream ~= "" and metric.dns_upstream or "1.1.1.1",
			dns_country = metric.dns_loc,
			trace_country = metric.trace_country,
			dns_consistent = dns_ok,
			ipv6_leak = metric.ipv6_leak,
			delay = 0,
		}

		-- ===== 判定：照搬老版「线路体检」的三段裁决 =====
		--   miss → err（不可用）；risk → warn（有风险）；都没有 → ok（绿灯）
		--   机房 IP / 被标记为代理 属「链路合规但 IP 不干净」→ risk，不判死；
		--   没查到（unknown）同样算未确认，绝不给绿灯。
		local miss = {}
		local risk = {}
		local line_ok = (row.exit_ip ~= "")

		if not line_ok then
			if metric.channel_ok and metric.http_s then
				table.insert(risk, string.format("通道可用但当前很慢（首字节 %.1f 秒），多为线路拥堵", metric.http_s))
			else
				table.insert(miss, "出口 IP 未探测到" .. (metric.err ~= "" and ("（" .. metric.err .. "）") or ""))
			end
		end

		if line_ok and metric.proxy_ok == 0 then
			table.insert(miss, "流量没走代理：出口 IP 与路由器直连 IP 相同")
		end

		if dns_match == "false" then
			table.insert(miss, "DNS 与出口国不一致（出口 " .. (row.country ~= "" and row.country or "?")
				.. " / 解析 " .. metric.trace_country .. "）")
		end

		if metric.ipv6_leak and (rules.block_ipv6_leak or "1") == "1" then
			table.insert(miss, "检测到 IPv6 泄漏（防泄漏自检未通过）")
		end

		-- IP 质量（机房 / 代理标记）单独作为风险项
		local ip_risk = {}
		if metric.hosting_state == "true" then
			table.insert(ip_risk, "机房 IP")
		elseif metric.hosting_state == "unknown" then
			table.insert(ip_risk, "IP 类型未确认（公网库未返回该字段，需人工核验）")
		end
		if metric.proxy_state == "true" then
			table.insert(ip_risk, "被标记为代理")
		elseif metric.proxy_state == "unknown" then
			table.insert(ip_risk, "代理标记未确认（公网库未返回该字段，需人工核验）")
		end
		if dns_match == "unknown" then
			table.insert(ip_risk, "解析侧位置未探测到（不影响使用）")
		end

		local override_note = nil
		if is_override then
			override_note = "已人工标记为住宅（覆盖公网判定：" .. raw_ip_type .. "）"
			ip_risk = {}
		end
		for _, v in ipairs(ip_risk) do table.insert(risk, v) end

		local env_level = "ok"
		if #miss > 0 then
			env_level = "err"
		elseif #risk > 0 then
			env_level = "warn"
		end

		-- 表格徽章沿用 pass/risk/fail 三态，与 env_level 一一对应
		local verdict, verdict_text
		if env_level == "err" then
			verdict = "fail"
			verdict_text = "不可用"
		elseif env_level == "warn" then
			verdict = "risk"
			verdict_text = "有风险"
		else
			verdict = "pass"
			verdict_text = "可用"
		end

		-- 一句话结论（老版「探测成功：…」）
		local bits = {}
		local summary
		if line_ok then
			table.insert(bits, string.format("出口 %s（%s）", metric.exit_ip,
				metric.country ~= "" and metric.country or "?"))
			if metric.hosting_state == "true" then
				table.insert(bits, "机房 IP")
			elseif metric.hosting_state == "false" then
				table.insert(bits, "住宅/ISP IP")
			end
			if metric.proxy_state == "true" then table.insert(bits, "被标记为代理") end
			if dns_match == "true" then
				table.insert(bits, "DNS 与出口一致")
			elseif dns_match == "false" then
				table.insert(bits, "DNS 与出口不一致")
			end
			if is_override then table.insert(bits, "已人工标记为住宅") end
			summary = "探测成功：" .. table.concat(bits, "，")
		else
			summary = "探测失败：未取到出口 IP"
		end
		local level = (env_level == "ok") and "ok" or ((env_level == "warn") and "warn" or "err")

		-- 该线路真实的 DNS 链路：从 /etc/tkproxy/xray.json 里这条线路的 dns inbound
		-- （dokodemo-door，监听 10.11.N.1:530N）读它的转发目标，例如 1.1.1.1:53。
		-- 客户端的 53 被 nft 劫持到 530N，再由 xray 经该线路的 outbound 出去解析。
		-- 之前这里读的是 /tmp/resolv.conf.auto（路由器 WAN 上游，如 192.168.100.1），与线路无关，是错的。
		local dns_target, dns_port = nil, 5300 + line_num
		do
			local fh = io.open("/etc/tkproxy/xray.json", "r")
			if fh then
				local raw = fh:read("*a") or ""
				fh:close()
				local okp, cfg = pcall(jsonc.parse, raw)
				if okp and type(cfg) == "table" and type(cfg.inbounds) == "table" then
					for _, inb in ipairs(cfg.inbounds) do
						if type(inb) == "table" and tonumber(inb.port) == dns_port then
							local st = inb.settings or {}
							if type(st) == "table" and st.address and st.address ~= "" then
								dns_target = string.format("%s:%s", tostring(st.address),
									tostring(st.port or 53))
							end
							break
						end
					end
				end
			end
		end

		-- 供弹窗直接渲染的 probe 结构（字段与老版 sp_probe_json 对齐；三态用字符串）
		local probe = {
			ip = metric.exit_ip,
			cc = metric.country,
			country = metric.country,
			isp = metric.org,
			asn = metric.asn,
			hosting = metric.hosting_state,
			proxy_flag = metric.proxy_state,
			latency_ms = metric.latency_ms,
			http_s = metric.http_s,
			channel_ok = metric.channel_ok,
			source = metric.source,
			dns = {
				-- 该线路实际解析用的 DNS（经该线路代理发出）
				upstream = dns_target or "1.1.1.1:53",
				mode = string.format("dokodemo %d → 该线路代理", dns_port),
				shunt = "none",
				via_proxy = "true",
				loc = metric.trace_country,
				loc2 = "",
				match = dns_match,
				-- 路由器自身（LAN dnsmasq）的上游，仅作参考，不代表这条线路
				router_upstream = metric.dns_upstream,
			},
		}

		-- 覆盖标记说明追加到 reasons（不影响 verdict）
		if override_note then
			table.insert(miss, override_note)
		end

		-- 结论文案统一用老版那句（summary）；conclusion 保留同值兼容旧前端
		local conclusion = summary

		local out = {
			ok = true,
			line = line_num,
			verdict = verdict,
			verdict_text = verdict_text,
			exit_ip = row.exit_ip,
			country = row.country,
			isp = row.isp,
			asn = row.asn,
			ip_type = row.ip_type,
			ip_quality = row.ip_quality,
			hosting = row.hosting,
			proxy = row.proxy,
			mobile = row.mobile,
			reverse = row.reverse,
			dns_upstream = row.dns_upstream,
			dns_country = row.dns_country,
			trace_country = row.trace_country,
			dns_consistent = row.dns_consistent,
			ipv6_leak = row.ipv6_leak,
			reasons = miss,
			conclusion = conclusion,
			override = is_override and 1 or 0,
			raw_quality = raw_quality,
			-- 老版「线路体检」字段
			summary = summary,
			level = level,
			env_ok = (env_level == "ok"),
			env_level = env_level,
			env_miss = table.concat(miss, "；"),
			env_risk = table.concat(risk, "、"),
			probe = probe,
		}

		-- 结果落盘：节点/IP 没变时，刷新页面仍显示这次结果，徽章随时能点开
		do
			local fs = require "nixio.fs"
			if fs and fs.mkdirr then pcall(fs.mkdirr, "/tmp/tkproxy/web") end
			local path = "/tmp/tkproxy/web/purity-state.json"
			local all = {}
			local fh = io.open(path, "r")
			if fh then
				local raw = fh:read("*a") or ""
				fh:close()
				local okp, t = pcall(jsonc.parse, raw)
				if okp and type(t) == "table" then all = t end
			end
			local cur_line = (util.lines())[line_num] or ""
			all[tostring(line_num)] = { ts = os.time(), line = cur_line, data = out }
			local wf = io.open(path, "w")
			if wf then
				wf:write(jsonc.stringify(all))
				wf:close()
			end
		end

		return send_json(out)
	end

	if cmd == "deploy_line" then
		-- 单条线路部署：只重建这一条（名称/密码/启用/换节点）
		local idx = tonumber(http.formvalue("idx")) or 0
		local started, err = util.start_deploy_line(idx)
		if not started then
			return send_json({ ok = false, msg = err or "无法启动部署" })
		end
		-- 只把这一行标记为「已部署」，其它未部署的改动仍然保留提醒
		do
			local fs = require "nixio.fs"
			if fs and fs.mkdirr then pcall(fs.mkdirr, "/tmp/tkproxy/web") end
			local path = "/tmp/tkproxy/web/deploy-target.txt"
			local snap = {}
			local fh = io.open(path, "r")
			if fh then
				local raw = fh:read("*a") or ""
				fh:close()
				for ln in raw:gmatch("[^\r\n]+") do
					if ln ~= "" then snap[#snap + 1] = ln end
				end
			end
			local lines = util.lines()
			if lines[idx] then
				snap[idx] = lines[idx]
				local out = {}
				local n = math.max(#snap, #lines)
				for i = 1, n do
					out[#out + 1] = snap[i] or ""
				end
				-- 去掉尾部空行
				while #out > 0 and out[#out] == "" do table.remove(out) end
				local wf = io.open(path, "w")
				if wf then
					wf:write(table.concat(out, "\n") .. "\n")
					wf:close()
				end
			end
		end
		return send_json({ ok = true, msg = "已开始部署第 " .. tostring(idx) .. " 条线路" })
	end

	if cmd == "node_health" then
		-- 部署后自动体检的结果（/tmp/tkproxy/nodetest.txt）对照当前线路绑定，
		-- 返回"绑定的节点体检不通"的线路，供前端顶栏告警
		local ok_map, has_data = {}, false
		-- 部署后的自动体检写的是 nodetest-bound.txt（只测在用节点），手动体检写 nodetest.txt
		local rf = io.open("/tmp/tkproxy/nodetest-bound.txt", "r")
			or io.open("/tmp/tkproxy/nodetest.txt", "r")
		if rf then
			for ln in rf:lines() do
				local name, state = ln:match("^([^|]+)|[^|]*|[^|]*|(%u+)")
				if name then
					ok_map[name] = state
					has_data = true
				end
			end
			rf:close()
		end
		local fails, unknown, i = {}, 0, 0
		for _, L in ipairs(util.lines()) do
			i = i + 1
			local ssid = L:match("^([^|]*)")
			local node = L:match("^[^|]*|[^|]*|@?([^|]*)")
			if node and node ~= "" then
				local st = ok_map[node]
				if st == "FAIL" or st == "DNSFAIL" then
					fails[#fails + 1] = { idx = i, ssid = ssid or "", node = node,
						reason = (st == "DNSFAIL") and "dns" or "dead" }
				elseif not st then
					unknown = unknown + 1
				end
			end
		end
		return send_json({ ok = true, has_data = has_data, bound_fail = #fails, unknown = unknown, fails = fails })
	end

	if cmd == "pending" then
		-- 「已有改动 N 条」：当前清单 vs 上次部署清单（deploy-target.txt）
		local function read_list(path)
			local out = {}
			local fh = io.open(path, "r")
			if not fh then return out end
			local raw = fh:read("*a") or ""
			fh:close()
			for ln in raw:gmatch("[^\r\n]+") do
				ln = ln:gsub("^%s+", ""):gsub("%s+$", "")
				if ln ~= "" and ln:sub(1, 1) ~= "#" then out[#out + 1] = ln end
			end
			return out
		end

		local cur = util.lines()
		local snap = read_list("/tmp/tkproxy/web/deploy-target.txt")

		-- 上次部署失败（rc 非 0）→ 视为没部署成功，清单全算「未应用」
		local fs = require "nixio.fs"
		local rc_ok = true
		if fs and fs.stat and fs.stat("/tmp/tkproxy/web/deploy.rc") then
			local fh = io.open("/tmp/tkproxy/web/deploy.rc", "r")
			if fh then
				local rc = (fh:read("*a") or ""):gsub("%s", "")
				fh:close()
				if rc ~= "" and rc ~= "0" then rc_ok = false end
			end
		end
		if not rc_ok then snap = {} end

		-- 按行位置比较：一行就是一条改动（改名也算「修改」，不拆成删除+新增）
		local added, changed, removed = 0, 0, 0
		local nmax = math.max(#cur, #snap)
		for i = 1, nmax do
			local a, b = cur[i], snap[i]
			if a and b then
				if a ~= b then changed = changed + 1 end
			elseif a then
				added = added + 1
			else
				removed = removed + 1
			end
		end
		return send_json({
			ok = true,
			pending = added + changed + removed,
			added = added, changed = changed, removed = removed,
			total = #cur,
			rc_ok = rc_ok,
		})
	end
	if cmd == "purity_state" then
		-- 返回已落盘的检测结果（只返回线路行没变的，节点/链接改了自动失效）
		local jsonc = require "luci.jsonc"
		local fs = require "nixio.fs"
		local path = "/tmp/tkproxy/web/purity-state.json"
		local all = {}
		if fs and fs.stat and fs.stat(path) then
			local fh = io.open(path, "r")
			if fh then
				local raw = fh:read("*a") or ""
				fh:close()
				local okp, t = pcall(jsonc.parse, raw)
				if okp and type(t) == "table" then all = t end
			end
		end
		local lines = util.lines()
		local items = {}
		if type(all) == "table" then
			for k, v in pairs(all) do
				local idx = tonumber(k)
				if idx and type(v) == "table" and type(v.data) == "table" then
					local cur = lines[idx] or ""
					if v.line == cur then
						v.data.stale = false
						items[k] = v.data
					end
				end
			end
		end
		return send_json({ ok = true, items = items })
	end
	return send_json({ ok = false, msg = "未登记的命令，已拒绝：" .. tostring(cmd) })
end
