-- SPDX-License-Identifier: GPL-3.0
-- buerwrt-ads LuCI 控制器
--
-- 页面：资源推荐（服务 → 资源推荐）
-- 只读 /etc/config/buerwrt 的 buerwrt.ads.* 段，渲染纯本地页面；
-- 保存接口供页面上的「启用/关闭」开关使用，POST + CSRF token 校验
-- 由 Dispatcher（post()）完成，这里只处理业务字段。
--
-- 约定（与 luci-app-tkproxy 同一套）：
--   - 所有动态输出一律经 esc() 转义后再进 HTML；
--   - 不写死任何密钥，不触碰 buerwrt.ads 之外的任何配置。

module("luci.controller.buerwrtads", package.seeall)

local http = require "luci.http"
local disp = require "luci.dispatcher"
local uci_mod = require "luci.model.uci"

local function cursor()
	return uci_mod.cursor()
end

-- 读 ads 主段；config/段缺失时返回默认值（与 uci-defaults 一致），页面照常渲染
local function read_main()
	local t = {
		enabled = true,
		title = "TK 各种资源",
		subtitle = "精选 TIKTOK 相关资源与服务入口",
		url = "https://buerai.net",
		open_in_new_tab = true
	}

	local c = cursor()
	-- 注意：c:get(conf, sec) 不带 option 时只返回 .type/.name，读字段要 get_all
	local ok, main = pcall(function() return c:get_all("buerwrt", "ads") end)
	if not ok or type(main) ~= "table" then
		return t
	end

	t.enabled = (main.enabled ~= "0")
	t.title = (main.title and main.title ~= "") and main.title or t.title
	t.subtitle = (main.subtitle and main.subtitle ~= "") and main.subtitle or t.subtitle
	t.url = (main.url and main.url ~= "") and main.url or t.url
	t.open_in_new_tab = (main.open_in_new_tab ~= "0")

	return t
end

-- 读资源位列表（config item 段），只收「标题+链接」都非空的
local function read_items()
	local c = cursor()
	local items = {}

	local ok, cfg = pcall(function() return c:get_all("buerwrt") end)
	if not ok or type(cfg) ~= "table" then
		return items
	end

	for _, sec in ipairs(cfg) do
		if type(sec) == "table" and sec[".type"] == "item"
			and sec[".name"] and sec.title and sec.url
			and sec.title ~= "" and sec.url ~= "" then
			items[#items + 1] = {
				name = sec[".name"],
				title = sec.title,
				desc = sec.desc or "",
				url = sec.url,
				open_in_new_tab = (sec.open_in_new_tab ~= "0")
			}
		end
	end

	return items
end

local function send_json(t)
	http.header("Cache-Control", "no-store")
	http.prepare_content("application/json")
	http.write_json(t)
end

-- preload 配置端点：preload JS 每次页面加载都会拉一次（no-store），
-- 关闭时返回 enabled=0，preload JS 据此移除菜单项并跳过卡片注入。
function action_config()
	local main = read_main()
	send_json({
		enabled = main.enabled,
		title = main.title,
		url = main.url,
		open_in_new_tab = main.open_in_new_tab
	})
end

-- 删除 LuCI 页面树缓存（/tmp/luci-indexcache.<hash>.json）。
-- 缓存里存的是 menu.d depends 的求值结果，不清的话开关切换要等
-- rpcd/uhttpd 重启才生效。只删 /tmp 下自己这一个 glob，不碰别的东西。
local fs = require "nixio.fs"
local function drop_menu_cache()
	local ok, entries = pcall(function()
		local out = {}
		for e in fs.dir("/tmp") do
			if e:match("^luci%-indexcache%..+%.json$") then
				out[#out + 1] = e
			end
		end
		return out
	end)
	if ok and entries then
		for _, e in ipairs(entries) do
			fs.unlink("/tmp/" .. e)
		end
	end
end

-- 保存开关：只写 enabled / open_in_new_tab 两个布尔位；
-- 文案与链接继续走 uci / uci-defaults 维护，不开放网页改，缩小攻击面。
-- enabled 决定菜单可见性，而菜单树在 /tmp/luci-indexcache.* 里缓存着
-- depends 求值结果，所以保存后必须清掉缓存，下次刷新才会重新求值。
function action_save()
	local enabled = http.formvalue("enabled")
	local newtab = http.formvalue("open_in_new_tab")

	if enabled ~= "0" and enabled ~= "1" then
		return send_json({ ok = false, msg = "enabled 取值非法" })
	end

	local c = cursor()
	if not c:get_all("buerwrt", "ads") then
		-- 主段约定：section 名 'ads'、类型 'main'（与 uci-defaults 一致）
		c:set("buerwrt", "ads", "main")
	end
	c:set("buerwrt", "ads", "enabled", enabled)
	if newtab == "0" or newtab == "1" then
		c:set("buerwrt", "ads", "open_in_new_tab", newtab)
	end

	if not c:save("buerwrt") then
		return send_json({ ok = false, msg = "写入 uci 失败" })
	end
	if not c:commit("buerwrt") then
		-- 提交失败：丢掉暂存区的半成品，避免与磁盘状态不一致
		pcall(function() c:revert("buerwrt") end)
		return send_json({ ok = false, msg = "提交 uci 失败" })
	end

	drop_menu_cache()

	send_json({ ok = true, enabled = (enabled == "1") })
end

function action_page()
	local main = read_main()

	-- 关闭后整页不可达（配合菜单隐藏）
	if not main.enabled then
		http.status(404, "Not Found")
		return
	end

	luci.template.render("buerwrtads/page", {
		main = main,
		items = read_items()
	})
end

function index()
	-- 主页面节点「admin/services/buerwrtads」由 menu.d JSON 注册：
	-- build_pagetree 里 controllers 在 menu.d 之后处理，index() 若重复注册
	-- 会覆盖 JSON 节点的 spec，所以这里只挂子端点。
	entry({ "admin", "services", "buerwrtads", "config" }, call("action_config")).leaf = true
	entry({ "admin", "services", "buerwrtads", "save" }, post("action_save")).leaf = true
end
