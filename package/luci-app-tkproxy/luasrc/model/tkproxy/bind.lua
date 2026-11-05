-- SPDX-License-Identifier: GPL-3.0
-- tkproxy 绑定视图：SSID → 节点 的行内绑定界面

local util = require "luci.model.tkproxy.util"
local gen = require "luci.model.tkproxy.gen"

local M = {}

-- 主机打码：只留前 2 段 + .***
local function mask_host(h)
	h = tostring(h or "")
	if h == "" then return "" end
	-- IPv4: 取前两段
	if h:match("^%d+%.%d+%.%d+%.%d+$") then
		local seg = h:match("^(%d+%.%d+)%.")
		if seg then return seg .. ".***" end
	end
	-- 域名/其他：前 2 字符 + *** + 后 2 字符
	if #h <= 4 then return "****" end
	return h:sub(1, 2) .. "***"
end

-- 返回绑定视图的行列表
-- 每行：{idx, ssid, band, enabled, node_name, node_type, node_host, bound, warn}
-- 取一行用于展示/统计：即使「启用但未绑定」，也要返回行对象，
-- 否则这类行会从绑定表与统计里消失（用户永远绑不上）。
local function row_of(line, i, node_pool)
	local row = util.parse_line(line, i, node_pool)
	if row then return row end
	local ssid, band, link, en = util.split_line(line)
	if not ssid or (link ~= nil and link ~= "") then
		return nil
	end
	return {
		idx = i,
		ssid = ssid,
		band = band or "both",
		band_label = (band == "5g") and "5G" or ((band == "2g") and "2.4G" or "双频"),
		link = "",
		node_name = "",
		node_type = "",
		node_server = "",
		is_ref = false,
		enabled = not (en == "0" or en == "false" or en == "off"),
	}
end

function M.rows()
	local lines = util.lines()
	local node_pool = util.nodes()
	local out = {}

	-- 统计每个节点被哪些 SSID 使用
	local usage = {}
	for i, line in ipairs(lines) do
		local ssid, band, link = util.split_line(line)
		if link and link:sub(1, 1) == "@" then
			local name = link:sub(2):gsub("^%s+", ""):gsub("%s+$", "")
			if name ~= "" then
				usage[name] = usage[name] or {}
				table.insert(usage[name], ssid)
			end
		end
	end

	for i, line in ipairs(lines) do
		local row = row_of(line, i, node_pool)
		if row then
			local node_name = ""
			local node_type = ""
			local node_host = ""
			local bound = false
			local warn = ""

			if row.link and row.link ~= "" then
				if row.is_ref then
					-- @节点名引用
					node_name = row.node_name or ""
					local node = util.node_by_name(node_name)
					if node then
						local ob = gen.parse_node(node.link)
						if ob then
							node_type = tostring(ob.type or "")
							node_host = mask_host(tostring(ob.server or ""))
						end
						bound = true
						-- 共用检测
						if usage[node_name] and #usage[node_name] > 1 then
							local others = {}
							for _, s in ipairs(usage[node_name]) do
								if s ~= row.ssid then
									table.insert(others, s)
								end
							end
							if #others > 0 then
								warn = string.format("与 %s 共用出口（仅供参考）", others[1])
							end
						end
					end
				else
					-- 直连链接
					bound = true
					node_type = row.node_type or ""
					node_host = mask_host(row.node_server or "")
				end
			end

			out[#out + 1] = {
				idx = i,
				ssid = row.ssid or "",
				band = row.band or "both",
				enabled = row.enabled ~= false,
				node_name = node_name,
				node_type = node_type,
				node_host = node_host,
				bound = bound,
				warn = warn,
			}
		end
	end

	return out
end

-- 返回节点池：{name, kind, host_masked, used_by={ssid,...}}
function M.pool()
	local nodes = util.nodes()
	local lines = util.lines()
	local node_pool_map = util.nodes()

	-- 统计使用情况
	local usage = {}
	for i, line in ipairs(lines) do
		local ssid, _, link = util.split_line(line)
		if link and link:sub(1, 1) == "@" then
			local name = link:sub(2):gsub("^%s+", ""):gsub("%s+$", "")
			if name ~= "" then
				usage[name] = usage[name] or {}
				table.insert(usage[name], ssid)
			end
		end
	end

	local out = {}
	for _, n in ipairs(nodes) do
		local ob = gen.parse_node(n.link)
		local kind = ""
		local host = ""
		if ob then
			kind = tostring(ob.type or "")
			host = mask_host(tostring(ob.server or ""))
		end
		out[#out + 1] = {
			name = n.name,
			kind = kind,
			host_masked = host,
			used_by = usage[n.name] or {},
		}
	end

	return out
end

-- 设置绑定：只改第 idx 行的节点字段（保持启用位不变）
-- node_name 为空字符串时解绑
-- BLK-09：整个读-改-写在锁内完成
function M.set_bind(idx, node_name)
	idx = tonumber(idx) or 0
	return util.with_lock(function()
		local lines = util.lines()
		if idx < 1 or idx > #lines then
			return nil, "行索引越界"
		end

		local line = lines[idx]
		local ssid, band, link, en = util.split_line(line)
		if not ssid then
			return nil, "行格式错误"
		end

		-- 校验节点存在
		node_name = (node_name or ""):gsub("^%s+", ""):gsub("%s+$", "")
		if node_name ~= "" then
			local node = util.node_by_name(node_name)
			if not node then
				return nil, string.format("节点 %s 不存在", node_name)
			end
		end

		-- 重建行：SSID|频段|节点|启用|本条密码（第 5 段必须保留，否则换节点会丢密码）
		local new_link = (node_name ~= "" and ("@" .. node_name)) or ""
		local new_line = string.format("%s|%s|%s", ssid, band or "both", new_link)
		if en then
			new_line = new_line .. "|" .. en
		end
		local keep_key = util.line_key(line)
		if keep_key ~= "" then
			new_line = new_line .. "|" .. keep_key
		end

		lines[idx] = new_line

		-- 保存前校验：仅禁止节点共用（不做完整性校验）
		local check = util.validate_unique_nodes(lines, false)
		if not check.ok then
			return nil, check.msg
		end

		local ok, err = util.save_lines_locked(lines)
		if not ok then
			return nil, err or "保存失败"
		end

		return new_line
	end)
end

-- 切换启用位
function M.toggle(idx, enabled)
	idx = tonumber(idx) or 0
	return util.with_lock(function()
		local lines = util.lines()
		if idx < 1 or idx > #lines then
			return nil, "行索引越界"
		end

		local line = lines[idx]
		local ssid, band, link, _ = util.split_line(line)
		if not ssid then
			return nil, "行格式错误"
		end

		local en_flag = enabled and "1" or "0"
		local new_line = string.format("%s|%s|%s|%s", ssid, band or "both", link or "", en_flag)
		-- 第 5 段（本条密码）必须原样保留
		local keep_key1 = util.line_key(line)
		if keep_key1 ~= "" then new_line = new_line .. "|" .. keep_key1 end

		lines[idx] = new_line

		-- 保存前校验：仅禁止节点共用（不做完整性校验）
		local check = util.validate_unique_nodes(lines, false)
		if not check.ok then
			return nil, check.msg
		end

		local ok, err = util.save_lines_locked(lines)
		if not ok then
			return nil, err or "保存失败"
		end

		return new_line
	end)
end

-- 自动绑定：对已启用但未绑定的行，按池顺序分配节点
-- 允许共用：池用完时从池头开始复用
-- 删除某一行线路（只动清单，不触发部署）
function M.remove_line(idx)
	idx = tonumber(idx) or 0
	return util.with_lock(function()
		local lines = util.lines()
		if idx < 1 or idx > #lines then
			return nil, "行索引越界"
		end
		local ssid = util.split_line(lines[idx])
		table.remove(lines, idx)
		local ok, err = util.save_lines_locked(lines)
		if not ok then
			return nil, err or "保存失败"
		end
		return true, ssid or ""
	end)
end

-- 取某条线路的当前密码：优先本条自定义（第 5 段）→ 设备上该 SSID 实际生效值 → 全局密码
function M.line_info(idx)
	idx = tonumber(idx) or 0
	local lines = util.lines()
	if idx < 1 or idx > #lines then
		return nil, "行索引越界"
	end
	local ssid, band, link, en = util.split_line(lines[idx])
	local key = util.line_key(lines[idx])
	local src = "line"
	if key == "" then
		-- 部署后设备上才有该 SSID，读它当前的 key（服务端渲染的段名是 tkpNN_2g / tkpNN_5g）
		local ok_c, c = pcall(require, "luci.model.uci")
		if ok_c and c then
			local cur = c.cursor()
			local base = string.format("tkp%02d", idx)
			for _, b in ipairs({ "2g", "5g" }) do
				local k = cur:get("wireless", base .. "_" .. b, "key")
				if k and k ~= "" then key = k; src = "device"; break end
			end
		end
	end
	if key == "" then
		local g = util.get_wifi_password()
		if g and g ~= "" then key = g; src = "global" end
	end
	return {
		idx = idx, ssid = ssid, band = band, enabled = (en ~= "0"),
		key = key, key_source = src,
		is_ref = (link and link:sub(1, 1) == "@"),
	}
end

-- 二次编辑单条线路：SSID 名 / 频段 / 启用位（只改清单，不触发部署）
-- opts = { ssid=, band=, enabled= }
function M.update_line(idx, opts)
	idx = tonumber(idx) or 0
	opts = opts or {}
	return util.with_lock(function()
		local lines = util.lines()
		if idx < 1 or idx > #lines then
			return nil, "行索引越界"
		end
		local ssid, band, link, en = util.split_line(lines[idx])
		if not ssid then
			return nil, "该行格式无法解析"
		end

		local new_ssid = tostring(opts.ssid or ssid):gsub("^%s+", ""):gsub("%s+$", "")
		if new_ssid == "" then return nil, "SSID 不能为空" end
		if #new_ssid > 32 then return nil, "SSID 最长 32 字节" end
		if new_ssid:find("[|\r\n]") then return nil, "SSID 不能包含竖线或换行" end

		for i, l in ipairs(lines) do
			if i ~= idx then
				local s2 = util.split_line(l)
				if s2 == new_ssid then
					return nil, "SSID 已存在：" .. new_ssid
				end
			end
		end

		local new_band = tostring(opts.band or band or "2g"):lower()
		if new_band ~= "2g" and new_band ~= "5g" and new_band ~= "both" then
			return nil, "频段只能是 2g / 5g / both"
		end

		local new_en = (en == "0") and "0" or "1"
		if opts.enabled ~= nil then
			new_en = (tostring(opts.enabled) == "1") and "1" or "0"
		end

		-- 第 5 段：本条线路自己的 WiFi 密码（nil=不改；""=清除，回退全局）
		local cur_key = util.line_key(lines[idx])
		local new_key = cur_key
		if opts.password ~= nil then
			local pw = tostring(opts.password)
			if pw ~= "" then
				if #pw < 8 then return nil, "WiFi 密码至少 8 位（WPA2 要求）" end
				if #pw > 63 then return nil, "WiFi 密码最长 63 位" end
				if pw:find("[|\r\n]") then return nil, "密码不能包含竖线或换行" end
			end
			new_key = pw
		end

		if new_key ~= "" then
			lines[idx] = string.format("%s|%s|%s|%s|%s", new_ssid, new_band, link or "", new_en, new_key)
		else
			lines[idx] = string.format("%s|%s|%s|%s", new_ssid, new_band, link or "", new_en)
		end
		local ok, err = util.save_lines_locked(lines)
		if not ok then
			return nil, err or "保存失败"
		end
		return lines[idx]
	end)
end

-- 清空全部线路（只动清单，不触发部署）
function M.clear_lines()
	return util.with_lock(function()
		local lines = util.lines()
		local n = #lines
		local ok, err = util.save_lines_locked({})
		if not ok then
			return nil, err or "保存失败"
		end
		return true, n
	end)
end

-- 清空全部节点（BLK-11：阻止清空仍被引用的节点）
function M.clear_nodes()
	return util.with_lock(function()
		local nodes = util.nodes()
		local n = #nodes

		-- 检查是否有线路仍在引用节点池中的节点
		local lines = util.lines()
		local refs = {}
		for i, line in ipairs(lines) do
			local ssid, _, link = util.split_line(line)
			if link and link:sub(1, 1) == "@" then
				local name = link:sub(2):gsub("^%s+", ""):gsub("%s+$", "")
				if name ~= "" then
					refs[#refs + 1] = {line = i, ssid = ssid, node = name}
				end
			end
		end

		if #refs > 0 then
			local msg = string.format("有 %d 条线路仍在引用节点，请先解绑或删除这些线路：", #refs)
			for i, r in ipairs(refs) do
				if i <= 3 then
					msg = msg .. string.format("\n  - 第 %d 行 %s → @%s", r.line, r.ssid, r.node)
				elseif i == 4 then
					msg = msg .. string.format("\n  …… 及其他 %d 条", #refs - 3)
					break
				end
			end
			return nil, msg
		end

		local ok, err = util.save_nodes_locked({})
		if not ok then
			return nil, err or "保存失败"
		end
		return true, n
	end)
end

-- 读取 nodetest.sh 落盘的体检结果：节点名 → OK/FAIL。
-- 没体检过 / 文件不存在时返回空表（不阻断自动绑定）。
local function nodetest_results()
	local out = {}
	local fh = io.open("/tmp/tkproxy/nodetest.txt", "r")
	if not fh then return out end
	for line in fh:lines() do
		-- 汇总行（available=X / total=X）不含竖线，本就走不到匹配分支；
		-- 显式跳过防未来格式变化误识别
		if not (line:match("^available=") or line:match("^total=")) then
			-- 格式：名称|IP|国家|OK/FAIL
			local name, status = line:match("^([^|]+)|[^|]*|[^|]*|([^|]+)$")
			if name and status then out[name] = status end
		end
	end
	fh:close()
	return out
end

-- 构造分层节点池：体检 OK → 未体检 → 体检 FAIL。
-- 返回 排好序的可用节点名列表、OK 数、未知数（用于统计分到 FAIL 节点的线路数）。
local function build_prioritized_pool(nodes, used_names, test_results)
	local free_ok, free_unknown, free_fail = {}, {}, {}
	local seen = {}
	for _, n in ipairs(nodes) do
		if not used_names[n.name] and not seen[n.name] then
			seen[n.name] = true
			local st = test_results[n.name]
			if st == "OK" then
				free_ok[#free_ok + 1] = n.name
			elseif st == "FAIL" then
				free_fail[#free_fail + 1] = n.name
			else
				free_unknown[#free_unknown + 1] = n.name
			end
		end
	end
	local free = {}
	for _, t in ipairs({ free_ok, free_unknown, free_fail }) do
		for _, name in ipairs(t) do free[#free + 1] = name end
	end
	return free, #free_ok, #free_unknown
end

function M.auto_bind()
	return util.with_lock(function()
		local lines = util.lines()
		local nodes = util.nodes()

		local unbound = {}
		local used = {}
		for i, line in ipairs(lines) do
			local ssid, band, link, en = util.split_line(line)
			if ssid then
				local enabled = not (en == "0" or en == "false" or en == "off")
				if link and link:sub(1, 1) == "@" then
					local name = link:sub(2):gsub("^%s+", ""):gsub("%s+$", "")
					if name ~= "" then used[name] = true end
				elseif (link == nil or link == "") then
					-- 必须将所有未绑定线路（含禁用线路）加入待分配列表
					unbound[#unbound + 1] = { idx = i, ssid = ssid, band = band or "both", enabled = enabled }
				end
			end
		end

		if #unbound == 0 then
			-- 检查是否已有共用节点
			local check = util.validate_unique_nodes(lines)
			if not check.ok then
				return { ok = false, msg = check.msg }
			end
			return { ok = true, bound = 0, shared = {} }
		end

		-- 按节点名去重，构造可用节点集合；体检 OK 优先、FAIL 兜底
		local test = nodetest_results()
		local free, n_ok, n_unknown = build_prioritized_pool(nodes, used, test)

		local need = #unbound
		local avail = #free
		if avail < need then
			return {
				ok = false,
				msg = string.format("节点不足：需要 %d 个，当前可用 %d 个，缺 %d 个", need, avail, need - avail)
			}
		end

		-- 分配：体检通过的优先，其次未体检的，最后才是已知不通的
		local dead_bound = 0
		for k, u in ipairs(unbound) do
			local name = free[k]
			local keep_k = util.line_key(lines[u.idx])
			local nl = string.format("%s|%s|@%s|%s", u.ssid, u.band, name, u.enabled and "1" or "0")
			if keep_k ~= "" then nl = nl .. "|" .. keep_k end
			lines[u.idx] = nl
			-- 分到已知不通节点的线路数（供前端提示「本次绑定了 N 个已知不通的节点」）
			if k > n_ok + n_unknown then dead_bound = dead_bound + 1 end
		end

		-- 保存前再次检查唯一性（防止在分配过程中产生共用）
		local check = util.validate_unique_nodes(lines)
		if not check.ok then
			return { ok = false, msg = check.msg }
		end

		local ok, err = util.save_lines_locked(lines)
		if not ok then
			return nil, err or "保存失败"
		end
		return { ok = true, bound = #unbound, shared = {}, dead_bound = dead_bound }
	end)
end

-- 统计信息
function M.stats()
	local lines = util.lines()
	local node_pool = util.nodes()
	local total = #lines
	local enabled = 0
	local bound = 0
	local unbound = 0

	-- 统计共用组数
	local usage = {}
	for i, line in ipairs(lines) do
		local row = row_of(line, i, node_pool)
		if row then
			if row.enabled ~= false then
				enabled = enabled + 1
			end
			if row.link and row.link ~= "" then
				bound = bound + 1
				if row.is_ref then
					local name = row.node_name or ""
					usage[name] = (usage[name] or 0) + 1
				end
			elseif row.enabled ~= false then
				unbound = unbound + 1
			end
		end
	end

	local shared_groups = 0
	for _, count in pairs(usage) do
		if count > 1 then
			shared_groups = shared_groups + 1
		end
	end

	return {
		total = total,
		enabled = enabled,
		bound = bound,
		unbound = unbound,
		pool = #node_pool,
		shared_groups = shared_groups,
	}
end

return M
