-- SPDX-License-Identifier: GPL-3.0
-- TikTok 纯净度体检规则与判定

local uci_mod = require "luci.model.uci"
local sys = require "luci.sys"
local fs = require "nixio.fs"
local jsonc = require "luci.jsonc"

local M = {}

M.PURITY_SCRIPT = "/usr/libexec/tkproxy/purity.sh"

-- 默认规则
M.DEFAULTS = {
	allow_countries = "",           -- 空=不限制；填 US,JP,SG 则只认这些
	require_residential = "1",      -- 机房 IP 直接判不可用
	require_unique_ip = "1",        -- 出口 IP 重复判不可用
	require_dns_consistent = "1",   -- DNS 国家不一致判不可用
	block_ipv6_leak = "1",          -- IPv6 泄漏判不可用
	min_pass_items = "3",           -- 满分 4，至少通过 3 项
}

-- 规则说明文案
M.RULE_LABELS = {
	allow_countries = "允许的国家（逗号分隔，空=不限制）",
	require_residential = "要求住宅 IP（机房 IP 直接不可用）",
	require_unique_ip = "要求出口 IP 唯一（重复直接不可用）",
	require_dns_consistent = "要求 DNS 国家一致（不一致直接不可用）",
	block_ipv6_leak = "阻止 IPv6 泄漏（泄漏直接不可用）",
	min_pass_items = "最低通过项数（满分 4：国家/住宅/DNS/无撞车）",
}

-- 不通过时的提示文案
M.FAIL_REASONS = {
	country_not_allowed = "出口国不在允许列表",
	is_datacenter = "检测到机房 IP（非住宅）",
	dns_mismatch = "DNS 解析国家与出口 IP 国家不一致",
	ip_duplicated = "出口 IP 与其他线路重复",
	ipv6_leak = "检测到 IPv6 泄漏",
	min_items_not_met = "通过项数不足最低要求",
	probe_failed = "探测失败，无法获取出口信息",
}

-- ---------------------------------------------------------------------------
-- UCI 读写
-- ---------------------------------------------------------------------------

local function cursor()
	return uci_mod.cursor()
end

-- 读取规则
function M.get_rules()
	local c = cursor()
	local rules = {}
	for k, def in pairs(M.DEFAULTS) do
		rules[k] = c:get("tkproxy", "purity", k) or def
	end
	return rules
end

-- 保存规则
function M.save_rules(rules)
	local c = cursor()
	-- 确保 purity section 存在
	if not c:get("tkproxy", "purity") then
		c:set("tkproxy", "purity", "purity")
	end
	for k, v in pairs(rules) do
		if M.DEFAULTS[k] ~= nil then
			c:set("tkproxy", "purity", k, tostring(v))
		end
	end
	return c:commit("tkproxy")
end

-- ---------------------------------------------------------------------------
-- 体检执行与结果解析
-- ---------------------------------------------------------------------------

-- 执行体检脚本，返回 JSON 数组
-- ---------------------------------------------------------------------------
-- 采集 + 判定
--   shell 只负责并行抓取（TSV），这里负责机房判定、撞车、按规则给结论
-- ---------------------------------------------------------------------------

-- 三档 IP 质量分类
-- 云厂商/托管机房 ASN（命中即 cloud）
M.CLOUD_ASN = {
	["AS16509"] = "AWS",
	["AS14618"] = "AWS",
	["AS15169"] = "Google",
	["AS396982"] = "GCP",
	["AS8075"] = "Azure",
	["AS14061"] = "DigitalOcean",
	["AS20473"] = "Vultr",
	["AS63949"] = "Linode",
	["AS24940"] = "Hetzner",
	["AS16276"] = "OVH",
	["AS51167"] = "Contabo",
	["AS30058"] = "FDCservers",
	["AS45102"] = "AlibabaCloud",
	["AS132203"] = "TencentCloud",
	["AS55990"] = "HuaweiCloud",
	["AS9009"] = "M247",
	["AS36352"] = "ColoCrossing",
	["AS46844"] = "Sharktech",
	["AS62240"] = "Clouvider",
}

-- 云/机房关键词（命中即 cloud）
M.CLOUD_KEYWORDS = {
	"amazon", "aws", "google", "microsoft", "azure", "alibaba", "aliyun", "tencent",
	"huawei cloud", "digitalocean", "vultr", "linode", "hetzner", "ovh", "contabo", "m247", "fdcservers",
	"choopa", "colocation", "datacenter", "data center", "datacentre", "hosting", "cloud", "vps", "vserver", "idc",
	"dedicated server", "colo", "sharktech", "nocix", "psychz", "quadranet", "multacom",
	"oracle", "gcore", "kamatera", "hostwinds", "hostinger", "upcloud",
}

-- 骨干/企业运营商关键词（命中即 transit）
M.TRANSIT_KEYWORDS = {
	"ntt", "gtt", "cogent", "lumen", "level3", "level 3", "pccw", "telstra",
	"hurricane", "arelion", "telia", "cogentco", "megapath", "verizon business", "at&t business",
	"china telecom", "china unicom", "china mobile", "kt corp", "kddi", "softbank",
	"transit", "backbone", "ip transit",
}

-- 住宅 IP 提示（命中即 residential）
M.RESIDENTIAL_HINTS = {
	"pppoe", "dynamic", "dsl", "adsl", "ftth", "fiber", "broadband", "cable",
	"comcast", "charter", "cox", "centurylink", "frontier", "orange", "deutsche telekom", "telefonica",
	"virgin media", "sky broadband", "j:com", "フレッツ", "so-net", "ocn", "hinet", "resident",
	-- 美国家宽巨头特征词（2026-11-02 补充，对应 selftest AT&T Internet Services 用例）
	"at&t internet", "att internet", "spectrum", "verizon fios", "cox communications",
	"xfinity", "frontier communications", "google fiber",
}

-- IP 质量三档判定（cloud|transit|residential|unknown）
-- opts: { hosting, proxy, mobile, reverse } 来自 ip-api.com 的字段
-- 返回：quality, reason
function M.classify_ip(org, asn, opts)
	opts = opts or {}
	local hosting = opts.hosting
	local proxy_flag = opts.proxy
	local reverse = opts.reverse

	-- 1. hosting==true 或 proxy==true → cloud
	if hosting == true or hosting == "true" or hosting == "1" then
		return "cloud", "hosting=true"
	end
	if proxy_flag == true or proxy_flag == "true" or proxy_flag == "1" then
		return "cloud", "proxy=true"
	end

	-- 2. ASN 命中云厂商白名单 → cloud
	local asn_str = tostring(asn or "")
	local asn_num = asn_str:match("^(AS%d+)")
	if asn_num then
		asn_num = string.upper(asn_num)
		if M.CLOUD_ASN[asn_num] then
			return "cloud", asn_num .. " " .. M.CLOUD_ASN[asn_num]
		end
	end

	-- 3. ISP/org 命中云/机房关键词 → cloud
	local s = string.lower(tostring(org or ""))
	for _, kw in ipairs(M.CLOUD_KEYWORDS) do
		if s:find(kw, 1, true) then
			return "cloud", "isp:" .. kw
		end
	end

	-- 4. reverse/ISP/org 命中住宅提示 → residential
	local combined = string.lower(tostring(reverse or "") .. " " .. tostring(org or ""))
	for _, kw in ipairs(M.RESIDENTIAL_HINTS) do
		if combined:find(kw, 1, true) then
			return "residential", "isp:" .. kw
		end
	end

	-- 5. ISP/org 命中骨干/企业运营商 → transit
	for _, kw in ipairs(M.TRANSIT_KEYWORDS) do
		if s:find(kw, 1, true) then
			return "transit", "isp:" .. kw
		end
	end

	-- 6. 其余 → unknown
	return "unknown", "无法确认"
end

-- 兼容包装：is_datacenter 返回布尔 + 原因（cloud == datacenter）
function M.is_datacenter(org, asn, opts)
	local quality, reason = M.classify_ip(org, asn, opts)
	return (quality == "cloud"), reason
end

local function read_manifest()
	local f = io.open("/etc/tkproxy/manifest.json", "r")
	if not f then return nil, "manifest.json 不存在（请先部署）" end
	local raw = f:read("*a")
	f:close()
	local ok, data = pcall(jsonc.parse, raw or "")
	if not ok or type(data) ~= "table" then
		return nil, "manifest.json 解析失败"
	end
	local arr = data.ssids or data
	if type(arr) ~= "table" then return nil, "manifest.json 结构不认识" end
	local list = {}
	for i, s in ipairs(arr) do
		if type(s) == "table" and s.ssid then
			local idx = tonumber(s.index) or i
			list[#list + 1] = {
				idx = idx,
				ssid = tostring(s.ssid),
				band = tostring(s.band or ""),
				port = tonumber(s.port) or (21000 + idx),
			}
		end
	end
	return list
end

function M.run_check()
	if not fs.access(M.PURITY_SCRIPT, "x") then
		return nil, "体检脚本不存在或不可执行"
	end
	local list, lerr = read_manifest()
	if not list then return nil, lerr end
	if #list == 0 then return nil, "清单为空（请先部署）" end

	local rules = M.get_rules()
	pcall(fs.mkdirr, "/tmp/tkproxy")
	local pairs_path = "/tmp/tkproxy/purity-in.tsv"
	local pf = io.open(pairs_path, "w")
	if not pf then return nil, "无法写入临时文件" end
	for _, it in ipairs(list) do
		-- 体检走「tproxy 端口 + 1000」的专用 socks 入站
		pf:write(string.format("%d\t%s\t%d\n", it.idx, it.ssid, it.port + 1000))
	end
	pf:close()

	local out = sys.exec("sh " .. M.PURITY_SCRIPT .. " " .. pairs_path .. " 2>/dev/null") or ""
	if out == "" then
		return nil, "体检没有输出（请确认已部署且 Xray 正在运行）"
	end

	local metric = {}
	for line in out:gmatch("[^\n]+") do
		-- 解析扩展后的 TSV：增加 hosting/proxy/reverse 三个字段
		local parts = {}
		for v in (line .. "\t"):gmatch("([^\t]*)\t") do
			table.insert(parts, v)
		end
		local idx = tonumber(parts[1])
		if idx then
			metric[idx] = {
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
				reverse = parts[12] or "",
			}
		end
	end

	local items, by_ip = {}, {}
	for _, it in ipairs(list) do
		local m = metric[it.idx] or { err = "未返回探测结果" }

		-- 三档 IP 质量判定
		local ip_quality, quality_reason = M.classify_ip(
			m.org, m.asn, { hosting = m.hosting, proxy = m.proxy_flag, reverse = m.reverse })

		local dns_ok = (m.dns_loc or "") ~= "" and (m.country or "") ~= ""
			and string.lower(m.dns_loc) == string.lower(m.country)

		local row = {
			idx = it.idx,
			ssid = it.ssid,
			band = it.band,
			exit_ip = m.exit_ip or "",
			country = m.country or "",
			org = m.org or "",
			asn = m.asn or "",
			reverse = m.reverse or "",
			dns_country = m.dns_loc or "",
			ip_quality = ip_quality,
			ip_quality_reason = quality_reason or "",
			-- 保留兼容字段（旧逻辑里的 is_datacenter）
			is_datacenter = (ip_quality == "cloud"),
			datacenter_keyword = (ip_quality == "cloud") and quality_reason or "",
			dns_consistent = dns_ok,
			ipv6_leak = (m.ipv6_leak == true),
			ip_duplicated = false,
			proxy_ok = (m.proxy_ok or -1),
			-- 线路是否通：只看有没有拿到出口 IP（与运营环境分开判定）
			line_ok = (m.exit_ip or "") ~= "",
			err = m.err or "",
		}
		items[#items + 1] = row
		if row.exit_ip ~= "" then
			by_ip[row.exit_ip] = by_ip[row.exit_ip] or {}
			table.insert(by_ip[row.exit_ip], row.ssid)
		end
	end

	for _, row in ipairs(items) do
		local g = by_ip[row.exit_ip]
		if row.exit_ip ~= "" and g and #g > 1 then
			row.ip_duplicated = true
			local others = {}
			for _, ssid in ipairs(g) do
				if ssid ~= row.ssid then table.insert(others, ssid) end
			end
			row.dup_with = others
		end
	end

	-- 判定分两维（对齐老插件 ssidproxy probe/leak 的语义）：
	--   miss（必须通过）→ 运营环境「不可用」；risk（风险项）→ 「有风险」
	for _, row in ipairs(items) do
		local miss, risk = {}, {}

		-- 1) 线路本身：拿不到出口 IP 就是不通（单独一列显示，这里也记 miss）
		if not row.line_ok then
			table.insert(miss, { cat = "line", text = "线路不通：未取到出口 IP"
				.. (row.err ~= "" and ("（" .. row.err .. "）") or "") })
		end

		-- 2) 是否真的走代理（规则是否生效）
		if row.line_ok then
			if row.proxy_ok == 0 then
				table.insert(miss, { cat = "rule",
					text = "流量没走代理：出口 IP 与路由器直连 IP 相同（分流规则可能未生效）" })
			elseif row.proxy_ok == -1 then
				table.insert(risk, { cat = "rule", text = "无法确认是否经代理（取不到路由器直连 IP）" })
			end
		end

		-- 3) 允许国家
		local allow = trim2(rules.allow_countries or "")
		local country_ok
		if allow == "" then
			country_ok = (row.country ~= "")
		else
			country_ok = false
			for c in allow:gmatch("[^,%s]+") do
				if string.upper(c) == string.upper(row.country) then country_ok = true end
			end
		end
		if row.line_ok and not country_ok then
			table.insert(miss, { cat = "ip", text = "出口国不在允许列表"
				.. (row.country ~= "" and ("（" .. row.country .. "）") or "") })
		end

		-- 4) IP 质量：三档判定
		if row.line_ok then
			if row.ip_quality == "cloud" then
				table.insert(miss, { cat = "ip", text = "云机房 IP（不可用于 TikTok 运营）："
					.. (row.ip_quality_reason ~= "" and row.ip_quality_reason or "unknown") })
			elseif row.ip_quality == "transit" then
				table.insert(miss, { cat = "ip", text = "企业/骨干线路 IP（非家宽住宅，风控较高）："
					.. (row.ip_quality_reason ~= "" and row.ip_quality_reason or "unknown") })
			elseif row.ip_quality == "unknown" then
				table.insert(risk, { cat = "ip", text = "无法确认是否住宅 IP，建议人工核实" })
			end
			-- residential 不扣分，继续检查其他项
		end

		-- 5) DNS：能取到解析国就必须与出口国一致；取不到只算「待确认」（不算必修）
		if row.line_ok then
			if (row.dns_country or "") == "" then
				table.insert(risk, { cat = "dns",
					text = "DNS 归属未确认：本次没取到解析侧国家，不影响使用，建议复测" })
			elseif not row.dns_consistent then
				table.insert(miss, { cat = "dns", text = "DNS 问题：解析国家与出口国不一致"
					.. "（出口 " .. (row.country ~= "" and row.country or "?")
					.. " / 解析 " .. row.dns_country .. "）" })
			end
		end

		-- 6) IPv6 泄漏
		if row.ipv6_leak then
			table.insert(miss, { cat = "rule", text = "IPv6 泄漏：请求可绕过代理走 IPv6" })
		end

		-- 7) 出口 IP 重复（共用节点）→ 仅提示，不影响结论
		if row.ip_duplicated then
			table.insert(risk, { cat = "ip", text = "出口 IP 与其他线路重复（"
				.. table.concat(row.dup_with or {}, "、") .. "），供参考" })
		end

		-- 结构化检查项（弹窗按这个逐条渲染，对齐老插件的分区+状态标签）
		local function has(list, cat, kw)
			for _, x in ipairs(list) do
				if x.cat == cat and (not kw or x.text:find(kw, 1, true)) then return x.text end
			end
			return nil
		end
		local checks = {}
		local line_down = not row.line_ok

		checks[#checks + 1] = {
			name = "线路连通",
			status = row.line_ok and "pass" or "fail",
			detail = row.line_ok
				and string.format("出口 IP %s（%s）", row.exit_ip, row.country ~= "" and row.country or "?")
				or ("未取到出口 IP" .. (row.err ~= "" and ("：" .. row.err) or "")),
		}

		local proxy_bad = has(miss, "rule", "没走代理")
		local proxy_unk = has(risk, "rule", "无法确认是否经代理")
		checks[#checks + 1] = {
			name = "是否经代理",
			status = line_down and "na" or (proxy_bad and "fail" or (proxy_unk and "risk" or "pass")),
			detail = line_down and "线路不通，未检测"
				or (proxy_bad or proxy_unk or "出口 IP 与路由器直连 IP 不同，确认走了代理"),
		}

		local dc_txt = has(miss, "ip", "云机房") or has(miss, "ip", "企业/骨干") or has(risk, "ip", "无法确认")
		if row.ip_quality == "cloud" then
			checks[#checks + 1] = {
				name = "IP 质量",
				status = "fail",
				detail = "云机房 IP" .. (row.ip_quality_reason ~= "" and ("：" .. row.ip_quality_reason) or ""),
			}
		elseif row.ip_quality == "transit" then
			checks[#checks + 1] = {
				name = "IP 质量",
				status = "risk",
				detail = "企业/骨干线路 IP" .. (row.ip_quality_reason ~= "" and ("：" .. row.ip_quality_reason) or ""),
			}
		elseif row.ip_quality == "residential" then
			checks[#checks + 1] = {
				name = "IP 质量",
				status = "pass",
				detail = "住宅 IP" .. (row.org ~= "" and ("（" .. row.org .. "）") or ""),
			}
		else -- unknown
			checks[#checks + 1] = {
				name = "IP 质量",
				status = "risk",
				detail = "未知（无法确认是否住宅 IP）",
			}
		end

		local dns_bad = has(miss, "dns", "不一致")
		local dns_unk = has(risk, "dns", "未确认")
		checks[#checks + 1] = {
			name = "DNS 一致性",
			status = line_down and "na" or ((row.dns_country or "") == ""
				and "risk" or (dns_bad and "fail" or "pass")),
			detail = line_down and "线路不通，未检测"
				or ((row.dns_country or "") == "" and "解析侧国家未取到，建议复测"
					or (dns_bad or string.format("解析 %s 与出口 %s 一致",
						row.dns_country, row.country ~= "" and row.country or "?"))),
		}

		checks[#checks + 1] = {
			name = "IPv6 泄漏",
			status = line_down and "na" or (row.ipv6_leak and "fail" or "pass"),
			detail = line_down and "线路不通，未检测"
				or (row.ipv6_leak and "检测到 IPv6 可绕过代理出网" or "未检测到 IPv6 泄漏"),
		}

		checks[#checks + 1] = {
			name = "出口 IP 唯一性",
			status = line_down and "na" or (row.ip_duplicated and "risk" or "pass"),
			detail = line_down and "线路不通，未检测"
				or (row.ip_duplicated
					and ("与 " .. table.concat(row.dup_with or {}, "、") .. " 共用同一出口（仅供参考）")
					or "本机内唯一"),
		}

		if (row.country or "") ~= "" then
			checks[#checks + 1] = {
				name = "出口国家",
				status = "pass",
				detail = row.country,
			}
		end

		row.checks = checks

		-- 结论
		row.env_miss = {}
		row.env_risk = {}
		for _, m in ipairs(miss) do table.insert(row.env_miss, m.text) end
		for _, r in ipairs(risk) do table.insert(row.env_risk, r.text) end

		local uniq_cats = {}
		for _, m in ipairs(miss) do uniq_cats[m.cat] = true end
		row.env_cats = {}
		for c in pairs(uniq_cats) do table.insert(row.env_cats, c) end

		if #miss > 0 then
			row.env_level = "unusable"
			row.verdict = "fail"
			row.verdict_label = "运营环境不可用"
		elseif #risk > 0 then
			row.env_level = "risky"
			row.verdict = "risk"
			row.verdict_label = "有风险"
		else
			row.env_level = "ok"
			row.verdict = "pass"
			row.verdict_label = "达标"
		end

		-- 兼容老字段：reasons 汇总（弹窗里也用它）
		local all = {}
		for _, t in ipairs(row.env_miss) do table.insert(all, t) end
		for _, t in ipairs(row.env_risk) do table.insert(all, t) end
		row.reasons_list = all
		row.reasons = (#all > 0) and table.concat(all, "；") or ""
		row.pass_items = 0
	end

	return items
end

-- 统计结果
function M.summarize(items)
	local pass_count = 0
	local risk_count = 0
	local fail_count = 0
	local line_ok_count = 0
	local line_bad_count = 0
	local ip_set = {}
	local dup_ips = {}

	for _, it in ipairs(items or {}) do
		if it.verdict == "pass" then
			pass_count = pass_count + 1
		elseif it.verdict == "risk" then
			risk_count = risk_count + 1
		elseif it.verdict == "fail" then
			fail_count = fail_count + 1
		end

		if it.line_ok then line_ok_count = line_ok_count + 1 else line_bad_count = line_bad_count + 1 end

		if it.exit_ip and it.exit_ip ~= "" then
			if ip_set[it.exit_ip] then
				dup_ips[it.exit_ip] = true
			else
				ip_set[it.exit_ip] = true
			end
		end
	end

	local dup_count = 0
	for _ in pairs(dup_ips) do
		dup_count = dup_count + 1
	end

	return {
		-- 两个维度：线路连通 / 运营环境
		line_ok = line_ok_count,
		line_bad = line_bad_count,
		env_pass = pass_count,
		env_risk = risk_count,
		env_fail = fail_count,
		total = #items,
		pass = pass_count,
		risk = risk_count,
		fail = fail_count,
		dup_ip_count = dup_count,
	}
end

-- 结论标签
function M.verdict_label(v)
	if v == "pass" then return "✓ 可用" end
	if v == "risk" then return "⚠ 有风险" end
	if v == "fail" then return "✗ 不可用" end
	return "未知"
end

-- 结论颜色类
function M.verdict_class(v)
	if v == "pass" then return "is-pass" end
	if v == "risk" then return "is-risk" end
	if v == "fail" then return "is-fail" end
	return ""
end

return M
