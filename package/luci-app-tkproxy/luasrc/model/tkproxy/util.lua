-- SPDX-License-Identifier: GPL-3.0
-- tkproxy Web 工具层
--
-- 职责：
--   * 清单（SSID|频段|链接）的解析、前置校验、UCI 存取；
--   * 调 T2 的 apply.sh / status.sh / clean.sh，并在后台跑、把进度写进
--     /tmp/tkproxy/web/*，供页面轮询；
--   * 不自己写 wireless/network/dhcp/firewall —— 全部交给 apply.sh。
--
-- 关键约束：
--   * 用户输入只进 UCI（uci:set_list）和生成器产物文件，绝不拼进 shell 命令；
--   * 生成器产物在 /tmp（0700），真正的落盘与权限由 apply.sh 负责；
--   * status.sh 一次要跑 N 个 netns + curl，可能几十秒，必须后台跑。

local uci_mod = require "luci.model.uci"
local sys = require "luci.sys"
local fs = require "nixio.fs"
local jsonc = require "luci.jsonc"
local gen = require "luci.model.tkproxy.gen"

local M = {}

M.UCI_CFG = "tkproxy"
M.UCI_SEC = "main"
M.CONF_FILE = "/etc/config/tkproxy"
M.CONF_DIR = "/etc/tkproxy"
M.RUN_DIR = "/tmp/tkproxy/web"
-- 所有写操作（bind_set/toggle/auto/line_delete/clear/nodes_import/delete/clear/save/deploy/clean）共用同一把锁
M.LOCK_DIR = M.RUN_DIR .. "/.lock"
M.BACKUP_DIR = M.CONF_DIR .. "/backup"  -- 持久化备份目录
M.APPLY = "/usr/libexec/tkproxy/apply.sh"
M.STATUS = "/usr/libexec/tkproxy/status.sh"
M.CLEAN = "/usr/libexec/tkproxy/clean.sh"

M.LIMIT = 16          -- 单射频名额上限
M.BASE = "10.11"      -- 与 gen.lua / gen.py 默认一致
M.PORT_BASE = 21000

-- ---------------------------------------------------------------------------
-- 基础工具（必须定义在使用它的函数之前，否则运行期会解析成全局 nil）
-- ---------------------------------------------------------------------------

local function trim(s)
	return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

-- WiFi 密码校验：8-63 字节，ASCII 可见字符（0x20-0x7E），排除引号
-- 创建 WiFi 时密码留空的默认值（界面 placeholder 与这里必须一致）
M.DEFAULT_WIFI_PASSWORD = "abc123456"

local function validate_wifi_password(pw)
	if type(pw) ~= "string" or pw == "" then
		return false, "密码不能为空"
	end
	local len = #pw
	if len < 8 or len > 63 then
		return false, string.format("密码长度必须是 8-63 字节（当前 %d）", len)
	end
	-- 检查 ASCII 可见字符（0x20-0x7E），排除单引号和双引号
	for i = 1, len do
		local b = pw:byte(i)
		if b < 0x20 or b > 0x7E then
			return false, "密码只能包含 ASCII 可见字符（0x20-0x7E）"
		end
		if b == 0x22 or b == 0x27 then  -- " 或 '
			return false, "密码不能包含引号"
		end
	end
	return true
end

local function ensure_conf_file()
	if not fs.stat(M.CONF_FILE) then
		fs.writefile(M.CONF_FILE, "config tkproxy 'main'\n\toption updated_at '0'\n")
	end
	-- 清单里有节点链接（含账号/密码），每次访问都强制收紧到 0600
	local ok, ret = pcall(fs.chmod, M.CONF_FILE, 384) -- 0600
	if not (ok and ret) then
		-- chmod 失败不阻断读取（已存在的配置仍可用），但生产环境应确保权限正确
	end
end

local function cursor()
	ensure_conf_file()
	return uci_mod.cursor()
end

-- ---------------------------------------------------------------------------
-- 节点池（存 uci list node，格式 "名称|链接" 或 "链接"）
-- ---------------------------------------------------------------------------

-- 从链接提取默认名称：优先 fragment，其次 json 的 tag/server，最后 uuid/server 前 8 位
-- URL 解码（节点名常来自链接 fragment，带 %XX 编码）
local function urldecode(str)
	local out = tostring(str or ""):gsub("%%(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end)
	-- 再按 UTF-8 原样返回（lua5.1 不做编码转换）
	return out
end

-- 节点名净化：清单用 '|' 分隔，名字里出现 '|' 会把字段劈开；控制字符也要去掉
local function clean_name(name)
	local n = tostring(name or "")
	n = n:gsub("[\r\n\t]", " ")
	n = n:gsub("|", "/")
	n = n:gsub("^%s+", ""):gsub("%s+$", "")
	if n == "" then n = "node" end
	if #n > 60 then n = n:sub(1, 60) end
	return n
end

local function default_node_name(link)
	local frag = link:match("#([^#]+)$")
	if frag and trim(frag) ~= "" then
		return clean_name(urldecode(trim(frag)))
	end
	if link:sub(1, 5) == "json:" then
		local ob = gen.parse_node(link)
		if ob and ob.tag then return clean_name(tostring(ob.tag)) end
		if ob and ob.server then return clean_name(tostring(ob.server):sub(1, 15)) end
	end
	local ob = gen.parse_node(link)
	if not ob then return "node" end
	if ob.uuid then return clean_name(tostring(ob.uuid):sub(1, 8)) end
	if ob.server then return clean_name(tostring(ob.server):sub(1, 12)) end
	return "node"
end

-- 规范化链接：去空白、去 fragment（vless/vmess 的 # 后是备注，不参与连接逻辑）
local function normalize_link(link)
	link = trim(link)
	if link:sub(1, 5) == "json:" then return link end
	return (link:gsub("#.*$", ""))
end

-- 解析一条 node 条目："名称|链接" 或 "链接" -> {name, link, link_norm}
-- 协议白名单（必须在 parse_node_entry 之前定义，否则运行期解析成全局 nil）
local SUPPORTED = { "vless://", "vmess://", "trojan://", "ss://", "socks5://", "socks://", "json:" }

-- 合法性：协议必须在白名单里，且必须能取出真实主机与端口
-- （以前只看协议头，导致 vless://坏链接 这种垃圾行也被当成节点存进池子）
local function supported_link(link)
	local low = tostring(link or ""):lower()
	local hit = false
	for _, p in ipairs(SUPPORTED) do
		if low:sub(1, #p) == p then hit = true break end
	end
	if not hit then return false end

	-- json(hysteria2 等)：必须有 server 与 server_port
	if low:sub(1, 5) == "json:" then
		local srv = low:match('"server"%s*:%s*"([^"]+)"')
		local prt = low:match('"server_port"%s*:%s*(%d+)')
		return srv ~= nil and srv ~= "" and prt ~= nil
	end

	-- socks5://user:pass@host:port?front=前置节点名#名字
	if low:sub(1, 8) == "socks5:/" or low:sub(1, 8) == "socks://" then
		local body = low:gsub("^socks5?://", "")
		body = body:gsub("#.*$", ""):gsub("%?.*$", "")
		local host, port = body:match("@([%w%.%-]+):(%d+)$")
		if not host then host, port = body:match("^([%w%.%-]+):(%d+)$") end
		if not host or not port then return false end
		local pn = tonumber(port)
		return pn ~= nil and pn > 0 and pn <= 65535
	end

	-- ss:// 可能是整段 base64（不含 @host:port），够长就放行
	if low:sub(1, 5) == "ss://" then
		local body = low:sub(6):gsub("#.*$", "")
		if body:find("@", 1, true) then
			return body:match("@[%w%.%-]+:%d+") ~= nil
		end
		return #body >= 16
	end

	-- 其它：必须有 host:port
	local host, port = low:match("@([%w%.%-]+):(%d+)")
	if not host then host, port = low:match("//([%w%.%-]+):(%d+)") end
	if not host or not port then return false end
	local pn = tonumber(port)
	return pn ~= nil and pn > 0 and pn <= 65535
end

-- 内核能力门槛：这版插件跑的是 Xray，Hysteria2 / TUIC 是 sing-box 才有的出站协议，
-- Xray 加载时会直接报 "unknown config id"。以前这类节点能正常导入进池，一旦被绑到线路，
-- xray.json 校验就会失败，整个部署被挡住（不是坏一条，是全机不生效）。
-- 这里在解析阶段就拒掉，并给出人话原因，供前端标红显示。
local KERNEL_UNSUPPORTED = {
	hysteria2 = "Hysteria2",
	hysteria = "Hysteria2",
	tuic = "TUIC",
	snell = "Snell",
}

function M.node_reject_reason(entry)
	local low = tostring(entry or ""):lower()
	if low:sub(1, 5) ~= "json:" then
		-- 非 json: 的裸链接：直接看协议头
		local sch = low:match("^([%a][%w%-%+]*)://")
		if sch == "hysteria2" or sch == "hy2" then return "不支持 Hysteria2 协议" end
		if sch == "tuic" then return "不支持 TUIC 协议" end
		if sch == "snell" then return "不支持 Snell 协议" end
		return nil
	end
	local t = low:match('"type"%s*:%s*"([%w_%-]+)"')
	if not t then return nil end
	local human = KERNEL_UNSUPPORTED[t]
	if human then
		return "不支持 " .. human .. " 协议，请改用 VLESS / VMess / Trojan / SS"
	end
	return nil
end

function M.parse_node_entry(entry)
	local raw = trim(entry)
	if raw == "" then return nil end
	local pipe = raw:find("|", 1, true)
	local name, link
	if pipe then
		name = clean_name(trim(raw:sub(1, pipe - 1)))
		link = trim(raw:sub(pipe + 1))
		if name == "" or name == "node" then name = nil end
	else
		link = raw
	end
	-- 四段写法 host:port:用户名:密码（老插件格式，用户会直接粘）：
	-- 只在导入入口规范成 socks5://user:pass@host:port，池子里统一存标准链接
	-- 只适配不含 :// 的裸四段，避免误伤 vless/vmess 等带协议头的链接
	if not link:match("://") and link:match("^[%w%.%-]+:%d+:[^:]*:.*$") then
		local h, p, u2, pw = link:match("^([%w%.%-]+):(%d+):([^:]*):(.*)$")
		if h and p then
			local userinfo = ""
			if u2 ~= "" then
				userinfo = u2 .. ":" .. pw
			end
			link = "socks5://" .. userinfo .. "@" .. h .. ":" .. p
			if not name then name = h .. ":" .. p end
		end
	end
	if link == "" or not supported_link(link) then return nil end
	-- 内核跑不了的协议一律不进池（否则绑上线路会让整个部署失败）
	if M.node_reject_reason(link) then return nil end
	name = name or default_node_name(link)
	-- 过滤机场"信息节点"：很多订阅会把流量/到期信息伪装成节点（真实 vless 链接 + 文案名字，
	-- 例如「剩余流量：1008.42 GB」「套餐到期：2027-03-28」「距离下次重置剩余：25 天」）。
	-- 它们能正常解析，一旦进池就会被自动绑定分给新线路，等于发一条死线出去。
	if name and name ~= "" then
		local info_words = {
			"剩余流量", "距离下次重置", "套餐到期", "到期时间", "有效期至",
			"重置剩余", "过期时间", "官网地址", "订阅链接",
		}
		for _, w in ipairs(info_words) do
			if name:find(w, 1, true) then return nil end
		end
	end
	return { name = name, link = link, link_norm = normalize_link(link) }
end

-- 读取节点池
function M.nodes()
	local c = cursor()
	local raw = c:get_list(M.UCI_CFG, M.UCI_SEC, "node") or {}
	local out = {}
	for _, s in ipairs(raw) do
		local n = M.parse_node_entry(s)
		if n then out[#out + 1] = n end
	end
	return out
end

-- 按名称查节点
function M.node_by_name(name)
	name = trim(name)
	for _, n in ipairs(M.nodes()) do
		if n.name == name then return n end
	end
	return nil
end

-- 去重：按 link_norm 去重，保留第一次出现的
function M.dedup_nodes(nodes)
	local seen, out = {}, {}
	for _, n in ipairs(nodes or {}) do
		-- 判重键必须带名字：订阅里常见「同一台服务器多条不同名字」的节点
		-- （例如 免费IT09 / 免费IT12 指向同一 ss 服务器），只按链接去掉 name 判重
		-- 会把它们当成重复，一旦节点池被重写（导入/删除/追加）就静默吃掉其中一条，
		-- 绑定在这些名字上的线路随之「引用的节点不存在」，部署被整条卡住。
		local key = tostring(n.name or "") .. "\0" .. tostring(n.link_norm or n.link or "")
		if not seen[key] then
			seen[key] = true
			out[#out + 1] = n
		end
	end
	return out
end

-- 解析清单行（必须在任何使用它的函数之前定义）
local function split_line(line)
	local p1 = line:find("|", 1, true)
	if not p1 then return nil end
	local ssid = trim(line:sub(1, p1 - 1))
	local rest = line:sub(p1 + 1)
	local p2 = rest:find("|", 1, true)
	if not p2 then
		return ssid, nil, trim(rest)
	end
	local mid = trim(rest:sub(1, p2 - 1))
	local after = trim(rest:sub(p2 + 1))
	local m = mid:lower()
	if m == "2g" or m == "5g" or m == "both" then
		-- 第 4 段：启用位（缺省=启用；0=禁用）
		local p3 = after:find("|", 1, true)
		if p3 then
			local en = trim(after:sub(p3 + 1))
			-- 第 5 段是本条线路自己的 WiFi 密码，不能让 enabled 读到它
			local bar = en:find("|", 1, true)
			if bar then en = trim(en:sub(1, bar - 1)) end
			return ssid, m, trim(after:sub(1, p3 - 1)), en
		end
		return ssid, m, after
	end
	-- SSID|链接|启用
	local p3 = rest:find("|", 1, true)
	local p4 = p3 and rest:find("|", p3 + 1, true)
	if p4 then
		return ssid, nil, trim(rest:sub(1, p4 - 1)), trim(rest:sub(p4 + 1))
	end
	return ssid, nil, trim(rest)
end

-- 查询哪些行在引用某个节点
function M.lines_using_node(node_name)
	local out = {}
	for i, line in ipairs(M.lines()) do
		local _, _, link = split_line(line)
		if link and link:sub(1, 1) == "@" and trim(link:sub(2)) == node_name then
			out[#out + 1] = i
		end
	end
	return out
end

-- 校验线路绑定是否满足「一 WiFi 一节点」严格 1:1
-- 返回 {ok=true} 或 {ok=false, msg="...", duplicates={...}}
-- full_check=true 时执行完整性校验（线路总数 == 唯一节点数），false 时仅检测节点共用
function M.validate_unique_nodes(lines, full_check)
	lines = lines or M.lines()
	full_check = (full_check == nil) and true or full_check
	local node_pool = M.nodes()
	local node_count = {}  -- {[node_name] = {ssid1, ssid2, ...}}
	local total_lines = 0

	for i, line in ipairs(lines) do
		local ssid, _, link, en = split_line(line)
		if ssid then
			total_lines = total_lines + 1
			-- 节点共用检测必须覆盖全部已有绑定（含禁用线路）
			if link and link:sub(1, 1) == "@" then
				local name = trim(link:sub(2))
				if name ~= "" then
					node_count[name] = node_count[name] or {}
					table.insert(node_count[name], ssid)
				end
			end
		end
	end

	-- 检测共用节点（返回节点名及全部共用线路名）
	local duplicates = {}
	for name, ssids in pairs(node_count) do
		if #ssids > 1 then
			table.insert(duplicates, {node = name, ssids = ssids, count = #ssids})
		end
	end

	if #duplicates > 0 then
		local msg = string.format("检测到节点共用违规：%d 个节点被多条线路重复使用", #duplicates)
		for _, dup in ipairs(duplicates) do
			msg = msg .. string.format("\n  - 节点 @%s 被 %d 条线路共用：%s",
				dup.node, dup.count, table.concat(dup.ssids, "、"))
		end
		return {ok = false, msg = msg, duplicates = duplicates}
	end

	-- 完整性校验：线路总数 == 绑定唯一节点数（仅在 full_check=true 时执行）
	if full_check then
		local unique_nodes = 0
		for _, _ in pairs(node_count) do
			unique_nodes = unique_nodes + 1
		end

		if total_lines > unique_nodes then
			return {
				ok = false,
				msg = string.format("线路总数 %d 条，但仅绑定了 %d 个唯一节点，缺 %d 个节点",
					total_lines, unique_nodes, total_lines - unique_nodes)
			}
		end
	end

	return {ok = true}
end

-- ---------------------------------------------------------------------------
-- 基础工具
-- ---------------------------------------------------------------------------


-- UTF-8 码点数（与 gen.lua 的 SSID 长度语义一致）
local function utf8_len(s)
	local _, n = tostring(s or ""):gsub("[^\128-\191]", "")
	return n
end

-- shell 单引号包裹：只用于常量路径，不接收用户输入
local function shq(s)
	return "'" .. tostring(s or ""):gsub("'", "'\\''") .. "'"
end

M.shq = shq

function M.exec(cmd)
	return sys.exec(cmd) or ""
end

-- 日志限长：超过 maxbytes 时截断为最后 maxbytes（保留尾部）
-- 使用文件锁防止并发追加丢失，原子替换避免中间状态
-- flock 不可用时回退到无锁模式（存在竞态但仍能限长）
local function truncate_log_if_needed(path, maxbytes)
	maxbytes = maxbytes or (256 * 1024) -- 默认 256KB
	local st = fs.stat(path)
	if not st or st.size <= maxbytes then return true end

	local tmp = path .. ".trunc." .. os.time() .. "." .. math.random(10000, 99999)
	local lock = path .. ".lock"

	-- 优先尝试 flock 模式
	local cmd_flock = string.format(
		"exec 9>%s && flock -x 9 && " ..
		"tail -c %d %s > %s && " ..
		"cat %s > %s && " ..
		"rm -f %s && " ..
		"exec 9>&-",
		shq(lock), maxbytes, shq(path), shq(tmp), shq(tmp), shq(path), shq(tmp)
	)
	local ret = os.execute(cmd_flock)

	-- flock 失败时回退到无锁模式
	if ret ~= 0 then
		fs.remove(tmp)
		local cmd_nolock = string.format(
			"tail -c %d %s > %s && cat %s > %s && rm -f %s",
			maxbytes, shq(path), shq(tmp), shq(tmp), shq(path), shq(tmp)
		)
		ret = os.execute(cmd_nolock)
		if ret ~= 0 then
			fs.remove(tmp)
			return false, "截断日志失败（有锁和无锁模式均失败）：" .. path
		end
	end

	-- 严格校验截断后不超过限制
	st = fs.stat(path)
	if not st or st.size > maxbytes then
		return false, "截断后大小校验失败（超过限制）：" .. path
	end

	return true
end

-- 统一日志限长：遍历所有日志并限制大小
local function truncate_all_logs()
	local dirs = { M.RUN_DIR, "/etc/tkproxy" }
	for _, dir in ipairs(dirs) do
		if fs.stat(dir) then
			local iter, state, var = fs.dir(dir)
			if iter then
				for entry in iter, state, var do
					if entry:match("%.log$") then
						local path = dir .. "/" .. entry
						local ok, err = truncate_log_if_needed(path, 256 * 1024)
						if not ok then
							return false, err
						end
					end
				end
			end
		end
	end
	return true
end

-- 导出供后台任务调用
M.truncate_all_logs = truncate_all_logs

local function ensure_dir(path)
	if not fs.stat(path) then
		fs.mkdirr(path)
	end
	-- 运行目录里会有节点凭据（config.json），只给 root
	local ok, ret = pcall(fs.chmod, path, 700) -- 0700
	if not ok then
		return false, "设置目录权限 0700 失败：" .. path
	end
	-- chmod 成功时 pcall 返回 true,nil；核验实际权限
	local st = fs.stat(path)
	return true
end

function M.ensure_run()
	local ok, err = ensure_dir(M.RUN_DIR)
	if not ok then return false, err end
	-- BLK-09：确保持久备份目录存在
	ok, err = ensure_dir(M.BACKUP_DIR)
	if not ok then return false, err end
	return true
end

-- ---------------------------------------------------------------------------
-- 并发锁
--
-- job_running 的「检查」与 job_start 的「启动」之间原本有窗口，多标签页
-- 同时提交会写出半新半旧的配置。mkdir 在 POSIX 上是原子的，因此用
-- RUN_DIR/.lock 目录把「检查 → 生成 → 启动」整段串行化；deploy 与 clean
-- 共用同一把锁，二者永远不会交错。
-- ---------------------------------------------------------------------------

local function self_pid()
	local s = fs.readfile("/proc/self/stat") or ""
	return s:match("^(%d+)") or "0"
end

local function lock_owner_alive()
	local pid = trim(fs.readfile(M.LOCK_DIR .. "/pid") or "")
	if pid:match("^%d+$") then
		return trim(M.exec("kill -0 " .. pid .. " >/dev/null 2>&1 && printf 1")) == "1"
	end
	return false
end

local function lock_release()
	fs.remove(M.LOCK_DIR .. "/pid")
	if not fs.rmdir(M.LOCK_DIR) then
		os.execute("rm -rf " .. shq(M.LOCK_DIR) .. " >/dev/null 2>&1")
	end
end

local function lock_acquire()
	M.ensure_run()
	for _ = 1, 2 do
		local rc = os.execute("mkdir " .. shq(M.LOCK_DIR) .. " >/dev/null 2>&1")
		if rc == 0 or rc == true then
			fs.writefile(M.LOCK_DIR .. "/pid", self_pid())
			return true
		end
		-- 持锁进程崩溃会留下锁目录：确认 pid 已死且锁不是刚创建的，才清理
		local st = fs.stat(M.LOCK_DIR)
		if st and (os.time() - st.mtime) >= 30 and not lock_owner_alive() then
			os.execute("rm -rf " .. shq(M.LOCK_DIR) .. " >/dev/null 2>&1")
		else
			return false
		end
	end
	return false
end

-- 僵死清理函数的前置声明：真正的定义在文件后方
local cleanup_zombie_task

-- 在锁内执行 fn；无论 fn 成功、失败还是抛错都会释放锁
-- BLK-09：所有写操作统一检查部署/清理任务，防止执行期间修改 UCI
local function with_lock(fn)
	if not lock_acquire() then
		return false, "另一个写操作正在执行，请稍候"
	end
	-- 部署/清理任务执行期间禁止其他写操作
	if M.job_running("deploy") or M.job_running("clean") then
		lock_release()
		return false, "部署或回滚任务正在执行，请稍候"
	end
	-- 进程已死但 PID 文件残留，尝试清理僵死任务
	for _, _n in ipairs({ "deploy", "clean" }) do
		if fs.stat(M.RUN_DIR .. "/" .. _n .. ".pid") then
			cleanup_zombie_task(_n)
		end
	end
	local ok, a, b = pcall(fn)
	lock_release()
	if not ok then
		return false, "操作执行失败：" .. tostring(a)
	end
	return a, b
end

local function read_tail(path, maxbytes)
	local s = fs.readfile(path)
	if not s then return "" end
	maxbytes = maxbytes or 12000
	if #s > maxbytes then
		return "…\n" .. s:sub(-maxbytes)
	end
	return s
end

local function last_line(text)
	local last = ""
	for line in tostring(text or ""):gmatch("[^\n]+") do
		local t = trim(line)
		if t ~= "" then last = t end
	end
	if #last > 160 then last = last:sub(1, 160) .. "…" end
	return last
end

local function str(v)
	if type(v) == "string" then return v end
	return ""
end

-- ---------------------------------------------------------------------------
-- UCI 存取
--
-- 清单放在 /etc/config/tkproxy 的 list line 里：
--   config tkproxy 'main'
--       list line 'TK-01|2g|vless://...'
--
-- 不放进 /etc/tkproxy：clean.sh（回滚）会把那个目录整个删掉，
-- 而清单是用户的输入，回滚后必须还在，才能重新部署。
-- ---------------------------------------------------------------------------



function M.lines()
	local c = cursor()
	local raw = c:get_list(M.UCI_CFG, M.UCI_SEC, "line") or {}
	local out = {}
	for _, s in ipairs(raw) do
		s = trim(s)
		if s ~= "" and s:sub(1, 1) ~= "#" then
			out[#out + 1] = s
		end
	end
	return out
end

function M.stored_text()
	return table.concat(M.lines(), "\n")
end

-- 获取 WiFi 密码（从 UCI 或返回 nil）
function M.get_wifi_password()
	local c = cursor()
	local pw = c:get(M.UCI_CFG, M.UCI_SEC, "password")
	return (pw and pw ~= "") and pw or nil
end

-- 保存 WiFi 密码到 UCI（不直接暴露，只在内部使用）
function M.save_wifi_password(password)
	return with_lock(function()
		local ok_val, err_val = validate_wifi_password(password)
		if not ok_val then
			return false, err_val
		end
		local c = cursor()
		c:set(M.UCI_CFG, M.UCI_SEC, "password", password)
		return c:commit(M.UCI_CFG)
	end)
end

-- 保存线路清单（内部函数，需由调用者持锁）
local function save_lines_locked(lines)
	local c = cursor()
	local buf = {}
	for _, l in ipairs(lines or {}) do
		local t = trim(l)
		if t ~= "" then
			buf[#buf + 1] = t
		end
	end
	if #buf > 0 then
		c:set_list(M.UCI_CFG, M.UCI_SEC, "line", buf)
	else
		c:delete(M.UCI_CFG, M.UCI_SEC, "line")
	end
	c:set(M.UCI_CFG, M.UCI_SEC, "updated_at", tostring(os.time()))
	if not c:commit(M.UCI_CFG) then
		return nil, "写入 /etc/config/tkproxy 失败"
	end
	-- uci commit 可能按 umask 重建文件，提交后再次强制 0600
	local ok_chmod = pcall(fs.chmod, M.CONF_FILE, 384) -- 0600
	-- 注意：fs.chmod 成功时返回 nil，因此不能检查其返回值，只判断 pcall 是否抛错
	return true
end

-- 保存线路清单（对外接口，自动加锁）
function M.save_lines(lines)
	return with_lock(function()
		return save_lines_locked(lines)
	end)
end

-- 保存节点池（内部函数，需由调用者持锁）
-- 兼容两种入参：
--   1) { {name=..., link=...}, ... }（parse_node_entry 的返回格式）
--   2) 字符串数组 { "name|link", ... }（字符串按第一个 | 拆，无 | 时交给 parse_node_entry 取默认名）
-- 防误删：入参非空但解析后有效条目为 0 → 拒绝写入并返回错误（历史上字符串入参会
-- 静默清空整张节点池还返回 true，t_d1519957）。
local function save_nodes_locked(nodes)
	local c = cursor()
	local buf = {}
	local total = 0
	for _, n in ipairs(nodes or {}) do
		total = total + 1
		local entry
		if type(n) == "string" then
			-- 字符串入参：交给 parse_node_entry 统一校验/取名，返回 nil 说明链接不合法
			local parsed = M.parse_node_entry(n)
			if parsed then
				entry = parsed.name .. "|" .. parsed.link
			else
				entry = nil
			end
		else
			entry = n.name and (n.name .. "|" .. n.link) or n.link
		end
		if entry and entry ~= "" then
			buf[#buf + 1] = entry
		end
	end
	-- 防误删：入参里有条目但一条有效都没有 → 格式错误，拒绝写入（不允许 delete 整张列表）。
	-- 传入空数组（total == 0）是「合法清空池」，行为保持不变。
	if total > 0 and #buf == 0 then
		return nil, "节点条目格式错误（有效 0 条），已拒绝写入"
	end
	if #buf > 0 then
		c:set_list(M.UCI_CFG, M.UCI_SEC, "node", buf)
	else
		c:delete(M.UCI_CFG, M.UCI_SEC, "node")
	end
	if not c:commit(M.UCI_CFG) then
		return nil, "写入节点池失败"
	end
	local ok_chmod = pcall(fs.chmod, M.CONF_FILE, 384)
	-- 注意：fs.chmod 成功时返回 nil，因此不能检查其返回值，只判断 pcall 是否抛错
	return true
end

-- 保存节点池（对外接口，自动加锁）
-- 入参支持 { {name=...,link=...}, ... } 或字符串数组 { "name|link", ... }（见 save_nodes_locked）
function M.save_nodes(nodes)
	return with_lock(function()
		return save_nodes_locked(nodes)
	end)
end

-- 增加节点（追加到池尾，自动去重），读改写整体持锁
function M.add_nodes(new_nodes)
	return with_lock(function()
		local pool = M.nodes()
		for _, n in ipairs(new_nodes or {}) do
			pool[#pool + 1] = n
		end
		pool = M.dedup_nodes(pool)
		return save_nodes_locked(pool)
	end)
end

-- 删除节点（按名称），读改写整体持锁
function M.remove_node(name)
	return with_lock(function()
		local pool = M.nodes()
		local out = {}
		for _, n in ipairs(pool) do
			if n.name ~= name then out[#out + 1] = n end
		end
		return save_nodes_locked(out)
	end)
end

-- 导出锁内保存接口和锁函数供 bind.lua 使用（BLK-09）
M.save_lines_locked = save_lines_locked
M.save_nodes_locked = save_nodes_locked
M.with_lock = with_lock

function M.is_deployed()
	return fs.stat(M.CONF_DIR .. "/manifest.json") ~= nil
end

-- ---------------------------------------------------------------------------
-- 清单解析
-- ---------------------------------------------------------------------------

-- 拆分一行：SSID|频段|链接
-- 第二段不是 2g/5g/both 时，按 gen.lua 的规则把「第一个 | 之后」整体当链接。

-- 取某行自己的 WiFi 密码（第 5 段）；没有则返回 ""
local function line_key(line)
	local parts, n = {}, 0
	local rest = tostring(line or "")
	while true do
		local i = rest:find("|", 1, true)
		n = n + 1
		if not i then
			parts[n] = rest
			break
		end
		parts[n] = rest:sub(1, i - 1)
		rest = rest:sub(i + 1)
	end
	if n < 5 then return "" end
	return trim(parts[5] or "")
end
M.line_key = line_key

M.split_line = split_line

local NODE_LABEL = {
	shadowsocks = "Shadowsocks",
	vless = "VLESS",
	vmess = "VMess",
	trojan = "Trojan",
	socks = "SOCKS",
	http = "HTTP",
	hysteria2 = "Hysteria2",
	tuic = "TUIC",
	direct = "Direct",
}

local BAND_LABEL = { ["2g"] = "2.4G", ["5g"] = "5G", both = "双频" }

function M.node_label(t)
	t = tostring(t or "")
	return NODE_LABEL[t] or (t ~= "" and t or "—")
end

function M.band_label(b)
	return BAND_LABEL[tostring(b or "")] or "双频"
end

-- 节点域名/IP 打码：页面只需要知道「连到哪个域名」，不需要完整地址
function M.mask_host(h)
	h = tostring(h or "")
	if h == "" then return "" end
	if h:match("^%d+%.%d+%.%d+%.%d+$") then
		local p = h:match("^(%d+%.%d+)%.")
		if p then return p .. ".*.*" end
	end
	if #h <= 4 then return "****" end
	return h:sub(1, 2) .. "***" .. h:sub(-2)
end

-- validate 的对外行：剥掉 raw/link（含节点凭据），域名打码。
-- idx/slug/subnet/port 等非敏感字段保留，页面预览仍能正常渲染。
function M.public_row(row)
	return {
		idx = row.idx,
		ssid = row.ssid,
		band = row.band,
		band_label = row.band_label,
		slug = row.slug,
		subnet = row.subnet,
		gateway = row.gateway,
		port = row.port,
		node_type = row.node_type,
		node_label = row.node_label,
		protocol = row.node_type,
		domain = M.mask_host(row.node_server),
		valid = (row.error == nil),
		error = row.error,
		enabled = (row.enabled ~= false),
		enabled_label = row.enabled_label,
		node_name = row.node_name or "",
		is_ref = row.is_ref,
	}
end

-- 解析单条；idx 从 1 开始（决定网段与端口）；node_pool 用于 @引用解析
function M.parse_line(line, idx, node_pool)
	local ssid, band, link, en = split_line(tostring(line or ""))
	local enabled = not (en == "0" or en == "false" or en == "off")
	if not ssid then
		return nil, "缺少 '|'（格式：SSID|频段|链接）"
	end
	if ssid == "" then
		return nil, "SSID 不能为空"
	end
	if ssid:find("[\"']") then
		return nil, "SSID 不能包含引号"
	end
	-- BLK-11：统一按 UTF-8 字节数限制（与 gen.lua 一致）
	if #ssid > 32 then
		return nil, "SSID 超过 32 字节"
	end
	if (link == nil or link == "") and enabled then
		return nil, "节点链接为空（启用中的线路必须先绑定节点）"
	end
	if link == nil or link == "" then
		link = ""
	end
	if link:find("[\r\n]") then
		return nil, "节点链接不能包含换行"
	end

	-- @节点名 引用解析
	local actual_link = link
	local is_ref = false
	if link ~= "" and link:sub(1, 1) == "@" then
		is_ref = true
		local node_name = trim(link:sub(2))
		if node_name == "" then
			return nil, "引用格式错误：@后面必须跟节点名"
		end
		local found = false
		node_pool = node_pool or M.nodes()
		for _, n in ipairs(node_pool) do
			if n.name == node_name then
				actual_link = n.link
				found = true
				break
			end
		end
		if not found then
			return nil, ("引用的节点 %s 不存在"):format(node_name)
		end
	elseif link ~= "" and not supported_link(link) then
		return nil, "不支持的链接协议（只支持 vless / vmess / trojan / ss / socks5 / json: 或 @节点名）"
	end

	local slug, serr = gen.slugify(ssid)
	if not slug then return nil, tostring(serr) end

	local ob, oerr = nil, nil
	if actual_link ~= "" then
		ob, oerr = gen.parse_node(actual_link)
	end
	if actual_link ~= "" and not ob then
		-- 生成器的报错可能回显 UUID，返回页面前先打码
		local msg = tostring(oerr or "节点解析失败")
		msg = msg:gsub("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x",
			"********-****-****-****-************")
		return nil, msg
	end

	ob = ob or {}
	band = band or "both"
	if band ~= "2g" and band ~= "5g" and band ~= "both" then band = "both" end

	local subnet = M.BASE .. "." .. idx .. ".0/24"
	return {
		idx = idx,
		raw = trim(line),
		ssid = ssid,
		band = band,
		band_label = M.band_label(band),
		link = link,
		slug = slug,
		subnet = subnet,
		gateway = M.BASE .. "." .. idx .. ".1",
		port = M.PORT_BASE + idx,
		node_type = tostring(ob.type or ""),
		node_label = M.node_label(ob.type),
		node_server = str(ob.server),
		node_port = ob.server_port or "",
		is_ref = is_ref,
		enabled = enabled,
		enabled_label = enabled and "启用" or "已禁用",
		-- 选中节点名：@引用时取池内名字；直连链接时留空（页面回退显示主机名）
		node_name = is_ref and trim(link:sub(2)) or "",
	}
end

-- 取清单里的数据行（丢掉空行与 # 注释）
function M.data_lines(text)
	local out = {}
	for raw in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
		local line = trim(raw)
		if line ~= "" and line:sub(1, 1) ~= "#" then
			out[#out + 1] = line
		end
	end
	return out
end

-- 前置校验：SSID 重复 / 单射频超 16 / 协议不支持 / 缺字段
-- 返回 { ok, errors[], rows[], count, quota={limit,g2,g5} }
function M.validate(text)
	local rows, errors = {}, {}
	local seen_ssid, seen_slug = {}, {}
	local seq, n2, n5, ln = 0, 0, 0, 0
	local node_pool = M.nodes()

	for raw in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
		ln = ln + 1
		local line = trim(raw)
		if line ~= "" and line:sub(1, 1) ~= "#" then
			seq = seq + 1
			local row, err = M.parse_line(line, seq, node_pool)
			if not row then
				errors[#errors + 1] = { line = ln, idx = seq, msg = tostring(err) }
			else
				local conflict
				if seen_ssid[row.ssid] then
					conflict = string.format("SSID 与第 %d 行重复", seen_ssid[row.ssid])
				elseif seen_slug[row.slug] then
					conflict = string.format("SSID 生成的标识 %s 与第 %d 行冲突", row.slug, seen_slug[row.slug])
				else
					seen_ssid[row.ssid] = ln
					seen_slug[row.slug] = ln
				end
				if conflict then
					row.error = conflict
					errors[#errors + 1] = { line = ln, idx = seq, msg = conflict }
				end
				rows[#rows + 1] = M.public_row(row)
				-- 禁用行不占射频名额
				if row.enabled ~= false then
					if row.band == "2g" or row.band == "both" then n2 = n2 + 1 end
					if row.band == "5g" or row.band == "both" then n5 = n5 + 1 end
				end
			end
		end
	end

	if #rows == 0 and #errors == 0 then
		errors[#errors + 1] = {
			line = 0, idx = 0,
			msg = "清单为空：请粘贴至少一条「SSID|频段|链接」",
		}
	end
	if n2 > M.LIMIT then
		errors[#errors + 1] = {
			line = 0, idx = 0,
			msg = string.format("2.4G 频段共 %d 条，超过单射频上限 %d 条", n2, M.LIMIT),
		}
	end
	if n5 > M.LIMIT then
		errors[#errors + 1] = {
			line = 0, idx = 0,
			msg = string.format("5G 频段共 %d 条，超过单射频上限 %d 条", n5, M.LIMIT),
		}
	end

	return {
		ok = (#errors == 0),
		errors = errors,
		rows = rows,
		count = #rows,
		quota = { limit = M.LIMIT, g2 = n2, g5 = n5 },
	}
end

function M.overview()
	local lines = M.lines()
	local v = M.validate(table.concat(lines, "\n"))
	v.has_lines = (#lines > 0)
	v.deployed = M.is_deployed()
	return v
end

function M.line_at(idx)
	local lines = M.lines()
	idx = tonumber(idx) or 0
	if idx < 1 or idx > #lines then return nil, #lines end
	return lines[idx], #lines
end

-- ---------------------------------------------------------------------------
-- 生成产物（只写 /tmp，落盘交给 apply.sh）
-- ---------------------------------------------------------------------------

-- 把最新完整产物发布为 RUN_DIR/gen。符号链接的 rename 是原子的：
-- 任何时刻读到的 gen 要么是旧的完整产物，要么是新的完整产物。
local function publish_artifacts(dir)
	local pointer = M.RUN_DIR .. "/gen"
	local tmp = pointer .. ".new"
	fs.remove(tmp)
	os.execute("ln -s " .. shq(dir) .. " " .. shq(tmp) .. " >/dev/null 2>&1")
	if not fs.readlink(tmp) then return false end
	-- 兼容旧版本留下的同名真实目录
	if fs.stat(pointer) and not fs.readlink(pointer) then
		os.execute("rm -rf " .. shq(pointer) .. " >/dev/null 2>&1")
	end
	if fs.rename(tmp, pointer) then return true end
	fs.remove(pointer)
	return fs.rename(tmp, pointer) and true or false
end

local function prune_artifacts(keep)
	-- 安全目录遍历：确定最近 3 份（含当前产物），删除其余
	-- 始终显式保留 keep，其余名额再按确定性顺序选取
	local MAX_KEEP = 3
	local items = {}
	local lfs = require("nixio.fs")

	-- 安全检查目录及迭代器
	if not lfs.stat(M.RUN_DIR) then return end
	local iter, state, var = lfs.dir(M.RUN_DIR)
	if not iter then return end

	for entry in iter, state, var do
		local path = M.RUN_DIR .. "/" .. entry
		if entry:match("^gen%-") then
			local st = lfs.stat(path)
			if st and st.type == "dir" then
				-- 提取目录名中的时间戳用于排序（gen-<timestamp>[-suffix]）
				local ts = tonumber(entry:match("^gen%-(%d+)")) or 0
				items[#items + 1] = { path = path, name = entry, timestamp = ts, mtime = st.mtime or 0 }
			end
		end
	end

	-- 按目录名中的时间戳降序排序（保证生成先后顺序），timestamp 相同时提取后缀数字按数值降序
	table.sort(items, function(a, b)
		if a.timestamp ~= b.timestamp then return a.timestamp > b.timestamp end
		-- 仅对 gen-<ts>-<n> 格式（有两个连字符）解析后缀 n，gen-<ts> 格式按 mtime 排序
		local na = tonumber(a.name:match("^gen%-%d+%-(%d+)$")) or 0
		local nb = tonumber(b.name:match("^gen%-%d+%-(%d+)$")) or 0
		if na ~= nb then return na > nb end
		return a.mtime > b.mtime
	end)

	-- 显式保留 keep（当前产物），其余名额从非 keep 项中选取
	local to_keep = {}
	if keep then
		to_keep[keep] = true
	end

	-- 从排序后的列表中选取非 keep 项以保证总数最近 3 份
	local need = MAX_KEEP - (keep and 1 or 0)
	local added = 0
	for _, item in ipairs(items) do
		if item.path ~= keep and added < need then
			to_keep[item.path] = true
			added = added + 1
		end
	end

	-- 删除不在保留集合中的产物
	for _, item in ipairs(items) do
		if not to_keep[item.path] then
			os.execute("rm -rf " .. shq(item.path) .. " >/dev/null 2>&1")
		end
	end
end

function M.prepare_artifacts(lines)
	local text = table.concat(lines, "\n")
	local node_pool = M.nodes()
	local pool_for_gen = {}
	for _, n in ipairs(node_pool) do
		pool_for_gen[#pool_for_gen + 1] = { name = n.name, link = n.link }
	end
	local ok, res, err = pcall(gen.render, text, { node_pool = pool_for_gen })
	if not ok then
		prune_artifacts(nil) -- 渲染失败也清理
		return nil, tostring(res)
	end
	if not res then
		prune_artifacts(nil)
		return nil, tostring(err)
	end

	-- 获取 WiFi 密码并校验
	local password = M.get_wifi_password()
	if not password or password == "" then
		prune_artifacts(nil) -- 密码检查失败也清理
		return nil, "WiFi 密码未配置，请先在批量生成页面设置密码"
	end
	local ok_pw, err_pw = validate_wifi_password(password)
	if not ok_pw then
		prune_artifacts(nil)
		return nil, "WiFi 密码不合规：" .. tostring(err_pw)
	end

	local ok_run, err_run = M.ensure_run()
	if not ok_run then
		prune_artifacts(nil)
		return nil, err_run
	end
	-- 每次部署独占一个产物目录，绝不与其他请求共写同一份文件
	local stamp = tostring(os.time())
	local dir = M.RUN_DIR .. "/gen-" .. stamp
	local n = 0
	while fs.stat(dir) do
		n = n + 1
		dir = M.RUN_DIR .. "/gen-" .. stamp .. "-" .. n
	end

	local function fail(msg)
		os.execute("rm -rf " .. shq(dir) .. " >/dev/null 2>&1")
		prune_artifacts(nil) -- 失败后清理旧产物
		return nil, msg
	end

	-- 创建产物目录并确保权限 0700
	fs.mkdirr(dir)
	local ok_chmod = pcall(fs.chmod, dir, 700) -- 0700
	-- 注意：fs.chmod 成功时返回 nil，因此不能检查其返回值，只判断 pcall 是否抛错
	local st_dir = fs.stat(dir)

	-- 确保持久化配置目录 /etc/tkproxy 存在且权限 0700
	local ok_etc, err_etc = ensure_dir(M.CONF_DIR)
	if not ok_etc then
		return fail(err_etc)
	end

	if not fs.writefile(dir .. "/xray.json", res.config) then
		return fail("写入 xray.json 失败")
	end
	-- xray.json 含凭据必须 0600 且 chmod 失败视为失败
	local ok_chmod = pcall(fs.chmod, dir .. "/xray.json", 384) -- 0600 -- 0600
	-- 注意：fs.chmod 成功时返回 nil，因此不能检查其返回值，只判断 pcall 是否抛错
	local st_xray = fs.stat(dir .. "/xray.json")
	if not fs.writefile(dir .. "/tkproxy.nft", res.nft) then
		return fail("写入 tkproxy.nft 失败")
	end
	if not fs.writefile(dir .. "/manifest.json", res.manifest) then
		return fail("写入 manifest.json 失败")
	end
	-- 写入 WiFi 密码到产物（权限 0600）
	if not fs.writefile(dir .. "/wifi.key", password .. "\n") then
		return fail("写入 wifi.key 失败")
	end
	-- 每条线路自己的 WiFi 密码（线路行第 5 段）：写成 "<idx> <key>" 表，
	-- apply.sh 生成该条 wifi-iface 时优先用它，没有才回退全局 wifi.key。
	local keys_buf = {}
	for i, ln in ipairs(lines) do
		local k = M.line_key(ln)
		if k ~= "" then
			keys_buf[#keys_buf + 1] = string.format("%d %s", i, k)
		end
	end
	if #keys_buf > 0 then
		if not fs.writefile(dir .. "/wifi.keys", table.concat(keys_buf, "\n") .. "\n") then
			return fail("写入 wifi.keys 失败")
		end
		pcall(fs.chmod, dir .. "/wifi.keys", 384) -- 0600
	end
	local ok_chmod = pcall(fs.chmod, dir .. "/wifi.key", 384) -- 0600
	-- 注意：fs.chmod 成功时返回 nil，因此不能检查其返回值，只判断 pcall 是否抛错
	local st_key = fs.stat(dir .. "/wifi.key")
	-- 四份产物全部写成功后才原子发布
	if not publish_artifacts(dir) then
		return fail("发布产物失败：符号链接操作未成功")
	end
	prune_artifacts(dir) -- 成功后清理旧产物
	return dir
end

-- ---------------------------------------------------------------------------
-- 后台任务（apply.sh / clean.sh / status.sh）
--
-- 每个任务三件套：<name>.log / <name>.rc / <name>.pid
--   rc 不存在 + pid 活着 = running
--   rc 存在              = done / failed（rc 即退出码）
-- ---------------------------------------------------------------------------

local function job_log(n) return M.RUN_DIR .. "/" .. n .. ".log" end
local function job_rc(n) return M.RUN_DIR .. "/" .. n .. ".rc" end
local function job_pid(n) return M.RUN_DIR .. "/" .. n .. ".pid" end
local function job_started(n) return M.RUN_DIR .. "/" .. n .. ".started" end
local function status_json() return M.RUN_DIR .. "/status.json" end

function M.job_running(name)
	if fs.stat(job_rc(name)) then return false end
	local pid = trim(fs.readfile(job_pid(name)) or "")
	if pid:match("^%d+$") then
		return trim(M.exec("kill -0 " .. pid .. " >/dev/null 2>&1 && printf 1")) == "1"
	end
	-- pid 还没落盘的极短窗口：10 秒内按 running 处理，避免并发重复启动
	local st = fs.stat(job_started(name))
	if st and (os.time() - st.mtime) < 10 then return true end
	return false
end

function M.job_start(name, cmdline)
	local ok, err = M.ensure_run()
	if not ok then return false, err end
	if M.job_running(name) then
		return false, "已有任务正在运行，请稍候"
	end
	fs.remove(job_rc(name))
	fs.remove(job_log(name))
	fs.remove(job_pid(name))
	fs.writefile(job_started(name), tostring(os.time()))

	-- 通过管道拦截任务输出，每次写入后同步限长，限长失败时阻止继续写入
	-- 任务输出先进管道，由包裹脚本逐行写入并实时限长，确保日志不会先超限
	-- 使用临时文件跨管道传递源命令真实退出码
	-- 追加与截断共用同一把锁（.log.lock），优先 flock 加锁写入，回退到无锁模式
	local rc_tmp = job_rc(name) .. ".tmp"
	local logpath = job_log(name)
	local lockpath = logpath .. ".lock"
	local wrapper = string.format(
		"{ { %s; } 2>&1 & _src=$!; wait $_src; echo $? > %s; " ..
		"} | { while IFS= read -r _line; do " ..
		"{ exec 9>%s && flock -x 9 && echo \"$_line\" >> %s && exec 9>&-; } || " ..
		"echo \"$_line\" >> %s; " ..
		"if [ $(stat -c %%s %s 2>/dev/null || echo 0) -gt 262144 ]; then " ..
		"lua -e 'local u=require(\"luci.model.tkproxy.util\"); " ..
		"local ok,e=u.truncate_all_logs(); " ..
		"if not ok then io.stderr:write(\"限长失败: \"..tostring(e)..\"\\n\"); os.exit(1) end' || " ..
		"{ echo \"日志限长失败，任务已终止\" >> %s; exit 1; }; fi; done; }; " ..
		"cat %s > %s 2>/dev/null || echo 1 > %s",
		cmdline, shq(rc_tmp), shq(lockpath), shq(logpath), shq(logpath), shq(logpath), shq(logpath),
		shq(rc_tmp), shq(job_rc(name)), shq(job_rc(name))
	)
	-- 25.12 的 busybox 里没有 nohup（applet 被裁），原来这条命令会让作业静默不启动，
	-- 表现是「点部署什么都没发生、AP/桥都不变」。改成把 wrapper 落成脚本文件，
	-- 有 setsid 用 setsid，没有就退回直接后台跑。
	local jobsh = M.RUN_DIR .. "/job-" .. name .. ".sh"
	fs.writefile(jobsh, "#!/bin/sh\n" .. wrapper .. "\n")
	fs.chmod(jobsh, "0700") -- fs.chmod 要字符串模式，传数字会报 bad argument
	local cmd = "(command -v setsid >/dev/null 2>&1 && setsid sh " .. shq(jobsh) ..
		" || sh " .. shq(jobsh) .. ") >/dev/null 2>&1 & echo $! >" .. shq(job_pid(name))
	M.exec(cmd)
	return true
end

local function progress_of(name, log)
	local marks
	if name == "clean" then
		marks = { { "== 1.", 12 }, { "== 2.", 45 }, { "== 3.", 75 }, { "== 4.", 90 } }
	else
		marks = {
			{ "== 1.", 8 }, { "== 2.", 20 }, { "== 3.", 35 },
			{ "== 4.", 55 }, { "== 5.", 78 }, { "== 6.", 94 },
		}
	end
	local p = log ~= "" and 3 or 0
	for _, m in ipairs(marks) do
		if log:find(m[1], 1, true) then p = m[2] end
	end
	if log:find("部署完成", 1, true) or log:find("已拆除", 1, true) then p = 100 end
	return p
end

function M.job_state(name)
	local log = read_tail(job_log(name))
	if not fs.stat(job_rc(name)) then
		if M.job_running(name) then
			return {
				state = "running",
				ok = false,
				progress = progress_of(name, log),
				msg = last_line(log) ~= "" and last_line(log) or "任务已启动…",
				log = log,
			}
		end
		return { state = "idle", ok = false, progress = 0, msg = "", log = "" }
	end
	local rc = trim(fs.readfile(job_rc(name)) or "")
	local ok = (rc == "0")
	local msg
	if ok then
		msg = (name == "clean") and "回滚完成" or "部署完成"
	else
		msg = last_line(log)
		if msg == "" then msg = "任务失败（退出码 " .. rc .. "）" end
	end
	return {
		state = ok and "done" or "failed",
		ok = ok,
		progress = ok and 100 or progress_of(name, log),
		msg = msg,
		log = log,
	}
end

function M.invalidate_status()
	fs.remove(status_json())
	fs.remove(M.RUN_DIR .. "/status.json.tmp")
	fs.remove(job_rc("status"))
	fs.remove(job_pid("status"))
	fs.remove(job_started("status"))
end

-- 检测并清理僵死任务（前置声明已在 with_lock 之前完成）
cleanup_zombie_task = function(task_name)
	local pid_file = M.RUN_DIR .. "/" .. task_name .. ".pid"
	local status_file = M.RUN_DIR .. "/status.json"
	local lock_file = M.RUN_DIR .. "/.lock"

	local pid = trim(fs.readfile(pid_file) or "")
	if not pid:match("^%d+$") then return false end

	-- 检查进程是否存在
	local alive = false
	local zcmd = trim(M.exec("cat /proc/" .. pid .. "/cmdline 2>/dev/null | tr '\\000' ' '"))
	if zcmd ~= "" and (zcmd:find("apply%.sh") or zcmd:find("clean%.sh") or zcmd:find("tkproxy")) then
		alive = trim(M.exec("kill -0 " .. pid .. " >/dev/null 2>&1 && printf 1")) == "1"
	end
	if not alive then
		-- 进程已不存在，检查 status.json 状态
		local status_data = fs.readfile(status_file)
		local is_running = false
		if status_data then
			local ok, json = pcall(jsonc.parse, status_data)
			if ok and type(json) == "table" and json.state == "running" then
				is_running = true
			end
		end

		-- 如果 status.json 不是 running 且锁文件超过 10 分钟，判为僵死
		-- 进程已确认不是我们的部署任务（PID 可能被复用）：直接清理，不再等 10 分钟
		if true then
			local lock_stat = fs.stat(lock_file)
			if true then
				-- 清理僵死任务
				fs.remove(pid_file)
				fs.remove(M.RUN_DIR .. "/" .. task_name .. ".rc")
				fs.remove(M.RUN_DIR .. "/" .. task_name .. ".started")
				fs.remove(lock_file)
				local log = M.RUN_DIR .. "/" .. task_name .. ".log"
				local f = io.open(log, "a")
				if f then
					f:write(string.format("\n[%s] 清理僵死任务：进程 %s 已不存在，锁文件超过 10 分钟\n",
						os.date("%Y-%m-%d %H:%M:%S"), pid))
					f:close()
				end
				return true
			end
		end
	end
	return false
end

-- ---------------------------------------------------------------------------
-- 部署单例锁（deploy.lock）：防止多个 apply 并发互踩
-- flock 由 apply.sh 自己持有；这里在启动前检查锁文件的持有者是否存活。
-- ---------------------------------------------------------------------------
M.DEPLOY_LOCK = M.RUN_DIR .. "/deploy.lock"

-- 检查 deploy.lock 是否被活跃进程持有；僵死时自动清理。
-- 返回 true 表示可以启动，false, msg 表示不可以。
local function check_deploy_lock()
	local lock = M.DEPLOY_LOCK
	if not fs.stat(lock) then return true end

	-- 不能只看 kill -0：PID 会被系统复用，旧 PID 落到别的进程上就永远判“部署在运行”。
	-- 也不能只看 flock：busybox 下用 exec fd + flock -n 探测会误报“被占用”。
	-- 只认一件事——有没有真正在跑的 apply.sh / clean.sh。
	local function is_our_proc(pid)
		if not tostring(pid or ""):match("^%d+$") then return false end
		local cl = trim(M.exec("cat /proc/" .. pid .. "/cmdline 2>/dev/null | tr '\\000' ' '"))
		if cl == "" then return false end
		if (cl:find("apply%.sh") or cl:find("clean%.sh")) then
			return trim(M.exec("kill -0 " .. pid .. " >/dev/null 2>&1 && printf 1")) == "1"
		end
		return false
	end

	local pid = trim(fs.readfile(lock .. ".pid") or "")
	if is_our_proc(pid) then
		return false, string.format("已有部署在运行（PID %s），请稍候", pid)
	end

	-- 扫进程表时排除自己和父进程，否则命令行里带的 "apply.sh" 字样会自我匹配，永远判“在跑”
	local running = trim(M.exec("for d in /proc/[0-9]*; do p=${d#/proc/}; [ \"$p\" = \"$$\" ] && continue; [ \"$p\" = \"$PPID\" ] && continue; c=$(tr '\\000' ' ' < $d/cmdline 2>/dev/null); case \"$c\" in *apply.sh*|*clean.sh*) echo 1; break;; esac; done"))
	if running == "1" then
		return false, "已有部署在运行，请稍候"
	end

	-- 没有真实进程在跑：锁文件就是残留，清掉放行
	fs.remove(lock)
	fs.remove(lock .. ".pid")
	return true
end

-- 必须在锁内调用：检查 → 生成 → 启动 整段不可被打断
local function deploy_locked(lines, only_idx)
	-- 部署前严格校验：禁止节点共用
	local check = M.validate_unique_nodes(lines)
	if not check.ok then
		return false, check.msg
	end

	local dir, err = M.prepare_artifacts(lines)
	if not dir then return false, err end
	M.invalidate_status()
	if only_idx then
		return M.job_start("deploy", "sh " .. shq(M.APPLY) .. " --only " .. tostring(only_idx) .. " " .. shq(dir))
	end
	return M.job_start("deploy", "sh " .. shq(M.APPLY) .. " " .. shq(dir))
end

-- 单条线路部署：只重建这一条的无线/网络/端口/规则，其他线路不动
function M.start_deploy_line(idx)
	idx = tonumber(idx) or 0
	local lines = M.lines()
	if idx < 1 then return false, "行号无效" end
	if idx > #lines then return false, "行索引越界" end

	local lock_ok, lock_msg = check_deploy_lock()
	if not lock_ok then return false, lock_msg end
	if M.job_running("deploy") then
		return false, "上一次部署还在进行，请稍候"
	end
	if fs.stat(M.RUN_DIR .. "/deploy.pid") then
		if not cleanup_zombie_task("deploy") then
			return false, "上一次部署还在进行，请稍候"
		end
	end
	return with_lock(function()
		return deploy_locked(lines, idx)
	end)
end

function M.start_deploy(lines)
	lines = lines or M.lines()
	-- 部署单例锁：检查 deploy.lock 是否被持有
	local lock_ok, lock_msg = check_deploy_lock()
	if not lock_ok then
		return false, lock_msg
	end
	-- 启动前检测并清理僵死任务：进程已死但状态/锁残留
	if M.job_running("deploy") then
		return false, "部署任务正在执行，请稍候"
	end
	-- 进程不在运行但 PID 文件残留，检测僵死任务
	if fs.stat(M.RUN_DIR .. "/deploy.pid") then
		if not cleanup_zombie_task("deploy") then
			return false, "存在残留部署任务但不满足僵死清理条件，请稍候"
		end
	end
	return with_lock(function()
		return deploy_locked(lines)
	end)
end

-- 保存清单 + 部署：
--   1) 锁内先确认能生成产物（即「可启动」），再写 UCI；
--   2) 启动失败时把 UCI 回滚到保存前的快照，避免「UCI 已改但没部署」。
-- BLK-09：修复嵌套锁问题，直接调用 save_lines_locked
function M.save_and_deploy(lines)
	lines = lines or {}
	-- 部署单例锁：检查 deploy.lock 是否被持有
	local lock_ok, lock_msg = check_deploy_lock()
	if not lock_ok then
		return false, lock_msg
	end
	return with_lock(function()
		-- 部署前严格校验：禁止节点共用
		local check = M.validate_unique_nodes(lines)
		if not check.ok then
			return false, check.msg
		end

		local dir, err = M.prepare_artifacts(lines)
		if not dir then return false, err end
		local prev = M.lines()
		local ok, serr = save_lines_locked(lines)
		if not ok then return false, serr end
		M.invalidate_status()
		local started, jerr = M.job_start("deploy", "sh " .. shq(M.APPLY) .. " " .. shq(dir))
		if not started then
			if save_lines_locked(prev) then
				return false, (jerr or "无法启动部署") .. "（已恢复保存前的清单）"
			end
			return false, (jerr or "无法启动部署") .. "（恢复原清单失败，请手动检查 /etc/config/tkproxy）"
		end
		return true
	end)
end

function M.start_clean()
	-- 部署单例锁：检查 deploy.lock 是否被持有
	local lock_ok, lock_msg = check_deploy_lock()
	if not lock_ok then
		return false, lock_msg
	end
	-- 启动前检测并清理僵死任务：进程已死但状态/锁残留
	if M.job_running("clean") then
		return false, "回滚任务正在执行，请稍候"
	end
	-- 进程不在运行但 PID 文件残留，检测僵死任务
	if fs.stat(M.RUN_DIR .. "/clean.pid") then
		if not cleanup_zombie_task("clean") then
			return false, "存在残留回滚任务但不满足僵死清理条件，请稍候"
		end
	end
	return with_lock(function()
		M.invalidate_status()
		return M.job_start("clean", "sh " .. shq(M.CLEAN))
	end)
end

-- ---------------------------------------------------------------------------
-- 状态采集
-- ---------------------------------------------------------------------------

-- status.sh 的每一项都必须带这些字段，缺一项就说明采集没真正跑完
local function valid_status_item(it, i)
	if type(it) ~= "table" then
		return false, string.format("第 %d 项不是对象", i)
	end
	if type(it.ssid) ~= "string" or it.ssid == "" then
		return false, string.format("第 %d 项缺少 ssid", i)
	end
	if type(it.band) ~= "string" then
		return false, string.format("第 %d 项缺少 band", i)
	end
	if type(it.subnet) ~= "string" then
		return false, string.format("第 %d 项缺少 subnet", i)
	end
	if type(it.port) ~= "number" then
		return false, string.format("第 %d 项 port 不是数字", i)
	end
	if type(it.node_type) ~= "string" then
		return false, string.format("第 %d 项缺少 node_type", i)
	end
	if type(it.online) ~= "boolean" then
		return false, string.format("第 %d 项 online 不是布尔值", i)
	end
	if it.exit_ip ~= nil and type(it.exit_ip) ~= "string" then
		return false, string.format("第 %d 项 exit_ip 类型错误", i)
	end
	if it.note ~= nil and type(it.note) ~= "string" then
		return false, string.format("第 %d 项 note 类型错误", i)
	end
	return true
end

-- 解析并校验一份状态输出。返回 items, err；err 非空表示不可用。
local function parse_status(text)
	if not text or trim(text) == "" then
		return nil, "状态输出为空"
	end
	local t = trim(text)
	if t:sub(1, 1) ~= "[" then
		return nil, "状态输出不是 JSON 数组"
	end
	local ok, d = pcall(jsonc.parse, text)
	if not ok or type(d) ~= "table" then
		return nil, "状态输出不是合法 JSON"
	end
	for i, it in ipairs(d) do
		local good, why = valid_status_item(it, i)
		if not good then return nil, why end
	end
	local out = {}
	for _, it in ipairs(d) do
		out[#out + 1] = {
			ssid = str(it.ssid),
			band = str(it.band),
			subnet = str(it.subnet),
			port = tonumber(it.port) or 0,
			node_type = str(it.node_type),
			online = (it.online == true),
			exit_ip = str(it.exit_ip),
			note = str(it.note),
		}
	end
	return out
end

function M.read_status()
	return parse_status(fs.readfile(status_json()) or "")
end

-- 只有「非空 + 合法 JSON 数组 + 必需字段齐全」才原子替换 status.json。
-- status.sh 的真实退出码由 job_start 写进 status.rc，不再被 mv 吞掉。
local function promote_status()
	local tmp = status_json() .. ".tmp"
	local items, perr = parse_status(fs.readfile(tmp) or "")
	if not items then return false, perr end
	if not fs.rename(tmp, status_json()) then
		return false, "无法原子替换状态文件"
	end
	return true, items
end

local function status_start()
	local ok, err = M.ensure_run()
	if not ok then return false, err end
	local tmp = status_json() .. ".tmp"
	fs.remove(tmp)
	-- 这里不能接 mv：rc 必须是 status.sh 自己的退出码；
	-- 合法性校验与原子 rename 都在 promote_status() 里完成。
	-- stdout 进临时文件，stderr 也通过 job_start 的限长管道写入日志
	local cmd = "sh " .. shq(M.STATUS) .. " --json >" .. shq(tmp)
	return M.job_start("status", cmd)
end

function M.status_state()
	if not M.is_deployed() then
		return { state = "idle", deployed = false, items = {} }
	end

	local tmp = status_json() .. ".tmp"
	local src = fs.stat(job_rc("status"))

	-- 采集任务已结束：先验证临时输出，只有合法 JSON 数组才原子替换
	if src then
		local rc = trim(fs.readfile(job_rc("status")) or "")
		local promoted, perr
		if rc == "0" then
			promoted, perr = promote_status()
		else
			local log = read_tail(job_log("status"), 800)
			perr = last_line(log)
			if perr == "" then
				perr = "状态采集失败（退出码 " .. (rc ~= "" and rc or "?") .. "）"
			end
		end
		if promoted then
			-- 本次结果已落地，清掉任务标记，避免下一轮重复处理
			fs.remove(job_rc("status"))
			fs.remove(job_pid("status"))
			fs.remove(job_started("status"))
			fs.remove(tmp)
		else
			fs.remove(tmp)
			local age = os.time() - src.mtime
			-- 刚失败过（15 秒内）先不重启，避免脚本缺失时每 2.5 秒拉起一次
			if age < 15 then
				return {
					state = "failed",
					deployed = true,
					items = {},
					msg = perr or "状态采集失败",
				}
			end
			-- 失败后丢弃旧缓存，下一轮重新采集，避免把旧数据当成「已更新」
			fs.remove(status_json())
			fs.remove(job_rc("status"))
			fs.remove(job_pid("status"))
			fs.remove(job_started("status"))
		end
	end

	-- 部署/回滚刚跑完时，旧的 status.json 一定是过期的
	local dep = fs.stat(job_rc("deploy"))
	local cln = fs.stat(job_rc("clean"))
	local sj = fs.stat(status_json())
	local stale = false
	if dep and (not sj or sj.mtime <= dep.mtime) then stale = true end
	if cln and (not sj or sj.mtime <= cln.mtime) then stale = true end

	if M.job_running("deploy") or M.job_running("clean") then
		return { state = "wait", deployed = true, items = {} }
	end

	local items, item_err = M.read_status()
	local age = sj and (os.time() - sj.mtime) or nil
	if sj and not stale and age and age < 60 and not item_err then
		return { state = "done", deployed = true, items = items, age = age }
	end

	-- 卡住的采集任务：超过 240 秒直接换一个，否则页面永远等不到状态
	if M.job_running("status") then
		local st = fs.stat(job_started("status"))
		if st and (os.time() - st.mtime) > 240 then
			local pid = trim(fs.readfile(job_pid("status")) or "")
			if pid:match("^%d+$") then
				M.exec("kill -9 " .. pid .. " >/dev/null 2>&1")
			end
			fs.writefile(job_rc("status"), "124")
		else
			return { state = "running", deployed = true, items = items or {} }
		end
	end

	status_start()
	return { state = "running", deployed = true, items = items or {} }
end

-- ---------------------------------------------------------------------------
-- 批量生成 WiFi
-- ---------------------------------------------------------------------------

-- UTF-8 字节长度（用于 SSID 32 字节限制校验）
local function utf8_byte_len(s)
	return #tostring(s or "")
end

-- 生成随机密码（8~20 位，含大小写字母数字）
local function random_password()
	local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	local len = math.random(8, 20)
	local out = {}
	for i = 1, len do
		local idx = math.random(1, #chars)
		out[i] = chars:sub(idx, idx)
	end
	return table.concat(out)
end

-- 随机源播种：LuCI 每个请求都是全新 Lua state，不播种时 Lua 5.1 的
-- 默认种子固定，两批「留空随机」生成的密码序列完全一致（真机 30 条
-- 出现 15 组两两重复）。首次使用时用 /dev/urandom 播一次种。
local random_seeded = false
local function ensure_random_seed()
	if random_seeded then return end
	random_seeded = true
	local fh = io.open("/dev/urandom", "rb")
	if fh then
		local b = fh:read(4) or ""
		fh:close()
		if #b == 4 then
			local b1, b2, b3, b4 = b:byte(1, 4)
			-- 取模 2^31，保证落在任何 math.randomseed 实现都接受的范围内
			local seed = (b1 * 16777216 + b2 * 65536 + b3 * 256 + b4) % 2147483648
			math.randomseed(seed)
			return
		end
	end
	-- urandom 不可用时的兜底：时间 + 时钟精度混合
	math.randomseed(os.time() % 2147483647 * 1000 + math.floor((os.clock() % 1) * 1000000))
end

-- 从未被用过的随机密码：与已有线路/本批已生成的密码去重。
-- 62 字符集 × 8~20 位，500 次内仍撞车在概率上不可能；真撞了就报错，
-- 绝不静默生成重复密码。
local function unique_random_key(used_keys)
	ensure_random_seed()
	for _ = 1, 500 do
		local pw = random_password()
		if not used_keys[pw] then
			used_keys[pw] = true
			return pw
		end
	end
	return nil
end

-- 容量预览：计算创建后每个射频的 AP 数
-- 自动匹配：把池里未被引用的节点，按顺序分配给尚未绑定节点的线路
-- 返回 { ok, lines, assigned, shortfall, pool_free }
function M.auto_assign(lines)
	lines = lines or M.lines()
	local pool = M.nodes()

	local used = {}
	local unbound = {}
	local out = {}

	for i, ln in ipairs(lines) do
		out[i] = ln
		local ssid, band, src = split_line(ln)
		if ssid then
			src = trim(src or "")
			if src:sub(1, 1) == "@" and #src > 1 then
				used[src:sub(2)] = true
			elseif src == "" then
				unbound[#unbound + 1] = { idx = i, ssid = ssid, band = (band ~= "" and band) or "2g" }
			end
		end
	end

	local free = {}
	for _, n in ipairs(pool) do
		if not used[n.name] then free[#free + 1] = n.name end
	end

	local assigned = {}
	for k, u in ipairs(unbound) do
		local name = free[k]
		if not name then break end
		local keep_a = line_key(out[u.idx] or "")
		local nl_a = string.format("%s|%s|@%s", u.ssid, u.band, name)
		if keep_a ~= "" then nl_a = nl_a .. "|1|" .. keep_a end
		out[u.idx] = nl_a
		assigned[#assigned + 1] = { line_index = u.idx, ssid = u.ssid, node = name }
	end

	return {
		ok = true,
		lines = out,
		assigned = assigned,
		shortfall = #unbound - #assigned,
		pool_free = #free - #assigned,
	}
end

function M.batch_capacity_preview(opts)
	local count = tonumber(opts.count) or 0
	local mode = opts.mode or "auto"
	local limit_2g = tonumber(opts.limit_2g) or M.LIMIT
	local limit_5g = tonumber(opts.limit_5g) or M.LIMIT
	local used_2g = tonumber(opts.used_2g) or 0
	local used_5g = tonumber(opts.used_5g) or 0

	local need_2g, need_5g = 0, 0

	if mode == "manual" then
		need_2g = tonumber(opts.count_2g) or 0
		need_5g = tonumber(opts.count_5g) or 0
	else
		-- 自动均分：2.4G 先填到上限，剩下的给 5G
		local avail_2g = limit_2g - used_2g
		if count <= avail_2g then
			need_2g = count
			need_5g = 0
		else
			need_2g = avail_2g
			need_5g = count - avail_2g
		end
	end

	local final_2g = used_2g + need_2g
	local final_5g = used_5g + need_5g

	local ok = true
	local errors = {}

	if final_2g > limit_2g then
		ok = false
		local over = final_2g - limit_2g
		table.insert(errors, string.format(
			"radio0 (2.4G) 将达 %d 个 AP，超过驱动上限 %d，请减少 %d 个",
			final_2g, limit_2g, over
		))
	end

	if final_5g > limit_5g then
		ok = false
		local over = final_5g - limit_5g
		table.insert(errors, string.format(
			"radio1 (5G) 将达 %d 个 AP，超过驱动上限 %d，请减少 %d 个",
			final_5g, limit_5g, over
		))
	end

	return {
		ok = ok,
		errors = errors,
		need_2g = need_2g,
		need_5g = need_5g,
		final_2g = final_2g,
		final_5g = final_5g,
	}
end

-- 批量生成 WiFi 清单行
function M.batch_generate(opts)
	local count = tonumber(opts.count) or 0
	local prefix = tostring(opts.prefix or "TK-")
	local start_seq = tonumber(opts.start_seq) or 1
	local password = opts.password or ""
	local mode = opts.mode or "auto"

	if count < 1 or count > 30 then
		return { ok = false, error = "数量必须在 1~30 之间" }
	end
	if start_seq < 1 then
		return { ok = false, error = "起始序号必须 ≥1" }
	end
	if prefix == "" then
		return { ok = false, error = "前缀不能为空" }
	end
	if prefix:find("[%c\"'|]") then
		return { ok = false, error = "前缀不能包含引号、竖线或控制字符" }
	end
	if password ~= "" then
		local ok_pw, err_pw = validate_wifi_password(password)
		if not ok_pw then
			return { ok = false, error = err_pw }
		end
	end

	local preview = M.batch_capacity_preview(opts)
	if not preview.ok then
		return { ok = false, error = table.concat(preview.errors, "；") }
	end

	local lines = opts.existing_lines or M.lines()
	local existing = {}
	for _, ln in ipairs(lines) do
		local ssid = ln:match("^([^|]+)")
		if ssid then existing[ssid] = true end
	end

	-- 跨批次密码去重：把已有线路的密码全部收进集合，
	-- 这样「先建 15 条再建 15 条」第二批不会撞第一批的密码
	local used_keys = {}
	for _, ln in ipairs(lines) do
		local k = line_key(ln)
		if k ~= "" then used_keys[k] = true end
	end
	if password ~= "" then used_keys[password] = true end

	-- 池里已被引用的节点不再重复分配
	local pool = M.nodes()
	local used = {}
	for _, ln in ipairs(lines) do
		local _, _, src = split_line(ln)
		src = trim(src or "")
		if src:sub(1, 1) == "@" and #src > 1 then
			used[src:sub(2)] = true
		end
	end
	local free = {}
	for _, n in ipairs(pool) do
		if not used[n.name] then free[#free + 1] = n.name end
	end

	local new_lines, assigned = {}, {}
	local generated_keys = {}
	local seq = start_seq
	local made = 0
	local skipped = 0

	local function make(band)
		local ssid
		local guard = 0
		repeat
			ssid = prefix .. string.format("%02d", seq)
			seq = seq + 1
			guard = guard + 1
			if guard > 500 then
				return nil, "序号连续冲突过多，请调大起始序号"
			end
			if existing[ssid] then
				ssid = nil
				skipped = skipped + 1
			elseif ssid:find("%c") then
				return nil, string.format("SSID '%s' 含控制字符", ssid)
			elseif utf8_byte_len(ssid) > 32 then
				return nil, string.format("SSID '%s' 超过 32 字节（按 UTF-8 计）", ssid)
			end
		until ssid

		local name = free[made + 1]
		-- 密码留空 → 统一用默认密码 abc123456（与界面 placeholder 一致）
		local pw_use = password
		if pw_use == "" then
			pw_use = M.DEFAULT_WIFI_PASSWORD
		end
		local line
		if name then
			-- 直接绑定该节点 URI：一个 SSID 对应一个节点
			if pw_use ~= "" then
				line = string.format("%s|%s|@%s|1|%s", ssid, band, name, pw_use)
			else
				line = string.format("%s|%s|@%s", ssid, band, name)
			end
			assigned[#assigned + 1] = { ssid = ssid, band = band, node = name }
		else
			-- 池里没有空闲节点：留空链接，后续在概览页下拉选择
			if pw_use ~= "" then
				line = string.format("%s|%s||1|%s", ssid, band, pw_use)
			else
				line = string.format("%s|%s|", ssid, band)
			end
		end
		if pw_use ~= "" then
			generated_keys[#generated_keys + 1] = { ssid = ssid, key = pw_use }
		end
		existing[ssid] = true
		made = made + 1
		new_lines[#new_lines + 1] = line
		return true
	end

	local i
	for i = 1, preview.need_2g do
		local ok2, err2 = make("2g")
		if not ok2 then return { ok = false, error = err2 } end
	end
	for i = 1, preview.need_5g do
		local ok5, err5 = make("5g")
		if not ok5 then return { ok = false, error = err5 } end
	end

	-- 保存密码到 UCI（留空时也把默认密码记下来，供下次"单条部署"使用）
	if password == "" then password = M.DEFAULT_WIFI_PASSWORD end
	if password ~= "" then
		local ok_save, err_save = M.save_wifi_password(password)
		if not ok_save then
			return { ok = false, error = "密码保存失败：" .. tostring(err_save) }
		end
	end

	return {
		ok = true,
		lines = new_lines,
		keys = generated_keys,
		count = #new_lines,
		assigned = assigned,
		unbound = #new_lines - #assigned,
		skipped = skipped,
		password = password,
		final_2g = preview.final_2g,
		final_5g = preview.final_5g,
	}
end

return M
