#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 开箱自检（t_d32788de）
#
# 用途：固件刷好后自动跑一次系统自检（preflight.sh --json），结果落盘
#       /etc/tkproxy/bootcheck.json，概览页据此显示「待机 · 可直接使用」状态条。
#
# 节流：bootcheck.json 不存在或距今超过 24h 才真正跑；--force 强制重跑。
# 时序：由 init boot/start_service 或 apply.sh 部署完成后后台拉起，
#       绝不阻塞开机与部署；自检失败只写日志，不影响任何流程。
# 兼容：版本号读取兼容 opkg(24.10) 与 apk(25.12+)，与 update.sh 的
#       installed_version() 同口径，不另写一套。
#
# bootcheck.json 数据契约（固定，前端按此渲染）：
#   {"ts":1793...,"ver":"3.13.x","block":0,"warn":0,"pass":10,
#    "items":[{"id":"xray","title":"Xray 核心","level":"pass","detail":"已安装 26.3.27","fix":""}]}
#
# 失败兜底（脚本异常/解析失败也必须产出可渲染的 JSON）：
#   {"ts":...,"ver":"...","block":1,"warn":0,"pass":0,
#    "items":[{"id":"bootcheck","title":"开箱自检","level":"block","detail":"...","fix":""}]}

BOOT_DIR=/etc/tkproxy
BOOT_JSON=$BOOT_DIR/bootcheck.json
BOOT_TMP=$BOOT_JSON.tmp
BOOT_LOCK=/tmp/tkproxy/bootcheck.lock.d
PREFLIGHT=/usr/libexec/tkproxy/preflight.sh
MAX_AGE=86400  # 24h

log() { logger -t tkproxy-bootcheck "$*" 2>/dev/null; }

json_esc() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'
}

# 已装插件版本：opkg(24.10) 优先，apk(25.12+) 兜底（与 update.sh installed_version 同口径）
pkg_version() {
	local v
	v=$(sed -n 's/^Version:[[:space:]]*//p' /usr/lib/opkg/info/luci-app-tkproxy.control 2>/dev/null | head -n1)
	if [ -z "$v" ] && [ -f /lib/apk/db/installed ]; then
		v=$(awk '/^P:luci-app-tkproxy$/{f=1;next} f&&/^V:/{print substr($0,3);exit}' /lib/apk/db/installed 2>/dev/null)
	fi
	[ -n "$v" ] || v="0"
	# opkg 3.13.5-1 / apk 3.13.5-r1 → 统一 3.13.5（sed 字符类不是 Lua 的 %w 写法）
	printf '%s' "$v" | sed 's/[^A-Za-z0-9.-]//g; s/-r\{0,1\}[0-9][0-9]*$//'
}

# 是否需要跑：文件不存在 / 内容损坏 / 超过 24h → 是
need_run() {
	[ -s "$BOOT_JSON" ] || return 0
	local now ts
	now=$(date +%s 2>/dev/null) || return 0
	ts=$(sed -n 's/.*"ts":\([0-9][0-9]*\).*/\1/p' "$BOOT_JSON" 2>/dev/null | head -n1)
	case "$ts" in ''|*[!0-9]*) return 0 ;; esac
	[ $((now - ts)) -ge $MAX_AGE ] && return 0
	return 1
}

# 写失败兜底 JSON：detail $1
write_fallback() {
	local detail now
	now=$(date +%s 2>/dev/null) || now=0
	mkdir -p "$BOOT_DIR" 2>/dev/null
	{
		printf '{"ts":%s,"ver":"%s","block":1,"warn":0,"pass":0,' \
			"$now" "$(json_esc "$(pkg_version)")"
		printf '"items":[{"id":"bootcheck","title":"开箱自检","level":"block","detail":"%s","fix":""}]}' \
			"$(json_esc "$1")"
	} >"$BOOT_TMP" 2>/dev/null && mv "$BOOT_TMP" "$BOOT_JSON"
}

# 主流程：跑 preflight --json，统计 block/warn/pass，重写为契约结构（原子写）
run_check() {
	local raw now ver n_block n_warn n_pass
	now=$(date +%s 2>/dev/null) || now=0
	ver=$(pkg_version)

	raw=$(sh "$PREFLIGHT" --json 2>/dev/null)
	if [ -z "$raw" ]; then
		log "preflight 无输出，写失败兜底"
		write_fallback "自检脚本无输出，请点「立即自检」重试"
		return 1
	fi

	# preflight 输出的是 items 数组；这里统计各档数量并拼成契约 JSON
	n_block=0; n_warn=0; n_pass=0
	n_block=$(printf '%s' "$raw" | grep -o '"level":"block"' | wc -l)
	n_warn=$(printf '%s' "$raw" | grep -o '"level":"warn"' | wc -l)
	n_pass=$(printf '%s' "$raw" | grep -o '"level":"pass"' | wc -l)

	mkdir -p "$BOOT_DIR" 2>/dev/null
	{
		printf '{"ts":%s,"ver":"%s","block":%s,"warn":%s,"pass":%s,"items":%s}' \
			"$now" "$(json_esc "$ver")" "$n_block" "$n_warn" "$n_pass" "$raw"
	} >"$BOOT_TMP" 2>/dev/null || {
		log "写 $BOOT_TMP 失败"
		write_fallback "自检结果写入失败（存储空间？）"
		return 1
	}
	mv "$BOOT_TMP" "$BOOT_JSON" || {
		log "mv 原子替换失败"
		write_fallback "自检结果落盘失败"
		return 1
	}
	log "开箱自检完成：block=$n_block warn=$n_warn pass=$n_pass → $BOOT_JSON"
	return 0
}

main() {
	mkdir -p /tmp/tkproxy 2>/dev/null

	# --force：跳过节流（页面「立即自检」按钮用）
	if [ "$1" != "--force" ]; then
		if ! need_run; then
			log "未到 24h 且已有结果，跳过"
			return 0
		fi
	fi

	# 并发去重：mkdir 是原子的，两个进程只会有一个成功（部署完成与 boot 同时触发时只跑一份）
	# 旧式「先 cat 检查 PID 再写锁」有 TOCTOU 竞态，弃用
	if ! mkdir "$BOOT_LOCK" 2>/dev/null; then
		log "已有自检在跑（锁 $BOOT_LOCK 被占），退出"
		return 0
	fi
	trap 'rmdir "$BOOT_LOCK" 2>/dev/null' EXIT INT TERM

	run_check
}

main "$@"
