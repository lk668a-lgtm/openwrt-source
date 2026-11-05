#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# Xray 内核版本自检与一键升级/回滚
#
# 用法：
#   xray-upgrade.sh current    # 输出当前版本号
#   xray-upgrade.sh check      # 检查版本是否满足最低要求，输出 JSON
#   xray-upgrade.sh upgrade    # 一键升级到最新版并验证，支持回滚
#
# 最低要求版本（内置常量，用于 check 命令）
MIN_VERSION=26.0.0
# 升级目标版本（GitHub Release 版本号）
TARGET_VERSION=26.10.31

PROG=xray-upgrade

die() {
	printf '[ERROR] %s: %s\n' "$PROG" "$*" >&2
	exit 1
}

say() {
	printf '[INFO] %s\n' "$*"
}

# 版本比较：v1 < v2 返回 0，否则返回 1
# 用 awk 按 . 分段比较（支持 25.2.21、26.10.31 格式）
version_lt() {
	printf '%s\n%s\n' "$1" "$2" | awk '
		BEGIN { FS = "."; v1[1] = v1[2] = v1[3] = 0; v2[1] = v2[2] = v2[3] = 0 }
		NR == 1 {
			split($0, v1, ".")
			for (i = 1; i <= 3; i++) v1[i] = v1[i] + 0
		}
		NR == 2 {
			split($0, v2, ".")
			for (i = 1; i <= 3; i++) v2[i] = v2[i] + 0
		}
		END {
			if (v1[1] < v2[1]) exit 0
			if (v1[1] > v2[1]) exit 1
			if (v1[2] < v2[2]) exit 0
			if (v1[2] > v2[2]) exit 1
			if (v1[3] < v2[3]) exit 0
			exit 1
		}
	'
}

# 提取 Xray 版本号（输入：xray version 首行输出，如 "Xray 25.2.21 (Xray, Penetrates Everything.)"）
extract_version() {
	printf '%s\n' "$1" | sed -n 's/^Xray \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n 1
}

# current 子命令：输出当前版本号
cmd_current() {
	if ! command -v xray >/dev/null 2>&1; then
		printf 'unknown\n'
		return 0
	fi
	local output
	output=$(xray version 2>/dev/null | head -n 1) || {
		printf 'unknown\n'
		return 0
	}
	local ver
	ver=$(extract_version "$output")
	[ -n "$ver" ] || ver=unknown
	printf '%s\n' "$ver"
}

# check 子命令：输出 JSON
cmd_check() {
	local current
	current=$(cmd_current)
	local satisfied=false
	if [ "$current" != "unknown" ]; then
		if version_lt "$current" "$MIN_VERSION"; then
			satisfied=false
		else
			satisfied=true
		fi
	fi
	printf '{"ok":true,"current":"%s","min":"%s","satisfied":%s}\n' "$current" "$MIN_VERSION" "$satisfied"
}

# 架构映射（uname -m 到 Xray Release 包名）
arch_map() {
	local machine
	machine=$(uname -m) || die "无法获取架构（uname -m 失败）"
	case "$machine" in
		aarch64) printf 'linux-arm64-v8a' ;;
		armv7l)  printf 'linux-arm32-v7a' ;;
		x86_64)  printf 'linux-64' ;;
		*) die "不支持的架构：$machine（支持 aarch64/armv7l/x86_64）" ;;
	esac
}

# upgrade 子命令：下载→校验→备份→替换→验证→失败回滚
cmd_upgrade() {
	local arch
	arch=$(arch_map)
	say "架构：$arch"

	local current
	current=$(cmd_current)
	say "当前版本：$current"

	if [ "$current" != "unknown" ]; then
		if ! version_lt "$current" "$TARGET_VERSION"; then
			say "当前版本 $current 已满足或高于目标版本 $TARGET_VERSION，无需升级"
			printf '{"ok":true,"from":"%s","to":"%s","skipped":true}\n' "$current" "$TARGET_VERSION"
			return 0
		fi
	fi

	local url="https://github.com/XTLS/Xray-core/releases/download/v${TARGET_VERSION}/Xray-${arch}.zip"
	local tmpdir="/tmp/xray-upgrade.$$"
	mkdir -p "$tmpdir" || die "无法创建临时目录：$tmpdir"

	say "下载 Xray v${TARGET_VERSION}（$arch）..."
	local zipfile="$tmpdir/Xray-${arch}.zip"
	if ! wget -q --timeout=120 --tries=3 -O "$zipfile" "$url" 2>&1; then
		rm -rf "$tmpdir"
		die "下载失败：$url（请检查网络或 GitHub 连通性）"
	fi

	# 校验文件大小（Xray 压缩包通常 >5MB）
	local size
	size=$(stat -c %s "$zipfile" 2>/dev/null) || size=0
	if [ "$size" -lt 5242880 ]; then
		rm -rf "$tmpdir"
		die "下载的文件过小（$size 字节 < 5MB），可能下载不完整"
	fi
	say "下载完成（$size 字节），正在解压..."

	if ! command -v unzip >/dev/null 2>&1; then
		rm -rf "$tmpdir"
		die "缺少 unzip 命令，无法解压（请安装 unzip）"
	fi

	if ! unzip -q "$zipfile" -d "$tmpdir" 2>&1; then
		rm -rf "$tmpdir"
		die "解压失败（文件可能损坏）"
	fi

	if [ ! -f "$tmpdir/xray" ]; then
		rm -rf "$tmpdir"
		die "解压后未找到 xray 二进制文件"
	fi

	# 改名为 /tmp/xray.new 并校验
	local xray_new="/tmp/xray.new"
	cp -f "$tmpdir/xray" "$xray_new" || {
		rm -rf "$tmpdir"
		die "无法创建 /tmp/xray.new"
	}
	chmod 755 "$xray_new" || {
		rm -rf "$tmpdir" "$xray_new"
		die "无法设置可执行权限"
	}

	# 验证新版本可执行
	say "验证新版本..."
	local new_output
	new_output=$("$xray_new" version 2>/dev/null | head -n 1) || {
		rm -rf "$tmpdir" "$xray_new"
		die "新版本 xray 无法执行（可能二进制不兼容或损坏）"
	}
	local new_ver
	new_ver=$(extract_version "$new_output")
	if [ -z "$new_ver" ] || [ "$new_ver" = "unknown" ]; then
		rm -rf "$tmpdir" "$xray_new"
		die "新版本 xray version 输出异常：$new_output"
	fi
	say "新版本号：$new_ver"

	# 备份旧版（如果存在）
	local xray_bin="/usr/bin/xray"
	local backup="/tmp/xray-old.bak"
	if [ -f "$xray_bin" ]; then
		say "备份旧版本到 $backup"
		if ! cp -f "$xray_bin" "$backup"; then
			rm -rf "$tmpdir" "$xray_new"
			die "备份失败"
		fi
	else
		say "未找到旧版本，直接安装"
	fi

	# 替换
	say "替换 $xray_bin"
	if ! cp -f "$xray_new" "$xray_bin"; then
		# 回滚
		if [ -f "$backup" ]; then
			if ! cp -f "$backup" "$xray_bin"; then
				die "替换失败且回滚失败"
			fi
		fi
		rm -rf "$tmpdir" "$xray_new"
		die "替换失败（权限不足？）"
	fi

	# 无条件重启服务
	say "重启服务..."
	local restart_ok=1
	if [ -x /etc/init.d/tkproxy ]; then
		if ! /etc/init.d/tkproxy restart >/dev/null 2>&1; then
			say "重启服务失败，正在回滚..."
			restart_ok=0
		fi
	else
		say "未找到 /etc/init.d/tkproxy，跳过服务重启"
	fi

	# 重启失败时回滚
	if [ "$restart_ok" = "0" ]; then
		if [ -f "$backup" ]; then
			if ! cp -f "$backup" "$xray_bin"; then
				die "重启失败且回滚失败"
			fi
			# 恢复后再次重启
			if [ -x /etc/init.d/tkproxy ]; then
				/etc/init.d/tkproxy restart >/dev/null 2>&1 || true
			fi
		fi
		rm -rf "$tmpdir" "$xray_new"
		die "服务重启失败，已回滚到旧版本"
	fi

	# 验证最终版本
	say "验证安装结果..."
	local final_ver
	final_ver=$(cmd_current)
	if [ "$final_ver" != "$new_ver" ]; then
		# 回滚
		say "错误：安装后版本号不匹配（期望 $new_ver，实际 $final_ver），正在回滚..."
		if [ -f "$backup" ]; then
			if ! cp -f "$backup" "$xray_bin"; then
				die "验证失败且回滚失败"
			fi
			# 恢复后检查版本
			local rollback_ver
			rollback_ver=$(cmd_current)
			if [ "$rollback_ver" != "$current" ]; then
				die "验证失败、回滚后版本仍不正确"
			fi
			# 重启服务
			if [ -x /etc/init.d/tkproxy ]; then
				if ! /etc/init.d/tkproxy restart >/dev/null 2>&1; then
					die "回滚后服务重启失败"
				fi
			fi
		fi
		rm -rf "$tmpdir" "$xray_new"
		die "升级失败并已回滚"
	fi

	# 清理
	rm -rf "$tmpdir" "$xray_new"
	[ -f "$backup" ] && rm -f "$backup"

	say "升级成功：$current → $final_ver"
	printf '{"ok":true,"from":"%s","to":"%s"}\n' "$current" "$final_ver"
}

# 主入口
case "${1:-}" in
	current)
		cmd_current
		;;
	check)
		cmd_check
		;;
	upgrade)
		cmd_upgrade
		;;
	-h|--help|help)
		printf 'xray-upgrade.sh <current|check|upgrade>\n'
		printf '  current  : 输出当前 Xray 版本号（未安装返回 unknown）\n'
		printf '  check    : 输出 JSON，包含 current/min/satisfied 字段\n'
		printf '  upgrade  : 一键升级到最新版（%s），支持自动回滚\n' "$TARGET_VERSION"
		exit 0
		;;
	"")
		die "缺少子命令，用法：xray-upgrade.sh <current|check|upgrade>"
		;;
	*)
		die "未知子命令：$1（可用：current、check、upgrade）"
		;;
esac
