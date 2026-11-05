#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# 线路真实性验收脚本（按实际线路数动态探测）
# 用法：/usr/libexec/tkproxy/acceptance.sh
# 输出：/tmp/tkproxy/acceptance.md（Markdown 报告） + stdout 统计摘要

set -e

PROG=tkproxy-acceptance
OUT_DIR=/tmp/tkproxy
REPORT="${OUT_DIR}/acceptance.md"
TEMP_DIR="${OUT_DIR}/acceptance.$$"

say() { logger -t "$PROG" "$*"; printf '%s\n' "$*"; }
die() { say "错误: $*"; exit 1; }

# 0. 统计实际线路数 N
N=$(uci -q get tkproxy.main.line | grep -c '|' || echo 0)
[ "$N" -gt 0 ] 2>/dev/null || die "未检测到有效线路（uci tkproxy.main.line 无含 | 的行）"

# 1. 初始化
mkdir -p "$TEMP_DIR" || die "无法创建临时目录 $TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

say "== 开始验收 $N 条线路 (probe 口 22001..$((22000+N))) =="

# 2. 并发探测 N 个 probe 口
say "探测出口 IP/国家/ISP ($N 口并发)..."
for port in $(seq 22001 $((22000+N))); do
    (
        result=$(curl -m8 -x "socks5h://127.0.0.1:${port}" \
                      "http://ip-api.com/line/?fields=query,countryCode,isp" 2>/dev/null || echo "FAILED")
        echo "${port}|${result}" > "${TEMP_DIR}/${port}.txt"
    ) &
done
wait

# 3. 统计：成功条数、唯一出口 IP、解析节点名（POSIX sh 兼容，使用 TSV）
say "统计结果..."
success=0
> "${TEMP_DIR}/ips.txt"
> "${TEMP_DIR}/details.tsv"
> "${TEMP_DIR}/lines.txt"

. /lib/functions.sh
collect_line() {
    # 与 gen.lua 一致：忽略空行/注释，跳过禁用且未绑定的线路；
    # 仅保留节点名，避免把直连 URI（及其中的凭据）写入报告。
    printf '%s\n' "$1" | awk -F'|' '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        {
            line = trim($0)
            if (line == "" || substr(line, 1, 1) == "#") next

            second = trim($2)
            band = tolower(second)
            if (band == "2g" || band == "5g" || band == "both") {
                source = trim($3)
                enabled = trim($4)
            } else {
                source = second
                enabled = trim($3)
            }

            if ((enabled == "0" || enabled == "false" || enabled == "off") && source == "") next

            if (substr(source, 1, 1) == "@") {
                node = trim(substr(source, 2))
                if (node == "") node = "unnamed"
            } else {
                node = "direct"
            }
            print node
        }
    ' >> "${TEMP_DIR}/lines.txt"
}
config_load tkproxy
config_list_foreach main line collect_line

for port in $(seq 22001 $((22000+N))); do
    result_file="${TEMP_DIR}/${port}.txt"
    if [ ! -f "$result_file" ]; then
        echo "${port}	TIMEOUT		" >> "${TEMP_DIR}/details.tsv"
        continue
    fi

    line=$(cat "$result_file")
    data=$(echo "$line" | cut -d'|' -f2-)

    # ip-api.com/line 实际依次返回：第1行 countryCode、第2行 isp、第3行 query(IP)
    cc=$(echo "$data" | sed -n '1p')
    isp=$(echo "$data" | sed -n '2p')
    ip=$(echo "$data" | sed -n '3p')

    # 判断第 3 行是否为合法 IPv4 或 IPv6（使用 grep -q 避免多行输出）
    if echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || \
       echo "$ip" | grep -qiE '^[0-9a-f:]+$'; then
        # 探测成功

        echo "$ip" >> "${TEMP_DIR}/ips.txt"
        success=$((success + 1))
    fi

    # 从按序读取的逻辑线路列表中取节点名；端口顺序与生成器保持一致。
    idx=$((port - 22000))
    node_name="未配置"

    entry=$(sed -n "${idx}p" "${TEMP_DIR}/lines.txt")
    if [ -n "$entry" ]; then
        node_name=$entry
    fi

    # 无论探测成功或失败，都保留节点名
    if echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || \
       echo "$ip" | grep -qiE '^[0-9a-f:]+$'; then
        echo "${port}	${node_name}	${ip}	${cc}	${isp}" >> "${TEMP_DIR}/details.tsv"
    else
        echo "${port}	${node_name}	探测失败		" >> "${TEMP_DIR}/details.tsv"
    fi
done

unique_ips=$(sort -u "${TEMP_DIR}/ips.txt" | wc -l)

say "成功: $success/$N, 唯一出口 IP: $unique_ips"

# 4. DNS 落地校验（抽样 3 口）
say "DNS 落地校验 (抽样)..."
# 抽样：首口、中口、末口
_mid=$((22000 + (N + 1) / 2))
_last=$((22000 + N))
sample_ports="22001 $_mid $_last"
dns_pass=0
dns_total=0

for port in $sample_ports; do
    dns_total=$((dns_total + 1))
    detail=$(awk -v p="$port" '$1 == p' "${TEMP_DIR}/details.tsv")
    node_cc=$(echo "$detail" | awk -F'\t' '{print $4}')

    if [ -z "$node_cc" ] || [ "$node_cc" = "" ]; then
        say "  口 $port: 跳过 (探测失败)"
        continue
    fi

    trace=$(curl -m8 -x "socks5h://127.0.0.1:${port}" \
                 "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null || echo "FAILED")

    if echo "$trace" | grep -q "^loc="; then
        dns_loc=$(echo "$trace" | sed -n 's/^loc=\(.*\)/\1/p')
        if [ "$dns_loc" = "$node_cc" ]; then
            say "  口 $port: DNS落地=$dns_loc ✓ (与节点国家 $node_cc 一致)"
            dns_pass=$((dns_pass + 1))
        else
            say "  口 $port: DNS落地=$dns_loc ✗ (节点国家 $node_cc 不一致)"
        fi
    else
        say "  口 $port: DNS 查询失败"
    fi
done

# 5. 资源采样
say "采样资源占用..."
xray_rss=0
if pidof xray >/dev/null; then
    xray_pid=$(pidof xray | awk '{print $1}')
    xray_rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$xray_pid/status" 2>/dev/null || echo 0)
fi

mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
overlay_free=$(df /overlay 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)

# 6. 生成 Markdown 报告
say "生成报告: $REPORT"
cat > "$REPORT" <<EOF
# tkproxy ${N} 条线路验收报告

**生成时间**: $(date '+%Y-%m-%d %H:%M:%S')

## 统计摘要
- **成功条数**: $success / $N
- **唯一出口 IP 数**: $unique_ips
- **DNS 落地校验**: $dns_pass / $dns_total 通过

## 资源占用
- **Xray 进程 RSS**: $(awk "BEGIN {printf \"%.1f\", $xray_rss/1024}") MB
- **系统可用内存**: $(awk "BEGIN {printf \"%.1f\", $mem_avail/1024}") MB
- **/overlay 可用空间**: $(awk "BEGIN {printf \"%.1f\", $overlay_free/1024}") MB

## 线路明细

| 口号 | 节点名 | 出口 IP | 国家 | ISP |
|------|--------|---------|------|-----|
EOF

awk -F'\t' '{
    port = $1; node = $2; ip = $3; cc = $4; isp = $5
    if (node == "") node = "-"
    if (ip == "") ip = "-"
    if (cc == "") cc = "-"
    if (isp == "") isp = "-"
    printf "| %s | %s | %s | %s | %s |\n", port, node, ip, cc, isp
}' "${TEMP_DIR}/details.tsv" >> "$REPORT"

cat >> "$REPORT" <<EOF

---
**备注**:
- 探测超时 8 秒视为失败
- DNS 落地校验抽样 3 口 (首口、中口、末口)
- 仅读取运行时状态，未修改任何配置
EOF

say "== 验收完成 =="
say "报告: $REPORT"
say ""
say "=== 验收统计 ==="
say "成功: $success/$N"
say "失败: $((N - success))/$N"
say "唯一出口 IP: $unique_ips"
say "DNS 落地校验: $dns_pass/$dns_total"

# 失败明细
fail_count=0
while IFS='	' read -r _port _node _ip _cc _isp; do
	if [ "$_ip" = "探测失败" ] || [ -z "$_ip" ] || [ "$_ip" = "-" ]; then
		fail_count=$((fail_count + 1))
		say "  失败: 口 $_port ($_node) — 无法获取出口 IP"
	fi
done < "${TEMP_DIR}/details.tsv"
if [ "$fail_count" -eq 0 ]; then
	say "  无失败线路"
fi

exit 0
