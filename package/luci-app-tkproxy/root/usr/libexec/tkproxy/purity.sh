#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 纯净度体检脚本（恢复老版判定：机房IP/DNS/IPv6/IP重复 → 不可用）
#
# 用法：
#   purity.sh <tsv-pairs-file>
#     读取 TSV（每行：index<TAB>ssid<TAB>probe_port），输出 TSV 采集结果
#
# 输出格式（每条线路一行 TSV）：
#   line<TAB>exit_ip<TAB>country<TAB>org<TAB>asn<TAB>dns_country<TAB>ipv6_leak<TAB>proxy_ok<TAB>error<TAB>hosting<TAB>proxy<TAB>mobile<TAB>reverse<TAB>dns_upstream<TAB>trace_country<TAB>hosting_state<TAB>proxy_state<TAB>latency_ms<TAB>http_s<TAB>channel_ok<TAB>source
#
# 后 6 列（16..21）沿用老版「线路体检」的语义：
#   hosting_state / proxy_state：true|false|unknown 三态，unknown 表示「没查到」，绝不当成干净
#   latency_ms：3 次首字节中位数；http_s：一次完整 HTTP 总耗时；channel_ok：1=通道通（有 HTTP 响应）
#   source：出口身份主源（ipinfo / ip-api）

set -e

TMO=8
ROUTER_IP_CACHE="/tmp/tkproxy/purity-router-ip"

usage() {
	cat >&2 <<EOF
用法：
  $0 <tsv-pairs-file>

输入 TSV 格式（每行）：
  index<TAB>ssid<TAB>probe_port

输出 TSV 格式（每行）：
  line<TAB>exit_ip<TAB>country<TAB>org<TAB>asn<TAB>dns_country<TAB>ipv6_leak<TAB>proxy_ok<TAB>error<TAB>hosting<TAB>proxy<TAB>mobile<TAB>reverse<TAB>dns_upstream<TAB>trace_country<TAB>hosting_state<TAB>proxy_state<TAB>latency_ms<TAB>http_s<TAB>channel_ok<TAB>source

说明：
  - 经 probe 口（socks5h://127.0.0.1:port）采集出口信息
  - 出口身份主源 ipinfo.io（HTTPS），ip-api 兜底；hosting/proxy 只有 ip-api 给明确布尔
  - 延迟 = 经 probe 口取 https://1.1.1.1/cdn-cgi/trace 的 3 次首字节中位数（毫秒）
  - ip_type/proxy_flag/mobile 通过 ip-api.com 的 hosting/proxy/mobile 字段判定
  - dns_country 经 probe 口解析后查落地国家
  - trace_country 经 1.1.1.1/cdn-cgi/trace 的 loc 字段
  - dns_upstream 读 /tmp/resolv.conf.auto 或 /etc/resolv.conf 第一个 nameserver（取不到写 1.1.1.1）
  - ipv6_leak 检测是否有 IPv6 泄漏（0=无，1=有）
  - proxy_ok 对比出口 IP 与路由器直连 IP（1=走代理，0=未走代理，-1=无法确认）
EOF
	exit 2
}

[ $# -eq 1 ] || usage
IN_FILE="$1"
[ -f "$IN_FILE" ] || { echo "输入文件不存在：$IN_FILE" >&2; exit 1; }


# 获取路由器本机直连出口 IP（走 WAN，不经 tkproxy）
get_router_ip() {
	if [ -f "$ROUTER_IP_CACHE" ]; then
		cat "$ROUTER_IP_CACHE"
		return
	fi

	local _ip=""
	for _u in "http://ip-api.com/line/?fields=query" "http://ifconfig.me/ip" "http://icanhazip.com"; do
		_ip=$(curl -s -m 5 "$_u" 2>/dev/null | tr -d ' \r\n\t' | head -c 40)
		case "$_ip" in
			""|*[!0-9.]*) _ip="" ;;
			*) break ;;
		esac
	done

	if [ -n "$_ip" ]; then
		mkdir -p "$(dirname "$ROUTER_IP_CACHE")"
		printf '%s' "$_ip" > "$ROUTER_IP_CACHE"
	fi
	printf '%s' "$_ip"
}

# 检查单条线路（输出 TSV：line, exit_ip, country, org, asn, dns_country, ipv6_leak, proxy_ok, error, hosting, proxy, mobile, reverse, dns_upstream, trace_country）
check_line() {
	local idx="$1"
	local ssid="$2"
	local probe_port="$3"

	local exit_ip="" country="" org="" asn="" dns_country="" ipv6_leak=0 proxy_ok=-1 error=""
	local hosting="false" proxy_flag="false" mobile="false" reverse=""
	local dns_upstream="" trace_country=""
	local hosting_state="unknown" proxy_state="unknown" source=""
	local latency_ms="" http_s="" channel_ok=0

	# 1a. 出口身份主源：ipinfo.io（HTTPS，老版首选；ip.sb 现在直接 403 不可用）
	local _info=$(curl -s -m "$TMO" --socks5-hostname "127.0.0.1:$probe_port" \
		https://ipinfo.io/json 2>/dev/null || true)
	if printf '%s' "$_info" | grep -q '"ip"'; then
		exit_ip=$(printf '%s' "$_info" | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
		country=$(printf '%s' "$_info" | sed -n 's/.*"country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
		org=$(printf '%s' "$_info" | sed -n 's/.*"org"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
		source="ipinfo"
	fi

	# 1b. ip-api：唯一提供 hosting/proxy 明确 true|false 的源（免费版仅 HTTP，只取这两个标记）
	local _body=$(curl -s -m "$TMO" --socks5-hostname "127.0.0.1:$probe_port" \
		"http://ip-api.com/json/?fields=status,query,countryCode,isp,as,hosting,proxy,mobile,reverse" 2>/dev/null || true)

	if [ -n "$_body" ]; then
		local _status=$(printf '%s' "$_body" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
		if [ "$_status" = "success" ]; then
			[ -z "$exit_ip" ] && exit_ip=$(printf '%s' "$_body" | sed -n 's/.*"query"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
			[ -z "$country" ] && country=$(printf '%s' "$_body" | sed -n 's/.*"countryCode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
			[ -z "$org" ] && org=$(printf '%s' "$_body" | sed -n 's/.*"isp"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
			asn=$(printf '%s' "$_body" | sed -n 's/.*"as"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

			# 提取 hosting/proxy/mobile/reverse 字段
			hosting=$(printf '%s' "$_body" | sed -n 's/.*"hosting"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p')
			proxy_flag=$(printf '%s' "$_body" | sed -n 's/.*"proxy"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p')
			mobile=$(printf '%s' "$_body" | sed -n 's/.*"mobile"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p')
			reverse=$(printf '%s' "$_body" | sed -n 's/.*"reverse"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

			# 去除可能的空格
			hosting=$(printf '%s' "$hosting" | tr -d ' ')
			proxy_flag=$(printf '%s' "$proxy_flag" | tr -d ' ')
			mobile=$(printf '%s' "$mobile" | tr -d ' ')
			[ -z "$mobile" ] && mobile="false"
			[ -z "$source" ] && source="ip-api"

			# 三态：只有明确的 true/false 才算数；没查到一律 unknown（未确认 ≠ 干净）
			case "$hosting" in
				true|false) hosting_state="$hosting" ;;
				*) hosting_state="unknown"; hosting="false" ;;
			esac
			case "$proxy_flag" in
				true|false) proxy_state="$proxy_flag" ;;
				*) proxy_state="unknown"; proxy_flag="false" ;;
			esac
		fi
	fi
	[ -z "$exit_ip" ] && [ -z "$error" ] && error="出口 IP 未取到"

	# 2. DNS 上游（读 /tmp/resolv.conf.auto 或 /etc/resolv.conf 第一个 nameserver）
	if [ -f "/tmp/resolv.conf.auto" ]; then
		dns_upstream=$(sed -n 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*/\1/p' /tmp/resolv.conf.auto | head -n 1)
	elif [ -f "/etc/resolv.conf" ]; then
		dns_upstream=$(sed -n 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*/\1/p' /etc/resolv.conf | head -n 1)
	fi
	[ -z "$dns_upstream" ] && dns_upstream="1.1.1.1"

	# 3. trace_country（经 probe 口，用 1.1.1.1/cdn-cgi/trace 取 loc）
	if [ -n "$exit_ip" ]; then
		local _trace=$(curl -s -m 6 --socks5-hostname "127.0.0.1:$probe_port" \
			https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
		trace_country=$(printf '%s' "$_trace" | sed -n 's/^loc=//p' | head -n 1)
	fi

	# 4. DNS 落地国家（复用 trace_country，保持兼容）
	dns_country="$trace_country"

	# 5. IPv6 泄漏（经 probe 口，访问 v6.ipv6-test.com）
	if [ -n "$exit_ip" ]; then
		local v6_test=$(curl -s -m 6 --socks5-hostname "127.0.0.1:$probe_port" \
			https://v6.ipv6-test.com/api/myip.php 2>/dev/null || true)
		case "$v6_test" in
			*:*) ipv6_leak=1 ;;
		esac
	fi

	# 6. 对比出口 IP 与路由器直连 IP（判断是否走代理）
	if [ -n "$exit_ip" ]; then
		local router_ip=$(get_router_ip)
		if [ -z "$router_ip" ]; then
			proxy_ok=-1
		elif [ "$exit_ip" = "$router_ip" ]; then
			proxy_ok=0
		else
			proxy_ok=1
		fi
	fi

	# 7. 延迟与通道（沿用老版口径：3 次首字节取中位数 + 一次完整 HTTP 耗时）
	if [ -n "$exit_ip" ]; then
		local _i=1 _st="" _t
		while [ "$_i" -le 3 ]; do
			_t=$(curl -m 12 -s -o /dev/null -w '%{time_starttransfer}' \
				--socks5-hostname "127.0.0.1:$probe_port" https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
			case "$_t" in
				""|*[!0-9.]*) ;;
				*) _st="$_st$_t
" ;;
			esac
			_i=$((_i + 1))
		done
		if [ -n "$_st" ]; then
			latency_ms=$(printf '%s' "$_st" | grep -v '^$' | sort -n | sed -n '2p' \
				| awk '{ printf "%d", $1 * 1000 }')
			[ -z "$latency_ms" ] && latency_ms=""
		fi
		http_s=$(curl -m 12 -s -o /dev/null -w '%{time_total}' \
			--socks5-hostname "127.0.0.1:$probe_port" https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
		case "$http_s" in
			""|*[!0-9.]*) http_s="" ;;
			*) channel_ok=1 ;;
		esac
	fi

	# 输出 TSV（15 列旧字段 + 6 列老版体检语义）
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n' \
		"$idx" "$exit_ip" "$country" "$org" "$asn" "$dns_country" "$ipv6_leak" "$proxy_ok" "$error" "$hosting" "$proxy_flag" "$mobile" "$reverse" "$dns_upstream" "$trace_country" \
		"$hosting_state" "$proxy_state" "$latency_ms" "$http_s" "$channel_ok" "$source"
}

# 主逻辑：逐行读 TSV，执行检查并输出
while IFS="	" read -r idx ssid probe_port; do
	check_line "$idx" "$ssid" "$probe_port"
done < "$IN_FILE"

