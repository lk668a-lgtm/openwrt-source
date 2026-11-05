#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# TikTok 线路纯净度体检自检脚本
# 用固定用例调用 purity.classify_ip，逐条比对期望，全对退出 0；任一条错退出 1 并打印失败行。

PURITY_LUA="/usr/lib/lua/luci/model/tkproxy/purity.lua"

# 检查 purity.lua 是否存在
if [ ! -f "$PURITY_LUA" ]; then
	echo "FAIL: purity.lua not found at $PURITY_LUA"
	exit 1
fi

# Lua 执行函数：lua -e 'require模块.classify_ip(org, asn, opts) → quality'
test_classify() {
	local org="$1"
	local asn="$2"
	local hosting="${3:-false}"
	local proxy="${4:-false}"
	local reverse="${5:-}"
	local expect="$6"

	local lua_code="
		local p = require('luci.model.tkproxy.purity')
		local q, r = p.classify_ip('$org', '$asn', { hosting=$hosting, proxy=$proxy, reverse='$reverse' })
		print(q)
	"

	local result
	result=$(lua -e "$lua_code" 2>/dev/null)

	if [ "$result" != "$expect" ]; then
		echo "FAIL: org='$org' asn='$asn' hosting=$hosting proxy=$proxy reverse='$reverse' -> got '$result', expect '$expect'"
		return 1
	fi
	return 0
}

# 用例计数
total=0
pass=0

# ===== cloud 用例 =====
total=$((total+1)); test_classify "Amazon.com, Inc." "AS16509" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "FDCservers.net" "AS30058" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "DigitalOcean, LLC" "AS14061" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Microsoft Corporation" "AS8075" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Hetzner Online GmbH" "AS24940" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Vultr Holdings LLC" "AS20473" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "OVH SAS" "AS16276" false false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Some ISP" "AS12345" true false "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Some ISP" "AS12345" false true "" "cloud" && pass=$((pass+1))
total=$((total+1)); test_classify "Google Cloud Platform" "AS99999" false false "" "cloud" && pass=$((pass+1))

# ===== transit 用例 =====
total=$((total+1)); test_classify "NTT America, Inc." "AS2914" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "GTT Communications Inc." "AS3257" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "MegaPath Corporation" "AS10796" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "Cogent Communications" "AS174" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "Lumen Technologies" "AS3356" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "PCCW Global, Inc." "AS3491" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "Telstra International" "AS4637" false false "" "transit" && pass=$((pass+1))

# ===== residential 用例 =====
total=$((total+1)); test_classify "Comcast Cable Communications" "AS7922" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "Charter Communications Inc" "AS20115" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "AT&T Internet Services" "AS7018" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "Spectrum" "AS7843" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "Verizon Fios" "AS701" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "AT&T Business Services" "AS7018" false false "" "transit" && pass=$((pass+1))
total=$((total+1)); test_classify "Deutsche Telekom AG" "AS3320" false false "" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "Some ISP" "AS12345" false false "pppoe-dynamic-12345.example.com" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "Some ISP" "AS12345" false false "ftth-fiber-67890.example.com" "residential" && pass=$((pass+1))
total=$((total+1)); test_classify "HiNet" "AS3462" false false "" "residential" && pass=$((pass+1))

# ===== unknown 用例 =====
total=$((total+1)); test_classify "" "" false false "" "unknown" && pass=$((pass+1))
total=$((total+1)); test_classify "Unknown ISP Corp" "AS99999" false false "" "unknown" && pass=$((pass+1))

# 输出结果
if [ "$pass" -eq "$total" ]; then
	echo "PASS $pass/$total"
	exit 0
else
	echo "FAIL: $pass/$total passed"
	exit 1
fi
