#!/bin/sh
# SPDX-License-Identifier: GPL-3.0
# tkproxy 系统预检脚本
# 用法: preflight.sh --json
# 输出单行 JSON 数组，每项包含 id/title/level/detail/fix

check_xray() {
    local level="pass" detail="" fix=""
    if ! command -v xray >/dev/null 2>&1; then
        level="block"
        detail="未找到 xray 可执行文件"
        fix="opkg:xray-core"
        printf '{"id":"xray","title":"Xray 核心","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    local ver
    ver=$(xray version 2>/dev/null | head -1 | awk '{print $2}')
    if [ -z "$ver" ]; then
        level="block"
        detail="xray 命令找到但版本读取失败，请检查安装是否完整或手动运行 'xray version' 确认问题"
        fix="opkg:xray-core"
    else
        detail="已安装 ${ver}"
    fi
    printf '{"id":"xray","title":"Xray 核心","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_nft() {
    local level="pass" detail="" fix=""
    if ! command -v nft >/dev/null 2>&1; then
        level="block"
        detail="nft 命令不可用"
        fix="opkg:nftables"
        printf '{"id":"nft","title":"nftables + tproxy","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    local tmpf="/tmp/tkproxy-nft-test-$$.nft"
    cat >"$tmpf" <<'EOF'
table inet tkproxy_test {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto tcp tproxy ip to 127.0.0.1:1080
    }
}
EOF

    if nft -c -f "$tmpf" >/dev/null 2>&1; then
        detail="nft 可用且支持 tproxy"
    else
        if opkg list-installed kmod-nft-tproxy 2>/dev/null | grep -q kmod-nft-tproxy; then
            detail="kmod-nft-tproxy 已装但 nft 校验失败"
            level="warn"
        else
            level="block"
            detail="nft 不支持 tproxy 规则"
            fix="opkg:kmod-nft-tproxy"
        fi
    fi
    rm -f "$tmpf"

    printf '{"id":"nft","title":"nftables + tproxy","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_dnsmasq() {
    local level="pass" detail="" fix=""
    if pgrep dnsmasq >/dev/null 2>&1 || /etc/init.d/dnsmasq enabled 2>/dev/null; then
        detail="dnsmasq 运行中或已启用"
    else
        level="warn"
        detail="dnsmasq 未运行且未启用（DNS 分流会失效）"
        fix="svc:dnsmasq"
    fi
    printf '{"id":"dnsmasq","title":"dnsmasq 服务","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_wireless() {
    local level="pass" detail="" fix=""
    local cap=16

    if [ ! -e /etc/config/wireless ]; then
        level="block"
        detail="没有 /etc/config/wireless，未检测到无线"
        printf '{"id":"wireless","title":"无线射频与 AP 容量","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    # 每个 wifi-iface 归属哪个射频（option device 'radioX'）；没有 device 的算到第一个射频
    local counts
    counts=$(awk '
        /^config[ \t]+wifi-iface/ { dev="" ; inif=1 ; next }
        /^config[ \t]+wifi-device/ { inif=0 }
        inif && /option[ \t]+device/ {
            v=$3; gsub(/[\047"]/, "", v); dev=v;
            if (dev != "") { cnt[dev]++ ; seen=1 }
        }
        END {
            if (!seen) { print "NONE 0" ; exit }
            for (d in cnt) printf "%s %d\n", d, cnt[d]
        }' /etc/config/wireless 2>/dev/null)

    if [ -z "$counts" ] || [ "$counts" = "NONE 0" ]; then
        level="warn"
        detail="未发现任何 AP 实例（wifi-iface），可以先创建 WiFi"
        printf '{"id":"wireless","title":"无线射频与 AP 容量","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    local over=0 parts="" rem_txt=""
    local total=0
    while read -r dev cnt; do
        [ -z "$dev" ] && continue
        txt="$((cnt))/"$cap
        case "$dev" in
            radio0) parts="${parts}2.4G($dev) 已用 ${cnt}/${cap}" ;;
            radio1) parts="${parts}${parts:+ · }5G($dev) 已用 ${cnt}/${cap}" ;;
        report) ;;
            *) parts="${parts}${parts:+ · }${dev} 已用 ${cnt}/${cap}" ;;
        esac
        total=$((total + cnt))
        if [ "$cnt" -gt "$cap" ]; then over=$((over + 1)) ; fi
        if [ "$cnt" -lt "$cap" ]; then
            rem_txt="${rem_txt}${rem_txt:+, }${dev} 还能再加 $((cap - cnt)) 条"
        else
            rem_txt="${rem_txt}${rem_txt:+, }${dev} 已满（$cap/$cap）"
        fi
    done <<EOF
$counts
EOF

    if [ "$over" -gt 0 ]; then
        level="block"
        detail="有射频的 AP 数超过驱动上限 ${cap}：${parts}（超限会让整条射频掉线）"
        fix="trim"
    else
        level="pass"
        detail="${parts}（合计 ${total} 个 SSID；驱动上限每射频 ${cap}）— ${rem_txt}"
    fi

    printf '{"id":"wireless","title":"无线射频与 AP 容量","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}
check_memory() {
    local level="pass" detail="" fix=""
    local avail_kb=0

    if [ -r /proc/meminfo ]; then
        avail_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    fi

    local avail_mb=$((avail_kb / 1024))
    detail="可用内存 ${avail_mb} MB"

    if [ "$avail_mb" -lt 200 ]; then
        level="warn"
        detail="${detail}，建议 >= 200 MB"
    fi

    printf '{"id":"memory","title":"可用内存","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_storage() {
    local level="pass" detail="" fix=""
    local overlay_avail=0 tmp_avail=0

    overlay_avail=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}')
    tmp_avail=$(df -k /tmp 2>/dev/null | awk 'NR==2 {print $4}')

    overlay_avail=${overlay_avail:-0}
    tmp_avail=${tmp_avail:-0}

    local overlay_mb=$((overlay_avail / 1024))
    local tmp_mb=$((tmp_avail / 1024))

    detail="/overlay ${overlay_mb} MB, /tmp ${tmp_mb} MB"

    if [ "$overlay_avail" -lt 5120 ] || [ "$tmp_avail" -lt 2048 ]; then
        level="warn"
        detail="${detail}，建议 /overlay >= 5 MB, /tmp >= 2 MB"
    fi

    printf '{"id":"storage","title":"存储空间","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_time_network() {
    local level="pass" detail="" fix=""
    local year
    year=$(date +%Y 2>/dev/null || echo 0)

    # NTP 是否在跑（sysntpd / ntpd）
    local ntp_run=0
    if ps 2>/dev/null | grep -q "[s]ysntpd"; then ntp_run=1; fi
    if ps 2>/dev/null | grep -q "[n]tpd"; then ntp_run=1; fi

    local time_txt
    if [ "$year" -lt 2024 ]; then
        time_txt="系统时间异常 (${year})"
    elif [ "$ntp_run" = "1" ]; then
        time_txt="时间正常 (${year})，NTP 已在跑"
    else
        time_txt="时间正常 (${year})，但 NTP 未在运行（重启后可能回退）"
    fi

    # 出网 443：多目标测试，任一通即可（单测 1.1.1.1 会被部分运营商拦）
    local ok=0 try_txt=""
    if command -v curl >/dev/null 2>&1; then
        for u in "https://1.1.1.1" "https://www.cloudflare.com/cdn-cgi/trace" "https://www.baidu.com"; do
            if curl -s -m 5 --connect-timeout 3 -o /dev/null "$u" 2>/dev/null; then
                ok=1
                try_txt="$u"
                break
            fi
        done
    else
        level="warn"
        detail="${time_txt}；curl 未安装，无法测试 HTTPS"
        fix="opkg:curl,ca-bundle"
        printf '{"id":"timesync","title":"时间与出网","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    if [ "$year" -lt 2024 ]; then
        level="warn"
        detail="${time_txt}，TLS 连接可能失败"
        fix="svc:sysntpd"
    elif [ "$ok" = "0" ]; then
        level="warn"
        detail="${time_txt}；出网 443 全部失败（1.1.1.1 / cloudflare / baidu 都不通），可能是运营商限制或防火墙拦截"
        fix=""
    elif [ "$ntp_run" = "0" ]; then
        level="warn"
        detail="${time_txt}；HTTPS 出网正常（${try_txt}）"
        fix="svc:sysntpd"
    else
        level="pass"
        detail="${time_txt}；HTTPS 出网正常（${try_txt}）"
    fi

    printf '{"id":"timesync","title":"时间与出网","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}
check_connectivity() {
    local level="pass" detail="" fix=""

    if ! command -v curl >/dev/null 2>&1; then
        level="warn"
        detail="curl 未安装，无法测试裸网连通"
        fix="opkg:curl"
        printf '{"id":"connectivity","title":"裸网连通性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return
    fi

    if curl -s -m 5 --connect-timeout 3 http://1.1.1.1 >/dev/null 2>&1; then
        detail="可访问 1.1.1.1 HTTP"
    else
        level="warn"
        detail="无法访问 1.1.1.1 HTTP（可能是上游/防火墙限制）"
        fix="svc:network"
    fi

    printf '{"id":"connectivity","title":"裸网连通性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_residue() {
    local level="pass" detail="" fix=""
    local findings=""

    # 本插件「当前部署」也算有 nft 表与 brtk 网桥；这时不是残留，
    # 只有「制品还在但 UCI 清单里没有任何线路」才算残留。
    # 注意：/etc/config/tkproxy 存在本身不是残留——新装就有这个文件，
    # 「0 条线路」也合法；把「文件存在」当残留会永远消不掉（一键修复不删配置）。
    local deployed=0
    if [ -e /etc/config/tkproxy ] && uci -q get tkproxy.main.line >/dev/null 2>&1; then
        deployed=1
    fi

    if command -v nft >/dev/null 2>&1; then
        if nft list tables 2>/dev/null | grep -q tkproxy; then
            if [ "$deployed" = "1" ]; then
                :
            else
                findings="nft表残留"
            fi
        fi
    fi

    if ip link show 2>/dev/null | grep -q brtk; then
        if [ "$deployed" != "1" ]; then
            findings="${findings:+${findings}, }brtk 网桥残留"
        fi
    fi

    if [ -e /etc/config/tkproxy ]; then
        # 只有「配置里写着已部署的线路、但部署产物不见了」才算异常，
        # 交给「部署」修，不归「残留清理」。单纯的配置文件不算残留。
        :
    fi

    if [ "$deployed" = "1" ] && [ -z "$findings" ]; then
        local _n
        _n=$(uci -q get tkproxy.main.line | tr ' ' '\n' | grep -c '|' 2>/dev/null)
        detail="检测到本插件现有部署（${_n:-0} 条线路），非残留"
    fi

    if [ -z "$findings" ] && [ "$deployed" != "1" ]; then
        local _nn
        _nn=$(uci -q get tkproxy.main.node 2>/dev/null | tr ' ' '\n' | grep -c '|' 2>/dev/null)
        if [ "${_nn:-0}" -gt 0 ]; then
            detail="已导入 ${_nn} 个节点，尚未创建线路（正常，非残留）"
        fi
    fi

    if [ -z "$findings" ]; then
        detail="${detail:-无旧配置残留}"
    else
        level="warn"; fix="clean"
        detail="发现：${findings}"
    fi

    printf '{"id":"residue","title":"旧配置残留检测","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

check_firewall() {
    # 目的：提前发现「本机原有防火墙已经坏了」——否则部署到 firewall reload 才炸，
    # 那个时间点配置已经写进去了，只能回滚，用户看到的就是「部署失败」。
    local level="pass" detail="" fix="" findings="" out rc bad legacy

    if ! command -v fw4 >/dev/null 2>&1; then
        level="pass"; detail="fw3/iptables 老系统，跳过 fw4 兼容检查"
        printf '{"id":"firewall","title":"防火墙兼容性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return 0
    fi

    # 1) 遗留段：fw3 时代的 reload 选项 / 指向不存在文件的 include
    legacy=$(uci show firewall 2>/dev/null | grep -E "^\.*firewall\.(passwall|passwall2|shadowsocksr|ssr|clash)=" | sed -n "s/^\([^.]*\)\.\([^.]*\)=.*/\2/p" | sort -u | tr "\n" " ")

    # 2) fw4 自检
    out=$(fw4 check 2>&1); rc=$?
    if [ "$rc" != "0" ]; then
        bad=$(printf "%s\n" "$out" | grep -viE "^\[!\]" | grep -iE "error|fail|invalid|unexpected" | head -n 3 | tr "\n" ";")
        level="block"
        detail="本机防火墙自身有问题（fw4 check 退出码 $rc）：${bad:-见系统日志}。先在 SSH 里修好再部署，否则一定会失败"
        fix="fwfix"
        [ -n "$legacy" ] && detail="$detail ｜ 检测到遗留段：$legacy"
        printf '{"id":"firewall","title":"防火墙兼容性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return 0
    fi

    # 上次部署是否降级过（firewall reload 最终没成功）
    if [ -e /tmp/tkproxy/fw-degraded ]; then
        level="block"; fix="fwfix"
        detail="上次部署时防火墙没生效（隔离规则未加载），线路本身在跑。查看 /tmp/tkproxy/fw-degraded，修好后点「一键修复」再部署一次"
        [ -n "$legacy" ] && detail="$detail ｜ 遗留段：$legacy"
        printf '{"id":"firewall","title":"防火墙兼容性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
        return 0
    fi

    if [ -n "$legacy" ]; then
        level="warn"; fix="fwfix"
        detail="fw4 自检通过，但有 fw3 遗留段（${legacy}）带过时选项，建议清掉以免以后升内核后失败"
    else
        detail="fw4 自检通过，无遗留段"
    fi

    printf '{"id":"firewall","title":"防火墙兼容性","level":"%s","detail":"%s","fix":"%s"}' "$level" "$detail" "$fix"
}

main() {
    if [ "$1" != "--json" ]; then
        echo "Usage: $0 --json" >&2
        exit 1
    fi

    printf "["
    check_xray
    printf ","
    check_nft
    printf ","
    check_dnsmasq
    printf ","
    check_wireless
    printf ","
    check_memory
    printf ","
    check_storage
    printf ","
    check_time_network
    printf ","
    check_connectivity
    printf ","
    check_residue
    printf ","
    check_firewall
    printf "]\n"
}

main "$@"
