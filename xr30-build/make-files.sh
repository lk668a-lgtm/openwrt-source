#!/bin/sh
# 把 luci-app-tkproxy / luci-theme-argon / luci-app-buerwrt-ads 的文件树
# 拼成一个「FILES 目录」，供 ImageBuilder 直接塞进固件（10 分钟出包，不用等全量编译）。
#
# 用法： sh xr30-build/make-files.sh <输出目录>
set -e
OUT=${1:?用法: make-files.sh <输出目录>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
rm -rf "$OUT"
mkdir -p "$OUT"

put_root()   { [ -d "$1/root" ]   && cp -a "$1/root/."   "$OUT/" || true; }
put_htdocs() { [ -d "$1/htdocs" ] && mkdir -p "$OUT/www" && cp -a "$1/htdocs/." "$OUT/www/" || true; }
put_luasrc() { [ -d "$1/luasrc" ] && mkdir -p "$OUT/usr/lib/lua/luci" && cp -a "$1/luasrc/." "$OUT/usr/lib/lua/luci/" || true; }
put_ucode()  { [ -d "$1/ucode" ]  && mkdir -p "$OUT/usr/share/ucode/luci" && cp -a "$1/ucode/." "$OUT/usr/share/ucode/luci/" || true; }

for p in luci-app-tkproxy luci-app-buerwrt-ads; do
  [ -d "$ROOT/package/$p" ] || continue
  put_root   "$ROOT/package/$p"
  put_htdocs "$ROOT/package/$p"
  put_luasrc "$ROOT/package/$p"
done

# 主题：文件在 htdocs + ucode + root（ucode 模板必须落到 usr/share/ucode/luci，
# 否则登录页会报 No such file or directory）
if [ -d "$ROOT/package/luci-theme-argon" ]; then
  put_root   "$ROOT/package/luci-theme-argon"
  put_htdocs "$ROOT/package/luci-theme-argon"
  put_ucode  "$ROOT/package/luci-theme-argon"
fi

# 品牌 / 首启脚本 / apk 公钥
[ -d "$ROOT/files" ] && cp -a "$ROOT/files/." "$OUT/"

# ImageBuilder 不会跑 uci-defaults，得在首次启动时自己调
mkdir -p "$OUT/etc/uci-defaults"
cat > "$OUT/etc/uci-defaults/99-buer-wrt-imagebuilder" <<'EOF'
#!/bin/sh
# ImageBuilder 出来的镜像里，uci-defaults 不会像包安装那样自动执行，
# 这里挂一个开机钩子，把首启脚本按顺序跑一遍（幂等）。
for f in /etc/uci-defaults/9*-buer-wrt-* /etc/uci-defaults/99-tkproxy-argon-light /etc/uci-defaults/90-buerwrt-ads-defaults /etc/uci-defaults/30_luci-theme-argon; do
    [ -f "$f" ] || continue
    case "$f" in *99-buer-wrt-imagebuilder*) continue ;; esac
    sh "$f" >/dev/null 2>&1 || true
done
exit 0
EOF
chmod +x "$OUT/etc/uci-defaults/99-buer-wrt-imagebuilder"

echo "FILES 目录已生成：$(find "$OUT" -type f | wc -l) 个文件"
