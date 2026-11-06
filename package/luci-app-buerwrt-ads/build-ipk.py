# SPDX-License-Identifier: GPL-3.0
"""把 luci-app-buerwrt-ads 打成 OpenWrt(24.10, opkg) 可直接安装的 .ipk。

不依赖 OpenWrt SDK：LuCI 应用是纯 Lua/HTM + shell，Architecture: all，
可以在 Windows 上直接构造 ar + tar.gz。

用法（在本仓库根目录执行）：
    python luci-app-buerwrt-ads/build-ipk.py [--version 1.0.0] [--release 1] [--out dist]

产物：dist/luci-app-buerwrt-ads_<版本>-<release>_all.ipk
"""

import argparse
import gzip
import io
import os
import sys
import tarfile
import time

# 打包时间戳固定取一次，所有 tar 条目共用，保证同一次构建内可复现
MTIME = int(time.time())

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.dirname(os.path.abspath(__file__))

PKG_NAME = "luci-app-buerwrt-ads"
DEPENDS = "luci-base, luci-compat, lua"
MAINTAINER = "buerwrt <buerwrt@localhost>"
DESCRIPTION = (
    "LuCI app: 资源推荐（BUERWRT 广告/资源入口）。"
    "在「服务 → 资源推荐」提供可配置的资源卡片与资源位，全部内容来自"
    "/etc/config/buerwrt；若安装了 luci-app-tkproxy，会在其概览页底部注入"
    "同款卡片（不改动 tkproxy 任何文件）。纯本地渲染，无外链资源。"
)

# 需要可执行权限的文件（相对安装根路径）
EXEC_FILES = {
    "etc/uci-defaults/90-buerwrt-ads-defaults",
}

# 无论源目录怎么变，这些路径必须出现在包里（验收基线）
REQUIRED_PATHS = {
    "usr/lib/lua/luci/controller/buerwrtads.lua",
    "usr/lib/lua/luci/view/buerwrtads/page.htm",
    "usr/lib/lua/luci/view/buerwrtads/esc.htm",
    "www/luci-static/resources/buerwrt-ads/ads.css",
    "www/luci-static/resources/buerwrt-ads/page.js",
    "www/luci-static/resources/preload/buerwrt-ads.js",
    "usr/share/luci/menu.d/luci-app-buerwrt-ads.json",
    "etc/uci-defaults/90-buerwrt-ads-defaults",
}

# opkg 升级不覆盖的用户文件
CONFFILES = []


def collect() -> dict:
    """返回 {安装路径(无前导 ./): (源文件绝对路径, mode)}"""
    files = {}
    bases = [
        (os.path.join(PKG_DIR, "root"), ""),
        (os.path.join(PKG_DIR, "luasrc"), "usr/lib/lua/luci"),
        (os.path.join(PKG_DIR, "htdocs"), "www"),
    ]
    for base, prefix in bases:
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                src = os.path.join(dirpath, name)
                rel = os.path.relpath(src, base).replace(os.sep, "/")
                dest = (prefix + "/" + rel).lstrip("/") if prefix else rel
                mode = 0o755 if dest in EXEC_FILES else 0o644
                files[dest] = (src, mode)

    license_src = os.path.join(PKG_DIR, "LICENSE")
    if os.path.isfile(license_src):
        files["usr/share/" + PKG_NAME + "/LICENSE"] = (license_src, 0o644)
    else:
        print("警告：缺少 LICENSE，分发不合规", file=sys.stderr)

    missing = REQUIRED_PATHS - set(files)
    if missing:
        raise SystemExit("缺少验收基线文件: %s" % ", ".join(sorted(missing)))

    return files


def tar_bytes(entries: dict) -> bytes:
    """确定性 tar：mtime=构建时间戳、uid/gid=0、目录项在前、条目名不带 ./ 前缀。

    entries: {条目名: None(目录) 或 bytes 或 (src_path, mode) 或 (bytes, mode)}；
    """
    dirs = set()
    for name in entries:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        def base_ti(name: str) -> tarfile.TarInfo:
            ti = tarfile.TarInfo(name)
            ti.mtime = MTIME
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            return ti

        for d in sorted(dirs):
            ti = base_ti(d)
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            tar.addfile(ti)

        for name in sorted(entries):
            val = entries[name]
            ti = base_ti(name)
            if val is None:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tar.addfile(ti)
            elif isinstance(val, bytes):
                ti.size = len(val)
                ti.mode = 0o644
                tar.addfile(ti, io.BytesIO(val))
            elif isinstance(val[0], bytes):
                ti.size = len(val[0])
                ti.mode = val[1]
                tar.addfile(ti, io.BytesIO(val[0]))
            else:
                src, mode = val
                with open(src, "rb") as f:
                    data = f.read()
                ti.size = len(data)
                ti.mode = mode
                tar.addfile(ti, io.BytesIO(data))

    return buf.getvalue()


def gz(data: bytes) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=MTIME) as f:
        f.write(data)
    return out.getvalue()


def build(version: str, release: str, out_dir: str) -> str:
    files = collect()

    control = (
        "Package: %s\n"
        "Version: %s-%s\n"
        "Depends: %s\n"
        "Architecture: all\n"
        "Maintainer: %s\n"
        "Description: %s\n"
    ) % (PKG_NAME, version, release, DEPENDS, MAINTAINER, DESCRIPTION)

    conffiles = "".join(p + "\n" for p in CONFFILES)

    # postinst 与 luci.mk 默认一致：清页面树缓存 + 通知 rpcd 重载菜单
    postinst = (
        "#!/bin/sh\n"
        "[ -n \"${IPKG_INSTROOT}\" ] || {\n"
        "\trm -f /tmp/luci-indexcache.*\n"
        "\trm -rf /tmp/luci-modulecache/\n"
        "\tkillall -HUP rpcd 2>/dev/null\n"
        "\texit 0\n"
        "}\n"
    )

    control_entries = {
        "./control": (control.encode("utf-8"), 0o644),
        "./postinst": (postinst.encode("utf-8"), 0o755),
    }
    if conffiles:
        control_entries["./conffiles"] = conffiles.encode("utf-8")

    control_tar = gz(tar_bytes(control_entries))
    data_tar = gz(tar_bytes(files))

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "%s_%s-%s_all.ipk" % (PKG_NAME, version, release))

    with open(out_path, "wb") as f:
        # ipk = ar 包：debian-binary + control.tar.gz + data.tar.gz
        ar = io.BytesIO()
        ar.write(b"!<arch>\n")

        def add_ar(name: str, content: bytes):
            # ar 头字段顺序：name(16) mtime(12) uid(6) gid(6) mode(8) size(10)
            header = "%-16s%-12d%-6d%-6d%-8o%-10d`\n" % (
                name, MTIME, 0, 0, 0o100644, len(content))
            ar.write(header.encode("ascii"))
            ar.write(content)
            if len(content) % 2:
                ar.write(b"\n")

        add_ar("debian-binary", b"2.0\n")
        add_ar("control.tar.gz", control_tar)
        add_ar("data.tar.gz", data_tar)
        f.write(ar.getvalue())

    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--release", default="1")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = ap.parse_args()
    path = build(args.version, args.release, args.out)
    print("OK:", path)


if __name__ == "__main__":
    main()
