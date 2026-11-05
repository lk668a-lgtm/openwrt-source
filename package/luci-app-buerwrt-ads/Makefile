# SPDX-License-Identifier: GPL-3.0
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-buerwrt-ads
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0
PKG_MAINTAINER:=buerwrt <buerwrt@localhost>

LUCI_TITLE:=LuCI app: 资源推荐（BUERWRT 广告/资源入口）
LUCI_DESCRIPTION:=在「服务 → 资源推荐」提供一张可配置的资源卡片与若干资源位，\
全部内容来自 /etc/config/buerwrt 的 uci 配置；若安装了 luci-app-tkproxy，\
还会通过 LuCI preload 机制在其概览页底部注入同款卡片（不改动 tkproxy 任何文件）。\
纯本地渲染，不加载任何外链 JS/CSS/图片。
LUCI_DEPENDS:=+luci-base +luci-compat +lua
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# 菜单注册由 root/usr/share/luci/menu.d/luci-app-buerwrt-ads.json 提供；
# uci-defaults 负责写出厂默认配置（enabled=1，用户改过就不覆盖）。
# 安装脚本只装文件并注册菜单：不 enable/start 任何服务。

# call BuildPackage - OpenWrt buildroot signature
