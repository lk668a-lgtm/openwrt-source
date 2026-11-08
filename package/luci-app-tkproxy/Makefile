# SPDX-License-Identifier: GPL-3.0
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tkproxy
PKG_VERSION:=3.15.17
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0
PKG_MAINTAINER:=tkproxy <tkproxy@localhost>

LUCI_TITLE:=LuCI app: 多线路分流（每个 WiFi 一个出口）
LUCI_DESCRIPTION:=为每个 SSID/频段生成独立的 sing-box 入口、nftables 分流规则\
与策略路由，网页端维护线路清单；只写本方案自己的 uci 段，不改动已有\
wireless/network/dhcp/firewall 配置。纯 Lua 实现，不依赖 python 或 PassWall。
LUCI_DEPENDS:=+luci-base +luci-lua-runtime +luci-compat +lua +libuci-lua +uci +jshn +ip-full +curl \
	+nftables +kmod-nft-tproxy +kmod-nft-socket +kmod-nf-tproxy +kmod-veth +xray-core
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# 安装脚本只装文件并注册菜单：不 enable/start 任何服务，
# 也不触碰 wireless/network/dhcp/firewall 的任何段。

# call BuildPackage - OpenWrt buildroot signature
