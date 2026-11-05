#
# 预编译 Xray 核心（aarch64），只做打包不做编译：省掉 golang 工具链
#
include $(TOPDIR)/rules.mk

PKG_NAME:=xray-core
PKG_VERSION:=26.3.27
PKG_RELEASE:=1
PKG_LICENSE:=MPL-2.0

PKG_SOURCE:=Xray-linux-arm64-v8a.zip
PKG_SOURCE_URL:=https://github.com/XTLS/Xray-core/releases/download/v$(PKG_VERSION)
PKG_HASH:=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c

RSTRIP:=

include $(INCLUDE_DIR)/package.mk

define Package/xray-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Xray core (prebuilt aarch64)
  URL:=https://github.com/XTLS/Xray-core
endef

define Package/xray-core/description
  Xray 核心，预编译二进制（来自 XTLS 官方 release）。
endef

define Build/Compile
endef

define Package/xray-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xray $(1)/usr/bin/xray
endef

$(eval $(call BuildPackage,xray-core))
