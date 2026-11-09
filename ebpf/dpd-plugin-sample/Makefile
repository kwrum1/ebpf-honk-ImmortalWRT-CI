include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-plugin-sample
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-plugin-sample
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD example control-plane plugin (ABI v1)
  DEPENDS:=+dpdfwd
endef

define Package/dpd-plugin-sample/description
  Reference plugin for the dpdfwd plugin ABI: exports dpd_plugin_ops,
  blocks TCP/25 on new flows and counts topology/flow events. It is
  control-plane only and can be removed without affecting the datapath.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -fPIC -shared \
		-I$(STAGING_DIR)/usr/include/dpd \
		-o $(PKG_BUILD_DIR)/dpd_plugin_sample.so \
		$(PKG_BUILD_DIR)/sample.c
endef

define Package/dpd-plugin-sample/install
	$(INSTALL_DIR) $(1)/usr/lib/dpd/plugins
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpd_plugin_sample.so \
		$(1)/usr/lib/dpd/plugins/dpd_plugin_sample.so
endef

$(eval $(call BuildPackage,dpd-plugin-sample))
