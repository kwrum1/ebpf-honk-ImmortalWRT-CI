include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-dpd
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-dpd
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=DPD-FW status and plugin UI
  DEPENDS:=+luci-base +luci-compat +dpd-observe +dpd-honk
  PKGARCH:=all
endef

define Package/luci-app-dpd/description
  DPD-FW overview: datapath mode/gate, flow-cache size, honk proxy status and
  NAPI settings. The datapath pages that already exist in luci-app-ebpf
  (firewall/mwan) are linked, not duplicated.
endef

define Build/Compile
endef

define Package/luci-app-dpd/install
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/dpd $(1)/usr/libexec/rpcd/dpd
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-dpd.json $(1)/usr/share/rpcd/acl.d/luci-app-dpd.json
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-dpd.json $(1)/usr/share/luci/menu.d/luci-app-dpd.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/dpd
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/dpd/overview.js $(1)/www/luci-static/resources/view/dpd/overview.js
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/dpd/flows.js $(1)/www/luci-static/resources/view/dpd/flows.js
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/dpd/honk.js $(1)/www/luci-static/resources/view/dpd/honk.js
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/dpd/napi.js $(1)/www/luci-static/resources/view/dpd/napi.js
endef

$(eval $(call BuildPackage,luci-app-dpd))
