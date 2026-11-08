include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-observe
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-observe
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD status/telemetry composer
  DEPENDS:=+dpd-fastpath
  PKGARCH:=all
endef

define Package/dpd-observe/description
  Composes one status document from dpdctl, the gate file and the plugin
  status files. Exposes it over ubus for the LuCI page and scripts.
endef

define Build/Compile
endef

define Package/dpd-observe/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/dpd-observe.sh $(1)/usr/sbin/dpd-observe
	$(INSTALL_BIN) ./files/dpd-observe.init $(1)/etc/init.d/dpd-observe
	$(INSTALL_DATA) ./files/dpd_observe.config $(1)/etc/config/dpd_observe
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpd-observe $(1)/etc/rc.d/S97dpd-observe
endef

$(eval $(call BuildPackage,dpd-observe))
