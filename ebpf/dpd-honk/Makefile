include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-honk
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-honk
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD honk proxy plugin (control plane only)
  DEPENDS:=+dpd-fastpath +honk
  PKGARCH:=all
endef

define Package/dpd-honk/description
  Reports honk health, exposes the proxy side of DPD-FW and bumps the DPD
  flow-cache epoch when honk's config changes. It never starts, stops or
  reconfigures honk.
endef

define Build/Compile
endef

define Package/dpd-honk/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/dpd-honk.sh $(1)/usr/sbin/dpd-honk
	$(INSTALL_BIN) ./files/dpd-honk.init $(1)/etc/init.d/dpd-honk
	$(INSTALL_DATA) ./files/dpd_honk.config $(1)/etc/config/dpd_honk
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpd-honk $(1)/etc/rc.d/S96dpd-honk
endef

$(eval $(call BuildPackage,dpd-honk))
