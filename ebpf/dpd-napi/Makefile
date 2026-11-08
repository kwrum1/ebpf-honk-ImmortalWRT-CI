include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-napi
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-napi
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD NAPI/queue tuning
  DEPENDS:=+dpd-fastpath
  PKGARCH:=all
endef

define Package/dpd-napi/description
  Applies per-device NAPI and queue settings through standard sysfs/sysctl:
  netdev_budget, dev_weight, gro_flush_timeout, napi_defer_hard_irqs,
  RPS/XPS masks. No driver changes.
endef

define Build/Compile
endef

define Package/dpd-napi/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/dpd-napi.sh $(1)/usr/sbin/dpd-napi
	$(INSTALL_BIN) ./files/dpd-napi.init $(1)/etc/init.d/dpd-napi
	$(INSTALL_DATA) ./files/dpd_napi.config $(1)/etc/config/dpd_napi
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpd-napi $(1)/etc/rc.d/S94dpd-napi
endef

$(eval $(call BuildPackage,dpd-napi))
