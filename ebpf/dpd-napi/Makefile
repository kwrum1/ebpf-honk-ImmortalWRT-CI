include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-napi
PKG_VERSION:=0.1.0
PKG_RELEASE:=5
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-napi
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD NAPI/queue tuning
  DEPENDS:=+dpd-fastpath
endef

define Package/dpd-napi/description
  Applies NAPI and queue settings: netdev_budget, dev_weight, RPS/XPS masks
  through sysfs, plus per-NAPI gro_flush_timeout / defer_hard_irqs /
  irq_suspend_timeout / threaded through the kernel's netdev generic netlink
  family. No driver changes.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -O2 \
		-o $(PKG_BUILD_DIR)/dpd-napi-netdev \
		$(PKG_BUILD_DIR)/dpd-napi-netdev.c
endef

define Package/dpd-napi/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/dpd-napi.sh $(1)/usr/sbin/dpd-napi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpd-napi-netdev $(1)/usr/sbin/dpd-napi-netdev
	$(INSTALL_BIN) ./files/dpd-napi.init $(1)/etc/init.d/dpd-napi
	$(INSTALL_DATA) ./files/dpd_napi.config $(1)/etc/config/dpd_napi
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpd-napi $(1)/etc/rc.d/S94dpd-napi
endef

$(eval $(call BuildPackage,dpd-napi))
