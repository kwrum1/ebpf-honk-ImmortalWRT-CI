include $(TOPDIR)/rules.mk

PKG_NAME:=dpdfwd
PKG_VERSION:=0.1.0
PKG_RELEASE:=7
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpdfwd
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD Flow Manager (control plane)
  DEPENDS:=+dpd-fastpath
endef

define Package/dpdfwd/description
  Event-driven flow-cache manager: turns link/address/route/neighbour
  changes into one debounced epoch bump, subscribes to conntrack
  new/update/destroy for accounting, and publishes /var/run/dpd/flowd.json.
  The packet path stays in dpd-fastpath; this daemon never touches a packet.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -O2 \
		-o $(PKG_BUILD_DIR)/dpdfwd $(PKG_BUILD_DIR)/dpdfwd.c
endef

define Package/dpdfwd/conffiles
/etc/dpd/class.conf
endef

define Package/dpdfwd/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/dpd
	$(INSTALL_DIR) $(1)/usr/include/dpd $(1)/usr/lib/dpd/plugins
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpdfwd $(1)/usr/sbin/dpdfwd
	$(INSTALL_BIN) ./files/dpdfwd.init $(1)/etc/init.d/dpdfwd
	$(INSTALL_CONF) ./files/class.conf $(1)/etc/dpd/class.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dpd_plugin.h $(1)/usr/include/dpd/dpd_plugin.h
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpdfwd $(1)/etc/rc.d/S96dpdfwd
endef

$(eval $(call BuildPackage,dpdfwd))
