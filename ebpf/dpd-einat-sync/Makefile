include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-einat-sync
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-einat-sync
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD einat binding mirror
  DEPENDS:=+dpd-fastpath +einat-ebpf
endef

define Package/dpd-einat-sync/description
  Mirrors einat's full-cone outbound bindings into DPD's dpd_nat map. The DPD
  hit path applies the SNAT; einat remains the only binding allocator.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -O2 \
		-o $(PKG_BUILD_DIR)/dpd-einat-sync $(PKG_BUILD_DIR)/dpd-einat-sync.c
endef

define Package/dpd-einat-sync/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpd-einat-sync $(1)/usr/sbin/dpd-einat-sync
	$(INSTALL_BIN) ./files/dpd-einat-sync.init $(1)/etc/init.d/dpd-einat-sync
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/dpd-einat-sync $(1)/etc/rc.d/S95dpd-einat-sync
endef

$(eval $(call BuildPackage,dpd-einat-sync))
