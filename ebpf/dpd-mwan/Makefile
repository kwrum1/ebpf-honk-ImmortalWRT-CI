include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-mwan
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-mwan
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD multi-WAN plugin (ebpf-mwan)
  DEPENDS:=+dpd-fastpath
  PKGARCH:=all
endef

define Package/dpd-mwan/description
  Meta package for the DPD plugin name. The implementation stays in dpd-fastpath so
  existing UCI/LuCI remains compatible.
endef

define Build/Compile
endef

define Package/dpd-mwan/install
	$(INSTALL_DIR) $(1)/usr/share/dpd
endef

$(eval $(call BuildPackage,dpd-mwan))