include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-qos
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=kwrum1

include $(INCLUDE_DIR)/package.mk

define Package/dpd-qos
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=DPD
  TITLE:=DPD QoS/SQM plugin (router-qos)
  DEPENDS:=+router-qos
  PKGARCH:=all
endef

define Package/dpd-qos/description
  Meta package for the DPD plugin name. The implementation stays in router-qos so
  existing UCI/LuCI remains compatible.
endef

define Build/Compile
endef

define Package/dpd-qos/install
	$(INSTALL_DIR) $(1)/usr/share/dpd
endef

$(eval $(call BuildPackage,dpd-qos))