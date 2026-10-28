include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-mydist
PKG_VERSION:=0.5.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-mydist
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=eBPF datapath: menu layout and the simple firewall
  DEPENDS:=+luci-base +luci-compat +luci-lua-runtime +luci-app-smartdns +luci-app-honk
  PKGARCH:=all
endef

define Package/luci-app-mydist/description
  Menu layout and the pages this firmware keeps by hand:

    * Network -> 防火墙    (five-tuple port control for IPv4 and IPv6 on top of
                            fw4; firewall.mydist999 always blocks unsolicited
                            inbound and is not exposed in the UI)
    * Network -> DNS       (SmartDNS, the only resolver; it owns :53)
    * Network -> 代理      (honk)
    * Network -> DHCP      (stock page, dnsmasq half hidden, odhcpd only)

  dnsmasq is not a resolver here and is stopped by mydist-posture.
endef

define Build/Compile
endef

define Package/luci-app-mydist/install
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./files/menu-network.json $(1)/usr/share/luci/menu.d/zz-mydist-network.json
	$(INSTALL_DATA) ./files/menu-firewall.json $(1)/usr/share/luci/menu.d/zz-mydist-firewall.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/acl.d/luci-app-mydist.json $(1)/usr/share/rpcd/acl.d/luci-app-mydist.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/mydist
	$(INSTALL_DATA) ./files/htdocs/luci-static/resources/view/mydist/firewall.js $(1)/www/luci-static/resources/view/mydist/firewall.js
	$(INSTALL_DATA) ./files/htdocs/luci-static/resources/view/mydist/mwan.js $(1)/www/luci-static/resources/view/mydist/mwan.js
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-luci-mydist-trim $(1)/etc/uci-defaults/99-luci-mydist-trim
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/posture.init $(1)/etc/init.d/mydist-posture
endef

$(eval $(call BuildPackage,luci-app-mydist))
