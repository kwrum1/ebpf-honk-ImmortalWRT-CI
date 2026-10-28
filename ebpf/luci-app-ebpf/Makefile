include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ebpf
PKG_VERSION:=0.5.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=ebpf

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-ebpf
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=eBPF datapath: menu layout and the simple firewall
  DEPENDS:=+luci-base +luci-compat +luci-lua-runtime +luci-app-smartdns +luci-app-honk
  PKGARCH:=all
endef

define Package/luci-app-ebpf/description
  Menu layout and the pages this firmware keeps by hand:

    * Network -> 防火墙    (five-tuple port control for IPv4 and IPv6 on top of
                            fw4; firewall.ebpf999 always blocks unsolicited
                            inbound and is not exposed in the UI)
    * Network -> DNS       (SmartDNS, the only resolver; it owns :53)
    * Network -> 代理      (honk)
    * Network -> DHCP      (stock page, dnsmasq half hidden, odhcpd only)

  dnsmasq is not a resolver here and is stopped by ebpf-posture.
endef

define Build/Compile
endef

define Package/luci-app-ebpf/install
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./files/menu-network.json $(1)/usr/share/luci/menu.d/zz-ebpf-network.json
	$(INSTALL_DATA) ./files/menu-firewall.json $(1)/usr/share/luci/menu.d/zz-ebpf-firewall.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/acl.d/luci-app-ebpf.json $(1)/usr/share/rpcd/acl.d/luci-app-ebpf.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/ebpf
	$(INSTALL_DATA) ./files/htdocs/luci-static/resources/view/ebpf/firewall.js $(1)/www/luci-static/resources/view/ebpf/firewall.js
	$(INSTALL_DATA) ./files/htdocs/luci-static/resources/view/ebpf/mwan.js $(1)/www/luci-static/resources/view/ebpf/mwan.js
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-luci-ebpf-trim $(1)/etc/uci-defaults/99-luci-ebpf-trim
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/posture.init $(1)/etc/init.d/ebpf-posture

	# Ship the rc.d symlinks instead of relying on a first-boot `enable`:
	# the uci-defaults run at S10, i.e. after the boot scan of /etc/rc.d has
	# already decided what to start, so a service enabled there would not run
	# until the *second* boot. A flashed router must accelerate on the first.
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf ../init.d/ebpf-posture $(1)/etc/rc.d/S26ebpf-posture
endef

$(eval $(call BuildPackage,luci-app-ebpf))
