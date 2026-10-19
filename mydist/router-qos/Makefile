# SPDX-License-Identifier: GPL-2.0-only
#
# mydist / router-qos : CAKE on the WAN, one qdisc, no classifier cascade.
#
# Script-only package: no compilation, no eBPF object, nothing to shape but the
# upload. CAKE does its own per-flow fairness, ack filtering and DSCP->tin
# mapping, so "single TC program + CAKE" is taken literally: one root qdisc.
# The point is that it replaces the old HTB + classifier-cascade shape, not that
# it adds another program to the datapath.
#
# The download direction is not shaped. It would need an IFB, and both ways of
# feeding one are wrong on this device -- see the header of files/router-qos.sh
# for the measurement. Briefly: a mirror leaves the real packet unshaped, and a
# redirect either starves router-acl/dpd or changes the interface fw4 matches
# zones on.

include $(TOPDIR)/rules.mk

PKG_NAME:=router-qos
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/router-qos
  SECTION:=net
  CATEGORY:=Network
  TITLE:=mydist CAKE QoS (single root qdisc on the WAN)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+kmod-sched-core +kmod-sched-cake +tc-bpf
endef

define Package/router-qos/description
  CAKE QoS for the WAN upload.

    tc qdisc replace dev <wan> root cake bandwidth <upload>kbit ...

  One qdisc, no classes, no filter cascade: CAKE does the per-flow fairness and
  the DSCP->tin mapping itself. It replaces the old HTB + classifier-cascade
  shape rather than adding another program to the datapath.

  A root qdisc and the clsact qdisc that router-acl creates are independent
  (clsact lives at handle ffff:), so replacing root does not disturb the
  router-acl (pref 90) or dpd (pref 100) ingress/egress filter chains.

  The download direction is deliberately not shaped. An IFB is needed for that,
  and on this device a mirror leaves the real packet unshaped while a redirect
  either starves router-acl/dpd or breaks fw4's zone matching -- the long
  version, with the measurement, is in files/router-qos.sh.

  Default is enabled 0, and it refuses to start with upload=0: there would be
  nothing to shape and a stray qdisc is only a surprise.

  `nat 1` uses conntrack to keep a flow in one tin in both directions. Leave it
  0 when router-acl runs in bypass mode, because bypass is precisely the removal
  of that conntrack entry.
endef

define Package/router-qos/conffiles
/etc/config/router_qos
endef

# Script-only package. Without this the default Build/Compile runs `make` in a
# directory that has no Makefile at all and the build dies with
# "No targets specified and no makefile found".
define Build/Compile
	true
endef

define Package/router-qos/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DIR) $(1)/usr/libexec

	$(INSTALL_BIN) ./files/router_qos.init $(1)/etc/init.d/router-qos
	$(INSTALL_DATA) ./files/router-qos.sh $(1)/usr/libexec/router-qos.sh
	$(INSTALL_DATA) ./files/router_qos.config $(1)/etc/config/router_qos
	$(INSTALL_DATA) ./files/92-router-qos $(1)/etc/hotplug.d/iface/92-router-qos
endef

$(eval $(call BuildPackage,router-qos))
