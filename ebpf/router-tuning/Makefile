# SPDX-License-Identifier: GPL-2.0-only
#
# ebpf / router-tuning : first-boot performance profile.
#
# x86, rockchip and qualcommax all get the same script; the differences are
# detected at runtime (CPU count, RAM, guest-vs-metal, WAN device) rather than
# shipped as three files. See files/router_tuning.config for the knobs and
# docs/kernel-and-tuning-research.md for the evidence behind each one.
#
# Package-level dependencies are the two levers that cannot be done from a
# script:
#   kmod-tcp-bbr : BBRv1 itself (and its own /etc/sysctl.d/12-tcp-bbr.conf)
#   kmod-sched   : CONFIG_NET_SCH_FQ -> sch_fq.ko, BBR's pacing qdisc
# ethtool is the tool for rings/coalescing/offloads; it is already in the image,
# but depending on it keeps the package honest on a cut-down build.
#
# Nothing here writes /etc/config/{network,dhcp,firewall}, and nothing here
# touches the WAN root qdisc (router-qos owns CAKE) or rps_cpus while the
# upstream packet_steering service is enabled.

include $(TOPDIR)/rules.mk

PKG_NAME:=router-tuning
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/router-tuning
  SECTION:=net
  CATEGORY:=Network
  TITLE:=first-boot performance tuning (sysctl / NIC / BBR)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+kmod-tcp-bbr +kmod-sched +ethtool
endef

define Package/router-tuning/description
  A first-boot profile for the routing box, aimed at the handful of knobs that
  actually move throughput on this class of hardware:

    * a sysctl set scaled to RAM (socket buffers, softirq backlog, UDP minima),
      plus tcp_mtu_probing for the PPPoE / blocked-ICMP PMTU case and a wider
      ephemeral port range for einat's full-cone NAT;
    * BBR + fq when the modules are present (BBR is the single biggest win on
      the proxy path: honk's outbound sockets live in this kernel);
    * ring sizes, GRO/GSO/TSO, coalescing and txqueuelen on the physical ports;
    * xps_cpus per TX queue - the one steering item that the upstream
      packet_steering service does not cover.

  What it deliberately does not do:

    * it never writes the WAN root qdisc (CAKE, owned by router-qos);
    * it never writes rps_cpus while the upstream packet_steering service is
      enabled (only as a fallback when that service is absent and every mask is
      still zero);
    * it only ever *raises* the socket buffers honk also sets, and never lowers
      anything another package owns;
    * it never edits /etc/config/{network,dhcp,firewall}.

  Everything is reversible: `router-tuning report` prints what apply would do
  without changing anything (same code path), and `router-tuning restore` puts
  the recorded originals back.
endef

define Package/router-tuning/conffiles
/etc/config/router_tuning
endef

# Script-only package: without this the default Build/Compile runs `make` in a
# directory with no Makefile.
define Build/Compile
	true
endef

define Package/router-tuning/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DIR) $(1)/usr/libexec

	$(INSTALL_BIN) ./files/router_tuning.init $(1)/etc/init.d/router-tuning
	$(INSTALL_DATA) ./files/router-tuning.sh $(1)/usr/libexec/router-tuning.sh
	$(INSTALL_DATA) ./files/router_tuning.config $(1)/etc/config/router_tuning
	$(INSTALL_BIN) ./files/93-router-tuning $(1)/etc/hotplug.d/iface/93-router-tuning
	$(INSTALL_BIN) ./files/98-mydist-tuning $(1)/etc/uci-defaults/98-mydist-tuning
endef

$(eval $(call BuildPackage,router-tuning))
