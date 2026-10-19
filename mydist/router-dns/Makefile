# SPDX-License-Identifier: GPL-2.0-only
#
# mydist / router-dns : smartdns becomes the resolver, dnsmasq stays the front.
#
# Script-only package: nothing to compile. It ships two things and nothing else.
#
#   1. /etc/init.d/router-dns -- START=18, patches `no-resolv` and
#      `server=127.0.0.1#6053` into /etc/dnsmasq.conf, the file
#      /etc/init.d/dnsmasq passes to dnsmasq as --conf-file= (dnsmasq.init
#      :942-949). The delegation therefore needs no write into /etc/config/dhcp.
#
#      It is a boot-time patch rather than a shipped /etc/dnsmasq.conf on
#      purpose: that path is owned by dnsmasq-full, and a second package
#      providing it makes apk abort the whole install with
#
#        ERROR: router-dns-0.1.0-r1: trying to overwrite etc/dnsmasq.conf
#               owned by dnsmasq-full-2.93-r4.
#
#      as this package did in round 4. Patching at boot is also self-healing
#      across a dnsmasq package upgrade that restores the stock file.
#
#   2. /etc/uci-defaults/97-mydist-dns -- turns smartdns on, moves it to 6053,
#      sets auto_set_dnsmasq=0 and configures DNS-over-TLS upstreams. DoT is not
#      decoration: while honk runs, the router's own UDP never completes (a local
#      TCP connection to the same address does), so a UDP upstream resolves
#      nothing cold -- see the long comment in that file and §9 of
#      docs/proxy-accel-coexistence.md.
#
#   3. /usr/libexec/router-honk-dns -- while honk runs it OWNS transparent DNS:
#      its datapath intercepts LAN :53 (deliberately; its shipped policy even
#      excludes :53 from `direct(must)`) and answers from its own upstreams, so
#      the dnsmasq -> smartdns chain above is bypassed for every client. That
#      left a box with no working DNS at all when measured (2026-10-18):
#      clients got SERVFAIL ("upstream 'default' failed via 223.5.5.5:443") and
#      the router's own queries timed out. The patch gives DNS back to the
#      kernel/dnsmasq path: `dport(53) -> direct(must)` becomes the first routing
#      rule, the two now-redundant `&& !dport(53)` clauses are dropped, and honk's
#      `default` upstream (used for its own dialling) becomes smartdns on the
#      loopback. Idempotent, marked, and only applied while the file is stock.
#      Called from the init script below, so it runs before honk's own S95.
#      Handing :53 back is necessary but NOT sufficient: the resolver then has to
#      reach an upstream, and with honk running the router's own UDP does not
#      complete. That is why 97-mydist-dns configures DoT (TCP) upstreams; the
#      two halves were measured together, and each alone leaves a box that only
#      answers from cache.
#
# Why smartdns does NOT take over :53 (its other supported mode, `port 53` +
# auto_set_dnsmasq=1) even though that is the more literal reading of
# "smartdns replaces dnsmasq's resolution":
#
#   With dnsmasq at port 0 the box loses the LAN-facing name service that the
#   rest of this baseline depends on -- /etc/hosts, `local=/lan/`, and the names
#   odhcpd publishes in /tmp/hosts/odhcpd.hosts.lan (see the odhcpd handover
#   work). smartdns would have to be taught all of that separately and the
#   odhcpd hosts file would become dead weight.
#
#   Keeping dnsmasq on :53 as a pure forwarder gives exactly the same upstream
#   behaviour (smartdns does every lookup, concurrently, and picks the fastest
#   answer) while leaving local name resolution intact. What "the resolver is
#   smartdns" means in practice is: dnsmasq no longer resolves anything.
#
# auto_set_dnsmasq=0 is load-bearing: with it left at 1, smartdns's own init
# script rewrites /etc/config/dhcp (dhcp.@dnsmasq[0].server / noresolv /
# rebind_protection / domainneeded, or in the port-53 mode dhcp.@dnsmasq[0].port
# and dhcp.lan.dhcp_option). That is upstream's supported integration, but this
# distribution does not let a package rewrite the base config, so we take the
# forwarding half from upstream and do the dnsmasq half ourselves in
# /etc/dnsmasq.conf.
#
# Known cosmetic difference from upstream's mechanism: it also clears
# `rebind_protection` and `domainneeded` on dnsmasq. We cannot set those from a
# dnsmasq conf file (there is no inverse flag for --stop-dns-rebind), so they
# stay at the stock values. In practice this is harmless and slightly stricter:
# rebind protection only rejects public names that resolve into RFC1918 space,
# and --domain-needed only refuses to forward names without a dot.

include $(TOPDIR)/rules.mk

PKG_NAME:=router-dns
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/router-dns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=mydist DNS (smartdns resolves, dnsmasq stays the front)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+smartdns +dnsmasq
endef

define Package/router-dns/description
  smartdns does the resolution, dnsmasq stays the front end on :53.

  dnsmasq keeps serving /etc/hosts, local=/lan/ and the names odhcpd publishes,
  and forwards everything else to smartdns on 127.0.0.1:6053. smartdns races the
  configured upstreams concurrently and answers with the fastest result, so
  "smartdns replaces dnsmasq's resolution" holds without giving up the local
  name service.

  The dnsmasq side is two lines patched into /etc/dnsmasq.conf at boot by
  /etc/init.d/router-dns (no-resolv + one server= line); /etc/config/dhcp is
  not rewritten. The smartdns side is a uci-defaults script, so the whole
  change is visible in one place.

  Upstreams default to AliDNS + DNSPod. Edit
  /etc/config/smartdns (list server ...) to change them.
endef

# Script-only package. Without this the default Build/Compile runs `make` in a
# directory with no Makefile and the build dies with "No targets specified".
define Build/Compile
	true
endef

define Package/router-dns/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/router-dns.init $(1)/etc/init.d/router-dns
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/97-mydist-dns $(1)/etc/uci-defaults/97-mydist-dns
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/honk-dns.sh $(1)/usr/libexec/router-honk-dns
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/router_dns.config $(1)/etc/config/router_dns
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/88-router-dns-egress $(1)/etc/hotplug.d/iface/88-router-dns-egress
endef

$(eval $(call BuildPackage,router-dns))
