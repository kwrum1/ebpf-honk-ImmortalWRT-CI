# mydist / luci-front: the public HTTP(S) front end for LuCI.
#
# uhttpd keeps its two irreplaceable halves -- the embedded Lua interpreter that
# runs /cgi-bin/luci and the libubus bridge for /ubus -- but it moves to
# 127.0.0.1:8080 and stops doing TLS. Everything a browser touches first (:80,
# :443, HTTP/2, security headers, static assets, conditional GET) is served by
# this front end, which reverse-proxies the dynamic paths to uhttpd.
#
# The binary is built out of tree (build/luci-front, Rust + pingora, static musl)
# and shipped prebuilt, exactly like the honk-core binary that the honk package
# downloads: building Rust inside the OpenWrt tree would add a toolchain the size
# of the one we already have, for one 7.4 MB binary.
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-front
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/luci-front
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=LuCI front end (pingora): TLS/HTTP2 + static, dynamic proxied to uhttpd
  DEPENDS:=@(x86_64||aarch64) +luci-base +uhttpd
endef

define Package/luci-front/description
  Serves LuCI over HTTP/2 with the image's certificate and security headers,
  answers :80 with a redirect, serves /www itself (ETag, 304, cache policy) and
  reverse-proxies /cgi-bin/ and /ubus to uhttpd on loopback. uhttpd keeps the Lua
  CGI and the ubus bridge; it no longer listens on a public port.

  Built with pingora (cloudflare/pingora) as a Rust library; the binary is
  static musl and has no runtime dependencies.
endef

define Build/Compile
endef

# Never strip the shipped binary. It is built and accepted out of tree, and
# sstrip rewrites it: measured 2026-10-19, the stripped build answered :80 with
# the correct 301 but its :443 listener accepted the TCP connection and never
# completed a TLS handshake on the target, while the unstripped binary served the
# same image fine. RSTRIP is expanded inside package-ipkg.mk at recipe time.
RSTRIP:=:
STRIP:=:

# One prebuilt static musl binary per supported arch. `ARCH` is the OpenWrt CPU
# arch (x86_64 / aarch64); anything else is excluded by DEPENDS above.
ifeq ($(ARCH),aarch64)
  LUCI_FRONT_BIN:=./files/luci-front-aarch64
else
  LUCI_FRONT_BIN:=./files/luci-front
endif

define Package/luci-front/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(LUCI_FRONT_BIN) $(1)/usr/sbin/luci-front
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/luci_front.init $(1)/etc/init.d/luci-front
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/luci_front.config $(1)/etc/config/luci_front
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/96-mydist-front $(1)/etc/uci-defaults/96-mydist-front
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/luci-front-report $(1)/usr/libexec/luci-front-report
endef

$(eval $(call BuildPackage,luci-front))
