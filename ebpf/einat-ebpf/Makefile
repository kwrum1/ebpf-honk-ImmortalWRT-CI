# SPDX-License-Identifier: GPL-2.0-only
#
# ebpf: einat-ebpf as a PREBUILT-BINARY package.
#
# Why not build it from source: upstream's own OpenWrt packaging
# (muink/openwrt-einat-ebpf) declares
#
#     PKG_BUILD_DEPENDS:=rust/host libbpf HAS_BPF_TOOLCHAIN:bpf-headers
#
# which means bootstrapping a host Rust toolchain, downloading the llvm-bpf
# toolchain, and pulling in bpf-headers -- and bpf-headers pins linux-6.12,
# which is not in our download cache. None of that buys anything here: upstream
# publishes fully static binaries and the release build uses the `aya` loader,
# so there is no libbpf/elf/zlib dependency at runtime either.
#
# Cost/benefit: ~2.4 MB of binary, zero build dependencies, no rust/host.
#
# Licensing: BPF sources under src/bpf/kernel are GPL-2.0-only (derived from the
# kernel), the rest is GPL-2.0-or-later. The BPF program calls GPL-only kernel
# functions, so the binary is distributed as GPL-2.0-only.

include $(TOPDIR)/rules.mk

PKG_NAME:=einat-ebpf
PKG_VERSION:=0.1.11
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

# ARCH -> upstream release asset. Only the architectures einat supports are
# listed: it needs BPF-to-BPF calls, which the kernel only has for actively
# maintained archs (x86-64, aarch64). The DEPENDS line rejects everything else.
ifeq ($(ARCH),x86_64)
  EINAT_ASSET:=einat-static-x86_64-unknown-linux-musl
  EINAT_HASH:=d3c33347ba958f35d9ea6c81ec01b035cc2a41ac5cda074ae4589282d23981be
else ifeq ($(ARCH),aarch64)
  EINAT_ASSET:=einat-static-aarch64-unknown-linux-musl
  EINAT_HASH:=93df51fd9d02c8ba651daa359a5bf05d6728650806df67ea9a35fdd43b422f76
else
  EINAT_ASSET:=einat-static-$(ARCH)-unknown-linux-musl
  EINAT_HASH:=skip
endif

PKG_SOURCE:=$(EINAT_ASSET)
PKG_SOURCE_URL:=https://github.com/EHfive/einat-ebpf/releases/download/v$(PKG_VERSION)
PKG_HASH:=$(EINAT_HASH)

include $(INCLUDE_DIR)/package.mk

define Package/einat-ebpf
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=eBPF-based Endpoint-Independent (Full Cone) NAT
  URL:=https://github.com/EHfive/einat-ebpf
  DEPENDS:=@(x86_64||aarch64) +kmod-sched-core +kmod-sched-bpf +@KERNEL_DEBUG_INFO_BTF
  PROVIDES:=einat
endef

define Package/einat-ebpf/description
  Endpoint-Independent Mapping + Endpoint-Independent Filtering (i.e. full cone)
  NAT implemented from scratch on the TC ingress/egress hooks, replacing
  netfilter conntrack masquerading. Installed from upstream's prebuilt static
  binary (aya loader, no runtime library dependencies).
endef

define Package/einat-ebpf/conffiles
/etc/config/einat
endef

# PKG_SOURCE is a bare executable, not an archive, so the default unpack step
# (which would try to untar it) has to be replaced.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/einat-ebpf/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(DL_DIR)/$(PKG_SOURCE) $(1)/usr/bin/einat

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/einat.init $(1)/etc/init.d/einat
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/einat-wait-wan $(1)/usr/libexec/einat-wait-wan

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/einat-hotplug $(1)/etc/hotplug.d/iface/89-einat

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/einat.config $(1)/etc/config/einat

	$(INSTALL_DIR) $(1)/etc/capabilities
	$(INSTALL_CONF) ./files/capabilities.json $(1)/etc/capabilities/einat.json
endef

$(eval $(call BuildPackage,einat-ebpf))
