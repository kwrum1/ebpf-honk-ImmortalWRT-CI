# SPDX-License-Identifier: GPL-2.0-only
#
# ebpf: einat-ebpf as a PREBUILT-BINARY package.
#
# The binary is built by this repository's EINAT-BUILD workflow from upstream
# source (pinned commit) with patches/einat-perf.py applied, and published at
# the fixed release tag `einat-p1`:
#
#   * upstream `static` preset: v4-only, no NAT66 code in the BPF program
#     (this firmware never NATs v6; v6 is routed and accelerated by dpd);
#   * one less full L2/L3 parse per packet per direction: the v4-only build
#     still called get_is_ipv4() at the top of both TC programs even though
#     parse_packet() immediately parses the same header again.
#
# Hashes below are the sha256 of the published assets. Re-running EINAT-BUILD
# on a newer upstream commit means updating the version, the four hash lines and
# PKG_RELEASE.
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
PKG_VERSION:=0.1.11-p1
PKG_RELEASE:=2

PKG_LICENSE:=GPL-2.0-only GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

# ARCH -> upstream release asset. Only the architectures einat supports are
# listed: it needs BPF-to-BPF calls, which the kernel only has for actively
# maintained archs (x86-64, aarch64). The DEPENDS line rejects everything else.
ifeq ($(ARCH),x86_64)
  EINAT_ASSET:=einat-p1-x86_64-unknown-linux-musl
  EINAT_HASH:=200acccaefbe68dc5e77e0250eafe6782bfd7b881d87d97106007a393104a0b3
else ifeq ($(ARCH),aarch64)
  EINAT_ASSET:=einat-p1-aarch64-unknown-linux-musl
  EINAT_HASH:=067e2b889e64d4d5c11ff2f0a36bceb9394edf7dd702e2f5c7048a69faeb344f
else
  EINAT_ASSET:=einat-p1-$(ARCH)-unknown-linux-musl
  EINAT_HASH:=skip
endif

PKG_SOURCE:=$(EINAT_ASSET)
PKG_SOURCE_URL:=https://github.com/kwrum1/ebpf-honk-ImmortalWRT-CI/releases/download/einat-p1
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
