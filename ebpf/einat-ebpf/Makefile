# SPDX-License-Identifier: GPL-2.0-only
#
# ebpf: einat-ebpf as a PREBUILT-BINARY package.
#
# The binary is built by this repository's EINAT-BUILD workflow from upstream
# source (pinned commit) with two patches applied, and published at the fixed
# release tag `einat-p2`:
#
#   patches/einat-perf.py (p1)
#     * upstream `static` preset: v4-only, no NAT66 code in the BPF program
#       (this firmware never NATs v6; v6 is routed and accelerated by dpd);
#     * one less full L2/L3 parse per packet per direction: the v4-only build
#       still called get_is_ipv4() at the top of both TC programs even though
#       parse_packet() immediately parses the same header again.
#
#   patches/einat-perf-p2.py (p2)
#     * dest_config fast path: with a single dest entry (the WAN address) the
#       egress hook compares the packet destination instead of doing an LPM
#       lookup on every packet;
#     * established-TCP CT fast path: a TCP data packet on an established
#       connection skips the CT lookup and the (locked) bpf_timer_start() for
#       up to CT_FAST_PATH_MS after the last real lookup. SYN/FIN/RST, ICMP
#       errors, UDP/ICMP and any other CT state still take the slow path.
#
# The same EINAT-BUILD run executes patches/einat-e2e-nat.sh in network
# namespaces (EIM, EIF/full cone, ICMP, 20 MB TCP) before publishing, so the
# assets below are known to load and forward. Hashes are the sha256 of those
# assets: re-running EINAT-BUILD on a newer upstream commit means updating the
# version, the four hash lines and PKG_RELEASE.
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
PKG_VERSION:=0.1.11-p2
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

# ARCH -> upstream release asset. Only the architectures einat supports are
# listed: it needs BPF-to-BPF calls, which the kernel only has for actively
# maintained archs (x86-64, aarch64). The DEPENDS line rejects everything else.
ifeq ($(ARCH),x86_64)
  EINAT_ASSET:=einat-p2-x86_64-unknown-linux-musl
  EINAT_HASH:=c3390bee96f71bbbef497da27010a438b180e3622d29ac510a4c796afcade6e4
else ifeq ($(ARCH),aarch64)
  EINAT_ASSET:=einat-p2-aarch64-unknown-linux-musl
  EINAT_HASH:=b7d667fc6c1fd05d22452e988a32f0a0d3a36f330ab7fec229fb29e19307c744
else
  EINAT_ASSET:=einat-p2-$(ARCH)-unknown-linux-musl
  EINAT_HASH:=skip
endif

PKG_SOURCE:=$(EINAT_ASSET)
PKG_SOURCE_URL:=https://github.com/kwrum1/ebpf-honk-ImmortalWRT-CI/releases/download/einat-p2
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
