# SPDX-License-Identifier: GPL-2.0-only
#
# mydist / router-dataplane : dpd-fastpath
#
# The TC ingress eBPF fastpath. See src/dpd_common.h for the redlines.
# Depends only on things already in the shipped baseline:
#   libbpf / libelf are pulled in by ip-full and tc-bpf already
#   host clang is used for the BPF target (CONFIG_BPF_TOOLCHAIN_HOST=y)

include $(TOPDIR)/rules.mk

PKG_NAME:=dpd-fastpath
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

PKG_BUILD_DEPENDS:=libbpf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/dpd-fastpath
  SECTION:=net
  CATEGORY:=Network
  TITLE:=mydist TC ingress eBPF fastpath (dpd)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+libbpf +libelf +kmod-sched-core +kmod-sched-bpf +tc-bpf $(BPF_DEPENDS)
endef

define Package/dpd-fastpath/description
  dpd_fastpath is a TC *ingress* eBPF fastpath for the mydist datapath.

  It is deliberately narrow: ingress-only, no NAT, no conntrack, and it never
  reads einat's maps. NAT keeps exactly one owner (einat-ebpf).

  It attaches as a *classic* tc filter at pref 100, and that is the whole reason
  it can coexist with the transparent proxy: the proxy (honk/dae) owns TCX, and
  the kernel runs tcx_run() before tc_run(), so every classic filter sees only
  the flows the proxy already declined. Measured with `bpftool net show` in QEMU
  on 2026-10-17 -- see src/dpd_common.h for the full hook layout.

  Because taking a packet over skips netfilter, its reply is only accepted while
  einat is the attached NAT (it injects a blanket WAN->LAN accept into fw4).
  Acceleration is therefore gated on einat: without it the init script downgrades
  the mode to observe and says why. IPv6 is never accelerated (no NAT66 here).

  Modes: off / observe (telemetry only) / stateless / stateful / neigh-probe.
  Default is stateless on the LAN interfaces, subject to the gates above.
  Policy: allow_all (default) or vlans_only with an explicit VLAN id list.
endef

define Package/dpd-fastpath/conffiles
/etc/config/dpd_fastpath
endef

define Build/Prepare
	$(CP) ./src $(PKG_BUILD_DIR)/
endef

# ---------------------------------------------------------------------------
# The eBPF object.
#
# We intentionally do NOT use bpf.mk's CompileBPF: that path goes
# clang -> llc -> llvm-dis -> opt, and this build host has clang but not the
# llvm-* tools. A single clang invocation with -target bpf -g produces exactly
# what libbpf needs (BTF + BTF.ext + relocations), and -g is mandatory.
#
# Headers come from two places that are already in the tree:
#   $(STAGING_DIR)/usr/include       bpf/bpf_helpers.h  (from libbpf)
#   $(TOOLCHAIN_DIR)/include         linux/bpf.h, linux/pkt_cls.h (UAPI)
# bpf-headers is deliberately avoided: it pins Linux 6.12 and that tarball is
# not in dl/, so depending on it would force a fresh kernel download.
# ---------------------------------------------------------------------------
DPD_BPF_INCLUDES := \
	-I$(STAGING_DIR)/usr/include \
	-I$(TOOLCHAIN_DIR)/include

DPD_BPF_FLAGS := \
	-target bpf -g -O2 -Wall -Wno-unused-function -Wno-unused-variable \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-DDPD_MODE_DEFAULT=1

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/dpdctl $(PKG_BUILD_DIR)/src/dpdctl.c \
		-lbpf -lelf -lz
	$(CLANG) $(DPD_BPF_FLAGS) $(DPD_BPF_INCLUDES) \
		-c $(PKG_BUILD_DIR)/src/dpd_fastpath.bpf.c \
		-o $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o
	@echo "--- dpd_fastpath.bpf.o sections ---"
	@$(TARGET_CROSS)readelf -S $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o | \
		grep -E 'BTF|classifier|\.maps' || true
endef

define Package/dpd-fastpath/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dpdctl $(1)/usr/sbin/dpdctl
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o $(1)/lib/bpf/

	$(INSTALL_BIN) ./files/dpd_fastpath.init $(1)/etc/init.d/dpd-fastpath
	$(INSTALL_DATA) ./files/dpd-fastpath.sh $(1)/usr/libexec/dpd-fastpath.sh
	$(INSTALL_BIN) ./files/dpd-gate-refresh $(1)/usr/libexec/dpd-gate-refresh
	$(INSTALL_BIN) ./files/dpd-gate-watchdog $(1)/usr/libexec/dpd-gate-watchdog
	$(INSTALL_DATA) ./files/dpd_fastpath.config $(1)/etc/config/dpd_fastpath
	$(INSTALL_DATA) ./files/90-dpd-fastpath $(1)/etc/hotplug.d/iface/90-dpd-fastpath
endef

$(eval $(call BuildPackage,dpd-fastpath))
