# SPDX-License-Identifier: GPL-2.0-only
#
# mydist / router-acl : the WAN eBPF ACL
#
# See src/acl_common.h for the redlines and the hook layout. Depends only on
# things already in the shipped baseline: libbpf/libelf come in with ip-full and
# tc-bpf, and the host clang is used for the BPF target.

include $(TOPDIR)/rules.mk

PKG_NAME:=router-acl
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

PKG_BUILD_DEPENDS:=libbpf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/router-acl
  SECTION:=net
  CATEGORY:=Network
  TITLE:=mydist WAN eBPF ACL (drop unsolicited inbound, escape conntrack)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+libbpf +libelf +kmod-sched-core +kmod-sched-bpf +kmod-nft-core +tc-bpf $(BPF_DEPENDS)
endef

define Package/router-acl/description
  router-acl is the WAN filter of the mydist datapath.

  It is deliberately narrow: no NAT, no einat map access, no redirection. It
  learns what the LAN sent out by watching the WAN egress direction and then
  decides, on ingress, whether an inbound packet belongs to something we
  started.

  Two useful modes:

    guard   drop unsolicited inbound. Purely additive -- fw4 and conntrack keep
            working exactly as before, only junk disappears before it reaches
            either. A port scan no longer creates conntrack entries and no
            longer walks the nft ruleset.

    bypass  guard, plus marking, plus two generated fw4 includes that notrack
            the marked flows and accept them in the forward chain. This is what
            actually takes nf_conntrack out of the data path for NATed flows.
            It needs einat to be enabled, because fw4's masquerade is a
            conntrack operation and cannot NAT a notracked packet.

  The IPv4 table is keyed by (proto, wan_port) on purpose: einat is a full cone
  NAT, so any external source may reach a mapped port. A 5-tuple key would turn
  the box into a symmetric NAT and break that.

  Default is enabled 0: attached nothing, changed nothing.
endef

define Package/router-acl/conffiles
/etc/config/router_acl
endef

define Build/Prepare
	$(CP) ./src $(PKG_BUILD_DIR)/
endef

# ---------------------------------------------------------------------------
# The eBPF objects.
#
# Same reasoning as router-dataplane: we deliberately do NOT use bpf.mk's
# CompileBPF (that path needs llc/llvm-dis/opt, which this build host does not
# have). One clang invocation with -target bpf -g produces exactly what libbpf
# needs. -g is mandatory for BTF.
#
# The same source is compiled twice so each object carries exactly one program
# in section "classifier", which is what tc(8) expects. Both define the same
# maps; LIBBPF_PIN_BY_NAME makes the second load reuse the first one's maps, so
# cfg/stats/flow tables are shared between the two hooks.
# ---------------------------------------------------------------------------
ACL_BPF_INCLUDES := \
	-I$(STAGING_DIR)/usr/include \
	-I$(TOOLCHAIN_DIR)/include

ACL_BPF_FLAGS := \
	-target bpf -g -O2 -Wall -Wno-unused-function -Wno-unused-variable \
	-D__KERNEL__ -D__BPF_TRACING__

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/aclctl $(PKG_BUILD_DIR)/src/aclctl.c \
		-lbpf -lelf -lz
	$(CLANG) $(ACL_BPF_FLAGS) -DACL_BUILD_INGRESS $(ACL_BPF_INCLUDES) \
		-c $(PKG_BUILD_DIR)/src/acl.bpf.c \
		-o $(PKG_BUILD_DIR)/acl_ingress.bpf.o
	$(CLANG) $(ACL_BPF_FLAGS) -DACL_BUILD_EGRESS $(ACL_BPF_INCLUDES) \
		-c $(PKG_BUILD_DIR)/src/acl.bpf.c \
		-o $(PKG_BUILD_DIR)/acl_egress.bpf.o
	@echo "--- acl_ingress.bpf.o sections ---"
	@$(TARGET_CROSS)readelf -S $(PKG_BUILD_DIR)/acl_ingress.bpf.o | \
		grep -E 'BTF|classifier|\.maps' || true
	@echo "--- acl_egress.bpf.o sections ---"
	@$(TARGET_CROSS)readelf -S $(PKG_BUILD_DIR)/acl_egress.bpf.o | \
		grep -E 'BTF|classifier|\.maps' || true
endef

define Package/router-acl/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/aclctl $(1)/usr/sbin/aclctl
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/acl_ingress.bpf.o $(1)/lib/bpf/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/acl_egress.bpf.o $(1)/lib/bpf/

	$(INSTALL_BIN) ./files/router_acl.init $(1)/etc/init.d/router-acl
	$(INSTALL_DATA) ./files/router-acl.sh $(1)/usr/libexec/router-acl.sh
	$(INSTALL_DATA) ./files/router_acl.config $(1)/etc/config/router_acl
	$(INSTALL_DATA) ./files/91-router-acl $(1)/etc/hotplug.d/iface/91-router-acl
endef

$(eval $(call BuildPackage,router-acl))
