#!/bin/sh
# SPDX-License-Identifier: MIT
#
# apply-makefile.sh -- turn the *upstream* honk Makefile into the x86/RK
# variant that uses the locally built p1 core. Run after Packages.sh has
# cloned kenzok8/openwrt-honk and copied package/honk into the build tree.
#
# Only x86/ROCKCHIP call this. IPQ/MTK keep the stock upstream Makefile (and
# the stock core assets) untouched.
#
# Every anchor is checked; an upstream rename fails the build here instead of
# silently shipping an unpatched core. No git fork, no merge conflicts.
set -eu

MK=${1:-./package/honk/Makefile}
[ -f "$MK" ] || { echo "honk: $MK not found" >&2; exit 1; }

# The p1 patch (direct-classified flows back to the classic TC chain) is
# written against this commit. Bump only together with the patch; the
# HONK-CORE workflow fails loudly when the anchors drift.
CORE=64848881b7304e250e7a25422f4f1d86a5975eca

grep -q '^CORE_COMMIT:=' "$MK" || {
	echo "honk: CORE_COMMIT anchor missing in $MK" >&2
	exit 1
}
sed -i "s|^CORE_COMMIT:=.*|CORE_COMMIT:=$CORE|" "$MK"

grep -q '^HONK_PATCH_REV:=' "$MK" ||
	sed -i "/^CORE_COMMIT:=/a HONK_PATCH_REV:=p1" "$MK"

grep -q '^HONK_SOURCE_TAG?=' "$MK" || {
	echo "honk: HONK_SOURCE_TAG anchor missing" >&2
	exit 1
}
sed -i 's|^HONK_SOURCE_TAG?=.*|HONK_SOURCE_TAG?=core-p1|' "$MK"
grep -q '^HONK_SOURCE_URL?=' "$MK" || {
	echo "honk: HONK_SOURCE_URL anchor missing" >&2
	exit 1
}
sed -i 's|^HONK_SOURCE_URL?=.*|HONK_SOURCE_URL?=https://github.com/kwrum1/ebpf-honk-ImmortalWRT-CI/releases/download/$(HONK_SOURCE_TAG)|' "$MK"

for pair in X86_64:x86_64 AARCH64:aarch64 ARMV7:armv7; do
	var=${pair%%:*}
	arch=${pair##*:}
	grep -q "^HONK_ASSET_$var?=" "$MK" || {
		echo "honk: HONK_ASSET_$var anchor missing" >&2
		exit 1
	}
	sed -i "s|^HONK_ASSET_$var?=.*|HONK_ASSET_$var?=honk-core-\$(CORE_COMMIT)-\$(HONK_PATCH_REV)-$arch.tar.gz|" "$MK"
	grep -q "^HONK_HASH_$var?=" "$MK" || {
		echo "honk: HONK_HASH_$var anchor missing" >&2
		exit 1
	}
	# The real hashes come from honk/generated-stage.mk, fetched per build.
	sed -i "s|^HONK_HASH_$var?=.*|HONK_HASH_$var?=SKIP|" "$MK"
done

# The p1 core needs BTF (the eBPF object embeds it); the x86/RK kernel config
# enables CONFIG_KERNEL_DEBUG_INFO_BTF.
if ! grep -q '^[[:space:]]*DEPENDS:=.*@KERNEL_DEBUG_INFO_BTF' "$MK"; then
	sed -i 's|^\([[:space:]]*DEPENDS:=.*\)$|\1 +@KERNEL_DEBUG_INFO_BTF|' "$MK"
fi
grep -q '^[[:space:]]*DEPENDS:=.*@KERNEL_DEBUG_INFO_BTF' "$MK" || {
	echo "honk: could not add the BTF dependency" >&2
	exit 1
}

# Marker read by dpd's gate: this core hands direct flows back as UNSPEC.
if ! grep -q 'files/direct-unspec' "$MK"; then
	sed -i 's|^\(\t\$(INSTALL_BIN) \$(CURDIR)/files/control.sh.*\)$|\t$(INSTALL_DATA) $(CURDIR)/files/direct-unspec $(1)/usr/share/honk/direct-unspec\n\1|' "$MK"
fi
grep -q 'files/direct-unspec' "$MK" || {
	echo "honk: could not add the direct-unspec install line" >&2
	exit 1
}

echo "honk: patched $MK (core $CORE, patch rev p1, core-p1 assets)"
