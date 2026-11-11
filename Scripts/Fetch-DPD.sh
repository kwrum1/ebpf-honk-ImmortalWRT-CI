#!/bin/sh
# Fetch the DPD dataplane sources from kwrum1/dpd-fw's `arm` branch.
#
# The firmware repository deliberately keeps no copy of dpdctl.c, dpdfwd.c or
# the helper scripts: a second copy drifts (it shipped a pre-ABI-22 dpdctl once)
# and it makes CI a source repository. dpd-fw publishes the package-shaped tree
# on `arm`; this script copies it into the two package directories before the
# build.
#
# Pin a commit with DPD_REF=<sha> (recommended for a release build); the
# default follows the arm tip. The resolved commit is printed so the workflow
# log and the provenance file can record it.
set -eu

REF="${DPD_REF:-arm}"
REPO="${DPD_REPO:-https://github.com/kwrum1/dpd-fw.git}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git clone --quiet --depth 1 --branch "$REF" "$REPO" "$TMP/dpd"
REV=$(git -C "$TMP/dpd" rev-parse HEAD)

for pkg in router-dataplane dpdfwd; do
	rm -rf "$ROOT/ebpf/$pkg/src" "$ROOT/ebpf/$pkg/files"
	mkdir -p "$ROOT/ebpf/$pkg"
	cp -a "$TMP/dpd/packaging/$pkg/src" "$ROOT/ebpf/$pkg/"
	cp -a "$TMP/dpd/packaging/$pkg/files" "$ROOT/ebpf/$pkg/"
done

echo "fetch-dpd: $REPO $REF @ $REV"
