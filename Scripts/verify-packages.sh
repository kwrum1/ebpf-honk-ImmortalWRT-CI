#!/bin/bash
# SPDX-License-Identifier: MIT
#
# verify-packages.sh —— 固件软件清单闸门
#
# 用法：
#   Scripts/verify-packages.sh <manifest> [reference-manifest]
#
#   在 CI 里建议放在 "Compile Firmware" 之后、"Release Firmware" 之前。
#   它做三件事：
#     1) 必备清单：本项目的基线和数据面依赖必须出现（缺一个就失败）。
#     2) 禁用清单：被裁掉的包不许以任何形式回来（=y 或 =m 都算）。
#     3) 与参考清单对比：列出新增/删除，供人工确认没有误伤。
#
#   退出码：0 = 通过；1 = 有硬性失败。
set -uo pipefail

MANIFEST="${1:?usage: verify-packages.sh <manifest> [reference-manifest]}"
REFERENCE="${2:-}"

if [ ! -f "$MANIFEST" ]; then
	echo "verify-packages: manifest not found: $MANIFEST" >&2
	exit 2
fi

# manifest 每行的形式是 "<pkg> - <version>"，取第一列
PKGS=$(awk '{print $1}' "$MANIFEST" | sort -u)

has_pkg() { printf '%s\n' "$PKGS" | grep -qx "$1"; }

# ---------------------------------------------------------------------------
# 1. 必备清单
# ---------------------------------------------------------------------------
# 说明：这里只列「缺了整个固件就不成立」的包，不做全集断言，
#       否则每次上游改依赖都要改脚本。
REQUIRED="
honk
luci-app-honk
v2ray-geoip
v2ray-geosite
dpd-fastpath
tc-bpf
bpftool-minimal
libbpf1
# einat-ebpf 是本基线的 NAT（eBPF 全锥 NAT，挂在 WAN 的 TCX 钩子上）。它是
# dpd 加速的前置条件：接管一个流会绕过 netfilter，回程能被接受靠的就是 einat
# 注入 fw4 的那条兜底 WAN→LAN accept。它不在镜像里，加速门禁会（正确地）把模式
# 降到 observe —— 但那就说明这一版镜像少了核心组件，所以在这里断言它必须在。
# 行为断言（真的挂上 TCX、自证通过）在 build/qemu-closure.sh 里做。
einat-ebpf
firewall4
fullconenat-sonic
dnsmasq-full
# smartdns 做解析、dnsmasq 留作前端（ebpf/router-dns）。断言的是「包在镜像里」，
# 行为断言（/etc/dnsmasq.conf 的内容、smartdns 的 port/auto_set_dnsmasq）在
# build/final-check3.sh 里做，因为那些是文件内容而不是包名。
router-dns
smartdns
# ebpf 性能档位（ebpf/router-tuning）。它带着「只能靠包选择做」的两条：
# kmod-tcp-bbr（BBRv1 + 自己的 /etc/sysctl.d/12-tcp-bbr.conf）与 kmod-sched
# （其 KCONFIG 含 CONFIG_NET_SCH_FQ -> sch_fq.ko，BBR 的首选 pacing qdisc）。
# 少了它们首启脚本会自己降级并记日志，但那就说明这一版固件少了
# "最简单、收益最大"的那一条。行为断言在 build/qemu-tuning-audit.sh 里做。
router-tuning
kmod-tcp-bbr
kmod-sched
# odhcpd 全量变体（含 DHCPv4）。默认的 odhcpd-ipv6only 编不过 DHCPv4，而本基线
# 要求地址分配只有一个权威：odhcpd 发 v4 + v6，dnsmasq 退成纯 DNS。
# 换包本身在 Scripts/Handles.sh 里做（DEFAULT_PACKAGES.router 是无 prompt 的），
# 这里断言结果 —— 装错变体就发不出 v4 地址。
odhcpd
kmod-sched-core
kmod-sched-bpf
# kmod-nft-queue 曾经在这里：honk 依赖它拉进来。 #23 把 honk 打包层的 NFQUEUE
# 关掉（见 docs/honk-nfqueue-trim.md）并摘掉了那条 DEPENDS，所以它应当从镜像里
# 彻底消失 —— 因此现在它待在下面的禁用清单里。查过了：镜像里没有第二个包需要它
# （homeproxy / snort3 / ua2f / etherwake-nfqueue 都不在），内核里 nft-queue 也是
# 独立的 KernelPackage，没有别的 kmod 依赖它。
kmod-veth
kmod-wireguard
wireguard-tools
luci-proto-wireguard
kmod-sched-cake
ip-full
ca-bundle
"

# ---------------------------------------------------------------------------
# 2. 禁用清单
# ---------------------------------------------------------------------------
# 每一条都要写清「为什么不能用」：
#   docker 栈      243.7 MB = 64% rootfs，家用路由不需要，且它是 iptables/libcap/
#                  libseccomp/ca-certificates/ucode-mod-socket/ttyd 的唯一来源。
#   iptables 系列  数据面走 TC/eBPF，内核 conntrack/NAT 由 nftables 接管，
#                  传统 iptables 是纯累赘（实测仅 0.1 MB，但语义上必须清干净）。
#   upnp           家用不需要。
#   ttyd/ucode-mod-socket  只被 dockerman 拖进来。
#   ca-certificates        被 dockerd 拖进来；honk 的 TLS 用 ca-bundle（两者都
#                          PROVIDE @ca-certs，互不依赖）。
#   video-support/i915-firmware-dmc/kmod-drm-i915
#                  x86 target/linux/x86/Makefile 里的
#                  `DEFAULT_PACKAGES += video-support` 是无 prompt 的 bool，
#                  .config 覆盖无效 —— 所以改用 Scripts/Handles.sh 在构建期做 sed
#                  （§13.13）。**已实测生效**：x86 清单里 video-support /
#                  i915-firmware-dmc / kmod-drm-i915 / kmod-drm 全为 0，
#                  rootfs 里 i915.ko 与 lib/firmware/i915 都不在。
#                  所以现在**可以**列为禁用项了（之前列不了：砍不掉，列了
#                  闸门会永远报错）。kmod-drm-kms-helper / kmod-cec-core 是
#                  随 video-support 一起消失的传递项，不单独断言。
#   odhcpd-ipv6only  #25 把地址分配并给了全量 odhcpd（含 DHCPv4）。它必须消失：
#                   留着它就是要么两个包抢同一批文件，要么 v4 地址没人发。
FORBIDDEN="
odhcpd-ipv6only
# #23：honk 不再需要它（NFQUEUE 关了，DEPENDS 也摘了），镜像里不该再有。
kmod-nft-queue
# flow offloading 全关之后 nft 的 flowtable 支持没有使用者；它的两个来源
# （firewall4 的 DEPENDS、include/target.mk 的 DEFAULT_PACKAGES）都摘了。
kmod-nft-offload
video-support
i915-firmware-dmc
kmod-drm-i915
kmod-drm
docker
dockerd
containerd
runc
tini
docker-compose
docker-proxy
containerd-stress
containerd-shim-runc-v2
ctr
luci-app-dockerman
luci-i18n-dockerman-zh-cn
ca-certificates
ttyd
ucode-mod-socket
luci-app-upnp
luci-i18n-upnp-zh-cn
miniupnpd
miniupnpd-nftables
iptables-nft
ip6tables-nft
xtables-nft
iptables-mod-extra
libxtables
libiptext
libiptext6
libiptext-nft
kmod-iptables
kmod-ip6tables
kmod-ipt-core
kmod-ipt-extra
kmod-ipt-nat
kmod-ipt-nat6
kmod-ipt-conntrack
kmod-ipt-physdev
kmod-nf-ipt
kmod-nf-ipt6
kmod-nf-nat6
kmod-nft-compat
kmod-br-netfilter
coremark
libcap
libcap-ng
libseccomp
kmod-fuse
ntfs-3g
libfuse
libfuse3
davfs2
"

fail=0

# 两个清单都是按空白切词的，所以里面的注释行必须自己跳过，
# 否则 "#" 和注释里的每个词都会被当成包名去查。
# 两个清单都是多行字符串，按行读而不是按空白切词：切词会把注释行拆散，
# 注释里的每个词都会变成包名去查（"#23" 那行里的 honk 会被当成必备包）。
check_list() {
	local list="$1" mode="$2" p
	while IFS= read -r p; do
		case "$p" in ''|\#*) continue ;; esac
		case "$mode" in
		require)
			if has_pkg "$p"; then
				printf '  ok    %s\n' "$p"
			else
				printf '  MISSING  %s\n' "$p"
				fail=1
			fi
			;;
		forbid)
			if has_pkg "$p"; then
				printf '  PRESENT  %s  <-- 不该出现\n' "$p"
				leak=$((leak + 1))
				fail=1
			fi
			;;
		esac
	done <<EOF
$list
EOF
}

echo "############ 1. 必备清单 ############"
leak=0
check_list "$REQUIRED" require

echo
echo "############ 2. 禁用清单 ############"
check_list "$FORBIDDEN" forbid
[ "$leak" = 0 ] && echo "  clean"

echo
echo "############ 3. 与参考清单对比 ############"
if [ -n "$REFERENCE" ] && [ -f "$REFERENCE" ]; then
	awk '{print $1}' "$REFERENCE" | sort -u > /tmp/vp.ref
	printf '%s\n' "$PKGS" > /tmp/vp.now
	echo "  reference=$(wc -l < /tmp/vp.ref)  current=$(wc -l < /tmp/vp.now)"
	echo "  --- 新增 ---"
	comm -13 /tmp/vp.ref /tmp/vp.now | sed 's/^/    + /'
	echo "  --- 消失 ---"
	comm -23 /tmp/vp.ref /tmp/vp.now | sed 's/^/    - /'
else
	echo "  （未提供参考清单，跳过）"
fi

echo
printf '总包数: %s\n' "$(printf '%s\n' "$PKGS" | wc -l)"
if [ "$fail" != 0 ]; then
	echo "verify-packages: FAILED"
	exit 1
fi
echo "verify-packages: PASSED"
