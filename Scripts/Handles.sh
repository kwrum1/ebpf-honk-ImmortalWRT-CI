#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 kwrum1

PKG_PATH="$GITHUB_WORKSPACE/wrt/package/"

#预置HomeProxy数据
if [ -d *"homeproxy"* ]; then
	echo " "

	HP_RULE="surge"
	HP_PATH="homeproxy/root/etc/homeproxy"

	rm -rf ./$HP_PATH/resources/*

	git clone -q --depth=1 --single-branch --branch "release" "https://github.com/Loyalsoldier/surge-rules.git" ./$HP_RULE/
	cd ./$HP_RULE/ && RES_VER=$(git log -1 --pretty=format:'%s' | grep -o "[0-9]*")

	echo $RES_VER | tee china_ip4.ver china_ip6.ver china_list.ver gfw_list.ver
	awk -F, '/^IP-CIDR,/{print $2 > "china_ip4.txt"} /^IP-CIDR6,/{print $2 > "china_ip6.txt"}' cncidr.txt
	sed 's/^\.//g' direct.txt > china_list.txt ; sed 's/^\.//g' gfw.txt > gfw_list.txt
	mv -f ./{china_*,gfw_list}.{ver,txt} ../$HP_PATH/resources/

	cd .. && rm -rf ./$HP_RULE/

	cd $PKG_PATH && echo "homeproxy date has been updated!"
fi

#修改argon主题字体和颜色
if [ -d *"luci-theme-argon"* ]; then
	echo " " && cd ./luci-theme-argon/

	sed -i "s/primary '.*'/primary '#31a1a1'/; s/'0.2'/'0.5'/; s/'none'/'bing'/; s/'600'/'normal'/" ./luci-app-argon-config/root/etc/config/argon

	cd $PKG_PATH && echo "theme-argon has been fixed!"
fi

#修改aurora菜单式样
if [ -d *"luci-app-aurora-config"* ]; then
	echo " " && cd ./luci-app-aurora-config/

	sed -i "s/nav_type '.*'/nav_type 'dropdown'/g" $(find ./root/usr/share/aurora/ -type f -name "*.template")

	cd $PKG_PATH && echo "theme-aurora has been fixed!"
fi

#修改mini-diskmanager菜单位置
if [ -d *"luci-app-mini-diskmanager"* ]; then
	echo " " && cd ./luci-app-mini-diskmanager/

	sed -i "s/services/system/g" ./luci-app-mini-diskmanager/root/usr/share/luci/menu.d/luci-app-mini-diskmanager.json

	cd $PKG_PATH && echo "mini-diskmanager has been fixed!"
fi


# NOTE: the Tailscale and Rust hunks that used to live here were removed.
# This firmware set enables neither package (no tailscale, no tailscale
# LuCI app, and no Rust-based plugin in Config/*.txt), so the sed calls
# could never match and only added two find sweeps over the feed tree per
# build. Put them back together with the plugin if it is ever enabled.

#=============================================================================
# 以下全部是 ebpf 专属修改：只对 X86 / ROCKCHIP 生效
#=============================================================================
# IPQ / MTK 走原版逻辑（NSS + 原版 honk + 原版 config）：GPU 裁剪、flow offload、
# nft-offload、odhcpd 接管、dnsmasq ignore、honk NFQUEUE 都是 ebpf 数据面的配套，
# 不适用于它们。
if [[ "${WRT_CONFIG}" == "X86" || "${WRT_CONFIG}" == "ROCKCHIP" ]]; then

#=============================================================================
# 裁剪 x86 的 GPU / DRM 栈
#=============================================================================
# 背景（实测，见 工作计划.md §13.1）：
#
#   target/linux/x86/Makefile 的 DEFAULT_PACKAGES 和
#   target/linux/x86/image/*.mk 的 DEVICE_PACKAGES 会生成一批 **无 prompt** 的
#   CONFIG_DEFAULT_<pkg> / CONFIG_MODULE_DEFAULT_<pkg> 符号。因为无 prompt，
#   `make defconfig` 每次都会重算它们，.config 里的覆盖（包括
#   `CONFIG_PACKAGE_kmod-drm-i915=n`、`# CONFIG_DEFAULT_video-support is not set`）
#   **一律无效** —— 这是试了两轮、构建完解包才发现的。
#
#   后果（实测体积，x86_64）：
#       lib/modules/6.18.55/i915.ko            6.89 MB
#       lib/firmware/i915/*                    ~0.4 MB
#       kmod-drm / kmod-drm-kms-helper / kmod-cec-core   少量
#   i915.ko 一项就占整个固件约 5%，而路由器根本不用核显。
#
#   唯一能在**不改源码树、不新开 commit** 的前提下修掉它的地方就是这里。
#   Handles.sh 本来就是 CI 的构建期源码修补钩子（上面已经在 sed tailscale / rust
#   的 Makefile），所以这条和现有做法一致：改的是构建期的临时树，不动 fork。
#
#   刻意只删这三项：
#       DEFAULT_PACKAGES 里的 video-support  -> kmod-drm* 整条链
#       DEFAULT_PACKAGES 里的 i915-firmware-dmc
#       DEVICE_PACKAGES  里的 kmod-drm-i915
#   不动 kmod-fs-vfat / 网卡驱动 / automount —— 那些是用户明确要保留的。
#   内核侧不用管：target/linux/x86/config-6.18 里没有 DRM 条目，
#   CONFIG_DRM_I915 完全由 kmod-drm-i915 的 KCONFIG 驱动，
#   包没了它自然不会编译。
#=============================================================================
# 路径必须是**绝对**路径：Handles.sh 的工作目录是 $TREE/package
# （CI 里 `cd ./wrt/package/`，本地 build.sh 也是 `cd "$TREE/package"`），
# 所以相对路径 target/linux/x86/Makefile 实际指向 $TREE/package/target/...，
# 根本不存在 —— [ -f ] 直接失败，整段裁剪静默失效。
# 实测踩过：镜像里 i915.ko 消失只是因为当时手工改过活树，Handles.sh 这一段
# 从来没生效（§13.15）。这里用 $GITHUB_WORKSPACE/wrt，和本脚本其它地方
# （PKG_PATH）保持一致。
X86_DIR="$GITHUB_WORKSPACE/wrt/target/linux/x86"
if [ ! -d "$X86_DIR" ]; then
	echo "!! 跳过 x86 DRM 裁剪：找不到 $X86_DIR（CWD=$PWD）" >&2
else
	X86_MK="$X86_DIR/Makefile"
	if [ -f "$X86_MK" ]; then
		echo " "
		# 1) 从 DEFAULT_PACKAGES 的续行列表里摘掉 i915-firmware-dmc
		sed -i -E 's/[[:space:]]*i915-firmware-dmc//' "$X86_MK"
		# 2) 整行删掉 DEFAULT_PACKAGES += video-support
		sed -i -E '/^[[:space:]]*DEFAULT_PACKAGES[[:space:]]*\+=[[:space:]]*video-support[[:space:]]*$/d' "$X86_MK"
		echo "x86 Makefile: video-support / i915-firmware-dmc removed"
		grep -n 'DEFAULT_PACKAGES' "$X86_MK" | sed 's/^/  /'
	fi

	for MK in "$X86_DIR/image/64.mk" "$X86_DIR/image/generic.mk" "$X86_DIR/image/legacy.mk"; do
		if [ -f "$MK" ]; then
			# 3) 从 DEVICE_PACKAGES 里摘掉 kmod-drm-i915（可能在行尾，也可能独占一行）
			#    若它独占一行，删完会留下一行空行 —— 在 make 里空行只是结束续行列表，
			#    是无害的，所以这里**不做**空行清理（那会误删文件里所有空行）。
			sed -i -E 's/[[:space:]]*kmod-drm-i915//' "$MK"
			echo "$MK: kmod-drm-i915 removed"
			grep -n 'DEVICE_PACKAGES' -A6 "$MK" | sed 's/^/  /'
		fi
	done
	echo "x86 GPU/DRM stack trimmed (~7 MB)"
fi

#=============================================================================
# firewall4 的默认配置：关掉 flow offloading（einat/dpd 的前提）
#=============================================================================
# 背景（实测，见 工作计划.md §13.16）：
#
#   上游 ImmortalWrt 打了
#       package/network/config/firewall4/patches/002-default-enable-fullcone.patch
#   它给默认的 /etc/config/firewall 加了
#       option flow_offloading     1
#       option flow_offloading_hw  1
#       option fullcone            1
#   也就是**镜像开箱就是软件/硬件 offload 打开**——这和本项目的前提相反：
#   计划里软件 flowtable 是明确 rejected 的，einat 官方文档也要求先关掉一切
#   加速（offload 的快速路径会绕过 TC，正是我们的数据面所在）。
#
#   为什么改 patch 而不是改 /etc/config/firewall：
#     红线是「ebpf 不许动 /etc/config/{firewall,network,dhcp}」——指运行期
#     不许覆盖。这里改的是**构建期生成默认配置的补丁**，和 DRM 裁剪同一类做法。
#   为什么不能只在 .config 里关：
#     flow_offloading 是 uci 的**配置项**，不是包选择，.config 管不到。
#   为什么是「1 改成 0」而不是删行：
#     删行会让补丁的 hunk 行数对不上（@@ -5,6 +5,9 @@），patch 直接报错。
#     改值不动行数，补丁照旧干净应用。
F4_PATCH="$GITHUB_WORKSPACE/wrt/package/network/config/firewall4/patches/002-default-enable-fullcone.patch"
if [ -f "$F4_PATCH" ]; then
	# 只把这两行的**值**从 1 改成 0，行数一点不动（补丁才能照旧干净应用）。
	# 注意不能写成 s#...#\10#：`\10` 会被当成第 10 个反向引用，
	# 而且 `+` 不在捕获组里会被吃掉 —— 实测就是这么把补丁改坏的
	# （`+` 没了，patch 报 "malformed patch at line 14"）。
	# 所以用「先按整行定位、再只替换行尾的 1」这种不含歧义的写法。
	sed -i -E '/^\+[[:space:]]*option[[:space:]]+flow_offloading(_hw)?[[:space:]]+1$/ s/1$/0/' "$F4_PATCH"
	echo "firewall4 默认配置: flow_offloading / flow_offloading_hw -> 0"
	grep -n 'flow_offloading' "$F4_PATCH" | sed 's/^/  /'
	# 兜底：如果还留着 1，就是上游换了写法、这条 sed 没生效。静默跳过是
	# 最坏的结果（offload 开着，einat/dpd 的数据面被绕过），所以必须报出来。
	if grep -qE '^\+[[:space:]]*option[[:space:]]+flow_offloading(_hw)?[[:space:]]+1$' "$F4_PATCH"; then
		echo "!! flow_offloading 仍然是 1：这条 sed 没生效，offload 仍会开着" >&2
	fi
	# 改了补丁就必须让 firewall4 重新 prepare：OpenWrt 的 prepared stamp 不会
	# 因为补丁文件内容变了而失效（和 §13.15 里 base-files 那个坑同一类）。
	# CI 上是全新目录所以无所谓，但增量构建会继续用旧的 prepared 源码 ——
	# 结果就是「补丁改了，镜像里还是 1」。删掉构建目录的代价只是重编一个小包。
	# 注意必须用绝对路径：Handles.sh 的 CWD 是 $TREE/package。
	for d in "$GITHUB_WORKSPACE/wrt"/build_dir/target-*/firewall4-*; do
		[ -d "$d" ] || continue
		rm -rf "$d"
		echo "firewall4 构建目录已删（强制按新补丁重新 prepare）: $(basename "$d")"
	done
else
	echo "!! 找不到 $F4_PATCH（上游可能改了补丁名）—— flow offloading 仍然是开着的" >&2
fi

#=============================================================================
# 连带瘦身：既然 flow offloading 关了，kmod-nft-offload 就没有任何使用者了
#=============================================================================
# 它是 nftables 的 flowtable（软件 + 硬件 offload）支持。本项目的立场是明确的：
# 内核软件 flowtable 这条路已经否掉（见工作计划 §13.13），硬件 offload 在 x86/ARM
# 家用场景也没有能用的东西，而 fw4 的默认配置刚刚被上面那条 sed 把
# flow_offloading / flow_offloading_hw 都改成了 0 —— 这个模块装进去永远不会被用到。
#
# 但它有两个来源，必须**两处都删**，只删一个没用：
#   1) firewall4 的 DEPENDS 里写死的 `+kmod-nft-offload`（包的 DEPENDS 胜过 .config）
#   2) include/target.mk 的 DEFAULT_PACKAGES 里也列了它（无 prompt 的 CONFIG_DEFAULT_*）
# 删完还要在 Config/GENERAL.txt 里显式写 `# CONFIG_PACKAGE_kmod-nft-offload is not set`，
# 否则增量构建会沿用 .config 里的陈旧 =y。
#
# 查过了：全树只有 firewall4 一个包 DEPENDS 它（feeds 里没有），fullconenat-sonic
# 要的是 +kmod-nft-nat，跟它无关。
TMK="$GITHUB_WORKSPACE/wrt/include/target.mk"
if [ -f "$TMK" ]; then
	if grep -qE '^[[:space:]]*kmod-nft-offload([[:space:]]|\\)*$' "$TMK"; then
		sed -i -E '/^[[:space:]]*kmod-nft-offload([[:space:]]|\\)*$/d' "$TMK"
		echo "include/target.mk: DEFAULT_PACKAGES 去掉 kmod-nft-offload"
	else
		echo "  注意：include/target.mk 里已经没有 kmod-nft-offload（重复执行或上游已改）"
	fi
fi
# 必须用绝对路径：Handles.sh 的 CWD 是 $TREE/package
FW4_MK=$(find "$GITHUB_WORKSPACE/wrt/package" -maxdepth 4 -type d -name firewall4 2>/dev/null | head -1)
if [ -n "$FW4_MK" ] && [ -f "$FW4_MK/Makefile" ]; then
	if grep -q '+kmod-nft-offload' "$FW4_MK/Makefile"; then
		sed -i 's/+kmod-nft-fib +kmod-nft-offload/+kmod-nft-fib/' "$FW4_MK/Makefile"
		echo "firewall4/Makefile: DEPENDS 去掉 +kmod-nft-offload"
		grep -n 'kmod-nft-fib\|kmod-nft-offload' "$FW4_MK/Makefile" | sed 's/^/  /'
	fi
	if grep -q '+kmod-nft-offload' "$FW4_MK/Makefile"; then
		echo "!! firewall4 的 DEPENDS 里还留着 +kmod-nft-offload —— 镜像里还会有这个模块" >&2
	fi
else
	echo "!! 没找到 firewall4 的 Makefile —— kmod-nft-offload 的依赖没摘掉" >&2
fi

#=============================================================================
# #25：odhcpd 全接管 DHCP（v4 + v6）
#=============================================================================
# 目标：LAN 上的地址分配只有一个权威 —— odhcpd 同时负责 DHCPv4、DHCPv6 和 RA，
# dnsmasq 退成纯 DNS。三处改动，全部是**构建期生成默认配置**，不碰运行期的
# /etc/config/{dhcp,network,firewall}。
#
# 1) 换包。默认是 odhcpd-ipv6only（编不过 DHCPv4 的变体），它在
#    include/target.mk 的 DEFAULT_PACKAGES.router 里，而且是**无 prompt** 的
#    CONFIG_DEFAULT_* —— .config 里写 =n 无效（同 §13.1 那个坑），只能改这里。
#    odhcpd 的 Makefile 里 `PROVIDES:=odhcpd-ipv6only`，全量变体就是它。
#
# 2) 让 dnsmasq 别再发 v4 地址。dhcp.conf 里给 `config dhcp lan` 加
#    `option ignore 1`。实测 dnsmasq.init:541：
#        append_bool "$cfg" ignore "--no-dhcp-interface=$ifname" && {
#            dhcp_this_host_add ... ; return 0
#        }
#    也就是 ignore=1 会把整个接口的 DHCP/RA 段**直接 return 掉**，DNS 部分
#    完全不受影响（它只处理 /etc/config/dhcp 的 dhcp 段）。
#
# 3) 让 odhcpd 真的去发 v4 地址。odhcpd 的 config.c:1282 是
#        iface->dhcpv4 = config.main_dhcpv4 ? mode : MODE_DISABLED;
#    而 odhcpd.defaults（首次启动的 /etc/uci-defaults/15_odhcpd）把
#        maindhcp=$ODHCPDONLY     # 只要 /usr/sbin/dnsmasq 存在就是 0
#        dhcpv6=disabled          # 写死的，永远不开 DHCPv6
#    所以两行都要改：maindhcp 固定 1，dhcpv6 用 $V6MODE（v6 可用时 server）。
#
# 注意 odhcpd **不读** uci 的 ignore：config.c 里 iface->ignore 只是个内部派生
# 标志（初值 true，配置了 master/dhcpv4/dhcpv6/ra 任一就置 false）。所以同一个
# `config dhcp lan` 段可以同时「对 dnsmasq 是 ignore」和「对 odhcpd 是 server」。
ODHCPD_TAKEOVER=""
TMK="$GITHUB_WORKSPACE/wrt/include/target.mk"
if [ -f "$TMK" ]; then
	if grep -qE '^[[:space:]]*odhcpd-ipv6only([[:space:]]|\\)*$' "$TMK"; then
		sed -i -E 's/^([[:space:]]*)odhcpd-ipv6only([[:space:]]*\\?)$/\1odhcpd\2/' "$TMK"
		echo "include/target.mk: DEFAULT_PACKAGES 的 odhcpd-ipv6only -> odhcpd"
		grep -n 'odhcpd' "$TMK" | sed 's/^/  /'
	elif grep -qE '^[[:space:]]*odhcpd([[:space:]]|\\)*$' "$TMK"; then
		# 已经换过了（本地增量构建会重复跑这个脚本）—— 不是错误
		echo "include/target.mk: DEFAULT_PACKAGES 已经是 odhcpd（跳过）"
	else
		echo "!! include/target.mk 里既没有 odhcpd-ipv6only 也没有 odhcpd —— 上游改过默认包列表了" >&2
	fi
else
	echo "!! 找不到 $TMK" >&2
fi

DS_DHCP="$GITHUB_WORKSPACE/wrt/package/network/services/dnsmasq/files/dhcp.conf"
# 取某个 config 段的正文。**必须按段取**：上游的 dhcp.conf 里 `config dhcp wan`
# 本来就有一条 `option ignore 1`，如果在整个文件里 grep，就会误判「已经加过了」
# 而跳过插入 —— 那 dnsmasq 会继续在 LAN 上发 v4 地址，静默失效。
dhcp_section() {
	awk -v sec="$2" '
		/^config[[:space:]]+dhcp[[:space:]]+/ { f = ($3 == sec); if (f) print; next }
		/^config[[:space:]]/ { f = 0 }
		/^[[:space:]]*$/ { f = 0 }
		f { print }
	' "$1"
}
if [ -f "$DS_DHCP" ]; then
	TAB=$(printf '\t')
	if grep -qE "^config[[:space:]]+dhcp[[:space:]]+lan\$" "$DS_DHCP"; then
		# 幂等：lan 段里已经有了就别再加一遍（重复的 option 名 uci 能读，
		# 但 uci commit 写回时会打架）
		if dhcp_section "$DS_DHCP" lan | grep -qE '^[[:space:]]*option[[:space:]]+ignore[[:space:]]+1[[:space:]]*$'; then
			echo "dnsmasq/files/dhcp.conf: dhcp lan 段已经有 option ignore 1（跳过）"
		else
			sed -i -E "/^config[[:space:]]+dhcp[[:space:]]+lan\$/a\\${TAB}option ignore${TAB}1" "$DS_DHCP"
			echo "dnsmasq/files/dhcp.conf: config dhcp lan 加上 option ignore 1"
		fi
	fi
	# 出厂值也顺手改成 odhcpd 想要的 server；首次启动 15_odhcpd 还会再写一遍
	sed -i -E '/^[[:space:]]*option[[:space:]]+dhcpv6[[:space:]]+disabled[[:space:]]*$/ s/disabled/server/' "$DS_DHCP"
	if ! dhcp_section "$DS_DHCP" lan | grep -qE '^[[:space:]]*option[[:space:]]+ignore[[:space:]]+1[[:space:]]*$'; then
		echo "!! dhcp lan 段里没有 ignore 1 —— dnsmasq 会继续在 LAN 上发 v4 地址" >&2
	fi
	if ! dhcp_section "$DS_DHCP" lan | grep -qE '^[[:space:]]*option[[:space:]]+dhcpv6[[:space:]]+server[[:space:]]*$'; then
		echo "!! dhcp lan 段的 dhcpv6 不是 server —— odhcpd 的 v6 会缺 instruction" >&2
	fi
	dhcp_section "$DS_DHCP" lan | sed 's/^/  /'
else
	echo "!! 找不到 $DS_DHCP" >&2
fi

OD_DEF="$GITHUB_WORKSPACE/wrt/package/network/services/odhcpd/files/odhcpd.defaults"
if [ -f "$OD_DEF" ]; then
	sed -i -E 's/^([[:space:]]*set[[:space:]]+dhcp\.odhcpd\.maindhcp=).*$/\11/' "$OD_DEF"
	sed -i -E 's/^([[:space:]]*set[[:space:]]+dhcp\.lan\.dhcpv6=)disabled[[:space:]]*$/\1$V6MODE/' "$OD_DEF"
	if grep -qE '^[[:space:]]*set[[:space:]]+dhcp\.odhcpd\.maindhcp=1[[:space:]]*$' "$OD_DEF" \
	   && grep -qE '^[[:space:]]*set[[:space:]]+dhcp\.lan\.dhcpv6=\$V6MODE' "$OD_DEF"; then
		echo "odhcpd/files/odhcpd.defaults: maindhcp=1, dhcpv6=\$V6MODE"
	else
		echo "!! odhcpd.defaults 没改干净 —— odhcpd 不会接 v4" >&2
	fi
	grep -nE 'maindhcp|dhcpv6|dhcpv4|ra=' "$OD_DEF" | sed 's/^/  /'
else
	echo "!! 找不到 $OD_DEF" >&2
fi

# 改了 dnsmasq / odhcpd 的 files/ 就必须让这两个包重新 prepare —— OpenWrt 的
# package stamp 只看包 Makefile，files/ 的内容变了它一无所知（和 base-files 那个
# 坑完全一样，见 §13.15）。CI 上是全新目录所以无所谓，但**增量构建会继续用旧的
# 副本**，结果就是「源码改了、镜像里还是 dnsmasq 在发地址」——静默失效，而且
# 这种失效在清单上看不出来。删掉重编的代价只是两个小包。
# 必须用绝对路径：Handles.sh 的 CWD 是 $TREE/package。
for d in "$GITHUB_WORKSPACE/wrt"/build_dir/target-*/dnsmasq-* \
         "$GITHUB_WORKSPACE/wrt"/build_dir/target-*/odhcpd-*; do
	[ -d "$d" ] || continue
	rm -rf "$d"
	echo "  构建目录已删（files/ 改动不会让 stamp 失效）: $(basename "$d")"
done

# dnsmasq 还要认识 /tmp/hosts（odhcpd 把 v4 租约的 hostname 写在那里）。
# 没有 --addn-hosts 的话局域网主机名就解析不到了。
DS_INIT="$GITHUB_WORKSPACE/wrt/package/network/services/dnsmasq/files/dnsmasq.init"
if [ -f "$DS_INIT" ]; then
	if grep -qE 'addn-hosts|hostsdir' "$DS_INIT"; then
		echo "dnsmasq.init: 已经会读 /tmp/hosts（$(grep -cE 'addn-hosts|hostsdir' "$DS_INIT") 处）"
	else
		echo "!! dnsmasq.init 里没有 addn-hosts/hostsdir —— odhcpd 写的 hostname 不会进 DNS" >&2
	fi
fi

#=============================================================================
# #23：honk 的 NFQUEUE 裁剪（纯打包层，不动 Rust）
#=============================================================================
# 见 docs/honk-nfqueue-trim.md。honk 的打包层**主动强制** nfqueue_enable: true：
# 运行期写配置时硬编码 true，健康检查还**要求**它是 true，否则判定不健康并把
# 配置重写回 true —— 所以只改 /etc/honk/system.dae 是没用的，下次自检就冲回去。
#
# 裁剪的理由是数据面冲突：honk 的 NFQUEUE 路径独占 netfilter queue 320、建
# inet honk_nfqueue 链、在 conntrack/NAT **之前**扣住 LAN 转发的首包；而本项目的
# NAT 是 einat 在 TC egress 做的，业务流还要 notrack。两者对「谁先看到首包」
# 直接竞争。
#
# 全部 5 个 `true` 站点一次改掉（`false` 的那两处是 shadow/mock 配置，本来就对，
# 一起替换也只是幂等 —— 但下面的 sed 只匹配 true，所以那两处根本不动）。
# 再摘掉 Makefile 里的 +kmod-nft-queue 依赖。
HONK_DIR="$GITHUB_WORKSPACE/wrt/package/honk"
if [ -d "$HONK_DIR" ]; then
	HONK_HITS=0
	for f in "$HONK_DIR/files/system.dae" "$HONK_DIR/files/control.sh" "$HONK_DIR/files/maintenance.sh"; do
		[ -f "$f" ] || continue
		n=$(grep -c 'nfqueue_enable: true' "$f" 2>/dev/null || echo 0)
		[ "$n" = "0" ] && continue
		sed -i 's/nfqueue_enable: true/nfqueue_enable: false/g' "$f"
		HONK_HITS=$((HONK_HITS + n))
		echo "  ${f##*/}: $n 处 true -> false"
	done
	echo "honk NFQUEUE: 共改 $HONK_HITS 处（预期 5）"
	if [ "$HONK_HITS" != "5" ]; then
		echo "!! 改到的处数不是 5 —— 上游可能改了写法，逐处核对 docs/honk-nfqueue-trim.md" >&2
	fi
	# 剩下的必须全是 false，且不能还有 true 漏网
	echo "  剩余 true 计数: $(grep -rc 'nfqueue_enable: true' "$HONK_DIR/files/" 2>/dev/null | grep -v ':0$' | wc -l)"
	if [ -f "$HONK_DIR/Makefile" ]; then
		if grep -q ' +kmod-nft-queue' "$HONK_DIR/Makefile"; then
			sed -i 's/ +kmod-nft-queue//' "$HONK_DIR/Makefile"
			echo "  honk/Makefile: +kmod-nft-queue 已摘掉"
		fi
		grep -q 'kmod-nft-queue' "$HONK_DIR/Makefile" \
			&& echo "!! Makefile 里还有 kmod-nft-queue" >&2
	fi
	# nft_queue / nfnetlink_queue 这两个模块也不需要了（nfqueue_enable 全是
	# false，数据面根本不建 nfqueue）。但 honk 的 preflight 会
	# `module_available nft_queue nfnetlink_queue`，模块不在就拒绝启动 ——
	# 所以把这两个名字从它自己的两处模块清单里摘掉，让 preflight 与实际
	# 内核配置一致。
	#
	# 实测依据（QEMU x86_64，2026-10-17，qemu-honk5）：摘掉之后
	#   * preflight 通过（清单只剩 sch_ingress cls_bpf veth）
	#   * honk-core 正常启动：TCX 挂到 br-lan/eth0/eth1 + cgroup + dae0 +
	#     daens 里的 sk_lookup，native API 就绪
	#   * 真实 VLESS/REALITY 节点代理成功：LAN 客户端访问被规则代理的域名，
	#     出口 IP 从本机公网 113.194.4.185 变成节点 37.123.192.246
	# 也就是说 nfqueue 那两个模块在数据面确实没被用到。见
	# docs/honk-nfqueue-trim.md。
	if [ -f "$HONK_DIR/files/control.sh" ]; then
		M=$(grep -c 'nft_queue nfnetlink_queue' "$HONK_DIR/files/control.sh" 2>/dev/null)
		[ -n "$M" ] || M=0
		if [ "$M" -gt 0 ]; then
			sed -i 's/ nft_queue nfnetlink_queue//g' "$HONK_DIR/files/control.sh"
			echo "  honk/control.sh: 从 $M 处 preflight 模块清单里摘掉 nft_queue nfnetlink_queue"
		fi
		if [ "$M" != "2" ]; then
			echo "!! 摘掉的处数是 $M，预期 2 —— 上游可能改了清单写法，逐处核对" >&2
		fi
		grep -q 'nft_queue' "$HONK_DIR/files/control.sh" \
			&& echo "!! control.sh 里还有 nft_queue 残留" >&2
	fi
	# 改了 files/ 不会让 OpenWrt 的 prepared stamp 失效（同 base-files 那个坑），
	# 增量构建必须把 honk 的构建目录删掉才会重新 prepare。
	for d in "$GITHUB_WORKSPACE/wrt"/build_dir/target-*/honk-*; do
		[ -d "$d" ] || continue
		rm -rf "$d"
		echo "  honk 构建目录已删: $(basename "$d")"
	done
else
	echo "!! 找不到 $HONK_DIR（Packages.sh 应该先把它 clone 下来）" >&2
fi

fi  # WRT_CONFIG = X86 / ROCKCHIP

echo " "

#=============================================================================
# offload guard: IPQ/MTK must keep hardware flow offload
#=============================================================================
# The X86/ROCKCHIP block above turns fw4's flow_offloading off on purpose (the
# eBPF datapath has to see every packet). Every other target keeps it on --
# that is its acceleration path (PPE / NSS front end, firewall4 default patch
# 002 enables flow_offloading + flow_offloading_hw + fullcone).
#
# A future edit to the shared scripts could silently flip that for the QCA/MTK
# images too, and nothing would fail: the image builds, it is just slower. So
# assert it here and make the build log say which way it went.
if [[ "${WRT_CONFIG}" != "X86" && "${WRT_CONFIG}" != "ROCKCHIP" ]]; then
	F4P="$GITHUB_WORKSPACE/wrt/package/network/config/firewall4/patches/002-default-enable-fullcone.patch"
	if [ -f "$F4P" ]; then
		v_sw=$(grep -oE 'option[[:space:]]+flow_offloading[[:space:]]+[01]' "$F4P" 2>/dev/null | head -1 | awk '{print $NF}')
		v_hw=$(grep -oE 'option[[:space:]]+flow_offloading_hw[[:space:]]+[01]' "$F4P" 2>/dev/null | head -1 | awk '{print $NF}')
		# owrt ships 1 (kernel flowtable), main ships 0 (qca-nss/ECM does the
		# offload there). Both are upstream's choice; only a *missing* line is a
		# problem, because that is what the IPQ guard is meant to protect.
		if [ -n "$v_sw" ] && [ -n "$v_hw" ]; then
			echo "offload: $WRT_CONFIG keeps firewall4 flow_offloading=$v_sw flow_offloading_hw=$v_hw"
		else
			echo "!! offload: $WRT_CONFIG lost the flow_offloading lines in the firewall4 patch" >&2
		fi
	else
		echo "!! offload: firewall4 patch not found; cannot confirm offload defaults for $WRT_CONFIG" >&2
	fi
fi
