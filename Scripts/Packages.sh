#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 VIKINGYFY
#
# =============================================================================
#  第三方包引入 —— 单基线裁剪版
# =============================================================================
#  原脚本从 ~25 个第三方仓库拉插件。实测（对照 ref-X86.manifest / ref-ROCKCHIP.manifest）
#  真正进入固件的只有 5 个：
#
#      aurora           -> luci-theme-aurora / luci-i18n-aurora-*      （默认主题）
#      aurora-config    -> luci-app-aurora-config                       （主题配置页）
#      honk             -> honk / luci-app-honk / doona                 （透明代理，本项目的核心）
#      v2ray-geodata    -> v2ray-geoip / v2ray-geosite                  （honk 需要的地域数据）
#      partexp          -> luci-app-partexp                             （分区扩容，x86 装机要用）
#
#  其余 homeproxy/passwall/openclash/momo/nikki/tailscale/ddns-go/diskman/
#  easytier/mosdns/netspeedtest/netwizard/openlist/qbittorrent/qmodem/
#  quickfile/timecontrol/viking/vnt/argon/kucat 在基线的软件清单里**全部不存在**，
#  删除后不影响任何已选中的包。保留它们只会让每次 CI 多克隆十几 MB 的垃圾、
#  并在 make defconfig 时引入无用的 Kconfig 符号。
#
#  如果以后要重新引入某个插件，把对应的 UPDATE_PACKAGE 行加回来，并确认它在
#  Scripts/verify-packages.sh 的允许清单里。
# =============================================================================

#安装和更新软件包
UPDATE_PACKAGE() {
	local PKG_NAME=$1
	local PKG_REPO=$2
	local PKG_BRANCH=$3
	local PKG_SPECIAL=$4
	local PKG_LIST=("$PKG_NAME" $5)  # 第5个参数为自定义名称列表
	local REPO_NAME=${PKG_REPO#*/}

	echo " "

	# 删除本地可能存在的不同名称的软件包
	for NAME in "${PKG_LIST[@]}"; do
		# 查找匹配的目录
		echo "Search directory: $NAME"
		local FOUND_DIRS=$(find ../feeds/luci/ ../feeds/packages/ -maxdepth 3 -type d -iname "*$NAME*" 2>/dev/null)

		# 删除找到的目录
		if [ -n "$FOUND_DIRS" ]; then
			while read -r DIR; do
				rm -rf "$DIR"
				echo "Delete directory: $DIR"
			done <<< "$FOUND_DIRS"
		else
			echo "Not fonud directory: $NAME"
		fi
	done

	# 克隆 GitHub 仓库
	git clone --depth=1 --single-branch --branch $PKG_BRANCH "https://github.com/$PKG_REPO.git"

	# 处理克隆的仓库
	if [[ "$PKG_SPECIAL" == "pkg" ]]; then
		find ./$REPO_NAME/*/ -maxdepth 3 -type d -iname "*$PKG_NAME*" -prune -exec cp -rf {} ./ \;
		rm -rf ./$REPO_NAME/
	elif [[ "$PKG_SPECIAL" == "name" ]]; then
		mv -f $REPO_NAME $PKG_NAME
	fi
}

# 调用示例
# UPDATE_PACKAGE "OpenAppFilter" "destan19/OpenAppFilter" "master" "" "custom_name1 custom_name2"
# UPDATE_PACKAGE "open-app-filter" "destan19/OpenAppFilter" "master" "" "luci-app-appfilter oaf" 这样会把原有的open-app-filter，luci-app-appfilter，oaf相关组件删除，不会出现coremark错误。

# UPDATE_PACKAGE "包名" "项目地址" "项目分支" "pkg/name，可选，pkg为从大杂烩中单独提取包名插件；name为重命名为包名"

# -----------------------------------------------------------------------------
# SFE 基准变体：shortcut-fe + fast-classifier
#
# immortalwrt/obsolete 里也有这两个包，但那个仓库冻结在 2021-11（内核 5.x），
# 无法在本树的 kernel 6.18 上编译。coolsnowwolf/lede 一直在跟内核更新同名包，
# 所以从那里稀疏拉取（只取 package/qca/shortcut-fe，不拉整个仓库）。
# 这两个包与 mydist/einat 无关，仅用于三变体对比。
# -----------------------------------------------------------------------------
if [[ "${WRT_CONFIG}" == *"-SFE"* ]]; then
	rm -rf ./sfe-src ./shortcut-fe ./fast-classifier
	git clone --depth=1 --filter=blob:none --sparse \
		https://github.com/coolsnowwolf/lede.git sfe-src
	( cd sfe-src && git sparse-checkout set package/qca/shortcut-fe )
	cp -rf ./sfe-src/package/qca/shortcut-fe/shortcut-fe ./
	cp -rf ./sfe-src/package/qca/shortcut-fe/fast-classifier ./
	rm -rf ./sfe-src
	# shortcut-fe 还需要 Lean 的内核补丁：给 sk_buff 加 fast_forwarded 位、
	# 给 conntrack 加 chain notifier、bridge 统计钩子。缺了它 sfe_ipv4.c 会报
	# "'struct sk_buff' has no member named 'fast_forwarded'"。
	for D in ../target/linux/generic/hack-6.18 ../target/linux/generic/hack-6.12; do
		if [ -d "$D" ]; then
			curl -fsSL -o "$D/953-net-patch-linux-kernel-to-support-shortcut-fe.patch" \
				"https://raw.githubusercontent.com/coolsnowwolf/lede/master/target/linux/generic/hack-6.18/953-net-patch-linux-kernel-to-support-shortcut-fe.patch" \
				&& echo "SFE: kernel patch -> $D"
		fi
	done
	echo "SFE: shortcut-fe + fast-classifier <- coolsnowwolf/lede"
fi

# 默认主题：aurora（Settings.sh 里的 WRT_THEME=aurora 要与之对应）
UPDATE_PACKAGE "aurora" "eamonxg/luci-theme-aurora" "master"
UPDATE_PACKAGE "aurora-config" "eamonxg/luci-app-aurora-config" "master"

# Honk 核心 + LuCI/Doona 管理界面
# honk: X86/ROCKCHIP use the mydist branch (DNS stays in dnsmasq -> SmartDNS,
# honk resolves through 127.0.0.1:6053); IPQ and the rest keep mainline honk.
case "$WRT_CONFIG" in
	X86|ROCKCHIP) UPDATE_PACKAGE "honk" "kwrum1/openwrt-honk" "mydist" "pkg" ;;
	*)            UPDATE_PACKAGE "honk" "kwrum1/openwrt-honk" "main" "pkg" ;;
esac

# honk/ 下三个 generated-* 文件都被 .gitignore 忽略，由 openwrt-honk 的 release.yml
# 作为 asset 发布。缺任何一个都会在编译/打包阶段失败：
#   generated-stage.mk        -> HONK_HASH_* 停在 SKIP，download.pl 报错
#   generated-provenance.json -> honk 的 install 阶段 cannot stat
#   generated-doona-stage.mk  -> luci-app-honk 的 Doona 源地址/哈希
# 按 package 里的 CORE_COMMIT 找到对应 release，把三个都取下来，并把里面写死的
# kenzok8/openwrt-honk URL 改成实际的 release 目录（asset 发布在 kwrum1 这边）。
fetch_honk_stage() {
	local core rel_json base stage prov doona
	[ -d ./honk ] || return 0
	core=$(sed -n 's/^CORE_COMMIT:=//p' ./honk/Makefile 2>/dev/null | head -1)
	[ -n "$core" ] || return 0
	rel_json=$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
		"https://api.github.com/repos/kwrum1/openwrt-honk/releases?per_page=30" 2>/dev/null)
	pick() {
		printf '%s' "$rel_json" | jq -r --arg c "$core" --arg n "$1" \
			'[.[] | select(.assets != null) | select([.assets[].name] | index("honk-core-" + $c + "-x86_64.tar.gz"))][0].assets[]? | select(.name == $n) | .browser_download_url' 2>/dev/null | head -1
	}
	stage=$(pick generated-stage.mk)
	if [ -z "$stage" ] || [ "$stage" = "null" ]; then
		echo "!! honk: no generated-stage.mk for CORE_COMMIT=$core; honk will fail at download" >&2
		return 0
	fi
	base="${stage%/*}/"
	if ! curl -fsSL -o ./honk/generated-stage.mk "$stage"; then
		echo "!! honk: could not download $stage" >&2
		return 0
	fi
	sed -i "s|^PKG_SOURCE_URL:=.*|PKG_SOURCE_URL:=${base}|" ./honk/generated-stage.mk

	prov=$(pick generated-provenance.json)
	if [ -n "$prov" ] && [ "$prov" != "null" ]; then
		curl -fsSL -o ./honk/generated-provenance.json "$prov" || true
	fi

	doona=$(pick generated-doona-stage.mk)
	if [ -n "$doona" ] && [ "$doona" != "null" ] && [ -d ./luci-app-honk ]; then
		if curl -fsSL -o ./luci-app-honk/generated-doona-stage.mk "$doona"; then
			sed -i "s|^PKG_SOURCE_URL:=.*|PKG_SOURCE_URL:=${base}|" ./luci-app-honk/generated-doona-stage.mk
		fi
	fi

	echo "honk: stage assets <- ${base}"
	echo "honk: PKG_SOURCE_URL=$(sed -n 's/^PKG_SOURCE_URL:=//p' ./honk/generated-stage.mk | head -1)"
	# 早失败：HEAD 一下 x86_64 资产，省得编译 1.5 小时才发现 404。
	_probe="${base}$(sed -n 's/^HONK_ASSET_X86_64:=//p' ./honk/generated-stage.mk | head -1)"
	if curl -fsL -I --connect-timeout 10 --max-time 30 "$_probe" >/dev/null 2>&1; then
		echo "honk: core asset reachable"
	else
		echo "!! honk: core asset NOT reachable: $_probe" >&2
	fi
}
fetch_honk_stage
# Honk 所需的 GeoIP / GeoSite 数据包
UPDATE_PACKAGE "v2ray-geodata" "kenzok8/wall" "main" "pkg" "v2ray-geoip v2ray-geosite"

# x86 装机用：把剩余空间扩到根分区
UPDATE_PACKAGE "partexp" "sirpdboy/luci-app-partexp" "main"

# =============================================================================
# 本项目自己的包：mydist/（TC ingress eBPF 快路径 + eBPF full-cone NAT）
# =============================================================================
# mydist/ 是**唯一**的分发逻辑归属地，所以它必须是「仓库内一个目录」，而不是
# 散落在 upstream 文件里的改动。它不属于任何第三方仓库，所以走本地拷贝而不是
# git clone —— 落地方式与 UPDATE_PACKAGE 一致（都进构建树的 package/）。
#
# 整个 mydist/ 一起拷，不逐个列举：以后往里加包（einat-ebpf 已经在了）不需要
# 再改这个脚本，符合「所有分发逻辑一个目录」的约定。
#
# 找不到就**直接失败**。静默产出一个「没有数据面」的固件是最糟的结果：
# 镜像照样能启动、能上网，只有透明代理的快路径悄悄没了。verify-packages.sh
# 里也登记了 dpd-fastpath 作为第二道闸。
# mydist 数据面只给 X86 / ROCKCHIP。IPQ / MTK 走原版逻辑（NSS + 原版 honk），
# 不拷贝、也不启用 einat/dpd/router-* 这一套；它们的 GENERAL 用的是原版清单。
case "$WRT_CONFIG" in
X86|ROCKCHIP)
MYDIST_ROOT=""
for _c in "$GITHUB_WORKSPACE/wrt/mydist" \
          "$GITHUB_WORKSPACE/mydist" \
          "$GITHUB_WORKSPACE/wrt/package/mydist" \
          "$(pwd)/mydist"; do
	[ -d "$_c/router-dataplane" ] && { MYDIST_ROOT="$_c"; break; }
done

if [ -n "$MYDIST_ROOT" ]; then
	echo " "
	# 第三个候选位置就是 ./mydist 本身（上一次构建留下的），此时不能先 rm
	if [ "$(readlink -f "$MYDIST_ROOT" 2>/dev/null)" = "$(readlink -f ./mydist 2>/dev/null)" ]; then
		echo "mydist already in place at $(pwd)/mydist"
	else
		rm -rf ./mydist
		mkdir -p ./mydist
		cp -rf "$MYDIST_ROOT"/. ./mydist/
	fi
	find ./mydist -type f \( -name '*.sh' -o -name '*.init' -o -name '*-dpd-fastpath' \) \
		-exec sed -i 's/\r$//' {} \; -exec chmod 0755 {} \;
	echo "mydist installed into package/ (from $MYDIST_ROOT):"
	ls ./mydist | sed 's/^/  /'
else
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	echo "!! FATAL: mydist/router-dataplane not found."
	echo "!! 期望位置: \$GITHUB_WORKSPACE/mydist/router-dataplane"
	echo "!! 没有它，固件里不会有 eBPF 数据面。中止构建。"
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	exit 1
fi
	;;
*)
	echo "mydist: $WRT_CONFIG uses the original logic, datapath packages skipped"
	;;
esac

#更新软件包版本
UPDATE_VERSION() {
	local PKG_NAME=$1
	local PKG_MARK=${2:-false}
	local PKG_FILES=$(find ./ ../feeds/packages/ -maxdepth 3 -type f -wholename "*/$PKG_NAME/Makefile")

	if [ -z "$PKG_FILES" ]; then
		echo "$PKG_NAME not found!"
		return
	fi

	echo -e "\n$PKG_NAME version update has started!"

	for PKG_FILE in $PKG_FILES; do
		local PKG_REPO=$(grep -Po "PKG_SOURCE_URL:=https://.*github.com/\K[^/]+/[^/]+(?=.*)" $PKG_FILE)
		local PKG_TAG=$(curl -sL "https://api.github.com/repos/$PKG_REPO/releases" | jq -r "map(select(.prerelease == $PKG_MARK)) | first | .tag_name")

		local OLD_VER=$(grep -Po "PKG_VERSION:=\K.*" "$PKG_FILE")
		local OLD_URL=$(grep -Po "PKG_SOURCE_URL:=\K.*" "$PKG_FILE")
		local OLD_FILE=$(grep -Po "PKG_SOURCE:=\K.*" "$PKG_FILE")
		local OLD_HASH=$(grep -Po "PKG_HASH:=\K.*" "$PKG_FILE")

		local PKG_URL=$([[ "$OLD_URL" == *"releases"* ]] && echo "${OLD_URL%/}/$OLD_FILE" || echo "${OLD_URL%/}")

		local NEW_VER=$(echo $PKG_TAG | sed -E 's/[^0-9]+/\./g; s/^\.|\.$//g')
		local NEW_URL=$(echo $PKG_URL | sed "s/\$(PKG_VERSION)/$NEW_VER/g; s/\$(PKG_NAME)/$PKG_NAME/g")
		local NEW_HASH=$(curl -sL "$NEW_URL" | sha256sum | cut -d ' ' -f 1)

		echo "old version: $OLD_VER $OLD_HASH"
		echo "new version: $NEW_VER $NEW_HASH"

		if [[ "$NEW_VER" =~ ^[0-9].* ]] && dpkg --compare-versions "$OLD_VER" lt "$NEW_VER"; then
			sed -i "s/PKG_VERSION:=.*/PKG_VERSION:=$NEW_VER/g" "$PKG_FILE"
			sed -i "s/PKG_HASH:=.*/PKG_HASH:=$NEW_HASH/g" "$PKG_FILE"
			echo "$PKG_FILE version has been updated!"
		else
			echo "$PKG_FILE version is already the latest!"
		fi
	done
}

# 注意：原先这里有一句 UPDATE_VERSION "sing-box"。
# 基线软件清单里**没有任何 sing-box 包**（对照 ref-X86.manifest / ref-ROCKCHIP.manifest），
# 所以它每次 CI 都会：访问 GitHub API 取 release -> 下载整包 -> sha256 -> 改 Makefile，
# 全程没有任何效果，纯属浪费时间和网络。已删除。
# 如果需要它，请连同对应的 sing-box 插件一起加回来，并在 verify-packages.sh 里登记。

#引入私有扩展脚本
if [ -f "$GITHUB_WORKSPACE/Scripts/PRIVATE.sh" ]; then
	source "$GITHUB_WORKSPACE/Scripts/PRIVATE.sh"
fi
