#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 kwrum1
#
# Settings.sh - build the .config and apply the image-level tweaks.
#
# This repo builds exactly two targets (X86, ROCKCHIP) from one source fork.
# Everything platform-specific for qualcommax/mediatek (kernel size, DTS wifi
# swapping, qualcommax perf options) was removed with the upstream CI: it could
# never apply to either target and only added ways to fail.

set -e

########################################
# 生成最终 .config
########################################

function generate_config() {
  config_file=".config"

  # TEST runs take only their own config; real builds are
  # <target> + GENERAL (common mydist baseline).
  if [[ "${WRT_CONFIG,,}" == *"test"* ]]; then
    cat "$GITHUB_WORKSPACE/Config/${WRT_CONFIG}.txt" > "$config_file"
  else
    cat "$GITHUB_WORKSPACE/Config/${WRT_CONFIG}.txt" \
        "$GITHUB_WORKSPACE/Config/GENERAL.txt" > "$config_file"
  fi

  # skb recycler: kernel-side skb cache (harmless when the symbol is absent;
  # defconfig drops unknown symbols).
  cat >> "$config_file" <<EOF

CONFIG_KERNEL_SKB_RECYCLER=y
CONFIG_KERNEL_SKB_RECYCLER_MULTI_CPU=y
EOF
}

generate_config

########################################
# Luci / 系统修改
########################################

#移除luci-app-attendedsysupgrade
sed -i "/attendedsysupgrade/d" $(find ./feeds/luci/collections/ -type f -name "Makefile")
#修改默认主题
sed -i "s/luci-theme-bootstrap/luci-theme-$WRT_THEME/g" $(find ./feeds/luci/collections/ -type f -name "Makefile")

# 默认 IP。WRT_IP 为空时**不能**让这个 sed 把地址替换成空串：
#   sed "s/192\.168\.[0-9]*\.[0-9]*/$WRT_IP/g"
# 在 WRT_IP 为空时是「删掉地址」——LAN 就没有 IPv4，br-lan 起不来，
# 路由器完全无法访问；而且不可逆。语义定为：
#   WRT_IP 为空 = 保留上游默认；否则替换为 WRT_IP。
LAN_IP="${WRT_IP:-192.168.1.1}"
#修改immortalwrt.lan关联IP
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$LAN_IP/g" $(find ./feeds/luci/modules/luci-mod-system/ -type f -name "flash.js")
#添加编译日期标识
sed -i "s/(\(luciversion || ''\))/(\1) + (' \/ $WRT_MARK-$WRT_DATE')/g" $(find ./feeds/luci/modules/luci-mod-status/ -type f -name "10_system.js")

CFG_FILE="./package/base-files/files/bin/config_generate"
#修改默认IP地址
# 先把被清空的 lan 默认值修回来：字面匹配，不依赖正则转义。
grep -q 'lan) ipad=${ipaddr:-""}' "$CFG_FILE" &&
	sed -i 's#lan) ipad=${ipaddr:-""}#lan) ipad=${ipaddr:-"192.168.1.1"}#' "$CFG_FILE"
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$LAN_IP/g" "$CFG_FILE"
# 兜底断言：LAN 默认地址绝不允许为空。空地址 = 镜像能启动但**路由器访问不到**
# （br-lan 没有 IPv4、netifd 报 INVALID_ADDRESS、dpd 也挂不上 LAN）。
if grep -q 'lan) ipad=${ipaddr:-""}' "$CFG_FILE"; then
	echo "ERROR: config_generate 的 LAN 默认地址为空（WRT_IP='${WRT_IP:-<未设置>}'）" >&2
	echo "       LAN 会没有 IPv4，设备无法访问；检查 WRT_IP 与上面的 sed。" >&2
	exit 1
fi
#修改默认主机名
sed -i "s/hostname='.*'/hostname='$WRT_NAME'/g" $CFG_FILE

# 无线：两个目标都是纯有线设备，但同一份源码也描述 wifi 脚本；只在文件存在时改。
WIFI_UC="./package/network/config/wifi-scripts/files/lib/wifi/mac80211.uc"
if [ -f "$WIFI_UC" ]; then
	sed -i "s/ssid='.*'/ssid='$WRT_SSID'/g" $WIFI_UC
	sed -i "s/key='.*'/key='$WRT_WORD'/g" $WIFI_UC
	sed -i "s/country='.*'/country='CN'/g" $WIFI_UC
	sed -i "s/encryption='.*'/encryption='psk2+ccmp'/g" $WIFI_UC
fi

#配置文件修改
echo "CONFIG_PACKAGE_luci=y" >> ./.config
echo "CONFIG_LUCI_LANG_zh_Hans=y" >> ./.config
echo "CONFIG_PACKAGE_luci-theme-$WRT_THEME=y" >> ./.config
echo "CONFIG_PACKAGE_luci-app-$WRT_THEME-config=y" >> ./.config

#手动调整的插件
if [ -n "$WRT_PACKAGE" ]; then
	echo -e "$WRT_PACKAGE" >> ./.config
fi
