#!/bin/bash


# skb 回收
function enable_skb_recycler() {
  if [ -f "$1" ]; then
    cat >> "$1" <<EOF

CONFIG_KERNEL_SKB_RECYCLER=y
CONFIG_KERNEL_SKB_RECYCLER_MULTI_CPU=y
EOF
  fi
}

########################################
# 固定 kernel 6.18 新增 perf 选项
########################################

function pin_arm_perf_kernel_config() {
  local target
  target=$(grep -m 1 -oP '^CONFIG_TARGET_qualcommax_\K[[:alnum:]_]+(?=\=y)' "$GITHUB_WORKSPACE/Config/${WRT_CONFIG}.txt")

  local kernel_config="target/linux/qualcommax/${target}/config-default"
  if [ ! -f "$kernel_config" ]; then
    echo "skip kernel perf config: $kernel_config not found"
    return 0
  fi

  cat >> "$kernel_config" <<'EOF'

# Kernel 6.18 eBPF/BTF perf dependencies
# CONFIG_ARM64_BRBE is not set
# CONFIG_ARM_CCI_PMU is not set
# CONFIG_ARM_CCN is not set
# CONFIG_ARM_CMN is not set
# CONFIG_ARM_NI is not set
# CONFIG_ARM_SMMU_V3_PMU is not set
# CONFIG_ARM_DSU_PMU is not set
# CONFIG_ARM_SPE_PMU is not set
EOF
}

########################################
# 修改内核大小
########################################

function set_kernel_size() {

  # 只有 qualcommax 有这些 image/*.mk；x86/rockchip 上直接跳过，避免无谓的
  # sed 报错（glob 不展开时 sed 会拿到字面量路径）。
  [ -d target/linux/qualcommax/image ] || return 0

  for file in target/linux/qualcommax/image/*.mk; do
    sed -i 's/KERNEL_SIZE := [0-9]*k/KERNEL_SIZE := 12288k/g' "$file"
  done

}

########################################
# 生成最终 .config
########################################

function generate_config() {

  config_file=".config"

  # 与 WRT-CORE 的 "Custom Settings" 保持一致：TEST 配置只吃自己那份，
  # 不能再把 GENERAL 拼进去（否则 WRT-TEST 的“只输出配置”语义会被覆盖）。
  if [[ "${WRT_CONFIG,,}" == *"test"* ]]; then
    cat "$GITHUB_WORKSPACE/Config/${WRT_CONFIG}.txt" > "$config_file"
  else
    cat "$GITHUB_WORKSPACE/Config/${WRT_CONFIG}.txt" \
        "$GITHUB_WORKSPACE/Config/GENERAL.txt" > "$config_file"
  fi

  # skb recycler
  enable_skb_recycler "$config_file"

  # 内核大小
  set_kernel_size

  # kernel 6.18 perf config
  pin_arm_perf_kernel_config

  # luci-front 是 x86_64 预编译前端（PKGARCH:=x86_64）。其它目标显式关掉：
  # 不写这一行 defconfig 只会报 “not available”，而且容易误以为 RK/MTK/IPQ
  # 也带了这个 pingora 前端。
  if [ "${WRT_TARGET}" != "x86" ]; then
    echo "# CONFIG_PACKAGE_luci-front is not set" >> "$config_file"
  fi

}

########################################
# 执行生成 config
########################################

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
# 路由器完全无法访问；而且不可逆：下一次再跑时行里已经没有
# 192.168.x.y 可以匹配，坏状态会永久留在树里。
# 实测踩过：同一批里 ROCKCHIP 拿到 192.168.10.1，X86 拿到空串，
# 于是 x86 镜像启动后 network.interface.lan 报 INVALID_ADDRESS "/24"。
# 语义定为：WRT_IP 为空 = 保留上游默认；否则替换为 WRT_IP。
LAN_IP="${WRT_IP:-192.168.1.1}"
#修改immortalwrt.lan关联IP
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$LAN_IP/g" $(find ./feeds/luci/modules/luci-mod-system/ -type f -name "flash.js")
#添加编译日期标识
sed -i "s/(\(luciversion || ''\))/(\1) + (' \/ $WRT_MARK-$WRT_DATE')/g" $(find ./feeds/luci/modules/luci-mod-status/ -type f -name "10_system.js")

WIFI_SH=$(find ./target/linux/{mediatek/filogic,qualcommax}/base-files/etc/uci-defaults/ -type f -name "*set-wireless.sh" 2>/dev/null)
WIFI_UC="./package/network/config/wifi-scripts/files/lib/wifi/mac80211.uc"
if [ -f "$WIFI_SH" ]; then
	#修改WIFI名称
	sed -i "s/BASE_SSID='.*'/BASE_SSID='$WRT_SSID'/g" $WIFI_SH
	#修改WIFI密码
	sed -i "s/BASE_WORD='.*'/BASE_WORD='$WRT_WORD'/g" $WIFI_SH
elif [ -f "$WIFI_UC" ]; then
	#修改WIFI名称
	sed -i "s/ssid='.*'/ssid='$WRT_SSID'/g" $WIFI_UC
	#修改WIFI密码
	sed -i "s/key='.*'/key='$WRT_WORD'/g" $WIFI_UC
	#修改WIFI地区
	sed -i "s/country='.*'/country='CN'/g" $WIFI_UC
	#修改WIFI加密
	sed -i "s/encryption='.*'/encryption='psk2+ccmp'/g" $WIFI_UC
fi

CFG_FILE="./package/base-files/files/bin/config_generate"
#修改默认IP地址
# 先把被清空的 lan 默认值修回来：字面匹配，不依赖正则转义。
# 少了这一步，下面那个全局替换在坏树里永远匹配不到，LAN 会一直没地址。
grep -q 'lan) ipad=${ipaddr:-""}' "$CFG_FILE" &&
	sed -i 's#lan) ipad=${ipaddr:-""}#lan) ipad=${ipaddr:-"192.168.1.1"}#' "$CFG_FILE"
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$LAN_IP/g" "$CFG_FILE"
# 兜底断言：LAN 默认地址绝不允许为空。空地址 = 镜像能启动但**路由器访问不到**
# （br-lan 没有 IPv4、netifd 报 INVALID_ADDRESS、dpd 也挂不上 LAN），
# 而且要到开机后才暴露。宁可在这里直接失败。
if grep -q 'lan) ipad=${ipaddr:-""}' "$CFG_FILE"; then
	echo "ERROR: config_generate 的 LAN 默认地址为空（WRT_IP='${WRT_IP:-<未设置>}'）" >&2
	echo "       LAN 会没有 IPv4，设备无法访问；检查 WRT_IP 与上面的 sed。" >&2
	exit 1
fi
#修改默认主机名
sed -i "s/hostname='.*'/hostname='$WRT_NAME'/g" $CFG_FILE

#配置文件修改
echo "CONFIG_PACKAGE_luci=y" >> ./.config
echo "CONFIG_LUCI_LANG_zh_Hans=y" >> ./.config
echo "CONFIG_PACKAGE_luci-theme-$WRT_THEME=y" >> ./.config
echo "CONFIG_PACKAGE_luci-app-$WRT_THEME-config=y" >> ./.config

#手动调整的插件
if [ -n "$WRT_PACKAGE" ]; then
	echo -e "$WRT_PACKAGE" >> ./.config
fi

#无WIFI配置标志
if [[ "${WRT_CONFIG,,}" == *"wifi"* && "${WRT_CONFIG,,}" == *"no"* ]]; then
	echo "WRT_WIFI=wifi-no" >> $GITHUB_ENV
fi

#高通平台调整
DTS_PATH="./target/linux/qualcommax/dts/"
if [[ "${WRT_TARGET^^}" == *"QUALCOMMAX"* ]]; then
	#无WIFI配置调整Q6大小
	if [[ "${WRT_CONFIG,,}" == *"wifi"* && "${WRT_CONFIG,,}" == *"no"* ]]; then
		find $DTS_PATH -type f ! -iname '*nowifi*' -exec sed -i 's/ipq\(6018\|8074\).dtsi/ipq\1-nowifi.dtsi/g' {} +
		echo "qualcommax set up nowifi successfully!"
	fi
fi
