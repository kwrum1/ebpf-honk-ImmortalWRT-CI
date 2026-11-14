#!/bin/bash
# SPDX-License-Identifier: MIT
#
# verify-drift.sh —— 文档/包骨架/配置项的一致性闸门
#
# 为什么需要它：这个仓库的"真相"分散在四个地方——包 Makefile 的安装清单、
# LuCI 的 menu.d/json、ACL、以及 /etc/config 的默认值。历史上这四处各漂各的，
# 结果是"页面在树里、镜像里没有"、"配置项写了、脚本没读"、"文档让人 set 一个
# 早就不存在的 upload 选项"这类问题只有在真机上才被发现。
#
# 它检查的都是**机械可判定**的事实，不判断设计好坏：
#
#   1. 每个 ebpf/*/Makefile 里引用的 ./files/... 都存在（页面/脚本/配置漏提交）
#   2. menu.d 里的 "path": "ebpf/x" 在某个 luci-app 的 view/ 下真有 x.js，
#      且该文件被 Makefile 安装（页面没装进镜像）
#   3. 每个 view/*.js 里 fs.read('/var/run/...') 的路径在 ACL 里被授权
#      （页面能打开但读不到状态）
#   4. /etc/config 里出现的每个 option/list 名字在包内至少被引用一次
#      （配置项写了，没人读）
#   5. Config/*.txt 不再教人设置已被删除的选项（比如 router_qos.global.upload）
#   6. verify-packages.sh 的必备清单与禁用清单不相交（自相矛盾）
#
# 用法：Scripts/verify-drift.sh [--verbose]
# 退出码：0 通过；1 有硬性失败。

set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERBOSE=0
[ "${1:-}" = "--verbose" ] && VERBOSE=1

fails=0
bad()  { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }
ok()   { [ "$VERBOSE" = 1 ] && printf '  ok    %s\n' "$*"; return 0; }
note() { printf '  %s\n' "$*"; }

echo "== 1. 包 Makefile 引用的文件都存在 =="
while IFS= read -r mk; do
	pkgdir=$(dirname "$mk")
	while IFS= read -r ref; do
		[ -n "$ref" ] || continue
		case "$ref" in
		*'$('*|*'*'*) continue ;;	# 变量/通配符无法静态判定
		esac
		if [ -e "$pkgdir/$ref" ]; then
			ok "${mk#$ROOT/}: $ref"
		else
			bad "${mk#$ROOT/} 引用了不存在的 $ref"
		fi
	done < <(grep -oE '\./files/[A-Za-z0-9._/-]+' "$mk" | sort -u)
done < <(find "$ROOT/ebpf" -name Makefile -type f | sort)

echo "== 2. menu.d 的 path 指向真实存在且会被安装的 view =="
	for menu in "$ROOT"/ebpf/luci-app-*/files/menu-*.json; do
	[ -f "$menu" ] || continue
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		# menu.d also carries entries that point at other packages' pages
		# (smartdns, honk); only the views this repository ships are ours to
		# verify.
		case "$path" in
		ebpf/*) ;;
		*) ok "${menu#$ROOT/}: $path (external page, skipped)"; continue ;;
		esac
		found=""
		for app in "$ROOT"/ebpf/luci-app-*; do
			view="$app/files/htdocs/luci-static/resources/view/$path.js"
			[ -f "$view" ] || continue
			if grep -qF "view/$path.js" "$app/Makefile"; then
				found=1
				ok "${menu#$ROOT/}: $path -> ${view#$ROOT/}"
			else
				bad "${view#$ROOT/} 存在但 ${app##*/}/Makefile 没有安装它"
				found=1
			fi
		done
		[ -n "$found" ] || bad "${menu#$ROOT/} 的 path '$path' 没有对应的 view 文件"
	done < <(grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]+"' "$menu" |
		sed -E 's/.*"([^"]+)"$/\1/')
done

echo "== 3. 页面读取的 /var/run 路径在 ACL 里被授权 =="
for js in "$ROOT"/ebpf/luci-app-*/files/htdocs/luci-static/resources/view/*/*.js; do
	[ -f "$js" ] || continue
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		if grep -rqsF "\"$p\"" "$ROOT"/ebpf/luci-app-*/files/acl.d/; then
			ok "${js##*/}: $p"
		else
			bad "${js##*/} 读取 $p，但没有任何 acl.d 条目授权它"
		fi
	done < <(grep -oE "fs\.read\('[^']+'" "$js" |
		sed -E "s/^fs\.read\('//; s/'$//" | sort -u)
done

echo "== 4. /etc/config 里的选项在包内被引用 =="
for cfg in "$ROOT"/ebpf/*/files/*.config; do
	[ -f "$cfg" ] || continue
	pkgdir=$(dirname "$(dirname "$cfg")")
	while IFS= read -r opt; do
		[ -n "$opt" ] || continue
		# Some knobs are declared by the datapath package but consumed by the
		# flow manager (auto_tune, the TTL knobs): dpd_fastpath.config is the
		# single place the UI writes them, dpdfwd is what reads them.
		if grep -rqs --exclude="$(basename "$cfg")" -- "$opt" "$pkgdir" ||
			grep -rqs -- "$opt" "$ROOT/ebpf/dpdfwd"; then
			ok "${cfg#$ROOT/}: $opt"
		else
			bad "${cfg#$ROOT/} 定义了 '$opt'，但 ${pkgdir#$ROOT/} 和 ebpf/dpdfwd 里都没有引用"
		fi
	done < <(grep -oE '^[[:space:]]*(option|list)[[:space:]]+[A-Za-z0-9_]+' "$cfg" |
		awk '{print $2}' | sort -u)
done

echo "== 5. Config/*.txt 不再教人设置已删除的选项 =="
for stale in 'router_qos.global.upload' 'router_qos.global.download'; do
	if grep -rqs -- "$stale" "$ROOT/Config"; then
		bad "Config/ 仍引用 $stale（router-qos 已无此选项；现在只按 profile 自动选调度器）"
	else
		ok "Config/ 未引用 $stale"
	fi
done
if grep -qsE '^[[:space:]]*(option|list)[[:space:]]+(upload|download)' \
	"$ROOT/ebpf/router-qos/files/router_qos.config"; then
	bad "router_qos.config 又出现了 upload/download 选项（与 router-qos.sh 的 unlimited 设计冲突）"
else
	ok "router_qos.config 没有 upload/download"
fi

echo "== 6. verify-packages.sh 的必备/禁用清单不相交 =="
VP="$ROOT/Scripts/verify-packages.sh"
block() {
	awk -v start="^$1=\"" 'BEGIN{on=0} $0 ~ start {on=1; next}
		on && /^"$/ {exit}
		on && $0 !~ /^[[:space:]]*#/ {gsub(/[[:space:]]/,""); if (length($0)) print}' "$VP"
}
REQ=$(block REQUIRED)
FOR=$(block FORBIDDEN)
if [ -z "$REQ" ] || [ -z "$FOR" ]; then
	bad "无法解析 verify-packages.sh 的 REQUIRED/FORBIDDEN（脚本结构变了？）"
else
	both=$(comm -12 <(printf '%s\n' "$REQ" | sort -u) <(printf '%s\n' "$FOR" | sort -u))
	if [ -n "$both" ]; then
		printf '%s\n' "$both" | while IFS= read -r p; do
			bad "同时出现在必备与禁用清单: $p"
		done
		fails=$((fails + 1))
	else
		note "  必备 $(printf '%s\n' "$REQ" | wc -l) 条 / 禁用 $(printf '%s\n' "$FOR" | wc -l) 条，无交集"
	fi
fi

echo "== 7. IPQ/MTK 只允许只读 DPD 状态包（PPE/flowtable 独占转发） =="
# IPQ/MTK 走内核 flowtable（IPQ 还有 PPE 硬件卸载），DPD 数据面不参与竞争。
# 检查的是**源码约定**，不需要构建产物：谁把闸门删掉，CI 立刻失败，而不是等
# 烧到机器上才发现两套加速器抢同一条流。
#
# 真正的保护有三层，这里各查一层：
#   a) IPQ/MTK 的 Config/*.txt 不得选中任何 DPD 数据面包（选中即冲突）；
#   b) Packages.sh 的 ebpf/ 拷贝必须在 X86|ROCKCHIP 分支内；
#   c) 带 BPF 对象的包（事后会被 tc 挂到设备上）必须排除 TARGET_qualcommax，
#      因为 aarch64 的 IPQ 否则能直接装上。
leak=0

# a) configs
for cfg in "$ROOT"/Config/IPQ*.txt "$ROOT"/Config/MEDIATEK*.txt \
	   "$ROOT"/Config/AIROHA*.txt; do
	[ -f "$cfg" ] || continue
	while IFS= read -r pkg; do
		case "$pkg" in
		dpd-fastpath | einat-ebpf | router-acl | router-dataplane | dpdfwd)
			bad "${cfg#$ROOT/} 选中了 $pkg（IPQ/MTK 的加速归 flowtable/PPE）"
			leak=1
			;;
		esac
	done < <(sed -n 's/^CONFIG_PACKAGE_\([^=]*\)=[ym]$/\1/p' "$cfg")
done
[ "$leak" = 0 ] && ok "IPQ/MTK 的 Config 没有选中 DPD 数据面包"

# b) Packages.sh 的拷贝分支
if awk '/^case "\$WRT_CONFIG" in/{on=1}
	on && /^X86\|ROCKCHIP\)/{x86=1}
	on && /ebpf\/ \$/ {if (!x86) exit 1}
	on && /^esac/{on=0; x86=0}' "$ROOT/Scripts/Packages.sh"; then
	ok "Packages.sh 的 ebpf/ 拷贝仍在 X86|ROCKCHIP 分支内"
else
	bad "Packages.sh 会把 ebpf/ 拷进非 X86/ROCKCHIP 的构建（IPQ/MTK 会捡到 DPD 数据面）"
	leak=1
fi

# c) IPQ60xx/IPQ807x may install the *read* side only: router-dataplane
#    (dpdctl reads the PPE table from debugfs) and dpdfwd (publishes
#    status.json). Anything that could take the forwarding path over --
#    einat, router-acl, router-qos, router-dns, router-tuning -- must stay
#    out. The init gate keeps DPD in observe without einat, so the kernel
#    NSS/PPE path remains the only accelerator.
ipq_branch=$(awk '/^IPQ60XX\*\|IPQ807X\*\)/{on=1} on && /cp -rf/{print} on && /;;/{exit}' \
	"$ROOT/Scripts/Packages.sh")
case "$ipq_branch" in
*router-dataplane*) ;;
*)
	bad "Packages.sh 的 IPQ 分支缺少 router-dataplane（概况页需要 dpdctl 读 PPE）"
	leak=1
	;;
esac
case "$ipq_branch" in
*dpdfwd*) ;;
*)
	bad "Packages.sh 的 IPQ 分支缺少 dpdfwd（status.json 无人发布）"
	leak=1
	;;
esac
for pkg in einat router-acl router-qos router-dns router-tuning; do
	case "$ipq_branch" in
	*"$pkg"*)
		bad "Packages.sh 的 IPQ 分支包含 $pkg：IPQ 只允许只读的 router-dataplane/dpdfwd"
		leak=1
		;;
	esac
done

# Settings.sh must enable exactly those two for IPQ, not the acceleration
# stack (einat would compete with NSS/PPE for the forwarding path).
ipq_cfg=$(awk '/IPQ60XX\*\|IPQ807X\*\)/{on=1} on && /^CONFIG_PACKAGE_/{print} on && /^    ;;/{exit}' \
	"$ROOT/Scripts/Settings.sh")
for pkg in einat-ebpf router-acl luci-app-ebpf dpd-honk dpd-napi; do
	case "$ipq_cfg" in
	*"$pkg"*)
		bad "Settings.sh 给 IPQ 选了 $pkg：只允许 dpd-fastpath/dpdfwd"
		leak=1
		;;
	esac
done
[ "$leak" = 0 ] && ok "IPQ 只安装只读状态包（router-dataplane + dpdfwd）"

echo
if [ "$fails" != 0 ]; then
	echo "verify-drift: FAILED ($fails)"
	exit 1
fi
echo "verify-drift: PASSED"
