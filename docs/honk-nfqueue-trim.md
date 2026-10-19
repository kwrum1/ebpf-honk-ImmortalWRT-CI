# honk NFQUEUE 裁剪报告

> 目的：确认"取消 tproxy/NFQUEUE 模式"是打包层改动还是必须改 Rust 核心。
> 结论：**纯打包层改动**（无 Rust 修改）。实际改动 = **5 处 `true` → `false`**
> + `honk/Makefile` 去掉 `+kmod-nft-queue` + `Config/GENERAL.txt` 去掉显式选择。
>
> **本文档已落地**（`Scripts/Handles.sh` 的 #23 段），并在 x86 镜像里实测复核过 ——
> 见文末 §7。

---

## 1. 结论先行

`kwrum1/openwrt-honk` 的打包层**主动强制 `nfqueue_enable: true`**：

- 运行期写配置时硬编码 `true`
- 健康检查**要求** `true`，否则判定"不健康"并自动"修复"（重写回 `true`）
- 只有初始化阶段的 **mock/shadow 配置**用 `false`

因此**只在 `system.dae` 里改成 `false` 是无效的**——下次系统检查会被改回来。

→ 必须一并修改打包脚本中的 3 处写入点 + 1 处健康检查点。

---

## 2. 精确改动清单

| # | 文件 | 行 | 现有内容 | 作用 |
|---|---|---|---|---|
| 1 | `honk/files/system.dae` | 10 | `nfqueue_enable: true` | 出厂默认配置 |
| 2 | `honk/files/control.sh` | 308 | `write_runtime_system()` 写 `true` | **运行期写入点** |
| 3 | `honk/files/control.sh` | 543 | `grep -Fqx '    nfqueue_enable: true'` | **健康检查断言**（关键） |
| 4 | `honk/files/maintenance.sh` | 568 | 期望快照写 `true` | 配置一致性校验 |
| 5 | `honk/files/maintenance.sh` | 735 | `write_live_system()` 写 `true` | **维护流程写入点** |
| 6 | `honk/Makefile` | 56 | `DEPENDS ... +kmod-nft-queue` | 依赖包，可移除以减小固件 |

> 参考：`honk/files/maintenance.sh:701` 与 `control.sh:709` 已经是 `false`，
> 但那是 **shadow / mock** 配置（初始化与离线维护用），不是运行配置。

---

## 3. 关键代码位置（原文）

### `control.sh:296-318` — 运行期配置写入

```sh
write_runtime_system() {
	...
	printf "    store_subscribe: true\n    nfqueue_enable: true\n}\n\n"
	...
}
```

### `control.sh:541-549` — 健康检查（会导致"改回去"）

```sh
	if [ -r /usr/share/doona/index.html ] && ... && \
		grep -Fqx '    data_dir: '/etc/honk'' /etc/honk/system.dae && \
		grep -Fqx '    nfqueue_enable: true' /etc/honk/system.dae && \
		...; then
		echo '{"ok":true,"message":"system_config_healthy"}'
		return 0
	fi
```

→ 若断言失败，代码会走 `write_runtime_system` **重写配置**，把 `false` 冲回 `true`。
**这是必须同改的原因。**

### `maintenance.sh:718-736` — `write_live_system()`

```sh
write_live_system() {
	...
	cat > "$live_system" <<EOF
global {
	...
	store_subscribe: true
	nfqueue_enable: true
}
EOF
}
```

---

> **补注（落地时才发现的坑）**：`honk/files/` 下的文件改了**不会**让 OpenWrt 重建
> 这个包（`$(STAMP_BUILT)` 只认包 Makefile，同 `base-files`）。所以 `Handles.sh`
> 的 #23 段改完必须顺手 `rm -rf build_dir/target-*/honk-*`，否则增量构建会继续用
> prepare 时拷走的那份 `true` —— 源码改了、镜像里还是 `true`，清单上看不出来。

---

## 4. 裁剪后的影响与验证

### 预期收益
- 消除 UDP 首包被 NFQUEUE 持有、在 conntrack/NAT 之前被判定的路径
- 移除 `kmod-nft-queue` 依赖，减小固件
- 与 `einat`（TC eBPF NAT）不再争抢 queue 320 与 `inet honk_nfqueue`

### 必须实测的回归（P0）
| 项 | 方法 | 通过标准 |
|---|---|---|
| UDP 代理仍可用 | DNS(53/udp) + QUIC(443/udp) 走代理 | 正常分流 |
| UDP 直连仍可用 | 大流量 UDP（如 QUIC 视频） | 无首包丢失 |
| 无残留 nft/queue | `nft list ruleset`、`tc -s` | 无 `honk_nfqueue` / queue 320 |
| 健康检查不误报 | LuCI 系统检查 | `system_config_healthy` |

> ⚠️ 关闭 NFQUEUE 后某些 UDP 场景可能退化（首包判定路径改变）。
> 因此**必须与开启态做 A/B**，不能只验证"能上网"。

---

## 5. 与 einat 的冲突面（为什么必须裁）

honk 的 NFQUEUE 路径：
- 独占 netfilter queue 320
- 建立 `inet honk_nfqueue` / `udp_decision` 链
- 在 conntrack/NAT **之前**持有 LAN 转发的首包

而 `einat-ebpf` 的 NAT 在 **TC egress**，且业务流计划 `notrack`。
两者对"谁先看到首包"存在直接竞争 → 裁剪 NFQUEUE 是 einat 落地的前置条件之一。

---

## 7. 落地改动与实测复核

改动在 `Scripts/Handles.sh` 的 **#23** 段（构建期，幂等）。它 sed 的是**克隆下来的**
`package/honk/`，所以对上游 fork 没有任何要求。

### 7.1 静态改动

| 文件 | 改什么 |
|---|---|
| `files/system.dae` | `nfqueue_enable: true` → `false`（出厂配置，mode 0444） |
| `files/control.sh` | 308（`write_runtime_system`）与 **543（健康检查断言）** 两处 `true` → `false` |
| `files/maintenance.sh` | 568、735 两处写 `true` → `false` |
| `Makefile` | `DEPENDS` 去掉 `+kmod-nft-queue` |
| `Config/GENERAL.txt` | 去掉 `CONFIG_PACKAGE_kmod-nft-queue=y` |
| `Scripts/verify-packages.sh` | `kmod-nft-queue` 从必备清单挪进禁用清单 |

> 543 那一处是**断言**，不是写入。只改出厂配置的话，`control.sh check` 会判定
> "配置不健康"，然后走 `repair`（也就是 308 那个写入点）把它**改回 `true`**。
> 两处都改成 `false` 之后，无论健康检查跑不跑，这个不变式都成立 —— 见 §7.3。

### 7.2 镜像里实测（`build/qemu-25-23.sh`，x86 QEMU）

```
--- F1 honk 的出厂的/打包的配置 ---
-r--r--r--  /etc/honk/system.dae:10          nfqueue_enable: false
             /usr/share/honk/control.sh:308  nfqueue_enable: false
             /usr/share/honk/control.sh:543  grep -Fqx '… nfqueue_enable: false'   ← 断言也跟着改了
             /usr/share/honk/control.sh:709  false（本来就是 shadow/mock）
             /usr/share/honk/maintenance.sh:568/701/735  全部 false
--- F3 模块真的不在镜像里 ---
grep -c nft_queue /proc/modules        0
ls /lib/modules/*/nft_queue.ko         No such file or directory
nft list ruleset | grep -ci queue      0
```

（脚本里写的是"5 处 true"，实测 grep 出来是 5 处 `true` + 2 处本来就是 `false` 的
shadow/mock，共 7 处 —— 和 §2 的清单一致。）

清单侧同步验证：`verify-packages.sh` → `PASSED`，`kmod-nft-queue` 不在 396 个包里。

### 7.3 健康检查那条怎么证的（如实）

F2 想直接跑 `control.sh check`，结果它**先拒绝了**：

```
honk: package must be explicitly enabled and initialized
```

这是 honk 自己的守卫（没 enable + 没 initialize 就不给跑检查），**不是失败**。
所以没法在没启用代理的情况下把这个检查真跑一遍。改用了更强的论证：

* 检查的内容是纯 `grep -Fqx` 断言；
* 它现在断言的是 `false`（F1 里看到了），配置文件里也确实是 `false`；
* 于是检查**必然通过**，repair 分支不会触发；
* 而万一触发（比如将来有人手改了配置），repair 走的 `write_runtime_system`
  （308）现在写的也是 `false`。

所以**两个方向都是 `false`**，不依赖"检查跑没跑"。

