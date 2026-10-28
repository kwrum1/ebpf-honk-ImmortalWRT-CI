# router-tuning

首启性能档位。x86 / rockchip / qualcommax 共用同一份脚本：平台差异在运行时探测
（CPU 核数、内存、guest 还是裸机、WAN 设备），不走三份文件。

证据、逐条取舍和"为什么不做别的"写在 **`docs/kernel-and-tuning-research.md`**。

## 文件

| 文件 | 作用 |
|---|---|
| `files/router-tuning.sh` | 引擎（被 init/hotplug source；没有独立 dispatcher） |
| `files/router_tuning.init` | procd 服务，`START=26`（network 20、packet_steering 25 之后，einat 60/dpd 95/router-qos 97 之前） |
| `files/router_tuning.config` | `/etc/config/router_tuning`，每个开关都能单独关 |
| `files/93-router-tuning` | iface hotplug：设备重现时重做 ring/coalescing/txqueuelen/XPS |
| `files/98-ebpf-tuning` | uci-defaults：首启在 **S11 sysctl 之前**生成 `/etc/sysctl.d/29-router-tuning.conf`，并 enable 服务 |

## 为什么 sysctl 必须走 `/etc/sysctl.d/`

镜像里的 `/etc/init.d/sysctl` 是 **START=11**，而 `network` 是 **S20**。`default_qdisc`
只对**它设置之后创建**的设备生效，所以它必须在任何网卡存在之前落地。uci-defaults 由
`/etc/init.d/boot`（S10）执行，正好在 S11 之前 —— 这就是 `98-ebpf-tuning` 存在的全部理由。

## 它**不**做什么（都是刻意的）

| 不碰的东西 | 谁拥有它 | 我们的行为 |
|---|---|---|
| WAN 根 qdisc | `router-qos`（CAKE） | 完全不写 WAN 的 qdisc；只改 `net.core.default_qdisc` |
| `rps_cpus` 与 NAPI/IRQ 亲和 | 上游 `packet_steering`（本镜像 S25 **已 enable**） | 只有在"该服务不存在"且"所有 rps_cpus 仍为 0"时才补位 |
| `rp_filter` / `accept_local` / `ip_forward` | honk（`strings honk-core` 实测会写） | 不写；socket 缓冲只**抬升不降低** |
| `/etc/config/{network,dhcp,firewall}` | 出厂/上游 | 一行都不写（只读 uci/ubus） |

## 用法

```sh
router-tuning report     # 只打印将做什么，不改变任何东西（与 apply 同一条代码路径）
router-tuning start      # 应用
router-tuning restore    # 用 /etc/router-tuning.state 里记录的原值退回
uci set router_tuning.global.profile=conservative
```

## 验证方式

* 静态：`build/check-plat-artifacts.sh` 断言包存在、`/etc/rc.d/S26router-tuning` 存在、
  `/etc/sysctl.d/29-router-tuning.conf` 的档位值与内存相符、脚本权限正确。
* 动态：`build/qemu-tuning-audit.sh` —— 启动后先 dump 全部现状（sysctl、`rps_cpus`/
  `xps_cpus`、ring、coalescing、governor、IRQ 分布、qdisc），再做一次基线吞吐与"施加后"
  吞吐的 A/B。宿主无 KVM（TCG + virtio），所以绝对值不代表真机，**相对 delta 和审计 dump
  才是结论**。
