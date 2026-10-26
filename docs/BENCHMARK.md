# 数据面实测：原版 vs mydist eBPF

测试日期：2026-10-26
测试台：单台 ESXi（2×Xeon，12 核，17 GB），全部虚拟网卡为 **vmxnet3**，
bench 网络使用两台**无上行链路**的独立 vSwitch，与办公网物理隔离。

---

## 1. 目的与结论

比较两条 NAT 转发路径在**同一套虚拟硬件**上的差别：

| 变体 | 固件 | 数据面 |
|---|---|---|
| **原版** | `VIKINGYFY/OpenWRT-CI` 官方 X86 产物（`X86-VIKINGYFY-owrt-26.10.26-07.24.32`） | fw4 nftables conntrack + `MASQUERADE` |
| **mydist** | 本仓库产物（`X86-kwrum1-mydist-26.10.26-08.00.37`，源码 `a37c1ea`） | einat-ebpf `nat44`（TCX）+ dpd-fastpath（classic BPF，`effective=stateless`） |

结论：

1. **吞吐同一档**：2.3–3.2 Gbit/s、小包 32–36 万 pps，差异小于宿主机噪声。
2. **同负载下 eBPF 更省 CPU**：2 Gbit/s 时 28 % vs 44 %（−36 %）；1 Gbit/s 时 9 % vs 13 %；
   3 Gbit/s 时基本持平（61 % vs 63 %），此时两者都撞到单核 ~73 %。
3. **瓶颈不在 NAT 实现**：2 vCPU 虚拟机的成本主要花在 vmxnet3 收包、软中断与 vSwitch 上。
4. mydist 的价值因此不在“跑得更快”，而在 **full-cone NAT、per-flow 策略、可观测性**，
   以及在低负载区间省下的 CPU。

---

## 2. 拓扑与参数

```
client 192.168.10.198 ──[bench-lan]── router ──[bench-wan]── server 198.18.0.2
                          LAN 192.168.10.1   WAN 198.18.0.1
                          mgmt 10.1.18.236（仅管理，无测试流量）
```

- router 2 vCPU / 1 GB，client 3 vCPU / 448 MB，server 2 vCPU / 448 MB；磁盘 NVMe 虚拟盘。
- 管理通道：ESXi 虚拟串口（guest `ttyS0` → TCP），不依赖 guest 网络，测试网段保持隔离。
- 两个路由变体**互斥运行**，端点机全程不动；每个变体 3 轮取中位数。
- 路由 CPU：测试前后读 `/proc/stat` 求差值（总占用 + 单核峰值）。

### 两个必须注意的坑

1. **WAN 不能用 10.x**：einat 默认把 `10/8`、`172.16/12`、`192.168/16` 视为内网
   （`--internal`），用 10.46.x 做 WAN 时 eBPF 变体不会做 SNAT，比较直接失真。
   本次改用 `198.18.0.0/24`（RFC 2544 基准段）。
2. **64 字节小包不能用 iperf3 UDP 打**：单进程用户态发包约 9.7 万 pps，
   三进程并发时服务端丢包约 50 %，测到的是端点而不是路由器。
   本次把两端 MTU 降到 96（MSS 56 ≈ 110 B 帧），用 3 个并发 TCP 流让**内核**驱动小包，
   接收在软中断里完成，路由器才会成为瓶颈。

### 测试项

| 项目 | 命令 | 时长 |
|---|---|---|
| TCP 单流 | `iperf3 -c SERVER -t 20 -P 1` | 20 s |
| TCP 4 流 | `iperf3 -c SERVER -t 20 -P 4` | 20 s |
| UDP 1400 B | `iperf3 -c SERVER -u -b 0 -l 1400 -t 20` | 20 s |
| 小包 pps | 两端 MTU 96，3 个独立 iperf3 进程并发 | 15 s |
| 延迟 | `ping -c 10 -i 1`（空载 / 4 流满载） | 10 s |
| 固定负载 CPU | `iperf3 -b <1/2/3>G -P 4`，每档 3 次 | 3×15 s |

---

## 3. 结果

### 3.1 吞吐 / pps / 延迟

| 指标 | 原版无加速 | mydist eBPF |
|---|---|---|
| TCP 单流 (Gbit/s) | 2.60 | 3.21 |
| TCP 4 流 (Gbit/s) | 2.32 | 3.23 |
| UDP 1400 B (Mbit/s) | 990 | 1034 |
| UDP 丢包 | 3.9 % | 4.8 % |
| 64 B 小包 pps | 322 768 | 363 393 |
| 小包路由 CPU | 72 % | 73 % |
| TCP4 路由 CPU | 56 % | 67 % |
| TCP4 单核峰值 | 79 % | 73 % |
| 空闲 RTT | 2.14 ms | 2.12 ms |
| 满载 RTT | 3.36 ms | 10.49 ms |

### 3.2 固定负载下的 CPU（每档 3 次中位数）

| 固定负载 | 原版无加速 | mydist eBPF |
|---|---|---|
| 1 Gbit/s | 13 % | **9 %** |
| 2 Gbit/s | 44 % | **28 %** |
| 3 Gbit/s | 63 % | 61 % |

这是本次最有信息量的一张表：负载固定后，eBPF 在 1–2 Gbit/s 区间的每包成本明显更低；
到 3 Gbit/s 两边都撞上单核软中断，省不出来。

---

## 4. 解读

1. **为什么吞吐差不多**：2–3 Gbit/s 的成本主要在 vmxnet3 收包、`skb` 分配、软中断和 vSwitch；
   eBPF 省下的 NAT/conntrack 开销只是其中一段，而 TCX + classic 两趟 BPF 遍历又抵掉一部分。
2. **eBPF 的收益在“效率”不在“峰值”**：低负载省 CPU，意味着同样散热/功耗下能留出更多余量给
   QoS、代理、DNS 等用户态进程。
3. **单核瓶颈明显**：两个变体的单核峰值（73–79 %）都远高于总 CPU，说明转发压在 1–2 个核上，
   vmxnet3 多队列没有真正铺开。这是虚拟机环境的结构性限制。
4. **满载 RTT 不能直接比**：测 eBPF 时已经跑到 3.2 Gbit/s，原版只有 2.3 Gbit/s，排队长度不同。
   要下结论需要固定速率重测；本次只把它作为观察记录。

---

## 5. 噪声与限制（重要）

宿主是**共享 ESXi**，同时跑着十几台他人的虚拟机（内存长期只剩 1–1.5 GB 空闲），
同一变体跨轮波动可达 40 %：

- 原版 TCP4 在 6 轮里出现过 2.27 / 2.32 / 3.60 / 3.70 / 3.70 / 4.09 Gbit/s；
- eBPF 在 2.54–3.32 Gbit/s。

因此：

- 表中数字**不能当作精确排名**，只能说明“同一档”；
- 固定负载 CPU 表（3.2）比吞吐表更可信，因为负载被 iperf3 钉住了；
- 绝对数值偏低（2–3 Gbit/s）不代表硬件上限，只代表这台 2 vCPU 虚拟机的上限；
- 没有物理网卡直通、没有 10 G 打流器、也没有 ISP 实网，因此**不能**用这组数据推断
  真实宽带或万兆场景的表现。

---

## 6. 关于 SFE 变体

原计划同时对比 **shortcut-fe + fast-classifier**（SFE）版本，未纳入本报告：

- `shortcut-fe` 不在 ImmortalWrt 的 feeds 里；`immortalwrt/obsolete` 的副本冻结在 2021 年（内核 5.x），
  在 6.18 上无法编译。
- `coolsnowwolf/lede` 仍在维护同名包，但依赖一个内核补丁
  （`953-net-patch-linux-kernel-to-support-shortcut-fe.patch`，给 `sk_buff` 加 `fast_forwarded` 等）。
  该补丁里 `nf_conntrack_ecache.{c,h}` 两段与 OpenWrt 自带的
  `952-net-conntrack-events-support-multiple-registrant.patch` 冲突；裁剪后仍需一次完整构建验证。

在 x86 上 SFE 的预期收益本就有限（它的设计目标是弱 CPU 的 MIPS/ARM 设备），
所以本次先交付原版 vs eBPF 的可信对比。

---

## 7. 复现

实验台与脚本保留在本地 `work/bench/`：

```powershell
python bench.py <variant> <console_port> 3   # 吞吐 / pps / 延迟 / CPU
python load.py <variant> <console_port> 3    # 固定 1/2/3 G 的 CPU
python report.py                             # 汇总
```

要点：vmxnet3 + 隔离 vSwitch、串口管理、WAN 用 `198.18.0.0/24`、小包用 MTU 96 的内核发包路径。
