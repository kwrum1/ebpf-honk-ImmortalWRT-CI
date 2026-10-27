# 数据面实测：原版 / eBPF 优化前 / eBPF 优化后

测试日期 2026-10-27 ｜ 环境：单台 ESXi（12 核 / 17 GB）｜ 网卡：vmxnet3 ｜ 路由器：2 vCPU / 1 GB

---

## 1. 结论

| 结论 | 数据 |
|---|---|
| 优化后 eBPF 比优化前快 | TCP 4 流 4.25 → **5.37 Gbit/s**（+26%），单流 3.91 → 4.85（+24%） |
| 优化后 eBPF 比原版快 | TCP 4 流 4.47 → **5.37**（+20%），64B 小包 27.9 → **39.1 万 pps**（+40%） |
| 满载延迟明显下降 | 12.4 ms → **5.24 ms**（固定负载下；原版 12.7 ms） |
| 高负载更省 CPU | 3 Gbit/s 固定负载：53%（原版）/ 48%（优化前）/ **41%**（优化后） |

一句话：**优化后的 eBPF 在吞吐、小包 pps、满载延迟三项上都优于原版**，代价是低负载 CPU 略高（小包 pps 工况 69% vs 51%）。

---

## 2. 三个被测固件

| 变体 | 固件 | 数据面 |
|---|---|---|
| 原版无加速 | `X86-VIKINGYFY-owrt-26.10.26-07.24.32` | fw4 nftables conntrack + `MASQUERADE` |
| eBPF 优化前 | `X86-kwrum1-mydist-26.10.26-08.00.37`（源码 `a37c1ea`） | einat NAT + dpd stateless，只加速 LAN→WAN |
| eBPF 优化后 | `mydist` @ `ff48b36`（同一个镜像热换 dpd 对象） | einat NAT + dpd stateful：GSO 快路径、L2 直发、双向加速 |

三者内核同为 6.18.55；优化前后只差 dpd 程序与模式，einat 与其余组件完全相同。

---

## 3. 测试方法

```
client 192.168.10.204 ──[bench-lan]── router ──[bench-wan]── server 198.18.0.2
                             LAN 192.168.10.1   WAN 198.18.0.1
```

| 项目 | 设置 |
|---|---|
| 网络 | 两台无上行链路的独立 vSwitch，与办公网隔离 |
| 管理 | ESXi 虚拟串口（guest `ttyS0`），不占测试网段 |
| 规格 | router 2 vCPU / 1 GB；client 3 vCPU / 448 MB；server 2 vCPU / 448 MB |
| 采样 | 每项 3 轮取中位数；路由 CPU 用测试前后 `/proc/stat` 差值 |
| 测试项 | TCP 单流 / 4 流 20 s、UDP 1400 B 20 s、64 B 小包 15 s、ping 空载/满载、固定 1/2/3 G CPU |

两个前提：WAN 用 `198.18.0.0/24`（einat 默认把 10/8 当内网）；64 B 小包用 MTU 96 让内核发包（iperf3 UDP 会被用户态限死在 ~9.7 万 pps）。

---

## 4. 结果

### 4.1 吞吐 / pps / 延迟

| 指标 | 原版无加速 | eBPF 优化前 | eBPF 优化后 |
|---|---|---|---|
| TCP 单流 | 2.68 Gbit/s | 3.91 Gbit/s | **4.85 Gbit/s** |
| TCP 4 流 | 4.47 Gbit/s | 4.25 Gbit/s | **5.37 Gbit/s** |
| UDP 1400 B | 1141 Mbit/s | 1031 Mbit/s | 1115 Mbit/s |
| UDP 丢包 | 0.42 % | 2.30 % | 0.62 % |
| 64 B 小包 | 279 018 pps | 350 446 pps | **390 625 pps** |
| 小包路由 CPU | 51 % | 69 % | 69 % |
| TCP4 路由 CPU | 80 % | 74 % | 74 % |
| TCP4 单核峰值 | 83 % | 81 % | **75 %** |
| 空闲 RTT | 2.11 ms | 0.81 ms | 0.73 ms |
| 满载 RTT | 12.73 ms | 12.38 ms | **5.24 ms** |

### 4.2 固定负载下的 CPU

| 固定负载 | 原版无加速 | eBPF 优化前 | eBPF 优化后 |
|---|---|---|---|
| 1 Gbit/s | 9 % | 8 % | 9 % |
| 2 Gbit/s | 23 % | 21 % | 23 % |
| 3 Gbit/s | 53 % | 48 % | **41 %** |

低负载三者的 CPU 基本相同（转发成本主要在收包/软中断）；到 3 Gbit/s，
优化后的 eBPF 明显更省 CPU，也把单核峰值从 83% 压到 75%。

---

## 5. 优化做了什么

| 优化 | 机制 | 实测效果 |
|---|---|---|
| **GSO/GRO 快路径** | `bpf_fib_lookup` 用 `skb->gso_size` 做 MTU 检查，聚合包不再被判"需分片" | `fib_fail` 60% → 0，吞吐 +10% |
| **L2 直发** | 用 fib 的 `dmac/smac` 拼以太头 + `bpf_redirect()`，省掉每包 `redirect_neigh` 的二次 FIB+邻居查找 | 每包 CPU −10% |
| **双向加速** | 上行口 ingress 也挂 dpd（只对已学习流生效，首包仍走 netfilter） | 下载 +16%，上传 +6% |
| **默认 stateful** | 每包只做流表查找 + TTL + redirect；stateless 每包重跑 FIB | 4.6–5.0 vs 4.3–4.9 Gbit/s |

风险边界：被接管的包不再更新 conntrack 记账、不进 fw4 forward 链、跳过 `mangle_forward`；
需要下载方向逐包配额/限速的盒子设 `option downlink '0'`。

---

## 6. 解读

1. **为什么优化后比优化前快**：优化前每个包都要 FIB 查表 + 邻居查找，且大包（GRO）直接被拒绝加速；
   优化后大包也走快路径、L2 头直接写、回程也被接管，单核工作量显著下降。
2. **为什么原版吞吐不低但延迟差**：原版每个包都过 conntrack + nft 规则链，CPU 花在协议栈里；
   排队更长，满载 RTT 12.7 ms。eBPF 快路径把大部分包从协议栈里拿走，满载 RTT 降到 5.2 ms。
3. **低负载 CPU 反而略高**：eBPF 的 per-flow 记账/流表维护在轻载时是净开销；
   但固定 3 G 时反转（41% vs 53%），说明收益随负载增长。
4. **小包 pps**：优化后 39 万 pps 是**测试台上限**（3 个 iperf3 进程的用户态发包限制），
   不代表路由器上限。

---

## 7. 可信度与限制

- 宿主共享（另有十几台他人虚拟机），同变体跨轮波动可达 40%；表中是 3 轮中位数，
  且三组是**相邻时段**测得，但仍不能当精确排名。
- 绝对数值不代表硬件上限：无网卡直通、无 10 G 打流器、非 ISP 实网。
- 64 B pps 受测试端限制；真实上限需要专用打流器。

---

## 8. 复现

```powershell
python bench.py <variant> <console_port> 3   # 吞吐 / pps / 延迟 / CPU
python load.py  <variant> <console_port> 3   # 固定 1/2/3 G 的 CPU
python compare3.py                           # 三列对比
```

原始 JSON：`work/bench/results/`。优化前后差异只来自 dpd 对象与模式，其余不变。
