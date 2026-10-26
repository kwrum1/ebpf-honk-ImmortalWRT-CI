# 数据面实测：原版 vs mydist eBPF

测试日期 2026-10-26 ｜ 环境：单台 ESXi（12 核 / 17 GB）｜ 网卡：vmxnet3 ｜ 路由器：2 vCPU / 1 GB

---

## 1. 结论

| 结论 | 数据 |
|---|---|
| 吞吐同档 | 2.3–3.2 Gbit/s，64 B 小包 32–36 万 pps，差值在宿主噪声内 |
| 同负载更省 CPU | 2 Gbit/s：44 % → 28 %（−16 个百分点） |
| 峰值无差别 | 3 Gbit/s 时两者都撞到单核 ~73 %，61 % vs 63 % |
| 代价是延迟略高 | 满载 RTT 3.36 ms → 10.49 ms（两组负载不同，仅作观察） |

一句话：**2 vCPU 虚拟机里瓶颈在 vSwitch / 软中断，不在 NAT 实现**；
mydist 的收益是"同样流量少用 CPU"，以及 full-cone NAT 与策略能力，而不是更高峰值。

---

## 2. 对比对象

| 维度 | 原版无加速 | mydist eBPF | 实际效果 |
|---|---|---|---|
| NAT | conntrack + `MASQUERADE`（端口受限映射） | einat-ebpf，TC 上做 NAT44（EIM + EIF） | 外网可主动回连；本次未做回连测试 |
| 转发快路径 | 无，每包都过 nft 规则链 | dpd-fastpath：已建立流用 `bpf_fib_lookup` 直接重定向 | 已建立连接少走协议栈；实测 `effective=stateless` 已接管 |
| 入站策略 | fw4 zone / rule | router-acl（eBPF guard，叠加在 fw4 之上） | 无主入站默认丢弃；本次不涉及 |
| 出口整形 | 默认 `fq_codel` | CAKE（逐主机公平 + diffserv4） | 本次**关闭**，否则会把所有变体压到 100 Mbit |
| DNS | dnsmasq 解析 | SmartDNS 独占 :53 | 本次不涉及 |
| Web 前端 | uhttpd | pingora | 本次不涉及 |

被测固件：原版 `X86-VIKINGYFY-owrt-26.10.26-07.24.32`；mydist `X86-kwrum1-mydist-26.10.26-08.00.37`（源码 `a37c1ea`）。两者内核同为 6.18.55。

---

## 3. 测试方法

```
client 192.168.10.198 ──[bench-lan]── router ──[bench-wan]── server 198.18.0.2
                          LAN 192.168.10.1   WAN 198.18.0.1
```

| 项目 | 设置 |
|---|---|
| 网络 | 两台**无上行链路**的独立 vSwitch，与办公网隔离 |
| 管理 | ESXi 虚拟串口（guest `ttyS0`），不占测试网段 |
| 规格 | router 2 vCPU / 1 GB；client 3 vCPU / 448 MB；server 2 vCPU / 448 MB |
| 运行方式 | 两个变体互斥运行，端点机全程不动 |
| 采样 | 每项 3 轮取中位数；路由 CPU 用测试前后 `/proc/stat` 差值 |

| 测试项 | 命令 | 时长 |
|---|---|---|
| TCP 单流 / 4 流 | `iperf3 -c SERVER -t 20 -P 1/4` | 20 s |
| UDP 1400 B | `iperf3 -c SERVER -u -b 0 -l 1400 -t 20` | 20 s |
| 64 B 小包 | 两端 MTU 96，3 个 iperf3 进程并发 | 15 s |
| 延迟 | `ping -c 10 -i 1`（空载 / 4 流满载） | 10 s |
| 固定负载 CPU | `iperf3 -b 1/2/3G -P 4`，每档 3 次 | 3 × 15 s |

两个前提：

- **WAN 用 `198.18.0.0/24`**：einat 默认把 10/8、172.16/12、192.168/16 当内网，用 10.x 做 WAN 时 eBPF 变体不会 SNAT，对比会失效。
- **64 B 小包不用 UDP 打**：iperf3 单进程用户态约 9.7 万 pps，服务端会先丢包；改用 MTU 96（MSS 56）让内核发小包，路由器才是瓶颈。

---

## 4. 结果

### 4.1 吞吐与延迟

| 指标 | 原版 | mydist eBPF | 差距 |
|---|---|---|---|
| TCP 单流 | 2.60 Gbit/s | 3.21 Gbit/s | +23 %（噪声内） |
| TCP 4 流 | 2.32 Gbit/s | 3.23 Gbit/s | +39 %（噪声内） |
| UDP 1400 B | 990 Mbit/s | 1034 Mbit/s | +4 % |
| UDP 丢包 | 3.9 % | 4.8 % | +0.9 pp |
| 64 B 小包 | 322 768 pps | 363 393 pps | +13 %（噪声内） |
| 小包路由 CPU | 72 % | 73 % | 持平 |
| 空闲 RTT | 2.14 ms | 2.12 ms | 持平 |
| 满载 RTT | 3.36 ms | 10.49 ms | 不可直接比（负载不同） |

### 4.2 固定负载下的 CPU

| 固定负载 | 原版 | mydist eBPF | 差距 |
|---|---|---|---|
| 1 Gbit/s | 13 % | 9 % | −31 % |
| 2 Gbit/s | 44 % | 28 % | −36 % |
| 3 Gbit/s | 63 % | 61 % | −3 %（已撞单核上限） |

这一张表最能说明问题：负载被钉住后，eBPF 的每包成本在 1–2 Gbit/s 明显更低；
到 3 Gbit/s，两者都受限于单核软中断（峰值 73–79 %），差距消失。

---

## 5. 差距从哪来

| 现象 | 原因 |
|---|---|
| 吞吐拉不开 | 2–3 Gbit/s 的成本主要在收包、`skb` 分配、软中断、vSwitch；NAT 只占其中一段 |
| 低负载省 CPU | NAT 从 netfilter 移到 TC，已建立流又由 dpd 重定向，省掉了规则链遍历 |
| 3 G 后无差别 | 转发压在 1–2 个核上，vmxnet3 多队列没铺开，先撞单核上限 |
| 满载延迟更高 | eBPF 组测时已跑在 3.2 Gbit/s，原版只有 2.3 Gbit/s，排队长度不同 |

---

## 6. 可信度与限制

- 宿主是**共享 ESXi**（另有十几台他人虚拟机，空闲内存长期 1–1.5 GB），同变体跨轮波动可达 40 %：
  原版 TCP 4 流六轮为 2.27 / 2.32 / 3.60 / 3.70 / 3.70 / 4.09 Gbit/s，eBPF 为 2.54–3.32 Gbit/s。
- 因此吞吐表只能说明"同一档"，**不能当精确排名**；固定负载 CPU 表更可信。
- 绝对数值不代表硬件上限：无网卡直通、无 10 G 打流器、非 ISP 实网。
- SFE（shortcut-fe）未纳入：6.18 需要额外内核补丁，且在 x86 上预期收益有限。

---

## 7. 复现

```powershell
python bench.py <variant> <console_port> 3   # 吞吐 / pps / 延迟 / CPU
python load.py  <variant> <console_port> 3   # 固定 1/2/3 G 的 CPU
python report.py                             # 汇总
```

脚本与原始 JSON 保留在本地 `work/bench/`。
