# mydist / router-dns

**SmartDNS 是唯一解析器（`:53`）；dnsmasq 不再承担 DNS，也不再承担 DHCP。**

最终状态由 `mydist-posture`（S26）在每次启动时强制：

| 项 | 值 |
|---|---|
| `smartdns.@smartdns[0].port` | `53` |
| `dhcp.@dnsmasq[0].port` | `0`（并 stop + disable） |
| `dhcp.lan.ignore` / `master` | `0` / `1`（odhcpd 发地址） |
| `firewall.mydist999` | 存在且 `enabled=1`（wan→lan，v4+v6，REJECT） |

`/etc/uci-defaults/97-mydist-dns` 只负责让**首次启动、S26 之前**也处于同一状态，避免“S26 没跑到”时留下 dnsmasq 占着 :53 的中间态。

## 装了什么

| 路径 | 作用 |
|---|---|
| `/etc/uci-defaults/97-mydist-dns` | SmartDNS `:53`、`auto_set_dnsmasq=0`、dnsmasq `:0`、DoT 上游、启用 smartdns 与 router-dns |
| `/etc/init.d/router-dns`（S18） | 每次启动执行 `router-honk-dns patch`，把 honk 的 DNS 交还给 SmartDNS |
| `/usr/libexec/router-honk-dns` | 幂等修补 `/etc/honk/config.dae` + 迁移旧 UDP 上游到 DoT |

## 上游选择

SmartDNS 使用 **DoT（TCP 853）** 而不是明文 UDP，原因见 `honk-dns.sh` 顶部注释：

- honk 运行时，路由器**本机发出的 UDP** 可能无法完成（实测 2026-10-18：直连与代理都超时，本地 TCP 正常）；
- 纯 UDP 上游会让“冷启动解析”全部失败，而缓存命中的测试看不出来；
- DoT 走 TCP，honk 开/关都能用。

默认上游：`223.5.5.5`（`dns.alidns.com`）、`119.29.29.29`（`dot.pub`），外加一条明文 `223.5.5.5` 兜底。只在“没有任何 `@server` 配置”时写入；用户自定义过就不动。

## 与 honk 的关系

honk 默认会接管 LAN 的 `:53`（见 `openwrt-honk` 的 `main` 分支）。这边的 `honk-dns.sh` 在 honk 启动前把它改成：

```
routing {
    dport(53) -> direct(must)      # 第一条
    dip(geoip: private) -> direct(must)
    dip(geoip: cn) -> direct(must)
    ...
}
dns { upstream { default: 'udp://127.0.0.1:53' } }
```

- `config.dae` 是 conffile，升级不会覆盖；所以每次启动都重打一遍，并且 UI 改写坏了会用 `.mydist.bak` 恢复后再打。
- 只改 `default` 上游，用户自己设置的其它上游保持原样。
- honk 未安装/未启用时，`honk-dns.sh` 是 no-op。

## 排障

```sh
uci get smartdns.@smartdns[0].port     # 期望 53
uci get dhcp.@dnsmasq[0].port          # 期望 0
pgrep -f /usr/sbin/smartdns            # 应有进程
/usr/libexec/router-honk-dns status        # 看 honk 的 dns/routing 段
nslookup openwrt.org 127.0.0.1
```
