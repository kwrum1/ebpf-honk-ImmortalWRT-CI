import io

p = r"C:\路由设计\work\gh\src\ebpf\router-dataplane\src\dpd_fastpath.bpf.c"
s = io.open(p, encoding="utf-8").read()

start = s.index('SEC(DPD_SEC_NAME)\nint dpd_fastpath(struct __sk_buff *skb)')
end = s.index('char _license[] SEC("license") = "GPL";')

new = r'''SEC(DPD_SEC_NAME)
int dpd_fastpath(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dpd_config *cfg;
	struct dpd_flow_key fkey = {};
	struct dpd_stat_val *st;
	struct ethhdr *eth;
	__u32 l3_off = sizeof(*eth);
	__u16 h_proto;
	__u16 vlan_id = 0;	/* the 802.1Q/802.1AD VID, if tagged	*/
	__u8 tagged = 0;
	int ret;

	cfg = dpd_get_cfg();
	if (!cfg)
		return TC_ACT_UNSPEC;

	st = dpd_stat();
	DPD_INC(st, ST_PKT_TOTAL);
	DPD_ADD(st, ST_BYTES, skb->len);

	eth = data;
	if ((void *)(eth + 1) > data_end) {
		DPD_INC(st, ST_NON_IP);
		return TC_ACT_UNSPEC;
	}
	h_proto = bpf_ntohs(eth->h_proto);

	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct dpd_vlan_hdr *vh = data + l3_off;

		if ((void *)(vh + 1) > data_end) {
			DPD_INC(st, ST_NON_IP);
			return TC_ACT_UNSPEC;
		}
		h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
		vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0fff;
		tagged = 1;
		l3_off += sizeof(*vh);
	}

	fkey.ifindex = skb->ifindex;

	if (h_proto == ETH_P_IP) {
		struct iphdr *iph = data + l3_off;
		__u32 ihl;

		if ((void *)(iph + 1) > data_end)
			goto non_ip;
		if (iph->version != 4 || iph->ihl < 5 || iph->ihl > 15)
			goto non_ip;
		ihl = (__u32)iph->ihl * 4;
		if ((void *)iph + ihl > data_end)
			goto non_ip;

		/* fragments: see dpd_may_accelerate() -- no honest L4 header,
		 * no honest flow key, nothing to gate the :53 check on. */
		if (iph->frag_off & bpf_htons(DPD_IP_MF | DPD_IP_OFFMASK)) {
			DPD_INC(st, ST_FRAG_SKIP);
			return TC_ACT_UNSPEC;
		}

		fkey.family = AF_INET;
		fkey.proto = iph->protocol;
		fkey.saddr[3] = iph->saddr;
		fkey.daddr[3] = iph->daddr;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *th = (void *)iph + ihl;

			if ((void *)(th + 1) <= data_end) {
				fkey.sport = th->source;
				fkey.dport = th->dest;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = (void *)iph + ihl;

			if ((void *)(uh + 1) <= data_end) {
				fkey.sport = uh->source;
				fkey.dport = uh->dest;
			}
		}
	} else if (h_proto == ETH_P_IPV6) {
		/*
		 * Never accelerated (no NAT66 in this baseline, so the reply of a
		 * taken-over v6 flow would arrive untracked and fw4's forward
		 * chain would reject it) -- and therefore never worth a FIB
		 * lookup either. ABI 9 moved the rejection in front of the
		 * lookup; before that every v6 packet paid for a route lookup it
		 * could only ever fail.
		 */
		DPD_INC(st, ST_V6_SKIP);
		return TC_ACT_UNSPEC;
	} else {
		goto non_ip;
	}

	/* Every gate below needs no route: family, :53, DHCP, non-unicast and
	 * the VLAN policy all read the flow key or the config. Running them
	 * before bpf_fib_lookup() is what keeps DNS/broadcast/v6 traffic from
	 * paying for an acceleration it can never get. */
	if (!dpd_may_accelerate(cfg, vlan_id, tagged, &fkey, st))
		return TC_ACT_UNSPEC;

	/* ---- Mode B: try the self-learned shortcut first ---- */
	if (cfg->mode == DPD_MODE_STATEFUL) {
		__u32 now = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
		__u32 ttl = cfg->flow_ttl_ms;
		struct dpd_flow_val *fval;
		__s32 age;

		/* the freshness test is a *signed* difference: last_seen_ms is a
		 * 32-bit truncation, so an absolute compare would expire every
		 * flow once per 49.7 days. A negative age means the timestamp is
		 * "in the future" (that only happens across that wrap for an
		 * entry nobody refreshed) and is treated as expired. */
		if (ttl > 86400000u)	/* one day: keep the cast in range */
			ttl = 86400000u;

		fval = bpf_map_lookup_elem(&dpd_flows, &fkey);
		age = fval ? (__s32)(now - fval->last_seen_ms) : 0;
		if (fval && fval->egress_ifindex && age >= 0 &&
		    age < (__s32)ttl &&
		    /* epoch: a topology change (link, address, route,
		     * neighbour, WAN re-pick) bumps cfg->epoch and every entry
		     * learned before it stops matching. This one byte compare
		     * replaces the per-packet dpd_wans + dpd_iface re-validation
		     * the hit path used to do. */
		    (fval->wan & DPD_FLOW_EPOCH_MASK) ==
			((cfg->epoch & 0xff) << 8)) {
			__u32 primed = (fval->flags & DPD_FLOW_PRIME_MASK) >>
				       DPD_FLOW_PRIME_SHIFT;

			/*
			 * Prime the direction: the entry is usable, but the
			 * first DPD_FLOW_PRIME hits are handed to the stack
			 * instead of being redirected.
			 *
			 * Why this is not just politeness: taking over the
			 * second packet of a TCP flow means netfilter never
			 * sees the final ACK, so the conntrack entry stays in
			 * SYN_RECV and expires on the 120 s syn_recv timer
			 * while a bulk flow is still running (measured
			 * 2026-10-27: a 12.4 GB download left packets=1
			 * bytes=60 in the table). Letting one more packet per
			 * direction through completes the handshake.
			 */
			if (primed < DPD_FLOW_PRIME) {
				fval->flags = (fval->flags & ~DPD_FLOW_PRIME_MASK) |
					      ((primed + 1) << DPD_FLOW_PRIME_SHIFT);
				dpd_touch(fval, now, cfg->flow_refresh_ms);
				/* not counted as a hit: ST_FLOW_HIT keeps
				 * meaning "packets this program took over". */
				return TC_ACT_UNSPEC;
			}

			DPD_INC(st, ST_FLOW_HIT);
			dpd_touch(fval, now, cfg->flow_refresh_ms);

			/* Only the VLAN policy is re-checked here: every other
			 * gate reads a field of the flow key, and the entry was
			 * only written after those passed. The policy can be
			 * changed by the operator while a flow is live. */
			if (!dpd_policy_ok(cfg, vlan_id, tagged, st))
				return TC_ACT_UNSPEC;

			ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
			if (ret > 0) {
				DPD_INC(st, ST_TTL_DROP);
				return TC_ACT_SHOT;
			}
			if (ret < 0)
				return TC_ACT_UNSPEC;

			return dpd_emit_cached(skb, fval->egress_ifindex,
					       fval->flags, fval->dmac,
					       fval->smac, st);
		}
		DPD_INC(st, ST_FLOW_MISS);
	}

	/* ---- FIB lookup, shared by every mode ---- */
	{
		struct bpf_fib_lookup fib = {};
		struct iphdr *iph = data + l3_off;
		__u32 ihl;
		int no_neigh = 0;	/* FIB needed SKIP_NEIGH: no neighbour */

		if ((void *)(iph + 1) > data_end)
			return TC_ACT_UNSPEC;
		ihl = (__u32)iph->ihl * 4;

		fib.ifindex = skb->ifindex;
		fib.family = AF_INET;
		fib.l4_protocol = fkey.proto;
		fib.tot_len = bpf_ntohs(iph->tot_len);
		fib.ipv4_src = fkey.saddr[3];
		fib.ipv4_dst = fkey.daddr[3];
		fib.sport = fkey.sport;
		fib.dport = fkey.dport;

		/*
		 * GRO/GSO: the header carries the *aggregate* length (up to 64
		 * KB), which is larger than the MTU. bpf_fib_lookup() then
		 * answers FRAG_NEEDED and the packet is refused -- so the bulk
		 * of the bytes (the coalesced segments) never took the fast
		 * path. Measured 2026-10-27 with GRO on: fib_ok 100k vs
		 * fib_fail 145k, i.e. 60% of packets went the slow path; with
		 * GRO off fib_fail fell to 0 but throughput dropped from 4.5 to
		 * 0.95 Gbit/s because the packet count tripled.
		 *
		 * The MTU test only has to hold for ONE segment, and a segment
		 * is not gso_size: gso_size is the payload length, without the
		 * IP and L4 headers (this is what ABI 9 fixed -- using
		 * gso_size alone under-counted the segment by 28..60 bytes and
		 * could let a segment that really exceeds the MTU through).
		 *   TCP: ihl + th->doff*4 + gso_size
		 *   UDP: ihl + 8          + gso_size
		 * If the L4 header is not parseable, fall back to ihl+payload.
		 */
		if (skb->gso_size) {
			__u32 seg = ihl + skb->gso_size;

			if (fkey.proto == IPPROTO_TCP) {
				struct tcphdr *th = (void *)iph + ihl;

				if ((void *)(th + 1) <= data_end)
					seg += (__u32)th->doff * 4;
			} else if (fkey.proto == IPPROTO_UDP) {
				seg += 8;
			}
			if (seg < fib.tot_len)
				fib.tot_len = (__u16)seg;
		}

		ret = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
		if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
			/* ppp and tunnels have no neighbour table, so the first
			 * pass answers NO_NEIGH even though the route is right
			 * there. Ask for the route only; the emit path for such
			 * a device is bpf_redirect(ifindex), which needs no L2
			 * header. Measured 2026-10-18 on a PPPoE WAN before this
			 * retry: every packet of a working client flow ended in
			 * fib_fail, so acceleration never fired on ppp at all. */
			DPD_INC(st, ST_FIB_RETRY);
			no_neigh = 1;
			ret = bpf_fib_lookup(skb, &fib, sizeof(fib),
					     BPF_FIB_LOOKUP_SKIP_NEIGH);
		}
		if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
			DPD_INC(st, ST_FIB_FAIL);
			return TC_ACT_UNSPEC;
		}
		DPD_INC(st, ST_FIB_OK);

		/* never accelerate traffic that is local to this box */
		if (!fib.ifindex || fib.ifindex == skb->ifindex) {
			DPD_INC(st, ST_LOCAL);
			return TC_ACT_UNSPEC;
		}

		/* ---- Mode 0: observe only. never touch the packet. ---- */
		if (cfg->mode == DPD_MODE_OBSERVE)
			return TC_ACT_UNSPEC;

		/* ---- Mode A (and the #14 probe): take the packet over now ---- */
		if (cfg->mode != DPD_MODE_STATEFUL) {
			__u16 cls = dpd_emit_class(cfg, fib.ifindex, no_neigh,
						   !tagged);

			ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
			if (ret > 0) {
				DPD_INC(st, ST_TTL_DROP);
				return TC_ACT_SHOT;
			}
			if (ret < 0)
				return TC_ACT_UNSPEC;

			return dpd_emit_cached(skb, fib.ifindex, cls, fib.dmac,
					       fib.smac, st);
		}

		/* ---- Mode B: learn the shortcut, this packet stays slow ---- */
		{
			struct dpd_flow_val nv = {};
			__u16 cls = dpd_emit_class(cfg, fib.ifindex, no_neigh,
						   !tagged);

			nv.egress_ifindex = fib.ifindex;
			nv.last_seen_ms = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
			nv.flags = cls | (no_neigh ? DPD_FLOW_F_NO_NEIGH : 0);
			nv.wan = (__u16)((__u32)(cfg->epoch & 0xff) << 8);
			__builtin_memcpy(nv.dmac, fib.dmac, ETH_ALEN);
			__builtin_memcpy(nv.smac, fib.smac, ETH_ALEN);

			/*
			 * Multi-WAN: pick an uplink by weighted rendezvous and
			 * steer the slow path of this new flow with a fwmark
			 * (the daemon installs `ip rule fwmark <mark> lookup
			 * <table>` plus a default route per WAN). Only for
			 * packets that did not arrive on an uplink -- downlink
			 * traffic already has its egress (the LAN).
			 *
			 * The FIB lookup above still decides "is this
			 * forwardable at all" (local/unreachable packets return
			 * early), it just no longer decides *which* uplink.
			 */
			if (!dpd_is_uplink(skb->ifindex)) {
				int wi = dpd_pick_wan(&fkey);

				if (wi >= 0 && wi < DPD_WAN_MAX) {
					struct dpd_wan w;

					if (dpd_wan_get((__u32)wi, &w) == 0 &&
					    w.ifindex) {
						nv.egress_ifindex = w.ifindex;
						nv.wan = (__u16)((__u32)(wi + 1) |
							((__u32)(cfg->epoch & 0xff) << 8));
						/* ppp/tun uplinks have no L2
						 * header to write; everything else
						 * gets the usual decision. */
						nv.flags = (w.flags & DPD_WAN_F_L3)
							? (DPD_FLOW_F_DEV | DPD_FLOW_F_WAN)
							: (dpd_emit_class(cfg, w.ifindex, 0, 1) |
							   DPD_FLOW_F_WAN);
						__builtin_memcpy(nv.dmac, w.gw_mac, ETH_ALEN);
						__builtin_memcpy(nv.smac, w.dev_mac, ETH_ALEN);
						skb->mark = w.mark;
					}
				}
			}

			bpf_map_update_elem(&dpd_flows, &fkey, &nv, BPF_ANY);
			/* the map write may have invalidated the cached stats
			 * pointer; re-fetch before counting */
			st = dpd_stat();
			DPD_INC(st, ST_FLOW_WRITE);
			return TC_ACT_UNSPEC;
		}
	}

non_ip:
	DPD_INC(st, ST_NON_IP);
	return TC_ACT_UNSPEC;
}

'''

s = s[:start] + new + s[end:]
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("main rewritten,", len(s.splitlines()), "lines")
