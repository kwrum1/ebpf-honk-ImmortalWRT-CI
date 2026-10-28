#!/usr/bin/env python3
#
# einat perf patch p2 (applied after einat-perf.py).
#
# Two changes, both aimed at the per-packet cost of the TC datapath. Neither
# touches how a NAT mapping is allocated or looked up, i.e. neither can change
# the full-cone (EIM+EIF) behaviour that tests/e2e.sh verifies.
#
# 1) dest_config fast path
#    The egress program looks up map_*_dest_config(destination) on every packet
#    only to find hairpin/pass-nat destinations. On a plain router that map
#    holds nothing but the WAN address itself, so for every packet going to the
#    internet the lookup is a guaranteed miss -- and it is an LPM lookup, the
#    most expensive map type in the program. The loader now tells the datapath
#    which of three cases applies, via a .data global it updates whenever the
#    maps change:
#        0 = no dest_config entry at all      -> no lookup, ever
#        1 = only the default external address -> 32-bit compare, then lookup
#        2 = anything else                     -> always look up (upstream)
#    Case 1 is exact: with a single entry equal to the default external
#    address, the lookup can only hit when the destination equals it.
#
# 2) established-TCP CT fast path
#    In CT_ESTABLISHED a TCP data packet only refreshes the CT timer (see
#    ct_state_transition()). That is a map lookup plus bpf_timer_start() -- the
#    latter takes a lock -- on every single packet, in both directions. The
#    packet now skips both when the previous slow-path lookup, recorded in the
#    binding value, was less than CT_FAST_PATH_MS ago. Everything that can
#    change CT state (SYN/FIN/RST, ICMP errors, non-TCP protocols, states other
#    than ESTABLISHED) still takes the slow path, so the only difference is
#    that the timer is refreshed at most once per CT_FAST_PATH_MS instead of
#    once per packet.
#
import io
import sys

TREE = sys.argv[1] if len(sys.argv) > 1 else "."
TREE = TREE.rstrip("/")
BPF = TREE + "/src/bpf/einat.bpf.c"
HDR = TREE + "/src/bpf/einat.h"
TYPES = TREE + "/src/skel/einat/types.rs"
SKEL_MOD = TREE + "/src/skel/einat/mod.rs"
AYA = TREE + "/src/skel/einat/aya.rs"
INST_MOD = TREE + "/src/instance/mod.rs"


def patch(path, old, new, tag, count=1):
    s = io.open(path, encoding="utf-8").read()
    if new in s:
        print("  already patched:", tag)
        return
    found = s.count(old)
    if found != count:
        raise SystemExit(
            "  anchor not found exactly %d time(s) (%d): %s\n%s"
            % (count, found, tag, old)
        )
    io.open(path, "w", encoding="utf-8", newline="\n").write(
        s.replace(old, new, count)
    )
    print("  patched:", tag)


# ---------------------------------------------------------------- datapath ---

# The mode global is placed between g_deleting_map_entries and
# g_next_binding_seq so that the .data layout stays: ext addr(s), deleting flag,
# our mode byte(s), then the u32 sequence. src/skel/einat/types.rs mirrors it.
patch(
    BPF,
    """u8 g_deleting_map_entries SEC(".data") = 0;

u32 g_next_binding_seq = 0;
""",
    """u8 g_deleting_map_entries SEC(".data") = 0;

// How the egress path should treat the dest_config maps:
//   0 = no entry at all, the lookup can be skipped outright
//   1 = the only entry is the default external address, compare the packet
//       destination against it and only look up on a match
//   2 = arbitrary entries, always look up (upstream behaviour)
// Written by the userspace loader from the live configuration.
u8 g_ipv4_dest_config_mode SEC(".data") = 2;
#ifdef FEAT_IPV6
u8 g_ipv6_dest_config_mode SEC(".data") = 2;
#endif

u32 g_next_binding_seq = 0;
""",
    "dest_config mode globals",
)

patch(
    BPF,
    """const volatile u64 TIMEOUT_TCP_EST = 7200E9;
""",
    """const volatile u64 TIMEOUT_TCP_EST = 7200E9;

// Milliseconds between two CT timer refreshes of an established TCP flow
// before the datapath is forced back onto the slow path. 0 disables the fast
// path (every packet then looks the CT up, as upstream does).
const volatile u64 CT_FAST_PATH_MS = 1000;
""",
    "CT_FAST_PATH_MS rodata",
)

# Binding-side cache for the fast path.
patch(
    HDR,
    """    u32 outbound_ref;
    u32 ref;
    u32 seq;
};
""",
    """    u32 outbound_ref;
    u32 ref;
    u32 seq;
    // Last CT state observed for this binding by the slow path, and the ktime
    // (in ms) of that lookup. Used by ct_fast_path() to decide that a TCP data
    // packet can skip the CT lookup and the timer refresh.
    u32 ct_state_cached;
    u32 ct_touch_ms;
};
""",
    "map_binding_value ct cache",
)

# The fast dest_config lookup itself.
patch(
    BPF,
    """static __always_inline bool dest_hairpin(struct dest_config *config) {
""",
    """// Only hairpin/pass-nat destinations live in the dest_config maps, and on a
// router those maps hold nothing but the WAN address itself. The egress hook
// sees every packet, so the loader tells us which case applies and the lookup
// can be skipped for the overwhelming majority of destinations.
static __always_inline struct dest_config *
lookup_dest_config_fast(bool is_ipv4, const union u_inet_addr *addr) {
#ifdef FEAT_IPV6
    u8 mode = is_ipv4 ? g_ipv4_dest_config_mode : g_ipv6_dest_config_mode;
    if (mode == 0)
        return NULL;
    if (mode == 1) {
        if (is_ipv4) {
            if (addr->ip != g_ipv4_external_addr)
                return NULL;
        } else if (__builtin_memcmp(addr->ip6, g_ipv6_external_addr,
                                    sizeof(g_ipv6_external_addr)) != 0) {
            return NULL;
        }
    }
#else
    if (g_ipv4_dest_config_mode == 0)
        return NULL;
    if (g_ipv4_dest_config_mode == 1 && addr->ip != g_ipv4_external_addr)
        return NULL;
#endif
    return lookup_dest_config(is_ipv4, addr);
}

static __always_inline bool dest_hairpin(struct dest_config *config) {
""",
    "lookup_dest_config_fast",
)

# Egress uses the fast lookup.
patch(
    BPF,
    """    struct dest_config *dest_config =
        lookup_dest_config(PKT_IS_IPV4(), &pkt.tuple.daddr);
""",
    """    struct dest_config *dest_config =
        lookup_dest_config_fast(PKT_IS_IPV4(), &pkt.tuple.daddr);
""",
    "egress uses lookup_dest_config_fast",
)

# The fast path helpers, placed right before the two TC programs.
patch(
    BPF,
    """SEC("classifier")
int ingress_rev_snat(struct __sk_buff *skb) {
""",
    """// Record what the slow path just saw, so the fast path can tell whether
// skipping the CT lookup for a following packet is safe.
static __always_inline void ct_cache_store(struct map_binding_value *b_value,
                                           const struct map_ct_value *ct_value) {
    b_value->ct_state_cached = ct_value->state;
    b_value->ct_touch_ms = bpf_ktime_get_ns() / 1000000;
}

// In CT_ESTABLISHED a TCP data packet only refreshes the CT timer, so for a
// short while after a real lookup the lookup and the timer restart can both be
// skipped. Anything that can move the state machine (SYN/FIN/RST), any other
// protocol, an ICMP error, or a state other than ESTABLISHED still takes the
// slow path. The timer refresh is throttled to CT_FAST_PATH_MS, not disabled.
static __always_inline bool
ct_fast_path(const struct map_binding_value *b_value,
             const struct packet_info *pkt, bool is_icmpx_error) {
    if (CT_FAST_PATH_MS == 0)
        return false;
    if (is_icmpx_error)
        return false;
    if (pkt->pkt_type != PKT_TCP_DATA)
        return false;
    if (b_value->ct_state_cached != CT_ESTABLISHED)
        return false;

    u32 now_ms = bpf_ktime_get_ns() / 1000000;
    return (u32)(now_ms - b_value->ct_touch_ms) < CT_FAST_PATH_MS;
}

SEC("classifier")
int ingress_rev_snat(struct __sk_buff *skb) {
""",
    "ct_fast_path helpers",
)

# Ingress CT block: skip on the fast path, refresh the cache otherwise.
patch(
    BPF,
    """    if (!b_value_rev->is_static) {
        bool do_inbound_ct =
            !g_deleting_map_entries && !is_icmpx_error &&
            ((b_value_rev->outbound_ref != 0 &&
              pkt_allow_initiating_ct(pkt.pkt_type)) ||
             (do_inbound_binding &&
              inet_addr_equal(&b_value_rev->to_addr, &pkt.tuple.daddr)));

        struct map_ct_value *ct_value;
        ret = ingress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                       do_inbound_ct, &pkt.tuple, b_value_rev,
                                       &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, false,
                                b_value_rev, ct_value);
        }
    }
""",
    """    if (!b_value_rev->is_static &&
        !ct_fast_path(b_value_rev, &pkt, is_icmpx_error)) {
        bool do_inbound_ct =
            !g_deleting_map_entries && !is_icmpx_error &&
            ((b_value_rev->outbound_ref != 0 &&
              pkt_allow_initiating_ct(pkt.pkt_type)) ||
             (do_inbound_binding &&
              inet_addr_equal(&b_value_rev->to_addr, &pkt.tuple.daddr)));

        struct map_ct_value *ct_value;
        ret = ingress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                       do_inbound_ct, &pkt.tuple, b_value_rev,
                                       &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, false,
                                b_value_rev, ct_value);
        }
        ct_cache_store(b_value_rev, ct_value);
    }
""",
    "ingress ct fast path",
)

# Egress CT block, same treatment.
patch(
    BPF,
    """    if (!b_value_orig->is_static) {
        struct map_ct_value *ct_value;
        ret = egress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                      do_new, &pkt.tuple, b_value_orig,
                                      b_value_rev, &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, true,
                                b_value_orig, ct_value);
        }
    }
""",
    """    if (!b_value_orig->is_static &&
        !ct_fast_path(b_value_orig, &pkt, is_icmpx_error)) {
        struct map_ct_value *ct_value;
        ret = egress_lookup_or_new_ct(skb->ifindex, PKT_IS_IPV4(), pkt.nexthdr,
                                      do_new, &pkt.tuple, b_value_orig,
                                      b_value_rev, &ct_value);
        if (ret == LK_CT_NONE || ret == LK_CT_ERROR_NEW) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error && ret == LK_CT_EXIST) {
            ct_state_transition(skb->ifindex, pkt.nexthdr, pkt.pkt_type, true,
                                b_value_orig, ct_value);
        }
        ct_cache_store(b_value_orig, ct_value);
    }
""",
    "egress ct fast path",
)

# ------------------------------------------------------------------- loader ---

patch(
    TYPES,
    """    pub TIMEOUT_TCP_EST: u64,
}
""",
    """    pub TIMEOUT_TCP_EST: u64,
    /// How long an established TCP flow may skip the CT lookup (and timer
    /// refresh) after the last slow-path lookup. 0 disables the fast path.
    pub CT_FAST_PATH_MS: u64,
}
""",
    "EinatRoData CT_FAST_PATH_MS",
)

patch(
    TYPES,
    """            TIMEOUT_TCP_EST: 7200 * E9,
""",
    """            TIMEOUT_TCP_EST: 7200 * E9,
            CT_FAST_PATH_MS: 1000,
""",
    "EinatRoData default CT_FAST_PATH_MS",
)

patch(
    TYPES,
    """        pub g_deleting_map_entries: u8,
    }
""",
    """        pub g_deleting_map_entries: u8,
        // 0 = dest_config is empty, 1 = only the default external address,
        // 2 = arbitrary entries. See lookup_dest_config_fast().
        pub g_ipv4_dest_config_mode: u8,
        #[cfg(feature = "ipv6")]
        pub g_ipv6_dest_config_mode: u8,
    }
""",
    "EinatData dest_config mode",
)

patch(
    TYPES,
    """        pub use_: u32,
        pub ref_: u32,
        pub seq: u32,
    }
""",
    """        pub use_: u32,
        pub ref_: u32,
        pub seq: u32,
        /// Last CT state observed for this binding by the slow path.
        pub ct_state_cached: u32,
        /// ktime (ms) of that slow-path CT lookup.
        pub ct_touch_ms: u32,
    }
""",
    "MapBindingValue ct cache",
)

patch(
    SKEL_MOD,
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap;
}
""",
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap;

    /// Tell the datapath how the dest_config map looks, so that it can skip the
    /// per-packet lookup when the destination cannot possibly match:
    /// 0 = no entries at all, 1 = only the default external address,
    /// 2 = arbitrary entries. Backends that cannot update globals keep the safe
    /// default (2, i.e. always look up).
    fn set_dest_config_mode(&mut self, _mode: u8) -> Result<()> {
        Ok(())
    }
}
""",
    "EinatEbpfInet::set_dest_config_mode",
)

patch(
    AYA,
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv4_dest_config
    }
}
""",
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv4_dest_config
    }

    fn set_dest_config_mode(&mut self, mode: u8) -> Result<()> {
        self.alter_data_with(|data| data.g_ipv4_dest_config_mode = mode)
    }
}
""",
    "aya ipv4 set_dest_config_mode",
)

patch(
    AYA,
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv6_dest_config
    }
}
""",
    """    fn map_dest_config(&mut self) -> &mut Self::MapDestConfigMap {
        &mut self.map_ipv6_dest_config
    }

    fn set_dest_config_mode(&mut self, mode: u8) -> Result<()> {
        self.alter_data_with(|data| data.g_ipv6_dest_config_mode = mode)
    }
}
""",
    "aya ipv6 set_dest_config_mode",
)

patch(
    INST_MOD,
    """    let set_addr = old.is_none_or(|old| old.external_addr != config.external_addr);
""",
    """    // Keep the datapath's dest_config fast path in sync with the maps. Mode 2
    // (always look up) is applied first, so a stale mode can never make the
    // datapath skip a hairpin destination while the maps are being updated.
    skel.set_dest_config_mode(2)?;

    let set_addr = old.is_none_or(|old| old.external_addr != config.external_addr);
""",
    "apply_inet_config conservative mode",
)

patch(
    INST_MOD,
    """    for change in external_config_diff {
""",
    """    let dest_config_mode = if config.dest_config.is_empty() {
        0
    } else if !config.external_addr.is_unspecified()
        && config.dest_config.len() == 1
        && config.dest_config.iter().next().is_some_and(|(prefix, _)| {
            prefix == config.external_addr
                && IpNetwork::prefix_len(&prefix) == <P::Addr as IpAddress>::LEN
        })
    {
        1
    } else {
        2
    };
    skel.set_dest_config_mode(dest_config_mode)?;

    for change in external_config_diff {
""",
    "apply_inet_config dest_config mode",
)

print("einat perf patch p2 applied")
