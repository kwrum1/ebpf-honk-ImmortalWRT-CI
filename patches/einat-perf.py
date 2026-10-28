import io
import sys

# eiNat perf patch p1
#
# 1. (build flag, no source change) the package uses upstream's `static` preset,
#    which is already the v4-only build: no FEAT_IPV6, no NAT66 code in the
#    program. Nothing to patch for that; the build workflow pins the preset.
#
# 2. (this patch) v4-only builds still run get_is_ipv4() at the top of both TC
#    programs, which parses the ethertype/L3 header -- and then parse_packet()
#    parses the same header again. With FEAT_IPV6 compiled out, is_ipv4 is a
#    constant, so that first parse is pure overhead on every packet, in both
#    directions. Guard it.
#
# 3. (not in this patch) the dest_config lookup and the ct-vs-binding double
#    lookup are structural changes to maps that the Rust loader also reads
#    (cleanup/status). They are deliberately left for a change that can be
#    regression-tested end to end.

TREE = sys.argv[1] if len(sys.argv) > 1 else "."
BPF = TREE.rstrip("/") + "/src/bpf/einat.bpf.c"


def patch(path, old, new, tag):
    s = io.open(path, encoding="utf-8").read()
    if new in s:
        print("  already patched:", tag)
        return
    if old not in s:
        raise SystemExit("  anchor not found: %s\n%s" % (tag, old))
    io.open(path, "w", encoding="utf-8", newline="\n").write(s.replace(old, new, 1))
    print("  patched:", tag)


s = io.open(BPF, encoding="utf-8").read()
count = s.count("ret = get_is_ipv4(skb, &is_ipv4);")
print("  get_is_ipv4 call sites:", count)
if count != 2:
    raise SystemExit("expected 2 get_is_ipv4 call sites, found %d" % count)

old = """    bool is_ipv4;
    ret = get_is_ipv4(skb, &is_ipv4);
    if (ret != TC_ACT_OK) {
        return ret;
    }
"""
new = """#ifdef FEAT_IPV6
    bool is_ipv4;
    ret = get_is_ipv4(skb, &is_ipv4);
    if (ret != TC_ACT_OK) {
        return ret;
    }
#else
    /* v4-only build: the ethertype/L3 header is parsed again by
     * parse_packet() below, so sniffing it here is pure overhead. */
    bool is_ipv4 __attribute__((unused)) = true;
#endif
"""
patch(BPF, old, new, "skip the redundant ethertype parse (both programs)")

print("einat perf patch applied")
