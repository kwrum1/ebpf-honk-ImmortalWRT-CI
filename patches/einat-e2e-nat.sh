#!/usr/bin/env bash
#
# Functional check for the einat datapath patches, run as root on Linux.
#
# Topology (network namespaces):
#
#   device 192.168.1.100 -- br-lan -- router -- veth_r_s1 198.18.0.1 -- server1 198.18.0.2
#                                                                        server1 198.18.0.3
#
# einat runs on the router on veth_r_s1 with the same arguments the firmware
# uses. What the patches change, and what this script therefore has to prove
# still works:
#
#   * dest_config mode 1 (p2): with a single dest entry equal to the WAN address
#     the datapath compares the packet destination instead of doing an LPM
#     lookup. Traffic to 198.18.0.2/.3 takes the compare path on every packet,
#     so a broken compare would show up as a total traffic failure.
#   * established-TCP CT fast path (p2): the 20 MB download spends all but the
#     first second of its life on the fast path, in both directions.
#   * NAT semantics that must not change:
#       - EIM: one local UDP port mapped to two different peers keeps one
#         external port,
#       - EIF (full cone): a peer that was never contacted can reach that port.
#
set -euxo pipefail

EINAT=${EINAT:-$PWD/target/debug/einat}
WAN_ADDR=198.18.0.1
PEER_A=198.18.0.2
PEER_B=198.18.0.3
LAN_ADDR=192.168.1.100
WORK=/tmp/einat-e2e
rm -rf "$WORK"
mkdir -p "$WORK"

cleanup() {
    set +e
    jobs -p | xargs -r kill 2>/dev/null
    ip netns pids router | xargs -r kill 2>/dev/null
    ip -all netns delete
}
trap cleanup EXIT
ip -all netns delete 2>/dev/null || true

ip netns add server1
ip netns add router
ip netns add device

ip link add veth_r_s1 netns router type veth peer name veth_s1_r netns server1
ip link add br-lan netns router type bridge
ip link add veth_r_d1 netns router type veth peer name veth_d1_r netns device

ip netns exec server1 ip link set lo up
ip netns exec server1 ip addr add "$PEER_A/24" dev veth_s1_r
ip netns exec server1 ip addr add "$PEER_B/24" dev veth_s1_r
ip netns exec server1 ip link set veth_s1_r up

ip netns exec router ip link set lo up
ip netns exec router ip addr add "$WAN_ADDR/24" dev veth_r_s1
ip netns exec router ip link set veth_r_s1 up
ip netns exec router ip link set veth_r_d1 master br-lan
ip netns exec router ip addr add 192.168.1.1/24 dev br-lan
ip netns exec router ip link set br-lan up
ip netns exec router ip link set veth_r_d1 up
ip netns exec router sysctl -q net.ipv4.ip_forward=1

ip netns exec device ip link set lo up
ip netns exec device ip addr add "$LAN_ADDR/24" dev veth_d1_r
ip netns exec device ip link set veth_d1_r up
ip netns exec device ip route add default via 192.168.1.1

ip netns exec router "$EINAT" -i veth_r_s1 \
    --ports 20000-29999 --nat44 \
    --internal 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 \
    --hairpin-if lo br-lan >"$WORK/einat.log" 2>&1 &
sleep 1

# ------------------------------------------------------------------ ICMP ---
ip netns exec device ping -c2 -W2 "$PEER_A"
ip netns exec device ping -c2 -W2 "$PEER_B"

# ------------------------------------------------------------------- TCP ---
head -c 20000000 /dev/urandom >"$WORK/blob"
ip netns exec server1 python3 -m http.server 8080 --bind "$PEER_A" \
    --directory "$WORK" >"$WORK/http.log" 2>&1 &
for _ in $(seq 1 50); do
    ip netns exec device curl -s -o /dev/null "http://$PEER_A:8080/" && break
    sleep 0.1
done
ip netns exec device curl -sS --max-time 60 -o "$WORK/dl" "http://$PEER_A:8080/blob"
cmp "$WORK/blob" "$WORK/dl"
ip netns exec device curl -sS --max-time 60 -o "$WORK/dl2" "http://$PEER_A:8080/blob"
cmp "$WORK/blob" "$WORK/dl2"

# ------------------------------------------------------------------- UDP ---
cat >"$WORK/udp_echo.py" <<'PY'
import socket, sys

addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data + b" " + str(peer[1]).encode(), peer)
PY

cat >"$WORK/udp_eif.py" <<'PY'
import socket, sys, time

src, dst, port_file = sys.argv[1], sys.argv[2], sys.argv[3]
port = None
for _ in range(200):
    try:
        port = int(open(port_file).read().strip())
        break
    except (OSError, ValueError):
        time.sleep(0.05)
if port is None:
    sys.exit("no mapped external port appeared")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 7001))
s.sendto(b"eif", (dst, port))
PY

cat >"$WORK/udp_client.py" <<'PY'
import socket, sys

port_file = sys.argv[1]
peers = sys.argv[2:4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[4], 29999))
s.settimeout(10)


def probe(dst):
    s.sendto(b"probe", dst)
    data, _ = s.recvfrom(2048)
    return int(data.split()[-1])


ports = []
for peer in peers:
    host, port = peer.split(":")
    ports.append(probe((host, int(port))))
assert len(set(ports)) == 1, "EIM violated, external ports differ: %s" % ports
open(port_file, "w").write(str(ports[0]))

data, peer = s.recvfrom(2048)
assert data == b"eif", "unexpected payload from EIF peer: %r" % data
print("EIM external port %d, EIF peer %s:%d" % (ports[0], peer[0], peer[1]))
PY

ip netns exec server1 python3 "$WORK/udp_echo.py" "$PEER_A" 7000 &
ip netns exec server1 python3 "$WORK/udp_echo.py" "$PEER_B" 7000 &
ip netns exec server1 python3 "$WORK/udp_eif.py" "$PEER_B" "$WAN_ADDR" "$WORK/mapped_port" &
sleep 0.5

ip netns exec device python3 "$WORK/udp_client.py" \
    "$WORK/mapped_port" "$PEER_A:7000" "$PEER_B:7000" "$LAN_ADDR"

grep -E "einat|error" "$WORK/einat.log" || true
echo "EINAT-E2E-PASS"
