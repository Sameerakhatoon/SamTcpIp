#!/usr/bin/env bash
# Ch28: packet capture facility.
#
# Writes libpcap-format files (magic 0xa1b2c3d4, LINKTYPE_ETHERNET).
# Every frame that crosses send_pkt_out or pkt_receive lands in
# the active capture file.
#
# Test plan:
#   1. Capture a ping flow. Assert file exists + size > the
#      24-byte global header.
#   2. The magic header bytes match libpcap's expectation -
#      tcpdump / wireshark would open it.
#   3. Regression: no capture active -> no file mutation, suite
#      behaves identically.
. "$(dirname "$0")/lib.sh"

CAP="/tmp/samtcpip-ch28.pcap"
rm -f "$CAP"

# Capture a ping flow.
out="$(printf 'run pcap start %s\nrun node R0_re ping 20.1.1.2\nrun pcap stop\nquit\n' "$CAP" | ./testapp)"

# CLI logs.
assert_contains "$out" "PCAP open : $CAP" "open log"
assert_contains "$out" "PCAP close"       "close log"
assert_contains "$out" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping still runs"

# File exists + has substantive content.
if [ ! -f "$CAP" ]; then
    fail "pcap file $CAP does not exist after capture"
fi
SZ=$(stat -c %s "$CAP")
if [ "$SZ" -lt 100 ]; then
    fail "pcap file too small ($SZ bytes); ping produced no frames?"
fi

# Magic check: first 4 bytes must be d4 c3 b2 a1 (LE encoding
# of 0xa1b2c3d4).
HEX=$(head -c 4 "$CAP" | od -A n -t x1 | tr -d ' \n')
if [ "$HEX" != "d4c3b2a1" ]; then
    fail "pcap magic mismatch: got $HEX (expected d4c3b2a1)"
fi

# Regression: prior suite still passes (this is asserted by
# run-all.sh tagging us "ok"; just exercise one ping path here).
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"           "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"  "UDP regression"

rm -f "$CAP"
pass
