#!/usr/bin/env bash
# Ch23: TCP data + cumulative ACK.
#
# Builds on ch22's handshake. After ESTABLISHED, data-bearing
# PSH|ACK segments carry payload; the receiver consumes,
# advances rcv_nxt by len, and emits a bare ACK acknowledging
# the new cumulative byte position.
#
# tcp_send_data(node, dst_ip, dst_port, payload, len) walks the
# TCB list for an ESTABLISHED entry matching (remote_ip,
# remote_port) and emits a PSH|ACK with our snd_nxt + payload.
. "$(dirname "$0")/lib.sh"

# Full handshake + data + cumulative ACK.
out="$(printf 'config node R1_re tcp-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-syn 20.1.1.2 80\nrun node R0_re tcp-send 20.1.1.2 80 hello-tcp\nquit\n' | ./testapp)"

# ch22 handshake still works.
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "ch22 client ESTABLISHED"
assert_contains "$out" "TCP recv : R1_re : ACK seq=8193 ack=4097 -> ESTABLISHED"                    "ch22 server ESTABLISHED"

# ch23 data path.
assert_contains "$out" "TCP send : R0_re : data seq=8193 len=9 to 20.1.1.2:80"            "client sends 9 bytes"
assert_contains "$out" "TCP recv : R1_re : data seq=8193 len=9 \`hello-tcp\`"             "server receives + decodes payload"
assert_contains "$out" "TCP send : R1_re : ACK seq=4097 ack=8202 to 20.1.1.1:33333"       "server ACKs with cumulative position (8193+9)"

# Negative: no checksum drops on clean data.
if printf '%s\n' "$out" | grep -q 'TCP recv : .* checksum invalid'; then
    fail "clean data path must not log TCP csum invalid"
fi

# Send-without-TCB fails cleanly. With R2 (no listener, no
# handshake), the lookup returns no ESTABLISHED TCB.
out_notcb="$(printf 'run node R0_re tcp-send 30.1.1.2 9999 oops\nquit\n' | ./testapp)"
assert_contains "$out_notcb" "TCP send : R0_re : no ESTABLISHED TCB to" "send without TCB rejected"

# Regression.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"   "UDP regression"

pass
