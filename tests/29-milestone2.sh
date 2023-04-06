#!/usr/bin/env bash
# Ch29: Milestone 2 goal - in-stack HTTP responder.
#
# Tcb gains an on_data callback. tcp_listen_with_handler stashes
# it on the LISTEN TCB; the spawned child TCB inherits. On
# ESTABLISHED + data, the recv path calls the handler after
# the cumulative ACK.
#
# http.c ships http_hello_install: on any inbound data, send back
# HTTP/1.0 200 OK + body + initiate orderly close.
#
# Test plan:
#   1. http-listen installs a handler.
#   2. Simulator-side SYN + tcp-send drives the full HTTP flow:
#      handshake -> data -> server runs handler -> server sends
#      HTTP response -> server FIN -> client ACK -> client also
#      drives close to land in CLOSED.
#   3. Under root: same flow but via TAP. Curl from a sibling
#      process would work; we just verify the in-stack flow.
. "$(dirname "$0")/lib.sh"

# 1+2: full in-stack flow.
out="$(printf 'config node R1_re http-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-syn 20.1.1.2 80\nrun node R0_re tcp-send 20.1.1.2 80 GET\nrun node R0_re tcp-close 20.1.1.2 80\nshow node R0_re tcp\nshow node R1_re tcp\nquit\n' | ./testapp)"

# Listener with handler.
assert_contains "$out" "TCP listen : R1_re : port 80 (handler installed)" "http listener installed"

# Handshake + data + handler dispatch.
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "ch22 handshake"
assert_contains "$out" "TCP recv : R1_re : data seq=8193 len=3 \`GET\`" "GET arrives at server"
assert_contains "$out" "HTTP : R1_re : 200 OK -> peer"                    "HTTP handler fired"
assert_contains "$out" "TCP send : R1_re : data seq=4097 len=89 to 20.1.1.1:33333" "HTTP response emitted"

# Server-initiated close after the response.
assert_contains "$out" "TCP close : R1_re : ESTABLISHED -> FIN_WAIT_1"   "server closes after response"
assert_contains "$out" "TCP send : R1_re : FIN seq=4186 ack=8196 to 20.1.1.1:33333" "server sends FIN"

# Client received response.
assert_contains "$out" "TCP recv : R0_re : data seq=4097 len=89 \`HTTP/1.0 200 OK" "client receives HTTP response"

# Client receives the server's FIN.
assert_contains "$out" "TCP recv : R0_re : FIN seq=4186 -> CLOSE_WAIT"   "client transitions to CLOSE_WAIT on server FIN"

# 3. Regression: ping + UDP still work.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"   "UDP regression"

pass
