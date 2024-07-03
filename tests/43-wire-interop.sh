#!/usr/bin/env bash
# ch43: wire-format correctness + real-kernel interop.
#
# Gate 1 (always): every frame the simulator emits decodes as real
#   RFC bytes - EtherType, ARP fields, IPv4 version nibble + header
#   checksum, ICMP/UDP/TCP checksums with a network-order
#   pseudo-header. Checked by tests/tools/pcapcheck.py, which never
#   uses the stack's own structs. Before ch43 every frame failed
#   (EtherType 0x2603 for ARP, 0x0008 for IPv4).
#
# Gate 2 (when `unshare -rn` works - no sudo needed): inside a
#   private user+net namespace the Linux kernel on the far side of
#   samtap0 is the peer. Assert:
#     - our ARP frames are 42 bytes on the TAP
#     - our stack pings the kernel (>=2/3: probe 1 resolves ARP)
#     - the kernel pings our stack (3/3, our ARP cache is warm)
#     - curl (kernel TCP) gets "hello" from our HTTP responder
#   Skips (not fails) when user namespaces, ping or curl are absent.
. "$(dirname "$0")/lib.sh"

have_py=0; command -v python3 >/dev/null 2>&1 && have_py=1

# ---- inner half: runs inside `unshare -rn` -------------------------
if [ "${SAMTCPIP_IN_NETNS:-0}" = "1" ]; then
    ip link set lo up
    pcap="$(mktemp --suffix=.pcap)"
    fifo="$(mktemp -u)"; mkfifo "$fifo"
    log="$(mktemp)"
    ./testapp < "$fifo" > "$log" 2>&1 &
    app=$!
    exec 3> "$fifo"
    cmd(){ echo "$1" >&3; sleep "${2:-0.4}"; }

    cmd "run pcap start $pcap"
    cmd "run tap attach R0_re samtap0 eth0/0"
    cmd "run tap ifup samtap0"
    cmd "run tap host-ip samtap0 10.0.0.99 24"
    cmd "config node R0_re interface eth0/0 ip 10.0.0.1 24"
    cmd "config node R0_re http-listen 80" 0.8
    cmd "run node R0_re ping 10.0.0.99" 1.5          # also warms our ARP cache
    kping="$(ping -c 3 -i 0.3 -W 2 10.0.0.1 2>&1 || true)"
    body="$(curl -s --max-time 5 http://10.0.0.1/ || true)"
    cmd "run pcap stop"
    cmd "run tap detach" 0.5
    cmd "quit" 0.3
    exec 3>&-
    wait "$app" 2>/dev/null || true
    out="$(cat "$log")"; rm -f "$fifo" "$log"

    assert_contains "$out" "TAP attach : samtap0 -> R0_re/eth0/0" "TAP attach in netns"
    assert_contains "$out" "GARP : R0_re : announcing 10.0.0.1"   "GARP fired"
    assert_contains "$out" "TAP send : 42 bytes via R0_re/eth0/0" "ARP frame is 42 bytes on the wire"

    # Probe 1 resolves ARP and is dropped (no pending queue yet),
    # so 2 of 3 is the expected floor.
    n_reply=$(printf '%s\n' "$out" | grep -c '^Ping reply : R0_re : seq=[0-9]* from 10.0.0.99' || true)
    [ "$n_reply" -ge 2 ] || fail "stack->kernel ping: want >=2 replies, got $n_reply"

    assert_contains "$kping" "3 received" "kernel->stack ping 3/3"
    assert_contains "$out"  "TCP recv : R0_re : SYN seq="          "kernel SYN parsed"
    assert_contains "$out"  "HTTP : R0_re : 200 OK -> peer"        "HTTP handler fired"
    assert_eq "hello" "$body" "curl body from kernel TCP"

    if [ "$have_py" = "1" ]; then
        chk="$(python3 tests/tools/pcapcheck.py "$pcap")" || fail "interop pcap has bad frames: $chk"
    fi
    rm -f "$pcap"
    pass
fi

# ---- gate 1: simulator frames are real RFC bytes ---------------------
if [ "$have_py" = "1" ]; then
    pcap="$(mktemp --suffix=.pcap)"
    printf 'run pcap start %s\nrun node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nrun node R0_re udp-big 20.1.1.2 250\nconfig node R1_re http-listen 80\nrun node R0_re tcp-syn 20.1.1.2 80\nrun node R0_re tcp-send 20.1.1.2 80 GET\nrun node R0_re tcp-close 20.1.1.2 80\nrun pcap stop\nquit\n' "$pcap" | ./testapp >/dev/null 2>&1
    chk="$(python3 tests/tools/pcapcheck.py "$pcap")" || fail "simulator pcap has non-RFC frames: $chk"
    assert_contains "$chk" "bad=0" "all simulator frames decode as RFC bytes"
    assert_contains "$chk" "ARP op=1" "ARP requests present"
    assert_contains "$chk" "IPv4 proto=6" "TCP present"
    rm -f "$pcap"
else
    echo "$test_name : python3 absent, skipping pcap RFC gate"
fi

# ---- gate 2: real kernel peer, via an unprivileged netns -------------
if ! command -v ping >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "$test_name : ping/curl absent, skipping real-kernel gate"
    pass
fi
if ! unshare -rn true >/dev/null 2>&1; then
    echo "$test_name : user namespaces unavailable, skipping real-kernel gate"
    pass
fi
SAMTCPIP_IN_NETNS=1 unshare -rn bash "$0" || exit 1
