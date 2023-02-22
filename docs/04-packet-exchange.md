# ch4 - packet exchange simulation

Real bytes start flying between Nodes. Each Node binds a UDP socket
on a unique local port (40000+); a single background thread does
`select()` across all of them; sending is a `sendto` to the peer
Node's port on `127.0.0.1`. The wire is `lo`.

## Why UDP localhost

The whole topology is one process. We need a transport that:

- gives us per-Node receive queues (one socket per Node),
- doesn't require root or extra privileges (raw sockets / tun
  devices would),
- is reliable enough for local-loopback testing (kernel just
  copies the buffer between sockets - no drops on a normal box),
- works on stock Linux without extra deps.

UDP on loopback ticks all four. Each Node gets a distinct port; the
port doubles as that Node's "wire" address.

## Layout

```
graph.h
  Node { ...; unsigned int udp_port_number; int udp_sock_fd; }
comm.h
  send_pkt_out (Interface)         -> sendto on peer Node's port
  send_pkt_flood (Node)            -> send_pkt_out for each intf
  pkt_receive (Node, Interface)    -> calls layer2_frame_recv
  network_start_pkt_receiver_thread(Graph)
                                   -> spawn the select loop thread
Layer2/layer2.c
  layer2_frame_recv (stub) -> printf + promote_pkt_to_layer3
Layer3/layer3.c
  layer3_pkt_recv (stub) -> printf
```

## Send path

`send_pkt_out(pkt, size, oif)`:

1. Resolve peer Node via `get_nbr_node(oif)`. Bail if no peer.
2. Open an ephemeral UDP socket (fresh per call - cheap, avoids
   any per-thread state).
3. Build `send_buffer` = `<peer intf name, 16 bytes><payload>`.
   The peer interface name is the aux info so the receiver thread
   can identify which local Interface a datagram came in on. Note
   we serialize the *peer-side* name, not the sender-side.
4. `sendto` to `127.0.0.1 : <peer_node->udp_port_number>`.
5. Close the ephemeral socket.

`send_pkt_flood(node, pkt, size)` walks `node->intf[]` and calls
`send_pkt_out` for each non-null slot.

## Receive path

`network_start_pkt_receiver_thread(topo)` builds a fd_set of every
Node's bound socket, then loops:

1. `select()` blocks on the fd_set.
2. For each ready socket, find the owning Node and `recvfrom` into
   the static `recv_buffer`.
3. Call `_pkt_receive(node, recv_buffer, bytes)`:
   - First IF_NAME_SIZE bytes = aux header = recv-side interface name.
   - `get_node_if_by_name(node, name)` -> recv Interface.
   - `pkt_receive(node, iif, payload, payload_size)`.
4. `pkt_receive` calls into `layer2_frame_recv`. The L2 stub prints
   and promotes to `layer3_pkt_recv`.

The thread is detached and the loop runs forever - process exit
reaps it.

## Buffers + threading

- `recv_buffer` / `send_buffer` are static 2 KB globals shared by
  the receiver thread and sender path. Fine because:
  - The receiver thread is the only consumer of `recv_buffer`.
  - `send_pkt_out` is only ever called from the main thread (CLI
    dispatch). If we ever go multi-threaded on the send side, the
    buffer becomes a per-thread or per-call allocation.
- The select thread is created `PTHREAD_CREATE_DETACHED`. No join
  ever runs - process death cleans up.

## Port quirk preserved

The reference assigns and binds `sin_port` raw (no `htons`). Both
ends use the same convention so the kernel keeps the bytes
consistent on loopback. We replicate verbatim - it works on stock
Linux for our smoke tests. If we ever talk to a real peer (which
would expect network byte order), this becomes a gotcha to fix.

## CLI hook

New command:

```
run send <node> <if-name> <payload>
```

handler resolves the (Node, Interface) pair, calls `send_pkt_out`,
then `usleep(100ms)` so the detached receiver thread can dispatch
and print before the CLI returns to the bash test's `$(...)`
capture.

`nwcli_install` also calls `network_start_pkt_receiver_thread` and
sleeps 50 ms - enough for the thread to call `FD_SET` on every
socket before the first user `send`.

## Test

`tests/04-packet-exchange.sh`:

1. `run send R0_re eth0/0 hello`. The eth0/0 link goes to
   R1_re/eth0/1, so we expect L2 + L3 receipt logs on
   R1_re / eth0/1 with payload "hello".
2. `run send R0_re eth0/4 world`. eth0/4 goes to R2_re/eth0/5.
3. Bogus node name -> "no such node" on stderr, non-zero exit.
4. Bogus interface name -> "no such interface" on stderr, non-zero
   exit.
