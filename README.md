# SamTCPIP

A from-scratch TCP/IP stack in C.

## Layout

```
graph.h / graph.c       generic in-memory graph (Node / Link / Interface)
gluethread/             intrusive doubly-linked list used everywhere
topologies.c            canned topologies for smoke tests
testapp.c               minimal CLI driver for the build
Makefile / build.sh     build wiring
tests/                  bash E2E tests, one per chapter
```

*Diagram: the layered stack and its modules*

```mermaid
flowchart TD
  subgraph APP["Applications and CLI"]
    CLI["nwcli.c and cli.c: show, config, run verbs"]
    HTTP["Layer5/http.c: hello responder"]
    PING["Layer5/ping.c: ICMP echo and Frag Needed"]
  end
  subgraph L4["Layer 4"]
    TCP["Layer4/tcp.c: TCBs, FSM, cwnd"]
    UDP["Layer4/udp.c: port bindings"]
  end
  subgraph L3["Layer 3"]
    IP["Layer3/layer3.c: routes, forward, fragment"]
    PMTU["Layer3/pmtu.c: path MTU cache"]
  end
  subgraph L2["Layer 2"]
    ETH["Layer2/layer2.c: ARP, ingress rules, VLAN tags"]
    SW["Layer2/l2switch.c: MAC learning"]
  end
  subgraph WIRE["Wire"]
    COMM["comm.c: send_pkt_out, pkt_receive"]
    TAP["tap.c: Linux TAP device"]
  end
  BASE["graph.c, net.c, gluethread, utils.c inet_checksum"]
  CLI --> TCP
  CLI --> UDP
  CLI --> PING
  HTTP --> TCP
  TCP --> IP
  UDP --> IP
  PING --> IP
  IP --> PMTU
  IP --> ETH
  ETH --> SW
  ETH --> COMM
  SW --> COMM
  COMM --> TAP
  IP -.-> BASE
```

## Build + test

```
./build.sh
bash tests/run-all.sh
```
