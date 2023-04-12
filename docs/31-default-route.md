# ch31 - default route handling

The course's `l3rib_lookup_lpm` already special-cases
`0.0.0.0/0` - it walks routes, tracks the longest specific
match, and returns the default route ONLY if no specific
match was found. ch31 ships no new code; it verifies the
contract + documents what operators can rely on.

## End-to-end demo

```
samtcpip> show node R0_re pick-src 99.99.99.99
pick-src : R0_re : dst=99.99.99.99 -> src=122.1.1.0   ; loopback fallback

samtcpip> config node R0_re route 0.0.0.0 0 20.1.1.2 eth0/0
samtcpip> show node R0_re pick-src 99.99.99.99
pick-src : R0_re : dst=99.99.99.99 -> src=20.1.1.1    ; OIF IP now
```

LPM finds the default, ch30's `node_pick_src_ip` walks to step 1
(LPM with explicit oif), returns `20.1.1.1` (eth0/0's IP).

## What landed

Nothing in code. The test asserts:

1. Without a default route, non-routed dst -> loopback (ch30 fallback).
2. With a default route installed via `config node ... route 0.0.0.0 0 <gw> <oif>`,
   non-routed dst -> the OIF's IP.
3. Specific routes win over default. Install a /24 for
   `30.1.1.0` and a default; `30.1.1.5` uses the /24, while
   `99.99.99.99` uses the default.

## Design choices

### Why no separate "default-gw" CLI

`config node X route 0.0.0.0 0 <gw> <oif>` reads naturally and
matches what real network operators do. A `default-gw` shorthand
would be one fewer keystroke but invents a new concept.

### Why ch31 is a verification chapter

PLAN.md called for "default route handling" but didn't require
new code. The course already had the feature; we just need to
prove it works correctly under the lens of curl OUT (which
needs default routing).

Skipping the chapter would mean no test gate for default routing;
adding a test costs ~30 lines + a few minutes; cheap insurance
against a future LPM refactor breaking the contract.

## What's NOT here

- Multi-default with ECMP (equal-cost multi-path).
- Default route metric.
- Source-route policy (multiple routing tables).
- IPv6 default route.

## Test discipline

| Axis             | Positive                                                          |
|------------------|-------------------------------------------------------------------|
| No default       | `pick-src ... dst=99.99.99.99 -> src=122.1.1.0` (loopback)        |
| Default installed| `pick-src ... dst=99.99.99.99 -> src=20.1.1.1`                    |
| Default in table | `0.0.0.0  0  20.1.1.2  eth0/0` in `show node route`               |
| Specific wins    | `dst=30.1.1.5 -> src=20.1.1.1` (specific /24)                     |
| Default fallback | `dst=99.99.99.99 -> src=40.1.1.1` (the OTHER OIF in default)      |
| Ping regression  | works                                                              |

## What's left

ch32: ephemeral port allocation (pool of high ports). Needed
so multiple outbound TCP connections from our stack don't
collide on local-port.
