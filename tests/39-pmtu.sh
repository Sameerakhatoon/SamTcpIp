#!/usr/bin/env bash
# ch39: PMTUD path cache + ICMP Frag Needed parse.
#
# Verify:
#   - default (no cache) splits 250-byte UDP into 3 fragments
#   - `pmtu set <dst> 60` makes the SAME send fragment finer
#   - `pmtu clear` restores default
#   - the receive-side parse handler exists (smoke: pmtu show
#     after set lists the install line)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(printf '
run node R0_re ping 20.1.1.2
run pmtu show
run node R0_re udp-big 20.1.1.2 250
run pmtu set 20.1.1.2 60
run pmtu show
run node R0_re udp-big 20.1.1.2 250
run pmtu clear
run node R0_re udp-big 20.1.1.2 250
quit
' | ./testapp 2>&1)

# Slice into the three udp-big bursts by install/clear markers.
# The typed commands don't echo back, so we anchor on the OUTPUT
# lines those commands produce.
blk_default_1=$(echo "$OUT" | sed -n '1,/PMTU install : dst=20.1.1.2/p')
blk_after_set=$(echo "$OUT" | sed -n '/PMTU install : dst=20.1.1.2/,/PMTU clear all/p')
blk_after_clear=$(echo "$OUT" | sed -n '/PMTU clear all/,$p')

count_emits(){ echo "$1" | grep -c '^IP frag emit : R0_re' || true; }

n1=$(count_emits "$blk_default_1")
n2=$(count_emits "$blk_after_set")
n3=$(count_emits "$blk_after_clear")

[ "$n1" -ge 3 ] || { echo "FAIL: default expected >=3 frags, got $n1"; exit 1; }
[ "$n2" -ge 6 ] || { echo "FAIL: pmtu=60 expected >=6 frags, got $n2"; exit 1; }
[ "$n3" -ge 3 ] || { echo "FAIL: post-clear expected >=3 frags, got $n3"; exit 1; }
[ "$n2" -gt "$n1" ] || { echo "FAIL: pmtu=60 did not increase frag count ($n2 vs $n1)"; exit 1; }
[ "$n3" -le "$n2" ] || { echo "FAIL: post-clear should match default ($n3 vs $n2)"; exit 1; }

# Cache contents reported.
echo "$OUT" | grep -q "PMTU install : dst=20.1.1.2 mtu=60" || { echo "FAIL: install line missing"; exit 1; }
echo "$OUT" | grep -q "20.1.1.2 *mtu=60" || { echo "FAIL: show after set didn't list entry"; exit 1; }
echo "$OUT" | grep -q "PMTU clear all" || { echo "FAIL: clear all line missing"; exit 1; }

echo "PASS"
