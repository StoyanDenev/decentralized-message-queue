#!/usr/bin/env bash
# test_producer_admit_wiring_guard.sh — source guard for the producer-side
# admission wiring (SECURITY.md S-056/S-059/S-061/S-062).
#
# Problem it solves: `determ test-producer-admit` proves build_body honours a
# predicate it is HANDED, but it hand-wires BlockValidator::check_transaction
# itself — it cannot see whether Node still passes tx_admit_locked() at every
# build_body call site. A partial revert (e.g. the sign path only) is worse
# than none: the sign-path and finalize-path bodies would differ and every
# self-assembled block's K signatures would mismatch. This guard pins the
# wiring in the source text:
#   (1) every `build_body(` call in src/node/node.cpp carries `tx_admit_locked()`
#       in its argument list (the call spans several lines; the argument is
#       searched up to the closing `);`);
#   (2) there are exactly 3 such calls (sign, finalize, peer-BlockSig verify);
#   (3) build_body's admission line is the fail-SAFE form
#       `if (!admit || !admit(tx, nn)) continue;` (an empty predicate admits
#       nothing).
# Falsify-on-mutant (executed 2026-09-14, reverted): dropping `tx_admit_locked()`
# from one call site -> (1) RED; changing the admission line to the fail-open
# `if (admit && !admit(tx, nn))` -> (3) RED.
#
# Pure text check (grep/awk), needs no binary, never SKIPs. Exit 0 = wired.
set -u
cd "$(dirname "$0")/.."
NODE="src/node/node.cpp"; PROD="src/node/producer.cpp"
DRIFT=0
ok()    { echo "  ok:    $1"; }
drift() { echo "  drift: $1" >&2; DRIFT=$((DRIFT + 1)); }

echo "=== producer-admission wiring guard (Node -> build_body -> check_transaction) ==="
[ -f "$NODE" ] && [ -f "$PROD" ] || { drift "source files missing"; echo "  FAIL: test_producer_admit_wiring_guard"; exit 1; }

# Collect each build_body( call with its argument text up to the closing ");".
CALLS=$(awk '
  /build_body\(/ { grab = 1; buf = ""; line = NR }
  grab { buf = buf $0 " "; if ($0 ~ /\);/) { grab = 0; print line "\t" buf } }' "$NODE")
N=$(printf '%s\n' "$CALLS" | grep -c . || true)
if [ "$N" -eq 3 ]; then ok "exactly 3 build_body call sites in $NODE"
else drift "expected 3 build_body call sites in $NODE, found $N"; fi
while IFS=$'\t' read -r line buf; do
  [ -z "$line" ] && continue
  if printf '%s' "$buf" | grep -q 'tx_admit_locked()'; then ok "call at $NODE:$line passes tx_admit_locked()"
  else drift "build_body call at $NODE:$line does NOT pass tx_admit_locked()"; fi
done <<EOF2
$CALLS
EOF2

if grep -q 'if (!admit || !admit(tx, nn)) continue;' "$PROD"; then ok "build_body admission line is the fail-safe form"
else drift "build_body admission line missing or not fail-safe (expected: if (!admit || !admit(tx, nn)) continue;)"; fi

echo ""
if [ "$DRIFT" -eq 0 ]; then echo "  PASS: test_producer_admit_wiring_guard"; exit 0
else echo "  FAIL: test_producer_admit_wiring_guard ($DRIFT drift)"; exit 1; fi
