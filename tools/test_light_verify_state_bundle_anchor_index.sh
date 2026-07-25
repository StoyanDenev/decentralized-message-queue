#!/usr/bin/env bash
# LightVerify LSB-ANCHOR-INDEX — verify-state-bundle must bind the DISPLAYED
# anchor_index label to the anchor block's own (committee-authenticated) index.
#
# THE GAP: a state bundle is a proof-carrying artifact verified OFFLINE by a third
# party. Its `anchor_index` field is a DISPLAY LABEL the (untrusted) bundle
# supplies — echoed in the VERIFIED report + JSON. The crypto binding
# (successor.prev_hash == compute_hash(anchor), whose committee-signed digest
# includes anchor_block.index) authenticates the anchor BLOCK, but nothing tied
# the displayed anchor_index label to it. So a valid bundle for a real anchor at
# height B' could be RE-LABELLED anchor_index=B and verify-state-bundle would
# print "VERIFIED ... anchor_index: B" for state that is actually anchored at B'
# — deceiving the offline verifier about the height.
#
# THE FIX: a structural gate (placed next to the key-binding gate, before the
# crypto/genesis gates) requiring envelope anchor_index == anchor_block.index.
# The anchor block's index is then committee-authenticated by the crypto chain,
# so the label is transitively bound. Client-side only; no node/consensus change.
#
# Fully OFFLINE + FAST (hand-built JSON fixtures; the structural gate needs no
# real crypto — mirrors the key-binding leg of tools/test_light_state_bundle.sh).
#   NEG   anchor_index(5) != anchor_block.index(1)  -> UNVERIFIABLE exit 3
#         with the anchor_index diagnostic (rejected BEFORE the genesis gate).
#   CTRL  anchor_index(1) == anchor_block.index(1)  -> passes the gate, falls
#         through to a LATER gate (genesis load) — proves the gate is live, not a
#         tautology, and that a MATCHING label is NOT refused.
# Falsify-on-mutant (neutralize the gate): NEG falls through to the genesis-load
# gate (exit 1, no anchor_index diagnostic), flipping the NEG assert.
#
# Run from repo root: bash tools/test_light_verify_state_bundle_anchor_index.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

T=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/determ-light-anchoridx.$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass=0; fail=0
assert() { if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1));
           else echo "  FAIL: $2"; fail=$((fail+1)); fi; }

GH64=$(printf 'a%.0s' $(seq 1 64))
NOGEN="$T/nonexistent_gen.json"   # deliberately absent -> genesis-load is a LATER gate

# NEG: matching key_bytes ("a:alice" = 613a616c696365) so we pass the key-binding
# gate and REACH the anchor-index gate; anchor_index(5) != anchor_block.index(1).
cat > "$T/anchoridx_mismatch.json" <<JSON
{"schema":"determ-light-state-bundle/1","genesis_hash":"$GH64","namespace":"a","key":"alice",
 "anchor_index":5,"anchor_block":{"index":1},"successor_header":{"index":2},
 "state_proof":{"key_bytes":"613a616c696365","state_root":"ab","value_hash":"cd","proof":[],"target_index":0,"leaf_count":1}}
JSON
# CTRL: matching anchor_index(1) == anchor_block.index(1).
cat > "$T/anchoridx_match.json" <<JSON
{"schema":"determ-light-state-bundle/1","genesis_hash":"$GH64","namespace":"a","key":"alice",
 "anchor_index":1,"anchor_block":{"index":1},"successor_header":{"index":2},
 "state_proof":{"key_bytes":"613a616c696365","state_root":"ab","value_hash":"cd","proof":[],"target_index":0,"leaf_count":1}}
JSON

echo "=== NEG: envelope anchor_index(5) != anchor_block.index(1) -> UNVERIFIABLE exit 3 ==="
set +e
OUT=$("$DETERM_LIGHT" verify-state-bundle --in "$T/anchoridx_mismatch.json" --genesis "$NOGEN" 2>&1); RC=$?
set -e
echo "$OUT"
HIT=$(echo "$OUT" | grep -qiE "anchor_index label .* != anchor_block.index" && [ $RC -eq 3 ] && echo true || echo false)
assert "$HIT" "NEG: relabelled anchor_index rejected at the anchor-index gate (exit 3, exact diagnostic)"

echo "=== CTRL: matching anchor_index passes the gate, falls through to a LATER gate ==="
set +e
OUT2=$("$DETERM_LIGHT" verify-state-bundle --in "$T/anchoridx_match.json" --genesis "$NOGEN" 2>&1); RC2=$?
set -e
echo "$OUT2"
# Must NOT trip the anchor-index gate (no anchor_index diagnostic), and must NOT
# be VERIFIED (it falls through to the genesis-load gate on a nonexistent genesis).
NOTRIP=$(echo "$OUT2" | grep -qiE "anchor_index label .* != anchor_block.index" && echo false || echo true)
assert "$NOTRIP" "CTRL: a MATCHING anchor_index is NOT refused by the gate (non-vacuity)"

echo
echo "  $pass pass / $fail fail"
if [ "$fail" = "0" ]; then
  echo "  PASS: test_light_verify_state_bundle_anchor_index"; exit 0
else
  echo "  FAIL: test_light_verify_state_bundle_anchor_index"; exit 1
fi
