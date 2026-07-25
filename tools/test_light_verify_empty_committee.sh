#!/usr/bin/env bash
# LightVerify LVS-1 — determ-light verify_block_sigs must REJECT a header that
# names an empty committee (creators:[] / creator_block_sigs:[]).
#
# THE VULN: verify_block_sigs (light/verify.cpp) derived its quorum threshold
# from the block's OWN attacker-controlled creators.size():
#     required = bft ? (2*K+2)/3 : K
# With creators:[] the membership loop and the signature loop run zero
# iterations (valid=0), the size check is 0==0, and required=0 in BOTH modes, so
# `valid(0) < required(0)` is false and it returned ok=true with ZERO signatures
# verified. verify_block_sigs is the SOLE committee-signature gate under
# committee_bound_state_root, so a MITM/malicious RPC daemon could serve an
# empty-committee successor header and forge the committee-attested state_root
# (committee_verified=true) with zero sigs — deceiving the light-client user
# about their balance / a tx's inclusion / history / receipts. Block::from_json
# accepts an empty creators array, so the header is fully attacker-suppliable.
#
# THE FIX: reject an empty creator set (a committee-signed block always carries
# K>=1 creators; genesis idx0 is routed around this function). Client-side
# soundness tightening only — no node/consensus/wire change.
#
# Fully offline + FAST (no daemon): fixtures are hand-built JSON. Only the empty
# case needs no real crypto — that is the whole point.
#   NEG-1  empty committee, MD  -> FAIL "no creators", exit 1
#   NEG-2  empty committee, BFT -> FAIL "no creators", exit 1   (required would be 0 too)
#   CTRL   creators:[ghost] (not in committee) -> FAIL "not in the supplied
#          committee", exit 1  (non-vacuity: proves the CLI reaches the real
#          membership/quorum checks, so NEG-1/2 are rejected BEFORE that, by the
#          empty-set guard — falsify-on-mutant flips ONLY NEG-1/2 to OK).
#
# Run from repo root: bash tools/test_light_verify_empty_committee.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

T=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/determ-light-empty-committee.$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass=0; fail=0
assert() { if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1));
           else echo "  FAIL: $2"; fail=$((fail+1)); fi; }

# committee: one member (parse_committee requires a non-empty committee).
printf '[{"domain":"m0","ed_pub":"%s"}]' "$(printf '11%.0s' $(seq 1 32))" > "$T/committee.json"

python - "$T" <<'PY'
import json, sys
T = sys.argv[1]
base = dict(index=5, prev_hash='22'*32, state_root='33'*32, tx_root='44'*32,
            timestamp=1000, delay_seed='00'*32, consensus_mode=0,
            cumulative_rand='55'*32, abort_events=[])
empty = dict(base); empty['creators'] = []; empty['creator_block_sigs'] = []
json.dump({'headers': [empty]}, open(T + '/empty_hdr.json', 'w'))
ghost = dict(base); ghost['creators'] = ['ghost']; ghost['creator_block_sigs'] = ['66'*64]
json.dump({'headers': [ghost]}, open(T + '/ghost_hdr.json', 'w'))
PY

echo "=== NEG-1: empty committee, MD -> FAIL (no creators), exit 1 ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/empty_hdr.json" --committee "$T/committee.json" 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "no creators \(empty committee\)" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-1: MD rejects empty-committee header with the exact diagnostic + exit 1"

echo "=== NEG-2: empty committee, --bft -> FAIL (no creators), exit 1 ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/empty_hdr.json" --committee "$T/committee.json" --bft 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "no creators \(empty committee\)" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-2: BFT also rejects the empty committee (required would degenerate to 0)"

echo "=== CTRL: non-member creator -> FAIL 'not in the supplied committee', exit 1 (path reached) ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/ghost_hdr.json" --committee "$T/committee.json" 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "not in the supplied committee" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "CTRL: a non-member creator reaches + fails the membership check (non-vacuity)"

echo
echo "  $pass pass / $fail fail"
if [ "$fail" = "0" ]; then
  echo "  PASS: test_light_verify_empty_committee"
  exit 0
else
  echo "  FAIL: test_light_verify_empty_committee"
  exit 1
fi
