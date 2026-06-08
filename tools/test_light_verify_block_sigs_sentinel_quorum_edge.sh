#!/usr/bin/env bash
# determ-light verify-block-sigs / block-verify — the MD-vs-BFT sentinel-zero
# abstention quorum boundary.  EDGE focus, not a happy-path rehash.
#
# WHY THIS EDGE IS UNCOVERED
# --------------------------
# verify_block_sigs (light/verify.cpp) treats an all-zero (sentinel) creator
# block-sig specially:
#   • In MD (K-of-K) mode a sentinel-zero sig is REJECTED *before any sig is
#     checked* — `creator[i] '...' has sentinel-zero signature in MD mode`
#     (verify.cpp line ~244).  MD permits no abstentions: K-of-K is strict.
#   • In BFT mode the same sentinel slot is SKIPPED (an allowed abstention) and
#     the block PASSES iff the remaining real sigs reach ceil(2K/3).
#   • In BFT mode, if too many slots are sentinel/invalid so that fewer than
#     ceil(2K/3) real sigs verify, it FAILS with
#     `only N sigs verify (required M of K)` (verify.cpp line ~268).
#
# The existing light suite (test_light_verify_block_sigs.sh,
# test_light_block_verify.sh, test_verify_block_sigs.sh) only exercises
# tampered-sig / wrong-committee / missing-member.  None of them feeds a
# sentinel-zero sig to determ-light, so NONE asserts:
#   (a) the MD-mode sentinel REJECTION diagnostic (a fail-closed),
#   (b) that the SAME block PASSES once --bft is supplied (abstention allowed),
#   (c) the below-BFT-quorum `sigs verify (required ...)` diagnostic.
# The only sentinel/abstention coverage anywhere is
# test_wallet_committee_signature_verify.sh, which exercises the *wallet*
# binary's separate verifier against an operator-PINNED digest — it never
# touches determ-light's internally-recomputed-digest path and never asserts
# the MD-mode rejection (it only checks the BFT abstention pass).
#
# This test drives the REAL determ-light binary.  It does NOT reimplement
# Ed25519/Merkle: the one authentic K=3 signed block comes from a brief daemon
# run (the only source of real committee sigs in this repo, exactly as the
# sibling tests do); every edge variant is derived from that one real block and
# the verification phase is pure offline file-based crypto in determ-light.
#
# Assertions:
#   CONTROL-1  unmodified block verifies in MD (K-of-K)            -> OK / exit 0
#   EDGE-1     one sentinel-zero sig, MD mode                      -> FAIL "sentinel-zero ... MD mode", exit 1
#   EDGE-2     SAME block, --bft                                   -> OK (abstention allowed), exit 0
#   EDGE-3     two sentinel-zero sigs, --bft (1 valid < 2 quorum)  -> FAIL "sigs verify (required", exit 1
#   EDGE-4     block-verify (composite) one sentinel, MD           -> SIGS FAIL, exit 2
#   CONTROL-2  block-verify (composite) one sentinel, --bft        -> PASS, exit 0
#
# Run from repo root: bash tools/test_light_verify_block_sigs_sentinel_quorum_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ daemon binary not found (needed to mint one real signed block)"
    exit 0
fi

T=test_light_verify_block_sigs_sentinel_quorum_edge
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
  rm -rf "$TABS"
}
trap cleanup EXIT INT

rm -rf "$T"
mkdir -p "$T/n1" "$T/n2" "$T/n3"

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ───────────────────────────────────────────────────────────────────────────
# Phase A — mint ONE authentic K=3 signed block (the only step that needs the
# daemon).  Everything after this is offline file-based verification.
# ───────────────────────────────────────────────────────────────────────────
echo "=== A. Init 3-node cluster (mint one real K=3 signed block) ==="
for n in 1 2 3; do
  $DETERM init --data-dir "$T/n$n" --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir "$T/n$n" --stake 1000 > "$T/p$n.json"
done

cat > "$T/gen.json" <<EOF
{
  "chain_id": "test-light-sentinel",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat "$T/p1.json" | tr -d '\n'),
$(cat "$T/p2.json" | tr -d '\n'),
$(cat "$T/p3.json" | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build "$T/gen.json" | tail -1
GHASH=$(cat "$T/gen.json.hash")

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path']   = '$TABS/n$n/node_key.json'
c['data_dir']   = '$TABS/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7811 8811 '["127.0.0.1:7812","127.0.0.1:7813"]'
configure_node 2 7812 8812 '["127.0.0.1:7811","127.0.0.1:7813"]'
configure_node 3 7813 8813 '["127.0.0.1:7811","127.0.0.1:7812"]'

NODE_PIDS=("" "" "")
$DETERM start --config "$T/n1/config.json" > "$T/n1/log" 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config "$T/n2/config.json" > "$T/n2/log" 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config "$T/n3/config.json" > "$T/n3/log" 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== A2. Wait for height >= 3 (block 1 fully committed + queryable) ==="
# Match the proven sibling (test_light_verify_block_sigs.sh): block 1 is only
# reliably returned by the headers RPC once the head has advanced a couple
# blocks past it, so wait for >= 3 rather than racing the head at height 1.
H=0
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8811 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

# Fetch block 1's header (+ committee), retrying briefly in case the RPC slice
# is momentarily empty right at the height boundary.
for _ in $(seq 1 10); do
  $DETERM_LIGHT fetch-headers --rpc-port 8811 --from 1 --count 1 --out "$T/hdr.json" > "$T/fetch.out" 2>&1
  if [ -s "$T/hdr.json" ] && python -c "
import json,sys
try:
    r=json.load(open('$T/hdr.json'))
    sys.exit(0 if r.get('headers') else 1)
except Exception:
    sys.exit(1)
"; then break; fi
  sleep 0.5
done
$DETERM validators --rpc-port 8811 --json > "$T/committee.json" 2>&1

# Stop the cluster now — all remaining work is offline file verification.
for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
sleep 1
NODE_PIDS=()

HAVE_HDR=$([ -s "$T/hdr.json" ] && echo true || echo false)
if [ "$HAVE_HDR" != "true" ]; then
  echo "  SKIP: could not mint a real signed block (chain did not advance to height 1)"
  exit 0
fi

# Sanity: the real header must carry exactly 3 creators + 3 non-sentinel sigs,
# otherwise the edge variants below would be ill-formed.
NSIG=$(python -c "
import json
r=json.load(open('$T/hdr.json'))
hs=r.get('headers') if isinstance(r,dict) else None
if not hs:
    print('0 0 0')
else:
    h=hs[0]
    sigs=h.get('creator_block_sigs',[]); cre=h.get('creators',[])
    zero='0'*128
    real=sum(1 for s in sigs if s.lower()!=zero)
    print('%d %d %d' % (len(cre), len(sigs), real))
")
echo "  real header (creators sigs real-sigs): $NSIG"
read -r NCRE NSIGS NREAL <<<"$NSIG"
if [ "$NCRE" != "3" ] || [ "$NSIGS" != "3" ] || [ "$NREAL" != "3" ]; then
  echo "  SKIP: minted block is not a clean K=3 all-signed block (got $NSIG); edge needs 3 real sigs"
  exit 0
fi

# ───────────────────────────────────────────────────────────────────────────
# Phase B — offline edge verification (no daemon).
# ───────────────────────────────────────────────────────────────────────────

echo
echo "=== CONTROL-1: unmodified real block verifies in MD (K-of-K) → OK exit 0 ==="
OUT=$($DETERM_LIGHT verify-block-sigs --header "$T/hdr.json" --committee "$T/committee.json" 2>&1); RC=$?
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && [ $RC -eq 0 ] && echo true || echo false)
assert "$OK" "CONTROL-1: clean K=3 block → OK, exit 0 (proves fixture + MD path are sound)"

# Build the one-sentinel variant: zero creator_block_sigs[0] to the 128-zero
# sentinel.  This is the SAME bytes the producer would emit for a real BFT
# abstention, so it is a legal-shape block — the verifier's MODE decides.
python -c "
import json
r=json.load(open('$T/hdr.json'))
r['headers'][0]['creator_block_sigs'][0] = '0'*128
with open('$T/hdr_one_sentinel.json','w') as f: json.dump(r,f)
"

echo
echo "=== EDGE-1: one sentinel-zero sig, MD mode → FAIL (sentinel-zero ... MD mode), exit 1 ==="
OUT=$($DETERM_LIGHT verify-block-sigs --header "$T/hdr_one_sentinel.json" --committee "$T/committee.json" 2>&1); RC=$?
# Fail-closed: MD must reject the abstention BEFORE counting any quorum.
HIT=$(echo "$OUT" | grep -qiE "sentinel-zero signature in MD mode" && echo true || echo false)
assert "$HIT" "EDGE-1: MD rejects sentinel-zero abstention with the exact diagnostic"
EXIT_OK=$([ $RC -eq 1 ] && echo true || echo false)
assert "$EXIT_OK" "EDGE-1: exit 1 (verify-block-sigs FAIL)"

echo
echo "=== EDGE-2: SAME one-sentinel block, --bft → OK (abstention allowed), exit 0 ==="
# Only the --bft flag changes vs EDGE-1: proves the MD/BFT layers are distinct
# and that the sentinel slot is an ALLOWED abstention under BFT (2 valid ≥ 2).
OUT=$($DETERM_LIGHT verify-block-sigs --header "$T/hdr_one_sentinel.json" --committee "$T/committee.json" --bft 2>&1); RC=$?
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && [ $RC -eq 0 ] && echo true || echo false)
assert "$OK" "EDGE-2: BFT accepts the SAME block (1 abstain, 2 valid ≥ ceil(2*3/3)=2) → OK exit 0"
# The OK report should credit exactly the 2 surviving real sigs.
VC=$(echo "$OUT" | grep -E "verified:" | grep -oE "[0-9]+" | head -1)
VC_OK=$([ "${VC:-0}" = "2" ] && echo true || echo false)
assert "$VC_OK" "EDGE-2: reports verified: 2 sig(s) (the sentinel slot is not counted; got '${VC:-}')"

# Build the two-sentinel variant: now only 1 real sig remains < ceil(2*3/3)=2.
python -c "
import json
r=json.load(open('$T/hdr.json'))
r['headers'][0]['creator_block_sigs'][0] = '0'*128
r['headers'][0]['creator_block_sigs'][1] = '0'*128
with open('$T/hdr_two_sentinel.json','w') as f: json.dump(r,f)
"

echo
echo "=== EDGE-3: two sentinel-zero sigs, --bft (1 valid < 2 quorum) → FAIL (sigs verify required), exit 1 ==="
OUT=$($DETERM_LIGHT verify-block-sigs --header "$T/hdr_two_sentinel.json" --committee "$T/committee.json" --bft 2>&1); RC=$?
# Below BFT quorum: the verifier must fail-close with the quorum diagnostic.
HIT=$(echo "$OUT" | grep -qiE "sigs verify \(required" && echo true || echo false)
assert "$HIT" "EDGE-3: BFT below-quorum rejected with the 'sigs verify (required ...)' diagnostic"
EXIT_OK=$([ $RC -eq 1 ] && echo true || echo false)
assert "$EXIT_OK" "EDGE-3: exit 1 (below-quorum FAIL even under --bft)"

# ── Same edge through the composite block-verify (STRUCTURE+TX-ROOT+SIGS). ──
# block-verify wants an unwrapped Block JSON; unwrap the headers envelope.
python -c "
import json
r=json.load(open('$T/hdr_one_sentinel.json'))
with open('$T/block_one_sentinel.json','w') as f: json.dump(r['headers'][0], f)
"

echo
echo "=== EDGE-4: block-verify composite, one sentinel, MD → SIGS FAIL, exit 2 ==="
OUT=$($DETERM_LIGHT block-verify --block "$T/block_one_sentinel.json" --committee "$T/committee.json" 2>&1); RC=$?
SIGS_FAIL=$(echo "$OUT" | grep -qE "SIGS[[:space:]]+FAIL" && echo true || echo false)
assert "$SIGS_FAIL" "EDGE-4: composite block-verify surfaces SIGS FAIL on the MD sentinel"
EXIT_OK=$([ $RC -eq 2 ] && echo true || echo false)
assert "$EXIT_OK" "EDGE-4: exit 2 (block-verify check FAILED, distinct from arg-error exit 1)"

echo
echo "=== CONTROL-2: block-verify composite, one sentinel, --bft → PASS, exit 0 ==="
OUT=$($DETERM_LIGHT block-verify --block "$T/block_one_sentinel.json" --committee "$T/committee.json" --bft 2>&1); RC=$?
PASS=$(echo "$OUT" | grep -qE "BLOCK-VERIFY: PASS" && [ $RC -eq 0 ] && echo true || echo false)
assert "$PASS" "CONTROL-2: composite block-verify PASSES under --bft (proves SIGS is the only differing layer vs EDGE-4)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_block_sigs_sentinel_quorum_edge"
  exit 0
else
  echo "  FAIL: test_light_verify_block_sigs_sentinel_quorum_edge"
  exit 1
fi
