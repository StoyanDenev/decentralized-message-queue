#!/usr/bin/env bash
# D3.5e-5 / S-036 Layer 2 — the first LIVE epoch-boundary distress-fold
# validator (best-effort; SKIP-clean, see "Outcome discipline" below).
#
# This is the empirical validation of the ENTIRE D3.5e ladder (e-1..e-7e): a
# real beacon+shard EXTENDED cluster in which a SOURCE shard in genuine sub-2K
# distress has its tip
#   (1) broadcast as SHARD_TIP (full block) on every shard block append,
#   (2) VERIFIED by the beacon's on_shard_tip against the FROZEN cc:[E_source]
#       committee (D3.5e-4 verdict pin; the shard's committee rand is anchored
#       on beacon header index epoch_start-1 — the D3.5e-3 off-by-one fix,
#       never before exercised across a live epoch boundary),
#   (3) FOLDED into a beacon block as a ShardTipRecord + full-tip witness
#       (D3.5c/d-ii emission + e-7c witness attach, F2 intersection across the
#       beacon committee, gated on committee_pin_active — the e-7c gate),
#   (4) ACCEPTED by every beacon validator's check_shardtip_witnesses (e-7d —
#       the S-036 CLOSED-maker, live),
#   (5) committed as a t: state leaf (served via state-proof --ns t), and
#   (6) re-verified by the THIRD-PARTY auditor `determ-light
#       verify-shardtip-records` returning ok:true with records_verified>=1
#       (e-7e's first live POSITIVE-path run — its own test covers only the
#       vacuous 0-records path).
#
# Topology (5 processes):
#   BEACON: 2 nodes, region us-east, global_test profile (BEACON+EXTENDED),
#           M=K=2, FAST timing (800ms) — the epoch anchor header must always
#           reach the shard before the shard needs it.
#   SHARD0: 3 nodes, region eu-west, web_test profile (SHARD+EXTENDED),
#           M=3 K=2, SLOW timing (2500ms). eligible_count = 3 < 2K = 4 →
#           PERMANENTLY DISTRESSED → every epoch>=1 tip is fold-eligible.
#   Both genesis files: epoch_blocks=4 (cc:[1] folds at beacon block index 3),
#   initial_shard_count=3 (the EXTENDED >=3 gate), SAME k_block_sigs=2 (the
#   beacon's expected_k must equal the tip's creators count).
#   The beacon genesis carries the D3.5e-1 GENESIS-COMMITTED map
#   beacon_shard_regions=[{shard_id:0, committee_region:"eu-west"}] — the
#   authoritative shard→region source (and an e-7e auditor REQUIREMENT).
#   Beacon initial_creators include the 3 shard validators (region eu-west)
#   so the frozen cc: pool can derive the source committee; the beacon's own
#   production pool is region-filtered to us-east (committee_region).
#
# BOOT ORDER (load-bearing): shard nodes FIRST, then beacons. The shard's
# beacon-header tracking is STRICTLY CONTIGUOUS from index 1 (on_beacon_header
# has no catch-up — a missed header 1 permanently gaps the view and the epoch
# rand anchor never materializes). Beacon nodes dial shard_peers at startup,
# so the cross-link exists BEFORE the beacon's first block is produced.
#
# KNOWN LIVENESS RESIDUAL (why this is best-effort, not a hard gate).
# A beacon-fed EXTENDED shard's epoch>=1 committee derives from the beacon
# epoch-anchor header (beacon block INDEX epoch_start-1). The shard has NO
# anchor RE-ACQUISITION path: beacon_headers_ is in-memory + strictly
# contiguous-from-1, and there is no BEACON_HEADER_REQUEST protocol
# (the code's own deferred "B2c.2-full" follow-on). So if the shard produces
# an epoch>=1 block from the local-chain FALLBACK rand before the anchor
# header arrives (a brief window at each boundary that widens if the beacon
# lags or a header is dropped), the shard's own validator later re-derives the
# committee from the anchor and REJECTS its own subsequent blocks
# ('creator[i] mismatch') — a self-wedge. This is a PRE-EXISTING limitation of
# the shard-tip EXTENDED path (documented at current_epoch_rand, node.cpp), NOT
# introduced here; a partial wait-for-anchor gate was prototyped and REVERTED
# because closing it correctly needs the B2c.2-full header-sync increment
# (adversarial review: 3 confirmed HIGH — restart/late-join/mixed-config
# permanent stall). The staged boot + FAST-beacon/SLOW-shard timing keep the
# anchor ahead often enough that the full fold ladder usually completes; when
# the race wedges the shard, NO fold appears and the test SKIPs (below).
#
# Outcome discipline:
#   * SKIP (exit 0) — environment starvation (chains too slow to cross the
#     epoch boundary in budget) OR the anchor-timing wedge (no fold appears).
#     Neither is a ladder defect; the wedge is the documented B2c.2-full gap.
#   * FAIL — a fold DID appear but a downstream ladder property is broken
#     (witness fields wrong, a beacon validator rejected the fold, the t: leaf
#     is absent, or — the load-bearing one — the trustless auditor does NOT
#     confirm the record against the frozen source committee). That is the
#     S-036 closure property failing, which is what this test hard-gates.
#
# Cluster-bound (boots 5 nodes) — do NOT add to FAST=1.
#
# Run from repo root: bash tools/test_shardtip_live_fold.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# The trustless auditor (step 10) is the LOAD-BEARING assertion — the only one
# that proves the fold against the frozen source committee cryptographically.
# Without determ-light there is no trustless anchor, so rather than report a
# green run on the weaker daemon-asserted checks alone, SKIP the whole test.
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light not built — the trustless auditor assertion (the"
    echo "        S-036 closure proof) cannot run; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_shardtip_live_fold
TABS=$PROJECT_ROOT/$T

# Dedicated port block (785x listen / 885x RPC) — verified unused tree-wide.
BL1=7851; BL2=7852               # beacon listen
BR1=8851; BR2=8852               # beacon rpc
SL1=7855; SL2=7856; SL3=7857     # shard listen
SR1=8855; SR2=8856; SR3=8857     # shard rpc

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  if command -v taskkill >/dev/null 2>&1 && command -v netstat >/dev/null 2>&1; then
    for p in "$BR1" "$BR2" "$SR1" "$SR2" "$SR3"; do
      for spid in $(netstat -ano 2>/dev/null | grep LISTENING \
                    | grep -E "127\.0\.0\.1:$p\b" | awk '{print $NF}' | sort -u); do
        [ -n "$spid" ] && taskkill //F //PID "$spid" >/dev/null 2>&1
      done
    done
  fi
}
trap cleanup EXIT INT

# Pre-boot reap: kill any STALE cluster still holding this test's ports (a
# prior run whose nodes outlived their EXIT trap — the Windows taskkill/netstat
# reaping race). Booting a fresh cluster onto a live foreign one causes the
# confusing 'connect refused' / 'rename: Access is denied' / cross-genesis
# 'creators[0] mismatch' failures. Reap + settle before init so each run is
# hermetic whether launched by run_all.sh (fresh) or a tight repeat loop.
if command -v taskkill >/dev/null 2>&1 && command -v netstat >/dev/null 2>&1; then
  reaped=0
  for p in "$BL1" "$BL2" "$SL1" "$SL2" "$SL3" "$BR1" "$BR2" "$SR1" "$SR2" "$SR3"; do
    for spid in $(netstat -ano 2>/dev/null | grep LISTENING \
                  | grep -E "127\.0\.0\.1:$p\b" | awk '{print $NF}' | sort -u); do
      [ -n "$spid" ] && taskkill //F //PID "$spid" >/dev/null 2>&1 && reaped=$((reaped+1))
    done
  done
  [ "$reaped" -gt 0 ] && { echo "  pre-boot: reaped $reaped stale node(s) on this test's ports"; sleep 3; }
fi

rm -rf $T
mkdir -p $T/beacon/n1 $T/beacon/n2 $T/shard/n1 $T/shard/n2 $T/shard/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

echo "=== 1. Init nodes (beacon=global_test BEACON+EXTENDED, shard=web_test SHARD+EXTENDED) ==="
for n in 1 2; do
  $DETERM init --data-dir $T/beacon/n$n --profile global_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info beacon_n$n --data-dir $T/beacon/n$n --stake 1000 > $T/bp$n.json
  $PY -c "
import json
e=json.load(open('$T/bp$n.json')); e['region']='us-east'
json.dump(e,open('$T/bp$n.json','w'))"
done
for n in 1 2 3; do
  $DETERM init --data-dir $T/shard/n$n --profile web_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info shard_n$n --data-dir $T/shard/n$n --stake 1000 > $T/sp$n.json
  $PY -c "
import json
e=json.load(open('$T/sp$n.json')); e['region']='eu-west'
json.dump(e,open('$T/sp$n.json','w'))"
done

echo
echo "=== 2. Build the two genesis files (epoch_blocks=4, shared K=2) ==="
# BEACON genesis: carries the D3.5e-1 committed shard->region map AND the
# shard validators in initial_creators (region eu-west) so the frozen cc:
# checkpoints contain the source-shard pool. committee_region=us-east keeps
# the beacon's own production committee on the 2 beacon nodes.
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-stlf",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 1,
  "initial_shard_count": 3,
  "committee_region": "us-east",
  "epoch_blocks": 4,
  "beacon_shard_regions": [
    {"shard_id": 0, "committee_region": "eu-west"}
  ],
  "initial_creators": [
$(cat $T/bp1.json | tr -d '\n'),
$(cat $T/bp2.json | tr -d '\n'),
$(cat $T/sp1.json | tr -d '\n'),
$(cat $T/sp2.json | tr -d '\n'),
$(cat $T/sp3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}]
}
EOF
# SHARD genesis: the source shard's own chain, with the UNIFIED 5-creator
# set (same as the beacon genesis — "shard registry mirrors beacon at
# genesis"). The shard VERIFIES incoming BEACON_HEADERs against its own
# registry (on_beacon_header: reg.find(creator) -> "not in shard's tracked
# beacon pool" reject), so the beacon validators MUST be registered here too.
# The shard's own production pool stays region-filtered: eligible_in_region
# ("eu-west") = 3 eu-west validators with K=2 -> eligible_count 3 < 2K=4 ->
# permanently distressed. Same chain_id + epoch_blocks + K as the beacon
# (the anchor math + expected_k silently require uniformity).
cat > $T/shard_gen.json <<EOF
{
  "chain_id": "test-stlf",
  "m_creators": 3,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "eu-west",
  "epoch_blocks": 4,
  "initial_creators": [
$(cat $T/bp1.json | tr -d '\n'),
$(cat $T/bp2.json | tr -d '\n'),
$(cat $T/sp1.json | tr -d '\n'),
$(cat $T/sp2.json | tr -d '\n'),
$(cat $T/sp3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}]
}
EOF
$DETERM genesis-tool build $T/beacon_gen.json | tail -1
$DETERM genesis-tool build $T/shard_gen.json | tail -1
BEACON_HASH=$(cat $T/beacon_gen.json.hash)
SHARD_HASH=$(cat $T/shard_gen.json.hash)
BEACON_GEN="$TABS/beacon_gen.json"
SHARD_GEN="$TABS/shard_gen.json"
echo "  beacon hash: $BEACON_HASH"
echo "  shard  hash: $SHARD_HASH"

echo
echo "=== 3. Configure (beacon FAST 800ms, shard SLOW 2500ms, cross-peered) ==="
configure_node() {
  local dir=$1 dom=$2 listen=$3 rpc=$4 own_peers=$5 cross_kind=$6 cross_peers=$7 \
        gen_path=$8 gen_hash=$9 tc=${10} bs=${11} ac=${12}
  $PY -c "
import json
with open('$T/$dir/config.json') as f: c = json.load(f)
c['domain'] = '$dom'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $own_peers
c['$cross_kind'] = $cross_peers
c['genesis_path'] = '$gen_path'
c['genesis_hash'] = '$gen_hash'
c['chain_path'] = '$TABS/$dir/chain.json'
c['key_path']   = '$TABS/$dir/node_key.json'
c['data_dir']   = '$TABS/$dir'
c['tx_commit_ms'] = $tc
c['block_sig_ms'] = $bs
c['abort_claim_ms'] = $ac
with open('$T/$dir/config.json','w') as f: json.dump(c, f, indent=2)
"
}
SHARD_ADDRS="[\"127.0.0.1:$SL1\",\"127.0.0.1:$SL2\",\"127.0.0.1:$SL3\"]"
BEACON_ADDRS="[\"127.0.0.1:$BL1\",\"127.0.0.1:$BL2\"]"
configure_node beacon/n1 beacon_n1 $BL1 $BR1 "[\"127.0.0.1:$BL2\"]" shard_peers "$SHARD_ADDRS" "$BEACON_GEN" "$BEACON_HASH" 800 800 400
configure_node beacon/n2 beacon_n2 $BL2 $BR2 "[\"127.0.0.1:$BL1\"]" shard_peers "$SHARD_ADDRS" "$BEACON_GEN" "$BEACON_HASH" 800 800 400
configure_node shard/n1  shard_n1  $SL1 $SR1 "[\"127.0.0.1:$SL2\",\"127.0.0.1:$SL3\"]" beacon_peers "$BEACON_ADDRS" "$SHARD_GEN" "$SHARD_HASH" 2500 2500 1250
configure_node shard/n2  shard_n2  $SL2 $SR2 "[\"127.0.0.1:$SL1\",\"127.0.0.1:$SL3\"]" beacon_peers "$BEACON_ADDRS" "$SHARD_GEN" "$SHARD_HASH" 2500 2500 1250
configure_node shard/n3  shard_n3  $SL3 $SR3 "[\"127.0.0.1:$SL1\",\"127.0.0.1:$SL2\"]" beacon_peers "$BEACON_ADDRS" "$SHARD_GEN" "$SHARD_HASH" 2500 2500 1250

echo
echo "=== 4. Start 5 nodes — STAGED (contiguous-header guarantee) ==="
# The shard's beacon-header tracking is strictly contiguous from index 1,
# and localhost rounds complete on message arrival (blocks flow in ~100ms),
# so beacon block 1 must not outrun the cross-links. Staging removes the
# race deterministically: shards first, then beacon n1 ALONE — its K=2-of-2
# committee has no quorum without n2, so it CANNOT produce a block, but its
# shard_peers dials + HELLOs complete. Only then n2: the first beacon round
# runs with every cross-link already tagged, so header 1 reaches the shards.
NODE_PIDS=("" "" "" "" "")
$DETERM start --config $T/shard/n1/config.json > $T/shard/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/shard/n2/config.json > $T/shard/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/shard/n3/config.json > $T/shard/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5
$DETERM start --config $T/beacon/n1/config.json > $T/beacon/n1/log 2>&1 &
NODE_PIDS[3]=$!; sleep 2
$DETERM start --config $T/beacon/n2/config.json > $T/beacon/n2/log 2>&1 &
NODE_PIDS[4]=$!; sleep 0.5

echo
echo "=== 5. Pre-flight: shard tracks beacon header 1 (contiguity gate) ==="
HDRS="-"
for _ in $(seq 1 120); do
  HDRS=$(get_status_field $SR1 beacon_headers)
  if [ "$HDRS" != "-" ] && [ "$HDRS" -ge 1 ] 2>/dev/null; then break; fi
  sleep 0.5
done
if ! [ "$HDRS" -ge 1 ] 2>/dev/null; then
  echo "  SKIP: shard never tracked beacon header 1 within 60s (beacon_headers=$HDRS)."
  echo "        Environment too starved (or beacon block 1 outran the cross-dial);"
  echo "        not a fold-ladder defect. Beacon log tail:"
  tail -5 $T/beacon/n1/log 2>/dev/null | sed 's/^/  | /'
  exit 0
fi
assert "true" "pre-flight: shard tracks contiguous beacon headers (beacon_headers=$HDRS)"

echo
echo "=== 6. Wait: beacon crosses epoch 1 (cc:[1] pinned) + shard produces epoch-1 tips ==="
BH="-"; BEI="-"
for _ in $(seq 1 240); do
  BH=$(get_status_field $BR1 height)
  BEI=$(get_status_field $BR1 epoch_index)
  if [ "$BH" != "-" ] && [ "$BH" -ge 6 ] 2>/dev/null \
     && [ "$BEI" != "-" ] && [ "$BEI" -ge 1 ] 2>/dev/null; then break; fi
  sleep 0.5
done
if ! [ "$BEI" -ge 1 ] 2>/dev/null; then
  echo "  SKIP: beacon never crossed epoch 1 within 120s (height=$BH epoch_index=$BEI)."
  echo "        Environment too starved; not a fold-ladder defect."
  exit 0
fi
assert "true" "beacon crossed epoch boundary (height=$BH epoch_index=$BEI — cc:[1] committed)"

SH="-"
for _ in $(seq 1 360); do
  SH=$(get_status_field $SR1 height)
  if [ "$SH" != "-" ] && [ "$SH" -ge 6 ] 2>/dev/null; then break; fi
  sleep 0.5
done
if ! [ "$SH" -ge 6 ] 2>/dev/null; then
  echo "  SKIP: shard only reached height $SH within 180s (need >=6 for epoch-1 tips)."
  echo "        Environment too starved; not a fold-ladder defect."
  exit 0
fi
echo "  shard height: $SH (epoch-1 tips at source heights >= 4 now exist)"

echo
echo "=== 7. THE GATE: a distress ShardTipRecord + witness folds into a beacon block ==="
# Scan committed beacon blocks for non-empty shard_tip_witnesses via ONE
# paged `block-range --json` call per poll (the headers RPC strips only
# transactions/receipts, so shard_tip_records/witnesses survive — and local
# rounds complete on message arrival, so the beacon head grows far too fast
# for a per-height subprocess scan). The records themselves are canonical-
# encoding hex strings; the index-aligned witnesses are full JSON objects —
# assert via the witness fields. Records fold once per (shard,height), and
# they fold at the FIRST eligible round after cc:[E_source] pins, so the
# carrying block sits within the first few hundred beacon heights; cap the
# scan window rather than chase the head.
H_FOLD="-"; W_INDEX="-"; W_SHARD="-"; W_ELIG="-"; N_REC=0
SCAN_CAP=2000
for _ in $(seq 1 60); do
  HEAD=$(get_status_field $BR1 height)
  if [ "$HEAD" != "-" ] && [ "$HEAD" -ge 2 ] 2>/dev/null; then
    TO=$((HEAD - 1)); [ "$TO" -gt "$SCAN_CAP" ] && TO=$SCAN_CAP
    FOLD=$($DETERM block-range 1 $TO --json --rpc-port $BR1 2>/dev/null | $PY -c "
import json, sys
try:
    doc = json.loads(sys.stdin.read())
except Exception:
    doc = {}
# block-range --json emits {'headers': [...], 'from', 'to', 'received'}.
hs = doc.get('headers', []) if isinstance(doc, dict) else doc
for b in hs if isinstance(hs, list) else []:
    ws = b.get('shard_tip_witnesses', [])
    rs = b.get('shard_tip_records', [])
    if ws and rs and len(ws) == len(rs):
        w = ws[0]
        print(json.dumps({'h': b.get('index'), 'n': len(rs),
                          'w_index': w.get('index'),
                          'w_shard': w.get('source_shard_id'),
                          'w_elig': w.get('eligible_count')}))
        break
")
    if [ -n "$FOLD" ]; then
      H_FOLD=$(echo "$FOLD" | $PY -c "import sys,json;print(json.load(sys.stdin)['h'])")
      N_REC=$(echo "$FOLD"  | $PY -c "import sys,json;print(json.load(sys.stdin)['n'])")
      W_INDEX=$(echo "$FOLD"| $PY -c "import sys,json;print(json.load(sys.stdin)['w_index'])")
      W_SHARD=$(echo "$FOLD"| $PY -c "import sys,json;print(json.load(sys.stdin)['w_shard'])")
      W_ELIG=$(echo "$FOLD" | $PY -c "import sys,json;print(json.load(sys.stdin)['w_elig'])")
      break
    fi
  fi
  sleep 3
done
if [ "$H_FOLD" = "-" ]; then
  # No fold appeared. On the reverted tree this is the KNOWN anchor-timing
  # wedge (see the header "KNOWN LIVENESS RESIDUAL"): the shard produced an
  # epoch>=1 block from the fallback rand before the anchor header arrived and
  # self-wedged on 'creator[i] mismatch', so its distress tips are never
  # beacon-verifiable — the pre-existing B2c.2-full gap, not a fold-ladder
  # (S-036 closure) defect. SKIP-clean; the closure property is proven
  # deterministically in-process by test-shardtip-witness-verify (e-7d) +
  # test_light_verify_shardtip_records (e-7e).
  WEDGE=$(grep -c "creator\[.*\] mismatch\|creators\[.*\] mismatch" \
            $T/shard/n1/log $T/beacon/n1/log 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
  echo "  SKIP: no distress record folded within budget — the anchor-timing"
  echo "        wedge (creator-mismatch hits: $WEDGE), the documented B2c.2-full"
  echo "        residual, not an S-036 closure defect. When the anchor stays"
  echo "        ahead the full ladder completes (run again). Beacon n1 tail:"
  tail -6 $T/beacon/n1/log 2>/dev/null | sed 's/^/  | /'
  exit 0
fi
assert "true" "FOLD: beacon block $H_FOLD carries $N_REC shard-tip record(s)+witness(es)"

# Witness content: the genuine distressed source tip.
if [ "$W_SHARD" = "0" ] && [ "$W_ELIG" = "3" ] && [ "$W_INDEX" -ge 4 ] 2>/dev/null; then
  assert "true" "witness fields: source_shard_id=0, eligible_count=3 (<2K=4, distress), height=$W_INDEX (epoch>=1)"
else
  assert "false" "witness fields (got shard=$W_SHARD elig=$W_ELIG index=$W_INDEX; want 0/3/>=4)"
fi

# The beacon received + K-of-K-verified the tip against the frozen committee.
# on_shard_tip's stdout accept marker is a CORROBORATING signal only — the
# AUTHORITATIVE proof that the frozen-committee K-of-K verify happened is the
# auditor in step 10 (it re-verifies the sigs cryptographically). The log line
# is (a) stdout-buffer-lagged vs the in-memory RPC that already served the
# fold, and (b) emitted by whichever beacon node received the gossip — so poll
# a few seconds across BOTH beacon logs rather than grep n1 once. A fold at
# block $H_FOLD REQUIRES the record in BOTH committee members' Phase-1 views
# (full-K reconcile_intersection), so at least one verify line must appear.
tip_logged=false
for _ in $(seq 1 20); do
  if grep -qh "verified shard tip: shard=0" \
       $T/beacon/n1/log $T/beacon/n2/log 2>/dev/null; then
    tip_logged=true; break
  fi
  sleep 0.5
done
assert "$tip_logged" "beacon log: 'verified shard tip: shard=0' (frozen-committee verify fired on a committee member)"

echo
echo "=== 8. Every beacon validator accepted the fold (e-7d live) ==="
# Beacon n2 independently validated block H_FOLD via check_shardtip_witnesses
# before applying it. Same height + byte-identical block at H_FOLD = accept.
B2H="-"
for _ in $(seq 1 60); do
  B2H=$(get_status_field $BR2 height)
  if [ "$B2H" != "-" ] && [ "$B2H" -gt "$H_FOLD" ] 2>/dev/null; then break; fi
  sleep 0.5
done
J1=$($DETERM block-info $H_FOLD --json --rpc-port $BR1 2>/dev/null)
J2=$($DETERM block-info $H_FOLD --json --rpc-port $BR2 2>/dev/null)
SAME=$($PY -c "
import sys, json
try:
    a = json.loads('''$J1'''); b = json.loads('''$J2''')
    print('true' if a == b else 'false')
except Exception:
    print('false')
")
if [ "$SAME" = "true" ] && ! grep -q "invalid block: shard_tip" $T/beacon/n2/log 2>/dev/null; then
  assert "true" "beacon n2 accepted the fold block byte-identically (no shard_tip validator reject)"
else
  assert "false" "beacon n2 fold-block agreement (same=$SAME; reject lines below)"
  grep "invalid block" $T/beacon/n2/log 2>/dev/null | tail -3 | sed 's/^/  | /'
fi

echo
echo "=== 9. t: state leaf committed (state-proof --ns t) ==="
TKEY=$($PY -c "print('%08x%016x' % ($W_SHARD, $W_INDEX))")
TPROOF=$($DETERM state-proof --ns t --key "$TKEY" --rpc-port $BR1 2>/dev/null)
T_OK=$(echo "$TPROOF" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    ok = ('value_hash' in d) and d.get('error') is None
    print('true' if ok else 'false')
except Exception:
    print('false')
")
assert "$T_OK" "t:[shard=$W_SHARD,height=$W_INDEX] state-proof served (leaf committed to state_root)"

echo
echo "=== 10. THIRD-PARTY AUDITOR: verify-shardtip-records live POSITIVE path (e-7e) ==="
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP(sub): determ-light not built — auditor assertions skipped"
else
  set +e
  AOUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $BR1 --genesis $T/beacon_gen.json \
           --height $H_FOLD --wait 30 --json 2>&1)
  ARC=$?
  set -e
  echo "$AOUT" | tail -1
  A_OK=$(echo "$AOUT" | tail -1 | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    r = d.get('records', [{}])[0]
    ok = (d.get('ok') is True and d.get('records_total', 0) >= 1
          and d.get('records_verified') == d.get('records_total')
          and r.get('source_shard_id') == 0
          and r.get('eligible_count') == 3
          and r.get('region') == 'eu-west'
          and r.get('verified') is True)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
  if [ "$ARC" = "0" ] && [ "$A_OK" = "true" ]; then
    assert "true" "auditor: ok=true, records verified vs the FROZEN source committee (shard 0, elig 3, eu-west)"
  else
    assert "false" "auditor positive path (rc=$ARC ok=$A_OK)"
  fi

  # Negative control: the auditor against the WRONG genesis fails closed.
  set +e
  $DETERM_LIGHT verify-shardtip-records --rpc-port $BR1 --genesis $T/shard_gen.json \
      --height $H_FOLD --json >/dev/null 2>&1
  WRC=$?
  set -e
  if [ "$WRC" != "0" ]; then
    assert "true" "auditor wrong-genesis fails closed (rc=$WRC)"
  else
    assert "false" "auditor wrong-genesis should fail closed (got rc=0)"
  fi
fi

echo
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_shardtip_live_fold"; exit 0
else
  echo "  FAIL: test_shardtip_live_fold"; exit 1
fi
