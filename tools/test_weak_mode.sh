#!/usr/bin/env bash
# Weak-mode K-committee test for Determ (v1 rev.5 design, rev.9 semantics).
# Verifies the K<M hybrid committee design on a real 4-node cluster:
#   - 4 nodes registered (M_pool=4), committee size K=3 per round
#     (genesis-pinned m_creators=4 / k_block_sigs=3 override the
#     regional_test profile's 5/4; node.cpp:151-156).
#   - The committee is epoch-seeded (rev.9 B1): one fixed 3-of-4 committee
#     per epoch, re-derived from current_epoch_rand at epoch boundaries.
#     Genesis here sets epoch_blocks=2 so rotation is observable.
#   - tx_root = UNION of the K=3 committee lists (src/node/node.cpp:727;
#     the original "intersection" wording was stale).
#   - All 4 nodes converge on identical head_hash, every produced block
#     carries exactly K=3 creators (not the full 4-pool).
#
# Run from repo root: bash tools/test_weak_mode.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_weak

declare -a NODE_PIDS

cleanup() {
  echo
  echo "=== Stopping nodes ==="
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}
# Abnormal-exit guard: if the script dies before the final summary, still
# stop the nodes and emit a last-line FAIL marker for run_all.sh.
on_abort() {
  trap - EXIT INT
  cleanup
  echo "  FAIL: test_weak_mode (aborted before summary)"
  exit 1
}
trap on_abort EXIT INT

# Per-check helper: per-check lines use "  ok:"/"  bad:" so a stray
# "PASS:" can never land in run_all.sh's last-10-lines marker window;
# only the final verdict line uses PASS:/FAIL:.
pass_count=0; fail_count=0
check() {
  if [ "$1" = "true" ]; then echo "  ok:  $2"; pass_count=$((pass_count + 1))
  else echo "  bad: $2"; fail_count=$((fail_count + 1)); fi
}

get_height() {
  $DETERM status --rpc-port "$1" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}

get_head() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 nodes ==="
for n in 1 2 3 4; do
  $DETERM init --data-dir $T/n$n --profile regional_test 2>&1 | tail -1
done

echo
echo "=== 2. Generate peer-info entries ==="
for n in 1 2 3 4; do
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 3. Build genesis (M_pool=4, K_committee=3 weak BFT, epoch_blocks=2, subsidy=10) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-weak-mode",
  "m_creators": 4,
  "k_block_sigs": 3,
  "epoch_blocks": 2,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "treasury", "balance": 1000000}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

echo
echo "=== 4. Configure 4 nodes (4-mesh, ports 7771-7774, rpc 8771-8774) ==="
configure_node() {
  local n=$1
  local domain=$2
  local listen=$3
  local rpc=$4
  local peers_json=$5
  local cfg=$T/n$n/config.json
  python -c "
import json
with open('$cfg') as f: c = json.load(f)
c['domain']           = '$domain'
c['listen_port']      = $listen
c['rpc_port']         = $rpc
c['bootstrap_peers']  = $peers_json
c['genesis_path']     = '$GPATH'
c['genesis_hash']     = '$GHASH'
c['chain_path']       = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path']         = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir']         = '$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms']     = 2000
c['block_sig_ms']     = 2000
c['abort_claim_ms']   = 1000
with open('$cfg', 'w') as f: json.dump(c, f, indent=2)
print(f'  n$n: $domain listen=$listen rpc=$rpc')
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7774"]'
configure_node 4 node4 7774 8774 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773"]'

echo
echo "=== 5. Start 4 nodes ==="
NODE_PIDS=("" "" "" "")
for n in 1 2 3 4; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  echo "  n$n: pid ${NODE_PIDS[$((n-1))]}"
  sleep 0.3
done

echo
echo "=== 6. Wait 30s for sync + block production ==="
sleep 30

echo
echo "=== 7. Status snapshots ==="
for n in 1 2 3 4; do
  H=$(get_height 877$n)
  HEAD=$(get_head 877$n)
  echo "  n$n: height=$H head=${HEAD:0:16}..."
done

echo
echo "=== 8. Consistency check (sentinel-rejecting) ==="
# 8a. Liveness: every node's height must be numeric and >= 2 (rejects the
# '-' dead-RPC sentinel; >= 2 requires real post-genesis production).
HEIGHTS_OK=true
for n in 1 2 3 4; do
  H=$(get_height 877$n)
  if ! [[ "$H" =~ ^[0-9]+$ ]] || [ "$H" -lt 2 ]; then
    echo "  bad: n$n height='$H' (need numeric >= 2; '-' means dead RPC)"
    HEIGHTS_OK=false
  fi
done
check "$HEIGHTS_OK" "step 8a: all 4 nodes live with height >= 2"

# 8b. Convergence: HEAD1 must be a real 64-hex hash (rejects the '?'
# dead-RPC sentinel and empty strings) and all 4 heads must match.
# One re-poll allowed for in-flight head skew; persistent divergence is
# a hard FAIL, not a WARN.
heads_agree() {
  HEAD1=$(get_head 8771)
  [[ "$HEAD1" =~ ^[0-9a-f]{64}$ ]] || return 1
  local HN
  for n in 2 3 4; do
    HN=$(get_head 877$n)
    [ "$HN" = "$HEAD1" ] || return 1
  done
  return 0
}
if heads_agree; then
  check true "step 8b: all 4 nodes agree on a real 64-hex head_hash"
else
  echo "  note: first head poll diverged or hit a sentinel; re-polling once after 3s (in-flight block possible)"
  sleep 3
  if heads_agree; then
    check true "step 8b: all 4 nodes agree on a real 64-hex head_hash (after re-poll)"
  else
    for n in 1 2 3 4; do
      echo "  n$n head=$(get_head 877$n)"
    done
    check false "step 8b: head_hash convergence (sentinel or persistent divergence)"
  fi
fi

echo
echo "=== 9. Block-counts and committee membership inspection ==="
for n in 1 2 3 4; do
  blocks=$(grep -c "accepted block" $T/n$n/log)
  echo "  node$n: $blocks blocks accepted"
done

echo
echo "=== 10. Verify K-committee size in chain (S-021 wrapped chain.json) ==="
python -c "
import json, sys
ok = True
chain_path = '$T/n1/chain.json'
try:
    with open(chain_path) as f: doc = json.load(f)
    # S-021 saves the wrapped {head_hash, blocks} object; accept the legacy
    # bare array too (chain.cpp load-time fallback).
    blocks = doc['blocks'] if isinstance(doc, dict) else doc
    print(f'  chain length: {len(blocks)} blocks (incl genesis)')
    sizes = [len(b['creators']) for b in blocks[1:]]   # skip genesis
    print(f'  block creator-counts (post-genesis): {sizes[:10]}{\"...\" if len(sizes)>10 else \"\"}')
    if len(blocks) < 3:
        print(f'  bad: expected >= 3 blocks (genesis + >= 2 produced); got {len(blocks)}')
        ok = False
    if sizes and all(s == 3 for s in sizes):
        print('  ok:  every post-genesis block has exactly K=3 creators (committee size, not M_pool=4)')
    elif sizes:
        print(f'  bad: expected all post-genesis blocks to have K=3 creators; got {sorted(set(sizes))}')
        ok = False
    else:
        print('  bad: no post-genesis blocks to inspect (zero production)')
        ok = False

    # Rotation: committees are epoch-seeded (rev.9 B1); genesis pins
    # epoch_blocks=2, so the 3-of-4 committee re-derives every 2 blocks.
    # Assert rotation only at >= 8 post-genesis blocks (>= 4 epochs):
    # C(4,3) = 4 possible committees, so same-committee coincidence odds
    # are negligible but nonzero below that.
    committees = [tuple(sorted(b['creators'])) for b in blocks[1:]]
    unique = set(committees)
    print(f'  unique committees over {len(committees)} post-genesis blocks: {len(unique)}')
    if len(committees) >= 8:
        if len(unique) >= 2:
            print('  ok:  committee rotates across epochs (epoch_blocks=2)')
        else:
            print(f'  bad: one fixed committee across {len(committees)} blocks (>= 4 epochs at epoch_blocks=2)')
            ok = False
    else:
        print('  NOTE: fewer than 8 post-genesis blocks; rotation left unasserted (coincidence odds non-negligible)')
except Exception as e:
    print(f'  bad: chain.json inspection failed: {e}')
    ok = False
sys.exit(0 if ok else 1)
"
if [ $? -eq 0 ]; then
  check true "step 10: K=3 committee structure in n1 chain.json (>= 2 produced blocks, all creators == 3)"
else
  check false "step 10: K=3 committee structure in n1 chain.json"
fi

echo
echo "=== Test summary ==="
echo "  checks: $pass_count ok, $fail_count failed"
trap - EXIT INT
cleanup
if [ "$fail_count" -eq 0 ]; then
  echo "  PASS: test_weak_mode"
  exit 0
else
  echo "  FAIL: test_weak_mode ($fail_count checks failed)"
  exit 1
fi
