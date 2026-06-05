#!/usr/bin/env bash
# determ-light verify-param-value — trust-minimized MATCH / MISMATCH /
# UNVERIFIABLE verdict on whether the CURRENT effective value of a
# governance-activated consensus scalar (a genesis-pinned constant in the
# `k:` namespace) equals the value the caller asserts, with the proof bound
# to the EXACT (name, value) pair.
#
# This is the ACTIVATED counterpart to verify-param-change: that command
# proves a change is still STAGED in `p:`; this command proves the value
# that is LIVE RIGHT NOW after Chain::activate_pending_params has drained
# the matured `p:` bucket into the chain-instance scalar and
# build_state_leaves has re-committed it under `k:`.
#
# The verifier anchors genesis, committee-verifies the header chain to head,
# computes the canonical key ("k:" + name), fetches the `k:`-namespace
# state-proof (simple key — the daemon prepends "k:" to the raw name), and
# Merkle-verifies it against the committee-signed state_root — comparing the
# proof's value_hash against the locally-recomputed SHA256(u64_be(<value>)).
#
# Unlike the i:/m:/p: membership readers, every WELL-KNOWN `k:` consensus
# scalar ALWAYS has a committed leaf, so a value query is never a membership
# query: a verifying leaf whose value_hash matches the assertion is a sound
# MATCH; a verifying leaf whose value_hash does NOT match is a sound MISMATCH
# (the asserted value is provably NOT the live scalar). Only a tamper, key
# mismatch, malformed proof, stale state, or unknown-name not_found is
# UNVERIFIABLE.
#
# Because the genesis-pinned constants are committed on EVERY state_root
# chain (no governance flow required), this test asserts a REAL MATCH against
# the genesis-set block_subsidy=10 deterministically — no SKIP-clean headline
# needed for the positive case.
#
# Assertions (all run against a live single-node daemon):
#   1. (headline) --name block_subsidy --value 10 (the genesis value) → MATCH,
#      exit 0, with a committee-anchored state_root.
#   2. --name block_subsidy --value 999 (wrong) → MISMATCH (a sound verified
#      negative — the leaf committee-verified but commits a different value),
#      exit 0, NEVER a false MATCH.
#   3. Unknown / non-k: --name → UNVERIFIABLE (exit 3): no `k:` leaf to anchor;
#      fail-closed, never MATCH.
#   4. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any verdict); never MATCH.
#   5. --name carrying a ':' (a counter-shaped name) → usage error (exit 1).
#   6. Missing required flags → usage error (exit 1).
#   7. (anti-false-positive) The MISMATCH / UNVERIFIABLE / error variants never
#      print a line beginning with "MATCH".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_param_value.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vpv
TABS=$PROJECT_ROOT/$T

PY=python
command -v python >/dev/null 2>&1 || PY=python3

declare -a NODE_PIDS
cluster_running=1
stop_cluster() {
  set +e
  if [ "$cluster_running" = "1" ]; then
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    cluster_running=0
  fi
  return 0
}
trap stop_cluster EXIT INT

rm -rf $T
mkdir -p $T/node

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

echo "=== 1. Init data dir + node key ==="
$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json

echo
echo "=== 2. Build genesis (single-creator chain, M=K=1, block_subsidy=10) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-vpv",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/node_gen.json | tail -1
NODE_HASH=$(cat $T/node_gen.json.hash)

# A DIFFERENT genesis (different chain_id) → different compute_genesis_hash.
# Used by assertion 4 (wrong-genesis).
cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vpv-WRONG",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/node_gen_wrong.json | tail -1

echo
echo "=== 3. Configure node ==="
$PY -c "
import json
cfg = '$T/node/config.json'
with open(cfg) as f: c = json.load(f)
c['domain'] = 'node_n'
c['listen_port'] = 7903
c['rpc_port'] = 8903
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/node_gen.json'
c['genesis_hash'] = '$NODE_HASH'
c['chain_path'] = '$TABS/node/chain.json'
c['key_path'] = '$TABS/node/node_key.json'
c['data_dir'] = '$TABS/node'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open(cfg,'w') as f: json.dump(c,f,indent=2)
"

echo
echo "=== 4. Start node ==="
NODE_PIDS=("")
$DETERM start --config $T/node/config.json > $T/node/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3

echo
echo "=== 5. Poll until node produces blocks (need a state_root head) ==="
for _ in $(seq 1 90); do
  H=$(get_status_field 8903 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8903 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-param-value defect)."
  exit 0
fi

# Pre-flight: confirm the daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8903 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_param_value"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: block_subsidy == 10 (genesis value) → MATCH (exit 0) ==="
# k:block_subsidy is a genesis-pinned constant committed on every state_root
# chain — no governance flow required, so the positive case is deterministic.
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen.json \
        --name block_subsidy --value 10 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^MATCH"; then
  assert "true" "block_subsidy=10 → MATCH, exit 0 (real k: state-proof Merkle-verified)"
else
  assert "false" "block_subsidy=10 → MATCH/exit0 (got rc=$RC)"
fi

echo
echo "=== ASSERTION 2: block_subsidy == 999 (wrong) → MISMATCH (exit 0) ==="
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen.json \
        --name block_subsidy --value 999 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^MISMATCH"; then
  assert "true" "wrong value → MISMATCH, exit 0 (sound verified negative)"
else
  assert "false" "wrong value → MISMATCH/exit0 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^MATCH" && echo false || echo true)
assert "$NOFP2" "wrong value never yields a false MATCH"

echo
echo "=== ASSERTION 3: unknown --name → UNVERIFIABLE (exit 3) ==="
# A name that is not a known build_state_leaves k: constant has no committed
# leaf, so the daemon returns not_found and the verifier fails closed.
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen.json \
        --name not_a_real_constant --value 1 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qE "^UNVERIFIABLE"; then
  assert "true" "unknown name → UNVERIFIABLE, exit 3 (no k: leaf to anchor)"
else
  assert "false" "unknown name → UNVERIFIABLE/exit3 (got rc=$RC)"
fi
NOFP3=$(echo "$OUT" | grep -qE "^MATCH" && echo false || echo true)
assert "$NOFP3" "unknown name never yields MATCH"

echo
echo "=== ASSERTION 4: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen_wrong.json \
        --name block_subsidy --value 10 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP4=$(echo "$OUT" | grep -qE "^MATCH" && echo false || echo true)
assert "$NOFP4" "wrong genesis never yields MATCH"

echo
echo "=== ASSERTION 5: --name with ':' (counter-shaped) → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen.json \
        --name c:accumulated_subsidy --value 0 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "bare"; then
  assert "true" "':'-bearing name → usage error (exit 1, counters use the c namespace)"
else
  assert "false" "':'-bearing name should be a usage error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 6: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-param-value --rpc-port 8903 --genesis $T/node_gen.json \
        --name block_subsidy 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --value → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_param_value"; exit 0
else
  echo "  FAIL: test_light_verify_param_value"; exit 1
fi
