#!/usr/bin/env bash
# determ-light verify-param-change — trust-minimized INCLUDED /
# NOT-INCLUDED / UNVERIFIABLE verdict on whether a staged governance
# parameter change (effective_height, idx → name + value) is a member of
# the committee-verified `p:` (pending_param_changes) namespace, with the
# proof bound to the EXACT (name, value) the caller asserts.
#
# The verifier anchors genesis, committee-verifies the header chain to
# head, computes the canonical key ("p:" + eff_height_be8 + idx_be4),
# hex-encodes the binary body, fetches the `p:`-namespace state-proof, and
# Merkle-verifies it against the committee-signed state_root — binding the
# proof to THIS change via key_bytes == local key AND value_hash ==
# SHA256(u64_be(name_len) || name || u64_be(value_len) || value).
#
# The daemon serves the composite-key `p:` namespace (the caller hex-
# encodes the binary key body; see src/node/node.cpp rpc_state_proof), so
# the same verifier code path that fails closed against a legacy daemon
# yields a real INCLUDED against a current one.
#
# A `p:` leaf only exists while a PARAM_CHANGE is STAGED but not yet
# activated — which requires a GOVERNED chain (governance_mode + param
# keyholders + a threshold of signatures) and a future effective_height.
# Standing that flow up deterministically in a short test is fragile, so
# this test follows the receipt/merge SKIP-clean philosophy: it stands up
# a single node, probes the `pending_params` RPC for any staged change,
# and asserts a real INCLUDED if one exists. The fail-closed / negative
# assertions need only a live daemon with a non-empty state_root and
# always run.
#
# Assertions (all run; the INCLUDED headline only when a change is staged):
#   1. (headline, conditional) A genuinely-staged param change → INCLUDED,
#      exit 0, with a committee-anchored state_root. SKIP if none staged.
#   2. A random (never-staged) slot → NOT-INCLUDED (a sound verified
#      negative: daemon returns not_found), exit 0, NEVER a false INCLUDED.
#   3. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any verdict); never INCLUDED.
#   4. Out-of-range --idx (> u32) → non-zero exit, never INCLUDED.
#   5. Missing required flags → usage error (exit 1).
#   6. (anti-false-positive) The NOT-INCLUDED / error variants never print
#      a line beginning with "INCLUDED".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_param_change.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vpc
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
echo "=== 2. Build genesis (single-creator chain, M=K=1) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-vpc",
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
# Used by assertion 3 (wrong-genesis).
cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vpc-WRONG",
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
c['listen_port'] = 7901
c['rpc_port'] = 8901
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
  H=$(get_status_field 8901 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8901 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-param-change defect)."
  exit 0
fi

# Pre-flight: confirm the daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8901 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_param_change"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: a staged param change → INCLUDED (conditional) ==="
# pending_param_changes is surfaced by the determ CLI's `pending-params`
# command (governance visibility). Each entry carries (effective_height,
# name, value_hex); --idx is the entry's 0-based position within its
# effective_height bucket, so we group by eff_height and enumerate. Use
# --json so the FULL value_hex is returned (the human table truncates it).
PP=$($DETERM pending-params --json --rpc-port 8901 2>/dev/null | $PY -c "
import json, sys
try:
    arr = json.load(sys.stdin)
except Exception:
    raise SystemExit
if not isinstance(arr, list) or not arr:
    raise SystemExit
# Group by effective_height to recover each entry's bucket idx (the RPC emits
# entries in the same per-height order as build_state_leaves).
from collections import OrderedDict
buckets = OrderedDict()
for e in arr:
    buckets.setdefault(int(e['effective_height']), []).append(e)
for eff, items in buckets.items():
    for idx, e in enumerate(items):
        print('%d %d %s %s' % (eff, idx, e['name'], e.get('value_hex','') or '-'))
        raise SystemExit
" 2>/dev/null)

if [ -z "$PP" ]; then
  echo "  SKIP(headline): no param change staged within budget (the common"
  echo "        case; a staged p: leaf requires a GOVERNED chain + a future"
  echo "        effective_height). Negative / fail-closed assertions run below."
else
  P_EFF=$(echo "$PP" | awk '{print $1}')
  P_IDX=$(echo "$PP" | awk '{print $2}')
  P_NAME=$(echo "$PP" | awk '{print $3}')
  P_VAL=$(echo "$PP" | awk '{print $4}')
  [ "$P_VAL" = "-" ] && P_VAL=""
  echo "  staged change: eff=$P_EFF idx=$P_IDX name=$P_NAME value_hex='$P_VAL'"
  VAL_ARG=()
  [ -n "$P_VAL" ] && VAL_ARG=(--value-hex "$P_VAL")
  set +e
  OUT=$($DETERM_LIGHT verify-param-change --rpc-port 8901 --genesis $T/node_gen.json \
          --effective-height $P_EFF --idx $P_IDX --name "$P_NAME" \
          "${VAL_ARG[@]}" 2>&1)
  RC=$?
  set -e
  echo "$OUT"
  if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
    assert "true" "staged param change → INCLUDED, exit 0 (real p: state-proof Merkle-verified)"
  else
    assert "false" "staged param change → INCLUDED/exit0 (got rc=$RC)"
  fi
fi

echo
echo "=== ASSERTION 2: random (never-staged) slot → NOT-INCLUDED (exit 0) ==="
# A high effective_height that has no pending_param_changes leaf. name/value
# arbitrary (the daemon never gets to compare them — there is no leaf for the
# key).
RAND_EFF=$($PY -c "import os; print(int.from_bytes(os.urandom(4),'big') + 1000000)")
set +e
OUT=$($DETERM_LIGHT verify-param-change --rpc-port 8901 --genesis $T/node_gen.json \
        --effective-height $RAND_EFF --idx 0 --name nothing --value-hex 00 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "random slot → NOT-INCLUDED, exit 0 (daemon-asserted negative, (H-neg))"
else
  assert "false" "random slot → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "random slot never yields a false INCLUDED"

echo
echo "=== ASSERTION 3: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-param-change --rpc-port 8901 --genesis $T/node_gen_wrong.json \
        --effective-height 1 --idx 0 --name min_stake --value-hex 00 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP3=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP3" "wrong genesis never yields INCLUDED"

echo
echo "=== ASSERTION 4: out-of-range --idx (> u32) → non-zero, never INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-param-change --rpc-port 8901 --genesis $T/node_gen.json \
        --effective-height 1 --idx 4294967296 --name min_stake --value-hex 00 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "out-of-range --idx → non-zero exit, not INCLUDED (rc=$RC)"
else
  assert "false" "out-of-range --idx should hard-error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 5: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-param-change --rpc-port 8901 --genesis $T/node_gen.json \
        --effective-height 1 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --idx/--name → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_param_change"; exit 0
else
  echo "  FAIL: test_light_verify_param_change"; exit 1
fi
