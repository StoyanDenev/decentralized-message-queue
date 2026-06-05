#!/usr/bin/env bash
# determ-light committee-at-height — trust-minimized reader for the
# consensus committee (the set of block creators) that produced block H.
#
# The reader anchors genesis, binds header[H] to block 0 via a prev_hash
# chain walk, and verifies header[H]'s K-of-K (MD) / ceil(2K/3) (BFT)
# committee sigs over light_compute_block_digest(H) — which BINDS
# creators[] (see light/verify.cpp: `for (auto& c : b.creators)
# h.append(c)`). Only after that anchor succeeds does it enumerate
# creators[] paired with each member's genesis-committee ed_pub + per-slot
# sign status. So the reported committee is committee-attested, not merely
# daemon-asserted. With --member <D> it answers a sound
# IN-COMMITTEE / NOT-IN-COMMITTEE membership query.
#
# Distinct from verify-block-sigs (which checks sigs against a committee
# the OPERATOR supplies): committee-at-height DERIVES the committee
# trustlessly from the chain.
#
# Assertions (all run against a live single-node, M=K=1 chain):
#   1. committee-at-height at a produced block (H>=1) → OK, exit 0, and
#      lists the genesis creator domain.
#   2. --member <genesis-creator> → IN-COMMITTEE, exit 0.
#   3. --member <never-a-member> → NOT-IN-COMMITTEE, exit 0, never
#      IN-COMMITTEE.
#   4. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any committee is reported).
#   5. --height 0 (genesis) → rejected with a diagnostic, non-zero exit
#      (genesis has no committee by construction).
#   6. --height beyond head → non-zero exit (refuses to report a committee
#      the daemon cannot serve), never OK.
#   7. Missing required flags → usage error (exit 1).
#   8. --json output is valid JSON with committee_verified=true and a
#      non-empty members array.
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_committee_at_height.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_cah
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
  "chain_id": "test-light-cah",
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
  "chain_id": "test-light-cah-WRONG",
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
echo "=== 5. Poll until node produces blocks (need H>=1) ==="
for _ in $(seq 1 90); do
  H=$(get_status_field 8903 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8903 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a committee-at-height defect)."
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
  echo "  FAIL: test_light_committee_at_height"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

# Query a produced (non-genesis) block. Block index 1 is always produced
# once height >= 2.
QH=1

echo
echo "=== ASSERTION 1: committee-at-height at H=$QH → OK, lists creator ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height $QH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^OK" && echo "$OUT" | grep -q "node_n"; then
  assert "true" "H=$QH → OK, exit 0, committee lists node_n (committee-attested)"
else
  assert "false" "H=$QH → OK/exit0 listing node_n (got rc=$RC)"
fi

echo
echo "=== ASSERTION 2: --member node_n → IN-COMMITTEE, exit 0 ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height $QH --member node_n 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "IN-COMMITTEE"; then
  assert "true" "member node_n → IN-COMMITTEE, exit 0 (sound verified membership)"
else
  assert "false" "member node_n → IN-COMMITTEE/exit0 (got rc=$RC)"
fi

echo
echo "=== ASSERTION 3: --member nonsuch → NOT-IN-COMMITTEE, exit 0 ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height $QH --member nonsuch_validator 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "NOT-IN-COMMITTEE"; then
  assert "true" "member nonsuch → NOT-IN-COMMITTEE, exit 0 (sound verified negative)"
else
  assert "false" "member nonsuch → NOT-IN-COMMITTEE/exit0 (got rc=$RC)"
fi
NOFP3=$(echo "$OUT" | grep -qE "IN-COMMITTEE -> IN-COMMITTEE|-> IN-COMMITTEE" && echo false || echo true)
assert "$NOFP3" "non-member never yields a false IN-COMMITTEE"

echo
echo "=== ASSERTION 4: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen_wrong.json \
        --height $QH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP4=$(echo "$OUT" | grep -qE "^OK" && echo false || echo true)
assert "$NOFP4" "wrong genesis never reports a committee"

echo
echo "=== ASSERTION 5: --height 0 (genesis) → rejected, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height 0 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && echo "$OUT" | grep -qiE "genesis|no committee"; then
  assert "true" "H=0 (genesis) rejected with diagnostic (exit $RC)"
else
  assert "false" "H=0 should be rejected (genesis has no committee; got rc=$RC)"
fi

echo
echo "=== ASSERTION 6: --height beyond head → non-zero, never OK ==="
BEYOND=$(( NODE_H + 1000000 ))
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height $BEYOND 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^OK"; then
  assert "true" "height beyond head → non-zero exit, not OK (rc=$RC)"
else
  assert "false" "height beyond head should fail-closed (got rc=$RC)"
fi

echo
echo "=== ASSERTION 7: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --height → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 8: --json output is valid + committee_verified=true ==="
set +e
OUT=$($DETERM_LIGHT committee-at-height --rpc-port 8903 --genesis $T/node_gen.json \
        --height $QH --json 2>&1)
RC=$?
set -e
echo "$OUT"
JOK=$(echo "$OUT" | tail -1 | $PY -c "
import json, sys
try:
    o = json.load(sys.stdin)
    ok = (o.get('committee_verified') is True
          and isinstance(o.get('members'), list)
          and len(o['members']) >= 1
          and o.get('height') == $QH)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$RC" = "0" ] && [ "$JOK" = "true" ]; then
  assert "true" "--json: committee_verified=true, non-empty members, height=$QH"
else
  assert "false" "--json output malformed or not committee_verified (rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_committee_at_height"; exit 0
else
  echo "  FAIL: test_light_committee_at_height"; exit 1
fi
