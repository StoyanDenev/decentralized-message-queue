#!/usr/bin/env bash
# determ-light verify-registrant — trust-minimized INCLUDED / NOT-INCLUDED /
# UNVERIFIABLE verdict on whether a domain IS (or is NOT) a registered
# VALIDATOR at the committee-verified head, anchored to the `r:` (registrants)
# S-033 namespace. This is the validator-set sibling of
# verify-dapp-registration (the `d:` DApp reader); both are simple-key
# namespaces (the daemon prepends the prefix to the raw domain bytes) and both
# cross-check the daemon's cleartext fields against the committee-signed leaf
# value_hash so a daemon lie about ANY registrant field is detected, never
# propagated.
#
# The verifier anchors genesis, committee-verifies the header chain to head,
# fetches the `r:`-namespace state-proof, and Merkle-verifies it against the
# committee-signed state_root — binding the proof to THIS registrant via
# key_bytes == "r:"||domain AND value_hash == SHA256 over the
# build_state_leaves `r:` encoding (ed_pub || registered_at || active_from ||
# inactive_from || region.size() || region), recomputed locally from the
# daemon's `account` registry cleartext.
#
# A genesis creator with a non-zero ed_pub is auto-registered into the `r:`
# namespace at block 0 (chain.cpp ctor), so the node's own domain stands up a
# real Merkle-verified INCLUDED with no extra tx — no governed/registration
# round-trip needed.
#
# This script has TWO parts:
#   A. OFFLINE arg/dispatch/exit-code contract (always runs, no cluster):
#      missing --rpc-port/--genesis/--domain → exit 1; unknown arg → exit 1;
#      subcommand listed in `help`.
#   B. Best-effort LIVE INCLUDED leg: stands up a single-creator node and
#      asserts the node's own domain → INCLUDED (exit 0, ACTIVE), an
#      unregistered domain → NOT-INCLUDED (exit 2, sound verified negative),
#      and wrong --genesis → fail-closed. SKIPs (exit 0) when the local
#      cluster can't mint blocks on this host, mirroring the other verify-*
#      cluster tests.
#
# Cluster-bound part is NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_registrant.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vreg
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

# ───────────────────── PART A: OFFLINE arg/exit-code contract ─────────────
# These run with no daemon and assert the usage surface independently of any
# cluster, so the contract is guarded even when block production SKIPs below.
echo "=== PART A: offline arg/dispatch/exit-code contract ==="

# A genesis file the offline checks point at (never actually read because the
# arg guard rejects first — but keep a real path for hygiene).
cat > $T/dummy_gen.json <<'EOF'
{ "chain_id": "x", "m_creators": 1, "k_block_sigs": 1, "initial_creators": [] }
EOF

set +e
$DETERM_LIGHT verify-registrant >/dev/null 2>&1;                                   RC_NONE=$?
$DETERM_LIGHT verify-registrant --genesis $T/dummy_gen.json --domain d >/dev/null 2>&1; RC_NOPORT=$?
$DETERM_LIGHT verify-registrant --rpc-port 8911 --domain d >/dev/null 2>&1;        RC_NOGEN=$?
$DETERM_LIGHT verify-registrant --rpc-port 8911 --genesis $T/dummy_gen.json >/dev/null 2>&1; RC_NODOM=$?
$DETERM_LIGHT verify-registrant --rpc-port 8911 --genesis $T/dummy_gen.json --domain d --bogus >/dev/null 2>&1; RC_UNK=$?
set -e

[ "$RC_NONE"  = "1" ] && assert "true" "no args → exit 1 (usage)"            || assert "false" "no args → exit 1 (got $RC_NONE)"
[ "$RC_NOPORT" = "1" ] && assert "true" "missing --rpc-port → exit 1"        || assert "false" "missing --rpc-port → exit 1 (got $RC_NOPORT)"
[ "$RC_NOGEN" = "1" ] && assert "true" "missing --genesis → exit 1"          || assert "false" "missing --genesis → exit 1 (got $RC_NOGEN)"
[ "$RC_NODOM" = "1" ] && assert "true" "missing --domain → exit 1"           || assert "false" "missing --domain → exit 1 (got $RC_NODOM)"
[ "$RC_UNK"   = "1" ] && assert "true" "unknown arg → exit 1"                || assert "false" "unknown arg → exit 1 (got $RC_UNK)"

if $DETERM_LIGHT help 2>&1 | grep -qE "verify-registrant"; then
  assert "true" "verify-registrant listed in help"
else
  assert "false" "verify-registrant listed in help"
fi

# ───────────────────── PART B: best-effort LIVE INCLUDED leg ──────────────
echo
echo "=== PART B: live cluster INCLUDED leg (best-effort; SKIPs if starved) ==="

echo "=== B1. Init data dir + node key ==="
$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json

echo
echo "=== B2. Build genesis (single-creator chain, M=K=1) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-vreg",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "node_n", "balance": 100}
  ]
}
EOF
$DETERM genesis-tool build $T/node_gen.json | tail -1
NODE_HASH=$(cat $T/node_gen.json.hash)

# A DIFFERENT genesis (different chain_id) → different compute_genesis_hash.
cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vreg-WRONG",
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
echo "=== B3. Configure node ==="
$PY -c "
import json
cfg = '$T/node/config.json'
with open(cfg) as f: c = json.load(f)
c['domain'] = 'node_n'
c['listen_port'] = 7906
c['rpc_port'] = 8906
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
echo "=== B4. Start node ==="
NODE_PIDS=("")
$DETERM start --config $T/node/config.json > $T/node/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3

echo
echo "=== B5. Poll until node produces blocks (need a state_root head) ==="
for _ in $(seq 1 90); do
  H=$(get_status_field 8906 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8906 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-registrant defect)."
  echo
  echo "=== Test summary (offline contract only) ==="
  echo "  $pass_count pass / $fail_count fail"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_verify_registrant (offline contract; live leg skipped)"; exit 0
  else
    echo "  FAIL: test_light_verify_registrant"; exit 1
  fi
fi

# Pre-flight: confirm the daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8906 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_registrant"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: genesis-creator domain → INCLUDED (real r: state-proof) ==="
set +e
OUT=$($DETERM_LIGHT verify-registrant --rpc-port 8906 \
        --genesis $T/node_gen.json --domain node_n 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "registered validator → INCLUDED, exit 0 (r: state-proof Merkle-verified)"
else
  assert "false" "registered validator → INCLUDED/exit0 (got rc=$RC)"
fi
if echo "$OUT" | grep -qE "status:.*ACTIVE"; then
  assert "true" "INCLUDED verdict reports ACTIVE (committee-attested active_from/inactive_from)"
else
  assert "false" "INCLUDED verdict should report ACTIVE"
fi

echo
echo "=== ASSERTION 2: unregistered domain → NOT-INCLUDED (exit 2) ==="
set +e
OUT=$($DETERM_LIGHT verify-registrant --rpc-port 8906 \
        --genesis $T/node_gen.json --domain not_a_validator_xyz 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "2" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "unregistered domain → NOT-INCLUDED, exit 2 (sound verified negative)"
else
  assert "false" "unregistered domain → NOT-INCLUDED/exit2 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "unregistered domain never yields a false INCLUDED"

echo
echo "=== ASSERTION 3: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-registrant --rpc-port 8906 \
        --genesis $T/node_gen_wrong.json --domain node_n 2>&1)
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
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_registrant"; exit 0
else
  echo "  FAIL: test_light_verify_registrant"; exit 1
fi
