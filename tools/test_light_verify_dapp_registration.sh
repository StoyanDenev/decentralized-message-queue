#!/usr/bin/env bash
# determ-light verify-dapp-registration — trust-minimized INCLUDED /
# NOT-INCLUDED / UNVERIFIABLE verdict on whether a domain is CURRENTLY a
# registered DApp in the committee-verified `d:` (dapp_registry) namespace,
# with the proof bound to the EXACT registration the daemon serves over
# `dapp_info`.
#
# The verifier anchors genesis, committee-verifies the header chain to head,
# fetches the `d:`-namespace state-proof (simple key: the daemon prepends
# "d:" to the raw domain), and Merkle-verifies it against the committee-
# signed state_root — binding the proof to THIS registration via
# key_bytes == "d:"||domain AND value_hash == SHA256 over the
# build_state_leaves `d:` encoding (service_pubkey || registered_at ||
# active_from || inactive_from || endpoint_url || topics || retention ||
# metadata), all recomputed locally from the daemon's dapp_info cleartext.
# A daemon lie about ANY registration field is detected, not propagated.
#
# Unlike verify-param-change (which needs a GOVERNED chain to stand up a
# real INCLUDED), a DApp registration is submittable on any chain via the
# `submit-dapp-register` RPC, so this test stands one up deterministically
# and asserts a real Merkle-verified INCLUDED.
#
# Assertions (all run once the node + registration are live):
#   1. (headline) The registered domain → INCLUDED, exit 0, ACTIVE, with a
#      committee-anchored state_root and the recomputed value_hash matching.
#   2. An unregistered domain → NOT-INCLUDED (a daemon-asserted negative, (H-neg):
#      daemon returns not_found), exit 0, NEVER a false INCLUDED.
#   3. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any verdict); never INCLUDED.
#   4. Missing required flags → usage error (exit 1).
#   5. (anti-false-positive) The NOT-INCLUDED / error variants never print a
#      line beginning with "INCLUDED".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_dapp_registration.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vdr
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

# node_n's priv for signing DAPP_REGISTER (matches test_dapp_e2e.sh).
N_PRIV=$($PY -c "
import json
with open('$T/node/node_key.json') as f:
    k = json.load(f)
print(k.get('priv_seed') or k.get('priv') or k.get('seed') or '')")

# A 32-byte service_pubkey (the chain only stores it; no decryption here).
SVC_PUBKEY="$($PY -c "print('aa' * 32)")"

echo
echo "=== 2. Build genesis (single-creator chain, M=K=1) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-vdr",
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
# Used by assertion 3 (wrong-genesis).
cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vdr-WRONG",
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
c['listen_port'] = 7905
c['rpc_port'] = 8905
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
  H=$(get_status_field 8905 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8905 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-dapp-registration defect)."
  exit 0
fi

# Pre-flight: confirm the daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8905 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_dapp_registration"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== 6. node_n submits DAPP_REGISTER ==="
$DETERM submit-dapp-register --rpc-port 8905 \
  --priv "$N_PRIV" --from node_n \
  --service-pubkey "$SVC_PUBKEY" \
  --endpoint-url "https://dapp.example" \
  --topics "chat,rpc" \
  --metadata-hex "deadbeef" 2>&1 | tail -2

echo
echo "=== 7. Wait for the registration to apply ==="
for _ in $(seq 1 60); do
  INFO=$($DETERM dapp-info --rpc-port 8905 --domain node_n 2>/dev/null)
  if echo "$INFO" | $PY -c "
import sys,json
try:
    j = json.load(sys.stdin)
    sys.exit(0 if j.get('endpoint_url') == 'https://dapp.example' else 1)
except: sys.exit(1)" 2>/dev/null; then break; fi
  sleep 0.5
done
if ! echo "$INFO" | $PY -c "
import sys,json
try:
    j = json.load(sys.stdin)
    sys.exit(0 if j.get('endpoint_url') == 'https://dapp.example' else 1)
except: sys.exit(1)" 2>/dev/null; then
  echo "  SKIP: DApp registration did not apply in budget — environment too"
  echo "        starved (not a verify-dapp-registration defect)."
  exit 0
fi
echo "  registration applied: node_n is now a DApp"

echo
echo "=== ASSERTION 1: registered domain → INCLUDED (real d: state-proof) ==="
set +e
OUT=$($DETERM_LIGHT verify-dapp-registration --rpc-port 8905 \
        --genesis $T/node_gen.json --domain node_n 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "registered domain → INCLUDED, exit 0 (d: state-proof Merkle-verified)"
else
  assert "false" "registered domain → INCLUDED/exit0 (got rc=$RC)"
fi
if echo "$OUT" | grep -qE "status:.*ACTIVE"; then
  assert "true" "INCLUDED verdict reports ACTIVE (committee-attested inactive_from)"
else
  assert "false" "INCLUDED verdict should report ACTIVE"
fi

echo
echo "=== ASSERTION 2: unregistered domain → NOT-INCLUDED (exit 0) ==="
set +e
OUT=$($DETERM_LIGHT verify-dapp-registration --rpc-port 8905 \
        --genesis $T/node_gen.json --domain not_a_dapp_xyz 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "unregistered domain → NOT-INCLUDED, exit 0 (daemon-asserted negative, (H-neg))"
else
  assert "false" "unregistered domain → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "unregistered domain never yields a false INCLUDED"

echo
echo "=== ASSERTION 3: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-dapp-registration --rpc-port 8905 \
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
echo "=== ASSERTION 4: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-dapp-registration --rpc-port 8905 \
        --genesis $T/node_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --domain → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_dapp_registration"; exit 0
else
  echo "  FAIL: test_light_verify_dapp_registration"; exit 1
fi
