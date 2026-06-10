#!/usr/bin/env bash
# determ-light verify-account — trust-minimized EXISTS / NOT-CREATED /
# UNVERIFIABLE verdict on whether an ANON account has been materialized
# on-chain, with the canonical address DERIVED LOCALLY from either a raw
# Ed25519 pubkey (--pubkey) or an anon-address (--address).
#
# THEME: anon-address derivation, normalization (S-028) & the account
# auto-creation-on-first-credit lifecycle.
#
# The verifier (1) derives + lowercase-normalizes the canonical 0x address
# locally — with --pubkey it mirrors make_anon_address ("0x" +
# lowercase-hex(pubkey)); with --address it re-derives the pubkey and
# round-trips to canonical form, catching a case-mixed input. It then (2)
# anchors genesis, committee-verifies the header chain to head, and (3)
# renders a verdict against the `a:` namespace: a committee-anchored
# Merkle proof → EXISTS (verified balance + next_nonce, hash-bound to the
# daemon's `account` cleartext); a state_proof not_found at the verified
# head → NOT-CREATED, a DAEMON-ASSERTED negative — sound only under the
# single-daemon (H-neg) honesty premise (NegativeVerdictSoundness.md
# NV-2/NV-3), stronger than the fabricated zero the bare `account` RPC
# returns for any unknown address but NOT a cryptographic absence proof;
# --json tags it negative_footing=daemon_asserted. Unlike balance-trustless,
# which THROWS on a not_found leaf, verify-account distinguishes "never
# created" from "created then drained".
#
# Assertions (all run once the node + funded anon account are live):
#   1. (headline) The genesis-funded anon address → EXISTS, exit 0, with the
#      committee-anchored balance reported.
#   2. The SAME account queried by --pubkey <64-hex> → EXISTS, and the
#      printed canonical `address:` equals the lowercase 0x form (proves the
#      local make_anon_address derivation, no daemon trust).
#   3. The SAME account queried by an UPPERCASE --address → EXISTS with the
#      identical canonical address (S-028 normalization to one leaf).
#   4. An uncredited derived anon address → NOT-CREATED (a daemon-asserted
#      negative: state_proof not_found, (H-neg)), exit 0, never a false
#      EXISTS.
#   5. Wrong --genesis → fail-closed, non-zero exit; never EXISTS.
#   6. Missing / conflicting flags → usage error (exit 1).
#   7. (anti-false-positive) The NOT-CREATED / error variants never print a
#      line beginning with "EXISTS".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_account.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vacc
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

echo "=== 1. Init data dir + node key + two anon accounts ==="
$DETERM init --data-dir $T/node --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json

# Funded anon account (EXISTS path): create a keyfile + extract its address.
$DETERM account create --out $T/anon_funded.key 2>&1 > $T/anon_funded.out
FUNDED_ADDR=$(grep -oE "0x[0-9a-f]{64}" $T/anon_funded.out | head -1)
if [ -z "$FUNDED_ADDR" ]; then
  FUNDED_ADDR=$($PY -c "
import json
try:
    j = json.load(open('$T/anon_funded.key'))
    pk = j.get('pub_hex') or j.get('pubkey') or j.get('address','')
    if pk and not pk.startswith('0x'): pk = '0x' + pk
    print(pk)
except Exception: print('')")
fi
echo "  funded anon address: $FUNDED_ADDR"

# Uncredited anon account (NOT-CREATED path): create but DO NOT fund it.
$DETERM account create --out $T/anon_empty.key 2>&1 > $T/anon_empty.out
EMPTY_ADDR=$(grep -oE "0x[0-9a-f]{64}" $T/anon_empty.out | head -1)
if [ -z "$EMPTY_ADDR" ]; then
  EMPTY_ADDR=$($PY -c "
import json
try:
    j = json.load(open('$T/anon_empty.key'))
    pk = j.get('pub_hex') or j.get('pubkey') or j.get('address','')
    if pk and not pk.startswith('0x'): pk = '0x' + pk
    print(pk)
except Exception: print('')")
fi
echo "  uncredited anon address: $EMPTY_ADDR"

if [ -z "$FUNDED_ADDR" ] || [ -z "$EMPTY_ADDR" ]; then
  echo "  SKIP: could not generate anon addresses (account create output"
  echo "        format differs) — not a verify-account defect."
  exit 0
fi

# The bare 64-hex pubkey (no 0x) for the --pubkey derivation assertion.
FUNDED_PUBKEY=$($PY -c "print('$FUNDED_ADDR'[2:])")
# Uppercase variant of the funded address for the S-028 assertion.
FUNDED_UPPER=$($PY -c "print('0x' + '$FUNDED_ADDR'[2:].upper())")

echo
echo "=== 2. Build genesis (single-creator chain, M=K=1, fund FUNDED_ADDR) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-vacc",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "$FUNDED_ADDR", "balance": 500000}
  ]
}
EOF
$DETERM genesis-tool build $T/node_gen.json | tail -1
NODE_HASH=$(cat $T/node_gen.json.hash)

# A DIFFERENT genesis (different chain_id) → different compute_genesis_hash.
# Used by the wrong-genesis assertion.
cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vacc-WRONG",
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
c['listen_port'] = 7907
c['rpc_port'] = 8907
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
  H=$(get_status_field 8907 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8907 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-account defect)."
  exit 0
fi

# Pre-flight: confirm the daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8907 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_account"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: funded anon address → EXISTS (real a: state-proof) ==="
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json --address $FUNDED_ADDR 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^EXISTS"; then
  assert "true" "funded address → EXISTS, exit 0 (a: state-proof Merkle-verified)"
else
  assert "false" "funded address → EXISTS/exit0 (got rc=$RC)"
fi
if echo "$OUT" | grep -qE "balance:[[:space:]]+500000"; then
  assert "true" "EXISTS reports the committee-anchored balance (500000)"
else
  assert "false" "EXISTS should report balance 500000"
fi

echo
echo "=== ASSERTION 2: --pubkey derivation → EXISTS, canonical address printed ==="
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json --pubkey $FUNDED_PUBKEY 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^EXISTS"; then
  assert "true" "--pubkey derives the funded account → EXISTS, exit 0"
else
  assert "false" "--pubkey → EXISTS/exit0 (got rc=$RC)"
fi
if echo "$OUT" | grep -qE "address:[[:space:]]+$FUNDED_ADDR\$"; then
  assert "true" "--pubkey prints the canonical lowercase make_anon_address form"
else
  assert "false" "--pubkey should print canonical address $FUNDED_ADDR"
fi

echo
echo "=== ASSERTION 3: UPPERCASE --address normalizes (S-028) → same EXISTS ==="
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json --address $FUNDED_UPPER 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^EXISTS" \
   && echo "$OUT" | grep -qE "address:[[:space:]]+$FUNDED_ADDR\$"; then
  assert "true" "uppercase --address normalizes to the SAME canonical leaf → EXISTS"
else
  assert "false" "uppercase --address should normalize + EXISTS (got rc=$RC)"
fi

echo
echo "=== ASSERTION 4: uncredited anon address → NOT-CREATED (exit 0) ==="
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json --address $EMPTY_ADDR 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-CREATED"; then
  assert "true" "uncredited address → NOT-CREATED, exit 0 (daemon-asserted negative, (H-neg))"
else
  assert "false" "uncredited address → NOT-CREATED/exit0 (got rc=$RC)"
fi
NOFP4=$(echo "$OUT" | grep -qE "^EXISTS" && echo false || echo true)
assert "$NOFP4" "uncredited address never yields a false EXISTS"

echo
echo "=== ASSERTION 5: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen_wrong.json --address $FUNDED_ADDR 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP5=$(echo "$OUT" | grep -qE "^EXISTS" && echo false || echo true)
assert "$NOFP5" "wrong genesis never yields EXISTS"

echo
echo "=== ASSERTION 6: missing / conflicting flags → usage error (exit 1) ==="
# Neither --pubkey nor --address.
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "neither --pubkey nor --address → usage error (exit 1)"
else
  assert "false" "missing identity flag should be a usage error (got rc=$RC)"
fi
# BOTH --pubkey and --address (mutually exclusive).
set +e
OUT=$($DETERM_LIGHT verify-account --rpc-port 8907 \
        --genesis $T/node_gen.json \
        --pubkey $FUNDED_PUBKEY --address $FUNDED_ADDR 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ]; then
  assert "true" "both --pubkey and --address → usage error (exit 1, exactly one)"
else
  assert "false" "both identity flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_account"; exit 0
else
  echo "  FAIL: test_light_verify_account"; exit 1
fi
