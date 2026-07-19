#!/usr/bin/env bash
# determ-light verify-enote-inclusion — NC-8 §5.6 (the FINAL NC-8 increment):
# the light-client enote scan. PROVE a scanned (commitment, ciphertext)
# encrypted-note delivery is the genuine on-chain one before trial-decrypting.
# The MODERN `en:` state leaf commits value = SHA256(commitment || enote); this
# reader binds the caller-provided pair on BOTH axes (key_bytes == "en:"+
# hex(commitment) AND value_hash == SHA256(commitment || enote)) and
# Merkle-verifies against the committee-signed state_root. A lying node that
# fabricates a ciphertext is caught (value_hash mismatch → UNVERIFIABLE); one
# that invents a commitment is caught (not_found → NOT-INCLUDED).
#
# NOTE: a live INCLUDED leg needs a chain carrying a CONFIDENTIAL_TRANSFER enote
# (a submitted CTX tx on a MODERN chain) — a separable follow-on. The
# INCLUDED-specific SHA256(commitment || enote) recompute is unit-gated by
# `determ test-ctx-enote` (the en: leaf value is that hash there) and the
# committee-anchor + Merkle machinery is byte-identical to the live-gated
# verify-registrant / verify-notekey INCLUDED. This test gates the NEW en:
# routing / value-hash-bind via the offline contract + the live NOT-INCLUDED
# (a random unseen commitment) + wrong-genesis legs.
#
# TWO parts:
#   A. OFFLINE arg/dispatch/exit-code contract (always runs, no cluster).
#   B. Best-effort LIVE leg: an unseen commitment → NOT-INCLUDED (exit 0,
#      daemon-asserted, (H-neg)) and wrong --genesis → fail-closed. SKIPs
#      (exit 0) when the local cluster can't mint blocks. Cluster-bound part is
#      NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_enote_inclusion.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_ven
TABS=$PROJECT_ROOT/$T

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# A well-formed 33-byte commitment (0x02 || 32 bytes) + a small enote hex.
# Never published on our fresh chain → the daemon returns not_found.
COMMIT_HEX="02$(printf '%064d' 0 | tr '0' 'a')"   # 66 hex chars = 33 bytes
ENOTE_HEX="deadbeefcafe"

declare -a NODE_PIDS
cluster_running=1
stop_cluster() {
  set +e
  if [ "$cluster_running" = "1" ]; then
    for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
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
echo "=== PART A: offline arg/dispatch/exit-code contract ==="

cat > $T/dummy_gen.json <<'EOF'
{ "chain_id": "x", "m_creators": 1, "k_block_sigs": 1, "initial_creators": [] }
EOF

set +e
$DETERM_LIGHT verify-enote-inclusion >/dev/null 2>&1;                                             RC_NONE=$?
$DETERM_LIGHT verify-enote-inclusion --genesis $T/dummy_gen.json --commitment $COMMIT_HEX --enote $ENOTE_HEX >/dev/null 2>&1; RC_NOPORT=$?
$DETERM_LIGHT verify-enote-inclusion --rpc-port 8941 --commitment $COMMIT_HEX --enote $ENOTE_HEX >/dev/null 2>&1; RC_NOGEN=$?
$DETERM_LIGHT verify-enote-inclusion --rpc-port 8941 --genesis $T/dummy_gen.json --enote $ENOTE_HEX >/dev/null 2>&1; RC_NOCOMMIT=$?
$DETERM_LIGHT verify-enote-inclusion --rpc-port 8941 --genesis $T/dummy_gen.json --commitment $COMMIT_HEX >/dev/null 2>&1; RC_NOENOTE=$?
$DETERM_LIGHT verify-enote-inclusion --rpc-port 8941 --genesis $T/dummy_gen.json --commitment $COMMIT_HEX --enote $ENOTE_HEX --bogus >/dev/null 2>&1; RC_UNK=$?
# A malformed (non-33-byte) commitment must be rejected at exit 1.
$DETERM_LIGHT verify-enote-inclusion --rpc-port 8941 --genesis $T/dummy_gen.json --commitment 02ab --enote $ENOTE_HEX >/dev/null 2>&1; RC_BADCOMMIT=$?
set -e

[ "$RC_NONE"    = "1" ] && assert "true" "no args → exit 1 (usage)"                 || assert "false" "no args → exit 1 (got $RC_NONE)"
[ "$RC_NOPORT"  = "1" ] && assert "true" "missing --rpc-port → exit 1"              || assert "false" "missing --rpc-port → exit 1 (got $RC_NOPORT)"
[ "$RC_NOGEN"   = "1" ] && assert "true" "missing --genesis → exit 1"               || assert "false" "missing --genesis → exit 1 (got $RC_NOGEN)"
[ "$RC_NOCOMMIT" = "1" ] && assert "true" "missing --commitment → exit 1"           || assert "false" "missing --commitment → exit 1 (got $RC_NOCOMMIT)"
[ "$RC_NOENOTE" = "1" ] && assert "true" "missing --enote → exit 1"                 || assert "false" "missing --enote → exit 1 (got $RC_NOENOTE)"
[ "$RC_UNK"     = "1" ] && assert "true" "unknown arg → exit 1"                     || assert "false" "unknown arg → exit 1 (got $RC_UNK)"
[ "$RC_BADCOMMIT" = "1" ] && assert "true" "non-33-byte commitment → exit 1"        || assert "false" "non-33-byte commitment → exit 1 (got $RC_BADCOMMIT)"

if $DETERM_LIGHT help 2>&1 | grep -qE "verify-enote-inclusion"; then
  assert "true" "verify-enote-inclusion listed in help"
else
  assert "false" "verify-enote-inclusion listed in help"
fi

# ───────────────────── PART B: best-effort LIVE leg ───────────────────────
echo
echo "=== PART B: live cluster leg (best-effort; SKIPs if starved) ==="

echo "=== B1. Init data dir + node key ==="
$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json

echo
echo "=== B2. Build genesis (single-creator chain, M=K=1) ==="
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-ven",
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

cat > $T/node_gen_wrong.json <<EOF
{
  "chain_id": "test-light-ven-WRONG",
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
c['listen_port'] = 7946
c['rpc_port'] = 8946
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
  H=$(get_status_field 8946 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8946 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-enote-inclusion defect)."
  echo
  echo "=== Test summary (offline contract only) ==="
  echo "  $pass_count pass / $fail_count fail"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_verify_enote_inclusion (offline contract; live leg skipped)"; exit 0
  else
    echo "  FAIL: test_light_verify_enote_inclusion"; exit 1
  fi
fi

BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8946 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_enote_inclusion"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: unseen commitment → NOT-INCLUDED (exit 0) ==="
# Our fresh chain has no CONFIDENTIAL_TRANSFER enote, so the en: leaf for any
# commitment is absent → the real en-namespace state_proof returns not_found →
# a daemon-asserted NOT-INCLUDED ((H-neg)). Exercises the NEW en: routing +
# not_found path end-to-end against a live committee-verified head.
set +e
OUT=$($DETERM_LIGHT verify-enote-inclusion --rpc-port 8946 \
        --genesis $T/node_gen.json --commitment $COMMIT_HEX --enote $ENOTE_HEX 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "unseen commitment → NOT-INCLUDED, exit 0 (daemon-asserted, (H-neg))"
else
  assert "false" "unseen commitment → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP1=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP1" "unseen commitment never yields a false INCLUDED"

echo
echo "=== ASSERTION 2: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-enote-inclusion --rpc-port 8946 \
        --genesis $T/node_gen_wrong.json --commitment $COMMIT_HEX --enote $ENOTE_HEX 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "wrong genesis never yields INCLUDED"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_enote_inclusion"; exit 0
else
  echo "  FAIL: test_light_verify_enote_inclusion"; exit 1
fi
