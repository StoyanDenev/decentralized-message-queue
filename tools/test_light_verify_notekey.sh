#!/usr/bin/env bash
# determ-light verify-notekey — NC-8 §5b: trust-minimized INCLUDED /
# NOT-INCLUDED / UNVERIFIABLE verdict on an account's standing recipient
# note_pk (the 33-byte P-256 point a sender seals a CONFIDENTIAL_TRANSFER enote
# to), anchored to the `nk:` (note-key) S-033 namespace. The read-side sibling
# of the REGISTER_NOTE_KEY consensus publication (inc.5a): a sender can obtain a
# recipient's note_pk without trusting the daemon.
#
# The verifier anchors genesis, committee-verifies the header chain to head,
# fetches the `nk:`-namespace state-proof (simple key: the daemon prepends
# "nk:" to the raw addr), and Merkle-verifies it against the committee-signed
# state_root — binding the proof to THIS account via key_bytes == "nk:"||addr
# AND value_hash == SHA256(note_pk), recomputed locally from the daemon's
# `account` note_key cleartext (UNTRUSTED — the value-hash-bind is what makes
# the read trustless).
#
# NOTE: a live INCLUDED leg needs a published note key (a REGISTER_NOTE_KEY tx),
# which needs a determ-light `register-note-key` builder + submit (a separable
# follow-on). The INCLUDED-specific SHA256(note_pk) recompute is unit-gated by
# `determ test-register-note-key` (the nk: leaf IS state-proof-provable there),
# and the committee-anchor + Merkle machinery is byte-identical to the
# live-gated verify-registrant INCLUDED. This test gates the NEW verify-notekey
# routing/cross-check via the offline contract + the live NOT-INCLUDED +
# wrong-genesis legs.
#
# This script has TWO parts:
#   A. OFFLINE arg/dispatch/exit-code contract (always runs, no cluster).
#   B. Best-effort LIVE leg: a note-key-less domain → NOT-INCLUDED (exit 0,
#      daemon-asserted, (H-neg)) and wrong --genesis → fail-closed. SKIPs
#      (exit 0) when the local cluster can't mint blocks, like the other
#      verify-* cluster tests. Cluster-bound part is NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_notekey.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vnk
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
echo "=== PART A: offline arg/dispatch/exit-code contract ==="

cat > $T/dummy_gen.json <<'EOF'
{ "chain_id": "x", "m_creators": 1, "k_block_sigs": 1, "initial_creators": [] }
EOF

set +e
$DETERM_LIGHT verify-notekey >/dev/null 2>&1;                                        RC_NONE=$?
$DETERM_LIGHT verify-notekey --genesis $T/dummy_gen.json --domain d >/dev/null 2>&1; RC_NOPORT=$?
$DETERM_LIGHT verify-notekey --rpc-port 8931 --domain d >/dev/null 2>&1;             RC_NOGEN=$?
$DETERM_LIGHT verify-notekey --rpc-port 8931 --genesis $T/dummy_gen.json >/dev/null 2>&1; RC_NODOM=$?
$DETERM_LIGHT verify-notekey --rpc-port 8931 --genesis $T/dummy_gen.json --domain d --bogus >/dev/null 2>&1; RC_UNK=$?
set -e

[ "$RC_NONE"  = "1" ] && assert "true" "no args → exit 1 (usage)"            || assert "false" "no args → exit 1 (got $RC_NONE)"
[ "$RC_NOPORT" = "1" ] && assert "true" "missing --rpc-port → exit 1"        || assert "false" "missing --rpc-port → exit 1 (got $RC_NOPORT)"
[ "$RC_NOGEN" = "1" ] && assert "true" "missing --genesis → exit 1"          || assert "false" "missing --genesis → exit 1 (got $RC_NOGEN)"
[ "$RC_NODOM" = "1" ] && assert "true" "missing --domain → exit 1"           || assert "false" "missing --domain → exit 1 (got $RC_NODOM)"
[ "$RC_UNK"   = "1" ] && assert "true" "unknown arg → exit 1"                || assert "false" "unknown arg → exit 1 (got $RC_UNK)"

if $DETERM_LIGHT help 2>&1 | grep -qE "verify-notekey"; then
  assert "true" "verify-notekey listed in help"
else
  assert "false" "verify-notekey listed in help"
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
  "chain_id": "test-light-vnk",
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
  "chain_id": "test-light-vnk-WRONG",
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
c['listen_port'] = 7926
c['rpc_port'] = 8926
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
  H=$(get_status_field 8926 height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field 8926 height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not a verify-notekey defect)."
  echo
  echo "=== Test summary (offline contract only) ==="
  echo "  $pass_count pass / $fail_count fail"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_verify_notekey (offline contract; live leg skipped)"; exit 0
  else
    echo "  FAIL: test_light_verify_notekey"; exit 1
  fi
fi

BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8926 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$NODE_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: daemon block0=$BLK0 but our genesis=$NODE_HASH"
  assert "false" "pre-flight: daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_notekey"; exit 1
fi
echo "  pre-flight OK: daemon runs our genesis"

echo
echo "=== ASSERTION 1: note-key-less domain → NOT-INCLUDED (exit 0) ==="
# node_n has published no note key (genesis creators are NOT auto-note-keyed),
# so the real nk-namespace state_proof returns not_found and the account
# note_key cross-check is null → a consistent daemon-asserted NOT-INCLUDED
# ((H-neg), NegativeVerdictSoundness.md). Exercises the NEW nk: routing +
# null-note_key cross-check end-to-end against a live committee-verified head.
set +e
OUT=$($DETERM_LIGHT verify-notekey --rpc-port 8926 \
        --genesis $T/node_gen.json --domain node_n 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "note-key-less domain → NOT-INCLUDED, exit 0 (daemon-asserted, (H-neg))"
else
  assert "false" "note-key-less domain → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP1=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP1" "note-key-less domain never yields a false INCLUDED"

echo
echo "=== ASSERTION 2: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-notekey --rpc-port 8926 \
        --genesis $T/node_gen_wrong.json --domain node_n 2>&1)
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
  echo "  PASS: test_light_verify_notekey"; exit 0
else
  echo "  FAIL: test_light_verify_notekey"; exit 1
fi
