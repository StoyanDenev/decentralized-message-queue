#!/usr/bin/env bash
# determ-light supply-trustless — verified A1 unitary-supply conservation read.
#
# Boots a 3-node cluster. Runs the composite `supply-trustless --json` which:
# (1) anchors the genesis hash, (2) walks the chain verifying every committee
# sig, (3) fetches a state-proof for each of the five A1 supply counters from
# the `c:` namespace (genesis_total, accumulated_subsidy/inbound/slashed/
# outbound), each Merkle-verified against the SAME committee-signed
# state_root and hash-bound to the daemon's chain_summary cleartext, then
# (4) recomputes the closed-form A1 identity (genesis_total + subsidy +
# inbound - slashed - outbound) from the committed values and compares it
# against the daemon's claimed total_supply. Parity-checks the verified
# counters + the recomputed expected_total against `determ supply` from the
# full-binary side.
#
# This is the supply-namespace (c:) analogue of test_light_balance_trustless.sh
# (a:) and test_light_stake_trustless.sh (s:). Unlike those single-leaf reads,
# supply-trustless verifies a CROSS-LEAF invariant: the five committed counters
# are bound by the A1 identity the apply path enforces at every block
# (chain.cpp: `if (live_total_supply() != expected_total()) throw`), which is
# publicly recomputable from the committed counters alone — see
# docs/proofs/SupplyProofSoundness.md (SU-1..SU-E).
#
# The five c: counters are read via five SEQUENTIAL state_proof calls, so on a
# fast-producing single-host cluster the head can advance between them and the
# client CORRECTLY fail-closes on the cross-snapshot read ("daemon split the read
# across two states") rather than recompute the A1 identity over inconsistent
# state. Per the owner decision (Q2 = A) that is the intended safety posture
# (safety over liveness), so the honest-path assertions BRANCH host-independently:
#   CONSERVED path (chain quiesced): exit 0 + conserved=true + verdict CONSERVED
#     + five counters + 64-hex state_root + A1 recompute + parity vs `determ supply`.
#   SAFETY path (chain moving): the client returns UNVERIFIABLE/exit 3 with the
#     cross-snapshot detail, never a false CONSERVED, and the five counters still
#     parse + the A1 arithmetic still recomputes on the unverified JSON.
# Both paths gate the client behaving correctly; see SupplyProofSoundness.md and
# ProofClaimGateTraceability.md §3e.
#
# Run from repo root: bash tools/test_light_supply_trustless.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_supply_trustless
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cleanup() {
  rc=$?
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  # Preserve the script's real exit status — the kill -9 of an
  # already-dead PID returns non-zero and would otherwise clobber a
  # passing run's exit 0.
  return $rc
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes + genesis with staked creators ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-su",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "alice", "balance": 500}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path']   = '$TABS/n$n/node_key.json'
c['data_dir']   = '$TABS/n$n'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7811 8811 '["127.0.0.1:7812","127.0.0.1:7813"]'
configure_node 2 7812 8812 '["127.0.0.1:7811","127.0.0.1:7813"]'
configure_node 3 7813 8813 '["127.0.0.1:7811","127.0.0.1:7812"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 5 (subsidy accumulates) ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8811 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. determ-light supply-trustless --json ==="
# supply-trustless reads the five c: counters via five SEQUENTIAL state_proof
# calls; on a fast-producing chain the head can advance between them, so a later
# counter anchors to a newer state_root and the client CORRECTLY fail-closes on
# the cross-snapshot read ("daemon split the read across two states"). That is
# the intended safety posture (accept fail-closed), not a client defect — so the
# honest CONSERVED control is obtained under a QUIESCENT window: the fixture
# above slows block cadence to ~2 s so the five-read span fits inside one block
# interval, `--wait` supplies the committee-signed successor for the head bind,
# and we retry a few times to ride out any residual advance.
verdict_of() {
  echo "$1" | tail -1 | python -c "import json,sys
try: print(json.loads(sys.stdin.read()).get('verdict','MISSING'))
except Exception: print('MISSING')"
}
set +e
OUT=""; RC=1
for attempt in 1 2 3 4 5 6; do
  OUT=$($DETERM_LIGHT supply-trustless --rpc-port 8811 --genesis $T/gen.json --wait 20 --json 2>&1)
  RC=$?
  V=$(verdict_of "$OUT")
  if [ "$RC" = "0" ] && [ "$V" = "CONSERVED" ]; then break; fi
  echo "  (attempt $attempt: rc=$RC verdict=$V — chain advanced mid-read; retrying)"
  sleep 1
done
set -e
echo "$OUT"
V=$(verdict_of "$OUT")
CONSERVED_PATH=0
[ "$RC" = "0" ] && [ "$V" = "CONSERVED" ] && CONSERVED_PATH=1

# Common to both paths: the five counters are parsed + present, and the client's
# A1 recompute is arithmetically sound — true even in the UNVERIFIABLE JSON, so
# these gate the reader's parsing/arithmetic independent of the verdict.
FIELDS_OK=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = ['genesis_total','accumulated_subsidy','accumulated_inbound',
            'accumulated_slashed','accumulated_outbound','expected_total']
    print('true' if all(k in d for k in need) else 'false')
except Exception:
    print('false')
")
RECOMPUTE_OK=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    g=int(d['genesis_total']); s=int(d['accumulated_subsidy'])
    i=int(d['accumulated_inbound']); sl=int(d['accumulated_slashed'])
    o=int(d['accumulated_outbound'])
    print('true' if g+s+i-sl-o == int(d['expected_total']) else 'false')
except Exception:
    print('false')
")

if [ "$CONSERVED_PATH" = "1" ]; then
  # ── STRONG PATH: the chain quiesced enough for a consistent 5-counter snapshot.
  echo "=== 4-10. CONSERVED path (consistent snapshot) ==="
  assert "true" "supply-trustless --json exit 0 (CONSERVED)"
  CONSERVED=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print('true' if json.loads(sys.stdin.read()).get('conserved', False) else 'false')
except Exception: print('false')")
  assert "$CONSERVED" "supply-trustless JSON has conserved=true"
  assert "true" "verdict=CONSERVED"
  assert "$FIELDS_OK" "five counters + expected_total present"
  SR_PRESENT=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print('true' if len(json.loads(sys.stdin.read()).get('state_root','')) == 64 else 'false')
except Exception: print('false')")
  assert "$SR_PRESENT" "state_root populated (64 hex chars)"
  assert "$RECOMPUTE_OK" "expected_total == g+subsidy+inbound-slashed-outbound"

  # Parity vs the full binary (only meaningful on the verified path).
  LIGHT_EXP=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print(int(json.loads(sys.stdin.read())['expected_total']))
except Exception: print(-1)")
  FULL_EXP=$($DETERM supply --rpc-port 8811 --field expected_total 2>/dev/null | tr -d '[:space:]')
  if [ -n "$FULL_EXP" ] && [ "$FULL_EXP" = "$LIGHT_EXP" ]; then
      assert "true" "parity expected_total: light=$LIGHT_EXP == full=$FULL_EXP"
  else
      assert "false" "parity expected_total: light=$LIGHT_EXP vs full=$FULL_EXP"
  fi
  for FIELD in genesis_total accumulated_slashed accumulated_outbound; do
    LIGHT_V=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print(int(json.loads(sys.stdin.read())['$FIELD']))
except Exception: print(-1)")
    FULL_V=$($DETERM supply --rpc-port 8811 --field $FIELD 2>/dev/null | tr -d '[:space:]')
    if [ -n "$FULL_V" ] && [ "$FULL_V" = "$LIGHT_V" ]; then
        assert "true" "parity $FIELD: light=$LIGHT_V == full=$FULL_V"
    else
        assert "false" "parity $FIELD: light=$LIGHT_V vs full=$FULL_V"
    fi
  done
else
  # ── SAFETY PATH: honest read on a moving chain. The five c: counters are read
  # via five SEQUENTIAL state_proof calls; on a fast-producing single-host cluster
  # the head advances between them, so a later counter anchors to a newer
  # state_root and the client CORRECTLY refuses to recompute the A1 identity
  # across two snapshots. Per the owner decision (Q2 = A), fail-closed is the
  # intended safety posture (safety over liveness); this leg gates that behavior
  # host-independently. Cross-refs SupplyProofSoundness.md,
  # ProofClaimGateTraceability.md §3e.
  echo "=== 4-10. SAFETY path — chain never quiesced; asserting correct fail-close ==="
  if [ "$RC" = "3" ] && echo "$OUT" | tail -1 | grep -q "split the read across two states"; then
    assert "true" "moving-chain honest read → correct cross-snapshot fail-close (UNVERIFIABLE, exit 3)"
  else
    assert "false" "honest read neither CONSERVED nor a correct cross-snapshot fail-close (rc=$RC verdict=$V)"
  fi
  NOFALSE=$(echo "$OUT" | tail -1 | grep -q '"conserved":true' && echo false || echo true)
  assert "$NOFALSE" "moving-chain read never yields a false CONSERVED"
  assert "$FIELDS_OK" "five counters + expected_total present in the (unverified) JSON"
  assert "$RECOMPUTE_OK" "expected_total recomputes from the counters (client arithmetic sound even unverified)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_supply_trustless"; exit 0
else
  echo "  FAIL: test_light_supply_trustless"; exit 1
fi
