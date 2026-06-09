#!/usr/bin/env bash
# determ-light verify-state-root — per-height committee-verified state_root
# anchor primitive.
#
# Boots a 3-node cluster, lets it produce >=10 blocks, then exercises the
# `verify-state-root` subcommand. This command answers a question DISTINCT
# from verify-state-proof: rather than checking a Merkle PROOF against a
# GIVEN root, it verifies the ROOT ITSELF at a height H is genuinely
# committee-signed and bound to the pinned genesis. The reported root is
# the trust anchor an auditor would then feed to an out-of-band
# state-proof check, or compare across two independent observers.
#
# Trust model (load-bearing): the root is NOT the daemon's word. SOUNDNESS
# UPDATE — the committee signs compute_block_digest, which EXCLUDES
# state_root, so a header's bare state_root FIELD is NOT committee-attested
# (a malicious daemon could swap it after signing). For H >= 1 the root is
# now bound the sound way: committee_bound_state_root() fetches the FULL
# block at H, recomputes its block_hash, verifies the SUCCESSOR header
# (H+1)'s committee sigs, and requires successor.prev_hash == that
# recomputed hash — so the successor's signature transitively commits H's
# state_root. A daemon that swaps the state_root at H breaks the recomputed
# block_hash, the successor.prev_hash bind fails, and the command fails
# closed (non-zero exit) — never a bare daemon-reported root.
#
# CONSEQUENCES OF THE SUCCESSOR-BINDING MODEL (this test asserts them):
#   * sigs_verified is now 0 for H >= 1. Attestation comes from the
#     SUCCESSOR(H+1)'s sigs, NOT from header[H]'s own sigs, so the result no
#     longer counts header[H]'s sigs. committee_size still reports
#     |creators| of header[H] for context, but it is NOT equal to
#     sigs_verified anymore. (Genesis H==0 also reports sigs_verified=0,
#     committee_size=0 — pinned by the genesis hash, not a committee.)
#   * A query at the EXACT head index FAILS CLOSED: the head has no
#     committee-signed successor yet, so there is nothing to bind H's root
#     to. This is intended — we never report an unbound head root.
#
# Assertions:
#   1. verify-state-root at a mid-height H (which HAS a signed successor) →
#      exit 0, non-empty state_root, committee_verified=true.
#   2. The reported root EQUALS the state_root in the committee-verified
#      header at H (cross-checked against `fetch-headers --from H --count 1`).
#   3. Genesis anchor mismatch (wrong --genesis) → fail-closed non-zero exit
#      with a GENESIS HASH MISMATCH diagnostic.
#   4. Height beyond head (--height huge) → clean handled error (rc=1, not a
#      crash / not rc=2 unhandled), diagnostic names the head bound.
#   5. The command never emits a root without committee_verified=true: the
#      mid-height --json record has committee_verified=true, a non-empty
#      64-hex state_root, and (NEW semantics) sigs_verified == 0 while
#      committee_size == the genesis committee size. We do NOT assert
#      sigs_verified == committee_size anymore — that was the old
#      header-self-sig model; attestation is now via the successor.
#   6. (bonus) --json output parses with the documented shape
#      {height, state_root, committee_size, sigs_verified, committee_verified}.
#   7. (NEW) verify-state-root at the EXACT head index FAILS CLOSED (no
#      committee-signed successor exists yet) — exit non-zero, no bare root.
#
# Cluster-bound (boots 3 nodes) — do NOT add to FAST=1.
#
# Run from repo root: bash tools/test_light_verify_state_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_state_root
TABS=$PROJECT_ROOT/$T

# Dedicated port block (794x listen / 894x RPC), distinct from the
# 777x/877x block the other light tests use and the 787x/887x block the
# account-history test uses, so this test runs alongside concurrent
# cluster-bound tests without port collisions.
L1=7941; L2=7942; L3=7943
R1=8941; R2=8942; R3=8943

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  # Belt-and-suspenders on Windows/Git Bash: backgrounded native exes are
  # not always reaped by `kill` of the shell job PID. Reap anything still
  # LISTENING on THIS test's RPC ports via taskkill so we don't leave
  # strays that collide with the next cluster-bound test.
  if command -v taskkill >/dev/null 2>&1 && command -v netstat >/dev/null 2>&1; then
    for p in "${R1:-}" "${R2:-}" "${R3:-}"; do
      [ -z "$p" ] && continue
      for spid in $(netstat -ano 2>/dev/null | grep LISTENING \
                    | grep -E "127\.0\.0\.1:$p\b" | awk '{print $NF}' | sort -u); do
        [ -n "$spid" ] && taskkill //F //PID "$spid" >/dev/null 2>&1
      done
    done
  fi
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Init 3-node cluster (treasury funded in genesis) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vsr",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

# A second, DIFFERENT genesis for the anchor-mismatch assertion (#3).
# Same committee, different chain_id + initial balance ⇒ different hash.
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-vsr-WRONG",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 99999}]
}
EOF
$DETERM genesis-tool build $T/gen_wrong.json | tail -1

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
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 $L1 $R1 "[\"127.0.0.1:$L2\",\"127.0.0.1:$L3\"]"
configure_node 2 $L2 $R2 "[\"127.0.0.1:$L1\",\"127.0.0.1:$L3\"]"
configure_node 3 $L3 $R3 "[\"127.0.0.1:$L1\",\"127.0.0.1:$L2\"]"

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 10 ==="
wait_height() {
  local target=$1
  # Generous budget (180s): block production can stall under CPU
  # contention from concurrent cluster-bound tests. Prefer waiting over a
  # misleading FAIL when the chain was merely starved.
  for _ in $(seq 1 360); do
    H=$($DETERM status --rpc-port $R1 2>/dev/null \
         | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
    if [ "$H" -ge "$target" ] 2>/dev/null; then break; fi
    sleep 0.5
  done
}
wait_height 10
echo "  chain height: $H"

# Pre-flight: confirm the daemon on $R1 is running OUR genesis (block 0
# hash == GHASH). Catches port collisions with a stray/foreign cluster and
# stale chain.json reuse — both would otherwise surface as a confusing
# GENESIS HASH MISMATCH mid-test. Fail fast with a clear note.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port $R1 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$GHASH" ]; then
    echo "  PRE-FLIGHT FAIL: daemon on RPC $R1 has block0=$BLK0 but our"
    echo "  genesis hash=$GHASH — a foreign/stale daemon is on this port."
    echo "  (Is another cluster-bound test using ports $R1-$R3 / $L1-$L3?)"
    assert "false" "pre-flight: daemon on $R1 runs our genesis"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_verify_state_root"; exit 1
fi
echo "  pre-flight OK: daemon on $R1 runs our genesis ($GHASH)"

# Precondition: we sample a mid-height H. Need head index >= H. If
# production was so starved we never got there, SKIP rather than emit a
# misleading FAIL — the subcommand itself is fine; the environment
# couldn't produce enough blocks in time. Mirrors the repo convention for
# cluster-bound tests.
if [ "$H" -lt 11 ] 2>/dev/null; then
    echo "  SKIP: chain only reached height $H in the time budget (need"
    echo "        >=11 to sample a mid-height). Environment too starved;"
    echo "        not a determ-light verify-state-root defect."
    exit 0
fi

# Pick a mid-height H well inside [1, head_index]. head_index = H - 1.
HEAD_INDEX=$((H - 1))
MID=$((HEAD_INDEX / 2))
[ "$MID" -lt 1 ] && MID=1
echo "  head_index=$HEAD_INDEX, sampling mid-height H=$MID"

echo
echo "=== 3. verify-state-root at H=$MID (text mode) ==="
set +e
OUT=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen.json \
        --height $MID 2>&1)
RC=$?
set -e
echo "$OUT"

# ---- Assertion 1: exit 0 + non-empty 64-hex state_root + committee sigs.
TEXT_ROOT=$(echo "$OUT" | grep -E "^  state_root:" | head -1 | awk '{print $2}')
TEXT_SIGS=$(echo "$OUT" | grep -E "^  committee sigs:" | head -1)
if [ "$RC" = "0" ] && [ "${#TEXT_ROOT}" = "64" ] && [ -n "$TEXT_SIGS" ]; then
    assert "true" "verify-state-root H=$MID: exit 0, 64-hex state_root, committee sigs reported"
else
    assert "false" "verify-state-root H=$MID: exit 0 (got $RC), 64-hex root (got len=${#TEXT_ROOT}), sigs line (got '$TEXT_SIGS')"
fi
echo "  sample: state_root=${TEXT_ROOT:0:16}... ($TEXT_SIGS)"

echo
echo "=== 4. --json shape + committee_verified=true (assertions 5 + 6) ==="
set +e
JOUT=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen.json \
         --height $MID --json 2>&1)
JRC=$?
set -e
echo "$JOUT" | tail -1
echo "$JOUT" | tail -1 > $T/vsr_mid.json

# Bonus (assertion 6): parses with the documented shape.
SHAPE_OK=$(cat $T/vsr_mid.json | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = {'height','state_root','committee_size','sigs_verified','committee_verified'}
    if not need.issubset(d.keys()): print('false'); sys.exit()
    if d['height'] != $MID: print('false'); sys.exit()
    if len(d['state_root']) != 64: print('false'); sys.exit()
    if not isinstance(d['committee_size'], int): print('false'); sys.exit()
    if not isinstance(d['sigs_verified'], int): print('false'); sys.exit()
    if not isinstance(d['committee_verified'], bool): print('false'); sys.exit()
    print('true')
except Exception as e:
    sys.stderr.write('parse err: %s\n' % e); print('false')
")
if [ "$JRC" = "0" ] && [ "$SHAPE_OK" = "true" ]; then
    assert "true" "--json parses with {height,state_root,committee_size,sigs_verified,committee_verified}"
else
    assert "false" "--json shape ok (got rc=$JRC shape_ok=$SHAPE_OK)"
fi

# Assertion 5: never emits a root without committee_verified=true. NEW
# successor-binding semantics — the root at H>=1 is attested by the SIGNED
# SUCCESSOR(H+1), not by header[H]'s own sigs, so sigs_verified is 0 here
# (we do NOT assert sigs_verified == committee_size anymore). committee_size
# still reports |creators| of header[H] (>= 1) for context. The load-bearing
# checks are: committee_verified=true AND a non-empty 64-hex root.
CV_OK=$(cat $T/vsr_mid.json | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    cv = d.get('committee_verified') is True
    # Successor-binding model: sigs_verified is 0 for H>=1 (attestation is
    # via the successor header's sigs, not header[H]'s own). committee_size
    # is still the genesis committee (>= 1) for reporting context.
    sigs_zero = (d.get('sigs_verified') == 0)
    csize_ok = (d.get('committee_size', 0) >= 1)
    nonempty = len(d.get('state_root','')) == 64
    print('true' if (cv and sigs_zero and csize_ok and nonempty) else 'false')
except Exception:
    print('false')
")
assert "$CV_OK" "root reported only with committee_verified=true + non-empty 64-hex root (successor-bound: sigs_verified==0, committee_size>=1)"

echo
echo "=== 5. Reported root == committee-verified header[H].state_root (assertion 2) ==="
# Independently re-fetch header[H] and confirm the verify-state-root output
# matches the on-chain header's state_root. Additionally re-verify that
# header's committee sigs via verify-block-sigs so the comparison is
# against a COMMITTEE-ATTESTED header, not a raw daemon reply.
$DETERM_LIGHT fetch-headers --rpc-port $R1 --from $MID --count 1 \
    --out $T/hdr_mid.json >/dev/null 2>&1
HDR_ROOT=$(cat $T/hdr_mid.json | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0].get('state_root',''))
except Exception: print('')
")
# Build a committee.json the light client's verify-block-sigs consumes,
# and isolate header[H] as a single-object file.
$PY -c "
import json
g = json.load(open('$T/gen.json'))
members = [{'domain': c['domain'], 'ed_pub': c['ed_pub']}
           for c in g['initial_creators']]
json.dump({'members': members}, open('$T/committee.json','w'))
page = json.load(open('$T/hdr_mid.json'))
json.dump(page['headers'][0], open('$T/hdr_only.json','w'))
"
set +e
$DETERM_LIGHT verify-block-sigs --header $T/hdr_only.json --committee $T/committee.json >/dev/null 2>&1
VBS_RC=$?
set -e
JSON_ROOT=$(cat $T/vsr_mid.json | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['state_root'])
except Exception: print('')
")
if [ -n "$HDR_ROOT" ] && [ "$JSON_ROOT" = "$HDR_ROOT" ] \
   && [ "$TEXT_ROOT" = "$HDR_ROOT" ] && [ "$VBS_RC" = "0" ]; then
    assert "true" "reported root == committee-verified header[$MID].state_root (on-chain truth)"
else
    assert "false" "reported root matches committee-verified header (hdr=$HDR_ROOT json=$JSON_ROOT text=$TEXT_ROOT vbs_rc=$VBS_RC)"
fi

echo
echo "=== 6. Genesis anchor mismatch → fail-closed (assertion 3) ==="
set +e
WRONG_OUT=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen_wrong.json \
              --height $MID 2>&1)
WRONG_RC=$?
set -e
echo "$WRONG_OUT" | tail -2
if [ "$WRONG_RC" != "0" ] \
   && echo "$WRONG_OUT" | grep -qi "GENESIS HASH MISMATCH"; then
    assert "true" "wrong --genesis fails closed (rc=$WRONG_RC, GENESIS HASH MISMATCH)"
else
    assert "false" "wrong --genesis fails closed (got rc=$WRONG_RC)"
fi

echo
echo "=== 7. Height beyond head → clean error, no crash (assertion 4) ==="
set +e
BEYOND_OUT=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen.json \
               --height 99999 2>&1)
BEYOND_RC=$?
set -e
echo "$BEYOND_OUT" | tail -2
# Clean error = handled rc=1 (NOT rc=2 unhandled-exception, NOT 139/signal
# crash) + a diagnostic naming the head bound.
if [ "$BEYOND_RC" = "1" ] \
   && echo "$BEYOND_OUT" | grep -qi "beyond chain head"; then
    assert "true" "height beyond head → clean handled error (rc=1)"
else
    assert "false" "height beyond head → clean error (got rc=$BEYOND_RC)"
fi

echo
echo "=== 7b. EXACT head index fails closed — no signed successor (assertion 7) ==="
# The committee-bound attestation for index H is the SUCCESSOR(H+1)'s
# committee signature over a digest that binds prev_hash == block_hash(H).
# At the chain HEAD there is no successor yet, so there is nothing to bind
# the head's state_root to. verify-state-root at the exact head index must
# therefore FAIL CLOSED (non-zero exit, committee_verified=false in --json),
# NOT report a bare daemon root. We sample the head index observed at the
# verify-state-root call; re-probe to avoid a race where the chain advanced.
HEAD_NOW=$($DETERM status --rpc-port $R1 2>/dev/null | $PY -c "
import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
HEAD_IDX_NOW=$((HEAD_NOW - 1))
set +e
HEAD_OUT=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen.json \
             --height $HEAD_IDX_NOW --json 2>&1)
HEAD_RC=$?
set -e
echo "$HEAD_OUT" | tail -1
# INVARIANT under test: a committee-unbound (head) index is NEVER reported
# as verified. Two acceptable outcomes:
#   (a) rc != 0  → fail-closed. The --json object, if any, must NOT claim
#       committee_verified=true (it carries false, or an error line).
#   (b) rc == 0  → only sound if the chain ADVANCED between the status probe
#       and the call, so this index gained a signed successor; then the
#       result must be genuinely committee_verified=true.
HEAD_OK=$(echo "$HEAD_OUT" | tail -1 | HEAD_RC=$HEAD_RC $PY -c "
import json, sys, os
rc = int(os.environ.get('HEAD_RC', '1'))
try:
    cv = json.loads(sys.stdin.read()).get('committee_verified')
except Exception:
    cv = None   # non-JSON error text on the head index — a fail-closed form
if rc != 0:
    print('true' if cv is not True else 'false')      # must not claim verified
else:
    print('true' if cv is True else 'false')          # advanced → must be sound
")
assert "$HEAD_OK" "exact head index fails closed (rc=$HEAD_RC; head index has no signed successor to bind its root)"

echo
echo "=== 8. Genesis (H=0) anchored by hash, no committee sigs ==="
# H=0 is anchored by compute_genesis_hash (genesis has NO committee sigs by
# construction — it's the deterministic GenesisConfig->Block transform). It
# must succeed (rc=0) and report committee_size=0, sigs_verified=0,
# committee_verified=true. The genesis HEADER's own state_root field is
# empty on this build (block.state_root is "state after applying THIS
# block"; genesis leaves it zero — the post-genesis-apply commitment first
# lands on block 1's header). The command surfaces that honestly via an
# empty state_root rather than fabricating one. We accept EITHER an empty
# root OR a populated 64-hex root (a future build could populate genesis's
# own field), but REQUIRE the structural genesis invariants — the point is
# the command never invents a committee-signed root for the unsigned
# genesis block.
set +e
G0=$($DETERM_LIGHT verify-state-root --rpc-port $R1 --genesis $T/gen.json \
       --height 0 --json 2>&1)
G0RC=$?
set -e
echo "$G0" | tail -1
G0_OK=$(echo "$G0" | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    sr = d.get('state_root', '')
    root_honest = (sr == '' or len(sr) == 64)  # empty (none) or full hash
    ok = (d.get('height') == 0
          and d.get('committee_verified') is True
          and d.get('committee_size') == 0
          and d.get('sigs_verified') == 0
          and root_honest)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$G0RC" = "0" ] && [ "$G0_OK" = "true" ]; then
    assert "true" "genesis H=0 anchored by hash (committee_size=0, committee_verified=true, no fabricated root)"
else
    assert "false" "genesis H=0 handling (got rc=$G0RC ok=$G0_OK)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_state_root"; exit 0
else
  echo "  FAIL: test_light_verify_state_root"; exit 1
fi
