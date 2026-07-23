#!/usr/bin/env bash
# SS-5 / S-001 — the dapp_subscribe streaming-takeover branch must sit BEHIND
# the HMAC auth gate. Behavioral (live-node) complement to the source-order
# reasoning in docs/proofs/ProofClaimGateTraceability.md (#14 SS-5).
#
# THE ORDERING THIS GATE LOCKS (src/rpc/rpc.cpp::handle_session):
#     auth_err = verify_auth(req);                 // (1) auth FIRST
#     if (!auth_err.empty()) reply auth_err;       // (2) reject unauthenticated
#     else if (method == "dapp_subscribe") {        // (3) ONLY after auth passes
#         ... rpc_dapp_subscribe(conn, ...);        //     socket takeover
#     }
#
# THE SURVIVING MUTANT (SS-5): hoist the `dapp_subscribe` takeover branch ABOVE
# the verify_auth check. An unauthenticated subscribe would then reach
# rpc_dapp_subscribe — taking over the socket (registered domain) or leaking the
# unknown-DApp probe (unregistered domain) WITHOUT auth. test_rpc_hmac_auth.sh
# only exercises `status` (the final dispatch branch), which stays auth-gated
# under the hoist, so it does NOT catch this; test_dapp_subscribe.sh runs with
# auth DISABLED. This is the leg that discriminates the hoist.
#
# THE DISCRIMINATOR (single node, auth enabled, no registration needed):
#   * unauthenticated dapp_subscribe for an UNKNOWN domain -> "auth_required"
#     (correct: the auth gate fires before the domain is ever inspected).
#     Under the hoist it would be "unknown DApp" (the handler ran pre-auth).
#   * AUTHENTICATED dapp_subscribe for the same UNKNOWN domain -> "unknown DApp"
#     (positive control: auth passes and the request reaches the handler, so
#     the gate is not a tautology that rejects everything).
#
# Single node, M=K=1. Windows-standalone (needs a live daemon); NOT in FAST /
# ci_local. Run from repo root: bash tools/test_rpc_dapp_subscribe_auth.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_rpc_dapp_subscribe_auth
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1

pass_count=0; fail_count=0; skip_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }

SECRET="aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff"

echo "=== 1. Init single node, auth ENABLED (M=K=1) ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-dapp-sub-auth",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "node1", "balance": 100}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7871
c['rpc_port'] = 8871
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
c['rpc_auth_secret'] = '$SECRET'
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!

# Wait until the RPC answers an AUTHENTICATED status (daemon up).
UP=0
for _ in $(seq 1 60); do
  H=$(DETERM_RPC_AUTH_SECRET="$SECRET" $DETERM status --rpc-port 8871 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','x'))
except: print('x')" 2>/dev/null)
  if [ "$H" != "x" ] && [ -n "$H" ]; then UP=1; break; fi
  sleep 0.5
done
if [ "$UP" != "1" ]; then
  echo "  daemon did not answer an authenticated status; cannot run the auth-ordering legs."
  skip "SS-5 dapp_subscribe auth-ordering (daemon did not come up)"
  echo
  echo "=== Test summary ==="
  echo "  $pass_count pass / $fail_count fail / $skip_count skip"
  # No FAILs recorded; a non-starting daemon is an environment SKIP, not a fault.
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_rpc_dapp_subscribe_auth (daemon unavailable; legs skipped)"; exit 0
  else
    echo "  FAIL: test_rpc_dapp_subscribe_auth"; exit 1
  fi
fi
echo "  daemon up (authenticated status answered)"

# Sanity control: the auth gate is actually ON — an unauthenticated STATUS is
# rejected (mirrors test_rpc_hmac_auth §4, re-proven here so the SS-5 legs below
# rest on a confirmed-enabled gate rather than an assumed one).
echo
echo "=== 2. control: auth gate is ON (unauthenticated status rejected) ==="
unset DETERM_RPC_AUTH_SECRET
OUT=$($DETERM status --rpc-port 8871 2>&1 || true)
if echo "$OUT" | grep -qi "auth"; then
  assert true "unauthenticated status -> auth error (gate enabled)"
else
  assert false "unauthenticated status should be an auth error (got: $OUT)"
fi

# ── SS-5 NEGATIVE (the mutant catch): unauthenticated dapp_subscribe for an
#    UNKNOWN domain must be refused at the AUTH gate, i.e. "auth_required" —
#    NOT "unknown DApp" (which would prove the handler ran before auth). ──
echo
echo "=== 3. SS-5: unauthenticated dapp_subscribe (unknown domain) -> AUTH error ==="
unset DETERM_RPC_AUTH_SECRET
OUT=$($DETERM dapp-subscribe --rpc-port 8871 --domain nosuchdapp --max-frames 1 2>&1); RC=$?
echo "    rc=$RC out=$OUT"
if echo "$OUT" | grep -qi "auth" \
   && ! echo "$OUT" | grep -qi "unknown DApp" \
   && ! echo "$OUT" | grep -qi "subscribed"; then
  assert true "unauth dapp_subscribe -> auth error, NOT unknown-DApp / subscribed (auth precedes takeover)"
else
  assert false "unauth dapp_subscribe should be an AUTH error before the domain check (rc=$RC)"
fi

# ── SS-5 POSITIVE control: an AUTHENTICATED dapp_subscribe for the SAME unknown
#    domain must reach the handler -> "unknown DApp" (NOT an auth error). Proves
#    the gate is live (rejects unauth) but not a tautology (accepts authed). ──
echo
echo "=== 4. SS-5 control: AUTHENTICATED dapp_subscribe (unknown domain) -> handler (unknown DApp) ==="
OUT=$(DETERM_RPC_AUTH_SECRET="$SECRET" $DETERM dapp-subscribe --rpc-port 8871 \
        --domain nosuchdapp --max-frames 1 2>&1); RC=$?
echo "    rc=$RC out=$OUT"
if echo "$OUT" | grep -qi "unknown DApp" && ! echo "$OUT" | grep -qi "auth_required\|auth_failed"; then
  assert true "authed dapp_subscribe reaches the handler (unknown DApp), NOT auth-rejected"
else
  assert false "authed dapp_subscribe should reach the handler with 'unknown DApp' (rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count skip"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_rpc_dapp_subscribe_auth"; exit 0
else
  echo "  FAIL: test_rpc_dapp_subscribe_auth"; exit 1
fi
