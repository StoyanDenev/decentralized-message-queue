#!/usr/bin/env bash
# determ-wallet state-proof-verify — verified against a REAL daemon's state_proof.
#
# Regression guard for the S-040 wallet merkle-wrap bug (fixed in commit
# 8c34f38). The other wallet-verifier tests (test_wallet_state_proof_verify.sh
# etc.) use self-generated Python fixtures, so they cannot catch drift between
# the wallet's hand-rolled Merkle walk and the daemon's real state_root
# convention. That is exactly how the S-040 bug shipped silently: when S-040
# changed the committed state_root from the bare inner Merkle root to
# merkle_root_wrap(inner_root, leaf_count), the daemon + determ-light were
# updated (they share src/crypto/merkle.cpp) but the wallet's inline copy was
# not — so the wallet rejected genuinely-valid proofs from a real daemon while
# its self-fixtured tests (which reproduced the same bare root) kept passing.
#
# This test closes that gap end-to-end:
#   1. boots a single determ node (M=K=1, solo producer) with a genesis-funded
#      account "alice" (a: namespace leaf);
#   2. fetches a REAL state_proof for a:alice via determ-light fetch-state-proof
#      (the daemon's state_proof RPC — returns the S-040-WRAPPED state_root);
#   3. runs `determ-wallet state-proof-verify --in <real> --root <real root>`
#      and asserts VALID (exit 0) — THIS assertion fails pre-8c34f38 because the
#      wallet compared the bare inner root to the daemon's wrapped root;
#   4. tampers --root by one hex nibble and asserts INVALID (exit 2);
#   5. cross-binary: determ-light verify-state-proof on the SAME proof agrees
#      (VALID for the real root, rejected for the tampered root).
#
# Cluster/integration test — runs via the tools/test_*.sh full-suite glob only,
# NOT the FAST=1 in-process subset. SKIP-clean if any binary is unbuilt.
#
# Run from repo root: bash tools/test_wallet_state_proof_vs_daemon.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ] \
   || [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ] \
   || [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ / determ-wallet / determ-light binary not found; build with"
    echo "        cmake --build build --target determ determ-wallet determ-light"
    exit 0
fi

# Python (3 or 2) is used only for JSON field extraction in this test harness.
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "  SKIP: no python3/python on PATH (needed for JSON extraction)"
    exit 0
fi

T=test_wallet_state_proof_vs_daemon
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS
cleanup() {
  rc=$?
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
  return $rc
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init single solo-producer node + genesis-funded alice ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

cat > $T/gen.json <<EOF
{
  "chain_id": "test-wallet-sp-vs-daemon",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "alice", "balance": 500}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

"$PY" -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7891
c['rpc_port'] = 8891
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

NODE_PIDS=("")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 3 ==="
H=0
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8891 2>/dev/null \
       | "$PY" -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"
if [ "$H" -ge 3 ] 2>/dev/null; then
  assert "true" "node produced blocks (height=$H >= 3)"
else
  assert "false" "node produced blocks (height=$H)"
  echo "  (cannot proceed without a live chain)"; echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: $T"; exit 1
fi

echo
echo "=== 3. Fetch REAL state_proof for a:alice (daemon's wrapped state_root) ==="
set +e
$DETERM_LIGHT fetch-state-proof --rpc-port 8891 --ns a --key alice --out $T/proof.json 2>&1 | tail -1
FRC=$?
set -e
if [ "$FRC" = "0" ] && [ -s $T/proof.json ]; then
  assert "true" "fetch-state-proof wrote a:alice proof"
else
  assert "false" "fetch-state-proof wrote a:alice proof (rc=$FRC)"
  echo "  $pass_count pass / $fail_count fail"; echo "  FAIL: $T"; exit 1
fi

ROOT=$("$PY" -c "
import json
with open('$T/proof.json') as f: p = json.load(f)
print(p.get('state_root',''))
")
echo "  daemon state_root: $ROOT"
if [ "${#ROOT}" = "64" ]; then
  assert "true" "proof carries a 64-hex state_root"
else
  assert "false" "proof carries a 64-hex state_root (len=${#ROOT})"
fi
# NOTE: this state_root is the daemon's compute_state_root() at head — the same
# value populated into block.state_root and committee-signed (S-038). The
# merkle-wrap regression is independent of trust-anchoring (the light client's
# job); here we prove the wallet's Merkle walk matches the daemon's wrapped root.

echo
echo "=== 4. determ-wallet state-proof-verify --in <real> --root <real> => VALID ==="
echo "       (this is the assertion that FAILS pre-8c34f38: the wallet compared"
echo "        the bare inner root to the daemon's S-040-wrapped root)"
set +e
WOUT=$($DETERM_WALLET state-proof-verify --in $T/proof.json --root $ROOT 2>&1)
WRC=$?
set -e
echo "$WOUT" | tail -2
if [ "$WRC" = "0" ]; then
  assert "true" "wallet accepts real daemon proof (VALID, exit 0)"
else
  assert "false" "wallet accepts real daemon proof (got exit $WRC) [S-040 regression!]"
fi

echo
echo "=== 5. Tamper --root by one nibble => INVALID (exit 2) ==="
# Flip the first hex nibble deterministically (0<->1, else ->0).
BAD=$("$PY" -c "
r='$ROOT'
c=r[0]
nc='1' if c=='0' else '0'
print(nc + r[1:])
")
set +e
$DETERM_WALLET state-proof-verify --in $T/proof.json --root $BAD > $T/bad.out 2>&1
BRC=$?
set -e
tail -1 $T/bad.out
if [ "$BRC" = "2" ]; then
  assert "true" "wallet rejects tampered root (INVALID, exit 2)"
elif [ "$BRC" != "0" ]; then
  assert "true" "wallet rejects tampered root (non-zero exit $BRC)"
else
  assert "false" "wallet rejects tampered root (got exit 0 — accepted a bad root!)"
fi

echo
echo "=== 6. Cross-binary: determ-light verify-state-proof agrees ==="
set +e
$DETERM_LIGHT verify-state-proof --in $T/proof.json --state-root $ROOT > $T/light_ok.out 2>&1
LRC=$?
$DETERM_LIGHT verify-state-proof --in $T/proof.json --state-root $BAD > $T/light_bad.out 2>&1
LBRC=$?
set -e
if [ "$LRC" = "0" ]; then
  assert "true" "light verify-state-proof VALID on real root (exit 0)"
else
  assert "false" "light verify-state-proof VALID on real root (got $LRC)"
fi
if [ "$LBRC" != "0" ]; then
  assert "true" "light verify-state-proof rejects tampered root (exit $LBRC)"
else
  assert "false" "light verify-state-proof rejects tampered root (got exit 0)"
fi
# Agreement: both binaries accept the real root AND both reject the tampered one.
if [ "$WRC" = "0" ] && [ "$LRC" = "0" ] && [ "$WRC" = "$LRC" ]; then
  assert "true" "wallet + light agree: both VALID on the real daemon proof"
else
  assert "false" "wallet + light agree on the real daemon proof (wallet=$WRC light=$LRC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: $T"; exit 0
else
  echo "  FAIL: $T"; exit 1
fi
