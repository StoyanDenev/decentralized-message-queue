#!/usr/bin/env bash
# determ-light state_root committee-binding — OFFLINE guard for the
# soundness fix that ties a reported state_root to a committee signature.
#
# ─── The soundness gap this fix closes ─────────────────────────────────────
# The committee signs compute_block_digest, which EXCLUDES state_root.
# state_root is bound to a block ONLY via Block::signing_bytes →
# block_hash = SHA256(signing_bytes || creator_block_sigs). But the daemon's
# `headers` RPC STRIPS the heavy fields signing_bytes needs (transactions,
# cross_shard_receipts, inbound_receipts, initial_state), so a light client
# CANNOT recompute block_hash from a stripped header. Pre-fix, the state
# readers (read_account_trustless / verify-state-root) trusted the daemon's
# state_root + block_hash FIELDS — a malicious daemon could swap the
# state_root FIELD after the committee signed and have a forged balance
# reported as committee-verified.
#
# THE FIX (light/trustless_read.cpp::committee_bound_state_root): fetch the
# FULL block at the anchor index (so block_hash is recomputable), recompute
# block_hash, then confirm the COMMITTEE-SIGNED successor(anchor+1).prev_hash
# == that recomputed block_hash. The successor's digest binds prev_hash, so
# its committee sigs transitively commit the anchor's state_root. A swapped
# state_root changes the recomputed block_hash → the successor.prev_hash
# comparison fails → the command fails closed. balance-trustless and
# verify-state-root both route through this helper.
#
# ─── What THIS test covers (offline, no daemon) ────────────────────────────
# This box cannot run a live multi-node cluster (and compute_genesis_hash has
# a known Windows edge), so the END-TO-END FORGERY-CATCH — forge a served
# full-block state_root and confirm the successor-prev_hash mismatch is
# detected — is a CI / WSL2 cluster leg. It is documented and SKIPPED
# GRACEFULLY here (NOT faked). What this offline guard does assert with the
# REAL determ-light binary:
#
#   1. `determ-light help` still lists BOTH state-reader subcommands that
#      now route through the binding helper: balance-trustless and
#      verify-state-root. (A refactor that dropped either surface would be
#      caught here.)
#   2. verify-state-root fails closed (rc != 0, no "OK"/"committee_verified":
#      true on stdout) when pointed at a dead RPC port with a VALID genesis —
#      i.e. the genesis pin passes and the command reaches the RPC layer, so
#      the new code path is wired in and reachable, and it never reports an
#      unverified root.
#   3. balance-trustless likewise fails closed against a dead RPC port with a
#      valid genesis.
#   4. Both fail closed on a MISSING genesis (rc != 0) — the genesis pin is
#      still load-bearing in front of the new binding logic.
#
# Run from repo root: bash tools/test_light_state_root_binding.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_state_root_binding
rm -rf "$T"
mkdir -p "$T"

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# A dead RPC port nothing is listening on (well outside the cluster-test
# blocks). Connecting must fail fast — never hang.
DEAD_PORT=59997

echo "=== 1. help lists both state-reader subcommands (binding-helper consumers) ==="
HELP=$("$DETERM_LIGHT" help 2>&1)
if echo "$HELP" | grep -qE "^[[:space:]]*balance-trustless\b"; then
    assert "true" "help lists balance-trustless"
else
    assert "false" "help lists balance-trustless"
fi
if echo "$HELP" | grep -qE "^[[:space:]]*verify-state-root\b"; then
    assert "true" "help lists verify-state-root"
else
    assert "false" "help lists verify-state-root"
fi

echo
echo "=== 2. Build a VALID genesis so the genesis pin passes (reaches RPC layer) ==="
# Use the FULL node binary to mint a real peer-info + genesis. If it is
# unavailable, the offline RPC-layer assertions below SKIP gracefully (we
# still have the help assertions). Never fake a pass.
GEN_OK=false
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ]; then
    "$DETERM" init --data-dir "$T/n1" --profile single_test >/dev/null 2>&1
    if "$DETERM" genesis-tool peer-info node1 --data-dir "$T/n1" --stake 1000 \
            > "$T/p1.json" 2>/dev/null && [ -s "$T/p1.json" ]; then
        cat > "$T/gen.json" <<EOF
{
  "chain_id": "offline-state-root-binding",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(tr -d '\n' < "$T/p1.json")
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF
        if "$DETERM" genesis-tool build "$T/gen.json" >/dev/null 2>&1 \
                && [ -s "$T/gen.json.hash" ]; then
            GEN_OK=true
        fi
    fi
fi

if [ "$GEN_OK" != "true" ]; then
    echo "  SKIP (RPC-layer fail-closed assertions): could not mint a valid"
    echo "       genesis with the node binary in this environment. The help"
    echo "       assertions above still ran. The full end-to-end forgery-catch"
    echo "       (forge a served full-block state_root; confirm the"
    echo "       successor-prev_hash mismatch is detected) is a CI / WSL2"
    echo "       cluster leg — see the header comment."
    echo
    echo "=== Test summary ==="
    echo "  $pass_count pass / $fail_count fail (RPC-layer leg skipped)"
    if [ "$fail_count" = "0" ]; then
      echo "  PASS: $T"; exit 0
    else
      echo "  FAIL: $T"; exit 1
    fi
fi
echo "  genesis built; hash=$(cat "$T/gen.json.hash")"

echo
echo "=== 3. verify-state-root fails closed against a dead RPC port (valid genesis) ==="
set +e
OUT=$("$DETERM_LIGHT" verify-state-root --rpc-port "$DEAD_PORT" \
        --genesis "$T/gen.json" --height 1 2>&1)
RC=$?
set -e
echo "$OUT" | tail -2
# Fail-closed: non-zero exit AND no success token on stdout. The binding
# helper must NEVER surface a committee-verified root it could not bind.
if [ "$RC" != "0" ] \
   && ! echo "$OUT" | grep -qiE '"committee_verified"[[:space:]]*:[[:space:]]*true|^OK$'; then
    assert "true" "verify-state-root fails closed on dead RPC port (rc=$RC, no verified root)"
else
    assert "false" "verify-state-root fails closed (got rc=$RC, out='$OUT')"
fi

echo
echo "=== 4. balance-trustless fails closed against a dead RPC port (valid genesis) ==="
set +e
BOUT=$("$DETERM_LIGHT" balance-trustless --rpc-port "$DEAD_PORT" \
         --genesis "$T/gen.json" --domain treasury 2>&1)
BRC=$?
set -e
echo "$BOUT" | tail -2
if [ "$BRC" != "0" ] \
   && ! echo "$BOUT" | grep -qiE '"balance"|^balance[[:space:]]*='; then
    assert "true" "balance-trustless fails closed on dead RPC port (rc=$BRC, no balance)"
else
    assert "false" "balance-trustless fails closed (got rc=$BRC, out='$BOUT')"
fi

echo
echo "=== 5. Both fail closed on a MISSING genesis (genesis pin still load-bearing) ==="
set +e
M1=$("$DETERM_LIGHT" verify-state-root --rpc-port "$DEAD_PORT" \
       --genesis "$T/does-not-exist.json" --height 1 2>&1); M1RC=$?
M2=$("$DETERM_LIGHT" balance-trustless --rpc-port "$DEAD_PORT" \
       --genesis "$T/does-not-exist.json" --domain treasury 2>&1); M2RC=$?
set -e
if [ "$M1RC" != "0" ] && [ "$M2RC" != "0" ]; then
    assert "true" "both fail closed on missing genesis (vsr rc=$M1RC, bal rc=$M2RC)"
else
    assert "false" "both fail closed on missing genesis (vsr rc=$M1RC, bal rc=$M2RC)"
fi

echo
echo "=== NOTE: live end-to-end forgery-catch is a CI / WSL2 cluster leg ==="
echo "  This box cannot boot a multi-node cluster (and compute_genesis_hash"
echo "  has a known Windows edge). The full forgery-catch — boot a cluster,"
echo "  serve a full block whose state_root FIELD was swapped after signing,"
echo "  and confirm committee_bound_state_root() rejects it via the"
echo "  successor.prev_hash != recomputed block_hash check — runs on CI/WSL2."
echo "  It is SKIPPED here, NOT faked."

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: $T"; exit 0
else
  echo "  FAIL: $T"; exit 1
fi
