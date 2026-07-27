#!/usr/bin/env bash
# LightVerify LSB-COMMITTEE-SIZE — verify-state-bundle's OFFLINE committee-sig
# gate must forward the genesis k_block_sigs + bft_enabled so it enforces the
# node's committee-size mode-eligibility (LV-1/LV-2) on the bundle's SUCCESSOR
# header, exactly as the online committee_bound_state_root and this file's own
# export side already do.
#
# THE GAP (found by the wf_e73b18ec adversarial audit, HIGH, CLIENT-fixable):
# verify_state_bundle.cpp called verify_block_sigs(successor, committee, /*bft=*/
# false) in the 3-arg form, so expected_k defaulted to 0. With expected_k==0 the
# committee-size mode-eligibility gate (verify.cpp: "refusing a quorum downgrade")
# is SKIPPED and the accepted quorum floor becomes creators.size() instead of the
# genesis k_block_sigs. Under K-of-K mutual distrust ONE colluding genesis
# committee member M suffices: M serves a bundle whose successor is a 1-of-K
# MUTUAL_DISTRUST block (creators=[M], one real M-signature). Every other bundle
# leg is a structural self-consistency check M satisfies by construction, so the
# offline verifier would emit VERIFIED for arbitrary (namespace,key,balance)/
# state_root the full committee never attested. The node's check_creator_selection
# rejects the same successor (m=1 != k_full=K). This is the SAME class as the
# shipped LV-1/LV-2 chain-walk fix, on a 4th consumer that had been missed.
#
# THE FIX (client-side only; no node/consensus change): forward
# genesis.k_block_sigs + genesis.bft_enabled to the two verify_block_sigs calls,
# so the mode-eligibility gate is enforced on the successor.
#
# FAST + OFFLINE. Builds a real genesis with `determ genesis-tool build` (no
# cluster) so the chain-identity pin passes, then hand-builds the bundle. The
# mode-eligibility gate is a STRUCTURAL creators.size() check reached BEFORE any
# signature verification, so no real committee signatures are needed to trip it.
#   NEG   1-of-3 MUTUAL_DISTRUST successor (creators.size 1 != k_block_sigs 3)
#         -> UNVERIFIABLE exit 3 with the "quorum downgrade" diagnostic.
#   CTRL  3-of-3 MUTUAL_DISTRUST successor (creators.size 3 == 3) -> PASSES the
#         mode-eligibility gate and falls through to the LATER signature gate
#         (sentinel-zero sig), proving the gate is live, not a tautology.
# Falsify-on-mutant (revert the fix -> 3-arg calls, expected_k=0): the NEG is no
# longer rejected at the mode-eligibility gate; it falls through to the same
# sentinel-zero signature gate as the CTRL, so its diagnostic no longer says
# "quorum downgrade" -> the NEG assert flips.
#
# The chain-identity pin uses compute_genesis_hash (a known Windows edge); if it
# does not match on this box the whole verify SKIPs before reaching the gate, so
# a GENESIS-HASH-MISMATCH result SKIPs this test rather than faking a pass.
#
# Run from repo root: bash tools/test_light_verify_state_bundle_committee_size.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ] \
   || [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
  echo "  SKIP: determ + determ-light binaries required; build with"
  echo "        cmake --build build --config Release --target determ determ-light"
  exit 0
fi

T=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/determ-lsb-cksz.$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass=0; fail=0; skipc=0
assert() { if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1));
           else echo "  FAIL: $2"; fail=$((fail+1)); fi; }
skip()   { echo "  SKIP: $1"; skipc=$((skipc+1)); }

summary_exit() {
  echo
  echo "=== Test summary ==="
  echo "  $pass pass / $fail fail / $skipc skip"
  if [ "$fail" = "0" ]; then echo "  PASS: test_light_verify_state_bundle_committee_size"; exit 0
  else echo "  FAIL: test_light_verify_state_bundle_committee_size"; exit 1; fi
}

# ── Build a REAL genesis (k_block_sigs=3) offline so the chain-identity pin
#    passes and verify reaches the committee-sig gate. No cluster is started. ──
for n in 1 2 3; do
  "$DETERM" init --data-dir "$T/n$n" --profile single_test >/dev/null 2>&1
  "$DETERM" genesis-tool peer-info node$n --data-dir "$T/n$n" --stake 1000 > "$T/p$n.json" 2>/dev/null
done
cat > "$T/gen.json" <<EOF
{"chain_id":"lsb-committee-size","m_creators":3,"k_block_sigs":3,"block_subsidy":1,
 "initial_creators":[$(cat "$T/p1.json"|tr -d '\n'),$(cat "$T/p2.json"|tr -d '\n'),$(cat "$T/p3.json"|tr -d '\n')],
 "initial_balances":[{"domain":"alice","balance":500}]}
EOF
"$DETERM" genesis-tool build "$T/gen.json" >/dev/null 2>&1
GH=$(cat "$T/gen.json.hash" 2>/dev/null || echo "")
if [ -z "$GH" ]; then
  skip "genesis-tool build produced no hash on this box (cannot reach the committee-sig gate)"
  summary_exit
fi

Z64=$(printf '0%.0s' $(seq 1 64)); A64=$(printf 'a%.0s' $(seq 1 64)); S128=$(printf '0%.0s' $(seq 1 128))
ANCHOR="{\"index\":1,\"prev_hash\":\"$Z64\",\"timestamp\":1,\"block_hash\":\"$A64\",\"transactions\":[],\"creators\":[],\"creator_block_sigs\":[],\"cumulative_rand\":\"$Z64\",\"abort_events\":[],\"state_root\":\"$A64\"}"
# consensus_mode 0 = MUTUAL_DISTRUST; the mode-eligibility gate rejects an MD
# block whose creators.size() != genesis k_block_sigs BEFORE any sig check.
mk_succ() { echo "{\"index\":2,\"prev_hash\":\"$A64\",\"timestamp\":1,\"block_hash\":\"$A64\",\"transactions\":[],\"consensus_mode\":0,\"creators\":[$1],\"creator_block_sigs\":[$2],\"cumulative_rand\":\"$Z64\",\"abort_events\":[]}"; }
mk_bundle() { cat > "$2" <<JSON
{"schema":"determ-light-state-bundle/1","genesis_hash":"$GH","namespace":"a","key":"alice",
 "anchor_index":1,"anchor_block":$ANCHOR,"successor_header":$1,
 "state_proof":{"key_bytes":"613a616c696365","state_root":"ab","value_hash":"cd","proof":[],"target_index":0,"leaf_count":1}}
JSON
}
mk_bundle "$(mk_succ "\"node1\"" "\"$S128\"")" "$T/neg.json"
mk_bundle "$(mk_succ "\"node1\",\"node2\",\"node3\"" "\"$S128\",\"$S128\",\"$S128\"")" "$T/ctrl.json"

# ── NEG: 1-of-3 MD downgrade -> rejected at the mode-eligibility gate. ────────
set +e
NEG_OUT=$("$DETERM_LIGHT" verify-state-bundle --in "$T/neg.json" --genesis "$T/gen.json" 2>&1)
NEG_RC=$?
set -e
echo "$NEG_OUT" | sed 's/^/    neg| /'
if echo "$NEG_OUT" | grep -qi "GENESIS HASH MISMATCH"; then
  skip "compute_genesis_hash edge on this box (chain-identity pin did not match) — cannot reach the committee-sig gate"
  summary_exit
fi
if [ "$NEG_RC" = "3" ] && echo "$NEG_OUT" | grep -qiE "quorum downgrade|k_block_sigs"; then
  assert "true" "1-of-3 MUTUAL_DISTRUST successor -> UNVERIFIABLE exit 3 (committee-size mode-eligibility enforced; LV-1/LV-2 forward)"
else
  assert "false" "1-of-3 MD downgrade should be UNVERIFIABLE exit 3 with the quorum-downgrade diagnostic (got rc=$NEG_RC)"
fi

# ── CTRL: 3-of-3 MD passes the mode-eligibility gate (not a tautology) and
#    falls through to the LATER signature gate (sentinel-zero sigs). ──────────
set +e
CTRL_OUT=$("$DETERM_LIGHT" verify-state-bundle --in "$T/ctrl.json" --genesis "$T/gen.json" 2>&1)
CTRL_RC=$?
set -e
echo "$CTRL_OUT" | sed 's/^/    ctrl| /'
if echo "$CTRL_OUT" | grep -qiE "quorum downgrade"; then
  assert "false" "3-of-3 MD must NOT trip the mode-eligibility gate (it did — gate is over-broad)"
elif [ "$CTRL_RC" = "3" ] && echo "$CTRL_OUT" | grep -qiE "sentinel-zero|signature"; then
  assert "true" "3-of-3 MD passes the mode-eligibility gate, falls through to the signature gate (gate is live, not a tautology)"
else
  assert "false" "3-of-3 MD should pass mode-eligibility and reach the signature gate (got rc=$CTRL_RC)"
fi

summary_exit
