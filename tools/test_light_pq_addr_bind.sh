#!/usr/bin/env bash
# LightVerify PQ-ADDR-BIND — the offline `pq-verify-tx` must, for a PQ_TRANSFER,
# enforce the FULL node accept-rule (determ::chain::verify_pq_transaction),
# including the address binding make_pq_anon_address(form, ML-DSA pubkey) == from.
#
# THE GAP (found by direct read, HIGH, CLIENT-fixable): cmd_pq_verify_tx checked
# ONLY that the DPQ1 envelope's ML-DSA signature verifies over the tx
# signing_bytes. A DPQ1 envelope is SELF-CERTIFYING — it carries its own pubkey —
# so a signature that "verifies" only proves the CARRIED key signed, NOT that the
# key is the one committed to by `from`. So an attacker signing a victim-`from`
# message with ITS OWN ML-DSA key was reported VERIFIED offline, yet the node
# REJECTS it (make_pq_anon_address(form, attacker_pk) != victim_from). A false
# authenticity assurance — the stale header comment ("consensus accept-rule is a
# separate, owner-gated step") predated inc.4, which shipped verify_pq_transaction.
#
# THE FIX (client-side only; no node/consensus change): a PQ_TRANSFER (type 11)
# is routed through the shared verify_pq_transaction (the exact node rule). The
# generic (non-PQ-native) envelope check is unchanged.
#
# This wrapper runs the pure in-process falsify gate `selftest-pq-addr-bind`,
# which constructs a concrete forgery (attacker key B signs a victim-`from`(==H(A))
# message) and proves the raw envelope check STILL accepts it while the fixed core
# REJECTS it. Falsify-on-mutant: reverting the PQ_TRANSFER branch to the
# envelope-only check makes the forged case flip back to VERIFIED, failing the
# "-> INVALID" assertion.
#
# FAST + OFFLINE (no cluster, no genesis file — deterministic seeds).
# Run from repo root: bash tools/test_light_pq_addr_bind.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

set +e
OUT=$("$DETERM_LIGHT" selftest-pq-addr-bind 2>&1)
RC=$?
set -e
echo "$OUT"

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-pq-addr-bind"; then
  echo "  PASS: test_light_pq_addr_bind"
  exit 0
else
  echo "  FAIL: test_light_pq_addr_bind (rc=$RC)"
  exit 1
fi
