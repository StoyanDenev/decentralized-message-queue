#!/usr/bin/env bash
# V-REG-1 — REGISTER is CREATE-ONLY (owner-authorized 2026-09-15; docs/SECURITY.md
# S-060; DECISION-LOG 2026-08-14 `5e4afec` / `1c0a61d`).
#
# A REGISTER is verified against the key in its OWN payload and apply
# overwrote the whole registry record, so any key could rebind any domain:
# evict it from the committee (a 9/10 permanent halt at |pool| == K), sign
# consensus messages as it, and forge its equivocation forfeiture (the
# reopened S-052) — at fee 0, from any TCP socket, at the victim's public
# nonce (0 for every genesis creator). Now BlockValidator::check_transaction
# rejects a REGISTER whose domain is already in the RAW chain.registrants()
# map (active, pending, suspended or deregistered — the eligible registry
# would omit exactly the weakest) and one whose nonce is not 0 (a fresh
# domain's first transaction is nonce 0 by construction, so "one REGISTER per
# domain per block" is a per-tx rule with no block-level overlay and no
# producer mirror); rpc_register refuses to queue one for a registered node.
# Consequences, decided by the owner: a domain name is single-use, a lost key
# is terminal, key rotation is a separate incumbent-signed transaction
# (DECISION CLOCK R-6).
#
# Falsify-on-mutant (executed 2026-09-15, reverted):
#   M1 delete the registrants-map rule -> the three "create-only" arms flip RED
#      (takeover, incumbent re-REGISTER, deregistered domain); the control
#      stays GREEN.
#   M2 delete the nonce-0 rule -> the nonce arm and the one-per-block arm flip
#      RED.
#   M3 delete the rpc_register guard -> the rpc arm flips RED.
#   M4 delete the ingress mirror in verify_tx_signature_locked -> the three
#      ingress arms flip RED (gossip and RPC ingress apply only the mirror;
#      the verifier's rule fires at build, where the tx is then evicted).
# Positive controls: a fresh-domain REGISTER is accepted by the verifier and an
# UNREGISTERED node's rpc_register is queued.
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_register_create_only.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== V-REG-1 / S-060: REGISTER is create-only (raw registrants map, nonce 0); rpc_register refuses for a registered node ==="
OUT=$("$DETERM" test-register-create-only 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-register-create-only"; then
  echo "  PASS: test_register_create_only"
  exit 0
else
  echo "  FAIL: test_register_create_only (exit $rc)"
  exit 1
fi
