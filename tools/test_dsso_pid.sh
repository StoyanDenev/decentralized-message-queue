#!/usr/bin/env bash
# determ-dsso PID gate — DSSO as a WALLET-RELYING PARTY (Reg. (EU) 2024/1183 Art. 5b).
#
# Runs `determ-dsso selftest-pid`: accept a Person Identification Data presentation
# from an EUDI Wallet Unit, verify it under nine separately-testable rules, and
# decide whether it may be bound to a DSSO account.
#
# The format verified is SD-JWT VC (the JOSE/JSON profile) with a Key Binding JWT.
# ISO/IEC 18013-5 mdoc/CBOR is NOT implemented, so an mdoc-only wallet is out of
# scope until a second increment — see docs/proofs/DssoPidVerification.md for the
# justification and for everything this gate does NOT claim.
#
# What the gate pins, each with an accept case and its own rejections:
#   1 structure       bounded base64url + bounded JSON; non-canonical encodings,
#                     duplicate JSON keys, over-deep nesting, trailing data
#   2 issuer trust    the key comes from the configured PID Provider trust anchor
#                     list, never from the token (ARF OIA_12)
#   3 signature       ES256 over the exact wire signing input; alg:none, algorithm
#                     substitution, a wrong key, a truncated signature
#   4 disclosures     every disclosure hashes into `_sd`; no duplicate, no
#                     unbacked or shadowing attribute
#   5 holder binding  the KB-JWT is signed by the credential's `cnf` key and
#                     covers THIS presentation (ARF OIA_02)
#   6 aud + nonce     DSSO's own relying-party id, and the challenge DSSO issued
#                     for THIS request
#   7 freshness       iat/nbf/exp with bounded skew and bounded maximum age
#   8 status          Token Status List, signature-checked against the same trust
#                     anchors and FAIL-CLOSED when it cannot be consulted
#   9 assurance       evidence at or above the required eIDAS level
# plus the account-binding rules (a session alone never authorises a binding; one
# subject, one account; no reuse of a presentation), a pseudonym derivation that a
# database leak does not turn into an identity list, and fuzz arms over the three
# readers a hostile wallet reaches (6900 mutated inputs in total).
#
# PASSING THIS GATE IS NOT A COMPLIANCE CLAIM. The wallet-relying-party ACCESS
# CERTIFICATE (ARF RPA_01..RPA_06) and registration with a Member State registrar
# are external and are NOT obtained.
#
# Run from repo root: bash tools/test_dsso_pid.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== determ-dsso PID verification (SD-JWT VC wallet-relying-party surface) ==="
OUT=$($DETERM_DSSO selftest-pid 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dsso-pid all assertions"; then
  echo ""
  echo "  PASS: dsso_pid"
  exit 0
else
  echo ""
  echo "  FAIL: dsso_pid had assertion failures"
  exit 1
fi
