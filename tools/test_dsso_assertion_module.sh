#!/usr/bin/env bash
# DSSO §5 relying-party assertion module — the shipped module, not a harness.
#
# v2.25-DSSO-DAPP-SPEC.md §5 / claim C6. `dapps/dsso/assertion.{h,c}` issues the
# assertion at the IdP and verifies it at the RP:
#
#   binder = HMAC(sso_key,    DS_BINDER | canon(claim))
#   tag    = HMAC(tenant_key, DS_TAG    | canon(claim) | binder)
#
# The user presents (claim, binder) and NO tag. The RP accepts iff the tag it
# recomputes over the presented claim and binder is one of the reference tags the
# IdP delivered to it over the registered channel, the authenticated session id
# is the one this verifier opened, the clock legs hold, and the nonce is unseen. Still the paper's dual keyed hash over co-generated keys — no
# signature, no FROST, no block co-sign; HMAC-SHA-256 only, zero new primitive.
#
# WHAT THIS REPLACES. The rule that shipped in `determ test-dsso-assertion` was
#   accept iff HMAC(tenant_key, H1'_presented) == H2_presented
# — a pure function of tenant_key and presenter-chosen bytes, reading neither
# sso_key nor the claim. So (a) any tenant_key holder minted a token for any
# subject, and (b) one honestly issued token authenticated any substituted claim
# (spec §0.0(3)). Every rejection this gate asserts fails on that old rule.
#
# The assertions, by group:
#   honest        issue -> deliver -> accept, yielding the authenticated subject
#   C6(a)         a tenant_key holder who completed no login cannot mint; a binder
#                 from another sso_key over the same claim is rejected
#   C6(b)         substituting subject / audience / session / nonce / iat / exp /
#                 issuer / binder is each rejected on the MAC
#   session       a VALID assertion for session A is rejected by the verifier
#                 completing session B (DSSO_E_BINDING) — login-CSRF
#   cross-RP      A's assertion is rejected at B, even with A's tag injected
#   replay        the same assertion a second time is rejected (single-use nonce)
#   freshness     expired, not-yet-valid and over-long-lifetime claims rejected;
#                 a clock that cannot be read is DSSO_E_UNAVAILABLE
#   trust         an unknown RP, a rotated-out key_epoch and a previous
#                 reg_epoch are each DSSO_E_TRUST
#   pairwise      one user -> different subjects at two RPs, the same subject at
#                 one RP across two logins, a new subject on re-registration
#   cache         the nonce cache is bounded, fails closed when full, evicts only
#                 entries outside their window, and eviction cannot resurrect a
#                 used nonce inside its window
#   fail-closed   every missing or over-long input is a named status, never an
#                 accept and never a truncation
#
# Run from repo root: bash tools/test_dsso_assertion_module.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DSSO §5 RP assertion module (dapps/dsso/assertion.c, claim C6) ==="
OUT=$($DETERM_DSSO selftest-assertion 2>&1); rc=$?
echo "$OUT"

if [ $rc -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: dsso-assertion all assertions"; then
  echo ""
  echo "  PASS: dsso_assertion_module"
  exit 0
else
  echo ""
  echo "  FAIL: dsso_assertion_module had assertion failures (exit $rc)"
  exit 1
fi
