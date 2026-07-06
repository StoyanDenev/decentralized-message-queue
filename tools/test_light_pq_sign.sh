#!/usr/bin/env bash
# determ-light PQ transaction authentication (CRYPTO-C99-SPEC §3.21). Produces a
# DPQ1 envelope (determ::pqauth) over a REAL transaction's canonical
# signing_bytes (pq-sign-tx) and verifies it offline (pq-verify-tx). This is the
# CLIENT-side half of the owner-authorized PQ signature chain-integration track;
# the consensus accept-rule that admits such a tx is a separate, owner-gated
# step. Pure offline sign+verify — no daemon / cluster needed.
#
# Assertions:
#   1. pq-sign-tx (hybrid65) writes a DPQ1-authenticated tx (exit 0).
#   2. pq-verify-tx VERIFIES it (exit 0) — the envelope binds signing_bytes.
#   3. Tampering a signed field (amount) -> INVALID (exit 3).
#   4. pq-only mldsa87 round-trips (sign + verify exit 0).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ]; then
  echo "  FAIL: determ-light not built (DETERM_LIGHT unset)"; exit 1
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FROM="0x$(printf 'a%.0s' $(seq 1 64))"
TO="0x$(printf 'b%.0s' $(seq 1 64))"
MS=$(printf '01%.0s' $(seq 1 32))
ES=$(printf '02%.0s' $(seq 1 32))
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

# 1 + 2: hybrid65 sign then verify.
if $DETERM_LIGHT pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" --amount 100 --fee 1 --nonce 0 \
     --scheme hybrid65 --mldsa-seed "$MS" --ed-seed "$ES" --out "$TMP/tx.json" >/dev/null; then
  pass "pq-sign-tx hybrid65 wrote DPQ1 envelope"
else fail "pq-sign-tx hybrid65"; fi
if $DETERM_LIGHT pq-verify-tx --file "$TMP/tx.json" >/dev/null; then
  pass "pq-verify-tx VERIFIED hybrid65"
else fail "pq-verify-tx hybrid65"; fi

# 3: tamper a signed field -> INVALID (exit 3, envelope binds signing_bytes).
sed 's/"amount": 100/"amount": 101/' "$TMP/tx.json" > "$TMP/bad.json"
$DETERM_LIGHT pq-verify-tx --file "$TMP/bad.json" >/dev/null
if [ $? -eq 3 ]; then pass "tampered amount -> INVALID"; else fail "tamper not rejected"; fi

# 4: pq-only mldsa87 round-trip.
if $DETERM_LIGHT pq-sign-tx --type STAKE --from "$FROM" --to "" --amount 50 --fee 0 --nonce 7 \
     --scheme mldsa87 --mldsa-seed "$MS" --out "$TMP/tx2.json" >/dev/null \
   && $DETERM_LIGHT pq-verify-tx --file "$TMP/tx2.json" >/dev/null; then
  pass "pq-only mldsa87 round-trip"
else fail "pq-only mldsa87 round-trip"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: light PQ tx authentication"; else echo "  FAIL: light PQ tx authentication"; fi
exit $rc
