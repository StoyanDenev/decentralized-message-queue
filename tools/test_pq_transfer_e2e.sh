#!/usr/bin/env bash
# §3.21 inc.6 — the PQ_TRANSFER end-to-end CLIENT→CONSENSUS loop, CROSS-BINARY:
# `determ-light pq-transfer` produces a canonical, submittable PQ_TRANSFER (derives
# the PQ-native bearer `from` address + signs a DPQ1 envelope over signing_bytes),
# and `determ verify-pq-tx` applies the SHARED consensus accept-rule
# (determ::chain::verify_pq_transaction) to that exact JSON — the same rule the
# block validator + mempool run. A tx that this pair accepts is one a validator
# accepts. Pure offline; no daemon.
#
# Assertions:
#   1. pq-address derives a valid PQ-native bearer address (is_pq_anon_address).
#   2. pq-transfer writes a submittable PQ_TRANSFER (exit 0).
#   3. verify-pq-tx VERIFIES it (exit 0) — the consensus rule accepts.
#   4. the tx's `from` equals the independently-derived pq-address (binding).
#   5. tampering the amount -> verify-pq-tx INVALID (exit 3).
#   6. a hybrid-scheme attempt is refused by pq-transfer (PQ-native = PQ-only).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ]; then echo "  FAIL: determ-light not built"; exit 1; fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
MS=$(printf '07%.0s' $(seq 1 32))
TO="0x$(printf 'b%.0s' $(seq 1 64))"
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

# 1: derive the PQ address.
ADDR=$($DETERM_LIGHT pq-address --scheme mldsa65 --mldsa-seed "$MS" 2>/dev/null)
if [ "${ADDR:0:4}" = "0x02" ] && [ ${#ADDR} -eq 3908 ]; then pass "pq-address (ML-DSA-65 bearer, 3908 chars)"; else fail "pq-address shape ('${ADDR:0:12}...' len ${#ADDR})"; fi

# 2: produce a submittable PQ_TRANSFER.
if $DETERM_LIGHT pq-transfer --to "$TO" --amount 100 --fee 1 --nonce 0 \
     --scheme mldsa65 --mldsa-seed "$MS" --out "$TMP/tx.json" >/dev/null 2>&1; then
  pass "pq-transfer wrote a submittable PQ_TRANSFER"
else fail "pq-transfer"; fi

# 3: the consensus accept-rule (in the full binary) accepts it.
if $DETERM verify-pq-tx --file "$TMP/tx.json" >/dev/null 2>&1; then
  pass "verify-pq-tx VERIFIED (consensus rule accepts)"
else fail "verify-pq-tx rejected a valid PQ_TRANSFER"; fi

# 4: the tx.from equals the independently-derived address (address<->key binding).
TXFROM=$(grep -oE '"from": "0x[0-9a-f]+"' "$TMP/tx.json" | head -1 | sed 's/.*"\(0x[0-9a-f]*\)".*/\1/')
if [ "$TXFROM" = "$ADDR" ]; then pass "tx.from == derived pq-address"; else fail "tx.from != pq-address"; fi

# 5: tamper the amount -> the consensus rule rejects (envelope binds signing_bytes).
sed 's/"amount": 100/"amount": 101/' "$TMP/tx.json" > "$TMP/bad.json"
$DETERM verify-pq-tx --file "$TMP/bad.json" >/dev/null 2>&1
if [ $? -eq 3 ]; then pass "tampered amount -> INVALID (exit 3)"; else fail "tamper not rejected"; fi

# 6: hybrid is refused (a PQ-native account has no Ed25519).
if $DETERM_LIGHT pq-transfer --to "$TO" --amount 1 --fee 0 --nonce 0 \
     --scheme hybrid65 --mldsa-seed "$MS" >/dev/null 2>&1; then
  fail "pq-transfer accepted a hybrid scheme"
else pass "pq-transfer refuses a hybrid scheme (PQ-native = PQ-only)"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: PQ_TRANSFER client->consensus loop"; else echo "  FAIL: PQ_TRANSFER e2e"; fi
exit $rc
