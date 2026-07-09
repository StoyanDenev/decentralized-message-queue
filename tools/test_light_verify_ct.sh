#!/usr/bin/env bash
# A3 (pre-launch register, owner 2026-07-09) — determ-light CLIENT-SIDE
# confidential-transaction verification: `verify-ct-tx` (single tx) and the
# CT-PROOFS check inside `block-verify`. The light client re-runs the SAME
# cryptographic accept-rules the validator runs — range/balance proofs are
# NOT trusted to the committee.
#
# Fixtures are built by the INDEPENDENT python oracles (tools/verify_pedersen
# + verify_p256_balance — from-scratch P-256, the same modules the §3.13
# vector gate trusts) — so this is a dual-oracle test: python PROVES,
# the shipped C VERIFIES. The DCT1 fixture is the frozen corpus bundle
# (tools/vectors/p256_ctx_bundle.json, fee=1).
#
# 14 assertions:
#   SHIELD:   valid VERIFIED / inflated-amount reject / tampered-proof reject
#   UNSHIELD: valid context-BOUND VERIFIED / redirected-recipient reject
#             (the front-run defense) / UNBOUND-proof reject
#   DCT1:     frozen-corpus bundle VERIFIED / fee-mismatch reject /
#             tampered-bundle reject
#   contract: non-CT tx -> INVALID exit 3; missing --file -> exit 1
#   block-verify CT-PROOFS: PASS on a good CT block / FAIL on a tampered CT
#             block / vacuous-PASS with explicit 0-count on a CT-free block
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "=== determ-light client-side CT verification (A3) ==="

# ── fixture generation via the independent python oracles ──────────────────
python - "$TMP" <<'PYEOF'
import hashlib, json, os, sys
sys.path.insert(0, "tools")
import verify_pedersen as vp
import verify_p256_balance as bal

tmp = sys.argv[1]
A, R, FEE = 100, 0xBEEF, 1

def s32(x): return x.to_bytes(32, "big")

def tx(type_, frm, to, amount, fee, nonce, payload_hex):
    return {"type": type_, "from": frm, "to": to, "amount": amount,
            "fee": fee, "nonce": nonce, "payload": payload_hex,
            "sig": "00" * 64, "hash": "00" * 32}

def write(name, obj):
    with open(os.path.join(tmp, name), "w") as f:
        json.dump(obj, f)

# SHIELD: C = A*G + r*H ; E = C - A*G ; unbound Schnorr PoK(E = r*H).
C = bal.commit(A, R)
E = bal.balance_excess([C], [], A)
shield_payload = (vp.compress(C) + bal.balance_prove(E, R, 0xC0FFEE)).hex()
write("shield_ok.json", tx(12, "alice", "", A, FEE, 0, shield_payload))
write("shield_bad_amount.json", tx(12, "alice", "", A + 1, FEE, 0, shield_payload))
bad = bytearray(bytes.fromhex(shield_payload)); bad[-1] ^= 1
write("shield_tampered.json", tx(12, "alice", "", A, FEE, 0, bytes(bad).hex()))

# UNSHIELD: same note, proof BOUND to ctx = SHA256(DST || len64be(from)||from
# || len64be(to)||to || nonce_be || amount_be) via c = H_s(E || T || ctx).
def unshield_ctx(frm, to, nonce, amount):
    h = hashlib.sha256()
    h.update(b"determ-unshield-v1")
    h.update(len(frm).to_bytes(8, "big")); h.update(frm.encode())
    h.update(len(to).to_bytes(8, "big"));  h.update(to.encode())
    h.update(nonce.to_bytes(8, "big"));    h.update(amount.to_bytes(8, "big"))
    return h.digest()

def balance_prove_bound(E, x, k, ctx32):
    T = vp.pt_mul(k, bal.H())
    c = bal._hts(vp.compress(E) + vp.compress(T) + ctx32)
    s = (k + c * x) % bal.N
    return vp.compress(T) + s32(s)

ctx = unshield_ctx("alice", "bob", 1, A)
un_payload = (vp.compress(C) + balance_prove_bound(E, R, 0xD00D, ctx)).hex()
write("unshield_ok.json", tx(13, "alice", "bob", A, FEE, 1, un_payload))
# Same payload redirected to a different recipient -> ctx differs -> reject.
write("unshield_redirect.json", tx(13, "alice", "attacker", A, FEE, 1, un_payload))
# An UNBOUND proof in an UNSHIELD -> must reject (bound verify only).
un_unbound = (vp.compress(C) + bal.balance_prove(E, R, 0xD00D)).hex()
write("unshield_unbound.json", tx(13, "alice", "bob", A, FEE, 1, un_unbound))

# CONFIDENTIAL_TRANSFER: the frozen corpus DCT1 bundle (fee = 1).
with open("tools/vectors/p256_ctx_bundle.json") as f:
    rec = json.load(f)["vector"]
bundle_hex, bundle_fee = rec["bundle_hex"], rec["fee"]
write("ctx_ok.json", tx(14, "alice", "", 0, bundle_fee, 2, bundle_hex))
write("ctx_bad_fee.json", tx(14, "alice", "", 0, bundle_fee + 1, 2, bundle_hex))
badb = bytearray(bytes.fromhex(bundle_hex)); badb[-1] ^= 1
write("ctx_tampered.json", tx(14, "alice", "", 0, bundle_fee, 2, bytes(badb).hex()))

# Non-CT tx (plain TRANSFER).
write("transfer.json", tx(0, "alice", "bob", 5, 1, 0, ""))

# block-verify fixtures. tx_root = SHA256 over an EMPTY sorted-dedup union
# (creator_tx_lists empty) so STRUCTURE + TX-ROOT pass and the CT-PROOFS
# verdict is isolated. SIGS fails against the dummy committee — expected;
# the assertions below key on the CT-PROOFS check verdict via --json.
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
def block(txs):
    return {"index": 1, "prev_hash": "00" * 32, "timestamp": 1,
            "creators": ["val"], "creator_tx_lists": [],
            "tx_root": EMPTY_ROOT, "creator_block_sigs": [],
            "transactions": txs}
write("block_ct_ok.json",   block([tx(12, "alice", "", A, FEE, 0, shield_payload),
                                   tx(0, "alice", "bob", 5, 1, 1, "")]))
write("block_ct_bad.json",  block([tx(12, "alice", "", A, FEE, 0, bytes(bad).hex())]))
write("block_ct_none.json", block([tx(0, "alice", "bob", 5, 1, 0, "")]))
write("committee.json", {"validators": [{"domain": "val", "ed_pub": "00" * 32}]})
print("fixtures written")
PYEOF
if [ $? -ne 0 ]; then echo "  FAIL: fixture generation"; exit 1; fi

PASS=0; FAIL=0
check() {  # check <desc> <expected_rc> <cmd...>
  local desc="$1" want="$2"; shift 2
  "$@" > "$TMP/out.txt" 2>&1
  local rc=$?
  if [ "$rc" -eq "$want" ]; then
    echo "  PASS: $desc"; PASS=$((PASS+1))
  else
    echo "  FAIL: $desc (rc=$rc want=$want)"; sed 's/^/    | /' "$TMP/out.txt" | head -5
    FAIL=$((FAIL+1))
  fi
}

# ── verify-ct-tx ────────────────────────────────────────────────────────────
check "SHIELD valid proof VERIFIED"                0 $DETERM_LIGHT verify-ct-tx --file "$TMP/shield_ok.json"
check "SHIELD inflated amount REJECTED"            3 $DETERM_LIGHT verify-ct-tx --file "$TMP/shield_bad_amount.json"
check "SHIELD tampered proof REJECTED"             3 $DETERM_LIGHT verify-ct-tx --file "$TMP/shield_tampered.json"
check "UNSHIELD context-bound proof VERIFIED"      0 $DETERM_LIGHT verify-ct-tx --file "$TMP/unshield_ok.json"
check "UNSHIELD redirected recipient REJECTED (front-run defense)" \
                                                   3 $DETERM_LIGHT verify-ct-tx --file "$TMP/unshield_redirect.json"
check "UNSHIELD unbound proof REJECTED"            3 $DETERM_LIGHT verify-ct-tx --file "$TMP/unshield_unbound.json"
check "DCT1 frozen-corpus bundle VERIFIED"         0 $DETERM_LIGHT verify-ct-tx --file "$TMP/ctx_ok.json"
check "DCT1 fee mismatch REJECTED"                 3 $DETERM_LIGHT verify-ct-tx --file "$TMP/ctx_bad_fee.json"
check "DCT1 tampered bundle REJECTED"              3 $DETERM_LIGHT verify-ct-tx --file "$TMP/ctx_tampered.json"
check "non-CT tx is INVALID (never reads as verified)" \
                                                   3 $DETERM_LIGHT verify-ct-tx --file "$TMP/transfer.json"
check "missing --file is a usage error"            1 $DETERM_LIGHT verify-ct-tx

# ── block-verify CT-PROOFS check (verdict isolated via --json) ─────────────
ct_verdict() {  # ct_verdict <block-file> -> prints the CT-PROOFS verdict
  $DETERM_LIGHT block-verify --block "$1" --committee "$TMP/committee.json" --json 2>/dev/null \
    | python -c "import json,sys; d=json.load(sys.stdin); print(next(c['verdict'] for c in d['checks'] if c['check']=='CT-PROOFS'))"
}
V=$(ct_verdict "$TMP/block_ct_ok.json")
if [ "$V" = "PASS" ]; then echo "  PASS: block-verify CT-PROOFS PASS on valid CT block"; PASS=$((PASS+1))
else echo "  FAIL: block-verify CT-PROOFS on valid CT block (got '$V')"; FAIL=$((FAIL+1)); fi
V=$(ct_verdict "$TMP/block_ct_bad.json")
if [ "$V" = "FAIL" ]; then echo "  PASS: block-verify CT-PROOFS FAIL on tampered CT block"; PASS=$((PASS+1))
else echo "  FAIL: block-verify CT-PROOFS on tampered CT block (got '$V')"; FAIL=$((FAIL+1)); fi
V=$(ct_verdict "$TMP/block_ct_none.json")
DETAIL=$($DETERM_LIGHT block-verify --block "$TMP/block_ct_none.json" --committee "$TMP/committee.json" --json 2>/dev/null \
    | python -c "import json,sys; d=json.load(sys.stdin); print(next(c['detail'] for c in d['checks'] if c['check']=='CT-PROOFS'))")
if [ "$V" = "PASS" ] && echo "$DETAIL" | grep -q "none present"; then
  echo "  PASS: block-verify CT-PROOFS vacuous-PASS carries the explicit 0-count"; PASS=$((PASS+1))
else
  echo "  FAIL: block-verify CT-PROOFS vacuity (verdict '$V', detail '$DETAIL')"; FAIL=$((FAIL+1))
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "  PASS: test_light_verify_ct ($PASS assertions)"
  exit 0
else
  echo "  FAIL: test_light_verify_ct ($FAIL of $((PASS+FAIL)) assertions failed)"
  exit 1
fi
