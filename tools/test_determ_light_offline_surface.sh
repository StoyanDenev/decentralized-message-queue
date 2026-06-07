#!/usr/bin/env bash
# determ-light OFFLINE subcommand surface — daemon-free regression.
#
# Pure offline test (no cluster, no daemon, no RPC). Exercises the
# determ-light subcommands that need NO running node — the ones a
# user can run air-gapped against operator-supplied fixtures:
#
#   help / version          structured, exit 0
#   verify-headers          chain-of-hashes verify over an inline
#                           `headers` envelope (OK on a valid link,
#                           FAIL on a broken prev_hash chain, FAIL on
#                           a wrong --genesis-hash anchor)
#   verify-state-proof      fail-closed on a structurally malformed
#                           proof (exit 1, never a false OK)
#   verify-block-sigs       usage error (exit 1) when required flags
#                           are absent
#   sign-tx                 offline TRANSFER/STAKE signing with an
#                           operator-supplied nonce + plaintext keyfile
#                           (uses determ-wallet to mint a valid keypair;
#                           the keyfile loader rejects an address that
#                           doesn't match the Ed25519 pubkey per S-028,
#                           so the pair must be genuine — this group is
#                           skipped, not failed, if the wallet is absent)
#
# All fixtures are built inline the way tools/test_light_sign_tx.sh and
# tools/test_light_decode_wire.sh do — no cluster bring-up. The headers
# fixture is a hand-rolled two-header chain (genesis index 0 + a child
# whose prev_hash equals genesis block_hash); the tamper variant breaks
# that link.
#
# SKIP-with-PASS (exit 0) when determ-light is absent, so this script is
# a no-op pass in minimal build environments, never a hard failure.
#
# Run from repo root: bash tools/test_determ_light_offline_surface.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

TMP="build/test_determ_light_offline_surface.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. help → structured usage, exit 0 ==="
set +e
OUT=$("$DETERM_LIGHT" help 2>&1); RC=$?
set -e
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "^Usage: determ-light"; then
    assert "true" "help prints usage and exits 0"
else
    assert "false" "help prints usage and exits 0 (RC=$RC)"
fi

echo
echo "=== 2. version → exit 0, prints binary name ==="
set +e
OUT=$("$DETERM_LIGHT" version 2>&1); RC=$?
set -e
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "^determ-light "; then
    assert "true" "version prints 'determ-light <ver>' and exits 0"
else
    assert "false" "version prints 'determ-light <ver>' and exits 0 (RC=$RC)"
fi

echo
echo "=== 3. Build inline two-header chain fixture ==="
$PY -c "
import json
z  = '0' * 64
h0 = '11' * 32
h1 = '22' * 32
json.dump({'headers': [
    {'index': 0, 'prev_hash': z,  'block_hash': h0},
    {'index': 1, 'prev_hash': h0, 'block_hash': h1},
]}, open('$TMP/hdrs.json', 'w'))
# Tampered: break the prev_hash link at header 1.
json.dump({'headers': [
    {'index': 0, 'prev_hash': z,        'block_hash': h0},
    {'index': 1, 'prev_hash': '33' * 32, 'block_hash': h1},
]}, open('$TMP/hdrs_bad.json', 'w'))
"
if [ -s "$TMP/hdrs.json" ] && [ -s "$TMP/hdrs_bad.json" ]; then
    assert "true" "inline headers fixtures written"
else
    assert "false" "inline headers fixtures written"
fi

echo
echo "=== 4. verify-headers OK on a valid prev_hash chain ==="
set +e
OUT=$("$DETERM_LIGHT" verify-headers --in "$TMP/hdrs.json" 2>&1); RC=$?
set -e
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
if [ "$RC" = "0" ] && [ "$OK" = "true" ]; then
    assert "true" "verify-headers OK on valid chain"
else
    echo "$OUT"
    assert "false" "verify-headers OK on valid chain (RC=$RC)"
fi

echo
echo "=== 5. verify-headers FAIL on a broken prev_hash chain ==="
set +e
OUT=$("$DETERM_LIGHT" verify-headers --in "$TMP/hdrs_bad.json" 2>&1); RC=$?
set -e
FAIL=$(echo "$OUT" | grep -q "FAIL.*prev_hash chain break" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$FAIL" = "true" ]; then
    assert "true" "tampered prev_hash → FAIL, exit 1"
else
    echo "$OUT"
    assert "false" "tampered prev_hash → FAIL, exit 1 (RC=$RC)"
fi

echo
echo "=== 6. verify-headers FAIL on wrong --genesis-hash anchor ==="
WRONG=$($PY -c "print('a' * 64)")
set +e
OUT=$("$DETERM_LIGHT" verify-headers --in "$TMP/hdrs.json" --genesis-hash "$WRONG" 2>&1); RC=$?
set -e
FAIL=$(echo "$OUT" | grep -q "FAIL.*genesis block_hash mismatch" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$FAIL" = "true" ]; then
    assert "true" "wrong --genesis-hash → FAIL, exit 1"
else
    echo "$OUT"
    assert "false" "wrong --genesis-hash → FAIL, exit 1 (RC=$RC)"
fi

echo
echo "=== 7. verify-state-proof fails closed on a malformed proof ==="
# A short state_root (not 64 hex) is a structurally malformed proof —
# the verifier must reject it (exit 1), never emit a false OK.
echo '{"state_root":"00"}' > "$TMP/proof_bad.json"
set +e
OUT=$("$DETERM_LIGHT" verify-state-proof --in "$TMP/proof_bad.json" 2>&1); RC=$?
set -e
NOT_OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo false || echo true)
if [ "$RC" != "0" ] && [ "$NOT_OK" = "true" ]; then
    assert "true" "malformed proof → non-zero exit, no false OK"
else
    echo "$OUT"
    assert "false" "malformed proof → non-zero exit, no false OK (RC=$RC)"
fi

echo
echo "=== 8. verify-block-sigs usage error on missing flags ==="
set +e
OUT=$("$DETERM_LIGHT" verify-block-sigs 2>&1); RC=$?
set -e
USAGE=$(echo "$OUT" | grep -q "required" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$USAGE" = "true" ]; then
    assert "true" "verify-block-sigs missing flags → usage error, exit 1"
else
    echo "$OUT"
    assert "false" "verify-block-sigs missing flags → usage error, exit 1 (RC=$RC)"
fi

echo
echo "=== 9. sign-tx offline (operator-supplied nonce + plaintext keyfile) ==="
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet not found (needed to mint a valid keypair);"
    echo "        the keyfile loader rejects an address that doesn't match its"
    echo "        Ed25519 pubkey (S-028), so a hand-rolled keyfile can't be used."
else
    # Mint two anon keypairs; write a minimal {address,privkey_hex} keyfile.
    "$DETERM_WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
    $PY -c "
import json
d = json.load(open('$TMP/keys.json'))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open('$TMP/key_a.json', 'w'))
open('$TMP/addr_b.txt', 'w').write(d['accounts'][1]['address'])
"
    ADDR_B=$(cat "$TMP/addr_b.txt")

    echo "  -- 9a. TRANSFER produces a signed envelope --"
    set +e
    "$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
        --to "$ADDR_B" --amount 100 --fee 0 --nonce 0 --out "$TMP/tx.json" \
        > "$TMP/sign.out" 2>&1
    RC=$?
    set -e
    if [ "$RC" = "0" ] && [ -s "$TMP/tx.json" ]; then
        assert "true" "sign-tx TRANSFER wrote a signed envelope"
    else
        cat "$TMP/sign.out"
        assert "false" "sign-tx TRANSFER wrote a signed envelope (RC=$RC)"
    fi

    echo "  -- 9b. signed envelope has the expected shape --"
    SHAPE=$($PY -c "
import json
try:
    d = json.load(open('$TMP/tx.json'))
    need = ['type','from','to','amount','fee','nonce','sig','hash']
    missing = [k for k in need if k not in d]
    ok = (not missing
          and len(d.get('sig','')) == 128
          and len(d.get('hash','')) == 64)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
    assert "$SHAPE" "signed envelope shape (fields + sig=128 + hash=64 hex)"

    echo "  -- 9c. missing --to (TRANSFER) → usage error, exit 1 --"
    set +e
    "$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
        --amount 100 --fee 0 --nonce 0 >/dev/null 2>&1
    RC=$?
    set -e
    if [ "$RC" = "1" ]; then
        assert "true" "sign-tx TRANSFER missing --to → exit 1"
    else
        assert "false" "sign-tx TRANSFER missing --to → exit 1 (got $RC)"
    fi

    echo "  -- 9d. STAKE signing also succeeds --"
    set +e
    "$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type STAKE \
        --to validator-node --amount 1000 --fee 0 --nonce 1 \
        --out "$TMP/stake.json" >/dev/null 2>&1
    RC=$?
    set -e
    if [ "$RC" = "0" ] && [ -s "$TMP/stake.json" ]; then
        assert "true" "sign-tx STAKE wrote a signed envelope"
    else
        assert "false" "sign-tx STAKE wrote a signed envelope (RC=$RC)"
    fi
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_determ_light_offline_surface"; exit 0
else
  echo "  FAIL: test_determ_light_offline_surface"; exit 1
fi
