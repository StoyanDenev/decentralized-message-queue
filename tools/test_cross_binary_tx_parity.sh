#!/usr/bin/env bash
# Cross-binary CANONICAL-FORMAT PARITY — the interop invariant that the
# same Transaction must hash to a byte-identical tx_hash across ALL THREE
# Determ binaries: determ, determ-wallet, determ-light.
#
# WHY THIS TEST EXISTS
# --------------------
# All three binaries link the SAME canonical signing_bytes layout (the
# pre-image over which Ed25519 tx sigs are computed + SHA-256'd into the
# tx_hash). The reference layout lives in:
#   * src/chain/block.cpp  Transaction::signing_bytes (the canonical
#     source; determ links it; declared include/determ/chain/block.hpp:216)
#   * light/sign_tx.cpp:37 compute_signing_bytes (light's own copy,
#     documented "matches src/chain/block.cpp::Transaction::signing_bytes")
#   * wallet/main.cpp:8228 cmd_tx_sign_verify reconstructs the same layout
#     inline (the wallet deliberately does NOT link the chain lib).
#
# Because determ-wallet + determ-light each re-implement the byte layout
# independently (to keep their TCBs decoupled from the chain consensus
# lib), a future edit to ANY one copy — a flipped endianness, a moved NUL
# terminator, a reordered field — would silently diverge and break sig
# interop: a tx signed by one binary would fail verification on another.
# Per-binary unit tests (test_tx_signing_bytes.sh on determ only,
# test_wallet_tx_sign_verify.sh on wallet-vs-Python only) cannot catch a
# divergence BETWEEN binaries. This test pins the three-way agreement.
#
# WHAT IT DOES (offline, no cluster, no daemon)
# ---------------------------------------------
# For each canonical tx (TRANSFER, STAKE, UNSTAKE):
#   1. determ-light  sign-tx       — signs the canonical inputs; the signed
#                                    envelope carries `hash` = the light
#                                    binary's SHA-256(signing_bytes).
#   2. determ        tx-hash --in  — runs Transaction::from_json +
#                                    compute_hash on the SAME envelope and
#                                    prints the chain-canonical tx_hash.
#   3. determ-wallet tx-sign-verify — reconstructs signing_bytes inline,
#                                    reports tx_hash_hex /
#                                    computed_signing_bytes_sha256, AND
#                                    cryptographically verifies the light
#                                    sig under the sender's pubkey (the
#                                    anon-address minus the 0x prefix).
#   Assert: light.hash == determ.tx-hash == wallet.tx_hash_hex
#           == wallet.computed_signing_bytes_sha256  (byte-identical),
#           AND wallet reports valid=true (exit 0) — i.e. a sig produced
#           by the light binary verifies under the wallet's independent
#           signing_bytes reconstruction. That is the interop invariant.
#
# All paths used here are signing_bytes / tx_hash paths, which work on
# every host (including this Windows box). NONE of them touch
# compute_genesis_hash (which has a known Windows edge), so there is no
# genesis-dependent leg to SKIP.
#
# Run from repo root: bash tools/test_cross_binary_tx_parity.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# ── SKIP gracefully if any of the three binaries is missing ─────────────
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found; build with"
    echo "        cmake --build build --config Release --target determ"
    exit 0
fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "  SKIP: python not found (needed to read JSON fields)"
    exit 0
fi

TMP="build/test_cross_binary_tx_parity.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       a: $1"; echo "       b: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Mint a fresh anon keypair via determ-wallet ─────────────────────────
# account-create-batch emits {"accounts":[{"address":"0x<64hex>",
# "privkey_hex":"<64hex>"},...]}. The light keyfile loader
# (light/keyfile.cpp:84) accepts exactly the {address, privkey_hex} shape,
# so we hand it one account object verbatim. The wallet tx-sign-verify
# --pubkey is the address with the 0x stripped (anon address == 0x + the
# Ed25519 pubkey, per light/keyfile.cpp:132).
"$DETERM_WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
if [ ! -s "$TMP/keys.json" ]; then
    echo "  SKIP: account-create-batch produced no keys (wallet env issue)"
    exit 0
fi

# Use 'wb' so the byte-exact keyfile + addr files are LF-clean on Windows
# (Python text mode would translate LF->CRLF and corrupt nothing here, but
# we standardize on 'wb' for every file the native binaries read).
$PY - "$TMP/keys.json" "$TMP" <<'PY_EOF'
import json, sys
keys_path, tmp = sys.argv[1], sys.argv[2]
d = json.load(open(keys_path))
a = d["accounts"][0]
b = d["accounts"][1]
# One account object verbatim = a valid light keyfile.
with open(tmp + "/key_a.json", "wb") as f:
    f.write(json.dumps(a).encode("utf-8"))
with open(tmp + "/addr_a.txt", "wb") as f:
    f.write(a["address"].encode("utf-8"))
with open(tmp + "/addr_b.txt", "wb") as f:
    f.write(b["address"].encode("utf-8"))
PY_EOF

ADDR_A=$(cat "$TMP/addr_a.txt")
ADDR_B=$(cat "$TMP/addr_b.txt")
PUB_A="${ADDR_A#0x}"

echo "  sender (A): $ADDR_A"
echo "  recip  (B): $ADDR_B"

# ── Helper: run the full 3-binary parity check for one signed envelope ───
# Args: <label> <tx.json path>
# Reads light's stored `hash`, runs determ tx-hash + wallet tx-sign-verify
# on the SAME file, and asserts all four hash values are byte-identical
# (and that wallet declares the light sig valid → exit 0).
parity_check() {
    local label="$1" txjson="$2"

    # (1) light binary's stored hash (SHA-256 of ITS signing_bytes).
    local light_hash
    light_hash=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['hash'])" "$txjson")

    # (2) determ tx-hash --in (chain-canonical Transaction::compute_hash).
    local determ_hash determ_rc
    set +e
    determ_hash=$("$DETERM" tx-hash --in "$txjson" 2>/dev/null | tr -d '\r\n')
    determ_rc=$?
    set -e
    assert_eq "$determ_rc" "0" "[$label] determ tx-hash exits 0"

    # (3) wallet tx-sign-verify --json (independent signing_bytes rebuild +
    #     Ed25519 verify of the light sig under A's pubkey).
    local wallet_json wallet_rc wallet_hash wallet_csb wallet_valid
    set +e
    wallet_json=$("$DETERM_WALLET" tx-sign-verify --tx "$txjson" --pubkey "$PUB_A" --json 2>/dev/null | tr -d '\r')
    wallet_rc=$?
    set -e
    assert_eq "$wallet_rc" "0" "[$label] wallet tx-sign-verify exits 0 (light sig valid under wallet's signing_bytes)"
    wallet_hash=$(echo "$wallet_json"  | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])")
    wallet_csb=$(echo "$wallet_json"   | $PY -c "import json,sys; print(json.load(sys.stdin)['computed_signing_bytes_sha256'])")
    wallet_valid=$(echo "$wallet_json" | $PY -c "import json,sys; print(json.load(sys.stdin)['valid'])")

    assert_eq "$wallet_valid" "True" "[$label] wallet reports valid=true"

    # Sanity: a real 64-hex hash, not an empty / error string.
    assert_eq "${#light_hash}" "64" "[$label] light hash is 64 hex chars"

    # THE INTEROP INVARIANT — all four must be byte-identical.
    assert_eq "$determ_hash" "$light_hash"  "[$label] determ tx-hash == light hash"
    assert_eq "$wallet_hash" "$light_hash"  "[$label] wallet tx_hash_hex == light hash"
    assert_eq "$wallet_csb"  "$light_hash"  "[$label] wallet computed_signing_bytes_sha256 == light hash"
}

echo
echo "=== TRANSFER parity (to=B, amount=1000, fee=5, nonce=1) ==="
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount 1000 --fee 5 --nonce 1 \
    --out "$TMP/transfer.json" >/dev/null 2>&1
if [ -s "$TMP/transfer.json" ]; then
    parity_check "TRANSFER" "$TMP/transfer.json"
else
    echo "  FAIL: light sign-tx produced no TRANSFER envelope"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== TRANSFER parity, fee=0 (no-fee canonical path) ==="
# fee=0 omits no field but exercises the BE-zero fee leg; determ's
# from_json defaults a missing fee to 0, so this also confirms the
# explicit-zero and default-zero pre-images coincide.
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount 7 --fee 0 --nonce 9 \
    --out "$TMP/transfer0.json" >/dev/null 2>&1
if [ -s "$TMP/transfer0.json" ]; then
    parity_check "TRANSFER-fee0" "$TMP/transfer0.json"
else
    echo "  FAIL: light sign-tx produced no fee=0 TRANSFER envelope"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== STAKE parity (to empty, amount=1000, fee=0, nonce=2) ==="
# STAKE/UNSTAKE: light accepts an empty `to` (no semantic target). The
# resulting envelope has to="" — the canonical NUL-only `to` segment —
# which both determ from_json + wallet's reconstruction handle.
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type STAKE \
    --amount 1000 --fee 0 --nonce 2 \
    --out "$TMP/stake.json" >/dev/null 2>&1
if [ -s "$TMP/stake.json" ]; then
    parity_check "STAKE" "$TMP/stake.json"
else
    echo "  FAIL: light sign-tx produced no STAKE envelope"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== UNSTAKE parity (to empty, amount=500, fee=0, nonce=3) ==="
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type UNSTAKE \
    --amount 500 --fee 0 --nonce 3 \
    --out "$TMP/unstake.json" >/dev/null 2>&1
if [ -s "$TMP/unstake.json" ]; then
    parity_check "UNSTAKE" "$TMP/unstake.json"
else
    echo "  FAIL: light sign-tx produced no UNSTAKE envelope"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== Negative control: a hash divergence WOULD be caught ==="
# Tamper one byte of `amount` AFTER signing but leave the stored `hash`
# field intact. determ tx-hash recomputes from the (mutated) body, so it
# must DIVERGE from the stale stored hash — proving the assert_eq above is
# a live equality check, not a tautology that passes on any input.
if [ -s "$TMP/transfer.json" ]; then
    $PY - "$TMP/transfer.json" "$TMP/tampered.json" <<'PY_EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src))
stored = d["hash"]                 # keep stale stored hash
d["amount"] = int(d["amount"]) + 1 # mutate body -> recompute must differ
with open(dst, "wb") as f:
    f.write(json.dumps(d).encode("utf-8"))
with open(dst + ".storedhash", "wb") as f:
    f.write(stored.encode("utf-8"))
PY_EOF
    STORED=$(cat "$TMP/tampered.json.storedhash")
    set +e
    RECOMPUTED=$("$DETERM" tx-hash --in "$TMP/tampered.json" 2>/dev/null | tr -d '\r\n')
    set -e
    if [ -n "$RECOMPUTED" ] && [ "$RECOMPUTED" != "$STORED" ]; then
        echo "  PASS: mutated body recomputes to a DIFFERENT hash (equality check is live)"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: mutated body did not change recomputed hash (check is not live!)"
        fail_count=$((fail_count + 1))
    fi
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_cross_binary_tx_parity"
    exit 0
else
    echo "  FAIL: test_cross_binary_tx_parity"
    exit 1
fi
