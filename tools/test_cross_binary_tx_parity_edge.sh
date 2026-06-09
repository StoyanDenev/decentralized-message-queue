#!/usr/bin/env bash
# Cross-binary CANONICAL-FORMAT PARITY — EDGE-VALUE EXTENSION.
#
# Sibling of tools/test_cross_binary_tx_parity.sh. That test pins the
# three-way signing_bytes agreement (determ / determ-wallet / determ-light)
# but ONLY with small integer fields (amount=1000, fee=5, nonce=1). This
# test closes TWO gaps that the small-value test cannot reach:
#
# GAP 1 — HIGH-BYTE / u64-max VALUES
# ----------------------------------
# The canonical signing_bytes encodes amount/fee/nonce as u64 BIG-ENDIAN
# (src/chain/block.cpp:24-26):
#     for (int i = 7; i >= 0; --i) out.push_back((amount >> (i*8)) & 0xFF);
# A drift in that loop — a signed shift (`int` instead of `uint64_t`), a
# truncated high byte, a swapped byte, a >>1-off index — only changes
# OUTPUT bytes at positions i >= 4 (the high 4 bytes). Small operands
# (amount=1000 = 0x00000000000003E8) leave those high byte positions all
# zero, so a high-byte bug is INVISIBLE to the small-value test. This test
# drives operands that light up the high bytes:
#   * 2^64-1 = 18446744073709551615  — all eight bytes 0xFF
#   * 2^63   = 9223372036854775808   — ONLY the top bit set (catches a
#                                      signed arithmetic-shift bug: a
#                                      `int64_t >> 56` sign-extends, a
#                                      `uint64_t >> 56` does not)
#   * max-1  = 18446744073709551614  — used for fee (high-byte fee leg)
#   * max    = 18446744073709551615  — used for nonce (high-byte nonce leg)
#   * byte-walker 0x0101010101010101 = 72340172838076673 — every one of the
#                                      eight byte positions is distinctly
#                                      non-zero, so a dropped/swapped/dup'd
#                                      byte anywhere in the 8-byte field
#                                      changes the SHA-256.
#
# GAP 2 — THE SECOND (and THIRD) WALLET signing_bytes COPY
# --------------------------------------------------------
# The wallet re-implements the canonical layout inline in THREE separate
# places (deliberately un-DRY'd — see the in-source comments at each site,
# which all say "keep this copy in sync"):
#   (A) cmd_tx_sign_verify  wallet/main.cpp:8228  — exercised by the
#                                                   existing small-value test
#   (B) cmd_cold_sign       wallet/main.cpp:9550  — NOT exercised anywhere
#   (C) cmd_sign_anon_tx    wallet/main.cpp:10018 — its own third copy
# A high-byte drift in copy (B) or (C) alone would never be caught by the
# existing test (which only drives copy (A) via tx-sign-verify). This test
# drives ALL THREE wallet copies on high-byte operands and pins each to the
# canonical determ tx-hash.
#
#   * Copy (B) cmd_cold_sign: we hand it an UNSIGNED tx JSON carrying a
#     full-u64 amount and a plain {address,privkey_hex} keyfile (the same
#     shape account-create-batch emits — fully satisfiable OFFLINE, no
#     encrypted keyfile, no passphrase). cold-sign signs it and writes a
#     signed envelope whose `hash` field is copy-(B)'s
#     SHA-256(signing_bytes). We then run `determ tx-hash --in` on that
#     SAME envelope (canonical Transaction::compute_hash) AND
#     `tx-sign-verify` (copy (A)) and assert all three agree byte-for-byte,
#     AND that tx-sign-verify reports valid=true (so a sig produced by
#     copy-(B)'s signing_bytes verifies under copy-(A)'s reconstruction).
#     This transitively pins copy (B) to the canonical at full u64 range.
#
#   * Copy (C) cmd_sign_anon_tx: it BUILDS a TRANSFER from --to/--amount/
#     --fee/--nonce and signs, emitting an envelope with `type:"TRANSFER"`
#     (mnemonic) + `hash` = copy-(C)'s SHA-256(signing_bytes). Because its
#     `type` is the string mnemonic (not the numeric byte), `determ
#     tx-hash --in` won't parse it directly, so we cross-check copy (C) two
#     ways: (1) wallet `derive-tx-hash` (which accepts the mnemonic) must
#     reproduce the stored `hash`; (2) we build the byte-identical NUMERIC
#     envelope and run canonical `determ tx-hash --in` on it and assert it
#     equals copy-(C)'s stored hash. sign-anon-tx is TRANSFER-only and its
#     --amount/--fee/--nonce use a signed parse (stoll), so copy (C) is
#     exercised at the byte-walker tuple (within signed range); the
#     full-u64 high bytes for copy (C) are covered transitively because the
#     identical layout in copy (B) is pinned at 2^64-1.
#
# WHY light is dropped on the very-high tuples
# --------------------------------------------
# determ-light sign-tx parses --amount/--fee/--nonce with a SIGNED 64-bit
# parser, so it REJECTS any value > 2^63-1 (verified: it errors with
# "must be a non-negative integer" on 2^63 and 2^64-1). The task spec
# anticipates this ("If light rejects a value the chain would accept, work
# around it... still assert determ==wallet parity"). So:
#   * Tuples within light's signed range (byte-walker, large-but-signed):
#     FULL four-way parity via light sign-tx -> determ tx-hash ->
#     wallet tx-sign-verify (same invariant the existing test asserts).
#   * Tuples beyond light's range (2^64-1, 2^63, max-1, max): cold-sign
#     builds the envelope at full u64 and we assert
#     determ.tx-hash == cold-sign.hash == wallet.tx-sign-verify.tx_hash,
#     valid=true. The chain (determ) + wallet both accept full u64, so the
#     high-byte invariant is still pinned across the canonical + both
#     reachable wallet copies; only the (range-limited) light leg is
#     omitted for those operands.
#
# All paths used here are signing_bytes / tx_hash paths, which work on this
# Windows box. NONE of them touch compute_genesis_hash (the lone broken
# Windows path), so there is no genesis-dependent leg to SKIP.
#
# Run from repo root: bash tools/test_cross_binary_tx_parity_edge.sh
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
    echo "  SKIP: python not found (needed to read/build JSON fields)"
    exit 0
fi

TMP="build/test_cross_binary_tx_parity_edge.$$"
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
# "privkey_hex":"<64hex>"},...]}. One account object verbatim is BOTH a
# valid light keyfile (light/keyfile.cpp) AND a valid cold-sign /
# sign-anon-tx --priv-keyfile / --keyfile (the {address,privkey_hex}
# shape). The wallet tx-sign-verify --pubkey is the address with 0x
# stripped (anon address == 0x + the Ed25519 pubkey).
"$DETERM_WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
if [ ! -s "$TMP/keys.json" ]; then
    echo "  SKIP: account-create-batch produced no keys (wallet env issue)"
    exit 0
fi

$PY - "$TMP/keys.json" "$TMP" <<'PY_EOF'
import json, sys
keys_path, tmp = sys.argv[1], sys.argv[2]
d = json.load(open(keys_path))
a = d["accounts"][0]
b = d["accounts"][1]
# One account object verbatim = a valid light keyfile AND a valid
# cold-sign / sign-anon-tx keyfile.
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

# High-byte operand constants (all decimal so the binaries' integer
# parsers see exact values; no hex confusion across CLIs).
U64_MAX="18446744073709551615"        # 2^64-1, all bytes 0xFF
U64_MAX_M1="18446744073709551614"     # 2^64-2 (max-1)
TWO_POW_63="9223372036854775808"      # 2^63, only the top bit set
SIGNED_MAX="9223372036854775807"      # 2^63-1, largest light accepts
BYTE_WALKER="72340172838076673"       # 0x0101010101010101

# ── Helper: full FOUR-binary parity check for one LIGHT-signed envelope ──
# Identical invariant to the existing test's parity_check: light's stored
# `hash` == determ tx-hash == wallet tx_hash_hex ==
# wallet computed_signing_bytes_sha256, and wallet declares the light sig
# valid. Used ONLY for operands within light's signed range.
parity_check_light() {
    local label="$1" txjson="$2"

    local light_hash
    light_hash=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['hash'])" "$txjson")

    local determ_hash determ_rc
    set +e
    determ_hash=$("$DETERM" tx-hash --in "$txjson" 2>/dev/null | tr -d '\r\n')
    determ_rc=$?
    set -e
    assert_eq "$determ_rc" "0" "[$label] determ tx-hash exits 0"

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
    assert_eq "${#light_hash}" "64" "[$label] light hash is 64 hex chars"

    assert_eq "$determ_hash" "$light_hash"  "[$label] determ tx-hash == light hash"
    assert_eq "$wallet_hash" "$light_hash"  "[$label] wallet tx_hash_hex == light hash"
    assert_eq "$wallet_csb"  "$light_hash"  "[$label] wallet computed_signing_bytes_sha256 == light hash"
}

# ── Helper: COLD-SIGN parity for one full-u64 tuple (GAP 1 + GAP 2 copy B)
# Builds an UNSIGNED numeric-type tx JSON with the given amount/fee/nonce,
# drives cmd_cold_sign (wallet copy B) to sign it, then asserts the
# canonical determ tx-hash, cold-sign's own stored hash, and wallet
# tx-sign-verify (copy A) all agree byte-for-byte AND the sig verifies.
# Operands here may exceed light's signed range (that's the point); light
# is intentionally not in this leg.
# Args: <label> <amount> <fee> <nonce>
coldsign_parity() {
    local label="$1" amount="$2" fee="$3" nonce="$4"
    local unsigned="$TMP/unsigned_$label.json"
    local signed="$TMP/signed_$label.json"

    $PY - "$unsigned" "$ADDR_A" "$ADDR_B" "$amount" "$fee" "$nonce" <<'PY_EOF'
import json, sys
out, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
amount, fee, nonce = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
# type 0 = TRANSFER (numeric, the wire byte cold-sign + determ expect).
d = {"type": 0, "from": frm, "to": to,
     "amount": amount, "fee": fee, "nonce": nonce, "payload": ""}
with open(out, "wb") as f:
    f.write(json.dumps(d).encode("utf-8"))
PY_EOF

    # Copy (B): cold-sign produces a signed envelope; its `hash` field is
    # cmd_cold_sign's own SHA-256(signing_bytes).
    local cs_rc
    set +e
    "$DETERM_WALLET" cold-sign --tx-json "$unsigned" --priv-keyfile "$TMP/key_a.json" \
        --out "$signed" >/dev/null 2>&1
    cs_rc=$?
    set -e
    assert_eq "$cs_rc" "0" "[$label] wallet cold-sign exits 0"
    if [ ! -s "$signed" ]; then
        echo "  FAIL: [$label] cold-sign produced no signed envelope"
        fail_count=$((fail_count + 1))
        return
    fi

    local cold_hash
    cold_hash=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['hash'])" "$signed")
    assert_eq "${#cold_hash}" "64" "[$label] cold-sign hash is 64 hex chars"

    # Canonical: determ tx-hash recomputes from the (full-u64) body.
    local determ_hash determ_rc
    set +e
    determ_hash=$("$DETERM" tx-hash --in "$signed" 2>/dev/null | tr -d '\r\n')
    determ_rc=$?
    set -e
    assert_eq "$determ_rc" "0" "[$label] determ tx-hash exits 0 on cold-signed envelope"

    # Copy (A): tx-sign-verify reconstructs signing_bytes independently and
    # cryptographically verifies cold-sign's (copy B's) Ed25519 sig.
    local wallet_json wallet_hash wallet_csb wallet_valid
    set +e
    wallet_json=$("$DETERM_WALLET" tx-sign-verify --tx "$signed" --pubkey "$PUB_A" --json 2>/dev/null | tr -d '\r')
    set -e
    wallet_hash=$(echo "$wallet_json"  | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])")
    wallet_csb=$(echo "$wallet_json"   | $PY -c "import json,sys; print(json.load(sys.stdin)['computed_signing_bytes_sha256'])")
    wallet_valid=$(echo "$wallet_json" | $PY -c "import json,sys; print(json.load(sys.stdin)['valid'])")

    assert_eq "$wallet_valid" "True" "[$label] tx-sign-verify: cold-sign sig valid under copy-A signing_bytes"

    # THE INTEROP INVARIANT across the canonical + both reachable wallet
    # copies, at full u64 range.
    assert_eq "$determ_hash" "$cold_hash"   "[$label] determ tx-hash == cold-sign hash (canonical == copy B)"
    assert_eq "$wallet_hash" "$cold_hash"   "[$label] wallet tx_hash_hex == cold-sign hash (copy A == copy B)"
    assert_eq "$wallet_csb"  "$cold_hash"   "[$label] wallet computed_signing_bytes_sha256 == cold-sign hash"
}

# ─────────────────────────────────────────────────────────────────────────
# GAP 1 + full four-way parity, WITHIN light's signed range
# ─────────────────────────────────────────────────────────────────────────

echo
echo "=== byte-walker amount=0x0101010101010101, fee=0x01010101 nonce ==="
# The byte-walker amount makes all 8 amount bytes distinctly non-zero; the
# fee/nonce also use byte-walker-derived values so a swap across the three
# 8-byte fields would change the hash too. All within light's signed range.
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount "$BYTE_WALKER" --fee 16843009 --nonce 257 \
    --out "$TMP/walker.json" >/dev/null 2>&1
if [ -s "$TMP/walker.json" ]; then
    parity_check_light "BYTE-WALKER" "$TMP/walker.json"
else
    echo "  FAIL: light sign-tx produced no byte-walker envelope"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== large-but-signed amount=2^63-1, fee=2^62, nonce=2^61 ==="
# Populates the high byte positions (bytes 4..7 all non-zero) at the very
# top of light's signed-acceptable range — the highest operands the
# four-way light leg can reach. 2^62 = 4611686018427387904,
# 2^61 = 2305843009213693952.
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount "$SIGNED_MAX" --fee 4611686018427387904 --nonce 2305843009213693952 \
    --out "$TMP/signedmax.json" >/dev/null 2>&1
if [ -s "$TMP/signedmax.json" ]; then
    parity_check_light "SIGNED-MAX" "$TMP/signedmax.json"
else
    echo "  FAIL: light sign-tx produced no signed-max envelope"
    fail_count=$((fail_count + 1))
fi

# ─────────────────────────────────────────────────────────────────────────
# GAP 1 full-u64 high bytes + GAP 2 copy (B) cmd_cold_sign
# (operands beyond light's signed range; canonical + wallet only)
# ─────────────────────────────────────────────────────────────────────────

echo
echo "=== u64-MAX amount=2^64-1 (all bytes 0xFF), fee=5, nonce=1 ==="
coldsign_parity "U64MAX-AMT" "$U64_MAX" "5" "1"

echo
echo "=== TOP-BIT amount=2^63 (only top bit; catches signed-shift), fee=0, nonce=2 ==="
# amount=2^63 has ONLY byte 7's high bit set. A signed `int64_t >> 56`
# would sign-extend and corrupt every output byte; a correct `uint64_t`
# shift yields exactly 0x80,0x00,...,0x00. fee=0 is allowed by the chain
# here (only amount must be > 0 for a TRANSFER).
coldsign_parity "TOPBIT-AMT" "$TWO_POW_63" "0" "2"

echo
echo "=== HIGH-BYTE fee=2^64-2 (max-1) + nonce=2^64-1 (max), amount=1000 ==="
# Exercises the high bytes of the FEE and NONCE big-endian loops
# specifically (the existing test only ever had fee/nonce in {0,1,5,9}).
coldsign_parity "HIGH-FEE-NONCE" "1000" "$U64_MAX_M1" "$U64_MAX"

echo
echo "=== MIXED byte-walker amount + u64-max fee + 2^63 nonce ==="
# One tuple that simultaneously stresses a distinct-byte amount, an
# all-0xFF fee, and a top-bit-only nonce — a single swapped byte ANYWHERE
# across the 24-byte amount||fee||nonce region changes the hash.
coldsign_parity "MIXED" "$BYTE_WALKER" "$U64_MAX" "$TWO_POW_63"

# ─────────────────────────────────────────────────────────────────────────
# GAP 2 copy (C) cmd_sign_anon_tx — its own third inline signing_bytes copy
# ─────────────────────────────────────────────────────────────────────────

echo
echo "=== sign-anon-tx (copy C) byte-walker TRANSFER, cross-checked to canonical ==="
# sign-anon-tx BUILDS a TRANSFER from flags and signs with copy (C)'s
# inline signing_bytes (wallet/main.cpp:10018). It emits type:"TRANSFER"
# (mnemonic) + hash. TRANSFER-only + signed parse => exercise at the
# byte-walker tuple (within signed range, all amount bytes distinct).
ANON_AMT="$BYTE_WALKER"
ANON_FEE="16843009"      # 0x01010101 — byte-walker fee
ANON_NONCE="7"
"$DETERM_WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
    --amount "$ANON_AMT" --fee "$ANON_FEE" --nonce "$ANON_NONCE" \
    --out "$TMP/anon.json" >/dev/null 2>&1
if [ -s "$TMP/anon.json" ]; then
    ANON_HASH=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['hash'])" "$TMP/anon.json")
    assert_eq "${#ANON_HASH}" "64" "[ANON] sign-anon-tx hash is 64 hex chars"

    # Cross-check (1): wallet derive-tx-hash accepts the mnemonic envelope
    # and must reproduce copy (C)'s stored hash (a second wallet path over
    # the same envelope — same signing_bytes contract).
    DERIVE_RC=0
    set +e
    DERIVE_HASH=$("$DETERM_WALLET" derive-tx-hash --tx-json "$TMP/anon.json" 2>/dev/null | tr -d '\r\n')
    DERIVE_RC=$?
    set -e
    assert_eq "$DERIVE_RC" "0" "[ANON] wallet derive-tx-hash exits 0"
    assert_eq "$DERIVE_HASH" "$ANON_HASH" "[ANON] derive-tx-hash == sign-anon-tx hash"

    # Cross-check (2): build the BYTE-IDENTICAL numeric-type envelope (the
    # mnemonic "TRANSFER" == byte 0; from = keyfile address = A) and run
    # the CANONICAL determ tx-hash on it. Must equal copy (C)'s stored
    # hash, proving copy (C)'s signing_bytes layout matches the canonical.
    # determ from_json requires a `hash` field present (it recomputes from
    # the body and ignores the stored value), so we carry it through.
    $PY - "$TMP/anon_numeric.json" "$ADDR_A" "$ADDR_B" "$ANON_AMT" "$ANON_FEE" "$ANON_NONCE" "$ANON_HASH" <<'PY_EOF'
import json, sys
out, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
amount, fee, nonce = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
stored = sys.argv[7]
d = {"type": 0, "from": frm, "to": to,
     "amount": amount, "fee": fee, "nonce": nonce, "payload": "",
     "sig": "00" * 64, "hash": stored}
with open(out, "wb") as f:
    f.write(json.dumps(d).encode("utf-8"))
PY_EOF
    CANON_RC=0
    set +e
    CANON_HASH=$("$DETERM" tx-hash --in "$TMP/anon_numeric.json" 2>/dev/null | tr -d '\r\n')
    CANON_RC=$?
    set -e
    assert_eq "$CANON_RC" "0" "[ANON] determ tx-hash exits 0 on numeric-equivalent envelope"
    assert_eq "$CANON_HASH" "$ANON_HASH" "[ANON] determ tx-hash (canonical) == sign-anon-tx hash (copy C)"
else
    echo "  FAIL: sign-anon-tx produced no envelope"
    fail_count=$((fail_count + 1))
fi

# ─────────────────────────────────────────────────────────────────────────
# NEGATIVE CONTROL — flip a HIGH byte and confirm the hash diverges
# ─────────────────────────────────────────────────────────────────────────

echo
echo "=== Negative control: flipping a HIGH amount byte changes the hash ==="
# Take the cold-signed u64-MAX envelope, XOR bit 56 of amount (the high
# byte: amount ^= (1<<56)). The stored `hash` stays stale; determ tx-hash
# recomputes from the mutated body and MUST diverge. Flipping specifically
# a byte at position >= 4 proves the HIGH byte positions are actually bound
# into signing_bytes — if the BE loop dropped/zeroed the high byte, this
# mutation would be invisible and the hashes would (wrongly) still match.
if [ -s "$TMP/signed_U64MAX-AMT.json" ]; then
    $PY - "$TMP/signed_U64MAX-AMT.json" "$TMP/tampered.json" <<'PY_EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src))
stored = d["hash"]                          # keep the stale stored hash
amt = int(d["amount"])
amt ^= (1 << 56)                            # flip a HIGH byte (byte index 7)
d["amount"] = amt
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
        echo "  PASS: high-byte flip recomputes to a DIFFERENT hash (high bytes are bound; check is live)"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: high-byte flip did not change recomputed hash (high bytes NOT bound, or check dead!)"
        fail_count=$((fail_count + 1))
    fi
else
    echo "  FAIL: no u64-MAX cold-signed envelope to tamper for the negative control"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_cross_binary_tx_parity_edge"
    exit 0
else
    echo "  FAIL: test_cross_binary_tx_parity_edge"
    exit 1
fi
