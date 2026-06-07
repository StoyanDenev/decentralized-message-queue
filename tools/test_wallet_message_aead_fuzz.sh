#!/usr/bin/env bash
# determ-wallet encrypt-message / decrypt-message — OFFLINE round-trip +
# tamper PROPERTY FUZZ.
#
# This EXTENDS (does not duplicate) tools/test_wallet_message_aead.sh, which
# exercises a handful of fixed plaintexts with single hard-coded tamper
# positions. Here we drive a fixed-seed RNG over many random
# (plaintext, keypair-pair) combinations and assert the three AEAD
# properties that matter, using ONLY the known plaintext as the oracle —
# we never reimplement X25519 / HKDF / AES-256-GCM:
#
#   P1 (round-trip / correctness):
#       For each random plaintext P and fresh keypair pair (kA, kB),
#       decrypt-message(kB, pubA, encrypt-message(kA, pubB, P)) == P,
#       byte-for-byte (cmp -s). DH symmetry: the receiver side recovers it.
#
#   P2 (AEAD tamper-detection / integrity):
#       XOR-flipping ANY single byte of the wire ciphertext
#       (nonce ‖ ct ‖ tag) at a RANDOM offset must make decrypt FAIL —
#       nonzero exit AND status="error" reason="aead_tag_verify_failed".
#       The random offset roves over the whole blob across cases, so the
#       nonce region, the ciphertext body, and the 16-byte GCM tag all get
#       exercised over a run. XOR-flip guarantees the mutated byte really
#       changed (b ^ mask != b for mask != 0).
#
#   P3 (key confusion / authentication):
#       Decrypting a ciphertext addressed to (kA<->kB) with an UNRELATED
#       third keypair's pubkey must FAIL the same way — the derived AEAD
#       key differs, so the tag never verifies. Proves the peer pubkey
#       genuinely authenticates the channel.
#
# Fixed seed ⇒ deterministic plaintexts / offsets / case count across runs
# (the AEAD nonce is still fresh per encrypt inside the binary; that's the
# binary's CSPRNG, not ours, and P1 holds regardless).
#
# Fully OFFLINE: no daemon, no cluster, no network. Only the wallet binary
# + python (for byte-level JSON repack, deterministic RNG, and XOR tamper).
#
# Run from repo root: bash tools/test_wallet_message_aead_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "  SKIP: python not found (needed for deterministic RNG + byte tamper)"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ — same convention as the sibling wallet tests; dodges
# MSYS path-translation quirks when the native wallet binary opens files that
# python (a native Windows process) also writes.
SCRATCH="build/test_wallet_message_aead_fuzz.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
# Treat everything under SCRATCH as test-only secret material (keyfiles hold
# private seeds) and wipe it on every exit path.
trap 'rm -rf "$SCRATCH"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <condition-already-evaluated:0|nonzero-string-"true"> ... we use a
  # boolean-ish first arg: "1"/"0".
  if [ "$1" = "1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

NUM_CASES=24          # >= 20 random cases
SEED=20260607         # fixed seed ⇒ reproducible plaintexts + tamper offsets

# ── Helper: mint a fresh single-account keyfile in the {address,privkey_hex}
#    shape that encrypt/decrypt-message read for --priv-keyfile. Echoes the
#    bare pubkey (address minus the 0x prefix) on stdout. ─────────────────────
mint_keyfile() {
  # $1 = output keyfile path
  local batch="$1.batch.json"
  "$WALLET" account-create-batch --count 1 --out "$batch" >/dev/null 2>&1 || return 1
  "$PY" -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
print(a['address'][2:] if a['address'].startswith('0x') else a['address'])
" "$batch" "$1"
}

# ── Setup: a throwaway third keypair used by P3 (key-confusion). One is
#    enough; it's unrelated to every per-case pair. ──────────────────────────
echo "=== Setup: mint unrelated third keypair (for key-confusion property) ==="
PUBX=$(mint_keyfile "$TMP/kx.json")
if [ -n "$PUBX" ] && [ -f "$TMP/kx.json" ]; then
    echo "  PASS: third keypair minted (pubX=${PUBX:0:16}...)"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: could not mint third keypair"
    fail_count=$((fail_count + 1))
    echo; echo "=== Test summary ==="; echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL"; exit 1
fi

echo
echo "=== Property fuzz: $NUM_CASES random (plaintext, keypair-pair) cases (seed=$SEED) ==="

for i in $(seq 1 "$NUM_CASES"); do
    # --- Deterministic per-case plaintext: derive bytes from (SEED, i). The
    #     length varies 1..96 so we cover both sub-block and multi-block
    #     payloads, and we splice in NUL + high bytes so any C-string
    #     truncation bug surfaces in the round-trip. ---
    "$PY" -c "
import sys, random
seed, i = int(sys.argv[1]), int(sys.argv[2])
r = random.Random((seed << 8) ^ i)
n = r.randint(1, 96)
buf = bytes(r.randrange(256) for _ in range(n))
# Guarantee at least one NUL and one high byte are present in some cases.
if i % 3 == 0:
    buf = b'\x00' + buf + b'\xff'
open(sys.argv[3], 'wb').write(buf)
" "$SEED" "$i" "$TMP/p_$i.bin"

    PLEN=$(wc -c < "$TMP/p_$i.bin" | tr -d ' \r\n')

    # --- Fresh keypair pair for this case. ---
    PUBA=$(mint_keyfile "$TMP/ka_$i.json")
    PUBB=$(mint_keyfile "$TMP/kb_$i.json")
    if [ -z "$PUBA" ] || [ -z "$PUBB" ]; then
        echo "  FAIL: case $i keypair mint failed"; fail_count=$((fail_count + 1)); continue
    fi

    # --- Encrypt with sender kA -> recipient pubB. ---
    ENC_OUT=$("$WALLET" encrypt-message \
                --priv-keyfile "$TMP/ka_$i.json" \
                --peer-pubkey "$PUBB" \
                --in "$TMP/p_$i.bin" \
                --out "$TMP/c_$i.bin" 2>&1 | tr -d '\r')
    # Re-run to capture the true wallet exit code (the pipe above masks it).
    "$WALLET" encrypt-message \
        --priv-keyfile "$TMP/ka_$i.json" \
        --peer-pubkey "$PUBB" \
        --in "$TMP/p_$i.bin" \
        --out "$TMP/c_$i.bin" >/dev/null 2>&1
    ENC_RC=$?

    if [ "$ENC_RC" != "0" ] || [ ! -f "$TMP/c_$i.bin" ]; then
        echo "  FAIL: case $i encrypt failed (rc=$ENC_RC): $ENC_OUT"
        fail_count=$((fail_count + 1)); continue
    fi

    CLEN=$(wc -c < "$TMP/c_$i.bin" | tr -d ' \r\n')

    # ===== P1: round-trip recovers the exact plaintext (recipient side) =====
    DEC_OUT=$("$WALLET" decrypt-message \
                --priv-keyfile "$TMP/kb_$i.json" \
                --peer-pubkey "$PUBA" \
                --in "$TMP/c_$i.bin" \
                --out "$TMP/r_$i.bin" 2>&1 | tr -d '\r')
    "$WALLET" decrypt-message \
        --priv-keyfile "$TMP/kb_$i.json" \
        --peer-pubkey "$PUBA" \
        --in "$TMP/c_$i.bin" \
        --out "$TMP/r_$i.bin" >/dev/null 2>&1
    DEC_RC=$?

    if [ "$DEC_RC" = "0" ] && cmp -s "$TMP/p_$i.bin" "$TMP/r_$i.bin"; then
        assert 1 "case $i P1 round-trip: decrypt(encrypt(P))==P (plen=$PLEN, clen=$CLEN)"
    else
        echo "       case $i decrypt rc=$DEC_RC out=$DEC_OUT"
        assert 0 "case $i P1 round-trip: decrypt(encrypt(P))==P"
    fi

    # ===== P2: random-offset XOR tamper must be rejected (AEAD) =====
    # Pick a deterministic offset in [0, CLEN) and a nonzero XOR mask. Because
    # mask != 0, the byte provably changes. Offset roves the whole blob over
    # the run, so nonce / body / tag regions all get hit across cases.
    "$PY" -c "
import sys, random
seed, i, clen = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
r = random.Random((seed << 16) ^ (i << 1) ^ 0xA5)
off = r.randrange(clen)
mask = r.randint(1, 255)            # nonzero ⇒ guaranteed real mutation
data = bytearray(open(sys.argv[4], 'rb').read())
assert data[off] ^ mask != data[off]
data[off] ^= mask
open(sys.argv[5], 'wb').write(bytes(data))
print(off)
" "$SEED" "$i" "$CLEN" "$TMP/c_$i.bin" "$TMP/ct_$i.bin" > "$TMP/off_$i.txt"
    TOFF=$(tr -d ' \r\n' < "$TMP/off_$i.txt")

    TAMP_OUT=$("$WALLET" decrypt-message \
                 --priv-keyfile "$TMP/kb_$i.json" \
                 --peer-pubkey "$PUBA" \
                 --in "$TMP/ct_$i.bin" \
                 --out "$TMP/rt_$i.bin" 2>&1 | tr -d '\r')
    "$WALLET" decrypt-message \
        --priv-keyfile "$TMP/kb_$i.json" \
        --peer-pubkey "$PUBA" \
        --in "$TMP/ct_$i.bin" \
        --out "$TMP/rt_$i.bin" >/dev/null 2>&1
    TAMP_RC=$?

    if [ "$TAMP_RC" != "0" ] && echo "$TAMP_OUT" | grep -q "aead_tag_verify_failed"; then
        assert 1 "case $i P2 tamper@off=$TOFF rejected (rc=$TAMP_RC, aead_tag_verify_failed)"
    else
        echo "       case $i tamper rc=$TAMP_RC out=$TAMP_OUT"
        assert 0 "case $i P2 tampered ciphertext must be rejected with aead_tag_verify_failed"
    fi

    # ===== P3: wrong-peer (unrelated third key) must be rejected =====
    # Decrypt the UNTAMPERED ciphertext but claim the peer is kx (unrelated).
    # Derived AEAD key differs ⇒ tag fails. Authenticates the channel.
    WRONG_OUT=$("$WALLET" decrypt-message \
                  --priv-keyfile "$TMP/kb_$i.json" \
                  --peer-pubkey "$PUBX" \
                  --in "$TMP/c_$i.bin" \
                  --out "$TMP/rw_$i.bin" 2>&1 | tr -d '\r')
    "$WALLET" decrypt-message \
        --priv-keyfile "$TMP/kb_$i.json" \
        --peer-pubkey "$PUBX" \
        --in "$TMP/c_$i.bin" \
        --out "$TMP/rw_$i.bin" >/dev/null 2>&1
    WRONG_RC=$?

    if [ "$WRONG_RC" != "0" ] && echo "$WRONG_OUT" | grep -q "aead_tag_verify_failed"; then
        assert 1 "case $i P3 wrong-peer pubkey rejected (rc=$WRONG_RC, aead_tag_verify_failed)"
    else
        echo "       case $i wrong-peer rc=$WRONG_RC out=$WRONG_OUT"
        assert 0 "case $i P3 wrong-peer pubkey must be rejected with aead_tag_verify_failed"
    fi

    # Tidy per-case files so a long run doesn't accumulate megabytes of scratch.
    rm -f "$TMP/p_$i.bin" "$TMP/c_$i.bin" "$TMP/r_$i.bin" \
          "$TMP/ct_$i.bin" "$TMP/rt_$i.bin" "$TMP/rw_$i.bin" \
          "$TMP/off_$i.txt" \
          "$TMP/ka_$i.json" "$TMP/ka_$i.json.batch.json" \
          "$TMP/kb_$i.json" "$TMP/kb_$i.json.batch.json"
done

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet encrypt-message/decrypt-message round-trip + tamper fuzz ($NUM_CASES cases)"
    exit 0
else
    echo "  FAIL"
    exit 1
fi
