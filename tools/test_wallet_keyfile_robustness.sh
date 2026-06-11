#!/usr/bin/env bash
# determ-wallet KEYFILE-LOADER adversarial FAIL-CLOSED robustness test.
#
# Analogue of the determ-light persist-robustness test, but for the
# determ-wallet keyfile loaders. The contract under test is the
# FAIL-CLOSED property of every keyfile-consuming offline subcommand:
#
#     A malformed / tampered / truncated keyfile must FAIL CLOSED:
#       (1) non-zero exit code,
#       (2) a BOUNDED small exit code (NOT a crash / signal / abort —
#           0 < rc < 126; native faults surface as >=128 in bash or as a
#           huge Windows NTSTATUS like 3221225477),
#       (3) NO output that looks like a successfully-loaded key, and
#       (4) NO --out plaintext file left behind.
#
#  The valid-shape control (case 8) must LOAD (exit 0, key echoed) so the
#  suite provably DISCRIMINATES rather than rubber-stamping "everything
#  exits non-zero".
#
# ── Loaders driven (both OFFLINE, no daemon) ─────────────────────────────────
#  * PLAINTEXT loader  — `account-export --in <file>`
#       Consumes the canonical single-account JSON shape
#       { "address": "0x"+64hex, "privkey_hex": 64hex }
#       (wallet/main.cpp cmd_account_export, dispatch ~2320; the JSON parse
#       + is_object + required-field + length + from_hex guards live at
#       wallet/main.cpp:2373-2433). Requires NO passphrase and NO daemon —
#       the cleanest non-interactive keyfile loader in the binary. On ANY
#       malformed input it returns process-level exit 1 (verified).
#  * ENCRYPTED loader  — `keyfile-decrypt --in <file> --passphrase-from env:NAME`
#       Consumes the 2-line DETERM-NODE-V1 + DWE1-envelope encrypted node
#       keyfile (wallet/main.cpp cmd_keyfile_decrypt, dispatch ~3723).
#       Driven NON-INTERACTIVELY via the documented `env:` passphrase
#       source so the harness never blocks on a prompt. Used ONLY for the
#       envelope-length-tamper case (case 7), where the structural-only
#       `keyfile-info` parser canNOT discriminate (it reports the mutated
#       length verbatim without decrypting — confirmed empirically), so the
#       cryptographic loader is the one that actually fails closed.
#
# ── Why this suite is NEW (not a duplicate) ──────────────────────────────────
#  The existing wallet keyfile tests are FUNCTIONAL / happy-path or cover a
#  DIFFERENT malformed surface:
#    - test_wallet_keyfile_info.sh / _decrypt.sh: tampered header magic,
#      truncated/non-hex header pubkey, garbage envelope blob, missing blob
#      line, empty/missing file. They do NOT feed a JSON-ARRAY-not-object,
#      do NOT exercise the privkey off-by-one boundary (63 / 65 chars), and
#      craft fixtures with printf/text-mode python (LF->CRLF on Windows),
#      not byte-exact 'wb'.
#    - test_wallet_account_export.sh: feeds garbage JSON ("not-json{{{"),
#      missing fields, a 6-char privkey, and a no-0x address — but never an
#      EMPTY file, never a JSON ARRAY, and never the 63/65 boundary.
#    - test_wallet_account_export_hex_validity_edge.sh: non-hex content at
#      even/odd positions only (the from_hex catch), never length boundaries.
#    - test_wallet_keyfile_lifecycle_fuzz.sh: SAME-LENGTH XOR-flip of the
#      ciphertext / salt fields (exercises the AEAD tag). This suite instead
#      mutates field LENGTHS (short ciphertext, wrong-length salt, wrong-
#      length nonce), exercising the DWE1 deserializer's length handling +
#      the KDF — a distinct code path.
#  None of them assert the BOUNDED-exit ("not a crash") property explicitly,
#  and none consolidate the fail-closed triple across both loaders with
#  byte-exact ('wb') fixtures. That gap is what this file closes.
#
# ── Cases (each malformed case asserts the fail-closed triple) ───────────────
#   1. truncated JSON (object cut off before '}')        [plaintext loader]
#   2. JSON array, not object                            [plaintext loader]
#   3a. privkey_hex 63 chars (off-by-one short)          [plaintext loader]
#   3b. privkey_hex 65 chars (off-by-one long)           [plaintext loader]
#   4. privkey_hex with a non-hex char (right length)    [plaintext loader]
#   5a. missing required field 'address'                 [plaintext loader]
#   5b. missing required field 'privkey_hex'             [plaintext loader]
#   6. empty (0-byte) file                               [plaintext loader]
#   7a. encrypted: SHORT ciphertext (truncated tag)      [encrypted loader]
#   7b. encrypted: wrong-length salt                     [encrypted loader]
#   7c. encrypted: wrong-length nonce                    [encrypted loader]
#   8. valid-shape control that LOADS (exit 0)           [both loaders]
#
# All malformed fixtures are written byte-exact with python's open(...,'wb')
# (Windows text mode would translate LF->CRLF and perturb the bytes).
#
# Run from repo root: bash tools/test_wallet_keyfile_robustness.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

PY=python
if ! command -v python >/dev/null 2>&1; then
    if command -v python3 >/dev/null 2>&1; then
        PY=python3
    else
        echo "  SKIP: python not found (needed for byte-exact 'wb' fixtures)"
        exit 0
    fi
fi

# Scratch under build/ to dodge MSYS path translation: the native Windows
# determ-wallet.exe cannot open MSYS /tmp/... paths produced by mktemp -d
# (it would silently fail to read/write). Every sibling wallet test uses the
# same build/-relative convention.
SCRATCH="build/test_wallet_keyfile_robustness.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# ── The fail-closed triple, applied to one malformed loader invocation ───────
# fail_closed <label> <rc> <combined-stdout+stderr> <out-file-that-must-not-exist>
# Asserts:
#   (1) rc != 0
#   (2) 0 < rc < 126   (bounded: not a signal/abort/native fault)
#   (3) the output does NOT contain a 64-hex run that equals the secret seed
#       and does NOT contain a plaintext node_key field — i.e. no loaded key
#   (4) the --out plaintext file was NOT created
# SECRET is the 64-hex seed the malformed fixtures are (intentionally) built
# around; if it ever leaks to stdout the loader silently accepted a bad key.
SECRET_SEED=""
fail_closed() {
    local label="$1" rc="$2" out="$3" leak_file="$4"
    # (1) non-zero
    if [ "$rc" != "0" ]; then
        echo "  PASS: [$label] exit non-zero ($rc)"; pass_count=$((pass_count + 1))
    else
        echo "  FAIL: [$label] expected non-zero exit, got 0 (silent accept!)"
        fail_count=$((fail_count + 1))
    fi
    # (2) bounded — not a crash. Signals show as 128+N in bash; Windows native
    #     faults show as huge NTSTATUS (e.g. 3221225477). Anything >=126 is a
    #     crash, not a clean rejection.
    if [ "$rc" -gt 0 ] 2>/dev/null && [ "$rc" -lt 126 ] 2>/dev/null; then
        echo "  PASS: [$label] exit code is bounded/small ($rc < 126; no crash)"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: [$label] exit code $rc looks like a crash/signal (>=126)"
        fail_count=$((fail_count + 1))
    fi
    # (3) no successfully-loaded key in the output
    local leaked=0
    if [ -n "$SECRET_SEED" ] && echo "$out" | grep -q -- "$SECRET_SEED"; then
        leaked=1
    fi
    # node_key.json plaintext markers: a loaded key would surface priv_seed /
    # a bare 64-hex privkey echo. A rejection diagnostic must carry none.
    if echo "$out" | grep -Eq '"priv_seed"|^[0-9a-f]{64}$'; then
        leaked=1
    fi
    if [ "$leaked" = "0" ]; then
        echo "  PASS: [$label] output reveals no successfully-loaded key"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: [$label] output leaked key material:"
        echo "        $out"
        fail_count=$((fail_count + 1))
    fi
    # (4) no --out plaintext file left behind
    if [ -z "$leak_file" ] || [ ! -e "$leak_file" ]; then
        echo "  PASS: [$label] no plaintext --out file created"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: [$label] plaintext --out file unexpectedly present: $leak_file"
        fail_count=$((fail_count + 1))
    fi
}

# Run the plaintext loader on a fixture, capture rc + combined output.
# NOTE: we deliberately do NOT pipe the wallet into `tr` — `RC=$?` after a
# `cmd | tr` pipeline is tr's exit (always 0), and `${PIPESTATUS[0]}` is
# unreliable across a command-substitution assignment (it reflects the
# assignment, not the inner pipeline). Capturing to a file with a bare
# redirect gives the wallet's TRUE exit code, which is the whole point of a
# fail-closed test. CR is stripped afterwards from the captured string.
run_plain() {  # run_plain <infile>  -> sets RC + OUT
    set +e
    "$WALLET" account-export --in "$1" > "$TMP/_run.out" 2>&1
    RC=$?
    set -e
    OUT=$(tr -d '\r' < "$TMP/_run.out")
}

echo "=== 0. Fixtures: a fresh keypair (the seed our fixtures are built on) ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-create-batch produced a keypair"
SECRET_SEED=$($PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['address'])" <<< "$KEYPAIR")
assert_eq "${#SECRET_SEED}" "64" "fixture seed is 64 hex chars"
assert_eq "${#ADDR}" "66" "fixture address is 0x + 64 hex (66 chars)"

# ── 1. Truncated JSON ────────────────────────────────────────────────────────
echo
echo "=== 1. Truncated JSON object (cut off before closing brace) ==="
$PY - "$TMP/c1.json" "$ADDR" "$SECRET_SEED" <<'PY'
import sys
p, addr, seed = sys.argv[1], sys.argv[2], sys.argv[3]
# A valid prefix that is abruptly truncated mid-object: no closing '}'.
blob = ('{"address":"%s","privkey_hex":"%s"' % (addr, seed)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c1.json"
fail_closed "truncated-json" "$RC" "$OUT" ""

# ── 2. JSON array, not object ────────────────────────────────────────────────
echo
echo "=== 2. JSON array (top-level), not the required object ==="
$PY - "$TMP/c2.json" "$ADDR" "$SECRET_SEED" <<'PY'
import sys
p, addr, seed = sys.argv[1], sys.argv[2], sys.argv[3]
# Well-formed JSON, but an ARRAY — the loader requires a top-level object.
blob = ('[{"address":"%s","privkey_hex":"%s"}]' % (addr, seed)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c2.json"
fail_closed "json-array-not-object" "$RC" "$OUT" ""

# ── 3a. privkey_hex 63 chars (off-by-one short) ──────────────────────────────
echo
echo "=== 3a. privkey_hex 63 chars (one short of 64) ==="
$PY - "$TMP/c3a.json" "$ADDR" <<'PY'
import sys
p, addr = sys.argv[1], sys.argv[2]
priv = "a" * 63  # 63 hex chars: valid hex, wrong length
blob = ('{"address":"%s","privkey_hex":"%s"}' % (addr, priv)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c3a.json"
fail_closed "privkey-63-chars" "$RC" "$OUT" ""

# ── 3b. privkey_hex 65 chars (off-by-one long) ───────────────────────────────
echo
echo "=== 3b. privkey_hex 65 chars (one over 64) ==="
$PY - "$TMP/c3b.json" "$ADDR" <<'PY'
import sys
p, addr = sys.argv[1], sys.argv[2]
priv = "a" * 65  # 65 hex chars: valid hex, wrong length
blob = ('{"address":"%s","privkey_hex":"%s"}' % (addr, priv)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c3b.json"
fail_closed "privkey-65-chars" "$RC" "$OUT" ""

# ── 4. privkey_hex non-hex char (right length, wrong content) ────────────────
echo
echo "=== 4. privkey_hex right length but a non-hex char at an even pair pos ==="
$PY - "$TMP/c4.json" "$ADDR" <<'PY'
import sys
p, addr = sys.argv[1], sys.argv[2]
# 'z' at index 0 starts the first 2-char pair "za" which fails std::hex parse
# (from_hex throws). Length is exactly 64 so it passes the length guard first.
priv = "z" + ("a" * 63)
assert len(priv) == 64
blob = ('{"address":"%s","privkey_hex":"%s"}' % (addr, priv)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c4.json"
fail_closed "privkey-non-hex" "$RC" "$OUT" ""

# ── 5a. missing 'address' ────────────────────────────────────────────────────
echo
echo "=== 5a. missing required field 'address' ==="
$PY - "$TMP/c5a.json" "$SECRET_SEED" <<'PY'
import sys
p, seed = sys.argv[1], sys.argv[2]
blob = ('{"privkey_hex":"%s"}' % seed).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c5a.json"
fail_closed "missing-address" "$RC" "$OUT" ""

# ── 5b. missing 'privkey_hex' ────────────────────────────────────────────────
echo
echo "=== 5b. missing required field 'privkey_hex' ==="
$PY - "$TMP/c5b.json" "$ADDR" <<'PY'
import sys
p, addr = sys.argv[1], sys.argv[2]
blob = ('{"address":"%s"}' % addr).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
run_plain "$TMP/c5b.json"
fail_closed "missing-privkey" "$RC" "$OUT" ""

# ── 6. empty (0-byte) file ───────────────────────────────────────────────────
echo
echo "=== 6. empty (0-byte) file ==="
$PY - "$TMP/c6.json" <<'PY'
import sys
with open(sys.argv[1], "wb") as f:
    pass  # zero bytes, byte-exact
PY
# Sanity: confirm the fixture really is 0 bytes.
SZ=$(wc -c < "$TMP/c6.json" | tr -d ' \r')
assert_eq "$SZ" "0" "empty-file fixture is exactly 0 bytes"
run_plain "$TMP/c6.json"
fail_closed "empty-file" "$RC" "$OUT" ""

# ── 7. ENCRYPTED loader: envelope-length tampers must fail closed ────────────
# Built around a REAL valid keyfile so the header/AAD are correct; only the
# envelope field LENGTHS are mutated. Driven via keyfile-decrypt with a fixed
# passphrase sourced from an env var (NON-INTERACTIVE, documented path).
echo
echo "=== 7. Encrypted loader (keyfile-decrypt env: passphrase) length tampers ==="
export KFROB_PW="robustness-fixed-passphrase"
ENC_SRC="$TMP/node_key.enc"
"$WALLET" keyfile-create --priv "$SECRET_SEED" \
    --passphrase-from "env:KFROB_PW" --out "$ENC_SRC" >/dev/null 2>&1
ENC_RC=$?
if [ "$ENC_RC" != "0" ] || [ ! -s "$ENC_SRC" ]; then
    echo "  SKIP: keyfile-create did not produce an encrypted fixture (rc=$ENC_RC);"
    echo "        skipping the encrypted-loader length-tamper cases."
else
    echo "  PASS: encrypted fixture built (keyfile-create rc=0)"
    pass_count=$((pass_count + 1))

    # Helper: build a length-mutated copy by trimming N trailing hex chars off
    # a chosen dot-separated envelope field (field indices: 1=magic 2=salt
    # 3=iters 4=nonce 5=aad 6=ciphertext), then drive keyfile-decrypt on it.
    # Writes the tampered keyfile byte-exact ('wb', no CRLF translation).
    enc_tamper_run() {  # <label> <field-index> <trim-hex-chars> <outvar-leakfile>
        local label="$1" field="$2" trim="$3" leak="$4"
        local tfile="$TMP/enc_${label}.enc"
        $PY - "$ENC_SRC" "$tfile" "$field" "$trim" <<'PY'
import sys
src, dst, field, trim = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(src, "rb") as f:
    raw = f.read()
# 2-line file: header \n blob [\n]. Split on the FIRST newline only so the
# header bytes are preserved verbatim; normalize CR off the blob line.
nl = raw.find(b"\n")
header = raw[:nl]
blob = raw[nl+1:].replace(b"\r", b"").replace(b"\n", b"")
fields = blob.split(b".")
assert field-1 < len(fields), "field index out of range"
fields[field-1] = fields[field-1][:-trim] if trim < len(fields[field-1]) else b""
new_blob = b".".join(fields)
with open(dst, "wb") as f:
    f.write(header + b"\n" + new_blob + b"\n")
PY
        rm -f "$leak"
        set +e
        local out rc
        # Bare redirect (no `| tr`) so $? is the wallet's true exit code.
        "$WALLET" keyfile-decrypt --in "$tfile" \
            --passphrase-from "env:KFROB_PW" --out "$leak" > "$TMP/_enc.out" 2>&1
        rc=$?
        set -e
        out=$(tr -d '\r' < "$TMP/_enc.out")
        fail_closed "$label" "$rc" "$out" "$leak"
    }

    # 7a. SHORT ciphertext: trim 4 hex (2 bytes) off the ciphertext+tag field.
    #     AEAD tag no longer validates -> exit 2, no plaintext.
    enc_tamper_run "enc-short-ciphertext" 6 4 "$TMP/leak_7a.json"
    # 7b. WRONG-LENGTH salt: trim 2 hex (1 byte) off the salt -> KDF derives a
    #     different key -> AEAD fails -> exit 2, no plaintext.
    enc_tamper_run "enc-wrong-len-salt" 2 2 "$TMP/leak_7b.json"
    # 7c. WRONG-LENGTH nonce: trim 2 hex off the fixed-width nonce -> DWE1
    #     deserializer rejects -> exit 1, no plaintext.
    enc_tamper_run "enc-wrong-len-nonce" 4 2 "$TMP/leak_7c.json"
fi
unset KFROB_PW 2>/dev/null || true

# ── 8. Valid-shape CONTROL — proves the suite discriminates ──────────────────
echo
echo "=== 8. Valid control: well-shaped keyfile LOADS (exit 0, key echoed) ==="
$PY - "$TMP/c8.json" "$ADDR" "$SECRET_SEED" <<'PY'
import sys
p, addr, seed = sys.argv[1], sys.argv[2], sys.argv[3]
blob = ('{"address":"%s","privkey_hex":"%s"}' % (addr, seed)).encode()
with open(p, "wb") as f:
    f.write(blob)
PY
set +e
"$WALLET" account-export --in "$TMP/c8.json" > "$TMP/_ctrl.out" 2>&1
CTRL_RC=$?
set -e
CTRL_OUT=$(tr -d '\r\n' < "$TMP/_ctrl.out")
assert_eq "$CTRL_RC" "0" "valid control loads (exit 0)"
assert_eq "$CTRL_OUT" "$SECRET_SEED" "valid control echoes EXACTLY the seed (loader actually reads the key)"

# Encrypted control: the untampered fixture from step 7 must decrypt cleanly.
if [ -s "$ENC_SRC" ]; then
    export KFROB_PW="robustness-fixed-passphrase"
    CTRL_DEC="$TMP/c8_dec.json"
    rm -f "$CTRL_DEC"
    "$WALLET" keyfile-decrypt --in "$ENC_SRC" \
        --passphrase-from "env:KFROB_PW" --out "$CTRL_DEC" >/dev/null 2>&1
    CTRL_DEC_RC=$?
    assert_eq "$CTRL_DEC_RC" "0" "valid encrypted control decrypts (exit 0)"
    if [ -s "$CTRL_DEC" ]; then
        DEC_SEED=$($PY -c "import json;print(json.load(open('$CTRL_DEC'))['priv_seed'])" 2>/dev/null)
        assert_eq "$DEC_SEED" "$SECRET_SEED" "encrypted control recovers EXACTLY the seed"
    else
        echo "  FAIL: encrypted control produced no plaintext --out"
        fail_count=$((fail_count + 1))
    fi
    unset KFROB_PW 2>/dev/null || true
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-loader fail-closed robustness"
    exit 0
else
    echo "  FAIL: test_wallet_keyfile_robustness"
    exit 1
fi
