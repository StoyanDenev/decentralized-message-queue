#!/usr/bin/env bash
# determ-wallet BACKUP restore-path edge: SHARES-FILE y_hex tamper with an
# INTACT envelope, driven end-to-end through `keyfile-recover`.
#
# WHY THIS EDGE IS DISTINCT (non-duplication of existing backup coverage):
#
#   - test_wallet_backup_tamper_fuzz.sh byte-flips the *envelope* crypto
#     fields (salt/iters/nonce/ct/tag) and asserts the AEAD tag rejects via
#     standalone `envelope decrypt` + `backup-verify`. It NEVER tampers the
#     SHARES file, and never drives `keyfile-recover`.
#   - test_wallet_keyfile_recover.sh step 21 ("share/envelope mismatch")
#     swaps in WHOLE envelopes from a *second* backup of a different secret
#     (both files internally consistent). It does NOT flip a single byte of a
#     `y_hex` while keeping that share's MATCHING envelope intact.
#   - test_wallet_backup_verify.sh / test_wallet_backup_create.sh only assert
#     the clean-round-trip decrypted y_hex equals the shares y_hex; they never
#     mutate the shares file and re-run recovery.
#
# THE GAP: the shares file is plaintext and is NOT covered by the envelope
# AEAD tag (the tag authenticates only the encrypted y-bytes, not the separate
# `shares.json`). A silent same-length, still-valid-hex bit-flip of a share's
# `y_hex`:
#     * is STRUCTURALLY ACCEPTED by `backup-verify` (exit 0) — it never
#       decrypts, so it can't notice the value drifted; this documents that
#       structural verify alone is NOT a tamper oracle for the shares file.
#     * MUST be caught fail-closed by `keyfile-recover`, whose
#       decrypt-then-cross-check guard (wallet/main.cpp ~L5236-5245) compares
#       the AEAD-authenticated decrypted y-bytes against the shares `y_hex`
#       and rejects on mismatch with exit 2 + a "do NOT match" diagnostic,
#       BEFORE Shamir reconstruction can emit a corrupted secret.
#
# Fail-closed assertions on the reject path:
#     (1) exit code is exactly 2 (NOT 0, NOT a crash/garbage secret),
#     (2) the "do NOT match" diagnostic is emitted,
#     (3) NO secret material (neither the true secret nor any hex secret) is
#         leaked to stdout/stderr on the reject path,
#     (4) no --out file is produced.
# Plus a happy-path control: the UNtampered bundle recovers the exact secret.
#
# Fully OFFLINE: no node, daemon, cluster, or network. Temp under build/,
# cleaned on exit. Exit 0 = all pass, 1 = any fail.
#
# Run from repo root: bash tools/test_wallet_backup_shares_tamper_edge.sh
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
    echo "  SKIP: python not found (needed to flip one nibble of a y_hex)"
    exit 0
fi

W="$DETERM_WALLET"

# Scratch under build/ (mktemp -d yields /tmp/... which native-Windows Python
# inside the harness can't resolve — same convention as the sibling tests).
T="build/test_wallet_backup_shares_tamper_edge.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -qi -- "$2"; then echo "  FAIL: $3"; echo "       LEAKED substring: $2"; echo "       in:               $1"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

# A recognizable secret so a leak (or a garbage Shamir reconstruction emitted
# in error) is easy to spot.
SECRET="deadbeefcafebabe00112233445566778899aabbccddeeff"

echo "=== determ-wallet backup shares-file y_hex tamper (keyfile-recover restore path) ==="
echo

# ── Setup: a clean 2-of-3 backup ──────────────────────────────────────────────
echo "=== 0. Setup: backup-create 2-of-3 ==="
cat > "$T/kh.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"pw-1"},
  {"share_index":2,"passphrase":"pw-2"},
  {"share_index":3,"passphrase":"pw-3"}
]}
EOF
"$W" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$T/kh.json" \
    --shares-out "$T/sh.json" \
    --envelopes-out "$T/env.json" >/dev/null 2>&1
assert_eq "$?" "0" "backup-create exit 0 (setup precondition)"

# ── 1. Happy-path control: untampered bundle recovers the exact secret ─────────
echo
echo "=== 1. Happy-path control: clean bundle recovers exact secret ==="
"$W" keyfile-recover \
    --backup-shares "$T/sh.json" \
    --backup-envelopes "$T/env.json" \
    --keyholders "$T/kh.json" > "$T/clean_out.txt" 2>&1
RC=$?
CLEAN=$(tr -d '\r' < "$T/clean_out.txt")
assert_eq "$RC" "0" "clean keyfile-recover exit 0"
assert_eq "$CLEAN" "$SECRET" "clean recovery == original secret"

# ── 2. Tamper ONE nibble of share x=1's y_hex (same length, still valid hex) ──
echo
echo "=== 2. Flip one nibble of share x=1 y_hex (envelopes left intact) ==="
"$PY" - "$T/sh.json" "$T/sh_tamp.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
flipped = False
for s in d["shares"]:
    if s["x"] == 1:
        h = s["y_hex"]
        # Replace the first nibble with a DIFFERENT hex digit -> identical
        # length, still all-hex, so the value silently drifts by one nibble.
        new_first = '1' if h[0] != '1' else '2'
        s["y_hex"] = new_first + h[1:]
        flipped = True
assert flipped, "share x=1 not found"
json.dump(d, open(sys.argv[2], "w"))
PYEOF
if [ -s "$T/sh_tamp.json" ]; then
    echo "  PASS: tampered shares file produced"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: tampered shares file not produced"; fail_count=$((fail_count + 1))
fi

# ── 3. backup-verify STRUCTURALLY ACCEPTS the tamper (documents the boundary) ─
echo
echo "=== 3. backup-verify is structure-only: ACCEPTS the y_hex tamper (exit 0) ==="
# This is the dangerous gap the restore-path guard exists to close: structural
# verify cannot detect a same-length valid-hex value drift because it never
# decrypts. We assert exit 0 here to lock in that backup-verify is NOT a
# sufficient tamper oracle for the shares file on its own.
"$W" backup-verify --shares "$T/sh_tamp.json" --envelopes "$T/env.json" >/dev/null 2>&1
assert_eq "$?" "0" "backup-verify structurally accepts y_hex tamper (boundary documented)"

# ── 4. keyfile-recover MUST FAIL CLOSED on the tampered shares file ───────────
echo
echo "=== 4. keyfile-recover REJECTS the shares-file tamper (fail-closed) ==="
# Capture exit code WITHOUT a trailing pipe (a `| tr` would clobber $? with
# tr's exit status — that pitfall masks the real wallet rc).
"$W" keyfile-recover \
    --backup-shares "$T/sh_tamp.json" \
    --backup-envelopes "$T/env.json" \
    --keyholders "$T/kh.json" > "$T/tamp_out.txt" 2>&1
RC=$?
TAMP=$(tr -d '\r' < "$T/tamp_out.txt")
assert_eq "$RC" "2" "tampered shares -> exit 2 (fail-closed, not 0/garbage)"
assert_contains "$TAMP" "do NOT match" "emits 'do NOT match' tamper diagnostic"
assert_contains "$TAMP" "share_index=1" "diagnostic names the offending share_index"

# ── 5. NO secret leak on the reject path ──────────────────────────────────────
echo
echo "=== 5. Reject path leaks NO secret material ==="
# The true secret must never appear; nor may a (wrong) reconstructed secret be
# emitted -- the guard fires BEFORE shamir::combine, so no hex secret of the
# secret's length should surface at all.
assert_not_contains "$TAMP" "$SECRET" "true secret not leaked on reject path"
# No 'secret_hex' JSON field on the reject path (would imply a secret was emitted).
assert_not_contains "$TAMP" "secret_hex" "no secret_hex emitted on reject path"

# ── 6. No --out file produced on the reject path ──────────────────────────────
echo
echo "=== 6. --out not written when restore fails closed ==="
rm -f "$T/should_not_exist.json"
"$W" keyfile-recover \
    --backup-shares "$T/sh_tamp.json" \
    --backup-envelopes "$T/env.json" \
    --keyholders "$T/kh.json" \
    --out "$T/should_not_exist.json" > "$T/tamp_out2.txt" 2>&1
RC=$?
assert_eq "$RC" "2" "tampered shares + --out -> exit 2"
if [ ! -e "$T/should_not_exist.json" ]; then
    echo "  PASS: --out file not created on reject path"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file was created despite tamper rejection"; fail_count=$((fail_count + 1))
fi

# ── 7. Containment: the UNtampered bundle still recovers (tamper not sticky) ───
echo
echo "=== 7. Original (untampered) shares still recover the exact secret ==="
"$W" keyfile-recover \
    --backup-shares "$T/sh.json" \
    --backup-envelopes "$T/env.json" \
    --keyholders "$T/kh.json" > "$T/clean2_out.txt" 2>&1
RC=$?
CLEAN2=$(tr -d '\r' < "$T/clean2_out.txt")
assert_eq "$RC" "0" "untampered re-recovery exit 0"
assert_eq "$CLEAN2" "$SECRET" "untampered re-recovery == original secret"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ] && [ "$pass_count" -gt 0 ]; then
    echo "  PASS: determ-wallet backup shares-file y_hex tamper (restore fail-closed)"
    exit 0
else
    echo "  FAIL: determ-wallet backup shares-file y_hex tamper"
    exit 1
fi
