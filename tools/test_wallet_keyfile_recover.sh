#!/usr/bin/env bash
# determ-wallet keyfile-recover high-level recovery CLI test.
#
# `keyfile-recover` is the operator inverse of `backup-create`. It composes
# `envelope::decrypt` + `shamir::combine` into a single call: given the
# canonical pair of backup artifacts (shares + envelopes file produced by
# backup-create) and a JSON file listing a T-of-N subset of keyholder
# passphrases, it recovers the original secret.
#
# Round-trip coverage:
#   - Generate a backup with backup-create (T=3, N=5).
#   - Recover via keyfile-recover with a T-of-N subset → verify secret == original.
#   - Run two DIFFERENT T-subsets from the same backup → both must reconstruct
#     identical secret (Shamir any-T-of-N property).
#   - --out path writes JSON {"secret_hex": "..."}.
#   - --json on stdout same JSON shape.
#   - --threshold T enforces minimum keyholder count.
#
# Validation coverage:
#   - Missing required flags → exit 1.
#   - Malformed inputs (bad JSON, missing fields, wrong shape) → exit 2.
#   - Wrong passphrase → exit 2 with "wrong passphrase or corrupted envelope".
#   - Insufficient shares (< T with --threshold supplied) → exit 2.
#   - Missing share_index in keyholders → exit 2.
#   - Duplicate share_index in keyholders → exit 2.
#   - Empty passphrase → exit 2.
#   - share/envelopes mismatch (cross-verification fails) → exit 2.
#   - --out exists without --force → exit 1.
#   - --out exists with --force → exit 0.
#   - Output parent directory missing → exit 1.
#
# Run from repo root: bash tools/test_wallet_keyfile_recover.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
# Absolutize the wallet binary path so Python subprocess.run() under
# native-Windows Python sees a path it can CreateProcess on (msys path
# translation only applies to direct shell args).
if [ "${WALLET#/}" = "$WALLET" ] && [ "${WALLET#?:}" = "$WALLET" ]; then
    WALLET_ABS="$PROJECT_ROOT/$WALLET"
else
    WALLET_ABS="$WALLET"
fi

# Scratch under build/ for the same path-translation reason as the other
# wallet tests (mktemp -d returns /tmp/... which Python can't see).
SCRATCH="build/test_wallet_keyfile_recover.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

SECRET="deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"

# ── 1. Help text mentions keyfile-recover ─────────────────────────────────────
echo "=== 1. Help text mentions keyfile-recover ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "keyfile-recover"; then
    echo "  PASS: help mentions keyfile-recover"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing keyfile-recover"; fail_count=$((fail_count + 1))
fi

# ── 2. Set up a fresh 3-of-5 backup ───────────────────────────────────────────
echo
echo "=== 2. Setup: backup-create 3-of-5 backup with 5 distinct passphrases ==="
$PY - "$TMP/kh_full.json" <<'PY_EOF'
import json, sys
out = sys.argv[1]
khs = [{"share_index": i, "passphrase": f"keyholder-pw-{i}"} for i in range(1, 6)]
with open(out, "w") as f:
    json.dump({"keyholders": khs}, f)
PY_EOF
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/kh_full.json" \
    --shares-out "$TMP/shares.json" \
    --envelopes-out "$TMP/envelopes.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "backup-create exit 0 (setup precondition)"

# ── 3. Happy path: T-of-N recovery with {1,3,5} subset ────────────────────────
echo
echo "=== 3. Happy path: recover with T-of-N subset {1,3,5} ==="
cat > "$TMP/kh_sub_135.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
RECOVERED=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-recover exit 0 with {1,3,5}"
assert_eq "$RECOVERED" "$SECRET" "recovered secret == original ({1,3,5})"

# ── 4. Different T-subset {2,4,5} → same secret ───────────────────────────────
echo
echo "=== 4. Different T-subset {2,4,5} reconstructs same secret ==="
cat > "$TMP/kh_sub_245.json" <<'EOF'
{"keyholders":[
  {"share_index":2,"passphrase":"keyholder-pw-2"},
  {"share_index":4,"passphrase":"keyholder-pw-4"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
RECOVERED2=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_245.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-recover exit 0 with {2,4,5}"
assert_eq "$RECOVERED2" "$SECRET" "recovered secret == original ({2,4,5})"

# ── 5. Another T-subset {1,2,3} → same secret ─────────────────────────────────
echo
echo "=== 5. Another T-subset {1,2,3} reconstructs same secret ==="
cat > "$TMP/kh_sub_123.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":2,"passphrase":"keyholder-pw-2"},
  {"share_index":3,"passphrase":"keyholder-pw-3"}
]}
EOF
RECOVERED3=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_123.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-recover exit 0 with {1,2,3}"
assert_eq "$RECOVERED3" "$SECRET" "recovered secret == original ({1,2,3})"

# Cross-check all three subsets agree.
if [ "$RECOVERED" = "$RECOVERED2" ] && [ "$RECOVERED2" = "$RECOVERED3" ]; then
    echo "  PASS: all 3 T-subsets reconstruct identical secret"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: T-subsets reconstructed different secrets"; fail_count=$((fail_count + 1))
fi

# ── 6. All-N keyholders also recover ──────────────────────────────────────────
echo
echo "=== 6. Full N=5 keyholders set also reconstructs ==="
RECOVERED_N=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_full.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-recover exit 0 with full N=5"
assert_eq "$RECOVERED_N" "$SECRET" "recovered secret == original (full N)"

# ── 7. --json on stdout ───────────────────────────────────────────────────────
echo
echo "=== 7. --json on stdout produces {\"secret_hex\":\"...\"} ==="
JSON_OUT=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_OUT''')
assert "secret_hex" in d, "missing secret_hex field"
assert d["secret_hex"] == "$SECRET", f"secret mismatch: {d['secret_hex']!r}"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema and value correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema or value wrong"; fail_count=$((fail_count + 1))
fi

# ── 8. --out writes JSON file ─────────────────────────────────────────────────
echo
echo "=== 8. --out writes {\"secret_hex\":\"...\"} JSON file ==="
"$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --out "$TMP/recovered.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--out exit 0"
if [ -s "$TMP/recovered.json" ]; then
    echo "  PASS: --out file non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file missing or empty"; fail_count=$((fail_count + 1))
fi
$PY - "$TMP/recovered.json" <<PY_EOF
import json, sys
d = json.load(open(sys.argv[1]))
assert "secret_hex" in d, "missing secret_hex"
assert d["secret_hex"] == "$SECRET", f"secret mismatch: {d['secret_hex']!r}"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --out file contains correct secret_hex"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file contents wrong"; fail_count=$((fail_count + 1))
fi

# ── 9. Wrong passphrase → exit 2 ──────────────────────────────────────────────
echo
echo "=== 9. Wrong passphrase exits 2 ==="
cat > "$TMP/kh_wrong.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"WRONG-PASSPHRASE"},
  {"share_index":3,"passphrase":"keyholder-pw-3"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_wrong.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "wrong passphrase exit 2"
assert_contains "$ERR" "wrong passphrase or corrupted envelope" \
    "wrong-passphrase diagnostic"

# ── 10. Insufficient shares with --threshold supplied → exit 2 ────────────────
echo
echo "=== 10. Insufficient shares (1 < T=3) with --threshold exits 2 ==="
cat > "$TMP/kh_one.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"}
]}
EOF
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_one.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "insufficient shares (1 < 3) exit 2"
assert_contains "$ERR" "insufficient shares" "insufficient-shares diagnostic"

# ── 11. Subset of T=3 satisfies --threshold ───────────────────────────────────
echo
echo "=== 11. --threshold 3 with exactly T=3 keyholders passes ==="
"$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exactly T satisfies --threshold"

# ── 12. Missing share_index in keyholders (no matching share) → exit 2 ────────
echo
echo "=== 12. share_index 99 (not in backup) rejected ==="
cat > "$TMP/kh_bad_idx.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"},
  {"share_index":99,"passphrase":"keyholder-pw-99"}
]}
EOF
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_bad_idx.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "missing share_index exit 2"
assert_contains "$ERR" "no matching" "missing-share diagnostic"

# ── 13. Duplicate share_index in keyholders → exit 2 ──────────────────────────
echo
echo "=== 13. Duplicate share_index in keyholders rejected ==="
cat > "$TMP/kh_dup.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"}
]}
EOF
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_dup.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "duplicate share_index exit 2"
assert_contains "$ERR" "duplicate" "duplicate diagnostic"

# ── 14. Empty passphrase → exit 2 ─────────────────────────────────────────────
echo
echo "=== 14. Empty passphrase rejected ==="
cat > "$TMP/kh_empty_pw.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":""},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_empty_pw.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "empty passphrase exit 2"
assert_contains "$ERR" "passphrase is empty" "empty-passphrase diagnostic"

# ── 15. Empty keyholders array → exit 2 ───────────────────────────────────────
echo
echo "=== 15. Empty keyholders array rejected ==="
echo '{"keyholders":[]}' > "$TMP/kh_empty.json"
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_empty.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "empty keyholders exit 2"
assert_contains "$ERR" "empty" "empty-keyholders diagnostic"

# ── 16. Malformed keyholders JSON → exit 2 ────────────────────────────────────
echo
echo "=== 16. Malformed keyholders JSON rejected ==="
echo "not json {{" > "$TMP/kh_malformed.json"
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_malformed.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "malformed JSON exit 2"
assert_contains "$ERR" "parse" "parse diagnostic"

# ── 17. Missing --backup-shares → exit 1 ──────────────────────────────────────
echo
echo "=== 17. Missing --backup-shares exits 1 ==="
set +e
"$WALLET" keyfile-recover \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --backup-shares exit 1"

# ── 18. Missing --backup-envelopes → exit 1 ───────────────────────────────────
echo
echo "=== 18. Missing --backup-envelopes exits 1 ==="
set +e
"$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --keyholders "$TMP/kh_sub_135.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --backup-envelopes exit 1"

# ── 19. Missing --keyholders → exit 1 ─────────────────────────────────────────
echo
echo "=== 19. Missing --keyholders exits 1 ==="
set +e
"$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --keyholders exit 1"

# ── 20. Non-existent shares file → exit 1 ─────────────────────────────────────
echo
echo "=== 20. Non-existent --backup-shares file exits 1 ==="
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/does_not_exist.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "non-existent shares file exit 1"
assert_contains "$ERR" "cannot open" "cannot-open diagnostic"

# ── 21. share/envelopes mismatch → exit 2 ─────────────────────────────────────
echo
echo "=== 21. Cross-verification catches share/envelope mismatch ==="
# Create a SECOND backup with a DIFFERENT secret, then use the new envelopes
# but the old shares. Decrypt succeeds (passphrases unchanged) but the y_hex
# won't match the shares file → cross-verification triggers exit 2.
"$WALLET" backup-create \
    --secret "feedfacecafebabe" \
    --threshold 3 \
    --keyholders "$TMP/kh_full.json" \
    --shares-out "$TMP/shares_b.json" \
    --envelopes-out "$TMP/envelopes_b.json" >/dev/null 2>&1
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes_b.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "share/envelope mismatch exit 2"
assert_contains "$ERR" "do NOT match" "mismatch diagnostic"

# ── 22. --out exists without --force → exit 1 ─────────────────────────────────
echo
echo "=== 22. --out existing without --force exits 1 ==="
# recovered.json already exists from step 8.
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --out "$TMP/recovered.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "--out existing without --force exit 1"
assert_contains "$ERR" "already exists" "already-exists diagnostic"
assert_contains "$ERR" "--force" "force diagnostic"

# ── 23. --out existing with --force → exit 0 ──────────────────────────────────
echo
echo "=== 23. --out existing with --force exits 0 ==="
"$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --out "$TMP/recovered.json" \
    --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--force overwrites existing --out"

# ── 24. --out parent directory missing → exit 1 ───────────────────────────────
echo
echo "=== 24. --out parent directory missing exits 1 ==="
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --out "$TMP/nonexistent_dir/out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "missing parent dir exit 1"
assert_contains "$ERR" "does not exist" "does-not-exist diagnostic"

# ── 25. Unknown argument → exit 1 ─────────────────────────────────────────────
echo
echo "=== 25. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "unknown argument exit 1"
assert_contains "$ERR" "unknown" "unknown-argument diagnostic"

# ── 26. --threshold 0 rejected ────────────────────────────────────────────────
echo
echo "=== 26. --threshold 0 rejected ==="
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 0 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "--threshold 0 exit 1"
assert_contains "$ERR" "threshold" "threshold diagnostic"

# ── 27. Shares file with wrong top-level shape → exit 2 ───────────────────────
echo
echo "=== 27. Shares file with wrong top-level shape rejected ==="
echo '{"not_shares":[]}' > "$TMP/bad_shape_shares.json"
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/bad_shape_shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "bad shares shape exit 2"
assert_contains "$ERR" "shares" "shares-shape diagnostic"

# ── 28. Envelopes file with wrong top-level shape → exit 2 ────────────────────
echo
echo "=== 28. Envelopes file with wrong top-level shape rejected ==="
echo '{"not_envelopes":[]}' > "$TMP/bad_shape_envs.json"
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/bad_shape_envs.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "bad envelopes shape exit 2"
assert_contains "$ERR" "envelopes" "envelopes-shape diagnostic"

# ── 29. Keyholders file with wrong top-level shape → exit 2 ───────────────────
echo
echo "=== 29. Keyholders file with wrong top-level shape rejected ==="
echo '{"not_keyholders":[]}' > "$TMP/bad_shape_kh.json"
set +e
ERR=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/bad_shape_kh.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "bad keyholders shape exit 2"
assert_contains "$ERR" "keyholders" "keyholders-shape diagnostic"

# ── 30. 1-of-1 trivial recovery ───────────────────────────────────────────────
echo
echo "=== 30. 1-of-1 trivial backup recovers ==="
echo '{"keyholders":[{"share_index":1,"passphrase":"only-pw"}]}' > "$TMP/kh_1.json"
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 1 \
    --keyholders "$TMP/kh_1.json" \
    --shares-out "$TMP/shares_1.json" \
    --envelopes-out "$TMP/envelopes_1.json" >/dev/null 2>&1
RECOVERED_1=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares_1.json" \
    --backup-envelopes "$TMP/envelopes_1.json" \
    --keyholders "$TMP/kh_1.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "1-of-1 keyfile-recover exit 0"
assert_eq "$RECOVERED_1" "$SECRET" "1-of-1 recovered secret == original"

# ── 31. Decrypted y-bytes from cross-verification match shares file ───────────
echo
echo "=== 31. Cross-verification: decrypted y matches shares file y_hex ==="
# (This is implicitly already proven by the round-trip success in steps 3-6,
# but we add an explicit assertion to lock it in as a regression target.)
EXPECTED_Y1=$($PY -c "import json; d=json.load(open('$TMP/shares.json')); print(next(s['y_hex'] for s in d['shares'] if s['x']==1))")
BLOB1=$($PY -c "import json; d=json.load(open('$TMP/envelopes.json')); print(next(e['envelope_blob'] for e in d['envelopes'] if e['share_index']==1))")
DECRYPTED_Y1=$("$WALLET" envelope decrypt --envelope "$BLOB1" --password "keyholder-pw-1" 2>&1 | tr -d '\r')
assert_eq "$DECRYPTED_Y1" "$EXPECTED_Y1" "envelope[1] decrypt y_hex matches shares file"

# ── 32. --json + --out together (both written) ────────────────────────────────
echo
echo "=== 32. --json + --out together: file written AND JSON to stdout ==="
JSON_BOTH=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --out "$TMP/both.json" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json + --out exit 0"
if [ -s "$TMP/both.json" ]; then
    echo "  PASS: --out file written when --json also supplied"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file missing despite --json"; fail_count=$((fail_count + 1))
fi
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_BOTH''')
assert d.get("secret_hex") == "$SECRET", "stdout JSON secret mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json + --out stdout JSON has correct secret"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json + --out stdout JSON wrong"; fail_count=$((fail_count + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-recover"; exit 0
else
    echo "  FAIL: test_wallet_keyfile_recover"; exit 1
fi
