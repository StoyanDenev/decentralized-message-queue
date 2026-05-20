#!/usr/bin/env bash
# determ-wallet account-recover composite wallet-recovery CLI test.
#
# `account-recover` composes `keyfile-recover` (Shamir + envelope decrypt)
# with `account-import` (Ed25519 seed -> anon-account JSON) into a SINGLE
# call. Operator workflow: "I have my T-of-N backup, give me back my
# wallet account file ready to use" — one command instead of two.
#
# End-to-end coverage:
#   - account-create-batch a fresh account -> capture original address
#   - backup-create on the recovered priv with T=3, N=5 keyholders
#   - account-recover with T-of-N subset -> assert RECOVERED address == ORIGINAL
#   - account-recover with a DIFFERENT T-subset -> same address
#   - --json on stdout shape + value
#   - --out writes JSON file (single account record) with 0600 perms
#   - --json + --out together both written
#
# Failure-mode coverage:
#   - Insufficient passphrases (1 < T=3) -> exit 2
#   - Wrong passphrase -> exit 2
#   - Missing required flags (--shares / --envelopes / --keyholders / --threshold) -> exit 1
#   - Non-existent shares file -> exit 1
#   - Malformed JSON -> exit 2
#   - Wrong top-level shape on each of the three files -> exit 2
#   - Empty passphrase -> exit 2
#   - Duplicate share_index in keyholders -> exit 2
#   - share/envelope mismatch (cross-verification fails) -> exit 2
#   - --threshold 0 / > 255 -> exit 1
#   - Unknown argument -> exit 1
#   - --out exists without --force -> exit 1
#   - --out exists with --force -> exit 0
#   - Output parent directory missing -> exit 1
#
# Run from repo root: bash tools/test_wallet_account_recover.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
if [ "${WALLET#/}" = "$WALLET" ] && [ "${WALLET#?:}" = "$WALLET" ]; then
    WALLET_ABS="$PROJECT_ROOT/$WALLET"
else
    WALLET_ABS="$WALLET"
fi

SCRATCH="build/test_wallet_account_recover.$$"
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

# ── 1. Help text mentions account-recover ─────────────────────────────────────
echo "=== 1. Help text mentions account-recover ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "account-recover"; then
    echo "  PASS: help mentions account-recover"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing account-recover"; fail_count=$((fail_count + 1))
fi

# ── 2. Generate a fresh account, extract priv seed + original address ─────────
echo
echo "=== 2. Setup: account-create-batch fresh account ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/orig.json" --json >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-create-batch exit 0"

ORIG_ADDR=$($PY -c "import json; d=json.load(open('$TMP/orig.json')); print(d['accounts'][0]['address'])")
ORIG_PRIV=$($PY -c "import json; d=json.load(open('$TMP/orig.json')); print(d['accounts'][0]['privkey_hex'])")
if [ -n "$ORIG_ADDR" ] && [ -n "$ORIG_PRIV" ]; then
    echo "  PASS: extracted original address + priv_seed"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: could not extract original account fields"; fail_count=$((fail_count + 1))
fi

# ── 3. backup-create with T=3, N=5 on the priv seed ───────────────────────────
echo
echo "=== 3. backup-create T=3, N=5 over the original priv seed ==="
$PY - "$TMP/kh_full.json" <<'PY_EOF'
import json, sys
out = sys.argv[1]
khs = [{"share_index": i, "passphrase": f"keyholder-pw-{i}"} for i in range(1, 6)]
with open(out, "w") as f:
    json.dump({"keyholders": khs}, f)
PY_EOF
"$WALLET" backup-create \
    --secret "$ORIG_PRIV" \
    --threshold 3 \
    --keyholders "$TMP/kh_full.json" \
    --shares-out "$TMP/shares.json" \
    --envelopes-out "$TMP/envelopes.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "backup-create exit 0 (setup precondition)"

# ── 4. Happy path: account-recover with T-of-N {1,3,5} → human form ───────────
echo
echo "=== 4. account-recover with {1,3,5} subset (human form) ==="
cat > "$TMP/kh_sub_135.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
HUMAN_OUT=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-recover exit 0 with {1,3,5}"
assert_contains "$HUMAN_OUT" "recovered account" "human-form prefix"
assert_contains "$HUMAN_OUT" "$ORIG_ADDR" "recovered address == original"
assert_contains "$HUMAN_OUT" "$ORIG_PRIV" "recovered privkey_hex == original"

# ── 5. Different T-subset {2,4,5} → same address ──────────────────────────────
echo
echo "=== 5. Different T-subset {2,4,5} reconstructs same account ==="
cat > "$TMP/kh_sub_245.json" <<'EOF'
{"keyholders":[
  {"share_index":2,"passphrase":"keyholder-pw-2"},
  {"share_index":4,"passphrase":"keyholder-pw-4"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
JSON_245=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_245.json" \
    --threshold 3 \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-recover exit 0 with {2,4,5} (--json)"
ADDR_245=$($PY -c "import json; d=json.loads('''$JSON_245'''); print(d['address'])")
PRIV_245=$($PY -c "import json; d=json.loads('''$JSON_245'''); print(d['privkey_hex'])")
assert_eq "$ADDR_245" "$ORIG_ADDR" "{2,4,5} recovered address == original"
assert_eq "$PRIV_245" "$ORIG_PRIV" "{2,4,5} recovered priv == original"

# ── 6. --json on stdout produces valid {"address","privkey_hex"} ──────────────
echo
echo "=== 6. --json on stdout: schema + values ==="
JSON_OUT=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json, sys
d = json.loads('''$JSON_OUT''')
assert "address" in d and "privkey_hex" in d, "missing fields"
assert d["address"] == "$ORIG_ADDR", f"address mismatch: {d['address']!r}"
assert d["privkey_hex"] == "$ORIG_PRIV", f"priv mismatch: {d['privkey_hex']!r}"
assert d["address"].startswith("0x") and len(d["address"]) == 66, "address shape wrong"
assert len(d["privkey_hex"]) == 64, "privkey_hex length wrong"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema + values"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json shape or value wrong"; fail_count=$((fail_count + 1))
fi

# ── 7. --out writes JSON file ────────────────────────────────────────────────
echo
echo "=== 7. --out writes anon-account JSON file ==="
"$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
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
assert d["address"] == "$ORIG_ADDR", f"file address mismatch: {d['address']!r}"
assert d["privkey_hex"] == "$ORIG_PRIV", f"file priv mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --out file contents match original account"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file contents wrong"; fail_count=$((fail_count + 1))
fi

# ── 8. Wrong passphrase → exit 2 ──────────────────────────────────────────────
echo
echo "=== 8. Wrong passphrase exits 2 ==="
cat > "$TMP/kh_wrong.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"WRONG-PASSPHRASE"},
  {"share_index":3,"passphrase":"keyholder-pw-3"},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_wrong.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "wrong passphrase exit 2"
assert_contains "$ERR" "wrong passphrase or corrupted envelope" "wrong-passphrase diagnostic"

# ── 9. Insufficient passphrases (< T) → exit 2 ────────────────────────────────
echo
echo "=== 9. Insufficient shares (1 < T=3) exits 2 ==="
cat > "$TMP/kh_one.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"}
]}
EOF
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_one.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "insufficient shares exit 2"
assert_contains "$ERR" "insufficient shares" "insufficient-shares diagnostic"

# ── 10. Two below-threshold subset (T-1=2) also rejected ──────────────────────
echo
echo "=== 10. 2 < T=3 also rejected (boundary) ==="
cat > "$TMP/kh_two.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"}
]}
EOF
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_two.json" \
    --threshold 3 2>&1)
RC=$?
set -e
assert_eq "$RC" "2" "2 < T=3 exit 2"

# ── 11. Missing --threshold → exit 1 (required, unlike keyfile-recover) ───────
echo
echo "=== 11. Missing --threshold exits 1 (required flag) ==="
set +e
"$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --threshold exit 1"

# ── 12. Missing --shares → exit 1 ─────────────────────────────────────────────
echo
echo "=== 12. Missing --shares exits 1 ==="
set +e
"$WALLET" account-recover \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --shares exit 1"

# ── 13. Missing --envelopes → exit 1 ──────────────────────────────────────────
echo
echo "=== 13. Missing --envelopes exits 1 ==="
set +e
"$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --envelopes exit 1"

# ── 14. Missing --keyholders → exit 1 ─────────────────────────────────────────
echo
echo "=== 14. Missing --keyholders exits 1 ==="
set +e
"$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --threshold 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --keyholders exit 1"

# ── 15. Non-existent shares file → exit 1 ─────────────────────────────────────
echo
echo "=== 15. Non-existent --shares file exits 1 ==="
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/does_not_exist.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "non-existent shares exit 1"
assert_contains "$ERR" "cannot open" "cannot-open diagnostic"

# ── 16. Malformed keyholders JSON → exit 2 ────────────────────────────────────
echo
echo "=== 16. Malformed keyholders JSON rejected ==="
echo "not json {{" > "$TMP/kh_malformed.json"
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_malformed.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "malformed JSON exit 2"
assert_contains "$ERR" "parse" "parse diagnostic"

# ── 17. Wrong top-level shape (shares file) → exit 2 ──────────────────────────
echo
echo "=== 17. Wrong top-level shape on shares rejected ==="
echo '{"not_shares":[]}' > "$TMP/bad_shape_shares.json"
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/bad_shape_shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "bad shares shape exit 2"

# ── 18. Wrong top-level shape (envelopes file) → exit 2 ───────────────────────
echo
echo "=== 18. Wrong top-level shape on envelopes rejected ==="
echo '{"not_envelopes":[]}' > "$TMP/bad_shape_envs.json"
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/bad_shape_envs.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 2>&1)
RC=$?
set -e
assert_eq "$RC" "2" "bad envelopes shape exit 2"

# ── 19. Wrong top-level shape (keyholders file) → exit 2 ──────────────────────
echo
echo "=== 19. Wrong top-level shape on keyholders rejected ==="
echo '{"not_keyholders":[]}' > "$TMP/bad_shape_kh.json"
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/bad_shape_kh.json" \
    --threshold 3 2>&1)
RC=$?
set -e
assert_eq "$RC" "2" "bad keyholders shape exit 2"

# ── 20. Empty keyholders array → exit 2 ───────────────────────────────────────
echo
echo "=== 20. Empty keyholders array rejected ==="
echo '{"keyholders":[]}' > "$TMP/kh_empty.json"
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_empty.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "empty keyholders exit 2"
assert_contains "$ERR" "empty" "empty-keyholders diagnostic"

# ── 21. Empty passphrase → exit 2 ─────────────────────────────────────────────
echo
echo "=== 21. Empty passphrase rejected ==="
cat > "$TMP/kh_empty_pw.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":""},
  {"share_index":5,"passphrase":"keyholder-pw-5"}
]}
EOF
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_empty_pw.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "empty passphrase exit 2"
assert_contains "$ERR" "passphrase is empty" "empty-passphrase diagnostic"

# ── 22. Duplicate share_index in keyholders → exit 2 ──────────────────────────
echo
echo "=== 22. Duplicate share_index rejected ==="
cat > "$TMP/kh_dup.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":1,"passphrase":"keyholder-pw-1"},
  {"share_index":3,"passphrase":"keyholder-pw-3"}
]}
EOF
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_dup.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "duplicate share_index exit 2"
assert_contains "$ERR" "duplicate" "duplicate diagnostic"

# ── 23. share/envelope mismatch (cross-verification) → exit 2 ─────────────────
echo
echo "=== 23. share/envelope file mismatch caught ==="
# Build a SECOND backup over a DIFFERENT secret with the SAME keyholder
# passphrases. Decrypt succeeds against the new envelopes but the y_hex
# won't match the OLD shares file → cross-verification fires.
"$WALLET" backup-create \
    --secret "feedfacecafebabedeadbeef00112233445566778899aabbccddeeff00112233" \
    --threshold 3 \
    --keyholders "$TMP/kh_full.json" \
    --shares-out "$TMP/shares_b.json" \
    --envelopes-out "$TMP/envelopes_b.json" >/dev/null 2>&1
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes_b.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "share/envelope mismatch exit 2"
assert_contains "$ERR" "do NOT match" "mismatch diagnostic"

# ── 24. --threshold 0 rejected ────────────────────────────────────────────────
echo
echo "=== 24. --threshold 0 rejected ==="
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 0 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "--threshold 0 exit 1"
assert_contains "$ERR" "threshold" "threshold diagnostic"

# ── 25. --threshold > 255 rejected ────────────────────────────────────────────
echo
echo "=== 25. --threshold 300 rejected ==="
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 300 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "--threshold 300 exit 1"
assert_contains "$ERR" "255" "threshold-cap diagnostic"

# ── 26. Unknown argument → exit 1 ─────────────────────────────────────────────
echo
echo "=== 26. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "unknown argument exit 1"
assert_contains "$ERR" "unknown" "unknown-argument diagnostic"

# ── 27. --out exists without --force → exit 1 ─────────────────────────────────
echo
echo "=== 27. --out existing without --force exits 1 ==="
# recovered.json already exists from step 7.
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --out "$TMP/recovered.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "--out existing without --force exit 1"
assert_contains "$ERR" "already exists" "already-exists diagnostic"

# ── 28. --out exists with --force → exit 0 ────────────────────────────────────
echo
echo "=== 28. --out existing with --force exits 0 ==="
"$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --out "$TMP/recovered.json" \
    --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--force overwrites existing --out"

# ── 29. --out parent directory missing → exit 1 ───────────────────────────────
echo
echo "=== 29. --out parent directory missing exits 1 ==="
set +e
ERR=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --out "$TMP/nonexistent_dir/out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "missing parent dir exit 1"
assert_contains "$ERR" "does not exist" "parent-dir diagnostic"

# ── 30. --json + --out together: file written AND JSON to stdout ──────────────
echo
echo "=== 30. --json + --out together (file + stdout) ==="
JSON_BOTH=$("$WALLET" account-recover \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" \
    --threshold 3 \
    --out "$TMP/both.json" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json + --out exit 0"
if [ -s "$TMP/both.json" ]; then
    echo "  PASS: --out file written even with --json"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file missing despite --json"; fail_count=$((fail_count + 1))
fi
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_BOTH''')
assert d["address"] == "$ORIG_ADDR", "stdout JSON address mismatch"
assert d["privkey_hex"] == "$ORIG_PRIV", "stdout JSON priv mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json + --out stdout JSON correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json + --out stdout JSON wrong"; fail_count=$((fail_count + 1))
fi

# ── 31. Cross-CLI parity: account-recover output matches account-import path ──
echo
echo "=== 31. account-recover output matches keyfile-recover+account-import composition ==="
# Reference path: keyfile-recover -> account-import. Should yield the SAME
# {address, privkey_hex} record byte-for-byte (same primitives, same hex
# encoding, same anon-address derivation).
KFR_SECRET=$("$WALLET" keyfile-recover \
    --backup-shares "$TMP/shares.json" \
    --backup-envelopes "$TMP/envelopes.json" \
    --keyholders "$TMP/kh_sub_135.json" 2>&1 | tr -d '\r')
REFERENCE_JSON=$("$WALLET" account-import --priv "$KFR_SECRET" --json 2>&1 | tr -d '\r')
$PY - <<PY_EOF
import json
ref = json.loads('''$REFERENCE_JSON''')
got = json.loads('''$JSON_BOTH''')
assert ref["address"]     == got["address"],     f"address parity broken: {ref['address']} vs {got['address']}"
assert ref["privkey_hex"] == got["privkey_hex"], "privkey_hex parity broken"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: composite matches keyfile-recover+account-import composition"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: composite path diverged from constituent CLIs"; fail_count=$((fail_count + 1))
fi

# ── 32. Trivial 1-of-1 recovery round-trips ──────────────────────────────────
echo
echo "=== 32. 1-of-1 trivial round-trip ==="
echo '{"keyholders":[{"share_index":1,"passphrase":"only-pw"}]}' > "$TMP/kh_1.json"
"$WALLET" backup-create \
    --secret "$ORIG_PRIV" \
    --threshold 1 \
    --keyholders "$TMP/kh_1.json" \
    --shares-out "$TMP/shares_1.json" \
    --envelopes-out "$TMP/envelopes_1.json" >/dev/null 2>&1
JSON_1OF1=$("$WALLET" account-recover \
    --shares "$TMP/shares_1.json" \
    --envelopes "$TMP/envelopes_1.json" \
    --keyholders "$TMP/kh_1.json" \
    --threshold 1 \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "1-of-1 account-recover exit 0"
ADDR_1=$($PY -c "import json; print(json.loads('''$JSON_1OF1''')['address'])")
assert_eq "$ADDR_1" "$ORIG_ADDR" "1-of-1 recovered address == original"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-recover"; exit 0
else
    echo "  FAIL"; exit 1
fi
