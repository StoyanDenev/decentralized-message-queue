#!/usr/bin/env bash
# determ-light verify-headers — OFFLINE malformed/tamper/boundary edge cases.
#
# Pure offline fail-closed test (no cluster, no daemon, no genesis build).
# Unlike its sibling test_light_verify_headers.sh — which boots a live 3-node
# cluster and only exercises the happy path plus daemon-fetched tampered-prev
# / genesis-hash match+mismatch — this test hand-crafts the `headers` RPC reply
# JSON directly and drives the REAL determ-light binary against every
# structural malformation, tamper, and boundary the verify_headers() routine
# is supposed to reject (light/verify.cpp). The point is to prove the verifier
# FAILS CLOSED: a malformed / tampered / chain-broken input must NEVER print
# "OK" and must NEVER exit 0.
#
# verify-headers exit/output contract (light/main.cpp::cmd_verify_headers):
#   valid chain        → "OK" on stdout,  exit 0
#   verifier rejection → r.detail on stderr ("FAIL: ..." or structural msg), exit 1
#   parse / I/O error  → "verify-headers: ..." on stderr, exit 1
# In every non-OK case exit is 1 and stdout must not contain "OK".
#
# Assertions:
#   1.  Hand-crafted VALID 2-header chain (h0.block_hash == h1.prev_hash) → OK, exit 0.
#   2.  Empty headers array → OK, exit 0 (valid "nothing to verify" boundary).
#   3.  TAMPER trap: flip one byte of the valid chain's link → FAIL, exit 1, no "OK".
#   4.  Genesis header (index 0) with NON-ZERO prev_hash → FAIL, exit 1.
#   5.  prev_hash of wrong length (63 chars) → rejected, exit 1, no "OK".
#   6.  Header missing the 'block_hash' field → rejected, exit 1, no "OK".
#   7.  Hand-crafted prev_hash chain break at header 1 → FAIL, exit 1.
#   8.  --prev-hash anchor mismatch on a non-genesis first header → FAIL, exit 1.
#   9.  --genesis-hash anchor mismatch (offline) → FAIL, exit 1.
#   10. 'headers' key present but NOT an array → rejected, exit 1, no "OK".
#   11. 'headers' key entirely absent → rejected, exit 1, no "OK".
#   12. Non-JSON / truncated file → parse error, exit 1, no "OK".
#   13. Nonexistent --in path → I/O error, exit 1, no "OK".
#
# Run from repo root: bash tools/test_light_verify_headers_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Use a build-relative tmp dir (not mktemp): on this Windows box python can't
# resolve the MSYS /tmp path that mktemp hands back, which would silently break
# the JSON crafting. A repo-relative dir is visible to both bash and python.
TMP="build/test_light_verify_headers_edge.$$"
rm -rf "$TMP"; mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

ZERO64=$("$PY" -c "print('0'*64)")
A64=$("$PY"   -c "print('a'*64)")
B64=$("$PY"   -c "print('b'*64)")
C64=$("$PY"   -c "print('c'*64)")
E64=$("$PY"   -c "print('e'*64)")
F64=$("$PY"   -c "print('f'*64)")

# write_json <out> <python-dict-literal>  — emits a JSON file from a dict expr.
write_json() {
  "$PY" - "$1" "$2" <<'EOF'
import json, sys
out, expr = sys.argv[1], sys.argv[2]
json.dump(eval(expr), open(out, "w"))
EOF
}

# run_vh <file> [extra args...]; sets RC + OUT (stdout+stderr merged) globals.
run_vh() {
  set +e
  OUT=$("$DETERM_LIGHT" verify-headers --in "$1" "${@:2}" 2>&1)
  RC=$?
  set -e
}

# A valid chain: genesis prev_hash all-zero, and h1.prev_hash == h0.block_hash.
write_json "$TMP/valid.json" \
  "{'headers':[{'index':0,'prev_hash':'$ZERO64','block_hash':'$A64'},{'index':1,'prev_hash':'$A64','block_hash':'$C64'}]}"

echo "=== 1. Hand-crafted VALID 2-header chain → OK exit 0 ==="
run_vh "$TMP/valid.json"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "^OK$"; then
  assert "true" "valid chain → OK exit 0"
else
  echo "$OUT"; assert "false" "valid chain → OK exit 0 (rc=$RC)"
fi

echo
echo "=== 2. Empty headers array → OK exit 0 (nothing-to-verify boundary) ==="
write_json "$TMP/empty.json" "{'headers':[]}"
run_vh "$TMP/empty.json"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "^OK$"; then
  assert "true" "empty headers → OK exit 0"
else
  echo "$OUT"; assert "false" "empty headers → OK exit 0 (rc=$RC)"
fi

echo
echo "=== 3. TAMPER trap: flip the inter-header link → FAIL exit 1, no OK ==="
# Break the link: set h1.prev_hash to something != h0.block_hash.
write_json "$TMP/tamper.json" \
  "{'headers':[{'index':0,'prev_hash':'$ZERO64','block_hash':'$A64'},{'index':1,'prev_hash':'$B64','block_hash':'$C64'}]}"
run_vh "$TMP/tamper.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "prev_hash chain break" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "tampered link → FAIL exit 1 (no OK)"
else
  echo "$OUT"; assert "false" "tampered link → FAIL exit 1 (rc=$RC)"
fi

echo
echo "=== 4. Genesis header (index 0) with NON-ZERO prev_hash → FAIL exit 1 ==="
write_json "$TMP/gennonzero.json" \
  "{'headers':[{'index':0,'prev_hash':'1'+'0'*63,'block_hash':'$A64'}]}"
run_vh "$TMP/gennonzero.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "non-zero prev_hash" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "genesis non-zero prev_hash → FAIL exit 1"
else
  echo "$OUT"; assert "false" "genesis non-zero prev_hash → FAIL exit 1 (rc=$RC)"
fi

echo
echo "=== 5. prev_hash wrong length (63 chars) → rejected exit 1, no OK ==="
write_json "$TMP/badlen.json" \
  "{'headers':[{'index':0,'prev_hash':'0'*63,'block_hash':'$A64'}]}"
run_vh "$TMP/badlen.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qi "wrong length" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "wrong-length prev_hash → rejected exit 1"
else
  echo "$OUT"; assert "false" "wrong-length prev_hash → rejected exit 1 (rc=$RC)"
fi

echo
echo "=== 6. Header missing 'block_hash' field → rejected exit 1, no OK ==="
# A 2-header chain where header[0] lacks block_hash: walk needs prior block_hash.
write_json "$TMP/nofield.json" \
  "{'headers':[{'index':0,'prev_hash':'$ZERO64'},{'index':1,'prev_hash':'$ZERO64'}]}"
run_vh "$TMP/nofield.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qi "missing 'block_hash'" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "missing block_hash field → rejected exit 1"
else
  echo "$OUT"; assert "false" "missing block_hash field → rejected exit 1 (rc=$RC)"
fi

echo
echo "=== 7. Hand-crafted prev_hash chain break at header 1 → FAIL exit 1 ==="
write_json "$TMP/break.json" \
  "{'headers':[{'index':0,'prev_hash':'$ZERO64','block_hash':'$A64'},{'index':1,'prev_hash':'$B64','block_hash':'$C64'}]}"
run_vh "$TMP/break.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "prev_hash chain break at header 1"; then
  assert "true" "chain break at header 1 → FAIL exit 1"
else
  echo "$OUT"; assert "false" "chain break at header 1 → FAIL exit 1 (rc=$RC)"
fi

echo
echo "=== 8. --prev-hash anchor mismatch (non-genesis first header) → FAIL exit 1 ==="
write_json "$TMP/nongen.json" \
  "{'headers':[{'index':5,'prev_hash':'$A64','block_hash':'$B64'}]}"
run_vh "$TMP/nongen.json" --prev-hash "$E64"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "doesn't match supplied" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "--prev-hash anchor mismatch → FAIL exit 1"
else
  echo "$OUT"; assert "false" "--prev-hash anchor mismatch → FAIL exit 1 (rc=$RC)"
fi

echo
echo "=== 9. --genesis-hash anchor mismatch (offline) → FAIL exit 1 ==="
run_vh "$TMP/valid.json" --genesis-hash "$F64"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "genesis block_hash mismatch" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "--genesis-hash mismatch → FAIL exit 1"
else
  echo "$OUT"; assert "false" "--genesis-hash mismatch → FAIL exit 1 (rc=$RC)"
fi

echo
echo "=== 10. 'headers' present but NOT an array → rejected exit 1, no OK ==="
write_json "$TMP/notarr.json" "{'headers':{'index':0}}"
run_vh "$TMP/notarr.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "missing 'headers' array" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "headers-not-array → rejected exit 1"
else
  echo "$OUT"; assert "false" "headers-not-array → rejected exit 1 (rc=$RC)"
fi

echo
echo "=== 11. 'headers' key entirely absent → rejected exit 1, no OK ==="
write_json "$TMP/nohdrs.json" "{'foo':1}"
run_vh "$TMP/nohdrs.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "missing 'headers' array" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "absent headers key → rejected exit 1"
else
  echo "$OUT"; assert "false" "absent headers key → rejected exit 1 (rc=$RC)"
fi

echo
echo "=== 12. Non-JSON / truncated file → parse error exit 1, no OK ==="
printf 'this is not json {{{' > "$TMP/bad.json"
run_vh "$TMP/bad.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qi "parse error" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "non-JSON input → parse error exit 1"
else
  echo "$OUT"; assert "false" "non-JSON input → parse error exit 1 (rc=$RC)"
fi

echo
echo "=== 13. Nonexistent --in path → I/O error exit 1, no OK ==="
run_vh "$TMP/this_file_does_not_exist.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qi "cannot open" \
   && ! echo "$OUT" | grep -q "^OK$"; then
  assert "true" "nonexistent file → I/O error exit 1"
else
  echo "$OUT"; assert "false" "nonexistent file → I/O error exit 1 (rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_headers_edge"; exit 0
else
  echo "  FAIL: test_light_verify_headers_edge"; exit 1
fi
