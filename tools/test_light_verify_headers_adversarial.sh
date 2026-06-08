#!/usr/bin/env bash
# determ-light verify-headers — OFFLINE, EVERY-HOST adversarial regression.
#
# Drives light/verify.cpp::verify_headers through the CLI surface
#   determ-light verify-headers --in <file> [--genesis-hash <hex>] [--prev-hash <hex>]
# (light/main.cpp::cmd_verify_headers, line 609) with HAND-CRAFTED header JSON
# files. NO daemon, NO cluster, NO compute_genesis_hash — every assertion is a
# pure function of bytes we write, so this runs deterministically on THIS
# Windows host (unlike the cluster-bound tools/test_light_verify_chain_file.sh).
#
# The standout case is (1): the resume-soundness fix. A malicious daemon serving
# a resume-suffix header that claims index 0 used to divert verify_headers into
# its binding-free genesis branch — ignoring the caller's mid-chain --prev-hash
# anchor while the per-block sig loop skipped index 0. light/verify.cpp:172-186
# now REJECTS an index-0 header whenever a non-empty --prev-hash anchor was
# supplied. This test pins that REJECT (and the paired genesis-branch invariants)
# as a deterministic offline regression.
#
# verify_headers reads the {"headers":[...]} ENVELOPE (verify.cpp:140 — a bare
# array is rejected as "input missing 'headers' array"), and from each header:
# index (uint), prev_hash (64 hex), block_hash (64 hex).
#
# CLI exit codes (light/main.cpp:628/636): 0 = PASS (r.ok), 1 = FAIL/parse-error.
#
# Run from repo root: bash tools/test_light_verify_headers_adversarial.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY="${PY:-python}"

pass=0; fail=0
# ck <got-exit> <want-exit> <label>
ck() { if [ "$1" = "$2" ]; then echo "  PASS: $3 (exit $1)"; pass=$((pass+1));
       else echo "  FAIL: $3 (got exit $1, want $2)"; fail=$((fail+1)); fi; }
# ckdiag <haystack> <needle> <label> — assert a diagnostic substring is present.
ckdiag() { if printf '%s' "$1" | grep -qF "$2"; then
             echo "  PASS: $3"; pass=$((pass+1));
           else echo "  FAIL: $3 (diag did not contain '$2')";
             printf '%s\n' "$1" | sed 's/^/        /'; fail=$((fail+1)); fi; }

T="$(mktemp -d 2>/dev/null || echo /tmp/determ_lvh_$$)"; mkdir -p "$T"
trap 'rm -rf "$T" 2>/dev/null' EXIT INT

# ── Fixed, internally-consistent 64-hex chain hashes ───────────────────────────
# block_hash[i] == prev_hash[i+1] for the PASS cases; all distinct, all valid hex.
ZERO=$(printf '0%.0s' $(seq 1 64))                      # genesis prev_hash
H0=$(printf 'a%.0s'   $(seq 1 64))                       # block_hash of index-0
H1=$(printf 'b%.0s'   $(seq 1 64))                       # block_hash of index-1
H2=$(printf 'c%.0s'   $(seq 1 64))                       # block_hash of index-2
WRONG=$(printf 'd%.0s' $(seq 1 64))                      # a non-matching anchor/genesis

# write_headers <outfile> <python-list-literal-of-(index,prev,block)-dicts>
# Uses 'wb' so Python does NOT translate LF->CRLF on Windows (binary-safe).
write_headers() {
    local out="$1"; local body="$2"
    "$PY" - "$out" "$body" <<'PYEOF'
import sys, json
out  = sys.argv[1]
body = sys.argv[2]
doc  = {"headers": json.loads(body)}
data = (json.dumps(doc) + "\n").encode("utf-8")
with open(out, "wb") as f:        # 'wb' => no LF->CRLF translation on Windows
    f.write(data)
PYEOF
}

run() {  # run <file> [extra args...] -> sets OUT/RC
    set +e
    OUT="$("$DETERM_LIGHT" verify-headers --in "$1" "${@:2}" 2>&1)"; RC=$?
    set -e
}

echo "=== (1) THE RESUME FIX: index-0 first header WITH --prev-hash anchor -> FAIL ==="
# A 2-header resume suffix whose FIRST header lies about being genesis (index 0)
# while the caller pins a real mid-chain anchor via --prev-hash. Must FAIL, and
# the diagnostic must name the genesis/anchor rejection (verify.cpp:182-185).
write_headers "$T/resume_attack.json" \
  "[{\"index\":0,\"prev_hash\":\"$ZERO\",\"block_hash\":\"$H0\"},
    {\"index\":1,\"prev_hash\":\"$H0\",\"block_hash\":\"$H1\"}]"
run "$T/resume_attack.json" --prev-hash "$WRONG"
ck "$RC" 1 "index-0 header under --prev-hash anchor is rejected"
ckdiag "$OUT" "index 0" "diagnostic names the index-0/genesis rejection"
ckdiag "$OUT" "prev_hash anchor" "diagnostic names the supplied prev_hash anchor"

# Single-header variant of the same attack (suffix page of length 1).
write_headers "$T/resume_attack1.json" \
  "[{\"index\":0,\"prev_hash\":\"$ZERO\",\"block_hash\":\"$H0\"}]"
run "$T/resume_attack1.json" --prev-hash "$WRONG"
ck "$RC" 1 "single index-0 header under --prev-hash anchor is rejected"

echo
echo "=== (2) Legit mid-chain page (index>0, prev_hash==--prev-hash, chained) -> PASS ==="
# First header index 5, its prev_hash equals the supplied anchor, internally
# chained to the next header. The non-index-0 branch binds first prev_hash to
# --prev-hash (verify.cpp:202-208), then the continuity walk holds.
write_headers "$T/midchain_ok.json" \
  "[{\"index\":5,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H1\"},
    {\"index\":6,\"prev_hash\":\"$H1\",\"block_hash\":\"$H2\"}]"
run "$T/midchain_ok.json" --prev-hash "$WRONG"
ck "$RC" 0 "anchored mid-chain page verifies"
ckdiag "$OUT" "OK" "PASS output reports OK"

# Same page but the anchor does NOT match the first prev_hash -> FAIL.
run "$T/midchain_ok.json" --prev-hash "$H2"
ck "$RC" 1 "mid-chain page with mismatched --prev-hash is rejected"
ckdiag "$OUT" "match supplied" "diagnostic names the --prev-hash mismatch"

echo
echo "=== (3) prev_hash continuity break inside the page -> FAIL ==="
# headers[1].prev_hash != headers[0].block_hash (verify.cpp:212-223).
write_headers "$T/break.json" \
  "[{\"index\":5,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H1\"},
    {\"index\":6,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H2\"}]"
run "$T/break.json" --prev-hash "$WRONG"
ck "$RC" 1 "internal prev_hash chain break is rejected"
ckdiag "$OUT" "chain break" "diagnostic names the prev_hash chain break"

echo
echo "=== (4) Genesis-anchored page (index 0, zero prev_hash, --genesis-hash) ==="
# First header is genuine genesis: index 0, prev_hash all-zero, block_hash==H0;
# verified WITHOUT a --prev-hash anchor and WITH --genesis-hash==H0 (matches).
write_headers "$T/genesis_ok.json" \
  "[{\"index\":0,\"prev_hash\":\"$ZERO\",\"block_hash\":\"$H0\"},
    {\"index\":1,\"prev_hash\":\"$H0\",\"block_hash\":\"$H1\"}]"
run "$T/genesis_ok.json" --genesis-hash "$H0"
ck "$RC" 0 "genesis-anchored page with correct --genesis-hash verifies"
ckdiag "$OUT" "OK" "PASS output reports OK"

# Same file, WRONG --genesis-hash -> FAIL (verify.cpp:193-200).
run "$T/genesis_ok.json" --genesis-hash "$WRONG"
ck "$RC" 1 "genesis-anchored page with wrong --genesis-hash is rejected"
ckdiag "$OUT" "block_hash mismatch" "diagnostic names the genesis block_hash mismatch"

echo
echo "=== (5) index-0 header with NON-zero prev_hash, no anchor -> FAIL ==="
# Genesis must have zero prev_hash (verify.cpp:187-192). No --prev-hash, no
# --genesis-hash: the only thing that can reject it is the zero-prev_hash check.
write_headers "$T/genesis_nonzero_prev.json" \
  "[{\"index\":0,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H0\"}]"
run "$T/genesis_nonzero_prev.json"
ck "$RC" 1 "genesis header with non-zero prev_hash is rejected"
ckdiag "$OUT" "non-zero prev_hash" "diagnostic names the non-zero genesis prev_hash"

echo
echo "=== (6) No-anchor mid-chain slice (index>0, no flags) -> internal-only PASS ==="
# index>0, neither --genesis-hash nor --prev-hash. verify.cpp's non-index-0
# branch finds prev_hash_hex empty, so it binds nothing on the first header and
# only the internal continuity walk runs -> PASS.
write_headers "$T/slice_noanchor.json" \
  "[{\"index\":9,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H1\"},
    {\"index\":10,\"prev_hash\":\"$H1\",\"block_hash\":\"$H2\"}]"
run "$T/slice_noanchor.json"
ck "$RC" 0 "no-anchor mid-chain slice verifies on internal continuity"
ckdiag "$OUT" "OK" "PASS output reports OK"

# Negative twin: same slice but break the internal chain -> FAIL even with no flags.
write_headers "$T/slice_break.json" \
  "[{\"index\":9,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H1\"},
    {\"index\":10,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H2\"}]"
run "$T/slice_break.json"
ck "$RC" 1 "no-anchor slice with internal break is rejected"

echo
echo "=== (7) Shape guards ==="
# A bare JSON array (no envelope) is rejected: verify.cpp:140 requires
# {"headers":[...]} and reports "input missing 'headers' array".
printf '%s' "[{\"index\":1,\"prev_hash\":\"$WRONG\",\"block_hash\":\"$H1\"}]" \
  > "$T/bare_array.json"
run "$T/bare_array.json"
ck "$RC" 1 "bare array (no headers envelope) is rejected"
ckdiag "$OUT" "headers" "diagnostic names the missing 'headers' array"

# An empty headers slice is a graceful PASS (verify.cpp:145-149).
write_headers "$T/empty.json" "[]"
run "$T/empty.json"
ck "$RC" 0 "empty headers slice is a graceful PASS"

# A short prev_hash (not 64 hex) is rejected by the field-length guard
# (verify.cpp:158-164) regardless of anchors.
write_headers "$T/shorthash.json" \
  "[{\"index\":1,\"prev_hash\":\"dead\",\"block_hash\":\"$H1\"}]"
run "$T/shorthash.json"
ck "$RC" 1 "header with wrong-length prev_hash is rejected"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail"
if [ "$fail" -eq 0 ]; then echo "  PASS: test_light_verify_headers_adversarial"; exit 0
else echo "  FAIL: test_light_verify_headers_adversarial"; exit 1; fi
