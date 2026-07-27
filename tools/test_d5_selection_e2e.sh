#!/usr/bin/env bash
# D.5 inc.6b — deterministic reference-RP end-to-end (SPEC §12).
#
# The full flow, cross-binary, WITHOUT a live cluster (the live multi-node
# DAPP_CALL apply-path is a known TIME_WAIT flake — test_dapp_e2e.sh:206 — so the
# apply-path is covered in-process; this e2e covers the PRODUCER -> CITIZEN link
# deterministically):
#
#   d5rp emit               (BUSL producer)  -> the 3 DAPP_CALL payloads
#   → wrap them into committee-authenticated block bodies at h_o < H < h_s
#   → determ-light verify-selection-offline  (Apache citizen) -> SELECTED
#
# So the reference RP's ACTUAL output is verified by the REAL citizen path
# (collect_d5_streams + first-open-wins + roster cutoff-freeze + d5_draw
# re-derivation). Asserts: (1) the published result verifies (SELECTED); (2) a
# non-roster member -> NOT_SELECTED; (3) a byte-flipped result block ->
# UNVERIFIABLE (fail-closed).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python

# Locate d5rp (ci_local export, else probe — mirrors test_d5rp.sh).
D5RP="${DETERM_D5RP_BIN:-}"
if [ -z "$D5RP" ]; then
  for c in build/Release/d5rp.exe build/d5rp.exe build/d5rp build/Release/d5rp \
           build-linux/d5rp build-linux/Release/d5rp; do
    [ -x "$c" ] && { D5RP="$c"; break; }
  done
fi
if [ -z "$D5RP" ] || [ ! -x "$D5RP" ] || [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: d5rp and/or determ-light binary not found; build the d5rp + determ-light targets"
  exit 0
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ck() { if [ "$1" = "1" ]; then echo "  PASS: $2"; pass=$((pass+1)); else echo "  FAIL: $2"; fail=$((fail+1)); fi; }

# 1. The RP produces its three streams.
EMIT=$("$D5RP" emit)
ROSTER=$(echo "$EMIT" | awk '$1=="roster"{print $2}')
CASEOPEN=$(echo "$EMIT" | awk '$1=="case-open"{print $2}')
RESULT=$(echo "$EMIT" | awk '$1=="result"{print $2}')
DOMAIN=$(echo "$EMIT" | sed -n 's/.*domain=\([^ ]*\).*/\1/p')
[ -n "$ROSTER" ] && [ -n "$CASEOPEN" ] && [ -n "$RESULT" ] && [ -n "$DOMAIN" ] \
  && ck 1 "d5rp emitted roster/case-open/result for domain=$DOMAIN" \
  || { ck 0 "d5rp emit produced the three streams"; echo "  $pass pass / $fail fail"; echo "  FAIL: test_d5_selection_e2e"; exit 1; }

# The demo scenario's public parameters (d5rp_main.c): CASE-1, seed = i*7+1,
# cutoff=80, draw_height=100. Place roster <= cutoff, h_o < 100 < h_s.
SEED=$("$PY" -c "print(bytes((i*7+1)&255 for i in range(32)).hex())")
CASEID=$("$PY" -c "print('CASE-1'.encode().hex())")
NONMEMBER=$("$PY" -c "print('D5-MEMBER-99'.encode().hex())")

build_blocks() {  # $1=result_payload -> writes $2
  "$PY" - "$ROSTER" "$CASEOPEN" "$1" "$DOMAIN" "$2" <<'PYEOF'
import json, sys
roster, caseopen, result, domain, out = sys.argv[1:6]
def blk(h, p): return {"index": h, "transactions": [{"type": 10, "to": domain, "payload": p}]}
blocks = [blk(5, roster), blk(12, caseopen), blk(110, result)]
with open(out, "w") as f: json.dump(blocks, f)
PYEOF
}

# ── Assertion 1: the published result verifies (no member queried → SELECTED). ──
build_blocks "$RESULT" "$TMP/blocks.json"
OUT=$("$DETERM_LIGHT" verify-selection-offline --blocks "$TMP/blocks.json" \
        --domain "$DOMAIN" --case-id "$CASEID" --seed-hex "$SEED" 2>&1); RC=$?
echo "$OUT" | grep -q "SELECTED" && [ "$RC" = "0" ] \
  && ck 1 "the RP's published result verifies through the REAL citizen path (SELECTED)" \
  || ck 0 "published result SELECTED (got: $OUT / rc=$RC)"

# ── Assertion 2: a non-roster member is NOT_SELECTED. ──
OUT2=$("$DETERM_LIGHT" verify-selection-offline --blocks "$TMP/blocks.json" \
        --domain "$DOMAIN" --case-id "$CASEID" --seed-hex "$SEED" --member "$NONMEMBER" 2>&1)
echo "$OUT2" | grep -q "NOT_SELECTED" \
  && ck 1 "a non-roster member is NOT_SELECTED (never a false SELECTED)" \
  || ck 0 "non-member NOT_SELECTED (got: $OUT2)"

# ── Assertion 3: a byte-flipped result block → UNVERIFIABLE (fail-closed). ──
BADRESULT=$("$PY" -c "
r=bytearray.fromhex('$RESULT'); r[-1]^=0xff; print(r.hex())")
build_blocks "$BADRESULT" "$TMP/bad.json"
OUT3=$("$DETERM_LIGHT" verify-selection-offline --blocks "$TMP/bad.json" \
        --domain "$DOMAIN" --case-id "$CASEID" --seed-hex "$SEED" 2>&1); RC3=$?
echo "$OUT3" | grep -q "UNVERIFIABLE" && [ "$RC3" = "1" ] \
  && ck 1 "a byte-flipped published result is refused (UNVERIFIABLE)" \
  || ck 0 "tampered result UNVERIFIABLE (got: $OUT3 / rc=$RC3)"

echo "  $pass pass / $fail fail"
if [ "$fail" = "0" ]; then echo "  PASS: test_d5_selection_e2e"; exit 0; fi
echo "  FAIL: test_d5_selection_e2e"; exit 1
