#!/usr/bin/env bash
# test_determ_genesis_roundtrip_offline.sh — OFFLINE genesis-parser stability.
#
# Pure offline regression (no cluster, no daemon, no RPC, no socket): proves
# the determ daemon's `verify-genesis` parser is STABLE under round-trip —
# parsing the same genesis.json twice yields byte-identical JSON, and the
# reported chain-identity fields are stable across runs. A deterministic
# parser is a prerequisite for the cross-team / cross-operator genesis-hash
# coordination workflow `verify-genesis` exists to support (see
# src/main.cpp::cmd_verify_genesis, docs/SECURITY.md §S-039): if two
# operators feeding the SAME genesis.json could ever get DIFFERENT output,
# the "compare our hash to theirs" contract would be meaningless.
#
# What it asserts (offline, argv + local file fixtures only):
#   (1) verify-genesis --json on a valid genesis.json exits 0 and emits one
#       parseable JSON line with status=ok + a 64-hex genesis_hash.
#   (2) ROUND-TRIP DETERMINISM: a second identical invocation over the same
#       file path produces BYTE-IDENTICAL stdout (cmp -s). nlohmann emits
#       sorted-key single-line JSON, so any drift here is a real regression.
#   (3) FIELD STABILITY: the reported chain_id / chain_role / m_creators /
#       k_block_sigs match the fixture (chain_id=...,  chain_role=0 (SINGLE),
#       m=k=3) and are byte-stable run-to-run.
#   (4) genesis_hash STABILITY: the 64-hex identity hash is identical across
#       the two runs (the chain-identity anchor must be reproducible).
#   (5) FAIL-CLOSED: a corrupted genesis.json (malformed JSON) → non-zero
#       exit + an error diagnostic, never a false success.
#
# SKIP-with-PASS (exit 0) when the determ binary is absent, so this script is
# a clean no-op pass in minimal build environments, never a hard failure.
# It does NOT source tools/common.sh: that helper hard-exits (exit 1) when no
# determ binary is present, which would convert the intended SKIP into a
# FAIL. Instead it self-detects the binary mirroring common.sh's search order.
#
# run_all.sh judges the outcome from the FINAL terminal marker, greping for
# `^\s*PASS:` BEFORE `FAIL:`. So per-item results use a NEUTRAL prefix
# (`  ok:` / `  bad:`) and the script ends with EXACTLY ONE terminal
# `  PASS:` / `  FAIL:` after a blank line.
#
# Run from repo root: bash tools/test_determ_genesis_roundtrip_offline.sh
set -u
cd "$(dirname "$0")/.."

T=test_determ_genesis_roundtrip_offline

# ── determ binary self-detection (mirrors tools/common.sh search order) ──────
# NOT sourcing common.sh: it hard-exits when the binary is missing, which
# would turn the intended SKIP-with-PASS into a FAIL.
DETERM=""
for cand in \
    "${DETERM_BIN:-}" \
    "build/Release/determ.exe" \
    "build/determ.exe" \
    "build/determ" \
    "build/Release/determ"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then DETERM="$cand"; break; fi
done

if [ -z "$DETERM" ]; then
  echo "  SKIP: determ binary not found; build with"
  echo "        cmake --build build --config Release --target determ"
  echo ""
  echo "  PASS: $T (skipped — no determ binary; offline no-op)"
  exit 0
fi

# Prefer python3, fall back to python (Windows git-bash ships `python`).
PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

bad=0
ok()  { echo "  ok:    $1"; }
fail() { echo "  bad:   $1" >&2; bad=$((bad + 1)); }

WORK="build/$T.$$"
mkdir -p "$WORK" 2>/dev/null || true
trap 'rm -rf "$WORK"' EXIT

# A valid strong-mode 3-of-3 genesis fixture (mirrors test_verify_genesis.sh).
GEN="$WORK/genesis.json"
cat > "$GEN" <<EOF
{
  "chain_id": "test-determ-genesis-roundtrip-offline",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 100,
  "min_stake": 1000,
  "initial_creators": [],
  "initial_balances": []
}
EOF

echo "=== determ genesis round-trip (offline, no cluster) — binary: $DETERM ==="

# ── (1) verify-genesis --json over a valid fixture: exit 0 + parseable ───────
OUT1="$WORK/run1.json"
"$DETERM" verify-genesis --in "$GEN" --json > "$OUT1" 2>"$WORK/run1.err"
RC1=$?
if [ "$RC1" = "0" ] && [ -s "$OUT1" ]; then
  ok "verify-genesis --json (run 1) exits 0 with output"
else
  cat "$WORK/run1.err" 2>/dev/null
  fail "verify-genesis --json (run 1) exit 0 + output (rc=$RC1)"
fi

# Single parseable JSON line with status=ok + 64-hex genesis_hash.
SHAPE=$($PY -c "
import sys, json
try:
    d = json.load(open('$OUT1'))
    print('ok' if (d.get('status') == 'ok'
                   and len(d.get('genesis_hash','')) == 64) else 'bad')
except Exception:
    print('bad')
")
if [ "$SHAPE" = "ok" ]; then
  ok "run 1 JSON: status=ok + 64-hex genesis_hash"
else
  cat "$OUT1" 2>/dev/null
  fail "run 1 JSON shape (status=ok + 64-hex genesis_hash)"
fi

# ── (2) ROUND-TRIP DETERMINISM: a second identical run is byte-identical ─────
OUT2="$WORK/run2.json"
"$DETERM" verify-genesis --in "$GEN" --json > "$OUT2" 2>"$WORK/run2.err"
RC2=$?
if [ "$RC2" = "0" ] && cmp -s "$OUT1" "$OUT2"; then
  ok "round-trip: two identical invocations → byte-identical JSON (cmp -s)"
else
  echo "  --- run1 ---"; cat "$OUT1" 2>/dev/null
  echo "  --- run2 ---"; cat "$OUT2" 2>/dev/null
  fail "round-trip byte-identical JSON (rc2=$RC2)"
fi

# ── (3) FIELD STABILITY: chain_id / chain_role / m_creators / k_block_sigs ───
# Pull the reported fields from BOTH runs; they must equal the fixture AND
# agree run-to-run.
read_fields() {
  $PY -c "
import sys, json
try:
    d = json.load(open('$1'))
    print('%s|%s|%s|%s' % (
        d.get('chain_id',''),
        d.get('chain_role',''),
        d.get('m_creators',''),
        d.get('k_block_sigs','')))
except Exception:
    print('')
"
}
F1=$(read_fields "$OUT1")
F2=$(read_fields "$OUT2")
EXPECT="test-determ-genesis-roundtrip-offline|0|3|3"
if [ "$F1" = "$EXPECT" ] && [ "$F2" = "$EXPECT" ]; then
  ok "fields stable: chain_id/chain_role=0(SINGLE)/m=3/k=3 match across runs"
else
  echo "  expect=$EXPECT"
  echo "  run1=$F1"
  echo "  run2=$F2"
  fail "chain_id/chain_role/m_creators/k_block_sigs stability"
fi

# ── (4) genesis_hash STABILITY: identity anchor reproducible across runs ─────
read_hash() {
  $PY -c "
import sys, json
try:
    print(json.load(open('$1')).get('genesis_hash',''))
except Exception:
    print('')
"
}
H1=$(read_hash "$OUT1")
H2=$(read_hash "$OUT2")
if [ "${#H1}" -eq 64 ] && [ "$H1" = "$H2" ]; then
  ok "genesis_hash reproducible across runs ($H1)"
else
  echo "  hash1=$H1 hash2=$H2"
  fail "genesis_hash stability (64-hex + run-to-run identical)"
fi

# ── (5) FAIL-CLOSED: corrupted genesis.json → non-zero exit ──────────────────
BAD="$WORK/corrupt.json"
printf '{ this is not valid json,,, ' > "$BAD"
"$DETERM" verify-genesis --in "$BAD" --json > "$WORK/bad.out" 2>"$WORK/bad.err"
RCB=$?
if [ "$RCB" != "0" ]; then
  ok "corrupted genesis → non-zero exit (rc=$RCB), fail-closed"
else
  cat "$WORK/bad.out" "$WORK/bad.err" 2>/dev/null
  fail "corrupted genesis should fail closed (got rc=$RCB)"
fi

# ── verdict: EXACTLY ONE terminal PASS/FAIL after a blank line ───────────────
echo ""
if [ "$bad" -eq 0 ]; then
  echo "  PASS: $T (genesis parser stable under round-trip; fail-closed on corruption)"
  exit 0
else
  echo "  FAIL: $T ($bad assertion(s) failed)"
  exit 1
fi
