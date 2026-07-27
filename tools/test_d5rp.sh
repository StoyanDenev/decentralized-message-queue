#!/usr/bin/env bash
# D.5 inc.6a — d5rp, the reference-RP producer (dapps/d5-random-selection, BUSL-1.1).
# The orchestrator side of D.5: it PRODUCES the three canonical-binary DAPP_CALL
# streams (roster / case-open / result) from the shipped Apache-2.0 primitives
# (determ-crypto-c99: d5codec + d5draw), with NO consensus authority.
#
# GATE (FAST, offline; the `d5rp selftest` subcommand): produce the three streams
# for a fixed scenario, strip each DAPP_CALL envelope, decode via d5codec, and
# INDEPENDENTLY re-derive the lowest-hash draw over the decoded roster + seed —
# asserting it EQUALS the published `result`. This is exactly the contract the
# Apache-2.0 citizen verifier (`determ-light verify-selection`) enforces, so an
# honest RP's output is provably re-derivable. A tamper NEG flips one byte of a
# published selected id and confirms the round-trip CATCHES it.
# Falsify-on-mutant: mutate d5_rp_open_and_draw to publish a non-canonical result
# -> ONLY the CTRL "published == canonical" assertion flips RED.
#
# NB: never `echo "$OUT"` raw on success (the subcommand's FAIL: lines on a
# failing run would reach run_all's tail-10 marker scan).
set -u
cd "$(dirname "$0")/.."

# Locate d5rp: prefer the ci_local export (native build), else probe the
# standard MSVC / single-config layouts (mirrors tools/common.sh).
D5RP="${DETERM_D5RP_BIN:-}"
if [ -z "$D5RP" ]; then
  for c in build/Release/d5rp.exe build/d5rp.exe build/d5rp build/Release/d5rp \
           build-linux/d5rp build-linux/Release/d5rp; do
    [ -x "$c" ] && { D5RP="$c"; break; }
  done
fi
if [ -z "$D5RP" ] || [ ! -x "$D5RP" ]; then
  echo "  SKIP: d5rp binary not found; build with"
  echo "        cmake --build build --config Release --target d5rp"
  exit 0
fi

# ── 1. the C self-contained round-trip gate ──
OUT=$("$D5RP" selftest 2>&1); RC=$?
if [ "$RC" -ne 0 ] || ! echo "$OUT" | grep -q "PASS: selftest-d5rp"; then
  echo "  FAIL: test_d5rp (C selftest)"
  echo "$OUT" | grep -E "FAIL|pass / " | head -10
  exit 1
fi

# ── 2. INDEPENDENT dual-oracle (python-prove-first): parse the DAPP_CALL envelope
#       + d5codec + re-derive the lowest-hash draw with a separate implementation
#       (tools/verify_d5rp.py, shares no code with the C producer / its selftest),
#       asserting the RP's published `result` == the independent canonical draw. ──
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! "$PY" tools/verify_d5rp.py --selftest >/dev/null 2>&1; then
  echo "  FAIL: test_d5rp (python oracle selftest failed)"; exit 1
fi
if ! "$D5RP" emit | "$PY" tools/verify_d5rp.py --check - >/dev/null 2>&1; then
  echo "  FAIL: test_d5rp (independent oracle rejected the RP's emit output)"; exit 1
fi

# ── 3. no-drift: the committed vector must equal the current emit bytes. ──
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
"$D5RP" emit | "$PY" tools/verify_d5rp.py --gen - --out "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP" tools/vectors/d5rp.json >/dev/null 2>&1; then
  echo "  FAIL: test_d5rp (committed tools/vectors/d5rp.json drifted from d5rp emit)"; exit 1
fi

echo "  PASS: test_d5rp"
exit 0
