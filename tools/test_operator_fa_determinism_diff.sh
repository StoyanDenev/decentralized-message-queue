#!/usr/bin/env bash
# test_operator_fa_determinism_diff.sh — regression gate for
# tools/operator_fa_determinism_diff.sh (the cross-toolchain FA
# schedule-signature diff).
#
# Diff-tool contract under test:
#   exit 0  all SIGNATURE lines identical, or SKIP (fewer than two platform
#           binaries present)
#   exit 1  CROSS-TOOLCHAIN DIVERGENCE (signature mismatch)
#   exit 2  harness run failed / SIGNATURE line missing or duplicated / usage
#
# The gate NEVER invokes the real determ binaries: every tool invocation is
# steered through $DETERM_WIN_BIN / $DETERM_LINUX_BIN at stub #!/bin/sh
# scripts created in $TMPD — fast and runnable on any single platform.
# (Both this gate and the tool it gates are deliberately NOT in FAST; the
# tool is operator/CI-local only.)
#
# Assertions:
#   1. --help exits 0 and mentions both env override names
#      (DETERM_WIN_BIN, DETERM_LINUX_BIN).
#   2. SKIP path: both overrides at /nonexistent -> exit 0, output has "SKIP".
#   3. MISMATCH: stub A (trace=aaaa) vs stub B (trace=bbbb) — the stubs
#      branch on "$1" so the adversarial AND crash signature lines both
#      differ -> exit 1, output has "DIVERGENCE".
#   4. MATCH: stub A vs a byte-identical-output COPY (two distinct files)
#      -> exit 0, output has "PASS".
#   5. FAILING binary: a stub exiting 3 -> tool exits 2.
#   6. MISSING signature: a stub exiting 0 with no SIGNATURE line
#      -> tool exits 2.
#
# Exit 0 = all assertions passed.
set -u
cd "$(dirname "$0")/.."

TOOL="tools/operator_fa_determinism_diff.sh"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/fa_difftest.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

# Timeout fence: a hang in the script under test must never wedge the suite.
HAVE_TIMEOUT=""
command -v timeout >/dev/null 2>&1 && HAVE_TIMEOUT=1
run_to() { # run_to SECONDS CMD ARGS...
    local secs="$1"; shift
    if [ -n "$HAVE_TIMEOUT" ]; then timeout "$secs" "$@"; else "$@"; fi
}

if [ ! -f "$TOOL" ]; then
    fail "$TOOL not found"
    echo ""
    echo "  FAIL: test_operator_fa_determinism_diff ($FAILS assertion(s))"
    exit 1
fi

# make_stub PATH TAG — a plain #!/bin/sh stub mimicking the determ FA
# harnesses in --signature mode: ignores extra args, branches on "$1" for
# the adversarial vs crash SIGNATURE flavor, and tags BOTH flavors with TAG
# so two stubs with different tags mismatch on either subcommand.
# (On Windows Git Bash [ -x ] passes for these chmod +x shebang scripts.)
make_stub() {
    cat >"$1" <<EOF
#!/bin/sh
case "\${1:-}" in
  test-fa-crash-deterministic)
    echo "fa-crash-deterministic: PASS (stub)"
    echo "SIGNATURE v1 crash kill=2 trace=$2 n0=$2:$2 n1=$2:$2"
    ;;
  *)
    echo "fa-adversarial-deterministic: PASS (stub)"
    echo "SIGNATURE v1 adversarial trace=$2 faults=1,2,3,4 n0=$2:$2 n1=$2:$2"
    ;;
esac
exit 0
EOF
    chmod +x "$1"
}

# ── assertion 1: --help exits 0 + names both env overrides ────────────────────
HELP="$(run_to 10 bash "$TOOL" --help 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "--help exits 0"
else fail "--help exited $rc (expected 0)"; fi
if echo "$HELP" | grep -q 'DETERM_WIN_BIN' && echo "$HELP" | grep -q 'DETERM_LINUX_BIN'; then
    ok "--help mentions both env overrides (DETERM_WIN_BIN, DETERM_LINUX_BIN)"
else
    fail "--help does not mention both env override names"
fi

# ── assertion 2: SKIP path with no binaries present ───────────────────────────
OUT="$(run_to 10 env DETERM_WIN_BIN=/nonexistent DETERM_LINUX_BIN=/nonexistent bash "$TOOL" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "no binaries present -> exit 0 (SKIP-clean)"
else fail "no-binaries path exited $rc (expected 0)"; fi
if echo "$OUT" | grep -q 'SKIP'; then ok "no-binaries output contains SKIP"
else fail "no-binaries output lacks SKIP"; fi

# ── assertion 3: mismatching stub signatures -> exit 1 + DIVERGENCE ───────────
STUB_A="$TMPD/stub_a"
STUB_B="$TMPD/stub_b"
make_stub "$STUB_A" aaaa
make_stub "$STUB_B" bbbb
OUT="$(run_to 30 env DETERM_WIN_BIN="$STUB_A" DETERM_LINUX_BIN="$STUB_B" bash "$TOOL" 2>&1)"; rc=$?
if [ "$rc" -eq 1 ]; then ok "mismatching stub signatures -> exit 1"
else
    fail "mismatching stubs exited $rc (expected 1)"
    echo "$OUT" | tail -8 | sed 's/^/    | /'
fi
if echo "$OUT" | grep -q 'DIVERGENCE'; then ok "mismatch output contains DIVERGENCE"
else fail "mismatch output lacks DIVERGENCE"; fi

# ── assertion 4: identical-output stubs (two distinct files) -> exit 0 + PASS ─
STUB_A_COPY="$TMPD/stub_a_copy"
make_stub "$STUB_A_COPY" aaaa
OUT="$(run_to 30 env DETERM_WIN_BIN="$STUB_A" DETERM_LINUX_BIN="$STUB_A_COPY" bash "$TOOL" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "identical-output stubs -> exit 0"
else
    fail "identical-output stubs exited $rc (expected 0)"
    echo "$OUT" | tail -8 | sed 's/^/    | /'
fi
if echo "$OUT" | grep -q 'PASS'; then ok "match output contains PASS"
else fail "match output lacks PASS"; fi

# ── assertion 5: failing binary (exit 3) -> tool exits 2 ──────────────────────
STUB_RC3="$TMPD/stub_rc3"
cat >"$STUB_RC3" <<'EOF'
#!/bin/sh
echo "stub: simulated harness assertion failure"
exit 3
EOF
chmod +x "$STUB_RC3"
OUT="$(run_to 30 env DETERM_WIN_BIN="$STUB_RC3" DETERM_LINUX_BIN="$STUB_A" bash "$TOOL" 2>&1)"; rc=$?
if [ "$rc" -eq 2 ]; then ok "failing binary (exit 3) -> tool exits 2"
else
    fail "failing-binary path exited $rc (expected 2)"
    echo "$OUT" | tail -8 | sed 's/^/    | /'
fi

# ── assertion 6: no SIGNATURE line (exit 0) -> tool exits 2 ───────────────────
STUB_NOSIG="$TMPD/stub_nosig"
cat >"$STUB_NOSIG" <<'EOF'
#!/bin/sh
echo "fa harness: PASS (stub, deliberately no signature line)"
exit 0
EOF
chmod +x "$STUB_NOSIG"
OUT="$(run_to 30 env DETERM_WIN_BIN="$STUB_NOSIG" DETERM_LINUX_BIN="$STUB_A" bash "$TOOL" 2>&1)"; rc=$?
if [ "$rc" -eq 2 ]; then ok "missing SIGNATURE line -> tool exits 2"
else
    fail "missing-signature path exited $rc (expected 2)"
    echo "$OUT" | tail -8 | sed 's/^/    | /'
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_operator_fa_determinism_diff (diff-tool contract: --help names both env overrides, SKIP-clean exit 0 with <2 binaries, stub signature mismatch -> exit 1 + DIVERGENCE, identical-output stubs -> exit 0 + PASS, failing binary -> exit 2, missing SIGNATURE line -> exit 2; real determ binaries never invoked)"
    exit 0
else
    echo "  FAIL: test_operator_fa_determinism_diff ($FAILS assertion(s))"
    exit 1
fi
