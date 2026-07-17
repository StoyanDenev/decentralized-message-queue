#!/usr/bin/env bash
# operator_fa_determinism_diff.sh — cross-toolchain schedule-divergence
# detector for the deterministic FA harnesses.
#
# The determ binary's two deterministic FA harness subcommands
#
#   test-fa-adversarial-deterministic
#   test-fa-crash-deterministic
#
# accept a --signature second argument: after their normal PASS/FAIL output
# they print exactly ONE extra stdout line starting with "SIGNATURE v1 "
# fingerprinting the full deterministic schedule (trace hash, fault counts,
# per-node state digests). Two byte-identical schedules produce byte-identical
# SIGNATURE lines — so running BOTH platform binaries (MSVC + the Linux/GCC
# build) and byte-comparing their SIGNATURE lines detects a cross-toolchain
# schedule/state divergence (the UB-determinism fork class ci_local.sh exists
# for) without needing a LIVE cluster.
#
# Binary discovery:
#   windows: $DETERM_WIN_BIN,   default build/Release/determ.exe
#   linux:   $DETERM_LINUX_BIN, default build-linux/determ
# A binary counts as present if the file exists and is executable ([ -x ]).
# With FEWER than two binaries present the script SKIPs (exit 0) — the
# standard operator-tool convention: single-platform checkouts stay green.
#
# RUNTIME NOTE: each harness runs its scenario TWICE internally (the replay
# check), so expect several seconds per binary per subcommand. This is an
# OPERATOR / CI-local tool, deliberately NOT in FAST.
#
# NOTE: SIGNATURE lines are compared after stripping a trailing CR only — the
# MSVC binary writes CRLF stdout; the newline convention is a platform
# artifact, not a schedule divergence. Everything else is byte-exact.
#
# Usage:
#   tools/operator_fa_determinism_diff.sh
#   DETERM_WIN_BIN=/abs/determ.exe DETERM_LINUX_BIN=/abs/determ \
#       tools/operator_fa_determinism_diff.sh
#
# Exit codes:
#   0   signatures identical for every subcommand (or SKIP: fewer than two
#       binaries present)
#   1   CROSS-TOOLCHAIN DIVERGENCE (mismatching SIGNATURE lines, both
#       printed and labeled by binary)
#   2   a harness run failed (non-zero exit), or did not print exactly one
#       SIGNATURE line, or usage error
set -u
cd "$(dirname "$0")/.."

usage() {
  cat <<EOF
Usage: tools/operator_fa_determinism_diff.sh [--help]

Runs BOTH platform determ binaries' deterministic FA harnesses in
--signature mode and byte-compares their SIGNATURE v1 lines:

  windows binary: \$DETERM_WIN_BIN   (default: build/Release/determ.exe)
  linux binary:   \$DETERM_LINUX_BIN (default: build-linux/determ)

Subcommands compared:
  test-fa-adversarial-deterministic
  test-fa-crash-deterministic

With fewer than two binaries present the script SKIPs (exit 0). Each
harness runs its scenario twice internally (replay check) — expect
several seconds per binary per subcommand. OPERATOR / CI-local tool,
deliberately NOT in FAST.

Exit codes:
  0   all signatures identical (or SKIP: fewer than two binaries present)
  1   CROSS-TOOLCHAIN DIVERGENCE (both lines printed, labeled by binary)
  2   harness run failed / SIGNATURE line missing or duplicated / usage error
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "operator_fa_determinism_diff: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

WIN_BIN="${DETERM_WIN_BIN:-build/Release/determ.exe}"
LINUX_BIN="${DETERM_LINUX_BIN:-build-linux/determ}"

PRESENT=0
WIN_STATE="MISSING or not executable"
LINUX_STATE="MISSING or not executable"
if [ -x "$WIN_BIN" ]; then WIN_STATE="present"; PRESENT=$((PRESENT + 1)); fi
if [ -x "$LINUX_BIN" ]; then LINUX_STATE="present"; PRESENT=$((PRESENT + 1)); fi

if [ "$PRESENT" -lt 2 ]; then
  echo "SKIP: cross-toolchain FA determinism diff needs BOTH platform binaries; found $PRESENT/2:"
  echo "  windows: $WIN_BIN [$WIN_STATE]  (override: \$DETERM_WIN_BIN)"
  echo "  linux:   $LINUX_BIN [$LINUX_STATE]  (override: \$DETERM_LINUX_BIN)"
  echo "  build the missing binary (or point its env override at one) to enable the diff."
  exit 0
fi

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/fa_detdiff.$$")"
mkdir -p "$TMPD" || {
  echo "operator_fa_determinism_diff: cannot create workdir '$TMPD'" >&2
  exit 2
}
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

SUBS="test-fa-adversarial-deterministic test-fa-crash-deterministic"

# extract_sig LABEL BIN SUB SIGFILE — run "$BIN" SUB --signature capturing
# stdout+stderr, gate exit 0 + exactly one "SIGNATURE v1 " line, write the
# (trailing-CR-stripped) line to SIGFILE. Any violation: FAIL + exit 2.
# set -u only (no -e), so a zero-match grep cannot abort the script; the
# capture-then-test pattern is kept anyway per the tools/ convention.
extract_sig() {
  local label="$1" bin="$2" sub="$3" sigfile="$4"
  local out="$TMPD/${label}_${sub}.out"
  local rc nsig
  "$bin" "$sub" --signature >"$out" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: $label binary '$bin' $sub --signature exited $rc (expected 0)"
    echo "  last 5 output lines:"
    tail -5 "$out" | sed 's/^/    | /'
    exit 2
  fi
  nsig="$(grep -c '^SIGNATURE v1 ' "$out" 2>/dev/null || true)"
  case "$nsig" in ""|*[!0-9]*) nsig=0 ;; esac
  if [ "$nsig" -ne 1 ]; then
    echo "FAIL: $label binary '$bin' $sub --signature printed $nsig 'SIGNATURE v1 ' line(s) (expected exactly 1)"
    echo "  last 5 output lines:"
    tail -5 "$out" | sed 's/^/    | /'
    exit 2
  fi
  grep '^SIGNATURE v1 ' "$out" | tr -d '\r' >"$sigfile"
}

echo "=== FA cross-toolchain determinism diff ==="
echo "    windows: $WIN_BIN"
echo "    linux:   $LINUX_BIN"
echo "    (each harness runs its scenario twice internally — several seconds per run)"
echo ""

NSUB=0
for SUB in $SUBS; do
  WSIG="$TMPD/windows_${SUB}.sig"
  LSIG="$TMPD/linux_${SUB}.sig"
  extract_sig windows "$WIN_BIN" "$SUB" "$WSIG"
  extract_sig linux   "$LINUX_BIN" "$SUB" "$LSIG"
  if cmp -s "$WSIG" "$LSIG"; then
    echo "  OK: $SUB signatures identical"
    sed 's/^/      /' "$WSIG"
    NSUB=$((NSUB + 1))
  else
    echo "  MISMATCH: $SUB"
    echo "    windows ($WIN_BIN):"
    sed 's/^/      /' "$WSIG"
    echo "    linux ($LINUX_BIN):"
    sed 's/^/      /' "$LSIG"
    echo "CROSS-TOOLCHAIN DIVERGENCE"
    exit 1
  fi
done

echo ""
echo "PASS: cross-toolchain signatures identical ($NSUB subcommands)"
exit 0
