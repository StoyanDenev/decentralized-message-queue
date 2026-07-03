#!/usr/bin/env bash
# tools/ci_local.sh — the local second-platform verification gate.
#
# Builds all three binaries (determ, determ-wallet, determ-light) and runs
# the FAST=1 suite + the offline doc-coherence guards on the CURRENT
# platform's toolchain. Running it inside WSL2 Ubuntu (or any Linux) gives
# the green surface a second, independent platform: GCC/Linux next to the
# primary MSVC/Windows box — the "green on one laptop" -> "green on two
# toolchains" upgrade (DECISION-LOG.md context: single-box verification was
# the top open operational issue after the 2026-07-03 consolidation).
#
# Usage:
#   tools/ci_local.sh [--build-dir DIR] [--skip-build] [--jobs N]
#   tools/ci_local.sh --help
#
# From Windows, run it inside WSL2:
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh'
#
# Defaults: build dir is `build-linux` on Linux/macOS, `build` on Windows
# (so the Linux tree never clashes with the MSVC multi-config tree).
# The suite is pointed at the fresh binaries via the DETERM_BIN /
# DETERM_WALLET_BIN / DETERM_LIGHT_BIN overrides tools/common.sh honors.
#
# Exit: 0 = build + FAST + guards all green; non-zero otherwise.
# GitHub Actions runs the same content (.github/workflows/ci.yml).
set -u
cd "$(dirname "$0")/.."

JOBS=$( (command -v nproc >/dev/null && nproc) || echo 4 )
SKIP_BUILD=0
BUILD_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    *) echo "unknown arg: $1 (see --help)"; exit 1 ;;
  esac
done

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) DEFAULT_DIR="build" ;;
  *)                    DEFAULT_DIR="build-linux" ;;
esac
BUILD_DIR="${BUILD_DIR:-$DEFAULT_DIR}"

echo "=== ci_local: platform $(uname -sm), build dir $BUILD_DIR, jobs $JOBS ==="

if [ "$SKIP_BUILD" -eq 0 ]; then
  echo "=== ci_local: configure ==="
  cmake -B "$BUILD_DIR" -S . -DCMAKE_BUILD_TYPE=Release || {
    echo "FAIL: ci-local configure failed"; exit 1; }
  echo "=== ci_local: build determ + determ-wallet + determ-light ==="
  cmake --build "$BUILD_DIR" --config Release -j "$JOBS" \
        --target determ determ-wallet determ-light || {
    echo "FAIL: ci-local build failed"; exit 1; }
fi

# Locate the fresh binaries (single-config layout on Linux, Release/ on MSVC).
find_bin() {
  for c in "$BUILD_DIR/$1" "$BUILD_DIR/Release/$1" \
           "$BUILD_DIR/$1.exe" "$BUILD_DIR/Release/$1.exe"; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}
DETERM_BIN=$(find_bin determ)               || { echo "FAIL: determ binary not found under $BUILD_DIR"; exit 1; }
DETERM_WALLET_BIN=$(find_bin determ-wallet) || { echo "FAIL: determ-wallet binary not found"; exit 1; }
DETERM_LIGHT_BIN=$(find_bin determ-light)   || { echo "FAIL: determ-light binary not found"; exit 1; }
export DETERM_BIN DETERM_WALLET_BIN DETERM_LIGHT_BIN
echo "=== ci_local: binaries: $DETERM_BIN | $DETERM_WALLET_BIN | $DETERM_LIGHT_BIN ==="

echo "=== ci_local: FAST=1 suite ==="
FAST=1 QUIET=1 bash tools/run_all.sh || { echo "FAIL: ci-local FAST suite RED"; exit 1; }

echo "=== ci_local: offline doc-coherence guards ==="
GUARDS_OK=1
for g in test_doc_citation_bounds test_doc_tier_check test_docs_link_check \
         test_proofs_index_complete test_frost_chain_guard; do
  if [ -f "tools/$g.sh" ]; then
    if bash "tools/$g.sh" >/dev/null 2>&1; then
      echo "  PASS: $g"
    else
      echo "  FAIL: $g"; GUARDS_OK=0
    fi
  fi
done
[ "$GUARDS_OK" -eq 1 ] || { echo "FAIL: ci-local doc guards RED"; exit 1; }

echo ""
echo "PASS: ci-local build + FAST + guards green on $(uname -sm)"
