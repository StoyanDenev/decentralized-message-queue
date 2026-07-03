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
#   tools/ci_local.sh --sanitize [--jobs N]   # UBSan pass over the consensus
#                                             # surface (Linux/GCC-only, heavier)
#   tools/ci_local.sh --help
#
# From Windows, run it inside WSL2:
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh'
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh --sanitize'
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
SANITIZE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --sanitize) SANITIZE=1; shift ;;
    *) echo "unknown arg: $1 (see --help)"; exit 1 ;;
  esac
done

# ── UBSan mode (--sanitize): the undefined-behavior net for the consensus
# path. The 2026-07-03 state_root fork was a uint32 shift-UB that MSVC and
# GCC resolved differently; UBSan flags that class at the point of execution
# with a file:line. Builds `determ` with UBSan scoped to Determ's OWN targets
# (via -DDETERM_UBSAN=ON — the vendored OpenSSL/asio/json are NOT instrumented,
# so no dep-side noise and no whole-tree rebuild) and runs the consensus-
# serialization + arithmetic + determinism subcommands under it — the surfaces
# where a determinism-breaking UB would live. Linux/GCC-only and a bit heavier
# than the fast gate, so it is an OPT-IN job, not part of the default ci_local
# pass. ASan is intentionally NOT enabled (its shadow-memory instrumentation
# OOMs on the large main.cpp TU; memory-safety is a separable concern).
if [ "$SANITIZE" -eq 1 ]; then
  SAN_DIR="build-linux-ubsan"
  echo "=== ci_local --sanitize: UBSan build of determ ($SAN_DIR) ==="
  # -DDETERM_UBSAN=ON instruments ONLY Determ's own targets (determ +
  # determ-crypto-c99); the vendored OpenSSL/asio/json stay uninstrumented and
  # are reused from cache, so this is just the ~18 Determ TUs (not a whole-tree
  # sanitized rebuild). No dep instrumentation means no dep-side UBSan noise,
  # so no ignorelist/suppressions are needed. Abort-on-UB is enforced at
  # runtime via UBSAN_OPTIONS (a compile-time -fno-sanitize-recover would abort
  # unrelated CMake feature-tests).
  cmake -B "$SAN_DIR" -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDETERM_UBSAN=ON \
    >/dev/null 2>&1 || { echo "FAIL: UBSan configure"; exit 1; }
  cmake --build "$SAN_DIR" --config RelWithDebInfo -j "$JOBS" --target determ \
    2>&1 | grep -iE "error:|runtime error" && { echo "FAIL: UBSan build error"; exit 1; }
  SANBIN=$(find "$SAN_DIR" -maxdepth 2 -name determ -type f -perm -u+x | head -1)
  [ -x "$SANBIN" ] || { echo "FAIL: UBSan determ binary not found"; exit 1; }
  export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
  echo "=== ci_local --sanitize: run consensus/determinism + full c99-crypto surface under UBSan ==="
  # The consensus/determinism/arithmetic surface + the ENTIRE determ::c99 crypto
  # stack. The crypto set is load-bearing: the first --sanitize run (2026-07-03)
  # caught a left-shift-of-negative UB (C-standard UB) in the TweetNaCl-derived
  # car25519/modL of ed25519.c + x25519.c — byte-invariant but flagged; fixed.
  # (cwd is the repo root — see the `cd` at the top — so test-c99-vectors
  #  resolves its tests/vectors/*.json corpus.)
  SAN_CMDS="test-consensus-vectors test-state-root-determinism test-tx-signing-determinism \
            test-merge-event-determinism test-genesis-determinism test-state-proof-composite-key \
            test-cross-shard-atomicity test-cross-shard-multi-receipt test-cross-shard-outbound-apply \
            test-block-digest test-tx-root test-merkle test-overflow-paths \
            test-sha256 test-sha2-c99 test-blake2b-c99 test-chacha20-c99 test-xchacha-c99 \
            test-aes-c99 test-argon2id-c99 test-ct-c99 test-ed25519-c99 test-ed25519-vectors \
            test-ed25519-scalar-reduce test-x25519-c99 test-p256-c99 test-p256-h2c-c99 \
            test-p256-oprf-c99 test-frost-c99 test-c99-vectors test-c99-api"
  san_fail=0
  for cmd in $SAN_CMDS; do
    if "$SANBIN" "$cmd" >/tmp/ubsan_out.txt 2>&1; then
      echo "  PASS(ubsan): $cmd"
    else
      echo "  FAIL(ubsan): $cmd"; grep -iE "runtime error|undefined|shift" /tmp/ubsan_out.txt | head -3
      san_fail=1
    fi
  done
  [ "$san_fail" -eq 0 ] && { echo ""; echo "PASS: ci-local --sanitize (UBSan) clean over the consensus surface"; exit 0; }
  echo ""; echo "FAIL: ci-local --sanitize (UBSan) found undefined behavior"; exit 1
fi

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
