#!/usr/bin/env bash
# S-035 Path 3: portable test helpers.
#
# Tests source this file to pick up:
#   - DETERM         — path to the determ binary, platform-detected
#                      (build/Release/determ.exe on Windows /
#                      build/determ on Linux/Mac single-config builds).
#   - DETERM_WALLET  — same for the wallet binary.
#   - PROJECT_ROOT   — absolute path to the repo root, computed via
#                      `pwd` after the caller's `cd "$(dirname "$0")/.."`.
#                      Replaces hard-coded `C:/sauromatae` in JSON
#                      config emission (chain_path, key_path, etc.).
#
# Sourcing protocol:
#
#   #!/usr/bin/env bash
#   set -u
#   cd "$(dirname "$0")/.."
#   source tools/common.sh
#   # ... use $DETERM, $DETERM_WALLET, $PROJECT_ROOT ...
#
# The detection logic prefers an explicit DETERM_BIN / DETERM_WALLET_BIN
# environment variable so CI runners can point at any custom build
# layout without editing the tests. Defaults follow the on-disk build
# tree this repo currently produces under both MSVC (multi-config:
# build/Release/determ.exe) and single-config generators (Makefiles /
# Ninja on Linux/Mac: build/determ).
#
# The repo root computation assumes the caller cd'd to the repo root
# via `cd "$(dirname "$0")/.."` first. That's already the convention
# every existing test followed before S-035 Path 3.

# ── PROJECT_ROOT ───────────────────────────────────────────────────────────────
# On Git Bash for Windows, plain `pwd` returns a /c/foo/bar style path
# (MSYS-virtualized). The determ binary is a native Windows executable
# and doesn't understand those — it tries to open the literal MSYS path
# and fails with "Cannot open file: /c/...". Convert to Windows-style
# C:/foo/bar via `pwd -W` (Git Bash native) or `cygpath -m` (Cygwin),
# falling back to plain `pwd` for Linux/Mac where no conversion is
# needed.
if pwd -W >/dev/null 2>&1; then
    PROJECT_ROOT="$(pwd -W)"        # Git Bash on Windows
elif command -v cygpath >/dev/null 2>&1; then
    PROJECT_ROOT="$(cygpath -m "$(pwd)")"  # Cygwin
else
    PROJECT_ROOT="$(pwd)"           # Linux / Mac (no conversion needed)
fi

# ── DETERM (chain daemon binary) ───────────────────────────────────────────────
if [ -n "${DETERM_BIN:-}" ]; then
    DETERM="$DETERM_BIN"
elif [ -x "build/Release/determ.exe" ]; then
    DETERM="build/Release/determ.exe"   # Windows MSVC multi-config
elif [ -x "build/determ.exe" ]; then
    DETERM="build/determ.exe"           # Windows single-config (rare)
elif [ -x "build/determ" ]; then
    DETERM="build/determ"               # Linux / Mac single-config
elif [ -x "build/Release/determ" ]; then
    DETERM="build/Release/determ"       # Linux / Mac multi-config (rare)
else
    echo "common.sh: cannot find determ binary; tried:" >&2
    echo "  build/Release/determ.exe (Windows MSVC multi-config)" >&2
    echo "  build/determ.exe        (Windows single-config)" >&2
    echo "  build/determ            (Linux/Mac single-config)" >&2
    echo "  build/Release/determ    (Linux/Mac multi-config)" >&2
    echo "Set DETERM_BIN=/absolute/path to override." >&2
    exit 1
fi

# ── DETERM_WALLET (separate wallet binary) ────────────────────────────────────
if [ -n "${DETERM_WALLET_BIN:-}" ]; then
    DETERM_WALLET="$DETERM_WALLET_BIN"
elif [ -x "build/Release/determ-wallet.exe" ]; then
    DETERM_WALLET="build/Release/determ-wallet.exe"
elif [ -x "build/determ-wallet.exe" ]; then
    DETERM_WALLET="build/determ-wallet.exe"
elif [ -x "build/determ-wallet" ]; then
    DETERM_WALLET="build/determ-wallet"
elif [ -x "build/Release/determ-wallet" ]; then
    DETERM_WALLET="build/Release/determ-wallet"
else
    # Wallet binary is optional for tests that don't exercise it.
    # Don't fail the source; leave DETERM_WALLET unset.
    DETERM_WALLET=""
fi

# ── DETERM_LIGHT (light-client binary) ────────────────────────────────────────
# Third Determ binary (alongside `determ` + `determ-wallet`): the
# trust-minimized light-client that verifies every RPC response
# against a pinned genesis hash + committee-signed state_root.
# Optional like the wallet — tests that don't exercise it skip the
# detection block entirely.
if [ -n "${DETERM_LIGHT_BIN:-}" ]; then
    DETERM_LIGHT="$DETERM_LIGHT_BIN"
elif [ -x "build/Release/determ-light.exe" ]; then
    DETERM_LIGHT="build/Release/determ-light.exe"
elif [ -x "build/determ-light.exe" ]; then
    DETERM_LIGHT="build/determ-light.exe"
elif [ -x "build/determ-light" ]; then
    DETERM_LIGHT="build/determ-light"
elif [ -x "build/Release/determ-light" ]; then
    DETERM_LIGHT="build/Release/determ-light"
else
    # Light-client is optional for tests that don't exercise it.
    DETERM_LIGHT=""
fi

# ── DETERM_CRYPTOTEST (OpenSSL test-oracle binary) ────────────────────────────
# Standalone crypto test-oracle binary (cryptotest/main.cpp): carries the 11
# pure-oracle test-*-c99 subcommands split out of the daemon per
# docs/proofs/MinixTacticalProfile.md §6, so `determ` links zero OpenSSL.
# Optional like the wallet/light — tests that don't exercise it skip the
# detection block entirely; the test-*-c99 wrappers do their own fail when
# it is absent.
if [ -n "${DETERM_CRYPTOTEST_BIN:-}" ]; then
    DETERM_CRYPTOTEST="$DETERM_CRYPTOTEST_BIN"
elif [ -x "build/Release/determ-cryptotest.exe" ]; then
    DETERM_CRYPTOTEST="build/Release/determ-cryptotest.exe"
elif [ -x "build/determ-cryptotest.exe" ]; then
    DETERM_CRYPTOTEST="build/determ-cryptotest.exe"
elif [ -x "build/determ-cryptotest" ]; then
    DETERM_CRYPTOTEST="build/determ-cryptotest"
elif [ -x "build/Release/determ-cryptotest" ]; then
    DETERM_CRYPTOTEST="build/Release/determ-cryptotest"
else
    # Crypto-oracle binary is optional for tests that don't exercise it.
    DETERM_CRYPTOTEST=""
fi

# ── DETERM_DSF (deterministic simulation framework binary) ────────────────────
# Test-only fourth binary: the DSF core (virtual clock + scheduler + scenario
# DSL + property checker). Optional like the wallet/light — tests that don't
# exercise it skip it. Self-contained (no OpenSSL / no determ core link).
if [ -n "${DETERM_DSF_BIN:-}" ]; then
    DETERM_DSF="$DETERM_DSF_BIN"
elif [ -x "build/Release/determ-dsf.exe" ]; then
    DETERM_DSF="build/Release/determ-dsf.exe"
elif [ -x "build/determ-dsf.exe" ]; then
    DETERM_DSF="build/determ-dsf.exe"
elif [ -x "build/determ-dsf" ]; then
    DETERM_DSF="build/determ-dsf"
elif [ -x "build/Release/determ-dsf" ]; then
    DETERM_DSF="build/Release/determ-dsf"
else
    DETERM_DSF=""
fi

# ── Absolutize binary paths (Windows Python-subprocess portability) ────────────
# The detection above yields paths RELATIVE to the repo root (e.g.
# build/Release/determ.exe). Bash resolves a relative-with-slash path against
# the cwd fine, so direct `$DETERM ...` invocations work everywhere. But a
# Python `subprocess.run([$DETERM, ...])` on native Windows goes through
# CreateProcess, which does NOT search the cwd for the executable — a relative
# path raises FileNotFoundError [WinError 2]. That silently broke every test
# whose wallet-grinder/helper spawns the binary from Python (test_cross_shard_
# transfer's grinder produced 0 wallets → empty privkey → "hex length mismatch"
# → the cross-shard flow never ran; test_light_verify_receipt_inclusion too).
# These tests pass on Linux/CI (POSIX execvp resolves relative-with-slash) and
# only fail on native Git-Bash + Windows-Python. Prefixing $PROJECT_ROOT (already
# an absolute, Windows-native path via `pwd -W`) makes every invocation portable.
# Bash exec of an absolute path is identical to the relative one, and the
# operator_*.sh scripts' own `case "$DETERM"` absolutizers take their
# already-absolute branch (drive-letter / leading-slash), so nothing double-
# prefixes. An operator-supplied DETERM_BIN that is already absolute is left
# untouched.
_dt_abs() {  # echo $1 made absolute under PROJECT_ROOT unless empty/already-absolute
    case "$1" in
        ""|/*|[A-Za-z]:[/\\]*) printf '%s' "$1" ;;
        *)                     printf '%s/%s' "$PROJECT_ROOT" "$1" ;;
    esac
}
DETERM="$(_dt_abs "$DETERM")"
DETERM_WALLET="$(_dt_abs "$DETERM_WALLET")"
DETERM_LIGHT="$(_dt_abs "$DETERM_LIGHT")"
DETERM_CRYPTOTEST="$(_dt_abs "$DETERM_CRYPTOTEST")"

export PROJECT_ROOT DETERM DETERM_WALLET DETERM_LIGHT DETERM_CRYPTOTEST
