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

export PROJECT_ROOT DETERM DETERM_WALLET
