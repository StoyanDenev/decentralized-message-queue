#!/usr/bin/env bash
# Live byte-equal cross-validation of the WHOLE libsodium-free C99 crypto stack
# (Argon2id, BLAKE2b, X25519, XChaCha20-Poly1305) against libsodium — the explicit
# equivalence proof that the determ daemon's C99 primitives reproduce libsodium
# byte-for-byte, so migrating the libsodium call sites (e.g. the keyfile KDF) onto
# the C99 stack is provably behaviour-preserving.
#
# This compiles tools/c99_libsodium_xval.c standalone against the build tree's
# libsodium.a (a FetchContent artifact). It is NOT a FAST in-process test: it needs
# a compiler + a prior build. If libsodium.a / a compiler are absent it SKIPS with a
# PASS (so it is a no-op in minimal environments) rather than failing.
set -u
cd "$(dirname "$0")/.."

SODLIB=$(find build -name "libsodium.a" 2>/dev/null | head -1)
SODINC=$(find build -path "*libsodium*/include/sodium.h" 2>/dev/null | head -1)
SODINC=${SODINC%/sodium.h}
CC=${CC:-cc}

if [ -z "$SODLIB" ] || [ -z "$SODINC" ]; then
  echo "  SKIP: libsodium.a / headers not found under build/ (run a build first); xval not run"
  echo "  PASS: c99-libsodium-xval (skipped — no libsodium artifact)"
  exit 0
fi
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "  SKIP: no C compiler ($CC); xval not run"
  echo "  PASS: c99-libsodium-xval (skipped — no compiler)"
  exit 0
fi

BIN=$(mktemp -u /tmp/c99xval.XXXXXX)
echo "=== compiling c99_libsodium_xval against $SODLIB ==="
"$CC" -O2 -I include -I "$SODINC" \
  tools/c99_libsodium_xval.c \
  src/crypto/argon2/argon2id.c \
  src/crypto/blake2/blake2b.c \
  src/crypto/x25519/x25519.c \
  src/crypto/chacha20/chacha20.c \
  src/crypto/chacha20/poly1305.c \
  src/crypto/chacha20/chacha20_poly1305.c \
  src/crypto/chacha20/xchacha20_poly1305.c \
  src/crypto/secure_zero.c \
  "$SODLIB" -lpthread -o "$BIN" || { echo "  FAIL: harness compile failed"; exit 1; }

OUT=$("$BIN" 2>&1); rc=$?
echo "$OUT"
rm -f "$BIN"
if [ $rc -eq 0 ] && echo "$OUT" | tail -2 | grep -q "PASS: c99-libsodium-xval"; then
  echo ""; echo "  PASS: c99-libsodium-xval unit test"; exit 0
else
  echo ""; echo "  FAIL: c99-libsodium-xval had mismatches"; exit 1
fi
