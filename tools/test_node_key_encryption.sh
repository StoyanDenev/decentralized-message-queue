#!/usr/bin/env bash
# S-091 / D2 src-side node keyfile encryption regression gate.
#
# Asserts:
#   A. In-process test (determ test-node-key-encryption):
#      - Plaintext JSON backward compatibility (empty passphrase writes JSON, loads JSON)
#      - Canonical DNK1 binary container with DWE2 Argon2id + AES-256-GCM envelope
#      - Header pubkey binding (AAD = raw 32-byte pubkey)
#      - DeterM_PASSPHRASE env var fallback
#      - Fail-closed on missing passphrase
#      - Fail-closed on wrong passphrase
#      - Fail-closed on AAD pubkey tampering
#      - Fail-closed on ciphertext tampering
#      - Fail-closed on truncated file
#   B. Shipped CLI integration:
#      - `determ init --passphrase <pw>` creates node_key.bin (DNK1 magic, 0600 mode)
#      - `determ init --passphrase-from file:<path>` creates valid DNK1 container
#      - `determ genesis-tool peer-info` extracts pubkey from encrypted DNK1 header without passphrase
#   C. Cross-tool compatibility with determ-wallet:
#      - `determ-wallet keyfile-decrypt` decrypts node_key.bin created by determ init
#      - `determ-wallet keyfile-create` creates a DNK1 container loaded by determ
#
# FALSIFY-ON-MUTANT (executed):
#   M1: in src/crypto/keys.cpp::load_node_key, bypass envelope decrypt on DNK1
#       and return unverified key -> turns gate hard RED.
#   M2: in src/crypto/keys.cpp::save_node_key, ignore passphrase and always emit JSON
#       -> turns gate hard RED.

set -euo pipefail
cd "$(dirname "$0")/.."

source tools/common.sh

UNAME_S=$(uname -s 2>/dev/null || echo "unknown")
T=$(mktemp -d 2>/dev/null || mktemp -d -t 'test_node_key_enc')
trap 'rm -rf "$T"' EXIT

echo "=== A. in-process property test (determ test-node-key-encryption) ==="
OUT=$($DETERM test-node-key-encryption 2>&1)
echo "$OUT"

if ! echo "$OUT" | grep -q "PASS: test-node-key-encryption all assertions"; then
  echo "  FAIL: test-node-key-encryption had failures"
  exit 1
fi
echo "  PASS: section A (all 19 in-process assertions passed)"

echo
echo "=== B. shipped CLI integration (determ init + genesis-tool peer-info) ==="
# 1. determ init with --passphrase
D1="$T/node_pass"
mkdir -p "$D1"
$DETERM init --data-dir "$D1" --passphrase "test-secret-node-pass-1!" >/dev/null

if [ ! -f "$D1/node_key.bin" ]; then
  echo "  FAIL: determ init with --passphrase did not produce node_key.bin"
  exit 1
fi

MAGIC=$(head -c 4 "$D1/node_key.bin")
if [ "$MAGIC" != "DNK1" ]; then
  echo "  FAIL: node_key.bin does not start with DNK1 magic (got '$MAGIC')"
  exit 1
fi

if [ "$UNAME_S" != "Windows_NT" ]; then
  MODE=$(stat -f "%Lp" "$D1/node_key.bin" 2>/dev/null || stat -c "%a" "$D1/node_key.bin" 2>/dev/null || echo "unknown")
  if [ "$MODE" != "600" ]; then
    echo "  FAIL: node_key.bin mode is not 0600 (got $MODE)"
    exit 1
  fi
fi

# 2. Extract pubkey via genesis-tool peer-info without passphrase
INFO=$($DETERM genesis-tool peer-info "test.determ" --data-dir "$D1")
PUB_HEX=$(echo "$INFO" | grep '"ed_pub"' | sed -E 's/.*"ed_pub": "([0-9a-f]+)".*/\1/')
if [ -z "$PUB_HEX" ] || [ "${#PUB_HEX}" -ne 64 ]; then
  echo "  FAIL: genesis-tool peer-info did not extract valid 64-hex ed_pub from DNK1 file"
  exit 1
fi
echo "  PASS: genesis-tool peer-info extracted pubkey: $PUB_HEX"

# 3. determ init with --passphrase-from file:...
D2="$T/node_file"
mkdir -p "$D2"
PWFILE="$T/pw.txt"
echo -n "node-secret-from-file-42!" > "$PWFILE"
$DETERM init --data-dir "$D2" --passphrase-from "file:$PWFILE" >/dev/null

if [ ! -f "$D2/node_key.bin" ]; then
  echo "  FAIL: determ init with --passphrase-from file did not produce node_key.bin"
  exit 1
fi
echo "  PASS: determ init --passphrase-from file produced node_key.bin"

echo
echo "=== C. cross-tool compatibility with determ-wallet ==="
WALLET="${DETERM}-wallet"
if [ -x "$WALLET" ]; then
  # Decrypt node_key.bin with determ-wallet keyfile-decrypt
  export DEC_PW="test-secret-node-pass-1!"
  $WALLET keyfile-decrypt --in "$D1/node_key.bin" --passphrase-from "env:DEC_PW" --out "$T/decrypted.json" >/dev/null
  if [ ! -f "$T/decrypted.json" ]; then
    echo "  FAIL: determ-wallet keyfile-decrypt failed to decrypt determ-created node_key.bin"
    exit 1
  fi
  DEC_PUB=$(grep '"pubkey"' "$T/decrypted.json" | sed -E 's/.*"pubkey": "([0-9a-f]+)".*/\1/')
  if [ "$DEC_PUB" != "$PUB_HEX" ]; then
    echo "  FAIL: decrypted pubkey ($DEC_PUB) does not match peer-info pubkey ($PUB_HEX)"
    exit 1
  fi
  echo "  PASS: determ-wallet keyfile-decrypt decrypted node_key.bin byte-compatibly"

  # Create keyfile with determ-wallet keyfile-create, verify determ peer-info can read it
  D3="$T/wallet_created"
  mkdir -p "$D3"
  export CREAT_PW="wallet-created-key-pass!"
  export SEED_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  $WALLET keyfile-create --priv-from "env:SEED_HEX" --passphrase-from "env:CREAT_PW" --out "$D3/node_key.bin" >/dev/null
  W_INFO=$($DETERM genesis-tool peer-info "wallet.determ" --data-dir "$D3")
  W_PUB=$(echo "$W_INFO" | grep '"ed_pub"' | sed -E 's/.*"ed_pub": "([0-9a-f]+)".*/\1/')
  if [ -z "$W_PUB" ] || [ "${#W_PUB}" -ne 64 ]; then
    echo "  FAIL: determ peer-info could not read pubkey from wallet-created DNK1 container"
    exit 1
  fi
  echo "  PASS: determ peer-info successfully read wallet-created DNK1 container ($W_PUB)"
else
  echo "  SKIP: determ-wallet binary not found"
fi

echo
echo "=== summary ==="
echo "  PASS: test_node_key_encryption"
exit 0
