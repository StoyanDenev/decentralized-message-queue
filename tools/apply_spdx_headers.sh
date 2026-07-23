#!/usr/bin/env bash
# apply_spdx_headers.sh — stamp SPDX-License-Identifier per LICENSING.md.
# Rule: files compiled into a client/library target (determ-crypto-c99, determ-light,
# determ-wallet, future SDK/DSSO libs) are Apache-2.0; daemon-only files are AGPL-3.0-or-later.
# Idempotent (skips files already carrying an SPDX id). REVIEW `git diff` before committing.
#
# CAVEAT: the Apache set below is a best-effort enumeration. Any header transitively
# #included by determ-light or determ-wallet MUST be Apache-2.0 — verify the client
# include closure (e.g. `cmake --build ... -v` or compiler -H) and extend is_apache()
# before trusting this on headers. Erring AGPL on a client-included header is a conflict.
set -euo pipefail
cd "$(dirname "$0")/.."
APACHE="Apache-2.0"; AGPL="AGPL-3.0-or-later"
is_apache() {
  case "$1" in
    src/crypto/*|light/*|wallet/*|dapps/*|sdk/*) return 0;;
    src/chain/block.cpp|src/chain/genesis.cpp) return 0;;
    include/determ/chain/block.hpp|include/determ/chain/genesis.hpp) return 0;;
    include/determ/crypto/*|include/determ/util/*) return 0;;
  esac
  return 1
}
stamp() {
  grep -qI "SPDX-License-Identifier" "$1" && { echo "skip  $1"; return; }
  case "$1" in
    *.c|*.h|*.cc|*.cpp|*.hpp|*.hh) sed -i "1i // SPDX-License-Identifier: $2" "$1";;
    *) echo "??  $1 (unhandled type)"; return;;
  esac
  echo "stamp $2  $1"
}
find src include light wallet -type f \
  \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.hh' \) \
  | while read -r f; do is_apache "$f" && stamp "$f" "$APACHE" || stamp "$f" "$AGPL"; done
echo "done — review 'git diff', verify client include-closure, then commit."
