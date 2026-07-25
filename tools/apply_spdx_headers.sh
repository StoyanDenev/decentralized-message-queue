#!/usr/bin/env bash
# apply_spdx_headers.sh — stamp SPDX-License-Identifier per LICENSING.md.
# Rule (licensing v3.1, DECISION-LOG 2026-07-25): everything outside dapps/ and
# third_party/ is Apache-2.0 (core free for all); dapps/** is BUSL-1.1 (all nine),
# stamped per dapps/LICENSE when DApp code lands.
# Idempotent (skips files already carrying an SPDX id). REVIEW `git diff` before committing.
set -euo pipefail
cd "$(dirname "$0")/.."
APACHE="Apache-2.0"
stamp() {
  grep -qI "SPDX-License-Identifier" "$1" && { echo "skip  $1"; return; }
  case "$1" in
    *.c|*.h|*.cc|*.cpp|*.hpp|*.hh) sed -i "1i // SPDX-License-Identifier: $2" "$1";;
    *) echo "??  $1 (unhandled type)"; return;;
  esac
  echo "stamp $2  $1"
}
# dapps/ is deliberately NOT scanned: stamp per the dapps/LICENSE map when DApp code lands.
find src include light wallet sdk -type f \
  \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.hh' \) \
  | while read -r f; do stamp "$f" "$APACHE"; done
echo "done — review 'git diff', verify client include-closure, then commit."
