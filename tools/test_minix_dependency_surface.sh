#!/usr/bin/env bash
# Minix dependency-surface RATCHET (docs/proofs/MinixTacticalProfile.md).
#
# The minix goal: a minimal, fully-auditable external-dependency footprint
# (TACTICAL posture label). This guard turns DEPENDENCY CREEP red:
#
#   1. The third-party SOURCE dependency set is EXACTLY the three known
#      FetchContent libs — openssl (test-oracle only), asio (being replaced by
#      native IOCP/epoll/kqueue), json. Adding a FOURTH FetchContent dependency
#      fails this guard: new external code requires an explicit owner decision
#      + a MinixTacticalProfile.md inventory row (then update the pin here).
#
#   2. The minix seam INTERFACE headers stay asio-free. The whole point of
#      net::Timer / net::EventLoop (and later net::Transport) is that the
#      interface has NO transport-library types — only the *Asio* backend
#      headers may touch asio. An `asio` token leaking into an interface
#      header silently re-couples the seam and fails this guard.
#
#   3. OpenSSL stays test-oracle-only: `#include <openssl/...>` appears in NO
#      production source — only src/main.cpp (the §Q9 test-oracle subcommands).
#      A new openssl include anywhere else in src/ or include/ is production
#      OpenSSL creep and fails this guard.
#
# Pure grep over the tree; no build needed. Exit 0 = surface unchanged.

set -u
cd "$(dirname "$0")/.."

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

echo "=== minix dependency-surface ratchet ==="

# ── 1. FetchContent set is pinned to exactly {openssl, asio, json} ──────────
DECLARED="$(grep -A1 'FetchContent_Declare(' CMakeLists.txt \
            | grep -vE 'FetchContent_Declare|^--' \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort | tr '\n' ' ')"
EXPECTED="asio json openssl "
if [ "$DECLARED" = "$EXPECTED" ]; then
    ok "FetchContent set is exactly {asio, json, openssl} (no new third-party source dep)"
else
    fail "FetchContent set CHANGED: got '{$DECLARED}' expected '{$EXPECTED}' — a new external dependency needs an owner decision + a MinixTacticalProfile.md row (then update this pin)"
fi

# ── 2. minix seam interface headers are asio-free ───────────────────────────
IFACE_HEADERS="include/determ/net/timer.hpp include/determ/net/event_loop.hpp include/determ/net/transport.hpp"
for h in $IFACE_HEADERS; do
    if [ ! -f "$h" ]; then fail "interface header missing: $h"; continue; fi
    if grep -qE 'asio' "$h"; then
        # allow the word only inside comments referencing the backend by name
        if grep -vE '^\s*(//|\*)' "$h" | grep -qE 'asio'; then
            fail "$h contains a non-comment 'asio' token — the seam interface must stay transport-library-free"
        else
            ok "$h: asio appears only in comments (interface stays asio-free)"
        fi
    else
        ok "$h is asio-free"
    fi
done

# ── 3. OpenSSL includes confined to the test oracle (src/main.cpp) ──────────
LEAKS="$(grep -rlE '#include\s*<openssl/' src include 2>/dev/null | grep -v '^src/main.cpp$' || true)"
if [ -z "$LEAKS" ]; then
    ok "openssl includes confined to src/main.cpp (test-oracle only; production is determ-crypto-c99)"
else
    fail "openssl include leaked into production source: $LEAKS"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: minix-dependency-surface (3rd-party set pinned; seam interfaces asio-free; OpenSSL test-oracle-only)"
    exit 0
else
    echo "  FAIL: minix-dependency-surface ($FAILS violation(s))"
    exit 1
fi
