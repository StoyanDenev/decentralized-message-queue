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

# ── 1. FetchContent set is pinned to exactly {openssl, asio} ────────────────
# (json left the set in the minix JSON-track phase 1: it is VENDORED in-tree
#  at third_party/nlohmann/json.hpp and byte-pinned by check 1b below.)
DECLARED="$(grep -A1 'FetchContent_Declare(' CMakeLists.txt \
            | grep -vE 'FetchContent_Declare|^--' \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort | tr '\n' ' ')"
EXPECTED="asio openssl "
if [ "$DECLARED" = "$EXPECTED" ]; then
    ok "FetchContent set is exactly {asio, openssl} (json vendored; no new third-party source dep)"
else
    fail "FetchContent set CHANGED: got '{$DECLARED}' expected '{$EXPECTED}' — a new external dependency needs an owner decision + a MinixTacticalProfile.md row (then update this pin)"
fi

# ── 1b. Vendored nlohmann/json header is byte-pinned (SHA-256 ratchet) ──────
# Any edit to the vendored third-party header — a silent local patch, an
# unreviewed version bump — goes RED until the owner re-pins. The two
# byte-exact JSON contracts (the hash_abort_event claims_json.dump() consensus
# digest + the RPC HMAC canonical dump) make the JSON writer consensus-adjacent.
JSON_HDR="third_party/nlohmann/json.hpp"
JSON_PIN="9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6"
if [ ! -f "$JSON_HDR" ]; then
    fail "vendored JSON header missing: $JSON_HDR"
else
    GOT="$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$JSON_HDR" 2>/dev/null \
           || sha256sum "$JSON_HDR" | cut -d' ' -f1)"
    if [ "$GOT" = "$JSON_PIN" ]; then
        ok "vendored json.hpp (v3.11.3 single-include) matches the SHA-256 pin"
    else
        fail "vendored json.hpp SHA-256 CHANGED: got $GOT expected $JSON_PIN — an edit/bump of the vendored header needs owner review (byte-exact JSON contracts: abort-event digest + RPC HMAC)"
    fi
fi

# ── 2. minix seam interface headers are asio-free ───────────────────────────
# The iocp_*.hpp NATIVE backend headers (§4.5 increment 1) are pinned here
# too: unlike the Asio* backends they must never touch asio (they exist to
# replace it) — and per the §4.5 layout rule they carry no OS includes either
# (opaque void*/uintptr_t handles; <windows.h> lives in src/net/*.cpp only).
IFACE_HEADERS="include/determ/net/timer.hpp include/determ/net/event_loop.hpp include/determ/net/transport.hpp include/determ/net/iocp_event_loop.hpp include/determ/net/iocp_timer.hpp include/determ/net/iocp_transport.hpp include/determ/net/sync_client.hpp"
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

# ── 3. OpenSSL confined to the SEPARATE test-oracle binary (ZERO exception) ──
# After the minix §6 split, the daemon/wallet/light link zero OpenSSL; the
# ONLY permitted openssl includes in the tree live in cryptotest/main.cpp
# (the determ-cryptotest dual-oracle binary). ANY openssl include under src/
# or include/ is production OpenSSL creep and goes red.
LEAKS="$(grep -rlE '#include\s*<openssl/' src include 2>/dev/null || true)"
if [ -z "$LEAKS" ]; then
    ok "ZERO openssl includes in src/+include/ (oracle isolated in cryptotest/; daemon links no OpenSSL)"
else
    fail "openssl include leaked into production source: $LEAKS"
fi
if grep -qlE '#include\s*<openssl/' cryptotest/main.cpp 2>/dev/null; then
    ok "cryptotest/main.cpp holds the dual-oracle openssl includes (expected)"
else
    fail "cryptotest/main.cpp missing its openssl includes — the oracle binary lost its oracle"
fi

# ── 4. RpcServer stays asio-free (net::Transport slice B) ───────────────────
# Unlike check 2 (the net:: SEAM interface headers), rpc.hpp/rpc.cpp are a
# CONSUMER of the seam — but slice B moved RpcServer fully onto net::Transport/
# net::Connection, so the header should carry zero non-comment 'asio' tokens
# too. A re-introduced direct asio include here is a regression back toward
# the raw-socket coupling slice B removed.
RPC_HDR="include/determ/rpc/rpc.hpp"
if [ ! -f "$RPC_HDR" ]; then
    fail "RpcServer header missing: $RPC_HDR"
elif grep -qE 'asio' "$RPC_HDR"; then
    if grep -vE '^\s*(//|\*)' "$RPC_HDR" | grep -qE 'asio'; then
        fail "$RPC_HDR contains a non-comment 'asio' token — RpcServer regressed off the net::Transport seam"
    else
        ok "$RPC_HDR: asio appears only in comments (RpcServer stays seam-based)"
    fi
else
    ok "$RPC_HDR is asio-free (RpcServer fully on net::Transport/net::Connection)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: minix-dependency-surface (3rd-party set pinned; seam interfaces asio-free; RpcServer asio-free; OpenSSL test-oracle-only)"
    exit 0
else
    echo "  FAIL: minix-dependency-surface ($FAILS violation(s))"
    exit 1
fi
