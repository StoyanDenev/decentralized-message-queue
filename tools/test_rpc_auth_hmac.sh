#!/usr/bin/env bash
# S-001 / v2.16 RPC HMAC-SHA-256 authentication contract — in-process
# unit test (pure functions, no sockets, FAST=1).
#
# The production verifier (RpcServer::verify_auth) and client signer
# (rpc_call) live in src/rpc/rpc.cpp behind a live transport + Node,
# so they can only be exercised end-to-end; the verdict verify_auth
# applies (determ::rpc::auth_tag_verdict) is called directly (item 17).
# This is the pure-function complement that locks in the auth-field
# algebra those two surfaces agree on:
#
#   canonical_for_hmac(method, params) = method + "|" + params.dump()
#   auth_field = hex(HMAC-SHA-256(secret, canonical))
#   verify     = constant_time_equal(expected_auth, got_auth)
#
# Complements the wire-level test:
#
#   * tools/test_rpc_hmac_auth.sh — end-to-end RPC HMAC auth on a live
#     cluster (missing / wrong / correct auth tag)
#
# 37 assertions covering:
#
#   1-2.  Canonical message is EXACTLY "method|params.dump()" (single
#         '|' separator, method first)
#   3.    Empty-object params canonicalizes to "method|{}"
#   4-5.  HMAC-SHA-256 hex digest is 64 lowercase hex chars (32 bytes)
#   6.    Determinism over identical inputs
#   7.    Constant-time compare: equal digests accept
#   8.    Constant-time compare: single-nibble difference rejects
#   9-11. Constant-time compare length guard: shorter / longer / empty
#         'auth' field rejects WITHOUT indexing out of range
#   12.   Client/server agree on auth across a dump()/parse() round-trip
#         (the load-bearing nlohmann key-order stability property)
#   13.   Sensitivity: wrong secret → different (rejected) tag
#   14.   Sensitivity: wrong method → different tag (no method replay)
#   15.   Sensitivity: any params field change → different tag
#         (tamper-evident)
#   16.   Auth-disabled signal: empty secret hex decodes to empty key
#   17.   S-118, the PRODUCTION verdict (10 assertions): a computed tag
#         that is not 64 characters (empty or truncated) refuses every
#         client value, including the same short string; a complete tag
#         is accepted only on an exact match (first/last nibble, one byte
#         appended or removed, and an empty field are refused)
#   18.   S-122, the PRODUCTION secret decoder rpc_auth_key (11
#         assertions): "" is the auth-disabled key, well-formed hex in
#         either case decodes, odd length, non-hex digits, signs, a 0x
#         prefix and whitespace throw, and the message omits the secret
#   Plus two CLI checks: `determ dapp-subscribe` refuses a malformed
#   DETERM_RPC_AUTH_SECRET ("abc", "0xab") before dialing (S-122 wiring).
#
# Run from repo root: bash tools/test_rpc_auth_hmac.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== RPC HMAC-SHA-256 auth contract (S-001 / v2.16) ==="
OUT=$($DETERM test-rpc-auth-hmac 2>&1)
echo "$OUT"
FAILED=0
echo "$OUT" | tail -3 | grep -q "PASS: rpc-auth-hmac all assertions" || FAILED=1

# S-122 wiring, offline: dapp-subscribe decodes DETERM_RPC_AUTH_SECRET with the
# production decoder before it dials, so a malformed secret is refused up front
# (the lenient decoder it used to carry accepted both of these and dialed).
for BAD in abc 0xab; do
  SUB=$(DETERM_RPC_AUTH_SECRET="$BAD" timeout 20 $DETERM dapp-subscribe --domain probe --rpc-port 1 2>&1)
  RC=$?
  if [ "$RC" -eq 1 ] && echo "$SUB" | grep -q "is not valid hex"; then
    echo "  PASS: dapp-subscribe refuses DETERM_RPC_AUTH_SECRET=$BAD before dialing (S-122)"
  else
    echo "  FAIL: dapp-subscribe did not refuse DETERM_RPC_AUTH_SECRET=$BAD (exit $RC): $SUB"
    FAILED=1
  fi
done

echo ""
if [ "$FAILED" -eq 0 ]; then
  echo "  PASS: rpc-auth-hmac unit test"
  exit 0
else
  echo "  FAIL: rpc-auth-hmac had assertion failures"
  exit 1
fi
