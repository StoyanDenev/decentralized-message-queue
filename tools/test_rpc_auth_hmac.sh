#!/usr/bin/env bash
# S-001 / v2.16 RPC HMAC-SHA-256 authentication contract — in-process
# unit test (pure functions, no sockets, FAST=1).
#
# The production verifier (RpcServer::verify_auth) and client signer
# (rpc_call) live in src/rpc/rpc.cpp behind an asio io_context + Node,
# so they can only be exercised end-to-end. This is the pure-function
# complement that locks in the auth-field algebra those two surfaces
# agree on:
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
# 17 assertions covering:
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
#
# Run from repo root: bash tools/test_rpc_auth_hmac.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== RPC HMAC-SHA-256 auth contract (S-001 / v2.16) ==="
OUT=$($DETERM test-rpc-auth-hmac 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: rpc-auth-hmac all assertions"; then
  echo ""
  echo "  PASS: rpc-auth-hmac unit test"
  exit 0
else
  echo ""
  echo "  FAIL: rpc-auth-hmac had assertion failures"
  exit 1
fi
