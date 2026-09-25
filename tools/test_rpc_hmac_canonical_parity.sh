#!/usr/bin/env bash
# test_rpc_hmac_canonical_parity.sh — STATIC source-parity guard for the RPC
# HMAC canonical pre-image (register T-1 / RpcAuthHmacSoundness).
#
# The RPC auth tag is HMAC-SHA-256(secret, canonical_for_hmac(method, params)),
# and canonical_for_hmac binds the METHOD into the pre-image:
#     return method + "|" + params.dump();      (src/rpc/rpc.cpp, anon namespace)
# Binding the method is what stops CROSS-METHOD REPLAY: a valid auth tag for
# `balance` must NOT authenticate a `stop` / `submit` call. The register's
# surviving mutation drops the prefix (`return params.dump();`) — a captured tag
# for ANY method would then authenticate EVERY method.
#
# THE GAP this closes: nothing pins the method-binding at the PRODUCTION source.
#   * `determ test-rpc-auth-hmac` (src/main.cpp, 37 assertions incl. #14 "wrong
#     method -> different tag") tests a LOCAL LAMBDA copy of canonical_for_hmac,
#     NOT the production function — the production one lives in an anonymous
#     namespace (rpc.cpp), uncallable from the test, so the two are hand-mirrored
#     in different translation units.
#   * the live-cluster test (tools/test_rpc_hmac_auth.sh) drives the SAME
#     production canonical on BOTH client and server, so a dropped method prefix
#     still round-trips (correct / wrong / missing tag all still behave) — the
#     method-binding property is invisible to it.
# So a production drop of the method prefix survives EVERY existing gate. This is
# the block-digest / whitelist / F2-sub-hasher class again (PCL-1, ADC-3): two
# hand-mirrored copies in different binaries/TUs with no source-parity gate.
#
# This guard pins the PRODUCTION return expression EQUAL to the test lambda's.
# The lambda is the SELF-TESTED spec — assertion #14 ("wrong method -> different
# tag") turns RED if the lambda ever drops the method — so pinning
# production == lambda transitively gates production's method-binding.
#
# Pure read-only awk over the two .cpp files. No build, no node, never SKIPs.
# `SELFTEST=1 bash tools/test_rpc_hmac_canonical_parity.sh` drives a drifted
# snippet through the SAME extractor to prove the guard is live.
# Exit 0 = the two copies bind the method identically; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

RPC_FILE=src/rpc/rpc.cpp
TEST_FILE=src/main.cpp

# extract_return <file> <mode>  (mode = prod | lambda)
# Prints the normalized (whitespace-stripped) return EXPRESSION of the named
# canonical_for_hmac copy. Anchors on the DEFINITION at column 0 (prod) / the
# lambda assignment (test) — both drift-robust and distinct from call sites.
extract_return() {
  awk -v mode="$2" '
    !inreg && mode == "prod"   && /^std::string canonical_for_hmac\(/         { inreg = 1; next }
    !inreg && mode == "lambda" && /auto canonical_for_hmac = \[\]\(/          { inreg = 1; next }
    inreg {
      line = $0; sub(/\/\/.*/, "", line)
      if (line ~ /return /) {
        sub(/^.*return /, "", line); sub(/;.*$/, "", line)
        gsub(/[ \t]+/, "", line); print line; exit
      }
    }
  ' "$1"
}

# ── SELFTEST: the extractor + the drift rule are live ────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: rpc-hmac canonical source-parity extractor ==="
  ST_FAIL=0
  CANON=$(extract_return /dev/stdin prod <<'EOF'
std::string canonical_for_hmac(const std::string& method, const json& params) {
    return method + "|" + params.dump();
}
EOF
)
  DRIFT=$(extract_return /dev/stdin prod <<'EOF'
std::string canonical_for_hmac(const std::string& method, const json& params) {
    return params.dump();
}
EOF
)
  LAM=$(extract_return /dev/stdin lambda <<'EOF'
        auto canonical_for_hmac = [](const std::string& method,
                                     const json& params) -> std::string {
            return method + "|" + params.dump();
        };
EOF
)
  if [ -n "$CANON" ] && [ "$CANON" = "$LAM" ]; then
    echo "  ok:  a coherent prod copy == the lambda spec [$CANON]"
  else
    echo "  bad: coherent prod != lambda (extractor wrong)  prod=[$CANON] lambda=[$LAM]" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  if [ -n "$DRIFT" ] && [ "$DRIFT" != "$LAM" ]; then
    case "$DRIFT" in *method*) echo "  bad: dropped-prefix drift still contains method!" >&2; ST_FAIL=$((ST_FAIL + 1));;
                     *) echo "  ok:  a dropped-method-prefix prod copy is flagged (drift != lambda, no method)";; esac
  else
    echo "  bad: dropped-prefix drift NOT flagged  drift=[$DRIFT]" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_rpc_hmac_canonical_parity SELFTEST (extractor flags a dropped method prefix)"
    exit 0
  else
    echo "  FAIL: test_rpc_hmac_canonical_parity SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── MAIN: pin the live production copy to the live lambda spec ────────────────────
VIOL=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOL=$((VIOL + 1)); }

PROD=$(extract_return "$RPC_FILE" prod)
LAM=$(extract_return "$TEST_FILE" lambda)

[ -z "$PROD" ] && bad "production canonical_for_hmac return not found in $RPC_FILE (anchor drift)"
[ -z "$LAM" ]  && bad "test-lambda canonical_for_hmac return not found in $TEST_FILE (anchor drift)"

# The security property: the method MUST be in the pre-image (anti-cross-method-replay).
case "$PROD" in *method*) : ;; *) bad "production canonical does NOT bind the method — CROSS-METHOD REPLAY (dropped prefix)";; esac

if [ -n "$PROD" ] && [ -n "$LAM" ]; then
  if [ "$PROD" = "$LAM" ]; then
    ok "rpc.cpp::canonical_for_hmac return == the test-rpc-auth-hmac lambda spec [$PROD]"
  else
    bad "production canonical_for_hmac DIFFERS from the self-tested lambda spec (method-binding may have drifted)"
    echo "       production (rpc.cpp):     [$PROD]" >&2
    echo "       lambda spec (main.cpp):   [$LAM]" >&2
  fi
fi

echo ""
if [ "$VIOL" -eq 0 ]; then
  echo "  PASS: test_rpc_hmac_canonical_parity (production canonical_for_hmac binds the method + equals the self-tested lambda spec — no cross-method HMAC replay)"
  exit 0
else
  echo "  FAIL: test_rpc_hmac_canonical_parity ($VIOL parity violation(s) — the RPC HMAC canonical pre-image has drifted)"
  exit 1
fi
