#!/usr/bin/env bash
# operator_crypto_selftest.sh — read-only one-shot answering: "is this
# build's crypto stack healthy, and what exactly is in it?"
#
# Phase 1 (static): walks the per-module provenance READMEs required by
# docs/proofs/CRYPTO-C99-SPEC.md §3.16 (src/crypto/<module>/README.md)
# and prints a one-line digest per module: construction, the standards
# it is built from (RFC / FIPS / SP), and the validating test
# subcommand(s) the README cites. Needs no binary.
#
# Phase 2 (live): runs the full in-process C99 crypto battery through
# the determ binary — all 25 C99-family subcommands listed in `determ
# help` (test-ed25519-vectors .. test-c99-api), gating each on exit
# code 0 AND the subcommand's terminal summary marker. (The only other
# C99 cross-validation harness, tools/test_c99_libsodium_xval.sh, is
# out-of-process — it compiles a standalone .c against libsodium.a —
# so it is deliberately not part of this in-process battery.)
#
# This is an operator_ script, NOT a test_ script — tools/run_all.sh
# iterates tools/test_*.sh only and must not pick this up.
#
# Usage:
#   tools/operator_crypto_selftest.sh [--static-only]
#
# Exit codes:
#   0 — all green
#   1 — at least one live battery failed; bad args
#   2 — determ binary unavailable (missing, or locked by a rebuild)
set -u

usage() {
  cat <<'EOF'
Usage: operator_crypto_selftest.sh [--static-only]

Read-only crypto-stack health + inventory one-shot. Two phases:

Phase 1 (static, no binary required):
  For each src/crypto/<module>/README.md (the per-module provenance
  READMEs required by docs/proofs/CRYPTO-C99-SPEC.md §3.16), prints a
  one-line digest: module, construction, standards (RFC/FIPS/SP), and
  the validating test subcommand(s) the README cites. A module without
  a README is noted (not fatal).

Phase 2 (live, skipped with --static-only):
  Runs the in-process C99 crypto battery by invoking the determ binary
  directly, one subcommand at a time (the 27 C99-family subcommands in
  `determ help` order):
    test-ed25519-vectors  test-sha2-c99       test-chacha20-c99
    test-aes-c99          test-ed25519-c99    test-ed25519-scalar-reduce
    test-frost-c99        test-x25519-c99     test-blake2b-c99
    test-sha3-c99         test-mldsa-c99      test-xchacha-c99
    test-argon2id-c99     test-p256-c99       test-p256-h2c-c99
    test-p256-oprf-c99    test-pedersen-c99   test-bp-ipa-c99
    test-bp-rangeproof-c99 test-bp-agg-rangeproof-c99 test-ff-pedersen-c99
    test-ff-scalar-c99    test-ff-ipa-c99     test-ct-c99
    test-rng-c99          test-c99-vectors    test-c99-api
  Each battery must exit 0 AND emit its terminal PASS summary marker;
  the script prints a per-test OK/FAILED row and a final verdict.

Options:
  --static-only   Phase 1 only — no binary needed (e.g. mid-rebuild)
  -h, --help      Show this help

Exit codes:
  0   all green
  1   at least one live battery failed; bad args
  2   determ binary unavailable (missing, or locked by a rebuild)
EOF
}

STATIC_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --static-only) STATIC_ONLY=1; shift ;;
    *) echo "operator_crypto_selftest: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."

# Binary detection follows the house pattern (source tools/common.sh).
# Two wrinkles, both with precedent in operator_config_audit.sh:
#   - In --static-only mode the binary is never invoked, so neutralize
#     common.sh's hard-fail by pre-setting DETERM_BIN to `:` (POSIX
#     no-op) — Phase 1 must work on hosts with no built determ.exe.
#   - In live mode, common.sh `exit 1`s at source time when no binary
#     is found, but this script's contract maps "binary unavailable"
#     to exit 2. Probe the source in a subshell first so the failure
#     can be re-mapped before sourcing for real.
if [ "$STATIC_ONLY" = "1" ]; then
  : "${DETERM_BIN:=:}"
  export DETERM_BIN
fi
if ! (source tools/common.sh) >/dev/null 2>&1; then
  echo "operator_crypto_selftest: determ binary not found (is the build present under build/?)" >&2
  echo "operator_crypto_selftest: set DETERM_BIN=/abs/path to override, or use --static-only" >&2
  exit 2
fi
source tools/common.sh

# ── Phase 1: static provenance inventory ─────────────────────────────────────
echo "=== Phase 1: provenance inventory (src/crypto/*/README.md, CRYPTO-C99-SPEC §3.16) ==="
MISSING_README=0
MODULES=0
for d in src/crypto/*/; do
  [ -d "$d" ] || continue
  m=$(basename "$d")
  r="${d}README.md"
  MODULES=$((MODULES+1))
  if [ ! -f "$r" ]; then
    printf '  %-10s %s\n' "$m" "(no README.md — provenance not documented)"
    MISSING_README=$((MISSING_README+1))
    continue
  fi

  # Construction: first H1 heading. House title shapes are either
  #   "# src/crypto/<mod> — <construction>"   → take the part after the dash
  #   "# <construction> — <subtitle>"         → take the part before the dash
  title=$(grep -m1 '^# ' "$r" | sed 's/^# //; s/`//g')
  case "$title" in
    src/crypto/*' — '*) construction="${title#* — }" ;;
    *' — '*)            construction="${title%% — *}" ;;
    *)                  construction="$title" ;;
  esac
  [ -n "$construction" ] || construction="(untitled README)"

  # Standards: unique RFC / FIPS / SP citations in document order (cap 3).
  stds=$(grep -oE 'RFC [0-9]{3,5}|FIPS [0-9]{2,3}(-[0-9])?|SP 800-[0-9]+[A-Za-z]*' "$r" \
         | awk '!seen[$0]++ { a[++n]=$0 }
                END { for (i=1; i<=n && i<=3; i++) printf "%s%s", (i>1 ? ", " : ""), a[i];
                      if (n>3) printf ", …" }')
  [ -n "$stds" ] || stds="(no RFC/FIPS cited)"

  # Validating test(s): `determ test-…` subcommands the README cites (cap 3).
  tests=$(grep -oE 'determ test-[a-z0-9-]+' "$r" | sed 's/^determ //' \
          | awk '!seen[$0]++ { a[++n]=$0 }
                 END { for (i=1; i<=n && i<=3; i++) printf "%s%s", (i>1 ? ", " : ""), a[i];
                       if (n>3) printf ", …" }')
  [ -n "$tests" ] || tests="(none cited)"

  printf '  %-10s %-47s std: %-30s test: %s\n' "$m" "$construction" "$stds" "$tests"
done
echo "  ($MODULES modules scanned, $MISSING_README without a README)"

if [ "$STATIC_ONLY" = "1" ]; then
  echo
  echo "[OK] static provenance phase complete (live battery skipped via --static-only)"
  exit 0
fi

# ── Phase 2: live in-process crypto battery ──────────────────────────────────
# Cheap runnability probe: `determ` with no args prints usage and exits 0
# (src/main.cpp: `if (argc < 2) { usage(); return 0; }`). A locked exe
# (concurrent rebuild) or unrunnable file fails here → exit 2.
if ! "$DETERM" >/dev/null 2>&1; then
  echo "operator_crypto_selftest: determ binary at $DETERM is missing or not runnable" >&2
  echo "operator_crypto_selftest: (locked by a concurrent rebuild?) retry, or use --static-only" >&2
  exit 2
fi

echo
echo "=== Phase 2: live battery ($DETERM) ==="
# All 27 in-process C99-family subcommands, in `determ help` order
# (test-rng-c99 added with the §3.15 OS-entropy shim, R50; test-bp-ipa-c99
# added with the §3.19 inc.4 Bulletproofs inner-product argument;
# test-bp-rangeproof-c99 with inc.5 single-value range proof;
# test-bp-agg-rangeproof-c99 with inc.6 aggregated range proof;
# test-ff-pedersen-c99 with the §3.20 finite-field Pedersen backend;
# test-ff-scalar-c99 with the §3.20 inc.3 finite-field scalar field mod q;
# test-ff-ipa-c99 with the §3.20 inc.4 finite-field Bulletproofs IPA).
# Every one emits a terminal "PASS: <name> "/"FAIL: <name> " summary
# line from its src/main.cpp dispatch block (name = subcommand minus
# the "test-" prefix), which is what the marker gate below greps.
BATTERY="test-ed25519-vectors test-sha2-c99 test-chacha20-c99 test-aes-c99 \
         test-ed25519-c99 test-ed25519-scalar-reduce test-frost-c99 \
         test-x25519-c99 test-blake2b-c99 test-sha3-c99 test-mldsa-c99 \
         test-xchacha-c99 test-argon2id-c99 test-p256-c99 test-p256-h2c-c99 \
         test-p256-oprf-c99 test-pedersen-c99 test-bp-ipa-c99 \
         test-bp-rangeproof-c99 test-bp-agg-rangeproof-c99 test-ff-pedersen-c99 \
         test-ff-scalar-c99 test-ff-ipa-c99 test-ct-c99 test-rng-c99 \
         test-c99-vectors test-c99-api"
FAILED=0
TOTAL=0
for t in $BATTERY; do
  TOTAL=$((TOTAL+1))
  name="${t#test-}"
  OUT=$("$DETERM" "$t" 2>&1); RC=$?
  # 126/127 mid-battery = the binary became unrunnable between probes
  # (rebuild grabbed the lock) — that is "binary unavailable", not a
  # crypto failure. Map to the exit-2 contract immediately.
  if [ "$RC" = "126" ] || [ "$RC" = "127" ]; then
    echo "operator_crypto_selftest: determ binary became unrunnable mid-battery (rc=$RC on $t; locked by a rebuild?)" >&2
    exit 2
  fi
  # A battery is green only on exit 0 AND its terminal summary marker
  # ("PASS: <name> …", emitted by the src/main.cpp dispatch block).
  if [ "$RC" = "0" ] && printf '%s\n' "$OUT" | grep -q "PASS: $name "; then
    printf '  [OK]     %-26s terminal marker confirmed\n' "$t"
  else
    printf '  [X]      %-26s rc=%s (terminal marker missing or failures above it)\n' "$t" "$RC"
    printf '%s\n' "$OUT" | tail -5 | sed 's/^/      | /'
    FAILED=$((FAILED+1))
  fi
done

echo
if [ "$FAILED" = "0" ]; then
  echo "[OK] crypto stack healthy: $TOTAL/$TOTAL in-process batteries green"
  exit 0
fi
echo "[X]  crypto stack UNHEALTHY: $FAILED of $TOTAL batteries failed"
exit 1
