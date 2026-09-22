#!/usr/bin/env bash
# tools/ci_local.sh — the local second-platform verification gate.
#
# Builds the determ binaries (determ, determ-wallet, determ-light,
# determ-cryptotest — the Minix §6 OpenSSL test-oracle split) and runs
# the FAST=1 suite + the offline doc-coherence guards on the CURRENT
# platform's toolchain. Running it inside WSL2 Ubuntu (or any Linux) gives
# the green surface a second, independent platform: GCC/Linux next to the
# primary MSVC/Windows box — the "green on one laptop" -> "green on two
# toolchains" upgrade (DECISION-LOG.md context: single-box verification was
# the top open operational issue after the 2026-07-03 consolidation).
#
# Usage:
#   tools/ci_local.sh [--build-dir DIR] [--skip-build] [--jobs N]
#   tools/ci_local.sh --c99 [--c99-test TARGET] [--jobs N]
#   tools/ci_local.sh --c99-mutants [--jobs N]
#   tools/ci_local.sh --docs-only
#   tools/ci_local.sh --sanitize [--jobs N]   # UBSan pass over the consensus
#                                             # surface (Linux/GCC-only, heavier)
#   tools/ci_local.sh --asan [--jobs N]       # ASan over the in-process net/
#                                             # scheduler surface + the determ-dsso
#                                             # parsers (Linux/GCC-only, heavier)
#   tools/ci_local.sh --help
#
# From Windows, run it inside WSL2:
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh'
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh --sanitize'
#   wsl -d Ubuntu -- bash -lc 'cd /mnt/c/sauromatae && tools/ci_local.sh --asan'
#
# Defaults: build dir is `build-linux` on Linux/macOS, `build` on Windows
# (so the Linux tree never clashes with the MSVC multi-config tree).
# The suite is pointed at the fresh binaries via the DETERM_BIN /
# DETERM_WALLET_BIN / DETERM_LIGHT_BIN overrides tools/common.sh honors.
#
# Exit: 0 = build + FAST + guards all green; non-zero otherwise.
# The green line reports TWO figures read back out of the suite's own summary:
# how many FAST wrappers asserted, and how many skipped ENTIRELY because the
# property they gate does not exist on this platform (PLATFORM-SKIP — see
# tools/run_all.sh). On Linux and macOS the second is 0; on Windows it is not,
# and the line says so rather than reporting the same green for both.
# GitHub Actions runs the same content (.github/workflows/ci.yml).
set -u
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

JOBS=$( (command -v nproc >/dev/null && nproc) \
     || (command -v sysctl >/dev/null && sysctl -n hw.ncpu 2>/dev/null) \
     || echo 4 )
SKIP_BUILD=0
BUILD_DIR=""
SANITIZE=0
ASAN=0
C99=1
C99_EXPLICIT=0
C99_MUTANTS=0
DOCS_ONLY=0
C99_TESTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    --build-dir)
      [ $# -ge 2 ] || { echo "FAIL: --build-dir requires a directory"; exit 1; }
      BUILD_DIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --jobs)
      [ $# -ge 2 ] || { echo "FAIL: --jobs requires a count"; exit 1; }
      JOBS="$2"; shift 2 ;;
    --sanitize) SANITIZE=1; shift ;;
    --asan) ASAN=1; shift ;;
    --docs-only) DOCS_ONLY=1; C99=0; shift ;;
    --c99) C99=1; C99_EXPLICIT=1; shift ;;
    --c99-test)
      [ $# -ge 2 ] || { echo "FAIL: --c99-test requires a target"; exit 1; }
      C99=1; C99_EXPLICIT=1; C99_TESTS+=("$2"); shift 2 ;;
    --c99-mutants) C99=1; C99_MUTANTS=1; shift ;;
    *) echo "unknown arg: $1 (see --help)"; exit 1 ;;
  esac
done

run_doc_guards() {
  echo "=== ci_local: offline doc-coherence guards ==="
  GUARDS_OK=1
  DOC_GUARD_LOG=$(mktemp "${TMPDIR:-/tmp}/determ-doc-guard.XXXXXXXX") || return 1
  for g in test_doc_citation_bounds test_doc_tier_check test_docs_link_check \
           test_proofs_index_complete test_proofs_no_deleted_crypto_backend \
           test_security_ledger_coherence; do
    if [ -f "tools/$g.sh" ]; then
      if bash "tools/$g.sh" >"$DOC_GUARD_LOG" 2>&1; then
        echo "  PASS: $g"
      else
        echo "  FAIL: $g"; cat "$DOC_GUARD_LOG"; GUARDS_OK=0
      fi
    fi
  done
  rm -f "$DOC_GUARD_LOG"
  [ "$GUARDS_OK" -eq 1 ] || { echo "FAIL: ci-local doc guards RED"; return 1; }
}

if [ "$DOCS_ONLY" -eq 1 ]; then
  if [ "$C99_EXPLICIT" -ne 0 ] || [ "$SKIP_BUILD" -ne 0 ] || [ "$SANITIZE" -ne 0 ] || [ "$ASAN" -ne 0 ] || [ -n "$BUILD_DIR" ]; then
    echo "FAIL: --docs-only cannot be combined with build or binary-test modes"
    exit 1
  fi
  run_doc_guards || exit 1
  echo "PASS: ci-local docs-only guards (no binaries built or tested)"
  exit 0
fi

# Sovereign C99 Unikernel Execution Environment
if [ "$C99" -eq 1 ]; then
  if [ "$SKIP_BUILD" -ne 0 ]; then
    echo "FAIL: --c99 cannot be combined with --skip-build"
    exit 1
  fi
  if [ "$C99_MUTANTS" -eq 1 ]; then
    [ -z "$BUILD_DIR" ] && [ "${#C99_TESTS[@]}" -eq 0 ] || {
      echo "FAIL: --c99-mutants owns its isolated build directories and test selection"; exit 1; }
    exec python3 tools/c99_mutants.py --jobs "$JOBS"
  fi
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) DEFAULT_DIR="build" ;;
    *)                    DEFAULT_DIR="build-linux" ;;
  esac
  BUILD_DIR="${BUILD_DIR:-$DEFAULT_DIR}"
  HAS_CUSTOM_TESTS=0
  [ "${#C99_TESTS[@]}" -gt 0 ] && HAS_CUSTOM_TESTS=1
  source tools/ci_c99.sh
  rc=$?
  [ "$rc" -eq 0 ] || exit $rc
  if [ "$C99_EXPLICIT" -eq 0 ] && [ "$HAS_CUSTOM_TESTS" -eq 0 ] && [ "$SANITIZE" -eq 0 ] && [ "$ASAN" -eq 0 ]; then
    run_doc_guards || exit 1
  fi
  exit 0
fi

# ── UBSan mode (--sanitize): the undefined-behavior net for the consensus
# path. The 2026-07-03 state_root fork was a uint32 shift-UB that MSVC and
# GCC resolved differently; UBSan flags that class at the point of execution
# with a file:line. Builds `determ` with UBSan scoped to Determ's OWN targets
# (via -DDETERM_UBSAN=ON — the vendored OpenSSL/asio/json are NOT instrumented,
# so no dep-side noise and no whole-tree rebuild) and runs the consensus-
# serialization + arithmetic + determinism subcommands under it — the surfaces
# where a determinism-breaking UB would live. Linux/GCC-only and a bit heavier
# than the fast gate, so it is an OPT-IN job, not part of the default ci_local
# pass. ASan is intentionally NOT enabled (its shadow-memory instrumentation
# OOMs on the large main.cpp TU; memory-safety is a separable concern).
if [ "$SANITIZE" -eq 1 ]; then
  SAN_DIR="build-linux-ubsan"
  echo "=== ci_local --sanitize: UBSan build of determ ($SAN_DIR) ==="
  # -DDETERM_UBSAN=ON instruments ONLY Determ's own targets (determ +
  # determ-crypto-c99); the vendored OpenSSL/asio/json stay uninstrumented and
  # are reused from cache, so this is just the ~18 Determ TUs (not a whole-tree
  # sanitized rebuild). No dep instrumentation means no dep-side UBSan noise,
  # so no ignorelist/suppressions are needed. Abort-on-UB is enforced at
  # runtime via UBSAN_OPTIONS (a compile-time -fno-sanitize-recover would abort
  # unrelated CMake feature-tests).
  cmake -B "$SAN_DIR" -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDETERM_UBSAN=ON \
    >/dev/null 2>&1 || { echo "FAIL: UBSan configure"; exit 1; }
  # Cap parallelism to 2 for the UBSan build: main.cpp + the large consensus TUs
  # under UBSan peak several GB each, and -j4 concurrent OOM-killed the GitHub
  # runner (SIGTERM/143). -j2 (with the -O1 from CMakeLists) keeps peak RAM within
  # the runner while staying faster than a serial build (the job has 150-min headroom).
  SAN_JOBS=2; [ "$JOBS" -lt 2 ] && SAN_JOBS="$JOBS"
  # Minix §6 split: the 11 pure-oracle test-*-c99 subcommands live in the
  # standalone determ-cryptotest binary — build it under UBSan alongside determ
  # so the full c99-crypto surface stays in the sanitize net.
  #
  # GATE ON CMAKE'S OWN EXIT CODE, never a grep over the pipe (the run_all.sh
  # lesson, relearned here): `cmake --build … | grep -iE "error:" && fail` both
  # (a) SWALLOWED the real linker diagnostics — undefined-reference /
  # "No space left on device" / oom-kill lines contain no "error:" substring,
  # so the first red ubsan Actions run showed ONLY the useless
  # "collect2: error: ld returned 1" summary — and (b) would IGNORE a failure
  # whose output matches nothing, letting the binary-find below pick up a
  # STALE determ from a prior build (a false green). Log the full build output
  # and print its tail on failure so a red CI run is self-diagnosing.
  #
  # Targets built SEQUENTIALLY: linking a UBSan+RelWithDebInfo determ (the
  # 53k-line main.cpp TU) peaks several GB of ld RSS; overlapping it with the
  # determ-cryptotest link/compiles is exactly the OOM class that -j4 already
  # hit on the 16 GB GitHub runner (the SIGTERM/143 note above). Compile
  # parallelism within each target keeps -j$SAN_JOBS; only the giant links
  # stop overlapping.
  for tgt in determ determ-cryptotest; do
    if ! cmake --build "$SAN_DIR" --config RelWithDebInfo -j "$SAN_JOBS" --target "$tgt" \
         >"$SAN_DIR/build-$tgt.log" 2>&1; then
      echo "FAIL: UBSan build error ($tgt) — last 30 log lines:"
      tail -30 "$SAN_DIR/build-$tgt.log"
      exit 1
    fi
  done
  # Post-hoc scan (the old grep's one legitimate job): a UBSan runtime report
  # emitted DURING the build (e.g. an instrumented generator run) is a finding.
  if grep -iq "runtime error" "$SAN_DIR"/build-determ.log "$SAN_DIR"/build-determ-cryptotest.log; then
    echo "FAIL: UBSan runtime error during build:"
    grep -i "runtime error" "$SAN_DIR"/build-*.log | head -5
    exit 1
  fi
  SANBIN=$(find "$SAN_DIR" -maxdepth 2 -name determ -type f -perm -u+x | head -1)
  [ -x "$SANBIN" ] || { echo "FAIL: UBSan determ binary not found"; exit 1; }
  SANBIN_CT=$(find "$SAN_DIR" -maxdepth 2 -name determ-cryptotest -type f -perm -u+x | head -1)
  [ -x "$SANBIN_CT" ] || { echo "FAIL: UBSan determ-cryptotest binary not found"; exit 1; }
  export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
  echo "=== ci_local --sanitize: run consensus/determinism + full c99-crypto surface under UBSan ==="
  # The consensus/determinism/arithmetic surface + the ENTIRE determ::c99 crypto
  # stack. The crypto set is load-bearing: the first --sanitize run (2026-07-03)
  # caught a left-shift-of-negative UB (C-standard UB) in the TweetNaCl-derived
  # car25519/modL of ed25519.c + x25519.c — byte-invariant but flagged; fixed.
  # (cwd is the repo root — see the `cd` at the top — so test-c99-vectors
  #  resolves its tests/vectors/*.json corpus.)
  SAN_CMDS="test-consensus-vectors test-state-root-determinism test-tx-signing-determinism \
            test-merge-event-determinism test-genesis-determinism test-state-proof-composite-key \
            test-cross-shard-atomicity test-cross-shard-multi-receipt test-cross-shard-outbound-apply \
            test-block-digest test-tx-root test-merkle test-overflow-paths \
            test-sha256 test-argon2id-c99 test-ct-c99 test-ed25519-vectors \
            test-ed25519-scalar-reduce test-p256-oprf-c99 test-mldsa-c99 test-c99-vectors test-c99-api"
  # The 11 moved oracle subcommands (Minix §6) run on the UBSan determ-cryptotest.
  SAN_CMDS_CT="test-sha2-c99 test-blake2b-c99 test-sha3-c99 test-chacha20-c99 test-xchacha-c99 \
            test-aes-c99 test-ed25519-c99 test-x25519-c99 test-p256-c99 test-p256-h2c-c99"
  san_fail=0
  for cmd in $SAN_CMDS; do
    if "$SANBIN" "$cmd" >/tmp/ubsan_out.txt 2>&1; then
      echo "  PASS(ubsan): $cmd"
    else
      echo "  FAIL(ubsan): $cmd"; grep -iE "runtime error|undefined|shift" /tmp/ubsan_out.txt | head -3
      san_fail=1
    fi
  done
  for cmd in $SAN_CMDS_CT; do
    if "$SANBIN_CT" "$cmd" >/tmp/ubsan_out.txt 2>&1; then
      echo "  PASS(ubsan): $cmd [determ-cryptotest]"
    else
      echo "  FAIL(ubsan): $cmd [determ-cryptotest]"; grep -iE "runtime error|undefined|shift" /tmp/ubsan_out.txt | head -3
      san_fail=1
    fi
  done
  [ "$san_fail" -eq 0 ] && { echo ""; echo "PASS: ci-local --sanitize (UBSan) clean over the consensus surface"; exit 0; }
  echo ""; echo "FAIL: ci-local --sanitize (UBSan) found undefined behavior"; exit 1
fi

# ── ASan mode (--asan): the MEMORY-SAFETY companion to --sanitize. UBSan is blind
# to the heap/lifetime class — use-after-free, heap-buffer-overflow, and the
# re-entrant-container-mutation-during-destruction shape that the net/scheduler
# teardown paths can hit (a self-owning virtual timer torn down before it fires).
# Same target-scoped discipline (-DDETERM_ASAN=ON instruments only Determ's own
# targets; OpenSSL/asio/json stay uninstrumented and cached). Runs the in-process
# net/scheduler/consensus subcommands — the ones that build+destroy real Nodes,
# loops, and transports in-process, where a lifetime bug actually executes — AND
# (added 2026-09-17) the determ-dsso selftests, because that binary holds the only
# parsers in the tree that face attacker-supplied external formats and no
# sanitizer had ever been run over them.
# Linux/GCC-only, OPT-IN (heavier than the fast gate), not part of the default pass.
if [ "$ASAN" -eq 1 ]; then
  ASAN_DIR="build-linux-asan"
  echo "=== ci_local --asan: ASan build of determ ($ASAN_DIR) ==="
  cmake -B "$ASAN_DIR" -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDETERM_ASAN=ON \
    >/dev/null 2>&1 || { echo "FAIL: ASan configure"; exit 1; }
  # Same -j2 cap + -O1 (from CMakeLists) as the UBSan build: shadow-memory
  # instrumentation on the ~15k-line main.cpp TU peaks several GB.
  ASAN_JOBS=2; [ "$JOBS" -lt 2 ] && ASAN_JOBS="$JOBS"
  # Exit-code gate + logged output (same fix as the UBSan path above — the
  # grep-gate both swallowed real diagnostics and could false-green a failure
  # whose output matched nothing).
  # Targets built SEQUENTIALLY (same OOM reason as the --sanitize loop above:
  # the instrumented main.cpp link peaks several GB and must not overlap another
  # link). determ-dsso is the SECOND target: it is the binary that parses
  # attacker-supplied external formats (base64url / JSON / JOSE / DEFLATE, and
  # the nine PID rules on top of them), and until 2026-09-17 NO sanitizer had
  # ever run over it — the fuzz arms inside `selftest-pid` observe a definite
  # status and untouched guard bytes, which cannot see an out-of-bounds READ.
  # Its readers allocate nothing, so the instrumentation that matters is the
  # COMPILE-side one applied to the target in CMakeLists.txt.
  for tgt in determ determ-dsso; do
    if ! cmake --build "$ASAN_DIR" --config RelWithDebInfo -j "$ASAN_JOBS" --target "$tgt" \
         >"$ASAN_DIR/build-$tgt.log" 2>&1; then
      echo "FAIL: ASan build error ($tgt) — last 30 log lines:"
      tail -30 "$ASAN_DIR/build-$tgt.log"
      exit 1
    fi
  done
  ASANBIN=$(find "$ASAN_DIR" -maxdepth 2 -name determ -type f -perm -u+x | head -1)
  [ -x "$ASANBIN" ] || { echo "FAIL: ASan determ binary not found"; exit 1; }
  ASANBIN_DSSO=$(find "$ASAN_DIR" -maxdepth 2 -name determ-dsso -type f -perm -u+x | head -1)
  [ -x "$ASANBIN_DSSO" ] || { echo "FAIL: ASan determ-dsso binary not found"; exit 1; }
  # abort_on_error=1 turns any ASan report into a non-zero exit the loop below
  # catches; detect_leaks=0 (the daemon subcommands intentionally leave some
  # process-lifetime singletons — leaks are out of scope for this teardown gate).
  export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:print_stacktrace=1"
  echo "=== ci_local --asan: run in-process net/scheduler/consensus surface under ASan ==="
  # The subcommands that construct + tear down real Nodes/loops/transports in a
  # single process — where a use-after-free / re-entrant-teardown bug executes.
  ASAN_CMDS="test-scheduler-external test-scheduler-timers test-virtual-clock \
             test-net-virtual test-fa-liveness-virtual test-fa-partition-virtual \
             test-state-root-determinism test-genesis-determinism"
  asan_fail=0
  for cmd in $ASAN_CMDS; do
    if "$ASANBIN" "$cmd" >/tmp/asan_out.txt 2>&1; then
      echo "  PASS(asan): $cmd"
    else
      echo "  FAIL(asan): $cmd"
      grep -iE "ERROR: AddressSanitizer|heap-use-after-free|heap-buffer-overflow|SUMMARY|freed by" /tmp/asan_out.txt | head -5
      asan_fail=1
    fi
  done
  # The DSSO service's own selftests, on the instrumented determ-dsso. selftest-pid
  # carries the 8400-input fuzz corpus over the four readers a hostile wallet
  # reaches, so running it here is what turns "no crash, guard bytes untouched"
  # into "no out-of-bounds access"; the other three cover the assertion, the
  # authentication state machine and the shared core.
  for cmd in selftest-core selftest-assertion selftest-pid selftest-authn; do
    if "$ASANBIN_DSSO" "$cmd" >/tmp/asan_out.txt 2>&1; then
      echo "  PASS(asan): $cmd [determ-dsso]"
    else
      echo "  FAIL(asan): $cmd [determ-dsso]"
      grep -iE "ERROR: AddressSanitizer|stack-buffer-overflow|heap-use-after-free|heap-buffer-overflow|SUMMARY|freed by" /tmp/asan_out.txt | head -5
      asan_fail=1
    fi
  done
  [ "$asan_fail" -eq 0 ] && { echo ""; echo "PASS: ci-local --asan (ASan) clean over the in-process net/scheduler surface + the determ-dsso external-format readers"; exit 0; }
  echo ""; echo "FAIL: ci-local --asan (ASan) found a memory-safety error"; exit 1
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) DEFAULT_DIR="build" ;;
  *)                    DEFAULT_DIR="build-linux" ;;
esac
BUILD_DIR="${BUILD_DIR:-$DEFAULT_DIR}"

echo "=== ci_local: platform $(uname -sm), build dir $BUILD_DIR, jobs $JOBS ==="

if [ "$SKIP_BUILD" -eq 0 ]; then
  echo "=== ci_local: configure ==="
  cmake -B "$BUILD_DIR" -S . -DCMAKE_BUILD_TYPE=Release || {
    echo "FAIL: ci-local configure failed"; exit 1; }
  echo "=== ci_local: build determ + determ-wallet + determ-light + determ-cryptotest + determ-dsf + d5rp + determ-dsso ==="
  cmake --build "$BUILD_DIR" --config Release -j "$JOBS" \
        --target determ determ-wallet determ-light determ-cryptotest determ-dsf d5rp determ-dsso || {
    echo "FAIL: ci-local build failed"; exit 1; }
fi

# Locate the fresh binaries (single-config layout on Linux, Release/ on MSVC).
find_bin() {
  for c in "$BUILD_DIR/$1" "$BUILD_DIR/Release/$1" \
           "$BUILD_DIR/$1.exe" "$BUILD_DIR/Release/$1.exe"; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}
DETERM_BIN=$(find_bin determ)               || { echo "FAIL: determ binary not found under $BUILD_DIR"; exit 1; }
DETERM_WALLET_BIN=$(find_bin determ-wallet) || { echo "FAIL: determ-wallet binary not found"; exit 1; }
DETERM_LIGHT_BIN=$(find_bin determ-light)   || { echo "FAIL: determ-light binary not found"; exit 1; }
# Minix §6 split: the 11 pure-oracle test-*-c99 wrappers run against the
# standalone determ-cryptotest binary (the daemon links zero OpenSSL), so it
# is REQUIRED for a green FAST suite — fail loudly, not late in a wrapper.
DETERM_CRYPTOTEST_BIN=$(find_bin determ-cryptotest) || { echo "FAIL: determ-cryptotest binary not found"; exit 1; }
export DETERM_BIN DETERM_WALLET_BIN DETERM_LIGHT_BIN DETERM_CRYPTOTEST_BIN
# determ-dsf is the test-only 4th binary (its test is SKIP-clean). Export it so the
# DSF test uses the NATIVE build, not a Windows determ-dsf.exe picked up via WSL
# interop (which writes traces the Linux shell can't read — an empty-trace RED).
if DETERM_DSF_BIN=$(find_bin determ-dsf); then export DETERM_DSF_BIN; fi
# d5rp is the D.5 reference-RP producer (dapps/, BUSL). Export the NATIVE build so
# its FAST selftest wrapper doesn't pick a Windows d5rp.exe via WSL interop.
if DETERM_D5RP_BIN=$(find_bin d5rp); then export DETERM_D5RP_BIN; fi
# determ-dsso is the DSSO identity service (dapps/dsso). Same reason: export the
# NATIVE build so its FAST gates never pick a Windows binary via WSL interop.
if DETERM_DSSO_BIN=$(find_bin determ-dsso); then export DETERM_DSSO_BIN; fi
echo "=== ci_local: binaries: $DETERM_BIN | $DETERM_WALLET_BIN | $DETERM_LIGHT_BIN | $DETERM_CRYPTOTEST_BIN | ${DETERM_DSF_BIN:-<dsf: not built>} | ${DETERM_D5RP_BIN:-<d5rp: not built>} | ${DETERM_DSSO_BIN:-<dsso: not built>} ==="

echo "=== ci_local: FAST=1 suite ==="
# The suite's own summary is TEE'd to a file and the green line at the bottom is
# built from the figures IT reported, never from a number typed here. Since
# 2026-09-18 a wrapper has a third outcome — PLATFORM-SKIP, meaning it skipped
# ENTIRELY because the property it gates does not exist on this platform (see
# THE WRAPPER-LEVEL SKIP in tools/run_all.sh). A run in which two wrappers
# skipped entirely is NOT the same run as one in which every wrapper asserted,
# and a final line that printed the same words for both would be exactly the
# tidier-summary-that-hides-the-hole this repo keeps finding.
FAST_LOG="$BUILD_DIR/ci_local_fast.log"
FAST=1 QUIET=1 bash tools/run_all.sh 2>&1 | tee "$FAST_LOG"
FAST_RC=${PIPESTATUS[0]}
[ "$FAST_RC" -eq 0 ] || { echo "FAIL: ci-local FAST suite RED"; exit 1; }
# Read the columns back out of the suite's own summary. Fail closed if they are
# not there: a verdict line that invents its own figures is worse than none.
FAST_PASS=$(sed -n 's/^PASS:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$FAST_LOG" | head -1)
FAST_PSKIP=$(sed -n 's/^PLATFORM-SKIP:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$FAST_LOG" | head -1)
if [ -z "$FAST_PASS" ] || [ -z "$FAST_PSKIP" ]; then
  echo "FAIL: ci-local could not read the FAST suite's PASS / PLATFORM-SKIP columns from $FAST_LOG"
  echo "      (tools/run_all.sh's summary shape changed — re-pin this, do not guess the figures)"
  exit 1
fi

run_doc_guards || exit 1

echo ""
# Named BEFORE the verdict line, and unconditionally absent when the figure is
# zero — one terminal marker, carrying both figures, never a per-arm wording.
if [ "$FAST_PSKIP" -gt 0 ]; then
  echo "NOTE: $FAST_PSKIP FAST wrapper(s) skipped ENTIRELY on $(uname -s) — the properties they"
  echo "      gate do not exist here and have NO coverage on this platform. They are named in"
  echo "      the suite summary above. This run asserted $FAST_PASS wrappers, not $((FAST_PASS + FAST_PSKIP))."
fi
echo "PASS: ci-local build + FAST ($FAST_PASS wrappers asserted, $FAST_PSKIP skipped entirely) + guards green on $(uname -sm)"
