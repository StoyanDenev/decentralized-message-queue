#!/usr/bin/env bash
# Internal implementation of tools/ci_local.sh --c99; do not run directly.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "FAIL: run tools/ci_local.sh --c99 instead"
  exit 1
fi

case "$JOBS" in ''|*[!0-9]*|0) echo "FAIL: --jobs must be a positive integer"; return 1 ;; esac
# Assertion failures are expected in mutation runs; never leave core dumps in
# the source checkout or the isolated snapshots.
ulimit -c 0 || { echo "FAIL: cannot disable core dumps for C99 tests"; return 1; }
C99_PORTABLE=(test-k2-duel test-k2-duel-fallback test-dda test-qpc-clock-overflow
              test-binary-codec fuzzer-parser test-dsf-k2-recovery test-shard-routing
              test-ed25519-bounded test-pending-transfer test-stake-quorum)
C99_UNIX=(test-dsf-k2-duel test-k2-net-rpc test-peer-mesh test-block-store
          test-http-rpc test-ledger-state fuzz-ledger
          test-triple-entry-ledger test-rpc-shard-routing test-rpc-pending-transfer determ-node)
C99_IS_UNIX=1
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) C99_IS_UNIX=0 ;; esac
C99_SKIPPED=0

if [ "${#C99_TESTS[@]}" -eq 0 ]; then
  C99_TESTS=("${C99_PORTABLE[@]}")
  if [ "$C99_IS_UNIX" -eq 1 ]; then
    C99_TESTS+=("${C99_UNIX[@]}")
  else
    for target in "${C99_UNIX[@]}"; do
      echo "PLATFORM-SKIP(c99): $target (POSIX transport integration)"
      C99_SKIPPED=$((C99_SKIPPED + 1))
    done
  fi
fi
# Every test runs under a 300 s bound; exit 124 is reported as FAIL(timeout).
if command -v timeout >/dev/null 2>&1; then
  C99_TIMEOUT=(timeout 300)
elif command -v gtimeout >/dev/null 2>&1; then
  C99_TIMEOUT=(gtimeout 300)
elif command -v python3 >/dev/null 2>&1; then
  # Same contract as timeout(1): on expiry kill the test's process group and
  # exit 124; 126/127 when not launchable; 128+N when it dies from signal N.
  C99_TIMEOUT=(python3 -c '
import os, signal, subprocess, sys
try:
    child = subprocess.Popen(sys.argv[2:], start_new_session=True)
except FileNotFoundError:
    sys.exit(127)
except OSError:
    sys.exit(126)
try:
    rc = child.wait(timeout=float(sys.argv[1]))
except subprocess.TimeoutExpired:
    os.killpg(child.pid, signal.SIGKILL)
    child.wait()
    rc = 124
sys.exit(128 - rc if rc < 0 else rc)' 300)
else
  echo "FAIL: ci-local C99 needs timeout(1), gtimeout(1) or python3"
  return 1
fi
for target in "${C99_TESTS[@]}"; do
  case "$target" in
    test-k2-duel|test-k2-duel-fallback|test-dda|test-qpc-clock-overflow|test-binary-codec|fuzzer-parser|test-dsf-k2-recovery|test-shard-routing|test-ed25519-bounded|test-pending-transfer|test-stake-quorum) ;;
    test-dsf-k2-duel|test-k2-net-rpc|test-peer-mesh|test-block-store|test-http-rpc|test-ledger-state|fuzz-ledger|test-triple-entry-ledger|test-rpc-shard-routing|test-rpc-pending-transfer|determ-node)
      [ "$C99_IS_UNIX" -eq 1 ] || {
        echo "FAIL: requested target $target requires POSIX transport"; return 1; } ;;
    *) echo "FAIL: unsupported C99 target: $target"; return 1 ;;
  esac
done

if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/determ-c99.XXXXXXXX") || return 1
  trap 'rm -rf "$BUILD_DIR"' EXIT
fi
mkdir -p "$BUILD_DIR" || return 1
BUILD_DIR=$(cd "$BUILD_DIR" && pwd) || return 1
C99_SAN_MODE=OFF
if [ "${C99_SANITIZE:-0}" -eq 1 ]; then
  C99_SAN_MODE=ON
  export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1"
  export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
fi
echo "=== ci_local --c99: $(uname -sm), ${CC:-cc}, sanitizers $C99_SAN_MODE, build $BUILD_DIR ==="
if ! cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
    -DDETERM_BUILD_CRYPTOTEST=OFF -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DENABLE_LIBFUZZER=OFF -DENABLE_PARSER_LIBFUZZER=OFF \
    -DDETERM_ASAN=OFF -DDETERM_UBSAN=OFF -DDETERM_C99_SANITIZE=$C99_SAN_MODE \
    >"$BUILD_DIR/configure.log" 2>&1; then
  cat "$BUILD_DIR/configure.log"
  echo "FAIL(build): C99 configure"
  return 1
fi
C99_CC=$(sed -n 's/^CMAKE_C_COMPILER:[A-Z]*=//p' "$BUILD_DIR/CMakeCache.txt")
echo "CONFIGURED(c99): C compiler ${C99_CC:-unknown}, DETERM_C99_SANITIZE=$C99_SAN_MODE"
# --clean-first also protects an explicitly reused build directory. A failed
# configure/compile cannot reach execution or be counted as a killed mutant.
if ! cmake --build "$BUILD_DIR" --config Release --clean-first -j "$JOBS" \
    --target "${C99_TESTS[@]}" >"$BUILD_DIR/build.log" 2>&1; then
  tail -80 "$BUILD_DIR/build.log"
  echo "FAIL(build): C99 targets"
  return 1
fi
echo "BUILD_OK(c99): ${C99_TESTS[*]}"

C99_FAILED=0
for target in "${C99_TESTS[@]}"; do
  binary=""
  for candidate in "$BUILD_DIR/$target" "$BUILD_DIR/Release/$target" \
      "$BUILD_DIR/$target.exe" "$BUILD_DIR/Release/$target.exe"; do
    if [ -x "$candidate" ]; then binary="$candidate"; break; fi
  done
  if [ -z "$binary" ]; then
    echo "FAIL(launch): $target not found in configured build"
    return 1
  fi
  echo "RUN(c99): $target [$binary]"
  # CLI refusals and a live local routing query; not chain adoption proof.
  if [ "$target" = determ-node ]; then
    "${C99_TIMEOUT[@]}" python3 tools/c99_node_smoke.py "$binary" "$BUILD_DIR" >"$BUILD_DIR/$target.log" 2>&1
  else
    "${C99_TIMEOUT[@]}" "$binary" >"$BUILD_DIR/$target.log" 2>&1
  fi
  rc=$?
  if [ "$rc" -eq 124 ]; then
    cat "$BUILD_DIR/$target.log"
    echo "FAIL(timeout): $target"
    return 1
  fi
  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
    cat "$BUILD_DIR/$target.log"
    echo "FAIL(launch): $target (exit $rc)"
    return 1
  fi
  if [ "$rc" -eq 0 ]; then
    echo "PASS(test): $target"
  else
    cat "$BUILD_DIR/$target.log"
    echo "FAIL(test): $target (exit $rc)"
    C99_FAILED=1
  fi
done
if [ "$C99_FAILED" -ne 0 ]; then return 1; fi
echo "PASS: ci-local C99 scope (${#C99_TESTS[@]} targets run, $C99_SKIPPED platform-skipped, sanitizers $C99_SAN_MODE, ${C99_CC:-unknown}; determ-node covers CLI and local routing/pending RPC)"
return 0
