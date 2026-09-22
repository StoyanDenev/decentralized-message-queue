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
              test-ed25519-bounded test-pending-transfer)
C99_UNIX=(test-dsf-k2-duel test-k2-net-rpc test-peer-mesh test-block-store
          test-http-rpc test-ledger-dsso fuzz-ledger test-opaque-dsso
          test-triple-entry-ledger test-rpc-shard-routing test-rpc-pending-transfer determ-node)
C99_IS_UNIX=1
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) C99_IS_UNIX=0 ;; esac

if [ "${#C99_TESTS[@]}" -eq 0 ]; then
  C99_TESTS=("${C99_PORTABLE[@]}")
  if [ "$C99_IS_UNIX" -eq 1 ]; then
    C99_TESTS+=("${C99_UNIX[@]}")
  else
    for target in "${C99_UNIX[@]}"; do
      echo "PLATFORM-SKIP(c99): $target (POSIX transport integration)"
    done
  fi
fi
for target in "${C99_TESTS[@]}"; do
  case "$target" in
    test-k2-duel|test-k2-duel-fallback|test-dda|test-qpc-clock-overflow|test-binary-codec|fuzzer-parser|test-dsf-k2-recovery|test-shard-routing|test-ed25519-bounded|test-pending-transfer) ;;
    test-dsf-k2-duel|test-k2-net-rpc|test-peer-mesh|test-block-store|test-http-rpc|test-ledger-dsso|fuzz-ledger|test-opaque-dsso|test-triple-entry-ledger|test-rpc-shard-routing|test-rpc-pending-transfer|determ-node)
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
echo "=== ci_local --c99: $(uname -sm), build $BUILD_DIR ==="
if ! cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
    -DDETERM_BUILD_CRYPTOTEST=OFF -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DENABLE_LIBFUZZER=OFF -DENABLE_PARSER_LIBFUZZER=OFF \
    -DDETERM_ASAN=OFF -DDETERM_UBSAN=OFF >"$BUILD_DIR/configure.log" 2>&1; then
  cat "$BUILD_DIR/configure.log"
  echo "FAIL(build): C99 configure"
  return 1
fi
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
    python3 tools/c99_node_smoke.py "$binary" "$BUILD_DIR" >"$BUILD_DIR/$target.log" 2>&1
  else
    "$binary" >"$BUILD_DIR/$target.log" 2>&1
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
echo "PASS: ci-local C99 scope (${#C99_TESTS[@]} targets; determ-node covers CLI and local routing/pending RPC)"
return 0
