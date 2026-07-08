#!/usr/bin/env bash
# minix native-backend contract pins — IocpEventLoop + IocpTimer +
# IocpTransport (include/determ/net/iocp_*.hpp), the §4.5 increment-1
# Windows backend behind the SAME net:: seam the asio backends implement.
# Everything test_net_seam.sh pins for the asio backends, PLUS the
# transport surface:
#
#   * loopback accept/connect (ephemeral-port bind, ip:port endpoint)
#   * async exactly-N read / whole-span write round trip (1 MiB — forces
#     the XferOp partial-completion re-issue loop)
#   * sync write_all / read_line incl. the bytes-past-'\n' carry contract
#   * cross-thread close() aborts a PENDING ASYNC READ (CancelIoEx)
#   * cross-thread close() aborts a BLOCKED SYNC WRITE (the FB71
#     stuck-writer-release mechanism, on the native backend)
#
# The IOCP backend is Windows-only: on POSIX the subcommand prints its
# PASS marker and exits 0 (the ubuntu CI leg stays green; the epoll/kqueue
# reactors get their own contract run when they land). In-process,
# loopback-only, <10s — FAST=1 eligible.
#
# Run from repo root: bash tools/test_net_native.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== minix native backend: IocpEventLoop/IocpTimer/IocpTransport contracts ==="
OUT=$($DETERM test-net-native 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: net-native"; then
  echo ""
  echo "  PASS: net-native unit test"
  exit 0
else
  echo ""
  echo "  FAIL: net-native had assertion failures"
  exit 1
fi
