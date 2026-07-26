#!/usr/bin/env bash
# LightVerify LRPC-1 — RpcClient::read_line must CAP a single response line so a
# hostile/MITM daemon cannot exhaust the reader's memory.
#
# THE GAP: the light client talks to an UNTRUSTED / MITM daemon (the
# LightVerifyGateAudit surface). RpcClient::read_line accumulated recv() bytes
# into `inbuf` until it saw a '\n' — with NO upper bound. A malicious daemon
# that streams an endless newline-less body grows `inbuf` without limit until
# the client OOM-crashes: a trivial remote DoS.
#
# THE FIX: a light-local 16 MiB `kLightRpcMaxLineBytes` cap (mirrors the node's
# ingress `net::kMaxRpcLineBytes`). The newline-scan + cap were factored into a
# pure `read_line_capped(inbuf, fill)` core with the byte source INJECTED, so
# the cap is testable OFFLINE with no socket; the socket read_line is a thin
# wrapper whose `fill` does one recv(). Client-side only; no wire/consensus
# change — every legitimate response is far under 16 MiB.
#
# GATE (FAST, offline; the determ-light `selftest-readline-cap` subcommand drives
# read_line_capped with a synthetic fill):
#   CTRL-1  a normal newline-terminated line is returned, remainder buffered
#   CTRL-2  an under-cap newline-less stream that EOFs returns nullopt (the cap
#           does NOT false-trip on a legitimate short response)
#   NEG     an endless newline-less stream is aborted at the 16 MiB cap
# Falsify-on-mutant (neutralize the cap check): ONLY the NEG assert flips (the
# stream is no longer aborted); both CTRLs stay green — a clean directional split.
#
# Run from repo root: bash tools/test_light_rpc_readline_cap.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

# The subcommand prints its own PASS/FAIL asserts + a summary and mirrors the
# outcome in its exit code. Capture (never echo raw on success — its own FAIL:
# lines on a failing run would otherwise reach run_all's tail-10 marker scan).
OUT=$("$DETERM_LIGHT" selftest-readline-cap 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-readline-cap"; then
  echo "  PASS: test_light_rpc_readline_cap"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_rpc_readline_cap"
  exit 1
fi
