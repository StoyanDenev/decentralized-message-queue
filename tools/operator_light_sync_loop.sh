#!/usr/bin/env bash
# operator_light_sync_loop.sh — READ-ONLY operator wrapper around the
# steady-state determ-light `verify-chain --resume --persist` light-client
# loop (light/main.cpp::cmd_verify_chain, line 1344).
#
# Each cycle runs ONE `determ-light verify-chain --rpc-port N --genesis F
# --resume --persist [--state P]`:
#   - the FIRST cycle has no cached anchor yet, so verify-chain falls back to
#     a FULL from-genesis verify (every header + every committee sig) and
#     --persist writes the verified tip as the anchor;
#   - EVERY subsequent cycle --resume re-pins the local genesis against that
#     cached anchor and verifies ONLY the suffix the daemon added above it,
#     then --persist advances the anchor to the new verified tip.
# This is precisely the loop primitive documented at light/main.cpp:1449-1465
# ("the steady-state `verify-chain --resume --persist` loop").
#
# A K-bounded finite loop (default --cycles 3), NOT an infinite `while true`:
# the tool terminates so it can run under cron / CI as a steady-state probe.
#
# Soundness note (why a non-zero exit must STOP the loop, not be retried):
# a pre-merge adversarial verifier found, and we FIXED, a resume-soundness
# bug where a malicious daemon served a resume-suffix header claiming index 0
# to divert verify_headers into its binding-free genesis branch (ignoring the
# anchor prev_hash) while the per-block sig loop skipped index 0. The fix is
# three independent gates:
#   (1) light/verify.cpp::verify_headers REJECTS an index-0 header when a
#       non-empty prev_hash anchor was supplied (light/verify.cpp:181-186);
#   (2) light/trustless_read.cpp::verify_chain_walk asserts page header
#       indices are contiguous from `from` (light/trustless_read.cpp:146-159);
#   (3) the genesis sig-skip is gated on from==0 (light/trustless_read.cpp:187)
#       plus a walked-count gate headers_seen == head_height - start_from
#       (light/trustless_read.cpp:213).
# A suffix that does NOT chain onto the anchor (a fork/rollback BELOW it) is a
# HARD error in verify_chain_from_anchor (light/trustless_read.cpp:265-267) and
# surfaces as verify-chain exit 1 — never a silent fallback. So on the first
# failing cycle this loop exits non-zero immediately rather than looping past a
# hard error and re-trusting a forked daemon.
#
# Read-only: verify-chain only issues read RPCs and writes the LOCAL anchor
# cache (never the daemon's state). Safe against any running daemon.
#
# The live verify loop is cluster-bound (it needs a real daemon minting
# blocks above the anchor), so that path SKIPs on hosts without DETERM_LIGHT.
# The offline arg/usage contract (required --genesis/--rpc-port, unknown arg,
# --help, bad --cycles/--interval) is deterministic on every host.
set -u

usage() {
  cat <<'EOF'
Usage: operator_light_sync_loop.sh --rpc-port <N> --genesis <file>
                                   [--state <path>] [--cycles <K>]
                                   [--interval <secs>]

Runs the steady-state determ-light light-client sync loop a BOUNDED number of
times (NOT an infinite loop, so it terminates for cron / CI). Each cycle runs:

    determ-light verify-chain --rpc-port N --genesis F --resume --persist \
                              [--state P]

and prints a one-line health status (cycle index + scraped height + verdict).
The first cycle is a full from-genesis verify (no anchor yet); every later
cycle resumes from the persisted anchor and verifies only the new suffix.

The loop STOPS and exits non-zero on the FIRST cycle that fails — a
fork-below-anchor or any verify error is a hard error and is NEVER retried
(re-trusting a forked daemon would be unsound).

Required:
  --rpc-port <N>     RPC port of the daemon to verify against (1..65535).
  --genesis <file>   Genesis descriptor for the chain to pin to. Its LOCAL
                     genesis hash is the anchor every cycle re-checks — not
                     the daemon's claim.

Options:
  --state <path>     Persisted-anchor cache path (passed verbatim to
                     verify-chain --state). Default: the determ-light default
                     ($DETERM_LIGHT_STATE if set, else ~/.determ-light/state.json).
  --cycles <K>       Number of verify cycles to run (positive integer).
                     Default: 3.
  --interval <secs>  Seconds to sleep BETWEEN cycles (non-negative integer).
                     No sleep after the final cycle. Default: 0.
  -h, --help         Show this help (works without the binary).

Output (one line per cycle):
  cycle <i>/<K>: height=<H> verdict=<OK|RESUMED|FAIL> [note]

Exit codes:
  0   all <K> cycles verified clean
  1   a usage / argument error, OR the FIRST cycle that fails (fork-below-
      anchor or any verify error) — the loop stops immediately on failure

SKIP:
  Exits 0 with a SKIP line if the determ-light binary is unavailable
  (DETERM_LIGHT unset / not executable) — the live loop is cluster-bound and a
  no-op on a host without the binary, mirroring tools/test_light_state.sh.
EOF
}

# ── arg parse ────────────────────────────────────────────────────────────────
# --help is handled BEFORE sourcing common.sh / the SKIP gate so it works on a
# host with no binary built. All args are validated BEFORE the binary is ever
# invoked, so the offline contract is deterministic regardless of cluster.
RPC_PORT=""
GENESIS=""
STATE=""
HAVE_STATE=0
CYCLES=3
INTERVAL=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port)
      RPC_PORT="${2:-}"
      if [ -z "$RPC_PORT" ]; then
        echo "operator_light_sync_loop: --rpc-port requires a value" >&2
        exit 1
      fi
      shift 2 ;;
    --genesis)
      GENESIS="${2:-}"
      if [ -z "$GENESIS" ]; then
        echo "operator_light_sync_loop: --genesis requires a file argument" >&2
        exit 1
      fi
      shift 2 ;;
    --state)
      if [ -z "${2:-}" ]; then
        echo "operator_light_sync_loop: --state requires a path argument" >&2
        exit 1
      fi
      STATE="$2"; HAVE_STATE=1
      shift 2 ;;
    --cycles)
      CYCLES="${2:-}"
      if [ -z "$CYCLES" ]; then
        echo "operator_light_sync_loop: --cycles requires a value" >&2
        exit 1
      fi
      shift 2 ;;
    --interval)
      INTERVAL="${2:-}"
      if [ -z "$INTERVAL" ]; then
        echo "operator_light_sync_loop: --interval requires a value" >&2
        exit 1
      fi
      shift 2 ;;
    *)
      echo "operator_light_sync_loop: unknown argument: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

# Required args.
if [ -z "$RPC_PORT" ] || [ -z "$GENESIS" ]; then
  echo "operator_light_sync_loop: --rpc-port and --genesis are required" >&2
  usage >&2
  exit 1
fi

# --rpc-port: positive integer in 1..65535.
case "$RPC_PORT" in
  ''|*[!0-9]*)
    echo "operator_light_sync_loop: --rpc-port must be a positive integer (got '$RPC_PORT')" >&2
    exit 1 ;;
esac
if [ "$RPC_PORT" -lt 1 ] || [ "$RPC_PORT" -gt 65535 ]; then
  echo "operator_light_sync_loop: --rpc-port out of range 1..65535 (got '$RPC_PORT')" >&2
  exit 1
fi

# --cycles: positive integer (>= 1).
case "$CYCLES" in
  ''|*[!0-9]*)
    echo "operator_light_sync_loop: --cycles must be a positive integer (got '$CYCLES')" >&2
    exit 1 ;;
esac
if [ "$CYCLES" -lt 1 ]; then
  echo "operator_light_sync_loop: --cycles must be >= 1 (got '$CYCLES')" >&2
  exit 1
fi

# --interval: non-negative integer (>= 0).
case "$INTERVAL" in
  ''|*[!0-9]*)
    echo "operator_light_sync_loop: --interval must be a non-negative integer (got '$INTERVAL')" >&2
    exit 1 ;;
esac

# Genesis file must exist (offline, deterministic — checked before the binary).
if [ ! -f "$GENESIS" ]; then
  echo "operator_light_sync_loop: genesis file not found: $GENESIS" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# SKIP gate — identical to tools/test_light_state.sh. The live verify loop is
# cluster-bound; a host without the binary is a no-op, not a failure.
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

# ── one cycle ────────────────────────────────────────────────────────────────
# Runs verify-chain --resume --persist once. Echoes the captured output to a
# per-cycle log on stdout (the verify-chain summary), prints a one-line health
# status, and returns verify-chain's own exit code so the caller can stop the
# loop on the first hard error. The first cycle has no anchor and falls back to
# a full verify inside verify-chain; subsequent cycles resume.
run_cycle() {
  local idx="$1"
  local out rc
  if [ "$HAVE_STATE" -eq 1 ]; then
    out=$("$DETERM_LIGHT" verify-chain --rpc-port "$RPC_PORT" --genesis "$GENESIS" \
            --resume --persist --state "$STATE" 2>&1)
    rc=$?
  else
    out=$("$DETERM_LIGHT" verify-chain --rpc-port "$RPC_PORT" --genesis "$GENESIS" \
            --resume --persist 2>&1)
    rc=$?
  fi

  # Scrape height ("  height:             <N>") and a verdict token. verify-chain
  # prints "OK" as line 1 on success; a "resume:" line carrying "RESUMED"
  # distinguishes a resumed cycle from the initial full verify.
  local height verdict note
  height=$(printf '%s\n' "$out" | grep -E '^[[:space:]]*height:' | head -1 | awk '{print $NF}')
  [ -z "$height" ] && height="?"

  if [ "$rc" -ne 0 ]; then
    verdict="FAIL"
    # First non-empty stderr/stdout line is the most actionable error.
    note=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | head -1)
    echo "cycle $idx/$CYCLES: height=$height verdict=$verdict note=${note:-verify-chain error}" >&2
    # Surface the full verify-chain output for the operator on failure.
    printf '%s\n' "$out" >&2
    return "$rc"
  fi

  if printf '%s\n' "$out" | grep -q 'RESUMED from cached anchor'; then
    verdict="RESUMED"
  else
    verdict="OK"
  fi
  echo "cycle $idx/$CYCLES: height=$height verdict=$verdict"
  return 0
}

# ── bounded loop ─────────────────────────────────────────────────────────────
echo "=== determ-light sync loop (rpc-port $RPC_PORT, genesis $GENESIS, cycles $CYCLES, interval ${INTERVAL}s) ==="
i=1
while [ "$i" -le "$CYCLES" ]; do
  if ! run_cycle "$i"; then
    # HARD error on this cycle (fork-below-anchor or verify error). Do NOT keep
    # looping — re-trusting a forked / dishonest daemon would be unsound.
    echo "  FAIL: cycle $i failed — stopping loop (not retrying past a hard error)" >&2
    exit 1
  fi
  # Sleep between cycles only (not after the final one).
  if [ "$i" -lt "$CYCLES" ] && [ "$INTERVAL" -gt 0 ]; then
    sleep "$INTERVAL"
  fi
  i=$((i + 1))
done

echo "  PASS: all $CYCLES cycle(s) verified clean"
exit 0
