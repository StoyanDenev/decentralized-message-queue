#!/usr/bin/env bash
# operator_rpc_throughput_probe.sh — LIVE end-to-end RPC THROUGHPUT probe for a
# running determ daemon. Measures the achievable rate (successful `status`
# polls per second) over a fixed window and correlates it against the daemon's
# ADVERTISED rate-limit posture (the `protections.rpc_rate_limit` boolean in
# the status reply) so an operator can tell whether the configured limiter is
# plausibly the bottleneck.
#
# The operator question this answers — and that no existing tool answers:
#
#   "operator_rate_limiter_audit.sh tells me what rate-limit knobs are WRITTEN
#    in config.json. operator_rpc_auth_probe.sh tells me the auth gate is live.
#    But neither tells me what RPC request rate this node can ACTUALLY sustain
#    right now, nor whether the configured limiter is what's capping it. If I
#    fire status polls as fast as I can for N seconds, how many succeed per
#    second, and does that line up with a rate limit being engaged?"
#
# ── Lane distinction (why this is NOT a duplicate) ───────────────────────────
#
#   operator_rate_limiter_audit.sh         — STATIC config.json linter; reads
#                                            the 4 S-014 knobs off disk; never
#                                            touches the wire; says nothing
#                                            about ACHIEVABLE live throughput.
#   operator_rpc_auth_probe.sh             — one-shot auth-posture probe (a
#                                            single `status`); not a rate.
#   operator_rpc_method_surface.sh         — maps the mutating method surface
#                                            + its auth gating; not a rate.
#   operator_chain_replay_speedometer.sh   — measures BLOCKS/sec + TXS/sec
#                                            (chain-apply throughput), polling
#                                            `head` once per interval. That is
#                                            consensus cadence, NOT RPC request
#                                            throughput — it sends ~1 req/sec.
#   operator_tx_throughput.sh              — TPS read off finalized blocks
#                                            (on-chain tx rate); not RPC rate.
#
#   This tool is the only one that drives the RPC socket AS FAST AS IT CAN and
#   reports requests/sec — the RPC-server-front-door throughput dimension.
#
# ── HONESTY NOTE: what this DOES and DOES NOT measure ────────────────────────
#
#   What it measures: the END-TO-END achievable rate of successful `status`
#   replies as observed by THIS client, over the measurement window. That
#   number is the COMBINED result of (a) the S-014 token-bucket limiter, (b)
#   server CPU / lock contention / handler cost, (c) the TCP connect-per-call
#   cost, and (d) network round-trip latency between this probe and the node.
#   It is NOT an isolated measurement of limiter engagement.
#
#   What it CANNOT measure: the limiter's INTERNAL token state. The S-014
#   bucket (`net::RateLimiter`, include/determ/net/rate_limiter.hpp) exposes
#   NO RPC — there is no "tokens remaining" / "current fill" endpoint in
#   rpc.cpp::dispatch. So this tool cannot prove the limiter is or isn't the
#   bottleneck; it can only CORRELATE the observed rate against the advertised
#   posture and the count of `rate_limited` replies it actually received:
#
#     - `protections.rpc_rate_limit` (status, node.cpp:2537) is a BOOLEAN:
#       true iff (rpc_rate_per_sec > 0 AND rpc_rate_burst > 0). The CONFIGURED
#       numeric rate/burst are NOT exposed over RPC (they live only in
#       Config::to_json on disk — node.cpp:31-32), so this tool reports the
#       boolean and, when the operator supplies them, the operator-asserted
#       --configured-rate / --configured-burst for the correlation line. With
#       neither config access nor those flags, the correlation is qualitative.
#     - the count of `rate_limited` error replies (rpc.cpp:172-174) the probe
#       itself triggered IS a direct, honest signal that the limiter engaged
#       during the window — that is the one piece of limiter behaviour this
#       tool can observe on the wire, and it is reported explicitly.
#
#   The bottom line printed in every report + in --help: "this is end-to-end
#   achievable rate (limiter + server load + network combined), not limiter
#   engagement in isolation."
#
# ── SAFETY: strictly READ-ONLY ───────────────────────────────────────────────
#
#   The ONLY method this tool ever puts on the wire is `status` — a read-only
#   query handler (rpc.cpp dispatch → node.cpp::rpc_status; shared/lock-free
#   readback, no state_mutex_ unique_lock, no tx build/broadcast). It sends
#   MANY of them (that is the point — to measure rate), but never a mutating
#   method. No config is written, no chain state changes.
#
#   Note on load: by design this probe drives the RPC socket at the highest
#   rate it can achieve, which is a (light) load on the node. It is bounded by
#   --duration-sec and an optional --max-requests cap. Run it against a node
#   you operate; it is a diagnostic, not something to point at a third party's
#   daemon.
#
# ── Findings / severity ──────────────────────────────────────────────────────
#
#   OK    measurement completed; achievable rate reported with the posture
#         correlation. Exit 0.
#   INFO  limiter advertised DISABLED (rpc_rate_limit=false) — the observed
#         rate reflects pure server/network capacity, not a limiter. OR the
#         probe was itself rate-limited (limiter engaged) — reported as the
#         direct limiter-engagement signal, not an error. Exit 0.
#   WARN  --expected-min-rps supplied AND achievable rate fell below it — the
#         node is slower than the operator's SLO (could be limiter, load, or
#         network). Surfaced for investigation. Exit 0 normally; exit 2 under
#         --anomalies-only (cron/CI alert gate, house convention).
#
# Usage:
#   tools/operator_rpc_throughput_probe.sh [--rpc-port N] [--host H]
#       [--duration-sec N] [--max-requests N] [--timeout SEC]
#       [--configured-rate R] [--configured-burst B] [--expected-min-rps R]
#       [--anomalies-only] [--json]
#
# Exit codes (house contract):
#   0   ok / info / skip (unreachable daemon → INFO+SKIP)
#   1   transport error (malformed reply) / bad args
#   2   --anomalies-only AND achievable rate below --expected-min-rps
set -u

usage() {
  cat <<'EOF'
Usage: operator_rpc_throughput_probe.sh [--rpc-port N] [--host H]
       [--duration-sec N] [--max-requests N] [--timeout SEC]
       [--configured-rate R] [--configured-burst B] [--expected-min-rps R]
       [--anomalies-only] [--json]

Measures the LIVE achievable RPC throughput of a determ daemon: fires
read-only `status` polls as fast as it can for a fixed window and reports
requests/sec of SUCCESSFUL replies, then correlates that against the node's
advertised rate-limit posture (the `protections.rpc_rate_limit` boolean in
the status reply).

HONESTY / SCOPE — read this:
  This measures END-TO-END achievable rate (the COMBINED effect of the S-014
  token-bucket limiter + server load/lock-contention + connect-per-call cost
  + network round-trip), NOT limiter engagement in isolation. The limiter's
  internal token state is NOT exposed over RPC (no endpoint in rpc.cpp), so
  this tool cannot prove the limiter is the bottleneck. It reports:
    - the advertised limiter posture (a BOOLEAN — the configured numeric
      rate/burst are NOT RPC-exposed; supply them via --configured-rate /
      --configured-burst for a quantitative correlation line),
    - the count of `rate_limited` replies the probe itself triggered (the one
      direct, on-the-wire signal that the limiter engaged during the window),
    - the achievable successful-request rate.
  Strictly READ-ONLY: the only method sent is `status`. It IS sent at high
  volume (that is the measurement) — run it only against a node you operate.

Options:
  --rpc-port N          RPC port of the running daemon (default: 7778).
  --host H              Host to connect to (default: 127.0.0.1).
  --duration-sec N      Measurement window in seconds (default: 5, min 1).
  --max-requests N      Hard cap on total requests sent (default: 0 = no cap;
                        the window is the only bound). Use to bound load.
  --timeout SEC         Per-request socket connect/read timeout (default: 3).
  --configured-rate R   Operator-asserted rpc_rate_per_sec (from config.json,
                        since it is NOT RPC-exposed). Enables a quantitative
                        "observed vs configured" correlation line. Float ok.
  --configured-burst B  Operator-asserted rpc_rate_burst (same rationale).
  --expected-min-rps R  SLO floor: if achievable successful-rps < R, emit a
                        WARN (and exit 2 under --anomalies-only). Float ok.
  --anomalies-only      Suppress neutral rows; print only findings + verdict.
                        A clean run prints just the verdict. Any anomaly
                        present makes the exit code 2 in this mode.
  --json                Emit a single-line JSON envelope instead of the report.
  -h, --help            Show this help and exit 0.

JSON shape (--json):
  {"host":"...","rpc_port":N,"duration_sec":N,"timeout_sec":N,
   "limiter_advertised":bool,            # protections.rpc_rate_limit
   "configured_rate":R|null,"configured_burst":B|null,  # operator-asserted
   "requests_sent":N,"successful":N,"rate_limited":N,"errors":N,
   "elapsed_sec":F,
   "achievable_rps":F,                   # successful / elapsed
   "attempted_rps":F,                    # requests_sent / elapsed
   "expected_min_rps":R|null,
   "correlation":"...",                  # human one-liner
   "findings":[{"severity":"...","message":"..."}],
   "verdict":"OK"|"INFO"|"WARN",
   "skipped":false,"exit_code":0|2}

  Unreachable daemon → {"skipped":true,...} and exit 0.

Exit codes:
  0   ok / info / skip (unreachable daemon → INFO+SKIP)
  1   transport error (malformed reply) / bad args
  2   --anomalies-only AND achievable rate below --expected-min-rps
EOF
}

RPC_PORT=7778
HOST="127.0.0.1"
DURATION_SEC=5
MAX_REQUESTS=0
TIMEOUT=3
CONFIGURED_RATE=""
CONFIGURED_BURST=""
EXPECTED_MIN_RPS=""
ANOMALIES_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           RPC_PORT="${2:-}";        shift 2 ;;
    --host)               HOST="${2:-}";            shift 2 ;;
    --duration-sec)       DURATION_SEC="${2:-}";    shift 2 ;;
    --max-requests)       MAX_REQUESTS="${2:-}";    shift 2 ;;
    --timeout)            TIMEOUT="${2:-}";         shift 2 ;;
    --configured-rate)    CONFIGURED_RATE="${2:-}"; shift 2 ;;
    --configured-burst)   CONFIGURED_BURST="${2:-}";shift 2 ;;
    --expected-min-rps)   EXPECTED_MIN_RPS="${2:-}";shift 2 ;;
    --anomalies-only)     ANOMALIES_ONLY=1;         shift ;;
    --json)               JSON_OUT=1;               shift ;;
    *) echo "operator_rpc_throughput_probe: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric / value guards (same disposition as the rpc-probe siblings) ───────
case "$RPC_PORT" in *[!0-9]*|"")
  echo "operator_rpc_throughput_probe: --rpc-port must be a positive integer (got '$RPC_PORT')" >&2
  exit 1 ;;
esac
if [ "$RPC_PORT" -lt 1 ] || [ "$RPC_PORT" -gt 65535 ]; then
  echo "operator_rpc_throughput_probe: --rpc-port must be 1..65535 (got '$RPC_PORT')" >&2
  exit 1
fi
case "$DURATION_SEC" in *[!0-9]*|"")
  echo "operator_rpc_throughput_probe: --duration-sec must be a positive integer (got '$DURATION_SEC')" >&2
  exit 1 ;;
esac
if [ "$DURATION_SEC" -lt 1 ]; then
  echo "operator_rpc_throughput_probe: --duration-sec must be >= 1 (got '$DURATION_SEC')" >&2
  exit 1
fi
case "$MAX_REQUESTS" in *[!0-9]*|"")
  echo "operator_rpc_throughput_probe: --max-requests must be a non-negative integer (got '$MAX_REQUESTS')" >&2
  exit 1 ;;
esac
case "$TIMEOUT" in *[!0-9]*|"")
  echo "operator_rpc_throughput_probe: --timeout must be a positive integer seconds (got '$TIMEOUT')" >&2
  exit 1 ;;
esac
if [ "$TIMEOUT" -lt 1 ]; then
  echo "operator_rpc_throughput_probe: --timeout must be >= 1 (got '$TIMEOUT')" >&2
  exit 1
fi
if [ -z "$HOST" ]; then
  echo "operator_rpc_throughput_probe: --host must not be empty" >&2
  exit 1
fi
# Float-valued knobs: validate as non-negative decimals.
for pair in "configured-rate:$CONFIGURED_RATE" "configured-burst:$CONFIGURED_BURST" "expected-min-rps:$EXPECTED_MIN_RPS"; do
  name="${pair%%:*}"; val="${pair#*:}"
  [ -z "$val" ] && continue
  case "$val" in
    *[!0-9.]*|*.*.*|"")
      echo "operator_rpc_throughput_probe: --$name must be a non-negative number (got '$val')" >&2
      exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
# Pure socket probe — never invokes the determ binary, so pre-set DETERM_BIN
# to ':' (same pattern as operator_rpc_auth_probe.sh / operator_rpc_method_surface.sh)
# so common.sh's binary-presence check passes on an ops workstation that has no
# built determ.exe but does have network reach to the daemon.
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# All wire I/O, timing, and rendering happen in Python: a tight connect/send/
# recv loop with monotonic timing reads more clearly than a bash nc/jq loop,
# and Python ships everywhere the determ build pipeline ships (no new dep) —
# identical pattern to the rpc-probe siblings.
#
# Python emits the final exit code; capture and forward it verbatim so an
# external `|| exit 1` wrapper can't collapse the exit-2 alert gate to exit-1.
python - "$HOST" "$RPC_PORT" "$DURATION_SEC" "$MAX_REQUESTS" "$TIMEOUT" \
         "$CONFIGURED_RATE" "$CONFIGURED_BURST" "$EXPECTED_MIN_RPS" \
         "$ANOMALIES_ONLY" "$JSON_OUT" <<'PY'
import json, socket, sys, time

host            = sys.argv[1]
rpc_port        = int(sys.argv[2])
duration_sec    = int(sys.argv[3])
max_requests    = int(sys.argv[4])           # 0 = no cap
timeout         = float(sys.argv[5])
configured_rate  = float(sys.argv[6]) if sys.argv[6] else None
configured_burst = float(sys.argv[7]) if sys.argv[7] else None
expected_min_rps = float(sys.argv[8]) if sys.argv[8] else None
anomalies_only  = sys.argv[9] == "1"
json_out        = sys.argv[10] == "1"


def emit_skip():
    """Daemon unreachable → clean INFO + SKIP, exit 0 (house convention)."""
    if json_out:
        print(json.dumps({
            "host": host, "rpc_port": rpc_port,
            "duration_sec": duration_sec, "timeout_sec": timeout,
            "limiter_advertised": None,
            "configured_rate": configured_rate, "configured_burst": configured_burst,
            "requests_sent": 0, "successful": 0, "rate_limited": 0, "errors": 0,
            "elapsed_sec": 0.0, "achievable_rps": 0.0, "attempted_rps": 0.0,
            "expected_min_rps": expected_min_rps,
            "correlation": "daemon unreachable", "findings": [],
            "verdict": "INFO", "skipped": True, "exit_code": 0,
        }))
    else:
        print(f"INFO: no determ RPC reachable at {host}:{rpc_port} "
              f"(daemon not running?) - SKIP")
    sys.exit(0)


def rpc_status_once():
    """Open a fresh socket, send one unauthenticated newline-delimited `status`
    request, read one newline-delimited JSON reply. Returns the parsed reply
    dict. Fresh socket per call mirrors rpc::rpc_call's connect-per-call
    pattern (and is what a real RPC client costs per request — so the rate we
    measure includes that connect cost, honestly). Raises on transport error."""
    req = {"method": "status", "params": {}}
    line = (json.dumps(req) + "\n").encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, rpc_port))
        s.sendall(line)
        chunks = []
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            chunks.append(buf)
            if b"\n" in buf:
                break
        raw = b"".join(chunks)
    finally:
        try:
            s.close()
        except Exception:
            pass
    if not raw:
        raise RuntimeError("empty reply from RPC socket (daemon closed connection)")
    text = raw.split(b"\n", 1)[0].decode("utf-8", "replace")
    return json.loads(text)


# ── Warm-up probe: one status to (a) confirm reachability and (b) read the
#    advertised limiter posture before the timed loop. Connection refused /
#    timeout → daemon unreachable → SKIP. ──────────────────────────────────────
try:
    warm = rpc_status_once()
except (ConnectionRefusedError, socket.timeout, TimeoutError):
    emit_skip()
except OSError as e:
    err = getattr(e, "errno", None)
    if err in (61, 111, 10061, 113, 10065, 10060):  # ECONNREFUSED/EHOSTUNREACH/etc.
        emit_skip()
    sys.stderr.write(
        f"operator_rpc_throughput_probe: cannot reach RPC at {host}:{rpc_port} ({e})\n")
    sys.exit(1)
except Exception as e:
    sys.stderr.write(
        f"operator_rpc_throughput_probe: malformed reply from {host}:{rpc_port}: {e}\n")
    sys.exit(1)

# Read the advertised limiter posture from the warm-up status result.
# protections.rpc_rate_limit is a BOOLEAN (node.cpp:2537): true iff
# rpc_rate_per_sec>0 AND rpc_rate_burst>0. The numeric values are NOT here.
limiter_advertised = None
warm_result = warm.get("result", None)
warm_err    = warm.get("error", None)
if isinstance(warm_result, dict):
    prot = warm_result.get("protections", None)
    if isinstance(prot, dict) and "rpc_rate_limit" in prot:
        limiter_advertised = bool(prot["rpc_rate_limit"])
# If the warm-up was itself rate_limited, we still proceed — the timed loop
# will quantify it. If auth is enforced (status returned auth_required), the
# `status` read is still allowed unauthenticated in the default build, but if
# this server gates it we record errors honestly in the loop.

# ── Timed throughput loop ─────────────────────────────────────────────────────
# Fire status as fast as possible until the wall-clock window elapses or the
# --max-requests cap is hit. Classify each reply:
#   successful    → has a non-null result and no error
#   rate_limited  → error == "rate_limited" (S-014 engaged — the ONE direct
#                   on-the-wire limiter-engagement signal we can observe)
#   errors        → any other error reply OR a transport exception
requests_sent = 0
successful    = 0
rate_limited  = 0
errors        = 0

t0 = time.monotonic()
deadline = t0 + duration_sec
while True:
    now = time.monotonic()
    if now >= deadline:
        break
    if max_requests > 0 and requests_sent >= max_requests:
        break
    requests_sent += 1
    try:
        r = rpc_status_once()
    except Exception:
        errors += 1
        continue
    e = r.get("error", None)
    res = r.get("result", None)
    if e is None and res is not None:
        successful += 1
    elif e == "rate_limited":
        rate_limited += 1
    else:
        errors += 1
elapsed = max(1e-9, time.monotonic() - t0)

achievable_rps = successful / elapsed
attempted_rps  = requests_sent / elapsed

# ── Correlation line ──────────────────────────────────────────────────────────
# Honest, qualitative-by-default. If the operator supplied --configured-rate,
# we can state the observed-vs-configured comparison; otherwise we only have
# the boolean + the rate_limited count.
corr_bits = []
if limiter_advertised is True:
    corr_bits.append("limiter ADVERTISED ENABLED (rpc_rate_limit=true)")
elif limiter_advertised is False:
    corr_bits.append("limiter ADVERTISED DISABLED (rpc_rate_limit=false)")
else:
    corr_bits.append("limiter posture UNKNOWN (status did not expose "
                     "protections.rpc_rate_limit)")

if rate_limited > 0:
    corr_bits.append(f"{rate_limited} of {requests_sent} requests returned "
                     f"rate_limited (limiter ENGAGED during the window)")
else:
    corr_bits.append("no rate_limited replies observed "
                     "(limiter did not visibly engage at this load)")

if configured_rate is not None:
    # Operator-asserted steady-state. Note: the achievable rate can legitimately
    # exceed configured_rate transiently due to the burst bucket, and can fall
    # below it for reasons unrelated to the limiter (CPU/network). State the
    # comparison without overclaiming causation.
    if achievable_rps <= configured_rate * 1.10:
        corr_bits.append(
            f"achievable {achievable_rps:.1f}/s is at/below configured "
            f"{configured_rate:.1f}/s (steady-state) — CONSISTENT with the "
            f"limiter being a binding constraint (but server/network load "
            f"could equally explain it)")
    else:
        corr_bits.append(
            f"achievable {achievable_rps:.1f}/s EXCEEDS configured "
            f"{configured_rate:.1f}/s — expected when measuring under the "
            f"burst ceiling, or the limiter is not the active constraint")
correlation = "; ".join(corr_bits)

# ── Findings + verdict ────────────────────────────────────────────────────────
findings = []   # [{"severity","message"}]

if limiter_advertised is False:
    findings.append({
        "severity": "INFO",
        "message": "RPC rate-limit advertised DISABLED — the achievable rate "
                   "reflects raw server/network capacity, not a configured "
                   "limiter. (S-014 per-IP protection is not enforced in-process; "
                   "see operator_rate_limiter_audit.sh for the static config audit.)",
    })
if rate_limited > 0:
    findings.append({
        "severity": "INFO",
        "message": f"limiter ENGAGED: {rate_limited}/{requests_sent} probe "
                   f"requests returned rate_limited (S-014 token bucket fired "
                   f"before dispatch, rpc.cpp:172). This is the one direct "
                   f"on-the-wire signal of limiter engagement.",
    })
if errors > 0:
    findings.append({
        "severity": "INFO",
        "message": f"{errors}/{requests_sent} probe requests ended in a "
                   f"transport error or a non-rate_limited error reply "
                   f"(e.g. auth_required if this server gates status, or "
                   f"socket timeouts under load) — excluded from the "
                   f"successful-rate numerator.",
    })

verdict = "OK"
exit_code = 0
slo_breached = False
if expected_min_rps is not None and achievable_rps < expected_min_rps:
    slo_breached = True
    findings.append({
        "severity": "WARN",
        "message": f"achievable {achievable_rps:.1f} req/s is BELOW the "
                   f"--expected-min-rps floor of {expected_min_rps:.1f} req/s. "
                   f"Cause is end-to-end (limiter + server load + network) and "
                   f"NOT isolable from this measurement — investigate the "
                   f"limiter config, node CPU/IO, and the probe-to-node path.",
    })

if slo_breached:
    verdict = "WARN"
elif any(f["severity"] == "INFO" for f in findings):
    verdict = "INFO"
else:
    verdict = "OK"

# House exit-code contract: under --anomalies-only, an anomaly (the WARN SLO
# breach) makes the exit code 2 so cron/CI alerts. INFO findings are NOT
# anomalies (they are expected posture signals), so they never gate exit 2.
if anomalies_only and slo_breached:
    exit_code = 2

# ── Emit ──────────────────────────────────────────────────────────────────────
if json_out:
    print(json.dumps({
        "host": host, "rpc_port": rpc_port,
        "duration_sec": duration_sec, "timeout_sec": timeout,
        "limiter_advertised": limiter_advertised,
        "configured_rate": configured_rate, "configured_burst": configured_burst,
        "requests_sent": requests_sent, "successful": successful,
        "rate_limited": rate_limited, "errors": errors,
        "elapsed_sec": round(elapsed, 4),
        "achievable_rps": round(achievable_rps, 3),
        "attempted_rps": round(attempted_rps, 3),
        "expected_min_rps": expected_min_rps,
        "correlation": correlation,
        "findings": findings, "verdict": verdict,
        "skipped": False, "exit_code": exit_code,
    }))
    sys.exit(exit_code)

sev_tag = {"OK": "[OK]", "INFO": "[INFO]", "WARN": "[WARN]", "CRITICAL": "[CRIT]"}

if not anomalies_only:
    print(f"=== RPC throughput probe ({host}:{rpc_port}) ===")
    la = ("enabled" if limiter_advertised is True
          else "disabled" if limiter_advertised is False
          else "unknown")
    print(f"Limiter advertised:  {la}  (protections.rpc_rate_limit; "
          f"numeric rate/burst NOT RPC-exposed)")
    if configured_rate is not None or configured_burst is not None:
        cr = f"{configured_rate:.1f}/s" if configured_rate is not None else "?"
        cb = f"{configured_burst:.1f}"  if configured_burst is not None else "?"
        print(f"Configured (asserted): rate {cr}, burst {cb}  (operator-supplied)")
    print(f"Window:              {duration_sec}s "
          f"(elapsed {elapsed:.2f}s, timeout {timeout:.0f}s/req"
          + (f", max {max_requests} req" if max_requests > 0 else "") + ")")
    print(f"Requests sent:       {requests_sent}")
    print(f"  successful:        {successful}")
    print(f"  rate_limited:      {rate_limited}")
    print(f"  errors:            {errors}")
    print(f"Achievable rate:     {achievable_rps:.1f} successful req/s")
    print(f"Attempted rate:      {attempted_rps:.1f} req/s (sent, incl. failures)")
    if expected_min_rps is not None:
        print(f"Expected-min floor:  {expected_min_rps:.1f} req/s")
    print(f"Correlation:         {correlation}")
    print("Scope:               END-TO-END achievable rate (limiter + server "
          "load + network combined),")
    print("                     NOT limiter engagement in isolation — the "
          "limiter's token state is not RPC-exposed.")
    print()

if findings:
    if anomalies_only:
        rows = [f for f in findings if f["severity"] in ("CRITICAL", "WARN")]
        if rows:
            print(f"=== RPC throughput anomalies ({host}:{rpc_port}) ===")
            for f in rows:
                print(f"  {sev_tag.get(f['severity'], '[?]'):<7} {f['message']}")
            print()
    else:
        print("Findings:")
        for f in findings:
            print(f"  {sev_tag.get(f['severity'], '[?]'):<7} {f['message']}")
        print()

if verdict == "WARN":
    print(f"[ANOMALY] achievable rate below the expected-min floor — review "
          f"limiter / load / network (end-to-end, not isolable)")
elif verdict == "INFO":
    print(f"[OK] measurement complete: {achievable_rps:.1f} req/s achievable "
          f"(see INFO findings for limiter posture)")
else:
    print(f"[OK] measurement complete: {achievable_rps:.1f} req/s achievable")

sys.exit(exit_code)
PY
PY_RC=$?
# Forward Python's rc verbatim: 0 ok/info/skip, 1 transport/internal/bad-arg,
# 2 anomaly under --anomalies-only. Preserves the exit-2 gate end-to-end.
exit "$PY_RC"
