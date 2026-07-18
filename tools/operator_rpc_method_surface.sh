#!/usr/bin/env bash
# operator_rpc_method_surface.sh — LIVE map of this node's RPC METHOD SURFACE
# and whether its STATE-MUTATING methods are gated behind S-001 HMAC auth.
#
# The operator question this answers — and that no existing tool answers:
#
#   "The determ RPC server's dispatch() (src/rpc/rpc.cpp:197-272) routes a
#    FIXED set of methods, and that set MIXES read-only queries (status,
#    balance, validators, committee, ...) WITH state-MUTATING calls (send,
#    stake, unstake, register, submit_tx, submit_equivocation). There is no
#    per-method ACL — the ONLY thing standing between an anonymous caller
#    and a tx-creating RPC is the single global HMAC gate (verify_auth,
#    src/rpc/rpc.cpp:112). So: on THIS running node, is that mutating
#    surface actually gated, or can an unauthenticated caller reach
#    `send` / `submit_tx`?"
#
# This is distinct from the two existing siblings in this lane:
#
#   operator_rpc_auth_probe.sh   — proves auth is ENFORCED using exactly ONE
#                                  method (`status`). It tells you the global
#                                  gate exists; it does NOT enumerate the
#                                  method surface or distinguish the mutating
#                                  subset that the gate is actually protecting.
#   operator_rate_limiter_audit.sh — lints the S-014 rate knobs in a STATIC
#                                  config.json; never touches the wire and
#                                  says nothing about methods.
#
# This tool is the per-method, mutating-surface complement: it enumerates the
# dispatch() method table, classifies each entry read-only vs mutating, and —
# for the mutating subset — confirms on the wire whether the global auth gate
# rejects an UNauthenticated call before dispatch runs.
#
# ── SAFETY: why this is strictly READ-ONLY ───────────────────────────────────
#
#   The server checks auth BEFORE it dispatches (src/rpc/rpc.cpp:179-184):
#
#       std::string auth_err = verify_auth(req);
#       if (!auth_err.empty()) { ... error ... }   // ← returns here
#       else { response["result"] = dispatch(req); } // ← only runs if auth ok
#
#   So when auth is ENFORCED, sending a mutating method (e.g. `send`) with NO
#   `auth` field is rejected with "auth_required" *before* rpc_send() — the
#   handler that builds and broadcasts a tx — is ever reached. The probe
#   therefore confirms the gate WITHOUT triggering a mutation.
#
#   When auth is OPEN (no rpc_auth_secret), the OPPOSITE is true: a mutating
#   method WOULD execute. e.g. rpc_send(to="",amount=0,fee=0) passes the
#   balance pre-check (cost 0) and actually queues + broadcasts a zero-value
#   tx (src/node/node.cpp:2862-2899). THEREFORE THIS TOOL NEVER SENDS A
#   MUTATING METHOD WHEN AUTH IS OPEN. In the OPEN case the posture itself is
#   the finding (the entire mutating surface is ungated) and the tool reports
#   it from the known dispatch() table without poking any mutating handler.
#
#   Read-only methods are likewise never actively invoked here — the only
#   request this tool ever puts on the wire is an unauthenticated `status`
#   (the same discriminating probe operator_rpc_auth_probe.sh uses) plus, when
#   and only when auth is ENFORCED, unauthenticated mutating-method calls that
#   are guaranteed to bounce at the auth gate before dispatch.
#
# ── What is and is NOT observable (honesty note) ─────────────────────────────
#
#   OBSERVABLE over RPC:
#     - posture of the global auth gate (ENFORCED / OPEN / RATE_LIMITED), via
#       the unauthenticated status probe.
#     - that each mutating method, when auth is ENFORCED, returns auth_required
#       to an unauthenticated caller (i.e. the gate covers it, not just status).
#
#   NOT observable over RPC (reported from the source-pinned dispatch() table,
#   NOT claimed to be read off the wire):
#     - the method ROSTER itself. dispatch() has no "list methods" RPC; an
#       unknown method just throws "Unknown method: X" (src/rpc/rpc.cpp:271).
#       The read/mutating classification below is therefore a STATIC baseline
#       compiled from src/rpc/rpc.cpp at the cited lines, surfaced for the
#       operator, and (for the mutating subset under ENFORCED auth) confirmed
#       reachable-but-gated on the wire.
#     - S-022 per-message-size caps. Those live in the gossip/peer framing
#       layer (src/net/peer.cpp), NOT in the RPC server, so they are out of
#       scope for an RPC probe and are deliberately NOT asserted here.
#     - whether the bind is loopback-only. The operator asserts that with
#       --external-bind (same convention as operator_rpc_auth_probe.sh); the
#       RPC surface does not expose its own bind address.
#
# ── Method table (source-pinned to src/rpc/rpc.cpp::dispatch) ─────────────────
#
#   MUTATING (take state_mutex_ unique_lock and/or build+broadcast a tx):
#     register, send, stake, unstake, submit_tx, submit_equivocation
#       (src/rpc/rpc.cpp:203,206,212,217,226,228 → handlers in
#        src/node/node.cpp: rpc_register/ rpc_send/ rpc_stake/ rpc_unstake/
#        rpc_submit_tx/ rpc_submit_equivocation)
#   READ-ONLY (queries; shared_lock or lock-free):
#     status, peers, balance, nonce, stake_info, snapshot, state_root,
#     state_proof, dapp_info, dapp_list, dapp_messages, block, headers,
#     chain_summary, validators, committee, account, tx, pending_params,
#     abort_records, scan_enotes   (src/rpc/rpc.cpp:201..270)
#
# ── Findings / severity ──────────────────────────────────────────────────────
#
#   OK        auth ENFORCED and every mutating method probed returned
#             auth_required to the unauthenticated caller — the mutating
#             surface is gated. Exit 0.
#   CRITICAL  auth OPEN AND --external-bind — the full mutating surface
#             (send/stake/unstake/register/submit_tx/submit_equivocation) is
#             reachable by any unauthenticated remote caller. Exit 2.
#   WARN      auth OPEN on loopback — mutating surface is ungated but only
#             reachable from localhost (documented single-host dev posture);
#             still flagged because anything that reaches loopback (a local
#             web app, a container sidecar) can mint txs with no credential.
#             Exit 0 (or 2 under --anomalies-only, per the exit contract).
#   WARN      auth ENFORCED but a mutating method returned something OTHER
#             than auth_required to an unauthenticated call (unexpected gate
#             inconsistency — review). Exit 0 (or 2 under --anomalies-only).
#   INFO      probe rate-limited (S-014 fired before auth) — posture
#             indeterminate; re-run after the bucket refills. Exit 0.
#
# Usage:
#   tools/operator_rpc_method_surface.sh [--rpc-port N] [--host H]
#       [--external-bind] [--timeout SEC] [--anomalies-only] [--json]
#
# Exit codes (house contract):
#   0   ok / info / skip (unreachable daemon, rate-limited, OPEN-on-loopback)
#   1   transport error (no daemon / malformed reply) or bad args
#   2   CRITICAL (OPEN + --external-bind); OR --anomalies-only AND any anomaly
set -u

usage() {
  cat <<'EOF'
Usage: operator_rpc_method_surface.sh [--rpc-port N] [--host H]
       [--external-bind] [--timeout SEC] [--anomalies-only] [--json]

LIVE map of the determ RPC method surface and whether its STATE-MUTATING
methods (send, stake, unstake, register, submit_tx, submit_equivocation) are
gated behind the S-001 HMAC auth gate. Strictly read-only: the only wire
traffic is an unauthenticated `status` probe plus — ONLY when auth is
ENFORCED — unauthenticated mutating-method calls that are guaranteed to be
rejected at the auth gate BEFORE dispatch runs (src/rpc/rpc.cpp:179-184), so
no mutation is ever triggered. When auth is OPEN the tool sends NO mutating
method at all (it would execute) and reports the posture from the
source-pinned dispatch() table instead.

Options:
  --rpc-port N     RPC port of the running daemon (default: 7778).
  --host H         Host to connect to (default: 127.0.0.1). Loopback /
                   operator-local use is intended; a remote host is accepted
                   but the bind classification is the operator's to assert.
  --external-bind  Assert the node binds a non-loopback interface
                   (rpc_localhost_only=false). With this flag an OPEN posture
                   (mutating surface ungated) is CRITICAL rather than WARN,
                   because the tx-creating RPCs are then reachable by any
                   remote unauthenticated caller.
  --timeout SEC    Socket connect/read timeout, seconds (default: 5).
  --anomalies-only Suppress neutral rows; print ONLY findings + verdict. A
                   clean run prints just the verdict. Per the exit contract,
                   any anomaly present makes the exit code 2 in this mode.
  --json           Emit a single-line JSON envelope instead of the report.
  -h, --help       Show this help and exit 0.

JSON shape (--json):
  {"host":"...","rpc_port":N,"external_bind":bool,
   "posture":"ENFORCED"|"OPEN"|"RATE_LIMITED",
   "mutating_methods":[ "...", ... ],
   "readonly_methods":[ "...", ... ],
   "mutating_probe":[ {"method":"...","gated":bool|null,"detail":"..."} ],
   "findings":[ {"severity":"...","message":"..."} ],
   "verdict":"OK"|"WARN"|"CRITICAL"|"INFO",
   "skipped":false,
   "exit_code":0|2}

  Unreachable daemon → {"skipped":true,...} and exit 0.

Exit codes:
  0   ok / info / skip (unreachable, rate-limited, OPEN-on-loopback)
  1   transport error (malformed reply) or bad args
  2   CRITICAL (OPEN + --external-bind); OR --anomalies-only AND any anomaly
EOF
}

RPC_PORT=7778
HOST="127.0.0.1"
EXTERNAL_BIND=0
TIMEOUT=5
ANOMALIES_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       RPC_PORT="${2:-}";  shift 2 ;;
    --host)           HOST="${2:-}";      shift 2 ;;
    --external-bind)  EXTERNAL_BIND=1;    shift ;;
    --timeout)        TIMEOUT="${2:-}";   shift 2 ;;
    --anomalies-only) ANOMALIES_ONLY=1;   shift ;;
    --json)           JSON_OUT=1;         shift ;;
    *) echo "operator_rpc_method_surface: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric / value guards (same disposition as operator_rpc_auth_probe.sh).
case "$RPC_PORT" in *[!0-9]*|"")
  echo "operator_rpc_method_surface: --rpc-port must be a positive integer (got '$RPC_PORT')" >&2
  exit 1 ;;
esac
if [ "$RPC_PORT" -lt 1 ] || [ "$RPC_PORT" -gt 65535 ]; then
  echo "operator_rpc_method_surface: --rpc-port must be 1..65535 (got '$RPC_PORT')" >&2
  exit 1
fi
case "$TIMEOUT" in *[!0-9]*|"")
  echo "operator_rpc_method_surface: --timeout must be a positive integer seconds (got '$TIMEOUT')" >&2
  exit 1 ;;
esac
if [ "$TIMEOUT" -lt 1 ]; then
  echo "operator_rpc_method_surface: --timeout must be >= 1 (got '$TIMEOUT')" >&2
  exit 1
fi
if [ -z "$HOST" ]; then
  echo "operator_rpc_method_surface: --host must not be empty" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# Pure socket probe — never invokes the determ binary, so pre-set DETERM_BIN
# to ':' (same pattern as operator_rpc_auth_probe.sh / operator_rate_limiter_audit.sh)
# so common.sh's binary-presence check passes on an ops workstation that has
# no built determ.exe but does have network reach to the daemon.
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# All wire I/O, classification and rendering happen in Python: the socket
# driver and the cross-field severity logic read more clearly than a nc + jq
# chain, and Python ships everywhere the determ build pipeline ships (no new
# dep) — identical to operator_rpc_auth_probe.sh.
#
# Python emits the final exit code; capture and forward it verbatim so an
# external `|| exit 1` wrapper can't collapse the exit-2 alert gate to exit-1.
python - "$HOST" "$RPC_PORT" "$EXTERNAL_BIND" "$TIMEOUT" "$ANOMALIES_ONLY" "$JSON_OUT" <<'PY'
import json, socket, sys

host           = sys.argv[1]
rpc_port       = int(sys.argv[2])
external_bind  = sys.argv[3] == "1"
timeout        = float(sys.argv[4])
anomalies_only = sys.argv[5] == "1"
json_out       = sys.argv[6] == "1"

# ── Source-pinned dispatch() method table (src/rpc/rpc.cpp:197-272) ──────────
# Classification is by handler behaviour confirmed in src/node/node.cpp:
#   MUTATING  → takes std::unique_lock<state_mutex_> and/or builds+broadcasts
#               a tx (rpc_register/ rpc_send/ rpc_stake/ rpc_unstake/
#               rpc_submit_tx/ rpc_submit_equivocation).
#   READ-ONLY → query handlers (shared_lock or lock-free).
# This roster is NOT read off the wire (dispatch() exposes no enumeration RPC);
# it is the static baseline the tool surfaces, then — for the mutating subset
# under ENFORCED auth — confirms reachable-but-gated on the wire.
MUTATING = [
    "register", "send", "stake", "unstake",
    "submit_tx", "submit_equivocation",
]
READONLY = [
    "status", "peers", "balance", "nonce", "stake_info", "snapshot",
    "state_root", "state_proof", "dapp_info", "dapp_list", "dapp_messages",
    "block", "headers", "chain_summary", "validators", "committee",
    "account", "tx", "pending_params", "abort_records", "scan_enotes",
]


def emit_skip():
    """Daemon unreachable → clean INFO + SKIP, exit 0 (house convention)."""
    if json_out:
        print(json.dumps({
            "host": host, "rpc_port": rpc_port, "external_bind": external_bind,
            "posture": None, "mutating_methods": MUTATING,
            "readonly_methods": READONLY, "mutating_probe": [],
            "findings": [], "verdict": "INFO", "skipped": True, "exit_code": 0,
        }))
    else:
        print(f"INFO: no determ RPC reachable at {host}:{rpc_port} "
              f"(daemon not running?) - SKIP")
    sys.exit(0)


def rpc_probe(method, params, auth=None):
    """Open a fresh socket, send one newline-delimited JSON request, read one
    newline-delimited JSON reply. Returns the parsed reply dict; raises on any
    transport/protocol error. Fresh socket per call mirrors rpc::rpc_call's
    connect-per-call pattern."""
    req = {"method": method, "params": params}
    if auth is not None:
        req["auth"] = auth
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


# ── Primary probe: unauthenticated `status` (read-only) to fix the posture ───
# `status` is a read-only handler, so this request is safe regardless of
# posture. Connection refused / timeout → daemon unreachable → SKIP.
try:
    reply = rpc_probe("status", {}, auth=None)
except (ConnectionRefusedError, socket.timeout, TimeoutError):
    emit_skip()
except OSError as e:
    # Other connect-class errors (host unreachable, etc.) are also "no daemon
    # here" for the operator's purposes → SKIP rather than a hard error.
    err = getattr(e, "errno", None)
    if err in (61, 111, 10061, 113, 10065, 10060):  # ECONNREFUSED/EHOSTUNREACH/etc.
        emit_skip()
    sys.stderr.write(
        f"operator_rpc_method_surface: cannot reach RPC at {host}:{rpc_port} "
        f"({e})\n")
    sys.exit(1)
except Exception as e:
    sys.stderr.write(
        f"operator_rpc_method_surface: malformed reply from {host}:{rpc_port}: {e}\n")
    sys.exit(1)

err    = reply.get("error", None)
result = reply.get("result", None)

if err == "rate_limited":
    posture = "RATE_LIMITED"
elif isinstance(err, str) and err.startswith("auth_required"):
    posture = "ENFORCED"
elif err is None and result is not None:
    posture = "OPEN"
else:
    sys.stderr.write(
        f"operator_rpc_method_surface: unexpected RPC reply to unauthenticated "
        f"status (error={err!r}, result_present={result is not None}) — "
        f"cannot classify auth posture\n")
    sys.exit(1)

findings = []        # [{"severity","message"}]
mutating_probe = []  # [{"method","gated":bool|None,"detail"}]

# ── Posture branches ─────────────────────────────────────────────────────────
if posture == "RATE_LIMITED":
    findings.append({
        "severity": "INFO",
        "message": "Probe was rate-limited (S-014 token bucket fired before "
                   "auth could be evaluated) — mutating-surface gating "
                   "indeterminate; re-run after the bucket refills",
    })

elif posture == "ENFORCED":
    # Auth gate present. Confirm it covers the MUTATING subset (not just
    # status) by sending each mutating method WITHOUT an auth field. Because
    # verify_auth runs BEFORE dispatch (src/rpc/rpc.cpp:179-184), an
    # auth_required reply proves the handler is NOT reached — no mutation.
    all_gated = True
    for m in MUTATING:
        try:
            r = rpc_probe(m, {}, auth=None)
        except Exception as e:
            # Transport hiccup mid-enumeration: record indeterminate, keep going.
            mutating_probe.append({"method": m, "gated": None,
                                   "detail": f"probe transport error: {e}"})
            findings.append({
                "severity": "WARN",
                "message": f"could not probe mutating method '{m}' "
                           f"(transport error: {e}) — gating unconfirmed",
            })
            all_gated = False
            continue
        e2 = r.get("error", None)
        if isinstance(e2, str) and e2.startswith("auth_required"):
            mutating_probe.append({"method": m, "gated": True,
                                   "detail": "auth_required (gated before dispatch)"})
        elif e2 == "rate_limited":
            # Throttled this method; not a gating failure — note + skip.
            mutating_probe.append({"method": m, "gated": None,
                                   "detail": "rate_limited (S-014) — gating unconfirmed"})
            findings.append({
                "severity": "INFO",
                "message": f"mutating method '{m}' probe was rate-limited "
                           f"(S-014) — gating unconfirmed this run; re-run later",
            })
        else:
            # auth ENFORCED for status but this mutating method did NOT return
            # auth_required to an unauthenticated call. That is an unexpected
            # gate inconsistency the operator must see. (We did NOT supply an
            # auth field, so a non-auth_required reply means either the method
            # slipped the gate or returned an unusual error.)
            mutating_probe.append({"method": m, "gated": False,
                                   "detail": f"unexpected reply (error={e2!r})"})
            findings.append({
                "severity": "WARN",
                "message": f"mutating method '{m}' did NOT return auth_required "
                           f"to an unauthenticated call (error={e2!r}) — the "
                           f"global auth gate may not uniformly cover the "
                           f"mutating surface; review src/rpc/rpc.cpp dispatch",
            })
            all_gated = False
    if all_gated and mutating_probe and all(p["gated"] for p in mutating_probe):
        findings.append({
            "severity": "OK",
            "message": "RPC auth ENFORCED and every mutating method "
                       "(send/stake/unstake/register/submit_tx/"
                       "submit_equivocation) returned auth_required to an "
                       "unauthenticated caller — mutating surface is gated",
        })

elif posture == "OPEN":
    # Auth DISABLED. The mutating surface is ungated. We MUST NOT send any
    # mutating method here (it would execute — e.g. rpc_send would queue +
    # broadcast a zero-value tx). Report the posture from the static table.
    for m in MUTATING:
        mutating_probe.append({
            "method": m, "gated": False,
            "detail": "auth disabled — reachable unauthenticated (NOT probed: "
                      "sending it would execute the handler)",
        })
    if external_bind:
        findings.append({
            "severity": "CRITICAL",
            "message": "RPC auth is DISABLED and --external-bind asserted: the "
                       "ENTIRE state-mutating RPC surface (send / stake / "
                       "unstake / register / submit_tx / submit_equivocation) "
                       "is reachable by any UNAUTHENTICATED remote caller. Set "
                       "rpc_auth_secret or enable rpc_localhost_only immediately",
        })
    else:
        findings.append({
            "severity": "WARN",
            "message": "RPC auth is DISABLED on a loopback bind: the mutating "
                       "RPC surface is ungated but reachable only from "
                       "localhost (documented single-host dev posture). Any "
                       "local process (web app, container sidecar) can mint "
                       "txs with no credential — set rpc_auth_secret before "
                       "exposing this RPC beyond loopback",
        })

# ── Verdict + exit code ──────────────────────────────────────────────────────
n_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
n_warn     = sum(1 for f in findings if f["severity"] == "WARN")

if n_critical > 0:
    verdict = "CRITICAL"
    exit_code = 2
elif posture == "RATE_LIMITED":
    verdict = "INFO"
    exit_code = 0
elif n_warn > 0:
    # OPEN-on-loopback, or an ENFORCED gate inconsistency. Not a hard exit-2
    # in normal mode; the anomalies-only gate (below) escalates it.
    verdict = "WARN"
    exit_code = 0
else:
    verdict = "OK"
    exit_code = 0

# House exit-code contract: under --anomalies-only, ANY anomaly present makes
# the exit code 2 (so cron/CI alerts on WARN-level findings too). An anomaly
# is any non-OK / non-INFO finding (i.e. CRITICAL or WARN).
n_anomalies = n_critical + n_warn
if anomalies_only and n_anomalies > 0:
    exit_code = 2

# ── Emit ─────────────────────────────────────────────────────────────────────
if json_out:
    print(json.dumps({
        "host": host, "rpc_port": rpc_port, "external_bind": external_bind,
        "posture": posture,
        "mutating_methods": MUTATING, "readonly_methods": READONLY,
        "mutating_probe": mutating_probe,
        "findings": findings, "verdict": verdict,
        "skipped": False, "exit_code": exit_code,
    }))
    sys.exit(exit_code)

sev_tag = {"OK": "[OK]", "INFO": "[INFO]", "WARN": "[WARN]", "CRITICAL": "[CRIT]"}

if not anomalies_only:
    print(f"=== RPC method surface ({host}:{rpc_port}) ===")
    print(f"Auth posture:  {posture}")
    print(f"Bind asserted: {'external (non-loopback)' if external_bind else 'loopback'}")
    print(f"Mutating methods ({len(MUTATING)}): {', '.join(MUTATING)}")
    print(f"Read-only methods ({len(READONLY)}): {', '.join(READONLY)}")
    if mutating_probe:
        print()
        print("Mutating-method gating (unauthenticated probe; auth checked "
              "before dispatch):")
        for p in mutating_probe:
            if p["gated"] is True:
                tag = "[OK]"
            elif p["gated"] is False:
                tag = "[WARN]"
            else:
                tag = "[INFO]"
            print(f"  {tag:<7} {p['method']:<20} {p['detail']}")
    print()

if findings:
    if anomalies_only:
        # Print only CRITICAL / WARN rows in anomalies-only mode.
        rows = [f for f in findings if f["severity"] in ("CRITICAL", "WARN")]
        if rows:
            print(f"=== RPC method-surface anomalies ({host}:{rpc_port}) ===")
            for f in rows:
                print(f"  {sev_tag.get(f['severity'], '[?]'):<7} {f['message']}")
            print()
    else:
        print("Findings:")
        for f in findings:
            print(f"  {sev_tag.get(f['severity'], '[?]'):<7} {f['message']}")
        print()

if verdict == "CRITICAL":
    print(f"[ANOMALY] {n_critical} critical finding(s) — mutating RPC surface "
          f"is reachable unauthenticated on an external bind")
elif verdict == "WARN":
    print(f"[ANOMALY] {n_warn} finding(s) — review the mutating-surface gating "
          f"above")
elif verdict == "INFO":
    print("[OK] mutating-surface gating indeterminate (rate-limited) — re-run later")
else:
    print("[OK] mutating RPC surface is gated behind enforced auth")

sys.exit(exit_code)
PY
PY_RC=$?
# Forward Python's rc verbatim: 0 ok/info/skip, 1 transport/internal/bad-arg,
# 2 CRITICAL (or anomalies-only gate). Preserves the exit-2 gate end-to-end.
exit "$PY_RC"
