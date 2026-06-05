#!/usr/bin/env bash
# operator_rpc_auth_probe.sh — LIVE S-001 RPC-auth enforcement probe.
#
# Answers one operator question a config file can't: "is HMAC RPC auth
# (S-001) actually being ENFORCED on this node's wire RIGHT NOW?" — not
# "is rpc_auth_secret set in the config I happen to be reading", but the
# observable runtime behaviour of the listening RPC socket.
#
# This is the LIVE complement to operator_rate_limiter_audit.sh and
# operator_config_audit.sh, which lint a STATIC config.json snapshot and
# never touch a running daemon. Those answer "did the operator write the
# right knob?"; this answers "does the running server reject an
# unauthenticated read RPC?". The two are disjoint: a config can declare
# rpc_auth_secret while the running process was started from a stale
# config (or a different config), and only an on-the-wire probe catches
# that drift. Equally, an operator restoring from backup may have an
# auth-less config but want to confirm the live socket actually rejects
# anonymous callers before exposing it.
#
# Method (all READ-ONLY — never issues a mutating RPC):
#
#   The probe opens a raw TCP socket to 127.0.0.1:<rpc_port> and speaks
#   the determ RPC wire protocol directly (newline-delimited JSON, one
#   request per line — exactly what rpc::rpc_call emits at
#   src/rpc/rpc.cpp). It deliberately sends a `status` request with NO
#   `auth` field. The determ CLI can't express this (rpc_call always
#   attaches an HMAC when a secret is present — src/rpc/rpc.cpp:297), so
#   the probe drives the socket itself, the same python-driver pattern
#   used by operator_peer_topology.sh.
#
#   The server's reply discriminates the posture (RpcServer::verify_auth,
#   src/rpc/rpc.cpp:112):
#
#     ENFORCED   reply error == "auth_required: missing 'auth' field"
#                The server has a non-empty rpc_auth_secret and rejected
#                the unauthenticated request. S-001 is live. (OK)
#
#     OPEN       reply error == null AND result is a status object
#                The server accepted an unauthenticated `status` — auth
#                is DISABLED on the wire. Whether that is a finding
#                depends on the bind posture (see below): OPEN on a
#                loopback-only node is a documented, common dev/consortium
#                posture (INFO); OPEN combined with a non-loopback bind is
#                the S-001 danger case the server itself warns about at
#                startup (src/rpc/rpc.cpp:98) → CRITICAL.
#
#     RATE_LIMITED  reply error == "rate_limited"
#                The S-014 token bucket consumed this probe before auth
#                was even evaluated (rate-limit fires before auth —
#                src/rpc/rpc.cpp:172). The probe can't determine the auth
#                posture under throttle; reported as UNKNOWN (not a
#                finding — re-run when the bucket has refilled). This
#                interplay is exactly the S-001/S-014 ordering documented
#                in SECURITY.md.
#
# Optional positive/negative controls (still read-only, --secret):
#
#   With --secret <hex>, after the unauthenticated probe the script runs
#   two further read-only `status` probes to confirm the secret behaves:
#
#     POSITIVE   a correctly-HMAC'd `status` request must SUCCEED. A
#                failure here means the operator's secret does NOT match
#                the running server's secret — a deployment-drift CRITICAL
#                (the operator believes they hold the auth key but don't).
#
#     NEGATIVE   a request whose HMAC is computed with a one-byte-flipped
#                key must be REJECTED with "auth_failed". A success here
#                would mean the server is NOT validating the HMAC at all
#                (constant-time-compare bypass) — CRITICAL. This mirrors
#                the tamper case in tools/test_rpc_hmac_auth.sh but as a
#                live operator probe rather than a build-time regression.
#
#   The controls require Python's hmac/hashlib (stdlib — no new dep). The
#   HMAC pre-image is canonical_for_hmac(method, params) =
#   method + "|" + params.dump() (src/rpc/rpc.cpp:52); for `status` params
#   is {} so the pre-image is exactly "status|{}". The probe reproduces
#   that byte-for-byte so a correctly-configured secret authenticates.
#
# Severity policy (exit codes mirror operator_genesis_verify_live.sh /
# operator_rate_limiter_audit.sh — 0 ok, 1 transport/arg error, 2 alert):
#
#   CRITICAL — OPEN posture on a non-loopback bind (--external-bind), OR a
#              --secret positive/negative control failed. Exit 2.
#   INFO     — OPEN posture on loopback (default, documented dev posture).
#              Exit 0.
#   OK       — ENFORCED posture; optional controls passed. Exit 0.
#   UNKNOWN  — probe was rate-limited; posture indeterminate. Exit 0 (not
#              a finding; re-run later).
#
# Usage:
#   tools/operator_rpc_auth_probe.sh [--rpc-port N] [--host H]
#                                    [--secret <hex>] [--external-bind]
#                                    [--timeout SEC] [--json]
#
# Exit codes:
#   0   ENFORCED, or OPEN-on-loopback (INFO), or UNKNOWN (rate-limited)
#   1   transport error (no daemon on the port; bad args; bad secret hex)
#   2   CRITICAL — OPEN on external bind, or a --secret control failed
set -u

usage() {
  cat <<'EOF'
Usage: operator_rpc_auth_probe.sh [--rpc-port N] [--host H] [--secret <hex>]
                                  [--external-bind] [--timeout SEC] [--json]

LIVE probe: does this running determ node ENFORCE S-001 HMAC RPC auth on
the wire? Opens a raw TCP socket and sends an unauthenticated read-only
`status` request, then classifies the server's reply as ENFORCED / OPEN /
RATE_LIMITED. Never issues a mutating RPC.

Options:
  --rpc-port N       RPC port of the running daemon (default: 7778).
  --host H           Host to connect to (default: 127.0.0.1). The probe is
                     intended for loopback / operator-local use; a remote
                     host is accepted but the bind-posture classification
                     (--external-bind) is the operator's to assert.
  --secret <hex>     If set, additionally run two read-only control
                     probes: a POSITIVE probe (correct HMAC must succeed)
                     and a NEGATIVE probe (tampered HMAC must be rejected
                     with auth_failed). A failed control is CRITICAL —
                     either the operator's secret doesn't match the server
                     (positive fail) or the server isn't validating HMAC
                     (negative fail). Secret is 2N hex chars, same form as
                     rpc_auth_secret / DETERM_RPC_AUTH_SECRET.
  --external-bind    Assert the node binds a non-loopback interface
                     (rpc_localhost_only=false). With this flag an OPEN
                     posture (auth disabled) is CRITICAL rather than INFO,
                     because an externally-reachable RPC with no auth is
                     the S-001 danger case the server warns about at
                     startup. Without the flag, OPEN is treated as the
                     documented loopback dev/consortium posture (INFO).
  --timeout SEC      Socket connect/read timeout in seconds (default: 5).
  --json             Emit a single-line JSON envelope instead of the
                     human report.
  -h, --help         Show this help.

JSON shape (--json):
  {"host": "...", "rpc_port": N, "external_bind": bool,
   "posture": "ENFORCED" | "OPEN" | "RATE_LIMITED",
   "auth_enforced": bool | null,
   "controls": {"positive": "pass"|"fail"|"skip",
                "negative": "pass"|"fail"|"skip"},
   "findings": [{"severity":"...", "message":"..."}],
   "verdict": "OK" | "INFO" | "UNKNOWN" | "CRITICAL",
   "exit_code": 0 | 2}

Exit codes:
  0   ENFORCED, OPEN-on-loopback (INFO), or RATE_LIMITED (UNKNOWN)
  1   transport error (no daemon; bad args; bad secret hex)
  2   CRITICAL — OPEN on external bind, or a --secret control failed
EOF
}

RPC_PORT=7778
HOST="127.0.0.1"
SECRET=""
EXTERNAL_BIND=0
TIMEOUT=5
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       RPC_PORT="${2:-}";     shift 2 ;;
    --host)           HOST="${2:-}";         shift 2 ;;
    --secret)         SECRET="${2:-}";       shift 2 ;;
    --external-bind)  EXTERNAL_BIND=1;       shift ;;
    --timeout)        TIMEOUT="${2:-}";      shift 2 ;;
    --json)           JSON_OUT=1;            shift ;;
    *) echo "operator_rpc_auth_probe: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards (same disposition as operator_peer_topology.sh).
case "$RPC_PORT" in *[!0-9]*|"")
  echo "operator_rpc_auth_probe: --rpc-port must be a positive integer (got '$RPC_PORT')" >&2
  exit 1 ;;
esac
if [ "$RPC_PORT" -lt 1 ] || [ "$RPC_PORT" -gt 65535 ]; then
  echo "operator_rpc_auth_probe: --rpc-port must be 1..65535 (got '$RPC_PORT')" >&2
  exit 1
fi
case "$TIMEOUT" in *[!0-9]*|"")
  echo "operator_rpc_auth_probe: --timeout must be a positive integer seconds (got '$TIMEOUT')" >&2
  exit 1 ;;
esac
if [ "$TIMEOUT" -lt 1 ]; then
  echo "operator_rpc_auth_probe: --timeout must be >= 1 (got '$TIMEOUT')" >&2
  exit 1
fi
if [ -z "$HOST" ]; then
  echo "operator_rpc_auth_probe: --host must not be empty" >&2
  exit 1
fi
# Validate secret as even-length hex early (matches rpc_call's hex_to_bytes
# rejection at src/rpc/rpc.cpp:299). Empty = controls skipped.
if [ -n "$SECRET" ]; then
  case "$SECRET" in *[!0-9a-fA-F]*)
    echo "operator_rpc_auth_probe: --secret must be hex (0-9a-fA-F), got non-hex characters" >&2
    exit 1 ;;
  esac
  if [ $(( ${#SECRET} % 2 )) -ne 0 ]; then
    echo "operator_rpc_auth_probe: --secret must be an even number of hex chars (2N)" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
# Pure socket probe — never invokes the determ binary, so pre-set
# DETERM_BIN to ':' (same pattern as operator_rate_limiter_audit.sh) so
# common.sh's binary-presence check passes on an ops workstation that has
# no built determ.exe but does have network reach to the daemon.
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# All wire I/O, classification, and rendering happen in Python: the socket
# driver, HMAC reproduction (stdlib hmac/hashlib), and the cross-field
# severity logic read far more clearly than the equivalent nc + jq chain,
# and Python ships everywhere the determ build pipeline ships (no new dep).
#
# Python emits the final exit code (0 no-CRITICAL, 1 transport/internal, 2
# CRITICAL). Capture and forward it so an external `|| exit 1` wrapper
# can't collapse the exit-2 alert gate to exit-1.
python - "$HOST" "$RPC_PORT" "$SECRET" "$EXTERNAL_BIND" "$TIMEOUT" "$JSON_OUT" <<'PY'
import json, socket, sys, hmac, hashlib

host          = sys.argv[1]
rpc_port      = int(sys.argv[2])
secret_hex    = sys.argv[3]
external_bind = sys.argv[4] == "1"
timeout       = float(sys.argv[5])
json_out      = sys.argv[6] == "1"


def canonical_for_hmac(method, params):
    # Mirror src/rpc/rpc.cpp::canonical_for_hmac exactly:
    #     method + "|" + params.dump()
    # nlohmann::json's default type is std::map-backed, so dump() emits
    # object keys in sorted order and with no indent (compact). Python's
    # json.dumps(sort_keys=True, separators=(",", ":")) reproduces that
    # byte-for-byte for the simple params dicts the read RPCs use. For
    # `status` params is {} so the pre-image is exactly "status|{}".
    return method + "|" + json.dumps(params, sort_keys=True, separators=(",", ":"))


def hmac_hex(key_bytes, preimage):
    return hmac.new(key_bytes, preimage.encode("utf-8"), hashlib.sha256).hexdigest()


def rpc_probe(method, params, auth=None):
    """Open a fresh socket, send one newline-delimited JSON request, read
    one newline-delimited JSON reply. Returns the parsed reply dict, or
    raises on any transport/protocol error. A fresh socket per call mirrors
    rpc::rpc_call (connect-per-call); the server reads request lines in a
    loop but the operator probe keeps each request isolated."""
    req = {"method": method, "params": params}
    if auth is not None:
        req["auth"] = auth
    line = (json.dumps(req) + "\n").encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, rpc_port))
        s.sendall(line)
        # Read until newline (one reply per request).
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


# ── Primary probe: unauthenticated `status` (read-only) ──────────────────
# This is the discriminating request. No `auth` field is attached.
try:
    reply = rpc_probe("status", {}, auth=None)
except (OSError, socket.timeout) as e:
    sys.stderr.write(
        f"operator_rpc_auth_probe: cannot reach RPC at {host}:{rpc_port} ({e}) "
        f"— is the daemon running and bound to that port?\n")
    sys.exit(1)
except Exception as e:
    sys.stderr.write(
        f"operator_rpc_auth_probe: malformed reply from {host}:{rpc_port}: {e}\n")
    sys.exit(1)

err    = reply.get("error", None)
result = reply.get("result", None)

# ── Classify posture from the unauthenticated reply ──────────────────────
findings = []  # list of {"severity", "message"}

if err == "rate_limited":
    posture = "RATE_LIMITED"
    auth_enforced = None
elif isinstance(err, str) and err.startswith("auth_required"):
    posture = "ENFORCED"
    auth_enforced = True
elif err is None and result is not None:
    posture = "OPEN"
    auth_enforced = False
else:
    # Any other error to an unauthenticated read `status` is unexpected.
    # The server only emits auth_required / rate_limited / null-on-success
    # for this path; anything else (e.g. a server-internal error string)
    # is a transport-class surprise the operator should see verbatim.
    sys.stderr.write(
        f"operator_rpc_auth_probe: unexpected RPC reply to unauthenticated "
        f"status (error={err!r}, result_present={result is not None}) — "
        f"cannot classify auth posture\n")
    sys.exit(1)

# OPEN posture severity depends on bind posture.
if posture == "OPEN":
    if external_bind:
        findings.append({
            "severity": "CRITICAL",
            "message": "RPC auth is DISABLED (unauthenticated status accepted) "
                       "AND --external-bind asserted: an externally-reachable "
                       "RPC with no HMAC auth is the S-001 danger case — set "
                       "rpc_auth_secret or enable rpc_localhost_only immediately",
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": "RPC auth is DISABLED (unauthenticated status accepted) "
                       "on a loopback bind — documented dev / single-host "
                       "consortium posture. Set rpc_auth_secret before exposing "
                       "this RPC beyond loopback",
        })
elif posture == "ENFORCED":
    findings.append({
        "severity": "OK",
        "message": "RPC auth is ENFORCED — unauthenticated status rejected with "
                   "auth_required (S-001 live on the wire)",
    })
elif posture == "RATE_LIMITED":
    findings.append({
        "severity": "INFO",
        "message": "Probe was rate-limited (S-014 token bucket fired before "
                   "auth could be evaluated) — auth posture indeterminate; "
                   "re-run after the bucket refills",
    })

# ── Optional controls (only when --secret supplied AND auth ENFORCED) ────
# Controls are meaningful only when the server actually enforces auth. If
# the server is OPEN, both controls are 'skip' — an OPEN server ignores the
# auth field entirely, so a positive/negative result there says nothing
# about HMAC validation. If RATE_LIMITED, also skip (each control would
# itself be throttled and uninformative).
controls = {"positive": "skip", "negative": "skip"}

if secret_hex and posture == "ENFORCED":
    try:
        key = bytes.fromhex(secret_hex)
    except ValueError:
        sys.stderr.write(
            "operator_rpc_auth_probe: --secret is not valid hex\n")
        sys.exit(1)
    if not key:
        sys.stderr.write(
            "operator_rpc_auth_probe: --secret decoded to zero bytes\n")
        sys.exit(1)

    preimage = canonical_for_hmac("status", {})

    # POSITIVE: correct HMAC must succeed.
    try:
        good_auth = hmac_hex(key, preimage)
        pos_reply = rpc_probe("status", {}, auth=good_auth)
    except Exception as e:
        sys.stderr.write(
            f"operator_rpc_auth_probe: positive control transport error: {e}\n")
        sys.exit(1)
    pos_err = pos_reply.get("error", None)
    if pos_err == "rate_limited":
        # Throttled mid-control: don't assert pass/fail, leave as skip and
        # note it. Not a finding — the bucket is the cause, not auth.
        controls["positive"] = "skip"
        findings.append({
            "severity": "INFO",
            "message": "positive control was rate-limited (S-014) — secret "
                       "validity not confirmed this run; re-run later",
        })
    elif pos_err is None:
        controls["positive"] = "pass"
    else:
        controls["positive"] = "fail"
        findings.append({
            "severity": "CRITICAL",
            "message": f"positive control FAILED: a correctly-HMAC'd status was "
                       f"rejected (error={pos_err!r}) — the supplied --secret "
                       f"does NOT match the running server's rpc_auth_secret "
                       f"(deployment drift: operator does not hold the live key)",
        })

    # NEGATIVE: a tampered key must be rejected with auth_failed. Flip the
    # last byte of the key (mirrors the one-byte-flip case in
    # tools/test_rpc_hmac_auth.sh).
    try:
        bad_key = bytearray(key)
        bad_key[-1] ^= 0x01
        bad_auth = hmac_hex(bytes(bad_key), preimage)
        neg_reply = rpc_probe("status", {}, auth=bad_auth)
    except Exception as e:
        sys.stderr.write(
            f"operator_rpc_auth_probe: negative control transport error: {e}\n")
        sys.exit(1)
    neg_err = neg_reply.get("error", None)
    if neg_err == "rate_limited":
        controls["negative"] = "skip"
        findings.append({
            "severity": "INFO",
            "message": "negative control was rate-limited (S-014) — HMAC "
                       "rejection not confirmed this run; re-run later",
        })
    elif neg_err == "auth_failed":
        controls["negative"] = "pass"
    elif neg_err is None:
        controls["negative"] = "fail"
        findings.append({
            "severity": "CRITICAL",
            "message": "negative control FAILED: a status request authenticated "
                       "with a TAMPERED HMAC was ACCEPTED — the server is not "
                       "validating the HMAC (S-001 constant-time compare bypass)",
        })
    else:
        # auth_required (shouldn't happen — we sent an auth field) or some
        # other error: not the expected auth_failed, but also not an accept.
        # Treat as a non-fatal anomaly rather than a clean pass.
        controls["negative"] = "fail"
        findings.append({
            "severity": "WARN",
            "message": f"negative control returned an unexpected error "
                       f"(error={neg_err!r}) rather than auth_failed — review "
                       f"server auth path",
        })

elif secret_hex and posture == "OPEN":
    findings.append({
        "severity": "INFO",
        "message": "--secret controls skipped: server is OPEN (auth disabled), "
                   "so it ignores the auth field — controls are uninformative "
                   "until rpc_auth_secret is set",
    })

# ── Verdict + exit code ──────────────────────────────────────────────────
n_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
n_warn     = sum(1 for f in findings if f["severity"] == "WARN")

if n_critical > 0:
    verdict = "CRITICAL"
    exit_code = 2
elif posture == "RATE_LIMITED":
    verdict = "UNKNOWN"
    exit_code = 0
elif posture == "OPEN":
    # OPEN-on-loopback (INFO) reaches here; OPEN-on-external already raised
    # a CRITICAL finding above and was caught by n_critical.
    verdict = "INFO"
    exit_code = 0
else:
    # ENFORCED, controls passed (or skipped). A lone WARN (unexpected
    # negative-control error) does not gate the exit code — surfaced only.
    verdict = "OK"
    exit_code = 0

# ── Emit ──────────────────────────────────────────────────────────────────
if json_out:
    out = {
        "host":          host,
        "rpc_port":      rpc_port,
        "external_bind": external_bind,
        "posture":       posture,
        "auth_enforced": auth_enforced,
        "controls":      controls,
        "findings":      findings,
        "verdict":       verdict,
        "exit_code":     exit_code,
    }
    print(json.dumps(out))
    sys.exit(exit_code)

sev_tag = {
    "OK":       "[OK]",
    "INFO":     "[INFO]",
    "WARN":     "[WARN]",
    "CRITICAL": "[CRIT]",
}

print(f"=== RPC auth probe ({host}:{rpc_port}) ===")
print(f"Posture:       {posture}"
      + ("" if auth_enforced is None
         else f"  (auth_enforced={'yes' if auth_enforced else 'no'})"))
print(f"Bind asserted: {'external (non-loopback)' if external_bind else 'loopback'}")
if secret_hex:
    print(f"Controls:      positive={controls['positive']}  "
          f"negative={controls['negative']}")

print()
print("Findings:")
for f in findings:
    tag = sev_tag.get(f["severity"], "[?]")
    print(f"  {tag:<7} {f['message']}")

print()
if verdict == "CRITICAL":
    print(f"[CRIT] {n_critical} critical finding(s) — operator action required")
elif verdict == "UNKNOWN":
    print("[OK] auth posture indeterminate (rate-limited) — re-run later")
elif verdict == "INFO":
    print("[OK] auth disabled on loopback — intentional dev/consortium posture")
else:
    print("[OK] RPC auth enforced; controls passed")

sys.exit(exit_code)
PY
PY_RC=$?
# Forward Python's rc verbatim: 0 no-CRITICAL, 1 transport/internal error,
# 2 CRITICAL alert gate. Preserves the exit-2 gate end-to-end.
exit "$PY_RC"
