#!/usr/bin/env bash
# operator_rate_limiter_audit.sh — audit the S-014 per-peer-IP token-bucket
# rate-limiter configuration on a determ operator's `config.json`.
#
# Unlike operator_config_audit.sh (which lints the *whole* config against a
# fixed checklist), this script focuses exclusively on the four S-014 knobs:
#
#   rpc_rate_per_sec       steady-state RPC budget / peer-IP / second
#   rpc_rate_burst         RPC token-bucket capacity (max burst before throttle)
#   gossip_rate_per_sec    steady-state gossip budget / peer-IP / second
#   gossip_rate_burst      gossip token-bucket capacity
#
# and reports a *posture classification* per side (Disabled / Tight / Default /
# Loose) plus three anomaly checks the operator should never miss.
#
# Posture buckets (per side):
#
#     Disabled      rate_per_sec == 0           — bucket completely off; S-014
#                                                  protection is not enforced
#                                                  in-process. Emits WARN at
#                                                  minimum, CRITICAL if BOTH
#                                                  sides are disabled (full
#                                                  S-014 bypass — see anomaly
#                                                  list below).
#     Tight         RPC < 10/s   OR  gossip < 100/s
#                                                  defensive posture — small
#                                                  consortium, low-traffic ops
#                                                  node. INFO ("explicit tight
#                                                  budget — operator chose
#                                                  defensive setting").
#     Default       10 ≤ RPC ≤ 100  AND  100 ≤ gossip ≤ 1000
#                                                  matches the suggested
#                                                  defaults in node.hpp §S-014
#                                                  (rate=100/burst=200 RPC;
#                                                  rate=500/burst=1000 gossip).
#                                                  No flag (OK).
#     Loose         RPC > 100/s  OR  gossip > 1000/s
#                                                  high-throughput posture —
#                                                  tactical / public-DApp
#                                                  bridge. INFO ("high-RPS
#                                                  posture — confirm upstream
#                                                  DDoS mitigation").
#
# Anomalies (with `--anomalies-only`, ONLY these are emitted; severity gates
# the exit code per the policy below):
#
#   A1   BOTH sides disabled                       CRITICAL
#        S-014 protection is fully off — neither RPC nor gossip enforces
#        per-peer-IP token bucket. Exit code 2 (operator alert gate, same
#        convention as operator_config_audit.sh / operator_genesis_verify_live.sh).
#
#   A2   burst < rate                              WARN
#        A burst smaller than the steady-state rate is a configuration
#        error: the bucket would refill faster than it can ever fill, so
#        the burst ceiling never actually applies. Indicates the operator
#        swapped two knob values.
#
#   A3   profile mismatch                          WARN
#        With --profile <name>, the audit compares observed rates against
#        the expected window for that profile (see ranges below) and warns
#        if the observed rate falls outside the window in either direction.
#        Mismatch is WARN, never CRITICAL — operators may have intentional
#        reasons to diverge from the per-profile baseline.
#
# Profile expected ranges (when --profile <name> is supplied):
#
#     cluster        high RPS expected   (RPC 50-500/s, gossip 200-2000/s)
#                    rationale: low-latency in-house deployment, dense
#                    intra-cluster RPC / consensus traffic; ranges align with
#                    PROFILE_CLUSTER (50ms blocks, K=M=3 strong, FIPS).
#     web            moderate            (RPC 10-100/s, gossip 100-1000/s)
#                    rationale: matches default range; PROFILE_WEB is
#                    200ms blocks SHARD+EXTENDED — typical public-facing
#                    chain RPS profile.
#     regional       low-to-moderate     (RPC 5-50/s,   gossip 50-500/s)
#                    rationale: PROFILE_REGIONAL is 300ms blocks; less
#                    chatty, geographically distributed.
#     global         low-to-moderate     (RPC 5-50/s,   gossip 50-500/s)
#                    rationale: PROFILE_GLOBAL is 600ms blocks; sparse
#                    coordination traffic, regional peers buffer locally.
#     tactical       very high           (RPC 100-2000/s, gossip 500-5000/s)
#                    rationale: PROFILE_TACTICAL is 20ms blocks for swarm
#                    Layer-1 coordination; dense steady-state messaging.
#
# Severity policy:
#   CRITICAL — S-014 protection fully disabled (A1). Exit 2.
#   WARN     — configuration error or profile mismatch. Exit 0.
#   INFO     — operator-intentional posture (Tight / Loose). Exit 0.
#   OK       — Default posture, no anomalies. Exit 0.
#
# Usage:
#   tools/operator_rate_limiter_audit.sh [--config <file>] [--profile <name>]
#                                        [--anomalies-only] [--json]
#
# Exit codes:
#   0   no CRITICAL findings (WARN/INFO/OK entries may be present)
#   1   config file missing/unreadable/malformed; bad args
#   2   at least one CRITICAL finding (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_rate_limiter_audit.sh [--config <file>] [--profile <name>]
                                      [--anomalies-only] [--json]

Audits the S-014 token-bucket rate-limiter configuration (RPC + gossip) in
a determ operator's `config.json`. Reports per-side posture (Disabled /
Tight / Default / Loose), three anomaly checks (both-disabled CRITICAL,
burst<rate WARN, profile-mismatch WARN), and an overall verdict.

Options:
  --config <file>     Path to config.json (default: $HOME/.determ/config.json)
  --profile <name>    Cross-check observed rates against the expected window
                      for a named profile: cluster | web | regional | global |
                      tactical. Mismatch emits WARN (A3). Without this flag
                      the posture classification still applies.
  --anomalies-only    Suppress posture rows; emit ONLY anomalies (A1/A2/A3).
                      A clean audit prints nothing on stdout and exits 0.
  --json              Single-line JSON envelope instead of human table.
  -h, --help          Show this help.

Exit codes:
  0   no CRITICAL findings (WARN/INFO/OK entries may still be present)
  1   config file missing / unreadable / malformed; bad args
  2   at least one CRITICAL finding — A1 BOTH sides disabled

JSON shape (--json):
  {"config_path": "...",
   "profile":     "web" | null,
   "rpc":     {"rate":N, "burst":N, "posture":"...", "severity":"OK|INFO|WARN"},
   "gossip":  {"rate":N, "burst":N, "posture":"...", "severity":"OK|INFO|WARN"},
   "anomalies": [{"id":"A1|A2|A3", "severity":"WARN|CRITICAL", "message":"..."}],
   "summary": {"critical":N, "warn":N, "info":N, "ok":N},
   "exit_code": 0|2}
EOF
}

CONFIG="${HOME:-}/.determ/config.json"
PROFILE=""
ANOMALIES_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --config)         CONFIG="$2"; shift 2 ;;
    --profile)        PROFILE="$2"; shift 2 ;;
    --anomalies-only) ANOMALIES_ONLY=1; shift ;;
    --json)           JSON_OUT=1; shift ;;
    *) echo "operator_rate_limiter_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$CONFIG" ]; then
  echo "operator_rate_limiter_audit: --config <file> is required (HOME unset?)" >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "operator_rate_limiter_audit: config file not found: $CONFIG" >&2
  exit 1
fi
if [ ! -r "$CONFIG" ]; then
  echo "operator_rate_limiter_audit: config file not readable: $CONFIG" >&2
  exit 1
fi

# Validate --profile early so the operator gets a fast error before parsing.
# Empty string means no cross-check (A3 disabled); anything else must match
# the known set. The set is hard-coded here (not pulled from params.hpp) so
# the script works against a config snapshot without needing a built binary;
# any new profile would need a one-line addition here, same as operator_config_audit.sh.
case "$PROFILE" in
  ""|cluster|web|regional|global|tactical) ;;
  *) echo "operator_rate_limiter_audit: unknown profile '$PROFILE' (expected: cluster | web | regional | global | tactical)" >&2
     exit 1 ;;
esac

cd "$(dirname "$0")/.."
# Pure local-file linter — never invokes the determ binary, same pattern as
# operator_config_audit.sh. Pre-set DETERM_BIN to `:` so common.sh's
# binary-presence check passes on hosts without a built determ.exe (e.g.
# an ops workstation auditing a remote operator's config snapshot).
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# Drive parse + classification in Python; the cross-field conditionals
# (posture buckets, A1 both-disabled, A3 profile-window comparisons)
# read more clearly than the equivalent jq filter chain. Python ships
# everywhere the determ build pipeline ships, so this is no new dep.
#
# Python emits the script's final exit code (0 on no-CRITICAL, 2 on any
# CRITICAL). Capture the rc and fan it out explicitly so an external
# `|| exit 1` wrapper can't collapse exit 2 → exit 1 and silently swallow
# the operator-alert gate.
python - "$CONFIG" "$PROFILE" "$ANOMALIES_ONLY" "$JSON_OUT" <<'PY'
import json, sys

config_path     = sys.argv[1]
profile         = sys.argv[2] or None
anomalies_only  = sys.argv[3] == "1"
json_out        = sys.argv[4] == "1"

try:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_rate_limiter_audit: cannot parse {config_path}: {e}\n")
    sys.exit(1)

if not isinstance(cfg, dict):
    sys.stderr.write(f"operator_rate_limiter_audit: config root is not a JSON object: {config_path}\n")
    sys.exit(1)

# Field accessors with daemon defaults matching Config in include/determ/node/node.hpp.
# All four S-014 knobs default to 0.0, which means "rate-limiter disabled" —
# the audit reflects that runtime reality (Config::from_json never errors on
# an absent field; it leaves the disabled-by-default value in place).
def g_num(name, default=0.0):
    v = cfg.get(name, default)
    if v is None:
        return float(default)
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)

rpc_rate     = g_num("rpc_rate_per_sec")
rpc_burst    = g_num("rpc_rate_burst")
gossip_rate  = g_num("gossip_rate_per_sec")
gossip_burst = g_num("gossip_rate_burst")

# ── Per-side posture classification ──────────────────────────────────────
# Returns (posture_string, severity, message) for each side. Severity here
# is the *posture* severity — anomaly severities (A1/A2/A3) are layered on
# top in a second pass below, and the final exit code consults the
# anomalies, not the posture rows.
def classify_rpc(rate, burst):
    if rate == 0.0:
        return ("Disabled", "WARN",
                "RPC token-bucket disabled (rate=0/sec) — no in-process per-IP rate limit")
    if rate < 10.0:
        return ("Tight", "INFO",
                f"RPC {rate}/sec, burst {burst} — tight defensive posture (<10/s)")
    if rate <= 100.0:
        return ("Default", "OK",
                f"RPC {rate}/sec, burst {burst} — within suggested default range (10-100/s)")
    return ("Loose", "INFO",
            f"RPC {rate}/sec, burst {burst} — high-throughput posture (>100/s)")

def classify_gossip(rate, burst):
    if rate == 0.0:
        return ("Disabled", "WARN",
                "Gossip token-bucket disabled (rate=0/sec) — no in-process per-IP gossip limit")
    if rate < 100.0:
        return ("Tight", "INFO",
                f"Gossip {rate}/sec, burst {burst} — tight defensive posture (<100/s)")
    if rate <= 1000.0:
        return ("Default", "OK",
                f"Gossip {rate}/sec, burst {burst} — within suggested default range (100-1000/s)")
    return ("Loose", "INFO",
            f"Gossip {rate}/sec, burst {burst} — high-throughput posture (>1000/s)")

rpc_posture,    rpc_sev,    rpc_msg    = classify_rpc(rpc_rate,    rpc_burst)
gossip_posture, gossip_sev, gossip_msg = classify_gossip(gossip_rate, gossip_burst)

# ── Anomalies (A1 / A2 / A3) ─────────────────────────────────────────────
# A1 BOTH sides disabled is the only CRITICAL — that's a full S-014 bypass.
# A single side disabled is WARN-level via the posture row, not CRITICAL,
# because some operators legitimately disable one side (e.g. gossip-only
# behind a private VPN with RPC public).
anomalies = []

# A1: both sides disabled → full S-014 bypass
if rpc_rate == 0.0 and gossip_rate == 0.0:
    anomalies.append({
        "id": "A1",
        "severity": "CRITICAL",
        "message": "BOTH rpc_rate_per_sec and gossip_rate_per_sec are 0 — "
                   "S-014 per-IP token-bucket protection is fully disabled "
                   "(operator MUST rely on upstream LB / firewall for DoS mitigation)",
    })

# A2: burst < rate on either side is a config error (bucket can never fill
# above its refill rate). Only flag when rate > 0 — a disabled side has
# burst=0 by default and that's a posture issue (A1 / Disabled), not A2.
if rpc_rate > 0.0 and rpc_burst < rpc_rate:
    anomalies.append({
        "id": "A2",
        "severity": "WARN",
        "message": f"rpc_rate_burst ({rpc_burst}) < rpc_rate_per_sec ({rpc_rate}) "
                   f"— burst smaller than refill rate is a configuration error "
                   f"(operator likely swapped the two values)",
    })
if gossip_rate > 0.0 and gossip_burst < gossip_rate:
    anomalies.append({
        "id": "A2",
        "severity": "WARN",
        "message": f"gossip_rate_burst ({gossip_burst}) < gossip_rate_per_sec "
                   f"({gossip_rate}) — burst smaller than refill rate is a "
                   f"configuration error (operator likely swapped the two values)",
    })

# A3: profile mismatch — cross-check observed rates against expected window
# for the named profile. Only runs when --profile is supplied.
# Ranges per the docblock header above (see TimingProfile constants in
# include/determ/chain/params.hpp for the underlying block-timing rationale).
PROFILE_RANGES = {
    "cluster":  {"rpc": (50.0,  500.0),  "gossip": (200.0, 2000.0)},
    "web":      {"rpc": (10.0,  100.0),  "gossip": (100.0, 1000.0)},
    "regional": {"rpc": ( 5.0,   50.0),  "gossip": ( 50.0,  500.0)},
    "global":   {"rpc": ( 5.0,   50.0),  "gossip": ( 50.0,  500.0)},
    "tactical": {"rpc": (100.0, 2000.0), "gossip": (500.0, 5000.0)},
}
if profile and profile in PROFILE_RANGES:
    rng = PROFILE_RANGES[profile]
    lo, hi = rng["rpc"]
    # Only check sides that are enabled — A3 is for misconfigured-rate,
    # not disabled-rate (the latter is A1 / Disabled posture).
    if rpc_rate > 0.0 and not (lo <= rpc_rate <= hi):
        direction = "below" if rpc_rate < lo else "above"
        anomalies.append({
            "id": "A3",
            "severity": "WARN",
            "message": f"profile '{profile}': rpc_rate_per_sec {rpc_rate} is "
                       f"{direction} expected range [{lo}, {hi}]/sec",
        })
    lo, hi = rng["gossip"]
    if gossip_rate > 0.0 and not (lo <= gossip_rate <= hi):
        direction = "below" if gossip_rate < lo else "above"
        anomalies.append({
            "id": "A3",
            "severity": "WARN",
            "message": f"profile '{profile}': gossip_rate_per_sec {gossip_rate} "
                       f"is {direction} expected range [{lo}, {hi}]/sec",
        })

# ── Summary + exit code ──────────────────────────────────────────────────
# Exit code consults BOTH posture severities AND anomalies. The only path
# to exit 2 is a CRITICAL — currently only A1.
summary = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
for sev in (rpc_sev, gossip_sev):
    summary[sev.lower()] += 1
for a in anomalies:
    summary[a["severity"].lower()] += 1

exit_code = 2 if summary["critical"] > 0 else 0

# ── Emit ────────────────────────────────────────────────────────────────
if json_out:
    out = {
        "config_path": config_path,
        "profile":     profile,
        "rpc": {
            "rate":     rpc_rate,
            "burst":    rpc_burst,
            "posture":  rpc_posture,
            "severity": rpc_sev,
            "message":  rpc_msg,
        },
        "gossip": {
            "rate":     gossip_rate,
            "burst":    gossip_burst,
            "posture":  gossip_posture,
            "severity": gossip_sev,
            "message":  gossip_msg,
        },
        "anomalies": anomalies,
        "summary":   summary,
        "exit_code": exit_code,
    }
    print(json.dumps(out))
    sys.exit(exit_code)

# Human-readable output.
sev_tag = {
    "OK":       "[OK]",
    "INFO":     "[INFO]",
    "WARN":     "[WARN]",
    "CRITICAL": "[CRIT]",
}

if anomalies_only:
    # Anomalies-only mode: silent on clean audits, only print A1/A2/A3 rows
    # plus the final verdict line. Useful for cron / CI consumers.
    if anomalies:
        print(f"=== Rate limiter anomalies ({config_path}) ===")
        for a in anomalies:
            tag = sev_tag.get(a["severity"], "[?]")
            print(f"  {a['id']:<3}  {tag:<7} {a['message']}")
        print()
        if summary["critical"] > 0:
            print(f"[CRIT] {summary['critical']} critical anomaly — operator action required")
        else:
            print(f"[WARN] {summary['warn']} non-critical anomaly — review above")
    sys.exit(exit_code)

# Full human report.
print(f"=== Rate limiter audit ({config_path}) ===")
print(f"RPC rate:    {rpc_rate}/sec, burst {rpc_burst}    "
      f"{sev_tag[rpc_sev]:<7} {rpc_posture}")
print(f"Gossip rate: {gossip_rate}/sec, burst {gossip_burst}  "
      f"{sev_tag[gossip_sev]:<7} {gossip_posture}")

if profile:
    rng = PROFILE_RANGES.get(profile)
    if rng:
        rlo, rhi = rng["rpc"]
        glo, ghi = rng["gossip"]
        print(f"Profile: {profile} -> expected: RPC {rlo}-{rhi}/s, "
              f"gossip {glo}-{ghi}/s")

if anomalies:
    print()
    print("Anomalies:")
    for a in anomalies:
        tag = sev_tag.get(a["severity"], "[?]")
        print(f"  {a['id']:<3}  {tag:<7} {a['message']}")

print()
print(f"Audit summary: {summary['critical']} CRITICAL, "
      f"{summary['warn']} WARN, {summary['info']} INFO, {summary['ok']} OK")
# Verdict-line picker:
#   - any CRITICAL → operator-alert wording
#   - any WARN     → "non-critical findings" (covers A2/A3 and Disabled posture)
#   - any INFO     → "intentional posture" (Tight / Loose chosen deliberately)
#   - else (all OK) → "within expected range" (Default/Default)
if summary["critical"] > 0:
    print(f"[CRIT] {summary['critical']} critical finding(s) — operator action required")
elif summary["warn"] > 0:
    print(f"[WARN] {summary['warn']} non-critical finding(s) — review above")
elif summary["info"] > 0:
    print(f"[OK] Configuration acceptable — operator-intentional posture (Tight / Loose)")
else:
    print("[OK] Configuration within expected range")

sys.exit(exit_code)
PY
PY_RC=$?
# Map Python rc → bash exit. Python exits 1 on its own internal errors
# (parse failures emitted to stderr above), 0 on no-CRITICAL, 2 on any
# CRITICAL. Forward whatever rc Python produced so the operator-alert
# gate at exit 2 is preserved end-to-end.
exit "$PY_RC"
