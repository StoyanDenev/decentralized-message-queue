#!/usr/bin/env bash
# operator_validator_committee_share.sh — Per-validator COMMITTEE SHARE
# tracker over a window of finalized blocks. Frames the K-member
# committee selection (S-020 hybrid Fisher-Yates) as a per-validator
# slot-share question:
#
#     observed_share_i = slot_count_i / (block_count * K)
#     expected_share_i = stake_i / total_stake
#     deviation_i      = (observed_share_i - expected_share_i) / expected_share_i
#                                                            (relative dev)
#
# Per FA1 selection uniformity, each validator's frequency of selection
# should converge toward its stake-proportional share. This script
# surfaces validators that systematically over- or under-perform that
# expectation across a window.
#
# Sibling positioning — three committee-selection-axis operator tools:
#
#   operator_committee_audit.sh
#       Stake-proportional bias audit — answers "is the selection
#       biased away from stake-weighted expectation?" Carries position
#       distribution per slot index and a single conflated direction-
#       agnostic `committee_bias_high` anomaly.
#
#   operator_validator_committee_share.sh         (THIS)
#       Per-validator share-vs-expectation, with HIGH / LOW direction
#       split. An over-selected validator (`validator_biased_high`)
#       and an under-selected validator (`validator_biased_low`) are
#       BOTH suggestive of attack — but require different operator
#       responses (the former is a concentration alarm; the latter is
#       a censorship-via-omission signal). This script emits them as
#       separate anomalies so dashboards can route them independently.
#
#   operator_committee_membership_history.sh
#       Per-validator timeline + pair-wise co-occurrence (Sybil
#       clique detection). Treats absence streaks as the primary
#       signal rather than share arithmetic.
#
# Model:
#   Let W = window block count, K = modal len(creators) over the
#   window, N = registered pool from `determ validators --json` at
#   audit time. Per-validator with stake s_i:
#       slot_count_i      = blocks where validator appeared in creators[]
#       observed_share_i  = slot_count_i / (W * K)
#       expected_share_i  = s_i / total_stake
#       deviation_pct_i   = (observed_share_i - expected_share_i)
#                           / expected_share_i
#   When expected_share_i = 0 (zero-stake validator — possible under
#   DOMAIN_INCLUSION pre-genesis registrants) deviation is reported
#   as +inf if observed > 0, else 0. Deviation is finite-bounded by a
#   1e-12 small-expected guard.
#
#   Direction split: positive deviation = over-selected (more than
#   stake-share predicts); negative = under-selected. The two are
#   semantically different attack surfaces:
#     - over-selected: concentration / selection-rig in attacker's
#       favor
#     - under-selected: censorship / selection-rig against the
#       validator (omission attack)
#
# Pool composition caveat: validators are read from `determ
# validators` at audit time, NOT per-block. If the registry changed
# mid-window (REGISTER / DEREGISTER / unlock), the snapshot reflects
# the CURRENT registry. For windows shorter than the
# registry-stability horizon this is faithful; for longer windows the
# audit may flag late-registered validators as anomalously low
# (legitimate undersampling, not selection bias). Stake values are
# also taken from the current snapshot — staking churn mid-window
# introduces minor reporting error. The JSON envelope names the
# window length + pool composition so an operator can sanity-check
# this.
#
# Args:
#   --rpc-port N          RPC port (default 8545)
#   --from H              Lower window bound, inclusive
#                         (default: head - 999)
#   --to H                Upper window bound, inclusive
#                         (default: head)
#   --bias-threshold F    Flag |deviation| > threshold (default 0.30 —
#                         i.e. observed differs from expected by more
#                         than 30% in either direction)
#   --json                Emit structured JSON envelope
#   --anomalies-only      Suppress healthy rows; exit 2 if any anomaly
#                         fires
#   -h, --help            Show this help
#
# Anomaly flags:
#   validator_biased_high   any validator with |deviation| >
#                           --bias-threshold AND deviation > 0
#                           (over-selected — concentration / favoritism
#                           signal)
#   validator_biased_low    any validator with |deviation| >
#                           --bias-threshold AND deviation < 0
#                           (under-selected — censorship-by-omission
#                           signal)
#   validator_excluded      a registered validator with stake > 0 but
#                           slot_count = 0 in window. A strict subset
#                           of `validator_biased_low` in the
#                           expected_share > 0 case, but emitted
#                           SEPARATELY so an operator can distinguish
#                           "completely missing" (could be offline) from
#                           "selected but at a rate that's too low"
#                           (definitely a selection bias). Also fires
#                           independently for zero-rate validators
#                           below the threshold (e.g. a 0.5%
#                           expected-share validator picking up zero
#                           slots in a 1000-block window).
#
# Exit codes:
#   0   audit ran; no anomalies (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_committee_share.sh [--rpc-port N]
                                             [--from H] [--to H]
                                             [--bias-threshold F]
                                             [--json] [--anomalies-only]

Track per-validator COMMITTEE SHARE over a window of finalized
blocks. For each validator currently registered, compute
observed_share = slot_count / (W * K) vs expected_share =
stake / total_stake, then flag direction-split deviations.

Computes:
  per-validator: slot_count, observed_share, expected_share,
                 deviation_pct, status (MATCH / BIASED)
  summary:       total_validators, biased, excluded

Options:
  --rpc-port N         RPC port (default 8545)
  --from H             Lower window bound, inclusive (default: head-999)
  --to H               Upper window bound, inclusive (default: head)
  --bias-threshold F   |deviation| > F flags as biased (default: 0.30)
  --json               Emit structured JSON envelope
  --anomalies-only     Print only when ≥1 anomaly fires; exit 2 then
  -h, --help           Show this help

Anomalies:
  validator_biased_high   |deviation| > threshold AND over-selected
  validator_biased_low    |deviation| > threshold AND under-selected
  validator_excluded      stake > 0 AND slot_count == 0 in window

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W},
   "K_modal": K,
   "rpc_port": P,
   "bias_threshold": F,
   "validators": [
     {"domain": "...", "stake": N, "slot_count": C,
      "observed_share": R, "expected_share": E, "deviation_pct": D,
      "status": "MATCH" | "BIASED"}, ...],
   "anomalies": [...],
   "summary": {"total_validators": N, "biased": B, "excluded": X}}

Exit codes:
  0   success, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT="8545"
FROM=""
TO=""
BIAS_THRESHOLD="0.30"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";            shift 2 ;;
    --from)            FROM="${2:-}";            shift 2 ;;
    --to)              TO="${2:-}";              shift 2 ;;
    --bias-threshold)  BIAS_THRESHOLD="${2:-}";  shift 2 ;;
    --json)            JSON_OUT=1;               shift ;;
    --anomalies-only)  ANOM_ONLY=1;              shift ;;
    *) echo "operator_validator_committee_share: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_committee_share: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

for v in "$FROM" "$TO"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_validator_committee_share: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# Bias threshold: must be a non-negative float. Use python to parse +
# validate so any reasonable formatting (0.3, .3, 1.0, 1e-2, etc.) is
# accepted; bash regex over float literals is fragile. Passed as argv
# (not interpolated into source) so the diagnostic message can echo the
# operator-supplied value back verbatim.
python - "$BIAS_THRESHOLD" <<'PY' || exit 1
import sys
raw = sys.argv[1]
try:
    v = float(raw)
    if v < 0:
        raise ValueError('negative')
except Exception as e:
    sys.stderr.write(
        f"operator_validator_committee_share: --bias-threshold must be a non-negative float "
        f"(got '{raw}': {e})\n"
    )
    sys.exit(1)
PY

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_committee_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head ────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_committee_share: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_validator_committee_share: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. Default: last 1000 blocks ending at tip.
if [ -z "$TO" ]; then TO=$TOP; fi
if [ -z "$FROM" ]; then
  if [ "$TOP" -gt 999 ]; then
    FROM=$(( TOP - 999 ))
  else
    FROM=0
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_validator_committee_share: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: pool snapshot from validators RPC ─────────────────────────────────
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_committee_share: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: per-block walk + per-validator tally (driven from Python) ─────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_validator_committee_share: cannot create temp file" >&2; exit 1;
}
TMP_VAL=$(mktemp 2>/dev/null) || {
  echo "operator_validator_committee_share: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_VAL" 2>/dev/null' EXIT

printf '%s' "$VAL_JSON" >"$TMP_VAL"

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" \
        "$BIAS_THRESHOLD" "$TMP_VAL" <<'PY'
import json, subprocess, sys, math

(determ, port, from_h, to_h, out_path,
 bias_s, val_path) = sys.argv[1:8]
from_h, to_h = int(from_h), int(to_h)
bias_threshold = float(bias_s)

# ── Load registered-validator pool ────────────────────────────────────────────
try:
    with open(val_path, "r", encoding="utf-8") as f:
        validators = json.load(f)
except Exception:
    sys.stderr.write("operator_validator_committee_share: malformed validators JSON\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_validator_committee_share: validators RPC returned non-array\n")
    sys.exit(1)

# Pool: domain → stake (zero-stake entries retained — DOMAIN_INCLUSION
# pre-genesis registrants are legitimate; deviation math treats them
# with a finite/infinite branch below).
pool = {}
for v in validators:
    if not isinstance(v, dict): continue
    dom = v.get("domain")
    if not isinstance(dom, str) or not dom: continue
    try:
        st = int(v.get("stake", 0) or 0)
    except Exception:
        st = 0
    pool[dom] = st

if not pool:
    sys.stderr.write(f"operator_validator_committee_share: empty validator pool (port {port})\n")
    sys.exit(1)

total_stake = sum(pool.values())
N           = len(pool)

# Per-validator counters initialized to zero for every pool member so
# the never-selected ones surface in the report (zero is evidence here).
slot_count    = {d: 0 for d in pool}
size_dist     = {}  # K -> count of blocks at this committee size

# ── Per-block walk ───────────────────────────────────────────────────────────
# One block-info subprocess per height; same cost as the sibling
# committee scripts. Walk inclusive [from_h, to_h].
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_committee_share: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_committee_share: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_committee_share: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list): creators = []
    creators = [c for c in creators if isinstance(c, str)]

    k = len(creators)
    size_dist[k] = size_dist.get(k, 0) + 1

    for dom in creators:
        # Only count pool-member creators — a creator outside the
        # current snapshot (recently-deregistered validator captured
        # by the window but no longer registered at audit time) would
        # skew deviation arithmetic. Same convention as the sibling
        # operator_committee_audit.sh.
        if dom in pool:
            slot_count[dom] += 1

W = to_h - from_h + 1

# Modal K over the window. Ties broken by the larger K (same convention
# as operator_block_creator_fairness.sh / operator_committee_audit.sh
# — BFT-degraded blocks should not distort the "normal" K used as the
# baseline). When the window contains no blocks with creators (e.g.
# pure-genesis window), K = 0 and downstream slot-share math falls to
# the zero-total-slots branch.
if size_dist:
    K_modal = max(size_dist.items(), key=lambda kv: (kv[1], kv[0]))[0]
else:
    K_modal = 0

total_slots = W * K_modal

# ── Build per-validator rows ─────────────────────────────────────────────────
# expected_share = stake / total_stake     (zero if total_stake == 0)
# observed_share = slot_count / total_slots (zero if total_slots == 0)
# deviation handling:
#   - expected_share == 0 and observed_share == 0  => deviation = 0.0
#   - expected_share == 0 and observed_share  > 0  => deviation = +inf
#       (encoded as the literal string "+inf" in JSON output — vanilla
#        JSON has no IEEE infinity)
#   - expected_share > 0                            => relative dev
SMALL_EXPECTED = 1e-12

rows         = []
n_biased     = 0
n_excluded   = 0

for dom, st in pool.items():
    cnt = slot_count[dom]
    exp = (st / total_stake) if total_stake > 0 else 0.0
    obs = (cnt / total_slots) if total_slots > 0 else 0.0
    if exp > SMALL_EXPECTED:
        dev = (obs - exp) / exp
        dev_finite = True
    else:
        # Zero (or near-zero) expected stake. Observed-positive
        # indicates the selection algorithm reached into a zero-weighted
        # slot — a real anomaly under correct stake-weighted FY. Encode
        # as positive infinity; render as "+inf" in JSON.
        if obs > 0:
            dev = float('inf')
            dev_finite = False
        else:
            dev = 0.0
            dev_finite = True

    if dev_finite:
        mag = abs(dev)
    else:
        mag = float('inf')

    # Status: BIASED if magnitude > threshold AND row carries any
    # signal (either expected or observed positive — a strictly-zero
    # validator is just inactive, not biased).
    is_biased = (mag > bias_threshold) and (exp > 0 or obs > 0)
    # Excluded: stake > 0 (REGISTERED with non-zero weight) but
    # zero slots over the window. Reported independently of bias
    # status because "completely missing" carries different operator
    # semantics than "selected but under-rate".
    is_excluded = (st > 0) and (cnt == 0)

    if is_biased: n_biased += 1
    if is_excluded: n_excluded += 1

    status = "BIASED" if is_biased else "MATCH"

    rows.append({
        "domain":            dom,
        "stake":             st,
        "slot_count":        cnt,
        "observed_share":    obs,
        "expected_share":    exp,
        "deviation_pct":     dev if dev_finite else "+inf",
        # Internal helpers used for sorting + anomaly classification;
        # not emitted in the public JSON shape.
        "_dev_finite":       dev_finite,
        "_dev_magnitude":    mag if dev_finite else float('inf'),
        "_dev_direction":    (1 if (dev_finite and dev > 0) or not dev_finite else (-1 if dev_finite and dev < 0 else 0)),
        "_excluded":         is_excluded,
        "status":            status,
    })

# Sort: worst-deviation first (magnitude desc, infs at top), ties by
# domain asc. Strict infs sort above finite values via the magnitude
# key flag.
rows.sort(key=lambda r: (
    not r["_dev_finite"],                                       # infs first
    -(r["_dev_magnitude"] if r["_dev_finite"] else 0.0),        # desc within finites
    r["domain"],
))

# ── Anomaly classification ──────────────────────────────────────────────────
# Direction split: positive vs negative deviation (over- vs under-
# selected) emit as separate anomalies. The two carry different
# operator-response semantics:
#   high  — concentration / favoritism toward an attacker
#   low   — censorship-by-omission against the validator
# +inf deviations (zero-expected, positive-observed) are bucketed as
# `validator_biased_high` because they are over-selected relative to
# their (zero) expectation.
anomalies = []

# validator_biased_high: any row with magnitude > threshold AND
# direction > 0 (over-selected). Includes the +inf case.
if any(
    r["_dev_magnitude"] > bias_threshold
    and r["_dev_direction"] > 0
    and (r["expected_share"] > 0 or r["observed_share"] > 0)
    for r in rows
):
    anomalies.append("validator_biased_high")

# validator_biased_low: any row with magnitude > threshold AND
# direction < 0 (under-selected). Finite-only by construction (you
# can't have negative-direction +inf).
if any(
    r["_dev_finite"]
    and r["_dev_magnitude"] > bias_threshold
    and r["_dev_direction"] < 0
    and (r["expected_share"] > 0 or r["observed_share"] > 0)
    for r in rows
):
    anomalies.append("validator_biased_low")

# validator_excluded: any registered validator with stake > 0 but
# slot_count = 0. Strict subset of biased_low in the expected_share > 0
# case, but emitted SEPARATELY because the operator-response
# semantics differ:
#   biased_low  — under-rate; investigate selection or stake
#   excluded    — never picked at all; could be offline OR a
#                 stake-rounding edge OR a hard selection bias
if any(r["_excluded"] for r in rows):
    anomalies.append("validator_excluded")

# ── Strip internal-only helper keys before emission ──────────────────────────
public_rows = []
for r in rows:
    public_rows.append({
        "domain":         r["domain"],
        "stake":          r["stake"],
        "slot_count":     r["slot_count"],
        "observed_share": r["observed_share"],
        "expected_share": r["expected_share"],
        "deviation_pct":  r["deviation_pct"],
        "status":         r["status"],
    })

summary = {
    "total_validators": N,
    "biased":           n_biased,
    "excluded":         n_excluded,
}

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
    },
    "K_modal":         K_modal,
    "bias_threshold":  bias_threshold,
    "total_stake":     total_stake,
    "validators":      public_rows,
    "summary":         summary,
    "anomalies":       anomalies,
}

# Encode envelope; deviation_pct may carry the literal string "+inf"
# for zero-expected/positive-observed rows. json.dumps with
# allow_nan=False is fine because we've already converted IEEE inf to
# the string sentinel.
def safe(o):
    if isinstance(o, float) and (math.isinf(o) or math.isnan(o)):
        return "+inf" if o == float('inf') else ("-inf" if o == float('-inf') else None)
    raise TypeError

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f, default=safe, allow_nan=False)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 4: render envelope ──────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" \
        "$WINDOW" "$BIAS_THRESHOLD" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
window    = int(sys.argv[7])
bias_t    = float(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)

if json_out:
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress normal output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_validator_committee_share: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

K_modal     = env["K_modal"]
total_stake = env["total_stake"]
rows        = env["validators"]
summary     = env["summary"]

print(f"=== Validator committee share (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks) ===")
print(f"Pool size: {summary['total_validators']}    "
      f"Committee size K (modal): {K_modal}    "
      f"Total stake: {total_stake}")
print(f"Bias threshold: {bias_t}    "
      f"Biased: {summary['biased']}    "
      f"Excluded: {summary['excluded']}")
print()

def fmt_share(v):
    try:
        return f"{v*100:.2f}%"
    except Exception:
        return "n/a"

def fmt_dev(v):
    if isinstance(v, str):
        return v   # "+inf" / "-inf"
    try:
        return f"{v*100:+.1f}%"
    except Exception:
        return "n/a"

if anom_only:
    # Suppress healthy rows: print only validators with BIASED status
    # OR slot_count == 0 (the validator_excluded population).
    rows = [r for r in rows if r["status"] == "BIASED" or
            (r["stake"] > 0 and r["slot_count"] == 0)]

if not rows:
    print("[INFO] No validator rows to display")
else:
    print("Per-validator share (ranked by |deviation|, worst first):")
    print(f"  {'domain':<28} {'stake':>10} {'slots':>7} "
          f"{'observed':>10} {'expected':>10} {'deviation':>11} status")
    print(f"  {'-'*28} {'-'*10} {'-'*7} {'-'*10} {'-'*10} {'-'*11} {'-'*6}")
    for r in rows:
        dom    = r["domain"][:28]
        stake  = r["stake"]
        cnt    = r["slot_count"]
        obs    = fmt_share(r["observed_share"])
        exp    = fmt_share(r["expected_share"])
        dev    = fmt_dev(r["deviation_pct"])
        stat   = r["status"]
        print(f"  {dom:<28} {stake:>10} {cnt:>7} {obs:>10} {exp:>10} "
              f"{dev:>11} {stat:>6}")

print()
if n_anom == 0:
    print("[OK] No selection-share anomalies")
else:
    full_rows = env["validators"]
    def _fmt_offender(r):
        # Avoid a nested f-string (forbidden in Python ≤3.11 with same
        # quote style) by branching first.
        dv = r["deviation_pct"]
        if isinstance(dv, str):
            return f"{r['domain']} (dev={dv})"
        return f"{r['domain']} (dev={dv*100:+.1f}%)"
    for a in anomalies:
        if a == "validator_biased_high":
            offenders = [
                _fmt_offender(r)
                for r in full_rows
                if r["status"] == "BIASED"
                and (
                    isinstance(r["deviation_pct"], str)  # +inf bucket
                    or (isinstance(r["deviation_pct"], (int, float)) and r["deviation_pct"] > 0)
                )
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] validator_biased_high — over-selected validators "
                  f"(|dev| > {bias_t}): {disp}")
        elif a == "validator_biased_low":
            offenders = [
                _fmt_offender(r)
                for r in full_rows
                if r["status"] == "BIASED"
                and isinstance(r["deviation_pct"], (int, float))
                and r["deviation_pct"] < 0
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] validator_biased_low — under-selected validators "
                  f"(|dev| > {bias_t}): {disp}")
        elif a == "validator_excluded":
            offenders = [
                r["domain"]
                for r in full_rows
                if r["stake"] > 0 and r["slot_count"] == 0
            ]
            disp = ", ".join(offenders[:5])
            if len(offenders) > 5:
                disp += f", +{len(offenders)-5} more"
            print(f"[WARN] validator_excluded — registered validator(s) "
                  f"with stake > 0 and 0 slots in window: {disp}")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_validator_committee_share: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
# Same convention as sibling scripts: exit 2 only when --anomalies-only
# AND ≥1 anomaly fired. Default informational mode always exits 0 if
# the RPC walk succeeded.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
