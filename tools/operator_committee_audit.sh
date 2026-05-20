#!/usr/bin/env bash
# operator_committee_audit.sh — Per-validator committee-selection fairness
# audit over a window of finalized blocks. Determ's K-of-K consensus
# selects a fresh committee per block via stake-weighted Fisher-Yates
# from the registered pool (S-020 hybrid: rejection sampling at 2K ≤ N,
# partial FY shuffle at 2K > N — bounded O(N) regardless of ratio).
#
# Sibling tools and how this one differs:
#   operator_block_creator_fairness.sh
#       Uniform-null chi-squared goodness-of-fit. Asks: "would a uniform
#       lottery have produced this distribution?" Treats every pool member
#       as equiprobable (E = W·K/N). Right tool when the expected
#       distribution is FLAT.
#   operator_committee_audit.sh (THIS)
#       Stake-proportional deviation audit. Asks: "did each validator's
#       observed slot share match its stake share of the pool?" Treats
#       expected_share = stake_i / total_stake. Right tool when the
#       expected distribution is STAKE-WEIGHTED (Determ's actual rule).
#   operator_committee_rotation.sh
#       Composition / rotation rate across the window. Treats the
#       committee as a multiset evolving over time.
#   operator_block_creator_fairness.sh AND this script both walk the
#   same block window via `determ block-info <h> --json` and harvest
#   `creators[]`; the audits diverge only in the expected-distribution
#   model and anomaly rules.
#
# Model:
#   Let W = window block count, K = modal len(creators) over the window,
#   N = active validator pool from `determ validators --json` at audit
#   time. Per-validator i with stake s_i:
#       observed_share_i  = blocks_selected_i / (W * K)
#       expected_share_i  = s_i / total_stake
#       deviation_i       = (observed_share_i - expected_share_i) / expected_share_i
#                                                            (relative dev)
#   When expected_share_i = 0 (zero-stake validator — possible under
#   DOMAIN_INCLUSION pre-genesis registrants) the deviation is reported
#   as +inf if observed > 0, else 0; deviation is also undefined when
#   expected_share_i is so small that floating-point precision degrades,
#   handled by the small-expected guard below.
#
# Per-position-in-selection: tally each validator's appearance at each
# slot index 0..K-1 across the window. A validator that consistently
# appears at slot 0 (proposer position) while never at trailing slots
# suggests either a bias in `select_m_creators` index ordering or a
# real protocol artifact (the proposer slot is rotated deterministically
# from the committee draw — see PROTOCOL.md §5.3 proposer_idx). Emitted
# as `position_distribution` per validator for forensic drill-down.
#
# Pool composition caveat: validators are inferred from `determ
# validators` at audit time, NOT per-block. If the registry changed
# mid-window (REGISTER / DEREGISTER / unlock), the observed pool reflects
# the *current* snapshot. For windows shorter than the registry-
# stability horizon this is faithful; for longer windows the audit may
# flag late-registered validators as anomalously-low (legitimate
# undersampling, not selection bias). Stake values are also taken from
# the current snapshot — staking churn mid-window introduces error.
# The JSON envelope names the window length + pool composition so an
# operator can sanity-check this.
#
# Args:
#   [--rpc-port N]         RPC port to query (REQUIRED)
#   [--from H]             Lower window bound, inclusive (default: head-999)
#   [--to H]               Upper window bound, inclusive (default: head)
#   [--last N]             Shorthand for --from (head-N+1) --to head
#                          (mutually exclusive with --from/--to)
#   [--json]               Emit structured JSON envelope
#   [--anomalies-only]     Print only when ≥1 anomaly fires; exit 2 then
#   [--bias-threshold F]   Flag validator deviation magnitude > F
#                          (default: 0.30 — i.e. observed differs from
#                          expected by more than 30% in either direction)
#   [-h|--help]            Show this help
#
# Anomaly flags:
#   committee_bias_high     max |deviation| across all validators
#                           exceeds --bias-threshold (selection skewed
#                           relative to stake-proportional null)
#   validator_excluded      a registered validator with non-zero stake
#                           was NEVER selected in the window (potential
#                           exclusion bug, stake-weighting underflow, or
#                           legitimate late-registration → operator
#                           inspects `recently_active` separately)
#   validator_dominant      a single validator selected in > 50% of
#                           blocks (centralization signal — bias toward
#                           one validator could indicate pool collapse,
#                           weight misconfiguration, or operator
#                           misbehavior)
#
# Exit codes:
#   0   audit ran, no anomalies (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_audit.sh --rpc-port N
                                   [--from H] [--to H] [--last N]
                                   [--json] [--anomalies-only]
                                   [--bias-threshold F]

Audit per-validator committee-selection fairness over a window of
finalized blocks. For each block in the window, extracts creators[]
via `determ block-info <i> --json` and tallies per-validator selection
counts. Per-validator stake is taken from `determ validators --json`
at audit time.

Computes:
  per-validator: blocks_selected, observed_share = count / (W * K),
                 expected_share = stake_i / total_stake,
                 deviation      = (observed - expected) / expected
  summary:       max_deviation, n_biased, n_total
  position:      per-slot-index tally (proposer vs trailing positions)

Options:
  --rpc-port N         RPC port to query (REQUIRED)
  --from H             Lower window bound, inclusive (default: head-999)
  --to H               Upper window bound, inclusive (default: head)
  --last N             Shorthand for [head-N+1, head] (exclusive with
                       --from/--to)
  --json               Emit structured JSON envelope
  --anomalies-only     Print only when ≥1 anomaly fires; exit 2 then
  --bias-threshold F   Deviation magnitude > F flags as biased
                       (default: 0.30)
  -h, --help           Show this help

Anomalies:
  committee_bias_high   max |deviation| > --bias-threshold
  validator_excluded    non-zero-stake validator never selected in window
  validator_dominant    single validator in > 50% of blocks

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W, "K": K},
   "validators": [
     {"domain": "…", "stake": N, "blocks_selected": C,
      "observed_share": R, "expected_share": E, "deviation": D,
      "biased": bool,
      "position_distribution": [N_0, N_1, ..., N_{K-1}]}, ...],
   "summary": {"max_deviation": D, "n_biased": N, "n_total": N},
   "anomalies": [...],
   "rpc_port": P,
   "bias_threshold": F}

Exit codes:
  0   success, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
JSON_OUT=0
ANOM_ONLY=0
BIAS_THRESHOLD="0.30"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";            shift 2 ;;
    --from)            FROM="${2:-}";            shift 2 ;;
    --to)              TO="${2:-}";              shift 2 ;;
    --last)            LAST="${2:-}";            shift 2 ;;
    --json)            JSON_OUT=1;               shift ;;
    --anomalies-only)  ANOM_ONLY=1;              shift ;;
    --bias-threshold)  BIAS_THRESHOLD="${2:-}";  shift 2 ;;
    *) echo "operator_committee_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_committee_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_committee_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to (avoids the ambiguous
# case where an operator sets both and the intent is unclear).
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_committee_audit: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_committee_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_committee_audit: --last must be >= 1" >&2
  exit 1
fi

# Bias threshold: must be a non-negative float. Use python to parse +
# validate so any reasonable formatting (0.3, .3, 1.0, 1e-2, etc.) is
# accepted; bash regex over float literals is fragile.
python -c "
import sys
try:
    v = float('$BIAS_THRESHOLD')
    if v < 0: raise ValueError('negative')
except Exception as e:
    sys.stderr.write(f\"operator_committee_audit: --bias-threshold must be a non-negative float (got '\$BIAS_THRESHOLD': {e})\n\")
    sys.exit(1)
" || exit 1

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_dapp_inventory.sh).
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
  echo "operator_committee_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
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
  echo "operator_committee_audit: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1. (Block 0 is genesis with empty
# creators[]; included in the window if the operator opts into [0..H]
# but contributes nothing to the tally.)
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. Precedence: --last > (--from/--to) > defaults.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    # Default: last 1000 blocks ending at tip.
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_committee_audit: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: pool snapshot from validators RPC ─────────────────────────────────
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_audit: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: per-block walk + per-validator tally (driven from Python) ─────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_committee_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$BIAS_THRESHOLD" <<PY
import json, subprocess, sys, math

determ, port, from_h, to_h, out_path, bias_s = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)
bias_threshold = float(bias_s)

# Validators snapshot is fed via env (smaller than block walk, simpler
# than another tmp file).
val_json = '''$VAL_JSON'''
try:
    validators = json.loads(val_json)
except Exception:
    sys.stderr.write("operator_committee_audit: malformed validators JSON\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_committee_audit: validators RPC returned non-array\n")
    sys.exit(1)

# Pool domain → stake map. Zero-stake entries kept (DOMAIN_INCLUSION
# pre-genesis registrants are legitimate); the deviation math handles
# them with a finite/infinite branch.
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
    sys.stderr.write("operator_committee_audit: empty validator pool (port {})\n".format(port))
    sys.exit(1)

total_stake = sum(pool.values())
N           = len(pool)

# Per-validator counters. Init at zero for every pool member so the
# never-selected ones are visible (zero is evidence in this audit).
observed     = {d: 0 for d in pool}
# Position distribution: per-validator vector indexed by slot 0..K-1.
# Length is set after we know K; we collect raw (domain, slot) pairs.
position_hits = {d: {} for d in pool}  # domain -> {slot_idx: count}
size_dist     = {}  # K -> count of blocks at this size

# Walk the block window. One subprocess per block; cost is identical to
# operator_block_creator_fairness.sh / operator_fee_distribution_audit.sh.
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_committee_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_committee_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_committee_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list): creators = []
    creators = [c for c in creators if isinstance(c, str)]

    k = len(creators)
    size_dist[k] = size_dist.get(k, 0) + 1

    for idx, dom in enumerate(creators):
        # Only count pool-member creators (mirrors block_creator_fairness:
        # a creator outside the current pool — e.g. recently-deregistered
        # — would skew deviation arithmetic).
        if dom in pool:
            observed[dom] += 1
            d_slots = position_hits[dom]
            d_slots[idx] = d_slots.get(idx, 0) + 1

W = to_h - from_h + 1

# Modal K over the window. Ties broken by the larger K (same convention
# as operator_block_creator_fairness.sh — BFT-degraded blocks should not
# distort the "normal" K used as the baseline).
if size_dist:
    K = max(size_dist.items(), key=lambda kv: (kv[1], kv[0]))[0]
else:
    K = 0

total_slots = W * K
# Build per-validator rows.
# expected_share = stake / total_stake (zero if total_stake == 0).
# observed_share = blocks_selected / total_slots (zero if total_slots == 0).
# deviation handling:
#   - expected_share == 0 and observed_share == 0  => deviation = 0.0
#   - expected_share == 0 and observed_share  > 0  => deviation = +inf
#     (encoded as float('inf'); JSON emission converts inf to a
#     sentinel string "+inf" because vanilla JSON has no IEEE inf)
#   - expected_share > 0                            => relative dev
SMALL_EXPECTED = 1e-12

rows = []
max_dev_mag  = 0.0
max_dev_dom  = ""
n_biased     = 0
for dom, st in pool.items():
    cnt = observed[dom]
    exp = (st / total_stake) if total_stake > 0 else 0.0
    obs = (cnt / total_slots) if total_slots > 0 else 0.0
    if exp > SMALL_EXPECTED:
        dev = (obs - exp) / exp
        dev_finite = True
    else:
        # Zero (or near-zero) expected stake. Observed-positive indicates
        # the selection algorithm reached into a zero-weighted slot
        # which is a real anomaly (it shouldn't happen under correct
        # stake-weighted FY).
        if obs > 0:
            dev = float('inf')
            dev_finite = False
        else:
            dev = 0.0
            dev_finite = True
    biased = False
    if dev_finite:
        mag = abs(dev)
    else:
        mag = float('inf')
    if mag > bias_threshold:
        # Only count toward n_biased / max_dev when expected > 0 OR
        # observed > 0 — a strictly-zero validator doesn't deserve a
        # bias flag (it's just inactive).
        if exp > 0 or obs > 0:
            biased = True
            n_biased += 1
            if mag > max_dev_mag:
                max_dev_mag = mag
                max_dev_dom = dom

    # Position distribution as length-K vector. Missing slots get 0.
    pos_vec = []
    for slot in range(K):
        pos_vec.append(position_hits[dom].get(slot, 0))

    rows.append({
        "domain":                dom,
        "stake":                 st,
        "blocks_selected":       cnt,
        "observed_share":        obs,
        "expected_share":        exp,
        "deviation":             dev if dev_finite else "+inf",
        "deviation_magnitude":   mag if dev_finite else float('inf'),
        "deviation_finite":      dev_finite,
        "biased":                biased,
        "position_distribution": pos_vec,
    })

# Sort: worst-deviation first (magnitude desc, infs at top), ties by
# domain asc. Strict infs sort above finite values via the magnitude key.
rows.sort(key=lambda r: (
    not r["deviation_finite"],          # infs first
    -(r["deviation_magnitude"] if r["deviation_finite"] else 0.0),
    r["domain"],
))

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []
# committee_bias_high: any biased validator with a deviation magnitude
# above the threshold (max_dev_mag > bias_threshold AND max_dev_mag > 0).
if n_biased > 0:
    anomalies.append("committee_bias_high")
# validator_excluded: any non-zero-stake validator with zero observations.
# Window must be non-trivially long (W*K > 0 means we actually had
# selection slots to draw from).
if K > 0:
    for row in rows:
        if row["stake"] > 0 and row["blocks_selected"] == 0:
            anomalies.append("validator_excluded")
            break
# validator_dominant: any validator selected in > 50% of blocks.
# Using blocks (not slots) — a validator in 60% of blocks means it
# was on 60% of committees, even if K committees overlap with others.
if W > 0:
    for row in rows:
        if row["blocks_selected"] > W * 0.5:
            anomalies.append("validator_dominant")
            break

# Summary footer.
summary = {
    "max_deviation": (max_dev_mag if max_dev_mag != float('inf') else "+inf"),
    "max_deviation_domain": max_dev_dom,
    "n_biased":      n_biased,
    "n_total":       N,
}

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
        "K":           K,
    },
    "pool_size":   N,
    "total_stake": total_stake,
    "validators":  rows,
    "summary":     summary,
    "anomalies":   anomalies,
    "bias_threshold": bias_threshold,
}

# Encode envelope; serialize +inf in deviation/deviation_magnitude as
# the literal string "+inf" so the JSON is portable (json.dumps with
# allow_nan=False would error on inf).
def safe(o):
    if isinstance(o, float) and (math.isinf(o) or math.isnan(o)):
        return "+inf" if o == float('inf') else ("-inf" if o == float('-inf') else None)
    raise TypeError

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f, default=safe, allow_nan=False)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 4: render envelope ──────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" "$BIAS_THRESHOLD" <<'PY'
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
    print(f"operator_committee_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

K           = env["window"]["K"]
N           = env["pool_size"]
total_stake = env["total_stake"]
rows        = env["validators"]

print(f"=== Committee selection audit (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks) ===")
print(f"Pool size N: {N}    Committee size K (modal): {K}    "
      f"Total stake: {total_stake}")
print(f"Bias threshold: {bias_t}")
print()

def fmt_share(v):
    # Render a share fraction as a percentage with 2 decimal places.
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

# Per-validator table, sorted worst-deviation-first by the Python pass.
print("Per-validator selection (ranked by deviation, worst first):")
print(f"  {'domain':<28} {'stake':>10} {'selected':>9} {'observed':>10} {'expected':>10} {'deviation':>11} biased")
print(f"  {'-'*28} {'-'*10} {'-'*9} {'-'*10} {'-'*10} {'-'*11} {'-'*6}")
for r in rows:
    dom    = r["domain"][:28]
    stake  = r["stake"]
    cnt    = r["blocks_selected"]
    obs    = fmt_share(r["observed_share"])
    exp    = fmt_share(r["expected_share"])
    devraw = r["deviation"]
    dev    = fmt_dev(devraw)
    bflag  = "YES" if r["biased"] else "no"
    print(f"  {dom:<28} {stake:>10} {cnt:>9} {obs:>10} {exp:>10} {dev:>11} {bflag:>6}")

print()
summary = env["summary"]
md = summary["max_deviation"]
if isinstance(md, str):
    md_disp = md
else:
    md_disp = fmt_dev(md)
print(f"Max deviation: {md_disp}"
      + (f"  (validator: {summary['max_deviation_domain']})"
         if summary.get('max_deviation_domain') else ""))
print(f"Biased validators (|dev| > {bias_t}): "
      f"{summary['n_biased']} / {summary['n_total']}")

print()
if n_anom == 0:
    print("[OK] Selection within fairness bounds")
else:
    for a in anomalies:
        if a == "committee_bias_high":
            print(f"[WARN] committee_bias_high — max |deviation| > {bias_t}")
        elif a == "validator_excluded":
            # Find first excluded validator for the message.
            excl = [r["domain"] for r in rows
                    if r["stake"] > 0 and r["blocks_selected"] == 0]
            ex_disp = ", ".join(excl[:3])
            if len(excl) > 3:
                ex_disp += f", +{len(excl)-3} more"
            print(f"[WARN] validator_excluded — non-zero-stake validator(s) "
                  f"never selected: {ex_disp}")
        elif a == "validator_dominant":
            dom = [r["domain"] for r in rows
                   if r["blocks_selected"] > window * 0.5]
            print(f"[WARN] validator_dominant — single validator(s) "
                  f"selected in > 50% of blocks: {','.join(dom)}")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_committee_audit: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
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
