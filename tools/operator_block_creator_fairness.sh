#!/usr/bin/env bash
# operator_block_creator_fairness.sh — Audit committee-selection fairness
# over a window of finalized blocks on a running determ daemon. Answers
# the question: "given the active validator pool, is the on-chain
# committee-selection algorithm drawing uniformly across validators, or
# is some bias / RNG failure / sub-quorum situation producing a skewed
# distribution?"
#
# Sibling tools:
#   operator_committee_rotation.sh — composition + rotation rate of the
#                                    committee across a window (treats
#                                    the committee as a multiset evolving
#                                    over time; this script treats it as
#                                    a slot-allocation lottery).
#   operator_subsidy_audit.sh       — value-side concentration audit (who
#                                    got paid; this script asks who got
#                                    SELECTED, independent of payout).
#   operator_committee_audit.sh     — single-block (current-epoch) snapshot
#                                    of the committee, no statistical
#                                    treatment.
#
# Model:
#   Let N = size of the active validator pool (intersected against
#   `determ stakes --json` at audit time), K = committee size (taken as
#   the modal len(creators) observed in the window — robust against
#   transient BFT escalation blocks where K may temporarily diverge),
#   W = window block count.
#
#   Under a uniform-random committee selection rule (every K-subset of
#   the N-pool equally likely, as the rev.9 fork-free protocol intends),
#   each validator's *expected* selection count over W blocks is:
#
#       E = W * (K / N)
#
#   Per-validator observed count O_i is the number of blocks in
#   [--from..--to] whose `creators[]` contains validator i's domain.
#
#   Chi-squared statistic (Pearson):
#
#       χ² = Σ_i (O_i - E)² / E       over all N validators
#
#   degrees of freedom (d.f.) = N - 1. Under the uniform null hypothesis
#   the statistic is asymptotically χ²(N-1)-distributed; the audit
#   rejects uniformity when the right-tail p-value falls below 0.01.
#
#   p-value computed via the regularized upper incomplete gamma function
#   Q(a, x) (Numerical Recipes in C, §6.2): for χ² with k d.f.,
#       p = Q(k/2, χ²/2).
#   Implementation uses the gser / gcf series + continued-fraction
#   branches with gammln — no scipy dependency. Identical to the math in
#   `tools/test_shard_routing.sh`'s in-process chi-squared assertion.
#
# Pool composition caveat: validators are inferred from `determ stakes`
# at audit time, NOT from the registry at each block in the window. If
# the registry changed mid-window (REGISTER / DEREGISTER / unlock), the
# observed pool reflects the *current* snapshot. For windows shorter
# than the registry-stability horizon this is faithful; for longer
# windows the audit may flag validators that registered late as
# anomalously-low (legitimate undersampling, not selection bias). The
# `--anomalies-only` output names the pool size + window length so an
# operator can sanity-check this against operator_validator_history.
#
# Per-validator: O_i is computed by intersecting block.creators[] with
# the *current* stakes pool domain set; creators outside the current
# pool (e.g. a recently-deregistered validator that was active earlier
# in the window) are still counted toward the total committee slots
# but DO NOT enter the chi-squared sum — they would inflate d.f.
# without a meaningful uniform expectation.
#
# Args:
#   [--rpc-port N]      RPC port to query (default: 7778)
#   [--from H]          Lower window bound (inclusive). Default =
#                       max(0, head - 1000 + 1).
#   [--to H]            Upper window bound (inclusive). Default = head.
#   [--json]            Emit structured JSON envelope
#   [--anomalies-only]  Suppress non-anomaly output; exit 2 on alert
#   [-h|--help]         Show this help
#
# Exit codes:
#   0   success, no anomalies (or --anomalies-only not set)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 alert-worthy anomaly detected
#
# Anomaly flags:
#   chi_squared_significant     — p < 0.01 (statistically significant
#                                 deviation from uniform selection). On
#                                 a healthy chain the null hypothesis is
#                                 true and this fires ≤1% of audit runs
#                                 (definition of α). Repeated firings
#                                 across consecutive non-overlapping
#                                 windows are the real alert — a single
#                                 fire could be noise.
#   single_validator_dominant   — one validator appeared in >80% of
#                                 blocks (sub-quorum recovery or a clear
#                                 selection bias; in a healthy pool of
#                                 N ≥ 3 with K < N, the per-validator
#                                 ceiling is K/N which cannot exceed
#                                 67% for K ≤ 2N/3, so >80% strongly
#                                 implies degraded operation).
#   validator_zero_selections   — at least one validator in the pool
#                                 appeared in zero blocks of the window
#                                 (selection RNG failure, or just an
#                                 undersized window — fires below the
#                                 ~3K/W coverage threshold even on a
#                                 healthy chain; the JSON envelope
#                                 includes per-validator counts so the
#                                 operator can decide which case applies).
#
# Read-only RPC; safe against any running daemon. Requires `jq` for
# JSON traversal + `python` for the chi-squared math (manual Numerical
# Recipes impl — no scipy).
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_creator_fairness.sh [--rpc-port N] [--json]
                                          [--from H] [--to H]
                                          [--anomalies-only]

Audit committee-selection fairness over a window of finalized blocks.
For each block in [--from..--to] (default last 1000), extracts the
creators[] list via `determ block-info <i> --json` and tallies how
often each validator was selected. Pool is taken from `determ stakes
--json`; committee size K is the modal len(creators) over the window.

Expected per-validator selection count under uniform selection:
  E = W * (K / N)   where W = window blocks, N = pool size

Reports Pearson chi-squared statistic with (N-1) d.f. and p-value
(Numerical Recipes gammp/gammq; no scipy dependency).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --from H            Lower window bound (inclusive). Default:
                      max(0, head - 1000 + 1).
  --to H              Upper window bound (inclusive). Default: head.
  --json              Emit structured JSON envelope
  --anomalies-only    Print only when ≥1 alert-worthy anomaly is
                      detected; exit 2 in that case.
  -h, --help          Show this help

JSON shape:
  {"window":{"from":F,"to":T,"blocks":W},
   "pool_size":N,
   "committee_size":K,
   "expected_per_validator":E,
   "per_validator":[{"domain":"…","observed":O,"observed_rate":R,
                     "expected":E,"deviation":D},…],
   "chi_squared":X,
   "degrees_of_freedom":DF,
   "p_value":P,
   "anomalies":["…",…],
   "rpc_port":N}

Anomalies:
  chi_squared_significant     p < 0.01
  single_validator_dominant   one validator >80% selection rate
  validator_zero_selections   ≥1 pool validator with zero observations

Exit codes:
  0   success
  1   RPC error / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
FROM=""
TO=""
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";    shift 2 ;;
    --json)           JSON_OUT=1;       shift ;;
    --from)           FROM="${2:-}";    shift 2 ;;
    --to)             TO="${2:-}";      shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;      shift ;;
    *) echo "operator_block_creator_fairness: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_creator_fairness: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_block_creator_fairness: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_block_creator_fairness: jq is required (block JSON traversal)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_block_creator_fairness: python (or python3) is required for chi-squared math" >&2
  exit 1
fi
PYTHON=python
command -v python >/dev/null 2>&1 || PYTHON=python3

# ── Step 1: chain head ────────────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_creator_fairness: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_block_creator_fairness: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ -z "$TO" ]; then TO=$TOP; fi
if [ -z "$FROM" ]; then
  FROM=$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_block_creator_fairness: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: pool snapshot from stakes RPC ─────────────────────────────────────
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_creator_fairness: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}
# stakes returns an array of {rank, domain, stake, ...}; the domain set
# is the validator pool for the fairness null.
POOL_JSON=$(printf '%s' "$STAKES_JSON" | jq '[.[].domain]')
POOL_SIZE=$(printf '%s' "$POOL_JSON" | jq 'length')
case "$POOL_SIZE" in *[!0-9]*|"")
  echo "operator_block_creator_fairness: malformed stakes JSON (pool_size='$POOL_SIZE')" >&2
  exit 1 ;;
esac
if [ "$POOL_SIZE" = "0" ]; then
  echo "operator_block_creator_fairness: empty validator pool — nothing to audit (port $PORT)" >&2
  exit 1
fi

# ── Step 3: per-block walk + chi-squared (Python) ─────────────────────────────
TMP_AGG=$(mktemp)
trap 'rm -f "$TMP_AGG"' EXIT

# Drive the walk in Python so one subprocess per block is the only RPC
# cost. The Python pass produces the final JSON envelope (window meta,
# per-validator counts, chi-squared statistic, p-value, anomaly flags)
# in one go — the bash side reads the envelope back and renders.
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_AGG" "$POOL_JSON" <<'PY'
import json, subprocess, sys, math

determ, port, from_h, to_h, out_path, pool_json = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)
pool_domains = json.loads(pool_json)
pool_set     = set(pool_domains)
N            = len(pool_domains)

# Per-validator slot counts (domain → count) over the window. Init at
# zero for every pool member so chi-squared sees zero-observation
# validators (those would otherwise be silently excluded by a defaultdict
# that only inserts on first observation — a sin in goodness-of-fit
# tests, where the zero bucket is *evidence* for the alternative).
observed = {dom: 0 for dom in pool_domains}
size_dist = {}   # K → count of blocks with that committee size

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_block_creator_fairness: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_block_creator_fairness: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_block_creator_fairness: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    creators = [c for c in creators if isinstance(c, str)]

    K = len(creators)
    size_dist[K] = size_dist.get(K, 0) + 1

    # Only count pool-member creators toward the chi-squared sum (see
    # script header note on registry-mid-window changes).
    for dom in creators:
        if dom in pool_set:
            observed[dom] += 1

W = to_h - from_h + 1

# Committee size K: modal observed size over the window. Picks the most
# common; ties broken by the larger K (BFT-degraded blocks should not
# distort the "normal" K used as the fairness baseline). The expected-
# count formula assumes K is constant over the window — a multi-K window
# (BFT escalation) will inflate chi-squared slightly because the model
# is misspecified there. operator_committee_rotation.sh's
# committee_size_variance anomaly is the right surface for that.
if size_dist:
    K = max(size_dist.items(), key=lambda kv: (kv[1], kv[0]))[0]
else:
    K = 0

# Expected count per validator under uniform selection: E = W * K / N.
# Use float for the chi-squared sum, format final E and rate as floats.
if N > 0:
    E = (W * K) / N
else:
    E = 0.0

# ── Chi-squared sum ──────────────────────────────────────────────────────────
# Standard Pearson statistic. The pool can include validators with E < 5
# on small windows; we still compute the statistic but flag it for the
# operator (the chi-squared null is an asymptotic approximation that
# degrades when expected cell counts drop below ~5; below ~1 the
# approximation is poor and the p-value is more indicative than
# definitive). The protocol is: surface the number, leave the operator
# to decide whether a longer window is needed.
if E > 0:
    chi2 = sum((observed[dom] - E) ** 2 / E for dom in pool_domains)
else:
    # Degenerate case: K == 0 (no blocks observed, or every observed
    # block was empty-creators). Skip the chi-squared.
    chi2 = 0.0

# Degrees of freedom = N - 1 for a uniform-fit test on N bins.
dof = N - 1 if N > 0 else 0

# ── p-value via Numerical Recipes gammq ──────────────────────────────────────
# p = Q(dof/2, chi2/2) where Q is the regularized upper incomplete gamma.
# Implementation: gammln (Stirling-series log-gamma) + gser (series for
# x < a+1) + gcf (continued fraction for x >= a+1). Identical pattern
# to the in-process chi-squared assertion in tools/test_shard_routing.sh.

def gammln(xx):
    # Lanczos / Numerical Recipes log-gamma. Accurate to ~10 decimals
    # for xx > 0, which is all we need (a = dof/2 > 0 here).
    cof = [76.18009172947146, -86.50532032941677,
           24.01409824083091, -1.231739572450155,
           0.1208650973866179e-2, -0.5395239384953e-5]
    y = xx
    x = xx
    tmp = x + 5.5
    tmp -= (x + 0.5) * math.log(tmp)
    ser = 1.000000000190015
    for c in cof:
        y += 1.0
        ser += c / y
    return -tmp + math.log(2.5066282746310005 * ser / x)

def gser(a, x, eps=3.0e-16, itmax=200):
    # Series representation of the regularized lower incomplete gamma.
    # Returns (P(a,x), gammln(a)). Diverges only if x < 0 or a <= 0.
    gln = gammln(a)
    if x <= 0.0:
        return 0.0, gln
    ap  = a
    sum_ = 1.0 / a
    delta = sum_
    for _ in range(itmax):
        ap += 1.0
        delta *= x / ap
        sum_  += delta
        if abs(delta) < abs(sum_) * eps:
            return sum_ * math.exp(-x + a * math.log(x) - gln), gln
    # Did not converge — return best-effort (rare for sane chi-squared
    # inputs; the upper bound itmax=200 is enough for any astronomical
    # χ² that an honest chain would produce).
    return sum_ * math.exp(-x + a * math.log(x) - gln), gln

def gcf(a, x, eps=3.0e-16, itmax=200, fpmin=1.0e-300):
    # Continued fraction representation of the regularized upper
    # incomplete gamma. Lentz's algorithm with the early-bail of NR.
    # Returns (Q(a,x), gammln(a)).
    gln = gammln(a)
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, itmax + 1):
        an = -i * (i - a)
        b += 2.0
        d  = an * d + b
        if abs(d) < fpmin: d = fpmin
        c  = b + an / c
        if abs(c) < fpmin: c = fpmin
        d  = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return math.exp(-x + a * math.log(x) - gln) * h, gln

def gammq(a, x):
    # Q(a, x) = upper-tail regularized incomplete gamma. Routes to gser
    # / gcf per NR's convergence regions, returns 1.0 - lower or upper
    # directly. Edge cases: a <= 0 or x < 0 return 1.0 (no info; treated
    # as "test inapplicable, do not reject null").
    if a <= 0.0 or x < 0.0:
        return 1.0
    if x < a + 1.0:
        P, _ = gser(a, x)
        return 1.0 - P
    Q, _ = gcf(a, x)
    return Q

# p-value: Q(dof/2, chi2/2). Skipped (set to 1.0) when dof or chi2 is
# zero, since "no degrees of freedom" or "perfect fit" both mean "do
# not reject" — and gammq(0, *) is undefined.
if dof > 0 and chi2 > 0:
    p_value = gammq(dof / 2.0, chi2 / 2.0)
else:
    p_value = 1.0

# Per-validator output sorted by observed desc, ties by domain asc.
per_validator = []
for dom in pool_domains:
    o    = observed[dom]
    rate = (o / W) if W > 0 else 0.0
    per_validator.append({
        "domain":        dom,
        "observed":      o,
        "observed_rate": rate,
        "expected":      E,
        "deviation":     o - E,
    })
per_validator.sort(key=lambda r: (-r["observed"], r["domain"]))

# ── Anomaly detection ────────────────────────────────────────────────────────
anomalies = []
# chi_squared_significant: p < 0.01 with a non-degenerate test.
if dof > 0 and p_value < 0.01:
    anomalies.append("chi_squared_significant")
# single_validator_dominant: any validator's selection rate > 0.80.
if any(r["observed_rate"] > 0.80 for r in per_validator):
    anomalies.append("single_validator_dominant")
# validator_zero_selections: any pool validator with O = 0 (and the
# window has actually produced blocks, i.e. K > 0 — otherwise zeros
# are uninformative).
if K > 0 and any(r["observed"] == 0 for r in per_validator):
    anomalies.append("validator_zero_selections")

out = {
    "window": {"from": from_h, "to": to_h, "blocks": W},
    "pool_size":              N,
    "committee_size":         K,
    "expected_per_validator": E,
    "per_validator":          per_validator,
    "chi_squared":            chi2,
    "degrees_of_freedom":     dof,
    "p_value":                p_value,
    "anomalies":              anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(out))
PY
if [ "$?" -ne 0 ]; then
  echo "operator_block_creator_fairness: block walk / chi-squared failed" >&2
  exit 1
fi

# ── Step 4: render ────────────────────────────────────────────────────────────
RAW=$(cat "$TMP_AGG")
ANOM_COUNT=$(printf '%s' "$RAW" | jq '.anomalies | length')

# Inject rpc_port into the envelope.
ENVELOPE=$(printf '%s' "$RAW" | jq --argjson p "$PORT" '. + {rpc_port: $p}')

emit_json() {
  printf '%s' "$ENVELOPE" | jq .
}

# Format a float p-value for human readout: use scientific notation
# when very small (< 1e-3), three decimals otherwise. ">0.5" / ">0.9"
# bins for very-large p-values matches the test_lottery_subsidy style.
fmt_p() {
  printf '%s' "$ENVELOPE" | jq -r '
    .p_value as $p
    | if   $p >= 0.5  then "p > 0.5"
      elif $p >= 0.1  then "p > 0.1  (" + ($p | tostring) + ")"
      elif $p >= 0.01 then "p = " + ($p | tostring)
      else "p = " + ($p | tostring) + "  (< 0.01)"
      end
  '
}

emit_human() {
  echo "=== Block creator fairness (port $PORT, window [$FROM..$TO], $WINDOW blocks) ==="
  POOL=$(printf '%s' "$ENVELOPE" | jq -r '.pool_size')
  K=$(printf '%s' "$ENVELOPE" | jq -r '.committee_size')
  echo "Validator pool: $POOL"
  echo "Committee size K: $K"
  # Expected per-validator selection rate (K/N), rendered as a percentage
  # with one decimal place — same rounding convention as
  # operator_committee_rotation.sh's participation_rate.
  EXP_RATE=$(printf '%s' "$ENVELOPE" | jq -r '
    if .pool_size > 0
      then ((.committee_size / .pool_size) * 1000 | round / 10 | tostring) + "%"
      else "n/a"
    end
  ')
  EXP=$(printf '%s' "$ENVELOPE" | jq -r '.expected_per_validator | (. * 10 | round / 10)')
  echo "Expected per-validator selection rate: $EXP_RATE ($K/$POOL)"
  echo "Observed:"
  # Per-validator table: "  <domain>: <observed> (<rate>%)  expected <E>"
  MAXLEN=$(printf '%s' "$ENVELOPE" | jq -r '
    [.per_validator[].domain | length] | max // 0
  ')
  [ "$MAXLEN" -gt 24 ] && MAXLEN=24
  [ "$MAXLEN" -lt 8  ] && MAXLEN=8
  printf '%s' "$ENVELOPE" | jq -r --argjson w "$WINDOW" --argjson pad "$MAXLEN" '
    .per_validator[]
    | (
        .domain                                      as $d
        | .observed                                  as $o
        | (.observed_rate * 1000 | round / 10)       as $pct
        | (.expected * 10 | round / 10)              as $e
        | "  \($d):\("                                          " | .[0:($pad - ($d|length) + 1)]) \($o) (\($pct)%)  expected \($e)"
      )
  '

  DOF=$(printf '%s' "$ENVELOPE" | jq -r '.degrees_of_freedom')
  CHI2=$(printf '%s' "$ENVELOPE" | jq -r '.chi_squared | (. * 100 | round / 100)')
  PHUMAN=$(fmt_p)
  echo "Chi-squared ($DOF d.f.): $CHI2  ($PHUMAN)"

  if [ "$ANOM_COUNT" = "0" ]; then
    echo "[OK] Selection within fairness bounds"
  else
    printf '%s' "$ENVELOPE" | jq -r '.anomalies[]' | while IFS= read -r A; do
      case "$A" in
        chi_squared_significant)
          echo "[WARN] Chi-squared significant (p < 0.01) — selection deviates from uniform"
          ;;
        single_validator_dominant)
          echo "[WARN] Single validator >80% selection rate — bias or sub-quorum"
          ;;
        validator_zero_selections)
          echo "[WARN] At least one pool validator received zero selections in window"
          ;;
      esac
    done
  fi
}

# --anomalies-only mode: suppress output unless an anomaly was detected.
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$ANOM_COUNT" -gt 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
    exit 2
  fi
  exit 0
fi

if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
exit 0
