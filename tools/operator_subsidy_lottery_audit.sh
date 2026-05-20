#!/usr/bin/env bash
# operator_subsidy_lottery_audit.sh — audit LOTTERY-mode subsidy outcomes
# for fairness deviations. Distinct from `operator_subsidy_audit.sh`
# (which is FLAT-mode-aware and reports concentration / A1-drift over
# the assumed FLAT per-block subsidy). This script audits the E3
# subsidy-as-lottery semantics in chain.cpp::apply_block:
#
#   if (subsidy_mode_ == 1 && lottery_jackpot_multiplier_ >= 2) {
#       uint64_t lottery = read_be64(&b.cumulative_rand[0..8));
#       if (lottery % lottery_jackpot_multiplier_ == 0) {
#           base_subsidy = block_subsidy_ * lottery_jackpot_multiplier_;
#       } else {
#           base_subsidy = 0;
#       }
#   }
#
# Block-level lottery (per chain.cpp): the WHOLE block is the lottery
# unit. With probability 1/M the block pays `block_subsidy * M` (split
# equally across that block's creators); with probability (M-1)/M the
# block pays 0. Per-creator fairness derives from creator membership in
# jackpot blocks. The audit answers two questions:
#
#   (a) Is the jackpot HIT-RATE close to 1/M? (block-level fairness)
#       — chi-squared on (hits, misses) vs (n/M, n(M-1)/M).
#   (b) Are PER-CREATOR shares of total jackpot subsidy uniform?
#       — chi-squared on observed per-creator subsidy vs expected
#       uniform (total_subsidy / distinct_creators).
#
# FLAT-mode detection: if no LOTTERY signal is found (genesis says FLAT,
# or block sweep reveals all-non-empty creator credits with no zero-pay
# blocks), emit a single informational line and exit 0. This script is
# the LOTTERY counterpart; operators on FLAT chains should use
# `operator_subsidy_audit.sh` instead.
#
# Mode detection priority:
#   1. --genesis <file>     read subsidy_mode + lottery_jackpot_multiplier
#                           from the genesis JSON (authoritative source)
#   2. --multiplier <M>     operator-supplied M (skips heuristic)
#   3. Heuristic sweep      walk window blocks; count blocks where
#                           lottery = first 8 bytes (big-endian) of
#                           cumulative_rand divides cleanly by candidate M
#                           in {2,3,4,5,6,7,8,10,12,16,20,25,50,100};
#                           the M whose hit count is closest to N/M (the
#                           Bernoulli expectation) wins. Falls back to
#                           FLAT mode if heuristic yields no signal.
#
# RPC dependencies (all read-only):
#   - head              (current chain height)
#   - block-info <h>    (per-block JSON via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - jackpot_rate_pvalue_low     chi-squared p-value < 0.01 on the
#                                 (hits, misses) two-cell test (block-level
#                                 lottery rate deviates from 1/M)
#   - creator_share_pvalue_low    chi-squared p-value < 0.01 on the
#                                 N-cell per-creator share test
#                                 (a creator's jackpot participation is
#                                 statistically unfair vs uniform)
#   - single_creator_dominance    one creator has > 40% of all jackpot
#                                 subsidy (clear bias)
#   - mode_undetected             could not infer LOTTERY mode from genesis
#                                 or heuristic — the audit cannot run
#                                 (reported informationally; not a
#                                 fairness anomaly per se but still flagged)
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or FLAT-mode informational)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 statistical anomaly fired
#
# Usage:
#   tools/operator_subsidy_lottery_audit.sh [--rpc-port N] [--json]
#                                           [--from H] [--to H]
#                                           [--genesis <file>]
#                                           [--multiplier M]
#                                           [--anomalies-only]
set -u

usage() {
  cat <<'EOF'
Usage: operator_subsidy_lottery_audit.sh [--rpc-port N] [--json]
                                         [--from H] [--to H]
                                         [--genesis <file>]
                                         [--multiplier M]
                                         [--anomalies-only]

Audit LOTTERY-mode subsidy outcomes for fairness. Walks blocks via
`determ block-info <h> --json`, classifies each as jackpot/miss using
the chain.cpp lottery rule (`first8bytes(cumulative_rand) % M == 0`),
and reports:
  - block-level jackpot HIT RATE vs theoretical 1/M
  - per-creator distribution of jackpot subsidy vs theoretical uniform
  - chi-squared statistic + p-value on both
  - statistical anomalies (--anomalies-only gate, exit 2)

For FLAT-mode chains: emits an informational line and exits 0.
Use `operator_subsidy_audit.sh` for FLAT-mode chains.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window (default: tip)
  --genesis <file>    Parse mode from genesis.json (authoritative);
                      reads subsidy_mode (0=FLAT, 1=LOTTERY) and
                      lottery_jackpot_multiplier
  --multiplier M      Override mode detection: assume LOTTERY with this
                      jackpot multiplier (M >= 2)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Exit codes:
  0   success (or FLAT-mode informational)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 statistical anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
GEN_PATH=""
FORCE_MULT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";       shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="$2";     shift 2 ;;
    --to)              TO_H="$2";       shift 2 ;;
    --genesis)         GEN_PATH="$2";   shift 2 ;;
    --multiplier)      FORCE_MULT="$2"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_subsidy_lottery_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_subsidy_lottery_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_subsidy_lottery_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$FORCE_MULT" ]; then
  case "$FORCE_MULT" in *[!0-9]*|"")
    echo "operator_subsidy_lottery_audit: --multiplier must be a positive integer (got '$FORCE_MULT')" >&2
    exit 1 ;;
  esac
  if [ "$FORCE_MULT" -lt 2 ]; then
    echo "operator_subsidy_lottery_audit: --multiplier must be >= 2 (LOTTERY requires M>=2)" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve tip + window ──────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_lottery_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_subsidy_lottery_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip (per spec — wider than
# operator_subsidy_audit's 100 because lottery fairness analysis needs
# more samples to discriminate ~1/M Bernoulli rates at typical M).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_subsidy_lottery_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: try mode detection from --genesis (authoritative source) ─────────
GEN_MULT=""
GEN_MODE=""
if [ -n "$GEN_PATH" ]; then
  if [ ! -r "$GEN_PATH" ]; then
    echo "operator_subsidy_lottery_audit: --genesis path not readable: $GEN_PATH" >&2
    exit 1
  fi
  # Parse subsidy_mode + lottery_jackpot_multiplier from genesis JSON.
  # Direct field reads — these are top-level integers in genesis.json
  # per src/chain/genesis.cpp::to_json.
  GEN_PARSED=$(python - "$GEN_PATH" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        g = json.load(f)
    mode = int(g.get("subsidy_mode", 0))
    mult = int(g.get("lottery_jackpot_multiplier", 0))
    print(f"{mode}\t{mult}")
except Exception:
    print("ERR")
    sys.exit(2)
PY
)
  if [ "$GEN_PARSED" = "ERR" ] || [ -z "$GEN_PARSED" ]; then
    echo "operator_subsidy_lottery_audit: failed to parse --genesis JSON" >&2
    exit 1
  fi
  GEN_MODE=$(printf '%s' "$GEN_PARSED" | cut -f1)
  GEN_MULT=$(printf '%s' "$GEN_PARSED" | cut -f2)
fi

# Operator override beats genesis (genesis defaults to 0 if absent in
# older test setups; --multiplier lets you audit anyway).
if [ -n "$FORCE_MULT" ]; then
  MULT="$FORCE_MULT"
  MODE_SOURCE="cli_override"
elif [ -n "$GEN_MODE" ] && [ "$GEN_MODE" = "1" ]; then
  MULT="$GEN_MULT"
  MODE_SOURCE="genesis"
elif [ -n "$GEN_MODE" ] && [ "$GEN_MODE" = "0" ]; then
  # Genesis explicitly says FLAT. Short-circuit with the standard
  # informational line + exit 0.
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"mode":"flat","window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
    printf '"info":"chain runs FLAT-mode subsidy — lottery audit not applicable",'
    printf '"mode_source":"genesis","rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
  else
    echo "INFO: chain runs FLAT-mode subsidy — lottery audit not applicable"
  fi
  exit 0
else
  MULT=""    # will be filled by the heuristic sweep
  MODE_SOURCE="heuristic"
fi

# ── Step 3: walk the window + collect per-block lottery signal ───────────────
# For each block in [FROM, TO] we extract:
#   - cumulative_rand[0..8) as big-endian u64 (the "lottery" value used
#     by chain.cpp). Compute lottery % M for the M we ultimately settle
#     on; jackpot iff the remainder is 0.
#   - block.creators[] (for per-creator attribution on jackpot blocks)
# We collect the raw lottery values in a TSV ledger first, then resolve
# the multiplier (either supplied or heuristic-inferred) and aggregate
# in a second pass without re-fetching block-info.
#
# TMP_BLOCKS layout (one row per block in [FROM, TO]):
#   <height>\t<lottery_u64>\t<creator_count>\t<comma_sep_creators>
TMP_BLOCKS=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_lottery_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_BLOCKS" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_BLOCKS" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, blocks_path = sys.argv[1:6]
from_h = int(from_h)
to_h   = int(to_h)

# Read first 8 bytes of cumulative_rand as big-endian u64 — matches
# chain.cpp::apply_block: lottery = (lottery << 8) | b.cumulative_rand[i]
# for i in 0..8.
def be_u64_prefix(hex_str: str) -> int:
    s = hex_str.strip().lower()
    if len(s) < 16:
        return 0
    try:
        return int(s[:16], 16)
    except ValueError:
        return 0

with open(blocks_path, "w", encoding="utf-8") as out:
    for h in range(from_h, to_h + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=15
            )
        except Exception as e:
            sys.stderr.write(f"operator_subsidy_lottery_audit: block-info {h} failed: {e}\n")
            sys.exit(1)
        if r.returncode != 0:
            sys.stderr.write(f"operator_subsidy_lottery_audit: block-info {h} rc={r.returncode}\n")
            sys.stderr.write(r.stderr)
            sys.exit(1)
        try:
            blk = json.loads(r.stdout)
        except Exception:
            sys.stderr.write(f"operator_subsidy_lottery_audit: block-info {h} returned non-JSON\n")
            sys.exit(1)
        if not isinstance(blk, dict):
            continue
        cumr = blk.get("cumulative_rand") or ""
        if not isinstance(cumr, str):
            cumr = ""
        lottery = be_u64_prefix(cumr)
        creators = blk.get("creators") or []
        if not isinstance(creators, list):
            creators = []
        # Sanitize creator names (no tabs / commas to keep TSV+CSV clean).
        sanitized = [c for c in creators
                     if isinstance(c, str) and "\t" not in c and "," not in c]
        cc       = len(sanitized)
        joined   = ",".join(sanitized)
        out.write(f"{h}\t{lottery}\t{cc}\t{joined}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_subsidy_lottery_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 4: heuristic multiplier inference if needed ─────────────────────────
# Walk the lottery_u64 column and test each candidate M from a curated
# list of typical jackpot multipliers. For each candidate, compute the
# observed hit count (rows where `lottery % M == 0`) and the residual
# vs the theoretical hit count N/M.
#
# NOTE on the smallest-M tiebreak: if the chain's true multiplier is M*,
# then for every multiple of M* in the candidate list, `lottery % M == 0`
# also holds for a uniform fraction of blocks ≈ 1/M (because the
# chain-side lottery values are 8-bytes-of-cumulative_rand, effectively
# uniform mod-anything-not-a-power-of-2-multiplier-of-M*). So the
# residuals at M*, 2M*, 4M*, … all converge to zero as the window grows.
# We resolve this ambiguity by picking the SMALLEST candidate M whose
# residual is within tolerance — the true multiplier necessarily has
# the highest hit rate (1/M*), and any larger candidate would imply
# the chain is paying jackpots LESS often than observed, which is
# inconsistent.
#
# FLAT-mode safety: if NO candidate's hits match within tolerance — i.e.,
# the chain is FLAT (every block credits the same constant subsidy, so
# the lottery rule never fires and the cumulative_rand mod-M distribution
# carries no signal) — we fall through to the FLAT-mode informational
# branch. The tolerance is 5 pp (500 bps) for windows >= 100 blocks and
# 10 pp (1000 bps) for smaller windows, to avoid false-positive LOTTERY
# claims on chains where uniform cumulative_rand happens to match a
# multiple of some candidate M by chance.
if [ -z "$MULT" ]; then
  CANDIDATES="2 3 4 5 6 7 8 10 12 16 20 25 50 100"
  ACCEPT_BPS=500
  [ "$WIN_BLOCKS" -lt 100 ] && ACCEPT_BPS=1000
  BEST_M=""
  for M in $CANDIDATES; do
    HITS=$(awk -F'\t' -v m="$M" '$2 % m == 0 { c++ } END { print c+0 }' "$TMP_BLOCKS")
    if [ "$HITS" = "0" ]; then continue; fi
    EXPECTED_HITS=$(( WIN_BLOCKS / M ))
    DIFF=$(( HITS - EXPECTED_HITS ))
    [ "$DIFF" -lt 0 ] && DIFF=$(( - DIFF ))
    RESIDUAL_BPS=$(( DIFF * 10000 / (WIN_BLOCKS > 0 ? WIN_BLOCKS : 1) ))
    if [ "$RESIDUAL_BPS" -le "$ACCEPT_BPS" ]; then
      # First (smallest) candidate within tolerance wins; CANDIDATES is
      # sorted ascending, so we can break early.
      BEST_M="$M"
      break
    fi
  done
  if [ -n "$BEST_M" ]; then
    MULT="$BEST_M"
  fi
fi

# If we still don't have a multiplier, emit FLAT-mode short-circuit.
if [ -z "$MULT" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"mode":"flat","window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
    printf '"info":"chain runs FLAT-mode subsidy — lottery audit not applicable",'
    printf '"mode_source":"%s","rpc_port":%s,"head_height":%s}\n' "$MODE_SOURCE" "$PORT" "$HEAD_H"
  else
    echo "INFO: chain runs FLAT-mode subsidy — lottery audit not applicable"
  fi
  exit 0
fi

# ── Step 5: per-creator aggregation across jackpot blocks ────────────────────
# Per chain.cpp: jackpot block credits each of its creators with
# (block_subsidy * M) / len(creators), with the modular remainder going
# to creators[0]. The block_subsidy value isn't directly observable from
# block-info (it's a chain constant), but for FAIRNESS analysis we only
# need RELATIVE shares — the constant scales out. We weight each jackpot
# attribution as 1 unit per creator slot (or 1.0 / len(creators) for
# the relative-share metric). The chi-squared statistic is invariant to
# this scaling.
#
# We emit two TSV ledgers via Python so the math is exact:
#   TMP_CREATORS: <creator>\t<hits>\t<weighted_share_milli>
#   (weighted_share is in milli-units, scale = 1000 per jackpot, divided
#   among that block's creators — keeps integer math but with enough
#   precision to discriminate uneven creator counts)
TMP_CREATORS=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_lottery_audit: cannot create temp file" >&2; exit 1;
}
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_lottery_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_BLOCKS" "$TMP_CREATORS" "$TMP_STATS" 2>/dev/null' EXIT

python - "$TMP_BLOCKS" "$MULT" "$TMP_CREATORS" "$TMP_STATS" <<'PY'
import sys
from collections import defaultdict

blocks_path, mult_str, creators_path, stats_path = sys.argv[1:5]
M = int(mult_str)

# Per-creator counters.
hits_per      = defaultdict(int)          # # of jackpot blocks this creator appeared on
share_milli   = defaultdict(int)          # weighted milli-units of jackpot share

jackpot_blocks = 0
miss_blocks    = 0
total_blocks   = 0
empty_creators_jackpot = 0   # jackpot blocks that had no creators (apply-side pays nothing)

with open(blocks_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            # height\tlottery\tcc\t<no creators>  → cc=0, joined=""
            parts += [""] * (4 - len(parts))
        height_s, lottery_s, cc_s, joined = parts
        try:
            lottery = int(lottery_s)
            cc      = int(cc_s)
        except ValueError:
            continue
        total_blocks += 1
        is_jackpot = (lottery % M == 0)
        if is_jackpot:
            jackpot_blocks += 1
            if cc == 0:
                empty_creators_jackpot += 1
                continue
            # Each creator gets 1000/cc milli-units of jackpot share.
            # Remainder (1000 - cc * (1000//cc)) goes to creators[0],
            # mirroring chain.cpp's per-block dust rule.
            creators = [c for c in joined.split(",") if c]
            if len(creators) != cc:
                # joined-list parse mismatch; trust joined as ground truth
                cc = len(creators)
                if cc == 0:
                    empty_creators_jackpot += 1
                    continue
            each = 1000 // cc
            rem  = 1000 - each * cc
            for c in creators:
                hits_per[c] += 1
                share_milli[c] += each
            share_milli[creators[0]] += rem
        else:
            miss_blocks += 1

# Per-creator ledger sorted by hits desc (ties by name asc).
rows = sorted(
    hits_per.keys(),
    key=lambda c: (-hits_per[c], c)
)
with open(creators_path, "w", encoding="utf-8") as f:
    for c in rows:
        f.write(f"{c}\t{hits_per[c]}\t{share_milli[c]}\n")

total_share_milli = sum(share_milli.values())
distinct_creators = len(rows)

# ── Chi-squared #1: jackpot-rate (2 cells, 1 d.f.) ────────────────────────
# H0: P(jackpot) = 1/M.
#   observed = (jackpot_blocks, miss_blocks)
#   expected = (total/M, total*(M-1)/M)
#   chi2     = Σ (o_i - e_i)^2 / e_i
expected_jackpot = total_blocks / M if M > 0 else 0.0
expected_miss    = total_blocks - expected_jackpot
chi2_rate = 0.0
if expected_jackpot > 0 and expected_miss > 0:
    chi2_rate  = (jackpot_blocks - expected_jackpot) ** 2 / expected_jackpot
    chi2_rate += (miss_blocks - expected_miss) ** 2 / expected_miss

# ── Chi-squared #2: per-creator share (N cells, N-1 d.f.) ─────────────────
# H0: each creator receives 1/N of total jackpot subsidy.
# We use the share_milli weighting (so blocks with N committee creators
# contribute 1000 milli-units split N ways — preserves the per-creator
# attribution semantics of chain.cpp's "subsidy/m" split).
expected_share_each = (total_share_milli / distinct_creators) if distinct_creators > 0 else 0.0
chi2_creator = 0.0
if distinct_creators > 1 and expected_share_each > 0:
    for c in rows:
        diff = share_milli[c] - expected_share_each
        chi2_creator += (diff * diff) / expected_share_each

# ── P-value: chi-squared CDF via regularized lower incomplete gamma ──────
# p-value(chi2; k d.f.) = 1 - F_chi2(chi2; k)
#                      = 1 - P(k/2, chi2/2)
# where P(a, x) is the regularized lower incomplete gamma function.
# We compute P(a, x) via a Lanczos approximation of log(gamma(a)) plus a
# Kummer series expansion of γ(a, x) for x < a+1 and a continued-fraction
# expansion of Γ(a, x) for x >= a+1 — the standard Numerical-Recipes
# split. Scipy NOT required.
import math

def _ln_gamma(z):
    # Lanczos with g=7, n=9 — accurate to ~1e-15 over real z > 0.
    g = 7
    coefs = [
        0.99999999999980993,
        676.5203681218851, -1259.1392167224028,
        771.32342877765313, -176.61502916214059,
        12.507343278686905, -0.13857109526572012,
        9.9843695780195716e-6, 1.5056327351493116e-7
    ]
    if z < 0.5:
        return math.log(math.pi / math.sin(math.pi * z)) - _ln_gamma(1 - z)
    z -= 1
    x = coefs[0]
    for i in range(1, g + 2):
        x += coefs[i] / (z + i)
    t = z + g + 0.5
    return 0.5 * math.log(2 * math.pi) + (z + 0.5) * math.log(t) - t + math.log(x)

def _gser(a, x, itmax=200, eps=3e-16):
    # Kummer series for γ(a, x) / Γ(a) — converges for x < a+1.
    if x <= 0.0:
        return 0.0
    ap  = a
    s   = 1.0 / a
    delt = s
    for _ in range(itmax):
        ap += 1.0
        delt *= x / ap
        s    += delt
        if abs(delt) < abs(s) * eps:
            break
    return s * math.exp(-x + a * math.log(x) - _ln_gamma(a))

def _gcf(a, x, itmax=200, eps=3e-16):
    # Continued fraction for Γ(a, x) / Γ(a) — converges for x >= a+1.
    # Lentz's modified algorithm (Numerical Recipes §6.2).
    fpmin = 1e-300
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
        delt = d * c
        h *= delt
        if abs(delt - 1.0) < eps:
            break
    return h * math.exp(-x + a * math.log(x) - _ln_gamma(a))

def regularized_lower_gamma(a, x):
    # P(a, x) = γ(a, x) / Γ(a). Branch on x vs a+1.
    if x < 0.0 or a <= 0.0:
        return 0.0
    if x < a + 1.0:
        return _gser(a, x)
    else:
        return 1.0 - _gcf(a, x)

def chi2_pvalue(chi2, dof):
    if chi2 <= 0.0 or dof <= 0:
        return 1.0
    p_lower = regularized_lower_gamma(dof / 2.0, chi2 / 2.0)
    # Clamp numerical noise into [0, 1].
    p = 1.0 - p_lower
    if   p < 0.0: p = 0.0
    elif p > 1.0: p = 1.0
    return p

p_rate    = chi2_pvalue(chi2_rate,    1)
dof_creator = max(distinct_creators - 1, 1)
p_creator = chi2_pvalue(chi2_creator, dof_creator)

# Single-creator-dominance check: any creator with > 40% of share?
max_share_pct_x100 = 0    # percent × 100 (i.e., basis points)
top_creator = ""
if total_share_milli > 0:
    for c in rows:
        pct_x100 = int(share_milli[c] * 10000 / total_share_milli)
        if pct_x100 > max_share_pct_x100:
            max_share_pct_x100 = pct_x100
            top_creator = c

with open(stats_path, "w", encoding="utf-8") as f:
    f.write(f"jackpot_blocks\t{jackpot_blocks}\n")
    f.write(f"miss_blocks\t{miss_blocks}\n")
    f.write(f"total_blocks\t{total_blocks}\n")
    f.write(f"empty_creators_jackpot\t{empty_creators_jackpot}\n")
    f.write(f"distinct_creators\t{distinct_creators}\n")
    f.write(f"total_share_milli\t{total_share_milli}\n")
    # Floats stringified to 6 decimal places for stable parse + display.
    f.write(f"expected_jackpot_blocks\t{expected_jackpot:.6f}\n")
    f.write(f"expected_miss_blocks\t{expected_miss:.6f}\n")
    f.write(f"expected_share_each_milli\t{expected_share_each:.6f}\n")
    f.write(f"chi2_rate\t{chi2_rate:.6f}\n")
    f.write(f"chi2_creator\t{chi2_creator:.6f}\n")
    f.write(f"p_rate\t{p_rate:.6f}\n")
    f.write(f"p_creator\t{p_creator:.6f}\n")
    f.write(f"dof_creator\t{dof_creator}\n")
    f.write(f"max_share_bps\t{max_share_pct_x100}\n")
    f.write(f"top_creator\t{top_creator}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_subsidy_lottery_audit: per-creator aggregation failed" >&2
  exit 1
fi

# ── Step 6: read aggregated stats back into shell variables ──────────────────
read_stat() {
  awk -F'\t' -v k="$1" '$1 == k { for(i=2;i<=NF;i++){ if(i>2) printf "\t"; printf "%s", $i }; exit }' "$TMP_STATS"
}
JACKPOT_BLOCKS=$(read_stat jackpot_blocks)
MISS_BLOCKS=$(read_stat miss_blocks)
TOTAL_BLOCKS=$(read_stat total_blocks)
EMPTY_CREATORS_JACKPOT=$(read_stat empty_creators_jackpot)
DISTINCT_CREATORS=$(read_stat distinct_creators)
TOTAL_SHARE_MILLI=$(read_stat total_share_milli)
EXPECTED_JACKPOT_BLOCKS=$(read_stat expected_jackpot_blocks)
EXPECTED_MISS_BLOCKS=$(read_stat expected_miss_blocks)
EXPECTED_SHARE_EACH_MILLI=$(read_stat expected_share_each_milli)
CHI2_RATE=$(read_stat chi2_rate)
CHI2_CREATOR=$(read_stat chi2_creator)
P_RATE=$(read_stat p_rate)
P_CREATOR=$(read_stat p_creator)
DOF_CREATOR=$(read_stat dof_creator)
MAX_SHARE_BPS=$(read_stat max_share_bps)
TOP_CREATOR=$(read_stat top_creator)

# Defensive defaults if any field came back empty (e.g. malformed line).
: "${JACKPOT_BLOCKS:=0}"
: "${MISS_BLOCKS:=0}"
: "${TOTAL_BLOCKS:=0}"
: "${EMPTY_CREATORS_JACKPOT:=0}"
: "${DISTINCT_CREATORS:=0}"
: "${TOTAL_SHARE_MILLI:=0}"
: "${EXPECTED_JACKPOT_BLOCKS:=0.000000}"
: "${EXPECTED_MISS_BLOCKS:=0.000000}"
: "${EXPECTED_SHARE_EACH_MILLI:=0.000000}"
: "${CHI2_RATE:=0.000000}"
: "${CHI2_CREATOR:=0.000000}"
: "${P_RATE:=1.000000}"
: "${P_CREATOR:=1.000000}"
: "${DOF_CREATOR:=1}"
: "${MAX_SHARE_BPS:=0}"

# ── Step 7: assemble anomalies list ──────────────────────────────────────────
# Float comparison via awk (POSIX shell doesn't do floats).
flt_lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a+0 < b+0) }'; }

ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
if flt_lt "$P_RATE"    "0.01"; then add_anom "jackpot_rate_pvalue_low";  fi
if flt_lt "$P_CREATOR" "0.01"; then add_anom "creator_share_pvalue_low"; fi
if [ "$MAX_SHARE_BPS" -gt 4000 ]; then add_anom "single_creator_dominance"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# Helpers for rendering percent / p-value bands.
render_pct_milli() {
  # Input: milli-units of a fraction-of-total (0..1000). Output: "NN.N%".
  local m="$1"
  local whole=$(( m / 10 ))
  local frac=$((  m % 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}
render_p_band() {
  # Categorize p-value into operator-friendly bands.
  awk -v p="$1" 'BEGIN {
    if      (p+0 < 0.001) printf "p < 0.001";
    else if (p+0 < 0.01)  printf "p < 0.01";
    else if (p+0 < 0.05)  printf "p < 0.05";
    else if (p+0 < 0.1)   printf "p < 0.1";
    else if (p+0 < 0.5)   printf "p < 0.5";
    else                  printf "p > 0.5";
  }'
}

# Theoretical-rate display: e.g. M=5 → "20.0%".
THEORETICAL_RATE_BPS=$(( 10000 / MULT ))
# Convert 0..10000 bps to "NN.N%" via render_pct's bps style.
render_pct_bps() {
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}

# ── Step 8: emit output ──────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build per-creator observed/expected arrays. Same scaling: milli-units.
  printf '{"mode":"lottery","window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"multiplier":%s,"mode_source":"%s",' "$MULT" "$MODE_SOURCE"
  printf '"jackpot_blocks":%s,"miss_blocks":%s,' "$JACKPOT_BLOCKS" "$MISS_BLOCKS"
  printf '"expected_jackpot_blocks":%s,"expected_miss_blocks":%s,' "$EXPECTED_JACKPOT_BLOCKS" "$EXPECTED_MISS_BLOCKS"
  printf '"distinct_creators":%s,' "$DISTINCT_CREATORS"
  printf '"observed_wins":{'
  FIRST=1
  if [ -s "$TMP_CREATORS" ]; then
    while IFS=$'\t' read -r C HITS SHARE; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      printf '"%s":%s' "$C" "$HITS"
    done <"$TMP_CREATORS"
  fi
  printf '},"observed_share_milli":{'
  FIRST=1
  if [ -s "$TMP_CREATORS" ]; then
    while IFS=$'\t' read -r C HITS SHARE; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      printf '"%s":%s' "$C" "$SHARE"
    done <"$TMP_CREATORS"
  fi
  printf '},"expected_share_each_milli":%s,' "$EXPECTED_SHARE_EACH_MILLI"
  printf '"chi_squared":%s,"chi_squared_rate":%s,' "$CHI2_CREATOR" "$CHI2_RATE"
  printf '"p_value":%s,"p_value_rate":%s,' "$P_CREATOR" "$P_RATE"
  printf '"dof_creator":%s,' "$DOF_CREATOR"
  printf '"max_share_bps":%s,"top_creator":"%s",' "$MAX_SHARE_BPS" "$TOP_CREATOR"
  printf '"empty_creators_jackpot":%s,' "$EMPTY_CREATORS_JACKPOT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_subsidy_lottery_audit: no anomalies (port $PORT, window [$FROM..$TO], LOTTERY M=$MULT)"
  else
    echo "=== Subsidy lottery audit (port $PORT, window [$FROM..$TO], LOTTERY mode) ==="
    echo "Mode source             : $MODE_SOURCE"
    echo "Jackpot multiplier (M)  : $MULT"
    echo "Theoretical hit rate    : $(render_pct_bps "$THEORETICAL_RATE_BPS")   (= 1/M)"
    echo "Observed jackpot blocks : $JACKPOT_BLOCKS / $TOTAL_BLOCKS  (expected ~$EXPECTED_JACKPOT_BLOCKS)"
    echo "Distinct creators       : $DISTINCT_CREATORS"
    if [ "$DISTINCT_CREATORS" -gt 0 ]; then
      THEO_PER_CREATOR_BPS=$(( 10000 / DISTINCT_CREATORS ))
      echo "Theoretical win rate    : $(render_pct_bps "$THEO_PER_CREATOR_BPS") per creator  (= 1/N over N=$DISTINCT_CREATORS)"
    fi
    if [ "$ANOM_ONLY" != "1" ] && [ "$DISTINCT_CREATORS" -gt 0 ]; then
      echo
      echo "Observed wins:"
      while IFS=$'\t' read -r C HITS SHARE; do
        if [ "$TOTAL_SHARE_MILLI" -gt 0 ]; then
          PCT_MILLI=$(( SHARE * 1000 / TOTAL_SHARE_MILLI ))
        else
          PCT_MILLI=0
        fi
        # Expected per-creator hits ≈ JACKPOT_BLOCKS / DISTINCT_CREATORS
        # (assumes uniform creator membership; under K-of-K committees
        # with rotating membership this is the natural null hypothesis).
        EXP_HITS=$(awk -v j="$JACKPOT_BLOCKS" -v n="$DISTINCT_CREATORS" \
                       'BEGIN { if (n+0 > 0) printf "%.1f", (j+0)/(n+0); else printf "0.0" }')
        printf "  %-28s : %s (%s)  expected %s\n" "$C" "$HITS" "$(render_pct_milli "$PCT_MILLI")" "$EXP_HITS"
      done <"$TMP_CREATORS"
    fi
    echo
    echo "Chi-squared (jackpot rate, 1 d.f.) : $CHI2_RATE   ($(render_p_band "$P_RATE"))"
    echo "Chi-squared ($DOF_CREATOR d.f.)               : $CHI2_CREATOR   ($(render_p_band "$P_CREATOR"))"
    if [ "$EMPTY_CREATORS_JACKPOT" -gt 0 ]; then
      echo "Jackpot blocks with no creators    : $EMPTY_CREATORS_JACKPOT  (apply-side paid nothing)"
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] Lottery distribution within fairness bounds"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 9: exit-code policy ─────────────────────────────────────────────────
# Same convention as operator_subsidy_audit: exit 2 only when
# --anomalies-only is set AND at least one anomaly fired. Default
# informational mode always exits 0 if the audit ran.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
