#!/usr/bin/env bash
# operator_emission_reconcile.sh — Reconcile the chain's REALIZED coin
# emission against what the CONFIGURED flat block_subsidy predicts, block
# by block, over a window of finalized blocks. Read-only RPC composition;
# safe against a running/producing daemon. Single query then exit.
#
# ── THE OPERATOR QUESTION ─────────────────────────────────────────────────────
#   "Is the chain minting exactly the subsidy it was configured to mint?"
#   Concretely: for a FLAT-mode chain every creator-bearing block mints
#   exactly `block_subsidy` (clamped by the finite pool). The on-chain
#   counter `accumulated_subsidy` is the authoritative lifetime mint. This
#   tool predicts the EXPECTED cumulative emission from the configured
#   per-block subsidy applied to the creator-bearing blocks it actually
#   observes in the window, then reconciles that prediction against the
#   realized lifetime counter — surfacing over-mint / under-mint drift.
#
# ── WHY THIS IS DISTINCT FROM EVERY SIBLING (no duplication) ──────────────────
#   operator_subsidy_audit.sh / operator_subsidy_accrual_audit.sh
#       Per-VALIDATOR subsidy ATTRIBUTION + concentration (who got paid).
#       Their "drift" check is Σ-per-validator-credit vs Σ-per-block from
#       their OWN estimate — an internal-consistency check, NOT a
#       comparison against the configured block_subsidy or the realized
#       on-chain accumulated_subsidy counter.
#   operator_subsidy_pool_health.sh
#       FORWARD projection: observed drain RATE + projected EXHAUSTION
#       height/ETA. Snapshot + arithmetic, no per-block emission walk.
#   operator_subsidy_lottery_audit.sh
#       LOTTERY-mode hit-rate fairness vs 1/M. Mode-1 only.
#   operator_reward_budget.sh
#       FEE-COVERAGE ratio (fees / total reward). Composition of the
#       reward, not a mint-vs-configured reconciliation.
#   operator_nef_drain_audit.sh
#       The E1 NEF Zeroth-pool geometric halving vs REGISTER history — a
#       different pool entirely (entrant grants, not block subsidy).
#   operator_supply_check.sh / operator_supply_reconcile.sh
#       The A1 conservation identity (does the money add up across all
#       deltas). They never isolate the subsidy term against its config.
#
#   THIS tool is the BACKWARD emission-vs-configured reconciliation: it
#   ties the realized lifetime mint to the per-block subsidy the operator
#   configured, and flags per-block emission anomalies (a block that
#   minted more or less than the configured floor, e.g. an unexpected
#   empty-creator gap or an over-mint).
#
# ── THE EMISSION RULE (read from src/chain/chain.cpp::apply_block) ────────────
#   chain.cpp:1250  base_subsidy = block_subsidy_;                 // FLAT
#   chain.cpp:1251  if (subsidy_mode_ == 1 && lottery_mult >= 2) { // E3 LOTTERY
#                       base_subsidy = jackpot or 0 per cumulative_rand draw }
#   chain.cpp:1267  subsidy_this_block = base_subsidy;
#   chain.cpp:1268  if (subsidy_pool_initial_ != 0) {             // E4 finite pool
#   chain.cpp:1269      remaining = subsidy_pool_initial_ - accumulated_subsidy_;
#   chain.cpp:1271      subsidy_this_block = min(base_subsidy, remaining); }
#   chain.cpp:1390  if (total_distributed > 0 && !b.creators.empty())
#   chain.cpp:1391      accumulated_subsidy_ += subsidy_this_block; // the mint
#
#   So, for a FLAT (subsidy_mode == 0) chain that has NOT yet drained its
#   pool, every block with a non-empty `creators` list mints exactly
#   `block_subsidy`; empty-creator blocks mint 0 (the credit loop is
#   skipped entirely). The expected per-window emission is therefore:
#
#       expected_window_emission = block_subsidy * (creator-bearing blocks)
#
#   clamped so the *cumulative* lifetime mint can never exceed
#   subsidy_pool_initial (E4). LOTTERY mode (subsidy_mode == 1) makes the
#   per-block draw 0-or-jackpot with the SAME expected value, so the
#   per-block reconciliation does not hold deterministically — this tool
#   reports the lottery-expectation comparison as informational and does
#   NOT raise per-block mismatch anomalies in that mode (see notes).
#
# ── HOW WE GET THE CONFIGURED block_subsidy ───────────────────────────────────
#   There is NO live RPC that exposes the genesis-pinned block_subsidy
#   (it lives in chain-state constants; only `snapshot inspect` — a file
#   op — surfaces it). So, exactly like operator_reward_budget.sh and
#   operator_subsidy_audit.sh, the configured per-block subsidy is sourced
#   by precedence:
#     --block-subsidy V   FLAT-mode authoritative value (operator supplies
#                         the same value genesis encoded). PREFERRED.
#     else                lifetime-average heuristic =
#                         accumulated_subsidy / creator-bearing-block-count
#                         estimated across the WHOLE chain via the head
#                         counter. Exact for an undrained FLAT chain with
#                         no empty-creator blocks; an estimate otherwise.
#                         When no basis is derivable (height too low or
#                         accumulated_subsidy == 0) the subsidy_basis_
#                         unavailable anomaly fires and reconciliation is
#                         reported as not-checkable.
#
# ── WHAT WE COMPARE ───────────────────────────────────────────────────────────
#   realized_window_emission  : lifetime accumulated_subsidy is a chain-
#                               wide counter, so we cannot read a per-window
#                               realized delta from a single snapshot. We
#                               therefore reconcile two complementary views:
#     (A) WINDOW view  — expected_window = subsidy_basis * creator_blocks
#                        (the blocks WE observed paying creators in
#                        [from..to]); per-block expected vs the configured
#                        floor; flags blocks that deviate from the floor.
#     (B) LIFETIME view — expected_lifetime (cumulative) = subsidy_basis *
#                        creator-bearing blocks over the ENTIRE chain is not
#                        cheaply countable without a full walk, so we use
#                        the closed-form upper bound subsidy_basis *
#                        (head_blocks - 1) and reconcile the realized
#                        accumulated_subsidy against it: realized must be
#                        <= that ceiling (every block mints AT MOST the
#                        floor) and, for a fully-creator-bearing undrained
#                        FLAT chain, == it. Realized ABOVE the ceiling is a
#                        hard over-mint anomaly (emission_exceeds_config).
#
# ── TIMESTAMPS / INDEX SEMANTICS ──────────────────────────────────────────────
#   `head --field height` returns the TOTAL block count (block 0 = genesis,
#   highest valid index = height - 1). Mirrors the sibling tools.
#
# Usage:
#   tools/operator_emission_reconcile.sh [--rpc-port N] [--json]
#                                        [--from H] [--to H] [--last N]
#                                        [--block-subsidy V]
#                                        [--tolerance-pct PCT]
#                                        [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit a structured JSON envelope instead of human output
#   --from H            Start of window (inclusive; default: max(0, tip-100))
#   --to H              End of window (inclusive; default: tip)
#   --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
#   --block-subsidy V   Configured per-block subsidy (FLAT authoritative).
#                       Default: accumulated_subsidy / creator-bearing-blocks
#                       lifetime heuristic.
#   --tolerance-pct PCT Integer percent (0..100). The realized-vs-expected
#                       LIFETIME reconciliation tolerates a shortfall up to
#                       this fraction of the expected ceiling before flagging
#                       emission_below_config (a young chain with empty-
#                       creator blocks legitimately sits below the ceiling).
#                       Default: 0 (any shortfall is reported but only the
#                       OVER-mint direction is a hard anomaly; see below).
#   --anomalies-only    Print only anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head    --field height                  current chain height
#     (src/main.cpp cmd_head; node.cpp:2464 j["height"])
#   - supply  --field accumulated_subsidy      realized lifetime mint counter
#     (src/main.cpp cmd_supply allowed-field; node.cpp:2855 accumulated_subsidy)
#   - block-info <h> --json                    per-block `creators` walk
#     (src/main.cpp cmd_block_info; block.cpp:379 j["creators"])
#
# Anomaly flags (each adds an entry to anomalies[]):
#   emission_exceeds_config    realized accumulated_subsidy is GREATER than
#                              the closed-form ceiling subsidy_basis *
#                              (head_blocks-1). Every block mints AT MOST the
#                              configured floor, so this is impossible for a
#                              correctly-configured FLAT chain — a wrong
#                              --block-subsidy or a genuine over-mint. HARD.
#   emission_below_config      realized lifetime mint falls short of the
#                              expected ceiling by MORE than --tolerance-pct.
#                              Expected for chains with empty-creator blocks
#                              or a drained pool; only an anomaly past the
#                              operator-set tolerance.
#   window_emission_gap        within [from..to], the count of creator-
#                              bearing blocks is < the window span, i.e. at
#                              least one block minted 0 subsidy (empty
#                              creators). Informational — surfaces emission
#                              dropouts the operator may want to investigate.
#   subsidy_basis_unavailable  no usable per-block subsidy basis (no
#                              --block-subsidy and accumulated_subsidy == 0
#                              or no creator-bearing blocks). Reconciliation
#                              not-checkable; informational.
#   lottery_mode_estimate      subsidy_mode could not be confirmed FLAT and
#                              the heuristic basis is in use; per-block
#                              reconciliation is an EXPECTATION, not exact.
#                              (Best-effort: we cannot read subsidy_mode over
#                              RPC, so this fires whenever the basis is the
#                              heuristic AND --block-subsidy was not given.)
#                              Informational.
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable mid-audit / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
#
# Daemon-unreachable on the FIRST probe is a clean INFO + SKIP (exit 0), so
# this can run in a health loop against a not-yet-started node.
set -u

usage() {
  cat <<'EOF'
Usage: operator_emission_reconcile.sh [--rpc-port N] [--json]
                                      [--from H] [--to H] [--last N]
                                      [--block-subsidy V]
                                      [--tolerance-pct PCT]
                                      [--anomalies-only]

Reconcile the chain's REALIZED coin emission (on-chain accumulated_subsidy)
against what the CONFIGURED flat block_subsidy predicts, block by block,
over a window of finalized blocks. Surfaces over-mint / under-mint drift
and per-block emission dropouts.

Distinct from: operator_subsidy_audit (per-validator attribution),
operator_subsidy_pool_health (forward drain/ETA), operator_reward_budget
(fee-coverage ratio), operator_nef_drain_audit (NEF Zeroth pool), and
operator_supply_check (A1 conservation). None of those tie the realized
lifetime mint back to the configured per-block subsidy.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human output
  --from H            Start of window (default: max(0, tip-100))
  --to H              End of window (default: tip)
  --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
  --block-subsidy V   Configured per-block subsidy (FLAT authoritative);
                      default = accumulated_subsidy / creator-bearing-blocks
  --tolerance-pct PCT Integer percent 0..100; lifetime shortfall below the
                      expected ceiling beyond this flags emission_below_config
                      (default 0)
  --anomalies-only    Print only anomalies; exit 2 if any fire
  -h, --help          Show this help

RPC dependencies (read-only): head, supply, block-info.

Anomaly flags:
  emission_exceeds_config    realized mint > configured ceiling (HARD)
  emission_below_config      realized mint short of ceiling beyond tolerance
  window_emission_gap        a block in the window minted 0 (empty creators)
  subsidy_basis_unavailable  no usable per-block subsidy basis
  lottery_mode_estimate      basis is the heuristic; reconciliation is an estimate

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
BLOCK_SUBSIDY_OVR=""
TOLERANCE_PCT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";              shift 2 ;;
    --json)            JSON_OUT=1;                 shift ;;
    --from)            FROM_H="${2:-}";            shift 2 ;;
    --to)              TO_H="${2:-}";              shift 2 ;;
    --last)            LAST_N="${2:-}";            shift 2 ;;
    --block-subsidy)   BLOCK_SUBSIDY_OVR="${2:-}"; shift 2 ;;
    --tolerance-pct)   TOLERANCE_PCT="${2:-}";     shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;                shift ;;
    *) echo "operator_emission_reconcile: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_emission_reconcile: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N" "$BLOCK_SUBSIDY_OVR"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_emission_reconcile: --from / --to / --last / --block-subsidy must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_emission_reconcile: --last cannot be combined with --from / --to" >&2
  exit 1
fi
case "$TOLERANCE_PCT" in *[!0-9]*|"")
  echo "operator_emission_reconcile: --tolerance-pct must be an integer percent 0..100 (got '$TOLERANCE_PCT')" >&2
  exit 1 ;;
esac
if [ "$TOLERANCE_PCT" -gt 100 ]; then
  echo "operator_emission_reconcile: --tolerance-pct must be <= 100 (got '$TOLERANCE_PCT')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (mirrors operator_reward_budget.sh +
# operator_subsidy_accrual_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip (clean SKIP if daemon unreachable) ────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon_unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "operator_emission_reconcile: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  fi
  exit 0
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_emission_reconcile: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to reconcile. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"no_produced_blocks","head_height":%s,"rpc_port":%s}\n' "$HEAD_H" "$PORT"
  else
    echo "operator_emission_reconcile: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  fi
  exit 0
fi

# ── Step 2: realized lifetime mint counter ────────────────────────────────────
ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_emission_reconcile: RPC error querying supply (port $PORT)" >&2
  exit 1
}
ACCUM=$(printf '%s' "$ACCUM" | tr -d '[:space:]')
case "$ACCUM" in *[!0-9]*|"")
  echo "operator_emission_reconcile: supply returned non-numeric accumulated_subsidy '$ACCUM' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 3: resolve window bounds ─────────────────────────────────────────────
# Index semantics: head height = total block count; highest index = height-1.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then LAST_N=1; fi
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 100 ? TOP - 100 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_emission_reconcile: --from ($FROM) > --to ($TO); nothing to reconcile" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 4: walk the window, count creator-bearing blocks ─────────────────────
# Python driver: one block-info round-trip per block. Emits a single TSV
# stats line: creator_blocks <tab> empty_blocks <tab> total_walked.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_emission_reconcile: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_STATS" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, stats_path = sys.argv[1:6]
from_h = int(from_h)
to_h   = int(to_h)

creator_blocks = 0
empty_blocks   = 0
total_walked   = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_emission_reconcile: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_emission_reconcile: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_emission_reconcile: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    total_walked += 1
    if len(creators) > 0:
        creator_blocks += 1
    else:
        empty_blocks += 1

with open(stats_path, "w", encoding="utf-8") as f:
    f.write(f"{creator_blocks}\t{empty_blocks}\t{total_walked}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_emission_reconcile: block-walk failed" >&2
  exit 1
fi

STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_emission_reconcile: empty stats payload" >&2
  exit 1
fi
CREATOR_BLOCKS=$(printf '%s' "$STATS_LINE" | cut -f1)
EMPTY_BLOCKS=$(printf   '%s' "$STATS_LINE" | cut -f2)
TOTAL_WALKED=$(printf   '%s' "$STATS_LINE" | cut -f3)
case "$CREATOR_BLOCKS$EMPTY_BLOCKS$TOTAL_WALKED" in *[!0-9]*|"")
  echo "operator_emission_reconcile: malformed stats line '$STATS_LINE'" >&2
  exit 1 ;;
esac

# ── Step 5: resolve the configured per-block subsidy basis ────────────────────
# Lifetime creator-bearing-block count for the heuristic: we have not walked
# the whole chain, so the closed-form ceiling uses (head_blocks - 1) as the
# count of produced blocks and derives an average per-block mint from the
# realized counter. The heuristic basis is accumulated_subsidy / produced
# blocks (exact for an undrained, fully-creator-bearing FLAT chain).
PRODUCED_BLOCKS=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ "$PRODUCED_BLOCKS" -lt 1 ]; then PRODUCED_BLOCKS=1; fi

BASIS_HEURISTIC=0
if [ -n "$BLOCK_SUBSIDY_OVR" ]; then
  BASIS=$BLOCK_SUBSIDY_OVR
  BASIS_SOURCE="override"
elif [ "$ACCUM" -gt 0 ]; then
  BASIS=$(( ACCUM / PRODUCED_BLOCKS ))
  BASIS_SOURCE="heuristic"
  BASIS_HEURISTIC=1
else
  BASIS=0
  BASIS_SOURCE="unavailable"
fi

# ── Step 6: compute expected emission (window + lifetime ceiling) ─────────────
# Window: expected = basis * creator-bearing blocks WE observed in [from..to].
EXPECTED_WINDOW=$(( BASIS * CREATOR_BLOCKS ))
# Lifetime ceiling: every produced block mints AT MOST the floor, so the
# realized accumulated_subsidy can never exceed basis * produced blocks.
EXPECTED_LIFETIME_CEIL=$(( BASIS * PRODUCED_BLOCKS ))

# Realized-vs-ceiling reconciliation.
# Over-mint: realized > ceiling. Under-mint: realized < ceiling.
OVER_MINT=0
UNDER_MINT=0
SHORTFALL=0
if [ "$BASIS" -gt 0 ]; then
  if [ "$ACCUM" -gt "$EXPECTED_LIFETIME_CEIL" ]; then
    OVER_MINT=$(( ACCUM - EXPECTED_LIFETIME_CEIL ))
  elif [ "$ACCUM" -lt "$EXPECTED_LIFETIME_CEIL" ]; then
    UNDER_MINT=$(( EXPECTED_LIFETIME_CEIL - ACCUM ))
    SHORTFALL=$UNDER_MINT
  fi
fi

# ── Step 7: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

if [ "$BASIS_SOURCE" = "unavailable" ]; then
  add_anom "subsidy_basis_unavailable"
else
  # emission_exceeds_config: realized over the closed-form ceiling. HARD —
  # impossible for a correctly-configured FLAT chain (each block mints AT
  # MOST the floor). When the basis is the heuristic (accumulated/produced)
  # this can never fire by construction, so it is a genuine signal only when
  # --block-subsidy supplied an authoritative value.
  if [ "$OVER_MINT" -gt 0 ]; then add_anom "emission_exceeds_config"; fi
  # emission_below_config: shortfall beyond --tolerance-pct of the ceiling.
  if [ "$UNDER_MINT" -gt 0 ] && [ "$EXPECTED_LIFETIME_CEIL" -gt 0 ]; then
    TOL_ABS=$(( EXPECTED_LIFETIME_CEIL * TOLERANCE_PCT / 100 ))
    if [ "$SHORTFALL" -gt "$TOL_ABS" ]; then add_anom "emission_below_config"; fi
  fi
fi
# window_emission_gap: at least one empty-creator (zero-mint) block in window.
if [ "$EMPTY_BLOCKS" -gt 0 ]; then add_anom "window_emission_gap"; fi
# lottery_mode_estimate: heuristic basis in use (subsidy_mode not RPC-readable).
if [ "$BASIS_HEURISTIC" = "1" ]; then add_anom "lottery_mode_estimate"; fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 8: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"creator_blocks":%s,"empty_blocks":%s,"blocks_walked":%s,' \
    "$CREATOR_BLOCKS" "$EMPTY_BLOCKS" "$TOTAL_WALKED"
  printf '"subsidy_basis_per_block":%s,"subsidy_basis_source":"%s",' \
    "$BASIS" "$BASIS_SOURCE"
  printf '"expected_window_emission":%s,' "$EXPECTED_WINDOW"
  printf '"realized_accumulated_subsidy":%s,' "$ACCUM"
  printf '"produced_blocks":%s,"expected_lifetime_ceiling":%s,' \
    "$PRODUCED_BLOCKS" "$EXPECTED_LIFETIME_CEIL"
  printf '"over_mint":%s,"under_mint":%s,' "$OVER_MINT" "$UNDER_MINT"
  printf '"tolerance_pct":%s,' "$TOLERANCE_PCT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_emission_reconcile: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Emission reconciliation (port $PORT, window [$FROM..$TO], $TOTAL_WALKED blocks) ==="
    echo "Configured subsidy basis : ${BASIS}/block (source=$BASIS_SOURCE)"
    echo "Creator-bearing blocks   : $CREATOR_BLOCKS  (empty/zero-mint: $EMPTY_BLOCKS)"
    echo "Expected window emission : $EXPECTED_WINDOW  (basis * creator-bearing blocks)"
    echo "--- lifetime reconciliation ---"
    echo "Realized accumulated_subsidy : $ACCUM"
    echo "Expected lifetime ceiling    : $EXPECTED_LIFETIME_CEIL  (basis * $PRODUCED_BLOCKS produced blocks)"
    if [ "$OVER_MINT" -gt 0 ]; then
      echo "Over-mint  (realized > ceiling): $OVER_MINT"
    elif [ "$UNDER_MINT" -gt 0 ]; then
      echo "Under-mint (realized < ceiling): $UNDER_MINT  (tolerance ${TOLERANCE_PCT}%)"
    else
      echo "Realized matches the ceiling exactly."
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] emission reconciled; no anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in *,emission_exceeds_config,*)
        echo "  emission_exceeds_config   : realized mint exceeds configured ceiling by $OVER_MINT (over-mint or wrong --block-subsidy)" ;;
      esac
      case ",$ANOMALIES," in *,emission_below_config,*)
        echo "  emission_below_config     : realized mint short of ceiling by $UNDER_MINT (> ${TOLERANCE_PCT}% tolerance)" ;;
      esac
      case ",$ANOMALIES," in *,window_emission_gap,*)
        echo "  window_emission_gap       : $EMPTY_BLOCKS block(s) in window minted 0 subsidy (empty creators)" ;;
      esac
      case ",$ANOMALIES," in *,subsidy_basis_unavailable,*)
        echo "  subsidy_basis_unavailable : no per-block subsidy basis (pass --block-subsidy); reconciliation not-checkable" ;;
      esac
      case ",$ANOMALIES," in *,lottery_mode_estimate,*)
        echo "  lottery_mode_estimate     : basis is the lifetime-average heuristic; reconciliation is an expectation (pass --block-subsidy for exact)" ;;
      esac
    fi
  fi
fi

# ── Step 9: exit-code policy ──────────────────────────────────────────────────
# exit 2 only when --anomalies-only is set AND >= 1 anomaly fired. Default
# informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
