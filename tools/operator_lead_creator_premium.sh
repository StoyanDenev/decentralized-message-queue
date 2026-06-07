#!/usr/bin/env bash
# operator_lead_creator_premium.sh — Audit the LEAD-CREATOR (position-0)
# reward premium over a window of finalized blocks. Answers a recipient-side
# question none of the existing fee/subsidy tools answer:
#
#   "Within each block's creator list, position 0 is privileged: the apply
#    algorithm credits the integer-division REMAINDER (the dust left over
#    after the equal split of fees + subsidy) EXCLUSIVELY to creators[0].
#    Which validator repeatedly lands in that privileged lead slot, how
#    concentrated is lead-slot occupancy, and how large is the cumulative
#    remainder/dust premium that flows to lead creators on top of their
#    equal share?"
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# The apply-side credit rule in chain.cpp::apply_block (verified at
# src/chain/chain.cpp:1286-1305) is:
#
#     total_distributed = total_fees + subsidy_this_block        (line 1279-1285)
#     per_creator       = total_distributed / m                  (line 1288)
#     remainder         = total_distributed % m                  (line 1289)
#     for domain in creators:  balance[domain] += per_creator    (line 1290-1297)
#     balance[creators[0]] += remainder                          (line 1299-1304)
#
# So creators[0] — the FIRST entry of the ordered creator list (preserved
# in Block::to_json as the `creators` JSON array, src/chain/block.cpp:377-379)
# — receives an EXTRA `remainder` credit beyond its equal `per_creator`
# share, every block where total_distributed % m != 0. The existing
# recipient-side tools all treat creator positions symmetrically and never
# isolate this position-0 privilege:
#
#   operator_fee_distribution_audit.sh   total fee SHARE per creator
#                                        (equal-split attribution; folds the
#                                        remainder into creators[0]'s total
#                                        but never reports it as a separate
#                                        position-0 premium).
#   operator_subsidy_audit.sh            total subsidy SHARE per creator
#                                        (same equal-split + remainder fold).
#   operator_reward_budget.sh            fee-vs-subsidy income MIX (coverage
#                                        ratio); position-blind.
#   operator_block_creator_fairness.sh   chi-squared on MEMBERSHIP anywhere
#                                        in creators[] (selection lottery);
#                                        does NOT distinguish position 0.
#
# This tool isolates the position-0 angle: lead-slot occupancy count per
# validator, the Herfindahl-Hirschman concentration index of lead-slot
# occupancy, the top lead creator's share, and the cumulative remainder/dust
# premium (the extra value position 0 captured beyond an equal split). On a
# healthy fork-free chain the lead slot should rotate roughly uniformly with
# committee membership; persistent lead-slot capture by one domain is a
# selection-ordering or favoritism signal, and a large premium concentration
# means real value (not just selection frequency) is flowing to that slot.
#
# ── Premium attribution (mirrors chain.cpp::apply_block) ──────────────────────
# Per block with creator count m = len(creators) and
#   block_total = Σ tx.fee  (+ optional --block-subsidy basis if creators
#                            non-empty; default 0 — fees only, since there is
#                            no per-block subsidy RPC; see the subsidy note):
#     remainder = block_total % m       → credited to creators[0]
#   The lead creator at creators[0] accrues:
#     lead_occupancy[creators[0]] += 1
#     lead_premium[creators[0]]   += remainder
#
# fee total is a best-effort UPPER BOUND identical to
# operator_fee_distribution_audit.sh: silent-skip txs (FA-Apply-6 T-F2)
# appear in transactions[] but may not reach the total_fees credit line, and
# no RPC exposes the apply-time success bitmap. The remainder is therefore an
# upper bound too; the OCCUPANCY counts are exact (position 0 is read
# directly from the ordered creators array).
#
# ── Subsidy basis (optional) ──────────────────────────────────────────────────
# By default the premium is computed over FEES ONLY (block_total = Σ tx.fee),
# because the actual total_distributed the chain divided also folded in
# subsidy_this_block, and there is no per-block subsidy RPC. Operators who
# know their FLAT per-block subsidy (genesis block_subsidy) can pass
# --block-subsidy V to fold it into block_total so the remainder matches the
# real apply-time remainder exactly. Mirrors the --block-subsidy precedence
# in operator_reward_budget.sh / operator_subsidy_audit.sh.
#
# Read-only RPC composition; safe against a running daemon. One block-info
# round-trip per block in the window.
#
# Usage:
#   tools/operator_lead_creator_premium.sh [--rpc-port N] [--json]
#                                          [--from H] [--to H] [--last N]
#                                          [--block-subsidy V]
#                                          [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of window (inclusive; default: max(0, tip-1000))
#   --to H              End of window (inclusive; default: tip)
#   --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
#   --block-subsidy V   Per-block FLAT subsidy basis folded into block_total
#                       so the remainder matches the real apply-time value
#                       (default: 0 — fees-only premium)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head      (--field height)        current chain height (cmd_head,
#                                        src/main.cpp:2692; status RPC)
#   - block-info <h> --json             per-block creators[] + transactions[]
#                                        (cmd_block_info, src/main.cpp:2791;
#                                        block RPC → Block::to_json)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   lead_occupancy_concentrated  one validator held the lead (position-0)
#                                slot in > 50% of fee-bearing blocks (a
#                                rotating committee should spread the lead
#                                slot; > 50% capture by one domain is a
#                                selection-ordering / favoritism signal).
#   lead_hhi_high                Herfindahl-Hirschman index of lead-slot
#                                occupancy > 5000 (bps²-scaled to 0..10000;
#                                5000 ≈ effective lead-pool of 2 — too few
#                                distinct lead creators).
#   premium_concentrated         the top lead creator captured > 50% of the
#                                total remainder/dust premium in the window
#                                (real value, not just frequency, flowing to
#                                one privileged slot).
#
# Exit codes (mirrors operator_fee_distribution_audit / operator_reward_budget):
#   0   audit ran successfully, no anomalies (or default informational mode);
#       also the clean-SKIP path when the daemon is unreachable or the chain
#       has no produced blocks
#   1   RPC error after a reachable head / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_lead_creator_premium.sh [--rpc-port N] [--json]
                                        [--from H] [--to H] [--last N]
                                        [--block-subsidy V]
                                        [--anomalies-only]

Audit the LEAD-CREATOR (position-0) reward premium over a window of blocks.
The apply algorithm credits the integer-division remainder of each block's
(fees + subsidy) split EXCLUSIVELY to creators[0] — the first entry of the
ordered creator list. This tool isolates that privileged slot: who holds it,
how concentrated lead-slot occupancy is (HHI + top-1 share), and the
cumulative remainder/dust premium flowing to lead creators on top of the
equal split.

Distinct from operator_fee_distribution_audit.sh / operator_subsidy_audit.sh
(total per-creator SHARE; position-blind) and operator_block_creator_fairness.sh
(chi-squared on MEMBERSHIP anywhere in creators[]; not position 0).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of window (default: max(0, tip-1000))
  --to H              End of window (default: tip)
  --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
  --block-subsidy V   Per-block FLAT subsidy folded into block_total so the
                      remainder matches real apply-time value (default 0)
  --anomalies-only    Print only anomalies; exit 2 if any fire
  -h, --help          Show this help

RPC dependencies (read-only): head, block-info.

Anomaly flags:
  lead_occupancy_concentrated  one validator held lead in > 50% of blocks
  lead_hhi_high                lead-slot HHI > 5000 (effective pool < ~2)
  premium_concentrated         top lead creator > 50% of remainder premium

Exit codes:
  0   success / informational / clean SKIP (daemon down or no blocks)
  1   RPC error after reachable head / bad args / malformed response
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
BLOCK_SUBSIDY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";          shift 2 ;;
    --json)            JSON_OUT=1;             shift ;;
    --from)            FROM_H="${2:-}";        shift 2 ;;
    --to)              TO_H="${2:-}";          shift 2 ;;
    --last)            LAST_N="${2:-}";        shift 2 ;;
    --block-subsidy)   BLOCK_SUBSIDY="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;            shift ;;
    *) echo "operator_lead_creator_premium: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_lead_creator_premium: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N" "$BLOCK_SUBSIDY"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_lead_creator_premium: --from / --to / --last / --block-subsidy must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_lead_creator_premium: --last cannot be combined with --from / --to" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_reward_budget.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# SKIP (exit 0 + INFO) when the daemon is unreachable, matching the clean-skip
# contract: an operator running this in a health loop against a not-yet-started
# node must not see a hard failure.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" = "1" ]; then
    echo '{"skipped":true,"reason":"daemon unreachable","rpc_port":'"$PORT"'}'
  else
    echo "operator_lead_creator_premium: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  fi
  exit 0
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_lead_creator_premium: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    echo '{"skipped":true,"reason":"no produced blocks","head_height":'"$HEAD_H"',"rpc_port":'"$PORT"'}'
  else
    echo "operator_lead_creator_premium: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  fi
  exit 0
fi

# ── Step 2: resolve window bounds ─────────────────────────────────────────────
# `head --field height` returns total block count (block 0 = genesis; highest
# valid index = height - 1). Mirrors operator_reward_budget.sh index semantics.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then LAST_N=1; fi
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_lead_creator_premium: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk the window (JSON parse + position-0 aggregation) ─────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_lead_creator_premium: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$BLOCK_SUBSIDY" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, block_subsidy, out_path = sys.argv[1:7]
from_h        = int(from_h)
to_h          = int(to_h)
block_subsidy = int(block_subsidy)

# Per-lead-creator state. lead_occupancy[c] = # blocks where c was creators[0]
# (over blocks that paid a non-zero total). lead_premium[c] = Σ remainder
# credited to c at position 0.
lead_occupancy = defaultdict(int)
lead_premium   = defaultdict(int)

distributing_blocks = 0   # blocks with non-empty creators AND total > 0
empty_blocks        = 0   # blocks with zero creators (no credit loop)
zero_total_blocks   = 0   # non-empty creators but total == 0 (no remainder)
total_premium       = 0   # Σ remainder over the window
total_distributed   = 0   # Σ block_total over distributing blocks (cross-check)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_lead_creator_premium: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_lead_creator_premium: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_lead_creator_premium: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    if len(creators) == 0:
        empty_blocks += 1
        continue

    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []

    # Per-block fee total (best-effort upper bound; FA-Apply-6 T-F2). Negative
    # / bool guard mirrors operator_fee_distribution_audit.sh.
    block_fees = 0
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        f = tx.get("fee", 0)
        if isinstance(f, bool):
            continue
        if isinstance(f, (int, float)) and f > 0:
            block_fees += int(f)

    # block_total mirrors total_distributed = fees + subsidy_this_block.
    # subsidy basis is operator-supplied (FLAT) or omitted (fees-only).
    block_total = block_fees + (block_subsidy if block_subsidy > 0 else 0)
    if block_total <= 0:
        zero_total_blocks += 1
        continue

    m = len(creators)
    remainder = block_total % m
    lead = creators[0]
    if not isinstance(lead, str):
        # Defensive: a non-string position-0 entry would indicate JSON
        # corruption; skip its premium but don't crash.
        continue
    distributing_blocks += 1
    total_distributed   += block_total
    lead_occupancy[lead] += 1
    lead_premium[lead]   += remainder
    total_premium        += remainder

# Per-lead-creator ledger sorted by occupancy desc, then premium desc, then
# name asc (stable, deterministic — mirrors sibling emission order).
rows = sorted(
    lead_occupancy.keys(),
    key=lambda c: (-lead_occupancy[c], -lead_premium[c], c)
)
per_lead = [
    {
        "creator":        c,
        "lead_occupancy": lead_occupancy[c],
        "lead_premium":   lead_premium[c],
        "occupancy_bps":  (lead_occupancy[c] * 10000 // distributing_blocks)
                           if distributing_blocks > 0 else 0,
        "premium_bps":    (lead_premium[c] * 10000 // total_premium)
                           if total_premium > 0 else 0,
    }
    for c in rows
]

distinct_leads = len(lead_occupancy)

# Top-1 lead occupancy share (frequency) + top-1 premium share (value).
top_lead          = per_lead[0]["creator"]       if per_lead else ""
top_occupancy_bps = per_lead[0]["occupancy_bps"] if per_lead else 0
# The premium leader may differ from the occupancy leader; report both.
prem_sorted = sorted(per_lead, key=lambda row: (-row["lead_premium"], row["creator"]))
top_premium_creator = prem_sorted[0]["creator"]     if prem_sorted else ""
top_premium_bps     = prem_sorted[0]["premium_bps"] if prem_sorted else 0

# Herfindahl-Hirschman index of lead-slot OCCUPANCY. Each share s_c is the
# fraction of distributing blocks where c led; HHI = Σ s_c². We compute it in
# (bps)² space then rescale to 0..10000 so 10000 == single lead creator and a
# perfectly uniform L-lead pool == 10000 / L.
hhi_bps = 0
if distributing_blocks > 0:
    acc = 0
    for c in lead_occupancy:
        share_bps = lead_occupancy[c] * 10000 // distributing_blocks
        acc += share_bps * share_bps
    # acc is in (bps)² = up to 10000² = 1e8 for a single lead. Rescale to bps.
    hhi_bps = acc // 10000

# Anomaly classification.
anomalies = []
if top_occupancy_bps > 5000:
    anomalies.append("lead_occupancy_concentrated")
if hhi_bps > 5000:
    anomalies.append("lead_hhi_high")
if top_premium_bps > 5000 and total_premium > 0:
    anomalies.append("premium_concentrated")

result = {
    "distinct_leads":        distinct_leads,
    "distributing_blocks":   distributing_blocks,
    "empty_blocks":          empty_blocks,
    "zero_total_blocks":     zero_total_blocks,
    "total_premium":         total_premium,
    "total_distributed":     total_distributed,
    "top_lead":              top_lead,
    "top_occupancy_bps":     top_occupancy_bps,
    "top_premium_creator":   top_premium_creator,
    "top_premium_bps":       top_premium_bps,
    "hhi_bps":               hhi_bps,
    "block_subsidy_basis":   block_subsidy,
    "per_lead":              per_lead,
    "anomalies":             anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_lead_creator_premium: block-walk failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) ─────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$HEAD_H" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])
head_h     = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

anomalies  = r["anomalies"]
anom_count = len(anomalies)

def render_pct(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "window":              {"from": from_h, "to": to_h, "blocks": win_blocks},
        "distinct_leads":      r["distinct_leads"],
        "distributing_blocks": r["distributing_blocks"],
        "empty_blocks":        r["empty_blocks"],
        "zero_total_blocks":   r["zero_total_blocks"],
        "total_premium":       r["total_premium"],
        "total_distributed":   r["total_distributed"],
        "top_lead":            r["top_lead"],
        "top_occupancy_bps":   r["top_occupancy_bps"],
        "top_premium_creator": r["top_premium_creator"],
        "top_premium_bps":     r["top_premium_bps"],
        "hhi_bps":             r["hhi_bps"],
        "block_subsidy_basis": r["block_subsidy_basis"],
        "per_lead":            r["per_lead"],
        "anomalies":           anomalies,
        "rpc_port":            port,
        "head_height":         head_h,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_lead_creator_premium: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Lead-creator (position-0) premium audit (port {port}, "
      f"window [{from_h}..{to_h}], {win_blocks} blocks) ===")
basis = r["block_subsidy_basis"]
basis_note = f"fees + {basis}/block subsidy" if basis > 0 else "fees only"
print(f"Premium basis: {basis_note}")
print(f"Distributing blocks (non-empty creators, total>0): {r['distributing_blocks']}")
print(f"Empty-creators blocks: {r['empty_blocks']}")
print(f"Zero-total blocks (no remainder): {r['zero_total_blocks']}")
print(f"Distinct lead creators: {r['distinct_leads']}")
print(f"Total remainder/dust premium: {r['total_premium']}")

if r["per_lead"] and not anom_only:
    print()
    print("Per-lead-creator (sorted by lead occupancy desc):")
    rank = 0
    for row in r["per_lead"]:
        rank += 1
        occ = render_pct(row["occupancy_bps"])
        prm = render_pct(row["premium_bps"]) if r["total_premium"] > 0 else "-"
        tag = "  [top-lead]" if rank == 1 else ""
        print(f"  {row['creator']:<28} : lead={row['lead_occupancy']} "
              f"({occ})  premium={row['lead_premium']} ({prm}){tag}")

print()
if r["per_lead"]:
    print(f"Top lead occupancy : {r['top_lead']} ({render_pct(r['top_occupancy_bps'])})")
    print(f"Lead-slot HHI      : {render_pct(r['hhi_bps'])} "
          f"(10000 = single lead; uniform L-pool = 10000/L)")
    if r["total_premium"] > 0:
        print(f"Top premium share  : {r['top_premium_creator']} "
              f"({render_pct(r['top_premium_bps'])})")

print()
if anom_count == 0:
    print("[OK] No lead-slot concentration anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "lead_occupancy_concentrated" in anomalies:
        print(f"  lead_occupancy_concentrated : {r['top_lead']} held lead in "
              f"{render_pct(r['top_occupancy_bps'])} of distributing blocks (> 50%)")
    if "lead_hhi_high" in anomalies:
        print(f"  lead_hhi_high               : lead-slot HHI "
              f"{render_pct(r['hhi_bps'])} (> 5000; effective lead-pool < ~2)")
    if "premium_concentrated" in anomalies:
        print(f"  premium_concentrated        : {r['top_premium_creator']} captured "
              f"{render_pct(r['top_premium_bps'])} of remainder premium (> 50%)")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_lead_creator_premium: render failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# exit 2 only when --anomalies-only is set AND >= 1 anomaly fired. Default
# informational mode always exits 0 if the RPC walk succeeded.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: r = json.load(f)
print(len(r.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
