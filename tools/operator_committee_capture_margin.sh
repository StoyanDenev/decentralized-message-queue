#!/usr/bin/env bash
# operator_committee_capture_margin.sh — Stake-weighted COMMITTEE-CAPTURE
# margin audit for a running determ chain. Answers the consensus-control
# question that the abstract Nakamoto / Gini tools deliberately do NOT:
#
#   "Given THIS chain's actual committee parameters (K = m_creators and
#    the BFT quorum Q), how many of the top-stake validators would have
#    to collude to either (a) finalize a block by themselves [SAFETY
#    capture] or (b) withhold enough seats to deny the quorum and stall
#    liveness [HALT capture]?"
#
# WHY THIS IS A DISTINCT SIGNAL (not a near-duplicate)
#   The sibling stake-decentralization tools measure concentration
#   against ABSTRACT stake fractions or distribution SHAPE:
#     - operator_stake_distribution.sh : Nakamoto coefficient = min #top
#       validators exceeding a flat 1/3 (and 1/2) of total stake, + Gini
#       + a ranked table. The 1/3 cutoff is a generic BFT rule-of-thumb,
#       NOT this chain's enforced quorum.
#     - operator_stake_concentration.sh: Gini + top-1/3/10 share +
#       deciles + min_stake floor Sybil. Also shape-only; no committee
#       parameters enter the math.
#     - operator_validator_committee_share.sh / operator_committee_audit.sh:
#       OBSERVED per-validator slot share over a block window vs.
#       stake-proportional expectation (selection-fairness, FA1). They
#       audit realized selection, not the collusion threshold.
#
#   None of them folds in K (m_creators) or Q (required_block_sigs). This
#   tool projects each validator's stake SHARE onto its EXPECTED committee
#   seat count (share * K, since S-020 hybrid Fisher-Yates samples the
#   K-member committee stake-proportionally per block — see
#   src/crypto/select_m_creators.cpp + SECURITY.md §S-020) and then walks
#   the DESC-sorted seat vector to find the two capture thresholds below.
#   The headline numbers are therefore tied to the chain's REAL safety /
#   liveness gate, not a textbook constant.
#
# THE TWO CAPTURE THRESHOLDS (expected-seat basis)
#   Let K = m_creators (genesis committee-size target) and
#       Q = required_block_sigs(BFT, k_bft) where k_bft = ceil(2K/3) and
#           Q = ceil(2*k_bft/3) (src/node/producer.cpp:541-552). In
#       MUTUAL_DISTRUST (strong) mode Q == K and k_bft == K.
#   Each validator i has expected_seats_i = share_i * K (stake-weighted
#   selection, S-020). Accumulate over the DESC-by-stake list:
#     control_set (SAFETY): smallest #top validators whose cumulative
#                 expected seats >= Q. A coalition this size, if it
#                 captured a full quorum's worth of seats, could finalize
#                 a block without any honest signer — the safety-violation
#                 collusion floor.
#     halt_set    (LIVENESS): smallest #top validators whose cumulative
#                 expected seats > K - Q. Once a coalition controls more
#                 than the slack (K - Q) seats it can, by withholding,
#                 push the remaining honest seats below Q so no quorum
#                 forms — the censorship / liveness-stall floor. (At Q==K,
#                 K-Q==0, so halt_set == 1: any single seat withheld
#                 stalls a strong-mode block — exactly the K-of-K
#                 mutual-distrust property.)
#   Both are computed with EXACT integer arithmetic on basis-point seat
#   shares (no float-equality drift on a tie at exactly Q).
#
# OBSERVABILITY SCOPE (stated honestly in --help)
#   This is a STAKE-PROJECTION audit, not a realized-selection audit. It
#   uses expected seats (share * K), the long-run mean under S-020. The
#   per-block committee is randomized, so a coalition's instantaneous seat
#   count fluctuates around its expectation; this tool reports the
#   steady-state capture floor. For realized per-block seat shares over a
#   window use operator_validator_committee_share.sh instead.
#
# RPC DEPENDENCIES (read-only; safe against a producing chain)
#   - status   one call: height + m_creators (K) + k_block_sigs +
#              node_count. Fields emitted by src/node/node.cpp::rpc_status
#              (node.cpp:2464 height, :2466 node_count, :2469 m_creators,
#              :2470 k_block_sigs). m_creators == cfg_.m_creators (genesis
#              K); k_block_sigs == cfg_.k_block_sigs (strong-mode required
#              sigs; == m_creators for full mutual distrust).
#   - stakes   full validator set: flat JSON array of {rank, domain,
#              stake, active_from, region, ed_pub}, sorted by stake DESC
#              (ties domain ASC). This is `determ stakes --json`, which
#              materializes node.cpp::rpc_validators (node.cpp:2805) and
#              adds the rank field (src/main.cpp::cmd_stakes :2449-2462).
#              Pulled in full (no --top cap): every entry contributes to
#              total_stake and to the cumulative seat walk.
#
# QUORUM-MODE NOTE
#   `status` exposes m_creators and k_block_sigs but NOT the live
#   ConsensusMode, so this tool cannot read whether the chain is currently
#   in BFT-degraded mode. It computes Q under BOTH readings and lets the
#   operator pick via --quorum-mode:
#     strong (default): Q = K (mutual distrust; K-of-K). Matches a chain
#                       running at full committee with k_block_sigs == K.
#     bft             : Q = ceil(2*k_bft/3), k_bft = ceil(2K/3). The
#                       degraded-committee quorum (the smaller floor, so
#                       the more permissive capture thresholds).
#   The --json envelope always reports BOTH q_strong and q_bft so a
#   dashboard never has to re-derive them.
#
# ANOMALY FLAGS (each adds to anomalies[]; --anomalies-only exits 2)
#   control_set_singleton   control_set == 1: a single validator's
#                           expected seats already meet the quorum Q — one
#                           actor can finalize a block alone (safety
#                           breach floor of 1). The most severe
#                           centralization signal.
#   control_set_below       control_set <= --min-capture (default 2):
#                           the safety-collusion floor is at or under the
#                           configured minimum (default flags any chain
#                           where 2 or fewer validators can finalize).
#   halt_set_below          halt_set <= --min-capture: the liveness /
#                           censorship floor is at or under the minimum;
#                           that few validators can stall finalization by
#                           withholding seats.
#   total_stake_zero        sum of stakes == 0 (chain bootstrap or
#                           catastrophic stake loss): capture thresholds
#                           are undefined; the alert IS the value.
#   committee_undersized    eligible-pool / committee target inconsistency:
#                           total_validators < K (cannot even seat a full
#                           committee — capture math degrades to "all of
#                           them"). Informational-severity but surfaced so
#                           the capture numbers aren't read out of context.
#
# USAGE
#   tools/operator_committee_capture_margin.sh --rpc-port N [--json]
#         [--quorum-mode strong|bft] [--min-capture N] [--anomalies-only]
#
# OPTIONS
#   --rpc-port N        RPC port to query (required)
#   --quorum-mode M     Q basis: strong (Q=K, default) or bft (Q=ceil(2*k_bft/3))
#   --min-capture N     Flag control_set/halt_set <= N (default: 2)
#   --json              Emit a structured JSON envelope
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# EXIT CODES
#   0   audit ran; no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND >=1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_capture_margin.sh --rpc-port N [--json]
          [--quorum-mode strong|bft] [--min-capture N] [--anomalies-only]

Stake-weighted committee-capture margin audit for a running determ chain.
Projects each validator's stake share onto its EXPECTED committee seats
(share * K, K = m_creators, under S-020 stake-weighted selection) and
reports the two collusion floors tied to THIS chain's quorum Q:

  control_set (SAFETY)  : min #top-stake validators whose cumulative
                          expected seats >= Q. That many colluding could
                          finalize a block by themselves.
  halt_set (LIVENESS)   : min #top-stake validators whose cumulative
                          expected seats > K - Q. That many colluding
                          could withhold seats and deny the quorum.

Distinct from operator_stake_distribution.sh (abstract 1/3 Nakamoto
coefficient + Gini) and operator_stake_concentration.sh (Gini + top-N
shape): those use flat stake fractions; THIS folds in the chain's real
committee parameters K (m_creators) and Q (required_block_sigs).
Distinct from operator_validator_committee_share.sh, which audits
OBSERVED per-block slot shares over a window; this is a steady-state
stake-projection (expected seats), not a realized-selection audit.

RPCs used (read-only):
  status   height + m_creators (K) + k_block_sigs + node_count
  stakes   full validator -> stake array (sorted by stake DESC)

Options:
  --rpc-port N        RPC port to query (required)
  --quorum-mode M     Q basis: strong (Q=K, default) | bft (Q=ceil(2*k_bft/3))
  --min-capture N     Flag control_set/halt_set <= N (default: 2)
  --json              Emit a structured JSON envelope
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  control_set_singleton   one validator alone meets quorum Q (safety floor 1)
  control_set_below       control_set <= --min-capture
  halt_set_below          halt_set   <= --min-capture
  total_stake_zero        sum of stakes == 0 (bootstrap / catastrophic loss)
  committee_undersized    total_validators < K (cannot seat a full committee)

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
QUORUM_MODE="strong"
MIN_CAPTURE="2"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";        shift 2 ;;
    --quorum-mode)     QUORUM_MODE="${2:-}"; shift 2 ;;
    --min-capture)     MIN_CAPTURE="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    *) echo "operator_committee_capture_margin: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required and must be a positive integer.
case "$PORT" in *[!0-9]*|"")
  echo "operator_committee_capture_margin: --rpc-port is required and must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --quorum-mode is a closed enum.
case "$QUORUM_MODE" in
  strong|bft) : ;;
  *) echo "operator_committee_capture_margin: --quorum-mode must be 'strong' or 'bft' (got '$QUORUM_MODE')" >&2
     exit 1 ;;
esac

# --min-capture must be a non-negative integer.
case "$MIN_CAPTURE" in *[!0-9]*|"")
  echo "operator_committee_capture_margin: --min-capture must be a non-negative integer (got '$MIN_CAPTURE')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: status RPC → height + K + k_block_sigs + node_count ───────────────
# One call carries every committee parameter we need. Unreachable daemon is
# a clean SKIP (exit 0) per the operator-tool contract, NOT a hard error:
# a missing daemon must not turn a cron sweep red.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon unreachable on rpc-port %s"}\n' "$PORT"
  else
    echo "INFO: daemon unreachable on rpc-port $PORT; capture-margin audit SKIP"
  fi
  exit 0
}

# Parse the four fields via Python (robust without jq). Empty/garbage status
# is a malformed-response error (exit 1), distinct from the unreachable SKIP.
PARSED=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
    print(int(j.get('m_creators', 0)))
    print(int(j.get('k_block_sigs', 0)))
    print(int(j.get('node_count', 0)))
except Exception:
    sys.exit(1)
") || {
  echo "operator_committee_capture_margin: malformed status response (port $PORT)" >&2
  exit 1
}
HEAD_H=$(printf '%s\n' "$PARSED" | sed -n '1p')
KVAL=$(printf '%s\n' "$PARSED" | sed -n '2p')
KSIGS=$(printf '%s\n' "$PARSED" | sed -n '3p')
NODE_COUNT=$(printf '%s\n' "$PARSED" | sed -n '4p')
case "$HEAD_H" in *[!0-9]*|"") HEAD_H=0 ;; esac
case "$KVAL"   in *[!0-9]*|"") KVAL=0 ;; esac
case "$KSIGS"  in *[!0-9]*|"") KSIGS=0 ;; esac
case "$NODE_COUNT" in *[!0-9]*|"") NODE_COUNT=0 ;; esac

if [ "$KVAL" -le 0 ]; then
  echo "operator_committee_capture_margin: status reported m_creators=0 (port $PORT); cannot compute capture margins" >&2
  exit 1
fi

# ── Step 2: full stakes list (NO --top cap; the seat walk needs everything) ──
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_capture_margin: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# Stash the stakes payload in a temp file: the metric pass sources its
# program from a heredoc (which consumes stdin), so the JSON travels by an
# argv file path. Same temp-file convention as the sibling stake tools.
TMP_STAKES=$(mktemp 2>/dev/null) || {
  echo "operator_committee_capture_margin: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_committee_capture_margin: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STAKES" "$TMP_OUT" 2>/dev/null' EXIT
printf '%s' "$STAKES_OUT" >"$TMP_STAKES"

# ── Step 3: compute capture margins (Python; POSIX shell can't do this) ──────
python - "$TMP_STAKES" "$TMP_OUT" "$KVAL" "$KSIGS" "$QUORUM_MODE" "$MIN_CAPTURE" "$NODE_COUNT" <<'PY'
import sys, json

stakes_path, out_path, k_s, ksigs_s, qmode, mincap_s, nodecount_s = sys.argv[1:8]
K          = int(k_s)
k_sigs     = int(ksigs_s)
quorum_mode= qmode
min_capture= int(mincap_s)
node_count = int(nodecount_s)

try:
    with open(stakes_path, "r", encoding="utf-8") as f:
        stakes = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_committee_capture_margin: cannot parse stakes JSON: {e}\n")
    sys.exit(1)
if not isinstance(stakes, list):
    sys.stderr.write("operator_committee_capture_margin: stakes RPC is not a JSON array\n")
    sys.exit(1)

# Materialize per-validator records. RPC already returns stake-DESC, ties
# domain-ASC; we re-sort defensively against any future RPC reorder.
validators = []
for v in stakes:
    if not isinstance(v, dict):
        continue
    d = v.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    try:
        s = int(v.get("stake", 0) or 0)
    except Exception:
        s = 0
    if s < 0:
        s = 0
    validators.append({"domain": d, "stake": s})

validators.sort(key=lambda r: (-r["stake"], r["domain"]))
n_validators = len(validators)
total_stake  = sum(v["stake"] for v in validators)

# ── Quorum derivation tied to the chain's real committee math ────────────────
# k_bft = ceil(2K/3); Q_bft = ceil(2*k_bft/3) — mirrors
# src/node/producer.cpp::required_block_sigs (the (2*n+2)/3 integer-ceil
# form). Q_strong = K (MUTUAL_DISTRUST returns committee_size). Selecting
# the active Q by --quorum-mode.
def ceil2_3(n):
    # ceil(2n/3) via integer ceil: (2n + 2) // 3.
    return (2 * n + 2) // 3

k_bft   = ceil2_3(K)
q_bft   = ceil2_3(k_bft)
q_strong= K
Q = q_strong if quorum_mode == "strong" else q_bft

# ── Expected-seat projection (S-020 stake-weighted selection) ────────────────
# expected_seats_i = share_i * K. We work in seat-basis-points so the
# cumulative comparisons are exact integers: seat_bps_i = stake_i * K * 10000
# // total_stake. A full committee is K seats == K*10000 seat-bps. The two
# capture thresholds compare cumulative seat-bps against Q and (K - Q) in the
# same seat-bps units (Q seats == Q*10000 seat-bps).
for v in validators:
    v["seat_bps"] = (v["stake"] * K * 10000 // total_stake) if total_stake > 0 else 0
    v["share_bps"] = (v["stake"] * 10000 // total_stake) if total_stake > 0 else 0

# control_set (SAFETY): smallest #top validators whose cumulative expected
# seats >= Q. Compare cumulative seat-bps >= Q*10000. None if the whole set
# can't reach Q (only possible at total_stake==0, guarded below).
# halt_set (LIVENESS): smallest #top validators whose cumulative expected
# seats > (K - Q). Compare cumulative seat-bps > (K-Q)*10000. At Q==K the
# slack K-Q==0 so the first validator with ANY positive seat share (>0)
# already exceeds it -> halt_set == 1 (the K-of-K withhold-one property).
control_q_bps = Q * 10000
halt_slack_bps = (K - Q) * 10000   # K - Q >= 0 always (Q <= K)

control_set = None
halt_set    = None
if total_stake > 0:
    cum = 0
    for i, v in enumerate(validators, start=1):
        cum += v["seat_bps"]
        if control_set is None and cum >= control_q_bps:
            control_set = i
        if halt_set is None and cum > halt_slack_bps:
            halt_set = i
        if control_set is not None and halt_set is not None:
            break

# ── Anomaly classification ───────────────────────────────────────────────────
anomalies = []
if total_stake == 0:
    anomalies.append("total_stake_zero")
# committee_undersized: cannot even seat a full K-member committee from the
# eligible set. Surfaced so the capture numbers are read in context (when the
# pool is < K the "min validators to capture" question is partly moot).
if n_validators < K:
    anomalies.append("committee_undersized")
if total_stake > 0:
    if control_set == 1:
        anomalies.append("control_set_singleton")
    if control_set is not None and control_set <= min_capture:
        # Avoid double-emitting both singleton and below when control_set==1
        # and min_capture>=1: keep both — singleton is the sharper signal,
        # below is the threshold-gate signal; dashboards may route them
        # independently. They are intentionally separate flags.
        anomalies.append("control_set_below")
    if halt_set is not None and halt_set <= min_capture:
        anomalies.append("halt_set_below")

# Top-of-table for human output: top-N by stake with seat projection.
top_validators = []
for i, v in enumerate(validators[:20], start=1):
    top_validators.append({
        "rank":       i,
        "domain":     v["domain"],
        "stake":      v["stake"],
        "share_bps":  v["share_bps"],
        "seat_bps":   v["seat_bps"],
    })

result = {
    "K_committee":        K,
    "k_block_sigs":       k_sigs,
    "k_bft":              k_bft,
    "q_strong":           q_strong,
    "q_bft":              q_bft,
    "quorum_mode":        quorum_mode,
    "Q_active":           Q,
    "halt_slack_seats":   K - Q,
    "total_validators":   n_validators,
    "node_count":         node_count,
    "total_stake":        total_stake,
    "control_set":        control_set,
    "halt_set":           halt_set,
    "min_capture":        min_capture,
    "top_validators":     top_validators,
    "anomalies":          anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_committee_capture_margin: capture computation failed" >&2
  exit 1
fi

# ── Step 4: render (JSON or human) ───────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
head_h    = int(sys.argv[5])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

K            = r["K_committee"]
k_sigs       = r["k_block_sigs"]
k_bft        = r["k_bft"]
q_strong     = r["q_strong"]
q_bft        = r["q_bft"]
quorum_mode  = r["quorum_mode"]
Q            = r["Q_active"]
halt_slack   = r["halt_slack_seats"]
n_validators = r["total_validators"]
node_count   = r["node_count"]
total_stake  = r["total_stake"]
control_set  = r["control_set"]
halt_set     = r["halt_set"]
min_capture  = r["min_capture"]
top_validators = r["top_validators"]
anomalies    = r["anomalies"]
anom_count   = len(anomalies)

def pct(bps):
    """bps in 0..N → 'XX.X%' (one decimal)."""
    return f"{bps // 100}.{(bps % 100) // 10}%"

def seats(bps):
    """seat-bps → 'X.XX' expected seats (two decimals)."""
    return f"{bps // 10000}.{(bps % 10000) // 100:02d}"

def short(addr):
    if isinstance(addr, str) and len(addr) > 30:
        return addr[:27] + "..."
    return addr

if json_out:
    envelope = {
        "rpc_port":          port,
        "height":            head_h,
        "K_committee":       K,
        "k_block_sigs":      k_sigs,
        "k_bft":             k_bft,
        "q_strong":          q_strong,
        "q_bft":             q_bft,
        "quorum_mode":       quorum_mode,
        "Q_active":          Q,
        "halt_slack_seats":  halt_slack,
        "total_validators":  n_validators,
        "node_count":        node_count,
        "total_stake":       total_stake,
        "control_set":       control_set,
        "halt_set":          halt_set,
        "min_capture":       min_capture,
        "top_validators":    top_validators,
        "anomalies":         anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

if anom_only and anom_count == 0:
    print(f"operator_committee_capture_margin: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Committee-capture margin (port {port}) ===")
print(f"Chain height:        {head_h}")
print(f"Committee K:         {K}  (m_creators; k_block_sigs={k_sigs})")
print(f"BFT k_bft:           {k_bft}  (ceil(2K/3))")
print(f"Quorum Q:            {Q}  (mode={quorum_mode}; q_strong={q_strong}, q_bft={q_bft})")
print(f"Halt slack (K-Q):    {halt_slack} seat(s)")
print(f"Total validators:    {n_validators}  (registry node_count={node_count})")
print(f"Total stake:         {total_stake}")

if total_stake <= 0:
    print("Control set (Q):     n/a (zero total stake)")
    print("Halt set (K-Q):      n/a (zero total stake)")
else:
    cs = "n/a" if control_set is None else str(control_set)
    hs = "n/a" if halt_set is None else str(halt_set)
    print(f"Control set (SAFETY):  {cs} validator(s) to reach expected seats >= Q={Q}")
    print(f"Halt set (LIVENESS):   {hs} validator(s) to exceed slack K-Q={halt_slack}")

if not anom_only and top_validators:
    shown = len(top_validators)
    print(f"Top-{shown} by stake (expected committee seats = share * K):")
    for v in top_validators:
        print(f"  {v['rank']:>2}. {short(v['domain']):<30} "
              f"stake={v['stake']:<14} share={pct(v['share_bps']):>6} "
              f"seats~{seats(v['seat_bps'])}")

print()
if anom_count == 0:
    print("[OK] Committee-capture margins above configured minimum")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "total_stake_zero" in anomalies:
        print("  total_stake_zero       : sum of stakes == 0 (bootstrap / catastrophic loss)")
    if "committee_undersized" in anomalies:
        print(f"  committee_undersized   : {n_validators} validators < K={K} (cannot seat full committee)")
    if "control_set_singleton" in anomalies:
        print(f"  control_set_singleton  : 1 validator's expected seats already meet quorum Q={Q}")
    if "control_set_below" in anomalies:
        print(f"  control_set_below      : control_set={control_set} <= min-capture={min_capture} (safety-collusion floor)")
    if "halt_set_below" in anomalies:
        print(f"  halt_set_below         : halt_set={halt_set} <= min-capture={min_capture} (liveness / censorship floor)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_committee_capture_margin: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
# exit 2 only when --anomalies-only is set AND >=1 anomaly fired. Default
# informational mode always exits 0 on a healthy RPC pipeline.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
print(len(r.get("anomalies", [])))
PY
)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
