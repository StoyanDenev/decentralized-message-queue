#!/usr/bin/env bash
# operator_nonce_gap_audit.sh — Per-account ON-CHAIN nonce-gap / stuck-tx
# detector across a finalized block window on a running determ daemon.
#
# Answers the operator question none of the existing tx/mempool tools
# answer today:
#   "Looking at the transactions that ACTUALLY LANDED on-chain over this
#    window, does any sender's nonce sequence have HOLES (a stuck or
#    dropped earlier nonce that is blocking everything behind it), go
#    BACKWARDS (a nonce <= one already finalized — a replay / reorg-leak
#    signal that should be impossible under monotonic apply), or appear
#    TWICE (the same (from,nonce) finalized in two blocks)?"
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port.
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# The transaction-admission / mempool-pressure / nonce observability lane
# already has several tools, but NONE perform per-account nonce-sequence
# integrity analysis on the FINALIZED (on-chain) transaction stream:
#
#   operator_tx_throughput.sh
#       Walks the same block window via `block-info <h> --json`, but only
#       reads per-block `len(transactions)` + `timestamp` to compute TPS.
#       It never inspects the `nonce` field. (grep nonce → no matches.)
#
#   operator_tx_mix_trend.sh
#       Walks the window and aggregates the `type` field into a per-bucket
#       composition time-series. It never inspects `from` or `nonce`.
#       (grep nonce → no matches.)
#
#   operator_mempool_fee_floor.sh
#       Analyzes the S-008 ADMISSION fee floor (what fee an incoming tx
#       needs, eviction-vulnerable fraction). Fee axis only — no nonce
#       sequencing.
#
#   operator_mempool_inspector.sh / operator_mempool_diagnostic.sh
#       BOTH are forward-staged for a per-tx `mempool` RPC dump method
#       that today's daemon does NOT expose (only the scalar
#       `mempool_size` lives in the `status` RPC — see
#       src/node/node.cpp::rpc_status, and src/rpc/rpc.cpp::dispatch has
#       no `mempool` method). Their nonce-gap scan targets the PENDING
#       (un-finalized) pool and therefore SKIPs against any live daemon.
#       This tool is orthogonal: it scans the FINALIZED stream that the
#       `block` RPC DOES expose, so it produces real findings against a
#       running node instead of skipping.
#
# So the uncovered signal here is: nonce-sequence INTEGRITY on the
# finalized chain, per sender, across a window. A persistent on-chain gap
# for an account means everything queued behind the missing nonce is
# wedged (the account is stuck), which is a real liveness / fairness
# signal an operator wants surfaced.
#
# ── Data source (all read-only, all verified to exist) ────────────────────────
#   - status   RPC  → `height` (chain tip). src/node/node.cpp::rpc_status
#                     (j["height"] = chain_.height()). Reached via
#                     `determ status --rpc-port N`.
#   - block    RPC  → full Block JSON incl. `transactions` array. Reached
#                     via `determ block-info <index> --json`
#                     (src/main.cpp::cmd_block_info → rpc_call(... "block"
#                     {index})). Dispatch: src/rpc/rpc.cpp:252-253.
#     Each element of transactions[] is Transaction::to_json
#     (src/chain/block.cpp:36-48) with fields:
#         type (int), from (string), to (string), amount (u64),
#         fee (u64), nonce (u64), payload (hex), sig (hex), hash (hex).
#     This tool consumes only `from` and `nonce` (plus the enclosing
#     block `index` for diagnostics). No invented fields.
#
# ── Nonce-sequence model (what "gap" / "regression" / "duplicate" mean) ───────
# Determ uses per-account monotonic nonces (replay protection; see
# tx-replay-protection unit test + S-002). A correctly-behaving account
# emits a CONTIGUOUS increasing nonce sequence; each finalized tx for an
# account should carry exactly (prev_finalized_nonce + 1).
#
# We scan blocks in increasing height order. For each sender we track the
# highest nonce seen so far (`last`) and the full set of seen nonces.
# For each finalized tx (from=F, nonce=n):
#
#   - FIRST sight of F: record last[F]=n. (We make NO assumption about
#     the account's genesis/base nonce — the window may start mid-stream,
#     so the first observed nonce is the baseline, not necessarily 0/1.)
#   - n == last[F] + 1 : normal contiguous advance. No anomaly.
#   - n  > last[F] + 1 : GAP. Nonces (last[F]+1 .. n-1) never appeared
#                         on-chain in this window for F → earlier tx is
#                         stuck/dropped and is blocking the queue. The
#                         gap WIDTH = n - last[F] - 1 missing nonces.
#   - n <= last[F]     : either a DUPLICATE (n already in seen set — same
#                         (from,nonce) finalized twice, a double-inclusion
#                         bug) or a REGRESSION (n < last[F], not seen — a
#                         nonce went BACKWARDS across blocks, which should
#                         be impossible under monotonic apply: replay /
#                         reorg-leak signal).
#
# Per-sender summary (neutral rows): observed tx count, nonce range
# [min..max], contiguous? yes/no, total missing nonces (sum of gap
# widths), and per-anomaly counts.
#
# ── Usage ─────────────────────────────────────────────────────────────────────
#   tools/operator_nonce_gap_audit.sh [--rpc-port N] [--json]
#                                     [--from H] [--to H]
#                                     [--top N] [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human output
#   --from H            Start of window (inclusive; default: max(0, tip-1000))
#   --to H              End of window (inclusive; default: tip)
#   --top N             Cap the per-sender detail rows printed in human mode
#                       to the N senders with the most gaps/anomalies
#                       (default: 20; 0 = unlimited). Does NOT affect the
#                       aggregate verdict or the JSON (which always carries
#                       the full anomaly set).
#   --anomalies-only    Print only senders that carry >=1 anomaly; exit 2
#                       if any anomaly fired anywhere in the window.
#   -h, --help          Show this help
#
# ── Anomaly flags (each adds to anomalies[]) ──────────────────────────────────
#   nonce_gap          A sender's on-chain nonces are non-contiguous in the
#                      window (>=1 missing nonce between two finalized txs).
#   nonce_regression   A sender's later-block nonce is strictly LESS than a
#                      nonce already finalized in an earlier block (backwards
#                      movement — should be impossible; replay/reorg signal).
#   nonce_duplicate    The same (from,nonce) pair finalized in two blocks
#                      within the window (double-inclusion).
#
# ── Exit codes ────────────────────────────────────────────────────────────────
#   0   audit ran; no anomalies (or default informational mode). Also the
#       clean SKIP path (daemon unreachable / no python) so a monitoring
#       wrapper run against a node down for maintenance does not page.
#   1   RPC error (daemon up but malformed) / empty window / bad args.
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate).
set -u

usage() {
  cat <<'EOF'
Usage: operator_nonce_gap_audit.sh [--rpc-port N] [--json]
                                   [--from H] [--to H]
                                   [--top N] [--anomalies-only]

Per-account ON-CHAIN nonce-gap / stuck-tx detector across a finalized
block window. Walks the window via `block-info <h> --json`, groups the
finalized transactions by sender (`from`), and checks each sender's
`nonce` sequence for holes (stuck/dropped earlier nonce blocking the
queue), backwards movement (replay/reorg signal), and double-inclusion.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human
  --from H            Start of window (default: max(0, tip-1000))
  --to H              End of window (default: tip)
  --top N             Cap per-sender detail rows in human mode (default 20;
                      0 = unlimited). Verdict + JSON always cover all.
  --anomalies-only    Print only senders with >=1 anomaly; exit 2 if any
  -h, --help          Show this help

Anomaly flags:
  nonce_gap          sender's on-chain nonces non-contiguous (missing nonce)
  nonce_regression   sender's later nonce < an already-finalized nonce
  nonce_duplicate    same (from,nonce) finalized in two blocks

Exit codes:
  0   success / informational / clean SKIP (daemon down)
  1   RPC error / empty window / bad args
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
TOP_N=20
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --top)             TOP_N="${2:-}";  shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_nonce_gap_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards (args validated before any RPC / daemon contact).
case "$PORT" in *[!0-9]*|"")
  echo "operator_nonce_gap_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_nonce_gap_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$TOP_N" in *[!0-9]*|"")
  echo "operator_nonce_gap_audit: --top must be a non-negative integer (got '$TOP_N')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve an absolute path to the determ binary so the python driver can
# subprocess it regardless of the python child's cwd (mirrors the
# convention in operator_mempool_fee_floor.sh / operator_block_size_audit.sh).
case "$DETERM" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) DETERM_ABS="$DETERM" ;;
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# Pick a python interpreter (python3 preferred, python fallback). No
# interpreter => clean SKIP (exit 0) so this never hard-fails a CI/monitor
# environment that lacks python — same convention as the sibling tools.
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python  >/dev/null 2>&1; then PY=python
else
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"no python interpreter (need python3/python)"}'
  else
    echo "operator_nonce_gap_audit: [SKIP] no python interpreter found (need python3/python)"
  fi
  exit 0
fi

# ── Step 1: resolve chain tip (clean SKIP if the daemon is unreachable) ───────
# Prefer the `status` RPC (carries `height` in one round-trip;
# src/node/node.cpp::rpc_status). An unreachable daemon => clean SKIP
# (exit 0) so a monitoring wrapper run against a node down for maintenance
# does not page; a daemon that is UP but returns a malformed height is a
# real error (exit 1).
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null)
if [ -z "$STATUS_JSON" ]; then
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"daemon unreachable on rpc-port '"$PORT"' (no status response)"}'
  else
    echo "operator_nonce_gap_audit: [SKIP] daemon unreachable on rpc-port $PORT (no status response)"
  fi
  exit 0
fi

HEAD_H=$(printf '%s' "$STATUS_JSON" | "$PY" -c "
import sys, json
try:
    j = json.load(sys.stdin)
    h = j.get('height')
    print(int(h) if h is not None else '')
except Exception:
    print('')
")
# Fall back to `head --field height` if status didn't carry a usable height.
if [ -z "$HEAD_H" ]; then
  HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null || echo "")
fi
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_nonce_gap_audit: malformed status/head response (height='$HEAD_H', port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEAD_H" = "0" ]; then
  echo "operator_nonce_gap_audit: chain is empty (height=0); nothing to audit" >&2
  exit 1
fi

# ── Step 2: resolve window ────────────────────────────────────────────────────
# Default: last 1000 blocks ending at tip (matches sibling tx/fee tools).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_nonce_gap_audit: --from ($FROM) > --to ($TO); empty window" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk window, group by sender, check nonce-sequence integrity ──────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_nonce_gap_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$JSON_OUT" "$TOP_N" "$ANOM_ONLY" <<'PY'
import json, subprocess, sys
from collections import OrderedDict

(determ, port, from_h_s, to_h_s, out_path,
 json_out_s, top_n_s, anom_only_s) = sys.argv[1:9]
from_h    = int(from_h_s)
to_h      = int(to_h_s)
json_out  = json_out_s == "1"
top_n     = int(top_n_s)
anom_only = anom_only_s == "1"

# Per-sender accumulator. Insertion-ordered so deterministic output.
#   last  — highest nonce seen so far (None until first sight)
#   seen  — set of nonces seen (duplicate detection)
#   nmin/nmax — observed range
#   count — finalized tx count for this sender in window
#   gap_missing  — sum of widths of all gaps (total missing nonces)
#   gaps  — list of (after_nonce, next_nonce, width) gap records
#   regressions  — count of backwards-nonce events
#   duplicates   — count of repeated (from,nonce)
senders = OrderedDict()

def acc(f):
    s = senders.get(f)
    if s is None:
        s = {"last": None, "seen": set(), "nmin": None, "nmax": None,
             "count": 0, "gap_missing": 0, "gaps": [],
             "regressions": 0, "duplicates": 0}
        senders[f] = s
    return s

total_txs = 0
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15)
    except Exception as e:
        sys.stderr.write(f"operator_nonce_gap_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_nonce_gap_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_nonce_gap_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        f = tx.get("from")
        n = tx.get("nonce")
        if not isinstance(f, str) or not isinstance(n, int):
            # Skip malformed tx entries rather than aborting the whole
            # audit; Transaction::to_json always emits both as the right
            # types, so this only guards against a future schema drift.
            continue
        total_txs += 1
        s = acc(f)
        s["count"] += 1
        if s["nmin"] is None or n < s["nmin"]:
            s["nmin"] = n
        if s["nmax"] is None or n > s["nmax"]:
            s["nmax"] = n

        if s["last"] is None:
            # First sight: baseline. No gap claim against the unknown
            # pre-window history.
            s["last"] = n
            s["seen"].add(n)
            continue

        if n in s["seen"]:
            s["duplicates"] += 1
        elif n == s["last"] + 1:
            pass  # contiguous advance
        elif n > s["last"] + 1:
            width = n - s["last"] - 1
            s["gap_missing"] += width
            s["gaps"].append((s["last"], n, width))
        else:  # n < s["last"] and not previously seen
            s["regressions"] += 1

        s["seen"].add(n)
        if n > s["last"]:
            s["last"] = n

# Build per-sender result records + classify anomalies.
results = []
anom_senders = 0
total_gap_senders = 0
total_regression_senders = 0
total_duplicate_senders = 0
for f, s in senders.items():
    contiguous = (s["gap_missing"] == 0 and s["regressions"] == 0
                  and s["duplicates"] == 0)
    flags = []
    if s["gap_missing"] > 0:       flags.append("nonce_gap")
    if s["regressions"] > 0:       flags.append("nonce_regression")
    if s["duplicates"] > 0:        flags.append("nonce_duplicate")
    if flags:
        anom_senders += 1
        if "nonce_gap" in flags:        total_gap_senders += 1
        if "nonce_regression" in flags: total_regression_senders += 1
        if "nonce_duplicate" in flags:  total_duplicate_senders += 1
    results.append({
        "from": f,
        "tx_count": s["count"],
        "nonce_min": s["nmin"],
        "nonce_max": s["nmax"],
        "contiguous": contiguous,
        "missing_nonces": s["gap_missing"],
        "gap_count": len(s["gaps"]),
        "gaps": [{"after": g[0], "next": g[1], "width": g[2]}
                 for g in s["gaps"]],
        "regressions": s["regressions"],
        "duplicates": s["duplicates"],
        "flags": flags,
    })

# Sort: most-anomalous first (missing nonces desc, then regressions+dups
# desc, then tx_count desc), so --top surfaces the worst offenders.
def sort_key(r):
    return (-(r["missing_nonces"]),
            -(r["regressions"] + r["duplicates"]),
            -r["tx_count"],
            r["from"])
results.sort(key=sort_key)

summary = {
    "from_height": from_h,
    "to_height": to_h,
    "window_blocks": to_h - from_h + 1,
    "total_finalized_txs": total_txs,
    "distinct_senders": len(senders),
    "anomalous_senders": anom_senders,
    "senders_with_gaps": total_gap_senders,
    "senders_with_regressions": total_regression_senders,
    "senders_with_duplicates": total_duplicate_senders,
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump({"summary": summary, "senders": results}, fh)
PY

PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  # The python driver already wrote a diagnostic to stderr on RPC/parse
  # failure. Propagate as a hard error (daemon up but malformed).
  exit 1
fi

# ── Step 4: render output + compute verdict / exit code ───────────────────────
# A single python pass formats either the human report or the JSON
# envelope from the intermediate file, and prints a trailing token the
# shell reads to decide the exit code:
#   __VERDICT__ <anomalous_senders>
RENDER=$("$PY" - "$TMP_OUT" "$JSON_OUT" "$TOP_N" "$ANOM_ONLY" <<'PY'
import json, sys
out_path, json_out_s, top_n_s, anom_only_s = sys.argv[1:5]
json_out  = json_out_s == "1"
top_n     = int(top_n_s)
anom_only = anom_only_s == "1"

with open(out_path, encoding="utf-8") as fh:
    data = json.load(fh)
summary = data["summary"]
senders = data["senders"]

anomalous = summary["anomalous_senders"]

if json_out:
    env = {
        "tool": "operator_nonce_gap_audit",
        "summary": summary,
        "senders": senders,  # full set, already worst-first
        "anomaly": anomalous > 0,
    }
    print(json.dumps(env))
    print(f"__VERDICT__ {anomalous}")
    sys.exit(0)

# Human output.
lines = []
lines.append("Nonce-gap audit — finalized per-account nonce-sequence integrity")
lines.append(f"  window         : blocks [{summary['from_height']}..{summary['to_height']}] "
             f"({summary['window_blocks']} blocks)")
lines.append(f"  finalized txs  : {summary['total_finalized_txs']}")
lines.append(f"  distinct from  : {summary['distinct_senders']}")
lines.append(f"  anomalous from : {summary['anomalous_senders']} "
             f"(gaps={summary['senders_with_gaps']} "
             f"regressions={summary['senders_with_regressions']} "
             f"duplicates={summary['senders_with_duplicates']})")
lines.append("")

rows = senders
if anom_only:
    rows = [r for r in rows if r["flags"]]
if top_n > 0:
    rows = rows[:top_n]

if not rows:
    if anom_only:
        lines.append("  (no senders with nonce anomalies in window)")
    else:
        lines.append("  (no senders / no finalized txs in window)")
else:
    # Neutral per-sender rows.
    lines.append("  sender                          txs  nonce[min..max]  miss  flags")
    for r in rows:
        frm = r["from"]
        disp = frm if len(frm) <= 30 else frm[:27] + "..."
        rng = f"[{r['nonce_min']}..{r['nonce_max']}]"
        flags = ",".join(r["flags"]) if r["flags"] else "-"
        lines.append(f"  {disp:<30}  {r['tx_count']:>4}  {rng:>15}  "
                     f"{r['missing_nonces']:>4}  {flags}")
    # Detail the actual gap segments for flagged senders (bounded by --top).
    flagged = [r for r in rows if r["gaps"] or r["regressions"] or r["duplicates"]]
    if flagged:
        lines.append("")
        lines.append("  anomaly detail:")
        for r in flagged:
            frm = r["from"]
            disp = frm if len(frm) <= 30 else frm[:27] + "..."
            for g in r["gaps"]:
                lines.append(f"    {disp}: gap after nonce {g['after']} -> "
                             f"{g['next']} ({g['width']} missing)")
            if r["regressions"]:
                lines.append(f"    {disp}: {r['regressions']} nonce regression(s) "
                             f"(backwards movement; replay/reorg signal)")
            if r["duplicates"]:
                lines.append(f"    {disp}: {r['duplicates']} duplicate (from,nonce) "
                             f"finalization(s)")

lines.append("")
if anomalous > 0:
    lines.append(f"[ANOMALY] {anomalous} sender(s) with nonce-sequence anomalies")
else:
    lines.append("[OK] all observed senders have contiguous nonce sequences")

print("\n".join(lines))
print(f"__VERDICT__ {anomalous}")
PY
)
RENDER_RC=$?
if [ "$RENDER_RC" -ne 0 ]; then
  echo "operator_nonce_gap_audit: render step failed" >&2
  exit 1
fi

# Split the trailing __VERDICT__ token off the rendered output.
ANOMALOUS=$(printf '%s\n' "$RENDER" | sed -n 's/^__VERDICT__ //p' | tail -n1)
printf '%s\n' "$RENDER" | grep -v '^__VERDICT__ '

case "$ANOMALOUS" in *[!0-9]*|"") ANOMALOUS=0 ;; esac

if [ "$ANOM_ONLY" -eq 1 ] && [ "$ANOMALOUS" -gt 0 ]; then
  exit 2
fi
exit 0
