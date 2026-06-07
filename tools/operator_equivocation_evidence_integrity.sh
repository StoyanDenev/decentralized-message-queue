#!/usr/bin/env bash
# operator_equivocation_evidence_integrity.sh — Structural well-formedness
# audit of the FA6 double-sign EVIDENCE payloads baked into finalized
# blocks, plus verification-key resolvability for each equivocator.
#
# THE OPERATOR QUESTION
#   "Every EquivocationEvent that landed on this chain forfeited a
#    validator's ENTIRE stake. Is each of those on-chain slashing
#    proofs STRUCTURALLY WELL-FORMED — two DIFFERENT digests, two
#    DIFFERENT signatures, all hex fields the right length — and can I
#    still resolve the equivocator's Ed25519 verification key to
#    re-check the proof myself?"
#
# This mirrors the OFFLINE-CHECKABLE subset of the node's apply-time
# admission gate, src/node/validator.cpp::check_equivocation_events
# (validator.cpp:322-347). That gate enforces, per event:
#
#     (a) digest_a != digest_b        else "not equivocation"
#     (b) sig_a    != sig_b           else "same signature"
#     (c) equivocator IN registry     else "equivocator not in registry"
#     (d) ed25519_verify(pub, digest_a, sig_a)   else reject
#     (e) ed25519_verify(pub, digest_b, sig_b)   else reject
#
# (a) and (b) are pure structural predicates an operator can re-check
# from observable RPC data without any crypto. (c) maps to whether the
# equivocator's `ed_pub` is still resolvable via the `validators` RPC.
# (d)/(e) — the actual Ed25519 verifications — require a signature-
# verify primitive this read-only shell tool deliberately does NOT
# re-implement; the digest/sig material IS surfaced (truncated) so an
# operator can hand it to `determ`'s crypto path for a full re-verify.
#
# WHY THE STRUCTURAL CHECK MATTERS EVEN THOUGH THE NODE ALREADY GATES IT
#   The K-of-K committee that finalized the carrying block already ran
#   check_equivocation_events, so on a healthy chain every event is
#   well-formed by construction. This tool is the operator's INDEPENDENT
#   confirmation of that property — a non-zero structural-violation count
#   means either (i) a consensus/admission bug let a malformed proof
#   through, or (ii) the chain data this RPC is serving has been
#   tampered (the events are bound into the block hash via
#   Block::signing_bytes, block.cpp:264-280, so tampering would also
#   break the hash — surfacing a structural violation here is an early,
#   cheap tripwire that something is wrong with the served chain).
#
# WHY THIS IS NOT A DUPLICATE OF ITS SIBLINGS
#   operator_equivocation_digest.sh
#       Per-OFFENDER COUNT + slashed-amount digest over a window. It
#       answers "who double-signed and how often" — it never inspects
#       whether each event's digest_a/sig_a/digest_b/sig_b payload is
#       structurally valid, and never checks key resolvability.
#   operator_slashing_ledger.sh
#       Cumulative `accumulated_slashed` counter + A1 reconciliation +
#       per-domain equiv/abort EVENT tallies. Sums penalties; does not
#       inspect evidence well-formedness.
#   operator_event_summary.sh
#       Cross-class (abort + equivocation + merge) per-validator
#       aggregation. A volume lens, not an evidence-integrity lens.
#   operator_suspension_watch.sh
#       Forward abort-suspension WINDOW forecast (the recoverable abort
#       path). Nothing about equivocation evidence payloads.
#   operator_escalation_consistency.sh
#       Per-block BFT-escalation LEGALITY (consensus_mode invariants).
#       Orthogonal axis.
#   operator_signature_audit.sh
#       K-of-K committee SIG-FILL ratios on creator_block_sigs[].
#       Different signature set (per-block committee sigs, not the
#       two-sig equivocation proof).
#   THIS (operator_equivocation_evidence_integrity.sh)
#       Per-EVENT structural well-formedness (I1 digest distinctness,
#       I2 sig distinctness, I3 hex-length validity) + per-equivocator
#       verification-key resolvability (R1). The only tool that audits
#       the EVIDENCE PAYLOAD itself.
#
# DATA SOURCES (all read-only; no block scan beyond the window)
#   * `determ head --field height`        current tip (one integer).
#   * `determ block-range FROM TO --json`  paged `headers` RPC; the
#                                          server strips only
#                                          transactions / cross_shard_
#                                          receipts / inbound_receipts /
#                                          initial_state (node.cpp:2652-
#                                          2655), so equivocation_events
#                                          (digest_a/sig_a/digest_b/sig_b)
#                                          are RETAINED on each header.
#   * `determ validators --json`           domain -> ed_pub map
#                                          (node.cpp:2805-2820) for the
#                                          R1 key-resolvability check.
#
# EquivocationEvent JSON field names (block.cpp:120-131, to_json):
#   equivocator, block_index, digest_a, sig_a, digest_b, sig_b,
#   shard_id, beacon_anchor_height.
# Hex lengths the node enforces on parse (block.cpp:141-144):
#   digest_* = 64 hex chars (32 bytes), sig_* = 128 hex chars (64 bytes).
#
# Read-only; never sends a tx, never writes chain/snapshot files.
#
# Usage:
#   tools/operator_equivocation_evidence_integrity.sh --rpc-port N
#                            [--from H] [--to H] [--last N]
#                            [--json] [--anomalies-only]
#
# Output:
#   Human (default): one row per event — containing block, height of the
#     double-sign, equivocator, digest_a/digest_b prefixes, the per-event
#     structural verdict (OK / I1 / I2 / I3) and R1 key-resolvability;
#     then a footer with totals + an [OK] / [ANOMALY] verdict line.
#   --json: {window, counts, events:[...], summary, anomalies:[...],
#            rpc_port}
#
# Exit codes:
#   0   success / informational / clean SKIP (daemon unreachable, or the
#       window holds zero equivocation events)
#   1   bad args / RPC error after a reachable head / malformed response /
#       empty window (--from > --to)
#   2   --anomalies-only AND >=1 structural violation (I1/I2/I3) present
set -u

usage() {
  cat <<'EOF'
Usage: operator_equivocation_evidence_integrity.sh --rpc-port N
                         [--from H] [--to H] [--last N]
                         [--json] [--anomalies-only]

Structural well-formedness audit of FA6 equivocation EVIDENCE payloads in
finalized blocks. Re-checks the offline-verifiable subset of the node's
apply-time gate src/node/validator.cpp::check_equivocation_events:

  I1 digest_a == digest_b   -> not equivocation (degenerate proof)
  I2 sig_a    == sig_b      -> same signature (degenerate proof)
  I3 bad hex length         -> digest_* != 64 or sig_* != 128 hex chars

and the per-equivocator verification-key resolvability:

  R1 key_unresolved         -> equivocator absent from `validators` (its
                               ed_pub is no longer available for a full
                               Ed25519 re-verify; NOT an anomaly — a
                               slashed equivocator is DEACTIVATED, so a
                               historical event legitimately loses its
                               key once the registry entry is gone)

Only I1/I2/I3 are anomalies (they would mean the node admitted a
malformed proof, or the served chain was tampered). R1 is reported
for forensic completeness but never flips the exit code.

Required:
  --rpc-port N        RPC port to query

Options:
  --from H            Lower window bound, inclusive (default: head-1000)
  --to H              Upper window bound, inclusive (default: current head)
  --last N            Shorthand for [head-N+1, head] (exclusive with
                      --from/--to)
  --json              Emit a structured JSON envelope instead of human output
  --anomalies-only    Print only events with a structural violation; exit 2
                      if any fired
  -h, --help          Show this help

Exit codes:
  0   success / informational / clean SKIP (daemon unreachable or no events)
  1   bad args / RPC error / malformed response / empty window
  2   --anomalies-only AND >=1 structural violation (I1/I2/I3)
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";  shift 2 ;;
    --from)           FROM="${2:-}";  shift 2 ;;
    --to)             TO="${2:-}";    shift 2 ;;
    --last)           LAST="${2:-}";  shift 2 ;;
    --json)           JSON_OUT=1;     shift ;;
    --anomalies-only) ANOM_ONLY=1;    shift ;;
    *) echo "operator_equivocation_evidence_integrity: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
if [ -z "$PORT" ]; then
  echo "operator_equivocation_evidence_integrity: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_equivocation_evidence_integrity: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_equivocation_evidence_integrity: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_equivocation_evidence_integrity: --last cannot be combined with --from / --to" >&2
  exit 1
fi
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_equivocation_evidence_integrity: --last must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip (clean SKIP if daemon unreachable) ────────────
# An operator running this in a health loop against a not-yet-started node
# should get an informational SKIP, not a hard failure. A genuine RPC error
# AFTER a reachable head still exits 1.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_equivocation_evidence_integrity: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  [ "$JSON_OUT" = "1" ] && echo '{"skipped":true,"reason":"daemon_unreachable","rpc_port":'"$PORT"'}'
  exit 0
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_equivocation_evidence_integrity: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks, so no equivocation
# events possible. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  echo "operator_equivocation_evidence_integrity: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  [ "$JSON_OUT" = "1" ] && echo '{"skipped":true,"reason":"no_produced_blocks","height":'"$HEAD_H"',"rpc_port":'"$PORT"'}'
  exit 0
fi

# ── Step 2: resolve window bounds ─────────────────────────────────────────────
# `head` height is the next-to-be-produced index; highest finalized block
# has index = height - 1.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
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
    FROM=$(( TOP > 1000 ? TOP - 1000 : 0 ))
  fi
fi
# Clamp --to to the chain tail without error (operator may have typed a
# --to ahead of where the chain has caught up).
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_equivocation_evidence_integrity: --from ($FROM) > --to ($TO); empty window" >&2
  exit 1
fi

# ── Step 3: bulk-fetch the window (headers RPC retains equivocation_events) ───
RANGE_JSON=$("$DETERM" block-range "$FROM" "$TO" --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_equivocation_evidence_integrity: RPC error fetching block-range [$FROM..$TO] on port $PORT" >&2
  exit 1
}

# ── Step 4: pool snapshot (domain -> ed_pub) for the R1 resolvability check ───
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_equivocation_evidence_integrity: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}
[ -z "$VAL_JSON" ] && VAL_JSON="[]"

# ── Step 5: structural audit + render (python; no jq dependency) ──────────────
python - "$RANGE_JSON" "$VAL_JSON" "$FROM" "$TO" "$PORT" "$JSON_OUT" "$ANOM_ONLY" <<'PY'
import json, sys

range_raw, val_raw, from_s, to_s, port_s, json_out_s, anom_only_s = sys.argv[1:8]
win_from  = int(from_s)
win_to    = int(to_s)
port      = int(port_s)
json_out  = (json_out_s == '1')
anom_only = (anom_only_s == '1')

def fail(msg):
    sys.stderr.write("operator_equivocation_evidence_integrity: " + msg + "\n")
    sys.exit(1)

try:
    rng = json.loads(range_raw)
except Exception:
    fail("malformed block-range payload (port %d)" % port)
headers = rng.get("headers") if isinstance(rng, dict) else None
if not isinstance(headers, list):
    fail("block-range payload missing 'headers' array (port %d)" % port)

# domain -> ed_pub resolvability set. We only need presence; the ed_pub
# value is surfaced (prefix) for the operator's manual re-verify.
try:
    vals = json.loads(val_raw)
except Exception:
    vals = []
keymap = {}
if isinstance(vals, list):
    for v in vals:
        if isinstance(v, dict):
            d = v.get("domain")
            p = v.get("ed_pub")
            if isinstance(d, str):
                keymap[d] = p if isinstance(p, str) else None

HEX = set("0123456789abcdefABCDEF")
def is_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in HEX for c in s)

events = []
n_i1 = n_i2 = n_i3 = n_r1 = 0

for h in headers:
    if not isinstance(h, dict):
        continue
    blk_idx = h.get("index")
    blk_hash = h.get("block_hash")
    evs = h.get("equivocation_events") or []
    if not isinstance(evs, list):
        continue
    for ev in evs:
        if not isinstance(ev, dict):
            continue
        offender = ev.get("equivocator")
        dsign_h  = ev.get("block_index")          # height of the double-sign
        da = ev.get("digest_a"); sa = ev.get("sig_a")
        db = ev.get("digest_b"); sb = ev.get("sig_b")

        viol = []
        # I3: hex-field well-formedness (mirrors from_hex_arr<32>/<64>
        # length enforcement at block.cpp:141-144). Checked first so the
        # distinctness predicates below operate on the canonical strings.
        hex_ok = (is_hex(da, 64) and is_hex(db, 64)
                  and is_hex(sa, 128) and is_hex(sb, 128))
        if not hex_ok:
            viol.append("I3")
            n_i3 += 1
        # I1: digest_a != digest_b (validator.cpp:327). Compare case-
        # insensitively — block.cpp to_hex emits lowercase, but a hand-
        # submitted proof could differ in case while encoding the same
        # bytes; the node compares the decoded byte arrays.
        if isinstance(da, str) and isinstance(db, str) and da.lower() == db.lower():
            viol.append("I1")
            n_i1 += 1
        # I2: sig_a != sig_b (validator.cpp:330).
        if isinstance(sa, str) and isinstance(sb, str) and sa.lower() == sb.lower():
            viol.append("I2")
            n_i2 += 1

        # R1: verification-key resolvability (maps to validator.cpp:334
        # "equivocator not in registry"). NOT an anomaly — a slashed
        # equivocator is deactivated (chain.cpp full-stake forfeit +
        # registry deactivation), so a historical event legitimately
        # outlives the registry entry that once carried its key.
        key_present = offender in keymap and keymap.get(offender)
        if not key_present:
            n_r1 += 1

        events.append({
            "containing_block_index": blk_idx,
            "containing_block_hash":  blk_hash,
            "double_sign_height":     dsign_h,
            "equivocator":            offender,
            "shard_id":               ev.get("shard_id", 0),
            "digest_a_prefix":        (da[:16] if isinstance(da, str) else None),
            "digest_b_prefix":        (db[:16] if isinstance(db, str) else None),
            "hex_ok":                 hex_ok,
            "violations":             viol,
            "key_resolvable":         bool(key_present),
            "ed_pub_prefix":          (keymap.get(offender)[:16]
                                       if key_present else None),
        })

total = len(events)
violating = sum(1 for e in events if e["violations"])
anomaly = violating > 0   # only I1/I2/I3 (structural) gate the exit code

anomalies = []
if n_i1: anomalies.append("I1")
if n_i2: anomalies.append("I2")
if n_i3: anomalies.append("I3")

summary = {
    "n_events":               total,
    "n_violating_events":     violating,
    "n_key_unresolvable":     n_r1,
    "violation_counts":       {"I1": n_i1, "I2": n_i2, "I3": n_i3},
}

if json_out:
    rows = [e for e in events if e["violations"]] if anom_only else events
    out = {
        "window":   {"from": win_from, "to": win_to,
                     "block_count": (win_to - win_from + 1)},
        "counts":   {"events": total, "violating_events": violating,
                     "key_unresolvable": n_r1},
        "events":   rows,
        "summary":  summary,
        "anomalies": anomalies,
        "rpc_port": port,
    }
    print(json.dumps(out))
    sys.exit(2 if (anom_only and anomaly) else 0)

# ── Human output ──────────────────────────────────────────────────────────────
print("Equivocation evidence integrity -- window [%d..%d] (%d blocks), port %d"
      % (win_from, win_to, win_to - win_from + 1, port))

if total == 0:
    # Zero events in the window is success, not an anomaly. (A clean chain
    # never produces equivocation evidence.)
    print("  no equivocation events in window -- nothing to audit")
    print("[OK] 0 events")
    sys.exit(0)

rows = [e for e in events if e["violations"]] if anom_only else events
if anom_only and not rows:
    print("  no structural violations in window (%d events all well-formed)"
          % total)
else:
    print("  %-7s %-9s %-22s %-18s %-18s %-8s %s"
          % ("blk", "dsHeight", "equivocator", "digest_a", "digest_b",
             "verdict", "key"))
    for e in rows:
        verdict = ",".join(e["violations"]) if e["violations"] else "OK"
        key = "resolvable" if e["key_resolvable"] else "R1-unresolved"
        print("  %-7s %-9s %-22s %-18s %-18s %-8s %s"
              % (str(e["containing_block_index"]),
                 str(e["double_sign_height"]),
                 (e["equivocator"] or "?")[:22],
                 (e["digest_a_prefix"] or "?"),
                 (e["digest_b_prefix"] or "?"),
                 verdict, key))

print("  ---")
print("  events: %d   structurally-violating: %d   key-unresolvable (R1): %d"
      % (total, violating, n_r1))
print("  violation breakdown: I1(digest==)=%d  I2(sig==)=%d  I3(bad-hex)=%d"
      % (n_i1, n_i2, n_i3))
if n_r1:
    print("  note: R1 key-unresolvable is expected for already-slashed "
          "(deactivated) equivocators; not an anomaly.")

if anomaly:
    print("[ANOMALY] %d event(s) carry malformed equivocation evidence "
          "(I1/I2/I3) -- admission gate or served-chain integrity suspect"
          % violating)
else:
    print("[OK] all %d event(s) structurally well-formed" % total)

sys.exit(2 if (anom_only and anomaly) else 0)
PY
