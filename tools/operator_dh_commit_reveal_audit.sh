#!/usr/bin/env bash
# operator_dh_commit_reveal_audit.sh — Per-creator commit-reveal binding
# audit over a window of finalized blocks. Re-derives, from OUTSIDE the
# daemon, the S-009 selective-abort-defense binding that the validator
# enforces at apply time:
#
#       creator_dh_inputs[i] == SHA256( creator_dh_secrets[i] || pubkey_i )
#
# for every committee slot i of every block in [--from..--to]. This is
# the Phase-1 commitment / Phase-2 reveal pair that feeds the block's
# `delay_seed` and `delay_output` (and therefore `cumulative_rand`).
# Source of truth, byte-for-byte:
#   src/node/validator.cpp::check_creator_dh_secrets (lines 355-370):
#       expected = SHA256Builder{}.append(creator_dh_secrets[i])
#                                 .append(pubkey_i).finalize();
#       if (expected != creator_dh_inputs[i]) -> reject
#   src/node/producer.cpp::compute_delay_seed  (line 509) consumes
#       creator_dh_inputs; ::compute_block_rand (line 637) consumes
#       creator_dh_secrets. The commit-reveal binding is what makes the
#       revealed secret non-substitutable: any post-Phase-1 swap of a
#       secret breaks this SHA-256 equality.
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# Determ's randomness lane already has ONE dedicated stream auditor, plus
# several beacon consumers. NONE of them re-derive the per-creator
# commit-reveal binding. They operate strictly on the AGGREGATE outputs
# (delay_output / cumulative_rand), never on the per-slot
# creator_dh_inputs[] / creator_dh_secrets[] arrays:
#
#   operator_randomness_beacon_audit.sh
#       Verifies the BEACON STREAM: cumulative_rand[h] == SHA256(prev ||
#       delay_output[h]) recurrence, non-repetition, and nibble entropy.
#       It reads `cumulative_rand` + `delay_output` ONLY. It never touches
#       creator_dh_inputs / creator_dh_secrets and never re-derives the
#       SHA256(secret||pubkey) commitment. (grep: that script matches
#       `delay_output`; it does NOT match `creator_dh_inputs`/`secrets`.)
#       A block can pass the beacon recurrence (delay_output is internally
#       self-consistent with whatever secrets were used) and STILL have a
#       broken commit binding if a node mis-restored or tampered the
#       per-creator arrays — this tool is the only surface that catches it.
#   operator_subsidy_lottery_audit.sh
#       CONSUMES first8(cumulative_rand) % M for jackpot/miss outcomes.
#   operator_stake_activation_audit.sh
#       CONSUMES derive_delay(cumulative_rand, tx.hash) activation offsets.
#   operator_block_inclusion_audit.sh / operator_signature_audit.sh
#       Audit creator_block_SIGS participation (who SIGNED the block).
#       Orthogonal: this tool audits the DH commit/reveal contribution,
#       a different per-creator array entirely.
#   operator_committee_audit.sh / *_fairness / *_rotation
#       Audit creators[] SELECTION distribution. They harvest the
#       creators[] domain list; they ignore the DH arrays.
#
# A grep across tools/operator_*.sh for `creator_dh_inputs` /
# `creator_dh_secrets` / `dh_secret` returns ZERO files — this is the
# first operator surface to re-derive the S-009 binding off-daemon.
#
# ── Checks (all derived from `block-info <h> --json` + `validators --json`) ────
#   (A) binding_correctness   For each block, for each committee slot i,
#                             recompute SHA256(secret_i || pubkey_i) where
#                             secret_i = creator_dh_secrets[i] (32 raw
#                             bytes) and pubkey_i = the ed_pub of
#                             creators[i] looked up in the validators RPC
#                             (32 raw bytes). Assert it equals
#                             creator_dh_inputs[i]. A mismatch means a
#                             finalized block carries a reveal that does
#                             NOT open its own Phase-1 commitment — a
#                             tampered/mis-restored chain or a consensus
#                             bug that bypassed validator.cpp's gate.
#                             Anomaly: dh_binding_break (MAX severity).
#   (B) array_shape           creators[], creator_dh_inputs[], and
#                             creator_dh_secrets[] must be equal-length on
#                             every produced block (the validator rejects
#                             any block where they diverge). A length
#                             mismatch is itself a malformed/illegal block.
#                             Anomaly: dh_array_shape_mismatch.
#   (C) secret_reuse          No NON-ZERO creator_dh_secrets[] value may
#                             repeat across the window — a revealed secret
#                             is fresh per (block, slot). A repeat is a
#                             replayed reveal (grinding signal at the
#                             contribution layer, distinct from the beacon
#                             auditor's delay_OUTPUT repeat). The all-zero
#                             sentinel (empty-creator / degenerate blocks)
#                             is exempt. Anomaly: dh_secret_reuse.
#
# A creator whose ed_pub is NOT resolvable from the current validators
# RPC (e.g. a since-deregistered validator that signed a historical
# block) cannot have its binding recomputed; such slots are counted as
# `unresolved` and reported informationally — they do NOT fire an
# anomaly (the pubkey is simply unavailable now, not proof of a break).
# Operators auditing deep history should narrow the window to recent
# blocks where the committee pool still overlaps the live registry.
#
# ── Index semantics ──────────────────────────────────────────────────────────
# `head --field height` returns the total block COUNT (block 0 == genesis;
# highest valid index == height - 1). Mirrors operator_randomness_beacon_audit.sh.
#
# Usage:
#   tools/operator_dh_commit_reveal_audit.sh [--rpc-port N] [--json]
#                                            [--from H] [--to H] [--last N]
#                                            [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit a structured JSON envelope instead of human text
#   --from H            Start of window (inclusive; default: max(0, tip-1000))
#   --to H              End of window (inclusive; default: tip)
#   --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
#   --anomalies-only    Print only anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head        (--field height)        current chain height / tip
#   - validators  --json                  domain -> ed_pub pool snapshot
#   - block-info <h> --json               per-block creators[] +
#                                         creator_dh_inputs[] + creator_dh_secrets[]
#
# Anomaly flags (each adds an entry to anomalies[]):
#   dh_binding_break          a slot's SHA256(secret||pubkey) != stored commit
#   dh_array_shape_mismatch   creators/inputs/secrets length divergence on a block
#   dh_secret_reuse           a non-zero creator_dh_secret repeats in the window
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode);
#       ALSO the clean SKIP path when the daemon is unreachable or the chain
#       has no produced blocks (INFO + exit 0)
#   1   RPC error / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dh_commit_reveal_audit.sh [--rpc-port N] [--json]
                                          [--from H] [--to H] [--last N]
                                          [--anomalies-only]

Per-creator commit-reveal binding audit (S-009 selective-abort defense).
Walks a window of finalized blocks via block-info and re-derives, from
outside the daemon, the binding the validator enforces at apply time:

  creator_dh_inputs[i] == SHA256( creator_dh_secrets[i] || pubkey_i )

for every committee slot i of every block. pubkey_i is resolved from the
`validators` RPC (ed_pub of creators[i]). Three axes:
  (A) binding   each revealed secret must open its own Phase-1 commitment
  (B) shape     creators[]/inputs[]/secrets[] must be equal length
  (C) freshness no non-zero revealed secret repeats across the window

This is distinct from operator_randomness_beacon_audit.sh, which audits
the AGGREGATE beacon stream (cumulative_rand / delay_output) and never
re-derives the per-creator SHA256(secret||pubkey) commitment.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit a structured JSON envelope instead of human text
  --from H            Start of window (default: max(0, tip-1000))
  --to H              End of window (default: tip)
  --last N            Shorthand for [tip-N+1, tip] (excl. --from / --to)
  --anomalies-only    Print only anomalies; exit 2 if any fire
  -h, --help          Show this help

RPC dependencies (read-only): head, validators, block-info.

Anomaly flags:
  dh_binding_break          SHA256(secret||pubkey) != stored commit on a slot
  dh_array_shape_mismatch   creators/inputs/secrets length divergence on a block
  dh_secret_reuse           a non-zero creator_dh_secret repeats in the window

Exit codes:
  0   success / informational / clean SKIP (daemon unreachable or no blocks)
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
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --last)            LAST_N="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_dh_commit_reveal_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_dh_commit_reveal_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dh_commit_reveal_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_dh_commit_reveal_audit: --last cannot be combined with --from / --to" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_randomness_beacon_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# Clean SKIP (INFO + exit 0) when the daemon is unreachable — an operator
# running this in a health loop against a not-yet-started node should not see
# a hard failure. A genuine RPC error after a reachable head still exits 1.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dh_commit_reveal_audit: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  [ "$JSON_OUT" = "1" ] && echo '{"skipped":true,"reason":"daemon_unreachable","rpc_port":'"$PORT"'}'
  exit 0
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dh_commit_reveal_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  echo "operator_dh_commit_reveal_audit: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  [ "$JSON_OUT" = "1" ] && echo '{"skipped":true,"reason":"no_produced_blocks","height":'"$HEAD_H"',"rpc_port":'"$PORT"'}'
  exit 0
fi

# ── Step 2: pool snapshot from validators RPC (domain -> ed_pub) ───────────────
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dh_commit_reveal_audit: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: resolve window bounds ─────────────────────────────────────────────
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
  echo "operator_dh_commit_reveal_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 4: temp files (validators JSON in, stats + offenders out) ────────────
TMP_VAL=$(mktemp 2>/dev/null) || {
  echo "operator_dh_commit_reveal_audit: cannot create temp file" >&2; exit 1; }
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_dh_commit_reveal_audit: cannot create temp file" >&2; exit 1; }
TMP_BREAKS=$(mktemp 2>/dev/null) || {
  echo "operator_dh_commit_reveal_audit: cannot create temp file" >&2; exit 1; }
trap 'rm -f "$TMP_VAL" "$TMP_STATS" "$TMP_BREAKS" 2>/dev/null' EXIT
printf '%s' "$VAL_JSON" >"$TMP_VAL"

# ── Step 5: walk window + run the three binding checks in Python ──────────────
# One block-info round-trip per block. Python re-derives the
# SHA256(secret||pubkey) commitment per slot, tracks array-shape and
# secret-reuse, and emits a single TSV stats line + a small TSV of up to
# the first few binding-break offenders for the human digest.
python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_VAL" "$TMP_STATS" "$TMP_BREAKS" <<'PY'
import json, subprocess, sys, hashlib

determ, port, from_h, to_h, val_path, stats_path, breaks_path = sys.argv[1:8]
from_h = int(from_h)
to_h   = int(to_h)

ZERO64 = "0" * 64  # all-zero 32-byte (64 hex chars) sentinel

def norm_hex(s):
    if not isinstance(s, str):
        return ""
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s

def hex_bytes(s):
    """Return bytes for a hex string, or None if it isn't valid hex."""
    try:
        return bytes.fromhex(s)
    except Exception:
        return None

# ── domain -> ed_pub (normalized hex) from the validators snapshot ────────────
try:
    with open(val_path, "r", encoding="utf-8") as f:
        validators = json.loads(f.read())
except Exception:
    sys.stderr.write("operator_dh_commit_reveal_audit: malformed validators JSON\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_dh_commit_reveal_audit: validators RPC returned non-array\n")
    sys.exit(1)

pubkeys = {}  # domain -> normalized ed_pub hex
for v in validators:
    if not isinstance(v, dict):
        continue
    dom = v.get("domain")
    pk  = norm_hex(v.get("ed_pub"))
    if isinstance(dom, str) and dom and pk:
        pubkeys[dom] = pk

# ── per-block walk ────────────────────────────────────────────────────────────
total_blocks      = 0
total_slots       = 0
unresolved_slots  = 0   # creator pubkey not in the live validators snapshot
checked_slots     = 0   # slots where the binding was actually recomputed
binding_breaks    = []  # (height, slot, domain, expected16, stored16)
shape_mismatches  = []  # (height, n_creators, n_inputs, n_secrets)
secret_seen       = {}  # non-zero secret hex -> (first_height, first_slot)
secret_reuses     = []  # (first_height, dup_height, dup_slot)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_dh_commit_reveal_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dh_commit_reveal_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dh_commit_reveal_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators")
    inputs   = blk.get("creator_dh_inputs")
    secrets  = blk.get("creator_dh_secrets")
    if not isinstance(creators, list): creators = []
    if not isinstance(inputs, list):   inputs   = []
    if not isinstance(secrets, list):  secrets  = []

    total_blocks += 1

    nc, ni, ns = len(creators), len(inputs), len(secrets)
    # (B) array shape: the three arrays must be equal length on every
    # produced block (validator.cpp rejects any divergence).
    if not (nc == ni == ns):
        shape_mismatches.append((h, nc, ni, ns))
        # Still attempt per-slot checks over the safe overlap so a single
        # malformed block doesn't blind the rest of the audit.

    n = min(nc, ni, ns)
    total_slots += n
    for i in range(n):
        dom        = creators[i] if isinstance(creators[i], str) else ""
        commit_hex = norm_hex(inputs[i])
        secret_hex = norm_hex(secrets[i])

        # (C) secret reuse: track non-zero revealed secrets for freshness.
        if secret_hex and secret_hex != ZERO64:
            if secret_hex in secret_seen:
                fh, fs = secret_seen[secret_hex]
                secret_reuses.append((fh, h, i))
            else:
                secret_seen[secret_hex] = (h, i)

        # (A) binding: SHA256(secret || pubkey) == stored commit.
        pk_hex = pubkeys.get(dom)
        if pk_hex is None:
            unresolved_slots += 1
            continue
        sb = hex_bytes(secret_hex)
        pb = hex_bytes(pk_hex)
        if sb is None or pb is None or commit_hex == "":
            # Material we can't parse — count as a break (these fields are
            # mandatory + well-formed on every produced block).
            binding_breaks.append((h, i, dom, "(unverifiable)", commit_hex[:16] or "(empty)"))
            checked_slots += 1
            continue
        expected = hashlib.sha256(sb + pb).hexdigest()
        checked_slots += 1
        if expected != commit_hex:
            binding_breaks.append((h, i, dom, expected[:16], commit_hex[:16]))

# ── emit offenders digest (up to first 5 binding breaks) ──────────────────────
with open(breaks_path, "w", encoding="utf-8") as f:
    for (hh, si, dom, exp, sto) in binding_breaks[:5]:
        # domain may contain odd chars; keep the digest TSV-safe.
        safe = (dom or "").replace("\t", " ").replace("\n", " ")
        f.write(f"{hh}\t{si}\t{safe}\t{exp}\t{sto}\n")

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks,
        total_slots,
        checked_slots,
        unresolved_slots,
        len(binding_breaks),
        len(shape_mismatches),
        len(secret_reuses),
        # First-offender height samples for the digest (0 sentinel if none).
        (binding_breaks[0][0]   if binding_breaks   else 0),
        (shape_mismatches[0][0] if shape_mismatches else 0),
        (secret_reuses[0][1]    if secret_reuses    else 0),
    ]) + "\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dh_commit_reveal_audit: commit-reveal walk failed" >&2
  exit 1
fi

# ── Step 6: read stats back ───────────────────────────────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_dh_commit_reveal_audit: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'    "$STATS_LINE" | cut -f1)
TOTAL_SLOTS=$(printf '%s'     "$STATS_LINE" | cut -f2)
CHECKED_SLOTS=$(printf '%s'   "$STATS_LINE" | cut -f3)
UNRESOLVED_SLOTS=$(printf '%s' "$STATS_LINE" | cut -f4)
BINDING_BREAKS=$(printf '%s'  "$STATS_LINE" | cut -f5)
SHAPE_MISMATCH=$(printf '%s'  "$STATS_LINE" | cut -f6)
SECRET_REUSES=$(printf '%s'   "$STATS_LINE" | cut -f7)
FIRST_BREAK=$(printf '%s'     "$STATS_LINE" | cut -f8)
FIRST_SHAPE=$(printf '%s'     "$STATS_LINE" | cut -f9)
FIRST_REUSE=$(printf '%s'     "$STATS_LINE" | cut -f10)

# ── Step 7: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

if [ "${BINDING_BREAKS:-0}" -gt 0 ] 2>/dev/null; then add_anom "dh_binding_break"; fi
if [ "${SHAPE_MISMATCH:-0}" -gt 0 ] 2>/dev/null; then add_anom "dh_array_shape_mismatch"; fi
if [ "${SECRET_REUSES:-0}" -gt 0 ] 2>/dev/null;  then add_anom "dh_secret_reuse"; fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 8: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,"total_slots":%s,"checked_slots":%s,"unresolved_slots":%s,' \
    "$TOTAL_BLOCKS" "$TOTAL_SLOTS" "$CHECKED_SLOTS" "$UNRESOLVED_SLOTS"
  printf '"binding_breaks":%s,"array_shape_mismatches":%s,"secret_reuses":%s,' \
    "$BINDING_BREAKS" "$SHAPE_MISMATCH" "$SECRET_REUSES"
  printf '"first_binding_break_height":%s,"first_shape_mismatch_height":%s,"first_secret_reuse_height":%s,' \
    "$FIRST_BREAK" "$FIRST_SHAPE" "$FIRST_REUSE"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_dh_commit_reveal_audit: no anomalies (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks, $CHECKED_SLOTS slots checked)"
  else
    echo "=== DH commit-reveal audit (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks) ==="
    echo "Committee slots seen:     $TOTAL_SLOTS"
    echo "Slots binding-checked:    $CHECKED_SLOTS  (SHA256(secret||pubkey) vs creator_dh_inputs[i])"
    echo "Slots unresolved pubkey:  $UNRESOLVED_SLOTS  (creator not in live validators snapshot; informational)"
    echo "Binding breaks:           $BINDING_BREAKS"
    echo "Array-shape mismatches:   $SHAPE_MISMATCH  (creators/inputs/secrets length divergence)"
    echo "Repeated non-zero secret: $SECRET_REUSES"
    if [ "$ANOM_ONLY" != "1" ] && [ -s "$TMP_BREAKS" ]; then
      echo "First binding break(s):"
      while IFS=$'\t' read -r BH BSLOT BDOM BEXP BSTO; do
        printf "  block %s slot %s [%s]: expected %s... stored %s...\n" "$BH" "$BSLOT" "$BDOM" "$BEXP" "$BSTO"
      done <"$TMP_BREAKS"
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] commit-reveal binding holds on every checked slot; arrays well-shaped; no secret reuse"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,dh_binding_break,*)
          echo "  dh_binding_break        : $BINDING_BREAKS slot(s) where SHA256(secret||pubkey) != stored commit (first @ block $FIRST_BREAK) — tampered/mis-restored chain or a block that bypassed validator.cpp::check_creator_dh_secrets" ;;
      esac
      case ",$ANOMALIES," in
        *,dh_array_shape_mismatch,*)
          echo "  dh_array_shape_mismatch : $SHAPE_MISMATCH block(s) with unequal creators/inputs/secrets lengths (first @ block $FIRST_SHAPE) — malformed/illegal block" ;;
      esac
      case ",$ANOMALIES," in
        *,dh_secret_reuse,*)
          echo "  dh_secret_reuse         : $SECRET_REUSES repeated non-zero revealed secret(s) (first dup @ block $FIRST_REUSE) — replayed reveal (contribution-layer grinding signal)" ;;
      esac
    fi
  fi
fi

# ── Step 9: exit-code policy ──────────────────────────────────────────────────
# Same convention as the sibling audits: exit 2 only when --anomalies-only is
# set AND >= 1 anomaly fired. Default informational mode always exits 0 if the
# RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
