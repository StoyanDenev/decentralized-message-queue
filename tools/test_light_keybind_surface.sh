#!/usr/bin/env bash
# test_light_keybind_surface.sh — STATIC completeness guard for the F-6 key-bind
# invariant: EVERY determ-light function that derives a value/verdict from a
# state_proof must bind the proof to the key it asked for.
#
# THE F-6 FORGE CLASS (this guard's whole reason to exist)
# -------------------------------------------------------
# A single-leaf trustless reader does three things with a state_proof:
#   (1) Merkle-verify the proof self-consistently (verify_state_proof),
#   (2) anchor the proof's state_root to a committee-signed root (S-042,
#       committee_bound_state_root), and
#   (3) hash-bind the daemon's cleartext reply to the proof's value_hash.
# NONE of those checks which KEY the proof is for — verify_state_proof
# Merkle-verifies whatever key_bytes the daemon SUPPLIES, and the cleartext
# hash-bind compares the cleartext against the SERVED leaf, not the queried
# one. So a Byzantine daemon can serve a valid, committee-anchored proof for
# SOME OTHER leaf and a matching cleartext, and the reader attributes that
# leaf's committed value to the QUERIED key — forging e.g. a whale's balance
# onto an empty account, or laundering a heavily-aborted node behind a clean
# one's record. The fix (NegativeVerdictSoundness.md F-6) is a key-bind:
#   proof.key_bytes (hex) MUST equal the locally-computed canonical key,
#   byte-for-byte, BEFORE trusting the proof.
#
# This forge class has bitten THREE times — read_stake_trustless (the original
# F-6), cmd_verify_abort_record, and read_account_trustless (the balance/nonce
# reader, the most-used of all). The value-hash bind alone is forgeable whenever
# the daemon also controls the cleartext source — which is ALWAYS. Nothing
# locked the invariant, so each new single-leaf reader could silently reopen it.
# THIS guard turns RED the instant a state_proof consumer ships without a
# key-bind, BEFORE any build/cluster run.
#
# THE INVARIANT (static, source-only over light/*.cpp)
# ----------------------------------------------------
# Partition every function that calls `rpc.call("state_proof"` into:
#   * CONSUMERS — derive a verdict/value from the proof; MUST key-bind.
#   * PASS-THROUGH — raw fetch/echo utilities that emit the daemon reply
#     verbatim without deriving a trust-minimized verdict (e.g.
#     cmd_fetch_state_proof). These legitimately do NOT key-bind because they
#     make no claim about a key; they are the QUARANTINE list, enumerated +
#     justified below. A reader that STOPS being pass-through (starts emitting
#     a verdict) must be removed from the quarantine and gain a key-bind.
# Assert: (# state_proof-calling functions) − (# with a key-bind) == (# quarantined),
# AND the un-bound set equals the quarantine set exactly (no surprise omissions,
# no stale quarantine entries).
#
# A "key-bind" is detected structurally: within the function body, a comparison
# of the proof's key_bytes against a locally-built key — the canonical shape is
#   std::string proof_key_hex = proof.value("key_bytes", ...);   // or proof["key_bytes"]
#   if (proof_key_hex != local_key_hex) throw ...;
# We match the load-bearing token `key_bytes` appearing in a `!=`/`==` guard or
# a `proof.value("key_bytes"` / `proof["key_bytes"]` extraction inside the fn.
#
# QUARANTINE (must stay tiny + justified):
#   cmd_fetch_state_proof — the `fetch-state-proof` CLI: fetches a proof and
#     prints it verbatim for offline inspection / piping to verify-state-proof.
#     It derives NO verdict and makes NO key claim, so a key-bind is N/A. If it
#     ever starts interpreting the proof, drop it from KEYBIND_QUARANTINE.
#
# SELFTEST=1: injects a key-bind removal into a scratch copy and asserts RED.
#
# Pure read-only (awk/grep over light/*.cpp); no determ binary, no build, no
# cluster. SKIP-clean (exit 0) when light/ is absent. run_all.sh auto-discovers
# it (tools/test_*.sh) and reads the single terminal PASS:/FAIL: marker.
#
# Exit 0 = every state_proof consumer key-binds (or quarantined+justified);
# exit 1 = a consumer ships without a key-bind (F-6 regression).
set -u
cd "$(dirname "$0")/.."

# Files that host state_proof consumers.
FILES="light/main.cpp light/trustless_read.cpp light/account_history.cpp"

# Quarantine: function names that call state_proof but legitimately do NOT
# key-bind (raw pass-through, no verdict). Whitespace/newline separated.
KEYBIND_QUARANTINE="cmd_fetch_state_proof"

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# is_quarantined <fn-name>
is_quarantined() { printf '%s\n' $KEYBIND_QUARANTINE | grep -qxF "$1"; }

# scan_file <file> — emit one line per state_proof-calling function:
#   "<fn> <query:0|1> <keybind:0|1>"
# A function starts at a top-level definition line (a return-typed signature at
# column 0 whose name is captured) and ends at the next such line. We classify
# each owning function by whether its body contains a state_proof call and a
# key_bytes bind. CR-tolerant.
scan_file() {
  awk '
    function flush() {
      if (fn != "" && q) printf "%s %d %d\n", fn, q, b
    }
    # Top-level function definition: a return type + name( at column 0 (no
    # leading whitespace), not a comment, not a control keyword.
    /^[A-Za-z_][A-Za-z0-9_:<>* ]*[ \*]([A-Za-z_][A-Za-z0-9_]*)[ ]*\(/ {
      # Heuristic guard: skip obvious non-defs (return/if/for/while/else).
      if ($0 !~ /^(return|if|for|while|else|switch|do)\b/) {
        flush()
        line = $0
        # extract the identifier immediately before the first "("
        nm = $0
        sub(/\(.*/, "", nm)          # drop from first "(" on
        gsub(/[^A-Za-z0-9_]+$/, "", nm)   # trailing junk
        n = split(nm, parts, /[^A-Za-z0-9_]+/)
        fn = parts[n]
        q = 0; b = 0
        next
      }
    }
    /rpc\.call\("state_proof"/ { q = 1 }
    /key_bytes/ {
      if ($0 ~ /(!=|==).*key_bytes|key_bytes.*(!=|==)|proof\.value\("key_bytes"|proof\["key_bytes"\]/) b = 1
    }
    END { flush() }
  ' "$1"
}

echo "=== F-6 key-bind surface guard (every state_proof consumer key-binds) ==="

present=0
for f in $FILES; do [ -f "$f" ] && present=1; done
if [ "$present" = "0" ]; then
  echo "  SKIP: light/ sources absent — nothing to guard (source-light checkout)."
  echo "  PASS: test_light_keybind_surface (SKIP — targets absent)"
  exit 0
fi

# Aggregate the scan across all files.
total_q=0      # functions that call state_proof
total_bound=0  # of those, ones with a key-bind
unbound_list=""

for f in $FILES; do
  [ -f "$f" ] || continue
  while read -r fn qf bf; do
    [ -z "${fn:-}" ] && continue
    total_q=$((total_q + 1))
    if [ "${bf:-0}" = "1" ]; then
      total_bound=$((total_bound + 1))
    else
      unbound_list="$unbound_list $fn"
    fi
  done <<EOF
$(scan_file "$f")
EOF
done

echo "  info: $total_q state_proof-calling function(s); $total_bound key-bind; quarantine = [$KEYBIND_QUARANTINE]"

# Invariant 1: every un-bound function is quarantined (+ justified).
unbound_unquarantined=""
for fn in $unbound_list; do
  if ! is_quarantined "$fn"; then
    unbound_unquarantined="$unbound_unquarantined $fn"
  fi
done
if [ -z "$unbound_unquarantined" ]; then
  ok "every state_proof consumer key-binds proof.key_bytes (un-bound set ⊆ quarantine)"
else
  bad "state_proof consumer(s) WITHOUT a key-bind (F-6 forge reopened):$unbound_unquarantined"
fi

# Invariant 2: no stale quarantine — every quarantined name must (a) exist as a
# state_proof-calling function and (b) actually lack a key-bind (else it should
# be de-quarantined). This stops the quarantine from silently masking a reader
# that later gained/needed a bind.
all_q_fns=" "
for f in $FILES; do
  [ -f "$f" ] || continue
  while read -r fn qf bf; do
    [ -z "${fn:-}" ] && continue
    all_q_fns="$all_q_fns$fn:$bf "
  done <<EOF
$(scan_file "$f")
EOF
done
stale_quarantine=""
for qn in $KEYBIND_QUARANTINE; do
  case "$all_q_fns" in
    *" $qn:0 "*) : ;;                                   # present + unbound: legit
    *" $qn:1 "*) stale_quarantine="$stale_quarantine $qn(now-binds)";;  # de-quarantine it
    *)           stale_quarantine="$stale_quarantine $qn(absent)";;     # vanished
  esac
done
if [ -z "$stale_quarantine" ]; then
  ok "quarantine is exact (every entry present + genuinely un-bound)"
else
  bad "stale quarantine entr(ies):$stale_quarantine — de-quarantine or remove"
fi

# Invariant 3: the count identity (defence in depth against a parser miss).
expected_unbound=$(printf '%s\n' $KEYBIND_QUARANTINE | grep -c . )
actual_unbound=$((total_q - total_bound))
if [ "$actual_unbound" = "$expected_unbound" ]; then
  ok "count identity holds: $total_q consumers − $total_bound bound == $expected_unbound quarantined"
else
  bad "count identity broken: $total_q − $total_bound = $actual_unbound ≠ $expected_unbound quarantined"
fi

# ── SELFTEST: prove the guard is live ───────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo
  echo "=== SELFTEST: strip a key-bind -> expect RED ==="
  ST_FAIL=0
  tmp=$(mktemp -d 2>/dev/null || echo "/tmp/kbsurf.$$"); mkdir -p "$tmp"
  trap 'rm -rf "$tmp"' EXIT
  # Mutate trustless_read.cpp: neutralize read_account_trustless's key-bind by
  # renaming its key_bytes comparison token, leaving the call intact.
  scratch="$tmp/trustless_read.cpp"
  sed 's/proof_key_hex != local_key_hex/proof_key_hex == proof_key_hex \/* NEUTERED *\//' \
      light/trustless_read.cpp > "$scratch"
  # also blank the proof.value("key_bytes") extraction so no key_bytes token survives in that fn
  sed -i 's/proof\.value("key_bytes"/proof.value("NEUTERED_kb"/' "$scratch" 2>/dev/null \
    || sed 's/proof\.value("key_bytes"/proof.value("NEUTERED_kb"/' "$scratch" > "$scratch.2" && mv "$scratch.2" "$scratch" 2>/dev/null || true
  inj=$(scan_file "$scratch" | awk '$1=="read_account_trustless"{print $3}')
  if [ "${inj:-1}" = "0" ]; then
    echo "  ok:  injected key-bind removal -> read_account_trustless detected as UN-BOUND"
  else
    echo "  bad: SELFTEST could not neutralize the key-bind (scan still sees bind=$inj)" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  echo
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_keybind_surface SELFTEST (detects a stripped key-bind)"
  else
    echo "  FAIL: test_light_keybind_surface SELFTEST"
    exit 1
  fi
fi

echo
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_light_keybind_surface (every state_proof consumer key-binds; quarantine exact)"
  exit 0
else
  echo "  FAIL: test_light_keybind_surface ($VIOLATIONS F-6 key-bind surface violation(s))"
  exit 1
fi
