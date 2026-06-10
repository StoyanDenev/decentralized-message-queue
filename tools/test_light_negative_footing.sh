#!/usr/bin/env bash
# test_light_negative_footing.sh — contract for the F-2 `negative_footing` field
# on determ-light's negative-verdict --json output (NegativeVerdictSoundness.md F-2).
#
# WHAT THIS LOCKS
# --------------
# NegativeVerdictSoundness.md proves the determ-light negative verdict has a
# NON-UNIFORM trust footing:
#   * CRYPTOGRAPHIC — sound under A1/A2 against a fully-Byzantine daemon:
#       - `verify-tx-inclusion` NOT-INCLUDED (full-set tx_root recompute, NV-1);
#       - `verify-unstake-eligibility` NO-STAKE when the s: leaf EXISTS with
#         locked == 0 (a committee-anchored POSITIVE proof of a zero stake —
#         negative-by-proven-zero-value, the third footing pattern).
#   * DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
#     negative-honesty premise (NV-2/NV-3): the state-proof absence negatives
#     of `verify-receipt-inclusion` (i:), `verify-merge-state` (m:),
#     `verify-param-change` (p:), `verify-account` (a: NOT-CREATED),
#     `verify-registrant` (r:), `verify-dapp-registration` (d:),
#     `verify-unstake-eligibility` (s:-absence NO-STAKE), and
#     `verify-abort-record` (b: NOT-RECORDED).
# F-2 surfaces the distinction in --json so a downstream consumer applies NV-6
# clause (2) (authoritative absence) vs clause (3) ("no proof obtained")
# AUTOMATICALLY rather than hard-coding which command it called.
#
# CENSUS (the count-lock; a new negative-verdict command that forgets the
# field, a dropped site, or a wrong value turns this RED):
#   * `out["negative_footing"] = "..."` assignment form:
#       2 × "cryptographic"   (tx-inclusion; unstake locked==0 arm)
#       7 × "daemon_asserted" (i: m: p: a: r: d: + unstake absence arm)
#   * JSON initializer-list form `{"negative_footing", "daemon_asserted"}`:
#       1 × (verify-abort-record's NOT-RECORDED block builds its json inline)
#   = 10 emissions total. BOTH shapes are counted — an earlier revision of
#   this guard counted only the assignment form and silently missed the b:
#   reader's initializer-list emission (NegativeVerdictSoundness.md F-2).
#
# GATING: every assignment-form emission must be gated, on the immediately
# preceding line, by a recognized NEGATIVE-verdict condition —
# InclusionVerdict::NOT_INCLUDED, AccountExistVerdict::NOT_CREATED, or the
# UnstakeVerdict::NO_STAKE two-arm split — never emitted for a positive or
# UNVERIFIABLE verdict. The unstake arms additionally pin value-per-gate:
# `NO_STAKE && have_stake` → "cryptographic" (proven zero) and
# `NO_STAKE && !have_stake` → "daemon_asserted" (absence). The init-list
# emission must sit inside the NOT-RECORDED json object.
#
# F-5 RATCHET: the unstake catch must match ONLY the `not_found` absence
# marker. The former `msg.find("no verified")` disjunct matched read_stake_-
# trustless's step-3 throw prefix ("domain has no verified stake leaf?"),
# which wraps EVERY state_proof RPC error — so any daemon refusal was
# classified NO-STAKE instead of UNVERIFIABLE (fail-open on the negative
# surface; NegativeVerdictSoundness.md F-5, fixed). It must not return.
#
# WHAT RUNS HERE (offline, no cluster) vs CI: this is the OFFLINE source
# contract (grep/awk over light/main.cpp); the live behavioral leg — drive
# each command to its negative against a cluster and assert the emitted
# footing — is a CI/WSL2 leg, documented + SKIPPED here, not faked.
#
# Pure read-only; no determ binary, no build, no cluster. SKIP-clean (exit 0)
# when light/main.cpp is absent.
# Run from repo root: bash tools/test_light_negative_footing.sh
set -u
cd "$(dirname "$0")/.."

TARGET="light/main.cpp"

pass=0; fail=0; skip=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
no()  { echo "  FAIL: $1" >&2; fail=$((fail+1)); }
skp() { echo "  SKIP: $1"; skip=$((skip+1)); }

if [ ! -f "$TARGET" ]; then
    echo "  SKIP: $TARGET absent — nothing to contract (source-light checkout)."
    echo "  PASS: test_light_negative_footing (SKIP — target absent)"
    exit 0
fi

echo "=== F-2 negative_footing source contract ($TARGET) ==="

# ── 1. census: 2 cryptographic + 7 daemon_asserted assignments + 1 init-list ────
n_crypto=$(grep -cE 'out\["negative_footing"\][[:space:]]*=[[:space:]]*"cryptographic"' "$TARGET")
n_daemon=$(grep -cE 'out\["negative_footing"\][[:space:]]*=[[:space:]]*"daemon_asserted"' "$TARGET")
n_initlist=$(grep -cE '\{"negative_footing",[[:space:]]*"daemon_asserted"\}' "$TARGET")
if [ "$n_crypto" = "2" ]; then ok "exactly 2 cryptographic footings (tx-inclusion NV-1; unstake proven-zero-stake)"
else no "expected 2 'cryptographic' negative_footing assignments, got $n_crypto"; fi
if [ "$n_daemon" = "7" ]; then ok "exactly 7 daemon_asserted assignment-form footings (i:/m:/p:/a:/r:/d: + s:-absence)"
else no "expected 7 'daemon_asserted' negative_footing assignments, got $n_daemon"; fi
if [ "$n_initlist" = "1" ]; then ok "exactly 1 initializer-list daemon_asserted footing (b: NOT-RECORDED)"
else no "expected 1 init-list '{\"negative_footing\", \"daemon_asserted\"}', got $n_initlist"; fi

# ── 2+3. every assignment-form emission is GATED on a negative verdict AND its
#         VALUE matches that gate's footing (per-site value-pin, not just a count).
# This closes the paired-cross-site-swap false-pass: mislabeling tx-inclusion as
# daemon_asserted while mislabeling i: as cryptographic preserves the 2/7 counts
# but is caught here because each emission's value is pinned to its own gate.
# Gate→footing map (1-line proximity; the emission is a single gated statement):
#   cryptographic gates: `r.verdict == InclusionVerdict::NOT_INCLUDED)` (tx-inclusion,
#                        VerifyResult member — note the `r.` prefix) and
#                        `UnstakeVerdict::NO_STAKE && have_stake)` (proven-zero).
#   daemon_asserted gates: bare `(verdict == InclusionVerdict::NOT_INCLUDED)` (i/m/p/r/d),
#                        `AccountExistVerdict::NOT_CREATED)` (a:), and
#                        `UnstakeVerdict::NO_STAKE && !have_stake)` (s: absence).
# A comment line can never satisfy a gate (prev must be real code), closing the
# comment-spoofed-gate false-pass.
gate_chk=$(awk '
    function iscomment(s){ return s ~ /^[[:space:]]*\/\// }
    /out\["negative_footing"\][[:space:]]*=/ {
        val = ($0 ~ /"cryptographic"/) ? "C" : (($0 ~ /"daemon_asserted"/) ? "D" : "?")
        gate = "none"
        if (iscomment(prev)) gate = "comment"
        else if (prev ~ /r\.verdict == InclusionVerdict::NOT_INCLUDED\)/)     gate = "C"
        else if (prev ~ /UnstakeVerdict::NO_STAKE && have_stake\)/)           gate = "C"
        else if (prev ~ /UnstakeVerdict::NO_STAKE && !have_stake\)/)          gate = "D"
        else if (prev ~ /[^.]verdict == InclusionVerdict::NOT_INCLUDED\)/)    gate = "D"
        else if (prev ~ /AccountExistVerdict::NOT_CREATED\)/)                 gate = "D"
        n++
        if (gate == "none" || gate == "comment") { ungated++; print "    ungated/comment-gated @" NR ": " $0 > "/dev/stderr" }
        else if (gate != val) { mism++; print "    footing/gate mismatch @" NR " (gate=" gate " value=" val "): " $0 > "/dev/stderr" }
        if (gate == "C") seen_c++; if (gate == "D") seen_d++
    }
    { prev=$0 }
    END { printf "%d %d %d %d %d", ungated+0, mism+0, n+0, seen_c+0, seen_d+0 }
' "$TARGET")
g_ungated=$(echo "$gate_chk" | cut -d' ' -f1); g_mism=$(echo "$gate_chk" | cut -d' ' -f2)
g_n=$(echo "$gate_chk" | cut -d' ' -f3); g_c=$(echo "$gate_chk" | cut -d' ' -f4); g_d=$(echo "$gate_chk" | cut -d' ' -f5)
if [ "$g_ungated" = "0" ]; then ok "all $g_n assignment-form emissions gated on real-code negative verdicts (no comment-spoofed gate)"
else no "$g_ungated negative_footing emission(s) ungated or comment-gated — would mislabel a positive/unverifiable verdict"; fi
if [ "$g_mism" = "0" ]; then ok "every emission's value matches its gate's footing (C-gate→cryptographic, D-gate→daemon_asserted) — paired-swap proof"
else no "$g_mism negative_footing emission(s) whose value contradicts its verdict gate (footing mislabeled)"; fi
if [ "$g_c" = "2" ] && [ "$g_d" = "7" ]; then ok "gate census: 2 cryptographic-gated + 7 daemon_asserted-gated assignment emissions"
else no "gate census off: expected 2 C-gated + 7 D-gated, got $g_c C + $g_d D"; fi

# ── 4. the init-list emission sits inside the NOT-RECORDED json object ──────────
b_ok=$(awk '
    { for (i=5; i>1; i--) ctx[i]=ctx[i-1]; ctx[1]=$0 }
    /\{"negative_footing",[[:space:]]*"daemon_asserted"\}/ {
        found=0; for (i=1; i<=5; i++) if (ctx[i] ~ /"NOT-RECORDED"/) found=1
        if (!found) bad++
    }
    END { printf "%d", bad+0 }
' "$TARGET")
if [ "$b_ok" = "0" ]; then ok "init-list emission co-located with the NOT-RECORDED verdict (b: reader)"
else no "init-list negative_footing emission NOT inside a NOT-RECORDED json object"; fi

# ── 5. F-5 ratchet (two-sided): the unstake absence matcher must classify on
#      the not_found marker ONLY, and must rethrow everything else. The negative
#      leg bars the over-broad "no verified" disjunct from returning; the
#      positive leg bars the matcher being deleted / short-circuited to `if(true)`
#      (which would classify EVERY read_stake_trustless failure as NO-STAKE —
#      the same fail-open F-5 describes). Without the positive leg, `if(true)`
#      passes the guard (empirically confirmed false-pass).
if ! grep -q 'msg.find("no verified")' "$TARGET"; then
    ok "F-5 ratchet (neg): no msg.find(\"no verified\") disjunct (only the not_found marker classifies NO-STAKE)"
else
    no "F-5 regression: msg.find(\"no verified\") is back — every state_proof RPC error would classify as NO-STAKE instead of UNVERIFIABLE"
fi
# Positive leg: the unstake catch must contain the exact not_found matcher AND a
# bare `throw;` rethrow within a 6-line window (the else arm that fails closed).
f5_pos=$(awk '
    /if \(msg.find\("not_found"\) != std::string::npos\)/ { win=6; have_match=1 }
    win>0 { if ($0 ~ /^[[:space:]]*throw;/) have_throw=1; win-- }
    END { printf "%d %d", have_match+0, have_throw+0 }
' "$TARGET")
f5_m=$(echo "$f5_pos" | cut -d' ' -f1); f5_t=$(echo "$f5_pos" | cut -d' ' -f2)
if [ "$f5_m" = "1" ] && [ "$f5_t" = "1" ]; then
    ok "F-5 ratchet (pos): unstake catch keys on msg.find(\"not_found\") and rethrows (bare throw;) on any other failure"
else no "F-5 regression: the not_found matcher (found=$f5_m) or its fail-closed rethrow (found=$f5_t) is missing — the absence classifier may be deleted/short-circuited (fail-open)"; fi

# ── 6. total emissions == 10 (one per negative-verdict surface; no stragglers) ──
n_total=$(( $(grep -cE 'out\["negative_footing"\]' "$TARGET") + n_initlist ))
if [ "$n_total" = "10" ]; then ok "exactly 10 negative_footing emissions total (2 cryptographic + 8 daemon_asserted across both shapes)"
else no "expected 10 negative_footing emissions total, got $n_total (a command added/removed without updating the contract?)"; fi

# ── 7. live behavioral leg — CI/WSL2 cluster only ───────────────────────────────
echo
echo "=== live behavioral leg (drive each command to its negative, assert footing) ==="
skp "live negative_footing leg (needs a cluster: tx missing-tx + unstake locked==0 -> cryptographic; i:/m:/p:/a:/r:/d:/s:-absence/b: not_found -> daemon_asserted) — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
if [ "$fail" = "0" ]; then
    echo "  PASS: test_light_negative_footing (F-2 source contract; live leg is a CI leg)"
    exit 0
else
    echo "  FAIL: test_light_negative_footing"
    exit 1
fi
