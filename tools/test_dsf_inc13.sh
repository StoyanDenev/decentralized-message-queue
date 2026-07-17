#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 13 — `--gen-seed`:
# decouple the §Q5 PROFILE draw from the §Q6 fault REALIZATION on the CLI.
#
# Before inc-13, `--generate N --seed S` used S for BOTH the generator seed
# (which fault profiles are drawn) and the run seed (which individual
# messages drop/duplicate), so a generated profile could only ever be run at
# ONE realization — the coverage gap recorded by the inc-9/10 review.
# `--gen-seed G` pins the drawn profile set to G while `--seed S` varies the
# realization independently: the sweep can now hammer one profile under many
# realizations. Omitted, --gen-seed collapses to --seed (byte-identical to
# the old behavior).
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. REGRESSION: `--generate 6 --seed S --list` is byte-identical to
#      `--generate 6 --seed S --gen-seed S --list` (the collapsed form is
#      unchanged) — for two different S.
#   2. PROFILE PINNING: with a fixed --gen-seed, three different --seed
#      values produce byte-identical --list output (profiles are a function
#      of the gen seed alone).
#   3. PROFILE VARIANCE: two different --gen-seed values produce DIFFERENT
#      --list output (the flag actually drives the draw).
#   4. REALIZATION VARIANCE: with a fixed --gen-seed, at least one generated
#      variant's trace DIFFERS across two run seeds (the run seed actually
#      drives the fault realization).
#   5. REPLAY: the same (--generate, --gen-seed, --seed, scenario) tuple
#      replays byte-identically, and the run exits 0 non-vacuously.
#   6. --gen-seed works with --template (pinned profiles on a non-default
#      template).
#   7. Usage errors: a garbage --gen-seed exits 2; a dangling --gen-seed
#      (no value) exits 2.
#
# Exit 0 = all assertions passed OR clean SKIP.

set -u
cd "$(dirname "$0")/.."

DSF=""
if [ -n "${DETERM_DSF_BIN:-}" ] && [ -x "${DETERM_DSF_BIN:-}" ]; then DSF="$DETERM_DSF_BIN"
elif [ -x "build/Release/determ-dsf.exe" ]; then DSF="build/Release/determ-dsf.exe"
elif [ -x "build/determ-dsf.exe" ]; then DSF="build/determ-dsf.exe"
elif [ -x "build/determ-dsf" ]; then DSF="build/determ-dsf"
elif [ -x "build/Release/determ-dsf" ]; then DSF="build/Release/determ-dsf"
fi

if [ -z "$DSF" ]; then
    echo "SKIP test_dsf_inc13: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target)."
    exit 0
fi

echo "test_dsf_inc13: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc13.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

# ── assertion 1: the collapsed single-seed form is byte-identical ─────────────
for S in 0xFEED 0xA6; do
    "$DSF" --generate 6 --seed "$S" --list > "$TMPD/old_$S.txt" 2>&1
    "$DSF" --generate 6 --seed "$S" --gen-seed "$S" --list > "$TMPD/new_$S.txt" 2>&1
    if diff -q "$TMPD/old_$S.txt" "$TMPD/new_$S.txt" >/dev/null 2>&1 && [ -s "$TMPD/old_$S.txt" ]; then
        ok "no --gen-seed collapses to --seed (byte-identical --list @$S)"
    else
        fail "collapsed form changed at --seed $S (inc-5 regression!)"
    fi
done

# ── assertion 2: fixed --gen-seed pins profiles across run seeds ──────────────
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x1   --list > "$TMPD/pin1.txt" 2>&1
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x2   --list > "$TMPD/pin2.txt" 2>&1
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x999 --list > "$TMPD/pin3.txt" 2>&1
if diff -q "$TMPD/pin1.txt" "$TMPD/pin2.txt" >/dev/null 2>&1 \
   && diff -q "$TMPD/pin1.txt" "$TMPD/pin3.txt" >/dev/null 2>&1 \
   && [ -s "$TMPD/pin1.txt" ]; then
    ok "fixed --gen-seed pins the drawn profiles across 3 run seeds"
else
    fail "profiles varied with the run seed despite a fixed --gen-seed"
fi

# ── assertion 3: different --gen-seed values draw different profiles ──────────
"$DSF" --generate 6 --gen-seed 0xBB --seed 0x1 --list > "$TMPD/pinB.txt" 2>&1
if ! diff -q "$TMPD/pin1.txt" "$TMPD/pinB.txt" >/dev/null 2>&1; then
    ok "--gen-seed 0xAA vs 0xBB draw different profile sets"
else
    fail "two different --gen-seed values drew identical profiles"
fi

# ── assertion 4: run seed varies the realization under a pinned profile ───────
# The trace's FIRST line embeds the run seed (SCENARIO ... seed=0xS), so a
# whole-file diff differs unconditionally and would gate nothing. Strip the
# banner (tail -n +2) and compare the trace BODIES — only a genuinely
# different fault realization makes those diverge.
diffed=0
for v in gen_run_00 gen_run_01 gen_run_02 gen_run_03 gen_run_04 gen_run_05; do
    "$DSF" --generate 6 --gen-seed 0xAA --seed 0x1 --scenario "$v" --trace "$TMPD/${v}_s1.log" --quiet >/dev/null 2>&1
    "$DSF" --generate 6 --gen-seed 0xAA --seed 0x2 --scenario "$v" --trace "$TMPD/${v}_s2.log" --quiet >/dev/null 2>&1
    tail -n +2 "$TMPD/${v}_s1.log" > "$TMPD/${v}_s1.body" 2>/dev/null
    tail -n +2 "$TMPD/${v}_s2.log" > "$TMPD/${v}_s2.body" 2>/dev/null
    if [ -s "$TMPD/${v}_s1.body" ] && ! diff -q "$TMPD/${v}_s1.body" "$TMPD/${v}_s2.body" >/dev/null 2>&1; then
        diffed=1
        break
    fi
done
if [ "$diffed" -eq 1 ]; then
    ok "run seed varies the fault realization under a pinned profile ($v trace BODIES differ @0x1 vs @0x2, banner stripped)"
else
    fail "no generated variant's trace body differed across run seeds (realization not seed-driven?)"
fi

# ── assertion 5: full-tuple replay is byte-identical + non-vacuous ────────────
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x2 --scenario gen_run_00 --trace "$TMPD/rp_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x2 --scenario gen_run_00 --trace "$TMPD/rp_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --gen-seed 0xAA --seed 0x2 --scenario gen_run_00 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/rp_a.log" ] && diff -q "$TMPD/rp_a.log" "$TMPD/rp_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "same (--generate, --gen-seed, --seed, scenario) tuple replays byte-identically (§Q6)"
else
    fail "full-tuple replay failed (rc=$rc)"
fi

# ── assertion 6: --gen-seed composes with --template ──────────────────────────
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x1 --template quorum --list > "$TMPD/tq1.txt" 2>&1
"$DSF" --generate 6 --gen-seed 0xAA --seed 0x7 --template quorum --list > "$TMPD/tq2.txt" 2>&1
if diff -q "$TMPD/tq1.txt" "$TMPD/tq2.txt" >/dev/null 2>&1 \
   && grep -A1 '^  gen_run_00' "$TMPD/tq1.txt" | grep -qi 'quorum'; then
    ok "--gen-seed pins profiles on a non-default --template (quorum)"
else
    fail "--gen-seed + --template pinning failed"
fi

# ── assertion 7: usage errors exit 2 ──────────────────────────────────────────
"$DSF" --generate 6 --gen-seed zzz --list >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "garbage --gen-seed exits 2" || fail "garbage --gen-seed did not exit 2"
"$DSF" --generate 6 --list --gen-seed >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "dangling --gen-seed exits 2" || fail "dangling --gen-seed did not exit 2"
# Validation is UNCONDITIONAL (symmetric with --seed): garbage exits 2 even
# without --generate, and an explicitly EMPTY value cannot silently collapse.
"$DSF" --scenario gen_rotation_00 --seed 0xA6 --gen-seed zzz >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "garbage --gen-seed WITHOUT --generate exits 2" || fail "garbage --gen-seed without --generate did not exit 2"
"$DSF" --generate 6 --gen-seed "" --list >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "explicitly empty --gen-seed exits 2" || fail "explicitly empty --gen-seed did not exit 2"

# ── assertion 8: a failing generated variant's repro hint reproduces ──────────
# Force a liveness FAIL via --max-events truncation; the printed "reproduce
# with:" line must carry the FULL tuple (--generate/--gen-seed/--template).
OUT="$("$DSF" --generate 6 --gen-seed 0xCAFE --seed 0x2 --template rotation --scenario gen_run_00 --max-events 30 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] \
   && echo "$OUT" | grep -q -- "--generate 6" \
   && echo "$OUT" | grep -q -- "--gen-seed 0xcafe" \
   && echo "$OUT" | grep -q -- "--template rotation"; then
    ok "FAIL repro hint carries the full tuple (--generate/--gen-seed/--template)"
else
    fail "FAIL repro hint incomplete under the decoupled form (rc=$rc)"
fi
if echo "$OUT" | grep -q "gen-seed 0xcafe"; then
    ok "run banner surfaces the explicit gen-seed"
else
    fail "run banner missing the explicit gen-seed"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc13 (--gen-seed profile/realization decoupling: the collapsed single-seed form is byte-identical to before, a fixed --gen-seed pins the drawn profiles across run seeds and across --template, run seeds vary the realization, full tuples replay byte-identically, usage errors exit 2)"
    exit 0
else
    echo "  FAIL: test_dsf_inc13 ($FAILS assertion(s))"
    exit 1
fi
