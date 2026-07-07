#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 5 — the `--generate N --seed S`
# CLI (§Q5 parametric generation + §Q6 command-line reproducible replay).
#
# Increment 4 shipped the generator as a header with a BAKED-IN 6-variant set.
# Increment 5 exposes it on the command line: `--generate N --seed S` registers
# N reliable-broadcast variants (gen_run_00..0(N-1)) drawn from S, listable and
# runnable, without touching the baked inc-4 set. Build-agnostic: SKIP-clean if
# determ-dsf isn't built. Asserts:
#   1. --generate N --seed S --list shows exactly N gen_run_NN rows.
#   2. --generate adds NO self-test (with_selftest=false on the CLI path).
#   3. COUNT-PARAMETRIC: --generate 3 -> 3 rows; --generate 12 -> 12 rows.
#   4. GENERATOR-SEED byte-stable: same (N,S) --list twice -> byte-identical.
#   5. GENERATOR-SEED varied: a different S -> a different profile set.
#   6. The variants are PARAMETRIC not baked: gen_run_00 is unknown WITHOUT
#      --generate (fails with exit 2).
#   7. Each gen_run_K runs, converges non-vacuously, AND is run-deterministic
#      (§Q6: same --generate N --seed S --scenario gen_run_K twice -> identical
#      trace) — the command-line reproducible-replay contract.
#   8. The baked inc-4 set (gen_broadcast_00..05 + gen_overcount_selftest) is
#      still present under a plain --list (no regression).
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
    echo "SKIP test_dsf_inc5: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc5: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc5.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

SEED="0xC0FFEE"

# ── assertion 1: --generate 8 --seed S --list shows exactly 8 gen_run rows ──
L8="$("$DSF" --generate 8 --seed "$SEED" --list 2>&1)"
N_RUN="$(echo "$L8" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$N_RUN" -eq 8 ]; then ok "--generate 8 registers exactly 8 gen_run_NN variants"
else fail "--generate 8 produced $N_RUN gen_run_NN rows (expected 8)"; fi
for i in 00 01 07; do
    echo "$L8" | grep -q "^  gen_run_$i" || fail "--generate 8 missing gen_run_$i"
done

# ── assertion 2: --generate adds NO self-test on the CLI path ───────────────
if echo "$L8" | grep -q '^  gen_run_.*expect-violation'; then
    fail "a gen_run variant is marked expect-violation (CLI path must not add a self-test)"
else
    ok "--generate variants carry no self-test (with_selftest=false)"
fi

# ── assertion 3: count-parametric ──────────────────────────────────────────
for n in 3 12; do
    c="$("$DSF" --generate "$n" --seed "$SEED" --list 2>&1 | grep -cE '^  gen_run_[0-9][0-9]')"
    if [ "$c" -eq "$n" ]; then ok "--generate $n -> $n gen_run variants (count-parametric)"
    else fail "--generate $n -> $c gen_run variants (expected $n)"; fi
done

# ── assertion 4: generation is byte-stable per generator seed ──────────────
"$DSF" --generate 8 --seed "$SEED" --list > "$TMPD/gl_a" 2>&1
"$DSF" --generate 8 --seed "$SEED" --list > "$TMPD/gl_b" 2>&1
if diff -q "$TMPD/gl_a" "$TMPD/gl_b" >/dev/null 2>&1; then
    ok "generation is byte-stable across runs (same --generate N --seed S)"
else
    fail "generation --list DIFFERS across runs (non-deterministic generation!)"
fi

# ── assertion 5: a different seed yields a different profile set ────────────
PA="$("$DSF" --generate 8 --seed 0xC0FFEE  --list 2>&1 | grep -A1 '^  gen_run_' | grep -oE 'followers=[0-9]+ latency=[0-9]+ms jitter=[0-9]+ms drop=[0-9.]+ dup=[0-9.]+')"
PB="$("$DSF" --generate 8 --seed 0xBADBEEF --list 2>&1 | grep -A1 '^  gen_run_' | grep -oE 'followers=[0-9]+ latency=[0-9]+ms jitter=[0-9]+ms drop=[0-9.]+ dup=[0-9.]+')"
if [ -n "$PA" ] && [ "$PA" != "$PB" ]; then
    ok "a different --seed produces a different variant profile set (seed-driven)"
else
    fail "changing --seed did not change the generated variants (generator ignores seed?)"
fi

# ── assertion 6: variants are parametric, not baked ────────────────────────
"$DSF" --scenario gen_run_00 --seed "$SEED" >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then ok "gen_run_00 is unknown WITHOUT --generate (truly parametric)"
else fail "gen_run_00 resolved without --generate (rc=$rc; should be 2 unknown-scenario)"; fi

# ── assertion 7: each variant runs, converges non-vacuously, replays byte-identically ─
bad=""
for i in 00 01 02 03 04 05 06 07; do
    s="gen_run_$i"
    "$DSF" --generate 8 --seed "$SEED" --scenario "$s" --trace "$TMPD/${s}_a.log" --quiet >/dev/null 2>&1
    "$DSF" --generate 8 --seed "$SEED" --scenario "$s" --trace "$TMPD/${s}_b.log" --quiet >/dev/null 2>&1
    if [ ! -s "$TMPD/${s}_a.log" ] || ! diff -q "$TMPD/${s}_a.log" "$TMPD/${s}_b.log" >/dev/null 2>&1; then
        bad="$bad ${s}(replay-differs/empty)"; continue
    fi
    OUT="$("$DSF" --generate 8 --seed "$SEED" --scenario "$s" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then bad="$bad ${s}(rc=$rc)"; continue; fi
    echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps' || bad="$bad ${s}(vacuous)"
done
if [ -z "$bad" ]; then
    ok "all 8 gen_run variants run, converge non-vacuously, and replay byte-identically (§Q6)"
else
    fail "gen_run variant issue(s):$bad"
fi

# ── assertion 8: baked inc-4 set intact under a plain --list (no regression) ─
PLAIN="$("$DSF" --list 2>&1)"
miss=""
for s in gen_broadcast_00 gen_broadcast_05 gen_overcount_selftest; do
    echo "$PLAIN" | grep -q "^  $s" || miss="$miss $s"
done
if [ -z "$miss" ]; then ok "baked inc-4 set (gen_broadcast_00..05 + selftest) intact"
else fail "plain --list lost baked scenario(s):$miss"; fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc5 (--generate N --seed S CLI: count-parametric, generator-seed byte-stable + varied, parametric-not-baked, each variant converges + replays byte-identically)"
    exit 0
else
    echo "  FAIL: test_dsf_inc5 ($FAILS assertion(s))"
    exit 1
fi
