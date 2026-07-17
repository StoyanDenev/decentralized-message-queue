#!/usr/bin/env bash
# operator_dsf_sweep.sh — sweep the DSF §Q5 generator templates across many
# seeds and variants, collecting failures with exact bit-for-bit repro lines.
#
# This is the operational half of the DSF-SPEC §Q6 contract: "CI runs N
# variants overnight; a failed variant seed reproduces it bit-for-bit."
# For each (template, sweep-seed) pair the script:
#
#   (a) runs every generated variant
#         determ-dsf --generate N --seed S --template T --scenario gen_run_XX
#       and treats a non-zero exit OR output lacking the non-vacuous pass
#       marker ("invariant(s) held over <n> steps") as a FAILURE;
#   (b) performs one replay-determinism spot check: traces gen_run_00 twice
#       and byte-diffs the traces (§Q6: identical (generate-args, seed,
#       template, scenario) => byte-identical trace).
#
# --realizations R (default 1): profiles were previously only ever run at ONE
# realization — the collapsed --seed drove both the fault-PROFILE draw and the
# fault REALIZATION — but the inc-13 --gen-seed flag decouples them, so with
# R >= 2 each variant runs R times per (template, sweep-seed) pair: --gen-seed S
# pins the drawn profile set while --seed sweeps S, S+1, ..., S+R-1 over the
# realization. Each of the R runs is gated exactly like a single run (exit 0 +
# the non-vacuous pass marker); the replay spot check stays once per pair.
# R = 1 keeps the classic collapsed single-seed invocation (no --gen-seed
# passed), byte-for-byte identical to the pre-option behavior.
#
# Every failure prints the EXACT reproduction command line, and the final
# summary repeats all repro lines in a REPRO block. On failure the trace
# directory is PRESERVED and its path printed.
#
# Seed derivation is fully deterministic (no $RANDOM, no wall clock):
#   seed_i = seed_base + i * 0x9E37              (rendered as 0x-hex)
#   realization seed_k = seed_i + k, k = 0..R-1  (--realizations R, 0x-hex)
#
# NOTE: this is an OPERATOR tool, not a commit gate. The commit gates for
# the DSF harness are tools/test_dsf_inc*.sh.
#
# NOTE: determ-dsf silently falls back to the broadcast template on an
# UNKNOWN --template name (no error), so this script validates template
# names itself against KNOWN_TEMPLATES below.
#
# Usage:
#   tools/operator_dsf_sweep.sh                       # full default sweep
#   tools/operator_dsf_sweep.sh --quick               # smoke: 1 seed, 3 variants
#   tools/operator_dsf_sweep.sh --templates quorum,ratchet --seeds 8
#   tools/operator_dsf_sweep.sh --templates broadcast --seeds 2 --realizations 5
#   tools/operator_dsf_sweep.sh --bin build/Release/determ-dsf.exe --seed-base 0xBEEF
#
# Options:
#   --bin PATH        determ-dsf binary (default: $DETERM_DSF_BIN, then the
#                     standard build-tree discovery chain)
#   --templates CSV   generator templates to sweep (default: broadcast,agree,
#                     ratchet,quorum,conserve,recon,crashrec,partition,rotation)
#   --variants N      generated variants per (template, seed)   (default: 6)
#   --seeds M         sweep seeds per template                   (default: 4)
#   --seed-base HEX   first sweep seed, 0x-hex or decimal        (default: 0xC1)
#   --realizations R  fault-realization runs per variant         (default: 1)
#                     R >= 2: --gen-seed S pins the profile draw, --seed
#                     sweeps S..S+R-1; R = 1: classic collapsed single-seed
#                     invocation, no --gen-seed passed (see above)
#   --quick           shorthand for --seeds 1 --variants 3 (does NOT change
#                     --realizations)
#   --trace-dir DIR   where replay traces go (default: a mktemp dir, removed
#                     on a green sweep; PRESERVED if any failure occurred)
#   --help            this text
#
# Exit codes:
#   0   all runs green (every variant passed, every replay byte-identical)
#   1   at least one variant failed (repro lines printed in the REPRO block)
#   2   usage error (unknown flag, missing value, bad number, unknown
#       template name, unusable --trace-dir)
#   3   determ-dsf binary not found
set -u
cd "$(dirname "$0")/.."

# ── one-line-extensible template lists ────────────────────────────────────────
# DEFAULT_TEMPLATES: what a bare sweep runs. KNOWN_TEMPLATES: every name the
# binary actually maps (dsf_main.cpp routes agree|agreement -> Agreement,
# ratchet -> Ratchet, quorum -> Quorum, conserve|conservation -> Conservation,
# recon|reconcile|reconciliation -> Reconcile, crashrec|crashrecover ->
# CrashRecover, partition|partheal -> PartitionHeal, rotation|rotate ->
# Rotation, anything else ->
# Broadcast, silently — hence the local validation).
DEFAULT_TEMPLATES="broadcast,agree,ratchet,quorum,conserve,recon,crashrec,partition,rotation"
KNOWN_TEMPLATES="broadcast agree agreement ratchet quorum conserve conservation recon reconcile reconciliation crashrec crashrecover partition partheal rotation rotate"

SEED_STRIDE=0x9E37   # deterministic sweep-seed stride (see header)

usage() {
  cat <<EOF
Usage: operator_dsf_sweep.sh [--bin PATH] [--templates CSV] [--variants N]
                             [--seeds M] [--seed-base HEX] [--realizations R]
                             [--quick] [--trace-dir DIR]

Operational half of the DSF-SPEC §Q6 contract: "CI runs N variants
overnight; a failed variant seed reproduces it bit-for-bit." Sweeps the
§Q5 generator templates across deterministically derived seeds
(seed_i = seed_base + i*0x9E37), runs every generated variant, and does
one replay-determinism byte-diff per (template, seed) pair. Every
failure prints its exact reproduction command line.

With --realizations R >= 2 each variant runs R times: --gen-seed S pins
the drawn fault PROFILES while --seed sweeps S..S+R-1 over the fault
REALIZATION (profiles were previously only ever run at one realization;
the inc-13 --gen-seed flag decouples the two draws).

Examples:
  tools/operator_dsf_sweep.sh                       # full default sweep
  tools/operator_dsf_sweep.sh --quick               # smoke: 1 seed, 3 variants
  tools/operator_dsf_sweep.sh --templates quorum,ratchet --seeds 8
  tools/operator_dsf_sweep.sh --templates broadcast --seeds 2 --realizations 5

Options:
  --bin PATH        determ-dsf binary (default: \$DETERM_DSF_BIN, then the
                    standard build-tree discovery chain)
  --templates CSV   templates to sweep      (default: $DEFAULT_TEMPLATES)
                    known names: $KNOWN_TEMPLATES
  --variants N      variants per (template, seed)          (default: 6)
  --seeds M         sweep seeds per template               (default: 4)
  --seed-base HEX   first sweep seed, 0x-hex or decimal    (default: 0xC1)
  --realizations R  realization runs per variant           (default: 1)
                    R = 1 keeps the classic single-seed invocation
                    (no --gen-seed passed), byte-for-byte identical
  --quick           shorthand for --seeds 1 --variants 3 (leaves
                    --realizations unchanged)
  --trace-dir DIR   replay-trace dir (default: mktemp dir, removed on a
                    green sweep; PRESERVED if any failure occurred)
  -h, --help        this text

Exit codes:
  0   all runs green
  1   at least one variant failed (repro lines in the REPRO block)
  2   usage error (unknown flag, missing value, bad number, unknown
      template name, unusable --trace-dir)
  3   determ-dsf binary not found

OPERATOR tool, not a commit gate (the commit gates are tools/test_dsf_inc*.sh).
EOF
}

BIN=""
TEMPLATES_CSV="$DEFAULT_TEMPLATES"
VARIANTS=6
SEEDS=4
SEED_BASE="0xC1"
REALIZATIONS=1
TRACE_DIR=""
TRACE_DIR_IS_TEMP=0

# need_val FLAG: the flag at $1 requires a value at $2 — exit 2 if missing.
# (A bare `shift 2` with no value present fails WITHOUT shifting, which would
# re-parse the same flag forever.)
need_val() {
  if [ "$2" -lt 2 ]; then
    echo "operator_dsf_sweep: $1 requires an argument" >&2
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --bin)         need_val "$1" $#; BIN="$2"; shift 2 ;;
    --templates)   need_val "$1" $#; TEMPLATES_CSV="$2"; shift 2 ;;
    --variants)    need_val "$1" $#; VARIANTS="$2"; shift 2 ;;
    --seeds)       need_val "$1" $#; SEEDS="$2"; shift 2 ;;
    --seed-base)   need_val "$1" $#; SEED_BASE="$2"; shift 2 ;;
    --realizations) need_val "$1" $#; REALIZATIONS="$2"; shift 2 ;;
    --quick)       SEEDS=1; VARIANTS=3; shift ;;
    --trace-dir)   need_val "$1" $#; TRACE_DIR="$2"; shift 2 ;;
    *) echo "operator_dsf_sweep: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ── numeric / seed validation ─────────────────────────────────────────────────
case "$VARIANTS" in ""|*[!0-9]*)
  echo "operator_dsf_sweep: --variants must be a positive integer (got '$VARIANTS')" >&2
  exit 2 ;;
esac
case "$SEEDS" in ""|*[!0-9]*)
  echo "operator_dsf_sweep: --seeds must be a positive integer (got '$SEEDS')" >&2
  exit 2 ;;
esac
case "$REALIZATIONS" in ""|*[!0-9]*)
  echo "operator_dsf_sweep: --realizations must be a positive integer (got '$REALIZATIONS')" >&2
  exit 2 ;;
esac
if [ "$VARIANTS" -lt 1 ] || [ "$SEEDS" -lt 1 ] || [ "$REALIZATIONS" -lt 1 ]; then
  echo "operator_dsf_sweep: --variants, --seeds and --realizations must be >= 1" >&2
  exit 2
fi

seed_base_ok=0
case "$SEED_BASE" in
  0[xX]*)
    hexpart="${SEED_BASE#0[xX]}"
    case "$hexpart" in
      ""|*[!0-9a-fA-F]*) seed_base_ok=0 ;;
      *)                 seed_base_ok=1 ;;
    esac ;;
  ""|*[!0-9]*) seed_base_ok=0 ;;
  *)           seed_base_ok=1 ;;
esac
if [ "$seed_base_ok" -ne 1 ]; then
  echo "operator_dsf_sweep: --seed-base must be 0x-hex or decimal (got '$SEED_BASE')" >&2
  exit 2
fi
SEED_BASE_NUM=$(( SEED_BASE ))

# ── template-name validation (the binary won't do it — silent fallback) ───────
TEMPLATES=""
IFS=',' read -ra _TPLS <<<"$TEMPLATES_CSV"
for raw in "${_TPLS[@]}"; do
  t="${raw#"${raw%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  [ -z "$t" ] && continue
  known=0
  for k in $KNOWN_TEMPLATES; do
    if [ "$t" = "$k" ]; then known=1; break; fi
  done
  if [ "$known" -ne 1 ]; then
    echo "operator_dsf_sweep: unknown template '$t' (known: $KNOWN_TEMPLATES)" >&2
    echo "operator_dsf_sweep: refusing to run — determ-dsf silently falls back to broadcast on unknown names" >&2
    exit 2
  fi
  TEMPLATES="$TEMPLATES $t"
done
TEMPLATES="${TEMPLATES# }"
if [ -z "$TEMPLATES" ]; then
  echo "operator_dsf_sweep: --templates resolved to an empty list" >&2
  exit 2
fi

# ── binary discovery (same chain as tools/test_dsf_inc*.sh) ───────────────────
if [ -z "$BIN" ]; then
  if [ -n "${DETERM_DSF_BIN:-}" ] && [ -x "${DETERM_DSF_BIN:-}" ]; then BIN="$DETERM_DSF_BIN"
  elif [ -x "build/Release/determ-dsf.exe" ]; then BIN="build/Release/determ-dsf.exe"
  elif [ -x "build/determ-dsf.exe" ]; then BIN="build/determ-dsf.exe"
  elif [ -x "build/determ-dsf" ]; then BIN="build/determ-dsf"
  elif [ -x "build/Release/determ-dsf" ]; then BIN="build/Release/determ-dsf"
  fi
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "operator_dsf_sweep: determ-dsf binary not found (pass --bin PATH, set DETERM_DSF_BIN," >&2
  echo "                    or build the determ-dsf CMake target)" >&2
  exit 3
fi

# ── trace dir ─────────────────────────────────────────────────────────────────
if [ -z "$TRACE_DIR" ]; then
  TRACE_DIR="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_sweep.$$")"
  TRACE_DIR_IS_TEMP=1
fi
mkdir -p "$TRACE_DIR" || {
  echo "operator_dsf_sweep: cannot create trace dir '$TRACE_DIR'" >&2
  exit 2
}

TOTAL=0
PASSES=0
FAILURES=0
REPRO_LINES=()

cleanup() {
  # Preserve the trace dir on ANY failure (repro evidence); only auto-remove
  # the mktemp default on a fully green sweep. A user-supplied --trace-dir is
  # never removed.
  if [ "$TRACE_DIR_IS_TEMP" -eq 1 ] && [ "$FAILURES" -eq 0 ]; then
    rm -rf "$TRACE_DIR"
  fi
}
trap cleanup EXIT

echo "=== DSF sweep: templates [$TEMPLATES], $SEEDS seed(s) from $SEED_BASE, $VARIANTS variant(s) each ==="
echo "    bin: $BIN"
echo "    trace dir: $TRACE_DIR"
if [ "$REALIZATIONS" -ge 2 ]; then
  echo "    realizations: $REALIZATIONS per variant (--gen-seed pins the profile draw)"
fi
echo ""

PASS_MARKER='invariant\(s\) held over [1-9][0-9]* steps'

for T in $TEMPLATES; do
  i=0
  while [ "$i" -lt "$SEEDS" ]; do
    S_NUM=$(( SEED_BASE_NUM + i * SEED_STRIDE ))
    S="$(printf '0x%x' "$S_NUM")"

    # (a) run every generated variant (without --quiet so the non-vacuous
    #     pass marker is grep-able). With --realizations R >= 2, each variant
    #     runs R times: --gen-seed $S pins the drawn fault profiles while
    #     --seed sweeps S..S+R-1 over the fault realization (deterministic
    #     derivation, 0x-hex via printf). R = 1 keeps the classic collapsed
    #     single-seed invocation, byte-for-byte identical (no --gen-seed).
    #     A variant counts toward pair_pass only if ALL its realizations pass.
    pair_pass=0
    v=0
    while [ "$v" -lt "$VARIANTS" ]; do
      NAME="$(printf 'gen_run_%02d' "$v")"
      vfails=0
      k=0
      while [ "$k" -lt "$REALIZATIONS" ]; do
        TOTAL=$((TOTAL + 1))
        if [ "$REALIZATIONS" -eq 1 ]; then
          OUT="$("$BIN" --generate "$VARIANTS" --seed "$S" --template "$T" --scenario "$NAME" 2>&1)"
          rc=$?
          REPRO="\"$BIN\" --generate $VARIANTS --seed $S --template $T --scenario $NAME"
          FAIL_AT="$T @$S $NAME"
        else
          RSEED="$(printf '0x%x' $(( S_NUM + k )))"
          OUT="$("$BIN" --generate "$VARIANTS" --gen-seed "$S" --seed "$RSEED" --template "$T" --scenario "$NAME" 2>&1)"
          rc=$?
          REPRO="\"$BIN\" --generate $VARIANTS --gen-seed $S --seed $RSEED --template $T --scenario $NAME"
          FAIL_AT="$T @$S $NAME realization seed=$RSEED"
        fi
        if [ "$rc" -eq 0 ] && printf '%s\n' "$OUT" | grep -qE "$PASS_MARKER"; then
          PASSES=$((PASSES + 1))
        else
          FAILURES=$((FAILURES + 1))
          vfails=$((vfails + 1))
          REPRO_LINES+=("$REPRO")
          echo "  FAIL: $FAIL_AT (exit $rc)"
          printf '%s\n' "$OUT" | sed 's/^/    | /'
          echo "    reproduce: $REPRO"
        fi
        k=$((k + 1))
      done
      if [ "$vfails" -eq 0 ]; then
        pair_pass=$((pair_pass + 1))
      fi
      v=$((v + 1))
    done

    # (b) one replay-determinism spot check per (T, S): trace gen_run_00
    #     twice and byte-diff (§Q6 bit-for-bit contract). Stays once per
    #     pair regardless of --realizations (one realization suffices —
    #     realization 0, run seed $S, profile draw pinned by --gen-seed
    #     when R >= 2).
    TOTAL=$((TOTAL + 1))
    TA="$TRACE_DIR/${T}_${S}_a.trace"
    TB="$TRACE_DIR/${T}_${S}_b.trace"
    if [ "$REALIZATIONS" -eq 1 ]; then
      "$BIN" --generate "$VARIANTS" --seed "$S" --template "$T" --scenario gen_run_00 --trace "$TA" --quiet >/dev/null 2>&1
      "$BIN" --generate "$VARIANTS" --seed "$S" --template "$T" --scenario gen_run_00 --trace "$TB" --quiet >/dev/null 2>&1
      RREPRO="\"$BIN\" --generate $VARIANTS --seed $S --template $T --scenario gen_run_00 --trace <path>  # run twice, byte-diff ($TA vs $TB)"
    else
      "$BIN" --generate "$VARIANTS" --gen-seed "$S" --seed "$S" --template "$T" --scenario gen_run_00 --trace "$TA" --quiet >/dev/null 2>&1
      "$BIN" --generate "$VARIANTS" --gen-seed "$S" --seed "$S" --template "$T" --scenario gen_run_00 --trace "$TB" --quiet >/dev/null 2>&1
      RREPRO="\"$BIN\" --generate $VARIANTS --gen-seed $S --template $T --seed $S --scenario gen_run_00 --trace <path>  # run twice, byte-diff ($TA vs $TB)"
    fi
    replay="replay ok"
    if [ -s "$TA" ] && diff -q "$TA" "$TB" >/dev/null 2>&1; then
      PASSES=$((PASSES + 1))
    else
      FAILURES=$((FAILURES + 1))
      replay="REPLAY DIVERGED"
      REPRO_LINES+=("$RREPRO")
      echo "  FAIL: $T @$S replay-determinism (trace empty or byte-diff mismatch)"
      echo "    reproduce: $RREPRO"
    fi

    if [ "$REALIZATIONS" -eq 1 ]; then
      echo "  $T @$S: $pair_pass/$VARIANTS pass, $replay"
    else
      echo "  $T @$S: $pair_pass/$VARIANTS x$REALIZATIONS realizations pass, $replay"
    fi
    i=$((i + 1))
  done
done

echo ""
echo "=== DSF sweep summary ==="
echo "  total runs : $TOTAL  (incl. one replay check per template/seed pair)"
echo "  passes     : $PASSES"
echo "  failures   : $FAILURES"

if [ "$FAILURES" -gt 0 ]; then
  echo ""
  echo "=== REPRO (each line reproduces one failure bit-for-bit) ==="
  for line in "${REPRO_LINES[@]}"; do
    echo "  $line"
  done
  echo ""
  echo "  traces preserved in: $TRACE_DIR"
  exit 1
fi

echo "  [OK] sweep green"
exit 0
