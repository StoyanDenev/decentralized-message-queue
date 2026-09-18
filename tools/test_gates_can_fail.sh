#!/usr/bin/env bash
# tools/test_gates_can_fail.sh — the suite's accounting, and one class of gate
# that cannot fail, both made falsifiable.
#
# WHY THIS EXISTS. On 2026-09-17 two gates in this tree were found that could
# report success having asserted nothing:
#   * tools/test_wallet_shamir_rotate.sh section 28 checked the mode of a file
#     holding Shamir shares of a live secret and scored PASS on BOTH arms of its
#     `if` — a world-readable shares file was green (fixed in 4d4f7a4);
#   * tools/test_wallet_out_perms.sh printed `PASS:` and exited 0 when the wallet
#     binary was absent, and judged only on `fail_count`, so a box with neither
#     strace nor a C compiler scored `0 pass / 0 fail` as PASS (fixed in 579cd43).
# Both were found by reading, after the fact. This gate is the mechanical
# version, and it also falsifies the runner's own arithmetic — because a summary
# nobody can verify is the same defect class as a gate that cannot fail.
#
# WHAT IT CHECKS
#   A. tools/run_all.sh's summary arithmetic, driven over SYNTHETIC wrappers in
#      a throwaway tree: PASS + FAIL == RUN, SKIP <= PASS, VACUOUS <= SKIP, and
#      each column takes the value the fixtures dictate. The REAL run_all.sh is
#      copied and executed — not a re-implementation of it.
#   B. four mutants of that arithmetic, each verified to have REACHED the copied
#      source before its verdict is read, each of which must turn A RED.
#   C. the skip column is a FUNCTION of the fixtures (a positive control):
#      deleting the one SKIP: line from a fixture drops the column by one.
#   D. a ratchet over the real tools/*.sh: no `if`/`case` in which every arm
#      banks a pass and no arm can fail (D1), no SKIP that banks a pass in the
#      same statement (D2), and no growth in the set of wrappers that print a
#      PASS: marker and exit 0 on a "cannot run" guard while assertions remain
#      below them (D3, an exact allowlist of the five that do it today), and no
#      python heredoc inside a tools/test_*.sh gate whose comparison can only
#      ever be true or whose failure a bare `except: pass` swallows (D4, zero).
#   E. SELFTEST, run inline on every invocation: the D1-D4 checkers are fed
#      snippets reproducing the two 2026-09-17 defects verbatim and both heredoc
#      shapes, and must flag each one; plus clean snippets they must not flag,
#      and a WRONG-but-falsifiable predicate they must not claim. Without E this
#      guard could silently stop looking and stay green — which is the exact
#      defect it exists to find.
#
# WHAT IT CANNOT SEE, stated because the alternative is a guard that lies:
#   * A WRONG PREDICATE. Both remaining holes of 2026-09-17 were assertions that
#     ran, could fail in principle, and tested the wrong thing: `find("priv_seed")
#     == npos` passes on a zero-byte file, and a chmod regex matching only
#     `fchmod(fd, …)` reports a path-based widen as "closed". Nothing structural
#     distinguishes those from a correct assertion. Measured: this file's
#     checkers, run against tools/test_node_key_perms.sh as it stood at a152664,
#     return ZERO findings.
#   * AN EMBEDDED PROGRAM THAT IS NOT PYTHON, OR NOT A HEREDOC — an awk, perl or
#     sed script, and `python -c '…'` one-liners. D4 parses python heredocs only
#     (37 single-quoted `-c` one-liners and every awk block in tools/ are outside
#     it), and within those it sees two shapes, not "is this assertion right".
#   * A LEG THAT IS FALSIFIABLE BUT NEVER EXECUTED ANYWHERE — the Darwin/BSD
#     arms of several mode assertions have never run on any machine.
#   * ANY C++ SELFTEST. The `check(…)` calls inside src/, wallet/, light/ and
#     dapps/ are a separate surface; two findings there are recorded in the
#     2026-09-18 DECISION-LOG entry with file:line and are NOT gated here.
#   * `fail_count == 0` verdicts with no assertion floor: 161 wrappers in this
#     tree still have that shape (18 of them FAST members), measured 2026-09-18.
#     Ratcheting it would be a suite-wide migration, not this increment; the
#     convention is written down in tools/common.sh and run_all.sh's skip column
#     makes each instance visible in the summary as it is hit.
#
# Pure shell + python over source and over a throwaway tree. Needs NO determ
# binary (it plants a stub for the copied runner's own binary probe), never
# SKIPs, runs offline, deterministic. run_all.sh auto-discovers it.
set -u
cd "$(dirname "$0")/.."

# Loop breaker: leg A runs the REAL tools/run_all.sh inside a throwaway tree over
# five synthetic fixtures. This file is never one of them, so the branch below is
# unreachable in normal operation; it exists in case a future change to the inner
# invocation ever lets it reach this file. It prints NO terminal PASS marker, so
# run_all's markerless branch scores it a FAILURE — a branch that asserts nothing
# must not bank a pass, including this one (lesson 15 applied to this file).
if [ "${DETERM_GATES_CAN_FAIL_INNER:-0}" = "1" ]; then
    echo "  SKIP: test_gates_can_fail invoked recursively; nothing was asserted"
    echo "  (no terminal marker on purpose — run_all scores a markerless run as a failure)"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0
fail_count=0
skip_count=0
ok()   { echo "  PASS: $1"; pass_count=$((pass_count + 1)); }
bad()  { echo "  FAIL: $1"; fail_count=$((fail_count + 1)); }
eqq()  { # eqq <got> <want> <label>
  if [ "$1" = "$2" ]; then ok "$3"
  else bad "$3"; echo "       expected: $2"; echo "       got:      $1"; fi
}

T=$(mktemp -d "${TMPDIR:-/tmp}/determ-gatescanfail.XXXXXX") || {
    echo "  FAIL: test_gates_can_fail — cannot create a temp dir"; exit 1; }
trap 'rm -rf "$T"' EXIT

# ══════════════════════════════════════════════════════════════════════════════
# The throwaway tree: the REAL run_all.sh + common.sh, five synthetic wrappers,
# and a stub `determ` so the copied runner's binary probe is satisfied offline.
# ══════════════════════════════════════════════════════════════════════════════
build_tree() {  # build_tree <root> [--no-skip-in-b]
  local R="$1"; shift
  rm -rf "$R"; mkdir -p "$R/tools" "$R/build-linux"
  cp tools/run_all.sh tools/common.sh "$R/tools/"
  printf '#!/bin/sh\nexit 0\n' > "$R/build-linux/determ"; chmod +x "$R/build-linux/determ"

  # a. clean: three assertions, no declined section
  cat > "$R/tools/test_a_clean.sh" <<'FIX'
#!/usr/bin/env bash
echo "  PASS: a1"; echo "  PASS: a2"; echo "  PASS: a3"
echo "  PASS: fixture-a"
FIX
  # b. declined: two assertions AND one declined section
  if [ "${1:-}" = "--no-skip-in-b" ]; then
    cat > "$R/tools/test_b_declined.sh" <<'FIX'
#!/usr/bin/env bash
echo "  PASS: b1"; echo "  PASS: b2"
echo "  PASS: fixture-b"
FIX
  else
    cat > "$R/tools/test_b_declined.sh" <<'FIX'
#!/usr/bin/env bash
echo "  PASS: b1"; echo "  PASS: b2"
echo "  SKIP: b3 (no strace here)"
echo "  PASS: fixture-b"
FIX
  fi
  # c. vacuous: declined everything, asserted nothing, still prints PASS —
  #    the 2026-09-17 test_wallet_out_perms shape, preserved as a fixture
  cat > "$R/tools/test_c_vacuous.sh" <<'FIX'
#!/usr/bin/env bash
echo "  SKIP: c1 (no compiler here)"
echo "  SKIP: c2 (no ptrace here)"
echo "  PASS: fixture-c (nothing to gate)"
FIX
  # d. a plain failure
  cat > "$R/tools/test_d_fail.sh" <<'FIX'
#!/usr/bin/env bash
echo "  PASS: d1"
echo "  FAIL: fixture-d"
exit 1
FIX
  # e. no terminal marker at all (run_all counts it as a failure)
  cat > "$R/tools/test_e_nomarker.sh" <<'FIX'
#!/usr/bin/env bash
echo "nothing to see here"
FIX
  chmod +x "$R/tools/"*.sh
}

run_tree() {  # run_tree <root> -> prints the runner's stdout; exit code preserved
  # FAST / ONLY_PATTERN / SKIP_PATTERN are neutralised explicitly. ci_local runs
  # this wrapper with FAST=1 QUIET=1 exported, and an inherited FAST=1 makes the
  # inner runner apply the FAST alternation to the synthetic fixtures, match
  # none, and report RUN 0 — which is exactly what happened on the first
  # ci_local run of this gate. The RUN == 5 assertion in leg A is what caught it
  # and is left in place as the guard against it recurring.
  ( cd "$1" && DETERM_GATES_CAN_FAIL_INNER=1 REAP_DAEMONS=0 QUIET=1 \
      FAST=0 ONLY_PATTERN= SKIP_PATTERN= \
      DETERM_BIN="$1/build-linux/determ" bash tools/run_all.sh 2>&1 )
}
field() { echo "$1" | sed -n "s/^$2:[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -1; }

echo "=== A. run_all.sh summary arithmetic over five synthetic wrappers ==="
build_tree "$T/r1"
OUT_A=$(run_tree "$T/r1"); RC_A=$?
if [ -z "$(field "$OUT_A" RUN)" ]; then
    echo "$OUT_A" | tail -20
    bad "the runner printed no RUN: column — leg A cannot be judged (shape changed; re-pin this gate)"
else
    eqq "$(field "$OUT_A" RUN)"  "5" "RUN counts every wrapper executed"
    eqq "$(field "$OUT_A" PASS)" "3" "PASS counts the three wrappers with a terminal PASS marker"
    eqq "$(field "$OUT_A" FAIL)" "2" "FAIL counts the explicit failure AND the markerless wrapper"
    eqq "$(field "$OUT_A" SKIP)" "2" "SKIP counts the two passing wrappers that declined a section"
    eqq "$(echo "$OUT_A" | grep -c 'asserted nothing at all')" "1" \
        "the asserted-nothing sub-list is printed when a wrapper banked green having checked nothing"
    eqq "$(echo "$OUT_A" | sed -n 's/.*(\([0-9]*\) of those asserted nothing).*/\1/p' | head -1)" "1" \
        "exactly one of the two declining wrappers asserted nothing"
    eqq "$(( $(field "$OUT_A" PASS) + $(field "$OUT_A" FAIL) ))" "$(field "$OUT_A" RUN)" \
        "PASS + FAIL accounts for every wrapper run"
    eqq "$RC_A" "1" "a suite with a failing wrapper still exits non-zero"
    eqq "$(echo "$OUT_A" | grep -c 'summary arithmetic')" "0" \
        "the runner's own arithmetic self-check is silent on a consistent run"
    # The wrapper named in the asserted-nothing list is the right one.
    eqq "$(echo "$OUT_A" | grep -c '! tools/test_c_vacuous.sh')" "1" \
        "the asserted-nothing wrapper is named, so a reader can go and fix it"
fi

echo
echo "=== B. mutants of the runner's accounting — each must turn A RED ==="
mutate_and_run() {  # mutate_and_run <label> <sed-expr> <marker-that-must-appear>
  local label="$1" expr="$2" marker="$3" R="$T/m"
  build_tree "$R"
  sed -i.bak "$expr" "$R/tools/run_all.sh" && rm -f "$R/tools/run_all.sh.bak"
  # RULE 5 OF THE WAVE DOCTRINE: refuse to report a verdict if the mutation did
  # not actually reach the source. A harness that reads a verdict from an
  # unmutated copy is worse than no harness.
  if ! grep -qF "$marker" "$R/tools/run_all.sh"; then
      bad "$label — the mutation did NOT reach the copied runner (marker '$marker' absent); no verdict taken"
      return
  fi
  local out rc
  out=$(run_tree "$R"); rc=$?
  if echo "$out" | grep -q 'FAIL: run_all summary arithmetic' && [ "$rc" -ne 0 ]; then
      ok "$label — the arithmetic self-check fires and the runner exits non-zero"
  else
      bad "$label — the runner stayed GREEN on a broken summary"
      echo "$out" | tail -8
  fi
}
mutate_and_run "M1 (RUN is not incremented)" \
  's/^    RUN_COUNT=$((RUN_COUNT + 1))$/    RUN_COUNT=$((RUN_COUNT + 0))  # M1/' 'RUN_COUNT + 0'
mutate_and_run "M2 (PASS double-counts)" \
  's/        PASS_COUNT=$((PASS_COUNT + 1))$/        PASS_COUNT=$((PASS_COUNT + 2))  # M2/' 'PASS_COUNT + 2'
mutate_and_run "M3 (SKIP over-counts past PASS)" \
  's/            SKIP_COUNT=$((SKIP_COUNT + 1))$/            SKIP_COUNT=$((SKIP_COUNT + 9))  # M3/' 'SKIP_COUNT + 9'
mutate_and_run "M4 (asserted-nothing over-counts past SKIP)" \
  's/                VACUOUS_COUNT=$((VACUOUS_COUNT + 1))$/                VACUOUS_COUNT=$((VACUOUS_COUNT + 9))  # M4/' 'VACUOUS_COUNT + 9'

echo
echo "=== C. positive control: the skip column is a function of the fixtures ==="
build_tree "$T/r2" --no-skip-in-b
OUT_C=$(run_tree "$T/r2") || true
eqq "$(field "$OUT_C" SKIP)" "1" \
    "removing the one SKIP: line from fixture b drops the column from 2 to 1 (the column is read, not assumed)"
eqq "$(field "$OUT_C" PASS)" "3" "and no verdict moved: PASS is still 3"

echo
echo "=== D. ratchet over the real tools/*.sh ==="
# The checkers live in one heredoc so leg E can feed them synthetic files.
cat > "$T/checkers.py" <<'PYEOF'
import os, re, sys, glob
PASS_ECHO = re.compile(r'echo\s+.{0,4}"?\s*PASS:')
FAIL_ECHO = re.compile(r'echo\s+.{0,4}"?\s*FAIL:')
SKIP_ECHO = re.compile(r'echo\s+.{0,4}"?\s*SKIP:')
PASS_INC  = re.compile(r'(pass_count|passes|PASS_COUNT)\s*=\s*\$\(\(')
FAIL_INC  = re.compile(r'(fail_count|fails|FAIL_COUNT|fail)\s*=\s*\$\(\(')

def blocks(ls):
    stack, out = [], []
    for i, l in enumerate(ls):
        s = l.strip()
        if s.startswith('#'):
            continue
        if re.match(r'^(if|case)\b', s):
            stack.append([('if' if s.startswith('if') else 'case'), i, []])
        elif stack and re.match(r'^(elif|else)\b', s):
            stack[-1][2].append(i)
        elif stack and re.match(r'^(fi|esac)\b', s):
            kind, start, arms = stack.pop()
            out.append((kind, start, i, arms))
        elif stack and stack[-1][0] == 'case' and re.match(r'^[^#]*\)\s*$', s) and ';;' not in s:
            stack[-1][2].append(i)
    return out

def d1(path, ls):                     # every arm banks a pass, no arm can fail
    hits = []
    for kind, start, end, arms in blocks(ls):
        if end - start > 120:
            continue
        bounds = [start] + arms + [end]
        segs = ['\n'.join(ls[bounds[k] + 1:bounds[k + 1]]) for k in range(len(bounds) - 1)]
        if len(segs) < 2:
            continue
        banks = [bool(PASS_ECHO.search(t) or PASS_INC.search(t)) for t in segs]
        fails = [bool(FAIL_ECHO.search(t) or FAIL_INC.search(t)
                      or re.search(r'\bassert\w*\s', t) or 'exit 1' in t) for t in segs]
        if all(banks) and not any(fails):
            hits.append((start + 1, ls[start].strip()[:110]))
    return hits

def d2(path, ls):                     # a SKIP that increments the PASS COUNTER
    hits = []                         # in the same statement (the §20/§28 shape)
    for i, l in enumerate(ls):
        if l.strip().startswith('#') or not SKIP_ECHO.search(l):
            continue
        if PASS_INC.search(l):
            hits.append((i + 1, l.strip()[:110])); continue
        for j in range(i + 1, min(i + 3, len(ls))):
            s = ls[j].strip()
            if not s or s.startswith('#'):
                continue
            if re.match(r'^(fi|esac|else|elif|;;|\})', s):
                break
            if PASS_INC.search(s):
                hits.append((i + 1, (l.strip() + ' -> ' + s)[:110]))
            break
    return hits

def d3(path, ls):                     # PASS: + exit 0 on a "cannot run" guard,
    hits = []                         # with assertions still below it
    for i, l in enumerate(ls):
        if l.strip().startswith('#') or not PASS_ECHO.search(l):
            continue
        # A trailing comment must not hide the bail-out: `exit 0  # why` is the
        # same defect. Measured 2026-09-18 — mutant M3 stayed GREEN until this
        # allowed it.
        if not re.search(r'^\s*exit\s+0\s*(?:#.*)?$', '\n'.join(ls[i + 1:i + 3]), re.M):
            continue
        below = '\n'.join(ls[i + 1:])
        if not re.search(r'^\s*(assert\w*|check\w*)\s', below, re.M) and not PASS_INC.search(below):
            continue
        back = '\n'.join(ls[max(0, i - 6):i]).lower()
        if re.search(r'not found|not available|not installed|not built|missing|nothing to|'
                     r'absent|-x |command -v|-z "\$|skip', back):
            hits.append((i + 1, l.strip()[:110]))
    return hits

HEREDOC = re.compile(
    r'(?:\$PY|\$\{PY\}|python3?)[^\n<]*<<\s*(?P<q>[\'"]?)(?P<tag>[A-Za-z_]\w*)(?P=q)\s*\n'
    r'(?P<body>.*?)\n(?P=tag)\s*$', re.S | re.M)

def d4(path, ls):                     # an assertion inside an embedded python
    import ast                        # heredoc that can only ever be true, or
    hits = []                         # whose failure is swallowed
    src = '\n'.join(ls)
    for m in HEREDOC.finditer(src):
        body = m.group('body')
        if m.group('q') == '':        # unquoted tag: the shell expanded $vars
            body = re.sub(r'\$\{?[A-Za-z_]\w*\}?', '_SHVAR_', body)
            body = re.sub(r'\$\([^)]*\)', '_SHSUB_', body)
        base = src[:m.start('body')].count('\n') + 1
        try:
            tree = ast.parse(body)
        except SyntaxError:
            continue                  # not python (awk/perl/sed); D4 reads python only
        for n in ast.walk(tree):
            # (a) a comparison whose two operands are syntactically identical:
            #     the verdict it feeds the shell can only ever take one value.
            if isinstance(n, ast.Compare) and len(n.comparators) == 1 and \
                    isinstance(n.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                try:
                    same = ast.dump(n.left) == ast.dump(n.comparators[0])
                except Exception:
                    same = False
                if same:
                    hits.append((base + n.lineno - 1,
                                 'comparison with two identical operands inside a heredoc'))
            # (b) a bare `except: pass`: the heredoc crashes and the shell reads
            #     whatever the pre-set verdict variable held, usually the pass token.
            if isinstance(n, ast.ExceptHandler) and len(n.body) == 1 and \
                    isinstance(n.body[0], ast.Pass):
                hits.append((base + n.lineno - 1,
                             'bare `except: pass` swallows the failure of the assertion it wraps'))
    return hits

CHECKS = {'D1': d1, 'D2': d2, 'D3': d3, 'D4': d4}
which = sys.argv[1]
for p in sorted(sys.argv[2:]):
    ls = open(p, encoding='utf-8', errors='replace').read().split('\n')
    for ln, ev in CHECKS[which](p, ls):
        print('%s|%s:%d|%s' % (which, os.path.normpath(p), ln, ev))
PYEOF

# THIS FILE IS EXCLUDED FROM THE SWEEP. It carries, as heredoc fixtures, verbatim
# copies of the two defects of 2026-09-17 so that leg E can prove the checkers
# still see them; sweeping itself would report its own fixtures as tree defects.
# The cost is that this file's own shell is not ratcheted by D1/D2/D3 — leg E is
# what stands behind it, and its verdict carries the pass_count floor.
SWEEP=$(ls tools/*.sh | grep -v '^tools/test_gates_can_fail\.sh$')

D1_HITS=$($PY "$T/checkers.py" D1 $SWEEP)
eqq "$(printf '%s' "$D1_HITS" | grep -c . )" "0" \
    "D1: no if/case in tools/*.sh in which every arm banks a pass and no arm can fail"
[ -z "$D1_HITS" ] || printf '%s\n' "$D1_HITS" | sed 's/^/       /'

D2_HITS=$($PY "$T/checkers.py" D2 $SWEEP)
eqq "$(printf '%s' "$D2_HITS" | grep -c . )" "0" \
    "D2: no SKIP in tools/*.sh banks a pass in the same statement"
[ -z "$D2_HITS" ] || printf '%s\n' "$D2_HITS" | sed 's/^/       /'

# D3 is a RATCHET, not a zero: five wrappers still print a PASS marker and exit 0
# on a "cannot run" guard. None is a FAST member and none is one of ci_local's
# 16 doc guards; each bails on an absent BINARY or an absent multi-node cluster,
# which is an environment, and converting those is a suite-wide migration rather
# than this increment. The four whose bail-out was over an absent TRACKED SOURCE
# were fixed on 2026-09-18 instead — a tracked file missing is a broken checkout,
# not an environment, and two of those four (keybind_surface,
# resume_monotonicity_guard) are ci_local doc guards, so the vacuous PASS was a
# hole in the verdict itself. The set is pinned EXACTLY so a sixth is RED and so
# a fixed one must be removed from this list.
# NOTE on the first entry: tools/test_cluster_output_discipline.sh is a KNOWN
# FALSE POSITIVE of the D3 heuristic. Its `PASS: … SELFTEST` + `exit 0` is the
# terminal of its SELFTEST=1 mode, not a cannot-run bail-out; the "back window"
# match comes from the words in its own st_expect labels. It is listed because
# the allowlist is the checker's OUTPUT, not a judgement, and an allowlist that
# quietly dropped a hit would be a second place for a defect to hide.
D3_ALLOW=$(cat <<'EOF'
tools/test_cluster_output_discipline.sh
tools/test_light_block_verify.sh
tools/test_light_fetch_validators.sh
tools/test_light_verify_chain_file.sh
tools/test_light_verify_unstake_eligibility.sh
EOF
)
D3_NOW=$($PY "$T/checkers.py" D3 $SWEEP | cut -d'|' -f2 | cut -d: -f1 | sort -u)
NEW=$(comm -13 <(printf '%s\n' "$D3_ALLOW" | sort -u) <(printf '%s\n' "$D3_NOW"))
GONE=$(comm -23 <(printf '%s\n' "$D3_ALLOW" | sort -u) <(printf '%s\n' "$D3_NOW"))
if [ -z "$NEW" ]; then ok "D3: no NEW wrapper banks a PASS and exits 0 on a cannot-run guard"
else bad "D3: a new wrapper banks a PASS having asserted nothing"; printf '%s\n' "$NEW" | sed 's/^/       + /'; fi
if [ -z "$GONE" ]; then ok "D3: the allowlist is exact — every name on it still offends"
else bad "D3: the allowlist is stale — these no longer offend and must be removed from it"; printf '%s\n' "$GONE" | sed 's/^/       - /'; fi

# D4 — the surface the 2026-09-17 sweep explicitly could NOT see: a verdict
# computed inside an embedded python heredoc. Ratcheted at ZERO over the test
# wrappers (the gates); tools/operator_*.sh are operator REPORTS whose heredocs
# produce no suite verdict, and seven of them carry a bare `except: pass` today —
# listed in the 2026-09-18 log entry with file:line, not gated here.
D4_SWEEP=$(ls tools/test_*.sh | grep -v '^tools/test_gates_can_fail\.sh$')
D4_HITS=$($PY "$T/checkers.py" D4 $D4_SWEEP)
eqq "$(printf '%s' "$D4_HITS" | grep -c . )" "0" \
    "D4: no python heredoc in a tools/test_*.sh gate carries an always-true comparison or a bare except: pass"
[ -z "$D4_HITS" ] || printf '%s\n' "$D4_HITS" | sed 's/^/       /'

echo
echo "=== E. SELFTEST: the D-checkers flag the two defects of 2026-09-17 ==="
mkdir -p "$T/sel"
# E1 — tools/test_wallet_shamir_rotate.sh section 28 as it stood at c895d9b.
cat > "$T/sel/test_e1_shamir28.sh" <<'FIX'
#!/usr/bin/env bash
if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then
    PERMS=$(stat -c "%a" "$TMP/rotated.json")
    if [ "$PERMS" = "600" ]; then
        echo "  PASS: output file perms are 600"; pass_count=$((pass_count + 1))
    else
        echo "  PASS: output file perms reported '$PERMS' (best-effort; non-fatal)"; pass_count=$((pass_count + 1))
    fi
else
    echo "  PASS: skip perms check on Windows (NTFS ACL)"; pass_count=$((pass_count + 1))
fi
FIX
# E2 — a SKIP that banks a pass (the section-20 / section-28 spelling).
cat > "$T/sel/test_e2_skipbanks.sh" <<'FIX'
#!/usr/bin/env bash
case "$UNAME" in
    Linux) assert_eq "$MODE" "600" "file mode is 0600" ;;
    *) echo "  SKIP: 0600 check (uname=$UNAME)"; pass_count=$((pass_count + 1)) ;;
esac
FIX
# E3 — tools/test_wallet_out_perms.sh's vacuous bail-out as it stood at a5d7d56.
cat > "$T/sel/test_e3_vacuous.sh" <<'FIX'
#!/usr/bin/env bash
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --target determ-wallet"
    echo "  PASS: determ-wallet output perms (nothing to gate)"
    exit 0
fi
assert_eq "$(mode_of "$F")" "600" "the output file is 0600"
FIX
# E0 — the clean shape: a real assertion on one arm, a counted skip on the other.
cat > "$T/sel/test_e0_clean.sh" <<'FIX'
#!/usr/bin/env bash
case "$UNAME" in
    Linux|Darwin) assert_eq "$MODE" "600" "file mode is 0600" ;;
    *) echo "  SKIP: 0600 check (uname=$UNAME; POSIX-only assertion)"; skip_count=$((skip_count + 1)) ;;
esac
if [ "$pass_count" -eq 0 ]; then echo "  FAIL: nothing asserted"; exit 1; fi
FIX
eqq "$($PY "$T/checkers.py" D1 "$T/sel/test_e1_shamir28.sh" | grep -c .)" "2" \
    "E1: the shamir section-28 shape (both arms bank a pass) is flagged by D1, inner and outer if"
eqq "$($PY "$T/checkers.py" D2 "$T/sel/test_e2_skipbanks.sh" | grep -c .)" "1" \
    "E2: a SKIP that increments pass_count is flagged by D2"
eqq "$($PY "$T/checkers.py" D3 "$T/sel/test_e3_vacuous.sh" | grep -c .)" "1" \
    "E3: the vacuous PASS bail-out over a missing binary is flagged by D3"
eqq "$($PY "$T/checkers.py" D1 "$T/sel/test_e0_clean.sh" | grep -c .)$($PY "$T/checkers.py" D2 "$T/sel/test_e0_clean.sh" | grep -c .)$($PY "$T/checkers.py" D3 "$T/sel/test_e0_clean.sh" | grep -c .)" "000" \
    "E0: the corrected shape (assert on one arm, counted skip on the other, a floor) is flagged by none of the three"
# E5 — the two heredoc shapes D4 exists for, and a falsifiable heredoc control.
cat > "$T/sel/test_e5_heredoc.sh" <<'FIX'
#!/usr/bin/env bash
V=$($PY <<'PYFIX'
import json
a = json.load(open('a.json'))
print("ok" if a["root"] == a["root"] else "bad")
PYFIX
)
W=$($PY <<'PYFIX'
import json
verdict = "ok"
try:
    d = json.load(open('b.json'))
    verdict = "ok" if d["root"] == d["expected"] else "bad"
except:
    pass
print(verdict)
PYFIX
)
FIX
cat > "$T/sel/test_e5_clean.sh" <<'FIX'
#!/usr/bin/env bash
V=$($PY <<'PYFIX'
import json, sys
a = json.load(open('a.json'))
b = json.load(open('b.json'))
if "root" not in a or "root" not in b:
    sys.exit(2)
print("ok" if a["root"] == b["root"] else "bad")
PYFIX
) || { echo "  FAIL: the comparison could not be made"; exit 1; }
FIX
eqq "$($PY "$T/checkers.py" D4 "$T/sel/test_e5_heredoc.sh" | grep -c .)" "2" \
    "E5: an always-true heredoc comparison AND a bare except: pass are both flagged by D4"
eqq "$($PY "$T/checkers.py" D4 "$T/sel/test_e5_clean.sh" | grep -c .)" "0" \
    "E5: a heredoc whose verdict is a real function of two different operands, with a non-zero exit on bad input, is flagged by neither"

# E4 — the honest negative: a WRONG PREDICATE is invisible to all three. This is
# the false-negative surface, asserted so the claim in the header stays true.
cat > "$T/sel/test_e4_wrongpredicate.sh" <<'FIX'
#!/usr/bin/env bash
# The 2026-09-17 node-key gate: a real assertion, falsifiable, and wrong — a
# zero-byte leftover file satisfies it exactly.
assert_eq "$(grep -c priv_seed "$F" || true)" "0" "no seed was written to the unprotectable file"
FIX
eqq "$($PY "$T/checkers.py" D1 "$T/sel/test_e4_wrongpredicate.sh" | grep -c .)$($PY "$T/checkers.py" D2 "$T/sel/test_e4_wrongpredicate.sh" | grep -c .)$($PY "$T/checkers.py" D3 "$T/sel/test_e4_wrongpredicate.sh" | grep -c .)" "000" \
    "E4: a WRONG-but-falsifiable predicate is flagged by none of the three — the header's stated blind spot, pinned"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count skip"
# The floor (wave-doctrine lesson 15): fail_count == 0 is not a verdict.
if [ "$pass_count" -eq 0 ]; then
    echo "  FAIL: test_gates_can_fail — nothing was asserted"; exit 1
elif [ "$fail_count" -eq 0 ]; then
    echo "  PASS: test_gates_can_fail (suite accounting falsifiable; no gate in tools/ banks a pass on a branch that checked nothing)"; exit 0
else
    echo "  FAIL: test_gates_can_fail"; exit 1
fi
