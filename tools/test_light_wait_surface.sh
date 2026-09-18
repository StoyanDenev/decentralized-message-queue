#!/usr/bin/env bash
# test_light_wait_surface.sh — PURELY STATIC completeness guard for the S-042
# "every head-anchored binding consumer forwards --wait" invariant in determ-light.
#
# WHAT THIS IS
# ------------
# S-042's trustless readers anchor a daemon-served state proof to a COMMITTEE-SIGNED
# head. When the operator passes `--wait <seconds>`, that anchoring must keep retrying
# until a freshly-signed head appears, otherwise a light client racing a just-produced
# block reads a head that is not yet committee-attested and either fails spuriously or
# (worse) is forced onto a stale anchor. The usability fix threaded a `wait_seconds`
# (a.k.a. `max_wait_seconds`) parameter through EVERY head-anchored binding consumer:
# `committee_bound_state_root`, `verify_state_root_at`, `read_account_trustless`, and
# `read_stake_trustless`. The exact class of bug just fixed was a handful of call sites
# (verify-and-submit / verify-unstake-eligibility / committee-at-height) that bound the
# head WITHOUT forwarding the operator's `--wait`, so the wait was silently a no-op.
#
# THE RISK THIS LOCKS
# -------------------
# A future command handler can be added that calls one of these binding helpers but
# forgets to forward `wait_seconds` — re-opening exactly the S-042 head-read usability
# gap, silently, with no build/run failure. This guard turns RED the instant any
# binding call site drops the wait argument, BEFORE any build or cluster run.
#
# WHY THE POSITION PIN WAS REMOVED (2026-09-18 repair — READ THIS BEFORE EDITING)
# ------------------------------------------------------------------------------
# The first revision of this guard asserted that a binding call's argument list CLOSES
# with a wait variable — i.e. that the wait argument is syntactically LAST. That was a
# PROXY for "the wait lands in the wait parameter", true only at the moment it was
# written. `committee_bound_state_root` later gained `expected_k` and `bft_enabled`
# (LV-1/LV-2) AFTER the wait parameter, and `verify_state_root_at` the same, so every
# correct call stopped closing with the wait variable. The guard then reported
# `opens=14 good=0 bad=14` and called it an "S-042 head-read REGRESSION" for weeks while
# `light/` was in fact correct — it sits outside FAST and outside ci_local's doc guards,
# so nothing was watching. Adjudicated as GUARD DRIFT in DECISION-LOG 2026-09-18.
#
# The repair does NOT move the pin to the new position — that would rot the same way on
# the next signature change. The wait slot is now DERIVED FROM THE DECLARATION: the
# guard parses each helper's parameter list, finds the parameter NAMED `wait` /
# `wait_seconds` / `max_wait` / `max_wait_seconds`, and asserts that every call passes a
# wait expression (a bare or member-qualified one of those names) AT THAT
# INDEX. The source of truth for "which slot is the wait slot" is the signature itself.
#
# ROBUST TO / NOT ROBUST TO (say it plainly so a future green is not misread):
#   ROBUST TO: adding, removing or reordering parameters around the wait parameter;
#     the wait parameter moving to any position; extra trailing out-parameters; the
#     helper being declared in a different header; multi-line calls; CRLF; comments and
#     string literals containing the helper name or a comma.
#   NOT ROBUST TO (deliberately, and each fails LOUD, never silently green):
#     * renaming the wait parameter to something outside `(max_)?wait(_seconds)?` — the
#       guard fails closed with "no wait parameter", which is also exactly what a
#       REVERT of the S-042 fix looks like, and the two are indistinguishable by design;
#     * a call forwarding a correctly-named wait that a LOCAL variable shadows with a
#       constant (`uint64_t wait_seconds = 0;` hard-coded in a handler) — static
#       name-matching cannot see that; it is a dataflow property, and the offline
#       `tools/test_light_wait_flag.sh` + the live cluster leg are what cover it;
#     * a wait threaded through an intermediate helper this guard does not know about.
#
# FIVE INVARIANTS (all static, source-only over $LIGHT_DIR):
#   A. Each binding helper HAS a wait parameter in its declaration, and the guard derives
#      its 1-based index. The HELPER SET is itself derived, not only listed: the four
#      named helpers plus every function in $LIGHT_DIR that takes a wait parameter AND
#      reaches a binding call, because such a function is a binding route whose own
#      callers must forward. Without that, an intermediate helper could be introduced and
#      its callers drop the wait while every named helper still checked out. Today it adds
#      account_history.cpp::verify_header_state_root_at and outbox.cpp::verify_and_bind. A helper with no wait parameter, an
#      unparseable declaration, a missing declaration, or two declarations that
#      disagree on the index → RED. This is the "the S-042 fix is still in the API"
#      assertion; the old guard had no equivalent at all.
#   B. Every CALL of those helpers in main.cpp passes a wait expression at the derived
#      index. A call that omits the argument (relying on the `= 0` default) has fewer
#      arguments than the index and is RED — that is precisely the dropped-wait defect.
#      A call that passes a literal, or that passes the wait into the WRONG slot, is RED.
#   C. Every CALL in the rest of $LIGHT_DIR (the routes main.cpp threads its wait
#      through, and the other CLI entry points: account_history, outbox, outbox_cli,
#      trustless_read, verify_state_root) does the same. main.cpp is the flag-parsing
#      layer; these are the layers it forwards into, and S-042 re-opens just as
#      silently there. TWO carve-outs, both described below.
#   D. The help/usage block advertises `[--wait <seconds>]` on at least MIN_WAIT_HELP
#      head-anchored command lines. LOWER BOUND, so adding wait-aware commands never
#      falsely fails; it fires only if the help surface is gutted.
#   E. Non-vacuity: at least one call site of each helper — named or derived — was
#      actually examined, so a parse that silently matched nothing cannot report green.
#
# CARVE-OUT 1 — "there is no wait to forward" (DERIVED, not a list). A binding call may
# omit the wait iff the FILE it lives in contains no wait identifier anywhere in its
# code (comments and string literals do not count). Such a file has no operator `--wait`
# and no wait parameter to thread, so there is nothing to drop. This is self-
# invalidating by construction: the moment that file gains a `--wait` or a wait
# parameter, every binding call in it must forward one or the guard goes RED. Today it
# covers `verify_state_bundle.cpp` only (`export-state-bundle` parses no `--wait` and
# `ExportStateBundleOptions` has no wait field; the call annotates the slot
# `/*max_wait_seconds=*/0`). `outbox_selftest.cpp` USED to be covered too — it drives an
# in-memory `FixtureRpc`, not a daemon — but since 2026-09-18 it exercises the wait
# deliberately (the S-112 case), so it HAS a wait to forward and is no longer excused:
# every binding call in it now passes a named wait, including the zero the control read
# uses because the fixture's successor is always one poll away. No hand-maintained
# exception list, so nothing here rots on a line shift or a rename.
#
# CARVE-OUT 2 — KNOWN GAPS (a named, dated, reported product finding, NOT an approval).
# The list is EMPTY as of 2026-09-18 and the mechanism is kept, because it is what makes
# a standing permission impossible to leave behind. Its one entry was S-112:
# `light/outbox_cli.cpp::cmd_enqueue` called `read_account_trustless` for its nonce hint
# WITHOUT forwarding a wait, while `outbox`'s shared `parse_args` accepted `--wait` for
# every verb and only `outbox reconcile` forwarded it — so `outbox enqueue --wait N` was
# accepted and was silently a no-op, the exact S-042 symptom class. It was found by the
# 2026-09-18 repair that extended this guard past main.cpp, and CLOSED the same day
# (S-113): the hint read became `light/outbox.cpp::nonce_hint_trustless`, whose
# `wait_seconds` parameter has NO default, so omitting it no longer compiles; this guard
# sees that route as a DERIVED helper and requires `cmd_enqueue` to pass a wait
# expression into its slot. Because the list is PINNED, deleting the entry was not
# optional: a fixed gap is RED until its entry goes, exactly as a second route-layer drop
# is RED for having no entry. Nothing here is an approval; a future increment that needs
# an entry must name, date and report it, and it goes RED again the day it is fixed.
#
# SELFTEST (SELFTEST=1): copies $LIGHT_DIR to a scratch tree, injects one synthetic
# violation per invariant, and asserts the guard flags each. Proves the checks are live,
# not tautological. No real source is modified. Run:
#       SELFTEST=1 bash tools/test_light_wait_surface.sh
# LIGHT_DIR=<dir> points the production path at a scratch copy of light/ — the hook the
# external mutant harness uses so the transcripts are runs of the PRODUCTION path, not
# of a private copy of the logic. It defaults to `light` and nothing in ci_local or
# run_all.sh sets it; the analyzed directory is echoed in the header line.
#
# Optional live cross-check (only when DETERM_LIGHT is set): also assert the
# `$DETERM_LIGHT help` output advertises `[--wait <seconds>]`. SKIPs cleanly when unset
# — the guard's verdict NEVER depends on a binary being present.
#
# Pure read-only source check. Needs NO determ binary, never requires a build/cluster.
# Deterministic + offline. Needs python3 for the argument-list parse; a box without it
# FAILS CLOSED rather than printing a pass it did not earn (wave doctrine lesson 15).
# run_all.sh auto-discovers it (tools/test_*.sh) and reads the single terminal
# PASS:/FAIL: marker.
#
# Exit 0 = every head-anchored binding consumer forwards --wait into the declared wait
# slot; exit 1 = a binding call site dropped it (S-042 usability regression) or the
# guard could not establish the property.
set -u
cd "$(dirname "$0")/.."

LIGHT_DIR="${LIGHT_DIR:-light}"
MIN_WAIT_HELP=19   # invariant D floor; 19 measured 2026-09-18. Never an exact count.

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

if ! command -v python3 >/dev/null 2>&1; then
  echo "  FAIL: test_light_wait_surface — python3 is required to parse argument lists; a guard that cannot run must not report green"
  exit 1
fi

# ── check_invariants <light-dir> ────────────────────────────────────────────────
# Runs A–E against <light-dir> (the real light/ in production, a mutated scratch copy
# under SELFTEST). Prints ok/bad and increments VIOLATIONS.
check_invariants() {
  local dir="$1" out rc line
  out=$(python3 - "$dir" "$MIN_WAIT_HELP" <<'PYSCAN'
import os, re, sys

LIGHT_DIR = sys.argv[1]
MIN_HELP  = int(sys.argv[2])
WAIT_RE   = re.compile(r'^(?:max_)?wait(?:_seconds)?$')
WAIT_EXPR = re.compile(r'(?<![A-Za-z0-9_])(?:max_)?wait(?:_seconds)?(?![A-Za-z0-9_])')
ANY_WAIT  = re.compile(r'(?<![A-Za-z0-9_])[A-Za-z0-9_]*wait[A-Za-z0-9_]*(?![A-Za-z0-9_])', re.I)
BASE_HELPERS = ["committee_bound_state_root", "verify_state_root_at",
                "read_account_trustless", "read_stake_trustless"]

# CARVE-OUT 2 — KNOWN GAPS. (file, enclosing function, helper) -> why. A named,
# reported product finding, not an approval; see the header. The list is PINNED:
# it must match EXACTLY, so a second route-layer drop is RED and a closed gap is
# RED until its entry is deleted here. EMPTY since 2026-09-18, when its only
# entry (S-112, outbox_cli.cpp::cmd_enqueue) was fixed and therefore had to go.
KNOWN_GAP = {
}

out = []
def OK(m):   out.append("OK " + m)
def BAD(m):  out.append("BAD " + m)
def NOTE(m): out.append("note: " + m)
def GAP(m):  out.append("GAP: " + m)

def blank(src):
    """Blank comment bodies and string/char literal bodies, preserving every newline so
    line numbers are unchanged. A helper name, a wait token or a comma inside a comment
    or a string can then never be mistaken for code."""
    o = list(src); i = 0; n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i+1] == '/':
            while i < n and src[i] != '\n': o[i] = ' '; i += 1
            continue
        if c == '/' and i + 1 < n and src[i+1] == '*':
            o[i] = o[i+1] = ' '; i += 2
            while i < n and not (src[i] == '*' and i + 1 < n and src[i+1] == '/'):
                if src[i] != '\n': o[i] = ' '
                i += 1
            if i < n: o[i] = o[i+1] = ' '; i += 2
            continue
        if c in '"\'':
            q = c; j = i + 1
            while j < n:
                if src[j] == '\\': j += 2; continue
                if src[j] == q: j += 1; break
                if src[j] == '\n': break
                j += 1
            for k in range(i + 1, min(j - 1, n)):
                if src[k] != '\n': o[k] = '_'
            i = j; continue
        i += 1
    return ''.join(o)

def split_args(s):
    """Split an argument/parameter list on TOP-LEVEL commas. Tracks () [] {} and skips a
    balanced template <...> whose '<' follows an identifier, so std::map<K, V> is one
    part. Returns [] for an empty list."""
    parts = []; depth = 0; cur = ''; i = 0; n = len(s)
    while i < n:
        c = s[i]
        if c == '<' and cur and (cur[-1].isalnum() or cur[-1] == '_'):
            d = 0; j = i
            while j < n:
                if s[j] == '<': d += 1
                elif s[j] == '>':
                    d -= 1
                    if d == 0: break
                elif s[j] in ';{}': j = n; break
                j += 1
            if j < n:
                cur += s[i:j+1]; i = j + 1; continue
        if c in '([{': depth += 1; cur += c
        elif c in ')]}': depth -= 1; cur += c
        elif c == ',' and depth == 0: parts.append(cur); cur = ''
        else: cur += c
        i += 1
    if cur.strip() or parts: parts.append(cur)
    return [' '.join(p.split()) for p in parts]

def param_name(p):
    """The declared NAME of a parameter, or None. Strips a default initializer first."""
    p = re.split(r'(?<![<>=!])=(?!=)', p, 1)[0].strip()
    m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', p)
    return m.group(1) if m else None

def is_param_list(parts):
    """True iff every part looks like a PARAMETER declaration (a type plus a name). This,
    not the trailing punctuation, separates a declaration/definition from a call: a call
    ends in ';' too, but its first argument is a bare expression."""
    if not parts: return False
    for p in parts:
        if not p or '.' in p or '->' in p or '(' in p: return False
        head = re.split(r'(?<![<>=!])=(?!=)', p, 1)[0]
        words = [w for w in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', head) if w != 'const']
        if len(words) < 2: return False
    return True

def funcs_of(src):
    return [(src.count('\n', 0, m.start()) + 1, m.group(1))
            for m in re.finditer(
                r'(?m)^[A-Za-z_][A-Za-z0-9_:<>*&, ]*?\s[*&]?([A-Za-z_][A-Za-z0-9_]*)\s*\(', src)]

def enclosing(fns, ln):
    best = '<file-scope>'
    for sl, nm in fns:
        if sl <= ln: best = nm
        else: break
    return best

def sites(src, name):
    """Every occurrence of `name(` in BLANKED source: (line, parts, is_decl)."""
    res = []
    for m in re.finditer(r'(?<![A-Za-z0-9_])' + name + r'\s*\(', src):
        ln = src.count('\n', 0, m.start()) + 1
        i = m.end(); d = 1
        while i < len(src) and d > 0:
            if src[i] == '(': d += 1
            elif src[i] == ')': d -= 1
            i += 1
        if d != 0: continue
        parts = split_args(src[m.end():i-1])
        res.append((ln, parts, is_param_list(parts)))
    return res

files = {}
for fn in sorted(os.listdir(LIGHT_DIR)):
    if fn.endswith(('.hpp', '.cpp')):
        raw = open(os.path.join(LIGHT_DIR, fn), encoding='utf-8', errors='replace').read()
        files[fn] = (raw, blank(raw))
if 'main.cpp' not in files:
    BAD("main.cpp is absent from %s — a guard with no target cannot report green" % LIGHT_DIR)
    print('\n'.join(out)); sys.exit(2)
fns_of = {fn: funcs_of(b) for fn, (r, b) in files.items()}
# A file "has a wait to forward" if its CODE names a wait identifier OR its text offers a
# `--wait` flag. The second half closes the hole where a new CLI parses `--wait` into a
# differently-named variable and would otherwise be excused as having nothing to forward.
has_wait = {fn: bool(ANY_WAIT.search(b)) or ('--wait' in raw)
            for fn, (raw, b) in files.items()}

def body_after(b, i):
    """The brace-matched body that starts at the first '{' at or after i, or ''."""
    j = b.find('{', i)
    if j < 0: return ''
    d = 0; k = j
    while k < len(b):
        if b[k] == '{': d += 1
        elif b[k] == '}':
            d -= 1
            if d == 0: return b[j:k+1]
        k += 1
    return b[j:]

# The helper set is DERIVED, not only listed: any function that takes a wait parameter
# AND reaches a binding call is itself a binding route, so its own callers must forward.
# Without this an intermediate helper could be introduced and its callers drop the wait
# while every listed helper still checked out. Today it adds
# account_history.cpp::verify_header_state_root_at, outbox.cpp::verify_and_bind and
# outbox.cpp::nonce_hint_trustless (the S-112 fix: the enqueue nonce hint became a named
# route whose wait parameter has no default, so this guard checks cmd_enqueue's call into
# it exactly as it checks any other route).
HELPERS = list(BASE_HELPERS)
for fn, (raw, b) in files.items():
    for m in re.finditer(
            r'(?m)^[A-Za-z_][A-Za-z0-9_:<>*&, ]*?\s[*&]?([A-Za-z_][A-Za-z0-9_]*)\s*\(', b):
        nm = m.group(1)
        if nm in HELPERS: continue
        i = m.end(); d = 1
        while i < len(b) and d > 0:
            if b[i] == '(': d += 1
            elif b[i] == ')': d -= 1
            i += 1
        params = split_args(b[m.end():i-1])
        if not is_param_list(params): continue
        if not any(param_name(p) and WAIT_RE.match(param_name(p)) for p in params): continue
        if b[i:b.find('{', i) if b.find('{', i) >= 0 else i].strip(): continue
        body = body_after(b, i)
        if re.search(r'(?<![A-Za-z0-9_])committee_bound_state_root\s*\(', body) or \
           any(re.search(r'(?<![A-Za-z0-9_])%s\s*\(' % h, body) for h in BASE_HELPERS[1:]):
            HELPERS.append(nm)
derived = [h for h in HELPERS if h not in BASE_HELPERS]
if derived:
    NOTE("derived binding route(s) beyond the four named helpers, checked the same way: %s"
         % ", ".join(sorted(derived)))

# ── A: derive each helper's wait-parameter index FROM ITS DECLARATION ────────────
widx = {}
for h in HELPERS:
    decls = [(fn, ln, parts) for fn, (raw, b) in files.items()
             for ln, parts, isdecl in sites(b, h) if isdecl]
    if not decls:
        BAD("A %s: no declaration found anywhere in %s — cannot derive the wait slot"
            % (h, LIGHT_DIR)); continue
    idxs = set(); arity = {}; broken = False
    for fn, ln, parts in decls:
        found = [k for k, p in enumerate(parts, 1)
                 if param_name(p) and WAIT_RE.match(param_name(p))]
        if len(found) != 1:
            BAD("A %s declared at %s:%d has %d parameter(s) named (max_)wait_seconds, "
                "expected exactly 1 — the S-042 wait parameter was removed or renamed"
                % (h, fn, ln, len(found))); broken = True; continue
        # ONLY the index is pinned. Arity is deliberately NOT compared across
        # declarations: a mismatch there is a compile error, and pinning it would make
        # the guard rot on exactly the signature growth it exists to survive.
        idxs.add(found[0]); arity[found[0]] = len(parts)
    if broken or not idxs: continue
    if len(idxs) != 1:
        BAD("A %s: its %d declarations disagree on WHICH argument is the wait (%s) — "
            "ambiguous signature" % (h, len(decls), sorted(idxs))); continue
    k = idxs.pop(); np = arity[k]
    widx[h] = k
    OK("A %s declares its wait parameter at argument %d of %d (%d declaration(s)) — "
       "slot DERIVED from the signature, not pinned" % (h, k, np, len(decls)))

# ── B/C: every CALL passes a wait expression at the derived index ────────────────
examined = {h: 0 for h in HELPERS}
gaps_hit = set()
for tag, flist, label in (
        ("B", ["main.cpp"], "main.cpp command handlers"),
        ("C", [f for f in sorted(files) if f != "main.cpp"],
              "the routes and other CLI entry points")):
    good = bad = nowait = gap = 0
    for fn in flist:
        raw, b = files[fn]
        for h in HELPERS:
            if h not in widx: continue
            k = widx[h]
            for ln, parts, isdecl in sites(b, h):
                if isdecl: continue
                examined[h] += 1
                arg = parts[k-1] if len(parts) >= k else None
                encl = enclosing(fns_of[fn], ln)
                if arg is not None and WAIT_EXPR.search(arg):
                    good += 1; continue
                key = (fn, encl, h)
                if key in KNOWN_GAP:
                    gap += 1; gaps_hit.add(key)
                    GAP("%s:%d %s::%s -> %s() does NOT forward a wait (slot %d = %s) — %s"
                        % (fn, ln, fn, encl, h, k,
                           "omitted" if arg is None else "'%s'" % arg, KNOWN_GAP[key]))
                    continue
                if tag == "C" and not has_wait[fn]:
                    nowait += 1
                    NOTE("%s:%d %s() wait slot %d = %s — %s has NO wait identifier in its "
                         "code at all, so there is nothing to forward (derived carve-out)"
                         % (fn, ln, h, k, "omitted" if arg is None else "'%s'" % arg, fn))
                    continue
                bad += 1
                if arg is None:
                    out.append("    %s:%d %s(): only %d argument(s) but the wait slot is %d "
                               "— the wait argument is OMITTED and silently defaults "
                               "(S-042 dropped wait) [%s]" % (fn, ln, h, len(parts), k, encl))
                else:
                    extra = ""
                    misplaced = [i for i, p in enumerate(parts, 1) if WAIT_EXPR.search(p)]
                    if misplaced:
                        extra = (" — a wait expression IS passed, at argument %d, i.e. into "
                                 "the WRONG slot" % misplaced[0])
                    out.append("    %s:%d %s(): wait slot %d holds '%s', not a wait "
                               "expression%s [%s]" % (fn, ln, h, k, arg, extra, encl))
    total = good + bad + nowait + gap
    if total == 0:
        BAD("%s no binding call site found in %s — the scan matched nothing, so nothing "
            "was asserted" % (tag, label))
    elif bad == 0:
        OK("%s %d binding call(s) examined in %s: %d forward a wait expression at the "
           "declared slot, %d have no wait to forward, %d known gap(s); none unaccounted for"
           % (tag, total, label, good, nowait, gap))
    else:
        BAD("%s %d of %d binding call(s) in %s do NOT pass a wait expression at the "
            "declared slot (S-042 head-read REGRESSION)" % (tag, bad, total, label))

# The known-gap list is PINNED, so it cannot silently outlive its cause.
stale = [k for k in KNOWN_GAP if k not in gaps_hit]
if stale:
    BAD("C known gap(s) %s no longer match a non-forwarding call — the gap is CLOSED or "
        "moved; delete the entry from KNOWN_GAP rather than leaving a standing permission"
        % ", ".join("%s::%s -> %s" % k for k in stale))
elif KNOWN_GAP:
    OK("C the known-gap list is exact: all %d entr(y/ies) still name a real "
       "non-forwarding call, and no other route-layer call drops the wait" % len(KNOWN_GAP))
else:
    NOTE("C the known-gap list is EMPTY — no route-layer call holds a standing permission "
         "to drop the wait (S-112 closed 2026-09-18 by outbox.cpp::nonce_hint_trustless)")

# ── D: help surface floor ───────────────────────────────────────────────────────
n_help = files['main.cpp'][0].count('[--wait <seconds>]')
if n_help >= MIN_HELP:
    OK("D help block advertises [--wait <seconds>] on %d line(s) (>= floor %d)"
       % (n_help, MIN_HELP))
else:
    BAD("D only %d help line(s) carry [--wait <seconds>] (< floor %d) — the wait surface "
        "shrank below the head-anchored command set" % (n_help, MIN_HELP))

# ── E: non-vacuity ──────────────────────────────────────────────────────────────
missing = [h for h in HELPERS if examined.get(h, 0) == 0]
if not missing:
    OK("E every helper has at least one examined call site (%s)"
       % ", ".join("%s=%d" % (h, examined[h]) for h in HELPERS))
else:
    BAD("E no call site examined for: %s — the scan matched nothing for these helpers, so "
        "their invariant asserted nothing" % ", ".join(missing))

print('\n'.join(out))
PYSCAN
)
  rc=$?
  while IFS= read -r line; do
    case "$line" in
      "OK "*)   ok  "${line#OK }" ;;
      "BAD "*)  bad "${line#BAD }" ;;
      "GAP: "*) echo "  ${line}" >&2 ;;
      "")       ;;
      *)        echo "    $line" >&2 ;;
    esac
  done <<< "$out"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    bad "scanner exited $rc — the guard could not complete its analysis of $dir"
  fi
}

# ── SELFTEST mode (SELFTEST=1) ────────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: S-042 wait-surface guard liveness (inject regressions -> expect RED) ==="
  if [ ! -d "$LIGHT_DIR" ] || [ ! -f "$LIGHT_DIR/main.cpp" ]; then
    echo "  FAIL: $LIGHT_DIR/main.cpp absent — cannot run SELFTEST"; exit 1
  fi
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/s042wait.$$")
  mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT

  # Wave-doctrine lesson 5: a harness must REFUSE a verdict when the mutation never
  # reached the source. Every injected case must differ from the clean copy.
  st_reached() {
    if diff -rq "$clean_dir" "$1" >/dev/null 2>&1; then
      echo "  bad: $2 -> MUTATION DID NOT REACH THE SOURCE (scratch tree identical to clean); refusing to report a verdict" >&2
      ST_FAIL=$((ST_FAIL + 1)); return 1
    fi
    return 0
  }
  st_expect_red() {
    # $1 label  $2 scratch light dir (already mutated). Expects >=1 violation.
    st_reached "$2" "$1" || return 0
    local label="$1" sdir="$2" before="$VIOLATIONS" delta
    check_invariants "$sdir" >/dev/null 2>&1
    delta=$((VIOLATIONS - before))
    VIOLATIONS="$before"   # reset — selftest must not pollute the real count
    if [ "$delta" -ge 1 ]; then echo "  ok:  $label -> flagged ($delta violation(s))"
    else
      echo "  bad: $label -> NOT flagged (guard is not live for this regression)" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  mk() { rm -rf "$tmproot/$1"; cp -r "$LIGHT_DIR" "$tmproot/$1"; echo "$tmproot/$1"; }

  # Sanity: a faithful copy of the real source must PASS (zero violations).
  clean=$(mk clean); clean_dir="$clean"
  before="$VIOLATIONS"; check_invariants "$clean" >/dev/null 2>&1
  if [ "$VIOLATIONS" = "$before" ]; then echo "  ok:  clean-copy sanity -> 0 violations"
  else echo "  bad: clean-copy sanity unexpectedly flagged" >&2; ST_FAIL=$((ST_FAIL + 1)); fi
  VIOLATIONS="$before"

  st_expect_green() {
    # $1 label  $2 scratch light dir. A LEGITIMATE change that must NOT flag.
    st_reached "$2" "$1" || return 0
    local label="$1" sdir="$2" before="$VIOLATIONS" delta
    check_invariants "$sdir" >/dev/null 2>&1
    delta=$((VIOLATIONS - before)); VIOLATIONS="$before"
    if [ "$delta" -eq 0 ]; then echo "  ok:  $label -> GREEN (0 violations) — the repaired guard does not rot on this"
    else
      echo "  bad: $label -> $delta violation(s), expected GREEN (the guard rots on this)" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # GA — THE ANTI-ROT CASE, and the reason this repair exists: the signature gains ANOTHER
  #      parameter AFTER the wait, exactly as expected_k/bft_enabled did. Every call then
  #      stops closing with the wait variable — which is what turned the OLD position pin
  #      RED on a correct tree — while the derived wait slot is unchanged. Must be GREEN.
  ga=$(mk ga)
  perl -0pi -e 's/(uint64_t max_wait_seconds = 0,\n)/$1                                       size_t future_param = 0,\n/' "$ga/trustless_read.hpp"
  perl -0pi -e 's/(committee_bound_state_root\(rpc, committee_json, anchor_index, wait_seconds, genesis\.k_block_sigs, genesis\.bft_enabled)\)/$1, 0)/g' "$ga/main.cpp"
  st_expect_green "GA the signature gains a parameter AFTER the wait (the change that broke the old pin)" "$ga"

  # GB — the wait parameter MOVES to a different position, declaration, definition and
  #      every call updated together. The old guard pinned "last"; this one reads the slot
  #      off the signature, so a coherent reorder must be GREEN. This is the strongest
  #      statement of what "derived, not pinned" buys.
  gb=$(mk gb)
  for f in "$gb"/*.hpp "$gb"/*.cpp; do
    perl -0pi -e 's/uint64_t anchor_index,(\s*\n\s*)uint64_t max_wait_seconds( = 0)?,/uint64_t max_wait_seconds$2,$1uint64_t anchor_index,/' "$f"
    perl -0pi -e 's/committee_bound_state_root\((\s*)rpc,(\s*)committee_json,(\s*)([A-Za-z_][A-Za-z0-9_ .\-]*?),(\s*)((?:max_)?wait_seconds|0),/committee_bound_state_root($1rpc,$2committee_json,$3$6,$5$4,/g' "$f"
  done
  st_expect_green "GB the wait parameter MOVES position, declaration/definition/calls together" "$gb"

  # RA: a main.cpp binding call drops the wait ARGUMENT entirely (falls back to the
  #     `= 0` default) — the literal S-042 defect.
  ra=$(mk ra)
  perl -0pi -e 's/committee_bound_state_root\(rpc, committee_json, anchor_index, wait_seconds, genesis\.k_block_sigs, genesis\.bft_enabled\)/committee_bound_state_root(rpc, committee_json, anchor_index)/' "$ra/main.cpp"
  st_expect_red "RA main.cpp binding call omits the wait argument" "$ra"

  # RB: a main.cpp binding call passes a LITERAL in the wait slot (wait silently 0).
  rb=$(mk rb)
  perl -0pi -e 's/committee_bound_state_root\(rpc, committee_json, anchor_index, wait_seconds,/committee_bound_state_root(rpc, committee_json, anchor_index, 0,/' "$rb/main.cpp"
  st_expect_red "RB main.cpp binding call passes a literal in the wait slot" "$rb"

  # RC: a helper call forwards the wait into the WRONG slot — the class the old
  #     position pin could never see, because the call still "closes" plausibly.
  rc=$(mk rc)
  perl -0pi -e 's/verify_state_root_at\(rpc, committee_seed, genesis_hash_hex, height, wait_seconds, genesis\.k_block_sigs, genesis\.bft_enabled\)/verify_state_root_at(rpc, committee_seed, genesis_hash_hex, height, 0, genesis.k_block_sigs, wait_seconds)/' "$rc/main.cpp"
  st_expect_red "RC helper call forwards the wait into the wrong slot" "$rc"

  # RD: the S-042 fix is reverted at the API — the wait parameter leaves the signature.
  rd=$(mk rd)
  perl -0pi -e 's/uint64_t max_wait_seconds = 0,\n//' "$rd/trustless_read.hpp"
  st_expect_red "RD committee_bound_state_root loses its wait parameter (API revert)" "$rd"

  # RE: a NON-main.cpp route drops the wait (the forwarding layer, invariant C).
  re=$(mk re)
  perl -0pi -e 's/committee_bound_state_root\(rpc, committee_json, h, wait_seconds,/committee_bound_state_root(rpc, committee_json, h, 0,/' "$re/outbox.cpp"
  st_expect_red "RE outbox.cpp route drops the wait" "$re"

  # RF: the export-path exception is abused — the excepted function gains a wait and
  #     keeps passing the literal, so the exception must stop applying.
  rf=$(mk rf)
  perl -0pi -e 's/int run_export_state_bundle\(const ExportStateBundleOptions& opts\) \{/int run_export_state_bundle(const ExportStateBundleOptions& opts) {\n    uint64_t wait_seconds = opts.wait_seconds;/' "$rf/verify_state_bundle.cpp"
  st_expect_red "RF excepted export path gains a wait but still passes a literal" "$rf"

  # RH: S-112 is RE-OPENED inside the route that closed it — the enqueue nonce hint
  #     reads with a literal 0 while the operator's wait sits unused in the parameter.
  #     This is the defect the (now empty) KNOWN_GAP entry used to name; with the entry
  #     gone, the ordinary invariant-C check is what must see it.
  rh=$(mk rh)
  perl -0pi -e 's/(read_account_trustless\(rpc, build_genesis_committee\(genesis\), genesis,\s*\n\s*sender, \/\*resume=\*\/false, \/\*state_path=\*\/"",\s*\n\s*)wait_seconds\)/${1}0)/' "$rh/outbox.cpp"
  st_expect_red "RH the S-112 route re-opened: nonce_hint_trustless reads with a literal 0" "$rh"

  # RJ: the CALL SITE drops it instead — cmd_enqueue passes a literal 0 into the route's
  #     wait slot. The route itself still forwards, so only the derived-helper check sees
  #     this; it is the half of S-112 the in-process runtime gate cannot reach.
  rj=$(mk rj)
  perl -0pi -e 's/nonce_hint_trustless\(rpc, genesis, ghash, kf\.anon_address, a\.wait\)/nonce_hint_trustless(rpc, genesis, ghash, kf.anon_address, 0)/' "$rj/outbox_cli.cpp"
  st_expect_red "RJ cmd_enqueue passes a literal 0 into the nonce-hint route's wait slot" "$rj"

  # RI: a NEW intermediate binding route is introduced and one of its callers drops the
  #     wait. The derived helper set is what sees this; a fixed list of four would not.
  ri=$(mk ri)
  cat >> "$ri/main.cpp" <<'CPPEOF'
std::string route_helper(RpcClient& rpc, const nlohmann::json& committee_json,
                         uint64_t idx, uint64_t wait_seconds) {
    return determ::light::committee_bound_state_root(rpc, committee_json, idx, wait_seconds);
}
int cmd_uses_route(int argc, char** argv) {
    std::string r = route_helper(rpc, committee_json, anchor_index);
    return 0;
}
CPPEOF
  st_expect_red "RI a new intermediate binding route whose caller drops the wait" "$ri"

  # RG: gut the help surface — strip every [--wait <seconds>] occurrence.
  rg=$(mk rg)
  perl -0pi -e 's/\[--wait <seconds>\]//g' "$rg/main.cpp"
  st_expect_red "RG help block stripped of [--wait <seconds>]" "$rg"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_wait_surface SELFTEST (flags all 10 regression classes, GREEN on the signature extension that broke the old pin)"
    exit 0
  else
    echo "  FAIL: test_light_wait_surface SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── Production path ───────────────────────────────────────────────────────────────
echo "=== S-042 determ-light --wait completeness guard (static; $LIGHT_DIR) ==="

if [ ! -d "$LIGHT_DIR" ] || [ ! -f "$LIGHT_DIR/main.cpp" ]; then
  # FAIL CLOSED (2026-09-18) — see tools/test_light_keybind_surface.sh.
  # $LIGHT_DIR/main.cpp is tracked; its absence is a broken checkout, not an
  # environment this guard declines on.
  echo "  FAIL: test_light_wait_surface — $LIGHT_DIR/main.cpp is absent; a guard with no target cannot report green"
  exit 1
fi

check_invariants "$LIGHT_DIR"

# Optional live cross-check — only when DETERM_LIGHT is set. SKIPs cleanly otherwise;
# the guard's verdict above does NOT depend on it.
if [ -n "${DETERM_LIGHT:-}" ] && [ -x "${DETERM_LIGHT}" ]; then
  if "$DETERM_LIGHT" help 2>/dev/null | grep -qF '[--wait <seconds>]'; then
    ok "live $DETERM_LIGHT help advertises [--wait <seconds>]"
  else
    bad "live $DETERM_LIGHT help does NOT advertise [--wait <seconds>] — built binary lost the wait surface"
  fi
else
  echo "  skip: DETERM_LIGHT unset/non-exec — static checks only (offline)."
fi

echo ""
echo "  not asserted here: that a forwarded wait is not shadowed by a hard-coded local,"
echo "  and the runtime behaviour of the wait itself — dataflow and liveness properties"
echo "  this static guard cannot see (tools/test_light_wait_flag.sh + the cluster leg)."
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_light_wait_surface (every head-anchored binding consumer forwards --wait into the declared wait slot; help surface intact)"
  exit 0
else
  echo "  FAIL: test_light_wait_surface ($VIOLATIONS S-042 wait-surface regression(s) — a head-anchored read may ignore --wait)"
  exit 1
fi
