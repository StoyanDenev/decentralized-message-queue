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
#     negative-honesty premise (NV-2/NV-3): the state-proof ABSENCE negatives,
#     where the verdict rests on the daemon replying `not_found`.
# F-2 surfaces the distinction in --json so a downstream consumer applies NV-6
# clause (2) (authoritative absence) vs clause (3) ("no proof obtained")
# AUTOMATICALLY rather than hard-coding which command it called.
#
# WHY THE CENSUS PINS WERE REMOVED (2026-09-18 repair — READ THIS BEFORE EDITING)
# ------------------------------------------------------------------------------
# The first revision pinned hard-coded counts: exactly 2 `cryptographic`, exactly 7
# `daemon_asserted` assignment-form, exactly 1 initializer-list, exactly 10 total. Those
# counts were a PROXY for "every negative-verdict surface carries a correctly-classed
# footing". `verify-notekey` (nk:) and `verify-enote-inclusion` (en:) later landed, each
# with a correctly gated and correctly labelled `daemon_asserted` footing, and the pins
# went RED on a tree that was right — 9 against 7, 12 against 10. The wrapper sits
# outside FAST and outside ci_local's doc guards, so it stayed red. Adjudicated as GUARD
# DRIFT in DECISION-LOG 2026-09-18; the class of the two new footings was re-established
# from the source by this increment (both set their negative verdict inside an
# `err == "not_found"` branch of the `state_proof` RPC reply, which is the definition of
# the DAEMON_ASSERTED class, and `verify-notekey`'s own comment says so: "Catches only a
# self-contradicting daemon; a consistent liar still forges the negative ((H-neg))").
#
# The repair does NOT raise the pins — a census pin updated without checking what it now
# counts is worse than a red pin, and it would rot again on the next command. The counts
# are replaced by properties DERIVED from the source:
#
#   1  COMPLETENESS (replaces the 2/7/1/10 pins). Every function that both names a
#      recognized NEGATIVE verdict in real code and emits json (any `.dump()`) must
#      emit `negative_footing`. Two code-derived sets, compared; no number. A NEW
#      negative-verdict command that forgets the field is RED; a new one that carries it
#      is GREEN with no edit here. That is the rot this repair removes.
#   1b MEMBERSHIP RATCHET (was a cardinality floor until 2026-09-18). The pinned SET of
#      commands that carry a footing must all still carry one. A floor could not see
#      clone-one-delete-one: delete one pinned command's negative-verdict surface, clone
#      another, and the COUNT is unchanged, so `>= 11` stayed green while the surface had
#      moved. Membership makes a removal and a substitution RED and still lets ADDITIONS
#      through untouched — a new negative-verdict command joins `need` with no edit here,
#      which is the rot the census pins were removed for. A deliberate RENAME is RED too
#      and must be re-pinned; that cost is the point, since the pin is what says a human
#      confirmed the command still owes and carries a footing.
#   2  GATING. Every emission is gated on a recognized negative-verdict condition, on a
#      real code line — never emitted for a positive or UNVERIFIABLE verdict. The
#      recognized set fails CLOSED: an unrecognized gate is RED, not silently allowed.
#   3  CLASS, DERIVED (the substantive strengthening). The old revision pinned each
#      emission's value to its GATE SHAPE, via a hard-coded map that assumed a bare
#      `verdict == InclusionVerdict::NOT_INCLUDED` means daemon_asserted. That map is the
#      same rot pattern one level up: `verify-tx-inclusion` uses the SAME enumerator for
#      a CRYPTOGRAPHIC negative. The class is now derived from HOW THE NEGATIVE WAS
#      ESTABLISHED: the guard collects every assignment made inside a `not_found` branch
#      of the enclosing command, and requires
#            absence-derived  <=>  "daemon_asserted".
#      That catches everything the gate-shape map caught (including the paired
#      cross-site swap) plus the mislabels the map was blind to, and it needs no edit
#      when a command is added.
#   3b A THIRD CRYPTOGRAPHIC FOOTING IS RED BY DESIGN, and this is the one deliberate
#      pin left. A `cryptographic` footing is a claim of soundness against a fully
#      Byzantine daemon; the guard recognizes exactly the two derivations
#      NegativeVerdictSoundness.md proves and refuses to bless a third. Adding a
#      `daemon_asserted` footing — the common case, the one that rotted — needs no edit;
#      adding a `cryptographic` one needs a human and a proof. The asymmetry is the point.
#   3c Non-vacuity: both classes are present and every emission was classified, so an
#      analysis that silently matched nothing cannot report green.
#   4  The initializer-list emission sits inside the NOT-RECORDED json object.
#   5  The F-5 two-sided ratchet on the unstake absence matcher (unchanged, it works).
#   6  The negative-verdict enumerator set has not GROWN. The recognized F-2 family is an
#      explicit list, which is a hole: a command using a NEW negative enumerator would be
#      invisible to 1. So the guard enumerates every NOT_/NO_ member of every `enum class
#      *Verdict` in light/ and requires the out-of-F-2-family remainder to be exactly the
#      four recorded ones. One (`Bind::NOT_INCLUDED`) is ESTABLISHED out of family — a
#      file-local return code in outbox.cpp that reaches no --json field. The other three
#      (committee-at-height, verify-equivocation, verify-selection) are recorded as NOT
#      ADJUDICATED: establishing whether they owe an F-2 footing needs those commands read
#      against NegativeVerdictSoundness, which is its own increment, and a contract must
#      not assert what it has not established. What IS asserted is that a FIFTH cannot be
#      inherited silently.
#
# WHAT THIS CANNOT SEE (so a green is not misread): it is a SOURCE contract. It cannot
# see the value a built binary actually emits, and it establishes the absence/non-absence
# dichotomy that IS the F-2 class boundary — it does not re-prove NV-1's full-set
# recompute, which is the proof document's job. The live behavioural leg (drive each
# command to its negative against a cluster and assert the emitted footing) is a CI/WSL2
# leg, documented and SKIPPED here, not faked.
#
# F-5 RATCHET: the unstake catch must match ONLY the `not_found` absence
# marker. The former `msg.find("no verified")` disjunct matched read_stake_-
# trustless's step-3 throw prefix ("domain has no verified stake leaf?"),
# which wraps EVERY state_proof RPC error — so any daemon refusal was
# classified NO-STAKE instead of UNVERIFIABLE (fail-open on the negative
# surface; NegativeVerdictSoundness.md F-5, fixed). It must not return.
#
# SELFTEST (SELFTEST=1): copies $LIGHT_DIR to a scratch tree, injects one synthetic
# violation per property (and one legitimate ADDITION that must stay GREEN), and asserts
# the guard's verdict on each. Proves the checks are live, not tautological, and proves
# the repaired contract does not rot on the change that broke the old one. Run:
#       SELFTEST=1 bash tools/test_light_negative_footing.sh
# LIGHT_DIR=<dir> points the production path at a scratch copy of light/ — the hook the
# external mutant harness uses so the transcripts are runs of the PRODUCTION path. It
# defaults to `light`; nothing in ci_local or run_all.sh sets it, and the analyzed
# directory is echoed in the header line.
#
# Pure read-only; no determ binary, no build, no cluster. Needs python3 for the
# source analysis; a box without it FAILS CLOSED rather than printing a pass it did not
# earn (wave doctrine lesson 15). FAIL-CLOSED when $LIGHT_DIR/main.cpp is absent.
# Run from repo root: bash tools/test_light_negative_footing.sh
set -u
cd "$(dirname "$0")/.."

LIGHT_DIR="${LIGHT_DIR:-light}"
# invariant 1b MEMBERSHIP ratchet; the 11 measured 2026-09-18, in `need`-order. This is
# a SUBSET pin, never an exact set: an ADDITION is green with no edit here, a removal or
# a substitution is RED. Replaced a `MIN_CMDS=11` cardinality floor, which clone-one-
# delete-one walked straight past.
PINNED_CMDS="cmd_verify_abort_record cmd_verify_account cmd_verify_dapp_registration \
cmd_verify_enote_inclusion cmd_verify_merge_state cmd_verify_notekey \
cmd_verify_param_change cmd_verify_receipt_inclusion cmd_verify_registrant \
cmd_verify_tx_inclusion cmd_verify_unstake_eligibility"

pass=0; fail=0; skip=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
no()  { echo "  FAIL: $1" >&2; fail=$((fail+1)); }
skp() { echo "  SKIP: $1"; skip=$((skip+1)); }

if ! command -v python3 >/dev/null 2>&1; then
    echo "  FAIL: test_light_negative_footing — python3 is required for the source analysis; a contract that cannot run must not report green"
    exit 1
fi

# ── run_contract <light-dir> ────────────────────────────────────────────────────
# Runs 1..5 against <light-dir>. Prints PASS/FAIL and updates the counters.
run_contract() {
  local dir="$1" out rc line
  out=$(python3 - "$dir" "$PINNED_CMDS" <<'PYSCAN'
import os, re, sys

LIGHT_DIR = sys.argv[1]
PINNED    = sorted(set(sys.argv[2].split()))
TARGET    = "main.cpp"
# Recognized NEGATIVE-verdict enumerators / literal. An emission gated on anything else
# is RED: the list fails CLOSED, it does not whitelist silently.
NEG_ENUM  = ["InclusionVerdict::NOT_INCLUDED", "AccountExistVerdict::NOT_CREATED",
             "UnstakeVerdict::NO_STAKE"]
NEG_LIT   = '"NOT-RECORDED"'
# Enumerators that LOOK like a negative verdict but are NOT in the F-2 family, each with
# the reason it is out of family. NOT ADJUDICATED by this contract: whether these three
# owe an F-2 footing was not established by the 2026-09-18 repair (it would need the
# three commands read against NegativeVerdictSoundness, which is its own increment), and
# a contract must not assert what it has not established. What IS asserted is that the
# out-of-family set has not GROWN: a fourth NOT_/NO_ verdict enumerator appearing in
# light/ turns this RED so the question is adjudicated then, not silently inherited.
OUT_OF_FAMILY = {
  "Bind::NOT_INCLUDED": "outbox.cpp's file-local return code for verify_and_bind, derived "
      "FROM InclusionVerdict::NOT_INCLUDED and consumed internally by reconcile — it "
      "reaches no --json verdict field; ESTABLISHED out of family 2026-09-18",
  "CommitteeVerdict::NOT_IN_COMMITTEE": "committee-at-height — non-membership in an "
      "authenticated committee list, not a state-proof absence; NOT ADJUDICATED",
  "EquivVerdict::NOT_EQUIVOCATION":     "verify-equivocation — 'no equivocation proven', "
      "an evidence verdict, not a state-proof absence; NOT ADJUDICATED",
  "SelectionVerdict::NOT_SELECTED":     "verify-selection — a recomputed draw outcome, "
      "not a state-proof absence; NOT ADJUDICATED",
}
# The two soundness-PROVED cryptographic derivations (NegativeVerdictSoundness.md §1.1).
# A third is a new soundness claim: justify it in the proof document and add it here.
CRYPTO_OK = {
  "cmd_verify_tx_inclusion":        "NV-1 full-set tx_root recompute + bijection gate",
  "cmd_verify_unstake_eligibility": "committee-anchored POSITIVE proof of a zero stake "
                                    "(s: leaf present, locked == 0)",
}

out = []
def OK(m):   out.append("OK " + m)
def BAD(m):  out.append("BAD " + m)
def NOTE(m): out.append("note: " + m)

def blank(src):
    """Blank comment bodies, preserving every newline so line numbers are unchanged. A
    gate, an enumerator or a not_found marker written in a comment can then never
    satisfy anything (the comment-spoofed-gate false-pass)."""
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
        i += 1
    return ''.join(o)

def funcs_of(src):
    return [(src.count('\n', 0, m.start()) + 1, m.group(1), m.start())
            for m in re.finditer(
                r'(?m)^[A-Za-z_][A-Za-z0-9_:<>*&, ]*?\s[*&]?([A-Za-z_][A-Za-z0-9_]*)\s*\(', src)]

def enclosing(fns, ln):
    best = '<file-scope>'
    for sl, nm, off in fns:
        if sl <= ln: best = nm
        else: break
    return best

def body_of(src, fns, ln):
    start = None
    for sl, nm, off in fns:
        if sl <= ln: start = off
        else: break
    if start is None: return ''
    i = src.find('{', start)
    if i < 0: return ''
    d = 0; j = i
    while j < len(src):
        if src[j] == '{': d += 1
        elif src[j] == '}':
            d -= 1
            if d == 0: return src[i:j+1]
        j += 1
    return src[i:]

def absence_targets(body):
    """Every assignment made INSIDE a `not_found` branch of `body`, as {(lhs, rhs_atom)}.
    This is what turns "which footing is this" from a hard-coded gate-shape map into a
    property derived from how the negative was actually established."""
    res = set()
    for m in re.finditer(r'(?:==\s*"not_found"|\.find\("not_found"\))', body):
        i = m.end(); d = 0
        while i < len(body):
            if body[i] == '(': d += 1
            elif body[i] == ')':
                if d == 0: i += 1; break
                d -= 1
            elif body[i] == ';': break
            i += 1
        while i < len(body) and body[i] in ' \t\r\n': i += 1
        if i < len(body) and body[i] == '{':
            d = 0; j = i
            while j < len(body):
                if body[j] == '{': d += 1
                elif body[j] == '}':
                    d -= 1
                    if d == 0: break
                j += 1
            region = body[i:j+1]
        else:
            j = body.find(';', i)
            region = body[i:j+1] if j > 0 else body[i:i+200]
        for a in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);', region):
            mm = re.search(r'([A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*|true|false)\s*$',
                           a.group(2).strip())
            if mm: res.add((a.group(1), mm.group(1)))
    return res

def gate_atoms(gate):
    enums = [(m.group(1), m.group(2), m.group(3)) for m in
             re.finditer(r'(?:([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*==\s*'
                         r'([A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*)', gate)]
    bools = [(m.group(2) == '!', m.group(3)) for m in
             re.finditer(r'(&&|\|\||\(|^)\s*(!?)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=&&|\|\||\)|$)', gate)]
    return enums, bools

path = os.path.join(LIGHT_DIR, TARGET)
if not os.path.isfile(path):
    BAD("%s is absent — a source contract with no source cannot report green" % path)
    print('\n'.join(out)); sys.exit(2)
raw      = open(path, encoding='utf-8', errors='replace').read()
src      = blank(raw)
lines    = src.split('\n')
rawlines = raw.split('\n')
fns      = funcs_of(src)
other = {}
for fn in sorted(os.listdir(LIGHT_DIR)):
    if fn.endswith('.cpp') and fn != TARGET:
        other[fn] = blank(open(os.path.join(LIGHT_DIR, fn),
                               encoding='utf-8', errors='replace').read())

EMIT_ASSIGN = re.compile(r'out\["negative_footing"\]\s*=')
EMIT_INIT   = re.compile(r'\{"negative_footing"\s*,')
emissions = []
for i, l in enumerate(lines, 1):
    if   EMIT_ASSIGN.search(l): emissions.append((i, 'assign', l))
    elif EMIT_INIT.search(l):   emissions.append((i, 'init', l))

# ── 1 / 1b: COMPLETENESS + floor (derived; no census pin) ────────────────────────
neg_fns, json_fns, foot_fns = set(), set(), set()
for i, l in enumerate(lines, 1):
    f = enclosing(fns, i)
    if any(e in l for e in NEG_ENUM) or NEG_LIT in l: neg_fns.add(f)
    if '.dump()' in l: json_fns.add(f)
for ln, kind, l in emissions: foot_fns.add(enclosing(fns, ln))
need    = sorted(neg_fns & json_fns)
missing = [f for f in need if f not in foot_fns]
extra   = sorted(foot_fns - set(need))
if not need:
    BAD("1 no function both names a negative verdict and emits --json — the scan matched "
        "nothing, so nothing was asserted")
elif missing:
    BAD("1 %d command(s) have a negative-verdict --json surface with NO negative_footing "
        "emission: %s — F-2 is incomplete, a consumer cannot tell NV-6 clause (2) from (3)"
        % (len(missing), ", ".join(missing)))
elif extra:
    BAD("1 %d function(s) emit negative_footing with no negative-verdict --json surface: "
        "%s — a footing on a non-negative surface" % (len(extra), ", ".join(extra)))
else:
    OK("1 completeness: the %d command(s) with a negative-verdict --json surface are "
       "EXACTLY the %d that emit negative_footing (both sets derived from the source; "
       "no census pin)" % (len(need), len(foot_fns)))
gone = [c for c in PINNED if c not in need]
if not PINNED:
    BAD("1b the pinned command set is EMPTY — a ratchet with nothing pinned asserts "
        "nothing about the F-2 surface")
elif gone:
    BAD("1b %d pinned command(s) no longer carry a negative-verdict footing: %s — the F-2 "
        "surface SHRANK or was substituted (a count would not see this: deleting one and "
        "cloning another keeps it at %d). If the command was deliberately renamed or "
        "retired, re-pin PINNED_CMDS and say why" % (len(gone), ", ".join(gone), len(need)))
else:
    OK("1b membership ratchet: all %d pinned command(s) still carry a negative-verdict "
       "footing (%d carry one in all — additions are free, removals and substitutions "
       "are RED)" % (len(PINNED), len(need)))

# ── 2 / 3 / 3b: gating + DERIVED class ──────────────────────────────────────────
ungated = mism = unknown = 0
seen = {'cryptographic': 0, 'daemon_asserted': 0}
for ln, kind, l in emissions:
    f    = enclosing(fns, ln)
    body = body_of(src, fns, ln)
    mv   = re.search(r'"(cryptographic|daemon_asserted)"', l)
    val  = mv.group(1) if mv else None
    if kind == 'assign':
        gate = lines[ln-2]
    else:
        # An init-list emission sits inside a json object inside the enclosing if-chain;
        # take EVERY `if (...)` in the preceding window as the gate, so the governing
        # condition is found wherever in the chain it sits. A spurious atom can only make
        # the class UNDECIDABLE (RED), never wrongly green.
        gate = "\n".join(lines[k] for k in range(max(ln-26, 0), ln-1)
                         if re.search(r'\bif\s*\(', lines[k]))
    if val is None:
        unknown += 1
        out.append("    %s:%d emission carries no recognized footing value: %s"
                   % (TARGET, ln, l.strip()[:80])); continue
    enums, bools = gate_atoms(gate)
    at = absence_targets(body)
    absence_bools = {n for neg, n in bools if (n, 'false') in at}
    neg_ok = any(e[2] in NEG_ENUM for e in enums) or bool(absence_bools)
    if kind == 'init':
        neg_ok = neg_ok and (NEG_LIT in '\n'.join(lines[max(ln-6,0):ln+1]))
    if not neg_ok:
        ungated += 1
        out.append("    %s:%d UNGATED: gate '%s' names no recognized negative verdict — "
                   "the field would be emitted for a positive or UNVERIFIABLE verdict"
                   % (TARGET, ln, gate.strip().replace('\n', ' ')[:72])); continue
    derived = None; why = ''
    for obj, lhs, en in enums:
        if en in NEG_ENUM and (lhs, en) in at:
            derived = 'daemon_asserted'
            why = "%s = %s is assigned inside a not_found branch of %s" % (lhs, en, f)
    for neg, name in bools:
        if name in absence_bools:
            if neg:
                derived = 'daemon_asserted'
                why = ("the gate tests !%s and %s = false is assigned inside a not_found "
                       "branch" % (name, name))
            elif derived != 'daemon_asserted':
                derived = 'cryptographic'
                why = ("the gate tests %s, which is false only in the not_found branch, so "
                       "the leaf was READ, not asserted absent" % name)
    if derived is None:
        callee = None
        for obj, lhs, en in enums:
            if obj:
                m = re.search(r'\b%s\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(' % re.escape(obj), body)
                if m: callee = m.group(1)
        if callee and not any(re.search(r'\b%s\s*\(' % re.escape(callee), b) and 'not_found' in b
                              for b in other.values()):
            derived = 'cryptographic'
            why = ("the verdict comes from %s(), whose implementation carries no not_found "
                   "absence classifier" % callee)
        elif not at:
            derived = 'cryptographic'
            why = ("%s has no not_found branch at all, so its negative is not a daemon "
                   "absence assertion" % f)
    if derived is None:
        unknown += 1
        out.append("    %s:%d class UNDECIDABLE from the source (gate '%s') — the contract "
                   "refuses to bless a footing whose class it cannot derive"
                   % (TARGET, ln, gate.strip().replace('\n', ' ')[:60])); continue
    if derived != val:
        mism += 1
        out.append("    %s:%d footing '%s' contradicts the class DERIVED from the source, "
                   "'%s': %s" % (TARGET, ln, val, derived, why)); continue
    if val == 'cryptographic' and f not in CRYPTO_OK:
        mism += 1
        out.append("    %s:%d %s claims a CRYPTOGRAPHIC footing but is not one of the "
                   "soundness-proved derivations — a new cryptographic negative is a NEW "
                   "SOUNDNESS CLAIM: prove it in NegativeVerdictSoundness.md and add it to "
                   "CRYPTO_OK" % (TARGET, ln, f)); continue
    seen[val] += 1
    NOTE("%s:%d %s -> %s (%s)" % (TARGET, ln, f, val, why))

if not emissions:
    BAD("2 no negative_footing emission found at all — nothing was asserted")
elif ungated == 0:
    OK("2 all %d emission(s) gated on a recognized negative verdict, on a real code line "
       "— never emitted for a positive or UNVERIFIABLE verdict" % len(emissions))
else:
    BAD("2 %d emission(s) ungated or gated on an unrecognized condition" % ungated)

if emissions and mism == 0 and unknown == 0:
    OK("3 every emission's footing matches the class DERIVED from how its negative was "
       "established — absence-derived <=> daemon_asserted (%d cryptographic + %d "
       "daemon_asserted); catches the paired cross-site swap, which preserves any count"
       % (seen['cryptographic'], seen['daemon_asserted']))
else:
    BAD("3 %d emission(s) whose footing contradicts its derived class, %d undecidable"
        % (mism, unknown))

if seen['cryptographic'] >= 1 and seen['daemon_asserted'] >= 1:
    OK("3c non-vacuity: both footing classes are present and derived (%d + %d), and the "
       "only cryptographic derivations recognized are the %d proved in "
       "NegativeVerdictSoundness.md"
       % (seen['cryptographic'], seen['daemon_asserted'], len(CRYPTO_OK)))
else:
    BAD("3c a footing class is absent (%d cryptographic, %d daemon_asserted) — a wholesale "
        "reclassification would go unnoticed" % (seen['cryptographic'], seen['daemon_asserted']))

# ── 4: init-list emission co-located with the NOT-RECORDED verdict ──────────────
bad4 = n4 = 0
for ln, kind, l in emissions:
    if kind != 'init': continue
    n4 += 1
    if NEG_LIT not in '\n'.join(lines[max(ln-6, 0):ln+1]): bad4 += 1
if n4 == 0:
    BAD("4 no initializer-list emission found — the b: reader's inline json emission is "
        "gone, or the scan stopped seeing that shape")
elif bad4 == 0:
    OK("4 all %d initializer-list emission(s) co-located with the NOT-RECORDED verdict "
       "(b: reader)" % n4)
else:
    BAD("4 %d initializer-list emission(s) NOT inside a NOT-RECORDED json object" % bad4)

# ── 5: F-5 two-sided ratchet on the unstake absence matcher ─────────────────────
if 'msg.find("no verified")' not in src:
    OK('5a F-5 ratchet (neg): no msg.find("no verified") disjunct — only the not_found '
       'marker classifies NO-STAKE')
else:
    BAD('5a F-5 regression: msg.find("no verified") is back — every state_proof RPC error '
        'would classify as NO-STAKE instead of UNVERIFIABLE')
have_m = have_t = 0
for i, l in enumerate(lines, 1):
    if re.search(r'if \(msg\.find\("not_found"\) != std::string::npos\)', l):
        have_m = 1
        for k in range(i, min(i+6, len(lines)+1)):
            if re.match(r'^\s*throw;', lines[k-1]): have_t = 1
if have_m and have_t:
    OK('5b F-5 ratchet (pos): the unstake catch keys on msg.find("not_found") and rethrows '
       '(bare throw;) on any other failure — it cannot be deleted or short-circuited to '
       'if(true) without going RED')
else:
    BAD("5b F-5 regression: the not_found matcher (found=%d) or its fail-closed rethrow "
        "(found=%d) is missing — the absence classifier may be deleted or short-circuited "
        "(fail-open)" % (have_m, have_t))

# ── 6: the out-of-family negative enumerator set has not GROWN ──────────────────
seen_enum = set()
for fn in sorted(os.listdir(LIGHT_DIR)):
    if not fn.endswith(('.hpp', '.cpp')): continue
    b = blank(open(os.path.join(LIGHT_DIR, fn), encoding='utf-8', errors='replace').read())
    for m in re.finditer(r'enum\s+class\s+([A-Za-z_]\w*)[^{]*\{([^}]*)\}', b, re.S):
        for e in re.findall(r'\b(NOT_[A-Z0-9_]+|NO_[A-Z0-9_]+)\b', m.group(2)):
            seen_enum.add(m.group(1) + '::' + e)
unknown_enum = sorted(e for e in seen_enum
                      if e not in NEG_ENUM and e not in OUT_OF_FAMILY)
if not seen_enum:
    BAD("6 no NOT_/NO_ verdict enumerator found anywhere in %s — the scan matched nothing, "
        "so nothing was asserted" % LIGHT_DIR)
elif unknown_enum:
    BAD("6 %d NOT_/NO_ verdict enumerator(s) are neither in the F-2 family nor in the "
        "recorded out-of-family set: %s — adjudicate whether each owes an F-2 footing "
        "(NegativeVerdictSoundness.md F-2) and record the answer, do not inherit it"
        % (len(unknown_enum), ", ".join(unknown_enum)))
else:
    OK("6 the negative-verdict enumerator set has not grown: %d in the F-2 family, %d "
       "recorded out of family and unchanged — a new one is RED, not silently inherited"
       % (len(NEG_ENUM), len(OUT_OF_FAMILY)))

print('\n'.join(out))
PYSCAN
)
  rc=$?
  while IFS= read -r line; do
    case "$line" in
      "OK "*)  ok  "${line#OK }" ;;
      "BAD "*) no  "${line#BAD }" ;;
      "")      ;;
      *)       echo "    $line" >&2 ;;
    esac
  done <<< "$out"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    no "scanner exited $rc — the contract could not complete its analysis of $dir"
  fi
}

# ── SELFTEST mode (SELFTEST=1) ─────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: F-2 negative-footing contract liveness (inject -> expect RED/GREEN) ==="
  if [ ! -f "$LIGHT_DIR/main.cpp" ]; then
    echo "  FAIL: $LIGHT_DIR/main.cpp absent — cannot run SELFTEST"; exit 1
  fi
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/f2foot.$$")
  mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT
  mk() { rm -rf "$tmproot/$1"; cp -r "$LIGHT_DIR" "$tmproot/$1"; echo "$tmproot/$1"; }

  st_run() {  # $1 dir -> prints "<pass> <fail>"
    local before_p="$pass" before_f="$fail" dp df
    run_contract "$1" >/dev/null 2>&1
    dp=$((pass - before_p)); df=$((fail - before_f))
    pass="$before_p"; fail="$before_f"     # selftest must not pollute the real counters
    echo "$dp $df"
  }
  # Wave-doctrine lesson 5: a harness must REFUSE a verdict when the mutation never
  # reached the source. Every injected case must differ from the clean copy.
  st_reached() {
    if diff -rq "$clean" "$1" >/dev/null 2>&1; then
      echo "  bad: $2 -> MUTATION DID NOT REACH THE SOURCE (scratch tree identical to clean); refusing to report a verdict" >&2
      ST_FAIL=$((ST_FAIL + 1)); return 1
    fi
    return 0
  }
  st_expect_red() {
    st_reached "$2" "$1" || return 0
    local r; r=$(st_run "$2")
    if [ "${r#* }" -ge 1 ]; then echo "  ok:  $1 -> RED (${r#* } failure(s))"
    else echo "  bad: $1 -> NOT flagged (the contract is not live for this)" >&2; ST_FAIL=$((ST_FAIL+1)); fi
  }
  st_expect_green() {
    if [ "${3:-mutated}" = "mutated" ]; then st_reached "$2" "$1" || return 0; fi
    local r; r=$(st_run "$2")
    if [ "${r#* }" = "0" ] && [ "${r%% *}" -ge 1 ]; then echo "  ok:  $1 -> GREEN (${r%% *} assertion(s), 0 failures) — the contract does not rot on this"
    else echo "  bad: $1 -> ${r%% *} pass / ${r#* } fail, expected all-green" >&2; ST_FAIL=$((ST_FAIL+1)); fi
  }

  clean=$(mk clean); st_expect_green "clean-copy sanity" "$clean" identical

  # G1 — THE ANTI-ROT CASE, and the reason this repair exists: a NEW command lands with a
  #      correctly gated, correctly classed daemon_asserted footing. The old census pins
  #      went RED on exactly this (that is how nk:/en: broke them). It must stay GREEN.
  g1=$(mk g1)
  cat >> "$g1/main.cpp" <<'CPPEOF'
int cmd_verify_synthetic_ok(int argc, char** argv) {
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    auto proof = rpc.call("state_proof", {{"namespace", "zz"}, {"key", domain}});
    if (proof.contains("error") && !proof["error"].is_null()) {
        std::string err = proof["error"].dump();
        if (err == "not_found") {
            verdict = InclusionVerdict::NOT_INCLUDED;
        }
    }
    json out = {{"verdict", verdict_str(verdict)}};
    if (verdict == InclusionVerdict::NOT_INCLUDED)
        out["negative_footing"] = "daemon_asserted";
    std::cout << out.dump() << "\n";
    return 0;
}
CPPEOF
  st_expect_green "G1 a NEW command lands with a correct daemon_asserted footing" "$g1"

  # N1 — the same new command FORGETS the field: completeness must catch it with no pin.
  n1=$(mk n1)
  cat >> "$n1/main.cpp" <<'CPPEOF'
int cmd_verify_synthetic_bad(int argc, char** argv) {
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    if (whatever) verdict = InclusionVerdict::NOT_INCLUDED;
    json out = {{"verdict", verdict_str(verdict)}};
    std::cout << out.dump() << "\n";
    return 0;
}
CPPEOF
  st_expect_red "N1 a new negative-verdict command with NO footing" "$n1"

  # N2 — an existing command's footing is dropped.
  n2=$(mk n2)
  perl -0pi -e 's/\n *out\["negative_footing"\] = "daemon_asserted";(?=\n *if \(included\) out\["note_pk"\])//' "$n2/main.cpp"
  st_expect_red "N2 verify-notekey drops its footing emission" "$n2"

  # N3 — an absence-derived negative is MISLABELLED cryptographic (the class check; the
  #      old gate-shape map also caught this one, the next two it could not).
  n3=$(mk n3)
  perl -0pi -e 's/(namespace_, "nk"[\s\S]{0,4000}?)out\["negative_footing"\] = "daemon_asserted";/$1out["negative_footing"] = "cryptographic";/' "$n3/main.cpp"
  perl -0pi -e 's/(\{"namespace", "nk"\}[\s\S]{0,6000}?)out\["negative_footing"\] = "daemon_asserted";/$1out["negative_footing"] = "cryptographic";/' "$n3/main.cpp"
  st_expect_red "N3 an absence-derived negative mislabelled cryptographic" "$n3"

  # N4 — PAIRED CROSS-SITE SWAP: tx-inclusion -> daemon_asserted and receipt-inclusion ->
  #      cryptographic. Every count is preserved; only a derived class catches it.
  n4=$(mk n4)
  perl -0pi -e 's/(r\.verdict == InclusionVerdict::NOT_INCLUDED\)\n\s*out\["negative_footing"\] = )"cryptographic"/$1"daemon_asserted"/' "$n4/main.cpp"
  perl -0pi -e 's/(\{"namespace", "i"\}[\s\S]{0,6000}?out\["negative_footing"\] = )"daemon_asserted"/$1"cryptographic"/' "$n4/main.cpp"
  st_expect_red "N4 paired cross-site swap (all counts preserved)" "$n4"

  # N5 — the unstake two-arm value pin: the arms are swapped.
  n5=$(mk n5)
  perl -0pi -e 's/(NO_STAKE && have_stake\)\n\s*out\["negative_footing"\] = )"cryptographic"/$1"daemon_asserted"/' "$n5/main.cpp"
  perl -0pi -e 's/(NO_STAKE && !have_stake\)\n\s*out\["negative_footing"\] = )"daemon_asserted"/$1"cryptographic"/' "$n5/main.cpp"
  st_expect_red "N5 the unstake proven-zero / absence arms swapped" "$n5"

  # N6 — an emission is un-gated (emitted unconditionally, i.e. on positives too).
  n6=$(mk n6)
  perl -0pi -e 's/if \(verdict == AccountExistVerdict::NOT_CREATED\)\n(\s*)out\["negative_footing"\]/$1out["negative_footing"]/' "$n6/main.cpp"
  st_expect_red "N6 verify-account emits the footing unconditionally" "$n6"

  # N7 — the gate is spoofed by a COMMENT (comments are blanked, so it cannot satisfy).
  n7=$(mk n7)
  perl -0pi -e 's|if \(verdict == AccountExistVerdict::NOT_CREATED\)\n(\s*)out\["negative_footing"\]|// if (verdict == AccountExistVerdict::NOT_CREATED)\n$1out["negative_footing"]|' "$n7/main.cpp"
  st_expect_red "N7 the verdict gate replaced by a comment" "$n7"

  # N8 — F-5 negative leg: the over-broad "no verified" disjunct returns.
  n8=$(mk n8)
  perl -0pi -e 's/if \(msg\.find\("not_found"\) != std::string::npos\)/if (msg.find("not_found") != std::string::npos || msg.find("no verified") != std::string::npos)/' "$n8/main.cpp"
  st_expect_red "N8 F-5 regression: the no-verified disjunct returns" "$n8"

  # N9 — F-5 positive leg: the absence classifier is short-circuited to if(true).
  n9=$(mk n9)
  perl -0pi -e 's/if \(msg\.find\("not_found"\) != std::string::npos\) \{/if (true) {/' "$n9/main.cpp"
  st_expect_red "N9 F-5 regression: the absence matcher short-circuited to if(true)" "$n9"

  # N10 — the b: initializer-list emission is moved off its NOT-RECORDED object.
  n10=$(mk n10)
  perl -0pi -e 's/\{"verdict",          "NOT-RECORDED"\},/{"verdict",          "ABSENT"},/' "$n10/main.cpp"
  st_expect_red "N10 the init-list emission leaves its NOT-RECORDED object" "$n10"

  # N11 — the whole F-2 surface is deleted: non-vacuity and completeness must both fire.
  n11=$(mk n11)
  perl -0pi -e 's/^.*negative_footing.*\n//mg' "$n11/main.cpp"
  st_expect_red "N11 every negative_footing emission deleted" "$n11"

  # N12 — a NEW negative-verdict enumerator appears: section 6 must demand it be
  #       adjudicated rather than let it be inherited silently.
  n12=$(mk n12)
  perl -0pi -e 's/enum class SupplyVerdict \{ CONSERVED, VIOLATED, UNVERIFIABLE \};/enum class SupplyVerdict { CONSERVED, VIOLATED, NOT_SUPPLIED, UNVERIFIABLE };/' "$n12/main.cpp"
  st_expect_red "N12 a new NOT_ verdict enumerator appears unadjudicated" "$n12"

  # N13 — CLONE-ONE-DELETE-ONE, the shape the old MIN_CMDS cardinality floor could not
  #       see: a pinned command is renamed, so `need` loses one member and gains one and
  #       the COUNT is unchanged at 11. Completeness (1) stays satisfied — both sets move
  #       together — and only the membership ratchet fires. A real removal-plus-addition
  #       has the identical signature; this is the cheapest faithful way to inject it.
  n13=$(mk n13)
  perl -0pi -e 's/\bcmd_verify_notekey\b/cmd_verify_notekey_clone/g' "$n13/main.cpp"
  st_expect_red "N13 clone-one-delete-one: a pinned command substituted, count unchanged" "$n13"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_negative_footing SELFTEST (13 regressions RED, 2 legitimate changes GREEN)"
    exit 0
  else
    echo "  FAIL: test_light_negative_footing SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── Production path ────────────────────────────────────────────────────────────
if [ ! -f "$LIGHT_DIR/main.cpp" ]; then
    # FAIL CLOSED (2026-09-18) — see tools/test_light_keybind_surface.sh.
    # $LIGHT_DIR/main.cpp is tracked; its absence is a broken checkout, not an
    # environment this contract declines on.
    echo "  FAIL: test_light_negative_footing — $LIGHT_DIR/main.cpp is absent; a source contract with no source cannot report green"
    exit 1
fi

echo "=== F-2 negative_footing source contract ($LIGHT_DIR/main.cpp) ==="
run_contract "$LIGHT_DIR"

echo
echo "=== live behavioral leg (drive each command to its negative, assert footing) ==="
skp "live negative_footing leg (needs a cluster: tx missing-tx + unstake locked==0 -> cryptographic; every state_proof not_found absence -> daemon_asserted) — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
echo "  not asserted here: the value a BUILT binary emits, and NV-1's full-set recompute"
echo "  itself — this contract establishes the absence/non-absence dichotomy that is the"
echo "  F-2 class boundary, and the proof document establishes the rest."
# The floor (wave-doctrine lesson 15): `fail == 0` is not a verdict. The live
# leg always declines here, so without this a file whose analysis stopped
# matching would report 0 pass / 0 fail / 1 skip and print PASS.
if [ "$pass" -eq 0 ]; then
    echo "  FAIL: test_light_negative_footing — every section declined; nothing was asserted"
    exit 1
elif [ "$fail" = "0" ]; then
    echo "  PASS: test_light_negative_footing (F-2 source contract; live leg is a CI leg)"
    exit 0
else
    echo "  FAIL: test_light_negative_footing"
    exit 1
fi
