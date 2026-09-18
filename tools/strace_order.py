#!/usr/bin/env python3
"""tools/strace_order.py — the ONE strace mode-ordering parser.

WHAT IT ANSWERS, over an strace of a real command:

    among the mode-setting calls that affect TARGET between its CREATING open
    and the FIRST write to that descriptor, does at least one EXIST and does
    the LAST one set 0600?

and, when RENAME_TO is given, additionally: was that inode never wider than
0600 between the first write and the rename that published it, and did that
rename actually happen?

USAGE
    strace_order.py TRACE TARGET [RENAME_TO]
        line 1  the verdict — "600" when the ordering holds, or the failure in
                words ("none", "no-create-open", "no-write", "no-rename",
                "last-before-write:<mode>", "widened-before-publish:<mode>").
        line 2  the SAME parse over the SAME trace with every pre-write
                mode-setting line for that target removed. It must say "none",
                or the window line 1 claims to inspect is not load-bearing and
                the caller's assertion is vacuous.
    strace_order.py --self-test
        Runs the parser over SYNTHETIC traces with known answers and prints one
        `ok <name>` / `BAD <name> got=<x> want=<y>` line each, then a terminal
        `self-test: <n> ok / <m> bad`. Needs no strace, no ptrace and no binary,
        so the parser itself is falsifiable on every platform — including the
        ones where the legs that USE it can only skip. Exit 0 iff m == 0.

WHY IT IS ONE FILE (2026-09-18). This parser existed in THREE copies:
`tools/test_wallet_out_perms.sh` section A (inline heredoc),
`tools/test_wallet_out_perms.sh` section C (a generated `ordered.py`) and
`tools/test_account_create_perms.sh` section B (`order_verdict`). A fourth,
structurally different one is in `tools/test_node_key_perms.sh` (twice) and is
NOT merged here — see the note at the bottom. Copies of a security parser drift,
and this one already had: a descriptor-only version scored
`create 0600; fchmod(fd,0600); chmod(path,0666); write; chmod(path,0600)` as
CLOSED with the window fully open, and every final-mode assertion in the tree
passes on that trace. `--self-test` case `path_widen_before_write` is that exact
trace and it is the reason the PATH spellings below are not optional.

WHAT IT DELIBERATELY DOES NOT DO
  * It does NOT read the mode argument of the `openat`. Measured 2026-09-17:
    strace prints `openat(..., O_CREAT|O_TRUNC, 0600) = 3` whether or not the
    kernel used that mode, so a trace grep for 0600 passes on a file that stayed
    0644. The create mode applies only when the file is CREATED; the callers
    therefore run against PRE-EXISTING 0644 targets and this parser judges the
    mode-setting CALLS, not the open's argument.
  * It does NOT assert "no write precedes the openat": a write to fd N cannot
    precede the openat that returned N. That is a tautology, not a check.
  * It says nothing about the FINAL mode of the file. That is the callers'
    separate `stat` assertion, and it is the one a create-then-narrow mutant
    still passes.
"""
import re
import sys


def compile_for(target, rename_to=None):
    """The four regexes, bound to one target path."""
    q = re.escape(target)
    return {
        # The CREATING open of the target: O_CREAT, a mode argument, and a
        # RETURNED fd. The path also appears in non-creating opens (a fsync
        # re-open, a read-back), and a failed open returns -1 and creates
        # nothing, so neither may be taken for the create.
        "OPEN": re.compile(
            r'\bopenat?\((?:AT_FDCWD, )?"%s", ([^,)]*O_CREAT[^,)]*), 0[0-7]+\)\s*=\s*([0-9]+)\b' % q),
        # Mode-setting calls that affect that file: on the DESCRIPTOR, or on
        # the PATH. BOTH, always — see the drift note in the docstring.
        # fchmodat2 (glibc >= 2.39 / Linux >= 6.6) is in the alternation
        # because a new enough libc routes chmod()/fchmodat() through it.
        "FCHMOD": re.compile(r'\bfchmod\((\d+), 0?([0-7]+)\)'),
        "PCHMOD": re.compile(
            r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"%s", 0?([0-7]+)' % q),
        "RENAME": re.compile(
            r'\brenameat2?\(.*?"%s".*?"%s"|\brename\("%s", "%s"\)'
            % (q, re.escape(rename_to or ""), q, re.escape(rename_to or ""))),
    }


def _modes_between(rx, lines, lo, hi, fd):
    out = []
    for i in range(lo + 1, hi):
        m = rx["FCHMOD"].search(lines[i])
        if m and m.group(1) == fd:
            out.append(m.group(2).lstrip("0") or "0")
            continue
        m = rx["PCHMOD"].search(lines[i])
        if m:
            out.append(m.group(1).lstrip("0") or "0")
    return out


def verdict(lines, target, rename_to=None, rx=None):
    rx = rx or compile_for(target, rename_to)
    op = next(((i, m) for i, l in enumerate(lines) for m in [rx["OPEN"].search(l)] if m), None)
    if op is None:
        return "no-create-open"
    i_open, fd = op[0], op[1].group(2)
    W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(lines) if i > i_open and W.search(l)), None)
    if i_write is None:
        return "no-write"
    before = _modes_between(rx, lines, i_open, i_write, fd)
    if not before:
        return "none"          # nothing narrowed the file before the secret went in
    if before[-1] != "600":
        return "last-before-write:" + before[-1]
    if rename_to is not None:
        i_ren = next((i for i, l in enumerate(lines) if i > i_write and rx["RENAME"].search(l)), None)
        if i_ren is None:
            return "no-rename"
        after = [m for m in _modes_between(rx, lines, i_write, i_ren, fd) if m != "600"]
        if after:
            return "widened-before-publish:" + after[-1]
    return "600"


def stripped_verdict(lines, target, rename_to=None, rx=None):
    """The non-vacuity self-check: the SAME parse over the SAME trace with every
    pre-write mode-setting line for that target removed — BOTH spellings. It
    must answer "none". A parse that had stopped looking inside that window, or
    one blind to the path spelling, would still answer 600 and the caller's
    self-check assertion goes RED."""
    rx = rx or compile_for(target, rename_to)
    op = next(((i, m) for i, l in enumerate(lines) for m in [rx["OPEN"].search(l)] if m), None)
    if op is None:
        return "no-create-open"
    i_open, fd = op[0], op[1].group(2)
    W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(lines) if i > i_open and W.search(l)), None)
    keep = [l for i, l in enumerate(lines)
            if not (i_open < i < (i_write if i_write is not None else 0)
                    and (rx["FCHMOD"].search(l) or rx["PCHMOD"].search(l)))]
    return verdict(keep, target, rename_to, rx)


# ── synthetic traces with known answers ──────────────────────────────────────
# Every case is a real strace SHAPE, written out by hand so the parser can be
# falsified with no strace, no ptrace, no C compiler and no determ binary.
T = "/tmp/k.bin"
R = "/tmp/k.final"


def _tr(*lines):
    return list(lines)


_OPEN600 = 'openat(AT_FDCWD, "%s", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW, 0600) = 3' % T
_OPEN666 = 'openat(AT_FDCWD, "%s", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3' % T
_WRITE = 'write(3, "DAK1\\0\\0\\0", 68)      = 68'
_FCH600 = 'fchmod(3, 0600)                   = 0'
_PCH666 = 'chmod("%s", 0666)                 = 0' % T
_PCH600 = 'fchmodat(AT_FDCWD, "%s", 0600)    = 0' % T
_CLOSE = 'close(3)                          = 0'
_RENAME = 'rename("%s", "%s")                = 0' % (T, R)

SELF_TESTS = [
    # NOTE FOR WHOEVER ADDS A CASE: the terminal `self-test: N ok / 0 bad` line
    # is PINNED by tools/test_wallet_out_perms.sh section E. Adding or removing
    # a case moves N and turns that gate RED until the pinned string is moved
    # with it. That coupling is deliberate — a self-test whose size nothing
    # watches can shrink to nothing quietly — so update both in one change.
    # name, trace, rename_to, want_verdict, want_stripped
    ("narrowed_by_fd",
     _tr(_OPEN600, _FCH600, _WRITE, _CLOSE), None, "600", "none"),
    ("narrowed_by_path",
     _tr(_OPEN600, _PCH600, _WRITE, _CLOSE), None, "600", "none"),
    # THE DEFECT S-109 recorded: created wide, filled, narrowed afterwards.
    ("create_then_narrow",
     _tr(_OPEN666, _WRITE, _PCH600, _CLOSE), None, "none", "none"),
    # THE DRIFT a descriptor-only parser scores as "closed": the window is
    # re-opened BY PATH between the narrowing and the first write, and the file
    # still ends at 0600 so every final-mode assertion in the tree passes.
    ("path_widen_before_write",
     _tr(_OPEN600, _FCH600, _PCH666, _WRITE, _PCH600, _CLOSE), None,
     "last-before-write:666", "none"),
    # A non-creating open of the same path must not be taken for the create.
    ("noncreating_open_first",
     _tr('openat(AT_FDCWD, "%s", O_RDONLY)  = 7' % T, _OPEN600, _FCH600, _WRITE),
     None, "600", "none"),
    # A FAILED open creates nothing and returns -1; it must not be taken either.
    ("failed_open_first",
     _tr('openat(AT_FDCWD, "%s", O_WRONLY|O_CREAT|O_TRUNC, 0600) = -1 EACCES (Permission denied)' % T,
         _OPEN600, _FCH600, _WRITE),
     None, "600", "none"),
    # fchmod on a DIFFERENT descriptor is not this file's narrowing.
    ("other_fd_fchmod",
     _tr(_OPEN600, 'fchmod(9, 0600)                   = 0', _WRITE), None,
     "none", "none"),
    ("no_write_at_all",
     _tr(_OPEN600, _FCH600, _CLOSE), None, "no-write", "no-write"),
    ("no_create_open",
     _tr(_WRITE, _CLOSE), None, "no-create-open", "no-create-open"),
    # write-then-rename: the inode the rename publishes IS the one written.
    ("rename_ok",
     _tr(_OPEN600, _FCH600, _WRITE, _CLOSE, _RENAME), R, "600", "none"),
    ("rename_widened_before_publish",
     _tr(_OPEN600, _FCH600, _WRITE, _PCH666, _CLOSE, _RENAME), R,
     "widened-before-publish:666", "none"),
    ("rename_missing",
     _tr(_OPEN600, _FCH600, _WRITE, _CLOSE), R, "no-rename", "none"),
]


def self_test():
    ok = bad = 0
    for name, tr, ren, want_v, want_s in SELF_TESTS:
        got_v = verdict(tr, T, ren)
        got_s = stripped_verdict(tr, T, ren)
        for label, got, want in (("verdict", got_v, want_v), ("stripped", got_s, want_s)):
            if got == want:
                print("  ok  %s/%s = %s" % (name, label, got))
                ok += 1
            else:
                print("  BAD %s/%s got=%s want=%s" % (name, label, got, want))
                bad += 1
    print("self-test: %d ok / %d bad" % (ok, bad))
    return 0 if bad == 0 else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) < 3:
        sys.stderr.write("usage: strace_order.py TRACE TARGET [RENAME_TO]\n"
                         "       strace_order.py --self-test\n")
        return 2
    lines = open(argv[1]).read().splitlines()
    target = argv[2]
    rename_to = argv[3] if len(argv) > 3 else None
    rx = compile_for(target, rename_to)
    print(verdict(lines, target, rename_to, rx))
    print(stripped_verdict(lines, target, rename_to, rx))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# NOT MERGED HERE, deliberately, and named so it is not silently dropped:
# tools/test_node_key_perms.sh carries its own ordering parser TWICE
# (its sections at :202 and :249). It is a different parser, not a fourth copy
# of this one: it scopes its window by the descriptor's CLOSE rather than by the
# first write, hardcodes the `node_key.json` suffix instead of taking a target,
# and answers "closed"/"open" rather than a mode. Rewriting it onto this
# interface changes what that gate asserts and belongs in its own increment; it
# already enumerates chmod / fchmod / fchmodat / fchmodat2, so it does not carry
# the drift this file exists to prevent.
