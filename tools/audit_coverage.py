#!/usr/bin/env python3
"""Coverage record of the local audit (C99-MINIX-PORT 14.1; summary in ADR-006 7).

Every tracked file must match a rule in tools/audit_coverage.tsv. REVIEWED and
PARTIAL rules name one exact path and the git blob that was reviewed, and take
precedence; otherwise the first matching pattern wins, and `*` also matches `/`.
A reviewed file whose working-tree content no longer hashes to its pinned blob
is STALE: the guard fails until the change is reviewed and the row re-pinned, or
the row is downgraded to PENDING. A changed file is never counted as reviewed.

  --check (default)  exit 1 on a file without a row, a malformed or duplicated
                     rule, a literal row naming an untracked path, or a stale
                     reviewed file; print a summary
  --list             one line per tracked file: path, surface, status, scope

Uses only the Python standard library and git.
"""
import fnmatch
import os
import subprocess
import sys
from collections import Counter

DISPOSITIONS = ("REVIEWED", "PARTIAL", "PENDING", "DATA", "EXCLUDED")
EXACT = ("REVIEWED", "PARTIAL")
HEX = set("0123456789abcdef")


def fail(message):
    print("  FAIL: test_audit_coverage (%s)" % message)
    return 1


def load_rules(path):
    rules, errors = [], []
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 5:
                errors.append("line %d: expected 5 tab-separated fields" % number)
                continue
            pattern, surface, disposition, blob, note = fields
            if disposition not in DISPOSITIONS:
                errors.append("line %d: unknown disposition %r" % (number, disposition))
            elif disposition in EXACT:
                if any(c in pattern for c in "*?["):
                    errors.append("line %d: %s rule must name one exact path" % (number, disposition))
                if len(blob) != 40 or not set(blob) <= HEX:
                    errors.append("line %d: %s rule needs the reviewed 40-hex blob" % (number, disposition))
            elif blob != "-":
                errors.append("line %d: only REVIEWED/PARTIAL rules carry a blob" % number)
            if not surface or not note.strip():
                errors.append("line %d: surface and scope/reason are required" % number)
            rules.append((number, pattern, surface, disposition, blob, note))
    return rules, errors


def git(root, *args, stdin=None):
    return subprocess.run(["git", "-C", root] + list(args), check=True, input=stdin,
                          capture_output=True).stdout.decode("utf-8")


def main(argv):
    mode = argv[1] if len(argv) > 1 else "--check"
    if mode not in ("--check", "--list"):
        print("usage: audit_coverage.py [--check|--list]")
        return 2
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        rules, errors = load_rules(os.path.join(root, "tools", "audit_coverage.tsv"))
        tracked = sorted(p for p in git(root, "ls-files", "-z").split("\0") if p)
        exact = {}
        for rule in rules:
            if rule[3] in EXACT:
                if rule[1] in exact:
                    errors.append("line %d: duplicate exact row for %s" % (rule[0], rule[1]))
                exact[rule[1]] = rule
        pinned = [p for p in tracked if p in exact]
        hashes = git(root, "hash-object", "--stdin-paths",
                     stdin="".join(p + "\n" for p in pinned).encode("utf-8")).split()
    except (OSError, subprocess.CalledProcessError) as error:
        return fail("cannot read the rules or the git checkout: %s" % error)
    current = dict(zip(pinned, hashes))
    for path in exact:
        if path not in current:
            errors.append("exact row names an untracked path: %s" % path)
    used, counts, stale, unmatched = set(), Counter(), [], []
    for path in tracked:
        rule = exact.get(path)
        if rule is None:
            rule = next((r for r in rules if r[3] not in EXACT and fnmatch.fnmatchcase(path, r[1])), None)
        if rule is None:
            unmatched.append(path)
            continue
        used.add(rule[0])
        number, pattern, surface, disposition, blob, note = rule
        status = disposition
        if disposition in EXACT and current.get(path) != blob:
            status = "STALE"
            stale.append(path)
        counts[status] += 1
        if mode == "--list":
            print("%s\t%s\t%s\t%s" % (path, surface, status, note))
    for rule in rules:  # glob rows may wait for future files; a literal path must exist
        if rule[0] not in used and rule[3] not in EXACT and not any(c in rule[1] for c in "*?["):
            errors.append("line %d: row names an untracked path: %s" % (rule[0], rule[1]))
    errors += ["no row for tracked file: %s" % p for p in unmatched]
    errors += ["reviewed file changed since its review (re-review and re-pin, or mark PENDING): %s" % p
               for p in stale]
    if mode == "--list":
        for error in errors:
            print("drift: " + error, file=sys.stderr)
        return 1 if errors else 0
    print("=== audit coverage record (tools/audit_coverage.tsv) ===")
    print("  tracked files: %d" % len(tracked))
    for status in ("REVIEWED", "PARTIAL", "STALE", "PENDING", "DATA", "EXCLUDED"):
        print("  %-9s %d" % (status + ":", counts.get(status, 0)))
    for error in errors:
        print("  drift: %s" % error)
    if errors:
        return fail("%d problem(s)" % len(errors))
    print("  PASS: test_audit_coverage (every tracked file has a disposition; no reviewed file is stale)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
