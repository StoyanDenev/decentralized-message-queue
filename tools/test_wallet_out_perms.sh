#!/usr/bin/env bash
# determ-wallet output-file permission gate (P-1 / P-2, S-109).
#
# WHAT IT GATES, AND WHY THIS SHAPE
# ---------------------------------
# `write_bytes_file_0600` (wallet/main.cpp) is the single helper through which
# ten wallet commands put key material on disk; `backup-create --shares-out`
# and `keyfile-decrypt --out` are routed through it too. Two properties:
#
#   P-1  the file is at 0600 BEFORE the first byte of the secret reaches it.
#        Until 2026-09-17 it was created by `std::ofstream` at 0666 & ~umask,
#        filled, and narrowed afterwards — the whole secret was world-readable
#        for the duration of the write, on every successful run.
#   P-2  a failed narrowing is REPORTED (stderr diagnostic + `perms_narrowed`
#        false in the --json summary). It used to be discarded with
#        `(void)perm_ec`: exit 0, empty stderr, world-readable key file.
#
# Both legs run against a **PRE-EXISTING 0644 target**, deliberately. Measured:
# `open(O_CREAT|O_TRUNC, 0600)` applies its mode ONLY when the file is created,
# so on an overwrite (the --force path, and any second run) a create-mode-only
# fix leaves the entire window open while a fresh-create test stays green. A
# gate that only tests a fresh create tests the wrong path.
#
# Leg (i) asserts, over an strace of a real command: among the mode-setting
# calls that affect the target between the creating open and the first write to
# that descriptor, at least one EXISTS and the LAST one sets 0600. Both clauses
# are load-bearing. It does NOT assert on the mode argument of the `openat`:
# measured, strace prints `openat(..., O_CREAT|O_TRUNC, 0600) = 3` on a file
# that stayed 0644, so that assertion gates the source text of the call rather
# than the property. It does not assert "no write precedes the openat" either —
# a write to fd N cannot precede the openat that returns N; that is a tautology.
# Path-based calls (chmod / fchmodat / fchmodat2 naming the target) count as
# well as descriptor-based ones, or a mutant that creates 0600, widens the PATH
# to 0666, writes, and narrows again would pass while leaving the window fully
# open — and it would also satisfy the final-mode assertion in
# tools/test_wallet_shamir_rotate.sh section 28.
#
# Leg (ii) runs a real command under an LD_PRELOAD shim that makes every
# chmod/fchmod/fchmodat return EPERM (standing in for a filesystem or platform
# where narrowing cannot happen: FAT/exFAT, some network and FUSE mounts, a path
# owned by another user) and asserts BOTH that the harm is real (the resulting
# mode is NOT 0600) and that the command now says so, on stderr and in --json.
#
# Section C adds the same two legs for the two sites S-109 named as follow-ups
# and this increment closes: `account-import-many`, which emits one PLAINTEXT
# DAK1 keyfile PER RECORD inside a loop, and `keyfile-rotate`, the one
# write-then-rename shape in the file. C asserts the ordering on a NON-FIRST
# record (a fix that restricts only the first file of the loop goes RED) and,
# for the rotate, on the STAGED TEMP — because the mode travels with the inode
# through rename(2), so the file published under the final name IS that inode.
# Sections B5/B6 add their reporting legs under the same fault-injection shim.
#
# All legs SKIP BY NAME where the capability is absent (no strace / no ptrace /
# an strace that rejects a name the leg needs / no LD_PRELOAD / no C compiler),
# and a SKIP does NOT increment the pass count — a branch that checked nothing
# must not score.
#
# WINDOWS is the separate case, and since 2026-09-18 it is handled at the
# WRAPPER level rather than leg by leg: there is no POSIX file mode there, so
# P-1 and P-2 are not statements that can be true or false and every section
# declines. The floor below then reported a product failure for a property that
# does not exist on that platform, which is how the windows-2022 CI job has been
# red since this gate landed. The wrapper now prints the terminal
# `PLATFORM-SKIP:` marker tools/run_all.sh counts in its own column — not a
# pass, not a failure — and says in its own output what is consequently NOT
# gated there. A MISSING TOOL on a POSIX box is emphatically not this case.
#
# Run from repo root: bash tools/test_wallet_out_perms.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    # Fail closed. A gate that reports PASS having asserted nothing is the exact
    # defect the two increments before this one existed to remove; it is not
    # acceptable in the gate that removes it. The sibling gates fail closed here
    # too (test_node_key_perms via common.sh, test_light_seed_source by marker).
    echo "  FAIL: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 1
fi
WALLET="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
skip_count=0
assert() {  # $1 = true/false, $2 = description
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }

mode_of() {  # nine access bits of $1, or "unreadable"
  stat -c "%a" "$1" 2>/dev/null || stat -f "%Lp" "$1" 2>/dev/null || echo unreadable
}

UNAME_S=$(uname -s 2>/dev/null || echo unknown)

# ── The one platform where this gate's PROPERTY DOES NOT EXIST ────────────────
# Both properties this wrapper gates are statements about a POSIX file mode:
# P-1 is "the file is at 0600 before the first secret byte reaches it" and P-2
# is "a failed NARROWING is reported". Windows has no POSIX mode, so neither is
# a statement that can be true or false there — sections A, B, C and D would all
# decline and the `pass_count > 0` floor at the bottom would turn a run that
# asserted nothing into a FAIL against a wallet that is not broken. This is a
# FAST member and the CI matrix carries a windows-2022 job, so that failure has
# been live since the gate landed. The terminal marker below is the outcome
# tools/run_all.sh scores in its own column: not a pass, not a failure, named in
# the summary so the absence of coverage is on the record.
#
# THE BOUNDARY, and it is the whole point: this is a PURE `uname` TEST, placed
# AFTER the missing-binary check above so a broken build still fails closed. A
# Linux or macOS box that merely LACKS A TOOL — no strace, no ptrace permission,
# no C compiler — does NOT come here: the property exists there, section D
# asserts the outcome with nothing but `stat`, and the legs that cannot run
# print a named SKIP. "The property is absent" and "the tool is absent" are
# different facts; conflating them would make this marker a new way to go
# quietly green.
case "$UNAME_S" in
  MINGW*|MSYS*|CYGWIN*)
    echo "  NOT GATED HERE: sections A and C (strace ordering), B (LD_PRELOAD fault"
    echo "        injection) and D (the final mode of every output) all rest on a POSIX"
    echo "        file mode, which $UNAME_S does not have. What protects a wallet output"
    echo "        on that platform is the containing directory's NTFS ACL, and nothing in"
    echo "        this suite checks it — so P-1 and P-2 have NO coverage there."
    echo "  PLATFORM-SKIP: test_wallet_out_perms — POSIX file modes do not exist on $UNAME_S; the property this gate observes is absent, so nothing was asserted and no pass is banked"
    exit 0
    ;;
esac

# A share-set to rotate, and a pre-existing 0644 target to overwrite.
umask 022
"$WALLET" shamir-split --secret aabbccddeeff00112233445566778899 \
    --threshold 2 --shares 3 --out "$TMP/src.json" >/dev/null 2>&1 \
    || { echo "  FAIL: fixture shamir-split failed"; echo "  FAIL: test_wallet_out_perms"; exit 1; }

# Inputs for the two follow-up sites, built ONCE at top level because section C
# (strace) and section B (fault injection) each need them and each can skip
# independently. A failed fixture is a hard RED, never a silent skip.
"$WALLET" account-create-batch --count 3 --json > "$TMP/aim_batch.json" 2>/dev/null \
    || { echo "  FAIL: fixture account-create-batch failed"; echo "  FAIL: test_wallet_out_perms"; exit 1; }
$PY - "$TMP/aim_batch.json" "$TMP/aim_in.json" <<'EOF'
import json, sys
src = json.load(open(sys.argv[1]))
# Names make the per-record filenames predictable: rec1 / rec2 / rec3.keyfile.
recs = [{'address': a['address'], 'privkey_hex': a['privkey_hex'], 'name': 'rec%d' % (i + 1)}
        for i, a in enumerate(src['accounts'])]
json.dump(recs, open(sys.argv[2], 'w'), indent=2)
EOF
[ -s "$TMP/aim_in.json" ] \
    || { echo "  FAIL: fixture account-import-many input not built"; echo "  FAIL: test_wallet_out_perms"; exit 1; }
echo "rotate-old-passphrase" > "$TMP/rot_old.txt"
echo "rotate-new-passphrase" > "$TMP/rot_new.txt"
"$WALLET" keyfile-create --priv 2222222222222222222222222222222222222222222222222222222222222222 \
    --passphrase-from "file:$TMP/rot_old.txt" --out "$TMP/rot_in.dnk1" --force >/dev/null 2>&1 \
    || { echo "  FAIL: fixture keyfile-create failed"; echo "  FAIL: test_wallet_out_perms"; exit 1; }

echo "=== A. ordering: the file is 0600 before the secret is written (Linux strace) ==="
# fchmodat2 (glibc >= 2.39 / Linux >= 6.6) is in the set because a new enough
# libc routes chmod()/fchmodat() through it; without it the leg would be blind
# to the very call it exists to observe. Probe the SET as well as the binary —
# an strace that does not know a name exits 1 WITHOUT creating its -o file, so
# assuming the set turns a box that should run the leg into a hard RED. Same
# pattern as tools/test_light_outbox.sh section C.
TRACE_SET=openat,open,write,chmod,fchmod,fchmodat,fchmodat2
DEGRADED=0
SKIP_A=""
if ! command -v strace >/dev/null 2>&1; then SKIP_A="strace is not installed"
elif [ "$UNAME_S" != "Linux" ]; then SKIP_A="this is not Linux and strace is Linux-only"
elif ! strace -o /dev/null true >/dev/null 2>&1; then SKIP_A="ptrace is not permitted here"
elif ! strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1; then
  TRACE_SET=openat,open,write,chmod,fchmod,fchmodat
  DEGRADED=1
  strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1 \
    || SKIP_A="this strace rejects a syscall name the leg needs"
fi
TGT="$TMP/pre0644.json"
: > "$TGT"; chmod 644 "$TGT" 2>/dev/null
# Fixture precondition, not an assertion: a filesystem that does not honour file
# modes at all cannot host this leg, and a hard RED there would be a statement
# about the mount, not about the code.
[ -z "$SKIP_A" ] && [ "$(mode_of "$TGT")" != "644" ] \
  && SKIP_A="this filesystem does not honour file modes (the target could not be put at 0644)"
if [ -n "$SKIP_A" ]; then
  skip "section A ($SKIP_A); the syscall-ordering leg runs on Linux only"
else
  echo "  fixture: the target exists at 0644 before the run — the overwrite path, where a create-mode-only fix does nothing"
  TR="$TMP/strace.txt"
  strace -f -e trace="$TRACE_SET" -o "$TR" \
      "$WALLET" shamir-split --secret aabbccddeeff00112233445566778899 \
      --threshold 2 --shares 3 --out "$TGT" --force >/dev/null 2>&1
  if [ ! -s "$TR" ]; then
    assert false "strace produced no trace for the write (the ordering cannot be judged)"
  else
    VERDICT=$($PY - "$TR" "$TGT" <<'EOF'
import re, sys
trace, target = open(sys.argv[1]).read().splitlines(), sys.argv[2]
q = re.escape(target)
# The CREATING open of the target: O_CREAT, a mode argument, and a returned fd.
# The path also appears in non-creating opens, and a failed open returns -1 and
# creates nothing, so neither may be taken for the create.
OPEN = re.compile(r'\bopenat?\((?:AT_FDCWD, )?"%s", ([^,)]*O_CREAT[^,)]*), 0[0-7]+\)\s*=\s*([0-9]+)\b' % q)
# Mode-setting calls that affect that file: on the descriptor, or on the path.
FCHMOD  = re.compile(r'\bfchmod\((\d+), 0?([0-7]+)\)')
PCHMOD  = re.compile(r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"%s", 0?([0-7]+)' % q)
def run(lines):
    op = next(((i, m) for i, l in enumerate(lines) for m in [OPEN.search(l)] if m), None)
    if op is None:
        return "no-create-open"
    i_open, fd = op[0], op[1].group(2)
    WRITE = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(lines) if i > i_open and WRITE.search(l)), None)
    if i_write is None:
        return "no-write"
    modes = []
    for i in range(i_open + 1, i_write):
        m = FCHMOD.search(lines[i])
        if m and m.group(1) == fd:
            modes.append(m.group(2)); continue
        m = PCHMOD.search(lines[i])
        if m:
            modes.append(m.group(1))
    if not modes:
        return "none"            # nothing narrowed the file before the secret went in
    return modes[-1].lstrip("0") or "0"
print(run(trace))
# Parser self-check: the SAME parse over a trace with every pre-write
# mode-setting line removed must answer "none". A parse that stopped looking
# at the pre-write window would answer 600 here and this line goes RED.
op = next(((i, m) for i, l in enumerate(trace) for m in [OPEN.search(l)] if m), None)
if op is None:
    print("no-create-open")
else:
    i_open, fd = op[0], op[1].group(2)
    W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(trace) if i > i_open and W.search(l)), None)
    stripped = [l for i, l in enumerate(trace)
                if not (i_open < i < (i_write if i_write is not None else 0)
                        and (FCHMOD.search(l) or PCHMOD.search(l)))]
    print(run(stripped))
EOF
)
    GOT=$(echo "$VERDICT" | sed -n 1p)
    SELF=$(echo "$VERDICT" | sed -n 2p)
    [ "$DEGRADED" = "1" ] && echo "  note: this strace does not know fchmodat2; it was dropped from the trace set"
    assert_eq "$GOT" "600" "strace: a mode-setting call sits between the creating open and the first write, and the last one sets 0600 (target pre-existed at 0644)"
    assert_eq "$SELF" "none" "strace: removing the pre-write mode-setting lines turns the same parse RED (that window is load-bearing, not a tautology)"
    assert_eq "$(mode_of "$TGT")" "600" "the overwritten file ends at 0600 as well"
  fi
fi

echo
echo "=== C. ordering at the two follow-up sites S-109 named: account-import-many (per record) and keyfile-rotate (the staged temp) ==="
# Same capability gate as section A, same strace, same reasons to skip.
#
# Both legs run against PRE-EXISTING 0644 targets for the same measured reason
# section A does. For account-import-many that is decisive: records 2 and 3 have
# their keyfile already on disk at 0644, so the create mode of the open cannot
# narrow them and only a call ON THE DESCRIPTOR before the first write can. A fix
# that set the create mode alone, or that restricted only the first file of the
# loop, leaves those two records fully exposed and a fresh-create test green.
#
# For keyfile-rotate the target of the ordering assertion is the STAGED TEMP,
# because the mode travels with the inode through rename(2): the file published
# under the final name IS that inode. The leg therefore asserts, over the trace:
#   (a) at least one mode-setting call on the temp sits between its creating open
#       and the first write to that descriptor — the window the defect left open;
#   (b) the LAST of them sets 0600 — it was narrowed, not widened;
#   (c) nothing between that first write and the rename sets anything but 0600 —
#       so the inode was never wider than 0600 while it held the ciphertext;
#   (d) the rename to the final name actually happened — otherwise (a)-(c) would
#       be a statement about a file nobody published.
# Path-based spellings (chmod / fchmodat / fchmodat2 naming the file) count
# alongside the descriptor-based fchmod, or a mutant that creates 0600, widens
# the PATH to 0666, writes, and narrows again passes with the window wide open.
if [ -n "$SKIP_A" ]; then
  skip "section C ($SKIP_A); the syscall-ordering legs run on Linux only"
else
  cat > "$TMP/ordered.py" <<'PYEOF'
# ordered.py TRACE TARGET [RENAME_TO]
# line 1: the verdict — "600" when the ordering holds, or the failure in words.
# line 2: the SAME parse over a trace with every pre-write mode-setting line for
#         that target removed; it must say "none", or the window the leg claims
#         to inspect is not load-bearing and the leg is vacuous.
import re, sys

trace = open(sys.argv[1]).read().splitlines()
target = sys.argv[2]
rename_to = sys.argv[3] if len(sys.argv) > 3 else None
q = re.escape(target)

# The CREATING open of the target: O_CREAT, a mode argument, and a returned fd.
# The path also appears in non-creating opens (the fsync re-open), and a failed
# open returns -1 and creates nothing, so neither may be taken for the create.
OPEN = re.compile(r'\bopenat?\((?:AT_FDCWD, )?"%s", ([^,)]*O_CREAT[^,)]*), 0[0-7]+\)\s*=\s*([0-9]+)\b' % q)
FCHMOD = re.compile(r'\bfchmod\((\d+), 0?([0-7]+)\)')
PCHMOD = re.compile(r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"%s", 0?([0-7]+)' % q)
RENAME = re.compile(r'\brenameat2?\(.*?"%s".*?"%s"|\brename\("%s", "%s"\)'
                    % (q, re.escape(rename_to or ""), q, re.escape(rename_to or "")))

def modes_between(lines, lo, hi, fd):
    out = []
    for i in range(lo + 1, hi):
        m = FCHMOD.search(lines[i])
        if m and m.group(1) == fd:
            out.append(m.group(2).lstrip("0") or "0"); continue
        m = PCHMOD.search(lines[i])
        if m:
            out.append(m.group(1).lstrip("0") or "0")
    return out

def run(lines):
    op = next(((i, m) for i, l in enumerate(lines) for m in [OPEN.search(l)] if m), None)
    if op is None:
        return "no-create-open"
    i_open, fd = op[0], op[1].group(2)
    W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(lines) if i > i_open and W.search(l)), None)
    if i_write is None:
        return "no-write"
    before = modes_between(lines, i_open, i_write, fd)
    if not before:
        return "none"          # nothing narrowed the file before the secret went in
    if before[-1] != "600":
        return "last-before-write:" + before[-1]
    if rename_to is not None:
        i_ren = next((i for i, l in enumerate(lines) if i > i_write and RENAME.search(l)), None)
        if i_ren is None:
            return "no-rename"
        after = [m for m in modes_between(lines, i_write, i_ren, fd) if m != "600"]
        if after:
            return "widened-before-publish:" + after[-1]
    return "600"

print(run(trace))

# Parser self-check: strip every pre-write mode-setting line for this target —
# BOTH spellings — and the same parse must answer "none". A parse that had
# stopped looking at that window would still answer 600 and this line goes RED.
op = next(((i, m) for i, l in enumerate(trace) for m in [OPEN.search(l)] if m), None)
if op is None:
    print("no-create-open")
else:
    i_open, fd = op[0], op[1].group(2)
    W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
    i_write = next((i for i, l in enumerate(trace) if i > i_open and W.search(l)), None)
    stripped = [l for i, l in enumerate(trace)
                if not (i_open < i < (i_write if i_write is not None else 0)
                        and (FCHMOD.search(l) or PCHMOD.search(l)))]
    print(run(stripped))
PYEOF

  # ── C1. account-import-many — one plaintext DAK1 keyfile per record ──────
  AIMD="$TMP/aim_out"
  mkdir -p "$AIMD"
  for r in rec2 rec3; do : > "$AIMD/$r.keyfile"; chmod 644 "$AIMD/$r.keyfile" 2>/dev/null; done
  echo "  fixture: rec2.keyfile and rec3.keyfile exist at 0644 before the run — non-first records, on the overwrite path"
  TRA="$TMP/strace_aim.txt"
  strace -f -e trace="$TRACE_SET" -o "$TRA" \
      "$WALLET" account-import-many --in "$TMP/aim_in.json" --out-dir "$AIMD" \
      --summary "$TMP/aim_sum.json" --force >/dev/null 2>&1
  if [ ! -s "$TRA" ]; then
    assert false "strace produced no trace for account-import-many (the ordering cannot be judged)"
  else
    for r in rec2 rec3; do
      V=$($PY "$TMP/ordered.py" "$TRA" "$AIMD/$r.keyfile")
      assert_eq "$(echo "$V" | sed -n 1p)" "600" \
        "account-import-many/$r (a NON-first record, target pre-existed at 0644): a mode-setting call sits between the creating open and the first write, and the last one sets 0600"
      assert_eq "$(echo "$V" | sed -n 2p)" "none" \
        "account-import-many/$r: removing the pre-write mode-setting lines turns the same parse RED (the window is load-bearing)"
      assert_eq "$(mode_of "$AIMD/$r.keyfile")" "600" "account-import-many/$r ends at 0600 as well"
    done
  fi

  # ── C2. keyfile-rotate — the staged temp, whose inode the rename publishes ─
  ROTT="$TMP/rot_target.dnk1"
  : > "$ROTT"; chmod 644 "$ROTT" 2>/dev/null
  echo "  fixture: the rename target exists at 0644 before the run"
  # Probe the EXTENDED set the same way section A probes its own: an strace that
  # does not know one of these names exits 1 and creates no -o file, and reading
  # that as "no trace" would be a hard RED about the strace rather than the code.
  TRACE_SET_R="$TRACE_SET,rename,renameat,renameat2"
  for cand in "$TRACE_SET,rename,renameat,renameat2" "$TRACE_SET,rename,renameat" "$TRACE_SET,rename"; do
    if strace -e trace="$cand" -o /dev/null true >/dev/null 2>&1; then TRACE_SET_R="$cand"; break; fi
  done
  TRR="$TMP/strace_rot.txt"
  strace -f -e trace="$TRACE_SET_R" -o "$TRR" \
      "$WALLET" keyfile-rotate --in "$TMP/rot_in.dnk1" --out "$ROTT" \
      --old-passphrase-from "file:$TMP/rot_old.txt" \
      --new-passphrase-from "file:$TMP/rot_new.txt" --force >/dev/null 2>&1
  if [ ! -s "$TRR" ]; then
    assert false "strace produced no trace for keyfile-rotate (the ordering cannot be judged)"
  else
    V=$($PY "$TMP/ordered.py" "$TRR" "${ROTT}_tmp.bin" "$ROTT")
    assert_eq "$(echo "$V" | sed -n 1p)" "600" \
      "keyfile-rotate: the inode the rename publishes was never wider than 0600 while it held the ciphertext (narrowed before the first write, not widened before the publish, and the rename happened)"
    assert_eq "$(echo "$V" | sed -n 2p)" "none" \
      "keyfile-rotate: removing the pre-write mode-setting lines turns the same parse RED (the window is load-bearing)"
    assert_eq "$(mode_of "$ROTT")" "600" "the rotated keyfile ends at 0600 as well"
    # The staging temp must not be left behind: a 0600 leftover is still a copy
    # of the ciphertext under a predictable name.
    assert_eq "$([ -e "${ROTT}_tmp.bin" ] && echo present || echo absent)" "absent" \
      "the staging temp is gone after the publish (the rename consumed it)"
  fi
fi

echo
echo "=== B. a failed narrowing is real harm AND is reported (LD_PRELOAD fault injection) ==="
CC_BIN=""
for c in "${CC:-}" cc gcc clang; do
  [ -n "$c" ] && command -v "$c" >/dev/null 2>&1 && { CC_BIN="$c"; break; }
done
SKIP_B=""
SHIM="$TMP/nochmod.so"
if [ -z "$CC_BIN" ]; then SKIP_B="no C compiler (cc/gcc/clang) to build the fault-injection shim"
else
  cat > "$TMP/nochmod.c" <<'EOF'
/* Every attempt to narrow a file's mode fails with EPERM. Stands in for a
   filesystem or platform where the narrowing cannot happen. */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/stat.h>
int chmod(const char *p, mode_t m)                  { (void)p;(void)m; errno = EPERM; return -1; }
int fchmod(int fd, mode_t m)                        { (void)fd;(void)m; errno = EPERM; return -1; }
int fchmodat(int d, const char *p, mode_t m, int f) { (void)d;(void)p;(void)m;(void)f; errno = EPERM; return -1; }
EOF
  cat > "$TMP/probe.c" <<'EOF'
#include <sys/stat.h>
#include <stdio.h>
int main(int argc, char **argv) { (void)argc; return chmod(argv[1], 0600) == 0 ? 0 : 1; }
EOF
  if ! "$CC_BIN" -shared -fPIC -o "$SHIM" "$TMP/nochmod.c" >/dev/null 2>&1; then
    SKIP_B="the fault-injection shim does not build with $CC_BIN here"
  elif ! "$CC_BIN" -o "$TMP/probe" "$TMP/probe.c" >/dev/null 2>&1; then
    SKIP_B="the LD_PRELOAD capability probe does not build with $CC_BIN here"
  else
    # Independent capability probe, in TWO steps, because "the file stayed 644"
    # is also what a probe that never RAN produces — a noexec temp mount, or a
    # loader that refuses the shim, would otherwise be read as successful
    # interception and turn the whole leg into a false RED.
    : > "$TMP/probe.f"; chmod 644 "$TMP/probe.f" 2>/dev/null
    "$TMP/probe" "$TMP/probe.f" >/dev/null 2>&1
    if [ "$(mode_of "$TMP/probe.f")" != "600" ]; then
      SKIP_B="the capability probe cannot run or the filesystem does not honour file modes (noexec temp mount?)"
    else
      chmod 644 "$TMP/probe.f" 2>/dev/null
      LD_PRELOAD="$SHIM" "$TMP/probe" "$TMP/probe.f" >/dev/null 2>&1
      [ "$(mode_of "$TMP/probe.f")" = "644" ] \
        || SKIP_B="LD_PRELOAD does not intercept chmod here (SIP / static libc / unsupported platform)"
    fi
  fi
fi
if [ -n "$SKIP_B" ]; then
  skip "section B ($SKIP_B); the fault-injection leg needs LD_PRELOAD and a C compiler"
else
  # ── B1. shamir-rotate: a helper caller with a --json summary ────────────
  ROT="$TMP/rot_pre.json"; : > "$ROT"; chmod 644 "$ROT"
  LD_PRELOAD="$SHIM" "$WALLET" shamir-rotate --shares "$TMP/src.json" --threshold 2 \
      --shares-out "$ROT" --force --json >"$TMP/rot.out" 2>"$TMP/rot.err"
  RC=$?
  assert_eq "$RC" "0" "shamir-rotate still exits 0 (the file is written, not deleted, and no workflow breaks)"
  assert_eq "$(mode_of "$ROT")" "644" "the harm is REAL: with narrowing denied the shares file is left world-readable"
  # Three separate clauses, because they are killed by three different defects:
  # the PRE-WRITE narrowing failing silently, the FINAL (belt-and-braces)
  # narrowing failing silently — the `(void)perm_ec` this increment removes —
  # and the operator not being told what to do about it.
  grep -q "could not set 0600 permissions on .* before writing it: " "$TMP/rot.err" \
    && assert true "shamir-rotate reports the PRE-WRITE narrowing failure on stderr (file + reason)" \
    || assert false "shamir-rotate pre-write diagnostic: [$(tr '\n' ' ' < "$TMP/rot.err")]"
  grep "could not set 0600 permissions on" "$TMP/rot.err" | grep -qv "before writing it" \
    && assert true "shamir-rotate reports the FINAL narrowing failure on stderr (the discarded perm_ec)" \
    || assert false "shamir-rotate final-narrowing diagnostic: [$(tr '\n' ' ' < "$TMP/rot.err")]"
  grep -q "Verify manually" "$TMP/rot.err" \
    && assert true "shamir-rotate tells the operator to verify the mode by hand" \
    || assert false "shamir-rotate verify-manually line: [$(tr '\n' ' ' < "$TMP/rot.err")]"
  NARROWED=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/rot.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$NARROWED" "False" "shamir-rotate --json reports perms_narrowed=false"

  # ── B2. backup-create --shares-out: an independent site routed through the
  # helper by this increment. Gating it is what proves the routing landed.
  cat > "$TMP/kh.json" <<'EOF'
{"keyholders":[{"share_index":1,"passphrase":"kh-pw-1"},{"share_index":2,"passphrase":"kh-pw-2"},{"share_index":3,"passphrase":"kh-pw-3"}]}
EOF
  BSH="$TMP/bk_shares.json"; : > "$BSH"; chmod 644 "$BSH"
  BEN="$TMP/bk_envs.json"
  LD_PRELOAD="$SHIM" "$WALLET" backup-create --secret aabbccddeeff00112233445566778899 \
      --threshold 2 --keyholders "$TMP/kh.json" --shares-out "$BSH" \
      --envelopes-out "$BEN" --force --json >"$TMP/bk.out" 2>"$TMP/bk.err"
  assert_eq "$(mode_of "$BSH")" "644" "backup-create --shares-out: the harm is REAL with narrowing denied"
  grep -q "backup-create: Warning: could not set 0600 permissions on" "$TMP/bk.err" \
    && assert true "backup-create names the failure on stderr (the site is routed through the hardened helper)" \
    || assert false "backup-create stderr diagnostic: [$(tr '\n' ' ' < "$TMP/bk.err")]"
  BN=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/bk.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$BN" "False" "backup-create --json reports perms_narrowed=false"

  # ── B3. keyfile-decrypt --out: the other site routed through the helper.
  echo "keyfile-passphrase" > "$TMP/pw.txt"
  "$WALLET" keyfile-create --priv 1111111111111111111111111111111111111111111111111111111111111111 \
      --passphrase-from "file:$TMP/pw.txt" --out "$TMP/kf.dnk1" --force >/dev/null 2>&1
  DEC="$TMP/dec.json"; : > "$DEC"; chmod 644 "$DEC"
  LD_PRELOAD="$SHIM" "$WALLET" keyfile-decrypt --in "$TMP/kf.dnk1" \
      --passphrase-from "file:$TMP/pw.txt" --out "$DEC" --force --json \
      >"$TMP/dec.out" 2>"$TMP/dec.err"
  assert_eq "$(mode_of "$DEC")" "644" "keyfile-decrypt --out: the harm is REAL with narrowing denied"
  grep -q "keyfile-decrypt: Warning: could not set 0600 permissions on" "$TMP/dec.err" \
    && assert true "keyfile-decrypt names the failure on stderr (the site is routed through the hardened helper)" \
    || assert false "keyfile-decrypt stderr diagnostic: [$(tr '\n' ' ' < "$TMP/dec.err")]"
  DN=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/dec.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$DN" "False" "keyfile-decrypt --json reports perms_narrowed=false"

  # ── B4. the success path is UNCHANGED: no diagnostic, no field. Without this
  # a "always report failure" mutant would satisfy every assertion above.
  OKF="$TMP/rot_ok.json"
  "$WALLET" shamir-rotate --shares "$TMP/src.json" --threshold 2 \
      --shares-out "$OKF" --json >"$TMP/ok.out" 2>"$TMP/ok.err"
  assert_eq "$(mode_of "$OKF")" "600" "without the shim the rotated file is 0600"
  assert_eq "$([ -s "$TMP/ok.err" ] && echo nonempty || echo empty)" "empty" "a successful narrowing prints nothing on stderr"
  OKN=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/ok.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$OKN" "<absent>" "a successful summary carries no perms_narrowed field (the success JSON is byte-unchanged)"

  # ── B5. account-import-many — the per-record loop S-109 named as a follow-up.
  # rec2 and rec3 exist at 0644 before the run, so with every chmod denied the
  # create mode cannot save them: the harm is REAL on a NON-FIRST record, which
  # is exactly the half that a fix restricting only the first file of the loop
  # would leave open while a fresh-create test stayed green. rec1 is asserted
  # too, in the other direction — it is freshly created, so it reaches 0600 from
  # the open(2) mode even here, and the 644 above is a statement about the
  # overwrite path rather than about a broken create.
  AIMP="$TMP/aim_eperm"
  mkdir -p "$AIMP"
  for r in rec2 rec3; do : > "$AIMP/$r.keyfile"; chmod 644 "$AIMP/$r.keyfile" 2>/dev/null; done
  LD_PRELOAD="$SHIM" "$WALLET" account-import-many --in "$TMP/aim_in.json" \
      --out-dir "$AIMP" --summary "$TMP/aim_sum_eperm.json" --force \
      >"$TMP/aim.out" 2>"$TMP/aim.err"
  AIMRC=$?
  assert_eq "$AIMRC" "0" "account-import-many still exits 0 (one unprotectable mode must not invalidate 49,999 good records)"
  assert_eq "$(mode_of "$AIMP/rec2.keyfile")" "644" "account-import-many/rec2: the harm is REAL — with narrowing denied a NON-FIRST record's plaintext keyfile is left world-readable"
  assert_eq "$(mode_of "$AIMP/rec3.keyfile")" "644" "account-import-many/rec3: the harm is REAL on a second non-first record too"
  assert_eq "$(mode_of "$AIMP/rec1.keyfile")" "600" "account-import-many/rec1: a freshly created record still reaches 0600 from the open(2) mode, chmod denied"
  grep -qF "could not set 0600 permissions on $AIMP/rec2.keyfile before writing it" "$TMP/aim.err" \
    && assert true "account-import-many names the failure for a NON-FIRST record on stderr" \
    || assert false "account-import-many rec2 stderr diagnostic: [$(tr '\n' ' ' < "$TMP/aim.err")]"
  AIMN=$($PY - "$TMP/aim_sum_eperm.json" <<'EOF'
import json, sys
try:
    s = json.load(open(sys.argv[1]))
except Exception as e:
    print("<unparseable>"); raise SystemExit(0)
bad = [r for r in s if r.get("status") == "ok" and r.get("perms_narrowed") is not False]
print("all-false" if s and not bad else "missing:%d" % len(bad))
EOF
)
  assert_eq "$AIMN" "all-false" "every ok record in the --summary carries perms_narrowed=false (machine-readable, per record — the operator of a 50,000-account import is not reading 50,000 stderr lines)"
  # The success path is UNCHANGED: without the shim, the same pre-existing 0644
  # records end at 0600 and the summary carries no perms_narrowed field at all.
  # Without this an "always report failure" mutant satisfies everything above.
  AIMO="$TMP/aim_ok"
  mkdir -p "$AIMO"
  for r in rec2 rec3; do : > "$AIMO/$r.keyfile"; chmod 644 "$AIMO/$r.keyfile" 2>/dev/null; done
  "$WALLET" account-import-many --in "$TMP/aim_in.json" --out-dir "$AIMO" \
      --summary "$TMP/aim_sum_ok.json" --force >/dev/null 2>"$TMP/aim_ok.err"
  assert_eq "$(mode_of "$AIMO/rec2.keyfile")" "600" "without the shim a pre-existing 0644 record ends at 0600"
  AIMOK=$($PY - "$TMP/aim_sum_ok.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))
print("absent" if all("perms_narrowed" not in r for r in s) else "present")
EOF
)
  assert_eq "$AIMOK" "absent" "a successful --summary carries no perms_narrowed field (the success summary is byte-unchanged)"

  # ── B6. keyfile-rotate — the write-then-rename site. Note what is asserted
  # and what is NOT: with the staging temp CREATED at 0600 the published file
  # is 0600 here even though every chmod failed, because the open(2) mode is not
  # a chmod and the shim cannot touch it. That is the discriminator against the
  # defect — measured at HEAD this same command left the rotated keyfile at 644
  # with an empty stderr and exit 0. So the leg asserts the published mode AND
  # the two diagnostics, the second of which is the `(void)perm_ec` this
  # increment removes: it names the FINAL path, after the rename, not the temp.
  ROT2="$TMP/rot_eperm.dnk1"
  : > "$ROT2"; chmod 644 "$ROT2" 2>/dev/null
  LD_PRELOAD="$SHIM" "$WALLET" keyfile-rotate --in "$TMP/rot_in.dnk1" --out "$ROT2" \
      --old-passphrase-from "file:$TMP/rot_old.txt" \
      --new-passphrase-from "file:$TMP/rot_new.txt" --force --json \
      >"$TMP/kfrot.out" 2>"$TMP/kfrot.err"
  ROTRC=$?
  assert_eq "$ROTRC" "0" "keyfile-rotate still exits 0 (the rotated keyfile is published, not destroyed)"
  assert_eq "$(mode_of "$ROT2")" "600" "keyfile-rotate publishes a 0600 file even with every chmod denied — the staging temp was CREATED restricted (at HEAD this measured 644)"
  grep -qF "could not set 0600 permissions on ${ROT2}_tmp.bin before writing it" "$TMP/kfrot.err" \
    && assert true "keyfile-rotate reports the PRE-WRITE narrowing failure on the STAGING TEMP" \
    || assert false "keyfile-rotate staging diagnostic: [$(tr '\n' ' ' < "$TMP/kfrot.err")]"
  grep -qF "could not set 0600 permissions on ${ROT2}: " "$TMP/kfrot.err" \
    && assert true "keyfile-rotate reports the POST-RENAME narrowing failure on the FINAL path (the discarded perm_ec)" \
    || assert false "keyfile-rotate post-rename diagnostic: [$(tr '\n' ' ' < "$TMP/kfrot.err")]"
  RN=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/kfrot.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$RN" "False" "keyfile-rotate --json reports perms_narrowed=false"
  ROT3="$TMP/rot_ok.dnk1"
  : > "$ROT3"; chmod 644 "$ROT3" 2>/dev/null
  "$WALLET" keyfile-rotate --in "$TMP/rot_in.dnk1" --out "$ROT3" \
      --old-passphrase-from "file:$TMP/rot_old.txt" \
      --new-passphrase-from "file:$TMP/rot_new.txt" --force --json \
      >"$TMP/rot_ok.out" 2>"$TMP/rot_ok.err"
  assert_eq "$(mode_of "$ROT3")" "600" "without the shim the rotated keyfile is 0600"
  assert_eq "$([ -s "$TMP/rot_ok.err" ] && echo nonempty || echo empty)" "empty" "a successful rotation prints nothing on stderr"
  RON=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("perms_narrowed","<absent>"))' "$TMP/rot_ok.out" 2>/dev/null || echo "<unparseable>")
  assert_eq "$RON" "<absent>" "a successful rotation --json carries no perms_narrowed field"
fi

echo
echo "=== D. outcome: every key-material output ends at 0600 (POSIX, no strace or LD_PRELOAD needed) ==="
# Sections A-C need strace or LD_PRELOAD and therefore run on Linux only. That
# left this wrapper with NOTHING to assert on macOS and the BSDs — where the
# property it gates is perfectly real and `stat` can see it — so the whole gate
# declined every section and the pass_count floor (correctly) called that a
# failure. Observed on the owner's Darwin arm64 box, 2026-09-18, and it is the
# gate's defect, not the wallet's.
#
# WHAT THIS SECTION DOES AND DOES NOT GATE, so a green here is not misread:
# it asserts the OUTCOME — the mode every one of these outputs ends at — and
# NOT the window between the create and the first write (section A/C, strace)
# and NOT the reporting of a failed narrowing (section B, LD_PRELOAD). A mutant
# that restores the old create-then-narrow shape leaves the final mode 0600 and
# is GREEN here; that is exactly why sections A-C exist and why this one does
# not replace them. On a platform without strace this gate covers the contract
# `write_bytes_file_0600` states, not the window S-109 was opened for.
case "$UNAME_S" in
  Linux|Darwin|FreeBSD|OpenBSD|NetBSD|DragonFly)
    DOUT="$TMP/outcome"; mkdir -p "$DOUT"
    # 1 — a fresh create.
    "$WALLET" shamir-split --secret 99887766554433221100ffeeddccbbaa \
        --threshold 2 --shares 3 --out "$DOUT/fresh.json" >/dev/null 2>&1
    assert_eq "$(mode_of "$DOUT/fresh.json")" "600" "shamir-split --out lands at 0600"
    # 2 — over a PRE-EXISTING 0644 target, the path a create-mode-only fix misses.
    : > "$DOUT/pre.json"; chmod 644 "$DOUT/pre.json"
    "$WALLET" shamir-rotate --shares "$TMP/src.json" --threshold 2 \
        --shares-out "$DOUT/pre.json" --force >/dev/null 2>&1
    assert_eq "$(mode_of "$DOUT/pre.json")" "600" "shamir-rotate over a pre-existing 0644 target ends at 0600"
    # 3 — EVERY record of the bulk loop, not just the first: the S-109 follow-up
    #     defect was per-record, and a fix that restricts only record 1 must fail.
    AIMX="$DOUT/aim"; mkdir -p "$AIMX"
    for r in 1 2 3; do : > "$AIMX/rec$r.keyfile"; chmod 644 "$AIMX/rec$r.keyfile"; done
    "$WALLET" account-import-many --in "$TMP/aim_in.json" --out-dir "$AIMX" \
        --summary "$DOUT/aim_sum.json" --force >/dev/null 2>&1
    for r in 1 2 3; do
      assert_eq "$(mode_of "$AIMX/rec$r.keyfile")" "600" "account-import-many record $r ends at 0600 (was a pre-existing 0644 file)"
    done
    # 4 — the atomically published rotate target.
    : > "$DOUT/rot.dnk1"; chmod 644 "$DOUT/rot.dnk1"
    "$WALLET" keyfile-rotate --in "$TMP/rot_in.dnk1" --out "$DOUT/rot.dnk1" \
        --old-passphrase-from "file:$TMP/rot_old.txt" \
        --new-passphrase-from "file:$TMP/rot_new.txt" --force >/dev/null 2>&1
    assert_eq "$(mode_of "$DOUT/rot.dnk1")" "600" "keyfile-rotate publishes at 0600 over a pre-existing 0644 target"
    ;;
  *)
    # Windows never reaches here: it exits at the PLATFORM-SKIP gate near the top
    # of this file, before the fixtures are even built. This arm is the residual
    # for a uname this wrapper does not recognise as a POSIX-mode platform —
    # decline by name, bank nothing, and let the floor below fail closed if that
    # leaves the run with no assertion at all. An unrecognised platform is a
    # reason to fail closed, not a reason to claim the property is absent.
    skip "section D (this wrapper does not know whether POSIX file modes exist on $UNAME_S, so the final modes are not judged here)"
    ;;
esac

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count skipped section(s)"
# fail_count == 0 is NOT sufficient: on a box with neither strace/ptrace nor a C
# compiler both sections SKIP and 0 pass / 0 fail would have printed PASS. A gate
# that can report success having checked nothing is what this increment removes.
if [ "$pass_count" = "0" ]; then
    echo "  FAIL: test_wallet_out_perms — every section skipped; nothing was asserted"
    exit 1
elif [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet output perms — $pass_count assertion(s) checked, $skip_count section(s) declined"
  echo "        what declined is NOT asserted here (see any SKIP lines above)"
  exit 0
else
    echo "  FAIL: test_wallet_out_perms"; exit 1
fi
