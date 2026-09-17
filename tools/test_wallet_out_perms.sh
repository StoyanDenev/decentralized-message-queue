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
# Both legs SKIP BY NAME where the capability is absent (no strace / no ptrace /
# an strace that rejects a name the leg needs / no LD_PRELOAD / no C compiler),
# and a SKIP does NOT increment the pass count — a branch that checked nothing
# must not score.
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

# A share-set to rotate, and a pre-existing 0644 target to overwrite.
umask 022
"$WALLET" shamir-split --secret aabbccddeeff00112233445566778899 \
    --threshold 2 --shares 3 --out "$TMP/src.json" >/dev/null 2>&1 \
    || { echo "  FAIL: fixture shamir-split failed"; echo "  FAIL: test_wallet_out_perms"; exit 1; }

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
fi

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
    echo "  PASS: determ-wallet output perms (P-1 ordering + P-2 reporting)"; exit 0
else
    echo "  FAIL: test_wallet_out_perms"; exit 1
fi
