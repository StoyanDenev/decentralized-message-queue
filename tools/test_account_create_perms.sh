#!/usr/bin/env bash
# `determ account create --out` output-file permission gate (S-111).
#
# WHAT IT GATES, AND WHY THIS SHAPE
# ---------------------------------
# `determ account create --out F` writes a fresh Ed25519 account from the
# DAEMON binary. Until 2026-09-18 both of its file branches — the plaintext
# JSON and the `--passphrase` AES-256-GCM envelope — used a bare std::ofstream,
# which creates at 0666 & ~umask, and narrowed to 0600 only AFTER the bytes
# were written. Reproduced against the binary built from HEAD, umask 022:
#
#   openat(AT_FDCWD, ".../plain.json", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
#   write(3, "{\n  \"address\": \"0x12019ee1f40ee7"..., 243) = 243
#   close(3)
#   fchmodat(AT_FDCWD, ".../plain.json", 0600)                        = 0
#
# An LD_PRELOAD observer on the narrowing call measured "mode 0644 with 243
# bytes already written", and with the narrowing denied user `nobody` read the
# privkey straight out of the file. The FINAL mode is 0600, so `keystore-audit`,
# the `mode_not_0600` tag and every after-the-fact check in the tree see a
# correct file. That is why this gate asserts ORDERING, not the resulting mode
# alone: a gate on the resulting mode was already green on the defect.
#
# Four legs, none of them sufficient alone:
#
#   A. the in-process property test `determ test-account-create-perms` — the
#      pre-existing-0644 case the create mode provably cannot reach (on both
#      branches), the symlink refusal, the mode under umask 000, and the two
#      containers being byte-compatible so no reader changes.
#
#   B. the syscall ORDER under strace, which no in-process assertion can make:
#      among the mode-setting calls affecting the target between its creating
#      open and the first write to that descriptor, at least one exists and the
#      last sets 0600. Run against a PRE-EXISTING 0644 target, deliberately:
#      measured, open(O_CREAT|O_TRUNC, 0600) applies its mode ONLY on create, so
#      a create-mode-only fix leaves the whole window open on every overwrite
#      while a fresh-create test stays green. Both branches are traced.
#
#      It does NOT assert on the mode argument of the openat: strace prints
#      `openat(..., O_CREAT, 0600)` whether or not the kernel used it — the
#      pre-fix trace above prints 0666 for a file that ended at 0644 — so that
#      assertion would gate the call's source text rather than the property.
#      Path-based calls (chmod / fchmodat / fchmodat2 naming the target) count
#      alongside descriptor-based fchmod, or the mutant that creates 0600,
#      widens the PATH to 0666, writes, and narrows back would be reported as
#      "closed" with the window fully open — and it satisfies every final-mode
#      assertion in the tree. The non-vacuity self-check strips BOTH spellings.
#
#   C. LD_PRELOAD fault injection (chmod/fchmod/fchmodat -> EPERM), the only way
#      to reach the P-2 reporting path: this process owns the file it writes and
#      an owner's fchmod does not fail. It asserts BOTH that the harm is real —
#      the file is left 0644 with the key in it — AND that the named diagnostics
#      appear: the pre-write one AND the perm_ec one this site has always had
#      (it is the site wallet/main.cpp copied its diagnostic from). Run against
#      a PRE-EXISTING 0644 target: with the fix in place a FRESH create under
#      the shim still lands 0600 from the create mode, so a fresh-create leg
#      cannot show the harm at all. Exit codes are unchanged on this path and
#      that is asserted, not assumed.
#
#   D. the platform-skip arms of this gate and of its sibling
#      `test-node-key-perms` bank no pass. Until 2026-09-18 the sibling printed
#      `PASS: node-key-perms all assertions` right after its own SKIP on
#      Windows, so its wrapper's leg A recorded a pass for a run that asserted
#      nothing. The arm is unreachable on this box, so the binary exposes it
#      under DETERM_TEST_FORCE_PLATFORM_SKIP — without that hook the property
#      could only be checked by reading the source.
#
# NOT gated here, because it is not closed: Windows. `_S_IREAD|_S_IWRITE` drives
# only FILE_ATTRIBUTE_READONLY and the effective ACL arrives by inheritance from
# the parent directory (docs/proofs/S005PassphraseKeyfile.md F-4), so that arm
# of the writer keeps the previous std::ofstream verbatim and the window there
# is exactly as wide as it was.
#
# Every leg SKIPs BY NAME where its capability is absent, a SKIP does NOT
# increment the pass count, and the summary refuses to report success with
# pass_count == 0 or a missing binary — `fail_count == 0` is not a verdict.
#
# Run from repo root: bash tools/test_account_create_perms.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "${DETERM:-}" ]; then
    # Fail closed. A gate that reports PASS having asserted nothing is the exact
    # defect this increment also removes from the sibling gate's Windows arm.
    echo "  FAIL: determ binary not found; build with"
    echo "        cmake --build build-linux --config Release --target determ"
    echo "  FAIL: test_account_create_perms"
    exit 1
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="$(mktemp -d "${TMPDIR:-/tmp}/determ-acctperms.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
skip_count=0
assert() {   # $1 = true/false, $2 = description
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }
mode_of() { stat -c "%a" "$1" 2>/dev/null || stat -f "%Lp" "$1" 2>/dev/null || echo unreadable; }

UNAME_S=$(uname -s 2>/dev/null || echo unknown)
umask 022
# The command falls back to DETERM_PASSPHRASE when --passphrase is absent, so an
# inherited one would silently route every "plaintext" leg below through the
# envelope branch and the plaintext branch would never be exercised at all.
unset DETERM_PASSPHRASE DETERM_TEST_FORCE_PLATFORM_SKIP 2>/dev/null || true

echo "=== A. in-process property test (determ test-account-create-perms) ==="
OUT=$("$DETERM" test-account-create-perms 2>&1); ARC=$?
echo "$OUT" | sed 's/^/  | /'
if echo "$OUT" | tail -3 | grep -q "PASS: account-create-perms all assertions"; then
  assert "$([ "$ARC" = "0" ] && echo true || echo false)" \
         "determ test-account-create-perms reports all assertions passing and exits 0"
elif echo "$OUT" | tail -3 | grep -q "SKIP: account-create-perms"; then
  # A platform where the property does not exist. It must NOT be read as a pass,
  # and it must not be read as a product failure either.
  skip "section A (the in-process gate reports a platform SKIP and banks no pass)"
else
  assert false "determ test-account-create-perms printed neither its PASS marker nor a SKIP marker (exit $ARC)"
fi

echo
echo "=== B. syscall order: 0600 before the key is written (Linux strace) ==="
# fchmodat2 (glibc >= 2.39 / Linux >= 6.6) is in the set because a new enough
# libc routes fchmod()/chmod() through it; without it the leg would be blind to
# the very call it exists to observe. Probe the SET as well as the binary — an
# strace that does not know a name exits 1 WITHOUT creating its -o file, so
# assuming the set turns a box that should run the leg into a hard RED. Same
# pattern as tools/test_light_outbox.sh section C.
TRACE_SET=openat,open,write,chmod,fchmod,fchmodat,fchmodat2,close
DEGRADED=0
SKIP_B=""
if ! command -v strace >/dev/null 2>&1; then SKIP_B="strace is not installed"
elif [ "$UNAME_S" != "Linux" ]; then SKIP_B="this is not Linux and strace is Linux-only"
elif ! strace -o /dev/null true >/dev/null 2>&1; then SKIP_B="ptrace is not permitted here"
elif ! strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1; then
  TRACE_SET=openat,open,write,chmod,fchmod,fchmodat,close
  DEGRADED=1
  strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1 \
    || SKIP_B="this strace rejects a syscall name the leg needs"
fi
if [ -z "$SKIP_B" ]; then
  # Fixture precondition, not an assertion: a filesystem that does not honour
  # file modes cannot host this leg, and a hard RED there would be a statement
  # about the mount rather than about the code.
  PROBE="$TMP/modeprobe"; : > "$PROBE"; chmod 644 "$PROBE" 2>/dev/null
  [ "$(mode_of "$PROBE")" != "644" ] \
    && SKIP_B="this filesystem does not honour file modes (a target could not be put at 0644)"
fi
if [ -n "$SKIP_B" ]; then
  skip "section B ($SKIP_B); the syscall-ordering leg runs on Linux only"
else
  [ "$DEGRADED" = "1" ] && echo "  note: this strace does not know fchmodat2; it was dropped from the trace set"
  order_verdict() {  # $1 = trace file, $2 = target -> "<last mode before first write>|<self-check>"
    $PY - "$1" "$2" <<'EOF'
import re, sys
trace, target = open(sys.argv[1]).read().splitlines(), sys.argv[2]
q = re.escape(target)
# The CREATING open of the target: O_CREAT, a mode argument, and a RETURNED fd.
# The path also appears in non-creating opens, and a failed open returns -1 and
# creates nothing, so neither may be taken for the create.
OPEN   = re.compile(r'\bopenat?\((?:AT_FDCWD, )?"%s", ([^,)]*O_CREAT[^,)]*), 0[0-7]+\)\s*=\s*([0-9]+)\b' % q)
# Mode-setting calls that affect that file: on the DESCRIPTOR, or on the PATH.
# Both, because `create 0600; fchmod(fd,0600); chmod(path,0666); write;
# chmod(path,0600)` leaves the window fully open, ends at the right mode, and a
# descriptor-only parser calls it closed.
FCHMOD = re.compile(r'\bfchmod\((\d+), 0?([0-7]+)\)')
PCHMOD = re.compile(r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"%s", 0?([0-7]+)' % q)
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
        return "none"          # nothing narrowed the file before the key went in
    return modes[-1].lstrip("0") or "0"
# Self-check on the PARSE, not on the product: the same parse over the same
# trace with every pre-write mode-setting line removed — BOTH spellings — must
# answer "none". A parser that stopped looking inside the pre-write window, or
# one blind to the path spelling, would answer 600 here and that line goes RED.
op = next(((i, m) for i, l in enumerate(trace) for m in [OPEN.search(l)] if m), None)
if op is None:
    print("no-create-open|no-create-open"); raise SystemExit(0)
i_open, fd = op[0], op[1].group(2)
W = re.compile(r'\bwrite\(%s, ' % re.escape(fd))
i_write = next((i for i, l in enumerate(trace) if i > i_open and W.search(l)), None)
stripped = [l for i, l in enumerate(trace)
            if not (i_open < i < (i_write if i_write is not None else 0)
                    and (FCHMOD.search(l) or PCHMOD.search(l)))]
print("%s|%s" % (run(trace), run(stripped)))
EOF
  }

  # B1. plaintext branch over a PRE-EXISTING 0644 target.
  TGT="$TMP/pre_plain.json"; printf 'stale' > "$TGT"; chmod 644 "$TGT"
  echo "  fixture: the target exists at 0644 before the run — the overwrite path, where a create-mode-only fix does nothing"
  strace -f -e trace="$TRACE_SET" -o "$TMP/plain.strace" \
      "$DETERM" account create --out "$TGT" >/dev/null 2>&1
  if [ ! -s "$TMP/plain.strace" ]; then
    assert false "strace produced no trace for the plaintext write (the ordering cannot be judged)"
  else
    V=$(order_verdict "$TMP/plain.strace" "$TGT")
    assert_eq "${V%%|*}" "600" \
      "plaintext: a mode-setting call sits between the creating open and the first write, and the last one sets 0600 (target pre-existed at 0644)"
    assert_eq "${V##*|}" "none" \
      "plaintext: removing the pre-write mode-setting lines (both spellings) turns the same parse RED (that window is load-bearing, not a tautology)"
    assert_eq "$(mode_of "$TGT")" "600" "plaintext: the overwritten file ends at 0600 as well"
    grep -q '"privkey"' "$TGT" \
      && assert true "plaintext: control — the traced write really did put a private key in that file" \
      || assert false "plaintext: control — the traced file holds no private key"
  fi

  # B2. the SECOND branch of the same command: the --passphrase envelope.
  TGT2="$TMP/pre_enc.acct"; printf 'stale' > "$TGT2"; chmod 644 "$TGT2"
  strace -f -e trace="$TRACE_SET" -o "$TMP/enc.strace" \
      "$DETERM" account create --out "$TGT2" --passphrase "gate-pass-abc" >/dev/null 2>&1
  if [ ! -s "$TMP/enc.strace" ]; then
    assert false "strace produced no trace for the encrypted write (the ordering cannot be judged)"
  else
    V2=$(order_verdict "$TMP/enc.strace" "$TGT2")
    assert_eq "${V2%%|*}" "600" \
      "envelope: the encrypted branch is narrowed before its first write too (same defect, adjacent code)"
    assert_eq "${V2##*|}" "none" \
      "envelope: the same non-vacuity self-check on that trace"
    assert_eq "$(mode_of "$TGT2")" "600" "envelope: the overwritten file ends at 0600 as well"
  fi
fi

echo
echo "=== C. a narrowing that cannot happen: real harm, and both diagnostics (LD_PRELOAD) ==="
CC_BIN=""
for c in "${CC:-}" cc gcc clang; do
  [ -n "$c" ] && command -v "$c" >/dev/null 2>&1 && { CC_BIN="$c"; break; }
done
SKIP_C=""
SHIM="$TMP/nochmod.so"
if [ -z "$CC_BIN" ]; then SKIP_C="no C compiler (cc/gcc/clang) to build the fault-injection shim"
else
  cat > "$TMP/nochmod.c" <<'EOF'
/* Fault injection: every attempt to narrow a file's mode fails with EPERM.
   Stands in for a filesystem or platform where the narrowing cannot happen
   (a FAT/exFAT stick, some network mounts, a file owned by another user). */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/stat.h>
int chmod(const char *p, mode_t m)                  { (void)p;(void)m; errno = EPERM; return -1; }
int fchmod(int fd, mode_t m)                        { (void)fd;(void)m; errno = EPERM; return -1; }
int fchmodat(int d, const char *p, mode_t m, int f) { (void)d;(void)p;(void)m;(void)f; errno = EPERM; return -1; }
EOF
  cat > "$TMP/probe.c" <<'EOF'
#include <sys/stat.h>
int main(int argc, char **argv) { (void)argc; return chmod(argv[1], 0600) == 0 ? 0 : 1; }
EOF
  if ! "$CC_BIN" -shared -fPIC -o "$SHIM" "$TMP/nochmod.c" >/dev/null 2>&1; then
    SKIP_C="the fault-injection shim does not build with $CC_BIN here"
  elif ! "$CC_BIN" -o "$TMP/probe" "$TMP/probe.c" >/dev/null 2>&1; then
    SKIP_C="the LD_PRELOAD capability probe does not build with $CC_BIN here"
  else
    # Two-step probe, because "the file stayed 644" is also what a probe that
    # never RAN produces — a noexec temp mount or a loader that refuses the shim
    # would otherwise be read as successful interception and make the leg a
    # false RED.
    : > "$TMP/probe.f"; chmod 644 "$TMP/probe.f" 2>/dev/null
    "$TMP/probe" "$TMP/probe.f" >/dev/null 2>&1
    if [ "$(mode_of "$TMP/probe.f")" != "600" ]; then
      SKIP_C="the capability probe cannot run or the filesystem does not honour file modes (noexec temp mount?)"
    else
      chmod 644 "$TMP/probe.f" 2>/dev/null
      LD_PRELOAD="$SHIM" "$TMP/probe" "$TMP/probe.f" >/dev/null 2>&1
      [ "$(mode_of "$TMP/probe.f")" = "644" ] \
        || SKIP_C="LD_PRELOAD does not intercept chmod here (SIP / static libc / unsupported platform)"
    fi
  fi
fi
if [ -n "$SKIP_C" ]; then
  skip "section C ($SKIP_C); the fault-injection leg needs LD_PRELOAD and a C compiler"
else
  # Both sub-legs run over a PRE-EXISTING 0644 target. With the fix in place a
  # FRESH create under this shim still lands 0600 from the create mode, so a
  # fresh-create leg could not show the harm at all and the "is it reported?"
  # assertions would be gating a message nobody would ever see.
  # C1. plaintext branch: the key lands in a file that could not be narrowed.
  P="$TMP/denied.json"; printf 'stale' > "$P"; chmod 644 "$P"
  LD_PRELOAD="$SHIM" "$DETERM" account create --out "$P" >"$TMP/d.out" 2>"$TMP/d.err"; RC=$?
  assert_eq "$RC" "0" "plaintext: the exit code is unchanged (0) when the narrowing fails — this increment changes no exit code here"
  assert_eq "$(mode_of "$P")" "644" "plaintext: the harm is REAL — with narrowing denied the keyfile is left world-readable"
  grep -q '"privkey"' "$P" \
    && assert true "plaintext: control — that world-readable file really does hold the private key" \
    || assert false "plaintext: control — the file left behind holds no private key"
  # Three separate clauses, killed by three different defects: the PRE-WRITE
  # narrowing failing silently, the FINAL (belt-and-braces) narrowing failing
  # silently — the perm_ec check this site has always had, and the one
  # wallet/main.cpp copied — and the operator not being told what to do.
  grep -q "could not set 0600 permissions on $P before writing it" "$TMP/d.err" \
    && assert true "plaintext: the PRE-WRITE narrowing failure is reported (file + reason)" \
    || assert false "plaintext pre-write diagnostic: [$(tr '\n' ' ' < "$TMP/d.err")]"
  grep "could not set 0600 permissions on" "$TMP/d.err" | grep -qv "before writing it" \
    && assert true "plaintext: the FINAL narrowing failure is reported as well (perm_ec is still checked)" \
    || assert false "plaintext final-narrowing diagnostic: [$(tr '\n' ' ' < "$TMP/d.err")]"
  grep -q "Verify manually (chmod 0600 / icacls)" "$TMP/d.err" \
    && assert true "plaintext: the operator is told to verify the mode by hand" \
    || assert false "plaintext verify-manually line: [$(tr '\n' ' ' < "$TMP/d.err")]"
  grep -q "Account written to" "$TMP/d.out" \
    && assert true "plaintext: the success line is still printed (the file IS written; nothing about the outcome changed)" \
    || assert false "plaintext success line: [$(tr '\n' ' ' < "$TMP/d.out")]"

  # C2. envelope branch: the same, on the adjacent code path.
  E="$TMP/denied.acct"; printf 'stale' > "$E"; chmod 644 "$E"
  LD_PRELOAD="$SHIM" "$DETERM" account create --out "$E" --passphrase "gate-pass-abc" \
      >"$TMP/e.out" 2>"$TMP/e.err"; ERC=$?
  assert_eq "$ERC" "0" "envelope: the exit code is unchanged (0) when the narrowing fails"
  assert_eq "$(mode_of "$E")" "644" "envelope: the harm is REAL on the encrypted branch too"
  grep -q "could not set 0600 permissions on $E before writing it" "$TMP/e.err" \
    && assert true "envelope: the PRE-WRITE narrowing failure is reported (file + reason)" \
    || assert false "envelope pre-write diagnostic: [$(tr '\n' ' ' < "$TMP/e.err")]"
  grep "could not set 0600 permissions on" "$TMP/e.err" | grep -qv "before writing it" \
    && assert true "envelope: the FINAL narrowing failure is reported as well (perm_ec is still checked)" \
    || assert false "envelope final-narrowing diagnostic: [$(tr '\n' ' ' < "$TMP/e.err")]"
  head -1 "$E" | grep -q "^DETERM-ACCOUNT-V1 " \
    && assert true "envelope: the file kept is the real artifact, not a husk" \
    || assert false "envelope: the file kept is not a DETERM-ACCOUNT-V1 container"

  # C3. the success path is UNCHANGED. Without this, a mutant that always warns
  # satisfies every assertion above.
  OK="$TMP/ok.json"
  "$DETERM" account create --out "$OK" >"$TMP/ok.out" 2>"$TMP/ok.err"; ORC=$?
  assert_eq "$ORC" "0" "success path: without the shim the command exits 0"
  assert_eq "$(mode_of "$OK")" "600" "success path: the file is 0600"
  assert_eq "$([ -s "$TMP/ok.err" ] && echo nonempty || echo empty)" "empty" \
    "success path: a successful run prints nothing on stderr"
fi

echo
echo "=== D. the platform-skip arms bank no pass ==="
# The property: on a platform where the permissions window does not exist these
# gates must NOT print their terminal PASS marker. Until 2026-09-18
# test-node-key-perms printed `PASS: node-key-perms all assertions` immediately
# after its own SKIP line on Windows, so its wrapper's leg A recorded a pass for
# a run with zero assertions. That arm is unreachable on this box, so the binary
# exposes it under DETERM_TEST_FORCE_PLATFORM_SKIP — without that hook this
# property could only be checked by reading the source.
for T_CMD in test-node-key-perms test-account-create-perms; do
  SOUT=$(DETERM_TEST_FORCE_PLATFORM_SKIP=1 "$DETERM" "$T_CMD" 2>&1); SRC=$?
  MARK="${T_CMD#test-}"
  echo "$SOUT" | grep -q "PASS: $MARK all assertions" \
    && assert false "$T_CMD: the platform-skip arm still prints the terminal PASS marker" \
    || assert true "$T_CMD: the platform-skip arm does NOT print the terminal PASS marker"
  echo "$SOUT" | grep -q "SKIP: $MARK" \
    && assert true "$T_CMD: the platform-skip arm names itself as a SKIP" \
    || assert false "$T_CMD: the platform-skip arm printed no SKIP marker [$(echo "$SOUT" | tr '\n' ' ')]"
  assert "$([ "$SRC" != "0" ] && echo true || echo false)" \
    "$T_CMD: the platform-skip arm exits non-zero, so no caller can read success from the exit code (got $SRC)"
done

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count skipped section(s)"
# fail_count == 0 is NOT a verdict: on a box with neither strace/ptrace nor a C
# compiler two sections SKIP, and 0 pass / 0 fail would otherwise print PASS.
if [ "$pass_count" = "0" ]; then
    echo "  FAIL: test_account_create_perms — every section skipped; nothing was asserted"
    exit 1
elif [ "$fail_count" = "0" ]; then
    echo "  PASS: account create output perms (S-111 write-window ordering + reporting)"; exit 0
else
    echo "  FAIL: test_account_create_perms"; exit 1
fi
