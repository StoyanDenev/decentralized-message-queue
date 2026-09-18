#!/usr/bin/env bash
# tools/test_node_key_perms.sh — S-091 (PARTIAL): the node identity SEED at rest,
# gated on the OUTCOME on the filesystem, never on the source text.
#
# The defect, reproduced 2026-09-17 against the binary built from HEAD:
# `crypto::save_node_key` wrote the 32-byte Ed25519 seed as plaintext hex through
# a bare std::ofstream, which creates at 0666 & ~umask and narrows nothing, so
# `determ init` left node_key.json at 0644 (0666 under umask 000) inside a 0755
# data dir, and an unprivileged local user (`nobody`) read priv_seed straight out
# of it. Both shipped callers are `determ init` (src/main.cpp cmd_init) and
# `determ start` on first run (cmd_start).
#
# THREE legs, because no one of them is sufficient:
#
#   A. the in-process property test `determ test-node-key-perms` — the create
#      mode, the narrowing of an ALREADY-EXISTING 0666 file (which the create
#      mode provably cannot do), the 0700 directory this function creates, a
#      pre-existing directory deliberately left alone, a symlinked path refused,
#      the container byte-identical, and a failed narrowing reported by throwing.
#
#   B. the outcome of the REAL command: `determ init` under umask 022 AND under
#      umask 000, because a mode that is only right under a lucky umask is not a
#      mitigation. Leg A runs inside one process with a fixed umask; this is the
#      end-to-end statement about the shipped command. (`determ start`'s
#      first-run keygen is the same call; it is not separately exercised because
#      starting a daemon binds ports and would make a FAST gate slow and racy.)
#
#   C. the syscall ORDER under strace, which no in-process assertion can make:
#      among the mode-setting calls on the key's descriptor BEFORE its first
#      write, at least one exists and the last one sets 0600. This is what kills
#      a "create 0600, widen to 0666, write, narrow back to 0600" implementation,
#      which ends at the right mode and leaves the window fully open.
#
# What leg C deliberately does NOT do: assert on the MODE ARGUMENT of the
# openat. Measured today, strace prints `openat(..., O_CREAT, 0600) = 3` whether
# or not the kernel used that mode — the pre-fix binary's own trace reads
# `openat(..., O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3` for a file that ended up
# 0644 — so grepping the trace for a mode gates the call's source text, not the
# property. Only the fchmod-on-the-descriptor ordering is asserted here.
#
# Leg C is behind a capability probe (strace present, Linux, ptrace permitted,
# and the trace SET accepted — an strace that does not know a name in the set
# exits 1 without creating its -o file) in the shape tools/test_light_outbox.sh
# section C uses. `fchmodat2` is in the set because a newer glibc can route
# fchmod(2) through it; a pre-6.6 strace does not know the name, so the probe
# degrades to the set without it rather than losing the leg. Where it cannot run
# it prints SKIP: with the cause and banks no pass.
#
# Windows: nothing is asserted and nothing is claimed, and since 2026-09-18 the
# WRAPPER says so as a whole rather than declining leg by leg into a failure.
# save_node_key sets no permission there by design — _S_IREAD|_S_IWRITE drives
# only FILE_ATTRIBUTE_READONLY and the ACL arrives by inheritance
# (docs/proofs/S005PassphraseKeyfile.md F-4) — so there is no POSIX mode on disk
# for leg A, B or C to observe and every one of them declined. The `pass_count
# > 0` floor then correctly called a run that asserted nothing a FAILURE; this
# is a FAST member and the CI matrix carries a windows-2022 job, so the Windows
# job went red for a gate whose subject does not exist there. The wrapper now
# emits, before any leg runs, the terminal `PLATFORM-SKIP:` marker that
# tools/run_all.sh scores in its own column: not a pass, not a failure, and
# named in the summary so the ABSENCE OF COVERAGE stays visible instead of being
# tidied away. Leg A's in-process Windows arm — `determ test-node-key-perms`
# prints `SKIP: node-key-perms` in place of its PASS marker (src/main.cpp) — is
# unchanged and is still what a developer running that subcommand by hand there
# sees; the wrapper simply no longer gets that far.
#
# STILL OPEN after this gate, by construction: the seed is PLAINTEXT. Encryption
# (a KDF + envelope, as the wallet's DWE2 and the light client's DAK1/DNK1 do) is
# the owner-gated D2 src-side keyfile increment. S-091 stays OPEN for it.
#
# Run from repo root: bash tools/test_node_key_perms.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── The one platform where this gate's PROPERTY DOES NOT EXIST ────────────────
# Windows has no POSIX file mode, so "node_key.json ends at 0600" is not a
# statement that can be true or false there; see the Windows paragraph in the
# header for what protects the key on that platform instead. Every leg below
# would decline and the floor at the bottom would turn that into a FAIL against
# a product that is not broken.
#
# THE BOUNDARY, and it is the whole point: this is a PURE `uname` TEST. A Linux
# or macOS box that merely LACKS A TOOL — no strace, no ptrace permission, no C
# compiler — does NOT come here. The property exists on those boxes, legs that
# can run still run, legs that cannot print a named SKIP, and if that leaves
# nothing asserted the floor fails closed exactly as before. "The property is
# absent" and "the tool is absent" are different facts and only the first one
# may reach this branch; conflating them would make PLATFORM-SKIP a new way to
# go quietly green.
UNAME_S=$(uname -s 2>/dev/null || echo unknown)
case "$UNAME_S" in
  MINGW*|MSYS*|CYGWIN*)
    echo "  NOT GATED HERE: legs A (in-process modes), B (determ init outcome) and"
    echo "        C (strace ordering) all rest on a POSIX file mode, which $UNAME_S"
    echo "        does not have. The node key's protection on Windows is the parent"
    echo "        directory's NTFS ACL, which save_node_key deliberately does not"
    echo "        touch (docs/proofs/S005PassphraseKeyfile.md F-4) and which nothing"
    echo "        in this suite checks."
    echo "  PLATFORM-SKIP: test_node_key_perms — POSIX file modes do not exist on $UNAME_S; the property this gate observes is absent, so nothing was asserted and no pass is banked"
    exit 0
    ;;
esac

pass_count=0
fail_count=0
assert() {  # assert <true|false> <message>
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
mode_of() { # portable mode of a path, or the literal "unreadable"
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo "unreadable"
}

T=$(mktemp -d "${TMPDIR:-/tmp}/determ-nodekeyperms.XXXXXX")
trap 'rm -rf "$T"' EXIT

echo "=== A. in-process property test (determ test-node-key-perms) ==="
OUT=$("$DETERM" test-node-key-perms 2>&1) || true
echo "$OUT" | sed 's/^/  | /'
if echo "$OUT" | tail -3 | grep -q "PASS: node-key-perms all assertions"; then
  assert true "determ test-node-key-perms reports all assertions passing"
elif echo "$OUT" | tail -3 | grep -q "SKIP: node-key-perms"; then
  dt_skip "section A (the in-process gate reports a platform SKIP and banks no pass)"
else
  assert false "determ test-node-key-perms printed neither its PASS marker nor a SKIP marker"
fi

echo
echo "=== B. outcome of the shipped command (determ init) ==="
case "$UNAME_S" in
  Linux|Darwin|*BSD|DragonFly)
    # umask 022 — the default, and the umask under which the defect showed 0644.
    ( umask 022; "$DETERM" init --data-dir "$T/d022" ) >"$T/init022.log" 2>&1
    RC=$?
    assert "$([ "$RC" = "0" ] && [ -f "$T/d022/node_key.json" ] && echo true || echo false)" \
           "determ init creates a node key (exit $RC)"
    # Control: this file really is the secret. Without it every mode assertion
    # below could be true of a file that never held a seed.
    assert "$(grep -q '"priv_seed"' "$T/d022/node_key.json" && echo true || echo false)" \
           "control — the file written really does contain the private seed"
    M=$(mode_of "$T/d022/node_key.json")
    assert "$([ "$M" = "600" ] && echo true || echo false)" \
           "umask 022: node_key.json mode is 0600 (got $M; was 644 before the fix)"
    # umask 000 — proves the mode is SET, not inherited from a lucky umask.
    ( umask 000; "$DETERM" init --data-dir "$T/d000" ) >"$T/init000.log" 2>&1
    M=$(mode_of "$T/d000/node_key.json")
    assert "$([ "$M" = "600" ] && echo true || echo false)" \
           "umask 000: node_key.json mode is still 0600 (got $M; was 666 before the fix)"
    # The data dir `determ init` creates is NOT narrowed and is not asserted to
    # be: cmd_init creates it itself before calling save_node_key, so it is not a
    # directory this function created (src/crypto/keys.cpp states the rule and
    # the DECISION-LOG entry states the consequence). The 0700 property belongs
    # to a directory save_node_key creates, and section A gates it at the layer
    # where the rule lives. `determ start`'s first-run keygen is the SAME call
    # with the same two properties and is not separately exercised here: it
    # blocks, binds the configured ports and would make a FAST gate slow and
    # racy for a statement section A already makes.
    ;;
  *)
    # Windows never reaches here — it exits at the PLATFORM-SKIP gate near the
    # top of this file, before any leg runs. This arm is the residual for a
    # uname this wrapper does not recognise as a POSIX-mode platform: decline by
    # name, bank nothing, and let the floor at the bottom fail closed if that
    # leaves the run with no assertion at all. An unrecognised platform is a
    # reason to fail closed, not a reason to claim the property is absent.
    echo "  SKIP: section B (this wrapper does not know whether POSIX file modes"
    echo "        exist on $UNAME_S, so the outcome of determ init is not judged here)"
    ;;
esac

echo
echo "=== C. syscall order (Linux strace): the narrowing precedes the first write ==="
# glibc's fchmod(2) is normally the `fchmod` syscall, but a newer glibc can route
# it through `fchmodat2` (Linux 6.6), and a chmod-by-path implementation would
# show up as `chmod`/`fchmodat`. All four must be TRACED and MATCHED or the leg
# is blind to the very syscall it exists to observe.
TRACE_SET=openat,fchmod,fchmodat,fchmodat2,chmod,write,close
SKIP_C=""
if ! command -v strace >/dev/null 2>&1; then SKIP_C="strace is not installed"
elif [ "$UNAME_S" != "Linux" ]; then SKIP_C="this is not Linux and strace is Linux-only"
elif ! strace -o /dev/null true >/dev/null 2>&1; then SKIP_C="ptrace is not permitted here"
elif ! strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1; then
  # An strace that does not know a name in the set exits 1 WITHOUT creating its
  # -o file, so the SET is probed too, not just the binary. `fchmodat2` is the
  # newest name here and the only one a pre-6.6-era strace lacks; on such a box
  # the glibc that would emit it does not exist either, so degrade to the set
  # without it rather than lose the leg.
  TRACE_SET=openat,fchmod,fchmodat,chmod,write,close
  strace -e trace="$TRACE_SET" -o /dev/null true >/dev/null 2>&1 \
    || SKIP_C="this strace rejects a syscall name the leg needs"
fi
if [ -z "$SKIP_C" ]; then
  TR="$T/strace.txt"
  ( umask 022; strace -e trace="$TRACE_SET" -o "$TR" \
        "$DETERM" init --data-dir "$T/dtrace" >/dev/null 2>&1 )
  if [ ! -s "$TR" ]; then
    assert false "strace produced no trace for determ init (the syscall order cannot be judged)"
  else
    ORDER=$($PY - "$TR" <<'EOF'
import re, sys
# Scope to the ONE descriptor the key file was opened on, from its openat to its
# close: file descriptors are reused, so a chmod on a LATER file that happens to
# get the same number must not be read as this file's. A trace line split as
# "<unfinished ...>" does not match and the leg goes RED rather than guessing.
OPEN = re.compile(r'openat\((?:AT_FDCWD, )?"([^"]*node_key\.json)"[^)]*\)\s*=\s*(\d+)\b')
lines = open(sys.argv[1]).read().splitlines()
op = None
for i, l in enumerate(lines):
    m = OPEN.search(l)
    if m:
        op = (i, m.group(2))
        break
if op is None:
    print("no-open"); sys.exit(0)
start, fd = op
CLOSE = re.compile(r'\bclose\(' + fd + r'\)')
end = next((i for i in range(start + 1, len(lines)) if CLOSE.search(lines[i])), len(lines))
window = lines[start + 1:end]
# Mode-setting calls ON THIS DESCRIPTOR, in order, with the mode they set.
# Descriptor-based AND path-based: a widen done by path between the create and
# the first write is just as real, and a descriptor-only pattern reports it
# as "closed" with the window fully open. The sibling gate
# tools/test_wallet_out_perms.sh counts both; this one did not.
CHMOD  = re.compile(r'\bfchmod\(' + fd + r', 0?([0-7]{3,4})[,)]')
PCHMOD = re.compile(r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"[^"]*node_key\.json", 0?([0-7]{3,4})[,)]')
WRITE = re.compile(r'\bwrite\(' + fd + r',')
first_write = next((i for i, l in enumerate(window) if WRITE.search(l)), None)
if first_write is None:
    print("no-write"); sys.exit(0)
modes = [m.group(1) for i, l in enumerate(window) if i < first_write
         for m in [CHMOD.search(l) or PCHMOD.search(l)] if m]
print(("closed" if modes and modes[-1].lstrip("0") == "600" else "open") + " " + ",".join(modes))
EOF
)
    VERDICT=$(echo "$ORDER" | awk '{print $1}')
    assert "$([ "$VERDICT" = "closed" ] && echo true || echo false)" \
           "strace: among the mode-setting calls on the key descriptor before its first write, at least one exists and the last sets 0600 (parse said: $ORDER)"
    # Self-check on the PARSE, not a statement about the product: the pre-fix
    # trace (no mode-setting call at all on that descriptor) must not be readable
    # as "closed". Re-runs the same parser over the same trace with every fchmod
    # line removed; if it still answered "closed" the assertion above would be
    # vacuous.
    # Strip everything the parser counts as a mode-setting call, path-based
    # included, or the self-check would not be stripping what it claims to.
    grep -v -E '\bf?chmod(at2?)?\(' "$TR" > "$T/strace_nochmod.txt"
    ORDER2=$($PY - "$T/strace_nochmod.txt" <<'EOF'
import re, sys
OPEN = re.compile(r'openat\((?:AT_FDCWD, )?"([^"]*node_key\.json)"[^)]*\)\s*=\s*(\d+)\b')
lines = open(sys.argv[1]).read().splitlines()
op = None
for i, l in enumerate(lines):
    m = OPEN.search(l)
    if m:
        op = (i, m.group(2)); break
if op is None:
    print("no-open"); sys.exit(0)
start, fd = op
CLOSE = re.compile(r'\bclose\(' + fd + r'\)')
end = next((i for i in range(start + 1, len(lines)) if CLOSE.search(lines[i])), len(lines))
window = lines[start + 1:end]
# Descriptor-based AND path-based: a widen done by path between the create and
# the first write is just as real, and a descriptor-only pattern reports it
# as "closed" with the window fully open. The sibling gate
# tools/test_wallet_out_perms.sh counts both; this one did not.
CHMOD  = re.compile(r'\bfchmod\(' + fd + r', 0?([0-7]{3,4})[,)]')
PCHMOD = re.compile(r'\b(?:chmod|fchmodat2?)\((?:AT_FDCWD, )?"[^"]*node_key\.json", 0?([0-7]{3,4})[,)]')
WRITE = re.compile(r'\bwrite\(' + fd + r',')
first_write = next((i for i, l in enumerate(window) if WRITE.search(l)), None)
if first_write is None:
    print("no-write"); sys.exit(0)
modes = [m.group(1) for i, l in enumerate(window) if i < first_write
         for m in [CHMOD.search(l) or PCHMOD.search(l)] if m]
print(("closed" if modes and modes[-1].lstrip("0") == "600" else "open") + " " + ",".join(modes))
EOF
)
    assert "$([ "$(echo "$ORDER2" | awk '{print $1}')" != "closed" ] && echo true || echo false)" \
           "strace: the same parse over the same trace with the fchmod lines removed is NOT 'closed' (the assertion is not vacuous; got: $ORDER2)"
  fi
else
  echo "  SKIP: section C ($SKIP_C); the syscall-order leg runs on Linux only —"
  echo "        sections A and B still gate the resulting modes, but the window"
  echo "        between the create and the first write is NOT gated on this box"
fi

echo
echo "=== summary ==="
echo "  $pass_count pass / $fail_count fail / ${skip_count:-0} skipped section(s)"
# fail_count == 0 is not a verdict: where every section skips this would print
# PASS having asserted nothing — the defect this gate's own increment removes.
if [ "$pass_count" = "0" ]; then
  echo "  FAIL: test_node_key_perms — every section skipped; nothing was asserted"; exit 1
fi
if [ "$fail_count" = "0" ]; then echo "  PASS: test_node_key_perms"; exit 0; fi
echo "  FAIL: test_node_key_perms"; exit 1
