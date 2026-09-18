#!/usr/bin/env bash
# S-114 (determ-wallet) / S-115 (the determ daemon) — private key material must
# not HAVE to travel on the command line.
#
# PROBLEM (reproduced by execution 2026-09-18, /root/audit/z2/REPRO-2026-09-18.txt,
# and again inside this gate at D2/D4): a running process's argument vector is
# world-readable at /proc/<pid>/cmdline — it is mode -r--r--r-- and an unrelated
# process in another session reads it — `ps` prints it to every user on the
# host, and the operator's interactive shell writes it verbatim into the history
# file. `determ-wallet` took a private key, a master seed, a Shamir secret, an
# RPC HMAC secret or an envelope password as a command-line ARGUMENT at twelve
# parse sites, and `determ` at six. For those strings that IS the secret.
#
# The fix is ADDITIVE and is the convention S-110 shipped for determ-light:
# `--<name>-from <file:path|env:NAME|prompt>`, the raw flag kept working but
# printing the named `WARNING[seed-on-command-line]` to stderr, both forms at
# once refused, and every malformed source refused with a named diagnostic and
# exit 1. The mechanism is one header — include/determ/util/secret_source.hpp.
#
# This gate asserts, at the layer where each rule lives:
#   A. EQUIVALENCE — for the SAME secret, the `-from` form and the raw form
#      produce byte-identical STDOUT on every deterministic command, and on the
#      randomized ones (which mint fresh salts/nonces/polynomials) the artifact
#      the `-from` form produces reconstructs to the SAME secret.
#   B. SOURCES — for EVERY ONE of the eighteen converted flag pairs: a missing
#      `file:` source is refused with a named diagnostic naming that flag and
#      exits 1, and both forms at once are refused and exit 1. Plus, on
#      representatives, `env:`, `prompt`, an unset variable, an empty file, an
#      empty path and an unknown scheme.
#   C. WARNING — for EVERY ONE of the eighteen pairs the raw flag prints
#      `WARNING[seed-on-command-line]` naming its `-from` twin, and the `-from`
#      form prints no such marker; and the warning is a WARNING — the raw form
#      still does its job and still exits 0.
#   D. PROCESS TABLE — the property itself, READ FROM THE KERNEL, not from the
#      source: with `-from` the secret is ABSENT from the running child's
#      /proc/<pid>/cmdline, and with the raw flag it is PRESENT there.
#
#      THE WINDOW IS THE WHOLE POINT, and it is SYNCHRONISED, not timed. Each
#      child is pinned by a FIFO and the sample is taken only once the kernel
#      says that child is BLOCKED in the FIFO's open(2) — /proc/<pid>/wchan
#      naming the FIFO rendezvous wait. For the `--out` legs (D1, D3) that open
#      is the LAST thing the command does before writing, so it is reached only
#      after the key has been derived / the envelope sealed, and every argv
#      write from the moment the secret is resolved up to that open is visible
#      to the sample. This replaced a fixed `sleep 0.1` on 2026-09-18: measured
#      5 runs out of 5, that sleep landed ~50 ms INSIDE the daemon's Argon2id
#      (state=R, wchan=0, the --out FIFO not yet open), so D3 was sampling
#      before the envelope existed and any post-seal argv write was invisible.
#      The transcript is /root/audit/z2/fix/B2-window-BEFORE.txt.
#
#      WHAT THE WINDOW STILL DOES NOT COVER, said here rather than discovered
#      later: an argv write AFTER that open(2) returns — i.e. during the write
#      itself, or between the write and exit. The FIFO can pin a process at the
#      open and nowhere else. That residue is a few hundred microseconds of a
#      code path that holds no secret; it is not zero and this gate does not
#      claim it is.
#
#      On a platform with no readable /proc/<pid>/cmdline, or whose kernel does
#      not name the FIFO wait in /proc/<pid>/wchan, the legs that need the
#      window print SKIP: and bank nothing; A, B and C do not need /proc and
#      still assert there.
#
# WHAT THIS GATE DOES NOT COVER, stated because the alternative is a gate that
# implies more than it checks:
#   * D covers three commands (wallet account-import, wallet shamir-split,
#     daemon account create). The four `determ submit-*` commands need a live
#     RPC peer to reach any window at all, so they are covered by B and C only —
#     their `-from` path is proved to parse, resolve and refuse, but no kernel
#     read is taken of them.
#   * the raw flags still exist. This gate pins that they KEEP WORKING; it is
#     not, and cannot be, evidence that the class is closed.
#
# Run from repo root: bash tools/test_secret_on_argv.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# Fail CLOSED when a binary this gate needs is missing: a wrapper that banks a
# pass having asserted nothing is the defect tools/test_gates_can_fail.sh exists
# to find (wave-doctrine lesson 15).
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  FAIL: determ-wallet binary not found — this gate cannot report green without it"
    exit 1
fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  FAIL: determ binary not found — this gate cannot report green without it"
    exit 1
fi

W="$DETERM_WALLET"
D="$DETERM"
# The daemon's two account subcommands fall back to this variable. Anything
# inherited from the environment would mask a refusal, so it is cleared here.
unset DETERM_PASSPHRASE

TMP="build/test_secret_on_argv.$$"; mkdir -p "$TMP"
TMP_ABS="$PWD/$TMP"
trap 'rm -rf "$TMP"' EXIT
rc=0; npass=0
pass(){ echo "  PASS: $1"; npass=$((npass+1)); }
fail(){ echo "  FAIL: $1"; rc=1; }
skip(){ echo "  SKIP: $1"; }

echo "=== S-114 / S-115: determ-wallet + determ secrets off the command line ==="

# ── fixtures ────────────────────────────────────────────────────────────────
PRIV=$(printf 'ab%.0s' $(seq 1 32))          # 64 hex — an Ed25519 seed
SEED=$(printf '3c%.0s' $(seq 1 32))          # 64 hex — a master seed
SEC=$(printf 'cd%.0s' $(seq 1 16))           # 32 hex — a Shamir / HMAC secret
PW='  p a s s  w/ spaces  '                  # LEADING, INTERNAL and TRAILING spaces:
                                             # the case the passphrase policy exists for.
                                             # A source that trimmed would change the
                                             # secret; A5/A6 and mutant M7 pin that.
PUBK=$(printf 'ee%.0s' $(seq 1 32))          # 64 hex — a DApp service pubkey
printf '%s\n' "$PRIV" > "$TMP/priv.hex";  chmod 600 "$TMP/priv.hex"
printf '%s\n' "$SEED" > "$TMP/seed.hex";  chmod 600 "$TMP/seed.hex"
printf '%s\n' "$SEC"  > "$TMP/sec.hex";   chmod 600 "$TMP/sec.hex"
printf '%s\n' "$PW"   > "$TMP/pw.txt";    chmod 600 "$TMP/pw.txt"
: > "$TMP/empty.txt"
printf '{"keyholders":[{"share_index":1,"passphrase":"kh1"},{"share_index":2,"passphrase":"kh2"}]}' \
    > "$TMP/kh.json"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "── A. EQUIVALENCE — the -from form yields the same secret as the raw form ──"

cmp_forms(){   # cmp_forms <label> <rawfile> <fromfile>
  if [ -s "$2" ] && cmp -s "$2" "$3"; then pass "$1"
  else fail "$1 (stdout differs between the raw and -from forms)"; fi
}

"$W" account-import --priv "$PRIV" --json > "$TMP/ai.raw" 2>"$TMP/ai.raw.err"
"$W" account-import --priv-from "file:$TMP_ABS/priv.hex" --json > "$TMP/ai.from" 2>"$TMP/ai.from.err"
cmp_forms "A1 account-import --priv-from file: == --priv (byte-identical JSON)" \
          "$TMP/ai.raw" "$TMP/ai.from"

"$W" message-sign --priv "$PRIV" --message "hello" --domain-tag siwe --json \
     > "$TMP/ms.raw" 2>/dev/null
Z2_PRIV="$PRIV" "$W" message-sign --priv-from env:Z2_PRIV --message "hello" \
     --domain-tag siwe --json > "$TMP/ms.env" 2>/dev/null
cmp_forms "A2 message-sign --priv-from env: == --priv (byte-identical signature JSON)" \
          "$TMP/ms.raw" "$TMP/ms.env"

"$W" rpc-auth --method head --secret "$SEC" --json > "$TMP/ra.raw" 2>/dev/null
printf '%s\n' "$SEC" | "$W" rpc-auth --method head --secret-from prompt --json \
     > "$TMP/ra.prompt" 2>/dev/null
cmp_forms "A3 rpc-auth --secret-from prompt == --secret (byte-identical auth tag JSON)" \
          "$TMP/ra.raw" "$TMP/ra.prompt"

"$W" account-derive-batch --seed "$SEED" --count 3 --json > "$TMP/ad.raw" 2>/dev/null
"$W" account-derive-batch --seed-from "file:$TMP_ABS/seed.hex" --count 3 --json \
     > "$TMP/ad.from" 2>/dev/null
cmp_forms "A4 account-derive-batch --seed-from file: == --seed (byte-identical derived set)" \
          "$TMP/ad.raw" "$TMP/ad.from"

# envelope encrypt is RANDOMIZED (fresh salt + nonce), so the equivalence that
# matters is that the password RESOLVES to the same bytes: an envelope sealed
# with --password-from must open with the raw --password, and vice versa. The
# fixture password carries leading/trailing and internal spaces, which is the
# case the passphrase policy exists for — a whitespace-trimming source would
# produce a container nobody can open and this assertion is what catches it.
BLOB_FROM=$("$W" envelope encrypt --plaintext "$SEC" --password-from "file:$TMP_ABS/pw.txt" \
             --iters 10000 2>/dev/null | tr -d '\r')
DEC_RAW=$("$W" envelope decrypt --envelope "$BLOB_FROM" --password "$PW" 2>/dev/null | tr -d '\r')
if [ -n "$BLOB_FROM" ] && [ "$DEC_RAW" = "$SEC" ]; then
  pass "A5 envelope: sealed with --password-from, opened with the raw --password (same password bytes, spaces preserved)"
else fail "A5 envelope --password-from/--password round-trip (got '$DEC_RAW')"; fi

BLOB_RAW=$("$W" envelope encrypt --plaintext "$SEC" --password "$PW" --iters 10000 2>/dev/null | tr -d '\r')
DEC_FROM=$("$W" envelope decrypt --envelope "$BLOB_RAW" --password-from "file:$TMP_ABS/pw.txt" \
             2>/dev/null | tr -d '\r')
if [ -n "$BLOB_RAW" ] && [ "$DEC_FROM" = "$SEC" ]; then
  pass "A6 envelope: sealed with the raw --password, opened with --password-from"
else fail "A6 envelope reverse round-trip (got '$DEC_FROM')"; fi

# A5b / A6b — THE SAME no-trim rule on the OTHER branch. `trim_all_ws == false`
# governs two different functions: detail::normalize_line (the `file:` branch,
# which strips only the line terminator) and detail::normalize_value (the `env:`
# and `prompt` branches, which take the value verbatim). A5 and A6 above exercise
# the `file:` branch only, so a mutant that adds trimming to normalize_value
# ALONE — one branch over — silently changed every env:/prompt passphrase and
# left all 98 assertions green. That hole was found by review on 2026-09-18 and
# these two assertions close it; mutant M7b is the proof they can fail. The
# fixture password carries LEADING, INTERNAL and TRAILING spaces, so a trimming
# source resolves to different bytes and the container does not open.
BLOB_ENV=$(Z2PW="$PW" "$W" envelope encrypt --plaintext "$SEC" --password-from env:Z2PW \
             --iters 10000 2>/dev/null | tr -d '\r')
DEC_ENV_RAW=$("$W" envelope decrypt --envelope "$BLOB_ENV" --password "$PW" 2>/dev/null | tr -d '\r')
if [ -n "$BLOB_ENV" ] && [ "$DEC_ENV_RAW" = "$SEC" ]; then
  pass "A5b envelope: sealed with --password-from env:, opened with the raw --password (env: values are VERBATIM — leading and trailing spaces survive)"
else fail "A5b envelope --password-from env: round-trip (got '$DEC_ENV_RAW')"; fi

BLOB_PROMPT=$(printf '%s\n' "$PW" | "$W" envelope encrypt --plaintext "$SEC" \
               --password-from prompt --iters 10000 2>/dev/null | tr -d '\r')
DEC_PROMPT_RAW=$("$W" envelope decrypt --envelope "$BLOB_PROMPT" --password "$PW" 2>/dev/null | tr -d '\r')
if [ -n "$BLOB_PROMPT" ] && [ "$DEC_PROMPT_RAW" = "$SEC" ]; then
  pass "A6b envelope: sealed with --password-from prompt, opened with the raw --password (prompt values are VERBATIM too)"
else fail "A6b envelope --password-from prompt round-trip (got '$DEC_PROMPT_RAW')"; fi

# shamir-split is randomized (fresh polynomial). The invariant is the secret.
"$W" shamir-split --secret-from "file:$TMP_ABS/sec.hex" --threshold 2 --shares 3 \
     --out "$TMP/sh.bin" >/dev/null 2>&1
SH_BACK=$("$W" shamir-combine --shares "$TMP/sh.bin" --json 2>/dev/null \
          | sed -n 's/.*"secret_hex":"\([0-9a-f]*\)".*/\1/p')
if [ "$SH_BACK" = "$SEC" ]; then
  pass "A7 shamir-split --secret-from: the shares reconstruct the SAME secret"
else fail "A7 shamir-split --secret-from reconstruct (got '$SH_BACK')"; fi

"$W" backup-create --secret-from "file:$TMP_ABS/sec.hex" --threshold 2 \
     --keyholders "$TMP/kh.json" --shares-out "$TMP/bs.bin" \
     --envelopes-out "$TMP/be.bin" --json >/dev/null 2>&1
BK_BACK=$("$W" shamir-combine --shares "$TMP/bs.bin" --json 2>/dev/null \
          | sed -n 's/.*"secret_hex":"\([0-9a-f]*\)".*/\1/p')
if [ "$BK_BACK" = "$SEC" ]; then
  pass "A8 backup-create --secret-from: the backup reconstructs the SAME secret"
else fail "A8 backup-create --secret-from reconstruct (got '$BK_BACK')"; fi

# keyfile-create is randomized (KDF salt + nonce). Its inverse recovers the key.
"$W" keyfile-create --priv-from "file:$TMP_ABS/priv.hex" \
     --passphrase-from "file:$TMP_ABS/pw.txt" --out "$TMP/node.kf" --force \
     >/dev/null 2>&1
"$W" keyfile-decrypt --in "$TMP/node.kf" --passphrase-from "file:$TMP_ABS/pw.txt" \
     --out "$TMP/node.plain" --force --json >/dev/null 2>&1
KF_BACK=$(sed -n 's/.*"priv_seed"[: "]*\([0-9a-f]\{64\}\).*/\1/p' "$TMP/node.plain" 2>/dev/null)
if [ "$KF_BACK" = "$PRIV" ]; then
  pass "A9 keyfile-create --priv-from: the DNK1 container holds the SAME private key"
else fail "A9 keyfile-create --priv-from round-trip (got '$KF_BACK')"; fi

# create-recovery + recover: both secrets via -from, recovered seed must match.
"$W" create-recovery --seed-from "file:$TMP_ABS/seed.hex" \
     --password-from "file:$TMP_ABS/pw.txt" -t 1 -n 1 --out "$TMP/rec.bin" \
     >/dev/null 2>&1
REC_FROM=$("$W" recover --in "$TMP/rec.bin" --password-from "file:$TMP_ABS/pw.txt" 2>/dev/null \
           | tr -d '\r' | grep -oE '[0-9a-f]{64}' | head -1)
REC_RAW=$("$W" recover --in "$TMP/rec.bin" --password "$PW" 2>/dev/null \
           | tr -d '\r' | grep -oE '[0-9a-f]{64}' | head -1)
if [ "$REC_FROM" = "$SEED" ] && [ "$REC_RAW" = "$SEED" ]; then
  pass "A10 create-recovery/recover: --seed-from + --password-from round-trip to the SAME seed, and the raw --password opens it too"
else fail "A10 create-recovery/recover round-trip (from='$REC_FROM' raw='$REC_RAW')"; fi

# The daemon: account create --passphrase-from seals, account decrypt reads it
# back under BOTH forms, and the two read-backs are byte-identical.
"$D" account create --out "$TMP/acct.enc" --passphrase-from "file:$TMP_ABS/pw.txt" \
     >/dev/null 2>&1
"$D" account decrypt --in "$TMP/acct.enc" --passphrase "$PW" > "$TMP/dec.raw" 2>/dev/null
"$D" account decrypt --in "$TMP/acct.enc" --passphrase-from "file:$TMP_ABS/pw.txt" \
     > "$TMP/dec.from" 2>/dev/null
cmp_forms "A11 determ account create --passphrase-from seals, and account decrypt reads it back byte-identically under BOTH forms" \
          "$TMP/dec.raw" "$TMP/dec.from"
if grep -q '"privkey"' "$TMP/dec.from" 2>/dev/null; then
  pass "A12 control: that read-back really does contain the private key (so A11 is not comparing two empty files)"
else fail "A12 the daemon read-back holds no privkey — A11 proves nothing"; fi

# ════════════════════════════════════════════════════════════════════════════
# THE SITE TABLE. One row per converted flag pair; B and C are driven from it,
# so a site that is added to the binaries and not to this table is not silently
# covered, and a site in this table whose flag was never wired turns B RED.
#
#   <bin>|<noun>|<raw-flag>|<from-flag>|<raw-value>|<subcommand + other args>
# ════════════════════════════════════════════════════════════════════════════
SITES=(
"W|secret|--secret|--secret-from|$SEC|shamir-split --threshold 2 --shares 3 --out $TMP_ABS/t1.bin"
"W|password|--password|--password-from|$PW|envelope encrypt --plaintext aabb --iters 10000"
"W|password|--password|--password-from|$PW|envelope decrypt --envelope $BLOB_RAW"
"W|seed|--seed|--seed-from|$SEED|account-derive-batch --count 1 --json"
"W|private key|--priv|--priv-from|$PRIV|account-import --json"
"W|secret|--secret|--secret-from|$SEC|backup-create --threshold 2 --keyholders $TMP_ABS/kh.json --shares-out $TMP_ABS/t2.bin --envelopes-out $TMP_ABS/t3.bin --force --json"
"W|private key|--priv|--priv-from|$PRIV|keyfile-create --passphrase-from file:$TMP_ABS/pw.txt --out $TMP_ABS/t4.kf --force --json"
"W|seed|--seed|--seed-from|$SEED|create-recovery --password-from file:$TMP_ABS/pw.txt -t 1 -n 1 --out $TMP_ABS/t5.bin"
"W|password|--password|--password-from|$PW|create-recovery --seed-from file:$TMP_ABS/seed.hex -t 1 -n 1 --out $TMP_ABS/t6.bin"
"W|password|--password|--password-from|$PW|recover --in $TMP_ABS/rec.bin"
"W|private key|--priv|--priv-from|$PRIV|message-sign --message hello --domain-tag siwe --json"
"W|secret|--secret|--secret-from|$SEC|rpc-auth --method head --json"
"D|passphrase|--passphrase|--passphrase-from|$PW|account create --out $TMP_ABS/t7.acct"
"D|passphrase|--passphrase|--passphrase-from|$PW|account decrypt --in $TMP_ABS/acct.enc"
"D|private key|--priv|--priv-from|$PRIV|submit-param-change --from d.determ --name x --value-hex 00 --effective-height 1 --keyholder-sig 0:aabb --rpc-port 1"
"D|private key|--priv|--priv-from|$PRIV|submit-merge-event --from d.determ --event begin --shard-id 1 --partner-id 2 --effective-height 1 --evidence-window-start 1 --rpc-port 1"
"D|private key|--priv|--priv-from|$PRIV|submit-dapp-register --from d.determ --service-pubkey $PUBK --endpoint-url http://127.0.0.1:1/x --rpc-port 1"
"D|private key|--priv|--priv-from|$PRIV|submit-dapp-call --from d.determ --to e.determ --rpc-port 1"
)

bin_of(){ [ "$1" = "W" ] && echo "$W" || echo "$D"; }

echo ""
echo "── B. SOURCES — every converted flag pair refuses a bad source, by name ──"
echo "   (${#SITES[@]} sites x 2 assertions)"
for row in "${SITES[@]}"; do
  IFS='|' read -r bk noun raw from val rest <<< "$row"
  B=$(bin_of "$bk"); label="$(echo "$rest" | awk '{print $1 (($2 ~ /^--/) ? "" : " " $2)}') $from"
  # B-a: a missing file: source is REFUSED, exit 1, named, and it NAMES THE FLAG.
  # This is what proves the flag is parsed and routed at all: an unwired flag is
  # ignored and the command instead prints its required-argument usage error.
  out=$("$B" $rest "$from" "file:$TMP_ABS/no-such-source.hex" 2>&1 >/dev/null); r=$?
  if [ $r -eq 1 ] \
     && printf '%s' "$out" | grep -qF "cannot open $noun file:" \
     && printf '%s' "$out" | grep -qF -- "$from"; then
    pass "B $label: a missing file: source is refused (exit 1, 'cannot open $noun file:')"
  else
    fail "B $label: missing-source refusal (exit $r): $(printf '%s' "$out" | head -1)"
  fi
  # B-b: both forms at once is REFUSED. Silently preferring one would hide which
  # secret was actually used.
  out=$("$B" $rest "$raw" "$val" "$from" "file:$TMP_ABS/pw.txt" 2>&1 >/dev/null); r=$?
  if [ $r -eq 1 ] && printf '%s' "$out" | grep -qF "are mutually exclusive"; then
    pass "B $label: $raw and $from together are refused (exit 1)"
  else
    fail "B $label: both-forms-at-once (exit $r): $(printf '%s' "$out" | head -1)"
  fi
done

# The remaining source shapes, on one representative each — the mechanism is one
# header, so these are properties of that header and not of eighteen call sites.
refuse_check(){   # refuse_check <label> <expected-substring> -- <argv...>
  local label="$1" want="$2"; shift 2; [ "$1" = "--" ] && shift
  local err="$TMP/refuse.err"
  "$@" >/dev/null 2>"$err"; local r=$?
  if [ $r -eq 1 ] && grep -qF "$want" "$err"; then
    pass "$label (exit 1, named: $want)"
  else
    fail "$label (exit $r, stderr: $(head -1 "$err"))"
  fi
}
refuse_check "B19 unset env variable" "environment variable not set or empty: Z2_NO_SUCH_VAR" -- \
  "$W" account-import --priv-from env:Z2_NO_SUCH_VAR --json
refuse_check "B20 empty file" "private key file is empty:" -- \
  "$W" account-import --priv-from "file:$TMP_ABS/empty.txt" --json
refuse_check "B21 unknown source scheme" "unknown private key source 'bogus:x'" -- \
  "$W" account-import --priv-from "bogus:x" --json
refuse_check "B22 file: with an empty path" "file: source has empty path" -- \
  "$W" account-import --priv-from "file:" --json
refuse_check "B23 env: with an empty variable name" "env: source has empty variable name" -- \
  "$W" account-import --priv-from "env:" --json
refuse_check "B24 daemon: unknown source scheme" "unknown passphrase source 'bogus:x'" -- \
  "$D" account decrypt --in "$TMP_ABS/acct.enc" --passphrase-from "bogus:x"
# B21b/B21c: the refusal above ECHOES the spec, and the likeliest way to reach
# it is `--priv-from <the key itself>` — one character from `--priv <key>`, with
# the two flags adjacent in every usage string. /proc/<pid>/cmdline dies with the
# process; a CI log does not. So a spec longer than 16 characters is elided, and
# a spec with no scheme-looking prefix is not echoed at all.
"$W" account-import --priv-from "$PRIV" --json >/dev/null 2>"$TMP/echo.err"; r=$?
if [ $r -eq 1 ] && ! grep -qF "$PRIV" "$TMP/echo.err" \
   && grep -qF "64 chars elided" "$TMP/echo.err"; then
  pass "B21b a 64-hex spec (the typo that puts the KEY after --priv-from) is refused WITHOUT echoing the key: $(head -1 "$TMP/echo.err" | tr -d '\n')"
else
  fail "B21b the unknown-scheme diagnostic echoed the key: $(head -1 "$TMP/echo.err")"
fi
# ... and a mistyped SCHEME is still diagnosable: the prefix survives.
"$W" account-import --priv-from "fille:/etc/determ/node.key" --json \
    >/dev/null 2>"$TMP/echo2.err"; r=$?
if [ $r -eq 1 ] && grep -qF "unknown private key source 'fille:<" "$TMP/echo2.err"; then
  pass "B21c a mistyped scheme keeps its prefix in the diagnostic (fille:<N chars elided>)"
else
  fail "B21c mistyped-scheme diagnostic (exit $r): $(head -1 "$TMP/echo2.err")"
fi
# env: reads the NAMED variable only — a hard-coded name would pass B19 too.
Z2_OTHER="$PRIV" "$W" account-import --priv-from env:Z2_WRONG_NAME --json \
    >/dev/null 2>"$TMP/wrongenv.err"
if [ $? -ne 0 ] && grep -qF "environment variable not set or empty: Z2_WRONG_NAME" "$TMP/wrongenv.err"; then
  pass "B25 env: reads the NAMED variable only (another variable holding the key is not picked up)"
else fail "B25 env: named-variable-only"; fi

echo ""
echo "── C. WARNING — the raw flag warns by name; the -from form does not ──"
echo "   (${#SITES[@]} sites x 2 assertions)"
for row in "${SITES[@]}"; do
  IFS='|' read -r bk noun raw from val rest <<< "$row"
  B=$(bin_of "$bk"); label="$(echo "$rest" | awk '{print $1 (($2 ~ /^--/) ? "" : " " $2)}') $raw"
  err=$("$B" $rest "$raw" "$val" 2>&1 >/dev/null)
  if printf '%s' "$err" | grep -qF "WARNING[seed-on-command-line]" \
     && printf '%s' "$err" | grep -qF -- "$from"; then
    pass "C $label: warns with the named marker and names $from"
  else
    fail "C $label: no named warning on the raw flag"
  fi
  err=$("$B" $rest "$from" "file:$TMP_ABS/pw.txt" 2>&1 >/dev/null)
  if printf '%s' "$err" | grep -qF "WARNING[seed-on-command-line]"; then
    fail "C $label: the $from form warned too (the warning must be about the RAW flag)"
  else
    pass "C $label: the $from form emits no such warning"
  fi
done

# The warning is a WARNING. Without this a mutant that refuses the raw flag
# outright satisfies every C assertion above.
if [ -s "$TMP/ai.raw" ] && grep -q '"privkey_hex"' "$TMP/ai.raw" \
   && grep -qF "WARNING[seed-on-command-line]" "$TMP/ai.raw.err"; then
  pass "C37 the raw form still WORKS: account-import --priv warned AND printed its account JSON"
else fail "C37 the raw form stopped working"; fi
if [ ! -s "$TMP/ai.from.err" ]; then
  pass "C38 the --priv-from form's stderr is completely empty"
else fail "C38 the -from form wrote to stderr: $(head -1 "$TMP/ai.from.err")"; fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "── D. PROCESS TABLE — the property, read from the kernel ──"
#
# fifo_blocked <pid> — true when the kernel says this process is parked in a
# FIFO's open(2) rendezvous. `wait_for_partner` is the Linux symbol; the others
# are the spellings older and other kernels use for the same wait. Anything
# else — including the empty read and the literal `0` a kernel without
# CONFIG_KALLSYMS_ALL gives — is NOT a block.
fifo_blocked(){
  case "$(cat "/proc/$1/wchan" 2>/dev/null)" in
    *wait_for_partner*|*fifo_open*|*pipe_wait*) return 0 ;;
    *) return 1 ;;
  esac
}

# Does this kernel name that wait at all? Probed ONCE, by parking a shell in a
# FIFO open exactly as the legs below do, because a gate that polls for a string
# the platform never produces would silently degrade into the fixed sleep this
# replaced. Costs ~40 ms where it works.
WCHAN_SYNC=0
[ -r /proc/self/cmdline ] && mkfifo "$TMP/probe.fifo" 2>/dev/null
if [ -p "$TMP/probe.fifo" ]; then
  ( exec 9> "$TMP/probe.fifo" ) 2>/dev/null &
  probe_pid=$!
  for i in $(seq 1 100); do
    if fifo_blocked "$probe_pid"; then WCHAN_SYNC=1; break; fi
    kill -0 "$probe_pid" 2>/dev/null || break
    sleep 0.02
  done
  ( cat "$TMP/probe.fifo" >/dev/null ) 2>/dev/null &
  wait "$probe_pid" 2>/dev/null
fi

# cmdline_of_blocked_child <mode> <fifo> <feed> <comm> <outfile> -- <argv...>
#   mode=drain: the FIFO is the child's OUTPUT path — it blocks in open(2) for
#               WRITING until we open the read end. The command reaches that
#               open only after the secret has been resolved AND used (the key
#               derived, the envelope sealed), so the sample sees every argv
#               write in between.
#   mode=feed : the FIFO is a `file:` SOURCE — the child blocks in open(2) for
#               READING until we write into it. That window is BEFORE the read,
#               and proves the source path itself puts nothing on argv.
#   Waits on /proc/<pid>/comm (the executable's name, which no argv edit can
#   forge) until the child has exec'd, then waits until the KERNEL says it is
#   blocked in the FIFO open, snapshots /proc/<pid>/cmdline, THEN unblocks it.
#   A watchdog bounds the child so a mutant that never blocks cannot hang the
#   suite.
#   Sets CHILD_BLOCKED for the caller, which must not bank a pass without it:
#     yes     — sampled with the child parked in the FIFO open (the real window)
#     no      — the child exited without ever reaching it (the window never
#               existed; the caller FAILS, it does not skip)
#     timeout — still running after the bound without ever blocking (same)
#     unknown — this kernel does not name the wait; the caller SKIPS
CHILD_BLOCKED=unknown
cmdline_of_blocked_child(){
  local mode="$1" fifo="$2" feed="$3" comm="$4" outfile="$5"; shift 5
  [ "$1" = "--" ] && shift
  : > "$outfile"
  CHILD_BLOCKED=unknown
  "$@" >/dev/null 2>&1 &
  local pid=$! i wdog
  ( sleep 25; kill -9 "$pid" ) >/dev/null 2>&1 &
  wdog=$!
  for i in $(seq 1 400); do
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "$comm" ] && break
    sleep 0.02
  done
  if [ "$WCHAN_SYNC" = "1" ]; then
    CHILD_BLOCKED=timeout
    for i in $(seq 1 400); do          # 400 x 0.02 s = 8 s, inside the watchdog
      if fifo_blocked "$pid"; then CHILD_BLOCKED=yes; break; fi
      if ! kill -0 "$pid" 2>/dev/null; then CHILD_BLOCKED=no; break; fi
      sleep 0.02
    done
  else
    sleep 0.1                          # no kernel wchan: the old, weaker window
  fi
  tr '\0' '\n' < "/proc/$pid/cmdline" > "$outfile" 2>/dev/null
  if [ "$mode" = "feed" ]; then
    ( printf '%s\n' "$feed" > "$fifo" ) 2>/dev/null &
  else
    ( cat "$fifo" >/dev/null ) 2>/dev/null &
  fi
  wait "$pid" 2>/dev/null
  kill "$wdog" >/dev/null 2>&1
  return 0
}

# The one place the three -from legs agree on what a non-`yes` window means.
# Returns 0 when the caller may read its verdict, 1 when it has already been
# reported (as a SKIP that banks nothing, or as a FAIL).
window_usable(){   # window_usable <label>
  case "$CHILD_BLOCKED" in
    yes) return 0 ;;
    unknown) skip "$1: this kernel does not name the FIFO wait in /proc/<pid>/wchan, so the post-use window cannot be established — nothing banked"; return 1 ;;
    no)  fail "$1: the child exited without ever blocking in the FIFO open — the post-use window never existed, so nothing was proven"; return 1 ;;
    *)   fail "$1: the child never reached the FIFO open within 8 s — the post-use window never existed, so nothing was proven"; return 1 ;;
  esac
}

if [ ! -r /proc/self/cmdline ]; then
  skip "D /proc/<pid>/cmdline is unreadable on this platform — the four kernel-read assertions did not run (A, B and C above did)"
else
  # D1: the wallet, -from form, sampled with the child PARKED in the --out FIFO
  # open — which account-import reaches only after the key has been derived and
  # the container built.
  mkfifo "$TMP/w1.fifo"
  cmdline_of_blocked_child drain "$TMP/w1.fifo" "" determ-wallet "$TMP/cmd.w.from" -- \
    "$W" account-import --priv-from "file:$TMP_ABS/priv.hex" --out "$TMP/w1.fifo" --force
  if ! window_usable "D1 wallet --priv-from"; then :
  elif [ ! -s "$TMP/cmd.w.from" ]; then
    fail "D1 could not read /proc/<pid>/cmdline of the -from child"
  elif grep -q "account-import" "$TMP/cmd.w.from" && ! grep -qF "$PRIV" "$TMP/cmd.w.from"; then
    pass "D1 wallet --priv-from: the private key is ABSENT from /proc/<pid>/cmdline while the child is BLOCKED in the --out open, i.e. after the key was derived and the container built"
  else
    fail "D1 the private key appeared in /proc/<pid>/cmdline under --priv-from"
  fi

  # D2: the positive control — the raw flag DOES leak it, so D1's grep is live
  # and is not passing on a broken read. It needs no post-use window (a raw
  # argument is on argv from exec onwards), so it asserts whatever the kernel
  # gave us; that is why it is not routed through window_usable.
  mkfifo "$TMP/w2.fifo"
  cmdline_of_blocked_child drain "$TMP/w2.fifo" "" determ-wallet "$TMP/cmd.w.raw" -- \
    "$W" account-import --priv "$PRIV" --out "$TMP/w2.fifo" --force
  if grep -qF "$PRIV" "$TMP/cmd.w.raw"; then
    pass "D2 control: the RAW --priv DOES put the key in /proc/<pid>/cmdline (S-114 reproduced in-gate)"
  else
    fail "D2 control failed — the /proc read sees no key even for the raw form, so D1 proves nothing"
  fi

  # D3: the daemon, -from form, sampled with the child PARKED in the --out FIFO
  # open — which `account create` reaches only once the Argon2id KDF has run and
  # the AES-256-GCM envelope keyed from that passphrase has been sealed and
  # serialized. THIS is the leg the fixed sleep got wrong: the daemon costs
  # ~160 ms and the sample used to land at ~110 ms, inside the KDF.
  mkfifo "$TMP/d1.fifo"
  cmdline_of_blocked_child drain "$TMP/d1.fifo" "" determ "$TMP/cmd.d.from" -- \
    "$D" account create --out "$TMP/d1.fifo" --passphrase-from "file:$TMP_ABS/pw.txt"
  if ! window_usable "D3 daemon --passphrase-from"; then :
  elif [ ! -s "$TMP/cmd.d.from" ]; then
    fail "D3 could not read /proc/<pid>/cmdline of the daemon -from child"
  elif grep -q "account" "$TMP/cmd.d.from" && ! grep -qF "$PW" "$TMP/cmd.d.from"; then
    pass "D3 daemon --passphrase-from: the passphrase is ABSENT from /proc/<pid>/cmdline while the child is BLOCKED in the --out open, i.e. after the envelope was sealed with it"
  else
    fail "D3 the passphrase appeared in /proc/<pid>/cmdline under --passphrase-from"
  fi

  # D4: the daemon's positive control in the same window.
  mkfifo "$TMP/d2.fifo"
  cmdline_of_blocked_child drain "$TMP/d2.fifo" "" determ "$TMP/cmd.d.raw" -- \
    "$D" account create --out "$TMP/d2.fifo" --passphrase "$PW"
  if grep -qF "$PW" "$TMP/cmd.d.raw"; then
    pass "D4 control: the RAW --passphrase DOES put it in /proc/<pid>/cmdline (S-115 reproduced in-gate)"
  else
    fail "D4 control failed — the /proc read sees no passphrase even for the raw form, so D3 proves nothing"
  fi

  # D5: a third command, sampled while it BLOCKS ON THE SOURCE ITSELF (the
  # `file:` path is a FIFO). Weaker than D1/D3 — it cannot see a post-resolution
  # leak — but it proves the resolution path never puts the secret on argv.
  mkfifo "$TMP/src.fifo"
  cmdline_of_blocked_child feed "$TMP/src.fifo" "$SEC" determ-wallet "$TMP/cmd.w.src" -- \
    "$W" shamir-split --secret-from "file:$TMP/src.fifo" --threshold 2 --shares 3 \
    --out "$TMP/d5.bin" --force
  if ! window_usable "D5 shamir-split --secret-from"; then :
  elif grep -q "shamir-split" "$TMP/cmd.w.src" && ! grep -qF "$SEC" "$TMP/cmd.w.src"; then
    pass "D5 shamir-split --secret-from: the secret is absent from /proc/<pid>/cmdline while the child is BLOCKED reading the source"
  else
    fail "D5 shamir-split --secret-from /proc/<pid>/cmdline check"
  fi
fi

echo ""
echo "  $npass assertions passed"
# fail_count == 0 is NOT a verdict: a run in which every section declined would
# report 0 pass / 0 fail. The floor is part of the verdict.
if [ $rc -eq 0 ] && [ $npass -gt 0 ]; then
  echo "  PASS: secret on argv all assertions"
else
  echo "  FAIL: secret on argv ($npass assertions passed, rc=$rc)"
  rc=1
fi
exit $rc
