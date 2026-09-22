#!/usr/bin/env bash
# S-110 — determ-light secret seeds must not have to travel on the command line.
#
# PROBLEM (reproduced 2026-09-17, /root/audit/w3/REPRO-2026-09-17.txt): every
# determ-light subcommand that takes a private seed took it as a command-line
# ARGUMENT. A running process's argument vector is world-readable at
# /proc/<pid>/cmdline, `ps` prints it to every user on the host, and the
# operator's shell writes it verbatim into the history file. For the ML-DSA /
# Ed25519 seeds that IS the private key.
#
# The fix is ADDITIVE: `--mldsa-seed-from` / `--ed-seed-from` / `--blind-seed-from`
# taking `file:<path>` | `env:<NAME>` | `prompt` (the convention
# `determ-wallet keyfile-create --passphrase-from` already uses), the raw flags
# kept working but warned about.
#
# This gate asserts, at the layer where each rule lives:
#   A. EQUIVALENCE — `--mldsa-seed-from file:<path>` produces BYTE-IDENTICAL
#      output to `--mldsa-seed <hex>` for the same seed: the pq-address address,
#      the pq-transfer tx JSON, and the pq-sign-tx (hybrid, both seeds) tx JSON.
#   B. SOURCES — env: and prompt: work and agree with the raw form; a missing
#      file, an unset variable, a bad source scheme, both-forms-at-once and a
#      malformed (odd / short) hex value are each REFUSED with a named
#      diagnostic and exit code 1.
#   C. WARNING — the raw form prints WARNING[seed-on-command-line] naming the
#      -from alternative on stderr and still exits 0; the -from form prints no
#      such warning.
#   D. PROCESS TABLE — the property itself, read from the kernel, NOT from the
#      source: with `--*-seed-from` the seed is ABSENT from the running child's
#      /proc/<pid>/cmdline, while with the raw flag it is PRESENT there. Both
#      children are held in a deterministic window by a FIFO (a `file:` source
#      that is a FIFO blocks in open(2); an `--out` that is a FIFO blocks in
#      open(2) after signing), so there is no race. This section requires the
#      Linux kernel's /proc and FIFO behavior; elsewhere it prints SKIP: and
#      asserts nothing. MSYS /proc does not provide this native-process contract.
#   E. BLIND SEEDS — build-shield / build-unshield --blind-seed-from round-trips
#      to a byte-identical tx and warns on the raw form.
#
# Run from repo root: bash tools/test_light_seed_source.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi

TMP="build/test_light_seed_source.$$"; mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
rc=0; npass=0
pass(){ echo "  PASS: $1"; npass=$((npass+1)); }
fail(){ echo "  FAIL: $1"; rc=1; }
skip(){ echo "  SKIP: $1"; }

echo "=== S-110: determ-light --*-seed-from (file:/env:/prompt) ==="

MS=$(printf '01%.0s' $(seq 1 32))            # 64 hex chars — the ML-DSA seed
ES=$(printf '02%.0s' $(seq 1 32))            # 64 hex chars — the Ed25519 seed
FROM="0x$(printf 'a%.0s' $(seq 1 64))"
TO="0x$(printf 'b%.0s' $(seq 1 64))"
printf '%s\n' "$MS" > "$TMP/ms.hex"; chmod 600 "$TMP/ms.hex"
printf '%s\n' "$ES" > "$TMP/es.hex"; chmod 600 "$TMP/es.hex"

# ── A. byte-identical output: raw vs file: ──────────────────────────────────
"$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed "$MS" \
    > "$TMP/addr.raw" 2>"$TMP/addr.raw.err"
"$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/ms.hex" \
    > "$TMP/addr.file" 2>"$TMP/addr.file.err"
if [ -s "$TMP/addr.raw" ] && cmp -s "$TMP/addr.raw" "$TMP/addr.file"; then
  pass "A1 pq-address: --mldsa-seed-from file: == --mldsa-seed (byte-identical address)"
else fail "A1 pq-address file: address differs from the raw form"; fi

"$DETERM_LIGHT" pq-transfer --to "$TO" --amount 100 --fee 1 --nonce 7 \
    --scheme mldsa65 --mldsa-seed "$MS" > "$TMP/tr.raw" 2>/dev/null
"$DETERM_LIGHT" pq-transfer --to "$TO" --amount 100 --fee 1 --nonce 7 \
    --scheme mldsa65 --mldsa-seed-from "file:$TMP/ms.hex" > "$TMP/tr.file" 2>/dev/null
if [ -s "$TMP/tr.raw" ] && cmp -s "$TMP/tr.raw" "$TMP/tr.file"; then
  pass "A2 pq-transfer: signed PQ_TRANSFER JSON byte-identical under both forms"
else fail "A2 pq-transfer JSON differs between --mldsa-seed and --mldsa-seed-from"; fi

"$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
    --amount 100 --fee 1 --nonce 0 --scheme hybrid65 \
    --mldsa-seed "$MS" --ed-seed "$ES" > "$TMP/sg.raw" 2>/dev/null
"$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
    --amount 100 --fee 1 --nonce 0 --scheme hybrid65 \
    --mldsa-seed-from "file:$TMP/ms.hex" --ed-seed-from "file:$TMP/es.hex" \
    > "$TMP/sg.file" 2>/dev/null
if [ -s "$TMP/sg.raw" ] && cmp -s "$TMP/sg.raw" "$TMP/sg.file"; then
  pass "A3 pq-sign-tx hybrid65: both seeds via -from == both raw (byte-identical tx)"
else fail "A3 pq-sign-tx hybrid tx differs between the raw and -from forms"; fi

# The -from output is not merely self-consistent: it is a VALID envelope.
if "$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
      --amount 100 --fee 1 --nonce 0 --scheme hybrid65 \
      --mldsa-seed-from "file:$TMP/ms.hex" --ed-seed-from "file:$TMP/es.hex" \
      --out "$TMP/sg.json" >/dev/null 2>&1 \
   && "$DETERM_LIGHT" pq-verify-tx --file "$TMP/sg.json" >/dev/null 2>&1; then
  pass "A4 the -from-signed tx VERIFIES (pq-verify-tx exit 0)"
else fail "A4 the -from-signed tx did not verify"; fi

# ── B. the other two sources, and every refusal ─────────────────────────────
MLDSA_SEED_TEST="$MS" "$DETERM_LIGHT" pq-address --scheme mldsa65 \
    --mldsa-seed-from env:MLDSA_SEED_TEST > "$TMP/addr.env" 2>/dev/null
if cmp -s "$TMP/addr.raw" "$TMP/addr.env"; then
  pass "B1 env:NAME reads THAT variable and yields the same address"
else fail "B1 env: source"; fi

printf '%s\n' "$MS" | "$DETERM_LIGHT" pq-address --scheme mldsa65 \
    --mldsa-seed-from prompt > "$TMP/addr.prompt" 2>/dev/null
if cmp -s "$TMP/addr.raw" "$TMP/addr.prompt"; then
  pass "B2 prompt reads stdin and yields the same address"
else fail "B2 prompt source"; fi

# A DIFFERENT variable must NOT be read (catches a hard-coded variable name).
MLDSA_SEED_TEST="$MS" "$DETERM_LIGHT" pq-address --scheme mldsa65 \
    --mldsa-seed-from env:SOME_OTHER_SEED_VAR > "$TMP/addr.wrongenv" 2>"$TMP/wrongenv.err"
if [ $? -ne 0 ] && grep -q "environment variable not set or empty: SOME_OTHER_SEED_VAR" "$TMP/wrongenv.err"; then
  pass "B3 env: reads the NAMED variable only (unset one -> named refusal)"
else fail "B3 env: read some other variable, or the diagnostic was not named"; fi

# refuse_check <label> <expected-substring> -- <argv...>
refuse_check(){
  local label="$1" want="$2"; shift 2; [ "$1" = "--" ] && shift
  local err="$TMP/refuse.err"; local out
  out=$("$@" 2>"$err"); local r=$?
  if [ $r -eq 1 ] && grep -qF "$want" "$err"; then
    pass "$label (exit 1, named: $want)"
  else
    fail "$label (exit $r, stderr: $(head -1 "$err"))"
  fi
}
printf 'abc\n'  > "$TMP/odd.hex"      # odd number of hex chars
printf 'aabb\n' > "$TMP/short.hex"    # even but only 2 bytes
: > "$TMP/empty.hex"

refuse_check "B4 missing file" "cannot open seed file:" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/nope.hex"
refuse_check "B5 unset variable" "environment variable not set or empty: NO_SUCH_SEED_VAR" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from env:NO_SUCH_SEED_VAR
refuse_check "B6 odd-length hex" "is not valid hex" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/odd.hex"
refuse_check "B7 short hex" "must be 32 bytes (64 hex chars); got 2 bytes" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/short.hex"
refuse_check "B8 empty file" "seed file is empty:" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/empty.hex"
refuse_check "B9 unknown source scheme" "unknown seed source 'bogus:x'" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "bogus:x"
refuse_check "B10 both forms at once" "are mutually exclusive" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed "$MS" --mldsa-seed-from "file:$TMP/ms.hex"
refuse_check "B11 raw odd-length hex still refused" "is not valid hex" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed abc
refuse_check "B12 raw short hex still refused" "must be 32 bytes (64 hex chars); got 2 bytes" -- \
  "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed aabb

# ── C. the named warning ────────────────────────────────────────────────────
if grep -q "WARNING\[seed-on-command-line\]" "$TMP/addr.raw.err" \
   && grep -q -- "--mldsa-seed-from" "$TMP/addr.raw.err" \
   && grep -qi "process" "$TMP/addr.raw.err" \
   && grep -qi "history" "$TMP/addr.raw.err"; then
  pass "C1 raw --mldsa-seed warns (named, mentions the process table + shell history + the -from flag)"
else fail "C1 the raw form did not emit the named warning"; fi
if [ -s "$TMP/addr.raw" ]; then
  pass "C2 the warning is a WARNING: the raw form still exits 0 and prints the address"
else fail "C2 the raw form stopped working"; fi
if [ ! -s "$TMP/addr.file.err" ]; then
  pass "C3 the --mldsa-seed-from form emits NO warning (clean stderr)"
else fail "C3 the -from form wrote to stderr: $(head -1 "$TMP/addr.file.err")"; fi
# hybrid: the ed seed gets its OWN named warning naming --ed-seed-from
"$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
    --amount 1 --fee 1 --nonce 0 --scheme hybrid65 \
    --mldsa-seed-from "file:$TMP/ms.hex" --ed-seed "$ES" \
    >/dev/null 2>"$TMP/edwarn.err"
if grep -q "WARNING\[seed-on-command-line\]" "$TMP/edwarn.err" \
   && grep -q -- "--ed-seed-from" "$TMP/edwarn.err"; then
  pass "C4 raw --ed-seed warns and names --ed-seed-from"
else fail "C4 raw --ed-seed did not warn"; fi

# ── D. the property, read from the kernel ───────────────────────────────────
#
# cmdline_of_blocked_child <mode> <fifo> <feed> <outfile> -- <argv...>
#   mode=feed : the FIFO is a `file:` SEED SOURCE — the child blocks in open(2)
#               for reading until we write <feed> into it.
#   mode=drain: the FIFO is the `--out` path — the child blocks in open(2) for
#               writing until we read from it.
#   Waits on /proc/<pid>/comm (the executable's name — no argv edit can forge
#   it) until the child has exec'd, snapshots /proc/<pid>/cmdline into
#   <outfile>, THEN unblocks. A watchdog bounds the child so a mutant that never
#   blocks (or never finishes) cannot hang the suite.
cmdline_of_blocked_child(){
  local mode="$1" fifo="$2" feed="$3" outfile="$4"; shift 4
  [ "$1" = "--" ] && shift
  : > "$outfile"
  "$@" >/dev/null 2>&1 &
  local pid=$! i wdog
  ( sleep 25; kill -9 "$pid" ) >/dev/null 2>&1 &
  wdog=$!
  for i in $(seq 1 400); do
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "determ-light" ] && break
    sleep 0.02
  done
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

if [ "$(uname -s)" != Linux ] || [ ! -r /proc/self/cmdline ]; then
  skip "D requires Linux kernel /proc and FIFO observation — the process-table assertions did not run; functional seed-source checks remain active"
else
  # D1: the -from form, sampled AFTER the seed has been read and used. The seed
  # comes from an ordinary file; the FIFO is `--out`, which pq-sign-tx opens
  # only once the DPQ1 envelope is signed — so the window is strictly LATER
  # than every point at which the process has handled the seed. (Sampling
  # before the read would prove nothing about what the resolved seed does
  # next: that gap let a "write the resolved seed back into argv" mutant sit
  # GREEN when this gate was first written.)
  mkfifo "$TMP/out1.fifo"
  cmdline_of_blocked_child drain "$TMP/out1.fifo" "" "$TMP/cmdline.from" -- \
    "$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
    --amount 100 --fee 1 --nonce 0 --scheme mldsa65 \
    --mldsa-seed-from "file:$TMP/ms.hex" --out "$TMP/out1.fifo"
  if [ ! -s "$TMP/cmdline.from" ]; then
    fail "D1 could not read /proc/<pid>/cmdline of the -from child"
  elif grep -q "pq-sign-tx" "$TMP/cmdline.from" \
       && ! grep -qF "$MS" "$TMP/cmdline.from"; then
    pass "D1 --mldsa-seed-from: the seed is ABSENT from /proc/<pid>/cmdline even AFTER the signature"
  else
    fail "D1 the seed appeared in /proc/<pid>/cmdline under --mldsa-seed-from"
  fi

  # D2: the positive control — the raw form DOES leak it in the SAME window, so
  # D1's grep is live and not passing on a broken read.
  mkfifo "$TMP/out2.fifo"
  cmdline_of_blocked_child drain "$TMP/out2.fifo" "" "$TMP/cmdline.raw" -- \
    "$DETERM_LIGHT" pq-sign-tx --type TRANSFER --from "$FROM" --to "$TO" \
    --amount 100 --fee 1 --nonce 0 --scheme mldsa65 --mldsa-seed "$MS" --out "$TMP/out2.fifo"
  if grep -qF "$MS" "$TMP/cmdline.raw"; then
    pass "D2 control: the RAW form does put the seed in /proc/<pid>/cmdline (S-110 reproduced in-gate)"
  else
    fail "D2 control failed — the /proc read sees no seed even for the raw form, so D1 proves nothing"
  fi

  # D3: pq-address too, sampled while it BLOCKS on a FIFO `file:` source — the
  # window before the read. Weaker than D1 (it cannot see a post-resolution
  # leak) but it covers the second command and proves the source path itself
  # never puts the seed on the command line.
  mkfifo "$TMP/seed.fifo"
  cmdline_of_blocked_child feed "$TMP/seed.fifo" "$MS" "$TMP/cmdline.addr" -- \
    "$DETERM_LIGHT" pq-address --scheme mldsa65 --mldsa-seed-from "file:$TMP/seed.fifo"
  if grep -q "pq-address" "$TMP/cmdline.addr" && ! grep -qF "$MS" "$TMP/cmdline.addr"; then
    pass "D3 pq-address --mldsa-seed-from: seed absent from /proc/<pid>/cmdline while it blocks on the source"
  else
    fail "D3 pq-address /proc/<pid>/cmdline check"
  fi
fi

# ── E. --blind-seed-from on the CT builders ─────────────────────────────────
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  skip "E determ-wallet not found (needed to mint a light keyfile) — blind-seed assertions did not run"
else
  PY=python; command -v python >/dev/null 2>&1 || PY=python3
  "$DETERM_WALLET" account-create-batch --count 1 --json > "$TMP/keys.json" 2>/dev/null
  KPRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/keys.json" 2>/dev/null)
  "$DETERM_WALLET" account-import --priv "$KPRIV" --out "$TMP/key.json" >/dev/null 2>&1
  BS=$(printf 'aa%.0s' $(seq 1 32))
  printf '%s\n' "$BS" > "$TMP/bs.hex"; chmod 600 "$TMP/bs.hex"
  if [ ! -s "$TMP/key.json" ]; then
    skip "E could not mint a light keyfile — blind-seed assertions did not run"
  else
    "$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed "$BS" \
        --amount 500 --fee 1 --nonce 0 > "$TMP/sh.raw" 2>"$TMP/sh.raw.err"
    "$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed-from "file:$TMP/bs.hex" \
        --amount 500 --fee 1 --nonce 0 > "$TMP/sh.file" 2>"$TMP/sh.file.err"
    if [ -s "$TMP/sh.raw" ] && cmp -s "$TMP/sh.raw" "$TMP/sh.file"; then
      pass "E1 build-shield: --blind-seed-from file: == --blind-seed (byte-identical SHIELD)"
    else fail "E1 build-shield output differs between the two forms"; fi
    if grep -q "WARNING\[seed-on-command-line\]" "$TMP/sh.raw.err" \
       && grep -q -- "--blind-seed-from" "$TMP/sh.raw.err"; then
      pass "E2 build-shield raw --blind-seed warns and names --blind-seed-from"
    else fail "E2 build-shield raw form did not warn"; fi
    if [ ! -s "$TMP/sh.file.err" ]; then
      pass "E3 build-shield --blind-seed-from emits no warning"
    else fail "E3 build-shield -from wrote to stderr"; fi

    "$DETERM_LIGHT" build-unshield --keyfile "$TMP/key.json" --blind-seed "$BS" \
        --to "$TO" --amount 100 --fee 1 --nonce 1 > "$TMP/un.raw" 2>/dev/null
    "$DETERM_LIGHT" build-unshield --keyfile "$TMP/key.json" \
        --blind-seed-from "file:$TMP/bs.hex" \
        --to "$TO" --amount 100 --fee 1 --nonce 1 > "$TMP/un.file" 2>/dev/null
    if [ -s "$TMP/un.raw" ] && cmp -s "$TMP/un.raw" "$TMP/un.file"; then
      pass "E4 build-unshield: --blind-seed-from file: == --blind-seed (byte-identical UNSHIELD)"
    else fail "E4 build-unshield output differs between the two forms"; fi
    refuse_check "E5 build-unshield missing blind-seed file" "cannot open seed file:" -- \
      "$DETERM_LIGHT" build-unshield --keyfile "$TMP/key.json" \
      --blind-seed-from "file:$TMP/nope.hex" --to "$TO" --amount 100 --fee 1 --nonce 1
  fi
fi

echo ""
echo "  $npass assertions passed"
if [ $rc -eq 0 ]; then echo "  PASS: light seed source all assertions"
else echo "  FAIL: light seed source"; fi
exit $rc
