#!/usr/bin/env bash
# determ-wallet backup-create / backup-verify OFFLINE round-trip + tamper
# PROPERTY FUZZ (T-of-N encrypted backup bundle hardening).
#
# This is the byte-level TAMPER + ROUND-TRIP sibling of:
#   - test_wallet_backup_create.sh  (validation matrix + reconstruction)
#   - test_wallet_backup_verify.sh  (structural verify + JSON-field tampers)
# Those two tamper only at the JSON STRING level (replace the magic with a
# literal "deadbeef" word, renumber share_index). This test is distinct: it
# fuzzes MANY randomized bundles and performs BYTE-LEVEL XOR-FLIP tampers on
# the individual envelope fields (salt / pbkdf2-iters / nonce / ciphertext
# body / GCM tag) inside the canonical dot-separated-hex envelope blob, plus
# structural breaks (magic flip, GCM-tag truncation).
#
# SAFE REFERENCE (no cipher / KDF / AEAD is ever reimplemented as an oracle):
#   R1 round-trip: clean bundle -> backup-verify ACCEPTS; threshold recovery
#      (envelope decrypt of T shares + shamir-combine) yields the KNOWN
#      original secret EXACTLY. The known original is the only oracle.
#   R2 crypto tamper: XOR one byte of a random crypto field of a random
#      envelope. The blob is still structurally well-formed, so backup-verify
#      still ACCEPTS (it never decrypts) -- but `envelope decrypt` of that
#      tampered envelope is REJECTED by the AES-GCM tag (exit 2). When T < N,
#      recovering from the remaining UNTOUCHED shares still reproduces the
#      KNOWN original (the tamper is contained, not catastrophic).
#   R3 structural tamper: flip the 4-byte magic OR truncate the GCM tag below
#      16 bytes -> backup-verify REJECTS (exit 2) because the envelope no
#      longer deserializes.
#
# Fully OFFLINE: no node, no daemon, no cluster, no network. Fixed-seed RNG
# (deterministic across runs). >= 20 randomized fuzz cases.
#
# Canonical envelope blob layout (dot-separated lowercase hex), confirmed via
# `inspect-envelope`:
#   [0] magic      = 44574531  ("DWE1", 4 bytes)
#   [1] salt       = 16 bytes
#   [2] iters      = u32 little-endian (4 bytes)
#   [3] nonce      = 12 bytes
#   [4] aad        = (empty when no AAD)
#   [5] ct||tag    = ciphertext body || 16-byte AES-GCM tag
#
# Run from repo root: bash tools/test_wallet_backup_tamper_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "  SKIP: python not found (needed to drive subprocess fuzz harness)"
    exit 0
fi

WALLET="$DETERM_WALLET"
# Absolutize the wallet path so Python subprocess.run() under native-Windows
# Python can CreateProcess on it (MSYS path translation only applies to
# direct shell args, not to Python's CreateProcess call).
if [ "${WALLET#/}" = "$WALLET" ] && [ "${WALLET#?:}" = "$WALLET" ]; then
    WALLET_ABS="$PROJECT_ROOT/$WALLET"
else
    WALLET_ABS="$WALLET"
fi

# Scratch under build/ for the same path-translation reason as the sibling
# backup tests (mktemp -d returns /tmp/... which native Python can't see).
T="build/test_wallet_backup_tamper_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <condition-rc-as-string-0> <message>
  if [ "$1" = "0" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

NUM_CASES=22

echo "=== determ-wallet backup tamper/round-trip property fuzz ==="
echo "    cases: $NUM_CASES  (fixed-seed, offline)"
echo

# The entire fuzz loop runs inside one Python harness so the per-case
# randomized choices (secret bytes, N, threshold, which field to tamper,
# which byte to flip) are reproducible from a single fixed seed. The harness
# emits one "OK <msg>" / "FAIL <msg>" line per sub-assertion; the shell maps
# those onto the assert() counters so the final PASS/FAIL tally is canonical.
RESULTS=$($PY - "$WALLET_ABS" "$T" "$NUM_CASES" <<'PY_EOF'
import json, os, random, subprocess, sys

wallet, tmp, num_cases = sys.argv[1], sys.argv[2], int(sys.argv[3])
random.seed(0xDE7E12)  # fixed seed -> deterministic fuzz

results = []
def ok(msg):   results.append(("OK", msg))
def fail(msg): results.append(("FAIL", msg))

def run(args, **kw):
    return subprocess.run([wallet] + args, capture_output=True, text=True, **kw)

# Canonical envelope-blob section indices (dot-separated hex).
MAGIC, SALT, ITERS, NONCE, AAD, CTTAG = 0, 1, 2, 3, 4, 5

def xor_flip_section(blob, section_idx, rng):
    """XOR one random byte of the given hex section; return mutated blob."""
    parts = blob.split(".")
    raw = bytearray.fromhex(parts[section_idx])
    if len(raw) == 0:
        return None  # nothing to flip (e.g. empty AAD)
    pos = rng.randrange(len(raw))
    raw[pos] ^= (1 << rng.randrange(8))
    parts[section_idx] = raw.hex()
    return ".".join(parts)

def truncate_tag(blob):
    """Chop the ct||tag section below the 16-byte GCM tag -> breaks structure."""
    parts = blob.split(".")
    raw = bytearray.fromhex(parts[CTTAG])
    raw = raw[:8]  # shorter than a 16-byte tag => deserialize must fail
    parts[CTTAG] = raw.hex()
    return ".".join(parts)

def recover_secret(shares_path, env_path, skip_index, threshold, N):
    """Decrypt T envelopes (skipping skip_index if set) + shamir-combine.

    Returns (secret_hex, None) on success or (None, reason) on failure.
    Uses the wallet's own decrypt+combine -- NEVER reimplements the cipher."""
    envs = {e["share_index"]: e["envelope_blob"]
            for e in json.load(open(env_path))["envelopes"]}
    avail = [i for i in sorted(envs) if i != skip_index]
    if len(avail) < threshold:
        return None, "insufficient_after_skip"
    picked = avail[:threshold]
    rec = []
    for idx in picked:
        pw = f"kh-pw-{idx}"
        r = run(["envelope", "decrypt", "--envelope", envs[idx], "--password", pw])
        if r.returncode != 0:
            return None, f"decrypt_fail idx={idx} rc={r.returncode}"
        rec.append({"x": idx, "y_hex": r.stdout.strip().replace("\r", "")})
    sf = os.path.join(tmp, f"rec_{skip_index}_{threshold}.json")
    json.dump({"shares": rec}, open(sf, "w"))
    r = run(["shamir-combine", "--shares", sf, "--json"])
    if r.returncode != 0:
        return None, f"combine_fail rc={r.returncode}"
    try:
        return json.loads(r.stdout.strip().replace("\r", ""))["secret_hex"], None
    except Exception as ex:
        return None, f"combine_parse {ex}"

crypto_fields = [
    (SALT,  "salt"),
    (ITERS, "iters"),
    (NONCE, "nonce"),
    (CTTAG, "ciphertext/tag"),
]

for case in range(num_cases):
    rng = random.Random(0xBEEF0000 + case)  # per-case sub-stream

    # Random secret of an even number of hex bytes (8..40 bytes).
    nbytes = rng.choice([8, 12, 16, 24, 32, 40])
    secret = "".join(rng.choice("0123456789abcdef") for _ in range(nbytes * 2))

    N = rng.randint(2, 5)
    threshold = rng.randint(1, N)

    # Build the keyholders file with distinct per-share passphrases.
    khs = [{"share_index": i, "passphrase": f"kh-pw-{i}"} for i in range(1, N + 1)]
    kh_path  = os.path.join(tmp, f"kh_{case}.json")
    sh_path  = os.path.join(tmp, f"sh_{case}.json")
    env_path = os.path.join(tmp, f"env_{case}.json")
    json.dump({"keyholders": khs}, open(kh_path, "w"))

    # Use low PBKDF2 iters to keep N derivations fast.
    r = run(["backup-create", "--secret", secret, "--threshold", str(threshold),
             "--keyholders", kh_path, "--shares-out", sh_path,
             "--envelopes-out", env_path, "--force"])
    if r.returncode != 0:
        fail(f"case {case}: backup-create rc={r.returncode} {r.stderr.strip()}")
        continue

    # ---- R1: clean bundle structurally verifies (exit 0) -------------------
    r = run(["backup-verify", "--shares", sh_path, "--envelopes", env_path])
    if r.returncode == 0:
        ok(f"case {case}: clean backup-verify accepts (T={threshold} N={N})")
    else:
        fail(f"case {case}: clean backup-verify rc={r.returncode} (expected 0)")
        continue

    # ---- R1: clean threshold recovery == KNOWN original secret -------------
    got, reason = recover_secret(sh_path, env_path, None, threshold, N)
    if got is None:
        fail(f"case {case}: clean recovery failed ({reason})")
    elif got.lower() == secret.lower():
        ok(f"case {case}: clean recovery == known original")
    else:
        fail(f"case {case}: clean recovery mismatch got={got} want={secret}")

    # ---- R2: byte-level XOR tamper of a random crypto field ----------------
    # Choose a random envelope + a random crypto field, flip one byte.
    sect, sect_name = rng.choice(crypto_fields)
    victim = rng.randint(1, N)
    d = json.load(open(env_path))
    pos = next(k for k, e in enumerate(d["envelopes"]) if e["share_index"] == victim)
    mutated = xor_flip_section(d["envelopes"][pos]["envelope_blob"], sect, rng)
    if mutated is None:
        # Field had no bytes to flip; skip this sub-case cleanly.
        ok(f"case {case}: crypto field '{sect_name}' empty (no-op tamper skipped)")
    else:
        d["envelopes"][pos]["envelope_blob"] = mutated
        env_tamp = os.path.join(tmp, f"env_{case}_crypto.json")
        json.dump(d, open(env_tamp, "w"))

        # backup-verify is structure-only: a byte-flip keeps the blob
        # deserializable, so it STILL accepts (exit 0). This documents the
        # boundary: structural verify catches shape, AEAD catches content.
        r = run(["backup-verify", "--shares", sh_path, "--envelopes", env_tamp])
        if r.returncode == 0:
            ok(f"case {case}: byte-tamper '{sect_name}' still structurally valid")
        else:
            fail(f"case {case}: byte-tamper '{sect_name}' verify rc={r.returncode} "
                 f"(expected structural 0)")

        # The tampered envelope itself must FAIL to decrypt (AEAD tag rejects).
        r = run(["envelope", "decrypt", "--envelope", mutated, "--password",
                 f"kh-pw-{victim}"])
        if r.returncode == 2:
            ok(f"case {case}: AEAD rejects '{sect_name}' tamper (exit 2)")
        else:
            fail(f"case {case}: tampered '{sect_name}' decrypt rc={r.returncode} "
                 f"(expected 2 AEAD failure)")

        # Containment: if threshold < N, recovery from the OTHER untouched
        # shares still reproduces the KNOWN original secret.
        if threshold < N:
            got, reason = recover_secret(sh_path, env_tamp, victim, threshold, N)
            if got is None:
                fail(f"case {case}: degraded recovery failed ({reason})")
            elif got.lower() == secret.lower():
                ok(f"case {case}: recovery from untouched shares == original")
            else:
                fail(f"case {case}: degraded recovery mismatch got={got}")

    # ---- R3: structural tampers -> backup-verify REJECTS (exit 2) ----------
    # (a) flip the 4-byte magic of a random envelope.
    d = json.load(open(env_path))
    vpos = rng.randrange(len(d["envelopes"]))
    flipped = xor_flip_section(d["envelopes"][vpos]["envelope_blob"], MAGIC, rng)
    d["envelopes"][vpos]["envelope_blob"] = flipped
    env_magic = os.path.join(tmp, f"env_{case}_magic.json")
    json.dump(d, open(env_magic, "w"))
    r = run(["backup-verify", "--shares", sh_path, "--envelopes", env_magic])
    if r.returncode == 2:
        ok(f"case {case}: magic-flip rejected by backup-verify (exit 2)")
    else:
        fail(f"case {case}: magic-flip verify rc={r.returncode} (expected 2)")

    # (b) truncate the GCM tag of a random envelope.
    d = json.load(open(env_path))
    vpos = rng.randrange(len(d["envelopes"]))
    d["envelopes"][vpos]["envelope_blob"] = truncate_tag(
        d["envelopes"][vpos]["envelope_blob"])
    env_trunc = os.path.join(tmp, f"env_{case}_trunc.json")
    json.dump(d, open(env_trunc, "w"))
    r = run(["backup-verify", "--shares", sh_path, "--envelopes", env_trunc])
    if r.returncode == 2:
        ok(f"case {case}: tag-truncation rejected by backup-verify (exit 2)")
    else:
        fail(f"case {case}: tag-truncation verify rc={r.returncode} (expected 2)")

# Emit machine-readable result lines for the shell to tally.
for status, msg in results:
    print(f"{status}\t{msg}")
PY_EOF
)
PY_RC=$?

if [ "$PY_RC" != "0" ] && [ -z "$RESULTS" ]; then
    echo "  FAIL: fuzz harness crashed (python rc=$PY_RC, no results)"
    echo "  $pass_count pass / 1 fail"
    echo "  FAIL: determ-wallet backup tamper/round-trip fuzz"
    exit 1
fi

# Map each harness result line onto an assert() so counts are canonical.
while IFS=$'\t' read -r status msg; do
    [ -z "$status" ] && continue
    if [ "$status" = "OK" ]; then
        assert 0 "$msg"
    else
        assert 1 "$msg"
    fi
done <<< "$RESULTS"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ] && [ "$pass_count" -gt 0 ]; then
    echo "  PASS: determ-wallet backup tamper/round-trip fuzz"
    exit 0
else
    echo "  FAIL: determ-wallet backup tamper/round-trip fuzz"
    exit 1
fi
