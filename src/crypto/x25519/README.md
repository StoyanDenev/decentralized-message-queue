# `src/crypto/x25519/` — C99 X25519 (RFC 7748)

Per-module provenance + audit README required by CRYPTO-C99-SPEC.md §3.16.
Module status in the spec's §2 Q3 table: **SHIPPED**, public domain, ~140 LOC.
The shipping commit `bc87704` is recorded at spec work unit §3.3 and audit §8c
(and exists in git history under that hash).

## 1. What this module implements

Curve25519 Diffie-Hellman (X25519, RFC 7748) — the key-exchange companion to the
C99 Ed25519 signature primitive. One translation unit, two entry points
(`include/determ/crypto/x25519/x25519.h`):

- `int determ_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])`
  — scalar multiplication `out = X25519(scalar, point)`. The scalar is clamped
  internally per RFC 7748 §5 (pass the raw 32-byte secret); `point` is the
  little-endian u-coordinate. Returns 0 on success, **-1 if the result is the
  all-zero low-order point** (RFC 7748 "contributory" check, matching OpenSSL
  `EVP_PKEY_derive` rejecting small-order peer keys).
- `int determ_x25519_base(uint8_t out[32], const uint8_t scalar[32])`
  — public key = `X25519(scalar, 9)`. Always returns 0 (a clamped scalar times
  the base point is never low-order).

Additive as of this writing: **no daemon call site consumes X25519 yet**. It
completes the curve25519 family for the future libsodium-free DH consumers named
in the spec's §2 Q1 tables (gossip handshake KX, v2.22 amount DH handshake).

## 2. Provenance + construction

- **TweetNaCl-derived** (public domain, Bernstein et al.) — the canonical
  TweetNaCl `crypto_scalarmult` Montgomery cswap-ladder over the Curve25519
  field, p = 2^255-19, in the radix-2^16 `gf[16]` representation (`i64` limbs:
  `car25519` / `sel25519` / `pack25519` / `unpack25519` / `fadd` / `fsub` /
  `fmul` / `fsqr` / `inv25519`, plus the `_121665` ladder constant).
- **Same field lineage as `src/crypto/ed25519/ed25519.c`.** Deliberately NOT
  curve25519-donna (the candidate the spec's §2 Q1 decision table and §4 effort
  table originally named):
  CRYPTO-C99-SPEC §3.3 records the choice of one auditable `gf[16]` field
  implementation across the whole curve25519 family. The Ed25519 sibling's
  field/scalar arithmetic was differential-tested vs exact GMP in the §6 audit
  (C99CryptoStackAudit.md), and this module inherits that assurance; the
  DH-specific surface is only the ladder + RFC 7748 §5 clamp + final Fermat
  inversion.
- **License posture: public domain** (spec §2 Q3 module table), consistent with
  the TweetNaCl upstream. No libsodium linkage.

## 3. Validation evidence

- **`determ test-x25519-c99`** (dispatch block in `src/main.cpp`; wrapper
  `tools/test_x25519_c99.sh`) — 8 assertions in three groups:
  1. **OpenSSL cross-validation (the spec §Q9 gate), assertions 1-3:** byte-equal
     vs OpenSSL `EVP_PKEY_X25519` over a 64-scalar fuzzed grid — public-key
     derivation (`EVP_PKEY_get_raw_public_key`), ECDH (`EVP_PKEY_derive`), and
     DH symmetry `X25519(a,[b]B) == X25519(b,[a]B)`. Any single-bit deviation in
     clamping, ladder, or inversion fails.
  2. **RFC 7748 §6.1 KAT, assertions 4-7:** the canonical Alice/Bob vectors —
     both public keys, the published shared secret, and both-parties-agree. This
     is the OpenSSL-independent anchor.
  3. **Contributory check, assertion 8:** `X25519(scalar, all-zero u)` returns -1.
- **libsodium byte-equality (standing harness):** `tools/test_c99_libsodium_xval.sh`
  compiles `tools/c99_libsodium_xval.c` against the build tree's `libsodium.a`
  and asserts `determ_x25519_base` / `determ_x25519` byte-equal
  `crypto_scalarmult_base` / `crypto_scalarmult` over 64 keypairs + DH symmetry
  (CRYPTO-C99-SPEC §Q9 step 3 evidence).
- **Adversarial audit:** C99CryptoStackAudit.md §8c — the four-dimension
  workflow produced **1 confirmed finding, X25519-MEM-001 (High)**: the
  `inv25519` Fermat-exponentiation scratch was left unwiped. Remediated with
  `determ_secure_zero(c, sizeof c)` after the result copy (the auditor's
  suggested placement was *before* the copy, which would have zeroed the
  inverse — verified and corrected). Audit complete; no other confirmed findings.

## 4. Constant-time / hygiene posture

- **Montgomery cswap-ladder, constant trip count:** the ladder runs all 255
  steps (`i = 254 .. 0`); each step's swap is the `sel25519` arithmetic-masked
  conditional swap driven by the secret scalar bit. No secret-dependent branch
  and no secret-dependent memory index anywhere in the module — no cache-timing
  channel.
- **Branchless everywhere a secret could flow:** `pack25519`'s final reduction
  uses `sel25519` (not a branch); `inv25519` raises to the *public* fixed
  exponent p-2 (its loop-counter `if` is on public data); the contributory
  check is a branchless aggregate-OR over the output bytes
  (`allzero |= out[k]`), the house compare discipline of audit §4.
- **`determ_secure_zero`** (`include/determ/crypto/secure_zero.h`) scrubs, before
  return: the clamped scalar copy `z`, the ladder state `x[80]`, all six `gf`
  temporaries `a..f`, and the `inv25519` exponentiation scratch
  (X25519-MEM-001 remediation).
- **`determ_ct_memcmp`** (`include/determ/crypto/ct.h`, CRYPTO-C99-SPEC §3.10):
  this module has **no call sites** — X25519 performs no equality-vs-expected
  comparison on secret material (DH output is returned, not compared). Any
  future compare of a derived shared secret belongs in the consumer and must
  route through `determ_ct_memcmp`, like the AEAD tag and Ed25519/FROST point
  compares do.

## 5. Known limitations / future work

- **No call site yet** — additive primitive; wiring into the gossip handshake /
  v2.22 amount DH handshake is the tracked consumer work (spec §2 Q1 tables).
- **Performance:** the spec's module table records a `ref10` radix-2^51 field as
  a future perf variant for this `gf[16]` lineage (noted on the Ed25519 row).
  Because the field is shared, any such swap applies to both curve25519-family
  modules together — preserving the single-auditable-field decision of §3.3.
- **Empirical CT verification** (dudect/ctgrind, spec §3.12) is planned
  stack-wide but not yet integrated; the constant-time claims above are by
  construction + audit review, not yet instrumented measurement.
