# `src/crypto/p256/` — NIST P-256 (secp256r1)

CRYPTO-C99-SPEC.md §3.8c. The FIPS-profile curve: per spec §2 Q10 the
`tactical` + `cluster` profiles bundle FIPS-validated cryptography, and
secp256k1 is not on NIST's curve list — P-256 supplants it in those
deployments. The downstream consumer is OPRF-P256 (§3.9b); ECDH-style scalar
multiplication is the surface shipped here.

## What this module implements

`p256.c` / `include/determ/crypto/p256/p256.h`:

- `determ_p256_base_mul(out65, scalar_be32)` — `[k]G`, SEC1 uncompressed
  (`0x04 || X || Y`, big-endian). `-1` on an invalid scalar (zero or `>= n`).
- `determ_p256_point_mul(out65, scalar_be32, point65)` — `[k]P` for an
  attacker-supplied point (the ECDH core; the shared secret is `out[1..32]`,
  the X coordinate). `-1` on invalid scalar, failed point decode (bad prefix,
  coordinate `>= p`, off-curve), or a point-at-infinity result.
- `determ_p256_point_check(point65)` — `0` iff a well-formed on-curve SEC1
  uncompressed encoding.
- `determ_p256_params(...)` — exports p/n/b/Gx/Gy (big-endian) for the test
  gate below.

Wire convention: big-endian scalars and coordinates (the SEC1/X9.62 family
convention) — deliberately unlike the little-endian curve25519 modules.

## Provenance + construction

From-scratch C99 per published method — NO vendored third-party code (same
posture as the §3.2 gf[16] Ed25519):

- **Field:** 8×32-bit limbs, Montgomery multiplication (CIOS). `p ≡ −1 (mod
  2³²)` makes the Montgomery factor `n0' = 1`, so the reduction multiplier is
  simply the accumulator's low limb. `R² mod p` and the Montgomery forms of
  `b`/`G` are **derived at runtime** (256 modular doublings of
  `R mod p = 2²⁵⁶ − p`) — the only hand-transcribed constants are p/n/b/Gx/Gy
  themselves (canonical source FIPS 186-5 D.2.3), and those are asserted
  byte-equal against OpenSSL's `EC_GROUP` by the validating test *before any
  arithmetic is trusted*.
- **Points:** Renes–Costello–Batina complete addition formulas for `a = −3`
  short-Weierstrass curves (EUROCRYPT 2016, algorithm 4), projective
  (X:Y:Z) — exception-free: one formula handles `P+Q`, `P+P`, and `P+O`.
- **Scalar mult:** double-and-add-always over the complete formulas with a
  branchless conditional swap per bit.

License posture: Determ-original (from the published method), ~330 LOC.

## Validation evidence

`determ test-p256-c99` (`tools/test_p256_c99.sh`), 6 assertions with
load-bearing ORDER:

1. Curve constants p/n/b/Gx/Gy byte-equal OpenSSL `EC_GROUP` + `a == −3 mod
   p` — the gate that converts the in-source constants from "transcribed"
   into "mechanically verified".
2. `[k]G` byte-equal vs OpenSSL `EC_POINT_mul` over a 12-scalar grid
   including `k = 1, 2` (the §Q9 cross-validation gate).
3. ECDH: `[a]([b]G) == [b]([a]G)`, byte-equal vs OpenSSL.
4. Scalar-mult commutativity on a non-generator base point.
5. Reject paths: off-curve / bad-prefix / coordinate `>= p` all rejected by
   `point_check` AND refused by `point_mul`.
6. Scalar gates: `0` and `n` rejected; `[n−1]G == −G` (same X as G;
   `Y + Gy == p` verified by byte arithmetic).

Vector-gate coverage (§3.13 both halves): `tools/vectors/p256.json` — 11
vectors (6 keygen, 3 ECDH triples with both-direction equality, 2
off-curve negatives), generated and verified via `cryptography.hazmat`
under the no-fabrication rule with the curve parameters *recovered from the
library itself* (no memory constants on the generation side either);
file-side recompute in `tools/test_c99_vector_files.sh`, binary-side
consumption in `determ test-c99-vectors`.

## Constant-time / hygiene posture

No secret-dependent branch or index: the ladder is uniform
double-and-add-always with mask-select cswap; field add/sub/mul use
branchless carry/borrow masks; inversion iterates the PUBLIC constant
exponent `p − 2`. Branches exist only on public data (encoding validity,
scalar-range outcomes, the one-time init flag). Ladder temporaries are
scrubbed via `determ_secure_zero`. Timing-probe coverage: tranche 3 registers
`p256-base-mul` (secret = scalar), `p256-h2c` (secret = msg) and `p256-sc-mul`
(secret = both operands) with `determ ct-timing-probe` — first measured runs
clean (max |t| < 1.5 at smoke sample sizes). ConstantTimeInventory.md gains
its per-mechanism rows when the §3.12 sweep next runs.

## §3.9b groundwork (same module)

Shipped on top of the base: mod-n scalar arithmetic (Montgomery with
runtime-derived `n0'` via Newton iteration + `R²` via modular doublings;
`determ_p256_scalar_mul_mod_n` / `_inv_mod_n`) and the RFC 9380 hash-to-curve
suite `P256_XMD:SHA-256_SSWU_RO_` (`determ_p256_expand_message_xmd` +
`determ_p256_hash_to_curve`; simplified SSWU, Z = −10, branchless throughout —
an OPRF input behind `u` may be a user secret). Validated by `determ
test-p256-h2c-c99` (OpenSSL BIGNUM oracle for mod-n; structural h2c gates) and
byte-exactly by both §3.13 gate halves against `tools/vectors/p256_h2c.json` —
15 genuine RFC 9380 appendix vectors (K.1 + J.1.1) fetched from rfc-editor.org
and re-verified by two independent python implementations before import.

## Known limitations / future work

- The voprf PROTOCOL layer (blind/evaluate/unblind flow, DLEQ proofs) is the
  remaining §3.9b work; the cryptographic groundwork above is complete.
- ECDSA-P256 sign/verify is NOT implemented — out of the §3.8c seed's scope
  (ECDSA lands only if a FIPS-profile signing consumer appears).
- No compressed-point (0x02/0x03) decode — SEC1 uncompressed only.
- Performance: the portable 32-bit-limb Montgomery field favors auditability
  over throughput (same trade as the gf[16] Ed25519); a 64-bit-limb variant
  is a future perf option.
- ConstantTimeInventory.md does not carry this module's per-mechanism rows
  yet (probe targets registered in tranche 3; the inventory sweep is the
  remaining §3.12 follow-up).
