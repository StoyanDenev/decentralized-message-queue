# `src/crypto/mldsa/` — ML-DSA (Dilithium, NIST FIPS 204)

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16. Status: **increment 1 of the owner-authorized on-chain post-quantum
SIGNATURE track** — the ring arithmetic core (modular reduction + the negacyclic
NTT) that every ML-DSA parameter set is built on. Public domain, C99, two
translation units plus a machine-generated constants file. Headers under
`include/determ/crypto/mldsa/`.

## 1. What this module implements (and what it does NOT, yet)

ML-DSA (the standardized form of CRYSTALS-Dilithium, FIPS 204) is a lattice
signature whose every polynomial operation happens in the ring
**R_q = Z_q[X]/(X²⁵⁶ + 1)** with **q = 2²³ − 2¹³ + 1 = 8380417**. This module
ships that ring's arithmetic foundation:

| File | Contents |
|---|---|
| `include/determ/crypto/mldsa/params.h` | Parameter-set-independent constants: `N=256`, `Q=8380417`, `QINV`, `MONT`, `D`. |
| `reduce.c` (`reduce.h`) | `determ_mldsa_montgomery_reduce` (a·2⁻³² mod q), `determ_mldsa_reduce32` (Barrett), `determ_mldsa_caddq` (conditional +q). |
| `ntt.c` (`ntt.h`) | `determ_mldsa_ntt` (forward negacyclic NTT) and `determ_mldsa_invntt_tomont` (inverse, to the Montgomery domain), over the 256 twiddle factors in `zetas.inc`. |
| `zetas.inc` | **Machine-generated** table `zetas[i] = 2³² · ζ^{brv8(i)} mod q` (centered), ζ = 1753. Regenerated + verified by `tools/verify_mldsa_vectors.py`; never hand-edited. |

The NTT diagonalizes ring multiplication: a length-256 negacyclic convolution
(the ring product) becomes 256 independent coefficient multiplications in the
NTT domain — the O(n log n) multiply ML-DSA leans on throughout keygen/sign/verify.

**Built on SHAKE.** ML-DSA expands its public matrix **Â** from a seed with
**SHAKE128** and samples secrets/masks + hashes the message with **SHAKE256** —
the `src/crypto/sha3/` XOF shipped in CRYPTO-C99-SPEC §3.17. This increment does
not yet call SHAKE; it lays the arithmetic the sampler will feed.

**Scope (increment 1).** The ring's reduction + NTT ONLY. **Not yet here:**
coefficient packing/unpacking, power-of-two and decompose/hint rounding, rejection
sampling (`SampleInBall`, `RejNTTPoly`, `RejBoundedPoly`), the matrix/vector layer,
and the keygen/sign/verify top level — nor the three parameter sets (ML-DSA-44/65/87).
Those are later increments. **There is no signing capability in this module and no
in-tree consumer**; it is purely additive.

## 2. Provenance + construction

- **Construction:** the canonical Dilithium reference arithmetic (Cooley-Tukey
  forward NTT, Gentleman-Sande inverse) written for Determ. The 256 twiddle
  factors are **derived** (not copied) from the primitive 512-th root of unity
  ζ = 1753 by `tools/verify_mldsa_vectors.py` and emitted to `zetas.inc`; the
  reduction constants (`QINV = 58728449 = q⁻¹ mod 2³²`, `MONT = −4186625 = 2³²
  mod q`, the inverse-NTT final scale `f = 41978 = 2⁶⁴/256 mod q`) are all
  recomputed and asserted in that generator and in the `test-mldsa-c99` gate. No
  code vendored from the reference; the modulus/root/constants are the public
  FIPS 204 parameters.
- **License posture:** public domain (Determ-original implementation of the
  public-domain Dilithium construction), per the CRYPTO-C99-SPEC §2 Q3 table.
- **Version pin:** NIST FIPS 204 (ML-DSA), August 2024. Ring degree 256,
  q = 8380417, ζ = 1753.

## 3. Validation evidence

Correctness is pinned WITHOUT trusting any single implementation — the NTT is
constrained by two self-consistent algebraic identities plus a fixed KAT, and
separately by a byte-exact file corpus recomputed by an independent reference:

1. **`determ test-mldsa-c99`** (wrapper `tools/test_mldsa_c99.sh`, FAST-eligible):
   (a) the reduction contract (`reduce32` residue + centered bound, `caddq`
   range, `montgomery_reduce` = a·2⁻³²) over a swept grid; (b) NTT round-trip
   `invntt_tomont(ntt(a)) ≡ a·2³² (mod q)`; (c) NTT-domain product ==
   from-scratch **O(n²) schoolbook negacyclic convolution** — the decisive gate,
   since a single wrong/misordered twiddle factor breaks the convolution while
   leaving the transform self-invertible; (d) the KAT `ntt(1) == all-ones` (the
   NTT of the constant polynomial evaluates to 1 at every root).
2. **`tools/vectors/mldsa_ntt.json`** wired into BOTH §3.13 halves:
   `determ test-c99-vectors` recomputes each vector through the shipped `ntt.c`
   and matches the **exact int32 forward-NTT output** (byte-exact interop) and
   the standard-domain ring product; `tools/test_c99_vector_files.sh` recomputes
   through the independent from-scratch Python reference (`verify_mldsa_vectors.py`),
   which additionally cross-checks every `product` vector against schoolbook.
   A bug in `ntt.c` — not just a corrupted vector — turns the corpus RED.

**What is NOT yet proven:** FIPS 204 *signature-level* byte interop (there is no
signer yet). The exact-int32 NTT KAT does pin the transform against the reference
layout, but end-to-end ACVP/FIPS 204 known-answer signature tests arrive with the
keygen/sign/verify increment.

## 4. Constant-time / hygiene posture

- **Data-independent by construction.** The NTT butterflies and the reduction
  functions have no secret-dependent branch, loop bound, or memory index — every
  control-flow decision is on public indices (block length, position). `caddq`
  and `montgomery_reduce` use the sign bit via arithmetic shift, not a branch.
  This is why the NTT is the standard constant-time multiply for lattice schemes.
- **Signed-shift discipline (the repo's UBSan gate).** `montgomery_reduce` does
  its low-word multiply UNSIGNED (`(uint32_t)a * (uint32_t)QINV`) to avoid
  signed-overflow UB; the subsequent arithmetic right shifts of a possibly-
  negative `int64`/`int32` (`caddq`, the reduction `>> 32`/`>> 23`) are
  implementation-defined-but-not-UB and match the reference on every target
  Determ builds for. Coefficient growth in the forward NTT is bounded (< 9q ≈
  2²⁶ < 2³¹), so the un-reduced additive butterflies never overflow `int32`.
- **No key material yet.** This layer holds no secrets; zeroization/`ct` compares
  belong to the later sampling/signing increment.

## 5. Known limitations / future work

- **Later PQ increments (owner-authorized):** packing/rounding, rejection
  sampling (on the SHAKE XOF), the matrix/vector layer, then keygen/sign/verify +
  the three parameter sets, gated by FIPS 204 / ACVP KATs — and only then the
  chain-integration + anon-address-format reopening, each separately reviewed.
- **Scalar reference NTT.** No AVX2 / vectorized path; correctness and
  constant-time posture are the gates, throughput tuning is later (same posture
  as the AES S-box and the SHA-3 permutation).
