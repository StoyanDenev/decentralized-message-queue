# `src/crypto/mldsa/` — ML-DSA (Dilithium, NIST FIPS 204)

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16. Status: **increments 1-5 of the owner-authorized on-chain post-quantum
SIGNATURE track** — the ring arithmetic core (modular reduction + the negacyclic
NTT), the coefficient rounding / hint layer, the SHAKE rejection samplers (the
first consumers of the SHA-3 XOF), the coefficient bit-packing, and the
per-polynomial ring operations, all shared by every ML-DSA parameter set.
Public domain, C99, six translation units plus a machine-generated constants
file. Headers under `include/determ/crypto/mldsa/`.

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
| `rounding.c` (`rounding.h`) | `determ_mldsa_power2round` (t = t1·2^D + t0, the keygen public-key split), `determ_mldsa_decompose` (HighBits/LowBits around the GAMMA2 grid), `determ_mldsa_make_hint` / `determ_mldsa_use_hint` (the signature's per-coefficient carry hint). gamma2 is a runtime arg (GAMMA2_88 / GAMMA2_32). |
| `sample.c` (`sample.h`) | The SHAKE samplers — the FIRST consumers of `src/crypto/sha3/`: `determ_mldsa_sample_uniform` (RejNTTPoly, SHAKE128 → [0,q), the public matrix Â), `determ_mldsa_sample_eta` (RejBoundedPoly, SHAKE256 → [-η,η], the secrets; η∈{2,4} runtime), `determ_mldsa_sample_in_ball` (SHAKE256 → the challenge, exactly τ signed 1s; τ runtime), and `determ_mldsa_sample_gamma1` (ExpandMask, SHAKE256 → a FIXED squeeze unpacked into (-γ1,γ1]; γ1∈{2¹⁷,2¹⁹} runtime; **no rejection → constant-time**, inc.5). |
| `pack.c` (`pack.h`) | Coefficient bit-packing: the generic LSB-first `pack_bits`/`unpack_bits` plus the FIPS 204 field encoders t1 (10-bit), t0 (13-bit), s1/s2 (η-bit), w1 (γ2-bit), z (γ1-bit) — the polynomial ↔ byte codec keygen/sign/verify serialize with. |
| `poly.c` (`poly.h`) | Per-polynomial ring operations (inc.5) the top level composes over the NTT + samplers: `determ_mldsa_poly_add`/`_sub` (e.g. A·s1 + s2), `determ_mldsa_poly_reduce`/`_caddq` (coefficients back into range / to [0,q)), `determ_mldsa_poly_pointwise_montgomery` (the per-poly step of a matrix·vector product in the NTT domain). |

The NTT diagonalizes ring multiplication: a length-256 negacyclic convolution
(the ring product) becomes 256 independent coefficient multiplications in the
NTT domain — the O(n log n) multiply ML-DSA leans on throughout keygen/sign/verify.
The rounding layer is what keygen (power2round on **t**) and sign/verify
(decompose + hints on **w**) sit on top of that ring arithmetic.

**Built on SHAKE.** ML-DSA expands its public matrix **Â** from a seed with
**SHAKE128** and samples secrets/masks + hashes the message with **SHAKE256** —
the `src/crypto/sha3/` XOF shipped in CRYPTO-C99-SPEC §3.17. Increment 3 (`sample.c`)
is the first code to actually call SHAKE, turning a seed into ring elements; the
increment-5 `sample_gamma1` (ExpandMask) is the mask sampler sign uses per round.

**Scope (increments 1-5).** The ring's reduction + NTT, the coefficient rounding
/ hint layer, the SHAKE samplers (uniform/eta/in-ball + the gamma1 mask), the
coefficient bit-packing (`pack.c`), and the per-polynomial ring operations
(`poly.c`: add/sub/reduce/caddq + pointwise-Montgomery multiply). **Not yet here:**
the matrix/vector layer (ExpandA/ExpandS build the domain-separated seeds and
iterate these samplers over the k×l poly vectors), and the keygen/sign/verify top
level — nor the three parameter sets (ML-DSA-44/65/87). Those are later increments.
**There is no signing capability in this module and no in-tree consumer**; it is
purely additive.

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
   leaving the transform self-invertible; (d) an **independent direct-DFT oracle**
   `ntt(X)[j] == root^(2·brv8(j)+1)` — a closed-form root evaluation that reuses
   neither the zetas table nor the butterfly, so a *symmetric* zeta-ordering bug
   (which the round-trip AND the convolution are both blind to, being invariant
   under a consistent permutation of the NTT domain) cannot survive; (e) the
   rounding-layer contracts — power2round / decompose reconstruction + bounds, the
   `use_hint` semantic round-trip `use_hint(r, [HB(r)≠HB(r+z)]) == HB(r+z)` for
   |z| ≤ γ2, `make_hint`'s definitional formula, and boundary KATs at the
   decomposition seams — over both γ2 values.
2. **`tools/vectors/mldsa_ntt.json`** wired into BOTH §3.13 halves:
   `determ test-c99-vectors` recomputes each vector through the shipped `ntt.c`
   and matches the **exact int32 forward-NTT output** (byte-exact interop) and
   the standard-domain ring product; `tools/test_c99_vector_files.sh` recomputes
   through the independent from-scratch Python reference (`verify_mldsa_vectors.py`),
   which cross-checks every `ntt` vector against the **independent direct-DFT
   oracle** and every `product` vector against schoolbook. A bug in `ntt.c` — not
   just a corrupted vector — turns the corpus RED.

**Why the direct-DFT oracle matters (an adversarial-audit finding).** The
round-trip and the schoolbook-convolution checks are BOTH invariant under a
consistent permutation of the NTT domain — a symmetric bug in the zetas
derivation/ordering permutes both operands, and the shared (equally-permuted)
inverse undoes it, so a *wrong-but-self-consistent* forward transform passes them
and even yields correct ring products. Only the direct-DFT oracle, whose expected
values come from root exponentiation rather than the transform under test, pins
the exact forward-NTT output ordering that byte-exact interop needs.

3. **The SHAKE samplers** — `determ test-mldsa-c99` structural gates (uniform in
   [0,q); eta in [-η,η]; in-ball exactly τ signed 1s with ‖c‖²==τ; gamma1 in
   (-γ1,γ1] + fail-safe-zero on unsupported γ1; all deterministic), plus
   `tools/vectors/mldsa_sample.json` (generated + reproduced by
   `tools/verify_mldsa_sample.py`) wired into both §3.13 halves. The SHAKE STREAM
   is cross-checked against python `hashlib.shake_128/256` — a SHAKE **distinct
   from the C `determ_shake`** (proven byte-equal + vs OpenSSL in R62). The
   value-mapping RULE is shared (both encode the FIPS 204 algorithm), so — an
   **R65-audit hardening** — the mapping is ALSO cross-checked by an INDEPENDENT
   REPRESENTATION: a spec lookup TABLE for the eta / in-ball-sign convention (data,
   not the arithmetic formula), stdlib `int.from_bytes` for the uniform 23-bit
   read, and a **bit-slice field read by absolute offset** for the gamma1 mask
   (distinct from the word-at-a-time unpacker). A shared formula bug (e.g. an eta
   sign-flip that stays in range) that the byte-equal KAT + structural gates would
   miss is caught by these. `sample_in_ball` fail-safes on out-of-contract τ (and
   `sample_eta` on unsupported η, `sample_gamma1` on unsupported γ1) — the
   untrusted vector-file path validates them too.
4. **The bit-packing** — `determ test-mldsa-c99` checks pack↔unpack round-trip AND
   an **independent bit-slice oracle** (each field re-read by absolute bit offset,
   a code path distinct from the unpacker, so a symmetric pack/unpack permutation
   cannot pass); `tools/vectors/mldsa_pack.json` (via `tools/verify_mldsa_pack.py`)
   is wired into both §3.13 halves, with `t1` byte-checked against the canonical
   reference `pack_t1` formula. **R66-audit fix:** the `mldsa_pack` vector-file
   handler now derives the comparison length from the vector's `kind` (the encoder's
   fixed output size), never from the untrusted JSON `bits` field — a crafted `bits`
   could otherwise size the compare loop past the fixed output buffer (an
   out-of-bounds read on the modeled untrusted-input surface).
5. **The per-poly ring ops** — `determ test-mldsa-c99` checks add/sub exact
   element-wise, reduce/caddq residue-preserving within their documented bounds, and
   `poly_pointwise_montgomery` driven through the SAME independent O(n²)
   schoolbook-negacyclic oracle as the arithmetic core: `invntt(pw(ntt a, ntt b)) ==
   schoolbook a·b (mod q)`. A wrong pointwise wrapper cannot pass, since the expected
   product comes from the from-scratch convolution, not the transform under test.

**What is NOT yet proven:** FIPS 204 *signature-level* byte interop (there is no
signer yet). The NTT KAT + direct-DFT oracle pin the transform; the samplers +
packing are cross-checked against independent representations of both the SHAKE
stream and the value mapping — but the AUTHORITATIVE end-to-end pin of the sampler
/ pack value mappings arrives with the FIPS 204 keygen/sign ACVP KATs at the
signing increment.

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
  `reduce32` does its rounding bias-add in `int64` (`((int64_t)a + (1<<22)) >> 23`)
  so it is UB-free for **any** `int32 a`, not just the canonical `a ≤ 2³¹ − 2²²`
  precondition (an adversarial-audit hardening; costs nothing).
- **Samplers are NOT constant-time in the loop count.** `sample_uniform/eta/in_ball`
  have a data-dependent number of SHAKE bytes consumed (the rejection loop), as in
  the canonical Dilithium reference — the coefficient *values* are computed
  branchlessly, but the *timing* depends on the SHAKE stream. For `sample_uniform`
  (public matrix Â from ρ) and `sample_in_ball` (public challenge) the seed is
  public, so this is harmless; `sample_eta` runs on the secret ρ', matching the
  reference's accepted posture (the leak is the reject count, not the secret
  coefficients). The samplers scrub their SHAKE context with `determ_secure_zero`.
- **Bit-packing is data-independent.** `pack_bits`/`unpack_bits` and the field
  encoders have fixed loop bounds and no value-dependent branch or memory index
  (the shift amounts depend only on the public bit width), so serializing a secret
  polynomial does not leak it through timing.
- **No stored key material.** No verify entry point / secret comparison here yet;
  the `ct.h` compares belong to the later signing increment.

## 5. Known limitations / future work

- **Later PQ increments (owner-authorized):** the matrix/vector layer
  (ExpandA/ExpandS/ExpandMask that build the domain-separated seeds and iterate
  these samplers over vectors of polynomials), then keygen/sign/verify +
  the three parameter sets, gated by FIPS 204 / ACVP KATs — and only then the
  chain-integration + anon-address-format reopening, each separately reviewed.
- **Scalar reference NTT.** No AVX2 / vectorized path; correctness and
  constant-time posture are the gates, throughput tuning is later (same posture
  as the AES S-box and the SHA-3 permutation).
