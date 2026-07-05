# MLDSAConformance — ML-DSA (Dilithium, FIPS 204) conformance + soundness accounting

This document is the "what is proven vs. what is asserted-in-prose" honest accounting for the **complete C99-native ML-DSA signature scheme** — KeyGen + Sign + Verify — shipped in `src/crypto/mldsa/` (`keygen.c`, `sign.c`, `poly.c`, `polyvec.c`, plus the arithmetic core `reduce.c`/`ntt.c`/`rounding.c`/`sample.c`/`pack.c` and their headers under `include/determ/crypto/mldsa/`). It answers two questions the individual test outputs do not answer on their own: (1) **what** each top-level operation is, mapped onto ML-DSA-44/65/87 and the FIPS 204 algorithms, verified against the source; and (2) **how much** the validation legs — the ACVP byte gate (both §3.13 halves over the `tools/vectors/mldsa_*.json` corpus) and the structural/round-trip test (`determ test-mldsa-c99`) plus the C++ wrapper round-trip (`test-c99-api` assertion (13)) — jointly establish, and where their reach stops.

## Scope

**In scope — the pure external + internal interface.** The three operations `determ_mldsa_keygen` (Algorithm 6, KeyGen_internal), `determ_mldsa_sign` (Algorithm 7, Sign_internal), and `determ_mldsa_verify` (Algorithm 8, Verify_internal), for all three parameter sets ML-DSA-44/65/87. The **deterministic** signing variant (32-byte all-zero `rnd`, the FIPS 204 / ACVP sigGen "deterministic" mode) is the byte-pinned one; the **hedged** variant (caller-supplied random `rnd`) is the same code path with a different `rnd` input. The **pure external interface** is covered via `determ_mldsa_format_message` producing `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`; the raw internal interface (a caller-supplied `M'`) is what all three operations actually consume.

**Out of scope.** The prehash **HashML-DSA** variants (ctx + hash-OID prefix over a message digest); the **externalMu** ACVP interface (pre-hashed `mu`); and **chain integration** — ML-DSA is not yet a Determ consensus/wallet primitive. It is an additive **library primitive** with no in-tree consumer. None of these out-of-scope items affects the KAT conformance of the covered sign/verify path.

**Authoritative external standard + oracle.** NIST **FIPS 204** (ML-DSA), August 2024 (ring degree n=256, q=8380417, ζ=1753). The external correctness oracle is the **NIST ACVP** corpus (`usnistgov/ACVP-Server` `ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json`): frozen NIST bytes, matched by two independent implementations (the shipped C and a from-scratch Python).

Companion / trust-base documents: `src/crypto/mldsa/README.md` (module provenance + per-increment validation narrative); `CRYPTO-C99-SPEC.md` §3.18 (the ML-DSA design entry), §3.17 (the SHAKE XOF this scheme is built on), §3.13 (the two-half vector gate mechanics this document instantiates). SHAKE128/256 correctness is discharged there (proven byte-equal to OpenSSL/hashlib in R62), not here.

---

## 1. The construction map

Parameter sets, verified against `keygen.c:20-25` and `include/determ/crypto/mldsa/keygen.h:30-42` (`{k, l, eta, tau, gamma1, gamma2, omega, lambda}`; β = τ·η is derived):

| Set | k | l | η | τ | γ1 | γ2 | ω | λ | pk / sk / sig bytes |
|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 4 | 4 | 2 | 39 | 2¹⁷ | (q−1)/88 | 80 | 128 | 1312 / 2560 / 2420 |
| ML-DSA-65 | 6 | 5 | 4 | 49 | 2¹⁹ | (q−1)/32 | 55 | 192 | 1952 / 4032 / 3309 |
| ML-DSA-87 | 8 | 7 | 2 | 60 | 2¹⁹ | (q−1)/32 | 75 | 256 | 2592 / 4896 / 4627 |

The byte sizes are computed by `determ_mldsa_pk_bytes`/`_sk_bytes` (`keygen.c:30-39`) and `determ_mldsa_sig_bytes` (`sign.c:27-31`); assertion (16) pins the pk/sk sizes and (17)/(18) exercise the sig sizes.

Operation → FIPS 204 algorithm map, each verified against the source:

| Operation | C function | Construction (verified) | Source |
|---|---|---|---|
| **KeyGen_internal** (Alg 6) | `determ_mldsa_keygen` | `(ρ,ρ',K) = H(ξ‖k‖l, 128)`; `Â = ExpandA(ρ)`; `(s1,s2) = ExpandS(ρ')`; `t = invNTT(Â∘NTT(s1)) + s2`; `(t1,t0) = Power2Round(t)`; `pk = pkEncode(ρ,t1)`; `tr = H(pk,64)`; `sk = skEncode(ρ,K,tr,s1,s2,t0)` | `keygen.c:41-109` |
| **Sign_internal** (Alg 7) | `determ_mldsa_sign` | skDecode; `mu = H(tr‖M',64)`; `ρ'' = H(K‖rnd‖mu,64)`; Fiat-Shamir-with-aborts loop: `y = ExpandMask(ρ'',κ)`, `w = invNTT(Â∘NTT(y))`, `w1 = HighBits(w)`, `c̃ = H(mu‖w1Encode,λ/4)`, `c = SampleInBall(c̃)`, `z = y + c·s1`, `r0 = LowBits(w − c·s2)`; reject on ‖z‖∞ ≥ γ1−β, ‖r0‖∞ ≥ γ2−β, ‖c·t0‖∞ ≥ γ2, #hints > ω; then `sigEncode(c̃, z mod±q, h)` with `MakeHint`/HintBitPack | `sign.c:75-189` |
| **Verify_internal** (Alg 8) | `determ_mldsa_verify` | length check; pkDecode + sigDecode (HintBitUnpack with its 3 rejections); reject ‖z‖∞ ≥ γ1−β; `mu = H(H(pk,64)‖M',64)`; `c = SampleInBall(c̃)`; `w'Approx = invNTT(Â∘NTT(z) − ĉ∘NTT(t1·2^d))`; `w1' = UseHint(h, w'Approx)`; accept iff `c̃ == H(mu‖w1Encode(w1'),λ/4)` | `sign.c:191-269` |
| **format_message** (M' assembly) | `determ_mldsa_format_message` | `M' = 0x00 ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ M`; returns 0 if `ctxlen > 255` | `sign.c:52-60` |

**Determinism note.** Both keygen and (deterministic-variant) sign are deterministic in their inputs (`seed`/`ξ` for keygen; `(sk, M', rnd)` for sign). The all-zero `rnd` gives the FIPS 204 deterministic variant the ACVP sigGen KATs fix, making the signature byte-reproducible; a caller supplying a random `rnd` gets the hedged variant along the same path.

---

## 2. Conformance / soundness claims (MC-1 .. MC-13)

Each claim states the claim, the **evidence** (which test assertion / ACVP vector file / oracle proves it), and honest caveats.

### MC-1 — KeyGen reproduces the NIST ACVP KeyGen KATs byte-for-byte

**Claim.** For each ACVP KeyGen vector (seed ξ → pk/sk), the shipped `determ_mldsa_keygen` produces the encoded pk and sk **byte-for-byte** equal to the frozen NIST bytes, for all three parameter sets.

**Evidence.** `tools/vectors/mldsa_keygen.json` (3 vectors: the first AFT case of each parameter set from `ML-DSA-keyGen-FIPS204/internalProjection.json`), wired into **both** §3.13 halves. C half: `determ test-c99-vectors` runs the C keygen on the ACVP seed and asserts `gpk == wpk` and `gsk == wsk` byte-for-byte (`main.cpp:14091-14110`). Python half: `tools/test_c99_vector_files.sh` → `chk_mldsa_keygen` recomputes through the independent `tools/verify_mldsa_keygen.py` (hashlib SHAKE + a from-scratch Python NTT, `ZS = [pow(1753, brv8(k), q)]`) and matches the same frozen bytes. Because the expected pk/sk are the real NIST values, a bug shared by C and Python is still caught. `test-mldsa-c99` adds the fast structural gate (16) (pk/sk sizes for all 3 sets, determinism, shared-ρ prefix `pk[0:32]==sk[0:32]`) and a compact SHA-256-pinned ML-DSA-44 KAT (17) against `451a808c…159f6a34` (pk) / `0196ccbd…c9fc32c2` (sk).

**Caveat.** One authoritative external vector per parameter set (the first AFT case), not the full ACVP set. Reproducing the ACVP pk/sk retroactively exercises the whole increment 1–6 stack (NTT, samplers, packing, ring ops, ExpandA/S seed layout) end-to-end — see MC-8..MC-11.

### MC-2 — Sign reproduces the NIST ACVP sigGen signatures byte-for-byte (deterministic variant)

**Claim.** For each ACVP sigGen (deterministic) vector, `determ_mldsa_sign(sk, M', rnd=0³²)` produces the signature **byte-for-byte** equal to the NIST bytes, for all three parameter sets and both the external and internal interface variants.

**Evidence.** `tools/vectors/mldsa_sign.json` (6 vectors: 2 per set — one `iface=external`, one `iface=internal`; `M'` pre-formatted) wired into both §3.13 halves. C half: `determ test-c99-vectors` runs `Sign_internal` with a 32-byte zero `rnd` and asserts `gsig == wsig` byte-for-byte (`main.cpp:14122-14130`). Python half: `chk_mldsa_sign` recomputes through the independent `tools/verify_mldsa_sign.py` (hashlib SHAKE + from-scratch Python NTT). Because the expected signature is the frozen NIST value, a bug shared by C and Python is still caught.

**Caveat.** Deterministic variant only (`rnd=0³²`). The hedged variant is the same code path (`sign.c:94`, `if (rnd == 0) rnd = ZERO32`) but is not byte-pinnable and is exercised only functionally (MC-4). Two vectors per set (external + internal iface).

### MC-3 — Verify reproduces the NIST ACVP sigVer accept/reject flags

**Claim.** For each ACVP sigVer vector, `determ_mldsa_verify` returns the stored `testPassed` flag, across genuine and deliberately-corrupted signatures.

**Evidence.** `tools/vectors/mldsa_verify.json` (15 vectors: 5 per set; each carries `expected` + a `reason`) wired into both §3.13 halves. C half: `determ test-c99-vectors` runs `Verify_internal` and asserts `(got != 0) == expected` (`main.cpp:14131-14136`). Python half: `chk_mldsa_verify` reproduces the flag through `verify_mldsa_sign.py`. The corpus's reject cases exercise the distinct rejection paths named in their `reason`: **modified signature — z** (the ‖z‖∞ < γ1−β bound, `sign.c:234`), **modified signature — hint** (a HintBitUnpack malformation, `sign.c:220-232`), **modified signature — commitment** and **modified message** (the final `c̃ == c̃'` equality, `sign.c:267`). Accept and reject flags are both directly pinned to NIST.

**Caveat.** The `reason` labels come from ACVP; the mapping of each label to the specific in-code rejection is this document's reading of `sign.c`, not a separately-asserted fact. The three HintBitUnpack rejections are additionally unit-checked structurally (MC-6).

### MC-4 — Self-contained keygen → sign → verify round-trip + tamper rejection (all 3 sets)

**Claim.** A freshly generated key round-trips: verify **accepts** a genuine signature; **rejects** a signature with a flipped byte; **rejects** a flipped message; and signing twice yields byte-identical output (determinism), for all three parameter sets.

**Evidence.** `test-mldsa-c99` assertion (18) (`main.cpp:14940-14971`): for each of ML-DSA-44/65/87 it keygens from a fixed seed, formats `M' = format("ctx", "determ ml-dsa sign roundtrip")`, signs with `rnd=0³²`, asserts verify == 1 (accept), asserts a mid-signature bit-flip and a last-message-byte flip both verify == 0 (reject), and asserts a second sign is byte-identical.

**Caveat.** This is functional coverage over one message per set, not an external-oracle check — MC-1..MC-3 are the byte-pinned legs. It does establish end-to-end self-consistency of the shipped C for the hedged/deterministic mechanics that the ACVP legs cover only per-fixed-input.

### MC-5 — Verify is memory-safe on a wrong-length / truncated signature

**Claim.** `determ_mldsa_verify` rejects a signature whose length ≠ `determ_mldsa_sig_bytes(p)` **before any byte of the attacker-controlled `sig` is read**, so every subsequent read (sigDecode + the ω+k-byte HintBitUnpack) is in-bounds.

**Evidence.** Source: `sign.c:210`, `if (siglen != determ_mldsa_sig_bytes(p)) return 0;` guards all reads. Test: `test-mldsa-c99` assertion (18) feeds a truncated σ (`sig.size()-1`) and asserts reject (`main.cpp:14964`); the C++ wrapper (13) and `mldsa_api_selftest` do the same via `bad.pop_back()` (`main.cpp:1409-1410`).

**Caveat.** This is a bounds-safety property (no OOB read), not a claim that every malformed-but-correct-length σ is rejected — that is MC-3's ACVP-pinned reject cases plus MC-6's structural hint checks. The R70 self-audit added this guard; it is a defensive property of `verify`, distinct from KAT conformance.

### MC-6 — The three HintBitUnpack malformed-hint rejections are structurally enforced

**Claim.** `Verify_internal`'s HintBitUnpack (`sign.c:220-232`) rejects (a) a hint end-count that is < the running index or > ω (bad count), (b) non-strictly-increasing hint indices, and (c) a non-zero trailing pad — the three FIPS 204 Alg 21 malformed-hint rejections.

**Evidence.** Source: the three `return 0` sites at `sign.c:224` (count), `:226` (increasing), `:231` (pad). Externally: `mldsa_verify.json`'s "modified signature — hint" reject cases (MC-3) drive at least one of these on ML-DSA-65 and -87.

**Caveat.** The three rejection branches are read from source and covered *collectively* by the ACVP hint-reject vectors; there is no unit test that isolates each of the three branches individually with a hand-crafted σ. The `siglen` guard (MC-5) makes reaching them memory-safe.

### MC-7 — format_message produces the exact M' layout and fails closed on oversized ctx

**Claim.** `determ_mldsa_format_message(out, ctx, ctxlen, msg, mlen)` writes `0x00 ‖ ctxlen ‖ ctx ‖ msg` and returns 0 (no write) when `ctxlen > 255`.

**Evidence.** `test-mldsa-c99` assertion (19) (`main.cpp:14972-14983`): checks `format({0xAA,0xBB}, {1,2,3}) == {0x00,0x02,0xAA,0xBB,0x01,0x02,0x03}` (length 7) and that `ctxlen=256` returns 0. Source: `sign.c:52-60`.

**Caveat.** This pins the pure external interface's message-prefix layout only; it does not exercise the prehash M' variants (out of scope).

### MC-8 — The NTT ring-multiply core is twiddle-exact (four independent checks)

**Claim.** The negacyclic NTT over Z_q[X]/(X²⁵⁶+1) computes the correct forward transform, exact byte-for-byte, so the ring products keygen/sign/verify are built on are correct.

**Evidence.** `test-mldsa-c99` assertions (1)–(4b): (1) the reduction contract (`reduce32` residue + centered bound |t|<6283009, `caddq` range, `montgomery_reduce = a·2⁻³²`) over a swept grid; (2) round-trip `invntt_tomont(ntt(a)) ≡ a·2³² (mod q)`; (3) NTT-domain product == from-scratch **O(n²) schoolbook negacyclic convolution** (the decisive gate — a wrong twiddle breaks it); (4) `ntt(1) == all-ones`; (4b) the **independent direct-DFT oracle** `ntt(X)[j] == 1753^(2·brv8(j)+1) (mod q)`, reusing neither the zetas table nor the butterfly, so a *symmetric* zeta-ordering permutation (invisible to (2) and (3)) cannot survive. File-side: `tools/vectors/mldsa_ntt.json` (7 vectors: 5 `ntt` matched to the exact int32 forward output + 2 `product`) wired into both §3.13 halves, the Python half recomputing through the from-scratch `verify_mldsa_vectors.py` and cross-checking the direct-DFT oracle.

**Caveat.** None material to correctness; the four checks are mutually non-redundant by design (the direct-DFT oracle is the R-audit hardening that closes the symmetric-permutation blind spot).

### MC-9 — The rounding / hint layer satisfies its FIPS 204 contracts

**Claim.** `power2round`, `decompose`, `use_hint`, and `make_hint` satisfy their reconstruction + bound contracts over both γ2 grids.

**Evidence.** `test-mldsa-c99` (5)–(9): (5) `power2round` reconstruction `a1·2^D + a0 == a`, |a0| ≤ 2¹²; (6) `decompose` reconstruction mod q, |a0| ≤ γ2, a1 ∈ [0,m); (7) `use_hint` semantic round-trip `use_hint(r, [HB(r)≠HB(r+z)]) == HB(r+z)` for |z| ≤ γ2; (8) `make_hint` against an **independent** decompose-based oracle over dense seams (R64-audit tautology fix); (9) exact (a0,a1) boundary KATs at the decomposition seams, both γ2.

**Caveat.** Property + boundary-KAT coverage, not an external oracle — but this layer is also transitively pinned by MC-1..MC-3 (keygen's Power2Round, sign/verify's decompose + hints feed the ACVP bytes).

### MC-10 — The SHAKE rejection samplers match the independent hashlib-SHAKE reference

**Claim.** `sample_uniform` (RejNTTPoly → [0,q)), `sample_eta` (RejBoundedPoly → [−η,η]), `sample_in_ball` (τ signed 1s), and `sample_gamma1` (ExpandMask → (−γ1,γ1]) produce the correct coefficients, byte-for-byte against a SHAKE reference independent of the C `determ_shake`.

**Evidence.** `test-mldsa-c99` structural gates (uniform in [0,q); eta in [−η,η]; in-ball exactly τ signed 1s with ‖c‖²==τ; gamma1 in (−γ1,γ1] + an independent absolute-bit-offset field re-read (10) + fail-safe-zero on unsupported γ1). File-side: `tools/vectors/mldsa_sample.json` (17 vectors: 3 uniform, 4 eta, 6 in_ball, 4 gamma1) generated + reproduced by `tools/verify_mldsa_sample.py` over python `hashlib.shake_128/256` (distinct from the C SHAKE), wired into both §3.13 halves, with the value-mapping additionally cross-checked by an independent representation (spec lookup table for eta/in-ball sign, `int.from_bytes` for the 23-bit uniform read, absolute-offset bit-slice for the gamma1 mask).

**Caveat.** `sample_gamma1` (ExpandMask) is rejection-free → constant-time in its byte consumption; the other three are rejection samplers (see NP-1). Fail-safe behaviour on out-of-contract τ/η/γ1 (zero output) is checked, not a silent-wrong path.

### MC-11 — The bit-packing, per-poly ring ops, and matrix/vector layer are pinned

**Claim.** The FIPS 204 field encoders (t1/t0/s-η/w1/z), the per-poly ops (add/sub/reduce/caddq/pointwise-Montgomery), and the matrix/vector layer (ExpandA/ExpandS/ExpandMask + the NTT-domain matrix·vector product) are correct.

**Evidence.** `test-mldsa-c99`: pack round-trip + independent bit-slice oracle for the generic packer and each field encoder; `tools/vectors/mldsa_pack.json` (10 vectors: 2 each of t1/t0/eta/w1/z) wired into both §3.13 halves with t1 byte-checked against the reference `pack_t1` formula. Per-poly ops (11)–(12): add/sub exact element-wise, reduce/caddq residue-preserving, `poly_pointwise_montgomery` through the same O(n²) schoolbook oracle. Matrix/vector (13)–(15): ExpandA entry (i,j) re-derived as `sample_uniform(ρ‖col=j‖row=i)` (catches a transpose / swapped nonce order), ExpandS/ExpandMask nonce sequence (s1:0.., s2:l.., y:l·κ+i) re-derived, and the **decisive** `invNTT(Â·ŝ) == O(n²) schoolbook A·s` on a **non-square (k≠l)** set. All of this is additionally transitively pinned by the ACVP KeyGen/Sign bytes (MC-1, MC-2).

**Caveat.** No standalone external ACVP oracle exists for these sub-layers pre-signer; the pins are independent re-derivations + the schoolbook oracle + the transitive ACVP coverage.

### MC-12 — The C++ wrapper (`determ::c99::mldsa`) equals the raw C API

**Claim.** The C++ convenience wrapper (`keygen`/`sign`/`verify`/`format_message`/size helpers in the `determ::c99::mldsa` namespace) produces byte-identical output to the raw C functions and round-trips + rejects tampering.

**Evidence.** `test-c99-api` assertion (13) → `mldsa_api_selftest()` (`main.cpp:1388-1418`): for all three sets it asserts `wrapper keygen == raw determ_mldsa_keygen` (`kp.pk == rpk && kp.sk == rsk`), a deterministic sign, verify accepts, a re-sign is identical, a tampered σ rejects, and a truncated σ rejects safely (via a try/catch that reports rather than terminates).

**Caveat.** The wrapper is a thin marshalling layer; this is an equivalence + round-trip check, not an independent re-implementation.

### MC-13 — Secret-bearing locals are scrubbed on every exit path

**Claim.** `Sign_internal` zeroes all secret-bearing stack locals — the master secrets (s1, s2, t0, K, ρ'') plus the key-recovering intermediates (the mask y/yh, and c·s1, c·s2, c·t0, w, and z/zc/r0/w1) — on **every** exit path (success and safety-cap), via a shared `cleanup:` block; `keygen` scrubs (ctx, h, s1, s1h, s2, t0).

**Evidence.** Source only: `sign.c:174-188` (the shared `cleanup:` with `determ_secure_zero` over every secret local) and `keygen.c:102-108`. This is an R70-audit hardening.

**Caveat.** This is a **source-verified hygiene property, not a machine-checked one** — no test asserts the stack is scrubbed, and scrubbing does not survive compiler dead-store elimination guarantees beyond what `determ_secure_zero` provides. It is a memory-hygiene measure, **not** a timing-side-channel defense (see NP-1).

---

## 3. What is NOT proven

### NP-1 — The implementation is NOT proven constant-time; no timing-side-channel review has been done

This is the honest posture, matching the module README §4 and the R70 self-audit note:

- **Data-independent by construction (the public-index paths).** The NTT butterflies, the reduction functions, and the bit-packing have no secret-dependent branch, loop bound, or memory index — control flow is on public indices only (`caddq`/`montgomery_reduce` use the sign bit via arithmetic shift, not a branch). This is why the NTT is the standard constant-time multiply for lattice schemes.
- **The rejection samplers are NOT constant-time in loop count.** `sample_uniform`/`sample_eta`/`sample_in_ball` consume a **data-dependent** number of SHAKE bytes (the rejection loop) — the canonical Dilithium reference behaviour. For `sample_uniform` (Â from public ρ) and `sample_in_ball` (public challenge) the seed is public, so this is harmless; `sample_eta` runs on the secret ρ', matching the reference's accepted posture (the leak is the reject *count*, not the secret coefficients). `sample_gamma1` (ExpandMask) is rejection-free → constant-time.
- **The signing loop has data-dependent iteration count.** `Sign_internal`'s Fiat-Shamir-with-aborts loop (`sign.c:116`, `SIGN_MAX_ITERS` cap) iterates a **secret-and-message-dependent** number of times — the canonical ML-DSA behaviour. The number of rejections is observable through timing.
- **`determ_mldsa_verify` compares c̃ with a plain byte loop** (`sign.c:267`, `if (ctil[c] != ctil2[c]) return 0`), early-returning on the first mismatch — a non-constant-time comparison. Verify operates on public data (pk, σ, M'), so this is not a secret leak, but it is not a CT compare.

**A dedicated constant-time / side-channel timing audit of the secret-dependent paths has NOT been performed.** This is a **library primitive**; such a review is a **separate, owner-gated step** required before production signing (per README §5 and the R70 note). MC-13's secret scrubbing is a memory-hygiene measure only and does not address timing.

### NP-2 — This is not (yet) a chain consensus primitive

ML-DSA has **no in-tree consumer**. It is purely additive. Offering it as a PQ signature option alongside Ed25519 is a **consensus-critical change** (and reopens the anon-address-format decision) — a later, separately-reviewed integration step. Nothing in this document establishes any chain-level property; the claims are exclusively about the library primitive's conformance to FIPS 204 / ACVP.

### NP-3 — Coverage is one-to-a-few ACVP vectors per parameter set, not the full ACVP set

The byte-pinned legs use the first AFT KeyGen case per set (3 total), 2 sigGen cases per set (6 total), and 5 sigVer cases per set (15 total). This is the authoritative external oracle for the covered inputs, and reproducing the ACVP bytes transitively exercises the whole stack — but it is not exhaustive over ACVP's full vector list, and the deterministic sign variant is the only byte-reproducible one.

### NP-4 — The prehash + externalMu interface variants are not implemented

HashML-DSA (prehash) and externalMu are out of scope for the chain path and are not implemented; no claim is made about them.

---

## 4. Trust base and assumptions

- **(FIPS 204)** the standard is correct and the ACVP `internalProjection.json` vectors are genuine NIST bytes.
- **(A-SHAKE)** the C99 SHAKE128/256 (`src/crypto/sha3/`) is correct — discharged in CRYPTO-C99-SPEC §3.17 (byte-equal to OpenSSL/hashlib, R62), assumed here.
- **(A-oracle)** the independent Python references (`verify_mldsa_keygen.py`, `verify_mldsa_sign.py`, `verify_mldsa_vectors.py`, `verify_mldsa_sample.py`, `verify_mldsa_pack.py`) implement FIPS 204 correctly and share no code with `src/crypto/`. Their SHAKE is python `hashlib` (distinct from the C `determ_shake`), and their NTT is a from-scratch Python transform.
- **(A-corpus)** both §3.13 halves read the same frozen `tools/vectors/mldsa_*.json` bytes; the expected pk/sk/σ/flags are the NIST values, not recomputed by either implementation, so a bug shared by C and Python is still caught by the external oracle.
- **(A-json)** python `json` and the C++ JSON parser agree on the corpus parse.

The **lattice hardness** ML-DSA's unforgeability ultimately rests on (MLWE/MSIS) is assumed, not proved here — this document covers **conformance** (byte-exact agreement with FIPS 204 via ACVP) and **memory-safety / hygiene** properties, not cryptographic security reductions.
