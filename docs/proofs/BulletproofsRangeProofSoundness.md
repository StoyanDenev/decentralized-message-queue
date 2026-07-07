> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# BulletproofsRangeProofSoundness — Determ C99 Bulletproofs single-value range proof over NIST P-256: completeness / soundness / determinism + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **C99-native Bulletproofs single-value range proof** shipped in `src/crypto/pedersen/rangeproof.c` (public API `include/determ/crypto/pedersen/rangeproof.h`, CRYPTO-C99-SPEC.md §3.19 **increment 5**). It is the successor to `BulletproofsIPASoundness.md` (increment 4): where that document accounts for the log-size inner-product **subroutine**, this one accounts for the **range predicate** built on top of it — a proof that a Pedersen-committed value `v` lies in `[0, 2^n)` without revealing `v`.

The module is thin composition. It is written **entirely against the §3.19 inc.1-4 pedersen/IPA public APIs** (`determ_pedersen_generator_h` / `determ_pedersen_gen` / `determ_pedersen_msm` / `determ_ipa_prove_gens` / `determ_ipa_verify_gens`) **and the §3.8c P-256 point/scalar ops** (`rangeproof.c:9-13`), introducing **no new group arithmetic of its own**. The only new scalar logic is a local `sc_add` / `sc_sub` (a big-endian modular add and its subtract, `rangeproof.c:38-72`) and the `rp_inner` accumulator over them; every point operation and every mod-`n` scalar multiply/inverse/hash-to-scalar is a call into an already-gated primitive. Its correctness therefore composes on top of those layers' own validation rather than re-deriving it; the only genuinely new logic is the **range-proof prover/verifier assembly + the Fiat-Shamir transcript**, which the structural gate pins by algebraic property and `tools/vectors/bp_rangeproof.json` pins byte-for-byte against an independent Python re-derivation.

This is the **last** of the five range-proof / confidential-transaction track increments authorized 2026-07-04 — **library-primitive-first, KAT-gated, ZERO consensus touch** (`rangeproof.h` "LIBRARY PRIMITIVE — no chain call site"; additive, not wired into any chain, ledger, or wallet code path).

## Scope

**In scope.** The exported operations, verified against `rangeproof.c`:
- `determ_rangeproof_prove` — the value commitment `V = v*g + gamma*h` + the proof `A|S|T1|T2|taux|mu|t_hat|ipa` (`:172-269`);
- `determ_rangeproof_verify` — the two-check verifier (`:271-...`): the `t_hat` polynomial identity + the reconstructed-`P` IPA check;
- `determ_rangeproof_proof_len` — the `228 + determ_ipa_proof_len(n)`-byte length contract, `0` for a non-power-of-two or `n > 64` (`:158-161`);
- the deterministic Fiat-Shamir transcript (`rtr_init`/`rtr_absorb`/`rtr_challenge`, `:164-... `): seeded with `(V, n)`, absorbing `A,S` → `y,z`, then `T1,T2` → `x`, distinct label/DST (`DETERM-BP-RANGE-v1`) from the IPA's;
- the generator layout: value generator `g` = the P-256 base point, blinding generator `h` = the Pedersen scalar `H`, bit-vector generators `g_i`/`h_i` = `pedersen_gen(i,0/1)`, the IPA generator `u = pedersen_gen(0xFFFFFFFF,0)`, and the `y`-rescaled `h'_i = y^-i·h_i`.

**Out of scope.**
- **Aggregation** — proving multiple values / multiple ranges in one argument. This is a single-value proof (NC-1).
- **The single multi-exponentiation verify optimization** — the verifier here reconstructs `P` and folds the IPA generators explicitly rather than collapsing everything into one `O(n)` multi-exp. Same accept set, non-optimized computation (NC-2).
- **Any chain / wallet wiring** — no Determ code path constructs, proves, or verifies a range proof (NC-3).
- **Timing side channels** — `sc_add`/`sc_sub`'s conditional subtraction and the `pedersen_msm` zero-scalar skip are data-dependent on the secret witness (`v`'s bits, `s_L`/`s_R`); a production prover needs constant-time variants. The CT-hardening is the owner-gated step (NC-4, L-4).

**Authoritative external sources.** Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell, **"Bulletproofs: Short Proofs for Confidential Transactions and More"** (IEEE S&P 2018) — the single range proof is §4.1 (Protocol 1 / the `l(X)`,`r(X)`,`t(X)` construction) and §4.2 (the IPA reduction), with soundness via §4.1 Theorem 3 (reduction to the inner-product argument's special-soundness). The group is NIST **P-256** / secp256r1 (**FIPS 186-5** / SP 800-186). The Fiat-Shamir challenges are derived via **RFC 9380** `hash_to_field` with the group order as modulus (the §3.8c `hash_to_scalar`). Special-soundness rests on the P-256 **discrete-log** hardness assumption (ECDLP) and, for the non-interactive transform, the **random-oracle model (ROM)** — both assumed, not proved here (L-1, L-3).

Companion / trust-base documents: `BulletproofsIPASoundness.md` (increment 4 — the inner-product argument this reduces its final `<l,r>=t_hat` check to); `PedersenCommitmentSoundness.md` (increments 1-3 — the `pedersen_gen` generator families + the `pedersen_msm` every group op reduces to); `P256CryptoStackAudit.md` (the correctness + constant-time audit of the underlying P-256 field / RCB addition / CT ladder / SSWU / mod-n ops); `CRYPTO-C99-SPEC.md` §3.19 (design entry, increment 5), §3.8c, §3.13 (the dual-oracle vector gate); `ConstantTimeInventory.md` / §3.12 (the timing boundary handed off in L-4).

---

## 1. The construction map

### 1.1 The statement and generators

The prover holds a value `v ∈ [0, 2^n)` and a blinding `gamma`, and publishes the Pedersen commitment `V = v·g + gamma·h`. The range proof convinces a verifier that the committed `v` lies in `[0, 2^n)` without revealing it.

| Generator | Derivation | Role |
|---|---|---|
| `g` | the P-256 base point (`base_g` = `compress(1·G)`, `rangeproof.c:118-123`) | the value generator |
| `h` | `pedersen_generator_h` (the nothing-up-my-sleeve scalar `H`, unknown `log_g(h)`) | the blinding generator |
| `g_i`, `h_i` (`i<n`) | `pedersen_gen(i, 0)`, `pedersen_gen(i, 1)` — the inc.2 families | the bit-vector generators |
| `u` | `pedersen_gen(0xFFFFFFFF, 0)` | the IPA inner-product generator |
| `h'_i` | `y^-i · h_i` | the `y`-rescaled `h` family the IPA runs over |

All are nothing-up-my-sleeve RFC 9380 hash-to-curve images (or the base point) with no known mutual discrete-log relation — the load-bearing independence for soundness (`PedersenCommitmentSoundness.md` PC-9).

### 1.2 The protocol (matching `rangeproof.c` exactly)

**Prover** (`determ_rangeproof_prove`):
1. `a_L` = the `n` bits of `v`; `a_R = a_L − 1^n` (`:190-195`).
2. `A = alpha·h + <a_L, g> + <a_R, h>` (`:203-...`), `S = rho·h + <s_L, g> + <s_R, h>` — the inc.2 vector-commit shape via `pedersen_msm`.
3. Transcript absorbs `A, S`; challenges `y, z` (`:...`).
4. `l(X) = (a_L − z·1^n) + s_L·X`; `r(X) = y^n ∘ (a_R + z·1^n + s_R·X) + z²·2^n`; `t(X) = <l(X),r(X)> = t_0 + t_1·X + t_2·X²`.
5. `T_1 = t_1·g + tau_1·h`, `T_2 = t_2·g + tau_2·h` (the inc.1 Pedersen-commit shape).
6. Transcript absorbs `T_1, T_2`; challenge `x`.
7. `l = l(x)`, `r = r(x)`, `t_hat = <l,r>`, `taux = tau_2·x² + tau_1·x + z²·gamma`, `mu = alpha + rho·x`.
8. The **inc.4 IPA** (`determ_ipa_prove_gens`) proves `<l,r> = t_hat` over `(g_i, h'_i, u)`, with `P_ipa = <l,g> + <r,h'> + t_hat·u`.

**Verifier** (`determ_rangeproof_verify`): recompute `y,z,x` from the transcript (re-seeded with the *supplied* `V`), then:
- **Check 1** (the `t_hat` polynomial identity): `t_hat·g + taux·h == z²·V + delta(y,z)·g + x·T_1 + x²·T_2`, where `delta(y,z) = (z − z²)·<1^n, y^n> − z³·<1^n, 2^n>`.
- **Check 2** (the IPA relation): reconstruct `P = A + x·S − z·<1^n,g> + <z·y^n + z²·2^n, h'> − mu·h`, then `determ_ipa_verify_gens(P + t_hat·u, …)`.

Accept iff both checks pass. Fail-**closed**: any identity intermediate (`pedersen_msm` return ≠ 0) or point-decode failure rejects (`msm_nonid`, `:...`).

### 1.3 The key oracle (why completeness holds)

The decisive algebraic fact is `t_0 = <l_0, r_0> = z²·v + delta(y,z)` for an in-range `v` (the identity Check 1 relies on). This is machine-verified **independently of `prove()`** by the Python reference's `_t0_oracle` (`verify_bp_rangeproof.py`), which recomputes `t_0` from the `l_0`/`r_0` vectors and compares to the closed form `z²·v + delta`, for every `n ∈ {1,2,4,8,16}` and several `v`. Combined with the IPA's own per-round invariant (`BulletproofsIPASoundness.md` IPA-1), this is why an honest proof always verifies (completeness) and why an out-of-range `v` cannot (its bits encode `v mod 2^n ≠ v`, so `t_0` fails to match `z²·v` and Check 1 rejects).

---

## 2. Soundness / conformance claims (RP-1 .. RP-6)

The `determ test-bp-rangeproof-c99` checks are at `src/main.cpp` (the `test-bp-rangeproof-c99` block); the three-vector corpus is `tools/vectors/bp_rangeproof.json` (`n ∈ {4,8,16}`), consumed by both §3.13 halves; the Python reference is `tools/verify_bp_rangeproof.py`.

### RP-1 — Completeness: an honestly-generated proof always verifies (all n), the t_0 identity is the reason

**Claim.** For any `v ∈ [0,2^n)` and honest randomness, `verify(V, prove(v,…), n) == 0`.

**Evidence.** Structural round-trip (C): `test-bp-rangeproof-c99` assertion (2) runs `prove → verify` and requires accept for `n ∈ {4,8,16}`. Python `_selftest` runs it for `n ∈ {1,2,4,8,16}` × several `v`. The decisive reason is `_t0_oracle` (§1.3) + the IPA per-round invariant, both machine-verified over the covered `n`.

**Caveat.** Verified on the fixed witness family / bounded `n` (L-2); completeness for arbitrary `v` follows from the algebra (§1.3), not exhaustive coverage.

### RP-2 — Soundness: a verifying proof binds v ∈ [0, 2^n) (reduction to Bulletproofs §4 under ECDLP + ROM)

**Claim.** A proof `verify` accepts for commitment `V` binds the prover to a `v ∈ [0, 2^n)` such that `V = v·g + gamma·h` — a prover cannot make `verify` accept for a `V` committing to an out-of-range value, except by breaking P-256 discrete log or the ROM assumption.

**Argument (reduction, NOT re-proved here).** Bünz et al. 2018 §4.1 Theorem 3: a range proof reduces to the inner-product argument's special-soundness (their Theorem 1) plus the binding of the Pedersen commitments `V`/`A`/`S`/`T_1`/`T_2` under ECDLP. The `y`-challenge enforces the Hadamard constraint `a_L ∘ a_R = 0` (bits are 0/1), the `z`-challenge folds in `a_R = a_L − 1` and `v = <a_L, 2^n>`, and the `x`-challenge binds the polynomial identity — an extractor from enough accepting transcripts recovers a valid `(v, gamma)` opening with `v ∈ [0,2^n)`, else it yields a nontrivial dlog relation among the independent generators. The Fiat-Shamir transform inherits this in the ROM.

**Evidence (structural reject witnesses, NOT an extractor).** `test-bp-rangeproof-c99` assertion (4) and the Python `_selftest`: a byte-flipped proof rejects; a proof made for `V` does NOT verify under a different `V'`; and an **out-of-range** `v = 2^n` cannot yield a verifying proof (Check 1 fails on the `t_0` mismatch, §1.3).

**Caveat.** These are **existence witnesses** that the deployed reject paths fire on the injected tampers / the out-of-range case; they are **not** a machine-checked extractor and **not** a proof of soundness (that is the cited literature theorem under ECDLP + ROM, L-1/L-3).

### RP-3 — Determinism / non-interactivity: the transcript is a pure function of (V, generators, messages)

**Claim.** `prove` is deterministic in `(v, gamma, alpha, rho, tau1, tau2, sL, sR)` — identical inputs → identical `V` + proof bytes — and `verify` recomputes exactly the prover's challenges, binding the proof to `V`.

**Evidence.** `test-bp-rangeproof-c99` assertion (3): `prove` twice → byte-identical `V` + proof, for `n ∈ {4,8,16}`. Structural consequence of the randomness-free transcript (`rtr_*`), independently corroborated by the byte-exact dual oracle (RP-4). The `V`-binding is the "wrong commitment rejects" witness (RP-2).

**Caveat.** A production prover draws `alpha/rho/sL/sR/tau1/tau2` from a CSPRNG — here they are caller-supplied purely so the KAT is reproducible; the security of a real deployment depends on that randomness being unpredictable (L-2).

### RP-4 — Dual-oracle byte-exactness: the C proof bytes equal the independent Python's for the corpus

**Claim.** For each corpus vector (`n ∈ {4,8,16}`), the shipped C recomputes the **entire proof** — `V`, `A`, `S`, `T_1`, `T_2`, `taux`, `mu`, `t_hat`, and the inner IPA (`L/R` + final `a,b`) — and matches, **byte-for-byte**, the values an independent from-scratch Python implementation generated.

**Evidence.** The §3.13 dual-oracle posture over `tools/vectors/bp_rangeproof.json`: the binary half (`test-c99-vectors`'s `bp_rangeproof` branch, run in `FAST=1`) rebuilds the prover randomness from `(n, seed)`, drives the C `prove`, asserts every field matches the frozen hex, and asserts `verify` accepts; the file half (`test_c99_vector_files.sh`'s `chk_bp_rangeproof` → `verify_bp_rangeproof.check_rangeproof`) recomputes the same through the **independent** Python (its own P-256 EC + RFC 9380 h2c + the IPA, sharing zero source with `src/crypto/*`) and matches all fields plus a live round-trip.

**Caveat.** Byte-exact over exactly the **three frozen vectors** (one witness family per `n`), a fixed point set, not the input space (L-2). The Python oracle's own faithfulness to Bulletproofs §4 is the (P-oracle) assumption, corroborated by its `_t0_oracle` + round-trip + tamper + out-of-range self-tests.

### RP-5 — proof_len contract: 228 + ipa_proof_len(n), and non-power-of-two / oversized n yield 0

**Claim.** `determ_rangeproof_proof_len(n)` returns `228 + determ_ipa_proof_len(n)` for a power of two `n ∈ [1, 64]`, and `0` for a non-power-of-two or `n > 64` — and `prove`/`verify` reject such `n` with `-1`.

**Evidence.** `test-bp-rangeproof-c99` assertion (1): `proof_len(4)==424`, `(8)==490`, `(16)==556`, `proof_len(3)==0`, `proof_len(128)==0`. The `rp_rounds` guard (`rangeproof.c:145-151`) rejects `n < 1`, `n > 64`, and any non-power-of-two; `prove`/`verify`/`proof_len` all call it first.

**Caveat.** None material — a total, input-checked size/validity contract.

### RP-6 — Trust inheritance: every group/scalar op is an already-gated primitive; the only new arithmetic is sc_add/sc_sub

**Claim.** `rangeproof.c` adds **no** new field or group arithmetic. Every point/multi-exp/IPA operation is a call into a primitive already validated (byte-equal vs OpenSSL EC / the RFC 9380 vectors, or the inc.1-4 gates). The **only** new scalar logic is `sc_add` (a big-endian add + one conditional subtract of `n`) and `sc_sub` (`a + (n−b)`, with the `b==0` special-case), plus the `rp_inner`/`sc_powers` helpers over them.

**Evidence.** Reading `rangeproof.c` end-to-end: the calls are `determ_p256_base_mul`/`_point_{mul,add,compress,decompress}`, `determ_p256_scalar_{mul,inv}_mod_n`, `determ_p256_hash_to_scalar`, `determ_pedersen_{generator_h,gen,msm}`, `determ_ipa_{prove,verify}_gens` — validated by `test-p256-c99` / `test-p256-h2c-c99` / `test-pedersen-c99` / `test-bp-ipa-c99`. `sc_add`/`sc_sub` are exercised by every fold/coefficient computation; their correctness is corroborated by the byte-exact dual oracle (RP-4) — a wrong reduction would diverge the folded scalars from the independent Python's `%N` arithmetic — AND by the adversarial audit's exhaustive `sc_add`/`sc_sub` boundary fuzz (100k+ cases vs a Python `%N` oracle).

**Caveat.** A **forward-reference**, not a re-proof: the underlying scalar-mult / point-add / SSWU / mod-n correctness + CT posture is discharged in `P256CryptoStackAudit.md`, not here. `sc_add`/`sc_sub` have no standalone KAT — their correctness rests on the dual-oracle agreement over the computations they participate in + the audit fuzz, not a dedicated modular-add test (L-2).

---

## 3. Non-claims (NC-1 .. NC-4)

- **NC-1 — Single value only.** This proves ONE committed value in `[0,2^n)`; it does not aggregate multiple values/ranges into one argument.
- **NC-2 — Not the multi-exp-optimized verifier.** The verifier reconstructs `P` and folds the IPA generators explicitly rather than collapsing the whole check into one `O(n)` multi-exponentiation. Same accept set, deliberately non-optimized computation.
- **NC-3 — Not a consensus or wallet primitive yet.** No Determ chain/ledger/wallet path constructs, proves, or verifies a range proof. This is an additive **library primitive with no in-tree consumer**. A confidential-transaction chain integration is a later, separately-reviewed, consensus-critical increment. (Note: the owner **rejected secp256k1** on 2026-07-07 — it was never built (no `src/crypto/secp256k1*`), so the *eventual* v2.22 chain-level Bulletproofs is over this **same NIST P-256** stack; this from-scratch **P-256** range-proof stack is the library-primitive-first exploration. See `DECISION-LOG.md` 2026-07-07 and the CRYPTO-C99-SPEC.md §2 SUPERSEDED banner.)
- **NC-4 — Not constant-time.** `sc_add`/`sc_sub`'s conditional subtraction and the `pedersen_msm` zero-scalar skip branch on the **secret** witness (`v`'s bits, `s_L`/`s_R`). A production prover needs constant-time modular arithmetic and a constant-time multi-exp — the owner-gated CT-hardening step. This document asserts **functional** correctness only, not timing (L-4).

---

## 4. Limits (L-1 .. L-4)

- **L-1 — Soundness is not proven; it is assumed under ECDLP + generator independence.** RP-2 is a reduction to the Bulletproofs §4 theorem; the tests exercise reject paths (tamper, wrong-`V`, out-of-range), **not** a machine-checked extractor. A break of ECDLP on P-256 breaks binding regardless of any byte-exactness here.
- **L-2 — Bounded input set.** RP-4 quantifies over exactly the **three** frozen `bp_rangeproof.json` vectors; the structural round-trip / determinism / soundness widen to `n ∈ {4,8,16}` (C) and `{1,2,4,8,16}` (Python) but are not byte-pinned beyond the corpus. Not exercised: `n` up to 64, other witness families, adversarial near-boundary values. `sc_add`/`sc_sub` have no standalone KAT (RP-6 caveat) beyond the audit fuzz.
- **L-3 — The Fiat-Shamir transform's soundness is in the ROM.** The non-interactive challenges are `hash_to_scalar(transcript)`; the argument that this is as sound as the interactive protocol is a ROM result. Assumed, not proved.
- **L-4 — Timing out of scope.** `sc_add`/`sc_sub`'s conditional subtraction (NC-4) and the `pedersen_msm` zero-scalar skip are data-dependent on the secret witness; the normative timing boundary is CRYPTO-C99-SPEC §3.12 / `ConstantTimeInventory.md`. A constant-time prover is the owner-gated hardening step.

---

## 5. Mechanized witnesses

| Layer | Script / subcommand | What it pins |
|---|---|---|
| Structural / negative | `determ test-bp-rangeproof-c99` | (1) `proof_len == 228 + ipa_proof_len(n)`, non-power-of-2 / n>64 → 0 (RP-5); (2) round-trip `prove→verify` accepts for `n ∈ {4,8,16}` (RP-1); (3) determinism — prove twice → identical V + proof (RP-3); (4) soundness — a tampered proof, a wrong commitment, AND an out-of-range v all reject (RP-2). |
| Byte gate, file half | `tools/test_c99_vector_files.sh` (`chk_bp_rangeproof` → `verify_bp_rangeproof.check_rangeproof`) | RP-4 leg 1 + RP-1: independent from-scratch Python recomputes V + every proof field + the inner IPA and matches the frozen bytes, plus a live round-trip; the `_t0_oracle` + tamper + out-of-range self-tests machine-verify the §1.3 identity. Offline, fail-closed. |
| Byte gate, binary half | `determ test-c99-vectors` (`bp_rangeproof` branch), in `FAST=1` | RP-4 leg 2: the three vectors through the shipped C `prove`/`verify`, every field byte string-compared to the frozen hex, with a live `verify` accept. |
| Underlying primitives (context, RP-6) | `determ test-p256-c99` / `test-p256-h2c-c99` / `test-pedersen-c99` / `test-bp-ipa-c99` | Curve/hash-to-curve/generator/MSM/IPA correctness — the base under every range-proof operation. |

The two-leg split is the standard §3.13 defense-in-depth: the structural test is the **reject-path + round-trip + determinism + out-of-range** witness the accept-only vectors cannot provide; the byte gate is the **dual-oracle conformance** witness (C99 == independent Python over frozen bytes, incl. the full proof); RP-6 forward-references the inc.1-4 + P-256 audits for the primitive-correctness base; and the Python `_t0_oracle` is the algebraic oracle that machine-verifies the completeness identity. Their conjunction — bounded by L-1..L-4 — is what "the C99 Bulletproofs range proof is complete, deterministic, byte-conformant, and binding under ECDLP+ROM" means for this increment-5 library primitive.

---

## 5A. The aggregated range proof (increment 6)

Increment 6 (`determ_agg_rangeproof_prove`/`_verify`, same `rangeproof.c`) generalizes the single-value proof to prove that **`m` committed values `v_0..v_{m-1}` each lie in `[0, 2^n)` in ONE proof** of size `2*log2(m*n) + O(1)` group elements (Bünz et al. 2018 **§4.3**, the aggregation of `m` single range proofs). The `m` bit-vectors are concatenated into a length-`m*n` `a_L`; value `j`'s `2^n` slot is scaled by `z^(2+j)` (0-indexed), so the constant term is `t_0 = Σ_j z^(2+j)·v_j + delta(y,z)` with `delta = (z − z^2)·<1^{mn}, y^{mn}> − (Σ_j z^(3+j))·<1^n, 2^n>`, and the final `<l,r> = t̂` check is the **same inc.4 IPA over the `m*n`-wide generators**. Setting `m = 1` recovers §1.2 exactly.

**All of RP-1..RP-6 carry over** with the `m`-value generalization — the construction is identical modulo the per-slot `z^(2+j)` weighting, which the same `t_0`-oracle machine-verifies (`verify_bp_agg_rangeproof._t0_oracle` checks `t_0 == Σ_j z^(2+j)·v_j + delta` over `(m,n) ∈ {(1,4),(2,2),(2,4),(4,2),(2,8),(4,4)}`). The **soundness** (RP-2) is Bünz §4.3's reduction: aggregation preserves special-soundness, and the `z^(2+j)` separation binds each value to its own range — so a **single out-of-range value anywhere in the batch is caught** (its slot's `z^(2+j)·v_j` term breaks Check 1). This is a witnessed reject in the structural test, not just prose.

**Gate.** `determ test-bp-agg-rangeproof-c99` (proof_len contract `228 + ipa_proof_len(m*n)`, non-pow2 `m*n` / `m*n>256 → 0`; round-trip for `(m,n) ∈ {(1,4),(2,4),(4,4),(2,8)}`; determinism; soundness — tampered proof, wrong batch of commitments, AND out-of-range-in-batch all reject) + the §3.13 dual-oracle corpus `tools/vectors/bp_agg_rangeproof.json` (3 vectors, `(m,n) ∈ {(2,4),(4,4),(2,8)}`) recomputed byte-for-byte by BOTH the C and the independent from-scratch Python (`tools/verify_bp_agg_rangeproof.py`). An off-corpus cross-check further confirms byte-exact agreement at the **`m*n = 256` max-buffer boundary** (`m=32, n=8`), empirically de-risking the exact-fit aggregated `scal`/`pts` `(2·256+3)`-element arrays. The **non-claims/limits carry over verbatim** except NC-1 (single-value) which inc.6 supersedes; NC-2's "not aggregated" is now also superseded (aggregation shipped) while the single-multi-exp verify optimization remains a non-goal.

---

## 6. Status

- **Spec.** Complete (this document).
- **The structural test + both byte-gate halves shipped and green.** `test-bp-rangeproof-c99` (proof_len + round-trip + determinism + soundness-reject incl. out-of-range), the `bp_rangeproof` branch of `test-c99-vectors` (binary half), and `chk_bp_rangeproof`/`verify_bp_rangeproof.check_rangeproof` (file half) validate the three-vector corpus + the reject/round-trip paths; the C99 output — `V` + all proof fields + the inner IPA — is byte-exact against the independent Python, whose `_t0_oracle` machine-verifies the completeness identity for `n ∈ {1,2,4,8,16}`.
- **Claims.** RP-1 (completeness), RP-2 (soundness — reduced to Bulletproofs §4 under ECDLP + ROM; reject witnesses incl. out-of-range, NOT an extractor), RP-3 (determinism / non-interactivity), RP-4 (dual-oracle byte-exactness — full proof, two independent impls), RP-5 (proof_len contract), RP-6 (trust inheritance; `sc_add`/`sc_sub` the only new arithmetic, corroborated via the byte-exact oracle + the audit fuzz) — all closed.
- **Non-claims (NC-1..NC-4).** Single value only [SUPERSEDED by the inc.6 aggregation, §5A]; not the multi-exp-optimized verifier [aggregation now shipped]; not a consensus/wallet primitive; not constant-time (owner-gated CT hardening).
- **Increment 6 (aggregation).** Shipped and gated (§5A): `m` values in one proof, `test-bp-agg-rangeproof-c99` + the dual C∥Python `bp_agg_rangeproof.json` corpus, RP-1..RP-6 carry over, a single out-of-range value in the batch rejects, byte-exact to the `m*n=256` max-buffer boundary.
- **Limits (L-1..L-4).** Soundness assumes ECDLP + generator independence (reduction, not extractor); conformance is over the three frozen vectors + bounded structural `n`; Fiat-Shamir soundness is in the ROM; timing → §3.12 / `ConstantTimeInventory.md`.
