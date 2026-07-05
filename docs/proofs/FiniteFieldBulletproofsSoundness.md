> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# FiniteFieldBulletproofsSoundness — Determ C99 Bulletproofs range-proof stack over Z_p* (RFC 3526 MODP-3072): setup / reduction chain / completeness / soundness / HVZK + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **complete C99-native finite-field Bulletproofs range-proof stack** shipped in `src/crypto/ff/` (`ffgroup.c`, `ffipa.c`, `ffrangeproof.c`; public API `include/determ/crypto/ff/ffgroup.h` and the two increment headers; CRYPTO-C99-SPEC.md **§3.20**, increments 1-6). It is the **MODERN-profile "large primes, not curves" sibling** of the §3.19 P-256 stack accounted for in [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) (single-value + aggregation) and [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) (the inner-product subroutine). Where those account for the construction over NIST **P-256** (an elliptic-curve group), this one accounts for the identical Bulletproofs construction over the **prime-order subgroup `G_q ⊂ Z_p*`** — same protocol algebra, a different group.

The owner-decided curve/group split (CRYPTO-C99-SPEC.md §3.20, 2026-07-05): **FIPS profiles get the §3.19 P-256 stack; MODERN profiles get this finite-field stack** — NIST-curve-for-the-NIST-trusting-audience, non-NIST-big-prime-math-for-the-privacy-audience — making confidential amounts available in every profile. The chosen amount primitive is a **Pedersen commitment** (not ElGamal). The integration into the ledger is design-stage and owner-gated; see [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (a FUTURE-tier proposal, decides nothing).

The stack is a layered composition. Increments 4-6 (IPA, single-value range proof, aggregated range proof) are written **entirely against the §3.20 inc.1-3 group / vector-commit / MSM / scalar-field public API** (`determ_ff_gen` / `determ_ff_msm` / `determ_ff_vector_commit` / `determ_ff_scalar_*` / `determ_ff_hash_to_scalar`, `ffipa.c:9-10`, `ffrangeproof.c:8-10`), introducing **no new field or group arithmetic** above the inc.1-3 bignum. All group elements and scalars are 384-byte (3072-bit) big-endian; group exponents and challenge scalars are reduced mod `q` (the subgroup order), group elements reduced mod `p`.

This is **library-primitive-first, KAT-gated, ZERO consensus touch** (`ffgroup.h` "LIBRARY PRIMITIVE — no chain call site"; additive, not wired into any chain, ledger, or wallet path).

## Scope

**In scope.** The exported operations, verified against the three source files:
- **inc.1** (`ffgroup.c`): the Pedersen commitment `C = g^v · h^r mod p` and its opening / additive homomorphism — `determ_ff_pedersen_generator_h` / `_commit` / `_verify` / `_add` (`ffgroup.c:127-163`);
- **inc.2** (`ffgroup.c`): the two nothing-up-my-sleeve order-`q` generator families `G_i = determ_ff_gen(i,0)` / `H_i = determ_ff_gen(i,1)`, the vector Pedersen commit `determ_ff_vector_commit`, and the general multi-exponentiation `determ_ff_msm` (`ffgroup.c:246-295`);
- **inc.3** (`ffgroup.c`): the scalar field mod `q` — `determ_ff_scalar_reduce` / `_add` / `_sub` / `_mul` / `_inv` (Fermat `a^{q-2}`) and the Fiat-Shamir challenge map `determ_ff_hash_to_scalar` (`ffgroup.c:299-378`);
- **inc.4** (`ffipa.c`): the inner-product argument — `determ_ff_ipa_commit` / `_prove` / `_verify` (+ the `_gens` generator-supplied variants the range proof uses with a `y`-rescaled `h` family), transcript label `DETERM-FF-BP-IPA-v1` (`ffipa.c:17`);
- **inc.5** (`ffrangeproof.c`): the single-value range proof — `determ_ff_rangeproof_prove` / `_verify` / `_proof_len`, proof layout `A|S|T1|T2|taux|mu|that|ipa` (`ffrangeproof.c:19-27`), transcript `DETERM-FF-BP-RANGE-v1`;
- **inc.6** (`ffrangeproof.c`): the aggregated range proof — `determ_ff_agg_rangeproof_prove` / `_verify` / `_proof_len`, transcript `DETERM-FF-BP-AGGRANGE-v1` (`ffrangeproof.c:302-303`).

**Out of scope.**
- **The single multi-exponentiation verify optimization** — the verifier reconstructs `P` and folds the IPA generators explicitly (`ffipa.c:192-215`) rather than collapsing everything into one `O(n)` multi-exp. Same accept set, non-optimized computation (NC-1).
- **Any chain / wallet wiring** — no Determ code path constructs, proves, or verifies a finite-field range proof (NC-2).
- **Timing side channels** — the modexp square-and-multiply branches on secret exponent bits (`modexp_c`, `ffgroup.c:98-111`), and the `msm` / `vector_commit` zero-scalar skip is data-dependent (`ffgroup.c:287`, `:263`/`:270`); a production prover over secret witnesses needs constant-time variants. CT-hardening is the owner-gated step (NC-3, L-4).
- **Post-quantum security** — finite-field discrete log is broken by Shor's algorithm; this is a classical-adversary construction (NC-4, L-5).

**Authoritative external sources.** Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell, **"Bulletproofs: Short Proofs for Confidential Transactions and More"** (IEEE S&P 2018) — the inner-product argument is §3 (Protocol 1/2), the single range proof is **§4.1-4.2** (the `l(X)`,`r(X)`,`t(X)` construction + the IPA reduction), and aggregation is **§4.3**. Soundness is via §4.1 Theorem 3 (reduction to the inner-product argument's special-soundness, their Theorem 1). The group is the RFC 3526 group-15 (**MODP-3072**) safe-prime subgroup; the discrete-log hardness assumption is over `Z_p*` (finite-field DL), and the non-interactive Fiat-Shamir transform is sound in the **random-oracle model (ROM)** — both assumed, not proved here (L-1, L-3).

Companion / trust-base documents: [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) / [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) (the P-256 siblings — the same protocol, the FIPS group); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (the FUTURE-tier, owner-gated chain-integration proposal); `CRYPTO-C99-SPEC.md` §3.20 (design entry, increments 1-6), §3.13 (the dual-oracle vector gate); `src/crypto/ff/README.md` (module provenance).

---

## 1. Setup: the group, the commitment, binding and hiding

### 1.1 The group `G_q ⊂ Z_p*`

| Constant | Value / derivation | Role |
|---|---|---|
| `p` | the **RFC 3526 MODP-3072** safe prime (group 15), 3072 bits, machine-verified prime with `q = (p-1)/2` also prime | the field modulus |
| `q` | `(p-1)/2`, prime | the prime **subgroup order** — the scalar/exponent field |
| `g` | `4` (`G_LIMB`, `ffgroup.c:17`) — a quadratic residue mod `p`, hence an order-`q` generator of `G_q` | the value generator |
| `h` | `DETERM_FF_H` — a **nothing-up-my-sleeve** second generator (hash-to-group of a fixed DST → mod p → square into `G_q`), pinned KAT, with **unknown `log_g(h)`** | the blinding generator |
| `G_i`, `H_i` | `determ_ff_gen(i, 0)` / `determ_ff_gen(i, 1)` — 13 SHA-256 counter blocks of `family-DST ‖ big-endian index` → reduce mod p → **square into `G_q`** (`ff_hash_to_group`, `ffgroup.c:215-228`; DSTs `ffgroup.c:230-231`) | the bit-vector generators |
| `u` | `determ_ff_gen(0xFFFFFFFF, 0)` (`U_INDEX`, `ffipa.c:19`) | the IPA inner-product generator |

Every generator is an order-`q` element (the group ops verify `pow(gg, q, p) == 1` in the Python reference, `verify_ff_pedersen.py:186-187`), `≠ 1`, and with **no known mutual discrete-log relation** — the load-bearing independence for binding/soundness. Squaring an arbitrary residue into `G_q` (`ff_hash_to_group` `modmul_normal(out, hs, hs)`, `ffgroup.c:225`) forces membership: `(hs²)^q = (hs^q)² = 1` because `hs^{2q} = hs^{p-1} = 1` by Fermat, so every image lies in the order-`q` QR subgroup. The identity of `G_q` is the element `1` (representable), so the MSM is **2-way** (`0` on success, `-1` on a bad scalar/point) rather than the P-256 3-way — a §3.20-specific structural difference from §3.19 recorded in `ffgroup.h:80-88`.

### 1.2 The Pedersen commitment, binding, hiding

The commitment is `C = g^v · h^r mod p` (`determ_ff_pedersen_commit`, `ffgroup.c:132-144`): `modexp(gv, g, v)`, `modexp(hr, h, r)`, `modmul(c, gv, hr)`, with `v ∈ [0, q)` (`v == 0` allowed) and `r ∈ (0, q)` (`r == 0` rejected — no hiding; `ffgroup.c:137-138`). It is homomorphic: `commit(v1,r1) · commit(v2,r2) = commit((v1+v2) mod q, (r1+r2) mod q)` — exercised including a **mod-q wraparound** in the exponents (`verify_ff_pedersen.py:180-182`).

- **FFBP-1 (binding — reduces to finite-field DL).** Given two openings `(v, r) ≠ (v', r')` of the same `C`, one has `g^{v-v'} = h^{r'-r} mod p`, i.e. a nontrivial `log_g(h) = (v-v')·(r'-r)^{-1} mod q` — computing which is exactly the **finite-field discrete logarithm** in `G_q`. So a computationally-bounded prover cannot open a commitment two ways without solving DL. **Assumed, not proved:** finite-field DL hardness in the MODP-3072 subgroup (L-1). The `h`-is-nothing-up-my-sleeve KAT (`test-ff-pedersen-c99` assertion (1)) plus the `q`-subgroup membership of `g`,`h`,`G_i`,`H_i` (Python `_selftest`, `verify_ff_pedersen.py:170-187`) are the *setup-integrity* witnesses that no dlog trapdoor was baked in; they do not prove DL hard.
- **FFBP-2 (hiding — information-theoretic for uniform `r`).** For `r` uniform in `(0, q)`, `h^r` is uniform over `G_q`, so `C = g^v · h^r` is uniform over `G_q` **independent of `v`** — a computationally-unbounded adversary learns nothing about `v` from `C`. This is unconditional (no assumption), given honestly-uniform `r`. The `r == 0` reject (`ffgroup.c:138`) closes the degenerate no-hiding case.

---

## 2. The reduction chain (Pedersen → vector-commit/MSM → IPA → range proof → aggregation)

Each layer is a pure composition over the one below; the algebra below matches Bünz et al. 2018 and the P-256 sibling exactly, with `Z_p*` exponentiation `P^s` playing the role of the P-256 scalar-mult `s·P`.

### 2.1 Vector commit / MSM (inc.2)

`determ_ff_msm(out, scalars, points, n) = Π_i points_i^{scalars_i} mod p` (`ffgroup.c:280-295`), and `determ_ff_vector_commit(out, a, b, n, r) = h^r · Π G_i^{a_i} · Π H_i^{b_i}` (`ffgroup.c:253-278`) — the special case of the MSM over `[h, G_0..G_{n-1}, H_0..H_{n-1}]`. Bounds are checked (scalar `≥ q` or point `0`/`≥ p` → `-1`); a zero scalar's term is skipped (identity `1`). Every subsequent MSM (the IPA folds, the range-proof `A`/`S`/`T`/`P` assemblies) routes through this one primitive.

### 2.2 The inner-product argument (inc.4)

The IPA proves knowledge of vectors `a, b` with committed statement

```
P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>}   mod p
```

(`determ_ff_ipa_commit`, `ffipa.c:79-101`), in `2·log2(n)` group elements + 2 final scalars (`determ_ff_ipa_proof_len = (2·rounds + 2)·E`, `ffipa.c:29-32`). Each round (`ffipa.c:118-167`) sends `L = <a_L,g_R> + <b_R,h_L> + <a_L,b_R>·u` and `R = <a_R,g_L> + <b_L,h_R> + <a_R,b_L>·u`, absorbs them into the **deterministic Fiat-Shamir transcript** (label `DETERM-FF-BP-IPA-v1`, challenge DST `…-challenge`, `ffipa.c:17-18`; seeded with `(P, u, n)`, `ffipa.c:60-68`), derives challenge `x = hash_to_scalar(transcript)`, and folds `a' = a_L·x + a_R·x⁻¹`, `b' = b_L·x⁻¹ + b_R·x`, `g' = g_L^{x⁻¹}·g_R^x`, `h' = h_L^x·h_R^{x⁻¹}`. The verifier (`determ_ff_ipa_verify_gens`, `ffipa.c:176-228`) recomputes the same challenges, folds the generators identically, updates `P' = L^{x²}·P·R^{x⁻²}` per round, and finally checks `P == g_0^{a} · h_0^{b} · u^{a·b}` (`ffipa.c:216-224`). A malformed `L`/`R`/`a_f`/`b_f` rejects via the MSM/scalar bound checks (`ffipa.c:213`, `:219`). This is the §3.20 analogue of the §3.19 IPA in `BulletproofsIPASoundness.md`.

### 2.3 The single-value range proof (inc.5)

For a Pedersen-committed value `V = g^v · h^gamma mod p` (`g = 4`, the inc.1 value generator; `h` the inc.1 blinding generator; `ffrangeproof.c:114-121`), the prover (`determ_ff_rangeproof_prove`, `ffrangeproof.c:87-208`) proves `v ∈ [0, 2^n)` WITHOUT revealing `v`:

1. `a_L =` the `n` bits of `v`; `a_R = a_L − 1^n` (`ffrangeproof.c:110-113`).
2. `A = h^alpha · Π G_i^{a_{L,i}} · Π H_i^{a_{R,i}}`; `S = h^rho · Π G_i^{s_{L,i}} · Π H_i^{s_{R,i}}` — the inc.2 vector-commit shape via `determ_ff_msm` (`ffrangeproof.c:122-131`).
3. Transcript (`DETERM-FF-BP-RANGE-v1`, seeded `(V, n)`, `ffrangeproof.c:72-79`) absorbs `A, S` → challenges `y, z`.
4. `l(X) = (a_L − z·1^n) + s_L·X`; `r(X) = y^n ∘ (a_R + z·1^n + s_R·X) + z²·2^n`; `t(X) = <l(X),r(X)> = t_0 + t_1·X + t_2·X²` (`l0`/`r0`/`r1`, `ffrangeproof.c:140-149`).
5. `T_1 = g^{t_1} · h^{tau_1}`, `T_2 = g^{t_2} · h^{tau_2}` (the inc.1 Pedersen-commit shape; `ffrangeproof.c:150-159`).
6. Transcript absorbs `T_1, T_2` → challenge `x`.
7. `l = l(x)`, `r = r(x)`, `that = <l,r>`, `taux = tau_2·x² + tau_1·x + z²·gamma`, `mu = alpha + rho·x` (`ffrangeproof.c:164-183`).
8. The inc.4 IPA (`determ_ff_ipa_prove_gens`) proves `<l,r> = that` over `(G_i, h'_i = H_i^{y^{-i}}, u)`, with `P_ipa = Π G_i^{l_i} · Π h'^{r_i} · u^{that}` (`ffrangeproof.c:184-198`).

The verifier (`determ_ff_rangeproof_verify`, `ffrangeproof.c:210-292`) recomputes `y,z,x` from the transcript re-seeded with the **supplied** `V`, then:
- **Check 1** (the `that` polynomial / range-binding identity, `ffrangeproof.c:242-258`): `g^{that} · h^{taux} == V^{z²} · g^{delta(y,z)} · T_1^x · T_2^{x²}`, where `delta(y,z) = (z − z²)·<1^n, y^n> − z³·<1^n, 2^n>` (`ta`/`tb`/`delta`, `ffrangeproof.c:247-251`).
- **Check 2** (the IPA relation, `ffrangeproof.c:260-288`): reconstruct `P = A · S^x · Π G_i^{-z} · Π h'^{z·y^i + z²·2^i} · h^{-mu}`, form `P_ipa = P · u^{that}`, and run `determ_ff_ipa_verify_gens(P_ipa, ipa, G, h', u, n)`.

Accept iff both checks pass. Fail-**closed**: any intermediate MSM/scalar return `≠ 0`, or the Check-1 `memcmp` mismatch, leaves `rc = -1` (`ffrangeproof.c:258`).

### 2.4 The aggregated range proof (inc.6)

`determ_ff_agg_rangeproof_prove` / `_verify` (`ffrangeproof.c:337-558`) prove that `m` committed values `v_0..v_{m-1}` **each** lie in `[0, 2^n)` in ONE proof of size `2·log2(m·n)+O(1)` group elements (`m·n ≤ 256`; transcript `DETERM-FF-BP-AGGRANGE-v1`, seeded `(m, n, V_0..V_{m-1})`, `ffrangeproof.c:320-329`). The `m` bit-vectors are concatenated into a length-`m·n` `a_L`; value `j`'s `2^n` slot is scaled by `z^(2+j)` (`zslot[j·n+k] = z^(2+j)·2^k`, `ffrangeproof.c:392-398`); `taux` gains `Σ_j z^(2+j)·gamma_j` (`ffrangeproof.c:432-437`); `delta` gains the `Σ_j z^(3+j)` term (`zsum`, `ffrangeproof.c:498-508`, used as `delta = (z − z²)·<1^{mn},y^{mn}> − zsum·<1^n,2^n>`, `ffrangeproof.c:509-517`); Check 1's V-side becomes `Π_j V_j^{z^(2+j)}` (`vscal[j] = z^(2+j)`, `ffrangeproof.c:519-527`). Setting `m = 1` recovers §2.3 exactly (`agg_proof_len(1,4) == proof_len(4)`, asserted in the Python reference `verify_ff_rangeproof.py:405`).

---

## 3. Completeness, soundness, and honest-verifier zero-knowledge

### 3.1 Completeness

- **FFBP-3 (completeness — the `t_0 = delta(y,z) + z²·v` identity is the reason).** For any `v ∈ [0, 2^n)` and honest randomness, `verify(V, prove(v,…), n) == 0`. The decisive algebraic fact is that the constant term of `t(X)` is `t_0 = <l_0, r_0> = z²·v + delta(y,z)` for an in-range `v` — precisely the quantity Check 1 tests when it equates `g^{that}·h^{taux}` with `V^{z²}·g^{delta}·T_1^x·T_2^{x²}` at the challenge `x`. Because `V = g^v·h^gamma` and `taux = tau_2·x²+tau_1·x+z²·gamma`, the `h`-exponents match iff the `g`-exponents do, i.e. iff `that = t_0 + t_1·x + t_2·x²` with `t_0 = z²·v + delta`. Combined with the IPA per-round invariant (Check 2, `BulletproofsIPASoundness.md` IPA-1's §3.20 analogue), an honest proof always verifies. **Evidence:** `test-ff-rangeproof-c99` runs `prove → verify` accept for `(n,v) ∈ {(2,3),(4,11)}` (`main.cpp:13975-13988`); the Python reference `_selftest` widens to `(n,v) ∈ {(2,3),(4,11),(8,200)}` (`verify_ff_rangeproof.py:375-379`). The aggregated `_selftest` covers `(m,n) ∈ {(2,2),(2,4),(4,2)}` (`verify_ff_rangeproof.py:391-396`). **Caveat:** verified on the fixed witness family / bounded `n`, `m·n` (L-2); completeness for arbitrary `v` follows from the algebra, not exhaustive coverage.

### 3.2 Soundness

- **FFBP-4 (soundness — a verifying proof binds `v ∈ [0, 2^n)`, reduction to Bünz §4 under finite-field DL + ROM).** A proof that `verify` accepts for commitment `V` binds the prover to a `v ∈ [0, 2^n)` with `V = g^v·h^gamma` — a prover cannot make `verify` accept for a `V` committing to an out-of-range value, except by breaking finite-field discrete log in `G_q` or the ROM assumption. **Argument (reduction, NOT re-proved here):** Bünz et al. 2018 §4.1 Theorem 3 — the range proof reduces to the inner-product argument's special-soundness (their Theorem 1) plus the binding (FFBP-1) of the commitments `V`/`A`/`S`/`T_1`/`T_2` under DL. The `y`-challenge enforces the Hadamard constraint `a_L ∘ a_R = 0` (bits are 0/1), the `z`-challenge folds in `a_R = a_L − 1` and `v = <a_L, 2^n>`, and the `x`-challenge binds the polynomial identity of §3.1 — an extractor from enough accepting transcripts recovers a valid `(v, gamma)` opening with `v ∈ [0,2^n)`, else it yields a nontrivial dlog relation among the independent generators. The Fiat-Shamir transform inherits this in the ROM. **Why out-of-range fails, concretely:** an out-of-range `v` (e.g. `v = 2^n`) has `n`-bit decomposition `aL` encoding `v mod 2^n ≠ v`, so the constructed `t_0` matches `z²·(v mod 2^n) + delta ≠ z²·v + delta`; Check 1 (which uses the *actual* `V = g^v·h^gamma`) then mismatches. **Evidence (reject witnesses, NOT an extractor):** `test-ff-rangeproof-c99` (`main.cpp:13989-13995`) and the Python `_selftest` — a byte-flipped `that` region rejects, a proof made for `V` does NOT verify under a different `V'`, and an out-of-range `v = 2^n` cannot yield a verifying proof. The IPA's own soundness reject is witnessed by `test-ff-ipa-c99` (wrong `P` + tampered proof, `main.cpp:13953-13956`; Python `verify_ff_ipa.py:214-218`, `n ∈ {1,2,4,8}`). **Caveat:** these are *existence witnesses* that the deployed reject paths fire; they are **not** a machine-checked extractor and **not** a proof of soundness (that is the cited literature theorem under DL + ROM, L-1/L-3).

- **FFBP-5 (aggregation soundness — the `z^(2+j)` per-slot binding rejects an out-of-range value in every batch position).** A verifying aggregated proof binds **each** `v_j ∈ [0, 2^n)`. **Argument (Bünz §4.3, NOT re-proved here):** aggregation weights value `j`'s `2^n` slot by `z^(2+j)` and its commitment contribution by `V_j^{z^(2+j)}` in Check 1 (`ffrangeproof.c:519-527`); the distinct powers of `z` separate the `m` values into independent slots, so an out-of-range `v_j` anywhere breaks the `t_0 = Σ_j z^(2+j)·v_j + delta` identity in *its* slot, and Check 1 rejects regardless of position. Aggregation preserves the special-soundness of the single-value proof. **Evidence:** `test-ff-agg-rangeproof-c99` sets `v[m-1] = 2^n` (the **last** batch position) and requires reject, plus tamper + wrong-`V` reject, for `(m,n) ∈ {(2,2),(2,4)}` (`main.cpp:14030-14037`); the Python `_selftest` sets `vbad[m-1] = 1<<n` for `(m,n) ∈ {(2,2),(2,4),(4,2)}` (`verify_ff_rangeproof.py:397-400`). **Caveat:** the reject witness is at position `m-1`; the *every-position* claim is the §4.3 argument, corroborated by the byte-exact dual oracle (FFBP-7), not exhaustively witnessed per position (L-2).

### 3.3 Honest-verifier zero-knowledge

- **FFBP-6 (HVZK — the proof reveals nothing about `v` beyond `v ∈ [0, 2^n)`).** The single-value proof is honest-verifier zero-knowledge: `V` is a perfectly-hiding Pedersen commitment (FFBP-2); `A` and `S` are blinded by uniform `alpha`, `rho` (`h^alpha`, `h^rho`); `T_1`, `T_2` by uniform `tau_1`, `tau_2`; `taux = tau_2·x²+tau_1·x+z²·gamma` and `mu = alpha+rho·x` are the blinded openings; and `s_L`, `s_R` are uniform masks so that `l = l(x)`, `r = r(x)` (hence `that = <l,r>`) leak nothing about `a_L`,`a_R` (the bits of `v`). A simulator with the challenges can produce an identically-distributed transcript without `v` — the §4.1 Theorem-3 HVZK claim of Bünz et al. **Assumed, not proved here:** HVZK is the cited literature theorem; this document does not machine-check a simulator. **Structural corroboration:** the prover draws `alpha`/`rho`/`s_L`/`s_R`/`tau_1`/`tau_2` from outside (`determ_ff_rangeproof_prove` takes them as parameters, `ffrangeproof.c:87-90`) — here caller-supplied purely so the KAT is reproducible; a real deployment MUST draw them from a CSPRNG for the hiding to hold (L-2, and the CT caveat NC-3). **Caveat:** the proof reveals `n` (the bit-width, hence the range) and the fact of a valid commitment; it does not reveal `v`, `gamma`, or the bits.

### 3.4 Determinism / conformance

- **FFBP-7 (dual-oracle byte-exactness — the C bytes equal an independent from-scratch Python's over the §3.13 corpora).** For every corpus vector, the shipped C recomputes the entire artifact (commitment(s) + every proof field + the inner IPA) and matches, **byte-for-byte**, the values an independent from-scratch Python implementation generated using native bignums. **Evidence:** the §3.13 dual-oracle posture over the five corpora — `ff_pedersen.json` (14 vectors: `H` KAT, commits incl. mod-q wraparound, gen KATs, vector_commit, MSM incl. the all-zero identity), `ff_scalar.json` (14: reduce/add/mul/inv/hash_to_scalar), `ff_ipa.json` (4: commit + prove for `n ∈ {2,4}`, the file half re-verifying each proof), `ff_rangeproof.json` (2: `n ∈ {2,4}`), `ff_aggrangeproof.json` (2: `(m,n) ∈ {(2,2),(2,4)}`). The independent Python references are `tools/verify_ff_pedersen.py` / `verify_ff_scalar.py` / `verify_ff_ipa.py` / `verify_ff_rangeproof.py`, whose self-tests each pass — the Pedersen reference machine-verifies safe-prime + `q`-subgroup membership + binding + homomorphism (`verify_ff_pedersen.py:169-205`) before emitting. Determinism is a structural consequence of the randomness-free transcript (`hash_to_scalar` challenges only). **Caveat:** byte-exact over exactly the frozen vectors (one witness family per dimension), not the input space (L-2); the Python oracle's own faithfulness to Bünz §4 is the (P-oracle) assumption, corroborated by its round-trip + out-of-range + tamper + wrong-`V` self-tests.

- **FFBP-8 (proof_len contract + trust inheritance — no new arithmetic above inc.1-3).** `determ_ff_ipa_proof_len(n) = (2·rounds+2)·E` and `determ_ff_rangeproof_proof_len(n) = 7·E + ipa_proof_len(n)` (`RP_HDR + …`, `ffrangeproof.c:45-48`), `agg_proof_len(m,n) = 7·E + ipa_proof_len(m·n)` (`ffrangeproof.c:315-318`), all `0` for a non-power-of-two / oversized dimension (`ff_rounds` / `rp_rounds` / `agg_rounds`, `ffipa.c:22-27`, `ffrangeproof.c:38-43`, `:306-313`), and `prove`/`verify` reject such dimensions with `-1`. Every group/scalar op in inc.4-6 is a call into an inc.1-3 primitive validated by `test-ff-pedersen-c99` (7 assertions) / `test-ff-scalar-c99` (6 assertions); inc.4-6 introduce **no new field or group arithmetic**. **Evidence:** `test-ff-ipa-c99` pins `plen == (2·rr+2)·E` (`main.cpp:13949`); the `_selftest`s pin the range/agg lengths (`verify_ff_rangeproof.py:378`, `:395`, `:405`). **Caveat:** a forward-reference — the inc.1-3 bignum correctness (CIOS Montgomery, hash-to-group, mod-q field) is discharged by its own KAT gates + the Python `_selftest`s, not re-derived here.

---

## 4. Validation map

Each claim ↔ its structural test subcommand, its §3.13 dual-oracle corpus, and the two independent soundness audits. **PROVEN-by-KAT** = byte-pinned or reject-witnessed by a shipped, green test; **argued-in-prose** = a reduction to the cited literature theorem (assumed, not machine-checked here).

| Claim | Structural test (`determ …`) | §3.13 dual-oracle corpus | Independent soundness audit | Status |
|---|---|---|---|---|
| **FFBP-1** binding = finite-field DL | `test-ff-pedersen-c99` (2)/(4): commit/verify + wrong-v/wrong-r reject; `h` KAT (1); subgroup membership | `ff_pedersen.json` (14) | Setup integrity (no dlog trapdoor: `h` NUMS + `g`,`h`,`G_i`,`H_i` order-`q`, `verify_ff_pedersen.py:170-187`) — the **hardness itself is argued-in-prose** (L-1) | KAT (setup) + prose (hardness) |
| **FFBP-2** hiding = info-theoretic | `test-ff-pedersen-c99` (4): `r==0` reject | `ff_pedersen.json` | Unconditional (uniform `r` ⇒ `h^r` uniform) — argued-in-prose | prose (unconditional) |
| **FFBP-3** completeness (`t_0=delta+z²v`) | `test-ff-rangeproof-c99`: `prove→verify` accept `(n,v)∈{(2,3),(4,11)}`; `test-ff-agg-…` `(m,n)∈{(2,2),(2,4)}` | `ff_rangeproof.json` (2), `ff_aggrangeproof.json` (2) | Single-value: re-derived from **Bünz et al. 2018 §4.2**, confirmed `t_0 = delta(y,z) + z²·v` (the range-binding identity holds numerically) | KAT (round-trip) + prose (identity) |
| **FFBP-4** soundness (single) | `test-ff-rangeproof-c99`: out-of-range `v=2^n` + tamper + wrong-`V` reject; `test-ff-ipa-c99` wrong-`P`/tamper reject | `ff_rangeproof.json`, `ff_ipa.json` (4) | Re-derived from **§4.1 Thm 3 / §4.2**: reduction to IPA special-soundness + Pedersen binding under DL + ROM | KAT (reject witnesses) + prose (extractor) |
| **FFBP-5** soundness (aggregated) | `test-ff-agg-rangeproof-c99`: one value `v[m-1]=2^n` OOR + tamper + wrong-`V` reject | `ff_aggrangeproof.json` (2) | Re-derived from **§4.3**: the `z^(2+j)` binding rejects an out-of-range value in **every** batch position | KAT (position `m-1`) + prose (every position) |
| **FFBP-6** HVZK | (no dedicated test; simulator not machine-checked) | (structural: blinders caller-supplied) | **§4.1 Thm 3** HVZK — argued-in-prose | prose |
| **FFBP-7** dual-oracle byte-exactness | `test-c99-vectors` (binary half) + `test_c99_vector_files.sh` (Python file half) | all five corpora (14+14+4+2+2 = 36 vectors) | C bytes == independent from-scratch Python bytes; Python `_selftest`s pass (safe-prime/subgroup/binding/round-trip/OOR/tamper) | KAT (byte-pinned) |
| **FFBP-8** proof_len + trust inheritance | `test-ff-ipa-c99` length pin; `test-ff-pedersen-c99`/`test-ff-scalar-c99` primitive gates | all five corpora | No new arithmetic above inc.1-3 (forward-reference) | KAT (length) + prose (inheritance) |

The two-leg split is the standard §3.13 defense-in-depth: the structural `test-ff-*-c99` subcommands are the **reject-path + round-trip + determinism + out-of-range** witnesses the accept-only vectors cannot provide; the byte gate (`test-c99-vectors` binary half + `test_c99_vector_files.sh` Python file half) is the **dual-oracle conformance** witness (C99 == independent Python over frozen bytes). Their conjunction — bounded by L-1..L-5 — is what "the C99 finite-field Bulletproofs stack is complete, deterministic, byte-conformant, and binding under finite-field DL + ROM" means for this §3.20 library primitive.

---

## 5. Non-claims (NC-1 .. NC-4) and limits (L-1 .. L-5)

### Non-claims
- **NC-1 — Not the multi-exp-optimized verifier.** The verifier reconstructs `P` and folds the IPA generators explicitly (`ffipa.c:192-215`) rather than collapsing the whole check into one `O(n)` multi-exponentiation. Same accept set, deliberately non-optimized computation.
- **NC-2 — Not a consensus or wallet primitive.** No Determ chain/ledger/wallet path constructs, proves, or verifies a finite-field range proof. This is an additive **library primitive with no in-tree consumer** (`ffgroup.h` "LIBRARY PRIMITIVE — no chain call site"). A confidential-transaction chain integration is a separate, owner-gated, consensus-critical step — see [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (a FUTURE-tier proposal that decides nothing).
- **NC-3 — Not constant-time.** The square-and-multiply `modexp_c` branches on **secret** exponent bits (`ffgroup.c:98-111`), and the `msm`/`vector_commit` zero-scalar skip is data-dependent on the witness (`ffgroup.c:287`, `:263`/`:270`; e.g. `v`'s bits, `s_L`/`s_R`). A production prover needs a constant-time (windowed/Montgomery-ladder-style) modexp and a constant-time multi-exp. This document asserts **functional** correctness only, not timing (L-4). CT-hardening is the owner-gated step and, per the design doc, a hard requirement before any on-chain prover use.
- **NC-4 — Not post-quantum.** Binding (FFBP-1) rests on finite-field discrete log, which Shor's algorithm solves on a scalable quantum computer. This is a classical-adversary construction (L-5).

### Limits
- **L-1 — Soundness/binding is not proven; it is assumed under finite-field DL + generator independence.** FFBP-1/FFBP-4/FFBP-5 are reductions to the Bünz §4 theorems; the tests exercise reject paths (tamper, wrong-`V`, out-of-range), **not** a machine-checked extractor. A break of DL in the MODP-3072 subgroup breaks binding regardless of any byte-exactness here.
- **L-2 — Bounded input set.** FFBP-7 quantifies over exactly the frozen corpus vectors (14+14+4+2+2); the structural round-trip / determinism / soundness widen to `(n,v) ∈ {(2,3),(4,11)}` C / `{(2,3),(4,11),(8,200)}` Python for single, `(m,n) ∈ {(2,2),(2,4)}` C / `{(2,2),(2,4),(4,2)}` Python for aggregated — but are not byte-pinned beyond the corpus. HVZK's hiding assumes the blinders are drawn from a CSPRNG (they are caller-supplied for KAT reproducibility). `m·n` is kept small because the 3072-bit modexp is **~1700× slower** than the P-256 stack (CRYPTO-C99-SPEC §3.20).
- **L-3 — The Fiat-Shamir transform's soundness is in the ROM.** The non-interactive challenges are `determ_ff_hash_to_scalar(transcript)` (13 SHA-256 counter blocks → mod q); the argument that this is as sound as the interactive protocol is a ROM result. Assumed, not proved.
- **L-4 — Timing out of scope.** The `modexp_c` secret-bit branch (NC-3) and the `msm`/`vector_commit` zero-scalar skip are data-dependent on the secret witness; a constant-time prover is the owner-gated hardening step (CRYPTO-C99-SPEC §3.12 / `ConstantTimeInventory.md`).
- **L-5 — Not post-quantum (NC-4).** Finite-field DL is broken by Shor. A PQ range proof (lattice / hash-based) is a separate, unrelated construction, out of scope for this stack.

---

## 6. Status

- **Spec.** Complete (this document).
- **All five structural tests + both byte-gate halves shipped and green.** `test-ff-pedersen-c99` (7 assertions: `H` KAT, commit/verify, homomorphism, input validation, gen families, vector_commit==MSM, MSM identity/reject), `test-ff-scalar-c99` (6), `test-ff-ipa-c99` (round-trip + length + wrong-`P`/tamper reject, `n ∈ {1,2,4}`), `test-ff-rangeproof-c99` (round-trip + out-of-range + tamper + wrong-`V`, `(n,v) ∈ {(2,3),(4,11)}`), `test-ff-agg-rangeproof-c99` (round-trip + one-value-OOR + tamper + wrong-`V`, `(m,n) ∈ {(2,2),(2,4)}`); the binary half (`test-c99-vectors`) and Python file half (`test_c99_vector_files.sh`) validate the five §3.13 corpora byte-for-byte against the independent from-scratch Python.
- **Claims.** FFBP-1 (binding = finite-field DL), FFBP-2 (hiding = info-theoretic), FFBP-3 (completeness via `t_0 = delta + z²·v`), FFBP-4 (single-value soundness — reduced to Bünz §4 under DL + ROM; reject witnesses, NOT an extractor), FFBP-5 (aggregation soundness — the `z^(2+j)` per-slot binding), FFBP-6 (HVZK — argued from §4.1 Thm 3), FFBP-7 (dual-oracle byte-exactness — full stack, two independent impls), FFBP-8 (proof_len contract + trust inheritance, no new arithmetic above inc.1-3) — all closed at the KAT/prose split recorded in §4.
- **Non-claims (NC-1..NC-4).** Not the multi-exp-optimized verifier; not a consensus/wallet primitive (owner-gated CT integration per the design doc); not constant-time (owner-gated CT hardening); not post-quantum.
- **Limits (L-1..L-5).** Binding/soundness assume finite-field DL + generator independence (reduction, not extractor); conformance is over the frozen corpora + bounded structural dimensions; Fiat-Shamir soundness is in the ROM; timing → §3.12 / `ConstantTimeInventory.md`; not PQ (Shor).
