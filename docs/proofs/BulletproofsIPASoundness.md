> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# BulletproofsIPASoundness — Determ C99 Bulletproofs inner-product argument over NIST P-256: completeness / soundness / determinism + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **C99-native Bulletproofs inner-product argument (IPA)** shipped in `src/crypto/pedersen/ipa.c` (public API `include/determ/crypto/pedersen/ipa.h`, CRYPTO-C99-SPEC.md §3.19 **increment 4**). It answers two questions the individual test outputs do not answer on their own: (1) **what** the primitive computes, mapped onto the Bulletproofs §3 inner-product argument over NIST P-256 and its exact deterministic Fiat-Shamir transcript, verified statement-by-statement against the source; and (2) **how much** the two validation legs — the structural/negative unit test (`determ test-bp-ipa-c99`) and the dual-oracle byte gate (both §3.13 halves over `tools/vectors/bp_ipa.json`) — jointly establish about the argument's **completeness**, **special-soundness / binding**, **determinism / non-interactivity**, and byte-exact **interop**, and where their reach stops.

The module is deliberately thin. It is written **entirely against the §3.19 Pedersen (`pedersen_gen` / `pedersen_msm`) and §3.8c P-256 point/scalar PUBLIC APIs** (`ipa.c:1-9`), introducing **no new group arithmetic of its own**. The only new scalar logic is a local `sc_add` (a big-endian modular add with a single conditional subtraction of `n`, `ipa.c:27-43`) and the `inner_product` accumulator over it (`:45-54`); every point operation and every mod-`n` scalar multiply/inverse/hash-to-scalar is a call into an already-gated primitive. Its correctness therefore composes on top of those layers' own validation (`test-p256-c99` OpenSSL EC parity + `test-p256-h2c-c99` RFC 9380 vectors + `test-pedersen-c99`) rather than re-deriving it; the only new logic is the **recursive fold + the transcript assembly**, which the structural gate pins by algebraic property and `tools/vectors/bp_ipa.json` pins byte-for-byte against an independent Python re-derivation.

This is the **last** of the four range-proof / confidential-transaction track increments authorized 2026-07-04: the log-size **subroutine** the range proof is built on — **library-primitive-first, KAT-gated, ZERO consensus touch** (`ipa.h:12` "LIBRARY PRIMITIVE — no chain call site"; additive, not wired into any chain, ledger, or wallet code path). It is the successor to `PedersenCommitmentSoundness.md`'s NC-4 ("no inner-product argument / range-proof protocol yet").

## Scope

**In scope.** The exported operations, verified against `ipa.c`:
- `determ_ipa_commit` — the statement commitment `P = <a,g> + <b,h> + <a,b>*u` over the fixed generators (`:116-133`);
- `determ_ipa_prove` — the recursive `n → n/2` fold producing the proof `L[log₂n] ‖ R[log₂n] ‖ a_final ‖ b_final` (`:135-202`);
- `determ_ipa_verify` — the challenge-recompute + `P'` update + final one-round check (`:204-246`);
- `determ_ipa_proof_len` — the `66·log₂(n) + 64`-byte length contract, `0` for a non-power-of-two or `n > 256` (`:85-88`);
- the deterministic Fiat-Shamir transcript (`tr_init`/`tr_absorb`/`tr_challenge`, `:90-114`): a pure function of `(P, u, n)` seeded, then each `L`,`R` absorbed, each challenge re-absorbed;
- the fixed ciphersuite generators: `g_i = pedersen_gen(i,0)`, `h_i = pedersen_gen(i,1)`, `u = pedersen_gen(0xFFFFFFFF,0)` (`:56-61`, `:21`).

This is **increment 4** of the range-proof / confidential-transaction track (owner-authorized 2026-07-04): **library-primitive-first, ZERO consensus touch** (`ipa.h:1-12`).

**Out of scope.**
- **The range-proof protocol itself** — the bit-decomposition of `v` into `a_L`/`a_R`, the `l(X)`/`r(X)` polynomials, the `T_1`/`T_2` polynomial commitments, and the `t̂`/`τ_x`/`μ` scalars that bind a committed value into a proof of `v ∈ [0, 2ⁿ)`. The IPA is the log-size **subroutine** that compresses the final `<l, r> = t̂` check, **not** the full range proof (NC-1). A verifying IPA proves knowledge of `a,b` opening the *given* `P`; it proves **no range predicate** whatever.
- **Batch verification** — the verifier here folds `g,h` explicitly, one round at a time; it does not batch multiple proofs into a single multi-exponentiation (NC-2).
- **The single multi-exponentiation verify optimization** — the standard Bulletproofs verifier collapses the whole fold into one `O(n)` multi-exp with the `s_i` scalar products; this implementation instead folds `g,h` **explicitly** round-by-round (`ipa.c:228-231`, matching the Python reference `verify_bp_ipa.py:117-138`). Same accept set, different (non-optimized) computation (NC-2).
- **Aggregation** — proving multiple values / multiple ranges in one argument (NC-2).
- **Any chain / wallet wiring** — no Determ code path constructs, proves, or verifies an IPA (NC-3).
- **Timing side channels** — `sc_add`'s conditional subtraction and the `pedersen_msm` zero-scalar skip are data-dependent on the secret `a,b`; a range prover needs a constant-time variant. The CT-hardening is the owner-gated step (NC-4, L-4).

**Authoritative external sources.** Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell, **"Bulletproofs: Short Proofs for Confidential Transactions and More"** (IEEE S&P 2018) — the inner-product argument is §3 (Protocol 1 / the recursive `Protocol 2`), and its special-soundness / witness-extraction theorem is Theorem 1 there. The group is NIST **P-256** / secp256r1 (**FIPS 186-5** / SP 800-186). The Fiat-Shamir challenge is derived via **RFC 9380** `hash_to_field` with the group order `n` as modulus (the §3.8c `hash_to_scalar`, m=1, L=48). Special-soundness rests on the P-256 **discrete-log** hardness assumption (ECDLP); the non-interactive Fiat-Shamir transform's soundness additionally rests on the **random-oracle model (ROM)** for the transcript hash — both assumed, not proved here (L-1, L-3).

Companion / trust-base documents: `docs/proofs/PedersenCommitmentSoundness.md` (increments 1-3 — the `pedersen_gen` generator families and the `pedersen_msm` this IPA reduces every group operation to; its PC-9/PC-11 are the reason the generator-independence and MSM-correctness under each IPA operation are themselves trustworthy — the forward-referenced base); `docs/proofs/P256CryptoStackAudit.md` (the correctness + constant-time audit of the underlying P-256 field / RCB complete-addition / CT ladder / SSWU hash-to-curve / mod-n scalar ops — the reason `point_mul`/`point_add`/`scalar_mul_mod_n`/`scalar_inv_mod_n`/`hash_to_scalar` are trustworthy); `docs/proofs/VectorGateComposition.md` / `OprfConformanceMap.md` (the two-half §3.13 gate mechanics this document instantiates for the IPA corpus); `CRYPTO-C99-SPEC.md` §3.19 (design entry, increment 4), §3.8c (the curve + hash-to-scalar enablers), §3.13 (the dual-oracle vector gate); `docs/proofs/ConstantTimeInventory.md` / §3.12 (the timing boundary handed off in L-4).

---

## 1. The construction map

### 1.1 The statement and the fixed generators

The IPA proves knowledge of two length-`n` scalar vectors `a`, `b` (mod the prime order `n_ord`) that open a public commitment `P`:

```
P = <a, g> + <b, h> + <a,b>·u      over the P-256 group of prime order n_ord
  = Σ_{i<n} a_i·g_i  +  Σ_{i<n} b_i·h_i  +  (Σ_{i<n} a_i·b_i)·u
```

The generators are **fixed by the ciphersuite** (so prover and verifier agree without transmitting them), each a nothing-up-my-sleeve RFC 9380 hash-to-curve image via `pedersen_gen` (`ipa.c:56-61`, `gen_c`):

| Generator | Derivation | Source |
|---|---|---|
| `g_i` (`i = 0 … n−1`) | `pedersen_gen(i, 0)` — the increment-2 "G" family (DST `DETERM-PEDERSEN-VEC-G-…`) | `:122`, `:143`, `:209` |
| `h_i` (`i = 0 … n−1`) | `pedersen_gen(i, 1)` — the increment-2 "H" family (DST `DETERM-PEDERSEN-VEC-H-…`) | `:126`, `:144`, `:210` |
| `u` (the inner-product generator) | `pedersen_gen(0xFFFFFFFF, 0)` — the "G" family at index `0xFFFFFFFF` | `:131`, `:146`, `:212` (`U_INDEX`, `:21`) |

`u` shares the **G-family DST** with `g_i` but at index `0xFFFFFFFF`; since supported `n ≤ 256` (`DETERM_IPA_MAX_N`, `ipa.h:31`), no `g_i` ever uses that index. `u` is therefore a **distinct random-oracle image** from every `g_i` (different index, same DST) and from every `h_i` (entirely different DST), so its discrete log relative to the `g`/`h` families is unknown — the load-bearing independence for soundness (§1.2, IPA-2, L-1). `pedersen_gen`'s generator-family independence is the subject of `PedersenCommitmentSoundness.md` PC-9.

**Wire convention** (inherited from §3.8c P-256): scalars `a_i`, `b_i` are 32-byte **big-endian** integers `< n_ord`; points are 33-byte **SEC1 compressed** (`0x02`/`0x03` ‖ X). A proof for vector length `n` is `L[log₂n] ‖ R[log₂n] ‖ a_final ‖ b_final` = `66·log₂(n) + 64` bytes (`determ_ipa_proof_len`, `:85-88`; e.g. `n=1 → 64`, `n=4 → 196`, `n=8 → 262`).

### 1.2 The protocol (matching `ipa.c` exactly)

**The commitment** (`determ_ipa_commit`, `:116-133`) assembles the length-`2n+1` multi-exp `[a‖b‖<a,b>]` against the point list `[g₀…g_{n−1} ‖ h₀…h_{n−1} ‖ u]` and reduces it via `determ_pedersen_msm` — exactly the statement `P = <a,g> + <b,h> + <a,b>·u`. `<a,b>` is computed by the local `inner_product` (`:45-54`).

**The transcript** (`:90-114`) is a deterministic, append-only byte buffer:
- `tr_init` (`:93-102`) seeds `LABEL "DETERM-BP-IPA-v1"` ‖ `P` (33 B) ‖ `u` (33 B) ‖ `n` (4-byte big-endian).
- Each round absorbs `L` then `R` (`tr_absorb`, `:103-105`).
- `tr_challenge` (`:106-114`) hashes the **whole buffer** via `determ_p256_hash_to_scalar` under the challenge DST `"DETERM-BP-IPA-v1-challenge"`, rejects a zero challenge (negligible), and **re-absorbs** the 32-byte challenge so subsequent challenges depend on it. This is the Fiat-Shamir replacement for the interactive verifier's coins.

**Each prover round** `n → n/2` (`m = n/2`, `:151-198`) sends:
```
L = <aL, gR> + <bR, hL> + <aL, bR>·u        (:156-164)
R = <aR, gL> + <bL, hR> + <aR, bL>·u        (:166-174)
```
absorbs `L, R`, draws `x = tr_challenge(...)` and `xinv = x⁻¹ mod n_ord` (`:176-178`, via `determ_p256_scalar_inv_mod_n`), then folds **in place**:
```
a' = aL·x   + aR·xinv        b' = bL·xinv + bR·x           (:181-189, sc_add over scalar_mul_mod_n)
g' = xinv·gL + x·gR          h' = x·hL   + xinv·hR          (:191-194, fold_point)
```
After `log₂(n)` rounds it emits `L[·]`, `R[·]`, and the final scalars `a[0]`, `b[0]` (`:199-201`).

**The verifier** (`:204-246`) recomputes the same challenges from the same transcript (seeded identically with the *supplied* `P`), folds `g,h` **identically** to the prover (`:228-231`), and updates the running commitment each round:
```
P' ← x²·L + P' + xinv²·R        (:232-236, a 3-term pedersen_msm)
```
It accepts iff, after all rounds, the fully-folded single-element statement holds (`:239-245`):
```
P_final == a_final·g[0] + b_final·h[0] + (a_final·b_final)·u
```
via a `memcmp` of the two 33-byte compressed encodings (`:245`).

### 1.3 The key per-round invariant (why completeness holds)

The decisive algebraic fact is that the fold **preserves the statement**: with `g' = xinv·gL + x·gR`, `h' = x·hL + xinv·hR`, `a' = x·aL + xinv·aR`, `b' = xinv·bL + x·bR`, and `P' = x²·L + P + xinv²·R`,

```
<a',g'> + <b',h'> + <a',b'>·u  ==  P'          (the invariant)
```

One-line derivation. Expand `<a', g'> = <x·aL + xinv·aR, xinv·gL + x·gR>`. The cross terms `x·xinv` collapse the "diagonal" `<aL,gL> + <aR,gR>` back into `<a,g>` (the un-primed inner product), and the off-diagonal terms are `x²·<aL,gR> + xinv²·<aR,gL>`. Symmetrically for `<b',h'>` the off-diagonals are `x²·<bR,hL> + xinv²·<bL,hR>`, and for `<a',b'>·u` they are `x²·<aL,bR>·u + xinv²·<aR,bL>·u`. Collecting: the `x²` group is exactly `<aL,gR> + <bR,hL> + <aL,bR>·u = L`, and the `xinv²` group is exactly `<aR,gL> + <bL,hR> + <aR,bL>·u = R`. So `<a',g'> + <b',h'> + <a',b'>·u = (<a,g> + <b,h> + <a,b>·u) + x²·L + xinv²·R = P + x²·L + xinv²·R = P'`. ∎

Thus an honest prover's folded `(a', b', g', h', P')` **still satisfy the statement**, and by induction the final single-element check `P_final == a_final·g[0] + b_final·h[0] + a_final·b_final·u` holds — which is completeness. This invariant is not merely argued: it is **machine-verified at every fold** by the Python reference's `_check_invariant` (`verify_bp_ipa.py:178-200`), which recomputes `commit_P(a,b,g,h,u)` from the folded vectors/generators and asserts it equals the `P'`-updated running point, for every round and every `n ∈ {1,2,4,8,16}` (IPA-1).

---

## 2. Soundness / conformance claims (IPA-1 .. IPA-6)

Each claim states the claim, the **evidence** (which `test-bp-ipa-c99` assertion, which `bp_ipa.json` vector, or which Python oracle proves it), and honest caveats. The `determ test-bp-ipa-c99` checks are at `src/main.cpp:13539-13584`; the two-vector corpus is `tools/vectors/bp_ipa.json` (`n=4`, `n=8`), consumed by both §3.13 halves; the Python reference is `tools/verify_bp_ipa.py`.

### IPA-1 — Completeness: an honestly-generated proof always verifies (all n), the per-round invariant is the reason

**Claim.** For any witness `a, b` and `P = commit(a,b)`, `verify(P, prove(a,b,P,n), n) == 0` — an honest proof accepts, for every supported `n`.

**Evidence.**
- **Structural round-trip (C):** `test-bp-ipa-c99` (2)-(4) (`main.cpp:13560-13578`) runs `commit → prove → verify` and requires accept for `n ∈ {1,2,4,8}` (the `rt` flag; a failure breaks the loop). Witness `a_i = 7i+3`, `b_i = 5i+11` (`mkab`, `:13549-13552`).
- **Round-trip (Python), wider n:** `verify_bp_ipa._selftest` (`:203-221`) runs `prove`+`verify` and asserts accept for `n ∈ {1,2,4,8,16}`.
- **The decisive reason — the per-round invariant:** `_check_invariant` (`:178-200`, called by `_selftest` for every `n`) machine-verifies `<a,g>+<b,h>+<a,b>·u == P_running` **at every fold**, i.e. the §1.3 identity holds through the whole recursion. This is the algebraic oracle that *explains* completeness rather than merely observing it on outputs: it checks the folded statement, independent of `verify()`.

**Caveat.** Round-trip accept is verified on the fixed witness family (`7i+3`, `5i+11`) at `n ≤ 16` (Python) / `n ≤ 8` (C structural), plus the two corpus points `n ∈ {4,8}`; the invariant check is the general algebraic reason but is itself run over the same bounded `n` set (L-2). No test enumerates all witnesses — completeness for arbitrary `a,b` follows from the invariant's algebra (§1.3), not from exhaustive coverage.

### IPA-2 — Special-soundness / binding: a verifying proof binds the committed `<a,b>` relation (reduction to Bulletproofs §3 under ECDLP + ROM)

**Claim.** A proof that `verify` accepts for commitment `P` binds the prover to knowledge of vectors `a,b` with `P = <a,g> + <b,h> + <a,b>·u` over the fixed, mutually-independent generators — a prover cannot make `verify` accept for a `P` it does not know such an opening of, except by breaking P-256 discrete log or the random-oracle assumption on the transcript hash.

**Argument (reduction, NOT re-proved here).** This is the Bulletproofs inner-product argument's **special-soundness** theorem (Bünz et al. 2018, §3, Theorem 1): from `3` (more generally, a tree of) accepting transcripts with distinct challenges at each of the `log₂(n)` rounds, the extractor recovers a valid witness `(a,b)`; a prover that convinces the verifier without knowing such a witness yields a nontrivial discrete-log relation among the independent generators `g_i, h_i, u`, contradicting ECDLP on P-256. The Fiat-Shamir transform (challenges = `hash_to_scalar(transcript)` rather than verifier coins) makes this non-interactive and inherits soundness in the **random-oracle model** for the transcript hash. The generator independence the extractor needs is precisely that `u`'s discrete log to the `g`/`h` families — and the `g_i`/`h_i` cross-dlogs — are unknown (§1.1; `PedersenCommitmentSoundness.md` PC-9), which the nothing-up-my-sleeve RFC 9380 derivation supplies under the same ROM.

**Evidence (structural reject witnesses, NOT an extractor).** `test-bp-ipa-c99` (`main.cpp:13560-13580`, the `sound` flag) and the Python `_selftest` (`:211-220`) exercise soundness-shaped behaviour on the *implemented* verifier:
- **Wrong commitment rejects.** C: perturb the witness `a` (flip a byte, `:13574-13576`) to get `P2 = commit(a2,b)`, and require `verify(P2, pf, n) != 0` — a proof made for `P` must NOT verify under a different commitment `P2`. Python: `verify(P + u, …)` rejects (`:212-213`).
- **Tampered proof rejects.** C: flip one byte at the `L/R` midpoint (`:13572-13573`) and require reject. Python: flipping the final `a` (`:215-216`), and (for `n>1`) tampering `L[0]` (`:218-220`), both reject.

**Caveat.** These are **existence witnesses** that the implemented reject paths fire on the *specific* tampers injected; they are **not** a machine-checked extractor and **not** a proof of special-soundness (that is the cited literature theorem under ECDLP + ROM, L-1/L-3). No test can exhibit hardness of ECDLP, and none constructs the `3`-transcript extractor. What the tests establish is that a wrong-`P` / byte-tampered proof does not slip through the *deployed* verifier on the covered cases — the reject side the accept-only corpus is structurally blind to.

### IPA-3 — Determinism / non-interactivity: the transcript is a pure function of `(P, generators, messages)`

**Claim.** `prove` is deterministic (same inputs → identical proof bytes), and `verify` recomputes exactly the prover's challenges — so the proof is bound to `P`: a proof for `P` does not verify under a different `P'` even though the generators are identical.

**Evidence.**
- **Determinism.** `test-bp-ipa-c99` (`main.cpp:13570-13571`, the `det` flag): `prove` is called twice on the same inputs and the two proofs must be byte-identical, for `n ∈ {1,2,4,8}`. This is exactly what the pure-function transcript guarantees: no randomness enters `prove` — `L`,`R` are deterministic multi-exps, and each challenge is `hash_to_scalar` over the running buffer (`ipa.c:106-114`). (Contrast the OPRF/VOPRF layer, where blind/proof-randomness are caller-supplied; the IPA transcript draws **no** secrets.)
- **Non-interactivity / P-binding.** The transcript is seeded with `P` (`tr_init`, `:93-102`), so the challenges are a function of the statement. `verify` re-seeds with the *supplied* `P` (`:216`) and recomputes; the "wrong commitment rejects" witness (IPA-2, `main.cpp:13574-13576`) is exactly the P-binding statement — a proof transcript generated against `P` yields challenges that do not satisfy the final check under `P2`.

**Caveat.** Determinism is pinned across two prove calls on the covered `n`; it is a structural consequence of the transcript being randomness-free, which the byte-exact dual-oracle (IPA-4) independently corroborates (a nondeterministic prover could not reproduce the frozen bytes). The P-binding witness is over the single perturbation tested, not all `P' != P` (L-2); the general statement is the transcript-seeding argument above.

### IPA-4 — Dual-oracle byte-exactness: the C proof bytes equal the independent Python's for the corpus

**Claim.** For each corpus vector (`n=4`, `n=8`), the shipped C recomputes the **entire proof** — the commitment `P`, all `L`/`R` points, and the final `(a, b)` scalars — and matches, **byte-for-byte**, the values an independent from-scratch Python implementation of the same recursive protocol + transcript generated. Two independent implementations of the IPA agreeing on every byte is the conformance witness the accept-only structural test cannot provide.

**Evidence.** The §3.13 dual-oracle posture over `tools/vectors/bp_ipa.json`:
- **Binary half:** `determ test-c99-vectors`'s `bp_ipa` branch (`main.cpp:14389-14415`, run in `FAST=1`) reads the stored witness `(av_hex, bv_hex)`, drives the shipped C `determ_ipa_commit` and asserts `hx(P) == P_hex` (`:14401-14402`), `determ_ipa_prove` + `determ_ipa_verify` accept (`:14405-14406`), then string-compares every `L_hex[j]`, `R_hex[j]`, `a_hex`, `b_hex` slice of the proof to the frozen corpus (`:14407-14415`). A single divergent byte fails the vector.
- **File half:** `tools/test_c99_vector_files.sh`'s `chk_bp_ipa` → `verify_bp_ipa.check_ipa` (`:1178-1188`, `verify_bp_ipa.py:158-175`) recomputes `P`, the `L/R` proof points, and the final `(a,b)` from the witness through the **independent from-scratch Python** (its own P-256 EC + RFC 9380 hash-to-curve, reused from `verify_pedersen.py`, sharing zero source with `src/crypto/*`), matches all against the frozen hex, AND runs a live `verify(prove(...))` round-trip (`:173-174`) so the corpus is a live round-trip, not just static bytes.

Because the frozen bytes come from an independent RFC 9380 / EC re-derivation (not copied from the C), a bug shared *only by convention* is still caught: the same proof bytes reached from disjoint codebases (Bulletproofs §3 → Python; §3 → C99) is what makes a common-mode wrong-but-agreeing failure implausible.

**Caveat.** Byte-exact conformance is over exactly the **two frozen vectors** (`n ∈ {4,8}`, one fixed witness family), a fixed point set, not the input space (L-2). A wholesale self-consistent substitution of the whole corpus would survive recomputation by construction; what it defeats is only the free-text provenance, not the "C == Python oracle" soundness (the FB68 T-2 residual). The Python oracle's own correctness (that it computes Bulletproofs §3 faithfully) is the (P-oracle) assumption, corroborated by its per-round invariant self-test (IPA-1).

### IPA-5 — proof_len contract: `66·log₂(n) + 64`, and non-power-of-two / oversized `n` yield 0

**Claim.** `determ_ipa_proof_len(n)` returns `66·log₂(n) + 64` for a power of two `n ∈ [1, 256]` (`2·log₂n` compressed points of 33 B each + two 32-B scalars), and `0` for a non-power-of-two or `n > DETERM_IPA_MAX_N` — and `commit`/`prove`/`verify` all reject such `n` with `-1`.

**Evidence.** `test-bp-ipa-c99` (1) (`main.cpp:13554-13558`): `proof_len(1)==64`, `(2)==130`, `(4)==196`, `(8)==262`, and `proof_len(3)==0` (non-power-of-two), `proof_len(512)==0` (`> 256`). The `ipa_rounds` guard (`ipa.c:78-83`) rejects `n < 1`, `n > 256`, and any `n` with a set low bit during the halving, returning `-1`; `commit`/`prove`/`verify` all call it first (`:117`, `:137`, `:205`).

**Caveat.** None material — this is a total, input-checked size/validity contract; the powers of two `{1,2,4,8}` and the two negative cases are directly asserted, and the formula is closed-form.

### IPA-6 — Trust inheritance: every group/scalar op is an already-gated primitive; the only new arithmetic is `sc_add`

**Claim.** `ipa.c` adds **no** new field or group arithmetic. Every point operation (`point_mul`/`point_add`/`point_compress`/`point_decompress`), every mod-`n_ord` scalar op (`scalar_mul_mod_n`/`scalar_inv_mod_n`/`hash_to_scalar`), the generator derivation (`pedersen_gen`), and every multi-exp (`pedersen_msm`) is a call into a primitive already validated byte-equal against OpenSSL EC / the RFC 9380 vectors / the BIGNUM oracle. The **only** new scalar logic is `sc_add` (a big-endian add with one conditional subtraction of `n_ord`, `:27-43`) and the `inner_product` accumulator over it (`:45-54`) — both exercised by the fold and the `<a,b>` computation.

**Evidence.** Reading `ipa.c` end-to-end: the point/scalar/multi-exp calls are `determ_p256_point_{mul,add,compress,decompress}`, `determ_p256_scalar_{mul,inv}_mod_n`, `determ_p256_hash_to_scalar`, `determ_pedersen_gen`, `determ_pedersen_msm` — no other arithmetic appears (`:56-246`). Each is validated by `determ test-p256-c99` (curve constants byte-equal OpenSSL `EC_GROUP`; `[k]G` byte-equal OpenSSL `EVP` over a scalar grid; on-curve accept/reject; scalar-validity gates), `determ test-p256-h2c-c99` (the RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` appendix vectors + mod-n ops vs the OpenSSL BIGNUM oracle), and `determ test-pedersen-c99` (the generator families + MSM — `PedersenCommitmentSoundness.md` PC-9/PC-11). The new `sc_add` is exercised on the covered `n` by every fold step (`:185`, `:188`) and every `inner_product` term (`:51`); its correctness is corroborated end-to-end by the byte-exact dual oracle (IPA-4): a wrong modular reduction would diverge the folded `a_final`/`b_final` scalars — and hence the frozen bytes — from the independent Python's canonical `% N` arithmetic (`verify_bp_ipa.py:107-108`, `39-40`).

**Caveat.** This is a **forward-reference**, not a re-proof: that the underlying scalar-mult / point-add / SSWU / mod-n are correct and constant-time is discharged in `P256CryptoStackAudit.md` + the OpenSSL parity tests, not here. `sc_add` is the one genuinely new arithmetic; it is validated only *indirectly* (via the byte-exact fold outputs on the covered vectors, L-2) — there is no standalone `sc_add`-vs-oracle KAT, so its correctness rests on the dual-oracle agreement over the folds it participates in, not on a dedicated modular-add test.

---

## 3. What is NOT proven / non-claims (NC-1 .. NC-4)

- **NC-1 — This is NOT a range proof.** The IPA proves knowledge of `a, b` with `P = <a,g> + <b,h> + <a,b>·u` for the *given* `P` — it proves `<a,b> = c` for a committed inner product, **nothing about any value lying in a range**. The bit-decomposition of `v` into `a_L`/`a_R`, the `l(X)`/`r(X)` polynomials, the `T_1`/`T_2` polynomial commitments, and the scalars binding them into a proof of `v ∈ [0, 2ⁿ)` are the **next increment** and are entirely out of scope. The IPA is the log-size *subroutine* that compresses the final `<l,r> = t̂` check; on its own it enforces no range predicate (NC stands with `PedersenCommitmentSoundness.md` NC-1).
- **NC-2 — Not batch verification, not the multi-exp verify optimization, not aggregation.** The verifier folds `g,h` **explicitly** round-by-round (`ipa.c:228-231`) rather than collapsing the recursion into a single `O(n)` multi-exponentiation with the `s_i` scalar products (the standard Bulletproofs verifier optimization). It verifies **one** proof at a time (no batching) and proves **one** relation (no aggregation of multiple values/ranges). Same accept set as the optimized/batched forms, different — and deliberately non-optimized — computation.
- **NC-3 — Not a consensus or wallet primitive yet.** No Determ chain, ledger, or wallet code path constructs, proves, or verifies an IPA. This is an additive **library primitive with no in-tree consumer** (`ipa.h:12`). None of the completeness/soundness claims here says anything about a chain-level confidential-transaction protocol — that is a later, separately-reviewed increment. (Note also: CRYPTO-C99-SPEC §3.1/§48 record that the *eventual* v2.22 chain-level Bulletproofs is planned over **secp256k1** via libsecp256k1-zkp; this from-scratch **P-256** IPA is the library-primitive-first exploration of the log-size argument, not that eventual chain path.)
- **NC-4 — Not constant-time.** `sc_add`'s conditional subtraction of `n_ord` (`ipa.c:36-42`, "the subtract-or-not branch is a data-dependent path") and the `pedersen_msm` zero-scalar skip both branch on the **secret** vectors `a, b`. A range prover over secret bit-vectors needs a constant-time modular-add and a constant-time multi-exp — the owner-gated CT-hardening step (the same posture as every other §3 primitive; `pedersen.h:94-96`). This document asserts **functional** correctness only, not timing (L-4).

---

## 4. Limits (L-1 .. L-4)

- **L-1 — Special-soundness / binding is not proven; it is assumed under ECDLP + generator independence.** IPA-2 is a reduction to the Bulletproofs §3 special-soundness theorem (Bünz et al. 2018, Theorem 1); the tests exercise the reject paths (wrong-`P`, tamper), **not** a machine-checked witness extractor. That the generators `g_i, h_i, u` have no known mutual discrete-log relation rests on their nothing-up-my-sleeve RFC 9380 derivation (§1.1; PC-9) AND on P-256 discrete-log hardness. A break of ECDLP on P-256 breaks binding regardless of any byte-exactness here.
- **L-2 — Bounded input set for byte-exact conformance and for the structural round-trip.** IPA-4 quantifies over exactly the **two** frozen `bp_ipa.json` vectors (`n ∈ {4,8}`, one witness family `a_i=7i+3, b_i=5i+11`). The structural round-trip / determinism / soundness (IPA-1/IPA-3/IPA-2) widen coverage to `n ∈ {1,2,4,8}` (C) and `{1,2,4,8,16}` (Python) but are not byte-pinned beyond the corpus. Not exercised: `n` up to the `256` maximum, other witness families, near-inverse / adversarial witnesses, and the (negligible) zero-challenge / identity-intermediate `-1` paths. `sc_add` has no standalone KAT (IPA-6 caveat).
- **L-3 — The Fiat-Shamir transform's soundness is in the random-oracle model.** The non-interactive challenge is `hash_to_scalar(transcript)`; the argument that this is as sound as the interactive protocol is a ROM result on the transcript hash (the RFC 9380 `hash_to_field` over SHA-256). This document assumes the ROM (the ambient Fiat-Shamir assumption), it does not prove it; a ROM-uninstantiability attack on the concrete hash is outside what any byte gate can catch.
- **L-4 — Timing out of scope.** `sc_add`'s conditional subtraction (NC-4) and the `pedersen_msm` zero-scalar skip are data-dependent on the secret `a, b`; the underlying ladder's CT posture is asserted in `src/crypto/p256/README.md` / `P256CryptoStackAudit.md` and probed by the `ct-timing-probe` tranche; the normative timing boundary is CRYPTO-C99-SPEC §3.12 / `ConstantTimeInventory.md`. This document asserts functional conformance only. A range prover's constant-time variant is the owner-gated hardening step.

---

## 5. Mechanized witnesses

| Layer | Script / subcommand | What it pins |
|---|---|---|
| Structural / negative | `determ test-bp-ipa-c99` (`src/main.cpp:13539-13584`) | (1) `proof_len == 66·log₂n+64`, non-power-of-2 / `n>256` → 0 (IPA-5); (2) round-trip `commit→prove→verify` accepts for `n ∈ {1,2,4,8}` (IPA-1); (3) determinism — prove twice → identical bytes (IPA-3); (4) soundness — a tampered proof AND a wrong commitment both reject (IPA-2). |
| Byte gate, file half | `tools/test_c99_vector_files.sh` (`chk_bp_ipa` → `verify_bp_ipa.check_ipa`, `:1178-1188`) | IPA-4 leg 1 + IPA-1: independent from-scratch Python (own P-256 EC + RFC 9380 h2c) recomputes `P` + `L/R` + final `(a,b)` and matches the frozen bytes, plus a live round-trip; no binary, offline, fail-closed. The `_selftest`'s `_check_invariant` machine-verifies the per-round invariant for `n ∈ {1,2,4,8,16}`. |
| Byte gate, binary half | `determ test-c99-vectors` (`bp_ipa` branch, `src/main.cpp:14389-14415`), in `FAST=1` | IPA-4 leg 2: the two vectors through the shipped C99 `commit`/`prove`/`verify`, every `P`/`L`/`R`/`a`/`b` byte string-compared to the frozen hex, with a live `verify` accept. |
| Underlying primitives (context, IPA-6) | `determ test-p256-c99` / `test-p256-h2c-c99` / `test-pedersen-c99` | Curve-constant + `[k]G` + on-curve parity vs OpenSSL EC; RFC 9380 h2c appendix vectors + mod-n vs BIGNUM oracle; the `pedersen_gen` generator families + `pedersen_msm` (PC-9/PC-11) — the correctness base under every IPA operation. |

The two-leg split is the standard §3.13 defense-in-depth: the structural test (`test-bp-ipa-c99`) is the **reject-path + round-trip + determinism** witness the accept-only vectors cannot provide; the byte gate is the **dual-oracle conformance** witness (C99 == independent Python over frozen bytes, incl. the full `L/R`/final-scalar proof); IPA-6 forward-references the P-256 + Pedersen audits for the primitive-correctness base; and the Python `_check_invariant` is the algebraic oracle that machine-verifies the §1.3 completeness invariant per fold. Their conjunction — bounded by L-1..L-4 — is what "the C99 Bulletproofs IPA is complete, deterministic, byte-conformant, and binding under ECDLP+ROM" means for this increment-4 library primitive.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `src/crypto/pedersen/ipa.c` | The shipped implementation — every §1 construction-map claim (commit / prove / verify / transcript / fold) is verified against it. |
| `include/determ/crypto/pedersen/ipa.h` | The public API contracts (statement, fixed generators, wire format, `proof_len`, determinism). |
| `include/determ/crypto/pedersen/pedersen.h` | The §3.19 `pedersen_gen` / `pedersen_msm` contracts the IPA reduces every group operation to. |
| `include/determ/crypto/p256/p256.h` | The §3.8c primitive contracts (`point_mul`/`point_add`/`compress`/`decompress`/`scalar_mul_mod_n`/`scalar_inv_mod_n`/`hash_to_scalar`) the module composes over. |
| `src/main.cpp` (`test-bp-ipa-c99`, `:13539-13584`) | The structural/negative test (IPA-1/IPA-2/IPA-3/IPA-5). |
| `src/main.cpp` (`test-c99-vectors` `bp_ipa` branch, `:14389-14415`) | Byte gate binary half — full-proof recompute + match (IPA-4 leg 2). |
| `tools/vectors/bp_ipa.json` | The two-vector (`n=4`, `n=8`) dual-oracle corpus — the byte-pinned middle term (IPA-4). |
| `tools/verify_bp_ipa.py` | The independent from-scratch Python oracle + `emit()` generator (IPA-4 leg 1); `_check_invariant` machine-verifies the per-round completeness invariant (IPA-1). |
| `tools/test_c99_vector_files.sh` (`chk_bp_ipa`, `:1178-1188`) | Byte gate file half wiring. |
| `docs/proofs/PedersenCommitmentSoundness.md` | Increments 1-3 — the generator families (PC-9) + the MSM (PC-11) this IPA reduces to; successor to its NC-4. |
| `docs/proofs/P256CryptoStackAudit.md` | The correctness + constant-time companion for the underlying P-256 primitives (IPA-6 / L-4 forward-reference). |
| `docs/proofs/VectorGateComposition.md` / `OprfConformanceMap.md` | The two-half §3.13 gate mechanics this document instantiates. |
| `docs/proofs/CRYPTO-C99-SPEC.md` §3.19 (inc.4) / §3.8c / §3.13 | The IPA / curve+h2c / vector-gate design entries. |
| `docs/proofs/ConstantTimeInventory.md` / §3.12 | The timing boundary handed off in NC-4 / L-4. |
| Bünz–Bootle–Boneh–Poelstra–Wuille–Maxwell, "Bulletproofs" (IEEE S&P 2018) §3 / Thm 1; FIPS 186-5 (P-256); RFC 9380 (hash-to-scalar) | The external construction (inner-product argument + soundness theorem), curve, and challenge-derivation sources. |

---

## 7. Status

- **Spec.** Complete (this document).
- **The structural test + both byte-gate halves shipped and green.** `test-bp-ipa-c99` (proof_len + round-trip + determinism + soundness-reject), the `bp_ipa` branch of `test-c99-vectors` (binary half), and `chk_bp_ipa`/`verify_bp_ipa.check_ipa` (file half) validate the two-vector corpus + the reject/round-trip paths; the C99 output — `P`, all `L`/`R` points, and the final `(a,b)` — is byte-exact against the independent Python, whose `_check_invariant` machine-verifies the per-round completeness invariant for `n ∈ {1,2,4,8,16}`.
- **Claims.** IPA-1 (completeness — round-trip all `n`, the per-round invariant the reason), IPA-2 (special-soundness / binding — reduced to Bulletproofs §3 under ECDLP + ROM; wrong-commitment + tamper reject witnesses only, NOT an extractor), IPA-3 (determinism / non-interactivity — pure-function transcript, `P`-binding), IPA-4 (dual-oracle byte-exactness — full proof, two independent impls), IPA-5 (proof_len contract + `n`-validity), IPA-6 (trust inheritance — composition over already-gated P-256 + Pedersen primitives; `sc_add` the only new arithmetic, corroborated via the byte-exact fold) — all closed.
- **Non-claims (NC-1..NC-4).** Not a range proof (the log-size subroutine only); not batch / multi-exp-optimized verify / aggregation; not a consensus/wallet primitive; not constant-time (`sc_add` conditional subtract + MSM zero-skip are secret-data-dependent — CT hardening owner-gated).
- **Limits (L-1..L-4).** Soundness assumes ECDLP + generator independence (reduction, not extractor); conformance is over the two frozen vectors + bounded structural `n`; Fiat-Shamir soundness is in the ROM; timing → §3.12 / `ConstantTimeInventory.md`.
