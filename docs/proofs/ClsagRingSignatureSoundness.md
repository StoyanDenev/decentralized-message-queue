> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md
> **LIBRARY REMOVED FROM TREE 2026-07-09 (pre-launch register B2, jointly A7, `PRE-LAUNCH-DECISIONS.md`).** The ring-signature module this document analyses (the `ringsig` library) was deleted from the tree; git history preserves the code; this document is the retained design record.

# ClsagRingSignatureSoundness — §3.23b CLSAG concise linkable ring signature over P-256: unforgeable + anonymous-within-the-ring + a deterministic key-image nullifier + amount-commitment BALANCE-binding, all in ONE concise ring / library-primitive-first / dual-oracle byte-frozen

This document is the "proven-in-code vs. argued-in-prose" honest accounting for the **CLSAG concise linkable ring signature** — the **input-unlinkability increment 2** of the shielded-pool track, building directly on the §3.23 [`LsagRingSignatureSoundness.md`](LsagRingSignatureSoundness.md) primitive. It is the **Goodell-Noether-RandomRun 2019** "Concise Linkable Spontaneous Anonymous Group" signature — **Monero's current RingCT membership + balance primitive** (deployed since 2020, replacing MLSAG).

CLSAG generalises LSAG to **two key layers signed by ONE concise ring** (`n+1` scalars, **not** `2n`):

- **layer 0 (spend key):** ring key `P_i`, signer secret `p` (`P_ℓ = p·G`), **key image `I = p·H_p(P_ℓ)`** — the double-spend nullifier.
- **layer 1 (amount commitment):** ring key `C_i`, signer secret `z` (`C_ℓ − Coffset = z·G`), auxiliary image `D = z·H_p(P_ℓ)`.

The two layers are folded by **hash-derived aggregation coefficients** `μ_P, μ_C` into a single ring over the aggregated keys `W_i = μ_P·P_i + μ_C·(C_i − Coffset)` with aggregated image `Wimg = μ_P·I + μ_C·D`. Proving `C_ℓ − Coffset` is a **pure-`G` multiple** (no `H` component) is exactly the RingCT **balance** statement — "the pseudo-out `Coffset` commits to the *same amount* as the real input commitment `C_ℓ`". `H_p` is the RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` hash-to-curve (the same map that derives the §3.19 Pedersen `H` and the §3.23 LSAG `H_p`, distinct DST).

- **Module** — `src/crypto/ringsig/clsag.c` + `include/determ/crypto/ringsig/clsag.h` (`determ_clsag_key_images` / `_sign` / `_verify` / `_sig_len`), CRYPTO-C99-SPEC.md **§3.23b**.
- **Built entirely on the shipped §3.8c/§3.9b P-256 API** (`base_mul` / `point_mul` / `point_add` / `hash_to_curve` / `hash_to_scalar` / `compress`), each already validated byte-equal vs OpenSSL EC (`test-p256-c99`) or the RFC 9380 vectors (`test-p256-h2c-c99`). It adds **NO new hardness assumption** — soundness rests on **P-256 ECDLP + the Fiat-Shamir ROM**.
- **Gate** — `test-clsag-c99` via `tools/test_clsag_c99.sh`: sign→verify accept; the **dual-oracle byte-freeze** (key image `I`, aux image `D`, signature bytes) vs the independent Python reference `tools/verify_clsag.py` (own P-256 ladder + RFC 9380 hash-to-curve); linkability; and tamper / wrong-message / wrong-aux-image / wrong-key-image / wrong-pseudo-out / malformed reject.

**Authoritative external sources.** Goodell, Noether, RandomRun, *"Concise Linkable Ring Signatures and Forgery Against Adversarial Keys"* (IACR 2019/654) — the CLSAG construction, the conciseness result, and the **forgery-against-adversarial-keys** theorem that motivates the hash-derived aggregation; Liu-Wei-Wong (ACISP 2004) for the underlying LSAG; the CryptoNote v2 whitepaper (2013) key-image spend model; Monero's RingCT (MRL-0005). Nothing new is assumed beyond CLSAG + P-256 ECDLP + the ROM.

---

## 1. Construction (from `clsag.c`)

Wire: `ringP33` / `ringC33` = `n` consecutive 33-byte SEC1-compressed pubkeys each; `Coffset33` = 33 B; key image `I` = 33 B, aux image `D` = 33 B; **signature = `c0(32) ‖ s_0(32) ‖ … ‖ s_{n-1}(32)`** = `32·(n+1)` bytes — the SAME length as LSAG despite the second layer (the "concise" property). All challenges/nonces are scalars mod the P-256 order `n_ord`.

- **aggregation** `μ_P = hash_to_scalar(agg, AGG0_DST)`, `μ_C = hash_to_scalar(agg, AGG1_DST)`, where `agg = ringP ‖ ringC ‖ I ‖ D ‖ Coffset` (all 33-byte compressed). The two coefficients differ only by DST — an unpredictable, transcript-bound folding of the two layers.
- **prefix** = `SHA-256(DOM ‖ n_be4 ‖ ringP ‖ ringC ‖ Coffset ‖ I ‖ D ‖ msg)` (`DOM = "DETERM-CLSAG-P256-v1"`) — binds both rings, the pseudo-out, both images, and the message into every challenge.
- **key images** `I = p·H_p(compress(P_ℓ))`, `D = z·H_p(compress(P_ℓ))` — both on the SAME base `H_p(P_ℓ)`.
- **aggregated key** `W_i = μ_P·P_i + μ_C·(C_i − Coffset)`; **aggregated image** `Wimg = μ_P·I + μ_C·D`. Point negation `−Coffset` is computed as `(n_ord−1)·Coffset` (byte-identical to the Python `(x, p−y)`).
- **sign** (deterministic): `α = hash_to_scalar("alpha" ‖ p ‖ z ‖ prefix)`; the real-index challenge `c_{ℓ+1} = hash_to_scalar(prefix ‖ compress(α·G) ‖ compress(α·H_p_ℓ))`; for each decoy `i` (around the ring) pick `s_i = hash_to_scalar("s" ‖ p ‖ z ‖ prefix ‖ i_be4)` and set `c_{i+1} = hash_to_scalar(prefix ‖ compress(s_i·G + c_i·W_i) ‖ compress(s_i·H_p_i + c_i·Wimg))`; close with `s_ℓ = α − c_ℓ·w mod n_ord`, where the **aggregated secret** `w = μ_P·p + μ_C·z`. Output `c_0 ‖ s_0..s_{n-1}`.
- **verify**: reject unless `len == 32·(n+1)` and every scalar (`c0`, `s_i`) is in `[1, n_ord)` and `I`, `D`, `Coffset`, every `P_i`, every `C_i` decode on-curve; recompute `μ_P, μ_C, W_i, Wimg`; walk `c := c0`, for each `i`: `L_i = s_i·G + c·W_i`, `R_i = s_i·H_p_i + c·Wimg`, `c := hash_to_scalar(prefix ‖ compress(L_i) ‖ compress(R_i))`; **accept iff the recomputed `c == c0`** (the ring closes).

**Why the ring closes only for a signer who knows BOTH secrets.** At the real index, `W_ℓ = μ_P·(p·G) + μ_C·(z·G) = w·G` and `Wimg = μ_P·I + μ_C·D = (μ_P·p + μ_C·z)·H_p_ℓ = w·H_p_ℓ` (using `I = p·H_p_ℓ`, `D = z·H_p_ℓ`). So `s_ℓ·G + c_ℓ·W_ℓ = (α − c_ℓ·w)·G + c_ℓ·w·G = α·G = L_ℓ` and `s_ℓ·H_p_ℓ + c_ℓ·Wimg = (α − c_ℓ·w)·H_p_ℓ + c_ℓ·w·H_p_ℓ = α·H_p_ℓ = R_ℓ` — the closure holds iff the discrete log of `W_ℓ` (base `G`) equals that of `Wimg` (base `H_p_ℓ`), i.e. iff a single `w` opens BOTH layers. Because `μ_C` is an unpredictable hash of the transcript, a residual `H`-component in `C_ℓ − Coffset` (an unbalanced amount) would force `w` to depend on `μ_C·(unknown H-log)` — which the signer cannot pre-commit to (GNR 2019 forgery-against-adversarial-keys).

---

## 2. Claims (CLSAG-1 .. CLSAG-7)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-clsag-c99`. **argued-in-prose** = a reduction to a cited theorem (assumed, not machine-checked here).

- **CLSAG-1 (unforgeability — a non-member cannot forge).** Under P-256 ECDLP + the Fiat-Shamir ROM, no party lacking a spend key of any ring member can produce a signature that `determ_clsag_verify` accepts (GNR 2019 unforgeability, reduced to discrete log by the forking lemma). **argued-in-prose** (the reduction) **+ proven-in-code** (the deployed reject paths fire): `test-clsag-c99` — a **wrong-message** signature is rejected; a **tampered** signature (any flipped byte) is rejected; a **wrong key image** is rejected. The closure `c == c0` over the aggregation-bound + prefix-bound transcript is the whole mechanism (`clsag.c` verify loop).

- **CLSAG-2 (anonymity within the ring — unlinkable to a member).** A verifying signature hides **which** ring index signed: the decoy responses `s_i` and the real `s_ℓ = α − c_ℓ·w` are identically distributed (uniform mod `n_ord`) given the challenges, so the signature is (computationally) independent of `ℓ` (GNR 2019 / LWW 2004 signer-anonymity, in the ROM). **argued-in-prose.** The privacy set is exactly the ring; a larger ring = a larger anonymity set.

- **CLSAG-3 (linkability — the key image is a deterministic double-spend nullifier).** `I = p·H_p(P_ℓ)` is a **deterministic function of the spend key** (independent of `z`, `Coffset`, and the message), so any two signatures by the same spend key carry the **same** image (double-spend detectable by a seen-image set) while distinct keys give distinct images. **proven-in-code:** `test-clsag-c99` — signing two **different messages** (with different pseudo-outs) using the same spend key yields the **SAME** key image (and different signatures); a **different** spend key yields a **different** image; the standalone `determ_clsag_key_images` equals the `(I, D)` the signer emits.

- **CLSAG-4 (amount-commitment BALANCE-binding — the distinguishing CLSAG property).** A verifying signature proves the signer knows a `z` with `C_ℓ − Coffset = z·G` at the (hidden) real index — i.e. the difference has **no `H` component**, so the real input commitment `C_ℓ` and the pseudo-out `Coffset` commit to the **same amount**. Because the layers are folded by the transcript-hash coefficient `μ_C` (unknown before `I, D, Coffset` are fixed), a signer with an **unbalanced** pair (a residual `a·H`, `a ≠ 0`) cannot close the ring — GNR 2019's forgery-against-adversarial-keys result. **argued-in-prose** (the GNR reduction) **+ proven-in-code:** `test-clsag-c99` — a **wrong pseudo-out** (a `Coffset` the signature was not made for) is rejected; a **wrong aux image `D`** is rejected (`D` is bound into `μ_P/μ_C` + the prefix); the Python oracle's balance precondition (`tools/verify_clsag.py`) refuses to even construct a signature for an amount-mismatched `Coffset` (no valid `z` exists).

- **CLSAG-5 (memory-safe, fail-closed parser + honest-prover correctness).** `determ_clsag_verify` treats every input byte as adversarial: it rejects unless `sig_len == determ_clsag_sig_len(n) = 32·(n+1)`, every scalar (`c0`, each `s_i`) is in `[1, n_ord)`, `I` / `D` / `Coffset` / every `P_i` / every `C_i` decode on-curve, and every point operation succeeds — so all interior reads are bounded and no malformed input is accepted. The `n·65` `H_p[]` and the `(2n+3)·33` aggregation buffer are freed on every path (`goto done`). **proven-in-code:** the length gate + range checks + decode checks + the free discipline; `test-clsag-c99` — a **malformed length** rejects. **Caveat:** "memory-safe" is an argued property of the bounds arithmetic; not a machine-checked ASan/fuzz proof, though the underlying P-256 stack runs under the `DETERM_UBSAN`/ASan gate (L-4).

- **CLSAG-6 (deterministic → dual-oracle byte-freeze).** Signing is a pure function of `(p, z, ringP, ringC, Coffset, index, msg)` — nonces are RFC-6979-style (`hash_to_scalar` over both secrets + the prefix), the `α == 0 → 1` edge is replicated, and every buffer layout / DST / endianness / point-negation convention is fixed — so the bytes are **bit-exactly reproducible** across platforms. **proven-in-code:** `test-clsag-c99` pins the exact key image + aux image + signature of a 4-member ring, and an **INDEPENDENT** from-scratch Python oracle `tools/verify_clsag.py` (own P-256 ladder + RFC 9380 hash-to-curve) reproduces the **same** `I`, `D`, and signature **byte-for-byte** (also frozen into `tools/vectors/clsag.json`, `n = 2, 4, 8`). Two independent implementations agreeing on one frozen signature means a divergence with both green is *our* bug, not the vector's.

- **CLSAG-7 (concise — two layers in `n+1` scalars).** The signature is `32·(n+1)` bytes regardless of the two key layers — the aggregation folds layer-0 and layer-1 into a single ring, versus MLSAG's `~2n` scalars for the same statement. **proven-in-code:** `determ_clsag_sig_len(n) == 32·(n+1)` and the byte-freeze over a 2-layer statement. **argued-in-prose** (that this is the minimal size / GNR conciseness): GNR 2019.

---

## 3. Validation map

| Claim | Enforced in source | Gate (`test-clsag-c99`) | Reduces to | Status |
|---|---|---|---|---|
| **CLSAG-1** unforgeability | `clsag.c` verify closure `c==c0` over aggregation+prefix transcript | wrong-message / tamper / wrong-image reject | GNR 2019 + ECDLP + ROM | proven-in-code (rejects) + argued-in-prose (reduction) |
| **CLSAG-2** anonymity in the ring | `clsag.c` sign (uniform decoy `s_i`, real `s_ℓ`) | — (distributional; no single-run witness) | GNR 2019 / LWW 2004 (ROM) | argued-in-prose |
| **CLSAG-3** linkable key-image nullifier | `clsag.c` `I = p·H_p(P_ℓ)` deterministic in the spend key | same spend key → SAME image; diff key → diff image | RO(H_p) + P-256 prime order | proven-in-code |
| **CLSAG-4** amount balance-binding | `clsag.c` `μ_C`-folded `C_i − Coffset` layer + closure | wrong-pseudo-out / wrong-`D` reject; oracle balance precondition | GNR 2019 adversarial-key forgery | proven-in-code (reject) + argued-in-prose |
| **CLSAG-5** memory-safe fail-closed parse | `clsag.c` `len==32(n+1)` + scalar-range + decode + free discipline | malformed length rejects | — | proven-in-code |
| **CLSAG-6** determinism / dual-oracle byte-freeze | `clsag.c` deterministic nonces + fixed layout + `(n-1)·P` negation | `I` + `D` + sig bytes == `verify_clsag.py` (byte-freeze) | — | proven-in-code |
| **CLSAG-7** concise (`n+1` scalars, 2 layers) | `clsag.c` `sig_len == 32·(n+1)` | length + 2-layer byte-freeze | GNR 2019 conciseness | proven-in-code + argued-in-prose |

The `test-clsag-c99` gate is the **functional + dual-oracle** witness; the unforgeability/anonymity/balance theorems are the GNR 2019 reductions over the already-gated P-256 + RFC 9380 primitives. Their conjunction — bounded by L-1..L-4 — is what "CLSAG over P-256 is an unforgeable, ring-anonymous, linkable membership signature with a deterministic key-image nullifier AND amount-commitment balance-binding, concise in `n+1` scalars, under ECDLP + the ROM" means for this §3.23b library primitive.

---

## 4. Non-claims — THIS IS A LIBRARY PRIMITIVE, NOT AN UNLINKABLE-SPEND CONSENSUS FEATURE

- **NC-1 — No consensus wiring / no on-chain nullifier set.** CLSAG proves ring membership + balance + emits a key image; it does **not** by itself constitute an unlinkable RingCT spend. That needs a shielded-pool integration: giving each note a **spend key** and a **commitment**, choosing the anonymity **ring** (real + decoys) from the pool, forming the **pseudo-out** `Coffset`, maintaining an on-chain **key-image (nullifier) set** for double-spend rejection, and composing with the §3.22c amount-**range** proofs. That integration is a separate, consensus-critical, **owner-gated** step (design not yet drafted). It supersedes the named-input model of [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) **NC-7**.

- **NC-2 — Balance ≠ range.** CLSAG-4 proves the input and pseudo-out commit to the SAME amount (the difference is a pure-`G` multiple); it proves **nothing** about non-negativity or the `[0, 2^64)` bound of any amount. Range/non-negativity is the §3.22c DCT1 **range** proof. A full unlinkable confidential spend composes BOTH (CLSAG for input membership + balance, the range proofs for the amounts).

- **NC-3 — O(N) size (not log-size).** The signature is `32·(n+1)` bytes — linear in the ring size (though concise across the two *layers*). The anonymity set = the ring, so privacy trades off against size. The log-size **Groth-Kohlweiss / Lelantus one-out-of-many** proof is a later optimization, not this increment.

- **NC-4 — NOT constant-time.** Signing branches on the secret nonces and the real index; verify is public-data but not CT-analyzed. CT-hardening (a hard prerequisite before a production prover handles secret keys under timing observation) is an owner-gated step.

- **NC-5 — Not post-quantum.** Unforgeability + linkability + balance rest on P-256 ECDLP, broken by Shor. Classical-adversary construction.

- **NC-6 — No `z`-consistency check inside `sign`.** `determ_clsag_sign` does not itself verify `C_ℓ − Coffset == z·G` (the caller supplies a consistent `z`); a wrong `z` simply yields a signature that does not verify. The Python oracle's `sign` DOES assert the precondition (to catch a caller bug early) — this is a defense-in-depth difference, not a soundness gap (a wrong `z` is unforgeable, not silently accepted).

---

## 5. Limits (L-1 .. L-4)

- **L-1 — Soundness is a REDUCTION, not a machine-checked extractor.** CLSAG-1/2/4/7 are the GNR 2019 theorems reduced to ECDLP + the Fiat-Shamir ROM; a break of P-256 discrete log or the ROM assumption breaks the scheme regardless of any gating here. `test-clsag-c99`'s reject witnesses show the deployed paths fire — they are **not** a soundness proof.

- **L-2 — Conformance is over FIXED witnesses.** The gate exercises three rings (`n = 2, 4, 8`) at fixed keys/amounts/blindings/indices/messages (dual-oracle byte-frozen) plus the reject cases; completeness/soundness for arbitrary rings follows from the construction + the reductions, not exhaustive coverage.

- **L-3 — Key-image collision-freedom is a RO assumption.** "Distinct spend keys → distinct images" and "the image is bound to a controlled member" rest on `H_p` (RFC 9380 SSWU) behaving as a random oracle and P-256 being prime-order. This is the standard CryptoNote / RingCT key-image assumption.

- **L-4 — Not a constant-time / fuzz proof.** This document asserts functional soundness (unforgeability/anonymity/linkability/balance/fail-closed), not a timing or exhaustive memory-safety proof beyond the bounds argument + the §3.8c UBSan/ASan gate on the underlying P-256 core.

---

## 6. Status

- **Spec.** Complete (this document); design entry CRYPTO-C99-SPEC.md §3.23b.
- **Module + gate shipped and green.** `src/crypto/ringsig/clsag.c` (`determ_clsag_key_images` / `_sign` / `_verify` / `_sig_len`); `test-clsag-c99` via `tools/test_clsag_c99.sh` — sign/verify accept, the dual-oracle byte-freeze vs `tools/verify_clsag.py` (+ `tools/vectors/clsag.json`), linkability, and tamper / wrong-message / wrong-aux-image / wrong-key-image / wrong-pseudo-out / malformed reject. Validated MSVC + GCC/MinGW (`ci_local`).
- **Claims.** CLSAG-1 (unforgeability), CLSAG-2 (ring anonymity), CLSAG-3 (linkable key-image nullifier), CLSAG-4 (amount balance-binding), CLSAG-5 (memory-safe fail-closed parse), CLSAG-6 (determinism / dual-oracle byte-freeze), CLSAG-7 (concise, `n+1` scalars for two layers) — at the proven-in-code / argued-in-prose split in §3.
- **Non-claims (NC-1..NC-6).** No consensus wiring / no on-chain nullifier set (owner-gated, supersedes the named-input model); balance ≠ range; O(N) size (not log-size); not constant-time; not post-quantum; no in-`sign` `z`-consistency check.
- **Limits (L-1..L-4).** Soundness is an inherited GNR reduction; conformance is fixed witnesses; key-image collision-freedom is a RO assumption; not a timing/fuzz proof.

Cross-references: [`LsagRingSignatureSoundness.md`](LsagRingSignatureSoundness.md) (§3.23 — the single-layer LSAG this generalises); [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (**NC-7** — the input-unlinkability gap this primitive is built to close); [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) / [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (the amount range/balance layer CLSAG composes with); [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the shared RFC 9380 hash-to-curve → `H_p` and the commitment `C = v·H + r·G`); CRYPTO-C99-SPEC.md §3.23b (this design entry), §3.8c/§3.9b (the P-256 primitives), §3.13 (the dual-oracle vector gate); `src/crypto/ringsig/` module.
