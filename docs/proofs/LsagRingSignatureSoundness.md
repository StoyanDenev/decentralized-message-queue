> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# LsagRingSignatureSoundness — §3.23 LSAG linkable ring signature over P-256: unforgeable + anonymous-within-the-ring + a deterministic key-image nullifier / library-primitive-first / dual-oracle byte-frozen

This document is the "proven-in-code vs. argued-in-prose" honest accounting for the **LSAG linkable ring signature** — the **input-unlinkability increment 1** of the shielded-pool track, and the primitive that will let a confidential spend prove it consumes *one of N* pool notes **without revealing which** (breaking the deposit↔spend link that [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) **NC-7** leaves open).

It is the **Liu-Wei-Wong 2004** Linkable Spontaneous Anonymous Group signature — the CryptoNote / early-Monero RingCT membership primitive. A signer who knows the private key `x` of **one** of `n` ring public keys `{P_0..P_{n-1}}` (each `P_i = x_i·G`) proves membership, and publishes a **key image** `I = x·H_p(P_signer)` that is **deterministic** in the signing key (the double-spend nullifier) yet **unlinkable** to any particular ring member. `H_p` is the RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` hash-to-curve (the same map that derives the §3.19 Pedersen `H`).

- **Module** — `src/crypto/ringsig/lsag.c` + `include/determ/crypto/ringsig/lsag.h` (`determ_lsag_key_image` / `_sign` / `_verify` / `_sig_len`), CRYPTO-C99-SPEC.md **§3.23**.
- **Built entirely on the shipped §3.8c/§3.9b P-256 API** (`base_mul` / `point_mul` / `point_add` / `hash_to_curve` / `hash_to_scalar` / `compress`), each already validated byte-equal vs OpenSSL EC (`test-p256-c99`) or the RFC 9380 vectors (`test-p256-h2c-c99`). It adds **NO new hardness assumption** — soundness rests on **P-256 ECDLP + the Fiat-Shamir ROM**.
- **Gate** — `test-lsag-c99` via `tools/test_lsag_c99.sh`: sign→verify accept; the **dual-oracle byte-freeze** (key image + signature bytes) vs the independent Python reference `tools/verify_lsag.py` (own P-256 ladder + RFC 9380 hash-to-curve); linkability; and tamper / wrong-message / wrong-image / malformed reject.

**Authoritative external sources.** Liu, Wei, Wong, *"Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups"* (ACISP 2004) — the LSAG construction, unforgeability + anonymity + linkability theorems; Fujisaki-Suzuki (2007) traceable-ring refinements; the CryptoNote v2 whitepaper (2013) key-image spend model. Nothing new is assumed beyond LSAG + P-256 ECDLP + the ROM.

---

## 1. Construction (from `lsag.c`)

Wire: `ring33` = `n` consecutive 33-byte SEC1-compressed pubkeys; key image `I` = 33 B compressed; **signature = `c0(32) ‖ s_0(32) ‖ … ‖ s_{n-1}(32)`** = `32·(n+1)` bytes. All challenges/nonces are scalars mod the P-256 order `n_ord`.

- **prefix** = `SHA-256(DOM ‖ n_be4 ‖ ring ‖ I ‖ msg)` — binds the ring, the image, and the message into every challenge (`DOM = "DETERM-LSAG-P256-v1"`).
- **key image** `I = x·H_p(compress(P_signer))`, `H_p` = RFC 9380 SSWU RO map under `KI_DST`.
- **sign** (deterministic): `alpha = hash_to_scalar("alpha" ‖ x ‖ prefix)`; the real-index challenge `c_{ℓ+1} = hash_to_scalar(prefix ‖ compress(alpha·G) ‖ compress(alpha·H_p_ℓ))`; for each decoy `i` (going around the ring) pick `s_i = hash_to_scalar("s" ‖ x ‖ prefix ‖ i_be4)` and set `c_{i+1} = hash_to_scalar(prefix ‖ compress(s_i·G + c_i·P_i) ‖ compress(s_i·H_p_i + c_i·I))`; close the ring with `s_ℓ = alpha − c_ℓ·x mod n_ord`. Output `c_0 ‖ s_0..s_{n-1}`.
- **verify**: reject unless `len == 32·(n+1)` and every scalar (`c0`, `s_i`) is in `[1, n_ord)` and `I` + every ring member decode on-curve; then walk `c := c0`, for each `i`: `L_i = s_i·G + c·P_i`, `R_i = s_i·H_p_i + c·I`, `c := hash_to_scalar(prefix ‖ compress(L_i) ‖ compress(R_i))`; **accept iff the recomputed `c == c0`** (the ring closes).

The `s_i·G + c·P_i` / `s_i·H_p_i + c·I` pairing ties the discrete log of `P_i` (base `G`) to that of `I` (base `H_p_i`) with the SAME `(s_i, c)` — only at the real index, where the signer knows `x` with `P_ℓ = x·G` **and** `I = x·H_p_ℓ`, does the closure hold, and the image is therefore bound to a key the signer controls.

---

## 2. Claims (LSAG-1 .. LSAG-6)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-lsag-c99`. **argued-in-prose** = a reduction to a cited theorem (assumed, not machine-checked here).

- **LSAG-1 (unforgeability — a non-member cannot forge).** Under P-256 ECDLP + the Fiat-Shamir ROM, no party lacking a private key of any ring member can produce a signature that `determ_lsag_verify` accepts (LWW 2004 unforgeability, reduced to discrete log by the forking lemma). **argued-in-prose** (the reduction) **+ proven-in-code** (the deployed reject paths fire): `test-lsag-c99` — a signature produced over a **different ring** (a key not in the honest ring) is rejected; a **wrong-message** signature is rejected; a **tampered** signature (any flipped byte) is rejected. The closure check `c == c0` over the prefix-bound transcript is the whole mechanism (`lsag.c` verify loop).

- **LSAG-2 (anonymity within the ring — unlinkable to a member).** A verifying signature hides **which** ring index signed: the decoy responses `s_i` and the real `s_ℓ = alpha − c_ℓ·x` are identically distributed (uniform mod `n_ord`) given the challenges, so the signature is (computationally) independent of `ℓ` (LWW 2004 signer-anonymity, in the ROM). **argued-in-prose.** The privacy set is exactly the ring; a larger ring = a larger anonymity set (NC-2).

- **LSAG-3 (linkability — the key image is a deterministic double-spend nullifier).** `I = x·H_p(P_signer)` is a **deterministic function of the signing key**, so any two signatures by the same key carry the **same** image (double-spend is detectable by a seen-image set) while distinct keys give distinct images. **proven-in-code:** `test-lsag-c99` — signing two **different messages** with the same key yields the **SAME** key image (and different signatures); a **different key** yields a **different** image; the standalone `determ_lsag_key_image` equals the image the signer emits. Collision-freedom across distinct keys rests on `H_p` being a random oracle + P-256 prime order (L-3).

- **LSAG-4 (the key image is BOUND to a controlled ring member).** A verifying signature proves `I = x·H_p(P_ℓ)` for the same `x` with `P_ℓ = x·G` at the (hidden) real index — the `R_i = s_i·H_p_i + c·I` relation shares `(s_i, c)` with `L_i = s_i·G + c·P_i`, so the image cannot be an arbitrary unbound point; presenting a `wrong key image` (an image for a different key) fails to close. **proven-in-code:** `test-lsag-c99` — verify with a **wrong key image** rejects. **argued-in-prose** (that closure forces `I = x·H_p_ℓ`): LWW 2004.

- **LSAG-5 (memory-safe, fail-closed parser + honest-prover correctness).** `determ_lsag_verify` treats every input byte as adversarial: it rejects unless `sig_len == determ_lsag_sig_len(n) = 32·(n+1)`, every scalar (`c0`, each `s_i`) is in `[1, n_ord)`, the key image + every ring member decode on-curve, and every point operation succeeds — so all interior reads are bounded and no malformed input is accepted. All heap allocations (`n·65` for `H_p[]`, `n·32` for `c[]`/`s[]`) are freed on every path. **proven-in-code:** the length gate + range checks + decode checks + the `goto done` free discipline; `test-lsag-c99` — a **malformed length** rejects. **Caveat:** "memory-safe" is an argued property of the bounds arithmetic; not a machine-checked ASan/fuzz proof, though the underlying P-256 stack runs under the `DETERM_UBSAN`/ASan gate (L-4).

- **LSAG-6 (deterministic → dual-oracle byte-freeze).** Signing is a pure function of `(x, ring, index, msg)` — nonces are RFC-6979-style (`hash_to_scalar` over the key + the prefix), the `alpha == 0 → 1` edge is replicated, and every buffer layout / DST / endianness is fixed — so the bytes are **bit-exactly reproducible** across platforms. **proven-in-code:** `test-lsag-c99` pins the exact key image + signature of a 4-member ring, and an **INDEPENDENT** from-scratch Python oracle `tools/verify_lsag.py` (own P-256 ladder + RFC 9380 hash-to-curve) reproduces the **same** image + signature **byte-for-byte** (also frozen into `tools/vectors/lsag.json`). Two independent implementations agreeing on one frozen signature means a divergence with both green is *our* bug, not the vector's.

---

## 3. Validation map

| Claim | Enforced in source | Gate (`test-lsag-c99`) | Reduces to | Status |
|---|---|---|---|---|
| **LSAG-1** unforgeability | `lsag.c` verify closure `c==c0` over prefix-bound transcript | wrong-ring / wrong-message / tamper reject | LWW 2004 + ECDLP + ROM | proven-in-code (rejects) + argued-in-prose (reduction) |
| **LSAG-2** anonymity in the ring | `lsag.c` sign (uniform decoy `s_i`, real `s_ℓ`) | — (distributional; no single-run witness) | LWW 2004 (ROM) | argued-in-prose |
| **LSAG-3** linkable key-image nullifier | `lsag.c` `I = x·H_p(P)` deterministic | same key → SAME image; diff key → diff image | RO(H_p) + P-256 prime order | proven-in-code |
| **LSAG-4** image bound to a controlled member | `lsag.c` `R_i = s_i·H_p_i + c·I` pairing | wrong key image rejects | LWW 2004 | proven-in-code (reject) + argued-in-prose |
| **LSAG-5** memory-safe fail-closed parse | `lsag.c` `len==32(n+1)` + scalar-range + decode + free discipline | malformed length rejects | — | proven-in-code |
| **LSAG-6** determinism / dual-oracle byte-freeze | `lsag.c` deterministic nonces + fixed layout | image + sig bytes == `verify_lsag.py` (byte-freeze) | — | proven-in-code |

The `test-lsag-c99` gate is the **functional + dual-oracle** witness; the unforgeability/anonymity theorems are the LWW 2004 reductions over the already-gated P-256 + RFC 9380 primitives. Their conjunction — bounded by L-1..L-4 — is what "LSAG over P-256 is an unforgeable, ring-anonymous, linkable membership signature with a deterministic key-image nullifier, under ECDLP + the ROM" means for this §3.23 library primitive.

---

## 4. Non-claims — THIS IS A LIBRARY PRIMITIVE, NOT AN UNLINKABLE-SPEND CONSENSUS FEATURE

- **NC-1 — No consensus wiring / no on-chain nullifier set.** LSAG proves ring membership + emits a key image; it does **not** by itself constitute an unlinkable confidential spend. That needs a shielded-pool integration: giving each note a **spend key**, choosing the anonymity **ring** from the pool, maintaining an on-chain **key-image (nullifier) set** for double-spend rejection, and composing with the §3.22c amount-hiding balance/range proofs. That integration is a separate, consensus-critical, **owner-gated** step (design not yet drafted).

- **NC-2 — O(N) size (not log-size).** The signature is `32·(n+1)` bytes — linear in the ring size. The anonymity set = the ring, so privacy trades off against size. The log-size **Groth-Kohlweiss / Lelantus one-out-of-many** proof is a later optimization, not this increment.

- **NC-3 — Amount privacy is a DIFFERENT layer.** LSAG hides **which** note is spent; it hides **nothing** about amounts. Amount-hiding is the §3.22c DCT1 bundle. A full unlinkable confidential spend composes BOTH (LSAG for the input, the range/balance proofs for the amounts).

- **NC-4 — NOT constant-time.** Signing branches on the secret nonces and the real index; verify is public-data but not CT-analyzed. CT-hardening (a hard prerequisite before a production prover handles secret keys under timing observation) is an owner-gated step.

- **NC-5 — Not post-quantum.** Unforgeability + linkability rest on P-256 ECDLP, broken by Shor. Classical-adversary construction.

---

## 5. Limits (L-1 .. L-4)

- **L-1 — Soundness is a REDUCTION, not a machine-checked extractor.** LSAG-1/2/4 are the LWW 2004 theorems reduced to ECDLP + the Fiat-Shamir ROM; a break of P-256 discrete log or the ROM assumption breaks the scheme regardless of any gating here. `test-lsag-c99`'s reject witnesses show the deployed paths fire — they are **not** a soundness proof.

- **L-2 — Conformance is over FIXED witnesses.** The gate exercises three rings (n = 2, 4, 8) at fixed keys/indices/messages (dual-oracle byte-frozen) plus the reject cases; completeness/soundness for arbitrary rings follows from the construction + the reductions, not exhaustive coverage.

- **L-3 — Key-image collision-freedom is a RO assumption.** "Distinct keys → distinct images" and "the image is not forgeable to a different note" rest on `H_p` (RFC 9380 SSWU) behaving as a random oracle and P-256 being prime-order (so every on-curve point is a valid image with a unique discrete log to `H_p(P)`). This is the standard CryptoNote key-image assumption.

- **L-4 — Not a constant-time / fuzz proof.** This document asserts functional soundness (unforgeability/anonymity/linkability/fail-closed), not a timing or exhaustive memory-safety proof beyond the bounds argument + the §3.8c UBSan/ASan gate on the underlying P-256 core.

---

## 6. Status

- **Spec.** Complete (this document); design entry CRYPTO-C99-SPEC.md §3.23.
- **Module + gate shipped and green.** `src/crypto/ringsig/lsag.c` (`determ_lsag_key_image` / `_sign` / `_verify` / `_sig_len`); `test-lsag-c99` via `tools/test_lsag_c99.sh` — sign/verify accept, the dual-oracle byte-freeze vs `tools/verify_lsag.py` (+ `tools/vectors/lsag.json`), linkability, and tamper / wrong-message / wrong-image / malformed reject. Validated MSVC + GCC/MinGW (`ci_local`).
- **Claims.** LSAG-1 (unforgeability), LSAG-2 (ring anonymity), LSAG-3 (linkable key-image nullifier), LSAG-4 (image bound to a controlled member), LSAG-5 (memory-safe fail-closed parse), LSAG-6 (determinism / dual-oracle byte-freeze) — at the proven-in-code / argued-in-prose split in §3.
- **Non-claims (NC-1..NC-5).** No consensus wiring / no on-chain nullifier set (owner-gated); O(N) size (not log-size); amount privacy is the §3.22c layer; not constant-time; not post-quantum.
- **Limits (L-1..L-4).** Soundness is an inherited LWW reduction; conformance is fixed witnesses; key-image collision-freedom is a RO assumption; not a timing/fuzz proof.

Cross-references: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (**NC-7** — the input-unlinkability gap this primitive is built to close); [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) / [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (the amount-hiding layer LSAG composes with); [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the shared RFC 9380 hash-to-curve → `H_p`); CRYPTO-C99-SPEC.md §3.23 (this design entry), §3.8c/§3.9b (the P-256 primitives), §3.13 (the dual-oracle vector gate); `src/crypto/ringsig/` module.
