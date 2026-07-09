> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md
> **LIBRARY REMOVED FROM TREE 2026-07-09 (pre-launch register B2, jointly A7, `PRE-LAUNCH-DECISIONS.md`).** The ring-signature module this document analyses (the `ringsig` library) was deleted from the tree; git history preserves the code; this document is the retained design record.

# RingCTSpendCompositionSoundness — §3.23c the LIBRARY-only RingCT spend statement: CLSAG (input membership + balance) ⊕ a commitment-transposition bridge ⊕ the §3.22c DCT1 bundle (range + balance), composed end-to-end / the value-on-H ↔ value-on-G reconciliation / dual-oracle byte-frozen

This document is the "proven-in-code vs. argued-in-prose" honest accounting for the **RingCT spend-statement composition** — the **input-unlinkability increment 3** of the shielded-pool track, and the increment that shows the shipped privacy layers **compose into one end-to-end confidential + unlinkable spend proof**, with **ZERO consensus touch**.

It stitches three already-shipped-or-here layers:

1. **§3.23b CLSAG** ([`ClsagRingSignatureSoundness.md`](ClsagRingSignatureSoundness.md)) — proves the spender owns **one of n** ring notes and that the pseudo-out `Coffset_H` commits to the **same amount** as their real input, hiding **which** (input-unlinkable); emits the key image `I` (double-spend nullifier). CLSAG commitments are the **RingCT convention: amount on H, blinding on G**.
2. **§3.23c the commitment-transposition proof** — the reconciliation this increment **adds**. CLSAG is amount-on-H; the §3.19/§3.22c range+balance stack is amount-on-G (`C = v·G + r·H`). A **Schnorr AND-proof with a shared value response** certifies a value-on-H commitment `C_H = v·H + a·G` and a value-on-G commitment `C_G = v·G + b·H` hide the **same amount v** — the bridge between the two conventions.
3. **§3.22c DCT1 bundle** ([`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md)) — the amount-on-G confidential-transfer bundle: proves `Coffset_G`'s amount = Σ(output amounts) + fee (**balance**) and each output in `[0, 2^n)` (**range**).

**Composition:** `CLSAG(Coffset_H) → TRANSPOSE(Coffset_H == Coffset_G in amount) → DCT1(C_in = [Coffset_G])`. The amount flows from a hidden ring member, through the transposed pseudo-out, to hidden in-range outputs — amounts secret, input unlinkable, value conserved end-to-end.

- **Module** — `src/crypto/ringsig/ringct_spend.c` + `include/determ/crypto/ringsig/ringct_spend.h` (`determ_commit_transpose_prove` / `_verify`, `determ_ringct_spend_verify`), CRYPTO-C99-SPEC.md **§3.23c**.
- **The transpose proof is the ONLY new crypto** — a textbook Schnorr AND-proof over the shipped §3.8c P-256 + §3.19 `determ_pedersen_generator_h` APIs; it adds **NO new hardness assumption** (soundness rests on **P-256 ECDLP + the Fiat-Shamir ROM**). CLSAG + the DCT1 bundle verifier are reused **verbatim**.
- **Gate** — `test-ringct-spend-c99` via `tools/test_ringct_spend_c99.sh`: the transpose proof (prove→verify + the **dual-oracle byte-freeze** vs the independent Python reference `tools/verify_ringct_spend.py` + a wrong-amount reject); and the full spend verifier — accept the honest CLSAG→transpose→DCT1 spend, reject a tamper of **any** layer, a wrong pseudo-out, and a wrong message.

**Authoritative external sources.** Standard Σ-protocols for equality of committed values (Chaum-Pedersen 1992; Camenisch-Stadler 1997 AND-composition; the Fiat-Shamir transform). The composed layers cite their own sources (CLSAG: GNR 2019; the DCT1 bundle: Bünz et al. Bulletproofs 2018). Nothing new is assumed beyond those + P-256 ECDLP + the ROM.

---

## 1. Construction (from `ringct_spend.c`)

### 1.1 The commitment-transposition proof (162 B)

Both commitments share the **same** generator pair `{G (P-256 base), H (§3.19 nothing-up-my-sleeve)}` — only the value/blinding **role** differs:

- `C_H = v·H + a·G` (RingCT / CLSAG convention: amount `v` on `H`).
- `C_G = v·G + b·H` (§3.19 convention: amount `v` on `G`).

Prover (knows `v, a, b`, deterministic nonces `ρv, ρa, ρb`):
- `A_H = ρv·H + ρa·G`, `A_G = ρv·G + ρb·H` (**the same `ρv` in both** — this is what ties `v`).
- `c = hash_to_scalar(C_H ‖ C_G ‖ A_H ‖ A_G)` (DST `…-challenge-v1`).
- `sv = ρv + c·v`, `sa = ρa + c·a`, `sb = ρb + c·b` (mod `n`).
- proof = `A_H(33) ‖ A_G(33) ‖ sv(32) ‖ sa(32) ‖ sb(32)`.

Verifier — accept iff **both**: `sv·H + sa·G == A_H + c·C_H` **and** `sv·G + sb·H == A_G + c·C_G`. The **shared `sv`** appears in both equations; that is exactly what forces the `H`-coefficient of `C_H` to equal the `G`-coefficient of `C_G`.

### 1.2 The spend verifier (`determ_ringct_spend_verify`)

Given `(msg, ringP, ringC, coffset_H, I, D, clsag_sig, transpose_proof, bundle)`, returns 0 iff **all** hold:
1. `determ_clsag_verify(…, coffset_H, I, D, clsag_sig)` — input membership + `coffset_H` commits to the real input amount + the nullifier `I`.
2. `determ_ctx_bundle_header(bundle)` parses with **exactly one** input (`n_in == 1`); `coffset_G` is **extracted** as `C_in[0] = bundle + 15`.
3. `determ_commit_transpose_verify(coffset_H, coffset_G, transpose_proof)` — the two pseudo-out commitments hide the same amount.
4. `determ_ctx_bundle_verify(bundle)` — range over the outputs + balance `coffset_G = Σ outputs + fee`.

The **structural links** — `coffset_H` is both CLSAG's pseudo-out and the transpose's H-side; `coffset_G` is both the transpose's G-side and the bundle's `C_in[0]` — are enforced by passing the **same 33-byte points** to the adjacent verifiers (the verifier extracts `coffset_G` from the bundle rather than trusting a separate copy).

---

## 2. Claims (RCS-1 .. RCS-6)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-ringct-spend-c99`. **argued-in-prose** = a reduction to a cited theorem (assumed, not machine-checked here).

- **RCS-1 (transpose soundness — the bridge binds a single amount).** Under P-256 ECDLP + the ROM, a verifying transpose proof implies `C_H` and `C_G` commit to the **same** `v`. **argued-in-prose** (special soundness: from two accepting transcripts with `c ≠ c'`, the extractor recovers `v = (sv−sv')/(c−c')`, `a = (sa−sa')/(c−c')`, `b = (sb−sb')/(c−c')`; the shared `sv` yields the **same** `v` in both `C_H = v·H + a·G` and `C_G = v·G + b·H`) **+ proven-in-code:** `test-ringct-spend-c99` — verify with a **wrong-amount** `C_G` (an `A+1`-on-G commitment) rejects; a **tampered** proof rejects.

- **RCS-2 (transpose completeness + determinism → dual-oracle byte-freeze).** An honestly-built proof always verifies, and — nonces being RFC-6979-style (`hash_to_scalar` over `v‖a‖b‖C_H‖C_G`) with fixed layout/DST/endianness — its bytes are **bit-exactly reproducible**. **proven-in-code:** `test-ringct-spend-c99` re-derives the 162-byte proof for `(v=3, a, b)` and an **INDEPENDENT** Python oracle `tools/verify_ringct_spend.py` reproduces it **byte-for-byte** (frozen into `tools/vectors/ringct_spend.json`); the emitted `C_H`/`C_G` equal the pinned `coffset_H`/`coffset_G`.

- **RCS-3 (transpose zero-knowledge — hides the amount + blindings).** The proof reveals nothing about `v, a, b`: a simulator picks `c, sv, sa, sb` uniformly and sets `A_H = sv·H + sa·G − c·C_H`, `A_G = sv·G + sb·H − c·C_G`, producing an identically-distributed transcript. **argued-in-prose** (HVZK of the Σ-protocol under Fiat-Shamir).

- **RCS-4 (end-to-end spend soundness).** A verifying spend certifies: the spender controls **one of the n** ring notes (unlinkable), whose amount `A` the pseudo-out `Coffset_H` commits to (CLSAG); `Coffset_G` commits to the **same** `A` (transpose); and `A = Σ(output amounts) + fee` with every output in `[0, 2^n)` (DCT1). Composition = the conjunction; the structural links prevent mixing pieces from different spends. **proven-in-code:** `test-ringct-spend-c99` — the honest spend is **accepted**, and a tamper of **any** layer (CLSAG sig / transpose / bundle), a **wrong pseudo-out** (`coffset_G` fed as `coffset_H`), and a **wrong message** each **reject**. **argued-in-prose** (that the conjunction is the intended spend statement).

- **RCS-5 (the bridge is load-bearing — naive composition is UNSOUND).** The value-on-H ↔ value-on-G gap is **not** cosmetic: CLSAG's balance `C_l − Coffset = z·G` means "same amount" **only** because the amount rides `H`; a range/balance proof in the amount-on-G convention ranges a **different** scalar. Directly reusing `Coffset_H` as the DCT1 input would range/balance the wrong quantity. The transpose proof is exactly what makes the two agree on the amount. **argued-in-prose + proven-in-code** (the wrong-amount transpose reject witnesses the gap).

- **RCS-6 (memory-safe, fail-closed parse).** `determ_commit_transpose_verify` rejects unless the 162-byte layout decodes, every response scalar is in `[0, n)`, and `A_H/A_G/C_H/C_G` decode on-curve; `determ_ringct_spend_verify` rejects unless the bundle header is well-formed with `n_in == 1` before it touches any commitment. No heap in the transpose path (fixed stack buffers); the CLSAG/DCT1 sub-verifiers carry their own fail-closed discipline. **proven-in-code:** the range checks + `n_in == 1` gate + the reject witnesses. **Caveat:** an argued bounds property, not a machine-checked ASan/fuzz proof (L-4).

---

## 3. Validation map

| Claim | Enforced in source | Gate (`test-ringct-spend-c99`) | Reduces to | Status |
|---|---|---|---|---|
| **RCS-1** transpose soundness | `ringct_spend.c` shared-`sv` two-equation check | wrong-amount `C_G` / tamper reject | Σ-protocol special soundness + ECDLP + ROM | proven-in-code (reject) + argued-in-prose |
| **RCS-2** completeness / byte-freeze | `ringct_spend.c` deterministic nonces + fixed layout | proof bytes == `verify_ringct_spend.py`; `C_H/C_G` == pinned | — | proven-in-code |
| **RCS-3** transpose zero-knowledge | `ringct_spend.c` Σ-protocol structure | — (simulator argument) | HVZK + Fiat-Shamir | argued-in-prose |
| **RCS-4** end-to-end spend soundness | `ringct_spend.c` clsag ∧ transpose ∧ bundle + structural links | honest accept; any-layer-tamper / wrong-pseudo-out / wrong-msg reject | CLSAG + DCT1 + RCS-1 | proven-in-code (accept + rejects) + argued-in-prose |
| **RCS-5** the bridge is load-bearing | `ringct_spend.c` extracts `coffset_G` from the bundle for the transpose | wrong-amount transpose reject | the amount-generator argument | proven-in-code (reject) + argued-in-prose |
| **RCS-6** memory-safe fail-closed parse | `ringct_spend.c` len + scalar-range + `n_in==1` gate | reject witnesses fire | — | proven-in-code |

The gate is the **functional + dual-oracle** witness; the soundness/ZK properties are the standard Σ-protocol reductions over the already-gated CLSAG + DCT1 + P-256 primitives. Their conjunction — bounded by L-1..L-4 — is what "the shipped privacy layers compose into a sound, amount-hiding, input-unlinkable spend statement, bridged across the two commitment conventions, under ECDLP + the ROM" means for this §3.23c library increment.

---

## 4. Non-claims — THIS IS A LIBRARY COMPOSITION, NOT A CONSENSUS SPEND

- **NC-1 — No consensus wiring / no on-chain state.** `determ_ringct_spend_verify` checks a spend **statement**; it touches **no** consensus state — no on-chain **key-image (nullifier) set** (so double-spend is *detectable* via `I` but not *enforced* here), no note **pool**, no ring **selection** policy, no fee/emission accounting. Wiring this into an unlinkable RingCT consensus spend is a separate, consensus-critical, **owner-gated** step.

- **NC-2 — A partial transaction, not a whole one.** The statement proves input **membership + balance** (CLSAG) and output **range + balance** (DCT1) bridged by the transpose. It does **not** prove output one-time-key ownership, tx-to/from binding, replay protection, or that the outputs are well-formed notes — a full unlinkable tx composes more (e.g. the §3.22b context-binding, per-output stealth keys).

- **NC-3 — Single-input demo.** The verifier requires `n_in == 1` (one transposed pseudo-out). Multi-input RingCT (several rings + several transposed pseudo-outs summing in the bundle balance) is a straightforward generalization, not built here.

- **NC-4 — NOT constant-time; not post-quantum.** The transpose prover branches on secret nonces; the whole stack rests on P-256 ECDLP (broken by Shor). CT-hardening + a PQ variant are owner-gated.

---

## 5. Limits (L-1 .. L-4)

- **L-1 — Soundness is a REDUCTION.** RCS-1/3/4 are the standard Σ-protocol + CLSAG + DCT1 theorems reduced to ECDLP + the Fiat-Shamir ROM; a break of P-256 discrete log or the ROM breaks the composition. The gate's reject witnesses show the deployed paths fire — they are **not** a soundness proof.
- **L-2 — Conformance is over ONE fixed witness.** The gate exercises a single ring-4/idx-2 spend (`A = 3 → outputs [1,1] + fee 1`, dual-oracle byte-frozen) plus the reject cases; general soundness follows from the construction + the reductions.
- **L-3 — Inherited assumptions.** The composition inherits CLSAG's key-image RO assumption + P-256 prime order and the DCT1 bundle's Bulletproofs soundness; see those docs.
- **L-4 — Not a constant-time / fuzz proof.** Functional soundness (soundness/ZK/fail-closed) is asserted, not a timing or exhaustive memory-safety proof beyond the bounds argument + the §3.8c UBSan/ASan gate on the underlying P-256 core.

---

## 6. Status

- **Spec.** Complete (this document); design entry CRYPTO-C99-SPEC.md §3.23c.
- **Module + gate shipped and green.** `src/crypto/ringsig/ringct_spend.c` (`determ_commit_transpose_prove` / `_verify`, `determ_ringct_spend_verify`); `test-ringct-spend-c99` via `tools/test_ringct_spend_c99.sh` — the transpose dual-oracle byte-freeze vs `tools/verify_ringct_spend.py` (+ `tools/vectors/ringct_spend.json`), the wrong-amount transpose reject, the honest end-to-end spend accept, and the any-layer-tamper / wrong-pseudo-out / wrong-message rejects. Validated MSVC + GCC (`-Wall -Wextra -Wconversion` clean).
- **Claims.** RCS-1 (transpose soundness), RCS-2 (completeness / dual-oracle byte-freeze), RCS-3 (transpose ZK), RCS-4 (end-to-end spend soundness), RCS-5 (the bridge is load-bearing), RCS-6 (memory-safe fail-closed parse) — at the proven-in-code / argued-in-prose split in §3.
- **Non-claims (NC-1..NC-4).** No consensus wiring / no on-chain nullifier set (owner-gated); a partial tx, not a whole one; single-input demo; not constant-time / not post-quantum.
- **Limits (L-1..L-4).** Soundness is an inherited reduction; conformance is one fixed witness; inherited CLSAG/DCT1 assumptions; not a timing/fuzz proof.

Cross-references: [`ClsagRingSignatureSoundness.md`](ClsagRingSignatureSoundness.md) (§3.23b — the input-membership + balance layer), [`LsagRingSignatureSoundness.md`](LsagRingSignatureSoundness.md) (§3.23 — the single-layer ancestor), [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) (§3.22c — the amount range/balance layer), [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the shared `G`/`H` generators the transpose bridges), [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (**NC-7** — the input-unlinkability gap this whole track closes); CRYPTO-C99-SPEC.md §3.23c (this design entry), §3.8c/§3.9b (the P-256 primitives), §3.13 (the dual-oracle vector gate); `src/crypto/ringsig/` module.
