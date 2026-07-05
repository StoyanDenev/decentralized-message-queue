> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# ConfidentialTxBalanceSoundness — the confidential-transaction BALANCE PROOF + end-to-end COMPOSITION over both curve/group profiles: setup / reduction chain / completeness / soundness / amount-hiding + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **amount-conservation half** of a confidential transaction and for the **end-to-end composition** that ties it to the range-proof half — on **both** curve/group profiles Determ ships:

- **FIPS profile — NIST P-256** (`src/crypto/pedersen/balance.c`, CRYPTO-C99-SPEC.md **§3.19 increment 7**) + the composition test (`test-p256-confidential-tx-c99`, **§3.19 increment 8**);
- **MODERN profile — `Z_p*` (RFC 3526 MODP-3072 prime-order subgroup)** (`src/crypto/ff/ffbalance.c`, CRYPTO-C99-SPEC.md **§3.20 increment 7**) + the composition test (`test-ff-confidential-tx-c99`, **§3.20 increment 8**).

It is the sibling of, and depends on, the **range-proof** soundness accounting: [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) + [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) + [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the §3.19 P-256 inc.1-6 stack) and [`FiniteFieldBulletproofsSoundness.md`](FiniteFieldBulletproofsSoundness.md) (the §3.20 `Z_p*` inc.1-6 stack). Those account for the *no-inflation-by-overflow / non-negativity* half (every output value lies in `[0, 2^n)`); **this** document accounts for the *amount-conservation* half (`Σ v_in = Σ v_out + fee`) and the composition of the two into a confidential transaction.

The owner-decided curve/group split (CRYPTO-C99-SPEC.md §3.19/§3.20, 2026-07-05): **FIPS profiles get the P-256 stack; MODERN profiles get the finite-field stack** — the same protocol algebra over a different group. The two balance proofs are structurally identical; the two compositions are structurally identical. This document accounts for both at once, flagging the per-profile differences where they matter (P-256 is an additive elliptic-curve group; `Z_p*` is a multiplicative finite-field group).

This is **library-primitive-first, KAT-gated, ZERO consensus touch** (both balance modules carry "LIBRARY PRIMITIVE — no chain call site"; additive, not wired into any chain, ledger, or wallet path). The integration into the ledger is design-stage and owner-gated; see [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (a FUTURE-tier proposal, decides nothing).

## Scope

**In scope.** The exported operations of the two balance modules, plus the two composition tests, verified against the source:

- **The balance proof** (both profiles): `determ_p256_balance_excess` / `_prove` / `_verify` (P-256) and `determ_ff_balance_excess` / `_prove` / `_verify` (`Z_p*`). A Schnorr proof of knowledge of the blinding excess `x` with `E = x·H` (additive) / `E = h^x` (multiplicative), where `E` is the commitment excess `Σ C_in − Σ C_out − fee·G` (additive) / `Π C_in · Π C_out^{-1} · g^{-fee}` (multiplicative).
- **The composition** (both profiles): the structural composition of a per-output range proof (inc.5/6) with the balance proof (inc.7) into one confidential transaction, exercised by `test-p256-confidential-tx-c99` / `test-ff-confidential-tx-c99`.

**Out of scope.**
- **The range proofs themselves** (inc.1-6, both profiles) — accounted for in the four sibling documents above. This document treats a verifying range proof as a black-box witness that its committed value lies in `[0, 2^n)`.
- **Any chain / wallet wiring** — no Determ code path constructs, proves, or verifies a confidential transaction (NC-2).
- **Timing side channels** — the group exponentiation / multi-exponentiation branches on secret scalars; CT-hardening is the owner-gated step (NC-3, L-4).
- **Privacy beyond amounts** — a confidential transaction hides *amounts*, not sender/receiver identity, the transaction graph, the fee (public), or the fact a transaction exists (NC-1).
- **Post-quantum security** — both discrete-log assumptions are broken by Shor's algorithm (NC-4, L-5).

**Authoritative external sources.** Schnorr, *"Efficient Signature Generation by Smart Cards"* (J. Cryptology 1991) — the proof of knowledge of discrete log; Maxwell, *"Confidential Transactions"* (2015) — the balance-via-commitment-excess construction; Pedersen, *"Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"* (CRYPTO '91) — the commitment. The discrete-log hardness assumption is over the P-256 group (ECDLP) / the MODP-3072 subgroup (finite-field DL); the non-interactive Fiat-Shamir transform is sound in the **random-oracle model (ROM)** — both assumed, not proved here (L-1, L-3).

---

## 1. Setup: the commitment excess and the balance relation

### 1.1 The two groups and the commitment

| | FIPS profile (§3.19) | MODERN profile (§3.20) |
|---|---|---|
| Group | NIST P-256, additive, prime order `n` | `G_q ⊂ Z_p*`, multiplicative, prime order `q` |
| Value generator | `G` (the base point) | `g = 4` (a QR of order `q`) |
| Blinding generator | `H` (nothing-up-my-sleeve RFC 9380 hash-to-curve, unknown `log_G(H)`) | `h` (nothing-up-my-sleeve hash-to-group, unknown `log_g(h)`) |
| Commitment | `C = v·G + r·H` | `C = g^v · h^r mod p` |
| Element / scalar wire | 33-byte SEC1 compressed / 32-byte big-endian | 384-byte big-endian / 384-byte big-endian |

The commitment is **binding** under discrete log (a second opening recovers `log(H)`) and **information-theoretically hiding** for uniform blinding — the base-primitive facts established in [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (P-256) / [`FiniteFieldBulletproofsSoundness.md`](FiniteFieldBulletproofsSoundness.md) FFBP-1/FFBP-2 (`Z_p*`). This document inherits them (CTB-8).

### 1.2 The balance relation and the excess

A confidential transaction with input value-commitments `C_in`, output value-commitments `C_out`, and a **public** fee `fee` **conserves value** iff `Σ v_in = Σ v_out + fee`. Define the **commitment excess**

```
FIPS   :  E = Σ C_in − Σ C_out − fee·G          (additive)
MODERN :  E = Π C_in · Π C_out^{-1} · g^{-fee}   (multiplicative)
```

Expanding with `C = v·G + r·H` (resp. `g^v·h^r`), the excess collapses to

```
E = (Σv_in − Σv_out − fee)·G + (Σr_in − Σr_out)·H       (additive)
E = g^{(Σv_in − Σv_out − fee)} · h^{(Σr_in − Σr_out)}    (multiplicative)
```

so **`E` has no G-component (resp. no g-component) iff the transaction conserves value**, in which case `E = x·H` (resp. `E = h^x`) for the **blinding excess** `x = (Σ r_in − Σ r_out) mod n` (resp. `mod q`).

**The scalar-negation trick (both profiles, no group-inverse primitive):** the point subtractions `−C` and `−fee·G` are computed as **scalar negations in the exponent** — `−C = (n−1)·C`, `−fee·G = (n−fee)·G` (additive) / `C^{-1} = C^{q-1}`, `g^{-fee} = g^{q-fee}` (multiplicative) — so `E` is a single multi-exponentiation (`determ_pedersen_msm` / `determ_ff_msm`) with **no point-negation / group-inverse primitive** and, on P-256, **no change to the sealed core** (the two mod-`n` scalar ops it needs are implemented locally in `balance.c`).

### 1.3 The proof

The prover proves knowledge of `x` with a **Schnorr proof of discrete log base `H`** (`E = x·H` / `E = h^x`): pick nonce `k`; `T = k·H` (resp. `h^k`); `c = Hash(E ‖ T)`; `s = k + c·x mod` order; the proof is `T ‖ s`. The verifier recomputes `c` and checks `s·H == T + c·E` (resp. `h^s == T · E^c`). The Fiat-Shamir challenge is `determ_p256_hash_to_scalar` / `determ_ff_hash_to_scalar` over the domain-separation tag `DETERM-P256-BALANCE-v1-challenge` / `DETERM-FF-BALANCE-v1-challenge`. Proof sizes: **65 bytes** (`compress(T)‖s = 33+32`, P-256) / **768 bytes** (`T‖s = 384+384`, `Z_p*`).

---

## 2. Claims

**PROVEN-by-KAT** = byte-pinned or reject-witnessed by a shipped, green test; **argued-in-prose** = a reduction to the cited literature theorem (assumed, not machine-checked here).

### 2.1 The balance proof

- **CTB-1 (balance completeness — an honestly-balanced tx always verifies).** For a value-conserving transaction (`Σv_in = Σv_out + fee`) with honestly-formed commitments, `balance_excess` yields `E = x·H` (resp. `h^x`) with `x = (Σr_in − Σr_out) mod` order, and `balance_verify(E, balance_prove(E, x, k))` returns accept. The decisive fact is §1.2: value conservation kills the G/g-component of `E`, so `E` is exactly `x·H`, and the Schnorr identity `s·H = (k + c·x)·H = T + c·(x·H) = T + c·E` holds. **Evidence:** the balanced-accept assertion of `test-p256-balance-c99` / `test-ff-balance-c99` (each 3 assertions) + the balanced vectors of `p256_balance.json` / `ff_balance.json` (each 2 vectors) whose proofs the file-side oracle re-verifies. The Python selftests additionally assert the algebraic identity `E == x·H` (resp. `pow(H, x, P)`) directly before proving. **Caveat:** verified on the fixed corpus + selftest witnesses; completeness for arbitrary balanced inputs follows from the §1.2 algebra.

- **CTB-2 (the Schnorr proof is a sound PoK of discrete log base `H`).** A prover that makes `balance_verify` accept for a given `E` knows `x` with `E = x·H` (resp. `h^x`), except with negligible probability. **Argument (reduction, NOT re-proved here):** Schnorr 1991 — special-soundness (two accepting transcripts `(T, c, s)`, `(T, c', s')` with `c ≠ c'` on the same `T` extract `x = (s − s')·(c − c')^{-1}`), lifted to the non-interactive setting by the forking lemma in the ROM. This is the standard proof-of-knowledge-of-discrete-log result; it is **assumed**, corroborated by the tamper-reject witnesses (CTB-6), not machine-checked (L-1/L-3).

- **CTB-3 (balance soundness — a verifying balance proof binds value conservation).** If `balance_verify(E, π)` accepts for the excess `E` derived from a transaction's commitments, then `Σ v_in = Σ v_out + fee`, except by breaking discrete log or the ROM assumption. **Argument (reduction):** by CTB-2 the prover knows `x` with `E = x·H` (resp. `h^x`), i.e. `E` has a **zero** G/g-component. But `E = (Σv_in − Σv_out − fee)·G + (Σr_in − Σr_out)·H` by construction (§1.2); a zero G-component with a *known* representation forces `Σv_in − Σv_out − fee ≡ 0` **unless the prover knows `log(H)`** (which would let it move value between the `G` and `H` components) — and `log(H)` is exactly the unknown-discrete-log the nothing-up-my-sleeve generator rules out. So value conservation is bound to the unknown-`log(H)` assumption, i.e. binding of the commitment under DL. **Why an unbalanced tx fails, concretely:** if `Σv_out + fee ≠ Σv_in`, `E` gains a nonzero G/g-component `Δ·G`, so `E ≠ x·H` for any `x`; the honest prover cannot produce a `T,s` satisfying `s·H = T + c·E` (that would require solving for `log(H)`). **Evidence (reject witnesses, NOT an extractor):** `test-*-balance-c99` builds an unbalanced tx (one output value bumped, honest blindings) and requires `balance_verify` to REJECT; the Python selftests additionally assert `E_bad ≠ x·H` before checking the reject. **Caveat:** these witness that the deployed reject path fires; they are **not** a machine-checked extractor and **not** a proof of soundness (that is Schnorr 1991 + commitment binding under DL + ROM, L-1/L-3).

- **CTB-4 (amount-hiding — the proof + excess reveal nothing about the amounts).** The balance proof and the excess `E` reveal nothing about the individual amounts `v_in`/`v_out` or blindings `r_in`/`r_out` beyond the (public) fact that the transaction is balanced. Each commitment `C = v·G + r·H` is perfectly hiding for uniform blinding (base-primitive fact); `E = x·H` is a commitment to zero under the blinding excess `x`; and the Schnorr transcript `(T, s)` is a standard honest-verifier zero-knowledge proof (a simulator with the challenge produces an identically-distributed `(T, s)` without `x`). **Assumed, not proved here:** Schnorr HVZK is the cited literature property; this document does not machine-check a simulator. **Caveat:** the proof *does* reveal the number of inputs/outputs and the public fee; and hiding assumes the blindings are drawn from a CSPRNG (the tests supply them deterministically for KAT reproducibility, L-2).

### 2.2 The composition

- **CTB-5 (composition soundness — range ∧ balance = a sound confidential transaction).** A confidential transaction that (a) carries a verifying range proof for **every** output and (b) carries a verifying balance proof is sound: no output is negative or overflows the scalar field (no wrap-forge), and total value is conserved (no mint/burn). This is the composition of two independent guarantees:
  - **Range = non-negativity / no-overflow:** each output's range proof binds `v_j ∈ [0, 2^n)` (the sibling-doc results RP-2 / FFBP-4), so no output value is negative and none wraps the order to forge coins.
  - **Balance = conservation:** CTB-3 binds `Σ v_in = Σ v_out + fee`.
  The **load-bearing composition fact** is that the SAME commitment serves both proofs: an output's range-proof value commitment `V_j = v_j·G + γ_j·H` (resp. `g^{v_j}·h^{γ_j}`) is **byte-identical** to its balance-side tx commitment `C_out[j] = v_j·G + r_j·H` when `γ_j = r_j` — because both primitives use the **same** value generator `G`/`g` and blinding generator `H`/`h`. A cross-primitive generator mismatch (a different `G` or `H` between the range proof and the balance proof) would silently break the composition. **Evidence:** `test-p256-confidential-tx-c99` / `test-ff-confidential-tx-c99` (6 assertions each) assert `V_j == C_out[j]` by `memcmp` (a genuine cross-primitive check: on P-256 `V_j` comes from the range prover's MSM path and `C_out[j]` from the Pedersen limb path — two distinct code paths, the same math), then require the honest tx to accept (all range proofs AND the balance proof), an **inflation** attempt (an output bumped so `Σv_out + fee ≠ Σv_in`, honest blindings) to be caught by the **balance** proof while the per-output range proofs still pass, and an **out-of-range** output (`= 2^n`) to be caught by that output's **range** proof. **Caveat:** this is the *division-of-labour* demonstration on a fixed 2-in-2-out witness; the general soundness is the conjunction of the sibling-doc range results + CTB-3, not an exhaustive proof over all transaction shapes (L-2). An independent adversarial review of the `Z_p*` composition test confirmed all six assertions are non-vacuous (the identity check is a real two-code-path cross-check; the reject assertions genuinely require rejection).

- **CTB-6 (dual-oracle byte-exactness + reject witnesses — the C bytes equal an independent from-scratch Python's, and every reject path fires).** For every balance corpus vector the shipped C recomputes the excess `E` + the entire Schnorr proof and matches, **byte-for-byte**, an independent from-scratch Python implementation; and the deployed reject paths (unbalanced tx, tampered proof, out-of-range output) all fire. **Evidence:** the §3.13 dual-oracle over `p256_balance.json` (2 vectors, `tools/verify_p256_balance.py`, own scalar-mult ladder) + `ff_balance.json` (2 vectors, `tools/verify_ff_balance.py`, native bignums) — both wired into `test-c99-vectors` (binary half) AND `test_c99_vector_files.sh` (Python file half, which also re-verifies each proof); plus the structural `test-*-balance-c99` (balanced accept + unbalanced reject + tamper reject) and `test-*-confidential-tx-c99` (the 6-assertion composition). The Python composition oracles (`tools/verify_{p256,ff}_confidential_tx.py`) prove the flow (honest-accept + inflation-reject-by-balance + OOR-reject-by-range) independently. **Caveat:** byte-exact over exactly the frozen corpora (one witness family per case), not the input space (L-2).

- **CTB-7 (group-independence — the two profiles are the same protocol over a different group).** The FIPS and MODERN balance proofs (and compositions) are the identical protocol algebra with the P-256 additive scalar-mult `s·P` playing the role of the `Z_p*` multiplicative exponentiation `P^s`. The scalar-negation trick (§1.2) is identical in both. **Two per-profile differences, both handled:** (i) on P-256 the group **identity has no SEC1-compressed encoding**, so the degenerate `x = 0` case (a balanced tx whose blindings happen to cancel, giving `E = 0·H = O`) is excluded from the corpus — a real transaction with CSPRNG blindings never hits it, and `balance_excess` returns the 3-way MSM code `1` for the identity rather than a spurious point (whereas the `Z_p*` identity is the representable element `1`); (ii) on P-256 the two mod-`n` scalar ops the excess needs (`add_mod_n`, `negate_mod_n`) are **not** in the public P-256 API (which exposes only mul/inv), so `balance.c` implements them locally over the exported curve order — an independent adversarial audit confirmed those local ops correct in all regimes (the `a+b == n` reduction; the `carry ⟹ a+b−n < n` argument for `n > 2^255`), the SEC1 compression parity, and fail-closed-on-identity. On `Z_p*` the public scalar field already exposes add/sub, so `ffbalance.c` uses them directly.

- **CTB-8 (trust inheritance + fail-closed — no new hardness, no new arithmetic above the gated primitives).** Both balance proofs compose over already-gated primitives — the Pedersen commit + MSM + `hash_to_scalar` of the §3.19/§3.20 stacks (themselves gated by their own KAT + dual-oracle corpora and audits) — introducing only the Schnorr transcript and, on P-256, the two local mod-`n` scalar ops (CTB-7). `balance_verify` is **fail-closed**: a malformed `T`/`E`/`s`, an out-of-range scalar, or an MSM that returns the group identity all yield a reject (`−1`) rather than a spurious accept. **Evidence:** the tamper-reject assertions + the audits; the fail-closed identity handling verified in the P-256 audit (property 6). **Caveat:** a forward-reference — the inc.1-6 primitive correctness is discharged by the sibling docs, not re-derived here.

---

## 3. Validation map

| Claim | Structural test (`determ …`) | §3.13 dual-oracle corpus | Independent check | Status |
|---|---|---|---|---|
| **CTB-1** balance completeness | `test-p256-balance-c99` / `test-ff-balance-c99` — balanced accept (3 assertions each) | `p256_balance.json` (2) / `ff_balance.json` (2) | Python selftests assert `E == x·H` before proving | KAT (round-trip) + prose (identity) |
| **CTB-2** Schnorr PoK sound | (tamper-reject witnesses) | — | **Schnorr 1991** special-soundness / forking lemma — argued-in-prose | prose (extractor) |
| **CTB-3** balance soundness | `test-*-balance-c99` — unbalanced tx rejects | `p256_balance.json` / `ff_balance.json` | Python selftests assert `E_bad ≠ x·H` | KAT (reject witness) + prose (reduction) |
| **CTB-4** amount-hiding | (structural: blindings caller-supplied) | — | Schnorr HVZK + perfect commitment hiding — argued-in-prose | prose |
| **CTB-5** composition soundness | `test-p256-confidential-tx-c99` / `test-ff-confidential-tx-c99` (6 assertions each: `V_j==C_out[j]`, honest accept, inflation→balance-reject, OOR→range-reject) | (composed bytes pinned by the range + balance corpora) | Python composition oracles; the `Z_p*` composition non-vacuity audit (all 6 SOUND) | KAT (division of labour) + prose (general conjunction) |
| **CTB-6** dual-oracle byte-exactness | `test-c99-vectors` (binary half) + `test_c99_vector_files.sh` (Python file half) | `p256_balance.json` + `ff_balance.json` (4 vectors) | C bytes == independent from-scratch Python bytes; proofs re-verified | KAT (byte-pinned) |
| **CTB-7** group-independence | both profiles' tests | both corpora | the P-256 balance local-arithmetic audit (add/negate-mod-n regimes, SEC1 parity, fail-closed) — all SOUND | KAT + prose + audit |
| **CTB-8** trust inheritance + fail-closed | tamper-reject; malformed-input reject | all corpora | sibling-doc primitive gates; the fail-closed-on-identity audit finding | KAT (fail-closed) + prose (inheritance) |

The two-leg split is the standard §3.13 defense-in-depth: the structural `test-*-c99` subcommands are the **reject-path + round-trip + composition** witnesses the accept-only vectors cannot provide; the byte gate is the **dual-oracle conformance** witness (C == independent Python over frozen bytes). Their conjunction — bounded by L-1..L-6 — is what "the confidential-tx balance proof is complete, deterministic, byte-conformant, amount-hiding, and binds value conservation under discrete log + ROM, on both profiles" means for these §3.19/§3.20 library primitives.

---

## 4. Non-claims (NC-1 .. NC-4) and limits (L-1 .. L-6)

### Non-claims
- **NC-1 — Amount privacy only, NOT identity / graph / fee / existence privacy.** A confidential transaction hides the *amounts*. It does NOT hide the sender or receiver, the transaction graph, the fee (public by construction — it appears as the `fee·G` / `g^{-fee}` term), or the fact that a transaction exists.
- **NC-2 — Not a consensus or wallet primitive.** No Determ chain/ledger/wallet path constructs, proves, or verifies a confidential transaction. This is an additive **library primitive with no in-tree consumer**. Chain integration is a separate, owner-gated, consensus-critical step — see [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md).
- **NC-3 — Not constant-time.** The group exponentiation / multi-exponentiation (`modexp_c` / the P-256 ladder) and the zero-scalar skips branch on secret scalars (the blinding excess `x`, the nonce `k`). A production prover needs constant-time variants. This document asserts **functional** correctness only, not timing (L-4). CT-hardening is the owner-gated step and, per the design doc, a hard requirement before any on-chain prover use.
- **NC-4 — Not post-quantum.** Soundness (CTB-2/CTB-3) rests on discrete log (ECDLP / finite-field DL), which Shor's algorithm solves on a scalable quantum computer. Classical-adversary construction (L-5).

### Limits
- **L-1 — Soundness/binding is not proven; it is assumed under discrete log + ROM.** CTB-2/CTB-3 are reductions to Schnorr 1991 + commitment binding; the tests exercise reject paths (unbalanced, tamper), **not** a machine-checked extractor. A break of DL breaks value-conservation binding regardless of any byte-exactness here.
- **L-2 — Bounded input set.** CTB-6 quantifies over exactly the frozen corpora (4 balance vectors total); the composition tests use a fixed 2-in-2-out witness. Completeness/soundness/hiding for arbitrary transaction shapes follow from the algebra + the cited theorems, not exhaustive coverage. Amount-hiding assumes CSPRNG blindings (caller-supplied deterministically for KAT reproducibility).
- **L-3 — The Fiat-Shamir transform's soundness is in the ROM.** The non-interactive challenge is `hash_to_scalar(E ‖ T)`; that this is as sound as the interactive protocol is a ROM result. Assumed, not proved.
- **L-4 — Timing out of scope.** The secret-scalar exponentiation branches (NC-3) mean a constant-time prover is the owner-gated hardening step (CRYPTO-C99-SPEC §3.12 / [`ConstantTimeInventory.md`](ConstantTimeInventory.md)).
- **L-5 — Not post-quantum (NC-4).** Discrete log is broken by Shor.
- **L-6 — The `x = 0` / identity-excess degeneracy (P-256).** A balanced transaction whose blindings exactly cancel gives `E = O` (the group identity), which has no SEC1-compressed encoding and cannot be Schnorr-proven; this measure-zero case is excluded from the P-256 corpus and never arises with CSPRNG blindings (CTB-7). The `Z_p*` identity is the representable element `1`, so the case does not arise there.

---

## 5. Status

- **Spec.** Complete (this document).
- **Both profiles' balance + composition tests shipped and green.** `test-p256-balance-c99` / `test-ff-balance-c99` (3 assertions each: balanced accept + unbalanced reject + tamper reject); `test-p256-confidential-tx-c99` / `test-ff-confidential-tx-c99` (6 assertions each: `V_j==C_out[j]` + honest accept + inflation-reject-by-balance + out-of-range-reject-by-range); the binary + Python file halves validate `p256_balance.json` + `ff_balance.json` (4 vectors) byte-for-byte against the independent from-scratch Python references.
- **Claims.** CTB-1 (balance completeness), CTB-2 (Schnorr PoK of discrete log — argued from Schnorr 1991), CTB-3 (balance soundness = value conservation, reduced to CTB-2 + commitment binding under DL + ROM; reject witnesses, NOT an extractor), CTB-4 (amount-hiding — HVZK + perfect commitment hiding), CTB-5 (composition soundness — range ∧ balance, the `V_j==C_out[j]` identity + the division of labour), CTB-6 (dual-oracle byte-exactness + reject witnesses, both profiles), CTB-7 (group-independence — same protocol, P-256-vs-`Z_p*` differences handled, local-arithmetic audited), CTB-8 (trust inheritance + fail-closed) — all closed at the KAT/prose split recorded in §3.
- **Non-claims (NC-1..NC-4).** Amount privacy only (not identity/graph/fee/existence); not a consensus/wallet primitive (owner-gated integration); not constant-time (owner-gated CT hardening, a hard prerequisite before on-chain use); not post-quantum.
- **Limits (L-1..L-6).** Soundness/binding assume DL + generator independence (reduction, not extractor); conformance is over the frozen corpora + a fixed composition witness; Fiat-Shamir soundness is in the ROM; timing → §3.12 / `ConstantTimeInventory.md`; not PQ (Shor); the P-256 `x=0`/identity degeneracy is excluded.

Cross-references: [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) / [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) / [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the §3.19 P-256 range-proof half); [`FiniteFieldBulletproofsSoundness.md`](FiniteFieldBulletproofsSoundness.md) (the §3.20 `Z_p*` range-proof half); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (the FUTURE-tier, owner-gated chain-integration proposal); CRYPTO-C99-SPEC.md §3.19/§3.20 (design entries, inc.7 balance proof + inc.8 composition), §3.13 (the dual-oracle vector gate); `src/crypto/pedersen/README.md` + `src/crypto/ff/README.md` (module provenance).
