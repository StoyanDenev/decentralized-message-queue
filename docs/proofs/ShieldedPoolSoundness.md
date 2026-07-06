> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# ShieldedPoolSoundness — §3.22 SHIELD (transparent → confidential on-ramp): the accept-rule binds C to the public amount / supply is conserved / additive + state-root-invariant / double-mint blocked

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for **SHIELD** — the **first shielded-pool CONSENSUS operation** and the first chain integration of the §3.19/§3.22 confidential-transaction primitives. SHIELD is the **deposit half** of a confidential pool: it debits a **PUBLIC** amount `A` (+ fee) from a transparent sender and moves that value into a **confidential commitment set** (the `cn:` state namespace) as a Pedersen commitment `C`, tallied in the shielded-supply counter `accumulated_shielded_`.

This closes exactly **one** of the confidential-tx-bundle doc's non-claims — [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) **NC-1** ("no shielded-pool STATE MODEL … deposit/withdraw rules bridging the transparent and confidential value pools"). It closes the **commitment-set + deposit-bridge** part; it deliberately does **not** yet add the **nullifier set / spend / withdraw** parts (see **§4 non-claims** — a SHIELD note can be *created* but nothing yet *consumes* it, so no nullifier is required at this increment).

- **Modules —**
  - accept-rule: `determ_shield_verify` (`src/crypto/pedersen/ctxbundle.c` + `…/ctxbundle.h`), a thin composition of the shipped §3.19 balance/excess primitive.
  - consensus: `TxType::SHIELD = 12` (`include/determ/chain/block.hpp`); apply case + `cn:`/`c:accumulated_shielded` state leaves + conditional snapshot serialize/restore (`src/chain/chain.cpp`); submit-time accept-rule (`src/node/validator.cpp`); provisional debit (`src/node/producer.cpp`); the `accumulated_shielded_` counter + `expected_total()` subtraction (`include/determ/chain/chain.hpp`).
- **Gate —** `test-shield` (the `main.cpp` subcommand) via `tools/test_shield.sh`: the standalone accept-rule (valid / wrong-amount / tampered), the apply-path debit + A1 supply conservation + `cn:`/`c:` leaves + state-root observability, and the two belt-and-suspenders apply rejections (bad proof, duplicate note). The **state-root invariance** for a shield-free chain is witnessed by the whole **FAST golden state-root corpus** staying byte-identical.
- **Inherited crypto —** the amount-binding math is [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (**CTB-1..CTB-8**) via the balance/excess primitive; SHIELD adds **no new hardness assumption**.

**Authoritative external sources.** Maxwell, *"Confidential Transactions"* (2015) — the commitment-set + value-conservation model; Pedersen (CRYPTO '91) — the commitment; Schnorr (J. Cryptology 1991) — the PoK of the blinding. Nothing new is assumed beyond the §3.19 stack.

---

## 1. What SHIELD does — the deposit bridge

### 1.1 Transaction shape

A SHIELD is a normal signed transaction (`TxType::SHIELD = 12`, added **after** `PQ_TRANSFER = 11`) with:

```
tx.amount   = A         PUBLIC deposit amount (in the clear; it MUST be public to debit
                        the transparent balance). Also the fee is public as for any tx.
tx.payload  = C(33) || balance_proof(65)          exactly 98 bytes
    C              SEC1-compressed Pedersen commitment  C = A·G + r·H
    balance_proof  Schnorr PoK that the excess E = C − A·G opens to zero on H
```

The payload is a **normal signed payload** — it is part of `signing_bytes()` and the block hash (unlike the §3.21 `pq_auth` field, which is excluded). This is intentional: the commitment `C` must be authenticated by the depositor's signature so it cannot be swapped in flight.

### 1.2 The accept-rule (`determ_shield_verify`)

```c
int determ_shield_verify(const uint8_t *payload, size_t len, uint64_t amount) {
    if (payload == 0 || len != 98) return -1;
    uint8_t E[33];
    if (determ_p256_balance_excess(E, payload, 1, 0, 0, amount) != 0) return -1;  /* E = C − amount·G */
    return determ_p256_balance_verify(E, payload + 33);                            /* PoK(E = r·H)     */
}
```

This is the **balance/excess primitive** specialized to *one input commitment, zero outputs, `fee = amount`*: the excess is `E = C − A·G`. A verifying balance proof proves `E = r·H` for a known `r` — i.e. `E` has **no `G`-component** — which forces the value committed in `C` to be **exactly `A`**. (If `C` committed to `A' ≠ A`, then `E = (A'−A)·G + r·H` would have a non-zero `G`-coefficient and, since `log_G(H)` is unknown, no balance proof exists for it — inherited **CTB-3**.) So the accept-rule is precisely: **"`C` commits to the declared public amount `A`."** A depositor who tried to commit to *more* than they debit produces a proof that cannot verify. The `n_out = 0` / `C_out = NULL` call is safe: `determ_p256_balance_excess` skips the output loop entirely and computes `cnt = n_in + 0 + 1 = 2` (input + `−fee·G`), never dereferencing the NULL.

### 1.3 The apply path (`chain.cpp`, `TxType::SHIELD` case)

```
A    = tx.amount ; cost = A + tx.fee
if sender.balance < cost            : skip (insufficient funds)
if tx.payload.size() != 98          : skip
if determ_shield_verify(payload,98,A): skip           (belt-and-suspenders re-verify)
ckey = hex(C)                                          (the 33-byte commitment)
if shielded_pool_.count(ckey)       : skip             (duplicate commitment — no double-mint)
sender.balance      -= cost
total_fees          += tx.fee
shielded_pool_[ckey] = height                          (add the unspent note)
accumulated_shielded_ += A                             (A left the transparent live sum)
sender.next_nonce++
```

`A` is **removed from the transparent live sum** (sender debited) and **added to `accumulated_shielded_`**. The fee is redistributed to block creators as for any tx (it stays in the live sum). Value is **relocated, not created or destroyed**.

---

## 2. Supply conservation (the A1 invariant, extended)

The A1 unitary-balance invariant (`chain.hpp`) is asserted after **every** block apply: `Σ accounts.balance + Σ stakes.locked == expected_total()`. §3.22 extends `expected_total()` with a single subtraction:

```
expected_total = genesis_total + accumulated_subsidy + accumulated_inbound
                 − accumulated_slashed − accumulated_outbound − accumulated_shielded
```

Because a SHIELD debits `A` from the transparent live sum **and** adds `A` to `accumulated_shielded_`, the two moves cancel in the identity and A1 continues to hold **exactly**. The apply itself calls the assertion, so a SHIELD that broke conservation would **throw** at apply time (fail-closed). The **total real supply** is `live_total_supply() + accumulated_shielded_` — the confidential pool holds the deposited value as opaque commitments. This is the global-conservation identity `test-shield` pins:

```
live_total_supply() + accumulated_shielded() − accumulated_subsidy() == genesis baseline
```

---

## 3. Claims (SP-1 .. SP-5)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-shield` (or by the FAST golden state-root corpus). **argued-in-prose** = a reduction to a cited theorem or to an inherited CTB-* claim.

- **SP-1 (the accept-rule binds `C` to the public amount `A` — no mint-on-deposit).** `determ_shield_verify(payload, 98, A) == 0` **iff** the 98-byte payload's commitment `C` commits to **exactly** `A` (the excess `E = C − A·G` opens to zero on `H`). Therefore a depositor **cannot inject value** by committing to more than the `A` they are debited — the over-committed `C` has a non-zero `G`-component in `E` and no balance proof verifies for it. **Proven-in-code** (the two `!= 0 return -1` guards are unconditional and sequential) **+ inherited-in-prose** (that `E = r·H` forces `v(C) = A` is **CTB-3** under DL + the Fiat-Shamir ROM). **Evidence:** `test-shield` — a valid payload **accepts** for `A`; the **same** payload **rejects** for a wrong (inflated) `A+1`; a tampered balance proof (last byte flipped) **rejects**.

- **SP-2 (supply is conserved — value is relocated, not created).** A SHIELD moves `A` from the transparent live sum into `accumulated_shielded_`; `expected_total()` subtracts `accumulated_shielded_`; the A1 assertion (`live == expected_total`) is checked at the end of the apply and **throws** on any drift. Hence total real supply `= live_total_supply() + accumulated_shielded_` is invariant across a SHIELD. **Proven-in-code:** the apply performs `sender.balance -= (A+fee)` and `accumulated_shielded_ += A` atomically, and `Chain::append` runs the always-on A1 assertion afterward. **Evidence:** `test-shield` — the SHIELD block applies **without throwing** (A1 held); `accumulated_shielded == A`; the sender is debited **exactly** `A + fee`; and the global identity `live + shielded − subsidy == genesis baseline` holds. Inherits the A1 machinery of [`SupplyProofSoundness.md`](SupplyProofSoundness.md).

- **SP-3 (additive + state-root-invariant — a shield-free chain is byte-identical to a pre-§3.22 chain).** SHIELD is a purely additive feature: a **new** `TxType = 12`, a **new** `cn:` state namespace, and a shielded-supply counter leaf `c:accumulated_shielded`. The state leaves are emitted **conditionally** — the counter leaf only when `accumulated_shielded_ != 0`, and the `cn:` leaves only for a non-empty pool. So on **any chain that never SHIELDs**, `build_state_leaves()` produces the **identical** leaf set it produced before §3.22, hence a **byte-identical `state_root`**. **Proven-in-code** (the `if (accumulated_shielded_ != 0)` guard + the empty-pool loop) **and witnessed by the FAST golden state-root corpus**: every pre-existing `test-*-determinism` / `consensus-vectors` golden root stays green *with the §3.22 code compiled in* — that corpus **IS** the invariance proof. **Evidence:** `test-shield` — genesis has zero shielded supply + an empty pool (the guard is off); a SHIELD **changes** the state root (the `cn:`/`c:` leaves appear — the feature is observable **only when used**); and FAST stays byte-identical.

- **SP-4 (double-mint / duplicate-commitment blocked; belt-and-suspenders re-verify).** In this deposit-only increment a commitment `C` **is its own identifier** — re-SHIELDing the **same** `C` is rejected at apply (`shielded_pool_.count(ckey)` ⟹ skip, no debit, no counter bump), so the same note cannot be minted twice. The accept-rule is enforced in **two** places: the **validator** is the authoritative submit-time gate (rejects malformed SHIELD before mempool), and the **apply** path **re-verifies** (`determ_shield_verify`) as a belt-and-suspenders defense against a tx included by a buggy/hostile producer. **Proven-in-code:** the `count(ckey)` guard + the apply-side `determ_shield_verify` call; both the validator and apply call the **same shared helper** (the S-043 "one formula, one function" rule). **Evidence:** `test-shield` — a bad-proof SHIELD is a **no-op** (sender NOT debited, no note created, A1 intact); a duplicate-commitment SHIELD in a later block is a **no-op** (`accumulated_shielded` and note-count unchanged). **Caveat:** duplicate-detection here is *note creation* only; **spend**/double-spend prevention (the nullifier set) is out of scope until CONFIDENTIAL_TRANSFER lands (NC-1).

- **SP-5 (snapshot round-trips exactly; shield-free snapshot is byte-identical).** `serialize_state` emits `accumulated_shielded` and the `shielded_pool` array **only when non-zero / non-empty**, and `restore_from_snapshot` reads them back with zero/empty defaults. So (a) a shield-free chain's snapshot JSON is **byte-identical** to a pre-§3.22 snapshot, and (b) a shielded chain serializes → restores to a state whose recomputed `state_root` matches. **Proven-in-code:** the conditional `if (accumulated_shielded_ != 0) …` / `if (!shielded_pool_.empty()) …` emit guards + the `snap.value(..., 0)` / `snap.contains("shielded_pool")` restore guards. **Evidence:** the FAST snapshot-round-trip goldens stay green (shield-free byte-identity); the apply path's post-restore A1 assertion covers the shielded round-trip. **Caveat:** this increment does not add a *dedicated* shielded snapshot-round-trip subcommand — the shielded round-trip is covered transitively by the snapshot goldens + A1, not by a bespoke `cn:`-diff assertion (L-2).

---

## 4. Validation map

| Claim | Enforced in source | Gate (`test-shield` unless noted) | Inherited from | Status |
|---|---|---|---|---|
| **SP-1** accept-rule binds `C` to public `A` | `ctxbundle.c` `determ_shield_verify` (excess → balance, both must pass) | valid accepts; wrong-amount rejects; tampered proof rejects | CTB-3 (balance ⟹ conservation) | proven-in-code (both guards) + inherited-in-prose (binding) |
| **SP-2** supply conserved | `chain.cpp` SHIELD apply (`−=cost` / `+=A`) + `chain.hpp` `expected_total()` `−accumulated_shielded_` + A1 assert | applies without throw; `accumulated_shielded==A`; sender −(A+fee); `live+shielded−subsidy==baseline` | SupplyProofSoundness (A1) | proven-in-code |
| **SP-3** additive + state-root-invariant | `chain.cpp` `build_state_leaves` conditional `c:`/`cn:` leaves; `block.hpp` `TxType=12` | genesis shield-free; SHIELD changes root; **FAST golden roots byte-identical** | — | proven-in-code + golden-corpus witness |
| **SP-4** double-mint blocked + re-verify | `chain.cpp` `count(ckey)` skip + apply `determ_shield_verify`; `validator.cpp` SHIELD case | bad-proof no-op; duplicate-commitment no-op | S-043 shared-helper rule | proven-in-code |
| **SP-5** snapshot round-trip / shield-free byte-identity | `chain.cpp` conditional serialize/restore of `accumulated_shielded` + `shielded_pool` | FAST snapshot goldens + post-restore A1 | — | proven-in-code (conditional emit) |

The `test-shield` gate is the **consensus-integration** witness (debit + conservation + leaf emission + double-mint) that the accept-only crypto vectors cannot provide; the amount-binding crypto is the already-green §3.19 balance stack. Their conjunction — bounded by L-1..L-4 — is what "SHIELD is a fail-closed, supply-conserving, state-root-invariant deposit into a confidential commitment set whose accept-rule binds `C` to the declared public amount, under the inherited DL + ROM assumptions" means for this §3.22 consensus increment.

---

## 5. Non-claims — SHIELD IS THE DEPOSIT HALF, NOT A COMPLETE SHIELDED POOL

**Read this before treating SHIELD as a privacy feature.** SHIELD is the transparent→confidential **on-ramp** — a value bridge + commitment binding. A complete confidential-transaction feature needs strictly more, none of which ships in this increment:

- **NC-1 — No SPEND / withdraw / nullifier set yet.** SHIELD only **creates** notes. There is **no `CONFIDENTIAL_TRANSFER`** (confidential→confidential, which needs the DCT1 bundle consuming input notes and producing output notes) and **no `UNSHIELD`** (confidential→transparent). Because nothing yet **consumes** a note, no **nullifier set** is required at this increment — but a real pool needs one, and it is the *next* increment. Double-**spend** prevention is therefore explicitly out of scope (SP-4 blocks double-**mint** of the same commitment, a different thing).

- **NC-2 — The SHIELD amount `A` is PUBLIC — SHIELD hides NOTHING by itself.** `A` is `tx.amount`, in the clear, and *must* be to debit the transparent balance; the fee is public too. Amount privacy begins only once value moves **confidential → confidential** via the not-yet-shipped `CONFIDENTIAL_TRANSFER`. What SHIELD provides is the *bridge* + the *binding* (`C` commits to exactly `A`), so that value can *later* be moved privately. The commitment `C` is hiding, but with `A` public the deposit reveals its own amount.

- **NC-3 — No sender / receiver / graph privacy.** The depositor's transparent address (`tx.from`) is public, as is the existence of the SHIELD. This is inherited **NC-3** of the bundle doc.

- **NC-4 — Not post-quantum.** The amount-binding soundness rests on P-256 discrete log (ECDLP), broken by Shor. Classical-adversary construction.

- **NC-5 — Single-shard, single-profile (P-256 / FIPS).** SHIELD is wired for the P-256 confidential-tx stack on a single shard. A cross-shard confidential transfer and the `Z_p*` (MODERN) mirror are not wired. Anonymous (bearer) senders **may** SHIELD (the validator relaxes its anon-only-`TRANSFER` gate to also allow `SHIELD`), but that is an on-ramp permission, not graph privacy.

---

## 6. Limits (L-1 .. L-4)

- **L-1 — Soundness is an inherited REDUCTION, not a machine-checked extractor.** SP-1's binding rests on CTB-3 (balance = conservation, reduced to Schnorr 1991 + Pedersen binding under DL + the Fiat-Shamir ROM). This document adds **no** new extractor and re-proves **nothing**; a break of P-256 DL or the ROM assumption breaks SHIELD regardless of the consensus gating. The `test-shield` tamper witnesses show the deployed reject paths fire — they are **not** a soundness proof.

- **L-2 — Conformance is over a FIXED witness + the golden invariance corpus, not the input space.** `test-shield` exercises one honest deposit (`A = 100`, fixed blinding) plus its wrong-amount / tampered / bad-proof / duplicate variants; the state-root **invariance** is the FAST golden corpus (a shield-free chain), not an exhaustive sweep of shielded chains. The shielded snapshot round-trip is covered transitively (SP-5 caveat), not by a bespoke `cn:`-diff subcommand.

- **L-3 — The accept-rule lives in TWO enforcement sites (by design).** The validator (authoritative, submit-time) and the apply path (belt-and-suspenders) both gate SHIELD; both call the **same** `determ_shield_verify` (the S-043 shared-helper discipline), so they cannot drift. The producer additionally debits provisionally. Three sites, one formula.

- **L-4 — Not a constant-time claim beyond §3.19's prover CT-hardening.** `determ_shield_verify` runs on public, attacker-supplied bytes (amount `A` is public), so its timing is not secret-dependent. The depositor's blinding `r` is chosen client-side; the §3.19 balance *prover* was CT-hardened 2026-07-06 (`ConstantTimeInventory.md`). This document asserts only functional soundness.

---

## 7. Status

- **Spec.** Complete (this document); design entry CRYPTO-C99-SPEC.md §3.22 (SHIELD sub-section).
- **Consensus integration shipped and green.** `TxType::SHIELD = 12`; apply case + `cn:`/`c:accumulated_shielded` state leaves + conditional snapshot serialize/restore (`chain.cpp`); `accumulated_shielded_` counter + `expected_total()` subtraction (`chain.hpp`); submit-time accept-rule + relaxed anon gate (`validator.cpp`); provisional debit (`producer.cpp`); accept-rule `determ_shield_verify` (`ctxbundle.c`). Gate: `test-shield` via `tools/test_shield.sh` (accept-rule valid/wrong-amount/tampered; apply debit + A1 conservation + `cn:`/`c:` leaves + state-root observability; bad-proof + duplicate-note no-op). State-root invariance witnessed by the FAST golden corpus.
- **Claims.** SP-1 (accept-rule binds `C` to public `A`), SP-2 (supply conserved), SP-3 (additive + state-root-invariant), SP-4 (double-mint blocked + belt-and-suspenders re-verify), SP-5 (snapshot round-trip / shield-free byte-identity) — at the proven-in-code / inherited-in-prose split in §4.
- **Non-claims (NC-1..NC-5).** No spend/withdraw/nullifier yet (deposit half only); the SHIELD amount is PUBLIC (no privacy from SHIELD alone); no sender/receiver/graph privacy; not post-quantum; single-shard / P-256 profile.
- **Limits (L-1..L-4).** Soundness is an inherited reduction; conformance is a fixed witness + the golden invariance corpus; the accept-rule lives in two sites (shared helper); not a timing proof beyond §3.19's CT-hardening.

Cross-references: [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) (**NC-1** — the shielded-pool state model SHIELD begins to close; CTBN-1..CTBN-5); [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (CTB-1..CTB-8 — the inherited amount-binding soundness); [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the commitment); [`SupplyProofSoundness.md`](SupplyProofSoundness.md) (the A1 unitary-supply machinery SP-2 extends); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (the owner-gated integration proposal); CRYPTO-C99-SPEC.md §3.22 (the SHIELD + DCT1 design entry), §3.19 (the P-256 confidential-tx primitives).
