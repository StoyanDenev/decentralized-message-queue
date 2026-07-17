> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# ShieldedPoolSoundness — §3.22 SHIELD (deposit) + §3.22b UNSHIELD (withdraw): accept-rules bind C to the public amount / a tx-bound proof defeats front-running / supply is conserved / additive + state-root-invariant / the commitment is its own nullifier

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **shielded-pool consensus track** — the chain integration of the §3.19/§3.22 confidential-transaction primitives. Two operations ship here:

- **§3.22 SHIELD** — the **deposit** on-ramp: debits a **PUBLIC** amount `A` (+ fee) from a transparent sender and adds a Pedersen commitment `C` to a **confidential commitment set** (the `cn:` state namespace), tallied in the shielded-supply counter `accumulated_shielded_`.
- **§3.22b UNSHIELD** — the **withdraw** off-ramp: **spends** an unspent note `C` and returns its PUBLIC amount `A` to a transparent recipient (minus fee). The commitment **is its own nullifier** — apply removes `C` from the set, so a note is spendable at most once (the *named-input* CT model: inputs reference prior output commitments, membership = the unspent set).
- **§3.22c CONFIDENTIAL_TRANSFER** — confidential→confidential: consumes `n_in` unspent **named** input notes and produces `m` output notes with **HIDDEN amounts**, verified by the shipped **DCT1 bundle** (range ∧ balance: `Σv_in = Σv_out + fee`, fee PUBLIC). Inputs are removed (their own nullifiers), outputs added, the public fee leaves the pool to creators. This is the **first consensus consumer** of the CTX-1 DCT1 bundle. Amount-**private in motion** — but **not** input-unlinkable (inputs are named) and with no on-chain output-secret delivery (NC-7/NC-8).

Together these close the **deposit/withdraw + confidential-move + commitment-set + nullifier** parts of [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) **NC-1** ("no shielded-pool STATE MODEL"). The remaining privacy work is **input-unlinkability** (hidden inputs via a nullifier-from-secret + set-membership argument) — a genuinely larger, owner-gated crypto increment, not yet built.

**The load-bearing UNSHIELD property is the CONTEXT-BOUND spend proof.** A confidential withdraw proves knowledge of the note blinding `r` (which authorizes the spend), but a *bare* proof-of-knowledge is **replayable**: the balance proof is decoupled from the tx signer, so a mempool observer could copy the public `C‖proof` into their OWN tx and **redirect the credit** (front-running theft). The fix binds the proof's Fiat-Shamir challenge to `ctx = SHA-256(from ‖ to ‖ nonce ‖ amount)` of the withdrawing tx, so any change to those fields invalidates the proof. This is a new construction, owner-authorized (2026-07-06) under the FROST-deviation discipline.

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

- **SP-2 (supply is conserved — value is relocated, not created).** A SHIELD moves `A` from the transparent live sum into `accumulated_shielded_`; `expected_total()` subtracts `accumulated_shielded_`; the A1 assertion (`live == expected_total`) is checked at the end of the apply. Hence total real supply `= live_total_supply() + accumulated_shielded_` is invariant across a SHIELD. **Proven-in-code:** the apply computes the debit `cost = A + fee` via `checked_add_u64` and **skips the tx on overflow** (no state change), then performs `sender.balance -= cost` and `accumulated_shielded_ += A` atomically, and `Chain::append` runs the always-on A1 assertion afterward. **Evidence:** `test-shield` — the SHIELD block applies **without throwing** (A1 held); `accumulated_shielded == A`; the sender is debited **exactly** `A + fee`; and the global identity `live + shielded − subsidy == genesis baseline` holds. Inherits the A1 machinery of [`SupplyProofSoundness.md`](SupplyProofSoundness.md).
  - **S-049 correction (checked debit is the guard, NOT A1).** An earlier draft rested SP-2/SP-7/SP-12 on the claim that the always-on A1 assertion "throws on any drift." A1 is a **mod-2^64 identity**, so it does *not* catch a value-conservation break whose injected discrepancy is an exact multiple of 2^64 — precisely the failure the pre-S-049 unchecked `A + fee` debit produced (an attacker choosing `A ≈ 2^64 − fee` wrapped `cost` to ~0, minting the note; both sides of A1 then moved by 0 mod 2^64 and A1 stayed silent). The actual guarantee that value is *relocated, not created* is therefore the **checked debit** (`checked_add_u64(A, fee) → skip on overflow`) together with **Pedersen binding** (which fixes `accumulated_shielded_ += A` to the true committed value) — A1 remains a useful non-2^64-multiple drift check but is not a general overflow/underflow catch. See [`../SECURITY.md`](../SECURITY.md) S-049 and `determ test-value-overflow-mint`.

- **SP-3 (additive + state-root-invariant — a shield-free chain is byte-identical to a pre-§3.22 chain).** SHIELD is a purely additive feature: a **new** `TxType = 12`, a **new** `cn:` state namespace, and a shielded-supply counter leaf `c:accumulated_shielded`. The state leaves are emitted **conditionally** — the counter leaf only when `accumulated_shielded_ != 0`, and the `cn:` leaves only for a non-empty pool. So on **any chain that never SHIELDs**, `build_state_leaves()` produces the **identical** leaf set it produced before §3.22, hence a **byte-identical `state_root`**. **Proven-in-code** (the `if (accumulated_shielded_ != 0)` guard + the empty-pool loop) **and witnessed by the FAST golden state-root corpus**: every pre-existing `test-*-determinism` / `consensus-vectors` golden root stays green *with the §3.22 code compiled in* — that corpus **IS** the invariance proof. **Evidence:** `test-shield` — genesis has zero shielded supply + an empty pool (the guard is off); a SHIELD **changes** the state root (the `cn:`/`c:` leaves appear — the feature is observable **only when used**); and FAST stays byte-identical.

- **SP-4 (double-mint / duplicate-commitment blocked; belt-and-suspenders re-verify).** In this deposit-only increment a commitment `C` **is its own identifier** — re-SHIELDing the **same** `C` is rejected at apply (`shielded_pool_.count(ckey)` ⟹ skip, no debit, no counter bump), so the same note cannot be minted twice. The accept-rule is enforced in **two** places: the **validator** is the authoritative submit-time gate (rejects malformed SHIELD before mempool), and the **apply** path **re-verifies** (`determ_shield_verify`) as a belt-and-suspenders defense against a tx included by a buggy/hostile producer. **Proven-in-code:** the `count(ckey)` guard + the apply-side `determ_shield_verify` call; both the validator and apply call the **same shared helper** (the S-043 "one formula, one function" rule). **Evidence:** `test-shield` — a bad-proof SHIELD is a **no-op** (sender NOT debited, no note created, A1 intact); a duplicate-commitment SHIELD in a later block is a **no-op** (`accumulated_shielded` and note-count unchanged). **Caveat:** duplicate-detection here is *note creation* only; **spend**/double-spend prevention (the nullifier set) is out of scope until CONFIDENTIAL_TRANSFER lands (NC-1).

- **SP-5 (snapshot round-trips exactly; shield-free snapshot is byte-identical).** `serialize_state` emits `accumulated_shielded` and the `shielded_pool` array **only when non-zero / non-empty**, and `restore_from_snapshot` reads them back with zero/empty defaults. So (a) a shield-free chain's snapshot JSON is **byte-identical** to a pre-§3.22 snapshot, and (b) a shielded chain serializes → restores to a state whose recomputed `state_root` matches. **Proven-in-code:** the conditional `if (accumulated_shielded_ != 0) …` / `if (!shielded_pool_.empty()) …` emit guards + the `snap.value(..., 0)` / `snap.contains("shielded_pool")` restore guards. **Evidence:** the FAST snapshot-round-trip goldens stay green (shield-free byte-identity); the apply path's post-restore A1 assertion covers the shielded round-trip. **Caveat:** this increment does not add a *dedicated* shielded snapshot-round-trip subcommand — the shielded round-trip is covered transitively by the snapshot goldens + A1, not by a bespoke `cn:`-diff assertion (L-2).

### §3.22b UNSHIELD claims (SP-6 .. SP-9)

- **SP-6 (the tx-bound accept-rule defeats front-running / redirect — the load-bearing UNSHIELD property).** `determ_unshield_verify(payload, 98, A, ctx32) == 0` **iff** the note `C` commits to exactly `A` **AND** the balance proof's Fiat-Shamir challenge was computed over `E ‖ T ‖ ctx32` for the **same** `ctx32 = SHA-256(from ‖ to ‖ nonce ‖ amount)` the verifier derives from the withdrawing tx (via the shared `unshield_spend_ctx_hash`). Therefore a captured `C‖proof` **cannot be replayed or redirected**: an attacker who changes `to` (to steal) or `from`/`nonce` (to resubmit) makes the verifier derive a **different** `ctx32`, so `c` differs and `s·H == T + c·E` fails. **Proven-in-code:** `balance.c` `determ_p256_balance_verify_bound` hashes `2·PT + SC = 98` bytes (`E ‖ T ‖ ctx32`), a distinct challenge from the unbound 66-byte hash — so a bound proof and an unbound (SHIELD) proof over the same `(E,T)` get different challenges and **neither verifies under the other** (domain separation) **+ inherited-in-prose** (that a verifying context-bound Schnorr PoK binds knowledge of `r` for exactly `C` is CTB-2/CTB-3 with the transcript extended, under DL + ROM). **Evidence:** `test-unshield` — the bound proof accepts for its own `(alice,bob,1,A)`; the **SAME** proof **REJECTS** when redirected to `attacker`; rejects for a wrong amount; and an unbound SHIELD proof is rejected by the UNSHIELD verifier.

- **SP-7 (withdraw conserves supply — value relocates back, no underflow).** UNSHIELD removes `A` from `accumulated_shielded_` and credits `A − fee` to the transparent recipient (fee to creators), so the transparent live sum rises by `A` while the confidential counter falls by `A` — the A1 identity holds exactly (asserted every block; throws on drift). Because a Pedersen commitment is **computationally binding**, the `A` proven at UNSHIELD equals the `A` the note was SHIELDed with, so `accumulated_shielded_ ≥ A` and the subtraction **cannot underflow** (the guarantee is Pedersen binding plus the S-049-checked SHIELD debit that fixes `accumulated_shielded_` to the true `A` on the way in — not A1, which is only a mod-2^64 drift check; see SP-2's S-049 correction). **Proven-in-code:** the apply case's `accumulated_shielded_ -= A` + `checked_add_u64` recipient credit + `total_fees += fee`, gated by the A1 assertion. **Evidence:** `test-unshield` — applies without throw; note removed + `accumulated_shielded == 0`; recipient credited **exactly** `A − fee`; the withdrawer's transparent balance is **untouched** (value came from the pool); A1 holds.

- **SP-8 (the commitment is its own nullifier — no double-spend).** A note is an entry in `shielded_pool_`; UNSHIELD **removes** it (`shielded_pool_.erase`). A second spend of the same `C` finds it absent (`find == end`) and is a no-op — so a note is spendable **at most once** without any separate nullifier set. Referencing a never-shielded `C` is likewise rejected (not in the set). **Proven-in-code:** the `find`/`erase` in the apply case + the submit-time `chain.shielded_note_exists` gate in the validator. **Evidence:** `test-unshield` — a redirected (front-run) UNSHIELD leaves the note **unspent** and credits no one; a second UNSHIELD of the spent note is a **no-op**. **Caveat:** removal reveals **which** note was spent and **to whom** — UNSHIELD is amount-public on exit and **not graph-private** (NC-6).

- **SP-9 (enforced at both ingresses via the SHARED ctx helper).** The tx-bound accept-rule is checked at the **validator** (submit-time: `payload==98`, `A ≥ fee`, note exists, bound proof verifies) **and** re-checked + note-removed at **apply** (authoritative). Both — and the client prover — derive `ctx32` from the **single** `unshield_spend_ctx_hash` (the S-043 one-formula-one-function rule), so the three sites cannot drift; the producer debits/credits provisionally. **Proven-in-code:** `validator.cpp` UNSHIELD case + `chain.cpp` UNSHIELD apply + `shielded.hpp` shared helper. **Evidence:** `test-unshield` exercises the apply path end-to-end; the anon-relax additionally lets a bearer account UNSHIELD (a withdraw permission, still ctx-bound).

### §3.22c CONFIDENTIAL_TRANSFER claims (SP-10 .. SP-13)

- **SP-10 (a verifying transfer is a sound confidential move — hidden amounts, no inflation-by-overflow, value conserved).** Apply accepts a CONFIDENTIAL_TRANSFER **iff** the DCT1 bundle verifies: the aggregated range proof (each hidden output `∈ [0, 2^n)` — no negative/overflow output) **and** the balance proof (`Σv_in = Σv_out + fee`, fee PUBLIC). This is the bundle-level soundness of [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) **CTBN-1** (inherits CTB-5/CTB-3/RP-2), now wired to consensus. **Proven-in-code:** the apply case calls `determ_ctx_bundle_verify` and skips on any non-zero return. **Evidence:** `test-confidential-transfer` — a valid 2-in/2-out bundle applies; a tampered bundle is a no-op.

- **SP-11 (the input dedup blocks the double-count INFLATION attack — the load-bearing consensus check).** The bundle proves `Σv_in = Σv_out + fee` over whatever commitments it *lists*, but the crypto **cannot tell** that two listed inputs are the *same* pool note. Listing one note worth `V` twice makes the bundle prove `Σv_in = 2V` and mint `2V − fee` of outputs while removing a single `V` note — pure inflation. Apply defeats this with an **all-or-nothing dedup**: it gathers every input+output commitment key into a `std::set`; a repeated key (input listed twice, or an output equal to an input/another output) fails the insert and the **whole tx is skipped** before any mutation; and every input must already be an unspent pool note (`shielded_pool_.count`). **Proven-in-code:** the `seen.insert(k).second` guard across inputs *and* outputs, gather-before-mutate. **Evidence:** `test-confidential-transfer` — a **cryptographically valid** bundle that lists the same note twice is **REJECTED**; the note stays, no inflation.

- **SP-12 (supply conserved — only the PUBLIC fee leaves the pool; no underflow).** A transfer removes `Σv_in` of note value and adds `Σv_out = Σv_in − fee`, so the confidential pool shrinks by exactly the public `fee`; `accumulated_shielded_ -= fee` and the fee is credited to creators, so total real supply is invariant and the always-on A1 throw holds. `tx.fee` is bound to equal the bundle's public `fee`, so the counter update and the creator credit are the same number. By Pedersen **binding**, `Σv_in` equals the consumed notes' shield-time values, so `accumulated_shielded_ ≥ Σv_in ≥ fee` — **no underflow**. **Proven-in-code:** the `tx.fee != bundle_fee` reject + `accumulated_shielded_ -= bundle_fee` + `total_fees += tx.fee`, gated by A1. **Evidence:** `test-confidential-transfer` — post-apply `accumulated_shielded == Σv_out`, the fee is credited to creators, A1 holds.

- **SP-13 (memory-safe parse; enforced at both ingresses; deterministic + state-root-invariant).** `determ_ctx_bundle_header` validates the magic, the parameter ranges, and that `len` equals the **exact** expected size, so the `C_in = payload+15` / `C_out = payload+15+n_in·33` slices are provably in-bounds before the apply reads them; `determ_ctx_bundle_verify` re-validates independently. The accept-rule is enforced at the **validator** (submit) + **apply** (authoritative consume/produce). CONFIDENTIAL_TRANSFER is **pool→pool** — no transparent `tx.to` credit — so (unlike UNSHIELD) it has **no cross-shard vector**. It adds no always-emitted state leaf, so a transfer-free chain's state root is unchanged (FAST goldens byte-identical). **Proven-in-code:** the header length gate + the exhaustive validator switch case. **Evidence:** `test-confidential-transfer` + FAST goldens green.

---

## 4. Validation map

| Claim | Enforced in source | Gate (`test-shield` unless noted) | Inherited from | Status |
|---|---|---|---|---|
| **SP-1** accept-rule binds `C` to public `A` | `ctxbundle.c` `determ_shield_verify` (excess → balance, both must pass) | valid accepts; wrong-amount rejects; tampered proof rejects | CTB-3 (balance ⟹ conservation) | proven-in-code (both guards) + inherited-in-prose (binding) |
| **SP-2** supply conserved | `chain.cpp` SHIELD apply (`−=cost` / `+=A`) + `chain.hpp` `expected_total()` `−accumulated_shielded_` + A1 assert | applies without throw; `accumulated_shielded==A`; sender −(A+fee); `live+shielded−subsidy==baseline` | SupplyProofSoundness (A1) | proven-in-code |
| **SP-3** additive + state-root-invariant | `chain.cpp` `build_state_leaves` conditional `c:`/`cn:` leaves; `block.hpp` `TxType=12` | genesis shield-free; SHIELD changes root; **FAST golden roots byte-identical** | — | proven-in-code + golden-corpus witness |
| **SP-4** double-mint blocked + re-verify | `chain.cpp` `count(ckey)` skip + apply `determ_shield_verify`; `validator.cpp` SHIELD case | bad-proof no-op; duplicate-commitment no-op | S-043 shared-helper rule | proven-in-code |
| **SP-5** snapshot round-trip / shield-free byte-identity | `chain.cpp` conditional serialize/restore of `accumulated_shielded` + `shielded_pool` | FAST snapshot goldens + post-restore A1 | — | proven-in-code (conditional emit) |
| **SP-6** tx-bound proof defeats front-run/redirect | `balance.c` `verify_bound` (challenge over `E‖T‖ctx32`) + `ctxbundle.c` `determ_unshield_verify` + `shielded.hpp` ctx | `test-unshield`: bound accepts; **redirect REJECTS**; wrong-amount rejects; unbound-proof rejected (domain sep) | CTB-2/CTB-3 (extended transcript) | proven-in-code (distinct challenge) + inherited-in-prose (PoK binding) |
| **SP-7** withdraw conserves supply (no underflow) | `chain.cpp` UNSHIELD apply (`−=A` / credit `A−fee`) + A1 assert | `test-unshield`: applies without throw; `accumulated_shielded==0`; recipient `+A−fee`; withdrawer untouched | SupplyProofSoundness (A1) + Pedersen binding | proven-in-code |
| **SP-8** commitment is its own nullifier | `chain.cpp` `find`/`erase` + `validator.cpp` `shielded_note_exists` | `test-unshield`: front-run no-op (note unspent); double-spend no-op | — | proven-in-code |
| **SP-9** enforced at both ingresses via shared ctx | `validator.cpp` UNSHIELD case + `chain.cpp` apply + `shielded.hpp` `unshield_spend_ctx_hash` | `test-unshield` apply path; anon-relax | S-043 shared-helper rule | proven-in-code |
| **SP-10** verifying transfer = sound confidential move | `chain.cpp` CONFIDENTIAL_TRANSFER apply calls `determ_ctx_bundle_verify` | `test-confidential-transfer`: valid 2-in/2-out applies; tampered bundle no-op | CTBN-1 (range ∧ balance) | proven-in-code + inherited-in-prose |
| **SP-11** input dedup blocks the double-count INFLATION | `chain.cpp` `std::set seen` across inputs+outputs, gather-before-mutate + `count` | `test-confidential-transfer`: **valid double-listing bundle REJECTED** — no inflation | — | proven-in-code (the load-bearing consensus check) |
| **SP-12** supply conserved (only public fee leaves; no underflow) | `chain.cpp` `tx.fee==bundle_fee` + `accumulated_shielded_ -= fee` + A1 | `test-confidential-transfer`: `accumulated_shielded==Σv_out`; fee to creators; A1 holds | SupplyProofSoundness (A1) + Pedersen binding | proven-in-code |
| **SP-13** memory-safe parse; both ingresses; pool→pool (no cross-shard) | `ctxbundle.c` `determ_ctx_bundle_header` (len==need) + `validator.cpp` case | `test-confidential-transfer` + FAST goldens | — | proven-in-code |

The `test-shield` / `test-unshield` / `test-confidential-transfer` gates are the **consensus-integration** witness (debit + conservation + leaf emission + double-mint) that the accept-only crypto vectors cannot provide; the amount-binding crypto is the already-green §3.19 balance stack. Their conjunction — bounded by L-1..L-4 — is what "SHIELD is a fail-closed, supply-conserving, state-root-invariant deposit into a confidential commitment set whose accept-rule binds `C` to the declared public amount, under the inherited DL + ROM assumptions" means for this §3.22 consensus increment.

---

## 5. Non-claims — SHIELD + UNSHIELD ARE DEPOSIT + WITHDRAW, NOT A COMPLETE *PRIVATE* SHIELDED POOL

**Read this before treating the shielded pool as a privacy feature.** SHIELD/UNSHIELD are the transparent↔confidential value **bridge**. A complete *confidential* transaction feature needs strictly more, none of which ships in these two increments:

- **NC-1 — No confidential→confidential transfer yet (the actual privacy op).** SHIELD creates notes and UNSHIELD spends them, but there is **no `CONFIDENTIAL_TRANSFER`** — the confidential→confidential move (the full DCT1 bundle consuming input notes and producing output notes with hidden amounts) is the piece that actually provides *amount privacy in motion*. It is the next increment. What ships here is the bridge + a sound single-note spend, **not** a private payment. (SP-8's "commitment is its own nullifier" gives double-**spend** prevention for the named-input model; a hidden-input transfer would additionally need real nullifiers to hide *which* note is spent.)

- **NC-2 — The SHIELD amount `A` is PUBLIC — SHIELD hides NOTHING by itself.** `A` is `tx.amount`, in the clear, and *must* be to debit the transparent balance; the fee is public too. Amount privacy begins only once value moves **confidential → confidential** via the not-yet-shipped `CONFIDENTIAL_TRANSFER`. What SHIELD provides is the *bridge* + the *binding* (`C` commits to exactly `A`), so that value can *later* be moved privately. The commitment `C` is hiding, but with `A` public the deposit reveals its own amount.

- **NC-3 — No sender / receiver / graph privacy.** The depositor's transparent address (`tx.from`) is public, as is the existence of the SHIELD. This is inherited **NC-3** of the bundle doc.

- **NC-4 — Not post-quantum.** The amount-binding soundness rests on P-256 discrete log (ECDLP), broken by Shor. Classical-adversary construction.

- **NC-5 — Single-shard, single-profile (P-256 / FIPS) — ENFORCED for UNSHIELD.** SHIELD/UNSHIELD are wired for the P-256 confidential-tx stack on a single shard. A cross-shard confidential withdraw is not wired. Critically, a cross-shard UNSHIELD (`tx.to` routing off-shard) is **rejected in code** at all three sites (validator submit-time, producer, and apply — a no-op that does **not** spend the note), matching the DAPP_CALL v2.19 single-shard reject. This is enforced, not just documented: without it, a cross-shard credit would land spendable value on the source shard with no outbound booking + no receipt — a silent break of the K-shard aggregate supply identity that per-shard A1 cannot catch (a HIGH finding from the §3.22b adversarial audit, remediated 2026-07-06). SHIELD itself has no `tx.to` credit, so no cross-shard concern. Anonymous (bearer) senders **may** SHIELD and UNSHIELD (the validator relaxes its anon-only-`TRANSFER` gate), but that is a bridge permission, not graph privacy.

- **NC-6 — UNSHIELD is NOT graph-private (it links the note to the recipient).** The withdraw references the note commitment `C` by name and removes it, and the credit goes to a public `tx.to` — so an observer learns *which* deposited note was withdrawn and *to whom*, and (with the amount public on exit) can link a specific SHIELD deposit to a specific UNSHIELD withdrawal. The tx-bound proof (SP-6) protects against **theft**, not against **linkability**. Unlinkable exit requires the hidden-input `CONFIDENTIAL_TRANSFER` (NC-1) to break the deposit↔withdrawal correlation first.

- **NC-7 — CONFIDENTIAL_TRANSFER is amount-private but NOT input-unlinkable.** §3.22c hides the transferred **amounts** (the outputs are hiding commitments; the bundle reveals only "in range" + "balanced" + the public fee), which is the real privacy-in-motion win. But the inputs are **NAMED** — the bundle lists the exact input commitments it consumes and apply removes them — so an observer can follow the note *graph* (which prior notes fed which transfer), even though the values are hidden. True input-unlinkability needs a **nullifier-from-secret** (spend a note without revealing which one) + a set-membership argument — a materially larger, owner-gated crypto increment that is **not** built. The named-input dedup that prevents inflation (SP-11) is exactly what makes inputs visible.

- **NC-8 — No on-chain output-secret delivery, at the CONSENSUS level (recipient channel is off-chain).** A transfer's output notes are commitments whose blindings the *sender* chose; to let a recipient later spend an output, the recipient must learn its `(value, blinding)` — which §3.22c does **not** yet deliver on-chain. **The delivery PRIMITIVE now ships** (shielded Option A, owner-decided 2026-07-17): ephemeral-static ECIES over P-256, `determ_enote_seal`/`_open` (`src/crypto/enote/enote.c`), dual-oracle-frozen — see [`EncryptedNoteDeliveryDesign.md`](EncryptedNoteDeliveryDesign.md) / [`EncryptedNoteSoundness.md`](EncryptedNoteSoundness.md). It lets a wallet scan + trial-decrypt the note secret with no out-of-band channel, and lets a view-/audit-key holder read amounts on-chain. What remains owner-gated is the CONSENSUS WIRING that attaches that ciphertext to a CONFIDENTIAL_TRANSFER / SHIELD output (payload region + scan RPC + light-client scan); until that lands, NC-8 stays open at the tx level and senders/recipients coordinate off-chain. Adds NO graph privacy — NC-7 (named inputs) is unchanged, so the no-double-spend-by-design property is preserved.

---

## 6. Limits (L-1 .. L-5)

- **L-1 — Soundness is an inherited REDUCTION, not a machine-checked extractor.** SP-1's binding rests on CTB-3 (balance = conservation, reduced to Schnorr 1991 + Pedersen binding under DL + the Fiat-Shamir ROM). This document adds **no** new extractor and re-proves **nothing**; a break of P-256 DL or the ROM assumption breaks SHIELD regardless of the consensus gating. The `test-shield` tamper witnesses show the deployed reject paths fire — they are **not** a soundness proof.

- **L-2 — Conformance is over a FIXED witness + the golden invariance corpus, not the input space.** `test-shield` exercises one honest deposit (`A = 100`, fixed blinding) plus its wrong-amount / tampered / bad-proof / duplicate variants; the state-root **invariance** is the FAST golden corpus (a shield-free chain), not an exhaustive sweep of shielded chains. The shielded snapshot round-trip is covered transitively (SP-5 caveat), not by a bespoke `cn:`-diff subcommand.

- **L-3 — The accept-rule lives in TWO enforcement sites (by design).** The validator (authoritative, submit-time) and the apply path (belt-and-suspenders) both gate SHIELD; both call the **same** `determ_shield_verify` (the S-043 shared-helper discipline), so they cannot drift. The producer additionally debits provisionally. Three sites, one formula.

- **L-4 — Not a constant-time claim beyond §3.19's prover CT-hardening.** `determ_shield_verify` / `determ_unshield_verify` run on public, attacker-supplied bytes (amount `A` is public), so their timing is not secret-dependent. The depositor/withdrawer's blinding `r` is chosen client-side; the §3.19 balance *prover* was CT-hardened 2026-07-06 (`ConstantTimeInventory.md`). This document asserts only functional soundness.

- **L-5 — The tx-bound proof (SP-6) is a NEW construction, owner-authorized, session-audited — not externally reviewed.** Extending the Schnorr balance proof's Fiat-Shamir challenge with `ctx32` to defeat redirect is a standard transcript-binding technique, but it is an AI-designed increment (owner-authorized 2026-07-06 under the FROST-deviation discipline) whose soundness (redirect-resistance = the extended transcript is collision-bound to `(from,to,nonce,amount)` under the ROM) is **argued-in-prose + witnessed** by the `test-unshield` redirect/domain-sep rejects and a refute-by-default adversarial audit — **not** an external cryptographic review. The binding assumes the SHA-256 ctx digest is collision-resistant and the RFC 9380 hash-to-scalar is a random oracle.

---

## 7. Status

- **Spec.** Complete (this document); design entries CRYPTO-C99-SPEC.md §3.22 (SHIELD) + §3.22b (UNSHIELD) + §3.22c (CONFIDENTIAL_TRANSFER).
- **Consensus integration shipped and green.** SHIELD (`TxType = 12`) + UNSHIELD (`TxType = 13`) + CONFIDENTIAL_TRANSFER (`TxType = 14`): apply cases + `cn:`/`c:accumulated_shielded` state leaves + conditional snapshot serialize/restore (`chain.cpp`); `accumulated_shielded_` counter + `expected_total()` subtraction + `shielded_note_exists` (`chain.hpp`); submit-time accept-rules + relaxed anon gate (`validator.cpp`); provisional accounting (`producer.cpp`); accept-rules `determ_shield_verify` / `determ_unshield_verify` / the DCT1 `determ_ctx_bundle_verify` + `determ_ctx_bundle_header` + the tx-bound `determ_p256_balance_prove_bound`/`_verify_bound` (`ctxbundle.c` / `balance.c`); the shared `unshield_spend_ctx_hash` (`shielded.hpp`). Gates: `test-shield` + `test-unshield` + `test-confidential-transfer`. State-root invariance witnessed by the FAST golden corpus. Validated MSVC + GCC/MinGW (`ci_local`); each increment cleared a refute-by-default adversarial audit (UNSHIELD's caught + fixed a HIGH cross-shard bug; CONFIDENTIAL_TRANSFER's was clean).
- **Claims.** §3.22 SHIELD SP-1..5; §3.22b UNSHIELD SP-6..9 (tx-bound proof defeats front-run/redirect; withdraw conserves supply; commitment-as-nullifier; both-ingress enforcement); §3.22c CONFIDENTIAL_TRANSFER SP-10..13 (sound confidential move via the DCT1 bundle; the input-dedup INFLATION guard; supply conserved — only the public fee leaves; memory-safe parse + pool→pool no cross-shard) — at the proven-in-code / inherited-in-prose split in §4.
- **Non-claims (NC-1..NC-8).** The remaining privacy gap is **input-unlinkability** (CONFIDENTIAL_TRANSFER hides amounts but names its inputs — NC-7) + on-chain output-secret delivery (NC-8); the SHIELD/UNSHIELD amounts + the transfer fee are PUBLIC; no sender/receiver privacy; not post-quantum; single-shard (cross-shard UNSHIELD rejected in code) / P-256 profile; UNSHIELD is not graph-private.
- **Limits (L-1..L-5).** Soundness is an inherited reduction; conformance is fixed witnesses + the golden invariance corpus; the accept-rules live in two/three sites (shared helpers); not a timing proof beyond §3.19's CT-hardening; the tx-bound proof (UNSHIELD) is a new AI-designed, session-audited construction, not externally reviewed. CONFIDENTIAL_TRANSFER adds **no** new primitive — it reuses the CTX-1 DCT1 bundle (dual-oracle-frozen) + the named-input model.

Cross-references: [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) (**NC-1** — the shielded-pool state model SHIELD begins to close; CTBN-1..CTBN-5); [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (CTB-1..CTB-8 — the inherited amount-binding soundness); [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the commitment); [`SupplyProofSoundness.md`](SupplyProofSoundness.md) (the A1 unitary-supply machinery SP-2 extends); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (the owner-gated integration proposal); CRYPTO-C99-SPEC.md §3.22 (the SHIELD + DCT1 design entry), §3.19 (the P-256 confidential-tx primitives).
