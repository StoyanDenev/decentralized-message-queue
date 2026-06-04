# SupplyInvariantComposition — the A1 unitary-supply accounting identity across apply + snapshot + cross-shard (SI-1..SI-3)

This document proves a single closed theorem that the existing per-surface proofs do **not** state jointly: that Determ's **A1 unitary-supply accounting identity** — `live_total_supply() == expected_total()`, i.e. `Σ balances + Σ staked == genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` — is preserved **simultaneously** by the three surfaces that touch supply-bearing state: (1) the per-block apply path (every transaction type), (2) the snapshot serialize/restore round trip, and (3) the cross-shard receipt machinery aggregated over a `K`-shard set. It is the composition that ties the per-account apply invariant, the all-namespace snapshot determinism result, and the K-shard conservation theorem into one statement an auditor can read in one place: *the identity that the apply path asserts on every block is the same identity that survives a snapshot and the same identity that the K-shard sum conserves.*

The proof is a **composition**, not a fresh mechanical argument. It threads:

- `AccountStateInvariants.md` (FA-Apply-1) **I-6 / T-A6** — the per-shard A1 identity, established by exhaustive case analysis over `apply_transactions`'s value-bearing branches (the per-account balance-channel decomposition I-5, the balance/stake-channel decomposition I-3);
- `EconomicSoundness.md` (FA11) **T-12** — the chain-level closed-form supply ledger, proved by induction on block height, plus **T-13** (E1 NEF neutrality) and **T-14** (E3 lottery + E4 finite-pool cap);
- `SnapshotDeterminismComposition.md` **SD-5** — A1 accounting-invariance across `serialize_state → restore_from_snapshot` (the `a:` / `s:` / `c:` namespaces round-trip exactly);
- `CrossShardSupplyConservation.md` (FA-Apply-17) **XS-1..XS-5** — the K-shard aggregate conservation identity (in-flight value tracked by `accumulated_outbound_` / `accumulated_inbound_`);
- **S-007** (`checked_add_u64`, `chain.cpp:33`) — the overflow protection that turns every credit into a guarded operation, so the identity is never broken by `u64` wraparound (a thrown overflow rolls the block back under A9 atomic apply).

The strength of this document is **consolidation**. Each input proves the identity on *one* surface; this proof states the closed identity as invariant across *all three at once*, which is the property an operator relies on when they compute a chain's total supply from genesis parameters + counter values and trust that number to be exact whether the chain was (a) replayed from genesis, (b) bootstrapped from a snapshot, or (c) one shard of a multi-shard deployment with coin in flight.

**A-number namespace (critical).** This proof concerns the apply-layer **accounting** identity historically labelled "the A1 unitary-supply invariant" in the `FA-Apply-*` series. Per `Preliminaries.md` §2.0, that label is an *accounting* invariant — `live_total_supply + accumulated_slashed = expected_total` (equivalently `live = genesis + subsidy + inbound − slashed − outbound`) — and is **entirely unrelated** to the cryptographic assumption **A1** (Ed25519 EUF-CMA, `Preliminaries.md` §2.2). The two share the letter "A1" by historical accident. Throughout this document, **"A1" written bare means the accounting identity**; we never invoke Ed25519 in the SI theorems. The only cryptographic reduction this document touches is to **A2** (SHA-256 collision resistance, `Preliminaries.md` §2.1), and only indirectly via the snapshot state-root gate (SD-2 / the `c:` namespace coverage) and the cross-shard receipt-key uniqueness (FA-Apply-17 XS-2); we do **not** use "FA3" for SHA-256 (in this series FA3 = `SelectiveAbort.md`, an unrelated property).

**Companion documents.** `Preliminaries.md` (F0) §2.0 (the A1-accounting / A1-crypto namespace split), §2.1 (A2); `AccountStateInvariants.md` (FA-Apply-1) for the per-shard A1 identity I-6/T-A6 and the per-account channel decompositions I-3 (balance/stake) + I-5 (balance arithmetic) + I-1 (S-007 no-underflow/no-overflow); `EconomicSoundness.md` (FA11) for the chain-level closed form T-12, NEF neutrality T-13, lottery+cap T-14, and determinism T-12.1; `SnapshotDeterminismComposition.md` for SD-1 (round-trip byte-identity), SD-2 (state_root preservation), SD-5 (A1 accounting-invariance across restore); `CrossShardSupplyConservation.md` (FA-Apply-17) for the K-shard aggregate conservation XS-1..XS-5 and the in-flight quantity (§2.3/§2.4); `SnapshotEquivalence.md` (FA-Apply-2) for the serialize-restore identity T-S1/T-S3 that SD-5 rests on; `FeeAccounting.md` (FA-Apply-6) for the fee-is-intra-supply property T-F6 that SI-1's TRANSFER case relies on; `docs/SECURITY.md` §S-007 / §S-033 / §S-037 / §S-038 for the overflow-protection, Merkle-state-commitment, and snapshot serialize-gap closures.

---

## 1. Scope

### 1.1 What this proves

For a reachable chain state, write the A1 identity as the predicate

```
A1(C)  :≡   live_total_supply(C)  ==  expected_total(C)
```

where (from `chain.cpp:548-553` and `chain.hpp:443-449`)

```
live_total_supply(C)  =  Σ_{d ∈ accounts_} balance[d]  +  Σ_{d ∈ stakes_} locked[d]
expected_total(C)     =  genesis_total_
                       + accumulated_subsidy_
                       + accumulated_inbound_
                       − accumulated_slashed_
                       − accumulated_outbound_
```

This document proves three theorems jointly over the three supply-touching surfaces:

- **SI-1** — **apply-preservation**: every value-bearing transaction type and every value-bearing event in `apply_transactions` (TRANSFER same-shard / TRANSFER cross-shard / STAKE / UNSTAKE / inbound cross-shard receipt / subsidy mint / fee redistribution / suspension slash / equivocation slash / REGISTER+NEF / DEREGISTER / PARAM_CHANGE / MERGE_EVENT / DAPP_*) preserves `A1` from the pre-apply state to the post-apply state, by case analysis composing FA-Apply-1 I-6 with S-007 overflow protection. This is the per-block step that the apply tail *asserts* at `chain.cpp:1397-1419`.
- **SI-2** — **snapshot round-trip invariance**: the supply-bearing namespaces round-trip exactly across `serialize_state → restore_from_snapshot`, so `A1` holds with **identical** LHS and RHS values pre- and post-restore. The `c:` counters (`chain.cpp:1622-1626` / `1747-1750`) and the `a:` / `s:` sums round-trip byte-exactly, composing `SnapshotDeterminismComposition` **SD-5**.
- **SI-3** — **cross-shard conservation**: `accumulated_inbound_` / `accumulated_outbound_` track in-flight value so the per-shard `A1` composes into the K-shard chain-wide conserved sum; value debited on a source shard but not yet credited on its destination is carried by the `−accumulated_outbound` term on the source and cancelled by the `−accumulated_inbound` term on the destination, conserving the aggregate. This composes `CrossShardSupplyConservation` **FA-Apply-17** (XS-1..XS-5).

The closed statement (SI-4, the composition corollary) is: **`A1` is an invariant of the reachable-state machine whose transitions are {apply one block, snapshot+restore a chain, apply one cross-shard receipt}, and the K-shard aggregate of `expected_total` equals the K-shard aggregate of `genesis_total` for every reachable multi-shard state.**

### 1.2 What this adds over the per-surface proofs

Each input proof covers exactly one surface:

| Proof | Covers (the surface) | What it does NOT state |
|---|---|---|
| `AccountStateInvariants.md` I-6 / FA11 T-12 | **apply** — `A1` after every single block on one chain | nothing about snapshot restore or the K-shard sum |
| `SnapshotDeterminismComposition.md` SD-5 | **snapshot** — `A1` LHS/RHS identical post-restore | nothing about the per-tx case analysis or cross-shard in-flight |
| `CrossShardSupplyConservation.md` FA-Apply-17 | **cross-shard** — K-shard aggregate conserved | consumes per-shard `A1` as a *hypothesis*; does not re-derive the per-tx closure or the snapshot round-trip on its own |

None of them states the **joint** property: that the *same* identity is the apply-tail assertion, the snapshot-survivable invariant, and the K-shard-conserved quantity — and therefore that an operator's supply figure is exact across all three execution modes simultaneously. SI-1 makes the per-tx closure explicit (so SI-3's hypothesis is discharged here, not assumed); SI-2 makes the snapshot round-trip explicit (so a snapshot-bootstrapped shard enters SI-3's K-shard sum with a correct `expected_total`); SI-3 lifts the single-shard `A1` to the K-shard aggregate. The practical value is the same as the brief's framing: *the unitary-supply identity is one identity, asserted in one place, and this proof shows the three surfaces that could each independently break it do not.*

### 1.3 What this does not prove

The SI theorems are **apply-correctness** properties: they hold whenever the apply / serialize / restore rules execute as written on honestly-produced data. They are **not** a defense against Byzantine *block content* (a producer fabricating a receipt with no matching source debit, or a forged balance) — those are caught by orthogonal mechanisms (the V12/V13 cross-shard validator predicates, FA1 Ed25519 transaction authentication, the S-033/S-038 state_root gate). Nor against Byzantine *snapshot bytes* (a hostile operator shipping a self-inconsistent snapshot) — caught by the restore-side G1 head-hash gate (`chain.cpp:1859-1862`-region) and G2 state-root gate (`chain.cpp:1893-1911`-region, reducing to A2). §5 makes the boundary precise. This document also does not re-prove the Merkle primitive (`MerkleTreeSoundness.md`), the per-namespace serialize coverage beyond the supply-bearing ones (`SnapshotEquivalence.md` / `SnapshotDeterminismComposition.md`), or the cross-shard exactly-once *delivery* (`CrossShardReceipts.md` FA7 — treated as a black box, as in FA-Apply-17).

---

## 2. Model

### 2.1 The supply-bearing state (exact, from `chain.cpp` @ 35c779e)

The complete set of fields that contribute to `live_total_supply()` or `expected_total()` — the *only* fields `A1` is about — is, on each `Chain` object:

| # | Field | Type | Role in A1 | Code anchor (this checkout) |
|---|-------|------|------------|------------|
| 1 | `accounts_[d].balance` | `uint64_t` per account | summed into `live_total_supply` (LHS) | `chain.cpp:550` |
| 2 | `stakes_[d].locked` | `uint64_t` per stake entry | summed into `live_total_supply` (LHS) | `chain.cpp:551` |
| 3 | `genesis_total_` | `uint64_t` | baseline `Σ initial_balance + Σ initial_stake` at block 0 | `chain.cpp:687-711`, `chain.hpp:611` |
| 4 | `accumulated_subsidy_` | `uint64_t` | block-subsidy minted to creators; `+` term | `chain.cpp:1391`, `chain.hpp:612` |
| 5 | `accumulated_slashed_` | `uint64_t` | suspension + equivocation forfeiture; `−` term | `chain.cpp:1395`, `chain.hpp:613` |
| 6 | `accumulated_inbound_` | `uint64_t` | cross-shard receipt value credited *into* this shard; `+` term | `chain.cpp:1393`, `chain.hpp:614` |
| 7 | `accumulated_outbound_` | `uint64_t` | cross-shard `TRANSFER` value that *left* this shard; `−` term | `chain.cpp:1394`, `chain.hpp:615` |

This list is **complete** and matches `CrossShardSupplyConservation.md` §2.2 (seven fields, no separate `outbound_receipts_` member; the source-side in-flight signal is the monotone counter `accumulated_outbound_`). `live_total_supply()` (`chain.cpp:548-553`) sums *only* fields 1+2 — there is no pseudo-account pool or separate fee escrow on the conservation path: fees flow through `accounts_` via the creator distribution at `chain.cpp:1286-1305` (SI-1, fee case). `expected_total()` (`chain.hpp:443-449`) is the signed sum of fields 3–7. The post-apply assertion `actual == expected` (`chain.cpp:1397-1419`) ties (1+2) to (3+4+6−5−7) on every block.

The genesis bootstrap (`chain.cpp:681-717`) initializes field 3 (`genesis_total_ = gtotal`, the running Σ over `b.initial_state` at lines 687-709, written at 711) and zeros fields 4–7 (lines 712-715). The apply tail (`chain.cpp:1391-1395`) is the *only* site that mutates fields 4–7 per block, folding the per-block running counters `block_inbound` / `block_outbound` / `block_slashed` (declared near `chain.cpp:722`) and `subsidy_this_block` into them.

### 2.2 The three surfaces as state-machine transitions

`A1` is a predicate over a single `Chain` (or, for SI-3, over a `K`-shard product of `Chain`s). The three surfaces are the three ways the state evolves:

- **APPLY** — `Chain::apply_transactions(const Block& b)` (`chain.cpp:633`): the per-block transition. Wrapped in `try { … } catch (...) { restore_state_snapshot(…); throw; }` (the A9 atomic-apply property, `AccountStateInvariants.md` §1.2), so a thrown S-007 overflow, an A1-mismatch throw, or an S-033 state-root mismatch leaves the chain in its pre-apply state. SI-1 is about *successful* applies (no throw).
- **SNAPSHOT** — `serialize_state` (`chain.cpp:1541`-region) followed by `restore_from_snapshot` (`chain.cpp:1703`-region): replacing a `Chain` with one reconstructed from its serialized state. SI-2 is about this transition.
- **CROSS-SHARD** — the inbound-receipt arm of APPLY on a destination shard (`chain.cpp:1363-1381`), paired with the source-debit arm on a source shard (`chain.cpp:742-769`, cross-shard branch). SI-3 aggregates over the K-shard product.

### 2.3 The cross-shard in-flight quantity

Following `CrossShardSupplyConservation.md` §2.3-§2.4, a unit of value is **in flight** once a source shard `S` has incremented `accumulated_outbound_` (via `block_outbound += tx.amount` at `chain.cpp:765`, folded at `1394`) but before the destination shard `D` has incremented `accumulated_inbound_` (via `block_inbound += r.amount` at `chain.cpp:1377`, folded at `1393`). The K-shard aggregate that conserves is FA-Apply-17's **Form B** (`main.cpp` `aggregate_conserved()` lambda):

```
aggregate  =  Σ_s [ live_total_supply(C_s)
                  + accumulated_outbound(C_s)
                  + accumulated_slashed(C_s)
                  − accumulated_inbound(C_s)
                  − accumulated_subsidy(C_s) ]
```

with the theorem `aggregate = Σ_s genesis_total(C_s)` for every reachable multi-shard state (FA-Apply-17 XS-5). SI-3 re-states this and shows it is the K-shard lift of the per-shard `A1` that SI-1 establishes.

---

## 3. Theorems

Throughout §3, "reachable chain state" means a `Chain` obtained by replaying genesis followed by zero or more `apply_transactions`-valid blocks (and possibly one or more SNAPSHOT round trips). For SI-3, the K-shard set `𝕊 = {C_0, …, C_{K−1}}` shares one `shard_count_ = K` and one `shard_salt_` with distinct `my_shard_id_` (FA-Apply-17 §2.1).

### SI-1 — Apply-preservation

**Statement.** For every reachable chain `C` with `A1(C)` true, and every block `b` such that `apply_transactions(b)` returns successfully (does not throw), `A1(C')` is true where `C'` is the post-apply state. Equivalently: every value-bearing apply branch adjusts `live_total_supply` and the accumulators *together* so that `live = expected_total` is restored at the apply tail.

**Proof.** This is FA-Apply-1 **I-6 / T-A6** (equivalently FA11 **T-12**), which we restate here as a per-branch case analysis so SI-3's hypothesis is discharged constructively. For each value-bearing branch the table records the `live` delta, the matching accumulator delta, and the net effect on `expected − live`; a reviewer confirms closure without re-deriving T-12 by checking every row is net-zero on `expected − live`:

| Apply branch | `live` delta | matching accumulator delta | net on `expected − live` | code anchor |
|---|---|---|---|---|
| TRANSFER, same-shard | `0` (sender `−(a+f)`, recipient `+a`, creator `+f` at tail) | none | `0` | `chain.cpp:742-769`, credit `757` |
| TRANSFER, cross-shard (source) | `−a` (sender `−(a+f)`, creator `+f`) | `accumulated_outbound += a` | `0` (`−out` drops by `a`) | `chain.cpp:762-767`, `block_outbound 765` |
| Inbound receipt (destination) | `+a` (recipient `+a`) | `accumulated_inbound += a` | `0` (`+in` rises by `a`) | `chain.cpp:1363-1381`, credit `1368` |
| STAKE | `0` (balance → locked, both in `live`) | none | `0` | `chain.cpp:858-871` |
| UNSTAKE (post-unlock) | `0` (locked → balance, both in `live`) | none | `0` | `chain.cpp:873-894`, `890-891` |
| UNSTAKE (too-early / insufficient lock) | `0` (fee debited then refunded) | none | `0` | `chain.cpp:878-888` (fee refund `884-885`) |
| Suspension slash (Phase-1 abort) | `−d` (locked `−d`, `d = min(suspension_slash_, locked)`) | `accumulated_slashed += d` | `0` (`−slashed` rises by `d`) | `chain.cpp:1313-1328`, `1324-1327` |
| Equivocation slash (full forfeit) | `−L` (locked `−L`) | `accumulated_slashed += L` | `0` | `chain.cpp:1344-1356`, `1348-1349` |
| Subsidy mint | `+s` (creators `+s`, `s = subsidy_this_block`) | `accumulated_subsidy += s` | `0` (`+subsidy` rises by `s`) | `chain.cpp:1267-1305`, fold `1390-1392` |
| Fee redistribution | `0` (senders `−Σf` already counted, creators `+Σf`) | none | `0` | `chain.cpp:1279-1305` |
| REGISTER (+ E1 NEF) | `0` (fee `−f` redistributed; NEF is pool→registrant transfer, sum-preserving) | none | `0` | `chain.cpp:772-…` REGISTER arm; NEF (FA11 T-13) |
| DEREGISTER / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER / DAPP_CALL | `0` (or `−f` fee, redistributed) | none | `0` | respective arms; MERGE metadata-only (FA-Apply-17 §5 lim. 6) |

Every row is net-zero on `expected − live`. Composing them over the (finite, canonical-order) set of transactions and events in `b`: the total `live` delta is `Δlive = +subsidy_this_block + block_inbound − block_outbound − block_slashed` (the fee terms cancel exactly, `−Σ fees + total_fees = 0`, since every fee debited from a sender is added to `total_fees`; FA11 §3 inductive step), and the total accumulator delta is `Δexpected = +subsidy_this_block + block_inbound − block_outbound − block_slashed` (the folds at `chain.cpp:1391-1395`). Hence `Δexpected = Δlive`, and since `A1(C)` gave `expected(C) = live(C)`, we have `expected(C') = expected(C) + Δexpected = live(C) + Δlive = live(C')`, i.e. `A1(C')`. This is exactly what the apply tail asserts at `chain.cpp:1397-1399`; a violation throws the `"unitary-balance invariant violated"` diagnostic (`chain.cpp:1405-1418`) and rolls back. ∎

**S-007 overflow protection (why no `u64` wrap silently breaks `A1`).** Every credit channel in the table above is guarded by `checked_add_u64` (`chain.cpp:33`), which returns `false` on overflow rather than wrapping: TRANSFER recipient (`757`), inbound receipt (`1368`), per-block inbound sum (`1377`), per-creator subsidy/fee (`1292`), dust to `creators[0]` (`1300`), and `total_distributed = total_fees + subsidy_this_block` (`1280`). Every debit channel is guarded by an explicit `balance ≥ cost` pre-check (`AccountStateInvariants.md` I-1): TRANSFER source (`744`), STAKE (`864`), `charge_fee` (the `chain.cpp:727`-region lambda). On overflow the `checked_add_u64` site throws an `S-007` diagnostic, which the outer try/catch converts to a `restore_state_snapshot` rollback (A9). So either the block applies fully with `A1` preserved (the table), or it throws and leaves `C` unchanged with `A1(C)` still true. There is **no** intermediate state in which a wrapped `u64` is observed with `A1` silently violated — the assertion at `1397-1419` would in any case catch a wrapped value as a `live ≠ expected` mismatch of magnitude ≈ `2^64 − x` and throw (`AccountStateInvariants.md` §4, "I-1 violation").

**Test witness.** `tools/test_supply_invariant.sh` (direct A1 assertion with synthetic per-counter deltas), `tools/test_supply_lifecycle.sh` (A1 closing equality after each of TRANSFER / STAKE / UNSTAKE / REGISTER±NEF / DEREGISTER / equivocation+suspension slash / lottery subsidy / finite-pool exhaustion / cross-shard inbound+outbound), `tools/test_overflow_paths.sh` (S-007 throws roll back rather than wrap), `tools/test_fee_distribution_edge.sh` (fee redistribution net-zero on `live`).

### SI-2 — Snapshot round-trip invariance

**Statement.** Let `C` be a reachable chain with `A1(C)` true, `S = serialize_state(C)`, and `C₁ = restore_from_snapshot(S)`. Then `live_total_supply(C₁) == live_total_supply(C)` and `expected_total(C₁) == expected_total(C)` (each side preserved value-for-value), and consequently `A1(C₁)` is true. The supply-bearing namespaces `a:` (account balances), `s:` (stake locked), and `c:` (the five counters) round-trip exactly.

**Proof.** This is `SnapshotDeterminismComposition.md` **SD-5** (which itself rests on `SnapshotEquivalence.md` FA-Apply-2 T-S1 conditions 1–4). The LHS of `A1`, `live_total_supply = Σ balance + Σ locked`, is a fold over the `a:` namespace (`accounts_[d].balance`) and the `s:` namespace (`stakes_[d].locked`); the RHS, `expected_total`, is the signed sum of the five `c:` counters. Each is preserved:

- **`a:`** — `serialize_state` emits `accounts[] = {domain, balance, next_nonce}` (`chain.cpp:1551-1557`-region) and `restore_from_snapshot` reloads `c.accounts_[domain] = {balance, next_nonce}` (`chain.cpp:1748-1755`-region), so every `balance[d]` is preserved; the LHS first term is equal.
- **`s:`** — `serialize_state` emits `stakes[] = {domain, locked, unlock_height}` (`chain.cpp:1561-1567`-region) and `restore_from_snapshot` reloads `c.stakes_[domain] = {locked, unlock_height}` (`chain.cpp:1756-1763`-region), so every `locked[d]` is preserved; the LHS second term is equal.
- **`c:`** — the five counters are persisted verbatim by `serialize_state` (`chain.cpp:1622-1626`):

  ```
  snap["genesis_total"]        = genesis_total_;
  snap["accumulated_subsidy"]  = accumulated_subsidy_;
  snap["accumulated_slashed"]  = accumulated_slashed_;
  snap["accumulated_inbound"]  = accumulated_inbound_;
  snap["accumulated_outbound"] = accumulated_outbound_;
  ```

  and re-read by `restore_from_snapshot`: the four delta counters at `chain.cpp:1747-1750` (subsidy/slashed/inbound/outbound) and `genesis_total_` at `chain.cpp:1883` (with the legacy back-solve at `1885-1891`). So the RHS is equal value-for-value.

Therefore both sides of `A1` take the same numeric value on `C` and `C₁`, and in particular `A1(C₁)` holds iff `A1(C)` held. Since `C` is reachable, `A1(C)` held (SI-1, by induction from genesis), so `A1(C₁)` holds. The first post-restore block's apply-tail A1 assertion (`chain.cpp:1397-1419`) thus starts from a satisfied invariant — which is exactly *why* the counters are persisted (the `serialize_state` comment at `chain.cpp:1618-1621` states: without them `expected_total()` would be `0` on a restored chain and the very first apply would trip the invariant). ∎

**Legacy back-solve preserves the identity by construction.** If `genesis_total` is absent from `S` (legacy snapshot), `restore_from_snapshot` back-solves it (`chain.cpp:1885-1891`):

```
live       = c.live_total_supply();
deltas_pos = c.accumulated_subsidy_ + c.accumulated_inbound_;
deltas_neg = c.accumulated_slashed_ + c.accumulated_outbound_;
c.genesis_total_ = live + deltas_neg − deltas_pos;
```

This is the rearrangement of `A1` (`genesis_total = live − (subsidy + inbound) + (slashed + outbound)`), so the restored chain satisfies `live == expected_total` *by construction*, and the back-solved `genesis_total_` equals the original (because the original also satisfied `A1`). Either way all five counters + both sums are reproduced and `A1(C₁)` holds. Moreover S-033 binds the round trip cryptographically: the snapshot tail head's `state_root` covers the `c:` namespace (the five counters, `chain.cpp:404-408`) plus `a:`/`s:`, so a tampered counter or balance fails the restore-side G2 recompute (`chain.cpp:1893-1911`-region) — that is the Byzantine-bytes defense of §5, reducing to A2, distinct from the apply-correctness statement SI-2 makes for honest snapshots.

**Test witness.** F5's `determ test-snapshot-full-determinism` (R40) — the supply-invariance assertion (`live_total_supply == expected_total` post-restore, equal to the donor's values, over the all-namespace fixture); `tools/test_supply_lifecycle.sh` + `tools/operator_supply_check.sh` (re-runs the A1 check from snapshot data); `tools/test_snapshot_roundtrip.sh` + `tools/test_dapp_snapshot.sh` (the `d:`-active joint surface that exercises the snapshot tail head's stored `state_root` end-to-end).

### SI-3 — Cross-shard conservation

**Statement.** For a `K`-shard set `𝕊` (each shard a reachable chain with its per-shard `A1` true), the in-flight value tracked by `accumulated_outbound_` (source) and `accumulated_inbound_` (destination) makes the K-shard aggregate of `expected_total` conserved:

```
Σ_s expected_total(C_s)  +  (Σ_s accumulated_outbound(C_s) − Σ_s accumulated_inbound(C_s))  +  Σ_s accumulated_subsidy_-netting …
```

— equivalently, FA-Apply-17 **Form B**: `Σ_s [ live(C_s) + accumulated_outbound(C_s) + accumulated_slashed(C_s) − accumulated_inbound(C_s) − accumulated_subsidy(C_s) ] = Σ_s genesis_total(C_s) =: G`, for every reachable multi-shard state. Value debited on a source shard but not yet credited on its destination ("in flight") is counted by the `−accumulated_outbound` term on the source until the matching `−accumulated_inbound` term on the destination cancels it; nothing is created or destroyed by the cross-shard machinery.

**Proof.** This is `CrossShardSupplyConservation.md` (FA-Apply-17) **XS-1..XS-5**, whose load-bearing hypothesis is the *per-shard* `A1` invariant — discharged here by SI-1 (per-block apply) and SI-2 (preserved across any snapshot a shard underwent). We recap the composition; FA-Apply-17 has the full development:

- **XS-0 (disjointness).** Distinct shards are disjoint `Chain` objects; one shard's apply touches no other shard's `accounts_ / stakes_ / accumulated_*` (no shared static supply state in `chain.cpp`). So the aggregate is a sum of independent per-object contributions, well-defined and order-independent under any interleaving.
- **XS-1 (per-step conservation).** Substituting the per-shard `A1` (`live(C_s) = expected_total(C_s)`, which SI-1 establishes and the apply tail asserts at `chain.cpp:1397-1399`) into shard `C_s`'s Form-B contribution makes every accumulator term cancel its mirror, leaving `contrib(C_s) = genesis_total(C_s)` — constant across all blocks (`genesis_total_` written once at `chain.cpp:711`, never re-mutated on the apply path; the only other writer is SI-2's back-solve, which reproduces the same value). The mechanism, case by case: the **source debit + emit** (`chain.cpp:742-769`, cross-shard arm, `block_outbound += tx.amount` at `765`) drops `live` by `a` and `−out` by `a` (source contribution invariant; coin now in flight); the **destination credit** (`chain.cpp:1363-1381`, `block_inbound += r.amount` at `1377`) raises `live` by `a` and `−in` by `a` (destination contribution invariant; coin landed). The two net-zero deltas compose to an aggregate delta of `0`.
- **XS-2 (no double-credit ⇒ no inflation).** The dedup guard `if (applied_inbound_receipts_.count(key)) continue;` (`chain.cpp:1365`, `key = (r.src_shard, r.tx_hash)`) fires *before* both the credit (`1368`) and the `block_inbound` tick (`1377`) on any replay, so each emitted receipt contributes to `accumulated_inbound_` *exactly once* — matching the exactly-once source increment. Key uniqueness rests on **A2** (SHA-256 collision resistance): the pair key keeps two distinct source shards' receipts distinct even under a (negligible) `tx_hash` collision (FA-Apply-17 XS-2, FA-Apply-9 T-R3).
- **XS-3 (fee intra-shard).** On the cross-shard arm only `tx.amount` is booked into `block_outbound` (`chain.cpp:765`); the `fee` is added to `total_fees` (`767`) and redistributed to creators on the *source* shard at the apply tail (`1279-1305`), so it never crosses a shard boundary and leaves the source contribution unchanged (FA-Apply-6 T-F6, "fees are intra-supply").
- **XS-4 (snapshot-restore invariance).** Each shard's supply-bearing fields + the dedup set survive `serialize_state → restore_from_snapshot` (this is SI-2 for the `a:`/`s:`/`c:` fields, plus FA-Apply-12 / the `i:` namespace for `applied_inbound_receipts_`, `chain.cpp:1586-1591` / `1778-1785`-region), so each shard's Form-B contribution (= `genesis_total(C_s)` by XS-1) is identical post-restore.
- **XS-5 (aggregate identity).** By induction over the interleaved per-shard apply steps (base case genesis: all accumulators `0`, `live(C_s) = genesis_total(C_s)`; inductive step: XS-1 leaves the aggregate unchanged, XS-2 covers duplicate receipts, XS-3 covers fees, XS-4 covers snapshot-restore steps), `aggregate = G` for every reachable multi-shard state. ∎

Thus the per-shard `A1` that SI-1 proves and SI-2 preserves is exactly the hypothesis FA-Apply-17 consumes; SI-3 is the statement that the three compose into the K-shard conserved sum.

**Test witness.** D1's `determ test-cross-shard-supply-invariant` (commit `7ee49da`, wrapper `tools/test_cross_shard_supply_invariant.sh`, 30 PASS) — pins the aggregate identity at genesis, mid-cycle (coin in flight), after credit, after a duplicate inbound (XS-2 no-op), and across a snapshot round trip (XS-4), all asserting `aggregate_conserved() == kGenesisAggregate` over a `K = 3` shard set with a non-zero staked term.

### SI-4 — Composition corollary (closed statement)

**Statement.** `A1` is an invariant of the reachable-state machine whose transitions are APPLY (one block), SNAPSHOT (serialize+restore), and CROSS-SHARD (one inbound receipt); and for any `K`-shard set, `Σ_s expected_total(C_s)` reduces (netting in-flight and minted value) to `Σ_s genesis_total(C_s)` for every reachable multi-shard state.

**Proof.** Single-shard reachability is generated by APPLY and SNAPSHOT transitions. Base case: post-genesis, `live = genesis_total` with all accumulators `0` (`chain.cpp:711-716`), so `A1` holds. Inductive step: an APPLY transition preserves `A1` (SI-1), and a SNAPSHOT transition preserves `A1` (SI-2). Hence `A1(C)` for every reachable single-shard `C`. The CROSS-SHARD transition is the inbound-receipt arm of APPLY, already covered by SI-1's "inbound receipt (destination)" row, so it too preserves `A1`. Lifting to the K-shard product: each shard's `A1` holds (the above), and SI-3 (FA-Apply-17 XS-5) closes the aggregate to `G`. ∎

This is the operator-facing guarantee: the supply figure computed from genesis parameters + counter values is **exact** — not approximate — whether the chain was replayed from genesis, bootstrapped from a snapshot, or is one shard of a multi-shard deployment with coin in flight (FA11 §9 conclusion, now stated as a composition across all three surfaces).

---

## 4. Mapping to the empirical pins

The SI theorems are pinned by the existing regression suite (no new test is introduced by this proof; it is analytic and composes shipped results):

| SI theorem | Surface | Empirical pin |
|---|---|---|
| **SI-1** (apply-preservation) | apply | `tools/test_supply_invariant.sh` (direct A1 assertion) + `tools/test_supply_lifecycle.sh` (A1 after every tx-type) + `tools/test_overflow_paths.sh` (S-007 rollback) |
| **SI-2** (snapshot round-trip) | snapshot | F5's `determ test-snapshot-full-determinism` (supply-invariance assertion) + `tools/operator_supply_check.sh` (A1 from snapshot data) + `tools/test_snapshot_roundtrip.sh` |
| **SI-3** (cross-shard conservation) | cross-shard | D1's `determ test-cross-shard-supply-invariant` (`tools/test_cross_shard_supply_invariant.sh`, 30 PASS over K=3) |
| **SI-4** (composition) | all three | the conjunction of the above — each surface's A1 assertion, taken together, is the inductive trace of the closed statement |

Each pin asserts the *same* `A1` identity (`live_total_supply == expected_total`, or its K-shard Form-B aggregate) on its surface; the proof's contribution is to show these are one identity preserved across all three, so the conjunction of the pins is a single coherent guarantee rather than three disjoint ones.

---

## 5. Limitations and scope

1. **Apply-correctness, not Byzantine-content defense.** The SI theorems hold whenever the apply / serialize / restore rules execute as written. They do **not** by themselves defend against a malicious producer fabricating a receipt with no matching source debit, a forged balance, or a self-inconsistent snapshot. Those are caught by orthogonal mechanisms: the V12/V13 cross-shard validator predicates (`Preliminaries.md`; reject ill-formed receipts pre-apply), FA1 (Ed25519 EUF-CMA, transaction authentication — the *cryptographic* A1, distinct from this proof's accounting A1), and the S-033/S-038 state_root gate (`chain.cpp:1421`-region apply-side recompute + the restore-side G2 gate, reducing to A2). This proof composes *on top of* those: given a V12/V13-cleared, signature-valid, state_root-bound block and an honest snapshot, the three surfaces preserve `A1`.

2. **Single deployment, bounded shard set (SI-3).** SI-3's K-shard conservation is over one deployment sharing one `shard_salt_` / `shard_count_`. Cross-deployment bridges (value between two independent Determ chains) are out of scope — the v2.23 bridge work, which would add a lock/mint accounting layer not modeled here (`CrossShardSupplyConservation.md` §5 lim. 1).

3. **Cross-shard delivery is assumed, not proved here (SI-3).** XS-1's source/destination pairing relies on FA7's exactly-once *delivery* as a black box; SI-3 proves that *given* exactly-once delivery, the aggregate is conserved, and that even *duplicate* delivery (XS-2) cannot break it. Liveness of delivery (the in-flight coin *eventually* lands) is a separate property (`CrossShardReceipts.md` / `S016InboundReceiptTimeOrdered.md`); conservation holds whether or not the coin has landed (it is counted as in-flight until it does).

4. **`u64` arithmetic / overflow.** All supply fields are `uint64_t`. SI-1's S-007 paragraph covers the closure: every credit is guarded by `checked_add_u64` (`chain.cpp:33`) and every debit by an explicit pre-check, throwing rather than wrapping; a thrown overflow rolls the block back (A9), so the conserved state is never corrupted by wraparound. The underflow edge of the *aggregate* (`slashed + outbound` exceeding `genesis + subsidy + inbound`) requires breaking the per-tx slash bound `min(suspension_slash_, locked)` (`chain.cpp:1324`) / full-forfeit-of-`locked` (`1348-1349`), which the apply path prevents structurally (FA11 §7).

5. **Subsidy/slashing are conserved, not absent.** The SI theorems hold *with* subsidy minting (E1 NEF / E3 lottery / E4 finite pool, FA11 T-13/T-14) and slashing active — the `accumulated_subsidy_` and `accumulated_slashed_` terms carry them, and SI-1's table includes those rows. D1's cross-shard test runs with `subsidy = 0` and no slashing to isolate the cross-shard flow; SI-1's lifecycle pin (`test_supply_lifecycle.sh`) exercises the subsidy + slash channels' A1-invariance.

6. **R4 under-quorum merge does not move supply (SI-3).** The R4 `MERGE_EVENT` apply branch mutates only `merge_state_` (a `shard_id → refugee_region` metadata map in the `m:` namespace) and consumes fee + nonce; it does **not** transfer `accounts_` or `stakes_` between shards. So `merge_state_` is not a supply-bearing field (absent from §2.1's seven), and MERGE_BEGIN/MERGE_END fall under SI-1's net-zero "fee redistributed, otherwise net-zero" row (`CrossShardSupplyConservation.md` §5 lim. 6). The identity is invariant across merge events.

---

## 6. Cross-references

| Surface | Location | Relevance |
|---|---|---|
| A1 assertion (apply tail) | `src/chain/chain.cpp:1397-1419` | the `actual == expected` post-apply check SI-1 establishes per block |
| `live_total_supply()` | `src/chain/chain.cpp:548-553` | fields 1+2 (balances + locked stake), the A1 LHS |
| `expected_total()` | `include/determ/chain/chain.hpp:443-449` | the `genesis + subsidy + inbound − slashed − outbound` formula, the A1 RHS |
| A1 counter declarations | `include/determ/chain/chain.hpp:611-615` | fields 3–7 |
| Genesis bootstrap | `src/chain/chain.cpp:681-717` | `genesis_total_` Σ (687-709, written 711) + zeroing accumulators (712-715); SI-4 base case |
| TRANSFER (same-shard credit) | `src/chain/chain.cpp:742-769`, credit `757` | SI-1 same-shard row (S-007-guarded) |
| TRANSFER (cross-shard source) | `src/chain/chain.cpp:762-767`, `block_outbound 765` | SI-1 cross-shard row, SI-3 source debit |
| Inbound receipt apply (destination) | `src/chain/chain.cpp:1363-1381`, credit `1368`, dedup `1365`, `block_inbound 1377` | SI-1 inbound row, SI-3 destination credit + XS-2 dedup |
| STAKE / UNSTAKE | `src/chain/chain.cpp:858-871` / `873-894` | SI-1 balance↔locked channel rows (I-3) |
| Suspension slash | `src/chain/chain.cpp:1313-1328`, deduct `1324-1327` | SI-1 suspension-slash row (`block_slashed`) |
| Equivocation slash | `src/chain/chain.cpp:1344-1356`, forfeit `1348-1349` | SI-1 equivocation-slash row (`block_slashed`) |
| Subsidy compute + cap | `src/chain/chain.cpp:1262-1272` | SI-1 subsidy row, FA11 T-14 (E4 cap) |
| Fee → creator distribution | `src/chain/chain.cpp:1279-1305`, per-creator `1292`, dust `1300` | SI-1 fee row (intra-shard, XS-3) |
| Accumulator fold (apply tail) | `src/chain/chain.cpp:1391-1395` | the only per-block mutation of fields 4–7 |
| `checked_add_u64` (S-007) | `src/chain/chain.cpp:33` | overflow protection on every credit (SI-1 S-007 paragraph) |
| `is_cross_shard` | `src/chain/chain.cpp:198` | the routing predicate defining a cross-shard transfer (SI-3) |
| `serialize_state` (counters) | `src/chain/chain.cpp:1622-1626` | persist fields 3–7 (SI-2) |
| `restore_from_snapshot` (counters + back-solve) | `src/chain/chain.cpp:1747-1750`, `1883-1891` | reload fields 4–7; back-solve `genesis_total` for legacy (SI-2) |
| `c:` namespace in state_root | `src/chain/chain.cpp:404-408` | S-033 binds the five counters (SI-2 tamper-detection) |
| **FA-Apply-1** | `docs/proofs/AccountStateInvariants.md` | per-shard A1 identity I-6/T-A6 + channel decompositions I-1/I-3/I-5 (SI-1) |
| **FA11** | `docs/proofs/EconomicSoundness.md` | chain-level closed form T-12 + NEF T-13 + lottery/cap T-14 + determinism T-12.1 (SI-1) |
| **SnapshotDeterminismComposition** | `docs/proofs/SnapshotDeterminismComposition.md` | SD-5 A1 accounting-invariance across restore (SI-2) |
| **FA-Apply-2** | `docs/proofs/SnapshotEquivalence.md` | serialize-restore identity T-S1/T-S3 underpinning SD-5 (SI-2) |
| **FA-Apply-17** | `docs/proofs/CrossShardSupplyConservation.md` | K-shard aggregate conservation XS-1..XS-5 (SI-3) |
| **FA-Apply-6** | `docs/proofs/FeeAccounting.md` | fee-is-intra-supply T-F6 (SI-1 fee row, SI-3 XS-3) |
| `Preliminaries.md` §2.0 / §2.1 | `docs/proofs/Preliminaries.md` | the A1-accounting / A1-crypto namespace split; A2 (the only reduction target) |
| `docs/SECURITY.md` §S-007 / §S-033 / §S-037 / §S-038 | overflow protection / Merkle state commitment / `d:` serialize-gap / producer-side `body.state_root` wiring |
| **SI-1 pin** | `determ test-supply-invariant` / `test-supply-lifecycle` / `test-overflow-paths` → `tools/test_supply_*.sh`, `tools/test_overflow_paths.sh` | apply-surface A1 assertions |
| **SI-2 pin** | F5's `determ test-snapshot-full-determinism` + `tools/operator_supply_check.sh` | snapshot-surface A1 invariance |
| **SI-3 pin** | D1's `determ test-cross-shard-supply-invariant` → `tools/test_cross_shard_supply_invariant.sh` (30 PASS) | cross-shard-surface aggregate conservation |

---

## 7. Status

**Proof complete (SI-1..SI-4); analytic composition, changes no code.**

All four theorems are closed by composition of shipped results:

- **SI-1** (apply-preservation) — via FA-Apply-1 I-6 / FA11 T-12 (per-tx case analysis, every value-bearing branch net-zero on `expected − live`) + S-007 overflow protection (`checked_add_u64` guards every credit, A9 rolls back on throw). The runtime check is the apply-tail assertion at `chain.cpp:1397-1419`.
- **SI-2** (snapshot round-trip invariance) — via SnapshotDeterminismComposition SD-5 (the `a:`/`s:`/`c:` namespaces round-trip exactly, FA-Apply-2 T-S1 conditions 1–4), with the legacy back-solve (`chain.cpp:1885-1891`) preserving the identity by construction and S-033/G2 binding it cryptographically.
- **SI-3** (cross-shard conservation) — via CrossShardSupplyConservation FA-Apply-17 XS-1..XS-5, whose per-shard A1 hypothesis is discharged by SI-1 + SI-2; in-flight value carried by `accumulated_outbound_` / `accumulated_inbound_`, dedup (XS-2) reducing to A2.
- **SI-4** (composition corollary) — the closed statement that `A1` is invariant across {APPLY, SNAPSHOT, CROSS-SHARD} and the K-shard `Σ expected_total` reduces to `Σ genesis_total`; the operator's exact-supply guarantee.

The §2.1 supply-component list (7 fields) matches `src/chain/chain.cpp` @ 35c779e exactly; there is no separate `outbound_receipts_` member (the source-side in-flight signal is the `accumulated_outbound_` counter, consistent with FA-Apply-17 and D1's test). No SI theorem is open or partial. The empirical pins are the shipped SI-1 / SI-2 / SI-3 surface tests (§4); this document is the proof that they assert one identity, preserved across all three surfaces.
