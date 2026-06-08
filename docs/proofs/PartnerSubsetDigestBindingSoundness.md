# PartnerSubsetDigestBindingSoundness — the `partner_subset_hash` digest-binding closure of S-030-D2 (commit `8585a50`)

This document proves the soundness of binding the R4/R7 merged-signing commitment `partner_subset_hash` directly into `compute_block_digest` (commit `8585a50`). It is the analytic companion to `S030-D2-Analysis.md` §4 item 9 — the one S-030-D2 dimension that closed at the consensus layer with **no** Phase-1 view-reconciliation, because the field is deterministic rather than a gossip-async per-member pool view.

It exists as a standalone proof because the `partner_subset_hash` closure is structurally *unlike* the three pool-fed F2 closures (inbound / equivocation / abort). Those needed the carry→reconcile→digest machinery of `EqAbortViewDigestExtension.md` precisely because the digested set is a function of divergent gossip-fed pools; `partner_subset_hash` needs none of it. Getting that distinction wrong is the trap `S030-D2-Analysis.md` §2 documents: binding a per-member view RAW into the digest stalls the chain under gossip drift. This proof shows why binding `partner_subset_hash` RAW is the *correct* fix for *this* field, and why the same RAW append would be wrong for any of the three pool-fed fields.

**The two-step contrast (load-bearing — read first).** S-030-D2 has five digest-coverage dimensions (`S030-D2-Analysis.md` §1 table). They split into two classes by *what determines the field's value at digest time*:

- **Gossip-async per-member views** — `inbound_receipts`, `equivocation_events`, `abort_events`. Each committee member's local pool view differs at its Phase-1 commit instant (member A holds `{e1}`, member B holds `{e1,e2}`). The value digested must be a deterministic *reconciliation* of the K signed Phase-1 commits (intersection for inbound, union for eq/abort), computed at the Phase-1→Phase-2 boundary, so honest assemblers converge on one digest. Binding the pre-reconciliation per-member view RAW reintroduces the divergence and stalls the round. This is the `EqAbortViewDigestExtension.md` / `S030-D2-Analysis.md` §3 design.
- **Deterministic merge-state fields** — `partner_subset_hash` (and, by the §5 numeric-median analog, `timestamp`). Every committee member at a merged height computes the *identical* `partner_subset_hash` from `Chain::merge_state_` (`S030-D2-Analysis.md` §3.2). There is no per-member pool; there is no divergence to absorb; there is nothing to reconcile. Binding it RAW is safe by construction.

`partner_subset_hash` is in the second class. The whole proof below is the formalization of that membership and its consequences.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage (§2.1), **A4** = CSPRNG uniform sampling (§2.3).

**Companion documents.** `S030-D2-Analysis.md` (the authoritative field-coverage analysis; §3.2 the determinism statement, §4 item 9 the partner_subset_hash closure, §5 the timestamp closure); `EqAbortViewDigestExtension.md` (the UNION-reconciliation closure of the pool-fed eq/abort dimensions — the *contrast* class); `TimestampReconciliationSoundness.md` (the median-reconciliation closure of the `timestamp` dimension — the sibling deterministic-but-numeric field; spec-level cite, may be authored in parallel); `UnderQuorumMerge.md` (FA9 — the R4 under-quorum merge whose `merge_state_` is the deterministic source of `partner_subset_hash`); `StateRootAnchorSoundness.md` (the `state_root` field's *transitive-forward* binding — the field `partner_subset_hash` shares the `signing_bytes` zero-skip shim with, but unlike `state_root`, `partner_subset_hash` IS bound directly into the digest); `Safety.md` (FA1 — the ≤1-finalized-digest-per-height property whose two-instance footnote the D2 dimensions narrow); `Preliminaries.md` (F0) §2.0 (assumption labels); `docs/SECURITY.md §S-030`; `docs/PROTOCOL.md §4.1` (`signing_bytes` field list) + §4.3 (`block_digest` field list).

---

## 1. Scope

`partner_subset_hash` is the R4/R7 merged-signing commitment: when an under-quorum shard merges with a partner (FA9 / `UnderQuorumMerge.md`), the block carries a 32-byte hash binding the partner shard's tx-subset commitment into the K-of-K committee signature. On a non-merged block the field is the all-zero default.

Commit `8585a50` made `compute_block_digest` append `partner_subset_hash` when non-zero. The proof covers, as four numbered theorems plus supporting lemmas:

- **T-1** DETERMINISM-WITHOUT-RECONCILIATION — `partner_subset_hash` is computed identically by every committee member at a merged height from `merge_state_`, so it can be bound RAW into the digest with no Phase-1 view-reconciliation, and doing so cannot reintroduce the §2 gossip-async divergence.
- **T-2** STRIP/ALTER-DETECTION — binding it into the K-of-K-signed digest closes the S-030-D2 `partner_subset_hash` ✗ row: a relayer that strips or alters the merged-signing commitment after the signatures gather changes the digest, so verification fails.
- **T-3** BACKWARD-COMPAT — the conditional-on-non-zero gate (mirroring `signing_bytes`, block.cpp:329-334) keeps every non-merged block byte-identical to the v1 digest.
- **T-4** LIGHT-CLIENT — `partner_subset_hash` survives the `rpc_headers` strip, so `light_compute_block_digest` binds it too; header-only sync stays sound for merged-but-non-F2 blocks.

The relationship to the `timestamp` closure (`TimestampReconciliationSoundness.md`) and the resulting "S-030-D2 fully digest-closed" status (`cross_shard_receipts` excepted as derived-from-`tx_root`) is stated in §5.

**Out of scope.** The R4 merge state machine's own correctness (FA9 / `UnderQuorumMerge.md` — that `merge_state_` is a deterministic function of canonical MERGE_EVENT apply order, and that the partner is the unique `(shard_id + 1) mod shard_count_`); this proof *consumes* FA9's determinism as a premise. The cryptographic soundness of the merged-signing scheme itself (R4 design). The pool-fed eq/abort/inbound closures (`EqAbortViewDigestExtension.md`). The apply-layer S-033 closure path (`S030-D2-Analysis.md` §3.5).

---

## 2. The binding (load-bearing)

This section states precisely, from the source, what binds `partner_subset_hash` and how, so that T-1..T-4 rest on the actual mechanism rather than on the field's name.

### 2.1 What the committee signs: `compute_block_digest` (binds `partner_subset_hash` when non-zero)

Each committee member's Phase-2 Ed25519 signature in `creator_block_sigs[i]` is over `compute_block_digest(B)` (`src/node/producer.cpp::compute_block_digest`, the append sequence ending at lines 674-676). After the v1 core (index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs) and the three conditional F2 appendages (inbound at :629, eq at :650, abort at :656), the digest appends:

```cpp
if (!is_zero_hash_(b.partner_subset_hash)) {
    h.append(b.partner_subset_hash);
}
```

The fixed field order is **inbound, eq, abort, partner_subset_hash, timestamp** (producer.cpp:673, :688). `partner_subset_hash` is therefore *directly* covered by the K-of-K Phase-2 signature on a merged block — in contrast with `state_root`, which is absent from the digest and bound only transitively-forward via `signing_bytes` → `block_hash` → next block's `prev_hash` (`StateRootAnchorSoundness.md` §3).

### 2.2 What `partner_subset_hash` is also bound into: `signing_bytes` / `block_hash` (when non-zero)

`Block::signing_bytes()` independently appends `partner_subset_hash` under the same non-zero guard (block.cpp:329-334):

```cpp
{
    Hash zero{};
    if (partner_subset_hash != zero) {
        b.append(partner_subset_hash);
    }
}
```

so `partner_subset_hash(B) ∈ signing_bytes(B) ∈ block_hash(B)` whenever it is non-zero, exactly as `state_root` is (block.cpp:345-350). This is the WireFormatBackwardCompat zero-skip pattern. The digest binding of §2.1 is the *additional* coverage that commit `8585a50` introduced: pre-`8585a50`, `partner_subset_hash` was bound into `block_hash` (so a future block's `prev_hash` forward-bound it) but **not** into the *current* block's K-of-K digest, leaving the §3.4 strip-after-signing window the D2 ✗ row records.

### 2.3 The deterministic source: `Chain::merge_state_`

`partner_subset_hash` is non-zero only on a merged block, and its value is a pure function of the merging shard's state. Per `UnderQuorumMerge.md` (FA9): `Chain::merge_state_` maps `shard_id → {partner_id, refugee_region}`, mutated only inside `apply_transactions` and only on canonical MERGE_EVENT input, with `partner_id == (shard_id + 1) mod shard_count_` enforced at BEGIN. FA9 §3 (Determinism, L-1.1 analog): `merge_state_` is a deterministic function of the apply order of MERGE_EVENT txs, so the merged-shard state at height `h` is identical for every honest node that has applied the same canonical block prefix. The `partner_subset_hash` derived from it inherits that determinism — this is the premise T-1 discharges into the digest argument.

### 2.4 Field-membership table

| Field | In `compute_block_digest`? | In `signing_bytes` (`block_hash`)? | Class | Reconciliation needed before digest? |
|---|---|---|---|---|
| `index`, `prev_hash`, `tx_root`, `delay_seed` | yes | yes | v1 core | n/a (committed Phase-1 / structural) |
| `inbound_receipts` (root) | yes, when non-empty (`a727cb2`) | yes | gossip-async pool | **yes** — INTERSECTION of K committed views |
| `equivocation_events` (root) | yes, on non-zero view root (`48c4b45`) | yes | gossip-async pool | **yes** — UNION of K committed views |
| `abort_events` (root) | yes, on non-zero view root (`48c4b45`) | yes | gossip-async pool | **yes** — UNION of K committed views |
| **`partner_subset_hash`** | **yes, when non-zero (`8585a50`)** | yes, when non-zero | **deterministic merge-state** | **NO — identical across members** |
| `timestamp` | yes, when reconciled (`f99eeb8`) | yes | deterministic (numeric median) | median of K committed times (numeric, not set) |
| `state_root` | NO | yes, when non-zero | apply-derived | n/a (transitive-forward binding) |
| `cross_shard_receipts` | NO | yes | derived from tx set | n/a (already bound via `tx_root`) |

The `partner_subset_hash` row is the subject of this proof. The decisive column is the rightmost: it is the only digest-bound field that is both (a) NOT a v1-core structural field and (b) requires NO reconciliation, because it is deterministic from chain state rather than gossip-fed. `timestamp` is its near-sibling (deterministic, but a numeric median rather than a single chain-derived hash — see §5).

---

## 3. Threat model

### 3.1 Adversary `A_relay`

`A_relay` is a relayer / man-in-the-middle on the gossip layer that observes a genuine merged block `B` after its K-of-K Phase-2 signatures have gathered, and attempts to propagate a mutated instance `B'` that (a) differs from `B` in the merged-signing commitment (strip `partner_subset_hash` to zero, or substitute a forged `R_A`), yet (b) still passes committee-signature verification at honest receivers, so the receivers apply a block carrying a partner-subset commitment the committee never signed. This is the S-030-D2 "strip/alter after signing" attack shape, specialized to `partner_subset_hash`.

### 3.2 Adversary `A_stall`

`A_stall` is the dual concern raised by `S030-D2-Analysis.md` §2: a *correctness-of-the-fix* adversary, namely the gossip-async race itself. The §2 obstacle is not a malicious party but an honest-network phenomenon — if the digested value were a per-member gossip-fed view, two honest assemblers would compute different digests and the K signatures would never gather, stalling the round. T-1 is the claim that `partner_subset_hash` does not expose this surface (it is deterministic), so binding it RAW cannot induce `A_stall`.

### 3.3 Out of scope

`A_crypto` (SHA-256 collision finder / Ed25519 forger): the binding rests on A1 + A2 being infeasible. A fully-Byzantine K-of-K committee that mints a single block with a chosen `partner_subset_hash`: that is the producer's own signed commitment, not a relay attack — the digest binding makes the committee *accountable* for the value it signed (and the value's correctness against `merge_state_` is FA9's validator-side concern), but the two-instance fully-Byzantine case is the residual `S030-D2-Analysis.md` §3.5 / Safety.md §5.3 boundary, identical to every other dimension. The R4 merge state machine's own soundness (FA9).

---

## 4. Soundness theorems

Throughout, `B` is a genuine merged block at height `h` with non-zero `partner_subset_hash = R_T`; `K_h` the height-`h` committee; `digest(·)` = `compute_block_digest(·)`; `required` the K-of-K (MD) or `⌈2·k_bft/3⌉`-of-`k_bft` (BFT) signature count. Bounds use the `Preliminaries.md §2.0` labels (A1, A2 ≈ `2⁻¹²⁸`).

### 4.1 T-1 (determinism-without-reconciliation)

**Statement.** Let `h` be a merged height and let `M ⊆ K_h` be the honest committee members that have applied the same canonical block prefix `B_0 … B_{h-1}`. Then every member in `M` computes the *identical* `partner_subset_hash` value `R_T`. Consequently `compute_block_digest` may append `R_T` RAW — with no Phase-1 commit-then-reconcile step — and the resulting digest is byte-identical across all members of `M`, so the K-of-K signatures gather. Binding `partner_subset_hash` RAW cannot reintroduce the gossip-async digest divergence of `S030-D2-Analysis.md` §2.

**Proof.** By §2.3 + FA9 (`UnderQuorumMerge.md` §3, Determinism L-1.1 analog), `partner_subset_hash` at height `h` is a pure function of `Chain::merge_state_`, which is itself a deterministic function of the canonical MERGE_EVENT apply order over the shared prefix `B_0 … B_{h-1}`. Every member of `M` has, by hypothesis, applied that identical prefix; `apply_transactions` is deterministic (FA9; and the per-shard apply determinism of FA-Apply-15 / `MultiEventComposition.md`). Therefore each member's `merge_state_` is byte-identical, hence each member's derived `partner_subset_hash` is the identical 32-byte value `R_T`.

Now compare with the gossip-async class. For a pool-fed field (eq/abort/inbound), the digested value at member `m` is `f(view_m)` where `view_m` is `m`'s local pool snapshot at its commit instant; two honest members hold `view_A ≠ view_B` under gossip lag, so `f(view_A) ≠ f(view_B)`, divergent digests, no signature gathering (`S030-D2-Analysis.md` §2). The structural fix for that class is to digest `reconcile(commit_1, …, commit_K)` — a function of the K *signed* Phase-1 commits, identical across members (`EqAbortViewDigestExtension.md` §3.2). For `partner_subset_hash` there is **no `view_m`**: the value is read from chain state, not from a gossip-fed pool, so it is *already* identical across `M` without any reconciliation step. The reconciliation machinery would be a no-op (reconciling K identical values yields that value). Hence the RAW append at producer.cpp:674-676 produces the same digest at every member of `M`; the K-of-K signatures gather; `A_stall` (§3.2) is not induced. ∎

**Remark (why this is *not* the reverted naive fix).** `S030-D2-Analysis.md` §2 records that a naive RAW extension of the digest was implemented and reverted because it broke the equivocation-slashing regression — but that extension hashed the *pool-fed* per-member views. The lesson is "do not RAW-bind a gossip-async per-member view," not "do not RAW-bind anything new." `partner_subset_hash` is categorically outside the pool-fed class (§2.4), so the §2 prohibition does not reach it. This is exactly the disposition `S030-D2-Analysis.md` §3.2 anticipates ("For `partner_subset_hash` (R4 merge), the reconciliation is simpler — it's a single hash value that all committee members at a merged height should compute identically from the merge state. No per-member pool involved.").

### 4.2 T-2 (strip/alter-detection)

**Statement.** Binding `partner_subset_hash` into `compute_block_digest` closes the S-030-D2 `partner_subset_hash` ✗ row: under `A_relay` (§3.1), a mutated instance `B'` with `partner_subset_hash = R_A ≠ R_T` (including the strip-to-zero case `R_A = 0`) cannot retain `B`'s K-of-K signatures, except with probability `≤ required · 2⁻¹²⁸` (A1) or `≤ 2⁻¹²⁸` (A2).

**Adversary game.** `A_relay` observes genuine `B` with `partner_subset_hash = R_T ≠ 0` and `required` valid `creator_block_sigs` over `digest(B)`. It emits `B'` identical to `B` except `partner_subset_hash = R_A ≠ R_T`, replaying the genuine signatures. `A_relay` wins if an honest receiver's `verify_block_sigs(B')` returns `ok`.

**Proof.** The receiver recomputes `digest(B')` and Ed25519-verifies the replayed `creator_block_sigs` against `K_h`. Two cases on `R_A`:

- **`R_A ≠ 0` (alter).** Both `R_T` and `R_A` are non-zero, so the producer.cpp:674 guard fires for both; `digest` appends `R_T` for `B` and `R_A` for `B'`. Since the append differs in those 32 bytes and all prior appends are identical, `digest(B') = digest(B)` only if the two distinct input byte-strings collide under SHA-256 — an A2 event, `≤ 2⁻¹²⁸`. Absent the collision, `digest(B') ≠ digest(B)`, so the replayed signatures (valid over `digest(B)`) do not verify over `digest(B')`. To make them verify, `A_relay` must forge `required` signatures over `digest(B')` against distinct `K_h` members — A1, `≤ required · 2⁻¹²⁸` by union bound.

- **`R_A = 0` (strip).** Now the producer.cpp:674 guard does *not* fire for `B'`, so `digest(B')` omits the 32-byte `partner_subset_hash` append entirely, whereas `digest(B)` included it. The two digests differ by the presence/absence of a 32-byte tail field; `digest(B') = digest(B)` again requires a SHA-256 collision between a string and its `partner_subset_hash`-extended form (A2, `≤ 2⁻¹²⁸`). Same conclusion: the signatures fail to verify over `digest(B')` absent a collision or an A1 forgery.

Either way, `Pr[A_relay wins T-2] ≤ required · 2⁻¹²⁸ + 2⁻¹²⁸`. Pre-`8585a50`, `partner_subset_hash` was absent from the digest, so a stripped/altered instance recomputed the *same* digest (the field was not in it) and the genuine signatures verified — the open ✗ row. Commit `8585a50` is exactly the append that moves `partner_subset_hash` into the signed byte-string, defeating the relay. ∎

**Remark (relation to the forward-binding that already existed).** Even pre-`8585a50`, `partner_subset_hash` was in `signing_bytes` (§2.2), so the *next* block's `prev_hash` would have surfaced the tamper at height `h+1` (the `StateRootAnchorSoundness.md`-style transitive-forward mechanism, one-block detection window). T-2's contribution is to close the window at height `h` itself: the committee's *own* signature on `B` now attests to `R_T`, so an honest receiver rejects `B'` immediately on signature verification rather than one block later via `prev_hash` mismatch. This narrows the D2 divergence window for the merged-signing dimension from "one block" to "zero blocks," matching the inbound/eq/abort closures.

### 4.3 T-3 (backward-compat)

**Statement.** The conditional-on-non-zero gate keeps every non-merged block byte-identical to the v1 digest. Formally, for any block `B` with `partner_subset_hash = 0`, `compute_block_digest(B)` equals the pre-`8585a50` digest byte-for-byte; the binding contributes nothing.

**Proof.** The append is guarded by `if (!is_zero_hash_(b.partner_subset_hash))` (producer.cpp:674). On a non-merged block `partner_subset_hash` is the all-zero default `Hash{}`, so `is_zero_hash_` returns true and the body is skipped — no bytes are appended. The remaining appends are exactly the pre-`8585a50` sequence. Therefore the digest is byte-identical to the v1 digest for every non-merged block. This is the same zero-skip shim `signing_bytes` uses for `partner_subset_hash` (block.cpp:329-334) and for `state_root` (block.cpp:345-350) — the WireFormatBackwardCompat C-2 pattern. The empirical pin is **FAST=1 (158→159 PASS)**: no existing digest changed across the `8585a50` build, confirming zero non-merged blocks were perturbed. The in-process `determ test-block-digest` (26 assertions) exercises both branches: the merged (non-zero) path appends and changes the digest, the non-merged (zero) path leaves the v1 digest byte-identical. ∎

**Corollary (composability with the other conditional appends).** Because every D2 append (inbound, eq, abort, partner_subset_hash, timestamp) is individually empty-skip-gated and the field order is fixed (producer.cpp:629/650/656/674/689), a block that is merged-but-not-F2 appends *only* `partner_subset_hash`, and a block that is F2-but-not-merged appends *only* the pool-fed roots. The gates are orthogonal; no combination perturbs a field it does not carry. This is what lets T-4's light client bind `partner_subset_hash` even on a header where the F2 collections were stripped (§4.4).

### 4.4 T-4 (light-client)

**Statement.** `partner_subset_hash` survives the `rpc_headers` strip, so `light_compute_block_digest` binds it byte-identically to the node's digest; a light client doing header-only sync stays sound for merged-but-non-F2 blocks (it detects a daemon that tampers `partner_subset_hash` post-signing), while the F2 view-roots remain omitted by the light client because they need the stripped collections.

**Proof.** Two facts, both from source:

1. **The field survives the strip.** `Node::rpc_headers` (node.cpp:2639) strips only the four heavy collections — `transactions`, `cross_shard_receipts`, `inbound_receipts`, `initial_state` — and explicitly *keeps* `partner_subset_hash` (node.cpp:2629-2634 comment lists it among the retained fields alongside `state_root`). So a header fetched via `rpc_headers` carries the genuine `partner_subset_hash`.

2. **The light client mirrors the append.** `light/verify.cpp::light_compute_block_digest` appends `partner_subset_hash` under the same non-zero guard (verify.cpp:76-78, `if (b.partner_subset_hash != zero) h.append(...)`), explicitly mirroring producer's trailing conditional append (verify.cpp:70-74 comment). Because the field is present in the stripped header (fact 1) and the append logic is byte-identical (fact 2), `light_compute_block_digest(header) = compute_block_digest(B)` for any merged header — so the light client recomputes the exact digest the committee signed and Ed25519-verifies the retained `creator_block_sigs` against the genesis-seeded committee.

Consequently a daemon that tampers `partner_subset_hash` in the served header fails the light client's signature check (the recomputed digest no longer matches the K signatures) — by the T-2 argument, applied at the light client. This is the contrast `light/verify.cpp:46-52` documents: the F2 view-roots (inbound/eq/abort) are *omitted* by the light client and it fail-closes on F2 / cross-shard blocks, because reconstructing those roots needs the stripped collections; `partner_subset_hash` is bound exactly because it is a self-contained field that survives the strip. So header-only sync is sound for the merged-but-non-F2 case: the light client binds `partner_subset_hash` (deterministic, present in the header) but does not attempt the pool-fed roots (which need the heavy collections it does not fetch). The soundness is a false-negative-only posture — the light client never false-PASSes a tampered `partner_subset_hash`; at worst it fail-closes on an F2 block whose pool-fed roots it cannot reconstruct. ∎

### 4.5 Supporting lemmas

**Lemma PSD-L1 (`light_compute_block_digest` partner_subset_hash byte-equivalence).** For any header `H`, the `partner_subset_hash` append in `light/verify.cpp::light_compute_block_digest` (verify.cpp:76-78) is byte-identical to the append in `src/node/producer.cpp::compute_block_digest` (producer.cpp:674-676): same non-zero guard, same single 32-byte `h.append(partner_subset_hash)`, same position in the fixed field order (after abort, before timestamp). *Proof:* line-for-line comparison; both guard on the all-zero `Hash`, both append the raw 32 bytes, both sit at the inbound→eq→abort→**partner_subset_hash**→timestamp position (producer.cpp:673 / verify.cpp:87 comments both pin the order). Any future divergence surfaces in the cross-binary `tools/test_light_verify_block_sigs.sh` (boots a real producer-generated block) and in `determ test-block-digest`. □

**Lemma PSD-L2 (`block_hash` independently binds partner_subset_hash when non-zero).** For any block with `partner_subset_hash ≠ 0`, two distinct values produce distinct `block_hash` except with probability `≤ 2⁻¹²⁸`. *Proof:* `signing_bytes` appends `partner_subset_hash` at block.cpp:331-332 under the `!= zero` guard, and `block_hash = SHA256(signing_bytes ‖ creator_block_sigs)` (block.cpp:356-359). Replacing the field with a distinct non-zero value changes the `signing_bytes` byte-string, so `block_hash` changes unless the two strings collide under SHA-256 — A2. This is the *forward*-binding half that pre-dated `8585a50`; T-2's digest binding is the *direct* coverage that closes the at-height window the forward link left open. □

---

## 5. Composition — the S-030-D2 digest closure is now complete

`partner_subset_hash` (this document) and `timestamp` (`TimestampReconciliationSoundness.md`) are the two non-pool-fed D2 dimensions. Their closures complete the picture `S030-D2-Analysis.md` §4 tracks:

| Dimension | Closure mechanism | Reconciliation? | Proof |
|---|---|---|---|
| `inbound_receipts` | digest-bind INTERSECTION of K committed views (`a727cb2`) | yes (intersection) | `S030-D2-Analysis.md` §4 item 7 |
| `equivocation_events` | digest-bind UNION of K committed views (`48c4b45`) | yes (union) | `EqAbortViewDigestExtension.md` |
| `abort_events` | digest-bind UNION of K committed views (`48c4b45`) | yes (union) | `EqAbortViewDigestExtension.md` |
| **`partner_subset_hash`** | **digest-bind RAW (deterministic from merge state) (`8585a50`)** | **NO** | **this document (T-1..T-4)** |
| `timestamp` | digest-bind lower-median of K committed times (`f99eeb8`) | numeric median (deterministic) | `TimestampReconciliationSoundness.md` |
| `cross_shard_receipts` | NOT bound — derived from the committee tx set | n/a | already bound via `tx_root` + `creator_tx_lists` |

**Relation to the timestamp closure.** `partner_subset_hash` and `timestamp` are both *deterministic* fields, so neither needs the carry→reconcile→digest pool machinery of the eq/abort/inbound closures. They differ only in *how* the deterministic value is obtained: `partner_subset_hash` is read from chain state (`merge_state_`), so it is identical across honest members *before* any aggregation (T-1 — RAW append suffices); `timestamp` is a numeric *lower-median* of the K committed `proposer_time`s, so it requires a trivial aggregation step at the Phase-1→Phase-2 boundary (`reconcile_median_time` over the K signed times) but no set-reconciliation, and the median is itself a deterministic pure function of the K signed commits (`TimestampReconciliationSoundness.md` / `S030-D2-Analysis.md` §5). Both append conditionally (partner_subset_hash on non-zero; timestamp on non-empty `creator_proposer_times`) so both preserve the v1 digest for legacy blocks (T-3 and its timestamp analog). They occupy adjacent slots in the fixed field order — `…, abort, partner_subset_hash, timestamp` (producer.cpp:673/688, verify.cpp:87) — and both survive the `rpc_headers` strip, so the light client binds both (T-4 and its timestamp analog).

**Joint conclusion (S-030-D2 fully digest-closed).** With `partner_subset_hash` (T-1..T-4) and `timestamp` (`TimestampReconciliationSoundness.md`) both bound, and the three pool-fed dimensions bound via F2 reconciliation, **every S-030-D2 digest dimension is now covered by the K-of-K Phase-2 signature** — `cross_shard_receipts` excepted, and that field is not an independent divergence vector: it is deterministically derived from the committee tx set, which `tx_root` + `creator_tx_lists` already bind into the digest (`S030-D2-Analysis.md` §1 row / §4 item 10). So no two distinct block instances can both gather K-of-K signatures at the same height on the basis of any differing apply-affecting field. The consensus-layer D2 closure is therefore complete, strengthening the apply-layer S-033 partial closure (`S030-D2-Analysis.md` §3.5) into a full consensus-layer property: the literal "no two K-of-K-signed bodies per height" claim now holds for the merged-signing dimension, not merely "only one apply-validates."

---

## 6. Limitations

### 6.1 Two-instance fully-Byzantine committee (inherited boundary)

T-2 defeats `A_relay` (post-signing tamper). It does *not* by itself prevent a fully-Byzantine K-of-K committee from minting a *single* block with a chosen `partner_subset_hash` and signing it. That value's correctness against `merge_state_` is FA9's validator-side concern (`UnderQuorumMerge.md`), not the digest binding's. The two-instance fully-Byzantine case (two distinct bodies, both K-of-K-signed, with different `partner_subset_hash`) is the residual `Safety.md` §5.3 / `S030-D2-Analysis.md` §3.5 boundary identical to every D2 dimension; the digest binding makes the committee *accountable* (the signed value is now pinned) but the honest-majority-committee assumption is what excludes the two-instance attack. For permissioned/consortium deployments this is the operative threat model; the digest binding is the consensus-layer hardening over the apply-layer S-033 fallback.

### 6.2 Determinism premise is FA9's

T-1 consumes FA9's claim that `merge_state_` (hence `partner_subset_hash`) is a deterministic function of canonical MERGE_EVENT apply order. If FA9's premise failed (e.g. a non-deterministic merge path), honest members could derive different `partner_subset_hash` values, and the RAW append would re-expose `A_stall`. This proof is conditional on FA9; it does not re-prove merge determinism. The empirical pin for the joint property is `tools/test_under_quorum_merge.sh` (FA9) composed with `determ test-block-digest` (the digest binding).

### 6.3 Light-client F2 fail-close (not a partner_subset_hash defect)

T-4's "merged-but-non-F2" qualifier is load-bearing: on a block that is *both* merged *and* F2 (carries pool-fed view roots), the light client still binds `partner_subset_hash` correctly but fail-closes on the F2 view-roots it cannot reconstruct from the stripped collections (`light/verify.cpp:46-48`). This is a property of the F2 dimensions, not of `partner_subset_hash` — the light client's `partner_subset_hash` binding is sound regardless; it simply cannot complete full digest verification on an F2 block via headers alone, and correctly fail-closes rather than false-PASS (verify those against a full node).

---

## 7. Cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| `compute_block_digest` partner_subset_hash append | `src/node/producer.cpp:674-676` (guard `!is_zero_hash_`) | The §2.1 / T-2 direct digest binding (commit `8585a50`). Field order pinned at :673. |
| `Block::signing_bytes` partner_subset_hash append | `src/chain/block.cpp:329-334` (guard `!= zero`) | The §2.2 forward-binding half (pre-`8585a50`); the zero-skip shim T-3 mirrors. |
| `Block::compute_hash` | `src/chain/block.cpp:356-359` | `SHA256(signing_bytes ‖ creator_block_sigs)` = `block_hash` (PSD-L2). |
| `light_compute_block_digest` partner_subset_hash append | `light/verify.cpp:70-78` | The T-4 / PSD-L1 light-client mirror; comment at :46-52 documents the F2-omit vs partner-bind contrast. |
| `Node::rpc_headers` | `src/node/node.cpp:2639` (retain list at :2629-2634) | T-4 fact 1: `partner_subset_hash` survives the header strip (kept alongside `state_root`). |
| `Chain::merge_state_` + MERGE_EVENT apply | `src/chain/chain.cpp::apply_transactions` (FA9 §6 table) | T-1 / §2.3: the deterministic source of `partner_subset_hash`. |
| `S030-D2-Analysis.md` | §3.2 (determinism), §4 item 9 (partner_subset_hash closure), §5 (timestamp), §1 table | The authoritative field-coverage analysis this proof formalizes for the partner dimension. |
| `EqAbortViewDigestExtension.md` | §3 (gossip-async gate) | The contrast class — pool-fed UNION reconciliation; T-1's foil. |
| `TimestampReconciliationSoundness.md` | (sibling, this round) | The other deterministic-field closure; §5 composition. (Spec-level cite.) |
| `UnderQuorumMerge.md` | FA9 §3 (Determinism), §6 (code table) | The premise T-1 / §2.3 consumes: `merge_state_` determinism. |
| `StateRootAnchorSoundness.md` | §3 (transitive-forward binding) | The contrast field: `state_root` is NOT in the digest (transitive-forward only); `partner_subset_hash` IS (direct). |
| `Safety.md` | FA1 §5.3 | The ≤1-finalized-digest property whose two-instance footnote §6.1 inherits. |
| `tools/test_block_digest.sh` / `determ test-block-digest` | (26 assertions) | In-process pin: merged path appends + changes digest, non-merged path keeps v1 digest (T-3). |
| FAST=1 regression set | (158→159 PASS across the `8585a50` build) | Empirical pin that no existing digest changed (T-3). |

---

## 8. Status

- **Implementation.** Shipped in commit `8585a50`: `src/node/producer.cpp::compute_block_digest` appends `partner_subset_hash` when non-zero (producer.cpp:674-676); `light/verify.cpp::light_compute_block_digest` mirrors it (verify.cpp:76-78). The `signing_bytes` forward-binding (block.cpp:329-334) and the `rpc_headers` retention (node.cpp:2629-2634) pre-existed.
- **Proof.** Complete (this document). T-1 (determinism-without-reconciliation), T-2 (strip/alter-detection), T-3 (backward-compat), T-4 (light-client), with supporting lemmas PSD-L1 / PSD-L2.
- **Closure classification.** `partner_subset_hash` is the one S-030-D2 dimension that closed at the consensus layer with **NO** Phase-1 view-reconciliation, because it is deterministic from `merge_state_` rather than a gossip-async per-member pool view. This is categorically distinct from the inbound/eq/abort closures (`EqAbortViewDigestExtension.md`) and is the disposition `S030-D2-Analysis.md` §3.2 anticipated.
- **Joint status.** With `partner_subset_hash` (this proof) and `timestamp` (`TimestampReconciliationSoundness.md`) bound, **every S-030-D2 digest dimension is now consensus-layer-closed** — `cross_shard_receipts` excepted as deterministically derived from the committee tx set already bound via `tx_root` (§5). The consensus-layer D2 closure strengthens the apply-layer S-033 partial closure into the full "no two K-of-K-signed bodies per height" property.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA) and A2 (SHA-256 collision resistance), per `Preliminaries.md §2.0`.
- **Concrete-security bound.** T-2: `≤ required · 2⁻¹²⁸ + 2⁻¹²⁸ ≤ (K+1) · 2⁻¹²⁸`. T-1 / T-3 are exact (determinism + byte-identity, no probabilistic term). T-4 inherits T-2's bound at the light client.
- **Conditional on FA9.** T-1's determinism premise is FA9 (`UnderQuorumMerge.md`); this proof does not re-prove merge-state determinism (§6.2).
