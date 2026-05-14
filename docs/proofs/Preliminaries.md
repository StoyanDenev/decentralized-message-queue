# Determ — Formal-verification Preliminaries

This document fixes the notation, cryptographic assumptions, network model, and protocol-object definitions that the per-property theorems (Safety, Censorship Resistance, Selective-Abort Defense, Liveness, BFT-mode safety, Equivocation Slashing, Cross-shard Receipts, Regional Sharding) reference.

A reader who has not seen the Determ implementation can follow this document to understand what the formal claims are *about*. A reader who has only the code can use the cross-references in §10 to locate the source-level objects.

---

## 1. Notation

### 1.1 Validators

Let `V = {v₁, …, v_N}` denote the validator pool — the set of all registered, active, staked-at-or-above-`min_stake`, non-suspended domains at a given chain height. `N := |V|`.

Each validator `v_i ∈ V` holds an Ed25519 keypair `(sk_i, pk_i)`, where:
- `sk_i ∈ {0,1}²⁵⁶` is a 32-byte secret seed.
- `pk_i ∈ 𝔼` is the corresponding curve25519 public key.

The signing function `Sign(sk, m) ↦ σ ∈ {0,1}⁵¹²` and verification `Verify(pk, m, σ) ↦ {0, 1}` are RFC 8032 Ed25519.

### 1.2 Heights, rounds, and committees

A chain produces a sequence of blocks `B₀, B₁, B₂, …` with strictly monotone height. `B₀` is the genesis block (constructed without consensus). Heights `h ≥ 1` are produced by consensus.

At each height `h`, one or more **rounds** may execute. A round is an attempt to finalize a block at that height. Most heights succeed on round 1; aborted rounds increment a per-height counter and retry. A block carries an `abort_events[]` list of round-level abort certificates for that height.

For each round at height `h`, the protocol deterministically selects a **K-committee** `K_h ⊂ V` of `K` distinct validators, where `K` is the genesis-pinned `k_block_sigs` constant and `1 ≤ K ≤ N`. Selection details are in §6.

Each committee member computes:
- A fresh 32-byte secret `s_i ∈ {0,1}²⁵⁶` drawn from a CSPRNG, used in Phase 1.
- A Phase-1 commitment `c_i := SHA256(s_i ‖ pk_i)`.

### 1.3 Hashes and message digests

`H : {0,1}* → {0,1}²⁵⁶` denotes SHA-256 (NIST FIPS 180-4). Concatenation is `‖`. Multi-byte integers in hash inputs are encoded **big-endian**.

`signing_bytes(B)` is the canonical serialization of all block fields except the K Phase-2 signatures (those are appended afterward to form `compute_hash(B)`). See `src/chain/block.cpp::signing_bytes`.

`compute_block_digest(B)` is what each Phase-2 committee member signs over. It **excludes** `delay_output` and `creator_dh_secrets` so members can sign immediately at Phase-2 entry without waiting for the K reveals to gather. The final `delay_output` and reveals are bound into the block hash via `signing_bytes(B)`.

`R(B)` denotes the block's randomness output: `R(B) := SHA256(delay_seed(B) ‖ s_{σ(1)} ‖ … ‖ s_{σ(K)})` where `σ` is the committee selection order. We refer to `R(B)` as `delay_output(B)`.

### 1.4 Inclusion model

The chain is parameterized by `inclusion_model ∈ {STAKE, DOMAIN}`. STAKE-mode chains gate eligibility on `stake(v) ≥ min_stake`; DOMAIN-mode chains gate on registration only (`min_stake = 0`). Both deliver the same K-of-K mutual-distrust property; theorems below apply to both unless otherwise stated.

---

## 2. Cryptographic assumptions

Theorems below are proved under the following standard concrete-security assumptions. All bounds are concrete-security (concrete probability of adversarial success per CPU step), not asymptotic.

### 2.1 SHA-256

**Collision resistance.** No polynomial-time adversary can find `x, y` with `x ≠ y` and `H(x) = H(y)` with probability non-negligibly better than `2⁻¹²⁸` (birthday bound on a 256-bit output). Citation: NIST FIPS 180-4; see Bellare & Rogaway "Introduction to Modern Cryptography" §5.3 for a textbook treatment.

**Preimage resistance.** No polynomial-time adversary can recover `x` from `H(x)` for uniformly random `x ∈ {0,1}²⁵⁶` with probability non-negligibly better than `2⁻²⁵⁶`. (Under Grover, the quantum lower bound is `2⁻¹²⁸`.)

**Second-preimage resistance.** No polynomial-time adversary, given `x`, can find `x' ≠ x` with `H(x') = H(x)` with probability non-negligibly better than `2⁻²⁵⁶`. (Implied by collision resistance up to constants.)

Several theorems below use SHA-256 in the **random oracle model** (ROM) for clean security reductions. Where this is the case, it is stated explicitly. The same theorems can be re-derived in the standard model using only the three concrete-security properties above, with messier hybrid arguments.

### 2.2 Ed25519

**EUF-CMA.** No polynomial-time adversary, given oracle access to `Sign(sk, ·)` and the public key `pk`, can produce `(m, σ)` with `Verify(pk, m, σ) = 1` for an `m` it never queried, except with probability non-negligibly better than `~2⁻¹²⁸`. Reference: RFC 8032 + Brendel-Cremers-Jackson-Zhao "The Provable Security of Ed25519" (USENIX 2021).

We assume Ed25519 implementations reject low-order points (libsodium / OpenSSL behavior; see RFC 8032 §5.1.7).

### 2.3 Uniform secret sampling

Phase-1 secrets `s_i ∈ {0,1}²⁵⁶` are drawn from a CSPRNG that is computationally indistinguishable from a true uniform source. In practice, OpenSSL `RAND_bytes`. Min-entropy of the underlying OS source is assumed to be `≥ 256` bits per draw.

### 2.4 What we do not assume

- We do **not** assume hash-based VDFs, iterated SHA-256 sequentiality, or any compute-time bounds on the adversary's hash rate. The protocol's selective-abort defense is information-theoretic under preimage resistance, not compute-time-bound (see Safety theorem and Selective-Abort theorem).
- We do **not** assume a trusted third party, secure clock, or VRF beacon.
- We do **not** assume any honest majority, honest minority, or `f < N/3` bound for **safety** properties (those hold unconditionally). For **liveness** properties, see §4.

---

## 3. Network and adversary model

### 3.1 Network

We assume **partial synchrony** (Dwork, Lynch, Stockmeyer 1988): there exists a known bound `Δ` such that during synchrony intervals, every message sent at time `t` is delivered to every honest recipient by `t + Δ`. Between synchrony intervals, message delivery may be arbitrarily delayed.

Honest validators run on devices with bounded local clock drift; clocks may be unsynchronized but are not adversarially controllable.

### 3.2 Adversary

A **Byzantine adversary** A may corrupt any subset `F ⊂ V` of validators (the **Byzantine set**), `|F| =: f`. Corrupted validators may:
- Deviate arbitrarily from the protocol: equivocate, delay, refuse, fabricate state.
- Delay their own messages within `Δ` during synchrony intervals.
- Choose which Phase-1 commits and Phase-2 reveals to publish.
- Coordinate among themselves.

A may **not**:
- Forge Ed25519 signatures of honest validators (EUF-CMA).
- Break SHA-256 (collision / preimage / 2nd-preimage).
- Recover Phase-1 secrets of honest members before Phase 2 (preimage resistance on the commitments).
- Eavesdrop on honest validators' private state (CSPRNG outputs that remain in memory).

### 3.3 Honest fraction bounds

For **safety claims** (no two valid blocks at the same height, no false-positive equivocation slashing, etc.), no upper bound on `f` is assumed. Determ's K-of-K mutual-distrust safety holds even if `f = N` for MD-mode blocks — see Safety theorem (FA1).

For **BFT-mode block safety**: `f < K/3` *within the K-effective BFT committee* is required. See FA5.

For **liveness claims**: at least one all-honest K-committee must form within bounded round retries, under partial synchrony. See FA4.

The protocol's effective decentralization threshold for an external observer is **`≥ 1` non-Byzantine validator in `V`** (FA1 + FA2 cover this). This is a property of the system, not a protocol assumption.

---

## 4. Honest validator behavior

A validator `v_i ∈ V \ F` is **honest** iff, in every round of every height, it:

**H1.** Generates a fresh Phase-1 secret `s_i ←ᵤ {0,1}²⁵⁶` (uniform draw, fresh per round); publishes the commitment `c_i = SHA256(s_i ‖ pk_i)` as part of its `ContribMsg` Phase-1 broadcast.

**H2.** Signs at most one block-digest AND at most one contrib commitment per (height, round, aborts_gen) tuple. Specifically: (a) the Phase-2 `BlockSigMsg.ed_sig` is a signature over exactly one `compute_block_digest(B)` value at any height — `v_i` never signs two distinct block digests at the same height in the same round; (b) the Phase-1 `ContribMsg.ed_sig` is a signature over exactly one `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` value at any height-and-generation — `v_i` never signs two distinct contrib commitments at the same (height, aborts_gen) (post-S-006 closure). Cross-generation contribs are legitimate retries after abort and do NOT violate H2.

**H3.** Reveals its Phase-1 secret in Phase-2's `BlockSigMsg.dh_secret` iff the K Phase-1 commits have all been received and validated.

**H4.** Constructs `ContribMsg.tx_hashes` as a deterministic function of its local mempool at Phase-1 start (sorted, deduplicated). The selection rule is implementation-defined but applied uniformly to all mempool entries.

**H5.** Broadcasts via gossip every message it produces or successfully verifies (no withholding). Specifically, if `v_i` verifies a peer's `ContribMsg` or `BlockSigMsg`, it relays it.

**H6.** Refuses to apply any block that fails `BlockValidator::validate` (see §5).

**Note.** "Honest" does not mean morally good; it means "follows the protocol rules above." A validator that deviates from any of H1–H6 is Byzantine for the purposes of these proofs. The reasons for following the protocol — fee revenue, regulatory accountability, reputation, mistake — are outside the proof model.

---

## 5. Block validity predicate

A block `B` at height `h` is **valid** with respect to a chain prefix `B₀, …, B_{h-1}` iff all of the following hold. This is the formal statement of `BlockValidator::validate` (`src/node/validator.cpp`).

For `h = 0` (genesis), validity is trivially `true` — the genesis is not authenticated by signatures, only by its pinned hash in operator config.

For `h ≥ 1`:

**V1 — Previous hash.** `B.prev_hash = compute_hash(B_{h-1})`.

**V2 — Creators registered.** Every `v ∈ B.creators` is in the registry derived from `B₀, …, B_{h-1}` (active, staked-at-or-above-`min_stake`, non-suspended).

**V3 — Creator selection.** `B.creators` equals the deterministic committee `K_h` derived from the abort_events accumulated at this height + the chain's prior `cumulative_rand` + (for shards) the beacon's epoch rand. See §6.

**V4 — Phase-1 commit signatures.** For every `i ∈ [0, K)`:
```
Verify(pk_{B.creators[i]},
       make_contrib_commitment(B.index, B.prev_hash,
                                B.creator_tx_lists[i], B.creator_dh_inputs[i]),
       B.creator_ed_sigs[i]) = 1
```

**V5 — Commit-reveal binding.** For every `i ∈ [0, K)`:
```
SHA256(B.creator_dh_secrets[i] ‖ pk_{B.creators[i]})
    = B.creator_dh_inputs[i]
```

**V6 — Randomness derivation.**
```
B.delay_seed = SHA256(B.index ‖ B.prev_hash ‖ B.tx_root
                       ‖ B.creator_dh_inputs[0] ‖ … ‖ B.creator_dh_inputs[K-1])
B.delay_output = SHA256(B.delay_seed ‖ B.creator_dh_secrets[0]
                                       ‖ … ‖ B.creator_dh_secrets[K-1])
```

**V7 — Transaction root.** `B.tx_root = SHA256(union of B.creator_tx_lists in sorted-unique order)`.

**V8 — Block-digest signatures.** Let `d = compute_block_digest(B)`. Write `k := B.creators.size()` — the round's effective committee size. In MD mode `k = K` (genesis-pinned); in BFT mode `k = k_bft = ⌈2K/3⌉` after the §5.3 committee shrinkage. For every `i ∈ [0, k)`:
```
Verify(pk_{B.creators[i]}, d, B.creator_block_sigs[i]) = 1
   OR
B.creator_block_sigs[i] = 0⁶⁴   ∧   B.consensus_mode = BFT
```
The number of nonzero signatures must be `≥ k` (MD; no sentinels permitted) or `≥ ⌈2 k / 3⌉` (BFT; standard 2/3 quorum within the shrunk committee — see `BlockValidator::check_block_sigs` and `producer.cpp::required_block_sigs`). Note: in BFT mode the relevant threshold is taken over the *BFT committee* `k = k_bft`, not over the genesis K — this matters at K ≥ 6 where the two values diverge (e.g., K = 6 ⇒ k_bft = 4, BFT-required-sigs = 3 not 4).

**V9 — Cumulative rand.** `B.cumulative_rand = SHA256(B_{h-1}.cumulative_rand ‖ B.delay_output)`.

**V10 — Abort certificates.** Each `ae ∈ B.abort_events` carries `K-1` distinct, valid `AbortClaimMsg` signatures from members of the at-event committee against the aborting node.

**V11 — Equivocation events.** Each `ev ∈ B.equivocation_events` carries two distinct signatures `(sig_a, sig_b)` over distinct digests `(digest_a, digest_b)` by the equivocator's registered Ed25519 key, both verifying.

**V12 — Cross-shard receipts, source side** (shards only). `B.cross_shard_receipts` matches the cross-shard subset of `B.transactions` one-for-one with field-wise equality, including `(src_shard, dst_shard, tx_hash, from, to, amount, fee, nonce)`. Enforced by `BlockValidator::check_cross_shard_receipts` (`src/node/validator.cpp`). Used in FA7 L-7.1.

**V13 — Inbound receipts, destination side** (shards only). `B.inbound_receipts` is the destination-side credit list. Each entry must have `dst_shard == my_shard_id`, `src_shard ≠ my_shard_id`, be unique within `B`, and not already be in `chain.applied_inbound_receipts_`. Enforced by `BlockValidator::check_inbound_receipts`. Used in FA7 L-7.2.

**V14 — Timestamp.** `|B.timestamp - now()| ≤ 30s` against the validator's local clock (S-003 closure).

**V15 — Transaction apply.** Applying `B.transactions` in canonical order to the chain state derived from `B₀, …, B_{h-1}` produces a consistent state (no negative balances, sequential nonces, valid signatures, etc.). Enforced by `BlockValidator::check_transactions` + `Chain::apply_transactions`.

A block is **finalized** when it has passed V1–V15 on at least one honest validator. By V8, finalization implies at least K (MD) or ⌈2K/3⌉ (BFT) committee members have signed the same `block_digest`.

---

## 6. Committee selection

The committee at height `h`, round `r`, for shard `s` is:

```
epoch_index  = h / epoch_blocks
epoch_start  = epoch_index × epoch_blocks
epoch_rand   = cumulative_rand_at(epoch_start - 1)   // genesis-anchored when epoch_start = 0
shard_seed   = SHA256(epoch_rand ‖ "shard-committee" ‖ shard_id_be(s))
round_rand   = shard_seed; for each ae in current_aborts_at(h):
                  round_rand = SHA256(round_rand ‖ ae.event_hash)
pool         = eligible_in_region(committee_region_of_chain)
                  minus excluded-this-height set
indices      = select_m_creators(round_rand, |pool|, K)
K_{h,r,s}[i] = pool[indices[i]],  i ∈ [0, K)
```

Where:

- `eligible_in_region(R)`: returns the full eligible pool when `R = ""` (global / CURRENT mode); when `R ≠ ""` returns only validators whose registered `region` matches `R` (EXTENDED mode).
- `select_m_creators(seed, n, K)`: deterministic K-out-of-n sampler using `seed` as the PRG source (see `src/crypto/random.cpp`). Without replacement. Hybrid implementation (S-020): rejection sampling when `2K ≤ n` (cheap, no allocation); partial Fisher-Yates shuffle when `2K > n` (bounded O(n) regardless of ratio). Both branches uniform over K-subsets under ROM on `seed`.

For the beacon chain (SINGLE or BEACON role), `shard_id = 0` and `committee_region = ""` typically; the same formula applies.

For shards running `EXTENDED` mode, every shard receives the **same** `epoch_rand` from the beacon (zero-trust: each side independently derives), and the per-shard salt makes selections independent.

---

## 7. State machine

Each validator runs a per-height state machine:

```
IDLE ──(in_sync ∧ selected_for_committee)──> CONTRIB
CONTRIB ──(K Phase-1 contribs received)──> BLOCK_SIG    // asio::post breaks recursion
BLOCK_SIG ──(K Phase-2 BlockSigs received)──> apply_block ──> IDLE (next height)
CONTRIB / BLOCK_SIG ──(timer fires before quorum)──> abort → reset_round (same height)
```

Transitions are deterministic given message arrivals + timer expirations. The `enter_block_sig_phase` transition posts via `asio::post` to break the synchronous call chain — necessary for M=K=1 (single-validator) chains to avoid stack recursion.

---

## 8. Cross-shard receipts (B3)

A cross-shard TRANSFER from `A` on shard `S_a` to `B` on shard `S_b` (where `shard_id_for_address(B) = S_b ≠ S_a`) proceeds:

1. Tx is included in source-shard block at height `h_a`. Source-side apply debits `A` by `amount + fee`; does **not** credit `B` locally.
2. Source producer appends `r ∈ CrossShardReceipt` to `block_{h_a}.cross_shard_receipts` with fields `{src_shard, dst_shard, src_block_index, src_block_hash, tx_hash, from, to, amount, fee, nonce}`.
3. Source broadcasts `CROSS_SHARD_RECEIPT_BUNDLE(block_{h_a})`. Beacon relays unchanged.
4. Destination shard receives the bundle, filters receipts where `r.dst_shard = my_shard`, deduplicates against `pending_inbound_receipts_`, queues by key `(src_shard, tx_hash)`.
5. Destination producer dequeues + bakes into `block.inbound_receipts`. Validator V13 enforces no duplicates against `applied_inbound_receipts_`.
6. Destination apply credits `B` by `r.amount`; inserts `(src_shard, tx_hash)` into `applied_inbound_receipts_`.

**Idempotency invariant.** For every receipt `r`, the destination shard credits `r.to` by `r.amount` at most once. (Step 6 + V13.)

---

## 9. Equivocation slashing

An **equivocation event** is a quadruple `(equivocator, h, σ_a, σ_b)` such that:
- `equivocator ∈ V` is a registered validator with known `pk`.
- `σ_a, σ_b` are valid Ed25519 signatures by `pk` over distinct digests `d_a ≠ d_b`, both at height `h`.

Validator V11 enforces these checks. On apply, the chain:
- Zeroes `stakes_[equivocator].locked`.
- Sets `registrants_[equivocator].inactive_from = h + 1`.

Both effects are atomic with the block apply.

---

## 10. Implementation cross-reference

Notation in this document maps to source-level objects as follows:

| Document | Source |
|---|---|
| `V`, `pk_i`, `sk_i` | `include/determ/node/registry.hpp::NodeEntry`, `crypto::NodeKey` |
| `K_h`, `K_{h,r,s}` | `src/node/node.cpp::check_if_selected` (per-node), `src/node/validator.cpp::check_creator_selection` (verifier) |
| `c_i` (Phase-1 commit) | `ContribMsg::dh_input` in `include/determ/node/producer.hpp` |
| `s_i` (Phase-1 secret) | `Node::current_round_secret_` in `src/node/node.cpp` (held locally, revealed in Phase 2) |
| `B.tx_root` | `Block::tx_root` |
| `B.delay_seed` | `Block::delay_seed` |
| `B.delay_output = R(B)` | `Block::delay_output` |
| `B.creator_dh_inputs[]` | `Block::creator_dh_inputs` |
| `B.creator_dh_secrets[]` | `Block::creator_dh_secrets` (Phase-2 reveals) |
| `B.creator_block_sigs[]` | `Block::creator_block_sigs` (sigs over `compute_block_digest`) |
| `signing_bytes(B)` | `Block::signing_bytes()` in `src/chain/block.cpp` |
| `compute_block_digest(B)` | `compute_block_digest` in `src/node/producer.cpp` |
| `Validate(B)` | `BlockValidator::validate` in `src/node/validator.cpp` |
| `select_m_creators` | `crypto::select_m_creators` in `src/crypto/random.cpp` |
| `epoch_committee_seed` | `crypto::epoch_committee_seed` |
| `eligible_in_region` | `NodeRegistry::eligible_in_region` |
| `applied_inbound_receipts_` | `Chain::applied_inbound_receipts_` |
| Equivocation event | `EquivocationEvent` in `include/determ/chain/block.hpp` |

---

## 11. Citation conventions

Within the per-property documents (`Safety.md`, `Censorship.md`, …):

- **Theorem T-X.** stated as `(Assumptions) ⇒ (Property)`.
- **Proof.** uses Lemmas + reduction to the assumptions in §2.
- **Concrete-security bound** noted alongside qualitative claim where it differs from `negl(λ)`.

Citations within proofs reference this Preliminaries document by section number (`§5.V8`, `§6`, etc.) and reference textbook results (Boneh-Shoup, Goldreich) for cryptographic primitives.

---

## 12. Conventions for the rest of the proof series

- Every theorem starts by re-stating which assumptions from §2 it uses.
- Edge cases (empty chain, height 0, BFT/MD mode mix) are handled in the per-theorem document, not here.
- The proof series treats each theorem as a standalone document; cross-references between theorems (e.g., FA5 BFT-safety uses FA1 quorum-intersection lemma) are marked explicitly.

The series:

| File | Property |
|---|---|
| `Safety.md` (FA1) | Fork freedom: at most one valid block per height. |
| `Censorship.md` (FA2) | K-conjunction censorship resistance. |
| `SelectiveAbort.md` (FA3) | Commit-reveal hybrid argument; no member can bias `R` predictively. |
| `Liveness.md` (FA4) | Probabilistic liveness under (1-p)^K > 0 and synchrony. |
| `BFTSafety.md` (FA5) | Conditional safety of BFT-mode blocks under `f_h < |K_h|/3` within the BFT committee (`|K_h| = ⌈2K/3⌉`). |
| `EquivocationSlashing.md` (FA6) | Only Byzantine validators are slashed (no false positives). |
| `CrossShardReceipts.md` (FA7) | At-most-once + at-least-once (under fairness) credit. |
| `RegionalSharding.md` (FA8) | Regional-pool corollary of safety + censorship. |
