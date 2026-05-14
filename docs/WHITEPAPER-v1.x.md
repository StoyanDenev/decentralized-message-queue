# Determ: A Fork-Free L1 Payment and Identity Chain with Mutual-Distrust Safety

**Version 1.x specification, 2026**

---

## Abstract

We present Determ, a Layer-1 blockchain protocol designed around three structural properties: fork freedom (at most one block finalizes per height), censorship resistance (any single non-Byzantine validator suffices to defeat censorship), and zero-trust safety (no protocol component trusts any participant). Safety is achieved through K-of-K mutual-distrust consensus — every committee member must sign every block — combined with union-tx-root inclusion (the canonical transaction set is the union of every committee member's proposed list). Liveness is achieved through per-height BFT escalation: when the K-of-K committee cannot complete, an automatic fallback to a `ceil(2K/3)` BFT consensus mode unsticks the chain, with the per-block safety mode tagged in the block header so applications can reason about per-block trust.

The protocol uses only two cryptographic primitives — Ed25519 signatures and SHA-256 hashes — and avoids proof-of-work, multi-round voting, and trusted leaders. Randomness is generated via a SHA-256 commit-reveal protocol that defeats selective-abort attacks by information-theoretic construction rather than economic disincentive. Determ scales horizontally via a beacon + shard architecture with cross-shard receipts; in EXTENDED mode, shards group validators by region for sub-second in-shard finality on the public internet.

This v1.x specification covers consensus, sharding, regional pinning with under-quorum merge, governance via N-of-N keyholder PARAM_CHANGE, economic primitives (block subsidy, finite-pool option, lottery distribution, negative entry fee), and a separate wallet binary implementing distributed seed recovery via Shamir's Secret Sharing layered with AEAD envelopes and an OPAQUE password-authenticated key exchange. Every safety-critical mechanism has a corresponding formal-verification proof under standard cryptographic assumptions (Ed25519 EUF-CMA, SHA-256 collision and preimage resistance, with a random-oracle treatment of the commit-reveal binding); a parallel TLA+ specification covers the state-machine layer.

---

## 1. Introduction

### 1.1 Problem statement

Existing blockchain protocols make different tradeoffs across the safety-liveness axis. Nakamoto consensus achieves liveness at the cost of probabilistic, eventual finality and a deep fork tail. BFT-family protocols (Tendermint, Cosmos, Algorand) achieve immediate finality conditional on an honest supermajority (`f < N/3`), trading away unconditional safety: a Byzantine `≥ N/3` can fork. Pipelined and DAG-based designs (Solana, Aleph) sacrifice further on the safety axis for throughput.

Determ targets a different point in this design space: **unconditional safety in steady state**, with conditional liveness restored by a tagged BFT fallback only when the unconditional path stalls. The protocol's primary mechanism is structurally simple — every committee member must sign every block — but the consequences are substantial: a single non-Byzantine validator anywhere in the committee suffices to prevent forks. Censorship resistance follows directly: the canonical transaction set is the union of every committee member's proposed list, so a single honest member suffices to include any pending transaction. The economic security argument inverts from BFT's "majority-honest" assumption to "any-honest" — strictly weaker, strictly more conservative.

This positioning suits applications where safety failures are intolerable (payments, identity, settlement) and where occasional stalls under adversarial load are acceptable. It is explicitly unsuitable for applications requiring arbitrary computation (no contract VM), high-throughput at any cost (no optimistic concurrency), or eventual-consistency semantics (no fork tail).

### 1.2 Contributions

- **K-of-K mutual-distrust consensus** with per-height BFT escalation: a per-block consensus-mode tag exposes the safety guarantee to applications. MD blocks have unconditional safety; BFT blocks have `f_h < k_bft/3` conditional safety (where `k_bft = ⌈2K/3⌉` is the shrunk BFT committee size) plus economic slashing recovery.
- **SHA-256 commit-reveal randomness**: defeats selective-abort by information-theoretic construction. Committee members commit to their secrets in phase 1 before observing any block content; reveal in phase 2 produces a uniform random output bound to the committee but unpredictable at commit time.
- **Union transaction root**: censorship requires unanimous collusion of every validator that ever rotates onto a committee — structurally impossible without full registry capture.
- **Regional sharding (EXTENDED mode)** with under-quorum merge: shards group validators by region tag for intra-region RTT block times; when a regional pool drops below safety threshold, the protocol transparently merges committee operations with the modular-next shard.
- **Genesis-mode governance**: a single bit at chain creation selects "uncontrolled" (consensus constants immutable forever) or "governed" (N-of-N keyholder multisig may mutate a whitelisted subset of parameters mid-chain). The whitelist is enforced by validator; off-list parameters require a new chain identity.
- **Distributed wallet recovery primitive**: T-of-N Shamir secret sharing layered with AES-256-GCM AEAD envelopes and an OPAQUE-style password-authenticated key exchange, providing threshold key recovery without weakening the chain's identity model.
- **Full formal-verification coverage**: every safety-critical mechanism (consensus, sharding, governance, recovery) has a corresponding analytic proof under standard cryptographic assumptions plus a machine-checkable TLA+ specification of its state-machine layer.

### 1.3 Document organization

Sections 2–4 establish system + threat models and describe the core consensus protocol. Sections 5–6 cover sharding architecture and the under-quorum merge mechanism. Sections 7–8 describe governance and economic primitives. Section 9 covers wallet recovery. Section 10 summarizes the formal-verification track. Sections 11–13 cover related work, limitations, and conclusion.

---

## 2. System and threat models

### 2.1 Validator set

A validator is a participant registered on-chain via a REGISTER transaction carrying:
- A 32-byte Ed25519 public key (binds the validator's identity to a cryptographic credential).
- An optional 32-byte UTF-8 region tag (in lowercase ASCII with charset `[a-z0-9-_]`), used only under EXTENDED sharding.
- Stake (under STAKE_INCLUSION) or a domain registration (under DOMAIN_INCLUSION).

Both inclusion models share the same Sybil-resistance + disincentive structure: under STAKE_INCLUSION, sybil cost is capital lock-up and disincentive is stake forfeiture; under DOMAIN_INCLUSION, sybil cost is domain registration and disincentive is deregistration. The protocol treats both identically for consensus purposes.

### 2.2 Adversary model

We consider three composable adversary capabilities:

**(C1) Byzantine validators.** A subset `F ⊆ V` of the validator set may deviate arbitrarily from the protocol — sign anything, send anything, refuse anything, or coordinate fully. Their secret keys are known to the adversary; their public keys are known to everyone.

**(C2) Network partitions.** Messages between honest validators may be delayed, reordered, or dropped, but cannot be forged (cryptographic authentication prevents impersonation). The protocol does not assume synchronous network delivery for safety; for liveness it assumes eventual delivery within bounded round timers.

**(C3) Cryptographic adversary.** A polynomial-time attacker with budget `Q` may attempt forgeries against honest signatures or preimage / collision attacks against SHA-256. Per standard cryptographic assumptions: Ed25519 EUF-CMA forgery probability is `≤ 2⁻¹²⁸ + ε_Ed25519` per attempt; SHA-256 collision finding is `≤ 2⁻¹²⁸` per attempt; SHA-256 preimage is `≤ 2⁻²⁵⁶`.

### 2.3 Safety claims under the adversary model

- **Unconditional safety** (MD-mode blocks): Determ's K-of-K committee structure means a single non-Byzantine member of any committee suffices to prevent forks at that height. This is structurally weaker than BFT's "f < N/3" assumption — it requires only `1 ≤ |V \ F|`, not `|V \ F| > 2N/3`.
- **Conditional safety** (BFT-mode blocks): when the K-of-K committee cannot complete (e.g., a member is offline), the protocol escalates to a BFT consensus mode in which the committee shrinks to `k_bft = ⌈2K/3⌉` and the within-committee 2/3 quorum `Q = ⌈2·k_bft/3⌉` suffices. Safety is now conditional on `f_h < k_bft/3` for that single block, plus economic slashing recovery for any equivocator (full stake forfeiture + deregistration).
- **Censorship resistance**: an honest validator anywhere in the K committee proposes its transaction list in phase 1; the canonical block's transaction set is the union of all K lists. Censorship requires unanimous collusion of all K members at every block where the targeted transaction is pending — `(f/|V|)^K` capture probability per epoch boundary.

The trade-offs:

| Property | MD-mode | BFT-mode |
|---|---|---|
| Safety | Unconditional (1 honest in committee suffices) | Conditional `f_h < k_bft/3` + slashing |
| Liveness | Halts on persistent silent member | Recovers with `ceil(2K/3)` available |
| Censorship | K-conjunction (`(f/N)^K`) | `(Q − 1)`-conjunction over the BFT committee (i.e., to censor a tx, the adversary must control all but at most `k_bft − Q` slots) |
| Per-block trust | Tag exposed in `block.consensus_mode` | Tag exposed in `block.consensus_mode` |

Applications choose which blocks they trust by reading the `consensus_mode` tag and the chain's per-block `block_digest`. Most steady-state blocks are MD on both layers (beacon + shards); BFT blocks are the tail-liveness fallback when the chain would otherwise stall.

---

## 3. Consensus protocol

### 3.1 Per-height protocol overview

Each block is produced in two phases by a K-member committee selected deterministically from the validator pool via the previous block's `cumulative_rand` plus an epoch-relative seed:

**Phase 1 (Contrib).** Each committee member `i` independently:
1. Selects a transaction list `tx_list_i` from its local mempool.
2. Samples a uniform random secret `secret_i` (32 bytes).
3. Commits to the secret: `dh_input_i = SHA-256(secret_i ‖ pubkey_i)`.
4. Broadcasts `ContribMsg{block_index, signer, prev_hash, aborts_gen, tx_hashes, dh_input, ed_sig}` where `ed_sig` is Ed25519 over the canonical signing bytes.

**Phase 1 → 2 transition.** Once K phase-1 commits gather:
- `tx_root` = SHA-256 over the union of all K transaction lists in canonical order.
- `delay_seed` = SHA-256 over `block_index ‖ prev_hash ‖ tx_root ‖ ordered(dh_input_1, ..., dh_input_K)` — the `dh_input`s appear in committee-selection order (i.e., `creators[i]`'s commitment at position `i`), not sorted; both producer and validator iterate the K committee members in the same fixed order so the hash matches across nodes (`src/node/producer.cpp::compute_delay_seed`).

**Phase 2 (BlockSig).** Each committee member:
1. Reveals `secret_i` via `BlockSigMsg{block_index, signer, delay_output, dh_secret, ed_sig}` where `dh_secret = secret_i`.
2. Signs `block_digest`, defined as `SHA-256` over `{index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators[], creator_tx_lists[][], creator_ed_sigs[], creator_dh_inputs[]}` — a strict subset of the full block content. Fields revealed or derived after Phase 1 are excluded (`delay_output`, `cumulative_rand`, `creator_dh_secrets`), as are evidence/receipt lists that depend on gossip-async pool views (`abort_events`, `equivocation_events`, `inbound_receipts`, `cross_shard_receipts`, `partner_subset_hash`, `timestamp`, `state_root`). The narrower-than-full coverage is the structural source of S-030 D1/D2 (see `SECURITY.md` S-030 and `docs/proofs/S030-D2-Analysis.md`); D1 is effective-closed via S-033 (state_root binding into `Block::signing_bytes` enforces apply-time consistency); D2 is partial-closed by the same mechanism, with v2.7 F2 view reconciliation tracked for full consensus-layer closure.
3. Receivers verify `SHA-256(dh_secret ‖ pubkey_i) == sender's dh_input`. Mismatch rejects the message; the committee member is treated as offline for this round.

**Finalize.** Once K block-sigs gather:
- `delay_output` = SHA-256 over `delay_seed ‖ ordered(secret_1, ..., secret_K)` — secrets appear in the same committee-selection order as their `dh_input` commitments, not sorted (`src/node/producer.cpp::compute_block_rand`).
- `cumulative_rand` = SHA-256 over `prev_cumulative_rand ‖ delay_output`.
- The block is finalized with `consensus_mode = MUTUAL_DISTRUST`.

### 3.2 Selective-abort defense

The classical attack against commit-reveal randomness is selective abort: a committee member, after seeing other reveals, refuses to reveal its own if the resulting block would be unfavorable. Determ's commit-reveal design defeats this structurally:

- `dh_input_i = SHA-256(secret_i ‖ pubkey_i)` is published before any other phase-2 message.
- `delay_seed` is computed entirely from phase-1 data — it is committed before any reveal.
- `delay_output` (and consequently `cumulative_rand`) is determined by `delay_seed ‖ ordered(secrets)`.

An adversary observing `K - 1` reveals before deciding its own action gains nothing: by SHA-256's preimage resistance, the adversary cannot predict `delay_output` without revealing its own `secret_i`. Refusing to reveal aborts the round; revealing publishes a `secret_i` that produces a `delay_output` whose distribution is uniform from the adversary's perspective (random oracle on the unrevealed secret in the random-oracle model, or `≤ 2⁻²⁵⁶` distinguishing advantage in the standard model).

Concrete-security bound: `2⁻²⁵⁶` per selective-abort attempt. See `docs/proofs/SelectiveAbort.md` (FA3) for the full proof in both the random-oracle and standard models.

### 3.3 BFT escalation

When the K-of-K committee cannot complete — typically because a member is offline or partitioned away — the round aborts. Four conditions must hold for the next round to fall back to BFT consensus (`src/node/node.cpp::start_new_round`; full spec in PROTOCOL.md §5.3):

1. `bft_enabled = true` (genesis-pinned, default `true`).
2. `total_aborts ≥ bft_escalation_threshold` (genesis-pinned, default 5; Round-1 and Round-2 aborts both count).
3. Available pool (registry minus aborted-this-height domains) has dropped below `K`.
4. Available pool is still ≥ `ceil(2K/3)`. If the pool collapses below this, the shard stalls — under EXTENDED sharding the R4 under-quorum merge mechanism may absorb the shard.

When all four hold, the round runs in BFT mode with two-level shrinkage:

- Committee size shrinks from K to `k_bft = ceil(2K/3)` (e.g., K=3 → committee of 2; K=6 → committee of 4; K=9 → committee of 6).
- Within that smaller committee, the required-signature threshold is `Q = ceil(2·k_bft/3)` — standard BFT 2/3 quorum applied to `k_bft`, **not** to the genesis K. The two values coincide only at K=3 (Q = k_bft = 2); at K=6, Q = 3 while k_bft = 4; at K=9, Q = 4 while k_bft = 6.
- A designated proposer is deterministically chosen from the committee via `proposer_idx(seed, abort_events, k_bft)` where `seed = epoch_committee_seed(epoch_rand, shard_id)` and the inputs are domain-separated by the ASCII tag `"bft-proposer"` (full algorithm in PROTOCOL.md §5.3.1). The proposer must sign; up to `k_bft − Q` other slots may carry sentinel-zero signatures.
- The block tags `consensus_mode = BFT` and `bft_proposer = <domain>`.

BFT-mode safety is conditional on `f_h < k_bft/3` (the standard BFT bound applied to the smaller BFT committee), plus economic slashing recovery for any equivocator. See `docs/proofs/BFTSafety.md` (FA5) for the conditional safety argument.

### 3.4 Equivocation slashing

An equivocation occurs when a validator signs two distinct hashes under the same registered key at the same height — provable by exhibiting both signatures. The protocol treats this **digest-agnostically**: validator V11 (`docs/proofs/Preliminaries.md` §5) only checks "two distinct hashes both verifying under the equivocator's registered Ed25519 key," so two detection paths feed the same `EquivocationEvent` channel:

- **BlockSigMsg-level (rev.8).** The committee member signs `compute_block_digest(b)` of two different block bodies at the same height. Detection: `Node::apply_block_locked` cross-block check when a duplicate-height block arrives with a different `block_hash`.
- **ContribMsg same-generation (S-006 closure).** The committee member signs `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` over two different `(tx_hashes, dh_input)` snapshots at the same `(block_index, prev_hash, aborts_gen)`. Detection: `Node::on_contrib` recomputes commitments when a same-signer duplicate arrives.

Either detection path produces an `EquivocationEvent` containing the two signatures + digests; when baked into a finalized block, the event triggers:

- **STAKE_INCLUSION chains:** full stake forfeiture (zeroes `stakes_[X].locked`) plus registry deregistration.
- **DOMAIN_INCLUSION chains:** registry deregistration (the stake is already 0).

The slashing pipeline: detection → gossip via `EQUIVOCATION_EVIDENCE` (message type 11) → pool in `pending_equivocation_evidence_` → producer includes in `block.equivocation_events` → validator verifies V11 → apply commits the slash.

Slashing soundness: an honest validator can never be slashed for equivocation. By Ed25519 EUF-CMA, forging two distinct signatures under an honest key is `≤ 2⁻¹²⁸` per attempt. The digest-agnostic V11 means the bound covers both detection paths simultaneously. See `docs/proofs/EquivocationSlashing.md` (FA6) for the full one-sided soundness argument.

---

## 4. Identity model

### 4.1 Two-tier addresses

Determ distinguishes two address classes sharing the same balance namespace:

- **Registered domains:** named on-chain via REGISTER transactions; eligible to participate in consensus committees. Identity = `(domain_name, ed25519_pubkey)` pair; the chain enforces the binding via the REGISTER transaction's signature.
- **Anonymous bearer wallets:** addresses derived from an Ed25519 public key (`addr = "0x" || hex(pubkey)`); no registration required. Any user can self-issue keys offline; the chain accepts TRANSFER transactions signed by the corresponding private key.

Both share the same balance and nonce namespace — a domain may send to a bearer wallet and vice versa. The validator's per-tx-type gate distinguishes them: REGISTER is meaningful only for domains (it creates the registry entry); STAKE/UNSTAKE/DEREGISTER require a registered domain; TRANSFER works for both.

### 4.2 Why both tiers

Real deployments have two distinct identity requirements that don't compose well into a single primitive:

- **Validators need accountability.** A misbehaving validator must be identifiable for slashing, reputation, and exit consequences. Domain registration with on-chain stake or DNS-anchored names provides this.
- **End users need fungibility + offline issuance.** A payment recipient cannot wait for on-chain registration before generating an address. Bearer wallets satisfy this requirement.

Determ's two-tier model preserves both: the validator pool is fully accountable, while end-user transfers are zero-friction. The bearer model has a natural privacy benefit (no on-chain identity), but Determ does not market this as the primary feature — anonymity comes from the bearer's choice to use a fresh key per transaction, not from any cryptographic mixer.

---

## 5. Sharding architecture

### 5.1 Beacon + shards

A sharded Determ deployment splits responsibility into a single **beacon chain** and `S` **shard chains**, each running the same two-phase commit-reveal consensus on its own state subset. The beacon is the trust anchor: it holds the validator pool, slashing records, cross-shard receipts, and epoch transitions. Shards process user transactions for accounts assigned to them.

The `ShardingMode` axis (pinned per timing profile at genesis) selects topology:

- **NONE**: single chain, no shards. Test/demo only. `chain_role = SINGLE`.
- **CURRENT**: beacon plus `S` shards; each shard's K-committee drawn from the global validator pool.
- **EXTENDED**: beacon plus `S` shards; each shard's K-committee restricted to validators whose `region` tag matches the shard's `committee_region`. `initial_shard_count ≥ 3` is enforced at genesis.

Beacon block times run at the wide-area RTT envelope (~1.5s on the global timing profile). Shard block times under EXTENDED can run at intra-region RTT (~200ms on the web profile) since each shard's K-committee is colocated.

### 5.2 Account-to-shard assignment

Account routing uses a salted SHA-256 over the address:

```
shard_id(addr) = first_8_bytes_be(SHA-256(shard_address_salt ‖ addr)) mod S
```

The `shard_address_salt` is 32 random bytes pinned at genesis. The assignment is deterministic and stable for the chain's lifetime. Users who care about latency can grind addresses for a target shard; this is application-level concern, not protocol-level.

### 5.3 Cross-shard transactions

A TRANSFER whose `to` routes to a different shard is processed in two phases:

1. **Source phase**: source shard's block apply debits `sender.balance -= (amount + fee)`. The block carries a `CrossShardReceipt` entry recording the credit owed to the destination.
2. **Destination phase**: beacon relays the receipt; destination shard's producer picks it up from `pending_inbound_receipts_` and bakes it into a future block's `inbound_receipts`. Apply credits `accounts[to].balance += amount` and inserts `(src_shard, tx_hash)` into the destination's `applied_inbound_receipts_` set (dedup).

**Atomicity property**: source debit and destination credit are temporally decoupled but cryptographically linked via `(src_shard, tx_hash)`. The destination's K-of-K committee signature certifies the inbound set; the source block's K-of-K committee signature certifies the original transfer.

The protocol's global supply invariant (A1) tracks every cross-shard flow via per-shard `accumulated_outbound_` and `accumulated_inbound_` counters; in the global cut, in-flight value is captured in a `Pending` term so total supply is closed-form at any consistent multi-shard cut. See `docs/proofs/CrossShardReceipts.md` (FA7).

### 5.4 Regional sharding (EXTENDED mode)

Under EXTENDED sharding, each shard's genesis declares a `committee_region` (lowercase ASCII, `[a-z0-9-_]`, ≤ 32 bytes — opaque to the protocol; operators choose the taxonomy). A validator declares its own region at REGISTER time via the REGISTER payload extension:

```
REGISTER payload = [pubkey: 32B] [region_len: u8] [region: utf8]
```

Empty `region_len = 0` is the backward-compat path (= global pool). The committee for shard `s` is drawn from `NodeRegistry::eligible_in_region(s.committee_region)` — the registry subset matching the shard's region tag.

The trade-off: per-shard censorship resistance becomes **regional** rather than global. Capturing one region captures that region's shards. Two compensating mechanisms keep the protocol model coherent:

- **Beacon stays global.** The trust anchor still draws from the unified pool; cross-shard receipts still pay the global beacon RTT.
- **Misclaimed regions self-correct.** A validator with poor connectivity to other in-region members aborts rounds, triggering suspension. Operators don't need to attest regions cryptographically — economic disincentive does the policing.

See `docs/proofs/RegionalSharding.md` (FA8) for the safety argument under regional pinning.

---

## 6. Under-quorum merge

### 6.1 Trigger and lifecycle

When a regional shard's eligible pool drops below `2K`, that shard temporarily merges committee operations with its modular-next neighbor `T = (S + 1) mod num_shards`. The mechanism:

- **Trigger** (v1.x: operator-driven; v1.1: beacon-auto): a `MERGE_EVENT` transaction (TxType = 7) carries `(event_type ∈ {BEGIN, END}, shard_id, partner_id, effective_height, evidence_window_start, refugee_region)` with the partner shard's region tag in the payload.
- **Validator gates**: `sharding_mode == EXTENDED`; canonical 26+region_len byte payload; `partner_id == (shard_id + 1) mod num_shards`; refugee region charset compliant; `effective_height ≥ block.index + merge_grace_blocks`; for BEGIN, evidence window lies in committed history.
- **State machine**: BEGIN inserts `(shard_id → {partner_id, refugee_region})` into `Chain::merge_state_`; END erases it. Snapshot save/restore round-trips the state.
- **Eligibility stress branch**: when this shard absorbs refugees (`Chain::shards_absorbed_by(my_shard) ≠ ∅`), the producer + validator extend their eligible pool with validators tagged in each refugee region. The validator mirrors the producer's pool extension exactly, eliminating the divergence surface.
- **Auto-revert**: a symmetric MERGE_END event reverts the partner. Default thresholds: `merge_threshold_blocks = 100`, `revert_threshold_blocks = 200` (2:1 hysteresis to bias toward stability).

### 6.2 Safety preservation across BEGIN/END

The structural argument: the stress branch widens the pool from `Pool_T` to `Pool_T ∪ Pool_S_refugees` but does not relax FA1's K-of-K signature requirement. K-of-K signatures over distinct digests still require forging an honest signature (EUF-CMA bound `2⁻¹²⁸`). Validator mirrors producer's pool extension via the same chain-side helper — no divergence.

Cross-shard receipt atomicity (FA7) is unaffected: receipt identity is `(src_shard, tx_hash)`, independent of who signed the source block. Receipts in flight across BEGIN or END boundaries are delivered exactly once via the existing dedup set.

See `docs/proofs/UnderQuorumMerge.md` (FA9) for the full safety argument.

---

## 7. Governance

### 7.1 Mode selector

Two genesis-pinned modes:

- **`governance_mode = 0` (uncontrolled, default).** Consensus constants are immutable post-genesis. Changing any of them requires a new chain identity. Suitable for permissionless deployments wanting a single stable parameter set forever.
- **`governance_mode = 1` (governed).** An N-of-N founder keyholder set may emit `PARAM_CHANGE` transactions mutating a whitelisted subset of parameters mid-chain.

The keyholder set is genesis-pinned via `param_keyholders: [PubKey ...]`. The signature threshold is `param_threshold: u32`, defaulting to N-of-N when set to 0. Both fields are mixed into the genesis hash only when non-default, preserving pre-A5 genesis files as byte-identical.

### 7.2 PARAM_CHANGE protocol

A PARAM_CHANGE transaction (TxType = 6) carries a canonical payload:

```
[name_len: u8][name: utf8]
[value_len: u16 LE][value: bytes]
[effective_height: u64 LE]
[sig_count: u8]
sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
```

Each `(keyholder_index, ed_sig)` is an Ed25519 signature over the canonical signing message `[name_len ‖ name ‖ value_len ‖ value ‖ effective_height]`. The validator gates (in order): governance mode, payload shape, name in whitelist, threshold over distinct verifying signatures.

The whitelist (validator-enforced; off-list rejected even with full N-of-N):
- `MIN_STAKE`, `SUSPENSION_SLASH`, `UNSTAKE_DELAY` — economic policy fields
- `bft_escalation_threshold` — consensus parameter
- `tx_commit_ms`, `block_sig_ms`, `abort_claim_ms` — round timer durations
- `param_keyholders`, `param_threshold` — self-referential governance metadata

Off-list parameters (committee size K, sharding mode, chain identity, crypto primitives) require a new genesis = new chain.

### 7.3 Apply-side staging + activation

A validated PARAM_CHANGE is staged at `effective_height` in `Chain::pending_param_changes_`. At the start of every subsequent `apply_transactions(b)`, `activate_pending_params(b.index)` walks pending entries with `eff_height ≤ b.index` and writes to chain instance state (for chain-local fields like MIN_STAKE) or fires a Node-installed `ParamChangedHook` (for validator-side fields like `param_keyholders`). Snapshot save/restore round-trips the pending map so snapshot-bootstrapped nodes activate at identical heights.

Soundness: unauthorized PARAM_CHANGE acceptance requires forging keyholder signatures. For N-of-N with N = 5 and adversary budget Q = 2⁶⁰, cumulative false-positive probability is `≤ 2⁻⁴⁵²` — strongly negligible. See `docs/proofs/Governance.md` (FA10).

---

## 8. Economic primitives

### 8.1 Unitary supply invariant (A1)

The chain maintains five running counters: `genesis_total`, `accumulated_subsidy`, `accumulated_slashed`, `accumulated_inbound`, `accumulated_outbound`. The closed-form invariant asserted after every `apply_transactions`:

```
Σ accounts.balance + Σ stakes.locked
  == genesis_total + accumulated_subsidy + accumulated_inbound
     - accumulated_slashed - accumulated_outbound
```

The assertion is structural (no cryptographic assumption needed). Each mutation site is paired with the corresponding counter delta; the post-apply walk catches any divergence before the block commits. Snapshot save/restore preserves the counters.

### 8.2 Block subsidy and fee distribution

Each block credits the K committee members with `total_fees + subsidy_this_block`. Dust goes to `creators[0]`. The subsidy is genesis-pinned (`block_subsidy: u64`); zero produces a fees-only chain.

### 8.3 Finite subsidy fund (E4)

Optional cap on cumulative subsidy: `subsidy_pool_initial: u64`. When non-zero, total subsidy ever paid is hard-capped; once `accumulated_subsidy_ == subsidy_pool_initial_`, subsequent blocks pay fees only. The A1 invariant holds across the exhaustion transition because the apply path tracks the actually-paid amount, not the literal `block_subsidy_`.

### 8.4 Lottery subsidy mode (E3)

`subsidy_mode = 1 (LOTTERY)` replaces FLAT distribution with a two-point draw seeded by the block's `cumulative_rand`:
- Probability `1/M` of paying `block_subsidy_ * M` (jackpot block)
- Probability `(M-1)/M` of paying 0

Expected per-block value equals FLAT subsidy — total issuance schedule unchanged. Variance trades for incentive concentration. Pairs cleanly with E4: when the pool is near exhaustion, jackpot payouts cap at remaining.

### 8.5 Negative entry fee from Zeroth pool (E1)

A pseudo-account at the canonical all-zero address `0x00…00` is seeded at genesis with `zeroth_pool_initial: u64`. The validator rejects any transaction with `from == ZEROTH_ADDRESS` — no key can sign over the all-zero pubkey, so the pool is provably unsynthesizable. A genesis with `zeroth_pool_initial = 0` disables E1 entirely.

On each **first-time** REGISTER apply for a new domain (not re-registrations / key rotations), the pool delivers a **deterministic geometric grant**:

```
if first_time_register and pool.balance > 0:
    nef = pool.balance / 2
    pool.balance       -= nef
    accounts[tx.from]  += nef
```

The mechanism is intentionally minimal: no per-registrant lottery, no per-block randomness gate, no auxiliary genesis parameter beyond `zeroth_pool_initial`. The first registrant after genesis receives half the pool; the second receives a quarter; the n-th receives `pool / 2^n` (asymptotically). Re-registrations of an existing domain (key rotation, region update) do **not** trigger the grant — the apply path checks `registrants_.find(tx.from) == registrants_.end()` before touching the pool. The pool-empty case (`pool.balance == 0 ⇒ nef == 0`) is a silent no-op; no separate disable flag is needed.

Properties:

- **Supply-preserving.** E1 is a balance transfer (pool → registrant), not a mint. The pool's initial balance is included in `genesis_total_` at the index-0 apply, so the A1 unitary-supply invariant holds trivially across the transfer.
- **Deterministic.** No randomness gate; every validator computes the same `nef` from the post-apply pool balance and the first-time-register predicate. No fork-choice ambiguity.
- **Order-sensitive payout, but provably finite.** Earlier registrants receive larger absolute grants; later registrants asymptote toward zero. The total ever distributed is bounded above by `zeroth_pool_initial`.
- **Sybil-bounded under STAKE_INCLUSION.** A sybil paying `MIN_STAKE` to receive `pool / 2^n` is economically irrational once `pool / 2^n < MIN_STAKE`. Operators choosing `MIN_STAKE` set the natural depth bound.

See `docs/proofs/EconomicSoundness.md` (FA11 T-13) for the supply-neutrality proof; `chain.cpp:821-831` for the apply-site code.

---

## 9. Wallet recovery (A2)

### 9.1 Problem

A lost Ed25519 private key today means permanent loss of the registered domain and its balance. Determ's wallet recovery primitive provides opt-in distributed seed reconstruction without weakening the chain's identity model.

### 9.2 Mechanism

Pure client-side feature implemented in a separate `determ-wallet` binary; no protocol changes. The wallet's secret material never enters the chain daemon's address space.

Setup flow:

1. Split the 32-byte Ed25519 seed `s` into `N` Shamir shares `(x_i, y_i)` over GF(2⁸) with threshold `T`.
2. For each share `i`, derive an unwrap key `k_i`:
   - **Passphrase scheme** (default in v1.x): `k_i = PBKDF2-HMAC-SHA-256(password, fresh_salt, 600000 iters)`.
   - **OPAQUE scheme**: `(record_i, export_key_i) = OPAQUE_Register(password, gid=i)`; `k_i = export_key_i`.
3. Encrypt each share via AES-256-GCM under `k_i` with fresh nonce and AAD binding `DWR1 ‖ guardian_id ‖ version`.
4. Output a self-contained JSON setup carrying the envelopes, x-coordinates, scheme tag, suite identifier, and optional pubkey checksum.

Recovery flow:

1. Dispatch by scheme tag.
2. Decrypt at least `T` envelopes via the password (passphrase) or `T` OPAQUE handshakes (OPAQUE).
3. Apply Shamir Lagrange interpolation at `x = 0` to reconstruct the seed.
4. Verify against the optional `pubkey_checksum` (defense-in-depth against AEAD false positives).

### 9.3 Layered security claims

- **Below-threshold compromise**: `T-1` shares (even with cleanly-recovered keys) reveal exactly zero bits about the secret. Information-theoretic — Shannon's measure of conditional entropy is exact.
- **Envelope tampering**: AES-256-GCM SUF-CMA gives `≤ 2⁻¹²⁸` per single-bit modification detection.
- **Password-grind defense (real OPAQUE)**: a compromised guardian's `record_i` cannot be ground offline; every guess requires fresh interaction with the (rate-limited) guardian. RFC 9807 Theorem 4.1.
- **Composite bound** under real OPAQUE: with T-1 guardian compromises + Q online attempts vs. 1 surviving guardian + 60-bit password + Q = 2¹⁶: `Pr[recovery] ≤ 2⁻⁴⁴`.

### 9.4 Phase 5 stub limitations

The v1.x release ships a stub OPAQUE adapter using libsodium's Argon2id directly. The stub is **offline-grindable** from any single compromised guardian — it does not provide OPAQUE's hallmark online-only password protection. The wallet's `is_stub()` flag gates production use. Phase 6 (real libopaque integration) is documented as multi-cycle Windows MSVC porting work in `wallet/PHASE6_PORTING_NOTES.md`. See `docs/proofs/WalletRecovery.md` (FA12) for stub-mode bound degradation.

---

## 10. Formal verification

Determ's safety-critical mechanisms have full coverage in two parallel tracks: analytic proofs against standard cryptographic assumptions, and machine-checkable state-machine specifications in TLA+.

### 10.1 FA-track (analytic proofs)

| # | File | Property | Bound |
|---|---|---|---|
| F0 | `Preliminaries.md` | Notation, validity predicates V1–V15 | — |
| FA1 | `Safety.md` | MD-mode K-of-K safety | `2⁻¹²⁸` per fork attempt |
| FA2 | `Censorship.md` | Union-tx-root censorship resistance | `(f/N)^K` per epoch |
| FA3 | `SelectiveAbort.md` | Commit-reveal hiding (ROM + std-model) | `2⁻²⁵⁶` per attempt |
| FA4 | `Liveness.md` | Bounded-round termination | Geometric in `p_honest` |
| FA5 | `BFTSafety.md` | BFT-mode conditional safety | `f_h < |K_h|/3` + slashing recovery |
| FA6 | `EquivocationSlashing.md` | No false-positive slashing | `2⁻¹²⁸` per fabrication |
| FA7 | `CrossShardReceipts.md` | No double-credit, atomicity | `K · 2⁻¹²⁸` per fabrication |
| FA8 | `RegionalSharding.md` | Properties under regional pinning | Same as FA1/FA4/FA5/FA6/FA7 |
| FA9 | `UnderQuorumMerge.md` | R4 merge preserves FA1/FA7 | `2⁻¹²⁸` per fork attempt |
| FA10 | `Governance.md` | A5 PARAM_CHANGE soundness | `Q · 2⁻¹²⁸·(N-1)` for N keyholders |
| FA11 | `EconomicSoundness.md` | A1 supply invariant + E1/E3/E4 | Structural |
| FA12 | `WalletRecovery.md` | A2 Shamir + AEAD + OPAQUE composition | `Q · 2⁻⁶⁰` real OPAQUE; offline-grindable stub |

Every proof cites its source-code enforcement points; reviewers can trace any theorem → state-machine → implementation.

### 10.2 FB-track (TLA+ specifications)

Machine-checkable state-machine projections of the consensus, sharding, and receipt-dedup mechanisms:

- `tla/Consensus.tla` — per-height K-of-K state machine with abort/BFT escalation. Invariants: one-digest-finalized, no-early-reveal, honest-no-equivocate; liveness via fair-scheduling.
- `tla/Sharding.tla` — cross-shard receipt flow with replay adversary. Invariants: no-double-credit, applied-has-origin, supply-invariant.
- `tla/Receipts.tla` — focused dedup state machine; smallest model, fastest TLC check.
- `tla/CHECK-RESULTS.md` — model-check transcripts (pending TLC installation in CI).

### 10.3 Concrete-security summary

Under standard assumptions (Ed25519 EUF-CMA, SHA-256 collision and preimage resistance, random oracle where used), every FA-track property holds with cumulative failure probability `≤ Q · 2⁻¹²⁸` over polynomial adversary budget `Q`. For `Q = 2⁶⁰`: `≤ 2⁻⁶⁸` — strongly negligible.

Under post-quantum threat (Grover's algorithm reducing collision and signature-finding to square-root cost), bounds degrade to `Q · 2⁻⁶⁴`. The protocol remains operationally secure but a post-quantum signature migration (Dilithium, Falcon) is the recommended forward path.

---

## 11. Comparison to related work

### 11.1 Nakamoto consensus (Bitcoin)

Probabilistic eventual finality via proof-of-work and longest-chain selection. Safety is asymptotic in confirmation depth; fork tails are routine. Determ inverts this: immediate unconditional finality per block, no fork tail, no proof-of-work. Trade: Determ's per-block latency is ~200ms–1.5s (committee-RTT bounded); Bitcoin's is ~10 minutes.

### 11.2 Tendermint / Cosmos / Algorand

BFT-family protocols with immediate finality conditional on `f < N/3`. Multi-round voting (typically 2–3 rounds per block) gives strong safety in expectation but allows forks when the honest supermajority assumption is violated. Determ's MD mode is structurally stronger (any single honest validator prevents forks); BFT mode is roughly equivalent but uses it as a fallback rather than the primary path.

### 11.3 Dfinity / Internet Computer

Threshold-BLS-based consensus with strong probabilistic guarantees and high throughput. Heavier cryptographic dependencies (pairing-friendly curves, threshold BLS). Determ uses only Ed25519 + SHA-256, no exotic primitives.

### 11.4 Solana

Pipeline-parallel PoS with proof-of-history. High throughput but documented occasional forks under load. Determ accepts lower throughput per shard but scales horizontally via the EXTENDED sharding mode without compromising per-block safety.

### 11.5 Ethereum (Gasper)

Hybrid finality gadget (Casper FFG) layered over a fork-choice rule (LMD GHOST). Probabilistic safety with checkpoint finality every 32 blocks. Determ trades the smart-contract platform for stronger per-block safety; the two protocols target different use cases.

The general pattern: existing protocols trade between liveness, finality latency, and economic security in standard combinations. Determ targets a less common point — unconditional safety in steady state with tagged BFT fallback — which suits payment + identity use cases but is less suitable for arbitrary computation.

---

## 12. Limitations and future work

### 12.1 Out-of-scope

The base protocol explicitly does not provide:

- Smart-contract execution (EVM, WASM, or otherwise). The protocol's value proposition is fork-free payments + identity, not arbitrary computation.
- Off-chain storage layer (IPFS-like).
- Cross-chain bridges. Could be built on top; not in the base protocol.
- Oracle networks.
- Zero-knowledge or shielded transactions. Anonymous bearer wallets are the privacy story; no ZK layer planned.

These are intentional non-goals, not roadmap items.

### 12.2 Within-scope future work

**v1.1 targeted improvements:**

- Beacon-side MERGE_EVENT auto-detection (observe `eligible_in_region < 2K` over the threshold window, emit MERGE_BEGIN automatically). v1.x ships operator-driven via `determ submit-merge-event`.
- Full S-036 witness-window historical validation. Requires SHARD_TIP records moved from gossip-only to on-chain.
- Real libopaque + liboprf vendoring for the wallet's OPAQUE adapter. Windows MSVC port of upstream VLAs is the principal blocker; four completion paths documented.

**v2 design space (canonical list in `docs/V2-DESIGN.md` — 26 items across 9 themes):**

- v2.1 State Merkle root — ✅ shipped (`compute_state_root` + `Block.state_root` + `signing_bytes` binding).
- v2.2 Light-client headers / state_proof RPC — ✅ foundation shipped (SMT inclusion-proof RPC + CLI); header-only sync flow remains as a follow-on.
- v2.3 Trustless fast sync — ✅ shipped (state_root verified on snapshot restore).
- v2.4 Atomic block apply (A9) — ✅ shipped (Phase 1-2D + COMPOSABLE_BATCH).
- v2.5 Registry cache (S-032) — ✅ shipped.
- v2.6 Gossip out of state-lock — ✅ shipped.
- A3/v2.X Binary message codec — ✅ shipped (`src/net/binary_codec.cpp`; per-pair `wire_version` negotiated via HELLO; legacy JSON remains the default until both sides advertise v1).
- v2.7 F2 view reconciliation (full S-030 D2 closure) — ⏳ spec'd in `docs/proofs/F2-SPEC.md`, ~3-4 days.
- v2.10 Threshold randomness aggregation — 🔥 active, ~1 week (BLS12-381 + DKG); defeats residual selective-abort.
- Stake-weighted creator selection — design item, parallel-representation analysis required first.
- v2.8 Post-quantum signature migration (Dilithium / Falcon) — ⏳ not started.
- v2.14 OPAQUE wallet recovery (real `libopaque`) — ⏳ not started; gated on the MSVC porting of upstream VLAs.
- v2.25 + v2.26 Distributed identity provider (DSSO) — ⏳ Theme 9 new; depends on v2.10 + v2.14.

The v2 themes cover Theme 1 (Trust minimization), Theme 2 (Scale + concurrency), Theme 3 (Cryptographic hardening), Theme 4 (Liveness + randomness), Theme 5 (Composability), Theme 6 (Wallet + operator UX), Theme 7 (DApp layer — v2.18 / v2.19 shipped), Theme 8 (Privacy + interop — v2.22 / v2.23 / v2.24), Theme 9 (DSSO — v2.25 / v2.26).

### 12.3 Network partition behavior

A partition that splits the committee blocks progress on both sides until it heals (modulo BFT escalation, which can finalize a side with `ceil(2K/3)` honest committee members). Appropriate for a financial ledger (CP, not AP). Under EXTENDED sharding, a region losing connectivity stalls cross-shard receipts; in-shard production continues.

---

## 13. Conclusion

Determ demonstrates that fork-free, immediately-final consensus is achievable at sub-second block times with only two well-known cryptographic primitives — Ed25519 and SHA-256 — without proof-of-work, multi-round voting, or a trusted leader. The two-phase Contrib + BlockSig protocol places randomness generation under a SHA-256-based commit-reveal binding, defeating selective abort by structural construction rather than economic disincentive. The union-of-committee transaction root makes inclusion a collaborative property: a single honest committee member suffices to defeat censorship.

The protocol is intentionally minimal: two consensus message types per block, one signature scheme, one hash function, no exotic cryptography or external dependencies. This makes it auditable, implementable, and amenable to formal verification of its core safety property: no two valid blocks at the same height. The v1.x specification covers consensus, sharding (CURRENT + EXTENDED with regional pinning and under-quorum merge), governance (uncontrolled + governed modes with N-of-N keyholder PARAM_CHANGE), economic primitives (block subsidy, finite-pool option, lottery distribution, negative entry fee), and distributed wallet recovery via Shamir + AEAD + OPAQUE composition.

Every safety-critical mechanism has a corresponding formal-verification proof under standard cryptographic assumptions; a parallel TLA+ specification covers the state-machine layer. The reference implementation ships in ~17 KLOC of C++ across the chain daemon and wallet binary, with 47 shell-driven integration test suites in `tools/test_*.sh` covering every protocol feature (consensus, sharding, equivocation slashing, governance PARAM_CHANGE, A1 unitary balance, A9 atomic apply, S-008 mempool bounds, S-014 rate-limit on both RPC and gossip, S-021 chain-file integrity, S-022 per-message-type caps, S-026 TCP keepalive, S-028 anon-address case normalization, v2.18 / v2.19 DApp substrate, OPAQUE wallet recovery via stub adapter, and end-to-end cross-shard transfer + under-quorum merge).

Determ's design space — unconditional safety in steady state, conditional liveness with tagged fallback — suits applications where safety failures are intolerable: inter-organization settlement, regional payment networks, federated identity registries, validator-coordinated directories. It is explicitly unsuitable for applications requiring arbitrary computation or eventual-consistency semantics. Within its target scope, it provides a strictly more conservative safety posture than BFT-family protocols at comparable latency, making it a reasonable choice for deployments where the cost of a safety failure exceeds the cost of an occasional stall.

---

## References

1. Bernstein, D. J., et al. *High-speed high-security signatures.* Journal of Cryptographic Engineering, 2012. (Ed25519)

2. National Institute of Standards and Technology. *Secure Hash Standard (SHS).* FIPS PUB 180-4, 2015. (SHA-256)

3. Lamport, L. *Specifying Systems: The TLA+ Language and Tools.* Addison-Wesley, 2002.

4. Buchman, E. *Tendermint: Byzantine Fault Tolerance in the Age of Blockchains.* M.Sc. thesis, University of Guelph, 2016.

5. Gilad, Y., et al. *Algorand: Scaling Byzantine Agreements for Cryptocurrencies.* SOSP, 2017.

6. Bonneau, J., et al. *Bitcoin and Cryptocurrency Technologies.* Princeton University Press, 2016.

7. Shamir, A. *How to Share a Secret.* Communications of the ACM, 1979. (Shamir's Secret Sharing)

8. Bourse, F., et al. *OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-computation Attacks.* EUROCRYPT, 2018.

9. Internet Research Task Force. *RFC 9807: The OPAQUE Asymmetric PAKE Protocol.* 2024.

10. Internet Research Task Force. *RFC 9497: Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups.* 2023.

11. McGrew, D., and Viega, J. *The Galois/Counter Mode of Operation (GCM).* NIST SP 800-38D, 2007. (AES-256-GCM)

12. Biryukov, A., et al. *Argon2: the memory-hard function for password hashing and other applications.* PHC, 2015.

13. Hopkinson, P., and Wagner, D. *Composition of Cryptographic Protocols.* IACR ePrint 2023/123. (Universally Composable security framework)

---

## Appendix A: Cryptographic primitives at a glance

| Primitive | Use | Reference |
|---|---|---|
| Ed25519 | Validator signatures, transaction signatures, block signatures | [1] |
| SHA-256 | Block hashes, transaction hashes, commit-reveal commitments, address derivation | [2] |
| AES-256-GCM | Wallet AEAD envelope (32-byte key, 12-byte nonce, 16-byte tag) | [11] |
| Ristretto255 | OPAQUE OPRF prime-order group | [10] |
| Argon2id | OPAQUE password stretching | [12] |
| HKDF-SHA-256 | OPAQUE AKE key derivation | [9] |
| Shamir SSS | Wallet threshold secret sharing over GF(2⁸) | [7] |

## Appendix B: Genesis configuration schema (abridged)

```
GenesisConfig {
  chain_id: string                     // operator-chosen unique identifier
  m_creators: u32                      // pool size per round
  k_block_sigs: u32                    // committee size (1 <= K <= M)
  block_subsidy: u64                   // page reward per block
  bft_enabled: bool                    // enable per-height BFT escalation
  bft_escalation_threshold: u32        // round-1 aborts before BFT fallback
  inclusion_model: enum                // STAKE_INCLUSION | DOMAIN_INCLUSION
  min_stake: u64                       // STAKE_INCLUSION threshold
  chain_role: enum                     // SINGLE | BEACON | SHARD
  sharding_mode: enum                  // NONE | CURRENT | EXTENDED
  shard_id: u32                        // 0 for SINGLE/BEACON
  initial_shard_count: u32             // 1 = unsharded; >=3 under EXTENDED
  epoch_blocks: u32                    // E (epoch-relative committee derivation)
  shard_address_salt: 32B              // address-to-shard routing salt
  committee_region: string             // EXTENDED mode pinning (lowercase ASCII)
  tx_commit_ms: u32                    // Phase-1 round timer (default per profile)
  block_sig_ms: u32                    // Phase-2 round timer
  abort_claim_ms: u32                  // abort-claim collection window
  governance_mode: u8                  // 0 = uncontrolled, 1 = governed
  param_keyholders: [PubKey ...]       // founder set (governed mode)
  param_threshold: u32                 // signature count (default N-of-N)
  suspension_slash: u64                // economic disincentive per abort
  unstake_delay: u64                   // blocks past inactive_from
  merge_threshold_blocks: u32          // R4 trigger window
  revert_threshold_blocks: u32         // R4 hysteresis on revert
  merge_grace_blocks: u32              // R4 effective-height grace period
  subsidy_pool_initial: u64            // E4 hard cap on cumulative subsidy
  subsidy_mode: u8                     // E3: 0 = FLAT, 1 = LOTTERY
  lottery_jackpot_multiplier: u32      // E3: required when LOTTERY
  zeroth_pool_initial: u64             // E1: NEF pool seed; 0 disables NEF (geometric pool/2 per first-time REGISTER)
  initial_creators: [GenesisCreator]
  initial_balances: [GenesisAllocation]
}
```

## Appendix C: Document inventory

This whitepaper is a self-contained narrative; deeper technical details are split across the documentation tree:

| Document | Audience |
|---|---|
| `README.md` | System-level overview, design rationale, scope |
| `docs/PROTOCOL.md` | Wire formats, validity predicates, message encodings |
| `docs/CLI-REFERENCE.md` | Operator command-line reference |
| `docs/QUICKSTART.md` | Hands-on operator recipes |
| `docs/SECURITY.md` | Open findings, security triage table |
| `docs/proofs/` | Formal-verification proofs (F0 + FA1–FA12, FB1–FB4) |
| `wallet/PHASE6_PORTING_NOTES.md` | libopaque integration status + completion paths |

The reference implementation lives at `src/` (chain daemon) and `wallet/` (wallet binary), totalling ~17 KLOC of C++ across both binaries plus vendored libsodium / OpenSSL. Integration tests at `tools/test_*.sh` cover every protocol feature in 47 self-contained suites; representative entries are listed in `docs/README.md` § "Behavioral test suite."
