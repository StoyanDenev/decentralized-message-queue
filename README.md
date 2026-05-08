# DHCoin: A Fork-Free Cryptocurrency with Two-Phase Sequential-Delay Co-Creation

**Version 1, rev. 7**

---

## Abstract

DHCoin is a registration-gated cryptocurrency that achieves immediate, fork-free finality through a two-phase, K-of-K unanimous co-creation protocol. Each block is produced by a deterministically rotated **K-committee** drawn from the registered creator pool. The protocol runs in two phases per block: a **Contrib phase** in which each committee member commits transaction proposals and a freshly-generated DH input under an Ed25519 signature, and a **BlockSig phase** in which each committee member, after locally evaluating a sequential **delay-hash** (T iterations of SHA-256) over the joint Phase 1 commitments, signs the resulting block digest. A block is final when all K committee Ed25519 signatures are present.

Two design choices distinguish DHCoin from prior fork-free systems:

1. **Sequentially-blinded selective abort.** The block's randomness is `R = delay_hash(seed, T)` — T iterations of SHA-256, where the seed binds every committee member's Phase 1 commitment. A committee member deciding whether to publish their Phase 1 contribution cannot pre-compute `R` because SHA-256 is inherently sequential and `T` exceeds the Phase 1 window. Selective abort — the canonical attack on aggregate-signature randomness beacons — is cryptographically defeated, not just economically discouraged.

2. **Union transaction set within the committee.** A transaction is included in block `n` if at least one committee member contributes it in Phase 1. Censorship requires every committee member to collude — a `K`-conjunction property that scales exponentially in `K`.

Identity is two-tiered: **registered domains** (named, staked, eligible to be selected as creators) and **anonymous accounts** (Ed25519-keyed bearer wallets, address-derived from public key). Both transact under the same Ed25519 signing scheme; only registered domains participate in consensus.

---

## 1. Introduction

Most blockchain consensus protocols separate block proposal from finalization. A single leader proposes a block; a committee, a validator set, or accumulated proof-of-work finalizes it. This architecture introduces either probabilistic finality (Bitcoin), multi-round voting latency (Tendermint, Ethereum PoS), or a trusted-leader failure mode (Solana, early DPoS systems).

DHCoin takes a different approach: a small committee of `K` creators co-produces every block, and each block carries `K` independently-signed authenticators. A valid block requires all `K` signatures over the same digest. There is no proposer to censor and no quorum threshold to game — the only way to prevent block production is to make at least one committee member silent, which the protocol detects and reroutes around.

The protocol's randomness is supplied by a **sequential delay-hash** — T iterations of SHA-256 — rather than an aggregate signature or a randomness beacon. The delay-hash's sequentiality is what defeats selective abort: at the moment a committee member decides whether to contribute, the resulting randomness is not yet computable, because evaluating the delay-hash takes longer than the Phase 1 window.

This design has three consequences worth highlighting:

1. **No fork-choice rule is needed.** A valid block is final by definition. Two blocks at the same height would require the same committee to sign two different digests — which honest committee members refuse to do — and a digest mismatch is detected by the missing or invalid signatures.

2. **Censorship resistance is structural.** Each committee member independently proposes transactions in Phase 1. The block's transaction root is the union of all committee proposals. A transaction is excluded only if every one of the `K` committee members colludes — probability `(f/N)^K` for adversarial fraction `f/N`.

3. **Randomness is unbiasable.** The delay-hash binds every committee member's Phase 1 commitment into the seed. Once Phase 1 closes, the randomness is determined; before Phase 1 closes, no one — including the committee — can predict it because evaluating the delay-hash takes longer than the Phase 1 window.

---

## 2. System Model

**Participants.** Two classes of participants exist:

- **Registered domains.** A node identified by a human-readable domain string. Each holds an Ed25519 keypair, registers on-chain via a REGISTER transaction, stakes at least `MIN_STAKE`, and is eligible for committee selection.
- **Anonymous accounts.** A user-side keypair. Address is derived directly from the Ed25519 public key (`0x` + 64 hex chars). Anonymous accounts may transact (TRANSFER, STAKE, etc.) but cannot be selected as creators.

Transactions from both account types are signed under Ed25519. The chain validates signatures uniformly; the only difference is consensus eligibility.

**Network assumptions.** We assume a partially synchronous network: messages are delivered within some known bound `Δ` during normal operation. The protocol tolerates periods of asynchrony by aborting and restarting rounds. Safety does not require synchrony — an invalid block is rejected regardless of message ordering.

**Adversary model.** An adversary may corrupt up to `f` of `N` registered nodes. Corrupted nodes may deviate arbitrarily from the protocol (Byzantine faults), delay messages within `Δ`, and choose which Phase 1 contributions to publish. The adversary cannot forge Ed25519 signatures or break SHA-256, and cannot evaluate the iterated SHA-256 delay-hash faster than its inherent sequential bound.

**Safety assumption.** Safety (no two valid blocks at the same height) holds unconditionally — it is enforced by the K-of-K signature requirement over the same block digest.

**Liveness assumption.** Liveness requires that at least one committee can be formed from `K` honest, online committee members. With `M_pool` registered nodes and per-node availability `(1-p)`, the probability that a specific committee is fully live is `(1-p)^K`. The committee rotates per round; persistent absence triggers suspension.

---

## 3. Data Structures

### 3.1 Node Key

```
NodeKey {
    ed_pub:    [32]byte
    priv_seed: [32]byte
}
```

A single Ed25519 keypair authenticates both transaction signing (when the registered domain is the sender) and consensus participation. Anonymous accounts hold the same shape, with `priv_seed` known only to the user.

### 3.2 Address Format

- Registered domain: the human-readable string registered on-chain (e.g., `node1`, `treasury`).
- Anonymous account: `0x` followed by the 64-hex-char Ed25519 public key.

The chain's account state is keyed by address, so registered and anonymous accounts share the same balance/nonce namespace.

### 3.3 Transaction

```
Transaction {
    type:    uint8         // TRANSFER | REGISTER | DEREGISTER | STAKE | UNSTAKE
    from:    string        // sender address
    to:      string        // recipient address (TRANSFER only)
    amount:  uint64
    fee:     uint64
    nonce:   uint64        // sequential per-account
    payload: []byte        // REGISTER: ed_pub[32]; STAKE/UNSTAKE: amount[8]
    sig:     [64]byte      // Ed25519 over signing_bytes()
    hash:    [32]byte      // SHA-256 of signing_bytes()
}
```

Nonces are sequential (account state tracks `next_nonce`), preventing replay.

### 3.4 ContribMsg (Phase 1)

```
ContribMsg {
    block_index : uint64
    signer      : string
    prev_hash   : [32]
    tx_hashes   : []Hash       // sorted ascending unique
    dh_input    : [32]         // freshly-generated, contributes to delay-hash seed
    aborts_gen  : uint64       // current_aborts.size() at sender
    ed_sig      : [64]         // Ed25519 over (idx ‖ prev_hash ‖ H(tx_hashes) ‖ dh_input)
}
```

### 3.5 BlockSigMsg (Phase 2)

```
BlockSigMsg {
    block_index : uint64
    signer      : string
    delay_output: [32]
    ed_sig      : [64]         // Ed25519 over block_digest
}
```

### 3.6 AbortClaimMsg / AbortEvent (S7)

```
AbortClaimMsg {
    block_index, round, prev_hash, missing_creator, claimer
    ed_sig : [64]
}

AbortEvent {
    round         : uint8       // 1 = Phase 1, 2 = Phase 2
    aborting_node : string
    timestamp     : int64
    event_hash    : [32]        // chained for verifiability
    claims_json   : json[]      // K-1 signed AbortClaimMsgs forming the quorum
}
```

A round aborts when `K-1` distinct committee members each broadcast an `AbortClaimMsg` against the same missing creator at the same round. The aggregated quorum is recorded as an `AbortEvent` baked into the next finalized block.

### 3.7 Block

```
Block {
    index, prev_hash, timestamp
    transactions      : []Transaction      // canonical (from, nonce, hash) order
    creators          : []string           // K committee, selection order
    creator_tx_lists  : [][]Hash           // K Phase 1 hash lists
    creator_ed_sigs   : [][64]             // K Phase 1 commit sigs
    creator_dh_inputs : [][32]             // K Phase 1 randomness contributions
    tx_root           : [32]               // root over union(creator_tx_lists)
    delay_seed        : [32]               // H(idx ‖ prev_hash ‖ tx_root ‖ dh_inputs)
    delay_output      : [32]               // R = SHA-256^T(delay_seed)
    creator_block_sigs: [][64]             // K Phase 2 Ed25519 sigs over block_digest
    abort_events      : []AbortEvent
    cumulative_rand   : [32]               // SHA-256(prev_rand ‖ delay_output)
    hash              : [32]
}
```

---

## 4. Genesis and Chain-Wide Constants

The genesis block fixes parameters that must be identical across all participants:

```
GenesisConfig {
    chain_id            : string
    m_creators          : uint64    // M_pool: registered creator pool size
    k_block_sigs        : uint64    // K: committee size per round, 1 ≤ K ≤ M_pool
    block_subsidy       : uint64    // page reward in atomic units
    delay_T             : uint64    // delay-hash iteration count (chain-wide)
    initial_creators    : []GenesisCreator
    initial_balances    : []GenesisAlloc
}
```

`k_block_sigs` is the protocol's mode-selector:

- `K = M_pool` — **strong mode**: every registered creator is on every committee. Censorship requires all `M_pool` to collude. Liveness requires all `M_pool` to be live.
- `K < M_pool` — **hybrid mode**: a rotating `K`-subset of the pool forms each committee. Censorship requires committee collusion. Liveness should tolerate `M_pool − K` silent creators via committee rotation. (See §10.4 for the v1 caveat.)

A node whose loaded `GenesisConfig.k_block_sigs` does not satisfy `1 ≤ K ≤ M_pool` refuses to start. Per-node config cannot override these chain-wide constants.

The genesis block is signed implicitly by the operator who builds it; integrity is enforced by the genesis hash, which every node pins on startup.

---

## 5. Node Registry, Stake, and Suspension

### 5.1 Registration

A node joins the eligible pool by broadcasting a REGISTER transaction whose payload is its 32-byte Ed25519 public key. The transaction is itself signed with the corresponding private key, proving possession.

Registration takes effect after a randomized 1–10 block delay derived from `(tx.hash || cumulative_rand)`. This prevents a registrant from timing entry to guarantee selection in a chosen round.

### 5.2 Stake

Eligibility additionally requires `stake[domain] ≥ MIN_STAKE`. Stake is locked on a STAKE transaction and released after an unlock window on UNSTAKE. The chain enforces `stake_table[domain]` updates atomically during block application.

### 5.3 Suspension

A registered, staked domain is **suspended** from selection if it has any Phase 1 abort against it in chain history; the suspension window grows exponentially with repeat offenses:

```
suspension_blocks(count) = min(BASE × 2^(count-1), MAX)
BASE = 10, MAX = 10000
```

Only **Phase 1** aborts (`round=1` AbortEvents) count toward suspension. Phase 2 aborts can fire on a healthy creator when its block-sig arrival is delayed past the timer (timing skew); using them would inflate false-positive suspensions and harm liveness without improving censorship guarantees. Phase 1 absence is the reliable "creator is unresponsive" signal.

---

## 6. Committee Selection

Given the registry at the chain's current height (sorted deterministically by domain), `current_aborts` for the in-flight round, and the previous block's `cumulative_rand`:

```
excluded   = {ae.aborting_node : ae in current_aborts}
available  = registry \ excluded
effective_rand = cumulative_rand
for ae in current_aborts:
    effective_rand = SHA-256(effective_rand ‖ ae.event_hash)
indices    = select_m_creators(effective_rand, |available|, K)
committee  = [available[i] : i in indices]
```

`select_m_creators` is rejection sampling with a counter — deterministic, terminates in `O(K)` for small `K/N`. Excluding aborted-this-height domains from the local pool ensures committee re-selection after an abort doesn't re-pick the same silent creator before the chain-baked suspension takes effect on the next finalized block. The validator reproduces the same selection given a block's `abort_events` field.

---

## 7. Two-Phase Consensus

### 7.1 Phase 1 — Contrib

When a node finds itself in the round's committee (and the chain is in-sync), it:

1. Snapshots its mempool: `tx_hashes = sorted(keys(tx_store))`.
2. Generates a fresh `dh_input` from a CSPRNG.
3. Computes the commit: `H(idx ‖ prev_hash ‖ H(tx_hashes) ‖ dh_input)`.
4. Signs the commit under its Ed25519 key.
5. Broadcasts `ContribMsg`.

Receiving nodes verify the signature and the message gen, store the contrib, and proceed to local delay-hash when all `K` committee contribs are present.

### 7.2 Local delay-hash

Once `K` valid contribs are accumulated, every node (regardless of whether it is a committee member) derives:

```
tx_root    = root(union(creator_tx_lists))           // union of K hash lists
delay_seed = H(idx ‖ prev_hash ‖ tx_root ‖ dh_inputs[K])
```

The delay-hash is computed in a worker thread:

```
R = delay_hash(delay_seed, T) = SHA-256^T(delay_seed)
```

`T` is the chain-wide iteration count fixed in `GenesisConfig`. SHA-256 is inherently sequential — extra cores do not parallelize it. Verification reruns the same `T` iterations (~2 ms at `T = 200k` with SHA-NI hardware acceleration), so no separate proof field is needed.

### 7.3 Latency optimizations

- **O1 piggyback.** The first node to finish its delay-hash broadcasts `BlockSigMsg`. Other nodes verify the embedded `delay_output` against their own derived seed (one rerun of `T` SHA-256 iterations); on success they cancel their in-flight worker and adopt the verified `R`. Wall-clock delay-hash cost across the cluster collapses to the fastest single node.
- **O2 async worker.** Delay-hash runs on a dedicated thread; the consensus thread continues handling gossip, mempool, and chain state.
- **O3 buffer-and-replay.** `BlockSigMsg`s arriving before local delay-hash completes are buffered and replayed once the result (own or verified peer) is available.
- **O4 Delay-driven Phase 2 timer.** Phase 2 timer fires from `min(local_delay_done_time, peer_R_arrival_time) + block_sig_ms`, not from a fixed wall-clock budget.
- **O5 round pipelining.** Round `n+1`'s Phase 1 starts immediately after applying block `n` locally; previous-round gossip propagation continues in parallel.
- **O7 own-Contrib pre-publish.** A creator's own Phase 1 contribution can be assembled and broadcast as soon as `prev_hash` is known, eliminating own-side latency from the Phase 1 budget.

### 7.4 Phase 2 — BlockSig

Each committee member, having computed (or verified-from-peer) `R`, signs `block_digest = H(idx ‖ prev_hash ‖ tx_root ‖ delay_seed ‖ delay_output)` under its Ed25519 key and broadcasts `BlockSigMsg`.

When all `K` BlockSig messages are present, any node assembles the canonical block body (transactions resolved deterministically from `union(creator_tx_lists)` and the local mempool, sorted by `(from, nonce, hash)`) and applies it.

### 7.5 Abort

If Phase 1's `tx_commit_ms` timer fires before all `K` contribs arrive, every committee member who has its own contrib but not the missing creator's broadcasts an `AbortClaimMsg` against the missing creator. When `K-1` distinct claims are gathered locally (an `AbortEvent`), the round restarts: `current_aborts` grows, the committee is re-selected with the missing creator excluded, and Phase 1 begins anew.

If Phase 2's `block_sig_ms` timer fires with fewer than `K` sigs, an analogous claim quorum forms (`round=2`), but does not contribute to suspension (§5.3).

---

## 8. Block Validation

A node receiving a block verifies:

1. `prev_hash` matches the local chain head.
2. `creators` is exactly the deterministic K-committee derived from `prev.cumulative_rand`, `b.abort_events`, and the registry — using the exclude-mixed selection of §6.
3. Each `creator_ed_sigs[i]` is a valid Ed25519 signature over the Phase 1 commit, by `creators[i]`'s registered key.
4. `tx_root` equals `root(union(creator_tx_lists))`.
5. `delay_seed` equals `H(idx ‖ prev_hash ‖ tx_root ‖ creator_dh_inputs)`.
6. `delay_hash_verify(delay_seed, T, delay_output)` succeeds — i.e., re-running `T` SHA-256 iterations on `delay_seed` yields `delay_output`.
7. Each `creator_block_sigs[i]` is a valid Ed25519 signature over `block_digest` by `creators[i]`'s registered key.
8. Each `AbortEvent` carries a valid `K-1` quorum of signed `AbortClaimMsg`s, with claimers drawn from the at-event committee (reconstructed by the same exclude-mixed rule).
9. Transactions are valid against the running balance/nonce model in canonical order.
10. `cumulative_rand` equals `H(prev.cumulative_rand ‖ delay_output)`.
11. `timestamp` is within `±30 s` of the local clock.

Steps 2, 3, 6, and 7 together guarantee fork-freedom: producing two valid blocks at the same height would require the same committee to sign two different digests, which any honest committee member refuses; or differing committees, which would each fail step 2 against the deterministic selection.

---

## 9. Page Reward and Fees

Every applied block credits the genesis-pinned `block_subsidy` (the **page reward**) split evenly across the committee:

```
per_creator_subsidy = block_subsidy / K
```

Plus the committee splits the block's transaction fees identically. Subsidy and fee credits land in the creator's domain account at apply time, atomically with the rest of the block's state transition.

Subsidy is a fixed integer set at genesis — not a curve. Operators choose the subsidy at chain creation; changing it requires a hard fork.

---

## 10. Security Analysis

### 10.1 Fork freedom

Producing two valid blocks at the same height requires either:

- The same committee to produce two different digests, then sign each `K`-times — impossible if any committee member is honest, since an honest member signs at most one digest per height; or
- Differing committees at the same height — impossible by determinism of selection given identical predecessor state.

Therefore at most one valid block exists at any height.

### 10.2 Censorship resistance

A transaction is omitted from block `n` only if every one of the `K` committee members fails to include it in their Phase 1 contribution. Under uniform adversarial fraction `f/N`:

```
P(tx censored in round n) ≈ (f/N)^K
```

With `K = 3` and `f/N = 0.10`: `P ≈ 10⁻³` per round. Since the committee rotates per round, persistent censorship is exponentially unlikely.

### 10.3 Selective abort defense (sequential delay-hash)

A naive aggregate-signature randomness beacon (e.g., the rev.1 BLS design) is vulnerable to **selective abort**: a committee member could compute the resulting `R` from a candidate Phase 1 set, decide whether `R` favors them, and choose whether to publish their share — biasing future selection.

DHCoin defeats this with a sequential delay-hash binding:

- The seed includes every `dh_input` from every committee member.
- A committee member deciding whether to publish their contribution would need to compute `R = SHA-256^T(seed)` for each candidate `dh_input` to evaluate the choice.
- SHA-256 chains are inherently sequential: arbitrary parallelism does not speed up a single chain. An attacker with extra cores cannot evaluate `R` faster than a single CPU executing `T` iterations in series.
- `T` is set so `T_delay ≥ 2 × T_phase_1`. Within the Phase 1 window, an attacker can complete fewer than 0.5 candidate evaluations on average — far less than 1 useful trial.

| `T_delay / T_phase_1` | Grinding attempts per round | Selective-abort feasibility |
|---|---|---|
| 0.5 | 2 | Real |
| 1.0 | 1 | Marginal |
| 2.0 | 0.5 | Acceptable |
| 5.0 | 0.2 | Negligible |

The default profile sets `T_delay = 2 × tx_commit_ms`, giving the "Acceptable" row above.

A note on terminology: this primitive resembles a "verifiable delay function" (VDF) in spirit, but lacks the succinct-verify property of true VDFs (Wesolowski/Pietrzak class-group constructions). Verification reruns all `T` SHA-256 iterations rather than checking a `O(log T)` proof. This trade is deliberate: succinct verify is a *performance* feature, not a *security* feature. The selective-abort defense depends only on **sequentiality**, which iterated SHA-256 provides without exotic cryptography or external dependencies. Verifier cost at `T = 200k` is ~2 ms with SHA-NI hardware acceleration — negligible for a full node. Solana's Proof of History uses the same primitive for an analogous purpose.

### 10.4 Liveness

**Strong mode (`K = M_pool`).** Every committee is the entire pool. A single silent creator triggers an abort. Suspension thereafter excludes the silent creator and the chain proceeds with `K-1` healthy creators if the chain operator has set `K = M_pool - 1` (rare in strong mode). In practice strong mode requires every `M_pool` to be alive.

**Hybrid mode (`K < M_pool`).** Each round selects `K` of `M_pool`. The design intent is to tolerate `M_pool − K` silent creators by rotating around them — a Phase 1 abort against a silent creator excludes them locally (§6), and once a block finalizes the abort baked in, suspension kicks in chain-wide.

**v1 caveat.** Hybrid mode in the current implementation is structurally complete (selection, exclusion, abort certs, validator symmetry) but does not yet deliver its full liveness benefit. Phase 2 finalization for `K < M` is fundamentally racy without a designated proposer: different peers can collect different `K`-subsets of signatures and produce divergent (but each individually valid) blocks at the same height. The current implementation requires all `K` Phase 2 signatures to finalize a block, treating hybrid mode as operationally equivalent to strong mode within the committee. The genesis-pinned `K < M_pool` parameter is preserved for forward compatibility; the proposer rotation or fork-choice logic that activates hybrid liveness is a v2 deliverable.

For production v1 deployments, use strong mode (`K = M_pool`).

### 10.5 Censorship vs. liveness, side by side

| Mode | K | Censorship requires | Liveness requires (v1) |
|---|---|---|---|
| Strong | M_pool | All M_pool collude | All M_pool live |
| Hybrid | K < M_pool | All K committee collude | All K committee live (v1); M_pool − K silent tolerated (v2) |

---

## 11. Identity Model

### 11.1 Domains (registered, named)

A domain registers via REGISTER with its Ed25519 public key. Domains are listed in chain state and can be inspected by any observer. Domains may stake to become eligible creators; they may also transact (TRANSFER, etc.) under the same key.

### 11.2 Anonymous accounts (bearer wallets)

An anonymous account is a user-side keypair whose address is `0x` followed by the 64-hex Ed25519 public key. The user generates the keypair locally and keeps the private key on their own device. The address is not registered on-chain — it appears in chain state only when first credited (e.g., via TRANSFER).

The CLI exposes:

- `dhcoin account create` — generates `{address, privkey}`.
- `dhcoin send_anon <to> <amount> <privkey>` — signs a TRANSFER offline and submits via any node's `submit_tx` RPC.

Anonymous accounts cannot be selected as creators (consensus requires registered domains), but they can receive arbitrary credits and transfer them under bearer-wallet semantics: possession of the private key is full authority.

This separation provides:

- **Fungibility for end-users** without on-chain registration overhead.
- **Auditability for operators**: domains have stable, named identities for governance.
- **Censorship resistance for transfers**: the union-tx-set property applies equally to anonymous transactions.

---

## 12. Network Protocol

### 12.1 Message Types

| Type | ID | Direction | Purpose |
|---|---|---|---|
| HELLO | 0 | peer → peer | Announce domain and listen port |
| BLOCK | 1 | broadcast | Complete finalized block |
| TX | 2 | broadcast | Unconfirmed transaction |
| BLOCK_SIG | 3 | broadcast | Phase 2: signed block digest + delay-hash output |
| CONTRIB | 4 | broadcast | Phase 1: TxCommit + DhInput + Ed25519 sig |
| ABORT_CLAIM | 5 | broadcast | S7 Phase-1/2 abort claim (signed) |
| GET_CHAIN | 6 | peer → peer | Request chain sync from index |
| CHAIN_RESPONSE | 7 | peer → peer | Chain sync chunk |
| STATUS_REQUEST/RESPONSE | 8/9 | peer → peer | Sync state probe |

### 12.2 Wire Format

All messages are length-prefixed JSON over TCP:

```
[4 bytes BE length][JSON payload]
```

The JSON envelope carries a `type` discriminator. A binary codec (S8) is on the v2 roadmap.

### 12.3 Gossip

All messages broadcast to all directly connected peers. Receiver-side dedup: blocks by `index` (`b.index < chain_.height()` skips silently); contribs by signer; block-sigs by signer. Cross-generation contribs (`aborts_gen` mismatch) are rejected.

### 12.4 Sync Mode (M12)

A node behind on chain state enters SYNC mode: it does not contribute to consensus, requests `GET_CHAIN` from peers, applies received chunks, and only re-enters `IN_SYNC` once it matches the network's head. This prevents a stale node from acting as a creator and disrupting the live committee.

---

## 13. Implementation Parameters

| Parameter | Default | Notes |
|---|---|---|
| `m_creators` (M_pool) | 3 (web profile) | Genesis-pinned |
| `k_block_sigs` (K) | 3 (= M_pool, strong) | Genesis-pinned |
| `block_subsidy` | 10 (atomic) | Genesis-pinned, page reward |
| `delay_T` | 200000 (web profile) | Genesis-pinned, iteration count |
| `tx_commit_ms` | 200 | Phase 1 timer |
| `block_sig_ms` | 200 | Phase 2 timer |
| `abort_claim_ms` | 100 | Abort claim collection window |
| `MIN_STAKE` | 100 | Eligibility threshold |
| `BASE_SUSPENSION_BLOCKS` | 10 | First-offense suspension |
| `MAX_SUSPENSION_BLOCKS` | 10000 | Cap |
| `MAX_ABORT_EXPONENT` | 10 | Backoff cap |
| `REGISTRATION_DELAY_WINDOW` | 10 blocks | Activation jitter |

### 13.1 Timing profiles

| Profile | tx_commit_ms | T_delay (wall) | block_sig_ms | abort_claim_ms | target block time |
|---|---|---|---|---|---|
| cluster (LAN) | 50 | 100 | 50 | 25 | ~225 ms |
| web (default) | 200 | 400 | 200 | 100 | ~900 ms |
| regional | 300 | 600 | 300 | 150 | ~1.4 s |
| global | 600 | 1200 | 600 | 300 | ~2.7 s |

`T_delay ≈ 2 × tx_commit_ms` per profile maintains the selective-abort safety factor. With O1 piggyback active, real-world block time approaches `T_phase_1 + fastest_node_T_delay + 2 × RTT`.

---

## 14. Comparison with Related Work

### 14.1 Bitcoin (Nakamoto Consensus)

PoW longest-chain. Probabilistic finality, energy-intensive, fork-prone. DHCoin is registration-gated, immediately final, fork-free.

### 14.2 Ethereum (Gasper)

PoS with 2/3+ attester finality over ~12.8 minutes. DHCoin finalizes per block (~900 ms web profile). Ethereum tolerates per-validator faults; DHCoin's K-of-K does not, but achieves stronger censorship resistance through union tx set.

### 14.3 Tendermint / Cosmos

2/3+ vote in a two-phase commit. Single proposer per round is a censorship bottleneck; DHCoin's union-of-K is not.

### 14.4 Algorand

VRF sortition + BA* over ~3.7 s. Tolerates `f < N/3` Byzantine. DHCoin's per-round committee is much smaller (`K`, typically 3) but every member must contribute — censorship requires unanimity within the committee.

### 14.5 Dfinity / Internet Computer

Threshold BLS beacon + ranked leader model. DHCoin has no leader; all `K` committee members are co-equal. DHCoin uses an iterated-SHA-256 delay-hash (not threshold BLS) for randomness, which avoids the selective-abort vulnerability inherent to aggregate-signature beacons.

### 14.6 Solana

Iterated-SHA-256 PoH for sequencing + Tower BFT for finality lagging by ~32 slots. DHCoin uses the same primitive (iterated SHA-256) but for per-block randomness rather than continuous sequencing, and achieves single-slot finality.

---

## 15. Limitations and Future Work

**Hybrid-mode liveness (v2).** As §10.4 notes, `K < M_pool` does not yet deliver `M_pool − K` silent-tolerance under Phase 2 timing skew. v2 will add a designated proposer per round (or fork-choice with bounded reorg) to make hybrid mode operationally tolerate creator drops.

**Stake-weighted selection.** v1 selects creators uniformly from the stake-eligible pool. Stake-weighted selection (proportional to bonded stake) is a natural extension for production deployments.

**Sharding / parallel execution.** Transactions execute serially in canonical order. Throughput is bounded by single-threaded validation. Parallel validation with conflict detection is future work.

**Network partition behavior.** A partition that splits the committee blocks progress on both sides until it heals. Appropriate for a financial ledger (CP, not AP).

**Binary wire codec (S8).** Current JSON-over-TCP is convenient but verbose. v2 will introduce a binary message codec for bandwidth efficiency.

---

## 16. Conclusion

DHCoin demonstrates that fork-free, immediately-final consensus is achievable at sub-second block times with just two well-known cryptographic primitives — Ed25519 and SHA-256 — without proof-of-work, multi-round voting, or a trusted leader. The two-phase Contrib + BlockSig protocol places randomness generation under a sequential delay-hash (iterated SHA-256), defeating selective abort by construction rather than by economic disincentive. The union-of-committee transaction root makes inclusion a collaborative property: a single honest committee member suffices to defeat censorship.

The two-tier identity model — registered domains for consensus, anonymous accounts for transfers — preserves both governance auditability and end-user fungibility under one unified Ed25519 signature scheme.

The protocol is intentionally minimal: two consensus message types per block, one signature scheme, one hash function, no exotic cryptography or external dependencies. This makes the protocol auditable, implementable, and amenable to formal verification of its core safety property: no two valid blocks at the same height.

---

## References

1. Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System." 2008.
2. Buterin, V. et al. "Combining GHOST and Casper." 2020.
3. Gilad, Y. et al. "Algorand: Scaling Byzantine Agreements for Cryptocurrencies." SOSP 2017.
4. Kwon, J. "Tendermint: Consensus without Mining." 2014.
5. Hanke, T., Movahedi, M., Williams, D. "DFINITY Technology Overview Series, Consensus System." 2018.
6. Yakovenko, A. "Solana: A new architecture for a high performance blockchain." 2018.
7. Boneh, D., Bonneau, J., Bünz, B., Fisch, B. "Verifiable Delay Functions." CRYPTO 2018. (Theoretical context for sequential-delay primitives. DHCoin's iterated SHA-256 satisfies the sequentiality requirement without the succinct-verify property of true VDFs.)
