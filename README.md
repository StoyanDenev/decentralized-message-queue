# Determ: A Fork-Free Cryptocurrency with Two-Phase Co-Creation

**Version 2** · [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Scope, briefly:** Determ is a **base-layer fork-free L1 payment + identity chain** with mutual-distrust safety. It is **not** a DApp hosting platform — there is no smart-contract execution layer (no EVM, no WASM, no gas), no off-chain storage integration, no bridges. Native transaction types are TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE — that's it. The full breakdown of what fits and what doesn't is in [§17 Scope](#17-scope).
>
> **For operators:** see [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for a 5-minute walkthrough and [`docs/CLI-REFERENCE.md`](docs/CLI-REFERENCE.md) for the full command list.
>
> **For protocol researchers / auditors:** see [`docs/WHITEPAPER-v1.x.md`](docs/WHITEPAPER-v1.x.md) for the standalone academic-style technical paper, and [`docs/proofs/`](docs/proofs/README.md) for the formal-verification track (F0 + FA1–FA12 analytic proofs, FB1–FB4 TLA+ specs).
>
> **What's new in v2:** sharding gains a `ShardingMode` switch — `CURRENT` keeps the v1 1-beacon-S-shards topology, while `EXTENDED` enables latency-grouped regional shard committees that drop in-shard block time to cluster-profile (~125-250 ms) on the public internet. Each profile (cluster / web / regional / global, plus sub-30 ms `_test` variants for CI) pins both a `chain_role` and a `sharding_mode`; there are no separate CLI overrides for either. Selective-abort defense is now commit-reveal (information-theoretic — no wall-clock delay function, no `delay_T` parameter to calibrate).

---

## Abstract

Determ is a registration-gated cryptocurrency that achieves immediate, fork-free finality through a two-phase, K-of-K unanimous co-creation protocol. Each block is produced by a deterministically rotated **K-committee** drawn from the registered creator pool. The protocol runs in two phases per block: a **Contrib phase** in which each committee member commits transaction proposals plus a Phase-1 commitment to a fresh per-round secret (`SHA256(secret ‖ pubkey)`) under an Ed25519 signature, and a **BlockSig phase** in which each member reveals their secret alongside an Ed25519 signature over the block digest. A block is final when all K committee signatures are present and all K secrets verify against the Phase-1 commitments.

Two design choices distinguish Determ from prior fork-free systems:

1. **Commit-reveal selective-abort defense.** The block's randomness `R = SHA256(delay_seed ‖ ordered_secrets)` is committed-then-revealed: in Phase 1 every committee member commits to a 32-byte secret via `SHA256(secret ‖ pubkey)`; in Phase 2 they reveal. A committee member deciding whether to publish their Phase 1 commitment cannot predict `R` because the other K−1 secrets are still uniformly random under SHA-256 preimage resistance. Selective abort — the canonical attack on aggregate-signature randomness beacons — is cryptographically defeated, not just economically discouraged.

2. **Union transaction set within the committee.** A transaction is included in block `n` if at least one committee member contributes it in Phase 1. Censorship requires every committee member to collude — a `K`-conjunction property that scales exponentially in `K`.

Identity is two-tiered: **registered domains** (named, staked, eligible to be selected as creators) and **anonymous accounts** (Ed25519-keyed bearer wallets, address-derived from public key). Both transact under the same Ed25519 signing scheme; only registered domains participate in consensus.

---

## 1. Introduction

Most blockchain consensus protocols separate block proposal from finalization. A single leader proposes a block; a committee, a validator set, or accumulated proof-of-work finalizes it. This architecture introduces either probabilistic finality (Bitcoin), multi-round voting latency (Tendermint, Ethereum PoS), or a trusted-leader failure mode (Solana, early DPoS systems).

Determ takes a different approach: a small committee of `K` creators co-produces every block, and each block carries `K` independently-signed authenticators. A valid block requires all `K` signatures over the same digest. There is no proposer to censor and no quorum threshold to game — the only way to prevent block production is to make at least one committee member silent, which the protocol detects and reroutes around.

The protocol's randomness is supplied by a **commit-reveal protocol** rather than an aggregate signature or a randomness beacon. Phase 1 seals each member's contribution to `R` under a SHA-256 commitment; Phase 2 reveals. At the moment a committee member decides whether to contribute, the K−1 other secrets are still uniformly random — preimage resistance makes `R` unpredictable until reveals gather, defeating selective abort.

This design has three consequences worth highlighting:

1. **No fork-choice rule is needed.** A valid block is final by definition. Two blocks at the same height would require the same committee to sign two different digests — which honest committee members refuse to do — and a digest mismatch is detected by the missing or invalid signatures.

2. **Censorship resistance is structural.** Each committee member independently proposes transactions in Phase 1. The block's transaction root is the union of all committee proposals. A transaction is excluded only if every one of the `K` committee members colludes — probability `(f/N)^K` for adversarial fraction `f/N`.

3. **Randomness is unbiasable.** Each member's Phase 1 commitment is sealed before any reveals; the K-of-K finalization gate ensures all K secrets are revealed together (or none, in which case the round aborts). No member can adapt their secret to the Phase-1 commitments of others — they were chosen first.

---

## 2. System Model

**Participants.** Two classes of participants exist:

- **Registered domains.** A node identified by a human-readable domain string. Each holds an Ed25519 keypair, registers on-chain via a REGISTER transaction, stakes at least `MIN_STAKE`, and is eligible for committee selection.
- **Anonymous accounts.** A user-side keypair. Address is derived directly from the Ed25519 public key (`0x` + 64 hex chars). Anonymous accounts may transact (TRANSFER, STAKE, etc.) but cannot be selected as creators.

Transactions from both account types are signed under Ed25519. The chain validates signatures uniformly; the only difference is consensus eligibility.

**Trust model — zero-trust system, mutual-distrust environment.** Determ is a **zero-trust system internally**. The protocol itself assumes nothing about any participant's honesty, intent, or alignment with chain progress. It only enforces rules: verify signatures, run the consensus state machine, propagate messages. No participant — including beacons, validators, users, or operators — is granted any trust by the protocol. Every actor is treated as potentially adversarial.

**All trust comes from outside the system, never from within it.** External observers (users, regulators, auditors) may form their own beliefs about specific validators based on external evidence — public domain identity, off-chain reputation, regulatory accountability, code review of the validator software, etc. — and those beliefs may inform the observer's choice of which chain to use, which validators to peer with, which blocks to consider final beyond protocol guarantees. But none of those external beliefs are encoded into the protocol. The protocol works identically whether observers trust validators or not.

Determ contrasts here with classic BFT protocols (Tendermint, HotStuff, PBFT) that assume participants pursue a **common goal** — *advance the chain* — and bound the fraction that can defect from that goal (typically `f < N/3`). BFT framings smuggle a soft trust assumption into the protocol: "≥2/3 of validators want the chain to function." Determ assumes nothing of the kind. **Validators have no common goal.** Each is a self-interested actor pursuing its own block reward. They do not cooperate voluntarily; they cooperate **involuntarily and only at the moment of block propagation**, because the protocol's K-of-K and union-tx-root rules make individual defection either rewardless (no share of the block) or impotent (a refusal to include a tx is overridden by anyone else who does include it).

This is "mutual distrust" — every validator watches every other, assumes every other is potentially adversarial, and the protocol is robust *because* the rules align self-interested behavior into chain progress without requiring shared intent.

### 2.1 The actual decentralization threshold

Determ's safety + censorship-resistance properties hold **as long as at least one validator in the registry is non-Byzantine**:

- **At least 1 non-Byzantine validator anywhere in the registry → mutual-distrust environment.** The K-of-K committee rotates over time, so a single non-Byzantine validator eventually appears on any committee. Their Phase 1 contribution unions any censored tx into the block (mutual inclusion). Their refusal to sign malformed proposals is a veto on those they reject (mutual veto). The chain stays open and uncensored.
- **0 non-Byzantine validators (100% adversarial capture) → fully controlled adversarial network.** No protocol provides safety in this case — the attacker controls every committee member at every height and can produce any block they want. This is the universal limit beyond which no consensus protocol can function. Determ makes no claim here.

Two important caveats on this threshold:

1. **"Non-Byzantine" is not "honest."** The protocol doesn't require *anyone* to be honest in any moral sense — it only requires that *some* participant follows protocol rules (for whatever reason: self-interest, regulation, mistake, ethics). Following the protocol is rationally cheaper than deviating, so the property holds even under fully self-interested rational actors.
2. **The threshold is a property of the system, not a protocol assumption.** The protocol does not *believe* that ≥1 validator is non-Byzantine — it doesn't believe anything. The threshold is what an *external observer* needs to assume in order to expect the chain to remain useful. If the observer doesn't believe even ≥1 validator follows the protocol, they don't use the chain. That choice happens outside the system.

The "honest minority" tolerance most BFT protocols celebrate (`f < N/3`) is **strictly weaker** than what Determ's K-of-K + union model achieves: Determ tolerates `f < N` (one non-Byzantine validator in the entire registry suffices for safety + censorship resistance), at the cost of giving up `f < N/3` liveness (a single Byzantine in the *committee* can halt that round, mitigated by rotation + BFT escalation in §10.4).

### 2.2 The three structural properties

The mutual-distrust model rests on:

1. **Mutual veto via K-of-K signatures.** A block requires every committee member to sign the same digest. Any single member can refuse — they cannot unilaterally produce a block, but they also cannot unilaterally allow a malformed one. Refusal is detectable (Phase 1 absence triggers an `AbortClaimMsg` quorum, recorded as an `AbortEvent` in the next block) and economically costly (suspension + slashing).

2. **Mutual inclusion via union tx_root.** A transaction enters the block if **any** committee member contributes it in Phase 1 — not just a majority. To censor a transaction, every member must omit it; a single defector breaks the censorship. Defection is the rational individual choice (a defector who includes the tx earns its fee and avoids being implicated in censorship). The K-way unanimous collusion required to censor is fragile because each colluder has standing incentive to defect.

3. **No predictability of consequence.** The block's randomness `R = SHA256(delay_seed ‖ ordered_secrets)` is computed only once K Phase-2 reveals gather. In Phase 1, each member only sees others' commitments `SHA256(secret_j ‖ pubkey_j)`; under SHA-256 preimage resistance the underlying secrets remain uniformly random. A committee member deciding whether to participate cannot compute whether participation favors them — selective abort is cryptographically defeated.

### 2.3 Trade-off vs. BFT

Determ gives up `f < N/3` Byzantine *liveness* tolerance — a single silent committee member halts the round (in strong mode; BFT escalation in §10.4 falls back to `ceil(2K/3)` after threshold aborts). In return it gets:
- **Stronger censorship resistance** — `(f/N)^K` per round, exponential in K, no leader bottleneck.
- **Unconditional fork-freedom** — no fork-choice rule needed; K-of-K signatures over the same digest at the same height are unforgeable.
- **Lower honest-fraction requirement** — `≥1 of N` honest, not `≥2/3 of N` honest, for the chain to remain useful.
- **Clean economic story** — every participant pursues block rewards. Deviation either earns no reward (refusal → no share), gets slashed (equivocation → forfeit), or is futile (censorship → defected by any honest member). No "honest majority assumption" is bolted on.

**Network assumptions.** We assume a partially synchronous network: messages are delivered within some known bound `Δ` during normal operation. The protocol tolerates periods of asynchrony by aborting and restarting rounds. Safety does not require synchrony — an invalid block is rejected regardless of message ordering.

**Adversary model.** Concretely, an adversary may control any subset of `N` registered nodes (no fraction bound assumed for safety). Corrupted nodes may deviate arbitrarily from the protocol, delay messages within `Δ`, and choose which Phase 1 contributions to publish. The adversary cannot forge Ed25519 signatures or break SHA-256 (preimage or collision resistance). Liveness — but not safety — degrades as adversary fraction approaches 100%.

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
    dh_input    : [32]         // SHA256(secret_i ‖ pubkey_i) — Phase-1 commitment to the per-round secret
    aborts_gen  : uint64       // current_aborts.size() at sender
    ed_sig      : [64]         // Ed25519 over (idx ‖ prev_hash ‖ H(tx_hashes) ‖ dh_input)
}
```

### 3.5 BlockSigMsg (Phase 2)

```
BlockSigMsg {
    block_index : uint64
    signer      : string
    delay_output: [32]         // SHA256(delay_seed) at this stage; final R recomputed once K secrets gather
    dh_secret   : [32]         // Phase-2 reveal — must satisfy SHA256(dh_secret ‖ signer.pubkey) == sender's Phase-1 dh_input
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
    creators          : []string           // committee, selection order
    creator_tx_lists  : [][]Hash           // K' Phase 1 hash lists
    creator_ed_sigs   : [][64]             // K' Phase 1 commit sigs
    creator_dh_inputs : [][32]             // K' Phase 1 commitments to per-round secrets
    creator_dh_secrets: [][32]             // K' Phase 2 revealed secrets (each verified against the matching dh_input)
    tx_root           : [32]               // root over union(creator_tx_lists)
    delay_seed        : [32]               // H(idx ‖ prev_hash ‖ tx_root ‖ dh_inputs)
    delay_output      : [32]               // R = SHA256(delay_seed ‖ ordered_dh_secrets)
    consensus_mode    : uint8              // 0 = MUTUAL_DISTRUST (K-of-K), 1 = BFT
    bft_proposer      : string             // empty in MD blocks
    creator_block_sigs : [][64]            // K' Phase 2 Ed25519 sigs over block_digest
    abort_events       : []AbortEvent
    equivocation_events: []EquivocationEvent  // baked evidence; apply slashes equivocator's stake (§15)
    cross_shard_receipts: []CrossShardReceipt // outbound receipts for off-shard `to` (§16.4)
    inbound_receipts   : []CrossShardReceipt  // inbound receipts credited by this block; exactly-once on (src_shard, tx_hash)
    initial_state      : []GenesisAlloc       // genesis only (index == 0); seeds account / stake / registry tables
    cumulative_rand    : [32]               // SHA-256(prev_rand ‖ delay_output)
    hash               : [32]
}
```

`K'` is the committee size for this block:
- `K' = K` (genesis-pinned `k_block_sigs`) for MD blocks (steady state).
- `K' = ceil(2K/3)` for BFT blocks (per-height escalation; see §10.4).

In MD blocks every position in `creator_block_sigs` carries a real Ed25519 signature (K-of-K). In BFT blocks up to `K' - ceil(2K'/3)` positions may carry the all-zero `Signature{}` sentinel (proposer-led `ceil(2K'/3)`-of-K' threshold, see §10.4). `bft_proposer` is the deterministically-chosen committee member who finalized the block; in MD blocks it is empty.

### 3.7.1 Block hash composition

`block.hash = SHA-256(signing_bytes ‖ creator_block_sigs)` where `signing_bytes` is the SHA-256 of the following ordered sequence (per `Block::signing_bytes` in `src/chain/block.cpp`):

```
index ‖ prev_hash ‖ timestamp ‖
SHA-256(transactions[].signing_bytes()) ‖
creators[] ‖ creator_tx_lists[] ‖ creator_ed_sigs[] ‖
creator_dh_inputs[] ‖ creator_dh_secrets[] ‖
tx_root ‖ delay_seed ‖ delay_output ‖
consensus_mode ‖ bft_proposer ‖ cumulative_rand ‖
abort_events[].event_hash ‖
equivocation_events[] ‖ cross_shard_receipts[] ‖ inbound_receipts[] ‖
initial_state[]
```

This is broader than `block_digest` (§7.4), which is what committee members sign in Phase 2. `block_digest` excludes `delay_output` and `creator_dh_secrets` so members can sign at Phase-2 entry without waiting for the K reveals to gather; `signing_bytes` includes them so the final block identity uniquely binds the post-reveal randomness output.

---

## 4. Genesis and Chain-Wide Constants

The genesis block fixes parameters that must be identical across all participants:

```
GenesisConfig {
    chain_id            : string
    m_creators          : uint64    // M_pool: registered creator pool size
    k_block_sigs        : uint64    // K: committee size per round, 1 ≤ K ≤ M_pool
    block_subsidy       : uint64    // page reward in atomic units
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

### 5.1 Inclusion models

Determ supports two genesis-pinned validator-inclusion policies. Both deliver **identical decentralization and censorship-resistance guarantees** — they differ only in the Sybil-resistance medium and the disincentive currency.

| Mode | `min_stake` | Sybil cost | Disincentive on misbehavior |
|---|---|---|---|
| **`STAKE_INCLUSION`** (default) | 1000 (configurable) | Capital lock-up `min_stake × N` | Stake forfeit (suspension slash + equivocation forfeit) |
| **`DOMAIN_INCLUSION`** | 0 | Domain registration | Deregistration (lose all future block rewards; re-entry costs a fresh registration) |

**Why the decentralization claim is mode-invariant:** Determ's K-of-K mutual veto plus union tx_root means a tx is included if **any single committee member** adds it to their Phase-1 hash list. A single honest validator anywhere in the registry, given enough rounds, eventually rotates onto a committee and unions the tx into a block. Censorship would require **unanimous collusion of every validator that ever rotates onto any committee** — structurally impossible without 100% capture of the registry. This property is a function of K-of-K + union + rotation, not of the inclusion mechanism. Both `STAKE_INCLUSION` and `DOMAIN_INCLUSION` deliver it equally.

The choice between modes is operational: which Sybil-resistance medium and disincentive currency the deployment prefers. Stake is the natural choice for chains where the native token has economic weight; domain-based inclusion is the natural choice for deployments where on-chain economics doesn't yet exist or where validator identities are intentionally public for accountability.

### 5.2 Registration

A node joins the eligible pool by broadcasting a REGISTER transaction whose payload is its 32-byte Ed25519 public key. The transaction is itself signed with the corresponding private key, proving possession.

Registration takes effect after a randomized 1–10 block delay derived from `(tx.hash || cumulative_rand)`. This prevents a registrant from timing entry to guarantee selection in a chosen round.

In `DOMAIN_INCLUSION` chains the convention is that `tx.from` is a real DNS name (e.g., `validator1.example.com`). The protocol does not enforce DNS validity — that's an off-chain concern (operators may verify via DNSSEC TXT records pointing to the on-chain `ed_pub`). Mismatches surface as governance issues, not protocol violations.

### 5.3 Stake

Eligibility additionally requires `stake[domain] ≥ chain.min_stake()`. In `STAKE_INCLUSION` mode this is `min_stake = 1000` (configurable per chain at genesis). In `DOMAIN_INCLUSION` mode `min_stake = 0` and the gate is skipped entirely — registration alone suffices. STAKE / UNSTAKE transactions still work in both modes (validators may voluntarily lock stake even in `DOMAIN_INCLUSION`); they just don't gate eligibility.

### 5.4 Suspension and equivocation deregistration

A registered, eligible domain is **suspended** from selection if it has any Phase 1 abort against it in chain history; the suspension window grows exponentially with repeat offenses:

```
suspension_blocks(count) = min(BASE × 2^(count-1), MAX)
BASE = 10, MAX = 10000
```

Only **Phase 1** aborts (`round=1` AbortEvents) count toward suspension. Phase 2 aborts can fire on a healthy creator when its block-sig arrival is delayed past the timer (timing skew); using them would inflate false-positive suspensions and harm liveness without improving censorship guarantees.

A domain that **equivocates** (signs two different `block_digest`s at the same height) is permanently removed from the registry — `inactive_from` is set to the next block. Re-entry requires a fresh REGISTER (with a new Ed25519 key, and in `DOMAIN_INCLUSION` mode a new domain). In `STAKE_INCLUSION` mode the equivocator's stake is also fully forfeited; in `DOMAIN_INCLUSION` mode there's no stake to forfeit, but the registry-level deregistration is the punishment.

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

`select_m_creators` uses a deterministic hybrid (S-020): rejection sampling with a counter when `2K ≤ N` (cheap path, expected `O(K)` hashes, no allocation), or a partial Fisher-Yates shuffle when `2K > N` (bounded `O(N)` setup + exactly `K` hashes, no rejection spin even at `K = N − 1`). Both branches are pure functions of `(random_state, N, K)` so every node picks the same branch and the same indices. Excluding aborted-this-height domains from the local pool ensures committee re-selection after an abort doesn't re-pick the same silent creator before the chain-baked suspension takes effect on the next finalized block. The validator reproduces the same selection given a block's `abort_events` field.

---

## 7. Two-Phase Consensus

### 7.1 Phase 1 — Contrib

When a node finds itself in the round's committee (and the chain is in-sync), it:

1. Snapshots its mempool: `tx_hashes = sorted(keys(tx_store))`.
2. Generates a fresh 32-byte secret `s_i` from a CSPRNG and computes the commitment `dh_input = SHA256(s_i ‖ pubkey_i)`. The secret is held locally until Phase 2.
3. Computes the commit: `H(idx ‖ prev_hash ‖ H(tx_hashes) ‖ dh_input)`.
4. Signs the commit under its Ed25519 key.
5. Broadcasts `ContribMsg`.

Receiving nodes verify the signature and store the contrib. When all `K` committee contribs are present, the round transitions immediately into Phase 2.

### 7.2 Phase 1 → Phase 2 transition

Once `K` valid contribs are accumulated, every node (regardless of whether it is a committee member) derives:

```
tx_root    = root(union(creator_tx_lists))           // union of K hash lists
delay_seed = H(idx ‖ prev_hash ‖ tx_root ‖ dh_inputs[K])
```

The transition is immediate (no wall-clock delay). Selective-abort defense comes from the commit-reveal binding: in Phase 1 each member's secret is sealed under `SHA256(secret ‖ pubkey)`, so when a member decides whether to publish their commitment they cannot predict the eventual `R` — the K−1 other secrets remain uniformly random under SHA-256 preimage resistance.

### 7.3 Latency optimizations

- **Buffer-and-replay.** `BlockSigMsg`s that arrive before this node has assembled its own K Phase-1 contribs are buffered and replayed once the round transitions into Phase 2.
- **Round pipelining.** Round `n+1`'s Phase 1 starts immediately after applying block `n` locally; previous-round gossip propagation continues in parallel.
- **Own-Contrib pre-publish.** A creator's own Phase 1 contribution can be assembled and broadcast as soon as `prev_hash` is known, eliminating own-side latency from the Phase 1 budget.

### 7.4 Phase 2 — BlockSig (reveal)

Each committee member signs `block_digest` under its Ed25519 key and broadcasts `BlockSigMsg` carrying the **revealed** `dh_secret`. Other members verify `SHA256(dh_secret ‖ signer.pubkey) == sender's Phase-1 dh_input`, rejecting on mismatch.

`block_digest` is the SHA-256 of `idx ‖ prev_hash ‖ tx_root ‖ delay_seed ‖ consensus_mode ‖ bft_proposer ‖ creators[] ‖ creator_tx_lists ‖ creator_ed_sigs ‖ creator_dh_inputs`. Note it **excludes** `delay_output` and `creator_dh_secrets` so members can sign at Phase-2 entry without waiting for the K reveals to gather; the final `delay_output = SHA256(delay_seed ‖ ordered_secrets)` and the secrets themselves are bound into the block hash via `signing_bytes()` instead.

When all `K` BlockSig messages are present (and all K secrets verify), any node assembles the canonical block body (transactions resolved deterministically from `union(creator_tx_lists)` and the local mempool, sorted by `(from, nonce, hash)`) and applies it.

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
6. For each `i`, `SHA256(creator_dh_secrets[i] ‖ creators[i].pubkey)` equals `creator_dh_inputs[i]` (Phase-2 reveal verifies against the Phase-1 commitment).
7. `delay_output` equals `SHA256(delay_seed ‖ creator_dh_secrets[0..K])`.
8. Each `creator_block_sigs[i]` is a valid Ed25519 signature over `block_digest` by `creators[i]`'s registered key.
9. Each `AbortEvent` carries a valid `K-1` quorum of signed `AbortClaimMsg`s, with claimers drawn from the at-event committee (reconstructed by the same exclude-mixed rule).
10. Transactions are valid against the running balance/nonce model in canonical order.
11. `cumulative_rand` equals `H(prev.cumulative_rand ‖ delay_output)`.
12. `timestamp` is within `±30 s` of the local clock.

Steps 2, 3, 7, and 8 together guarantee fork-freedom: producing two valid blocks at the same height would require the same committee to sign two different digests, which any honest committee member refuses; or differing committees, which would each fail step 2 against the deterministic selection.

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

### 10.3 Selective abort defense (commit-reveal)

A naive aggregate-signature randomness beacon (e.g., a BLS-based randomness beacon) is vulnerable to **selective abort**: a committee member could compute the resulting `R` from a candidate Phase 1 set, decide whether `R` favors them, and choose whether to publish their share — biasing future selection.

Determ defeats this with a Phase-1/Phase-2 commit-reveal binding:

- In Phase 1, each member commits to their secret via `dh_input = SHA256(secret_i ‖ pubkey_i)` — a one-way commitment under SHA-256 preimage resistance.
- The block's randomness `R = SHA256(delay_seed ‖ ordered_secrets)` depends on **all K** revealed secrets. While a member is deciding whether to publish their Phase-1 commitment, the K−1 other secrets are still uniformly random; under SHA-256 preimage resistance, no candidate `R` can be tested.
- Phase-2 reveals are bound to Phase-1 commitments: a malicious member cannot substitute a different secret post-hoc, since the block validator rejects unless `SHA256(reveal ‖ pubkey) == matching dh_input`.
- `T` is set so `T_delay ≥ 2 × T_phase_1`. Within the Phase 1 window, an attacker can complete fewer than 0.5 candidate evaluations on average — far less than 1 useful trial.

| `T_delay / T_phase_1` | Grinding attempts per round | Selective-abort feasibility |
|---|---|---|
| 0.5 | 2 | Real |
| 1.0 | 1 | Marginal |
| 2.0 | 0.5 | Acceptable |
| 5.0 | 0.2 | Negligible |

The default profile sets `T_delay = 2 × tx_commit_ms`, giving the "Acceptable" row above.

An iterated-SHA-256 delay function (`R = SHA256^T(seed)`) was considered as an alternative selective-abort defense — sequential SHA-256 cannot be parallelized, so an attacker grinding candidates during Phase 1 would be bounded by `T`. The construction was rejected because SHA-256 is the most heavily-ASIC'd hash in existence: an attacker with optimized silicon completes `T` iterations in a fraction of the wall-clock budget, regaining the predictive-evaluation window. Commit-reveal replaces the time-bound argument with a structural one — preimage resistance is independent of compute speed.

### 10.4 Liveness — per-height BFT escalation

**Strong mode (`K = M_pool`)** is the default. Every committee is the entire pool; a single silent creator halts the round.

**Per-height BFT escalation** restores liveness without giving up strong mode's safety on most blocks. The mechanism, configured via genesis-pinned `bft_enabled` (default `true`) and `bft_escalation_threshold` (default 5):

1. **Default state**: each round runs in **MUTUAL_DISTRUST** mode — full K-of-K Phase 2 unanimity, every block is unconditionally fork-free.
2. **Trigger** (all four must hold — see PROTOCOL.md §5.3 for the exact gates): `bft_enabled = true` AND in-flight round at height `h` accumulates `bft_escalation_threshold` aborts (Round 1 + Round 2 both count) AND the available pool (registry minus aborted-this-height domains) has dropped below `K` AND the available pool is still ≥ `ceil(2K/3)`. If the available pool falls below `ceil(2K/3)` the shard stalls — there's not enough to form a BFT committee either; under EXTENDED sharding the R4 under-quorum merge mechanism may absorb the shard.
3. **BFT mode**: committee shrinks to `k_bft = ceil(2K/3)` selected from the available pool. A deterministic **designated proposer** (chosen from the committee via `proposer_idx(seed, abort_events, k_bft)` with `seed = epoch_committee_seed(epoch_rand, shard_id)` plus a 12-byte `"bft-proposer"` ASCII domain separator — see PROTOCOL.md §5.3.1 for the full algorithm) is the only node that builds a block at this height. Phase 1 still requires unanimity within the smaller committee; Phase 2 finalizes on `Q = ceil(2·k_bft/3)` sigs collected by the proposer (the standard BFT 2/3 quorum applied to the shrunk committee, not to the genesis K — the two coincide only at K=3). The block carries `consensus_mode = BFT` and `bft_proposer = <domain>`.
4. **Reset**: after the escalated block finalizes, height `h+1` resets to MD by default.

**Per-block trust claim:**

| Block type | Safety                                  | Censorship                                |
|-----------|-----------------------------------------|-------------------------------------------|
| MD        | **Unconditional** (no honest-fraction assumption — see §2 trust model) | K-conjunction over committee |
| BFT       | Conditional on `f_h < k_bft/3` in this committee + economic disincentive (`k_bft = ⌈2K/3⌉`) | `k_bft`-conjunction over the smaller committee — the union-tx-root rule covers all `k_bft` Phase-1 contributions; Phase-2 sentinels only affect signing |

Applications (and light clients) inspect each block's `consensus_mode` and reason accordingly. High-value transactions can wait for the next MD-mode block; routine transactions accept BFT blocks knowing the weaker safety claim. Most blocks (steady state) are MD; BFT is the tail liveness fallback.

**Slashing**: BFT-mode safety depends on `f < N/3` plus economic cost on misbehavior. `SUSPENSION_SLASH` (default 10 DTM) is deducted from a validator's stake whenever an `AbortEvent` for round 1 baked into a finalized block names them. Suspension counts only Phase-1 aborts to avoid Phase-2 timing-skew false positives; escalation counts all aborts.

**Opt out**: setting `bft_enabled = false` at genesis disables escalation — the chain halts on a persistent silent committee member, by design. Suitable for deployments that prefer unconditional safety on every block over liveness fallback.

### 10.5 Censorship vs. liveness, side by side

| Mode | K | Censorship requires | Liveness requires |
|---|---|---|---|
| Strong | M_pool | All M_pool collude | All M_pool live (BFT escalation falls back to ceil(2K/3) on persistent abort) |
| Hybrid | K < M_pool | All K committee collude | All K committee live; BFT escalation tolerates dropouts by shrinking the committee to `k_bft = ⌈2K/3⌉` |

---

## 11. Identity Model

### 11.1 Domains (registered, named)

A domain registers via REGISTER with its Ed25519 public key. Domains are listed in chain state and can be inspected by any observer. Domains may stake to become eligible creators; they may also transact (TRANSFER, etc.) under the same key.

### 11.2 Anonymous accounts (bearer wallets)

An anonymous account is a user-side keypair whose address is `0x` followed by the 64-hex Ed25519 public key. The user generates the keypair locally and keeps the private key on their own device. The address is not registered on-chain — it appears in chain state only when first credited (e.g., via TRANSFER).

The CLI exposes:

- `determ account create` — generates `{address, privkey}`.
- `determ send_anon <to> <amount> <privkey>` — signs a TRANSFER offline and submits via any node's `submit_tx` RPC.

Anonymous accounts cannot be selected as creators (consensus requires registered domains), but they can receive arbitrary credits and transfer them under bearer-wallet semantics: possession of the private key is full authority.

This separation provides:

- **Fungibility for end-users** without on-chain registration overhead.
- **Auditability for operators**: domains have stable, named identities for governance.
- **Censorship resistance for transfers**: the union-tx-set property applies equally to anonymous transactions.

### 11.3 Identity-anchored federated authentication (v2.25, planned)

The v1.x identity model is sufficient for on-chain action authorization (signing a tx). It does not yet specify a federated authentication ceremony for off-chain services — a service ("relying party" in SSO terms) cannot today challenge a user to prove possession of a domain key in a standardized way, and cannot accept a session token signed by the chain's committee.

v2.25 specifies that ceremony. The K-of-K committee acts as a mutual-distrust identity provider via **T-OPAQUE** (threshold OPAQUE — the modern CFRG aPAKE, instantiated in threshold form across the committee). RPs register on-chain via v2.18 DAPP_REGISTER; users authenticate via OPAQUE against the committee (passwords never leave the user's device, recovery envelopes are precomputation-resistant even if a committee minority colludes); the committee co-signs a SIWE-class assertion of the form `(issuer = chain_id, subject = user_identity, audience = rp_identity, iat, exp, nonce, state_root)` which the RP verifies against the on-chain committee pubkey set via v2.2 state_proof RPC.

v2.26 adds an on-chain `ROTATE_KEY` tx so a compromised key can be retired without losing the identity. Both items are specified in `docs/V2-DESIGN.md` Theme 9.

---

## 12. Network Protocol

### 12.1 Message Types

| Type | ID | Direction | Purpose |
|---|---|---|---|
| HELLO | 0 | peer → peer | Announce domain, port, chain role, shard_id |
| BLOCK | 1 | broadcast | Complete finalized block |
| TRANSACTION | 2 | broadcast | Unconfirmed transaction |
| BLOCK_SIG | 3 | broadcast | Phase 2: signed block digest + revealed dh_secret |
| CONTRIB | 4 | broadcast | Phase 1: TxCommit + DhInput + Ed25519 sig |
| GET_CHAIN | 5 | peer → peer | Request chain sync from index |
| CHAIN_RESPONSE | 6 | peer → peer | Chain sync chunk |
| STATUS_REQUEST | 7 | peer → peer | Sync state probe |
| STATUS_RESPONSE | 8 | peer → peer | Sync state response (height, genesis hash) |
| ABORT_CLAIM | 9 | broadcast | S7 Phase-1/2 abort claim (signed) |
| ABORT_EVENT | 10 | broadcast | Assembled K-1-claim quorum |
| EQUIVOCATION_EVIDENCE | 11 | broadcast | Two conflicting BlockSig sigs at same height |
| BEACON_HEADER | 12 | beacon → shard | Beacon block for shard-side header-chain |
| SHARD_TIP | 13 | shard → beacon | Shard block for beacon-side committee verify |
| CROSS_SHARD_RECEIPT_BUNDLE | 14 | broadcast (relay via beacon) | Source-shard block carrying outbound receipts |
| SNAPSHOT_REQUEST | 15 | peer → peer | Bootstrap snapshot fetch |
| SNAPSHOT_RESPONSE | 16 | peer → peer | Serialized chain state for fast-bootstrap |

### 12.2 Wire Format

All messages are length-prefixed:

```
[4 bytes BE length][envelope payload]
```

Two codecs are supported per-pair via the A3 / S8 wire-version negotiation (PROTOCOL.md §16.1):

* `kWireVersionLegacy = 0` — JSON envelope `{type: u8, payload: ...}`, default.
* `kWireVersionBinary = 1` — compact binary envelope (see `src/net/binary_codec.cpp` for layout).

HELLO advertises each side's `wire_version`; both sides negotiate down to `min(local, remote)` and use the negotiated codec for subsequent messages. HELLO itself is always JSON (it carries the version advertisement). Binary codec gracefully falls back to JSON serialization for any message type it can't encode.

S-022 per-message-type body caps apply at deserialize time regardless of codec: 1 MB for consensus chatter, 4 MB for blocks/headers/bundles, 16 MB only for SNAPSHOT_RESPONSE / CHAIN_RESPONSE. The 16 MB framing-layer ceiling (`kMaxFrameBytes`) is enforced at read time before the per-type check.

### 12.3 Gossip

All messages broadcast to all directly connected peers. Receiver-side dedup: blocks by `index` (`b.index < chain_.height()` skips silently); contribs by signer; block-sigs by signer. Cross-generation contribs (`aborts_gen` mismatch) are rejected.

### 12.4 Sync Mode (M12)

A node behind on chain state enters SYNC mode: it does not contribute to consensus, requests `GET_CHAIN` from peers, applies received chunks, and only re-enters `IN_SYNC` once it matches the network's head. This prevents a stale node from acting as a creator and disrupting the live committee.

---

## 13. Implementation Parameters

| Parameter | Default | Notes |
|---|---|---|
| `m_creators` (M_pool) | 3 (web profile) | Genesis-pinned. Per-profile M in §13.1 |
| `k_block_sigs` (K) | 2 (web profile, hybrid K<M) | Genesis-pinned. Only `cluster` is strong (K=M); `web`/`regional`/`global` are hybrid. Per-profile K in §13.1 |
| `block_subsidy` | 10 (atomic, by genesis convention) | Genesis-pinned, page reward. No code-level default — operator sets it in `GenesisConfig`; `tools/test_*.sh` use 10 |
| `bft_enabled` | true | Genesis-pinned. Enables per-height BFT escalation (§10.4) |
| `bft_escalation_threshold` | 5 | Genesis-pinned. Total aborts at same height before escalation |
| `SUSPENSION_SLASH` | 10 (atomic) | Stake deducted on each round-1 abort suspension |
| `tx_commit_ms` | 200 | Phase 1 timer |
| `block_sig_ms` | 200 | Phase 2 timer |
| `abort_claim_ms` | 100 | Abort claim collection window |
| `min_stake` | 1000 (`STAKE_INCLUSION`) / 0 (`DOMAIN_INCLUSION`) | Genesis-pinned per chain. Eligibility threshold |
| `inclusion_model` | `STAKE_INCLUSION` | Genesis-pinned. Either `STAKE_INCLUSION` or `DOMAIN_INCLUSION` |
| `BASE_SUSPENSION_BLOCKS` | 10 | First-offense suspension |
| `MAX_SUSPENSION_BLOCKS` | 10000 | Cap |
| `MAX_ABORT_EXPONENT` | 10 | Backoff cap |
| `REGISTRATION_DELAY_WINDOW` | 10 blocks | Activation jitter |

### 13.1 Timing profiles

A profile is a **complete deployment archetype**: timing, committee size, chain role, and sharding mode are all pinned together. To change role or sharding mode, pick a different profile — there is no separate CLI override.

| Profile | M | K | tx_commit_ms | block_sig_ms | abort_claim_ms | role | sharding_mode | target block time |
|---|---|---|---|---|---|---|---|---|
| `cluster` | 3 | 3 (strong) | 50 | 50 | 25 | BEACON | CURRENT | ~125 ms |
| `web` (default) | 3 | 2 (hybrid) | 200 | 200 | 100 | SHARD | EXTENDED | ~500 ms |
| `regional` | 5 | 4 (hybrid) | 300 | 300 | 150 | SHARD | CURRENT | ~750 ms |
| `global` | 7 | 5 (hybrid) | 600 | 600 | 300 | BEACON | EXTENDED | ~1.5 s |
| `tactical` | 3 | 3 (strong) | 20 | 20 | 10 | SHARD | EXTENDED | ~50 ms |

**Test variants** — sub-30 ms rounds for fast CI execution (`tx_commit_ms = block_sig_ms = 5`, `abort_claim_ms = 3`). Each test profile mirrors its production sibling's M / K / role / sharding_mode:

| Profile | M | K | role | sharding_mode |
|---|---|---|---|---|
| `single_test` | 3 | 3 (strong) | SINGLE | NONE |
| `cluster_test` | 3 | 3 (strong) | BEACON | CURRENT |
| `web_test` | 3 | 2 (hybrid) | SHARD | EXTENDED |
| `regional_test` | 5 | 4 (hybrid) | SHARD | CURRENT |
| `global_test` | 7 | 5 (hybrid) | BEACON | EXTENDED |
| `tactical_test` | 3 | 3 (strong) | SHARD | EXTENDED |

`ShardingMode` values:
- **`NONE`** — single-chain deployment, no sharding (test-only).
- **`CURRENT`** — 1 beacon + S shard chains, account routing by salted-SHA256 modulus, committees drawn from the global validator pool.
- **`EXTENDED`** — same as `CURRENT` plus per-shard `committee_region`: each shard's K-committee is restricted to validators tagged with that region, dropping intra-shard RTT and per-shard block time. Cross-shard tx still pays the wider beacon round-trip (B3 receipts).

Block time approaches `T_phase_1 + T_phase_2 + 2 × max RTT in committee` once the round transitions immediately at K-of-K Phase-1 arrival. Under `EXTENDED` sharding the relevant RTT is intra-region, not global.

---

## 14. Comparison with Related Work

### 14.1 Bitcoin (Nakamoto Consensus)

PoW longest-chain. Probabilistic finality, energy-intensive, fork-prone. Determ is registration-gated, immediately final, fork-free.

### 14.2 Ethereum (Gasper)

PoS with 2/3+ attester finality over ~12.8 minutes. Determ finalizes per block (~500 ms web profile). Ethereum tolerates per-validator faults; Determ's K-of-K does not, but achieves stronger censorship resistance through union tx set.

### 14.3 Tendermint / Cosmos

2/3+ vote in a two-phase commit. Single proposer per round is a censorship bottleneck; Determ's union-of-K is not.

### 14.4 Algorand

VRF sortition + BA* over ~3.7 s. Tolerates `f < N/3` Byzantine. Determ's per-round committee is much smaller (`K`, typically 3) but every member must contribute — censorship requires unanimity within the committee.

### 14.5 Dfinity / Internet Computer

Threshold BLS beacon + ranked leader model. Determ has no leader; all `K` committee members are co-equal. Determ uses a commit-reveal randomness protocol (not threshold BLS) for per-block `R`, which avoids the selective-abort vulnerability inherent to aggregate-signature beacons without depending on the heavy threshold-BLS toolchain.

### 14.6 Solana

Iterated-SHA-256 Proof of History for sequencing + Tower BFT for finality lagging by ~32 slots. Determ's randomness uses commit-reveal rather than iterated SHA-256; finality is per-slot K-of-K signatures rather than tower-vote accumulation.

---

## 15. Limitations and Future Work

**Hybrid-mode liveness.** A `K < M_pool` configuration tolerates `M_pool − K` silent creators only via per-height BFT escalation; the genesis-pinned `K<M` parameter is preserved for future fork-choice variants but the escalation path is the canonical liveness story.

**Stake-weighted selection.** Creators are selected uniformly from the stake-eligible pool. Stake-weighted selection (proportional to bonded stake) is a natural extension for production deployments.

**Sharding for scale.** Single-chain TPS scaling via in-block parallel transaction execution is **not on the roadmap** — the design philosophy preferences sharding (per-shard mutual-distrust K-conjunction) over single-chain optimistic-concurrency execution. A deployment that hits a per-shard TPS ceiling adds shards rather than rewriting the apply path. Under `EXTENDED` sharding the throughput axis aligns with regional locality: most user traffic stays in-shard at intra-region RTT.

**Network partition behavior.** A partition that splits the committee blocks progress on both sides until it heals (modulo BFT escalation, which can finalize a side with `ceil(2K/3)` honest committee members). Appropriate for a financial ledger (CP, not AP). Under `EXTENDED` sharding a region losing connectivity to the rest of the world stalls cross-shard receipts; in-shard production continues.

**Binary wire codec — shipped (A3 / S8).** Two codecs co-exist per-pair: JSON-over-TCP (legacy, the default), and a compact binary envelope (`src/net/binary_codec.cpp`). HELLO advertises each side's `wire_version`; pairs negotiate to `min(local, remote)`. Pre-A3 peers stay on JSON automatically. PROTOCOL.md §16.1 has the version-negotiation details.

**Light clients.** Inclusion-proof RPC (`state_proof`) is shipped via the v2.2 foundation — light clients query a full node for a Merkle proof of any state entry against the current `state_root` (which is bound into `signing_bytes` and committee-signed). The full header-only sync flow (light client downloads only block headers + verifies against epoch-boundary committee state) builds on this primitive and is a follow-on RPC track. CLI `determ state-proof --ns <a|s|r|b|k|c> --key <name>` exercises the primitive today.

**Distributed identity provider (DSSO).** The K-of-K committee is structurally a mutual-distrust operator group — a natural fit for distributed-IdP designs in the literature. v2.25 + v2.26 (V2-DESIGN.md Theme 9) specify a "Sign-In With Determ" substrate using **T-OPAQUE** (threshold-OPAQUE, replacing the original SRP in PAKE-as-black-box framework designs) over the committee, paired with on-chain key rotation. RPs register via the existing v2.18 DAPP_REGISTER channel; challenges and signed assertions ride v2.19 DAPP_CALL. The framework's authentication ceremony depends on v2.10 (threshold randomness / BLS infrastructure) and v2.14 (single-server OPAQUE wallet recovery) shipping first. See `docs/V2-DESIGN.md` Theme 9 for the full architecture.

**Equivocation handling — fully closed-loop:**

The disincentive depends on the chain's governance model (§5.1):

- **`STAKE_INCLUSION`** chains: `SUSPENSION_SLASH = 10` deducted on every Phase-1 abort. Equivocation triggers full stake forfeiture **and** registry deregistration.
- **`DOMAIN_INCLUSION`** chains: `SUSPENSION_SLASH` is a no-op (no stake to deduct). Equivocation deregisters the validator from the chain — they lose all future block rewards and must register a new domain to participate again.

Both modes use the same `EquivocationEvent` evidence structure (two Ed25519 signatures by the same registered key over two different `block_digest`s at the same `block_index` — unambiguous proof of double-signing) and the same end-to-end pipeline:

The full pipeline:

1. **Detection** (`apply_block_locked`): when a duplicate-height BFT block with a different hash arrives, the assembler computes both blocks' digests, extracts the proposer's signatures from each block's `creator_block_sigs`, and constructs an `EquivocationEvent`.
2. **Gossip** (`EQUIVOCATION_EVIDENCE`, msg type 11): the event is broadcast so peers can validate independently and pool the evidence.
3. **Pool** (`Node::pending_equivocation_evidence_`): each node maintains a pool of unbaked evidence. Peers receiving gossiped evidence validate the two-sig proof against the equivocator's registered key before adding.
4. **Production** (`build_body`): producers include the evidence pool in `block.equivocation_events` when building the next block.
5. **Validator** (`check_equivocation_events`): rejects malformed events (digests equal, sigs equal, equivocator not in registry, sigs don't verify against the registered key).
6. **Slashing** (`apply_transactions`): each `EquivocationEvent` zeroes the equivocator's `stakes_[X].locked`. Validator's stake-below-MIN_STAKE filter then removes them from selection on the next registry build.
7. **Dedup**: after a block bakes evidence, that equivocator's entries are removed from the pending pool (no double-baking).

BFT-mode safety claims (conditional on `f < N/3` plus economic disincentive) are now economically meaningful end-to-end.

---

## 16. Sharding

A sharded Determ deployment splits responsibility into a single **beacon chain** and `S` **shard chains**, each running the same two-phase commit-reveal consensus on its own state subset. The beacon is the trust anchor: it holds the validator pool, slashing records, cross-shard receipts, and epoch transitions. Shards process user transactions for accounts assigned to them.

The `ShardingMode` axis (pinned per profile) selects the topology:

- **`NONE`** — single chain, no shards. Test/demo deployments.
- **`CURRENT`** — beacon plus `S` shards; each shard's K-committee drawn from the **global** pool.
- **`EXTENDED`** — beacon plus `S` shards; each shard's K-committee restricted to validators tagged with that shard's `committee_region`. Per-shard block time bounded by intra-region RTT, not global.

### 16.1 Architecture

```
       ┌──────────────────────────────────────────┐
       │  Beacon chain (MD K-of-K, no escalation) │
       │  cumulative_rand, validator pool,        │
       │  cross-shard receipts, epoch transitions │
       └──┬───────────┬──────────────┬────────────┘
          │           │              │      epoch_seed
          ▼           ▼              ▼
     ┌────────┐  ┌────────┐    ┌─────────┐
     │ Shard 0│  │ Shard 1│ …  │Shard S-1│
     │ MD+BFT │  │ MD+BFT │    │ MD+BFT  │
     └────────┘  └────────┘    └─────────┘
```

The beacon runs MD K-of-K only (no escalation; halts on persistent silent committee member). Shards run MD-default with per-height BFT escalation. Asymmetry rationale: the beacon is the trust anchor — strong unconditional safety on every beacon block, low volume, halt-recoverable. Shards are the throughput layer — needs liveness more than censorship in steady state.

Under `EXTENDED` sharding each shard additionally pins a `committee_region` (operator-defined string, e.g. `"us-east"`, `"eu-west"`). Validators self-declare their region at REGISTER time; the committee for shard `s` is drawn only from validators tagged with `s.committee_region`. The trade is that per-shard censorship resistance becomes regional rather than global — see §16.6.

### 16.2 Reusing `cumulative_rand` for shard committees

Per epoch (every `E` beacon blocks), each shard's committee is derived from the beacon's `cumulative_rand` plus a per-shard salt:

```
shard_seed = SHA-256(beacon_epoch_seed ‖ "shard-committee" ‖ shard_id)
shard_committee[s] = select_m_creators(shard_seed, validator_pool_size, K_per_shard)
```

The same `select_m_creators` function used in single-chain mode. The salt makes shards' committees independent. The commit-reveal seed binding (§10.3) prevents adversaries from grinding stake placement: the K committed secrets that determine the next epoch's seed are not revealed until the current epoch's blocks finalize.

### 16.3 Account-to-shard assignment

```
shard_id(addr) = first_8_bytes_be(SHA-256(genesis_salt ‖ addr)) % S
```

`genesis_salt` is `GenesisConfig.shard_address_salt`, fixed at chain creation (32 random bytes). Stable for chain lifetime. `S` may grow at epoch boundaries via a beacon governance op (forthcoming).

### 16.4 Cross-shard transactions

Two-phase via beacon-mediated receipts:

1. User submits TRANSFER from `A_in_shard_0` to `B_in_shard_1`. Routed to shard 0.
2. Shard 0 includes the tx in its block, debiting A's balance. Emits `CrossShardReceipt{src=0, dst=1, ...}` in `cross_shard_receipts`.
3. Beacon relays via `CROSS_SHARD_RECEIPT_BUNDLE` gossip; destination shard filters by `dst_shard`, dedups by `(src_shard, tx_hash)`, and queues for inclusion.
4. Shard 1 bakes the receipt in its next block as `inbound_receipts`, crediting B's balance.

Cross-shard finality: `~3 × shard block time`. In-shard: `~1 × shard block time`. Atomicity is eventual consistency (debit-then-credit); atomic 2PC with timeout-revert is on the v3 roadmap.

### 16.5 Regional sharding (`EXTENDED` mode)

Under `EXTENDED` sharding each shard's genesis pins a `committee_region`. Validators self-declare a `region` at REGISTER time (UTF-8 string, ≤32 bytes — opaque to the protocol). The committee for shard `s` is drawn deterministically from the registry subset matching `s.committee_region`.

**Why this exists.** Per-block finality is bounded by `2 × max RTT in committee` (§13.1). Globally-distributed K-committees inherit transcontinental RTT (~150 ms one-way → ~500 ms+ blocks). Regional committees collapse this to intra-region RTT (~5-15 ms → ~125-250 ms blocks).

**The trade.** Per-shard censorship resistance becomes regional rather than global: capturing one region captures that region's shards. Two compensating mechanisms keep the protocol model coherent:

- **Beacon stays global.** The trust anchor still draws from the unified pool. Cross-shard receipts still pay the global beacon RTT, so cross-region txs gain no fast-path through regional capture.
- **Misclaimed regions self-correct.** A `us-east`-tagged validator with poor connectivity to other us-east members causes its rounds to abort, triggering suspension. Operators don't need to attest the claim cryptographically — economic disincentive does the policing.

**When to use which mode:**
- **`CURRENT`** for deployments where global censorship resistance is the priority and ~500 ms blocks are acceptable.
- **`EXTENDED`** for deployments where in-shard latency matters (interactive payments, regional consortiums) and operators are explicit about regional trust assumptions.
- **`NONE`** for tests and single-chain demos.

**Region taxonomy.** The protocol enforces only that `region` and `committee_region` strings are ASCII-lowercase, charset `[a-z0-9-_]`, max 32 bytes. Operators are free to use any labels within that charset. A recommended geographic taxonomy:

- `us-east`, `us-west` — North America
- `eu-west`, `eu-central` — Europe
- `apac-east`, `apac-south` — Asia-Pacific
- `sa-east` — South America

Closed deployments (consortium, enterprise) commonly use custom labels (`bank-cluster-1`, `branch-tokyo`, etc.). The genesis hash includes `committee_region`, so two shards with the same `shard_id` but different region claims have distinct chain identities.

**`num_shards >= 3` invariant.** A deployment that pins `sharding_mode = EXTENDED` must declare `initial_shard_count >= 3` in genesis. Smaller deployments would expose cascading-merge undefined behavior under the v1 under-quorum recovery mechanism (S-038 mitigation; see `docs/SECURITY.md`). The invariant is enforced both at `genesis-tool build-sharded` time and at node startup.

**REGISTER tx region field.** A validator joining an `EXTENDED` chain declares its region in the REGISTER tx payload:

```
REGISTER payload = [pubkey: 32B] [region_len: u8] [region: utf8 bytes]
```

Legacy payload (`region_len = 0`, no trailing bytes) is wire-compatible — it means "global pool", which is the implicit default for non-`EXTENDED` chains. New `EXTENDED` deployments set the region explicitly. The tx's own Ed25519 signature binds the region into the tx hash via `Transaction::signing_bytes()`.

`shard_id_for_address` is unchanged: `first_8_bytes_be(SHA-256(genesis_salt ‖ addr)) % S`. Account-region affinity is application-level — addresses can be ground for a target shard if locality matters.

### 16.6 Censorship + safety claims under sharding

Determ's K-conjunction censorship resistance is **per-shard, per-epoch**. An adversary capturing a single shard's K-committee for an epoch can censor that shard's transactions for the epoch. Rotation at the next epoch boundary evicts them. Operator knobs:

- Larger `K_per_shard` — harder to capture.
- Shorter `E` — less window per capture.
- Larger `pool / S` ratio — captures need validators across multiple epochs to land enough on a target shard.

**Under `EXTENDED` sharding the per-shard threat model is regional.** Capture probability becomes `(f_in_R / N_in_R)^K`, not `(f_global / N_global)^K`. If a single jurisdiction can compel all validators in region `R`, it can produce blocks for shards pinned to `R` without input from other regions. Document the regional trust assumption explicitly in your deployment spec; a regional capture does not propagate to other regions' shards because each shard's committee is independent.

Per-block trust is observable via `consensus_mode`:

| Block | Safety | Censorship |
|---|---|---|
| Beacon | Unconditional (MD-only, no escalation) | K-conjunction over beacon committee |
| Shard MD | Unconditional (MD steady-state) | K-conjunction over shard committee |
| Shard BFT | Conditional `f_h < k_bft/3` + slashing | `k_bft`-conjunction over shard BFT committee (Phase-1 union-tx-root applies; Phase-2 sentinels affect signing only) |

Applications choose which blocks they trust. Most blocks (steady state) are MD on both layers; BFT shard blocks are the tail-liveness fallback when a shard would otherwise stall.

### 16.7 Under-quorum merge

When a shard's regional pool drops below `2K`, that shard temporarily merges committee operations with its modular-next neighbor (`partner_id = (shard_id + 1) mod num_shards`). Mechanism:

- **Trigger.** A `MERGE_EVENT` tx (type 7) baked into a beacon block carries `(event_type ∈ {BEGIN, END}, shard_id, partner_id, effective_height, evidence_window_start, merging_shard_region)`.
- **Eligibility stress branch.** Partner T extends its committee pool with validators tagged with the refugee shard's region. Producer (`Node::check_if_selected`) and validator (`BlockValidator::check_creator_selection`) mirror the extension exactly.
- **Auto-revert.** A symmetric `MERGE_END` event reverts the partner to its native pool. Default thresholds: `merge_threshold_blocks = 100`, `revert_threshold_blocks = 200` (2:1 hysteresis to bias toward stability).
- **Grace period.** `effective_height >= block.index + merge_grace_blocks` so committees observe the transition before it takes effect.

Operator surface: `determ submit-merge-event --event {begin|end} --shard-id N --partner-id N --effective-height N --refugee-region R --priv <hex> --from <domain>`. Auto-detection on the beacon (observe `eligible_in_region < 2K` over the threshold window) is a v1.1 work item; v1.x ships the operator-driven path.

Safety preservation is proven in `docs/proofs/UnderQuorumMerge.md` (FA9).

---

## 17. Scope

Determ's design intent is intentionally narrow: a **fork-free L1 payment + identity chain with mutual-distrust safety**. It is not trying to be Ethereum, not trying to be a DApp hosting platform, not trying to host arbitrary computation. This section names what fits, what doesn't, and what's deliberately out of scope.

### 17.1 What Determ is built for

- **Permissionless payment system.** TRANSFER between named domains and anonymous bearer-wallet accounts. Censorship-resistant via K-of-K + union tx_root — any single non-Byzantine committee member can include any tx. Zero-trust safety (no protocol component trusts any participant).
- **Validator pool with cryptoeconomic accountability.** Validators register on-chain, can be staked or domain-anchored (§5.1). Misbehavior is detectable, slashable, and self-defeating regardless of adversary fraction (so long as ≥1 non-Byzantine validator remains in the registry).
- **Two-tier identity.** Registered domains (named, on-chain, eligible to validate) plus anonymous bearer-wallet accounts (Ed25519-pubkey-derived addresses; any user can self-issue). Both share the same balance/nonce namespace.
- **Page-reward system.** Genesis-pinned `block_subsidy` minted per block, split across the committee with fees.
- **Per-height BFT escalation.** Default mutual-distrust K-of-K; falls back to BFT `ceil(2K/3)` + designated proposer when the eligible pool can't form K-of-K and the abort threshold has been met. Per-block `consensus_mode` tag lets observers reason about per-block trust.
- **Sharded scaling.** Beacon + S shards with cross-shard receipts. `EXTENDED` sharding mode adds latency-grouped regional shard committees for sub-second in-shard finality on the public internet (§16.5).

### 17.2 Suitable use cases

- **Payment applications** — direct transfers between named domains and anonymous accounts.
- **Inter-organization settlement networks** — `DOMAIN_INCLUSION` chains where validators are publicly accountable organizations (banks, government registries, etc.).
- **Validator-coordinated registries** — REGISTER + STAKE patterns repurposed for identity directories, DNS-record registries, reputation systems.
- **Page-reward economies** — applications using the native subsidy + fee distribution as the incentive primitive.
- **Anything stateless that fits the named-account balance model.**

### 17.3 What Determ does not host

- **Computation beyond balance arithmetic** — needs a contract VM that Determ doesn't provide.
- **Large on-chain state** — tx payloads are tiny by design.
- **Cross-application composability** — no contracts means no cross-app calls.
- **Off-chain data dependencies** — no oracle infrastructure.

### 17.4 Deliberately out of scope

These are not roadmap items — they're outside the design intent:

- **Smart-contract VMs** (EVM, WASM). The value proposition is censorship-resistant fork-free payments + identity, not arbitrary execution.
- **Off-chain storage layer** (IPFS, Arweave). Application-specific; compose externally.
- **Bridges to other chains.** Could be built on top, not part of the core protocol.
- **On-chain frontend hosting.** Belongs off-chain.
- **Oracle networks.** Application-specific.
- **ZK / shielded transactions.** The anonymous bearer-wallet account model is the privacy story; no zero-knowledge layer planned.

A future fork or layer-2 could add these. The base protocol does not.

### 17.5 Honest framing

Calling Determ a "DApp hosting network" misrepresents what it is. Calling it a "decentralized cryptocurrency with mutual-distrust safety" is accurate. Specific fits:

- Inter-organization settlement where payment + identity is the whole value proposition.
- Censorship-resistant value transfer in environments where trust assumptions about validators are explicitly rejected.
- Federated registries where domain-anchored validators provide identity and the chain provides ordering + auditability.
- Regional payment networks (`EXTENDED` sharding) where in-shard sub-second finality matters and operators are explicit about regional trust assumptions.

If you need contracts, build them on a different chain or build a layer-2 on top of Determ. The base protocol's job is to be very good at one narrow thing — fork-free payment + identity with cryptoeconomic safety — not to be everything.

---

## 18. Governance

Determ supports two genesis-pinned governance modes:

- **`governance_mode = 0` (uncontrolled, default).** Consensus constants are immutable post-genesis. Changing any of them requires a new chain identity. Suitable for permissionless deployments and chains that want a single, stable parameter set forever.
- **`governance_mode = 1` (governed).** An N-of-N founder keyholder set may emit `PARAM_CHANGE` transactions mutating a whitelisted parameter set mid-chain. Suitable for consortium and enterprise deployments where parameter tuning is operationally necessary.

The whitelist (validator-enforced):

```
MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY,
bft_escalation_threshold,
param_keyholders, param_threshold,
tx_commit_ms, block_sig_ms, abort_claim_ms
```

Off-list parameters (committee size K, sharding mode, chain identity, crypto primitives) are not mutable. Changing them requires a new chain.

The PARAM_CHANGE payload carries `(name, value, effective_height)` plus signatures from `>= param_threshold` distinct keyholders over the canonical signing message. The validator rejects mode-incompatible, off-whitelist, or threshold-failing transactions outright. The apply path stages the change; activation fires at `effective_height` via `Chain::activate_pending_params(h)`.

Operator surface: `determ submit-param-change --priv <sender_hex> --from <sender_domain> --name <NAME> --value-hex <hex> --effective-height N --keyholder-sig <idx>:<priv_hex> [more...]`. Offline-signed; the CLI bundles the multisig + tx wrap.

Soundness is proven in `docs/proofs/Governance.md` (FA10).

---

## 18.5. Wallet recovery (A2)

A lost Ed25519 private key today means permanent loss of the registered domain and its balance. The `determ-wallet` binary provides an opt-in distributed recovery primitive layered over Shamir's Secret Sharing, AEAD envelopes, and an OPAQUE adapter — solving key loss without weakening on-chain trust.

**Threat model.** The wallet's recovery flow protects against:

- Loss of any (N − T) of N guardians (threshold reconstruction survives partial unavailability).
- Compromise of any (T − 1) guardians (information-theoretic: zero bits of the seed leak below threshold).
- Tampering with any individual envelope (AEAD detects single-bit modifications with probability ≥ 1 − 2⁻¹²⁸).
- Offline password grind against an isolated record (real OPAQUE only — gated to v2.14; the development-stub adapter is offline-grindable and is `is_stub()`-flagged against production use).

**Layered design.** Each layer addresses a distinct threat:

1. **Shamir SSS over GF(2⁸)** — splits the Ed25519 seed into N shares; any T reconstruct, any T − 1 reveal nothing.
2. **AEAD envelope (AES-256-GCM)** — wraps each share with a per-envelope salt + nonce; AAD binds guardian index + scheme version.
3. **OPAQUE adapter (interface)** — under the `opaque` scheme, each envelope's unwrap key is the export key from an OPAQUE registration/authentication round with the corresponding guardian. Under the `passphrase` scheme (default in v1.x while libopaque vendoring is pending), keys are PBKDF2-derived from the user's password directly.

**Wire format.** A recovery setup is a single self-contained JSON document:

```json
{
  "version": 1,
  "scheme": "shamir-aead-opaque-stub-argon2id-v1",
  "threshold": 3,
  "share_count": 5,
  "secret_len": 32,
  "guardian_x": [1, 2, 3, 4, 5],
  "envelopes": ["DWE1.<salt>.<iters>.<nonce>.<aad>.<ct>", ...],
  "opaque_records": ["<hex>", ...],
  "pubkey_checksum": "<sha256(ed25519_pubkey(seed))>"
}
```

The setup is fully portable — it carries everything needed for threshold reconstruction (modulo the user knowing the password and having access to ≥ T envelopes).

**Operator surface:**

```
determ-wallet shamir split <hex> -t T -n N         Split secret into N shares
determ-wallet shamir combine <share> ...           Reconstruct from >=T shares
determ-wallet envelope encrypt --plaintext <hex>   AEAD-wrap arbitrary data
                                --password <str>
determ-wallet envelope decrypt --envelope <blob>   Unwrap an envelope
                                --password <str>
determ-wallet create-recovery --seed <hex>         Persist a T-of-N recovery setup
                              --password <str>
                              -t T -n N --out <file>
                              [--scheme {passphrase|opaque}]
determ-wallet recover --in <file>                  Reconstruct the seed
                      --password <str>
                      [--guardians <i,j,k,...>]
determ-wallet opaque-handshake --mode {register|authenticate}
                                --password <str>
                                --guardian-id <0..255>
                                [--record <hex>]
determ-wallet oprf-smoke                           Verify libsodium primitives wired
```

**Wallet adapter status.** v1.x ships Phases 1–5 + 7 of the wallet's internal phase plan (greenfield wallet binary, all crypto layers wired against libsodium, OPAQUE adapter interface locked, recovery flow routed through the adapter). The Phase-6 work item — vendor real `libopaque` + `liboprf` to replace the stub adapter implementation, multi-cycle Windows MSVC porting work — is tracked as **v2.14 (Real OPAQUE wallet recovery)** in `docs/V2-DESIGN.md`; the wallet's `is_stub()` flag gates production deployment until v2.14 lands. See `docs/proofs/WalletRecovery.md` (FA12) for the formal-soundness analysis covering both stub and real-OPAQUE bounds, plus the Phase-numbering-↔-v2.14 mapping note at the top of that file.

**Binary isolation.** `determ-wallet` is a separate executable from the `determ` daemon. Secret material never enters the chain daemon's address space — by design. The daemon handles networking and consensus; the wallet handles keys.

---

## 19. Formal verification

Determ's safety-critical mechanisms are covered by per-property analytic proofs and machine-checkable TLA+ specifications. The full set lives in [`docs/proofs/`](docs/proofs/README.md):

| Layer | Coverage |
|---|---|
| **FA-track** (analytic proofs) | F0 Preliminaries + FA1–FA12: safety, censorship, selective-abort, liveness, BFT-mode safety, slashing soundness, cross-shard atomicity, regional sharding, under-quorum merge, governance, economic soundness, wallet recovery. |
| **FB-track** (TLA+ specs) | Consensus.tla, Sharding.tla, Receipts.tla + CHECK-RESULTS.md. Model-check transcripts pending TLC installation in CI; specs ready for local validation. |

Every theorem cites its cryptographic assumptions (A1 Ed25519 EUF-CMA, A3 SHA-256 collision resistance, A4 SHA-256 preimage resistance, A5 SHA-256 as random oracle), the validity predicates it depends on (V1–V14 from F0), and the source-code location that enforces it. A reviewer can trace any property end-to-end: theorem → state-machine model → implementation.

Concrete-security bounds: every property holds with probability `≥ 1 − Q · 2⁻¹²⁸` over polynomial adversary budget `Q`. Under Grover (post-quantum), bounds degrade to `Q · 2⁻⁶⁴` for Ed25519 — operationally secure but a PQ-signature migration (Dilithium / Falcon) would restore classical bounds.

---

## 20. Conclusion

Determ demonstrates that fork-free, immediately-final consensus is achievable at sub-second block times with just two well-known cryptographic primitives — Ed25519 and SHA-256 — without proof-of-work, multi-round voting, or a trusted leader. The two-phase Contrib + BlockSig protocol places randomness generation under a SHA-256-based commit-reveal binding, defeating selective abort by construction rather than by economic disincentive or wall-clock delay. The union-of-committee transaction root makes inclusion a collaborative property: a single honest committee member suffices to defeat censorship.

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
7. Boneh, D., Bonneau, J., Bünz, B., Fisch, B. "Verifiable Delay Functions." CRYPTO 2018. (Theoretical context for sequential-delay primitives. Determ's iterated SHA-256 satisfies the sequentiality requirement without the succinct-verify property of true VDFs.)

---

## License

Determ is licensed under the **Apache License, Version 2.0** ([LICENSE](LICENSE)).

```
Copyright 2026 Determ Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.
```

Third-party components (OpenSSL, Asio, nlohmann/json, libsodium) are bundled or referenced under their respective licenses. See [NOTICE](NOTICE) for the full attribution list.

Source files carry an SPDX identifier (`// SPDX-License-Identifier: Apache-2.0`) so toolchain-level license scanners can verify provenance automatically.
