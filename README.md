# DHCoin: A Fork-Free Cryptocurrency with Two-Phase Sequential-Delay Co-Creation

**Version 1, rev. 8** (rev. 9 sharding scaffolding in progress)

> **Scope, briefly:** DHCoin is a **base-layer fork-free L1 payment + identity chain** with mutual-distrust safety. It is **not** a DApp hosting platform — there is no smart-contract execution layer (no EVM, no WASM, no gas), no off-chain storage integration, no bridges, no light clients yet. Native transaction types are TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE — that's it. The full breakdown of what's done vs. what isn't is in [§17 Scope and Current Status](#17-scope-and-current-status).

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

**Trust model — zero-trust system, mutual-distrust environment.** DHCoin is a **zero-trust system internally**. The protocol itself assumes nothing about any participant's honesty, intent, or alignment with chain progress. It only enforces rules: verify signatures, run the consensus state machine, propagate messages. No participant — including beacons, validators, users, or operators — is granted any trust by the protocol. Every actor is treated as potentially adversarial.

**All trust comes from outside the system, never from within it.** External observers (users, regulators, auditors) may form their own beliefs about specific validators based on external evidence — public domain identity, off-chain reputation, regulatory accountability, code review of the validator software, etc. — and those beliefs may inform the observer's choice of which chain to use, which validators to peer with, which blocks to consider final beyond protocol guarantees. But none of those external beliefs are encoded into the protocol. The protocol works identically whether observers trust validators or not.

DHCoin contrasts here with classic BFT protocols (Tendermint, HotStuff, PBFT) that assume participants pursue a **common goal** — *advance the chain* — and bound the fraction that can defect from that goal (typically `f < N/3`). BFT framings smuggle a soft trust assumption into the protocol: "≥2/3 of validators want the chain to function." DHCoin assumes nothing of the kind. **Validators have no common goal.** Each is a self-interested actor pursuing its own block reward. They do not cooperate voluntarily; they cooperate **involuntarily and only at the moment of block propagation**, because the protocol's K-of-K and union-tx-root rules make individual defection either rewardless (no share of the block) or impotent (a refusal to include a tx is overridden by anyone else who does include it).

This is "mutual distrust" — every validator watches every other, assumes every other is potentially adversarial, and the protocol is robust *because* the rules align self-interested behavior into chain progress without requiring shared intent.

### 2.1 The actual decentralization threshold

DHCoin's safety + censorship-resistance properties hold **as long as at least one validator in the registry is non-Byzantine**:

- **At least 1 non-Byzantine validator anywhere in the registry → mutual-distrust environment.** The K-of-K committee rotates over time, so a single non-Byzantine validator eventually appears on any committee. Their Phase 1 contribution unions any censored tx into the block (mutual inclusion). Their refusal to sign malformed proposals is a veto on those they reject (mutual veto). The chain stays open and uncensored.
- **0 non-Byzantine validators (100% adversarial capture) → fully controlled adversarial network.** No protocol provides safety in this case — the attacker controls every committee member at every height and can produce any block they want. This is the universal limit beyond which no consensus protocol can function. DHCoin makes no claim here.

Two important caveats on this threshold:

1. **"Non-Byzantine" is not "honest."** The protocol doesn't require *anyone* to be honest in any moral sense — it only requires that *some* participant follows protocol rules (for whatever reason: self-interest, regulation, mistake, ethics). Following the protocol is rationally cheaper than deviating, so the property holds even under fully self-interested rational actors.
2. **The threshold is a property of the system, not a protocol assumption.** The protocol does not *believe* that ≥1 validator is non-Byzantine — it doesn't believe anything. The threshold is what an *external observer* needs to assume in order to expect the chain to remain useful. If the observer doesn't believe even ≥1 validator follows the protocol, they don't use the chain. That choice happens outside the system.

The "honest minority" tolerance most BFT protocols celebrate (`f < N/3`) is **strictly weaker** than what DHCoin's K-of-K + union model achieves: DHCoin tolerates `f < N` (one non-Byzantine validator in the entire registry suffices for safety + censorship resistance), at the cost of giving up `f < N/3` liveness (a single Byzantine in the *committee* can halt that round, mitigated by rotation + BFT escalation in §10.4).

### 2.2 The three structural properties

The mutual-distrust model rests on:

1. **Mutual veto via K-of-K signatures.** A block requires every committee member to sign the same digest. Any single member can refuse — they cannot unilaterally produce a block, but they also cannot unilaterally allow a malformed one. Refusal is detectable (Phase 1 absence triggers an `AbortClaimMsg` quorum, recorded as an `AbortEvent` in the next block) and economically costly (suspension + slashing).

2. **Mutual inclusion via union tx_root.** A transaction enters the block if **any** committee member contributes it in Phase 1 — not just a majority. To censor a transaction, every member must omit it; a single defector breaks the censorship. Defection is the rational individual choice (a defector who includes the tx earns its fee and avoids being implicated in censorship). The K-way unanimous collusion required to censor is fragile because each colluder has standing incentive to defect.

3. **No predictability of consequence.** The block's randomness `R = SHA-256^T(seed)` is committed-then-revealed: every committee member's `dh_input` is part of the seed, but `R` is not computable until after Phase 1 closes (the delay-hash takes longer than the Phase 1 window). A committee member deciding whether to participate cannot compute whether participation favors them — selective abort is cryptographically defeated.

### 2.3 Trade-off vs. BFT

DHCoin gives up `f < N/3` Byzantine *liveness* tolerance — a single silent committee member halts the round (in strong mode; rev.8 BFT escalation in §10.4 falls back to `ceil(2K/3)` after threshold aborts). In return it gets:
- **Stronger censorship resistance** — `(f/N)^K` per round, exponential in K, no leader bottleneck.
- **Unconditional fork-freedom** — no fork-choice rule needed; K-of-K signatures over the same digest at the same height are unforgeable.
- **Lower honest-fraction requirement** — `≥1 of N` honest, not `≥2/3 of N` honest, for the chain to remain useful.
- **Clean economic story** — every participant pursues block rewards. Deviation either earns no reward (refusal → no share), gets slashed (equivocation → forfeit), or is futile (censorship → defected by any honest member). No "honest majority assumption" is bolted on.

**Network assumptions.** We assume a partially synchronous network: messages are delivered within some known bound `Δ` during normal operation. The protocol tolerates periods of asynchrony by aborting and restarting rounds. Safety does not require synchrony — an invalid block is rejected regardless of message ordering.

**Adversary model.** Concretely, an adversary may control any subset of `N` registered nodes (no fraction bound assumed for safety). Corrupted nodes may deviate arbitrarily from the protocol, delay messages within `Δ`, and choose which Phase 1 contributions to publish. The adversary cannot forge Ed25519 signatures or break SHA-256, and cannot evaluate the iterated SHA-256 delay-hash faster than its inherent sequential bound. Liveness — but not safety — degrades as adversary fraction approaches 100%.

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
    creators          : []string           // committee, selection order
    creator_tx_lists  : [][]Hash           // K' Phase 1 hash lists
    creator_ed_sigs   : [][64]             // K' Phase 1 commit sigs
    creator_dh_inputs : [][32]             // K' Phase 1 randomness contributions
    tx_root           : [32]               // root over union(creator_tx_lists)
    delay_seed        : [32]               // H(idx ‖ prev_hash ‖ tx_root ‖ dh_inputs)
    delay_output      : [32]               // R = SHA-256^T(delay_seed)
    consensus_mode    : uint8              // 0 = MUTUAL_DISTRUST (K-of-K), 1 = BFT
    bft_proposer      : string             // empty in MD blocks
    creator_block_sigs: [][64]             // K' Phase 2 Ed25519 sigs over block_digest
    abort_events      : []AbortEvent
    cumulative_rand   : [32]               // SHA-256(prev_rand ‖ delay_output)
    hash              : [32]
}
```

`K'` is the committee size for this block:
- `K' = K` (genesis-pinned `k_block_sigs`) for MD blocks (steady state).
- `K' = ceil(2K/3)` for BFT blocks (per-height escalation; see §10.4).

In MD blocks every position in `creator_block_sigs` carries a real Ed25519 signature (K-of-K). In BFT blocks up to `K' - ceil(2K'/3)` positions may carry the all-zero `Signature{}` sentinel (proposer-led `ceil(2K'/3)`-of-K' threshold, see §10.4). `bft_proposer` is the deterministically-chosen committee member who finalized the block; in MD blocks it is empty.

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

### 5.1 Inclusion models

DHCoin supports two genesis-pinned validator-inclusion policies. Both deliver **identical decentralization and censorship-resistance guarantees** — they differ only in the Sybil-resistance medium and the disincentive currency.

| Mode | `min_stake` | Sybil cost | Disincentive on misbehavior |
|---|---|---|---|
| **`STAKE_INCLUSION`** (default) | 1000 (configurable) | Capital lock-up `min_stake × N` | Stake forfeit (suspension slash + equivocation forfeit) |
| **`DOMAIN_INCLUSION`** | 0 | Domain registration | Deregistration (lose all future block rewards; re-entry costs a fresh registration) |

**Why the decentralization claim is mode-invariant:** DHCoin's K-of-K mutual veto plus union tx_root means a tx is included if **any single committee member** adds it to their Phase-1 hash list. A single honest validator anywhere in the registry, given enough rounds, eventually rotates onto a committee and unions the tx into a block. Censorship would require **unanimous collusion of every validator that ever rotates onto any committee** — structurally impossible without 100% capture of the registry. This property is a function of K-of-K + union + rotation, not of the inclusion mechanism. Both `STAKE_INCLUSION` and `DOMAIN_INCLUSION` deliver it equally.

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

### 10.4 Liveness — per-height BFT escalation

**Strong mode (`K = M_pool`)** is the default. Every committee is the entire pool; a single silent creator halts the round.

**Per-height BFT escalation (rev.8)** restores liveness without giving up strong mode's safety on most blocks. The mechanism, configured via genesis-pinned `bft_enabled` (default `true`) and `bft_escalation_threshold` (default 5):

1. **Default state**: each round runs in **MUTUAL_DISTRUST** mode — full K-of-K Phase 2 unanimity, every block is unconditionally fork-free.
2. **Trigger**: when an in-flight round at height `h` accumulates `bft_escalation_threshold` aborts AND the eligible pool (registry minus aborted-this-height domains) has dropped below `K`, the next round at `h` falls back to **BFT** mode.
3. **BFT mode**: committee shrinks to `ceil(2K/3)` selected from the available pool. A deterministic **designated proposer** (chosen from the committee via `proposer_idx(prev_cum_rand, abort_events, |committee|)`) is the only node that builds a block at this height. Phase 1 still requires unanimity within the smaller committee; Phase 2 finalizes on `ceil(2K_eff/3)` sigs collected by the proposer. The block carries `consensus_mode = BFT` and `bft_proposer = <domain>`.
4. **Reset**: after the escalated block finalizes, height `h+1` resets to MD by default.

**Per-block trust claim:**

| Block type | Safety                                  | Censorship                                |
|-----------|-----------------------------------------|-------------------------------------------|
| MD        | **Unconditional** (no honest-fraction assumption — see §2 trust model) | K-conjunction over committee |
| BFT       | Conditional on `f < N/3` in this committee + economic disincentive | (1+K_eff/3)-conjunction over the smaller committee |

Applications (and light clients) inspect each block's `consensus_mode` and reason accordingly. High-value transactions can wait for the next MD-mode block; routine transactions accept BFT blocks knowing the weaker safety claim. Most blocks (steady state) are MD; BFT is the tail liveness fallback.

**Slashing (rev.8)**: BFT-mode safety depends on `f < N/3` plus economic cost on misbehavior. `SUSPENSION_SLASH` (default 10 DHC) is deducted from a validator's stake whenever an `AbortEvent` for round 1 baked into a finalized block names them. Suspension counts only Phase-1 aborts to avoid Phase-2 timing-skew false positives; escalation counts all aborts.

**Opt out**: setting `bft_enabled = false` at genesis preserves the rev.7 single-mode behavior — chain halts on persistent silent committee member, by design. Suitable for deployments that prefer unconditional safety on every block over liveness fallback.

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

**Hybrid-mode liveness (v2).** As §10.4 notes, the rev.7 hybrid-mode `K < M_pool` configuration is partially superseded by rev.8's per-height BFT escalation. The escalation mechanism delivers what hybrid mode was originally trying to: chain progress when the eligible pool can't form K-of-K. Hybrid mode is preserved as a parameter but the escalation path is now the recommended liveness story.

**Stake-weighted selection.** v1 selects creators uniformly from the stake-eligible pool. Stake-weighted selection (proportional to bonded stake) is a natural extension for production deployments.

**Sharding for scale.** §16 introduces the rev.9 sharding architecture and its current scaffolding state. Full multi-chain coordination (Stage B2c onward) is in progress. Single-chain TPS scaling via in-block parallel transaction execution is **not on the roadmap** — the design philosophy preferences sharding (per-shard mutual-distrust K-conjunction) over single-chain optimistic-concurrency execution. A deployment that hits a per-shard TPS ceiling adds shards rather than rewriting the apply path.

**Network partition behavior.** A partition that splits the committee blocks progress on both sides until it heals (modulo BFT escalation, which can finalize a side with `ceil(2K/3)` honest committee members). Appropriate for a financial ledger (CP, not AP).

**Binary wire codec (S8).** Current JSON-over-TCP is convenient but verbose. v2 will introduce a binary message codec for bandwidth efficiency.

**Equivocation handling — fully closed-loop in rev.8:**

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

## 16. Sharding (rev.9, in progress)

A sharded DHCoin deployment splits responsibility into a single **beacon chain** and `S` **shard chains**, each running the rev.8 protocol on its own state subset. The beacon is the trust anchor: it holds the validator pool, slashing records, cross-shard receipts, and epoch transitions. Shards process user transactions for accounts assigned to them.

### 17.1 Architecture

```
       ┌──────────────────────────────────────────┐
       │  Beacon chain (rev.7 MD K-of-K)          │
       │  cumulative_rand, validator pool,        │
       │  cross-shard receipts, epoch transitions │
       └──┬───────────┬──────────────┬────────────┘
          │           │              │      epoch_seed
          ▼           ▼              ▼
     ┌────────┐  ┌────────┐    ┌────────┐
     │ Shard 0│  │ Shard 1│ …  │Shard S-1│
     │ rev.8  │  │ rev.8  │    │  rev.8  │
     │ MD+BFT │  │ MD+BFT │    │ MD+BFT  │
     └────────┘  └────────┘    └────────┘
```

The beacon runs MD K-of-K only (no escalation; halts on persistent silent committee member). Shards run rev.8 MD-default with per-height BFT escalation. Asymmetry rationale: the beacon is the trust anchor — strong unconditional safety on every beacon block, low volume, halt-recoverable. Shards are the throughput layer — needs liveness more than censorship in steady state.

### 17.2 Reusing `cumulative_rand` for shard committees

Per epoch (every `E` beacon blocks), each shard's committee is derived from the beacon's `cumulative_rand` plus a per-shard salt:

```
shard_seed = SHA-256(beacon_epoch_seed ‖ "shard-committee" ‖ shard_id)
shard_committee[s] = select_m_creators(shard_seed, validator_pool_size, K_per_shard)
```

The same `select_m_creators` function used in single-chain mode. The salt makes shards' committees independent. The delay-hash sequentiality (§10.3) prevents adversaries from grinding their stake to land on a target shard's committee — the next epoch's seed is not computable until the current epoch finalizes.

### 17.3 Account-to-shard assignment

```
shard_id(addr) = first_8_bytes_be(SHA-256(genesis_salt ‖ addr)) % S
```

`genesis_salt` is `GenesisConfig.shard_address_salt`, fixed at chain creation (32 random bytes). Stable for chain lifetime. `S` may grow at epoch boundaries via a beacon governance op (forthcoming).

### 17.4 Cross-shard transactions (planned)

Two-phase via beacon-mediated receipts:

1. User submits TRANSFER from `A_in_shard_0` to `B_in_shard_1`. Routed to shard 0.
2. Shard 0 includes the tx in its block, debiting A's balance. Emits `CrossShardReceipt{src=0, dst=1, ...}` in `receipts_consumed`.
3. Beacon picks up the receipt at its next block, includes in `receipts_published`.
4. Shard 1 reads the beacon, includes the receipt in its next block, crediting B's balance.

Cross-shard finality: `~3 × shard block time` (~2.7s on web profile). In-shard: `~1 × shard block time`. Atomicity is eventual consistency (debit-then-credit); atomic 2PC with timeout-revert is v3.

### 17.5 Current implementation state (rev.9)

The architecture is staged across multiple stages, each delivering standalone value:

| Stage | What | Status |
|---|---|---|
| **B0** | `ChainRole {SINGLE, BEACON, SHARD}` enum threaded through `GenesisConfig`, `Node Config`, JSON I/O | ✅ done |
| **B1** | Per-epoch + per-shard committee seed (`epoch_committee_seed(rand, shard_id)`), `current_epoch_index/rand` helpers, validator mirror | ✅ done |
| **B2a** | `genesis-tool build-sharded` produces `(1 beacon + S shard)` genesis files with distinct hashes | ✅ done |
| **B2b-lite** | RPC + log surface `chain_role` / `shard_id` / `epoch_index`. `tools/test_sharded_smoke.sh` boots beacon + shard side-by-side | ✅ done |
| **B2c.1** | `BEACON_HEADER` gossip message + storage skeleton | ✅ done |
| **B2c.2** | Shard-side header validation (sequential, prev_hash chain, K-of-K sigs) | ✅ done |
| **B2c.3** | `SHARD_TIP` gossip + beacon-side committee derivation + sig verify + tracking | ✅ done |
| **B2c.4** | `EquivocationEvent.shard_id` + `beacon_anchor_height` cross-chain provenance | ✅ done |
| **B2c.5** | HELLO role tagging, role-based gossip filter, `beacon_peers`/`shard_peers` config, `tools/test_zero_trust_cross_chain.sh` | ✅ done |
| **B2c.2-full** | Shards source committee rand from verified beacon header chain via `BlockValidator::resolve_epoch_rand` + `EpochRandProvider` callback. Production zero-trust path: both sides derive identical committees from the same beacon-anchored rand | ✅ done |
| **B3.1** | Salted-SHA256 address routing (`crypto::shard_id_for_address`); `CrossShardReceipt` struct + JSON I/O; `Block::cross_shard_receipts` field bound into block hash | ✅ done |
| **B3.2** | Source-shard apply suppresses local credit when `to` routes off-shard; producer emits receipt; validator verifies receipts match cross-shard tx subset one-for-one | ✅ done |
| **B3.3** | `CROSS_SHARD_RECEIPT_BUNDLE` gossip; beacon role acts as relay; destination shard filters + dedups + queues into `pending_inbound_receipts_` | ✅ done |
| **B3.4** | Destination shard producer bakes `inbound_receipts`; apply credits `to`; `applied_inbound_receipts_` ensures exactly-once delivery; validator dedup check | ✅ done |
| **B4** | `tools/test_cross_shard_transfer.sh` — 1 beacon + 2 shards M=K=1, grinds bearer wallets routing to each shard, asserts cross-shard TRANSFER credits destination end-to-end. Fixes cross-chain-only IN_SYNC bug | ✅ done |
| **B5** | Validator rotation across epochs; cross-chain slashing relay (equivocation evidence flows shard → beacon for stake forfeit). Rotation primitives are wired via B2c.2-full + epoch_committee_seed; full slashing relay test pending | 🔄 partial |
| **B6** | Hardening (state-sync snapshots, recovery, light clients, shard-count growth) | ⏳ pending |

`ChainRole = SINGLE` is the default. With S=1 and SINGLE, behavior is bitwise-identical to rev.8 — sharding is opt-in at genesis.

### 17.6 Censorship + safety claims under sharding

DHCoin's K-conjunction censorship resistance is **per-shard, per-epoch**. An adversary capturing a single shard's K-committee for an epoch can censor that shard's transactions for the epoch. Rotation at the next epoch boundary evicts them. Operator knobs:

- Larger `K_per_shard` — harder to capture.
- Shorter `E` — less window per capture.
- Larger `pool / S` ratio — captures need validators across multiple epochs to land enough on a target shard.

Per-block trust is observable via `consensus_mode`:

| Block | Safety | Censorship |
|---|---|---|
| Beacon | Unconditional (rev.7 MD) | K-conjunction over beacon committee |
| Shard MD | Unconditional (rev.8 MD) | K-conjunction over shard committee |
| Shard BFT | Conditional `f < N/3` + slashing | (1+K_eff/3)-conjunction over shard committee |

Applications choose which blocks they trust. Most blocks (steady state) are MD on both layers; BFT shard blocks are the tail-liveness fallback when a shard would otherwise stall.

---

## 17. Scope and Current Status

DHCoin's design intent is intentionally narrow: a **fork-free L1 payment + identity chain with mutual-distrust safety**. It is *not* trying to be Ethereum, not trying to be a DApp hosting platform, not trying to host arbitrary computation. This section is an honest accounting of what's actually built, what's in progress, and what's deliberately out of scope.

### 17.1 What DHCoin currently is good at

These work end-to-end today, with passing integration tests:

- **Permissionless payment system.** TRANSFER between named domains and anonymous bearer-wallet accounts. Censorship-resistant via K-of-K + union tx_root (any single non-Byzantine committee member can include any tx). Zero-trust safety (no protocol component trusts any participant).
- **Validator pool with cryptoeconomic accountability.** Validators register on-chain, can be staked or domain-anchored (§5.1). Misbehavior is detectable, slashable, and self-defeating regardless of adversary fraction (so long as ≥1 non-Byzantine validator remains in the registry).
- **Two-tier identity.** Registered domains (named, on-chain, eligible to validate) plus anonymous bearer-wallet accounts (Ed25519 pubkey-derived addresses; any user can self-issue). Both share the same balance/nonce namespace.
- **Page-reward system.** Genesis-pinned `block_subsidy` minted per block, split across the committee with fees. Native economic incentive for block production.
- **Per-height BFT escalation.** Default mutual-distrust K-of-K; falls back to BFT `ceil(2K/3)` + designated proposer when the eligible pool can't form K-of-K and the abort threshold has been met. Per-block `consensus_mode` tag lets observers reason about per-block trust.

### 17.2 Capability matrix

Status: ✅ done · 🟨 partial / in progress · ❌ not started · 🚫 deliberately out of scope

| Layer / Capability | Status | Notes |
|---|---|---|
| **Consensus / safety** | ✅ ~95% | K-of-K mutual-distrust, BFT escalation, zero-trust framing, equivocation slashing closed-loop |
| Block production + propagation | ✅ ~90% | 2-phase Contrib + delay-hash + BlockSig; gossip mesh; sync via chunked GET_CHAIN |
| Sybil resistance | ✅ ~95% | `STAKE_INCLUSION` + `DOMAIN_INCLUSION` |
| Slashing + disincentives | ✅ ~85% | Suspension + equivocation, both end-to-end |
| Identity / accounts | ✅ ~80% | Domains + anonymous bearer wallets |
| Native tx types | ✅ ~80% | TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE |
| Mempool / replace-by-fee | ✅ ~70% | Sequential nonce; no fee market or gas |
| CLI / wallet | ✅ ~75% | `dhcoin {account,send,send_anon,stake,show-block,chain-summary,validators,show-account,show-tx,...}` — block-explorer surface complete |
| **Scaling / sharding** | ✅ ~85% | B0/B1/B2a/B2b-lite + B2c.1-5 + **B2c.2-full** + **B3.1-3.4 cross-shard receipt loop end-to-end** + **B4 multi-shard test harness** all done. Cross-shard TRANSFER verified behaviorally |
| Cross-shard receipts | ✅ 100% | B3 complete (emit / relay / dst-credit / dedup) |
| Multi-shard production tooling | ✅ ~70% | `genesis-tool build-sharded`; cross-chain peering config; behavioral test. Production-grade orchestration scripts pending |
| Cross-chain validator rotation + slashing | 🟨 ~60% | Rotation wired via epoch-relative committee seed + B2c.2-full beacon-anchored rand. Cross-chain `EquivocationEvent` provenance fields done; full shard→beacon slashing-relay test pending (B5) |
| State sync (snapshots, pruning) | ❌ 0% | Full chain replay only; B6 |
| Light clients | ❌ 0% | B6, deferred |
| **Smart-contract execution layer** | 🚫 N/A | **Not in scope.** No EVM, no WASM, no gas. The chain handles native tx types only |
| Contract storage | 🚫 N/A | Implied by the above |
| Off-chain storage (IPFS/Arweave-style) | 🚫 N/A | Not in scope |
| Indexer (Graph-like) | ❌ 0% | Could be built externally |
| Block explorer | ❌ 0% | Could be built externally |
| SDK (JS/Python/Rust) | ❌ 0% | RPC over JSON exists; no client-side libraries |
| Bridges to other chains | ❌ 0% | Out of scope for v1; could be retrofitted |
| ZK / privacy | 🚫 N/A | Anonymous accounts are the privacy story; no ZK proofs |
| Oracles | 🚫 N/A | Not in scope |
| On-chain governance | ❌ 0% | Genesis-pinned constants; no on-chain proposals/voting |
| Frontend hosting | 🚫 N/A | Always external (e.g., IPFS); never on-chain |

### 17.3 Three honest interpretations of "% done"

The percentage depends on what frame of reference you pick:

- **Narrow ("fork-free L1 payment + identity chain")** → **~88–92% done.** Consensus is mature; cross-shard transactional loop closes end-to-end and is behaviorally verified (B0-B4 done); payments + identity work end-to-end. Finish B5 (cross-chain slashing-relay test) ~1 week, add basic state-sync snapshots (~1 week), and v1 ships.
- **Medium ("L1 + multi-chain scaling + DApp-execution-ready base")** → **~30-40% done.** Adds sharding completion, light clients, basic indexer, and a contract execution layer. Most of the missing work is the contract VM and supporting tooling.
- **Wide ("full DApp hosting platform comparable to Ethereum + IPFS + Graph + tooling ecosystem")** → **~5-10% done.** The contract VM, off-chain storage, indexer, SDKs, block explorer, bridges, governance, privacy, oracles — all absent. This is years of work for a small team and most of it is deliberately not on the DHCoin roadmap.

### 17.4 What DHCoin can host today

If you frame it as "what kind of DApp could be built on DHCoin as it stands":

- **Payment apps** — direct transfers between named domains + anonymous accounts. ✅
- **Validator-coordinated registries** — REGISTER + STAKE patterns can be repurposed for identity directories, DNS-record registries, reputation systems. ✅ partial.
- **Consortium settlement networks** — `DOMAIN_INCLUSION` chains where validators are publicly accountable organizations (banks, govt registries, etc.). ✅
- **Page-reward economies** — applications using the native subsidy + fee distribution as their incentive primitive. ✅
- **Anything stateless that fits the named-account balance model.** ✅

What it can't host:

- **Anything requiring computation beyond balance arithmetic** — needs a contract VM. ❌
- **Anything requiring large state** — REGISTER carries up to 32-byte payloads; tx payloads are tiny by design. ❌
- **Cross-application composability** — no contracts means no cross-app calls. ❌
- **Anything depending on off-chain data** — no oracle infrastructure. ❌

### 17.5 What's deliberately out of scope (and probably stays that way)

These are not "TODO" items — they're outside DHCoin's design intent:

- **Smart-contract VMs** (EVM, WASM). DHCoin's value proposition is censorship-resistant fork-free payments + identity, not arbitrary execution.
- **Off-chain storage layer** (IPFS, Arweave). Application-specific; users compose externally if they want it.
- **Bridges to other chains.** Could be built on top, not part of the core protocol.
- **On-chain frontend hosting.** Always belongs off-chain.
- **Oracle networks.** Application-specific; not a base-layer concern.
- **ZK / shielded transactions.** The anonymous bearer-wallet account model is the privacy story; no zero-knowledge layer planned.

A future fork or layer-2 of DHCoin could add these. The base protocol will not.

### 17.6 Realistic v1 release path

To ship v1 (the "narrow" ~80% scope above) the remaining work is roughly:

| Milestone | Estimate |
|---|---|
| Stage B2c.1-5 — cross-chain plumbing | ✅ DONE |
| Stage B2c.2-full — beacon-anchored committee rand | ✅ DONE |
| Stage B3 — cross-shard receipts (emit / relay / credit / dedup) | ✅ DONE |
| Stage B4 — multi-shard test harness; cross-chain-only IN_SYNC fix | ✅ DONE |
| Stage B5 — cross-chain slashing-relay test (rotation primitives done) | ~1d |
| Stage B6.basic — state sync snapshots | ~5d |
| Block-explorer CLI primitives (`status`/`peers`/`show-block`/`chain-summary`/`validators`/`show-account`/`show-tx`) | ✅ DONE |
| Light client primitives | ~5d |
| Deterministic-inbound-pool via Phase-1 contrib union (B3 hardening) | ~2d |
| Documentation / spec freeze | ~3d |
| Whitepaper PDF generation polish | ~1d |

Remaining: roughly **2-3 weeks** of focused work after the current state. The cross-shard transactional loop is functionally complete and behaviorally verified; what's left is mostly hardening, state-sync, and polish. None of this is contract execution; v1 ships as a payment + identity chain.

### 17.7 Honest framing

Calling DHCoin a "DApp hosting network" overstates what's built and what's planned. Calling it a "decentralized cryptocurrency with mutual-distrust safety" is accurate. Specific use cases that fit:
- Inter-organization settlement where payment + identity is the whole value prop.
- Censorship-resistant value transfer in environments where trust assumptions about validators are explicitly rejected.
- Federated registries where domain-anchored validators provide identity and the chain provides ordering + auditability.

If you need contracts, you'd build them on a different chain or build a layer-2 on top of DHCoin. The base protocol's job is to be very good at one narrow thing — fork-free payment + identity with cryptoeconomic safety — not to be everything.

---

## 18. Conclusion

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
