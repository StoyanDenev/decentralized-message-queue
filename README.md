# Determ

Determ contains a C++ ledger implementation (`determ`) and an experimental C99
two-participant commit/reveal driver (`determ-node`). They are separate executables
and protocols; the C99 driver has not replaced the C++ chain validator.

The C99 driver requires two commitments and two matching payload reveals. An
incomplete attempt returns an error; a caller can explicitly begin another attempt.
Its AES/SHA-256 evaluator is an experimental repeated-work function, with no proved
sequential-hardness bound or succinct proof. A completed evaluation is not an
accepted ledger block. The driver has no authenticated election, production block
validation, chain selection/reorganization, or cross-shard settlement.

The C99 node provides `get_shard_for_pubkey`, a read-only query using the existing
salted modulus map and canonical lowercase account addresses. Configure its local
inputs with `--routing-shards` and `--routing-salt`; defaults are one shard and a
zero salt. Responses identify these as local settings, not authenticated genesis
or enforced transaction ownership. The JSON-RPC server (`--rpc-port`) binds
127.0.0.1 and sends no CORS headers. See the [routing contract](docs/proofs/ShardRoutingSoundness.md#c99-local-routing-query-2026-09-22).

An optional bounded inbox now accepts signed, intra-shard anonymous transfers via
`submit_pending_transfer` and lists their canonical binary frames with
`get_pending_transfers`. Enable it with `--pending-genesis <64 hex>` alongside
`--rpc-port`; routing uses the same local count/salt. It checks signatures and
context before retaining up to four transactions per occupied shard, eight shards
per node. Responses say `state_validated:false`: balances, nonce readiness,
execution, persistence and gossip are not implemented by this inbox. The signed
preimage binds `genesis_hash` and `shard_id` (the chain identity decided in D23),
which the C++ `Transaction::signing_bytes()` does not sign (S-103), so the C99 and
C++ transaction formats differ. See the
[pending contract](docs/proofs/ShardRoutingSoundness.md#c99-signed-pending-inbox-2026-09-22).

`test-dsf-k2-recovery` separately tests finite sibling selection and state replay,
including late smaller-header correction and descendant revalidation. Its fixed
eligibility/receipt fixtures are model assumptions; it does not implement production
chain recovery. See the [DSF scope](docs/proofs/DSF-SPEC.md#104-bounded-c99-fork-recovery-model).

[ADR-004](docs/decisions/ADR-004-Fault-Model.md) records PoSW as an architectural
direction with unresolved security obligations; no PoSW chain protocol is
implemented. Claims of unconditional liveness, 1-of-2 completion, fork-free C99
finality, zero bias, hardware-independent timing, and MEV prevention are withdrawn.
See the [C99 contracts and refutations](docs/proofs/K2_VDF_Soundness.md)
and [security ledger](docs/SECURITY.md). [Temporal sharding](docs/decisions/ADR-005-Temporal-Sharding.md)
is at its design gate; it does not deprecate the C++ beacon or EXTENDED topology.

For protocol comparisons, start with the [preserved K=2 requirements and K-of-K
comparison](docs/decisions/ADR-004-Fault-Model.md#6-preserved-k2-design-for-comparison-2026-09-24).
It separates owner decisions, local-model evidence and unresolved production proofs.
The [open K=2 design holes](docs/decisions/ADR-004-Fault-Model.md#7-open-design-holes-2026-09-24)
list the outstanding proofs and specification details needed to qualify the design.

The owner has adopted the [combined development plan](docs/decisions/ADR-004-Fault-Model.md#84-adopted-development-plan-2026-09-24):
two unanimous co-creators over one canonical receiver-validated body/context,
joint receipt, the selected election/VDF, external recovery witnesses and checkpoint
settlement, with reviewed K-of-K validation/encoding/persistence principles. First
specify and prove the one-shard receiver/resource and recovery contract; then build
the smallest qualified component. This is a development direction, not a complete
security proof or production release. The [Claude handoff](docs/C99-MINIX-PORT.md#12-claude-commit-and-development-handoff-2026-09-24)
records the review, local-commit and first-development instructions.

The **current implementation target** is a strict freestanding C99 unikernel/MicroVM
with no libc, external crypto/network library or heap allocation. Bounded storage,
explicit platform contracts and compiler/target-specific security evidence are
required. This supersedes the earlier hosted Minix/POSIX deployment plan; existing
hosted executables remain reference and test implementations under the
[port-then-retire rule](docs/C99-MINIX-PORT.md#0-status-on-2026-09-23--what-exists-and-the-retirement-rule).
The [foundation examples and validation](docs/C99-MINIX-PORT.md#11-freestanding-unikernel-foundation-owner-goal-2026-09-24)
are complete within their stated scope; the complete target image is not built or
qualified. Existing Argon2id and libc-backed crypto helpers require a conforming,
independently qualified solution before admission to that target; the goal does not
waive its secret-independent memory-access requirement for them.

Run the C99 checks through the project CI entry point:

```sh
bash tools/ci_local.sh --c99 --jobs 4
bash tools/ci_local.sh --c99-sanitize --jobs 4   # the same targets under ASan + UBSan
bash tools/ci_local.sh --c99-mutants --jobs 4
bash tools/ci_local.sh --freestanding-examples # isolated foundation evidence
```

The arithmetic and local state-machine tests are portable C99. The network driver
and its live socket tests currently use POSIX transport; Windows transport support
is not established by these checks. On a POSIX host `--c99` builds and runs 21
targets (10 portable, 11 POSIX-only; a Windows shell reports the 11 as
platform-skipped), and `--c99-mutants` runs the isolated mutation gate. Each of
these targets compiles as strict ISO C99 (no GNU extensions) with
`-Wall -Wextra -Werror -pedantic` on GCC and Clang (`determ_c99_strict` in
`CMakeLists.txt`); the shared `determ-crypto-c99` library, which the C++ binaries
also link, keeps its own settings. There is no root Makefile. The ordinary
`ci_local.sh` path still tests the C++ implementation. Pull-request CI also
configures a separate Ubuntu 24.04 job for the C99 suite (GCC and Clang builds,
then GCC under ASan + UBSan), isolated mutation checks and documentation guards;
local results do not substitute for that runner's result.

## C++ implementation reference

The remaining overview describes the existing C++ payment/identity chain and its
recorded design. Its committee, beacon, storage and wire rules do not apply to the
C99 experiment. Security claims remain subject to the assumptions and open findings
in the decision log and security ledger; they are not a proof of launch readiness.

**Version v1.1 (mainnet launch target)** · [![License: Multi-licensed](https://img.shields.io/badge/License-Multi--licensed-blue.svg)](LICENSING.md)

> **Scope, briefly:** Determ is a **base-layer fork-free L1 payment + identity chain** with mutual-distrust safety. It is **not** a general DApp hosting platform — there is no Turing-complete smart-contract execution layer (no EVM, no WASM, no gas), no off-chain storage integration, no bridges. Native transaction types cover base payments and identity (TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE), atomic multi-operation composition (COMPOSABLE_BATCH), canonical encrypted DApp messaging (DAPP_REGISTER, DAPP_CALL), post-quantum bearer payments (PQ_TRANSFER via ML-DSA / FIPS 204), confidential transactions (SHIELD, UNSHIELD, CONFIDENTIAL_TRANSFER with DCT1 Pedersen/range proofs), audit trail management (ROTATE_AUDIT_KEY, LOG_AUDIT_ACCESS, REGISTER_NOTE_KEY), governed configuration (PARAM_CHANGE) and under-quorum shard merges (MERGE_EVENT). The full breakdown of what fits and what doesn't is in [§17 Scope](#17-scope).
>
> **For operators:** see [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for a 5-minute walkthrough and [`docs/CLI-REFERENCE.md`](docs/CLI-REFERENCE.md) for the full command list.
>
> **For protocol researchers / auditors:** see [`docs/WHITEPAPER-v1.x.md`](docs/WHITEPAPER-v1.x.md) for the standalone academic-style technical paper, and [`docs/proofs/`](docs/proofs/README.md) for the formal-verification track (F0 + FA1–FA12 analytic proofs, FB1–FB4 TLA+ specs).
>
> **v1.1 is THE LAUNCH** — single mainnet event, no test/main net before v1.1. All substrate bundles (per [`docs/proofs/IMPLEMENTATION-SEQUENCING.md`](docs/proofs/IMPLEMENTATION-SEQUENCING.md) Bundles 1-5) and application bundles (per [`docs/proofs/V1.1-PLAN.md`](docs/proofs/V1.1-PLAN.md) Bundles A-E) ship together at v1.1 genesis.
>
> **Three properties locked at v1.1 launch (immutable for chain lifetime):**
> 1. **God protocol** (Szabo sense) — K-of-K mutual-distrust default; no trusted third party can be subverted. Default mode; §6.2 Quorum Liveness OPTIONAL is the only documented relaxation, opt-in at genesis. Block randomness uses v1.x commit-reveal (commitment-bound; selective-abort bias remains open); block authentication uses K individual Ed25519 signatures.
> 2. **Decentralized identity provider** — the mutual-distrust IdP of *Identity provider in an environment of mutual distrust* (academia.edu/80188125), realized as **threshold-OPAQUE**: OPAQUE in place of the paper's SRP, and a **t-of-n, unordered** threshold OPRF (any t of n servers, any order; no server below t learns the password) in place of the paper's sequential all-node chain. The relying-party token is the paper's **hash challenge-response** over the handshake-co-generated keys — no signature, **no FROST**, no block co-sign. Uses only already-shipped primitives (Ed25519, P-256 §3.9b OPRF, SHA-256/HKDF, DAPP_REGISTER/DAPP_CALL). See `docs/proofs/v2.25-DSSO-DAPP-SPEC.md`.
> 3. **Perfect forward secrecy** — v2.22 per-tx PFS via OTPK; amounts irrecoverable after consumption even under future master-key compromise. *(Design-locked; Phase-2 build, not yet shipped.)*
>
> **No migrations post-launch.** Post-v1.1 the protocol is locked: no schema migrations, no wire-format breaks, no coordinated consensus-rule changes. In-protocol mechanisms (ROTATE_VIEW_MASTER, ROTATE_AUDIT_KEY, MANIFEST_UPDATE, PUBLISH_OTPK_BATCH) and additive-only changes (new optional fields, new tx types legacy validators fail-closed on) remain allowed. The constraint is load-bearing for **formal verifiability**: the FA1-FA12 analytic proofs, FB1-FB4 TLA+ specs, and ~100 `docs/proofs/` soundness theorems target a *fixed* protocol — migrations would force the entire verification track to rebuild against a new target. Lock once at v1.1, never touch, trust forever.

---

## Abstract

The C++ implementation uses a registration-gated, two-phase K-of-K committee protocol. Each block is produced by a deterministically rotated **K-committee** drawn from the registered creator pool. The protocol runs in two phases per block: a **Contrib phase** in which each committee member commits transaction proposals plus a Phase-1 commitment to a fresh per-round secret (`SHA256(secret ‖ pubkey)`) under an Ed25519 signature, and a **BlockSig phase** in which each member reveals their secret alongside an Ed25519 signature over the block digest. A block is final when all K committee signatures are present and all K secrets verify against the Phase-1 commitments.

Two design choices distinguish Determ from prior fork-free systems:

1. **Commitment binding.** Phase 1 commits to a secret; Phase 2 verifies its opening. This prevents changing the committed secret under the hash assumption. It does not stop a last revealer, who knows its own secret, from computing the result and withholding an unfavorable outcome.

2. **Union transaction set within the committee.** A transaction is included in block `n` if at least one committee member contributes it in Phase 1. Censorship requires every committee member to collude — a `K`-conjunction property that scales exponentially in `K`.

Identity is two-tiered: **registered domains** (named, staked, eligible to be selected as creators) and **anonymous accounts** (Ed25519-keyed bearer wallets, address-derived from public key). Both transact under the same Ed25519 signing scheme; only registered domains participate in consensus.

---

## 1. Introduction

Most blockchain consensus protocols separate block proposal from finalization. A single leader proposes a block; a committee, a validator set, or accumulated proof-of-work finalizes it. This architecture introduces either probabilistic finality (Bitcoin), multi-round voting latency (Tendermint, Ethereum PoS), or a trusted-leader failure mode (Solana, early DPoS systems).

Determ takes a different approach: a small committee of `K` creators co-produces every block, and each block carries `K` independently-signed authenticators. A valid block requires all `K` signatures over the same digest. There is no proposer to censor and no quorum threshold to game — the only way to prevent block production is to make at least one committee member silent, which the protocol detects and reroutes around.

The C++ protocol derives randomness from ordered committed secrets. Commitment binding constrains the opening; it does not establish an unbiased distribution of completed rounds. Selective abort remains an explicit limitation (SECURITY.md S-077).

This design has three consequences worth highlighting:

1. **Same-committee forks need every member to double-sign.** Two blocks at the same height from the same committee would require every member to sign two different digests — which honest committee members refuse to do — and a digest mismatch is detected by the missing or invalid signatures. Blocks from different committees at one height (different abort histories) are excluded only under the §2 safety assumption, and the node keeps a deterministic fork choice for same-height siblings (`Chain::resolve_fork`, S-029).

2. **Censorship resistance is structural.** Each committee member independently proposes transactions in Phase 1. The block's transaction root is the union of all committee proposals. A transaction is excluded only if every one of the `K` committee members colludes — probability `(f/N)^K` for adversarial fraction `f/N`.

3. **Randomness inputs are commitment-bound.** A participant cannot substitute an opening, but can withhold it. Publication order and retry policy matter to bias.

---

## 2. System Model

**Participants.** Two classes of participants exist:

- **Registered domains.** A node identified by a human-readable domain string. Each holds an Ed25519 keypair, registers on-chain via a REGISTER transaction, stakes at least `MIN_STAKE`, and is eligible for committee selection.
- **Anonymous accounts.** A user-side keypair. Address is derived directly from the Ed25519 public key (`0x` + 64 hex chars). Anonymous accounts may send TRANSFER, the confidential types (SHIELD, UNSHIELD, CONFIDENTIAL_TRANSFER) and ROTATE_AUDIT_KEY, LOG_AUDIT_ACCESS and REGISTER_NOTE_KEY — node ingress currently admits only TRANSFER from them (S-065) — but cannot stake, register or be selected as creators.

Transactions from both account types are signed under Ed25519. The chain validates signatures uniformly; the differences are consensus eligibility and the transaction types each may send.

**Trust model — zero-trust system, mutual-distrust environment.** Determ is a **zero-trust system internally**. The protocol itself assumes nothing about any participant's honesty, intent, or alignment with chain progress. It only enforces rules: verify signatures, run the consensus state machine, propagate messages. No participant — including beacons, validators, users, or operators — is granted any trust by the protocol. Every actor is treated as potentially adversarial.

**All trust comes from outside the system, never from within it.** External observers (users, regulators, auditors) may form their own beliefs about specific validators based on external evidence — public domain identity, off-chain reputation, regulatory accountability, code review of the validator software, etc. — and those beliefs may inform the observer's choice of which chain to use, which validators to peer with, which blocks to consider final beyond protocol guarantees. But none of those external beliefs are encoded into the protocol. The protocol works identically whether observers trust validators or not.

Determ contrasts here with classic BFT protocols (Tendermint, HotStuff, PBFT) that assume participants pursue a **common goal** — *advance the chain* — and bound the fraction that can defect from that goal (typically `f < N/3`). BFT framings smuggle a soft trust assumption into the protocol: "≥2/3 of validators want the chain to function." Determ assumes nothing of the kind. **Validators have no common goal.** Each is a self-interested actor pursuing its own block reward. They do not cooperate voluntarily; they cooperate **involuntarily and only at the moment of block propagation**, because the protocol's K-of-K and union-tx-root rules make individual defection either rewardless (no share of the block) or impotent (a refusal to include a tx is overridden by anyone else who does include it).

This is "mutual distrust" — every validator watches every other, assumes every other is potentially adversarial, and the protocol is robust *because* the rules align self-interested behavior into chain progress without requiring shared intent.

### 2.1 The actual decentralization threshold

Determ's censorship-resistance property holds **as long as at least one validator in the registry is rule-following**; its safety claims need more — the honest-signing and committee-intersection hypotheses stated under "Safety assumption" below:

- **At least 1 rule-following validator anywhere in the registry → mutual-distrust environment.** The K-of-K committee rotates over time, so a single rule-following validator eventually appears on any committee. Their Phase 1 contribution unions any censored tx into the block (mutual inclusion). Their refusal to sign malformed proposals is a veto on those they reject (mutual veto). The chain stays open and uncensored.
- **0 rule-following validators (100% adversarial capture) → fully controlled adversarial network.** No protocol provides safety in this case — the attacker controls every committee member at every height and can produce any block they want. This is the universal limit beyond which no consensus protocol can function. Determ makes no claim here.

Two important caveats on this threshold:

1. **"Rule-following" is not "honest."** The protocol doesn't require *anyone* to be honest in any moral sense — it only requires that *some* participant follows protocol rules (for whatever reason: self-interest, regulation, mistake, ethics). Following the protocol is rationally cheaper than deviating, so the property holds even under fully self-interested rational actors.
2. **The threshold is a property of the system, not a protocol assumption.** The protocol does not *believe* that ≥1 validator is rule-following — it doesn't believe anything. The threshold is what an *external observer* needs to assume in order to expect the chain to remain useful. If the observer doesn't believe even ≥1 validator follows the protocol, they don't use the chain. That choice happens outside the system.

The C++ committee protocol has conditional safety and liveness under its recorded assumptions. The C99 two-participant experiment supplies no network-liveness or finality guarantee.

### 2.2 The three structural properties

The mutual-distrust model rests on:

1. **Mutual veto via K-of-K signatures.** A block requires every committee member to sign the same digest. Any single member can refuse — they cannot unilaterally produce a block, but they also cannot unilaterally allow a malformed one. Refusal is detectable (Phase 1 absence triggers an `AbortClaimMsg` quorum, recorded as an `AbortEvent` in the next block) and costly (suspension from committee selection for an exponentially growing window; the round-1 stake deduction was retired 2026-09-16, D13).

2. **Mutual inclusion via union tx_root.** A transaction enters the block if **any** committee member contributes it in Phase 1 — not just a majority. To censor a transaction, every member must omit it; a single defector breaks the censorship. Defection is the rational individual choice (a defector who includes the tx earns its fee and avoids being implicated in censorship). The total collusion required to censor is fragile because each colluder has standing incentive to defect.

3. **Limits of hiding.** A participant may lack other secrets before their release, but a last revealer already knows its own secret. Once it sees the other openings it can evaluate the output before deciding to publish. Preimage resistance supplies no selective-abort defense at that point.

### 2.3 Trade-off vs. BFT

The following are C++ design objectives, subject to the security ledger and their individual proof assumptions:
- **Stronger censorship resistance** — `(f/N)^K` per round, exponential in K, no leader bottleneck.
- **Conditional committee safety** — requires the committee-intersection and honest-signing assumptions recorded in the proof set; signature unforgeability alone does not prevent conflicting signatures.
- **Lower honest-fraction requirement** — `≥1 of N` honest, not `≥2/3 of N` honest, for the chain to remain useful.
- **Clean economic story** — every participant pursues block rewards. Deviation either earns no reward (refusal → no share), is recorded as evidence (equivocation — an on-chain record with no L1 consequence since 2026-09-16, DECISION-LOG D4; the designated input to an L2 policy, D22, that is not yet designed), or is futile (censorship → defected by any honest member). No "honest majority assumption" is bolted on.

**Network assumptions.** We assume a partially synchronous network: messages are delivered within some known bound `Δ` during normal operation. The protocol tolerates periods of asynchrony by aborting and restarting rounds. Safety does not require synchrony — an invalid block is rejected regardless of message ordering.

**Adversary model.** Concretely, an adversary may control any subset of `N` registered nodes (no fraction bound assumed for safety). Corrupted nodes may deviate arbitrarily from the protocol, delay messages within `Δ`, and choose which Phase 1 contributions to publish. The adversary cannot forge Ed25519 signatures or break SHA-256 (preimage or collision resistance). Liveness — but not safety — degrades as adversary fraction approaches 100%.

**Safety assumption.** No-two-finalized-blocks claims require explicit honest-signing and committee-intersection hypotheses. They do not follow unconditionally from the K-of-K signature check, and they do not apply to the C99 prototype.

**Liveness assumption.** Liveness requires that at least one committee can be formed from `K` honest, online committee members. With `M_pool` registered nodes and per-node availability `(1-p)`, the probability that a specific committee is fully live is `(1-p)^K`. The committee is redrawn per epoch and on abort re-selection (§10.2); persistent absence triggers suspension.

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
    type:    uint8         // 0..17 native transaction types (see below)
    from:    string        // sender address (domain name or anonymous 0x...)
    to:      string        // recipient address (TRANSFER, DAPP_CALL, UNSHIELD)
    amount:  uint64
    fee:     uint64
    nonce:   uint64        // sequential per-account
    payload: []byte        // type-specific canonical binary payload
    sig:     [64]byte      // Ed25519 signature over signing_bytes()
    pq_auth: []byte        // optional DPQ1 post-quantum auth envelope (PQ_TRANSFER only)
    hash:    [32]byte      // SHA-256 of signing_bytes()
}
```

Nonces are sequential (account state tracks `next_nonce`), preventing replay within one chain. `signing_bytes()` binds no chain identity, so a signed transaction is also valid on any other chain or shard where `(from, nonce)` matches (S-103, open; the genesis-hash and shard-id binding is decided in D23, not landed). The verifier does not recompute `hash` for transactions inside a block (S-101, open).

**Native Transaction Types (`TxType`):**
- `0: TRANSFER` — Direct balance transfer between accounts (domain or anonymous).
- `1: REGISTER` — Creates a domain identity (create-only, nonce 0). Binds domain name to 32-byte Ed25519 key. Rejects small-order torsion keys (S-068).
- `2: DEREGISTER` — Deactivates validator eligibility and initiates unbonding delay for staked bond.
- `3: STAKE` — Locks validator stake from the sender's balance. Accepted only from a domain already in the eligible registry: under `STAKE_INCLUSION` the STAKE of a registered-but-unstaked domain is rejected ("tx sender not in registry"), so no domain can join after genesis (S-069, open; the D6 join rule is decided, not landed — §5.2).
- `4: UNSTAKE` — Moves locked stake back to the domain's balance once `block_index >= stake_unlock_height`. That height stays `UINT64_MAX` until DEREGISTER sets it, so an active validator cannot unstake any amount; a deregistered domain can UNSTAKE after the unbonding delay (D7 / S-067, partial — the unlocked balance cannot be moved by any later transaction; §5.3).
- `5: REGION_CHANGE` — Reserved for epoch-boundary regional rebalancing.
- `6: PARAM_CHANGE` — Multisig parameter governance under `governed` mode ($M$-of-$N$ threshold signatures over whitelisted parameters).
- `7: MERGE_EVENT` — Under-quorum shard merge coordination event under `EXTENDED` sharding mode.
- `8: COMPOSABLE_BATCH` — Serialized batch of inner transactions executed within an atomic scope; inner transactions roll back atomically on any failure while outer submitter pays block space fee.
- `9: DAPP_REGISTER` — Registers or updates a DApp service entry in `dapp_registry_` (service public key, endpoint URL, routing topics, and metadata).
- `10: DAPP_CALL` — Sends an authenticated, canonical encrypted payload to a registered DApp with optional direct payment.
- `11: PQ_TRANSFER` — Post-quantum bearer transfer authenticated by an ML-DSA (FIPS 204) public key committed to by a PQ anonymous address, carried in `pq_auth`. Non-PQ types carrying `pq_auth` are strictly rejected (D9 / S-057).
- `12: SHIELD` — On-ramp from transparent account into confidential commitment pool, proving value $A$ matches Pedersen commitment $C$.
- `13: UNSHIELD` — Off-ramp from confidential pool back to transparent account, consuming note commitment $C$ as nullifier with replay protection.
- `14: CONFIDENTIAL_TRANSFER` — Confidential-to-confidential transfer with hidden amounts, verified via DCT1 Pedersen commitments and Bulletproof range proofs.
- `15: ROTATE_AUDIT_KEY` — Rotates or revokes the account's standing view-master audit key for regulatory inspection (A2).
- `16: LOG_AUDIT_ACCESS` — Records on-chain disclosure proof to an auditor ("audit the auditors"), incrementing the account disclosure count.
- `17: REGISTER_NOTE_KEY` — Publishes the account's P-256 encrypted note public key to allow senders to deliver confidential notes.

**Anonymous Address Validation:** Anonymous addresses (`0x...`) are validated against Ed25519 small-order curve points. Transactions from 8-torsion points are rejected fail-closed under consensus (D10 / S-072).

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
    claims        : AbortClaim[]  // max(2, K-1) signed claims forming the quorum
}
```

A round aborts when `max(2, K-1)` distinct committee members (`K-1` for `K ≥ 3`; unsatisfiable at `K = 2`, S-044) each broadcast an `AbortClaimMsg` against the same missing creator at the same round. The aggregated quorum is recorded as an `AbortEvent` baked into the next finalized block.

The claim list is a **typed** vector of the six consensus-bound fields, carried and hashed as one canonical fixed-layout binary encoding — `[count u16 LE]` then, per claim, `[block_index u64 LE][round u8][prev_hash 32][ed_sig 64][len u8]missing_creator[len u8]claimer`. Those exact bytes are both the `hash_abort_event` digest preimage (domain `DTM-F2-ABORT-v2`, recomputed identically by the light client) and, hex-wrapped, the block-container value, so the stored form and the hashed form cannot drift. Decoding is fail-closed with exact-consumption semantics. The per-claim Ed25519 signature covers `(block_index, round, prev_hash, missing_creator)` only — never any serialization.

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
    equivocation_events: []EquivocationEvent  // baked evidence; an on-chain record only, apply moves no state (§5.4, §15)
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
initial_state[] ‖
partner_subset_hash    [bound only when non-zero — R4 Phase 3 backward-compat] ‖
state_root             [bound only when non-zero — S-033 v2.1 backward-compat]
```

This is broader than `block_digest` (§7.4), which is what committee members sign in Phase 2. `block_digest` excludes `delay_output` and `creator_dh_secrets` so members can sign at Phase-2 entry without waiting for the K reveals to gather; `signing_bytes` includes them so the final block identity uniquely binds the post-reveal randomness output.

### 3.7.2 Block Size and Storage Integrity

- **No consensus block-byte cap (S-057, partial):** no rule in `BlockValidator::validate` bounds a block's encoded size, so a block that passes validation can exceed the 4 MB wire cap for BLOCK messages (§12.2) and then cannot be relayed. The consensus cap matching the wire limit is decided (D9 / R-7) but not landed. D9's other rule is in code: a non-PQ transaction carrying a non-empty `pq_auth` is rejected by the verifier and by the ingress mirror.
- **Storage Integrity & Continuity (S-084):** `Chain::load` and the offline text export (`Chain::export_store_json`) check every stored block record for height continuity (`b.index == i`), a zero `prev_hash` at genesis and hash linking (`b.prev_hash` equals the previous record's hash). A missing, corrupted or non-linking block file throws, so the node fails closed on startup.

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
| **`STAKE_INCLUSION`** (default) | 1000 (configurable) | Capital lock-up `min_stake × N` | Abort suspension only (the round-1 stake deduction was retired — D13, 2026-09-16; equivocation carries no L1 stake consequence — D4, 2026-09-16) |
| **`DOMAIN_INCLUSION`** | 0 | Domain registration | Abort suspension only (equivocation carries no L1 registry consequence — D4) |

**Why the decentralization claim is mode-invariant:** Determ's K-of-K mutual veto plus union tx_root means a tx is included if **any single committee member** adds it to their Phase-1 hash list. A single honest validator anywhere in the registry, given enough rounds, eventually rotates onto a committee and unions the tx into a block. Censorship would require **total collusion of every validator that ever rotates onto any committee** — structurally impossible without 100% capture of the registry. This property is a function of K-of-K + union + rotation, not of the inclusion mechanism. Both `STAKE_INCLUSION` and `DOMAIN_INCLUSION` deliver it equally.

The choice between modes is operational: which Sybil-resistance medium and disincentive currency the deployment prefers. Stake is the natural choice for chains where the native token has economic weight; domain-based inclusion is the natural choice for deployments where on-chain economics doesn't yet exist or where validator identities are intentionally public for accountability.

### 5.2 Registration

A node registers by broadcasting a REGISTER transaction whose payload is its 32-byte Ed25519 public key (create-only since V-REG-1, 2026-09-15: one REGISTER per domain name, ever). The transaction is itself signed with the corresponding private key, proving possession. Small-order torsion keys are strictly rejected (S-068).

Registration takes effect after a randomized 1–10 block delay derived from `(tx.hash || cumulative_rand)`. This prevents a registrant from timing entry to guarantee selection in a chosen round.

Under `STAKE_INCLUSION` (the default) registration alone does not make a node eligible for committee selection, and the verifier rejects every transaction from a registered-but-unstaked domain ("tx sender not in registry") — including the STAKE that would make it eligible. The validator set is therefore closed at genesis (SECURITY.md S-069, open). The owner decision to accept STAKE and its funding TRANSFER from such a domain (D6 / R-12) is decided but not landed.

In `DOMAIN_INCLUSION` chains the convention is that `tx.from` is a real DNS name (e.g., `validator1.example.com`). The protocol does not enforce DNS validity — that's an off-chain concern (operators may verify via DNSSEC TXT records pointing to the on-chain `ed_pub`). Mismatches surface as governance issues, not protocol violations.

### 5.3 Stake and Unbonding Exit

Eligibility requires `stake[domain] ≥ chain.min_stake()`. In `STAKE_INCLUSION` mode this is `min_stake = 1000` (configurable per chain at genesis). In `DOMAIN_INCLUSION` mode `min_stake = 0` and the gate is skipped entirely — registration alone suffices.

**Committee-intersection bound (S-054, partial).** Genesis validation requires `2K > M_pool` over `m_creators` (with `K ≤ M_pool` checked at node start, §4), so any two `K`-subsets of an `M_pool`-sized pool overlap. No rule bounds the eligible pool `N(h)` from which committees are actually drawn: there is no genesis check against the initial creators, no assertion at committee selection (§6) and no STAKE cap. Enforcing `2K > N(h)` is decided (D5a / R-4) but not landed. An overlap of `2K − N(h)` members would not by itself make a shared member honest; the safety hypotheses are stated in §2.

**Exit (D7 / S-067, partial).** Stake stays locked while a domain is registered: `unlock_height` is `UINT64_MAX` until DEREGISTER sets it to `inactive_from + unstake_delay`, so an active validator cannot UNSTAKE any amount. From `block_index >= stake_unlock_height(domain)` the deregistered domain may submit UNSTAKE — the only transaction type the verifier accepts from a registered domain outside the eligible registry — authenticated by its registered key. The amount is credited to the domain's balance, which no later transaction can move: every other type from that domain, including COMPOSABLE_BATCH inners, is still rejected ("tx sender not in registry").

### 5.4 Suspension and equivocation evidence

A registered, eligible domain is **suspended** from selection if it has any Phase 1 abort against it in chain history; the suspension window grows exponentially with repeat offenses:

```
suspension_blocks(count) = min(BASE × 2^(count-1), MAX)
BASE = 10, MAX = 10000
```

Only **Phase 1** aborts (`round=1` AbortEvents) count toward suspension. Phase 2 aborts can fire on a healthy creator when its block-sig arrival is delayed past the timer (timing skew); using them would inflate false-positive suspensions and harm liveness without improving censorship guarantees.

A domain that **equivocates** has the double-sign proof recorded on chain as an `EquivocationEvent` — an evidence record for the L2 policy that carries **no L1 consequence** (owner decision 2026-09-16, DECISION-LOG D4: no stake forfeiture, no registry deactivation). The protocol detects two equivocation surfaces, both checked by the same V11 rule (two signed openings at the same height and round generation with different body roots, both verifying under the same registered key against the digests the validator derives from them):

1. **BlockSigMsg-level (rev.8)**: the validator signs `compute_block_digest(b)` for two different block bodies at the same height. Detection in `Node::apply_block_locked`.
2. **ContribMsg same-generation (S-006 closure)**: the validator signs `make_contrib_commitment(...)` for two different `(tx_hashes, dh_input)` snapshots at the same `(block_index, prev_hash, aborts_gen)`. Detection in `Node::on_contrib`.

Both detection paths feed the same `EquivocationEvent` channel; an external implementer must wire both to record all equivocation surfaces. A block may carry at most `EQUIVOCATION_EVENTS_PER_BLOCK_MAX = 16` events and no duplicate event; the verifier rejects a block that breaks either rule (O-1 step 3b). The record is the designated input to the L2 bond policy (D22), which is not yet designed; until it exists, equivocation has no consequence anywhere.

---

## 6. Committee Selection

Given the registry at the chain's current height (sorted deterministically by domain), `current_aborts` for the in-flight round, and the epoch seed `epoch_committee_seed(epoch_rand, shard_id)` — `epoch_rand` being the `cumulative_rand` of the block before the current epoch opens (in epoch 0, of the previous block; on a shard, the beacon's — §16.2):

```
excluded   = {ae.aborting_node : ae in current_aborts}
available  = registry \ excluded
effective_rand = epoch_committee_seed(epoch_rand, shard_id)
for ae in current_aborts:
    effective_rand = SHA-256(effective_rand ‖ ae.event_hash)
indices    = select_m_creators(effective_rand, |available|, K)
committee  = [available[i] : i in indices]
```

`select_m_creators` uses a deterministic hybrid (S-020): rejection sampling with a counter when `2K ≤ N` (cheap path, expected `O(K)` hashes, no allocation), or a partial Fisher-Yates shuffle when `2K > N` (bounded `O(N)` setup + exactly `K` hashes, no rejection spin even at `K = N − 1`). Both branches are pure functions of `(random_state, N, K)` so every node picks the same branch and the same indices. Excluding aborted-this-height domains from the local pool ensures committee re-selection after an abort doesn't re-pick the same silent creator before the chain-baked suspension takes effect on the next finalized block. The validator reproduces the same selection given a block's `abort_events` field.

**No pool-size assertion (S-054, partial).** Neither the producer's selection (`Node::check_if_selected`) nor the verifier (`BlockValidator::check_creator_selection`) bounds `|available|` against `2K`; the D5a assertion at selection is decided but not landed (§5.3).

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

The transition is immediate (no wall-clock delay). The commit-reveal binding hides the outcome at commitment time: in Phase 1 each member's secret is sealed under `SHA256(secret ‖ pubkey)`, so when a member decides whether to publish their commitment they cannot predict the eventual `R` — the K−1 other secrets remain uniformly random under SHA-256 preimage resistance. It is no defense at Phase 2: a last revealer can compute `R` before deciding to reveal (§10.3, S-077).

### 7.3 Latency optimizations

- **Buffer-and-replay.** `BlockSigMsg`s that arrive before this node has assembled its own K Phase-1 contribs are buffered and replayed once the round transitions into Phase 2.
- **Round pipelining.** Round `n+1`'s Phase 1 starts immediately after applying block `n` locally; previous-round gossip propagation continues in parallel.
- **Own-Contrib pre-publish.** A creator's own Phase 1 contribution can be assembled and broadcast as soon as `prev_hash` is known, eliminating own-side latency from the Phase 1 budget.

### 7.4 Phase 2 — BlockSig (reveal)

Each committee member signs `block_digest` under its Ed25519 key and broadcasts `BlockSigMsg` carrying the **revealed** `dh_secret`. Other members verify `SHA256(dh_secret ‖ signer.pubkey) == sender's Phase-1 dh_input`, rejecting on mismatch.

`block_digest` is the SHA-256 of `idx ‖ prev_hash ‖ tx_root ‖ delay_seed ‖ consensus_mode ‖ bft_proposer ‖ creators[] ‖ creator_tx_lists ‖ creator_ed_sigs ‖ creator_dh_inputs`. Note it **excludes** `delay_output` and `creator_dh_secrets` so members can sign at Phase-2 entry without waiting for the K reveals to gather; the final `delay_output = SHA256(delay_seed ‖ ordered_secrets)` and the secrets themselves are bound into the block hash via `signing_bytes()` instead.

When all `K` BlockSig messages are present (and all K secrets verify), the node responsible for finalization assembles the canonical block body (transactions resolved deterministically from `union(creator_tx_lists)` and the local mempool, sorted by `(from, nonce, hash)`), populates `body.state_root` via a tentative-chain dry-run (S-033 v2.1 / S-038 — the post-apply state Merkle root that binds the block to a specific state-after-apply outcome), and applies it. Peer nodes receiving the gossiped block independently re-derive `state_root` over their own apply and reject if the value diverges — this is the apply-layer closure of S-030 D1/D2 (any divergence between honest nodes surfaces immediately rather than silently corrupting state).

### 7.5 Abort

If Phase 1's `tx_commit_ms` timer fires before all `K` contribs arrive, every committee member who has its own contrib but not the missing creator's broadcasts an `AbortClaimMsg` against the missing creator. When `max(2, K-1)` distinct claims are gathered locally (an `AbortEvent`), the round restarts: `current_aborts` grows, the committee is re-selected with the missing creator excluded, and Phase 1 begins anew.

If Phase 2's `block_sig_ms` timer fires with fewer than `K` sigs, an analogous claim quorum forms (`round=2`), but does not contribute to suspension (§5.4).

---

## 8. Block Validation

A node receiving a block verifies:

1. `prev_hash` matches the local chain head.
2. `creators` is exactly the deterministic K-committee derived from the epoch seed, `b.abort_events`, and the registry — using the exclude-mixed selection of §6.
3. Each `creator_ed_sigs[i]` is a valid Ed25519 signature over the Phase 1 commit, by `creators[i]`'s registered key.
4. `tx_root` equals `root(union(creator_tx_lists))`.
5. `delay_seed` equals `H(idx ‖ prev_hash ‖ tx_root ‖ creator_dh_inputs)`.
6. For each `i`, `SHA256(creator_dh_secrets[i] ‖ creators[i].pubkey)` equals `creator_dh_inputs[i]` (Phase-2 reveal verifies against the Phase-1 commitment).
7. `delay_output` equals `SHA256(delay_seed ‖ creator_dh_secrets[0..K])`.
8. Each `creator_block_sigs[i]` is a valid Ed25519 signature over `block_digest` by `creators[i]`'s registered key.
9. Each `AbortEvent` carries a valid `max(2, K-1)` quorum of signed `AbortClaimMsg`s, with claimers drawn from the at-event committee (reconstructed by the same exclude-mixed rule).
10. Transactions are valid against the running balance/nonce model in canonical order.
11. `cumulative_rand` equals `H(prev.cumulative_rand ‖ delay_output)`.
12. `timestamp` is within `±30 s` of the local clock.

Steps 2, 3, 7, and 8 give fork-freedom only under the §2 safety assumption. Two valid blocks at the same height from the same committee would require every member to sign two different digests, which any honest committee member refuses. Blocks carrying different `abort_events` are checked against different committees, so each can pass step 2; the pool bound that would make any two committees overlap is not enforced (S-054, partial — §5.3).

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

- The same committee to produce two different digests, then sign each `K`-times — excluded when any committee member follows the honest-signing rule (FA1, [Safety.md](docs/proofs/Safety.md)); or
- Differing committees at the same height — not excluded by selection: the committee is derived from each block's own `abort_events` (§6), so two blocks with different abort histories are each checked against their own committee. Excluding this case needs the committee-intersection and honest-signing hypotheses of §2; the pool bound `2K > N(h)` is not enforced (S-054, partial — §5.3).

At most one valid block exists at a height only under those hypotheses.

### 10.2 Censorship resistance

A transaction is omitted from block `n` only if every one of the `K` committee members fails to include it in their Phase 1 contribution. Under uniform adversarial fraction `f/N`:

```
P(tx censored in round n) ≈ (f/N)^K
```

With `K = 3` and `f/N = 0.10`: `P ≈ 10⁻³` per committee draw. The committee is redrawn at each epoch boundary (`epoch_blocks`, genesis-pinned; during epoch 0 at every block) and on abort re-selection, not every round, so a committee that censors can keep doing so until its epoch ends; persistence becomes exponentially unlikely across epochs (§16.6).

### 10.3 Commitment binding and selective abort

Receivers verify a revealed secret against its earlier SHA-256 commitment. This
binds the opening under the hash assumption. It does not force publication. A last
revealer knows its own secret and, after receiving the others, can compute the
result before deciding whether to reveal. Claims that this is information-theoretically
unbiased, or that a local delay parameter prevents the attack, are withdrawn.
See [SelectiveAbort.md](docs/proofs/SelectiveAbort.md) and SECURITY.md S-077. The C99
experiment additionally permits colluders to precompute both payloads before starting.

### 10.4 Liveness — per-height BFT escalation

**Strong mode (`K = M_pool`)** is the default. Every committee is the entire pool; a single silent creator halts the round.

**Per-height BFT escalation** restores liveness without giving up strong mode's safety on most blocks. The mechanism, configured via genesis-pinned `bft_enabled` (default `true`) and `bft_escalation_threshold` (default 1 since S-045; was 5):

1. **Default state**: each round runs in **MUTUAL_DISTRUST** mode — full K-of-K Phase 2 unanimity; MD blocks are fork-free under the §2 safety assumption (§10.1).
2. **Trigger** (all four must hold — see PROTOCOL.md §5.3 for the exact gates): `bft_enabled = true` AND in-flight round at height `h` accumulates `bft_escalation_threshold` aborts (Round 1 + Round 2 both count) AND the available pool (registry minus aborted-this-height domains) has dropped below `K` AND the available pool is still ≥ `ceil(2K/3)`. If the available pool falls below `ceil(2K/3)` the shard stalls — there's not enough to form a BFT committee either; under EXTENDED sharding the R4 under-quorum merge mechanism may absorb the shard.
3. **BFT mode**: committee shrinks to `k_bft = ceil(2K/3)` selected from the available pool. A deterministic **designated proposer** (chosen from the committee via `proposer_idx(seed, abort_events, k_bft)` with `seed = epoch_committee_seed(epoch_rand, shard_id)` plus a 12-byte `"bft-proposer"` ASCII domain separator — see PROTOCOL.md §5.3.1 for the full algorithm) is the only node that builds a block at this height. Phase 1 still requires unanimity within the smaller committee; Phase 2 finalizes on `Q = ceil(2·k_bft/3)` sigs collected by the proposer (the standard BFT 2/3 quorum applied to the shrunk committee, not to the genesis K — the two coincide only at K=3). The block carries `consensus_mode = BFT` and `bft_proposer = <domain>`.
4. **Reset**: after the escalated block finalizes, height `h+1` resets to MD by default.

**Per-block trust claim:**

| Block type | Safety                                  | Censorship                                |
|-----------|-----------------------------------------|-------------------------------------------|
| MD        | Conditional on the §2 safety assumption: an honest signer in the committee plus committee intersection (§10.1) | K-conjunction over committee |
| BFT       | Conditional on `f_h < k_bft/3` in this committee (`k_bft = ⌈2K/3⌉`) and on the §2 committee-intersection hypothesis | `k_bft`-conjunction over the smaller committee — the union-tx-root rule covers all `k_bft` Phase-1 contributions; Phase-2 sentinels only affect signing |

Applications (and light clients) inspect each block's `consensus_mode` and reason accordingly. High-value transactions can wait for the next MD-mode block; routine transactions accept BFT blocks knowing the weaker safety claim. Most blocks (steady state) are MD; BFT is the tail liveness fallback.

**Suspension**: BFT-mode safety depends on `f_h < k_bft/3` (standard BFT 1/3 bound applied to the BFT-shrunk committee). An `AbortEvent` for round 1 baked into a finalized block records a suspension against the named validator (the S-032 `abort_records` cache: exponential-backoff exclusion from committee selection); it moves no stake — the former `SUSPENSION_SLASH` deduction was retired 2026-09-16 (owner decision D13; the parameter remains as an inert genesis-covered field). Suspension counts only Phase-1 aborts to avoid Phase-2 timing-skew false positives; escalation counts all aborts.

**Opt out**: setting `bft_enabled = false` at genesis disables escalation — the chain halts on a persistent silent committee member, by design. Suitable for deployments that prefer MD-mode safety (§10.1) on every block over liveness fallback.

### 10.5 Censorship vs. liveness, side by side

| Mode | K | Censorship requires | Liveness requires |
|---|---|---|---|
| Strong | M_pool | All M_pool collude | All M_pool live (BFT escalation falls back to ceil(2K/3) on persistent abort) |
| Hybrid | K < M_pool | All K committee collude | All K committee live; BFT escalation tolerates dropouts by shrinking the committee to `k_bft = ⌈2K/3⌉` |

---

## 11. Identity Model

### 11.1 Domains (registered, named)

A domain registers via REGISTER with its Ed25519 public key. Domains are listed in chain state and can be inspected by any observer. Under `STAKE_INCLUSION` a domain can stake and transact only while it is in the eligible registry, so a domain registered after genesis cannot become an eligible creator (S-069, §5.2); an eligible domain may also transact (TRANSFER, etc.) under the same key.

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

v2.25 specifies that ceremony as the mutual-distrust IdP of academia.edu/80188125, realized with two improvements over the paper: **OPAQUE in place of SRP**, and a **t-of-n, unordered threshold OPRF** in place of the paper's sequential all-node chain (any t of the K committee members, in any order; no member below t learns the password). RPs register on-chain via v2.18 DAPP_REGISTER; the threshold OPRF authenticates the password and the OPAQUE handshake co-generates a shared key, from which the user proves authentication to the RP by the paper's **dual-hash challenge-response** (`H2 = H(tenant_key, H1')`) carried over v2.19 DAPP_CALL — no committee signature, no FROST, no block co-sign. Full mechanism: `docs/proofs/v2.25-DSSO-DAPP-SPEC.md`.

v2.26 would add an on-chain `ROTATE_KEY` tx so a compromised key can be retired without losing the identity; key rotation is decided (D15 / R-6) but not in code — the shipped `TxType` values are 0..17 and a lost key is terminal for its domain. Both items are specified in `docs/V2-DESIGN.md` Theme 9.

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
| ABORT_EVENT | 10 | broadcast | Assembled `max(2, K-1)`-claim quorum |
| EQUIVOCATION_EVIDENCE | 11 | broadcast | Two conflicting signatures (block digests or contrib commitments) at one height |
| BEACON_HEADER | 12 | beacon → shard | Beacon block for shard-side header-chain |
| SHARD_TIP | 13 | shard → beacon | Shard block for beacon-side committee verify |
| CROSS_SHARD_RECEIPT_BUNDLE | 14 | broadcast (relay via beacon) | Source-shard block carrying outbound receipts |
| SNAPSHOT_REQUEST | 15 | peer → peer | Bootstrap snapshot fetch |
| SNAPSHOT_RESPONSE | 16 | peer → peer | Serialized chain state for fast-bootstrap |
| HEADERS_REQUEST | 17 | peer → peer | Header-page request (`from`, `count`) |
| HEADERS_RESPONSE | 18 | peer → peer | Page of at most 256 DHF1 header records |

### 12.2 Wire Format

All messages are length-prefixed:

```
[4 bytes BE length][envelope payload]
```

One codec is shipped — the p2p envelope is binary-only (D2, DECISION-LOG 2026-07-28; corrected here 2026-09-14, the text below described the pre-D2 state):

* every body on the wire is the `0xB1` binary envelope (`src/net/binary_codec.cpp`); the legacy JSON envelope (wire-version 0) and the per-pair HELLO version negotiation were removed pre-genesis, and a non-`0xB1` body is rejected fail-closed.
* HELLO still carries a `wire_version` advertisement — with a single shipped version it decides nothing; it is the additive post-genesis upgrade hatch.

Per-type payloads inside the envelope are fixed binary frames for all 19 message types (PROTOCOL.md §9.1): since D2 inc7c (2026-09-16) HEADERS_RESPONSE is a page of DHF1 header records and SNAPSHOT_RESPONSE is the DSN1 snapshot record verbatim, the length-prefixed JSON fallback is deleted, and a message type the codec cannot encode or decode is rejected rather than serialized as JSON.

S-022 per-message-type body caps apply at deserialize time regardless of codec: 1 MB for consensus chatter, 4 MB for blocks/headers/bundles, 16 MB only for SNAPSHOT_RESPONSE / CHAIN_RESPONSE. The 16 MB framing-layer ceiling (`kMaxFrameBytes`) is enforced at read time before the per-type check.

### 12.3 Gossip

All messages broadcast to all directly connected peers. Receiver-side dedup: blocks by `index` (`b.index < chain_.height()` skips silently); contribs by signer; block-sigs by signer. Cross-generation contribs (`aborts_gen` mismatch) are rejected.

### 12.4 Sync Mode (M12)

A node behind on chain state enters SYNC mode: it does not contribute to consensus, requests `GET_CHAIN` from peers, applies received chunks, and only re-enters `IN_SYNC` once it matches the network's head. This prevents a stale node from acting as a creator and disrupting the live committee.

### 12.5 Egress Bounds and Sync Safety

- **Bounded Peer Egress Queue (S-082, partial):** each peer's outbound queue holds at most `MAX_PEER_WRITE_QUEUE = 256` frames. An enqueue at that depth closes the connection (`conn_->close()`) instead of growing the queue, and a write error clears it. The bound counts frames, not bytes (one frame may be up to 16 MB, §12.2); an accepted socket joins the broadcast set before its HELLO; and the number of connections is not capped.
- **Sync requests (S-080, S-085 open):** a node that is behind broadcasts `GET_CHAIN` to all peers and takes the first response (§12.4), with no in-flight bound or backoff, and it records the height a peer reports in `STATUS_RESPONSE` with no plausibility bound.
- **Light-Client Quorum Floor on Inclusion Proofs (S-100):** `verify_tx_inclusion_from_block` passes the genesis `k_block_sigs` and `bft_enabled` to `verify_block_sigs`, so the inclusion block must name exactly `k_block_sigs` creators (MD) or, only when `bft_enabled`, exactly `ceil(2K/3)` (BFT); a reduced-quorum block is rejected as unverifiable.

---

## 13. Implementation Parameters

| Parameter | Default | Notes |
|---|---|---|
| `m_creators` (M_pool) | 4 (web profile) | Genesis-pinned. Per-profile M in §13.1 |
| `k_block_sigs` (K) | 3 (web profile, hybrid K<M) | Genesis-pinned. `cluster` and `tactical` are strong (K=M); `web`/`regional`/`global` are hybrid. Per-profile K in §13.1 |
| `block_subsidy` | 10 (atomic, by genesis convention) | Genesis-pinned, page reward. No code-level default — operator sets it in `GenesisConfig`; `tools/test_*.sh` use 10 |
| `bft_enabled` | true | Genesis-pinned. Enables per-height BFT escalation (§10.4) |
| `bft_escalation_threshold` | 1 | Genesis-pinned. Total aborts at same height before escalation (S-045; was 5) |
| `SUSPENSION_SLASH` | 10 (atomic) | Inert since 2026-09-16 (D13): no stake is deducted on an abort; kept as a genesis-hash-covered field |
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

A profile is a **complete deployment archetype**: timing, committee size, chain role, sharding mode, AND cryptographic posture are all pinned together. To change any of these, pick a different profile — there is no separate CLI override.

| Profile | M | K | block time | role | sharding_mode | crypto | confidential tx | Primary use case |
|---|---|---|---|---|---|---|---|---|
| **`cluster`** | 3 | 3 (strong) | ~125 ms | BEACON | CURRENT | **FIPS** | ❌ | **In-house enterprise, financial services, banking settlement, regulated single-org chains, single-org CBDC, HIPAA-strict healthcare** |
| `web` (default) | 4 | 3 (hybrid) | ~500 ms | SHARD | EXTENDED | MODERN | ✅ | Public-internet, regional shards, commercial single-cluster non-FIPS, regulated gambling, B2B payment |
| `regional` | 5 | 4 (hybrid) | ~750 ms | SHARD | CURRENT | MODERN | ✅ | Regional / continental RTT, state lottery, multi-region commercial |
| `global` | 7 | 5 (hybrid) | ~1.5 s | BEACON | EXTENDED | MODERN | ✅ | Inter-continental hub-and-spoke, international CBDC federation |
| **`tactical`** | 3 | 3 (strong) | ~50 ms | SHARD | EXTENDED | **FIPS** | ❌ | **Military, defense, drone swarm, embedded mobile units, DoD deployments** |

Timing fields (`tx_commit_ms` / `block_sig_ms` / `abort_claim_ms`): cluster `50/50/25`, web `200/200/100`, regional `300/300/150`, global `600/600/300`, tactical `20/20/10`.

**Cryptographic profile bundling.** Two of the five profiles (`cluster`, `tactical`) bundle the **FIPS** cryptographic stack: AES-256-GCM AEAD, PBKDF2-HMAC-SHA-256 KDF, NIST P-256 prime-order operations, Ed25519 (FIPS 186-5) signatures, X25519 (SP 800-186) KX. Confidential transactions (Pedersen + Bulletproofs over P-256, §3.19 / the §3.22 shielded pool) are built on FIPS-approved primitives (P-256 + SHA-256), but the zero-knowledge CONSTRUCTIONS themselves are NOT FIPS-validated ALGORITHMS (NIST has no approved range-proof standard), so the FIPS profiles (`cluster`, `tactical`) ship with confidential-tx **disabled** (the profile table's ❌). Input-unlinkability ring signatures (LSAG/CLSAG, §3.23) are a **design record only** — the library was removed from the tree per pre-launch register B2 (2026-07-09), not a shipped feature.

The other three profiles (`web`, `regional`, `global`) bundle the **MODERN** cryptographic stack: XChaCha20-Poly1305 AEAD, Argon2id KDF, Ed25519 signatures, X25519 KX. Confidential transactions ride the profile-agnostic P-256 shielded pool (§3.22) — the same P-256 backend the FIPS stack is built on, enabled on the MODERN profiles; MODERN adds no separate ZK curve (secp256k1 was never built; the big-prime Z_p* backend was removed 2026-07-07).

See `docs/proofs/CRYPTO-C99-SPEC.md` §2.Q10 for full cryptographic-profile rationale and feature-availability matrix.

**Test variants** — sub-30 ms rounds for fast CI execution (`tx_commit_ms = block_sig_ms = 5`, `abort_claim_ms = 3`). Each test profile mirrors its production sibling's M / K / role / sharding_mode / crypto profile:

| Profile | M | K | role | sharding_mode | crypto |
|---|---|---|---|---|---|
| `single_test` | 3 | 3 (strong) | SINGLE | NONE | MODERN |
| `cluster_test` | 3 | 3 (strong) | BEACON | CURRENT | **FIPS** |
| `web_test` | 4 | 3 (hybrid) | SHARD | EXTENDED | MODERN |
| `regional_test` | 5 | 4 (hybrid) | SHARD | CURRENT | MODERN |
| `global_test` | 7 | 5 (hybrid) | BEACON | EXTENDED | MODERN |
| `tactical_test` | 3 | 3 (strong) | SHARD | EXTENDED | **FIPS** |

`ShardingMode` values:
- **`NONE`** — single-chain deployment, no sharding (test-only).
- **`CURRENT`** — 1 beacon + S shard chains, account routing by salted-SHA256 modulus, committees drawn from the global validator pool.
- **`EXTENDED`** — same as `CURRENT` plus per-shard `committee_region`: each shard's K-committee is restricted to validators tagged with that region, dropping intra-shard RTT and per-shard block time. Cross-shard tx still pays the wider beacon round-trip (B3 receipts).

Block time approaches `T_phase_1 + T_phase_2 + 2 × max RTT in committee` once the round transitions immediately at K-of-K Phase-1 arrival. Under `EXTENDED` sharding the relevant RTT is intra-region, not global.

---

## 14. Comparison with Related Work

### 14.1 Bitcoin (Nakamoto Consensus)

PoW longest-chain. Probabilistic finality, energy-intensive, fork-prone. Determ is registration-gated and finalizes each block by committee signatures; its fork-freedom holds under the §2 safety assumption (§10.1), not unconditionally.

### 14.2 Ethereum (Gasper)

PoS with 2/3+ attester finality over ~12.8 minutes. Determ finalizes per block (~500 ms web profile). Ethereum tolerates per-validator faults; Determ's K-of-K does not, but achieves stronger censorship resistance through union tx set.

### 14.3 Tendermint / Cosmos

2/3+ vote in a two-phase commit. Single proposer per round is a censorship bottleneck; Determ's union-of-K is not.

### 14.4 Algorand

VRF sortition + BA* over ~3.7 s. Tolerates adversarial fraction `f < N/3`. Determ's per-round committee is much smaller (`K`, typically 3) but every member must contribute — censorship requires unanimity within the committee.

### 14.5 Dfinity / Internet Computer

The C++ implementation uses K-member co-creation and hash commitments for randomness. Its selective-abort limitation must be assessed separately from any comparison with threshold beacons.

### 14.6 Solana

Iterated-SHA-256 Proof of History for sequencing + Tower BFT for finality lagging by ~32 slots. Determ's randomness uses commit-reveal rather than iterated SHA-256; finality is per-slot K-of-K signatures rather than tower-vote accumulation.

---

## 15. Limitations and Future Work

**Hybrid-mode liveness.** A `K < M_pool` configuration tolerates `M_pool − K` silent creators only via per-height BFT escalation; the genesis-pinned `K<M` parameter is preserved for future fork-choice variants but the escalation path is the canonical liveness story.

**Stake-weighted selection.** Creators are selected uniformly from the stake-eligible pool. Stake-weighted selection (proportional to bonded stake) is a natural extension for production deployments.

**Sharding for scale.** Single-chain TPS scaling via in-block parallel transaction execution is **not on the roadmap** — the design philosophy preferences sharding (per-shard mutual-distrust K-conjunction) over single-chain optimistic-concurrency execution. A deployment that hits a per-shard TPS ceiling adds shards rather than rewriting the apply path. Under `EXTENDED` sharding the throughput axis aligns with regional locality: most user traffic stays in-shard at intra-region RTT.

**Network partition behavior.** A partition that splits the committee blocks progress on both sides until it heals (modulo BFT escalation, which can finalize a side with `ceil(2K/3)` honest committee members). Appropriate for a financial ledger (CP, not AP). Under `EXTENDED` sharding a region losing connectivity to the rest of the world stalls cross-shard receipts; in-shard production continues.

**Binary wire codec — shipped and mandatory (A3 / S8, then D2).** The `0xB1` binary envelope (`src/net/binary_codec.cpp`) is the only codec on the wire; the legacy JSON envelope and the HELLO codec negotiation were deleted pre-genesis (DECISION-LOG 2026-07-28, commit ce31c6f). HELLO keeps a `wire_version` advertisement as the additive post-genesis upgrade hatch. PROTOCOL.md §9.1 has the per-type frame layouts. (Corrected 2026-09-14.)

**Light clients.** Inclusion-proof RPC (`state_proof`) is shipped via the v2.2 foundation — light clients query a full node for a Merkle proof of any state entry against the current `state_root` (which is bound into `signing_bytes` and committee-signed). CLI `determ state-proof --ns <a|s|r|d|b|k|c> --key <name>` fetches a proof; the `d` namespace surfaces v2.18 DApp-registry entries. **Local verification of fetched proofs** is provided by `determ verify-state-proof --in proof.json [--state-root <trusted-hex64>]` which calls `crypto::merkle_verify` without trusting the responding node — the optional `--state-root` flag pins an externally-trusted root, defeating a malicious full node that fabricates a fake root to make its tampered proof self-consistent. **Snapshot-level trustless verification** by the same anti-tampering pin is `determ snapshot inspect --in snap.bin --state-root <trusted-hex64>` (S-033 + S-038 gates verify the snapshot's whole state Merkle against the operator's pinned root). **Header-only sync** is the `headers` RPC + `determ headers --from N --count M` CLI: returns block-header slices (Block JSON minus the heavy `transactions` / receipt / `initial_state` fields, plus an explicit `block_hash` per header), so a light client can chain prev_hash → state_root → state-proof without downloading every tx. The CLI accepts **two fetch paths**: `--rpc-port P` (against a local node's RPC) or `--peer host:port` (gossip-layer **`HEADERS_REQUEST`** / **`HEADERS_RESPONSE`** wire messages, MsgType 17/18 — light clients peer directly with full nodes without RPC binding). The envelope is byte-identical across both paths, so every downstream verifier works against either fetch source. **Header-chain integrity** is verified locally via `determ verify-headers --in headers.json [--genesis-hash <hex64>] [--prev-hash <hex64>]`: walks consecutive header pairs and asserts `header[i].prev_hash == header[i-1].block_hash`. **K-of-K committee-signature verification** on each header is `determ verify-block-sigs --header <file> --committee <file> [--bft]`: computes `compute_block_digest(b)` over the header fields and verifies each `creators[i]`'s `creator_block_sigs[i]` against a supplied committee pubkey map; the `committee` file is a JSON array of `{domain, ed_pub}`, or an object with that array under `members` (the shape the `committee` / `validators` RPCs internally produce). Together these four CLIs constitute the complete v2.2 light-client trustless-verification chain: `headers` (fetch from RPC OR peer-gossip) → `verify-headers` (chain links) → `verify-block-sigs` (committee K-of-K) → anchor `state_root` → `verify-state-proof` / `snapshot inspect --state-root` (per-field / whole-state). **v2.2 has no outstanding asks** — the gossip-layer HEADERS_REQUEST/HEADERS_RESPONSE wire messages closed the last v2.2 piece.

**Distributed identity provider (DSSO).** The K-of-K committee is structurally a mutual-distrust operator group — the exact setting of *Identity provider in an environment of mutual distrust* (academia.edu/80188125). v2.25 + v2.26 (V2-DESIGN.md Theme 9) realize that paper's IdP as a "Sign-In With Determ" flow with two improvements: **OPAQUE in place of the paper's SRP**, and a **t-of-n, unordered threshold OPRF** in place of the paper's sequential all-node chain. RPs register via v2.18 DAPP_REGISTER; challenges and the paper's hash-challenge-response token ride v2.19 DAPP_CALL. The ceremony uses only already-shipped primitives (Ed25519, the P-256 RFC 9497 OPRF §3.9b, SHA-256/HKDF, DAPP_REGISTER/DAPP_CALL), needs **no threshold signature** and **no FROST**, and pairs with v2.26 on-chain key rotation. Full mechanism: `docs/proofs/v2.25-DSSO-DAPP-SPEC.md`; `docs/V2-DESIGN.md` Theme 9 retains the architectural narrative.

**Equivocation handling — detection and on-chain record:**

The disincentive depends on the chain's inclusion model (§5.1):

- **`STAKE_INCLUSION`** chains: a Phase-1 abort records a suspension and deducts nothing (the `SUSPENSION_SLASH` deduction was retired 2026-09-16, D13). Equivocation carries **no** L1 consequence since 2026-09-16 (O-1 step 3a; DECISION-LOG D4) — the `EquivocationEvent` is an evidence record for the L2 policy.
- **`DOMAIN_INCLUSION`** chains: a Phase-1 abort likewise records a suspension only. Equivocation carries no L1 consequence here either (D4) — the record is the L2 policy's input.

Both modes use the same `EquivocationEvent` evidence structure (two Ed25519 signatures by the same registered key over two different digests — block digests or contrib commitments — at the same `block_index` and round generation; proof that the key signed twice, though an honest node restarted by the stall valve can also produce such a pair, S-095) and the same end-to-end pipeline:

The full pipeline:

1. **Detection** (`apply_block_locked`): when a duplicate-height BFT block with a different hash arrives, the assembler computes both blocks' digests, extracts the proposer's signatures from each block's `creator_block_sigs`, and constructs an `EquivocationEvent`.
2. **Gossip** (`EQUIVOCATION_EVIDENCE`, msg type 11): the event is broadcast so peers can validate independently and pool the evidence.
3. **Pool** (`Node::pending_equivocation_evidence_`): each node maintains a pool of unbaked evidence. Peers receiving gossiped evidence validate the two-sig proof against the equivocator's registered key before adding.
4. **Production** (`build_body`): producers include pooled evidence that the verifier's per-event rule admits (S-105) in `block.equivocation_events`, deduplicated, sorted by event hash and truncated to `EQUIVOCATION_EVENTS_PER_BLOCK_MAX = 16`.
5. **Validator** (`check_equivocation_events`): rejects a block carrying more than 16 events or a duplicate event (O-1 step 3b), and any malformed event (unknown kind, mismatched heights or round generations, equal body roots, equal sigs, equivocator not in registry, sigs that don't verify against the digests derived from the openings).
6. **Apply** (`apply_transactions`): each `EquivocationEvent` is committed as an on-chain record and nothing else — no stake, registry or counter movement (D4, 2026-09-16; `determ test-equivocation-apply`).
7. **Dedup**: after a block bakes evidence, that equivocator's entries are removed from the pending pool. The verifier's duplicate rule is per block, so a later block can carry the same event again.

BFT-mode safety claims are conditional on `f_h < k_bft/3` within the BFT committee (and, like every same-height claim, on the §2 committee-intersection hypothesis) and on no economic term; the accountable-safety corollary that rested on slashing (T-5.1) was WITHDRAWN on 2026-09-17 — above the bound the offenders are identifiable and nothing removes them, so accountable safety here is evidence-only (`docs/proofs/BFTSafety.md` §4).

---

## 16. Sharding

A sharded Determ deployment splits responsibility into a single **beacon chain** and `S` **shard chains**, each running the same two-phase commit-reveal consensus on its own state subset. The beacon is the trust anchor: it holds the validator pool, cross-shard receipts, and epoch transitions. Shards process user transactions for accounts assigned to them.

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

The beacon runs MD K-of-K only (no escalation; halts on persistent silent committee member). Shards run MD-default with per-height BFT escalation. Asymmetry rationale: the beacon is the trust anchor — MD-mode safety (§10.1) on every beacon block, low volume, halt-recoverable. Shards are the throughput layer — needs liveness more than censorship in steady state.

Under `EXTENDED` sharding each shard additionally pins a `committee_region` (operator-defined string, e.g. `"us-east"`, `"eu-west"`). Validators self-declare their region at REGISTER time; the committee for shard `s` is drawn only from validators tagged with `s.committee_region`. The trade is that per-shard censorship resistance becomes regional rather than global — see §16.6.

### 16.2 Reusing `cumulative_rand` for shard committees

Per epoch (every `E` beacon blocks), each shard's committee is derived from the beacon's `cumulative_rand` plus a per-shard salt:

```
shard_seed = SHA-256(beacon_epoch_seed ‖ "shard-committee" ‖ shard_id)
shard_committee[s] = select_m_creators(shard_seed, validator_pool_size, K_per_shard)
```

The same `select_m_creators` function used in single-chain mode. The salt makes shards' committees independent. The commit-reveal seed binding (§10.3) keeps the seed unknown while stake is placed: the K committed secrets that determine the next epoch's seed are not revealed until the current epoch's blocks finalize. It does not stop a last revealer from withholding an unfavorable outcome (§10.3, S-077).

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

Under `EXTENDED` sharding each shard's genesis pins a `committee_region`. Validators self-declare a `region` at REGISTER time (≤ 32 bytes of `[a-z0-9-_]`, see the region taxonomy below; its meaning is opaque to the protocol). The committee for shard `s` is drawn deterministically from the registry subset matching `s.committee_region`.

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

**`num_shards >= 3` invariant.** A deployment that pins `sharding_mode = EXTENDED` must declare `initial_shard_count >= 3` in genesis. Smaller deployments would expose cascading-merge undefined behavior under the v1 under-quorum recovery mechanism — see `docs/SECURITY.md` §6.5 "Regional sharding posture" + T-004 (the cascading-merge concern was originally drafted as a proposed S-038 finding but was closed by construction via this invariant; the SECURITY.md `S-038` number was later reassigned to "state_root verification gate dormant"). The invariant is enforced both at `genesis-tool build-sharded` time and at node startup.

**REGISTER tx region field.** A validator joining an `EXTENDED` chain declares its region in the REGISTER tx payload:

```
REGISTER payload = [pubkey: 32B] [region_len: u8] [region: utf8 bytes]
```

The legacy payload (the bare 32-byte pubkey, no `region_len` byte) is accepted — it means "global pool", which is the implicit default for non-`EXTENDED` chains; a `region_len` byte with no region bytes after it is rejected as truncated. New `EXTENDED` deployments set the region explicitly. The tx's own Ed25519 signature binds the region into the tx hash via `Transaction::signing_bytes()`.

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
| Beacon | MD-mode, conditional on the §2 safety assumption (MD-only, no escalation) | K-conjunction over beacon committee |
| Shard MD | MD-mode, conditional on the §2 safety assumption (MD steady-state) | K-conjunction over shard committee |
| Shard BFT | Conditional `f_h < k_bft/3` and the §2 committee-intersection hypothesis | `k_bft`-conjunction over shard BFT committee (Phase-1 union-tx-root applies; Phase-2 sentinels affect signing only) |

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

- **Permissionless payment system.** TRANSFER between named domains and anonymous bearer-wallet accounts. Censorship-resistant via K-of-K + union tx_root — any single rule-following committee member can include any tx. Zero-trust safety (no protocol component trusts any participant).
- **Composable Atomic Batching.** Atomic multi-transaction scopes (`COMPOSABLE_BATCH`) executing multiple operations in a single block space allocation with all-or-nothing rollback on inner transaction failure.
- **Canonical Encrypted DApp Messaging.** Lightweight DApp service discovery and encrypted payload delivery (`DAPP_REGISTER`, `DAPP_CALL`) without VM execution overhead.
- **Post-Quantum Bearer Payments.** Opt-in ML-DSA (FIPS 204) authenticated transfers (`PQ_TRANSFER`) coexisting seamlessly with classical Ed25519 accounts.
- **Confidential Transfers & Audit Trails.** Amount-private payments via Pedersen commitments and Bulletproofs range proofs (`SHIELD`, `UNSHIELD`, `CONFIDENTIAL_TRANSFER`) coupled with on-chain dual-mode audit key rotation and disclosure logging (`ROTATE_AUDIT_KEY`, `LOG_AUDIT_ACCESS`, `REGISTER_NOTE_KEY`).
- **Validator pool with on-chain accountability.** Validators register on-chain, can be staked or domain-anchored (§5.1). Misbehavior is detectable and recorded: a Phase-1 abort suspends the absent member from selection, and equivocation is kept as an on-chain evidence record. L1 slashes nothing — no stake deduction on aborts (D13) and no stake or registry consequence for equivocation (D4); the L2 bond policy that is to consume the record (D22) is not yet designed.
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
- **Full anonymity / graph privacy** (mixnets, stealth addresses, sender/receiver hiding). The anonymous bearer-wallet account model is the *identity*-privacy story. *Amount*-privacy confidential transactions — Bulletproofs range proofs + the shielded pool: **SHIELD** / **UNSHIELD** (transparent↔confidential bridge) + **CONFIDENTIAL_TRANSFER** (confidential→confidential, hidden amounts) (CRYPTO-C99-SPEC §3.22a/b/c; MODERN profiles) — are an owner-authorized, in-flight feature: they hide **amounts**, and (today) still name their inputs, so the note graph is visible. **Input-unlinkability** — linkable-ring-signature membership primitives that will let a spend hide **which** note it consumes, with a key-image nullifier for double-spend: **LSAG** (§3.23, inc.1) and the more capable **CLSAG** (§3.23b, inc.2 — Monero's RingCT primitive, folding a spend-key layer and an amount-commitment *balance* layer into ONE concise `n+1`-scalar ring) — were prototyped as validated **library primitives** but **removed from the tree per pre-launch register B2 (2026-07-09)** — design record only (§3.23), not shipped code. Historically, that **library-only end-to-end composition** (§3.23c, inc.3) demonstrated the layers stitch together — CLSAG (input membership + balance) bridged by a commitment-transposition proof (reconciling CLSAG's amount-on-H convention with the range proofs' amount-on-G) into the §3.22c range+balance bundle — a full confidential *and* unlinkable spend *statement*, still short of the owner-gated consensus wiring. None of this hides the sender/receiver identities beyond the note layer.

A future fork or layer-2 could add these. The base protocol does not.

### 17.5 Honest framing

Calling Determ a "DApp hosting network" misrepresents what it is. Calling it a "decentralized cryptocurrency with mutual-distrust safety" is accurate. Specific fits:

- Inter-organization settlement where payment + identity is the whole value proposition.
- Censorship-resistant value transfer in environments where trust assumptions about validators are explicitly rejected.
- Federated registries where domain-anchored validators provide identity and the chain provides ordering + auditability.
- Regional payment networks (`EXTENDED` sharding) where in-shard sub-second finality matters and operators are explicit about regional trust assumptions.

If you need contracts, build them on a different chain or build a layer-2 on top of Determ. The base protocol's job is to be very good at one narrow thing — fork-free payment + identity with mutual-distrust safety — not to be everything.

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

A lost Ed25519 private key today means permanent loss of the registered domain and its balance. The `determ-wallet` binary provides an opt-in distributed recovery primitive layered over Shamir's Secret Sharing and passphrase-derived AEAD envelopes — solving key loss without weakening on-chain trust. The wallet is libsodium-free: all its crypto runs on the daemon's `determ::c99` stack plus the determ::c99 cryptographic backend, exactly like the `determ` daemon.

**Threat model.** The wallet's recovery flow protects against:

- Loss of any (N − T) of N guardians (threshold reconstruction survives partial unavailability).
- Compromise of any (T − 1) guardians (information-theoretic: zero bits of the seed leak below threshold).
- Tampering with any individual envelope (AEAD detects single-bit modifications with probability ≥ 1 − 2⁻¹²⁸).
- Casual inspection of a captured envelope (the memory-hard Argon2id work factor raises the cost of an offline password grind; note that with the passphrase scheme an isolated record remains offline-grindable, so passwords must carry real entropy).

**Layered design.** Each layer addresses a distinct threat:

1. **Shamir SSS over GF(2⁸)** — splits the Ed25519 seed into N shares; any T reconstruct, any T − 1 reveal nothing.
2. **AEAD envelope (AES-256-GCM)** — wraps each share with a per-envelope salt + nonce; AAD binds guardian index + scheme version.
3. **Passphrase key derivation (Argon2id)** — under the `passphrase` scheme, each envelope's unwrap key is derived with Argon2id (t = 3, 64 MiB; the DWE2 envelope layout) from the user's password and the per-envelope salt. Envelopes in the older PBKDF2 layout (DWE1) remain readable.

**At-rest format.** A recovery setup is one canonical binary DRS1 container (D2; layout in `wallet/recovery.hpp`, integers little-endian, decoded only at its exact length):

```text
"DRS1" | version u32 (= 1) | threshold u8 (>= 1) | share_count u8 (>= threshold)
       | secret_len u32 (1..4096) | checksum_len u8 (0 or 32) | pubkey_checksum
       | share_count x { guardian_x u8 (1..255, distinct) | env_len u32 | DWE envelope bytes }
```

`pubkey_checksum` is the SHA-256 of the seed's Ed25519 public key and is re-checked after reconstruction.

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
                              [--scheme passphrase]
determ-wallet recover --in <file>                  Reconstruct the seed
                      --password <str>
                      [--guardians <i,j,k,...>]
```

**Wallet crypto status.** `determ-wallet` is libsodium-free: every crypto layer runs on the daemon's `determ::c99` stack (Ed25519, X25519, SHA-256, Argon2id) plus the determ::c99 cryptographic backend — the same library posture as the `determ` daemon and `determ-light`, neither of which ever linked libsodium. Recovery ships the `passphrase` scheme only (Shamir SSS + Argon2id-derived AEAD envelopes); there is no OPAQUE adapter or threshold-guardian handshake in the wallet. See `docs/proofs/WalletRecovery.md` (FA12) for the formal-soundness analysis of the passphrase scheme.

**Binary isolation.** `determ-wallet` is a separate executable from the `determ` daemon. Secret material never enters the chain daemon's address space — by design. The daemon handles networking and consensus; the wallet handles keys.

---

## 19. Formal verification

Determ's safety-critical mechanisms are covered by per-property analytic proofs and machine-checkable TLA+ specifications. The full set lives in [`docs/proofs/`](docs/proofs/README.md):

| Layer | Coverage |
|---|---|
| **FA-track** (analytic proofs) | F0 Preliminaries + FA1–FA12: safety, censorship, selective-abort (FA3's completed-round unbiasedness claim is withdrawn; S-077 open), liveness, BFT-mode safety, equivocation-evidence soundness, cross-shard atomicity, regional sharding, under-quorum merge, governance, economic soundness, wallet recovery. |
| **FB-track** (TLA+ specs) | Consensus.tla, Sharding.tla, Receipts.tla. [CHECK-RESULTS.md](docs/proofs/tla/CHECK-RESULTS.md) records the last TLC run (tla2tools v1.7.4, 2026-09-23), in which all 48 configured models passed — Consensus as the C++ K-of-K committee model (FB1). TLC runs in CI (the `tla` job); `tools/test_tla_model_check.sh` fails closed when java or a pinned jar is absent. |
| **Test suite** (CI regression) | The FAST suite (`tools/run_all.sh`, `FAST=1`), run by `tools/ci_local.sh`; the CI workflow runs it on Linux and Windows. The C99 targets have their own gate (`tools/ci_local.sh --c99`, `--c99-sanitize`, `--c99-mutants`). |
| **Integrity guards** (docs/ledger) | Offline doc, tier, link, citation and ledger-coherence checks, run by `tools/ci_local.sh` (standalone: `--docs-only`) in CI. |

Every theorem cites its cryptographic assumptions by the F0 labels (A1 Ed25519 EUF-CMA, A2 SHA-256 collision resistance, A3 SHA-256 preimage / second-preimage resistance, A4 CSPRNG uniform secret sampling; a theorem that models SHA-256 as a random oracle says so explicitly), the validity predicates it depends on (V1–V15 from F0; V12/V13 are the cross-shard receipt source/destination split, V14 is the timestamp bound, V15 is transaction apply consistency), and the source-code location that enforces it. A reviewer can trace any property end-to-end: theorem → state-machine model → implementation.

Concrete-security bounds: a proved property holds, under its stated hypotheses, with probability `≥ 1 − Q · 2⁻¹²⁸` over polynomial adversary budget `Q`. Ed25519 (A1) is a classical assumption: a scalable quantum computer running Shor's algorithm breaks it (PQE-L-2 in the soundness document linked below). A **post-quantum signature path is available**: an opt-in **`PQ_TRANSFER`** whose sender is a PQ-native bearer account bound to an **ML-DSA (Dilithium, FIPS 204)** key (CRYPTO-C99-SPEC §3.21; [`PQSignatureEnvelopeSoundness.md`](docs/proofs/PQSignatureEnvelopeSoundness.md)). It is additive and state-root-invariant — an existing Ed25519 chain is byte-identical — so PQ accounts coexist with classical ones without a migration.

---

## 20. Conclusion

The C++ ledger and C99 pair experiment have separate implementation and proof
boundaries. The C++ security ledger records unresolved findings; the C99 experiment
has only the local contracts stated above. Neither test success nor fixed pair size
establishes unbiased randomness, unconditional finality or production readiness.

---

## References

1. Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System." 2008.
2. Buterin, V. et al. "Combining GHOST and Casper." 2020.
3. Gilad, Y. et al. "Algorand: Scaling Byzantine Agreements for Cryptocurrencies." SOSP 2017.
4. Kwon, J. "Tendermint: Consensus without Mining." 2014.
5. Hanke, T., Movahedi, M., Williams, D. "DFINITY Technology Overview Series, Consensus System." 2018.
6. Yakovenko, A. "Solana: A new architecture for a high performance blockchain." 2018.
7. Boneh, D., Bonneau, J., Bünz, B., Fisch, B. "Verifiable Delay Functions." CRYPTO 2018. (Background only; this citation does not prove sequential hardness of the custom C99 evaluator.)

---

## License

Determ is **multi-licensed** — [LICENSING.md](LICENSING.md) is the authoritative map (PENDING-COUNSEL, DECISION-LOG 2026-07-25, licensing v3.1):

- **Core — free for all.** Everything except `dapps/` (daemon, consensus, crypto library, light client, wallet, SDK, DSSO client libs, tools, docs) is **Apache-2.0** ([LICENSE](LICENSE)): run, modify, embed, resell — no obligations beyond attribution.
- **Reference DApps (`dapps/`, D.1-D.9) — BUSL-1.1**: source-available; free for development/test/CI **and for noncommercial production** (individuals, noncommercial organizations); **production use by a commercial entity or a public-sector body requires a paid grant** ([COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)); each release converts to Apache-2.0 after 4 years.
- **End users pay nothing**: the Licensor operates reference DApp instances on the network free of charge; using a hosted instance is not a licensed activity.

The C++ and C99 implementations coexist. C++ networking and serialization dependencies remain; the C99 driver has not replaced them. See [NOTICE](NOTICE) and the implementation-specific build targets.

Source files carry a per-component SPDX identifier (rule in [LICENSING.md](LICENSING.md)) so toolchain-level license scanners can verify provenance automatically.
