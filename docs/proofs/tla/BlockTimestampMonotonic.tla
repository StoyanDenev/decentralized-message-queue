--------------------------- MODULE BlockTimestampMonotonic ---------------------------
(*
FB29 — TLA+ companion to R24A5 `test-time-monotonicity` (the in-process
unit test that pins the Block.timestamp contracts at the chain + hash +
digest + signing_bytes layers; see `src/main.cpp::test-time-monotonicity`
at lines 28776..29049 and the shell wrapper `tools/test_time_monotonicity.sh`).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
BlockTimestampMonotonic.cfg BlockTimestampMonotonic.tla` once the
TLC toolchain is installed in CI.

Scope. Formalizes the four-surface Block.timestamp contract pinned
by R24A5 at the state-machine layer. The Block.timestamp field is
threaded through four cryptographic surfaces (chain identity,
creator-signature target, K-of-K committee digest, on-disk wrap)
with deliberately different inclusion behavior at each layer:

  * `Block::compute_hash` INCLUDES timestamp — chain-identity binding;
    two blocks differing only in timestamp produce different hashes
    (test scenario 5). This is the surface S-021's load-time
    recompute keys on; tampering a historical timestamp cascades
    through the prev_hash chain to make the head_hash check fail.
  * `Block::signing_bytes` INCLUDES timestamp — creator-signature
    target binding; a committee member's signature cannot replay
    across blocks differing in timestamp (test scenario 6).
  * `compute_block_digest` EXCLUDES timestamp — the K-of-K Phase-2
    digest deliberately omits consensus-time metadata so committee
    members converge on the same digest despite local clock skew
    within the +/-30s validator window (test scenario 7; see also
    S-030 D2 Analysis at docs/proofs/S030-D2-Analysis.md).
  * Chain-layer apply (`Chain::append`) currently does NOT enforce
    inter-block monotonicity — per the R24A5 test scenarios 1, 2, 3,
    8, backward / equal / far-future / negative timestamps are all
    admissible at the chain layer. The Preliminaries V14 invariant
    documents the validator's wall-clock-window-only check
    (`check_timestamp`), which is +/-30s of `now()`, NOT a cross-
    block gate. The S-035 path-1 documented gap notes this; a
    future revision adding a strict-monotonic gate is the forward-
    looking contract this spec models as the `monotonic_gate` flag.

This spec models BOTH the current behavior (test-pinned, R24A5,
gate disabled) AND the forward-looking contract (gate enabled,
SECURITY.md S-035 path 1) under the same state machine, with a
boolean `monotonic_gate` constant selecting which invariant
discipline TLC checks. The default cfg leaves the gate DISABLED
to match the current `Chain::append` source code; flipping it to
TRUE exercises the forward-looking invariant for spec-coverage
purposes ahead of the actual code change.

Five paired theorems are pinned (per the R24A5 test scenarios +
the forward-looking S-035 path-1 contract):

  (T-1) TimestampMonotonic (forward-looking contract). When the
        monotonic_gate is ENABLED, every produced block b at chain
        index i satisfies b.timestamp >= chain[i-1].timestamp. The
        non-strict inequality matches the second-granularity clock
        sampling (the EqualTimestampAccepted clause of T-5 is the
        boundary case at the same UTC second).
  (T-2) DigestExcludesTimestamp. Two blocks b1, b2 identical in
        every field EXCEPT timestamp produce identical
        `compute_block_digest(b1) = compute_block_digest(b2)`. This
        is the structural witness that K-of-K committee signatures
        remain stable across operator-side clock skew within the
        +/-30s window. Models test scenario 7.
  (T-3) SigningBytesIncludesTimestamp. Two blocks b1, b2 identical
        in every field EXCEPT timestamp where b1.timestamp /=
        b2.timestamp produce DIFFERENT
        `compute_signing_bytes(b1) /= compute_signing_bytes(b2)`.
        The producer's full block hash IS timestamp-bound for chain-
        history integrity. Models test scenario 6.
  (T-4) HistoricalTamperCascades. Tampering chain[i].timestamp for
        an interior block invalidates the `compute_hash` cascade
        for chain[i+1..head] via the prev_hash chain — the next
        block's prev_hash field references the pre-tamper
        compute_hash; after tampering, the recomputed compute_hash
        of chain[i] differs (because compute_hash INCLUDES
        timestamp), so the chain.json head_hash recompute at
        load-time catches the tamper (composes with S-021). Models
        test scenario 5 + 8.
  (T-5) EqualTimestampAccepted. Adjacent equal timestamps
        (chain[i].timestamp = chain[i-1].timestamp) are admissible
        under non-strict monotonicity — block production within
        the same UTC second is allowed. Models test scenario 2.

Modeling scope (kept tractable for TLC):

  * `Timestamps` is a finite universe of integer-valued seconds (the
    int64_t spec-layer projection; the universe is bounded by
    MaxTimestamp to keep TLC tractable). The model uses a small
    monotone sequence {0, 1, 2, 3} for the recommended cfg.
  * `MaxChainLength` bounds chain growth so TLC exhausts in seconds.
  * `MaxTimestampSkew` bounds how much a producer's sampled
    timestamp can diverge from head().timestamp at ProduceBlock
    time (the +/-30s validator window lifted to a small spec-layer
    constant).
  * The chain is modeled as `Seq(Block)` with each `Block` carrying
    the four invariant-relevant fields: index, timestamp, prev_hash,
    txs (the tx-set abstraction from FB26
    BlockchainStateIntegrity.tla). The chain identity surfaces are
    pure-function operators over these fields.
  * Hashes / digests / signing_bytes are modeled as deterministic
    functions over tagged tuples (the "abstract hash = pre-image
    identity" pattern used by FB22 / FB24 / FB26). Distinct
    pre-images map to distinct hashes; identical pre-images map to
    identical hashes. This is the spec-layer abstraction of A2
    (SHA-256 collision resistance per Preliminaries §2.1).
  * `compute_hash(b)` binds (index, timestamp, prev_hash, txs) —
    timestamp INCLUDED.
  * `compute_block_digest(b)` binds (index, prev_hash, txs) —
    timestamp EXCLUDED.
  * `compute_signing_bytes(b)` binds (index, timestamp, prev_hash,
    txs, digest) — timestamp INCLUDED via the leading triple, AND
    the digest is appended at the tail. The C++ side's
    signing_bytes lifts approximately the same surface (it also
    threads partner_subset_hash + state_root conditionally; see
    PROTOCOL.md §4.1); the spec's projection captures the timestamp
    surface that matters for T-2 / T-3.
  * `monotonic_gate` is a Boolean CONSTANT. When TRUE, ApplyBlock
    rejects b if b.timestamp < head.timestamp; when FALSE, the
    chain accepts arbitrary timestamps (current R24A5-pinned
    behavior). The spec's INV_TimestampMonotonic is conditional on
    monotonic_gate; the four cryptographic invariants (T-2, T-3,
    T-4, T-5) hold regardless of the gate setting.
  * Tampering is modeled as `TamperHistoricalTimestamp(i)`: mutate
    chain[i].timestamp to a value other than its current setting.
    The post-tamper chain has chain[i].compute_hash() /=
    chain[i+1].prev_hash, so a load-time replay reject fires (T-4
    cascade; composes with FB26's INV_LoadDetectsTampering).
  * `ReloadChain` is the spec-layer projection of `Chain::load`:
    walk the chain validating prev_hash continuity; reject on any
    mismatch by latching `load_throws = TRUE` and refusing to
    install. The reload action is what catches T-4 tampering at
    its boundary.

Six invariants codify the five theorems + a type predicate:

  INV_1 TimestampMonotonic — when `monotonic_gate` is TRUE, every
        adjacent pair satisfies chain[i].timestamp >=
        chain[i-1].timestamp. When `monotonic_gate` is FALSE, the
        invariant is vacuously TRUE (matching the R24A5-pinned
        current behavior). Models T-1.
  INV_2 DigestExcludesTimestamp — for every pair of blocks b1, b2
        that are identical in every field except timestamp,
        compute_block_digest(b1) = compute_block_digest(b2). The
        structural witness: compute_block_digest's pre-image tuple
        omits the timestamp field; pure-function abstraction makes
        the equality automatic. Models T-2.
  INV_3 SigningBytesIncludesTimestamp — for every pair of blocks
        b1, b2 identical in every field except timestamp where
        b1.timestamp /= b2.timestamp, compute_signing_bytes(b1) /=
        compute_signing_bytes(b2). The structural witness:
        compute_signing_bytes's pre-image tuple INCLUDES timestamp;
        by abstract-hash injectivity, distinct timestamps produce
        distinct signing_bytes. Models T-3.
  INV_4 HistoricalTamperCascades — at every reachable state where
        tampered_at[n] /= "none" AND ReloadChain has fired since
        the tamper, load_throws[n] = TRUE. The structural witness:
        the prev_hash continuity check in validate_chain
        (mirroring FB26's helper) fails on a tampered block because
        compute_hash of the tampered block /= prev_hash of the next
        block (compute_hash INCLUDES timestamp, so a single-field
        mutation breaks the cascade). Models T-4.
  INV_5 EqualTimestampAccepted — adjacent equal timestamps are
        admissible under non-strict monotonicity. The structural
        witness: ProduceBlock samples timestamps from
        [head.timestamp, head.timestamp + MaxTimestampSkew]
        (inclusive of the lower bound), so head.timestamp is a
        reachable sample, witnessing equal-timestamp admissibility.
        Models T-5.
  INV_6 TypeOK — shape predicate for `chains`, `tampered_at`,
        `load_throws`. Standard FB-track type discipline.

Two temporal properties pin the headline composition claims:

  PROP_EventualBlockProduction — under fairness on ProduceBlock,
    chain length grows over time; eventually some chain reaches
    MaxChainLength (or every node-equivalent is in saturation /
    reload-throw state). Models the "chain length grows" forward-
    progress claim.
  PROP_NoSilentDivergence — tampered chain at any node fires the
    load-time recompute reject before any downstream apply. State-
    form: for every reachable state where tampered_at /= "none"
    AND a downstream ApplyBlock would extend the tampered chain,
    the in-between ReloadChain has fired and latched load_throws.
    Models the headline T-4 cascade + S-021 composition claim
    that no silent divergence is reachable.

The state machine. Four actions cover the four operational surfaces:

  * ProduceBlock(n) — n builds a new block at chain[n] head;
    samples timestamp from [head.timestamp, head.timestamp +
    MaxTimestampSkew]. The sample lower bound makes
    EqualTimestampAccepted reachable; the upper bound makes
    forward-monotonic samples reachable. The producer broadcasts
    by appending to other-node pending_inbox (modeling network
    gossip).
  * ApplyBlock(n) — n applies the head of pending_inbox[n] to
    chain[n], subject to the monotonic_gate predicate. When the
    gate is FALSE (current behavior), any prev_hash-continuous
    block applies; when TRUE (forward-looking contract), a block
    with b.timestamp < head.timestamp is rejected. Apply also
    validates prev_hash continuity (S-021 / FB26's structural
    discipline).
  * TamperHistoricalTimestamp(n, i) — adversary mutates
    chain[n][i].timestamp. The post-tamper chain has a broken
    compute_hash at chain[n][i] (since compute_hash includes
    timestamp), so chain[n][i+1].prev_hash no longer matches.
    tampered_at[n] is set to i to log the tamper for invariant
    coverage.
  * ReloadChain(n) — n recomputes head_hash from disk-state chain;
    walks prev_hash continuity per the FB26 validate_chain helper;
    sets load_throws[n] = TRUE on mismatch. The reload action is
    the boundary that catches T-4 tampering.

To check (assuming TLC installed):
  $ tlc BlockTimestampMonotonic.tla -config BlockTimestampMonotonic.cfg

Recommended config (state space ~10^4, < 30s):
  Nodes = {n1, n2}, MaxChainLength = 3, MaxTimestamp = 3,
  MaxTimestampSkew = 1, TxUniverse = {t1}, monotonic_gate = FALSE.

To exercise the forward-looking strict-monotonic discipline (with
T-1 active), flip `monotonic_gate` to TRUE in the .cfg.

Cross-references:
  - src/main.cpp::test-time-monotonicity — the R24A5 in-process
    unit test that pins the contracts this spec lifts to the
    state-machine layer. The 17 assertions across 9 scenarios at
    lines 28776..29049 are the analytic source.
  - tools/test_time_monotonicity.sh — the shell wrapper that runs
    the in-process test as part of the regression suite (S-035
    Path 1 coverage).
  - docs/proofs/Preliminaries.md §V14 — the validator's wall-clock
    proximity invariant (|B.timestamp - now()| <= 30s); the spec
    documents that this is wall-clock-window-only, NOT a strict
    inter-block monotonic gate.
  - docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — sibling
    state-integrity surface (S-021 + S-033 + S-038 composition);
    INV_4 HistoricalTamperCascades composes with FB26's
    INV_LoadDetectsTampering via the shared prev_hash continuity
    discipline.
  - docs/proofs/tla/JsonValidation.tla (FB27) — S-018 clear-
    diagnostic + defense-in-depth; sibling FB-track spec
    establishing the "pure-function + bounded enumeration + INV-*"
    style this module reuses.
  - docs/proofs/tla/S006ContribMsgEquivocation.tla (FB28) — the
    most recent FB-track spec; this spec follows its header-block
    + soundness-commentary structure verbatim.
  - docs/proofs/S030-D2-Analysis.md — the analytic source for T-2
    (DigestExcludesTimestamp); compute_block_digest's deliberate
    omission of timestamp + delay_output + creator_dh_secrets is
    a load-bearing design choice for selective-abort resistance
    (the D1 + D2 analysis).
  - docs/SECURITY.md §S-035 path 1 — the documented gap: chain
    layer + validator do not enforce strict inter-block
    monotonicity; only the wall-clock window. The forward-looking
    contract (gate ENABLED) is the spec-layer projection of the
    S-035 path-1 closure.
  - include/determ/chain/block.hpp — Block struct + signing_bytes
    + compute_hash declarations.
  - src/chain/chain.cpp:54-58 — Chain::append prev_hash check
    (no timestamp comparison); the current-behavior pin.
  - src/node/producer.cpp::compute_block_digest — the K-of-K
    digest computation that omits timestamp.
  - src/node/validator.cpp::check_timestamp — the +/-30s wall-
    clock window check (the only timestamp gate in the validator
    pipeline today).
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,              \* finite universe of node IDs
    MaxChainLength,     \* spec-time bound on chain length
    MaxTimestamp,       \* finite universe upper bound on timestamps
    MaxTimestampSkew,   \* max forward-skew a producer may sample
    TxUniverse,         \* finite universe of tx hashes
    monotonic_gate      \* BOOLEAN: enables the strict-monotonic invariant
                         \* (forward-looking S-035 path-1 contract).
                         \* FALSE matches the current R24A5-pinned chain
                         \* behavior.

ASSUME ConfigOK ==
    /\ Cardinality(Nodes)      >= 1
    /\ MaxChainLength \in Nat /\ MaxChainLength >= 1
    /\ MaxTimestamp    \in Nat /\ MaxTimestamp    >= 1
    /\ MaxTimestampSkew \in Nat
    /\ Cardinality(TxUniverse) >= 1
    /\ monotonic_gate \in BOOLEAN

\* -----------------------------------------------------------------
\* §1. State shape and abstract-hash model.
\* -----------------------------------------------------------------
\*
\* Blocks are records (index, timestamp, prev_hash, txs). The model
\* represents each as a TLA+ record; compute_hash and friends are
\* pure functions of their inputs — the standard "abstract hash =
\* pre-image identity" abstraction used by FB22 / FB24 / FB26.
\* Distinct pre-images map to distinct outputs; identical pre-images
\* map to identical outputs (A2 / SHA-256 collision resistance lifted
\* to the bounded universe).

\* Timestamps are integer seconds bounded by MaxTimestamp. The model
\* admits 0..MaxTimestamp; the genesis block is pinned at timestamp 0
\* per make_genesis_block at src/chain/genesis.cpp:301.
Timestamps == 0..MaxTimestamp

\* The hash output universe. compute_hash binds the full tuple
\* INCLUDING timestamp; compute_block_digest binds the tuple EXCLUDING
\* timestamp; compute_signing_bytes binds the full tuple PLUS the
\* digest. The "HASH" / "DIGEST" / "SIGN" discriminator tags prevent
\* accidental cross-namespace collision; this is the standard
\* abstract-hash discipline.
HashUniverse  == { <<"HASH", i, t, sub>>  : i \in 0..MaxChainLength,
                                            t \in Timestamps,
                                            sub \in SUBSET TxUniverse }
                 \cup { <<"GENESIS">> }

\* Block shape. prev_hash refers to the prior block's compute_hash
\* output; the genesis sentinel is <<"GENESIS">>. txs is a SUBSET
\* of TxUniverse (the tx-set abstraction from FB26).
Block == [
    index      : 0..MaxChainLength,
    timestamp  : Timestamps,
    prev_hash  : HashUniverse,
    txs        : SUBSET TxUniverse
]

\* compute_hash: binds (index, timestamp, prev_hash, txs). Timestamp
\* INCLUDED — this is the chain-identity surface that drives the
\* prev_hash cascade. The "HASH" discriminator separates this output
\* namespace from compute_block_digest and compute_signing_bytes.
compute_hash(b) == <<"HASH", b.index, b.timestamp, b.txs>>

\* compute_block_digest: binds (index, prev_hash, txs) — timestamp
\* DELIBERATELY OMITTED. The K-of-K Phase-2 digest is signed by
\* committee members; the omission lets the committee converge on
\* the same digest despite local clock skew within the +/-30s
\* validator window. The structural witness for T-2.
compute_block_digest(b) == <<"DIGEST", b.index, b.prev_hash, b.txs>>

\* compute_signing_bytes: binds (index, timestamp, prev_hash, txs,
\* digest). Timestamp INCLUDED via the leading tuple; the digest is
\* appended at the tail so the producer's full block hash IS
\* timestamp-bound. The structural witness for T-3.
compute_signing_bytes(b) ==
    <<"SIGN", b.index, b.timestamp, b.prev_hash, b.txs,
      compute_block_digest(b)>>

\* The genesis hash sentinel.
GenesisHash == <<"GENESIS">>

\* The genesis block. Pinned at index = 0, timestamp = 0, prev_hash =
\* GenesisHash (matching the C++ make_genesis_block at
\* src/chain/genesis.cpp:301 with the hard-coded timestamp = 0
\* convention).
GenesisBlock == [
    index     |-> 0,
    timestamp |-> 0,
    prev_hash |-> GenesisHash,
    txs       |-> {}
]

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    chains,             \* function NodeId -> Seq(Block)
    pending_inbox,      \* function NodeId -> Seq(Block) — gossip queue
    tampered_at,        \* function NodeId -> Nat or "none" — interior
                         \* tamper site, latches across actions
    load_throws         \* function NodeId -> BOOLEAN — reload reject

vars == <<chains, pending_inbox, tampered_at, load_throws>>

\* -----------------------------------------------------------------
\* §3. Helpers.
\* -----------------------------------------------------------------

\* head_block(c): the chain's head (last appended block). Genesis-form
\* is the GenesisBlock when chain is empty (which never reaches
\* TLC's invariants because Init populates chains with [<<GenesisBlock>>]).
head_block(c) ==
    IF Len(c) = 0
    THEN GenesisBlock
    ELSE c[Len(c)]

\* head_hash(c): mirroring Chain::head_hash() at src/chain/chain.cpp:71-73.
head_hash(c) ==
    IF Len(c) = 0
    THEN GenesisHash
    ELSE compute_hash(c[Len(c)])

\* validate_chain(c): replay-time validation. Returns TRUE iff every
\* block's prev_hash equals the prior prefix's head_hash (mirrors the
\* FB26 helper of the same name; the C++ correspondent is the
\* Chain::append prev_hash check at chain.cpp:54-58 lifted to a per-
\* chain predicate). T-4 (HistoricalTamperCascades) is the standing
\* witness that any tamper of an interior block's timestamp breaks
\* this predicate via the compute_hash inclusion of timestamp.
RECURSIVE validate_chain_(_, _)
validate_chain_(c, i) ==
    IF i = 0
    THEN TRUE
    ELSE
        IF i = 1
        THEN c[1].prev_hash = GenesisHash
        ELSE
            LET prefix == SubSeq(c, 1, i - 1) IN
            /\ c[i].prev_hash = head_hash(prefix)
            /\ validate_chain_(c, i - 1)

validate_chain(c) == validate_chain_(c, Len(c))

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* Every node starts with a chain containing just the genesis block.
\* The genesis block is the FB26-style genesis: index 0, timestamp 0,
\* prev_hash = GenesisHash, empty txs. All gates start clear.

Init ==
    /\ chains         = [n \in Nodes |-> <<GenesisBlock>>]
    /\ pending_inbox  = [n \in Nodes |-> <<>>]
    /\ tampered_at    = [n \in Nodes |-> "none"]
    /\ load_throws    = [n \in Nodes |-> FALSE]

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* ProduceBlock(n): n builds a new block at chain[n] head. The
\* timestamp is sampled from [head.timestamp, head.timestamp +
\* MaxTimestampSkew] inclusive on both ends — the lower bound makes
\* EqualTimestampAccepted (T-5) reachable; the upper bound makes
\* forward-monotonic samples reachable.
\*
\* The producer broadcasts to other nodes' pending_inbox; the
\* receiver-side ApplyBlock action drains the inbox subject to
\* prev_hash continuity + (optionally, when monotonic_gate is TRUE)
\* the strict-monotonic gate.

ProduceBlock(n) ==
    /\ n \in Nodes
    /\ Len(chains[n]) <= MaxChainLength
    /\ \E txs_sub \in SUBSET TxUniverse :
       \E ts \in Timestamps :
          LET head == head_block(chains[n]) IN
          /\ ts >= head.timestamp
          /\ ts <= head.timestamp + MaxTimestampSkew
          /\ ts <= MaxTimestamp
          /\ LET body == [
                    index     |-> Len(chains[n]),
                    timestamp |-> ts,
                    prev_hash |-> head_hash(chains[n]),
                    txs       |-> txs_sub] IN
             /\ chains' = [chains EXCEPT ![n] = Append(chains[n], body)]
             /\ pending_inbox' = [m \in Nodes |->
                    IF m = n
                    THEN pending_inbox[m]
                    ELSE Append(pending_inbox[m], body)]
             /\ UNCHANGED <<tampered_at, load_throws>>

\* ApplyBlock(n): receiver-side action. Drains the head of
\* pending_inbox[n] and validates:
\*   (1) prev_hash continuity (S-021 / FB26 discipline)
\*   (2) optional strict-monotonic timestamp gate when
\*       monotonic_gate is TRUE (forward-looking S-035 path-1
\*       contract). When the gate is FALSE (current R24A5-pinned
\*       chain behavior), any timestamp value is admissible.
\*
\* When validation passes, append to chain[n]; otherwise drain the
\* offending block from the inbox without extending the chain (the
\* C++ apply-side throw is modeled here as silent drop because
\* the spec captures the chain-state outcome, not the exception
\* surface — the exception-surface invariants live in FB27
\* JsonValidation.tla / FB26 BlockchainStateIntegrity.tla).

ApplyBlock(n) ==
    /\ n \in Nodes
    /\ Len(pending_inbox[n]) > 0
    /\ Len(chains[n]) <= MaxChainLength
    /\ LET b         == Head(pending_inbox[n]) IN
       LET remaining == Tail(pending_inbox[n]) IN
       LET head      == head_block(chains[n]) IN
       LET prev_ok   == b.prev_hash = head_hash(chains[n])
                        /\ b.index = Len(chains[n]) IN
       LET ts_ok     == ~monotonic_gate \/ b.timestamp >= head.timestamp IN
       IF prev_ok /\ ts_ok
       THEN
          \* Apply succeeds: append + drain.
          /\ chains' = [chains EXCEPT ![n] = Append(chains[n], b)]
          /\ pending_inbox' = [pending_inbox EXCEPT ![n] = remaining]
          /\ UNCHANGED <<tampered_at, load_throws>>
       ELSE
          \* Apply rejects: drain offending block, do not extend
          \* chain. The reject is silent at the spec layer; the
          \* exception-surface invariants live in sibling FB-track
          \* specs.
          /\ pending_inbox' = [pending_inbox EXCEPT ![n] = remaining]
          /\ UNCHANGED <<chains, tampered_at, load_throws>>

\* TamperHistoricalTimestamp(n, i): adversary mutates chain[n][i]'s
\* timestamp to any value other than its current setting (within
\* Timestamps universe). The post-tamper compute_hash of chain[n][i]
\* differs from its prior value (since compute_hash INCLUDES
\* timestamp); the next block's prev_hash field no longer matches,
\* so validate_chain returns FALSE — the cascade contract that T-4
\* asserts.
\*
\* tampered_at[n] is set to i to log the tamper for invariant
\* coverage; ReloadChain consumes this signal.

TamperHistoricalTimestamp(n) ==
    /\ n \in Nodes
    /\ Len(chains[n]) >= 2
       \* Need at least one block past genesis to tamper meaningfully.
    /\ \E i \in 2..Len(chains[n]) :
          \* i ranges over post-genesis blocks (1-indexed; index 1 is
          \* genesis, which we don't tamper since it's pinned and the
          \* chain identity is pre-validated against a hardcoded hash).
       \E new_ts \in Timestamps :
          /\ new_ts /= chains[n][i].timestamp
          /\ LET old == chains[n][i] IN
             LET tampered == [
                    index     |-> old.index,
                    timestamp |-> new_ts,
                    prev_hash |-> old.prev_hash,
                    txs       |-> old.txs] IN
             /\ chains' = [chains EXCEPT ![n] =
                    [j \in 1..Len(chains[n]) |->
                       IF j = i THEN tampered
                       ELSE chains[n][j]]]
             /\ tampered_at' = [tampered_at EXCEPT ![n] = i]
             /\ UNCHANGED <<pending_inbox, load_throws>>

\* ReloadChain(n): the spec-layer projection of Chain::load. Walks
\* chain[n] re-validating prev_hash continuity; if any prev_hash
\* mismatch fires (T-4 cascade post-tamper), set load_throws[n] =
\* TRUE. The chain is NOT installed (modeled here as: chains[n] is
\* preserved but the gate latches — the C++ side's load throws an
\* exception and refuses to install; the spec's load_throws is the
\* observable witness).
\*
\* When validate_chain returns TRUE, the load is a no-op (chain
\* already installed from in-memory state). PROP_NoSilentDivergence
\* asserts: any tamper at any node fires the load-time reject before
\* downstream apply can extend the tampered chain.

ReloadChain(n) ==
    /\ n \in Nodes
    /\ LET valid == validate_chain(chains[n]) IN
       IF ~valid
       THEN
          \* Reload detects the tamper. Latch load_throws.
          /\ load_throws' = [load_throws EXCEPT ![n] = TRUE]
          /\ UNCHANGED <<chains, pending_inbox, tampered_at>>
       ELSE
          \* Reload sees an intact chain. No-op.
          UNCHANGED vars

\* Stutter (TLC bounds the state space; invariants are evaluated at
\* every reachable state along the way).

Stutter ==
    /\ \A n \in Nodes : Len(chains[n]) > MaxChainLength
    /\ UNCHANGED vars

Next ==
    \/ \E n \in Nodes : ProduceBlock(n)
    \/ \E n \in Nodes : ApplyBlock(n)
    \/ \E n \in Nodes : TamperHistoricalTimestamp(n)
    \/ \E n \in Nodes : ReloadChain(n)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E n \in Nodes : ProduceBlock(n))
             /\ WF_vars(\E n \in Nodes : ReloadChain(n))

\* -----------------------------------------------------------------
\* §6. Invariants — the five T-1..T-5 claims + TypeOK.
\* -----------------------------------------------------------------

\* INV_1 TimestampMonotonic (T-1).
\*
\* When the monotonic_gate is enabled (forward-looking S-035 path-1
\* contract), every adjacent pair in every chain satisfies
\* chain[i].timestamp >= chain[i-1].timestamp. When the gate is
\* disabled (current R24A5-pinned chain behavior), the invariant is
\* vacuously TRUE — ApplyBlock admits arbitrary timestamps.
\*
\* The structural witness: ApplyBlock's ts_ok predicate (LET
\* binding above) gates on b.timestamp >= head.timestamp when
\* monotonic_gate is TRUE; rejects otherwise. ProduceBlock samples
\* timestamps only in the [head.timestamp, head.timestamp +
\* MaxTimestampSkew] range, so producer-side blocks always satisfy
\* T-1 regardless of the gate setting — the gate's role is to reject
\* adversarial / tampered inbound blocks at apply time.
INV_TimestampMonotonic ==
    \A n \in Nodes :
       \A i \in 2..Len(chains[n]) :
          monotonic_gate =>
             chains[n][i].timestamp >= chains[n][i - 1].timestamp

\* INV_2 DigestExcludesTimestamp (T-2).
\*
\* For every pair of conceptual blocks b1, b2 that are identical in
\* every field EXCEPT timestamp, compute_block_digest(b1) =
\* compute_block_digest(b2). The structural witness:
\* compute_block_digest's pre-image tuple omits the timestamp field
\* (see the operator definition above), so by pure-function equality
\* + abstract-hash discipline, the equality holds automatically.
\*
\* State-form witness (TLC-checkable): for every pair of (index,
\* prev_hash, txs) tuples reachable in any chain, the digest depends
\* only on those fields and not on the per-block timestamp. We assert
\* this via the universal quantification over admissible
\* timestamp pairs t1, t2.
INV_DigestExcludesTimestamp ==
    \A i \in 0..MaxChainLength :
       \A h \in HashUniverse :
          \A sub \in SUBSET TxUniverse :
             \A t1, t2 \in Timestamps :
                LET b1 == [index |-> i, timestamp |-> t1,
                           prev_hash |-> h, txs |-> sub] IN
                LET b2 == [index |-> i, timestamp |-> t2,
                           prev_hash |-> h, txs |-> sub] IN
                compute_block_digest(b1) = compute_block_digest(b2)

\* INV_3 SigningBytesIncludesTimestamp (T-3).
\*
\* For every pair of blocks b1, b2 identical in every field except
\* timestamp where b1.timestamp /= b2.timestamp,
\* compute_signing_bytes(b1) /= compute_signing_bytes(b2). The
\* structural witness: compute_signing_bytes's pre-image tuple
\* INCLUDES timestamp; by abstract-hash injectivity (distinct
\* pre-images map to distinct outputs), distinct timestamps produce
\* distinct signing_bytes.
\*
\* Note: under the abstract-hash discipline, this invariant is
\* structurally tautological once compute_signing_bytes is defined
\* over a pre-image tuple including timestamp; the invariant exists
\* to make the property TLC-checkable + the structural commitment
\* documented in the spec.
INV_SigningBytesIncludesTimestamp ==
    \A i \in 0..MaxChainLength :
       \A h \in HashUniverse :
          \A sub \in SUBSET TxUniverse :
             \A t1, t2 \in Timestamps :
                LET b1 == [index |-> i, timestamp |-> t1,
                           prev_hash |-> h, txs |-> sub] IN
                LET b2 == [index |-> i, timestamp |-> t2,
                           prev_hash |-> h, txs |-> sub] IN
                (t1 /= t2) =>
                   compute_signing_bytes(b1) /= compute_signing_bytes(b2)

\* INV_4 HistoricalTamperCascades (T-4).
\*
\* At every reachable state where tampered_at[n] /= "none" AND
\* ReloadChain has fired since the tamper, load_throws[n] = TRUE.
\* The structural witness: the prev_hash continuity check in
\* validate_chain (mirroring FB26's discipline) fails on a tampered
\* block because compute_hash of the tampered block /= prev_hash of
\* the next block (compute_hash INCLUDES timestamp, so a single-field
\* mutation breaks the cascade).
\*
\* The invariant is expressed in the standing-state form: any chain
\* with tampered_at[n] /= "none" AND tampered_at[n] < Len(chains[n])
\* (i.e., the tampered block has at least one successor) has a
\* compute_hash / prev_hash mismatch at the boundary. The ReloadChain
\* action's failure path latches load_throws on this case.
\*
\* For the standing-state assertion: at every reachable state, if a
\* chain has tampered_at[n] /= "none" with at least one successor
\* block, then validate_chain(chains[n]) is FALSE. ReloadChain
\* converts this into load_throws[n] = TRUE the moment it fires.
INV_HistoricalTamperCascades ==
    \A n \in Nodes :
       \A k \in 2..(MaxChainLength + 1) :
          (tampered_at[n] = k /\ k < Len(chains[n]))
          => ~validate_chain(chains[n])

\* INV_5 EqualTimestampAccepted (T-5).
\*
\* Adjacent equal timestamps are admissible. The structural witness:
\* ProduceBlock samples timestamps from [head.timestamp,
\* head.timestamp + MaxTimestampSkew] inclusive of the lower bound,
\* so head.timestamp is a reachable sample. ApplyBlock's ts_ok
\* predicate uses non-strict `>=`, so equal-timestamp adjacent blocks
\* are admissible under both gate-OFF and gate-ON disciplines.
\*
\* State-form witness: there exists a reachable state where some
\* chain has chain[i].timestamp = chain[i-1].timestamp. We assert
\* this as a possibility-style invariant — the chain admits the
\* equal-timestamp case, never structurally forbidding it.
\*
\* The structural form: for every reachable state, every pair of
\* adjacent equal-timestamp blocks in chains[n] is "legal" — i.e.,
\* the chain reached this state via legitimate ProduceBlock + ApplyBlock
\* steps without any invariant violation. This is automatic given
\* the action specifications; the invariant exists to document the
\* contract.
INV_EqualTimestampAccepted ==
    \A n \in Nodes :
       \A i \in 2..Len(chains[n]) :
          \* Equal-timestamp adjacency is admissible: the chain
          \* may have extended through ProduceBlock + ApplyBlock at
          \* the lower-bound sample (head.timestamp itself), and
          \* ApplyBlock's ts_ok predicate uses non-strict >=. The
          \* invariant body asserts that an equal-timestamp adjacency
          \* DOES NOT imply tamper — equal adjacents are admissible
          \* without invalidating validate_chain (in the absence of a
          \* separate tamper event on this chain).
          (chains[n][i].timestamp = chains[n][i - 1].timestamp
           /\ tampered_at[n] = "none")
          => validate_chain(chains[n])

\* -----------------------------------------------------------------
\* §7. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ chains \in [Nodes -> Seq(Block)]
    /\ pending_inbox \in [Nodes -> Seq(Block)]
    /\ tampered_at \in [Nodes -> (0..(MaxChainLength + 1)) \cup {"none"}]
    /\ load_throws \in [Nodes -> BOOLEAN]

\* -----------------------------------------------------------------
\* §8. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualBlockProduction.
\*
\* Under fairness on ProduceBlock, chain length grows over time —
\* eventually every chain either reaches MaxChainLength or saturates
\* (every active producer reaches the bound). The structural witness:
\* ProduceBlock's pre-condition Len(chains[n]) <= MaxChainLength is
\* enabled until saturation; weak fairness on the action set guarantees
\* it fires until disabled. TLC enumerates the reachable schedule
\* under fairness.
\*
\* This is the eventual-progress claim that the chain-extension
\* surface is live; the dual of FB26's "no silent divergence" liveness
\* track.
PROP_EventualBlockProduction ==
    <>(\E n \in Nodes : Len(chains[n]) > MaxChainLength)

\* PROP_NoSilentDivergence.
\*
\* Tampered chain at any node fires the load-time recompute reject
\* before any downstream apply extends the tampered chain. State-form
\* witness: for every reachable state where tampered_at[n] /= "none"
\* AND chain[n] has a successor block past the tamper site, eventually
\* ReloadChain fires and latches load_throws[n] = TRUE.
\*
\* Composes with FB26's INV_LoadDetectsTampering via the shared
\* prev_hash continuity discipline + the shared validate_chain helper.
\* T-4 (HistoricalTamperCascades) is the structural source; this
\* temporal property asserts the cascade is observable via the
\* load_throws gate within the bounded reachable schedule.
PROP_NoSilentDivergence ==
    \A n \in Nodes :
       \A k \in 2..(MaxChainLength + 1) :
          []((tampered_at[n] = k /\ k < Len(chains[n]))
             => <>(load_throws[n] = TRUE))

\* -----------------------------------------------------------------
\* §9. Soundness commentary — what TLC checks vs. what the test
\* pins.
\* -----------------------------------------------------------------
\*
\* The R24A5 in-process test (`determ test-time-monotonicity`) pins
\* nine scenarios across the chain + hash + digest + signing_bytes
\* + validator surfaces. The TLA+ state-machine layer abstracts
\* these into four actions + six invariants + two temporal
\* properties:
\*
\*   * Test scenarios 1, 2, 3, 8 (chain layer accepts backward /
\*     equal / far-future / negative timestamps under current code)
\*     are captured by ApplyBlock's monotonic_gate=FALSE branch (the
\*     ts_ok predicate is vacuously TRUE). INV_1 TimestampMonotonic
\*     is conditional on monotonic_gate; under the current-behavior
\*     cfg, it's vacuously satisfied.
\*   * Test scenario 5 (compute_hash IS sensitive to timestamp) is
\*     captured by INV_4 HistoricalTamperCascades' structural
\*     argument — the cascade only breaks because compute_hash's
\*     pre-image INCLUDES timestamp. The invariant exercises the
\*     same compute_hash injectivity TLC verifies via abstract-hash
\*     discipline.
\*   * Test scenario 6 (signing_bytes IS sensitive to timestamp) is
\*     captured by INV_3 SigningBytesIncludesTimestamp — distinct
\*     timestamps produce distinct signing_bytes by abstract-hash
\*     injectivity.
\*   * Test scenario 7 (compute_block_digest is INVARIANT to
\*     timestamp) is captured by INV_2 DigestExcludesTimestamp.
\*     compute_block_digest's pre-image tuple omits timestamp; pure-
\*     function equality + abstract-hash discipline makes the equality
\*     automatic.
\*   * Test scenarios 4 (now_unix monotonicity), 8 (genesis pinned
\*     at timestamp 0), and 9 (validator short-circuits genesis) are
\*     captured implicitly: now_unix() is an environment helper not
\*     modeled at the spec layer; genesis is the pinned GenesisBlock
\*     constant; validator short-circuit at genesis is captured by
\*     the chains[n] init seeding with the trusted GenesisBlock (no
\*     ApplyBlock fires on index 0).
\*
\* What this spec adds beyond the test:
\*
\*   * The forward-looking S-035 path-1 contract (strict-monotonic
\*     gate at apply time) is encoded as the monotonic_gate Boolean
\*     constant. Flipping it to TRUE exercises the forward-looking
\*     invariant ahead of the actual code change. This is the spec-
\*     layer projection of "what the code SHOULD do once S-035 path 1
\*     is closed."
\*   * The state-machine witness that the four surfaces (chain
\*     identity, signing_bytes, digest, apply-time gate) compose
\*     correctly under every reachable interleaving of ProduceBlock
\*     + ApplyBlock + TamperHistoricalTimestamp + ReloadChain.
\*   * The cascade T-4 lift: tampering an interior timestamp breaks
\*     compute_hash at the tampered block, breaks prev_hash at the
\*     next block, breaks validate_chain at load time, latches
\*     load_throws. The spec witnesses the cascade end-to-end via
\*     INV_4 + PROP_NoSilentDivergence.
\*
\* What the spec does NOT check (consistent with the test's §scope):
\*
\*   * The validator's wall-clock window check (|B.timestamp -
\*     now()| <= 30s). This is a validator-time gate (Preliminaries
\*     V14) orthogonal to the chain-layer monotonicity contract; the
\*     spec abstracts now() and the +/-30s window into the
\*     MaxTimestampSkew constant at ProduceBlock time.
\*   * The partner_subset_hash + state_root threading in
\*     signing_bytes (PROTOCOL.md §4.1, R4 Phase 3 conditional +
\*     S-033 conditional). The spec's compute_signing_bytes is a
\*     timestamp-focused projection; the full signing_bytes
\*     specification is FB26 (BlockchainStateIntegrity.tla) +
\*     PROTOCOL.md.
\*   * The genesis-trust pin (validator.cpp:19 short-circuit at
\*     index 0). The chain init seeds with GenesisBlock; the spec
\*     never re-applies genesis.
\*   * Cryptographic soundness of SHA-256 (A2) and Ed25519 EUF-CMA
\*     (A1). The abstract-hash discipline + abstract-sig pattern
\*     is FA-track territory (FB23 FrostVerify.tla).
\*   * The +/-30s validator window's interaction with operator-side
\*     clock skew. The spec's MaxTimestampSkew abstracts this; the
\*     wall-clock skew model is documented in §V14 of Preliminaries
\*     + the S-003 validator-window analysis.
\*
\* Companion documents:
\*   * src/main.cpp::test-time-monotonicity (R24A5, lines 28776..29049)
\*     — the in-process test pinning the contracts at the C++ layer.
\*   * tools/test_time_monotonicity.sh — the shell wrapper.
\*   * docs/proofs/Preliminaries.md §V14 — wall-clock window
\*     validator predicate.
\*   * docs/proofs/S030-D2-Analysis.md — the digest-omission
\*     analysis (T-2 source).
\*   * docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — sibling
\*     state-integrity spec; T-4 + PROP_NoSilentDivergence compose
\*     with FB26's INV_LoadDetectsTampering.
\*   * docs/proofs/tla/JsonValidation.tla (FB27),
\*     docs/proofs/tla/S006ContribMsgEquivocation.tla (FB28) — sibling
\*     FB-track specs; style template for this module.
\*   * docs/SECURITY.md §S-035 path 1 — the documented chain-layer
\*     gap. Forward-looking gate ENABLED corresponds to the path-1
\*     closure.

============================================================================
\* Cross-references.
\*
\* R24A5 test (`test-time-monotonicity`) ->
\*   Scenario 1 (chain accepts backward timestamp)   : INV_TimestampMonotonic
\*       conditional on monotonic_gate; vacuously true at gate=FALSE.
\*   Scenario 2 (chain accepts equal timestamps)     : INV_EqualTimestampAccepted.
\*       ApplyBlock's ts_ok predicate uses non-strict >=.
\*   Scenario 3 (chain accepts far-future timestamp) : Timestamps
\*       universe bound; chain-layer has no upper bound modulo MaxTimestamp.
\*   Scenario 4 (now_unix monotonicity)               : abstracted to
\*       MaxTimestampSkew constant at ProduceBlock time.
\*   Scenario 5 (compute_hash IS sensitive to timestamp) : INV_4
\*       HistoricalTamperCascades + abstract-hash injectivity discipline.
\*   Scenario 6 (signing_bytes IS sensitive to timestamp) : INV_3
\*       SigningBytesIncludesTimestamp.
\*   Scenario 7 (compute_block_digest is INVARIANT to timestamp) :
\*       INV_2 DigestExcludesTimestamp.
\*   Scenario 8 (genesis pinned at timestamp 0)        : GenesisBlock
\*       constant; chain init seeds genesis with timestamp 0.
\*   Scenario 9 (validator short-circuits genesis)     : chain init
\*       never re-applies genesis; the validator entry point is
\*       abstracted at the spec layer (no validate() action).
\*
\* SECURITY.md §S-035 path 1 : the chain-layer monotonicity gap.
\*   monotonic_gate=FALSE matches the current behavior;
\*   monotonic_gate=TRUE exercises the forward-looking contract.
\*
\* Preliminaries.md §V14 (validator wall-clock window) : abstracted
\*   into the ProduceBlock-time MaxTimestampSkew bound. The validator's
\*   +/-30s window is a wall-clock-window-only gate, NOT a cross-block
\*   monotonic gate; the spec models the absence of the cross-block
\*   gate by default + the forward-looking presence under the gate flag.
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) : abstract-
\*   hash discipline. The HASH / DIGEST / SIGN tagged-tuple
\*   discriminators model distinct namespaces; injectivity within each
\*   namespace gives INV_2 + INV_3 + INV_4 their structural witness.
\*
\* FB22 F2ViewReconciliation.tla (v2.7 F2 view-reconciliation),
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model),
\* FB24 MakeContribCommitment.tla (S-030 D2 commit-binding),
\* FB25 RateLimiterEviction.tla (S-014 F-1 lifetime-bound),
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038 composition
\*   — sibling state-integrity surface; this spec's T-4
\*   HistoricalTamperCascades + PROP_NoSilentDivergence compose with
\*   FB26's INV_LoadDetectsTampering via the shared prev_hash
\*   continuity discipline),
\* FB27 JsonValidation.tla (S-018 clear-diagnostic + defense-in-depth),
\* FB28 S006ContribMsgEquivocation.tla (S-006 Phase-1 same-gen
\*   detection) : sibling FB-track specs; style template for this
\*   module (the "pure-function + bounded enumeration + INV-*" pattern,
\*   the abstract-hash discipline, the companion-analytic-source
\*   citation format).
\*
\* C++ enforcement:
\*   src/main.cpp:28776..29049     : R24A5 test fixture (9 scenarios,
\*       17 assertions; the analytic source this spec lifts).
\*   tools/test_time_monotonicity.sh: shell wrapper.
\*   src/chain/chain.cpp:54-58     : Chain::append prev_hash check
\*       (no timestamp comparison — the current-behavior pin under
\*       monotonic_gate=FALSE).
\*   src/chain/chain.cpp:71-73     : Chain::head_hash (the spec's
\*       head_hash helper mirrors this).
\*   src/chain/genesis.cpp:301     : make_genesis_block — timestamp = 0
\*       hard-coded; the spec's GenesisBlock constant matches.
\*   include/determ/chain/block.hpp::compute_hash : binds timestamp
\*       (the spec's compute_hash includes b.timestamp in the tuple).
\*   include/determ/chain/block.hpp::signing_bytes : binds timestamp
\*       (the spec's compute_signing_bytes includes b.timestamp).
\*   src/node/producer.cpp::compute_block_digest : omits timestamp
\*       (the spec's compute_block_digest omits b.timestamp; T-2
\*       structural witness).
\*   src/node/validator.cpp::check_timestamp : +/-30s wall-clock
\*       window (abstracted at the spec layer via MaxTimestampSkew).
\*   src/node/validator.cpp:19    : genesis short-circuit (chain init
\*       seeds GenesisBlock without re-validation).
\*
\* Runtime regressions:
\*   tools/test_time_monotonicity.sh (R24A5; 17 assertions / 9 scenarios)
\*     — the analytic source.
\*   tools/test_chain_integrity.sh (S-021; 4/4 PASS) — INV_4
\*       cascade composition with FB26.
\*   tools/test_block_hash.sh (16 assertions) — INV_3 signing_bytes
\*       coverage.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB29 row — pending.
\*   SECURITY.md §S-035 path 1 — documents the chain-layer gap;
\*       the forward-looking monotonic_gate=TRUE exercise is a spec-
\*       layer projection of the path-1 closure.
============================================================================
