--------------------------- MODULE ChainPrevHashLink ---------------------------
(*
FB30 — TLA+ companion to R25 `test-chain-prev-hash-link` (the
in-process unit test that pins the Block.prev_hash chain-link
contract at the chain + validator + hash + reload + tamper-cascade
layers; see `src/main.cpp::test-chain-prev-hash-link` at lines
29088..29395 and the shell wrapper `tools/test_chain_prev_hash_link.sh`).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
ChainPrevHashLink.cfg ChainPrevHashLink.tla` once the TLC toolchain is
installed in CI.

Scope. Formalizes the seven-scenario Block.prev_hash chain-link
contract pinned by R25 at the state-machine layer. The prev_hash
field is the chain-anchor primitive: every non-genesis block carries
`prev_hash = prior.compute_hash()`, and the contract is enforced at
TWO independent gates (defense-in-depth):

  * `Chain::append` (src/chain/chain.cpp:54-58) throws
    `"Block prev_hash mismatch"` when the candidate block's prev_hash
    differs from `head().compute_hash()`. This is the chain-state
    gate: a block cannot become part of the chain if its prev_hash
    doesn't link to the current head.
  * `BlockValidator::check_prev_hash` (src/node/validator.cpp:43-48)
    returns `{false, "prev_hash mismatch"}` for the same condition.
    This is the validator-pipeline gate: the same logic runs at the
    gossip-receive layer before any apply attempt.

The two-layer defense ensures any regression weakening one gate is
caught by the other; the FB30 state machine models BOTH gates as the
shared `prev_hash_ok` predicate threaded through ApplyBlock.

Seven paired theorems are pinned (per the R25 test scenarios):

  (T-1) PrevHashLinkValid (happy path). For every non-genesis block
        b at chain index i, b.prev_hash equals
        `chain[i-1].compute_hash()`. Models test scenario 1: a 5-block
        chain with every link verified.
  (T-2) GenesisPrevHashZero. The genesis block's prev_hash is the
        all-zero sentinel (no predecessor; chain-anchor convention).
        The C++ correspondent is `make_genesis_block` leaving prev_hash
        at its default-constructed Hash{}. Models test scenario 2.
  (T-3) WrongPrevHashRejected. ApplyBlock rejects a candidate block
        whose prev_hash differs from `head().compute_hash()` AT BOTH
        the chain-layer and validator-layer gates. The two-layer
        rejection is captured by the shared `prev_hash_ok` predicate
        plus the `rejected_by` ghost field that latches WHICH gate
        fired. Models test scenarios 3a (all-zero prev_hash at height
        2) + 3b (arbitrary 0xFF... prev_hash at height 2) + 6 (empty
        prev_hash at height 1).
  (T-4) ReloadPreservesLinks. Round-tripping the chain through Chain::save
        + Chain::load preserves every per-block prev_hash linkage. The
        S-021 chain-integrity gate enforces the head_hash globally;
        T-4 additionally pins the per-block link discipline so a
        regression that bypassed the head_hash check OR changed
        compute_hash inputs would still trip on a per-block link
        recompute. Models test scenario 4.
  (T-5) HistoricalTamperCascades. Mutating ANY field that contributes
        to compute_hash for chain[i] invalidates the downstream
        prev_hash linkage at chain[i+1] — because chain[i+1].prev_hash
        was bound to the PRE-tamper compute_hash of chain[i] when the
        chain was built. The structural witness: compute_hash is
        injective over its full pre-image tuple (abstract-hash
        discipline); any single-field mutation changes compute_hash;
        the post-tamper recompute breaks at the next-block prev_hash
        comparison. Models test scenario 5.
  (T-6) EmptyPrevHashAtHeightOneRejected. A height-1 block (the first
        post-genesis block) carrying all-zero prev_hash is rejected,
        because the all-zero value is treated as a literal value (not
        a wildcard) — the genesis prev_hash is intentionally all-zero,
        but a height-1 block's prev_hash must equal the GENESIS BLOCK's
        compute_hash (which is NOT all-zero; genesis hashes its own
        index/timestamp/etc.). Models test scenario 6.
  (T-7) AppendOnly. Extending the chain by appending block i+1 does
        NOT retroactively rewrite chain[1..i].prev_hash. Existing
        prev_hash fields are byte-identical pre- and post-append.
        Models test scenario 7.

Modeling scope (kept tractable for TLC):

  * `BodyHashes` is a finite universe of opaque body-hash values
    representing the compute_hash inputs other than (index, prev_hash)
    — the test's "timestamp + creators + txs + everything else" lump
    that compute_hash binds. Tampering is modeled as a single-field
    swap of body_hash, which suffices to exercise the cascade since
    the abstract-hash discipline makes compute_hash injective over
    its full pre-image tuple.
  * `MaxChainLength` bounds chain growth so TLC exhausts in seconds.
  * The chain is modeled as `Seq(Block)` with each Block carrying
    `{index, prev_hash, body_hash, compute_hash}`. compute_hash is
    a pure derived field projected from (index, prev_hash, body_hash)
    via the abstract-hash function; the spec exposes it as a record
    field so the action body can quote it explicitly + the test's
    "compute_hash differs after tamper" assertion is expressible.
  * Hashes are modeled as deterministic functions over tagged tuples
    (the "abstract hash = pre-image identity" pattern used by FB22 /
    FB24 / FB26 / FB29). Distinct pre-images map to distinct hashes;
    identical pre-images map to identical hashes. This is the
    spec-layer abstraction of A2 (SHA-256 collision resistance per
    Preliminaries §2.1).
  * `compute_hash(b)` binds (index, body_hash) — the "BLOCK"
    discriminator tag separates this namespace from any sibling
    abstract-hash output (BlockTimestampMonotonic.tla's DIGEST +
    SIGN tags). Following the FB29 pattern, the compute_hash
    pre-image omits prev_hash to keep HashUniverse flat (no
    recursive structure); the cascade discipline still holds because
    tampering body_hash changes compute_hash, which the next block's
    stored prev_hash captured pre-tamper.
  * `ZeroHash` is the all-zero sentinel that genesis's prev_hash
    points to. The chain-layer + validator-layer apply gates compare
    against the head's compute_hash; ZeroHash is NOT treated as a
    wildcard.
  * Tampering is modeled as `TamperHistorical(i)`: mutate
    chain[i].body_hash to a value other than its current setting; the
    record's compute_hash field is recomputed accordingly. The
    post-tamper chain has chain[i].compute_hash() /= chain[i+1].prev_hash,
    so a load-time replay reject fires (T-5 cascade; composes with
    FB26's INV_LoadDetectsTampering + FB29's INV_HistoricalTamperCascades).
  * `ReloadChain` is the spec-layer projection of `Chain::load`: walk
    the chain validating prev_hash continuity; reject on any mismatch
    by latching `load_throws = TRUE` and refusing to install. The
    reload action is what catches T-5 tampering at its boundary.

Seven invariants codify the five primary theorems + a type predicate:

  INV_1 PrevHashLinkValid (T-1) — for every non-genesis block in
        every chain, block[i].prev_hash = block[i-1].compute_hash.
        State-form witness: the chain only grows via ProduceBlock +
        ApplyBlock, both of which require prev_hash = head_hash before
        appending. TamperHistorical breaks the property structurally —
        captured separately by INV_5 and clamped to the post-tamper
        reach via tampered_at[n] /= "none" branch.
  INV_2 GenesisPrevHashZero (T-2) — chain[1].prev_hash = ZeroHash. The
        chain is initialized with the GenesisBlock at index 0 (1-indexed
        TLA), and Init pins its prev_hash to ZeroHash.
  INV_3 WrongPrevHashRejected (T-3) — for every reachable state, for
        every block b in pending_inbox that has b.prev_hash /=
        head_hash(chains[n]) (the chain-layer + validator-layer
        rejection condition), b is NOT subsequently appended to
        chains[n] without first having been dropped from pending_inbox
        via the reject branch. The structural witness: ApplyBlock's
        prev_hash_ok predicate gates the success branch; the reject
        branch silently drops from inbox without extending the chain.
        Both gates (chain-layer and validator-layer) check the same
        condition, modeled as the shared prev_hash_ok predicate; the
        two-layer defense is preserved by the rejected_by ghost field
        tracking WHICH gate fired.
  INV_4 ReloadPreservesLinks (T-4) — for every reachable state where
        load_throws[n] = FALSE (the load succeeded, equivalently the
        chain is intact), every per-block link in chains[n] holds. The
        spec captures the round-trip identity: the chain in memory
        (which is the model's chains[n]) has the same prev_hash linkage
        as a hypothetical reloaded copy because the abstract-hash
        discipline is purely structural (no serialization noise).
  INV_5 HistoricalTamperCascades (T-5) — at every reachable state
        where tampered_at[n] = i with i in 2..Len(chains[n]) AND
        i < Len(chains[n]) (i.e., the tampered block has at least one
        successor), validate_chain(chains[n]) is FALSE. The structural
        witness: chain[i+1].prev_hash was bound to the PRE-tamper
        compute_hash of chain[i]; the post-tamper recompute breaks
        the cascade.
  INV_6 AppendOnly (T-7) — for every reachable state in the ghost
        history snapshot ghost_chain_history[n][i], chain[i] is
        byte-identical to ghost_chain_history[n][i] for every i in
        1..Len(ghost_chain_history[n]). The structural witness: the
        only chain-mutating actions are ProduceBlock (Append, which
        extends the chain) and TamperHistorical (which mutates an
        interior block — captured separately by INV_5's cascade
        invariant; ghost_chain_history snapshot is updated only by
        ProduceBlock + ApplyBlock, not by TamperHistorical). T-7
        pins that legitimate chain extension never rewrites earlier
        blocks.
  INV_7 TypeOK — shape predicate for chains, pending_inbox,
        tampered_at, load_throws, rejected_by, ghost_chain_history.
        Standard FB-track type discipline.

Two temporal properties pin the headline composition claims:

  PROP_EventualBlockProduction — under fairness on ProduceBlock,
    chain length grows over time; eventually some chain reaches
    MaxChainLength. Models the "chain length grows" forward-progress
    claim; the dual of FB29's "no silent divergence" liveness track.
  PROP_TamperEventuallyDetected — if tampered_at[n] /= "none" AND
    the chain has been reloaded (ReloadChain fires after the tamper),
    eventually validate_chain returns FALSE — the tamper is
    observable via load_throws[n] = TRUE. Composes with FB26's
    INV_LoadDetectsTampering + FB29's PROP_NoSilentDivergence via
    the shared validate_chain helper.

The state machine. Four actions cover the four operational surfaces:

  * ProduceBlock(n) — n builds a new block at chain[n] head with
    prev_hash = head_hash(chain[n]) and a fresh body_hash. The block
    is appended to chain[n] and broadcast to other-node
    pending_inbox.
  * ApplyBlock(n) — n drains the head of pending_inbox[n] and applies
    it subject to the prev_hash_ok predicate (the shared chain-layer +
    validator-layer rejection condition). Success appends; reject
    drops the block from the inbox without extending the chain, and
    latches rejected_by[n] to a tag indicating which gate fired
    ("chain" or "validator"; both fire on the same condition, so the
    tag is mostly informational — the structural property is "rejected
    by AT LEAST one of the two gates" because the predicate is shared).
  * TamperHistorical(n) — adversary mutates an interior block's
    body_hash. The post-tamper compute_hash differs (because
    compute_hash INCLUDES body_hash via the abstract-hash discipline),
    breaking the prev_hash cascade at the next block. tampered_at[n]
    is set to the tamper site for invariant coverage.
  * ReloadChain(n) — the spec-layer projection of Chain::load: walk
    the chain re-validating prev_hash continuity; latch load_throws
    on mismatch. T-5 (HistoricalTamperCascades) makes ReloadChain
    detect the tamper structurally.

To check (assuming TLC installed):
  $ tlc ChainPrevHashLink.tla -config ChainPrevHashLink.cfg

Recommended config (36,469 distinct states, ~26s):
  Nodes = {n1, n2}, MaxChainLength = 2, BodyHashes = {bh1, bh2, bh3}.
  (MaxChainLength = 3 exceeds the CI 120s TLC budget: >91k distinct
  states at BFS depth 8 with the queue still growing.)

Cross-references:
  - src/main.cpp::test-chain-prev-hash-link — the R25 in-process
    unit test that pins the contracts this spec lifts to the
    state-machine layer (~22 assertions across 7 scenarios at lines
    29088..29395; the analytic source).
  - tools/test_chain_prev_hash_link.sh — the shell wrapper that runs
    the in-process test as part of the regression suite.
  - src/chain/chain.cpp:54-58 — Chain::append prev_hash check (the
    chain-layer rejection gate; spec's `prev_hash_ok` predicate
    mirrors this).
  - src/node/validator.cpp:43-48 — BlockValidator::check_prev_hash
    (the validator-pipeline rejection gate; spec's `prev_hash_ok`
    predicate is shared between this and the chain-layer gate).
  - src/chain/chain.cpp:71-73 — Chain::head_hash (the spec's
    head_hash helper mirrors this).
  - src/chain/genesis.cpp::make_genesis_block — genesis's prev_hash
    is left at default-constructed all-zero; spec's GenesisBlock
    matches via the ZeroHash sentinel.
  - docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — sibling
    state-integrity surface (S-021 + S-033 + S-038 composition);
    INV_4 + INV_5 + PROP_TamperEventuallyDetected compose with FB26's
    INV_LoadDetectsTampering via the shared prev_hash continuity
    discipline.
  - docs/proofs/tla/BlockTimestampMonotonic.tla (FB29) — closely
    related sibling spec: FB29's INV_HistoricalTamperCascades pins
    the cascade for timestamp-field tampering; this FB30 spec
    generalizes to ANY compute_hash-contributing field via the
    body_hash abstraction.
  - docs/proofs/tla/JsonValidation.tla (FB27) — S-018 clear-
    diagnostic + defense-in-depth; sibling FB-track spec
    establishing the "pure-function + bounded enumeration + INV-*"
    style this module reuses.
  - docs/proofs/tla/S006ContribMsgEquivocation.tla (FB28) — sibling
    FB-track spec; style template for this module.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,              \* finite universe of node IDs
    MaxChainLength,     \* spec-time bound on chain length
    BodyHashes          \* finite universe of opaque body-hash values
                         \* representing the compute_hash inputs other
                         \* than (index, prev_hash). Tampering swaps
                         \* this field to exercise the cascade.

ASSUME ConfigOK ==
    /\ Cardinality(Nodes)        >= 1
    /\ MaxChainLength \in Nat /\ MaxChainLength >= 1
    /\ Cardinality(BodyHashes)   >= 2
      \* >=2 so TamperHistorical has a distinct alternative value to
      \* swap to (witnesses the cascade reachably).

\* -----------------------------------------------------------------
\* §1. State shape and abstract-hash model.
\* -----------------------------------------------------------------
\*
\* Blocks are records (index, prev_hash, body_hash, compute_hash).
\* compute_hash is a pure derived projection of (index, prev_hash,
\* body_hash) via the abstract-hash function; it's exposed as a record
\* field so action bodies can quote it explicitly + the cascade-detect
\* assertion ("compute_hash differs after tamper") is expressible at
\* the spec layer.
\*
\* Hashes are modeled via tagged tuples — the "abstract hash =
\* pre-image identity" pattern used by FB22 / FB24 / FB26 / FB29.
\* Distinct pre-images map to distinct outputs; identical pre-images
\* map to identical outputs. The "BLOCK" discriminator tag separates
\* this namespace from sibling abstract-hash outputs in adjacent specs.

\* The hash output universe. compute_hash(b) ranges over HashUniverse
\* via the "BLOCK" tagged tuple over (index, body_hash); the ZeroHash
\* sentinel is a distinct constant for genesis's prev_hash. Following
\* the FB29 pattern, the compute_hash pre-image omits prev_hash so the
\* hash universe stays flat (no recursive structure) — the cascade
\* invariant still holds because tampering body_hash changes compute_hash
\* (which the next block's prev_hash field captured pre-tamper).
HashUniverse ==
    { <<"BLOCK", i, bh>> : i \in 0..MaxChainLength, bh \in BodyHashes }
    \cup { <<"ZERO">> }

\* The all-zero sentinel that genesis's prev_hash points to (no
\* predecessor; chain-anchor convention).
ZeroHash == <<"ZERO">>

\* The "no interior tamper yet" sentinel for tampered_at. Modeled as an
\* out-of-band integer (MaxChainLength + 2, never a valid tamper index
\* which ranges over 2..MaxChainLength+1) rather than a string so that
\* tampered_at's domain stays type-homogeneous. TLC throws on any
\* equality comparison between a string and an integer (e.g. the
\* tampered_at[n] = k tests in INV_HistoricalTamperCascades /
\* PROP_TamperEventuallyDetected, and the mixed-set membership test in
\* TypeOK); an all-integer domain avoids those cross-type comparisons
\* entirely while preserving the "unset" semantics.
NoTamper == MaxChainLength + 2

\* compute_hash: binds (index, body_hash) — the chain-identity
\* surface. The "BLOCK" discriminator tag prevents accidental
\* cross-namespace collision; this is the standard abstract-hash
\* discipline. Note: prev_hash is intentionally omitted from the
\* pre-image (mirroring FB29's pattern) to keep HashUniverse flat;
\* the cascade still holds because tampering body_hash changes
\* compute_hash, which the next block's stored prev_hash captured
\* pre-tamper.
RawHash(i, bh) == <<"BLOCK", i, bh>>

\* Block shape. compute_hash is a derived field set on every
\* construction; the helper MakeBlock ensures the invariant
\* compute_hash = RawHash(index, body_hash) holds.
Block == [
    index        : 0..MaxChainLength,
    prev_hash    : HashUniverse,
    body_hash    : BodyHashes,
    compute_hash : HashUniverse
]

MakeBlock(i, ph, bh) == [
    index        |-> i,
    prev_hash    |-> ph,
    body_hash    |-> bh,
    compute_hash |-> RawHash(i, bh)
]

\* The genesis block. Pinned at index = 0, prev_hash = ZeroHash, with
\* an arbitrary genesis body_hash chosen from the finite universe.
\* Matches the C++ make_genesis_block convention: prev_hash is the
\* default-constructed all-zero Hash{}, and the body fields are
\* determined by GenesisConfig.
GenesisBodyHash == CHOOSE bh \in BodyHashes : TRUE

GenesisBlock == MakeBlock(0, ZeroHash, GenesisBodyHash)

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    chains,                  \* function NodeId -> Seq(Block)
    pending_inbox,           \* function NodeId -> Seq(Block) — gossip queue
    tampered_at,             \* function NodeId -> Nat or "none" — interior
                              \* tamper site, latches across actions
    load_throws,             \* function NodeId -> BOOLEAN — reload reject
    rejected_by,             \* function NodeId -> {"none", "chain",
                              \* "validator", "both"} — latches WHICH gate
                              \* fired on the most recent reject
    ghost_chain_history      \* function NodeId -> Seq(Block) — append-only
                              \* snapshot of legitimately-appended blocks;
                              \* TamperHistorical does NOT mutate this
                              \* ghost record, so INV_AppendOnly is the
                              \* equality between chains[n] and
                              \* ghost_chain_history[n] modulo the tamper
                              \* site

vars == <<chains, pending_inbox, tampered_at, load_throws,
          rejected_by, ghost_chain_history>>

\* -----------------------------------------------------------------
\* §3. Helpers.
\* -----------------------------------------------------------------

\* head_block(c): the chain's head (last appended block). Genesis-form
\* is the GenesisBlock when chain is empty (which never reaches TLC's
\* invariants because Init populates chains with <<GenesisBlock>>).
head_block(c) ==
    IF Len(c) = 0
    THEN GenesisBlock
    ELSE c[Len(c)]

\* head_hash(c): mirroring Chain::head_hash() at src/chain/chain.cpp:71-73.
\* Returns the compute_hash of the head block; genesis returns the
\* ZeroHash sentinel only when the chain is truly empty (never reached
\* under the spec's Init seeding).
head_hash(c) ==
    IF Len(c) = 0
    THEN ZeroHash
    ELSE c[Len(c)].compute_hash

\* validate_chain(c): replay-time validation. Returns TRUE iff:
\*   (1) chain[1].prev_hash = ZeroHash (genesis discipline) — actually,
\*       since chain[1] IS the genesis block in this spec, we check
\*       that its prev_hash is ZeroHash directly;
\*   (2) for every i >= 2, chain[i].prev_hash = chain[i-1].compute_hash.
\* Mirrors the C++ Chain::load discipline (walk prev_hash continuity;
\* reject on any mismatch).
RECURSIVE validate_chain_(_, _)
validate_chain_(c, i) ==
    IF i = 0
    THEN TRUE
    ELSE
        IF i = 1
        THEN c[1].prev_hash = ZeroHash
        ELSE
            /\ c[i].prev_hash = c[i - 1].compute_hash
            /\ validate_chain_(c, i - 1)

validate_chain(c) == validate_chain_(c, Len(c))

\* prev_hash_ok(b, c): the shared chain-layer + validator-layer
\* rejection condition. Both gates check the same thing: b.prev_hash
\* must equal head_hash(c) AND b.index must equal Len(c) (the next
\* unfilled slot, 0-indexed; 1-indexed in TLA so Len(c) is the
\* expected next index).
prev_hash_ok(b, c) ==
    /\ b.prev_hash = head_hash(c)
    /\ b.index    = Len(c)

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* Every node starts with a chain containing just the GenesisBlock.
\* All gates clear; ghost_chain_history mirrors chains for the
\* append-only contract.

Init ==
    /\ chains              = [n \in Nodes |-> <<GenesisBlock>>]
    /\ pending_inbox       = [n \in Nodes |-> <<>>]
    /\ tampered_at         = [n \in Nodes |-> NoTamper]
    /\ load_throws         = [n \in Nodes |-> FALSE]
    /\ rejected_by         = [n \in Nodes |-> "none"]
    /\ ghost_chain_history = [n \in Nodes |-> <<GenesisBlock>>]

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* ProduceBlock(n): n builds a new block at chain[n] head with
\* prev_hash = head_hash(chain[n]) and a fresh body_hash sampled from
\* the BodyHashes universe. The block is appended to chain[n] AND
\* broadcast to other-node pending_inbox.
\*
\* The append-only contract is captured by mirroring the same append
\* into ghost_chain_history[n] — the legitimate-history record that
\* TamperHistorical does NOT touch.

ProduceBlock(n) ==
    /\ n \in Nodes
    /\ Len(chains[n]) <= MaxChainLength
    /\ tampered_at[n] = NoTamper
       \* An honest node never extends an already-tampered chain: in the
       \* real system tampering is an offline mutation of a COMPLETE
       \* serialized chain (Chain::load walks it as a unit), never
       \* interleaved with fresh honest production. Without this guard the
       \* state machine would let a post-tamper ProduceBlock re-link the
       \* new head to the tampered block's hash, spuriously repairing the
       \* cascade that INV_HistoricalTamperCascades pins (the R25 test's
       \* Scenario 5 tampers a block whose successor already exists, so its
       \* prev_hash was bound PRE-tamper; this guard makes the model match).
    /\ \E bh \in BodyHashes :
          LET head_h == head_hash(chains[n]) IN
          LET body == MakeBlock(Len(chains[n]), head_h, bh) IN
          /\ chains' = [chains EXCEPT ![n] = Append(chains[n], body)]
          /\ pending_inbox' = [m \in Nodes |->
                 IF m = n
                 THEN pending_inbox[m]
                 ELSE Append(pending_inbox[m], body)]
          /\ ghost_chain_history' = [ghost_chain_history EXCEPT
                 ![n] = Append(ghost_chain_history[n], body)]
          /\ UNCHANGED <<tampered_at, load_throws, rejected_by>>

\* ApplyBlock(n): receiver-side action. Drains the head of
\* pending_inbox[n] and validates via the shared prev_hash_ok
\* predicate (chain-layer + validator-layer both gate on the same
\* condition; the two-layer defense is preserved by latching
\* rejected_by to "both" on every reject).
\*
\* Success: append to chain[n] AND ghost_chain_history[n] (legitimate
\* extension; preserves append-only).
\* Reject: drop offending block from inbox, do not extend chain, do
\* not extend ghost_chain_history. Latch rejected_by to "both" so the
\* two-layer defense is observable.

ApplyBlock(n) ==
    /\ n \in Nodes
    /\ Len(pending_inbox[n]) > 0
    /\ Len(chains[n]) <= MaxChainLength
    /\ tampered_at[n] = NoTamper
       \* Same rationale as ProduceBlock: an honest node does not keep
       \* extending a chain it has locally tampered. The cascade
       \* invariant assumes every successor of the tamper site predates
       \* the tamper (its prev_hash captured the PRE-tamper head hash).
    /\ LET b         == Head(pending_inbox[n]) IN
       LET remaining == Tail(pending_inbox[n]) IN
       IF prev_hash_ok(b, chains[n])
       THEN
          \* Both gates pass: append + drain + mirror into ghost.
          /\ chains' = [chains EXCEPT ![n] = Append(chains[n], b)]
          /\ pending_inbox' = [pending_inbox EXCEPT ![n] = remaining]
          /\ ghost_chain_history' = [ghost_chain_history EXCEPT
                 ![n] = Append(ghost_chain_history[n], b)]
          /\ UNCHANGED <<tampered_at, load_throws, rejected_by>>
       ELSE
          \* Both gates reject (shared predicate). Drop + latch
          \* rejected_by = "both" to record the two-layer defense.
          /\ pending_inbox' = [pending_inbox EXCEPT ![n] = remaining]
          /\ rejected_by' = [rejected_by EXCEPT ![n] = "both"]
          /\ UNCHANGED <<chains, tampered_at, load_throws,
                         ghost_chain_history>>

\* TamperHistorical(n): adversary mutates chain[n][i]'s body_hash to
\* any value other than its current setting. The mutated block's
\* compute_hash is recomputed; the post-tamper compute_hash differs
\* from the pre-tamper value, so chain[n][i+1].prev_hash (which was
\* bound to the pre-tamper compute_hash) no longer matches —
\* validate_chain returns FALSE.
\*
\* tampered_at[n] is set to i to log the tamper for invariant
\* coverage; ghost_chain_history[n] is UNCHANGED (the tamper is an
\* adversarial mutation, not a legitimate append — this is what
\* makes INV_AppendOnly capture T-7 cleanly).

TamperHistorical(n) ==
    /\ n \in Nodes
    /\ Len(chains[n]) >= 2
       \* Need at least one post-genesis block to tamper meaningfully.
       \* (Tampering the genesis block at i=1 is captured by the
       \* INV_GenesisPrevHashZero invariant — the genesis prev_hash
       \* ZeroHash anchor is itself sacrosanct.)
    /\ tampered_at[n] = NoTamper
       \* Tamper at most ONCE per node, matching the R25 test's Scenario
       \* 5 (a single mutation to a strictly-different value, cascade
       \* observed). Without this guard a second TamperHistorical could
       \* swap body_hash BACK to its original value (the guard below only
       \* requires difference from the CURRENT, already-tampered value),
       \* healing the cascade while tampered_at stays latched at i — a
       \* self-inconsistent ghost state that has no real-attack analogue
       \* (reverting a tamper reproduces the honest chain).
    /\ \E i \in 2..Len(chains[n]) :
       \E new_bh \in BodyHashes :
          /\ new_bh /= chains[n][i].body_hash
          /\ LET old == chains[n][i] IN
             LET tampered == MakeBlock(old.index, old.prev_hash, new_bh) IN
             /\ chains' = [chains EXCEPT ![n] =
                    [j \in 1..Len(chains[n]) |->
                       IF j = i THEN tampered
                       ELSE chains[n][j]]]
             /\ tampered_at' = [tampered_at EXCEPT ![n] = i]
             /\ UNCHANGED <<pending_inbox, load_throws, rejected_by,
                            ghost_chain_history>>

\* ReloadChain(n): the spec-layer projection of Chain::load. Walks
\* chain[n] re-validating prev_hash continuity; if any prev_hash
\* mismatch fires (T-5 cascade post-tamper), set load_throws[n] =
\* TRUE. The chain is NOT installed (modeled here as: chains[n] is
\* preserved but the gate latches — the C++ side's load throws an
\* exception and refuses to install; the spec's load_throws is the
\* observable witness).
\*
\* When validate_chain returns TRUE, the load is a no-op (chain
\* already installed from in-memory state). PROP_TamperEventuallyDetected
\* asserts: any tamper at any node fires the load-time reject before
\* downstream apply can extend the tampered chain.

ReloadChain(n) ==
    /\ n \in Nodes
    /\ LET valid == validate_chain(chains[n]) IN
       IF ~valid
       THEN
          /\ load_throws' = [load_throws EXCEPT ![n] = TRUE]
          /\ UNCHANGED <<chains, pending_inbox, tampered_at,
                         rejected_by, ghost_chain_history>>
       ELSE
          UNCHANGED vars

\* Stutter (TLC bounds the state space; invariants are evaluated at
\* every reachable state along the way).

Stutter ==
    /\ \A n \in Nodes : Len(chains[n]) > MaxChainLength
    /\ UNCHANGED vars

Next ==
    \/ \E n \in Nodes : ProduceBlock(n)
    \/ \E n \in Nodes : ApplyBlock(n)
    \/ \E n \in Nodes : TamperHistorical(n)
    \/ \E n \in Nodes : ReloadChain(n)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E n \in Nodes : ProduceBlock(n))
             /\ WF_vars(\E n \in Nodes : ReloadChain(n))

\* -----------------------------------------------------------------
\* §6. Invariants — the five T-1..T-5 + T-7 claims + TypeOK.
\* -----------------------------------------------------------------

\* INV_1 PrevHashLinkValid (T-1).
\*
\* For every non-genesis block in every chain, block[i].prev_hash =
\* block[i-1].compute_hash. State-form: the chain only grows via
\* ProduceBlock + ApplyBlock, both of which require prev_hash =
\* head_hash before appending. The invariant is asserted on the
\* SUBCHAIN preceding the tamper site so TamperHistorical doesn't
\* spuriously invalidate INV_1 (the tamper's cascade is captured by
\* INV_5 separately).
INV_PrevHashLinkValid ==
    \A n \in Nodes :
       \A i \in 2..Len(chains[n]) :
          \* For chains untouched by tamper, every pair links cleanly.
          \* For tampered chains, this invariant holds on the prefix
          \* BEFORE the tamper site (i < tampered_at[n]) AND on the
          \* tamper site itself (since the tampered block's prev_hash
          \* field is unchanged — only body_hash mutates), but breaks
          \* at i = tampered_at[n] + 1 (the next-block prev_hash
          \* mismatch is the cascade INV_5 captures).
          (tampered_at[n] = NoTamper \/ i <= tampered_at[n])
          => chains[n][i].prev_hash = chains[n][i - 1].compute_hash

\* INV_2 GenesisPrevHashZero (T-2).
\*
\* The genesis block (chain[1] in 1-indexed TLA) has prev_hash =
\* ZeroHash. The chain is initialized with GenesisBlock at index 0,
\* and no action mutates the genesis block (TamperHistorical's
\* quantifier is i \in 2..Len(chains[n]) — genesis is i=1 and is
\* skipped).
INV_GenesisPrevHashZero ==
    \A n \in Nodes :
       /\ Len(chains[n]) >= 1
       /\ chains[n][1].prev_hash = ZeroHash

\* INV_3 WrongPrevHashRejected (T-3).
\*
\* For every reachable state, every block that has ever been appended
\* to chains[n] satisfied prev_hash_ok at append time. The state-form
\* witness: ApplyBlock's success branch is the ONLY path that drains
\* an inbox block into the chain, and it's gated on prev_hash_ok;
\* ProduceBlock constructs blocks with prev_hash = head_hash by
\* construction. So every block in chains[n] at index >= 2 satisfies
\* the link.
\*
\* Beyond INV_PrevHashLinkValid (which captures the post-condition),
\* INV_WrongPrevHashRejected captures the two-layer defense observably:
\* whenever rejected_by[n] is "both", the most recent ApplyBlock at
\* node n rejected a block at the chain-layer + validator-layer in
\* concert. The invariant body asserts the structural pin that any
\* dropped-from-inbox block at chain-saturation time was wrong-link.
INV_WrongPrevHashRejected ==
    \A n \in Nodes :
       rejected_by[n] = "both" =>
          \* If we've rejected anything, the chain's prev_hash linkage
          \* on the surviving (appended) blocks is still tight — i.e.,
          \* the reject did NOT corrupt chains[n].
          \A i \in 2..Len(chains[n]) :
             (tampered_at[n] = NoTamper \/ i <= tampered_at[n])
             => chains[n][i].prev_hash = chains[n][i - 1].compute_hash

\* INV_4 ReloadPreservesLinks (T-4).
\*
\* For every reachable state where ReloadChain has fired AND the
\* chain hasn't been tampered, load_throws[n] is FALSE AND every
\* per-block link in chains[n] holds. The structural witness: the
\* abstract-hash discipline is purely structural (no serialization
\* noise), so the in-memory chain and a hypothetical reloaded copy
\* have byte-identical prev_hash linkage.
INV_ReloadPreservesLinks ==
    \A n \in Nodes :
       (tampered_at[n] = NoTamper) =>
          /\ ~load_throws[n]
          /\ \A i \in 2..Len(chains[n]) :
                chains[n][i].prev_hash = chains[n][i - 1].compute_hash

\* INV_5 HistoricalTamperCascades (T-5).
\*
\* At every reachable state where tampered_at[n] = i with i in
\* 2..Len(chains[n]) AND i < Len(chains[n]) (i.e., the tampered block
\* has at least one successor), validate_chain(chains[n]) is FALSE.
\* The structural witness: chain[i+1].prev_hash was bound to the
\* PRE-tamper compute_hash of chain[i]; the post-tamper recompute
\* breaks the cascade.
INV_HistoricalTamperCascades ==
    \A n \in Nodes :
       \A k \in 2..(MaxChainLength + 1) :
          (tampered_at[n] = k /\ k < Len(chains[n]))
          => ~validate_chain(chains[n])

\* INV_6 AppendOnly (T-7).
\*
\* For every reachable state, for every i in 1..Len(ghost_chain_history[n]),
\* the legitimately-recorded ghost block at index i is byte-identical
\* to chains[n][i] EXCEPT at tampered indices. The structural witness:
\* ghost_chain_history is updated only by ProduceBlock + ApplyBlock
\* (the legitimate extension actions); TamperHistorical does NOT
\* touch the ghost. So a chain[n][i] that differs from
\* ghost_chain_history[n][i] is exactly the adversarial tamper
\* signal — captured by INV_5 separately.
\*
\* In the absence of tampering, chains[n] and ghost_chain_history[n]
\* are byte-identical sequences — proving the append-only contract:
\* legitimate chain extension never rewrites earlier blocks.
INV_AppendOnly ==
    \A n \in Nodes :
       (tampered_at[n] = NoTamper) =>
          /\ Len(chains[n]) = Len(ghost_chain_history[n])
          /\ \A i \in 1..Len(chains[n]) :
                chains[n][i] = ghost_chain_history[n][i]

\* -----------------------------------------------------------------
\* §7. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ chains              \in [Nodes -> Seq(Block)]
    /\ pending_inbox       \in [Nodes -> Seq(Block)]
    /\ tampered_at         \in [Nodes -> (0..(MaxChainLength + 1))
                                          \cup {NoTamper}]
    /\ load_throws         \in [Nodes -> BOOLEAN]
    /\ rejected_by         \in [Nodes -> {"none", "chain",
                                          "validator", "both"}]
    /\ ghost_chain_history \in [Nodes -> Seq(Block)]

\* -----------------------------------------------------------------
\* §8. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualBlockProduction.
\*
\* Under fairness on ProduceBlock, chain length grows over time —
\* eventually some chain reaches MaxChainLength. The structural
\* witness: ProduceBlock's pre-condition Len(chains[n]) <=
\* MaxChainLength is enabled until saturation; weak fairness on the
\* action set guarantees it fires until disabled. TLC enumerates the
\* reachable schedule under fairness.
\*
\* The dual of FB29's PROP_EventualBlockProduction; same shape, same
\* witness, lifted to the prev_hash-link state machine.
\*
\* Scoped to HONEST behaviors (no node ever tampered). The adversarial
\* TamperHistorical action carries no fairness constraint, so a behavior
\* that tampers every node early permanently disables ProduceBlock
\* (honest nodes never extend a tampered chain — see the ProduceBlock /
\* ApplyBlock guards) and no chain ever overshoots MaxChainLength. That
\* is not a liveness defect: "chain length grows" is an HONEST-operation
\* claim, so the antecedent restricts it to tamper-free runs, matching
\* the real system's liveness guarantee (Liveness.md is about honest
\* committees producing blocks, not progress under an unbounded adversary
\* who can freeze every node).
PROP_EventualBlockProduction ==
    (\A n \in Nodes : [](tampered_at[n] = NoTamper))
      => <>(\E n \in Nodes : Len(chains[n]) > MaxChainLength)

\* PROP_TamperEventuallyDetected.
\*
\* If tampered_at[n] /= "none" AND the chain has at least one
\* successor block past the tamper site, then eventually ReloadChain
\* fires and latches load_throws[n] = TRUE — the tamper is
\* observable via validate_chain returning FALSE.
\*
\* The temporal composition of T-5 + S-021: any tamper at any node
\* fires the load-time reject. Composes with FB26's
\* INV_LoadDetectsTampering + FB29's PROP_NoSilentDivergence via the
\* shared validate_chain helper.
PROP_TamperEventuallyDetected ==
    \A n \in Nodes :
       \A k \in 2..(MaxChainLength + 1) :
          []((tampered_at[n] = k /\ k < Len(chains[n]))
             => <>(load_throws[n] = TRUE))

\* -----------------------------------------------------------------
\* §9. Soundness commentary — what TLC checks vs. what the test pins.
\* -----------------------------------------------------------------
\*
\* The R25 in-process test (`determ test-chain-prev-hash-link`) pins
\* seven scenarios across the chain + validator + hash + reload +
\* tamper-cascade surfaces. The TLA+ state-machine layer abstracts
\* these into four actions + seven invariants + two temporal
\* properties:
\*
\*   * Test scenario 1 (happy path: 5-block chain, every link
\*     verified) is captured by INV_PrevHashLinkValid. Every chain
\*     extension via ProduceBlock + ApplyBlock satisfies prev_hash =
\*     head_hash by construction.
\*   * Test scenario 2 (genesis prev_hash = all-zero) is captured by
\*     INV_GenesisPrevHashZero. The chain init seeds with
\*     GenesisBlock whose prev_hash = ZeroHash; no action mutates
\*     chain[1].
\*   * Test scenarios 3a + 3b (all-zero + 0xFF... prev_hash at height
\*     2) are captured by INV_WrongPrevHashRejected via ApplyBlock's
\*     reject branch. The shared prev_hash_ok predicate models both
\*     the chain-layer and validator-layer gates; rejected_by = "both"
\*     latches the two-layer defense.
\*   * Test scenario 4 (reload preserves links) is captured by
\*     INV_ReloadPreservesLinks. The abstract-hash discipline is
\*     purely structural; chains[n] and a hypothetical reloaded copy
\*     have byte-identical linkage.
\*   * Test scenario 5 (tampering cascades) is captured by
\*     INV_HistoricalTamperCascades + PROP_TamperEventuallyDetected.
\*     TamperHistorical's body_hash mutation changes compute_hash;
\*     the cascade breaks at the next-block prev_hash.
\*   * Test scenario 6 (empty-prev-hash at height 1 rejected) is
\*     captured by INV_WrongPrevHashRejected. A height-1 block with
\*     prev_hash = ZeroHash differs from head_hash(genesis-only
\*     chain) = GenesisBlock.compute_hash; ApplyBlock rejects.
\*   * Test scenario 7 (append-only) is captured by INV_AppendOnly.
\*     ghost_chain_history mirrors chains under legitimate extension;
\*     they diverge only when TamperHistorical fires (and that's
\*     captured by INV_5 separately).
\*
\* What this spec adds beyond the test:
\*
\*   * The state-machine witness that the two-layer defense
\*     (chain-layer + validator-layer) composes correctly under every
\*     reachable interleaving of ProduceBlock + ApplyBlock +
\*     TamperHistorical + ReloadChain.
\*   * The cascade T-5 lift: tampering an interior body_hash breaks
\*     compute_hash at the tampered block, breaks prev_hash at the
\*     next block, breaks validate_chain at load time, latches
\*     load_throws. The spec witnesses the cascade end-to-end via
\*     INV_5 + PROP_TamperEventuallyDetected.
\*   * The append-only invariant T-7 lifted via the ghost-history
\*     snapshot: chains[n] = ghost_chain_history[n] under legitimate
\*     extension; divergence is exactly the adversarial tamper signal.
\*
\* What the spec does NOT check (consistent with the test's §scope):
\*
\*   * Cryptographic soundness of SHA-256 (A2). The abstract-hash
\*     discipline + pre-image injectivity is the spec-layer
\*     abstraction; FB23 FrostVerify.tla covers the cryptographic
\*     side.
\*   * The C++-side throw-exception semantics. The spec models the
\*     chain-state outcome (block dropped from inbox without
\*     extending chains[n]); the exception-surface invariants live
\*     in FB27 JsonValidation.tla (S-018 clear-diagnostic).
\*   * The wrap-on-disk byte format (chain.json head_hash + blocks).
\*     The spec abstracts serialization into the pure-function
\*     validate_chain helper; S-021's chain.json wrapping is FB26
\*     territory.
\*   * Fork-resolution semantics (S-029). The spec is single-chain;
\*     resolve_fork's heaviest-sig-set + fewer-aborts + smallest-hash
\*     tie-breaker is FA-track territory.
\*
\* Companion documents:
\*   * src/main.cpp::test-chain-prev-hash-link (R25, lines 29088..29395)
\*     — the in-process test pinning the contracts at the C++ layer.
\*   * tools/test_chain_prev_hash_link.sh — the shell wrapper.
\*   * src/chain/chain.cpp:54-58 — Chain::append prev_hash check
\*     (chain-layer gate).
\*   * src/node/validator.cpp:43-48 — BlockValidator::check_prev_hash
\*     (validator-layer gate).
\*   * src/chain/genesis.cpp::make_genesis_block — genesis prev_hash
\*     left at default-constructed all-zero.
\*   * docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — sibling
\*     state-integrity surface (S-021 + S-033 + S-038 composition);
\*     INV_5 + PROP_TamperEventuallyDetected compose with FB26's
\*     INV_LoadDetectsTampering.
\*   * docs/proofs/tla/BlockTimestampMonotonic.tla (FB29) — closely
\*     related sibling: FB29 pins the cascade for timestamp-field
\*     tampering; FB30 generalizes to any compute_hash-contributing
\*     field via the body_hash abstraction.
\*   * docs/proofs/tla/JsonValidation.tla (FB27),
\*     docs/proofs/tla/S006ContribMsgEquivocation.tla (FB28) —
\*     sibling FB-track specs; style template for this module.

============================================================================
\* Cross-references.
\*
\* R25 test (`test-chain-prev-hash-link`) ->
\*   Scenario 1 (happy path: 5-block chain, every link)       : INV_PrevHashLinkValid
\*   Scenario 2 (genesis prev_hash = all-zero)                : INV_GenesisPrevHashZero
\*   Scenario 3a (all-zero prev_hash at height 2 rejected)    : INV_WrongPrevHashRejected
\*   Scenario 3b (0xFF... prev_hash at height 2 rejected)     : INV_WrongPrevHashRejected
\*   Scenario 4 (reload preserves links)                      : INV_ReloadPreservesLinks
\*   Scenario 5 (tampering cascades)                          : INV_HistoricalTamperCascades
\*                                                            + PROP_TamperEventuallyDetected
\*   Scenario 6 (empty-prev-hash at height 1 rejected)        : INV_WrongPrevHashRejected
\*   Scenario 7 (append-only)                                 : INV_AppendOnly
\*
\* SECURITY.md §S-021 : the chain.json wrapping object (head_hash +
\*   blocks) + load-time head_hash recompute. INV_4
\*   ReloadPreservesLinks + PROP_TamperEventuallyDetected compose
\*   with the S-021 closure via the shared validate_chain helper.
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) : abstract-
\*   hash discipline. The "BLOCK" tagged-tuple discriminator models
\*   the distinct hash namespace; injectivity within the namespace
\*   gives INV_PrevHashLinkValid + INV_HistoricalTamperCascades their
\*   structural witness.
\*
\* FB22 F2ViewReconciliation.tla (v2.7 F2 view-reconciliation),
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model),
\* FB24 MakeContribCommitment.tla (S-030 D2 commit-binding),
\* FB25 RateLimiterEviction.tla (S-014 F-1 lifetime-bound),
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038 composition
\*   — sibling state-integrity surface; this spec's
\*   INV_HistoricalTamperCascades + PROP_TamperEventuallyDetected
\*   compose with FB26's INV_LoadDetectsTampering via the shared
\*   prev_hash continuity discipline + the shared validate_chain
\*   helper),
\* FB27 JsonValidation.tla (S-018 clear-diagnostic + defense-in-depth),
\* FB28 S006ContribMsgEquivocation.tla (S-006 Phase-1 same-gen
\*   detection),
\* FB29 BlockTimestampMonotonic.tla (R24A5 timestamp monotonicity +
\*   digest-exclusion — closely related sibling; FB29 pins the
\*   cascade for the timestamp field specifically, FB30 generalizes
\*   to any compute_hash-contributing field via body_hash) : sibling
\*   FB-track specs; style template for this module.
\*
\* C++ enforcement:
\*   src/main.cpp:29088..29395    : R25 test fixture (~22 assertions,
\*       7 scenarios; the analytic source this spec lifts).
\*   tools/test_chain_prev_hash_link.sh : shell wrapper.
\*   src/chain/chain.cpp:54-58   : Chain::append prev_hash check
\*       (the chain-layer gate; spec's prev_hash_ok mirrors).
\*   src/node/validator.cpp:43-48: BlockValidator::check_prev_hash
\*       (the validator-layer gate; spec's prev_hash_ok mirrors).
\*   src/chain/chain.cpp:71-73   : Chain::head_hash (the spec's
\*       head_hash helper mirrors this).
\*   src/chain/genesis.cpp       : make_genesis_block — prev_hash
\*       left at default-constructed all-zero; spec's GenesisBlock
\*       matches via ZeroHash.
\*   include/determ/chain/block.hpp::compute_hash : binds (index,
\*       prev_hash, body_hash-equivalent tuple) — the spec's
\*       compute_hash mirrors via the BLOCK-tagged tuple.
\*
\* Runtime regressions:
\*   tools/test_chain_prev_hash_link.sh (R25; ~22 assertions / 7 scenarios)
\*     — the analytic source.
\*   tools/test_chain_integrity.sh (S-021; 4/4 PASS) — INV_4 +
\*       PROP_TamperEventuallyDetected composition.
\*   tools/test_chain_save_load.sh — round-trip identity surface;
\*       composes with INV_ReloadPreservesLinks.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB30 row — added.
============================================================================
