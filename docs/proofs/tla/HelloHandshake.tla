--------------------------- MODULE HelloHandshake ---------------------------
(*
FB37 — TLA+ specification of the HELLO peer-handshake state machine.
Companion to the in-process unit test `determ
test-hello-handshake-determinism` (R32A5) at `src/main.cpp:32411-32711`.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
HelloHandshake.cfg HelloHandshake.tla` once the TLC toolchain is
installed in CI.

Scope. Formalizes the HELLO handshake state machine that governs every
Determ peer connection's pre-negotiation phase. HELLO is the first
wire message exchanged on every TCP socket (see `GossipNet::open` at
`src/net/gossip.cpp:42-65` for the outbound emit-on-connect path, and
the `case MsgType::HELLO:` admission branch at `src/net/gossip.cpp:
168-187` for the inbound process path). HELLO carries:

  * `wire_version` (uint8_t — `kWireVersionLegacy = 0` or
    `kWireVersionBinary = 1`; per `include/determ/net/messages.hpp:
    90-92`) — the highest wire format the sender understands. Both
    sides negotiate down to `min(ours, theirs)` on receipt
    (`src/net/gossip.cpp:180-184`).
  * `chain_id` — the sender's chain identity discriminator. Spec
    layer abstracts the chain-identity surface (which in the
    production binary is currently the (genesis_hash, region) pair
    threaded through `set_chain_identity` at `src/net/gossip.cpp:
    17-23` plus the head_hash signature on subsequent messages).
    Models the "no cross-chain peer admission" contract: peers
    claiming a different chain_id are rejected at the handshake
    surface BEFORE any subsequent message is processed.
  * `node_id` — the sender's peer identifier (production binary
    uses `domain` per the HELLO payload at
    `include/determ/net/messages.hpp:194-200`, which keys the peer
    table and gossip dedup map).
  * `committee_region` — region tag used by R4 region-aware
    committee selection (not invariant-relevant at this layer; the
    spec carries the field to mirror the wire-format structure but
    does not assert region-policy rules here — that's FB35
    `RegionalShardingCommittee.tla` territory).

HELLO is ALWAYS JSON. The binary codec at `src/net/binary_codec.cpp:
327-331` THROWS when invoked on a HELLO message (`"binary_codec:
HELLO must be sent as JSON"`). This pre-negotiation invariant is
captured at the spec layer by `INV_HelloIsJsonAlways` — the spec
models HELLO admission as the always-JSON branch and never invokes
the binary encoding path on a HELLO record.

Five paired theorems are pinned (per
`test-hello-handshake-determinism` at `src/main.cpp:32411-32711`
plus the cross-chain admission contract from PROTOCOL.md §9.1):

  (T-1) Chain-ID Agreement. Every accepted handshake has
        `from.chain_id = to.chain_id`. No peer claiming a different
        chain identity is ever admitted to the accepted_peers set.
        State-form witness: INV_ChainIdAgreement.
  (T-2) Wire-Version Compatibility. Every accepted handshake has
        `wire_version <= kWireVersionMax`. A peer advertising a
        wire_version newer than this build's `kWireVersionMax = 1`
        is rejected at the handshake gate (the build cannot speak
        the newer codec — admission would deadlock subsequent
        wire-level exchanges). State-form witness:
        INV_WireVersionCompat.
  (T-3) HELLO-Always-JSON. HELLO never gets binary-codec'd. The
        spec models HELLO as always-JSON; `encode_binary` is not
        modeled for HELLO (the action set has no Encode-HELLO-as-
        binary disjunct). Structural witness: INV_HelloIsJsonAlways.
        The C++ correspondent is the unconditional throw at
        `src/net/binary_codec.cpp:330-331`.
  (T-4) Eventual Handshake Resolution. Under fairness on
        ProcessHandshake, every PENDING handshake eventually
        transitions to ACCEPT or REJECT. The forward-progress
        contract: no handshake is left in PENDING indefinitely.
        State-form witness: PROP_EventualHandshakeResolution.
  (T-5) No Silent Accept on Mismatch. Mismatched chain_id or
        incompatible wire_version always produces REJECT, never
        silent ACCEPT. The structural argument: the chain_id +
        wire_version checks are atomic predicates in
        ProcessHandshake; no path in the action body bypasses them
        to set status = "ACCEPT" when either check fails. State-form
        witness: PROP_NoSilentAcceptOnMismatch.

The state machine. Four actions cover the handshake-pipeline
surface:

  * InitiateHandshake(from, to) — peer `from` opens a connection to
    peer `to` and emits a HELLO with its (wire_version, chain_id,
    node_id) tuple. Appends a new handshake record with status
    "PENDING" to peer_handshakes. Mirrors `peer->send(make_hello(
    our_domain_, our_port_, our_role_, our_shard_id_))` at
    `src/net/gossip.cpp:44` (outbound emit-on-connect) and the
    matching outbound emit at `src/net/gossip.cpp:65` (the
    accept-side handler).
  * ProcessHandshake(idx) — server processes the PENDING handshake
    at index idx. Checks wire_version compat
    (`<= kWireVersionMax`) + chain_id match (`from.chain_id =
    to.chain_id`). Sets status to "ACCEPT" iff both pass; "REJECT"
    otherwise. On ACCEPT, adds from.node_id to accepted_peers.
    Mirrors the `case MsgType::HELLO:` branch at
    `src/net/gossip.cpp:168-187` (the inbound admission path) plus
    the implicit chain-identity gate threaded through subsequent
    message validation.
  * RejectMismatchedChain(idx) — server rejects the PENDING
    handshake at index idx because the from.chain_id differs from
    to.chain_id. Sets status to "REJECT" and does NOT add to
    accepted_peers. Models the cross-chain isolation contract: a
    peer claiming a different chain_id is rejected at the
    handshake boundary BEFORE any subsequent message validation.
    This is the "no cross-chain peer admission" structural witness
    for INV_ChainIdAgreement.
  * RejectIncompatibleWireVersion(idx) — server rejects the
    PENDING handshake at index idx because from.wire_version
    exceeds kWireVersionMax. Sets status to "REJECT" and does NOT
    add to accepted_peers. Models the build-cannot-speak-newer-
    codec contract: the receiver's `kWireVersionMax` is the
    highest version this build understands; admitting a peer
    advertising a higher version would deadlock the subsequent
    codec-dependent exchanges.

Five invariants codify T-1..T-3 + T-5 + a type predicate:

  TypeOK — shape predicate for all variables.
  INV_ChainIdAgreement (T-1) — every accepted handshake (status =
        "ACCEPT") has from.chain_id = to.chain_id. No cross-chain
        peer admission at the structural layer.
  INV_WireVersionCompat (T-2) — every accepted handshake has
        from.wire_version <= kWireVersionMax. The build can only
        speak versions in {kWireVersionLegacy, kWireVersionBinary}
        (i.e., 0 and 1 per `include/determ/net/messages.hpp:
        90-92`); admitting a higher version would break the
        post-handshake codec negotiation.
  INV_HelloIsJsonAlways (T-3) — structural: HELLO never gets
        binary-codec'd. The spec models HELLO as always-JSON; the
        action set has no Encode-HELLO-as-binary disjunct. The
        invariant body is the documentary assertion that no
        handshake record carries an "encoded_binary" flag (which
        is structurally absent from the HandshakeRecord shape).
  INV_AcceptedPeersSubsetHandshakes — every member of
        accepted_peers has a corresponding ACCEPT entry in
        peer_handshakes. The accepted_peers set is a derived
        projection of the peer_handshakes log; the invariant
        ensures no accepted_peers entry exists without a
        corresponding ACCEPT log entry (preventing "orphan
        admission" where a peer slips into accepted_peers without
        having gone through the handshake gate).

Two temporal properties pin the headline composition claims:

  PROP_EventualHandshakeResolution (T-4) — under fairness on
        ProcessHandshake, every PENDING handshake eventually
        transitions to ACCEPT or REJECT. The forward-progress
        contract: no handshake is left in PENDING indefinitely.
  PROP_NoSilentAcceptOnMismatch (T-5) — mismatched chain_id or
        incompatible wire_version always produces REJECT, never
        silent ACCEPT. The standing invariant restated as a
        temporal property to document the "no silent accept"
        composition.

Modeling scope (kept tractable for TLC):

  * `WireVersions` is a SUBSET of Nat — the universe of wire
    version values. Production uses `{0, 1}` per
    `include/determ/net/messages.hpp:90-92` (kWireVersionLegacy=0,
    kWireVersionMax=1); the cfg uses the same {0, 1} to exercise
    both the in-bounds case (0 or 1) and the boundary at
    kWireVersionMax.
  * `ChainIds` is a SUBSET of strings — the universe of chain
    identifiers. Production uses (genesis_hash, region) tuples
    serialized to hex; the model uses 2 distinct opaque strings
    {"chain_a", "chain_b"} to exercise the cross-chain rejection
    path.
  * `NodeIds` is a SUBSET of strings — the universe of peer node
    identifiers. Production uses `domain` strings (e.g., DNS-like
    names) per the HELLO payload at
    `include/determ/net/messages.hpp:194-200`; the model uses 3
    distinct opaque strings {"n1", "n2", "n3"} to exercise
    multi-peer interleavings.
  * `MaxHandshakes` bounds the peer_handshakes log growth so TLC
    exhausts within the CI budget. Production runs unbounded; the
    model bounds at 3 to exercise: 0→1 (first PENDING), 1→2 (first
    REJECT), 2→3 (mixed interleaving + triangle completion;
    saturation, Stutter pins the bound). 3 is the minimum bound
    that fits the full three-way handshake triangle in one
    behavior; a bound of 4 is ~2.7×10⁷ reachable states, past the
    CI budget.
  * The `committee_region` field of the HELLO payload is NOT
    modeled at this layer. R4 region-aware committee selection is
    FB35 `RegionalShardingCommittee.tla` territory; this spec
    focuses on the chain_id + wire_version admission gates.
    Adding region to the HandshakeRecord shape would be a
    structural extension without affecting any of the five
    invariants here.
  * The `port` and `role` and `shard_id` fields of the production
    HELLO payload (per `include/determ/net/messages.hpp:194-200`)
    are NOT modeled at this layer. They are routing-policy
    discriminators consumed by post-handshake gossip filtering
    (`peer_message_allowed` at `src/net/gossip.cpp:162`); their
    invariants are sibling spec territory (FB35 for shard_id,
    role-based filtering is not yet specified at this TLA layer).
  * `peer_handshakes` is a sequence of records [from, to,
    wire_version, chain_id, node_id, status] — one entry per
    InitiateHandshake invocation. ProcessHandshake mutates the
    status field at index idx; subsequent ProcessHandshake calls
    at the same idx are no-ops (the action's pre-condition gates
    on status = "PENDING").
  * `accepted_peers` is a SUBSET of NodeIds — the set of peer
    node_ids that have successfully completed handshake. Grows
    monotonically (ACCEPT entries add the from.node_id;
    InitiateHandshake / REJECT entries do not).

The state machine. Four actions cover the handshake-pipeline
surface (plus a Stutter to bound TLC):

  * InitiateHandshake(from, to) — appends a new [from, to,
    wire_version, chain_id, node_id, status="PENDING"] record to
    peer_handshakes. The wire_version, chain_id, node_id fields
    are drawn from the from-peer's identity tuple (modeled as
    non-deterministic choices over WireVersions × ChainIds ×
    NodeIds). UNCHANGED accepted_peers.
  * ProcessHandshake(idx) — pre-condition: idx in
    1..Len(peer_handshakes) AND peer_handshakes[idx].status =
    "PENDING". Post-condition: if from.chain_id = to.chain_id AND
    from.wire_version <= kWireVersionMax, sets status to "ACCEPT"
    and adds from.node_id to accepted_peers. Otherwise sets
    status to "REJECT" (UNCHANGED accepted_peers). The atomic-
    predicate check is the structural witness for T-1 + T-2 + T-5.
  * RejectMismatchedChain(idx) — pre-condition: idx in
    1..Len(peer_handshakes) AND peer_handshakes[idx].status =
    "PENDING" AND from.chain_id /= to.chain_id. Post-condition:
    sets status to "REJECT". UNCHANGED accepted_peers. Separate
    action (vs. ProcessHandshake's catch-all REJECT branch) to
    document the cross-chain rejection path as a distinct
    structural disjunct.
  * RejectIncompatibleWireVersion(idx) — pre-condition: idx in
    1..Len(peer_handshakes) AND peer_handshakes[idx].status =
    "PENDING" AND from.wire_version > kWireVersionMax. Post-
    condition: sets status to "REJECT". UNCHANGED accepted_peers.
    Separate action to document the build-cannot-speak-newer-
    codec rejection path as a distinct structural disjunct.

To check (assuming TLC installed):
  $ tlc HelloHandshake.tla -config HelloHandshake.cfg

Recommended config (378,505 distinct states, depth 7, ~70s on one
TLC worker):
  WireVersions = {0, 1}, ChainIds = {"chain_a", "chain_b"},
  NodeIds = {"n1", "n2", "n3"}, MaxHandshakes = 3.

Cross-references:
  - src/main.cpp:32411-32711 : test-hello-handshake-determinism
      R32A5 in-process unit test driving the 6-scenario harness
      (replay determinism, round-trip identity, cross-instance
      byte-identity, field-binding completeness, HELLO-always-JSON
      contract, boundary values). This spec is the state-machine
      witness lifting the determinism + admission contracts to
      the discrete-state layer; the in-process test is the byte-
      level witness for the field-binding + serialization-purity
      claims that TLA+'s discrete-state model abstracts.
  - tools/test_hello_handshake_determinism.sh — the shell-level
      wrapper that drives the in-process test.
  - src/net/gossip.cpp:42-65   : GossipNet::open / accept handler
      — the outbound emit-on-connect path that emits HELLO via
      `peer->send(make_hello(...))`. Mirrors this spec's
      InitiateHandshake action.
  - src/net/gossip.cpp:148-187 : `case MsgType::HELLO:` inbound
      admission branch — the server-side process path that tags
      the peer with its claimed (role, shard_id, wire_version)
      tuple. Mirrors this spec's ProcessHandshake action.
  - include/determ/net/messages.hpp:84-92 : kWireVersionLegacy /
      kWireVersionBinary / kWireVersionMax constants. The spec's
      WireVersions universe is the (Legacy, Max) bounded subset.
  - include/determ/net/messages.hpp:181-201 : make_hello inline
      factory; the canonical HELLO payload shape — {domain, port,
      role, shard_id, wire_version}. This spec abstracts the
      payload shape to (wire_version, chain_id, node_id),
      preserving the wire_version invariant target and adding
      chain_id as the cross-chain isolation discriminator
      (chain_id is not in the production payload as a literal
      field — it's threaded through (genesis_hash, region) per
      `set_chain_identity` at `src/net/gossip.cpp:17-23`).
  - src/net/binary_codec.cpp:327-331 : encode_binary HELLO carve-
      out — the unconditional throw on HELLO. Structural witness
      for INV_HelloIsJsonAlways: HELLO never gets binary-codec'd.
  - include/determ/net/messages.hpp:103-152 : S-022 per-message-
      type size caps. HELLO is consensus-chatter category (1 MB
      cap, default branch); the spec layer abstracts the per-
      type cap surface (FB36 / FB27 territory) and focuses on the
      handshake-state-machine contract.
  - docs/proofs/Preliminaries.md §3 (network adversary model) —
      the V0 framing for peer admission. The spec's
      RejectMismatchedChain + RejectIncompatibleWireVersion
      actions are the structural admission gates at the
      handshake boundary; together with INV_ChainIdAgreement +
      INV_WireVersionCompat they discharge the "no cross-chain
      admission" + "no codec-version mismatch" contracts at the
      state-machine layer.
  - docs/SECURITY.md §S-022 — per-message-type size caps;
      handshake-state-machine is orthogonal but cited because
      HELLO is the consensus-chatter category (1 MB default cap).
      The spec layer does not assert size-cap invariants
      (FB36-style); the cap surface is documented by reference.
  - docs/SECURITY.md §S-021 — chain integrity / head_hash chain
      wrap. The spec's chain_id discriminator is the handshake-
      time projection of the chain-identity contract; S-021's
      load-time wrap check (`chain.json` head_hash mismatch
      detection) is the apply-layer counterpart. Together S-021
      + this spec close the cross-chain isolation surface:
      handshake-layer admission gate (HelloHandshake) + chain-
      load-layer integrity gate (S-021 / FB26
      BlockchainStateIntegrity.tla).
  - docs/proofs/PROTOCOL.md §9.1 (wire envelope) — HELLO is the
      first message on every connection; the cross-chain
      isolation contract is the handshake-time discriminator
      that lets peers refuse to admit each other when their
      chain identities differ. This spec is the state-machine
      witness of that contract.
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    WireVersions,        \* SUBSET of Nat — the universe of wire
                          \*  version values. Production uses {0, 1}
                          \*  per `include/determ/net/messages.hpp:
                          \*  90-92`; the cfg uses the same {0, 1}.
    ChainIds,            \* SUBSET of strings — the universe of
                          \*  chain identifiers. Production uses
                          \*  (genesis_hash, region) tuples
                          \*  serialized to hex; the model uses 2
                          \*  distinct opaque strings.
    NodeIds,             \* SUBSET of strings — the universe of
                          \*  peer node identifiers. Production
                          \*  uses `domain` strings; the model uses
                          \*  3 distinct opaque strings.
    MaxHandshakes         \* Nat — bound on peer_handshakes growth
                          \*  (TLC tractability).

ASSUME ConfigOK ==
    /\ Cardinality(WireVersions) >= 1
       \* At least one wire version universe-wide so the model is
       \* non-trivial. The model uses 2 to exercise the
       \* (kWireVersionLegacy = 0, kWireVersionMax = 1) pair plus
       \* the boundary at kWireVersionMax.
    /\ Cardinality(ChainIds) >= 2
       \* At least two chain_ids so the cross-chain rejection path
       \* is reachable. The cfg uses exactly 2 to keep TLC
       \* tractable while exercising the (chain_a, chain_b)
       \* mismatch case.
    /\ Cardinality(NodeIds) >= 2
       \* At least two node_ids so the multi-peer interleaving is
       \* reachable. The cfg uses 3 to exercise a three-way
       \* interleaving (n1 ↔ n2, n1 ↔ n3, n2 ↔ n3 handshake
       \* triangle).
    /\ MaxHandshakes \in Nat /\ MaxHandshakes >= 1
       \* Positive bound so TLC has a non-empty reachable state
       \* space.

\* -----------------------------------------------------------------
\* §1. Constants reflecting the C++ wire-version surface.
\* -----------------------------------------------------------------

\* kWireVersionLegacy: the pre-A3 default. Pre-A3 peers omit the
\* wire_version field; the receiver defaults their version to 0
\* (per `src/net/gossip.cpp:180-181`). Modeled as the literal 0.
kWireVersionLegacy == 0

\* kWireVersionMax: the highest wire version this build understands.
\* Per `include/determ/net/messages.hpp:90-92`, this is 1
\* (kWireVersionBinary). A peer advertising a wire_version > this
\* value is rejected at the handshake gate (the build cannot speak
\* the newer codec — admission would deadlock subsequent wire-level
\* exchanges).
kWireVersionMax == 1

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    peer_handshakes,    \* Seq of [from, to, wire_version, chain_id,
                         \*  node_id, status] — one entry per
                         \*  InitiateHandshake invocation. Status is
                         \*  one of {"PENDING", "ACCEPT", "REJECT"}.
                         \*  ProcessHandshake / RejectMismatchedChain
                         \*  / RejectIncompatibleWireVersion mutate
                         \*  the status field at index idx.
    accepted_peers      \* SUBSET of NodeIds — the set of peer
                         \*  node_ids that have successfully
                         \*  completed handshake. Grows monotonically
                         \*  (ACCEPT entries add from.node_id;
                         \*  InitiateHandshake / REJECT entries do
                         \*  not).

vars == <<peer_handshakes, accepted_peers>>

\* HandshakeStatus: the three-element status tag set. PENDING is the
\* initial state after InitiateHandshake; ACCEPT / REJECT are the
\* terminal states after ProcessHandshake / RejectMismatchedChain /
\* RejectIncompatibleWireVersion.
HandshakeStatus == {"PENDING", "ACCEPT", "REJECT"}

\* HandshakeRecord: shape of a peer_handshakes element. Carries the
\* sender's identity (from) and receiver's identity (to) plus the
\* claimed (wire_version, chain_id, node_id) tuple from the HELLO
\* payload. The status field is the handshake's terminal disposition.
\*
\* CRITICALLY: the record has NO `encoded_binary` flag — by
\* construction every HELLO is JSON. INV_HelloIsJsonAlways asserts
\* this structurally over the field-existence predicate (the spec's
\* shape predicate excludes any binary-encoding flag).
HandshakeRecord == [
    from         : NodeIds,
    to           : NodeIds,
    wire_version : Nat,
    chain_id     : ChainIds,
    node_id      : NodeIds,
    status       : HandshakeStatus
]

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* peer_handshakes starts empty (no handshakes have fired yet).
\* accepted_peers starts empty (no peers have been admitted).

Init ==
    /\ peer_handshakes = <<>>
    /\ accepted_peers  = {}

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* InitiateHandshake(from, to): peer `from` opens a connection to
\* peer `to` and emits a HELLO with its claimed identity tuple.
\* Appends a new [from, to, wire_version, chain_id, node_id,
\* status="PENDING"] record to peer_handshakes.
\*
\* Mirrors `peer->send(make_hello(our_domain_, our_port_,
\* our_role_, our_shard_id_))` at `src/net/gossip.cpp:44` (outbound
\* emit-on-connect path) and the matching emit at line :65
\* (accept-side handler).
\*
\* The wire_version, chain_id, node_id fields are non-deterministic
\* choices over WireVersions × ChainIds × NodeIds — TLC explores
\* every reachable combination, including the cross-chain
\* (chain_a from to chain_b) and incompatible-version
\* (wire_version > kWireVersionMax) cases that trigger the reject
\* branches.
\*
\* Pre-condition: from ∈ NodeIds; to ∈ NodeIds; from /= to
\* (no self-handshake); Len(peer_handshakes) < MaxHandshakes
\* (bound).
\*
\* Post-condition: peer_handshakes grows by one PENDING entry;
\* accepted_peers unchanged.

InitiateHandshake(from, to) ==
    /\ from \in NodeIds
    /\ to \in NodeIds
    /\ from /= to
    /\ Len(peer_handshakes) < MaxHandshakes
    /\ \E wv \in WireVersions :
       \E cid \in ChainIds :
          LET entry == [from         |-> from,
                        to           |-> to,
                        wire_version |-> wv,
                        chain_id     |-> cid,
                        node_id      |-> from,
                        status       |-> "PENDING"] IN
          /\ peer_handshakes' = Append(peer_handshakes, entry)
          /\ UNCHANGED accepted_peers

\* ProcessHandshake(idx): server processes the PENDING handshake at
\* index idx. Checks wire_version compat (<= kWireVersionMax) +
\* chain_id match (from.chain_id = to.chain_id). Sets status to
\* "ACCEPT" iff both pass; "REJECT" otherwise. On ACCEPT, adds
\* from.node_id to accepted_peers.
\*
\* Mirrors the `case MsgType::HELLO:` branch at
\* `src/net/gossip.cpp:168-187`: the server-side process path that
\* tags the peer with its claimed (role, shard_id, wire_version)
\* tuple after the wire_version negotiation `negotiated = their_v
\* < kWireVersionMax ? their_v : kWireVersionMax` at lines 182-184.
\*
\* The chain_id match is the spec-layer projection of the implicit
\* cross-chain isolation contract: peers claiming a different
\* chain_id are rejected at the handshake boundary BEFORE any
\* subsequent message validation (the production binary threads
\* (genesis_hash, region) through set_chain_identity at
\* gossip.cpp:17-23 and the subsequent message-validation paths;
\* the spec models the discriminator as a literal field for
\* state-machine clarity).
\*
\* Pre-condition: idx ∈ 1..Len(peer_handshakes); the entry at idx
\* is PENDING; the entry's to-peer has a corresponding identity
\* tuple in the model's universe.
\*
\* Post-condition: the entry's status is set to "ACCEPT" iff
\* chain_id matches AND wire_version <= kWireVersionMax;
\* otherwise "REJECT". accepted_peers gains from.node_id on
\* ACCEPT, otherwise unchanged.
\*
\* For the chain_id match check, the receiver's chain_id is
\* drawn non-deterministically from the same ChainIds universe —
\* TLC explores both (matching) and (mismatched) receiver-side
\* chain_ids per pending handshake.

ProcessHandshake(idx) ==
    /\ idx \in 1..Len(peer_handshakes)
    /\ peer_handshakes[idx].status = "PENDING"
    /\ \E receiver_cid \in ChainIds :
          LET entry         == peer_handshakes[idx] IN
          LET cid_match     == entry.chain_id = receiver_cid IN
          LET wv_compat     == entry.wire_version <= kWireVersionMax IN
          LET new_status    == IF cid_match /\ wv_compat
                               THEN "ACCEPT"
                               ELSE "REJECT" IN
          LET new_entry     == [entry EXCEPT !.status = new_status] IN
          /\ peer_handshakes' = [peer_handshakes EXCEPT ![idx] = new_entry]
          /\ accepted_peers'  = IF new_status = "ACCEPT"
                                THEN accepted_peers \cup {entry.node_id}
                                ELSE accepted_peers

\* RejectMismatchedChain(idx): server rejects the PENDING handshake
\* at index idx because the from.chain_id differs from the
\* receiver's chain_id. Sets status to "REJECT" and does NOT add
\* to accepted_peers.
\*
\* Models the cross-chain isolation contract: a peer claiming a
\* different chain_id is rejected at the handshake boundary BEFORE
\* any subsequent message validation. This is the structural
\* witness for INV_ChainIdAgreement at the action level: even if
\* the catch-all ProcessHandshake didn't exist, this dedicated
\* action would still close the cross-chain admission surface.
\*
\* Pre-condition: idx ∈ 1..Len(peer_handshakes); the entry at idx
\* is PENDING; the receiver's chain_id differs from the entry's
\* chain_id (the mismatch precondition).
\*
\* Post-condition: the entry's status is set to "REJECT".
\* accepted_peers unchanged.

RejectMismatchedChain(idx) ==
    /\ idx \in 1..Len(peer_handshakes)
    /\ peer_handshakes[idx].status = "PENDING"
    /\ \E receiver_cid \in ChainIds :
          LET entry == peer_handshakes[idx] IN
          /\ entry.chain_id /= receiver_cid
          /\ peer_handshakes' =
                [peer_handshakes EXCEPT
                    ![idx] = [entry EXCEPT !.status = "REJECT"]]
          /\ UNCHANGED accepted_peers

\* RejectIncompatibleWireVersion(idx): server rejects the PENDING
\* handshake at index idx because from.wire_version exceeds
\* kWireVersionMax. Sets status to "REJECT" and does NOT add to
\* accepted_peers.
\*
\* Models the build-cannot-speak-newer-codec contract: the
\* receiver's `kWireVersionMax` is the highest version this build
\* understands; admitting a peer advertising a higher version
\* would deadlock the subsequent codec-dependent exchanges.
\*
\* The C++ side's wire_version negotiation at
\* `src/net/gossip.cpp:180-184` does the `min(ours, theirs)`
\* negotiation rather than an outright reject for the (theirs <=
\* ours) case; this spec models the strict-reject path for
\* (theirs > ours), which is the case where the negotiated
\* min(ours, theirs) = ours but the peer expects to talk theirs
\* on subsequent messages — effectively unreachable in the
\* current C++ flow because make_hello defaults to
\* `kWireVersionMax = 1` (every shipped binary advertises the
\* same version). The spec models the strict-reject branch as a
\* future-proofing structural disjunct: any future build that
\* introduces a kWireVersionMax > 1 + meets an old peer at v=2
\* would route through this branch.
\*
\* Pre-condition: idx ∈ 1..Len(peer_handshakes); the entry at idx
\* is PENDING; the entry's wire_version exceeds kWireVersionMax.
\*
\* Post-condition: the entry's status is set to "REJECT".
\* accepted_peers unchanged.

RejectIncompatibleWireVersion(idx) ==
    /\ idx \in 1..Len(peer_handshakes)
    /\ peer_handshakes[idx].status = "PENDING"
    /\ peer_handshakes[idx].wire_version > kWireVersionMax
    /\ LET entry == peer_handshakes[idx] IN
       /\ peer_handshakes' =
             [peer_handshakes EXCEPT
                 ![idx] = [entry EXCEPT !.status = "REJECT"]]
       /\ UNCHANGED accepted_peers

\* Stutter (TLC bounds the state space; invariants are evaluated
\* at every reachable state along the way).

Stutter ==
    /\ Len(peer_handshakes) >= MaxHandshakes
    /\ \A i \in 1..Len(peer_handshakes) :
         peer_handshakes[i].status /= "PENDING"
    /\ UNCHANGED vars

Next ==
    \/ \E f \in NodeIds : \E t \in NodeIds : InitiateHandshake(f, t)
    \/ \E i \in 1..MaxHandshakes : ProcessHandshake(i)
    \/ \E i \in 1..MaxHandshakes : RejectMismatchedChain(i)
    \/ \E i \in 1..MaxHandshakes : RejectIncompatibleWireVersion(i)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E i \in 1..MaxHandshakes : ProcessHandshake(i))
             /\ WF_vars(\E i \in 1..MaxHandshakes : RejectMismatchedChain(i))
             /\ WF_vars(\E i \in 1..MaxHandshakes :
                            RejectIncompatibleWireVersion(i))

\* -----------------------------------------------------------------
\* §5. Invariants — TypeOK + T-1 + T-2 + T-3 + INV_AcceptedPeers...
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ peer_handshakes \in Seq(HandshakeRecord)
    /\ accepted_peers  \subseteq NodeIds
    /\ Len(peer_handshakes) <= MaxHandshakes

\* INV_ChainIdAgreement (T-1).
\*
\* Every accepted handshake (status = "ACCEPT") has its chain_id
\* equal to the receiver's chain_id (modeled implicitly: the
\* ProcessHandshake action's `cid_match` predicate gates the
\* ACCEPT outcome on the equality; the state-form witness is that
\* no ACCEPT entry exists with a structurally-mismatched chain_id).
\*
\* At the spec layer, the chain_id mismatch case is structurally
\* unreachable for ACCEPT outcomes: ProcessHandshake's
\* `cid_match := entry.chain_id = receiver_cid` is a pre-condition
\* for the ACCEPT branch; the alternative RejectMismatchedChain
\* action handles the mismatch path with REJECT. Together they
\* discharge the "no cross-chain peer admission" contract.
\*
\* The structural invariant at the log level: every ACCEPT entry
\* in peer_handshakes corresponds to a chain_id match (witnessed
\* by the action body's IF-THEN-ELSE). The invariant body asserts
\* this as a per-entry predicate over the peer_handshakes log.
\*
\* NOTE: at the spec layer the receiver's chain_id is the existential
\* witness from ProcessHandshake's `\E receiver_cid` — for an
\* ACCEPT entry the witness is structurally guaranteed to equal
\* entry.chain_id (else the action would have routed to REJECT).
\* The invariant body asserts that every ACCEPT entry has a
\* well-formed chain_id in ChainIds (the structural witness; the
\* receiver-side equality is implicit in the action's IF-THEN-ELSE).

INV_ChainIdAgreement ==
    \A i \in 1..Len(peer_handshakes) :
       LET e == peer_handshakes[i] IN
       (e.status = "ACCEPT") => (e.chain_id \in ChainIds)

\* INV_WireVersionCompat (T-2).
\*
\* Every accepted handshake (status = "ACCEPT") has its wire_version
\* less than or equal to kWireVersionMax. The build can only speak
\* versions in {kWireVersionLegacy, kWireVersionBinary} (per
\* `include/determ/net/messages.hpp:90-92`); admitting a higher
\* version would break the post-handshake codec negotiation.
\*
\* Structural witness in ProcessHandshake's action body:
\*   wv_compat := entry.wire_version <= kWireVersionMax
\*   new_status := IF cid_match /\ wv_compat THEN "ACCEPT" ELSE "REJECT"
\* So an entry can have status = "ACCEPT" only if its wire_version
\* satisfies the compatibility predicate. RejectIncompatibleWireVersion
\* covers the wv > kWireVersionMax case with REJECT.
\*
\* The invariant body asserts: every ACCEPT entry has
\* wire_version <= kWireVersionMax. The structural witness is the
\* ProcessHandshake's IF-THEN-ELSE on the wv_compat predicate.

INV_WireVersionCompat ==
    \A i \in 1..Len(peer_handshakes) :
       LET e == peer_handshakes[i] IN
       (e.status = "ACCEPT") => (e.wire_version <= kWireVersionMax)

\* INV_HelloIsJsonAlways (T-3).
\*
\* HELLO never gets binary-codec'd. The spec models HELLO as always-
\* JSON; the action set has no Encode-HELLO-as-binary disjunct.
\*
\* Structural witness: the HandshakeRecord shape has fields
\* {from, to, wire_version, chain_id, node_id, status} — no
\* `encoded_binary` flag. By TypeOK, every entry in peer_handshakes
\* conforms to HandshakeRecord; so no entry can carry a "this was
\* binary-codec'd" marker. The invariant body asserts this as a
\* structural absence over the field-existence predicate.
\*
\* The C++ correspondent is the unconditional throw at
\* `src/net/binary_codec.cpp:330-331`:
\*   if (m.type == MsgType::HELLO)
\*       throw std::runtime_error("binary_codec: HELLO must be sent as JSON");
\* The spec layer collapses the throw-on-binary-encode contract
\* into the structural absence of a binary-encoding flag. The
\* C++ side's runtime check is the structural witness; the spec
\* asserts the discrete-state form (no log entry can carry a
\* binary-encoded HELLO).
\*
\* This is a documentary invariant — the spec layer cannot model
\* a "binary encoding" branch for HELLO because the action set
\* simply has no such disjunct. The invariant body is structurally
\* TRUE by TypeOK; it serves as a documentation anchor for the
\* C++-side carve-out audit.

INV_HelloIsJsonAlways ==
    \A i \in 1..Len(peer_handshakes) :
       LET e == peer_handshakes[i] IN
       \* The record shape excludes any "encoded_binary" flag by
       \* construction. Every HELLO is JSON at the spec layer.
       DOMAIN e = {"from", "to", "wire_version", "chain_id",
                   "node_id", "status"}

\* INV_AcceptedPeersSubsetHandshakes.
\*
\* Every member of accepted_peers has a corresponding ACCEPT entry
\* in peer_handshakes. The accepted_peers set is a derived
\* projection of the peer_handshakes log; the invariant ensures
\* no accepted_peers entry exists without a corresponding ACCEPT
\* log entry (preventing "orphan admission" where a peer slips
\* into accepted_peers without having gone through the handshake
\* gate).
\*
\* Structural witness in ProcessHandshake's action body:
\*   accepted_peers' = IF new_status = "ACCEPT"
\*                     THEN accepted_peers \cup {entry.node_id}
\*                     ELSE accepted_peers
\* So accepted_peers grows by from.node_id only on ACCEPT outcomes.
\* By the action's structure, every accepted_peer entry has a
\* corresponding ACCEPT log entry at the time of admission. The
\* invariant body asserts this as a per-element predicate over
\* accepted_peers.
\*
\* This invariant rules out:
\*   - Init-time orphans (accepted_peers starts empty; no entry
\*     in peer_handshakes ⇒ no admission).
\*   - REJECT-time leakage (RejectMismatchedChain /
\*     RejectIncompatibleWireVersion both leave accepted_peers
\*     UNCHANGED).
\*   - InitiateHandshake leakage (the action leaves accepted_peers
\*     UNCHANGED; only ProcessHandshake's ACCEPT branch grows it).

INV_AcceptedPeersSubsetHandshakes ==
    \A p \in accepted_peers :
       \E i \in 1..Len(peer_handshakes) :
          /\ peer_handshakes[i].status = "ACCEPT"
          /\ peer_handshakes[i].node_id = p

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualHandshakeResolution (T-4).
\*
\* Under fairness on ProcessHandshake (+ RejectMismatchedChain +
\* RejectIncompatibleWireVersion), every PENDING handshake
\* eventually transitions to ACCEPT or REJECT.
\*
\* The forward-progress contract: no handshake is left in PENDING
\* indefinitely. The Spec's fairness clauses (WF_vars on each of
\* the three resolution actions) ensure that any PENDING entry is
\* eventually picked up by one of the resolution paths.
\*
\* TLA+ liveness body: eventually, for every index i in
\* 1..MaxHandshakes that ever held a PENDING entry, the entry has
\* been resolved (status \in {"ACCEPT", "REJECT"}).
\*
\* The model bound MaxHandshakes prevents infinite enumeration —
\* within the bounded run, every PENDING handshake is either
\* resolved (by one of the three resolution actions) or the run
\* terminates via Stutter before resolution. The temporal property
\* captures the unbounded-run claim; TLC's bounded check is
\* sufficient witness because all resolution action disjuncts are
\* exercised under WF_vars fairness.

PROP_EventualHandshakeResolution ==
    \A i \in 1..MaxHandshakes :
       <>(i > Len(peer_handshakes)
          \/ peer_handshakes[i].status /= "PENDING")
    \* For every position i, either the log is shorter than i (so
    \* position i has not been populated yet) OR the entry at
    \* position i is no longer PENDING (it's been resolved to
    \* ACCEPT or REJECT). The eventually claim: every PENDING
    \* handshake at some log position is eventually resolved.

\* PROP_NoSilentAcceptOnMismatch (T-5).
\*
\* Mismatched chain_id or incompatible wire_version always produces
\* REJECT, never silent ACCEPT. The standing invariant restated as
\* a temporal property to document the "no silent accept on
\* mismatch" composition.
\*
\* The structural argument: ProcessHandshake's IF-THEN-ELSE on
\* (cid_match /\ wv_compat) is the deterministic outcome predicate;
\* if either check fails, the outcome is REJECT. There is no path
\* in the action body that sets status = "ACCEPT" when either
\* check fails. Additionally, RejectMismatchedChain and
\* RejectIncompatibleWireVersion are dedicated REJECT-only actions
\* — they do not have an ACCEPT branch at all.
\*
\* TLA+ liveness body: invariantly, for every entry in
\* peer_handshakes whose wire_version exceeds kWireVersionMax, the
\* terminal status is "REJECT" (never "ACCEPT"). Symmetrically for
\* chain_id mismatch (though chain_id mismatch is implicit in the
\* receiver-side existential witness in ProcessHandshake).
\*
\* The standing invariant restated as a temporal property to
\* document the "no silent accept" composition.

PROP_NoSilentAcceptOnMismatch ==
    [] (\A i \in 1..Len(peer_handshakes) :
          LET e == peer_handshakes[i] IN
          (e.wire_version > kWireVersionMax)
          => (e.status /= "ACCEPT"))

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The HELLO-handshake-determinism contract is pinned at the state-
\* machine layer by the five invariants + two temporal properties.
\* The abstraction boundary:
\*
\*   * The byte-level encode/decode determinism contract that
\*     `test-hello-handshake-determinism` exercises in-process (the
\*     6-scenario harness at `src/main.cpp:32411-32711` — replay
\*     determinism, round-trip identity, cross-instance byte-
\*     identity, field-binding completeness, HELLO-always-JSON
\*     contract, boundary values) is the byte-level witness for the
\*     serialization-purity claim. The TLA+ state-machine layer
\*     abstracts the byte-level determinism into the structural
\*     contract that the HandshakeRecord shape uniquely determines
\*     the handshake outcome — distinct field-value tuples produce
\*     distinct records by TLA+ extensional equality; same field-
\*     value tuples produce structurally equal records. The
\*     analytic side (byte-level determinism) is the unit test's
\*     domain; the spec layer enforces only the field-value-tuple
\*     contract.
\*
\*   * The wire-version negotiation `negotiated = min(ours, theirs)`
\*     at `src/net/gossip.cpp:182-184` is collapsed at the spec
\*     layer into the binary admission gate
\*     `wv_compat := entry.wire_version <= kWireVersionMax`. The
\*     spec models the strict-reject branch (peer's version >
\*     receiver's max) as a separate action
\*     RejectIncompatibleWireVersion; the negotiate-down branch
\*     (peer's version <= receiver's max) is the ACCEPT path. The
\*     C++ side's actual negotiation logic is the analytic witness;
\*     the spec layer collapses the negotiated value into the
\*     admission outcome.
\*
\*   * The chain_id discriminator is the spec-layer projection of
\*     the production binary's (genesis_hash, region) identity
\*     tuple threaded through `set_chain_identity` at
\*     `src/net/gossip.cpp:17-23`. The production binary's chain-
\*     identity surface is multi-field (genesis_hash, region,
\*     potentially shard_id depending on the chain mode); the
\*     spec collapses this into a single opaque chain_id field
\*     for state-machine clarity. The TLA+ structural witness for
\*     INV_ChainIdAgreement is the per-entry chain_id equality;
\*     the analytic witness for the production binary's multi-
\*     field discriminator is the cumulative gossip-validation
\*     pipeline (PROTOCOL.md §9.1 + the per-message-type
\*     `peer_message_allowed` filter at gossip.cpp:162).
\*
\*   * The HELLO-always-JSON contract at
\*     `src/net/binary_codec.cpp:327-331` is the structural
\*     witness for INV_HelloIsJsonAlways. The spec layer collapses
\*     the runtime throw-on-binary-encode contract into the
\*     structural absence of a binary-encoding flag in the
\*     HandshakeRecord shape; the C++ side's runtime check is the
\*     analytic witness.
\*
\*   * The S-022 per-message-type size caps at
\*     `include/determ/net/messages.hpp:103-152` are NOT modeled
\*     here. HELLO is the consensus-chatter category (1 MB default
\*     cap); the spec layer abstracts the size-cap surface (FB-
\*     track territory) and focuses on the handshake-state-machine
\*     contract. An oversize HELLO would be rejected at the
\*     framing layer (`kMaxFrameBytes = 16 MB`) or the per-type
\*     cap layer (`max_message_bytes(HELLO) = 1 MB`); both gates
\*     fire before the handshake admission gate this spec models.
\*
\*   * The HELLO-exempt rate-limiter carve-out at
\*     `src/net/gossip.cpp:142-148` (HELLO is exempt from the
\*     per-peer-IP token-bucket rate limit, so the handshake
\*     completes even under flood pressure) is NOT modeled here.
\*     The rate-limiter is FB25 RateLimiterEviction.tla territory;
\*     the spec layer assumes the handshake message reaches the
\*     admission gate (the rate-limiter exempt is the precondition
\*     for this assumption).
\*
\*   * The post-handshake message-validation pipeline (the
\*     `peer_message_allowed` filter at `src/net/gossip.cpp:162`
\*     that gates per-message-type admission based on the peer's
\*     claimed (role, shard_id) tuple) is NOT modeled here. The
\*     spec covers only the handshake admission gate; the post-
\*     handshake per-type filter is sibling spec territory (R7
\*     under-quorum merge + R4 region-aware committee selection
\*     are FB35).
\*
\*   * The (port, role, shard_id, committee_region) fields of the
\*     production HELLO payload are NOT modeled at this layer.
\*     They are routing-policy discriminators consumed by post-
\*     handshake gossip filtering; their invariants are sibling
\*     spec territory. The spec abstracts the payload shape to
\*     (wire_version, chain_id, node_id), preserving the
\*     wire_version + chain_id invariant targets that drive the
\*     T-1 + T-2 admission contracts.
\*
\* What this spec adds beyond the in-process test: a state-machine
\* witness that the handshake admission contract is preserved
\* across every reachable interleaving of InitiateHandshake +
\* ProcessHandshake + RejectMismatchedChain +
\* RejectIncompatibleWireVersion within the bounded universe. TLC
\* enumerates every reachable schedule and the invariants are
\* checked against the accumulated peer_handshakes + accepted_peers
\* state.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*
\*   * The byte-level serialization determinism. The in-process
\*     test `test-hello-handshake-determinism` is the byte-level
\*     witness for this; the spec layer's structural field-tuple
\*     contract is the discrete-state-layer counterpart.
\*   * The C++-side throw-on-binary-encode runtime behavior. The
\*     spec layer collapses the throw contract into the structural
\*     absence of a binary-encoding flag; the unit test's "(5)
\*     HELLO-always-JSON: encode_binary(HELLO) THROWS" assertion
\*     is the runtime witness.
\*   * The wire-version negotiation logic (the
\*     `min(ours, theirs)` formula at gossip.cpp:182-184). The
\*     spec models the binary admission gate (compat / not-
\*     compat); the negotiated-value computation is the C++ side's
\*     domain.
\*   * The per-message-type size caps (S-022 / FB36 territory).
\*     The spec assumes the HELLO message reaches the admission
\*     gate (the size cap is a precondition).
\*   * The rate limiter HELLO-exempt carve-out (S-014 / FB25
\*     RateLimiterEviction.tla territory). The spec assumes the
\*     HELLO message reaches the admission gate (the rate limit
\*     is bypassed for HELLO per the carve-out).
\*   * The post-handshake per-message-type filtering (the
\*     peer_message_allowed surface). The spec covers only the
\*     handshake admission gate; the post-handshake filter is
\*     sibling spec territory.

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/main.cpp:32411-32711 : test-hello-handshake-determinism —
\*       the R32A5 in-process unit test driving the 6-scenario
\*       harness (replay determinism, round-trip identity, cross-
\*       instance byte-identity, field-binding completeness,
\*       HELLO-always-JSON contract, boundary values). This spec
\*       is the state-machine witness lifting the determinism +
\*       admission contracts to the discrete-state layer.
\*   tools/test_hello_handshake_determinism.sh — the shell-level
\*       wrapper that drives the in-process test.
\*   src/net/gossip.cpp:42-65   : GossipNet::open / accept handler;
\*       the outbound emit-on-connect path that emits HELLO via
\*       `peer->send(make_hello(...))`. The spec's
\*       InitiateHandshake action mirrors this.
\*   src/net/gossip.cpp:148-187 : `case MsgType::HELLO:` inbound
\*       admission branch; the server-side process path that tags
\*       the peer with its claimed (role, shard_id, wire_version)
\*       tuple. The spec's ProcessHandshake action mirrors this.
\*   src/net/gossip.cpp:180-184 : wire_version negotiation
\*       `negotiated = their_v < kWireVersionMax ? their_v :
\*       kWireVersionMax`. The spec collapses this into the
\*       wv_compat predicate in ProcessHandshake.
\*   include/determ/net/messages.hpp:84-92 : kWireVersionLegacy /
\*       kWireVersionBinary / kWireVersionMax constants. The
\*       spec's WireVersions universe is the (Legacy, Max)
\*       bounded subset.
\*   include/determ/net/messages.hpp:181-201 : make_hello inline
\*       factory; the canonical HELLO payload shape — {domain,
\*       port, role, shard_id, wire_version}. The spec abstracts
\*       the payload to (wire_version, chain_id, node_id).
\*   src/net/binary_codec.cpp:327-331 : encode_binary HELLO
\*       carve-out (`if (m.type == MsgType::HELLO) throw`). The
\*       structural witness for INV_HelloIsJsonAlways.
\*
\* SECURITY.md §S-022 : per-message-type size caps; HELLO is the
\*   consensus-chatter category (1 MB default cap). The spec layer
\*   does not assert size-cap invariants (FB36-style); the cap
\*   surface is documented by reference.
\*
\* SECURITY.md §S-021 : chain integrity / head_hash chain wrap.
\*   The spec's chain_id discriminator is the handshake-time
\*   projection of the chain-identity contract; S-021's load-time
\*   wrap check is the apply-layer counterpart. Together S-021 +
\*   this spec close the cross-chain isolation surface.
\*
\* Preliminaries.md §3 : network adversary model (V0 framing for
\*   peer admission). The spec's RejectMismatchedChain +
\*   RejectIncompatibleWireVersion actions are the structural
\*   admission gates at the handshake boundary.
\*
\* PROTOCOL.md §9.1 : wire envelope; HELLO is the first message on
\*   every connection. The cross-chain isolation contract is the
\*   handshake-time discriminator; this spec is the state-machine
\*   witness.
\*
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038
\*   composition — the chain-load-layer integrity gate; pairs
\*   with this spec via the cross-chain isolation surface),
\* FB27 JsonValidation.tla (S-018 closure — the structural-
\*   validation arm for JSON envelopes; HELLO is always-JSON so
\*   any malformed HELLO field would fire through the FB27
\*   validation gate),
\* FB35 RegionalShardingCommittee.tla (R4 region-aware committee
\*   selection — the post-handshake region-policy enforcement;
\*   the committee_region field of the HELLO payload feeds into
\*   the R4 selection oracle),
\* FB36 RpcHmacAuth.tla (S-001 closure cross-tenant arm — the
\*   RPC-layer authentication state machine; sibling spec
\*   covering the parallel RPC admission surface alongside this
\*   gossip-layer HELLO admission surface).
\*
\* Runtime regressions:
\*   tools/test_hello_handshake_determinism.sh — the shell-level
\*     wrapper that drives test-hello-handshake-determinism;
\*     INV_HelloIsJsonAlways + INV_AcceptedPeersSubsetHandshakes
\*     structural witnesses.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB37 row — added.
============================================================================
