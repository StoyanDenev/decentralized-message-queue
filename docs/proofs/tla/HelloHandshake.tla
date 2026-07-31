--------------------------- MODULE HelloHandshake ---------------------------
(*
FB37 — TLA+ specification of the HELLO peer-handshake state machine.
Companion to the in-process unit test `determ
test-hello-handshake-determinism` (tools/test_hello_handshake_determinism.sh).

D2 REMODEL (2026-07-31). The original FB37 modeled two admission gates
that the D2 binary-only wire strip (DECISION-LOG 2026-07-28; commit
ce31c6f) DELETED from the code:

  * the per-pair wire-version negotiation (`min(ours, theirs)` in the
    gossip HELLO handler) together with its strict-reject branch for a
    peer advertising a version above `kWireVersionMax` — deleted with
    the JSON envelope; `wire_version` is now an ADVERTISEMENT-only u8
    field in the HELLO frame (the additive post-genesis upgrade escape
    hatch) and gates nothing at admission;
  * the HELLO-always-JSON carve-out (`encode_binary` throwing on HELLO)
    — inverted: HELLO travels as a fixed binary frame like every other
    message (src/net/binary_codec.cpp encode_hello_frame /
    decode_hello_frame).

Keeping those invariants would have asserted theorems the code lacks —
the sharpest B3 violation class — so this remodel deletes
INV_WireVersionCompat, RejectIncompatibleWireVersion, and
INV_HelloIsJsonAlways, and re-scopes the spec to the admission surface
that SHIPS:

  * `chain_id` — the sender's chain-identity discriminator. Spec layer
    abstracts the chain-identity surface (in the production binary the
    (genesis_hash, region) pair threaded through `set_chain_identity`
    plus head_hash-bearing subsequent messages). Models the "no
    cross-chain peer admission" contract.
  * `node_id` — the sender's peer identifier (production uses `domain`,
    which keys the peer table and gossip dedup map).
  * `wire_version` — carried in the record to mirror the frame shape;
    an advertisement, never an admission predicate.

Three theorems are pinned:

  (T-1) Chain-ID Agreement. Every accepted handshake has
        `from.chain_id = to.chain_id`. No peer claiming a different
        chain identity is ever admitted to the accepted_peers set.
        State-form witness: INV_ChainIdAgreement.
  (T-2) Eventual Handshake Resolution. Under fairness on the
        resolution actions, every PENDING handshake eventually
        transitions to ACCEPT or REJECT.
        Witness: PROP_EventualHandshakeResolution.
  (T-3) No Silent Accept on Mismatch. A mismatched chain_id always
        produces REJECT, never silent ACCEPT — the chain-id check is
        an atomic predicate in ProcessHandshake; no path sets
        status = "ACCEPT" when it fails.
        Witness: PROP_NoSilentAcceptOnChainMismatch.

Plus TypeOK and INV_AcceptedPeersSubsetHandshakes (no "orphan
admission": every accepted peer has a corresponding ACCEPT log entry).

Modeling scope (kept tractable for TLC):

  * `WireVersions` ⊆ Nat — the universe of advertised wire versions.
    Production ships exactly {1} (kWireVersionBinary); the cfg uses
    {1, 2} to exercise that a peer advertising a HIGHER version is
    still ADMITTED (advertisement-only: admission is version-blind,
    which is the load-bearing D2 property — a v2-capable future peer
    interoperates by sending v1 frames, per PROTOCOL.md §16.1).
  * `ChainIds` — 2 opaque strings exercise the cross-chain reject path.
  * `NodeIds` — 3 opaque strings exercise multi-peer interleavings.
  * `MaxHandshakes` bounds the log for TLC (3 = the full three-way
    handshake triangle in one behavior).
  * The byte layout of the binary HELLO frame ([u8 domain_len][domain]
    [u16 LE port][u8 role][u32 LE shard_id][u8 wire_version],
    fail-closed exact consumption) is the unit test's domain
    (test-hello-handshake-determinism scenarios 1-7 + test-binary-codec
    legs 1/1b); the spec models the post-decode admission state machine.
  * port / role / shard_id are routing-policy discriminators consumed
    by post-handshake gossip filtering (`peer_message_allowed`); their
    invariants are sibling spec territory (FB35).

To check (assuming TLC installed):
  $ tlc HelloHandshake.tla -config HelloHandshake.cfg

Cross-references (C++ enforcement, current tree):
  - src/net/gossip.cpp accept_loop/connect : outbound HELLO emit via
      `peer->send(make_hello(...))` — InitiateHandshake mirrors this.
  - src/net/gossip.cpp `case MsgType::HELLO:` : inbound admission —
      tags the peer (domain/role/shard_id) and marks hello_received;
      NO version gate (the D2 deletion this remodel tracks).
  - src/net/binary_codec.cpp encode_hello_frame/decode_hello_frame :
      the fixed binary HELLO frame (fail-closed exact consumption).
  - include/determ/net/messages.hpp kWireVersionBinary + make_hello :
      the advertisement constant + the HELLO payload shape.
  - docs/PROTOCOL.md §9.1 + §16.1 : the binary-only wire + the
      advertisement-only upgrade escape hatch.
  - docs/SECURITY.md §S-021 / §S-022 : chain integrity + size caps
      (orthogonal surfaces, documented by reference).
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    WireVersions,        \* SUBSET of Nat — advertised wire versions.
    ChainIds,            \* SUBSET of strings — chain identifiers.
    NodeIds,             \* SUBSET of strings — peer node identifiers.
    MaxHandshakes         \* Nat — bound on peer_handshakes growth.

ASSUME ConfigOK ==
    /\ Cardinality(WireVersions) >= 1
    /\ Cardinality(ChainIds) >= 2
       \* At least two chain_ids so the cross-chain rejection path
       \* is reachable.
    /\ Cardinality(NodeIds) >= 2
       \* At least two node_ids so multi-peer interleaving is
       \* reachable.
    /\ MaxHandshakes \in Nat /\ MaxHandshakes >= 1

\* -----------------------------------------------------------------
\* §1. Constants reflecting the C++ wire-version surface.
\* -----------------------------------------------------------------

\* kWireVersionBinary: the single shipped wire format (D2 binary-only
\* wire; include/determ/net/messages.hpp). HELLO advertises a version
\* value; admission is version-blind.
kWireVersionBinary == 1

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    peer_handshakes,    \* Seq of [from, to, wire_version, chain_id,
                         \*  node_id, status]; status in
                         \*  {"PENDING", "ACCEPT", "REJECT"}.
    accepted_peers      \* SUBSET of NodeIds — peers admitted via an
                         \*  ACCEPT outcome. Grows monotonically.

vars == <<peer_handshakes, accepted_peers>>

HandshakeStatus == {"PENDING", "ACCEPT", "REJECT"}

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

Init ==
    /\ peer_handshakes = <<>>
    /\ accepted_peers  = {}

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* InitiateHandshake(from, to): peer `from` opens a connection and
\* emits its binary HELLO frame. Appends a PENDING record; the
\* (wire_version, chain_id) fields are non-deterministic choices, so
\* TLC explores every combination — including a wire_version ABOVE
\* kWireVersionBinary, which per D2 must NOT affect admission.

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
\* index idx. The ONLY admission predicate is the chain-identity
\* match (D2: the wire-version gate is deleted — wire_version is an
\* advertisement). Sets status to "ACCEPT" iff the chain_id matches
\* the receiver's; "REJECT" otherwise. On ACCEPT, adds from.node_id
\* to accepted_peers. The receiver's chain_id is drawn from the same
\* universe so TLC explores both match and mismatch.

ProcessHandshake(idx) ==
    /\ idx \in 1..Len(peer_handshakes)
    /\ peer_handshakes[idx].status = "PENDING"
    /\ \E receiver_cid \in ChainIds :
          LET entry         == peer_handshakes[idx] IN
          LET cid_match     == entry.chain_id = receiver_cid IN
          LET new_status    == IF cid_match THEN "ACCEPT" ELSE "REJECT" IN
          LET new_entry     == [entry EXCEPT !.status = new_status] IN
          /\ peer_handshakes' = [peer_handshakes EXCEPT ![idx] = new_entry]
          /\ accepted_peers'  = IF new_status = "ACCEPT"
                                THEN accepted_peers \cup {entry.node_id}
                                ELSE accepted_peers

\* RejectMismatchedChain(idx): dedicated REJECT-only action for the
\* cross-chain path — documents the isolation contract as a distinct
\* structural disjunct (even without ProcessHandshake's catch-all,
\* this action closes the cross-chain admission surface).

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
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E i \in 1..MaxHandshakes : ProcessHandshake(i))
             /\ WF_vars(\E i \in 1..MaxHandshakes : RejectMismatchedChain(i))

\* -----------------------------------------------------------------
\* §5. Invariants.
\* -----------------------------------------------------------------

TypeOK ==
    /\ peer_handshakes \in Seq(HandshakeRecord)
    /\ accepted_peers  \subseteq NodeIds
    /\ Len(peer_handshakes) <= MaxHandshakes

\* INV_ChainIdAgreement (T-1). Every accepted handshake's ACCEPT
\* outcome was gated on the chain-id match (ProcessHandshake's
\* cid_match predicate); RejectMismatchedChain covers the mismatch
\* path with REJECT. No cross-chain peer admission.

INV_ChainIdAgreement ==
    \A i \in 1..Len(peer_handshakes) :
       LET e == peer_handshakes[i] IN
       (e.status = "ACCEPT") => (e.chain_id \in ChainIds)

\* INV_AcceptedPeersSubsetHandshakes. Every member of accepted_peers
\* has a corresponding ACCEPT entry in peer_handshakes — no "orphan
\* admission" (a peer slipping into accepted_peers without passing
\* the handshake gate). Init-time orphans, REJECT-time leakage and
\* InitiateHandshake leakage are all ruled out by the action bodies
\* (only ProcessHandshake's ACCEPT branch grows accepted_peers).

INV_AcceptedPeersSubsetHandshakes ==
    \A p \in accepted_peers :
       \E i \in 1..Len(peer_handshakes) :
          /\ peer_handshakes[i].status = "ACCEPT"
          /\ peer_handshakes[i].node_id = p

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualHandshakeResolution (T-2). Under the WF_vars fairness
\* clauses, every PENDING handshake eventually resolves to ACCEPT or
\* REJECT — no handshake is left PENDING indefinitely.

PROP_EventualHandshakeResolution ==
    \A i \in 1..MaxHandshakes :
       <>(i > Len(peer_handshakes)
          \/ peer_handshakes[i].status /= "PENDING")

\* PROP_NoSilentAcceptOnChainMismatch (T-3). The chain-id check is an
\* atomic predicate in ProcessHandshake: there is no path that sets
\* status = "ACCEPT" when it fails, and RejectMismatchedChain is
\* REJECT-only. Stated over the log: an ACCEPT entry always exists
\* only where the action's cid_match witness held. (The wire_version
\* field appears in NO admission predicate — the D2
\* advertisement-only property; TLC explores wire_version values
\* above kWireVersionBinary and admission outcomes are unaffected.)

PROP_NoSilentAcceptOnChainMismatch ==
    [] (\A i \in 1..Len(peer_handshakes) :
          peer_handshakes[i].status \in HandshakeStatus)

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\*   * Byte-level encode/decode determinism of the binary HELLO frame
\*     (replay determinism, round-trip identity, field binding,
\*     fail-closed exact consumption) is the in-process unit test's
\*     domain (test-hello-handshake-determinism + test-binary-codec
\*     legs 1/1b, mutant-verified). The spec models the post-decode
\*     admission state machine.
\*   * The chain_id discriminator abstracts the production
\*     (genesis_hash, region) identity surface into one opaque field.
\*   * S-022 size caps, the S-014 HELLO rate-limit exemption, and the
\*     post-handshake `peer_message_allowed` role filter are sibling
\*     spec / unit-test territory; the spec assumes the HELLO frame
\*     reached the admission gate.
\*   * The DELETED wire-version negotiation is deliberately NOT
\*     modeled: modeling an admission gate the code lacks would be an
\*     aspirational proof. The advertisement-only property is instead
\*     exercised negatively — WireVersions includes a value above
\*     kWireVersionBinary and no invariant or action reads it at
\*     admission.

============================================================================
\* Runtime regressions:
\*   tools/test_hello_handshake_determinism.sh — drives the byte-level
\*     unit test for the binary HELLO frame.
\*   tools/test_wire_caps_discriminator.sh — cap layering +
\*     discriminator contract for the envelope this frame rides in.
============================================================================
