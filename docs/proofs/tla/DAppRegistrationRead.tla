--------------------------- MODULE DAppRegistrationRead ---------------------------
(*
FB50 — TLA+ specification of the TRUSTLESS d:-NAMESPACE DApp-registration
READER: the end-to-end `verify-dapp-registration` pipeline that proves a
DApp's on-chain registration to a light client WITHOUT trusting the
serving daemon. This is the d: sibling of the i:/m:/p: composite-key
readers — it completes the trustless-read family across every queryable
state namespace (a|s|r|d|b|k|c simple + i|m|p composite).

NOTE: no model-check this session — caller will TLC-validate. This module
is syntactically self-contained and ready for `tlc -config
DAppRegistrationRead.cfg DAppRegistrationRead.tla` once a companion `.cfg`
is supplied (one is shipped alongside).

Scope. A `verify-dapp-registration <domain>` read composes four trust
reductions, each of which a malicious daemon could try to subvert:

  (1) ANCHOR  — the client recomputes the genesis hash locally and
      rejects any daemon whose block-0 hash differs (light/trustless
      _read.cpp::anchor_genesis). A daemon serving a DIFFERENT chain
      is refused before any registry data is read.
  (2) HEAD    — the client verifies the committee-signed header chain
      to the tip and extracts the tip's committed state_root
      (light/trustless_read.cpp::verify_chain_to_head). The state_root
      is the only datum the rest of the read trusts.
  (3) PATH    — the client fetches the `d:<domain>` state-proof and
      runs merkle_verify: the (key_bytes, value_hash) leaf at
      target_index in a leaf_count-leaf tree must recompute (with the
      proof siblings + the S-040 root-wrapper) to the trusted
      state_root. This is FB44 (MerklePathVerify) territory — abstracted
      here to a single PathOk predicate.
  (4) BIND    — THE NOVEL CRUX OF FB50. The served leaf's `value_hash`
      must equal SHA256 of the CANONICAL DAppEntry field-encoding for
      the entry the client believes it is reading:
        value_hash = SHA256( service_pubkey[32]
                            || u64_be(registered_at)
                            || u64_be(active_from)
                            || u64_be(inactive_from)
                            || u64_be(len endpoint_url) || endpoint_url
                            || u64_be(len topics) || topics...
                            || retention
                            || u64_be(len metadata) || metadata )
      (src/chain/chain.cpp::build_state_leaves d: branch, lines 312-329).
      WITHOUT the bind, a daemon could serve a cryptographically-valid
      Merkle path for the RIGHT key + state_root but hand the client a
      value_hash that does NOT correspond to the registry entry it
      claims — letting the daemon assert "domain D is owned by pk' /
      registered at h' / is still active" while the chain committed a
      DIFFERENT entry. The bind closes this: the client recomputes
      SHA256(canonical_encoding(claimed_entry)) and compares it to the
      served value_hash; a mismatch is REJECTED.

The load-bearing safety property: a read is ACCEPTED (the client
believes the claimed DAppEntry is the on-chain registration) iff ALL
FOUR reductions pass — the daemon ran our chain (anchor), the header
chain to the tip is committee-signed (head), the d:<domain> Merkle path
recomputes to the trusted state_root (path), AND the served value_hash
equals SHA256(canonical_encoding(claimed_entry)) (bind). No reachable
read accepts a claimed entry whose canonical encoding does not hash to
the committed leaf value. This reduces a trustless DApp-registration
read to SHA-256 collision/second-preimage resistance
(Preliminaries.md §2.1) plus the FB44 path soundness plus the FB23
committee-signature soundness.

Seven theorems are pinned:

  (T-DR1) Four-Gate Soundness. Every ACCEPTED read passed all four
          gates (anchor /\ head /\ path /\ bind). No reachable accept
          skips a gate. The headline no-trust-leak contract.
  (T-DR2) Anchor Gate. A read against a daemon whose block-0 hash
          differs from the locally-recomputed genesis hash is REJECTED
          before any registry datum is consumed (anchor_genesis throw;
          trustless_read.cpp:72-77). No accept ever has anchor = FALSE.
  (T-DR3) Head Gate. A read whose header chain to the tip is NOT
          committee-verified (a forged or unsigned head) is REJECTED;
          the state_root such a read would trust is never used. No
          accept ever has head_verified = FALSE.
  (T-DR4) Path Gate. A read whose d:<domain> Merkle path does NOT
          recompute to the trusted state_root is REJECTED (the FB44
          merkle_verify gate). No accept ever has path_ok = FALSE.
  (T-DR5) Value-Hash Binding (THE NOVEL CRUX). A read whose claimed
          DAppEntry canonical encoding does NOT hash to the served
          value_hash is REJECTED. The client recomputes
          SHA256(canonical_encoding(claimed)) and compares; a forged
          claimed entry (wrong owner / wrong registered_at / wrong
          active window / wrong endpoint / wrong topics) yields a
          DIFFERENT canonical encoding hence a DIFFERENT recomputed
          hash, hence the bind fails. No accept ever has bind_ok =
          FALSE. This is the d:-namespace anti-substitution invariant.
  (T-DR6) Field Faithfulness. For every ACCEPTED read, the claimed
          DAppEntry equals the entry the chain actually committed at
          that domain's leaf — every queried field (owner /
          service_pubkey, registered_at, active_from, inactive_from,
          endpoint, topics, retention, metadata) matches the committed
          entry. Derived from T-DR5 under the injective-encoding
          abstraction: equal canonical encodings imply equal entries.
  (T-DR7) Determinism. Two identical reads (same domain, same daemon
          state) produce the identical accept/reject outcome. The
          recompute + the four gate predicates are pure functions of
          the read inputs against the fixed committed state.

The state machine. A single committed registry (the chain's d:
namespace leaf domain at a fixed state-root) is set at Init. A
non-deterministic Read action admits one (domain, claimed-entry,
daemon-honest flags) request per step, runs it through the four-gate
pipeline, and appends a ReadRecord to a read log. The invariants read
the log to verify every accepted read passed all four gates (T-DR1)
and that an accepted read's claimed entry is field-faithful to the
committed entry (T-DR6).

The four gates as pure-function predicates:

  AnchorOk(daemon)      : the daemon's block-0 hash matches the
                          locally-recomputed genesis hash. Modeled as
                          a per-daemon BOOLEAN flag (the byte-level
                          recompute is trustless_read.cpp's job).
  HeadOk(daemon)        : the daemon's header chain to the tip is
                          committee-signed (FB23 + verify_chain_to_head).
                          Modeled as a per-daemon BOOLEAN flag.
  PathOk(domain, daemon): the served d:<domain> Merkle path recomputes
                          to the daemon's committed state_root (FB44
                          merkle_verify). Modeled as TRUE iff the domain
                          is committed AND the daemon serves the honest
                          path. A daemon may serve a forged path
                          (path_ok = FALSE) — the gate must reject it.
  BindOk(claimed, committed): SHA256(canonical_encoding(claimed)) =
                          committed_value_hash. Modeled via the
                          injective Encode abstraction: BindOk holds
                          iff claimed = committed (equal canonical
                          encodings under collision resistance imply
                          equal entries). THE NOVEL d:-NAMESPACE GATE.

Variables:

  * `committed` — function Domains -> DAppEntry \cup {ABSENT}. The
    chain's d: namespace leaf domain at the fixed state-root: which
    domains are registered and (for each) the canonical committed
    entry. Set once at Init; the read pipeline checks claimed entries
    against it. Models the build_state_leaves d:-branch output.
  * `read_log` — a Seq of ReadRecord. Each record tags the request
    (domain, claimed entry, the daemon's four honest/forged flags), the
    four per-gate Booleans, and the overall accept decision. The
    invariants read this log.
  * `read_count` — Nat. Bounds read_log length for TLC tractability
    (one Read per step until MaxReads).

Modeling scope (kept tractable for TLC):

  * SHA-256 / the canonical DAppEntry encoding is modeled as an
    injective abstract constructor: Encode(entry) is a structured TERM,
    and two terms are equal IFF the entries are structurally identical.
    This is the standard collision-resistance abstraction (FB23
    FrostVerify, FB26 BlockchainStateIntegrity, FB44 MerklePathVerify
    use the same device). Under collision resistance, value_hash
    equality reduces to entry equality, so the bind gate (T-DR5) is
    EXACTLY claimed = committed.
  * A DAppEntry is modeled as a record over the invariant-relevant
    field subset: owner (the canonical owner / the bytes that key the
    entry), service_pubkey, registered_at, active_from, inactive_from.
    The endpoint_url / topics / retention / metadata fields are absorbed
    into the abstract `extra` field — they ARE part of the canonical
    encoding (build_state_leaves hashes them in), so a forged extra
    changes the encoding hence the value_hash; the model carries one
    abstract `extra` slot rather than the full payload to stay
    tractable. The bind gate's faithfulness (T-DR6) covers every
    field because Encode is injective over the full record.
  * The anchor + head gates are modeled as per-daemon BOOLEAN flags
    (a daemon either runs our chain + serves a committee-signed head,
    or it does not). The byte-level genesis recompute is
    trustless_read.cpp::anchor_genesis (lines 52-79); the committee-
    signature soundness is FB23 (FrostVerify.tla). FB50 abstracts both
    to flags and pins that an accept requires BOTH to be TRUE — the
    composition obligation, not the primitive soundness.
  * The path gate is modeled as TRUE iff the domain is committed AND
    the daemon serves the honest path; a forged path is path_ok =
    FALSE. The cryptographic path soundness is FB44 (MerklePathVerify.
    tla); FB50 consumes its accept/reject decision as the PathOk
    predicate. A NOT-committed domain has no committed value_hash, so
    a read for an absent domain cannot bind (BindOk against ABSENT is
    FALSE) and is rejected — the no-fabricated-registration analog of
    FB43's INV_AbsenceSound (T-CK5) at the application layer.

The state machine. Two actions cover the reader:

  * Read(domain, claimed, daemon) — admit one (domain, claimed-entry,
    daemon-flags) request, run the four-gate pipeline via MakeRecord,
    append one ReadRecord to read_log, increment read_count. Models one
    `determ-light verify-dapp-registration <domain>` invocation against
    a (possibly adversarial) daemon.
  * Saturate — stutter once read_count reaches MaxReads. TLC bounds the
    state space; the invariants are evaluated at every reachable state
    along the way.

TLC verifies the seven invariants at every reachable state across every
reachable interleaving of Read actions over the bounded domain x
claimed-entry x daemon-flag universe against the fixed committed
registry.

To check (assuming TLC installed):
  $ tlc DAppRegistrationRead.tla -config DAppRegistrationRead.cfg

Recommended config (state space ~10^4, < 30s):
  Domains = {d1, d2}, Owners = {o1, o2}, PubKeys = {k1, k2},
  Heights = {0, 1}, Extras = {x1, x2}, MaxReads = 5, committed = a
  1-2 element subset (so an absent-domain read is reachable), and a
  daemon-flag universe spanning honest + each single-gate-forged
  variant (anchor-forged, head-forged, path-forged, bind-forged).

Cross-references:
  - docs/proofs/tla/CompositeKeyStateProof.tla (FB43) — the SERVER-side
    key reconstruction over all ten namespaces (right key); FB50 is the
    d:-namespace application-layer reader that consumes a served proof
    and BINDS its value_hash to a DAppEntry encoding (right value). FB43
    pins "the key is canonical"; FB50 pins "the value is the registry
    entry you think it is."
  - docs/proofs/tla/MerklePathVerify.tla (FB44) — the CLIENT-side path
    verification (right path); FB50's PathOk predicate abstracts FB44's
    accept/reject decision. Composition: FB43 (right key) + FB44 (right
    path) + FB50 (right value) = a fully trustless d:-namespace read.
  - docs/proofs/tla/FrostVerify.tla (FB23) — the committee-signature
    verify over the state_root header; FB50's HeadOk predicate abstracts
    FB23's accept/reject decision. The trusted state_root FB50's path
    gate verifies against is the one FB23 confirms is committee-signed.
  - docs/proofs/tla/DAppRegistry.tla (FB9) /
    docs/proofs/tla/DAppRegistryLifecycleSM.tla (FB42) — the APPLY-side
    registry state machine (how the committed entry got there); FB50 is
    the READ-side: how a light client trustlessly learns that entry. FB9
    + FB42 pin owner-immutability + state-progression at apply; FB50
    pins value-hash-binding at read. The committed entry FB50 reads is
    exactly the one FB9 / FB42's apply actions produced.
  - light/trustless_read.cpp:55-82 — anchor_genesis (the AnchorOk gate);
    :81+ verify_chain_to_head (the HeadOk gate).
  - src/chain/chain.cpp:309-329 — build_state_leaves d: branch; the
    canonical DAppEntry field-encoding the value_hash commits. Encode is
    the spec-layer projection of this hash builder.
  - tools/test_dapp_register.sh + tools/test_dapp_e2e.sh +
    tools/operator_dapp_registration_audit.sh — the runtime surface
    exercising the d: namespace registration + read path.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,    \* set of DApp domain identifiers
    Owners,     \* set of owner identities (the bytes keying the entry)
    PubKeys,    \* set of service public keys (opaque 32-byte stand-ins)
    Heights,    \* finite set of block heights (registered_at / active_from / inactive_from)
    Extras,     \* abstract stand-in for endpoint_url + topics + retention + metadata
    MaxReads    \* bound on read_log length (TLC tractability)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ Cardinality(Owners)  >= 1
    /\ Cardinality(PubKeys) >= 1
    /\ Cardinality(Heights) >= 1
    /\ Cardinality(Extras)  >= 1
    /\ MaxReads \in Nat /\ MaxReads >= 1

\* -----------------------------------------------------------------
\* §1. DAppEntry shape + the ABSENT sentinel.
\* -----------------------------------------------------------------
\*
\* A DAppEntry is the canonical registry record FB50 reads. The model
\* carries the invariant-relevant field subset; the endpoint_url /
\* topics / retention / metadata payload is absorbed into the abstract
\* `extra` slot (it IS hashed into the canonical encoding by
\* build_state_leaves, so a forged extra changes the value_hash). See
\* FB9 / FB42 for the apply-side field semantics.
\*
\* owner          — the bytes keying the entry (the canonical owner;
\*                  preserved across apply-side RegisterUpdate per FB9).
\* service_pubkey — opaque PubKey stand-in.
\* registered_at  — block height at first-time register (immutable).
\* active_from    — block height the entry became callable.
\* inactive_from  — block height the entry deactivates (or a sentinel).
\* extra          — abstract stand-in for endpoint_url + topics +
\*                  retention + metadata (all hashed into the encoding).
DAppEntry == [owner:          Owners,
              service_pubkey: PubKeys,
              registered_at:  Heights,
              active_from:    Heights,
              inactive_from:  Heights,
              extra:          Extras]

\* ABSENT marks "no d:<domain> leaf was committed for this domain." A
\* read against an absent domain cannot bind (there is no committed
\* value_hash) and is rejected — the no-fabricated-registration analog
\* of FB43's INV_AbsenceSound at the application layer.
ABSENT == [absent |-> TRUE]

CommittedShape == DAppEntry \cup {ABSENT}

\* -----------------------------------------------------------------
\* §2. Encode — the injective canonical DAppEntry encoding (abstract).
\* -----------------------------------------------------------------
\*
\* value_hash = SHA256( service_pubkey || u64_be(registered_at) ||
\*   u64_be(active_from) || u64_be(inactive_from) || ... endpoint/topics/
\*   retention/metadata ... ) (src/chain/chain.cpp:312-329).
\*
\* Under SHA-256 collision/second-preimage resistance, two value_hashes
\* are equal IFF the encoded entries are identical. We model Encode as a
\* structured TERM (the entry record itself, tagged): TLA+ record
\* equality is structural, so Encode(e1) = Encode(e2) <=> e1 = e2 —
\* exactly the injective-encoding abstraction (FB23 / FB26 / FB44 use
\* the same device). The owner field is carried into the encoding via
\* the entry's canonical key + the hashed-in service_pubkey; a forged
\* owner-keyed substitution therefore changes the term.
Encode(e) == <<"dapp_leaf", e>>

\* -----------------------------------------------------------------
\* §3. The four trust-reduction gates as pure-function predicates.
\* -----------------------------------------------------------------
\*
\* A daemon is modeled by four honest/forged Booleans plus the claimed
\* entry it serves. The gates read these flags + the fixed committed
\* registry. A read accepts iff ALL FOUR gates pass.
\*
\* DaemonFlags shape:
\*   anchor_honest : the daemon's block-0 hash matches our genesis hash.
\*   head_honest   : the daemon's header chain to the tip is committee-
\*                   signed (FB23 / verify_chain_to_head).
\*   path_honest   : the daemon serves the honest d:<domain> Merkle path
\*                   (recomputes to the committed state_root; FB44).
\*   claimed       : the DAppEntry the daemon claims is the registration
\*                   (the entry the client will BIND-check against the
\*                   served value_hash). A forged claimed entry differs
\*                   from the committed entry.
DaemonFlags == [anchor_honest : BOOLEAN,
                head_honest   : BOOLEAN,
                path_honest   : BOOLEAN,
                claimed       : DAppEntry]

\* AnchorOk(daemon) — the daemon ran our chain (block-0 hash matches the
\* locally-recomputed genesis hash). trustless_read.cpp:55-82.
AnchorOk(daemon) == daemon.anchor_honest = TRUE

\* HeadOk(daemon) — the daemon's header chain to the tip is committee-
\* signed; the state_root the path gate trusts is genuine. FB23 +
\* verify_chain_to_head (trustless_read.cpp:81+).
HeadOk(daemon) == daemon.head_honest = TRUE

\* PathOk(domain, daemon) — the served d:<domain> Merkle path recomputes
\* to the trusted state_root (FB44 merkle_verify). TRUE iff the domain is
\* committed (there is a leaf to prove membership of) AND the daemon
\* serves the honest path. A read for an absent domain has no committed
\* leaf, so PathOk is FALSE (no membership proof exists — the daemon
\* would have to forge one, which FB44 rejects).
PathOk(domain, daemon) ==
    /\ committed[domain] /= ABSENT
    /\ daemon.path_honest = TRUE

\* BindOk(domain, daemon) — THE NOVEL d:-NAMESPACE GATE. The served
\* value_hash equals SHA256(canonical_encoding(claimed)). Under the
\* injective-Encode abstraction, this holds iff the claimed entry equals
\* the committed entry: a daemon that serves a forged claimed entry
\* produces a recomputed hash Encode(claimed) /= Encode(committed) =
\* committed value_hash, so the bind fails. An absent domain has no
\* committed entry to bind against, so BindOk is FALSE.
\*
\* src/chain/chain.cpp:312-329 commits value_hash = Encode(committed);
\* the client recomputes Encode(claimed) and compares. THE crux of
\* T-DR5 + T-DR6.
BindOk(domain, daemon) ==
    /\ committed[domain] /= ABSENT
    /\ Encode(daemon.claimed) = Encode(committed[domain])

\* -----------------------------------------------------------------
\* §4. ReadRecord shape + the MakeRecord pipeline.
\* -----------------------------------------------------------------
\*
\* Each Read appends one ReadRecord: the request (domain + daemon flags
\* + claimed entry), the four per-gate Booleans, and the overall accept
\* decision. The invariants read this log.

ReadRecord == [
    domain   : Domains,
    daemon   : DaemonFlags,
    anchor   : BOOLEAN,
    head     : BOOLEAN,
    path     : BOOLEAN,
    bind     : BOOLEAN,
    accepted : BOOLEAN
]

\* MakeRecord(domain, daemon): run the four-gate pipeline. The accept
\* decision is the conjunction of all four gates — exactly the
\* trustless-read contract: the read is believed iff the daemon ran our
\* chain (anchor) AND served a committee-signed head (head) AND the
\* d:<domain> path recomputes to the trusted state_root (path) AND the
\* served value_hash binds to the claimed entry's canonical encoding
\* (bind).
MakeRecord(domain, daemon) ==
    LET a == AnchorOk(daemon)
        h == HeadOk(daemon)
        p == PathOk(domain, daemon)
        b == BindOk(domain, daemon)
    IN [ domain   |-> domain,
         daemon   |-> daemon,
         anchor   |-> a,
         head     |-> h,
         path     |-> p,
         bind     |-> b,
         accepted |-> a /\ h /\ p /\ b ]

\* -----------------------------------------------------------------
\* §5. Variables.
\* -----------------------------------------------------------------

VARIABLES
    committed,    \* function Domains -> CommittedShape (the d: leaf domain)
    read_log,     \* Seq(ReadRecord)
    read_count    \* Nat (bounds read_log for TLC)

vars == <<committed, read_log, read_count>>

\* -----------------------------------------------------------------
\* §6. Initial state.
\* -----------------------------------------------------------------
\*
\* The committed registry is fixed at Init: each domain either maps to a
\* committed DAppEntry or to ABSENT. The model leaves the concrete
\* committed mapping to the .cfg (CHOOSE over the legal shapes) so TLC
\* explores reads against both committed and absent domains. read_log
\* starts empty; read_count starts at 0.
Init ==
    /\ committed \in [Domains -> CommittedShape]
    /\ read_log    = <<>>
    /\ read_count  = 0

\* -----------------------------------------------------------------
\* §7. Actions.
\* -----------------------------------------------------------------

\* Read(domain, daemon): the headline action — admit one (domain,
\* daemon-flags + claimed-entry) request, run the four-gate pipeline via
\* MakeRecord, append one ReadRecord to read_log, increment read_count.
\* Models one `determ-light verify-dapp-registration <domain>`
\* invocation against a (possibly adversarial) daemon. The committed
\* registry is read-only (the chain state is fixed at this state-root).
Read(domain, daemon) ==
    /\ domain \in Domains
    /\ daemon \in DaemonFlags
    /\ read_count < MaxReads
    /\ read_log'   = Append(read_log, MakeRecord(domain, daemon))
    /\ read_count' = read_count + 1
    /\ UNCHANGED committed

\* Saturate: stutter once read_count reaches MaxReads. TLC bounds the
\* state space; the invariants are evaluated at every reachable state
\* along the way.
Saturate ==
    /\ read_count >= MaxReads
    /\ UNCHANGED vars

Next ==
    \/ \E domain \in Domains, daemon \in DaemonFlags : Read(domain, daemon)
    \/ Saturate

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E domain \in Domains, daemon \in DaemonFlags :
                            Read(domain, daemon))

\* -----------------------------------------------------------------
\* §8. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ committed  \in [Domains -> CommittedShape]
    /\ read_log   \in Seq(ReadRecord)
    /\ read_count \in Nat
    /\ read_count <= MaxReads
    /\ Len(read_log) = read_count

\* -----------------------------------------------------------------
\* §9. Invariants — the seven T-DR1..T-DR7 claims.
\* -----------------------------------------------------------------

\* INV_FourGateSound (T-DR1) — the headline no-trust-leak contract.
\* Every accepted read passed ALL FOUR gates. No reachable accept skips
\* a gate.
\*
\* Structural witness: MakeRecord sets accepted = anchor /\ head /\ path
\* /\ bind by construction. So accepted = TRUE implies all four per-gate
\* Booleans are TRUE.
INV_FourGateSound ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => (e.anchor /\ e.head /\ e.path /\ e.bind)

\* INV_AnchorGate (T-DR2) — a read against a daemon that does NOT run
\* our chain is rejected. No accepted read has anchor = FALSE.
\*
\* Structural witness: AnchorOk(daemon) = daemon.anchor_honest; a forged
\* anchor (anchor_honest = FALSE) makes anchor = FALSE, so accepted =
\* FALSE. trustless_read.cpp:72-77 (the GENESIS HASH MISMATCH throw).
INV_AnchorGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => e.anchor

\* INV_HeadGate (T-DR3) — a read whose header chain is not committee-
\* verified is rejected; the state_root such a read would trust is never
\* used. No accepted read has head = FALSE.
\*
\* Structural witness: HeadOk(daemon) = daemon.head_honest; a forged head
\* makes head = FALSE, so accepted = FALSE. FB23 (FrostVerify) +
\* verify_chain_to_head.
INV_HeadGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => e.head

\* INV_PathGate (T-DR4) — a read whose d:<domain> Merkle path does not
\* recompute to the trusted state_root is rejected. No accepted read has
\* path = FALSE. A read for an absent domain has no committed leaf, so
\* PathOk is FALSE and the read is rejected.
\*
\* Structural witness: PathOk requires committed[domain] /= ABSENT AND
\* the honest path; a forged path makes path = FALSE. FB44 merkle_verify.
INV_PathGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => e.path

\* INV_BindGate (T-DR5) — THE NOVEL d:-NAMESPACE anti-substitution
\* invariant. A read whose claimed DAppEntry canonical encoding does NOT
\* hash to the served value_hash is rejected. No accepted read has bind
\* = FALSE.
\*
\* Structural witness: BindOk requires committed[domain] /= ABSENT AND
\* Encode(claimed) = Encode(committed[domain]); a forged claimed entry
\* makes bind = FALSE. src/chain/chain.cpp:312-329 (the canonical
\* encoding the value_hash commits).
INV_BindGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => e.bind

\* INV_FieldFaithful (T-DR6) — for every accepted read, the claimed
\* DAppEntry EQUALS the entry the chain actually committed at that
\* domain's leaf. Every queried field (owner, service_pubkey,
\* registered_at, active_from, inactive_from, extra) matches.
\*
\* Derivation: an accepted read has bind = TRUE (INV_BindGate), so
\* Encode(daemon.claimed) = Encode(committed[domain]). Under the
\* injective-Encode abstraction, equal canonical encodings imply equal
\* entries, so daemon.claimed = committed[domain]. This is the strongest
\* application-layer statement: the light client learns the EXACT
\* committed registration, never a daemon-chosen substitute.
INV_FieldFaithful ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => (e.daemon.claimed = committed[e.domain])

\* INV_NoAbsentAccept (T-DR4 + T-DR5, absence corollary) — a read for an
\* absent domain (no committed d:<domain> leaf) is never accepted. The
\* no-fabricated-registration invariant at the application layer (the
\* analog of FB43 INV_AbsenceSound (T-CK5)).
\*
\* Structural witness: both PathOk and BindOk require committed[domain]
\* /= ABSENT, so an absent domain fails both the path AND the bind gate;
\* accepted = FALSE.
INV_NoAbsentAccept ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.accepted => (committed[e.domain] /= ABSENT)

\* -----------------------------------------------------------------
\* §10. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualAnswer — under fairness on Read, the read_log always
\* eventually grows until saturation. The pipeline always terminates
\* with an accept/reject decision — it never hangs on a read. The
\* no-stuck-read liveness contract.
PROP_EventualAnswer ==
    (read_count < MaxReads)
    ~> (read_count > 0 /\ Len(read_log) = read_count)

\* PROP_Determinism (T-DR7) — the four-gate pipeline is a pure function
\* of (domain, daemon) against the fixed committed registry. Stated as a
\* standing invariant over the log: any two records with the same
\* (domain, daemon) have the identical four per-gate Booleans AND the
\* identical accept decision. Since committed is fixed at Init and
\* MakeRecord is deterministic, identical reads always produce identical
\* records.
PROP_Determinism ==
    \A i, j \in 1..Len(read_log) :
       (/\ read_log[i].domain = read_log[j].domain
        /\ read_log[i].daemon = read_log[j].daemon)
       => (/\ read_log[i].anchor   = read_log[j].anchor
           /\ read_log[i].head     = read_log[j].head
           /\ read_log[i].path     = read_log[j].path
           /\ read_log[i].bind     = read_log[j].bind
           /\ read_log[i].accepted = read_log[j].accepted)

\* -----------------------------------------------------------------
\* §11. Soundness commentary — what TLC checks vs. the C++ reader.
\* -----------------------------------------------------------------
\*
\* The trustless DApp-registration read composes four trust reductions,
\* each of which a malicious daemon could try to subvert independently.
\* FB50 pins the COMPOSITION obligation: an accept requires ALL FOUR
\* gates, so subverting any one of them is caught. TLC enumerates every
\* reachable interleaving of reads over the bounded domain x
\* daemon-flag universe — including the four single-gate-forged daemon
\* variants — and confirms the seven invariants hold against the fixed
\* committed registry.
\*
\* The crux is INV_BindGate (T-DR5) + INV_FieldFaithful (T-DR6): the
\* novel d:-namespace value-hash binding. FB43 (CompositeKeyStateProof)
\* pins that the served KEY is canonical (no wrong-key alias); FB44
\* (MerklePathVerify) pins that the served PATH recomputes to the
\* state_root (no forged inclusion). But a daemon that serves the RIGHT
\* key + a VALID path could still hand the client a value_hash that does
\* not correspond to the DAppEntry it claims — letting the daemon assert
\* a forged owner / registered_at / active window / endpoint / topics
\* while the chain committed a different entry. INV_BindGate closes this:
\* the client recomputes SHA256(canonical_encoding(claimed)) and compares
\* it to the served value_hash; under collision resistance, a match
\* implies claimed = committed (INV_FieldFaithful). This is the
\* application-layer anti-substitution gate that completes the
\* trustless-read family across the d: namespace:
\*
\*   FB43 (right key) + FB44 (right path) + FB50 (right value)
\*       = a fully trustless d:-namespace DApp-registration read.
\*
\* Composed with FB23 (FrostVerify) for the committee-signed head and
\* the anchor_genesis recompute, the full chain of trust reductions is:
\*
\*   anchor (our chain) -> head (committee-signed root) ->
\*       path (Merkle membership under that root) ->
\*       bind (value_hash = encoding of the claimed entry).
\*
\* Each reduction terminates in either a locally-recomputable equality
\* (anchor, bind) or a previously-proven primitive (head = FB23, path =
\* FB44). FB50 is the application-layer composition proof that pins
\* "all four, or reject."
\*
\* What this spec adds beyond the apply-side FB9 / FB42: those pin how
\* the committed entry GOT there (owner-immutability, state-progression
\* at apply); FB50 pins how a light client trustlessly LEARNS that entry
\* — the read-side counterpart. The committed entry FB50 reads is exactly
\* the one FB9 / FB42's apply actions produced.
\*
\* What the spec does NOT check (consistent with the sibling specs'
\* scope notes + the collision-resistance abstraction):
\*   * The byte-level SHA-256 / canonical encoding. Modeled as an
\*     injective term constructor (the standard abstraction; FB23 / FB26
\*     / FB44 use the same device). The concrete encoding is exercised by
\*     tools/test_dapp_register.sh + tools/test_dapp_e2e.sh +
\*     tools/test_dapp_snapshot.sh (the latter asserts the d:-namespace
\*     leaf survives a snapshot round-trip with the SAME state_root, per
\*     S-037 + S-038).
\*   * The Merkle-path bytes. PathOk abstracts FB44 (MerklePathVerify)'s
\*     accept/reject decision; the byte-level walk soundness is FB44.
\*   * The committee-signature bytes. HeadOk abstracts FB23
\*     (FrostVerify)'s accept/reject decision; the Ed25519/FROST verify
\*     soundness is FB23.
\*   * Non-membership. An absent domain returns reject (INV_NoAbsent
\*     Accept); trustless non-membership requires the documented SMT
\*     migration and is out of scope (same boundary as FB43 T-CK5).
\*   * The apply-side registry mutation. How committed[domain] came to
\*     hold its value is FB9 / FB42 territory; FB50 reads a fixed
\*     committed registry at a single state-root.

============================================================================
\* Cross-references.
\*
\* CompositeKeyStateProof.tla (FB43) ->
\*   FB43 (right key) + FB50 (right value). FB43 pins the served KEY is
\*       canonical over all ten namespaces; FB50 pins the d:-namespace
\*       served VALUE binds to a DAppEntry encoding. FB50 is the
\*       application-layer d: sibling of FB43's namespace-generic key
\*       reconstruction.
\*
\* MerklePathVerify.tla (FB44) ->
\*   FB44 (right path); FB50's PathOk predicate abstracts FB44's
\*       accept/reject decision. Composition FB43 + FB44 + FB50 = a fully
\*       trustless d:-namespace read.
\*
\* FrostVerify.tla (FB23) ->
\*   FB23 (committee-signed head); FB50's HeadOk predicate abstracts
\*       FB23's accept/reject decision. The trusted state_root FB50's
\*       path gate verifies against is the one FB23 confirms is signed.
\*
\* DAppRegistry.tla (FB9) / DAppRegistryLifecycleSM.tla (FB42) ->
\*   The APPLY-side registry state machine (owner-immutability, state-
\*       progression); FB50 is the READ-side. The committed entry FB50
\*       reads is the one FB9 / FB42's apply actions produced.
\*
\* C++ enforcement:
\*   light/trustless_read.cpp:55-82 : anchor_genesis — the AnchorOk gate
\*       (the GENESIS HASH MISMATCH throw at :72-77). INV_AnchorGate
\*       (T-DR2).
\*   light/trustless_read.cpp:81+   : verify_chain_to_head — the HeadOk
\*       gate (the committee-signed header walk to the tip + state_root
\*       extraction). INV_HeadGate (T-DR3).
\*   src/chain/chain.cpp:309-329    : build_state_leaves d: branch — the
\*       canonical DAppEntry field-encoding the value_hash commits.
\*       Encode is the spec-layer projection. INV_BindGate (T-DR5) +
\*       INV_FieldFaithful (T-DR6).
\*   src/chain/chain.cpp:435+       : Chain::state_proof — the d:<domain>
\*       state-proof the path gate verifies (key_bytes + value_hash +
\*       proof + target_index + leaf_count). The PathOk + BindOk inputs.
\*
\* Sibling specs (style template):
\*   FB43 CompositeKeyStateProof.tla — the pure-function + bounded-
\*       enumeration + INV-* state-machine style this module reuses; FB50
\*       is its d:-namespace application-layer read companion.
\*   FB44 MerklePathVerify.tla — the injective-hash-term abstraction +
\*       the four-gate accept-iff-all-gates pattern.
\*   FB23 FrostVerify.tla — the committee-signature verify abstraction
\*       FB50's HeadOk consumes.
\*
\* Runtime regressions:
\*   tools/test_dapp_register.sh / tools/test_dapp_e2e.sh — exercise the
\*       d: namespace registration + the apply-side path; FB50's
\*       committed registry is the d:-leaf set they produce.
\*   tools/test_dapp_snapshot.sh — asserts the d:-namespace leaf survives
\*       a snapshot round-trip with the SAME state_root (S-037 + S-038);
\*       FB50's BindOk recomputes against that committed value_hash.
\*   tools/operator_dapp_registration_audit.sh — operator-facing audit of
\*       the d: namespace registrations; FB50 is the trustless light-
\*       client read counterpart.
============================================================================
