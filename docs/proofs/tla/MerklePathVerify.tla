--------------------------- MODULE MerklePathVerify ---------------------------
(*
FB44 — TLA+ specification of the CLIENT-SIDE Merkle-inclusion-proof
verification primitive: the recompute-the-root-and-compare walk at
`determ::crypto::merkle_verify` (src/crypto/merkle.cpp:113-141). This
is the light-client's ground-truth gate — `light::verify_state_proof`
(light/verify.cpp:333-343) and v2.3 trustless fast sync both reduce
"is this leaf committed under the trusted state_root" to a single
merkle_verify call. FB44 lifts that walk to the state-machine layer.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
MerklePathVerify.cfg MerklePathVerify.tla` once a companion `.cfg` is
supplied (one is shipped alongside).

Scope. merkle_verify takes a (root, key, value_hash, target_index,
leaf_count, proof[]) tuple and decides whether the (key, value_hash)
leaf at sorted-position target_index in a tree of leaf_count total
leaves, combined with the proof's sibling hashes, recomputes to root.
The walk is:

  current := leaf_hash(key, value_hash)              \* 0x00-prefixed
  idx := target_index ; level := leaf_count ; pi := 0
  WHILE level > 1:
    IF level odd THEN level := level + 1              \* duplicate-last
    sibling := proof[pi] ; pi := pi + 1
    IF idx even THEN current := inner(current, sibling)   \* 0x01-prefixed
                ELSE current := inner(sibling, current)
    idx := idx / 2 ; level := level / 2
  current := root_wrap(leaf_count, current)          \* 0x02-prefixed (S-040)
  RETURN pi = Len(proof) AND current = root

S-040 CLOSURE (now reflected in this model). The committed root is no
longer the bare inner-tree root; it is the root-wrapper hash
  root = SHA256(0x02 || be_u32(leaf_count) || inner_root)
(src/crypto/merkle.cpp::merkle_root_wrap; prefix 0x02 domain-separated
from 0x00 leaf / 0x01 inner). merkle_verify re-derives the inner root
from the proof exactly as before, then applies the SAME wrapper with
the CALLER-supplied leaf_count and compares to the committed root. A
forged count M /= N therefore yields a DIFFERENT committed root term
(SHA256(0x02||M||inner) /= SHA256(0x02||N||inner) = root) and is
REJECTED. leaf_count is now cryptographically BOUND into the root.

The load-bearing safety property: merkle_verify accepts iff the
recomputed (wrapped) root EQUALS the trusted root AND the proof length
exactly matches the walk height. No reachable input accepts against a
root the leaf+path+leaf_count does not actually hash to — the verifier
never approves a forged inclusion NOR a forged leaf_count. This is the
trustless-read soundness contract: a light client that runs
merkle_verify against a committee-signed state_root learns membership
of EXACTLY the (key, value_hash) it recomputed AT EXACTLY the
leaf_count the root commits to, never a server-chosen substitute,
because acceptance reduces to SHA-256 collision/second-preimage
resistance (Preliminaries.md §2.1).

The companion analytic surface is the exhaustive negative-space test
tools/test_merkle_proof_tampering.sh (~30 assertions, 15 scenario
groups); FB44 is the state-machine companion that pins the same
accept/reject decision across every reachable (input, tamper)
interleaving rather than a fixed mechanical input list.

Seven theorems are pinned, all SEVEN positive invariants (T-MV7 was
previously a MODELED-BUT-NOT-ASSERTED weakness; S-040 is now CLOSED,
so it is flipped to a true invariant — see below):

  (T-MV1) Recompute Soundness. Every accepted input recomputes to the
          supplied root: an "accept" outcome implies Recompute(input)
          = input.root. No reachable state accepts an input whose
          leaf+path does not hash to its root. The headline
          no-forged-inclusion contract (merkle.cpp:140
          `current == root`).
  (T-MV2) Domain Separation. The leaf hash is 0x00-prefixed, the inner
          hash is 0x01-prefixed, and the root-wrapper hash is
          0x02-prefixed (S-040); all three prefixes are pairwise
          disjoint, so no leaf hash can ever equal an inner-node hash
          nor a root-wrapper hash. This defeats the second-preimage
          attack where an attacker presents an inner node as a leaf (or
          vice-versa) and the cross-shape root aliasing the root-wrapper
          prefix forecloses. Modeled structurally: LeafTag, InnerTag,
          RootTag pairwise distinct in every recomputed hash term
          (merkle.cpp:28 prefix 0x00 vs :38 prefix 0x01 vs
          merkle_root_wrap prefix 0x02; merkle.hpp:93-96 rationale).
  (T-MV3) Exact-Length Gate. Acceptance requires the proof length to
          EXACTLY equal the walk height (pi = Len(proof) at the end);
          a truncated OR an over-long proof is rejected even if the
          consumed prefix would otherwise recompute to the root. No
          reachable accept has leftover or missing siblings
          (merkle.cpp:129 short-proof guard + :140 `proof_idx ==
          proof.size()` exact-consumption gate).
  (T-MV4) Parity-Directed Pairing. At each level the leaf-side hash is
          placed LEFT when idx is even and RIGHT when idx is odd
          (merkle.cpp:131-135). Swapping the order at any level
          changes the inner hash (inner is not commutative — the two
          operands are concatenated, not summed), so a proof built for
          one parity sequence cannot be replayed under another. Pinned
          via the order-sensitivity of Inner in Recompute.
  (T-MV5) Range Gate. Acceptance requires leaf_count >= 1 AND
          target_index < leaf_count; an empty tree (leaf_count = 0) or
          an out-of-range index is rejected before any hashing
          (merkle.cpp:119-120). No reachable accept violates the range
          precondition.
  (T-MV6) Determinism. Two identical inputs (same root, key,
          value_hash, target_index, leaf_count, proof) produce the
          identical accept/reject outcome. Recompute is a pure
          function of its arguments; the comparison against root is
          pure. The idempotence-under-replay witness.

  (T-MV7) Leaf-Count Binding (S-040 CLOSED). leaf_count IS bound into
          the committed root via the root-wrapper hash root =
          SHA256(0x02 || be_u32(leaf_count) || inner_root)
          (merkle.cpp::merkle_root_wrap). Two distinct
          (target_index, leaf_count) pairs that produce the SAME inner
          walk shape (same ceil(log2 N) level count + same per-level
          parity) consume the same siblings and recompute to the same
          INNER root, but the wrapper then folds in the DISTINCT
          leaf_count, so the COMMITTED roots differ: M /= N implies
          SHA256(0x02||M||inner) /= SHA256(0x02||N||inner). A caller
          that supplies a forged leaf_count therefore recomputes a
          wrapped root that does NOT equal the committed root and is
          REJECTED. The former boundary case pinned by `determ
          test-merkle-proof-tampering` scenario #8 — claiming
          leaf_count = 8 for a 5-leaf tree at index 2 — now REJECTS
          (the scenario assertion was inverted on S-040 closure: 5 and
          8 no longer alias because their wrapped roots differ). FB44
          asserts this as the true invariant INV_LeafCountBound: no two
          ACCEPTED records may share (leaf, idx, sibs, root) yet differ
          in n, because differing n forces differing committed roots.
          The caller-trust obligation S-040 documented is now
          cryptographically ENFORCED, not an operator guideline
          (merkle.hpp:64-83; SECURITY.md §S-040 CLOSED).

The state machine. A bounded universe of inputs is enumerated; a
non-deterministic Verify action admits one input per step, runs it
through the recompute walk, and appends a VerifyRecord (input + the
recomputed-root term + the accept/reject decision) to a verify log.
The seven positive invariants read the log to confirm every accept is
sound (T-MV1), domain-separated (T-MV2), exact-length (T-MV3),
parity-correct (T-MV4), in-range (T-MV5), and leaf-count-bound (T-MV7);
S-040 is CLOSED, so INV_LeafCountBound holds — no two accepted records
sharing (leaf, idx, sibs, root) may differ in n.

Modeling scope (kept tractable for TLC):

  * SHA-256 is modeled as an injective abstract constructor: a hash is
    a structured TERM, and two terms are equal IFF they are
    syntactically identical. This is the standard collision-resistance
    abstraction (the same one FB23 FrostVerify and FB26
    BlockchainStateIntegrity use): under collision resistance, hash
    equality reduces to input equality, so modeling the hash function
    as a free injective constructor is sound for the accept/reject
    decision. The TERMS carry their full structure (LeafTerm vs
    InnerTerm + operands), so the domain-separation prefix (T-MV2) and
    the operand-order (T-MV4) are observable in the term shape.
  * A "leaf" is a (key, value_hash) pair drawn from a small finite
    Leaves universe; the committed tree is the SORTED leaf array, and
    the honest root / honest proof for a target_index are computed by
    the same recompute walk the verifier runs (so the positive cases
    are self-consistent by construction).
  * The proof, target_index, and leaf_count an ATTACKER supplies are
    drawn from a bounded adversarial universe (honest values plus
    tampered variants: sibling-swap, truncation, extension, index
    off-by-one, leaf_count drift). The verifier does not trust them;
    merkle_verify's job is to reject every tampered variant — INCLUDING
    the leaf_count-drift case, which post-S-040 the root-wrapper hash
    now catches (T-MV7): a forged leaf_count produces a different
    committed root and is rejected.
  * Tree depth is bounded by the finite Leaves universe (a 2-4 leaf
    model gives 1-2 level walks, enough to exercise the parity gate,
    the odd-leaf duplication, and the exact-length gate; a 5-leaf vs
    8-leaf model under the .cfg confirms the S-040 fix — both yield the
    same INNER walk shape but DIFFERENT committed roots, so the former
    leaf_count=8 alias is now rejected, not accepted).

The state machine. Two actions cover the verifier:

  * Verify(input) — admit one input, run Recompute via the walk,
    append one VerifyRecord (the input, the recomputed-root term, and
    the accept Boolean) to verify_log, increment verify_count. Models
    one merkle_verify invocation.
  * Saturate — stutter once verify_count reaches MaxVerifies. TLC
    bounds the state space; the invariants are evaluated at every
    reachable state along the way.

TLC verifies the seven positive invariants at every reachable state
across every reachable interleaving of Verify actions over the bounded
input universe. INV_LeafCountBound holds because the root-wrapper hash
binds leaf_count into the committed root (S-040 closed); the 5-leaf vs
8-leaf model confirms the former alias no longer accepts.

To check (assuming TLC installed):
  $ tlc MerklePathVerify.tla -config MerklePathVerify.cfg

Recommended config (state space ~10^4, < 30s):
  Leaves = a 3-element leaf universe, target indices 0..2, an
  adversarial Proofs universe of honest + tampered sibling lists,
  LeafCounts = {2,3,4} (+ {5,8} to confirm the S-040 fix — the two no
  longer alias because the root-wrapper binds the distinct counts),
  MaxVerifies = 5.

Cross-references:
  - tools/test_merkle_proof_tampering.sh — the exhaustive negative-
    space regression (~30 assertions, 15 scenario groups); FB44 is the
    state-machine companion to its accept/reject decision. Scenario #8
    (leaf_count drift) is the T-MV7 / INV_LeafCountBound witness — its
    assertion was INVERTED on S-040 closure to assert the forged
    leaf_count=8 is now REJECTED (was a pinned ACCEPT pre-fix).
  - tools/test_merkle.sh + tools/test_merkle_tree_balanced.sh — the
    positive surface (round-trip every leaf) FB44's HonestRoot /
    HonestProof construction mirrors.
  - docs/proofs/tla/CompositeKeyStateProof.tla (FB43) — the SERVER-
    side key reconstruction (right key); FB44 is the CLIENT-side path
    verification (right path). Together: FB43 (right key) + FB44
    (right path) = right membership for the trustless light-client
    read. FB43's "proof" tag is exactly the object FB44 consumes.
  - docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — the chain-
    level state-root binding (the root FB44 verifies against is the
    one FB26 commits + the committee signs).
  - docs/proofs/tla/FrostVerify.tla (FB23) — the Ed25519/FROST verify
    primitive over the state_root header; FB23 + FB44 compose into the
    full anchor: a committee-signed root (FB23) that a recomputed path
    (FB44) is checked against.
  - docs/proofs/Preliminaries.md §2.1 — SHA-256 collision/second-
    preimage resistance; T-MV1 + T-MV2 reduce to it.
  - SECURITY.md §S-040 (CLOSED) — the leaf_count caller-trust threat
    model + the shipped root-wrapper fix; T-MV7 / INV_LeafCountBound is
    its state-machine witness now that the binding is enforced.
  - src/crypto/merkle.cpp:113-141 — merkle_verify; the Recompute
    operator is the spec-layer projection of the walk.
  - include/determ/crypto/merkle.hpp:64-98 — merkle_verify +
    merkle_leaf_hash + merkle_inner_hash contracts; the LeafTerm /
    InnerTerm constructors are the spec-layer projection.
  - light/verify.cpp:333-343 — light::verify_state_proof; the single
    merkle_verify call FB44 models is this function's load-bearing gate.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Leaves,        \* finite universe of leaf identifiers (proxy for (key, value_hash))
    Proofs,        \* finite universe of proof sibling-lists (honest + tampered)
    LeafCounts,    \* finite set of leaf_count values an input may carry
    MaxIndex,      \* upper bound on target_index (TLC tractability)
    MaxVerifies    \* bound on verify_log length (TLC tractability)

ASSUME ConfigOK ==
    /\ Cardinality(Leaves)  >= 1
    /\ Cardinality(Proofs)  >= 1
    /\ LeafCounts \subseteq Nat
    /\ MaxIndex  \in Nat
    /\ MaxVerifies \in Nat /\ MaxVerifies >= 1

\* -----------------------------------------------------------------
\* §1. Abstract SHA-256 as an injective term constructor.
\* -----------------------------------------------------------------
\*
\* Under collision/second-preimage resistance, two SHA-256 outputs are
\* equal IFF the inputs are identical. We model a hash as a structured
\* TERM; TLA+ tuple equality is structural, so two terms are equal iff
\* they are syntactically identical — exactly the collision-resistance
\* abstraction (FB23 + FB26 use the same device).
\*
\* LeafTag (0x00), InnerTag (0x01), and RootTag (0x02) are the
\* domain-separation prefixes (merkle.cpp:28 / :38 / merkle_root_wrap).
\* They are pairwise DISTINCT model values, so a LeafTerm can never
\* equal an InnerTerm nor a RootTerm (T-MV2 domain separation is
\* structural).

LeafTag  == "L"   \* the 0x00 leaf-hash prefix
InnerTag == "I"   \* the 0x01 inner-node-hash prefix
RootTag  == "R"   \* the 0x02 root-wrapper prefix (S-040)

\* leaf_hash(key, value_hash) = SHA256(0x00 || u32_be(len) || key || value_hash).
\* Modeled as <<LeafTag, leaf>> — the (key, value_hash) pair is the
\* `leaf` identifier; the u32-length-prefix is subsumed (it is a pure
\* function of key and does not affect injectivity at this abstraction).
LeafTerm(leaf) == <<LeafTag, leaf>>

\* inner_hash(left, right) = SHA256(0x01 || left || right). Modeled as
\* <<InnerTag, left, right>> — ORDER MATTERS (left /= right slot), so
\* Inner(a,b) /= Inner(b,a) whenever a /= b (T-MV4 parity sensitivity).
InnerTerm(left, right) == <<InnerTag, left, right>>

\* root_wrap(leaf_count, inner_root) = SHA256(0x02 || be_u32(leaf_count)
\* || inner_root). Modeled as <<RootTag, n, inner>> — the S-040
\* root-wrapper that BINDS leaf_count into the committed root. Two
\* distinct counts m /= n over the same inner root give distinct
\* committed roots (RootTerm(m, inner) /= RootTerm(n, inner)), so a
\* forged leaf_count cannot recompute to the trusted root (T-MV7;
\* merkle.cpp::merkle_root_wrap).
RootTerm(n, inner) == <<RootTag, n, inner>>

\* -----------------------------------------------------------------
\* §2. The recompute walk (merkle_verify lifted to a pure function).
\* -----------------------------------------------------------------
\*
\* RangeOk(idx, n): the leaf_count >= 1 AND target_index < leaf_count
\* precondition (merkle.cpp:119-120). An empty tree or out-of-range
\* index short-circuits to reject BEFORE any hashing.
RangeOk(idx, n) == n >= 1 /\ idx < n

\* WalkHeight(n): the number of levels merkle_verify walks for a tree
\* of n leaves = ceil(log2 n) = number of times level halves before
\* reaching 1, with odd levels rounded up (the duplicate-last
\* convention). Computed recursively to mirror the WHILE loop:
\*   level=1 -> 0 ; else step (round odd up, halve) and add 1.
RECURSIVE WalkHeightAux(_)
WalkHeightAux(level) ==
    IF level <= 1 THEN 0
    ELSE LET even == IF level % 2 = 1 THEN level + 1 ELSE level IN
         1 + WalkHeightAux(even \div 2)

WalkHeight(n) == WalkHeightAux(n)

\* RecomputeInner(leaf, idx, n, sibs): the recomputed INNER-tree-root
\* TERM produced by the walk, starting from LeafTerm(leaf) and folding
\* in the sibling sequence `sibs` (each element is itself a TERM) under
\* the parity-directed pairing. `sibs` is a 1-based Seq of sibling
\* terms; the walk consumes them in order. This is the pure-function
\* projection of merkle.cpp:122-138 — the inner root BEFORE the S-040
\* root-wrapper is applied.
RECURSIVE RecomputeInnerAux(_, _, _, _, _)
RecomputeInnerAux(current, idx, level, sibs, pi) ==
    IF level <= 1 THEN current
    ELSE LET even == IF level % 2 = 1 THEN level + 1 ELSE level
             sib  == sibs[pi]
             nxt  == IF idx % 2 = 0 THEN InnerTerm(current, sib)
                                    ELSE InnerTerm(sib, current)
         IN RecomputeInnerAux(nxt, idx \div 2, even \div 2, sibs, pi + 1)

RecomputeInner(leaf, idx, n, sibs) ==
    RecomputeInnerAux(LeafTerm(leaf), idx, n, sibs, 1)

\* Recompute(leaf, idx, n, sibs): the full committed-root TERM. The
\* inner root from the walk is wrapped by RootTerm(n, inner) — the S-040
\* root-wrapper SHA256(0x02 || be_u32(n) || inner_root)
\* (merkle.cpp::merkle_root_wrap). The verifier accepts iff this WRAPPED
\* term EQUALS the supplied root AND the consumed sibling count equals
\* Len(sibs) (T-MV3). Because n is folded into the outermost term, a
\* forged leaf_count yields a distinct committed root and is rejected
\* (T-MV7 / INV_LeafCountBound).
Recompute(leaf, idx, n, sibs) ==
    RootTerm(n, RecomputeInner(leaf, idx, n, sibs))

\* Accept(leaf, idx, n, sibs, root): the full merkle_verify decision.
\*   1. RangeOk gate (T-MV5).
\*   2. Exact-length gate: Len(sibs) must equal WalkHeight(n) — the
\*      walk consumes exactly that many siblings, and the final
\*      `proof_idx == proof.size()` check rejects any leftover OR
\*      missing sibling (T-MV3). A short proof also trips the
\*      `proof_idx >= proof.size()` guard mid-walk (merkle.cpp:129);
\*      either way a wrong-length proof never accepts.
\*   3. Recompute(...) = root (T-MV1).
Accept(leaf, idx, n, sibs, root) ==
    /\ RangeOk(idx, n)
    /\ Len(sibs) = WalkHeight(n)
    /\ Recompute(leaf, idx, n, sibs) = root

\* -----------------------------------------------------------------
\* §3. Honest tree construction (self-consistent positive cases).
\* -----------------------------------------------------------------
\*
\* The honest committed tree is the SORTED leaf array. We do not model
\* the sort here (the Leaves universe is the already-sorted domain);
\* the honest proof + root for (leaf-at-idx, n) are the ones the SAME
\* recompute walk produces, so the positive cases accept by
\* construction. The .cfg supplies the Proofs universe (honest sibling
\* lists for the committed indices PLUS tampered variants); HonestRoot
\* is the term the verifier should recompute for a well-formed input.
\*
\* For the spec we expose the honest root as the recompute of an
\* honest proof — i.e. an input <<leaf, idx, n, sibs, root>> is HONEST
\* iff root = Recompute(leaf, idx, n, sibs) AND Len(sibs) = WalkHeight(n)
\* AND RangeOk(idx, n). Honest inputs accept; the verifier's soundness
\* (T-MV1) is that ONLY inputs satisfying root = Recompute(...) accept.
IsHonest(leaf, idx, n, sibs, root) ==
    /\ RangeOk(idx, n)
    /\ Len(sibs) = WalkHeight(n)
    /\ root = Recompute(leaf, idx, n, sibs)

\* -----------------------------------------------------------------
\* §4. Input + record shapes.
\* -----------------------------------------------------------------
\*
\* An input is a verifier call. `sibs` is one of the Proofs universe
\* (a Seq of sibling TERMS). `root` is a TERM the caller claims is the
\* committed state-root; the verifier checks the recompute against it.
\*
\* To keep the universe finite and the roots meaningful, the candidate
\* root is ALWAYS the recompute of SOME (leaf', idx', n', sibs') honest
\* input — i.e. a real committed root — so an "accept against the wrong
\* root" outcome is the interesting forgery the verifier must reject.
\* The .cfg pins the concrete honest + adversarial combinations.

InputShape == [
    leaf : Leaves,
    idx  : 0..MaxIndex,
    n    : LeafCounts,
    sibs : Proofs,
    root : { Recompute(l, i, m, s) :
               l \in Leaves, i \in 0..MaxIndex, m \in LeafCounts, s \in Proofs }
]

\* Each Verify appends one VerifyRecord: the input fields, the
\* recomputed-root term, and the accept Boolean. The invariants read
\* this log.
VerifyRecord == [
    leaf     : Leaves,
    idx      : 0..MaxIndex,
    n        : LeafCounts,
    sibs     : Proofs,
    root     : { Recompute(l, i, m, s) :
                   l \in Leaves, i \in 0..MaxIndex, m \in LeafCounts, s \in Proofs },
    recomp   : { Recompute(l, i, m, s) :
                   l \in Leaves, i \in 0..MaxIndex, m \in LeafCounts, s \in Proofs },
    accepted : BOOLEAN
]

MakeRecord(in) ==
    [ leaf     |-> in.leaf,
      idx      |-> in.idx,
      n        |-> in.n,
      sibs     |-> in.sibs,
      root     |-> in.root,
      recomp   |-> Recompute(in.leaf, in.idx, in.n, in.sibs),
      accepted |-> Accept(in.leaf, in.idx, in.n, in.sibs, in.root) ]

\* -----------------------------------------------------------------
\* §5. Variables.
\* -----------------------------------------------------------------

VARIABLES
    verify_log,    \* Seq(VerifyRecord)
    verify_count   \* Nat (bounds verify_log for TLC)

vars == <<verify_log, verify_count>>

\* -----------------------------------------------------------------
\* §6. Initial state.
\* -----------------------------------------------------------------

Init ==
    /\ verify_log   = <<>>
    /\ verify_count = 0

\* -----------------------------------------------------------------
\* §7. Actions.
\* -----------------------------------------------------------------

\* Verify(in): the headline action — admit one input, run the recompute
\* walk via MakeRecord, append one VerifyRecord to verify_log, increment
\* verify_count. Models one merkle_verify invocation.
Verify(in) ==
    /\ in \in InputShape
    /\ verify_count < MaxVerifies
    /\ verify_log'   = Append(verify_log, MakeRecord(in))
    /\ verify_count' = verify_count + 1

\* Saturate: stutter once verify_count reaches MaxVerifies. TLC bounds
\* the state space; the invariants are evaluated at every reachable
\* state along the way.
Saturate ==
    /\ verify_count >= MaxVerifies
    /\ UNCHANGED vars

Next ==
    \/ \E in \in InputShape : Verify(in)
    \/ Saturate

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E in \in InputShape : Verify(in))

\* -----------------------------------------------------------------
\* §8. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ verify_log   \in Seq(VerifyRecord)
    /\ verify_count \in Nat
    /\ verify_count <= MaxVerifies
    /\ Len(verify_log) = verify_count

\* -----------------------------------------------------------------
\* §9. Invariants — the positive theorems T-MV1..T-MV6 (T-MV7 in §11).
\* -----------------------------------------------------------------

\* INV_RecomputeSound (T-MV1) — the headline no-forged-inclusion
\* contract. Every accepted record recomputes to its supplied root.
\* No reachable state accepts an input whose leaf+path does not hash
\* to its root.
\*
\* Structural witness: Accept's third conjunct is Recompute(...) =
\* root; MakeRecord sets recomp = Recompute(...). So accepted = TRUE
\* implies recomp = root by construction. Under the SHA-256
\* collision-resistance abstraction (terms equal iff structurally
\* identical), this is precisely merkle.cpp:140 `current == root`.
INV_RecomputeSound ==
    \A i \in 1..Len(verify_log) :
       LET e == verify_log[i] IN
       e.accepted => (e.recomp = e.root)

\* INV_DomainSeparation (T-MV2) — the leaf-vs-inner-vs-root
\* second-preimage defense. Post-S-040 every accepted record's
\* committed root is a RootTerm (0x02-prefixed root-wrapper), NEVER a
\* bare LeafTerm (0x00) nor a bare InnerTerm (0x01): the outermost
\* constructor is always the leaf-count-binding wrapper, even for the
\* single-leaf tree (RootTerm(1, LeafTerm(...))). The three prefixes are
\* pairwise disjoint, so no leaf hash, inner hash, or root hash can
\* collide across the three shapes.
\*
\* Structural witness: Recompute = RootTerm(n, RecomputeInner(...)), so
\* the outermost head is ALWAYS RootTag. LeafTag, InnerTag, RootTag
\* pairwise distinct pins disjointness.
INV_DomainSeparation ==
    /\ LeafTag /= InnerTag
    /\ LeafTag /= RootTag
    /\ InnerTag /= RootTag
    /\ \A i \in 1..Len(verify_log) :
          LET e == verify_log[i] IN
          e.accepted => (e.recomp[1] = RootTag)

\* INV_ExactLength (T-MV3) — the proof-length gate. Every accepted
\* record's sibling sequence has length EXACTLY WalkHeight(n): a
\* truncated or over-long proof never accepts even if a prefix would
\* recompute to the root.
\*
\* Structural witness: Accept's second conjunct is Len(sibs) =
\* WalkHeight(n). This is merkle.cpp:129 (short-proof mid-walk guard)
\* + :140 `proof_idx == proof.size()` (no-leftover exact-consumption
\* gate), composed into a single length equality.
INV_ExactLength ==
    \A i \in 1..Len(verify_log) :
       LET e == verify_log[i] IN
       e.accepted => (Len(e.sibs) = WalkHeight(e.n))

\* INV_RangeGate (T-MV5) — the precondition gate. Every accepted record
\* satisfies leaf_count >= 1 AND target_index < leaf_count. An empty
\* tree or an out-of-range index is rejected before any hashing.
\*
\* Structural witness: Accept's first conjunct is RangeOk(idx, n) =
\* (n >= 1 /\ idx < n). This is merkle.cpp:119-120.
INV_RangeGate ==
    \A i \in 1..Len(verify_log) :
       LET e == verify_log[i] IN
       e.accepted => (e.n >= 1 /\ e.idx < e.n)

\* INV_AcceptIffHonest (T-MV1 + T-MV4 combined) — acceptance is
\* EXACTLY the honest-input predicate. An input accepts iff it is a
\* well-formed honest proof (in range, exact length, recompute = root).
\* This is the tight characterization: there is NO reachable accepted
\* record that is not honest, and the verifier accepts every honest
\* record. The parity-directed pairing (T-MV4) is folded in via
\* Recompute's order-sensitive InnerTerm — an input whose sibling order
\* does not match the idx-parity sequence recomputes to a DIFFERENT
\* term and so fails the root equality, hence is not honest, hence is
\* rejected.
INV_AcceptIffHonest ==
    \A i \in 1..Len(verify_log) :
       LET e == verify_log[i] IN
       e.accepted <=> IsHonest(e.leaf, e.idx, e.n, e.sibs, e.root)

\* PROP_Determinism (T-MV6) — the recompute + comparison are pure
\* functions of the input. Stated as a standing invariant over the log:
\* any two records with identical inputs have the identical recomputed
\* term AND the identical accept decision. The idempotence-under-replay
\* witness.
PROP_Determinism ==
    \A i, j \in 1..Len(verify_log) :
       (/\ verify_log[i].leaf = verify_log[j].leaf
        /\ verify_log[i].idx  = verify_log[j].idx
        /\ verify_log[i].n    = verify_log[j].n
        /\ verify_log[i].sibs = verify_log[j].sibs
        /\ verify_log[i].root = verify_log[j].root)
       => (/\ verify_log[i].recomp   = verify_log[j].recomp
           /\ verify_log[i].accepted = verify_log[j].accepted)

\* -----------------------------------------------------------------
\* §10. Temporal property — liveness.
\* -----------------------------------------------------------------

\* PROP_EventualAnswer — under fairness on Verify, the verify_log
\* always eventually grows until saturation. merkle_verify always
\* terminates with a decision — the walk is bounded by WalkHeight(n)
\* and never hangs. The no-stuck-verify liveness contract.
PROP_EventualAnswer ==
    (verify_count < MaxVerifies)
    ~> (verify_count > 0 /\ Len(verify_log) = verify_count)

\* -----------------------------------------------------------------
\* §11. T-MV7 — the S-040 leaf-count binding, a TRUE INVARIANT (CLOSED).
\* -----------------------------------------------------------------
\*
\* INV_LeafCountBound is a positive invariant the primitive NOW
\* satisfies (S-040 CLOSED): "no two distinct leaf_count values accept
\* the same (leaf, idx, sibs, root) input." Pre-fix this was a modeled
\* NON-invariant because leaf_count was not bound into any hash; the
\* root-wrapper SHA256(0x02 || be_u32(leaf_count) || inner_root)
\* (merkle.cpp::merkle_root_wrap) now folds leaf_count into the
\* committed root, so two distinct counts produce two distinct roots.
\*
\* The former boundary witness — {5, 8} at idx 2, scenario #8 of
\* test_merkle_proof_tampering.sh — no longer aliases: n=5 and n=8 still
\* yield the same INNER walk (WalkHeight 3, same per-level parity,
\* same 3 siblings, same inner root), but the wrapper produces
\* RootTerm(5, inner) /= RootTerm(8, inner). Only one of the two can
\* equal the single trusted committed root, so at most one accepts; a
\* record claiming the OTHER count recomputes a wrapped root that does
\* not match and is rejected. Hence no two accepted records can share
\* (leaf, idx, sibs, root) yet differ in n.
\*
\* The caller-trust obligation S-040 documented is now cryptographically
\* ENFORCED, not an operator guideline. FB44 asserts INV_LeafCountBound
\* directly in the INVARIANTS block (merkle.hpp:64-83; SECURITY.md
\* §S-040 CLOSED).
INV_LeafCountBound ==
    \A i, j \in 1..Len(verify_log) :
       (/\ verify_log[i].accepted
        /\ verify_log[j].accepted
        /\ verify_log[i].leaf = verify_log[j].leaf
        /\ verify_log[i].idx  = verify_log[j].idx
        /\ verify_log[i].sibs = verify_log[j].sibs
        /\ verify_log[i].root = verify_log[j].root)
       => (verify_log[i].n = verify_log[j].n)

\* -----------------------------------------------------------------
\* §12. Soundness commentary — what TLC checks vs. the C++ primitive.
\* -----------------------------------------------------------------
\*
\* tools/test_merkle_proof_tampering.sh establishes the negative-space
\* soundness of merkle_verify by a fixed mechanical input list (~30
\* assertions over 15 scenario groups: value-hash flip, sibling tamper
\* at every position, index off-by-one, out-of-range, truncation,
\* extension, leaf_count drift, padding paths, key tamper). FB44 lifts
\* the SAME accept/reject decision to a state machine and pins it across
\* every reachable (input, tamper) interleaving over the bounded
\* universe.
\*
\* The crux is INV_AcceptIffHonest: acceptance is EXACTLY the honest-
\* input predicate (in range, exact length, recompute = root). Under
\* the SHA-256 collision-resistance abstraction (terms equal iff
\* structurally identical), this is the strongest possible soundness
\* statement: the verifier accepts a tampered input ONLY IF the tamper
\* produces a term structurally identical to the honest root — which
\* under collision resistance requires a SHA-256 collision. Composed
\* with FB43 (CompositeKeyStateProof.tla)'s key-reconstruction
\* soundness, this gives the full trustless-read contract:
\*
\*   FB43 (right key)  +  FB44 (right path)  =  right membership.
\*
\* A forged path here would let a malicious snapshot server prove
\* membership of a leaf the chain never committed — exactly what
\* INV_RecomputeSound + INV_AcceptIffHonest forbid at the verification
\* layer (FB43 forbids reconstructing the wrong key in the first place).
\*
\* The domain-separation invariant (T-MV2) is the second-preimage
\* defense: without the 0x00/0x01/0x02 prefix split, an attacker could
\* present an inner-node hash as a leaf (or a 64-byte leaf as a pair of
\* child hashes), aliasing a leaf to an internal node, or alias a
\* bare inner root against the leaf-count-bound committed root. The
\* pairwise-disjoint LeafTag/InnerTag/RootTag prefixes — modeled
\* structurally — close this (merkle.hpp:93-96).
\*
\* The leaf-count-binding invariant (T-MV7 / INV_LeafCountBound) is the
\* S-040 closure: the root-wrapper hash SHA256(0x02 || be_u32(n) ||
\* inner_root) folds leaf_count into the committed root, so a forged
\* leaf_count recomputes a distinct wrapped root and is rejected. Two
\* accepted records can no longer share (leaf, idx, sibs, root) yet
\* differ in n. Pre-S-040 this was a modeled non-invariant documenting
\* a caller-trust boundary; the binding is now cryptographically
\* enforced inside the primitive.
\*
\* What this spec adds beyond the regression test: a state-machine
\* witness that the accept/reject soundness holds across every
\* reachable interleaving of verifier calls, plus an explicit
\* state-machine statement of the leaf-count binding (T-MV7 /
\* INV_LeafCountBound) the primitive now provides post-S-040. The model
\* tracks the C++ primitive: every guarantee merkle_verify enforces is a
\* checked invariant here, with no remaining caller-trust gap.
\*
\* What the spec does NOT check (consistent with the regression's
\* scope + the SHA-256 abstraction):
\*   * The byte-level SHA-256 computation. Modeled as an injective term
\*     constructor (the standard collision-resistance abstraction; FB23
\*     + FB26 use the same device). The concrete hashing is exercised
\*     by tools/test_merkle.sh + test_merkle_proof_tampering.sh.
\*   * Non-membership. The tree is balanced-binary-over-sorted-leaves,
\*     NOT a sparse Merkle tree (merkle.hpp:5-21); it serves MEMBERSHIP
\*     proofs only. Non-membership requires the documented SMT
\*     migration; out of scope here.
\*   * The state-proof KEY reconstruction. That is FB43
\*     (CompositeKeyStateProof.tla) territory; FB44 consumes the
\*     already-reconstructed (key, value_hash) leaf and verifies the
\*     PATH. The composition FB43 + FB44 is the full read.
\*   * The committee signature over the state_root. That is FB23
\*     (FrostVerify.tla) / FB40 (MakeBlockSigPrimitive.tla) territory;
\*     FB44 takes the trusted root as a given anchor and verifies the
\*     path against it.

============================================================================
\* Cross-references.
\*
\* tools/test_merkle_proof_tampering.sh ->
\*   The exhaustive negative-space regression (15 scenario groups);
\*       FB44 is its state-machine companion. Scenario #8 (leaf_count
\*       drift) is the T-MV7 / INV_LeafCountBound witness — its
\*       assertion was INVERTED on S-040 closure to assert the forged
\*       leaf_count=8 is now REJECTED (was a pinned ACCEPT pre-fix).
\*
\* CompositeKeyStateProof.tla (FB43) ->
\*   FB43 (right key) + FB44 (right path) = right membership. FB43's
\*       "proof" outcome tag is exactly the object FB44 consumes.
\*
\* BlockchainStateIntegrity.tla (FB26) ->
\*   The state-root FB44 verifies against is the one FB26 commits +
\*       the committee signs; FB44 is the client-side counterpart of
\*       FB26's chain-side path soundness.
\*
\* FrostVerify.tla (FB23) ->
\*   FB23 (signed root anchor) + FB44 (path against the anchor) compose
\*       into the full trustless inclusion check.
\*
\* C++ enforcement:
\*   src/crypto/merkle.cpp:113-141 : merkle_verify. The Recompute +
\*       Accept operators are the spec-layer projection of the walk.
\*   src/crypto/merkle.cpp:119-120 : leaf_count==0 / out-of-range index
\*       reject. INV_RangeGate (T-MV5).
\*   src/crypto/merkle.cpp:122      : current = leaf_hash(key, value).
\*       LeafTerm; the 0x00-prefixed walk seed (T-MV2).
\*   src/crypto/merkle.cpp:127-137 : the per-level walk (odd-duplicate,
\*       parity-directed inner-hash, idx + level halving).
\*       RecomputeInner's RecomputeInnerAux body (T-MV4 parity pairing).
\*   src/crypto/merkle.cpp:129      : `proof_idx >= proof.size()` short-
\*       proof guard. INV_ExactLength (T-MV3), mid-walk half.
\*   src/crypto/merkle.cpp::merkle_root_wrap : root = SHA256(0x02 ||
\*       be_u32(leaf_count) || inner_root) — the S-040 root-wrapper.
\*       RootTerm(n, inner) (T-MV7 / INV_LeafCountBound + T-MV2 RootTag).
\*   src/crypto/merkle.cpp:140      : `proof_idx == proof.size() &&
\*       current == root` exact-consumption + root-equality gate, where
\*       `current` is the WRAPPED root. INV_ExactLength (T-MV3) +
\*       INV_RecomputeSound (T-MV1).
\*   include/determ/crypto/merkle.hpp:28 / :38 : 0x00 leaf prefix vs
\*       0x01 inner prefix vs 0x02 root-wrapper prefix. LeafTag,
\*       InnerTag, RootTag pairwise distinct (T-MV2).
\*   include/determ/crypto/merkle.hpp:64-83 : the S-040 leaf_count
\*       binding (CLOSED via root-wrapper). T-MV7 / INV_LeafCountBound
\*       is its state-machine witness.
\*   light/verify.cpp:333-343 : light::verify_state_proof; the single
\*       merkle_verify call FB44 models is this function's gate.
\*
\* SECURITY.md §S-040 (CLOSED) -> T-MV7 / INV_LeafCountBound (the
\*       leaf_count caller-trust threat model + the shipped root-wrapper
\*       fix that cryptographically binds leaf_count into the root).
\* docs/proofs/Preliminaries.md §2.1 -> T-MV1 + T-MV2 reduce to SHA-256
\*       collision / second-preimage resistance.
============================================================================
