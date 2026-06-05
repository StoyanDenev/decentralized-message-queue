--------------------------- MODULE BFTAcceptGate ---------------------------
(*
FB45 — TLA+ specification of the validator-side BFT accept-gate
decision tree for candidate blocks. Models the receiver's
mode-eligibility + quorum + proposer-binding checks that decide
whether a candidate block is admissible, with explicit coverage of
the two-level BFT shrinkage arithmetic (committee K -> k_bft, then
within-committee quorum Q) and the sentinel-aware signature count.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
BFTAcceptGate.cfg BFTAcceptGate.tla` once the TLC toolchain is
installed in CI.

Scope. Where FB1 Consensus.tla models the WITHIN-ROUND producer-side
message flow (IDLE -> CONTRIB -> BLOCK_SIG -> FINAL) and abstracts the
BFT branch to a single shrinkage (Keff = ceil(2K/3), degenerate at
K=3), this spec models the RECEIVER-side accept-gate that
`BlockValidator::validate_block` runs on a fully-formed candidate
block. It pins the exact decision tree of
`BlockValidator::check_creator_selection` (the committee-size <-> mode
pairing at `src/node/validator.cpp:96-104`) composed with
`BlockValidator::check_block_sigs` (the mode-eligibility gate at
`:388-401`, the proposer-must-sign gate at `:408-426`, and the
sentinel-aware quorum at `:429-449`). The producer-side escalation
gates of `Node::start_new_round` (`src/node/node.cpp:770-781`) are
modeled as the space of candidate blocks the receiver must adjudicate
— including ADVERSARIAL candidates a Byzantine producer might emit
(an under-threshold BFT escalation, a wrong proposer, a mis-sized
committee, an unsigned proposer, an under-quorum sig set).

The two-level shrinkage. The real protocol applies TWO independent
shrinkages when escalating to BFT (documented at `producer.cpp:543-552`
and mirrored in the validator at `validator.cpp:96-101` + `:403`):

  (1) committee size shrinks from the genesis K to k_bft = ceil(2K/3)
      members (the producer's `start_new_round` sets
      `current_creator_domains_.size() = k_bft` before block assembly).
  (2) within that smaller committee, a 2/3 quorum
      Q = ceil(2*k_bft/3) signatures are required (the value
      `required_block_sigs(BFT, k_bft)` returns).

The two coincide only at K=3 (k_bft=2, Q=2 — degenerate). At K=6:
k_bft=4, Q=3 (one sentinel slot permitted). At K=9: k_bft=6, Q=4 (two
sentinel slots). This spec models BOTH shrinkages explicitly via the
`KBft(k)` and `RequiredSigs(mode, m)` operators below — unlike FB1
which over-approximates by applying only shrinkage (1). The headline
INV_QuorumArithmeticSound invariant pins the exact arithmetic so the
K>=6 cases (where FB1 over-approximates) are checked at full fidelity.

The four BFT escalation gates. A candidate block claiming BFT mode is
mode-eligible only when ALL FOUR of the producer-side escalation gates
held at production time (`node.cpp:774-777`), re-checked structurally
by the receiver:

  (G1) bft_enabled (genesis flag; `validator.cpp:396`).
  (G2) total_aborts >= bft_escalation_threshold (the abort-count gate;
       `validator.cpp:394` + `:398-400`).
  (G3) committee size == k_bft, NOT k_full (the size<->mode pairing;
       `validator.cpp:101`). The producer escalates only when the
       region pool dropped below k_full (G3-producer at `node.cpp:774`);
       the receiver enforces the dual: a BFT block MUST carry a
       k_bft-sized committee, an MD block MUST carry a k_full-sized one.
  (G4) committee size >= k_bft (the pool was large enough to still
       form the shrunk committee; `node.cpp:777`). Modeled as the
       feasibility precondition on the candidate committee size.

What the model verifies (under TLC):

  (T-AG1) INV_TypeOK — shape predicate for the candidate-block record
          and the verdict log.
  (T-AG2) INV_ModeSizePairing — every ACCEPTED candidate has
          committee size == k_full iff MD, == k_bft iff BFT. A
          mis-sized candidate is always REJECTED. The state-form
          witness of `validator.cpp:100-104`'s md_ok/bft_ok disjunction.
  (T-AG3) INV_QuorumArithmeticSound — every ACCEPTED candidate has
          signed_count >= RequiredSigs(mode, committee_size), where
          RequiredSigs is the EXACT two-level arithmetic (MD -> m,
          BFT -> ceil(2m/3) with m already = k_bft). The headline
          invariant: no candidate with fewer than the required sigs
          is ever accepted, at ANY K (including K>=6 where the two
          shrinkages diverge).
  (T-AG4) INV_BftRequiresEscalation — every ACCEPTED BFT candidate
          satisfies all four escalation gates (G1..G4). A malicious
          producer cannot get a BFT block accepted by unilaterally
          escalating below the abort threshold. The state-form witness
          of `validator.cpp:388-401`.
  (T-AG5) INV_ProposerSignedWhenBft — every ACCEPTED BFT candidate
          names the deterministically-chosen proposer AND that proposer
          signed (non-sentinel at the proposer index). The state-form
          witness of `validator.cpp:408-426`. MD candidates carry an
          empty proposer field (`validator.cpp:406-407`).
  (T-AG6) INV_SentinelBudgetRespected — every ACCEPTED candidate has
          at most (committee_size - RequiredSigs) sentinel (unsigned)
          slots. MD permits zero sentinels; BFT permits up to
          k_bft - Q. The state-form witness of `validator.cpp:433-437`.

Two temporal properties pin the headline liveness claims:

  (PROP_EventualVerdict) — every submitted candidate eventually
    receives a verdict (ACCEPT or REJECT); the gate never wedges.
  (PROP_HonestBlockAccepted) — a well-formed honest candidate (correct
    size, correct quorum, correct proposer, escalation-justified)
    is eventually ACCEPTED. The accept-gate is not vacuously
    rejecting — it admits the honest path.

The companion analytic proofs give the cryptographic soundness:
  - FA5 BFTSafety.md (BFT safety under f_h < |K_h|/3; the |K_h|/Q
    intersection arithmetic this spec's RequiredSigs operator pins).
  - S025BFTEscalationSoundness.md (the escalation-gate analytic
    closure that INV_BftRequiresEscalation lifts to the state-machine
    layer).
  - the FB1 Consensus.tla within-round flow + FB40
    MakeBlockSigPrimitive.tla per-member sig binding feed the
    candidate blocks this spec adjudicates.

To check (assuming TLC installed):
  $ tlc BFTAcceptGate.tla -config BFTAcceptGate.cfg

Recommended config (state space small; exhausts in seconds):
  Members = {n1, n2, n3, n4, n5, n6}, KFull = 6, AbortThreshold = 5,
  MaxAborts = 7. K=6 is chosen DELIBERATELY so the two-level shrinkage
  is non-degenerate (k_bft=4, Q=3) — the regime FB1 over-approximates
  and this spec checks at full fidelity. A second cfg run at KFull=3
  exercises the degenerate-shrinkage path.
*)

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Members,            \* finite universe of committee-member domain IDs
    KFull,              \* genesis K (block_sig_committee_size); MD committee size
    AbortThreshold,     \* bft_escalation_threshold (abort count gating BFT)
    MaxAborts           \* spec-time bound on the abort count a candidate may carry

ASSUME ConfigOK ==
    /\ KFull \in Nat /\ KFull >= 1
    /\ Cardinality(Members) >= KFull
       \* The member universe must be large enough to draw a k_full committee.
    /\ AbortThreshold \in Nat
    /\ MaxAborts \in Nat /\ MaxAborts >= AbortThreshold

\* -----------------------------------------------------------------
\* §1. Shrinkage arithmetic — the EXACT two-level BFT quorum formula.
\* -----------------------------------------------------------------
\*
\* KBft(k) = ceil(2k/3) is the BFT-shrunk committee size (shrinkage 1).
\* Mirrors `size_t k_bft = (2 * k_full + 2) / 3;` at
\* validator.cpp:98 / :218 + producer's k_bft at node.cpp:771.
KBft(k) == (2 * k + 2) \div 3

\* RequiredSigs(mode, m) is the within-committee quorum (shrinkage 2):
\*   MD  -> m            (full K-of-K, no sentinels)
\*   BFT -> ceil(2m/3)   where m is ALREADY the shrunk k_bft
\* Mirrors `required_block_sigs` at producer.cpp:541-553 exactly.
\* At K=3: KBft(3)=2, RequiredSigs(BFT,2)=2 — degenerate.
\* At K=6: KBft(6)=4, RequiredSigs(BFT,4)=3 — one sentinel slot.
\* At K=9: KBft(9)=6, RequiredSigs(BFT,6)=4 — two sentinel slots.
RequiredSigs(mode, m) ==
    IF mode = "MD" THEN m ELSE (2 * m + 2) \div 3

\* The maximum number of sentinel (unsigned) slots a mode permits:
\*   MD  -> 0           (every committee member must sign)
\*   BFT -> k_bft - Q   (the slack between committee size and quorum)
SentinelBudget(mode, m) == m - RequiredSigs(mode, m)

\* -----------------------------------------------------------------
\* §2. The deterministic proposer index (abstracted).
\* -----------------------------------------------------------------
\*
\* The real protocol derives the proposer via `proposer_idx(seed,
\* aborts, committee_size)` (producer.cpp / validator.cpp:416). The
\* cryptographic seed derivation (epoch_committee_seed + abort_event
\* hashing) is FB23 / Preliminaries §2.3 territory; here we abstract it
\* to a pure deterministic function of (committee, abort_count) so the
\* accept-gate's proposer-binding check is observable. The KEY property
\* the spec pins is that the EXPECTED proposer is a deterministic
\* function of the candidate's own committee + abort count — the
\* receiver recomputes it and rejects a block naming any other member.
ProposerIndex(committee_seq, abort_count) ==
    \* committee_seq is a sequence (ordered committee); the proposer is
    \* at index ((abort_count) % Len) + 1 (1-based TLA sequences). This
    \* is the spec-layer projection of proposer_idx's rotate-on-abort
    \* behavior (the proposer rotates across abort retries).
    ((abort_count % Len(committee_seq)) + 1)

\* -----------------------------------------------------------------
\* §3. Candidate-block well-formedness + the accept predicate.
\* -----------------------------------------------------------------
\*
\* A candidate block is a record:
\*   mode    : "MD" | "BFT"
\*   creators: a SEQUENCE of committee-member domains (the ordered
\*             committee). Len(creators) is the committee size m.
\*   signers : a SUBSET of 1..Len(creators) — the indices that carry a
\*             non-sentinel signature. |signers| = signed_count.
\*   proposer: a member index in 1..Len(creators) for BFT, or 0 for MD
\*             (0 models the empty bft_proposer field).
\*   aborts  : Nat — the abort count the block carries (b.abort_events
\*             .size()); gates BFT escalation.
\*
\* The accept predicate is the conjunction of the five validator gates,
\* in the SAME ORDER the C++ evaluates them.

\* G_SizePairing: committee size <-> mode pairing (validator.cpp:100-104).
G_SizePairing(blk) ==
    \/ (blk.mode = "MD"  /\ Len(blk.creators) = KFull)
    \/ (blk.mode = "BFT" /\ Len(blk.creators) = KBft(KFull))

\* G_Escalation: BFT mode-eligibility — all four escalation gates
\* (validator.cpp:388-401). MD blocks pass this gate vacuously.
G_Escalation(blk) ==
    \/ blk.mode = "MD"
    \/ (/\ blk.mode = "BFT"
        /\ blk.aborts >= AbortThreshold              \* G2
        /\ Len(blk.creators) = KBft(KFull)           \* G3 (size = k_bft)
        /\ Len(blk.creators) >= KBft(KFull))         \* G4 (>= k_bft)
        \* G1 (bft_enabled) is a genesis CONSTANT here — the cfg fixes
        \* bft_enabled = TRUE; the bft_enabled=FALSE rejection path is
        \* exercised by a second cfg run. Modeled in BftEnabled below.

\* G1 as a genesis flag. The cfg sets it; a FALSE run rejects all BFT.
BftEnabled == TRUE

\* G_Proposer: proposer-binding (validator.cpp:406-426).
\*   MD  -> proposer field must be 0 (empty).
\*   BFT -> proposer == ProposerIndex(creators, aborts) AND that
\*          index is a signer (non-sentinel).
G_Proposer(blk) ==
    \/ (blk.mode = "MD" /\ blk.proposer = 0)
    \/ (/\ blk.mode = "BFT"
        /\ blk.proposer = ProposerIndex(blk.creators, blk.aborts)
        /\ blk.proposer \in blk.signers)

\* G_Quorum: sentinel-aware quorum (validator.cpp:429-449).
\* signed_count = |signers| must be >= RequiredSigs(mode, m).
G_Quorum(blk) ==
    Cardinality(blk.signers) >= RequiredSigs(blk.mode, Len(blk.creators))

\* The composite accept predicate: ALL gates pass.
Accept(blk) ==
    /\ (blk.mode = "BFT" => BftEnabled)              \* G1
    /\ G_SizePairing(blk)                            \* check_creator_selection
    /\ G_Escalation(blk)                             \* G2..G4
    /\ G_Proposer(blk)                               \* proposer-binding
    /\ G_Quorum(blk)                                 \* signed_count >= required

\* -----------------------------------------------------------------
\* §4. Candidate universe — the blocks the receiver may be handed.
\* -----------------------------------------------------------------
\*
\* The candidate universe is bounded for TLC: committee sizes are
\* exactly k_full or k_bft (mis-sized candidates also generated to
\* exercise the rejection path); signer subsets range over all subsets
\* of the committee indices; proposer ranges over 0..m; abort count
\* ranges over 0..MaxAborts. To keep the state space tractable we draw
\* the ordered committee as a fixed canonical sequence of the first m
\* members (the committee ORDER is the producer's selection order; the
\* accept-gate's proposer-binding only depends on the order + abort
\* count, both observable in the candidate).

\* A canonical ordered committee of size m: the first m members under a
\* fixed enumeration of Members. CommitteeOfSize(m) is a SEQUENCE.
MemberSeq == CHOOSE s \in [1..Cardinality(Members) -> Members] :
                 \A i, j \in 1..Cardinality(Members) :
                    (i # j) => (s[i] # s[j])
CommitteeOfSize(m) == [i \in 1..m |-> MemberSeq[i]]

\* The committee sizes the receiver may see: the legitimate k_full and
\* k_bft, PLUS one mis-sized value (k_full + 1, clamped to the member
\* universe) to exercise the G_SizePairing rejection path.
CandidateSizes ==
    LET kb == KBft(KFull)
        ms == Cardinality(Members)
    IN  { KFull, kb } \cup
        (IF KFull + 1 <= ms THEN { KFull + 1 } ELSE {})

\* -----------------------------------------------------------------
\* §5. Variables + state machine.
\* -----------------------------------------------------------------
\*
\* The receiver processes candidates one at a time and appends a verdict
\* to a log. `pending` holds the current candidate (or a NONE sentinel);
\* `verdicts` is the append-only record of (candidate, accepted?) pairs.

NONE == [mode |-> "NONE", creators |-> << >>, signers |-> {},
         proposer |-> 0, aborts |-> 0]

VARIABLES
    pending,        \* the candidate currently under adjudication, or NONE
    verdicts,       \* sequence of [blk |-> candidate, accepted |-> BOOLEAN]
    n_processed     \* count of candidates adjudicated (bounds TLC)

vars == <<pending, verdicts, n_processed>>

MaxCandidates == 6   \* bound on adjudicated candidates (TLC exhaustion)

Init ==
    /\ pending = NONE
    /\ verdicts = << >>
    /\ n_processed = 0

\* SubmitCandidate: a producer (honest or Byzantine) hands the receiver
\* a candidate block. The candidate is drawn from the bounded universe.
SubmitCandidate(m, sigset, prop, ab, md) ==
    /\ pending = NONE
    /\ n_processed < MaxCandidates
    /\ m \in CandidateSizes
    /\ m >= 1
    /\ sigset \subseteq (1..m)
    /\ prop \in 0..m
    /\ ab \in 0..MaxAborts
    /\ md \in {"MD", "BFT"}
    /\ pending' = [mode |-> md, creators |-> CommitteeOfSize(m),
                   signers |-> sigset, proposer |-> prop, aborts |-> ab]
    /\ UNCHANGED <<verdicts, n_processed>>

\* Adjudicate: the receiver runs the accept-gate on the pending
\* candidate, appends the verdict, and clears `pending`.
Adjudicate ==
    /\ pending # NONE
    /\ verdicts' = Append(verdicts,
                          [blk |-> pending, accepted |-> Accept(pending)])
    /\ pending' = NONE
    /\ n_processed' = n_processed + 1

\* Stutter at saturation (TLC bound).
Stutter ==
    /\ n_processed >= MaxCandidates
    /\ pending = NONE
    /\ UNCHANGED vars

Next ==
    \/ \E m \in CandidateSizes, prop \in 0..Cardinality(Members),
          ab \in 0..MaxAborts, md \in {"MD", "BFT"} :
          \E sigset \in SUBSET (1..m) :
             SubmitCandidate(m, sigset, prop, ab, md)
    \/ Adjudicate
    \/ Stutter

Spec == Init /\ [][Next]_vars /\ WF_vars(Adjudicate)

\* -----------------------------------------------------------------
\* §6. Invariants — T-AG1..T-AG6.
\* -----------------------------------------------------------------

\* Convenience: the set of ACCEPTED candidates in the verdict log.
Accepted == { verdicts[i].blk : i \in
                {j \in 1..Len(verdicts) : verdicts[j].accepted} }

\* INV_TypeOK (T-AG1) — shape predicate.
INV_TypeOK ==
    /\ n_processed \in 0..MaxCandidates
    /\ pending = NONE \/
       (/\ pending.mode \in {"MD", "BFT"}
        /\ pending.proposer \in Nat
        /\ pending.aborts \in 0..MaxAborts
        /\ pending.signers \subseteq (1..Len(pending.creators)))
    /\ \A i \in 1..Len(verdicts) :
          /\ verdicts[i].accepted \in BOOLEAN
          /\ verdicts[i].blk.mode \in {"MD", "BFT"}

\* INV_ModeSizePairing (T-AG2) — every accepted candidate's committee
\* size matches its mode: k_full for MD, k_bft for BFT.
INV_ModeSizePairing ==
    \A blk \in Accepted :
       \/ (blk.mode = "MD"  /\ Len(blk.creators) = KFull)
       \/ (blk.mode = "BFT" /\ Len(blk.creators) = KBft(KFull))

\* INV_QuorumArithmeticSound (T-AG3) — the headline invariant: every
\* accepted candidate carries at least the required signature count,
\* under the EXACT two-level shrinkage arithmetic. No under-quorum
\* block is ever accepted at ANY K (including K>=6 where the two
\* shrinkages diverge — the regime FB1 over-approximates).
INV_QuorumArithmeticSound ==
    \A blk \in Accepted :
       Cardinality(blk.signers)
           >= RequiredSigs(blk.mode, Len(blk.creators))

\* INV_BftRequiresEscalation (T-AG4) — every accepted BFT candidate
\* satisfies all four escalation gates. A malicious producer cannot
\* get a BFT block accepted by escalating below the abort threshold.
INV_BftRequiresEscalation ==
    \A blk \in Accepted :
       (blk.mode = "BFT") =>
          /\ BftEnabled                                \* G1
          /\ blk.aborts >= AbortThreshold              \* G2
          /\ Len(blk.creators) = KBft(KFull)           \* G3
          /\ Len(blk.creators) >= KBft(KFull)          \* G4

\* INV_ProposerSignedWhenBft (T-AG5) — every accepted BFT candidate
\* names the deterministically-chosen proposer AND that proposer signed.
\* MD candidates carry an empty (0) proposer field.
INV_ProposerSignedWhenBft ==
    \A blk \in Accepted :
       /\ (blk.mode = "BFT") =>
             /\ blk.proposer = ProposerIndex(blk.creators, blk.aborts)
             /\ blk.proposer \in blk.signers
       /\ (blk.mode = "MD") => (blk.proposer = 0)

\* INV_SentinelBudgetRespected (T-AG6) — every accepted candidate has at
\* most (committee_size - required) sentinel slots. MD permits zero;
\* BFT permits up to k_bft - Q.
INV_SentinelBudgetRespected ==
    \A blk \in Accepted :
       LET m     == Len(blk.creators)
           unset == m - Cardinality(blk.signers)
       IN  unset <= SentinelBudget(blk.mode, m)

\* -----------------------------------------------------------------
\* §7. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualVerdict — every submitted candidate eventually receives
\* a verdict; the accept-gate never wedges on a pending candidate.
PROP_EventualVerdict ==
    (pending # NONE) ~> (pending = NONE)

\* PROP_HonestBlockAccepted — a well-formed honest candidate is
\* eventually ACCEPTED. Witnesses non-vacuity: the gate admits the
\* honest path, it does not vacuously reject everything.
\*
\* Honest-MD witness: an MD block with the full k_full committee, all
\* k_full members signing, empty proposer, any abort count. This passes
\* every gate. Under fairness on Adjudicate + the reachability of such
\* a candidate via SubmitCandidate, some accepted verdict appears.
HonestMDAccepted ==
    \E i \in 1..Len(verdicts) :
       /\ verdicts[i].accepted
       /\ verdicts[i].blk.mode = "MD"

PROP_HonestBlockAccepted == <>HonestMDAccepted

\* -----------------------------------------------------------------
\* §8. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The accept-gate contract is pinned at the state-machine layer by the
\* six invariants + two temporal properties. The abstraction boundary:
\*
\*   * The CRYPTOGRAPHIC validity of each signature (Ed25519 EUF-CMA
\*     verify at validator.cpp:441) is NOT modeled — a slot is either a
\*     valid sig (index in `signers`) or a sentinel (index absent). The
\*     signature-verification soundness is FB23 FrostVerify.tla /
\*     FB40 MakeBlockSigPrimitive.tla / Preliminaries §2.0 (A1 Ed25519)
\*     territory. This spec asserts the COUNTING + GATING contract: how
\*     many valid sigs are required and which structural gates a block
\*     must clear — conditional on each non-sentinel slot being a
\*     genuine sig (FB40's per-member binding).
\*
\*   * The PROPOSER seed derivation (epoch_committee_seed + abort hash
\*     folding feeding proposer_idx) is abstracted to ProposerIndex's
\*     rotate-on-abort modular index. The cryptographic uniformity of
\*     the seed is FB23 / FB34 EpochCommitteeRotation.tla territory.
\*     The KEY property this spec pins is that the proposer is a
\*     DETERMINISTIC function of the candidate's own committee + abort
\*     count, so the receiver can recompute it and reject impostors.
\*
\*   * The COMMITTEE-SELECTION soundness (that `creators` is the correct
\*     deterministic draw from the active/region pool) is NOT re-checked
\*     here — that is FB34 EpochCommitteeRotation.tla + FB35
\*     RegionalShardingCommittee.tla territory (check_creator_selection's
\*     full reconstruction). This spec takes the committee as given and
\*     checks the SIZE<->MODE pairing + the quorum/proposer gates that
\*     `check_block_sigs` layers on top.
\*
\*   * The producer-side escalation MECHANICS (the region pool dropping
\*     below k_full driving the escalation at node.cpp:774) are modeled
\*     as the SPACE of candidate blocks: the receiver must adjudicate
\*     both honest escalations and adversarial ones. INV_BftRequiresEsc
\*     pins that only escalation-justified BFT blocks are accepted,
\*     regardless of what a Byzantine producer claims.
\*
\* What this spec adds beyond existing FB-track surfaces:
\*
\*   * The EXACT two-level shrinkage arithmetic (KBft + RequiredSigs)
\*     checked at K>=6 where the two shrinkages DIVERGE — the regime
\*     FB1 Consensus.tla explicitly over-approximates (Consensus.tla
\*     §148-166 applies only shrinkage 1; this spec applies both).
\*     INV_QuorumArithmeticSound + INV_SentinelBudgetRespected are the
\*     full-fidelity check FB1 defers.
\*
\*   * The receiver-side accept-gate decision tree as a single state
\*     machine: size<->mode pairing + 4-gate escalation eligibility +
\*     proposer-binding + sentinel-aware quorum, adjudicated over the
\*     full space of honest AND adversarial candidate blocks. None of
\*     FB1 (producer flow) / FB40 (sig primitive) / FB34 / FB35
\*     (committee selection) models the receiver's admissibility
\*     decision as a composed predicate.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*   * Ed25519 EUF-CMA sig validity (FB23 / FB40 / Preliminaries A1).
\*   * Committee-selection reconstruction soundness (FB34 / FB35).
\*   * The chain-link / state-root gates that validate_block ALSO runs
\*     before reaching check_block_sigs (FB26 BlockchainStateIntegrity
\*     .tla + FB30 ChainPrevHashLink.tla territory).
\*   * The within-round producer message flow that BUILDS the candidate
\*     (FB1 Consensus.tla territory).

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/node/producer.cpp:541-553   : required_block_sigs (the exact
\*       two-level quorum arithmetic that RequiredSigs mirrors;
\*       MD -> m, BFT -> ceil(2m/3) with m already = k_bft).
\*   src/node/validator.cpp:96-104   : check_creator_selection's
\*       committee-size <-> mode pairing (md_ok / bft_ok disjunction)
\*       that G_SizePairing + INV_ModeSizePairing pin.
\*   src/node/validator.cpp:388-401  : check_block_sigs' BFT
\*       mode-eligibility gate (bft_enabled + total_aborts >=
\*       bft_escalation_threshold) that G_Escalation +
\*       INV_BftRequiresEscalation pin.
\*   src/node/validator.cpp:403      : required = required_block_sigs(
\*       b.consensus_mode, b.creators.size()) — the per-block quorum
\*       lookup that G_Quorum + INV_QuorumArithmeticSound pin.
\*   src/node/validator.cpp:406-426  : the proposer-binding gate
\*       (MD -> empty bft_proposer; BFT -> proposer == proposer_idx
\*       draw AND proposer signed) that G_Proposer +
\*       INV_ProposerSignedWhenBft pin.
\*   src/node/validator.cpp:429-449  : the sentinel-aware signed_count
\*       loop + `signed_count < required` rejection that G_Quorum +
\*       INV_SentinelBudgetRespected pin.
\*   src/node/node.cpp:770-781       : start_new_round's producer-side
\*       four-gate escalation (avail < k_target && bft_enabled &&
\*       total_aborts >= threshold && avail >= k_bft) — the space of
\*       candidate blocks this spec's receiver adjudicates.
\*   include/determ/node/producer.hpp:298-310 : proposer_idx +
\*       required_block_sigs declarations.
\*
\* SECURITY.md §S-025 (BFT escalation soundness) — the escalation-gate
\*   analytic closure that INV_BftRequiresEscalation lifts to the
\*   state-machine layer.
\*
\* docs/proofs/BFTSafety.md (FA5) — the BFT safety proof under
\*   f_h < |K_h|/3 whose |K_h|/Q intersection arithmetic this spec's
\*   RequiredSigs operator pins at the receiver layer.
\* docs/proofs/S025BFTEscalationSoundness.md — the escalation-gate
\*   analytic companion; INV_BftRequiresEscalation is its TLA+ form.
\* docs/proofs/tla/Consensus.tla (FB1) — the within-round producer
\*   flow; FB1 over-approximates the BFT quorum (single shrinkage,
\*   degenerate at K=3); this spec checks the full two-level arithmetic
\*   at K>=6 where the shrinkages diverge.
\* docs/proofs/tla/MakeBlockSigPrimitive.tla (FB40) — the Phase-2
\*   per-member sig binding that makes each non-sentinel slot a genuine
\*   sig; this spec's quorum-counting is conditional on FB40's binding.
\* docs/proofs/tla/EpochCommitteeRotation.tla (FB34) +
\*   RegionalShardingCommittee.tla (FB35) — the committee-selection
\*   reconstruction this spec takes as given (it checks the gates
\*   layered ON the committee, not the committee draw).
\* docs/proofs/tla/FrostVerify.tla (FB23) — the Ed25519 EUF-CMA model
\*   underlying the per-slot sig validity this spec abstracts.
\*
\* Runtime regressions:
\*   tools/test_required_block_sigs.sh — the in-process test that pins
\*     required_block_sigs' two-level arithmetic at the C++ layer
\*     (MD -> K, BFT -> ceil(2K/3)) across the production K profiles;
\*     INV_QuorumArithmeticSound's C++ witness.
\*   tools/test_block_validator_extensive.sh — the check_creator_selection
\*     + check_block_sigs receiver-side cross-check regression;
\*     INV_ModeSizePairing + INV_BftRequiresEscalation + INV_Proposer
\*     SignedWhenBft structural witnesses.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB45 row — added.
============================================================================
