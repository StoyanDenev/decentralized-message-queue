--------------------------- MODULE Consensus ---------------------------
(*
FB1 — TLA+ specification of Determ's per-height K-of-K consensus state
machine. Machine-checks the FA1 (Safety), FA3 (Selective-abort), and
FA4 (Liveness) properties at the level of round-by-round message flow.

This spec is intentionally a simplified projection of the real protocol:

  * One height at a time (round-by-round semantics within the height).
  * Validators are modeled as records of {state, contrib_sent, secret,
    sig_sent} — no actual cryptography is modeled; signatures and
    commit-reveal binding are abstracted as boolean predicates.
  * Aborts are modeled by an adversary action that drops messages or
    delays validators.
  * BFT escalation is captured as a mode-switch after N aborts, WITH the
    committee shrink the code performs: node.cpp start_new_round sets
    k_use = k_bft = ceil(2K/3) and only those members contribute/sign
    (V3 pins B.creators to that committee; V8 counts only their sigs).
    The model picks the shrunk committee nondeterministically per abort,
    over-approximating the code's deterministic seed-based selection.

What the model verifies (under TLC):

  * Safety (Inv_OneDigest):     at most one digest finalizes at the height.
  * Selective-abort (Inv_NoEarlyReveal): no honest validator reveals
    dh_secret before observing K phase-1 commits.
  * Liveness (Prop_Termination): under fair scheduling and at least one
    honest committee member, the height eventually finalizes.

The companion analytic proofs (FA1, FA3, FA4) give the cryptographic
soundness; the TLA+ spec gives the state-machine soundness.

To check (assuming TLC installed):
  $ tlc Consensus.tla -config Consensus.cfg

Recommended model: K = 3, F = 1 (one Byzantine), MAX_ROUNDS = 5.
State space is small enough to exhaust in seconds.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Validators,         \* set of committee members
    K,                  \* committee size = |Validators|
    Byzantine,          \* subset of Validators that may misbehave
    MaxRounds,          \* bound on rounds for TLC exhaustion
    BFTThreshold        \* round count after which mode switches to BFT

ASSUME ConfigOK ==
    /\ K = Cardinality(Validators)
    /\ Byzantine \subseteq Validators
    /\ Cardinality(Validators \ Byzantine) >= 1   \* FA1 standard hypothesis
    /\ MaxRounds \in Nat /\ MaxRounds >= 1
    /\ BFTThreshold \in Nat

Honest == Validators \ Byzantine

\* Validator local state in the consensus loop.
\* IDLE → CONTRIB (phase 1) → BLOCK_SIG (phase 2) → FINAL
States == {"IDLE", "CONTRIB", "BLOCK_SIG", "FINAL", "ABORTED"}

\* Consensus modes per FA5.
Modes == {"MD", "BFT"}

\* Digests are abstracted as integers; distinct integers = distinct blocks.
\* TLC will explore a small set.
Digests == 0..2

\* BFT-shrunk committee size k_bft = ceil(2K/3)
\* (include/determ/chain/params.hpp bft_committee_size).
KBft == (2*K + 2) \div 3

VARIABLES
    v_state,            \* function Validators → States
    contribs,           \* set of (validator, digest) phase-1 commits seen
    secrets_revealed,   \* set of validators who revealed dh_secret
    sigs,               \* function digest → set of validators signing it
    round,              \* current round (1..MaxRounds)
    mode,               \* current consensus mode
    committee,          \* active committee (Validators in MD; k_bft subset in BFT)
    finalized,          \* set of finalized digests at this height
    aborted_rounds      \* count of rounds that aborted

vars == <<v_state, contribs, secrets_revealed, sigs, round, mode,
          committee, finalized, aborted_rounds>>

----------------------------------------------------------------------------
\* Initial state: all validators IDLE, round 1, MD mode.

Init ==
    /\ v_state = [v \in Validators |-> "IDLE"]
    /\ contribs = {}
    /\ secrets_revealed = {}
    /\ sigs = [d \in Digests |-> {}]
    /\ round = 1
    /\ mode = "MD"
    /\ committee = Validators
    /\ finalized = {}
    /\ aborted_rounds = 0

----------------------------------------------------------------------------
\* Actions.

\* Honest validator v submits phase-1 commit for digest d. Only committee
\* members contribute (in BFT mode V3 pins B.creators to the shrunk
\* committee; non-members have no slot in the block).
\* Honest constraint: each honest v submits at most one (v, *) pair per round.
ContribHonest(v, d) ==
    /\ v \in Honest
    /\ v \in committee
    /\ v_state[v] = "IDLE"
    /\ ~ \E d2 \in Digests : <<v, d2>> \in contribs    \* H2: one commit
    /\ contribs' = contribs \cup {<<v, d>>}
    /\ v_state' = [v_state EXCEPT ![v] = "CONTRIB"]
    /\ UNCHANGED <<secrets_revealed, sigs, round, mode, committee,
                   finalized, aborted_rounds>>

\* Byzantine validator may equivocate: submit two distinct commits.
\* This action models the worst-case adversary in FA1's analytic proof.
\* Slashing (FA6) detects this, but the spec doesn't model slashing here —
\* the goal is to show that even with equivocation, the safety invariant
\* still holds because the quorum always contains an honest member.
ContribByzantine(v, d) ==
    /\ v \in Byzantine
    /\ v \in committee
    /\ v_state[v] \in {"IDLE", "CONTRIB"}
    /\ contribs' = contribs \cup {<<v, d>>}
    /\ v_state' = [v_state EXCEPT ![v] = "CONTRIB"]
    /\ UNCHANGED <<secrets_revealed, sigs, round, mode, committee,
                   finalized, aborted_rounds>>

\* Transition phase 1 → phase 2: a validator that has seen all committee
\* phase-1 commits proceeds to BLOCK_SIG (reveals secret, signs digest).
\* The "all commits seen" condition is the selective-abort defense (H3).
\* Threshold is the round's committee size: K in MD, k_bft in BFT (block
\* assembly needs every creator slot filled; only phase-2 sigs may be
\* sentinel-zero in BFT — validator.cpp check_block_sigs).
SeenKCommits ==
    Cardinality({v \in committee : \E d \in Digests : <<v, d>> \in contribs})
        >= Cardinality(committee)

EnterBlockSig(v) ==
    /\ v_state[v] = "CONTRIB"
    /\ SeenKCommits
    /\ v_state' = [v_state EXCEPT ![v] = "BLOCK_SIG"]
    /\ secrets_revealed' = secrets_revealed \cup {v}
    /\ UNCHANGED <<contribs, sigs, round, mode, committee,
                   finalized, aborted_rounds>>

\* The digest honest validators sign. In the code the block digest is
\* compute_block_digest (producer.cpp ~L619) over the ASSEMBLED block —
\* a deterministic function of the round's contrib set — not a per-
\* validator vote. CHOOSE models that: an arbitrary-but-fixed function
\* of the current contrib set.
ContribDigests == {d \in Digests : \E v \in Validators : <<v, d>> \in contribs}
AssembledDigest == CHOOSE d \in ContribDigests : TRUE

\* Validator v signs digest d (phase 2). Honest v signs the assembled
\* digest, and at most one digest per (height, round) — H2(a),
\* Preliminaries.md §4.
SignHonest(v, d) ==
    /\ v \in Honest
    /\ v_state[v] = "BLOCK_SIG"
    /\ d = AssembledDigest
    /\ ~ \E d2 \in Digests : v \in sigs[d2]            \* H2: one digest
    /\ sigs' = [sigs EXCEPT ![d] = sigs[d] \cup {v}]
    /\ UNCHANGED <<v_state, contribs, secrets_revealed, round, mode,
                   committee, finalized, aborted_rounds>>

\* Byzantine v may sign any digest in phase 2.
SignByzantine(v, d) ==
    /\ v \in Byzantine
    /\ v_state[v] = "BLOCK_SIG"
    /\ sigs' = [sigs EXCEPT ![d] = sigs[d] \cup {v}]
    /\ UNCHANGED <<v_state, contribs, secrets_revealed, round, mode,
                   committee, finalized, aborted_rounds>>

\* Finalize: digest d has K signatures (MD) or Q signatures (BFT mode).
\*
\* In BFT mode the protocol applies TWO levels of shrinkage, and BOTH are
\* load-bearing for safety (FA5 / BFTSafety.md L-5.1):
\*   (1) the COMMITTEE shrinks to k_bft = ceil(2K/3) members — modeled by
\*       the `committee` variable (node.cpp start_new_round ~L778 sets
\*       k_use = k_bft; V3 pins B.creators to it);
\*   (2) Q = ceil(2*k_bft/3) sigs are required WITHIN that committee
\*       (producer.cpp required_block_sigs ~L583 — its committee_size
\*       argument is already the shrunk k_bft; validator.cpp
\*       check_block_sigs ~L432 counts only creators' sigs).
\* Quorums drawn from the SAME k_bft committee intersect in >= 2Q - k_bft
\* >= k_bft/3 members, so under FA5's B1 hypothesis (f_h < k_bft/3) an
\* honest member is in every two quorums and H2 forbids double-finalize.
\* Shrinking only the threshold over the full K validators (an earlier
\* revision of this spec) breaks exactly that intersection — at K=3 it
\* admits 2-of-3 quorums meeting only at a Byzantine node.
\*
\* Only committee members can reach BLOCK_SIG, so sigs[d] \subseteq
\* committee and a plain cardinality test matches the code's V8 count.
\*
\* The spec's BFTThreshold parameter is the abort count that triggers
\* escalation, not the post-escalation sig quorum.
Keff == IF mode = "BFT" THEN (2*Cardinality(committee) + 2) \div 3
                        ELSE Cardinality(committee)

Finalize(d) ==
    /\ Cardinality(sigs[d]) >= Keff
    /\ finalized' = finalized \cup {d}
    /\ v_state' = [v \in Validators |-> "FINAL"]
    /\ UNCHANGED <<contribs, secrets_revealed, sigs, round, mode,
                   committee, aborted_rounds>>

\* Abort: round times out without reaching SeenKCommits or quorum sigs.
\* Increments aborted_rounds and may escalate mode to BFT. On escalation
\* the committee shrinks to k_bft members; the code re-derives it
\* deterministically from the abort-adjusted seed each round
\* (node.cpp ~L791-808) — the model over-approximates with a
\* nondeterministic choice over all k_bft-subsets.
AbortRound ==
    /\ round < MaxRounds
    /\ finalized = {}
    /\ \/ ~SeenKCommits
       \/ \A d \in Digests : Cardinality(sigs[d]) < Keff
    /\ round' = round + 1
    /\ aborted_rounds' = aborted_rounds + 1
    /\ mode' = IF aborted_rounds + 1 >= BFTThreshold THEN "BFT" ELSE mode
    /\ IF aborted_rounds + 1 >= BFTThreshold
       THEN \E C \in SUBSET Validators :
                /\ Cardinality(C) = KBft
                /\ committee' = C
       ELSE committee' = Validators
    /\ v_state' = [v \in Validators |-> "IDLE"]
    /\ contribs' = {}
    /\ secrets_revealed' = {}
    /\ sigs' = [d \in Digests |-> {}]
    /\ UNCHANGED <<finalized>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E v \in Validators, d \in Digests : ContribHonest(v, d)
    \/ \E v \in Validators, d \in Digests : ContribByzantine(v, d)
    \/ \E v \in Validators : EnterBlockSig(v)
    \/ \E v \in Validators, d \in Digests : SignHonest(v, d)
    \/ \E v \in Validators, d \in Digests : SignByzantine(v, d)
    \/ \E d \in Digests : Finalize(d)
    \/ AbortRound

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

----------------------------------------------------------------------------
\* Invariants.

\* FA1 Safety: at most one finalized digest per height.
Inv_OneDigest == Cardinality(finalized) <= 1

\* FA3 Selective-abort: no validator reveals dh_secret before K commits seen.
Inv_NoEarlyReveal ==
    secrets_revealed = {} \/ SeenKCommits

\* FA6 Slashing soundness (state-machine analog): no honest validator
\* signs two distinct digests at this height.
Inv_HonestNoEquivocate ==
    \A v \in Honest : Cardinality({d \in Digests : v \in sigs[d]}) <= 1

\* Type invariant.
TypeOK ==
    /\ v_state \in [Validators -> States]
    /\ contribs \subseteq Validators \X Digests
    /\ secrets_revealed \subseteq Validators
    /\ sigs \in [Digests -> SUBSET Validators]
    /\ round \in 1..MaxRounds
    /\ mode \in Modes
    /\ committee \subseteq Validators
    /\ Cardinality(committee) = IF mode = "BFT" THEN KBft ELSE K
    /\ finalized \subseteq Digests
    /\ aborted_rounds \in Nat

----------------------------------------------------------------------------
\* Temporal properties.

\* FA4 Liveness: eventually the height finalizes (under fair scheduling).
Prop_Termination == <>(finalized /= {})

============================================================================
