------------------------- MODULE AbortEscalation -------------------------
(*
Companion spec to AbortCascadeLiveness.md (FB67) — TLA+
specification of the per-height round / abort / BFT-escalation state
machine in `src/node/node.cpp`. Both findings it was built to exhibit
are now MITIGATED (docs/SECURITY.md §S-044/§S-045); the shipped
AbortEscalation.cfg now models the FIX (all invariants EXPECTED TO
HOLD), and the pre-fix defect configuration is retained as the
E1-historical regression reference. The two findings and the shipped
fix:

  * S-044 (was High) — K=2 committees wedged permanently under timing
    skew: the abort-claim quorum at K=2 was K-1 = 1, so a single
    straggle excluded a member with ONE claim; exclusions accumulated
    (current_aborts_ clears ONLY on block accept, node.cpp:1856) until
    the eligible pool fell below K, and check_if_selected silently
    returns forever (node.cpp:788). BFT escalation could not rescue K=2
    because k_bft = ceil(2K/3) = 2 = K — no committee shrink.
    FIX (F-a): the quorum is now max(2, K-1) via chain::abort_claim_quorum
    — unsatisfiable at K=2, so no single-claim abort forms (crash-stop,
    modeled by QuorumFloor=2). Also PROFILE_WEB retuned M=3/K=2 -> M=4/K=3.
  * S-045 (was High, upgraded from Medium) — BFT escalation unreachable
    at the historical genesis-default threshold 5: rounds generate abort
    events, so at M=K a single dead member's counter ceiling K-1 froze
    below 5 forever. FIX: the genesis default threshold is now 1
    (include/determ/chain/genesis.hpp) — reached by the first abort event,
    so the counter never freezes below it (modeled by BftThreshold=1).

STATUS: written, model-check pending (TLC unavailable in this
environment). The spec is ready-to-check:
  $ java -jar tla2tools.jar -config AbortEscalation.cfg AbortEscalation.tla
The shipped AbortEscalation.cfg is now the PRIMARY SHIPPED-FIX exhibit
(F-a QuorumFloor=2 + θ BftThreshold=1 on the M=K=3 stress posture);
its invariants are EXPECTED TO HOLD and the liveness property EXPECTED
TO HOLD — the fix removes the wedge. The pre-fix wedge configuration is
E1-historical below (invariants EXPECTED TO FAIL — the defect the fix
removes). Alternate configurations E2-E7 remain tabulated below.

--------------------------------------------------------------------------
Code anchors (each verified against src/ at spec-writing time):

  * node.cpp:756        k_target = cfg_.k_block_sigs (MD committee size).
  * node.cpp:762-768    excluded := {ae.aborting_node : ae in
                        current_aborts_}; avail_domains := pool \ excluded.
  * node.cpp:777        total_aborts = current_aborts_.size()  — an EVENT
                        count, not a distinct-member count.
  * node.cpp:778        k_bft = (2*K + 2) / 3   (integer ceil(2K/3)).
  * node.cpp:781-787    the escalation conjunction (modeled by Escalate).
  * node.cpp:788        `if (avail < k_use) return;` — the silent
                        return (modeled by Stall). NOTE: this returns
                        BEFORE node.cpp:806-808 reassigns
                        current_creator_domains_, so the LAST formed
                        committee persists through the stall — which is
                        why further abort events against other members
                        of that committee can still validate and be
                        adopted after formation already failed
                        (RoundStraggle does not require roundActive).
  * node.cpp:1180-1198  phase-1 timeout emits an AbortClaimMsg against
                        the first missing committee member;
                        node.cpp:1218-1236 is the phase-2 sibling.
  * node.cpp:1274-1277  claim quorum in on_abort_claim: needed =
                        current_creator_domains_.size() - 1.
  * node.cpp:1280-1295  AbortEvent assembly: event_hash binds the LOCAL
                        wall-clock ts (compute_abort_hash /
                        chain_abort_hash append `timestamp`,
                        src/crypto/random.cpp:102-120), so two nodes
                        assembling the same quorum produce events with
                        DISTINCT hashes.
  * node.cpp:1321-1323  on_abort_event dedups by event_hash ONLY —
                        therefore each peer's locally-built event for
                        the SAME straggle is adopted as a separate
                        current_aborts_ entry (DuplicateAbortAdoption).
                        This is the only channel by which total_aborts
                        exceeds the distinct-member count.
  * node.cpp:1329-1331 + node.cpp:1354  the K-1 claim-quorum validation
                        on adoption (needed = committee size - 1;
                        claimers must be committee members != the
                        accused, node.cpp:1340-1344).
  * node.cpp:1856       the SOLE current_aborts_.clear() site — on block
                        accept. No decay, no expiry, no retry.
  * node.cpp:2113-2116  the aborts_gen gate: contribs whose generation
                        != current_aborts_.size() are dropped. This is
                        the cascade DRIVER in S-044 (transient gen
                        desync makes the next member look silent); the
                        spec abstracts it into the SkewStraggle
                        nondeterminism rather than modeling per-peer
                        generation vectors.
  * include/determ/chain/params.hpp  PROFILE_WEB now M=4/K=3 (the
                        `determ init` DEFAULT; retuned from the pre-fix
                        M=3/K=2 exposed posture by the S-044/S-045 fix);
                        regional M=5/K=4; cluster
                        M=K=3; :178-181 tactical M=K=3; :216-220
                        web_test mirrors 3/2.
  * include/determ/chain/genesis.hpp:145  bft_escalation_threshold{5}
                        genesis default.

Empirical anchors:
  * tools/test_web_hybrid.sh:118-129 and
    tools/test_regional_shards.sh:154-162 carry KNOWN-BUG S-044 notes
    (sustained K=2 production bars suspended until S-044 closes).
  * tools/test_weak_3node.sh:7-19 documents the observed live cascade
    (K=2 forms wedge even at 2000 ms timers; K=3 quorum = 2 claims is
    immune to single straggles).
  * tools/test_bft_escalation.sh is the GREEN single-dead-member
    escalation case — its genesis pins bft_escalation_threshold=1
    (tools/test_bft_escalation.sh:84; the header comment's
    "threshold=2" is stale). Exhibit E3 must NOT violate liveness —
    the sanity pin that this model matches the green test.

--------------------------------------------------------------------------
Derived facts the model encodes (verify in the proofs before relying
on them; both follow from the anchors above):

  * WEDGE CONDITION: |distinct aborted members| > pool - k_use blocks
    all round formation at the height (avail < k_use at node.cpp:788).
    Since aborted members accumulate monotonically within a height
    (sole clear at node.cpp:1856 requires a block accept, which
    requires formation), crossing the wedge condition with escalation
    unreachable is PERMANENT.
  * ESCALATION REACHABILITY: the BFT branch is reachable iff aborts
    concentrate on <= pool - k_bft distinct members (so avail >= k_bft
    survives) for long enough that total_aborts (events, including
    per-peer duplicate adoptions) reaches bft_escalation_threshold.
  * K=2 SPECIAL CASE: k_bft = (2*2+2)/3 = 2 = K — zero escalation
    headroom; AND claim quorum = K-1 = 1, so every straggle is an
    immediate exclusion. Both halves of S-044.
  * COUNTER CEILING: with no rounds running, the only counter growth
    is duplicate adoption, bounded by (1 + DupBound) events per
    aborted member (DupBound = number of OTHER live nodes that
    independently assemble the same claim quorum, each building a
    distinct-timestamp event). If
    |aborted| * (1 + DupBound) < BftThreshold and no further straggle
    can land, the counter is frozen below the threshold forever — the
    S-045 deadlock.

--------------------------------------------------------------------------
Exhibit configurations (CONSTANTS -> expected TLC verdicts).
E1 ships as AbortEscalation.cfg; E2-E7 are one-line .cfg edits.

  E1  PRIMARY S-044 web-profile wedge  (Pool={n1,n2,n3}, K=2,
      QuorumFloor=1, SkewStraggle=TRUE, Dead={}, BftThreshold=5,
      no fix toggles):
        Inv_NoPermanentWedge   EXPECTED FALSIFIED (cascade: two
                               single-claim straggles -> avail=1 <
                               k_bft=2 -> wedge);
        Inv_NoFrozenCounter    EXPECTED FALSIFIED (avail=1 < k_bft=2,
                               totalAborts <= 4 < 5 — the K=2 instance
                               of S-045, subsumed per SECURITY.md:1316);
        Prop_ProgressEventually EXPECTED VIOLATED (fair lasso stalls
                               at the wedge forever).
  E2  S-045 M=K=3 two-distinct-abort halt  (K=3, BftThreshold=5,
      SkewStraggle=TRUE, Dead={}):
        Inv_NoFrozenCounter    EXPECTED FALSIFIED (two distinct
                               straggles from the SAME persisted
                               committee -> avail=1 < k_bft=2,
                               totalAborts frozen <= 4 < 5);
        Prop_ProgressEventually EXPECTED VIOLATED.
  E3  GREEN single-dead-member escalation (test_bft_escalation.sh):
      K=3, Dead={n3}, SkewStraggle=FALSE, BftThreshold=1 (the test
      genesis value, tools/test_bft_escalation.sh:84):
        ALL invariants EXPECTED TO HOLD;
        Prop_ProgressEventually EXPECTED TO HOLD (straggle vs n3 ->
        totalAborts=1 >= 1, avail=2 >= k_bft=2 -> Escalate -> BFT
        round over {n1,n2} succeeds; repeats every height). This is
        the sanity pin against the green cluster test.
  E4  Fix F-a (abort-claim quorum floor max(2, K-1)) re-check of E1:
      E1 + QuorumFloor=2:
        ALL invariants + liveness EXPECTED TO HOLD — at |committee|=2
        the available claimers (1) can never meet max(2,1)=2, so no
        single-straggle exclusion exists; K >= 3 behavior unchanged
        (max(2, K-1) = K-1).
        CAVEAT the model surfaces honestly: F-a at K=2 with a truly
        DEAD member (run E4 with Dead={n3}) deadlocks in a hung round
        whenever the dead member is selected — it can be neither
        excluded nor waited out. That is the "degenerate but safe"
        trade-off named in SECURITY.md:1308; F-a fixes the TRANSIENT-
        skew wedge (S-044's actual failure mode), not dead-member
        liveness at K=2.
  E5  Fix F-b (wall-clock decay of current_aborts_) re-check of E1:
      E1 + AbortDecay=TRUE:
        Prop_ProgressEventually EXPECTED TO HOLD under the transient-
        skew assumption (straggleBudget bounds skew events per height;
        decay drains exclusions, formation resumes). The wedge-state
        invariants are qualified by the AbortDecay disjunct (a decayed
        wedge is not permanent). NOTE: decay alone does NOT rescue a
        permanently dead member (E5 + Dead#{} deadlocks at K=3 once
        the budget is spent) — compose with F-c (E7).
  E6  Fix F-c (count formation failures toward the threshold) re-check
      of E1: E1 + CountFormationFailures=TRUE:
        STILL WEDGED — Inv_NoPermanentWedge EXPECTED FALSIFIED and
        Prop_ProgressEventually EXPECTED VIOLATED, because at K=2 the
        escalation precondition avail >= k_bft = 2 = K has no headroom
        (node.cpp:778): once 2 distinct members are excluded, avail=1
        and no counter value helps. F-c alone cannot close S-044; it
        targets the S-045 frozen-counter subcase (E7).
  E7  Fix F-c rescue case (the S-045 single-member freeze at the
      GENESIS-DEFAULT threshold): K=3, Dead={n3}, SkewStraggle=FALSE,
      BftThreshold=5, CountFormationFailures=TRUE:
        Prop_ProgressEventually EXPECTED TO HOLD (formationFailures
        climbs to 5 under fairness; Escalate fires at avail=2 >=
        k_bft=2). WITHOUT the toggle this config freezes — the model's
        prediction that test_bft_escalation.sh is green ONLY because
        its genesis pins threshold=1: at the default threshold 5
        (genesis.hpp:145) a single dead member yields at most
        1 + DupBound events (2 in a 3-node cluster) < 5, an S-045
        instance.

--------------------------------------------------------------------------
Modeling scope and deliberate abstractions (TLC tractability):

  * ONE node's consensus-relevant view; gossip convergence on claims /
    events / generations is assumed (the aborts_gen drop gate at
    node.cpp:2113-2116 is abstracted into SkewStraggle nondeterminism).
  * No cryptography: claim signatures (Ed25519, verified at
    node.cpp:1349-1352) are sound by FA-track assumption; a "straggle"
    nondeterministically stands for any timing skew that yields a
    valid claim quorum against a live or dead member.
  * Committee selection (crypto::select_m_creators, node.cpp:803, with
    the epoch seed + abort-hash mixing at node.cpp:796-800) is replaced
    by nondeterministic choice of a k_use-subset of the available pool.
    This is OPTIMISTIC for liveness re-checks (the real epoch-stable
    seed can repeatedly pick the same committee within an epoch); a
    liveness VIOLATION in the model is therefore also a violation of
    the real system, while a liveness PASS additionally assumes the
    selection eventually varies (true across epochs).
  * abortEvents[m] is the per-member entry count in current_aborts_;
    the spec-level views are derived:
        aborted     == {m : abortEvents[m] > 0}     (the excluded set)
        totalAborts == sum over Pool of abortEvents (= current_aborts_.
                       size(), node.cpp:777 — the escalation counter)
    DuplicateAbortAdoption is capped at 1 + DupBound entries per
    member, mirroring the distinct-timestamp adoption channel.
  * straggleBudget bounds skew events per height ("transient skew").
    Without it, decay configs (E5) admit fair straggle/decay livelocks
    that say nothing about the fix; the budget is the standard
    finitely-many-faults liveness hypothesis and resets on block
    accept. The S-044/S-045 exhibits stay within the budget — the
    wedge needs only 2 straggles.
  * One height's abort state is modeled exactly; height is a counter
    driving the liveness property. Post-accept stale abort events are
    out of scope (rejected by the block_index/prev_hash gates at
    node.cpp:1316-1318), which is why RoundSuccess may reset committee
    to {} even though current_creator_domains_ physically persists.
*)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Pool,                   \* validator set (eligible registry pool at the height)
    K,                      \* MD committee size = cfg_.k_block_sigs (node.cpp:756)
    BftEnabled,             \* BOOLEAN — cfg_.bft_enabled (node.cpp:782)
    BftThreshold,           \* cfg_.bft_escalation_threshold (node.cpp:783;
                            \* genesis default 5, genesis.hpp:145)
    Dead,                   \* subset of Pool that never delivers (crashed) —
                            \* a round whose committee intersects Dead cannot
                            \* succeed, and Dead members may always straggle.
                            \* {} for pure-skew configs (E1/E2), {n3} for the
                            \* green test_bft_escalation.sh posture (E3/E7).
    SkewStraggle,           \* BOOLEAN — when TRUE, ANY live committee member
                            \* may transiently straggle (timing skew / S-044's
                            \* aborts_gen desync, node.cpp:2113-2116). The
                            \* round retains the option to succeed — skew is
                            \* transient, which is exactly why converting it
                            \* into permanent exclusion is the bug.
    QuorumFloor,            \* FIX TOGGLE (F-a): needed abort claims =
                            \* max(QuorumFloor, committeeSize - 1).
                            \* QuorumFloor = 1 reproduces current behavior
                            \* (needed = size - 1, node.cpp:1329-1331);
                            \* QuorumFloor = 2 is candidate fix (a)
                            \* max(2, K-1) from SECURITY.md:1308.
    AbortDecay,             \* FIX TOGGLE (F-b): BOOLEAN — wall-clock decay /
                            \* expiry of current_aborts_ entries (enables
                            \* DecayAbort).
    CountFormationFailures, \* FIX TOGGLE (F-c): BOOLEAN — failed committee-
                            \* formation attempts count toward
                            \* bft_escalation_threshold (enables
                            \* FormationFailure; folds into effectiveAborts).
    DupBound,               \* max ADDITIONAL current_aborts_ entries per
                            \* aborted member from cross-peer adoption of
                            \* distinct-timestamp AbortEvents (node.cpp:
                            \* 1280-1295 + 1321-1323). Physical value =
                            \* count of OTHER live nodes assembling the same
                            \* quorum; 1 for a 3-node cluster.
    MaxStraggles,           \* per-height skew-event budget (straggles +
                            \* duplicate adoptions) — the transient-skew
                            \* liveness hypothesis; resets on block accept.
    MaxHeight               \* height bound for TLC exhaustion.

ASSUME ConfigOK ==
    /\ IsFiniteSet(Pool) /\ Cardinality(Pool) >= 2
    /\ K \in Nat /\ K >= 2 /\ K <= Cardinality(Pool)
    /\ BftEnabled \in BOOLEAN
    /\ BftThreshold \in Nat /\ BftThreshold >= 1
    /\ Dead \subseteq Pool
    /\ SkewStraggle \in BOOLEAN
    /\ QuorumFloor \in Nat /\ QuorumFloor >= 1
    /\ AbortDecay \in BOOLEAN
    /\ CountFormationFailures \in BOOLEAN
    /\ DupBound \in Nat
    /\ MaxStraggles \in Nat /\ MaxStraggles >= 2
    /\ MaxHeight \in Nat /\ MaxHeight >= 1

MaxNat(a, b) == IF a > b THEN a ELSE b

\* k_bft = ceil(2K/3) via the exact integer form at node.cpp:778.
\* K=2 -> 2 (= K, zero headroom); K=3 -> 2; K=4 -> 3; K=6 -> 4.
kBft == (2 * K + 2) \div 3

----------------------------------------------------------------------------
\* State.

VARIABLES
    height,             \* blocks accepted so far (liveness driver)
    abortEvents,        \* [Pool -> Nat]: per-member current_aborts_ entry
                        \* count. aborted/totalAborts are derived below.
    formationFailures,  \* F-c counter of failed formation attempts
                        \* (always 0 unless CountFormationFailures)
    roundActive,        \* TRUE while a formed round is in flight
    roundMode,          \* "NONE" / "MD" / "BFT" (chain::ConsensusMode)
    committee,          \* current_creator_domains_ — PERSISTS after a
                        \* straggle ends the round (node.cpp:788 returns
                        \* before node.cpp:806-808 reassigns), enabling
                        \* further same-committee abort adoptions.
    straggleBudget      \* remaining skew events at this height

vars == <<height, abortEvents, formationFailures, roundActive, roundMode,
          committee, straggleBudget>>

\* Derived views (the task-level "aborted" and "totalAborts" variables).
aborted  == {m \in Pool : abortEvents[m] > 0}
availSet == Pool \ aborted                          \* node.cpp:762-768
avail    == Cardinality(availSet)

RECURSIVE SumEvents(_)
SumEvents(S) ==
    IF S = {} THEN 0
    ELSE LET m == CHOOSE x \in S : TRUE
         IN  abortEvents[m] + SumEvents(S \ {m})

totalAborts == SumEvents(Pool)                      \* node.cpp:777

\* F-c: the escalation counter the gate compares against the threshold.
effectiveAborts ==
    totalAborts + (IF CountFormationFailures THEN formationFailures ELSE 0)

\* The four-conjunct escalation gate, node.cpp:781-784 (with the F-c
\* counter substitution when the toggle is on).
EscalationGate ==
    /\ avail < K                                    \* node.cpp:781
    /\ BftEnabled                                   \* node.cpp:782
    /\ effectiveAborts >= BftThreshold              \* node.cpp:783
    /\ avail >= kBft                                \* node.cpp:784

\* Who may straggle: dead members always look silent; under skew, any
\* live member can transiently look silent (gen desync / late contrib).
MayStraggle(m) == m \in Dead \/ SkewStraggle

\* Abort-claim quorum: needed = max(QuorumFloor, committeeSize - 1);
\* QuorumFloor = 1 collapses to the shipped needed = size - 1
\* (node.cpp:1274-1277 build side, node.cpp:1329-1331 + 1354 verify
\* side). Available claimers = committee members other than the accused
\* (node.cpp:1340-1344), all live-or-signed-before-dying in the worst
\* case = committeeSize - 1. Quorum reachable iff that meets needed.
\* Only evaluated under m \in committee (committee # {}).
NeededClaims        == MaxNat(QuorumFloor, Cardinality(committee) - 1)
ClaimQuorumReachable == Cardinality(committee) - 1 >= NeededClaims

----------------------------------------------------------------------------
\* Initial state.

Init ==
    /\ height            = 0
    /\ abortEvents       = [m \in Pool |-> 0]
    /\ formationFailures = 0
    /\ roundActive       = FALSE
    /\ roundMode         = "NONE"
    /\ committee         = {}
    /\ straggleBudget    = MaxStraggles

----------------------------------------------------------------------------
\* Actions.

\* StartRoundMD: ordinary K-of-K formation (avail >= k_target). The
\* committee is any K-subset of the available pool — nondeterminism
\* over-approximates select_m_creators (node.cpp:796-808).
StartRoundMD ==
    /\ ~roundActive
    /\ height < MaxHeight
    /\ avail >= K
    /\ \E c \in SUBSET availSet :
          /\ Cardinality(c) = K
          /\ committee' = c
    /\ roundActive' = TRUE
    /\ roundMode'   = "MD"
    /\ UNCHANGED <<height, abortEvents, formationFailures, straggleBudget>>

\* Escalate: the rev.8 BFT branch — fires exactly when the four-conjunct
\* gate (node.cpp:781-784) holds, shrinking the committee to k_bft and
\* running the round in BFT mode (node.cpp:785-786).
Escalate ==
    /\ ~roundActive
    /\ height < MaxHeight
    /\ EscalationGate
    /\ \E c \in SUBSET availSet :
          /\ Cardinality(c) = kBft
          /\ committee' = c
    /\ roundActive' = TRUE
    /\ roundMode'   = "BFT"
    /\ UNCHANGED <<height, abortEvents, formationFailures, straggleBudget>>

\* RoundSuccess: the round finalizes a block. Requires every committee
\* member able to deliver (no dead member). On accept: current_aborts_
\* clears (node.cpp:1856 — the SOLE clear site), the F-c counter would
\* reset with it, and the per-height skew budget renews. committee is
\* reset to {} as hygiene: stale abort events against the old committee
\* at the new height fail the block_index/prev_hash gates
\* (node.cpp:1316-1318), so the physical persistence of
\* current_creator_domains_ past an accept is unreachable dead state.
RoundSuccess ==
    /\ roundActive
    /\ committee \cap Dead = {}
    /\ height'            = height + 1
    /\ abortEvents'       = [m \in Pool |-> 0]      \* node.cpp:1856
    /\ formationFailures' = 0
    /\ straggleBudget'    = MaxStraggles
    /\ roundActive'       = FALSE
    /\ roundMode'         = "NONE"
    /\ committee'         = {}

\* RoundStraggle(m): committee member m gets abort-quorumed — the
\* phase-1/phase-2 timeout claims (node.cpp:1180-1198 / 1218-1236)
\* reach the claim quorum and an AbortEvent lands (locally built at
\* node.cpp:1280-1295 or adopted at node.cpp:1357). Guards:
\*   - m \in committee: claims validate only against
\*     current_creator_domains_ (node.cpp:1342-1344). roundActive is
\*     NOT required — the committee persists after a stall
\*     (node.cpp:788 returns before reassignment), so a second
\*     distinct member of the same committee can still be quorumed
\*     after formation already failed. This is how S-045's
\*     "TWO distinct aborted members at one height" arises at M=K=3.
\*   - abortEvents[m] = 0: the FIRST event against m (duplicates go
\*     through DuplicateAbortAdoption).
\*   - MayStraggle(m): dead members always; live members only under
\*     SkewStraggle.
\*   - ClaimQuorumReachable: committeeSize - 1 available claimers must
\*     meet max(QuorumFloor, committeeSize - 1). At K=2 with
\*     QuorumFloor=1 a SINGLE claim suffices (the S-044 hair-trigger);
\*     with QuorumFloor=2 (fix F-a) this guard is unsatisfiable at
\*     committee size 2 and unchanged at size >= 3.
\* Effect: m joins the excluded set; the round aborts
\* (reset_round + check_if_selected, node.cpp:1308-1309 / 1361-1362).
RoundStraggle(m) ==
    /\ m \in committee
    /\ abortEvents[m] = 0
    /\ MayStraggle(m)
    /\ straggleBudget > 0
    /\ ClaimQuorumReachable
    /\ abortEvents'    = [abortEvents EXCEPT ![m] = 1]
    /\ straggleBudget' = straggleBudget - 1
    /\ roundActive'    = FALSE
    /\ roundMode'      = "NONE"
    /\ UNCHANGED <<height, formationFailures, committee>>

\* DuplicateAbortAdoption(m): adoption of ANOTHER peer's locally-built
\* AbortEvent for the SAME straggle. Each assembling node bakes its own
\* wall-clock into event_hash (node.cpp:1280-1285; compute_abort_hash /
\* chain_abort_hash append `timestamp`, src/crypto/random.cpp:102-120),
\* and on_abort_event dedups by event_hash only (node.cpp:1321-1323) —
\* so the events are all adopted, inflating total_aborts WITHOUT adding
\* a distinct excluded member. Capped at 1 + DupBound entries per
\* member (DupBound = other live assemblers). This is the only channel
\* by which the escalation counter exceeds |aborted|, and hence the
\* load-bearing step for any escalation whose threshold exceeds the
\* number of distinct excludable members.
DuplicateAbortAdoption(m) ==
    /\ abortEvents[m] >= 1
    /\ abortEvents[m] < 1 + DupBound
    /\ straggleBudget > 0
    /\ abortEvents'    = [abortEvents EXCEPT ![m] = @ + 1]
    /\ straggleBudget' = straggleBudget - 1
    /\ UNCHANGED <<height, formationFailures, roundActive, roundMode,
                   committee>>

\* Stall: the silent-return self-loop (node.cpp:788). Formation is
\* impossible and nothing in the shipped code path will retry — no
\* decay, no timer, sole clear unreachable. Modeled as an explicit
\* no-op transition so wedge states are self-looping rather than
\* TLC-deadlocked, letting the liveness checker produce the lasso
\* counterexample. Also covers the benign height = MaxHeight model
\* boundary.
Stall ==
    /\ \/ height = MaxHeight
       \/ /\ ~roundActive
          /\ avail < K
          /\ ~EscalationGate
    /\ UNCHANGED vars

\* DecayAbort(m) — FIX F-b (gated on AbortDecay): one current_aborts_
\* entry for m expires by wall clock. m rejoins the eligible pool when
\* its last entry expires. NOT shipped; consensus-critical
\* (SECURITY.md:1308 candidate (b)).
DecayAbort(m) ==
    /\ AbortDecay
    /\ abortEvents[m] > 0
    /\ abortEvents' = [abortEvents EXCEPT ![m] = @ - 1]
    /\ UNCHANGED <<height, formationFailures, roundActive, roundMode,
                   committee, straggleBudget>>

\* FormationFailure — FIX F-c (gated on CountFormationFailures): a
\* failed check_if_selected attempt increments a counter that feeds
\* effectiveAborts. Guarded on formation actually being impossible
\* right now (the would-be retry-timer tick observing the node.cpp:788
\* condition). Bounded by BftThreshold — beyond it the gate is already
\* satisfied. NOT shipped; consensus-critical (SECURITY.md:1308
\* candidate (c), composes with S-045 per SECURITY.md:1318).
FormationFailure ==
    /\ CountFormationFailures
    /\ ~roundActive
    /\ height < MaxHeight
    /\ avail < K
    /\ ~EscalationGate
    /\ formationFailures < BftThreshold
    /\ formationFailures' = formationFailures + 1
    /\ UNCHANGED <<height, abortEvents, roundActive, roundMode, committee,
                   straggleBudget>>

----------------------------------------------------------------------------
\* Next-state relation and fairness.

StraggleDead == \E m \in Dead : RoundStraggle(m)

Next ==
    \/ StartRoundMD
    \/ Escalate
    \/ RoundSuccess
    \/ \E m \in Pool : RoundStraggle(m)
    \/ \E m \in Pool : DuplicateAbortAdoption(m)
    \/ \E m \in Pool : DecayAbort(m)
    \/ FormationFailure
    \/ Stall

\* Fairness justification, action by action:
\*   - StartRoundMD / Escalate: check_if_selected runs on every abort
\*     quorum, adoption, and block accept (node.cpp:1309/1362/1945) —
\*     if formation is continuously possible it eventually happens.
\*   - RoundSuccess: a formed round whose members are all live
\*     eventually finalizes (messages eventually delivered). Straggles
\*     may preempt it (disabling it), which keeps adversarial cascade
\*     lassos fair — exactly the S-044 trace shape.
\*   - StraggleDead: a dead committee member deterministically times
\*     out (node.cpp:1180-1198) and the live majority's claims
\*     eventually quorum — the green test depends on this firing.
\*     Straggles against LIVE members are deliberately NOT fair:
\*     transient skew may or may not happen (adversarial choice).
\*   - DuplicateAbortAdoption: gossip eventually delivers the peers'
\*     broadcast AbortEvents (node.cpp:1306 -> 1357).
\*   - DecayAbort: wall-clock expiry eventually fires (F-b only).
\*   - FormationFailure: the fix's retry tick eventually fires (F-c).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(StartRoundMD)
    /\ WF_vars(Escalate)
    /\ WF_vars(RoundSuccess)
    /\ WF_vars(StraggleDead)
    /\ WF_vars(\E m \in Pool : DuplicateAbortAdoption(m))
    /\ WF_vars(\E m \in Pool : DecayAbort(m))
    /\ WF_vars(FormationFailure)

----------------------------------------------------------------------------
\* State predicates for the two findings.

\* Counter ceiling reachable at this height without any further
\* distinct-member straggle: every aborted member can contribute at
\* most 1 + DupBound entries; F-c adds up to BftThreshold formation
\* failures. Over-approximates the truly reachable counter (ignores
\* straggleBudget), which makes WedgeState below an UNDER-approximation
\* of wedged states — sound for the falsification direction (a TLC
\* counterexample is a real wedge).
MaxReachableCounter ==
    Cardinality(aborted) * (1 + DupBound)
    + (IF CountFormationFailures THEN BftThreshold ELSE 0)

\* No further straggle can enlarge the excluded set (and hence raise
\* the ceiling or shrink avail): every non-aborted member of the
\* persisted committee is either not straggle-able or the claim quorum
\* is structurally unreachable.
NoMoreStraggles ==
    \/ \A m \in committee \ aborted : ~MayStraggle(m)
    \/ ~ClaimQuorumReachable

\* THE S-044 WEDGE: MD formation is impossible now (avail < K) and the
\* BFT branch can never rescue — either the pool already fell below
\* k_bft (every future straggle only shrinks it further), or BFT is
\* off, or the counter ceiling sits below the threshold with no way to
\* raise it (NoMoreStraggles pins the ceiling: no further straggle can
\* add an aborted member, and with F-c on the ceiling already includes
\* the BftThreshold term, voiding the third case). Under current
\* semantics (AbortDecay = FALSE) this is PERMANENT: aborted is
\* monotone within the height (sole clear at node.cpp:1856 requires a
\* block accept, which requires formation).
WedgeState ==
    /\ avail < K
    /\ \/ ~BftEnabled
       \/ avail < kBft
       \/ /\ MaxReachableCounter < BftThreshold
          /\ NoMoreStraggles

\* THE S-045 FROZEN-COUNTER DEADLOCK: the pool fell below k_bft while
\* total_aborts is still below the threshold — no round can run, so
\* nothing can ever move the counter (only duplicate adoptions, capped
\* below the threshold in the exhibit configs), and escalation's
\* avail >= k_bft precondition is dead regardless.
FrozenCounterState ==
    /\ avail < kBft
    /\ totalAborts < BftThreshold

----------------------------------------------------------------------------
\* Invariants.

TypeOK ==
    /\ height            \in 0..MaxHeight
    /\ abortEvents       \in [Pool -> 0..(1 + DupBound)]
    /\ formationFailures \in 0..BftThreshold
    /\ roundActive       \in BOOLEAN
    /\ roundMode         \in {"NONE", "MD", "BFT"}
    /\ committee         \subseteq Pool
    /\ straggleBudget    \in 0..MaxStraggles

\* roundMode is exactly the round-in-flight discriminator.
Inv_ModeCoupling == roundActive <=> roundMode # "NONE"

\* A formed round never contains an excluded member (the node.cpp:
\* 762-768 filter) and has the mode-correct size (k_target MD /
\* k_bft BFT, node.cpp:778-787). Holds because RoundStraggle ends the
\* round in the same step it excludes, and StartRoundMD/Escalate draw
\* from availSet.
Inv_ActiveCommitteeWellFormed ==
    roundActive =>
        /\ committee \cap aborted = {}
        /\ \/ roundMode = "MD"  /\ Cardinality(committee) = K
           \/ roundMode = "BFT" /\ Cardinality(committee) = kBft

\* S-044 exhibit invariant. EXPECTED FALSIFIED on current semantics in
\* the E1 (web K=2) and E2 (M=K=3) configurations — the TLC
\* counterexample trace IS the abort-cascade wedge. Qualified by the
\* AbortDecay toggle: with decay (F-b) a wedge-shaped state is
\* escapable, hence not permanent, and the liveness property is the
\* authoritative check instead.
Inv_NoPermanentWedge == AbortDecay \/ ~WedgeState

\* S-045 exhibit invariant. EXPECTED FALSIFIED at E1/E2 (at E1 it is
\* the K=2 instance SECURITY.md:1316 notes is subsumed by S-044).
\* Note F-c does NOT clear this invariant (formationFailures climbing
\* cannot help while avail < k_bft); only decay (F-b) restores the
\* pool, hence the same AbortDecay qualification.
Inv_NoFrozenCounter == AbortDecay \/ ~FrozenCounterState

----------------------------------------------------------------------------
\* Temporal properties.

\* ProgressEventually: from every reachable height below the model
\* bound, the chain eventually advances. VIOLATED on current semantics
\* at E1 (web-profile S-044 wedge: fair lasso = two single-claim
\* straggles, duplicate adoptions to the cap, then Stall forever) and
\* E2; HOLDS at E3 (green escalation sanity) and at the fix re-checks
\* E4 (QuorumFloor=2), E5 (AbortDecay), E7 (F-c rescue) per the
\* exhibit table in the header.
Prop_ProgressEventually ==
    \A h \in 0..(MaxHeight - 1) : (height = h) ~> (height > h)

============================================================================
