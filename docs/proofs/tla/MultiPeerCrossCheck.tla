--------------------------- MODULE MultiPeerCrossCheck ---------------------------
(*
FB58 — TLA+ specification of the determ-light MULTI-PEER CROSS-CHECK DIVERGENCE
DETECTOR (`determ-light cross-check`, light/main.cpp::cmd_cross_check, commit
`36e7053`; cross-HOST `--peer` support `9fed9ad`). Machine-checkable companion to
`docs/proofs/MultiPeerCrossCheckSoundness.md` (theorems MPC-1..MPC-5).

This closes the single-daemon residual flagged across the light-client proof
family (LightClientCompositionMap.md §6 "single-daemon (no multi-peer
cross-check)"; LightClientThreatModel.md §6). The cross-check queries N >= 2
independent daemons against ONE pinned genesis, fully verifies each
INDEPENDENTLY (anchor_genesis + verify_chain_to_head), then groups the verified
heads by reported height and requires every height shared by >= 2 peers to agree
on (block_hash, state_root). The spec lifts that pipeline to a finite state
machine so the four verdicts and the soundness theorems can be model-checked.

NOTE: spec-only — no .cfg yet, so NOT model-checked (see tla/CHECK-RESULTS.md for the checked set; matching every no-cfg sibling in this
directory).

--------------------------------------------------------------------------
The shipped mechanism (read off cmd_cross_check; quoted faithfully):

  1. PER-PEER VERIFY (fail-closed FIRST, before ANY compare). For each endpoint
     (light/main.cpp:1642-1659) the tool opens the RpcClient, runs
     `anchor_genesis(rpc, genesis)` (recompute genesis hash locally; reject on
     block-0 mismatch — the LightClientThreatModel T-L1 anchor) and
     `verify_chain_to_head(rpc, committee_seed, gh)` (prev_hash continuity +
     K-of-K Ed25519 over compute_block_digest, the T-L2 head-trust primitive),
     recording (height, head_block_hash, head_state_root). ANY failure — socket
     open (`:1645-1648`), anchor or chain-verify throw (`:1654-1657`), or an
     outer genesis/committee load throw (`:1660-1662`) — prints
     "UNVERIFIABLE (fail-closed)" and `return 1` IMMEDIATELY, before the
     height-grouping/compare block is ever reached. You cannot cross-check
     against a peer you could not verify (MPC-4).

  2. HEIGHT GROUPING. `by_height` maps reported height -> list of peer indices
     (light/main.cpp:1666-1667); min_h / max_h are scanned with explicit
     comparisons (`:1670-1674`; the source note explains the <windows.h>
     min/max-macro hazard avoided here).

  3. SHARED-HEIGHT AGREEMENT. For each height group, groups of size < 2 are
     SKIPPED (`:1680` `if (idxs.size() < 2) continue;`) — a strictly-behind /
     ahead peer that shares its height with no other peer is NEVER compared
     (MPC-3 lag-benignity). For a group of >= 2, peer[idxs[0]] is the reference
     and every other member must match BOTH block_hash AND state_root
     (`:1685` `if (q.block_hash != ref.block_hash || q.state_root !=
     ref.state_root)`); a mismatch sets `divergence = true` and appends a
     diagnostic (`:1685-1692`). `any_shared` is set true whenever some group had
     >= 2 members (`:1681`).

  4. VERDICT + EXIT CODE (light/main.cpp:1696-1721). The verdict is
     `divergence ? "DIVERGENCE" : (any_shared ? "AGREE" : "INCONCLUSIVE")`
     (`:1704`). Exit codes: DIVERGENCE => `return 2` (`:1719`); INCONCLUSIVE
     (no two peers shared a height) => `return 3` (`:1720`); AGREE => `return 0`
     (`:1721`). UNVERIFIABLE => `return 1` (step 1, before this block). Note the
     precedence: divergence DOMINATES any_shared, so a DIVERGENCE is reported
     even if some other group merely agreed.

--------------------------------------------------------------------------
What this spec models (and what it abstracts).

  * A small finite set Peers of daemon endpoints (the N queried by the operator;
    CONSTANT Peers, tiny — e.g. {p1, p2, p3}). Each peer is partitioned into
    Honest / Byz / Eclipsed (CONSTANTS), the spec-layer projection of
    A_eclipse + A_byz_committee (MultiPeerCrossCheckSoundness.md §2).

  * A SINGLE canonical chain is the symbolic function Canonical: height ->
    <<block_hash, state_root>> over a tiny finite Heights domain (the
    "exactly one block per height" fact MPC-1 rests on — the canonical chain is
    one sequence). Honest peers' verified views are PREFIXES of Canonical (a
    verified head at h' is a verified prefix position, MPC-3); Byzantine /
    eclipsed peers may hold a DIFFERENT (forked) value at some height.

  * Per-peer state is `view[peer]` = a partial function height ->
    <<block_hash, state_root>> (the verified (height -> (block_hash,state_root))
    LightClientThreatModel records) PLUS `failed[peer]` (BOOLEAN — did this peer
    fail its own anchor/committee verify). VerifyPeer(peer) populates one peer's
    view (honest => a canonical prefix; Byz/eclipsed => possibly a fork) or sets
    failed[peer] = TRUE (the UNVERIFIABLE branch). One-shot per peer.

  * CrossCheck is the single comparison action, enabled only once EVERY peer has
    been processed (verified or failed). It encodes the EXACT cmd_cross_check
    control flow:
      (a) if ANY peer failed  => verdict := "UNVERIFIABLE" (the fail-closed
          early `return 1` — modeled as the whole-run verdict, since in the
          source the first failing peer aborts before the compare loop);
      (b) else compute, over every height h shared by >= 2 verified peers,
          whether all those peers agree on <<block_hash, state_root>>:
            - some shared group disagrees => verdict := "DIVERGENCE";
            - >= 1 shared group, all agree => verdict := "AGREE";
            - no height shared by >= 2 peers => verdict := "INCONCLUSIVE".
    The divergence-dominates-agree precedence is encoded by checking the
    DIVERGENCE disjunct first.

  * The committee-sig / SHA-256 / prev_hash machinery is abstracted to its
    outcome: an honest peer's verified view equals Canonical on its prefix (A1
    EUF-CMA + A2 collision resistance make a forged-but-verified block
    negligible — out of scope per the sibling convention, exactly as FB55/FB56
    abstract their crypto). A Byzantine/eclipsed peer that PASSES its own verify
    (failed = FALSE) yet serves a different value at a height is the modeled
    A_byz_committee fork (>= f+1 equivocation) the cross-check is designed to
    surface (MPC-2).

  * `compared[peer]` (BOOLEAN, ghost) records whether a peer's head entered a
    >=2 comparison group — used by INV_LagBenign to witness that a strictly-
    behind peer (sharing its height with no one) is never compared.

--------------------------------------------------------------------------
Invariants (mapping MPC-1..MPC-5):

  (MPC-0) TypeOK — variable shapes; views are partial functions Heights ->
          (BlockHash x StateRoot); the verdict is one of the four labels.
  (MPC-1) INV_NoFalseDivergence — if every NON-failed peer's verified view is a
          canonical prefix (the honest-on-one-chain hypothesis) then the verdict
          is never "DIVERGENCE". Honest peers agree at every shared height
          because the canonical chain has exactly one block per height, so a
          DIVERGENCE is never raised against honest daemons on one chain — a
          sound alarm, not noise.
  (MPC-2) INV_DivergenceIsRealFork — a "DIVERGENCE" verdict implies there exist
          two peers, both NON-failed (hence both passed their own K-of-K
          committee verify), sharing a height h at which their
          <<block_hash,state_root>> differ: two committee-verified blocks at one
          height — a genuine fork / equivocation witness (MPC-2).
  (MPC-3) INV_LagBenign — a peer whose verified height is shared by no other
          peer is never compared (compared[peer] = FALSE); a strictly-behind (or
          ahead) head is benign network asynchrony, not a divergence.
  (MPC-4) INV_FailClosed — if ANY peer failed its own verify, the verdict (once
          decided) is "UNVERIFIABLE", never "AGREE": an unverifiable peer forces
          fail-closed BEFORE any comparison, never a false AGREE.
  (MPC-5) INV_PerPeerPreserved — every peer whose head is in a comparison group
          was independently fully verified first (failed = FALSE and its view is
          populated). The cross-check is a pure post-hoc comparison of
          already-verified results; it weakens no single-peer guarantee.

A temporal property pins eventual decision:
  (MPC-6) Prop_EventuallyDecided — under fairness, once every peer has been
          processed the run eventually reaches a decided verdict (one of the four
          labels), and that verdict is "UNVERIFIABLE" iff some peer failed.

--------------------------------------------------------------------------
Modeling scope (kept small + finite-checkable so it COULD be model-checked
later): tiny Peers (3), tiny Heights (e.g. {1,2}), a 2-element BlockHash and
StateRoot symbolic universe so a fork has a distinct alternative value, a fixed
Honest/Byz/Eclipsed partition, and a single canonical chain Canonical. The
action set is naturally bounded (verify each peer once, then CrossCheck once),
so no step counter is needed.

Companion analytic source: `docs/proofs/MultiPeerCrossCheckSoundness.md`
(theorems MPC-1..MPC-5; §1 mechanism; §2 threat model; §4 honest limitations).

Adjacent specs:
  FB55 (TimestampMedianReconciliation.tla) — the digest-binding family this
    cross-check rides on (the divergence witness is over the committee-signed
    digest the per-peer verify_chain_to_head checks).
  FB56 (PartnerSubsetDigestBinding.tla) — the deterministic single-value
    digest-binding sibling; this spec mirrors its banner / Init / Next / Spec /
    INV_* / closing C++ anchor-block house style.

To check (assuming TLC installed):
  $ tlc MultiPeerCrossCheck.tla -config MultiPeerCrossCheck.cfg
Recommended config (small + finite): Peers = {p1, p2, p3},
  Honest = {p1, p2}, Byz = {p3}, Eclipsed = {},
  Heights = {1, 2}, BlockHash = {bA, bB}, StateRoot = {sA, sB},
  CanonHash = bA, CanonRoot = sA, ForkHash = bB, ForkRoot = sB.
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Peers,       \* the finite set of daemon endpoints the operator queries (N >= 2)
    Honest,      \* peers serving the canonical chain (their verified view is a prefix)
    Byz,         \* Byzantine / forked peers (A_byz_committee — may serve a fork)
    Eclipsed,    \* eclipsed peers (A_eclipse — may serve a forked/stale/lying chain)
    Heights,     \* the finite set of block heights modeled (>= 1)
    BlockHash,   \* finite symbolic universe of block_hash values (>= 2 for a fork)
    StateRoot,   \* finite symbolic universe of state_root values (>= 2 for a fork)
    CanonHash,   \* the canonical block_hash at every modeled height
    CanonRoot,   \* the canonical state_root at every modeled height
    ForkHash,    \* a distinct (non-canonical) block_hash a fork peer may serve
    ForkRoot     \* a distinct (non-canonical) state_root a fork peer may serve

\* The verdict labels (the four cmd_cross_check outcomes) + the pre-decision sentinel.
Pending      == "PENDING"        \* no verdict decided yet (CrossCheck not yet fired)
Agree        == "AGREE"          \* exit 0  — every shared-height group consistent
Divergence   == "DIVERGENCE"     \* exit 2  — some shared height disagrees
Inconclusive == "INCONCLUSIVE"   \* exit 3  — no two peers share a height this round
Unverifiable == "UNVERIFIABLE"   \* exit 1  — a peer failed its own anchor/committee verify
Verdicts     == {Pending, Agree, Divergence, Inconclusive, Unverifiable}

\* The "no head verified yet" sentinel for a peer's reported height (distinct from
\* any value in Heights). A peer is unprocessed until VerifyPeer fires.
NoHeight     == 0

\* The pair value a verified view records at a height: <<block_hash, state_root>>.
Pairs        == BlockHash \X StateRoot
CanonPair    == <<CanonHash, CanonRoot>>
ForkPair     == <<ForkHash, ForkRoot>>

ASSUME ConfigOK ==
    /\ Cardinality(Peers) >= 2                         \* >= 2 peers required (the CLI gate)
    /\ Honest \cup Byz \cup Eclipsed = Peers           \* the partition covers every peer
    /\ Honest \cap Byz = {} /\ Honest \cap Eclipsed = {} /\ Byz \cap Eclipsed = {}
    /\ Heights \subseteq (Nat \ {0})                   \* heights >= 1 (NoHeight = 0 reserved)
    /\ Heights # {}
    /\ Cardinality(BlockHash) >= 2                     \* >= 2 so a fork hash is distinct
    /\ Cardinality(StateRoot) >= 2
    /\ CanonHash \in BlockHash /\ CanonRoot \in StateRoot
    /\ ForkHash  \in BlockHash /\ ForkRoot  \in StateRoot
    /\ <<ForkHash, ForkRoot>> # <<CanonHash, CanonRoot>>  \* the fork pair is non-canonical

----------------------------------------------------------------------------
\* §1. The single canonical chain. Exactly one (block_hash, state_root) per
\* height — the "canonical chain is a single sequence with one block per height"
\* fact MPC-1 / MPC-3 rest on. Modeled as the constant function returning
\* CanonPair at every height (the symbolic universe is intentionally collapsed to
\* one canonical value per height; the fork peers' alternative is ForkPair).
Canonical(h) == CanonPair

----------------------------------------------------------------------------
\* §2. State.
\*
\* `view[p]` is peer p's VERIFIED head record: <<height, pair>> where height is
\* the reported head height (NoHeight if not yet processed) and pair is the
\* <<block_hash, state_root>> verify_chain_to_head captured at that head. (We
\* model only the HEAD record — the cmd_cross_check comparison is head-vs-head per
\* the reported height; the full prefix is verified but only the head enters the
\* group compare.) `failed[p]` is TRUE iff peer p failed its own anchor/committee
\* verify (the UNVERIFIABLE branch). `processed[p]` marks that VerifyPeer has run
\* on p (verified or failed). `verdict` is the cross-check outcome (Pending until
\* CrossCheck fires). `compared[p]` (ghost) records whether p's head entered a
\* >=2 comparison group (the LagBenign witness).

VARIABLES
    view,        \* function Peers -> <<(Heights \cup {NoHeight}), Pairs>>
    failed,      \* function Peers -> BOOLEAN  (failed its own anchor/committee verify)
    processed,   \* function Peers -> BOOLEAN  (VerifyPeer has run on this peer)
    verdict,     \* the cross-check verdict (one of Verdicts)
    compared     \* function Peers -> BOOLEAN  (ghost: head entered a >=2 group)

vars == <<view, failed, processed, verdict, compared>>

----------------------------------------------------------------------------
\* §3. Helpers.

\* The reported head height / pair of a processed peer.
HeightOf(p) == view[p][1]
PairOf(p)   == view[p][2]

\* Every peer has been processed (verified or failed) — the readiness gate for
\* CrossCheck (the source processes the whole endpoint list before comparing).
AllProcessed == \A p \in Peers : processed[p]

\* At least one peer failed its own verify — the fail-closed trigger (cmd_cross_check
\* returns 1 on the FIRST failing peer, before any compare; modeled as the
\* whole-run UNVERIFIABLE verdict).
AnyFailed == \E p \in Peers : failed[p]

\* The set of NON-failed, processed peers whose verified head is exactly at height h.
\* These are the peers cmd_cross_check's `by_height[h]` group contains (a failed peer
\* never reaches the grouping — it aborted the run). Only meaningful once processed.
AtHeight(h) == { p \in Peers : processed[p] /\ ~failed[p] /\ HeightOf(p) = h }

\* A height is SHARED iff >= 2 non-failed peers report it (the `idxs.size() < 2
\* continue;` gate at light/main.cpp:1680 — size-1 groups are skipped).
SharedHeights == { h \in Heights : Cardinality(AtHeight(h)) >= 2 }

\* A shared height h DISAGREES iff two of its peers hold different <<block_hash,
\* state_root>> pairs (the `q.block_hash != ref.block_hash || q.state_root !=
\* ref.state_root` test at light/main.cpp:1685). Order-independent: the reference
\* is peer idxs[0], but "all match the reference" is equivalent to "all pairs
\* equal", which is what this existential over distinct pairs captures.
GroupDisagrees(h) ==
    \E p, q \in AtHeight(h) : PairOf(p) # PairOf(q)

\* Some shared height disagrees (=> DIVERGENCE), and the dual: a shared height
\* exists (=> AGREE vs INCONCLUSIVE distinction).
SomeDivergence == \E h \in SharedHeights : GroupDisagrees(h)
AnyShared      == SharedHeights # {}

----------------------------------------------------------------------------
\* §4. Initial state. No peer processed; views empty (NoHeight, an arbitrary
\* pair placeholder); nothing failed or compared; the verdict is Pending.

Init ==
    /\ view      = [p \in Peers |-> <<NoHeight, CanonPair>>]
    /\ failed    = [p \in Peers |-> FALSE]
    /\ processed = [p \in Peers |-> FALSE]
    /\ verdict   = Pending
    /\ compared  = [p \in Peers |-> FALSE]

----------------------------------------------------------------------------
\* §5. Actions.

\* VerifyHonest(p, h): an HONEST peer is verified successfully. Its verified head
\* is at some height h and its pair is the CANONICAL pair at h (an honest daemon
\* on the canonical chain — verify_chain_to_head captured Canonical(h)). Honest
\* peers may sit at DIFFERENT heights (network asynchrony / lag — MPC-3), but
\* every honest verified pair is canonical. One-shot (a peer is processed once).
VerifyHonest(p, h) ==
    /\ p \in Honest
    /\ ~processed[p]
    /\ h \in Heights
    /\ view'      = [view      EXCEPT ![p] = <<h, Canonical(h)>>]
    /\ failed'    = [failed    EXCEPT ![p] = FALSE]
    /\ processed' = [processed EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<verdict, compared>>

\* VerifyForked(p, h, pr): a Byzantine / eclipsed peer that PASSES its own
\* anchor + committee verify (failed = FALSE) yet serves an arbitrary pair pr at
\* height h. When pr is the fork pair this is the A_byz_committee fork (>= f+1
\* equivocation) the cross-check surfaces (MPC-2); when pr is canonical the
\* adversary chose to serve the honest chain (silent — the all-collude case
\* reduces to AGREE, MPC-4 §4). One-shot.
VerifyForked(p, h, pr) ==
    /\ p \in (Byz \cup Eclipsed)
    /\ ~processed[p]
    /\ h \in Heights
    /\ pr \in Pairs
    /\ view'      = [view      EXCEPT ![p] = <<h, pr>>]
    /\ failed'    = [failed    EXCEPT ![p] = FALSE]
    /\ processed' = [processed EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<verdict, compared>>

\* FailVerify(p): a peer FAILS its own verify — wrong genesis (anchor_genesis
\* reject), a bad committee sig, or a broken prev_hash (verify_chain_to_head
\* throw), or a socket-open failure. Sets failed[p] = TRUE. In the source this
\* aborts the whole run with `return 1` before the compare; here it latches the
\* failure flag and AnyFailed forces UNVERIFIABLE at CrossCheck. Any peer class
\* may fail (an honest daemon could be unreachable; a Byz/eclipsed daemon could
\* serve an unverifiable chain). One-shot.
FailVerify(p) ==
    /\ ~processed[p]
    /\ failed'    = [failed    EXCEPT ![p] = TRUE]
    /\ processed' = [processed EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<view, verdict, compared>>

\* CrossCheck: the single comparison action (light/main.cpp:1665-1721), enabled
\* once EVERY peer has been processed and no verdict decided yet. Encodes the
\* exact control flow:
\*   (a) AnyFailed              => UNVERIFIABLE (fail-closed early return 1);
\*   (b) else SomeDivergence    => DIVERGENCE (a shared height disagrees; exit 2);
\*   (c) else AnyShared         => AGREE (>= 1 shared group, all agree; exit 0);
\*   (d) else                   => INCONCLUSIVE (no shared height; exit 3).
\* The divergence-dominates-agree precedence (light/main.cpp:1704) is the order of
\* the (b)/(c) disjuncts. `compared` is set TRUE for exactly the peers whose head
\* entered a >=2 group (a peer at a shared height) on the non-failed path — the
\* LagBenign / PerPeerPreserved ghost (no comparison happens on the fail path).
CrossCheck ==
    /\ verdict = Pending
    /\ AllProcessed
    /\ IF AnyFailed
       THEN /\ verdict'  = Unverifiable
            /\ compared' = [p \in Peers |-> FALSE]      \* no compare on the fail path
       ELSE /\ verdict'  = IF SomeDivergence THEN Divergence
                          ELSE IF AnyShared  THEN Agree
                          ELSE Inconclusive
            /\ compared' = [p \in Peers |->
                              processed[p] /\ ~failed[p]
                              /\ HeightOf(p) \in SharedHeights]
    /\ UNCHANGED <<view, failed, processed>>

----------------------------------------------------------------------------
\* §6. Next-state relation + spec. The per-peer verify fan-in (honest / forked /
\* fail), then the single CrossCheck decision.

Next ==
    \/ \E p \in Honest, h \in Heights : VerifyHonest(p, h)
    \/ \E p \in (Byz \cup Eclipsed), h \in Heights, pr \in Pairs : VerifyForked(p, h, pr)
    \/ \E p \in Peers : FailVerify(p)
    \/ CrossCheck

\* Weak fairness on the verify actions + CrossCheck drives Prop_EventuallyDecided:
\* every peer eventually gets processed and the comparison eventually fires. The
\* safety invariants (MPC-1..MPC-5) hold in EVERY reachable state regardless of
\* interleaving.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A p \in Honest : WF_vars(\E h \in Heights : VerifyHonest(p, h))
    /\ \A p \in (Byz \cup Eclipsed) :
          WF_vars(\E h \in Heights, pr \in Pairs : VerifyForked(p, h, pr))
    /\ WF_vars(CrossCheck)

----------------------------------------------------------------------------
\* §7. Invariants — MPC-0..MPC-5.

\* MPC-0 / TypeOK. Shapes + bounds.
TypeOK ==
    /\ view      \in [Peers -> ((Heights \cup {NoHeight}) \X Pairs)]
    /\ failed    \in [Peers -> BOOLEAN]
    /\ processed \in [Peers -> BOOLEAN]
    /\ verdict   \in Verdicts
    /\ compared  \in [Peers -> BOOLEAN]

\* MPC-1 / INV_NoFalseDivergence. If every NON-failed processed peer's verified
\* head pair is the CANONICAL pair (the honest-peers-on-one-chain hypothesis),
\* then the verdict is never DIVERGENCE. The canonical chain has exactly one block
\* per height, so all peers sharing a height hold the byte-identical
\* <<block_hash,state_root>> and GroupDisagrees is false at every shared height.
\* Honest daemons on one chain never trip a false DIVERGENCE — the alarm is sound,
\* not noise (MultiPeerCrossCheckSoundness.md MPC-1). The crypto (A1+A2) that makes
\* a forged-but-canonical-passing block negligible is abstracted: an honest peer's
\* verified pair IS canonical by VerifyHonest.
INV_NoFalseDivergence ==
    (\A p \in Peers : (processed[p] /\ ~failed[p]) => PairOf(p) = CanonPair)
      => (verdict # Divergence)

\* MPC-2 / INV_DivergenceIsRealFork. A DIVERGENCE verdict implies two
\* committee-verified blocks differ at one height: there exist two NON-failed
\* (hence each independently K-of-K-verified) peers at the SAME height whose
\* <<block_hash,state_root>> pairs differ. That is a genuine fork / equivocation
\* witness — the two-instance condition surfaced across peers (MPC-2). DIVERGENCE
\* is never raised without such a witness.
INV_DivergenceIsRealFork ==
    (verdict = Divergence)
      => \E p, q \in Peers :
            /\ processed[p] /\ ~failed[p]
            /\ processed[q] /\ ~failed[q]
            /\ HeightOf(p) = HeightOf(q)
            /\ HeightOf(p) \in Heights
            /\ PairOf(p) # PairOf(q)

\* MPC-3 / INV_LagBenign. A peer whose verified height is shared by no other
\* peer (it is the sole occupant of its height — a strictly-behind or strictly-
\* ahead head) is NEVER compared: compared[p] = FALSE. A lagging head is benign
\* network asynchrony, not a divergence; the size-1 group is skipped
\* (light/main.cpp:1680). Holds after CrossCheck has set `compared` (and trivially
\* before, where all compared are FALSE).
INV_LagBenign ==
    \A p \in Peers :
        ( processed[p] /\ ~failed[p] /\ HeightOf(p) \in Heights
          /\ Cardinality(AtHeight(HeightOf(p))) = 1 )
            => (compared[p] = FALSE)

\* MPC-4 / INV_FailClosed. If ANY peer failed its own verify, then once a verdict
\* is decided it is UNVERIFIABLE — never AGREE (and never DIVERGENCE/INCONCLUSIVE).
\* An unverifiable peer forces fail-closed BEFORE any comparison; you cannot cross-
\* check against a peer you could not verify, and a failure never silently
\* downgrades to a false AGREE (MultiPeerCrossCheckSoundness.md MPC-4).
INV_FailClosed ==
    (AnyFailed /\ verdict # Pending) => (verdict = Unverifiable)

\* MPC-5 / INV_PerPeerPreserved. Every peer whose head ENTERED a comparison group
\* (compared[p] = TRUE) was independently fully verified first: processed and NOT
\* failed (verify_chain_to_head ran and passed before its head reached the group
\* compare). The cross-check is a pure post-hoc comparison of already-verified
\* results — it weakens no single-peer guarantee (MPC-5).
INV_PerPeerPreserved ==
    \A p \in Peers : compared[p] => (processed[p] /\ ~failed[p])

----------------------------------------------------------------------------
\* §8. Temporal property.

\* MPC-6 / Prop_EventuallyDecided. Under fairness on the verify actions +
\* CrossCheck, the run eventually reaches a DECIDED verdict (Pending leads to one
\* of the four labels), and the decided verdict is UNVERIFIABLE exactly when some
\* peer failed its own verify. The standing leads-to that the cross-check
\* terminates with a well-formed verdict.
Prop_EventuallyDecided ==
    <> ( /\ verdict # Pending
         /\ (verdict = Unverifiable) <=> AnyFailed )

============================================================================
\* Cross-references.
\*
\* FB55 (TimestampMedianReconciliation.tla) — the digest-binding family: the
\*   divergence witness this cross-check surfaces is over the committee-signed
\*   compute_block_digest that verify_chain_to_head checks per peer. FB55 binds
\*   the reconciled median INTO that digest; this spec compares the digest-bound
\*   HEADS across N independently verified peers.
\* FB56 (PartnerSubsetDigestBinding.tla) — the deterministic single-value
\*   digest-binding sibling whose banner / Init / Next / Spec / INV_* / closing
\*   C++ anchor-block house style this spec mirrors. PSB-2's "post-sign tamper
\*   changes the digest, sigs no longer verify" is the SINGLE-peer analog of this
\*   spec's INV_DivergenceIsRealFork (a committee-verified fork across peers).
\*
\* Companion analytic record:
\*   docs/proofs/MultiPeerCrossCheckSoundness.md — theorems MPC-1..MPC-5 this
\*     spec's INV_* lift to the state-machine layer; §1 mechanism (the per-peer
\*     verify -> height-group -> shared-height-agree pipeline); §2 threat model
\*     (A_eclipse / A_byz_committee = the Byz/Eclipsed partition); §4 honest
\*     limitations (all-collude => AGREE, modeled by VerifyForked with a canonical
\*     pair; not a liveness/non-membership proof).
\*   LightClientThreatModel.md — T-L1 anchor (anchor_genesis) + T-L2 head-trust
\*     (verify_chain_to_head), the per-peer primitives reused without new
\*     assumption.
\*   LightClientCompositionMap.md §6 — the single-daemon residual this closes.
\*
\* C++ enforcement (light/main.cpp::cmd_cross_check, commit 36e7053; cross-HOST
\* --peer support 9fed9ad):
\*   light/main.cpp:1609          : cmd_cross_check entry point.
\*   light/main.cpp:1613-1635     : arg parse (--rpc-port => 127.0.0.1:<N>; --peer
\*       <host:port> cross-HOST; --genesis; --json) + the ">= 2 peers and a
\*       --genesis required" gate (:1631-1635, the Cardinality(Peers) >= 2 ASSUME).
\*   light/main.cpp:1642-1659     : per-peer loop — RpcClient open (:1645-1648
\*       UNVERIFIABLE return 1 on socket fail) then anchor_genesis +
\*       verify_chain_to_head, recording (height, head_block_hash, head_state_root)
\*       (:1651-1653); anchor/verify throw => UNVERIFIABLE return 1 (:1654-1657)
\*       BEFORE any compare. (VerifyHonest / VerifyForked / FailVerify + INV_FailClosed
\*       / MPC-4.)
\*   light/main.cpp:1660-1662     : outer genesis/committee load throw => return 1
\*       (the fail-closed wrapper; FailVerify / MPC-4).
\*   light/main.cpp:1666-1674     : by_height grouping + min_h/max_h scan (explicit
\*       comparisons — the <windows.h> min/max-macro note). (HeightOf / AtHeight.)
\*   light/main.cpp:1680          : `if (idxs.size() < 2) continue;` — size-1 groups
\*       SKIPPED (SharedHeights / INV_LagBenign / MPC-3).
\*   light/main.cpp:1681-1694     : intra-group agreement — ref = idxs[0], compare
\*       block_hash AND state_root (:1685), set divergence + diag on mismatch;
\*       any_shared set when a group has >= 2 members. (GroupDisagrees /
\*       INV_DivergenceIsRealFork / MPC-2; AnyShared.)
\*   light/main.cpp:1704          : verdict = divergence ? "DIVERGENCE"
\*       : (any_shared ? "AGREE" : "INCONCLUSIVE") — the precedence CrossCheck
\*       encodes (divergence dominates).
\*   light/main.cpp:1719-1721     : exit codes — DIVERGENCE return 2; INCONCLUSIVE
\*       return 3; AGREE return 0. (UNVERIFIABLE return 1 lives in the per-peer loop
\*       above; the four Verdicts map 1:1.)
\*   light/main.cpp:6607          : `if (cmd == "cross-check") return
\*       cmd_cross_check(...)` dispatch.
\*
\* Test surface:
\*   tools/test_light_cross_check.sh — (A) deterministic offline CLI/dispatch/
\*     exit-code contract (>= 2 --rpc-port required, missing --genesis, unknown
\*     arg, help-listed); (B) best-effort live 2-daemon AGREE (cluster-bound, SKIPs
\*     where the local cluster cannot mint). DIVERGENCE needs a forked/Byzantine
\*     daemon (test-only), exercised on WSL2/CI (MultiPeerCrossCheckSoundness.md §5).
\*
\* NOTE: spec-only — no .cfg yet, so NOT model-checked (see tla/CHECK-RESULTS.md).
============================================================================
