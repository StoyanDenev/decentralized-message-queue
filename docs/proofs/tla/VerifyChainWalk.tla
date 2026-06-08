--------------------------- MODULE VerifyChainWalk ---------------------------
(*
FB59 — TLA+ specification of the determ-light PAGE-WALK SOUNDNESS GATES
(SHIPPED feature; `light/trustless_read.cpp::verify_chain_walk` — the single
verified core shared by `verify_chain_to_head` (from-genesis) and
`verify_chain_from_anchor` (resume from a persisted anchor)). Machine-checkable
companion to `docs/proofs/VerifyChainWalkSoundness.md` (theorems VCW-1..VCW-5).

This is the state-machine model of the gauntlet a daemon's header pages must run
to ACCEPT a verified head: a sequence of pages over the range [StartFrom, Head)
is walked with (a) the INDEX-CONTIGUITY gate (each page is exactly the indices
[from, from+count) in order — no index injection, no gaps), (b) the
FIRST-PAGE genesis-vs-anchor branch (from==0 anchors block 0 to genesis_hash;
from>0 chains the first header onto the persisted anchor prev_hash), (c) the
GENESIS sig-skip gated on `from==0` (the binding-free genesis branch fires only
at the genuine genesis position), and (d) the WALKED-COUNT gate (headers_seen
must equal Head - StartFrom, so a short final page cannot silently truncate the
walk while still reporting Head as the verified tip). The walk ends in ACCEPT
(the full range committee-verified onto the start anchor) or REJECT.

NOTE: spec-only, model-check pending TLC install (matching every sibling in this
directory).

--------------------------------------------------------------------------
Background — the resume-soundness bug this spec pins as FIXED. A pre-merge
adversarial verifier found that a malicious daemon serving a RESUME-suffix header
claiming index 0 diverted `verify_headers` into its binding-free GENESIS branch
(which, when genesis_hash_hex is empty, ignores the anchor prev_hash entirely)
WHILE the per-block sig loop skipped index 0 — so the suffix's first block dodged
BOTH the anchor link AND the committee-sig check. It was fixed THREE ways, all
modeled here:

  (1) `light/verify.cpp::verify_headers` now REJECTS an index-0 header when a
      non-empty prev_hash anchor was supplied (the RESUME-SOUNDNESS GATE at
      verify.cpp:172-186: `if (first_index == 0) ... if (!prev_hash_hex.empty())
      return FAIL`). A suffix header can no longer masquerade as genesis.
  (2) `light/trustless_read.cpp::verify_chain_walk` asserts page indices are
      CONTIGUOUS from `from` (the index-contiguity gate at trustless_read.cpp:
      146-155: `got != from + i => throw`). An injected index-0 (or any gap) is a
      hard error before any chain/sig check runs.
  (3) the genesis sig-skip is gated on `from == 0` (trustless_read.cpp:187:
      `if (idx == 0 && from == 0) continue;`) AND the WALKED-COUNT gate
      (trustless_read.cpp:213-219: `headers_seen != head_height - start_from =>
      throw`) closes the truncation face. The contiguity gate already makes
      `idx==0 <=> from==0`, but the `&& from==0` makes the suffix walk's
      never-skip property explicit and independent of it (defense in depth).

--------------------------------------------------------------------------
The headline contract — the VCW-1..VCW-5 theorems lifted to the state-machine
layer (each grounded in shipped source):

  VCW-1 (Walk-decides). Every walk over a finite range terminates in exactly one
    of ACCEPT / REJECT — the for-loop at trustless_read.cpp:127 runs to
    head_height then the walked-count gate (213) decides, or any gate throws
    mid-loop (a REJECT). Modeled: every reachable run reaches a terminal
    `decision \in {"ACCEPT", "REJECT"}` (Prop_EventuallyDecided), and ACCEPT
    means the full range was verified onto the start anchor.

  VCW-2 (No-index-injection). An index-injected page (a header whose index is not
    its contiguous position `from + i`) — IN PARTICULAR a resume suffix whose
    FIRST index is 0 instead of StartFrom — is REJECTED, never ACCEPTed. This is
    the index-contiguity gate (trustless_read.cpp:146-155) PLUS the verify_headers
    anchored-page guard (verify.cpp:172-186). A gapped page (missing index) is the
    same gate. Modeled: INV_NoIndexInjection — if any processed page was
    index-injected or gapped, `decision /= "ACCEPT"`.

  VCW-3 (Anchor-bound). ACCEPT implies the FIRST page chained onto the START
    ANCHOR: for a from-genesis walk (StartFrom==0) the first page anchored block 0
    to genesis_hash (verify_headers' genesis branch, verify.cpp:193-201); for a
    resume walk (StartFrom>0) the first page's first header chained onto the
    persisted anchor prev_hash (verify.cpp:202-208, reached because the index-0
    branch is now rejected for a non-empty anchor). Modeled: INV_AnchorBound —
    ACCEPT implies the recorded first-page link equals the start anchor.

  VCW-4 (Full-coverage). ACCEPT implies headers_seen == Head - StartFrom — the
    walked-count gate (trustless_read.cpp:213-219). A SHORT-FINAL page (the daemon
    serves fewer headers than the range demands) is therefore REJECTED: it cannot
    report Head as the verified tip while having walked fewer blocks. Modeled:
    INV_FullCoverage — ACCEPT implies headersSeen = Head - StartFrom.

  VCW-5 (Genesis-skip-only-at-zero). The per-block committee-sig skip fires ONLY
    at the genuine from==0 genesis position (trustless_read.cpp:181-187:
    `if (idx == 0 && from == 0) continue;`). On a resume walk (StartFrom>0) NO
    block is skipped — every suffix block's K-of-K committee signature is checked.
    So the index-0 diversion cannot buy a free (unsigned) block. Modeled:
    INV_GenesisSkipOnlyAtZero — a block is sig-skipped iff its index is 0 AND the
    page's `from` is 0 (equivalently StartFrom==0 on the first page).

--------------------------------------------------------------------------
Threat / trust model (VerifyChainWalkSoundness.md §2). The daemon is UNTRUSTED:
it serves pages over RPC and may offer any of the adversarial page shapes below.
The cryptographic substrate is the per-run verify-chain base
{A1 Ed25519 EUF-CMA over light_compute_block_digest, A2 SHA-256 collision
resistance for prev_hash / block_hash / genesis_hash} (Preliminaries.md §2.0-2.2).
This spec abstracts that substrate exactly as the sibling FB-track light specs
do: a block's committee signature is an opaque "this header's K-of-K sig verifies"
predicate (the A1 content of verify_block_sigs), and a prev_hash link is symbolic
equality of opaque hash handles (the A2 content of verify_headers' chain walk).
What the spec models is the CONTROL FLOW of the gates over an adversarial page
sequence — the layer the resume-soundness bug lived in (the bug was not a broken
signature check; it was a control-flow diversion AROUND the checks). The daemon
cannot forge a committee sig (A1) — so the only leverage it has is page SHAPE,
which is exactly the nondeterministic offering enumerated below.

--------------------------------------------------------------------------
Modeling scope (kept small + finite-checkable so it COULD be model-checked):

  * CONSTANTS Head (a small finite tip height) and StartFrom (0 for a from-genesis
    walk, or a mid-chain anchor height for a resume) and PageSize (the page
    granularity, the spec-layer projection of the PAGE=256 constant at
    trustless_read.cpp:120). The range [StartFrom, Head) is finite; the walk
    consumes it one page at a time. A boolean StartIsGenesis == (StartFrom = 0)
    selects the first-page genesis-vs-anchor branch.
  * `cursor`: the next index the walk expects (initialized to StartFrom, advanced
    by the honest page width). `headersSeen`: the running count (the
    `headers_seen` accumulator). `firstLink`: the anchor the first processed page
    chained onto ("genesis" if the from==0 genesis branch fired and matched
    genesis_hash; "anchor" if the from>0 branch chained onto the persisted anchor
    prev_hash; "none" before the first page). `pagesProcessed`: how many pages have
    been consumed. `lastSkipWasGenesis`: whether the most recent page sig-skipped
    a block (only legal at the genuine genesis position). `decision`: "PENDING" |
    "ACCEPT" | "REJECT". `badShapeSeen`: a ghost flag recording whether any
    processed page was index-injected / gapped / short-nonfinal (the
    INV_NoIndexInjection antecedent).
  * The daemon's per-page OFFERING is the nondeterministic choice the ServePage
    action ranges over: "honest" (a contiguous page of the correct width chaining
    onto the running prev_anchor), "index0" (the adversarial index-0 diversion — a
    first header claiming index 0 inside a resume suffix), "injected" (some header
    index != its contiguous position, a non-genesis injection / gap), "gapped" (a
    page that skips an index), "short_final" (the FINAL page serves fewer headers
    than the range's remainder), "continuity_break" (a page whose first header's
    prev_hash does not chain onto the running anchor). Each maps deterministically
    to a gate verdict, mirroring the code's gate ORDER (contiguity, then chain,
    then sig, then — at loop end — walked-count).

--------------------------------------------------------------------------
Invariants (mapping VCW-2..VCW-5; VCW-1 is the temporal Prop_EventuallyDecided):

  (VCW-0) TypeOK — variables have the right shapes; the value universes are finite
          so TLC's state space is bounded.
  (VCW-2) INV_NoIndexInjection — an index-injected or gapped page (in particular a
          resume suffix whose first index is 0 rather than StartFrom) is REJECTED,
          never ACCEPTed: if `badShapeSeen` is set (any processed page violated
          contiguity), `decision /= "ACCEPT"`. The index-contiguity gate
          (trustless_read.cpp:146-155) + the verify_headers anchored-page guard
          (verify.cpp:172-186).
  (VCW-3) INV_AnchorBound — ACCEPT implies the FIRST processed page chained onto
          the START anchor: `firstLink` is "genesis" when StartFrom==0 (the block-0
          genesis-hash anchor) and "anchor" when StartFrom>0 (the persisted
          prev_hash anchor). An ACCEPT can never have `firstLink = "none"` (no
          page processed) or the wrong branch for the walk kind. The first-page
          genesis-vs-anchor branch (trustless_read.cpp:161-163 + verify.cpp:
          172-209).
  (VCW-4) INV_FullCoverage — ACCEPT implies headersSeen == Head - StartFrom: the
          full range was walked, so a short-final page (fewer headers than the
          remainder) is REJECTED. The walked-count gate (trustless_read.cpp:
          213-219).
  (VCW-5) INV_GenesisSkipOnlyAtZero — the per-block sig-skip fires ONLY at the
          genuine genesis position (index 0 reached with the page `from`==0, i.e.
          StartFrom==0 on the first page). A resume walk (StartFrom>0) sig-skips no
          block: `lastSkipWasGenesis` can be TRUE only when StartIsGenesis. The
          `if (idx == 0 && from == 0) continue;` gate (trustless_read.cpp:181-187).

A temporal property pins VCW-1 (walk-decides):

  (VCW-1t) Prop_EventuallyDecided — under fairness on ServePage / Decide, every
           walk eventually reaches a terminal decision (ACCEPT or REJECT); it never
           hangs PENDING forever. The for-loop-to-head + walked-count-gate
           termination of verify_chain_walk.

--------------------------------------------------------------------------
Companion analytic source: `docs/proofs/VerifyChainWalkSoundness.md`
(VCW-1..VCW-5; being written concurrently — this spec mirrors its VCW theorem
numbering in the invariant names).

Adjacent specs:
  FB57 (LightStatePersistence.tla) — the persisted-anchor CACHE this walk's resume
    branch reads. FB57's ResumeVerify action ABSTRACTS the suffix walk to a single
    {RESUMED, FALLBACK, REJECTED} verdict (its INV_ResumeNoFalseAccept: only an
    honest "extends" reaches RESUMED); THIS spec is the page-by-page REFINEMENT of
    that abstraction — it models WHY the "index0" / "fork" offerings reach REJECTED
    (the contiguity + anchored-page + walked-count gates), not just THAT they do.
    The two compose: FB57's cached anchor is FB59's StartFrom / start-anchor.
  ChainPrevHashLink.tla (FB-track) — the daemon-side prev_hash continuity sibling;
    verify_headers' chain walk (verify.cpp:212-223) is the light-client port whose
    page-level lift is this spec's "continuity_break" -> REJECT.
  FB-track MakeBlockSigPrimitive.tla — the K-of-K committee-sig check
    (verify_block_sigs) this spec abstracts to the opaque per-block "sig verifies"
    predicate the genesis-skip gate (VCW-5) decides whether to RUN.

To check (assuming TLC installed):
  $ tlc VerifyChainWalk.tla -config VerifyChainWalk.cfg
Recommended config (small + finite): two configs exercise both walk kinds —
  (genesis walk) Head = 3, StartFrom = 0, PageSize = 2;
  (resume walk)  Head = 4, StartFrom = 2, PageSize = 2.
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Head,       \* the daemon's tip height (the verified range is [StartFrom, Head))
    StartFrom,  \* walk start: 0 for from-genesis, an anchor height for a resume
    PageSize    \* page granularity (the spec-layer projection of PAGE = 256)

\* The walk is a from-genesis walk iff it starts at 0; otherwise a resume walk that
\* must chain its first page onto the persisted anchor (StartFrom > 0).
StartIsGenesis == (StartFrom = 0)

\* The total number of headers the walk MUST verify to ACCEPT (the walked-count
\* gate's target: head_height - start_from).
RangeLen == Head - StartFrom

\* Distinguished sentinels (disjoint from every numeric / record-field value).
NoneLink == "none"        \* firstLink before any page is processed
Genesis  == "genesis"     \* first page anchored block 0 to genesis_hash (from==0)
Anchor   == "anchor"      \* first page chained onto the persisted anchor (from>0)
Pending  == "PENDING"     \* no terminal decision yet
Accept   == "ACCEPT"      \* full range verified onto the start anchor
Reject   == "REJECT"      \* a gate threw (hard error)

\* The daemon's per-page offering — the nondeterministic adversarial choice
\* ServePage ranges over. Each maps to a gate verdict mirroring the code's gate
\* order (contiguity, then chain, then sig, then loop-end walked-count):
\*   "honest"           — a contiguous page of the correct width chaining onto the
\*                        running prev_anchor (the only path that can ACCEPT);
\*   "index0"           — the adversarial index-0 diversion: a resume suffix whose
\*                        FIRST header claims index 0 (to divert verify_headers into
\*                        its binding-free genesis branch). REJECTED by the
\*                        contiguity gate (got 0 != expected StartFrom) AND the
\*                        verify_headers anchored-page guard;
\*   "injected"         — some header index != its contiguous position from+i
\*                        (a non-genesis index injection). REJECTED by contiguity;
\*   "gapped"           — a page that skips an index. REJECTED by contiguity;
\*   "short_final"      — the FINAL page serves fewer headers than the remainder.
\*                        Contiguous (so it passes the per-page gate) but trips the
\*                        loop-end walked-count gate;
\*   "continuity_break" — a contiguous page whose first header's prev_hash does NOT
\*                        chain onto the running anchor. REJECTED by verify_headers'
\*                        chain check.
Offerings == {"honest", "index0", "injected", "gapped", "short_final",
              "continuity_break"}

ASSUME ConfigOK ==
    /\ Head \in Nat /\ Head >= 1
    /\ StartFrom \in Nat
    /\ StartFrom < Head             \* a non-empty range to walk
    /\ PageSize \in Nat /\ PageSize >= 1

----------------------------------------------------------------------------
\* §1. State.
\*
\* `cursor` is the next index the walk expects (the running `from`, advanced by an
\* honest page's width). `headersSeen` is the running header count (the
\* `headers_seen` accumulator). `firstLink` records the anchor the FIRST processed
\* page chained onto (Genesis / Anchor / NoneLink). `pagesProcessed` counts consumed
\* pages. `lastSkipWasGenesis` records whether the most recent honest page
\* sig-skipped a block (legal only at the genuine genesis position). `decision`
\* sequences the terminal verdict. `badShapeSeen` is the ghost flag recording any
\* contiguity violation (the INV_NoIndexInjection antecedent).

VARIABLES
    cursor,             \* Nat — the next index the walk expects (running `from`)
    headersSeen,        \* Nat — running count of verified headers
    firstLink,          \* {NoneLink, Genesis, Anchor} — the first page's anchor link
    pagesProcessed,     \* Nat — number of pages consumed
    lastSkipWasGenesis, \* BOOLEAN — did the last page sig-skip a (genesis) block
    decision,           \* {Pending, Accept, Reject}
    badShapeSeen        \* BOOLEAN — any processed page was index-injected / gapped

vars == <<cursor, headersSeen, firstLink, pagesProcessed, lastSkipWasGenesis,
          decision, badShapeSeen>>

----------------------------------------------------------------------------
\* §2. Helpers.

\* The honest width of the page starting at index `f`: min(PageSize, Head - f) —
\* exactly `want = std::min(PAGE, head_height - from)` (trustless_read.cpp:128-129).
WantAt(f) == IF Head - f < PageSize THEN Head - f ELSE PageSize

\* The walk still has range left to consume (the for-loop guard `from < head_height`,
\* trustless_read.cpp:127).
MoreToWalk == cursor < Head

\* The current page is the FIRST page of the walk (pagesProcessed = 0): the one that
\* takes the genesis-vs-anchor branch (trustless_read.cpp:161-163).
OnFirstPage == pagesProcessed = 0

----------------------------------------------------------------------------
\* §3. Initial state. Nothing walked yet: the cursor sits at StartFrom, no headers
\* seen, no first-page link recorded, no pages processed, no skip, decision pending,
\* no bad shape observed.

Init ==
    /\ cursor             = StartFrom
    /\ headersSeen        = 0
    /\ firstLink          = NoneLink
    /\ pagesProcessed     = 0
    /\ lastSkipWasGenesis = FALSE
    /\ decision           = Pending
    /\ badShapeSeen       = FALSE

----------------------------------------------------------------------------
\* §4. Actions.

\* ServeHonest: the daemon serves a CONTIGUOUS page of the correct width
\* WantAt(cursor) chaining onto the running prev_anchor. The contiguity gate passes
\* (indices are [cursor, cursor+want)), the chain check passes (first header chains
\* onto the running anchor — genesis-hash on the first from==0 page, persisted
\* anchor on the first from>0 page, running prev_anchor thereafter), and every
\* non-skipped block's K-of-K committee sig verifies. The cursor and count advance;
\* the first page records its anchor link; a block is sig-skipped IFF this is the
\* genesis position (cursor==0 on the first page). Enabled only while range remains
\* and no decision is reached.
ServeHonest ==
    /\ decision = Pending
    /\ MoreToWalk
    /\ LET want == WantAt(cursor) IN
         /\ cursor'      = cursor + want
         /\ headersSeen' = headersSeen + want
         \* First page records the genesis-vs-anchor branch it chained onto.
         /\ firstLink' = IF OnFirstPage
                         THEN (IF StartIsGenesis THEN Genesis ELSE Anchor)
                         ELSE firstLink
         \* Sig-skip fires IFF this page covers the genuine genesis position:
         \* index 0 reached with from==0 (the first page of a from-genesis walk).
         /\ lastSkipWasGenesis' = (OnFirstPage /\ StartIsGenesis /\ cursor = 0)
    /\ pagesProcessed' = pagesProcessed + 1
    /\ UNCHANGED <<decision, badShapeSeen>>

\* ServeIndexInjected: the daemon serves a page violating index-contiguity — a
\* header whose index is not its contiguous position. Three sub-cases collapse to
\* the same REJECT (the contiguity gate throws, trustless_read.cpp:146-155):
\*   "index0"   — the resume suffix's first header claims index 0 (got 0 != the
\*                expected `cursor`==StartFrom>0). The adversarial diversion: it
\*                ALSO trips the verify_headers anchored-page guard (verify.cpp:
\*                172-186) on the chain layer, but the contiguity gate fires FIRST.
\*   "injected" — a non-genesis index injection (got != cursor+i for some i).
\*   "gapped"   — the page skips an index (a got > expected hole).
\* Records badShapeSeen (the INV_NoIndexInjection antecedent) and REJECTS. Enabled
\* while range remains and no decision is reached.
ServeIndexInjected ==
    /\ decision = Pending
    /\ MoreToWalk
    /\ \E shape \in {"index0", "injected", "gapped"} :
         shape \in Offerings        \* (range over the three injection shapes)
    /\ badShapeSeen'   = TRUE
    /\ decision'       = Reject
    /\ pagesProcessed' = pagesProcessed + 1
    /\ UNCHANGED <<cursor, headersSeen, firstLink, lastSkipWasGenesis>>

\* ServeContinuityBreak: the daemon serves a CONTIGUOUS page (indices fine) whose
\* first header's prev_hash does NOT chain onto the running anchor — a fork/rollback
\* below the anchor, or a broken link mid-walk. The contiguity gate passes but
\* verify_headers' chain check (verify.cpp:202-208 first-page anchor mismatch, or
\* :212-223 inter-page break) FAILS, and verify_chain_walk throws
\* (trustless_read.cpp:164-168). REJECTS. (NOT an index injection, so badShapeSeen
\* stays as-is.) Enabled while range remains and no decision is reached.
ServeContinuityBreak ==
    /\ decision = Pending
    /\ MoreToWalk
    /\ decision'       = Reject
    /\ pagesProcessed' = pagesProcessed + 1
    /\ UNCHANGED <<cursor, headersSeen, firstLink, lastSkipWasGenesis, badShapeSeen>>

\* ServeShortFinal: the daemon serves the FINAL page (the one whose honest width
\* would close the range) but with FEWER headers than the remainder — it is
\* contiguous as far as it goes (so the per-page contiguity + chain gates pass) but
\* leaves the cursor short of Head. The walk then exits the loop with
\* headersSeen < RangeLen, and the walked-count gate (trustless_read.cpp:213-219)
\* throws on Decide. Modeled by advancing the cursor PAST Head (no more pages) while
\* leaving headersSeen short, so MoreToWalk is false and Decide sees the shortfall.
\* Enabled only on the final page (a short page that is also non-final breaks
\* prev_hash continuity at the NEXT page, already covered by ServeContinuityBreak).
ServeShortFinal ==
    /\ decision = Pending
    /\ MoreToWalk
    /\ WantAt(cursor) > 1                 \* room to serve at least one fewer
    /\ cursor'      = Head                \* loop exits (the daemon stops serving)
    /\ headersSeen' = headersSeen + (WantAt(cursor) - 1)   \* one short of the range
    /\ firstLink'   = IF OnFirstPage
                      THEN (IF StartIsGenesis THEN Genesis ELSE Anchor)
                      ELSE firstLink
    /\ pagesProcessed'     = pagesProcessed + 1
    /\ lastSkipWasGenesis' = (OnFirstPage /\ StartIsGenesis /\ cursor = 0)
    /\ UNCHANGED <<decision, badShapeSeen>>

\* Decide: the walk has consumed the range (no more pages: cursor >= Head) and runs
\* the loop-end walked-count gate (trustless_read.cpp:213-219). ACCEPT iff
\* headersSeen == RangeLen (the full range verified); otherwise REJECT (a short
\* page truncated the walk). Enabled only once the loop has exited with no prior
\* decision.
Decide ==
    /\ decision = Pending
    /\ ~MoreToWalk
    /\ IF headersSeen = RangeLen
       THEN decision' = Accept        \* walked-count gate passes: full range verified
       ELSE decision' = Reject        \* short page: headersSeen < RangeLen
    /\ UNCHANGED <<cursor, headersSeen, firstLink, pagesProcessed,
                   lastSkipWasGenesis, badShapeSeen>>

----------------------------------------------------------------------------
\* §5. Next-state relation + spec. The daemon nondeterministically serves an
\* honest or adversarial page each step; once the range is consumed (or a gate
\* throws), the walk decides.

Next ==
    \/ ServeHonest
    \/ ServeIndexInjected
    \/ ServeContinuityBreak
    \/ ServeShortFinal
    \/ Decide

\* Weak fairness on the serving + deciding actions drives Prop_EventuallyDecided:
\* the walk does not stall PENDING forever. (The adversarial serve actions are part
\* of Next but the safety invariants hold regardless of which fire; fairness is on
\* the disjunction so SOME enabled action progresses the walk to a decision.)
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(ServeHonest \/ Decide)

----------------------------------------------------------------------------
\* §6. Invariants — VCW-0..VCW-5.

\* VCW-0 / TypeOK. Shapes + bounds; the value universes are finite for TLC.
TypeOK ==
    /\ cursor             \in 0..(Head + PageSize)   \* may step one honest width past Head
    /\ headersSeen        \in 0..RangeLen
    /\ firstLink          \in {NoneLink, Genesis, Anchor}
    /\ pagesProcessed     \in Nat
    /\ lastSkipWasGenesis \in BOOLEAN
    /\ decision           \in {Pending, Accept, Reject}
    /\ badShapeSeen       \in BOOLEAN

\* VCW-2 / INV_NoIndexInjection. An index-injected or gapped page (in particular a
\* resume suffix whose FIRST index is 0 rather than StartFrom) is REJECTED, never
\* ACCEPTed: once `badShapeSeen` is set (some processed page violated contiguity),
\* the decision can never be ACCEPT. The state-form witness that the index-
\* contiguity gate (trustless_read.cpp:146-155) + the verify_headers anchored-page
\* guard (verify.cpp:172-186) close the index-0 diversion — a suffix's first index
\* must be StartFrom, not 0. (ServeIndexInjected sets badShapeSeen AND decision=
\* Reject in the same step, so badShapeSeen never coexists with ACCEPT.)
INV_NoIndexInjection ==
    badShapeSeen => (decision /= Accept)

\* VCW-3 / INV_AnchorBound. ACCEPT implies the FIRST processed page chained onto the
\* START anchor: for a from-genesis walk (StartIsGenesis) `firstLink` = Genesis (the
\* block-0 genesis-hash anchor, verify.cpp:193-201); for a resume walk `firstLink` =
\* Anchor (the persisted prev_hash anchor, verify.cpp:202-208). An ACCEPT can never
\* have firstLink = NoneLink (no page processed) or the branch for the OTHER walk
\* kind. The first-page genesis-vs-anchor branch (trustless_read.cpp:161-163).
INV_AnchorBound ==
    (decision = Accept) =>
        /\ firstLink /= NoneLink
        /\ firstLink = (IF StartIsGenesis THEN Genesis ELSE Anchor)

\* VCW-4 / INV_FullCoverage. ACCEPT implies headersSeen == RangeLen (= Head -
\* StartFrom): the entire range was walked. A short-final page (fewer headers than
\* the remainder) is therefore REJECTED — it cannot report Head as the verified tip
\* while having walked fewer blocks. The walked-count gate (trustless_read.cpp:
\* 213-219: `headers_seen != head_height - start_from => throw`).
INV_FullCoverage ==
    (decision = Accept) => (headersSeen = RangeLen)

\* VCW-5 / INV_GenesisSkipOnlyAtZero. The per-block committee-sig skip fires ONLY at
\* the genuine genesis position: `lastSkipWasGenesis` can be TRUE only when the walk
\* started at genesis (StartIsGenesis). On a resume walk (StartFrom>0) NO block is
\* skipped — every suffix block's K-of-K sig is checked, so the index-0 diversion
\* cannot buy a free (unsigned) block. The `if (idx == 0 && from == 0) continue;`
\* gate (trustless_read.cpp:181-187), whose `&& from == 0` makes the suffix walk's
\* never-skip property explicit and independent of the contiguity gate.
INV_GenesisSkipOnlyAtZero ==
    lastSkipWasGenesis => StartIsGenesis

----------------------------------------------------------------------------
\* §7. Temporal property.

\* VCW-1t / Prop_EventuallyDecided. Under fairness on ServeHonest / Decide, every
\* walk eventually reaches a TERMINAL decision (ACCEPT or REJECT); it never hangs
\* PENDING forever. The for-loop-to-head + walked-count-gate termination of
\* verify_chain_walk: the range is finite, every honest page advances the cursor,
\* and the loop exit triggers Decide. (An adversarial gate REJECTs even sooner.)
Prop_EventuallyDecided ==
    <>(decision \in {Accept, Reject})

============================================================================
\* Cross-references.
\*
\* FB57 (LightStatePersistence.tla) — the persisted-anchor CACHE this walk's resume
\*   branch reads. FB57's ResumeVerify ABSTRACTS the suffix walk to a single
\*   {RESUMED, FALLBACK, REJECTED} verdict (INV_ResumeNoFalseAccept: only an honest
\*   "extends" reaches RESUMED). THIS spec is the page-by-page REFINEMENT: it models
\*   WHY the "index0" / "fork" offerings reach REJECTED — the contiguity gate
\*   (VCW-2) + the first-page anchor branch (VCW-3) + the walked-count gate (VCW-4)
\*   + the genesis-skip-only-at-zero gate (VCW-5). FB57's cached anchor IS this
\*   spec's StartFrom / start-anchor; FB57's "extends" success IS this spec's
\*   honest-page ACCEPT.
\*
\* ChainPrevHashLink.tla — the prev_hash continuity sibling; verify_headers' chain
\*   walk (verify.cpp:212-223) is the per-pair link this spec lifts to the page
\*   level as "continuity_break" -> REJECT (ServeContinuityBreak).
\*
\* MakeBlockSigPrimitive.tla — the K-of-K committee-sig check (verify_block_sigs)
\*   this spec abstracts to the opaque per-block "sig verifies" predicate the
\*   genesis-skip gate (VCW-5) decides whether to RUN.
\*
\* Companion analytic source:
\*   docs/proofs/VerifyChainWalkSoundness.md (VCW-1..VCW-5). VCW-1 =
\*     Prop_EventuallyDecided (walk-decides); VCW-2 = INV_NoIndexInjection;
\*     VCW-3 = INV_AnchorBound; VCW-4 = INV_FullCoverage; VCW-5 =
\*     INV_GenesisSkipOnlyAtZero.
\*   docs/proofs/LightClientThreatModel.md §2 — the untrusted-daemon model the
\*     ServePage offerings range over.
\*
\* C++ enforcement:
\*   light/trustless_read.cpp:102-227 : verify_chain_walk — the single verified core
\*       (the page loop) shared by verify_chain_to_head + verify_chain_from_anchor.
\*   light/trustless_read.cpp:127      : for (from = start_from; from < head_height;
\*       from += PAGE) — the finite range loop (Prop_EventuallyDecided / VCW-1 +
\*       the MoreToWalk loop guard).
\*   light/trustless_read.cpp:128-129  : want = min(PAGE, head_height - from) — the
\*       page width WantAt(f) projects.
\*   light/trustless_read.cpp:146-155  : the INDEX-CONTIGUITY gate — `got != from + i
\*       => throw` rejects an index-0 injection (got 0 != from) AND any gap
\*       (ServeIndexInjected / INV_NoIndexInjection / VCW-2).
\*   light/trustless_read.cpp:161-163  : the first-page genesis-vs-anchor branch —
\*       `(from == 0) ? verify_headers(page, genesis_hash_hex, "")
\*       : verify_headers(page, "", prev_anchor)` (firstLink / INV_AnchorBound /
\*       VCW-3 + ServeContinuityBreak's chain check).
\*   light/trustless_read.cpp:181-187  : the GENESIS sig-skip —
\*       `if (idx == 0 && from == 0) continue;` — fires only at the genuine genesis
\*       position; the `&& from == 0` makes the resume suffix's never-skip explicit
\*       (lastSkipWasGenesis / INV_GenesisSkipOnlyAtZero / VCW-5).
\*   light/trustless_read.cpp:188-200  : the per-block K-of-K committee-sig check
\*       (verify_block_sigs, MD then BFT retry) the genesis-skip gates.
\*   light/trustless_read.cpp:213-219  : the WALKED-COUNT gate —
\*       `if (headers_seen != head_height - start_from) throw` — catches a daemon
\*       serving a short FINAL page (Decide / INV_FullCoverage / VCW-4 +
\*       ServeShortFinal).
\*   light/trustless_read.cpp:231-245  : verify_chain_to_head — the StartFrom==0
\*       (from-genesis) caller of verify_chain_walk (StartIsGenesis branch).
\*   light/trustless_read.cpp:247-273  : verify_chain_from_anchor — the
\*       StartFrom==anchor_height (resume) caller; head_height <= anchor_height =>
\*       resumed=false fallback (:255-262); else suffix-walk from anchor_block_hash
\*       (the not-StartIsGenesis branch).
\*   light/verify.cpp:135-233          : verify_headers — the per-page chain check.
\*   light/verify.cpp:169-186          : the RESUME-SOUNDNESS GATE —
\*       `if (first_index == 0) ... if (!prev_hash_hex.empty()) return FAIL` —
\*       rejects an index-0 header when a mid-chain prev_hash anchor was supplied
\*       (the verify_headers half of the index-0 diversion defense; VCW-2).
\*   light/verify.cpp:193-201          : the genesis branch — block-0 block_hash ==
\*       genesis_hash_hex (the StartFrom==0 firstLink=Genesis anchor; VCW-3).
\*   light/verify.cpp:202-208          : the from>0 first-page anchor check —
\*       first header's prev_hash == prev_hash_hex (the resume firstLink=Anchor
\*       anchor; VCW-3 + ServeContinuityBreak first-page mismatch).
\*   light/verify.cpp:212-223          : the inter-pair prev_hash chain walk
\*       (ServeContinuityBreak mid-walk break).
\*   light/verify.cpp:57-92            : light_compute_block_digest — the digest the
\*       committee-sig check (VCW-5's gated check) is taken over.
\*
\* Runtime regression:
\*   tools/test_light_verify_chain.sh + the resume-soundness adversarial cases
\*     (index-0 suffix REJECTED; gapped page REJECTED; short-final REJECTED;
\*     continuity break REJECTED; honest from-genesis + honest resume ACCEPT) —
\*     the empirical witnesses of VCW-2..VCW-5 over determ-light verify-chain
\*     (build/Release/determ-light.exe).
\*
\* Doc updates (done by the orchestrator, NOT this file):
\*   docs/proofs/README.md FB59 row — index entry (house format).
\*   CHECK-RESULTS.md FB59 row — pending TLC install.
============================================================================
