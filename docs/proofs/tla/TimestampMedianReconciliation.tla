--------------------------- MODULE TimestampMedianReconciliation ---------------------------
(*
FB-NEXT — TLA+ specification of the S-030-D2 TIMESTAMP MEDIAN RECONCILIATION
(SHIPPED, commit `f99eeb8`; analytic source docs/proofs/S030-D2-Analysis.md §5).
This is the machine-checkable companion to the "non-fix that became the fix":
the deterministic lower-median that lets `Block.timestamp` be bound into the
K-of-K committee digest WITHOUT the gossip-async divergence that killed a RAW
timestamp append.

NOTE: spec-only, model-check pending TLC install (matching every sibling in this
directory).

--------------------------------------------------------------------------
Distinct from FB29 (tla/BlockTimestampMonotonic.tla). FB29 models timestamp
MONOTONICITY across heights (the forward-looking S-035 path-1 cross-block gate +
the four-surface chain/hash/digest/signing_bytes contract pinned by
`determ test-time-monotonicity`). THIS spec models the per-block, intra-height
MEDIAN RECONCILIATION: how K committee members' divergent committed local times
collapse to one canonical deterministic value that is digest-bound and validator
re-derived. FB29's `compute_block_digest` EXCLUDES the raw timestamp; this spec
models the conditional INCLUSION of the *reconciled* median — the two are not in
tension because the digest binds the post-reconciliation lower-median (a pure
function of the K signed Phase-1 commits), never a member's pre-reconciliation
local clock. The two specs are complementary halves of the timestamp story.

--------------------------------------------------------------------------
The headline contract — the S-030-D2 §5 five-step pattern, lifted to the
state-machine layer (each step grounded in shipped source):

  1. Phase-1 COMMIT. Each committee member's `ContribMsg` carries
     `proposer_time` = its local `now_unix()` at commit time, bound into
     `make_contrib_commitment` behind the `DTM-TS-v1` domain separator — but
     ONLY when non-zero (`src/node/producer.cpp:273-276`: the
     `if (proposer_time != 0)` gate appends the separator + the time AFTER the
     F2 `DTM-F2-v1` view-root block; zero appends nothing => a byte-identical v1
     commitment). The Phase-1 Ed25519 signature over this commitment authenticates
     the committed time, so a member cannot equivocate on the time it later feeds
     into the median. In production `node.cpp` passes `now_unix()`; honest members
     are modeled as committing a time within a bounded honest window, Byzantine
     members commit ARBITRARY times.

  2. RECONCILE at the Phase-1->2 boundary. `build_body`
     (`src/node/producer.cpp:826-844`): if EVERY entry of
     `creator_proposer_times` is non-zero (the production path), the canonical
     block timestamp becomes `b.timestamp = reconcile_median_time(creator_proposer_times)`
     — the deterministic LOWER-median `sorted[(K-1)/2]`
     (`reconcile_median_time` at `producer.cpp:286-291`: copy, `std::sort`,
     return `v[(v.size()-1)/2]`; 0 for empty). Otherwise the assembler CLEARS the
     vector and keeps its wall-clock `b.timestamp` (the v1 block shape — no
     `creator_proposer_times` field, timestamp NOT digest-bound).

  3. DIGEST BIND. `compute_block_digest` (`src/node/producer.cpp:689-691`)
     appends `b.timestamp` ONLY when `creator_proposer_times` is non-empty
     (the activation signal). A legacy/pre-feature block keeps the byte-identical
     v1 digest. Field order: inbound, eq, abort, `partner_subset_hash`, timestamp.

  4. VALIDATOR CHECK. `check_creator_commits` (`src/node/validator.cpp:167-182`)
     recomputes each creator's Phase-1 commit WITH its `proposer_time` (via the
     `pt_at` lambda) so the per-creator time is sig-authenticated. `check_timestamp`
     (`src/node/validator.cpp:1315-1322`): when `creator_proposer_times` is
     non-empty it REJECTS on `size != creators`, any zero entry, or
     `b.timestamp != reconcile_median_time(creator_proposer_times)`; the existing
     `±30s` wall-clock bound (`:1324-1327`) is retained as a liveness sanity.

  5. LIGHT CLIENT. `light/verify.cpp::light_compute_block_digest` mirrors the
     append; `creator_proposer_times` survives the `rpc_headers` strip
     (`node.cpp::rpc_headers` keeps it; only transactions / cross_shard_receipts /
     inbound_receipts / initial_state are stripped) — so header-only sync stays
     sound and a daemon that tampers `b.timestamp` post-signing fails the light
     sig check. (Modeled implicitly: the validator predicate of step 4 IS the
     light client's predicate over the same digest-bound value; not a separate
     action.)

--------------------------------------------------------------------------
The Byzantine-robustness headline (MedianHonestFlanked / T-3). Under `3f < K`
the lower-median `sorted[(K-1)/2]` is an order statistic that is FLANKED BY
HONEST VALUES on both sides: at most `f` Byzantine entries sit below it and at
most `f` above, and `f < K/3 <= (K-1)/2` for `K >= 3` means index `(K-1)/2` is
neither pushed past the honest minimum nor past the honest maximum. So the
reconciled timestamp always lies within `[min honest time, max honest time]` —
a Byzantine minority cannot drag the canonical time outside the honest-clock
spread. This is the standard BFT-time median order-statistic argument, mirroring
`reconcile_median_time`'s source comment (`producer.cpp:280-285`) and
S030-D2-Analysis §5 step 2.

--------------------------------------------------------------------------
Modeling scope (kept small + finite-checkable so it COULD be model-checked later):

  * CONSTANT K = committee size. A small finite Times domain `1..MaxTime` is the
    int64_t-seconds projection bounded for TLC; the separate sentinel `NoCommit`
    marks a member whose Phase-1 commit has not yet arrived (distinct from a
    legitimate committed value of 0). f = the Byzantine-count bound; the ASSUME
    pins `3*f < K` (the BFT threshold the order-statistic argument needs).
  * The K members are partitioned into a fixed honest set Honest and a fixed
    Byzantine set Byz with `Cardinality(Byz) <= f`. Honest members commit a time
    inside a contiguous HONEST WINDOW `[WinLo, WinHi]` (the spec-layer projection
    of the `±30s` wall-clock band: honest clocks agree to within the window).
    Byzantine members commit ANY value in `ByzVals` — including 0 (which trips the
    ConditionalGate / v1 fallback) and times far outside the honest window (which
    the lower-median must resist per T-3).
  * Reconciliation is the pure function `LowerMedian` over the committed MULTISET
    (a value->count rank argument) — modeled order-independently to witness
    MedianDeterministic. The lower-median is `sorted[(K-1)/2]`, computed via the
    cumulative-rank predicate over the bounded value domain (no Sequences sort).
  * The digest binding (DigestBind) + validator re-derivation (ValidatorCheck) are
    modeled as the abstract-equality predicate `b.timestamp == LowerMedian` — the
    spec-layer projection of the `compute_block_digest` append + the
    `check_timestamp` re-derive. The abstract "hash = pre-image identity" device of
    the sibling FB-track specs is unnecessary here because the binding reduces to a
    NUMERIC equality (the median value), not a hash collision argument.
  * Phase flag `phase`: "commit" -> "reconciled" -> "bound" -> "checked". Actions are
    gated on the phase so TLC enumerates the pipeline in order. The conditional gate
    (any committed time zero => no reconciliation => v1 digest) is the
    ConditionalGate invariant + the `Reconcile` action's else-branch.

--------------------------------------------------------------------------
Invariants (mapping the §5 steps + the §5-step-2 robustness argument):

  (T-0) TypeOK — variables have the right shapes; committed values in the value
        domain or NoCommit; the phase flag is one of the four pipeline labels.
  (T-1) MedianDeterministic — the reconciled value is a PURE FUNCTION of the
        committed MULTISET (order-independent): once Reconcile has fired on the
        production path, `reconciled = LowerMedian`, and LowerMedian is defined
        solely over the value->count rank function (no member ordering / arrival
        sequence appears). The state-machine witness that `std::sort` in
        `reconcile_median_time` makes arrival order irrelevant (every honest
        assembler computes the identical value — the no-gossip-async-divergence
        property §5 step 2 rests on).
  (T-2) MedianIsACommittedValue — the lower-median is always one of the K committed
        times (the `sorted[(K-1)/2]` order statistic is an element of the multiset,
        never an interpolated average), so the result is an exact integer second —
        the structural reason `reconcile_median_time` returns a `uint64_t` element,
        not a mean. Also pins LowerMedian's well-definedness (the rank-RankIdx
        element exists).
  (T-3) MedianHonestFlanked — THE Byzantine-robustness headline. Whenever
        reconciliation fired (all committed times non-zero), was not tampered, and
        `3*f < K`, the reconciled timestamp lies within `[min honest committed,
        max honest committed]`. A Byzantine minority `<= f` cannot bias the
        lower-median past the honest-clock spread. Mirrors
        `reconcile_median_time`'s order-statistic comment + S030-D2-Analysis §5.
  (T-4) DigestBindsMedian — once bound + checked, the validator accepts IFF
        `b.timestamp == LowerMedian(committed)`. A tampered `b.timestamp` (≠ the
        re-derived median) is rejected — the exact `check_timestamp` predicate
        `if (b.timestamp != reconcile_median_time(...)) return {false, ...}`.
  (T-5) ConditionalGate — if ANY committed time is zero (legacy / pre-activation /
        test), reconciliation does NOT fire: `creator_proposer_times` is cleared,
        the canonical timestamp stays the assembler wall-clock, the digest is the
        v1 (unbound) shape. The state-form witness of the §5 backward-compat
        boundary — every non-reconciled block byte-identical to v1.

A temporal property pins the eventual-pipeline-progress claim:
  (T-6) Prop_EventuallyChecked — under fairness on the pipeline actions, a round
        that committed all-non-zero times eventually reaches the "checked" phase
        with `accepted = TRUE` and `b.timestamp = LowerMedian` — the standing
        ~> claim that an honest (untampered) reconciled round finalizes.

--------------------------------------------------------------------------
Companion analytic source: `docs/proofs/S030-D2-Analysis.md` §5 (the SHIPPED
timestamp-inclusion fix, commit `f99eeb8`).

Adjacent specs:
  FB29 (tla/BlockTimestampMonotonic.tla) — timestamp MONOTONICITY across heights +
    the digest-EXCLUDES-raw-timestamp contract; THIS spec is the orthogonal
    per-block MEDIAN-RECONCILIATION half (digest INCLUDES the reconciled median).
  FB22 (tla/F2ViewReconciliation.tla) — the SET-valued (union/intersection) F2
    reconciliation this spec's NUMERIC median runs in parallel with (S030-D2-Analysis
    §5: "the same Phase-1-commit-then-reconcile pattern ... just with a numeric
    median instead of a set union/intersection"). `make_contrib_commitment` binds
    the `DTM-TS-v1` time AFTER the `DTM-F2-v1` view-root block.
  FB24 (tla/MakeContribCommitment.tla) — the S-030-D2 Phase-1 commit-binding this
    spec's COMMIT action's `proposer_time != 0` gate extends (the `DTM-TS-v1`
    append is the timestamp sibling of FB24's commit shape).
  EqAbortViewDigestExtension.md (FB-track design record) — the eq/abort UNION
    digest-binding whose carry->reconcile->digest pattern this numeric-median
    binding mirrors field-for-field (inbound INTERSECTION, eq/abort UNION,
    timestamp MEDIAN).

To check (assuming TLC installed):
  $ tlc TimestampMedianReconciliation.tla -config TimestampMedianReconciliation.cfg
Recommended config (small + finite): K = 4, f = 1 (3*1 < 4), MaxTime = 6,
  Honest = {c0, c1, c2}, Byz = {c3}, WinLo = 2, WinHi = 4,
  ByzVals = {0, 1, 5, 6}  (0 trips ConditionalGate; 1/5/6 are out-of-window
  outliers the median must resist).
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    K,          \* committee size = number of members committing a time
    f,          \* Byzantine-count bound (ASSUME 3*f < K)
    MaxTime,    \* upper bound on the finite Times domain (int64_t-seconds projection)
    Honest,     \* the fixed set of honest committee members
    Byz,        \* the fixed set of Byzantine committee members
    WinLo,      \* lower bound of the honest-clock window (the ±30s band projection)
    WinHi,      \* upper bound of the honest-clock window
    ByzVals     \* the finite set of values a Byzantine member may commit (incl. 0)

\* The committee member id set and the value domains.
Members      == Honest \cup Byz
HonestVals   == WinLo..WinHi              \* honest commits: in-window, all >= 1
NoCommit     == "no-commit"               \* sentinel: this member has not committed yet
\* The set of legitimate committed VALUES (0 = legacy/test zero; 1..MaxTime = a time).
CommittedVals == (0..MaxTime)

ASSUME ConfigOK ==
    /\ K \in Nat /\ K >= 3
    /\ f \in Nat
    /\ 3 * f < K                                \* the BFT threshold the median needs
    /\ MaxTime \in Nat /\ MaxTime >= 1
    /\ Honest \cap Byz = {}                      \* disjoint partition
    /\ Cardinality(Members) = K                  \* the partition covers exactly K members
    /\ Cardinality(Byz) <= f                     \* at most f Byzantine
    /\ Cardinality(Honest) >= K - f
    /\ WinLo \in Nat /\ WinHi \in Nat
    /\ 1 <= WinLo /\ WinLo <= WinHi /\ WinHi <= MaxTime
       \* honest times are non-zero (>= 1) so an all-honest contribution is always
       \* part of a reconcilable round; the zero value is reserved for the
       \* Byzantine / pre-activation fallback signal (ConditionalGate / T-5).
    /\ ByzVals \subseteq CommittedVals
    /\ Cardinality(Honest) >= 1                  \* HonestTimes non-empty (T-3 min/max defined)

----------------------------------------------------------------------------
\* §1. State.
\*
\* `committed` maps each member to its committed value, or NoCommit if its Phase-1
\* commit has not yet arrived. A Byzantine 0-commit (legitimate, trips the v1 gate)
\* is therefore distinct from an unscheduled slot. `reconciled` is the canonical
\* block timestamp the assembler computed; `bound` records whether the digest bound
\* it (the §5-step-3 conditional append); `wallclock` is the assembler's local clock
\* fallback used on the v1 (non-reconciled) path; `accepted` is the validator
\* verdict; `phase` sequences the pipeline.

VARIABLES
    committed,      \* function Members -> (CommittedVals \cup {NoCommit})
    reconciled,     \* CommittedVals — the canonical b.timestamp after Reconcile
    bound,          \* BOOLEAN — did compute_block_digest append b.timestamp
    wallclock,      \* HonestVals — the assembler wall-clock fallback (v1 path)
    accepted,       \* BOOLEAN — the validator's check_timestamp verdict
    phase           \* {"commit", "reconciled", "bound", "checked"}

vars == <<committed, reconciled, bound, wallclock, accepted, phase>>

----------------------------------------------------------------------------
\* §2. Helpers.

\* Every member has committed SOME value (no slot still at NoCommit). The readiness
\* gate for Reconcile — a Byzantine 0-commit counts as committed (it is not NoCommit).
AllActed == \A m \in Members : committed[m] # NoCommit

\* Every committed value is non-zero — the §5-step-2 "all_set" production signal
\* that fires reconciliation. A single zero (legacy / pre-activation / test member,
\* always a Byzantine slot here since honest commits are >= WinLo >= 1) falsifies
\* this and routes to the v1 fallback (ConditionalGate / T-5).
AllNonZero == AllActed /\ \A m \in Members : committed[m] # 0

\* Count of members whose committed value is exactly `t` (the committed MULTISET
\* represented by its value->count function — order-independent by construction,
\* the witness for MedianDeterministic / T-1). Only meaningful once AllActed.
CountEq(t)  == Cardinality({ m \in Members : committed[m] = t })

\* Cumulative rank: count of members whose committed value is <= `t`.
CountLeq(t) == Cardinality({ m \in Members : committed[m] # NoCommit /\ committed[m] <= t })

\* 0-indexed lower-median position sorted[(K-1)/2].
RankIdx == (K - 1) \div 2

\* LowerMedian: the deterministic lower-median sorted[(K-1)/2] of the K committed
\* values, via the cumulative-rank predicate (no sort needed). The lower-median is
\* the value t occupying sorted position RankIdx (0-indexed): the minimal t whose
\* cumulative count CountLeq(t) strictly exceeds RankIdx. This is byte-for-byte the
\* order statistic `reconcile_median_time` returns: v[(v.size()-1)/2] after
\* std::sort. A pure function of `committed` (hence of the value->count multiset),
\* so manifestly order-independent. Well-defined whenever AllActed (every position
\* 0..K-1 is occupied; T-2 is the well-definedness witness). Used only on the
\* AllNonZero production path (Reconcile gates on it).
LowerMedian ==
    CHOOSE t \in CommittedVals :
        /\ CountLeq(t) > RankIdx
        /\ \/ t = 0
           \/ CountLeq(t - 1) <= RankIdx

\* Honest committed times (the spread the median must stay within under T-3). Defined
\* only once every honest member has committed; honest commits are always in
\* HonestVals (>= 1), so this is a non-empty set of times.
HonestTimes == { committed[m] : m \in Honest }
MinHonest   == CHOOSE x \in HonestTimes : \A y \in HonestTimes : x <= y
MaxHonest   == CHOOSE x \in HonestTimes : \A y \in HonestTimes : x >= y

\* Ghost predicate: the round has been tampered iff reconciliation fired (AllNonZero,
\* past "commit") yet the canonical timestamp differs from the deterministic median.
\* Pure function of state; scopes the honest-path invariants T-2 / T-3 / T-6.
Tampered == /\ phase \in {"reconciled", "bound", "checked"}
            /\ AllNonZero
            /\ reconciled # LowerMedian

----------------------------------------------------------------------------
\* §3. Initial state. No member has committed (all NoCommit); nothing reconciled or
\* bound; the assembler holds some in-window wall-clock value; the verdict is unset;
\* the pipeline is at "commit".

Init ==
    /\ committed  = [m \in Members |-> NoCommit]
    /\ reconciled = 0
    /\ bound      = FALSE
    /\ wallclock  \in HonestVals          \* the assembler's local clock at build time
    /\ accepted   = FALSE
    /\ phase       = "commit"

----------------------------------------------------------------------------
\* §4. Actions.

\* CommitHonest(m, t): honest member m commits a time t inside the honest window
\* [WinLo, WinHi] (the ±30s band projection; honest clocks agree to within it).
\* Bound into the Phase-1 Ed25519 commitment (modeled abstractly: the committed
\* value is fixed once set — one-shot — so a member cannot equivocate on the time it
\* feeds the median; the §1 / §5-step-1 sig-authentication). Enabled only in
\* "commit" phase, only for a member that has not yet committed.
CommitHonest(m, t) ==
    /\ phase = "commit"
    /\ m \in Honest
    /\ committed[m] = NoCommit
    /\ t \in HonestVals
    /\ committed' = [committed EXCEPT ![m] = t]
    /\ UNCHANGED <<reconciled, bound, wallclock, accepted, phase>>

\* CommitByz(m, v): Byzantine member m commits an ARBITRARY value v in ByzVals —
\* including 0 (which trips the ConditionalGate / v1 fallback) and times far outside
\* the honest window (which the lower-median must resist per T-3). One-shot: once
\* committed, the value is fixed (the Phase-1 sig binds it, so even a Byzantine
\* member is committed to ONE value per round — it cannot present different times to
\* different honest assemblers, which is what makes the reconciliation input
\* identical across honest members).
CommitByz(m, v) ==
    /\ phase = "commit"
    /\ m \in Byz
    /\ committed[m] = NoCommit
    /\ v \in ByzVals
    /\ committed' = [committed EXCEPT ![m] = v]
    /\ UNCHANGED <<reconciled, bound, wallclock, accepted, phase>>

\* Reconcile: the Phase-1->2 boundary step in build_body. Once EVERY member has
\* committed (AllActed — no slot at NoCommit), the assembler runs the §5-step-2
\* "all_set" gate:
\*   - all committed values non-zero (AllNonZero) => reconciled = LowerMedian (the
\*     production reconciliation path); the canonical timestamp is the deterministic
\*     lower-median of the K committed times.
\*   - any committed value zero                   => v1 fallback: reconciled stays
\*     the assembler wall-clock, creator_proposer_times is conceptually cleared
\*     (bound then stays FALSE in DigestBind), timestamp NOT digest-bound.
Reconcile ==
    /\ phase = "commit"
    /\ AllActed
    /\ IF AllNonZero
       THEN reconciled' = LowerMedian        \* production: canonical = lower-median
       ELSE reconciled' = wallclock          \* v1 fallback: keep the wall-clock
    /\ phase' = "reconciled"
    /\ UNCHANGED <<committed, bound, wallclock, accepted>>

\* DigestBind: compute_block_digest appends b.timestamp ONLY when
\* creator_proposer_times is non-empty (AllNonZero — the activation signal). On the
\* v1 fallback path (some zero) the append is skipped and the digest keeps its
\* byte-identical v1 shape. `bound` records which path fired.
DigestBind ==
    /\ phase = "reconciled"
    /\ bound' = AllNonZero            \* TRUE => median bound into digest; FALSE => v1 digest
    /\ phase' = "bound"
    /\ UNCHANGED <<committed, reconciled, wallclock, accepted>>

\* ValidatorCheck: check_timestamp re-derives the median from creator_proposer_times
\* and accepts IFF b.timestamp equals it. On the reconciled path the verdict is
\* exactly `reconciled = LowerMedian`; on the v1 path (creator_proposer_times empty)
\* the median predicate is skipped and the block is admitted on the ±30s wall-clock
\* bound alone (modeled as `reconciled = wallclock`, the assembler's in-window
\* value). A TAMPERED timestamp (reconciled # LowerMedian on the bound path) yields
\* accepted = FALSE — the §5-step-4 reject, witnessed by DigestBindsMedian / T-4.
ValidatorCheck ==
    /\ phase = "bound"
    /\ IF bound
       THEN accepted' = (reconciled = LowerMedian)   \* reconciled path: median match
       ELSE accepted' = (reconciled = wallclock)      \* v1 path: wall-clock admit
    /\ phase' = "checked"
    /\ UNCHANGED <<committed, reconciled, bound, wallclock>>

\* Tamper: an adversarial assembler / relayer overwrites the canonical timestamp
\* with a value OTHER than the deterministic median, before validation. Models the
\* §5-step-4 attack the validator defeats: a tampered b.timestamp that no longer
\* equals reconcile_median_time(creator_proposer_times). Enabled on the reconciled
\* (all-non-zero) path between Reconcile and ValidatorCheck. The validator MUST
\* reject (accepted = FALSE) — witnessed by DigestBindsMedian / T-4. NOT fair (it is
\* an optional adversarial step the safety invariants tolerate, not required for
\* liveness).
Tamper ==
    /\ phase \in {"reconciled", "bound"}
    /\ AllNonZero
    /\ \E bad \in CommittedVals :
          /\ bad # LowerMedian
          /\ reconciled' = bad
    /\ UNCHANGED <<committed, bound, wallclock, accepted, phase>>

----------------------------------------------------------------------------
\* §5. Next-state relation + spec. The commit fan-in, then the deterministic
\* pipeline. Tamper is interleaved to exercise the validator gate.

Next ==
    \/ \E m \in Honest, t \in HonestVals : CommitHonest(m, t)
    \/ \E m \in Byz,    v \in ByzVals    : CommitByz(m, v)
    \/ Reconcile
    \/ DigestBind
    \/ ValidatorCheck
    \/ Tamper

\* Weak fairness on the deterministic pipeline actions drives
\* Prop_EventuallyChecked: once all members have committed, Reconcile -> DigestBind
\* -> ValidatorCheck fire to completion. Tamper is NOT fair (an optional adversarial
\* step, not a liveness requirement).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Reconcile)
    /\ WF_vars(DigestBind)
    /\ WF_vars(ValidatorCheck)

----------------------------------------------------------------------------
\* §6. Invariants — T-0..T-5.

\* T-0 / TypeOK. Shapes + bounds.
TypeOK ==
    /\ committed  \in [Members -> (CommittedVals \cup {NoCommit})]
    /\ reconciled \in CommittedVals
    /\ bound      \in BOOLEAN
    /\ wallclock  \in HonestVals
    /\ accepted   \in BOOLEAN
    /\ phase       \in {"commit", "reconciled", "bound", "checked"}

\* T-1 / MedianDeterministic. The reconciled value is a PURE FUNCTION of the
\* committed MULTISET — order-independent. Once Reconcile has fired on the
\* production path (AllNonZero) and the round is untampered, `reconciled` equals
\* LowerMedian, which is defined SOLELY over the cumulative-rank (CountLeq) function
\* of `committed` — no member ordering / arrival sequence appears anywhere in its
\* definition. The state-form witness that `std::sort` in reconcile_median_time
\* erases arrival order: two honest assemblers with the same K signed commits
\* compute the identical canonical timestamp (the no-gossip-async-divergence
\* property §5 step 2 rests on). The observable safety face — that the value sits
\* at rank RankIdx and is a committed element — is pinned jointly with T-2.
MedianDeterministic ==
    (phase \in {"reconciled", "bound", "checked"} /\ AllNonZero /\ ~Tampered)
      => /\ reconciled = LowerMedian
         /\ CountLeq(reconciled)     > RankIdx
         /\ \/ reconciled = 0
            \/ CountLeq(reconciled - 1) <= RankIdx

\* T-2 / MedianIsACommittedValue. When reconciliation fired (AllNonZero) and the
\* round is untampered, the canonical timestamp is ALWAYS one of the K committed
\* times (an order statistic, never an interpolated average) — the structural reason
\* reconcile_median_time returns a uint64_t element of its input. Also the
\* well-definedness witness for LowerMedian (the rank-RankIdx element exists).
MedianIsACommittedValue ==
    (phase \in {"reconciled", "bound", "checked"} /\ AllNonZero /\ ~Tampered)
      => \E m \in Members : reconciled = committed[m]

\* T-3 / MedianHonestFlanked. THE Byzantine-robustness headline. Whenever
\* reconciliation fired (AllNonZero), the round is untampered, and 3*f < K, the
\* reconciled timestamp lies within the honest-committed spread [MinHonest,
\* MaxHonest]. Under 3*f < K the lower-median order statistic at index (K-1) \div 2
\* is flanked by honest values on both sides — at most f Byzantine entries below and
\* at most f above, and f < K/3 <= (K-1)/2 (for K >= 3) means the rank-RankIdx
\* element cannot be a Byzantine outlier beyond the honest min/max. So a Byzantine
\* minority cannot drag the canonical time outside the honest-clock band. The
\* state-machine lift of reconcile_median_time's order-statistic comment
\* (producer.cpp:280-285) + S030-D2-Analysis §5 step 2.
MedianHonestFlanked ==
    (phase \in {"reconciled", "bound", "checked"} /\ AllNonZero /\ ~Tampered)
      => /\ reconciled >= MinHonest
         /\ reconciled <= MaxHonest

\* T-4 / DigestBindsMedian. Once the validator has run (phase = "checked") on the
\* bound (reconciled) path, it accepts IFF the canonical timestamp equals the
\* re-derived lower-median — the exact check_timestamp predicate. A tampered
\* timestamp (reconciled # LowerMedian) is REJECTED (accepted = FALSE). On the v1
\* fallback path (~bound) the median check is skipped and acceptance rests on the
\* wall-clock equality instead (the ±30s sanity bound).
DigestBindsMedian ==
    (phase = "checked" /\ bound)
      => (accepted <=> (reconciled = LowerMedian))

\* T-5 / ConditionalGate. If ANY committed value is zero (legacy / pre-activation /
\* test member), reconciliation does NOT bind: the digest stays the v1 shape
\* (bound = FALSE) and the canonical timestamp is the assembler wall-clock, NOT a
\* median. The state-form witness of the §5 backward-compat boundary — every
\* non-reconciled (some-zero) round keeps the byte-identical v1 digest. Scoped to
\* phases at/after the bind decision (before DigestBind, `bound` holds its prior
\* value and the v1/median split has not yet been recorded).
ConditionalGate ==
    (phase \in {"bound", "checked"} /\ AllActed /\ ~AllNonZero)
      => /\ bound = FALSE                 \* v1 digest: timestamp NOT bound
         /\ reconciled = wallclock        \* canonical timestamp is the wall-clock fallback

----------------------------------------------------------------------------
\* §7. Temporal property.

\* T-6 / Prop_EventuallyChecked. Under fairness on the pipeline actions, a round
\* that committed all-non-zero times and reconciled to the lower-median eventually
\* reaches the "checked" phase having ACCEPTED that canonical value (in the absence
\* of a Tamper step, which is not fair). The standing leads-to claim that an honest
\* (untampered) reconciled round finalizes on the deterministic median.
Prop_EventuallyChecked ==
    (AllNonZero /\ phase = "reconciled" /\ reconciled = LowerMedian)
      ~> (phase = "checked" /\ accepted /\ reconciled = LowerMedian)

============================================================================
\* Cross-references.
\*
\* FB29 (BlockTimestampMonotonic.tla) — timestamp MONOTONICITY across heights +
\*   the four-surface chain/hash/digest/signing_bytes contract; its
\*   INV_DigestExcludesTimestamp (T-2) pins that the RAW timestamp is NOT digested.
\*   THIS spec is the complementary half: the digest INCLUDES the RECONCILED median
\*   (a pure function of the K signed commits), so the two are not in tension —
\*   FB29 forbids binding a member's local clock; FB-NEXT binds the committee-agreed
\*   lower-median. Together they cover the full Block.timestamp story.
\*
\* FB22 (F2ViewReconciliation.tla) — the SET-valued (union/intersection) F2
\*   reconciliation this NUMERIC median runs alongside. S030-D2-Analysis §5: "the
\*   same Phase-1-commit-then-reconcile pattern ... just with a numeric median
\*   instead of a set union/intersection." make_contrib_commitment binds the
\*   DTM-TS-v1 time AFTER the DTM-F2-v1 view-root block (producer.cpp:262-276).
\*
\* FB24 (MakeContribCommitment.tla) — the S-030-D2 Phase-1 commit-binding; this
\*   spec's CommitHonest/CommitByz one-shot commitment (a member is fixed to ONE
\*   value per round) is the timestamp sibling of FB24's commit-shape binding.
\*
\* Companion analytic source:
\*   docs/proofs/S030-D2-Analysis.md §5 (SHIPPED timestamp inclusion, commit
\*     f99eeb8) — the five-step pattern this spec's actions lift to the state-machine
\*     layer; MedianHonestFlanked = §5 step-2 order-statistic robustness;
\*     DigestBindsMedian = §5 step-3 + step-4; ConditionalGate = §5 backward-compat.
\*   docs/proofs/EqAbortViewDigestExtension.md — the eq/abort UNION carry->reconcile
\*     ->digest pattern this numeric-median binding mirrors field-for-field.
\*
\* C++ enforcement:
\*   src/node/producer.cpp:286-291  : reconcile_median_time — deterministic
\*       LOWER-median sorted[(v.size()-1)/2]; 0 for empty (LowerMedian / T-1 / T-2).
\*   src/node/producer.cpp:267-276  : make_contrib_commitment — DTM-TS-v1 append of
\*       proposer_time ONLY when non-zero (the CommitHonest/CommitByz binding +
\*       the v1 byte-identical short-circuit feeding ConditionalGate / T-5).
\*   src/node/producer.cpp:826-844  : build_body — the all_set gate: all non-zero
\*       => b.timestamp = reconcile_median_time(...); else clear the vector + keep
\*       the wall-clock (Reconcile action, both branches; ConditionalGate / T-5).
\*   src/node/producer.cpp:689-691  : compute_block_digest — append b.timestamp
\*       ONLY when creator_proposer_times non-empty (DigestBind / T-5). Field order:
\*       inbound, eq, abort, partner_subset_hash, timestamp.
\*   src/node/validator.cpp:167-182 : check_creator_commits — recompute each
\*       creator's commit WITH its proposer_time (the per-member sig-authentication
\*       that makes the median inputs unforgeable; the CommitHonest/CommitByz
\*       one-shot binding).
\*   src/node/validator.cpp:1315-1322 : check_timestamp — reject size!=creators /
\*       any zero entry / b.timestamp != reconcile_median_time(...) (ValidatorCheck +
\*       DigestBindsMedian / T-4 + the Tamper-defeat).
\*   include/determ/chain/block.hpp Block::creator_proposer_times (uint64[]);
\*       src/chain/block.cpp:446-449 (to_json) + :586-588 (from_json) emit/read it
\*       only when present (the v1 byte-identity boundary; ConditionalGate / T-5).
\*   light/verify.cpp::light_compute_block_digest : mirrors the append; the field
\*       survives the rpc_headers strip (header-only sync stays sound — the §5
\*       step-5 light-client soundness, modeled as the same predicate over the
\*       digest-bound value in ValidatorCheck).
\*
\* Runtime regressions:
\*   determ test-timestamp-reconciliation (16 assertions; src/main.cpp ~29951-30048)
\*     — reconcile_median_time order statistic + the digest gate (bound iff
\*     creator_proposer_times present) + the make_contrib_commitment gate
\*     (proposer_time bound iff non-zero). The analytic source this spec lifts.
\*   determ test-block-digest (26 assertions) — the digest-binding half (timestamp
\*     BOUND when creator_proposer_times present; NOT bound when empty).
\*   FAST=1 158->159 PASS — every non-reconciled block byte-identical (ConditionalGate
\*     / T-5 backward-compat witness; zero existing digests changed by f99eeb8).
\*
\* Doc updates:
\*   docs/proofs/README.md FB-NEXT row — index entry (house format).
\*   CHECK-RESULTS.md FB-NEXT row — pending TLC install.
============================================================================
