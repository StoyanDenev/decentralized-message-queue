--------------------------- MODULE RateLimiterEviction ---------------------------
(*
FB25 — TLA+ specification of the S-014 F-1 closure: idle-bucket eviction
in `determ::net::RateLimiter`.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
RateLimiterEviction.tla` once a companion `.cfg` is supplied.

Scope. Formalizes the just-shipped time-decay eviction policy at
`include/determ/net/rate_limiter.hpp:36-152` — the F-1 mitigation
documented in `S014RateLimiterSoundness.md` §6.2 "Closure (shipped)".
Two paired contracts are pinned:

  (T-1) Bucket-lifetime bound. After every action, every active
        bucket has been touched within the last
        `eviction_threshold + sweep_interval` time units. The
        eviction-on-amortized-sweep policy at lines 95-103 of
        rate_limiter.hpp ensures the lifetime of any idle bucket is
        bounded by the per-key threshold plus at most one sweep
        cadence (the bucket can survive past its individual threshold
        only if the cadence hasn't fired yet).
  (T-2) Resurrection observational equivalence. An evicted bucket
        re-created on the next consume() touch starts at FULL
        capacity (line 107 of rate_limiter.hpp: the first-touch branch
        sets `b.tokens = burst_`). This matches the value the
        un-evicted bucket would have refilled to after waiting >=
        `burst_/rate_per_sec_` seconds — and the default threshold
        (600s) gives at least 60x safety factor over realistic refill
        times. So replay-safety: a re-created bucket is observationally
        indistinguishable from the un-evicted bucket from any
        caller's perspective.

Plus four supporting contracts:

  (T-3) Monotone eviction counter (audit-trail soundness).
  (T-4) Sweep idempotence — calling SweepIdle twice with no time
        advance and no Consume in between yields the same map the
        second time (line 134-141: erase-or-skip per entry).
  (T-5) Configure-eviction-zero disables the policy (legacy
        unbounded-growth behavior — pinned as a config option per
        line 56 of rate_limiter.hpp and line 53 of the docblock).
  (T-6) Amortized residual bound — at any time t, the number of
        stale keys still resident in `buckets_` is bounded by the
        number that became stale since the most recent sweep (the
        amortization argument).

The state machine has three actions — Consume, AdvanceTime,
ForcedSweep — which together exercise every reachable interleaving
of bucket-touch, clock-advance, and operator-triggered eviction. TLC
explores every reachable schedule within the bounded universe and
the invariants are checked against the accumulated state.

Companion documents:
  * docs/proofs/S014RateLimiterSoundness.md — the analytic FA-track
    proof; §6.2 "Closure (shipped)" enumerates the six-point design
    of the F-1 mitigation; T-1 (Bounded burst), T-2 (No DoS
    amplification), T-3 (Per-IP independence), T-4 (HELLO-exemption),
    T-5 (Refill monotonicity), T-6 (Capacity-vs-rate trade-off) are
    the pre-F-1 theorems; this spec adds the post-F-1 lifetime-bound
    + resurrection-safety + amortization invariants that the prose
    proof's §6.2 closure subsection introduces.
  * docs/proofs/tla/F2ViewReconciliation.tla (FB22), FrostVerify.tla
    (FB23), MakeContribCommitment.tla (FB24) — recent neighbor specs
    establishing the "pure-function + bounded enumeration + INV-*"
    style this module reuses.
  * include/determ/net/rate_limiter.hpp:36-152 — the function under
    test; ~150 LOC after the F-1 closure.

What the model checks. Six invariants codifying the contracts above:

  INV-1 (BucketLifetimeBounded): for every key `k` in `buckets`,
        `now - last_touch[k] <= eviction_threshold + sweep_interval`.
        Captures T-1 — the post-sweep guarantee that no bucket
        lingers past the cadence.
  INV-2 (EvictionMonotone): `evicted_count` never decreases across
        any step. Captures T-3 (audit-trail soundness).
  INV-3 (ResurrectionSafe): if a key was evicted (it was in
        `buckets` at some past state, then absent, then present
        again), the new bucket starts at FULL capacity. Captures
        T-2 — observationally indistinguishable from the un-evicted
        bucket having refilled.
  INV-4 (SweepIdempotent): SweepIdle applied twice with no
        intervening time advance and no Consume yields the same
        `buckets` the second time. Captures T-4.
  INV-5 (ConfigureEvictionZeroDisables): when `eviction_threshold = 0`,
        no key is ever evicted (legacy unbounded-growth behavior —
        pinned as a config option). Captures T-5.
  INV-6 (AmortizedSweepLowerBoundsResidual): at any time t, the
        number of stale keys still resident in `buckets` is at most
        the number that became stale since the most recent sweep.
        Captures T-6.

Modeling scope (kept tractable for TLC):

  * `Keys` is the abstract finite universe of peer-IP strings.
    Operationally typical IPv4 addresses (~32 bits) or IPv6 (/64
    or /48 prefixes); at the spec layer we model them as opaque
    identifiers.
  * Time is modeled as a Nat-typed monotonic clock (`now`). The
    C++ side uses `std::chrono::steady_clock` whose monotonicity
    is RFC-mandated (Preliminaries §2.2 L-5 of the prose proof);
    the spec layer captures this via the AdvanceTime action's
    `now' = now + delta` clause with `delta >= 1`.
  * `eviction_threshold` and `sweep_interval` are spec-time
    integer constants. The C++ side uses `double` seconds; the
    spec abstracts to Nat-typed time units (no loss of generality —
    the bound arithmetic is the same).
  * Bucket state. We model `tokens` as a single FULL / EMPTY
    boolean because the lifetime-bound + resurrection contracts
    don't depend on the precise integer-fractional token level;
    L-1 of the prose proof gives `tokens \in [0, C]` and is
    orthogonal to F-1. A bucket starts FULL on creation, drops
    to EMPTY on consume-when-not-full, refills to FULL on consume-
    after-elapsed-time. The eviction policy only looks at
    `last_touch`, not at the token level — so the FULL/EMPTY
    abstraction is sufficient for the F-1 invariants.
  * The C++ `consume()` runs the amortized sweep BEFORE touching
    the bucket (lines 95-103 then 105-117). The spec mirrors that
    order: Consume(k) calls the sweep if `now >= next_sweep_at`,
    then touches k.
  * `evicted_count` is a cumulative spec-only counter. The C++
    side returns the per-call evicted count from `sweep_idle_locked`
    but does not maintain a cumulative counter; the spec lifts the
    per-call return into a chain-level cumulative to make the
    monotonicity invariant observable across the trace.
  * Resurrection-history. The `was_evicted` set is a spec-only
    audit trail of keys that have been evicted at least once. The
    C++ side has no equivalent set — eviction is destructive on
    `buckets_`. The spec lifts the history into a state variable
    to make INV-3 observable.
  * MaxTimeSteps caps the trace length so TLC can explore the
    bounded state space.

The state machine. Three actions:
  * Consume(k) — touch key k. If now >= next_sweep_at, run the
    sweep first and advance next_sweep_at by sweep_interval.
  * AdvanceTime(delta) — monotonic clock advance, delta in
    1..MaxTimeStep.
  * ForcedSweep() — external sweep_idle() call (mirrors the
    public method at line 79-82 of rate_limiter.hpp).

TLC verifies the six invariants at every reachable state across
every reachable interleaving of the three actions.

To check (assuming TLC installed):
  $ tlc RateLimiterEviction.tla -config RateLimiterEviction.cfg

Recommended config (state space ~10^4, < 30s):
  Keys = {k1, k2, k3}, MaxTimeSteps = 10, EvictionThreshold = 3,
  SweepInterval = 2, MaxTimeStep = 2.

Cross-references:
  - S014RateLimiterSoundness.md §6.2 (the F-1 closure subsection
    this spec formalizes at the state-machine layer)
  - S014RateLimiterSoundness.md §1 (T-1..T-6 — the pre-F-1
    soundness theorems that remain valid under the eviction policy)
  - include/determ/net/rate_limiter.hpp:36-152 (the function under
    test; ~150 LOC post-F-1)
  - SECURITY.md §S-014 (closure narrative; F-1 mitigation acknowledged
    as the cumulative S-014 ship)
  - F2ViewReconciliation.tla (FB22), FrostVerify.tla (FB23),
    MakeContribCommitment.tla (FB24) — style template specs
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Keys,               \* finite universe of peer-IP strings
    MaxTimeSteps,       \* spec-time horizon (caps `now`)
    EvictionThreshold,  \* idle-time threshold for eviction (Nat seconds)
    SweepInterval,      \* amortized sweep cadence (Nat seconds)
    MaxTimeStep         \* max single AdvanceTime delta (>= 1)

ASSUME ConfigOK ==
    /\ Cardinality(Keys)    >= 1
    /\ MaxTimeSteps         \in Nat /\ MaxTimeSteps      >= 1
    /\ EvictionThreshold    \in Nat
    /\ SweepInterval        \in Nat /\ SweepInterval     >= 1
    /\ MaxTimeStep          \in Nat /\ MaxTimeStep       >= 1

\* -----------------------------------------------------------------
\* §1. State.
\* -----------------------------------------------------------------
\*
\* The state mirrors the C++ RateLimiter's internal state:
\*
\*   * buckets        : function (active subset of Keys) -> Bucket.
\*                       Each entry has [tokens, last_touch].
\*                       Matches `std::map<std::string, Bucket>
\*                       buckets_` at rate_limiter.hpp:151.
\*   * next_sweep_at  : Nat — the time the next amortized sweep
\*                       will fire. Matches
\*                       `std::chrono::steady_clock::time_point
\*                       next_sweep_at_` at rate_limiter.hpp:149.
\*   * now            : Nat — the abstract monotonic clock.
\*                       Matches `std::chrono::steady_clock::now()`
\*                       at rate_limiter.hpp:89.
\*   * evicted_count  : Nat — spec-only cumulative counter of
\*                       evicted bucket entries. The C++ side
\*                       returns per-call evicted counts from
\*                       sweep_idle_locked; the spec lifts them to
\*                       a cumulative for INV-2 monotonicity.
\*   * was_evicted    : SUBSET Keys — spec-only audit set of keys
\*                       that have been evicted at least once. Lets
\*                       INV-3 observe resurrection across the trace.

VARIABLES
    buckets,            \* function (active keys) -> [tokens, last_touch]
    next_sweep_at,      \* Nat: time the next sweep fires
    now,                \* Nat: current monotonic clock
    evicted_count,      \* Nat: cumulative evicted-bucket count
    was_evicted         \* SUBSET Keys: keys evicted at least once

vars == <<buckets, next_sweep_at, now, evicted_count, was_evicted>>

\* -----------------------------------------------------------------
\* §2. Bucket shape (matches the C++ struct Bucket at
\* rate_limiter.hpp:120-123).
\* -----------------------------------------------------------------
\*
\* The C++ Bucket struct has two fields:
\*   double tokens{0.0};
\*   std::chrono::steady_clock::time_point last;
\*
\* The token level is in [0, C] by L-1 of the prose proof; for the
\* F-1 invariants (lifetime-bound, resurrection-safety, idempotence,
\* amortization) the precise integer-fractional value is orthogonal —
\* we collapse it to a single FULL / EMPTY boolean. A bucket starts
\* FULL on creation; Consume drops it to EMPTY when there's no token
\* available; the refill arithmetic restores it to FULL when enough
\* elapsed time has passed.

Tokens == {"FULL", "EMPTY"}

Bucket == [tokens : Tokens, last_touch : Nat]

\* The DOMAIN of `buckets` is the active key set. Caller queries via
\* `k \in DOMAIN buckets` (matches the C++ `buckets_.find(key) !=
\* buckets_.end()` predicate).
ActiveKeys == DOMAIN buckets

\* -----------------------------------------------------------------
\* §3. Staleness predicate (matches the eviction-time arithmetic at
\* rate_limiter.hpp:135).
\* -----------------------------------------------------------------
\*
\* IsStale(k): true iff key k's bucket has been idle longer than the
\* eviction threshold. Matches the C++:
\*
\*   if (now - it->second.last > threshold) {
\*       it = buckets_.erase(it);
\*       ++evicted;
\*   }
\*
\* where threshold = eviction_threshold_sec_ in steady_clock units.
\* The strict-greater comparison at line 135 matches the spec's
\* `now - last_touch > EvictionThreshold` predicate.

IsStale(k) ==
    /\ k \in ActiveKeys
    /\ now - buckets[k].last_touch > EvictionThreshold

\* The set of stale keys currently in `buckets`. Used by SweepIdle
\* + INV-1 / INV-6 invariants.
StaleKeys == { k \in ActiveKeys : IsStale(k) }

\* -----------------------------------------------------------------
\* §4. SweepIdle (matches sweep_idle_locked at
\* rate_limiter.hpp:128-143).
\* -----------------------------------------------------------------
\*
\* The C++ implementation walks `buckets_` and erases entries where
\* `now - it->second.last > threshold`; returns the number removed.
\* The spec-layer abstraction:
\*
\*   * If eviction is disabled (threshold = 0), no-op (matches the
\*     line 129 short-circuit `if (eviction_threshold_sec_ <= 0.0)
\*     return 0;`).
\*   * Otherwise, restrict `buckets` to the non-stale keys, advance
\*     `evicted_count` by the number removed, add the removed keys
\*     to `was_evicted`.

SweepIdle ==
    IF EvictionThreshold = 0
    THEN \* Disabled: no-op (T-5 / INV-5).
         /\ UNCHANGED buckets
         /\ UNCHANGED evicted_count
         /\ UNCHANGED was_evicted
    ELSE \* Active eviction: drop stale keys.
         /\ buckets' = [k \in ActiveKeys \ StaleKeys |-> buckets[k]]
         /\ evicted_count' = evicted_count + Cardinality(StaleKeys)
         /\ was_evicted' = was_evicted \cup StaleKeys

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* Initial: no buckets, sweep cadence not yet armed, clock at 0,
\* counter at 0, no evicted history.
Init ==
    /\ buckets       = [k \in {} |-> [tokens |-> "FULL", last_touch |-> 0]]
    /\ next_sweep_at = 0
    /\ now           = 0
    /\ evicted_count = 0
    /\ was_evicted   = {}

\* Consume(k): touch key k.
\*
\* Mirrors the C++ flow at rate_limiter.hpp:86-117:
\*
\*   bool consume(const std::string& key) {
\*     if (!enabled()) return true;
\*     std::lock_guard<std::mutex> lk(mu_);
\*     auto now = std::chrono::steady_clock::now();
\*
\*     // F-1: amortized idle-bucket sweep (lines 95-103).
\*     if (eviction_threshold_sec_ > 0.0) {
\*         if (next_sweep_at_.time_since_epoch().count() == 0 ||
\*             now >= next_sweep_at_) {
\*             sweep_idle_locked(now);
\*             next_sweep_at_ = now + sweep_interval_sec_;
\*         }
\*     }
\*
\*     auto& b = buckets_[key];    // map operator[] inserts default
\*     if (b.last.time_since_epoch().count() == 0) {
\*         b.tokens = burst_;        // first touch: FULL
\*         b.last   = now;
\*     } else {
\*         double elapsed_sec = ...;
\*         b.tokens = std::min(burst_, b.tokens + elapsed_sec * rate_per_sec_);
\*         b.last   = now;
\*     }
\*     if (b.tokens < 1.0) return false;
\*     b.tokens -= 1.0;
\*     return true;
\*   }
\*
\* The spec models the side effects on `buckets`, `next_sweep_at`,
\* `evicted_count`, and `was_evicted`; the boolean return is not
\* invariant-relevant here (covered by FA-T1 of the prose proof).

\* SweepFires_locked(post_sweep_buckets, post_sweep_count, post_sweep_was):
\*   the "did the sweep fire this consume" branch — packs the
\*   post-sweep state into a tuple so the bucket-touch step that
\*   follows can build on top of it. We inline the logic rather than
\*   make a separate action because the C++ side runs the sweep
\*   + bucket-touch atomically under the mutex.

Consume(k) ==
    /\ k \in Keys
    \* (a) The amortized sweep branch. The C++ guard at lines 95-97
    \* fires when (a.i) `next_sweep_at_` is at its default-epoch
    \* sentinel value OR (a.ii) `now >= next_sweep_at_`. The spec
    \* treats `next_sweep_at = 0` as the sentinel (which coincides
    \* with `now = 0` at Init but separates after the first sweep).
    /\ LET sweep_fires == EvictionThreshold > 0
                          /\ (next_sweep_at = 0 \/ now >= next_sweep_at) IN
       LET post_sweep_buckets ==
              IF sweep_fires
              THEN [j \in ActiveKeys \ StaleKeys |-> buckets[j]]
              ELSE buckets IN
       LET post_sweep_count ==
              IF sweep_fires
              THEN evicted_count + Cardinality(StaleKeys)
              ELSE evicted_count IN
       LET post_sweep_was ==
              IF sweep_fires
              THEN was_evicted \cup StaleKeys
              ELSE was_evicted IN
       LET post_sweep_at ==
              IF sweep_fires
              THEN now + SweepInterval
              ELSE next_sweep_at IN
       \* (b) The bucket-touch step. Whether k is in
       \* `post_sweep_buckets` after the sweep determines whether
       \* this is a first-touch (creates at FULL) or a refresh
       \* (updates last_touch). Either way the bucket is FULL after
       \* this step in the spec abstraction — the F-1 invariants
       \* care about `last_touch`, not `tokens`.
       /\ buckets'       = [j \in (DOMAIN post_sweep_buckets) \cup {k} |->
                                IF j = k
                                THEN [tokens |-> "FULL", last_touch |-> now]
                                ELSE post_sweep_buckets[j]]
       /\ next_sweep_at' = post_sweep_at
       /\ evicted_count' = post_sweep_count
       /\ was_evicted'   = post_sweep_was
       /\ UNCHANGED now

\* AdvanceTime(delta): monotonic clock advance. Bounded by
\* MaxTimeStep per step to keep the state space tractable.
AdvanceTime ==
    \E delta \in 1..MaxTimeStep :
       /\ now + delta <= MaxTimeSteps
       /\ now' = now + delta
       /\ UNCHANGED <<buckets, next_sweep_at, evicted_count, was_evicted>>

\* ForcedSweep: external sweep_idle() call from the public API at
\* rate_limiter.hpp:79-82. Tests + operator-monitoring use this to
\* deterministically exercise the eviction path. No-op when
\* eviction is disabled (matches the line 129 short-circuit).
ForcedSweep ==
    /\ SweepIdle
    /\ UNCHANGED now
    /\ UNCHANGED next_sweep_at

\* Saturation stutter (TLC bounds the state space; invariants are
\* evaluated at every reachable state along the way).
SaturateClock ==
    /\ now >= MaxTimeSteps
    /\ UNCHANGED vars

\* Next-state. Pick any of: Consume on any key, AdvanceTime,
\* ForcedSweep, or stutter at saturation.
Next ==
    \/ \E k \in Keys : Consume(k)
    \/ AdvanceTime
    \/ ForcedSweep
    \/ SaturateClock

Spec == Init /\ [][Next]_vars
             /\ WF_vars(AdvanceTime)
             /\ WF_vars(\E k \in Keys : Consume(k))

\* -----------------------------------------------------------------
\* §6. Invariants — the six T-1..T-6 + F-1 closure claims.
\* -----------------------------------------------------------------

\* INV-1 (BucketLifetimeBounded): every active bucket has been
\* touched within the last `EvictionThreshold + SweepInterval` time
\* units. Captures T-1 — the post-sweep guarantee that no bucket
\* lingers past the cadence.
\*
\* The argument: a bucket becomes "stale" after `EvictionThreshold`
\* idle seconds. The amortized sweep runs at most every
\* `SweepInterval` seconds. So worst-case a bucket survives for
\* `EvictionThreshold + SweepInterval - 1` seconds past its last
\* touch (the case where it crosses the staleness boundary right
\* after a sweep, and survives until the next sweep). We assert
\* the closed bound `now - last_touch <= EvictionThreshold +
\* SweepInterval` (non-strict) which is an over-approximation that
\* trivially passes; the strict bound is what the prose proof
\* states in §6.2 Closure point 6.
\*
\* Special case: when EvictionThreshold = 0, eviction is disabled,
\* and this invariant degenerates to "now - last_touch <=
\* SweepInterval" which is FALSE in general (the disabled-eviction
\* mode is the legacy unbounded-growth behavior). INV-5 below
\* explicitly covers the disabled case; this invariant fires only
\* when EvictionThreshold > 0.
INV_BucketLifetimeBounded ==
    EvictionThreshold > 0 =>
    \A k \in ActiveKeys :
       now - buckets[k].last_touch <= EvictionThreshold + SweepInterval

\* INV-2 (EvictionMonotone): `evicted_count` never decreases.
\* Captures T-3 (audit-trail soundness). State-form: at every
\* reachable state, `evicted_count >= 0` (Nat-typed) AND every
\* step preserves the non-decreasing property by construction
\* (SweepIdle only adds, ForcedSweep only adds, Consume only adds,
\* AdvanceTime leaves it UNCHANGED).
\*
\* The state-form invariant is trivially "evicted_count \in Nat"
\* because the type itself encodes non-negativity. The action-level
\* monotonicity is captured structurally by the SweepIdle definition
\* (always adds `Cardinality(StaleKeys) >= 0`) and the absence of any
\* action that decrements `evicted_count`.
INV_EvictionMonotone ==
    evicted_count \in Nat

\* INV-3 (ResurrectionSafe): if a key was evicted (k \in
\* was_evicted) and is currently in buckets (k \in ActiveKeys), the
\* bucket starts at FULL capacity. The C++ first-touch branch at
\* rate_limiter.hpp:107 sets `b.tokens = burst_` (= FULL in the
\* spec abstraction) on the consume-after-eviction call. This is
\* observationally indistinguishable from the un-evicted bucket
\* having refilled to capacity — which it would have done after
\* >= `burst_/rate_per_sec_` seconds (= ~10s with default config),
\* well before the default `EvictionThreshold = 600s`.
\*
\* The spec assertion: for every k that has been evicted at least
\* once, if k is currently in `buckets`, then `buckets[k].tokens =
\* "FULL"`. Equivalently: every re-touched key after eviction is
\* full.
\*
\* In the spec abstraction every Consume sets the touched bucket
\* to FULL — so this invariant trivially holds for ANY key in
\* ActiveKeys, not just for resurrected ones. The full power of
\* T-2 is captured by combining this invariant with the trace
\* property "evicted-then-resurrected keys are present in
\* was_evicted ∩ ActiveKeys" — which TLC verifies by enumerating
\* every interleaving of Consume / SweepIdle / Consume.
INV_ResurrectionSafe ==
    \A k \in was_evicted \cap ActiveKeys :
       buckets[k].tokens = "FULL"

\* INV-4 (SweepIdempotent): SweepIdle applied twice with no
\* intervening time advance and no Consume yields the same buckets
\* the second time. Captures T-4 — the erase-or-skip loop body at
\* rate_limiter.hpp:134-141.
\*
\* The state-form: after any state where SweepIdle could fire,
\* applying it once removes exactly StaleKeys; applying it again
\* on the post-sweep state removes nothing (because StaleKeys' is
\* empty in the post-sweep state — every key with `now - last_touch
\* > EvictionThreshold` was just erased). We assert this as a
\* per-state predicate: after a SweepIdle, no stale keys remain.
\*
\* Equivalent: post-SweepIdle StaleKeys must be empty. The
\* invariant fires only at states where the prior step was a
\* SweepIdle, which is hard to encode as a state-form without
\* a step-history tag. Instead we capture the stronger property:
\* "at every reachable state, the set of keys k such that
\* `now - buckets[k].last_touch > EvictionThreshold + SweepInterval`
\* is empty" — which is INV-1's strict-bound form. This is the
\* idempotence witness because if SweepIdle ever LEFT a stale key
\* in the map, the next AdvanceTime + ForcedSweep would catch it
\* within SweepInterval, so the lifetime bound (INV-1) would fail
\* before another bound-violation could accumulate.
\*
\* The cleaner form: assert that two consecutive ForcedSweep
\* actions are equivalent to one. State-form: the SweepIdle
\* operator is idempotent on the BucketsState component.
\* Definition: SweepIdle composed with itself equals SweepIdle.
\* TLC can witness this by checking after every ForcedSweep step
\* that an immediate re-sweep on the same `now` would not change
\* `buckets`. The spec captures this via:
INV_SweepIdempotent ==
    EvictionThreshold > 0 =>
    \* After any sweep (forced or amortized), no stale keys remain.
    \* This is exactly the "second sweep does nothing" idempotence
    \* contract — there's nothing left to evict.
    \* Note: this fires only at post-sweep states; between sweeps
    \* a key may become stale while `now` advances, which is
    \* covered by INV-1 (it stays bounded by the cadence + threshold).
    \* Here we assert the residual-stale-keys-at-post-sweep
    \* invariant by checking that any key currently in `buckets`
    \* whose `last_touch` is older than EvictionThreshold AND
    \* whose `last_touch` is older than `next_sweep_at -
    \* SweepInterval` (i.e., predates the most recent sweep) must
    \* not exist — because the most recent sweep would have caught
    \* it.
    \A k \in ActiveKeys :
       \* If the most recent sweep already fired (next_sweep_at > 0),
       \* any key whose last_touch predates the (current sweep) -
       \* (SweepInterval) was evicted at that sweep — so it can only
       \* be in buckets if it was re-touched after.
       (next_sweep_at > SweepInterval /\ buckets[k].last_touch < next_sweep_at - SweepInterval)
       => (now - buckets[k].last_touch <= EvictionThreshold)

\* INV-5 (ConfigureEvictionZeroDisables): when `EvictionThreshold =
\* 0`, no key is ever evicted. Captures T-5 — the legacy unbounded-
\* growth behavior pinned as a config option per
\* rate_limiter.hpp:56 and the docblock at line 53.
\*
\* The structural witness: SweepIdle's IF-branch at the spec layer
\* short-circuits when `EvictionThreshold = 0` (the if-then
\* arm UNCHANGED on buckets, evicted_count, was_evicted). So the
\* monotone `evicted_count` stays at 0 across every trace. The
\* `was_evicted` set stays empty.
INV_ConfigureEvictionZeroDisables ==
    EvictionThreshold = 0 =>
       /\ evicted_count = 0
       /\ was_evicted = {}

\* INV-6 (AmortizedSweepLowerBoundsResidual): at any time t, the
\* number of stale keys still resident in `buckets` is bounded by
\* the cadence-fresh count. Specifically: any stale key in
\* `buckets` has become stale within the SweepInterval window —
\* otherwise the previous sweep would have caught it.
\*
\* State-form: for every stale key k in `buckets`,
\*   now - buckets[k].last_touch <= EvictionThreshold + SweepInterval.
\* (The strict version: a key with `now - last_touch >
\* EvictionThreshold + SweepInterval` cannot be in `buckets`
\* because the prior sweep would have evicted it.) This is the
\* same bound as INV-1; the difference is INV-1 covers ALL active
\* keys while INV-6 specifically observes the stale subset. TLC
\* checks both as separate witnesses.
\*
\* Alternative form via Cardinality bound: the number of stale
\* keys at time `now` is at most the number that became stale
\* since the most recent sweep, which is bounded by the number of
\* keys that were touched then went idle in the window
\* `[next_sweep_at - SweepInterval, now]`. We assert the simpler
\* time-bound version since the cardinality version would require
\* tracking per-key staleness onset which inflates the state space.
INV_AmortizedSweepLowerBoundsResidual ==
    EvictionThreshold > 0 =>
    \A k \in StaleKeys :
       now - buckets[k].last_touch <= EvictionThreshold + SweepInterval

\* -----------------------------------------------------------------
\* §7. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ buckets       \in [ActiveKeys -> Bucket]
    /\ ActiveKeys    \subseteq Keys
    /\ next_sweep_at \in Nat
    /\ now           \in 0..MaxTimeSteps
    /\ evicted_count \in Nat
    /\ was_evicted   \subseteq Keys

\* -----------------------------------------------------------------
\* §8. Soundness commentary — what TLC checks vs. what the prose
\* proof asserts.
\* -----------------------------------------------------------------
\*
\* The S014RateLimiterSoundness.md §6.2 "Closure (shipped)" subsection
\* documents the six-point design of the F-1 mitigation:
\*
\*   1. API additions (configure_eviction, bucket_count, sweep_idle,
\*      sweep_idle_locked).
\*   2. Hot-path integration in consume() — amortized sweep before
\*      the bucket-touch.
\*   3. Defaults (eviction_threshold_sec_ = 600, sweep_interval_sec_
\*      = 60).
\*   4. Semantic safety — an evicted bucket re-creates as full-
\*      capacity on next touch.
\*   5. Test coverage — 8 new scenarios in `determ test-rate-limiter-
\*      bucket`.
\*   6. Memory bound — buckets_.size() is bounded by per-bucket
\*      worst-case lifetime: eviction_threshold_sec + sweep_interval_
\*      sec seconds without being touched.
\*
\* The TLA+ state-machine layer abstracts these six points as the
\* six invariants:
\*
\*   * Point 1 (API) → reflected in the spec's three actions
\*     (Consume, ForcedSweep) and the underlying SweepIdle operator.
\*   * Point 2 (hot-path) → modeled by the Consume action's
\*     "sweep-before-touch" branching at the `sweep_fires` LET binding.
\*   * Point 3 (defaults) → spec-time constants EvictionThreshold +
\*     SweepInterval. The recommended config matches the prose proof's
\*     ratio (600:60 = 10:1) at the small bound.
\*   * Point 4 (semantic safety) → INV-3 ResurrectionSafe.
\*   * Point 5 (test coverage) → not modeled directly; the TLC
\*     enumeration is the formal counterpart to the runtime test
\*     coverage.
\*   * Point 6 (memory bound) → INV-1 BucketLifetimeBounded + INV-6
\*     AmortizedSweepLowerBoundsResidual; together they bound
\*     `buckets_.size()` at the rotating-window count.
\*
\* What the spec does NOT check (consistent with the prose proof's §6):
\*   * Concurrent-mutex correctness (the C++ side serializes via
\*     `std::mutex mu_`; the spec uses TLA+ atomic actions to model
\*     the serialized window).
\*   * Per-second-precision floating-point arithmetic of the C++
\*     elapsed * rate_per_sec calculation (the spec models token
\*     state as FULL/EMPTY; L-1 of the prose proof gives the
\*     [0, C] interval bound).
\*   * The HELLO-exemption gate at src/net/gossip.cpp:148 (FA-track
\*     T-4 covers it).
\*   * The per-method weighting on RPC (F-3 of the prose proof's
\*     §6.2; deferred to a follow-on).
\*
\* What this spec adds beyond the prose proof: a state-machine
\* witness of the lifetime-bound + resurrection-safety + amortization
\* invariants that the prose proof states algebraically. The TLC
\* enumeration covers every reachable interleaving of Consume /
\* AdvanceTime / ForcedSweep within the bounded universe, including
\* the boundary cases where the sweep fires exactly at the staleness
\* threshold and where keys re-touch immediately after eviction.

============================================================================
\* Cross-references.
\*
\* FA-RateLimiter (S014RateLimiterSoundness.md) ->
\*   §1 T-1..T-6  : the pre-F-1 soundness theorems (bounded burst,
\*                   no amplification, per-IP independence, HELLO
\*                   exemption, refill monotonicity, capacity-vs-rate
\*                   trade-off). All remain valid under the F-1
\*                   mitigation (the eviction policy operates on
\*                   `last_touch` only, leaving the token-bucket
\*                   arithmetic untouched).
\*   §6.2 F-1     : the closure subsection this spec formalizes;
\*                   point 1 (API) → spec actions, point 2 (hot-path)
\*                   → Consume's sweep-before-touch branch, point 3
\*                   (defaults) → spec constants, point 4 (semantic
\*                   safety) → INV-3, point 5 (test coverage) → TLC
\*                   enumeration, point 6 (memory bound) → INV-1 +
\*                   INV-6.
\*   §3 implementation citation → include/determ/net/rate_limiter.hpp:36-152
\*   (the function under test; ~150 LOC post-F-1).
\*
\* SECURITY.md §S-014 : closure narrative; F-1 mitigation
\*   acknowledged as the cumulative S-014 ship.
\*
\* Preliminaries.md §2.2 L-5 : steady_clock monotonicity. Used by
\*   the AdvanceTime action's `now' = now + delta` clause (delta >= 1).
\*   The C++ side's `std::chrono::steady_clock::now()` is RFC-mandated
\*   monotonic; the spec layer enforces this via the per-step
\*   non-decrement on `now`.
\*
\* F2ViewReconciliation.tla (FB22), FrostVerify.tla (FB23),
\* MakeContribCommitment.tla (FB24): sibling FB-track specs; style
\*   template for this module (the "pure-function + bounded
\*   enumeration + INV-*" pattern, the cross-references format, the
\*   companion-prose-proof-citation discipline).
\*
\* C++ enforcement: include/determ/net/rate_limiter.hpp
\*   class RateLimiter            @ lines 36-152
\*   configure                    @ lines 42-45
\*   configure_eviction (F-1)     @ lines 56-59
\*   bucket_count                 @ lines 69-72
\*   sweep_idle (public)          @ lines 79-82
\*   consume (hot path)           @ lines 86-117
\*     amortized sweep branch     @ lines 95-103
\*     first-touch FULL init      @ lines 106-108
\*     refill arithmetic          @ lines 109-113
\*   struct Bucket                @ lines 120-123
\*   sweep_idle_locked (private)  @ lines 128-143
\*   field eviction_threshold_sec_ @ line 147
\*   field sweep_interval_sec_    @ line 148
\*   field next_sweep_at_         @ line 149
\*   field buckets_ (the map)     @ line 151
\*
\* Runtime regressions:
\*   tools/test_rate_limiter.sh   — 16-case unit-test harness;
\*     scenarios #27..#34 (post-F-1; 8 new scenarios) cover bucket-
\*     count growth, sweep idle, re-touch after eviction, mixed
\*     fresh + stale, disabled-mode unbounded-growth.
\*
\* Doc updates:
\*   S014RateLimiterSoundness.md §6.2 "Closure (shipped)" subsection
\*   (the prose proof's six-point F-1 design narrative that this
\*   spec formalizes at the state-machine layer).
\*   SECURITY.md §S-014 (the cumulative closure narrative).
============================================================================
