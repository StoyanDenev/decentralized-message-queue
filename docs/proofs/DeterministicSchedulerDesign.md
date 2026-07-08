# Deterministic Scheduler Design — a no-thread virtual-time drive for the real consensus engine

**Status: DESIGN-REVIEW; increment 1 SHIPPED, increments 2-5 design-only.** This is
the design-review-first step the [KqueueReactorDesign.md](KqueueReactorDesign.md)
discipline mandates for a change that touches shipped orchestration. **Increment 1
(the additive, byte-invariant `VirtualEventLoop::run_until_idle()` — §4 table) is
SHIPPED** (pure-std test backend, production `run()` untouched); the substantive
scheduler (increments 2-5) stays design-only until the seam deltas below are
agreed, and one item (§5, the Node no-self-thread mode) requires an OWNER decision
because the smallest honest version of it touches the production `run()` path. The goal is a fully DETERMINISTIC single-thread scheduler
that drives the REAL `node::Node` + `BlockValidator` + producer so Byzantine
schedules replay byte-for-byte — closing the F-1/FA4 gap
([RealEngineFAHarness.md](RealEngineFAHarness.md) §5) and unblocking the reliable
loss-liveness gate + the deterministic S-048 reproduction that
[AdversarialTransportHarness.md](AdversarialTransportHarness.md) §3.1 documents as
BLOCKED on exactly this piece. It builds on two SHIPPED prerequisites: the §Q1
clock seam ([ClockInjectionSeam.md](ClockInjectionSeam.md)) and the §Q2
`net::`/`VirtualTransport` seam ([DSF-SPEC.md](DSF-SPEC.md) §Q2). Reference
convention: bare §0-§6 are this doc; `§Q1`/`§Q2` are DSF-SPEC.md; `S-047`/`S-048`
are `docs/SECURITY.md`.

## 0. Scope — the one property that must change, and the one that must not

The FA4 harnesses (`test-fa-liveness-virtual`, `test-fa-partition-virtual`) already
run FIVE real `Node`s in one process over the pure-std virtual backend — but on
REAL OS threads and REAL `steady_clock` timers, so they are *hermetic but not
deterministic* (RealEngineFAHarness.md §5, AdversarialTransportHarness.md §4). The
delta this design introduces is a **drive mode** in which ONE thread owns all
progress: it runs each loop body inline, consults a **virtual** clock the harness
steps, and processes posted closures + due timers in a fixed TOTAL ORDER. The
load-bearing constraint, identical in spirit to Kqueue §0's "the transport ports
byte-identical": **the production path must stay byte-invariant.** Every change is
therefore ADDITIVE — a new poll entry point on `VirtualEventLoop`, an optional
virtual-time timer source, an opt-in external-drive mode on `Node` — never a
change to the default `run()`/native-loop behavior. The digest-byte guarantee is
inherited wholesale from ClockInjectionSeam.md §0: digests bind the `int64`
seconds VALUE, never how it was sourced, so a deterministic scheduler that feeds
the same integers produces the same blocks.

## 1. AS-IS threading model (what actually runs today)

Three distinct thread populations exist per `Node`, all of which the deterministic
mode must collapse to zero:

**(a) The loop-worker pool.** `Node::run()`
([node.cpp:614](../../src/node/node.cpp)) spawns
`std::max(1u, std::thread::hardware_concurrency())` OS threads
([node.cpp:642](../../src/node/node.cpp)), each calling `loop_.run()`
([node.cpp:644](../../src/node/node.cpp)), stored in `threads_`
([node.hpp:724](../../include/determ/node/node.hpp)) and collected by
`join_loop_threads()` ([node.cpp:672](../../src/node/node.cpp)). `run()` itself
then BLOCKS in a tail `join_loop_threads()` ([node.cpp:669](../../src/node/node.cpp))
until `stop()` releases the loop. **This is the critical fact: even when `loop_` is
an injected `VirtualEventLoop`, `run()` unconditionally spawns
`hardware_concurrency` threads on it.** The FA harness spawns one `std::thread` per
node calling `n->run()` ([main.cpp:26134](../../src/main.cpp)), so a 5-node run is
5 × (HC loop threads) all racing, which is why those harnesses cannot be
deterministic no matter how the clock is wired.

**(b) The async-save worker.** `run()` also spawns `save_thread_`
([node.cpp:651](../../src/node/node.cpp), member
[node.hpp:772](../../include/determ/node/node.hpp)) running
`save_worker_loop()` ([node.cpp:726](../../src/node/node.cpp)); it waits on
`save_cv_`, and on wake takes `state_mutex_`'s shared lock to `chain_.save()`. It
does not touch digests, but it IS a wall-time thread and a second reader of
`state_mutex_`, so it breaks single-thread determinism and must be suppressed
(§5).

**(c) The TimerService deadline thread.** Each `VirtualEventLoop` owns a
`TimerService` ([virtual_transport.hpp:159](../../include/determ/net/virtual_transport.hpp))
that lazily starts ONE `std::thread`
([timer_service.hpp:56-57](../../include/determ/net/timer_service.hpp)) whose body
([timer_service.hpp:105](../../include/determ/net/timer_service.hpp)) sleeps on
`cv_.wait_until(next)` and, when `steady_clock::now()` passes a deadline
([timer_service.hpp:116](../../include/determ/net/timer_service.hpp),
[:124](../../include/determ/net/timer_service.hpp)), `post_`s the callback onto the
owning loop. **All three consensus timers ride this thread on REAL steady_clock:**
`contrib_timer_` and `block_sig_timer_` are `net::NativeTimer` = `LoopTimer`
([native.hpp:33](../../include/determ/net/native.hpp),
[:44](../../include/determ/net/native.hpp)) constructed over `loop_`
([node.hpp:699-700](../../include/determ/node/node.hpp), ctor
[node.cpp:152-153](../../src/node/node.cpp)), and the startup grace is a
`shared_ptr<NativeTimer>` ([node.cpp:658-659](../../src/node/node.cpp)). Each
`arm()` ([loop_timer.hpp:27](../../include/determ/net/loop_timer.hpp)) →
`loop_.timer_schedule` → `VirtualEventLoop::timer_schedule`
([virtual_transport.hpp:148](../../include/determ/net/virtual_transport.hpp)) →
`TimerService::schedule` with `steady_clock::now() + delay`
([timer_service.hpp:55](../../include/determ/net/timer_service.hpp)). The consensus
round timers are re-armed on the S-047 retry path
([node.cpp:1293](../../src/node/node.cpp),
[:1345](../../src/node/node.cpp)), which re-broadcasts full round state via
`rebroadcast_round_state_locked()` ([node.cpp:1255](../../src/node/node.cpp)).

**The VirtualEventLoop itself is already single-thread-clean IF driven by one
thread.** `run()` ([virtual_transport.cpp:128](../../src/net/virtual_transport.cpp))
is a `mutex`+`cv` loop that pops a `std::deque<std::function<void()>>` FIFO
([:132-134](../../src/net/virtual_transport.cpp)) and invokes the closure OUTSIDE
the lock ([:139](../../src/net/virtual_transport.cpp)); `post()`
([:87](../../src/net/virtual_transport.cpp)) is a locked `push_back` + `notify_one`
— a strict FIFO. The header already states the property we exploit
([virtual_transport.hpp:63-69](../../include/determ/net/virtual_transport.hpp)):
"With a SINGLE run() thread per loop, delivery order is exactly post() order." The
State is held by `shared_ptr` ([virtual_transport.hpp:157](../../include/determ/net/virtual_transport.hpp))
so teardown posts are order-free — the design that killed the multi-loop UAF. The
gap between "single run() thread per loop" and "deterministic" is precisely the
three thread populations above plus the wall-clock timer source.

**Concurrency points the mode removes.** Today every consensus callback runs on
some loop-pool thread and takes `state_mutex_`
([node.hpp:723](../../include/determ/node/node.hpp), a `std::shared_mutex`) —
e.g. `handle_contrib_timeout` under `unique_lock`
([node.cpp:1294](../../src/node/node.cpp)). `state_mutex_` exists SOLELY to
serialize those racing threads. Under a one-thread scheduler the mutex becomes
uncontended (never removed — the production path keeps it), and the
nondeterminism it papers over disappears at the source.

**Determinism-favorable fact (verified).** The consensus hot-path state is all
ORDERED or insertion-ordered — `pending_contribs_`, `pending_block_sigs_`,
`pending_claims_` are `std::map` and `current_creator_domains_`/`current_aborts_`
are `std::vector` ([node.hpp:590-706](../../include/determ/node/node.hpp)); gossip
`peers_` is a `std::vector` ([gossip.hpp:121](../../include/determ/net/gossip.hpp))
broadcast in insertion order ([gossip.cpp:338-341](../../src/net/gossip.cpp)).
**No `unordered_map` sits in the consensus or gossip iteration path** (grep-checked
against node.hpp / gossip.hpp), so map-iteration nondeterminism — the classic
scheduler hazard — is already absent. This is why the remaining hazards (§3) are
about scheduling order, not container order.

## 2. TO-BE — the deterministic single-thread model

One thread (the harness's) owns everything. The model has four responsibilities,
mapped to the minimal seam additions that provide each:

**(a) Run the loop body inline.** Add `VirtualEventLoop::run_until_idle()` (a
`poll()`): drain the FIFO on the CALLING thread and RETURN when the ready queue
empties, instead of `run()`'s block-until-`stop()`. Mechanically this is `run()`
([virtual_transport.cpp:128-142](../../src/net/virtual_transport.cpp)) with the
`cv.wait` replaced by "if empty, return." Purely additive; `run()` stays for
production. Because completions are already POSTED not inlined
([virtual_transport.hpp:22-24](../../include/determ/net/virtual_transport.hpp)),
draining on the caller thread changes nothing about ordering — it just removes the
worker pool.

**(b) A virtual "now" the timers consult.** The TimerService's
`steady_clock::now()` ([timer_service.hpp:116](../../include/determ/net/timer_service.hpp),
[:124](../../include/determ/net/timer_service.hpp)) is the wall-clock leak. Two
implementation shapes, pick one at build time:
  - **Preferred: a loop-local virtual timer queue.** In deterministic mode
    `VirtualEventLoop::timer_schedule` does NOT delegate to `TimerService`; it
    inserts `{virtual_now + delay, id, fn}` into an ordered in-loop structure and
    the scheduler (§d) pops due entries against a `virtual_now` it owns. No
    `TimerService` change, no timer thread, no `steady_clock`. `LoopTimer`
    ([loop_timer.hpp](../../include/determ/net/loop_timer.hpp)) is unaffected — it
    only holds an id. This is the KqueueReactor §2 "recommendation (c)" instinct:
    prefer the change that adds no new lifetime/liveness reasoning.
  - Alternative: inject a `Clock` into `TimerService` so its deadline math reads
    virtual time. Rejected for the same reason KqueueReactor rejected the
    `EVFILT_USER` retrigger chain — it keeps a real thread and a `wait_until`, so
    "deterministic" still depends on that thread never racing the scheduler.

**(c) A total order over closures + due timers.** Within one loop, closure order
is already FIFO (§1). The scheduler's step is: drain ALL ready closures FIFO; then,
if the queue is empty and timers are pending, pop the SINGLE earliest-deadline
timer (ties broken deterministically — §3), advance `virtual_now` to its deadline,
fire it (which posts more closures), and repeat. This is the classic
discrete-event loop: **ready work before time advance, time advances only to the
next due timer.**

**(d) Advance virtual time when the ready queue is empty.** The scheduler never
sleeps; when no closure is ready it JUMPS `virtual_now` to the next timer deadline.
This is what makes a 200 ms round timer cost zero wall time and makes the whole run
seed-reproducible. The §Q1 clock (`VirtualClock`,
[virtual_clock.hpp](../../include/determ/time/virtual_clock.hpp)) is stepped IN
LOCKSTEP with this scheduler `virtual_now` at quiescent points (its header already
anticipates this: "a virtual-time harness advances the clock at quiescent points",
[virtual_clock.hpp:14-15](../../include/determ/time/virtual_clock.hpp)), subject to
the ≤30 s constraint of §3.

**What `Node` needs.** An opt-in EXTERNAL-DRIVE mode: the `run()` setup (listen,
connect, the grace timer, wiring) MINUS the two thread-spawning acts —
`threads_.emplace_back(loop_.run)` ([node.cpp:642-644](../../src/node/node.cpp))
and the blocking tail `join_loop_threads()`
([node.cpp:669](../../src/node/node.cpp)) — plus suppression of `save_thread_`
([node.cpp:651](../../src/node/node.cpp)). The harness then owns the one thread and
calls the scheduler's step. **Prefer adding a `start_external()` entry point (setup
only, spawns nothing) over branching the existing `run()`** — same principle as
ClockInjectionSeam's defaulted-trailing-parameter: production callers of `run()`
see byte-identical behavior because they never take the new path. Whether this can
be done without touching `run()` at all is the §5 open question.

**Multi-node.** The FA harness holds N independent `VirtualEventLoop`s
([main.cpp:26090](../../src/main.cpp)). The scheduler must impose a deterministic
order across them (§3) — a single merged event queue keyed by a global logical
time, or round-robin polling with a shared `virtual_now`. That choice is the one
genuinely NEW algorithm here; everything else is additive plumbing.

## 3. Determinism hazards (concrete, each with its mitigation)

1. **Loop-worker concurrency (the primary hazard).** `hardware_concurrency`
   threads per loop ([node.cpp:642](../../src/node/node.cpp)) run callbacks
   concurrently; even with a FIFO queue, WHICH thread runs WHICH closure and their
   interleaving is nondeterministic. *Mitigation:* the entire point — the
   external-drive mode spawns zero loop threads; one thread drains inline (§2a).

2. **Wall-clock timer firing.** `TimerService` fires on `steady_clock`
   ([timer_service.hpp:116](../../include/determ/net/timer_service.hpp)), so timeout
   vs. message-arrival races resolve differently every run. *Mitigation:* the
   virtual timer queue (§2b) — timers fire at a `virtual_now` the scheduler
   controls, never at a wall instant.

3. **Same-instant timer ties.** When multiple timers share a deadline, the current
   `TimerService` pops them in `entries_` insertion order over a `std::vector`
   ([timer_service.hpp:126-133](../../include/determ/net/timer_service.hpp)) — fine
   per-loop, but across loops and after re-arms the "insertion order" is a function
   of scheduling history. *Mitigation:* impose a stable total order on the virtual
   timer queue: sort by `(deadline, monotonic_seq)` where `monotonic_seq` is a
   global counter incremented on every schedule; ties then break by
   deterministic schedule order, and across loops by a fixed loop index.

4. **Cross-loop delivery order.** A write on node A's connection posts a completion
   onto node B's loop State ([virtual_transport.cpp:290-291](../../src/net/virtual_transport.cpp),
   [:202](../../src/net/virtual_transport.cpp)). Per-loop this is FIFO, but the
   order in which the scheduler VISITS loops A and B decides the global interleave.
   *Mitigation:* a single global logical clock — either one merged ready-queue
   tagged with a global sequence number assigned at `post` time, or a fixed
   round-robin over loops with per-link latency so a message posted at virtual T
   becomes deliverable at T+latency. **This is the one hazard that needs a real
   design decision** (§5): the simplest correct form is a global monotonic sequence
   stamped on every `post`, giving a single total order without a latency model;
   per-link latency is a richer adversarial knob layered on later.

5. **Per-link fault RNG.** The fault model's `LinkFlags::rng`
   ([virtual_transport.cpp:46](../../src/net/virtual_transport.cpp)) is seeded from
   the pair's pseudo-port ([:530](../../src/net/virtual_transport.cpp)) and advanced
   under `Pair::mu` ([:51-58](../../src/net/virtual_transport.cpp)). It is ALREADY
   deterministic given a deterministic pair-creation order; the header's caveat
   that "exact drops inherit the harness's existing wall-clock nondeterminism"
   ([virtual_transport.hpp:238-240](../../include/determ/net/virtual_transport.hpp))
   is true ONLY because delivery timing is currently wall-driven. *Mitigation:*
   under the deterministic scheduler, pair-creation order (hence pseudo-port
   assignment, [:517](../../src/net/virtual_transport.cpp)) becomes a pure function
   of the schedule, so the drop sequence becomes reproducible — the caveat is
   RESOLVED by this work, not a new risk. Auto-port assignment
   ([:404](../../src/net/virtual_transport.cpp)) is likewise deterministic given
   deterministic listen order.

6. **`now_unix()` / RNG leaks in the engine.** The consensus tree reads wall time
   through the injected `clock_` (ClockInjectionSeam.md §1), so proposer_time
   ([node.cpp:960](../../src/node/node.cpp)) and abort-ts
   ([node.cpp:1407](../../src/node/node.cpp)) are already virtual under a
   `VirtualClock`. The KNOWN residual leak is the producer free-function fallback
   still on `now_unix()` ([producer.cpp:812](../../src/node/producer.cpp)) —
   non-digest-bound on the production path (ClockInjectionSeam.md §1) but a
   nondeterminism source if a scenario ever exercises it; the harness must avoid
   the legacy-sentinel path (VirtualClock seeded ≥1.5e9,
   [virtual_clock.hpp:27-32](../../include/determ/time/virtual_clock.hpp)).
   *Mitigation:* seed the shared `VirtualClock` realistically and assert no
   scenario drives the fallback; a follow-on could hoist that value if a scenario
   needs it.

7. **The ±30 s freshness window bounds the clock step.** The validator compares a
   block's stamp against `clock_->unix_seconds()` at validation time
   ([validator.cpp:1414](../../src/node/validator.cpp), ClockInjectionSeam.md §1);
   a harness that jumps virtual time by **>30 s in one step** makes an in-flight
   block (stamped old, validated new) correctly self-reject
   (ClockInjectionSeam.md §8). *Mitigation:* the scheduler's `virtual_now`
   advance-to-next-timer (§2d) must be clamped so the CONSENSUS clock
   (`VirtualClock::advance`) never moves more than 30 s while a round is in flight
   — in practice the round timers are 200 ms ([node.cpp:102-103](../../src/node/node.cpp)),
   far under the window, so ordinary advance-to-next-timer stays legal; only a
   deliberately injected long stall risks it, and that is a scenario-authoring
   constraint to document, not an engine change.

## 4. What it unblocks + the gate plan

**Byte-reproducible FA4.** With (1) the virtual scheduler, (2) a shared
`VirtualClock`, (3) the virtual transport, and (4) the fault model already shipped,
a scenario replays byte-for-byte from a seed: same closure order, same timer
firings, same drop sequence, same digests. Over that substrate the FA1/A1/FA6/FA7
checkers run against the REAL engine state after each scheduler step
(ClockInjectionSeam.md §5 defines this as the concrete closure of F-1/FA4), each
paired with an `expect_violation` planted-bug self-test — the non-vacuity +
negative-control discipline every `test-fa-*` already follows
(RealEngineFAHarness.md §2).

**Deterministic S-048 reproduction.** AdversarialTransportHarness.md §3.1 shows
ordinary link loss induces the timing skew that drives the abort-vs-finalize race
into the open S-048 same-height fork — but only NONDETERMINISTICALLY under wall
timers. The deterministic scheduler makes a chosen loss/reorder schedule produce
the fork ON DEMAND, which is the regression test the (owner-gated) `resolve_fork`
fix needs.

**Reliable loss-liveness gate.** Currently a NON-gating diagnostic
(AdversarialTransportHarness.md §3.1: "not assertable while S-048 is open" AND
because wall timers make convergence flaky, §3.2). Deterministic scheduling removes
the flakiness half immediately (a fixed schedule converges or does not,
reproducibly); the S-048 half remains owner-gated.

**Phased increment plan** (smallest safe first, each with its gate):

| # | Increment | Gate |
|---|---|---|
| 1 | **`VirtualEventLoop::run_until_idle()`** — caller-thread drain, additive; re-drive an existing single-loop test (`test-net-virtual`) through it instead of a spawned thread — **SHIPPED** ([virtual_transport.cpp](../../src/net/virtual_transport.cpp) `run_until_idle`; `test-net-virtual` phase 1b asserts caller-thread FIFO drain == threaded `run()` order, mid-drain re-posts run to quiescence in the same call, empty-queue returns immediately) | goldens byte-identical + FAST 207/0 both platforms + the re-driven test byte-matches the threaded run ✓ |
| 2 | **Virtual-time timer source** — loop-local ordered timer queue consulted by the poll, `virtual_now` advance-to-next-timer; a unit test arms 3 timers and asserts fixed fire order + zero wall time | FAST + timer-order test + `test-net-virtual` still green (native/`TimerService` path untouched) |
| 3 | **`Node::start_external()`** (§5 owner gate) — setup-only entry, spawns no loop/save threads; re-drive a SINGLE-node scenario (the `test-virtual-clock` shape, [main.cpp:26724](../../src/main.cpp)) deterministically | goldens + FAST + live `test_weak_3node` (production `run()` proven untouched) |
| 4 | **Global multi-loop scheduler** (§3.4 decision) — merged logical-time order over N loops; re-drive `test-fa-liveness-virtual` deterministically, blocks 1..3 byte-identical | FAST + the deterministic run byte-matches across TWO invocations (the replay-twice-identical check) + live cluster unchanged |
| 5 | **FA checkers + adversarial schedules** — FA1/A1/FA6/FA7 over real state each step w/ expect-violation self-tests; deterministic loss/partition/reorder schedules; deterministic S-048 repro | FAST + replay-twice-identical + each checker's planted-bug self-test RED-on-mutant |

The recurring gate across 3-5 is the one KqueueReactor §7 and every prior net
increment used: **goldens byte-identical + FAST + live cluster**, here strengthened
by the **replay-twice-identical** check that is the entire point of the work (run
the same seed twice, assert identical final `compute_state_root()` and identical
per-step trace).

## 5. Risks / open questions

- **[OWNER DECISION] Node no-self-thread mode touches `run()`.** The honest
  minimal version needs the setup of `run()` ([node.cpp:614-670](../../src/node/node.cpp))
  WITHOUT the thread spawns ([:642-644](../../src/node/node.cpp)) and blocking join
  ([:669](../../src/node/node.cpp)). Cleanest is a new `start_external()` that
  shares the setup body with `run()` via a common helper — but extracting that
  helper edits the production `run()` even if behavior is byte-identical. This is
  the same class of owner-gated fork as ClockInjectionSeam.md §6 increment 3
  (whether to link the real engine into `determ-dsf`): a production-path edit for a
  test-only capability. **Not decided:** add `start_external()` (small `run()`
  refactor, proven byte-neutral by the live gate) vs. a bolder mode flag on `run()`
  vs. keeping the harness on threads and abandoning full determinism. Recommend the
  first, gated exactly like the shipped increments; needs the owner's yes before
  any `node.cpp` line changes.

- **[OWNER-ADJACENT] `save_thread_` suppression.** `save_worker_loop`
  ([node.cpp:726](../../src/node/node.cpp)) is a second wall-time thread and a
  second `state_mutex_` reader. Deterministic mode must not spawn it
  ([node.cpp:651](../../src/node/node.cpp)). Options: a mode flag that skips the
  spawn (production edit), or a config that makes save synchronous, or accept that
  the scenario disables persistence. Tied to the same `run()` decision above.

- **[DESIGN] Global cross-loop order (§3.4).** Merged sequence-stamped queue vs.
  round-robin + per-link latency. The former is the smallest correct thing (one
  total order, no latency model); the latter is a richer adversarial knob. **Not
  decided** — recommend shipping the sequence-stamped total order first and layering
  latency later, mirroring how the fault model shipped loss/partition before any
  timing knob.

- **[SCOPE] S-048 fix is separate and owner-gated.** This scheduler unblocks the
  DETERMINISTIC REPRODUCTION of the S-048 same-height fork
  (AdversarialTransportHarness.md §3.1); it does NOT wire `Chain::resolve_fork` or
  the bounded head-reorg, which remain owner-gated
  ([UnitTestCoverageMap: S-048]). The loss-liveness gate stays partially blocked
  until that lands — deterministic scheduling removes the flakiness, not the open
  defect.

- **[VERIFY-AT-IMPLEMENTATION] TimerService untouched claim.** The preferred
  virtual-timer shape (§2b) keeps `TimerService` and its `steady_clock` for the
  native backends and only BYPASSES it in the poll path. This must be proven by
  re-running `test-net-virtual` (which exercises the real `TimerService`) green
  after increment 2 — the native timer path must be byte-neutral, the same
  "prove the refactor byte-neutral first" posture as KqueueReactor §7 step 1.

- **[VERIFY-AT-IMPLEMENTATION] Blocking-consumer closures.** The header warns a
  posted closure may never return (RpcServer sessions occupy a loop thread for the
  connection's lifetime,
  [virtual_transport.hpp:64-69](../../include/determ/net/virtual_transport.hpp)).
  The consensus FA scenarios do not run RpcServer sessions, so the single-thread
  drain never wedges on one — but this must be an explicit precondition of the
  deterministic mode (no blocking posted closures), asserted at scenario-authoring
  time, not discovered at runtime.

- **[NOT YET DECIDED] Latency/adversarial-schedule surface.** Beyond a total order,
  the eventual adversarial-schedule knobs (delayed/reordered delivery, timeout
  injection — AdversarialTransportHarness.md §4) are not specified here; §4
  increment 5 is where they get designed, on top of a proven-deterministic base.
