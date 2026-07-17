# Deterministic Scheduler Design — a no-thread virtual-time drive for the real consensus engine

**Status: increments 1-8 SHIPPED.** This is
the design-review-first step the [KqueueReactorDesign.md](KqueueReactorDesign.md)
discipline mandates for a change that touches shipped orchestration. **Increment 1
(the additive, byte-invariant `VirtualEventLoop::run_until_idle()` — §4 table),
increment 2 (the loop-local VIRTUAL-TIME timer source, §2b/§4), increment 3
(the Node no-self-thread `start_external()` + bounded-step `run_ready()`, §4 table),
increment 4 (the GLOBAL multi-loop scheduler `net::GlobalScheduler` + the two
additive `VirtualEventLoop` accessors `next_virtual_deadline_ms` /
`set_virtual_now_ms`, §3.4/§4 table), increment 5 (ADVERSARIAL schedules —
`test-fa-adversarial-deterministic`: loss/partition/heal + S-050 valve re-probe,
ALL hard gates), increment 6 (deterministic CRASH + RESTART-REJOIN —
`test-fa-crash-deterministic`), increment 7 (the `VirtualNetwork::set_dup`
frame-duplication fault + dup phase), and increment 8 (the per-step FA CHECKERS —
`FaStepMonitor` riding every drain-boundary predicate of both harnesses, with
expect-violation self-tests) are SHIPPED** (pure-std test backend,
production `run()` + the native `TimerService` path both untouched — the inc.3
`run()` refactor is a pure verbatim helper extraction, adversarial-review-confirmed
byte-neutral; the inc.4 accessors are virtual-time-only with zero production
caller; the inc.7 fault default consumes no RNG draw, byte-invariant; the inc.8
monitor is read-only, schedule-neutral). Increment 3 shipped under an explicit OWNER decision (the
inc.3→A4→D3 chain) because the smallest honest version of it touches the production
`run()` path; increment 4 needed no fresh gate (scheduler infra over the concrete
loop + a re-driven test, the same class as inc.1/inc.2). The goal is a fully DETERMINISTIC single-thread scheduler
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
  - **Preferred: a loop-local virtual timer queue. — SHIPPED (increment 2).** In
    virtual-time mode (`enable_virtual_time()`) `VirtualEventLoop::timer_schedule`
    does NOT delegate to `TimerService`; it inserts `{virtual_now + delay, seq, id,
    fn}` into the loop-local `vtimers_` structure and `advance_to_next_timer()` (§d)
    pops the earliest due entry against a `virtual_now_ms_` it owns. No
    `TimerService` change, no timer thread, no `steady_clock` on the virtual path.
    `LoopTimer` ([loop_timer.hpp](../../include/determ/net/loop_timer.hpp)) is
    unaffected — it only holds an id and routes through the same seam
    (`test-scheduler-timers` asserts it fires at its virtual deadline). This is the
    KqueueReactor §2 "recommendation (c)" instinct: prefer the change that adds no
    new lifetime/liveness reasoning. NOTE: increment 2 uses a PER-LOOP `seq`
    counter (sufficient for the single-loop scope); the GLOBAL logical-time
    sequence §3.4 needs is deferred to increment 4 (cross-loop order).
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

8. **The Phase-1 commit-reveal `dh_secret` — block-CONTENT entropy — SHIPPED as an
   injected seam.** The one per-round draw that enters block bytes (and thus
   `cumulative_rand` → the block hash → `resolve_fork`'s "smallest block hash"
   tie-break) was `determ_rng_bytes` at
   [node.cpp:964](../../src/node/node.cpp) (the sole such draw — node keygen is
   once-per-setup; the dapp-subscriber id and genesis salt never enter a block).
   It now reads through an injected `crypto::RngSource& rng_` (the entropy
   analogue of `clock_`): production defaults to `RealRng` (verbatim
   `determ_rng_bytes` — byte-neutral, adversarial-review-confirmed), and a harness
   injects `crypto::SeededRng` (a byte-portable SHA256(seed‖counter) stream) so a
   Byzantine schedule replays byte-for-byte. `test-scheduler-external` assertions
   5–6 prove same-seed → byte-identical blocks and different-seed → different
   blocks. This is the LAST substrate piece for a byte-deterministic S-048 reorg
   repro; the reorg wiring (A4 proper) builds on it.
   ([rng_source.hpp](../../include/determ/crypto/rng_source.hpp),
   [seeded_rng.hpp](../../include/determ/crypto/seeded_rng.hpp))

## 4. What it unblocks + the gate plan

**Byte-reproducible FA4.** With (1) the virtual scheduler, (2) a shared
`VirtualClock`, (3) the virtual transport, (4) the fault model, and (5) the RNG
seam (§3.8 — the per-round `dh_secret` now injectable) all shipped, a scenario
replays byte-for-byte from a seed: same closure order, same timer firings, same
drop sequence, same block content, same digests. Over that substrate the FA1/A1/FA6/FA7
checkers run against the REAL engine state after each scheduler step
(ClockInjectionSeam.md §5 defines this as the concrete closure of F-1/FA4), each
paired with an `expect_violation` planted-bug self-test — the non-vacuity +
negative-control discipline every `test-fa-*` already follows
(RealEngineFAHarness.md §2).

**Deterministic S-048 reproduction — now a HEALS-under-loss regression.**
AdversarialTransportHarness.md §3.1 shows ordinary link loss induces the timing
skew that drives the abort-vs-finalize race into the S-048 same-height fork — but
only NONDETERMINISTICALLY under wall timers. With inc.4 the GlobalScheduler makes a
chosen loss/reorder schedule produce the fork ON DEMAND. **And S-048 is now CLOSED
(A4 `maybe_reorg_to_locked`, BoundedReorgSoundness.md), so this is no longer a
"repro for the pending fix" but a REGRESSION that the A4 depth-1 reorg HEALS the
loss-induced fork deterministically** — the inc.5 payoff, SHIPPED (the loss phase
of `test-fa-adversarial-deterministic` logs the in-run `S-048 REORG` heals, and
its settled-agreement gate proves they converge).

**Reliable loss-liveness gate — now fully unblocked.** Was a NON-gating diagnostic
for TWO reasons (AdversarialTransportHarness.md §3.1/§3.2): "not assertable while
S-048 is open" AND wall-timer convergence flakiness. **Both halves are now
resolved:** inc.4's deterministic schedule removes the flakiness (a fixed schedule
converges or does not, reproducibly — witnessed by the 12/12 stability loop), and
S-048 is CLOSED (A4). The reliable loss-liveness gate SHIPPED in inc.5 as
`test-fa-adversarial-deterministic`'s Phase-1 HARD gate.

**Phased increment plan** (smallest safe first, each with its gate):

| # | Increment | Gate |
|---|---|---|
| 1 | **`VirtualEventLoop::run_until_idle()`** — caller-thread drain, additive; re-drive an existing single-loop test (`test-net-virtual`) through it instead of a spawned thread — **SHIPPED** ([virtual_transport.cpp](../../src/net/virtual_transport.cpp) `run_until_idle`; `test-net-virtual` phase 1b asserts caller-thread FIFO drain == threaded `run()` order, mid-drain re-posts run to quiescence in the same call, empty-queue returns immediately) | goldens byte-identical + FAST 207/0 both platforms + the re-driven test byte-matches the threaded run ✓ |
| 2 | **Virtual-time timer source** — loop-local ordered timer queue consulted by the poll, `virtual_now` advance-to-next-timer — **SHIPPED** (`VirtualEventLoop::enable_virtual_time()` / `advance_to_next_timer()` / `virtual_now_ms()` / `pending_timer_count()` + the loop-local `vtimers_` queue keyed on virtual `now`; `timer_schedule`/`timer_cancel` branch to it only when enabled, else delegate to `TimerService` verbatim — [virtual_transport.cpp](../../src/net/virtual_transport.cpp). Ties broken by `(deadline, seq)` for a stable total order (§3.3); the fired callback runs OUTSIDE the timer lock so it may re-arm/cancel/`post`. Test `test-scheduler-timers` (21 assertions): earliest-deadline-first fire order, virtual-`now` tracking, ~0 wall time (never slept the 200 ms schedule), stable tie-break, SINGLE-fire-per-advance (not batch), nonzero ids, cancel + idempotent double-cancel, reentrant re-arm at `now+delay`, ready-work-before-time-advance, replay-twice-identical, LoopTimer-over-virtual, and the `enable_virtual_time()`-after-native misuse guard) | goldens byte-identical + **FAST 209/0 both platforms** + `test-net-virtual` still green (native/`TimerService` path untouched) ✓ |
| 3 | **`Node::start_external()`** (§5 owner gate) — setup-only entry, spawns no loop/save threads — **SHIPPED** (owner GO for the inc.3→A4→D3 chain). `run()` was refactored by extracting two private helpers `listen_and_connect()` + `arm_startup_grace()` that `run()` now calls in the **same order** it previously inlined them (a pure verbatim extraction — production `run()` byte-neutral, independently confirmed by adversarial review); `start_external()` = `running_=true` + those two helpers, then returns (no loop threads, no save thread, no block). A bounded-step drive primitive `VirtualEventLoop::run_ready(size_t)` was added because an M=K=1 self-quorum node's finalize re-posts the next round with no timer gate — `run_until_idle()` would never return; the driver steps a batch, checks height, and fires the next virtual timer when ready work is exhausted. Test `test-scheduler-external` (5 assertions): self-produces ≥4 blocks with NO loop thread, `virtual_now` advances past the 1500 ms grace (logical time drove it), SCHEDULE determinism (two runs → same block count + same `vnow`), and a teardown-before-grace regression. **Block-CONTENT byte-replay is a SEPARATE seam** (see §3 hazard: each round draws a fresh Phase-1 commit-reveal secret from OS entropy — `determ_rng_bytes` in `start_contrib_phase` — so block bytes differ run-to-run; a deterministic-RNG injection is the remaining prerequisite for inc.5's fully byte-deterministic S-048 repro, tracked as its own consensus-adjacent decision). Teardown hazard found+fixed during review: `~VirtualEventLoop` now drains `vtimers_` with the same move-out-under-lock discipline as the closure queue, so a self-owning grace timer torn down UNfired (an isolated/never-selected A4 node) cannot re-enter `timer_cancel` on the vector mid-destruction (UB) — new `DETERM_ASAN` gate ([`ci_local.sh --asan`](../../tools/ci_local.sh)) covers this class. | goldens + FAST 214/0 both platforms + adversarial review (production `run()` proven untouched) + ASan clean ✓ |
| 4 | **Global multi-loop scheduler** (§3.4 decision) — **SHIPPED.** `net::GlobalScheduler` ([virtual_scheduler.hpp](../../include/determ/net/virtual_scheduler.hpp)) imposes ONE global logical-time order over N `VirtualEventLoop`s: FIXPOINT-drain ready work across ALL loops in index order (cross-loop transport deliveries are `State::post` ready work, not timers, so this settles every message before time advances), then fire the SINGLE global-earliest virtual timer (tie: lowest loop index) after lockstepping EVERY loop's virtual `now` onto the global clock. Two additive `VirtualEventLoop` accessors enable it — `next_virtual_deadline_ms(uint64_t&)` (peek the min deadline without firing) + `set_virtual_now_ms(uint64_t)` (forward-only global-clock lockstep, the §3.4-hazard fix: a lagging loop that arms a timer mid-drain would otherwise past-date it and move logical time backwards) — both virtual-time-only with ZERO production caller. The §3.4 decision landed as the fixed-loop-index fixpoint sweep (a deterministic total order that replays identically) with NO global-seq-stamp on `State::post` (deferred to inc.5 with per-link latency). Test `test-scheduler-multiloop`: FIVE real `node::Node`s (M=5, K=3) on one FROZEN `VirtualClock` + distinct fixed-seed identity keys + distinct fixed `SeededRng`, driven with NO threads — asserts LIVENESS (blocks 1..3 finalized), no-fork AGREEMENT (blocks 1..3 byte-identical across all 5), and REPLAY-TWICE-IDENTICAL (per-node terminal `head_hash` + `state_root` + ordered block list + a scheduler action-trace hash — the last catches an interleave that diverges yet converges). Clock FROZEN at kT0: round timing rides loop virtual-`now`, every `proposer_time == kT0 ==` the validator's clock (0 skew, always valid, trivially deterministic — the same frozen-clock multi-block property inc.3 relies on). Ridealong: gated the epoch-boundary observability `std::cout` (node.cpp) behind `!log_quiet`, consistent with the S-027 per-block-accept gate (console-only, byte-neutral). | goldens byte-identical + **FAST 228/0 both platforms** + replay-twice-identical (assertion b) + a **12/12 stability loop** (deterministic ⇒ 100% reproducible, vs the ~10% flake of the probabilistic threaded harness) + `test-fa-liveness-virtual`/`test-net-virtual`/`test-scheduler-timers` still green (the two accessors are byte-neutral to production `run()`) ✓ |
| 5 | **Adversarial schedules** — **SHIPPED** as `test-fa-adversarial-deterministic` (src/main.cpp): 10% per-frame loss on every link, the {4}\|{1} delivery partition, heal + the S-050 stall-valve re-probe (the valve's wall-clock windows ride the injected `clock_.steady_now()` — the §Q1 seam — stepped in ≤10 s increments at scheduler-quiescent points, inside the validator's ±30 s freshness gate), each a HARD gate — including the loss liveness that was non-gating under wall clocks — plus replay-twice byte-identity over the WHOLE schedule (terminal per-node `head_hash` + `state_root` + the scheduler action-trace hash). The loss phase deterministically produces and A4-heals same-height races (the in-run `S-048 REORG` markers): the "heals-under-loss regression" this section promised. | FAST 231/0 both platforms at ship + replay-twice-identical + wrapper `tools/test_fa_adversarial_deterministic.sh` ✓ |
| 6 | **Deterministic CRASH + RESTART-REJOIN** — **SHIPPED** as `test-fa-crash-deterministic` (src/main.cpp): node4 killed at a deterministic drain boundary (any of its in-flight sends left queued on survivor loops are delivered after the death — the S-047 asymmetric-death INGREDIENT, seed-dependent and not asserted; the crash fault the threaded harness needed 12+ wall-clock loops to sample); ALL-4 survivor liveness (+3 past the kill baseline — STRONGER than the threaded 3-of-4 majority gate, enabled by the A4 reorg + an S-050 valve fallback); settled-prefix fork-freedom; same-identity rejoin on fresh loop/transport (old acceptor port unregistered by the Node dtor; the fresh loop lockstepped onto the cluster's virtual now BEFORE its grace timer arms) over the REAL `GET_CHAIN`/`CHAIN_RESPONSE` sync path, adopting an outage block byte-identically. The live loop set changes at the crash and the rejoin, so each phase drives a FRESH `GlobalScheduler` over exactly the live loops (a loop's virtual now persists; `set_virtual_now_ms` is forward-only); the replay signature hashes the CONCATENATED phase traces. The crashed loop goes `stop()`-permanent (the threaded harness's model) and is never drained again. | MSVC 8/8 stability + Linux GCC + wrapper `tools/test_fa_crash_deterministic.sh` + FAST 240/0 both platforms ✓ |
| 7 | **`VirtualNetwork::set_dup`** — **SHIPPED**: per-link whole-frame DUPLICATION (per-mille, same scope/seeding as `set_loss`; a delivered frame lands in the peer inbox twice back-to-back = the receiver reads the SAME complete Peer message again — the application-level redelivery class the S-047 retry produces routinely, forced at the transport for EVERY message kind). Rate 0 consumes NO RNG draw (byte-invariant default; earlier phases replay identically); dropped frames are not rolled for duplication. `test-fa-adversarial-deterministic` gained a 30%-dup phase gating liveness + settled fork-freedom (receiver dedup/idempotency). | both platforms + byte-neutrality re-runs (`test-net-virtual`, crash, multiloop unchanged) + FAST 240/0 ✓ |
| 8 | **Per-step FA checkers** — **SHIPPED** as `FaStepMonitor` (src/main.cpp, shared by both deterministic harnesses), hardened per its own adversarial review: a READ-ONLY monitor riding every `run_until` done() predicate — FA1 settled-prefix agreement (the first observer of a settled index — strictly below the head, the A4 depth-1 bound — pins canonical bytes WITH provenance; later first-walk divergence, incl. a rejoiner adopting wrong bytes, is a violation) plus a ROLLING REWRITE PROBE (one already-pinned index re-fetched and byte-compared per observation — EVENTUAL, not instantaneous, coverage of in-place rewrites of settled history; without it a pinned index below every watermark would never be read again), per-node height monotonicity (a deliberate restart erases that node's watermark), and the A1 supply equality (`rpc_chain_summary` `total_supply == expected_total`) at EVERY observation, height-stalled nodes included. Schedule neutrality is STRUCTURAL (no posts, no timers, shared-lock reads only); the in-run replay gates witness determinism-WITH-observation, not neutrality vs. the pre-monitor schedule — nothing pins cross-commit schedule bytes, and nothing needs to. Each harness gates an expect-violation SELF-TEST (planted rewrite + planted walk divergence + planted height rollback must ALL be caught) plus a COVERAGE gate (all nodes observed, canonical non-empty / extending past the kill baseline — a silently unwired monitor cannot green). | both platforms + monitor-clean + coverage + self-test hard checks + replay-twice-identical incl. monitor verdicts + FAST 240/0 ✓ |

The recurring gate across 3-5 is the one KqueueReactor §7 and every prior net
increment used: **goldens byte-identical + FAST + live cluster**, here strengthened
by the **replay-twice-identical** check that is the entire point of the work (run
the same seed twice, assert identical final `compute_state_root()` and identical
per-step trace).

## 5. Risks / open questions

- **[RESOLVED — increment 3 SHIPPED under the owner's inc.3→A4→D3 GO.]** The
  recommended first option landed: `start_external()` over two verbatim-extracted
  helpers, production `run()` byte-neutral (adversarial-review-confirmed). Kept
  below as the original decision record. The honest
  minimal version needs the setup of `run()` without the thread spawns and
  blocking join. Cleanest is a new `start_external()` that
  shares the setup body with `run()` via a common helper — but extracting that
  helper edits the production `run()` even if behavior is byte-identical. This is
  the same class of owner-gated fork as ClockInjectionSeam.md §6 increment 3
  (whether to link the real engine into `determ-dsf`): a production-path edit for a
  test-only capability. Options were: add `start_external()` (small `run()`
  refactor, proven byte-neutral by the live gate) vs. a bolder mode flag on `run()`
  vs. keeping the harness on threads and abandoning full determinism.

- **[RESOLVED with increment 3] `save_thread_` suppression.** `start_external()`
  spawns neither loop threads nor the save worker; `stop()`'s final synchronous
  save covers persistence for a deterministic run (increment 6's rejoiner relies
  on exactly that on-disk tail).

- **[RESOLVED with increment 4] Global cross-loop order (§3.4).** Landed as the
  fixed-loop-index fixpoint sweep — one deterministic total order, NO
  global-seq-stamp on `State::post` and no latency model. The adversarial knobs
  shipped instead as delivery faults (loss, partition, duplication — increment 7);
  a per-link latency model remains unshipped and would be its own increment.

- **[SCOPE] S-048 fix is separate and owner-gated.** This scheduler unblocks the
  DETERMINISTIC REPRODUCTION of the S-048 same-height fork
  (AdversarialTransportHarness.md §3.1); it does NOT wire `Chain::resolve_fork` or
  the bounded head-reorg, which remain owner-gated
  ([UnitTestCoverageMap: S-048]). The loss-liveness gate stays partially blocked
  until that lands — deterministic scheduling removes the flakiness, not the open
  defect.

- **[VERIFIED — increment 2] TimerService untouched claim.** The shipped
  virtual-timer shape (§2b) keeps `TimerService` and its `steady_clock` for the
  native backends and only BYPASSES it when `enable_virtual_time()` was called
  (the default `virtual_time_ == false` path delegates verbatim). CONFIRMED:
  `test-net-virtual` (which exercises the real `TimerService`) is green after
  increment 2 on both platforms — the native timer path is byte-neutral, the same
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
