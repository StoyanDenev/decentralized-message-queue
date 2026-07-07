# Clock Injection Seam — byte-invariant §Q1/§Q2 dependency injection

**Status:** increment 1 SHIPPED (the `time::Clock` interface + `Node` ctor seam +
operational-read rewire, byte-invariant). Increments 2-6 planned; increment 3
carries an owner-gated architecture decision (see §6). Relates to
[DSF-SPEC.md](DSF-SPEC.md) §Q1/§Q2 and the F-1/FA4 gaps in
[UnitTestCoverageMap.md](UnitTestCoverageMap.md).

## 0. The one fact the design turns on

The entire consensus/production tree reads wall time through **one** inline
helper, `determ::now_unix()` ([include/determ/types.hpp:93](../../include/determ/types.hpp)):

```cpp
inline int64_t now_unix() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}
```

Everything digest-bound that involves time is a `uint64_t`/`int64_t` **value**
derived from this integer and appended to a `SHA256Builder`. The digest bytes
depend **only on the integer**, never on how it was sourced. Therefore a `Clock`
whose `RealClock` returns the byte-identical `now_unix()` value produces
byte-identical proposer_times, block timestamps, abort hashes, block digests,
K-of-K signatures, and state roots. **This is the entire byte-invariance
guarantee for the default path.**

A second load-bearing fact: the golden vectors (`test-consensus-vectors`, the
c99 goldens) and the FAST determinism suite construct `Block`s with hard-coded
timestamps and **never call `now_unix()`**. They are invariant under any
rewiring of `now_unix()` call sites as long as `RealClock` delegates verbatim.

## 1. The consensus time sites (verified anchors)

| Site | Anchor | Digest-bound? | Role |
|---|---|---|---|
| proposer_time (S-043) | [node.cpp:906](../../src/node/node.cpp) | **YES** | signed `ContribMsg` → `reconcile_median_time` → `b.timestamp` → `compute_block_digest` |
| abort-event ts (S-043 class) | [node.cpp:1294](../../src/node/node.cpp) | **YES** | `ev.timestamp` + `ev.event_hash` → view-abort root → `compute_block_digest`; peers adopt verbatim |
| assembler fallback | [producer.cpp:812](../../src/node/producer.cpp) | no (overwritten by median on the production path; only binds legacy block identity) | free function; hoist value from the Node caller |
| ±30s freshness gate | [validator.cpp:1414](../../src/node/validator.cpp) | no (accept/reject at VERIFY time) | needs a shared clock so producer + validator agree under simulation |
| subscriber heartbeat | [node.cpp:3453](../../src/node/node.cpp) / [:3507](../../src/node/node.cpp) | no (informational) | rewired in increment 1 |

`reconcile_median_time`, `check_timestamp`'s median re-derivation,
`light_compute_block_digest`, and genesis (`timestamp=0`) read **no** clock. The
apply/state-commitment path (`chain.cpp`) is clock-free, so **state roots are
time-independent** — only block digests and the ±30s gate depend on time.

## 2. The interface (increment 1, shipped)

[include/determ/time/clock.hpp](../../include/determ/time/clock.hpp) — a
read-only consumer interface, deliberately two reads so the consensus read can
never be routed through a monotonic/epoch-less source:

- `int64_t unix_seconds() const` — CONSENSUS wall time; `RealClock` returns
  `determ::now_unix()` **verbatim** (same `system_clock`, `duration_cast<seconds>`
  truncation, `int64_t` width).
- `std::chrono::steady_clock::time_point steady_now() const` — NON-digest
  scheduling (timeouts, freshness deltas, profiling); never enters a digest.

The DSF-SPEC §Q1 sketch proposed `now() -> steady_clock::time_point`. That type
is **wrong for the consensus path**: proposer_time binds `system_clock` int64
seconds (epoch-anchored), whereas `steady_clock` is monotonic and epoch-less.
Routing proposer_time through a `steady_clock::time_point` would silently change
the bytes. The shipped interface separates the two reads to make that impossible.

## 3. How defaulting preserves bytes

Injection is a **defaulted trailing ctor parameter**, so no existing caller
changes:

```cpp
explicit Node(const Config& cfg,
              time::Clock& clock = time::RealClock::instance());
```

`clock_` is declared and initialized immediately after `cfg_` (no `-Wreorder`;
the fragile `gossip_(io_)` fragment is untouched). `Node` already held an
`asio::io_context` member, so it was already non-copyable — the reference member
changes nothing there. Because `RealClock::unix_seconds() == now_unix()`, every
default-path value is the integer it is today.

## 4. How the DSF eventually drives real objects (units)

`sim::VirtualClock` is `VTime = uint64_t` nanoseconds-from-origin-0 (monotonic,
no wall read). A sim-side adapter maps it to the consensus read:

```cpp
int64_t unix_seconds() const override {
    return origin_unix_s_ + int64_t(vc_.now() / 1'000'000'000ull);
}
```

All committee members in a scenario share **one** SimClock so
`reconcile_median_time` still agrees and the ±30s gate passes. The origin is
seeded/fixed per (scenario, seed) for §Q6 byte-reproducibility and `≥ 1.5e9`
so the existing "plausible post-2017 / non-decreasing" unit tests still hold.

## 5. What "closes F-1/FA4" concretely means

A DSF scenario that (1) links the real `Node`/`BlockValidator`/producer, (2)
constructs them with a SimClock + a virtual transport, (3) drives a full
Phase-1 → Phase-2 → abort round deterministically and byte-reproducibly from a
seed, and (4) runs the FA1/A1/FA6/FA7 checkers over the **real** engine state
after each scheduler event, each paired with an `expect_violation` planted-bug
self-test.

## 6. Phased plan + the owner-gated fork

1. **Increment 1 (SHIPPED, byte-invariant):** interface + Node ctor seam +
   operational-heartbeat rewire. Gate: 3-target build + goldens + FAST 196/0 +
   a `RealClock == now_unix()` delegation assertion; GCC-13 header check.
2. **Increment 2 (production-side, byte-invariant):** rewire the two digest-bound
   Node sites (node.cpp:906, :1294) to `clock_.unix_seconds()`; give
   `BlockValidator` a `set_clock()` for the ±30s gate; hoist the producer
   fallback value from the Node caller (keep the free function clock-free). Gate:
   goldens + FAST unchanged (still invariant, RealClock delegates verbatim).
3. **Increment 3 (build linkage) — OWNER-GATED ARCHITECTURE FORK:** to drive the
   real engine, `determ-dsf` must link the consensus objects (a `determ-core`
   static lib = `src/*.cpp` minus `main.cpp`). That drags **asio + OpenSSL** into
   `determ-dsf`, reversing its current "self-contained, no OpenSSL/asio/core"
   property. Compile-once (a shared static lib) is the determinism-safe choice
   (flag parity); a determ-light-style recompile does **not** guarantee flag
   parity and could silently fork digests. **Decision required before building.**
4. **Increment 4 (`net::Transport`, §Q2):** `AsioTransport` (prod default) +
   `VirtualTransport` (sim: owns delivery order/latency/partition + drives the
   timers off the scheduler).
5. **Increment 5:** sim `Clock` adapter + a scenario that drives a REAL
   Node/Validator/producer round, replacing the toy `SimState`.
6. **Increment 6:** wire FA1/A1/FA6/FA7 as checkers over the real engine — the
   concrete closure of F-1/FA4.

## 7. Determinism risks the implementer must guard

- **Expression drift:** `RealClock::unix_seconds()` must stay a verbatim delegate
  to `now_unix()` (system_clock, NOT steady; same truncation/width). Pinned by
  the delegation assertion.
- **Cast drift** at node.cpp:906: keep `static_cast<uint64_t>(...)` at the call
  site.
- **Second-site omission (the S-043 class):** both node.cpp:906 AND :1294 are
  digest-bound and must share the same injected clock, or sim replay cannot
  control abort digests.
- **Shared-clock ±30s gate:** producer and validator must resolve to the same
  Clock instance under simulation or a valid block self-rejects (liveness wedge).
- **Producer legacy fallback** (producer.cpp:812) binds legacy block identity via
  `compute_hash`; keep the free function clock-free and hoist the value.
- **Build-flag/inline-ODR divergence:** the shared engine must be compiled under
  identical flags for `determ` and `determ-dsf` — the compile-once `determ-core`
  static lib guarantees this; a per-target recompile does not.
- **Genesis + apply trap:** genesis `timestamp=0` and the clock-free apply path
  must NOT be routed through `Clock`.
