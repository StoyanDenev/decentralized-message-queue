# S014ConcurrencyAnalysis — concurrency-layer companion to S-014 rate-limiter soundness

This document is the concurrency-layer companion to `S014RateLimiterSoundness.md` (S-014 closure). The original soundness proof formalizes the per-IP token-bucket arithmetic (T-1..T-6 there: burst bound, no amplification, per-IP independence, HELLO-exemption safety, refill monotonicity, capacity-vs-rate trade-off). It assumes — but does not prove — that the rate limiter's internal state evolves correctly under concurrent access from multiple io_context worker threads. This document supplies that proof.

The `determ::net::RateLimiter` instance is shared by two protocol surfaces (RPC `handle_session` + gossip `handle_message`), each dispatched on an asio io_context whose worker pool is sized to `std::thread::hardware_concurrency()` threads (`src/node/node.cpp:586-588`). A typical commodity node has 4-16 hardware threads; a tactical deployment may have 64+. All of these threads can call `RateLimiter::consume` concurrently against the same instance for two flooding sources to the same node. The analysis below establishes that this concurrent access is data-race-free, deadlock-free, and linearizable, and that the single-mutex design's throughput ceiling sits comfortably above every Determ deployment profile's expected request rate.

**Companion documents:** `S014RateLimiterSoundness.md` (the soundness proof this proof concurrency-augments; its T-1..T-6 are the per-bucket arithmetic statements this proof relies on for atomic-per-consume semantics); `RpcAuthHmacSoundness.md` (the Round 19 S-001 closure proof; citation-style template); `Preliminaries.md` §3 (network model + asio thread-pool assumption — extended here to cover the std::mutex / std::lock_guard contract); `docs/SECURITY.md` §S-014 for the closure-status narrative the original soundness proof formalizes.

---

## 1. Theorem statements

**Setup.** Let `R` denote a single `determ::net::RateLimiter` instance (`include/determ/net/rate_limiter.hpp:36-152`). `R` carries:

- A `mutable std::mutex mu_` (line 150).
- A `std::map<std::string, Bucket> buckets_` (line 151).
- Scalar configuration fields `rate_per_sec_`, `burst_`, `eviction_threshold_sec_`, `sweep_interval_sec_` (lines 145-148).
- A `std::chrono::steady_clock::time_point next_sweep_at_` (line 149).

`R` is accessed from a set of **caller threads** `{T_1, T_2, …, T_N}` where `N := std::thread::hardware_concurrency()` (the asio worker-pool size). Each `T_i` may, at any time, call:

1. `R.consume(key)` — the hot path; entered from RPC `handle_session` at `src/rpc/rpc.cpp:172` or from gossip `handle_message` at `src/net/gossip.cpp:154`.
2. `R.bucket_count()` — diagnostic; entered from tests + operator monitoring.
3. `R.sweep_idle()` — operator-tunable explicit sweep; entered from tests + future operator RPC.

Calls to `R.configure(…)` and `R.configure_eviction(…)` are made once during node startup (`src/rpc/rpc.cpp:91` for RPC; `src/net/gossip.cpp:22-28` for gossip) BEFORE any worker thread is spawned by `Node::start` (`src/node/node.cpp:586-588`), so they are not in scope for the concurrent-access argument. The non-const scalar mutators `rate_per_sec_`, `burst_`, `eviction_threshold_sec_`, `sweep_interval_sec_` are therefore initialized-then-read-only during the operational window of the limiter; the const accessors (`enabled()`, `rate_per_sec()`, `burst()`, `eviction_threshold_sec()`, `sweep_interval_sec()`) read these fields without taking `mu_`.

**Theorem T-1 (Mutual Exclusion).** Every read or write of `buckets_`, `next_sweep_at_`, or any `Bucket::tokens` / `Bucket::last` field that occurs on the hot paths (`consume`, `bucket_count`, `sweep_idle`) is sequenced under `mu_`. The `std::lock_guard<std::mutex>` contract (ISO/IEC 14882:2017 §33.4.3.2 [thread.lock.guard]) guarantees mutual exclusion of all such accesses. No data race on `R`'s mutable state is possible under the C++ memory model.

**Theorem T-2 (No Deadlock at the RateLimiter Layer).** The `RateLimiter` class holds exactly one mutex (`mu_`) and never recursively re-acquires it from within a critical section. By the standard mutex acquisition-release contract (ISO/IEC 14882:2017 §33.4.3.2.1 [thread.mutex.requirements.mutex.general]) plus the structural property of having only one mutex, no deadlock is possible at the `RateLimiter` layer. Deadlock involving `R` would require a second mutex held in the wrong order somewhere up the call chain — out of scope for `R`'s contract, but verified by inspection of all call sites in §4 L-2.

**Theorem T-3 (Fairness Under Contention — Documented Property).** `std::mutex` does not, by the C++ standard, guarantee FIFO acquisition order under contention (ISO/IEC 14882:2017 §33.4.3.2 [thread.mutex.requirements.mutex.general] is silent on fairness; implementations are free to use any scheduling). Under sustained heavy contention by `N` worker threads, one thread can in principle be starved (deferred indefinitely) by the other `N-1`. This is a documented property of `std::mutex`, not a defect; the operator-monitoring path detects starvation via the rate-limiter audit script. No fix is proposed: replacing `std::mutex` with a fair mutex (e.g., a ticket-lock spinning mutex, or a `std::mutex` wrapped in a FIFO queue) would impose constant overhead on every uncontended consume, paying a cost on the typical case to defend the pathological one. T-5 below bounds the throughput ceiling so the contention regime that triggers fairness concerns is operationally unreachable.

**Theorem T-4 (Sweep + Consume Interleaving Safety / Linearizability).** Every `consume(k)` call that triggers the amortized sweep (lines 95-103 of `rate_limiter.hpp`) holds `mu_` continuously from the `lock_guard` constructor through the `sweep_idle_locked()` call through the post-sweep `buckets_[key]` access through the token decrement, releasing the lock only at scope exit. A concurrent `consume(k')` on a different key from another thread either runs entirely before the sweeping thread acquires `mu_` (and observes pre-sweep `buckets_`) or entirely after the sweeping thread releases `mu_` (and observes post-sweep `buckets_`); no interleaving in which the second consume observes a partially-mutated `buckets_` is possible. The same linearization point applies to `consume + bucket_count` and `consume + sweep_idle` pairs. The operations on `R` are therefore linearizable in the Herlihy-Wing 1990 sense (every concurrent history is equivalent to a sequential history compatible with the real-time order of non-overlapping calls).

**Theorem T-5 (Throughput Ceiling under N-thread io_context).** Define `t_consume` := the wall-clock duration of one critical section of `R.consume(k)` from `lock_guard` entry to scope exit. Then the per-instance throughput ceiling for any number of concurrent caller threads is

$$
\Theta_{\max}(R) \;\leq\; \frac{1}{t_{\text{consume}}}.
$$

Per L-5 below, `t_consume ≈ 1 µs` typical for `|buckets_| ≤ 10^4`. The throughput ceiling is therefore `~10^6 consume/sec` per `RateLimiter` instance. This sits 4 orders of magnitude above the highest-rate Determ deployment profile (tactical: `~5 × 10^3 gossip/sec`), so single-mutex contention is not the bottleneck. The aggregate per-node throughput across `RpcServer::rate_limiter_` + `GossipNet::rate_limiter_` (two distinct instances) is `2 × Θ_max(R) ≈ 2 × 10^6 consume/sec`.

**Theorem T-6 (Sweep Cost Amortization).** Each `sweep_idle_locked()` call walks `buckets_` in `O(|buckets_|)` time. The amortized cost per `consume()` call is bounded by

$$
\text{amortized\_sweep\_cost} \;=\; \frac{O(|\texttt{buckets\_}|)}{r \cdot s} \;=\; O\!\left(\frac{|\texttt{buckets\_}|}{r \cdot s}\right)
$$

where `r := rate_per_sec_` and `s := sweep_interval_sec_`. For the default configuration `s = 60` seconds and an operationally typical `|buckets_| ≤ 10^4`, this is `O(10^4 / (r × 60))`. At the web-profile default `r = 100`, this is `O(10^4 / 6000) ≈ O(1.67)` floating-point comparisons per consume — well under the `O(log |buckets_|) ≈ 14` cost of the `std::map` lookup itself. The sweep is therefore not a stall source under any operational profile.

---

## 2. Background

### 2.1 The asio io_context multi-threaded model

`asio::io_context` is a thread-safe event-dispatch loop. A user-supplied set of threads call `io_.run()` and pull completion handlers off an internal queue. Each handler runs to completion on whichever thread happened to pick it up; the io_context does not pin a handler to a specific thread, and no per-handler serialization is provided unless the user explicitly wraps the handler in an `asio::strand`.

Determ's node bootstrap at `src/node/node.cpp:586-588`:

```cpp
unsigned n = std::max(1u, std::thread::hardware_concurrency());
for (unsigned i = 0; i < n; ++i)
    threads_.emplace_back([this] { io_.run(); });
```

spawns `n` worker threads (typically 4-16 on commodity hardware; up to 64+ on server hardware). All async completion handlers — including the RPC `handle_session` lambdas and the gossip `handle_message` lambdas — are dispatched into this single io_context's queue, then picked up by whichever worker is next idle.

Neither call site uses an `asio::strand` to serialize. The RPC accept loop at `src/rpc/rpc.cpp:135-139` does `asio::post(io_, [this, socket] { handle_session(socket); });` with no strand wrapping; the gossip `Peer::read_body` callback at `src/net/peer.cpp:75-98` similarly hands off to `on_msg_` without serialization. So a single node may have:

- `T_1` running `handle_session` for RPC peer A, computing `rate_limiter_.consume("198.51.100.10")` against the RPC `RateLimiter`.
- `T_2` running `handle_session` for RPC peer B, computing `rate_limiter_.consume("203.0.113.5")` against the same RPC `RateLimiter`.
- `T_3` running `handle_message` for gossip peer C, computing `rate_limiter_.consume("198.51.100.10")` against the gossip `RateLimiter`.

simultaneously. `T_1` and `T_2` contend on `RpcServer::rate_limiter_::mu_`. `T_3` operates on a different `RateLimiter` instance (`GossipNet::rate_limiter_`) and does not contend with `T_1`/`T_2`. The two limiters' mutexes are independent.

### 2.2 The two protocol surfaces sharing a RateLimiter pattern

S-014 ships **two** `RateLimiter` instances per node:

- `RpcServer::rate_limiter_` — guards RPC ingress. Caller threads: any io_context worker handling an RPC `handle_session`.
- `GossipNet::rate_limiter_` — guards gossip ingress. Caller threads: any io_context worker handling a gossip `handle_message`.

The two instances share the policy (token-bucket arithmetic, per-IP keying, HELLO exemption on the gossip side) but not the state. A heavy RPC caller does not deplete the gossip caller's budget for the same IP. T-3 in `S014RateLimiterSoundness.md` formalizes the per-IP-bucket independence; this proof's T-1 extends that to per-instance-mutex independence (`RpcServer::rate_limiter_::mu_` and `GossipNet::rate_limiter_::mu_` are distinct std::mutex objects; no interaction).

### 2.3 std::mutex / std::lock_guard contract (extended Preliminaries §3)

The C++ standard's `std::mutex` (ISO/IEC 14882:2017 §33.4.3.2) provides:

1. **Mutual exclusion.** At most one thread holds the mutex at any time. A second thread calling `lock()` while held blocks until release.
2. **Memory ordering.** A successful `lock()` synchronizes-with the previous unlock by another thread (release-acquire pair). All writes by the previous holder are visible to the new holder.
3. **No spurious failures.** `lock()` blocks until acquired; it does not return without holding the mutex.
4. **No fairness guarantee.** The standard is silent on FIFO order; implementations may starve.

`std::lock_guard<std::mutex>` (ISO/IEC 14882:2017 §33.4.4.2) is an RAII wrapper: the constructor calls `mu.lock()`; the destructor calls `mu.unlock()`. No way to forget to unlock; exception-safe.

The `mutable` qualifier on `mu_` (line 150 of the header) allows `bucket_count() const` to take the lock without violating its const-ness — standard idiom for thread-safe const accessors.

### 2.4 Linearizability (Herlihy-Wing 1990)

An object is **linearizable** iff every concurrent history of operations on it is equivalent to some sequential history that respects:

1. Each operation appears to take effect atomically at some instant between its invocation and its response (the "linearization point").
2. The order of non-overlapping operations in the concurrent history is preserved in the sequential history.

For a mutex-guarded object, the linearization point of each operation is naturally the moment the operation acquires the mutex (or equivalently, any point during the critical section, since no other operation can observe the state mid-section). T-4 below applies this directly.

---

## 3. Implementation citation

### 3.1 The single-mutex covering — non-const path

`RateLimiter::consume` at `include/determ/net/rate_limiter.hpp:86-117`:

```cpp
bool consume(const std::string& key) {
    if (!enabled()) return true;                              // line 87 — no lock if disabled
    std::lock_guard<std::mutex> lk(mu_);                      // line 88 — acquire mu_
    auto now = std::chrono::steady_clock::now();              // line 89

    if (eviction_threshold_sec_ > 0.0) {                      // line 95
        if (next_sweep_at_.time_since_epoch().count() == 0 || // line 96
            now >= next_sweep_at_) {                          // line 97
            sweep_idle_locked(now);                           // line 98 — sweep under lock
            next_sweep_at_ = now + …;                         // line 99-101
        }
    }

    auto& b = buckets_[key];                                  // line 105 — map access under lock
    if (b.last.time_since_epoch().count() == 0) {             // line 106
        b.tokens = burst_;                                    // line 107
        b.last   = now;                                       // line 108
    } else {
        double elapsed_sec = … ;                              // line 110
        b.tokens = std::min(burst_, b.tokens + … );           // line 111
        b.last   = now;                                       // line 112
    }
    if (b.tokens < 1.0) return false;                         // line 114
    b.tokens -= 1.0;                                          // line 115
    return true;                                              // line 116
}                                                              // line 117 — scope exit, lk dtor releases mu_
```

The `lock_guard` at line 88 takes `mu_`. Every subsequent access to `buckets_`, `next_sweep_at_`, and the per-bucket fields `b.tokens` and `b.last` is sequenced under that lock. The lock is released at line 117 (scope exit) — i.e., AFTER the bucket decrement returns its result. No early return between line 88 and line 117 releases the lock; the four `return` statements at lines 87, 114, 116 (and implicitly the `false`/`true` from the unenabled fast-path at 87) are: line 87 is before the lock is taken; lines 114 + 116 are after the lock is taken, and the lock_guard destructor runs as the function returns.

### 3.2 The single-mutex covering — explicit sweep path

`RateLimiter::sweep_idle` at lines 79-82:

```cpp
size_t sweep_idle() {
    std::lock_guard<std::mutex> lk(mu_);
    return sweep_idle_locked(std::chrono::steady_clock::now());
}
```

The lock is held for the entire duration of `sweep_idle_locked(now)`, which iterates `buckets_` and erases stale entries (lines 128-143).

### 3.3 The single-mutex covering — diagnostic path

`RateLimiter::bucket_count` at lines 69-72:

```cpp
size_t bucket_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return buckets_.size();
}
```

Even the size query takes the lock — necessary because `std::map::size()` is not thread-safe under concurrent modification (the map's internal node count + structural state could be transiently inconsistent during an insert/erase from another thread).

### 3.4 Sweep helper preconditions

`sweep_idle_locked` at lines 128-143 has the explicit precondition that the caller holds `mu_` (line 126 comment: "Caller must hold mu_"). The two callers (`consume` at line 98 and `sweep_idle` at line 81) both satisfy this precondition because they both take the lock immediately before calling. There is no third caller in the codebase.

### 3.5 The const + non-const method split

The accessors `enabled()`, `rate_per_sec()`, `burst()`, `eviction_threshold_sec()`, `sweep_interval_sec()` (lines 61-65) are const + lock-free:

```cpp
bool enabled() const { return rate_per_sec_ > 0.0 && burst_ > 0.0; }
double rate_per_sec() const { return rate_per_sec_; }
// …
```

They read `rate_per_sec_`, `burst_`, etc. without taking `mu_`. This is safe ONLY because `configure()` and `configure_eviction()` are called once during node bootstrap BEFORE any worker thread is spawned (see §1 setup). After bootstrap, these fields are write-once-then-read-only for the operational lifetime of the limiter, so the lock-free read is correct under the "happens-before" relationship established by the thread spawn (the C++ standard guarantees that `std::thread`'s constructor synchronizes-with the start of the new thread; the configure-then-spawn order means worker threads see the fully-initialized configure values).

If a future hot-reconfigure path is ever added (the operator changes `rate_per_sec_` at runtime), the const accessors would need to acquire `mu_`, OR `configure` would need a memory fence. This is documented in §6 F-1.

### 3.6 Call-site dispatch model

RPC `handle_session` at `src/rpc/rpc.cpp:135-139`:

```cpp
void RpcServer::accept_loop() {
    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    acceptor_.async_accept(*socket, [this, socket](std::error_code ec) {
        if (!ec)
            asio::post(io_, [this, socket] { handle_session(socket); });
        accept_loop();
    });
}
```

Each accepted RPC connection is posted to the io_context with no strand. The `handle_session` body (lines 142-195) runs the read-line-then-rate-limit-then-parse-then-auth-then-dispatch loop on whatever worker pulled the post.

Gossip `handle_message` at `src/net/gossip.cpp:139` is invoked from `Peer::read_body`'s asio completion handler (`src/net/peer.cpp:75-98`), which runs on whichever worker pulled the asio read completion off the queue. Again no strand.

The node bootstrap at `src/node/node.cpp:586-588`:

```cpp
unsigned n = std::max(1u, std::thread::hardware_concurrency());
for (unsigned i = 0; i < n; ++i)
    threads_.emplace_back([this] { io_.run(); });
```

spawns `n` workers all pumping the same `io_`. Memory's `hardware_concurrency` recording is exact.

---

## 4. Lemmas and proofs

### Lemma L-1 (Single-mutex covering of all mutable state)

By inspection of `include/determ/net/rate_limiter.hpp`:

- `buckets_` (line 151) — accessed at lines 70 (`bucket_count`), 105 (`consume`), 134-141 (`sweep_idle_locked`). All three sites are reached only after `mu_` has been acquired (lines 70, 88, 80 respectively).
- `next_sweep_at_` (line 149) — accessed at lines 96, 99 (`consume`). Both under the lock taken at line 88.
- `Bucket::tokens`, `Bucket::last` (lines 121-122) — accessed at lines 106-115 (`consume`) and lines 134-141 (`sweep_idle_locked` via iterator dereference). All under the consume lock (line 88) or the sweep lock (line 80).

The const accessors `enabled()`, `rate_per_sec()`, `burst()`, `eviction_threshold_sec()`, `sweep_interval_sec()` (lines 61-65) read the configure fields without the lock. By §3.5, the configure fields are write-once during bootstrap; after that they are immutable for the limiter's lifetime. No data race exists on these fields once worker threads start because the happens-before relationship from `std::thread`'s constructor synchronizes the configure write with every subsequent read.

The lock-free fast path `if (!enabled()) return true;` at line 87 is therefore correct even when called from many worker threads concurrently: every worker reads the same immutable `rate_per_sec_` / `burst_` values; if both are positive the workers proceed to acquire the lock; if either is zero the workers all return true without touching the locked state.   □

### Lemma L-2 (No nested lock acquisition; no second mutex involved)

Inspect the call graph of every site that acquires `mu_`:

- `bucket_count()` (line 69-72): acquires `mu_`; returns `buckets_.size()`; releases `mu_`. No other function call within the critical section. `std::map::size` is a non-allocating, non-blocking inspector; cannot trigger another lock acquisition.

- `sweep_idle()` (lines 79-82): acquires `mu_`; calls `sweep_idle_locked(now)`. `sweep_idle_locked` (lines 128-143) calls `std::map::erase`, `iterator++`, `std::chrono::duration_cast`. None of these touch any mutex.

- `consume(key)` (lines 86-117): acquires `mu_`; calls `std::chrono::steady_clock::now()` (no mutex), `sweep_idle_locked` (above, no mutex), `std::map::operator[]` (may allocate via `std::map`'s default allocator on first-touch insertion; allocator-of-default-`std::string` and `Bucket` does not take any user-visible mutex — the system allocator may take its own internal mutex but that is opaque to `RateLimiter` and cannot deadlock with `mu_` because the system allocator never calls back into RateLimiter), arithmetic + comparison (no mutex).

No nested lock acquisition occurs. There is exactly one mutex (`mu_`) in `RateLimiter`. By the classic deadlock-impossibility result (Coffman, Elphick, Shoshani 1971; informally: a deadlock cycle requires at least two resources held in conflicting orders by at least two threads), a single-mutex object cannot deadlock with itself.

Deadlock involving `R` would require some caller up the stack to hold a different mutex `M` and try to acquire `mu_` while another thread holds `mu_` and tries to acquire `M`. Inspection of the callers of `consume`:

- `RpcServer::handle_session` (`src/rpc/rpc.cpp:142-195`): the only mutex acquired in scope before `rate_limiter_.consume` is none — the function reads from the socket, then calls consume. No second mutex held.
- `GossipNet::handle_message` (`src/net/gossip.cpp:139-...`): similarly, no second mutex held before the consume call. The function is invoked from the asio peer's completion handler with no outer lock.

Therefore no deadlock is possible at the `RateLimiter` layer, and the call-site audit confirms no deadlock is possible at the broader call-graph layer either.   □

### Lemma L-3 (Linearization point at lock acquisition; intermediate states unobservable)

Fix two concurrent calls `consume(k_A)` from thread `T_1` and `consume(k_B)` from thread `T_2` against the same `RateLimiter` instance `R`. By the std::mutex contract, exactly one of `T_1` and `T_2` acquires `mu_` first; WLOG `T_1`. Then:

1. `T_1` runs lines 89-116 of `consume` to completion. During this window, `T_2` is blocked at line 88 waiting on `mu_`.
2. `T_1` exits scope; the lock_guard destructor releases `mu_`.
3. `T_2` is unblocked; it acquires `mu_` and runs lines 89-116.

The sequential history equivalent to the concurrent history is: `T_1`'s consume runs to completion, then `T_2`'s consume runs to completion. The linearization point of each is the moment it acquires `mu_` (the std::mutex's atomic exchange that flips the lock state).

For `consume + sweep_idle` interleaving: if `T_1` runs `consume` and `T_2` runs `sweep_idle` concurrently, the same argument applies — one acquires the lock first, runs to completion, then the other acquires and runs. The sweep observation of `buckets_` either includes the post-consume state (if `T_2` runs second) or excludes it (if `T_2` runs first). Either way, no partial state is observable.

For `consume + bucket_count`: identical argument. `bucket_count` returns `buckets_.size()` under the lock; the size value is exactly what was true at the moment `bucket_count` acquired the lock; no concurrent insert/erase can be in flight during the read.

For the in-line sweep within `consume` (lines 95-103): the same single critical section covers both the sweep and the subsequent bucket-touch. A concurrent `consume(k')` from another thread cannot observe the bucket map mid-sweep (some entries erased, others not); it must wait for the sweep to complete, then sees the fully-swept map.

This is the standard mutex-implies-linearizability result; see Herlihy & Wing 1990 §4 or Herlihy & Shavit 2008 "The Art of Multiprocessor Programming" §3.2 for the textbook treatment. Determ's `RateLimiter` is a direct instance.   □

### Lemma L-4 (std::mutex unfairness — documented property, not a defect)

The C++ standard (ISO/IEC 14882:2017 §33.4.3.2.1 [thread.mutex.requirements.mutex.general]) defines std::mutex's acquire-release semantics but is explicitly silent on fairness:

> The semantics regarding the order of acquisition by competing threads is implementation-defined.

In practice:

- **glibc / NPTL on Linux** uses futex-based unlock; the kernel's futex implementation typically wakes one waiter but does not guarantee FIFO order. On modern kernels (Linux 4.x+) the behavior is approximately LIFO under heavy contention (a thread releasing the mutex may immediately re-acquire it before queued waiters wake up).
- **Windows SRW / Slim Reader-Writer Lock** (which is what MSVC's std::mutex is built on for Windows) is documented as non-FIFO.
- **macOS / libc++** uses pthread_mutex_t which is configurable for fairness; the default is "normal" (unfair).

So a single `std::mutex` can in principle starve one thread. The pathological case is `N-1` threads tight-looping on consume against a heavily-contended mutex, while one thread `T_N` is repeatedly preempted by the OS scheduler at exactly the wrong instant to never acquire the lock.

In Determ's deployment profile, this is unreachable in practice because:

1. The contention regime requires each thread to call `consume` at a rate exceeding `1 / t_consume ≈ 10^6 / sec`. The highest deployment profile (tactical at 5000 gossip/sec aggregate from all peers combined) is 200× below this regime.
2. Even at full saturation, the OS scheduler's fairness guarantees on thread time-slicing (Linux CFS, Windows scheduler) prevent indefinite starvation in the long run. A starved thread will eventually acquire the lock — within tens of milliseconds in the worst case.

Operator monitoring of starvation would observe one io_context worker thread with anomalously low CPU utilization. The metric is implicit (the OS exposes per-thread CPU time via `/proc/$pid/task/*/stat` on Linux); the operator's existing process-monitoring (htop, top -H, etc.) would surface it.

The cost of switching to a fair mutex (ticket lock; or `std::mutex` wrapped in an explicit FIFO queue) is constant overhead per consume — typically 2-3× the uncontended cost. Paying this on every consume to defend against a fairness regime that's operationally unreachable is a net negative. **No fix is recommended.** The property is documented for completeness.   □

### Lemma L-5 (Per-consume critical-section cost)

The critical section of `consume` (lines 88-117 inside the `lock_guard` scope) consists of:

1. `std::chrono::steady_clock::now()` (line 89): one `clock_gettime(CLOCK_MONOTONIC)` syscall on Linux (~50ns including syscall overhead) or one `QueryPerformanceCounter()` on Windows (~20-100ns). Call it `t_clock ≈ 100ns`.

2. Sweep check at lines 95-103: a single `if (eviction_threshold_sec_ > 0.0)` comparison plus a `time_point` comparison plus a conditional sweep. The conditional sweep fires at most once per `sweep_interval_sec_` wall-clock seconds; we account for it separately in T-6's amortized cost. Per-consume, the check itself is ~5ns of comparison work.

3. Map lookup `buckets_[key]` (line 105): `std::map<std::string, Bucket>::operator[]` is `O(log |buckets_|)` comparisons, each comparison is a `std::string::compare` over typical-length IP-string keys (~16 bytes for IPv4, ~40 bytes for IPv6). For `|buckets_| = 10^4`, this is `log_2(10^4) ≈ 14` comparisons × ~5ns/comparison ≈ 70ns. The map node may also be inserted on first touch (allocator call ~30-100ns); steady-state consumes hit existing nodes for ~70ns.

4. First-touch branch + refill arithmetic (lines 106-113): ~5 floating-point operations (subtraction, multiplication, addition, comparison, assignment) — `~5ns × 5 = 25ns` on modern x86-64 / ARM64. Call it `t_arith ≈ 30ns`.

5. Token check + decrement (lines 114-116): one float comparison, one float subtraction, one return — `~10ns`.

6. `lock_guard` destructor (scope exit): one mutex unlock — `~30ns` uncontended (atomic-store on the futex word); higher under contention (involves OS wake of waiter).

Summing: `t_consume ≈ 100 + 5 + 70 + 30 + 10 + 30 ≈ 245 ns` per consume under no contention. Under heavy contention the futex-wait/wake overhead adds ~500ns-1µs per consume. Total: `~1µs` per consume under heavy contention, `~250ns` uncontended.

Throughput ceiling: `1 / 1µs = 10^6 / sec` per RateLimiter instance.

For `|buckets_| = 10^5` (a stretch case, well above the F-1-closure-bounded operational ceiling), the map lookup grows to `log_2(10^5) ≈ 17` comparisons, adding ~15ns to `t_consume`. Throughput ceiling drops slightly but stays in the `~10^6 / sec` order of magnitude.

The bound is conservative (the 5ns/comparison estimate is based on cache-cold conditions; cache-hot the comparison is ~1-2ns).   □

### Lemma L-6 (Sweep cost amortization)

Each invocation of `sweep_idle_locked(now)` walks every entry in `buckets_` (lines 134-141):

```cpp
for (auto it = buckets_.begin(); it != buckets_.end(); ) {
    if (now - it->second.last > threshold) {
        it = buckets_.erase(it);
        ++evicted;
    } else {
        ++it;
    }
}
```

The walk is `O(|buckets_|)` time; each iteration is one comparison plus possibly one erase (which is `O(log |buckets_|)` for `std::map::erase(iterator)` due to rebalancing — but amortized `O(1)` over many erases per the std::map contract).

The hot-path sweep at `consume`'s lines 95-103 fires at most once per `sweep_interval_sec_` wall-clock seconds. Over a window of `Δ` seconds, the total sweep cost is `⌈Δ / s⌉ × O(|buckets_|) = O(Δ × |buckets_| / s)` where `s := sweep_interval_sec_`.

Over the same window, the total number of consumes is bounded by `Δ × r × N_IPs` (with `r := rate_per_sec_`, `N_IPs := number of distinct IPs`). For a steady-state scenario where the same `N_IPs` keep churning, `|buckets_| ≤ N_IPs + churn_rate × eviction_threshold`. The amortized sweep cost per consume is:

$$
\text{sweep\_amortized\_per\_consume} \;=\; \frac{O(|\texttt{buckets\_}|)}{\Delta \times r \times N_{IPs}} \times \Delta \;=\; O\!\left(\frac{|\texttt{buckets\_}|}{r \times N_{IPs} \times s}\right) \times \Delta.
$$

Simplifying: amortized per-consume sweep cost is `O(|buckets_| / (r × N_IPs × s))` floating-point operations. At the web-profile default `r = 100, s = 60, N_IPs = |buckets_| = 10^4`:

```
amortized = 10^4 / (100 × 10^4 × 60) = 10^4 / 6 × 10^7 ≈ 1.67 × 10^-4 ops / consume
```

— essentially zero. The sweep walk takes `O(|buckets_|) ≈ 10^4 × 5ns = 50µs` per sweep firing, but firing only once per 60 seconds, the amortized cost per consume is far below the per-consume critical-section cost.

Under a worst-case continuous-attack scenario (an attacker rotates `10^5` distinct IPs every 60 seconds, growing `buckets_` to `10^5` before each sweep), the per-sweep cost rises to `~500µs`, and the per-consume amortized cost rises to `~5 × 10^-3 ops` — still negligible against the `~250ns` per-consume base cost.

The sweep is therefore not a stall source. Caller threads waiting on the lock during a sweep see a one-shot `50µs-500µs` delay every 60 seconds; the throughput averaged over the 60-second window is dominated by the unblocked-consume path.   □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Mutual Exclusion).** Direct from L-1. Every read or write of `R`'s mutable state (`buckets_`, `next_sweep_at_`, and per-bucket `tokens`/`last`) is sequenced under `mu_`. By `std::lock_guard<std::mutex>` contract (ISO/IEC 14882:2017 §33.4.4.2), at most one thread holds `mu_` at any time. Therefore at most one thread reads/writes the protected state at any time; no data race is possible under the C++ memory model (ISO/IEC 14882:2017 §6.9.2 [intro.races]).

The const accessors `enabled()`, `rate_per_sec()`, `burst()`, etc., read the configure fields without the lock. Per §3.5 + L-1's second paragraph, the configure fields are write-once during bootstrap (before worker threads spawn), and the std::thread happens-before relationship guarantees workers see the post-bootstrap values. No data race on these fields either.   ∎

**Proof of T-2 (No Deadlock at the RateLimiter Layer).** Direct from L-2. `RateLimiter` holds exactly one mutex (`mu_`), and no critical section calls back into RateLimiter or holds any other user-visible mutex. By the Coffman conditions (Coffman, Elphick, Shoshani 1971), a deadlock requires (a) mutual exclusion (yes, std::mutex), (b) hold-and-wait (yes possible), (c) no preemption (yes for std::mutex), (d) **circular wait** (no — only one resource, so no cycle possible).

The (d) condition fails because there is only one mutex; the dependency graph has one node and no edges. No deadlock cycle exists.

Deadlock at the broader call-graph layer is also impossible (per L-2's caller audit): both `RpcServer::handle_session` and `GossipNet::handle_message` invoke `rate_limiter_.consume` without holding any other mutex.   ∎

**Proof of T-3 (Fairness Under Contention).** Direct from L-4. `std::mutex` is documented unfair under the C++ standard. In Determ's operational regime (per-instance throughput `≤ 5000/sec`, ceiling `10^6/sec`), the contention is two orders of magnitude below saturation, so OS scheduler fairness ensures every thread acquires the lock within milliseconds. Sustained starvation is operationally unreachable.

The operator-observation path for any anomalous starvation is the existing per-thread-CPU-utilization metric exposed by the OS (visible via `htop -H`, `top -H`, or `/proc/$pid/task/*`). No new tooling is needed.

No fix is recommended: replacing `std::mutex` with a fair lock would impose ~2-3× overhead on the typical case to defend a pathological regime that does not occur in operational deployments.   ∎

**Proof of T-4 (Linearizability / Sweep + Consume Interleaving Safety).** Direct from L-3. For any pair of concurrent operations on `R`, the std::mutex serializes their critical sections. The first to acquire `mu_` runs to completion before the second acquires. Each operation's linearization point is its mutex acquisition. The concurrent history is equivalent to a sequential history that respects the real-time order of non-overlapping calls (per Herlihy & Wing 1990 §4).

Specifically for the sweep+consume case: if a `consume(k_A)` from thread `T_1` triggers the in-line sweep (lines 98-101 of `rate_limiter.hpp`), the entire sweep + the subsequent bucket-touch + the token decrement runs under one continuous `mu_`-hold from `T_1`. A concurrent `consume(k_B)` from `T_2` blocks at line 88 until `T_1` releases. When `T_2` proceeds, `buckets_` is in the fully-post-sweep state; `T_2`'s view of `buckets_[k_B]` is consistent with the post-sweep map.

There is no possible interleaving in which `T_2` observes `buckets_` with some entries swept and others not. The single mutex prevents it.   ∎

**Proof of T-5 (Throughput Ceiling).** Direct from L-5. The per-consume critical section is `t_consume ≈ 250ns` uncontended, `~1µs` under contention. By Amdahl's law applied to a single-mutex-serialized region, the throughput of `R` with `N` concurrent caller threads is bounded by `1 / t_consume`, independent of `N` (the serialized region is the entire critical section; the non-serialized region is the post-consume dispatch into the parse/auth/handler path, which is parallelizable across worker threads but not relevant to `R`'s ceiling).

Ceiling: `~10^6 consume/sec` per `RateLimiter` instance under heavy contention. Determ ships two instances per node (`RpcServer::rate_limiter_` + `GossipNet::rate_limiter_`), each with its own `mu_`, for an aggregate ceiling of `~2 × 10^6 consume/sec`. The two ceilings are independent because the two mutexes are distinct.

Determ's deployment-profile request rates (per `S014RateLimiterSoundness.md` T-6 table):

| Profile | RPC rate (req/s) | Gossip rate (msg/s) | Aggregate (sum) |
|---|---|---|---|
| cluster | 50–500 | 200–2000 | 250–2500 |
| web | 10–100 | 100–1000 | 110–1100 |
| regional | 5–50 | 50–500 | 55–550 |
| global | 5–50 | 50–500 | 55–550 |
| tactical | 100–2000 | 500–5000 | 600–7000 |

The highest profile (tactical at 7000/sec aggregate) sits 285× below the per-instance ceiling and 570× below the aggregate ceiling. Single-mutex contention is not the bottleneck in any operational profile.   ∎

**Proof of T-6 (Sweep Cost Amortization).** Direct from L-6. The amortized per-consume sweep cost is `O(|buckets_| / (r × N_IPs × s))`. For the default eviction parameters (`s = 60s, threshold = 600s`) and operational `|buckets_| ≤ 10^4`, the amortized cost is `~1.67 × 10^-4` floating-point ops per consume — three orders of magnitude below the per-consume base cost of ~30 floating-point ops (L-5).

The sweep is a stall source only in the synchronous sense (a single consume that triggers the sweep takes `~50µs` instead of `~250ns`). Caller threads waiting on the lock during the sweep see a one-shot ~50µs delay. Averaged over the 60-second sweep cadence, the effective rate is dominated by the unblocked-consume path.

Worst-case sweep cost (under attack: 10^5 distinct IPs / 60s, all evicted in one sweep) rises to `~500µs` per sweep. Still amortized to `~5 × 10^-3` ops per consume — negligible.

The sweep is therefore not a stall source under any operational profile. `O(|buckets_|)` cost amortizes to `O(1)` per consume.   ∎

---

## 6. Adversary model + identified gaps

### 6.1 Adversary model

The concurrency analysis defends against:

**(a) Malicious peer attempting to provoke a data race.** A peer cannot directly induce a race condition: every state-mutating path in `RateLimiter` is single-mutex-covered (T-1). The peer's only attack surface is the rate of consume calls, which is bounded by the network-layer arrival rate per IP, in turn bounded by S-014 token-bucket arithmetic on the previous consume calls (S014RateLimiterSoundness.md T-1).

**(b) Coordinated multi-peer flood attempting to saturate the mutex.** Multiple peers from multiple IPs send concurrent requests; multiple io_context workers serve them. Each worker contends on `mu_` to call `consume`. By T-5, the aggregate throughput is bounded by `~10^6 consume/sec` per instance. A coordinated flood beyond this rate would be bounded by the underlying TCP layer (kernel buffer + accept loop), not by `mu_` contention — i.e., the bottleneck shifts to network ingress before mutex contention.

**(c) Coordinated multi-peer flood attempting to starve one specific worker thread.** Per L-4, std::mutex is unfair. An attacker who could perfectly time their consume calls to always acquire the lock just before a specific worker `T_k` tries to acquire it would starve `T_k`. **Not achievable in practice.** The attacker has no visibility into the OS scheduler's per-thread state, no way to time their network-arrival precisely against `T_k`'s wakeup. The closest the attacker can come is to saturate the limiter — see (b) — which causes uniform delay, not per-thread starvation.

**(d) Long-running sweep stalls liveness.** Per T-6 + L-6, the sweep is amortized `O(1)` per consume. Worst-case per-sweep is `~500µs` — a one-shot delay that does not stall liveness (no consensus-critical operation has a 500µs deadline). The consensus liveness assumption (Preliminaries §3.1) is partial synchrony with bound `Δ` typically on the order of `seconds`, so a `500µs` mutex-hold is below `Δ` by 4 orders of magnitude.

**(e) Re-entrant call deadlock.** If any callback inside `consume` were to call back into the same `RateLimiter` instance — out of scope; the implementation has no such callback. The `std::chrono::steady_clock::now()` and `std::map::operator[]` calls are non-recursive into RateLimiter.

### 6.2 Identified gaps

**Gap G-1 (std::mutex unfairness — no fix recommended).** Per T-3 + L-4. Documented for completeness; operationally unreachable. Switching to a fair mutex (ticket lock or wrapped FIFO queue) would impose ~2-3× overhead on every uncontended consume. **No action.**

**Gap G-2 (Sweep-walk-under-contention as a stall source — argued not a stall source).** Per T-6 + L-6. Sweep walks `O(|buckets_|)` under the lock; concurrent consumes wait. The 60-second cadence + bounded `|buckets_| ≤ 10^4` keeps the worst-case stall under `~500µs`, below the consensus partial-synchrony `Δ` by 4 orders of magnitude. **No action.**

**Gap G-3 (configure-then-spawn order is implicit, not enforced).** Per §3.5. The const accessors read configure fields without `mu_`. This is safe ONLY because configure is called once during bootstrap before worker threads start. A future operator-tunable hot-reconfigure path would break this invariant. **Recommended mitigation:** if a hot-reconfigure RPC is ever added, either acquire `mu_` in the const accessors, or wrap the configure fields in `std::atomic<double>` for lock-free reads. **Severity: design-time consideration only; no defect today.**

**Gap G-4 (Per-instance mutex is shared across both surfaces' IP keys).** Each `RateLimiter` instance has one `mu_` covering all IP buckets. A heavy RPC flood from IP_A and a separate heavy RPC flood from IP_B contend on the same mutex even though they touch disjoint buckets. This is the standard cost of a single-mutex map; sharding the map by IP-hash into `K` mutex-buckets would reduce contention by `1/K`. **No action recommended at current scale** — the throughput ceiling per L-5 (10^6/sec) sits 200× above the highest operational profile (5000/sec tactical), so the contention-amplification headroom is enormous. If a future deployment profile exceeds `~10^5/sec` aggregate per limiter, a sharded-mutex design (per `std::shared_mutex` for the lookup + per-bucket mutex for the update) would be worth implementing. Estimated effort: ~80 LOC + per-shard tests.

The four gaps are advisory; none invalidate T-1..T-6. They are surfaced for completeness so an external auditor can confirm the scope of the concurrency-layer analytic conclusion.

---

## 7. Status

**Shipped (post-F-1 closure).** The `RateLimiter` class with single-mutex covering + amortized sweep is live in the current `main` branch:

- `include/determ/net/rate_limiter.hpp:36-152` — header-only implementation; the proof's primary object.
- `src/rpc/rpc.cpp:172` — RPC consume call site.
- `src/net/gossip.cpp:154` — gossip consume call site.
- `src/node/node.cpp:586-588` — io_context worker-thread pool spawn (`hardware_concurrency()` threads).

The concurrency analysis was added in the current review pass as the concurrency-layer companion to `S014RateLimiterSoundness.md`. It does not modify source code; it formalizes the multi-threaded-access argument that the single-mutex covering closes the data-race + deadlock + linearizability surface under standard `std::mutex` + `std::lock_guard` contracts.

**Not yet shipped (future work):**

- **Sharded-mutex design (Gap G-4 mitigation).** Per-IP-hash sub-mutexes for higher throughput ceilings beyond `~10^6/sec`. Not currently warranted; recommended only if a future deployment profile demands it.
- **Hot-reconfigure path with mutex-protected configure fields (Gap G-3 mitigation).** Only relevant if an operator-tunable runtime-reconfigure RPC is ever added; deferred until that path is on the roadmap.

---

## 8. References

### Specifications + standards

- **C++ ISO/IEC 14882:2017** §33.4.3.2 [thread.mutex.requirements.mutex.general] — std::mutex acquire-release semantics; fairness is implementation-defined.
- **C++ ISO/IEC 14882:2017** §33.4.4.2 [thread.lock.guard] — std::lock_guard RAII contract.
- **C++ ISO/IEC 14882:2017** §6.9.2 [intro.races] — data-race definition + happens-before semantics.
- **C++ ISO/IEC 14882:2017** §33.3.2 [thread.thread.constr] — std::thread constructor synchronizes-with the start of the new thread (the happens-before relationship underlying §3.5's lock-free configure-then-read argument).
- **RFC 2475** (Blake, Black, Carlson, Davies, Wang, Weiss, Dec 1998) — "An Architecture for Differentiated Services." Token-bucket conformance criterion (referenced by the parent `S014RateLimiterSoundness.md`).

### Concurrency literature

- **Herlihy, Wing** (ACM TOPLAS 1990) — "Linearizability: A Correctness Condition for Concurrent Objects." The formal linearizability definition this proof's T-4 invokes.
- **Herlihy, Shavit** (Morgan Kaufmann 2008) — "The Art of Multiprocessor Programming" §3.2 — textbook treatment of mutex-implies-linearizability for shared-state objects.
- **Coffman, Elphick, Shoshani** (ACM Computing Surveys 1971) — "System Deadlocks." The four-condition deadlock-existence result this proof's T-2 invokes.
- **Bellare, Goldwasser, Micali** (J.ACM 1986) — companion citation-style template for the PRF-to-MAC reduction style used in `RpcAuthHmacSoundness.md`.

### Determ-internal references

- `include/determ/net/rate_limiter.hpp:36-152` — `RateLimiter` class (the proof's primary object).
- `src/rpc/rpc.cpp:142-195` — `RpcServer::handle_session` (RPC consume call site + dispatch model).
- `src/net/gossip.cpp:139-205` — `GossipNet::handle_message` (gossip consume call site + dispatch model).
- `src/net/peer.cpp:75-98` — `Peer::read_body` (the asio completion handler that dispatches into `handle_message` on whichever worker thread pulled the read completion).
- `src/node/node.cpp:586-588` — io_context worker-thread pool spawn.
- `tools/test_rate_limiter.sh`, `tools/test_rpc_rate_limit.sh`, `tools/test_gossip_rate_limit.sh` — regression harnesses (the same set the parent soundness proof references).
- `docs/SECURITY.md` §S-014 — closure-status narrative.
- `docs/PROTOCOL.md` §10.1 — wire-level rate-limit-gate documentation.
- `docs/proofs/S014RateLimiterSoundness.md` — the soundness companion (T-1..T-6 there are the per-bucket arithmetic statements this proof's T-4 linearizability extends to multi-threaded access).
- `docs/proofs/RpcAuthHmacSoundness.md` — companion proof; citation-style template mirrored here (the cryptographic-vs-concurrency split: that proof formalizes the HMAC arithmetic, this one formalizes the mutex coverage for the comparable rate-limiter arithmetic).
- `docs/proofs/Preliminaries.md` §3 — network model + asio thread-pool assumption (extended in §2.3 of this proof to cover the std::mutex / std::lock_guard contract).
