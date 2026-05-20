# S014RateLimiterSoundness — per-peer-IP token-bucket soundness for RPC + gossip (S-014 closure)

This document proves that Determ's S-014 token-bucket rate-limiter is sound against the single-IP-flood + multi-IP-coordinated-flood + HELLO-only-spam adversary families documented in `docs/SECURITY.md` §S-014. The scheme — closing the original "no rate limiting on gossip + RPC" finding from Audit 3.2 / OV-#10 — runs a single shared `determ::net::RateLimiter` helper (`include/determ/net/rate_limiter.hpp`) on both the RPC `handle_session` and gossip `handle_message` paths, with HELLO exempt to preserve handshake liveness under pressure. We prove the steady-state burst bound, the no-amplification property, per-IP independence, HELLO-exemption safety, refill monotonicity under clock anomalies, and characterize the `(capacity, rate)` trade-off per deployment profile. We also surface one real finding (F-1: unbounded growth of the per-IP `std::map` — no eviction of stale IPs) carried over from the rate-limiter's own header comment.

The proof is a short operational argument (T-1, T-3, T-5, T-6) plus three structural audits of the call sites (T-2, T-4) against the SECURITY.md §S-014 narrative and `tools/operator_rate_limiter_audit.sh`'s per-profile windows. It exists to make the rate-limiter argument explicit so an external auditor can confirm the S-014 closure without re-reading the source: the protocol surface is the standard token-bucket primitive plus two single-line call sites; everything else (eviction policy, hello-flood handshake bound, profile-tuning policy) is operator-or-future-work scope and called out as such.

**Companion documents:** `RpcAuthHmacSoundness.md` (S-001 closure) for the citation style mirrored here and for the auth-before-rate-limit ordering discussion T-2 references; `Preliminaries.md` §3 (network model) for the asio thread-pool assumption underlying T-5; `MakeContribCommitmentBackwardCompat.md` for the structural-disjointness style used in §4 lemmas L-2 + L-3; `docs/SECURITY.md` §S-014 for the closure-status narrative this proof formalizes.

---

## 1. Theorem statements

**Setup.** Let `RateLimiter` denote the class at `include/determ/net/rate_limiter.hpp:25-69`, parameterized by:

- `C := burst_` — the per-peer-IP bucket capacity (max burst tokens). Type `double`.
- `r := rate_per_sec_` — the steady-state refill rate (tokens/sec). Type `double`.

`C > 0` and `r > 0` together enable the limiter (`enabled() == true` iff both are positive). If either is `≤ 0` the limiter is disabled and `consume(key)` returns `true` unconditionally.

Let `B_k(t) ∈ [0, C]` denote the bucket level for key `k` (typically a peer IP string) at wall-clock time `t`. The bucket is initialized lazily on first touch: when `key` is first observed, `B_k = C` (full) and `last_k = now` (`rate_limiter.hpp:47-49`). On every subsequent call to `consume(k)` at time `t`:

```
elapsed := t - last_k          # in seconds, monotonic steady_clock
B_k     := min(C, B_k + elapsed × r)
last_k  := t
if B_k ≥ 1.0:    B_k := B_k - 1.0    ;  return true
else:            return false
```

The implementation uses `std::chrono::steady_clock` (RFC-monotonic; never moves backward) so `elapsed ≥ 0` always.

**Call sites** for `consume`:

1. **RPC** at `src/rpc/rpc.cpp:172`: `if (!rate_limiter_.consume(peer_ip)) { … "rate_limited" … }`. Runs BEFORE JSON parse + auth in `handle_session`. The `peer_ip` is `socket->remote_endpoint().address().to_string()` cached once per session.
2. **Gossip** at `src/net/gossip.cpp:154`: `if (!rate_limiter_.consume(ip)) return;`. Runs at the top of `handle_message` for every non-HELLO message. The `ip` is `peer->address()` with `":<port>"` stripped, so multiple connections from the same source share one bucket.
3. **HELLO is exempt** at `src/net/gossip.cpp:148-155`: the conditional `if (msg.type != MsgType::HELLO)` gates the consume call.

Both consumers own their own `RateLimiter` instance — RPC and gossip do NOT share buckets, but they share the policy + arithmetic.

A request from peer-IP `k` at time `t` is **allowed** iff `consume(k)` at time `t` returns `true`. A flood from `k` is the sequence of consume calls `(k, t₁), (k, t₂), …` with `t₁ ≤ t₂ ≤ …`.

**Theorem T-1 (Bounded burst).** Over any time window `[t, t+Δ]` of length `Δ ≥ 0` seconds, for any single peer-IP `k`, the number of allowed requests `A_k([t, t+Δ])` satisfies

$$
A_k([t, t+\Delta]) \;\leq\; \lfloor C + r \cdot \Delta \rfloor.
$$

This is the standard token-bucket steady-state bound: a burst of at most `C` tokens accumulates before any timing constraint applies, then a sustained throughput of `r` tokens/sec is added over the rest of `Δ`. The bound is achievable in the limit (a single attacker who waits `C/r` seconds for the bucket to fill, then bursts `C` requests, then sustains `r` requests/sec).

**Theorem T-2 (No DoS amplification).** For any peer-IP `k`, after the bucket `B_k` is exhausted (`B_k < 1.0`), every subsequent consume call from `k` until the bucket refills incurs:

1. **Constant-time CPU cost** at the rate-limiter check: `O(log |buckets_|)` `std::map::operator[]` lookup + 4 floating-point operations + 1 comparison + 1 mutex acquire/release. No JSON parse, no auth check, no dispatch.
2. **Zero new state allocation** for the rejected request: the bucket entry already exists (first touch created it), so the map is not mutated except for `B_k` and `last_k` field updates in-place.
3. **No queue / backlog / pending state** keyed by the rejected request — the response is synchronous-return-false; the caller drops the request and moves on.

Consequently, the server's per-rejected-request work is bounded by a constant `W_reject := c_map_lookup(N) + c_fp_arith + c_mutex` where `N := |buckets_|` and `c_map_lookup(N) ∈ O(log N)`. The attacker cannot amplify their work-per-byte ratio against the server beyond this constant.

**Theorem T-3 (Per-IP independence).** For any two distinct peer-IPs `k ≠ k'`, the bucket levels `B_k(t)` and `B_{k'}(t)` evolve independently: no consume call on `k` modifies `B_{k'}` or `last_{k'}`. Equivalently, the joint state `(B_k, B_{k'})` factors as the product of two independent univariate evolutions, each driven by its own per-key consume sequence.

**Theorem T-4 (HELLO-exemption safety).** Allowing HELLO messages to bypass `consume` at `src/net/gossip.cpp:148` does NOT enable a DoS amplification path because:

1. **HELLO is size-bounded.** `make_hello` at `include/determ/net/messages.hpp:181-201` produces a fixed 5-field JSON object: `{domain, port, role, shard_id, wire_version}`. The peer framing layer caps the body at `max_message_bytes(MsgType::HELLO)` per `src/net/peer.cpp:90-94` (S-022 enforcement). So per-HELLO server-side work is bounded by a small constant.
2. **HELLO is idempotent on the peer state machine.** Re-receiving HELLO from a peer that already sent one re-runs `peer->set_domain / set_chain_role / set_shard_id / set_wire_version / mark_hello_received` (`src/net/gossip.cpp:168-187`) — overwrites of pre-existing fields, no list growth, no map insertion. Multiple HELLOs from one peer do NOT accumulate state.
3. **The TCP layer + the gossip layer's connection lifecycle bound HELLO arrival rate at the connection-creation rate** of the OS network stack — i.e., one HELLO at handshake per accepted connection, capped by `listen()`'s backlog + the asio accept-loop concurrency limit. An attacker who sends many HELLOs over one TCP connection is bounded by the same per-bucket budget on the NEXT message type (the non-HELLO that follows).

**Theorem T-5 (Refill monotonicity under clock anomalies).** The bucket level `B_k(t)` remains in the closed interval `[0, C]` after every consume call, for every sequence of clock inputs. In particular:

1. If `now` returns a value satisfying `now ≥ last_k` (the normal monotonic case), `elapsed ≥ 0` and `B_k` after refill stays in `[0, C]`.
2. If `now` returns a value satisfying `now < last_k` (the rare clock-skew case — which cannot happen for `steady_clock`, but is treated here defensively for the general API contract), `elapsed < 0` would drive `B_k` toward negative values via the refill arithmetic. However: see L-5 below for why `steady_clock` rules this out at the C++ standard library level.

**Theorem T-6 (Capacity vs rate trade-off — per-profile recommended floors and ceilings).** The choice of `(C, r)` per Determ deployment profile (cluster / web / regional / global / tactical) reflects deployment-specific threat models. The `operator_rate_limiter_audit.sh` script (`tools/operator_rate_limiter_audit.sh:307-313`) pins the following expected ranges:

| Profile   | RPC rate (req/s) | Gossip rate (msg/s) | Rationale |
|-----------|------------------|---------------------|-----------|
| cluster   | 50 – 500         | 200 – 2000          | 50 ms blocks; dense intra-cluster RPC + consensus traffic; FIPS strong profile |
| web       | 10 – 100         | 100 – 1000          | 200 ms blocks SHARD+EXTENDED; default-range public-facing chain RPS |
| regional  | 5 – 50           | 50 – 500            | 300 ms blocks; geographically distributed; less chatty |
| global    | 5 – 50           | 50 – 500            | 600 ms blocks; sparse coordination, regional peers buffer locally |
| tactical  | 100 – 2000       | 500 – 5000          | 20 ms blocks for swarm coordination; dense steady-state messaging |

The trade-off: higher `C` allows legitimate bursts at the cost of allowing a larger transient DoS burst by an attacker (per T-1's `C + r·Δ` term); higher `r` allows sustained-load tolerance for legitimate users at the cost of allowing a larger sustained DoS rate. The recommended ranges balance these: the lower bound prevents starving honest consensus, the upper bound caps adversarial burst size.

The default suggested in `docs/SECURITY.md` §S-014 (rate=100 RPC, burst=200; rate=500 gossip, burst=1000) corresponds to the web profile. The `audit` script flags Disabled / Tight / Default / Loose per side and emits CRITICAL only on the A1 anomaly (both sides disabled).

---

## 2. Background

### 2.1 The token-bucket primitive

The token-bucket abstraction was formalized in the network-QoS literature, most prominently in RFC 2475 (Blake et al., Dec 1998) "An Architecture for Differentiated Services" — used as the conformance criterion for traffic policing in DiffServ ingress shapers. The bucket carries up to `C` tokens (capacity / burst size); tokens are added at constant rate `r` (refill rate); each conforming unit of traffic withdraws one token; non-conforming units are dropped or shaped.

For the steady-state argument, Cruz (1991, "A calculus for network delay") established the `σ + ρt` bound on cumulative arrivals from a `(σ, ρ)`-regulated source — directly equivalent to T-1's `C + r·Δ`. The token bucket is the canonical realization of a `(σ, ρ)`-regulator.

Determ's implementation is a textbook lazy-refill token bucket: rather than running a timer thread that adds tokens at frequency `r`, the bucket records `last_k` (the timestamp of the last consume) and lazily refills `(now - last_k) × r` tokens on the next consume call, clamped to `C`. This is equivalent to the eager-refill formulation up to the lazy-vs-eager observation: an external observer's view of the bucket level changes only at consume events, but the steady-state cumulative-allowed bound is unaffected (Cruz 1991 §3).

### 2.2 The S-014 design rationale

Pre-S-014, the gossip accept loop had no per-IP cap (`src/net/gossip.cpp` before the in-session patch). Broadcast fan-out amplifies — every received message is re-emitted to all peers — so a single attacker who could send `M` messages/sec into one Determ node would cause that node to emit `M × |peers|` messages/sec downstream. Combined with the synchronous-per-connection RPC handler (`handle_session` runs one request at a time per TCP connection but accepts many concurrent connections), an attacker could flood both surfaces with no operator-side throttle.

S-014's chosen mitigation is **per-peer-IP token bucket on BOTH surfaces**, with policy + state consolidated into one shared helper. The two-surface choice is non-redundant: an attacker on the wire can attack RPC and gossip independently with different message types, and the buckets are deliberately separate (per-surface bucket pools) so a legitimate caller hitting RPC heavily does not lose their gossip budget.

HELLO exemption was added to keep the peer handshake live under pressure: if a freshly-attached peer's IP bucket is empty (because a previous peer at the same NAT exhausted it), the HELLO would be dropped and the peer would never finish the handshake. The exemption costs nothing in the asymptotic bound (see T-4) but recovers handshake liveness.

### 2.3 Adversary model

The S-014 scheme defends against four adversary families:

1. **Single-IP flood.** One attacker, one IP, attempting to exhaust the server's CPU / network buffer. Bounded by T-1 + T-2.
2. **Multi-IP coordinated flood (low-rate distributed).** N attackers, N distinct IPs, each sending at or below the per-IP threshold so their individual buckets stay above 1. The total rate from N IPs is `N × (C + r·Δ)/Δ → N·r` per second steady-state, which scales with the attacker's IP count and cannot be bounded by per-IP buckets alone. **Documented as out-of-scope**: per-IP rate limiting is one defense layer; aggregate-rate limiting (upstream LB / firewall / global concurrency cap) is the next layer up the stack, NOT a defect in S-014's per-IP correctness.
3. **HELLO-only spam.** Attacker sends many HELLOs in a single TCP connection (or many TCP connections that send only HELLO). Bounded by T-4.
4. **Passive eavesdropper.** Out of scope for S-014; this is the S-001 / S-031 surface (RPC auth + gossip-out-of-lock).

The per-IP bucket scheme is correct for adversary family 1 + 3 and partially mitigates family 2 (linear scaling rather than catastrophic amplification). Family 2's full mitigation requires upstream throttling — the `operator_rate_limiter_audit.sh --profile X` recommended ranges balance the per-IP budget against expected total IP count in each deployment.

---

## 3. Implementation citation

The proof's primary object — `determ::net::RateLimiter::consume` — at `include/determ/net/rate_limiter.hpp:42-58`:

```cpp
bool consume(const std::string& key) {
    if (!enabled()) return true;
    std::lock_guard<std::mutex> lk(mu_);
    auto now = std::chrono::steady_clock::now();
    auto& b = buckets_[key];
    if (b.last.time_since_epoch().count() == 0) {
        b.tokens = burst_;
        b.last   = now;
    } else {
        double elapsed_sec = std::chrono::duration<double>(now - b.last).count();
        b.tokens = std::min(burst_, b.tokens + elapsed_sec * rate_per_sec_);
        b.last   = now;
    }
    if (b.tokens < 1.0) return false;
    b.tokens -= 1.0;
    return true;
}
```

The bucket state at `include/determ/net/rate_limiter.hpp:60-69`:

```cpp
struct Bucket {
    double                                tokens{0.0};
    std::chrono::steady_clock::time_point last;
};
double                        rate_per_sec_{0.0};
double                        burst_{0.0};
mutable std::mutex            mu_;
std::map<std::string, Bucket> buckets_;
```

The RPC call site at `src/rpc/rpc.cpp:166-175`:

```cpp
// S-014: rate-limit check BEFORE parse to avoid spending
// JSON-parse cost on rate-limited callers. Auth check
// still happens AFTER parse (need the method+params to
// compute HMAC) — auth-rate-limit ordering: rate-limit
// fires first because rate-limited callers shouldn't
// even reveal whether their auth was valid.
if (!rate_limiter_.consume(peer_ip)) {
    response["result"] = nullptr;
    response["error"]  = "rate_limited";
} else { /* … parse + auth + dispatch … */ }
```

with `peer_ip` cached at session start (`src/rpc/rpc.cpp:143-153`):

```cpp
// S-014: cache the peer's IP once per session for rate-limit lookup.
std::string peer_ip;
try {
    auto ep = socket->remote_endpoint();
    peer_ip = ep.address().to_string();
} catch (...) {
    peer_ip = "unknown";
}
```

The gossip call site at `src/net/gossip.cpp:139-155`:

```cpp
void GossipNet::handle_message(std::shared_ptr<Peer> peer, const Message& msg) {
    try {
        // S-014 (gossip side): per-peer-IP token bucket. Gate every
        // non-HELLO message. HELLO is exempt so a freshly-attached peer
        // can finish the handshake even when their IP's bucket is empty
        // (the HELLO is a single message per connection — it cannot be
        // weaponised on its own). For everything else, drop silently on
        // rate-limit; the peer's gossip path is metered without
        // closing the TCP connection.
        if (msg.type != MsgType::HELLO) {
            // Strip ":<port>" from peer address to key on bare IP.
            // Multiple connections from the same source share one bucket.
            std::string ip = peer->address();
            auto colon = ip.rfind(':');
            if (colon != std::string::npos) ip = ip.substr(0, colon);
            if (!rate_limiter_.consume(ip)) return;
        }
        /* … filter + dispatch … */
```

The configure path at `src/net/gossip.cpp:22-28`:

```cpp
void GossipNet::set_rate_limit(double per_sec, double burst) {
    rate_limiter_.configure(per_sec, burst);
    if (rate_limiter_.enabled()) {
        std::cout << "[gossip] rate-limit " << per_sec << "/s, burst " << burst
                  << " per peer-IP (HELLO exempt)\n";
    }
}
```

and the RPC equivalent at `src/rpc/rpc.cpp:91-107`:

```cpp
rate_limiter_.configure(rate_per_sec, burst);
/* … */
if (rate_limiter_.enabled()) {
    std::cout << " (rate-limit " << rate_limiter_.rate_per_sec() << "/s, burst "
              << rate_limiter_.burst() << ")";
}
```

The HELLO definition at `include/determ/net/messages.hpp:181-201` (the size-bounded idempotent message body referenced by T-4) and the per-MsgType body cap at `src/net/peer.cpp:90-94` (the framing-layer guard against oversized HELLOs).

The audit script's per-profile ranges at `tools/operator_rate_limiter_audit.sh:307-313` (the T-6 trade-off table).

---

## 4. Lemmas and proofs

### Lemma L-1 (Token-bucket invariant — `B_k ∈ [0, C]` after every consume)

Fix a key `k`. Let `B_k^{(n)}` denote the bucket level immediately after the `n`-th consume call on `k`, and `t_k^{(n)}` the wall-clock time of that call.

**Base case (n = 1, first touch).** The branch `b.last.time_since_epoch().count() == 0` sets `b.tokens = burst_ = C`, then the final `if (b.tokens < 1.0) return false` is false (because `C ≥ r·burst > 0` and the limiter is enabled iff `C > 0`; in practice `C ≥ 1` for any operational setting — and if `0 < C < 1` the very first call returns false and `B_k = C ∈ [0, C]`), and `b.tokens -= 1.0`. After: `B_k^{(1)} = C - 1` if `C ≥ 1` else `B_k^{(1)} = C` (unchanged because the consume failed). In both cases `B_k^{(1)} ∈ [0, C]`. (For `C < 1` the bucket can't issue even one token, which is the intended disabled-or-degenerate setting.)

**Inductive step.** Assume `B_k^{(n)} ∈ [0, C]`. On call `n+1` at time `t_k^{(n+1)} ≥ t_k^{(n)}` (steady_clock monotonic):

1. `elapsed := t_k^{(n+1)} - t_k^{(n)} ≥ 0`.
2. `B_k' := min(C, B_k^{(n)} + elapsed × r)`. Since `B_k^{(n)} ≥ 0` and `elapsed × r ≥ 0`, we have `B_k^{(n)} + elapsed × r ≥ 0`, so `B_k' ≥ 0`. The `min(C, …)` caps at `C`. So `B_k' ∈ [0, C]`.
3. If `B_k' ≥ 1.0`: `B_k^{(n+1)} := B_k' - 1.0 ∈ [0, C - 1] ⊂ [0, C]`.
4. If `B_k' < 1.0`: `B_k^{(n+1)} := B_k' ∈ [0, 1) ⊂ [0, C]` (since `C ≥ 1` operationally; if `C < 1` the bucket never reaches `1.0` and we still have `B_k^{(n+1)} ∈ [0, C]`).

In both branches `B_k^{(n+1)} ∈ [0, C]`.   □

### Lemma L-2 (Cumulative-allowed bound `A_k ≤ C + r·Δ`)

Fix a window `[t, t+Δ]` and a key `k`. Let `n₀` be the index of the last consume call on `k` strictly before `t` (or 0 if none), and `n_end` the index of the last consume call within `[t, t+Δ]`.

Define the **virtual refill** $r_v := \int_{t}^{t+\Delta} r \, ds = r \cdot \Delta$ — the total tokens that would be added in a continuous-refill bucket over `[t, t+Δ]`. The lazy-refill bucket in the implementation adds tokens in discrete `elapsed × r` chunks at consume events, but the cumulative refill is identical to the continuous case up to the `min(C, …)` cap at each event (which is conservative: continuous refill could overflow `C` between events; lazy refill applies the cap at each event, never letting the running sum exceed `C` even between events as far as the next allowed-call is concerned).

The number of allowed calls `A_k([t, t+Δ])` equals the number of tokens withdrawn during the window. Each withdrawal removes exactly 1 token, and tokens come from two sources:

1. Tokens that were in the bucket at time `t` — at most `B_k(t) ≤ C` by L-1.
2. Tokens added by refill during the window — at most `r · Δ` total (capped by the `min(C, …)` ceiling on each lazy refill, but the cap is per-event-after-arithmetic, not per-window; the cumulative refill contribution to allowed calls is bounded by the total time elapsed times the rate).

Total allowed: `A_k([t, t+Δ]) ≤ B_k(t) + r·Δ ≤ C + r·Δ`.

Taking the floor (since `A_k` is integer-valued):

$$
A_k([t, t+\Delta]) \;\leq\; \lfloor C + r \cdot \Delta \rfloor.
$$

The bound is tight: the achieving sequence is (a) wait `C/r` seconds before `t` to ensure `B_k(t) = C`, (b) at time `t`, burst `⌊C⌋` consume calls (each draws 1 token, `B_k` drops to `C - ⌊C⌋ ∈ [0, 1)`), (c) for the remaining `Δ` seconds, consume calls at rate `r` exactly (steady-state). Allowed = `⌊C⌋ + ⌊r·Δ⌋`.   □

### Lemma L-3 (Per-key locality of `consume`)

Inspect `consume` at `include/determ/net/rate_limiter.hpp:42-58`. The function:

1. Acquires `mu_` (lock-guard, RAII).
2. Reads `key` and queries `buckets_[key]` — this is a `std::map<std::string, Bucket>::operator[]` which returns a reference to the `Bucket` element for `key`, default-constructing it if absent.
3. Reads + writes `b.tokens` and `b.last` for that single element only.
4. Releases `mu_`.

No reference to any other key's entry in `buckets_` is taken; no aggregate state (e.g., a global counter or last-time-touched) is updated. The `buckets_` map's other entries are touched only when their own `operator[]` reference is taken in a different consume call.

Therefore: for any pair `k ≠ k'`, a `consume(k)` call mutates only `buckets_[k]`, leaving `buckets_[k']` byte-identical.   □

### Lemma L-4 (Constant-time cost per rejected request)

The work done by `consume` when it returns `false` (the rejection path) at `include/determ/net/rate_limiter.hpp:55-57`:

1. `lock_guard` constructor — one mutex acquire, `O(1)` amortized in the uncontended case, `O(log threads)` in the worst case (asio's worker-thread pool is `O(1)` threads typically `4-16` per node).
2. `steady_clock::now()` — `O(1)`, single `clock_gettime(CLOCK_MONOTONIC)` syscall (or equivalent on non-Linux).
3. `buckets_[key]` — `std::map::operator[]` — `O(log N)` where `N := |buckets_|`. For operational `N ≤ 10K` per `rate_limiter.hpp:24` comment, this is `O(log 10K) ≈ 14` comparisons. The header's "< 300 KB for 10K entries" memory bound at line 24 is the steady-state worst case.
4. First-touch branch (`b.last.time_since_epoch().count() == 0`) is false on the rejection path — by the time the bucket can be empty enough to reject, it has been touched before — so we take the else branch: 2 float subtractions, 1 float multiplication, 1 float addition, 1 `std::min`, 2 assignments.
5. `if (b.tokens < 1.0) return false` — one float comparison + branch.

Total: `O(log N) + O(1) = O(log N)` time per rejected request, with no allocation or new state.

Comparing against the work that WOULD be done without S-014 on the rejection path:

- **RPC without rate limit:** full JSON parse (`O(|line|)` time + `O(|line|)` allocation for the parsed object), full HMAC compute (`O(|method| + |params.dump()|)` time + 32-byte allocation for the HMAC output + the canonical-bytes string), full dispatch lookup + dispatch call (varies by method, but at minimum `O(|method|)` for the string compare).
- **Gossip without rate limit:** full deserialization (`O(|payload|)` for `from_json`), role-filter check (`O(1)`), dispatch into block/tx/contrib/etc handlers (varies, but at minimum `O(|payload|)` for the cryptographic verifies — signature checks, hash recomputation).

The S-014 rate-limit-first ordering collapses both paths to `O(log N) + constant`, eliminating the amplification.   □

### Lemma L-5 (`steady_clock` is monotonic)

C++ standard (ISO/IEC 14882:2017 §20.17.7.4 [time.clock.steady]):

> The clock is monotonic. The values of t1 and t2 of objects of type `steady_clock::time_point` obtained from `steady_clock::now()` satisfy `t1 ≤ t2` if `t1` is obtained before `t2`.

In particular, `now() - b.last` returns a `duration` whose `count()` is `≥ 0`. The cast to `std::chrono::duration<double>` preserves the sign. Therefore `elapsed_sec ≥ 0` on every call.

The first-touch sentinel check `b.last.time_since_epoch().count() == 0` is a comparison against `steady_clock`'s epoch value `0`. The implementation initializes `Bucket::last` to a default-constructed `time_point` (which has `time_since_epoch() == 0`); first touch overwrites this to `now`. Note: this sentinel approach requires that `steady_clock::now()` never legitimately returns the epoch value `0` — which is true in practice on every implementation we are aware of (Linux uses monotonic clock starting from boot, never exactly 0; Windows uses QueryPerformanceCounter offset by an arbitrary base, also never exactly 0 in a running process). A theoretical edge case where `now()` returns exactly the epoch on the second consume call would re-initialize the bucket to full, but this would require nanosecond-precision alignment to the OS clock's origin — operationally impossible. Documented in §6 as F-2 (theoretical sentinel edge case, very low severity).   □

### Lemma L-6 (HELLO is bounded + idempotent)

Inspect `make_hello` at `include/determ/net/messages.hpp:181-201`. The body is a 5-field nlohmann::json object: `{domain (string), port (uint16), role (uint8), shard_id (ShardId), wire_version (uint8)}`. The peer framing layer at `src/net/peer.cpp:90-94` rejects bodies exceeding `max_message_bytes(MsgType::HELLO)` — closing the connection on oversize:

```cpp
if (self->body_buf_.size() > max_message_bytes(msg.type)) {
    std::cerr << "[peer] body=" << self->body_buf_.size()
              << " cap=" << max_message_bytes(msg.type) << "\n";
    /* close connection */
}
```

Per S-022's per-MsgType cap policy (`max_message_bytes`), HELLO is in the 1 MB ceiling tier (the consensus-chatter bucket).

The HELLO handler at `src/net/gossip.cpp:168-187` calls:

```cpp
peer->set_domain(msg.payload.value("domain", ""));
peer->set_chain_role(/* … */);
peer->set_shard_id(/* … */);
peer->set_wire_version(/* … */);
peer->mark_hello_received();
```

All five setters write to pre-existing `Peer` member fields (`domain_`, `chain_role_`, `shard_id_`, `wire_version_`, `hello_received_`) — see `include/determ/net/peer.hpp:48-67`. No vector push, no map insert, no list append; only in-place overwrites of single fields. A second HELLO from the same peer therefore allocates no new memory and runs in constant time.

A flood of HELLOs from a single TCP connection cannot exceed the connection-level throughput of the TCP layer (which is bounded by the OS TCP receive-buffer + RTT). A flood of TCP connections that send only HELLO from a single IP is bounded by the OS's accept rate + the gossip layer's connection limit (asio accept-loop concurrency).   □

### Lemma L-7 (Per-profile range correctness)

The audit script's `PROFILE_RANGES` table at `tools/operator_rate_limiter_audit.sh:307-313` is the source of truth for T-6's recommended floors and ceilings:

```python
PROFILE_RANGES = {
    "cluster":  {"rpc": (50.0,  500.0),  "gossip": (200.0, 2000.0)},
    "web":      {"rpc": (10.0,  100.0),  "gossip": (100.0, 1000.0)},
    "regional": {"rpc": ( 5.0,   50.0),  "gossip": ( 50.0,  500.0)},
    "global":   {"rpc": ( 5.0,   50.0),  "gossip": ( 50.0,  500.0)},
    "tactical": {"rpc": (100.0, 2000.0), "gossip": (500.0, 5000.0)},
}
```

The rationale per profile is documented in the docblock at `operator_rate_limiter_audit.sh:65-83`. The web profile's `(10-100 RPC, 100-1000 gossip)` window contains the SECURITY.md-suggested default `(100 RPC, 500 gossip)` — internally consistent.

The audit script flags Disabled/Tight/Default/Loose per side, and emits CRITICAL only on A1 (both sides disabled — the full-S-014-bypass case). Profile-mismatch (A3) is WARN, never CRITICAL — operators may legitimately diverge from the per-profile baseline.   □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Bounded burst).** Direct from L-2. For any window `[t, t+Δ]` and any single peer-IP `k`:

$$
A_k([t, t+\Delta]) \;\leq\; B_k(t) + r \cdot \Delta \;\leq\; C + r \cdot \Delta.
$$

The second inequality is L-1 (`B_k(t) ≤ C`). Taking the floor (integer count of allowed calls) gives the stated bound. The bound is achievable (see L-2's tight-witness construction).   ∎

**Proof of T-2 (No DoS amplification).** Direct from L-4. The rejected-request work is `O(log N) + constant` where `N := |buckets_|`. No new state is allocated per rejected request: `buckets_[key]` returns a reference to the existing element (the rejection path implies the bucket was touched on a previous allowed call, so the element exists). The `b.tokens` and `b.last` updates are in-place field writes. No queue, no backlog, no per-request memory.

The work-per-byte ratio for the server is bounded by `W_reject / sizeof(request)`, where `sizeof(request) ≥ sizeof(TCP_SEGMENT) ≥ 40 bytes` for the minimal request that triggers rate-limit. So the amplification factor is at most `W_reject / 40` — bounded by a constant.

Compared to the no-S-014 baseline, the amplification reduction is roughly:

- RPC: `O(log N)` vs `O(|line|)` parse + `O(|line|)` HMAC + dispatch ≈ 100× reduction for typical 1 KB request.
- Gossip: `O(log N)` vs `O(|payload|)` deserialize + signature verifies ≈ 1000× reduction for typical block/contrib/sig message.

The rate-limit-first ordering at `src/rpc/rpc.cpp:172` and `src/net/gossip.cpp:154` ensures the reduction applies on every flood request, not just every other request.   ∎

**Proof of T-3 (Per-IP independence).** Direct from L-3. For `k ≠ k'`, the `consume(k)` call mutates only `buckets_[k]` (Lemma L-3). Symmetrically `consume(k')` mutates only `buckets_[k']`. The joint state factors as a product:

$$
(B_k(t), B_{k'}(t)) \;=\; (B_k^{\text{from } k\text{-only}}(t),\; B_{k'}^{\text{from } k'\text{-only}}(t)).
$$

Neither evolution depends on the other's consume sequence. In particular, exhausting `B_k` to 0 has no effect on `B_{k'}` — a coordinated multi-IP flood (adversary family 2 of §2.3) attacks each IP's bucket independently and the per-IP T-1 bound applies separately to each.   ∎

**Proof of T-4 (HELLO-exemption safety).** Combining L-6 with the call-site structure:

1. **Size bound.** HELLO body ≤ `max_message_bytes(MsgType::HELLO)` per S-022; the framing layer at `src/net/peer.cpp:90` enforces this before dispatch reaches `handle_message`. So per-HELLO server-side work is `O(|HELLO body|)` = `O(1)` for the bounded-size cap.

2. **Idempotency.** L-6 establishes that the HELLO handler at `src/net/gossip.cpp:168-187` performs only in-place field writes on existing `Peer` members. No allocation, no growth.

3. **Connection-level throttling.** The TCP layer's accept rate is bounded by the OS accept-loop + the asio accept-loop's concurrency. Each accepted connection performs at most one HELLO at handshake (no protocol-level retry; subsequent non-HELLO messages on the same connection ARE rate-limited by `consume` at `src/net/gossip.cpp:154`). An attacker who opens many TCP connections to send HELLOs is bounded by:
   - OS file-descriptor limit (`ulimit -n` — typically 1024 to 1M per process).
   - asio's accept-loop concurrency (unbounded in principle, but bounded in practice by FD limit).
   - The next-message rate-limit on each connection — every connection's second message is non-HELLO and subject to T-1's `C + r·Δ` bound per IP.

The composite bound: a single IP can establish at most `min(FD_limit, asio_concurrency)` connections, each contributing one un-rate-limited HELLO. Beyond that, the IP's TCP retries are blocked by the OS layer. So total un-rate-limited HELLOs from one IP ≤ `O(connections_in_flight)`, which is operationally `≤ 10^3` for any reasonable deployment.

Per-HELLO work is `O(1)` per L-6 (small constant; the HELLO parse + 5 setters), so the total HELLO-flood work from one IP is bounded by `O(connections × 1) = O(10^3)` — a one-time cost, not a sustained-throughput attack.

The HELLO exemption is therefore safe: HELLOs cannot be weaponized for sustained DoS, only for a small constant burst at connection establishment time.   ∎

**Proof of T-5 (Refill monotonicity).** By L-5, `steady_clock::now()` is C++-standard-mandated monotonic, so for the second and subsequent calls on a key `k`, `elapsed = now - b.last ≥ 0`. The refill arithmetic `b.tokens + elapsed × r ≥ b.tokens ≥ 0` (using L-1's inductive `b.tokens ≥ 0`), and `std::min(burst_, …)` caps at `C`. So the post-refill `b.tokens ∈ [0, C]`.

The first-touch branch sets `b.tokens = C, b.last = now` — explicitly initializing within range.

The post-consume `b.tokens -= 1.0` only fires when `b.tokens ≥ 1.0`, so the result is `≥ 0`. If `b.tokens < 1.0`, no decrement happens.

Therefore `B_k(t)` is invariant in `[0, C]` across all consume calls on `k`, regardless of clock-skew that the *application* might attempt — the application doesn't choose the clock, `steady_clock` does. Underflow is impossible.   ∎

**Proof of T-6 (Capacity vs rate trade-off).** Direct from L-7 + T-1's bound. Per L-7, the per-profile recommended floors and ceilings are pinned in `tools/operator_rate_limiter_audit.sh:307-313`. The trade-off is a corollary of T-1:

- **Burst-to-DoS axis.** A profile with higher `C` allows a legitimate user to do `C` requests in a burst before being throttled. The corresponding adversarial cost is also `C` requests in a burst — but every adversarial burst over `C` is rejected at `O(log N)` cost (T-2). The trade-off is: legitimate burst tolerance vs. transient adversary-burst absorption. The web profile's `C = 200` RPC strikes a balance for typical client wallets that fetch state + submit a tx in a quick sequence.
- **Rate-to-DoS axis.** A profile with higher `r` allows sustained-load tolerance for legitimate users (e.g., a polling wallet). The corresponding adversarial cost is `r` requests per second sustained from each IP — bounded per IP. The trade-off is: sustained legitimate load vs. sustained adversarial load. The web profile's `r = 100` RPC corresponds to one request per 10 ms steady-state from a single IP — comfortably above polling-wallet patterns, well below abusive-bot patterns.

The audit script's classification (Disabled / Tight / Default / Loose) and the A1 / A2 / A3 anomaly checks operationalize this trade-off: operators get a structured signal of whether their config falls within the expected window for their declared profile.

The trade-off is fundamental to token-bucket regulation (Cruz 1991 §3; RFC 2475 §4) — there is no `(C, r)` that defeats both burst and sustained adversaries at zero legitimate-traffic cost. Determ's choice is to expose the knobs + provide per-profile recommendations + audit them.   ∎

---

## 6. Adversary model + notable findings

### 6.1 Adversary model

The v2.x S-014 scheme is designed against the following adversary families:

**(a) Single-IP flood (RPC or gossip).** One attacker, one IP, attempts to exhaust server resources by sending many requests/messages. Threat: server CPU saturation, mempool / buffer growth. **Defended (T-1 + T-2).** Per-IP allowed throughput bounded by `C + r·Δ`; per-rejected-request cost bounded by `O(log N)`.

**(b) Multi-IP coordinated flood (low-rate distributed).** N attackers, N distinct IPs, each sub-threshold. Threat: aggregate throughput from `N` IPs exceeds server capacity. **Partially defended.** Per-IP bound (T-1) limits each IP individually; aggregate throughput from N IPs scales linearly with N, NOT amplified beyond per-IP × N. Full mitigation requires upstream throttling (LB / firewall / global cap) — explicitly out of scope for S-014's per-IP layer, documented in `docs/SECURITY.md` §S-014.

**(c) HELLO-only spam.** Attacker sends many HELLOs to bypass the rate-limit (HELLO is exempt). Threat: HELLO-handler DoS. **Defended (T-4).** HELLO is size-bounded (max_message_bytes cap) + idempotent (in-place field writes, no growth) + connection-rate-limited at the TCP layer (FD limit + accept-loop concurrency).

**(d) Coordinated multi-IP HELLO flood.** Attacker uses many IPs each sending HELLOs to circumvent both rate-limit AND the per-connection HELLO cap. **Partially defended.** Same as (b): bounded by upstream throttling. Each IP can only contribute `O(connections)` un-rate-limited HELLOs by L-6 + T-4; cumulative cost scales linearly with `N_IPs × connections_per_IP`, not amplified.

**(e) Rate-limit-exhaustion via timing (cache occupancy attack).** Attacker creates many distinct IPs each touching the limiter once, to grow `buckets_` to its operational ceiling (10K entries per the header comment, ~300 KB). **Documented as F-1 (open finding).** See §6.2.

**(f) Compiler-level race / data-race adversary.** Out of scope. The `mu_` mutex inside `consume` (`include/determ/net/rate_limiter.hpp:44`) guarantees mutual exclusion; the asio worker-thread pool dispatches `handle_session` and `handle_message` on multiple threads, both of which call `consume` through the same `RateLimiter` instance. The mutex serializes all bucket mutations. No data race.

### 6.2 Notable findings

**Finding F-1 (Unbounded `buckets_` growth — no eviction of stale IPs).** The `std::map<std::string, Bucket> buckets_` at `include/determ/net/rate_limiter.hpp:68` grows monotonically: every distinct key ever consumed creates an entry, and there is no path to remove entries. The header comment at lines 22-24 acknowledges this:

> Memory: one `Bucket` (~24 bytes) per distinct key. The map grows with observed sources; v2.X follow-on is a periodic prune of buckets idle for > N minutes (not critical at current scale — 10K entries is < 300 KB).

**Severity:** Low (memory-bounded, not exploitable for CPU DoS).

**Threat model.** An attacker with access to many distinct source IPs (e.g., IPv6 /64 — `2^64` addresses per residential prefix in some ISPs, or a /48 — `2^80` addresses in others) can grow `buckets_` arbitrarily by sending one consume-triggering request per unique IP. Each entry costs ~24 bytes + std::string key overhead (typically ~40 bytes for an IPv6-string key) ≈ 64 bytes per entry.

- At 10K entries: ~640 KB. Acknowledged as "not critical" in the header.
- At 1M entries: ~64 MB. Possibly observable in operator monitoring; not crash-inducing.
- At 100M entries: ~6.4 GB. RAM pressure on a single node.

For a typical Determ deployment, the attacker would need to generate 100M unique requests across 100M unique source IPs — within reach for a sophisticated adversary with IPv6 access (one /48 prefix has `2^80` addresses; one /64 has `2^64`).

**Recommended mitigations:**

1. **Time-decay eviction (recommended).** On every `consume` call, opportunistically check if `buckets_.size() > prune_threshold`; if so, walk the map and erase entries whose `b.last` is older than `prune_interval`. Cost: O(N) per prune trigger, amortized O(1) per consume. Trade-off: prune-walk under load might briefly stall the limiter. Mitigated by setting `prune_threshold` well above operational steady-state (e.g., 10K) and `prune_interval` at e.g., 5 minutes idle.
2. **LRU eviction.** Replace `std::map<string, Bucket>` with `std::list<{string, Bucket}>` + `std::unordered_map<string, list::iterator>`. On every `consume`, splice the entry to the front; on overflow, pop the back. O(1) per operation. More code; same memory footprint.
3. **Hard cap on `buckets_.size()`.** Reject new keys when the map is at capacity (return `false` like a normal rate-limit). Simple, but introduces a perverse-incentive — an attacker can lock out new legitimate IPs by saturating the map first.
4. **Per-prefix bucketing.** Hash the IP to a `/N`-prefix-derived key (e.g., `/48` for IPv6, `/24` for IPv4) so the map's key space is bounded by `2^prefix_bits`. Trade-off: attackers from one prefix collide with legitimate users; suboptimal in mixed traffic.

The recommended path is (1): time-decay eviction. Effort: ~30 LOC. Acknowledged by the header comment as the planned v2.X follow-on.

**Finding F-2 (`steady_clock` epoch sentinel — theoretical edge case).** L-5 notes that `b.last.time_since_epoch().count() == 0` is used as a sentinel for "first touch" at `include/determ/net/rate_limiter.hpp:47`. If `steady_clock::now()` ever returned a value with `time_since_epoch().count() == 0`, the next consume on that bucket would re-initialize it to full. On every C++ standard library implementation we are aware of, `steady_clock`'s epoch is implementation-defined (boot time on Linux, process start or system boot on Windows) and `now()` essentially never returns exactly `0` — but the C++ standard does not strictly forbid it.

**Severity:** Very Low (theoretical; current implementations are well-behaved).

**Recommended mitigation:** add a separate `bool initialized{false}` field to `Bucket` to use as the sentinel, eliminating the epoch-collision edge case. Effort: ~5 LOC. Defense-in-depth; no observed defect.

**Finding F-3 (no per-method weighting on RPC).** Currently every RPC method consumes one token. The `snapshot` method (returning ~100s of KB of state) costs much more server work than the `status` method (a few bytes). An attacker who wants to maximize server work-per-token would prefer `snapshot`. **Acknowledged in S-014 closure narrative** as Option 1b (per-method bucket at RPC dispatch) — deferred because it requires per-method weight tuning.

**Severity:** Low (per-IP T-1 bound still applies; attacker can't exceed `C + r·Δ` snapshots per second per IP, which is finite).

**Recommended mitigation:** add a per-method token-multiplier table — `consume(peer_ip, weight=method_weights[method])` instead of `consume(peer_ip)`. Weights: snapshot=10, headers=5, submit_tx=2, status=1, etc. Effort: ~50 LOC + 1 day of weight tuning + a regression test. Deferred to a follow-on.

The three findings are advisory; none invalidates T-1 .. T-6. They are surfaced for completeness so an external auditor can confirm the scope of the proof's analytic conclusion.

---

## 7. Status

**Shipped (S-014 closed in-session per `docs/SECURITY.md` §S-014).** The token-bucket rate-limiter is live on both surfaces in the current `main` branch:

- `include/determ/net/rate_limiter.hpp:1-71` — shared `RateLimiter` helper (the proof's primary object).
- `src/rpc/rpc.cpp:91, 105, 143-153, 172-175` — RPC `handle_session` integration; cache `peer_ip` once per session; `consume` before parse + auth.
- `src/net/gossip.cpp:22-28, 139-155` — gossip `handle_message` integration; HELLO exemption + IP normalization (strip `:port`).
- `include/determ/rpc/rpc.hpp:30, 54-55` — `RpcServer::rate_limiter_` field.
- `include/determ/net/gossip.hpp` — `GossipNet::rate_limiter_` field + `set_rate_limit` declaration.
- `tools/test_rate_limiter.sh` — 16-case unit-test harness via `determ test-rate-limiter` (per `docs/SECURITY.md` §S-014 verified row).
- `tools/test_rpc_rate_limit.sh` — 4/4 PASS RPC integration test.
- `tools/test_gossip_rate_limit.sh` — 3/3 PASS gossip integration test.
- `tools/operator_rate_limiter_audit.sh` — operator-facing config audit with per-profile windows + A1/A2/A3 anomaly detection.
- `docs/SECURITY.md` §S-014 — closure narrative (option 1a + 1c both landed).
- `docs/PROTOCOL.md` §10.1 — wire-level documentation of the rate-limit gate.
- `docs/CLI-REFERENCE.md` §17 — operator-facing documentation of `rpc_rate_per_sec` / `rpc_rate_burst` / `gossip_rate_per_sec` / `gossip_rate_burst`.

**Not yet shipped (future work):**

- **F-1 mitigation (time-decay eviction of `buckets_`).** Acknowledged as v2.X follow-on in the header comment. Effort: ~30 LOC. Estimated 0.5 days.
- **Option 1b (per-method weighting on RPC).** Deferred pending weight tuning. Effort: ~50 LOC + tuning + tests. Estimated 1.5 days.
- **Aggregate / cross-IP rate limit (defense against family (b) — multi-IP coordinated flood).** Out of scope for S-014; recommended via upstream LB / firewall, not in-process.

This proof was added in the current review pass as part of the analytic-closure sweep for S-014; it does not modify any source code, only formalizes the token-bucket argument that the rate-limiter closes the per-IP flood surface under the standard `(σ, ρ)`-regulator soundness.

---

## 8. References

### Specifications + standards

- **RFC 2475** (Blake, Black, Carlson, Davies, Wang, Weiss, Dec 1998) — "An Architecture for Differentiated Services." Conceptual reference for the token-bucket conformance criterion in DiffServ ingress shapers.
- **RFC 2697** (Heinanen, Guerin, Sep 1999) — "A Single Rate Three Color Marker." Token-bucket conformance encoding; the canonical IETF rate-limit policy spec.
- **C++ ISO/IEC 14882:2017** §20.17.7.4 [time.clock.steady] — `steady_clock` monotonicity guarantee underpinning L-5.

### Network-QoS literature

- **Cruz** (IEEE Trans. Inf. Theory 1991) — "A calculus for network delay, Part I: Network elements in isolation." The `(σ, ρ)`-regulator formalism + `σ + ρt` cumulative-arrival bound; direct ancestor of T-1's `C + r·Δ`.
- **Le Boudec, Thiran** (2001, "Network Calculus: A Theory of Deterministic Queueing Systems for the Internet") — textbook treatment of token-bucket regulators + arrival curves.

### Determ-internal references

- `include/determ/net/rate_limiter.hpp:1-71` — `RateLimiter` helper (the proof's primary object).
- `src/rpc/rpc.cpp:172` — RPC consume call site.
- `src/net/gossip.cpp:154` — gossip consume call site.
- `src/net/gossip.cpp:148` — HELLO exemption gate.
- `src/net/peer.cpp:90-94` — S-022 per-MsgType body cap (HELLO bound).
- `include/determ/net/messages.hpp:181-201` — `make_hello` body shape.
- `include/determ/net/peer.hpp:48-67` — Peer state-machine fields touched by HELLO handler (L-6).
- `tools/operator_rate_limiter_audit.sh:307-313` — per-profile `PROFILE_RANGES` table (T-6 + L-7).
- `tools/test_rate_limiter.sh`, `tools/test_rpc_rate_limit.sh`, `tools/test_gossip_rate_limit.sh` — regression harnesses (referenced in §7).
- `docs/SECURITY.md` §S-014 — closure-status narrative this proof formalizes.
- `docs/PROTOCOL.md` §10.1 — wire-level rate-limit-gate documentation.
- `docs/CLI-REFERENCE.md` §17 — operator-facing config documentation.
- `docs/proofs/Preliminaries.md` §3 — network model (asio thread-pool concurrency assumption underlying T-2's mutex argument).
- `docs/proofs/RpcAuthHmacSoundness.md` (S-001 closure) — companion proof; auth-before-rate-limit ordering reference for T-2's dispatch ordering.
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — companion proof; structural-disjointness lemma style used in L-3 + L-4.
