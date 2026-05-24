# S014RateLimiterDDOSResistance — adversary-class defense + composition with S-022 caps (S-014 DDoS angle)

This document is the **DDoS-resistance companion** to `S014RateLimiterSoundness.md` (which formalized the algebraic per-bucket arithmetic — T-1 burst bound, T-2 no amplification, T-3 per-IP independence, T-4 HELLO-exemption, T-5 refill monotonicity, T-6 capacity-vs-rate trade-off) and `S014ConcurrencyAnalysis.md` (mutex correctness + linearizability under the asio thread pool). Both prior proofs treat the rate-limiter in isolation as a single-IP regulator and a thread-safe shared object; **this proof composes those facts with a structured adversary taxonomy and the system-level defenses** (`F-1` idle-bucket eviction, `S-022` per-message body caps, `S-026` TCP keepalive, OS file-descriptor + accept-loop limits) to characterize what attacker class is defended and what the cost-vs-benefit ratio of mounting an attack looks like on a deployed Determ node.

The proof has the shape of a defense-in-depth audit. §1 enumerates a five-class adversary taxonomy (A-V1 single IP; A-V2 small IPv4 botnet ≤256 IPs; A-V3 large IPv4 botnet ≤65k IPs; A-V4 IPv6 /64 rotation 2^64 addresses; A-V5 cooperative DoS from multiple IPs with synchronized burst), each parameterized by attacker IP-count, per-IP rate, attack duration, and observable system effect. §2 establishes five composition theorems (T-1 per-IP bound; T-2 aggregate-rate bound; T-3 memory bound under IPv6 /64 attack; T-4 HELLO-exemption safety as a DDoS lemma; T-5 composition with S-022 caps). §3 maps each adversary class to the defending theorem and surfaces the residual risk per class. §4 surfaces the same F-1/F-2/F-3 findings from `S014RateLimiterSoundness.md §6.2` with the additional view that, post-F-1 closure, operator monitoring of `bucket_count()` becomes the principal observable defense-health signal. §5 cites the test surface (`determ test-rate-limiter-bucket` for unit-level + `tools/test_gossip_rate_limit.sh` for integration). §6 references RFC 2475, RFC 2697, Cruz 1991, and Le Boudec-Thiran 2001 for the formal-network-QoS lineage.

**Companion documents:** `S014RateLimiterSoundness.md` (per-bucket algebra T-1..T-6; this proof's per-IP-bound theorem cites that document's T-1 directly); `S014ConcurrencyAnalysis.md` (mutex correctness + linearizability + throughput ceiling — establishes that contention is not a DDoS amplification path); `tla/RateLimiterEviction.tla` (FB25 state-machine proof of the F-1 eviction policy that bounds T-3's memory cap); `S022WireFormatCaps.md` (per-MsgType body caps used by T-5's bandwidth-DoS composition); `S026TcpKeepalive.md` (TCP-keepalive enables the OS layer to reap dead connections, complementing F-1); `docs/SECURITY.md` §S-014 (closure-status narrative).

---

## 1. Adversary model

We enumerate five attacker classes parameterized by their IP-address resource and attack pattern. The taxonomy follows the DDoS-attack literature lineage (Mirkovic-Reiher 2004 "A taxonomy of DDoS attack and DDoS defense mechanisms", Specht-Lee 2004 "Distributed Denial of Service: Taxonomies of Attacks, Tools and Countermeasures"), specialized to the Determ node's two-surface (RPC + gossip) ingress.

Let `R := rate_per_sec_` (refill rate, tokens/sec) and `C := burst_` (bucket capacity, tokens) denote the per-IP rate-limiter parameters. Per `tools/operator_rate_limiter_audit.sh:307-313`, web-profile defaults are `R = 100` for RPC and `R = 500` for gossip; tactical reaches `R = 2000` RPC + `R = 5000` gossip; cluster/regional/global sit in between. Let `H := eviction_threshold_sec_ + sweep_interval_sec_ = 660` seconds (default per `include/determ/net/rate_limiter.hpp:147-148`) denote the maximum bucket-survival window after last touch. Let `B_max := server_dispatch_rate` denote the per-process throughput ceiling of the asio io_context — operationally `~10^6` consume/sec per the `S014ConcurrencyAnalysis.md` T-5 single-mutex throughput ceiling.

**A-V1 (Single-IP flood).** One attacker, one IP `i`. Attack pattern: sustained burst of consume calls at rate `R_A >> R` against one Determ surface (RPC or gossip). Resource: trivial (one host, one IP).

  - Allowed throughput from `i`: bounded by T-1 of `S014RateLimiterSoundness.md` to `⌊C + R·Δ⌋` per window `[t, t+Δ]`. Steady-state: `R` consume/sec maximum.
  - Rejected throughput: at most `R_A - R` consume/sec; each rejection costs `O(log N) + const` server work per `S014RateLimiterSoundness.md` T-2 / L-4.
  - Server effect: bounded CPU saturation per IP; bucket size grows by 1 entry (~64 bytes).

**A-V2 (Small IPv4 botnet, ≤ 256 IPs).** N = 256 attackers each from a distinct IP (e.g., a single residential /24, or a small set of compromised hosts). Attack pattern: each IP sends at exactly `R` consume/sec (sub-threshold so the per-IP rate-limit never fires individually).

  - Aggregate allowed throughput: `N · R = 256 · R` consume/sec. At web-profile `R = 100` RPC: `25600` RPC/sec aggregate. At tactical `R = 2000`: `512000` RPC/sec aggregate (still under the `~10^6` ceiling).
  - Bucket count growth: 256 entries (~16 KB).
  - Server effect: aggregate CPU saturation on one or both surfaces; bounded by per-IP × N (linear), not exponential.

**A-V3 (Large IPv4 botnet, ≤ 65,536 IPs).** N = 2^16 attackers from distinct IPv4 addresses (a /16 prefix, or a moderate botnet). Each IP sends at `R` consume/sec, sub-threshold.

  - Aggregate allowed throughput: `N · R = 65536 · R`. At web-profile `R = 100` RPC: `6.5 · 10^6` RPC/sec — **exceeds** the single-mutex throughput ceiling `~10^6`. The asio worker pool serializes at the mutex; aggregate effective throughput is capped at `B_max`.
  - Bucket count growth: 65,536 entries (~4 MB). Within the F-1 amortized eviction window (660s default).
  - Server effect: the rate-limiter mutex becomes the bottleneck; per-IP throughput drops below `R` due to contention; aggregate is throttled by `B_max`. Per-bucket arithmetic still correct (T-1 + T-3 from `S014RateLimiterSoundness.md` apply; L-3 per-key locality holds).

**A-V4 (IPv6 /64 rotation, ≤ 2^64 addresses).** One attacker with control of a residential ISP IPv6 /64 prefix. The attacker cycles source IP every consume call, each from a distinct IPv6 address in `2^64`. Attack pattern: maximal IP-distinct rate, `R_A` consume/sec, each IP touched once before being abandoned.

  - Allowed throughput from each individual IP: 1 burst-token (because the first touch initializes the bucket to full + immediately consumes 1).
  - Aggregate allowed throughput: `R_A` consume/sec (every consume is allowed because every IP is fresh).
  - Bucket count growth at time `t` from start: `min(R_A · t, R_A · H)` because F-1 evicts buckets idle for ≥ `H` seconds. At `R_A = 10^4` consume/sec and `H = 660` sec: `|buckets_| ≤ 6.6 · 10^6` entries = ~422 MB. At `R_A = 10^5`: ~4.2 GB — RAM pressure. (Operators should set `eviction_threshold_sec_` lower under known A-V4 attack, e.g., 60 seconds.)
  - Server effect: bounded by **memory**, not CPU. T-3 below pins the memory bound.

**A-V5 (Cooperative DoS, synchronized burst).** N attackers from N distinct IPs (typical N ∈ [10, 10^4]) coordinate to fire bursts simultaneously. Attack pattern: at time `t_0`, every attacker IP `i_k` (k ∈ [1, N]) sends `C` consume calls within a tight `[t_0, t_0 + ε]` window (ε ≪ 1 sec), exhausting all N buckets. Then attacker pauses for `C/R` seconds (the bucket refill time), and bursts again.

  - Aggregate allowed throughput: `N · C / ε` per burst, then 0 during refill (`C / R` seconds), then repeat. Average: `N · C / (ε + C/R) ≈ N · R` for `ε ≪ C/R`. So in steady state cooperative-burst attack ≈ aggregate-low-rate attack (A-V2 or A-V3).
  - Peak instantaneous throughput: `N · C / ε`. At N = 10^4 IPs, C = 200 (web RPC burst), ε = 1 ms: `2 · 10^9` consume/sec **request rate at the TCP layer**, but bounded by `B_max` at the rate-limiter (the io_context worker pool serializes and drops the excess at the framing layer's RPC accept queue / gossip Peer::read_body backpressure).
  - Bucket count growth: N entries plus any persistent post-burst entries until F-1 evicts (660s window).
  - Server effect: synchronized burst causes a transient queue-depth spike; the rate-limiter clamps the steady-state to `N · R`. The transient must be absorbed by the asio io_context's accept queue (`listen()`'s backlog) and TCP's send/receive buffers; if those overflow, new connections are TCP-RST'd by the OS — not Determ-layer DoS, but a graceful denial.

The taxonomy is **exhaustive over the IP-resource axis**: A-V1 has 1 IP, A-V2 ≤ 2^8, A-V3 ≤ 2^16, A-V4 ≤ 2^64, A-V5 generalizes the burst pattern over any N. Other DDoS techniques (application-layer slow-loris, low-and-slow, amplification via reflection) are addressed elsewhere — slow-loris is bounded by `S026TcpKeepalive.md` (idle TCP connections reaped after ~2 hr OS default, tunable); amplification via Determ as a reflector is impossible because every response RPC method is bounded by the request shape (no DNS-style "small request → big response" amplification path in the protocol).

---

## 2. Defense theorems

**Theorem T-1 (Per-IP bound — composition with `S014RateLimiterSoundness.md` T-1).** For any single source IP `k` and any time window `[t, t+Δ]`, the number of consume calls allowed against the rate-limiter satisfies

$$
A_k([t, t+\Delta]) \;\leq\; \lfloor C + R \cdot \Delta \rfloor.
$$

**Proof.** Direct quote of `S014RateLimiterSoundness.md` T-1, which proves `A_k ≤ ⌊C + r·Δ⌋` via Lemma L-2 (cumulative-arrival bound for the `(σ, ρ)` regulator). The bound is a steady-state guarantee that does not depend on the attacker's choice of source rate `R_A`; an A-V1 attacker who fires at `R_A → ∞` against a single IP still has only `R_A := R = rate_per_sec_` allowed steady-state and only `⌊C⌋ + 1` burst-allowed. ∎

**Corollary T-1.1 (A-V1 defended).** A single-IP flood (A-V1) is bounded above by `R + C/Δ` consume/sec at the rate-limiter. Server work per rejected request is `O(log |buckets_|)` per `S014RateLimiterSoundness.md` T-2 / L-4. The attacker's amplification factor is ≤ 1 (the server's work-per-attacker-byte ratio is bounded by a small constant). ∎

**Theorem T-2 (Aggregate bound).** At most `min(|active_IPs| · R, B_max)` consume calls per second are *processed* at the rate-limiter across all peers, where:

  - `|active_IPs|` is the number of distinct IPs currently with bucket entries in `buckets_`, bounded by F-1 eviction to at most `attack_rate_distinct_IPs · H` (proved in T-3 below).
  - `B_max := 1 / t_consume` is the single-instance throughput ceiling from `S014ConcurrencyAnalysis.md` T-5 (~10^6 consume/sec at typical `|buckets_| ≤ 10^4`).

**Proof.** Each IP `i_k` is bounded above by T-1 to `R + C/Δ` consume/sec. Summing over `k ∈ active_IPs`:

$$
\sum_{k=1}^{N} A_{i_k}([t, t+\Delta]) \;\leq\; N \cdot (C + R \cdot \Delta) \;=\; (NC + NR \cdot \Delta).
$$

Dividing by `Δ` for the rate: aggregate rate ≤ `NR + NC/Δ`, which for `Δ ≫ C/R` collapses to `NR`. Independently, the asio io_context's single-mutex throughput ceiling caps the *effective* processing rate at `B_max` regardless of the offered load (per `S014ConcurrencyAnalysis.md` T-5: a single `std::mutex` cannot dispatch faster than `1 / t_consume`). The aggregate processed rate is therefore `min(NR, B_max)`. ∎

**Corollary T-2.1 (A-V2 + A-V3 defended).** A-V2 (N ≤ 256, R = 100 RPC) yields `NR = 2.5 · 10^4` consume/sec, well below `B_max`. A-V3 (N ≤ 2^16) yields `NR = 6.5 · 10^6` consume/sec offered, throttled to `B_max ≈ 10^6` at the mutex. Both are bounded; A-V3 exceeds `B_max` so the *attacker* gets less than their offered rate, but the *server* spends bounded `B_max` work — no amplification. ∎

**Theorem T-3 (Memory bound under IPv6 /64 attack — A-V4).** With F-1 eviction at threshold `H_e := eviction_threshold_sec_` and sweep cadence `S_i := sweep_interval_sec_`, the size of `buckets_` is bounded:

$$
|\texttt{buckets\_}| \;\leq\; R_{A,\text{distinct}} \cdot (H_e + S_i)
$$

where `R_{A,distinct}` is the adversary's distinct-IP arrival rate (consume calls/sec, each from a never-before-seen IP).

**Proof.** Let `t` be a reference time. Each bucket entry survives in `buckets_` until either:

1. The next sweep after the entry's `b.last` field crosses `t - H_e`, OR
2. The next consume() call after `t - H_e` that triggers the amortized sweep (per `rate_limiter.hpp:95-103`).

The sweep cadence guarantees a sweep fires every `S_i` wall-clock seconds. So an idle bucket survives at most `H_e + S_i` seconds from its last touch before being evicted on the next sweep.

Therefore: bucket entries created during the window `[t - (H_e + S_i), t]` are still resident in `buckets_` at time `t`; entries created strictly before that window have already been evicted by `t`. The count of entries created in the window is bounded by `R_{A,distinct} · (H_e + S_i)`, which is the total distinct-IP consume calls in the window. ∎

**Corollary T-3.1 (Worst-case A-V4 memory bound).** At default `H_e = 600` sec and `S_i = 60` sec, the maximum bucket count is `R_{A,distinct} · 660`. At a realistic 10^4 consume/sec from all-distinct IPs (an aggressive IPv6 /64 attack): `|buckets_| ≤ 6.6 · 10^6` entries. Per-entry cost ≈ 64 bytes (24-byte `Bucket` struct + ~40 bytes for the IPv6 string key) → ~**422 MB** worst case. At 10^3 distinct/sec: ~42 MB. At 10^5 distinct/sec: ~4.2 GB (operator must tighten `H_e` or rely on upstream throttling).

The bound is **achievable**: an attacker who actually sustains the distinct-IP rate `R_{A,distinct}` over an entire `H_e + S_i` window will see the bucket count grow to the upper bound, then plateau (eviction rate equals creation rate). Operator-monitoring via `bucket_count()` lets operators detect the regime and tune `eviction_threshold_sec_` via the configure_eviction RPC.

**Corollary T-3.2 (Defense recommendation).** Operators monitoring `bucket_count()` should configure alarms at thresholds:

| `bucket_count()` | Recommended action |
|------------------|---------------------|
| ≤ 10^4           | Normal operation. No action. |
| 10^4 – 10^6      | Watch for sustained growth. Check distinct-IP rate. |
| > 10^6           | Possible A-V4 attack. Reduce `eviction_threshold_sec_` to 60s via `configure_eviction(60.0, 10.0)`. |
| > 10^7           | Active A-V4 attack. Enable upstream firewall throttling. |

**Theorem T-4 (HELLO-exemption safety — DDoS angle).** The HELLO exemption at `src/net/gossip.cpp:148-155` (HELLO messages bypass `RateLimiter::consume`) does not introduce a DDoS amplification path. Specifically: per-HELLO server-side work is bounded by `O(|HELLO body|) = O(1)` per `S014RateLimiterSoundness.md` L-6, and the HELLO arrival rate is bounded by the OS accept-loop rate per `S014RateLimiterSoundness.md` T-4.

**Proof.** Three sub-bounds compose:

1. **Per-HELLO size bound (S-022 composition).** HELLO is a fixed 5-field JSON object per `make_hello` at `include/determ/net/messages.hpp:181-201`. The framing layer at `src/net/peer.cpp:90-94` enforces `max_message_bytes(MsgType::HELLO) = 1 MB` (S-022 default branch — see `S022WireFormatCaps.md` T-1). So per-HELLO body ≤ 1 MB; per-HELLO server work ≤ `O(1)` JSON parse + 5 field setters.

2. **Per-HELLO idempotency.** Per `S014RateLimiterSoundness.md` L-6, the HELLO handler at `src/net/gossip.cpp:168-187` performs only in-place field writes on existing `Peer` members. No allocation, no growth. A flood of HELLOs from one peer (or one IP via many connections) does not accumulate state.

3. **TCP-layer connection-rate bound.** An attacker who wants to flood HELLOs from a single IP must open a new TCP connection per HELLO (the second message on any single connection is non-HELLO and subject to the rate-limit). TCP-connection-open rate is bounded by: (a) the attacker's outbound TCP-SYN rate, (b) the OS accept-loop concurrency, (c) the OS file-descriptor limit (`ulimit -n`). On Linux defaults: ~1024 FDs per process, ~100 connections/sec accept rate. The cap may be raised, but it's never amplified by the attacker; it's a server-side property.

Composing 1+2+3: total HELLO-flood server work from a single IP at rate `λ_conn` (connections/sec) is bounded by `λ_conn · O(1) = O(λ_conn)`. Since `λ_conn` is bounded by the OS, the attack is bounded. The HELLO exemption is therefore safe: HELLOs cannot be used as a DoS amplifier. ∎

**Corollary T-4.1 (HELLO is not an attack amplifier).** The amplification factor `(server work)/(attacker bandwidth)` for HELLO-flood is ≤ 1: the attacker spends 1 KB of HELLO body to make the server do `O(1) ≈ 1 KB`-equivalent work. No multiplier; no per-byte amplification. ∎

**Theorem T-5 (Composition with S-022 caps — bandwidth-DoS bound).** For any peer connection with rate-limited surface (RPC or non-HELLO gossip), the per-connection bandwidth consumed by allowed requests is bounded:

$$
\text{bandwidth\_per\_IP} \;\leq\; R \cdot \max_m \texttt{max\_message\_bytes}(m).
$$

For the conservative bound (taking the maximum over all `MsgType` values m), this is `R · 16 MB` (only SNAPSHOT_RESPONSE / CHAIN_RESPONSE reach 16 MB; everything else ≤ 4 MB). For the typical case (no SNAPSHOT_REQUEST traffic from the attacker — they don't get the response), the bound tightens to `R · 1 MB` (the default S-022 cap for consensus chatter messages: HELLO, TRANSACTION, BLOCK_SIG, CONTRIB, etc).

**Proof.** Each consume token corresponds to one message (RPC request or gossip non-HELLO message). Each message's body is bounded by `max_message_bytes(MsgType)` per `S022WireFormatCaps.md` T-1 (every MsgType is bounded; default branch tight at 1 MB). The allowed-request rate per IP is bounded by `R` per T-1 of this proof.

Per-IP bandwidth = (allowed-request rate) × (max body size) ≤ `R · max_m max_message_bytes(m)`. ∎

**Corollary T-5.1 (Operational bandwidth-DoS bound per IP).** At gossip rate `R = 500` (web profile) and 1 MB per-message cap: `500 · 1 MB = 500 MB/s` per IP — a single attacker IP can saturate a 4 Gbps uplink. At 50 IPs: 25 GB/s — clearly upstream-throttle territory. The defense composition reduces to "per-IP rate × per-message-cap = per-IP bandwidth ceiling"; the per-IP rate is the rate-limiter's job (T-1 + T-2); the per-message-cap is S-022's job; the upstream firewall handles the aggregate.

Stricter operator configurations (e.g., regional profile `R = 50`, 1 MB cap) tighten this to `50 MB/s` per IP — manageable on a single residential-uplink-class link. The operator-config table in `tools/operator_rate_limiter_audit.sh:307-313` (cited by `S014RateLimiterSoundness.md` T-6) gives per-profile guidance on the (R, C) tuning consistent with the bandwidth bound.

**Corollary T-5.2 (Why HELLO needs S-022).** HELLO is rate-limit-exempt (T-4), so the bandwidth bound formula does not apply directly: a single connection could in principle send unlimited HELLOs. The S-022 cap on HELLO (1 MB body) reduces the per-HELLO bandwidth, but per-connection-throughput is then bounded by the TCP-layer receive-buffer. The defense composition for HELLO is therefore: (TCP receive buffer) × (OS accept-rate) — not the rate-limiter. This is captured operationally by T-4 above.

---

## 3. Adversary-class outcomes

Summary table of each adversary class A-V1 .. A-V5, which theorem(s) defend, and what residual risk remains after the defense composes.

| Class  | IPs               | Pattern              | Defending theorem(s)              | Residual risk |
|--------|-------------------|----------------------|------------------------------------|---------------|
| **A-V1** | 1                 | Single-IP flood      | T-1 (per-IP bound) + T-4 (HELLO)   | None at protocol layer. Saturates only the attacker's own bucket; server work bounded by `O(log N)` per rejected request. |
| **A-V2** | ≤ 256             | Small botnet, sub-threshold | T-1 + T-2 (aggregate bound)       | None at protocol layer. Aggregate throughput `25600 consume/sec` (web RPC) well below `B_max ≈ 10^6`; bucket count ≤ 256 entries. |
| **A-V3** | ≤ 2^16            | Large botnet, sub-threshold | T-1 + T-2 (mutex saturation kicks in) | Per-IP throughput drops below `R` due to mutex contention; aggregate processed throughput clamped at `B_max`. Bucket count ≤ 4 MB. Server still functional; consensus latency may rise. **Mitigation**: upstream firewall + per-prefix throttling. |
| **A-V4** | ≤ 2^64 (IPv6 /64) | Distinct-IP rotation | T-3 (memory bound) + F-1 eviction | **Memory only**. At `R_{A,distinct} = 10^5` consume/sec: ~4 GB worst-case `buckets_`. **Mitigation**: operator monitors `bucket_count()`; tightens `configure_eviction(60.0, 10.0)` under attack; enables upstream firewall throttling. |
| **A-V5** | N ∈ [10, 10^4]   | Synchronized burst   | T-2 (aggregate bound) + T-5 (S-022) | Transient queue-depth spike; new connections may TCP-RST; consensus disruption possible if burst rate × N exceeds `B_max`. **Mitigation**: F-1 + S-022 + asio io_context backpressure; sustained attack reduces to A-V3 in steady state. |

**Residual-risk axes** that the rate-limiter + S-022 composition does NOT defend:

1. **Application-layer protocol abuse.** A single IP exhausting allowed consume calls with `snapshot` RPCs (large response per request, F-3 from `S014RateLimiterSoundness.md`). Per-method weighting (Option 1b in §S-014 closure narrative) is the recommended mitigation. Deferred per `S014RateLimiterSoundness.md` §7.
2. **Aggregate-volume DoS.** The rate-limiter is per-IP, not aggregate. A botnet with N IPs each at `R/sec` produces `N·R/sec` aggregate, which scales linearly with botnet size. Upstream rate-limiting (LB, firewall, traffic shaper) is the next defense layer.
3. **Routing-layer / BGP-hijack DoS.** Out of scope for this proof; depends on the deployment's BGP posture and ISP-level reputation feeds.
4. **Slow-loris / low-and-slow.** Defended by `S026TcpKeepalive.md` at the TCP layer (idle connections reaped); not the rate-limiter's responsibility.

---

## 4. Findings (DDoS angle)

The three findings F-1, F-2, F-3 are first surfaced in `S014RateLimiterSoundness.md §6.2` (algebraic angle). This proof reiterates them from the DDoS-resistance angle, with the additional observation that operator monitoring of `bucket_count()` is now the principal defense-health signal post-F-1 closure.

**Finding F-1 (Unbounded `buckets_` growth — A-V4 defense gap; CLOSED).** Per `S014RateLimiterSoundness.md §6.2`, time-decay eviction shipped in the current `main` branch; the algorithm is formalized in `tla/RateLimiterEviction.tla` (FB25 state machine) and tested via `determ test-rate-limiter-bucket` scenarios #27..#34. Post-closure, the memory bound is `R_{A,distinct} · (H_e + S_i)` per T-3 of this proof. **Operator-monitoring recommendation (DDoS angle):** alarm on `bucket_count() > 10^6` as the A-V4 detection signal; reduce `configure_eviction(60.0, 10.0)` under sustained attack.

**Finding F-2 (`steady_clock` epoch sentinel — theoretical edge case).** Per `S014RateLimiterSoundness.md §6.2`, the first-touch sentinel `b.last.time_since_epoch().count() == 0` could be defeated by a theoretical `steady_clock::now() == 0` return. Severity: Very Low. From the DDoS angle: an attacker cannot induce `steady_clock` to return 0; the clock origin is OS-implementation-defined and never coincides with a valid timestamp in a running process. Not exploitable for amplification.

**Finding F-3 (No per-method weighting on RPC).** Per `S014RateLimiterSoundness.md §6.2` + §7, per-method weighting (option 1b) is deferred. From the DDoS angle: an A-V1 attacker who targets the heaviest RPC method (e.g., `snapshot`) maximizes server-work-per-bucket-token. The per-IP bound (T-1) still holds — the attacker cannot exceed `C + R·Δ` snapshots/sec per IP — but the per-method work asymmetry means each allowed snapshot is `~100×` more server work than each allowed `status`. The defense (T-2 aggregate bound) still applies; the residual risk is bounded.

**Recommendation (post-F-1 closure):** add `RateLimiter::bucket_count()` to the operator dashboard. The current implementation exposes the diagnostic; operators integrate via the `operator_rate_limiter_audit.sh` framework. Alarm thresholds per Corollary T-3.2.

---

## 5. Test surface

The rate-limiter's DDoS-resistance properties are exercised by two layers of regression tests in `tools/`:

**Unit-level: `determ test-rate-limiter-bucket` (R20A7, ~20 assertions across 8 scenarios).** Exercises the F-1 eviction path directly via the public API:

  - Scenarios #27..#34 (per `S014RateLimiterSoundness.md §6.2` closure subsection): defaults pin, `bucket_count()` growth + per-key uniqueness, `sweep_idle()` no-op on fresh buckets, sweep fires on stale buckets, re-touch after eviction yields full burst, amortized sweep on consume hot path, eviction disable via `configure_eviction(0)`, mixed fresh + stale (only stale evicted).
  - The test invokes `RateLimiter::configure_eviction(threshold_sec, interval_sec)` directly + advances mocked time (or uses `sweep_idle()` for explicit triggers) + asserts `bucket_count()` matches the expected post-state.
  - Covers T-3 of this proof directly: the memory bound is observable via `bucket_count()` after a synthetic A-V4 cycling pattern.

**Integration-level: `tools/test_gossip_rate_limit.sh` (S-014 integration, 3/3 PASS).** Exercises the rate-limit + dispatch composition end-to-end on a 3-node MD cluster:

  - Test 1: gossip_rate=500/s, burst=1000 (sensible operator defaults). Verify chain advances normally — consensus traffic flows comfortably under the cap.
  - Test 2: gossip_rate=1/s, burst=2 (tight). Verify the chain stalls (consensus messages get rate-limited, K-of-K can't complete). This proves the gate is wired into `handle_message`.
  - Test 3: gossip rate=0 (disabled). Verify the limiter is a no-op and chain advances at unbounded rate.

  Covers T-1, T-2, T-4 of this proof: the per-IP bound is exercised by the rate-limit-stalls-consensus path; the aggregate-rate bound is observable via the consensus-progress signal; the HELLO-exemption is exercised by the handshake-completes-under-pressure path (the tight `rate=1/s burst=2` setting would stall HELLO if HELLO were not exempt — the test passes BFT-start, confirming HELLO went through).

**Companion test surfaces (referenced but not specific to this proof):**

  - `tools/test_rate_limiter.sh` — 16 cases of unit-level token-bucket arithmetic exercised via `determ test-rate-limiter` (covers T-1 + T-3 + T-5 of `S014RateLimiterSoundness.md`).
  - `tools/test_rpc_rate_limit.sh` — RPC integration test (4/4 PASS); covers the RPC consume path.
  - `tools/operator_rate_limiter_audit.sh` — operator-facing config audit; covers the per-profile range table cited by T-2 of this proof.

The integration test surface is sufficient to confirm A-V1 (single-IP flood) defense end-to-end; A-V2..A-V5 are characterized analytically via T-1..T-5 of this proof and confirmed at unit-level via `test-rate-limiter-bucket`.

---

## 6. References

### Specifications + standards

- **RFC 2475** (Blake, Black, Carlson, Davies, Wang, Weiss, Dec 1998) — "An Architecture for Differentiated Services." Conceptual reference for the token-bucket conformance criterion in DiffServ ingress shapers; the canonical IETF reference for the per-IP rate-limit policy.
- **RFC 2697** (Heinanen, Guerin, Sep 1999) — "A Single Rate Three Color Marker." Token-bucket conformance encoding; the IETF canonical rate-limit policy spec.

### Network-QoS literature

- **Cruz** (IEEE Trans. Inf. Theory 1991) — "A calculus for network delay, Part I: Network elements in isolation." The `(σ, ρ)`-regulator formalism + `σ + ρt` cumulative-arrival bound — the direct ancestor of `S014RateLimiterSoundness.md` T-1 and this proof's T-1. The bound `A_k ≤ C + R·Δ` is Cruz's "Theorem 3" specialized to a single bucket.
- **Le Boudec, Thiran** (2001, "Network Calculus: A Theory of Deterministic Queueing Systems for the Internet") — textbook treatment of token-bucket regulators + arrival curves. Chapter 1 develops the `(σ, ρ)` regulator from first principles; Chapter 4 discusses the composition of multiple regulators (relevant to T-2 of this proof — the aggregate bound across N buckets is a composition of N independent `(σ, ρ)` regulators).

### DDoS attack + defense taxonomy

- **Mirkovic, Reiher** (2004, "A taxonomy of DDoS attack and DDoS defense mechanisms") — the IP-resource × attack-pattern taxonomy used in §1 of this proof. The A-V1..A-V5 classification follows Mirkovic-Reiher's "attack source distribution" axis, specialized to Determ's two-surface ingress.
- **Specht, Lee** (2004, "Distributed Denial of Service: Taxonomies of Attacks, Tools and Countermeasures") — companion DDoS taxonomy + the application-layer-vs-network-layer distinction used to scope this proof.

### Determ-internal references

- `include/determ/net/rate_limiter.hpp:1-152` — `RateLimiter` helper (the primary object; T-1..T-5 of this proof all cite this file).
- `include/determ/net/rate_limiter.hpp:95-103` — F-1 amortized eviction trigger (T-3 of this proof).
- `include/determ/net/rate_limiter.hpp:128-143` — `sweep_idle_locked` (T-3 mechanism).
- `src/rpc/rpc.cpp:172-175` — RPC consume call site.
- `src/net/gossip.cpp:148-155` — gossip consume call site + HELLO exemption (T-4 of this proof).
- `src/net/peer.cpp:90-97` — S-022 per-MsgType body cap enforcement (T-5 of this proof; `S022WireFormatCaps.md` T-1).
- `include/determ/net/messages.hpp:181-201` — `make_hello` body shape (T-4 of this proof).
- `tools/operator_rate_limiter_audit.sh:307-313` — per-profile `PROFILE_RANGES` table (referenced by T-5.1 of this proof for the per-profile bandwidth bound).
- `tools/test_gossip_rate_limit.sh` — gossip integration test (§5 of this proof).
- `tools/test_rate_limiter.sh` — unit-level token-bucket regression.
- `docs/SECURITY.md` §S-014 — closure-status narrative.
- `docs/proofs/S014RateLimiterSoundness.md` — the algebraic per-bucket proof (T-1..T-6 of that document; this proof's T-1 + T-3 cite directly).
- `docs/proofs/S014ConcurrencyAnalysis.md` — the mutex/asio concurrency proof (T-2 + T-5 of that document; this proof's T-2 + T-4 cite directly).
- `docs/proofs/tla/RateLimiterEviction.tla` — FB25 TLA+ state machine for the F-1 eviction policy (T-3 of this proof).
- `docs/proofs/S022WireFormatCaps.md` — S-022 per-MsgType caps (T-5 of this proof composes with T-1 of that document).
- `docs/proofs/S026TcpKeepalive.md` — TCP-keepalive for dead-connection reaping (slow-loris defense, residual-risk discussion in §3).
- `docs/proofs/Preliminaries.md` §3 — network model (asio thread-pool concurrency assumption).
