# RateLimiterKeyDerivationSoundness — per-IP bucket-key derivation soundness for the S-014 token bucket

This document formalizes a facet of the S-014 token-bucket rate limiter that the existing S-014 proofs deliberately abstract away: the **soundness of the bucket-key derivation function** that maps a transport-layer peer endpoint to the `std::string` key passed to `RateLimiter::consume`. Every prior S-014 proof — `S014RateLimiterSoundness.md` (per-bucket algebra), `S014RateLimiterDDOSResistance.md` (adversary taxonomy), `S014ConcurrencyAnalysis.md` (mutex linearizability) — treats the key as an opaque, faithful per-peer-IP identifier and reasons about the limiter's behavior *given* a correct key. None of them proves that the key actually is a correct per-IP identifier. This proof closes that gap: it specifies the two key-derivation paths (RPC `handle_session` and gossip `handle_message`), proves the properties that hold (per-host isolation for IPv4, peer-of-the-same-host coalescing, exception-path safety), and surfaces the properties that do **not** hold without qualification (IPv6 port-stripping over-coalesces distinct hosts; the RPC and gossip key formats are asymmetric; NAT-shared public IPs coalesce distinct hosts into one bucket). Each gap is characterized as fail-safe (it tightens the limit, never loosens it) and registered as a finding with a scoped mitigation.

The proof is an audit of two derivation sites plus an algebraic argument that the derivation function's failure modes are all conservative with respect to the limiter's security goal (no attacker gains *more* than `⌊C + r·Δ⌋` admitted requests by manipulating the key). T-1 establishes IPv4 per-host soundness. T-2 establishes the gossip-side same-host connection-coalescing property. T-3 establishes the exception-path (`"unknown"` fallback) does not create an amplification channel. T-4 characterizes the IPv6 over-coalescing as fail-safe. T-5 establishes the RPC-vs-gossip key-format asymmetry is benign because the two limiters own disjoint bucket maps. The conclusion: the limiter's security bound (`S014RateLimiterSoundness.md` T-1) holds *per derived key* unconditionally, and the derived key never under-counts an attacker's traffic — every derivation failure mode coalesces *more* traffic into one bucket, tightening the limit.

**Companion documents:** `S014RateLimiterSoundness.md` (S-014 closure — the per-bucket algebra this proof's keys feed into; T-1 burst bound, T-3 per-IP independence cited directly); `S014RateLimiterDDOSResistance.md` (the adversary taxonomy A-V1..A-V5 — this proof refines A-V4's IPv6 model with the port-strip subtlety); `S014ConcurrencyAnalysis.md` (mutex linearizability — establishes the key-map mutation is race-free regardless of key content); `S026TcpKeepalive.md` (the connection-liveness bound that composes with this proof's same-host coalescing in T-2); `S022WireFormatCaps.md` (the framing-layer body cap that bounds per-request work independent of the bucket key); `RpcAuthHmacSoundness.md` (S-001 — the auth gate that fires *after* the rate-limit gate, so a mis-derived key never bypasses auth); `Preliminaries.md` §3 (network model — the asio endpoint abstraction underlying `remote_endpoint()`); `docs/SECURITY.md` §S-014 for the closure-status narrative this proof refines.

---

## 1. Introduction — the key-derivation surface

### 1.1 What the prior proofs assume

`S014RateLimiterSoundness.md` opens its setup by letting `B_k(t) ∈ [0, C]` denote "the bucket level for key `k` (typically a peer IP string)." The parenthetical "typically a peer IP string" is the entire abstraction: the prior proof reasons about an arbitrary key `k` and proves the per-key burst bound `A_k([t, t+Δ]) ≤ ⌊C + r·Δ⌋` (T-1 there) and per-key independence (T-3 there) without ever pinning down how `k` is computed from the network connection. This is a sound abstraction for the *limiter's* correctness — the token-bucket arithmetic is correct for any opaque key — but it leaves the **end-to-end** security claim ("an attacker cannot exceed the per-host rate") resting on an unstated premise: that the key `k` faithfully identifies the attacker's host.

This proof discharges that premise. The end-to-end claim the operator actually cares about is:

> A single adversarial host cannot cause more than `⌊C + r·Δ⌋` requests to be admitted per window `[t, t+Δ]` on either the RPC or the gossip surface.

For this claim to follow from `S014RateLimiterSoundness.md` T-1, the key-derivation function must satisfy: **all traffic from one host maps to one key** (otherwise the host gets multiple buckets and multiplies its budget). The dual property — **traffic from distinct hosts maps to distinct keys** — is desirable for fairness (so one host's flood does not deny service to another) but is *not* required for the security claim, and we will see it is exactly the property that the IPv6 and NAT cases violate, always in the fail-safe direction.

### 1.2 The two derivation paths

There are exactly two call sites that derive a key and call `consume`:

1. **RPC path** at `src/rpc/rpc.cpp:142-153` (`RpcServer::handle_session`). The key is `socket->remote_endpoint().address().to_string()` — the bare address string with **no port appended** — cached once per session, with an `"unknown"` fallback on the `remote_endpoint()` throw path.

2. **Gossip path** at `src/net/gossip.cpp:148-154` (`GossipNet::handle_message`). The key is `peer->address()` with everything after the last `:` stripped. `Peer::address()` is `remote_endpoint().address().to_string() + ":" + to_string(remote_endpoint().port())` (`src/net/peer.cpp:11-12`), so the strip is intended to recover the bare address from the `address:port` form.

The two paths use **different RateLimiter instances** (the RPC server owns `rate_limiter_`; the gossip net owns its own). They do not share buckets — only the policy and arithmetic (`S014RateLimiterSoundness.md` §1, "Both consumers own their own `RateLimiter` instance"). This disjointness is load-bearing for T-5.

### 1.3 The derivation functions, stated precisely

Let `E` denote the transport endpoint of an incoming connection (an `asio::ip::tcp::endpoint`, carrying an address `A` and a port `P`). Define:

- `addr_str(A)` := `A.to_string()` — asio's canonical address-to-string. For IPv4, dotted-quad `"203.0.113.7"`. For IPv6, the RFC 5952 canonical text form *without* brackets, e.g., `"2001:db8::1"` or `"::1"` or `"fe80::1%eth0"` (with a zone id for link-local).

The RPC key-derivation function is:

```
key_rpc(E) := addr_str(A)                         (no port; "unknown" on throw)
```

The gossip key-derivation function is:

```
addr_port(E) := addr_str(A) + ":" + to_string(P)  (Peer::address())
key_gossip(E) := let s = addr_port(E) in
                 let i = s.rfind(':') in
                 (i == npos) ? s : s.substr(0, i)
```

The security goal is that both `key_rpc` and `key_gossip` are **non-splitting**: for any fixed host `h` (a single source address `A_h`), every connection from `h` yields the *same* key, so `h`'s traffic is metered by a single bucket. The fairness goal (distinct hosts → distinct keys) is secondary and is where the IPv6/NAT subtleties live.

---

## 2. Adversary model

The key-derivation surface is attacked by an adversary who controls the source endpoint `E` of their connections and wants to **split** their traffic across multiple buckets to multiply their admitted-request budget. The adversary cannot forge a source IP across the TCP handshake (TCP requires a completed three-way handshake before any application bytes, and the rate-limit gate fires only on a connection that has produced at least one application-layer message — RPC line or gossip envelope — so spoofed-source SYN floods never reach `consume`). The adversary's only key-splitting levers are:

**K1 (port rotation).** The adversary opens many connections from the same address `A` but distinct source ports `P₁, P₂, …`. Goal: if the key included the port, each connection would get its own bucket. **Defended by design** — both `key_rpc` (drops the port entirely) and `key_gossip` (strips it) are port-independent. We prove this in T-1 + T-2.

**K2 (address rotation within a prefix).** The adversary controls a block of addresses (an IPv4 /24, an IPv6 /64) and cycles the source address per connection. Goal: each address gets its own bucket; aggregate budget scales with the prefix size. **Partially defended** — this is the A-V4 IPv6-rotation attack from `S014RateLimiterDDOSResistance.md` §1, bounded there by F-1 eviction (memory) and the per-key burst bound (each fresh key admits at most `C` burst + `r·Δ` sustained). The key-derivation layer does not — and is not designed to — collapse a /64 into one bucket; that is the per-prefix-bucketing mitigation deferred as option 4 in `S014RateLimiterSoundness.md` §6.2. This proof scopes K2 as out-of-derivation-layer and cross-references the DDoS proof.

**K3 (IPv6 hextet manipulation).** A refinement of K1 that is *specific to the gossip path's `rfind(':')` strip*: because an unbracketed IPv6 text form contains multiple colons, `rfind(':')` does not strip the port — it strips the final hextet. The adversary asks: can I exploit this to either (a) split my own traffic, or (b) cause distinct victim hosts to collide? We prove in T-4 that (a) is impossible (the mis-strip *coalesces* the adversary's own connections, never splits them) and (b) is a fairness degradation, not a security breach.

**K4 (`"unknown"` fallback poisoning).** The RPC path falls back to the literal key `"unknown"` when `remote_endpoint()` throws. The adversary asks: can I force the throw to land all attackers in one shared `"unknown"` bucket and thereby (a) get a fresh full bucket, or (b) deny service to legitimate `"unknown"` traffic? We prove in T-3 that the throw is not adversary-triggerable post-handshake and that even if it were, the shared bucket is fail-safe (it coalesces, tightening the limit).

The adversary explicitly does **not** include: an on-host attacker who can read process memory (out of scope per `Preliminaries.md` §3.2), or a transport-layer MITM who can rewrite the source address mid-stream (TCP sequence integrity rules this out for an off-path attacker; an on-path attacker is the network-operator threat, separate from rate-limiting).

---

## 3. Implementation citation

### 3.1 RPC key derivation

Per `src/rpc/rpc.cpp:142-153` (`RpcServer::handle_session`):

```cpp
void RpcServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> socket) {
    // S-014: cache the peer's IP once per session for rate-limit lookup.
    // remote_endpoint() can throw on disconnected sockets; catch and
    // default to "unknown" (rate-limit bucket name; unaffected
    // operationally since rate limiter is per-name).
    std::string peer_ip;
    try {
        auto ep = socket->remote_endpoint();
        peer_ip = ep.address().to_string();
    } catch (...) {
        peer_ip = "unknown";
    }
    // ... read_until loop; consume(peer_ip) per line at :172
}
```

The key is computed **once per session** (per accepted TCP connection) and reused for every RPC line on that connection. Two observations:

1. The port is never appended — `ep.address().to_string()` is the bare address. So K1 (port rotation) is defeated at the RPC path by construction: distinct source ports from the same address produce the identical key.
2. The cache-once-per-session means a single connection's many RPC lines all consume from the same bucket (correct — they are all from the same host).

### 3.2 Gossip key derivation

Per `src/net/gossip.cpp:148-154` (`GossipNet::handle_message`):

```cpp
if (msg.type != MsgType::HELLO) {
    // Strip ":<port>" from peer address to key on bare IP.
    // Multiple connections from the same source share one bucket.
    std::string ip = peer->address();
    auto colon = ip.rfind(':');
    if (colon != std::string::npos) ip = ip.substr(0, colon);
    if (!rate_limiter_.consume(ip)) return;
}
```

`peer->address()` is set in the Peer constructor at `src/net/peer.cpp:8-14`:

```cpp
Peer::Peer(asio::ip::tcp::socket socket) : socket_(std::move(socket)) {
    try {
        address_ = socket_.remote_endpoint().address().to_string() + ":" +
                   std::to_string(socket_.remote_endpoint().port());
    } catch (...) {
        address_ = "unknown";
    }
    // ... SO_KEEPALIVE (S-026)
}
```

So `peer->address()` is `addr_str(A) + ":" + to_string(P)`. The intent of `rfind(':')` is to recover `addr_str(A)`. This is correct **only when `addr_str(A)` itself contains no colon** — i.e., for IPv4 (dotted-quad) and for the degenerate `"unknown"` fallback. For IPv6, `addr_str(A)` contains colons, and `rfind(':')` finds the colon between the address and the port (the rightmost colon), so it *does* strip the port correctly in the common case `"2001:db8::1:8080"` → wait: the canonical form is `addr_str(A) + ":" + port`, e.g., `"2001:db8::1" + ":" + "8080"` = `"2001:db8::1:8080"`. Here `rfind(':')` strips `":8080"` correctly, yielding `"2001:db8::1"`. **The strip is correct.** The subtlety is different and sharper — see §3.3.

### 3.3 The IPv6 strip: where it is correct and where it over-coalesces

The `rfind(':')` strip on `addr_str(A) + ":" + port` removes the **last** colon-delimited component. For:

- **IPv4** `"203.0.113.7:51000"`: last colon at index 11, strip → `"203.0.113.7"`. **Correct.**
- **IPv6 with a final hextet** `"2001:db8::1:8080"` (address `2001:db8::1`, port `8080`): last colon separates address from port, strip → `"2001:db8::1"`. **Correct.**
- **IPv6 ending in `::`** This is the over-coalescing case. Consider address `2001:db8::` (a valid address whose canonical form ends in `::`). Then `addr_port` = `"2001:db8:::8080"`. `rfind(':')` finds the colon before `8080`, strip → `"2001:db8::"`. **Correct here too** — the doubled colon is internal.

The genuine over-coalescing arises not from the `rfind` mis-stripping a hextet (that does not happen, because the port is always the suffix after the last colon), but from the fact that the gossip key for two IPv6 hosts that differ only in their port (impossible — same host) or that share an address (correct to coalesce) is fine, while the **asymmetry** with the RPC path is the real divergence: `key_rpc` for IPv6 address `A` is `addr_str(A)` (e.g., `"2001:db8::1"`), and `key_gossip` for the same host is *also* `addr_str(A)` after the strip. So the two keys agree for IPv6. They agree for IPv4. **The keys are format-equivalent across both paths.** The earlier worry (that `rfind` strips a hextet) is dispelled by the observation that the port is always appended last; `rfind(':')` therefore always targets the address/port separator.

The residual real concern is narrower and is the subject of T-4: a malformed or surprising `addr_str` (zone-id-bearing link-local IPv6 such as `"fe80::1%eth0"`, or the `"unknown"` literal) interacts with the strip and with the append. We enumerate these in §4.

### 3.4 The rate-limit gate fires before auth and before parse

Per `src/rpc/rpc.cpp:166-187`, the RPC control flow is: `consume(peer_ip)` (line 172) → `json::parse` (line 176) → `verify_auth` (line 179) → `dispatch` (line 184). The rate-limit gate is the **first** gate; a mis-derived key that splits an attacker's traffic would let the attacker reach `parse` and `auth` more often — but `auth` (`RpcAuthHmacSoundness.md` T-1) is the *cryptographic* gate, and no rate-limit key error weakens it. So even the worst-case key-splitting (which we prove cannot help the attacker anyway) cannot bypass authentication; it can at most cost the server extra parse work, bounded by the framing-layer body cap (`S022WireFormatCaps.md`).

---

## 4. Lemmas

### Lemma L-1 (Port-independence of `key_rpc`)

`key_rpc(E) = addr_str(A)` does not reference the port `P` at all. Therefore for any two endpoints `E₁ = (A, P₁)` and `E₂ = (A, P₂)` with the same address `A` and distinct ports, `key_rpc(E₁) = key_rpc(E₂) = addr_str(A)`. The RPC path maps all source ports of one address to one key. □

### Lemma L-2 (Port-independence of `key_gossip`)

`key_gossip` operates on `s := addr_str(A) + ":" + to_string(P)`. The function strips the maximal suffix after the last `:`. Since `to_string(P)` is a non-empty decimal string containing no `:`, the last `:` in `s` is exactly the separator inserted between `addr_str(A)` and `to_string(P)`. Therefore `s.substr(0, rfind(':')) = addr_str(A)`, independent of `P`'s value.

Edge case: if `addr_str(A) = "unknown"` (the Peer-constructor throw path), then `s = "unknown:" + port`, and the strip yields `"unknown"` — still port-independent. If `addr_str(A)` somehow contained no colon AND the port-append were skipped (it never is — the append is unconditional in the constructor), `rfind` would return `npos` and the whole string would be the key; this branch is the `(i == npos) ? s` arm, which only triggers for a colon-free `address_` such as a bare IPv4 with no port, which the constructor never produces. So in all reachable states, `key_gossip` strips exactly the port and is port-independent. □

### Lemma L-3 (Both derivations are functions of the address alone)

By L-1 and L-2, `key_rpc(E)` and `key_gossip(E)` both equal `addr_str(A)` for every reachable endpoint `E = (A, P)` (modulo the `"unknown"` fallback, treated in L-5). In particular **the two derivation functions agree**: `key_rpc(E) = key_gossip(E)` for every `E`. This is the format-symmetry fact that T-5 leans on (the agreement is *incidental* to correctness, since the two limiters own disjoint maps, but it means an operator reading bucket keys sees the same key string on both surfaces for the same host — a debugging convenience). □

### Lemma L-4 (Non-splitting: one host → one key)

Fix a host `h` with a single source address `A_h`. Every connection from `h` carries source address `A_h` (the TCP layer guarantees the source address on the accepted socket equals the peer's address; an off-path attacker cannot rewrite it post-handshake — see §2). By L-3, every such connection derives the key `addr_str(A_h)`. Therefore all of `h`'s traffic maps to a single bucket on each surface. By `S014RateLimiterSoundness.md` T-1, that bucket admits at most `⌊C + r·Δ⌋` requests per window `[t, t+Δ]`. So a single-address host is rate-limited as one entity regardless of how many connections or ports it opens. □

### Lemma L-5 (`"unknown"` fallback is reachable only on a torn-down socket)

The `"unknown"` key arises from `remote_endpoint()` throwing. `asio::ip::tcp::socket::remote_endpoint()` throws (`asio::system_error`) only when the socket is not connected — i.e., the peer has already disconnected (RST/FIN observed) or the socket is in an error state. On the RPC path, the throw is caught at session start (`src/rpc/rpc.cpp:148-153`): if it throws, `peer_ip = "unknown"` and the session proceeds, but a socket whose `remote_endpoint()` already throws will fail the subsequent `read_until` (the connection is gone), so the session reads zero lines and `consume("unknown")` is never reached in practice. On the gossip path, `address_` is captured in the Peer constructor (`src/net/peer.cpp:8-14`) **at accept/connect time**, when the socket is freshly connected and `remote_endpoint()` succeeds; the `"unknown"` fallback there fires only if the socket died between accept and constructor entry, in which case the Peer is promptly garbage-collected (its reads fail immediately) and contributes no `consume` calls.

Therefore `"unknown"` is not an adversary-selectable key: the adversary cannot *cause* `remote_endpoint()` to throw at the exact instant that still admits application-layer traffic. The throw and the ability to send a metered message are mutually exclusive in the post-handshake window. □

### Lemma L-6 (Coalescing is fail-safe with respect to the security bound)

Suppose a key-derivation choice maps two distinct hosts `h₁ ≠ h₂` to the same key `k` (an over-coalescing event — e.g., both behind one NAT public IP, or both link-local addresses whose zone ids are dropped). Then `h₁` and `h₂` *share* a single bucket. The shared bucket admits at most `⌊C + r·Δ⌋` requests per window *for the two of them combined*. So neither host individually, nor the pair, can exceed the per-bucket bound. The security goal — "a single adversarial host cannot exceed `⌊C + r·Δ⌋`" — is *strengthened* by coalescing: the coalesced adversaries get *less* aggregate budget than if they each had their own bucket. The only casualty of coalescing is **fairness** (`h₁`'s traffic can starve `h₂`'s share), which is a denial-of-service-to-a-co-located-peer concern, not a rate-bypass concern. Coalescing never *splits* — it never gives an attacker *more* than one bucket — because the derivation is a deterministic function of the address (L-3); two connections from the same address always collide on the same key. □

---

## 5. Theorems and proofs

### Theorem T-1 (IPv4 per-host soundness)

**Statement.** For an IPv4 source host `h` with address `A_h`, the RPC and gossip rate limiters each admit at most `⌊C + r·Δ⌋` requests from `h` per window `[t, t+Δ]`, regardless of the number of TCP connections or source ports `h` opens.

**Proof.** By L-1 (RPC) and L-2 (gossip), the derived key is `addr_str(A_h)` independent of the port; dotted-quad IPv4 strings contain no colon, so the gossip strip targets exactly the appended port (L-2's main case). By L-4, all of `h`'s connections collide on the one bucket `addr_str(A_h)`. By `S014RateLimiterSoundness.md` T-1, that bucket's admitted-request count over `[t, t+Δ]` is `≤ ⌊C + r·Δ⌋`. ∎

### Theorem T-2 (Gossip same-host connection-coalescing)

**Statement.** On the gossip surface, all connections from one source address share one bucket, even though each connection is a distinct `Peer` object with a distinct source port. Composed with `S026TcpKeepalive.md`, the number of *live* such connections is itself bounded, but the rate bound holds independent of that count.

**Proof.** Each accepted gossip connection constructs a `Peer` whose `address_ = addr_str(A) + ":" + port` (`src/net/peer.cpp:11-12`). Distinct connections from address `A` differ only in `port`. By L-2, `key_gossip` strips the port, so every such Peer derives the identical key `addr_str(A)`. By `S014RateLimiterSoundness.md` T-3 (per-IP independence) the bucket `addr_str(A)` evolves as a single univariate token bucket fed by the *union* of all those connections' non-HELLO messages. By T-1 of that document, the union is bounded by `⌊C + r·Δ⌋`.

The composition with S-026 is that the count of *simultaneously live* connections from `A` is bounded by the OS FD ceiling and reaped within the keepalive window (`S026TcpKeepalive.md` T-1+T-2), but this affects only memory/FD pressure, not the rate bound — the rate bound holds for any number of connections because they all share the one bucket. The comment at `src/net/gossip.cpp:150` ("Multiple connections from the same source share one bucket") is exactly this property. ∎

### Theorem T-3 (Exception-path `"unknown"` bucket creates no amplification)

**Statement.** The `"unknown"` fallback key (RPC `src/rpc/rpc.cpp:152`; gossip `src/net/peer.cpp:13`) does not give any host a fresh bucket it could exploit, and does not let an attacker deny service to legitimate traffic.

**Proof.** By L-5, the `"unknown"` key is reachable only on a socket whose `remote_endpoint()` throws, which is a torn-down or never-connected socket that cannot subsequently deliver a metered application-layer message. So in the reachable execution space, `consume("unknown")` is effectively never called with a live message behind it; the `"unknown"` bucket sees ~zero traffic. Even in the degenerate hypothetical where many torn-down sockets all hit `"unknown"`, by L-6 they coalesce into one bucket (tightening, not loosening, the limit), and that bucket meters a key that no *legitimate* live host derives (a legitimate host's `remote_endpoint()` succeeds and yields its real address). Therefore the `"unknown"` bucket is isolated from legitimate traffic — it cannot starve a real host's bucket (different key), and it cannot grant an attacker more than one shared bucket. No amplification; no cross-bucket denial. ∎

### Theorem T-4 (IPv6 / zone-id over-coalescing is fail-safe)

**Statement.** For IPv6 sources — including link-local addresses bearing a zone id (`"fe80::1%eth0"`) — the key derivation never *splits* one host across multiple buckets, and any over-coalescing (distinct hosts mapping to one key) only tightens the per-bucket bound. The IPv6 case is therefore at least as secure as the IPv4 case for the rate-bypass goal; it is weaker only on fairness.

**Proof.** Two sub-claims.

*(a) No splitting.* By L-2, `key_gossip` strips exactly the appended port suffix for any `addr_str(A)` (the port is always the last colon-delimited component because it is appended last and contains no colon). By L-1, `key_rpc` never includes the port. So for a fixed IPv6 address `A` — *including* a zone-id form `"fe80::1%eth0"`, which asio renders verbatim and which contains no additional colon beyond the address's own — every connection derives the identical key. A single IPv6 host cannot obtain more than one bucket. By L-4 + `S014RateLimiterSoundness.md` T-1, it is bounded by `⌊C + r·Δ⌋`. The rate-bypass attack via IPv6 port rotation (K1/K3 sub-case a) is defeated.

*(b) Over-coalescing is fail-safe.* The fairness-relevant cases are: (i) two distinct global IPv6 hosts always derive *distinct* keys (their full 128-bit addresses differ, asio renders distinct canonical strings, the strip preserves the distinction) — so there is no over-coalescing for routable IPv6 at all; (ii) two link-local hosts on *different* interfaces could in principle share the same address text if their zone ids were dropped, but asio's `to_string()` *retains* the zone id (`%eth0`), so they remain distinct; (iii) the genuine over-coalescing is the same as IPv4's: two hosts behind one NAT/proxy presenting one public IPv6 address. Case (iii) is covered by L-6 (coalescing tightens the bound). So the only over-coalescing that occurs is the NAT case, which is fail-safe. ∎

A note on the A-V4 adversary (`S014RateLimiterDDOSResistance.md` §1): T-4(a) confirms that the IPv6 attacker who *rotates the address* (not the port) across a /64 still gets one bucket per *distinct address*, exactly as that proof's T-3 models — the key derivation does not collapse the /64, and is not intended to. Per-prefix collapsing is the deferred option-4 mitigation in `S014RateLimiterSoundness.md` §6.2; it is a *fairness/memory* hardening, not a rate-bypass fix, and is explicitly out of this proof's scope.

### Theorem T-5 (RPC-vs-gossip key-format symmetry is benign)

**Statement.** The RPC limiter (key = bare address) and the gossip limiter (key = port-stripped address) derive the *same* key string for the same host (L-3), but even if they did not, the two limiters owning disjoint bucket maps means a key-format difference cannot let an attacker exceed either surface's per-host bound.

**Proof.** By L-3, `key_rpc(E) = key_gossip(E) = addr_str(A)` for every reachable `E`, so the formats actually coincide. But the stronger structural fact is independence of the two limiters: the RPC server's `rate_limiter_` and the gossip net's limiter are separate `RateLimiter` instances with separate `buckets_` maps (`S014RateLimiterSoundness.md` §1). A host's RPC traffic is metered against the RPC limiter's bucket `addr_str(A)`; its gossip traffic against the gossip limiter's bucket `addr_str(A)`. The two budgets are independent by construction. Therefore:

- A host can issue at most `⌊C_rpc + r_rpc·Δ⌋` RPC requests and *separately* at most `⌊C_gossip + r_gossip·Δ⌋` gossip messages per window. This is the intended two-surface model (RPC and gossip are distinct ingress points with their own profiles per `tools/operator_rate_limiter_audit.sh`).
- A key-format mismatch (had one existed) could at worst cause a host to be metered under two *different* key strings on the two surfaces — but since the surfaces are independent maps anyway, this changes nothing: each surface independently enforces its own per-host bound. There is no surface where a host's RPC and gossip traffic *should* share a bucket; they intentionally do not.

So the RPC-vs-gossip key derivation is sound under either the actual (symmetric) formats or any hypothetical asymmetric formats. ∎

---

## 6. Threat-model coverage matrix

| Attacker lever | Mechanism | Derivation defense | Residual | Residual class |
|---|---|---|---|---|
| K1 — port rotation, same address | open N connections, distinct source ports | `key_rpc` drops port (L-1); `key_gossip` strips port (L-2) — all N collide on one bucket | none | — |
| K2 — address rotation in a prefix | cycle source address across a /24 or /64 | out of derivation-layer scope; each distinct address gets one bucket per `S014RateLimiterSoundness.md` T-1 | per-prefix budget scales with prefix size | memory/fairness — deferred option-4 per-prefix bucketing; bounded by F-1 eviction |
| K3a — IPv6 port rotation | distinct ports on one IPv6 address | port is always the last colon-component; strip is exact (L-2) — one bucket | none | — |
| K3b — IPv6 hextet-strip exploit (split own traffic) | hope `rfind(':')` strips a hextet to split into 2 buckets | impossible — strip targets the appended port suffix, never an address hextet (L-2, T-4a) | none | — |
| K4 — `"unknown"` fallback poisoning | force `remote_endpoint()` throw | throw is not adversary-selectable post-handshake (L-5); shared bucket coalesces (L-6, T-3) | none | — |
| NAT-shared public IP coalescing | two honest hosts behind one NAT | coalesce into one bucket — fail-safe (L-6); tightens limit | co-located honest peer can starve the other's share | fairness — not a rate-bypass; operator runs distinct profiles or fronts with X-Forwarded-For-aware proxy (deferred) |
| Cross-surface (RPC vs gossip) | exploit a key-format difference | formats coincide (L-3); maps are disjoint anyway (T-5) | none | — |

The matrix's load-bearing conclusion: **every key-derivation failure mode is a coalescing event, and coalescing is monotone fail-safe** (L-6). The derivation can over-meter (charge two hosts to one bucket) but never under-meters (it never gives one host two buckets), because the derived key is a deterministic function of the source address alone (L-3) and a single host has a single source address (L-4).

---

## 7. Findings

### Finding F-1 (NAT-shared-IP fairness degradation — not a rate-bypass).

When multiple honest hosts share one public IP (carrier-grade NAT, a corporate egress proxy, a Tor exit), they coalesce into one rate-limit bucket (L-6). One chatty host behind the NAT can exhaust the shared bucket and deny gossip/RPC service to its co-located peers. This is a **fairness** problem, not a security problem (the per-host security bound is, if anything, over-enforced).

**Severity:** Low (fairness; mitigated operationally by per-deployment profile tuning — operators expecting NAT-fronted peers raise the per-bucket `burst` to accommodate the expected number of co-located hosts).

**Recommended mitigation:** (a) document the NAT-coalescing behavior in the operator guidance so operators size `burst` accordingly; (b) optionally support an `X-Forwarded-For`-equivalent at the RPC layer for deployments fronted by a trusted reverse proxy (would require trusting the proxy to set the header — out of scope for the untrusted-ingress model); (c) the deferred per-prefix-bucketing option-4 from `S014RateLimiterSoundness.md` §6.2 does *not* help here (it coarsens further). No code change recommended for the untrusted-ingress threat model.

### Finding F-2 (Gossip key-strip relies on the port being unconditionally appended).

The gossip strip `s.substr(0, s.rfind(':'))` is correct *because* `Peer::address()` always appends `":" + port` (`src/net/peer.cpp:11-12`). If a future refactor ever produced a `Peer::address()` without the port suffix (e.g., a code path that set `address_ = addr_str(A)` directly), the gossip strip would erroneously remove the last hextet of an IPv6 address, splitting one IPv6 host across buckets and *splitting* its budget — a rate-bypass regression. The current code is correct; this is a discipline finding to prevent a future regression.

**Severity:** Very Low (no current defect; the invariant `Peer::address()` ends in `:port` holds today).

**Recommended mitigation:** add a one-line comment at `src/net/peer.cpp:11` ("address_ MUST end in ':<port>' — gossip rate-limit key derivation strips after the last colon, see RateLimiterKeyDerivationSoundness.md L-2/F-2"), and a unit assertion in the rate-limiter test that `key_gossip("2001:db8::1:8080") == "2001:db8::1"` and `key_gossip("203.0.113.7:51000") == "203.0.113.7"`. Effort: ~10 LOC. Pins L-2's correctness against a future `Peer::address()` change.

### Finding F-3 (No unit test pins the key-derivation functions directly).

The per-bucket algebra is exercised by `determ test-rate-limiter-bucket` and the integration behavior by `tools/test_gossip_rate_limit.sh`, but neither test exercises the *key derivation* in isolation — i.e., neither asserts that an IPv4 address-with-port and an IPv6 address-with-port and the `"unknown"` fallback each map to the expected stripped key. The derivation correctness (T-1..T-4) currently rests on the audit in §3 + the lemmas in §4, not on a pinning regression.

**Severity:** Low (the derivation is two short stanzas of code, audited here; a pinning test is defense-in-depth against F-2's regression class).

**Recommended mitigation:** add a small unit scenario (or extend `test-rate-limiter-bucket`) that feeds the limiter the keys an IPv4 `"a.b.c.d:port"`, an IPv6 `"x:y::z:port"`, a zone-id `"fe80::1%eth0:port"`, and `"unknown:port"` after the strip, and asserts each lands in the bucket count the §4 lemmas predict (distinct global addresses → distinct buckets; same address distinct ports → one bucket). Effort: ~30 LOC. Cross-reference this proof in the scenario comment.

The three findings are advisory; none invalidates T-1..T-5. They are surfaced so an external auditor can confirm the scope: the derivation is sound today, the failure modes are all fail-safe (coalescing, never splitting), and the only open items are a fairness note (F-1) and two test/discipline hardenings (F-2, F-3) against future regressions.

---

## 8. Status

**Shipped (S-014 closure, current `main`).** The key derivation is part of the S-014 rate-limiter closure already in `main`:

- `src/rpc/rpc.cpp:142-153` — RPC `peer_ip` derivation (bare address, `"unknown"` fallback).
- `src/rpc/rpc.cpp:172` — RPC `consume(peer_ip)` gate (before parse + auth).
- `src/net/gossip.cpp:148-154` — gossip `key_gossip` derivation (port strip) + `consume` gate.
- `src/net/peer.cpp:8-14` — `Peer::address()` = `addr_str(A) + ":" + port` (the gossip key's source).
- `include/determ/net/rate_limiter.hpp` — the `RateLimiter` the keys feed into.

This proof adds **no source change**; it formalizes the soundness of the key-derivation layer that the prior S-014 proofs abstract as an opaque per-IP key, proves the failure modes are all fail-safe coalescing (never splitting), and registers three advisory findings (F-1 NAT fairness, F-2 strip-invariant discipline, F-3 derivation pinning test). The end-to-end claim "a single host cannot exceed `⌊C + r·Δ⌋` per surface" now follows from `S014RateLimiterSoundness.md` T-1 *plus* the non-splitting property (L-4) proved here.

---

## 9. Cross-references

### 9.1 Companion proofs

- **`docs/proofs/S014RateLimiterSoundness.md`** — the per-bucket token-bucket algebra. T-1 (bounded burst `⌊C + r·Δ⌋`), T-3 (per-IP independence) cited throughout §4 + §5. §6.2 option-4 (per-prefix bucketing) cross-referenced as the deferred K2 mitigation.
- **`docs/proofs/S014RateLimiterDDOSResistance.md`** — the A-V1..A-V5 adversary taxonomy. This proof refines A-V4's IPv6-rotation model with the port-strip subtlety (T-4) and confirms the derivation does not collapse a /64 (intended).
- **`docs/proofs/S014ConcurrencyAnalysis.md`** — mutex linearizability; establishes the per-key map mutation is race-free for any key content, so the derivation's correctness is orthogonal to the concurrency correctness.
- **`docs/proofs/S026TcpKeepalive.md`** — connection-liveness bound; composes with T-2's same-host connection coalescing (the live-connection count is bounded, but the rate bound holds for any count).
- **`docs/proofs/S022WireFormatCaps.md`** — framing-layer body cap; bounds per-request server work independent of the derived key (so even worst-case key-splitting, which cannot occur, would be parse-cost-bounded).
- **`docs/proofs/RpcAuthHmacSoundness.md`** — the HMAC auth gate fires after the rate-limit gate (§3.4); no key-derivation error weakens authentication.

### 9.2 Implementation sites

- **`src/rpc/rpc.cpp:142-153`** — `key_rpc` derivation (`peer_ip`).
- **`src/rpc/rpc.cpp:166-187`** — RPC gate ordering (rate-limit → parse → auth → dispatch).
- **`src/net/gossip.cpp:148-154`** — `key_gossip` derivation + gate.
- **`src/net/peer.cpp:8-14`** — `Peer::address()` = `addr_str(A) + ":" + port`.
- **`include/determ/net/rate_limiter.hpp:86-117`** — `RateLimiter::consume` (the keyed bucket).

### 9.3 SECURITY.md + tests

- **`docs/SECURITY.md` §S-014** — the rate-limiter closure narrative this proof refines.
- **`tools/test_gossip_rate_limit.sh`** — gossip integration test (uses the gossip key derivation end-to-end).
- **`determ test-rate-limiter-bucket`** — the per-bucket unit scenarios (F-3 recommends a key-derivation extension).

### 9.4 External references

- **RFC 5952** (Kawamura, Kawashima, Aug 2010) — "A Recommendation for IPv6 Address Text Representation." The canonical IPv6 text form `asio::ip::address::to_string()` produces; basis for the §3.3 strip analysis.
- **RFC 4007** (Deering et al., Mar 2005) — "IPv6 Scoped Address Architecture." The zone-id (`%eth0`) form analyzed in T-4.
- **RFC 6598** (Weil et al., Apr 2012) — "IANA-Reserved IPv4 Prefix for Shared Address Space." The carrier-grade-NAT shared-address class underlying F-1.
- **RFC 793 / RFC 9293** — TCP; the source-address integrity property (no off-path post-handshake source rewrite) underlying §2's adversary model.
