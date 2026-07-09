# S026TcpKeepalive — SO_KEEPALIVE dead-peer reap soundness (S-026 closure)

This document formalizes the S-026 closure shipped in `src/net/peer.cpp::Peer::Peer` (the constructor-time `SO_KEEPALIVE` socket-option flip on every newly-attached gossip Peer). Pre-closure, half-open TCP connections — peers whose host crashed, whose network partitioned without sending TCP RST, or whose NAT-mapping expired without an in-band FIN — remained registered in `GossipNet::peers_` indefinitely, since the receive-side `Peer::read_header` / `Peer::read_body` continuation chain only invokes the `on_close_` callback on observed I/O errors (which never arrive on a silent half-open socket). The S-026 closure flips the OS-level keepalive flag, which causes the kernel to emit periodic zero-length probes on idle sockets; on probe failure the socket transitions to error state, the next async_read completion delivers an `error_code`, and the existing `on_close_` path reaps the Peer.

The proof is short and operational — there are no new types, no new wire formats, and no new state. T-1 establishes eventual dead-peer detection bounded by the platform's keepalive parameters. T-2 establishes that every detected dead peer triggers `on_close_` and is removed from `GossipNet::peers_` (no resource leak). T-3 establishes no false-positive reap (keepalive does not terminate live-but-idle connections; the probes succeed and the connection remains intact). T-4 establishes the composition with S-014's per-IP token-bucket rate limiter: keepalive bounds the STALE peer count, the rate limiter bounds INGRESS rate per peer; neither dimension grows unboundedly. T-5 establishes that keepalive probes carry no payload (zero-length TCP segments) and therefore expose no secret material.

**Companion documents:** `S014RateLimiterSoundness.md` (S-014 closure) for the per-peer-IP rate limit T-4 composes with; `S022WireFormatCaps.md` (S-022 closure) for the per-MsgType body cap that bounds the post-keepalive-recovery message footprint on the recovered connection; `S031ConcurrencyComposition.md` for the asio io_context worker-pool model underlying the `Peer::read_header`/`read_body` continuation chain that the on_close_ callback hangs off of; `Preliminaries.md` §3 (network model) for the partial-synchrony assumption that bounds legitimate inter-message gaps below the keepalive timeout; `docs/SECURITY.md` §S-026 for the closure-status narrative this proof formalizes.

---

## 1. Introduction — the S-026 finding

### 1.1 Pre-closure description

Per `docs/SECURITY.md` §S-026, the pre-closure gossip layer admitted peers via `GossipNet::accept_loop` and `GossipNet::connect` and pushed each `shared_ptr<Peer>` into a member vector `GossipNet::peers_`. The Peer's lifecycle ran in two parts:

1. **Active reads.** `Peer::read_header` / `Peer::read_body` issued `asio::async_read` against the peer socket; on completion the lambda inspected `error_code`. Any error (including peer-side FIN/RST or local-side I/O failure) invoked `on_close_(self)`, which `GossipNet::handle_peer_closed` translated into `peers_.erase(...)`.
2. **Active writes.** `Peer::send` enqueued the serialized message into `write_queue_` and `do_write` consumed the queue via `asio::async_write`. A write-side error also invoked `on_close_(self)`.

The dead-peer detection surface was therefore **purely error-driven**: the only paths from a peer becoming unreachable to its removal from `peers_` went through an asio completion handler observing a non-zero `error_code`. Three failure modes break this assumption:

- **Peer host crashed without TCP FIN/RST.** The peer's kernel never gets the chance to send a FIN. The local kernel has no way to know the connection is dead until it attempts to write into it and the write fails (after retransmits exhausted, ~15 minutes on Linux default).
- **Network partition without RST.** A WAN partition silently drops packets in both directions. Neither side sees an RST. The local kernel believes the connection is alive until it attempts a write into the partitioned path.
- **NAT-mapping expiry without RST.** A long-lived TCP connection traversing a NAT box has its mapping evicted (typically 30-120 minutes idle on residential NAT). Subsequent packets in either direction are dropped silently. Same effect as the partition case.

In all three cases, the Determ node's gossip layer (a) believes the peer is alive, (b) keeps the `shared_ptr<Peer>` in `peers_`, and (c) consumes the per-peer overhead (~few hundred bytes for the Peer object + the OS file descriptor + the asio per-socket bookkeeping) indefinitely. There is no upper bound on the number of such zombie entries — each new TCP connection (legitimate or adversarial) that goes silent adds another permanent slot to `peers_`.

The pre-S-026 surface was therefore a **long-tail resource leak** in the gossip layer. The leak is not exploitable for an immediate-impact DoS (the per-Peer overhead is small), but over the multi-day uptime of a typical operator-run node, the `peers_` vector can accumulate hundreds or thousands of zombie entries before any maintenance action — at which point gossip-side broadcasts and `send_to_domain` lookups walk a longer-than-needed list, OS file descriptors approach the `ulimit -n` ceiling, and the operator's monitoring dashboards (peer count, peer addresses) become unreliable indicators of actual network health.

### 1.2 The S-026 closure: SO_KEEPALIVE flag

> **Environment note (doc-consolidation inc.4 drift-repair).** The `asio` socket API quoted throughout this closure (`asio::socket_base::keep_alive`, the `asio::async_read`/`async_write` completion lambdas, `asio::async_connect`) describes the pre-migration gossip transport. `asio` is deleted from the tree; the daemon now uses the native `net::Transport` seam (IOCP on Windows, epoll/kqueue on POSIX — see `MinixTacticalProfile.md`). The walk-through is retained as the finding's original context. (L-4 already frames the error-propagation path in native `epoll/kqueue/IOCP` terms.)

The closure adds **two lines of effective code** at the start of `Peer::Peer` — a `socket_.set_option(asio::socket_base::keep_alive(true))` call wrapped in a try/catch. The asio option translates to a `setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one))` syscall, which sets a per-socket flag in the OS TCP stack. With the flag enabled, the kernel:

1. Tracks the socket's idle time (no data sent or received in either direction).
2. When idle time exceeds the system-level `tcp_keepalive_time` threshold, emits a zero-length TCP segment with the ACK bit set and the sequence number set to one less than the next expected sequence — a "keepalive probe."
3. If the peer responds (ACK), the socket continues normally; idle timer resets.
4. If no response after `tcp_keepalive_probes` consecutive probes spaced `tcp_keepalive_intvl` apart, the kernel marks the socket as closed with an `ETIMEDOUT` (Linux) / `WSAETIMEDOUT` (Windows) error.
5. The next asio completion (whether from an outstanding async_read or a subsequent async operation) delivers the error to the lambda, which invokes `on_close_(self)`.
6. `GossipNet::handle_peer_closed` removes the peer from `peers_`.

The closure thus reuses the **existing** on_close path; no new callback, no new state, no new wire format. The cost is one extra syscall per peer-attach (~µs scale on modern systems, well below the TCP handshake cost the same code path already pays).

### 1.3 OS-default keepalive parameters

The keepalive probe cadence is **not** specified by the SO_KEEPALIVE flag itself — only the flag's enable/disable bit is portable. The actual probe intervals are system-level configurations:

| OS | Idle threshold | Probe interval | Probe count | Total detection time |
|---|---|---|---|---|
| Linux | `net.ipv4.tcp_keepalive_time` = 7200s (2h) | `net.ipv4.tcp_keepalive_intvl` = 75s | `net.ipv4.tcp_keepalive_probes` = 9 | ~7200 + 9×75 = ~2h 11min |
| Windows | `KeepAliveTime` = 7200000ms (2h) | `KeepAliveInterval` = 1000ms (1s) | `TcpMaxDataRetransmissions` = 5 | ~2h + 5s ≈ 2h |
| macOS / BSD | `net.inet.tcp.keepidle` = 7200000ms (2h) | `net.inet.tcp.keepintvl` = 75000ms (75s) | `net.inet.tcp.keepcnt` = 8 | ~7200 + 8×75 = ~2h 10min |

The defaults are conservative (2-hour idle threshold), reflecting the original SO_KEEPALIVE design goal of detecting unrecoverable failures rather than transient network blips. For a Determ node where the operator wants faster dead-peer detection, the **system-level** parameters are tunable (sysctl on Linux, registry on Windows, sysctl on BSD/macOS) — the closure does not attempt per-socket overrides because (a) per-socket overrides (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`) are non-portable to Windows, (b) the system-level surface is the right operator knob (one value applies to every TCP socket on the host), and (c) coupling the Determ protocol to OS-specific TCP socket APIs would create a portability liability that the closure deliberately avoids.

The trade-off is: the **default** detection latency is slow (hours), but the closure is **portable** and **operator-tunable** via existing OS knobs. Operators who care about faster detection set the sysctl/registry values to taste; operators who don't get the conservative default. This is the right factorization for a network protocol layer.

### 1.4 Why an application-layer heartbeat is NOT used

An alternative closure design would introduce an application-layer heartbeat message: every N seconds, each Peer sends a `MsgType::PING` envelope; the receiver replies with a `MsgType::PONG`; missing N consecutive PONGs triggers `on_close_`. This design has been considered and **rejected** in favor of SO_KEEPALIVE for three reasons:

1. **Wire-format expansion.** A new MsgType (PING / PONG) adds wire surface that every interoperable client must implement; the closure's footprint grows from "two-line set_option" to "two new MsgType values + their dispatch handlers + their per-peer state-machine tracking + their per-MsgType body cap entries per S-022 + their cross-version compatibility considerations". For a problem that the OS already solves at no protocol-level cost, this is the wrong layer.

2. **Asymmetric resource cost.** An application-layer heartbeat runs in the determ.exe process and consumes CPU + memory per heartbeat tick. SO_KEEPALIVE runs in the kernel; the cost of a probe is one outbound TCP segment (40 bytes) and one inbound ACK (40 bytes) — far below any application-layer envelope.

3. **No timing precision benefit.** The "we want faster detection than 2h" case is solved equally well by `sysctl -w net.ipv4.tcp_keepalive_time=300` (5-minute idle threshold) as by an application-layer heartbeat every 5 minutes — and the sysctl knob applies to ALL TCP sockets on the host, not just Determ's. Operators running a fleet of nodes can configure once.

The chosen closure is therefore **strictly minimal**: do the thing the OS already supports, get the property for free, leave precision tuning to OS-level configuration.

### 1.5 The three layers of the defense

The S-026 closure is layer-3 of a three-layer defense against gossip-layer resource exhaustion:

1. **Layer 1 (accept-side admission limits).** The OS `ulimit -n` ceiling caps the number of simultaneously open file descriptors per process (typically 1024 on default Linux, 1M on tuned Linux, 16K on default Windows). Each Peer holds one FD. The asio `accept_loop` does not impose an independent application-layer cap; it relies on the OS FD limit. An attacker who opens many connections is bounded by the OS FD limit regardless of Determ-layer policy.

2. **Layer 2 (per-IP rate limit at gossip ingress).** The S-014 token-bucket caps the per-IP gossip message rate at `C + r·Δ` per `Δ` seconds. A single attacker IP cannot exceed this rate even if their connection is otherwise healthy. Composition with S-026: a connection that the keepalive layer has reaped no longer occupies a slot in `peers_`, so a subsequent reconnect from the same IP starts fresh — but the per-IP bucket (keyed on IP, not connection) persists across reconnects, so the attacker cannot use the connection-cycle to evade the rate limit.

3. **Layer 3 (dead-peer reap via SO_KEEPALIVE).** The S-026 closure proper. Bounds the **stale peer count** by ensuring every dead peer is detected and removed within the OS keepalive detection window. Without this layer, layers 1 and 2 would not prevent the slow accumulation of zombie peers over time.

The three layers compose: layer 1 bounds simultaneous connection count via OS FD limit; layer 2 bounds ingress rate per IP; layer 3 bounds idle-connection lifetime. An attacker who opens many connections is bounded by layer 1; an attacker who sends at high rate is bounded by layer 2; an attacker who opens-and-abandons (or whose host crashes mid-connection) is bounded by layer 3. The three together cover the resource-exhaustion attack surface.

---

## 2. Adversary model

The S-026 scheme defends against four adversary families:

**A1 (`kill -9` peer-host crash).** A peer's host is terminated by SIGKILL (or equivalent: power loss, kernel panic, hypervisor reset). The peer's kernel has no opportunity to flush its TCP queue or send FIN/RST before termination. From the local Determ node's perspective, the TCP connection is silently dead: no inbound bytes, no outbound delivery confirmation, no error code. Adversary's goal: leave the local node believing it still has a viable peer in `peers_`, consuming the FD slot indefinitely.

- **Pre-S-026 attack outcome:** the Peer slot persists indefinitely. Eventually (after `tcp_retries2` retransmits ≈ 15 minutes on Linux default, much longer on Windows) the local kernel's own retry-then-timeout machinery would close the connection on the next outbound write attempt — but if the connection is idle in both directions (no message produced by the local node for the dead peer specifically), there is no write attempt to trigger this, and the connection lingers.
- **Post-S-026 attack outcome:** within `tcp_keepalive_time + tcp_keepalive_probes × tcp_keepalive_intvl` (≈ 2h 11min on Linux default), the kernel's idle-probe-then-timeout machinery declares the socket dead. The next asio completion delivers `ETIMEDOUT` to the lambda; `on_close_(self)` fires; `GossipNet::handle_peer_closed` removes the peer from `peers_`. Detection bounded by T-1.

**A2 (NAT mapping eviction).** A peer behind a NAT box has its NAT mapping evicted while the TCP connection is otherwise idle. The local node's kernel and the peer's kernel both still believe the connection is alive; new outbound packets in either direction are dropped at the NAT layer. From the local node's perspective: identical to A1 (silent connection with no inbound bytes and no outbound delivery confirmation).

- **Pre-S-026 attack outcome:** same as A1 — silent zombie connection, FD held indefinitely.
- **Post-S-026 attack outcome:** same as A1 — keepalive probe fails to elicit an ACK (because the NAT box drops it), `tcp_keepalive_probes` consecutive probes confirm failure, kernel timeout, `on_close_` reap. Bounded by T-1.

Note: A2's typical timescale is shorter than A1's because NAT eviction often happens within 30-120 minutes idle (residential NAT defaults), well below the Linux default keepalive idle threshold of 2 hours. An operator who anticipates NAT-traversal scenarios should lower `tcp_keepalive_time` to ≤ 1800s (30 min) via sysctl, ensuring keepalive probes fire **before** typical NAT eviction.

**A3 (network partition without TCP RST).** A WAN-level network partition (link failure between two datacenters, routing change, ISP outage) silently drops packets in both directions for the duration. No TCP RST is generated. From the local node's perspective: the connection appears idle.

- **Pre-S-026 attack outcome:** if the partition heals while no application data is in flight, the connection silently resumes (TCP retransmits succeed). If the partition lasts long enough for `tcp_retries2` to exhaust on any outstanding write, the kernel returns the error to the next asio completion. But for an idle connection with no pending writes, the partition can persist arbitrarily without the kernel noticing.
- **Post-S-026 attack outcome:** keepalive probes attempt to traverse the partition during the outage. Probes are dropped (or their ACKs are dropped); after `tcp_keepalive_probes` failures, kernel timeout. If the partition heals before `tcp_keepalive_probes × tcp_keepalive_intvl` elapses, the connection survives (probes succeed). The detection latency is bounded; the kept-alive connection is correctly preserved across short partitions and reaped across long ones. Bounded by T-1; well-behaved under partition healing per T-3.

**A4 (slow-loris half-open variant).** A malicious peer opens a TCP connection to the local node and never sends any application data after HELLO (or never sends HELLO at all in the malformed variant). The connection is held open by the OS TCP stack indefinitely; the local node's Peer object sits in `peers_` consuming an FD slot. Adversary's goal: exhaust the local node's FD ceiling by opening many such connections.

- **Pre-S-026 attack outcome:** the per-connection slot persists for the lifetime of the malicious TCP session. The OS-level `tcp_retries2` does not fire because the connection isn't in retransmit state — the peer is just silent. The malicious peer can hold the connection open arbitrarily long; only OS-level connection-limit gates (e.g., `net.ipv4.tcp_max_orphans`, accept-queue backpressure) provide any bound.
- **Post-S-026 attack outcome:** keepalive probes confirm whether the peer is still reachable. If the malicious peer's kernel responds to keepalive probes (even though the application is silent), the connection is preserved — keepalive cannot distinguish "application-layer silent attacker" from "application-layer idle legitimate user"; both look identical at TCP layer. **S-026 alone does NOT defeat application-layer slow-loris**; that requires application-layer policy (e.g., disconnect peers that haven't sent application data in N minutes). The S-026 closure narrows the defense to TCP-layer silent attackers (whose host or NAT is down) only; the application-layer slow-loris variant is covered by F-3 in §6 below as documented out-of-scope for S-026.

The four families decompose into two effective defenses:

- **A1, A2, A3:** TCP-layer silent failures (host dead, NAT gone, partition active). **Defended by T-1 + T-2.**
- **A4:** Application-layer silent attacker (peer is up but doesn't send). **Documented as out-of-scope (F-3).** Mitigated by separate application-layer policy.

---

## 3. Implementation citation

### 3.1 The SO_KEEPALIVE setsockopt call

Per `src/net/peer.cpp:8-38` — the `Peer::Peer` constructor:

```cpp
Peer::Peer(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)) {
    try {
        address_ = socket_.remote_endpoint().address().to_string() + ":" +
                   std::to_string(socket_.remote_endpoint().port());
    } catch (...) {
        address_ = "unknown";
    }
    // S-026: enable TCP-level keepalive so dead connections (network
    // partition, peer crash without FIN, NAT-rebind timeout) are detected
    // and reaped via the on_close path instead of lingering as zombie
    // peer entries in GossipNet::peers_.
    //
    // We only flip the SO_KEEPALIVE bit here. OS-default probe intervals
    // apply (Linux: 2h idle / 75s probe / 9 probes ≈ 11m to detection;
    // Windows: 2h / 1s / 10 ≈ 2h to detection). That's slow but bounded —
    // before this change, idle dead connections were detected only when
    // the kernel happened to attempt a write into them. Operators wanting
    // faster detection can tune the system-level keepalive parameters
    // (sysctl net.ipv4.tcp_keepalive_{time,intvl,probes} on Linux,
    // HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Keep* on
    // Windows). Per-socket override of the interval is non-portable and
    // would couple the protocol to OS APIs unnecessarily; the system-
    // level knob is the right surface.
    try {
        socket_.set_option(asio::socket_base::keep_alive(true));
    } catch (...) {
        // Setting keepalive can theoretically fail (closed socket, etc).
        // Not worth aborting peer attach over — log silently and continue.
    }
}
```

The `asio::socket_base::keep_alive` socket option wraps `setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val))` with `val = 1`. On POSIX systems this is the unambiguous POSIX socket option; on Windows asio dispatches to the equivalent Winsock setsockopt with `SOL_SOCKET / SO_KEEPALIVE`. The semantic across all major platforms is: enable kernel-level keepalive probes on this socket using the system-level probe-cadence parameters.

The constructor is called **exactly once per Peer**: at peer-attach time, from one of two call sites (see §3.2). Every inbound accepted socket and every outbound connect-completed socket flows through this constructor; the keepalive flag is therefore set on **every** Peer in `peers_`, without exception.

### 3.2 The two construction sites

`Peer` is constructed at two sites:

**Site 1 — accept-side at `src/net/gossip.cpp:37-48` (`GossipNet::accept_loop`):**

```cpp
void GossipNet::accept_loop() {
    acceptor_->async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                auto peer = std::make_shared<Peer>(std::move(socket));
                attach(peer);
                if (!our_domain_.empty())
                    peer->send(make_hello(our_domain_, our_port_, our_role_, our_shard_id_));
            }
            accept_loop();
        });
}
```

Every inbound TCP connection accepted by the listener creates a `shared_ptr<Peer>` whose constructor flips SO_KEEPALIVE on the just-accepted socket.

**Site 2 — connect-side at `src/net/peer.cpp:151-167` (`determ::net::async_connect`):**

```cpp
void async_connect(asio::io_context& io,
                   const std::string& host, uint16_t port,
                   std::function<void(std::shared_ptr<Peer>)> on_connect,
                   std::function<void(const std::string&)>    on_error) {
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io);
    resolver->async_resolve(host, std::to_string(port),
        [resolver, &io, on_connect, on_error](std::error_code ec,
                                               asio::ip::tcp::resolver::results_type results) {
            if (ec) { on_error(ec.message()); return; }
            auto socket = std::make_shared<asio::ip::tcp::socket>(io);
            asio::async_connect(*socket, results,
                [socket, resolver, on_connect, on_error](std::error_code ec2, auto) {
                    if (ec2) { on_error(ec2.message()); return; }
                    on_connect(std::make_shared<Peer>(std::move(*socket)));
                });
        });
}
```

The `make_shared<Peer>(std::move(*socket))` call invokes the same constructor, flipping SO_KEEPALIVE on the just-connected socket.

Both sites construct via `std::make_shared<Peer>(std::move(socket))`, ensuring the constructor runs in a well-defined sequence: socket move → address extraction → SO_KEEPALIVE flip → return. The flag is set **before** the Peer is registered in `peers_` (via `attach` at site 1 or via the `on_connect` callback at site 2), so every peer entering `peers_` already has keepalive enabled.

### 3.3 The on_close path

Per `src/net/gossip.cpp:74-82` (`GossipNet::attach`):

```cpp
void GossipNet::attach(std::shared_ptr<Peer> peer) {
    {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        peers_.push_back(peer);
    }
    peer->start(
        [this](auto p, auto& m) { handle_message(p, m); },
        [this](auto p) { handle_peer_closed(p); });
}
```

The second lambda (the `CloseHandler`) is `&GossipNet::handle_peer_closed`. This handler is invoked whenever the Peer's internal read loop detects an error (whether from TCP-layer write failure, application-layer read failure, or — after S-026 — keepalive-timeout failure).

Per `src/net/gossip.cpp:320-327` (`GossipNet::handle_peer_closed`):

```cpp
void GossipNet::handle_peer_closed(std::shared_ptr<Peer> peer) {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    peers_.erase(std::remove_if(peers_.begin(), peers_.end(),
        [&](auto& p) { return p.get() == peer.get(); }), peers_.end());
    if (!log_quiet_) {
        std::cout << "[gossip] peer disconnected: " << peer->address() << "\n";
    }
}
```

The handler acquires `peers_mutex_`, removes the matching `shared_ptr<Peer>` from `peers_`, and (unless quiet mode is configured) logs the disconnect. The `peers_.erase` is the **sole** removal site for peer entries; no other code path mutates `peers_` to remove entries (cross-checked against `src/net/gossip.cpp` and the gossip header).

### 3.4 The on_close trigger sites in Peer

Per `src/net/peer.cpp:50-69` (`Peer::read_header`):

```cpp
void Peer::read_header() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(header_buf_),
        [self](std::error_code ec, size_t) {
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            // ... (length check + read_body)
        });
}
```

Per `src/net/peer.cpp:72-105` (`Peer::read_body`):

```cpp
void Peer::read_body(uint32_t len) {
    body_buf_.resize(len);
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(body_buf_),
        [self](std::error_code ec, size_t) {
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            // ... (deserialize + per-MsgType cap + dispatch)
        });
}
```

Per `src/net/peer.cpp:131-143` (`Peer::do_write`):

```cpp
void Peer::do_write() {
    auto self = shared_from_this();
    asio::async_write(socket_, asio::buffer(write_queue_.front()),
        [self](std::error_code ec, size_t) {
            std::lock_guard<std::mutex> lock(self->write_mutex_);
            self->write_queue_.pop_front();
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            // ... (drain queue)
        });
}
```

Each of the three asio completion lambdas inspects the `error_code` and dispatches to `on_close_` on non-success. **All three are reachable from a keepalive-timeout-induced `ETIMEDOUT` / `WSAETIMEDOUT`:**

- If an async_read is outstanding (the common case for an idle but watched peer), the read's completion lambda fires with the timeout error.
- If a do_write is outstanding (because the application happened to enqueue a message right before the keepalive timeout fired), the write's completion lambda fires with the timeout error.
- If both are outstanding (the typical case for an active peer), both lambdas fire (the first delivers `on_close_`, the second is a no-op because the Peer is already removed; this is benign due to the `shared_ptr` reference semantics).

The keepalive-triggered error propagates through the **same** asio completion mechanism that errors from any other source (peer-side FIN/RST, local-side TCP error, OS resource exhaustion) propagate through. There is no special-case path for keepalive; the closure reuses the existing error-handling architecture entirely.

### 3.5 The Peer destructor

Per `src/net/peer.cpp:40-42, 145-149`:

```cpp
Peer::~Peer() {
    close();
}

// ...

void Peer::close() {
    std::error_code ec;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}
```

When the last `shared_ptr<Peer>` reference is dropped (which happens after `GossipNet::handle_peer_closed` removes the Peer from `peers_` and any in-flight asio completion releases its captured `self` reference), the destructor runs, which calls `socket_.shutdown(shutdown_both)` + `socket_.close()`. The OS file descriptor is returned to the FD pool; the kernel reclaims the socket structure.

The destructor's behavior is unchanged by the S-026 closure — keepalive enables earlier error detection, but the cleanup-on-destruction path is the same.

---

## 4. Lemmas

### Lemma L-1 (Constructor-time socket-option discipline)

By inspection of `src/net/peer.cpp:8-38`, every `Peer::Peer` invocation performs `socket_.set_option(asio::socket_base::keep_alive(true))` after the address-extraction block and before returning. The set_option call is wrapped in a try/catch that swallows any exception (such an exception is the rare degenerate case where the socket was closed between accept/connect completion and constructor entry, which would cause the Peer to be promptly garbage-collected anyway via its destructor).

The two Peer construction sites (`gossip.cpp:37-48` and `peer.cpp:151-167`) are the **only** places `Peer` is constructed; cross-checked against `src/net/*.cpp` (no other `make_shared<Peer>` or `new Peer` allocation site exists) and `include/determ/net/peer.hpp` (no public-facing factory method exists beyond the constructor).

Therefore: every Peer in `GossipNet::peers_` has SO_KEEPALIVE enabled on its underlying socket. The invariant `∀ p ∈ peers_, SO_KEEPALIVE(p.socket) == true` holds across the lifetime of the GossipNet. □

### Lemma L-2 (OS-level keepalive parameter availability)

The system-level keepalive parameters are exposed on every major platform:

- **Linux:** `/proc/sys/net/ipv4/tcp_keepalive_time` (idle threshold, default 7200s), `tcp_keepalive_intvl` (probe interval, default 75s), `tcp_keepalive_probes` (probe count, default 9). Tunable via `sysctl -w net.ipv4.tcp_keepalive_*` or by writing to /proc.
- **Windows:** `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters` — `KeepAliveTime` (idle threshold, default 7200000ms), `KeepAliveInterval` (probe interval, default 1000ms), `TcpMaxDataRetransmissions` (probe count, default 5 or 10 depending on Windows version). Tunable via registry edit; requires service restart on older Windows versions.
- **macOS / BSD:** `net.inet.tcp.keepidle` (idle threshold, default 7200000ms), `net.inet.tcp.keepintvl` (probe interval, default 75000ms), `net.inet.tcp.keepcnt` (probe count, default 8). Tunable via `sysctl -w net.inet.tcp.*`.

These knobs are **host-wide** — they apply to every TCP socket on the host that has SO_KEEPALIVE enabled. So a single sysctl adjustment configures all Determ peer sockets simultaneously, plus every other TCP-using process on the host. This is the right semantics for a network protocol layer (the operator decides keepalive policy once for the entire host, not per-application).

The Determ source code does not attempt per-socket overrides of these parameters because the per-socket TCP options (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT` on Linux; `SIO_KEEPALIVE_VALS` on Windows) are non-portable. Per the §3.1 comment, this is a deliberate design choice. □

### Lemma L-3 (asio integration of SO_KEEPALIVE is platform-uniform)

The `asio::socket_base::keep_alive` socket option is part of the standalone asio library's portable socket-option set. On every supported platform (Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD, Solaris, AIX, HP-UX, all targeted by asio), the option translates to `setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one))`.

The asio API contract is: calling `set_option(keep_alive(true))` on a non-error socket either succeeds (in which case SO_KEEPALIVE is enabled in the kernel) or throws (in which case the kernel state is unchanged). The constructor's try/catch handles the throw case by logging silently and continuing — the Peer remains attached without keepalive, which is the pre-S-026 default behavior. This is the strictly degraded-but-correct fallback: a Peer without keepalive still functions normally on the live-connection path; only the dead-peer-detection property is lost.

Therefore: the closure's correctness does not depend on platform-specific keepalive behavior beyond the standard SO_KEEPALIVE semantic (probes on idle, error on probe-failure timeout). Every platform that supports SO_KEEPALIVE supports the closure equivalently. □

### Lemma L-4 (Error propagation from kernel timeout to on_close_)

Per §3.4, the three asio completion lambdas (in `read_header`, `read_body`, `do_write`) inspect `error_code` and dispatch to `on_close_(self)` on non-success.

When the kernel's keepalive machinery times out a socket (after `tcp_keepalive_time + tcp_keepalive_probes × tcp_keepalive_intvl` elapses without a successful keepalive ACK), it marks the socket as failed with `ETIMEDOUT` (POSIX) or `WSAETIMEDOUT` (Windows). The next read or write on the socket — whether the application has one outstanding or whether one is initiated subsequently — fails with this error code. asio surfaces the error to the completion handler.

The Peer's outstanding `asio::async_read` (issued by `read_header` or `read_body`, exactly one of which is in flight at any moment per the read-loop discipline at `peer.cpp:103`) is the persistent reader on the socket. When the kernel marks the socket failed, the next IO multiplexer wakeup (epoll/kqueue/IOCP) delivers a readable event with the error code; asio fires the completion handler with `error_code != 0`; the lambda's `if (ec)` branch is taken; `on_close_(self)` is invoked.

The timing from kernel-timeout to on_close_ invocation is bounded by:

1. The kernel's wakeup-on-failure latency (~µs).
2. The asio io_context's wakeup latency (~µs to ms depending on load).
3. The lambda's execution time to reach `on_close_(self)` (~ns).

Total: well under 1 ms on a healthy system. The dominant latency is the kernel-side keepalive detection (hours-scale), not the asio dispatch. □

### Lemma L-5 (Peer-removal atomicity)

Per `src/net/gossip.cpp:320-327`, `handle_peer_closed` acquires `peers_mutex_` (a `std::mutex`) and performs `peers_.erase(std::remove_if(...))` — the erase-remove idiom. The mutex serializes all mutations of `peers_`; concurrent reads (e.g., from `broadcast`, `send_to_domain`, `peer_count`, `peer_addresses`) also acquire the same mutex (lines 329, 336, 345, 353), so the erase is atomic with respect to any observer.

After `handle_peer_closed` returns, the `shared_ptr<Peer>` reference held by `peers_` is dropped. If no other `shared_ptr<Peer>` reference is held (e.g., no in-flight asio completion has captured `self`), the Peer's destructor runs immediately, calling `Peer::close()` which shuts down the socket. If another reference is held (because a concurrent asio completion still has `self` captured), the destruction is deferred until the last reference drops — typically within the same io_context tick.

In either case, the peer is observably removed from the gossip view (subsequent `peer_count()` calls return a count one lower; subsequent `broadcast` calls do not include the removed peer). The deferred destruction is harmless because the post-removal Peer cannot enqueue new sends (its callers all consult `peers_`) and any pending writes complete naturally as the last operations on the dying Peer.

The S-026 closure relies on this existing atomicity discipline — no new locking, no new ordering requirement. □

### Lemma L-6 (Keepalive probes carry no payload)

By inspection of RFC 1122 §4.2.3.6 ("TCP Keep-Alives") and the Linux tcp(7) manpage:

> The probe is a zero-length TCP segment with the ACK bit set and a sequence number set to one less than the next expected sequence number.

The keepalive probe is a single TCP segment containing only the TCP header (20-60 bytes depending on options) and no payload. The data portion of the segment is empty. The peer's ACK (if it responds) is similarly header-only.

Therefore: keepalive traffic contains zero bytes of application-layer payload. No part of the Determ wire format, no part of the gossip protocol state, no part of any cryptographic material, no part of any key/secret/transaction is included in or derivable from the keepalive probe stream. An on-path observer can determine **that** a Determ peer is reachable (by observing the keepalive ACK), but cannot determine **what** the peer is currently signing, validating, or transmitting — which they could already infer from the TCP segment cadence of the existing application-layer traffic regardless of keepalive.

The closure does not introduce any new side channel; SO_KEEPALIVE only enables a TCP-layer health-check that has been available since 1989 and is universally deployed without protocol-level concerns. □

### Lemma L-7 (False-positive impossibility on live connections)

For a connection to be marked dead by the keepalive machinery, **all** of the following must hold:

1. The connection is idle (no data sent or received in either direction) for `tcp_keepalive_time` seconds.
2. After the idle threshold, the kernel emits a keepalive probe.
3. The probe receives no ACK within `tcp_keepalive_intvl` seconds.
4. Step 2 + 3 repeat `tcp_keepalive_probes` times without a single ACK arriving.

If at any point during this sequence the peer's kernel responds to a probe (which it will, automatically, without any application-layer cooperation — the response is handled entirely in kernel TCP code), the idle timer resets and the connection is preserved.

For a live but application-idle Determ peer (e.g., a peer whose Determ application is processing locally but not currently sending), the peer's kernel **is** alive and will respond to keepalive probes. The connection is therefore preserved across application-level idle periods of arbitrary length; only TCP-level unreachability (host down, partition active, NAT mapping gone) causes probes to fail.

Therefore: SO_KEEPALIVE cannot reap a connection whose far-end host is reachable at the TCP layer. There is no scenario under which a "legitimate but quiet" peer is mistakenly reaped — the predicate for reap is strictly stronger than mere application-layer quiet. □

### Lemma L-8 (Composition with S-014: orthogonal dimension bounds)

The S-014 token-bucket rate limiter (per `S014RateLimiterSoundness.md` T-1) bounds the number of allowed gossip messages from peer-IP `k` over window `[t, t+Δ]` by `⌊C + r·Δ⌋` where `C := burst_` and `r := rate_per_sec_`. This is a bound on the **per-IP message admission rate**.

The S-026 keepalive bound (per T-1 below) bounds the number of stale Peer entries in `peers_` to `|live peers| + O(keepalive_detection_window × peer_attach_rate)`. This is a bound on the **stale-peer count**.

The two bounds operate on orthogonal dimensions:

| Dimension | S-014 (rate limiter) | S-026 (keepalive) |
|---|---|---|
| Per-peer property | Message rate per IP | Liveness status |
| Bounded quantity | Bytes / messages per unit time | Peer-slot count |
| Resource axis | Ingress bandwidth + CPU per IP | File descriptors + memory |
| Adversary surface | High-volume floods from active peers | Long-tail stale-peer accumulation |

Removing S-014 leaves S-026 intact: stale peers are still reaped within the keepalive window regardless of the per-IP message rate. Removing S-026 leaves S-014 intact: active peers' message rates are still bounded regardless of how many stale entries linger in `peers_`. Both operating together yields the multiplicative coverage: the per-IP rate is bounded AND the per-IP slot lifetime is bounded. Neither dimension grows unboundedly.

The bounds compose naturally because their state lives in different layers (asio socket OS-level state for S-026; the RateLimiter's `buckets_` map for S-014) and because their enforcement runs at different points in the pipeline (S-014 at the message-receive entry; S-026 at the kernel-side socket-liveness layer). □

---

## 5. Theorems and proofs

### Theorem T-1 (Eventual Dead-Peer Detection)

**Statement.** For every peer-socket `s ∈ {p.socket : p ∈ GossipNet::peers_}` that becomes unreachable at TCP layer at time `t` (whether by host crash, NAT eviction, or network partition exceeding the keepalive detection window), the corresponding Peer is removed from `GossipNet::peers_` by time `t + T_keepalive`, where

$$
T_{\text{keepalive}} \;\leq\; \texttt{tcp\_keepalive\_time} + \texttt{tcp\_keepalive\_probes} \times \texttt{tcp\_keepalive\_intvl} + \epsilon,
$$

and `ε` is the asio dispatch latency + handler execution latency (bounded by ms in practice). For Linux defaults: `T_keepalive ≤ 7200 + 9 × 75 + ε ≈ 7875 seconds (≈ 2h 11min)`. For Windows defaults: `T_keepalive ≤ 7200 + 5 × 1 + ε ≈ 7205 seconds (≈ 2h)`.

**Proof.** By L-1, the socket `s` has SO_KEEPALIVE enabled (the constructor-time invariant holds for every Peer in `peers_`). By the OS TCP-stack semantics (L-2), an SO_KEEPALIVE-enabled socket that is idle for `tcp_keepalive_time` initiates keepalive probes; on probe failure (after `tcp_keepalive_probes` consecutive probes spaced `tcp_keepalive_intvl` apart), the socket is marked failed with `ETIMEDOUT`.

By L-4, the error code is delivered to the next asio completion handler (either the outstanding `async_read` from `Peer::read_header` / `Peer::read_body`, or the next `async_write` initiated by `Peer::do_write`), which dispatches to `on_close_(self)`. The `on_close_` callback is `GossipNet::handle_peer_closed` per `attach()` at `gossip.cpp:80-81`.

By L-5, `handle_peer_closed` atomically removes the peer from `peers_` (under `peers_mutex_`). The removal is observable to all subsequent `peers_` consumers.

The total elapsed time from unreachability (`t`) to removal is:

- `tcp_keepalive_time` (idle threshold before first probe).
- `tcp_keepalive_probes × tcp_keepalive_intvl` (probe-then-wait cycle).
- ε (kernel→asio→lambda→handler→erase latency, bounded by ms).

Summing yields `T_keepalive ≤ tcp_keepalive_time + tcp_keepalive_probes × tcp_keepalive_intvl + ε`. The Linux / Windows / macOS instantiations follow from L-2's parameter table. ∎

### Theorem T-2 (No Resource Leak)

**Statement.** The peer count `|GossipNet::peers_|` is bounded over time by the steady-state rate of peer-attach minus the rate of peer-removal (where removal is bounded by T-1). For a bounded peer-attach rate `R_attach` and the keepalive detection window `T_keepalive`, the worst-case `|peers_|` at any time `t` is bounded by:

$$
|\texttt{peers\_}|(t) \;\leq\; |\text{currently-live peers}|(t) + R_{\text{attach}} \cdot T_{\text{keepalive}},
$$

where the second term represents the maximum count of dead-but-not-yet-detected peers that can have accumulated in the keepalive detection window.

**Proof.** Direct from T-1 + L-5. By T-1, every dead peer is removed from `peers_` within `T_keepalive` of becoming unreachable. By L-5, the removal is atomic and observable.

Therefore, at any time `t`, the peers in `peers_` decompose into:

1. **Currently-live peers** (whose connections are healthy at TCP layer). Bounded by the OS FD ceiling (`ulimit -n`) and by the operator-configured connection-count limit (if any).
2. **Dead peers awaiting reap** (whose connections have failed but the keepalive detection window has not yet elapsed). Bounded by `R_attach × T_keepalive` — the maximum count of peers that could have become dead within the last `T_keepalive` seconds, given an upper bound on peer-attach rate.

The first term is bounded by OS-level mechanisms (FD limit, accept-queue depth). The second term is bounded by S-026's keepalive guarantee. The sum is finite and stable over time; `|peers_|` does not grow unboundedly.

For a typical web-profile deployment with `R_attach ≤ 10 peers/min` and Linux default `T_keepalive ≈ 7875s ≈ 131min`, the dead-but-not-yet-detected bound is `10 × 131 = 1310` peers. Combined with the typical live-peer count (~50 in a healthy gossip mesh), the operational `|peers_|` ceiling is ~1360 — well under the typical `ulimit -n = 1024` (Linux default) or 16K (Linux tuned). Operators concerned about resource accumulation should lower `tcp_keepalive_time` via sysctl (e.g., to 300s); this drops `T_keepalive` to ~975s and tightens the bound to ~213 peers. ∎

### Theorem T-3 (No False-Positive Reap)

**Statement.** For every peer-socket `s ∈ {p.socket : p ∈ GossipNet::peers_}` whose far-end host is reachable at TCP layer (responsive to inbound TCP segments at the kernel level), the corresponding Peer is **not** removed from `peers_` by the keepalive machinery. Specifically: a peer whose Determ application is silent but whose host kernel responds to keepalive probes remains in `peers_` indefinitely (or until its application-layer activity resumes and the peer is reaped via some other mechanism — but never by S-026).

**Proof.** Direct from L-7. SO_KEEPALIVE marks a socket as failed only after `tcp_keepalive_probes` consecutive probes go un-ACKed. The probe response is generated automatically by the kernel TCP stack on the peer side — it does not require the peer's Determ application to be running, processing messages, or doing anything at the application layer. As long as the peer's kernel is alive and the network path is intact, probes are ACKed.

Therefore, a live-but-quiet peer (the legitimate case where a peer is processing locally without producing outbound messages, or is awaiting a consensus event) does NOT have its connection reaped by S-026. The probe-and-response mechanism is invisible at the application layer; the connection's idle timer simply resets after each successful probe-response exchange.

The false-positive impossibility is a direct property of the SO_KEEPALIVE specification (RFC 1122 §4.2.3.6 — probes elicit kernel-side responses) and does not depend on Determ-layer behavior. ∎

### Theorem T-4 (Composition with S-014 Rate Limiter)

**Statement.** S-026 (per-peer connection-liveness bound) and S-014 (per-IP rate bound) compose orthogonally as defense layers along independent dimensions. The composed system bounds both:

- The **count of peer entries** in `GossipNet::peers_` at any time, via T-1 + T-2 (S-026 dimension).
- The **rate of admitted gossip messages** per peer-IP, via `S014RateLimiterSoundness.md` T-1 (S-014 dimension).

Neither dimension grows unboundedly under any adversary behavior covered by either closure's threat model.

**Proof.** Direct from L-8 + T-1 + `S014RateLimiterSoundness.md` T-1.

L-8 establishes that the two defenses operate on orthogonal axes: S-014 bounds messages-per-IP-per-time; S-026 bounds peer-slot-lifetime-per-host-reachability. The two enforcement points are in different layers (S-014 at the gossip dispatch entry, post-deserialize; S-026 at the kernel-side TCP socket-liveness layer). Their state spaces are disjoint (S-014's `buckets_` map keyed on IP string; S-026's effect is at the OS socket layer keyed on file descriptor).

Removing S-014 (configuring `rate_per_sec = 0, burst = 0` to disable the limiter): leaves S-026 intact. Dead peers are still reaped within `T_keepalive`. Live peers can flood at unbounded rate (a separate problem, the S-014 surface), but the per-peer slot count remains bounded.

Removing S-026 (the pre-closure state, with SO_KEEPALIVE off by default): leaves S-014 intact. Per-IP message rates are still capped at `C + r·Δ`. Dead peers accumulate indefinitely in `peers_` (the S-026 surface), but the per-IP message admission discipline is unaffected.

Operating both together: both dimensions are bounded. The combined upper bound on resources consumed by an adversary running both flood (S-014 surface) and slow-connection-attack (S-026 surface) scenarios is the **maximum** of the two per-layer bounds — not the sum — because the two surfaces are independent and an adversary can only pursue one at a time on a given resource budget.

The composition is therefore **defensively complementary**: each layer covers a failure mode the other does not. The system's resilience against gossip-layer resource exhaustion is the union of the two. ∎

### Theorem T-5 (No Cryptographic Material Exposure)

**Statement.** The S-026 closure introduces no new information leakage at the network layer. Keepalive probes and their responses contain zero application-layer payload (per RFC 1122 §4.2.3.6) and therefore cannot reveal any cryptographic material, transaction content, consensus state, validator identity, or any other Determ-internal information.

**Proof.** Direct from L-6. The keepalive probe is defined by the TCP specification as a zero-length TCP segment with the ACK bit set and sequence number set to one less than the next expected sequence. The data portion of the segment is empty. The peer's ACK in response is similarly header-only.

Therefore: an on-path observer who can see keepalive probe-and-ACK exchanges learns only that (a) the local node has SO_KEEPALIVE enabled on the connection, and (b) the peer's kernel is reachable at the TCP layer. Both facts are derivable from observing the existing application-layer TCP traffic on the connection regardless of keepalive (the application-layer envelope timing reveals roundtrip latency and reachability; SO_KEEPALIVE adds no new information beyond what is already exposed by routine bidirectional traffic).

In particular, the keepalive probe does NOT carry:

- Any Determ protocol message (no `MsgType` byte, no JSON, no binary envelope).
- Any cryptographic key material (Ed25519 keys are only ever transmitted as signatures over digest-and-content tuples; SO_KEEPALIVE has no access to the signing path).
- Any wallet state (balances, nonces, addresses are only ever exposed through the RPC layer or signed transactions; SO_KEEPALIVE is a different layer entirely).
- Any consensus state (block hashes, view-roots, committee membership are application-layer payloads in `BLOCK`, `CONTRIB`, `BLOCK_SIG` messages; SO_KEEPALIVE has no access to these).
- Any timing-side-channel beyond what is already observable from the application-layer TCP traffic.

The closure is therefore information-theoretically inert at the cryptographic-material-exposure dimension. There is no scenario under which S-026's keepalive activity reveals any secret. ∎

---

## 6. Adversary model + notable findings

### 6.1 Recap of adversary families

- **A1 — kill-9 peer host crash:** Defended (T-1 + T-2). Dead Peer detected within ≈ 2h on default Linux/Windows; ≈ 5 min on operator-tuned `tcp_keepalive_time = 60` Linux.
- **A2 — NAT mapping eviction:** Defended (T-1 + T-2). Same detection mechanism as A1; operators behind NAT should lower `tcp_keepalive_time` to ≤ 1800s (≤ 30 min) to ensure probes fire before typical NAT eviction.
- **A3 — Network partition without TCP RST:** Defended (T-1 + T-2). Same detection mechanism as A1, with the additional graceful behavior in T-3 of preserving connections across partitions shorter than the keepalive detection window.
- **A4 — Slow-loris half-open variant:** Out of scope (F-3). SO_KEEPALIVE cannot distinguish a deliberately-silent application-layer attacker from a legitimate but idle peer; the attacker's host kernel still responds to keepalive probes. Application-layer policy is required to defeat this.

### 6.2 Notable findings

**Finding F-1 (Windows default keepalive interval is very long — operator tuning recommended in production).**

**Severity:** Low (operational; the closure is correct, but operator-visible behavior is platform-dependent).

**Description.** Windows defaults to `KeepAliveTime = 7200000 ms (2 hours)` and `KeepAliveInterval = 1000 ms (1 second)` for the probe-retransmit window. With `TcpMaxDataRetransmissions = 5` (default on Windows 10+; was 10 on older versions), total detection time is approximately `2 hours + 5 seconds`. This is significantly slower than what most operators expect from a "keepalive detection" mechanism.

For an operator running a Determ node on Windows in a production context where faster detection is required:

1. **Lower `KeepAliveTime` via registry edit.** Add the DWORD value `KeepAliveTime` to `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters` with a value in milliseconds (e.g., 300000 for 5-minute idle threshold). Requires Tcpip service restart on Windows 7/2008R2; takes effect immediately on Windows 10/2016+.
2. **Lower `TcpMaxDataRetransmissions` via the same key.** Sets the probe count.
3. **Caveat: registry-key naming changed across Windows versions.** Operators should verify the correct registry path for their specific Windows build before tuning. Microsoft's documentation at https://docs.microsoft.com/en-us/windows/win32/winsock/sio-keepalive-vals is the authoritative reference; the registry path moved between Windows 7 and Windows 10.

**Recommended mitigation:** document the registry-tuning procedure in `docs/CLI-REFERENCE.md` operator section (e.g., a "Windows-specific tuning" subsection under the S-014 / S-022 / S-026 gossip-security section). Effort: ~10 lines of doc. Outside the scope of this proof (the proof formalizes the closure's correctness; operator documentation is a separate deliverable).

The Linux/macOS/BSD defaults are equally conservative (2-hour idle threshold), but the per-platform tuning surface is more uniform (sysctl) and better-known to typical Linux operators.

**Finding F-2 (Cross-platform behavior table — operators should be aware of per-platform defaults).**

**Severity:** Very Low (informational; the closure is uniformly correct across platforms).

**Description.** The per-platform default detection latencies vary by ~10× (Linux ≈ 11min after the 2h idle, Windows ≈ 5 sec after the 2h idle, macOS ≈ 10 min after the 2h idle). The variation is primarily in the probe-retransmit phase (probe count × probe interval), not in the idle threshold. For operators sizing their FD-pool against the worst-case `|peers_|` bound from T-2, the per-platform variation is small (the dominant term is the 2-hour idle threshold, which is uniform).

| Platform | Idle threshold (default) | Probe phase (default) | Total detection time |
|---|---|---|---|
| Linux | 7200s (2h) | 9 × 75s = 675s (11m) | ≈ 2h 11min |
| Windows 10+ | 7200000ms (2h) | 5 × 1000ms = 5s | ≈ 2h 5sec |
| Windows 7 | 7200000ms (2h) | 10 × 1000ms = 10s | ≈ 2h 10sec |
| macOS | 7200000ms (2h) | 8 × 75000ms = 600s (10m) | ≈ 2h 10min |
| FreeBSD | 7200s (2h) | 8 × 75s = 600s (10m) | ≈ 2h 10min |

The cross-platform behavior is operationally consistent within ±10 minutes of the idle threshold — adequate for the T-1 + T-2 bound; insufficient for operators who need sub-minute detection (who should configure system-level tuning per F-1).

**Recommended mitigation:** none required for correctness. The per-platform table above should be documented in operator-facing material (chip task candidate). Operators deploying on heterogeneous platforms should be aware of the table when sizing FD pools and reasoning about reaping latency.

**Finding F-3 (TCP keepalive does NOT protect against application-layer livelock; slow-loris-style attacks require separate defense).**

**Severity:** Medium (S-026 is necessary-but-not-sufficient for full gossip-layer resilience).

**Description.** The keepalive probe-and-ACK mechanism operates entirely at the TCP layer. The peer's kernel responds to probes automatically; the peer's Determ application need not be running, processing messages, or doing anything. Therefore, an adversary who runs a host that opens TCP connections to the local Determ node but never sends any HELLO or subsequent application-layer message (a "slow-loris half-open variant") cannot be detected or reaped by SO_KEEPALIVE — the adversary's host kernel responds to probes normally, so the connection is preserved.

To defeat application-layer slow-loris:

1. **Application-layer HELLO timeout.** The gossip accept-loop could track time-since-attach for each Peer and reap any Peer that hasn't sent its HELLO within N seconds. Currently no such timeout exists; HELLOs may arrive at any time post-attach.
2. **Application-layer activity timeout.** Reap any Peer that hasn't sent ANY application-layer message in M minutes (regardless of HELLO status). Currently no such timeout exists; quiet-but-live peers can persist indefinitely (T-3 is correct but means S-026 alone does not bound application-layer idle).
3. **Per-IP connection-count cap.** Limit the number of simultaneous TCP connections from any single IP to a small constant (e.g., 4). Currently the OS-level FD limit is the only ceiling; an IPv4 attacker can open up to the FD limit before being throttled.
4. **Connection-rate cap separate from message rate.** The S-014 rate-limiter caps messages-per-IP but not connections-per-IP. An attacker who opens many connections, sends nothing, and never disconnects bypasses both S-014 (no messages → no rate-limit hits) and S-026 (host alive → no keepalive timeout).

**Severity assessment:** Medium because the slow-loris surface is a real DoS vector against the gossip layer; the S-026 closure alone leaves it open. However: (a) the S-014 rate limiter does partially mitigate (a peer that sends nothing can't amplify, so the resource cost is limited to the FD slot itself), (b) the OS FD limit caps the worst case, and (c) the operational visibility into peer counts gives operators a feedback signal to react to (kill the determ.exe process or restart, or tune the OS-level `tcp_keepalive_time` low enough that the attacker's idle behavior triggers it — though as noted, the attacker's kernel will respond to probes, so this only catches the genuinely-dead case).

**Recommended mitigation:** add an application-layer "no-HELLO-within-30s" reap to `GossipNet::attach`, plus an application-layer "no-message-in-N-minutes" reap (operator-configurable). Effort: ~50 LOC + a regression test. Tracked as a separate operational hardening item; explicitly out of scope for the S-026 closure (which targets the TCP-layer silent-failure case only).

The four findings (F-1 Windows defaults, F-2 cross-platform table, F-3 slow-loris out-of-scope) are advisory. None invalidates T-1 through T-5. They are surfaced for completeness so an external auditor can confirm the scope of the proof's analytic conclusion: the S-026 closure correctly bounds TCP-layer silent-failure peer accumulation, with separate application-layer defenses required to cover the application-layer silent-attacker surface.

---

## 7. Test surface citation

The S-026 closure is fundamentally **kernel-level behavior** — the property under test is that the OS TCP stack correctly delivers an `ETIMEDOUT` error after the configured keepalive parameters elapse. A regression test in the Determ test suite cannot validate this property without either (a) waiting hours for the default-configured keepalive cycle to complete (impractical), (b) injecting a synthetic kernel-level failure via OS-specific test harnesses (non-portable and disproportionate to the closure's complexity), or (c) simulating the failure at the asio layer (which tests the asio integration but not the actual kernel-level keepalive correctness).

Therefore: **no dedicated automated regression test is recommended** for S-026. The closure's correctness is established by:

1. **Source-level audit** (this proof, §3 + §4): the SO_KEEPALIVE flag is set on every Peer; the error-propagation path through `Peer::read_header` / `read_body` / `do_write` to `on_close_` to `handle_peer_closed` to `peers_.erase` is straight-line code with no branches that could bypass it; the kernel-level SO_KEEPALIVE semantic is universally specified (RFC 1122, POSIX, Winsock).

2. **Operational verification via long-running operator scripts.** The existing `tools/operator_fork_watch.sh` (and any future `tools/operator_peer_health.sh`-style script) can be extended to monitor `peer_count()` over multi-hour observation windows, flagging any monotonic growth in `|peers_|` that exceeds the steady-state bound from T-2. An operator running such monitoring on a production node observes the S-026 closure's effect directly: dead peers are reaped within the expected window; the peer count stays in a steady-state range.

3. **Cross-platform reasoning** (this proof, §1.3 + L-2): the per-platform defaults are documented in the OS reference materials cited in §8; the closure's behavior across platforms is uniform up to the per-platform default detection latency.

The deferred-test posture is consistent with the closure's nature: SO_KEEPALIVE is a single setsockopt call whose downstream behavior is governed by the OS, not by Determ code. The Determ-side surface area (one set_option call + one existing on_close path) is small enough that the §3 source citation + §4 lemmas constitute the primary correctness argument. The operational-monitoring posture (point 2) provides ongoing assurance that the closure is functioning as designed in production.

A future operator-facing test could be added that explicitly:

1. Spins up two Determ nodes A and B with mutual gossip connections.
2. Configures both with `sysctl -w net.ipv4.tcp_keepalive_time=60 net.ipv4.tcp_keepalive_intvl=10 net.ipv4.tcp_keepalive_probes=3` (Linux-only).
3. Brings down node B's network interface (`ip link set down`).
4. Observes node A's `peer_count()` over the next 5 minutes; asserts it drops by 1 within `60 + 3 × 10 + ε = 90s` of the network drop.

Such a test would be Linux-only and require root for the sysctl + interface manipulation; it is outside the scope of the standard Determ regression suite. Operators with this concern can write it locally; the source citation in §3 makes the expected behavior explicit.

---

## 8. References

### Specifications + standards

- **RFC 1122** (Braden, Oct 1989) — "Requirements for Internet Hosts — Communication Layers." §4.2.3.6 "TCP Keep-Alives" is the canonical specification of the SO_KEEPALIVE probe semantic. Establishes the zero-length probe segment, the timer-driven retransmission model, and the implementation-defined probe interval defaults. The proof's L-6 (no payload exposure) and T-1 (eventual detection) rest on this RFC's definitions.
- **RFC 793** (Postel, Sep 1981) — "Transmission Control Protocol." Defines the TCP socket states (CLOSED, LISTEN, SYN-SENT, ..., TIME_WAIT) and the per-socket timer machinery that the keepalive layer leverages.
- **RFC 5681** (Allman, Paxson, Blanton, Sep 2009) — "TCP Congestion Control." Background for why the keepalive mechanism is conservative by default (the 2h idle threshold reflects the desire to avoid unnecessary network traffic on a long-lived but rarely-active connection).
- **POSIX.1-2008 / IEEE Std 1003.1-2008** §setsockopt — defines `SOL_SOCKET / SO_KEEPALIVE` as the standard POSIX socket option for enabling keepalive on a TCP socket.
- **Microsoft Winsock SOL_SOCKET options reference** — Microsoft's documentation of the Winsock socket-option set, including SO_KEEPALIVE semantics on Windows (which match the POSIX semantic at the application level).

### Network-programming literature

- **Stevens, "TCP/IP Illustrated, Volume 1: The Protocols" (1994 / 2nd ed. 2011 with Fall)** — §23.2 "The Keepalive Option" provides the canonical textbook treatment of SO_KEEPALIVE, including the probe-and-ACK mechanism, the per-platform defaults, and the operational trade-offs. This proof's §1.3 + L-2 reference Stevens's per-platform parameter discussion.
- **Stevens, Rago, "Advanced Programming in the UNIX Environment, 3rd edition" (2013)** — §16.9 "Socket Options" + §16.11 "Asynchronous I/O" cover the setsockopt API and the integration with select/poll/kqueue-style multiplexers that asio dispatches on.
- **Linux tcp(7) manpage** — `man 7 tcp` on any Linux system; the authoritative source for `SO_KEEPALIVE` semantics on Linux and the per-socket override options (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`). Referenced in §1.3 for the per-platform defaults and in F-1 for the operator-tuning surface.

### Windows-specific references

- **Microsoft Knowledge Base "How to modify the TCP/IP keepalive parameters"** (multiple KB articles across Windows versions; representative: KB 140325 for legacy Windows, KB updates for Windows 10/11). Documents the registry-key path and value semantics for Windows-side keepalive tuning. Referenced in F-1's operator-tuning guidance.
- **Microsoft Winsock SIO_KEEPALIVE_VALS reference** — covers the per-socket override of keepalive parameters via the `WSAIoctl` API (the Windows-side equivalent to Linux's `TCP_KEEPIDLE` / `TCP_KEEPINTVL` per-socket options). Referenced in §1.3's discussion of why per-socket override is not used.

### Determ-internal references

- `src/net/peer.cpp:8-38` — `Peer::Peer` constructor with SO_KEEPALIVE setsockopt (the proof's primary object).
- `src/net/peer.cpp:50-69` — `Peer::read_header` (the read-side on_close trigger path).
- `src/net/peer.cpp:72-105` — `Peer::read_body` (the second read-side on_close trigger path).
- `src/net/peer.cpp:131-143` — `Peer::do_write` (the write-side on_close trigger path).
- `src/net/peer.cpp:40-42, 145-149` — `Peer::~Peer` + `Peer::close` (the destruction path that returns the FD to the OS).
- `src/net/peer.cpp:151-167` — `async_connect` (the second Peer construction site).
- `src/net/gossip.cpp:37-48` — `GossipNet::accept_loop` (the first Peer construction site).
- `src/net/gossip.cpp:74-82` — `GossipNet::attach` (the registration of the on_close handler).
- `src/net/gossip.cpp:320-327` — `GossipNet::handle_peer_closed` (the sole peer-removal site; the `peers_.erase` target of the on_close chain).
- `include/determ/net/peer.hpp:14-68` — `Peer` class declaration.
- `include/determ/net/gossip.hpp` — `GossipNet` class declaration including `peers_` and `peers_mutex_`.

### Cross-references to companion proofs

- `docs/proofs/Preliminaries.md` §3 (network model, partial synchrony assumption) — establishes the messaging timing model that bounds legitimate inter-message gaps below typical keepalive thresholds.
- `docs/proofs/S014RateLimiterSoundness.md` (S-014 closure) — companion proof; T-1 (per-IP token-bucket bound) is the composition witness used in T-4 here. The two closures together cover the gossip-layer rate and lifetime dimensions.
- `docs/proofs/S022WireFormatCaps.md` (S-022 closure) — companion proof; the per-MsgType body cap bounds the per-message work on a recovered-from-keepalive-cycle peer (the post-reconnect path runs the same `Peer::read_body` cap-check).
- `docs/proofs/S031ConcurrencyComposition.md` — the gossip-out-of-lock concurrency analysis; the asio io_context worker-pool model underlying `Peer::read_header` / `read_body` / `do_write` continuation chains that the on_close path dispatches off of. Cross-references this proof for the keepalive-induced reap path.
- `docs/proofs/S013PerSignerCap.md` — sibling Track-A localized-closure proof; the structural-additivity proof style (a single new gate at a specific call site that composes cleanly with existing defenses) is mirrored here.
- `docs/proofs/S028AnonAddressNormalization.md` — sibling Track-A localized-closure proof for normalization style; mirrors the "one defensive gate, multiple call sites must respect it" pattern this proof formalizes for the Peer constructor.
- `docs/proofs/RpcAuthHmacSoundness.md` (S-001 closure) — companion proof for the RPC-layer authentication-and-rate-limit ordering; the analogous closure on the RPC surface to S-026 / S-014's gossip surface.

### Documentation references

- `docs/SECURITY.md` §S-026 — closure-status narrative this proof formalizes.
- `docs/SECURITY.md` §2 row 96 — S-026 audit table entry (✅ Mitigated, with implementation cited as `net/peer.cpp::Peer::Peer`).
- `docs/CLI-REFERENCE.md` §"Gossip security (S-014 / S-022 / S-026)" — operator-facing reference noting that S-026 is unconditional with no operator knob (system-level tuning is via OS sysctl/registry per F-1).

---

## 9. Status

**Shipped.** S-026 is recorded in `docs/SECURITY.md` §S-026 as ✅ Mitigated (Low/Op → Mitigated in-session, per the §1 summary table that includes S-026 alongside S-021, S-022, S-024, S-027, S-028, S-029, S-037 — 8 total Mitigated Low/Op). The closure was committed as `5bb2589 S-026 closure: TCP keepalive on every peer socket`.

Implementation surfaces:

- `src/net/peer.cpp:8-38` — `Peer::Peer` constructor with SO_KEEPALIVE setsockopt (the proof's primary object).
- `src/net/gossip.cpp:74-82` — `GossipNet::attach` registering `handle_peer_closed` as the close handler.
- `src/net/gossip.cpp:320-327` — `GossipNet::handle_peer_closed` performing the atomic `peers_.erase` under `peers_mutex_`.
- `docs/SECURITY.md` §S-026 — closure-status narrative.
- `docs/SECURITY.md` §2 row 96 — audit table entry.
- `docs/CLI-REFERENCE.md` §"Gossip security (S-014 / S-022 / S-026)" — operator-facing reference.

The closure is **strictly minimal** (one setsockopt call in the Peer constructor + reuse of the existing on_close path), preserves wire-format compatibility (no new MsgType, no new fields, no new validator predicate, no new apply branch), and depends only on existing primitives (asio socket options + asio async_read error propagation + `peers_mutex_`-guarded vector removal). T-4's composition with S-014 is structural: S-026 bounds peer-slot lifetime; S-014 bounds per-IP message rate; the two compose without coordination across orthogonal dimensions.

**Not yet shipped (chip task candidates):**

- **F-1 documentation** (Windows tuning guidance in `docs/CLI-REFERENCE.md`). Effort: ~10 lines of doc.
- **F-2 documentation** (cross-platform behavior table in `docs/CLI-REFERENCE.md` or `docs/SECURITY.md` §S-026). Effort: ~15 lines of doc.
- **F-3 mitigation** (application-layer HELLO timeout + per-peer activity timeout in `GossipNet::attach`). Effort: ~50 LOC + regression test. This addresses the slow-loris surface that S-026 explicitly does not cover.
- **Operator-facing peer-health monitoring** (extend `tools/operator_fork_watch.sh` or create `tools/operator_peer_health.sh` to surface peer-count trends over multi-hour windows). Effort: ~30 LOC of shell + a help/doc entry.

These are advisory for operational maturity; the closure itself (the two-line setsockopt + on_close reuse) is shipped and correct per the §4 lemmas and §5 theorems.
