# S022WireFormatCaps — per-message-type body-cap soundness (S-022 closure)

This document formalizes the S-022 closure shipped in `src/net/peer.cpp::read_body` and `include/determ/net/messages.hpp::max_message_bytes` (the per-message-type body-size cap and its single call-site enforcement). The pre-S-022 surface admitted bodies up to `kMaxFrameBytes` (16 MB) for **every** `MsgType`, which meant a flooder could send 16 MB CONTRIB or BLOCK_SIG frames at the framing-layer ceiling — even though the legitimate maximum for a CONTRIB envelope is well under 64 KB and a BLOCK_SIG is a fixed-shape ~200-byte struct. S-022 tightens this by interposing a second, type-aware cap **after** `Message::deserialize` returns: the framing layer reads at most 16 MB, the deserialize-time check then enforces `max_message_bytes(msg.type)` (1 MB for consensus chatter, 4 MB for blocks / headers / bundles, 16 MB only for `SNAPSHOT_RESPONSE` / `CHAIN_RESPONSE`), and a violation closes the connection (same disposition the framing-layer overflow path applies).

> **⚠ READ FIRST — round-12 revision (hostile-wire audit wf_c277c6d1).** Three load-bearing claims in this document were **false** and are corrected in place: §2.2's "`Message::deserialize` returns `msg.type` cheaply", §2.4's *Defended* verdict on the sustained 16-MB-padded CONTRIB flood, and a citation to an "asio accept-loop concurrency cap" that does not exist in this tree. The root cause is a single pattern — **every guard was correct but sat downstream of the cost it bounded** — which T-1..T-5 are structurally unable to detect, because they reason about *whether* a guard fires and never about *what has already been spent* when it does. **T-6** is the added theorem that covers pre-dispatch work. Two gaps remain open and owner-gated: **F-6** (in-ceiling DOM residual) and **F-7** (no inbound-connection cap). See §8 for the full revision record.

The proof is short and structural — there are no cryptographic assumptions; this is a pure length-bound argument. T-1 establishes completeness of the `max_message_bytes` mapping (every MsgType is bounded, with a tight 1 MB default branch absorbing future variants). T-2 establishes that the framing-layer ceiling (`kMaxFrameBytes`) acts as the outer defense before any type byte is interpreted. T-3 isolates the post-deserialize defense-in-depth posture: caps fire after framing succeeds but before `on_msg_` dispatch, so a deserialize that "leniently" accepts a padded body still cannot deliver an oversize payload to the message handler. T-4 covers the connection-close disposition: a violation triggers `Peer::close()` via the existing `on_close_` callback, not a silent drop — so a sustained flooder pays a TCP-reconnect cost on every oversize attempt. T-5 establishes the multiplicative composition with the S-014 rate limiter: bounded per-message work × bounded per-connection rate = bounded per-connection bandwidth. **T-6** (added round 12) covers the property the other five miss: that pre-dispatch work is bounded by a guard running *before* the parser allocates, on both wire formats and independently of any attacker-chosen field. T-1..T-4 are statements about *whether* a guard fires; T-5's parse term silently assumed the answer implied a work bound. It did not — see the READ FIRST note above.

**Companion documents:** `Preliminaries.md` §3 (network model) for the `Peer` framing-layer assumption underlying T-2; `S014RateLimiterSoundness.md` (S-014 closure) for the rate-limit composition theorem T-5 references; `S014ConcurrencyAnalysis.md` for the event-loop concurrency model that the per-connection `Peer::read_header` → `Peer::read_body` chain runs on (note: that model is now the native IOCP / epoll `net::` seam — **ASIO is deleted from this tree**, so any "asio" wording carried over from the original draft refers to the pre-minix-§7 backend and should be read as the `EventLoop` worker pool); `S006ContribMsgEquivocation.md` for the structural-additivity proof style mirrored here; `S030-D2-Analysis.md` for the state-divergence threat model that S-022 helps mitigate by bounding per-block work; `docs/SECURITY.md` §S-022 (quick-fix summary in §6.5) for the closure-status narrative this proof formalizes.

---

## 1. Theorem statements

**Setup.** Let `kMaxFrameBytes` denote the framing-layer ceiling (`include/determ/net/messages.hpp:101`):

```cpp
inline constexpr size_t kMaxFrameBytes = 16 * 1024 * 1024;   // 16 MB
```

Let `max_message_bytes : MsgType → size_t` denote the per-MsgType body-cap function defined at `include/determ/net/messages.hpp:124-152`. The function is a `switch` over the `MsgType` enum (values 0-18 at `include/determ/net/messages.hpp:13-82`) with three returnable values:

- **16 MB** for `MsgType::SNAPSHOT_RESPONSE` (16) and `MsgType::CHAIN_RESPONSE` (6).
- **4 MB** for `MsgType::BLOCK` (1), `MsgType::BEACON_HEADER` (12), `MsgType::SHARD_TIP` (13), `MsgType::CROSS_SHARD_RECEIPT_BUNDLE` (14), `MsgType::HEADERS_RESPONSE` (18).
- **1 MB** (default branch) for every other variant: `HELLO`, `TRANSACTION`, `BLOCK_SIG`, `CONTRIB`, `GET_CHAIN`, `STATUS_REQUEST`, `STATUS_RESPONSE`, `ABORT_CLAIM`, `ABORT_EVENT`, `EQUIVOCATION_EVIDENCE`, `SNAPSHOT_REQUEST`, `HEADERS_REQUEST`.

The default branch is **tight** (1 MB) by deliberate design — any new MsgType added without explicit categorisation inherits the strict cap rather than the permissive 16 MB ceiling. The `include/determ/net/messages.hpp:145-150` comment names this explicitly:

> Default branch keeps the cap tight even if new MsgType variants get added without explicit categorisation — better to be too strict and catch a regression in review than to let a new unbounded type slip through unchecked.

The peer read loop is at `src/net/peer.cpp::read_header` + `Peer::read_body`. After a 4-byte big-endian length header is read at lines 58-67, `read_header` applies the framing-layer guard:

```cpp
if (len == 0 || len > kMaxFrameBytes) {
    if (self->on_close_) self->on_close_(self);
    return;
}
```

then calls `read_body(len)` which reads `len` bytes into `body_buf_`, deserializes the body via `Message::deserialize` (a format-detecting JSON / binary dispatch at `messages.hpp:170` / `binary_codec.cpp`), and immediately applies the per-type cap at `src/net/peer.cpp:90-97`:

```cpp
if (self->body_buf_.size() > max_message_bytes(msg.type)) {
    std::cerr << "[peer] oversize message from " << self->address_
              << " type=" << static_cast<int>(msg.type)
              << " size=" << self->body_buf_.size()
              << " cap=" << max_message_bytes(msg.type) << "\n";
    if (self->on_close_) self->on_close_(self);
    return;
}
if (self->on_msg_) self->on_msg_(self, msg);
```

Let `M = (type, payload)` denote a `Message` (struct at `include/determ/net/messages.hpp:154-171`). Let `|body(M)|` denote the body-buffer length on the wire (the 4-byte-header-stripped payload, as observed at `Peer::read_body`'s `body_buf_.size()`).

**Theorem T-1 (Body-Cap Enforcement Completeness).** For every `MsgType m`, `max_message_bytes(m)` returns a finite size. The mapping is exhaustive across the 19 declared variants (`HELLO` = 0 .. `HEADERS_RESPONSE` = 18) plus the default branch, with three monotone tiers:

$$
\texttt{max\_message\_bytes}(m) \in \{2^{20},\; 2^{22},\; 2^{24}\} \;=\; \{1\ \text{MB},\; 4\ \text{MB},\; 16\ \text{MB}\}
\quad \text{for every}\ m \in \texttt{MsgType}.
$$

The default branch returns the tightest tier (1 MB), so any future `MsgType` variant added without explicit categorisation inherits the 1-MB cap. No `MsgType` value can produce an unbounded result.

**Theorem T-2 (Framing-Layer Outer Ceiling).** Any TCP read whose 4-byte length header decodes to a value `len > kMaxFrameBytes` is aborted at `Peer::read_header` (line 64) before `read_body` is invoked. The receiver therefore never allocates `body_buf_.resize(len)` for any `len > 16 MB`. Furthermore: the framing-layer abort fires before the type byte is read from the body, so an attacker cannot pre-allocate gigabyte buffers via a malformed framing header that lies about the message type.

**Theorem T-3 (Post-Deserialize Defense-in-Depth).** For every body successfully read by `Peer::read_body`, the per-type cap is applied **after** `Message::deserialize` returns the `Message` value but **before** `on_msg_` is invoked. Specifically:

- If `body_buf_.size() > max_message_bytes(msg.type)`, the message is **never delivered** to the dispatch layer (`on_msg_(self, msg)` is not called).
- The cap is enforced at the framing boundary regardless of `Message::deserialize`'s internal leniency on padding, trailing bytes, or duplicate keys. Even a deserialize that "leniently" accepts more bytes than the canonical wire form requires cannot defeat the cap, because the gate compares `body_buf_.size()` (the wire-read length) rather than any post-deserialize measure of the value.
- The post-deserialize position is **deliberate**: the cap needs `msg.type` to choose the per-type ceiling, and `msg.type` is only available after `Message::deserialize` parses the type byte from the body.

  **⚠ CORRECTED.** This bullet previously added: *"The type byte cannot be peeked at before deserialize because the binary envelope's magic prefix at `binary_codec.cpp` is not bit-equivalent across the JSON and binary paths."* **That was false for the binary path** — the binary envelope carries its type in the clear at body offset 2, and `b982332` now peeks exactly there. It remains true for the JSON path only. Two further consequences, neither visible to T-3 as originally stated:
  - Peeking the type does **not** make the cap sound on its own, because offset 2 is attacker-chosen (§2.3 fact 2). A hostile frame simply claims a 16 MB type.
  - T-3 reasons only about *whether* the cap gates dispatch. It says nothing about *what has already been spent* when the cap fires — which is where the 51.9× amplification lived. **T-3 as stated is true and was never violated; it was simply not a statement about resource consumption.** T-6 below is the theorem that covers the missing property.

The cap is therefore the **first** defense that knows the type and the **last** defense before dispatch — a defense-in-depth posture that closes the per-type gap without requiring a redesign of either the framing layer or the codec. It is **not** a bound on pre-dispatch work; that is T-6's job.

**Theorem T-4 (Connection-Close on Cap Violation).** A cap violation triggers `Peer::close()` via the existing `on_close_` callback chain (`src/net/peer.cpp:95`), not a silent message drop. Specifically:

1. The oversize-message branch invokes `if (self->on_close_) self->on_close_(self)` at line 95 — the same handler that fires on framing-layer overflow (line 65) and on TCP-level read errors (lines 54-56).
2. `on_close_` is the standard `GossipNet`-supplied closure-callback that removes the peer from the `peers_` map (`src/net/gossip.cpp`) and shuts down the socket via `Peer::~Peer` → `Peer::close`.
3. The `return` at line 96 prevents the read-loop from re-entering `read_header` — so no further messages from the offending peer are processed on the same connection.

A malicious peer flooding with oversize messages therefore incurs a per-message TCP-reconnect cost (a new SYN handshake + the gossip-layer attach + the HELLO exchange) **before** they can attempt another oversize frame. The amplification factor for the attacker's per-byte work is reduced from `O(1)` (per-message dispatch + parse cost) to `O(connection_setup_latency)` per attempted oversize frame.

**Theorem T-5 (Composition with S-014 Rate Limiter).** Let `W_msg` denote the maximum per-message work the gossip/RPC dispatch path performs on a single accepted message of `MsgType m`. Then:

$$
W_{\text{msg}}(m) \;\leq\; W_{\text{parse}}(\texttt{max\_message\_bytes}(m)) + W_{\text{dispatch}}(\texttt{max\_message\_bytes}(m)),
$$

where `W_parse` and `W_dispatch` are monotone non-decreasing in body size. Therefore `W_msg(m) ≤ W_msg(\text{16 MB cap})` uniformly, with the type-aware tightening reducing the bound by 4× (for the 4-MB tier) or 16× (for the 1-MB tier) over the framing-layer ceiling alone.

Compositing with the S-014 rate-limiter's per-IP token-bucket bound `A_k([t, t+Δ]) ≤ ⌊C + r·Δ⌋` (`S014RateLimiterSoundness.md` T-1):

$$
\text{Bandwidth}_{k}([t, t+\Delta]) \;\leq\; A_k([t, t+\Delta]) \cdot \max_{m \in \texttt{MsgType}} W_{\text{msg}}(m)
\;\leq\; \lfloor C + r \cdot \Delta \rfloor \cdot W_{\text{msg}}(\text{16 MB cap}).
$$

For consensus-chatter-only traffic (the common adversary's preferred attack vector — CONTRIB / BLOCK_SIG / ABORT_CLAIM flood), the bound tightens to:

$$
\text{Bandwidth}_{k}^{\text{chatter}}([t, t+\Delta]) \;\leq\; \lfloor C + r \cdot \Delta \rfloor \cdot 2^{20}\ \text{bytes}
\;=\; \lfloor C + r \cdot \Delta \rfloor \cdot 1\ \text{MB}.
$$

S-022 reduces the adversary's bandwidth ceiling by 16× on the consensus-chatter surface — the surface where rate-limit + per-message work composition matters most for liveness — and S-014 separately limits the per-IP message count. The two defenses **compose multiplicatively**: removing either one leaves the other intact, but operating both together strictly dominates either alone.

> **⚠ SCOPE CORRECTION on T-5.** As originally written, T-5 substituted `max_message_bytes(m)` for the body size in `W_parse` and treated the result as *the* per-message work bound. That substitution is only valid if the cap fires **before** the work it bounds. It does not: the cap is keyed on `msg.type`, which is unavailable until after the parse (§2.3). The honest pre-WIRE-2 statement of T-5 is therefore
> $$W_{\text{msg}} \;\leq\; W_{\text{parse}}(\texttt{kMaxFrameBytes}) + W_{\text{dispatch}}(\texttt{max\_message\_bytes}(m)),$$
> i.e. the **parse** term was bounded by the 16 MB framing ceiling for *every* type, not by the type's own cap — and `W_parse` is not linear in body size (the DOM expansion is ~52× at the pathological extreme), so even that bound was far looser than the arithmetic above implies. T-5's *conclusion* about the dispatch term and the S-014 composition stands; its parse term did not, and T-6 is what restores it.
>
> **Corrected form.** With WIRE-2 in place, `W_parse` is bounded by the structural ceiling rather than by the byte ceiling alone, uniformly across both wire formats and independently of the attacker-chosen type. T-5's multiplicative composition with S-014 is then sound as stated, with `W_parse` read as the WIRE-2-bounded quantity.

**Theorem T-6 (Pre-dispatch work is bounded before the parser allocates).** For every body admitted by `Peer::read_header`, on **both** wire formats, the work performed before `on_msg_` dispatch is bounded by a quantity that does **not** depend on any attacker-chosen field, and the bound is enforced by a guard that runs **before** `nlohmann::json::parse` is invoked:

1. **JSON envelope.** `Message::deserialize` calls `json_structural_precheck(data, len)` before `json::parse`. The scan is allocation-free, single-pass, and aborts at the first byte that exceeds `kMaxJsonDepth` or `kMaxJsonNodes` — so a body whose structure exceeds either ceiling costs only the prefix scanned, never a parse.
2. **Binary envelope.** `decode_binary` calls `json_structural_precheck(body + 4, plen)` before its payload `json::parse`, closing the path a hostile frame reaches by claiming a 16 MB type at offset 2.
3. **Parse failure terminates the connection.** Any exception from either path propagates to `Peer::read_body`'s `catch`, which invokes `on_close_` and returns without re-arming — so the cost of a rejected frame is paid at most once per connection (WIRE-3).

Consequently the resulting DOM is bounded by `O(kMaxJsonNodes)` nodes at depth `≤ kMaxJsonDepth` regardless of `msg.type`, and the per-connection repeat rate of a rejected frame is bounded by the TCP reconnect cost rather than by zero. **Residual:** T-6 bounds the DOM, not the *ratio* of DOM to input; a 16 MB frame within the ceilings still reaches a measured 482 MB (25.5×), or 525 MB (41.4×) including the `payload` deep copy — versus 130 MB (8.1×) for the densest legitimate message. Eliminating that residual requires a protocol decision — see F-6 and the measured table in §2.3.

---

## 2. Background

### 2.1 Pre-S-022 gap

Prior to S-022, the `Peer::read_body` path admitted any body up to `kMaxFrameBytes` (16 MB) for any `MsgType`. The original framing-layer cap was set at 16 MB because **some** MsgType — specifically `SNAPSHOT_RESPONSE` and `CHAIN_RESPONSE` — legitimately needs that ceiling for bootstrap state transfer. But the cap was applied uniformly: a flooder could send a 16-MB-padded `MsgType::CONTRIB` envelope and the receiver would:

1. Allocate the full 16 MB into `body_buf_`.
2. Run `Message::deserialize` over the 16 MB payload (`O(|payload|)` JSON parse, ~1 GB/s typical → ~16 ms per message).
3. Dispatch the parsed `ContribMsg` to `Node::on_contrib`, which would run the F2 / S-006 commitment-recompute path (~16 µs per nominal contrib).

The per-message work asymmetry is the attack surface: legitimate CONTRIBs are <64 KB and consume <100 µs of receiver CPU; an adversarial 16-MB-padded CONTRIB consumes 16 ms (160× legitimate work) — and the adversary's send cost is essentially free (one TCP send of mostly-zero bytes, low latency on a single connection). With a single attacker producing 60 messages/sec at 16 MB each, the receiver burns ~960 ms/sec of CPU on parse alone, **per-IP**. Multiple coordinating IPs amplify linearly.

The audit row in `docs/SECURITY.md` §2 names this directly:

> S-022 16 MB message limit too permissive — but snapshots use it

The "but snapshots use it" caveat is the design wrinkle: a naive fix that simply lowers `kMaxFrameBytes` would break bootstrap-via-snapshot. The S-022 closure threads this needle by keeping the framing-layer ceiling at 16 MB (so SNAPSHOT_RESPONSE / CHAIN_RESPONSE work) and adding a second, type-aware cap that fires only after the type byte is known.

### 2.2 S-022 design rationale: two-tier framing

Three structural facts make the two-tier design clean:

- **The type byte is in the body, not the framing header.** The wire format at `binary_codec.cpp` puts the magic bytes + type byte at the start of the body; the 4-byte framing-layer length header carries no type information. So any decision keyed on `MsgType` must happen **after** the body is read into `body_buf_`. The framing layer can only enforce an outer ceiling (`kMaxFrameBytes`) that applies uniformly to every type.

- **⚠ CORRECTED — `Message::deserialize` does NOT return `msg.type` cheaply.** This bullet previously read: *"Both paths return `msg.type` within `O(min(|body|, header_size))` work — well before the full payload is parsed."* **That premise was FALSE, and it was load-bearing for T-5.** The round-12 hostile-wire audit (wf_c277c6d1) measured the actual cost:

  - **Binary path (pre-`b982332`):** the type sits in the clear at body offset 2, but nothing *used* it before `decode_binary` ran — which reaches `nlohmann::json::parse` over the whole length-prefixed payload. `b982332` added the pre-decode per-type cap that this bullet had assumed all along.
  - **JSON path:** the type lives *inside* the document (`{"type":N,...}`), so it is unreadable until the parse completes. `O(min(|body|, header_size))` is not achievable here at all; the cost is `O(|body|)` plus the DOM the parse materialises.
  - **Measured amplification:** a 16 MB body of `'['` drives **~831 MB peak heap (51.9×), 33.5M allocations and ~4.3-4.8 s wall on ONE pre-auth connection**. A *balanced* 16 MB `{"type":4,"payload":[[[…]]]}` envelope parses **successfully** (409 MB, ~2.2 s) and is only *then* rejected by the per-type cap. The cap bought nothing on that path — the work it was meant to bound had already been done.

  The correct statement is: **the per-type cap is keyed on a quantity that is not available until after the expensive work.** That is why bounding the input length is insufficient on its own and why the WIRE-2 structural ceiling (§2.3) was added — it is the only guard in this chain that runs *before* the parser allocates.

- **The default branch is the right place to put the tight ceiling.** A new MsgType variant added without explicit categorisation (a common slip during development) would inherit whatever the `switch` default returns. The S-022 closure deliberately makes the default branch tight (1 MB) — so a regression is louder (a legitimate new large-payload type would visibly fail in QA with the strict default, prompting the developer to add an explicit case) rather than silent (a new large-payload type would silently consume up to 16 MB and only surface as an operational anomaly).

The closure is therefore additive at two sites (one `switch` in `messages.hpp::max_message_bytes` + one if-statement in `peer.cpp::read_body`) and uses zero new types, no new validator predicates, and no new apply branches. The price: ~50 LOC at the type-cap table + ~10 LOC at the read-body site.

### 2.3 WIRE-2: the structural ceiling (what the byte caps cannot do)

A byte cap bounds the **input**; it does not bound the **DOM the parser builds from that input**. `nlohmann` materialises roughly one 16-byte node per value plus a container allocation per array/object, so a body composed entirely of structural bytes expands by a large constant factor — measured at 51.9× above. Three facts make the byte caps structurally unable to close this:

1. **The JSON path's byte ceiling cannot be tightened below `kMaxFrameBytes`.** Its type is only readable *after* the parse, so the ceiling must be the maximum over all types. And it cannot be argued away by declaring the 16 MB types binary-only: `Peer::send` (`src/net/peer.cpp:103`) selects the JSON encoding whenever the peer's negotiated `wire_version` is `0`, which is the **default** (`peer.hpp:64`) until a HELLO is processed (`gossip.cpp:190`). `Node::on_snapshot_request` (`node.cpp:2317`) and `Node::on_get_chain` (`node.cpp:3102`) both reply through that same `peer->send`, and `peer_message_allowed` returns `true` unconditionally for the snapshot types while the role filter is skipped entirely for peers that have not sent HELLO (`gossip.cpp:115`). **SNAPSHOT_RESPONSE and CHAIN_RESPONSE therefore legitimately arrive as JSON envelopes at the 16 MB ceiling.** Option (ii) of the audit's decision — capping the JSON path at the 1 MB chatter ceiling — is **refuted by the send paths**.

2. **The binary path's per-type cap is keyed on an attacker-chosen field.** `b982332` reads the type from body offset 2 and applies `max_message_bytes` before decoding. But offset 2 is *attacker-controlled*: a hostile frame claiming `SNAPSHOT_RESPONSE` (16) or `CHAIN_RESPONSE` (6) buys the full 16 MB ceiling and lands in `decode_binary`'s payload parse with the amplification intact. WIRE-1 **narrowed** the vector to the two 16 MB types; it did not remove it.

3. **Nothing upstream meters the cost.** `GossipNet::accept_loop` (`src/net/gossip.cpp:46-57`) accepts unconditionally with no inbound-connection cap, and the S-014 per-IP token bucket (`gossip.cpp:163`) lives in `handle_message` — the `on_msg_` callback invoked at `peer.cpp:88`, strictly **downstream** of both the parse and the cap. It meters none of this.

The WIRE-2 ceiling (`kMaxJsonDepth = 64`, `kMaxJsonNodes = 4000000`, `include/determ/net/messages.hpp`) therefore bounds the DOM directly, in a single allocation-free pass over the raw bytes, applied **before** the parser runs on **both** wire formats (`Message::deserialize`'s JSON branch and `decode_binary`'s payload parse). Sizing, soundness and the residual are stated in the header commentary; the two facts that matter here:

- **It aborts at the offending byte.** The 16 MB `'['` flood is rejected after reading 65 bytes.
- **The depth ceiling exists to prevent a CRASH, not a heap spike.** This is worth stating precisely, because the obvious reading — "the node ceiling already stops a `'['` flood at 4M, so depth is redundant" — is true about heap and **wrong about safety**. Measured: nlohmann 3.11.3 parses iteratively and its destructor is stack-safe, so a depth-3,900,000 document parses *and destroys* cleanly while consuming only 3.9M nodes — i.e. the node ceiling alone **would have admitted it**. But `serializer::dump()` recurses, and `Message::serialize()` calls `envelope.dump()`, so a node that accepted such a document and re-emitted it dies of stack exhaustion on the **send** path. Measured on an 8 MB stack (g++ -O2): depth 50,000 dumps fine, depth 200,000 **segfaults**. `kMaxJsonDepth = 64` sits ~1000× below that threshold and 8× above the deepest legitimate document. ⚠ Do not relax it on redundancy grounds.
- **It removes the UNBOUNDED cases, not the constant factor.** ⚠ An earlier revision of this section claimed the in-ceiling residual was "of order 100 MB (≈6-8×)". **That was measurably wrong** — it rested on a "~16 bytes per value" DOM model that ignores `object_t = std::map`, where each `{` costs a map allocation plus a red-black-tree node per entry (~144 B for a single-entry object). Measured on the shipped ceilings (g++ -O2, counting global `operator new`):

  | shape | wire | DOM peak | factor |
  |---|---|---|---|
  | flat scalars `[0,0,…]` (the shape gate 8f uses) | 3.8 MB | 48 MB | 12.6× |
  | objects `[{"":0},…]` | 13.4 MB | 276 MB | 20.7× |
  | depth-63 object chain | 18.9 MB | 482 MB | **25.5×** |
  | objects + envelope, incl. the `payload` deep copy | 12.7 MB | 525 MB | **41.4×** |
  | — *legitimate* densest 16 MB snapshot, for calibration | 16.0 MB | 130 MB | 8.1× |

  So the honest statement is: **51.9× → 25.5× (41.4× counting the payload copy), against 8.1× for a legitimate large message.** The ceiling's real value is that it makes the worst case *finite and shape-independent* — it forecloses the 16.7M-container and arbitrary-depth families entirely — not that it reaches 100 MB. Eliminating the remaining factor requires capping the JSON path itself at the chatter ceiling, which per fact (1) is a **protocol decision**. See F-6 in §6.2.

### 2.4 Adversary model

The S-022 closure defends against three adversary families:

1. **Per-connection flood with maximally-padded oversized messages of consensus-chatter types.** One TCP connection, sustained 16-MB-padded `MsgType::CONTRIB` or `MsgType::BLOCK_SIG` frames.

   **⚠ CORRECTED verdict.** This row previously read *"every such frame is rejected at the framing boundary (the size > 1 MB cap check) and the connection is closed … **Defended (T-2 + T-3 + T-4)**"*. **The measurements refute that**, on two counts:

   - **"Rejected at the framing boundary" was wrong about ordering.** The per-type cap runs *after* `Message::deserialize`, so a 16-MB-padded CONTRIB was fully parsed — 831 MB peak heap, ~4.3-4.8 s CPU — and only *then* rejected. Every guard existed and was individually correct; each simply sat downstream of the cost it was supposed to bound. **Check-ordering is its own vulnerability class**, and neither T-3 nor T-4 detects it: both reason about *whether* the cap fires, never about *what has already been spent* when it does.
   - **"Adversary pays a TCP-reconnect cost" was wrong for the parse-error path.** True for the oversize branch, which returns after `on_close_`. But a frame that *fails to deserialize* hit the `catch` branch, which logged and re-armed `read_header()` — no close, so the cost was infinitely repeatable on one connection at zero cost to the sender. Closed as WIRE-3 (`src/net/peer.cpp`); T-4 is extended to cover it below.

   **Current status: MITIGATED, not eliminated (T-2 + T-3 + T-4 + T-6).** The WIRE-2 structural ceiling (§2.3) now aborts the pathological shapes before the parser allocates — the 16 MB `'['` flood dies after 65 bytes — and WIRE-3 closes the connection on any parse failure, restoring the per-attempt reconnect cost. The residual is the in-ceiling DOM — a measured 482 MB (25.5×) from a 16 MB frame, 525 MB (41.4×) with the `payload` copy, rather than 831 MB (51.9×); see F-6 and the table in §2.3.

2. **Multi-IP coordinated flood at the per-IP cap.** N attackers, N distinct IPs, each sending one oversize frame per connection before reconnecting. The per-IP rate-limit bound (T-1 of `S014RateLimiterSoundness.md`) prevents the per-IP burst from exceeding `C + r·Δ`; the per-message body-cap (T-1 + T-2 + T-3 here) further bounds the per-message work by `W_msg(m)`. The composite per-IP bandwidth bound from T-5 above is `(C + r·Δ) · W_msg(m)`. **Partially defended (T-5).** Aggregate-rate limiting across all IPs requires upstream throttling (out of scope for S-022's per-message layer; see `docs/SECURITY.md` §S-014 for the aggregate-rate discussion).

3. **New-MsgType slip-through during development.** A future contributor adds a new `MsgType` variant without explicit categorisation in `max_message_bytes`. Pre-S-022: would have inherited whatever the framing layer permitted (16 MB). Post-S-022: inherits the default branch's 1 MB tight cap, so any new type is bounded by default — explicit categorisation is required to relax (a visible code change in PR review) but never required to **strengthen**. **Defended by design (T-1 default-branch tightness).**

The closure does not address (and is not designed to address) the following:

- Cryptographic-signature-verify cost amplification on accepted (in-cap) messages. A CONTRIB at the 1-MB ceiling still costs the receiver one Ed25519 verify per signed payload, which is `O(1)` (~50 µs typical). S-022 caps the parse cost; the per-signature verify cost is intrinsic and bounded by the consensus protocol's own structural limits (e.g., committee size K).
- Per-connection memory growth across many concurrent connections. **⚠ CORRECTED:** this previously cited "the asio accept-loop concurrency cap". **No such cap exists in this tree.** ASIO was deleted (minix §7 step 4 — the daemon networks on native IOCP / epoll behind the `net::` seam), and its replacement `GossipNet::accept_loop` (`src/net/gossip.cpp:46-57`) accepts **unconditionally**: there is no inbound-connection cap, no per-IP connection limit, and no accept-rate gate. The only bound is the OS-level FD limit. Since `Node` spawns `hardware_concurrency()` event-loop threads, a handful of concurrent hostile frames can occupy them all and stall consensus I/O. **This is an open gap, not a defence** — tracked as F-7. The S-022 layer does not contribute defence here.
- Deserialize-time bugs that crash the receiver before the cap is checked. **⚠ CORRECTED:** this previously stated that a `Message::deserialize` exception "is caught at `peer.cpp:99-102` and merely logged — the connection remains open (the receive loop iterates back to `read_header`)", and called that disposition "structurally orthogonal" to cap enforcement. It was **not** orthogonal: it was the mechanism that made the parse cost above infinitely repeatable, and it contradicted the disposition every neighbouring branch applies. **Closed as WIRE-3** — the catch branch now invokes `on_close_` and returns. See T-6 and F-8. The *validation* content of a malformed message remains governed by S-018 (`JsonValidationSoundness.md`); only the connection disposition changed.

---

## 3. Implementation citation

### 3.1 The per-MsgType cap table

Per `include/determ/net/messages.hpp:124-152`:

```cpp
inline constexpr size_t max_message_bytes(MsgType type) {
    switch (type) {
    case MsgType::SNAPSHOT_RESPONSE:
    case MsgType::CHAIN_RESPONSE:
        return 16 * 1024 * 1024;        // 16 MB

    case MsgType::BLOCK:
    case MsgType::BEACON_HEADER:
    case MsgType::SHARD_TIP:
    case MsgType::CROSS_SHARD_RECEIPT_BUNDLE:
    case MsgType::HEADERS_RESPONSE:
        // 4 MB matches BLOCK because a HEADERS_RESPONSE carries
        // server-capped 256 headers max (rpc_headers's
        // HEADERS_PAGE_MAX), each header is bounded by the same
        // committee + sig + commit structure as a Block minus the
        // heavy collections (transactions / receipts /
        // initial_state). At 256 headers × ~16 KB each ≤ 4 MB.
        return 4  * 1024 * 1024;        // 4 MB

    // Everything else (consensus chatter, requests, status, tx, hello).
    // HEADERS_REQUEST is a tiny {from, count} envelope — same 1 MB
    // default applies. Default branch keeps the cap tight even if
    // new MsgType variants get added without explicit categorisation
    // — better to be too strict and catch a regression in review
    // than to let a new unbounded type slip through unchecked.
    default:
        return 1  * 1024 * 1024;        // 1 MB
    }
}
```

The framing-layer outer ceiling at `include/determ/net/messages.hpp:101`:

```cpp
inline constexpr size_t kMaxFrameBytes = 16 * 1024 * 1024;
```

### 3.2 The Peer::read_header / read_body chain

> **Environment note (doc-consolidation inc.4 drift-repair).** The `asio::async_read` / `asio::buffer` calls quoted below describe the pre-migration transport. `asio` is deleted from the tree; the gossip framing now runs behind the native `net::Transport` seam (IOCP on Windows, epoll on POSIX — see `MinixTacticalProfile.md`). The code walk-through is retained as the finding's original context; the per-`MsgType` body-cap enforcement it analyses lives in the `Peer::read_header`/`read_body` framing logic, not in asio.

The framing-layer guard at `src/net/peer.cpp:50-70`:

```cpp
void Peer::read_header() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(header_buf_),
        [self](std::error_code ec, size_t) {
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            uint32_t len = (static_cast<uint32_t>(self->header_buf_[0]) << 24)
                         | (static_cast<uint32_t>(self->header_buf_[1]) << 16)
                         | (static_cast<uint32_t>(self->header_buf_[2]) << 8)
                         |  static_cast<uint32_t>(self->header_buf_[3]);
            // S-022: framing-layer ceiling (kMaxFrameBytes = 16 MB). The
            // per-message-type cap fires AFTER deserialize in read_body.
            if (len == 0 || len > kMaxFrameBytes) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            self->read_body(len);
        });
}
```

The per-MsgType cap at `src/net/peer.cpp:72-105`:

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
            try {
                auto msg = Message::deserialize(self->body_buf_.data(),
                                                 self->body_buf_.size());
                // S-022: per-message-type cap. The framing layer accepted
                // up to kMaxFrameBytes (16 MB) so the only types with a
                // legitimate need for that ceiling get it; everything else
                // is bounded much tighter here. Oversize messages indicate
                // either a peer-side bug or an active flooding attempt;
                // drop the message and close the connection (same
                // disposition the framing layer applies).
                if (self->body_buf_.size() > max_message_bytes(msg.type)) {
                    std::cerr << "[peer] oversize message from " << self->address_
                              << " type=" << static_cast<int>(msg.type)
                              << " size=" << self->body_buf_.size()
                              << " cap=" << max_message_bytes(msg.type) << "\n";
                    if (self->on_close_) self->on_close_(self);
                    return;
                }
                if (self->on_msg_) self->on_msg_(self, msg);
            } catch (std::exception& e) {
                // WIRE-3: close, do NOT re-arm. (Pre-round-12 this branch
                // logged and fell through to read_header() below.)
                std::cerr << "[peer] message parse error from " << self->address_
                          << ": " << e.what() << " — closing connection\n";
                if (self->on_close_) self->on_close_(self);
                return;
            }
            self->read_header();
        });
}
```

The checks are placed so the read-loop has three distinct rejection paths, **all three of which now close the connection** (pre-WIRE-3 the third one did not, which is what made the parse cost repeatable):

1. **Framing-layer rejection** (`read_header`): `len > kMaxFrameBytes` or `len == 0` → close.
2. **Per-MsgType cap rejection** (`read_body`): `body_buf_.size() > max_message_bytes(msg.type)` → close.
3. **Deserialize-exception rejection** (the `catch` branch): `Message::deserialize` throws → log + **close** (WIRE-3). This includes throws from the WIRE-1 pre-decode cap and the WIRE-2 structural ceiling, so a frame rejected by either is paid for exactly once per connection. **⚠ CORRECTED:** this line previously read *"log + iterate (connection stays open; S-018 territory)"* — that disposition was the amplifier, not a neutral S-018 detail. S-018 still governs *what counts as* malformed; this proof governs what happens to the connection.

### 3.3 The MsgType enum surface

Per `include/determ/net/messages.hpp:13-82`, the full MsgType enum is:

| Value | Name | Body shape | Cap tier |
|:---:|---|---|---|
| 0 | `HELLO` | 5-field JSON: `{domain, port, role, shard_id, wire_version}` | 1 MB (default) |
| 1 | `BLOCK` | Full `chain::Block` JSON | 4 MB |
| 2 | `TRANSACTION` | Single `chain::Transaction` JSON | 1 MB (default) |
| 3 | `BLOCK_SIG` | Fixed-shape `BlockSigMsg` (block_hash + ed_sig + dh_secret + delay_output) | 1 MB (default) |
| 4 | `CONTRIB` | `ContribMsg` (Phase-1 commit + view-roots; ~few KB typical) | 1 MB (default) |
| 5 | `GET_CHAIN` | `{from, count}` envelope | 1 MB (default) |
| 6 | `CHAIN_RESPONSE` | Variable-size historical chain slice | 16 MB |
| 7 | `STATUS_REQUEST` | Empty envelope | 1 MB (default) |
| 8 | `STATUS_RESPONSE` | `{height, genesis}` | 1 MB (default) |
| 9 | `ABORT_CLAIM` | Single `AbortClaimMsg` | 1 MB (default) |
| 10 | `ABORT_EVENT` | Assembled `AbortEvent` with K-1 claims inline | 1 MB (default) |
| 11 | `EQUIVOCATION_EVIDENCE` | Two `(digest, sig)` pairs + signer info | 1 MB (default) |
| 12 | `BEACON_HEADER` | Full `chain::Block` (beacon) JSON | 4 MB |
| 13 | `SHARD_TIP` | `{shard_id, tip}` wrapping a `chain::Block` | 4 MB |
| 14 | `CROSS_SHARD_RECEIPT_BUNDLE` | `{src_shard, src_block}` wrapping full block | 4 MB |
| 15 | `SNAPSHOT_REQUEST` | `{headers: N}` | 1 MB (default) |
| 16 | `SNAPSHOT_RESPONSE` | Serialized chain state (multi-MB at scale) | 16 MB |
| 17 | `HEADERS_REQUEST` | `{from, count}` envelope | 1 MB (default) |
| 18 | `HEADERS_RESPONSE` | Up to 256 stripped-header blocks | 4 MB |

Every MsgType is in one of three tiers; the table is exhaustive on the 19 currently-declared variants. The default branch absorbs any future variant.

---

## 4. Lemmas and proofs

### Lemma L-1 (Total coverage of the MsgType enum)

The `MsgType` enum at `include/determ/net/messages.hpp:13-82` declares 19 variants with values 0 .. 18 (inclusive). The `switch` statement at `messages.hpp:124-152` enumerates:

- 2 explicit cases returning 16 MB: `SNAPSHOT_RESPONSE`, `CHAIN_RESPONSE`.
- 5 explicit cases returning 4 MB: `BLOCK`, `BEACON_HEADER`, `SHARD_TIP`, `CROSS_SHARD_RECEIPT_BUNDLE`, `HEADERS_RESPONSE`.
- 1 default case returning 1 MB.

Every value in the enum range falls into exactly one case (the explicit ones override the default). The C++ language guarantees the `switch` is well-formed: an unhandled value would fall through to `default`. So `max_message_bytes(m)` returns a finite value for every `m ∈ MsgType`, including any future-added variant. □

### Lemma L-2 (Monotone tiering of the cap table)

Examining the three returnable values: `1 MB < 4 MB < 16 MB`. The 16 MB tier is reserved for the two MsgTypes (`SNAPSHOT_RESPONSE`, `CHAIN_RESPONSE`) that carry full-state bootstrap payloads. The 4 MB tier is reserved for the five MsgTypes carrying block-level payloads (where the block-level structural cap `TRANSFER_PAYLOAD_MAX = 128` per tx × max-block tx count + receipts gives a ~2 MB ceiling at typical mainnet density, leaving the 4 MB cap with ~2× headroom). The 1 MB tier covers consensus chatter, requests, and status — every MsgType in this tier has a structural ceiling well under 100 KB at typical density; the 1 MB cap gives ≥10× headroom.

The tiering reflects the **legitimate maximum** per type: the cap is loose enough that no legitimate sender ever hits it, tight enough that an adversary cannot weaponize the per-message size as an amplification vector beyond the per-tier headroom factor. □

### Lemma L-3 (Framing-layer ceiling abort happens before any type-aware work)

Inspect `Peer::read_header` at `src/net/peer.cpp:50-70`. The function:

1. Issues `asio::async_read` to fill the 4-byte `header_buf_`.
2. On completion (no I/O error), decodes the 4 bytes as a big-endian uint32 `len`.
3. **Without consulting the body or the type byte**, checks `len == 0 || len > kMaxFrameBytes`. On hit, invokes `on_close_(self)` and returns.
4. Only on cap-pass does it invoke `read_body(len)`.

Therefore, when the framing-layer cap fires:
- `body_buf_` is **never resized** to `len` bytes. The receiver's RAM commitment for an oversize message stalls at the 4-byte header.
- `Message::deserialize` is **never called**.
- `on_msg_` is **never called**.

Equivalently: the framing-layer abort is **type-blind** — it cannot know which MsgType the body would have advertised — but its outer ceiling (16 MB) is the same as the loosest per-type cap (the SNAPSHOT_RESPONSE / CHAIN_RESPONSE tier), so legitimate large-payload types pass through it. The cap-failure path is fully resource-bounded: the receiver pays only the 4-byte read + the 8-byte length-decode + the comparison. □

### Lemma L-4 (Per-MsgType cap fires after deserialize-succeeded but before on_msg_)

Inspect `Peer::read_body` at `src/net/peer.cpp:72-105`. The function:

1. Issues `asio::async_read` to fill `body_buf_` with `len` bytes.
2. On completion (no I/O error), wraps the body-handler in a `try`/`catch`.
3. Inside the `try`:
   a. Calls `Message::deserialize(body_buf_.data(), body_buf_.size())` → `msg`.
   b. Checks `body_buf_.size() > max_message_bytes(msg.type)`. On hit: logs the violation, invokes `on_close_(self)`, returns (does NOT iterate `read_header` again).
   c. On cap-pass: invokes `on_msg_(self, msg)`.
4. After the `try`/`catch` block: calls `read_header()` to start the next iteration. **⚠ CORRECTED:** this step previously read *"(regardless of whether the body delivered or an exception fired)"*. That parenthetical described the pre-WIRE-3 behaviour and was the defect: an exception re-armed the read loop, so a peer that could not produce a parseable frame was nonetheless handed another one at zero cost. Post-WIRE-3 the `catch` branch invokes `on_close_` and **returns**, so `read_header()` is reached only on the delivered-or-capped path.

Therefore, the per-MsgType cap fires:
- **After** `Message::deserialize` parses out `msg.type` (because the cap key is `msg.type`).
- **Before** `on_msg_` is invoked (because the cap check precedes the dispatch line in source order).

The placement is structurally sound: there is no path from `Message::deserialize` returning a `msg` value to `on_msg_(self, msg)` being invoked that bypasses the cap check, because the two statements are in straight-line code (no conditional, no exception, no goto in between). The dispatch is gated by the cap. □

### Lemma L-5 (Connection-close on cap violation matches framing-layer disposition)

Compare the two cap-failure paths:

| Aspect | Framing-layer overflow (`peer.cpp:64-67`) | Per-MsgType overflow (`peer.cpp:90-97`) |
|---|---|---|
| Trigger | `len == 0 \|\| len > kMaxFrameBytes` after header read | `body_buf_.size() > max_message_bytes(msg.type)` after deserialize |
| Allocation cost | None (body never read) | `body_buf_.resize(len)` already paid + deserialize parse cost |
| Close handler | `if (self->on_close_) self->on_close_(self)` | `if (self->on_close_) self->on_close_(self)` |
| Loop continuation | `return` (no further reads on this Peer) | `return` (no further reads on this Peer) |
| Log line | Silent (no log on framing-layer abort) | `std::cerr << "[peer] oversize message from " << ... ;` |

The two paths share the same close-handler and return disposition; the per-MsgType path additionally pays the body-read + deserialize cost before the cap check (this is unavoidable — the cap needs `msg.type`). The per-MsgType path is also logged (the framing-layer path is silent for historical reasons; see F-3 in §6).

By calling `on_close_` rather than dropping the message and continuing, both paths force the offending peer to incur a TCP-reconnect cost before attempting another oversize frame. The cost is concrete:
- 1 RTT for the new SYN handshake.
- 1 message exchange for HELLO + handshake completion (~few hundred bytes each direction; bounded by the same MsgType cap).
- ~~Per-peer accept-rate gating via the asio accept-loop (`src/net/gossip.cpp` accept handler).~~ **⚠ STRUCK — this gate does not exist.** ASIO is deleted from the tree, and `GossipNet::accept_loop` (`src/net/gossip.cpp:46-57`) accepts unconditionally: no accept-rate gate, no inbound-connection cap, no per-IP connection limit. See F-7.
- For a sustained attacker, the FD limit (`ulimit -n`, typically 1024-1M per process) bounds simultaneous connections. **This is currently the only bound on concurrent inbound connections.**

The connection-close disposition therefore reduces the attacker's per-byte amplification factor by amortizing the reconnect cost over the dropped message. □

### Lemma L-6 (Composition arithmetic with S-014 rate limit)

The S-014 rate-limiter token-bucket theorem (T-1 of `S014RateLimiterSoundness.md`) bounds the number of allowed gossip messages from peer-IP `k` over window `[t, t+Δ]` as `A_k ≤ ⌊C + r·Δ⌋`, with `C := burst_` and `r := rate_per_sec_` (the configured gossip rate-limit). Each message that passes the rate-limit then enters `Peer::read_body` (the framing layer was already enforced upstream — both the framing-layer cap and the rate-limiter run before any per-message work).

Once admitted by the rate-limiter and through the framing-layer cap, the per-message work for an accepted (in-MsgType-cap) message is bounded by:

$$
W_{\text{msg}}(m) \;\leq\; W_{\text{parse}}(\texttt{max\_message\_bytes}(m)) + W_{\text{dispatch}}(\texttt{max\_message\_bytes}(m)),
$$

where both terms are monotone non-decreasing in body size. For consensus-chatter MsgTypes (the 1 MB tier), this is bounded by ~10 ms of total receiver work per message (1 MB parse at ~100 MB/s + dispatch); for the 4 MB tier (BLOCK, etc.) by ~40 ms; for the 16 MB tier (SNAPSHOT) by ~160 ms.

Therefore the per-IP bandwidth ceiling on consensus-chatter floods is:

$$
\text{Bandwidth}_{k}^{\text{chatter}}([t, t+\Delta]) \;\leq\; \lfloor C + r \cdot \Delta \rfloor \cdot 1\ \text{MB}.
$$

For the web-profile defaults (`r_gossip = 500`, `C_gossip = 1000`), a single-IP attacker is bounded to `1000 + 500·Δ` chatter messages per Δ seconds, each ≤ 1 MB — i.e., a sustained 500 MB/sec ceiling per attacker IP for consensus-chatter floods, capped against the receiver's NIC bandwidth and the event-loop worker pool (`hardware_concurrency()` threads; *not* an "asio worker-pool" — ASIO is deleted). The pre-S-022 equivalent was 16× higher (8 GB/sec per IP).

**⚠ SCOPE.** This lemma bounds work for messages that **reach** the rate limiter. It does not bound the parse that happens **before** it: S-014's token bucket lives in `GossipNet::handle_message` — the `on_msg_` callback invoked at `peer.cpp:88` — which is downstream of `Message::deserialize`. Every figure above is therefore a bound on *post-parse* work only. The pre-parse arm is T-6 (WIRE-2), not this lemma. □

### Lemma L-7 (Default-branch tightness preserves invariant under future MsgType additions)

Consider the development scenario where a contributor adds a new MsgType variant `MsgType::NEW_VARIANT = 19` to the enum at `include/determ/net/messages.hpp:13-82`. Two sub-cases:

**Case A: contributor also adds an explicit case to `max_message_bytes`.** The new case overrides the default. The cap is whatever the contributor wrote — they made a deliberate choice (and it appears in PR review as a code change to a security-relevant table). T-1 still holds (the case is exhaustive across the new enum), and the closure remains intact.

**Case B: contributor forgets to update `max_message_bytes`.** The `switch` falls through to `default`, which returns 1 MB. The new MsgType is therefore capped at 1 MB regardless of the contributor's intent.

In Case B, two further sub-cases:

- **Case B.1: the new MsgType has a legitimate maximum below 1 MB.** No regression — the default cap is sufficient.
- **Case B.2: the new MsgType has a legitimate maximum above 1 MB.** QA / regression testing flags the issue (legitimate large payloads from a real sender fail at the cap, surfacing a visible "oversize message" log + connection close). The contributor adds the explicit case in a follow-up.

In neither sub-case does the new MsgType slip through with an unbounded cap. The default-branch tight value of 1 MB is the **safe default**: too strict catches the regression in QA; too loose would silently introduce a 16-MB-per-message amplification surface.

This is the key reason the closure is forward-compatible without operator intervention — every new MsgType inherits the strict ceiling, and the only way to relax it is to deliberately add a case in the security-relevant table. □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Body-Cap Enforcement Completeness).** Direct from L-1 + L-2. By L-1, `max_message_bytes` is total over `MsgType` (every variant produces a finite result). By L-2, the three returnable values are `{1 MB, 4 MB, 16 MB}` — every variant maps to exactly one tier. The default branch returns 1 MB (the tightest tier), so any future variant added without explicit categorisation inherits the strict cap (L-7). The mapping is forward-compatible and complete. ∎

**Proof of T-2 (Framing-Layer Outer Ceiling).** Direct from L-3. The framing-layer guard at `peer.cpp:64` fires **before** the body is read into `body_buf_` and **before** the type byte is consumed. So:

1. `body_buf_.resize(len)` is never invoked for `len > kMaxFrameBytes`. The receiver's RAM commitment is bounded by the 4-byte header (effectively zero).
2. `Message::deserialize` is never invoked. The receiver's CPU commitment is bounded by the comparison.
3. `on_msg_` is never invoked. The dispatch layer is not exercised.

The framing-layer abort is therefore type-blind (cannot reject based on type) and outer-ceiling-only (only bounds size by `kMaxFrameBytes`), but it does so before any type-aware machinery runs, so an attacker cannot use a malformed framing header to pre-allocate gigabyte buffers. ∎

**Proof of T-3 (Post-Deserialize Defense-in-Depth).** Direct from L-4. The per-MsgType cap fires after `Message::deserialize` returns `msg` (so `msg.type` is available) but before `on_msg_(self, msg)` is invoked (the two statements are in straight-line code separated only by the cap check). There is no execution path from a deserialize-succeeded message to the dispatch layer that bypasses the cap check.

The cap is enforced on `body_buf_.size()` — the wire-read length, not any post-deserialize derived quantity. So even a hypothetically lenient `Message::deserialize` that silently accepts padding, duplicate keys, or trailing bytes cannot defeat the cap, because the cap compares the **byte count that came off the socket** rather than any model the deserializer might form of the payload.

The position is uniquely correct: the cap must come after deserialize (to know `msg.type`) and must come before dispatch (to gate `on_msg_`). The S-022 closure places it at exactly the unique well-defined point. ∎

**Proof of T-4 (Connection-Close on Cap Violation).** Direct from L-5. A cap violation invokes `if (self->on_close_) self->on_close_(self)` at `peer.cpp:95`, the same path used by:

1. Framing-layer overflow (line 65).
2. TCP-level read errors (lines 54-56 of `read_header`, lines 76-79 of `read_body`).

The `on_close_` callback is installed by `GossipNet` (or the RPC layer) at peer-attach time; its standard implementation removes the peer from `peers_`, decrements peer counts, and shuts down the socket. The Peer's destructor `~Peer()` additionally calls `close()` which invokes `socket_.shutdown` + `socket_.close`.

The `return` after the `on_close_` call (line 96) prevents the read-loop from iterating back to `read_header` on this Peer. Subsequent messages on the same TCP connection cannot be processed; the OS-level FIN reaches the peer; the peer must establish a new TCP connection (with a full SYN handshake + HELLO + handshake-complete latency) before sending any further messages.

This is strictly stronger than a "drop and continue" disposition: it imposes a per-violation reconnect cost on the attacker (~1 RTT + handshake latency, bounded by OS accept-loop concurrency), reducing the work-per-byte amplification factor. ∎

**Proof of T-5 (Composition with S-014 Rate Limiter).** Direct from L-6 + T-1 of `S014RateLimiterSoundness.md`. The two defenses operate at different layers and are independent:

- **S-014** (`include/determ/net/rate_limiter.hpp`, `src/net/gossip.cpp:154`, `src/rpc/rpc.cpp:172`): per-peer-IP token bucket. Bounds the **count** of accepted messages per IP per window.
- **S-022** (`src/net/peer.cpp:90`, `include/determ/net/messages.hpp::max_message_bytes`): per-MsgType body-size cap. Bounds the **size** of each accepted message by its type.

The composition is multiplicative:

$$
\text{Bandwidth}_{k}([t, t+\Delta]) \;\leq\; \underbrace{\lfloor C + r \cdot \Delta \rfloor}_{\text{S-014 count bound}} \cdot \underbrace{\max_{m} W_{\text{msg}}(m)}_{\text{S-022 per-message work bound}}.
$$

For consensus-chatter-only traffic (the common adversary's preferred vector), this tightens to `(C + r·Δ) · 1 MB`. Pre-S-022, the same expression would have been `(C + r·Δ) · 16 MB` — a 16× bandwidth-ceiling reduction on the consensus chatter surface where rate-limit + per-message work composition matters most.

The two defenses are also operationally orthogonal: disabling the rate limiter (`rate_limiter_.configure(0, 0)`) leaves the per-MsgType cap intact, and vice versa. An operator who tightens one knob does not inadvertently loosen the other. Their composition strictly dominates either alone. ∎

**Proof of T-6 (Pre-dispatch work is bounded before the parser allocates).** By inspection of the three call sites, each of which is a straight-line statement with no branch between it and the parse it guards:

1. `src/net/messages.cpp`, `Message::deserialize` — the JSON branch calls `json_structural_precheck(data, len)` on the line immediately preceding `nlohmann::json::parse(data, data + len)`. The precheck allocates nothing (three scalars of loop state) and `throw`s from inside the scan loop, so control never reaches the parse once a ceiling trips, and the bytes examined are exactly the prefix up to the offending index.
2. `src/net/binary_codec.cpp`, `decode_binary` — calls `json_structural_precheck(body + 4, plen)` immediately before its payload parse. This is the site that matters for the attacker-chosen-type bypass: `m.type` is read from `data[2]` and never gates this call, so a frame claiming a 16 MB type is scanned on exactly the same terms as any other.
3. `src/net/peer.cpp`, `Peer::read_body` — the `catch (std::exception&)` branch invokes `on_close_(self)` and `return`s. Since `read_header()` is reached only by falling off the end of the `try`, no execution path re-arms the read loop after a throw from either precheck (or from the parse itself).

The string-state argument in the `messages.hpp` commentary discharges the no-false-reject obligation: for any input the parser accepts, the scan's depth and node counts are exact, so clauses 1 and 2 cannot reject a document that would otherwise have parsed. Clause 3 then bounds repetition: a connection that emits a frame rejected by clauses 1-2 is closed, so the cost is paid once per TCP connection rather than once per frame.

Each clause is pinned by a gate that reddens when it is removed, verified by targeted mutant (§7): removing clause 1 reddens WIRE-2's JSON legs while the binary leg stays green; removing clause 2 reddens the bypass leg **while WIRE-1 stays green**; removing clause 3 reddens both WIRE-3 legs. ∎

---

## 6. Adversary model + notable findings

### 6.1 Adversary model

The S-022 closure defends against:

**(a) Per-connection oversize flood.** One attacker, one connection, repeated 16-MB-padded MsgType::CONTRIB / BLOCK_SIG frames. **⚠ CORRECTED — previously "Defended (T-2 + T-3 + T-4)"; now MITIGATED (T-2 + T-3 + T-4 + T-6).** The old verdict rested on "rejected at the framing boundary", which was false about ordering: the frame was fully parsed first (measured 831 MB / 4.3-4.8 s) and rejected afterwards. WIRE-2 now bounds the DOM before the parser allocates and WIRE-3 restores the per-attempt reconnect cost; the in-ceiling residual (a measured 25.5×, or 41.4× with the `payload` copy, rather than 51.9×) is F-6. See §2.4 family 1 for the full correction.

**(b) Multi-IP coordinated oversize flood.** N attackers, N connections, each sending oversize frames. **Partially defended (T-5).** Each connection's oversize is rejected per (a); the per-IP rate-limit (S-014) bounds the accepted-message count; the per-MsgType cap (S-022) bounds the per-message work. Aggregate-rate limiting requires upstream throttling.

**(c) New-MsgType slip-through.** A future variant added without explicit `max_message_bytes` entry. **Defended (T-1 default-branch tightness).** Inherits 1 MB cap by default.

**(d) Deserialize-bug exploitation.** A deserialize-time exception (e.g., a malformed JSON or binary envelope). **⚠ CORRECTED — previously "Out of scope for S-022; governed by S-018", on the reasoning that the catch-and-log disposition was "structurally orthogonal" to cap enforcement. It was not orthogonal: it was the amplifier.** Keeping the connection open after a parse failure is precisely what made the pre-parse cost repeatable without limit, so the disposition of a malformed frame is squarely an S-022 concern even though its *validation* content is S-018's. **Closed as WIRE-3** — the catch branch now invokes `on_close_` and returns (T-6 clause 3). `JsonValidationSoundness.md` continues to govern what counts as malformed; this proof governs what happens to the connection when it is.

**(e) Snapshot-cap abuse.** A malicious peer sends a `MsgType::SNAPSHOT_RESPONSE` (or `CHAIN_RESPONSE`) at the 16 MB ceiling. **Documented as F-2 in §6.2 below.** The cap is loose enough to permit legitimate bootstrap state transfers (multi-MB at scale), so a malicious snapshot is bounded only by the framing-layer ceiling. The receiver-side defense is the recipient-trust model: only a node actively bootstrapping requests SNAPSHOT_RESPONSE, and the snapshot's K-of-K signature + state_root must verify against the receiver's beacon view (per `BlockchainStateIntegrity.md` T-3). An unsolicited SNAPSHOT_RESPONSE is dropped at the dispatch layer.

### 6.2 Notable findings

**Finding F-1 (Default-branch sufficiency for current MsgTypes — confirmed by inspection).** The 12 MsgTypes that fall to the default branch (`HELLO`, `TRANSACTION`, `BLOCK_SIG`, `CONTRIB`, `GET_CHAIN`, `STATUS_REQUEST`, `STATUS_RESPONSE`, `ABORT_CLAIM`, `ABORT_EVENT`, `EQUIVOCATION_EVIDENCE`, `SNAPSHOT_REQUEST`, `HEADERS_REQUEST`) all have legitimate maximum payloads well under 1 MB:

| MsgType | Structural maximum | Typical | Headroom at 1 MB |
|---|---|---|---|
| `HELLO` | 5 fields, ~200 bytes | ~150 bytes | ≥5000× |
| `TRANSACTION` | Fixed-shape tx + `payload[128]` | ~500-2000 bytes | ≥500× |
| `BLOCK_SIG` | 4 fields, ~200 bytes (hashes + sig + secret) | ~200 bytes | ≥5000× |
| `CONTRIB` | 7 fields with `tx_hashes[]` list | ~few KB at K=256 | ≥250× |
| `GET_CHAIN` | `{from, count}` | ~50 bytes | ≥20000× |
| `STATUS_REQUEST` | Empty | ~30 bytes | ≥30000× |
| `STATUS_RESPONSE` | `{height, genesis}` | ~100 bytes | ≥10000× |
| `ABORT_CLAIM` | Fixed-shape AbortClaimMsg | ~300 bytes | ≥3000× |
| `ABORT_EVENT` | K-1 claims inline | ~K × 300 bytes | ≥3× (K=1000) |
| `EQUIVOCATION_EVIDENCE` | 2 (digest, sig) pairs + signer | ~300 bytes | ≥3000× |
| `SNAPSHOT_REQUEST` | `{headers: N}` | ~30 bytes | ≥30000× |
| `HEADERS_REQUEST` | `{from, count}` | ~50 bytes | ≥20000× |

Even the worst case (`ABORT_EVENT` at K=1000) leaves 3× headroom. No current MsgType in the default tier comes close to the 1 MB ceiling. The defaults are sound at present and remain sound under any reasonable K growth. **No action required.**

**Finding F-2 (16 MB tier is loose for SNAPSHOT_RESPONSE / CHAIN_RESPONSE — bounded only by framing layer).** A malicious sender can submit a SNAPSHOT_RESPONSE or CHAIN_RESPONSE up to 16 MB without triggering the per-MsgType cap (because those types **need** the 16 MB ceiling for legitimate bootstrap state transfers). The receiver-side defense is structural rather than cap-based:

1. **Recipient-trust gate.** A node only accepts a SNAPSHOT_RESPONSE if it has an outstanding SNAPSHOT_REQUEST in-flight (per the snapshot bootstrap protocol). Unsolicited SNAPSHOT_RESPONSEs are dropped at the dispatch layer (`Node::on_snapshot_response`).
2. **K-of-K signature + state_root verification.** Even an accepted snapshot must verify against the receiver's beacon view (per `BlockchainStateIntegrity.md` T-3): the snapshot tail's `state_root` is recomputed from the apply trail and compared to the snapshot's claimed value. A malicious snapshot with bogus data fails the gate and is rejected.
3. **Rate-limit composition.** The per-IP rate-limit (S-014) caps the count of accepted messages — a flooding attacker cannot sustainably send many 16-MB snapshots before being throttled.

The 16 MB ceiling is therefore loose **by design** (snapshots need it), but the structural defenses around the snapshot path bound the abuse window. **No action required**; this is the operationally intended posture.

A finer cap could be introduced (e.g., 8 MB hard cap on SNAPSHOT_RESPONSE bodies, with operators expected to bootstrap from smaller-state phases of the chain) but this introduces a UX regression for legitimate operators bootstrapping mature chains. The current loose-cap-with-structural-defense posture is the right trade-off.

**Finding F-3 (Asymmetric logging between framing-layer and per-MsgType cap paths).** The framing-layer cap-failure path at `peer.cpp:64-67` is **silent** (no log line is emitted; only `on_close_` fires). The per-MsgType cap-failure path at `peer.cpp:90-97` **does** emit a log line:

```cpp
std::cerr << "[peer] oversize message from " << self->address_
          << " type=" << static_cast<int>(msg.type)
          << " size=" << self->body_buf_.size()
          << " cap=" << max_message_bytes(msg.type) << "\n";
```

The asymmetry is operationally awkward: an operator monitoring for "oversize attack in progress" sees logs from the per-MsgType path but no signal from the framing-layer path. A coordinated attacker who carefully crafts every flooding frame at exactly `kMaxFrameBytes + 1` bytes triggers the framing-layer abort silently — leaving the operator blind to the attack.

**Severity:** Low (operational visibility, not a soundness gap — the abort still fires; just no log).

**Recommended mitigation:** add a parallel `std::cerr` line at `peer.cpp:64-67` mirroring the per-MsgType path. Effort: ~5 LOC. Defense-in-depth; no observed defect in the closure itself.

This is a chip-task candidate (see end of file).

**Finding F-4 (Connection-close on cap violation is eager via async_read continuation, not strictly synchronous).** When the per-MsgType cap fires, the sequence is:

1. `on_close_(self)` is invoked synchronously inside the `read_body` lambda.
2. `return` exits the lambda.
3. **The asio io_context may still have pending writes queued for this Peer** at `Peer::write_queue_` (see `peer.cpp:131-143`).
4. The Peer's destructor (`peer.cpp:40-42`) runs when the last `shared_ptr<Peer>` reference is dropped, which calls `Peer::close()` → `socket_.shutdown` + `socket_.close`.

If there are pending writes in `write_queue_` at the moment of the cap violation, those writes may or may not complete before the socket is shut down — the disposition depends on asio's scheduling. In practice, the OS-level TCP layer will accept the FIN and drop any pending writes that haven't been kernel-bufferred yet.

**Severity:** Very Low (a few bytes of latency between cap-violation detection and full disconnection; no soundness or amplification implication).

**Recommended mitigation:** explicitly drain `write_queue_` before calling `on_close_`. Effort: ~10 LOC. Defense-in-depth; the current behavior is acceptable.

**Finding F-5 (Per-MsgType cap is not configurable by operators).** The cap values (1 MB / 4 MB / 16 MB) are compile-time constants in `messages.hpp::max_message_bytes`. An operator running a chain with unusual parameters (e.g., a tactical deployment with very small K, where ABORT_EVENT's "K-1 claims inline" is unusually small; or a global deployment with very large blocks pushing the BLOCK tier toward 4 MB) cannot tune the caps without rebuilding.

**Severity:** Low (operational flexibility, not a soundness gap).

**Recommended mitigation:** option (a) — surface the caps as `Config` fields with the current compile-time values as defaults, allowing operator override via `config.json`; option (b) — leave compile-time but document the tuning surface in `docs/CLI-REFERENCE.md` so operators forking the codebase know which knob to turn.

The current compile-time-constant posture is acceptable for v1.x; v2.x deployment-profile work may introduce operator-facing knobs as part of the deployment-spec polish.

**Finding F-6 (JSON-path DOM residual — OWNER DECISION, protocol-level).** With WIRE-2 in place, a 16 MB frame within the ceilings still reaches a **measured 482 MB (25.5×)**, or 525 MB (41.4×) counting the `payload` deep copy — down from 831 MB (51.9×) unmitigated, against 130 MB (8.1×) for the densest *legitimate* message (table in §2.3). Eliminating the residual entirely means capping the JSON envelope path at the 1 MB chatter ceiling — which **cannot be done without a protocol decision**, because the two 16 MB types legitimately arrive as JSON. The reachability was established from the send paths, not assumed:

| Step | Citation | Fact |
|---|---|---|
| Default wire version is legacy JSON | `include/determ/net/peer.hpp:64` | `wire_version_{kWireVersionLegacy}` (= 0) |
| Only a received HELLO raises it | `src/net/gossip.cpp:190` | `set_wire_version(min(ours, theirs))` |
| Send picks JSON at version 0 | `src/net/peer.cpp:103` | `if (wire_version_ >= kWireVersionBinary && type != HELLO)` … `else serialize()` |
| …and also on binary-encode failure | `src/net/peer.cpp:105-111` | `catch (...) { bytes = msg.serialize(); }` |
| Snapshot replies go through that send | `src/node/node.cpp:2317` | `peer->send(make_snapshot_response(snap))` |
| Chain replies go through that send | `src/node/node.cpp:3102` | `peer->send({CHAIN_RESPONSE, …})` |
| A request needs no HELLO first | `src/net/gossip.cpp:115` | role filter applies only `if (peer->hello_received())` |
| …and snapshot types are role-agnostic | `src/net/gossip.cpp:131` | `SNAPSHOT_REQUEST/RESPONSE → return true` |

So a peer can connect and immediately send `SNAPSHOT_REQUEST` **without any HELLO**; the reply is serialized as JSON at `wire_version_ == 0` and can legitimately reach 16 MB. Capping the JSON path at 1 MB would break snapshot/chain sync for any `wire_version`-0 peer and inside the pre-HELLO window on every connection.

**Options for the owner:**
- **(A) Accept the residual.** 25.5× (41.4× with the payload copy) on a 16 MB frame, with WIRE-3 making each attempt cost a reconnect. No compatibility impact. *Current posture.*
- **(B) Require HELLO before serving the large types**, then drop `wire_version`-0 support and cap the JSON path at 1 MB. **This is the only option that actually closes it.** Costs legacy-peer compatibility and needs a protocol-version decision.
- **(C) Tighten `kMaxJsonNodes`.** ⚠ **ARITHMETICALLY DEAD — do not pursue.** An earlier revision offered this as "cheap, ~2.5× headroom". Measurement kills it: the densest *legitimate* 16 MB snapshot is 1,597,828 units and already costs **129.9 MB** of DOM. Bounding an attacker to ~130 MB therefore requires a cap at or below the legitimate ceiling — i.e. **no non-false-rejecting value of `kMaxJsonNodes` meaningfully improves the bound.** Charging `:` as an extra unit was also evaluated and rejected: it raises the legitimate snapshot to 2.80M units (headroom 2.5× → 1.4×) while moving the attacker's best only from 276 MB to 195 MB.
- **(D) Drop the `payload` deep copy.** `src/net/messages.cpp` does `m.payload = envelope["payload"]` with `envelope` still alive, which is the difference between the 25.5× and 41.4× rows. `std::move(envelope["payload"])` (or `envelope.at("payload").swap(m.payload)`) is a local, compatibility-free change that removes ~40% of peak. **Cheapest real win available; not taken this round because it is a hot-path edit outside the audited residuals.**

**Severity:** Medium (pre-auth resource amplification, no consensus-safety implication). **Status: OWNER-GATED.** The decision-relevant fact is that (C) is dead and (A) understates the exposure by ~4×, which the pre-measurement version of this table got wrong in both directions.

**Finding F-7 (No inbound-connection cap — the accept loop is unconditional).** `GossipNet::accept_loop` (`src/net/gossip.cpp:46-57`) accepts every inbound connection with no cap, no per-IP connection limit and no accept-rate gate; it re-arms unconditionally. The S-014 token bucket does not help — it is per-message and lives downstream in `handle_message`. Since `Node` spawns `hardware_concurrency()` event-loop threads, a small number of concurrent connections each feeding expensive frames can occupy every loop thread and stall consensus I/O. WIRE-2 reduces the per-frame cost but does not bound the number of concurrent attackers.

This is the gap the old §2.4 text papered over by citing a non-existent "asio accept-loop concurrency cap". **Severity:** Medium. **Status: OPEN, not addressed by S-022.** A per-IP concurrent-connection cap in `accept_loop` is the natural closure and is a chip-task candidate.

**Finding F-8 (WIRE-3 is a live-net behaviour change).** Closing on parse error is fail-closed hardening: a legitimate peer that emits a single malformed frame is now disconnected instead of tolerated. That is the intended trade — a conforming peer never emits one, and gossip reconnects — but it is a behaviour change on the live wire, not a pure internal refactor, and it is the one part of this change set whose blast radius is operational rather than analytic. Gated by the multi-node cluster tier (§7), which exercises real peer churn under real framing.

**Finding F-10 (⚠ HIGH — the depth ceiling is ENVELOPE-RELATIVE, and WIRE-3 turns the resulting asymmetry into a permanent sync wedge). OWNER DECISION REQUIRED BEFORE SHIPPING WIRE-2.**

`kMaxJsonDepth` is an **absolute** depth over the frame, but the same `Block` JSON sits at *different* absolute depths depending on which message carries it. A document accepted on an ingest path can therefore be **rejected on the serve path** — and WIRE-3 then closes the connection instead of dropping the frame.

**The unbounded-depth field.** `src/chain/block.cpp` `AbortEvent::from_json` stores `ae.claims_json = j.value("claims", json::array())` **verbatim**, and `to_json` re-emits it verbatim. This is documented as deliberate in `include/determ/chain/abort_canonical.hpp`: canonicalization strips unknown members from the **digest only**, never from the block body, because the per-claim Ed25519 signature covers only `block_index‖round‖prev_hash‖missing_creator`. `Block::signing_bytes` appends only `ae.event_hash`, so **injected junk does not change the block hash or the K-of-K digest** — honest committee members sign the poisoned block and no validator can distinguish it.

**Depth arithmetic** (the check is `++depth > 64`, so exactly 64 passes; L = injected nesting levels):

| path | claim object at depth | accepts |
|---|---|---|
| `ABORT_EVENT` — envelope → payload → event → claims[] → claim | 5 | L ≤ 59 |
| `BLOCK` — envelope → Block → abort_events[] → event → claims[] → claim | 6 | L ≤ 58 |
| `CHAIN_RESPONSE` — envelope → payload → blocks[] → Block → abort_events[] → event → claims[] → claim | **8** | **L ≤ 56** |

**L ∈ {57, 58} is accepted on every ingest path and rejected on every serve path.** Note this band is exactly 2 wide *for any value of `kMaxJsonDepth`* — raising or lowering the constant does not remove it, it only moves it.

**Failure.** A single registered validator injects `"z":` + 57 `[` + 57 `]` into its own abort claim. The block commits fleet-wide. Thereafter `Node::on_get_chain`, the snapshot `headers` array, and `rpc_headers` (which explicitly retains `abort_events`) all serve that block nested two levels deeper — the requester's `Message::deserialize` throws in the precheck, and WIRE-3 closes the connection. Nodes already holding the chain are unaffected (disk reload does not go through `Message::deserialize`), but **no new node can ever sync past that height**, and each attempt now also costs a disconnect.

**Direction of the regression matters:** the wedge is created by the WIRE-2 depth ceiling, and WIRE-3 escalates it from "frame dropped" to "connection closed in a retry loop". Neither exists without this change set.

**Recommended fix (root cause, one line, consensus-byte-neutral):** in `AbortEvent::from_json`, store the canonical rebuild of each claim — the six consensus-bound fields, exactly as `canonical_abort_claims_dump` already produces for the digest — and reject a claim that fails to canonicalize, instead of falling back to verbatim peer JSON. `signing_bytes` binds only `event_hash` and the digest is already canonicalized, so honest chains are byte-identical. This closes the entire unknown-member channel, of which unbounded depth is one symptom. **It is a consensus-struct change and therefore owner-gated.**

**Two escapes that do NOT work, so they are not offered as options:**
- *Raise `kMaxJsonDepth`.* The accept/reject band is `{cap−7, cap−6}` — exactly 2 values wide **for every value of the cap**. Raising it relocates the band; it never removes it.
- *Drop the depth ceiling.* The node ceiling does bound the `'['` flood, so this looks free — but §2.3 records the measurement that kills it: `dump()` recurses and segfaults between depth 50,000 and 200,000, and `Message::serialize()` dumps. Removing the depth ceiling trades a sync wedge for a remote **crash** on the send path.

**Interim options if the root-cause fix is not taken now:** ship WIRE-2 without WIRE-3 (the wedge degrades from a disconnect loop to a dropped frame — still unsyncable, but no retry storm), or hold both pending the `claims_json` fix. **Shipping WIRE-2 + WIRE-3 against a chain that can accept a poisoned abort claim is not safe, and that combination is what this change set currently contains.**

This also falsifies a claim made elsewhere in this change set: gate 8d's comment and the `messages.hpp` sizing note say Block nesting "cannot recurse past that second level". That is true of the Block **schema**; it is not true of the depth the schema **admits**, because `claims_json` is schema-free.

**Finding F-9 (`determ-light decode-wire` has the cap ordering right but no structural ceiling — NOT network-reachable).** The light client carries a deliberately duplicated copy of the wire constants (`light/main.cpp`, "Duplicated ON PURPOSE: this decoder validates an artifact against the PUBLISHED spec"). Its ordering is already correct — the S-022 per-type cap is applied *before* the payload parse — but the parse itself (`json::parse(body + 4, body + 4 + plen)`) has no `kMaxJsonDepth` / `kMaxJsonNodes` equivalent, so a hostile 16 MB artifact claiming SNAPSHOT_RESPONSE expands in the same way the daemon's did.

**Reachability first:** `decode-wire` is an **offline artifact decoder** — an operator runs it against a file they chose. It is not on any pre-auth network path, carries no consensus weight, and its worst case is a tool the operator can kill. This is the same distinction that correctly refuted the snapshot-restore "consensus" findings (`SnapshotRestoreGateAudit`): operator-opt-in ≠ remotely reachable.

**Severity:** Low. **Status: OPEN, reported not fixed** — deliberately out of scope for this round, which was scoped to the pre-auth daemon path. Worth closing on the repo's own "same rule, two binaries" convention (the light client is where the pre-decode cap rule *originated*), and cheap to do — it just costs a `determ-light` rebuild that this round's verification chain did not need.

The findings (F-1 confirmed-sufficient, F-2 design-intent, F-3 log-asymmetry, F-4 close-eager-but-not-synchronous, F-5 not-configurable, F-6 JSON-DOM residual, F-7 no-accept-cap, F-8 WIRE-3-behaviour-change, F-9 light-client mirror, **F-10 envelope-relative depth wedge**) are surfaced for completeness.

**⚠ F-10 is the one that gates shipping.** F-1 through F-5 are advisory. F-6, F-7 and F-9 are open gaps that this change set does not make worse. **F-10 is a hazard this change set INTRODUCES** — it does not exist without the WIRE-2 depth ceiling, and WIRE-3 escalates its consequence. It was found by adversarial audit of the fix itself, not of the original code, which is the argument for auditing changes with the same lenses used on the code they harden. F-1 through F-5 are advisory and invalidate nothing. **F-6 and F-7 are open gaps** and are the reason §2.4 family 1 now reads MITIGATED rather than Defended.

---

## 7. Test-suite citation

**⚠ SUPERSEDED HEADER.** This section previously opened: *"The cap-enforcement logic at `Peer::read_body:90` itself is **not** exercised by a dedicated cap-violation test."* That is no longer true. The round-12 gates below pin the ordering properties directly, each with a well-formed vector (so only the ceiling can be the rejecter) and each falsify-verified against a targeted mutant:

| Gate | Where | Asserts | Falsified by |
|---|---|---|---|
| **WIRE-1** | `determ test-binary-codec` (8b) | An oversize **binary** envelope is rejected before payload decode | Deleting the pre-decode cap in `Message::deserialize` |
| **WIRE-2** (deep, JSON) | `test-binary-codec` (8c) | A *valid, balanced* JSON envelope past `kMaxJsonDepth` is rejected pre-parse | Deleting `json_structural_precheck` in `messages.cpp` → **RED**, binary leg stays green |
| **WIRE-2** (accept) | `test-binary-codec` (8d) | The deepest *legitimate* envelope (CHAIN_RESPONSE, depth 8) still deserializes | Over-tightening `kMaxJsonDepth` |
| **WIRE-2** (string state) | `test-binary-codec` (8e) | Structural bytes past an **escaped quote** are data — no false reject | Dropping the escape arm of the scan |
| **WIRE-2** (nodes) | `test-binary-codec` (8f) | A *flat, depth-2* envelope past `kMaxJsonNodes` is rejected — the shape depth cannot see | Dropping the `,` arm of the scan |
| **WIRE-2** (binary bypass) | `test-binary-codec` (8g) | A binary envelope **claiming SNAPSHOT_RESPONSE** cannot use its 16 MB cap to bypass the ceiling | Deleting `json_structural_precheck` in `decode_binary` → **RED while WIRE-1 stays GREEN** |
| **WIRE-3** | `determ test-net-virtual` (4d-2) | A malformed frame closes the peer; a **well-formed frame queued behind it is never dispatched** | Restoring `read_header()` in the catch branch → both legs RED |

Two notes on gate design, both learned the hard way during this round:

- **WIRE-2 (8g) is the non-vacuity that matters.** Its setup leg asserts the frame is *under* its WIRE-1 per-type cap, so WIRE-1 provably cannot be what rejects it. Under the M2 mutant WIRE-1 stayed green while 8g went red — direct evidence that the landed WIRE-1 cap alone does **not** close the bypass.
- **WIRE-3 asserts a discriminator, not a timing.** Asserting only "`on_close_` fired" would be vacuous: the connection also closes later for unrelated reasons (teardown, EOF), so a re-arming mutant could go green on a slow enough wait. The gate instead writes a **well-formed** frame immediately behind the malformed one; "closed" versus "re-armed" is observationally exactly whether that second frame is dispatched, which is timing-independent. (The first draft of this gate also captured its promise by reference from a callback that outlives the scope — it aborted with `Promise already satisfied` under the mutant. State is now held by `shared_ptr` and captured by value.)

The remaining table records the pre-existing indirect coverage.

| Test | Source | Coverage |
|---|---|---|
| `tools/test_binary_codec_roundtrip_exhaustive.sh` (via `determ test-binary-codec-roundtrip-exhaustive`) | `src/main.cpp` exhaustive per-MsgType binary-roundtrip suite | Walks every non-HELLO MsgType in `MsgType` (1..18) with a representative payload, exercising `encode_binary` → `decode_binary`. Implicitly validates that the in-spec wire forms are well-within their per-MsgType cap (every test payload is small; the test does not synthesize cap-boundary or cap-violation cases). Pins the cap table indirectly: if `max_message_bytes` returned 0 for any type, all such roundtrips would fail at the framing boundary — but the test does not currently inject 16 MB padded payloads to verify the cap-rejection path. |
| `tools/test_binary_codec.sh` | High-level binary-codec smoke test | Exercises one or two MsgTypes per code path; comments at `test_binary_codec_roundtrip_exhaustive.sh:6` reference "the S-022 cap table" — the smoke test pins that decode_binary itself does NOT enforce the 16 MB framing cap; that is the `Peer::read_body` responsibility. |
| `tools/operator_block_size_audit.sh` | Operator audit script | Reports per-block size distribution against the `--max-block-size-bytes` reference (default 16 MB). Flags blocks >75% as `block_size_cap_approach` and blocks within 1 KB of the cap as `block_size_cap_hit`. The audit script's `Wire-cap reference` table at lines 35-42 documents the per-MsgType cap values verbatim — drift between the script and `messages.hpp::max_message_bytes` would surface in operator review. |
| Cap-violation test (deferred) | n/a | A dedicated test injecting a `body_buf_` larger than the per-MsgType cap (e.g., a 2-MB-padded CONTRIB) and asserting (a) the receive lambda invokes `on_close_`, (b) the connection's read-loop exits, (c) the offending peer is removed from `GossipNet::peers_`, (d) the "oversize message" log line is emitted — would close the test-coverage gap. The detection logic is structurally short (~7 LOC at lines 90-97 of peer.cpp) and exercised on every body-read path; the absence of a dedicated test reflects S-022's "dormant on honest paths" property rather than test-coverage neglect. A future test could synthesize via a unit-test framework injecting a `Peer` with a pre-filled `body_buf_` and asserting the lambda's outputs. |

The composition test-suite (binary-codec roundtrip exhaustive for the per-MsgType cap table; operator audit for the per-block size reference) validates that the cap table is internally consistent with the MsgType enum and operationally aligned with the receiver's expectations. The cap-rejection path itself is small enough that the §3 source citation + §4 proofs constitute the primary correctness argument; future S-035 work may add a dedicated synthesis test for the cap-rejection branch in isolation.

---

## 8. Status

**Shipped, with two open gaps.** S-022 is recorded in `SECURITY.md` as ✅ Mitigated (Low/Op → Mitigated in-session). The Mitigated Low/Op count includes S-022 alongside S-021, S-024, S-026, S-027, S-028, S-029, S-037 (8 total Mitigated Low/Op per the §1 summary table).

**Round-12 hostile-wire audit (wf_c277c6d1) revision.** This document previously asserted that `Message::deserialize` returns the type cheaply (§2.2), that the sustained 16-MB-padded CONTRIB flood was *Defended* (§2.4 family 1), and that per-connection memory was bounded by an "asio accept-loop concurrency cap". **All three were false**, and the first two were load-bearing for T-5. They are corrected in place above; the pattern is worth naming because it recurs:

> **Check-ordering is its own vulnerability class.** Every guard in this chain existed and was individually correct. Each simply sat *downstream* of the cost it was meant to bound — the per-type cap after the parse, the rate limiter after the dispatch decision, the close-on-error after a re-arm. A proof that reasons about *whether* a guard fires (T-3, T-4) is structurally blind to this; only a theorem about *what has been spent when it fires* (T-6) can see it.

Delivered this round: **WIRE-2** (structural DOM ceiling, both wire formats — including the bypass where a hostile binary frame claims a 16 MB type, which `b982332`'s per-type cap did **not** close) and **WIRE-3** (close on parse error). Still open and owner-gated: **F-6** (in-ceiling DOM residual; eliminating it is a protocol decision because the 16 MB types legitimately travel as JSON), **F-7** (no inbound-connection cap in the accept loop), **F-9** (light-client mirror), and — **gating** — **F-10**.

### 8.1 Verification record

| Gate | Result |
|---|---|
| `test-binary-codec` (48 assertions incl. WIRE-1, WIRE-2 ×6) | GREEN, Linux/GCC + Windows/MSVC |
| `test-net-virtual` (incl. WIRE-3 4d-2) | GREEN, 3 consecutive runs |
| FAST suite, Linux/GCC | 293/293 GREEN |
| Doc-coherence guards | 14/14 GREEN |
| **Live cluster tier, Windows/MSVC** | **446 tests + the 3 remaining multi-node clusters (`weak_3node`, `web_hybrid`, `zero_trust_cross_chain`) — no regressions** |

**Falsify-on-mutant.** M1 (drop the precheck in `Message::deserialize`) → WIRE-2's JSON legs RED, binary leg GREEN. M2 (drop it in `decode_binary`) → the bypass leg RED **while WIRE-1 stays GREEN**. M3 (restore `read_header()` in the catch branch) → both WIRE-3 legs RED.

**Red-test classification.** The cluster run showed 14 reds. `test_c99_vector_files` invokes no `determ` binary at all (pure Python recomputation of `tools/vectors/*.json`) and so cannot discriminate. The other 13 were re-run against the main tree's `b982332` binary, swapping **only** `determ` — `determ-wallet` globs `wallet/*.cpp` and `determ-light` lists `light/*.cpp`, so neither links the changed sources and neither introduces version skew. Nine were red on the baseline too. The three that looked like regressions were re-run 4× per arm and are **flakes**, matching the documented Windows TIME_WAIT flake on back-to-back runs (`docs/README.md`):

| test | baseline | with WIRE-2/WIRE-3 |
|---|---|---|
| `test_light_verify_and_submit` | 2/4 | 2/4 |
| `test_light_state_bundle` | 1/4 | 2/4 |
| `test_light_account_history` | 4/4 | 4/4 |

**Zero regressions.** Corroborating: `"message parse error"` appears **zero** times across all 193 node logs from the cluster run — neither the WIRE-2 precheck nor the WIRE-3 catch branch executed even once on healthy traffic, which is the expected posture (both are dormant on conforming peers).

⚠ **This clean gate does NOT clear F-10.** The cluster suite exercises honest peers; F-10 requires a byzantine validator to poison an abort claim, which no test constructs. A green cluster tier says WIRE-2/WIRE-3 are inert on healthy traffic — it says nothing about the wedge.

Implementation surfaces:

- `include/determ/net/messages.hpp:124-152` — `max_message_bytes(MsgType)` cap table (this proof's primary object).
- `include/determ/net/messages.hpp:101` — `kMaxFrameBytes` outer ceiling constant.
- `include/determ/net/messages.hpp:13-82` — `MsgType` enum (the cap table's domain).
- `src/net/peer.cpp` — `Peer::read_header` framing-layer guard (T-2 closure).
- `src/net/peer.cpp` — `Peer::read_body` per-MsgType cap enforcement (T-1 + T-3 + T-4 closure) **and the WIRE-3 close-on-parse-error disposition** (T-6 clause 3).
- `include/determ/net/messages.hpp` — `kMaxJsonDepth` / `kMaxJsonNodes` structural ceilings + the threat-model, sizing and soundness commentary (T-6).
- `src/net/messages.cpp` — `json_structural_precheck` implementation; the WIRE-1 pre-decode per-type cap in `Message::deserialize`; the WIRE-2 pre-parse call on the JSON branch (T-6 clause 1).
- `src/net/binary_codec.cpp` — the WIRE-2 pre-parse call in `decode_binary`, closing the attacker-chosen-type bypass (T-6 clause 2).
- `docs/SECURITY.md` §2 row + §6.5 quick-fix summary — audit-side closure record (S-022 row).
- `docs/PROTOCOL.md` §9.2 — wire-type table including per-type body-cap column.
- `docs/README.md` §12.2 — wire-format closure narrative.
- `docs/CLI-REFERENCE.md` — operator-facing reference for the cap values via `operator_block_size_audit.sh`.
- `tools/operator_block_size_audit.sh:35-42` — operator-facing cap reference table.
- `tools/test_binary_codec_roundtrip_exhaustive.sh` — exhaustive per-MsgType roundtrip regression (indirect cap-table coverage).

The closure is **localized** in the sense of Track A (~50 LOC for the `max_message_bytes` table + ~10 LOC for the `read_body` enforcement at a single site), preserves wire-format compatibility (no new MsgType values, no new struct fields, no new validator predicate, no new apply branch), and depends only on existing primitives (`MsgType` enum, `Peer::read_header` / `read_body`, `Message::deserialize`, `on_close_` callback). T-5's composition with S-014 (the rate-limit closure) is structural: S-022 caps per-message work, S-014 caps per-IP rate; the two compose without coordination.

---

## 9. References

### Implementation references

- `include/determ/net/messages.hpp:13-82` — `MsgType` enum (19 declared variants).
- `include/determ/net/messages.hpp:101` — `kMaxFrameBytes` framing-layer outer ceiling (16 MB).
- `include/determ/net/messages.hpp:124-152` — `max_message_bytes(MsgType)` per-type cap function (the proof's primary object).
- `include/determ/net/messages.hpp:154-171` — `Message` struct + `serialize` / `serialize_binary` / `deserialize`.
- `src/net/peer.cpp:50-70` — `Peer::read_header` framing-layer guard (T-2).
- `src/net/peer.cpp:72-105` — `Peer::read_body` per-MsgType cap enforcement + `on_msg_` dispatch gate (T-1 + T-3 + T-4).
- `src/net/peer.cpp:90-97` — the specific cap-enforcement if-statement.
- `src/net/binary_codec.cpp` — the binary envelope format-detect path used by `Message::deserialize` (referenced for the magic-byte mechanism that distinguishes JSON vs binary).
- `src/net/gossip.cpp` — gossip-layer `on_close_` callback implementation (peer removal on cap-violation close, per T-4).
- `tools/operator_block_size_audit.sh:35-42` — operator-facing cap reference table.
- `tools/test_binary_codec_roundtrip_exhaustive.sh` — exhaustive per-MsgType roundtrip regression.

### Cross-references to companion proofs

- `docs/proofs/Preliminaries.md` §3 — network model (asio thread-pool concurrency assumption underlying the `Peer::read_header` → `read_body` continuation chain).
- `docs/proofs/S014RateLimiterSoundness.md` — the rate-limiter soundness proof; T-1 (Bounded burst: `A_k ≤ ⌊C + r·Δ⌋`) is the composition witness used in T-5 here.
- `docs/proofs/S014ConcurrencyAnalysis.md` — concurrency analysis for the rate limiter; the asio io_context worker-pool model carries through to S-022's per-Peer `read_header` / `read_body` continuation chain (which is also dispatched on the io_context worker pool).
- `docs/proofs/S006ContribMsgEquivocation.md` — sibling Track-A closure proof; the structural-additivity proof style (one ~10-LOC enforcement site at the receive path) is mirrored here.
- `docs/proofs/S017UnstakeApplyConsistency.md` — sibling Track-A closure proof; multi-layer defense-in-depth pattern (admission gate + apply-time defense) mirrors S-022's framing-layer + per-MsgType two-tier defense.
- `docs/proofs/S030-D2-Analysis.md` — state-divergence threat model. S-022 helps mitigate the per-block work amplification that an attacker could otherwise use to slow apply layers across multiple peers simultaneously — bounding per-block work bounds the per-block divergence window.
- `docs/proofs/BlockchainStateIntegrity.md` — composition theorem on state-integrity; T-3 (apply-time state divergence detection) is the structural defense that compositions with S-022's per-message work bound to make snapshot abuse (F-2 in §6.2 above) tractable.
- `docs/proofs/JsonValidationSoundness.md` — S-018 closure proof; covers the deserialize-exception disposition (the catch-and-log path at `peer.cpp:99-102`) that S-022's cap-enforcement path is structurally orthogonal to.

### Documentation references

- `docs/SECURITY.md` §2 row 92 — S-022 audit table entry (✅ Mitigated).
- `docs/SECURITY.md` §6.5 quick-fix summary — S-022 closure narrative.
- `docs/PROTOCOL.md` §9.2 — wire-type table including per-type body-cap column.
- `docs/README.md` §12.2 — wire-format closure narrative.
- `docs/CLI-REFERENCE.md` — operator audit script reference.

### External references

- C++ ISO/IEC 14882:2017 §16.2.3 [defns.constant.expression] — `constexpr` evaluation semantics underlying `max_message_bytes`'s compile-time constant tier values.
- C++ ISO/IEC 14882:2017 §9.6.2 [stmt.switch] — `switch` statement exhaustion rules (the default-branch fallback per L-1).
- asio documentation `asio::async_read` — the asynchronous-read primitive used by `Peer::read_header` and `read_body` continuation chain; the `error_code` / `bytes_transferred` callback contract underlying the framing-layer guard and per-MsgType cap enforcement.

---

## Chip task candidates

The §6 finding-register surfaces F-3 (asymmetric logging) as a small operational-visibility improvement. Suggested as a chip task for a follow-on:

- **F-3 fix (asymmetric log line on framing-layer cap-failure path).** Add a `std::cerr` line at `src/net/peer.cpp:65` mirroring the per-MsgType cap-failure log at line 91. Effort: ~5 LOC. Restores operator-visible signal on coordinated `kMaxFrameBytes`-boundary floods. Defense-in-depth; no observed defect in the S-022 closure itself.
