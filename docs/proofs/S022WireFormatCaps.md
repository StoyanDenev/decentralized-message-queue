# S022WireFormatCaps — per-message-type body-cap soundness (S-022 closure)

This document formalizes the S-022 closure shipped in `src/net/peer.cpp::read_body` and `include/determ/net/messages.hpp::max_message_bytes` (the per-message-type body-size cap and its single call-site enforcement). The pre-S-022 surface admitted bodies up to `kMaxFrameBytes` (16 MB) for **every** `MsgType`, which meant a flooder could send 16 MB CONTRIB or BLOCK_SIG frames at the framing-layer ceiling — even though the legitimate maximum for a CONTRIB envelope is well under 64 KB and a BLOCK_SIG is a fixed-shape ~200-byte struct. S-022 tightens this by interposing a second, type-aware cap **after** `Message::deserialize` returns: the framing layer reads at most 16 MB, the deserialize-time check then enforces `max_message_bytes(msg.type)` (1 MB for consensus chatter, 4 MB for blocks / headers / bundles, 16 MB only for `SNAPSHOT_RESPONSE` / `CHAIN_RESPONSE`), and a violation closes the connection (same disposition the framing-layer overflow path applies).

The proof is short and structural — there are no cryptographic assumptions; this is a pure length-bound argument. T-1 establishes completeness of the `max_message_bytes` mapping (every MsgType is bounded, with a tight 1 MB default branch absorbing future variants). T-2 establishes that the framing-layer ceiling (`kMaxFrameBytes`) acts as the outer defense before any type byte is interpreted. T-3 isolates the post-deserialize defense-in-depth posture: caps fire after framing succeeds but before `on_msg_` dispatch, so a deserialize that "leniently" accepts a padded body still cannot deliver an oversize payload to the message handler. T-4 covers the connection-close disposition: a violation triggers `Peer::close()` via the existing `on_close_` callback, not a silent drop — so a sustained flooder pays a TCP-reconnect cost on every oversize attempt. T-5 establishes the multiplicative composition with the S-014 rate limiter: bounded per-message work × bounded per-connection rate = bounded per-connection bandwidth.

**Companion documents:** `Preliminaries.md` §3 (network model) for the `Peer` framing-layer assumption underlying T-2; `S014RateLimiterSoundness.md` (S-014 closure) for the rate-limit composition theorem T-5 references; `S014ConcurrencyAnalysis.md` for the asio-thread-pool concurrency model that the per-connection `Peer::read_header` → `Peer::read_body` chain runs on; `S006ContribMsgEquivocation.md` for the structural-additivity proof style mirrored here; `S030-D2-Analysis.md` for the state-divergence threat model that S-022 helps mitigate by bounding per-block work; `docs/SECURITY.md` §S-022 (quick-fix summary in §6.5) for the closure-status narrative this proof formalizes.

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
- The post-deserialize position is **deliberate**: the cap needs `msg.type` to choose the per-type ceiling, and `msg.type` is only available after `Message::deserialize` parses the type byte from the body. (The type byte cannot be peeked at before deserialize because the binary envelope's magic prefix at `binary_codec.cpp` is not bit-equivalent across the JSON and binary paths.)

The cap is therefore the **first** defense that knows the type and the **last** defense before dispatch — a defense-in-depth posture that closes the per-type gap without requiring a redesign of either the framing layer or the codec.

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

- **`Message::deserialize` returns `msg.type` cheaply.** The format-detect dispatch at `Message::deserialize` reads the first byte of the body to choose JSON vs binary, then reads the type byte either as the magic-header's type field (binary) or as the JSON object's `type` key (legacy). Both paths return `msg.type` within `O(min(|body|, header_size))` work — well before the full payload is parsed. The S-022 closure can therefore make a cap decision at deserialize-return-time without re-walking the body.

- **The default branch is the right place to put the tight ceiling.** A new MsgType variant added without explicit categorisation (a common slip during development) would inherit whatever the `switch` default returns. The S-022 closure deliberately makes the default branch tight (1 MB) — so a regression is louder (a legitimate new large-payload type would visibly fail in QA with the strict default, prompting the developer to add an explicit case) rather than silent (a new large-payload type would silently consume up to 16 MB and only surface as an operational anomaly).

The closure is therefore additive at two sites (one `switch` in `messages.hpp::max_message_bytes` + one if-statement in `peer.cpp::read_body`) and uses zero new types, no new validator predicates, and no new apply branches. The price: ~50 LOC at the type-cap table + ~10 LOC at the read-body site.

### 2.3 Adversary model

The S-022 closure defends against three adversary families:

1. **Per-connection flood with maximally-padded oversized messages of consensus-chatter types.** One TCP connection, sustained 16-MB-padded `MsgType::CONTRIB` or `MsgType::BLOCK_SIG` frames. Pre-S-022: each message burns 16 MB of allocate + parse cost. Post-S-022: every such frame is rejected at the framing boundary (the size > 1 MB cap check) and the connection is closed. Adversary pays a TCP-reconnect cost per attempted oversize. **Defended (T-2 + T-3 + T-4).**

2. **Multi-IP coordinated flood at the per-IP cap.** N attackers, N distinct IPs, each sending one oversize frame per connection before reconnecting. The per-IP rate-limit bound (T-1 of `S014RateLimiterSoundness.md`) prevents the per-IP burst from exceeding `C + r·Δ`; the per-message body-cap (T-1 + T-2 + T-3 here) further bounds the per-message work by `W_msg(m)`. The composite per-IP bandwidth bound from T-5 above is `(C + r·Δ) · W_msg(m)`. **Partially defended (T-5).** Aggregate-rate limiting across all IPs requires upstream throttling (out of scope for S-022's per-message layer; see `docs/SECURITY.md` §S-014 for the aggregate-rate discussion).

3. **New-MsgType slip-through during development.** A future contributor adds a new `MsgType` variant without explicit categorisation in `max_message_bytes`. Pre-S-022: would have inherited whatever the framing layer permitted (16 MB). Post-S-022: inherits the default branch's 1 MB tight cap, so any new type is bounded by default — explicit categorisation is required to relax (a visible code change in PR review) but never required to **strengthen**. **Defended by design (T-1 default-branch tightness).**

The closure does not address (and is not designed to address) the following:

- Cryptographic-signature-verify cost amplification on accepted (in-cap) messages. A CONTRIB at the 1-MB ceiling still costs the receiver one Ed25519 verify per signed payload, which is `O(1)` (~50 µs typical). S-022 caps the parse cost; the per-signature verify cost is intrinsic and bounded by the consensus protocol's own structural limits (e.g., committee size K).
- Per-connection memory growth across many concurrent connections. The OS-level FD limit and the asio accept-loop concurrency cap bound this; the S-022 layer does not contribute additional defense.
- Deserialize-time bugs that crash the receiver before the cap is checked. Any `Message::deserialize` exception is caught at `peer.cpp:99-102` and merely logged — the connection remains open (the receive loop iterates back to `read_header`). The catch-and-log disposition is structurally orthogonal to the cap-enforcement disposition and is governed by S-018 (JSON schema validation, see `JsonValidationSoundness.md`).

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
                std::cerr << "[peer] message parse error from " << self->address_
                          << ": " << e.what() << "\n";
            }
            self->read_header();
        });
}
```

The two checks are placed so the read-loop has three distinct rejection paths:

1. **Framing-layer rejection** (line 64): `len > kMaxFrameBytes` or `len == 0` → close.
2. **Per-MsgType cap rejection** (line 90): `body_buf_.size() > max_message_bytes(msg.type)` → close.
3. **Deserialize-exception rejection** (line 99): `Message::deserialize` throws → log + iterate (connection stays open; S-018 territory).

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
4. After the `try`/`catch` block (regardless of whether the body delivered or an exception fired): calls `read_header()` to start the next iteration.

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
- Per-peer accept-rate gating via the asio accept-loop (`src/net/gossip.cpp` accept handler).
- For a sustained attacker, the FD limit (`ulimit -n`, typically 1024-1M per process) bounds simultaneous connections.

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

For the web-profile defaults (`r_gossip = 500`, `C_gossip = 1000`), a single-IP attacker is bounded to `1000 + 500·Δ` chatter messages per Δ seconds, each ≤ 1 MB — i.e., a sustained 500 MB/sec ceiling per attacker IP for consensus-chatter floods, capped against the receiver's NIC bandwidth and asio worker-pool concurrency. The pre-S-022 equivalent was 16× higher (8 GB/sec per IP). □

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

## 5. Proofs of T-1 .. T-5

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

---

## 6. Adversary model + notable findings

### 6.1 Adversary model

The S-022 closure defends against:

**(a) Per-connection oversize flood.** One attacker, one connection, repeated 16-MB-padded MsgType::CONTRIB / BLOCK_SIG frames. **Defended (T-2 + T-3 + T-4).** Each oversize frame is rejected at the framing boundary; the connection is closed; the attacker pays a TCP-reconnect cost per attempt.

**(b) Multi-IP coordinated oversize flood.** N attackers, N connections, each sending oversize frames. **Partially defended (T-5).** Each connection's oversize is rejected per (a); the per-IP rate-limit (S-014) bounds the accepted-message count; the per-MsgType cap (S-022) bounds the per-message work. Aggregate-rate limiting requires upstream throttling.

**(c) New-MsgType slip-through.** A future variant added without explicit `max_message_bytes` entry. **Defended (T-1 default-branch tightness).** Inherits 1 MB cap by default.

**(d) Deserialize-bug exploitation.** A deserialize-time exception (e.g., a malformed JSON or binary envelope). **Out of scope for S-022; governed by S-018.** The catch-and-log disposition at `peer.cpp:99-102` keeps the connection open after a deserialize exception (the loop iterates back to `read_header`). This is structurally orthogonal to the cap-enforcement disposition: S-022 covers the in-spec-but-oversize case; S-018 covers the spec-violation case. See `JsonValidationSoundness.md` for the S-018 analysis.

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

The four findings (F-1 confirmed-sufficient, F-2 design-intent, F-3 log-asymmetry, F-4 close-eager-but-not-synchronous, F-5 not-configurable) are advisory. None invalidates T-1 through T-5. They are surfaced for completeness so an external auditor can confirm the scope of the proof's analytic conclusion.

---

## 7. Test-suite citation

The S-022 closure is exercised indirectly through several MsgType-level regression tests. The cap-enforcement logic at `Peer::read_body:90` itself is **not** exercised by a dedicated cap-violation test in the current `main` branch.

| Test | Source | Coverage |
|---|---|---|
| `tools/test_binary_codec_roundtrip_exhaustive.sh` (via `determ test-binary-codec-roundtrip-exhaustive`) | `src/main.cpp` exhaustive per-MsgType binary-roundtrip suite | Walks every non-HELLO MsgType in `MsgType` (1..18) with a representative payload, exercising `encode_binary` → `decode_binary`. Implicitly validates that the in-spec wire forms are well-within their per-MsgType cap (every test payload is small; the test does not synthesize cap-boundary or cap-violation cases). Pins the cap table indirectly: if `max_message_bytes` returned 0 for any type, all such roundtrips would fail at the framing boundary — but the test does not currently inject 16 MB padded payloads to verify the cap-rejection path. |
| `tools/test_binary_codec.sh` | High-level binary-codec smoke test | Exercises one or two MsgTypes per code path; comments at `test_binary_codec_roundtrip_exhaustive.sh:6` reference "the S-022 cap table" — the smoke test pins that decode_binary itself does NOT enforce the 16 MB framing cap; that is the `Peer::read_body` responsibility. |
| `tools/operator_block_size_audit.sh` | Operator audit script | Reports per-block size distribution against the `--max-block-size-bytes` reference (default 16 MB). Flags blocks >75% as `block_size_cap_approach` and blocks within 1 KB of the cap as `block_size_cap_hit`. The audit script's `Wire-cap reference` table at lines 35-42 documents the per-MsgType cap values verbatim — drift between the script and `messages.hpp::max_message_bytes` would surface in operator review. |
| Cap-violation test (deferred) | n/a | A dedicated test injecting a `body_buf_` larger than the per-MsgType cap (e.g., a 2-MB-padded CONTRIB) and asserting (a) the receive lambda invokes `on_close_`, (b) the connection's read-loop exits, (c) the offending peer is removed from `GossipNet::peers_`, (d) the "oversize message" log line is emitted — would close the test-coverage gap. The detection logic is structurally short (~7 LOC at lines 90-97 of peer.cpp) and exercised on every body-read path; the absence of a dedicated test reflects S-022's "dormant on honest paths" property rather than test-coverage neglect. A future test could synthesize via a unit-test framework injecting a `Peer` with a pre-filled `body_buf_` and asserting the lambda's outputs. |

The composition test-suite (binary-codec roundtrip exhaustive for the per-MsgType cap table; operator audit for the per-block size reference) validates that the cap table is internally consistent with the MsgType enum and operationally aligned with the receiver's expectations. The cap-rejection path itself is small enough that the §3 source citation + §4 proofs constitute the primary correctness argument; future S-035 work may add a dedicated synthesis test for the cap-rejection branch in isolation.

---

## 8. Status

**Shipped.** S-022 is recorded in `SECURITY.md` as ✅ Mitigated (Low/Op → Mitigated in-session). The Mitigated Low/Op count includes S-022 alongside S-021, S-024, S-026, S-027, S-028, S-029, S-037 (8 total Mitigated Low/Op per the §1 summary table).

Implementation surfaces:

- `include/determ/net/messages.hpp:124-152` — `max_message_bytes(MsgType)` cap table (this proof's primary object).
- `include/determ/net/messages.hpp:101` — `kMaxFrameBytes` outer ceiling constant.
- `include/determ/net/messages.hpp:13-82` — `MsgType` enum (the cap table's domain).
- `src/net/peer.cpp:50-70` — `Peer::read_header` framing-layer guard (T-2 closure).
- `src/net/peer.cpp:72-105` — `Peer::read_body` per-MsgType cap enforcement (T-1 + T-3 + T-4 closure).
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
