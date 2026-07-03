# StreamingSubscriptionSoundness — v2.20 `dapp_subscribe` streaming-RPC delivery-contract soundness

> **Status: SHIPPED (v2.20, R53) — companion FB71 machine-checks the backpressure protocol.**

This document formalizes the delivery contract of the **v2.20 streaming subscription RPC**: the `dapp_subscribe` method opens a long-lived connection over which the node pushes newline-JSON event frames (matching `DAPP_CALL` events, catch-up replay, heartbeats, error frames) to an authenticated subscriber. The source spec is `docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC*; this proof pins the spec's central promise as six numbered claims — **the client always knows exactly where it stands**: within one connection the stream is either gapless or observably dead (never silently lossy), the catch-up/live hand-off covers the event space exactly once, the server's resource exposure is a hard product bound, and no frame is ever pushed to an unauthenticated or un-rate-limited peer.

Unlike the light-client proof family (`SupplyProofSoundness.md` and siblings), the adversary here is **not** a Byzantine daemon lying to a verifying client — it is a resource-exhausting or unauthorized *client* attacking an honest node, plus the honest-but-slow subscriber whose delivery guarantees must stay unambiguous. Accordingly the claims are **systems arguments** (lock ordering, single-writer structure, bounded queues, gate ordering), not cryptographic reductions: v2.20 introduces no new cryptographic primitive, no consensus change, and no chain-state change (subscribers are per-node RPC-server lifecycle, not chain state — they do not contribute to `state_root` and do not appear in snapshots). The one machine-checked component is the backpressure protocol: **FB71** (`docs/proofs/tla/SubscriberBackpressure.tla`, authored in parallel this round) is the TLC model of the hook-enqueue / writer-drain / kill interleavings whose invariant `INV_NoSilentGap` exhaustively checks the contiguous-or-dead property SS-3 argues below.

**Companion documents.** `docs/V2-DESIGN.md` §v2.20 (the source spec — mechanism sketch, constants table, threat table, open questions; cited throughout by section name, never duplicated here); `docs/SECURITY.md` §S-001 (RPC HMAC auth — the authentication gate SS-5 composes) and §S-014 (per-peer-IP token-bucket rate limiter — the admission gate SS-5 composes); `S014RateLimiterSoundness.md` (T-1 bounded burst, T-2 no-amplification, T-3 per-IP independence — consumed verbatim by SS-5, not re-proved); `RpcAuthHmacSoundness.md` (the S-001 closure proof and the gate-ordering discussion in `handle_session` that SS-5 extends to the streaming takeover); `V2-DAPP-DESIGN.md` §10 (payload privacy — sender-side sealed-box encryption, unchanged by v2.20, cited by SS-6); FB71 `docs/proofs/tla/SubscriberBackpressure.tla` (the machine-checked backpressure companion, one-line role above).

---

## 1. Scope: the pinned wire contract

### 1.1 In scope (normative summary of the shipped contract)

The following is the contract this document proves properties *of*. It refines the spec sketch in `docs/V2-DESIGN.md` §v2.20 to the shipped shape; where the spec sketch and the shipped contract differ in surface detail (e.g., the frame field is the short `sid`, not the sketch's `subscriber_id` long form), the shipped contract below is authoritative.

1. **Request.** A standard RPC envelope: `{"method":"dapp_subscribe","params":{"domain":D,"topic":T?,"since":H?,"heartbeat_blocks":B?,"queue_max":Q?}}`. The request passes through the existing S-014 rate-limit consume and S-001 HMAC auth gate **before** the socket is handed to the streaming layer. Any validation failure returns a normal one-line RPC error response (`{"result":null,"error":"invalid_arg: ..."}`) and the connection remains a plain RPC session — the takeover never happens on a failed request.
2. **Takeover + frames.** On success the server takes over the socket and pushes newline-JSON frames, each carrying `"event"`, `"seq"`, and `"sid"` (a random 16-byte-hex subscriber id minted at subscribe time). `seq` starts at 0 on the `subscribed` frame and increases by exactly 1 on every subsequent frame. Frame emission is **single-writer**: one dedicated server thread per subscriber performs every socket write and assigns `seq` at write time.
3. **Frame types.** `subscribed{domain, topic, since, head, sid, seq:0}`; `dapp_call{block_index, tx_index, seq, tx_hash, from, to, amount, fee, nonce, topic, payload_hex}`; `live{block_index, seq}` (the catch-up→live transition marker); `heartbeat{block_index, seq, ts}`; `error{code ∈ {backpressure, shutdown, invalid_arg, rate_limited}, seq}` followed by socket close.
4. **Catch-up/live partition.** At subscribe time the server — holding the state shared lock — **atomically** captures the head `H` *and* registers the subscriber in the live-dispatch map. The per-block hook (which fires inside `apply_block_locked`, under `state_mutex_`, for every applied block on all 3 apply paths) enqueues matching events for blocks with `index ≥ H`. Catch-up replay then scans blocks `[since, H)` directly from the chain. The union covers `[since, ∞)` with no gap and no overlap; the `live` frame marks the transition.
5. **Backpressure.** The per-subscriber queue is bounded by `queue_max` frames — the client may request a **lower** bound than the server cap `SUBSCRIBER_QUEUE_MAX = 1024` (floor 4), never a higher one — and by `SUBSCRIBER_BYTES_MAX = 16 MiB`. On overflow the hook **kills** the subscriber (kill-on-overflow, NOT drop-oldest): it sets the killed flag, notifies, and if the writer thread is stuck in a blocking socket write, closes the socket to break it. The writer emits a best-effort final `error{code=backpressure}` frame and closes.
6. **Global caps.** `SUBSCRIBER_MAX_PER_NODE = 256` concurrent subscribers; excess subscribes are rejected `rate_limited`. Catch-up depth is bounded by `SUBSCRIBE_BACKLOG_MAX_BLOCKS = 10000`.
7. **Heartbeat.** Block-based: per subscriber, a counter of blocks since the last enqueued frame; when it reaches `heartbeat_blocks` (default 50, clamped to `[1, 10000]`) the hook enqueues a `heartbeat`. A 30 s wall-clock condvar-timeout fallback in the writer thread covers idle chains.
8. **Reconnect.** The client redials with `since` = last observed `block_index`; the dedup key is `(block_index, tx_index)`; replay across reconnect is expected and idempotent.

### 1.2 Out of scope (intentional)

- **Consensus and chain state.** No `src/chain/` change, no `state_root` contribution, no snapshot presence, no gossip-wire change. A node restart drops all subscriptions by design (spec §v2.20, open question 5).
- **Cryptographic novelty.** Nothing new to reduce; S-001's HMAC and the transport are consumed as shipped.
- **Content trustworthiness of the serving node.** A Byzantine node can lie in a stream exactly as it can lie in any RPC response; see SS-6.
- **Client-side dedup storage and multi-node stream reconciliation.** The contract hands the client sufficient keys (`block_index`, `tx_index`, `seq`, `sid`); what the client does with them is client-side.

---

## 2. Threat model

Four adversary/failure families, all *client-side* (dual to the light-client family's `A_daemon` — here the node is honest and the peer is not, or is merely slow):

- **`A_slow`** — an authenticated subscriber that stops reading (or reads arbitrarily slowly), attempting to pin unbounded server memory or wedge the apply path.
- **`A_flood`** — an authenticated client opening many subscriptions to exhaust `SUBSCRIBER_MAX_PER_NODE` or the node's thread/socket budget.
- **`A_unauth`** — a network client without a valid RPC token attempting to receive frames or to consume streaming-layer resources.
- **`A_storm`** — a DApp-side submitter driving high `DAPP_CALL` volume to amplify per-block fan-out work (bounded on the submission side by v2.19's min-fee + mempool-quota economics; the streaming layer only has to keep its own fan-out bounded — SS-4).

The honest-subscriber guarantee (SS-1, SS-2, SS-3) and the resource guarantee (SS-4, SS-5) are proved against these simultaneously: the kill-on-overflow rule is exactly the point where the two meet.

---

## 3. Premises

The claims below rest on four structural premises of the shipped design (file-level cross-references in §6; the implementation lands in parallel this round, so citations are by file and function name, not line):

- **P-1 (lock ordering).** The only lock order is `state_mutex_` → `subscribers_mutex_`. The per-block hook runs inside `apply_block_locked` (in `src/node/node.cpp`) already holding `state_mutex_` and may acquire `subscribers_mutex_`; the subscribe path acquires the state shared lock and then `subscribers_mutex_`; no path acquires them in the reverse order. (Hence: no deadlock, and the subscribe-time capture+register is atomic with respect to block application.)
- **P-2 (single writer).** Exactly one dedicated writer thread per subscriber performs socket writes and assigns `seq`. The enqueue side (per-block hook, catch-up scan, heartbeat) appends payloads to the subscriber's FIFO queue and never assigns `seq` or writes to the socket.
- **P-3 (apply-path totality).** Every block applied to the chain — on all 3 apply paths — passes through `apply_block_locked`, so the per-block hook observes every applied block exactly once, in index order (the chain is fork-free with dense monotone indices, FA1).
- **P-4 (gate ordering).** `handle_session` (in `src/rpc/rpc.cpp`) runs the S-014 rate-limit consume, then the S-001 HMAC verification, then method dispatch; `dapp_subscribe` is dispatched like any other method, and the socket takeover is the *last* step of a fully validated subscribe.

---

## 4. Claims SS-1..SS-6

### SS-1 (per-connection `seq` monotonicity is structural)

**Statement.** On any one subscription connection, the `seq` values on the frames the client observes form exactly `0, 1, 2, …, k` for some `k ≥ 0` — gapless-or-dead: the client either observes every `seq` value up to the largest it has seen, or the connection is dead. No cross-thread `seq` assignment exists anywhere in the design.

**Proof sketch.** By P-2, `seq` is assigned at write time by the one writer thread, from a writer-owned counter incremented by exactly 1 per emitted frame, starting at 0 on the `subscribed` frame. The producers (hook, catch-up, heartbeat) enqueue payloads without sequence numbers; there is no second writer, no shared counter, and therefore no interleaving to reason about — density and monotonicity of the *emitted* sequence hold by construction, not by locking discipline. On the wire, TCP delivers the byte stream in order or fails the connection, and newline framing yields one frame per line (JSON strings cannot contain a raw newline), so the client's *observed* frame sequence is a prefix of the emitted sequence. A `seq` gap on a live connection would require in-order byte delivery to skip bytes — excluded by transport semantics. The only truncation mode is connection death, which is the observable outcome SS-3 classifies. Consequence: a client that ever observes a non-contiguous `seq` on a live connection has witnessed a protocol violation by the serving node, never a benign concurrency artifact. ∎

### SS-2 (gap-freedom of the catch-up/live partition)

**Statement.** Let a successful subscription have parameter `since` and captured head `H` (the index of the first block the live hook will deliver; the `subscribed` frame reports it as `head`). Define **Replay** := matching events in blocks `[since, H)` and **Live** := matching events in blocks `[H, ∞)`. Then the connection's `dapp_call` frames are drawn from Replay ∪ Live, Replay ∩ Live = ∅, and every matching event in `[since, ∞)` is in exactly one of the two sets — no gap, no overlap. **Premise:** P-1 (lock ordering `state_mutex_` → `subscribers_mutex_`; the hook runs under the state lock) and P-3.

**Proof sketch.**

1. *The boundary is atomic.* The subscribe handler holds the state shared lock while it reads `H` and inserts the subscriber into the live-dispatch map (one critical section). `apply_block_locked` mutates the chain under the exclusive state lock, so no block can be applied between the capture of `H` and the registration: at the instant the critical section closes, blocks with `index < H` are exactly the chain-resident ones, and every subsequently applied block has `index ≥ H` (P-3: dense monotone indices, fork-free).
2. *Live is complete.* By P-3 the hook fires inside `apply_block_locked` for every applied block on all 3 apply paths; by step 1 the subscriber is registered before any block with `index ≥ H` is applied; the hook's filter enqueues matching events for `index ≥ H`. So no live event is missed and none is delivered twice (each block is applied once).
3. *Replay is complete.* Blocks `[since, H)` are chain-resident and immutable at capture time (fork-free chain), so the direct chain scan enumerates all matching events in that range. `since` is validated against the backlog window (`≥ head − SUBSCRIBE_BACKLOG_MAX_BLOCKS`), so the scan is bounded and the blocks are present.
4. *Disjointness.* Replay is strictly below `H`; the hook filter is at-or-above `H`. Disjoint by index arithmetic — the same event cannot be emitted by both phases within one connection.
5. *No deadlock, no lost registration.* P-1: hook (state → subscribers) and subscribe (state-shared → subscribers) acquire in the same order; the subscribers map is serialized under `subscribers_mutex_`.

The `live{block_index, seq}` frame delimits the replay segment for the client; every `dapp_call` frame independently carries `(block_index, tx_index)`, so the client can confirm the partition itself. Together with SS-1, within one connection each matching event in `[since, ∞)` is delivered exactly once or the connection dies (SS-3). ∎

### SS-3 (kill-vs-drop: the stream is contiguous or observably dead)

**Statement.** Under the backpressure contract, the client-observable outcome of any subscription is exactly one of: (i) a live connection whose frames are `seq`-contiguous (SS-1) and whose `dapp_call` set follows the SS-2 partition, or (ii) connection death — socket close, best-effort preceded by a final `error` frame (`backpressure` on overflow, `shutdown` on node stop). **Silent frame loss — a live connection that has skipped a matched event — is impossible.**

**Proof sketch.** Enumerate the fate of a matched event at its only entry point, the enqueue against a registered, non-killed subscriber:

- **(a) Enqueue succeeds** (both bounds respected — fewer than `min(queue_max, SUBSCRIBER_QUEUE_MAX)` frames and under `SUBSCRIBER_BYTES_MAX` buffered bytes): the frame is in the FIFO queue; by P-2 the single writer emits queued frames in order, so the event will be written before any later-enqueued frame, preserving SS-1/SS-2 on the live path.
- **(b) Enqueue trips a bound**: the hook does **not** drop the frame and continue — it kills the subscription: sets the killed flag, notifies the writer, and closes the socket if the writer is stuck in a blocking write (so the kill cannot itself be wedged by the slow consumer it is killing). The writer emits a best-effort final `error{code=backpressure}` and closes. The subscriber is removed from the dispatch map: no further enqueues, no half-alive state.

There is no drop-oldest path, no drop-newest-and-continue path, and no third outcome: the only lossy transition in the whole state machine is the killing one, and it is observable (socket death, usually with the terminal error frame). Hence a live connection has, by induction over enqueues, never lost a matched event, which is claim (i); every other execution ends in (ii). The spec's rationale, verbatim: silent drops make `seq` gaps ambiguous; kill forces reconnect-via-`since` so the client always knows where it stands.

**Machine-checked companion.** FB71 (`docs/proofs/tla/SubscriberBackpressure.tla`) model-checks precisely this case analysis — the hook-enqueue / writer-drain / kill interleavings — with `INV_NoSilentGap` asserting the client-visible stream is a contiguous prefix of the ideal stream or the connection is dead. This section is the design argument; FB71 is the exhaustive small-scope check of the same protocol. ∎

### SS-4 (bounded resource envelope)

**Statement.** The streaming layer's worst-case server memory is bounded by the product of per-subscriber and global caps:

- per subscriber: at most `min(queue_max, SUBSCRIBER_QUEUE_MAX = 1024)` queued frames **and** at most `SUBSCRIBER_BYTES_MAX = 16 MiB` buffered bytes (whichever trips first), plus O(1) fixed overhead (one writer thread, one socket, one `Subscriber` record);
- globally: at most `SUBSCRIBER_MAX_PER_NODE = 256` concurrent subscribers, so worst-case buffered payload is `256 × 16 MiB = 4 GiB` (defaults), reached only in the adversarial simultaneous-maximum where every one of 256 authenticated subscribers holds a full backlog at the same instant — each of which is then killed on its next overflowing enqueue.

Per-subscribe CPU is bounded too: catch-up scans at most `SUBSCRIBE_BACKLOG_MAX_BLOCKS = 10000` blocks; the per-block live fan-out is `O(|subscribers| × |matching events in block|)` with `|subscribers| ≤ 256`.

**Proof sketch.** Each bound is enforced at its unique growth site. Queue growth happens only in the enqueue of SS-3, which checks both per-subscriber ceilings before appending and kills instead of exceeding (so the ceilings are invariants, not targets). Subscriber-count growth happens only in the subscribe handler, which rejects with `error{code=rate_limited}` at `SUBSCRIBER_MAX_PER_NODE`. `queue_max` is clamped server-side: a client may lower its own bound (floor 4) but never raise it past the cap, so a hostile parameter cannot inflate the envelope. Heartbeat frames are enqueued through the same bounded path, so the liveness mechanism cannot bypass the envelope (an idle-chain writer emits at most one wall-clock-fallback heartbeat per 30 s). The product bound follows by multiplication.

**Operator levers.** Lower `SUBSCRIBER_MAX_PER_NODE` (the dominant factor — halving it halves the worst case); lower `SUBSCRIBER_BYTES_MAX` where large `payload_hex` bodies are not expected; encourage clients to request small `queue_max` (a well-behaved low-rate consumer needs far less than 1024); and the S-014 subscription weight (SS-5) prices how fast any one client can even *acquire* subscriber slots. The spec's threat table carries the same 4 GiB figure with the same tuning note. ∎

### SS-5 (auth/rate-limit composition — no unauthenticated frame path)

**Statement.** Every server-pushed frame is causally preceded, on the same TCP connection, by a `dapp_subscribe` request that passed — in this order — the S-014 rate-limit consume and the S-001 HMAC verification. A weighted consume (subscription weight ≫ one ordinary request) further prices long-lived connections. There exists no code path that emits a stream frame on a connection that has not passed both gates.

**Proof sketch.** By P-4 the subscribe request enters through the same front door as every RPC call — `handle_session` in `src/rpc/rpc.cpp`. The S-014 consume runs first (before parse and dispatch), so even a malformed or unauthenticated subscribe flood is priced at the limiter's constant-work rejection cost (`S014RateLimiterSoundness.md` T-2 — no amplification; T-1 bounds the burst of subscribe *attempts* per IP; T-3 keeps one client's exhausted bucket from affecting any other). The S-001 HMAC verification runs next (`RpcAuthHmacSoundness.md`; `docs/SECURITY.md` §S-001), and only then is the method dispatched. The streaming takeover is the *final* step of a successful `dapp_subscribe`: any earlier failure — rate-limited, auth-failed, or `invalid_arg` on parameter validation — produces a normal one-line RPC error response (`{"result":null,"error":"invalid_arg: ..."}` for validation) and leaves the connection a plain RPC session, never a stream. Since frames are written only by a per-subscriber writer (P-2), a writer exists only for a registered subscriber, and registration is strictly downstream of both gates, the no-unauthenticated-frame-path claim holds by construction.

The **weighted consume** closes the residual pricing gap: without it, one token-bucket unit would buy a long-lived server thread + queue — a resource asymmetry the flat per-request price does not capture. Charging a subscription weight at subscribe time composes with T-1's burst bound to bound the *rate of subscriber-slot acquisition* per IP/token, and the global `SUBSCRIBER_MAX_PER_NODE` rejection (`rate_limited`) bounds the aggregate regardless of how tokens are distributed (`A_flood`). The limiter's own soundness is unchanged — the weight is a new consumer of the same bucket arithmetic `S014RateLimiterSoundness.md` proves, not a modification of it. ∎

### SS-6 (trust model — what this document does NOT claim)

- **No cross-reconnect delivery guarantee beyond client dedup.** Exactly-once holds only *within* one connection (SS-1..SS-3). Across reconnects the contract is at-least-once: the client redials with `since` = last observed `block_index` and deduplicates on `(block_index, tx_index)`; replayed events are expected and idempotent. A client whose gap exceeds `SUBSCRIBE_BACKLOG_MAX_BLOCKS` must backfill through the polling RPC first (spec §v2.20). Nothing here makes the *node* remember a subscriber across restarts — subscribers are not chain state.
- **The serving node is trusted for content.** Frames are not individually signed; a Byzantine node can fabricate, censor, or reorder stream contents exactly as it can any RPC response. Trust-minimized verification of stream contents belongs to the light-client proof family (per-event re-verification against the tx-inclusion / state-proof machinery) and is explicitly out of v2.20's scope.
- **DAPP_CALL payload confidentiality is unchanged.** Payload bytes are opaque to the chain; confidentiality is sender-side encryption to the DApp's service key (sealed-box, `V2-DAPP-DESIGN.md` §10). A subscriber sees exactly what any reader of the chain sees; the stream adds no disclosure path.
- **Heartbeat timing reveals nothing not already public.** Heartbeats are block-cadence-derived, and block cadence is public via the `chain_summary`-class status RPCs; additionally every subscriber is S-001-authenticated (SS-5), so there is no unauthenticated observer to leak to.

**Condensed threat table** (from `docs/V2-DESIGN.md` §v2.20, condensed to the claim that discharges each row):

| Attack | Defense | Claim |
|---|---|---|
| Slow-subscriber DoS (subscribe, never read) | per-subscriber frame + byte ceilings; kill-on-overflow | SS-3, SS-4 |
| Connection-flood DoS (hoard subscriber slots) | weighted S-014 consume + `SUBSCRIBER_MAX_PER_NODE` rejection | SS-5, SS-4 |
| Event-storm amplification (spam `DAPP_CALL`s to fan out) | submission-side min-fee + mempool quota (v2.19, per the spec); fan-out bounded by the 256-subscriber cap | SS-4 |
| Replay across reconnect | explicit at-least-once semantics + `(block_index, tx_index)` dedup key | SS-6 |
| Payload confidentiality | unchanged — sender-side encryption per `V2-DAPP-DESIGN.md` §10 | SS-6 |
| Frame injection / `subscribed` impersonation | S-001 HMAC-authenticated channel; `sid` echoed on every frame | SS-5 |
| Topic-probing / heartbeat side channel | topics and cadence are already public chain/status data | SS-6 |

---

## 5. Composition with companion proofs

- **`S014RateLimiterSoundness.md`** — SS-5 consumes T-1 (bounded burst: caps subscribe-attempt rate per IP), T-2 (no amplification: rejected floods cost the node constant work before any streaming state exists), and T-3 (per-IP independence: one exhausted client cannot starve another's subscribe). The subscription weight is an additional consumer of the proven bucket arithmetic; it does not alter the limiter.
- **`RpcAuthHmacSoundness.md` / `docs/SECURITY.md` §S-001** — the authentication gate whose ordering inside `handle_session` SS-5 extends by one step: takeover-after-auth, never before.
- **FB71 `docs/proofs/tla/SubscriberBackpressure.tla`** — TLC model of the enqueue/kill/writer protocol; `INV_NoSilentGap` is the machine-checked form of SS-3's contiguous-or-dead case analysis. Authored in parallel this round; this document deliberately does not restate its state space or configuration.
- **`V2-DAPP-DESIGN.md` §10** — payload-privacy posture SS-6 inherits unchanged.
- **`docs/V2-DESIGN.md` §v2.20** — the source spec: mechanism, constants, threat table, and the kill-vs-drop rationale this document promotes from design prose to argued claims. Cited by section name throughout; this proof adds no wire surface beyond it.

---

## 6. Implementation cross-references

The implementation lands in parallel this round, so citations are pinned to **file + function names only** — no line numbers, by design.

| Claim | Component | File (function) | Role |
|---|---|---|---|
| SS-5 | RPC front door + gate ordering | `src/rpc/rpc.cpp` (`handle_session`) | S-014 consume, then S-001 HMAC verify, then dispatch; streaming takeover only after full validation |
| SS-5 | subscription-weight consume | `include/determ/net/rate_limiter.hpp` | the shipped S-014 token bucket, extended with a long-lived-connection weight class |
| SS-2 | per-block hook | `src/node/node.cpp` (`apply_block_locked`) | fires under `state_mutex_` on all 3 apply paths; enqueues matching events for `index ≥ H` |
| SS-1, SS-3 | subscriber writer + kill path | `src/node/node.cpp` (subscription layer, landing this round) | single-writer `seq` stamping; bounded FIFO enqueue; kill-on-overflow with blocking-write break |
| SS-4 | constants | `docs/V2-DESIGN.md` §v2.20 constants table | `SUBSCRIBER_QUEUE_MAX` 1024, `SUBSCRIBER_BYTES_MAX` 16 MiB, `SUBSCRIBER_MAX_PER_NODE` 256, `SUBSCRIBE_BACKLOG_MAX_BLOCKS` 10000, heartbeat default 50 |
| SS-3 | machine-checked companion | `docs/proofs/tla/SubscriberBackpressure.tla` (FB71) | `INV_NoSilentGap` over hook/writer/kill interleavings |
| SS-1..SS-3 | regression surface | `tools/test_dapp_subscribe.sh` (designated by the spec's touch list; lands with the implementation) | subscribe / heartbeat / deliver / backpressure-kill / reconnect-via-`since` scenarios |

---

## 7. Status

- **Spec.** `docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC* (source). This document is the delivery-contract proof over that contract; it changes no code and adds no wire surface.
- **Implementation.** Shipping this round (R53) in parallel with this document; cross-references above are file/function-pinned accordingly.
- **Assumptions.** No new cryptographic assumptions. Four systems premises: P-1 (lock ordering `state_mutex_` → `subscribers_mutex_`), P-2 (single writer per subscriber), P-3 (apply-path totality through `apply_block_locked`), P-4 (gate ordering in `handle_session`).
- **Claims.** SS-1 (structural `seq` monotonicity: gapless-or-dead, no cross-thread assignment); SS-2 (exact catch-up/live partition via atomic capture-and-register under the state lock: `[since, H)` ∪ `[H, ∞)`, no gap, no overlap); SS-3 (kill-vs-drop: contiguous stream or observable death; silent loss impossible — machine-checked as FB71 `INV_NoSilentGap`); SS-4 (hard resource envelope: `256 × 16 MiB = 4 GiB` worst case with named operator levers); SS-5 (takeover strictly after S-014 consume + S-001 HMAC verify; weighted consume prices long-lived connections; no unauthenticated frame path); SS-6 (explicit non-claims: at-least-once across reconnects with client dedup, node trusted for content, payload confidentiality unchanged, heartbeat timing already public).
- **Machine-checked companion.** FB71 `docs/proofs/tla/SubscriberBackpressure.tla` (backpressure protocol; authored in parallel this round).
- **Known limitations.** Exactly the SS-6 non-claims; none undermine the per-connection delivery contract.

---

## 8. References

### Specifications
- `docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC* — the source spec (mechanism, frames, constants, threat table, kill-vs-drop rationale).
- `V2-DAPP-DESIGN.md` §10 — DAPP_CALL payload privacy (sender-side sealed-box encryption).
- `docs/SECURITY.md` §S-001 — RPC HMAC authentication.
- `docs/SECURITY.md` §S-014 — per-peer-IP token-bucket rate limiting.

### Companion proofs
- `docs/proofs/S014RateLimiterSoundness.md` — T-1 (bounded burst), T-2 (no amplification), T-3 (per-IP independence) — consumed by SS-5.
- `docs/proofs/RpcAuthHmacSoundness.md` — S-001 closure; `handle_session` gate-ordering discussion SS-5 extends.
- `docs/proofs/tla/SubscriberBackpressure.tla` (FB71) — TLC-checked backpressure protocol; `INV_NoSilentGap` companion to SS-3.

### Implementation sites (file + function; lines intentionally unpinned — see §6)
- `src/rpc/rpc.cpp` — `handle_session` (gates + dispatch + takeover).
- `src/node/node.cpp` — `apply_block_locked` (per-block hook site); subscription layer (writer, enqueue, kill — landing this round).
- `include/determ/net/rate_limiter.hpp` — S-014 token bucket + subscription weight.
