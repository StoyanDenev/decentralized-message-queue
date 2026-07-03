# StreamingObservabilityReadOnly — the R54 `dapp_subscribers` observability RPC is read-only and non-perturbing

> **Status: SHIPPED (R54) — read-only observability over the v2.20 streaming subsystem.**

This document establishes that the R54 observability read `dapp_subscribers` — and the
operator tool `operator_dapp_stream_health.sh` layered over it — exposes the live state of
the v2.20 streaming subscription subsystem **without mutating chain state and without
disturbing the streams it observes**. It is the observability counterpart to
`StreamingSubscriptionSoundness.md` (which proves the *delivery* contract of the subsystem,
SS-1..SS-6) and a composition instance of `OperatorToolingReadOnly.md` (which proves the
`operator_*.sh` family is uniformly read-only, OT-1/OT-2). The new claim `dapp_subscribers`
adds — beyond the two proofs it composes — is that a *reader* of the streaming subsystem's
runtime structures cannot perturb the single-writer delivery invariants those structures
carry.

The adversary model is the streaming family's: the node is honest, and the reader we scrutinize
is the observability path itself. The question is not "can a Byzantine node lie in this read"
(it can, exactly as in any RPC — SS-6) but "can this read, by construction, mutate chain state
or the observed streams." The claims are therefore **systems arguments** — no-mutation,
lock-ordering, single-writer preservation, disclosure boundary — not cryptographic reductions.
v2.20 introduces no chain-state change (subscribers are per-node RPC-server lifecycle, not chain
state; they do not contribute to `state_root` and do not appear in snapshots — SS §1.2), and
`dapp_subscribers` adds no wire surface beyond a new READ method over that same runtime state.

**Companion documents.** `OperatorToolingReadOnly.md` (OT-1 read-only family, OT-2 no
side-effects beyond local files — this doc adds `dapp_subscribers` to the READ set OT-1
enumerates and shows the operator tool over it inherits both theorems);
`StreamingSubscriptionSoundness.md` (SS-1 single-writer `seq` monotonicity, SS-2 catch-up/live
partition, SS-3 kill-vs-drop contiguous-or-dead, SS-4 bounded resource envelope, SS-5
auth/rate-limit composition, SS-6 non-claims — this doc must not, and does not, weaken any of
them: it proves the observer touches none of the writer/hook state those claims constrain);
`docs/SECURITY.md` §S-001 (RPC HMAC auth — the gate SO-4 composes) and §S-014 (per-peer-IP
token-bucket rate limiter — the read-load bound C-1 inherits); `docs/V2-DESIGN.md`
§*v2.20 — Streaming subscription RPC* (the source spec for the subsystem being observed).

---

## §1. Scope: the pinned observability contract

### §1.1 In scope (normative summary of the shipped R54 read)

The following is the contract this document proves properties *of*; it is the R54
`dapp_subscribers` observability read as shipped.

1. **Method.** A new **read-only** RPC method `dapp_subscribers` (params: none), dispatched
   like every other method through the RPC front door and behind the S-001 HMAC gate.
2. **Response.** A single JSON object:

   ```
   {"count": N, "max": 256, "kills_backpressure": K,
    "subscribers": [ {"sid": "<16-byte hex>", "domain": "<D>",
                      "topic": "<T or empty string>",
                      "queue_depth": Q, "queue_max": Qmax, "bytes_buffered": B,
                      "seq": S, "killed": <bool>}, ... ]}
   ```

   where `count` = number of live `Subscriber` entries; `max` = `SUBSCRIBER_MAX_PER_NODE`
   (256, per the SS §1.1/SS-4 constants); `kills_backpressure` = cumulative count of
   subscribers killed for queue overflow since node start; and each row reports that
   subscriber's current queue depth, buffered bytes, last-stamped `seq`, and `killed` flag.
3. **Read-only + non-perturbing (the shipped invariant).** The handler takes
   `subscribers_mutex_` (and each `Subscriber::mu` briefly) to snapshot the runtime
   structures. It **never** takes `state_mutex_`, **never** mutates any chain or subscriber
   state, and does **not** perturb the live stream: a subscriber's queue and `seq` are *read*,
   never dequeued, re-stamped, or reordered. Lock order is
   `state_mutex_` → `subscribers_mutex_` → `Subscriber::mu`; this RPC touches only the latter
   two.
4. **CLI.** `determ dapp-subscribers [--rpc-port N]` prints the JSON (`dump(2)`) to stdout and
   exits 0; an RPC error / unreachable daemon prints to stderr and exits 1. HMAC-authed via
   `DETERM_RPC_AUTH_SECRET` like every RPC verb.
5. **Operator tool.** `operator_dapp_stream_health.sh` issues only the `dapp_subscribers` READ
   (via the `dapp-subscribers` CLI subcommand) and formats/rolls up its JSON; it issues no
   other daemon-touching command and writes only to stdout/stderr and operator-chosen local
   files.

The companion R54 CLI `determ dapp-subscribe … --reconnect [--max-reconnects N]
[--backoff-ms M]` (auto-redial on an error frame / disconnect, re-deriving `--since` from the
last observed `block_index`, dedup key `(block_index, tx_index)`) is a **client-side** feature
governed by SS-6's cross-reconnect at-least-once semantics; it is not part of the read this
document scrutinizes and is mentioned only to disambiguate the two R54 CLIs. `dapp-subscribe`
consumes streams; `dapp-subscribers` observes them.

### §1.2 Out of scope (intentional)

- **The delivery contract itself.** SS-1..SS-6 own the writer/hook correctness; this document
  assumes them and proves only that the reader does not disturb them.
- **Content trustworthiness of the serving node.** A Byzantine node can misreport its own
  subscriber roster exactly as it can misreport any RPC response (SS-6). `dapp_subscribers` is
  an *operator's view of their own node*, not a trust-minimized verification path.
- **Chain state / consensus.** No `src/chain/` change, no `state_root` contribution, no
  snapshot presence — inherited from v2.20 (SS §1.2).

---

## §2. Premises

The claims rest on the shipped design of the observed subsystem (its own premises P-1..P-4 in
`StreamingSubscriptionSoundness.md` §3) plus the placement of the new reader. The
implementation lands in parallel this round, so code citations are by **file + function name
only** (no line numbers); the exact lines are unknown at authoring time by design.

- **Q-1 (reader lock discipline).** `dapp_subscribers` (handler
  `Node::rpc_dapp_subscribers`, `src/node/node.cpp`) acquires `subscribers_mutex_` to walk the
  subscriber map and, per row, `Subscriber::mu` briefly to read that subscriber's
  `queue_depth` / `bytes_buffered` / `seq` / `killed`. It acquires **neither** `state_mutex_`
  **nor** any chain lock, and it holds no lock across a socket write of its own beyond the
  single reply on its own RPC connection.
- **Q-2 (reader mutates nothing).** The handler performs no assignment to chain state, to the
  subscriber map (no insert/erase), or to any `Subscriber` field. It copies scalar snapshots
  out under the briefly-held `Subscriber::mu`; the queue is measured (depth/bytes), never
  drained; `seq` is read, never incremented; `killed` is read, never set.
- **Q-3 (global order preserved).** The global lock order is
  `state_mutex_` → `subscribers_mutex_` → `Subscriber::mu` (SS P-1 extended by the leaf
  `Subscriber::mu`). The per-block hook (`apply_block_locked`, `src/node/node.cpp`,
  `on_block_finalized_for_subscribers`) descends from `state_mutex_`; the per-subscriber
  writer thread holds only `Subscriber::mu`; the reader takes only the bottom two levels,
  never up-locking to `state_mutex_`.
- **Q-4 (gate ordering, inherited).** `dapp_subscribers` enters through the same RPC front door
  as every method (`src/rpc/rpc.cpp`), behind the S-014 rate-limit consume and the S-001 HMAC
  verification (SS P-4; `S001RpcAuthSoundness.md`). It dispatches like any other READ; there is
  no takeover — it returns one JSON reply and the connection stays a plain RPC session.

---

## §3. Claims SO-1..SO-4

### SO-1 (chain-state read-only)

**Statement.** `dapp_subscribers` issues no state mutation and never takes `state_mutex_`; it
only snapshots the per-subscriber runtime structures. Its RPC method is a **READ** in the
sense of `OperatorToolingReadOnly.md` §2.3, hence disjoint from
`MUTATE_STATE := {send, stake, unstake, register, submit_tx, submit_equivocation}`. The
operator tool over it inherits OT-1 (read-only) and OT-2 (no daemon-side effects; local
files/stdout only).

**Proof sketch.** By Q-2 the handler contains no mutating operation: no gossip broadcast (the
tx/evidence broadcast reached only from the six `MUTATE_STATE` handlers per OT-2 step 1 is
absent here), no chain-store append, no subscriber-map insert/erase, no `Subscriber` field
write. It touches no `state_mutex_`-guarded structure at all (Q-1), so it cannot advance a
nonce, admit a tx, change a parameter, register/call a DApp, or slash a validator — the
Corollary OT-1.1 checklist is discharged trivially because the method reaches no handler in
`MUTATE_STATE`. Adding `dapp_subscribers` to the daemon's READ set therefore preserves the
§2.1 read/mutating partition of `OperatorToolingReadOnly.md`: the READ set grows by one method,
the mutating set is unchanged. For the tool: `operator_dapp_stream_health.sh` issues only the
`dapp-subscribers` subcommand (§1.1 item 5), which maps to this single READ method; by the OT-1
argument the tool's reachable-method-set is `⊆ READ`, and by OT-2 its only side effects are
stdout/stderr and operator-chosen local files. `dapp_subscribers` thus joins the READ set OT-1
enumerates, and the operator tool inherits OT-1/OT-2 verbatim. ∎

### SO-2 (non-perturbing on the stream)

**Statement.** Reading a subscriber's `queue_depth` / `bytes_buffered` / `seq` / `killed`
under `Subscriber::mu` does **not** dequeue, re-`seq`, or reorder anything. The writer thread
remains the *sole* mutator of the queue and the *sole* assigner of `seq` (SS-1 preserved). An
observer cannot cause a frame drop or a `seq` gap; the kill-vs-drop contract (SS-3) is a
property of the writer/hook, not of the reader.

**Proof sketch.** SS-1 rests on P-2: exactly one dedicated writer thread per subscriber
performs socket writes and assigns `seq` from a writer-owned counter; the producers (hook,
catch-up, heartbeat) only append payloads. `dapp_subscribers` is neither the writer nor a
producer — by Q-2 it appends nothing and dequeues nothing; it reads the *current* depth and
the *last-stamped* `seq` as scalars under the same `Subscriber::mu` the writer uses to publish
them, then releases. The writer's counter is untouched, so the emitted sequence
`0, 1, 2, …, k` is exactly what it would have been without the read; the reader observes a
value in that sequence, it does not perturb the sequence. Likewise the FIFO queue's contents
and order are unchanged (depth is *counted*, not consumed), so the single-writer drain in FIFO
order that SS-1/SS-2 depend on is intact. The `killed` flag is *read*, not *set*: the only
setter of `killed` is the SS-3 kill path (the hook on an overflowing enqueue), which
`dapp_subscribers` does not enter. Hence SS-3's dichotomy — a live connection whose frames are
`seq`-contiguous, or observable death — is decided entirely by the writer/hook state machine;
the reader can *report* which of the two a subscriber is in (`killed` true/false, current
depth), but cannot *cause* a transition between them. A reported `killed:true` row is a
subscriber the writer/hook already killed; a reported high `queue_depth` is a subscriber
approaching (but not pushed past) its SS-4 ceiling by the *writer's* producers, never by this
read. Therefore no observation via `dapp_subscribers` can drop a matched event or open a `seq`
gap: SS-1's monotonicity and SS-3's kill-vs-drop are untouched. ∎

### SO-3 (lock-ordering safety / no deadlock)

**Statement.** The reader takes `subscribers_mutex_` then `Subscriber::mu`, strictly below
`state_mutex_` in the global order `state_mutex_` → `subscribers_mutex_` → `Subscriber::mu`; it
never up-locks, so it cannot deadlock against the per-block hook (which holds `state_mutex_`
and descends) or the writer thread (which holds only `Subscriber::mu`). Each subscriber's row
is a point-in-time-consistent snapshot; across subscribers the report is a best-effort scan
(documented limit, SO-4 non-claim).

**Proof sketch.** By Q-3 the global lock order is a total order on the three locks, and by Q-1
the reader acquires only its bottom two levels, always top-down within that suffix
(`subscribers_mutex_` before `Subscriber::mu`) and never re-acquiring upward to `state_mutex_`.
Deadlock requires a cycle in the wait-for graph, i.e. two threads acquiring a shared pair in
opposite orders. Compare the reader against each concurrent actor:

- **vs. the per-block hook** (`apply_block_locked` / `on_block_finalized_for_subscribers`): the
  hook descends `state_mutex_` → `subscribers_mutex_` (→ `Subscriber::mu` on enqueue). The
  reader holds `subscribers_mutex_`/`Subscriber::mu` but *never* waits on `state_mutex_`, so no
  thread waits on a lock the other holds in the reverse sense — no cycle. (At worst the reader
  and the hook briefly serialize on `subscribers_mutex_`; SO-1 guarantees the reader releases
  it quickly and mutates nothing while held.)
- **vs. the writer thread**: the writer holds only `Subscriber::mu` (P-2) and does not acquire
  `subscribers_mutex_` while writing; the reader takes `Subscriber::mu` per row *after*
  `subscribers_mutex_`. Same suffix order, no reverse pair — no cycle. The reader's per-row
  hold of `Subscriber::mu` is brief (copy scalars, release), so it cannot wedge the writer.
- **vs. the subscribe path**: subscribe acquires the state shared lock then
  `subscribers_mutex_` (SS-2 step 1). The reader never holds `state_mutex_`, so it cannot
  block a state-lock acquisition; the two serialize only on `subscribers_mutex_`, in the same
  direction.

Per-subscriber the snapshot is consistent: the row's four fields are copied under one hold of
that subscriber's `Subscriber::mu`, so they reflect one instant of that subscriber's state.
Across subscribers the scan visits rows in map order, each under its own brief lock, so the
report is not a single global instant — a subscriber killed *between* two rows' captures may
appear live in the report or vice-versa. This is the point-in-time-vs-scan limit, recorded as a
non-claim in SO-4; it is a freshness caveat, never a safety one, because every field read is a
genuine (if slightly stale) value the writer published under the same mutex. ∎

### SO-4 (disclosure boundary / non-claims)

**Statement.** What the read exposes — `sid`, `domain`, `topic`, `queue_depth`, `queue_max`,
`bytes_buffered`, `seq`, `killed`, and the cumulative `kills_backpressure` — is
operator-facing metadata already implied by the authenticated subscribe requests plus public
chain data. It discloses **no** `DAPP_CALL` payload plaintext (SS-6 unchanged) and no secret.
The RPC is itself S-001 HMAC-authed (Q-4), so only authenticated operators read it. **Non-claim:**
the `count` / per-row depths are a *live snapshot*, not a linearizable global instant across all
subscribers.

**Proof sketch.** Field by field: `domain` and `topic` are the subscribe parameters the
operator's own authenticated clients supplied (SS §1.1 item 1); `sid` is the random 16-byte-hex
id the node minted for that subscribe (SS §1.1 item 2) and echoes only to distinguish rows;
`seq` is the last value the writer stamped (SS-1), a per-connection counter carrying no chain
secret; `queue_depth` / `bytes_buffered` are counts of buffered frames/bytes — runtime resource
gauges, bounded by the SS-4 ceilings (`SUBSCRIBER_QUEUE_MAX` frames, `SUBSCRIBER_BYTES_MAX`
bytes); `queue_max` is the subscriber's own (server-clamped) requested frame bound — a
subscribe parameter the operator's client supplied (SS §1.1 item 5), carrying no secret; `killed` and the node-cumulative `kills_backpressure` are backpressure telemetry from
the SS-3 kill path. None of these is a `DAPP_CALL` payload: the response schema (§1.1 item 2)
carries no `payload_hex` field, so payload confidentiality — sender-side sealed-box encryption
to the DApp's service key, `V2-DAPP-DESIGN.md` §10, unchanged by v2.20 (SS-6) — is untouched; a
subscriber's *buffered* frames may contain `payload_hex`, but `dapp_subscribers` reports the
*size* of that buffer, never its bytes. No signing key, HMAC secret, or other credential is in
the schema. Access is gated: by Q-4 the read sits behind the S-001 HMAC verification
(`docs/SECURITY.md` §S-001), so only an operator holding `DETERM_RPC_AUTH_SECRET` can invoke it
— there is no unauthenticated observer to leak roster metadata to (mirroring SS-6's
heartbeat-side-channel argument: the observers are already authenticated). Finally the explicit
non-claim: by SO-3 the cross-subscriber scan is not linearizable — `count` and the per-row
gauges are a best-effort, point-in-time-per-row snapshot, not a consistent global cut. Operators
must read the numbers as a *sampled* view of a live, concurrently-mutating roster, not as a
transactional instant. This is a freshness limitation only; every value is a real published
value, and no safety property (SO-1..SO-3) depends on cross-row simultaneity. ∎

---

## §4. Composition with companion proofs

- **`OperatorToolingReadOnly.md`** (OT-1, OT-2) — SO-1 adds `dapp_subscribers` to the READ set
  OT-1 enumerates (§2.1 partition), leaving `MUTATE_STATE` unchanged; the operator tool
  `operator_dapp_stream_health.sh` is a new member of the read-only family, inheriting OT-1
  (read-only) and OT-2 (no side-effects beyond local files) by the same subcommand→READ-method
  argument. This document is to `dapp_subscribers` what
  `StakeDistributionMetrics.md` SD-4 was to `operator_stake_distribution.sh`: a single-verb
  read-only instance of the family theorem.
- **`StreamingSubscriptionSoundness.md`** (SS-1..SS-6) — SO-2 shows the reader preserves SS-1
  (single-writer `seq` monotonicity — the writer stays the sole assigner) and does not enter
  the SS-3 kill path (kill-vs-drop stays a writer/hook property); SO-3 extends SS's lock order
  `state_mutex_` → `subscribers_mutex_` (SS P-1) by the leaf `Subscriber::mu` and shows the
  reader's bottom-two-levels-only acquisition is deadlock-free against hook, writer, and
  subscribe; SO-4 inherits SS-6's payload-confidentiality and authenticated-observer posture
  unchanged. This document introduces **no** new constraint on the delivery contract — it is a
  read layered on top of it.
- **`docs/SECURITY.md` §S-001** — the HMAC gate SO-4 composes: `dapp_subscribers`, like every
  RPC verb, is reachable only by an authenticated operator.
- **`docs/SECURITY.md` §S-014** — the per-peer-IP token bucket bounds the read load any
  operator (or client) can impose via `dapp_subscribers`, exactly as it bounds every other READ
  (`OperatorToolingReadOnly.md` C-1); a wide polling loop over `dapp_subscribers` is throttled,
  not a state risk.
- **`docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC*** — the source spec for the
  subsystem observed; `dapp_subscribers` adds an observability read over its runtime state and
  no wire surface beyond it.

---

## §5. Implementation cross-references

The implementation lands in parallel this round; citations are pinned to **file + function
names only** — line numbers intentionally unpinned.

| Claim | Component | File (function) | Role |
|---|---|---|---|
| SO-1, SO-2, SO-3 | observability handler | `src/node/node.cpp` (`rpc_dapp_subscribers`) | takes `subscribers_mutex_` + per-row `Subscriber::mu`; never `state_mutex_`; snapshots scalars, mutates nothing |
| SO-2, SO-3 | per-block hook (observed producer) | `src/node/node.cpp` (`on_block_finalized_for_subscribers`, under `apply_block_locked`) | the sole enqueue/kill site — the reader observes but never enters it |
| SO-1, SO-4 | RPC dispatch + auth gate | `src/rpc/rpc.cpp` | dispatches `dapp_subscribers` as a READ behind the S-014 consume + S-001 HMAC verify |
| SO-1..SO-4 | handler + subscriber runtime types | `include/determ/node/node.hpp` | `Subscriber` record fields (`queue_depth`/`bytes_buffered`/`seq`/`killed`), `subscribers_mutex_`, method declaration |

CLI surface: `determ dapp-subscribers [--rpc-port N]` (prints `dump(2)`, exit 0; error → stderr,
exit 1) and the operator tool `operator_dapp_stream_health.sh` over it — both HMAC-authed via
`DETERM_RPC_AUTH_SECRET`, both read-only by SO-1.

---

## §6. Status

- **Shipped.** R54 — read-only observability over the v2.20 streaming subsystem (SHIPPED R53).
  `dapp_subscribers` (RPC), `determ dapp-subscribers` (CLI), and
  `operator_dapp_stream_health.sh` (operator tool) expose live subscriber roster + backpressure
  telemetry without mutating chain state or perturbing the observed streams. This document
  changes no code and adds no wire surface.
- **Assumptions.** No new cryptographic assumptions. Four systems premises: Q-1 (reader takes
  only `subscribers_mutex_` + `Subscriber::mu`, never `state_mutex_`), Q-2 (reader mutates
  nothing — snapshots scalars, drains no queue, stamps no `seq`, sets no `killed`), Q-3 (global
  lock order `state_mutex_` → `subscribers_mutex_` → `Subscriber::mu` preserved; reader never
  up-locks), Q-4 (gate ordering inherited — S-014 consume then S-001 HMAC verify then READ
  dispatch, no takeover). Plus the observed subsystem's own premises (SS P-1..P-4).
- **Claims.** SO-1 (chain-state read-only: no mutation, no `state_mutex_`, method is a READ
  disjoint from `MUTATE_STATE`; composes OT-1/OT-2); SO-2 (non-perturbing: reading depth/`seq`/
  `killed` neither dequeues nor re-`seq`s nor reorders — writer stays the sole mutator, SS-1
  preserved, SS-3 kill-vs-drop is a writer/hook property); SO-3 (lock-ordering safety: reader
  takes the bottom two locks strictly below `state_mutex_`, never up-locks, deadlock-free
  against hook/writer/subscribe; per-row snapshot consistent, cross-row best-effort);
  SO-4 (disclosure boundary: exposes only operator-facing roster/backpressure metadata already
  implied by authenticated subscribes + public chain data, no `DAPP_CALL` payload plaintext
  (SS-6 unchanged), no secret, S-001-gated; non-claim: `count`/depths are a live snapshot, not
  a linearizable global instant).
- **Composed proofs.** `OperatorToolingReadOnly.md` (OT-1/OT-2 — READ-set membership + tool
  inheritance); `StreamingSubscriptionSoundness.md` (SS-1..SS-6 — delivery contract left
  intact by the reader); `docs/SECURITY.md` §S-001 (auth) and §S-014 (read-load bound).
- **Known limitations.** Exactly the SO-4 non-claim (cross-subscriber non-linearizability — a
  freshness caveat, not a safety one) and the SS-6 non-claims it inherits (node trusted for
  content; observability is an operator's view of their own node, not trust-minimized
  verification).

---

## §7. References

### Specifications
- `docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC* — the source spec for the observed
  subsystem.
- `V2-DAPP-DESIGN.md` §10 — DAPP_CALL payload privacy (sender-side sealed-box encryption),
  unchanged; cited by SO-4.
- `docs/SECURITY.md` §S-001 — RPC HMAC authentication (the SO-4 gate).
- `docs/SECURITY.md` §S-014 — per-peer-IP token-bucket rate limiting (the C-1 read-load bound).

### Companion proofs
- `docs/proofs/OperatorToolingReadOnly.md` — OT-1 (read-only family), OT-2 (no side-effects
  beyond local files); `dapp_subscribers` joins the READ set enumerated there.
- `docs/proofs/StreamingSubscriptionSoundness.md` — SS-1..SS-6 (v2.20 delivery contract); this
  document's SO-2/SO-3 leave SS-1's single-writer `seq` monotonicity and SS-3's kill-vs-drop
  untouched.

### Implementation sites (file + function; lines intentionally unpinned — see §5)
- `src/node/node.cpp` — `rpc_dapp_subscribers` (the observability handler);
  `on_block_finalized_for_subscribers` (the observed per-block hook, under `apply_block_locked`).
- `src/rpc/rpc.cpp` — RPC dispatch + S-001/S-014 gate ordering for `dapp_subscribers`.
- `include/determ/node/node.hpp` — `Subscriber` runtime fields, `subscribers_mutex_`, and the
  `rpc_dapp_subscribers` declaration.
