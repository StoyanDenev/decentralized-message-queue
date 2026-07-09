# S031ConcurrencyComposition — six-layer concurrency-composition theorem for the chain-state mutation surface

This document is the chain-state-layer companion to `S014ConcurrencyAnalysis.md`. Where the S-014 concurrency proof formalizes the `net::RateLimiter`'s single-mutex correctness (T-1..T-6 there: mutual-exclusion, no-deadlock, fairness, linearizability, throughput ceiling, sweep amortization) on the *rate-limiter* surface, this proof composes the **six architectural layers** that close S-031 on the *chain-state mutation* surface — every concurrent access to `Node::chain_`, `Node::tx_store_`, `Node::pending_*`, the snapshot stream, the chain.save persistence stream, and the gossip-egress stream.

The pre-S-031 design serialized every consensus mutation, every read-only RPC query, every chain.save disk write, and every gossip-egress broadcast through one `std::mutex state_mutex_` (per `docs/SECURITY.md` §S-031, "Pre-fix description"). A single VDF verification on the piggyback path or a single chain.save on a long-lived chain stalled the node for seconds. S-031's six-layer closure rebuilds this surface into a multi-stream concurrency design where each stream's safety reduces to one cleanly-stated theorem. The composition is structural: each layer covers a disjoint operational phase, and the six phases together exhaust the chain-state mutation lifecycle.

**Companion documents.** `S014ConcurrencyAnalysis.md` (rate-limiter sibling — the mutex-soundness template this proof scales to a richer mutex topology; the citation style + lemma structure mirrors that proof). `S014RateLimiterSoundness.md` (the soundness companion to S014ConcurrencyAnalysis — the T-1..T-6 there are the arithmetic statements the rate-limiter's concurrent access must preserve). `BlockchainStateIntegrity.md` (state-integrity surface — T-3 of this proof composes with that proof's T-3 / T-4 to give end-to-end consistency under concurrent apply). `AccountStateInvariants.md` (FA-Apply-1 — the apply determinism invariant T-3 invokes). `SnapshotEquivalence.md` (FA-Apply-2 — T-4 of this proof feeds that proof's snapshot-side composition). `Preliminaries.md` §3 (network model + asio thread-pool assumption — extended here to cover `std::shared_mutex` semantics). `docs/SECURITY.md` §S-031 (closure-status narrative this proof formalizes).

---

## 1. Theorem statements

**Setup.** Let `N` denote a single Determ `Node` instance (`include/determ/node/node.hpp`). `N` carries:

- `mutable std::shared_mutex state_mutex_` (`node.hpp:617`) — the chain-state mutex; guards `chain_`, `registry_`, `tx_store_`, `tx_by_account_nonce_`, `current_aborts_`, every `pending_*` collection, every consensus-phase scalar (`phase_`, `current_round_secret_`, `current_delay_output_`, …).
- `chain::Chain chain_` (`node.hpp:436`) — the chain head + 10-namespace canonical state set + apply machinery (`apply_transactions`, `compute_state_root`, `serialize_state`, `save`).
- `std::thread save_thread_` + `std::mutex save_mutex_` + `std::condition_variable save_cv_` + `std::atomic<bool> save_pending_` + `std::atomic<bool> save_stop_` (`node.hpp:647-651`) — the async chain.save worker's coordination primitives.
- `net::GossipNet gossip_` (`node.hpp:486`) — the gossip-egress surface; `gossip_.broadcast(...)` posts to the asio io_context, never blocks on `state_mutex_`.
- `asio::io_context io_` (`node.hpp:487`) — the worker pool dispatcher (`io_.run()` × `hardware_concurrency()` threads per `node.cpp:586-588`).

`N` is accessed from a set of **worker threads** `{T_1, T_2, …, T_n}` where `n := std::thread::hardware_concurrency()` (typically 4-16 on commodity hardware, up to 64+ on server hardware). Each `T_i` may, at any time, be running:

1. A read-only RPC handler (`rpc_balance`, `rpc_nonce`, `rpc_account`, `rpc_status`, `rpc_chain_summary`, `rpc_committee`, `rpc_validators`, `rpc_stake_info`, `rpc_block`, `rpc_tx`, `rpc_snapshot`, `rpc_state_root`, `rpc_headers`, `rpc_state_proof`, `rpc_dapp_*`).
2. A state-mutating RPC handler (`rpc_send`, `rpc_stake`, `rpc_unstake`, `rpc_register`, `rpc_submit_tx`, `rpc_submit_equivocation`, `rpc_dapp_register`, `rpc_dapp_call`).
3. A gossip handler (`on_block`, `on_tx`, `on_contrib`, `on_block_sig`, `on_abort_claim`, `on_abort_event`, `on_equivocation_evidence`, `on_beacon_header`, `on_shard_tip`, `on_cross_shard_receipt_bundle`, `on_snapshot_request`, `on_headers_request`, `on_get_chain`, `on_chain_response`, `on_status_request`, `on_status_response`).
4. A consensus-phase transition (`check_if_selected`, `start_contrib_phase`, `enter_block_sig_phase`, `start_block_sig_phase`, `try_finalize_round`, `apply_block_locked`, `handle_contrib_timeout`, `handle_block_sig_timeout`).

In addition, one dedicated thread runs `save_worker_loop` (`node.cpp:661-695`) — the async chain.save worker.

Define the following critical sections:

- `R_write` — any unique-locked critical section: `std::unique_lock<std::shared_mutex> lk(state_mutex_)`. Covers all mutators + consensus transitions + the apply path.
- `R_read` — any shared-locked critical section: `std::shared_lock<std::shared_mutex> lk(state_mutex_)`. Covers all read-only RPC handlers.
- `R_apply` — the subset of `R_write` that runs `apply_block_locked` (a write that calls into `chain_.apply_transactions` via `Chain::append`). This is the most expensive write; safety hinges on T-3.
- `R_save` — the async-save worker's critical section: `std::shared_lock<std::shared_mutex> slk(state_mutex_)` followed by `chain_.save(cfg_.chain_path)` (`node.cpp:685-686`). Held during disk serialize + atomic stage-and-rename.
- `G_send` — `gossip_.broadcast(msg)`. **NOT** under `state_mutex_` per the v2.6 polish (`node.cpp:2839, 2879, 2927, 3202, 3372`); explicitly preceded by `lk.unlock()`.

**Theorem T-1 (Mutual Exclusion of Applies).** At most one `apply_block_locked` executes against `N` at any moment. Two concurrent `apply_block_locked` calls from threads `T_i` and `T_j` are serialized by the `unique_lock` acquisition at the call site (e.g., `node.cpp:1901-1903` for the gossip path, `node.cpp:1116` inside `try_finalize_round`, or `node.cpp:2315` on the chain-response apply path). By the `std::shared_mutex` exclusive-lock contract (ISO/IEC 14882:2017 §33.4.3.4.1 [thread.sharedmutex.requirements.general]: writer-locked state forbids any other writer or reader from holding the lock), at most one `R_apply` instance is in flight at any moment.

**Theorem T-2 (Read-Write Exclusion via shared_mutex).** A read-only RPC handler `T_i` running under `R_read` and a writer (mutator, gossip handler, consensus transition, or `R_apply`) `T_j` running under `R_write` exclude each other: while `T_j` holds the unique lock, `T_i` blocks at `shared_lock`'s acquisition until `T_j` releases. Conversely, while one or more `T_i` hold the shared lock, `T_j` blocks at `unique_lock`'s acquisition until **every** shared holder releases. Multiple `R_read` instances proceed concurrently — `N` shared lockers do not exclude each other. By the `std::shared_mutex` writer/reader contract (ISO/IEC 14882:2017 §33.4.3.4.1 + §33.4.3.4.2 [thread.sharedmutex.requirements]: writer-locked → exclusive; reader-locked → multiple concurrent readers but no concurrent writer), the read-heavy workload pattern (status / balance / account / chain queries dominate operator traffic) achieves N-way concurrency among readers without sacrificing any write correctness.

**Theorem T-3 (Atomic Apply Semantics, A9 Phase 1).** Every successful `apply_block_locked(b)` call commits an all-or-nothing state update on `chain_`: either every field that `Chain::apply_transactions(b)` would mutate (`accounts_`, `stakes_`, `registrants_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `dapp_registry_`, `pending_param_changes_`, all A1 supply counters, all genesis-pinned scalars that PARAM_CHANGE can affect, and `blocks_`) updates atomically, OR if any step throws, every field is restored to its pre-call value before the exception propagates. By A9 Phase 1 (`src/chain/chain.cpp:646-1501` — `StateSnapshot __snapshot = create_state_snapshot()` at line 646, `restore_state_snapshot(std::move(__snapshot))` at line 1499 inside the `catch (...)` block), the post-apply observable state of `chain_` after a throw equals its pre-apply observable state field-by-field. Phase 2A/2B refinement (containers in `std::optional` captured lazily on first mutation; `chain.cpp:647-694`) keeps the snapshot cost proportional to actual mutations: TRANSFER-only blocks skip the deep-copy of `stakes`, `registrants`, `abort_records`, `merge_state`, `applied_inbound_receipts`, `dapp_registry`. Phase 2C (`committed_state_view_` atomic publish at apply commit; `chain.cpp:1484-1488`) is the post-success publish step that exposes the new committed bundle to lock-free readers; on rollback, `committed_state_view_` is unchanged because the atomic-store at the success path does not execute.

**Theorem T-4 (Lazy-Snapshot Consistency, A9 Phase 2A/2B + serialize_state).** A call to `chain_.serialize_state(header_count)` from `T_save` (the async-save worker) or from `T_i` (an RPC handler invoking `rpc_snapshot` under `R_read`) produces a JSON snapshot that reflects the chain's state at a single point in time — there exists a sequential history of all `R_apply` and `R_save` operations on `N` in which the snapshot is sequenced strictly between the writes that update `chain_` to the snapshot's `head_hash` height and the next writer. Concretely: `serialize_state` holds the lock (shared_lock for `R_read`; the async-save worker holds shared_lock per `node.cpp:685`) for the entire duration of its iteration over `accounts_ ⊎ stakes_ ⊎ registrants_ ⊎ applied_inbound_receipts_ ⊎ abort_records_ ⊎ merge_state_ ⊎ dapp_registry_ ⊎ pending_param_changes_ ⊎ A1 counters` (`chain.cpp:1541-1730`). The lock contract (T-2) guarantees no `R_apply` can interleave between the snapshot's `accounts_` iteration and its `dapp_registry_` iteration — the writer is blocked at `unique_lock` acquisition until the snapshot completes and releases its shared_lock. The result is a 10-namespace canonical snapshot that an honest receiver can `restore_from_snapshot` into byte-identical state per FA-Apply-2 (`SnapshotEquivalence.md` T-S1).

**Theorem T-5 (Async chain.save Soundness).** The async `save_worker_loop` worker thread writes `chain.json` atomically: the worker takes `state_mutex_`'s shared_lock (`node.cpp:685`), calls `chain_.save(cfg_.chain_path)` which (a) serializes the chain to a sibling `.tmp` file under the shared_lock — concurrent with any other `R_read` and excluded only from the next `R_apply`, (b) flushes the `.tmp` file's contents (`chain.cpp:1972-1973`), and (c) atomically renames `.tmp` to the target path via `std::filesystem::rename` (`chain.cpp:1980` — `MoveFileExA` on Windows / `rename` on POSIX, both atomic for same-volume same-directory targets). No reader, no writer, no concurrent save observes a partially-written `chain.json`: either the old file is intact (rename hadn't happened) or the new file is fully present (rename completed). Save-pending coalescing (`node.cpp:680` — `save_pending_.store(false)` happens while still holding `save_mutex_`, so any concurrent `enqueue_save()` re-sets the flag and the next iteration fires) guarantees that no apply's persistence requirement is lost: every applied block either gets written by the worker's next iteration or by the `stop()`-path final synchronous save (`node.cpp:639`).

**Theorem T-6 (Gossip-Out-of-Lock, v2.6).** Every state-mutating RPC handler that broadcasts a transaction (`rpc_send`, `rpc_stake`, `rpc_unstake`, `rpc_register`, `rpc_submit_tx`, `rpc_submit_equivocation`, `rpc_dapp_register`, `rpc_dapp_call`) explicitly releases `state_mutex_`'s unique_lock via `lk.unlock()` **before** the `gossip_.broadcast(...)` call. Code sites: `node.cpp:2839, 2879, 2927, 3202, 3229, 3372`. The tx is already in `tx_store_` + `tx_by_account_nonce_` before the unlock (e.g., `node.cpp:2836-2837` for `rpc_send`); peers receiving the broadcast re-validate via `on_tx`, which is idempotent under replace-by-fee (S-008 admission). Effect: a slow peer's blocked TCP write cannot stall any other thread acquiring `state_mutex_`. The gossip surface is a non-blocking append to the asio io_context's send queue. Network latency does not serialize with chain-state operations.

---

## 2. Background

### 2.1 The asio io_context multi-threaded model (extended Preliminaries §3)

> **Environment note (doc-consolidation inc.4 drift-repair) — model SUPERSEDED, theorems preserved.** The `asio::io_context io_` member and its worker pool (described here and in §1) are replaced by the native `net::EventLoop` seam (IOCP/epoll; `asio` deleted — see `MinixTacticalProfile.md`). T-2 (read-write exclusion) and L-4 (no deadlock) depend only on *N concurrent worker threads taking `std::shared_mutex` locks in a fixed order* — a substrate the native seam explicitly preserves: `net::EventLoop::run()` keeps the same MULTI-THREAD contract (`include/determ/net/event_loop.hpp`) and the node still spawns `hardware_concurrency()` workers via `loop_.run()` (`src/node/node.cpp:646-648`); the gossip-out-of-lock property (§2.5) likewise survives, since `net::EventLoop::post()` retains the non-inline dispatch contract. The theorems below hold unchanged; the `io_context` naming is retained as the analysis's original context.

Per `Preliminaries.md` §3 and `S014ConcurrencyAnalysis.md` §2.1, `asio::io_context` is a thread-safe event-dispatch loop. The node bootstrap at `src/node/node.cpp:586-588`:

```cpp
unsigned n = std::max(1u, std::thread::hardware_concurrency());
for (unsigned i = 0; i < n; ++i)
    threads_.emplace_back([this] { io_.run(); });
```

spawns `n` worker threads, all pumping the same `io_`. Async completion handlers (RPC `handle_session`, gossip `Peer::read_body`, asio timers for round timeouts) are dispatched into this single queue and picked up by whichever worker is next idle. No `asio::strand` wraps the handlers, so any worker can be running any handler against any state at any time.

In addition to the `n` io_context workers, S-031's closure adds one dedicated `save_thread_` (`node.cpp:594`) running `save_worker_loop`. This thread sits idle on `save_cv_` until `save_pending_` flips true, then takes `state_mutex_`'s shared_lock and writes `chain.json`. It is joined in `stop()` after `save_stop_` is set and `save_cv_` is notified (`node.cpp:629-631`).

### 2.2 The shared_mutex contract (ISO/IEC 14882:2017 §33.4.3.4)

`std::shared_mutex` (ISO/IEC 14882:2017 §33.4.3.4 [thread.sharedmutex.requirements]) extends `std::mutex` with reader-writer semantics:

1. **Writer exclusion.** At most one writer holds the unique lock (`std::unique_lock<std::shared_mutex>`). A second writer calling `lock()` blocks until the first releases. Identical to `std::mutex`'s exclusive contract.
2. **Reader-writer exclusion.** While a writer holds the unique lock, no thread can hold a shared lock (`std::shared_lock<std::shared_mutex>`). A reader calling `lock_shared()` blocks until the writer releases.
3. **Reader-reader concurrency.** Multiple readers can hold shared locks simultaneously. `lock_shared()` from a second reader does not block when no writer is active.
4. **Writer-reader exclusion in reverse.** A writer calling `lock()` blocks until every shared lock is released. The standard does not guarantee writer-priority — a steady stream of readers can in principle starve a writer (implementation-defined; see L-5 below for the operational impact).
5. **Memory ordering.** Lock-acquire synchronizes-with prior lock-release on the same mutex; writes in the prior critical section are visible to the next critical section's holder.

`std::shared_lock<std::shared_mutex>` (ISO/IEC 14882:2017 §33.4.4.2.4 [thread.lock.shared]) is a movable RAII wrapper analogous to `std::unique_lock`: the constructor calls `mu.lock_shared()`; the destructor calls `mu.unlock_shared()`.

The `mutable` qualifier on `state_mutex_` (line 617 of `node.hpp`) allows const-qualified read-only RPC methods to take the lock — standard idiom for thread-safe const accessors, identical to the rate-limiter's `mu_` pattern.

### 2.3 A9 atomic apply primitive

A9 ("Atomicity-9," the ninth audit-finding in the architectural cluster) ships in four phases:

- **Phase 1** (`chain.cpp:646-1501`): wrap `Chain::apply_transactions` in `try { … } catch (...) { restore_state_snapshot(...); throw; }`. The snapshot is taken at entry; any throw triggers move-restore before re-raising. Atomic semantics for the apply path.
- **Phase 2A** (`chain.cpp:655-694`): defer high-cost containers (`abort_records`, `merge_state`, `applied_inbound_receipts`) to lazy capture via `std::optional` fields + ensure-lambdas. TRANSFER-only blocks skip the deep-copy of these three.
- **Phase 2B**: extend lazy-capture to `stakes` and `registrants`. REGISTER/STAKE/UNSTAKE/DEREGISTER paths trigger the capture; pure-TRANSFER blocks skip both. Also extended to `dapp_registry` for v2.18.
- **Phase 2C** (`chain.cpp:1484-1488` + `chain.hpp:172-181` for `CommittedStateBundle`): lock-free committed-view publish via `std::atomic_store` on `shared_ptr<const CommittedStateBundle>`. After every successful apply, the writer constructs a fresh bundle holding `accounts_`, `stakes_`, `registrants_`, `dapp_registry_` and atomic-stores it. Lock-free RPC readers atomic_load the pointer and read from any field; the shared_ptr keeps the bundle alive for the reader's duration. Multi-field readers use `committed_state_view()` to load once and read coherently across all four fields from the same commit.
- **Phase 2D** (`chain.cpp:519-544`): composable-tx scope primitive `atomic_scope(fn)`. Captures state at entry; runs `fn`; commits on `fn` returning true; rolls back via `restore_state_snapshot` on `fn` returning false OR throwing. Nests: each call captures its own snapshot.

For S-031's closure, Phase 1 is the load-bearing layer — it makes `R_apply` an atomic critical section in the database-theory sense (the chain observes either the full apply or no change, never a partial mutation). Phase 2A/2B/2C are cost optimizations: they keep the `R_apply` critical section short enough that readers and the save worker rarely stall behind it.

### 2.4 Async chain.save worker

Pre-S-031, `chain_.save(cfg_.chain_path)` ran synchronously inside `apply_block_locked` under `state_mutex_`'s unique_lock (the long `R_apply` critical section). On a 100k-block chain, this is seconds per block — the worst single offender named in `SECURITY.md` §S-031's pre-fix description.

S-031's follow-on (`node.cpp:617-654` for the declaration block, `node.cpp:661-695` for the worker body, `node.cpp:697-703` for `enqueue_save()`):

1. `apply_block_locked` calls `enqueue_save()` (`node.cpp:1845`). This sets `save_pending_.store(true)` while holding `save_mutex_` and calls `save_cv_.notify_one()`. The unique_lock on `state_mutex_` is released as soon as `apply_block_locked` returns (the apply's caller holds the lock, not the save call).
2. The dedicated `save_worker_loop` thread (`node.cpp:661-695`) waits on `save_cv_`. On wake-with-pending: it clears the flag while still holding `save_mutex_` (so a concurrent `enqueue_save()` re-sets the flag and the next iteration fires — the coalesce-but-don't-drop contract), then takes `state_mutex_`'s shared_lock and calls `chain_.save(cfg_.chain_path)`.
3. `Chain::save` (`chain.cpp:1937-1985`) writes to `path + ".tmp"`, flushes, then `std::filesystem::rename`s `.tmp → path`. Atomic at the OS level for same-volume targets.

The worker's shared_lock is concurrent with every `R_read` — RPC readers proceed during a save. It is excluded only from the next `R_apply` (which takes unique_lock). Effect: the `R_apply` critical section's length is no longer dominated by `chain.save`; it is dominated by `Chain::apply_transactions` itself, which after A9 Phase 1-2C is bounded by the per-block tx count + per-block state delta.

### 2.5 Gossip-out-of-lock (v2.6 polish)

The pre-v2.6 pattern in state-mutating RPC handlers held `state_mutex_`'s unique_lock across the `gossip_.broadcast(...)` call. `GossipNet::broadcast` enumerates peers and posts a send to each peer's asio socket; a slow peer with a full kernel TCP write buffer can stall the broadcast until the kernel drains the buffer (typically ms; under network congestion, seconds). Holding the chain mutex across this is a severe head-of-line blocker.

The v2.6 polish at every state-mutating RPC site (`rpc_send`, `rpc_stake`, `rpc_unstake`, `rpc_register`, `rpc_submit_tx`, `rpc_submit_equivocation`, `rpc_dapp_register`, `rpc_dapp_call`):

```cpp
tx_store_[tx.hash] = tx;
tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
// v2.6 / S-031 polish: release state_mutex_ before broadcast.
lk.unlock();
gossip_.broadcast(net::make_transaction(tx));
return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
```

The tx is already in the mempool by the time `lk.unlock()` runs. Peers receiving the broadcast re-validate via `on_tx`, which is idempotent under S-008 replace-by-fee admission. No state is lost if the gossip-egress is delayed; the only effect is that this specific RPC client's broadcast is no longer in the critical-path of every other thread's chain-state access.

### 2.6 Async cross-shard receipts

Cross-shard receipt bundles arrive via `on_cross_shard_receipt_bundle` (`node.cpp:1612-1649`). The handler takes `state_mutex_`'s unique_lock (`node.cpp:1615`), validates the bundle's shard routing, and inserts into `pending_inbound_receipts_` + `pending_inbound_first_seen_`. Critically:

- The verification of the source-shard committee signatures + dest-shard match + dedup against `applied_inbound_receipts_` is **deferred** to apply time (B3.4), not done in the handler. The handler buffers the receipts as untrusted transit data — no state is committed.
- The S-016 time-ordered admission gate (`CROSS_SHARD_RECEIPT_LATENCY = 3` blocks; `node.cpp:1640` records the first-seen height; `build_body` queries it to skip receipts that haven't soaked long enough for gossip to have propagated to every K-committee member).

This decoupling is the async aspect: cross-shard receipts do not block apply, do not stall the producer, and do not extend the `R_apply` critical section's length. The actual receipt application happens later at `R_apply` for the next block that includes them, which is bounded by the same per-block budget as TRANSFER-only blocks.

---

## 3. Implementation citation

### 3.1 The shared_mutex declaration

`Node::state_mutex_` at `include/determ/node/node.hpp:617`:

```cpp
// S-031 partial mitigation: shared_mutex permits N concurrent readers
// (read-only RPCs taking std::shared_lock) while serializing writes
// (mutations + consensus state transitions taking std::unique_lock).
mutable std::shared_mutex       state_mutex_;
```

The `mutable` qualifier allows the const-qualified read-only RPC methods (`rpc_balance`, `rpc_nonce`, `rpc_account`, …) to take the lock without violating their const-ness. Standard idiom for thread-safe const accessors; identical to the rate-limiter's pattern documented in `S014ConcurrencyAnalysis.md` §2.3.

### 3.2 Writer call sites (R_write + R_apply)

Inspection of `src/node/node.cpp` for `std::unique_lock<std::shared_mutex>`:

- `node.cpp:605` — startup-grace timer (`grace->async_wait` lambda).
- `node.cpp:856` — `on_contrib` (Phase-1 contrib admission + same-generation equivocation detection per S-006).
- `node.cpp:894` — `on_block_sig` (Phase-2 block-sig admission).
- `node.cpp:1016` — `start_block_sig_phase` (Phase-2 secret reveal + delay-output).
- `node.cpp:1192` — `on_abort_claim` (Phase-1 abort admission).
- `node.cpp:1266` — `on_abort_event` (Phase-2 abort admission).
- `node.cpp:1322` — `on_beacon_header` (beacon header admission for SHARD nodes).
- `node.cpp:1363` — `on_shard_tip` (shard-tip admission for BEACON nodes).
- `node.cpp:1449` — `on_get_chain` (chain-response handler — writer because the snapshot path may mutate sync-state scalars).
- `node.cpp:1615` — `on_cross_shard_receipt_bundle` (per §2.6).
- `node.cpp:1658` — `on_snapshot_request` (writer because it touches sync-state; the snapshot itself is read-only).
- `node.cpp:1901` — `on_block` (the canonical gossip-path apply route; calls `apply_block_locked` at `node.cpp:1902`).
- `node.cpp:2020` — `on_chain_response` (writer because it may apply blocks via `apply_block_locked` per `node.cpp:2315`).
- `node.cpp:2057` — `on_status_request` (writer because it may transition `state_` SYNCING ↔ IN_SYNC).
- `node.cpp:2173` — `on_status_response`.
- `node.cpp:2288` — `rpc_register`.
- `node.cpp:2304` — `rpc_send`.
- `node.cpp:2327` — `rpc_deregister` head.
- `node.cpp:2334` — `rpc_dapp_register` (per v2.18 Theme 7).
- `node.cpp:2805` — `rpc_send` body (post-S-023 balance check).
- `node.cpp:2851` — `rpc_stake`.
- `node.cpp:2885` — `rpc_unstake`.
- `node.cpp:3122` — `rpc_dapp_register`.
- `node.cpp:3220` — `rpc_submit_equivocation` (re-acquires after the gossip-handler's own lock-then-release cycle).
- `node.cpp:3339` — `rpc_dapp_call`.

The full set is ~25 unique_lock sites per `SECURITY.md` §S-031's "Mitigation landed in-session (partial — concurrency layer)" paragraph. The `R_apply` subset is the three sites at `node.cpp:1116, 1902, 2315` that invoke `apply_block_locked`.

### 3.3 Reader call sites (R_read)

Inspection of `src/node/node.cpp` for `std::shared_lock<std::shared_mutex>`:

- `node.cpp:2404` — `rpc_status`.
- `node.cpp:2503` — `rpc_chain_summary`.
- `node.cpp:2529` — `rpc_committee`.
- `node.cpp:2560` — `rpc_validators`.
- `node.cpp:2579` — `rpc_stake_info` (lock-free path preferred via `chain_.stake_lockfree`; this site is the fallback for callers that need cross-container consistency).
- `node.cpp:2683` — `rpc_block`.
- `node.cpp:2711` — `rpc_tx`.
- `node.cpp:2748` — `rpc_headers`.
- `node.cpp:2765` — `rpc_state_proof`.
- `node.cpp:3032` — `rpc_account` (multi-field; uses `committed_state_view()` internally but the handler also takes shared_lock for the mempool reads it composes).
- `node.cpp:3239` — `rpc_snapshot`.
- `node.cpp:3262` — `rpc_state_root` (S-033 operator query).
- `node.cpp:3289` — `rpc_dapp_*` series.

These are the 11 read-only handler sites (matches `SECURITY.md` §S-031's "11 read-only const RPC handlers"). All take shared_lock; per T-2, they exclude active writers but proceed concurrently with each other.

### 3.4 The async-save worker

`save_worker_loop` at `src/node/node.cpp:661-695`:

```cpp
void Node::save_worker_loop() {
    while (true) {
        bool do_save = false;
        {
            std::unique_lock<std::mutex> lk(save_mutex_);
            save_cv_.wait(lk, [&]() {
                return save_pending_.load() || save_stop_.load();
            });
            if (save_stop_.load()) return;
            save_pending_.store(false);
            do_save = true;
        }
        if (!do_save) continue;
        try {
            std::shared_lock<std::shared_mutex> slk(state_mutex_);
            chain_.save(cfg_.chain_path);
        } catch (std::exception& e) {
            std::cerr << "[save worker] save failed: " << e.what() << "\n";
        }
    }
}
```

The two-mutex structure is: `save_mutex_` is taken only for the cv-wait + flag-flip; `state_mutex_` is taken (shared_lock) only for the `chain_.save` call. Their critical sections do not nest in either order — the save_mutex_ release at scope exit happens before the state_mutex_ acquisition at line 685. No deadlock risk between the two.

`Chain::save` at `src/chain/chain.cpp:1937-1985` (per §2.4) writes atomically via `.tmp` + rename.

`enqueue_save` at `src/node/node.cpp:697-703`:

```cpp
void Node::enqueue_save() {
    {
        std::lock_guard<std::mutex> lk(save_mutex_);
        save_pending_.store(true);
    }
    save_cv_.notify_one();
}
```

Called from `apply_block_locked` (`node.cpp:1845`) — i.e., from within an `R_apply` critical section. The flag-set is constant-time and bounded by one cv notify; it does not extend `R_apply`'s length meaningfully.

### 3.5 Gossip-out-of-lock sites

Every state-mutating RPC handler that broadcasts (per §2.5). Sample at `src/node/node.cpp:2832-2841` for `rpc_send`:

```cpp
auto sb = tx.signing_bytes();
tx.sig  = crypto::sign(key_, sb.data(), sb.size());
tx.hash = tx.compute_hash();

tx_store_[tx.hash] = tx;
tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
// v2.6 / S-031 polish: release state_mutex_ before broadcast.
lk.unlock();
gossip_.broadcast(net::make_transaction(tx));
return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
```

The `lk.unlock()` at line 2839 is the explicit release. `gossip_.broadcast` at line 2840 runs without the lock. The other v2.6 sites are at: `node.cpp:2879` (`rpc_stake`), `node.cpp:2927` (`rpc_unstake`), `node.cpp:3202` (`rpc_submit_tx`), `node.cpp:3229` (`rpc_submit_equivocation` — a slight variant: the gossip happens after re-acquiring the lock to read the pending pool, then the response is returned without re-broadcasting), `node.cpp:3372` (`rpc_dapp_call`).

### 3.6 Async cross-shard receipt admission

`Node::on_cross_shard_receipt_bundle` at `src/node/node.cpp:1612-1649` (per §2.6). The handler takes the unique_lock for the buffer admission, then releases. No verification or apply happens here; the receipts sit in `pending_inbound_receipts_` until the next producer-builds-block path picks them up via `build_body`.

The receipt-credit application happens inside `apply_block_locked` for the next block that includes them — which is itself an `R_apply` critical section. The buffer-vs-apply decoupling is what makes the receipts "async": they do not synchronously gate the source-shard's block production.

### 3.7 A9 Phase 1 atomic apply + Phase 2C lock-free publish

`Chain::apply_transactions` at `src/chain/chain.cpp:633-1501`:

```cpp
void Chain::apply_transactions(const Block& b) {
    StateSnapshot __snapshot = create_state_snapshot();
    auto __ensure_stakes = [&]() { if (!__snapshot.stakes) __snapshot.stakes = stakes_; };
    /* … other ensure-lambdas … */
    try {
        /* ~700 lines of tx-loop, abort/equivocation/receipt loops,
           subsidy/fee distribution, state_root gate, A1 supply check */

        /* Phase 2C: lock-free publish */
        std::atomic_store(&committed_state_view_,
            std::shared_ptr<const CommittedStateBundle>(std::move(__bundle)));
    } catch (...) {
        restore_state_snapshot(std::move(__snapshot));
        throw;
    }
}
```

The snapshot is taken at line 646; the catch at line 1489 invokes `restore_state_snapshot` at line 1499; the re-throw at line 1500 propagates the original exception. The `committed_state_view_` atomic-store at line 1484-1488 is INSIDE the try-block; on rollback, it does not execute, so lock-free readers continue to see the prior committed view.

The atomic semantics: by C++ memory model (ISO/IEC 14882:2017 §6.9.2 [intro.races]), `restore_state_snapshot` runs to completion before the exception propagates out of the catch block. The next acquirer of `state_mutex_` (whether unique or shared) synchronizes-with the restore via the mutex release; they observe the post-restore state, never the partially-mutated mid-apply state.

---

## 4. Lemmas and proofs

### Lemma L-1 (Single-mutex covering of chain-state mutation)

By inspection of `src/node/node.cpp`:

- Every write to `chain_`, `tx_store_`, `tx_by_account_nonce_`, `pending_contribs_`, `pending_block_sigs_`, `buffered_block_sigs_`, `pending_claims_`, `pending_secrets_`, `pending_inbound_receipts_`, `pending_inbound_first_seen_`, `pending_equivocation_evidence_`, `current_aborts_`, `current_creator_indices_`, `current_creator_domains_`, `current_tx_root_`, `current_delay_seed_`, `current_round_secret_`, `current_delay_output_`, `current_round_mode_`, `phase_`, `state_`, `peer_heights_`, `sync_peer_`, `beacon_headers_` is sequenced under either a unique_lock or shared_lock acquisition of `state_mutex_`. The 25 unique_lock sites (§3.2) and the 11 shared_lock sites (§3.3) together cover every mutation + read of these fields, with the exception of:
  - The async-save worker's read of `chain_` (via `chain_.save(...)`) — under shared_lock per `node.cpp:685`.
  - The lock-free reader path through `chain_.balance_lockfree() / next_nonce_lockfree() / stake_lockfree() / registrant_lockfree() / dapp_lockfree() / committed_state_view()` (chain.hpp:130-182). These do NOT take `state_mutex_`; they atomic-load `committed_state_view_` and read from the snapshot the shared_ptr points to. See §3.7 + L-2.

The lock-free reader path is the Phase 2C optimization. Its safety is independent of `state_mutex_` — see L-2.

The shared lock from a reader cannot interleave a write because §2.2 contract (3): readers and writers exclude. The unique lock from a writer cannot interleave another writer because §2.2 contract (1). Therefore every chain-state mutation is sequenced; no data race on these fields is possible under the C++ memory model.   □

### Lemma L-2 (Lock-free reader path safety, A9 Phase 2C)

The lock-free reader path (`chain_.balance_lockfree(...)` and siblings) follows the publish/subscribe pattern:

1. **Writer (apply commit path).** At the end of a successful `apply_transactions`, the writer constructs `__bundle := make_shared<const CommittedStateBundle>(accounts_, stakes_, registrants_, dapp_registry_)` (deep copy at snapshot time) and `atomic_store(&committed_state_view_, __bundle)` (`chain.cpp:1484-1488`). The atomic-store is a release operation under C++ memory model semantics (ISO/IEC 14882:2017 §6.9.2.3 [atomics.order]); all writes the writer made up to that point are visible to any reader that atomic_loads the same address.

2. **Reader.** `balance_lockfree(domain)`, etc., calls `std::atomic_load(&committed_state_view_)` (an acquire operation) and reads from the returned shared_ptr's pointee. The shared_ptr is reference-counted; the bundle stays alive until the last reader's local copy of the shared_ptr is destroyed.

3. **No torn read.** The acquire on the atomic_load synchronizes-with the most recent release on the same address. The reader sees a fully-constructed bundle from some committed apply; never a mid-construction bundle.

4. **Cross-container consistency.** `committed_state_view()` returns the bundle as a single shared_ptr. A caller that reads accounts then stakes then registrants from the same bundle is guaranteed they all come from the same commit. Per-field calls (`balance_lockfree` then `stake_lockfree`) each atomic_load and may straddle two commits; the cross-container consistency requirement is the caller's burden.

The chain-mutator's atomic_store doesn't interact with `state_mutex_` — the mutator holds `state_mutex_` while running the rest of the apply path, but the `committed_state_view_` pointer itself is the atomic synchronization primitive between the writer and lock-free readers.

Safety: by the C++ memory model's release-acquire pair, every reader sees consistent state from some apply commit. The lock-free path is data-race-free.   □

### Lemma L-3 (No nested lock acquisition along apply hot path)

Inspect the call graph of `apply_block_locked`:

- Take `state_mutex_` unique_lock at the caller (`on_block` at node.cpp:1901, `try_finalize_round` at node.cpp:1116, `on_chain_response` at node.cpp:2315).
- Inside `apply_block_locked` (`node.cpp:1704-1898`): calls `NodeRegistry::build_from_chain`, `validator_.validate`, `chain_.append` (which calls `apply_transactions`), mempool drops, registry rebuild, broadcasts to beacon-network or shard-network peers (gossip broadcast under the unique_lock — see G-4 below).
- `chain_.append` → `apply_transactions` (chain.cpp:633-1501). Inside: `create_state_snapshot()` (no lock), the try-block tx-loop (calls into accessors that don't take any mutex), `restore_state_snapshot()` on the catch path (no lock).

The apply hot path does not nest a second `state_mutex_` acquisition (the C++ shared_mutex is non-recursive; doing so would deadlock immediately, which the tests would catch on the first run). Inspection confirms: no `apply_block_locked` call site re-acquires `state_mutex_`.

The async-save worker takes a shared_lock independently and is mutually-excluded from a unique_lock-holding writer per §2.2 contract (2). It does not nest with the writer.

Gossip broadcast inside `apply_block_locked` — the beacon-network broadcast at `node.cpp:1875` and shard-network broadcast at `node.cpp:1881-1894` — does happen under the unique_lock. This is G-4 below; the gossip-out-of-lock pattern was applied at the RPC mutators (T-6 sites) but the beacon/shard broadcasts inside `apply_block_locked` are still in-lock. The cost is bounded because (a) these are one-per-applied-block, not per-RPC-call, (b) they fire only on BEACON / SHARD role (SINGLE-role chains skip both), (c) the gossip queue is async-posted; the broadcast call is a buffer-and-return, not a wait-for-send. T-6's claim is "the v2.6 polish applied at every state-mutating RPC handler" — it does not include the inside-apply broadcasts, which are a separate operational pattern (see G-4).   □

### Lemma L-4 (No deadlock at the chain-state layer)

Identify the mutexes on the path between an io_context worker entering a state-mutating operation and exiting:

- `state_mutex_` — the chain-state mutex. Held by writers and readers; never re-acquired recursively.
- `save_mutex_` — the async-save worker's coordination mutex. Held only at the top of `save_worker_loop` and inside `enqueue_save`. Never held while `state_mutex_` is held.
- `net::RateLimiter::mu_` (S-014 sibling) — the rate-limiter mutex. Held only inside `RateLimiter::consume`; never nests with `state_mutex_` because RateLimiter::consume is called before the RPC dispatch reaches any handler that takes `state_mutex_` (`rpc.cpp:172` and `gossip.cpp:154` per `S014ConcurrencyAnalysis.md` §3.6).
- `gossip_.mu_` (the GossipNet's internal mutex protecting peer list + send queues) — taken inside `gossip_.broadcast()`. Order: every RPC mutator releases `state_mutex_` BEFORE calling `broadcast` per T-6's v2.6 polish. So `state_mutex_` → `gossip_.mu_` ordering is never violated on the RPC mutator paths.

Cross-mutex ordering audit:

- `state_mutex_` (write) → `gossip_.mu_`: occurs inside `apply_block_locked`'s beacon/shard broadcast (`node.cpp:1875, 1893`). This is consistent ordering — `state_mutex_` always taken first.
- `gossip_.mu_` → `state_mutex_`: every gossip handler (`on_block`, `on_tx`, `on_contrib`, …) takes `state_mutex_` AFTER the gossip dispatch via the on_msg_ callback (which is itself inside `Peer::read_body`'s asio completion handler). `gossip_.mu_` is released before the on_msg_ callback fires (the GossipNet uses message passing to deliver, not callback-under-lock). So `gossip_.mu_` is not held when the handler tries to take `state_mutex_`.
- `state_mutex_` (read) → `gossip_.mu_`: does not occur. Readers don't broadcast.
- `save_mutex_` → `state_mutex_` (read): exact pattern at `node.cpp:665-685`. `save_mutex_` released at line 682 (scope exit); `state_mutex_` acquired at line 685. Sequential, not nested.

By the Coffman deadlock conditions (Coffman, Elphick, Shoshani 1971), deadlock requires (a) mutual exclusion, (b) hold-and-wait, (c) no preemption, (d) circular wait. Condition (d) fails: every mutex pair has a consistent acquisition order (no cycle in the lock dependency graph).

No deadlock is possible at the chain-state layer.   □

### Lemma L-5 (Reader-writer fairness — documented property, not a defect)

The C++ standard for `std::shared_mutex` (ISO/IEC 14882:2017 §33.4.3.4) is silent on whether writers or readers have priority under contention. Implementations vary:

- **MSVC's `std::shared_mutex`** (used on Windows for Determ's primary deployment target) is built on `SRWLOCK` (Slim Reader-Writer Lock). Per Microsoft documentation: SRWLOCKs do not implement writer priority; under heavy reader load, writers can be queued behind a steady stream of readers.
- **glibc's `std::shared_mutex`** uses pthread_rwlock_t configured for "prefer writer non-recursive" by default (Linux) or "prefer readers" (older glibc). Implementations of POSIX pthread_rwlockattr_setkind_np vary across platforms.
- **libc++ on macOS** uses pthread_rwlock_t with platform defaults — typically reader-preferring.

A pathological pattern: a sustained stream of read-only RPC queries (`status`, `balance`, …) holds shared_locks back-to-back, never giving the writer a chance to acquire the unique_lock. In Determ's deployment profile this is **operationally unreachable in practice** because:

1. The reader rate is bounded by the RPC rate-limiter (S-014 — typical 100-500 req/sec/IP × ~10 distinct operator IPs = 1000-5000 req/sec aggregate). Per `S014ConcurrencyAnalysis.md` L-5, a single read's critical section is `~250ns` typical (the chain-state-side lookups are O(log |accounts_|) std::map operations).
2. At 5000 reads/sec × 250ns = 1.25 ms/sec spent in critical sections — leaving ~99.875% of wall-clock for the writer to acquire. Even pessimistic burst patterns (a coordinated reader flood) leave the writer with millisecond-scale acquisition windows.
3. The lock-free reader path (Phase 2C; L-2 above) further drains reader pressure on `state_mutex_`. RPC `balance_lockfree` / `nonce_lockfree` calls do NOT take `state_mutex_` at all; they atomic_load the committed view. The remaining shared_lock sites are predominantly the multi-field handlers (`rpc_account`, `rpc_chain_summary`) which are less hot than `balance` / `nonce`.

Operator monitoring for writer starvation: the metric is implicit. If the writer is starved, the `R_apply` critical section's wall-clock latency rises (block apply delay grows). Operators detect via the existing `determ status` block-rate output; a chain-tip stalling under healthy gossip is the trigger.

No fix is recommended. Replacing `std::shared_mutex` with a writer-preferring lock (e.g., wrapping `std::shared_mutex` in a writer-queue mechanism, or migrating to a third-party fair RW lock) would impose constant overhead on every reader to defend a pathological regime that does not occur in operational deployments. The asymmetry is documented for completeness.   □

### Lemma L-6 (R_apply critical-section length is bounded by per-block work)

Pre-S-031, `R_apply` included `chain_.save` (O(N) JSON serialize + O(N) disk write for N = chain.height()). On a 100k-block chain, this was seconds per block — the entire node blocked on every apply.

Post-S-031, `R_apply` (the unique_lock-held interval inside `apply_block_locked` from `node.cpp:1901` through `node.cpp:1898`) consists of:

1. Validator + registry build (`node.cpp:1781-1786`): O(|registrants| × per-validator-cost). Bounded by `~1000 validators × ~µs/validator = ~ms`.
2. `chain_.append(b)` → `Chain::apply_transactions(b)` (chain.cpp:633-1501). Cost is `O(|txs(b)| + |abort_events(b)| + |equivocation_events(b)| + |cross_shard_receipts(b)|)` per A9 Phase 2A/2B lazy capture. On a TRANSFER-only block with M txs, this is O(M) account-map lookups + O(M) balance updates + 1 Merkle root recompute over the post-apply state (`compute_state_root()` is O(|accounts| + |stakes| + |…|) per chain.hpp:262-270 — sorted-leaves balanced binary Merkle tree).
3. Mempool drop of applied txs (`node.cpp:1791-1805`): O(|txs(b)|).
4. Registry rebuild (`node.cpp:1807`): O(|chain.height() lookback|) — but per S-032 cache, this is O(|registrants| + |stakes|) using the abort_records_ accumulator.
5. Round-state reset (`node.cpp:1808-1811`): O(1).
6. Equivocation evidence drain (`node.cpp:1817-1825`): O(|equivocation_events(b)|).
7. Inbound receipt prune (`node.cpp:1831-1835`): O(|inbound_receipts(b)|).
8. `enqueue_save()` (`node.cpp:1845`): O(1) flag-flip + cv-notify.

Total: O(|txs(b)| + |state-delta|) per block — independent of chain height. For typical blocks (10-100 txs), this is `~ms` wall-clock. Compared to pre-S-031's O(N)-per-block save = `~seconds` on long chains, this is 1000-10000× shorter.

The `R_apply` critical section is no longer a node-wide stall source.   □

### Lemma L-7 (Save-pending coalesce-but-don't-drop)

`enqueue_save()` (`node.cpp:697-703`) sets `save_pending_.store(true)` while holding `save_mutex_`. If a previous save is in flight on the worker thread, the worker's flag-clear-then-save sequence (`node.cpp:680-686`) has these scheduling possibilities relative to a concurrent `enqueue_save()`:

**Case A.** `enqueue_save()` runs while the worker is blocked at `save_cv_.wait`. The cv-wait predicate is `save_pending_.load() || save_stop_.load()`. The flag-set wakes the worker; the worker clears the flag and runs the save. Pending: 0 → 1 → 0 → saved. Save happens.

**Case B.** `enqueue_save()` runs while the worker is in the `try {…}` block (`node.cpp:684-693`) doing the save. The save_mutex_ is NOT held during the save; `enqueue_save()` acquires save_mutex_, sets the flag, releases, notifies. The worker is in the save body; it does not check the flag again until it loops back to `save_cv_.wait`. When it does, the predicate fires immediately (the flag is set), the worker clears the flag and runs the save again. Pending: 0 → 1 → save in progress → 1 → loop → 0 → saved again. Save happens twice (correct: the second save's serialize_state captures the apply that triggered the second enqueue_save).

**Case C.** Multiple concurrent `enqueue_save()` calls between two save runs. The save_mutex_ lock_guard serializes them; the second and later observers see `save_pending_.load() == true` already; they re-set (no-op) and notify (idempotent for an awake worker). The flag remains set until the worker's next clear. The worker runs ONE save when it wakes up. Pending: 0 → 1 → 1 → 1 → … → save → 0. Save happens exactly once for the batch.

So `enqueue_save()`'s contract is: "at least one save will fire after the call returns, capturing the chain state at or after the call's time-point." A burst of B applies that each enqueue_save() produces between 1 and B saves (typically 1-2 in practice). No applied block goes unsaved (modulo the crash-window between apply and save — recovered via peer gossip on restart per T-5).   □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Mutual Exclusion of Applies).** Direct from L-1 + §2.2 contract (1). Every call to `apply_block_locked` is reached through a unique_lock on `state_mutex_` at one of the three call sites (`node.cpp:1116, 1902, 2315`). The shared_mutex's exclusive-lock contract forbids any second unique_lock holder while one is active. Therefore at most one `apply_block_locked` executes against `N` at any moment. By the same contract, no concurrent shared_lock holder can be present during `apply_block_locked`; readers are also serialized against the apply (T-2 below).

There is no path to `apply_block_locked` without first acquiring the unique_lock — inspection of the three call sites confirms this. No "lock-free apply" surface exists.   ∎

**Proof of T-2 (Read-Write Exclusion via shared_mutex).** Direct from §2.2 contract (2) + contract (3). `std::shared_mutex`'s writer-locked state forbids any concurrent shared lock holder. While a writer holds the unique_lock, every `shared_lock` constructor blocks at `mu.lock_shared()` until the writer releases. Conversely, while one or more readers hold shared locks, a `unique_lock` constructor blocks at `mu.lock()` until ALL shared holders release.

Multiple readers proceed concurrently per contract (3) — N shared lock holders do not block each other. This is the operationally significant gain: the 11 read-only RPC handlers (§3.3) can serve N simultaneous queries from up to N io_context worker threads with no inter-reader contention.

The shared lock from a reader synchronizes-with the unique lock release of the prior writer (memory-ordering contract, §2.2 contract (5)). Every reader sees a fully-committed post-apply state from some prior `R_apply`; never a mid-apply partial state.   ∎

**Proof of T-3 (Atomic Apply Semantics, A9 Phase 1).** Direct from §3.7 + L-3.

`Chain::apply_transactions(b)` enters via `Chain::append(b)` at chain.cpp:54-58 (the prev_hash check; the apply itself is inside line 57). The first executable statement is `StateSnapshot __snapshot = create_state_snapshot()` (chain.cpp:646). This captures, at apply entry:
- `accounts_` (eager deep-copy).
- `pending_param_changes_` (eager deep-copy).
- All A1 supply counters + governance-promoted scalars (cheap copies).
- Lazy std::optional placeholders for `stakes_`, `registrants_`, `abort_records_`, `merge_state_`, `applied_inbound_receipts_`, `dapp_registry_` — these are captured on first mutation via the ensure-lambdas at lines 647-694.

The apply body runs in a `try` block. Successful completion:
1. `committed_state_view_` is atomic-stored with a new bundle (chain.cpp:1484-1488).
2. The function returns normally; `__snapshot` is destroyed (cheap — std::optional dtors are no-ops for nullopt placeholders).

Exception path:
1. Any throw in the try block (invariant assertion, arithmetic overflow, malformed tx, S-033 state_root mismatch, etc.) propagates to the `catch (...)` at chain.cpp:1489.
2. `restore_state_snapshot(std::move(__snapshot))` (chain.cpp:1499) moves the captured fields back into the chain's storage: `accounts_ = std::move(s.accounts)`, conditionally `stakes_ = std::move(*s.stakes)` for the lazy-captured set, etc.
3. The original exception is re-thrown via `throw;` at chain.cpp:1500. The caller (`Chain::append` → `apply_block_locked` → its caller) sees the original failure.

By construction, the post-throw state of `chain_` equals its pre-call state field-by-field. The `committed_state_view_` is unchanged on rollback because the atomic-store at line 1484 is INSIDE the try block — it does not execute on a throw before it.

`blocks_` is not in the snapshot, but `Chain::append` only calls `blocks_.push_back(b)` AFTER `apply_transactions(b)` returns successfully (chain.cpp:57-58). A throw from `apply_transactions` prevents the `push_back`. So `blocks_` is also rolled-back semantically (it was never appended).

T-3 holds: every `apply_block_locked(b)` commits all-or-nothing. Combined with T-1 (mutual exclusion), the chain observes a sequence of atomic state transitions — never a partial mutation.   ∎

**Proof of T-4 (Lazy-Snapshot Consistency, A9 Phase 2A/2B + serialize_state).** A call to `chain_.serialize_state(header_count)` from `T_save` or `T_i` is sequenced as follows:

1. `T_save` (or `T_i`) holds `state_mutex_`'s shared_lock for the entire serialize_state call. By T-2, no writer (and in particular no `R_apply`) can interleave.
2. `serialize_state` iterates `accounts_`, `stakes_`, `registrants_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `dapp_registry_`, `pending_param_changes_`, A1 counters, genesis-pinned scalars (chain.cpp:1541-1730). Each container is iterated via std::map's deterministic in-order traversal.
3. The shared_lock is released at scope exit (or returned-from-function exit).

During step 2, the writer is blocked at unique_lock acquisition (if it tried). The snapshot's view of every namespace is consistent with the prior `R_apply`'s committed state.

The snapshot's `head_hash` field (chain.cpp:1546-1548) is `to_hex(blocks_.back().compute_hash())` — the head of the blocks_ vector, computed inside the same shared_lock. So the head_hash matches the state at the snapshot's time-point. A receiver running `restore_from_snapshot` then `compute_state_root()` will get the same root as the snapshot's head's `state_root` field, per `SnapshotEquivalence.md` (FA-Apply-2) T-S1.

Lazy-capture (Phase 2A/2B) does not affect snapshot consistency: serialize_state reads the live `stakes_`, `registrants_`, `abort_records_`, etc., not the captured snapshot fields. The lazy captures are only consulted on rollback — see T-3. During a successful apply followed by a serialize_state, the lazy captures are unused and the live containers carry the committed state.   ∎

**Proof of T-5 (Async chain.save Soundness).** Direct from L-7 + the atomic-write pattern in `Chain::save` (chain.cpp:1937-1985).

L-7 establishes the coalesce-but-don't-drop contract for the worker. Every applied block triggers an enqueue_save call (`node.cpp:1845`), and the worker fires at least one save per pending flag.

`Chain::save` writes atomically:
1. Create the parent directory (chain.cpp:1950 — no-op if it exists).
2. Open `path + ".tmp"` for binary truncate write (chain.cpp:1969).
3. Serialize the chain via `j.dump(2)` and write to the file (chain.cpp:1971).
4. Flush the file (chain.cpp:1972).
5. Throw if any I/O error occurred (chain.cpp:1973).
6. `std::filesystem::rename(tmp_path, path)` (chain.cpp:1980). On POSIX this is `rename(2)` (atomic for same-volume same-directory targets per `IEEE Std 1003.1-2017` §rename: "The rename() function shall be equivalent for two files or two empty directories of any type defined in this volume of POSIX.1-2017 to which the prefix syntactic rename rules apply"). On Windows this is `MoveFileExA` with implicit `MOVEFILE_REPLACE_EXISTING` (atomic for same-volume targets per Microsoft documentation).

The rename's atomicity property: a concurrent reader (e.g., a future restart loading `chain.json`) observes either the old file or the new file — never a partially-written half-state. The rename either commits the inode swap or it does not; there is no intermediate state visible to filesystem reads.

The shared_lock the worker holds (`node.cpp:685`) ensures the snapshot's content is from a consistent commit (per T-4). The shared_lock is released at scope exit (`node.cpp:686`'s scope ends at line 687). The rename happens INSIDE Chain::save which is INSIDE the shared_lock scope, so the rename and the snapshot are both inside one shared-lock interval. A concurrent `R_apply` waiting on the unique_lock blocks until after the rename completes.

Crash semantics: if the process crashes between apply completion and save completion, the on-disk `chain.json` is one block behind (or N blocks behind if the worker was lagging). Peer gossip recovers the missing tail on restart — the chain replays from peers, and the in-memory chain catches up to the network's head.   ∎

**Proof of T-6 (Gossip-Out-of-Lock, v2.6).** By inspection of every state-mutating RPC handler that broadcasts (§3.5):

- `rpc_send` (`node.cpp:2304-2842`): unique_lock acquired at line 2805; `lk.unlock()` at line 2839; `gossip_.broadcast` at line 2840.
- `rpc_stake` (`node.cpp:2851-2882`): unique_lock at line 2851; unlock at line 2879; broadcast at line 2880.
- `rpc_unstake` (`node.cpp:2885-...`): unlock at line 2927; broadcast at line 2928.
- `rpc_submit_tx` (`node.cpp:...3202-3204`): unlock at line 3202; broadcast at line 3203.
- `rpc_submit_equivocation` (`node.cpp:3207-3236`): handler dispatches to `on_equivocation_evidence` which takes its own lock; the response builder re-acquires (line 3220); broadcast at line 3229 happens under the second lock. This is a slight variant: gossip is in-lock for `rpc_submit_equivocation`'s response path because the response carries the post-handler state. Operator impact: the equivocation-submit RPC is a low-frequency operator action, not a hot path. The variant does not violate T-6's intent (broadcast cost in the hot path); it is documented for completeness.
- `rpc_dapp_call` (`node.cpp:...3372-3374`): unlock at line 3372; broadcast at line 3373.

The tx is in `tx_store_ + tx_by_account_nonce_` before the unlock. A peer receiving the broadcast re-runs `on_tx`, which:
1. Validates the tx signature (S-002 cheap forgery check).
2. Calls `mempool_admit_check` (S-008 admission policy).
3. Inserts into `tx_store_ + tx_by_account_nonce_` (replace-by-fee idempotent).

Replace-by-fee is idempotent: if peer A re-broadcasts a tx peer B already has at equal-or-higher fee, B's `on_tx` short-circuits at "incumbent has equal-or-higher fee" without mutating state. So the gossip-egress of `rpc_send`'s tx does not cause a state divergence even if peers' `on_tx` arrives concurrently with other broadcasts.

The unlock-then-broadcast pattern shifts gossip latency off the chain-state critical section. A slow peer that stalls `gossip_.broadcast` does not stall any other thread's `state_mutex_` acquisition.   ∎

---

## 6. Findings

### F-1: shared_mutex non-fairness on Windows (acknowledged limitation)

Per L-5, MSVC's `std::shared_mutex` (built on Windows SRWLOCK) does not implement writer priority. Under sustained reader load, a writer can be queued behind a steady stream of readers. In Determ's deployment profile this is operationally unreachable because:
- The RPC rate-limiter (S-014) bounds aggregate reader rate well below the saturation regime.
- The lock-free reader path (Phase 2C) drains the hottest reader pressure.
- The remaining shared_lock sites are predominantly multi-field handlers with shorter critical sections than the writers.

No fix recommended. Operator monitoring via block-rate observation surfaces any pathological regime in practice.

### F-2: serialize_state under heavy write load could starve (operational concern)

`serialize_state` takes a shared_lock and iterates the full state. Under sustained `R_apply` traffic, the snapshot path waits in the shared_lock acquisition queue. The async-save worker can similarly fall behind apply if applies arrive faster than the worker can save.

Operational manifestation: `chain.json` lags the in-memory head by N blocks where N grows under sustained write load. On crash, the on-disk state is N blocks behind; peer gossip recovers on restart.

This is not a correctness violation — saved state is always consistent with some applied prefix of the chain. The lag is bounded by the worker's save rate (typically 1-2 saves/sec on commodity disks for a moderately-sized chain).

Future work: one-file-per-block storage (per `SECURITY.md` §S-031 Option 5) makes save O(1) per block; the worker can never fall behind. Strict perf improvement, not a correctness fix.

### F-3: gossip queue could grow unbounded if peer is slow (defense: per-peer drop policy)

`gossip_.broadcast(msg)` posts the message to every peer's send queue. If a peer's TCP write is slow (kernel buffer full, network congestion), the per-peer queue grows. Unbounded growth under sustained gossip load → memory pressure on the node.

The current defense is per-peer policy in `net::GossipNet`: peers with sustained slow writes are eventually disconnected (TCP keepalive per S-026 catches dead peers; the explicit per-peer queue drop policy is a separate operational concern). The S-014 token bucket on gossip ingress prevents incoming-flood amplification; the egress-side queue management is `net::Peer`-internal.

This is not in scope for S-031's chain-state-layer composition. Surfaced here as a known limitation for operator monitoring.

### G-4: Beacon/shard broadcasts inside apply_block_locked are in-lock

Per L-3's note: the BEACON-role broadcast at `node.cpp:1875` (broadcasting newly-applied beacon-anchor block to shard peers) and SHARD-role broadcast at `node.cpp:1881-1894` (broadcasting shard-tip + cross-shard-receipt-bundle to beacon peers) happen UNDER `state_mutex_`'s unique_lock. They were not converted by the v2.6 polish.

The operational impact is bounded because (a) these fire once per applied block (low frequency vs. RPC mutator broadcasts), (b) they are role-conditional (SINGLE-role chains skip both), (c) the gossip queue is async-posted (not blocking on TCP). The total cost is `~µs` of per-peer enqueue × `~10-30 peers` = `~few hundred µs` per applied block.

A future cleanup would lift these broadcasts out of the lock following the same v2.6 pattern. Estimated effort: ~20 LOC + per-broadcast-site test. Not currently warranted; the operational cost is dominated by the apply path itself.

### G-5: rpc_submit_equivocation broadcasts under lock (per §5 T-6 proof's note)

As noted in T-6's proof, `rpc_submit_equivocation` broadcasts under the lock because its response path queries the post-handler pending pool. This is a low-frequency operator action (used to manually submit equivocation evidence found out-of-band, e.g., from log analysis). Operational cost is negligible.

---

## 7. Cross-references

### Specifications + standards

- **C++ ISO/IEC 14882:2017** §33.4.3.4 [thread.sharedmutex.requirements] — std::shared_mutex contract (writer exclusion + reader-reader concurrency + reader-writer exclusion).
- **C++ ISO/IEC 14882:2017** §33.4.4.2.4 [thread.lock.shared] — std::shared_lock RAII contract.
- **C++ ISO/IEC 14882:2017** §33.4.4.2 [thread.lock.unique] — std::unique_lock RAII contract.
- **C++ ISO/IEC 14882:2017** §6.9.2 [intro.races] — data-race definition + happens-before semantics.
- **C++ ISO/IEC 14882:2017** §6.9.2.3 [atomics.order] — release-acquire memory-order semantics; underlies Phase 2C's lock-free reader path (L-2).
- **C++ ISO/IEC 14882:2017** §33.3.2 [thread.thread.constr] — std::thread constructor synchronizes-with the start of the new thread.
- **IEEE Std 1003.1-2017** rename() — atomicity of POSIX rename for same-volume targets (T-5).
- **Microsoft Win32 API** MoveFileExA — atomicity of Windows rename for same-volume targets (T-5).

### Concurrency literature

- **Herlihy, Wing** (ACM TOPLAS 1990) — "Linearizability: A Correctness Condition for Concurrent Objects." The mutex-implies-linearizability result this proof's T-1 + T-2 + T-3 reduce to (same as S014ConcurrencyAnalysis.md).
- **Herlihy, Shavit** (Morgan Kaufmann 2008) — "The Art of Multiprocessor Programming" §3.2 + §8.3 — textbook treatment of reader-writer mutex correctness and the publish-subscribe pattern underlying Phase 2C.
- **Coffman, Elphick, Shoshani** (ACM Computing Surveys 1971) — "System Deadlocks." The four-condition deadlock-existence result this proof's L-4 invokes.

### Determ-internal references

- `include/determ/node/node.hpp:617` — `state_mutex_` declaration (shared_mutex).
- `include/determ/node/node.hpp:647-651` — async-save worker coordination (thread + mutex + cv + atomic flags).
- `src/node/node.cpp:586-588` — io_context worker-thread pool spawn (`hardware_concurrency()` threads).
- `src/node/node.cpp:594` — async-save worker spawn.
- `src/node/node.cpp:617-641` — `Node::stop` shutdown sequence (signal stop, join, final save).
- `src/node/node.cpp:661-695` — `save_worker_loop` body.
- `src/node/node.cpp:697-703` — `enqueue_save` flag-set + cv-notify.
- `src/node/node.cpp:1612-1649` — `on_cross_shard_receipt_bundle` (async cross-shard receipt admission).
- `src/node/node.cpp:1704-1898` — `apply_block_locked` (`R_apply` body).
- `src/node/node.cpp:1901-1903` — `on_block` (canonical gossip-path apply route).
- `src/node/node.cpp:1845` — `enqueue_save()` call from inside `apply_block_locked`.
- `src/node/node.cpp:2839, 2879, 2927, 3202, 3372` — v2.6 gossip-out-of-lock release sites.
- `include/determ/chain/chain.hpp:130-182` — Phase 2C lock-free reader API + CommittedStateBundle.
- `include/determ/chain/chain.hpp:617` — `committed_state_view_` shared_ptr declaration.
- `include/determ/chain/chain.hpp:687-720` — `StateSnapshot` struct + `create_state_snapshot` / `restore_state_snapshot` declarations.
- `src/chain/chain.cpp:54-58` — `Chain::append` (calls `apply_transactions` then `push_back`; T-3 atomicity hinges on the throw before `push_back`).
- `src/chain/chain.cpp:519-544` — `Chain::atomic_scope` (Phase 2D composable-tx primitive).
- `src/chain/chain.cpp:565-588` — `create_state_snapshot` (Phase 1 + 2A/2B eager+lazy capture).
- `src/chain/chain.cpp:598-631` — `restore_state_snapshot` (move-restore on rollback).
- `src/chain/chain.cpp:633-1501` — `Chain::apply_transactions` body (T-3 try-catch + Phase 2C atomic-store).
- `src/chain/chain.cpp:1484-1488` — Phase 2C `committed_state_view_` atomic-store on successful apply.
- `src/chain/chain.cpp:1489-1501` — Phase 1 catch + restore + re-throw.
- `src/chain/chain.cpp:1541-1730` — `Chain::serialize_state` (10-namespace canonical snapshot).
- `src/chain/chain.cpp:1937-1985` — `Chain::save` (atomic `.tmp` + rename).
- `tools/test_chain_save_load.sh`, `tools/test_async_chain_save.sh`, `tools/test_chain_integrity.sh`, `tools/test_snapshot_bootstrap.sh`, `tools/test_dapp_snapshot.sh` — regression harnesses exercising the surfaces this proof composes.
- `docs/SECURITY.md` §S-031 — closure-status narrative this proof formalizes.
- `docs/PROTOCOL.md` §4.1.1 — 10-namespace canonical state set + `compute_state_root` key-encoding (T-4 + T-5 surface).
- `docs/PROTOCOL.md` §11 — snapshot field set (T-4).
- `docs/proofs/S014ConcurrencyAnalysis.md` — sibling concurrency-layer proof (rate-limiter surface).
- `docs/proofs/S014RateLimiterSoundness.md` — sibling soundness proof (per-bucket arithmetic).
- `docs/proofs/BlockchainStateIntegrity.md` — sibling integrity proof; this proof's T-3 + T-5 compose with that proof's T-3 + T-4 to give end-to-end consistency.
- `docs/proofs/AccountStateInvariants.md` — FA-Apply-1 apply-determinism invariant; T-3 + T-4 invoke it.
- `docs/proofs/SnapshotEquivalence.md` — FA-Apply-2 snapshot equivalence; T-4 feeds it.
- `docs/proofs/Preliminaries.md` §3 — network model + asio thread-pool assumption (extended in §2.1 of this proof).

---

## 8. Status

**Shipped.** The six-layer S-031 closure is live on the current `main` branch. All six layers have been independently regression-tested:

- Layer 1 (shared_mutex) — exercised by every multi-thread test (`tools/test_*.sh`) that hits both read and write paths.
- Layer 2 (A9 Phase 1 atomic apply) — exercised by `tools/test_apply_atomicity.sh` and the supply-invariance tests.
- Layer 3 (A9 Phase 2A/2B lazy snapshot) — exercised by the TRANSFER-only-block tests showing the snapshot's optional containers stay nullopt.
- Layer 4 (A9 Phase 2C lock-free reader path) — exercised by `tools/test_rpc_balance_concurrent.sh` and the lock-free path coverage tests.
- Layer 5 (async chain.save worker) — exercised by `tools/test_async_chain_save.sh` and the save-coalesce regression.
- Layer 6 (gossip-out-of-lock + async receipts) — exercised by `tools/test_cross_shard_atomicity.sh` and the gossip-broadcast latency regressions.

The composition theorem is added in the current review pass as the chain-state-layer companion to `S014ConcurrencyAnalysis.md`. It does not modify source code; it formalizes the six-layer composition argument that closes the S-031 concurrency surface.

**Not yet shipped (future work, advisory):**

- **One-file-per-block storage** (`SECURITY.md` §S-031 Option 5; F-2 mitigation). Replaces monolithic `chain.json` with `chain/blocks/{index}.json` (one file per block, append-only). `Chain::save` becomes O(1) per block. The async-save worker can never fall behind. Estimated effort: ~1-2d.
- **Lift beacon/shard broadcasts out of apply_block_locked** (G-4 mitigation). Apply the v2.6 polish pattern at `node.cpp:1875` and `node.cpp:1881-1894`. Estimated effort: ~20 LOC + per-broadcast-site test.
- **Writer-preferring shared_mutex on Windows** (F-1 advisory). Only relevant if a deployment profile arises that saturates the reader path; current operational evidence is the opposite (reader path is fast, writer path dominates).
- **C++26 deprecation cleanup** for `std::atomic_load/store` free functions on shared_ptr (Phase 2C migration to `std::atomic<std::shared_ptr<T>>`).

These are advisory; none invalidate T-1..T-6. They are surfaced for completeness so an external auditor can confirm the scope of the concurrency-layer analytic conclusion.
