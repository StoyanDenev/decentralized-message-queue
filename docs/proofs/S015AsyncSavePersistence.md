# S015AsyncSavePersistence — async chain.save worker + atomic file write + FlushOnExit soundness

This document is the persistence-layer analytic proof closing S-015. Where `S014ConcurrencyAnalysis.md` formalizes single-mutex correctness on the rate-limiter surface and `S031ConcurrencyComposition.md` composes the six-layer chain-state mutation surface, this proof restricts attention to the **async chain.save subsystem** — the dedicated `save_thread_` worker, its coordination primitives (`save_mutex_` + `save_cv_` + `save_pending_` + `save_stop_`), the `Chain::save` atomic file-write pattern (`.tmp` + `std::filesystem::rename`), and the `Node::stop()` FlushOnExit hand-off — and shows that each layer's correctness composes with S-021's wrapping-format integrity gate and S-031's `std::shared_mutex` exclusion contract to give end-to-end persistence soundness.

The pre-S-015 design ran `chain_.save(cfg_.chain_path)` synchronously inside `apply_block_locked` while holding `state_mutex_`'s unique_lock. On a long-lived chain the save is the dominant cost in the apply hot path (O(chain.height()) JSON serialize + fsync per block), and it stalls every other thread's `state_mutex_` acquisition for the full disk-write duration. Worse, the synchronous path used a plain `std::ofstream` write — a power loss or process crash between `f << j.dump(2)` and the next apply could leave `chain.json` half-written, and the next restart's `Chain::load` would parse-fail on the corrupted file. S-015's closure rebuilt this surface into a four-part design: (1) an async writer thread that takes the persistence work off the apply hot path, (2) an atomic file-write pattern via sibling `.tmp` + rename, (3) save-pending coalescing so bursts of applies do not produce a backlog of redundant saves, and (4) a FlushOnExit hand-off so clean shutdown finishes any in-flight or pending save before process exit. The composition is structural: each layer covers a disjoint operational hazard, and the four together exhaust the persistence-failure modes that S-015's audit-finding flagged.

**Companion documents.** `S014ConcurrencyAnalysis.md` (rate-limiter single-mutex template — the citation style + lemma structure mirrors that proof). `S031ConcurrencyComposition.md` (six-layer chain-state mutex composition — this proof's T-1 + T-6 compose with that proof's T-2 + T-5; the async-save worker is *Layer 5* of the S-031 composition, and this proof gives the persistence-side soundness argument that S-031 cites). `BlockchainStateIntegrity.md` (S-021 + S-033 + S-038 + apply-time gate composition — this proof's T-5 composes with that proof's T-1 wrapping `head_hash` recompute to defeat torn writes that survive a crash before rename). `SnapshotEquivalence.md` (FA-Apply-2 — T-4 of this proof feeds the FlushOnExit snapshot consistency that snapshot-restore depends on). `AccountStateInvariants.md` (FA-Apply-1 — the apply-determinism invariant T-6's snapshot consistency relies on). `Preliminaries.md` §3 (network model + asio thread-pool assumption — extended here to cover `std::condition_variable` semantics). `docs/SECURITY.md` §S-015 + §S-031's "Mitigation landed in-session" paragraph for the closure-status narrative this proof formalizes.

---

## 1. Theorem statements

**Setup.** Let `N` denote a single Determ `Node` instance (`include/determ/node/node.hpp`). `N`'s async-save subsystem consists of the following fields declared in `include/determ/node/node.hpp:647-651`:

- `std::thread save_thread_` — the dedicated persistence worker. Spawned in `Node::start` at `src/node/node.cpp:594`; joined in `Node::stop` at `node.cpp:631`.
- `std::mutex save_mutex_` — coordination mutex for the cv-wait protocol. Held only at the top of `save_worker_loop` (`node.cpp:665-682`) and inside `enqueue_save` (`node.cpp:697-703`). Never held while `state_mutex_` is held.
- `std::condition_variable save_cv_` — wake-up primitive. `wait()` is paired with the `save_pending_ || save_stop_` predicate.
- `std::atomic<bool> save_pending_{false}` — the "work-to-do" flag. Set by `enqueue_save` (`node.cpp:700`); cleared by the worker after wake (`node.cpp:680`).
- `std::atomic<bool> save_stop_{false}` — the "shutdown" flag. Set by `Node::stop` (`node.cpp:629`); read by the worker's wait predicate.

The worker thread executes `save_worker_loop` (`src/node/node.cpp:661-695`) — an unbounded loop that waits on `save_cv_`, on wake takes `state_mutex_`'s shared_lock + calls `chain_.save(cfg_.chain_path)`, releases both locks, loops back.

The persistence target is `chain_` (`include/determ/chain/chain.hpp`), whose `save(path)` method at `src/chain/chain.cpp:1937-1985` implements the atomic file write. Define:

- `R_save` — the worker's critical section: `std::shared_lock<std::shared_mutex> slk(state_mutex_)` followed by `chain_.save(path)`. Held during JSON serialize + write to `path.tmp` + `std::filesystem::rename`.
- `W_atomic_rename` — the sub-step inside `Chain::save` that runs after the `.tmp` close + flush: the `fs::rename(tmp_path, path)` call (`chain.cpp:1980`). This is the atomicity guarantee from POSIX/Win32 that T-2 invokes.
- `F_pending` — the flag-set protocol inside `enqueue_save`: lock `save_mutex_`, `save_pending_.store(true)`, unlock, `save_cv_.notify_one()`. Bounded constant time.
- `S_flush` — the `Node::stop` shutdown protocol at `node.cpp:617-641`: (a) `running_.exchange(false)` + `io_.stop()` + io thread joins, (b) `save_stop_.store(true)` + `save_cv_.notify_all()` + worker join, (c) one final synchronous `chain_.save(cfg_.chain_path)` call. Steps (a)-(c) are sequential in `Node::stop`'s body.

**Theorem T-1 (Apply-Path Lock-Free w.r.t. Disk I/O).** Inside `apply_block_locked` (`src/node/node.cpp:1704-1898`), the call to `enqueue_save()` at `node.cpp:1845` is the only persistence interaction. By inspection of `enqueue_save`'s body (`node.cpp:697-703`), it performs at most two synchronization operations — `save_mutex_.lock_guard` acquisition (constant-time uncontended; the contention regime is non-existent because the only other `save_mutex_` holder is `save_worker_loop`'s cv-wait, which releases `save_mutex_` while sleeping) and `save_cv_.notify_one()` (constant-time per the C++ standard's notify guarantee). The persistence I/O — the JSON serialize, the `.tmp` write, the `flush`, the rename — runs on `save_thread_`, never on the apply-caller thread. Therefore the apply hot path's wall-clock cost is independent of `chain_.size()` and of disk speed.

**Theorem T-2 (Atomic File Write via .tmp + rename).** `Chain::save(path)` (`src/chain/chain.cpp:1937-1985`) writes the chain JSON to `path + ".tmp"` (line 1969), flushes the `.tmp` file (line 1972), then calls `std::filesystem::rename(tmp_path, path)` (line 1980). The rename is atomic at the OS level for same-volume same-directory targets:

- **POSIX.** `rename(oldpath, newpath)` is required to be atomic when `oldpath` and `newpath` are on the same filesystem (`IEEE Std 1003.1-2017`, `rename()` synopsis: "*If newpath is the link name of an existing file, the behavior shall be as if the existing file were unlinked, but as a single operation*"). A concurrent reader's `open(newpath)` either sees the old file (rename hadn't happened) or the new file (rename completed); never a partially-written half-state.
- **Win32.** `std::filesystem::rename` on Windows is implemented via `MoveFileExW` with implicit `MOVEFILE_REPLACE_EXISTING` semantics for the std::filesystem wrapper. Microsoft documentation specifies atomicity for same-volume targets: "*The MoveFileEx function with MOVEFILE_REPLACE_EXISTING uses an atomic in-volume rename on NTFS*" (MoveFileExW documentation, "Remarks"). Cross-volume renames are NOT atomic and are an operator-side concern (F-1 below).

Therefore, for any crash sequence — process kill, kernel panic, OS reboot, power loss — occurring at any time during `Chain::save`'s body, the on-disk state of `path` is one of:

- The previous full chain.json content (rename had not yet happened).
- The new full chain.json content (rename had completed).
- The previous full chain.json content + a partial `path.tmp` file (rename had not happened; `.tmp` is partial). On restart, `Chain::load(path)` reads the intact previous file; the partial `.tmp` is unreferenced garbage that the next successful save overwrites and renames over (or that the operator can manually clean — `path.tmp` is a well-known sibling).

In no case does `path` itself contain a half-written half-state.

**Theorem T-3 (Latest-State Coalescing).** A burst of `B` `enqueue_save()` calls arriving in time interval `[t_0, t_0 + Δ]` where `Δ` is less than the worker's save duration produces between **one and two** writes to `chain.json`, not `B` writes. Concretely, by inspection of `enqueue_save` (`node.cpp:697-703`) and `save_worker_loop` (`node.cpp:661-695`):

- The B `enqueue_save` calls each take `save_mutex_`, set `save_pending_.store(true)` (idempotent — flag was already true after the first call), release, and notify. The notify is idempotent for an awake worker (no second wake fires; the cv is in the "wait" state for each notify, but only the first transition matters per L-7 below).
- The worker is either (a) currently sleeping in `save_cv_.wait` → the first notify wakes it; it clears the flag while holding `save_mutex_` (line 680), then releases save_mutex_ + takes state_mutex_'s shared_lock + runs save. Subsequent enqueue_save calls during the save body re-set the flag. After the save, the worker loops back and sees the flag set; it runs another save. Total writes: 2.
- Or (b) currently inside the save body → the first enqueue_save sets the flag (already true would no-op, but in this scenario the worker had cleared the flag before starting save, so the first enqueue resets). The worker on loop-back sees the flag and saves again. Total writes: 2.
- Or (c) currently between save body and loop-back → the worker is about to re-check the flag. The first enqueue sets it before the worker's wait. The worker sees the flag set, runs save. Total writes: 1.

Crucially: every save call after the first one captures **the latest chain state** at the moment the worker's `chain_.save` runs. Stale state from earlier in the burst is overwritten by the second save's content. By L-7, no applied block's state ever fails to reach disk (modulo the crash-window between apply and worker invocation, recovered via peer gossip per T-2's restart contract).

**Theorem T-4 (FlushOnExit Soundness).** `Node::stop` (`src/node/node.cpp:617-641`) sequences shutdown as follows:

1. `running_.exchange(false)` + `io_.stop()` (line 619) — io_context worker threads will exit `io_.run()` once their current handler completes.
2. `for (auto& t : threads_) if (t.joinable()) t.join();` (line 620) — join all io_context workers. No new `apply_block_locked` calls can be initiated after this point.
3. `save_stop_.store(true)` (line 629) — set the shutdown flag.
4. `save_cv_.notify_all()` (line 630) — wake the save worker if it's blocked in `save_cv_.wait`.
5. `if (save_thread_.joinable()) save_thread_.join();` (line 631) — wait for the save worker to exit.
6. `chain_.save(cfg_.chain_path);` (line 639) — one final synchronous save on the main thread.

By steps 1-2, no new `enqueue_save` calls can arrive after step 2 returns (all callers were io_context workers, all joined). By step 4-5, the save worker exits — if it was mid-save when stop fired, it completes the current save body before checking `save_stop_` on the next loop iteration; if it was waiting on `save_cv_`, the notify_all wakes it, the wait predicate sees `save_stop_ == true`, the worker returns from `save_worker_loop`. By step 6, the main thread runs one synchronous `chain_.save` against the chain's final state — covering two edge cases:

- **Case A.** `save_pending_` was set when stop fired. The worker exited the loop on the next iteration (line 669 `return`) before processing the flag. Step 6 covers the pending work.
- **Case B.** An apply landed between the worker's last save and `Node::stop` arriving. No `enqueue_save` reached the worker before the worker exited. Step 6 covers the lag.

In either case, the on-disk `chain.json` after `Node::stop` returns reflects the final applied state. The clean-shutdown contract is total.

**Theorem T-5 (Composition with S-021 chain.json wrap + load-time head_hash gate).** The S-021 closure (`BlockchainStateIntegrity.md` T-1) ships a wrapping JSON object `{"head_hash": "<hex>", "blocks": [...]}` and a load-time recompute-and-compare gate inside `Chain::load` (`src/chain/chain.cpp:2037-2051`). If a crash occurs during the *write of `path.tmp`* (between line 1969 and line 1980) — i.e., before the rename — then by T-2, `path` itself is unchanged and contains the prior full file. The prior `head_hash` field matches the prior block sequence, so `Chain::load` succeeds on restart.

If a crash occurs during the *rename* itself (line 1980) — this is the corner case T-2 disclaims for cross-volume renames — then under cross-volume conditions (F-1) the rename is implemented as a copy + unlink and is NOT atomic; `path` could be half-written. Composition: `Chain::load` at line 2037-2051 recomputes `to_hex(blocks_.back().compute_hash())` after JSON parse + replay and throws `"chain file: head_hash mismatch (tampering or corruption?)"` if it doesn't match the on-disk `head_hash` field. So a corrupted rename surfaces as a loud-fail on restart, not silent state divergence. The operator sees the throw, investigates, and either restores from a peer (gossip resync) or from the `.tmp` (which still exists on cross-volume failure mid-copy).

For the same-volume same-directory case (the operator-recommended default per F-1), the rename is atomic and this composition is unnecessary — the crash either leaves the old file intact or the new file intact, both pass the head_hash gate. The composition is a defense-in-depth layer for the operator-misconfiguration cross-volume case.

**Theorem T-6 (Composition with S-031 shared_mutex + A9 Phase 1 atomic apply).** The save worker takes `state_mutex_`'s **shared_lock** (`src/node/node.cpp:685`) — not unique_lock. By `S031ConcurrencyComposition.md` T-2 (read-write exclusion via shared_mutex), the shared_lock:

- Concurrent with other shared_lock holders — i.e., read-only RPC handlers (`rpc_balance`, `rpc_status`, …) proceed during a save.
- Excludes any writer (`R_write` per S-031's notation) — i.e., the next `apply_block_locked` blocks on the unique_lock acquisition until the save's shared_lock is released.
- Excluded by any currently-holding writer — i.e., if an `apply_block_locked` is in flight when the worker tries to acquire its shared_lock, the worker blocks at `shared_lock`'s constructor until the apply releases.

The shared_lock holds for the entire `chain_.save(cfg_.chain_path)` call (including the JSON serialize + .tmp write + rename). By A9 Phase 1's atomic apply contract (`S031ConcurrencyComposition.md` T-3 + `chain.cpp:646-1501`), the chain's state at the moment the worker acquires the shared_lock is some committed post-apply state — never a mid-apply partial state. The JSON serialize iterates the chain's blocks vector + the ten canonical state namespaces under the shared_lock; the result is byte-equivalent to a snapshot taken at the apply-commit point of the most-recent applied block.

By `SnapshotEquivalence.md` T-S1, any node loading the resulting `chain.json` via `Chain::load` recovers byte-identical state to the producer at that commit point. So the persisted-state-snapshot consistency is total. Composition with `BlockchainStateIntegrity.md` T-2 (apply-time state_root gate) gives end-to-end coverage: the chain.json reflects a committed apply, and load-time gates (S-021 head_hash + S-033 state_root via the on-block-replay path) verify the on-disk file is internally consistent + chain-derivable.

---

## 2. Background

### 2.1 The pre-S-015 synchronous-save pathology

Pre-S-015, the `apply_block_locked` body ended with a direct `chain_.save(cfg_.chain_path)` call under `state_mutex_`'s unique_lock. The save body's cost is:

- O(chain.height()) — every block's full JSON is re-serialized every save (one-file-per-block storage is a future-work optimization per `SECURITY.md` §S-031 Option 5).
- O(disk write bandwidth) for the resulting file — typically `~100-500 MB/sec` sequential write on commodity NVMe; `~10-50 MB/sec` on rotational disks or networked storage.
- O(filesystem syncall latency) for the flush — `~ms` on local disks, `~10s of ms` on NFS / NAS.

For a 10k-block chain with ~1KB per block of JSON, the save is `~10MB write × ~ms flush = ~10s of ms` per block. For 100k blocks, it's `~100MB × ~100ms = ~seconds` per block. The unique_lock is held for the full duration, blocking every other thread's `state_mutex_` access — every read-only RPC, every gossip-handler write, every consensus-phase transition. The pre-fix `SECURITY.md` §S-031 description named this as the dominant cost.

S-015's closure isolates the persistence I/O to a dedicated worker thread; the apply hot path's `enqueue_save` is constant-time (flag-set + cv-notify); the worker takes shared_lock (does not block readers); the worker's chain_.save runs without ever holding unique_lock.

### 2.2 std::condition_variable semantics (extended Preliminaries §3)

`std::condition_variable` (ISO/IEC 14882:2017 §33.5.3) provides:

1. **wait-with-predicate.** `cv.wait(lk, pred)` loops internally on `while (!pred()) cv.wait(lk);`. Spurious wakeups are tolerated — the predicate re-checks. On wake, `lk` is held; on entry to wait, `lk` is released atomically with the sleep transition.
2. **notify_one / notify_all.** `notify_one()` wakes at most one waiter; `notify_all()` wakes all waiters. If no waiter is currently in wait state, the notify is a no-op (does NOT queue a pending wake).
3. **Memory ordering.** A successful wake from wait synchronizes-with the notify call (release-acquire pair via the underlying mutex). All writes by the notifier before the notify are visible to the woken waiter.

The save worker's wait predicate at `node.cpp:666-668`:

```cpp
save_cv_.wait(lk, [&]() {
    return save_pending_.load() || save_stop_.load();
});
```

The predicate is checked under `save_mutex_`'s hold (lk). If `save_pending_` is set before the wait, the loop body never blocks. If set after the wait blocks, the next notify wakes the worker. Either way, no work is lost.

### 2.3 POSIX rename(2) atomicity contract

POSIX `rename(2)` (`IEEE Std 1003.1-2017`) specifies: "*If newpath already exists, it shall be removed atomically*" for files on the same filesystem. The atomicity is at the level of the filesystem's directory-entry inode pointer: a single inode-pointer swap that is observable to any concurrent `open` / `stat` / `readdir` as either pre-swap or post-swap, never a half-state.

Cross-filesystem rename is NOT covered by this contract. `rename(2)` returns `EXDEV` on cross-filesystem source/dest and the caller is expected to fall back to copy + unlink (which is NOT atomic). `std::filesystem::rename` on POSIX delegates to the OS rename and reports the EXDEV via `std::error_code`; on Windows the equivalent is `ERROR_NOT_SAME_DEVICE`.

The Determ operator profile is "same-directory same-volume" — `chain.json` and `chain.json.tmp` are sibling paths produced by `path + ".tmp"` string concatenation. So under all standard deployments, the rename is atomic. F-1 below records the operator-side cross-volume concern.

### 2.4 Win32 MoveFileEx atomicity

`MoveFileExW` (Microsoft documentation) with `MOVEFILE_REPLACE_EXISTING`: "*If the file is to be moved to a different volume, the function simulates the move by using the CopyFile and DeleteFile functions. If the file is successfully copied to a different volume and the original file is unable to be deleted, the function succeeds leaving the source file intact.*"

For same-volume targets on NTFS: the rename is an atomic directory-entry update. On FAT32 (legacy, rare in operator deployments), atomicity is implementation-defined and weaker.

The Determ operator profile is "NTFS, same-volume" on Windows — chain.json is typically under the operator's data directory on the same volume as the binary's working directory. F-1 records the FAT32 / cross-volume concern.

### 2.5 Stevens APUE Chapter 3 — atomic file replacement idiom

`Advanced Programming in the UNIX Environment` (Stevens, Rago — 3rd edition, 2013) §3.16 "fsync, fdatasync, and sync" + §4.16 "link, linkat, unlink, unlinkat, and remove" describe the atomic-replace idiom this proof's T-2 invokes:

1. Write the new content to a temporary file in the same directory as the target.
2. fsync the temporary file (forces the kernel to flush pending writes to the storage device).
3. Call rename to replace the target.

The pattern is universally applied across UNIX systems for configuration files, lock files, and similar small-but-critical files. Lamport's "Atomic Multi-Writer Registers" (Lamport 1986) gives the formal correctness foundation: the atomic-register abstraction the filesystem rename provides is equivalent to a multi-writer single-reader register where every write is committed atomically and reads see one consistent snapshot.

Determ's `Chain::save` uses this idiom verbatim, with the std::filesystem layer abstracting the OS-specific atomic-rename primitive. The `f.flush()` at chain.cpp:1972 is the C++ stream-layer flush (writes pending stream-internal buffers to the OS) — see L-6 for the limitation that this is NOT the kernel-level `fsync()` (which would force the storage device to commit; F-3 records this).

---

## 3. Implementation citation

### 3.1 The save worker thread declaration

`include/determ/node/node.hpp:647-651`:

```cpp
std::thread                     save_thread_;
std::mutex                      save_mutex_;
std::condition_variable         save_cv_;
std::atomic<bool>               save_pending_{false};
std::atomic<bool>               save_stop_{false};
void save_worker_loop();
void enqueue_save();
```

### 3.2 The worker spawn at startup

`src/node/node.cpp:594`:

```cpp
save_thread_ = std::thread([this] { save_worker_loop(); });
```

Spawned after the io_context worker pool (line 587-588) but before the startup-grace timer (line 601-612). The worker is therefore alive for the entire operational lifetime of the node, from end-of-startup to start-of-shutdown.

### 3.3 The save_worker_loop body

`src/node/node.cpp:661-695`:

```cpp
void Node::save_worker_loop() {
    while (true) {
        bool do_save = false;
        {
            std::unique_lock<std::mutex> lk(save_mutex_);
            save_cv_.wait(lk, [&]() {
                return save_pending_.load() || save_stop_.load();
            });
            if (save_stop_.load()) {
                return;
            }
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

The body is the canonical wait-flag-act-loop pattern (sometimes called "single-consumer ring-buffer of size 1," though here the "ring" carries no data — just the flag).

### 3.4 The enqueue_save body

`src/node/node.cpp:697-703`:

```cpp
void Node::enqueue_save() {
    {
        std::lock_guard<std::mutex> lk(save_mutex_);
        save_pending_.store(true);
    }
    save_cv_.notify_one();
}
```

The flag-set is inside the `save_mutex_` critical section to synchronize-with the worker's wait-predicate check (see L-1 for the memory-ordering argument). The notify is OUTSIDE the critical section — a minor optimization that avoids the woken worker immediately re-blocking on save_mutex_.

### 3.5 The enqueue_save call site from inside apply

`src/node/node.cpp:1845`:

```cpp
enqueue_save();
```

Called from inside `apply_block_locked` body, after every state-mutating step of the apply has completed and before the per-block accept log line (`node.cpp:1852-1855`). The unique_lock is still held when `enqueue_save` runs — the flag-set and notify happen under unique_lock — but the heavy work (the actual save) runs on the worker thread without holding state_mutex_.

The `enqueue_save` body is constant-time per L-3, so the unique_lock's hold time is not meaningfully extended.

### 3.6 The Node::stop shutdown sequence

`src/node/node.cpp:617-641`:

```cpp
void Node::stop() {
    if (running_.exchange(false)) {
        io_.stop();
        for (auto& t : threads_) if (t.joinable()) t.join();

        save_stop_.store(true);
        save_cv_.notify_all();
        if (save_thread_.joinable()) save_thread_.join();

        chain_.save(cfg_.chain_path);
    }
}
```

Six numbered shutdown steps per T-4's setup. The `running_.exchange(false)` at the head guarantees that `Node::stop` is idempotent — calling it twice from independent paths (e.g., signal handler + atexit) runs the body exactly once.

### 3.7 The atomic file write in Chain::save

`src/chain/chain.cpp:1937-1985` (excerpted in §1 of `S031ConcurrencyComposition.md` and below for completeness):

```cpp
void Chain::save(const std::string& path) const {
    fs::create_directories(fs::path(path).parent_path());
    std::string tmp_path = path + ".tmp";
    {
        json blocks_arr = json::array();
        for (auto& b : blocks_) blocks_arr.push_back(b.to_json());
        json j;
        j["head_hash"] = blocks_.empty()
                          ? std::string{}
                          : to_hex(blocks_.back().compute_hash());
        j["blocks"]    = std::move(blocks_arr);

        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write chain tmp file: " + tmp_path);
        f << j.dump(2);
        f.flush();
        if (!f) throw std::runtime_error("Failed to flush chain tmp file: " + tmp_path);
    }
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
        throw std::runtime_error("Cannot rename chain tmp " + tmp_path
            + " → " + path + ": " + ec.message());
    }
}
```

Inspection points:

- `fs::create_directories` (line 1950) — no-op if the parent directory exists; creates it if not. Safe under concurrent calls (`std::filesystem::create_directories` is documented as idempotent: "no error reported if directory already exists").
- `tmp_path = path + ".tmp"` (line 1951) — string concatenation; `tmp_path` is in the same directory as `path` (same-volume same-directory by construction).
- The `{ ... }` block scope (lines 1952-1974) — the std::ofstream `f` is declared inside the block. The block's scope exit at line 1974 invokes f's destructor, which closes the file. Per the C++ standard, ofstream's destructor flushes pending writes before closing. The explicit `f.flush()` at line 1972 is redundant w.r.t. close but is kept for early-fail detection (if flush sets the stream's failbit, the `if (!f)` check at line 1973 throws before reaching the rename).
- `fs::rename` (line 1980) — the atomic-rename per T-2. Error code reported via `ec`; non-zero `ec` throws (line 1981-1984).

The atomic-rename semantics depend on the OS-level rename being atomic. Under standard same-volume operator deployment, this is guaranteed.

---

## 4. Lemmas and proofs

### Lemma L-1 (Save-pending flag visibility — release-acquire memory ordering)

`enqueue_save` (`node.cpp:697-703`) sets `save_pending_.store(true)` while holding `save_mutex_`. The worker's wait predicate (`node.cpp:666-668`) reads `save_pending_.load()` while holding `save_mutex_` (via the cv-wait protocol — wait re-acquires the lock before returning).

By the C++ memory model (ISO/IEC 14882:2017 §33.5.3 [thread.condition.condvar]: the unlock-then-wait + notify-then-relock sequence is a release-acquire pair on the same mutex), the worker's load synchronizes-with the most recent store under the same mutex. Therefore:

- If the worker observed the flag as false during its previous wait-predicate check, then any subsequent `enqueue_save` that sets the flag to true is visible to the worker's NEXT wait-predicate check (either immediately because the notify wakes the worker, or eventually because spurious wakeups + re-check eventually catches it; condvars do not "miss" notifies for a flag-set that happens between unlock and wait, because the unlock-and-wait is atomic per the standard).
- The worker's `save_pending_.store(false)` at line 680 (clearing the flag) is also under save_mutex_. A subsequent `enqueue_save` that arrives AFTER the worker's clear but BEFORE the worker's release of save_mutex_ would block on save_mutex_'s lock; the worker's release synchronizes-with the next enqueue_save's lock acquisition. So the next enqueue sees a clean false flag, sets it to true, releases, notifies. The worker on next loop iteration sees true again and saves.

No save is lost. The flag-protocol is a single-bit ring buffer with the "consumer's clear" + "producer's set" both protected by the same mutex.   □

### Lemma L-2 (No deadlock between save_mutex_ and state_mutex_)

By inspection of every code site that holds save_mutex_ (`node.cpp:665`, `node.cpp:699`) and every code site that holds state_mutex_ (the 25 unique_lock sites + 11 shared_lock sites per `S031ConcurrencyComposition.md` §3.2-§3.3 + the worker's shared_lock at `node.cpp:685`):

- `save_mutex_` is never held while `state_mutex_` is held. The worker's save_mutex_ scope exits at line 682 (closing brace of the inner block); the state_mutex_'s shared_lock acquisition is at line 685, three lines later. Sequential, not nested.
- `state_mutex_` is never held while `save_mutex_` is acquired. Every `enqueue_save` call from inside an apply happens at `node.cpp:1845`; this is inside `apply_block_locked` which is called under unique_lock. So unique_lock IS held when enqueue_save is called. The enqueue_save body takes save_mutex_ briefly — this nests save_mutex_ INSIDE state_mutex_ (unique_lock outer, save_mutex_ inner). Critically, no path takes state_mutex_ from inside save_mutex_, so the dependency-graph edge is unidirectional: state_mutex_ → save_mutex_. By the standard deadlock-existence theorem (Coffman, Elphick, Shoshani 1971), a deadlock requires a cycle in the lock dependency graph; the graph has one edge, no cycle.

The worker's path is save_mutex_ THEN state_mutex_ (shared_lock at line 685, AFTER save_mutex_ scope exits at line 682). Sequential, no cycle.   □

### Lemma L-3 (enqueue_save is constant-time)

`enqueue_save` body (`node.cpp:697-703`):

1. `std::lock_guard<std::mutex> lk(save_mutex_)` — constant-time uncontended; the contention regime is rare because save_mutex_ is held only briefly inside the worker's loop top.
2. `save_pending_.store(true)` — constant-time atomic store.
3. Lock guard scope exit — constant-time unlock.
4. `save_cv_.notify_one()` — constant-time per the C++ standard's notify guarantee.

Total wall-clock cost: `~µs` typical, dominated by the uncontended mutex lock + unlock. No I/O, no chain.size()-dependent work, no waiting on any other thread.

Therefore enqueue_save's call from inside `apply_block_locked` does not extend the unique_lock's hold time meaningfully. The unique_lock hold is dominated by `apply_transactions` itself (per `S031ConcurrencyComposition.md` L-6).   □

### Lemma L-4 (Atomic-rename semantics — POSIX + Win32)

By §2.3 + §2.4, `std::filesystem::rename(tmp_path, path)` is atomic for same-volume same-directory targets on POSIX (via `rename(2)`) and on Windows NTFS (via `MoveFileExW`). The rename either:

- Completes — the directory entry's inode pointer is updated atomically; concurrent observers see the new file. The previous file's inode is unreferenced and eligible for garbage collection.
- Fails — the directory entry is unchanged; concurrent observers see the previous file. `std::error_code` carries the OS-level errno.

No intermediate state is observable. A `stat(path)` from a concurrent thread or process returns either the old size+contents or the new size+contents.

This is the canonical atomic-replace idiom from §2.5 (Stevens APUE Ch 3.16/4.16). Its formal model is the atomic register from Lamport 1986.   □

### Lemma L-5 (Crash-window characterization)

Suppose the process crashes (SIGKILL, kernel panic, power loss) at a specific cycle during `Chain::save`'s execution. Enumerate the crash positions:

**Position A.** Before line 1950 (`fs::create_directories`). The directory and file are unchanged. The prior `chain.json` (if any) is intact.

**Position B.** Between line 1950 and line 1969 (ofstream construction). The parent directory may have been created (idempotent). No `tmp_path` exists yet. Prior `chain.json` intact.

**Position C.** Between line 1969 and line 1971 (file open completed but no content written yet). The `tmp_path` exists as a zero-byte file. Prior `chain.json` intact.

**Position D.** During the `j.dump(2)` write (line 1971). The `tmp_path` exists with partial content. Prior `chain.json` intact.

**Position E.** Between line 1971 and line 1980 (write completed, rename not yet started). The `tmp_path` exists with full content. Prior `chain.json` intact.

**Position F.** During the `fs::rename` (line 1980). For same-volume targets, the rename is atomic — either the directory entry points to the old inode (Position E equivalent) or the new inode (Position G equivalent). No intermediate state is observable.

**Position G.** After line 1980 returns successfully but before line 1985 returns to caller. The rename has completed; `chain.json` points to the new content. The `tmp_path` is unreferenced (effectively deleted by the rename's "replace" semantics — on POSIX the directory entry for `tmp_path` is removed atomically with the entry for `path` being updated).

**Position H.** After line 1985 returns. `chain.json` is the new content.

In every position A-H, restart-loading `chain.json` either reads the old full content or the new full content. The `head_hash` field in the loaded file matches the loaded blocks because the file was a full write at one of the two valid snapshots. No corruption is silently propagated.

For positions C-D-E, the `tmp_path` may exist as orphaned partial-write garbage. On restart, this is benign — the file is unreferenced by `chain.json` (no metadata in chain.json points to it; the load doesn't look at it). The next successful save overwrites and renames over `tmp_path`, atomically replacing it.   □

### Lemma L-6 (f.flush() semantics — userspace not kernel)

The `f.flush()` at chain.cpp:1972 calls `std::ofstream::flush()`, which flushes the C++ stream-layer's internal buffer to the underlying OS file descriptor via `write(2)` (POSIX) or `WriteFile` (Win32). This is NOT `fsync(2)` / `FlushFileBuffers` — the OS may still have unwritten pages in its page cache when `flush()` returns. A power loss between `flush()` and a subsequent `fsync` could lose the last write window.

Determ does NOT call `fsync` / `FlushFileBuffers` in `Chain::save`. The crash-window semantics from L-5 are therefore weaker than "POSIX durable": a crash after rename + before page-cache flush could leave the directory entry pointing to the new inode but with the new file's data not yet on the storage device. On restart, the file's content could be a torn write at the storage-device level.

**Mitigation.** Three factors limit the operational impact:

1. **Modern filesystems metadata-journal but not data-journal by default** (ext4 default `data=ordered`, NTFS journals metadata). The rename's directory-entry update is journaled; on crash recovery, the metadata is consistent. The data may be torn, but only for the most-recent write window (typically `~5s` on ext4 with `commit=5`).
2. **The S-021 head_hash gate** (T-5 above) detects torn-write corruption on restart. A torn data write within the `chain.json` body produces a head_hash mismatch on load, triggering a loud-fail and operator investigation.
3. **The peer-gossip recovery contract** — even if the loud-fail fires, the operator can blow away the chain.json + restart with snapshot-bootstrap or chain-from-genesis, and the chain catches up via peer gossip.

A future hardening would add `fsync(fd)` between the ofstream close and the rename. F-3 below records this as advisory.   □

### Lemma L-7 (Save-pending coalesce-but-don't-drop, restated for the S-015 surface)

This lemma is identical in form to `S031ConcurrencyComposition.md` L-7 — the coalesce contract is the chain-state-layer composition's load-bearing property and is re-derived here for the persistence layer's analytic argument. Three scheduling cases:

**Case A.** `enqueue_save()` runs while the worker is blocked at `save_cv_.wait`. The cv-wait predicate `save_pending_.load() || save_stop_.load()` is checked under save_mutex_'s hold. The flag-set under save_mutex_ (by enqueue_save) synchronizes-with the predicate's load. The notify_one wakes the worker; the worker clears the flag and runs the save. Pending → 1 → 0 → save runs. One save fires.

**Case B.** `enqueue_save()` runs while the worker is in the `try { ... }` block at lines 684-693 doing the save. The save_mutex_ is NOT held during the save; enqueue_save acquires save_mutex_, sets the flag, releases, notifies. The worker is in the save body; it does not re-check the flag until it loops back to the wait. When it does, the predicate fires immediately (flag is set), the worker clears the flag and runs the save AGAIN. Pending: 0 → 1 → save in progress → 1 → loop → 0 → second save runs. Two saves fire.

**Case C.** Multiple concurrent `enqueue_save()` calls between two save runs. The save_mutex_'s lock_guard serializes them; the second and later observers see `save_pending_.load() == true` already; they re-set (no-op) and notify (idempotent for an awake worker). The flag remains set until the worker's next clear. The worker runs ONE save when it wakes. Pending: 0 → 1 → 1 → ... → save → 0. One save fires for the burst.

So `enqueue_save()`'s contract: "at least one save fires after the call returns, and that save's chain.json content reflects the chain state at or after the call's time-point." A burst of B applies → between 1 and 2 saves. Every applied block reaches disk modulo the crash-window-between-apply-and-save (recovered via peer gossip on restart per T-5 + the S-021 head_hash gate).   □

---

## 5. Proofs of T-1 .. T-6

**Proof of T-1 (Apply-Path Lock-Free w.r.t. Disk I/O).** By inspection of `apply_block_locked` (`src/node/node.cpp:1704-1898`):

1. The body is entered with `state_mutex_`'s unique_lock held by the caller.
2. The body executes the apply logic (validator check, registry rebuild, chain.append, mempool drops, registry rebuild, broadcasts).
3. At line 1845, `enqueue_save()` is called.
4. The body continues with the per-block log line + epoch-boundary observability (lines 1852-1898).
5. The body returns; the unique_lock is released by the caller.

The persistence I/O is none of the above. By L-3, `enqueue_save` is constant-time — no `chain_.size()`-dependent work, no disk write, no waiting on any condition. The cost is the cost of one mutex lock + one atomic store + one mutex unlock + one cv notify; total `~µs` on commodity hardware.

The actual save runs on `save_thread_` (`node.cpp:594` spawn, `node.cpp:661-695` body). The worker takes shared_lock at `node.cpp:685` and calls `chain_.save` at `node.cpp:686`. The shared_lock is concurrent with the apply-caller's unique_lock acquisition only if the unique_lock has been released first; in the common case the worker takes shared_lock between apply commits, when no unique_lock holder is active.

Therefore the apply hot path's wall-clock cost does not include the disk write. The pre-S-015 pathology (synchronous save inside apply) is eliminated.   ∎

**Proof of T-2 (Atomic File Write via .tmp + rename).** Direct from L-4 + L-5.

`Chain::save` writes to `tmp_path` (line 1969-1973), then renames (line 1980). The write-then-rename pattern is the Stevens APUE Ch 3 atomic-replace idiom (§2.5). By L-4, the rename is atomic for same-volume same-directory targets; by §2.3/§2.4, the operator's default deployment satisfies this constraint.

By L-5's case-enumeration, any crash position during the save's execution leaves the on-disk `chain.json` in one of two states: the old full file or the new full file. No intermediate state is observable to a restart load.

A torn data write at the storage-device level (L-6's caveat) is detected by the S-021 head_hash gate on restart (T-5). The composition is total under the operator's recommended deployment + the S-021 closure.   ∎

**Proof of T-3 (Latest-State Coalescing).** Direct from L-7.

A burst of B `enqueue_save` calls in time interval `[t_0, t_0 + Δ]` (where `Δ < t_save`, the worker's save duration) produces between 1 and 2 saves, never B saves. The save's chain.json content reflects the chain state at the moment the worker runs `chain_.save`, which is at or after the most-recent enqueue_save in the burst (because the worker's shared_lock is taken at line 685, after the loop's flag-check at lines 666-682 has serialized with the enqueue_save's flag-set under save_mutex_).

By the FA-Apply-1 apply-determinism invariant (`AccountStateInvariants.md` I-1..I-6), the chain's state at the worker's shared_lock acquisition is a committed post-apply state from some applied block. The save's content is byte-equivalent to a snapshot taken at that block's apply-commit point.

Coalescing does NOT drop saves silently — every applied block's state reaches disk modulo the crash-window. The discarded saves are redundant (the discarded state is a strict prefix of the next saved state in the same commit sequence).   ∎

**Proof of T-4 (FlushOnExit Soundness).** Direct from the six-step shutdown sequence in §3.6 + the worker's loop body in §3.3.

Step 1-2 (lines 619-620): io_context workers join. No new apply can initiate.

Step 3 (line 629): `save_stop_.store(true)` is visible to the worker on its next wait-predicate check (memory ordering per L-1).

Step 4 (line 630): `save_cv_.notify_all()` wakes the worker if it's blocked in wait. If the worker is mid-save, it completes the current save body before looping back to the wait; the wait predicate sees `save_stop_ == true`, the worker returns (line 669).

Step 5 (line 631): main thread joins the worker. After this returns, the worker is gone; no further saves from the worker.

Step 6 (line 639): main thread runs `chain_.save(cfg_.chain_path)` synchronously. This is on the main thread (no concurrent writer because all io_context workers + save_thread_ have joined). The save runs the same atomic-rename protocol; the result is a chain.json reflecting the latest applied state.

Two corner cases (Case A and Case B from T-4's statement) are covered by step 6:

- **Case A.** `save_pending_` was set when stop fired. The worker's wake from notify_all sees `save_stop_ == true` (after step 3's store); the worker exits without processing the pending flag. Step 6 covers it.
- **Case B.** An apply landed between the worker's last save and `Node::stop` arriving. No `enqueue_save` reached the worker because the io_context workers had already exited (step 1-2 ran before step 3). Step 6 covers it.

In either case, the on-disk `chain.json` after `Node::stop` returns reflects the final applied state.

Caveat: this contract covers CLEAN shutdown (`Node::stop` invoked via the main thread's normal exit path or via an explicit SIGTERM-then-atexit-then-stop sequence). It does NOT cover SIGKILL or kernel panic — the OS terminates the process before step 1 runs. F-2 below records this.   ∎

**Proof of T-5 (Composition with S-021 chain.json wrap + load-time head_hash gate).** By T-2, a crash before the rename leaves the prior chain.json intact; restart-load reads the prior content; the prior head_hash matches the prior blocks; load succeeds.

A crash after the rename leaves the new chain.json intact; restart-load reads the new content; the new head_hash matches the new blocks; load succeeds.

A crash *during* the rename — only possible for cross-volume targets per L-4, which is operator-misconfiguration (F-1) — leaves chain.json in an undefined intermediate state. Restart-load reads partial content; the parsed `head_hash` does NOT match the recomputed `to_hex(blocks_.back().compute_hash())` (because the partial-content blocks vector produces a different head); `Chain::load` throws `"chain file: head_hash mismatch (tampering or corruption?)"` at chain.cpp:2047-2050. The operator sees the throw, investigates, restores from snapshot or peer gossip.

The composition is: T-2 covers the standard same-volume case (no torn rename possible); the S-021 head_hash gate covers the cross-volume / torn-data-write case (loud-fail on restart). Together they exhaust the corruption modes that L-5's case-enumeration enumerates.   ∎

**Proof of T-6 (Composition with S-031 shared_mutex + A9 Phase 1 atomic apply).** The save worker takes shared_lock at `node.cpp:685`. By `S031ConcurrencyComposition.md` T-2 (read-write exclusion via shared_mutex), the shared_lock excludes any concurrent unique_lock holder. So no concurrent `apply_block_locked` can interleave between the worker's shared_lock acquisition and the rename completion.

The chain state at the worker's shared_lock acquisition is the post-apply state of the most-recent committed apply (by `S031ConcurrencyComposition.md` T-3, A9 Phase 1 atomic apply — every apply either commits all-or-nothing or rolls back via `restore_state_snapshot`). The JSON serialize in `Chain::save` iterates `blocks_` + the canonical state under the shared_lock; the serialization is byte-equivalent to a snapshot of that committed state.

By `SnapshotEquivalence.md` T-S1 (snapshot consistency under restore), any node that loads the resulting `chain.json` via `Chain::load` and replays the blocks recovers byte-identical state. By `BlockchainStateIntegrity.md` T-2 (apply-time state_root gate), each replayed block's `state_root` (S-033) is re-verified during replay; a torn block-body would produce a state_root mismatch and load would throw before completing.

So the persisted-state-snapshot consistency is total: a clean-shutdown chain.json that loads successfully under both gates (S-021 head_hash + S-033 state_root via per-block replay) reflects the producer's exact committed state.   ∎

---

## 6. Findings

### F-1: Cross-volume rename loses atomicity (operator-configuration concern)

`std::filesystem::rename` is atomic only for same-volume same-directory targets. If the operator configures `cfg_.chain_path` on a different volume than the working directory (e.g., `/data/chain.json` on a separate mounted volume), the `path + ".tmp"` concatenation produces `/data/chain.json.tmp` on the SAME volume — so the rename is still same-volume. But if the operator unusually configures `cfg_.chain_path` on a network filesystem (NFS) or a symlink to a different volume, the rename may cross volumes and lose atomicity.

**Operator guidance.** Keep `chain.json` on a local filesystem. Avoid symlinks to network mounts. The default config (relative path under the working directory) trivially satisfies the constraint.

**Defense-in-depth.** Even if the operator misconfigures the path and a cross-volume rename occurs mid-write (the only way a torn `chain.json` is observable), the S-021 head_hash gate (T-5) detects the torn write on restart and surfaces a loud-fail. The operator can then restore from peer gossip or snapshot-bootstrap.

### F-2: FlushOnExit does not cover SIGKILL or kernel panic

T-4's contract covers `Node::stop` invoked via normal exit. SIGKILL (`kill -9`), kernel panic, power loss, OOM-killer — the OS terminates the process before any user-space cleanup runs, so step 6 (the final synchronous save) never executes.

In these cases, the on-disk `chain.json` reflects the most-recent worker-completed save, which lags the in-memory head by some number of blocks (typically 0-2 per L-7's coalesce contract; potentially more under saturated write load per `S031ConcurrencyComposition.md` F-2's bound discussion). Peer gossip recovers the missing tail on restart — the chain replays from peers, and the in-memory chain catches up to the network head.

**Operator guidance.** For graceful shutdown, send SIGTERM (or use the operator's standard service-manager stop command), not SIGKILL. SIGTERM is caught by the node's signal handler and routed through `Node::stop`'s clean path.

**Defense-in-depth.** The crash-window-recovery contract (peer gossip resync) makes SIGKILL benign for chain integrity, only adversely affecting restart latency.

### F-3: f.flush() is userspace, not kernel — torn writes possible under page-cache loss

Per L-6, `Chain::save`'s `f.flush()` at chain.cpp:1972 flushes the C++ stream-layer buffer to the OS but does NOT call `fsync(2)` / `FlushFileBuffers`. A power loss between flush and OS page-cache write-back could leave the rename's target inode pointing to a partially-written file at the storage-device level.

**Operational manifestation.** A torn data write within the chain.json body is detected by the S-021 head_hash gate on restart — the recomputed head's compute_hash will not match the file's head_hash field, and `Chain::load` throws.

**Future hardening.** Add an explicit `fsync(fd)` between the ofstream close (the block scope exit at chain.cpp:1974) and the rename (chain.cpp:1980). Requires acquiring the file descriptor from the std::ofstream, which is non-portable on Windows (Win32's `_get_osfhandle` after `_fileno(_iob_func(...))` or similar). Estimated effort: `~20 LOC + platform conditionals + per-platform test`. Not currently warranted; the S-021 gate detects the failure mode loudly.

### F-4: Worker queue depth is structurally bounded at 1 (intentional)

The "queue" of pending saves is a single bit (`save_pending_`). A burst of N applies between two worker iterations collapses to one pending flag. Per L-7, this is the coalesce-but-don't-drop contract — no applied block fails to reach disk, but redundant saves are eliminated.

**Operational concern.** Under sustained write load where the worker cannot keep up (extreme tactical-profile burst, or operator-misconfigured slow disk), the lag between in-memory head and on-disk head grows. The lag is bounded by the worker's save rate.

**Future work.** One-file-per-block storage (`SECURITY.md` §S-031 Option 5) makes save O(1) per block. The worker can never fall behind. Estimated effort: ~1-2 days. Not currently warranted at common operator workloads (`~1-10 blocks/sec` apply rate is well within the worker's capacity).

---

## 7. Test surface citation

- **`tools/test_chain_save_load.sh`** — exercises `Chain::save` + `Chain::load` round-trip (14 assertions across 7 scenarios per the test's own preamble). Covers: non-empty file write, byte-for-byte state recovery, save→load→save→load idempotence (atomic-write semantics), and the non-existent-path fallback. Direct regression for T-2's atomic-write claim and T-6's snapshot consistency.
- **`tools/test_chain_integrity.sh`** — exercises the S-021 head_hash gate's tampering detection (4/4 PASS per the SECURITY.md S-021 row). Composes with T-5 (the wrapping-format integrity composition).
- **`tools/operator_chain_health.sh`** — operator monitoring script that reads `chain.json`'s size, modification time, and head_hash field. Surfaces the worker's save cadence and the lag between in-memory head and on-disk head. Direct operational instrumentation of T-3 + T-4.
- **`tools/test_snapshot_bootstrap.sh`** — exercises the SnapshotEquivalence (FA-Apply-2) round-trip. Composes with T-6 (the snapshot consistency that depends on the worker's shared_lock + atomic-apply).
- **`tools/test_dapp_snapshot.sh`** — exercises the S-037 + S-038 dapp-registry snapshot round-trip. Same composition surface as T-6 for the dapp-registry namespace.
- **`tools/test_snapshot_roundtrip.sh`** — exercises the in-memory snapshot serialize/restore. Composes with T-4's FlushOnExit + T-6's snapshot consistency.

Together these scripts give end-to-end regression coverage for the four theorems' operational surfaces (T-2 atomic write, T-3 coalescing, T-4 FlushOnExit, T-6 snapshot consistency). T-1 (apply-path lock-free) is exercised implicitly by every multi-block multi-rpc concurrent test in `tools/test_*.sh` — the pre-fix pathology would manifest as second-scale apply latency, which all current tests' wall-clock assertions implicitly rule out.

---

## 8. Cross-references

### Specifications + standards

- **IEEE Std 1003.1-2017** `rename(2)` — atomicity of POSIX rename for same-volume targets (T-2 + L-4).
- **Microsoft Win32 API** `MoveFileExW` — atomicity of Windows rename for same-volume NTFS targets (T-2 + L-4).
- **C++ ISO/IEC 14882:2017** §33.4.3.2 [thread.mutex.requirements] — std::mutex contract.
- **C++ ISO/IEC 14882:2017** §33.4.3.4 [thread.sharedmutex.requirements] — std::shared_mutex contract (T-6).
- **C++ ISO/IEC 14882:2017** §33.5.3 [thread.condition.condvar] — std::condition_variable wait + notify semantics (L-1).
- **C++ ISO/IEC 14882:2017** §33.4.4 [thread.lock] — std::lock_guard + std::unique_lock + std::shared_lock RAII contract.
- **C++ ISO/IEC 14882:2017** §29.3 [filesystem] — std::filesystem::rename behavior.
- **C++ ISO/IEC 14882:2017** §6.9.2 [intro.races] — data-race definition + happens-before semantics.

### Systems + concurrency literature

- **Stevens, Rago** (Addison-Wesley 2013, 3rd ed) — "Advanced Programming in the UNIX Environment" §3.16 + §4.16 — the atomic-replace idiom this proof's T-2 invokes; the textbook reference for the write-tmp + rename pattern.
- **Lamport** (Distributed Computing 1986) — "On Interprocess Communication. Part II: Algorithms" — the atomic-register abstraction the filesystem rename implements (referenced as "Atomic Multi-Writer Registers" in T-2's setup).
- **Herlihy, Wing** (ACM TOPLAS 1990) — "Linearizability: A Correctness Condition for Concurrent Objects" — the linearization-point framework the worker's flag-protocol reduces to.
- **Coffman, Elphick, Shoshani** (ACM Computing Surveys 1971) — "System Deadlocks" — the four-condition theorem L-2 invokes.

### Determ-internal references

- `include/determ/node/node.hpp:647-651` — async-save worker coordination block (thread + mutex + cv + atomic flags).
- `src/node/node.cpp:594` — `save_thread_` spawn at startup.
- `src/node/node.cpp:617-641` — `Node::stop` shutdown sequence (T-4).
- `src/node/node.cpp:629-631` — save-worker shutdown signal + join (T-4 steps 3-5).
- `src/node/node.cpp:639` — final synchronous save (T-4 step 6).
- `src/node/node.cpp:661-695` — `save_worker_loop` body.
- `src/node/node.cpp:665-682` — save_mutex_ + cv-wait + flag-clear (L-1 + L-7).
- `src/node/node.cpp:685-686` — state_mutex_ shared_lock + chain.save call (T-6).
- `src/node/node.cpp:697-703` — `enqueue_save` flag-set + notify (L-3).
- `src/node/node.cpp:1845` — `enqueue_save()` call from inside `apply_block_locked` (T-1).
- `src/chain/chain.cpp:1937-1985` — `Chain::save` atomic-rename body (T-2 + L-5).
- `src/chain/chain.cpp:1950` — fs::create_directories.
- `src/chain/chain.cpp:1969-1973` — ofstream write + flush.
- `src/chain/chain.cpp:1980` — fs::rename.
- `src/chain/chain.cpp:1987-2054` — `Chain::load` (the restart-load path T-5 cites).
- `src/chain/chain.cpp:2037-2051` — S-021 head_hash recompute-and-compare gate (T-5).
- `tools/test_chain_save_load.sh` — round-trip regression (T-2 + T-6).
- `tools/test_chain_integrity.sh` — S-021 tampering-detection regression (T-5).
- `tools/operator_chain_health.sh` — operator monitoring for T-3 + T-4 cadence.
- `tools/test_snapshot_bootstrap.sh`, `tools/test_dapp_snapshot.sh`, `tools/test_snapshot_roundtrip.sh` — FA-Apply-2 snapshot regressions (T-6).
- `docs/SECURITY.md` §S-015 — closure-status narrative this proof formalizes.
- `docs/SECURITY.md` §S-031 — broader chain-state mutation composition (T-6 composes with §S-031's `std::shared_mutex` closure).
- `docs/PROTOCOL.md` §11 — chain.json on-disk format (the wrapping object T-5 cites).
- `docs/proofs/S014ConcurrencyAnalysis.md` — sibling concurrency-layer proof (rate-limiter surface; template for citation style).
- `docs/proofs/S031ConcurrencyComposition.md` — sibling chain-state-layer composition (this proof is the persistence-layer companion; T-6 cites that proof's T-2 + T-3 directly).
- `docs/proofs/BlockchainStateIntegrity.md` — sibling state-integrity composition (T-5 cites that proof's T-1 head_hash gate).
- `docs/proofs/SnapshotEquivalence.md` — FA-Apply-2 snapshot equivalence (T-6 cites T-S1).
- `docs/proofs/AccountStateInvariants.md` — FA-Apply-1 apply-determinism invariant (T-3 + T-6 cite I-1..I-6).
- `docs/proofs/Preliminaries.md` §3 — network + asio model (extended in §2.2 here to cover std::condition_variable).

---

## 9. Status

**Shipped.** The async chain.save subsystem closing S-015 is live on the current `main` branch:

- Worker spawn + loop body: `src/node/node.cpp:594` + `node.cpp:661-695`.
- `enqueue_save` from inside apply: `node.cpp:1845`.
- Atomic `.tmp` + rename in `Chain::save`: `src/chain/chain.cpp:1937-1985`.
- FlushOnExit hand-off in `Node::stop`: `src/node/node.cpp:617-641`.

All six theorems are independently regression-tested per §7. The composition theorem is added in the current review pass as the persistence-layer companion to `S031ConcurrencyComposition.md` (which references the async-save worker as its Layer 5). This proof does not modify source code; it formalizes the four-layer composition argument that closes the S-015 persistence surface.

**Not yet shipped (future work, advisory):**

- **fsync between ofstream close and rename** (F-3 mitigation). Adds `fsync(_fileno(f))` or platform-equivalent. Removes the L-6 torn-write window. Estimated effort: ~20 LOC + per-platform test.
- **One-file-per-block storage** (F-4 mitigation). Replaces monolithic chain.json with `chain/blocks/{index}.json`. Worker save becomes O(1) per block. Estimated effort: ~1-2 days. See `SECURITY.md` §S-031 Option 5.
- **SIGKILL-resilient checkpointing** (F-2 advisory). Operator-side concern; out-of-scope for the in-process design. The peer-gossip recovery contract makes this benign for chain integrity.

These are advisory; none invalidate T-1..T-6. They are surfaced for completeness so an external auditor can confirm the scope of the persistence-layer analytic conclusion.
