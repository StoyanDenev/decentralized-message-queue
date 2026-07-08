# AdversarialTransportHarness — fault injection in the virtual net backend + the partition/loss FA4 harness

This document describes the adversarial-network layer of the FA4 in-process harness: a deterministic fault model in the pure-std `VirtualTransport` backend (`include/determ/net/virtual_transport.hpp` + `src/net/virtual_transport.cpp`) and the `test-fa-partition-virtual` subcommand (`src/main.cpp`) that drives five real `node::Node` instances through a network **partition** and **link loss**. Where `test-fa-liveness-virtual` (`RealEngineFAHarness.md` §5) stresses node **death**, this stresses the **delivery layer** — the S-047 territory. It also surfaces a genuine finding: **sustained loss triggers the open S-048 same-height fork, which the S-047 retry cannot heal**, so loss-liveness cannot be a hard gate while S-048 is open.

**Companion documents.** `RoundStateRetrySoundness.md` (S-047) — the retry whose message re-delivery this harness exercises; its fair-loss liveness theorem (T-2) is the asymptotic claim this harness demonstrates empirically. `RealEngineFAHarness.md` §5 + `docs/SECURITY.md` §S-047 — the failover harness and the retry fix. `docs/SECURITY.md` §S-048 — the open same-height-fork defect this harness's loss diagnostic surfaces. `MinixTacticalProfile.md` §4.1 — the `net::Transport` seam and the virtual backend the fault model extends.

---

## 1. The fault model

The virtual backend gains three test-facing controls on `VirtualNetwork`, all **off by default** (a fresh network is byte-identical to a perfect one — every prior test is unaffected):

- `set_loss(uint32_t permille)` — every link drops each gossip frame independently with probability `permille/1000`, both directions.
- `partition(std::set<int> side_a)` — every link whose two endpoint **groups** straddle the boundary (one group in `side_a`, the other not) has delivery blocked both ways; non-straddling links deliver normally. Endpoints are tagged with `VirtualTransport::set_partition_group(int)` (default group 0 ⇒ no straddle possible).
- `heal()` — clears any partition (loss unaffected; clear it separately with `set_loss(0)`).

### 1.1 Whole-frame granularity (the framing-coherence invariant)

**Invariant WF.** A fault operates at the granularity of one whole Peer message and can never split a frame. This holds because `Peer::send`/`do_write` (`src/net/peer.cpp`) serialize exactly one complete length-prefixed message and hand it to `Connection::async_write` in a **single call** with a **single outstanding write** at a time (the `write_queue_` pump). In the virtual backend `async_write` inserts that whole span into the peer inbox in one locked operation, so a fault either inserts the entire frame or none of it. A dropped frame is therefore a clean message loss: the receiver's parked exactly-N read simply never completes for that frame, and the next delivered frame's bytes still align to a fresh `[len][body]` boundary (the reader reads header-then-body of whichever frame arrives next; frames are self-delimiting). No partial frame is ever produced, so framing is never corrupted.

### 1.2 Loss semantics — a lost packet, not a broken pipe

A gated or RNG-dropped frame **leaves the host**: the sender's `async_write`/`write_all` still **succeeds** to the caller (it posts the whole-span completion / returns `true`), it just never reaches the peer inbox. This models packet loss downstream, not a socket teardown: no connection closes, no peer is reaped, no `on_close` fires. Consequently a partition (delivery-gating, not severing) **heals** without a reconnect — on `heal()` gossip simply resumes and the S-047 retry re-delivers what was lost. A minority partitioned below quorum cannot finalize (safety) but, absent a periodic re-sync probe, does not auto-catch-up on heal — §3.3.

### 1.3 Concurrency

Each connection `Pair` co-owns a `LinkFlags` (two direction-gate atomics, a drop-rate atomic, the two immutable endpoint groups, and a per-link xorshift RNG). The write path reads the gate/rate atomics lock-free and advances the RNG **only under the owning `Pair::mu`** (which the write already holds). `set_loss`/`partition`/`heal` take the network mutex and flip the atomics from the harness thread **without** `Pair::mu` — a deliberately benign race: a partition taking effect "around" an in-flight write is exactly what a real network does, and the atomics carry no ordering dependency. `LinkFlags` is co-owned (network registry + Pair), so the write path never dereferences a freed policy; the immutable `group0/1` are set at creation and never mutated. Lock order is one-way: the write path takes `Pair::mu` then reads atomics (never the network mutex); the fault API takes the network mutex then flips atomics (never `Pair::mu`) — no cycle.

---

## 2. `test-fa-partition-virtual` — the harness

Five real `Node`s in one process, the `test_weak_3node` shape (M=5, K=3 weak BFT, `epoch_blocks=1` per-block committees), node4 tagged partition group 1 and the rest group 0. Liveness is measured as a **chain property** — the tip (max height over a node set), not the min: under sustained loss a node can miss enough consecutive block broadcasts to fall past the sync tolerance and, with no re-sync probe (§3.3), get stuck; that straggler does not fork and does not stop the committee, so a min-based measure would misread its lag as a liveness failure.

### 2.1 Phase 1 — PARTITION SAFETY (the hard gate)

Runs first, on the pristine post-steady-state cluster. `partition({1})` isolates node4 from the group-0 majority. Assertions:

1. **Majority liveness** — the 4-node majority tip advances ≥ 2 blocks. The committee is drawn from all five, so ~60% of per-block committees include node4 (unreachable) and must abort-and-reselect around it; the S-047 retry (`RoundStateRetrySoundness.md`) is what makes those abort volleys converge on the clean intra-majority links. This assertion therefore exercises the retry directly.
2. **Minority frozen** — node4, below the K=3 quorum with no reachable peers, produces no block: its height is unchanged across the majority's ≥ 2-block advance.
3. **No fork** — node4's head block equals the majority's block at the same index (reference = the furthest-ahead majority node, which holds every lower block): node4's chain is a consistent **prefix**, never a competing branch.

The majority stays on **one** chain because its internal links are loss-free — no timing skew, hence no abort-vs-finalize race (contrast §3.1). This is why the partition phase is a reliable hard gate where the loss phase is not.

### 2.2 Phase 2 — LOSSY-LINKS DIAGNOSTIC (non-gating)

After heal, 10% per-frame loss is applied to every link and the harness **reports** (as `NOTE` lines, never `check()` calls, so the gate cannot flake on them):

- whether the majority tip advanced +2 under loss — it does, because the S-047 retry re-delivers dropped round messages (the fair-loss liveness of `RoundStateRetrySoundness.md` T-2, observed);
- whether a **same-height fork** was observed — it sometimes is, which is the finding of §3.1.

---

## 3. Findings

### 3.1 Loss triggers S-048; the S-047 retry cannot heal it

The S-047 retry re-delivers dropped **round** messages, so the chain keeps finalizing under loss. But sustained loss also induces **timing skew** — committee members see different subsets of contribs at different times — and timing skew is exactly what drives the abort-vs-finalize race that produces two validly-signed **same-height** blocks: the open **S-048** defect (`docs/SECURITY.md` §S-048). The retry delivers messages; it does not **reorg** a fork (`Chain::resolve_fork` is unwired, sync is append-only). So under loss the cluster can split into two same-height branches that never reconcile, and heavy loss can even fragment it below quorum on every branch. The harness's loss phase **observes** this (a `NOTE` when two holders disagree on a same-height block).

**Consequence for testing.** "No fork under loss" and "reliable liveness under loss" are **not assertable while S-048 is open** — any sustained loss can trigger the fork. A reliable loss-liveness gate must wait on the S-048 fix (wire `resolve_fork` + a bounded head-reorg, owner-gated). The natural home for it is the **virtual-TIME** evolution of this backend, where the schedule is deterministic and a loss-induced fork is **reproducible** and can be driven to the reorg path on demand — the next FA4 increment. Until then this harness gates on the **partition-safety** property (loss-free majority ⇒ no S-048) and treats loss as a diagnostic.

This is a genuine strengthening of the S-048 case: the same-height fork is not a partition-edge curiosity — **ordinary link loss reaches it**, so S-048 is the load-bearing open item for adversarial-network liveness.

### 3.2 Convergence is asymptotic (a wall-clock-budget boundary)

Even setting the fork aside, `RoundStateRetrySoundness.md` T-2 gives only **asymptotic** delivery under fair loss. Combined with per-block committee reselection (`epoch_blocks=1`, required so the majority can route around an isolated node), heavier loss (≳25%) drives prolonged abort/reselect storms whose per-block time exceeds a wall-clock gate's budget with 200 ms round timers. 10% is the pinned point where the diagnostic reliably shows tip progress; higher rates are a virtual-time follow-on.

### 3.3 No periodic re-sync probe (the §S-048-adjacent recovery boundary)

A delivery-partitioned (or loss-stranded) node that falls past the sync tolerance does not auto-catch-up: the only sync trigger is `Node::start_sync_if_behind` via `on_status_response`, which requires a `STATUS_REQUEST` — broadcast **once** at the startup grace (`src/node/node.cpp`) with no periodic re-probe. Recovery there is operational (restart / resync), the same boundary the failover harness's REJOIN phase works around by constructing a fresh node. The harness prints this as a `NOTE`, does not assert recovery.

---

## 4. Status

Fault model + `test-fa-partition-virtual` SHIPPED. Gate: partition-safety phase is a hard `check()` battery (10/10 stable locally, both platforms); loss is a non-gating diagnostic. The byte-invariant default keeps `test-net-virtual` + `test-fa-liveness-virtual` + all consensus golden vectors unchanged. The reliable loss-liveness gate and the deterministic reproduction of the loss-induced S-048 fork are the **virtual-TIME** follow-on (deterministic → adversarial schedules), which also unblocks the S-048 reorg fix's regression test.
