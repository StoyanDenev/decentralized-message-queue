# RoundStallValveSoundness — the S-050 stall valve is safety-neutral (scratch-only reset) and makes the round-state-fork livelock non-absorbing; the S-051 pool-exhaustion halt is the OPEN boundary

This document is the soundness argument for the S-050 fix (commit `48bc54f`): a **two-window wall-clock stall valve**, `Node::maybe_stall_reset_locked()` (`src/node/node.cpp:1608-1642`, constants `:1604-1606`), invoked from both phase-timeout handlers (`:1649`, `:1701`). The valve addresses the wedge class that the S-047 retry (`RoundStateRetrySoundness.md`) explicitly cannot: **deterministic mutual rejection**, where re-delivering a message re-enters the same reject. We establish two things. **(V-S, safety)** the valve's reset touches only receiver-local round *scratch* state — no input to block validation changes, so a valve firing cannot make an honest node accept an invalid block or reject a valid one. This is a code-level argument. **(V-R, recovery)** the reset makes the reproduced round-state-fork livelock **non-absorbing**: the wedged state is no longer a fixed point, and each firing restarts selection from canonical post-head state. V-R is **deliberately weaker than a liveness theorem** — it is a bounded-time-to-fire argument plus an *empirical* convergence record (`AdversarialTransportHarness.md` §3.4: wedge-class failures 5/30 → 0/30 across pinned-core and starved loops, both platforms; the valve fired in 4/8 starved runs and every run passed). No claim in this document asserts guaranteed liveness. §4 records the adjacent halt class the valve structurally cannot reach: **S-051, OPEN, owner-gated**.

**Companion documents.** `RoundStateRetrySoundness.md` (S-047) — the retry whose T-2 boundary ("deterministic rejection is outside T-2") this valve complements; its relay (`Node::rebroadcast_round_state_locked`, `src/node/node.cpp:1553-1561`) is the mechanism a reset node re-adopts a tail through. `AbortCascadeLiveness.md` (S-044/S-045) — the `abort_claim_quorum() = max(2, K−1)` floor (`include/determ/chain/params.hpp:156-160`) whose unsatisfiability under a forked height view is part of the wedge. `AdversarialTransportHarness.md` §3.4 — the CI-contention round that found and reproduced both S-050 and S-051 (2026-07-15); §3.3 — the stall-triggered re-sync probe this valve added. `tools/operator_stall_watch.sh` — the read-only operator detector for both signatures (§5).

---

## 1. Model

### 1.1 The wedge: a round-state fork under concurrent abort quorums (S-050)

Reproduced live on a **clean network** (no injected loss) under CI-grade CPU contention (`test-fa-partition-virtual`, 2026-07-15; `AdversarialTransportHarness.md` §3.4):

1. Two abort quorums for the same round form **concurrently** against different creators. Formation is local: `on_abort_claim` assembles an `AbortEvent` the moment its bucket reaches `abort_claim_quorum()` (`src/node/node.cpp:1790-1791`) and hash-chains it onto the local tail (`:1796-1799`).
2. The tail is **hash-chained by adoption order**: `chain_abort_hash(current_aborts_.back().event_hash, …)` (`:1798-1799`). Nodes that adopt the two events in different orders now hold **different tails** — same events, different `event_hash` chains.
3. Committee re-selection folds every in-flight `event_hash` into the selection seed (`check_if_selected`, `:1027-1029`). Diverged tails therefore re-derive **different committees** and different `delay_output`s.
4. From then on rejection is **deterministic**: every relayed `BlockSig` is dropped (`mismatched delay_output`), and relayed abort events fail the receiver's committee-view admission (`on_abort_event` requires each claimer in the *receiver's* `current_creator_domains_`, `:1856-1858`). The S-047 retry re-delivers into the same reject — re-delivery cannot heal a *rejection* wedge.
5. With ≤1 claim-eligible node per height view, the `max(2, K−1)` abort-claim quorum is unsatisfiable: no further abort event can form. An **absorbing livelock**.

### 1.2 Valve state and constants

Per-node state: `round_stall_ticks_`, `stall_since_`, `stall_soft_since_`, `stall_abort_count_`, `stalled_resync_`. Constants (`src/node/node.cpp:1604-1606`):

| Constant | Value | Role |
|---|---|---|
| `kRoundStallMinTicks` | 3 | certifies round timers are genuinely firing before any trip |
| `kRoundStallSoftWindow` | 5 s | no block **and** abort tail immobile |
| `kRoundStallHardWindow` | 30 s | no block, period (churn cannot defer forever) |

Both windows are **wall-clock**, read from the injected clock's non-digest scheduling path (`clock_.steady_now()`, `:1614`; `RealClock` delegates to `steady_clock::now()`, so production behavior is unchanged and a virtual-time harness can trip the valve deterministically). Wall-clock was a deliberate correction: a tick-count threshold silently scales with the configured timer period — 25 ticks validated at 200 ms timers became a 25 s trip point at 1 s timers (comment `:1588-1592`).

### 1.3 Trip rule (as implemented)

`maybe_stall_reset_locked()` runs at the top of both phase-timeout handlers, after their phase gates (`:1648-1649` CONTRIB; `:1700-1701` BLOCK_SIG), under the exclusive state lock (the timer callbacks take `state_mutex_` before dispatch, e.g. `:1673-1675`):

- **T-1 (cycle arm).** The first expiry of a cycle (`round_stall_ticks_++ == 0`) records `stall_since_`, `stall_soft_since_`, and the current abort-tail size (`:1615-1619`).
- **T-2 (soft restart on tail movement).** If `current_aborts_.size()` changed since last observed **and** the hard window has not elapsed, the soft window restarts and the valve does not fire (`:1622-1627`). Rationale (comment `:1577-1583`): killing a round mid-abort-recovery resets it back to the base committee that still *contains* the member the abort was routing around — a reproduced valve-induced groundhog loop.
- **T-3 (tick minimum).** No trip before `kRoundStallMinTicks` expiries (`:1628`).
- **T-4 (two-window trip).** Fire iff the soft window elapsed **or** the hard window elapsed (`:1629-1630`).
- **Fire actions** (`:1631-1641`): reset the tick counter; cancel both phase timers; **clear `current_aborts_`**; `reset_round()`; arm `stalled_resync_`; broadcast one `STATUS_REQUEST`; `check_if_selected()`.

### 1.4 The progress signal is blocks, only blocks

Only a block apply clears the stall cycle: `post_append_bookkeeping_locked` sets `round_stall_ticks_ = 0` and `stalled_resync_ = false` (`:2452-2455`). `reset_round()` deliberately does **not** clear the counter (`:2324-2327`) — it runs on every abort transition, and an abort-churn loop (abort → reselect → abort, zero blocks) must not suppress the valve. This is what makes T-4's hard window meaningful.

---

## 2. Safety (V-S): the reset is scratch-only

**Claim C-1 (no validation input changes).** Everything the valve mutates is receiver-local round scratch: `current_aborts_` (`:1636`), the per-round buffers and phase cleared by `reset_round()` (`pending_contribs_`, `pending_block_sigs_`, `buffered_block_sigs_`, `pending_claims_`, `pending_secrets_`, round hashes, `phase_ = IDLE`; `:2313-2328`), the two phase timers, and the stall bookkeeping itself. It does **not** touch `chain_`, `registry_` (rebuilt only on block apply, `:2447`), or any persisted state. Block validation reads none of the cleared state: a block's abort events are validated **from the block itself** — `validator.cpp check_abort_certs` (`src/node/validator.cpp:231`) re-derives the eligible pool from `(chain, registry)` and checks the inline claim quorum carried in the block, never the receiver's `current_aborts_`. Hence the block-validity predicate is identical before and after a valve firing: no invalid block becomes acceptable, no valid block becomes rejectable. Blocks self-certify; scratch is not load-bearing.

**Claim C-2 (valve emissions are benign).** The valve itself emits exactly one message, `STATUS_REQUEST` (`:1639`) — a probe answered with a status response (`on_status_request`, `:3161`); it creates no contrib, sig, claim, or abort event. `check_if_selected()` (`:953`) re-enters selection from canonical post-head state — the same call every block apply performs (`:2553`). If the node is selected it starts a fresh round and signs a **fresh contrib at the same height** — a new signature, so it needs its own argument: the reset cleared `current_aborts_`, so the fresh contrib carries `aborts_gen = 0` while peers still in the forked round hold `aborts_gen = |their tail| ≠ 0`. `on_contrib`'s generation gate drops cross-generation contribs *before* the S-006 duplicate comparison is ever reached (`msg.aborts_gen != current_aborts_.size()` → return, `:2841-2844`; the S-006 same-signer check sits below it and applies only within one generation, `:2887-2894`). A valve-induced re-sign therefore cannot fabricate equivocation evidence against the reset node; it is either dropped (peer in a different generation) or is the node's *first* contrib the peer sees at that generation.

**Claim C-3 (no stale-fire hazard).** The valve is only reachable through the phase-gated handlers (`:1648`, `:1700`); a stale queued expiry that survives a `cancel()` race (the known `timer_service.hpp` window) is discarded by the phase gate before the valve runs. Within the handler the valve runs under the exclusive `state_mutex_`, so its read-modify-write of the stall state and the reset actions are atomic with respect to message handlers.

**Claim C-4 (tolerance-0 sync is pull-only).** `stalled_resync_` makes `start_sync_if_behind` treat **any** positive height gap as sync-worthy (`TOLERANCE = stalled_resync_ ? 0 : 5`, `:3202`; rationale `:3198-3201`: a stalled node may be stranded 1-2 blocks behind after a missed broadcast, inside the normal tolerance window). Sync fetches blocks that still pass full validation on apply — no admission rule is weakened; only the *trigger* threshold changes, and it reverts on the next block apply (`:2455`).

**Validation anchor.** Every starved-loop run in which the valve fired passed the harness's fork/prefix-witness gates (4/8 fired, 8/8 passed; `AdversarialTransportHarness.md` §3.4). The S-050 commit touched only node runtime, harness, tooling, and docs (`git show --stat 48bc54f`: `src/node/node.cpp`, `include/determ/node/node.hpp`, `src/main.cpp` harness code, `tools/run_all.sh`, doc files) — no chain, validator, or serialization surface changed, so golden vectors are structurally unaffected.

---

## 3. Recovery (V-R): the wedge is non-absorbing — bounded time-to-fire, empirical convergence

**Claim R-1 (bounded time-to-fire, conditional on timers firing).** Suppose a node is wedged with its round timers firing (phase CONTRIB or BLOCK_SIG — precisely the S-050 wedge, where every node sits in an open round). Each expiry increments `round_stall_ticks_`; with no block applied, T-4 guarantees a trip no later than the hard window: abort-tail movement can restart the *soft* window (T-2) but cannot extend past `kRoundStallHardWindow` (the `now - stall_since_ < kRoundStallHardWindow` conjunct at `:1623` and the `||` at `:1629-1630`). So time-to-fire from cycle arm is at most ~30 s plus one timer period (plus the T-3 minimum on fast timers). **Condition:** this argument needs round timers to be firing at all — see §4 for the class where they are not.

**Claim R-2 (the wedged state is not a fixed point).** On firing, the node discards its (possibly forked) tail and committee view and recomputes both from canonical post-head state (§1.3 fire actions). A reset node with an empty tail re-adopts a peer's abort events from the S-047 relay (`:1553-1561`) **in that peer's chain order** — sequential adoption re-derives, event by event, the committee each subsequent event's claimers were drawn from, so it converges onto *one* peer's history instead of holding an independent fork. The `STATUS_REQUEST` + tolerance-0 sync (C-4) covers the sibling case where the "stall" was actually being stranded 1-2 blocks behind.

**What R-2 does NOT claim.** Convergence of the *fleet* is not proven. Two nodes may fire concurrently and re-enter the same concurrent-quorum race; adoption order after a reset is still timing-dependent. The precise claim is **non-absorption**: each firing re-samples the adoption race from a clean slate, so the wedge requires the adverse schedule to recur *every* cycle rather than once. That repeated trials escape in practice is an **empirical** result, not a theorem: in the reproduction loops the valve fired in 4/8 starved runs and every run passed; wedge-class failures went 5/30 → 0/30 on both platforms (`AdversarialTransportHarness.md` §3.4, §4). A schedule adversary that controls timing forever is outside this record.

**Claim R-3 (the two windows are each load-bearing).** Both windows exist because a simpler design failed in reproduction: soft-only (no hard cap) is deferred forever by abort churn (§1.4); firing without the T-2 soft restart kills rounds mid-abort-recovery and loops (the groundhog loop, `:1577-1583`). The pair is the minimal rule that passed the validation loops; no optimality claim is made.

---

## 4. The OPEN boundary: S-051 pool-exhaustion halt (owner-gated)

The valve's precondition — round timers firing — fails exactly when **no round can start**. S-051 is that class, found in the same CI-contention round and **OPEN**:

1. Every Phase-1 (round==1) abort baked into a block suspends the aborted domain from selection for `min(BASE_SUSPENSION_BLOCKS · 2^min(count−1, MAX_ABORT_EXPONENT), MAX_SUSPENSION_BLOCKS)` blocks — `NodeRegistry::build_from_chain`'s `is_suspended` (`src/node/registry.cpp:43-51`), constants `BASE_SUSPENSION_BLOCKS = 10`, `MAX_SUSPENSION_BLOCKS = 10'000`, `MAX_ABORT_EXPONENT = 10` (`include/determ/chain/params.hpp:35-37`).
2. Suspension expiry is measured in **block index** (`at_index <= ar.last_block + len`, `registry.cpp:50`), not time.
3. Under CPU starvation, **spurious** abort quorums (two starved nodes co-timing-out on a healthy third) accumulate suspensions. Once the eligible pool falls below the committee size, `check_if_selected` returns without starting a round (`avail_domains.size() < k_use`, `src/node/node.cpp:1017`).
4. No round ⇒ no phase timers ⇒ **the S-050 valve never fires**; no blocks ⇒ `at_index` never advances ⇒ **suspensions never expire**. A permanent, uniform-height halt. Reproduced twice in 30 runs pre-mitigation (majority frozen at 5,5,5,5 / 8,8,8,8; `AdversarialTransportHarness.md` §3.4).

**Fix constraint (why it is owner-gated).** Any eligibility change (e.g. a deterministic floor that ignores suspensions when the pool would drop below K) must land **byte-identically** on three surfaces, or the change itself forks `state_root`:

| Surface | Site |
|---|---|
| Live selection filter | `NodeRegistry::build_from_chain` (`src/node/registry.cpp:43-64`) |
| Block validation | the validator consumes the registry built by that same filter (`registry_` rebuilt at `src/node/node.cpp:2447`; committee/abort checks at `src/node/validator.cpp:43-52`, `:231`) |
| D3.3b frozen committee checkpoints | `Chain::freeze_epoch_committee` (`src/chain/chain.cpp:774-794`), whose `is_suspended` (`:776-784`) is a hoisted copy that "MUST stay byte-identical forever" (comment `:766-773`); folded into checkpoints at `:1830-1837` |

The shared `params.hpp` constants (D3.3b step0, comment `params.hpp:25-34`) collapse the constant-drift vector but not the predicate-drift vector. Until the protocol fix lands, the mitigations are harness-side (longer phase timers push the spurious co-timeouts into the far tail; §3.4) and operational detection (§5). **Status: OPEN.**

A second, narrower boundary carried over from `AdversarialTransportHarness.md` §3.3: an **idle off-committee** node runs no round timers, so the valve never fires for it; its recovery remains operational (restart/resync).

---

## 5. Operator observability: `tools/operator_stall_watch.sh`

Because S-051 is open, both signatures need an outside detector. `tools/operator_stall_watch.sh` polls each node's `determ status --field height` — the same **read-only** RPC its sibling `operator_consensus_lag.sh` uses (identical invocation at `operator_consensus_lag.sh:158`); the script issues **no mutating call** — over a fixed window and classifies the trajectories:

| Exit | Classification | Signature |
|---|---|---|
| 0 | HEALTHY | fleet max height advanced cleanly |
| 1 | unreachable / bad args | no node answered any poll — nothing to classify |
| 2 | S-050 territory | heights stalled but **non-uniform**, or stall-then-recover (flat stretch ≥ the 5 s soft window, then advance) — self-healing expected; watch, don't touch |
| 3 | **suspected S-051** | every node frozen at the **same** height for the whole window — permanent without operator action; must page |

The exit-code extension (siblings use 0/1/2) is deliberate and documented in the script header: the two alerts demand different operator responses. The S-051 classifier requires positive confirmation from *every* node (a node unreachable all window disqualifies the uniform-freeze verdict but still blocks HEALTHY). Syntax verified with `bash -n`; the bash-samples/python-classifies split and the `tools/common.sh` `$DETERM` resolution follow the sibling-script idiom. Detection only: exit 3 is "suspected" — a uniform freeze has other possible causes (e.g. all daemons paused); the operator confirms via per-node logs.

---

## 6. Implementation cross-reference

| This document | Source |
|---|---|
| Valve constants (3 ticks / 5 s / 30 s) | `src/node/node.cpp:1604-1606` |
| `maybe_stall_reset_locked` (trip rule + fire actions) | `src/node/node.cpp:1608-1642` |
| Valve call sites after phase gates | `src/node/node.cpp:1648-1649`, `:1700-1701` |
| Injected clock read | `src/node/node.cpp:1614`; `include/determ/time/clock.hpp` |
| Soft restart on abort-tail movement | `src/node/node.cpp:1622-1627` (rationale `:1577-1583`) |
| Wall-clock-not-ticks rationale | `src/node/node.cpp:1588-1592` |
| Blocks-only progress signal | `src/node/node.cpp:2452-2455` (clear), `:2324-2327` (deliberate non-clear) |
| Tolerance-0 stalled resync | `src/node/node.cpp:3193-3202` |
| One-shot startup probe (contrast) | `src/node/node.cpp:756` (`arm_startup_grace`) |
| Abort quorum formation / hash chaining | `src/node/node.cpp:1790-1791`, `:1796-1799` |
| Adoption committee gate + dedup | `src/node/node.cpp:1856-1858`, `:1835-1837` |
| Contrib generation gate (precedes S-006 check) | `src/node/node.cpp:2841-2844`, `:2887-2894` |
| Seed folds abort `event_hash`es | `src/node/node.cpp:1027-1029` |
| No-committee return (S-051 no-round condition) | `src/node/node.cpp:1017` |
| S-047 relay (re-adoption path) | `src/node/node.cpp:1553-1561` |
| Suspension predicate + constants | `src/node/registry.cpp:43-51`; `include/determ/chain/params.hpp:35-37` |
| D3.3b mirror + byte-identity mandate | `src/chain/chain.cpp:766-794`, `:1830-1837` |
| Abort-claim quorum floor | `include/determ/chain/params.hpp:156-160` |
| Block-side abort validation (self-certifying) | `src/node/validator.cpp:231` (`check_abort_certs`) |
| Empirical record (S-050 + S-051) | `docs/proofs/AdversarialTransportHarness.md` §3.4 |
| Operator detector | `tools/operator_stall_watch.sh` |

---

## 7. Status

- **S-050: FIXED** (commit `48bc54f`). Safety: C-1–C-4 — the valve reset is scratch-only, emits no consensus message, is phase-gated and lock-serialized, and only lowers a sync *trigger* threshold. Recovery: R-1–R-3 — bounded time-to-fire while round timers run, non-absorption of the round-state-fork wedge; fleet convergence is an **empirical record** (5/30 → 0/30 wedge-class, both platforms), **not a liveness theorem**, and this document claims nothing stronger.
- **S-051: OPEN, owner-gated.** Pool exhaustion halts rounds entirely, which is outside the valve's precondition by construction (§4). The fix is a state_root-fork-sensitive protocol change that must land identically on three surfaces; until then, detection is operational (`tools/operator_stall_watch.sh`, exit 3).
- **Boundaries carried forward:** idle off-committee nodes (no timers, no valve; §4); a schedule adversary that re-creates the adverse adoption race on every valve cycle is outside the empirical record (§3).
