# Real-Engine FA Harness — closing F-1/FA4 over the actual consensus engine

**Status:** increments 1-5 SHIPPED (`test-fa-{equivocation,abort,cross-shard,multi-event,merge}-trace`) — the apply-level event-family sweep is COMPLETE (§4); the FA4 liveness slice remains (§5). This is the
**self-contained path** chosen by the owner (AskUserQuestion, 2026-07-07) for the
DSF §Q1/§Q2 goal: rather than link the real engine into `determ-dsf` (which would
drag asio + OpenSSL and reverse its self-contained property — see
[ClockInjectionSeam.md](ClockInjectionSeam.md) §6), the real-engine Byzantine-trace
properties are exercised by `test-fa-*` subcommands **inside the `determ` binary**,
which already links the real `Chain`/apply path. **`determ-dsf` is never touched
and stays 100% self-contained.**

## 1. Why a separate harness (and where it lives)

The DSF toy scenarios (`sim/`, increments 1-6) exercise the *checker patterns* for
the production invariants FA1/A1/FA6/FA7 over a TOY `SimState` — they do NOT run
the real consensus engine, so proof gaps **F-1** ("Option 2 DSF still outstanding;
analytic proofs cover but no random-Byzantine fuzz") and **FA4** (liveness /
trace-level properties) stay open against the real code
([UnitTestCoverageMap.md](UnitTestCoverageMap.md) §F-1).

The real engine is already linked by the `determ` binary. `test-supply-invariant-fuzz`
([src/main.cpp](../../src/main.cpp)) demonstrates the pattern: a seeded SplitMix64
PRNG drives a multi-block trace of randomized TRANSFER/STAKE/UNSTAKE txs through
the **real** `Chain::append` apply path and asserts the A1 economic invariant
(`expected_total() == live_total_supply()`) after every block. **So the economic
A1 trace is already covered on the real engine.** The FA harness generalises this
to the **consensus-Byzantine** invariants (equivocation slashing, abort/escalation,
cross-shard receipt conservation) — the genuine F-1/FA4 gap.

## 2. Harness contract

Each `test-fa-*` subcommand:

1. Builds a real `Chain` from a `GenesisConfig` (real genesis, real apply).
2. Drives a fixed-length multi-block trace, each block carrying Byzantine events
   injected via the real block-apply path (`Chain::append`).
3. Uses a **seeded, counter-based SplitMix64** — no wall clock, no OS RNG — so the
   whole run is byte-reproducible.
4. Asserts trace-level invariants **after every block** (not just at the end).
5. Is **non-vacuous** (asserts the adversarial condition actually occurred) with a
   **negative control** (an event-free block does not move the tracked quantity)
   and a **same-seed determinism** check (identical final `compute_state_root()`).

## 3. Increment 1 — equivocation slashing (`test-fa-equivocation-trace`)

A never-slashed author + K=6 distinct-stake validators. Over 48 blocks, each block
injects an `EquivocationEvent` for a randomly-chosen validator (a mix of FRESH
targets and DUPLICATE re-submissions). Invariants checked after every block:

| Invariant | Assertion |
|---|---|
| Fresh-slash forfeit (FA6) | equivocator's `stake()` → 0 |
| Fresh-slash deregistration (FA6) | `registrant().inactive_from != UINT64_MAX` |
| Fresh-slash accounting | `accumulated_slashed()` += exactly the pre-slash stake |
| **Idempotence (slash-once)** | duplicate evidence does NOT change stake or `accumulated_slashed()` (no double-slash) |
| A1 conservation | `expected_total() == live_total_supply()` |
| Monotonicity | `accumulated_slashed()` non-decreasing |
| Exact total | `accumulated_slashed() == Σ` distinct-slashed stakes (no double-count) |
| Non-vacuity | ≥1 fresh slash AND ≥1 duplicate actually occurred |
| Negative control | an event-free block leaves `accumulated_slashed()` unchanged |
| Determinism | same seed ⇒ identical final `compute_state_root()` |

Observed run: **6 fresh slashes + 42 idempotent duplicates over 48 blocks**, all
assertions green; full-run output byte-identical across invocations. Gated by
`tools/test_fa_equivocation_trace.sh` (FAST). No consensus code is modified — the
harness only READS the real engine through existing public `Chain` APIs.

## 4. Increments 2-5 (SHIPPED) — the full apply-level event-family sweep

All four follow the §2 contract; each was drafted + adversarially verified
against the real Chain APIs by an independent reviewer before integration, and
each full run is byte-identical across invocations.

| Increment | Subcommand | Trace property (against the REAL apply) | Observed adversarial run |
|---|---|---|---|
| 2 — abort / suspension (S-032) | `test-fa-abort-trace` | Phase-1 `AbortEvent` deducts exactly `min(SUSPENSION_SLASH, stake)` with floor-at-0 (a forced schedule drives one small-stake validator through full → PARTIAL → floored-ZERO deducts); `abort_records` cache exact per domain (Phase-2 rounds never recorded); `accumulated_slashed` exact + monotone; A1 per block | 6 fresh + 34 repeat targets, 1 partial, 7 floored-zero deducts, 8 Phase-2 no-ops |
| 3 — cross-shard conservation (FA7) | `test-fa-cross-shard-trace` | TWO real chains (source shard A + dest shard B); real cross-shard TRANSFERs emit outbound receipts on A, B applies inbound receipts including adversarial DUPLICATE re-submissions — no-double-credit (`applied_inbound_receipts` dedup), no-credit-without-debit, two-chain conservation, per-chain A1 analogs, dual-chain state-root determinism | 48 unique credits, 23 duplicate rejects, 27 withheld/in-flight |
| 4 — multi-event composition (FA-Apply-15) | `test-fa-multi-event-trace` | blocks carrying RANDOM MIXES of TRANSFERs + `EquivocationEvent`s + `AbortEvent`s simultaneously; a shadow model mirrors the real apply rules (fees to creators, BOTH slash kinds into one `accumulated_slashed`, nonce monotonicity, stake never underflows); joint A1 per block | 57 transfers, 16 equivocations (6 fresh / 10 dup), 15 aborts, 21 multi-kind blocks |
| 5 — merge-event lifecycle | `test-fa-merge-trace` | `MergeEvent` BEGIN/END lifecycle over randomized topology per the real apply semantics — fresh BEGINs, duplicate BEGINs, valid ENDs, stale ENDs, bad-partner rejects; A1 per block | 14 fresh BEGINs, 5 dup BEGINs, 12 valid ENDs, 9 stale ENDs, 8 bad-partner rejects |

Gated by `tools/test_fa_{abort,cross_shard,multi_event,merge}_trace.sh` (FAST).

## 5. What this closes, and what remains

Increments 1-5 close the **apply-level** F-1 slices for every major consensus
event family: FA6 equivocation slashing, S-032 abort/suspension accounting, FA7
cross-shard receipt conservation, FA-Apply-15 multi-event composition (the
canonical F-1 target alongside FA4), and the merge-event lifecycle — each as a
seeded randomized-Byzantine multi-block trace over the REAL `Chain::append`
apply path, complementing `test-supply-invariant-fuzz`'s economic A1 trace.

**Still open: the FA4 liveness slice.** Liveness (height progress under
adversarial *scheduling* — timeouts, abort cascades, escalation) is a property
of the networked `Node` phase machine, not of the apply path; a real-engine
FA4 harness needs to drive a real `Node` under controlled time/transport — i.e.
the [ClockInjectionSeam.md](ClockInjectionSeam.md) increments 2+ plus the minix
`net::Transport` seam ([MinixTacticalProfile.md](MinixTacticalProfile.md) §4;
the same seam serves both goals). Until then FA4 remains covered only by the
per-block slices (`test-required-block-sigs` etc.), the analytic proof
(`Liveness.md`), and the live cluster tests.
