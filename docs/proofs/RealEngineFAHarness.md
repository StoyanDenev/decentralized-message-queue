# Real-Engine FA Harness — closing F-1/FA4 over the actual consensus engine

**Status:** increment 1 SHIPPED (`test-fa-equivocation-trace`). This is the
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

## 4. What this closes, and what remains

Increment 1 closes a **slice** of F-1/FA4 for the FA6 equivocation-slashing
invariant against the REAL apply path (previously only single-event apply tests +
the TOY DSF scenario existed). F-1/FA4 remain **open overall** until the other
consensus invariants have real-engine trace harnesses. Planned increments (each a
`test-fa-*` mirroring this structure):

- **inc 2 — abort / BFT-escalation:** a trace of abort events; assert escalation
  monotonicity + the quorum floor (S-044/S-045) + no spurious finalization.
- **inc 3 — cross-shard receipt conservation:** a multi-shard trace; assert
  no-double-credit / no-credit-without-debit + per-shard A1 (FA7).
- **inc 4 — merge-event / view-reconciliation (F2):** assert no phantom evidence.
- **liveness slice (FA4):** a trace asserting strict height progress + head
  advance under a bounded adversary.

The consensus **clock** injection ([ClockInjectionSeam.md](ClockInjectionSeam.md),
increment 1 shipped) is only required if a future harness drives a real *networked*
`Node` (which samples `proposer_time`); the block-apply-level harnesses here drive
the apply path directly and do not need it.
