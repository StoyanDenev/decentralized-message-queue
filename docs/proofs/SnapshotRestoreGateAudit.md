# Snapshot-Restore / Deserialize Gate-Gap Audit

**Status:** discovery complete (2026-07-25); **2** autonomous gates CLOSED (§2 A1-revalidate; §2b fieldless back-solve 6-term inverse — the latter from the round-10 apply-path invariant audit `wf_a941ce55`, 2026-07-28), surface otherwise SOUND under its documented trust model. FOURTH code-surface register in the falsify-on-mutant series, after
[ProofClaimGateTraceability](ProofClaimGateTraceability.md), [ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19), and [RpcIngressGateAudit](RpcIngressGateAudit.md).

## 0. Surface & method

The **deserialize + restore path** — how UNTRUSTED serialized input becomes in-memory chain
STATE: `Chain::restore_from_snapshot` (chain.cpp:2390), `Chain::load` (chain.cpp:2867, disk
`chain.json` replay), `Block::from_json` / `Transaction::from_json` (block.cpp), and node adoption
(node.cpp:563 disk load, node.cpp:596 snapshot restore).

Discovery workflow `wf_49023d9a-63d` — 5 finders (invariant-revalidate / missing-validation /
overflow-seed / restore-DoS / crash-coverage) → dedup → 8 adversarial REFUTE-by-default verifiers
(each classifying autonomous-safe vs owner-gated). 13 agents, ~1.1M tokens.

## 1. Verdict

**The snapshot-restore surface is SOUND under its documented trust model, with one real robustness
gap (now CLOSED).** The headline result of the adversarial pass: **snapshot adoption is
operator-opt-in, not remotely reachable.** `on_snapshot_response` is **never wired** on the full
node (gossip.cpp:279 calls a null `std::function`; node.cpp wires only `on_snapshot_request`), so a
pushed `SNAPSHOT_RESPONSE` frame is dropped. The single ingestion site is an **operator-configured
file** (`cfg_.snapshot_path`, node.cpp:591-596) — weak-subjectivity bootstrap (trust-the-source),
the documented model (PROTOCOL.md §11.1, S-012/S-033). The trustless alternative already ships:
`snapshot inspect --state-root <hex>` verifies the tail root against an externally-trusted root.

- **8 findings → 1 CONFIRMED autonomous-safe** (§2, CLOSED), **3 rank-1 "consensus" REFUTED** (they
  are the documented trust model, not vulns — §3), **3 enum-range findings REFUTED** (values survive
  the cast but have no state-affecting outcome — §3), **1 REFUTED owner-gated** (§3).

## 2. CLOSED — restore A1-revalidate (`test-snapshot-a1-revalidate`)

`restore_from_snapshot` reconstructs `accounts_` / `stakes_` and the A1 supply counters
(`genesis_total`, `accumulated_*`) **directly** and never re-asserts the unitary-balance identity
that `apply_transactions` enforces on **every** block (chain.cpp ~1866:
`expected_total() == live_total_supply()`). The `head_hash` (chain.cpp:2617) and S-033 `state_root`
(chain.cpp:2657) self-checks bind each leaf **value** but **not the accounting identity** among them
(`build_state_leaves` emits `c:genesis_total` + each `c:accumulated_*` + every `a:`/`s:` balance as
*independent* leaves; `compute_state_root` does no arithmetic over them). So a snapshot whose
`genesis_total` is set one below the identity value — self-consistent (state_root recomputed over the
tampered leaves), yet supply-inconsistent — loads clean, then throws **"unitary-balance invariant
violated"** on the FIRST post-restore block apply → the node can never apply another block →
**permanent wedge / DoS**. (A1 is also mod-2^64-blind, so a wrap-complementary tamper is doubly
unguarded.)

**Fix (OPT-IN node-adoption policy).** `restore_from_snapshot` gains a `bool
require_supply_invariant = false` param; when true, the end of restore re-runs the A1 identity once —
`if (c.expected_total() != c.live_total_supply()) throw …` — and rejects the inconsistent snapshot
**at load** instead of bricking the node on the first apply. **The node's operator-opt-in adopt path
(node.cpp) passes `true`**; the default `false` keeps the deserializer GENERAL, because tools and
round-trip tests legitimately serialize *synthetic* (non-A1-consistent) fixtures — the first
implementation checked unconditionally and regressed `test-snapshot-full-determinism` (a fixture that
doesn't satisfy A1), which is exactly what forced this cleaner scoping: the A1 re-verify is an
adoption policy, not a primitive-level invariant. Same identity the apply path already runs; **no
accept-rule / trust-model change**; inert for honest snapshots and for the fieldless branch
(chain.cpp:2630, which back-solves `genesis_total` into equality). Also corrected the misleading
chain.cpp:2646-2648 comment (it claimed "the committee-signed block_hash means the supplier cannot
manufacture a self-consistent forgery" — false on the restore path, which verifies no signature; it
is a self-consistency check under weak-subjectivity, per §1).

**Gate** = `test-snapshot-a1-revalidate` (bare Chain): build a chain, serialize, **bypass** the two
self-consistency gates the way a legitimate pre-S-033 / headerless snapshot does (zero the head's
`state_root`, drop `head_hash`), then tamper `genesis_total` by +1. With `require_supply_invariant=true`
restore MUST reject it, citing the A1 supply-invariant. **Controls**: the honest snapshot and a
self-checks-bypassed but A1-consistent snapshot both restore cleanly under `true` (no false-positive);
and the tampered snapshot restores cleanly under the **default `false`** (the opt-in control — the
general primitive is unchanged for tools/round-trips). **Falsify-on-mutant**: `if (false && expected
!= live)` flips EXACTLY the two REJECT asserts while the three positive/opt-in controls stay GREEN —
targeted counter-delta, both platforms.

## 2b. CLOSED — fieldless back-solve is the 6-term inverse of `expected_total()` (`test-snapshot-genesis-backsolve`)

Found by the round-10 apply-path invariant audit (`wf_a941ce55`, HIGH-confidence). A **fail-closed,
honest-unreachable, latent** correctness gap in the *fieldless* branch §2 relies on. When a snapshot
OMITS `genesis_total`, `restore_from_snapshot` back-solves it (chain.cpp:2628-2637) so the loaded
state satisfies A1 by construction — the §2 fix explicitly leans on this ("inert … for the fieldless
branch, which back-solves `genesis_total` into equality"). But §3.22 made `expected_total()` a
**six**-term sum (chain.hpp:590-597): `genesis + subsidy + inbound − slashed − outbound −
accumulated_shielded_`. The back-solve computed `genesis = live + (slashed + outbound) − (subsidy +
inbound)` — **omitting `+ accumulated_shielded_`**. `accumulated_shielded_` is restored at
chain.cpp:2443, *before* the back-solve, so on a fieldless snapshot carrying `accumulated_shielded_ >
0` the reconstructed `genesis_total_` was under-computed by exactly that amount, leaving
`expected_total() == live − accumulated_shielded_ ≠ live`.

**Fails closed, honest-unreachable — hence latent, not a live bug.** The mismatch is caught: the §2
`require_supply_invariant=true` re-check (chain.cpp:2693) throws at load, else the first post-restore
apply trips the A1 assertion (chain.cpp:1868). And it is unreachable via honest snapshots:
`serialize_state` writes `genesis_total` **unconditionally** (chain.cpp:2212) while
`accumulated_shielded` is emitted only when non-zero (chain.cpp:2219) — so any snapshot old enough to
omit `genesis_total` predates §3.22 ⇒ `accumulated_shielded_ == 0` ⇒ the back-solve was already
correct. The landmine: if the snapshot format ever makes the fieldless branch reachable with
`shielded > 0`, restore would silently under-compute `genesis_total_` and then **fail-closed REJECT a
valid snapshot** — a liveness bug.

**Fix (unconditionally correct, byte-neutral on every honest path).** Fold `+ c.accumulated_shielded_`
into `deltas_neg` (chain.cpp:2637) so the back-solve is the **exact inverse** of the 6-term
`expected_total()`: `genesis = live + slashed + outbound + accumulated_shielded_ − subsidy − inbound`.
On every honest fieldless snapshot `accumulated_shielded_ == 0`, so the term is `+0` and every
existing snapshot/supply test stays byte-identically green. Threaded into
[SupplyInvariantComposition](SupplyInvariantComposition.md) SI-2 and
[SnapshotDeterminismComposition](SnapshotDeterminismComposition.md) SD-5 (the code fix + gate;
the broader 5→6-term exhaustiveness reconciliation across the supply proofs is the §3.22 shielded-pool
doc pass).

**Gate** = `test-snapshot-genesis-backsolve` (bare Chain): serialize an honest shield-free chain,
bypass the two self-consistency gates (zero head `state_root`, drop `head_hash`) the way a legitimate
pre-S-033 / headerless snapshot does — required because `accumulated_shielded_` is a *state-root leaf*
(chain.cpp:502-503) so injecting it into a chain with no matching shielded state would otherwise trip
the state_root gate for an unrelated reason — then hand-build the otherwise-unreachable
fieldless+shielded snapshot (omit `genesis_total`, set `accumulated_shielded = X`). Asserts the
back-solved `genesis_total_ == base + X`, `expected_total() == live_total_supply()`, and that the
VALID snapshot restores cleanly under `require_supply_invariant=true` (NOT fail-closed rejected).
**Controls**: a shield-free fieldless snapshot (X == 0) back-solves to the honest genesis and restores
clean. **Falsify-on-mutant**: deleting `+ c.accumulated_shielded_` flips the three fieldless+shielded
asserts RED (restore rejects the valid snapshot citing `expected_total = live − X`) while the
shield-free control stays GREEN — proving byte-neutrality on honest snapshots. Verified both build
mutant→RED / fix→GREEN on MSVC.

## 3. REFUTED — the surface is sound under its trust model

| finding | why REFUTED |
|---|---|
| `snapshot-restore-bypasses-genesis-pin-and-committee-sig` (rank-1) | `on_snapshot_response` **unwired** → not remotely reachable; ingestion is operator-opt-in file bootstrap = documented weak-subjectivity model. A residual: the operator `genesis_hash` pin is skipped on the snapshot path (`goto chain_loaded`, node.cpp:620) — a defense-in-depth nit, **owner-gated** (any enforcement is a trust-model change; short-chain snapshots may lack block[0]). |
| `s033-state-root-skipped-on-zero-root-head` / `restore-state-root-gate-downgrade-bypassable` (rank-1) | The head_hash/state_root checks are **self-consistency** between two attacker-controlled fields, not a committee-sig trust anchor — that is the *documented* design, not a bypass. Trustless verification is out-of-band (`snapshot inspect --state-root`). Not remotely reachable. |
| `consensus-mode` / `tx-type` / `crypto-profile` enum-not-range-checked (rank-2) | The out-of-range value survives the `static_cast`, but has no state-affecting outcome on the restore path (mode is in `compute_hash` not `compute_state_root`; the values are inert on load). A parse-side `{0,1}`/domain throw would be pure hardening with no accept-rule change, but there is no live bug to pin — left as an optional future robustness nicety. |

## 4. Follow-up (not this register)

Owner-gated / lower-value residuals: enforce the `genesis_hash` pin on the snapshot path (trust-model
decision); optional enum-domain throws in `from_json`; `Chain::load` disk-file size ceiling
(operator-adjacent, low-severity). None is remotely reachable given the unwired `on_snapshot_response`.
