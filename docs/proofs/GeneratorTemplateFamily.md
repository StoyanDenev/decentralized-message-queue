> **TIER: FUTURE — post-1.0, non-authoritative.** Consolidates the DSF §Q5 generator-template family shipped under `sim/`. Companion: `docs/proofs/DSF-SPEC.md` (§Q5 generator, §Q6 replay, §Q7 checker families). Roadmap index: `docs/ROADMAP.md`.

# DSF Generator-Template Family

A source-faithful consolidation of the eight DSF generator templates (`sim/generator.hpp`, wired in `sim/dsf_main.cpp`, gated by `tools/test_dsf_inc{4,6,7,8,9,10,11,12}.sh`). This document is the reference for the template pattern and the recipe for the next one. With inc-11 (crash/recover) and inc-12 (partition/heal), the generator exercises EVERY fault dimension the simulator models: message faults (drop/dup/latency/jitter), node crash/recovery, and link partitions.

---

## 1. Purpose

The DSF generator (DSF-SPEC §Q5) emits seed-driven scenario variants. Each variant is a deterministic function of a generator seed: every random choice routes through `draw_params(SplitMix64&)`, so the same generator seed produces the same variants, byte-for-byte, on any host.

A **template** is a DSF-SPEC §Q7 checker family instantiated as a generator: an honest protocol that is robust *by construction* under any drawn fault profile, paired with

- a **SAFETY** invariant and a **LIVENESS** invariant, each a pure function of `const SimState&`, and
- exactly **one** planted-bug **self-test twin** (`expect_violation = true`) that proves the checker fires on the specific bug it targets.

The discipline is plain: a green checker that never fires is worthless. A SAFETY invariant that no scenario can violate proves nothing about the checker — only about the absence of a trigger. So every template ships its falsifying twin: a fixed-profile variant with the honest apply replaced by the exact bug the invariant exists to catch. The twin runs on every CI pass; if the checker is ever weakened to the point that it no longer catches the planted bug, the twin fails closed (the runner returns exit 1 — "expected a violation but none fired").

---

## 2. The shared fault profile

All eight templates draw from the SAME distribution. `draw_params` (verbatim from `sim/generator.hpp`) fills a `GenParams` from the generator PRNG:

| Field          | Draw                              | Range / set             |
|----------------|-----------------------------------|-------------------------|
| `followers`    | `2 + g.next_below(3)`             | `2 .. 4`                |
| `base_latency` | `vt_ms(g.next_below(3) * 5)`      | `{0, 5, 10}` ms         |
| `jitter`       | `vt_ms(g.next_below(3) * 5)`      | `{0, 5, 10}` ms         |
| `drop`         | `kDrops[g.next_below(6)]`         | `{0.0,0.1,0.2,0.3,0.4,0.5}` |
| `dup`          | `kDups[g.next_below(3)]`          | `{0.0, 0.5, 1.0}`       |

Every field routes through the generator PRNG `g`, so the whole profile is a deterministic function of the generator seed. The two-seed model holds across all templates: the fault **parameters** (this profile) are a function of the generator seed baked in at registration; the fault **realization** (which individual messages drop/duplicate at run time) is a function of the run `--seed`. Both are deterministic. Each family draws from its OWN `SplitMix64(gen_seed)`, so adding a new family never changes a prior family's drawn profiles.

---

## 3. The eight templates

Each template is robust because its honest apply has an algebraic property — idempotent, monotone, or reorder-immune — that neutralizes the drawn drop/dup/latency/jitter. That property, not the invariant, is what makes every honest variant pass. The self-test replaces exactly that property with a fragile alternative and shows the invariant fires.

### 3.1 Broadcast — §Q7 reliable-broadcast

- **Honest mechanism.** A leader re-broadcasts the current issued total as an idempotent, monotone `SET(total)`; each honest follower does monotone-max latching: `if (v > count) count = v`.
- **Why robust.** `max` is idempotent (a re-delivered `SET` changes nothing) and reorder-immune (out-of-order `SET`s still leave `count` at the running max). Under any drop ≤ 0.5 a late `SET(final)` carrying the final total is overwhelmingly likely to land — and, being seeded, it deterministically does or does not.
- **SAFETY** `gen_no_overcount` — no follower's `count` ever exceeds the issued total.
- **LIVENESS** `gen_all_converge` — every follower's `count` reaches the final issued total.
- **Self-test** `gen_overcount_selftest` — the follower apply is NON-idempotent additive (`count += v`) instead of monotone-max; under forced duplication the additive apply overcounts and `gen_no_overcount` fires. Fixed profile: `followers=2, drop=0.0, dup=1.0`.
- **Baked prefix** `gen_broadcast` (also the default `--generate` prefix `gen_run`).

### 3.2 Agreement — §Q7 equivocation / partition

- **Honest mechanism.** A leader floods one decision value `V` to every follower; each honest follower is first-write-wins on `DECIDE(V)`: `if (decided == 0) decided = v`.
- **Why robust.** Only one value is ever flooded, and the first latch never changes, so duplicates and reorder cannot produce a second, conflicting decision.
- **SAFETY** `agree_no_split` — no two followers hold different non-zero decided values.
- **LIVENESS** `agree_all_decided` — every follower eventually decides the honest value `V`.
- **Self-test** `gen_disagree_selftest` — a Byzantine leader equivocates: it floods `V` to even nodes and `V'` to odd nodes. First-write-wins deciders then latch different values and `agree_no_split` fires. Fixed profile: `followers=4, drop=0.0, dup=0.0` (clean delivery — equivocation is the bug, not the network).
- **Baked prefix** `gen_agree`.

### 3.3 Ratchet — §Q7 BFT-escalation / commit-index

- **Honest mechanism.** A leader ramps a ceiling `0 → CEIL` and re-floods it; each honest follower keeps a monotone high-water mark `hi = max(hi, v)` and commits `cur = hi`.
- **Why robust.** Max-latching never regresses under reorder or duplication, so a committed value pinned to the high-water can only advance — exactly like Broadcast's `SET(total)` and Agreement's first-write-wins.
- **SAFETY** `ratchet_no_regress` — no follower's committed `cur` is below its own high-water `hi` (`cur < hi` is a regression).
- **LIVENESS** `ratchet_advanced` — every follower's high-water advances to the leader's ceiling.
- **Self-test** `gen_regress_selftest` — the follower commits the RAW last-seen value (`cur = v`, no max) AND a Byzantine leader sends a decreasing tail after the ceiling holds, so a raw committer's `cur` drops below its own high-water and `ratchet_no_regress` fires (deterministically, no network reorder needed). Fixed profile: `followers=2, drop=0.0, dup=0.0`.
- **Baked prefix** `gen_ratchet`.

### 3.4 Quorum — §Q7 DKG-threshold / BFT-pre-vote / merge-quorum

- **Honest mechanism.** A collector counts DISTINCT ack senders — a set keyed on sender id — and commits exactly once `distinct >= K = floor(N/2)+1`.
- **Why robust.** Distinct-set insertion is idempotent under duplication (a re-delivered ack from a known sender does not grow the set) and reorder-immune, so the tally reflects true assent regardless of drop/dup/latency/jitter.
- **SAFETY** `quorum_no_early_commit` — the collector never commits with fewer than `K` distinct assenters (audited via `committed_distinct`, the true distinct-set size recorded at commit time).
- **LIVENESS** `quorum_commits` — the collector eventually reaches quorum and commits.
- **Self-test** `gen_underquorum_selftest` — the collector counts RAW acks (duplicates included) instead of distinct senders. Under forced duplication a SINGLE source's acks drive the raw tally to `K` while only one distinct sender has assented, so the collector commits below quorum and `quorum_no_early_commit` fires. Fixed profile: `followers=2, drop=0.0, dup=1.0` (so `K = 2` and it commits at `distinct = 1`).
- **Baked prefix** `gen_quorum`.

### 3.5 Conservation — §Q7 cross-shard receipt conservation

- **Honest mechanism.** A source issues receipts with unique ids and re-floods them; each ledger credits a receipt EXACTLY ONCE, keyed on its id (`r_<id>`) — the production FA7 applied-receipt-registry rule.
- **Why robust.** Per-id dedup is idempotent under duplication (a re-delivered receipt changes nothing) and reorder-immune; the re-flood makes it drop-tolerant, exactly like Broadcast's `SET(total)`.
- **SAFETY** `conserve_no_double_credit` — no ledger's credited total ever exceeds the receipts issued.
- **LIVENESS** `conserve_all_credited` — every ledger eventually credits every issued receipt.
- **Self-test** `gen_doublecredit_selftest` — the ledger counts RAW deliveries (no id dedup), so the very first re-delivery (forced dup and/or the re-flood itself) drives `credited` above the issued total and `conserve_no_double_credit` fires. Fixed profile: `followers=2, drop=0.0, dup=1.0`.
- **Baked prefix** `gen_conserve`.

### 3.6 Reconcile — §Q7 F2 view reconciliation

- **Honest mechanism.** Two sources each flood their half of a growing entry universe (`src_a` the odd ids, `src_b` the even ids); each reconciler merges by union-keyed-on-entry-id (`e_<id>`) — the production F2 `no_phantom_evidence` rule (a reconciler must never hold evidence present in NEITHER source view).
- **Why robust.** Union-by-id is idempotent under duplication and reorder-immune; the re-flood makes it drop-tolerant. Merging from two genuinely distinct views exercises the cross-view half the single-source templates cannot.
- **SAFETY** `recon_no_phantom` — no reconciler holds an entry outside the issued universe `1..issued_hi`.
- **LIVENESS** `recon_complete` — every reconciler merges the complete issued universe from BOTH sources.
- **Self-test** `gen_phantom_selftest` — on every merge the reconciler ALSO fabricates a phantom entry (`id+100`) that no source ever issued; `recon_no_phantom` fires deterministically on a CLEAN delivery profile (the bug is in the apply, not the network). Fixed profile: `followers=2, drop=0.0, dup=0.0`.
- **Baked prefix** `gen_recon`.

### 3.7 CrashRecover — §Q7 crash-recovery replay

- **Honest mechanism.** The first template to exercise the simulator's crash/recover seam (`Node::alive`: deliveries to a crashed node are dropped, its `kv` PERSISTS). Every follower crashes and recovers on a deterministic index-derived schedule (down for `[110+30i, 230+30i)` ms — no PRNG consumed) layered under the drawn profile; because state persists, the honest recovery procedure does NOTHING — the leader's 40× re-flood heals the missed window like a transient drop burst.
- **Why robust.** Monotone-max latching is recovery-oblivious: persisted state stands, re-delivery is idempotent, and a recovered follower has ≥27 heal attempts even at drop=0.5.
- **SAFETY** `crashrec_no_replay` — no follower's count ever exceeds the issued total.
- **LIVENESS** `crashrec_all_converged` — REQUIRES `crashes == recoveries == followers` (the crash path can never go vacuous) AND every follower converged to the final issued total.
- **Self-test** `gen_replay_selftest` — the NON-IDEMPOTENT RECOVERY REPLAY bug class: at crash the follower snapshots its journal (`saved = count`); at recovery it re-applies it ON TOP of persisted state (`count += saved`, the classic redo-log double-apply) → `count=10 > issued=5`. Fires at the recovery event itself on a clean profile. Fixed profile: `followers=2, drop=0.0, dup=0.0`.
- **Baked prefix** `gen_crashrec`.

### 3.8 PartitionHeal — §Q7 partition-quorum split-brain

- **Honest mechanism.** The first template to exercise the NetModel PARTITION seam (link cuts decided at SEND time, healed later). Two quorum collectors observe the same N ack sources: `col_a` keeps full connectivity; `col_b` is cut from the ceil(N/2) MAJORITY of sources for a deterministic window `[10ms, 396ms)` — leaving exactly `floor(N/2) = K-1` reachable senders, one short of quorum, for every drawn follower count. The honest minority-side collector therefore CANNOT commit while partitioned and commits only after the heal.
- **Why robust.** Distinct-sender counting makes duplication useless as a quorum-faker; drop only delays; post-heal `col_b` needs only ONE of the previously cut senders across ~24 remaining re-acks. The `healed` scalar flips at 395ms, BEFORE the links reopen at 396ms, so a legitimate post-heal commit can never be misrecorded as pre-heal.
- **SAFETY** `part_no_minority_commit` — `col_b` never commits while partitioned from the majority (recorded at commit time via `committed_preheal`).
- **LIVENESS** `part_both_commit` — REQUIRES `healed == 1` (the partition window can never go vacuous) AND both collectors reached quorum.
- **Self-test** `gen_splitbrain_selftest` — the inc-3 `single_decision` bug class under generated profiles: `col_b`'s effective quorum mis-set to K-1, exactly its reachable minority, so it commits WHILE PARTITIONED. Fixed profile: `followers=4, drop=0.0, dup=0.0`.
- **Baked prefix** `gen_partition`.

---

## 4. Wiring

Verbatim from `sim/generator.hpp` and `sim/dsf_main.cpp`:

- **Builders.** Each template is a `make_<name>_variant(idx, p, correct, self_test, prefix)` that returns a `Scenario{setup, run, check}`. `setup` adds nodes, applies the drawn `GenParams` to the network (`set_base_latency/jitter/drop_rate/dup_rate`), and registers the SAFETY + LIVENESS invariants; `run` drives the leader/sources; `check` is a no-op. `correct` selects the honest vs. bugged apply; `self_test` sets `s.expect_violation` and picks the self-test name.
- **Catalogue.** `enum class GenTemplate { Broadcast, Agreement, Ratchet, Quorum, Conservation, Reconcile, CrashRecover, PartitionHeal };`
- **Dispatcher.** `make_variant(tmpl, idx, p, correct, self_test, prefix)` switches on `GenTemplate` (default → Broadcast).
- **Registration.** `register_generated_scenarios(out, gen_seed, count, prefix, with_selftest, tmpl)` seeds a `SplitMix64(gen_seed)`, draws `count` honest variants (`correct=true, self_test=false`), and — when `with_selftest` — appends exactly one self-test on a FIXED profile (`correct=false, self_test=true`) so the violation is guaranteed rather than seed-luck. The fixed profile branches per template (§3 gives each).
- **Baked sets** (`dsf_main.cpp`). Six honest sets of 6, each with its self-test:
  - Broadcast — `register_generated_scenarios(scenarios, 0x9E5C6E, 6)` → `gen_broadcast_00..05` + `gen_overcount_selftest`.
  - Agreement — seed `0x4A17E5`, prefix `gen_agree`, `GenTemplate::Agreement` → `gen_agree_00..05` + `gen_disagree_selftest`.
  - Ratchet — seed `0x7B3D91`, prefix `gen_ratchet`, `GenTemplate::Ratchet` → `gen_ratchet_00..05` + `gen_regress_selftest`.
  - Quorum — seed `0x2C9F44`, prefix `gen_quorum`, `GenTemplate::Quorum` → `gen_quorum_00..05` + `gen_underquorum_selftest`.
  - Conservation — seed `0x5D21A7`, prefix `gen_conserve`, `GenTemplate::Conservation` → `gen_conserve_00..05` + `gen_doublecredit_selftest`.
  - Reconcile — seed `0x6E8B29`, prefix `gen_recon`, `GenTemplate::Reconcile` → `gen_recon_00..05` + `gen_phantom_selftest`.
  - CrashRecover — seed `0x7F44D3`, prefix `gen_crashrec`, `GenTemplate::CrashRecover` → `gen_crashrec_00..05` + `gen_replay_selftest`.
  - PartitionHeal — seed `0x8A15C6`, prefix `gen_partition`, `GenTemplate::PartitionHeal` → `gen_partition_00..05` + `gen_splitbrain_selftest`.
- **CLI.** `--generate N [--template broadcast|agree|ratchet|quorum|conserve|recon|crashrec|partition]` registers `N` variants of the chosen template from the run `--seed`, with `with_selftest=false`, named `gen_run_00..0(N-1)`. `--template` maps `agree`/`agreement` → Agreement, `ratchet` → Ratchet, `quorum` → Quorum, `conserve`/`conservation` → Conservation, `recon`/`reconcile`/`reconciliation` → Reconcile, `crashrec`/`crashrecover` → CrashRecover, `partition`/`partheal` → PartitionHeal, else Broadcast.
- **Sweep runner.** `tools/operator_dsf_sweep.sh` (operator tool, not a commit gate) realizes the §Q6 "CI runs N variants overnight" contract: every template × deterministically-derived sweep seeds, each variant gated on exit code + the non-vacuous pass marker, one byte-diff replay check per (template, seed) pair, exact repro command lines on failure.

---

## 5. Determinism contract (§Q6)

Identical `(scenario-or-generate-args, --seed, --template)` ⇒ byte-identical trace. No wall-clock, no OS RNG anywhere in the loop. Re-run the printed seed to reproduce any failure exactly. On a violation the runner prints the reproducing `--scenario … --seed …` (+ `--trace`) command; a self-test's expected violation is the SUCCESS condition (exit 0).

Each template has a shell wrapper (`tools/test_dsf_inc4.sh` broadcast, `inc6` agreement, `inc7` ratchet, `inc8` quorum, `inc9` conservation, `inc10` reconciliation, `inc11` crash/recover, `inc12` partition/heal). Build-agnostic (SKIP-clean if `determ-dsf` is not built), they assert:

1. `--list` membership — all 6 baked variants + the named self-test.
2. Per-variant run-determinism — identical trace across two runs at a fixed seed.
3. Non-vacuous advance across several seeds — `invariant(s) held over [1-9][0-9]* steps` (never a zero-step vacuous pass).
4. The self-test exits 0, fires its NAMED invariant, and prints the reproducing seed.
5. `--template` routing — the generated `gen_run_NN` descriptions match the requested template.
6. Prior-template regression guards — default `--generate` is still Broadcast; `--template agree`/`ratchet`/`quorum` still route to their families.
7. Byte-identical replay of a generated variant (§Q6).

---

## 6. Recipe for the next template

The eight templates are one code pattern. To add a ninth:

1. **Pick an untapped §Q7 family** (e.g. selective-abort committee bias, equivocation-slashing lifecycle — receipt conservation and F2 view reconciliation shipped as inc-9/inc-10; crash/recover and partition/heal as inc-11/inc-12). Templates may also use the crash/recover and partition seams with a DETERMINISTIC index-derived schedule (no PRNG), as inc-11/inc-12 do — the fault window must be provably non-vacuous via the LIVENESS predicate (require the crash/heal counters in it).
2. **Define a robust honest apply** whose algebra neutralizes drop/dup/latency/jitter — idempotent, monotone, or order-immune. This is the load-bearing property, NOT the invariant. If you cannot name why the honest apply is robust under any drawn profile, the template is not ready.
3. **Write SAFETY + LIVENESS invariants** as pure functions of `const SimState&`, each with a `std::string* d` violation detail.
4. **Add `make_<x>_variant(idx, p, correct, self_test, prefix)`** returning a `Scenario{setup, run, check}`; branch `correct` between the honest apply and the planted bug.
5. **Extend `enum class GenTemplate`** with the new tag.
6. **Add the `make_variant` case** dispatching the new tag.
7. **Add the fixed-profile self-test branch** in `register_generated_scenarios` (the `if (tmpl == …)` ladder) so the violation is guaranteed, not seed-luck.
8. **Bake the honest set + self-test** in `dsf_main.cpp` (a fresh generator seed + prefix), and add the `--template` alias + usage-text token.
9. **Write `tools/test_dsf_incN.sh`** covering the seven assertions of §5 (membership, run-determinism, non-vacuous advance, named-invariant self-test firing + repro seed, `--template` routing, prior-template regression guards, byte-identical replay).
10. **Add `dsf_incN` to the `run_all.sh` FAST regex.**
11. **Thread the three doc surfaces** — `DSF-SPEC.md` (§Q5 IMPLEMENTED note), `README.md`, `UnitTestCoverageMap.md` — and this file's §3 table.

Twin discipline throughout: the self-test twin is not optional decoration. It is the proof that the checker catches its target bug, and it must fail closed if the checker is ever weakened — the runner turns a self-test that no longer fires into an exit-1 failure ("checker did not catch the planted bug").
