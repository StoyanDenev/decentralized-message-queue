# Decision Log — design deliberation history

**Purpose.** Append-only log of the deliberation behind decisions captured in the spec files. The specs are authoritative for *what* was decided; this log is authoritative for *why* — the rejected alternatives, mid-review reversals, user-driven amendments, and cross-decision trade-offs that don't survive in spec text alone.

**Audience.** Implementation threads picking up bundles from `IMPLEMENTATION-SEQUENCING.md`. The team executes review-week decisions as 4-32 parallel Opus 4.7 threads (per memory `dlt-team-composition`); no thread carries tacit deliberation context across sessions. This file is the only deliberation source. Without it, threads will re-litigate closed decisions or make downstream choices incompatible with the rejected-alternative reasoning.

**Convention.** Append entries with date + spec reference. Do not modify or delete existing entries (history is the audit trail). If a decision is later revised, append a new entry referencing the prior one — do not edit the original.

**Format.** Each entry: question → options considered → choice → why others were rejected → cross-decision implications worth flagging.

---

## 2026-05-24 — Review week (CRYPTO-C99-SPEC.md)

### C99-11 mid-review revise: `tactical_civilian` + `cluster_civilian` profiles added

**Question.** Original C99-11 bundled crypto profile with timing profile: `tactical` = FIPS + sub-30ms; `cluster` = FIPS + ~50ms; `web/regional/global` = MODERN + various latencies. This forced commercial sub-50ms deployments into either accepting FIPS or downgrading to `regional` (~150ms).

**Why the revise.** A commercial drone-fleet operator, an industrial-robotics deployment, and a high-frequency commercial settlement deployment all need sub-50ms blocks but have no FIPS requirement. The original profiles didn't serve them: `tactical`/`cluster` bundled FIPS unnecessarily; `regional` was too slow.

**Choice.** Added two MODERN-profile variants at tactical/cluster latencies: `tactical_civilian` (sub-30ms, MODERN crypto) and `cluster_civilian` (~50ms, MODERN crypto). FIPS bundling stays explicit on `tactical`/`cluster` only.

**Why not just decouple crypto from timing entirely?** Decoupling restores the "two operator decisions" problem that bundling was meant to fix. Adding two more bundled options preserves "one operator decision" while serving the commercial low-latency case.

**Cross-decision implication.** Confidential transactions (PRIV-2 Bulletproofs) are MODERN-only. `tactical_civilian` and `cluster_civilian` accounts CAN use confidential txs; `tactical` and `cluster` cannot. Document for operator profile selection.

---

## 2026-05-24 — Review week (v2.22-PRIVACY-SPEC.md)

### PRIV-2 mid-review reversal: ristretto255 → secp256k1 for Bulletproofs

**Question.** Earlier v2.22 draft chose Bulletproofs over ristretto255 (curve25519 family) via dalek-cryptography reference. Why did this flip to secp256k1?

**Why the reversal.** The only mature C99 ristretto255 implementation is in libsodium. Vendoring libsodium-derived ristretto255 source conflicts with the libsodium-removal strategy in CRYPTO-C99-SPEC.md. Either we keep libsodium permanently (defeats the C99 strategy) or we vendor an unproven ristretto255 port (introduces audit risk).

**Choice.** Bulletproofs over secp256k1 via libsecp256k1-zkp (Blockstream / Mimblewimble-Grin). libsecp256k1 is Bitcoin Core's pinned secp256k1 library — ~$1T+ secured; multiple audits; libsecp256k1-zkp ships Bulletproofs production-ready since 2018-2019 (Liquid sidechain, Grin).

**Why not BLS12-381 (blst)?** Adds a third curve family for pairing-based primitives we don't need. God Stack pattern offloads pairing-based ZK to external L2.

**Cross-decision implication.** This decision indirectly shaped PRIV-3 (amount handshake curve choice). With Pedersen commitment on secp256k1 anyway, putting the DH on a different curve (X25519) created a two-curve protocol with no benefit. PRIV-3 was later revised to consolidate on secp256k1.

### PRIV-3 evolution: X25519 → secp256k1 ECDH → "curve follows profile"

**Question.** Amount handshake DH curve: stay with X25519 (was the original draft) or move to secp256k1?

**Why the move.** Three reasons converged:
1. PRIV-2 already pinned Pedersen commitment to secp256k1 — using X25519 for DH created an unnecessary two-curve protocol.
2. secp256k1 ECDH is in libsecp256k1 (already vendored for Q2 Bulletproofs); zero additional vendoring cost.
3. The "curve follows profile" principle from CRYPTO-C99 §2.Q1 was being violated by hardcoding X25519.

**Final form.** "Curve follows profile across all v2.22 DH: MODERN → secp256k1 ECDH; FIPS → NIST P-256 ECDH. X25519 removed from v2.22 (stays for v2.10 FROST-Ed25519 only)."

**Subtle constraint.** v2.22 confidential txs are MODERN-only (per C99-11 transitively). So the FIPS branch of the principle is never exercised by confidential txs themselves — it applies to adjacent DH-using protocols (v2.24 audit-key exchange) that might be added later in FIPS mode.

**Cross-decision implication.** Required CRYPTO-C99 to explicitly add P-256 ECDH (not just ECDSA) to the FIPS primitive inventory. Spec edit applied in §2.Q11 table.

### PRIV-5 split disposition: migration N/A; rotation tx types ship in v1.0

**Question.** PRIV-5 reads as "wire-format break + flag-day migration." Pre-mainnet status means migration is N/A — but does that defer the rotation tx types (`PUBLISH_VIEW_KEY`, `ROTATE_VIEW_MASTER`) too?

**Why the split was needed.** The tx types are operational primitives, not migration artifacts:
- `PUBLISH_VIEW_KEY`: used by every account that wants its view-key chain advanced. Day 2 of the chain depends on it.
- `ROTATE_VIEW_MASTER`: used the first time any account suffers a key compromise post-launch. Without it shipped at v1.0, the first compromised account triggers a hard fork.

**Choice.** Migration plumbing = N/A (no live chain to migrate from). Rotation tx types ship in v1.0 as operational primitives. The "migration N/A" disposition is for the dual-decode / flag-day / format-version-negotiation machinery, not for the tx types themselves.

**Generalization.** When pre-mainnet eliminates a "migration" decision, separate the *operational mechanism* from the *migration mechanism*. The former still ships; the latter is N/A.

### PRIV-6 (per-tx PFS): added mid-review based on user concern about long-term-key exposure

**Question.** Q3 amount handshake binds every confidential tx to the recipient's long-term `view_master_pk`. Compromise of `view_master_sk` decrypts every past confidential tx for the account. User asked: "Can we achieve Perfect Forward Secrecy?"

**Why the addition.** The cryptographic exclusivity is per-ciphertext: PFS and key-disclosure-audit cannot both hold for the same ciphertext. The existing design committed every tx to "auditable." High-stakes use cases (journalism, dissent, regulator-resistant payments) need PFS-per-tx as an opt-in mode.

**Choice.** Per-tx mode flag (`amount_mode: AMT_AUDITABLE | AMT_PFS`) + account-level immutable policy lock (`confidential_policy: AUDITABLE_ONLY | PFS_ONLY | MIXED`). In MIXED, sender picks per tx. In AUDITABLE_ONLY or PFS_ONLY, validator rejects the other mode at apply time.

**Why per-tx mode is exclusively per-ciphertext, but policy is locked per-account.** Crypto says exclusivity is per-ciphertext. Policy says lock at account level. Reason: per-tx mode selection within a MIXED-claimed account allows selective hiding of individual txs from audit — a regulatory evasion concern. Account-level lock at creation forces the operator to commit to its audit posture upfront; per-tx selection only happens in MIXED accounts that explicitly opted into mixed posture.

### PRIV-6 OTPK retention = Option D (permanent hash-only marker)

**Question.** After a one-time pubkey (OTPK) is consumed by a PFS tx, what stays on-chain? Recipient has deleted the privkey (PFS achieved); the chain has marked the OTPK used. Four options compared:

| Option | What stays | Cost |
|---|---|---|
| A | Full OTPK entry for ~10000 blocks, then hash-only marker | Apply-path pruning scheduler + grace-window state machine |
| B | Full entry forever | Largest permanent footprint per used OTPK |
| C | Per-account configurable retention | Per-account validator complexity |
| D | Atomic replacement at apply: full entry → 32-byte hash-marker | Smallest permanent footprint; no background pruning |

**Choice.** Option D.

**Why not A?** The 10000-block grace window buys nothing operational. After the tx applies, there's no retrieval reason to query the full OTPK pubkey — the recipient's wallet decrypted at apply time; outside auditors see swiss-cheese in PFS-mode anyway. Grace-window state machine adds complexity for no benefit.

**Why not B?** Larger permanent state for no retrieval advantage. ~32 bytes per used OTPK forever is ~3.2GB/year at 1M accounts × 100 PFS receives/year; full retention would be ~4.3GB/year. The delta isn't catastrophic but it's pure waste.

**Why not C?** Per-account retention adds validator complexity (each manifest verification must check each account's policy). No clear use case for variable retention.

**Cross-decision implication.** PRIV-6.1 reconciliation requires recipient wallets to locally cache their own `(otpk_id → otpk_pk)` mappings for batches they published — under Option D, the on-chain pubkey is gone after apply, so reconciliation's verification step 2 must come from chain *history* (queryable PUBLISH_OTPK_BATCH txs) plus wallet-side cache. Wallet cost: ~130KB/year — trivial.

### PRIV-6.1 (wallet-loss reconciliation): added based on user concern about pure-PFS failure mode

**Question.** PRIV-6 has recipient delete `otpk_sk` after use. If recipient wallet is lost before the apply step (or before observing it), the amount is permanently undecryptable. User asked: "Can we recover?"

**The cryptographic tension.** Any recovery mechanism for OTPK privkeys defeats PFS for the txs those privkeys can decrypt. PFS *means* no current secret can decrypt past traffic — by definition, recoverability and PFS are mutually exclusive.

**Six options considered.** A (accept the loss; document), B (encrypted backup, rolling), C (encrypted backup, permanent), D (deterministic from seed), E (sender-side record + recipient-asks-sender), F (double-encrypted with view_master fallback).

**Choice.** A + E. Pure PFS posture; off-chain sender-side reconciliation for bookkeeping recovery.

**Why not C, D, F?** They're not actually PFS — they're "audit-with-extra-steps." Sender backup compromise (C) or seed compromise (D) defeats the PFS guarantee. Double-encryption with view_master fallback (F) is structurally equivalent to AUDITABLE mode.

**Why not B?** Encrypted-backup-rolling is a real middle ground but introduces a backup-storage threat model question (where does the encrypted backup live? who can compromise it?) that adds scope for marginal benefit.

**Key insight that made A+E viable.** Recipient can verify sender's claim of "I sent you X" using only the on-chain Pedersen commitment + sender-disclosed `(amount, blinding_factor)`. No new crypto needed; on-chain footprint zero. The recipient *bookkeeping* breaks on wallet loss; the *funds* are still in the account (commitment math already updated balance).

**Honest residual.** Sender refusal or dual wallet loss leaves amount unrecoverable. Equivalent to losing a paper receipt for cash.

### PRIV-6.2 (cadence padding): added after recognizing PFS protects amounts but not metadata

**Question.** `PUBLISH_OTPK_BATCH` events are on-chain by necessity. Their timing leaks recipient's PFS-receive cadence. For the high-stakes threat models that justified PRIV-6 (journalism, dissent), metadata leakage is often as sensitive as amount leakage.

**Four mitigation classes considered.** A (cadence padding), B (cohort batching), C (decoy batches), D (accept as residual + document).

**Choice.** A + per-account opt-in. Per-account immutable `pfs_padding_cadence: NONE | DAILY | HOURLY` field. Default DAILY for `PFS_ONLY` accounts; default NONE for `MIXED`.

**Why not B?** Cohort batching requires recipient-coordination protocol that reduces to mixnet design. Out of scope for v2.22.

**Why not D?** Undermines PRIV-6's value proposition for the threat models it serves.

**Cost analysis under chain pruning (user observation).** Padding's per-account chain bandwidth cost is bounded under pruning — old padding txs prune to active-state amortization. Per-account tx fees are the remaining cost, paid by the user explicitly for cadence privacy. Anonymity-set thinness is the residual: if only PFS_ONLY accounts pad, padding cadence itself signals "high-stakes account." Operator guidance: encourage MIXED accounts in high-stakes deployments to opt into DAILY even when not strictly needed.

### PRIV-6 alternative-mechanism rejection summary

Four broader PFS alternatives considered and rejected for v1.0:

| Alternative | Why rejected |
|---|---|
| Forward-secure encryption / forward-secure HIBE | Eliminates cadence leak entirely (single PUBLISH at account creation). Rejected: canonical Canetti-Halevi-Katz uses bilinear pairings → BLS12-381 → third curve family. Pairing-free lattice-based constructions are bleeding-edge with no production deployments. |
| Puncturable encryption (Green-Miers) | Per-tx PFS without publish events. Rejected: research-grade; no production deployments; growing secret-key state; false-positive risk in Bloom-filter variants. |
| Stealth addresses (Monero-style) | Mature production deployment since 2014; combines amount-PFS with graph privacy. Rejected: full chain scan per recipient per receive; light-client problem unsolved at scale; architectural change vastly larger than v2.22's amount-PFS scope; conflicts with v2.24 audit model. Appropriate v3+. |
| Out-of-band ephemeral exchange | Zero on-chain metadata. Rejected as general solution: requires bidirectional OOB channel per sender-recipient pair; useless for ad-hoc send. May ship as opt-in "established-pair PFS" mode later. |

If a future implementation thread proposes one of these as a "better PFS" — the answer is "considered; rejected for these reasons; revisit when [the rejection reason] no longer applies."

---

## 2026-05-24 — Review week (Beaconless-v2-SPEC.md)

### BL-3 / BL-5 / BL-6 manifest-tunability pattern

**Question.** Three Beaconless v2 parameters were originally specified as fixed constants: `EPOCH_SNAPSHOT_INTERVAL` (BL-3), `merritt_k` (BL-5), `epoch_boundary_cutoff_blocks` (BL-6). Should they be hardcoded or operator-tunable?

**Choice.** All three → manifest-tunable. Added to `Beaconless-v2-SPEC.md §Q2` manifest contents.

**Why the pattern won.** Each parameter has a legitimate range of operator preferences:
- `epoch_snapshot_interval`: varies with profile epoch length and deployment scale
- `merritt_k`: varies with threat model (k=1 for typical; k=2-3 for high-stakes with enough shards)
- `epoch_boundary_cutoff_blocks`: liveness/bias trade-off varies with deployment topology

Hardcoding any one of them either ships defaults that don't fit some deployments OR forces forking for every variant. Manifest-tunability has near-zero implementation cost (one more field) and lets the manifest become the central tuning surface.

**Cross-decision implication.** Triggered Q2.1 manifest validity amendment — operator-tunable parameters need bounds-checking or they become silent footguns (see Q2.1 entry).

### BL-6 randomness handling: user initially picked VRF, was wrong choice

**Question.** Late-shard randomness: stall vs subset-with-recording. User initially answered "Use VRF-based aggregation" — overriding the spec's threshold-sig + subset-recording mechanism.

**Why VRF wasn't actually better.** Pushback explained: VRF doesn't solve the late-shard problem. The remaining attack surface is *withholding* (a shard refuses to sign or network delays the gossip past cutoff). VRF has the identical withholding attack. Switching primitives:
- Adds new crypto to C99 inventory (VRF over Ed25519 / P-256, separate impl per profile)
- Discards v2.10 DKG composition (FROST-Ed25519 already in tree)
- +2-4 weeks effort for sideways move

**Choice after pushback.** Revised to "Revise — pin cutoff in manifest" (threshold-sig accumulator + subset-recording + manifest-tunable cutoff window).

**Generalization for future threads.** If a user picks an option that contradicts the spec, push back constructively — the user may be reaching for a property that the proposed alternative doesn't actually deliver. Explain the underlying problem, then re-ask.

### Q2.1 manifest validity: hard/soft validation split (no operator override for Merritt invariant)

**Question.** Operator-tunable manifest parameters can be misconfigured. `merritt_k=2` with `num_shards=4` silently violates `num_shards > k(k+1)` → deployment runs with weaker Byzantine tolerance than claimed; no observable signal until adversarial exploitation. How to prevent?

**Two-tier choice.**
- **Hard invariants** (consensus-enforced; `MANIFEST_UPDATE` apply path rejects): `merritt_k`-related Byzantine tolerance precondition. **No operator override path.**
- **Soft warnings** (manifest-construction tooling only): performance bounds (snapshot interval, cutoff blocks). Override via `--acknowledge-soft-violations` flag.

**Why no operator override for Merritt.** The Merritt invariant is a *precondition for the security property the spec claims*. Allowing override means the deployment can claim properties it doesn't have. An operator who deliberately wants weaker tolerance can run a fork with adjusted constants — that's the correct escape valve.

**Why soft for performance.** Performance failure modes (snapshot churn, liveness loss) are operationally visible (slow nodes, stuck epochs). Operations teams catch and fix them. Consensus-enforcing performance bounds would freeze the operating envelope and prevent legitimate experimentation.

**Generalization.** Security failures (silent until exploited) → hard. Performance failures (operationally visible) → soft. This pattern should be reused for any future operator-tunable parameter that gates a security claim.

---

## 2026-05-24 — IMPLEMENTATION-SEQUENCING.md

### Approach C (bundled releases) chosen over A, B, D

**Question.** How to sequence implementation of 41 review-week decisions + 4 amendments?

**Options.**
- A. Strict topological (build prerequisite first, dependent only after stable)
- B. Pipelined with stubs (start dependents against stubbed prerequisites; rebase as prerequisites land)
- C. Bundled releases (ship related decisions together as discrete releases)
- D. Parallel teams (separate streams by discipline)

**Choice.** C.

**Why C over A.** Strict topological is too slow; serializes work that doesn't actually need to serialize.

**Why C over B.** Stub-based pipelining has rework risk if prerequisite design shifts. With user-driven amendments (PRIV-6/6.1/6.2 added mid-review), the rework risk is non-trivial.

**Why C over D.** Discovered after the choice (see §4.1 update) that the team is 4-32 parallel Opus 4.7 threads — discipline boundaries don't apply. D's framing was wrong from the start.

**Consequence.** Each bundle ships as a unit (v2.22 = PRIV-1..6.2 all together). Larger blast radius per release but cleaner user-facing story and cleaner audit scope.

### Phase D criterion: pure Option C (named-feature checklist, no stability gate)

**Question.** "v2 + Theme 9 substantially shipped" needs a concrete definition to gate Bundle 5 start.

**Four definition styles considered.** A (code-complete checklist), B (code-complete + N weeks stable), C (named-blocking-feature checklist; ignore non-blockers), D (audit completion).

**Choice.** Pure C (no stability gate).

**Why C over B.** User explicit picked C (not B, not the hybrid C+lightweight-B I recommended). The trade-off accepted: code-complete on blocking subset is the trigger; if a feature regresses after Phase D opens, Bundle 5 work doesn't unwind — fixes land in parallel.

**Why not A.** A includes non-blocking work in the gate; defers Phase D unnecessarily.

**Why not D.** Couples Phase D to external audit calendar; unacceptable schedule risk.

**Open at log time.** The actual blocking-feature checklists for v2 and Theme 9 are pending team input — see `IMPLEMENTATION-SEQUENCING.md §4.2`.

### Team composition discovery and its impact on §4.1

**Question.** Sequencing plan assumed engineering-discipline-bounded capacity. What's the actual team?

**Answer.** 4-32 parallel Opus 4.7 development threads. No human-discipline boundaries.

**Implication.** Capacity is no longer the binding constraint; coordination is. Wall-clock for Phase B/C ≈ longest single bundle (~3-3.5 months) rather than sum-of-bundles. Phase D ≈ Bundle 5 (~3-4 months). Total horizon: ~6-7.5 months gated on coordination quality.

**New failure modes specific to AI parallel threads.** Merge conflicts, architectural drift, cross-bundle interface contracts, test-discipline criticality, verification of generated work. Documented in `IMPLEMENTATION-SEQUENCING.md §4.1` with recommended coordination practices (pre-bundle interface freeze, single integration thread per bundle, pre-merge test gating, bundle-boundary verification, specs-as-canonical).

**Why this log file exists.** Without persistent decision-history, every parallel thread starts fresh and re-litigates closed deliberations. The user explicitly chose Option B (this dedicated log) over Option C (richer inline alternatives-rejected sections) after weighing the trade-off.

---

---

## 2026-05-24 — IMPLEMENTATION-SEQUENCING.md §4.3 (post-review-week amendment)

### Bundle release cadence + "no migrations" project constraint

**Question.** With Approach C bundled releases chosen, when do bundles ship? Three options: A (big-bang v1.0, internal-only until launch), B (phased post-launch with migration), C (pre-mainnet iterative v0.x + single v1.0 mainnet cut).

**User-introduced constraint.** "No migrations at all." Initially stated as "no migrations until v3," then strengthened to "no migrations at all" in the next message.

**Choice — release cadence.** Option A. No public pre-mainnet releases; internal development only; single launch event ships all 5 bundles together; total horizon ~6-7.5 months.

**Why A over C.** Trade-off accepted: forgo public delivery cadence + testnet adoption + incremental audit in exchange for one clean launch event. Reduces release-management overhead during development.

**Why B was dead from the constraint.** Phased post-launch requires migration plumbing for Bundles 4 and 5, which directly violates "no migrations at all."

**Choice — interpretation of "no migrations at all".** Practical reading: no breaking changes post-v1.0. In-protocol mechanisms (ROTATE_VIEW_MASTER, ROTATE_AUDIT_KEY, MANIFEST_UPDATE, PUBLISH_OTPK_BATCH) remain allowed because they are governed by consensus rules shipped in v1.0 — they execute the rules, they don't change them. Additive-only post-v1.0 changes allowed (new optional fields validators can ignore, new tx types that legacy validators fail-closed on). Security-critical hard forks reserved as last resort.

**Why not the strict literal reading.** Strict literal would make v1.0 immutable: no rotations, no manifest mutations, no security patches, ever. Locks in any v1.0 bugs permanently. User confirmed practical interpretation when asked.

**Why not the middle ("in-protocol only").** Middle reading bans additive evolution post-v1.0, which would prevent shipping any genuinely-new feature later (even backward-compatible ones). Too restrictive for long-term project health.

**Implications for review-week decisions.** None invalidated. The "pre-mainnet, no migration" disposition is now the *permanent* extension forward through v1.0 launch — no review-week decision needs re-design. All 5 bundles must complete before mainnet; BL-7/BL-8 sequencing stands.

**Future-evolution discipline established.** Implementation threads proposing post-mainnet wire/state/consensus changes must: (a) push into v1.0 scope, (b) restructure as additive-only, or (c) escalate as security-critical hard-fork candidate. Default answer to "can we change X post-mainnet?" is **no**. See memory `dlt-no-migrations-constraint` for the canonical statement.

---

*End of decision log. Append new entries below as future deliberations conclude.*
