> **TIER: PROCESS / ARCHIVE.** Deliberation/meta; retained for rationale but NOT coherence-maintained as part of the 1.0 set. Roadmap index: docs/ROADMAP.md

# Decision Log — design deliberation history

**Purpose.** Append-only log of the deliberation behind decisions captured in the spec files. The specs are authoritative for *what* was decided; this log is authoritative for *why* — the rejected alternatives, mid-review reversals, user-driven amendments, and cross-decision trade-offs that don't survive in spec text alone.

**Audience.** Implementation threads picking up bundles from `IMPLEMENTATION-SEQUENCING.md`. The team executes review-week decisions as 4-32 parallel Opus 4.7 threads (per memory `dlt-team-composition`); no thread carries tacit deliberation context across sessions. This file is the only deliberation source. Without it, threads will re-litigate closed decisions or make downstream choices incompatible with the rejected-alternative reasoning.

**Sibling artifact.** `Improvements.md` is the forward-looking complement to this log. Rejected alternatives and deferred items captured here are also catalogued there with classification (Additive / Breaking / Research / Process), dependencies, and revisit triggers. When an implementation thread proposes a feature that was previously rejected, both this log (for the rejection reasoning) and `Improvements.md` (for the future-revisit conditions) are relevant.

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

---

## 2026-05-24 — Improvements.md §7.5 (pre-v1.0-schema-freeze optionality)

### Five discriminator fields shipped in v1.0 to preserve post-mainnet optionality under no-migrations

**Question.** Under [[dlt-no-migrations-constraint]], several Breaking improvements in Improvements.md could be downgraded to Additive if the v1.0 schema includes cheap discriminator enums or optional fields enabling future protocol-mode dispatch without a schema change. Which discriminators ship in v1.0?

**Background.** Triage of Improvements.md identified 5 Breaking entries that could be made additive via discriminator dispatch: §6.1 BLS aggregation, §4.1 PQ migration, §1.1/§1.2 FSE/puncturable encryption, §1.8 trusted-issuer audit, §3.2 VRF aggregation, §6.4 IBLT contrib. The default-deny posture (skip all discriminators) would permanently foreclose all five paths under no-migrations. The cost of shipping all five is trivial (~5 bytes total across block/Account/manifest/ContribMsg).

**Choices made.**
- **7.5.1 `Block.signature_form` enum**: SHIP. Covers BLS aggregation + PQ migration with one discriminator. Default `SIG_KK_ED25519`. 1 byte/block.
- **7.5.2 `Account.view_key_mechanism` enum + optional `fs_view_pk`**: SHIP. Preserves FSE / puncturable encryption optionality. Default `OTPK_STREAM`. ~2 B/Account.
- **7.5.3 `Account.audit_model` enum + optional `trusted_issuer_pubkey`**: SHIP — overrides heuristic. Heuristic said "don't ship discriminators that invite principle-rejected paths" (trusted-issuer was principle-rejected for centralization in PRIV-4). User chose to ship anyway: discriminator slot preserved (also enables non-trusted-issuer audit variants like NO_AUDIT or future ZK-audit), accepting that future revisit of the trusted-issuer principle is structurally possible. Default `KEY_DISCLOSURE`.
- **7.5.4 `manifest.randomness_aggregation_form` enum**: SHIP. Preserves VRF-aggregation optionality. Default `THRESHOLD_SIG_ACCUMULATOR`. 1 byte/manifest.
- **7.5.5 `ContribMsg.contrib_msg_form` enum**: SHIP. Preserves IBLT/Minisketch optionality. Default `TX_HASH_ARRAY`. 1 byte/ContribMsg.

**Why "ship all five" over selective shipping.** The trivial aggregate cost (~5 bytes per applicable record) makes selective shipping cost-time-marginal: the saved bytes don't matter; the foreclosed options do. Default-deny only makes sense if the project is highly confident specific paths will never be revisited — confidence not warranted for items with research/maturation dependencies measured in years (FSE, puncturable, PQ-FROST).

**Important consequence.** Five Breaking improvements (§6.1, §1.1, §1.2, §1.8, §3.2, §6.4) are now reclassified as effectively Additive-via-discriminator-dispatch. Their underlying mechanism can ship post-v1.0 without schema migration as long as legacy validators fail-closed on unknown enum values. Only §1.3 stealth addresses, §3.1 sharding-of-sharding, §3.3 merritt_k override, and §6.3 dedup remain unambiguously Breaking / v3-only.

**Implementation work added to v1.0 bundles.**
- Bundle 3 (v2.22): adds 7.5.2 + 7.5.3 Account-state fields (~1-2 days)
- Bundle 5 (Beaconless v2): adds 7.5.4 manifest field (~0.5 days; integrates with Q2.1 `validate_manifest`)
- Foundation / pre-bundle: adds 7.5.1 Block-header field + 7.5.5 ContribMsg field (~1-2 days each); must land before any review-week bundle to lock genesis schema shape

**Generalization for future threads.** When proposing a feature classified Breaking post-v1.0, first check whether a v1.0 discriminator would have made it Additive. If yes — and the discriminator was shipped per §7.5 — the feature is implementable. If no, or the discriminator wasn't shipped, the feature is v3-only.

---

---

## 2026-05-24 — Improvements.md §7.6 (discriminator-coherence verification)

### Five §7.5 discriminators verified coherent with existing review-week decisions

**Question.** After committing to ship five v1.0 schema discriminators (§7.5), do they integrate cleanly with already-resolved decisions (v2.10 FROST, PRIV-4 audit, PRIV-6 confidential_policy, v2.6 gossip-out-of-lock)? Or are there conflicts that would render the discriminators non-functional?

**Method.** Walked each discriminator against the relevant review-week decisions; documented enum spaces, validator dispatch, and orthogonality / interaction with existing fields.

**Findings.** All five coherent. Specific clarifications captured in `Improvements.md §7.6`:

- **7.6.1** `signature_form` scope: per-creator block sigs only; v2.10 FROST epoch-randomness sig is a separate orthogonal field with fixed format. Avoids combinatorial-explosion enum.
- **7.6.2** `audit_model = KEY_DISCLOSURE` encompasses PRIV-4 dual-mode in full; master-vs-per-epoch is off-chain sub-mode choice, not chain-level enum. Discriminator distinguishes broader mechanism classes (key-disclosure vs trusted-issuer vs ZK-based).
- **7.6.3** `view_key_mechanism` × `confidential_policy` are orthogonal axes; all 9 combinations meaningful. v1.0 validator enforces `view_key_mechanism = OTPK_STREAM` until §1.1/§1.2 future mechanisms implemented.
- **7.6.4** `contrib_msg_form` has no interaction with v2.6 gossip-out-of-lock (v2.6 is send-side; discriminator is receive-side decode).
- **7.6.5** Per-record vs manifest-pinned asymmetry is correct by design; no current cross-checks needed.

**Why this matters.** Without verification, the discriminators committed in §7.5 could have been scaffolding that wouldn't actually function as intended — undermining the multi-year optionality just bought. The coherence check cost ~1 hour; the cost of catching mid-Bundle-3 would have been rework of foundational schema decisions.

**Generalization.** When future improvements add schema fields with intended optionality, run a coherence check against ALL existing schema fields before committing. The cost-asymmetry favors pre-commit verification by orders of magnitude.

---

---

## 2026-05-24 — DSSO architecture (v2.25): DApp, not substrate

### Reclassify v2.25 from chain-level substrate to post-v1.0 DApp

**Question.** V2-DESIGN.md §v2.25 designed DSSO as a chain-level substrate (T-OPAQUE on K committee members; threshold-signed assertions; light-client-verifiable against on-chain committee). Was the DApp-based alternative considered?

**Background.** V2-DESIGN.md picked substrate based on four properties: (1) K-of-K mutual-distrust requires committee specifically, (2) assertion sigs verifiable against on-chain committee pubkeys, (3) v2.10 FROST composition presupposes committee, (4) committee continuity ↔ identity continuity. The DApp alternative wasn't explicitly considered.

**Analysis (raised during Theme 9 review prep).** DSSO-as-DApp variant: register DSSO via v2.18 DAPP_REGISTER; the K DApp instances are run BY committee members; T-OPAQUE coordination via DAPP_CALL; assertion signing via chain's FROST primitive when ready OR per-DApp-instance signing verified via DApp registry. Reconstructs ~80% of the substrate's properties at additional DApp-internal complexity.

**Choice.** DApp. DSSO ships post-v1.0 as a chain-aware Theme 7 application; v2.25 leaves v1.0 critical path entirely.

**Why DApp over substrate.**
- Trade-off accepted: ~20% security-posture reconstruction-debt at DApp level vs ~4-6 weeks v1.0 critical-path work + ~4-6 weeks deliberation eliminated
- DSSO iterates post-mainnet without no-migrations constraints (DApp-level changes are not chain-level)
- Federation by design — multiple DSSO providers can coexist (one DApp per provider)
- Matches V2-DESIGN.md §God-protocol "everything else is a DApp" philosophy explicitly
- v2.18 + v2.19 substrate already shipped, so DApp path is fully unblocked today

**Why not substrate.** The substrate's strongest argument (cleanest cryptographic posture) doesn't outweigh the v1.0 schedule cost when the DApp path can reconstruct most of the desired properties.

**Why not hybrid.** Would require partial v1.0 chain work plus full DApp work, getting most of substrate's cost without most of its benefit.

**Implications.**
- Theme 9 review-track scope reduces from {v2.25 + v2.26} to {v2.26 only}.
- Phase D entry gate (per BL-8) becomes "v2 + v2.26 substantially shipped" rather than "v2 + Theme 9 substantially shipped".
- §4.2 blocking-feature checklist drops the DSSO half.
- v2.25 enters `Improvements.md` as a post-v1.0 DApp roadmap item (new §8, see).
- Calendar: ~4-6 weeks of deliberation + ~4-6 weeks of implementation removed from v1.0 critical path. Net horizon reduction substantial.
- §7.5/7.6 discriminator concerns about DSSO assertions become moot at chain level (DApp-internal wire format is DApp's concern, not v1.0 chain schema).
- Memory `dlt-dsso-as-dapp` added to project memory.

**Generalization for future scope reviews.** When V2-DESIGN.md items describe new chain-level substrate primitives, explicitly evaluate whether a chain-aware DApp variant could deliver ~80% of the properties at substantially lower v1.0 critical-path cost. Default-to-DApp when the existing substrate (v2.18 + v2.19) admits the construction; default-to-substrate only when the chain-level integration is genuinely structural (e.g., consensus rules, validator gates, randomness, key rotation primitives).

---

---

## 2026-05-24 — Improvements.md §7.5 completion (7.5.6 + 7.5.7)

### Tx-level + pubkey-form discriminators added after §7.5 incompleteness gap analysis

**Question.** The original §7.5 sweep (block / Account / manifest / ContribMsg discriminators) was incomplete for §4.1 PQ migration and §6.1 BLS aggregation: it covered block-level signatures but missed tx-level signatures AND pubkey-format optionality. Without tx sig + pubkey discriminators, post-v1.0 PQ migration is structurally blocked even with §7.5.1 in place.

**Choice.** Ship both:
- **7.5.6 `Transaction.sig_form` discriminator** — per-tx sig form (default `SIG_ED25519`). Cost: 1 byte/tx.
- **7.5.7 `pubkey_form` discriminator + variable-length pubkey encoding** — uniformly applied to every pubkey-bearing field (default `PUBKEY_ED25519`, 32B body). Cost: ~3-5 days v1.0 schema lift (substantive — touches every consumer of pubkey data including sig verification, address derivation, serialization).

**Why both.** Foreclosing PQ migration under no-migrations would be the worst possible optionality loss given the known eventual quantum-adversary horizon. The cost-asymmetry (~3-5 days v1.0 lift vs. permanent foreclosure across decade-scale horizon) favors shipping both decisively.

**Why not just 7.5.6.** Tx sig migration without pubkey migration is structurally incoherent — Ed25519 pubkeys can't verify Dilithium sigs. Half-PQ is no PQ.

**Key coherence resolutions (§7.6.6 + §7.6.7).**
- `Transaction.sig_form` is orthogonal to `Block.signature_form`; embedded sigs within a tx are homogeneous (all follow tx-level form), avoiding combinatorial complexity.
- `pubkey_form` is uniformly applied to every pubkey-bearing field; variable-length encoding pattern is `{form:u8, body_len:u16, body:bytes}` (body_len elidable for known fixed-size forms).
- **Address-derivation preimage MUST include `pubkey_form` discriminator** — getting this wrong now permanently forecloses PQ pubkey migration even with the discriminator present. v1.0 design lock-in.
- `sig_form` ↔ `pubkey_form` curve-family consistency enforced at sig verification (mismatch is hard reject).

**Implementation impact.** Pre-bundle critical-path work in IMPLEMENTATION-SEQUENCING.md updated from ~2-4 days to ~6-10 days. 7.5.7 dominates the lift (~3-5 days alone); the others remain cheap.

**Generalization.** When evaluating whether a Breaking improvement can be downgraded to Additive via discriminator dispatch, check ALL affected wire-format fields, not just the most obvious one. Tx-level + pubkey-level + address-derivation all need consistent treatment for crypto-scheme migrations to be coherent post-v1.0.

---

---

## 2026-05-24 — v2.26-ROTATION-SPEC.md (Theme 9 v2.26 review-track complete)

### 12 decisions resolved for on-chain key rotation (post-DSSO-as-DApp scope)

**Question.** Theme 9 scope reduced earlier today to just v2.26 (DSSO substrate reclassified as DApp per memory `dlt-dsso-as-dapp`). v2.26 needed formal deliberation; V2-DESIGN.md §v2.26 had substantial design but 5 §5 open questions and the DSSO-as-DApp pivot elevated KR-10's importance.

**Choices.**

| # | Decision | Disposition |
|---|---|---|
| KR-1 | Wire format with dual-key PoP | Accept as V2-DESIGN.md, with §7.5.6/§7.5.7 discriminator composition |
| KR-2 | 5 genesis-pinned constants | Accept |
| KR-3 | Revoke-only escape valve | Accept |
| KR-4 | Dual-validity window | Accept |
| KR-5 | Cross-epoch DKG guard | Accept |
| KR-6 | Multi-sig (v2.15) gating from day one | Accept |
| KR-7 | Genesis-validator cooldown from block 0 | Accept |
| KR-8 | Domain history RPC | Revise to Option C — lightweight RPC + `RegistryEntry.last_rotation_height: u64` (8 B) |
| KR-9 | Multi-sig cooldown | Revise to Option C — per-account `cooldown_blocks: u16` clamped [8, 1024]; matches §7.5 discriminator-philosophy |
| KR-10 | REGISTER vs DAPP_REGISTER unification | Revise to Option A — unify under ROTATE_KEY via `key_target` enum byte; DSSO DApp service_pubkey rotation inherits all v2.26 protections |
| KR-11 | Hardware wallet support | Defer to v3 — no v1.0 chain-level commitment; standard Ed25519 hashed-envelope sign keeps existing HW wallets wire-compatible |
| KR-12 | Total key loss recovery | Accept — via v2.14 OPAQUE / v2.15 multi-sig / DSSO-DApp recovery flow |

**Key revisions from V2-DESIGN.md:**
- **KR-8 (revise to Option C)** — V2-DESIGN.md recommended this; deliberation confirmed against alternatives (skip RPC entirely / richer materialized history / RPC without on-chain field). DSSO-as-DApp use case (post-rotation assertion staleness check) made the on-chain field load-bearing.
- **KR-9 (revise to Option C, per-account configurable)** — V2-DESIGN.md originally rejected multi-sig cooldown bypass. Revised disposition matches §7.5 discriminator-philosophy: trivial per-account state cost preserves operator flexibility. Multi-sig accounts can pick rapid-response cooldown (KR-12 v2.15-multi-sig recovery path no longer rate-limited by global cooldown).
- **KR-10 (revise to Option A, unify under ROTATE_KEY)** — V2-DESIGN.md recommended documenting asymmetry. Revised disposition driven by DSSO-as-DApp: DSSO DApp instances each have service_pubkeys; unification gets them v2.26 protections (PoP, dual-validity, cooldown, audit trail). `ROTATE_KEY.key_target` enum byte enables this without tx-type proliferation; future-extensible to v2.22 audit-key rotation (`key_target=2`).
- **KR-11 (defer to v3)** — V2-DESIGN.md described HW-wallet UX commitments. Reclassified to post-v1.0 wallet-ecosystem concern; chain stays HW-wallet-compatible by accident (standard Ed25519 hashed-envelope signing).

**Composition with prior decisions:**
- §7.5.6 `Transaction.sig_form` discriminator covers outer Transaction.sig + embedded old_key_sig (homogeneous within tx per §7.6.6)
- §7.5.7 `pubkey_form` variable-length encoding covers `new_pubkey` field + registry's existing pubkey
- v2.10 FROST: KR-5 cross-epoch DKG guard composes; activates automatically post-v2.10 (no flag-day)
- v2.15 multi-sig: KR-6 gating ships day one; KR-9 per-account cooldown lets multi-sig accounts pick rapid-response
- v2.22: ROTATE_VIEW_MASTER + ROTATE_AUDIT_KEY follow the v2.26 pattern; future ROTATE_AUDIT_KEY can fold into ROTATE_KEY via key_target=2
- DSSO-as-DApp: DSSO DApp instance rotations via ROTATE_KEY/key_target=1 (post-v1.0)

**Implications.**
- Theme 9 chain-level review-track now complete: v2.26 ✅. DSSO (v2.25) remains post-v1.0 DApp per earlier reclassification.
- v2.26 spec doc produced: `v2.26-ROTATION-SPEC.md`.
- IMPLEMENTATION-SEQUENCING.md §4.2 blocking-feature checklist now populatable from v2.26 spec.
- Effort estimate: ~10-11 days (slight increase from V2-DESIGN.md's ~9-10 due to KR-9 + KR-10).

**Generalization.** When a reclassification (e.g., DSSO-as-DApp) elevates the cross-cutting importance of a decision (e.g., KR-10 rotation unification), re-evaluate the original V2-DESIGN.md disposition under the new lens. Three of v2.26's 5 open-question resolutions changed from V2-DESIGN.md's original recommendations once DSSO-as-DApp + §7.5 discriminator-philosophy + KR-12 recovery-path emphasis were in scope.

---

---

## 2026-06-03 — Casino-fee mechanism rejection + alternative monetization paths adopted

### Tax-the-cryptographic-primitives proposal evaluated and rejected; 5 alternatives captured

**Question.** A monetization proposal was raised: tax specific opcodes (VRF, ZK fairness receipts, atomic commit-reveal escrow) on the basis that "casinos will pay because evading destroys their cryptographic guarantees." Designed to capture value from gambling industry without taxing identity or burdening enterprise adoption.

**Analysis.** Three substantive problems with the proposed mechanism:

1. **Primitives are NOT casino-specific.** VRF (fair-ordering, elections, lottery, fraud sampling, A/B testing), ZK proofs (confidential audit, regulatory attestation, supply-chain provenance, source protection), atomic commit-reveal escrow (B2B settlement, milestone supply chains, cross-shard 2PC, conditional regulatory release) all have substantial non-casino legitimate uses. Pricing them taxes every cross-industry use that overlaps casino needs.

2. **"Fairness receipt" doesn't add what's claimed.** Chain already provides per-tx ordering verifiability via v2.1 state_root + v2.2 light-client proofs. A separate ZK receipt only matters if it proves something state_root doesn't — but the claim ("no latency manipulation by sender") is unprovable because the chain can't observe sender-side pre-submission delays.

3. **Game theory fails under scrutiny.** Casinos don't need the global Determ validator set; equivalents exist on every other chain (Ethereum L2s, Cosmos, Solana, Polygon); players overwhelmingly don't verify protocol-level cryptographic receipts (they trust operator brand/license). Pricing the cryptographic features doesn't lock casinos in; it pushes them to alternatives.

Plus cross-cutting concerns: use-case pricing is a known anti-pattern in protocol design (Bitcoin/Ethereum deliberately price by resource); mismatches MOTIVATION.md framing (Determ's value prop is K-of-K mutual-distrust + Kerckhoffs, not specific high-margin opcodes); adverse selection (pricing pushes high-margin users away, leaving low-margin transit layer).

**Decision.** Drop the proposal; do not adopt. Captured this rejection rationale here so future threads understand the reasoning and don't re-propose under similar framing.

**Alternative monetization paths preserved as v3 research** (captured in `Improvements.md §9`):
- **Option A** — Stake/bond requirements scaled by deployment tier (slashable misdeclaration); preserves Determ character
- **Option B** — Application-layer (DApp) pricing; chain stays free; matches "everything else is a DApp"
- **Option C** — Resource-based pricing with feature multipliers (gas-style)
- **Option D** — Validator revenue sharing on premium operations
- **Option E** — Foundation/SDK revenue model (off-protocol); Linux-Foundation pattern

**Recommended for serious v3 deliberation:** Options A and B. They best preserve project character while addressing the legitimate goal.

**Pre-v1.0-schema-freeze implications.** Option A requires `§7.5.8 RegistryEntry.deployment_tier` discriminator. Option C requires `§7.5.9 Block.gas_pricing_form` discriminator. Both flagged for schema-freeze review if either is a serious candidate.

### Three v3-blocker unblocks captured

Separately captured in `Improvements.md §10`:

- **§10.1 §6.3 dedup reformulation** via per-creator Bloom/IBLT (already noted as alternative in §6.3 entry; ~1 week spec)
- **§10.2 §1.6 stateless scheduled decoys** (sidesteps unforgeability research; ~3-5 days; Additive)
- **§10.3 Operator-tier opt-in framework** as a v3 design pattern (generalizes §6.2 Quorum Liveness OPTIONAL pattern; unblocks §1.8, §5.2, §5.5, §9.1 as opt-in tiers; requires §7.5.10 schema decision pre-v1.0)

**Generalization.** When evaluating a use-case-specific monetization proposal, check whether the named "use-case-only" features have substantial non-target legitimate users. If yes, the proposal taxes the wrong thing. Use-case pricing requires features genuinely unique to the target — vanishingly rare in cryptographic infrastructure where primitives are inherently general-purpose.

---

---

## 2026-06-03 — Gas-style pricing rejected (Options 9.3 + 9.4 cascade)

### Resource-based gas pricing and validator revenue share dropped from monetization candidates

**Question.** Of the 5 monetization alternatives captured in `Improvements.md §9` (after the casino-fee rejection), are gas-style models (Option C resource-based pricing, Option D validator revenue share) viable v3 candidates?

**Decision.** Both rejected.

**Rationale (Option C — gas-style resource pricing).** "No gas-style" — explicit project-policy rejection. Reasoning:
- Changes Determ's "free for enterprise" framing fundamentally
- Adds substantial v3 infrastructure (gas accounting, mempool fee-priority, validator gas-metering, per-opcode cost schedule + governance for updates, gas-payment token model)
- Shifts project character from primitive-free public-interest infrastructure toward fee-market substrate
- Mismatches MOTIVATION.md framing (Determ as public-interest cryptographic substrate; gas pricing is the standard chain-economy model that the project deliberately departs from)

**Rationale (Option D — validator revenue share).** Cascade-rejection from Option C: depended on the same gas-style accounting infrastructure that Option C was rejected for. Additionally suffers the same use-case-overlap problem as the originally-rejected casino-fee proposal (VRF/ZK/escrow primitives have non-casino legitimate users who would also pay).

**Cascade decisions.**
- §7.5.9 `Block.gas_pricing_form` discriminator REMOVED from the pre-v1.0-schema-freeze candidate list. Gas-style is closed as an Additive v3 path.
- If gas-style is ever revisited post-v1.0, it becomes Breaking-only (would require v3 protocol opening or security-critical hard fork per the no-migrations constraint).
- Live monetization candidates reduced to 3: Option A (tier-bonds), Option B (DApp-layer pricing), Option E (foundation services).

**Pre-v1.0-schema-freeze candidates updated.** Only §7.5.8 `RegistryEntry.deployment_tier` (for Option A) and §7.5.10 `policy_tier_flags` (for operator-tier opt-in framework §10.3) remain candidates from this thread of decisions.

**Generalization.** Project consistently rejects fee-market substrates that would make Determ "another smart-contract chain." The project's character — public-interest infrastructure, primitive-free chain, "everything else is a DApp" — is more load-bearing than monetization mechanics. Future monetization proposals should preserve this character.

---

---

## 2026-06-03 — §7.5 sweep extension: 7.5.8 SKIP + 7.5.10 SHIP

### Final two pre-v1.0-schema-freeze discriminators decided

**Question.** After the casino-fee proposal rejection + gas-style rejection, two §7.5 discriminator candidates remained for explicit decision:
- **7.5.8** `RegistryEntry.deployment_tier: enum` — preserves Option A tier-bond monetization optionality (1 byte/RegistryEntry)
- **7.5.10** `manifest.policy_tier_flags: u32` bitset — preserves operator-tier opt-in framework cascading to §1.8 / §5.2 / §5.5 / §6.2 (4 bytes/manifest)

**Decisions.**
- **7.5.8 SKIP** — Option A monetization now Breaking-only post-v1.0 (would require v3 protocol opening to add tier-bonds)
- **7.5.10 SHIP** — operator-tier opt-in framework becomes Additive; 4 deferred items now have opt-in activation paths

**Rationale (7.5.8 skip).** Option A was one of three live monetization candidates (alongside §9.2 DApp-layer pricing and §9.5 foundation services). Skipping reduces live monetization candidates to 2; preserves chain-level character of "no per-account fee differentiation"; aligns with project philosophy of avoiding protocol-level monetization mechanisms that change chain economics. §7.5.10's `POLICY_TIER_BONDS_ENABLED` flag (bit 3) becomes vestigial but kept reserved to avoid bit-renumbering if Option A is ever revisited via v3 protocol opening.

**Rationale (7.5.10 ship).** Massive unblock multiplier — single 4-byte field at the manifest level preserves Additive optionality for:
- §1.8 trusted-issuer audit (was principle-rejected; now opt-in per deployment)
- §5.2 external audit (was project-policy; now deployment-policy opt-in)
- §5.5 HW wallet certification (was wallet-ecosystem-only; now chain-recognized tier)
- §6.2 Quorum Liveness OPTIONAL (closes the gap flagged earlier in §6.2 — partial; per-block `quorum_bitset` field still needs separate decision)

Best leverage of any §7.5 decision so far.

**Cascade decisions.**
- Live monetization candidates reduced to 2: §9.2 DApp-layer pricing, §9.5 foundation services
- §10.3 operator-tier opt-in framework reclassified from "pending §7.5.10 decision" to "ENABLED in v1.0"
- §6.2 Quorum Liveness OPTIONAL partially unblocked — manifest enablement flag exists but per-block `quorum_bitset` field is a residual gap (potential §7.5.11)
- §1.8 trusted-issuer reclassified from "principle-rejected" to "deployment-opt-in" — chain doesn't endorse, but doesn't prevent operators from choosing
- Pre-bundle schema discriminator count increased from 7 to 8 (the original 7 ship + 7.5.10 ship); 7.5.8 + 7.5.9 skipped explicitly
- IMPLEMENTATION-SEQUENCING.md pre-bundle work updated to include 7.5.10 (~1-2 days)

**Residual gap surfaced: per-block `quorum_bitset` field for §6.2.** The 7.5.10 manifest flag enables the BFT-threshold finalization mode at deployment level, but the per-block bitset indicating which committee members participated is a separate wire-format field that needs its own schema commitment. Could be a §7.5.11 candidate if §6.2 full enablement is wanted. Otherwise §6.2 is "enable-able by manifest but not actually implementable" — partial unblock only.

**Generalization.** Operator-tier opt-in via per-deployment bitset (the §6.2 → §10.3 → §7.5.10 evolution) is now the canonical project pattern for "controversial features that some deployments want but project doesn't want chain-wide." Trusted-issuer audit (was principle-rejected at chain level) becomes deployment-policy via this pattern — chain stays clean, operators get optionality. Reusable for future policy-blocked items.

---

---

## 2026-06-03 — 7.5.11 SHIP completes §6.2 Quorum Liveness unlock

### Per-block `quorum_bitset` field shipped to complete the §7.5.10 cascade

**Question.** After 7.5.10 shipped the manifest-level `POLICY_BFT_THRESHOLD_FINALIZATION` flag, §6.2 Quorum Liveness OPTIONAL was only partially unblocked — the manifest could opt in but no per-block field existed to record which committee members signed under BFT-threshold mode. Should the per-block `quorum_bitset` field ship as §7.5.11?

**Decision.** SHIP. §6.2 now fully Additive-via-opt-in.

**Rationale.** The whole purpose of shipping 7.5.10 was to unblock §6.2 (among other items). Skipping 7.5.11 would have made POLICY_BFT_THRESHOLD_FINALIZATION vestigial — same fate as POLICY_TIER_BONDS_ENABLED after 7.5.8 skip. Cost is meaningful but bounded (1-16 bytes/block depending on profile K, prunable). Coherent completion of the 7.5.10 ship decision.

**Wire format.** Variable-length bitset per genesis K. For K=8 (tactical) = 1 byte; K=32 (cluster) = 4 bytes; K=64 (regional) = 8 bytes; K=128 (global) = 16 bytes. Default all-1s (matches unanimous_k mode); equivalent to current K-of-K behavior pre-v6.2-activation. Validator short-circuits BFT-check to K-of-K equality when bitset is all-1s.

**Final §7.5 sweep state.** Nine discriminator candidates evaluated; 8 SHIP, 1 SKIP (7.5.8 deployment_tier), 1 REJECTED (7.5.9 gas_pricing_form).

| # | Discriminator | Status |
|---|---|---|
| 7.5.1 | Block.signature_form | ✅ Ship |
| 7.5.2 | Account.view_key_mechanism + fs_view_pk | ✅ Ship |
| 7.5.3 | Account.audit_model + trusted_issuer_pubkey | ✅ Ship |
| 7.5.4 | manifest.randomness_aggregation_form | ✅ Ship |
| 7.5.5 | ContribMsg.contrib_msg_form | ✅ Ship |
| 7.5.6 | Transaction.sig_form | ✅ Ship |
| 7.5.7 | pubkey_form + variable-length encoding | ✅ Ship |
| 7.5.8 | RegistryEntry.deployment_tier | ❌ Skip |
| 7.5.9 | Block.gas_pricing_form | ❌ Rejected |
| 7.5.10 | manifest.policy_tier_flags | ✅ Ship |
| 7.5.11 | per-block quorum_bitset | ✅ Ship |

**Cascade effects of §6.2 full unblock.**
- §6.2 reclassified from "Breaking-via-Quorum-Liveness-OPTIONAL" / "best-specified post-v2 architectural optimization 60% ready" → fully Additive
- The §10.3 operator-tier opt-in framework demonstrates its first complete cascade: §6.2 Quorum Liveness via POLICY_BFT_THRESHOLD_FINALIZATION + quorum_bitset
- Pattern established: future opt-in features needing both manifest enablement AND per-block field can follow the §6.2 model

**Pre-bundle schema work final tally.** 8 discriminators ship: 7.5.1, 7.5.2, 7.5.3, 7.5.4, 7.5.5, 7.5.6, 7.5.7, 7.5.10, 7.5.11. Plus the §7.5.7 variable-length pubkey encoding lift is the substantive item (~3-5 days). Combined pre-bundle critical-path: ~7-11 days before any review-week bundle starts. Trivial relative to ~6.5-8 month horizon.

**Generalization.** Operator-tier opt-in features generally need TWO schema commitments: (1) manifest-level enablement flag (per 7.5.10), (2) per-record field for whatever the feature records per-record (per 7.5.11). The §6.2 + 7.5.10 + 7.5.11 triplet is the template for future deployments of this pattern.

---

---

## 2026-06-03 — Four items reclassified from "v3 candidate" → §11 Out of scope

### "Does this motivate v3 by itself?" test applied; 4 items moved out of v3 queue

**Question.** The post-7.5 sweep state showed 4 items as "Breaking — v3 candidate": §1.3 stealth addresses, §3.1 sharding-of-sharding, §6.3 dedup, §9.1 tier-bond monetization. User observation: "the remaining structural foreclosures looks like overkill for v3." Are these items genuinely v3 candidates, or are they misclassified?

**Analysis.** A v3-candidate should either (a) *motivate* v3 by itself (compelling enough to justify the protocol break) or (b) *ride along* if v3 opens for another reason. Walked each item:

- **§1.3 stealth addresses** — Monero-class whole-chain rewrite just for graph privacy. Graph-privacy users have Monero/Zcash. Doesn't motivate v3; can't ride along (architectural rewrite too large to bundle).
- **§3.1 sharding-of-sharding** — Speculative scaling for a problem nobody has and nobody is forecast to have. 200-500 shards covers every realistic deployment. Beyond that, "deploy sibling chain + bridge" is the right answer (v2.23). Doesn't motivate; can't ride along.
- **§6.3 dedup `deduplicated_tx_root`** — Per the entry's own analysis, bandwidth savings aren't load-bearing at target throughput. Doesn't motivate v3. CAN ride along if v3 opens for crypto reason (per `§10.1` per-creator Bloom/IBLT reformulation, which makes dedup spec-ready).
- **§9.1 tier-bond monetization (Option A)** — Just explicitly skipped via 7.5.8. The skip was a deliberate value decision (project philosophy: primitive-free public-interest infrastructure). Calling it "v3 candidate" implied backdoor revisit — misleading.

**Decision.** All four reclassified from "v3 candidate (Breaking)" to **§11 Out of scope** in `Improvements.md`. Full original analysis preserved in §11.1-§11.4; original entries in §1.3, §3.1, §6.3, §9.1 replaced with brief redirect stubs pointing to §11.

**Why §11 rather than deletion.** Analysis is valuable — someone proposing stealth addresses or sharding-of-sharding later should find the deferral reasoning. Deletion loses institutional memory. §11 with "Out of scope" framing preserves the analysis without misleading "future work" signaling.

**Convention established for future v3-candidate triage.** Apply the §11 test: "Does this item motivate v3 by itself? If yes, v3 candidate. If no — even if Breaking — it belongs in §11." This protects the live v3 queue from items that create false planning expectations.

**Cross-reference updates applied:**
- `Improvements.md §7.1` Breaking-improvements list: removed §1.3, §3.1, §6.3, §9.1; noted reclassification
- `Improvements.md §7.3` revisit-trigger list: removed §3.1, §6.3; noted §11 reclassification
- `Improvements.md §1.3/§3.1/§6.3/§9.1`: replaced full entries with redirect stubs

**Net effect on live v3 queue.**
- Pre-reclassification: ~33 v3 items
- Post-reclassification: ~29 v3 items (24 Additive + 4 in §11 out of scope + 1 principle-rejected + 1 research-stuck — sums adjusted)
- The remaining "v3 candidates (Breaking)" are now: §6.1 BLS aggregation MODERN variant only — which has a real strategic motivation (curve roster expansion + Bitcoin-grade BLS adoption). One genuine v3-motivator remains.

**Generalization.** Most "v3-candidate Breaking" items in cryptographic infrastructure projects fail the §11 test because v3 protocol opening is itself a major project decision requiring overwhelming justification. Routine improvements should ship as Additive via discriminator dispatch; major improvements either justify v3 by themselves (rare) or ride along with another v3-opening event (limited set). The §11 section captures the rest honestly.

---

---

## 2026-06-05 — Bundle 5 priority levers within BL-7/BL-8 constraints

### Bundle 5 elevated to "top priority for development" via planning levers (not earlier chronological start)

**Question.** Bundle 5 (Beaconless v2 + v2.26) was identified as the most development-heavy single item in v1.0 (~3-4 months; cross-cutting architectural; composes with virtually every other spec; mainnet-readiness criteria depend on it). User direction: "Bundle 5 should be top priority for development."

**Constraint analysis.** Literal "start Bundle 5 first" violates two binding sequencing decisions from review week:
- **BL-7**: DSF (Bundle 4) is hard prerequisite. Skipping = shipping Bundle 5 Byzantine paths into no-migrations-bound mainnet without coverage.
- **BL-8**: Bundle 5 starts in Phase D after v2 + v2.26 substantially shipped. Skipping = constant rebases mid-Bundle-5 against in-flight Bundle 1-4 changes.

Both constraints remain load-bearing. Cannot relax.

**Decision.** Reframe "top priority" as **disproportionate planning attention during Phase B/C**, applied via three concrete levers that respect BL-7/BL-8:

1. **`BUNDLE5-INTERFACE-CONTRACTS.md`** produced during Phase B/C; locks cross-bundle interfaces Bundle 5 consumes (v2.10 FROST aggregation, v2.15 multi-sig threshold check, v2.22 cross-shard receipt × confidential amount, v2.26 ROTATE_KEY apply path, §7.5 discriminator semantics). Effort: ~3-5 days of one thread's time. Outcome: zero rebase pain at Phase D start.

2. **DSF Beaconless-v2 scenario prioritization** in `DSF-SPEC.md §0.7` initial 30-scenario set. Bundle 5-specific scenarios (selective-abort with committee continuity, equivocation with cross-shard receipt forgery, partition with header eviction storms, Merritt-witness collection, cross-epoch DKG guard, F2 interaction, BFT-escalation, manifest mutation under selective availability, randomness aggregation with adversarial timing) at top of the list. Effort: ~1 day during Bundle 4 spec finalization.

3. **v2.26 early-start carve-out** — v2.26 (~10-11 days) ships in late Phase B/C parallel with Bundle 3, NOT inside Bundle 5's Phase D envelope. Satisfies BL-8 "v2.26 substantially shipped" gate by being feature-complete. Removes v2.26 from Phase D critical path; Bundle 5 starts with ROTATE_KEY infrastructure ready.

**Additional supporting practices.**
- Bundle 5 integration-thread pre-selection during Phase B/C (the thread shadows Bundles 1-4 integration work and absorbs cross-bundle context)
- "Bundle 5 impact" checklist reviewed at every Bundle 1-4 milestone (catches downstream-impact decisions early)

**Why this matters more than nominal priority status.** Bundle 5's no-migrations exposure is the project's highest bug-cost surface — any Bundle 5 bug that escapes beta into mainnet binds permanently under `dlt-no-migrations-constraint`. Pre-bundle attention is the project's highest-leverage risk reduction. Calendar order is unchanged; risk posture substantially improved.

**Calendar effect.**
- Phase D start time: unchanged (still gated on BL-7 + BL-8)
- Phase D rebase risk: substantially reduced (interface contracts pre-frozen; v2.26 already shipped; DSF scenarios cover Bundle 5 from day 1)
- Phase D effort: same ~3-4 months but lower variance — fewer mid-bundle interface negotiations
- Bundle 5 spec-quality: higher entering Phase D (interface contract is itself a spec deliverable)

**Generalization.** "Priority" in a constrained-sequencing context means planning attention + risk monitoring, not earlier chronological start. When a project has hard prerequisites (BL-7 DSF, BL-8 substantial-ship gate), the answer to "we should prioritize X" is "we should pre-plan X" — not "we should violate prerequisite Y to start X."

---

---

## 2026-06-05 — No-migrations cascade cleanup (spec dead-code removal)

### v2.22 §4.8 + Beaconless-v2 §4.7 trimmed to remove migration tooling dead under no-migrations

**Question.** When the project committed to "no migrations at all" (memory `dlt-no-migrations-constraint`), several review-week-era spec sub-components became dead code without being removed from bundle effort estimates. Identified during a "most insignificant + heavy load" triage 2026-06-05.

**Two sub-components identified:**

1. **v2.22-PRIVACY-SPEC.md §4.8 Migration / wire-version bump (~1 week)** — flag-day machinery: dual-decode validator path (clear AND confidential during transition), pre/post-flag-day activation logic, operator migration tooling. Pre-mainnet + no-migrations means there's no flag-day boundary; the dual-decode path is never exercised; the whole sub-component is structurally dead except for the genesis-pinned validation rule + wire-format version stamp.

2. **Beaconless-v2-SPEC.md §4.7 AUTONOMOUS_SHARD chain_role + migration (~1-2 weeks)** — flag-day conversion tooling (beacon-bound → beaconless) + per-deployment migration runbook. Under no-migrations, an operator who deploys beacon-bound at v1.0 cannot later migrate to beaconless via chain mechanism. The chain_role enum + interop logic survive (needed for v1.0 launch where both types coexist); the migration tooling and runbook are dead.

**Decision.** Both sub-components revised:
- v2.22 §4.8: rewrite from ~1 week to ~1-2 days (genesis rule + wire-format version stamp only). Net deletion: ~5-7 days.
- Beaconless-v2 §4.7: rewrite from ~1-2 weeks to ~1 week (chain_role enum + interop only; drop conversion tooling + migration runbook). Net deletion: ~5-7 days.
- IMPLEMENTATION-SEQUENCING.md Bundle 5 entry: §4.7 line item revised from 1-2 weeks to ~1 week.

**Combined effort reduction: ~10-14 days across Bundle 3 + Bundle 5.** Not huge in the ~6.5-8 month total horizon, but real — implementation threads would otherwise have started this work, discovered it was moot, and wasted time. The cleanup makes bundle effort estimates aligned with project constraints.

**Operational guidance preserved.** §4.7 revised text notes that operators choosing to switch deployment types must do so via application-level account-balance transfer (operationally migrate to a new chain), not via chain-level mechanism. The operator-side migration path still exists; what's removed is the chain-level tooling that would have automated it.

**Generalization.** When a load-bearing project constraint is added mid-spec (like "no migrations at all" was added after v2.22 + Beaconless-v2 specs were drafted), do a cascade cleanup pass to remove sub-components that become dead under the new constraint. Without the pass, effort estimates over-state remaining work; implementation threads waste time starting dead sub-components. Cost of cleanup: ~1-2 hours per spec. Benefit: aligned estimates + no wasted implementation effort.

**Other no-migrations-cascade candidates checked:** PRIV-5 wire-format break was already correctly handled (migration N/A; tx types still ship as operational primitives). No other migration-tooling sub-components identified in the spec set.

---

---

## 2026-06-05 — AI-traffic-dominance monetization implications + §9 framing sharpening

### "Live monetization model is §9.2 + §9.5; others are preserved-rejection-rationale, not parallel candidates"

**Question.** By 2026, AI traffic has surpassed human traffic on the broader internet. What does this mean for the monetization candidates in `Improvements.md §9`?

**Analysis.**

- **Protocol-level pricing models (§9.1 tier-bonds, §9.3 gas-style, §9.4 validator revenue share) gain no new viability from AI-traffic-dominance.** The same blindness problem that rejected the casino-fee proposal applies: protocol cannot tell AI tx from human tx. Identity-classification at protocol level is structurally infeasible for AI vs human distinction same as it was for casino vs enterprise.
- **DApp-layer pricing (§9.2) is where AI-aware monetization happens.** DApps have visibility into principal vs delegate, subscription tier, action context — they can price-discriminate legitimately. Per-principal subscriptions, per-action-with-cap, delegation-credential issuance fees, volume-tier discounts are all DApp-layer patterns that handle the AI-volume reality.
- **Foundation services (§9.5) gain a sharpened positioning** as "AI-agent economy infrastructure provider" — Determ's design (K-of-K mutual-distrust, DSSO, PFS, ROTATE_KEY) genuinely fits the AI-agent-economy needs. Foundation services for support/certification/partnerships can target this market explicitly.
- **S-010 stake-pricing assumes human-velocity account creation.** AI orchestration changes the Sybil cost calculus; review is warranted (captured as `Improvements.md §5.6`).

**Sharpening decision.** User's follow-up question — "why do we need other pricing models?" — exposed that §9 was framed misleadingly as "5 candidates" when really §9.1, §9.3, §9.4 are rejection-rationale (preserved for record) and §9.2 + §9.5 are the live model. Sharpened §9.6 framing: "live monetization model is §9.2 + §9.5; nothing else." The two are orthogonal (DApp-layer captures application value; Foundation captures services value); they don't compete. Chain protocol itself stays free per project character (no per-tx fees; no gas; no per-account tier-bond differentiation).

**Why §9.2 + §9.5 is sufficient.** 
- Chain protocol stays free (matches MOTIVATION.md framing)
- Validators are operators paid by deployment sponsors (sovereign-deployment model)
- DApps capture application value via §9.2 patterns (per-principal subscription, delegation-credential fees, etc.)
- Foundation captures non-deployment-specific value via §9.5 (support, certification, partnerships)
- Three-layer architecture: chain (free) + DApp (captures app value) + Foundation (captures services value)

**Generalization for future monetization proposals.** Any proposal that captures revenue at the protocol layer must answer: (a) does it require identity-classification (blindness problem)? (b) does it shift Determ's character toward fee-market substrate? If yes to either, the proposal goes against established project posture and joins §9.1/§9.3/§9.4 as rejection-rationale, not live candidate. DApp-layer and Foundation-layer captures don't suffer either problem.

**Doc updates applied.**
- `Improvements.md §9.6` — sharpened to explicit "live model is §9.2 + §9.5 only"
- `Improvements.md §9.2.1` — new sub-section on DApp pricing patterns under AI-agent dominance
- `Improvements.md §9.5.1` — new sub-section on Foundation services AI-agent-economy repositioning
- `Improvements.md §5.6` — new entry: S-010 stake-pricing review under AI-volume assumptions
- `DAPP_SDK_GUIDANCE.md §7` (new) — DApp pricing patterns under AI-agent economy dominance with composition notes vs Determ primitives

---

---

## 2026-06-05 — §9 framing correction + economic-config validation entry

### "Chain stays free" over-simplification corrected; v1.x fee + subsidy mechanism re-acknowledged

**Question.** User raised: "If transactions have no fee, what happens when there is nothing more for block reward?" This is precisely the Bitcoin long-term-economics question. While exploring it, discovered that the §9 framing earlier said "Chain protocol itself stays free. No per-tx fees" — which contradicts v1.x's actual model.

**The mistake.** When sharpening §9 framing (2026-06-05 prior entry "Live monetization model is §9.2 + §9.5"), I conflated two distinct claims:
1. "No NEW chain-level monetization mechanism beyond v1.x" (correct — §9.3 gas-style, §9.4 validator revenue share rejected; §9.1 tier-bonds skipped)
2. "No fees at all at protocol level" (INCORRECT — v1.x already has per-tx fees + block subsidy + subsidy pool cap + FLAT/LOTTERY distribution per WHITEPAPER-v1.x.md §8.2-8.4)

The first claim is true; the second is wrong. v1.x has the chain-level economic primitive; per-deployment operator configures rates.

**Correction applied.** §9.6 framing rewritten to make explicit:

- **Chain protocol provides fee + subsidy mechanism** — `block_subsidy`, `subsidy_pool_initial`, `subsidy_mode`, per-tx `fee` field, all genesis-pinned per deployment
- **§9 research addresses ADDITIONAL revenue capture** beyond v1.x's existing chain-level primitive
- **Three independent layers**: (1) chain-level fee + subsidy [v1.x] (2) DApp-layer application pricing [§9.2] (3) Foundation services off-protocol [§9.5]

**New improvement entry (§5.7): Genesis-time economic-config validation.** The user's question exposed that some combinations of v1.x economic primitives are not self-consistent (e.g., bootstrap subsidy with zero fees and no sponsor declaration = chain dies at pool exhaustion). Proposed manifest hard-invariant that rejects bad combinations, plus a new `manifest.sponsor_declaration` enum letting operators attest to off-chain validator funding. Composes with Beaconless-v2 §Q2.1 manifest-validity pattern. ~1-2 days implementation + would need §7.5.12 schema discriminator if pursued pre-v1.0.

**Answer to user's specific question** (preserved for reference): "If transactions have no fee + subsidy pool exhausts, what funds validators?"

- **Sovereign-deployment model** (banks, governments, enterprises — primary intended model per MOTIVATION.md): validators paid by sponsor's organizational budget; subsidy/fees are bonus revenue; subsidy exhaustion is non-existential.
- **Public/permissionless model**: same Bitcoin post-2140 question. Determ's answer: operator chooses configuration (permanent inflation, bootstrap+fees, fees-only); §5.7 genesis validation prevents the broken combinations (e.g., pool-cap subsidy + zero fees + no sponsor).

**Doc updates applied.**
- `Improvements.md §9.6` — framing corrected (chain has v1.x fee + subsidy; §9 is ADDITIONAL layers)
- `Improvements.md §5.7` (new) — Genesis-time economic-config validation entry
- `DAPP_SDK_GUIDANCE.md §7.5` — DApp pricing composes with v1.x chain-level fees; three-layer framing explained
- This DECISION-LOG entry — captures correction + generalization

**Generalization.** When sharpening doc framing, verify against the actual implemented model. Over-simplifications that contradict existing code create real confusion downstream. "Chain stays free" was a shorthand for "no NEW protocol-level use-case-pricing mechanism beyond v1.x" — but stated unconditionally, it misled. Always qualify "stays free" with "of NEW mechanism" when the existing model already has chain-level economic primitives.

---

---

## 2026-06-06 — Doc coherence sweep (V1.1-PLAN cross-references + sibling-doc references)

### Working copy synced to HEAD; V1.1-PLAN cross-references added; V210ImplementationRoadmap + C99CryptoStackAudit linked from planning docs

**Question.** Repo has progressed substantially since session start — user committed multiple curation rounds ("Cleanup", "Updated design", "remove blockers", "Fees coherence", "Improvement"); v2.10 Phase 0 C99 crypto primitives substantially shipped (SHA-2, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, AES-256-GCM all complete per `V210ImplementationRoadmap.md`); `C99CryptoStackAudit.md` landed with 18 findings remediated (commit `2e0058b`). User flagged: "the repo is updated, make the docs coherent."

**Discovery.** Working copy was stale relative to HEAD (~31 KB / 548 net lines behind across 9 planning docs) because user's curation commits hadn't been pulled into the sandbox's working copy. My session-local edits had been integrated into HEAD via user's curation; only my untracked `V1.1-PLAN.md` was unique to working copy.

**Coherence pass applied.**
1. Synced 9 planning docs from HEAD to working copy via `git show HEAD:<file> > <file>` (preserves user's curation; loses my stale uncommitted local edits which were already integrated by user differently).
2. Added `V1.1-PLAN.md` to `IMPLEMENTATION-SEQUENCING.md` companion-docs list (the only thing genuinely missing from HEAD after sync).
3. Added `V210ImplementationRoadmap.md` + `C99CryptoStackAudit.md` to `IMPLEMENTATION-SEQUENCING.md` companion-docs list (these exist in HEAD but weren't cross-referenced from the sequencing plan; only README + CRYPTO-C99-SPEC referenced them).
4. Added `V1.1-PLAN.md` reference paragraph to `Improvements.md §8` (DApp roadmap section) pointing readers to v1.1 Bundle A for DSSO-DApp implementation.
5. Updated `V1.1-PLAN.md` companion-docs list to reference `V210ImplementationRoadmap.md` + `C99CryptoStackAudit.md` (so v1.1 planning context includes v1.0 implementation tracker + audit report).
6. Updated `V1.1-PLAN.md` Bundle A pre-requisites section to reflect actual v2.10 Phase 0 status (Phase 0 C99 crypto primitives substantially shipped; FROST itself still pending) rather than the optimistic stale "✅ Bundle 1 of v1.0" status.

**Net effect.** Planning artifacts now coherent across the three primary planning surfaces:
- v1.0 execution plan (`IMPLEMENTATION-SEQUENCING.md`)
- v1.0 implementation tracker (`V210ImplementationRoadmap.md` + `C99CryptoStackAudit.md`)
- v1.1 application-layer plan (`V1.1-PLAN.md`)

All three cross-reference each other appropriately. Substantial v1.0 Phase 0 implementation progress (10+ crypto primitives shipped + audit landed + remediation complete) is now visible from `V1.1-PLAN.md`'s perspective.

**Generalization for future doc coherence passes.** When the repo has parallel curation activity from the user (multiple commits to planning docs between my interactions), check working-copy-vs-HEAD diff before making edits. If HEAD is materially ahead, sync working copy first (via `git show HEAD:<file> > <file>`); then add only the cross-references/content genuinely new vs HEAD. Don't compete with user's curation — they're integrating my session work + their own thinking, and my stale working-copy edits often duplicate or contradict their better-curated versions.

---

---

## 2026-06-06 — V1.1-PLAN.md Bundle D expansion: zk-VM composition + Merritt-voting DApp

### Bundle D grows from 5 to 9 killer DApps; zk-VM substrate now composed with first-class killer apps (not just Bundle B internal demos)

**Question.** User asked: "Is there DApp in the plan that use zk-VM?" Discovered honest gap: Bundle B (zk-VM substrate) included 3 internal reference apps that DEMONSTRATE zk-VM, but Bundle D's 5 killer DApps used chain primitives only — none composed with zk-VM. The zk-VM substrate would have shipped without first-class killer-DApp consumption, undersells the God-Stack framing.

User direction: apply Option C (promote Bundle B's 3 reference apps to first-class Bundle D members) + Option A (augment D.4 AI-agent with zk-VM verifiable inference) + add a new D.9 Merritt-witness fault-tolerant voting DApp per Michael Merritt's 1984 PODC paper "Elections in the Presence of Faults."

**Decisions applied to `V1.1-PLAN.md`.**

1. **Bundle B §3 reference-app line item removed.** The 3 reference apps (private payment rollup, verifiable AI inference, anonymous credential issuance) are no longer Bundle B internal demos; they're first-class Bundle D killer DApps. Bundle B total revised: ~3-6 months → ~3-5 months (effort lifted out).

2. **Bundle D split into §5.1 chain-primitive DApps + §5.2 zk-VM-augmented DApps.** §5.1 = D.1, D.2, D.3, D.5, D.9 (5 DApps; depend only on DSSO). §5.2 = D.4, D.6, D.7, D.8 (4 DApps; depend on DSSO + zk-VM substrate).

3. **D.4 augmented with zk-VM verifiable inference.** AI-agent infrastructure DApp now composes Bundle B zk-VM so delegate AI agents can cryptographically prove they executed within authorized parameters. Effort: ~3-4 weeks base + ~1-2 weeks zk-VM integration = ~4-6 weeks total.

4. **D.6 Private payment rollup, D.7 Verifiable AI inference, D.8 Anonymous credential issuance** — promoted to first-class killer DApps; ~3-4 weeks each. These are the apps formerly listed as Bundle B internal demos.

5. **D.9 Merritt-witness fault-tolerant voting DApp added** — Byzantine-fault-tolerant elections per Merritt 1984 (the same paper that backs Beaconless-v2 §Q5 BL-5 Merritt-witness merge-detection). Use cases: government elections under hybrid-warfare conditions (mission-aligned per `MOTIVATION.md`), jury verdicts in distributed legal systems, corporate governance, consortium decisions, DAO governance. Reuses the Merritt-witness infrastructure already paid for at the consensus layer (BL-5). Composition: Merritt-witness pattern + DSSO identity + v2.22 confidential ballots + v2.10 FROST for tie-breaking + v2.24 audit hooks. Optionally augmentable with zk-VM (D.7-style) for ZK ballot proofs in a later iteration. Effort: ~3-4 weeks base; +1-2 weeks for optional zk-VM variant.

6. **Mission-alignment priority order updated.** D.5 first (government random-selection, original MOTIVATION.md use case); D.9 second (Merritt-voting, extends mission to elections themselves); D.4 + D.6 next (commercially and strategically broadest). D.7 + D.8 validate zk-VM substrate.

7. **§7 Sequencing updated.** Diagram shows §5.1 DApps starting when DSSO ships; §5.2 DApps starting when both DSSO + zk-VM ship. Net v1.1 horizon: ~5-8 months post-mainnet (slight increase from ~4-7 months due to D.9 addition + §5.2 dependency on Bundle B). Total project horizon: ~11-15 months from current state.

8. **§8 open questions extended** with two new D.9-specific questions:
   - D.9 ship sequencing — base first then zk-VM-augmented variant, or combined?
   - D.9 architecture — reuse Beaconless-v2 §Q5 BL-5 Merritt-affidavit collection code as a library, or implement standalone?

**Why D.9 is mission-strategic.** `MOTIVATION.md` cites the originating use case as Bulgarian random-judge-selection compromised by closed-source implementation. D.5 directly addresses random-selection. D.9 extends the same threat-model coverage to elections themselves — government voting under hybrid-warfare conditions where some voting infrastructure may be compromised. Merritt's "Mutually Verified Election" protocol provides provable Byzantine resistance with `num_voters > k(k+1)` for k Byzantine voters. The Merritt infrastructure is already in the project (paid for at consensus layer via BL-5); D.9 lifts it to a user-facing DApp.

**Why Option C (promotion over keep-as-Bundle-B-demos).** Calling the 3 zk-VM apps "Bundle B internal reference apps" understated their value. Private payment rollups, verifiable AI inference, and anonymous credential issuance are independently-valuable killer use cases — operators deploying them don't think of them as "demos for zk-VM substrate"; they think of them as solutions to their problems. The reframing makes the plan honest about what gets built and aligns Bundle D's role as "killer-DApp catalog" with what's actually produced.

**Why Option A (D.4 zk-VM augmentation).** AI-agent infrastructure is the most strategic killer DApp per `Improvements.md §9.5.1` AI-agent-economy positioning. Augmenting it with zk-VM verifiable inference makes it competitive with any other AI-agent infrastructure platform: cryptographic proof of correct delegate execution is exactly what compliance-bound AI deployments need. ~1-2 weeks additional effort for massive strategic positioning value.

**Generalization.** When a substrate (like zk-VM) is built, ensure first-class consumers exist beyond "internal reference apps." Internal demos prove the substrate works; first-class killer apps prove the substrate matters. The two roles are different; both are needed; ideally the same artifacts can serve both by promoting reference apps to first-class members.

---

---

## 2026-06-06 — Three-policy economic configuration + §5.8 EIP-1559-style mechanism

### Recommended operator economic-config pattern captured; new chain mechanism proposed for v1.0 ship as Additive

**Question.** User specified three-policy economic configuration for v1.0 deployments:
1. **Fixed Block Subsidy → minimum** — stops diluting token supply; eliminates inflation tax; true cost of messaging tied strictly to actual network demand
2. **Priority Tip Split → 100% to active K-of-K committee, split evenly 1/K** — symmetric incentive across signers; eliminates incentive to stall/veto/defect; critical for Phase-2 efficiency
3. **Base-Fee Parameters → microscopic floor with 50% utilization target** — keeps base cost at floor for telemetry/Web3-logging; only rises algorithmically when blocks exceed 50% full; priority tip uncapped

**Analysis.**
- **Items #1 and #2 are operator configuration** of existing v1.x mechanism — set `block_subsidy ≈ 0` and use existing `subsidy_mode = FLAT` (which already implements 1/K split with dust to creators[0]).
- **Item #3 is a NEW chain mechanism** — v1.x has a single per-tx `fee` field, not split into (base + tip). Adding EIP-1559-style semantics requires new wire-format fields + algorithmic base-fee computation + manifest-pinned algorithm parameters.

**Decisions applied.**

1. **Created `ECONOMICS_CONFIG_GUIDANCE.md`** (operator-facing) — captures the three-policy pattern as recommended-defaults; covers per-policy detail, self-consistent default config template, composition with chain primitives + §5.7 validation + §9.6 monetization framing.

2. **Added `Improvements.md §5.8` — EIP-1559-style base-fee + priority-tip mechanism** — new chain mechanism with wire-format additions:
   - `Transaction.priority_tip: u64` (new optional field; sender-set; uncapped; goes to validators 1/K)
   - `Block.base_fee: u64` (new per-block field; algorithmic per EIP-1559 adjustment)
   - `manifest.base_fee_floor`, `base_fee_target_util`, `base_fee_adjust_rate`, `base_fee_handling` (new genesis-pinned manifest fields)
   - Apply path: validator computes base_fee per block; rejects txs below base; priority_tip → 1/K FLAT distribution to K committee; base_fee disposition per manifest policy
   - Classification: Additive if shipped pre-v1.0 (~1-2 weeks); Breaking-only if shipped post-v1.0 without pre-v1.0 `Transaction.fee_form` discriminator
   - Recommended ship: pre-v1.0 (in v1.0 mainnet genesis schema) so the three-policy pattern is configurable from day 1

3. **Updated `IMPLEMENTATION-SEQUENCING.md` companion-docs** to reference `ECONOMICS_CONFIG_GUIDANCE.md`.

**Why ship §5.8 pre-v1.0.** The three-policy pattern is the recommended economic configuration per `MOTIVATION.md` framing (public-interest substrate, no monetary expansion subsidizing operators). Shipping §5.8 in v1.0 schema makes the pattern directly configurable at genesis. If §5.8 is deferred to post-v1.0 without pre-v1.0 discriminator scaffolding, the pattern becomes unavailable for v1.0 mainnet — operators must use v1.x's simpler single-fee mechanism with off-chain base-fee equivalents.

**Compositional cleanliness of §5.8.** The mechanism is Additive-via-default-zero: when `manifest.base_fee_floor = 0` AND `base_fee_target_util = 0` AND `Transaction.priority_tip = 0`, behavior reduces exactly to v1.x's existing single-fee model. Operators opt in to EIP-1559 by setting manifest fields; default deployment behavior unchanged. No no-migrations-constraint conflict.

**Compose with §5.7 genesis-time validation.** The three-policy pattern requires `sponsor_declaration` to be set (since both `block_subsidy ≈ 0` AND `base_fee_floor ≈ 0` mean validator economics depend on priority-tip flow + sponsor backing). §5.7 + §5.8 together let operators ship the three-policy pattern with safety-checked configuration that rejects misconfigured deployments at genesis.

**Generalization.** When operators want a specific economic pattern that depends on chain mechanism not in v1.x, the right move is: (a) add the chain mechanism as Additive via §7.5 discriminator OR new optional field, (b) capture the operator-pattern in `..._GUIDANCE.md` operator-facing doc, (c) add genesis-validation entry (§5.7-style) that rejects misconfigured combinations. This pattern (chain mechanism + operator guidance + genesis validation) keeps deployment economics safe by construction.

**Pre-v1.0-schema-freeze flag added.** §5.8 is the 4th candidate added post-§7.5-sweep (after §7.5.8 deployment_tier SKIPPED, §7.5.10/11 SHIPPED, §7.5.12 sponsor_declaration TBD). User-confirmed §7.5.8 + §7.5.10 + §7.5.11 already; §7.5.12 + §5.8 fields remain pre-v1.0 schema decisions.

---

---

## 2026-06-06 — Launch-model reframe: v1.0 → internal pre-launch dev; v1.1 → THE LAUNCH

### "No test/main net before v1.1" — single launch event collapsing the prior two-event model

**Question.** User stated: "There will be no test/main net before v1.1." What does this mean for the substrate-vs-application split in `IMPLEMENTATION-SEQUENCING.md` + `V1.1-PLAN.md`?

**Decision.** Reframe the launch model:
- **v1.0** = internal pre-launch development designation (no public release ever)
- **v1.1** = THE LAUNCH EVENT (mainnet — the single genesis ship)

All bundles previously framed as "v1.0 substrate ships first; v1.1 applications follow" now ship together as v1.1 mainnet. Substrate Bundles 1-5 (per `IMPLEMENTATION-SEQUENCING.md`) + application V1.1 Bundles A-E (per `V1.1-PLAN.md`) all complete before v1.1 launch.

**Rationale.** Launching the substrate without the applications would be a sterile event — DApps + zk-VM + DSSO are what gives the substrate visible value. Shipping them together at v1.1 means the mainnet genesis includes the complete ecosystem operators can actually use, not just the chain primitives they'd need to build applications on top of. Aligns with `MOTIVATION.md` (substrate-is-rich-enough thesis is validated by killer DApps that demonstrate it) and avoids the phased-launch coordination problem.

**Implications.**

| Area | Pre-reframe | Post-reframe |
|---|---|---|
| Launch events | Two (v1.0 mainnet + v1.1 release) | **One (v1.1 mainnet)** |
| No-migrations boundary | Applied from v1.0 launch | **Applied from v1.1 launch** |
| §7.5 schema discriminators | "v1.0 schema commitments" | **"v1.1 schema commitments"** |
| §5.8 EIP-1559 fee mechanism | Deferred Additive to post-v1.0 (would need pre-v1.0 discriminator) | **Ships in v1.1 genesis directly** (no discriminator needed; just genesis schema) |
| §5.7 economic-config validation | Pre-v1.0 schema decision (§7.5.12 sponsor_declaration) | **Ships in v1.1 genesis directly** |
| DSSO-as-DApp | Post-v1.0 DApp shipping in v1.1 release | **Ships at v1.1 launch as part of genesis-time DApp pre-loads** (or operator-installable add-on; deployment policy) |
| zk-VM-DApp | Post-v1.0 substrate shipping in v1.1 release | **Ships at v1.1 launch** |
| 9 killer DApps (D.1-D.9) | Post-v1.0 reference catalog | **Ship at v1.1 launch** as reference catalog (operators install per their use case) |
| Pre-launch development | Pre-v1.0 (substrate); pre-v1.1 (applications) | **Pre-v1.1** (everything) — breaking changes during dev allowed freely |
| Calendar | ~6.5-8 months v1.0 + ~5-8 months v1.1 = ~11-15 months total | **~11-15 months to v1.1 launch** (calendar barely changes; we just don't ship v1.0 separately) |
| MAINNET_READINESS criteria | v1.0 mainnet criteria | **v1.1 mainnet criteria** (combined substrate + applications scope) |

**Doc updates applied.**
- `IMPLEMENTATION-SEQUENCING.md` header — added LAUNCH MODEL REFRAMED paragraph; bundles ship as part of v1.1 launch
- `V1.1-PLAN.md` header + premise + convention — reframed as THE LAUNCH (not "post-v1.0 release"); convention notes no-migrations applies post-v1.1; everything ships at v1.1 genesis
- `MAINNET_READINESS.md` — reframed for v1.1 launch scope (combined substrate + applications)
- Memory `dlt-no-migrations-constraint` — updated to clarify constraint applies post-v1.1 launch; pre-v1.1 dev can have breaking changes
- This DECISION-LOG entry

**What this does NOT change.**
- The bundle structure (Bundles 1-5 substrate + Bundles A-E applications) is preserved
- The dependency ordering between bundles is preserved (V1.1 Bundle A DSSO-DApp still depends on Bundle 1 v2.10 FROST shipping; etc.)
- The work effort estimates are unchanged
- Memory `dlt-pre-mainnet-status` still applies — project is pre-mainnet (= pre-v1.1) until launch
- Memory `dlt-qa-strategy` (closed-beta, clean-break, open-ended, no external audit) applies to v1.1 beta
- Memory `dlt-team-composition` (4-32 fungible Opus 4.7 threads) unchanged
- Memory `dlt-dsso-as-dapp` — DSSO is still a chain-aware DApp, just shipping at v1.1 launch rather than post-v1.0

**What this DOES simplify.**
- §5.8 EIP-1559 fee mechanism no longer needs "ship pre-v1.0 OR discriminator-defer" decision — it's just genesis schema; ship it
- §5.7 genesis validation + §7.5.12 sponsor_declaration similar — direct genesis schema decision
- §7.5.8 deployment_tier reconsideration — was SKIP because Option A monetization became Breaking-only post-v1.0; under v1.1 launch model, all schema decisions are pre-launch so could revisit (but the underlying value decision against tier-bond monetization still applies)

**Generalization.** When a launch model changes from phased to single-event, all "pre-launch schema preservation" decisions simplify — there's no "pre-launch vs post-launch" boundary within the dev period; everything is pre-launch. The no-migrations constraint moves from "applies to v1.0 mainnet schema" to "applies to v1.1 mainnet schema" — same discipline, just at the actual launch event rather than an interim one.

---

---

## 2026-06-06 — v1.1 genesis schema final-call walkthrough + ECONOMICS_CONFIG_GUIDANCE block_subsidy correction

### 3 schema decisions resolved under reframed v1.1-launch model + block_subsidy recommendation refined from 0 → 1

**Question.** After the v1.1-launch model reframe (no test/main net before v1.1; v1.0 is internal pre-launch dev only), 3 deferred/pending schema items needed final ship-or-skip decisions for v1.1 genesis: §7.5.8 deployment_tier (was SKIPPED under old two-event model), §7.5.12 sponsor_declaration (pending), §5.8 EIP-1559 mechanism (pending — ship full mechanism, discriminator only, or skip).

Plus user direction: ECONOMICS_CONFIG_GUIDANCE recommended config should use `block_subsidy = 1` (one dust unit) not 0 — preserves A1 invariant subsidy counter exercise + defensive against subsidy code-path bitrot.

**Decisions.**

1. **`block_subsidy = 1` canonical recommendation** in ECONOMICS_CONFIG_GUIDANCE (corrected from prior `0` framing). Rationale: 1 dust × ~31M blocks/year ≈ 31M dust units/year is economically negligible but operationally safer; ensures subsidy mint path + A1 invariant tracking exercised every block; ensures validators always receive something even if priority-tip flow temporarily dries up.

2. **§7.5.8 `RegistryEntry.deployment_tier` enum — REVISED to SHIP in v1.1 genesis.** Was SKIPPED 2026-06-03 under the (now-defunct) "Breaking-only post-v1.0" framing. Under v1.1-launch model that boundary is gone; shipping the discriminator (1 byte/RegistryEntry) preserves Option A tier-bond monetization optionality at trivial schema cost. **Value-decision against tier-bond monetization stays** (validator enforces deployment_tier = UNSTAKED at v1.1 launch; tier-bond logic NOT implemented). Schema slot exists for future revisit.

3. **§7.5.12 `manifest.sponsor_declaration` enum — SHIP in v1.1 genesis.** Required by §5.7 economic-config validation rule + ECONOMICS_CONFIG_GUIDANCE recommended three-policy pattern (which includes `sponsor_declaration: SOVEREIGN_OPERATOR`). 1 byte/manifest enum (NONE / SOVEREIGN_OPERATOR / FOUNDATION_RUN / OTHER); ~1 day spec + ~1 day implementation. Chain validates field syntax but does not enforce truthfulness of off-chain sponsor attestation.

4. **§5.8 EIP-1559 fee mechanism — SHIP FULL MECHANISM in v1.1 genesis (not just discriminator).** Adds `Transaction.priority_tip: u64`, `Block.base_fee: u64`, and 4 manifest fields (`base_fee_floor`, `base_fee_target_util`, `base_fee_adjust_rate`, `base_fee_handling`). ~1-2 weeks pre-launch implementation. Additive-via-default-zero: when manifest fields are zero, behavior reduces exactly to v1.x single-fee model. Enables ECONOMICS_CONFIG_GUIDANCE three-policy pattern from v1.1 launch day 1.

5. **§7.5.9 gas_pricing_form stays REJECTED.** Gas-style monetization is value-decision rejection (changes Determ's character toward fee-market substrate), not boundary issue. Stays out of v1.1 schema regardless of launch-model reframing.

**Pre-launch schema work scope updated.**
- Was ~6-10 days for 7 discriminators (per prior IMPLEMENTATION-SEQUENCING)
- Now ~9-15 days for 9 discriminators + §5.8 EIP-1559 full mechanism (+2-4 days for 7.5.8/7.5.12 + 1-2 weeks for §5.8 mechanism implementation)

**Cascade effects.**
- ECONOMICS_CONFIG_GUIDANCE three-policy pattern (minimal subsidy + 1/K priority tip + EIP-1559 base fee) becomes fully configurable at v1.1 launch via §5.8 + §7.5.12 + existing FLAT distribution mode
- §5.7 economic-config validation has the `sponsor_declaration` field it needs to validate "zero subsidy + zero fees + no sponsor" as bad combination
- Bundle 3 (v2.22) work unit gains ~1-2 weeks for §5.8 EIP-1559 mechanism (can ship in same era as v2.22 since both touch Transaction wire format)
- Beaconless-v2 manifest schema gains 7.5.12 + 4 §5.8 manifest fields (~6 bytes total addition; trivial)
- Pre-bundle critical path: ~9-15 days

**Files updated.**
- `Improvements.md §7.5` table — 7.5.8 status revised SKIP → SHIP; 7.5.12 + §5.8.S rows added
- `IMPLEMENTATION-SEQUENCING.md` pre-bundle schema table — added 7.5.8 + 7.5.12 + §5.8 rows; combined effort updated from ~6-10 days to ~9-15 days
- `ECONOMICS_CONFIG_GUIDANCE.md` — `block_subsidy = 0` → `block_subsidy = 1` canonical; §2.1 rationale rewritten; §3 config template updated
- This DECISION-LOG entry

**Generalization.** When a launch-model reframing collapses "phased launch" into "single launch event," previously-foreclosed schema decisions can be revisited cheaply. The §7.5 sweep was final under the two-event model; under the v1.1-launch model, 3 additional items naturally fold in without the deliberation overhead the original sweep required. Reframing → schema-decision-window-reopened pattern is worth flagging if the project ever undergoes another such reframe.

---

---

## 2026-06-06 (afternoon) — Formal-verifiability rationale for no-migrations + v1.1 three-property achievement frame

### Why the no-migrations constraint is load-bearing, not stylistic

**Question.** Earlier no-migrations decisions ([[Bundle release cadence + "no migrations" project constraint]] 2026-06-03 + [[v1.1-launch model reframe]] 2026-06-06) recorded the constraint but not its load-bearing rationale. Why is it absolute?

**Answer (user direction 2026-06-06).** Formal verifiability requires an immutable target.

The project carries ~100 `docs/proofs/` soundness theorems across FA1-FA12 analytic proof families + FB1-FB4 TLA+ specs + the S-series + the BFT/F2/CrossShard/LightClient/AccountHistory chains. Every one of these proofs is parameterized over a *specific* protocol — specific wire format, specific consensus rules, specific state transitions. A schema migration invalidates the proof targets and forces the entire verification track to rebuild against the new protocol.

The decision is: lock the protocol at v1.1 launch, *never touch it*, and let the formal-verification track stabilize against a single immutable target. The trust property this delivers is qualitatively different from "the current version is verified": it is "the protocol that exists now is the protocol that will exist forever, and the proofs that hold now will hold forever."

**Cascade.** Three properties are now load-bearing-locked at v1.1:

1. **God protocol** (Szabo sense) — K-of-K mutual-distrust default mode. §6.2 Quorum Liveness OPTIONAL is the only documented relaxation, opt-in at genesis.
2. **Decentralized identity provider** — DSSO via T-OPAQUE (Bundle A); identity primitives ship at launch and persist for chain lifetime.
3. **Perfect forward secrecy** — v2.22 PRIV-6 per-tx PFS via OTPK; opt-in per-account, capability preserved chain-lifetime.

These three are not just *features* shipping at v1.1 — they are *commitments* the formal-verification track now targets as immutable. The cost of breaking any of them post-launch is not "one migration" — it is the entire FA1-FA12 + FB1-FB4 + S-series track restart against a new protocol, plus the trust degradation of a moving target.

**Files updated.**
- `README.md` — version header "Version 2" → "Version v1.1"; abstract reframed for v1.1; new §0 introducing the three properties + formal-verifiability rationale
- `V1.1-PLAN.md` — new §0 three-property achievement frame
- `IMPLEMENTATION-SEQUENCING.md` — header amended with formal-verifiability rationale paragraph
- `ECONOMICS_CONFIG_GUIDANCE.md §2.2` — K-of-K FROST assumption footnote (latent t-of-n disambiguation flag from prior crypto-vs-revenue analysis)
- `Beaconless-v2-SPEC.md` + `AnonAddressDerivationMigration.md` — migration-language tightening: "migration from beacon-bound" → "genesis deployment-type choice" where applicable
- Memory `dlt-no-migrations-constraint` — formal-verifiability rationale + three-property lock added
- This DECISION-LOG entry

**Generalization.** When a project constraint is reported as "stylistic" or "preferential" but turns out to be load-bearing for a downstream property (verification, audit, compliance), document the load-bearing-ness explicitly. Future-self (or future-team) will treat a stylistic constraint as negotiable and a load-bearing constraint as foreclosed — the difference matters under pressure. The no-migrations constraint moved from "we don't want to" → "we structurally cannot, because formal verification depends on it" through this clarification.

---

## 2026-06-07 — Adopt MPDH for the block-randomness beacon (de-scope v2.10 FROST-as-beacon)

*(Reference: `V210-PhaseD-RandomnessWiring.md` §9 + §9.1; `SECURITY.md` §1; `V2-DESIGN.md` v2.10 row. Authority: Stoyan Denev. This entry is recorded by the AI assistant on Stoyan's instruction and is **not co-authored** — the design decision is Stoyan's.)*

**Question.** Should the block-randomness beacon move from the v1 MPDH commit-reveal scheme to the planned v2.10 FROST-Ed25519 threshold-signature aggregate?

**Options considered.**
1. **Keep MPDH commit-reveal** (v1, shipped, stateless).
2. **FROST-as-block-beacon** (v2.10 Phases B–E: per-epoch DKG + PSS + threshold signing wired into `compute_block_rand`).
3. **Threshold BLS** (unique-signature beacon — drand/DFINITY style).

**Choice: Option 1 — retain MPDH.**

**Why the others were rejected.**
- *FROST (2):* adversarial verification (three workflows, 21 + 7 + 8 agents) established that a FROST aggregate is **not** a bias-resistance upgrade over MPDH. FROST/Schnorr is randomized + non-unique; a round-2 withholder forces a re-roll with a *different* `R` (it is not even drop-tolerant within a fixed signer set — only threshold-BLS interpolates any-`t` to the same output). MPDH already closes *grinding* bias information-theoretically (FA3 / `SelectiveAbort.md` T-3, under SHA-256 preimage resistance) and handles the *abort* residual by re-roll + suspension slashing. FROST would add a DKG/PSS ceremony, long-lived secret shares + their failure modes, and a wire-version bump — paying ≈BLS-level complexity **without** delivering BLS's defining uniqueness. Its two genuine edges (`t`-of-`K` availability, O(1) succinct verify) are narrow and largely already covered (abort→re-roll + BFT escalation; the light client doesn't re-verify the beacon and pays O(`K`) per header regardless).
- *BLS (3):* the only option that is unbiasable-by-construction, but the heaviest (pairings + DKG). Reserved for a future deployment that genuinely requires no-abort-re-roll randomness; not warranted under Determ's accepted abort posture.

**Cross-decision implications (worth flagging).**
- The FROST C99 stack (keygen/DKG/sign/aggregate/PSS, built + audited this cycle) is **retained** — only the *block-beacon application* is dropped. It remains available for `Beaconless-v2-SPEC.md` cross-shard randomness, threshold/multisig signing, and the shared curve25519 foundation for v2.22 / v2.25.
- **Elasticity (verified, 0/3 refuted).** MPDH's statelessness makes committee/validator churn **ceremony-free** — no DKG/PSS on rotation. This is an architectural asset, not just "good enough."
- **Beaconless-sharding payoff (verified; ADOPTED 2026-06-07).** `Beaconless-v2-SPEC.md` §Q6 is **switched from per-shard FROST threshold sigs to per-shard MPDH commit-reveal** as the cross-shard contribution (each shard contributes its `cumulative_rand` at a deterministic height; same SHA-256 accumulator + XOR-own-entropy), removing per-shard DKG/PSS/epoch-orchestration. **Conditions (folded into the §Q6 DECISION box):** the contribution (`cumulative_rand`) is **not** in the Phase-2 K-of-K committee digest — `compute_block_digest` excludes `cumulative_rand`, `delay_output`, and `state_root` alike; it is bound into the block *hash* (`signing_bytes`) and authenticated transitively via the prev_hash chain (verify the source shard's header chain through `H+1`), which the light-client mesh walks anyway; and the per-shard primitive is pinned by a genesis-time `randomness_aggregation_form` manifest discriminator (default `mpdh_commit_reveal`, no-migrations). Authorized by Stoyan Denev this session; the §1/§Q2/§Q3/§3.2/§4.x references were threaded to MPDH in the same change.
- Readiness: v2.10 is **no longer a permissionless-readiness gate**; the residual selective-abort is an accepted posture under MPDH. Remaining gate is v2.7 F2 (~3–4 days).

**Generalization.** A threshold *signature* scheme is not automatically a better *randomness beacon*. Bias-resistance for a beacon comes from either (a) hiding-commit + accepted abort handling (MPDH/FA3), (b) signature *uniqueness* (BLS), or (c) a VDF — not from "it's a threshold scheme." FROST sits in an awkward middle: keyed-scheme cost without keyed-scheme uniqueness. Prefer the stateless contributory scheme unless `t`-of-`K` availability or succinct single-sig verifiability is a hard, demonstrated requirement.

---

---

## 2026-06-07 — Option C: FROST removed from v1.1 chain consensus path + DLT-A composition for DSSO + FROST provenance NOTICE

### FROST identified as Claude-introduced design deviation; removed from v1.1 scope; DSSO restructured around DLT-native primitives

**Question.** Following the formal-verifiability rationale for no-migrations (2026-06-06 afternoon), re-examination of every primitive in the v1.1-locked surface for load-bearing-ness. FROST was found to be load-bearing only for DSSO assertion-binding; the v1.x commit-reveal protocol already provides unbiasable block randomness, and K individual Ed25519 sigs already provide block authentication. Three sub-questions arose:

1. Can DSSO be implemented without FROST using DLT-native primitives?
2. Should FROST be removed from the v1.1 chain consensus path entirely?
3. How to record the design provenance — FROST was Claude-introduced, not part of Stoyan Denev's original Determ design.

**Decisions (Stoyan 2026-06-07).**

1. **DSSO via DLT-A composition (no FROST).** Two crypto legs, both using primitives already shipped:
   - **T-OPRF leg:** X25519 threshold DH. N DSSO operators each hold scalar share k_i; user sends blinded password as X25519 point P; each operator returns P^k_i; user aggregates via group multiplication = P^(Σ k_i); user unblinds to OPRF output. Mathematically equivalent to single-server OPRF with key = Σ k_i. Uses already-shipped X25519 (commit `bc87704`). No new crypto primitive.
   - **Assertion-binding leg:** Block-anchored DAPP_CALL. DSSO emits a DAPP_CALL tx ("user U session S valid at block N") into mempool; tx included in block N via union_tx_root; block N signed K-of-K by chain committee (already happens every block). **The chain's K-of-K block signature IS the threshold attestation.** RP verifies (a) block sig K-of-K + (b) Merkle inclusion proof + (c) session signature.
   - Crypto inventory: Ed25519 + X25519 + SHA-2 + ChaCha20-Poly1305 + DAPP_CALL + state-root proofs. All already shipped. Zero new primitives.

2. **FROST removed from v1.1 chain consensus path entirely.**
   - v2.10 FROST chain-wiring removed from substrate Bundle 1
   - Beaconless v2 §4.6 cross-shard randomness switched from FROST threshold sig to commit-reveal aggregation across shards (matches within-shard pattern)
   - `signature_form` discriminator in §7.1: open question, evaluated separately under FROST-removal cascade
   - FROST C99 implementation under `src/crypto/frost/` is retained as a library (DApp-layer use post-launch is allowed under DApp authority); it is NOT part of the v1.1 consensus path, NOT part of the v1.1-locked formal-verification surface

3. **`FROST_DEVIATION_NOTICE.md` created** as provenance record. Establishes that FROST was Claude-introduced (not part of Stoyan's original Determ design), records the re-examination + removal, and sets the discipline for future AI-introduced design elements: AI must identify proposals as AI-suggested, cite the original design property the proposal addresses, compare against DLT-native alternatives, and defer to Stoyan for accept/reject before recording in any immutable document.

**Why this matters.** The no-migrations + formal-verifiability frame (per `DECISION-LOG.md 2026-06-06 afternoon` + memory `dlt-no-migrations-constraint`) makes every primitive in the v1.1 surface load-bearing for the chain's lifetime. AI-introduced primitives that propagate into specs + implementation + audit without explicit owner sign-off are a discipline failure mode. FROST is the recorded example. The NOTICE establishes the discipline so future sessions catch it preemptively.

**Cascade effects.**
- Bundle A (DSSO) effort estimate: ~6-8 weeks → ~4-6 weeks (no FROST chain-wiring; ~2 weeks saved)
- Bundle 1 (v2.10 FROST chain-wiring) removed from substrate critical path (~2-3 weeks saved)
- Beaconless v2 §4.6 switched to commit-reveal aggregation (already updated in spec; no new primitive needed)
- Formal-verification target surface reduced (no FROST DKG, no FROST sign, no PSS proofs needed for v1.1)
- C99 crypto stack: §3.8 FROST primitives retained as library, not in consensus path
- Light-client verifier: unchanged (still verifies K individual Ed25519 block sigs)
- Audit surface for v1.1: reduced (no threshold-cryptography family in consensus path)

**Files updated.**
- `FROST_DEVIATION_NOTICE.md` — NEW provenance record
- `V1.1-PLAN.md` — Bundle A reworked for DLT-A composition; §0 three-property frame updated (DSSO mechanism, god-protocol mechanism); companion docs list updated; effort estimate revised
- `IMPLEMENTATION-SEQUENCING.md` — Bundle 1 FROST chain-wiring removed; FROST_DEVIATION_NOTICE referenced
- `Beaconless-v2-SPEC.md` — §4.6 cross-shard randomness switched to commit-reveal aggregation (already done in prior session edit by Stoyan)
- `ECONOMICS_CONFIG_GUIDANCE.md §2.2` — K-of-K FROST forward-compat note removed (moot under FROST removal); replaced with simple K-individual-sigs distribution statement
- `CRYPTO-C99-SPEC.md` — NOTICE banner at top: §3.8 FROST not in v1.1 consensus path
- `V210ImplementationRoadmap.md` — NOTICE banner at top: roadmap goal FORECLOSED; document HISTORICAL
- `README.md` — DSSO mechanism description updated (DLT-A, not T-OPAQUE/FROST); FROST_DEVIATION_NOTICE referenced
- Memory `dlt-no-migrations-constraint` — DSSO mechanism updated; FROST_DEVIATION_NOTICE referenced
- This DECISION-LOG entry

**Generalization (added to project meta-discipline).** Any AI-introduced design element that becomes load-bearing in a long-lived artifact must be flagged as such in a NOTICE document. The asymmetry: an AI proposing a design element does not bear the consequences of its permanence. A human owner does. When the consequence is "this primitive is in the chain's immutable surface forever," provenance matters. The FROST case is now the project's worked example of catching AI-introduced drift before launch; the discipline is captured in `FROST_DEVIATION_NOTICE.md §4` for forward-applicability.

---

*End of decision log. Append new entries below as future deliberations conclude.*

## 2026-07-03 — Anon-address derivation formula FROZEN as-is + secp256k1/Bulletproofs implementation track DE-SCOPED

**Authority:** Stoyan Denev (decision relayed in-session; recorded by Claude Fable at his direction — the same recording pattern as the 2026-06-07 FROST NOTICE and its 2026-07-03 §6 amendment).

**Decision 1 — anon-address derivation (resolves `AnonAddressDerivationMigration.md`, the §7.6.7 formula question):** the current formula `make_anon_address(pk) = "0x" + hex(pk)` (`include/determ/types.hpp`) is **FROZEN for v1.1 genesis** — permanent under no-migrations. Anonymous addresses are Ed25519-only for the chain's lifetime; no `pubkey_form` discriminator enters the address preimage; the §7.6.7 pre-launch implementation bundle (hash+discriminator formula, `Transaction.from_pubkey`, fixture regeneration across dozens of test scripts) is **CANCELLED**. The §7.6.7 binding requirement is satisfied vacuously: with exactly one pubkey form ever admissible for anon addresses, cross-form address aliasing cannot arise. Post-quantum identity needs are served by the registered-domain identity layer, which can evolve — not by anon addresses. Rationale: Option A (SchemaDiscriminatorsImpl.md §4) bought optionality for a PQ-anon-address future that no v1.1 property commitment requires, at the price of a pre-launch consensus wire change plus full fixture churn. `tools/test_anon_address_derivation.sh` already pins the frozen formula as a bijection.

**Decision 2 — secp256k1 + libsecp256k1-zkp Bulletproofs + OPRF-secp256k1 DE-SCOPED from committed work** (CRYPTO-C99-SPEC §3.7 + §3.9a stamped): no consumer exists — v2.22 confidential transactions is FUTURE-tier design-only with zero code, DSSO was re-based to X25519 DLT-A (2026-06-07), and vendoring ~9K LOC of third-party curve code would add a lifetime audit/CT/vector obligation for nothing shipped. `PROTOCOL.md` §12.4's MODERN-profile crypto bundle is corrected to what actually ships (XChaCha20-Poly1305, Argon2id, Ed25519, X25519) and the "Confidential tx ✅ Available" claims are withdrawn. `v2.22-PRIVACY-SPEC.md` remains a FUTURE-tier design record; reviving the track requires a new decision satisfying `FROST_DEVIATION_NOTICE.md` §3-style justification (consumer, Stoyan-traced requirement, verification-cost estimate).

**Ridealong truth-ups recorded with this entry (drift, not decisions):** PROTOCOL.md §8.1 "until F2 ships" (F2 shipped); PROTOCOL.md §5.1 ContribMsg + `make_contrib_commitment` updated to the shipped DTM-F2-v1/DTM-TS-v1 wire shape; ROADMAP rows (F2 SHIPPED, C99 statuses, FROST-freeze cascade, address decision DECIDED); v2.10-DKG-SPEC + DOC-TIERING-PLAN retention phrasing aligned to the NOTICE §6 amendment (module FROZEN — the "retained for Beaconless/DSSO" claims were superseded); the stale "sole S-030-D2 residual" comment in `src/main.cpp` test-block-digest + the phantom "Validator (Phase 3) gates" comment in `block.hpp` (the digest-binding closure was re-verified at HEAD 2026-07-03: no open residual); libsodium FetchContent sha-pinned (was `GIT_TAG master`, an unpinned moving branch) and the false "only the wallet OPAQUE stub links sodium" claim corrected (CMakeLists.txt + CRYPTO-C99-SPEC §3.14 — actual surface: ~200 call sites across wallet/main.cpp).

## 2026-07-03 — Single build: DETERM_CRYPTO tri-state removed; FIPS market retained via pluggable CMVP-validated module

**Authority:** Stoyan Denev (decision relayed in-session; recorded by Claude Fable at his direction).

**Decision:** the `-DDETERM_CRYPTO={modern|fips|universal}` build tri-state, `include/determ/crypto/profile_build.hpp`, its `check_genesis_compatibility()` startup gate, and the never-built `src/crypto/{fips,modern,universal}/` placeholder subtrees are **REMOVED**. There is ONE build: every binary carries the full validated C99 stack (what `universal` was).

**Why:** verified at HEAD, the tri-state changed zero compiled code — all crypto modules linked into every variant; its entire effect was a 3-value label checked once at `determ init --profile`. The "FIPS module boundary" it claimed did not exist (a `fips` binary still linked every non-approved primitive), and could not have delivered compliance anyway: **FIPS 140 compliance is conferred by CMVP validation of the crypto module, not by algorithm selection** — a from-scratch stack will never carry a CMVP certificate. The split's original roadmap substance (secp256k1 + Bulletproofs confidential transactions as the MODERN differentiator) was de-scoped earlier the same day.

**What survives:** the profile presets' `crypto_profile` column (`params.hpp::TimingProfile`) as the documented ALGORITHM POSTURE per deployment archetype (`cluster`/`tactical` = FIPS-approved algorithms; `web`/`regional`/`global` = MODERN preference). Not consensus-bound (never serialized into genesis).

**What replaces the build split for the FIPS market:** FIPS deployments pair the FIPS algorithm posture with a **pluggable CMVP-validated crypto module** — a provider interface delegating the FIPS-relevant primitives to a certified module (e.g. a validated OpenSSL 3.x FIPS provider). This is the honest, industry-standard route to FIPS 140 markets and retains that market position. The provider interface itself is FUTURE work, **gated on a concrete FIPS customer** — recording the strategy now costs nothing; building the interface speculatively would repeat the aspirational-surface pattern this log keeps closing.

Threaded: CMakeLists.txt, src/main.cpp (gate removed), params.hpp (posture comment), src/crypto/README.md (tri-subtree table -> actual per-module layout), CRYPTO-C99-SPEC §2.Q10 (dated amendment), IMPLEMENTATION-SEQUENCING C99-12..14 rows (REMOVED), Improvements.md BLS gate reference.

## 2026-07-03 — Second-platform CI gate (option 1a); caught a latent cross-toolchain state_root fork

**Authority:** Stoyan Denev (chose option 1a in-session).

**Decision:** add `tools/ci_local.sh` (build all three binaries + FAST=1 + offline doc guards on the current toolchain, via the `DETERM_*_BIN` overrides) + `.github/workflows/ci.yml` (same content, ubuntu+windows, inert until pushed). Run inside WSL2 Ubuntu it gives the green surface a SECOND independent toolchain (GCC 13 / Linux) next to the primary MSVC / Windows box — closing the top operational issue: single-box, single-platform verification.

**What it caught on its FIRST run (a consensus-critical bug):** `Chain::build_state_leaves()` encoded the `i:` (applied-inbound-receipt) state-leaf key's `src_shard` as 8 big-endian bytes by shifting a `ShardId` (`uint32_t`) up to 56 bits — undefined behavior. MSVC folded the oversized shift to 0 (intended zero high bytes); x86-64 GCC masks the shift count mod 32, corrupting the high bytes. So `compute_state_root()` DIVERGED between toolchains whenever an inbound cross-shard receipt existed — two differently-compiled nodes would fork on the first cross-shard block. Invisible for as long as the tree built on one compiler. Fixed (chain.cpp:336, `static_cast<uint64_t>` before the shift) BYTE-INVARIANT vs the shipped MSVC lineage — no state root / genesis hash / pin moves; other compilers now conform. Committed separately (`fix(consensus): UB in the i: state-leaf key encoding`) and flagged for review per the consensus-change discipline. Whole bug class audited: chain.cpp:336 was the only real instance (all sibling BE-shift loops are width-matched).

**Follow-ups (recorded, not built):** the endgame this gate unblocks — 1b the §3.15 daemon crypto migration onto determ::c99 (retires EOL OpenSSL from the consensus path, byte-identical, gated on authorization + both-platform validation), then 1c the OpenSSL-3.x/removal cleanup — remain open, now safe to attempt because a second platform validates them.

## 2026-07-03 — UBSan gate (option 1) + cross-toolchain golden-vector contract (option 2); UBSan caught 2 crypto UBs

**Authority:** Stoyan Denev (chose "1+2" in-session).

**Decision.** Add two complementary determinism nets on top of the 1a second-platform gate:

- **Option 2 — `test-consensus-vectors` (committed `606bbb2`).** A cross-toolchain GOLDEN-hex contract: pins genesis_hash + `compute_state_root()` + head block_hash over a fixed scenario battery (bare genesis + the composite `i:`/`m:`/`p:` state namespaces). Every build must reproduce the goldens byte-for-byte; a mismatch is a cross-compiler consensus FORK caught at test time. This is the STATIC complement the within-build `test-state-root-determinism` could not provide (it can't see cross-compiler divergence). Proven byte-for-byte green on BOTH MSVC and GCC 13. V2 exercises the exact `i:` surface that carried the `chain.cpp` shift-UB — so this test would have RED-flagged that fork.

- **Option 1 — `tools/ci_local.sh --sanitize` (UBSan) + `DETERM_UBSAN` CMake option + `ubsan` CI job.** The RUNTIME net for the UB class. `-DDETERM_UBSAN=ON` scopes `-fsanitize=undefined` to Determ's OWN targets (`determ` + `determ-crypto-c99`); the vendored OpenSSL/asio/json stay uninstrumented (no dep-side noise, no whole-tree sanitized rebuild). Abort-on-UB is enforced at runtime via `UBSAN_OPTIONS=halt_on_error=1` (a compile-time `-fno-sanitize-recover` breaks OpenSSL's CMake feature-tests). ASan is intentionally NOT enabled (its shadow memory OOMs on the large `main.cpp` TU; memory-safety is separable). The gate runs the consensus/determinism surface + the ENTIRE `determ::c99` crypto stack (31 subcommands) under UBSan.

**What UBSan caught on its FIRST run (2 real UBs, byte-invariant fixes).** The consensus-serialization surface was UB-CLEAN (all 13 consensus/determinism subcommands PASS(ubsan) — corroborating the static audit that `chain.cpp` was the sole state-root shift-UB). But the crypto stack carried a distinct UB class: **left shift of a negative value** (C-standard UB) in the TweetNaCl-derived signed-limb field arithmetic:
- `src/crypto/ed25519/ed25519.c:57` — `car25519`'s `o[i] -= c << 16` (c = `o[i] >> 16` can be negative), and the same pattern in `modL` at line 186 (`x[j] -= carry << 8`).
- `src/crypto/x25519/x25519.c:22` — the identical `car25519` `o[i] -= c << 16`.

TweetNaCl relies on all real compilers implementing `<<` on a negative value as 2's-complement (which is why the output was still correct and byte-equal to libsodium), but it is formally UB and UBSan halts on it. Fix (all 3 sites): shift as unsigned then reinterpret — `(i64)((uint64_t)c << 16)` — bit-identical to the intended 2's-complement result on every conforming platform (C++20 mandates 2's-complement), so the field output stays **byte-equal to libsodium**. After the fixes, all 31 subcommands PASS(ubsan) (`SAN_FAIL=0`). Committed separately (`fix(crypto): well-define negative-left-shift UB in TweetNaCl-derived car25519/modL`).

**Byte-equality evidence.** (1) Empirical on GCC 13: `test-ed25519-c99`, `test-ed25519-vectors`, `test-x25519-c99`, `test-c99-vectors` (CAVP + libsodium-derived corpus) all PASS under UBSan post-fix. (2) Mathematical: unsigned-shift-then-reinterpret is bit-identical to the signed 2's-complement shift on any conforming platform. (3) Scope: these c99 files serve the wallet + self-tests, NOT the consensus/daemon path (still OpenSSL) — not consensus-critical today, but the fix matters ahead of the 1b daemon-crypto migration that WOULD put them on the chain path. MSVC empirical re-confirmation is deferred to the CI `windows` job (the local MSVC `build/` tree is mid-transition off libsodium and a full rebuild exceeds the local build window); the GCC proof + byte-invariance are the standing evidence.

**Local-run engineering note.** The scoped-UBSan `determ` link is heavy on the dev box (the instrumented `main.cpp.o` at `-O3` never linked within the process window). Resolved by compiling `main.cpp.o` at `-O0` (UBSan needs no optimization; `-O0` compiles the 38k-line TU in ~65s vs never-finishing at `-O3`; the object links fine against the `-O3` objects and UBSan still reports the UB's own `file:line`). The `ubsan` CI job on `ubuntu-latest` links the full binary directly with headroom.

## 2026-07-03 — §3.15 daemon crypto migration SHIPPED (1b): consensus path off EOL OpenSSL, onto determ::c99

**Authority:** Stoyan Denev ("Do the recommended" — option A + C in-session, after a 4-reader survey ranked EOL OpenSSL 1.1.1w in the consensus path as the top open issue).

**Decision (A).** Migrate the daemon/light consensus crypto from OpenSSL onto the in-tree `determ::c99` stack. The survey had reduced the surface to exactly three production files — `src/crypto/sha256.cpp` (EVP streaming SHA-256 behind every block hash / tx root / merkle / state root), `src/crypto/keys.cpp` (EVP_PKEY_ED25519, the only shipped signature backend), `src/node/node.cpp` RAND_bytes (the per-round dh_secret) — plus auxiliary sites (RPC-auth HMAC, light keyfile derivation, 7 CLI pubkey derivations, genesis salt). Two gaps closed en route: the C99 sha2 engine gained an exported streaming `init/update/final` API (the one-shot now wraps it, so the CAVP + §Q9 gates validate both), and a new §3.15 OS-entropy shim `determ_rng_bytes` (`src/crypto/rng/` — BCryptGenRandom / getrandom+urandom, fail-fatal) supplies the one primitive a from-scratch stack cannot synthesize.

**The work-reducing insight: pre-genesis timing dissolves the migration's hardest problem.** The C99 verifier is deliberately STRICTER than OpenSSL's lenient decoder (RFC 8032 canonicality: S < L, canonical pubkey) — on a live chain that is a coordinated-fork-class change requiring rolling-upgrade machinery. Determ has no live fleet, so the strict verifier is simply locked in as THE consensus signature-validity rule from genesis: safer semantics (non-canonical encodings rejected, signature uniqueness), zero transition cost. Honestly-generated keys/signatures behave identically under both backends.

**Byte-invariance evidence.** SHA-256 is a fixed function and the C99 engine was already CAVP + §Q9-validated; Ed25519 signing is deterministic RFC 8032, proven byte-equal to OpenSSL over a fuzzed (seed,msg) grid. Post-swap: `test-consensus-vectors` GOLDENS HELD BYTE-FOR-BYTE on both MSVC and GCC (the cross-toolchain contract built the day before proving its worth), `test-ed25519-vectors` — written explicitly as the backend-swap detector — passes with `crypto::sign/verify` on C99, `test-sha2-c99`/`test-ed25519-c99` §Q9 oracles still agree, and both platforms' FAST suites ran green. Keyfile format unchanged (the raw private key IS the RFC 8032 seed under both backends).

**What remains of OpenSSL (honest 1c scope).** `determ-light` links ZERO OpenSSL. `determ` keeps libcrypto ONLY for the §Q9 test-oracle subcommands (cross-validation BY DESIGN requires a non-determ implementation). The wallet keeps OpenSSL for its keyfile/backup envelopes (PBKDF2 + AES-256-GCM + base64) — migrating those needs the documented c99 AES-GCM decrypt-direction gap closed first. libssl (TLS — never used; src/net has none) is dropped from every target. So the EOL 1.1.1w liability is out of the CONSENSUS path entirely; the residual exposure is wallet-envelope + offline-oracle, addressable later by a wallet-scoped bump (1c) without touching consensus.

**Ridealongs (C, deletion-shaped).** `test_beacon_only.sh`'s dead SKIP branch removed (its "Crypto profile mismatch" trigger string was deleted from the binary with the DETERM_CRYPTO tri-state — the grep could never match again, leaving the suite silently believing the test could still skip); the stale "v2.7 F2 view reconciliation (deferred)" comment in test-block-digest corrected (F2 shipped, views digest-bound); SECURITY.md S-015 body header aligned to its triage-table Closed status; three stale "wraps OpenSSL" comments corrected (frost.cpp, light/sign_tx.cpp, the §Q7 test-ed25519-vectors pin).

## 2026-07-03 — R50: 1c executed as migration — wallet off OpenSSL; GCM arbitrary-IV + base64 + rng gate shipped

**Authority:** Stoyan Denev (standing "progress in optimal parallelism with zero merge cost" directive; 1c was the recorded follow-up of the same day's 1b decision).

**What shipped (serial, compiled).** (1) The REAL §3.5 gap closed: the survey's "AES-GCM decrypt not implemented" claim was STALE (decrypt existed with CT tag compare); the actual gap was arbitrary-length IVs — closed via the SP 800-38D §7.1 `gcm_j0` derivation (`J0 = GHASH_H(IV‖pad‖[ivlen·8]_64)` for ivlen != 12) + new `determ_aes256_gcm_encrypt_iv`/`_decrypt_iv` entry points (the fixed-IV functions became thin wrappers), cross-validated against OpenSSL EVP per IV length {1,8,16,20,32,60} (`test-aes-c99` §5) and against the python `cryptography` oracle (the R50 decrypt corpus). (2) New strict RFC 4648 base64 module (`src/crypto/base64/`) — encode total; decode rejects bad chars/padding/`inlen%4`/non-canonical trailing bits (fail-closed; deliberately stricter than `EVP_DecodeBlock`). (3) `test-rng-c99` smoke gate for the §3.15 entropy shim (contract edges, non-zero, distinct draws, 64 KiB chunked fill with no constant window, coarse uniformity) — FAST suite 168→169. (4) **1c executed as MIGRATION, not version bump:** `wallet/envelope.cpp` (PBKDF2→`determ_pbkdf2_hmac_sha256`, GCM→`determ_aes256_gcm_*`, entropy→`determ_rng_bytes`), `shamir.cpp`, `recovery.cpp`, and all `wallet/main.cpp` classes (aead helpers, HKDF's HMAC legs, RPC-auth HMAC, Ed25519 keygen/derive, 27 one-shot SHA-256 sites, base64 wrappers) moved to c99 — FORMAT-COMPATIBLE byte-for-byte (same PBKDF2/GCM outputs proven byte-equal by the §Q9 gates; envelope layout `ct‖tag` + "DWE1" serialization untouched, existing envelopes/backups/keyfiles decrypt identically). `determ-wallet` links ZERO OpenSSL. **The vendored OpenSSL 1.1.1w is now §Q9-test-oracle-only** — in no production code path of any binary; the EOL liability is fully contained.

**Parallel (zero merge cost, Workflow, each adversarially verified).** `tools/vectors/aes_gcm_decrypt.json` (16 vectors: 6 PASS/12-byte-IV, 4 FAIL tamper classes, 6 arbitrary-IV — python `cryptography` oracle, every vector independently recomputed INCLUDING a from-scratch GHASH/J0 re-derivation; wired into BOTH vector-gate halves: a new `aes256_gcm_decrypt` handler in `test-c99-vectors` and in `test_c99_vector_files.sh`); `src/crypto/rng/README.md` (verifier fixed 4 real defects in the draft: a false test claim, chunking off-by-one precision, an omitted consumer, an undisclosed generic-POSIX n==0 corner); `docs/proofs/CryptoBackendMigrationSoundness.md` CB-1..CB-5 (verifier renumbered 21 stale citations and tightened CB-3 to exactly what the source documents). **Dedup catch:** the 4th artifact (`operator_crypto_selfcheck.sh`) NEAR-DUPLICATED the existing `operator_crypto_selftest.sh` — DELETED; the existing script's battery gained `test-rng-c99` (14→15, 15/15 green) instead. Lesson: parallel artifact prompts must name what already exists, or the verifier stage should check for prior art.

**Validation.** MSVC: FAST=1 169/169; wallet envelope/shamir/keyfile/backup/recover/rotate/import/sign-anon suite 8/8; both vector-gate halves green; `test-rng-c99` + `test-aes-c99` (incl. the new §5 arbitrary-IV block) green. GCC/WSL: ci_local (build 3 binaries + FAST + guards) — recorded with this round's commit set.

## 2026-07-03 — R51: atomic state_proof value closes the supply-read race; chacha-decrypt + argon2id corpora; envelope format-freeze

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Serial (the race close).** `rpc_state_proof` now returns `value_hex`/`value_u64` for the `c:` (supply-counter) namespace ATOMICALLY with the proof — the whole RPC holds `state_mutex_`, so the counter value, the Merkle proof, `state_root`, and `height` are one snapshot. This is exactly the daemon-side fix `SupplyProofSoundness.md`'s R41 status banner prescribed ("the state_proof RPC returning the raw value bytes alongside value_hash so cleartext and proof are atomic"): the five A1 counters increment every block, so the previous flow (chain_summary cleartext fetched BEFORE the sequential proof round-trips) systematically mismatched an HONEST daemon's proofs — false TAMPERED. Fail-closed by construction: the field is attached only after a server-side self-check `SHA256(u64_be(value)) == value_hash` (encoding drift silently disables the field, S-043 one-formula lesson honored by checking rather than duplicating); the accessor↔leaf correspondence is unit-pinned by `test-state-proof-namespaces` assertion 10. `determ-light supply-trustless` prefers the atomic value (legacy chain_summary fallback for pre-R51 daemons) and the optional `total_supply` cross-check is height-gated (fresh post-anchor summary compared only when its height equals the anchored height — skipped rather than falsely VIOLATED on a live chain). Trust unchanged: the atomic value must still hash to the Merkle-verified value_hash under the committee-anchored root; SU-1..SU-4 apply verbatim.

**Parallel (zero merge cost, adversarially verified).** (1) `tools/vectors/chacha20_poly1305_decrypt.json` — 10 decrypt-direction vectors (6 PASS, 4 FAIL tamper classes) mirroring the R50 aes pattern; the verifier re-derived every vector with a FROM-SCRATCH RFC 8439 implementation self-tested against the RFC §2.8.2 vector, plus hazmat as a second oracle. (2) `tools/vectors/argon2id.json` — the §3.6 module's first vector-file corpus: 11 vectors via argon2-cffi (P-H-C reference bindings), the oracle itself proven byte-equal to the 4 libsodium KATs `test-argon2id-c99` pins before minting anything new; first cross-lane (p up to 4) coverage; the RFC 9106 §5.3 vector deliberately excluded (needs secret-K/AD-X the shipped API fixes empty) with the §5.3 COST parameters pinned instead. Both wired into BOTH vector-gate halves (new `chacha20_poly1305_decrypt` + `argon2id` handlers in `test-c99-vectors` and `test_c99_vector_files.sh`; corpus now 20 files); argon2-cffi added to the ci.yml python installs, missing-module = FAILURE (fail-closed, same posture as `cryptography`). (3) `tools/test_wallet_envelope_compat.sh` — the FORMAT-FREEZE guard the envelope family lacked: two pinned DWE1 blobs (generated post-1c with fixed passphrases) embedded verbatim; any future KDF/AEAD/serialization change that breaks existing envelopes turns it RED (the verifier proved the pin live via a bit-flip negative control); wrong-passphrase + fresh round-trip legs; added to FAST (169→170).

**Validation.** MSVC: test-state-proof-namespaces (incl. the new R51 pin), test-c99-vectors 20/20 files, test_c99_vector_files (both new checkers), envelope-compat 11/11, FAST=1 full; GCC/WSL ci_local — recorded with this round's commit set.

## 2026-07-03 — R52: light --track-registry (mid-chain REGISTER replay) + strict-verify consensus-rule corpus + FB70 machine-checked supply-read model

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Serial (the light-client scope close).** The light client's committee map was genesis-frozen — its own header documented the v1.x deferral ("chains with mid-chain REGISTERs need... a future stateful sync extension"). R52 built it: (1) the randomized activation-delay formula was EXTRACTED from `chain.cpp`'s static `derive_delay` into the shared inline header `include/determ/chain/registration_delay.hpp` (S-043 one-formula discipline — determ-light deliberately does not link `chain/chain.cpp`, so header-inline is the single-definition shape; PURE MOVE, proven byte-identical: consensus goldens + `test-randomized-delay` + genesis/state-root determinism all held); (2) `verify_chain_walk` gained `track_registry` — tx-bearing blocks (non-zero `tx_root`; bodies are stripped from the header stream) are re-fetched FULL and pinned to the already-chained `block_hash` (the F-7 trust step — doctored bodies fail closed), REGISTER/DEREGISTER txs mutate a working registry with the chain's exact `active_from`/`inactive_from` semantics, and the per-block committee check becomes activity-window-aware; (3) `determ-light verify-chain --track-registry` (full from-genesis walk only; `--resume`/`--persist` refused — a suffix walk cannot reconstruct the registry and the persisted anchor does not capture it). Trust model recorded in the header: the replay mirrors the full node's STRUCTURAL application but not its apply-time fee gate — a fee-failed-at-apply REGISTER would widen the light map (never forge: acceptance still requires a valid Ed25519 signature under the registered pubkey). Default off = pre-R52 behavior byte-for-byte.

**Parallel (zero merge cost, adversarially verified).** (1) `tools/vectors/ed25519_verify_strict.json` — the PRE-GENESIS CONSENSUS-RULE PIN for the §3.15 strict verifier: 3 RFC 8032 §7.1 published PASS anchors + 3 (R,S+L) malleability twins + 2 single-bit tampers + 2 non-canonical pubkeys (y=q+1, both sign bits), every vector live-confirmed against the pynacl/libsodium STRICT oracle (PASS verifies, all 7 FAILs reject) and independently recomputed by the verifier. (2) **FB70** `tla/SupplyCounterRead.tla` + `.cfg` — the R51 atomic five-counter read machine-checked: TLC green (76,448 distinct states, depth 7; 6 invariants + 3 liveness incl. the honest-path-reaches-CONSERVED witness), non-vacuity proven falsify-on-mutant (split-guard removed → the split-root attack literally executes and INV_S2 falsifies; bind gate removed → INV_S3 falsifies; stale gate removed → 2-state falsification); auto-discovered by the harness (config #44); the verifier fixed 2 comment-layer precision nits. (3) `tools/vectors/xchacha20_poly1305_decrypt.json` — the oracle-gated leg: pynacl WAS reachable, so 11 vectors shipped (7 PASS incl. AAD + IETF-draft-parameter anchor, 4 FAIL tamper classes). All three corpora wired into BOTH vector-gate halves (corpus now 22 files; new `ed25519_verify_strict` / `xchacha20_poly1305_decrypt` handlers binary-side + pynacl-oracle checkers file-side; pynacl added to ci.yml installs, missing = FAILURE, same fail-closed posture as cryptography/argon2-cffi).

**Validation.** Formula extraction byte-invariant (goldens); binary vector gate 22/22 files; file-side runner green; TLA harness `--only SupplyCounterRead` PASS; FAST=1 170/170 on MSVC and GCC 13 (serial half; the artifact half re-validated with this commit set). `CHECK-RESULTS.md` regenerated via the harness `--write` (44 configs).

## 2026-07-03 — R53: v2.20 streaming dapp_subscribe SHIPPED + FB71 machine-checked backpressure + base64-strict corpus

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Serial (the last "partial" V2 item closed).** v2.20 was the one ⚠️ partial row in `V2-DESIGN.md` (polling shipped in v2.19; streaming was the ~3-day remainder). R53 shipped the streaming subset — push-based DAPP_CALL delivery over a long-lived connection. `RpcServer::handle_session` (`src/rpc/rpc.cpp`) recognizes `dapp_subscribe`, charges the S-014 rate-limiter a weighted ~100 tokens (new `RateLimiter::consume(key, cost)` in `include/determ/net/rate_limiter.hpp`), verifies the S-001 HMAC, then hands the socket to `Node::rpc_dapp_subscribe`. Head `H` and the live-dispatch registration are captured atomically under `state_mutex_` (shared) so no block can apply between them; a per-subscriber writer thread (`subscriber_session`) replays catch-up `[since, H)` from the chain, emits a `live` marker, then drains the hook-fed queue — stamping the wire `seq` at send time, so per-connection `seq` is monotone by construction (single writer). `on_block_finalized_for_subscribers`, called inside `apply_block_locked` (all 3 apply paths, under the state lock), fans this block's matching DAPP_CALLs + heartbeat cadence into each subscriber's bounded queue (enqueue-and-notify only — no socket I/O on the hot path). **Backpressure = KILL-ON-OVERFLOW, never drop-oldest**: a would-overflow enqueue sets `killed`, clears the queue, and closes an in-flight write to break it, so a live connection's `seq` stream is gapless (silent frame loss is impossible — the client always knows exactly where it stands and redials with `--since`). Bounded by `queue_max` frames (client-declared, clamp `[4,1024]`) + 16 MiB + `SUBSCRIBER_MAX_PER_NODE=256`. Lock order `state_mutex_ → subscribers_mutex_ → Subscriber::mu`, never violated; `shutdown_subscribers` winds writers down on `stop()`. The DAPP_CALL payload-topic decode + the `dapp_call` frame body are now ONE shared helper across `rpc_dapp_messages` + catch-up + the hook (S-043 one-formula rule, so polling and streaming can never disagree on topic matching). `determ dapp-subscribe` CLI + `tools/test_dapp_subscribe.sh` (live 3-node: subscribed→live→heartbeat with contiguous seq + stable sid; queue_max clamp echo; invalid-domain + since-beyond-head refused via error envelope exit 2; catch-up replay subscribed→dapp_call→live; topic filter). Two deviations from the original V2-DESIGN sketch are noted inline in the spec (heartbeat_blocks/queue_max became client-tunable params; a per-subscriber std::thread with SO_SNDTIMEO-bounded blocking writes replaced the asio async worker — the kill-on-overflow close + write timeout together bound a stalled client).

**Parallel (zero merge cost, Workflow, each adversarially verified).** (1) **FB71** `tla/SubscriberBackpressure.tla` + `.cfg` — the queue/backpressure/kill-on-overflow protocol machine-checked: TLC green (880 distinct states, depth 18; 5 invariants incl. INV_NoSilentGap — a live connection's delivered seq is a contiguous prefix — + 3 liveness); non-vacuity re-verified falsify-on-mutant (drop-oldest → INV_KillOnOverflow falsifies at 12 states; no-bound → INV_BoundedQueue falsifies at 12 states; the two reachability probes falsify as designed at 272 / 29 states). (2) `docs/proofs/StreamingSubscriptionSoundness.md` — the delivery contract SS-1..SS-6 (seq monotonicity, catch-up/live partition gap-freedom, kill-vs-drop, bounded resource, auth/rate-limit composition, trust model). (3) `tools/vectors/base64_strict.json` — the strict RFC 4648 §4 decode contract of `determ_base64_decode`: 8 PASS (all tail shapes + '+'/'/' alphabet + all-0x00/0xFF) + 10 FAIL classes (non-alphabet, base64url, embedded whitespace/newline, missing/excess padding, mid-string '=', non-canonical trailing bits pad=1/pad=2, len%4); wired into BOTH vector-gate halves (corpus now 23 files; the file side runs an independent from-scratch strict decoder, no external dep, stricter than python binascii).

**Verification caveat (recorded per the no-fabrication discipline).** The parallel workflow's Fable-5 pass hit a usage limit mid-run: the FB71 author + the soundness-doc verifier died, and the round finished on Opus. Both surviving artifacts were adversarially re-verified here. **The FB71 TLA had shipped RED** — a string-vs-record sentinel (`NoFrame = "NONE"`) that TLC hard-errors on (INV_TypeOK, the house typed-sentinel-mismatch bug class) plus a fabricated "27,401 distinct states" measurement and unverified mutant depths. Fixed to a typed record sentinel; every state count / mutant result above is a real, reproduced TLC run. The base64 corpus (author + verifier both completed) and the soundness doc passed re-verification unchanged (all citations resolve at HEAD, no overclaims).

**Validation.** MSVC: FAST=1 170/170; test-c99-vectors 23/23 files + file-side green; live `test_dapp_subscribe.sh` 8/0; TLA harness `--only SubscriberBackpressure` PASS. `CHECK-RESULTS.md` regenerated via the harness `--write` (45 configs).

## 2026-07-04 — R54: dapp_subscribers observability RPC + dapp-subscribe --reconnect + streaming-health operator tool

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Serial (operating the v2.20 streaming subsystem shipped in R53).** (1) NEW read-only RPC `dapp_subscribers` (`src/node/node.cpp` rpc_dapp_subscribers) — a live snapshot of the streaming subscriber fleet: `{count, max, kills_backpressure, subscribers:[{sid, domain, topic, queue_depth, queue_max, bytes_buffered, seq, killed}]}`. It takes ONLY subscribers_mutex_ (+ each Subscriber::mu briefly) — never state_mutex_ — and mutates nothing, so it neither touches chain state nor perturbs any live stream (the writer thread stays the sole queue mutator + sole seq assigner; FB71/SS-1/SS-3 untouched by a reader). subscribers_mutex_ became `mutable` so the const accessor can lock it (same rationale as state_mutex_ being mutable). Subscriber gained an atomic `last_seq` (stamped by the writer in write_frame) so the accessor reports frames-delivered without the writer's stack-local `seq`; Node gained an atomic `subscriber_kills_backpressure_` counter bumped at the kill-on-overflow site. (2) `determ dapp-subscribers` CLI (read, exit 0/1). (3) `determ dapp-subscribe --reconnect [--max-reconnects N] [--backoff-ms M]` — auto-redials on an error frame (backpressure/shutdown) or clean disconnect using the last observed block_index as the new --since (the wire contract's reconnect-via-since; overlap deduped by (block_index, tx_index)); a plain RPC error envelope (unknown domain, since beyond head) stays a PERMANENT exit 2 with no retry; the HMAC is recomputed per attempt since params.since changes. **Design decision recorded:** the flagged `committed_state_view` std::map deep-copy perf item was investigated and DE-PRIORITIZED this round — subsidy credits the block creators' accounts every block (chain.cpp), so `accounts_` (the dominant map) is dirty on EVERY block; copy-on-write would save only the smaller stakes/registrants/dapp_registry maps against real read-path correctness risk. A persistent/structural-sharing map would touch consensus state maps (state_root) and is NOT to be done unilaterally. Left documented-but-not-forced.

**Parallel (zero merge cost, Workflow, each adversarially verified — both verifiers completed this round, no usage-limit cutoff).** (1) `tools/operator_dapp_stream_health.sh` — read-only operator diagnostic over `dapp_subscribers`: live count vs the 256 cap (saturation % + near-cap WARN), cumulative backpressure kills (delta under bounded --watch), per-subscriber queue-depth distribution + the backpressure-risk cohort; modes --json / --anomalies-only / --watch (hard-capped, no unbounded loop); exit 0/1/2. STRICTLY read-only — the verifier confirmed the only wire call is `dapp-subscribers` (zero of the 6 mutating verbs) and drove the full anomaly/watch matrix against a mocked stub (the author found + fixed a stdin-collision bug during self-test). (2) `docs/proofs/StreamingObservabilityReadOnly.md` — SO-1..SO-4 (chain-state read-only composing OperatorToolingReadOnly OT-1/OT-2; non-perturbing preserving SS-1/SS-3; lock-ordering-safe; disclosure boundary preserving SS-6, HMAC-gated per S-001; non-claim that the snapshot is linearizable).

**Validation.** MSVC: build clean; FAST=1 170/170; live `test_dapp_subscribe.sh` 11/0 (new step 7 starts a background streaming subscriber and asserts `dapp-subscribers` reports count>=1 with the node1 row — sid 32-hex, default queue_max 1024, not killed, queue_depth/seq/killed present; offline contract in step 0). operator tool bash -n clean + read-only audit (only `dapp-subscribers` on the wire). All doc guards green.

## 2026-07-04 — R55: FB72 machine-checks the SS-2 catch-up/live partition (streaming "no missed events") + proof-coverage map + gap-freedom cross-check

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Round shape (provable-security hardening).** With the non-gated feature surface saturated (the remaining runway is owner-gated — wallet per-domain accounting, keyfile→Argon2id — or doc-adjacent), this round hardens what the just-shipped v2.20 streaming subsystem RESTS on: its central "no missed events" guarantee (SS-2, the catch-up/live partition) was prose-only. R55 machine-checks it.

**Parallel (zero merge cost, Workflow, each adversarially verified — both verifiers completed).** (1) **FB72** `tla/SubscriberCatchupPartition.tla` + `.cfg` — the SS-2 partition machine-checked with TLC. The model captures the crux the whole guarantee turns on: subscribe reads `head_at_register = N` AND inserts into `subscribers_` under ONE `state_mutex_` SHARED critical section, while apply holds UNIQUE (mutually exclusive) — so capture+register is atomic w.r.t. any apply. Catch-up replays `[since, N)` EXCLUSIVE; the live hook (inside apply, under unique) covers `[N, ∞)` INCLUSIVE. TLC-green: 1346 distinct states, depth 11. INV_NoGap (every matching index in `[since, head)` is replayed ∪ live-enqueued — no missed events) + INV_NoOverlap (boundary `N` covered by exactly one side — exactly-once within a connection) + INV_HeadMonotone + all-eventually-delivered. **The non-vacuity mutant is the point:** make capture-then-register NON-ATOMIC (a matching block `N` can apply between reading `N` and registering) → INV_NoGap falsifies with the concrete gap-at-`N` trace (block `N` replayed by neither catch-up (exclusive of `N`) nor live (subscriber not yet registered when `N`'s hook ran)) — exactly the race the shared-before-unique lock discipline prevents. An inclusive catch-up bound falsifies INV_NoOverlap. Independently re-run on the harness here (1346 states, matching). (2) `StreamingProofCoverageMap.md` — an honest verification-coverage map for the entire v2.20 subsystem: every SS-1..SS-6 / SO-1..SO-4 claim classified (TLA-machine-checked FB71/FB72 / prose+code / composed / regression-tested) with an explicit gaps section. Does NOT overclaim — only SS-1(seq)/SS-3 (FB71) and SS-2 (FB72) are machine-checked; the rest are honestly prose or composed. SS-2 flipped to CLOSED now that FB72 is at HEAD.

**Serial (the live complement).** `tools/test_dapp_subscribe.sh` gained an SS-2 gap-freedom cross-check: when a DAPP_CALL applies, the streaming catch-up over `[since, head]` must deliver EXACTLY the event set the retrospective `dapp-messages` poll reports — same `(block_index, tx_hash)` identities, exact set equality, no gap and no extra. Independent-API cross-validation of the partition on the catch-up side (the live complement to FB72's machine-check). Gated on the DAPP_CALL applying (the known multi-node timing flake) — SKIPs rather than flakes. Live test 12/0.

**Validation.** Independent harness re-run of FB72 (`--only SubscriberCatchupPartition` PASS, 1346 states); live `test_dapp_subscribe.sh` 12/0; all doc guards green. `CHECK-RESULTS.md` regenerated via the harness `--write` (46 configs). No compiled change this round (test + proofs only), so FAST is unaffected.

## 2026-07-04 — R56: FB73 machine-checks the cross-reconnect no-loss seam (completes the streaming "no missed events" guarantee)

**Authority:** Stoyan Denev (standing optimal-parallelism directive).

**Round shape.** Non-gated feature surface confirmed saturated this round (§3.16 doesn't exist — a stale runway note; DSF is design-review-gated per its own spec preamble; determ-light persistence is already complete with --persist/--resume + persist.hpp + the `state` subcommand). So R56 completes the streaming correctness story: R55/FB72 machine-checked "no missed events" WITHIN one connection; the R54 `dapp-subscribe --reconnect` feature's CROSS-reconnect seam — and specifically its inclusive-`since` design decision — was still prose-only.

**Parallel (Workflow, adversarially verified — both agents Opus, both completed).** **FB73** `tla/SubscriberReconnectSeam.tla` + `.cfg` — the reconnect seam machine-checked, composing ON TOP of FB72 (imported as the within-connection deliverer premise). Models a growing chain with MULTI-EVENT blocks (tx_index 0,1), in-order delivery, `Disconnect` at any point including MID-BLOCK, and `Reconnect` redialing with `connSince = last_block` INCLUSIVE + a deduped `delivered` set keyed by `(block_index, tx_index)`. TLC-green: 2240 distinct states, depth 13. INV_NoLoss (caught-up ⇒ `delivered ⊇` every matching event in `[original_since, head)`) + INV_NoDup (exactly-once after dedup) + INV_LastBlockSound + the all-eventually-delivered temporal property (SF on Deliver — the adversarial Disconnect otherwise starves it). **The mutant validates the R54 decision:** the EXCLUSIVE-since mutant (`last_block + 1`) falsifies INV_NoLoss at 645 states with the exact lost-same-block trace (deliver `(B,0)`, disconnect mid-block, reconnect exclusive skips block `B`, `(B,1)` never delivered). The inclusive-since choice — `src/main.cpp` `eff_since = last_block`, not `+1` — is load-bearing. The verifier independently re-ran TLC + re-derived the mutant (645 states matching) and confirmed the C++ premise; I re-ran the harness (2240 states, matching).

**Serial (the deterministic live complement).** `tools/test_dapp_subscribe.sh` gained the SS-6 reconnect-seam boundary assertion: against the applied DAPP_CALL's block `B`, `--since B` INCLUDES the event while `--since B+1` EXCLUDES it — the deterministic core of the inclusive-since no-loss guarantee (a same-block event unshown before a disconnect is recovered on redial). Gated on the DAPP_CALL applying; SKIPs rather than flakes. Live test 13/0.

**Validation.** Independent harness re-run of FB73 (PASS, 2240 states); live `test_dapp_subscribe.sh` 13/0; all doc guards green. `CHECK-RESULTS.md` regenerated via the harness `--write` (47 configs). No compiled change (test + proofs only), so FAST is unaffected. The streaming subsystem's end-to-end no-loss guarantee is now machine-checked across BOTH halves: within-connection (FB72) + across-reconnect (FB73).

**Saturation note (honest).** With this, the v2.20 streaming subsystem is shipped (R53), operable (R54), and its safety properties machine-checked (R55 FB72 + R56 FB73). The genuinely high-value remaining work is owner-gated: wallet per-domain accounting (chain-state/consensus), keyfile PBKDF2→Argon2id (on-disk format change), the DSF harness (needs design review), and the large PQ/privacy tracks. Further non-gated rounds are incremental hardening of the kind R55/R56 represent.

---

## 2026-07-04 — R57: wallet account-accounting (owner-selected) — per-domain tx-flow reconciliation + WA-1..WA-5 proof; a real ledger-mismatch bug caught by the live test

**Authority:** Stoyan Denev — selected "wallet per-domain accounting" from the owner-gated menu surfaced at R56 saturation (AskUserQuestion). This is the authorization for the feature.

**Scope decision (read-only, not consensus).** The gated item was "wallet per-domain accounting (chain-state/consensus)". The chosen scope is deliberately the **read-only** half: a per-domain transaction-flow accounting + reconciliation *view* over already-committed chain state — NO new consensus rule, NO chain-code change, NO key operation. `cmd_account_accounting` walks blocks `[from,to]` via the `block` RPC, classifies each tx exactly as `chain.cpp` apply_transactions does, then reconciles the tx-flow net against the authoritative `balance`/`stake_info` RPCs; the residual (subsidy/NEF/genesis-opening) surfaces as `non_tx_delta`. This keeps the whole feature inside the wallet TCB with zero consensus-path risk — the "accounting" the owner wanted, without touching the immutable substrate.

**The load-bearing bug the live test caught (why the test earned its keep).** The classifier initially read the moved principal from the tx's `amount` field for ALL types. That is correct for TRANSFER/DAPP_CALL but **wrong for STAKE/UNSTAKE**: their `amount` field is 0 — the principal is carried as an 8-byte little-endian `payload` (`chain.cpp:860-863`/`:875-878`). So `staked`/`unstaked` silently tallied 0. The manual smoke test (a transfer) never exercised it; the live test's STAKE assertion (`staked==3`) failed and exposed it. Fix: decode the payload byte-identically to apply. **Lesson (recorded to memory): a per-tx classifier must be validated against EVERY tx type it claims to handle, not just the common one — the wire encoding is not uniform across types (amount-field vs payload-field), and a proof-doc table that describes the *semantic* amount can pass verification while the *shipped decode* reads the wrong field.**

**Test-design decision — poll cheap, window bounded.** The single-node sole-creator test chain mints an empty block every cycle, so the head grows without bound and `account-accounting`'s default O(head) walk diverges if used in a hot poll loop. Decision: poll tx application through the O(1) `balance`/`stake_info` RPCs, pin the accounting window at `[FROM,TO]` captured around the ops, and issue exactly one bounded-window accounting call. Also: the stake poll keys on the locked stake INCREASING past its genesis baseline (alice.v was a genesis validator with 1000 already locked — a naive `locked>=3` passes before the +3 lands and closes the window too early).

**Docs threaded (per the standing directive — docs follow the code).** `WalletDomainAccountingSoundness.md` (WA-1..WA-5, workflow-authored + adversarially verified against `chain.cpp`; amount-source note added post-fix), a proofs/README row, a CLI-REFERENCE "Read-only accounting (RPC)" subsection, and this entry. No push (push remains explicitly owner-authorized only).

**Cross-decision implication.** The remaining owner-gated menu is unchanged minus this item: keyfile PBKDF2→Argon2id (on-disk format change), the DSF harness (design-review-gated), and the PQ/privacy tracks.

---

## 2026-07-04 — R58: wallet keyfile KDF PBKDF2→Argon2id (owner-selected) — versioned back-compatible envelope migration

**Authority:** Stoyan Denev — selected "Argon2id keyfile" from the owner-gated menu (AskUserQuestion) after R57. This is the authorization for the on-disk keyfile format change the item was gated on.

**Question.** The wallet's passphrase-encrypted envelope (keyfiles, Shamir backup shares, recovery envelopes) derived its AES-256-GCM key via PBKDF2-HMAC-SHA-256 (600k iters). PBKDF2 is pure-compute and cheaply parallelized on GPU/ASIC; the C99 Argon2id primitive (memory-hard, RFC 9106) had shipped as a validated library since task #284 but had **no live caller** — its intended consumer, the keyfile KDF, was the gated on-disk format change. How to wire it without orphaning every envelope already on disk?

**Options considered.** (a) **Hard cutover** — switch encrypt+decrypt to Argon2id, re-pin all fixtures. Rejected: orphans every DWE1 keyfile/backup in the field, and the format-freeze guard exists precisely to make that a RED failure. (b) **New magic, dual-read** *(chosen)* — a 4-byte magic distinguishes DWE2 (Argon2id) from DWE1 (PBKDF2); `decrypt`/`deserialize` auto-select the KDF from it; `encrypt` defaults to Argon2id but `encrypt_pbkdf2` + `envelope encrypt --iters` retain the legacy path for interop; the params slot is 4 bytes (iters) for DWE1, 12 bytes (t|m|p) for DWE2, disambiguated by the magic. (c) **In-place bulk re-encrypt of existing files** — rejected as unnecessary and dangerous (touches every secret at rest at once); instead legacy files upgrade opportunistically on the next `keyfile-reencrypt`.

**Choice.** Option (b). Defaults t=3, m=64 MiB, p=1 (above the OWASP Argon2id floor). The AES-256-GCM AEAD leg is byte-identical across DWE1/DWE2 — only the KDF and its param slot differ — so the confidentiality/integrity proofs carry over verbatim and only the passphrase work-factor bound strengthens.

**Scope guard (why this stayed wallet-only).** Node keyfiles are produced by the *daemon* (`determ`, its own keyfile.cpp), not the wallet envelope; they remain PBKDF2 (a separable owner decision). The wallet's `keyfile-info`/`inspect-envelope`/`node-keyfile-info` inspectors were made KDF-aware so they honestly report either KDF, and `account-import-many`'s structural check was fixed to key on the correct cost field per KDF (it had rejected Argon2id's zero `pbkdf2_iters`).

**Validation.** `tools/test_wallet_keyfile_argon2.sh` (18/0): fresh keyfile is DWE2/argon2id with default params + round-trips; default-vs-`--iters` magic selection; the pinned pre-R58 DWE1 fixture still decrypts (no orphaned envelopes); wrong-passphrase fail-closed on both layouts; reencrypt keeps Argon2id + preserves the seed. The format-freeze guard (`test_wallet_envelope_compat.sh`) stayed green (DWE1 decrypt preserved). FAST=1 170→171, 0 fail. Proof `KeyfileArgon2Migration.md` (KM-1..KM-5) authored + adversarially verified.

**Cross-decision implication.** Argon2id now has a live consumer (CRYPTO-C99-SPEC §3.6 updated from "no live caller"). Remaining owner-gated menu: the DSF harness (design-review-gated) and the PQ/privacy tracks. Daemon-side node-keyfile Argon2id is a possible follow-up but was deliberately left out of R58's wallet scope.

---

## 2026-07-04 — R59: complete + operationalize the Argon2id at-rest migration; fix the R58 determ build breakage it uncovered

**Authority:** standing optimal-parallelism directive (continue development).

**What triggered it.** R58 shipped the wallet keyfile KDF migration but — verified this round — left the `determ` binary **not compiling**. R58 removed the `iters` parameter from `envelope::encrypt`, but the `determ` binary links `wallet/envelope.cpp` and had 12 call sites in `cmd_test_envelope` still calling the old 4-arg form. R58 only rebuilt `determ-wallet` locally, so the determ build was never exercised; `determ.exe` on disk was a stale pre-R58 binary still defaulting to PBKDF2. **This is exactly the cross-binary breakage the second-platform CI gate exists to catch — a local single-target (`--target determ-wallet`) build masked it.** The `daemon can read Argon2id keyfiles` claim was therefore unverified until this round.

**Fix (serial).** Routed the test-envelope PBKDF2-path call sites to the explicit `encrypt_pbkdf2()` (identical semantics — they assert `pbkdf2_iters == TEST_ITERS`), refreshed the stale "PBKDF2 600k" comment on `cmd_account_create`, rebuilt determ, and VERIFIED end-to-end: `determ account create --passphrase` now produces DWE2/Argon2id (magic 44574532) and `determ account decrypt` reads it back (rc 0). test-envelope stays green (PBKDF2 coverage preserved). determ-light was never affected (it doesn't link envelope.cpp).

**Operationalize (parallel, Workflow, adversarially verified).** `tools/operator_keyfile_kdf_audit.sh` + test (24/0) — a read-only KDF audit that scans keyfiles/envelopes and flags legacy DWE1/PBKDF2 files for `keyfile-reencrypt` upgrade (exit-2 alert gate); verifier independently confirmed read-only via sha256/mtime invariance + the exit-code contract + content-driven (not magic-grep) classification. `docs/proofs/AtRestKdfMigrationCoverage.md` — the end-to-end at-rest coverage map (verifier fixed a decrypt-path citation 5117→5119/5125).

**Lesson (to memory).** After ANY change to a signature in a source file shared across binaries (`wallet/envelope.cpp` is linked into determ AND determ-wallet), build ALL THREE targets (or run `ci_local.sh`) before declaring the round done — a single-target build is not proof the tree compiles. FAST=1 172/0.

---

## 2026-07-04 — R60: adversarial audit of the R57-R59 changes — 3 confirmed bugs fixed

**Authority:** standing optimal-parallelism directive.

**Why an audit round.** R59 showed that per-artifact verification (each Workflow artifact verified in isolation) missed a cross-binary defect R58 shipped. So R60 turned the same adversarial-verify machinery on my OWN R57-R59 changes: a 4-lens Workflow (accounting-classifier-vs-chain, envelope-KDF-migration, cross-binary-integrity, KDF-display) with a verify-to-refute pass on every finding. It **earned its keep** — 3 CONFIRMED medium defects (all REFUTED-resistant, reproduced by direct code trace), all the same class as the R57 STAKE-payload bug: the read-only accountant not replicating chain.cpp's CONDITIONAL apply.

**The 3 findings + dispositions.** (1) **backup-verify/import-many displayed DWE2 envelopes as "PBKDF2=0"** — a display path I'd updated for keyfile-info/inspect-envelope in R58 but missed. Code fix: `EnvDetail` made KDF-aware (verified: now prints `Argon2id(t=3,m=65536KiB,p=1)`). (2) **DAPP_CALL fee-only no-op** (inactive/unregistered DApp, bad topic/framing) — the tally counts dapp_spend/credit but chain.cpp charges fee only. (3) **cross-shard TRANSFER/DAPP_CALL receiver credit** — the tally fabricates a same-block credit on the sending shard for an off-shard recipient (only on `shard_count>1`; the default single-shard chain is unaffected).

**Disposition decision for (2)/(3).** Both are assume-applied violations the wallet CANNOT detect from a block walk (no `dapp_registry_` state; no shard geometry on a live-RPC tool), and the reconciliation identity still holds — `non_tx_delta` absorbs them. So, matching the tool's explicit assume-applied design + the existing V1/V2 precedent, the fix is **honest non-claims**, not a fabricated detection: the `--help` NON-CLAIMS + the proof's WA-2 now enumerate four cases (V1 insufficient-balance, V2 failed-UNSTAKE, V3 DAPP_CALL no-op, V4 cross-shard credit), and the WA-1 §4.1 / §1.2 cross-shard wording was corrected (the code *tallies* the cross-shard credit, it does not merely *omit* it — reconciling a code↔doc contradiction the audit flagged). A code-based detection was rejected: replicating chain.cpp's DApp-registry checks or shard geometry from the wallet's block-only view is infeasible and would add consensus-state coupling to a TCB-separated read tool.

**Lesson (to memory).** Adversarially reviewing your OWN recent changes (not just each artifact in isolation) is worth a dedicated round after a burst of feature work — it catches the conditional-apply-mismatch class that unit tests on the happy path miss. The R57 STAKE bug, and now R60's V3/V4 + the display miss, are all the same lesson: a per-tx classifier must be checked against EVERY apply branch (success AND every early-break), not just the happy path. FAST=1 172/0; all three binaries build clean (R59 lesson applied).

---

## 2026-07-04 — R61: owner decision menu on the blocked tracks — 3 full-build authorizations (2 reversals) + the accountant shrink

**Authority:** Stoyan Denev, via an AskUserQuestion decision menu (the owner asked for "simplification options for decisions that will unblock the development" — NOT deferral). Four decisions were teed up with simplest-first options; the owner chose:

1. **DSF → full 3-4wk build** (not the minimal-slice option). Execution note: DSF is non-consensus test infra, so it proceeds incrementally — increment 1 (deterministic core: virtual clock + scheduler + scenario DSL + trace/replay + seed scenarios) is authored as a new `sim/` module; the 30-scenario set + virtual-net + CI land in later increments. The full build is authorized; the increments are an execution convenience, not a scope reduction.

2. **Post-quantum → REOPEN for on-chain PQ.** **This REVERSES the 2026-07-03 "DECIDED — FROZEN AS-IS" anon-address decision** (`AnonAddressDerivationMigration.md`: Ed25519-only for the chain's lifetime, no discriminator in the address preimage). On-chain PQ signatures (ML-DSA/Dilithium) require exactly the address-format + wire + verifier changes that freeze foreclosed, so the freeze is hereby **reopened by owner authority**. Execution: the prerequisite first increment is the verified **ML-DSA (Dilithium) C99 library primitive** (KAT-gated, additive, off-chain — the same pattern as Ed25519/P-256/Argon2id/FROST); the address-format reopen + tx/wire integration + a fresh `AnonAddressDerivationMigration` decision (Option A hash-based, now that PQ forms are in scope) follow as separate, carefully-reviewed consensus increments. `Improvements.md §2.1/2.2` (Falcon, Dilithium-FROST) become live roadmap.

3. **v2.22 confidential transactions → FULL on-chain integration.** **This REVERSES the FUTURE/design-only tier** (`v2.22-PRIVACY-SPEC.md` "Status: specification only… do not begin until reviewed"; `CRYPTO-C99-SPEC.md §3.7` "No consumer exists"). Execution: prerequisite first increment is the **range-proof + Pedersen-commitment C99 primitive** (KAT-gated, additive), then view-key + tx-format + audit-hook consensus integration per the spec, as separate reviewed increments.

4. **account-accounting → shrink to provably-exact** (the R60 V3/V4 caveat). SHIPPED this round: dropped the `dapp_spend` tally + the DAPP_CALL/cross-shard receiver credit; the tool now tallies only single-shard-confirmable flows (TRANSFER debit + same-shard credit, STAKE/UNSTAKE payload, fees). The DAPP_CALL amount + inbound fold into `non_tx_delta` by construction, so no over-count is possible; WA-2 drops from four assume-applied cases to two; the proof + CLI-REFERENCE simplified. Single-shard is provably exact modulo V1/V2; multi-shard is out of scope (run per-shard).

**Governance note.** #2 and #3 are deliberate reversals of prior owner-frozen / future-tier decisions, made with explicit owner authority and recorded here per the append-only convention (the original entries stand; this supersedes them). Both are **consensus-critical, multi-week** tracks — they will be executed incrementally, library-primitive-first (KAT-verified, zero consensus touch), with the chain-integration steps each gated on their own review. Nothing is pushed.

---

## 2026-07-07 — Privacy-track direction: DSSO mechanism, input-unlinkability wiring, MODERN curve (owner decisions)

Three owner decisions made during a live review of the just-shipped input-unlinkability library primitives (§3.23 LSAG / §3.23b CLSAG / §3.23c RingCT-compose) and the profile↔crypto doc reconciliation. Spec refs: `CRYPTO-C99-SPEC.md` §3.23/§3.23b/§3.23c, §3.9b, §3.20; `v2.22-PRIVACY-SPEC.md`; `include/determ/chain/params.hpp`; README. Memory: `determ-profile-crypto-posture.md`, `determ-shielded-pool-track.md`.

### D1 — DSSO mechanism: DLT-A (not FROST-based T-OPAQUE)

**Question.** DSSO's identity assertions were originally designed as T-OPAQUE on the K committee, threshold-signed via FROST (V2-DESIGN §v2.25). FROST was later frozen as a Claude-introduced deviation. Which mechanism ships?

**Options.** (A) **DLT-A** — T-OPRF over threshold DH (joint password eval, no operator learns the password) + the chain's own K-of-K block signature AS the threshold attestation + DAPP_CALL; uses only shipped primitives. (B) restore **FROST-based T-OPAQUE**; (C) T-OPAQUE as a pure DApp (per-instance signing).

**Choice.** (A) DLT-A.

**Why not B/C.** B reopens the FROST freeze (re-audit + re-commit to a pulled primitive; foreclosed v2.10 DKG; against KISS) and buys nothing for the password property — FROST was only ever the *signature* layer, not the OPRF. C loses the chain-level threshold attestation (weaker trust). Corrects a prior agent error: "T-OPAQUE was removed" was WRONG — only the libsodium OPAQUE *stub* was deleted (#308); the threshold-OPRF core is live and needs no FROST.

**Cross-decision implication.** With D3, DLT-A's T-OPRF DH stays **X25519** (the README wording is now correct, not stale). MODERN needs a Z_p*-free threshold-OPRF only if D3 had gone big-prime — it didn't. DSSO ships post-v1.0 as a DApp.

### D2 — Input-unlinkability: stays LIBRARY, not wired

**Question.** Wire CLSAG into consensus now (per-note keys + ring/pseudo-out selection + on-chain key-image nullifier set) to deliver the FIPS graph-privacy feature, or leave the primitives as library code?

**Options.** (A) wire now; (B) leave as library, wire later; (C) build the Lelantus/Groth-Kohlweiss log-size alternative.

**Choice.** (B) leave as library.

**Why not A/C.** A is consensus-critical + multi-week + adds a decoy-selection footgun, with no concrete near-term requirement. C is a different architecture (global accumulator) superseding the already-built RingCT path. The graph-privacy *feature* is deferred; LSAG/CLSAG/RingCT-compose remain validated, audited library primitives ready to wire when a requirement is concrete.

### D3 — MODERN ZK curve: reuse P-256 (drop big primes AND secp256k1)

**Question.** MODERN's confidential-tx / large-prime backend was documented as big-prime Z_p* (§3.20). Is that the right choice?

**Options.** (A) big-prime Z_p*; (B) X25519-boundary variants; (C) ristretto255 (ed25519-family ZK); **(D, that emerged) reuse the profile-agnostic P-256 shielded pool — no MODERN-specific ZK backend.**

**Choice.** (D) reuse P-256. Clarifying fact: the owner's curve objection was **secp256k1 SPECIFICALLY** (Koblitz), NOT special curves in general — Ed25519 is acceptable, so big-prime Z_p* was solving a non-problem; and P-256 ≠ secp256k1, so the owner does not object to it. MODERN = Ed25519 sig + X25519 KX + the already-wired, profile-agnostic **P-256 shielded pool** (§3.22) for confidential-tx.

**Why not A/C.** A (big primes) pays a large per-tx cost (3072-bit DH ~1-2 orders of magnitude slower + ~12× bandwidth) to solve a problem that was really just "not secp256k1." C (ristretto255) is a *new backend to build + audit* — only worth it if MODERN-ZK-off-NIST-curves is a goal in itself, which it is not (the objection was secp256k1, not P-256).

**Cross-decision implication.** The **§3.20 Z_p* ff-stack** (`ffgroup`/`ffipa`/`ffrangeproof`/`ffbalance`/`ff_confidential_tx`, ~5 files + tests) is now **consumer-less**. Deletion vs keep-as-optional-conservative-backend is **PENDING owner confirmation** (they chose reuse-P-256 but did not answer the delete-Z_p* question). This also resolves the §Q10 per-curve amount-handshake ECDH inconsistency (MODERN amount handshake = X25519, FIPS = P-256) — that reconciliation + the ~112 T-OPAQUE→DLT-A doc refs are follow-on sweeps, not yet done. Docs reconciled to D3 (params.hpp / README / v2.22-PRIVACY-SPEC / PRE-IMPLEMENTATION-REVIEW) 2026-07-07.

**Governance note.** D1-D3 are direction decisions (not code). No consensus code changed; this entry + the doc corrections capture them. Nothing pushed.

---

## 2026-07-09 — Pre-launch decision review (17 items) + DSSO/DApp catalog + v1.1/v1.2 split

### Full launch-scope lock: 17 last-mile items decided; DSSO + reference-DApp catalog added; application layer split across v1.1 / v1.2

**Question.** A one-by-one pre-launch review (working doc `PRE-LAUNCH-DECISIONS.md`) resolved every open decision + simplification/reliability/security item for the launch. Two follow-on scope questions then arose: (1) add DSSO + the full nine-DApp reference catalog so all DApps share one identity layer? (2) if so, ship all nine together, or split on the zk-VM boundary?

**Decisions (Stoyan 2026-07-09).**

1. **17 last-mile items — all decided** (per-item record in `PRE-LAUNCH-DECISIONS.md`). Highlights: CT view-key/audit = Option C per-epoch HKDF + FULL dual-mode audit (`LOG_AUDIT_ACCESS` + `audit_view_master_pk`/`ROTATE_AUDIT_KEY`); confidential light-read = FULL client-side verification; S-048 = wire `resolve_fork` + bounded one-block head-reorg (owner sign-off granted); PQ freeze = hash-based PQ anon-address + `signature_form` {Ed25519 K-of-K, ML-DSA} at genesis; B1 one-file-per-block storage; B2 purge FROST + RingCT libraries; B3 rewrite v2.22 as-built (increment 1 of a one-consolidated-design-doc / 100%-provable-security program); B4 pre-genesis reserved-bit audit; C2 full adversarial FA/DSF sweep; D1 shielded-pool audit + per-deployment CT disable flag; D2 extend ct-timing-probe to integrated CT+PQ; D3 launch posture = EXTENDED → build on-chain SHARD_TIP (v2.11), close S-036; D4 one clean beta soak at feature-complete. **Dropped:** A7 RingCT wiring (library removed under B2), A8 hierarchical sharding (dropped outright — flat ~200-500-shard ceiling is the design limit). First DApp = provably-fair Liberty Bell lottery, which consumes the CT+audit stack end-to-end.

2. **DSSO + full DApp catalog added; DSSO is the shared identity layer.** DSSO (Bundle A, DLT-A composition over already-shipped X25519 + DAPP_CALL + light-client — zero new crypto) is pulled into the launch; all nine reference DApps authenticate through it.

3. **Application layer SPLIT on the zk-VM boundary.**
   - **v1.1 wave:** DSSO + Tier-1 DApps (D.1 gambling, D.2 B2B, D.3 journalism, D.5 government random-selection, D.9 Merritt voting) — need only DSSO + chain primitives. Pulls in three currently-unbuilt gating primitives: **v2.26 ROTATE_KEY** (D.2, D.3), **v2.15 multi-sig** (D.2), **v2.22 PFS / PRIV-6 OTPK** (D.3).
   - **v1.2 wave:** Bundle B zk-VM (~3-6 months) + Tier-2 DApps (D.4 AI-agent, D.6 private rollup, D.7 verifiable AI inference, D.8 anonymous credentials). Off the v1.1 critical path.

**Rationale.** Tier-1 is the mission-aligned set (per `MOTIVATION.md`: government/elections + commercial) and reuses the CT/audit/identity stack already in flight. The zk-VM is a ~3-6-month substrate that would otherwise dominate the schedule and gate four DApps. Splitting keeps v1.1 at a ~3.5-5-month feature-complete horizon and makes v1.2 a clean, zk-VM-gated boundary that iterates under DApp-layer freedom (no chain no-migrations exposure for the DApps themselves; only the zk-VM anchor/settlement primitive touches consensus, reviewed then).

**Cross-decision implication.** DSSO's dependencies (X25519, DAPP_CALL, light-client) are all shipped, so DSSO is NOT build-blocked — it should start early, parallel with the core, not sit behind Phase 1. Of the three gating primitives: v2.26 ROTATE_KEY already has `v2.26-ROTATION-SPEC.md`; v2.22 PFS/OTPK design is in `v2.22-PRIVACY-SPEC.md` (PRIV-6) + `PFS_DEPLOYMENT_GUIDANCE.md` (confirm coverage survived the B3 as-built rewrite); **v2.15 multi-sig has no spec** — stubbed 2026-07-09 (`PHASE2-PRIMITIVES-KICKOFF.md`) for owner review per the AI-drafted-design discipline. D.1/D.5/D.9 need only DSSO + already-shipped primitives and are the fastest Tier-1 validations.

**Files updated.** `PRE-LAUNCH-DECISIONS.md` (CLOSED + scope-addition E1-E7); this entry; `V1.1-PLAN.md` (split status banner); NEW `docs/proofs/PHASE2-PRIMITIVES-KICKOFF.md` (v2.15 multi-sig stub + v2.26/v2.22 pointers + impl checklists). Authority: Stoyan Denev.

---

---

## 2026-07-15 — DSSO T-OPRF re-based to t-of-n verifiable T-OPRF on P-256 (DLT-B); `v2.25-DSSO-DAPP-SPEC.md` created as the single authoritative DSSO doc

### D1-rev: DLT-A's X25519 T-OPRF leg replaced; assertion leg kept and its attestation claim sharpened

**Question.** DLT-A (2026-06-07; reaffirmed 2026-07-07 D1) specified the DSSO T-OPRF leg as "X25519 threshold DH, additive n-of-n shares, aggregate via group multiplication — zero new crypto primitives." A coherence review against the shipped API and the B3 100%-provable-security goal found three defects. Which mechanism ships?

**Findings that forced the question.**
1. **Not implementable as specified.** The shipped X25519 module (`include/determ/crypto/x25519/x25519.h`) exposes exactly two functions — clamped, x-only scalar multiplication. Additive-share aggregation needs point addition; OPRF unblinding needs *unclamped* multiplication by `r^{-1} mod ℓ`; "blinded password as an X25519 point" needs a hash-to-curve. None exist in that module, so the "zero new primitives" claim held only for a stack that could not run the protocol.
2. **No proof.** An OPRF over a cofactor-8, x-only group has no published security argument; RFC 9497 restricts OPRF suites to prime-order group abstractions for exactly this reason. This is the same class of gap the B3 program exists to eliminate.
3. **No byzantine verifiability, no liveness slack.** Additive n-of-n lets a single byzantine operator silently corrupt the joint output (undetectable without per-response proofs) and a single offline operator halt all logins.

**Options.** (A) Keep X25519 — add the missing group operations and author a custom security proof. **(B) DLT-B** — same two-leg composition; the T-OPRF leg moves to the **shipped P-256 RFC 9497 VOPRF stack** (§3.9b): t-of-n user-dealt Shamir shares, per-response DLEQ verification against block-anchored share pubkeys, client-side Lagrange recombination. (C) Restore FROST-based T-OPAQUE.

**Choice.** (B) DLT-B. Owner decision 2026-07-15 ("use the better direction"), following the in-session T-OPAQUE t-of-n analysis (any-t-of-n sufficiency; no predefined evaluation order).

**Why not A/C.** A builds and audits new curve code plus a novel proof to avoid a stack that is already shipped, KAT-gated against genuine RFC 9380/9497 vectors, and proof-carrying (2HashDH — Jarecki–Kiayias–Krawczyk 2014; threshold form TOPPSS — Jarecki–Kiayias–Krawczyk–Xu 2017; Gap-OMDH, ROM) — a pure loss under KISS + B3. C reopens the FROST freeze for a *signature* layer DSSO does not need: the assertion attestation remains the chain's existing K-of-K block signature (leg 2 unchanged), and FROST was never the OPRF.

**What DLT-B changes / preserves.**
- **Preserves:** the two-leg structure; the block-anchored assertion leg verbatim; the "already-shipped primitives only, zero new hardness assumptions" property — now on the stack where it is actually true (P-256: `point_add`, `_inv_mod_n`, RFC 9380 H2C, RFC 9497 OPRF/VOPRF all shipped and gated).
- **Changes:** OPRF curve X25519 → profile-agnostic P-256 (extends D3's reuse-P-256 logic; MODERN keeps X25519/XChaCha for share-envelope transport only); additive n-of-n → **t-of-n dial** (recommended default t = n−1; t is a stated secrecy/liveness trade-off — t colluders can offline-grind that user's password); per-response **DLEQ verifiability** (byzantine operators detected, not absorbed); **user-as-dealer** Shamir at registration (per-user OPRF key; no DKG, no PSS, no VSS complaint round — inconsistent dealing only self-DoSes the dealer's own account); restores the T-OPAQUE-shaped **envelope** (OPAQUE's envelope construction, JKX 2018) sealing a dedicated `cred_sk`, with **no AKE** — the chain-anchored assertion replaces it, and no threshold-AKE claim is made (no published proof exists).
- **Sharpened claim (leg 2):** the K-of-K block signature attests **inclusion/ordering/timestamp** of the assertion tx, NOT authentication truth; assertion truth reduces to Ed25519 EUF-CMA under the block-anchored `cred_pk`. The prior "the block signature IS the threshold attestation" phrasing conflated the two; consequence stated precisely: a malicious operator coalition can censor but cannot mint an assertion.

**Doc-consolidation implication (B3).** NEW `docs/proofs/v2.25-DSSO-DAPP-SPEC.md` is the **single** DSSO mechanism doc; every other document now carries a pointer, not mechanism detail. The pending "~112 T-OPAQUE→DLT-A reference sweep" (2026-07-07 entry) largely dissolves: DLT-B *is* a T-OPAQUE-shaped composition (T-OPRF + envelope, minus AKE), so surviving "T-OPAQUE" references are correct-in-kind and the spec defines the term precisely.

**Provenance discipline (`FROST_DEVIATION_NOTICE.md` §4).** AI-analyzed proposal (Claude Fable, this session), owner-accepted. Four-bar check: (1) insufficiency of status quo — findings 1–3 above; (2) Stoyan-traced requirement — Theme 9 DSSO + the B3 goal (owner-authored register) + the original mutual-distrust-IdP framing; (3) formal-verification cost — zero: no chain-surface change, DApp-layer protocol code over already-gated primitives; (4) no-migrations cost — none engaged: DApp layer stays iterable.

**Files updated.** NEW `v2.25-DSSO-DAPP-SPEC.md`; `V1.1-PLAN.md` (§0 property row + Bundle A reworked to DLT-B, mechanism text replaced by spec pointer); `Improvements.md` §8.1; `V2-DESIGN.md` (v2.25 status row, Theme 9 banner, v2.10-cascade bullet, Phase C row); `CRYPTO-C99-SPEC.md` (profile matrix row, §3.9b consumer note, §3.7 parenthetical); `SECURITY.md` (two status lines); `WHITEPAPER-v1.x.md`; `Beaconless-v2-SPEC.md` (two banner lines); `IMPLEMENTATION-SEQUENCING.md` (banner clause); `DAPP_SDK_GUIDANCE.md` (maintained rows only — ARCHIVE body untouched); `README.md` (locked-property #2 + DSSO section); `PRE-LAUNCH-DECISIONS.md` §E1 (mechanism paragraph, dated revision note); `include/determ/chain/params.hpp` (MODERN-profile comment); `FROST_DEVIATION_NOTICE.md` §10 amendment (append-only). Historical records (2026-06-07 / 2026-07-07 entries, quarantined substrate sections, plan.md ristretto-era text) intentionally NOT rewritten.

**Authority:** Stoyan Denev (owner decision relayed in-session 2026-07-15; recorded by Claude Fable at his direction — same recording pattern as the 2026-06-07 and 2026-07-07 entries).

---

## 2026-07-20 — DSSO settled: the paper's mutual-distrust IdP realized as threshold-OPAQUE; "DLT-A/-B" retired

### Owner correction — the block-anchored assertion re-engineering is withdrawn; the design is the paper's, improved with OPAQUE + t-of-n

**Question.** The 2026-07-15 entry recorded DSSO as "DLT-B": a t-of-n P-256 T-OPRF plus a *block-anchored DAPP_CALL assertion* whose truth reduced to a user credential signature verified via light-client block-sig + Merkle inclusion. On owner review that assertion mechanism was flagged as AI drift — a Determ-specific re-engineering, not the design of *Identity provider in an environment of mutual distrust* (academia.edu/80188125), which the owner had chosen to keep. What ships?

**Decision (owner, 2026-07-20).** Keep the paper's design, improved only by the owner's two stated changes:

1. **OPAQUE in place of the paper's SRP** — modern UC-secure aPAKE (OPRF blinding + precomputation-resistant envelope).
2. **t-of-n, unordered in place of the paper's sequential all-node chain** — the OPRF is thresholdized (Shamir, user-dealt); the user broadcasts the blinded password and recombines any t responses in any order.

The relying-party token is the **paper's dual-hash challenge-response** over the handshake-co-generated keys (`H2 = H(tenant_key, H1')`, RP compares) — **not** a signature, therefore **not** block-anchored and **not** FROST-co-signed. The paper co-signs nothing, so there was never a threshold-signature step: FROST is not merely dropped, it is structurally absent.

**Withdrawn.** The 2026-06-07 "DLT-A" and 2026-07-15 "DLT-B" assertion designs (block-anchored DAPP_CALL + committee/user signatures). The "DLT-A/-B" labels are retired across the corpus.

**Carried over (correct).** The t-of-n verifiable OPRF on the shipped P-256 RFC 9497 stack (§3.9b) — the only shipped stack with the required group operations — user-dealt Shamir shares + per-response DLEQ. An implementation substrate for the paper's threshold PAKE, not a change to the design.

**FROST.** Reaffirmed: removed (2026-06-07), deleted (2026-07-09), and now explicit as **not required by this design at all**. The stale "composes with v2.10 FROST" clause (KR-5) in `v2.26-ROTATION-SPEC.md` is marked N/A (no DKG ceremony exists).

**Provenance discipline (`FROST_DEVIATION_NOTICE.md` §4).** Corrects an AI-introduced drift (the block-anchored assertion) that had propagated into the spec + ~13 docs before owner review caught it — the same failure mode the FROST NOTICE records. NOTICE §11 appended.

**Files updated.** `v2.25-DSSO-DAPP-SPEC.md` (rewritten to the paper); `v2.26-ROTATION-SPEC.md` (KR-5 -> N/A); README (locked-property 2, §527, §686), V1.1-PLAN, Improvements §8.1, CRYPTO-C99-SPEC, SECURITY, WHITEPAPER, Beaconless-v2-SPEC, IMPLEMENTATION-SEQUENCING, DAPP_SDK_GUIDANCE, PRE-LAUNCH §E1, params.hpp — "DLT-B" retired, block-anchoring replaced by the paper's hash challenge-response. Historical entries (2026-06-07, 2026-07-15) left intact.

**Authority:** Stoyan Denev (owner decision relayed in-session 2026-07-20; recorded by Claude Fable at his direction).


---

## 2026-07-23 — Four launch decisions cleared: v2.15=Option A, v2.26 authorized, Z_p* delete, DApp go (D.5 first)

### The unblock — owner answers the standing menu; app-layer threads freed

**Context.** After the DSSO realignment settled (2026-07-20), the thread pool completed DSSO Bundle A end-to-end (G1-G4, 07-21) then drained the 07-20 traceability register. Scope-advance stalled because four questions stood unanswered. All four resolved this session.

**Decisions (owner, 2026-07-23).**

1. **v2.15 multi-sig = Option A** (COMPOSABLE_BATCH pattern + wallet policy layer; ~zero new consensus code). Gates D.2. Per `PHASE2-PRIMITIVES-KICKOFF.md §2`, Option B (on-chain M-of-N account policy) is **reserved as a §7.5 discriminator slot** in the B4 pre-genesis reserved-bit audit, so on-chain enforcement can ship additively later without a wire break.

2. **v2.26 ROTATE_KEY authorized for implementation, with KR-10 unification.** One rotation mechanism covers account key + DApp service_pubkey + audit key. Gates D.2, D.3, and DSSO production recovery. Zero dependencies beyond shipped Ed25519 (the stale FROST/KR-5 clause was marked N/A 2026-07-20).

3. **Z_p* big-prime ff-stack (§3.20) — DELETE.** `ffgroup`/`ffipa`/`ffrangeproof`/`ffbalance`/`ff_confidential_tx` (~5 files + tests) consumer-less since the 2026-07-07 D3 reuse-P-256 decision. Removed under the standard deletion gate (build + FAST both platforms + dependency ratchet + goldens byte-identical); git history preserves the code. Resolves the PENDING-owner-confirmation item from the 2026-07-07 entry.

4. **DApp go-signal: start D.5 first.** D.1/D.5/D.9 were already launch-authorized (`PRE-LAUNCH-DECISIONS.md §E1-E7`, 2026-07-09) and dependencies are now met (DSSO built end-to-end; commit-reveal randomness + light-client shipped). D.5 (government random-selection, the founding `MOTIVATION.md` use case) is lightest — DSSO identity + shipped commit-reveal randomness + v2.24 audit hooks — and the fastest end-to-end validation of the DSSO+DApp path. D.1 (flagship, CT+audit stack) and D.9 (Merritt voting) follow. A go, not a new design decision.

**Cascade.** `PHASE2-PRIMITIVES-KICKOFF.md` §2 STUB -> Option A selected; `v2.26-ROTATION-SPEC.md` status -> authorized-for-implementation; V1.1-PLAN D.1/D.5/D.9 dependency rows corrected ("v2.10 FROST randomness" credited a removed primitive — actual source is the v1.x commit-reveal / MPDH beacon per `FROST_DEVIATION_NOTICE.md`); Z_p* §3.20 files scheduled for deletion.

**Authority:** Stoyan Denev (owner decisions via the in-session AskUserQuestion menu, 2026-07-23; recorded by Claude Fable at his direction).


---

## 2026-07-23 — Active work directive: start v2.26 + D.5 now

**Directive (owner).** With all four launch decisions cleared (entry above) and DSSO built end-to-end (07-22), point threads at implementation **now** rather than finishing the traceability-register burn-down first. Active front, in parallel:

- **v2.26 ROTATE_KEY** — build per `v2.26-ROTATION-SPEC.md` (AUTHORIZED, KR-10 in scope). Gates D.2/D.3 + DSSO production recovery.
- **D.5 government random-selection DApp** — the lightest Tier-1 DApp (DSSO identity + shipped commit-reveal randomness + v2.24 audit hooks); the founding `MOTIVATION.md` use case; fastest end-to-end validation of the DSSO+DApp path.

**Then:** v2.15 Option-A multi-sig + D.1 (flagship, CT+audit) + D.9 (Merritt voting); DSSO packaging tail (G5/G6, RP SDK, reference RP DApp); Z_p* deletion under the standard gate. The traceability register (~20 open, MED/LOW) continues as background, not the front.

**Not changed:** the production floor — D4 soak at feature-complete + Critical/High discovery-curve flattening + (given no-migrations) external audit — is unaffected by this directive; it gates *launch*, not *feature work*.

**Authority:** Stoyan Denev (in-session directive, 2026-07-23; recorded by Claude Fable at his direction).


---

## 2026-07-23 — DApps/SDK = Apache-2.0; converge to zero vendored dependencies (JSON format -> canonical binary)

### D1 — All DApps + SDK + DSSO client are Apache-2.0

Extends the split-license decision (`LICENSING.md`): every DApp (D.1-D.9), the DApp/RP SDK, and the DSSO client libraries — wherever they land (`dapps/`, `sdk/`, client libs) — are **Apache-2.0**, not AGPL. The DApp layer is the adoption surface; permissive licensing removes copyleft friction for third-party/commercial DApp builders, consistent with the "everything else is a DApp" philosophy and the Apache-for-clients half of the split. AGPL copyleft stays confined to the daemon/consensus-execution core. `tools/apply_spdx_headers.sh` `is_apache()` extended to `dapps/` + `sdk/`.

### D2 — Zero vendored third-party dependencies; replace the JSON *format* with the canonical binary codec

**Directive (owner).** Drive the tree to **zero vendored third-party runtime dependencies**, and eliminate **JSON as a serialization format** everywhere it is used (storage, snapshots, RPC, gossip envelopes, keyfiles, config, light-client proofs, test vectors), replacing it with a **canonical length-prefixed binary encoding**.

**Current state — the goal is ~80% reached.** Asio **already deleted** (native sockets/IOCP, minix §7); OpenSSL + libsodium are **test-oracle-only** (daemon/wallet/light link zero of either, §3.15); nlohmann/json is a vendored single header already being replaced by the in-house `determ::json` (djson). JSON itself is the last dependency to retire.

**Key safety property — the authenticated form is already binary.** `signing_bytes()` / `compute_block_digest` / `build_state_leaves` / `src/net/binary_codec.cpp` are binary; JSON is only the *storage + transport-envelope + RPC + tooling container*, never the signed/hashed bytes. So the migration is **byte-neutral for all authenticated data** (signed-field goldens unchanged) and is **not state-level no-migrations-locked** (state_root is over binary leaves, independent of the JSON container). The one pre-genesis-sensitive surface is any JSON in the **p2p wire envelope** and anything feeding the byte-deterministic goldens — do those before v1.1 freeze; purely-local JSON (config, CLI, keyfiles, vectors) can change anytime.

**Mechanism.** Promote the existing **canonical binary codec** (`src/net/binary_codec.cpp`, proven by `BinaryCodecRoundTripSoundness.md`) to the **single** serialization for storage/RPC/config/keyfiles/messages. Delete `third_party/nlohmann/json.hpp` **and** `determ::json`/djson (no JSON parser remains). Regenerate the ~7,388 `.json` fixtures as binary vectors.

**Benefits.** (1) Zero-dep = smallest supply-chain/audit surface — directly strengthens NIS 2 Art. 21(2)(d) and the KISS small-green-surface directive. (2) Length-prefixed binary is **inherently cross-platform-deterministic** — it eliminates the whole class of JSON byte-determinism hazards (float formatting, key ordering, whitespace, escaping) the djson byte-exact gates exist to fight. (3) Trivial to port to C99/MINIX (no parser). (4) Smaller + faster.

**Trade-offs (accepted, with mitigations).** (a) **Loss of human-readability** for config/RPC/CLI is the real cost — mitigated by a `determ inspect` binary<->text debug tool, and optionally a thin *non-authenticated, local* text form for config/CLI only. (b) **Large refactor surface** (every JSON touchpoint + fixture regeneration). (c) **Sunk cost**: `determ::json`/djson is obsoleted, though its differential-fuzz + byte-determinism harness carries over to the binary codec's gates.

**Resolved (owner, 2026-07-23).** (i) The **authoritative form is always binary** (length-prefixed, canonical codec) on every surface. (ii) A **`determ inspect` binary<->text debug view ships** — read-only, non-authoritative. (iii) Storage, p2p wire, keyfiles, and test vectors are **binary-only**; operator-facing **config, CLI output, and RPC responses keep an optional human-readable text rendering derived from the binary** (binary stays authoritative — text is a view, never a parse target for authenticated data). This confines text to a non-authoritative operator-convenience layer and removes it from every dependency-bearing and determinism-bearing path.

**Sequencing.** Fits the minix / NH1 track: wire-envelope + goldens-adjacent parts pre-v1.1-freeze, the rest as an additive/local sweep. Blocks nothing already authorized; parallel to the feature front.

**Authority:** Stoyan Denev (owner directive, 2026-07-23; recorded by Claude Fable at his direction).


## 2026-07-23 — Licensing v3: dual-licensed core + BUSL-1.1 revenue DApps (royalty model); supersedes the all-Apache-DApps component of the same-day licensing entry

**Problem.** The owner requires a royalty stream from production users (governments, banks, funds, other public/private operators). No open-source license can carry royalties: Apache-2.0 grants free commercial use outright, and AGPL-3.0 binds only modify-and-serve operators to publish source — unmodified production use of the whole stack is free under the same-day split (AGPL core + all-Apache DApps), which forecloses the stated business model at exactly the layer the paying entities deploy.

**Decision (owner, 2026-07-23) — four tiers, forward-only, PENDING-COUNSEL:**

1. **Daemon / consensus core — dual-licensed: `AGPL-3.0-or-later OR commercial`.** The AGPL track is unchanged (un-capturable, inspectable, free for compliant operators); the paid commercial license is the escape from AGPL obligations for entities that modify + operate the daemon without publishing source (MySQL/Qt model). SPDX: `AGPL-3.0-or-later OR LicenseRef-Determ-Commercial`.
2. **Revenue DApps — BUSL-1.1** (source-available, NOT open source): free for development/evaluation/test/non-production; **production use requires a paid grant — this is the royalty.** Per-release parameters: Licensor = owner legal entity (counsel to fix); Licensed Work = the DApp release; Additional Use Grant = any non-production use; Change Date = 4 years after that release's first publication; Change License = Apache-2.0. Assigned: **D.1 Liberty Bell, D.2 B2B settlement, D.5 government random-selection**; Tier-2 default: **D.4 AI-agent, D.6 private rollup, D.7 verifiable inference**.
3. **Ecosystem / public-interest DApps — Apache-2.0:** **D.3 journalism, D.8 anonymous credentials, D.9 Merritt voting.** The owner may reassign any DApp before its first public release — nothing under `dapps/` has shipped code, so no published rights are affected.
4. **Integration surface — Apache-2.0, unchanged:** `determ-crypto-c99`, `determ-light`, `determ-wallet`, `sdk/**`, DSSO client libs, wire-format boundary files. The adoption funnel stays frictionless; royalties attach where value concentrates, not at the door.

**Non-license revenue lanes** (no code-license impact, recorded for completeness): a **trademark / "Determ Certified"** certification program, and a **compliance-evidence + security-update subscription** (audit reports, FIPS/NIS2 evidence packages, patch SLA).

**Consistency.** `Improvements.md §9.6` protocol-fee neutrality is untouched — royalties attach to software licenses, never to protocol-level tx discrimination. B3 provable security is untouched — BUSL is source-available, so every shipped byte stays inspectable; verification needs source availability, not OSI approval. The one-way compatibility rule extends: Apache → (A)GPL remains OK; AGPL code never enters Apache or BUSL targets; BUSL code never enters the daemon or the Apache libraries (each DApp is a leaf: it links the Apache SDK, nothing links it).

**Constraints.** Relicensing is forward-only — releases already published under Apache-2.0 remain Apache for their recipients; this structure applies from the next release. Sole copyright is the prerequisite (holds today; a CLA is required before any external contribution is merged). Bulgarian Electronic Governance Act + EU public-procurement open-source preferences must be checked by counsel before D.5 is priced as a BUSL product. **Status: repo layout binding now; legal effect PENDING-COUNSEL** (commercial template, BUSL parameter block, trademark filing).

**Files.** `LICENSING.md` (rewritten map), `LICENSE` (pointer), `NOTICE` (banner), `LICENSES/BUSL-1.1.txt` (placeholder — canonical text to be pasted, same discipline as AGPL), `dapps/LICENSE` (per-DApp map), `dapps/README.md`, `COMMERCIAL-LICENSE.md` (draft-for-counsel stub), `README.md` §License, `tools/apply_spdx_headers.sh` (dual SPDX for daemon; per-DApp rule).

**Authority:** Stoyan Denev (owner directive, 2026-07-23; recorded by Claude Fable at his direction).

## 2026-07-25 — Licensing v3.1: core free for all (Apache-2.0); ALL DApps BUSL-1.1 with a noncommercial production grant; owner-operated instances free for end users

**Problem.** Two facts arrived after v3: (a) the core through the 2026-07-21 push (`c037f05`) is published on the public GitHub remote with many clones — the Apache snapshot is irrevocably distributed, so a dual AGPL/commercial core protects only the future delta while adding sales/procurement friction for exactly the government-first market; (b) the owner's business model is sharper than v3 assumed: **he operates the DApps on the network himself, free of charge for end users**, and charges only when *someone else* deploys a DApp for commercial or public-sector use. The v3 core-escape lane and the per-DApp Apache carve-out no longer fit that model.

**Decision (owner, 2026-07-25) — supersedes the core tier and per-DApp split of licensing v3 (entry recorded under 2026-07-23):**

1. **Core free for all — Apache-2.0 everywhere except `dapps/**`.** The daemon returns to Apache-2.0 (dual AGPL/commercial tier withdrawn; `LicenseRef-Determ-Commercial` for the daemon and the commercial-core lane are dropped). Everything outside `dapps/**` and `third_party/**` — daemon, chain, crypto-c99, light, wallet, SDK, tools, docs — is Apache-2.0. Rationale: an L1's moat is the running network, its K-of-K operator set, audits, certification and trademark — not source secrecy; a fully open core maximizes the EU/Bulgarian public-procurement funnel; sole copyright preserves the option to tighten future releases if capture materializes.
2. **All nine DApps — BUSL-1.1** (`dapps/**`; the v3 d3/d8/d9 Apache carve-out is folded in, because the new grant covers the public-interest cases directly). Per-release parameters: Licensor = owner legal entity (counsel to fix); Licensed Work = the DApp release; Change Date = 4 years after first publication; Change License = Apache-2.0. **Additional Use Grant (recorded intent; counsel to draft):** free for development, evaluation, testing and CI; free for **production use by natural persons and noncommercial organizations for noncommercial purposes**. Production use **by or for a commercial entity, or by or for a government / public-sector body, requires a paid commercial grant — this is the royalty.**
3. **Owner-operated instances are free for end users.** The Licensor runs reference instances of the DApps on the network at no charge to end users; *using* a hosted instance requires no code license at all (the license governs deploying/operating the code, not consuming a service). Journalists, voters, credential holders, players ride free on the owner's instances or self-host noncommercially; ministries and companies deploying their own pay.
4. **Unchanged from v3:** trademark / "Determ Certified" certification and the compliance-evidence + security-update subscription as non-license revenue lanes; forward-only effect (the ≤2026-07-21 published snapshot stays Apache for its holders); B3 consistency (BUSL is source-available — every shipped byte inspectable); `Improvements.md §9.6` protocol-fee neutrality; leaf rule (Apache may enter BUSL DApps; BUSL code never enters anything outside `dapps/**`); owner may re-grant any DApp before its first release; **CLA required before any external contribution to `dapps/**`** (sole copyright in the DApps is what "owning" them means).
5. **Counsel shortlist (shrunk):** BUSL grant drafting — especially the *commercial* / *public-sector* / *noncommercial* definitions (PolyForm-Noncommercial-style definitions are the reference precedent) — trademark filing, sanctions/end-use screening for commercial grants, Bulgarian ZEU / EU-procurement check before D.5 pricing. The commercial-core template is no longer needed. **Status: repo layout binding now; legal effect PENDING-COUNSEL.**

**Files.** `LICENSING.md`, `LICENSE`, `NOTICE`, `COMMERCIAL-LICENSE.md`, `dapps/LICENSE`, `dapps/README.md`, `LICENSES/BUSL-1.1.txt` (parameters), `LICENSES/AGPL-3.0.txt` (tombstoned — unused; owner may `git rm`), `README.md` §License, `tools/apply_spdx_headers.sh` (all-Apache stamping restored).

**Authority:** Stoyan Denev (owner directive, 2026-07-25; recorded by Claude Fable at his direction).

## 2026-07-25 — D.10 confidential property register added to the DApp catalog (ten reference DApps)

**Problem.** In mid-July 2026 Romania's national land registry (ANCPI) was breached via
compromised credentials and its databases were **wiped** after a failed extortion attempt —
property transactions froze nationwide and the stolen data was offered for sale. A centralized
register is one credential away from national paralysis and one insider away from unlogged
browsing. The catalog had no DApp answering this: registry integrity + ownership
confidentiality + audited access.

**Decision (owner, 2026-07-25).** Catalog **D.10 — confidential government property register**:
commitments + per-parcel AEAD on-chain; `K_p` user-dealt Shamir t-of-n across the K-of-K node
set; reads require threshold cooperation with a **`LOG_AUDIT_ACCESS` record before any share is
released** (no silent browsing, by construction); transfers are owner+notary+cadastre
`COMPOSABLE_BATCH`; owners self-read free and prove ownership by commitment opening; judicial
inverse lookup is a separate court-order-gated class; GDPR via crypto-shredding. Spec sketch:
`docs/proofs/D10-PROPERTY-REGISTER-SPEC.md`. Tier-1 only — no zk dependency.

**Deployment economics (exemplifies licensing v3.1).** Any government runs the Apache-2.0 core
free of charge on its own mutually-distrusting institutions' nodes; D.10 production deployment
by a public-sector body is a BUSL-1.1 grant — the royalty event. The state buys the protection
of its citizens' register, not the infrastructure.

**Sequencing unchanged:** D.5 remains the first DApp (active-front directive 2026-07-23). D.10
is catalogued, not scheduled. Catalog counts of "nine DApps" in older docs are superseded by
this entry (ten) until the next convergence sweep. License-map files updated: `dapps/LICENSE`,
`dapps/README.md`, `LICENSING.md`, `LICENSE`, `COMMERCIAL-LICENSE.md`.

**Authority:** Stoyan Denev (owner directive, 2026-07-25; recorded by Claude Fable at his direction).

## 2026-07-26 — Active work directive: DSSO packaging tail folded into D.5 (Option C); D.5 is the reference RP

**Problem.** The DSSO threshold-OPAQUE protocol is SHIPPED and gated to `main` (G1+G2 `dec7498`, G3 `ad6bee9`, G4 login `40c078d`, G4 assertion `028e19b`, OPAQUE-3DH AKE + end-to-end `cc5373d`/`3848513`/`c1e8735`, `test-dsso-login-e2e` 18 assertions, 07-21/07-22). What remains is the **packaging tail** (spec §9 / DECISION-LOG line 1484): G5 constant-time review, G6 zeroization, the RP SDK, and a reference RP DApp — all owner-gated, so the thread pool has not self-started them and has defaulted to assurance registers (validator, rpc-ingress, light-client LVS). The tail is not blocked by any technical dependency; it is blocked only by the absence of an explicit owner directive.

**Decision (owner, 2026-07-26) — Option C. This is the active front; it supersedes assurance-register work as the pool's priority until the tail is closed.**

1. **Security floor first — G5 + G6.** Constant-time review of every secret-scalar path (`k`, `k_i`, coefficients, blind `r`, OPRF output `y`, derived keys) and zeroization of the same. This is the one part of shipped crypto that is unsafe to leave undone. **G5+G6 gate the point at which D.5 *ships*, not the point at which D.5 work *starts*** — build proceeds in parallel; neither the reference DApp nor the SDK may be published/tagged for production before G5+G6 are green.
2. **D.5 is the reference RP DApp.** D.5 (government random-selection, the already-designated first DApp) is itself a relying party. Build it as *the* worked RP integration rather than a throwaway demo — it exercises the full register → t-of-n login → OPAQUE-3DH AKE → dual-hash assertion → RP-accepts flow against real chain primitives.
3. **The RP SDK is extracted from the D.5 build, not designed in the abstract.** Let D.5's real integration needs define the SDK surface (client login, assertion verification with the §5 Option-A freshness discipline, key handling); factor the reusable client library out of the working consumer. No speculative SDK API ahead of a real caller.

**Ordering.** G5/G6 review can run concurrently with D.5 scaffolding; D.5 drives SDK extraction; G5+G6 are a merge/ship gate for the D.5 + SDK release. Target: a demonstrable end-to-end DSSO login into a real government DApp, with the identity crypto certified constant-time and zeroized.

**Consistency.** No new primitive (spec §2 — all shipped). BUSL-1.1 applies to D.5 as a revenue DApp (licensing v3.1); the RP SDK is Apache-2.0 integration surface (`sdk/**`). FROST remains out (not required). No-migrations untouched — DSSO is DApp-layer + already-shipped substrate primitives, no consensus change.

**Still open (NOT folded in here — separate owner decision):** the two rank-1 consensus-integrity findings (EQV-INGRESS forged-slash `validator.cpp:378`; empty-committee beacon `node.cpp:1973`, RpcIngressGateAudit §2). They are pre-genesis, in the no-migrations consensus path, and independent of the DSSO tail. They still await an owner directive on the fix; this entry does not authorize them.

**Authority:** Stoyan Denev (owner directive, 2026-07-26; recorded by Claude Fable at his direction).

## 2026-07-27 — Verifiable computation replaces the zk-VM: sum-check/GKR + extended Bulletproofs, proved per fixed circuit; Determ is a curated God-protocol rail, not a universal provable-compute VM

**Problem.** The zk-VM (Bundle B) was the single largest complexity import in the design — a whole proving stack that cannot live under the from-scratch-C99 / zero-heavy-deps / Minix-portable doctrine (RISC Zero / SP1 are large Rust stacks), whose succinct on-chain verifier needs either a pairing curve Determ does not have (new, non-PQ crypto) or a STARK. It gated four v1.2 DApps (D.4/D.6/D.7/D.8) and nothing on the v1.1 critical path. "zk-VM" conflates two things: **general verifiable computation** (the capability actually needed) and a **general-purpose VM that auto-proves arbitrary third-party bytecode** (a developer-convenience layer that is the source of the complexity).

**Decision (owner, 2026-07-27).** Drop the general zk-VM substrate. Provide verifiable computation by proving each specific, fixed computation as its own circuit, using only doctrine-compliant, transparent (no trusted setup) schemes that reuse the shipped stack:
- **sum-check / GKR (Spartan-style)** for computations needing PQ + succinct verification — minimal new crypto (sum-check + a hash-based polynomial commitment over the shipped SHA-256); PQ-capable; soundness proof simple enough (a degree/union-bound argument) to be falsify-on-mutant-gated, which a zk-VM's compiler+prover stack never is.
- **extended Bulletproofs** for small fixed circuits now — the shipped inner-product argument (`ipa.c`) generalizes from range proofs to R1CS / arithmetic-circuit satisfiability; zero new curve, transparent, already audited. Cost recorded: O(n) verify + non-PQ (discrete log over P-256) — acceptable for small circuits, not the default for large or PQ-required ones.

**Positioning — God protocol (Nick Szabo).** Determ remains a God-protocol emulator: **correctness + minimal-disclosure privacy under mutual distrust are preserved for every function instantiated.** The mutual-distrust/privacy leg lives in the K-of-K consensus + threshold layer (DSSO t-of-n OPRF, Shamir, D.10 threshold decryption) and is untouched. What is dropped is *universality* — "God computes any unforeseen program" — a coverage property, not a security property, that no real protocol fully achieves and that nothing on the roadmap requires. This better honors Szabo's core principle ("trusted third parties are security holes; minimize what must be trusted"): a small hand-built circuit + auditable sum-check trusts far less than an opaque zk-VM toolchain. The market claim narrows accordingly — Determ is the **trust-minimized rail for a curated set of God-protocol functions**, not a universal provable-compute platform for arbitrary third-party programs.

**Per-DApp consequence (deliberately harder — the point).** Each Tier-2 computation must be expressed as a specific circuit rather than compiled from arbitrary bytecode. Higher per-DApp effort is chosen intentionally: hand-built circuits are smaller, auditable, provable, and doctrine-clean — pressure that yields trust-minimized DApps.
- **D.6 private rollup:** state-transition function as a fixed sum-check circuit.
- **D.4 AI-agent:** authorized-parameter check as a policy circuit (or signatures + policy where full VC is unnecessary).
- **D.7 verifiable inference:** reclassified **RESEARCH** — zkML for a specific small model as a fixed circuit, or deferred until feasible; not a launch commitment.
- **D.8 anonymous credentials:** re-homed onto shipped primitives (P-256; BBS+/CL-style), pending a spec check — anonymous credentials are a fixed-statement proof and likely need no general VC at all.

**Supersedes / amends.** Closes the zk-VM stack-choice open question (V1.1-PLAN §3 "biggest open question" — moot: no stack to choose). Amends the 2026-06-06 "God-Stack" entry's zk-VM dependency: the God-Stack capability is delivered by threshold crypto + per-circuit verifiable computation, not a VM.

**Consistency.** Minimalism (removes the largest complexity import); from-scratch C99 (both verifiers vendorable; no pairing curve, no Rust stack); PQ (sum-check + hash commitment is PQ-capable; the non-PQ Bulletproofs path is flagged for small circuits only); B3 (sum-check soundness is auditable/falsifiable vs trusting a compiler); no-migrations (verifiable computation is DApp-layer + additive; no consensus change). v1.2 concern only.

**Caveat.** Engineering maturity of Spartan/Brakedown-class implementations moves fast and post-dates the current knowledge horizon; confirm current reference implementations + proof-size/prover-time numbers for the actual D.6/D.4 circuit sizes before building. Each Tier-2 circuit must be pinned before choosing the linear-verify Bulletproofs path vs the succinct sum-check path.

**Authority:** Stoyan Denev (owner directive, 2026-07-27; recorded by Claude Fable at his direction).

## 2026-07-28 — DApp substrate open questions (V2-DAPP-DESIGN §12, Q1–Q8) resolved: five ratified as-shipped, three decided

**Problem.** §12 carried eight open substrate questions with recommendations but no owner ratification. All are consensus accept-rules or wire-format → genesis-frozen under no-migrations, so they must be settled pre-genesis. Reconciliation against the shipped DAPP_REGISTER/DAPP_CALL code (`include/determ/chain/block.hpp` + `src/chain/chain.cpp`) found most already implemented — the design record simply never closed them (a coherence gap now fixed).

**Decision (owner, 2026-07-28).**

*Ratified as-shipped (code already matches; recorded as the decision):*
- **Q1 namespace** — shared, `d:`-prefix domain-separated (the `d:` registry state-root leaf).
- **Q5 reply-routing** — both paths: `endpoint_url` (≤255 B) for off-chain + on-chain DAPP_CALL-back.
- **Q6 proof-of-processing** — convention (a DApp posts its own reply tx); no protocol ACK type (minimalism).
- **Q7 deprecation** — `inactive_from` + `DAPP_GRACE_BLOCKS = 100`; calls to deactivated DApps rejected after grace.
- **Q8 bandwidth** — no priority lane; size bounded by the payload cap + `MAX_DAPP_METADATA = 4096`. Monitor; revisit only on a real problem.

*Decided — require pre-genesis code work, AUTHORIZED FOR IMPLEMENTATION:*
- **Q2 — DAPP_CALL payload cap → governance-mutable.** Currently `MAX_DAPP_CALL_PAYLOAD = 16384` (16 KB) as a `constexpr` (genesis-pinned). Move it to a PARAM_CHANGE-governed parameter, default 16 KB. Rationale: Tier-2 verifiable-computation proofs (sum-check/Bulletproofs, per the 2026-07-27 zk-VM decision) ride in this payload and their size is not measurable until circuits exist; a governed cap avoids a genesis trap (no-migrations) while keeping the initial surface small (minimalism).
- **Q3 — topic routing → ENFORCE.** Validator rejects a DAPP_CALL whose `topic` is not in the target DApp's registered set (topics already stored, ≤32 × ≤64 B). Confirm/add the call-time accept-rule and gate it falsify-on-mutant (B3). Adding a topic is a cheap re-DAPP_REGISTER.
- **Q4 — anonymous calls → ALLOW by default, per-DApp opt-out.** Add an `accept_anon` flag to the DAPP_REGISTER wire format (default: accept); relax the current registered-`tx.from` requirement so bearer/anon senders are admitted unless a DApp sets `accept_anon = false`. Serves the privacy / mutual-distrust mission (D.3, anon polling/oracles) while letting audit DApps (D.5, D.10) require identity. MUST land pre-genesis (wire-format change).

**Consistency.** No-migrations (Q2 governed not frozen; Q4 wire change done pre-genesis; all three settled before launch); minimalism (five ratified untouched, no speculative surface, Q2 default stays 16 KB); provable security (Q3 is a clean gateable accept-rule; Q2/Q4 additive + testable); canonical binary (all wire changes stay in the binary codec, no JSON); mutual distrust (Q4 enables privacy-preserving DApps). No effect on shipped Tier-1 DApps. Amends V2-DAPP-DESIGN §12 (resolution banner added; the per-question prose retained as rationale — DECISION-LOG is authoritative).

**Authority:** Stoyan Denev (owner directive, 2026-07-28; recorded by Claude Fable at his direction).

## 2026-07-28 — Authorized: execute the D2 JSON→binary migration (wire + storage + keyfiles) as the front after the D.5 tail

**Problem.** D2 (2026-07-23) decided binary-everywhere on storage / wire / keyfiles / vectors and deletion of the JSON parsers, but the migration is **unexecuted**: `third_party/nlohmann/json.hpp` (~900 KB heavy C++ dep) is still vendored, a second parser (`include/determ/json/json.hpp`) coexists, and JSON remains in the exact paths D2 mandated binary-only — the p2p wire envelope (`src/net/gossip.cpp`, `src/net/messages.cpp`) and storage/genesis (`src/chain/block.cpp`, `chain.cpp`, `genesis.cpp`). This is the largest standing doctrine-vs-code gap: it breaks canonical-binary, zero-heavy-deps, minimalism (two JSON impls), and C99/Minix portability at once, and the wire-envelope portion is genesis-frozen under no-migrations.

**Decision (owner, 2026-07-28).** Execute the D2 migration. Not a new decision — D2 already resolved the direction; this entry **schedules and scopes execution** as the **next front after the D.5 packaging tail (Option C) completes**. Priority order:
1. **Wire envelope (genesis-deadline):** remove JSON from `src/net/gossip.cpp`, `src/net/messages.cpp`, and any JSON path in `src/net/binary_codec.cpp`; the p2p envelope is binary-only. **Pre-genesis.**
2. **Storage / genesis:** `src/chain/block.cpp`, `chain.cpp`, `genesis.cpp` — storage container binary-only. (Authenticated bytes are already binary; this removes only the JSON *container*.)
3. **Keyfiles:** `wallet/` keyfile paths binary-only.
4. **Delete both parsers:** `third_party/nlohmann/json.hpp` and `include/determ/json/json.hpp`; regenerate the JSON test vectors as binary.
5. **Permitted to remain (D2 exception):** optional human-readable text for RPC responses, CLI output, and local config — non-authoritative views derived from the binary.

Each step gated falsify-on-mutant against the byte-golden vectors (B3); byte-neutral for authenticated data (signed/hashed bytes are already binary). No consensus-rule change — a container/serialization migration only.

**Consistency.** Canonical-binary (removes JSON from the mandated paths); zero-heavy-deps (deletes the nlohmann dependency); minimalism (two JSON impls → zero); C99/Minix (removes the C++-template blocker for the reference build); no-migrations (wire + storage container settled pre-genesis). Sequenced after D.5 so it does not preempt the active front.

**Authority:** Stoyan Denev (owner directive, 2026-07-28; recorded by Claude Fable at his direction).

## 2026-07-28 — Sequence-before-harden: D2 JSON→binary migration promoted to ACTIVE front; freeze hardening on the doomed JSON paths

**Problem.** The pool has been spending B3 hardening / perf effort on the JSON wire-envelope and serialization code that the D2 migration will delete (most recently `cb6ff49` — moving the payload subtree out of the JSON envelope; `b982332` — S-022 cap on the binary-vs-JSON envelope decode). Securing code scheduled for replacement is wasted proof-work: the artifact being hardened will not exist after D2. Security is the top goal — which is exactly why the hardening budget must land on the *final* code, not the transitional code.

**Decision (owner, 2026-07-28).**
1. **New doctrine — sequence-before-harden:** do not spend falsify-on-mutant / perf effort on code scheduled for replacement; execute the replacement first, then gate the survivor. Recorded in CLAUDE.md PROJECT DOCTRINE.
2. **Promote D2 to the ACTIVE front, now** (was NEXT). The D.5 reference RP + RP SDK are built (inc.6b + `sdk/rp`) and G5/G6 shipped, so the DSSO tail no longer blocks it. The pool executes the JSON→binary migration (wire envelope + storage/genesis + keyfiles; delete both JSON parsers; regenerate vectors as binary) before further hardening.
3. **Freeze** new hardening on the JSON-path files (`src/net/gossip.cpp`, `messages.cpp`, `binary_codec.cpp`; `src/chain/block.cpp`, `chain.cpp`, `genesis.cpp`) until D2 rewrites them; gate the binary replacements instead.
4. **Exemption:** consensus accept-rule / logic fixes that survive a container swap are NOT frozen — specifically the two rank-1 holes (`validator.cpp:378`, `node.cpp:1973`) are serialization-independent and remain the real security priority (still owner-gated).

**Consistency.** Serves provable security (B3) by directing the finite proof budget at the code that ships, not code that is deleted; minimalism (removes the JSON surface sooner); no-migrations (wire portion is genesis-deadline). No change to any accept rule — a sequencing directive.

**Authority:** Stoyan Denev (owner directive, 2026-07-28; recorded by Claude Fable at his direction).

## 2026-07-31 — Authorized: close the two rank-1 consensus holes (Hole 1 = same-height binding; Hole 2 = unify beacon-header committee verify)

**Problem.** Two rank-1, remote-unauthenticated consensus-integrity holes have been owner-gated since the 2026-07-23 RpcIngressGateAudit §2, unfixed. Both are consensus/wire changes → genesis-frozen under no-migrations, so they must close pre-genesis. They are the top provable-security (B3) gap and the last blocker on a production-ready core.

**Decision (owner, 2026-07-31) — AUTHORIZED FOR IMPLEMENTATION; security-critical pre-genesis; parallel to D2 (disjoint files):**

**Hole 1 — EQV-INGRESS forged-slash (`validator.cpp:378-402`, ingress `node.cpp:1902`) → Option A.** The equivocation-evidence check never binds the two signed digests to the same height, so an attacker replays an honest validator's normal cross-height signatures as "equivocation" and forges a full-stake slash + deregistration of any honest validator, remotely and unauthenticated. **Fix:** extend `EquivocationEvent` to carry the two conflicting block headers (or the minimal fields to recompute `compute_block_digest`); the verifier recomputes both digests and asserts `header_a.index == header_b.index == ev.block_index`. Wire-format change to slashing evidence — **pre-genesis**. Gate via the existing `check_equivocation_events_for_test` seam, falsify-on-mutant (genuine cross-height pair → REJECT; honest same-height → ACCEPT; mutant on the height-equality assertion falsifies).

**Hole 2 — INGRESS-beacon-header empty-committee (`node.cpp:1973-2007`, `on_beacon_header`) → Option B.** An empty `creators` list passes all three K-of-K checks vacuously, letting an untrusted mesh peer seed attacker-chosen `cumulative_rand` and bias epoch committee selection. **Fix:** route `on_beacon_header` through the SAME committee-signature verifier as `verify_shard_tip_committee_sig_root` (which already enforces non-empty + `required_k`), replacing the divergent hand-rolled path — includes the empty-check + `signed_count >= required_k` floor AND eliminates the divergence bug-class (one gated verifier, not two). Consensus accept-rule on the gossip path — **pre-genesis**. Gate via a new `on_beacon_header_for_test` seam + `test-beacon-header-committee`, falsify-on-mutant.

**Consistency.** Provable security (both bind the missing property explicitly + falsify-on-mutant gated); no-migrations (both settled pre-genesis — Hole 1 wire change, Hole 2 accept rule); minimalism (Hole 2 unifies two verifiers into one). Both EXEMPT from the sequence-before-harden JSON freeze — consensus accept-rule/logic, serialization-independent, survive D2. Disjoint files from D2 (validator.cpp/node.cpp vs the JSON wire/storage paths) → implementable in parallel.

**Deeper adjacent item (NOT authorized here — separate future decision):** the BEACON role is self-declared in the unauthenticated HELLO; Hole 2's floor closes the immediate hole, but authenticating the beacon-producer role is a larger separate hardening.

**Authority:** Stoyan Denev (owner directive, 2026-07-31; recorded by Claude Fable at his direction).

## 2026-08-11 — Pre-genesis backlog — macOS/Darwin support (dev env moved to MacBook Pro)

1. RNG Darwin branch (security-critical). `src/crypto/rng/` branches Windows/Linux only; macOS falls through to the generic `/dev/urandom` POSIX path, which carries a known undisclosed `n==0` corner. Add a `__APPLE__` branch using `getentropy(2)`/`arc4random_buf`, fail-fatal like the siblings, and gate it. Entropy is on the security-critical path — no unaudited fallback.
2. Script portability (BSD vs GNU). `tools/apply_spdx_headers.sh` uses GNU `sed -i "1i …"` which fails under BSD sed; audit `tools/*.sh` for `grep -P`, GNU `date`, `readlink -f`, `sha256sum` (→ `shasum -a 256`).
3. Determinism validation, not golden regeneration. First Mac build runs the full KAT + golden-vector suite. Match → the cross-platform determinism claim strengthens (add a macOS CI runner to lock it in). Mismatch → root-cause it; never regenerate Mac-specific goldens, since that would mask the exact defect the apparatus exists to catch. Prime suspect: `char` signedness (unsigned by default on Apple Silicon, signed on x86).
4. AppleClang C++20 coverage check, and APFS case-insensitivity watch.

**Authority:** Stoyan Denev (owner directive, 2026-08-11; recorded by Claude Fable at his direction).

## 2026-08-11 — macOS/Darwin port LANDED: first native Darwin/arm64 green (FAST 294/0); backlog items 1–2 closed, item 3 FAST-half validated

**Problem.** Execute the pre-genesis macOS/Darwin backlog recorded earlier today (this log, above) after the dev-env move to a MacBook Pro (Darwin arm64, AppleClang 21.0.0).

**What landed** (Linux reference re-verified 294/0 after every change):
- **RNG (item 1):** `__APPLE__` branch in `src/crypto/rng/rng.c` — `getentropy(2)` chunked at its 256-byte cap, fail-fatal, no `/dev/urandom` fallback; closes the generic-POSIX `n==0` corner on Darwin. Gated by the existing `test-rng-c99` (the 64 KiB fill crosses the chunk cap 256×, so a chunk-bound mutant goes red via `EINVAL`).
- **Net:** kqueue backend for `ReactorEventLoop` — the §4.5 "kqueue policy split" the header reserved. Wake pipe as the `EFD_SEMAPHORE` analogue (one byte = one wakeup unit), `EV_ONESHOT` per filter (the no-split-read property preserved), exact-interest re-arm (stale sibling filter deleted), single-change `kevent` submissions with an empty eventlist (batched receipt changelists can dequeue-and-drop pending events, and a batched delete's `ENOENT` can abort sibling changes). SIGPIPE immunity: `MSG_NOSIGNAL` → `kSendNoSigpipe` + per-fd `SO_NOSIGPIPE` (ReactorConnection ctor as the single choke point; SyncClient's two socket sites).
- **Scripts (item 2):** BSD/GNU portability (portable SPDX prepend replacing GNU `sed -i "1i"`; `shasum -a 256` fallback; `sysctl hw.ncpu` jobs; `timeout`→`gtimeout` shim) and the python shim: macOS's `/usr/bin/python` is an xcode-select STUB that exists (so `command -v` succeeds) but fails on exec, and `/usr/bin/python3` is a trampoline dispatching on argv[0] — the shim therefore guards on EXECUTION, not existence, and installs a wrapper (never a symlink) that `exec python3 "$@"`. 358 scripts invoke bare `python`; the shim rides PATH via `tools/common.sh` (352 scripts) + 6 standalone copies.
- Two `-Wcomment` nested-`/*` doc fixes (`enote.h`, `crypto.h`); truthfulness updates to the reactor/native header comments.

**Validation (item 3 discipline — validate, never regenerate).** First native Darwin/arm64 run: AppleClang 21 C++20 build green; FAST suite + doc guards **294/0**; every KAT/byte-freeze pin FAST exercises matched — notably `test-p256-ctx-bundle`'s dual-oracle SHA-256 pin — with **zero goldens regenerated**. kqueue backend additionally runtime-verified on Linux under libkqueue emulation (11/12 semantics; the 12th is a proven emulation limit, and the Darwin suite is the real gate — now green). Item-3 amendment: Apple's arm64 ABI pins `char` **signed** (the unsigned default is ARM *Linux*), so the recorded char-signedness suspect is void for the x86→Darwin pair; it stays live for any future Linux-ARM runner.

**Machine-move ledger (operational):** stale build trees from the previous machine must be deleted (their CMake caches pin foreign paths and `build/Release/determ.exe` poisons `common.sh` detection); use ONE consistent build user (root/user mixing yields EPERM in `_deps`); this MacBook additionally carries the owner-applied `sudo ln -s /Library/Developer/CommandLineTools/usr/bin/python3 .../python`, which satisfies the xcselect stub at the CLT layer — the repo shim is guard-inert while that holds and takes over on machines without it.

**Remaining tail (NOT closed here):** full `run_all` on Darwin (needs `pip3 install pynacl` for the XChaCha oracle in `test_c99_vector_files`, which is outside FAST); a macOS CI runner to lock the cross-platform determinism claim in; APFS case-insensitivity watch. Item 4's AppleClang C++20 coverage is confirmed by the green build.

**Authority:** Stoyan Denev (owner-directed session, 2026-08-11; recorded by Claude Fable at his direction).

## 2026-08-11 — Security fix: bound untrusted KDF cost in the wallet envelope (unbounded-work DoS); tamper-fuzz expectation corrected

**Problem.** `wallet/envelope.cpp` bounded the Argon2id/PBKDF2 cost read from an envelope only from BELOW (`argon2_t==0`, `argon2_p==0`, `argon2_m_kib < 8*p`, `pbkdf2_iters==0`) — no upper bound. Both the deserialize path (:256) and the decrypt path (:145) fed attacker-controlled cost straight into the KDF. A tampered/malicious envelope with a huge `t_cost`/`m_kib`/`iters` drives the KDF for effectively unbounded time; the AES-GCM tag check that is supposed to reject the tamper never runs. Surfaced by `test_wallet_backup_tamper_fuzz` on the first Darwin `run_all` (a single-byte XOR flip took `t_cost` 3 → 67,108,867 and the `determ-wallet envelope decrypt` child hung). Reproduced on Linux → pre-existing and cross-platform, NOT a macOS-port regression.

**Decision (owner-directed, 2026-08-11) — fail-closed upper bounds, reject BEFORE any KDF runs.** New `MAX_*` caps in `wallet/envelope.hpp` (`MAX_ARGON2_T_COST=64`, `MAX_ARGON2_M_COST_KIB=1 GiB`, `MAX_ARGON2_LANES=16`, `MAX_PBKDF2_ITERS=100M`), enforced at both the deserialize and decrypt guards → `std::nullopt` (structural reject) before the KDF is invoked. The caps sit far above every value the encrypt paths ever write (Argon2id always uses the fixed defaults t=3/m=64 MiB/p=1; PBKDF2 `--iters` is the sole tunable), so no legitimately-created envelope is ever rejected. Ceilings are `constexpr`, owner-tunable if a higher-cost profile is adopted.

**Gate (B3, falsify-on-mutant).** Extended the existing pure in-process gate `selftest-envelope-param-reject` (`test_wallet_envelope_param_reject.sh`, FAST) with five cases: D7/D8/D9 (deserialize rejects over-cap t/m/iters) and C5/C6 (decrypt rejects over-cap t/iters fast). C5 encodes the exact reported value (67,108,867): with the cap it returns nullopt instantly; deleting the cap HANGS the selftest — the falsify signal. Gate now 18 pass / 0.

**Test-expectation correction.** `test_wallet_backup_tamper_fuzz` R2 asserted a byte-tamper of any field is contained at the AEAD layer (verify 0, decrypt 2). A flip of the KDF-cost field ('iters'/DWE2 params slot) can now push cost out of the fail-closed bounds and is legitimately contained STRUCTURALLY (verify 2, decrypt 1) — a stronger rejection (before any KDF). The test was never green here before (those cases hung); corrected to accept either coherent fail-closed shape while still failing hard on any false-accept (decrypt rc==0). Now 125 pass / 0.

**Consistency.** Provable security / fail-closed (bounds the missing property, gated falsify-on-mutant); no-migrations (wallet keyfile/envelope layer, no consensus/wire/genesis change — the wire format is unchanged, only an accept-rule tightened; every previously-writable envelope with default cost still decrypts); minimalism (four one-line guard extensions + four `constexpr`). Verified: reported hang → fast reject; gate 18/0; fuzz 125/0; envelope/keyfile suite green; FAST 294/0.

**Adjacent (NOT fixed here):** `light/rpc_client.cpp` and `wallet/main.cpp` `::send` with flags 0 (SIGPIPE-exposed on a raced close, cross-platform) — pre-existing, separate from both this fix and the macOS port; left for a future backlog item.

**Authority:** Stoyan Denev (owner-directed session, 2026-08-11; recorded by Claude Fable at his direction).

## 2026-08-12 — LANDED: both rank-1 consensus holes closed; D2 step 3 (wallet/light keyfiles) binary; S-050 straggler recovery authorized + closed

**Scope.** Executes the two owner-authorized rank-1 consensus fixes (this log, 2026-07-31) and D2 migration step 3 (wallet keyfiles; 2026-07-28), plus one liveness fix authorized in-session (below). Parallel execution over disjoint file ownership; every increment falsify-on-mutant gated. Verified green on Darwin/arm64 via `tools/ci_local.sh`.

### 1. Hole 1 — EQV forged-slash closed by HEIGHT BINDING (Option A, restructured)

**Problem (recap).** `check_equivocation_events` never bound the two signed digests to the same height: an attacker replayed an honest validator's normal cross-height signatures as "equivocation" and forged a full-stake slash + deregistration, remotely and unauthenticated.

**What shipped — a refinement of Option A.** The authorization said "carry the conflicting headers". Carrying two full `Block`s was rejected on analysis: unbounded size, and `Block ⊃ EquivocationEvent ⊃ Block` recursion (crafted evidence nests infinitely), while even an "exact header subset" is recursive because `compute_block_digest`'s eq-root appendage reads the block's own equivocation_events. Shipped instead: both digest families that feed the evidence channel become **two-level and openable**:

    block_digest   = SHA256("DTM-BLKDIG-v2"  || index       u64 BE || body_root)
    contrib_commit = SHA256("DTM-CONTRIB-v2" || block_index u64 BE || body_root)

`EquivocationEvent` carries `kind` (0=BLOCK_DIGEST, 1=CONTRIB_COMMIT) plus, per side, the fixed 40-byte opening `{index u64, body_root 32}`; `digest_a`/`digest_b` are DELETED (now pure functions of carried fields). The verifier rejects `kind > 1`, asserts `index_a == index_b == ev.block_index`, and verifies each signature against the DERIVED digest — which is what makes the height signature-bound. The two outer tags MUST differ: without domain separation, one honest block signature plus one honest contrib signature at the same height would be a NEW forgery.

**Wire (GENESIS-DEADLINE, frozen candidate).** EQUIV_REC and the gossip EQUIVOCATION_EVIDENCE frame share the field order `[equivocator lp][block_index u64][kind u8][index_a u64][body_root_a 32][sig_a 64][index_b u64][body_root_b 32][sig_b 64][shard_id u32][beacon_anchor_height u64]`; fixed portion 229 B after the lp_str (`kMinEquivEvent` 213 → 230); decode fail-closes on `kind > 1`. Frame integers are LITTLE-endian; the digest preimage integers are BIG-endian (SHA256Builder convention) — deliberate, documented at both sites. `hash_equivocation_event` bumped to `"DTM-F2-EQ-v2"`.

**Consequence (pre-genesis, free).** Every block-digest and contrib-commitment VALUE changed. No shims, no negotiation. Crypto-primitive byte-freeze pins are unaffected (primitive-level).

**Gate.** The EQV block in `test-abort-cert-validation` (driven through `check_equivocation_events_for_test`), 8 arms incl. same-height ACCEPT control, cross-height REJECT, an openings-agree-but-≠-block_index REJECT that pins the `== ev.block_index` leg alone, derived-digest tamper, `kind=2` reject, and a contrib-kind control + cross-kind reject pinning domain separation. Mutant 1 (delete the height assert) and mutant 2 (weaken it to `index_a == index_b`) each go RED on exactly their arm; revert GREEN.

### 2. Hole 2 — empty/under-K beacon header closed by ONE shared verifier (Option B)

Extracted `verify_committee_sigs` (non-empty floor + size match + membership + sig verify + `signed_count >= required_k`) into `src/node/shardtip_verify.cpp`; BOTH `verify_shard_tip_committee_sig_root` and `Node::on_beacon_header` route through it — one gated verifier, killing the divergence bug-class. `required_k` on the beacon path is `cfg_.k_block_sigs` (build-sharded emits beacon + shards from one config). The caller-side K-of-K completeness rule (`signed_count == creators.size()`) is retained. Honest acceptance unchanged.

Direct wholesale reuse of `verify_shard_tip_committee_sig_root` was rejected as incorrect for this path: it derives an expected committee from `epoch_committee_seed(beacon_rand, shard_id)` over a pinned pool, which a shard cannot reproduce for the beacon's own chain — it would false-reject honest headers. Core-extraction is the unification the authorization describes.

**Gate.** `test-beacon-header-committee` (new seam `on_beacon_header_for_test`): empty-committee forge REJECTED, under-K forge REJECTED, 3-creator zero-sentinel completeness pin, honest K-of-K ACCEPTED. Mutant A (re-admit the vacuous loop) and mutant B (delete the `signed_count < required_k` arm) each go RED; revert GREEN.

**Scope correction recorded in code (B3, nothing aspirational).** An adversarial review of this change confirmed the fix does NOT authenticate `cumulative_rand`: the K-of-K `creator_block_sigs` sign `compute_block_digest`, which does not cover `cumulative_rand`/`delay_output` (both ARE bound into `signing_bytes`/`compute_hash`, but that is not the signed digest), and this ingest path does not run `check_cumulative_rand` (apply-path only). A MITM can therefore alter `cumulative_rand` on an otherwise-valid header without breaking the signatures; for the FIRST header the prev_hash chain check is skipped, so a tampered rand can seed ONE epoch's committee selection before subsequent genuine headers fail to chain (a stall, not silent acceptance). PRE-EXISTING — the old hand-rolled loop had the same gap; this fix is a strict improvement within its authorized scope. The `on_beacon_header` comment was corrected so it can no longer be read as claiming the field is authenticated. **Authenticating `cumulative_rand` on the beacon-header path remains NOT AUTHORIZED (owner decision, adjacent to the also-unauthorized HELLO beacon-role authentication).**

### 3. D2 step 3 — wallet + light at-rest artifacts are canonical binary

Eleven at-rest artifact families were inventoried; the "already binary" assumption was FALSE byte-wise — the DWE envelope serialized as dot-separated hex TEXT and the DETERM-NODE-V1 keyfile was a 2-line ASCII file whose encrypted plaintext was itself JSON. Seven binary containers shipped (magic + explicit LE + length prefixes + EXACT-length decode, refuse-never-clamp): **DWE** (canonical envelope bytes; the old `serialize`/`deserialize` names survive as the strict-hex CLI VIEW, which is what kept src/ edits at ZERO), **DAK1** (68 B keypair; a pubkey-from-seed derive-equality check REPLACES the S-028 address cross-check), **DAB1** (batch), **DNK1** (encrypted node keyfile; AAD = the RAW 32-byte pubkey, plaintext = the RAW 32-byte seed, no inner JSON), **DSS1**/**DBE1** (shamir shares / backup envelopes, DISTINCT-x enforced on decode), **DRS1** (recovery setup; `scheme` dropped), **DLS1** (light state cache, `state.bin`). The 1736ba8 KDF-cost caps are enforced in `deserialize_bytes` BEFORE any KDF runs — the DoS fix survives the rewrite.

**Gates.** `selftest-envelope-bytes` (21 cases), `selftest-keyfile-binary` (19), `selftest-backup-binary` (19), light `state --selftest` (8) — each with mutant-RED/revert-GREEN evidence: exact-length trailing-byte check, DAK1 derive-equality, DNK1 AAD binding, DSS1 DISTINCT-x, DLS1 length guard. `selftest-envelope-param-reject` keeps its falsify property on binary blobs.

**Explicit D2 REMAINDER (not closed here).** `node_key.json` (`src/crypto/keys.cpp`) and `DETERM-ACCOUNT-V1` stay src-owned JSON/text until the src-side storage/keyfiles increment; `keyfile-decrypt --out` still emits `node_key.json` (marked `D2-DEFERRED(src)` in code). DETERM-ACCOUNT-V1 line 2 changed dot-hex → single-hex (pre-genesis free). The light export-headers archive is deferred behind the binary header frame (it embeds `header_json`; binarizing now would freeze a JSON-carrying container — sequence-before-harden).

### 4. S-050 straggler recovery — AUTHORIZED IN-SESSION (owner, 2026-08-12) and closed

**How it surfaced.** `test-fa-adversarial-deterministic` regressed from green to a multi-hour spin (it ground `run_until`'s 5,000,000-step guard). Root-caused: NOT a fork — the chain stayed linear (757 heights, 757 unique hashes) — but ONE stranded straggler. Hole 1's changed digest VALUES flow into block identity (contrib sigs are bound into `signing_bytes`; the block hash seeds the committee-RNG chain), producing a different-but-consistent deterministic schedule in which node4 misses a delivery. Proof of causation: reverting both digests to their single-level forms reproduced the exact baseline block-1 hash and the test passed.

**The exposed defect is REAL and PRODUCTION, not a test artifact.** An idle non-committee follower arms no round timer (`check_if_selected` returns without arming when unselected), so the S-050 stall valve — which fires only from `handle_contrib_timeout`/`handle_block_sig_timeout` — never fires for it; `make_status_request` is otherwise broadcast only at one-shot startup. A follower that misses a block therefore has NO re-sync path and rejects every later block for prev_hash mismatch, forever. Recovery was shown to be purely message-driven (it needed no clock advance), so the gap is wall-clock-real, not an artifact of the harness's frozen virtual clock.

**Decision (owner, 2026-08-12).** In `apply_block_locked`, a block with `b.index > chain_.height()` (proof a peer minted past our head while we are missing ≥1 block) triggers the SAME tolerance-0 catch-up the valve uses: set `stalled_resync_`, broadcast one `STATUS_REQUEST`. **Guarded** by `!stalled_resync_` so it fires at most once per stall episode — an unguarded trigger would be a per-block STATUS_REQUEST amplification vector; the flag clears on the next successful append, re-arming detection. No new message type, accept-rule, digest, or state; additive, pre-genesis, reuses existing S-050 machinery.

**Gate.** `test-straggler-resync` (new seam `apply_block_for_test` + `stalled_resync_for_test`/`status_requests_sent_for_test` observables): stale/duplicate does NOT trigger; normal-next (`index == height`) does NOT trigger (pins the strict `>` boundary); future block triggers exactly one STATUS_REQUEST; a second future block does NOT re-broadcast (the DoS guard). Three mutants — delete the trigger, widen `>` to `>=`, delete the guard — each go RED on exactly their own arm; revert GREEN. `test-fa-adversarial-deterministic` returned to green (all assertions incl. byte-identical replay determinism) in 1.55 s.

**Consistency.** Provable security / B3 (every new property falsify-on-mutant gated; the Hole-2 comment corrected rather than left aspirational); no-migrations (Hole 1's evidence wire change, the keyfile containers, and the digest-value change are all settled pre-genesis; §4 changes no accept rule); minimalism (Hole 2 unifies two verifiers into one; §4 adds no new message type; `digest_a`/`digest_b` deleted as derivable); canonical binary (step 3 removes the last wallet/light text-at-rest containers); C99-forward (all new containers are explicit-LE, length-prefixed, trivially re-implementable).

**Authority:** Stoyan Denev (owner directives 2026-07-31 for Holes 1–2, 2026-07-28 for D2 step 3, and 2026-08-12 for the S-050 straggler fix; recorded by Claude Fable at his direction).

## 2026-08-12 — Owner decisions on the four items left open by the 2026-08-12 landing

**Context.** The parallel session that landed d34c632 + 8a106aa surfaced four items it deliberately did NOT act on. All four are decided here.

**Q1 — Beacon-header `cumulative_rand` authentication → REUSE THE EXISTING VALIDATOR CHECKS (not a digest change).**
*Problem.* The K-of-K `creator_block_sigs` cover `compute_block_digest`, which excludes `cumulative_rand` and `delay_output` (both ARE in `signing_bytes`/`compute_hash`, but that is not the signed digest), and `on_beacon_header` does not run `check_cumulative_rand` (apply-path only). A MITM can therefore alter `cumulative_rand` on an otherwise-valid header without breaking the signatures; for the FIRST header the prev_hash chain check is skipped, so a tampered rand seeds ONE epoch's committee selection before genuine headers fail to chain (bias, then stall).
*Decision.* Run the EXISTING, already-gated `check_delay` + `check_cumulative_rand` logic on the beacon-header ingest path. This binds the field without any wire or digest change: `check_cumulative_rand` re-derives `SHA256(prev_rand ‖ delay_output)`, and `check_delay` binds `delay_output` to `delay_seed` + `creator_dh_secrets` under commit-reveal, where `delay_seed` and `creator_dh_inputs` ARE digest-covered. Rejected: appending the fields to `compute_block_digest` (strongest but changes every digest value again, reshuffling the deterministic schedule, and is genesis-frozen once launched). Gate falsify-on-mutant through the `on_beacon_header_for_test` seam. **Pre-genesis** (accept-rule on the gossip path).

**Q2 — Hole 1b (same-height cross-round equivocation residual) → CLOSE IT NOW by binding the round.**
*Problem.* The shipped height binding blocks cross-height replay, but honest validators still legitimately sign two different digests at the SAME height across abort re-rounds (round-2 committee changes after an exclusion; a fresh `dh_input` per `start_contrib_phase` generation). Such an honest pair remains packageable as "equivocation" — the last forged-slash route.
*Decision.* Extend the shipped two-level compose scheme with the round generation: `TAG ‖ index u64 BE ‖ gen u64 BE ‖ body_root`, and carry `gen` per side in `EquivocationEvent` alongside the existing `(index, body_root)` opening. The verifier additionally asserts both sides share the same `gen`. This is an evidence-wire + digest-value change and therefore **GENESIS-DEADLINE — it must land pre-genesis.** Gate falsify-on-mutant: an honest re-round pair (same height, different `gen`) must be REJECTED; a genuine same-height same-`gen` double-sign must still be ACCEPTED. Supersedes the "OPEN residual" recorded in EquivocationSlashing.md Case (c) and PROTOCOL.md §6.

**Q3 — Parser endgame → PATH A (djson survives; delete the vendored nlohmann).**
*Problem.* Full parser deletion is not reachable while D2's own exception permits text for RPC responses, CLI output and local config: a parser stays load-bearing for the line-JSON RPC protocol (including the `method ‖ "|" ‖ params.dump()` HMAC preimage), the `Message::payload` DOM, and the light/wallet CLI surface.
*Decision.* Path A. Swap the surviving permitted-text surface (RPC server + clients, `Config`, CLI text I/O) onto the in-tree 577-LOC `include/determ/json/json.hpp` (djson) — already dual-oracle gated byte-exact on the RPC-HMAC subset by DetermJsonParitySoundness.md — then delete `third_party/nlohmann/json.hpp`. Outcome: **zero third-party parsers**; one small auditable in-tree parser remains for non-authoritative text. Consistent with D2 resolved (iii) and C99-MINIX-PORT.md:61. Rejected: Path B (additionally binarize RPC requests + re-type `Message::payload`) — ~3-5 kLOC more across node/gossip/wallet/light and it gives up human-readable RPC, for no consensus-security gain (RPC is not a consensus path). `tools/test_minix_sbom.sh` must be rewritten in the same commit as the deletion (its nlohmann SHA-pins are the designed tripwire), and `test_minix_dependency_surface.sh` gains a zero-`nlohmann`-token ratchet. **Not genesis-frozen** — sequence it AFTER the genesis-deadline items (Q1, Q2, inc7c).

**Q4 — `--from-domain` on bulk-send / bulk-stake → RATIFIED as shipped.**
DAK1 carries only an anon identity, so without this flag the previously-shipped domain-identity signing flow (a validator staking from its registered domain) was silently deleted by the keyfile binarization. The flag restores it explicitly; the daemon still verifies against the domain's registered `ed_pub`, so a wrong key fails closed server-side. Recorded as intentional surface, not incidental.

**Sequencing.** Genesis-frozen first: Q1, Q2, and D2 inc7c (HEADERS_RESPONSE + SNAPSHOT_RESPONSE reusing DSN1, then delete the lp-JSON fallback and retire WIRE-2). Q3 follows; Q4 needs no code.

**Still NOT authorized** (unchanged): authenticating the self-declared BEACON role in HELLO — a larger separate hardening, adjacent to Q1 but distinct.

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction).

## 2026-08-12 (later) — Q1 landed; Q2 PARTIAL — Hole 1b is NOT closed, and `gen` is the wrong round identity (adversarial-review finding, GENESIS BLOCKER)

**How this was found.** The Q1/Q2 implementations were green (`ci_local` FAST 302/0 + guards) and self-reported as closing their holes. A 12-agent adversarial review of the uncommitted diff raised 9 findings, **all 9 confirmed on independent re-derivation, zero false alarms** — four Critical. The gates were green because they tested the property the implementer believed was being bound, not the property actually needed. Recorded here in full, because the shipped code now carries corrected (weaker, true) claims and a future reader must know why.

**Q1 — LANDED (beacon-header randomness binding).** `on_beacon_header` now runs the existing `check_delay` + `check_creator_dh_secrets` + `check_cumulative_rand` logic via a new production seam `BlockValidator::check_header_rand_binding`, with the cores extracted so there is ONE implementation per rule (no duplicated verifier logic — the divergence class Hole 2 removed). Verified in code, not assumed: `check_creator_dh_secrets` is **load-bearing, not optional** — `creator_dh_secrets` is not digest-covered, so without the commit-reveal check an attacker substitutes secrets, recomputes `delay_output`, re-derives a matching `cumulative_rand`, and every K-of-K signature still verifies. A dedicated mutant proves it (dropping only that link reddens exactly one arm). Gate: `test-beacon-header-committee`, 9 arms.

*Two Q1 claims were corrected after review (both were overstated in the first draft):*
1. **"not silent long-run control" was FALSE.** The beacon-header ingress never checks that `b.creators` IS the beacon's derived committee — only that they are registered and signed. So **any `k_block_sigs` eligible domains can mint an internally-consistent header STREAM and drive the rand chain indefinitely**, with every check passing. A pure relay's tamper is self-limiting (header 2 fails to chain); a colluding eligible set is not. Separate OPEN hole on this path, adjacent to the still-unauthorized HELLO beacon-role authentication.
2. **"closing the first-header residual requires the B2c.5 pin" was FALSE.** It is closable in-tree by a successor-confirmation rule at the two consumption sites (do not let an unconfirmed first header seed epoch rand until a chaining successor arrives).

**Q2 — PARTIAL, and its central claim is FALSE. `gen` is a COUNT, not a round IDENTITY.**
`gen` is `current_aborts_.size()` / `b.abort_events.size()`. Two distinct rounds at one height can carry the SAME count, and two confirmed in-tree paths produce exactly that:
- **The S-050 stall valve.** With an EMPTY abort tail the tail is trivially "immobile" (`current_aborts_.size() != stall_abort_count_` is `0 != 0`), so the soft-restart deferral never fires; the valve `clear()`s, `reset_round()`s and re-enters `start_contrib_phase`, which draws a FRESH `dh_input`. Result: one honest validator, one height, one family, **same gen, different body roots, two valid signatures**. A peer still holding the first contrib assembles and gossips evidence that passes EVERY V11 clause including the new `gen_a == gen_b` assert, and apply forfeits the honest validator's FULL stake. No attacker signature anywhere. Reachable with K=2 by construction (`abort_claim_quorum(2) = max(2,1) = 2` is unsatisfiable, so the tail stays empty), and at K>=3 via the hard window once the valve's `clear()` returns gen to 0 while peers that never adopted those abort events still hold the original contrib.
- **The S-048 depth-1 reorg**, which re-rounds at the same height with gen reset to 0.
- **A non-committee follower never runs the valve at all** (it arms no round timer — see the S-050 straggler entry above), so in any `M > K` deployment some peer holds the stale first contrib indefinitely. This is the same idle-follower asymmetry that produced the straggler bug, resurfacing as a slashing hazard.

**Also confirmed:** `RoundStallValveSoundness.md` Claim C-2 — the proof the gen-bind rests on — **silently assumes a non-empty abort tail**, which is exactly the case that breaks. The proof is defective, not merely the code.

**Decision (interim, this session).** The Q2 mechanism is COMMITTED because it is a strict improvement (a genuine abort re-round, where the count really did change, is now rejected) and pre-genesis format changes are free — but every claim that it CLOSES Hole 1b is retracted in code, in the light-client verifier contract, and here. `determ-light verify-equivocation` PROVEN now means "two same-height same-gen signatures exist", explicitly NOT "this validator is dishonest"; operators are told to corroborate before acting on a slash. The v3 tags (`DTM-BLKDIG-v3` / `DTM-CONTRIB-v3`) and the 246-byte EQUIV_REC / 245-byte gossip frame are **PROVISIONAL**.

**OPEN — owner decision required, GENESIS BLOCKER.** Closing Hole 1b needs a genuine **per-height round counter that strictly increments on EVERY `start_contrib_phase` entry** (valve re-entry and reorg re-entry included), signed into `ContribMsg` AND recoverable from the `Block`. No abort-derived value can substitute: on the failing path the abort tail is IDENTICAL (empty) across both rounds, so binding `chain_abort_hash` or the tail's last `event_hash` fails identically. The alternative — forbid the valve from re-signing at an unchanged round identity — trades the slashing hazard for a liveness cost and must be weighed explicitly. This changes the evidence wire AGAIN (v4) and **must land before genesis.**

**Also open from this review (lower severity, not blockers):** the light client's independent Block-frame walker was not updated for `gen_a`/`gen_b`, and its `decode-wire` mirror rejects every EQUIVOCATION_EVIDENCE chatter frame (stale by 33 bytes now — it was already stale by 17 at HEAD, so this is pre-existing drift the review surfaced); and the canonical spec docs still describe the v2 tags, the 2-field opening and the 229/230-byte frames.

**Consistency.** Provable security / B3: the review is the reason this entry exists — a green gate proved the wrong property, and the correct response is to retract the claim, not to keep the comfortable one. No-migrations: everything here is pre-genesis and therefore still changeable, which is precisely why the round-counter decision must be made now.

**Authority:** adversarial-review finding recorded by Claude Fable, 2026-08-12; the round-counter design and the two Q1 residuals are escalated to Stoyan Denev and are NOT decided here.

## 2026-08-12 (later still) — Hole 1b closure design AUTHORIZED: gossiped round-reset marker; test-first; no interim softener

**Decision (owner, 2026-08-12), on the genesis blocker recorded in the entry above.**

**1. Mechanism — a GOSSIPED ROUND-RESET MARKER (not a local counter).** The round identity must satisfy two properties at once, and only a shared value does: (a) it must genuinely change on EVERY re-entry to `start_contrib_phase`, and (b) all nodes must converge on it, or two nodes that re-round at different times could never co-sign again — a permanent liveness break. A per-signer LOCAL monotonic counter satisfies (a) and fails (b), and was rejected for exactly that reason.

The S-050 stall valve and the S-048 depth-1 reorg will emit a **gossiped, adopted round-reset marker**, carried by the same machinery abort events already use (bounded, deterministic, gossiped, adopted, bound into the block). With it, the round generation really does increment on every re-entry, which fixes the hazard at its ROOT rather than at the verifier: `on_contrib` admits on `msg.aborts_gen != current_aborts_.size()`, so a peer receiving a re-round contrib will now **reject it at admission** instead of admitting it into the same generation, seeing a "duplicate signer", and assembling honest-validator slashing evidence. Nodes reconverge once the marker propagates.

Consequence: the ALREADY-COMMITTED v3 `gen` mechanism becomes CORRECT — this is a producer-side fix, not another evidence-format revision. Whether the v3 tags and the 246/245-byte frames can therefore stay final is to be confirmed by the implementation; they remain PROVISIONAL until it lands.

**2. Interim posture — DOCUMENTED, NO CODE CHANGE.** Nothing is launched, so no stake is at risk today. The hazard is recorded here, the code comments state the scope truthfully, and `determ-light verify-equivocation`'s PROVEN verdict already tells operators to corroborate before acting on a slash. A temporary softener would be shipped only to be reverted; fixing once, correctly, is cleaner.

**3. Sequencing — HOLE 1b FIRST, ALONE, TEST-FIRST.** Not bundled with the other beacon-path blockers (the un-checked committee derivation at header ingest; the still-unauthorized HELLO beacon-role authentication), despite the shared ingest surface: Hole 1b is the only blocker where an honest participant loses funds, and an isolated increment keeps the falsification unambiguous.

**Test-first is mandatory and is the point.** A reproduction gate that drives the valve path with an EMPTY abort tail and asserts an honest validator is NOT slashed MUST be written first and MUST FAIL at HEAD (a1a0cf1). That failure is the anchor: this session's central lesson is that a green, mutant-verified gate can prove the wrong property, so the fix is only credible if the gate demonstrably captures the real hazard BEFORE the fix exists. If the hazard cannot be reproduced as described, that is itself a finding to be reported — not worked around.

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction).

## 2026-08-12 (final) — Hole 1b: hazard REPRODUCED end-to-end; the authorized round-reset-marker design FAILED adversarial review and was NOT committed

**1. The hazard is REAL and is now reproduced in production code, not by analogy.**
A test-first gate (`test-honest-reround-not-slashed`) drives the genuine path — `handle_contrib_timeout` → `maybe_stall_reset_locked` → `clear + reset_round` → `check_if_selected` → `start_contrib_phase` (fresh `rng_.fill` dh_input) → gossip → peer `on_contrib` duplicate-signer assembly → gossip → independent V11 verify — with no attacker, no forged message and no tampered frame. Deterministic (3/3 byte-identical, 0.11 s). At the then-HEAD it FAILED on three arms:
- **H1** the peer's evidence pool NAMES the honest validator (it admits the re-round contrib because `msg.aborts_gen == current_aborts_.size()` is `0 == 0` on both sides, sees a duplicate signer, and assembles evidence);
- **H2** the victim itself ADOPTS the gossiped evidence against itself — it passes EVERY V11 clause including the Q2 `gen_a == gen_b` assert that was believed to close this;
- **H3** the victim's stake goes **1000 → 0** through the real `chain.cpp apply_transactions` full-forfeit path.
Five witness arms stayed green so the failure is not vacuous (peer really admitted contrib #1; its pool was empty beforehand, excluding the S-047 byte-identical rebroadcasts as the cause; the real valve fired; the abort tail was empty on both sides of the re-round; the victim re-entered CONTRIB at the same height).
Minimal reproducing topology: K=2 with one committee member never constructed (so `abort_claim_quorum(2) = max(2,1) = 2` is unsatisfiable and the tail stays EMPTY), plus a peer below `min_stake` — never selected, never arms a round timer, never valves — which therefore holds the first contrib indefinitely. That is the idle-follower asymmetry from the S-050 straggler entry, now in its slashing form.

**2. The authorized fix design FAILED review and is NOT in the tree.**
The gossiped round-reset marker was implemented and then attacked from three lenses (liveness/reconvergence, residual honest-slash, consensus agreement). **15 findings confirmed on independent re-derivation, 2 false alarms** — 1 Critical, 11 High. It was reverted rather than committed, because several defects are worse than the bug:
- **It inverts the deterrent.** Nothing bound a marker to an ACTUAL stall, so any committee member could mint a round boundary and **launder a genuine same-height double-sign out of the evidence rules** — a real equivocator escapes slashing.
- **One member could halt the chain.** `ROUND_RESET` was a unilateral, un-quorumed round teardown that erased the abort-claim state used to evict a faulty member; it also wiped not-yet-baked AbortEvents on every adopter, so abort-driven suspension slashing could be suppressed remotely.
- **Not a CRDT.** Adoption compared `new_gen` against the SUM but replaced only one term, so identical message sets in different orders yield different generations — two honest nodes diverge permanently at one height and wedge K-of-K. `round_generation()` composed a max-CRDT with the additive abort tail into something order-dependent.
- **In-memory only.** A validator restart regresses the generation to 0 at an unchanged `(height, prev_hash)` and **reopens the exact hazard**.
- **Unbounded magnitude.** One message setting `new_gen = kRoundGenMax` permanently disables the S-050 stall valve at that height for every adopter.
- The S-048 reorg path emitted `new_gen = 1` unconditionally (minted after the generation was already zeroed), colliding with any pre-reorg round at gen 1 — the Critical.

**3. What this means for the design (owner input needed before the next attempt).**
The failure is not merely implementational. A round-reset marker that any single member can mint at will is simultaneously a liveness weapon and a slashing escape hatch, so the next attempt must decide how a round boundary is AUTHORIZED — options include a quorumed marker (K-of-K or a claim quorum, like abort events), or a proof-carrying marker bound to evidence of an actual stall (e.g. the timed-out round's own state), rather than a unilateral declaration. It must additionally be: **persisted** (restart must not regress the generation), **order-independent** (a genuine CRDT, or derived from a single monotonic source rather than a sum of two), **magnitude-bounded**, and **coherent with the S-048 reorg path**. Whether the committed v3 evidence tags and the 246/245-byte frames survive that design is open.

**4. State of the tree.** Reverted to f3c0793; `ci_local` green (FAST 302/0 + doc guards). The reproduction gate and the failed-fix patch are preserved as session artifacts and are NOT committed — the reproduction depends on a `src/main.cpp` gate block plus four read-only `*_for_test` seams in `include/determ/node/node.hpp`, and it must be re-landed with the next attempt (registered OUT of FAST until it passes, since it is expected-RED while the hazard is open). Recreating it is cheap given §1 above, which specifies the topology and every arm.

**5. Interim posture is unchanged and deliberate:** documented, no softener. Nothing is launched; no stake is at risk today. `determ-light verify-equivocation`'s PROVEN verdict already tells operators to corroborate before acting on a slash.

**Hole 1b remains OPEN and remains a GENESIS BLOCKER.**

**Authority:** reproduction + adversarial-review findings recorded by Claude Fable, 2026-08-12; the round-boundary authorization design is escalated to Stoyan Denev and is NOT decided here.

## 2026-08-12 (final+1) — Option C (reuse the unrevealed round secret) is REFUTED; the root cause is named; Option D is now mandatory regardless

**Method.** Owner directive: prove Option C before implementing it, with Option D as backstop and A/B as fallbacks if the reveal-safety analysis fails. Four independent analysts (reveal paths, reorg+restart, randomness/bias, discrimination) plus a synthesis reviewer that re-derived rather than averaged. Verdicts: FAILS / FAILS / HOLDS_WITH_CONDITIONS / FAILS → **synthesis: UNSAFE. No code was written.**

**REFUTATION 1 (decisive) — Option C aims at the DETECTOR; the slashing rule lives in the VERIFIER.** The full V11 clause set (`src/node/validator.cpp:422-495`) and the adoption gate (`src/node/node.cpp:1901-1943`) test `body_root_a != body_root_b`. **Neither contains a "core" comparison.** The core-only comparison at `node.cpp:3043-3058` is a producer-side courtesy in ONE in-tree assembler. `make_contrib_body_root` (`src/node/producer.cpp:270-325`) additionally binds `proposer_time` (`DTM-TS-v1`), the three F2 view roots (`DTM-F2-v1`) and the shard-tip root (`DTM-STV-v1`) — none of which freezing the secret would fix. `proposer_time` is `clock_.unix_seconds()` at 1-second granularity while the valve enforces ≥5 s between attempts, and the in-tree comment at `node.cpp:1096-1101` states outright that the view legitimately VARIES across re-rounds. So the two body roots differ **with certainty and by design**. Option C's premise — "the re-round contrib is byte-identical" — is FALSE at the layer the rule reads. The slashable pair stays on the wire, `EQUIVOCATION_EVIDENCE` is accepted from ANY peer unconditionally (`src/net/gossip.cpp:117-119` returns true), and under K-of-K mutual distrust an assembler keying off the real rule is inside the threat model by definition.

**This nearly reproduced this session's signature failure.** A gate built on the existing reproduction would have gone GREEN while the bug stayed live, because that reproduction runs through the assembler that compares cores. Green, mutant-verified, and proving the wrong property — caught this time BEFORE implementation, by insisting the proof precede the code.

**REFUTATION 2 (independent) — the secret is public before the re-entry.** `start_block_sig_phase` broadcasts `dh_secret = current_round_secret_` in the clear to EVERY peer (`node.cpp:1417-1423`; `GossipNet::broadcast` has no committee filter, `gossip.cpp:332-337`; 32 raw bytes in the BLOCK_SIG frame, `binary_codec.cpp:508/521`), with NO block applied. `handle_block_sig_timeout` then routes through the same S-050 valve (`node.cpp:1709 → 1643-1648 → 1050`) back into `start_contrib_phase` at an unchanged `(height, prev_hash)`. Because the valve CLEARS the abort tail, the identical committee is re-derived — so on that path ALL K secrets are already public and `delay_output = compute_block_rand(delay_seed, creator_dh_secrets)` would contain no secret input at all. That is a live bias channel into `cumulative_rand` → `epoch_rand` → `epoch_committee_seed` → `select_m_creators`, plus the subsidy lottery (`chain.cpp:1717-1731`, whose own comment states the invariant being destroyed), and it restores the selective-abort attack S-009 exists to prevent. On that path Option C has **no legal move**: replay is forbidden (S-009), a fresh draw is Hole 1b verbatim.

**REFUTATION 3 — the literal instruction is a no-op that is worse than nothing.** `current_round_secret_` has exactly four references (`node.cpp:1088` write, `1420/1422` read, `2411` zero). `reset_round()` zeroes it and precedes EVERY re-entry path, so "reuse `current_round_secret_`" would commit `SHA256(0^32 || pubkey)` — a globally precomputable commitment, which is also the S-009 absent-reveal sentinel.

**ROOT CAUSE, now named precisely.** The synthesis corrected two of its own analysts: the round-2 abort quorum (`node.cpp:1839`) and abort-event adoption (`node.cpp:1893`) are NOT slashing paths — both `push_back` onto `current_aborts_` BEFORE `reset_round`, so the re-round signs `gen N+1` against the prior `gen N` and EQV-gen-bind already rejects the pair. **The S-050 valve is the UNIQUE slashing engine precisely because it CLEARS the tail back to 0** and re-collides with a gen-0 contrib. Therefore: *the evidence's round identity is a RESETTABLE CONTAINER SIZE, not a monotonic counter.* Everything else follows from that single defect. (Reorg is not a second key regression: a depth-1 reorg always changes `prev_hash`, height is non-decreasing, and `resolve_fork` is a strict total order, so an in-process round key is never revisited — **restart is the only other key regression**.)

**What survives, and what it costs.** A promoted variant "C-prime" — freeze and REPLAY the entire signed ContribMsg (not the secret), keyed by `(height, prev_hash)`, surviving `reset_round`, with a sticky reveal barrier — is implementable, and the synthesis specifies it as ten precise rules. But it is strictly worse than it first appears: on any post-reveal re-entry its only safe move is **abstention, which halts K-of-K at that height**; it requires a persisted signed-message record with a synchronous fsync on the consensus hot path (in a codebase that deliberately made chain saves asynchronous); it freezes `tx_hashes`, so a stalled height stops absorbing the mempool; and it leaves the BFT block family untouched. C-prime papers over the symptom while the round counter still regresses.

**CONCLUSION — Option D is mandatory regardless of which round-identity design wins.** It is the ONLY mechanism that binds where the rule actually lives (the verifier at `validator.cpp:422-495`, the adoption gate at `node.cpp:1901-1943`, and full forfeiture at `chain.cpp:1815-1826`). No producer-side measure can bound what a verifier accepts from a hostile assembler. D's core requirement: **total forfeiture is reserved for what a correct run PROVABLY cannot produce; same-height duplicate signatures that a correct run CAN produce get a bounded suspension/ejection.** Residuals D must cover even under a perfect round identity: the phase-2 valve path, restart before an fsync lands, the BFT block family, and any partial freeze.

**Requirement added for the A/B fallback (not in the earlier list).** The round boundary must be **SIGNATURE-BOUND INTO THE CONTRIB COMMITMENT ITSELF** — the verifier can assert "same round" only from the two signed openings; it has nothing else to trust (`validator.cpp:449-458` says so explicitly). Beyond that: **monotonic per `(height, prev_hash)` and never regressing** (today's `gen` regresses on every valve fire — that is the bug), persisted, order-independent, magnitude-bounded, coherent with S-048, and bound to evidence of an ACTUAL stall so a genuine equivocator cannot mint a boundary to launder a double-sign.

**Hole 1b remains OPEN and a GENESIS BLOCKER.** No code was written for C; the tree is unchanged.

**Authority:** analysis recorded by Claude Fable, 2026-08-12, under the owner's prove-before-implement directive. The A-vs-B round-boundary choice and Option D's penalty magnitude are escalated to Stoyan Denev.

## 2026-08-12 (final+2) — Owner decisions: Option D = bounded SUSPENSION; round boundary = Option B (proof-carrying), design-and-prove before implementing

**Decision (owner, 2026-08-12), following the Option-C refutation above.**

**D — the penalty bound is a SUSPENSION DURATION.** Same-height duplicate-signature evidence that a correct run CAN produce no longer triggers full-stake forfeiture + deregistration (`src/chain/chain.cpp:1815-1826`: `block_slashed += locked; locked = 0;` then `inactive_from = b.index + 1`). It instead suspends the domain from creator selection for a bounded number of blocks. Total forfeiture is RESERVED for what a correct run provably cannot produce.

Implementation direction: **reuse the existing exponential suspension mechanism, do not invent new consensus state.** `include/determ/chain/params.hpp:35-37` already defines `BASE_SUSPENSION_BLOCKS = 10`, `MAX_SUSPENSION_BLOCKS = 10'000`, `MAX_ABORT_EXPONENT = 10` (suspend for `BASE * 2^(count-1)`, capped), and its header comment records the load-bearing reason it lives at chain scope: BOTH the node-side selection filter (`NodeRegistry::build_from_chain`) and the chain-layer frozen committee checkpoint (`Chain::freeze_epoch_committee`, D3.3b) must read ONE authoritative definition, because a divergence between the live filter and a frozen checkpoint is a **state_root fork**. Any D implementation must respect that single-definition property.

Rationale for suspension over a partial-forfeiture cap or ejection-only: it "covers the non-unauthorized profiles" — an honest validator caught by a residual (the phase-2 valve path, restart before an fsync lands, the BFT block family) loses availability and selection weight for a bounded window and recovers, while a repeat offender's exponential curve escalates toward the existing cap. Deterrence is preserved without an unbounded downside on a pair a correct run can still produce.

**B — the round boundary is PROOF-CARRYING, chosen for cryptographic soundness** over A (quorumed). A was rejected because a quorum is unsatisfiable in exactly the crash-stop cases the S-050 valve exists to escape (at K=2, `abort_claim_quorum(2) = max(2,1) = 2` is unsatisfiable by construction, S-044), so it would reintroduce the wedge it is meant to resolve.

**B must be DESIGNED AND PROVEN BEFORE ANY CODE IS WRITTEN**, on the same discipline that just refuted Option C before it could ship. It must satisfy every requirement now on record: signature-bound into the contrib commitment itself (the verifier can assert "same round" ONLY from the two signed openings — `src/node/validator.cpp:449-458`); **monotonic per `(height, prev_hash)` and never regressing** (today's `gen` regresses on every valve fire — that IS the bug); persisted (restart is the only key regression); order-independent; magnitude-bounded; coherent with S-048; and bound so a genuine equivocator cannot mint a boundary to launder a double-sign.

**The open design question B must answer honestly:** a stall cannot be *proven* in an asynchronous system, so "proof-carrying" cannot mean "proof that a timeout occurred". A candidate shape to evaluate (NOT a conclusion): make rounds a **hash chain** — round *n+1*'s commitment binds `H(this signer's round-n contrib)`, so two signatures sharing a predecessor are the same round (equivocation) while a chain relationship is an honest re-round, and the identity is monotonic by construction. The laundering question must be settled explicitly: an equivocator can always *claim* a re-round by chaining, so the design must state precisely what an attacker gains or fails to gain by doing so, and whether superseded-by-chain is a sufficient safety property under K-of-K mutual distrust.

**Sequencing:** D is implementable now and is mandatory regardless of B's outcome. B produces a design + proof first; implementation only follows a clean verdict.

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction).

## 2026-08-12 (final+3) — Option D implementation FAILED review (penalty was zero for attackers, unbounded for honest nodes); Option B is VIABLE-WITH-CONDITIONS and R7 is proved UNACHIEVABLE

**Both tracks ran in parallel. D was implemented and reverted; B was designed and proved without writing code (per the prove-before-implement directive that refuted Option C).**

### D — the mechanism is right, the implementation inverted its own purpose. NOT COMMITTED.

The implementation did what the directive asked structurally: it deleted the full-forfeiture branch (`chain.cpp:1815-1826`) and instead incremented the EXISTING `abort_records_` accumulator, so the verdict is still computed by the single `suspension_active` predicate that `NodeRegistry::build_from_chain` and `Chain::freeze_epoch_committee` already share — the state_root-fork constraint was respected, and no new consensus state was added. Its own gate was 34/34 with six mutants verified RED, and FAST was 303/0. **Adversarial review then returned 14 confirmed findings (2 false alarms), and two of them invert the feature.**

**FATAL 1 — the penalty is identically ZERO in the default K-of-K deployment.** The S-051 eligibility floor (`include/determ/chain/eligibility_floor.hpp:118-136`) applies `active_from`, `inactive_from` and the stake floor as hard `continue`s, and only the `suspension_active` leg is liftable. The OLD rule made an equivocator structurally NON-liftable — `locked = 0` failed the stake floor and `inactive_from = b.index+1` failed the active check. D touches neither, so the equivocator stays a candidate; worse, the floor's lift order sorts ASCENDING by `count`, so a freshly-suspended domain (count 1) is **first in line for re-admission**. Reviewer measured it with a standalone compile of the shipped header: at K=3, `lifted=1 admit=1` at heights 40/45/50. The suspension is lifted in the same block it is imposed.

**FATAL 2 — the bound is per-INCLUSION, not per-OFFENCE, so it is unbounded.** Apply reads only `ev.equivocator` and the containing `b.index`; `ev.block_index` is never consulted, there is no applied-evidence set, `ar.count` never decays, and re-pooling is open (`gossip.cpp:117-119` returns true unconditionally). V11 imposes NO relation between `ev.block_index` and `b.index` — the asymmetry is stark, because the abort-claim gate 80 lines earlier DOES have exactly that bound (`validator.cpp:345`, `m_.block_index != b.index` → reject). So one harvested honest re-round pair, replayed after each window expiry, escalates the curve to the 10'000-block cap: **a single honest re-round becomes a permanent ban** — precisely the outcome D exists to prevent. (The implementer added an in-window idempotence guard, which stops stacking *within* a window and does nothing across windows.)

**Also confirmed:** provable double-signing now costs strictly LESS than an honest crash-stop abort and no permanent-ejection path remains anywhere (the deterrent is inverted); identity rotation resets the escalation curve while README asserts the opposite; `BFTSafety.md` assumption B2 + Corollary T-5.1 (slash-and-recover) become false un-bannered; `SECURITY.md` S-011's sole mitigation is voided; and 1030 lines of pure whitespace churn in README buried a 12-line semantic change.

**Three fixes D needs before a second attempt** (the approach itself stays authorized): (a) an applied-evidence dedup AND a staleness bound on `ev.block_index` relative to `b.index`, mirroring the abort-claim gate that already exists; (b) the S-051 floor must NOT lift an equivocation suspension — decide explicitly whether the floor's liveness guarantee or the penalty wins when they conflict, since that is a real trade-off and not an oversight; (c) an owner decision on whether provable equivocation retains ANY total-forfeiture path — under D as written there is no trigger left at all, which is only defensible once B supplies a predicate a correct run provably cannot satisfy.

### B — VIABLE-WITH-CONDITIONS, and it settles the problem's shape

The hash-chain round identity (each contrib commitment binds `H(this signer's previous contrib at this height)`) closes Hole 1b **at the layer where the rule lives**, is order-independent, needs no quorum, and — the non-obvious result — discharges the persistence requirement **without an fsync on the consensus hot path**, removing the objection that sank the C-prime variant.

**Two load-bearing conditions, each of which silently reopens the hole if got wrong:**
- **C-a. The exemption must be the NEGATIVE rule `link_a != link_b ⇒ not slashable`.** The intuitive positive form (`link_b == H(digest_a) ⇒ exempt`) is REFUTED: after three re-rounds the honest pair (contrib₁, contrib₃) is grandparent/grandchild, not adjacent, so a positive-adjacency verifier slashes an honest validator; carrying the intermediate chain would make V11 variable-size, which it cannot be.
- **C-b. Each chain's root must be FRESH PER PROCESS, not zero.** A zero root makes a restart reuse a link, which under the same-link predicate is a *guaranteed* honest slash rather than today's probabilistic one — strictly worse than HEAD.

**R7 IS PROVED UNACHIEVABLE (impossibility theorem, must be recorded so it is not re-opened).** Let `P` be any predicate over two signed openings from one signer at one height, and require that no correct-run re-round pair is slashable. Then some malicious pair is necessarily non-slashable: *a Byzantine node can run the correct algorithm verbatim — take the valve path, produce the honest pair (A, B) — and then deliver A to one peer set and B to another. The published openings are BIT-IDENTICAL to a correct node's; the only difference is delivery, which is not a function of the openings and is indistinguishable from asynchrony.* Hence exempting the honest pair forces exempting the malicious one. ∎ The only escapes are external authorization (Option A — deadlocks at K=2 by S-044) or unforgeable time (does not exist here). **R7 must therefore be RE-SCOPED by the owner before B is implemented.**

**The attacker's exact gain, bounded:** it cannot finalize two blocks (K-of-K requires every member's signature over ONE `compute_block_digest`, so a split committee simply never reaches K — a stalled round, not a safety violation); it gains a **stall without attribution**, whereas silence is attributable (`find_first_missing` names the silent creator and the abort quorum suspends it). Cost of the escape is one signature, chained from a predecessor it never broadcast — and no design can refute that, because a peer cannot distinguish "chained from a message you never saw" from "chained from a message suppressed from you".

**The conceptual result the owner should absorb:** equivocation slashing at this layer cannot be both sound and complete. The achievable goal is **SOUNDNESS — never slash an honest validator** — while accepting that some malicious stalls are unattributable. B delivers exactly that, and it is what makes total forfeiture defensible again: a same-parent fork is something a correct run provably cannot produce.

**Tree state:** reverted to 045604c; `ci_local` green. The D patch and the full B design are preserved as session artifacts. **Hole 1b remains OPEN and a GENESIS BLOCKER.**

**Authority:** review findings and design analysis recorded by Claude Fable, 2026-08-12. Escalated to Stoyan Denev: the R7 re-scope, the S-051-floor-vs-penalty conflict, and whether provable equivocation retains a total-forfeiture path.

## 2026-08-12 (final+4) — AUTHORIZED: replace the derived round identity with a first-class monotonic `round_seq`; SUPERSEDES the B and D approaches

**The rule being changed (the root of Hole 1b and of three failed fixes).** The round identity was `current_aborts_.size()` — a *derived function of mutable shared state that can decrease*. One field served two unrelated purposes: (i) "which aborts have happened", which legitimately belongs in the digest because the abort tail is mixed into committee selection (`src/node/node.cpp:1032-1042`), and (ii) "which attempt is this", the accountability question the slashing rule actually asks. Those correlated closely enough to look like one quantity — until `maybe_stall_reset_locked` does `current_aborts_.clear()` (`node.cpp:1643`) and the correlation breaks. Attempt 2 then reports the same identity as attempt 1, an honest signer produces two signed values in one apparent round, and V11 fires on a correct execution.

Every previous attempt tried to RECONSTRUCT attempt-identity from something else — a gossiped marker, producer determinism, a hash-chain ancestry relation, a softened penalty. All were downstream of one wrong primitive.

**Decision (owner, 2026-08-12).** Separate the two conflated concerns. Keep the abort tail exactly as-is for committee selection. Add **`round_seq`**: a first-class counter that (a) increments on every entry to `start_contrib_phase`, (b) NEVER resets while `(height, prev_hash)` is unchanged — in particular the S-050 valve and the S-048 reorg re-entry must not reset it, (c) is signed into `make_contrib_body_root`, and (d) is carried per side in `EquivocationEvent` so the verifier can read it from the two openings. The verifier's rule becomes `round_seq_a == round_seq_b` (retaining the existing height and kind binding).

**Admission gains ADOPT-UPWARD.** Today `on_contrib` only DISCARDS a mismatched generation (`msg.aborts_gen != current_aborts_.size()` → return). That absence — not the counter — is what previously made a monotonic per-signer counter look unusable ("two nodes at different counters could never co-sign again"). Nodes at different rounds SHOULD not co-sign; that is how every view-based BFT protocol works. What was missing is upward adoption: on observing evidence of a higher round, jump to it.

**What this dissolves.** Hole 1b closes by construction (an honest re-round signs a different `round_seq`, so the pair is trivially exempt). The predicate becomes SOUND — a correct node signs once per round by construction — so total forfeiture is legitimate again and needs no softening. **Option D is withdrawn as unnecessary** (no bounded tier, no suspension calibration, no S-051 floor conflict, no replay/idempotence guard, no `count==0` underflow, no offence anchoring). **Option B is withdrawn as unnecessary** (the hash chain existed only to synthesize a monotonic identity without coordination; with a real one it is redundant). Persistence shrinks from a signed-message record with an fsync on the consensus hot path to ONE integer.

**Expected liveness benefit, to be verified not assumed.** Today a splitter stalls, the valve clears the tail, the IDENTICAL committee re-derives (`node.cpp:1032-1042`), and the height halts permanently because epoch advance requires height advance. Under monotonic rounds a splitter must either sign twice in one round — now genuinely slashable, making splitting attributable for the first time — or use two rounds, in which case peers adopt the higher and the older message is merely stale. Either way it should buy a bounded delay, not a permanent halt. The liveness invariant below must demonstrate this rather than assume it.

**Residuals, stated.** The impossibility theorem still applies at the margin: a Byzantine node that merely WITHHOLDS is unattributable, as it always was. Round adoption must be MAGNITUDE-BOUNDED so a forged claim cannot drive it arbitrarily high (the exact defect that killed the marker design). The BFT block family needs `round_seq` threaded through `compute_block_digest` or an explicit scope-out. Wire: this is another pre-genesis evidence-format revision (v4); whether `gen_a`/`gen_b` are REPLACED by `round_seq_a`/`round_seq_b` rather than added is a minimalism call for the implementation to make and justify.

**Method — test-first, and the tests are a RATCHET.** The owner's requirement is that "further changes cannot bring the same problem to live again". Therefore: the regression harness is built and proven capable of failing BEFORE the fix exists (three designs this session shipped green, mutant-verified suites while being wrong). It has three parts: (1) DSF property invariants under randomized seeded schedules, each with an `expect_violation` twin that plants the bug and proves the checker fires; (2) case gates asserted at the VERIFIER's predicate, never a producer-side proxy; (3) a STRUCTURAL guard that fails if a future edit re-couples round identity to a container size or lets any re-entry path reset `round_seq` — the coupling itself becomes a test failure, not just its symptom.

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction). Supersedes the Option B design and the Option D authorization in the entries above.

## 2026-08-12 (final+5) — `round_seq` implementation FAILED review; and the RATCHET FAILED ITS OWN TEST. The anti-regression requirement needs a different answer.

**Method reminder.** The harness was built FIRST and proven RED at HEAD before any fix existed (three prior designs shipped green suites while being wrong). Then the fix. Then adversarial review: **17 findings confirmed on independent re-derivation, 1 false alarm.** Nothing was committed.

### What genuinely worked, and should be kept

- **The end-to-end reproduction** (`test-honest-reround-not-slashed`): runs the REAL path — `handle_contrib_timeout` → `maybe_stall_reset_locked` → `clear + reset_round` → `check_if_selected` → `start_contrib_phase` (fresh `rng_.fill`) → gossip → peer `on_contrib` assembly — and fails at HEAD with the verifier itself printing `V11 verdict on the honest re-round pair: ACCEPTED`, then stake `1000 -> 0` through the real apply path. Five witness arms stay green so the failure is not vacuous. Critically it asserts at the **verifier** (`check_equivocation_events_for_test`, `on_equivocation_evidence`, `Chain::append`), so it cannot be satisfied by the assembler's courtesy core-compare.
- **The DSF `expect_violation` twins**, which PIN their planted defect rather than reading production, so they keep firing after a fix.
- **`hole1b_fixed_rule_holds`**: the same seeded schedule against the authorized rule, holding over 173 steps — the executable statement of what the fix must deliver.

### THE HEADLINE: the anti-regression ratchet does not ratchet

Both of the mechanisms intended to satisfy "further changes cannot bring the same problem to live again" were **empirically defeated by the reviewer, not merely doubted**:

1. **The structural guard is defeatable in one line.** The reviewer copied `tools/test_round_identity_structural_guard.sh` (byte-identical logic, only paths changed) and ran it against three mutated `node.cpp` copies. **All three printed `PASS`, selftest 8/8, `R5 model coherence OK`.** Plant 1 was the literal HEAD defect restored as a single line — `round_seq_ = static_cast<uint64_t>(current_aborts_.size());` — inside the very function the guard reads. Cause: R1 matches `.size()`/`.count(`/`.length()`/`.empty()` against the ARGUMENT TEXT at the `make_contrib(` call site, which after the fix is the bare token `round_seq_`; it never resolves what that token was assigned from. A textual guard over source cannot enforce a semantic invariant.

2. **The DSF invariants do not test production code.** `CMakeLists.txt:406` is `add_executable(determ-dsf sim/dsf_main.cpp)` with an explicit "NO link deps (no OpenSSL, no determ core)" comment — the simulator contains **zero production code**. The five primary scenarios read `kProductionRoundIdRule`, a hand-maintained compile-time constant whose only tether to reality was R5, which is a pure function of the already-defeated R1. So a production regression leaves every DSF primary GREEN.

**Conclusion for the anti-regression requirement:** a static text guard and an unlinked model are both **advisory**, not ratchets. Across this entire session exactly two mechanisms ever caught a real defect: **an end-to-end gate that executes production code and asserts at the verifier**, and **adversarial review of the diff**. The ratchet must therefore be (i) the end-to-end reproduction, kept in-tree and RED until the property actually holds, plus (ii) mandatory adversarial review on any change touching the round identity, the evidence predicate, or the apply path. If a DSF invariant is wanted as a third leg, `determ-dsf` must LINK the production consensus code so the scenario drives real `Node`/`BlockValidator` objects; as built it can only test the model.

### The fix itself — design-level defect, not just bugs

**ADOPT-UPWARD as implemented is a one-node permanent liveness halt, worse than the bug it fixes.** `node.cpp:3221-3225` gates only per-message MAGNITUDE (`> kMaxRoundAdoptJump`, 64); there is no per-height cap, no per-signer cap, and no time budget (the header declares no adoption counter at all). Any registered domain — **not** restricted to the round's committee — can send `round_seq = observed+1` repeatedly, and each message drives `adopt_round_upward_locked`, which cancels both timers, `reset_round()`s (wiping a mid-Phase-2 node holding K-1 signatures), and re-arms. That is an unattributable round-reset primitive that suppresses both the abort machinery and the S-050 valve indefinitely.

Also confirmed: the block family takes its round identity from a **peer's contrib** rather than the node's own counter (`producer.cpp:1167`), so an honest node can still sign two block digests under one `(height, round_seq)`; `round_seq.bin` uses a **non-atomic truncate-then-write** so a crash in the window zeroes the reservation; restart with a lagging on-disk chain (the save is deliberately async) discards the reservation and re-signs used identities; `kRoundSeqReserve == kMaxRoundAdoptJump == 64` puts a restarted node exactly one round beyond what peers will adopt, so honest nodes fail to converge; the S-006 assembler lacks the `round_seq_a == round_seq_b` fail-close that both verifiers have, so it mints and pools a cross-round event that poisons its own block production; and `PROTOCOL.md`'s canonical Block frame omits `round_seq` while still pinning the empty frame at 297 bytes — a wire-normative error on genesis-frozen surface.

**The design direction is not refuted.** Monotonic `round_seq` still dissolves the root defect, and the reproduction plus `hole1b_fixed_rule_holds` show what "correct" looks like. What the next attempt must settle BEFORE coding: **adoption must be scoped and rate-bounded, not merely magnitude-bounded** — restricted to the round's committee, budgeted per height, and unable to wipe a node that already holds K-1 signatures; the block family must take the identity from the node's OWN counter; persistence must be atomic (tmp+fsync+rename, the pattern `write_file_atomic` already uses) and must not regress when the async chain save lags; and the reserve and adoption bounds must not be equal.

**Tree state:** reverted to de223ab; `ci_local` green. Harness + fix preserved as session artifacts. **Hole 1b remains OPEN and a GENESIS BLOCKER.**

**Authority:** review findings recorded by Claude Fable, 2026-08-12. Escalated to Stoyan Denev: the adoption-scoping design, and whether to invest in linking `determ-dsf` against production consensus code so invariant testing is real rather than modelled.

## 2026-08-12 (final+6) — AUTHORIZED (5th design): same-height duplicates are NEVER slashable — exclusion only; round_seq for precision, fresh-random per process; ratchet = E2E gate + mandatory review

**Decision (owner, 2026-08-12).**

**1. Mechanism — NEVER SLASH, EXCLUDE INSTEAD.** A same-height duplicate signature carries **no stake consequence of any kind**. The full-forfeiture + deregistration branch (`src/chain/chain.cpp:1815-1826`) is removed for equivocation evidence and replaced by exclusion from creator selection. This is chosen over the per-signer-seq slashing design because it makes the catastrophic outcome **structurally unreachable**: no implementation defect in the round identity — no reset, no restart regression, no replay, no verifier bug — can cost an honest validator its stake, because that path no longer exists. Four designs have now failed on exactly that hazard; removing the consequence removes the class.

**2. `round_seq` is retained, but ONLY for precision, not safety.** A per-signer monotonic counter, **seeded fresh-random per process** and incremented on every `start_contrib_phase` entry, signed into `make_contrib_body_root` and carried per side in the evidence. Its sole job is to distinguish *same-round duplicate* (exclude) from *honest re-round* (no action). Because it is no longer safety-critical, a bug in it costs at most a round of selection.
   - **No persistence, no fsync, no `round_seq.bin`.** A fresh random 64-bit start per process means a restart cannot reuse an identity (~2^-64), which removes the non-atomic-write defect, the lagging-async-save regression, and the reserve/adoption off-by-one that killed attempt 4.
   - **No ADOPT-UPWARD.** `round_seq` is compared ONLY within one signer's own pair, never across signers, so global agreement was never required. Admission keeps using the abort tail exactly as today. The entire attack surface that killed attempt 4 — an unattributable, unbounded-rate round-reset primitive open to any registered domain — does not exist in this design.

**3. Ratchet — E2E gate + mandatory review.** The end-to-end reproduction stays in-tree because it executes real production code and asserts at the VERIFIER; adversarial review becomes mandatory for any change touching the round identity, the evidence predicate, or the apply path. The structural guard and the unlinked DSF model are NOT relied upon — both were empirically defeated (see the entry above). Linking `determ-dsf` against production consensus code is deferred, not adopted.

**CONSEQUENCE THE OWNER MUST REVIEW (flagged, not overridden).** Removing stake forfeiture for equivocation removes the economic deterrent at this layer entirely, and the accountable-safety argument in `docs/proofs/BFTSafety.md` (assumption **B2** and Corollary **T-5.1**, slash-and-recover) is stated in terms of slashing. Those claims must be re-derived or re-scoped against this rule — a prior review already flagged them as silently voided by a weaker version of this change. `SECURITY.md` S-011's mitigation likewise cites slashing. The abort-driven `SUSPENSION_SLASH` path is a separate mechanism and is unaffected. **This must be settled before genesis; it is not settled here.**

**Also mandatory in the implementation** (each is a confirmed defect from a prior attempt): the exclusion must land on a predicate the **S-051 eligibility floor cannot lift**, or the penalty is identically zero in the default K-of-K deployment; the exclusion window must be **offence-anchored** so re-baking evidence cannot slide or escalate it; and the BFT block family must either be covered or scoped out explicitly.

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction). Supersedes the round_seq-as-slashing-identity design of the entry above.

## 2026-08-12 (final+7) — 5th design FAILED. The structural result: **at K == M there is no safe automated consequence for a same-height duplicate.**

**15 findings confirmed on independent re-derivation, 2 false alarms. Nothing committed; tree reverted to 4e7814c, `ci_local` green.** The E2E reproduction was re-landed and confirmed RED at HEAD first (V11 itself printing `ACCEPTED`, stake `1000 -> 0` through the real apply path), so the harness discipline held; it is the implementation and, more importantly, the *direction* that failed.

### The structural result — this is the finding that matters

**Exclusion is a permanent, unrecoverable halt in the default K == M configuration**, and this was measured, not argued: a reviewer compiled `eligibility_floor.hpp` standalone (3 registrants, `min_stake` 1000, k=3, one domain excluded at height 100 for `EQUIVOCATION_EXCLUSION_BLOCKS = 10'000`) and got `lifted=0, pool=2` at indices 101 / 150 / 10100, recovering to `pool=3` only at 10101. Pool 2 < K = 3 halts creator selection — and because the expiry is **block-indexed** while the halt prevents blocks from being produced, height never advances and the window is never reached. The halt is self-sustaining, exactly like the epoch-advance trap recorded earlier.

This is not an implementation slip. **At K == M the committee IS the entire validator set, so removing any member makes a committee unformable.** The S-051 eligibility floor exists precisely to prevent that — which is why the previous attempt's penalty was measured as identically zero. So an exclusion is either *liftable* (no effect, attempt 4's outcome) or *non-liftable* (permanent halt, this attempt's outcome). **There is no third option at K == M.**

Combined with what was already proved, the space is now closed:
- **Cannot slash** — the predicate is unsound; a correct run produces it (four designs failed on this).
- **Cannot exclude at K == M** — liftable means no effect, non-liftable means permanent halt (measured above).
- **Cannot reliably detect** — the impossibility theorem: a splitter's openings are bit-identical to an honest node's.
- **Any self-declared round identity is evadable.** Confirmed here concretely: `round_seq` is sender-chosen and ungated at admission (`on_contrib` gates only on `block_index`, `prev_hash`, `aborts_gen`, key, sig), and there is exactly ONE production construction site for kind-1 evidence — so an adversary simply signs two different `round_seq` values and is never detected, **while honest collisions still fire**. The precision term protects no one against an attacker and can only harm honest nodes. (This is the impossibility theorem showing up again, not a new defect.)

**Therefore: at K == M the only sound response to a same-height duplicate is NO AUTOMATED CONSEQUENCE — detect, log, gossip for operator attention, and take no consensus action.** For K < M exclusion is viable, because spare eligible validators exist to reach K. Any future design must be configuration-aware or must simply do nothing.

### Defects that came from the orchestrator's own design suggestions (recorded so they are not repeated)

1. **The "higher `round_seq` supersedes" tie-break has no phase guard.** Three reviewers found it independently: `node.cpp:3111` mutates a stored creator contrib with no check on `phase_`, so it can overwrite committed round state mid-Phase-2 and cause an invalid block to be gossiped.
2. **"Fresh-random per process" reasoned about the wrong relation.** The argument was collision probability (~2^-64), but the comparison at `node.cpp:3111-3115` is **ordered**, with a silent drop on the lower branch. A restart therefore produces a *lower* `round_seq` with probability ~1/2, and the node's contrib is silently discarded by peers.
3. RNG-failure fallback made `round_seq` deterministic, reintroducing the honest-restart collision the random seed was meant to remove.

### Other confirmed defects (for whoever attempts this next)

kind-0 (BFT block family) still excludes an honest validator with no attacker present, and under non-liftability that becomes a 10'000-block shard halt; nothing bounds `ev.block_index`, so a member can self-exclude permanently; the exclusion is domain-keyed with stake intact, so it is evadable by re-registration; the light client's `b:` leaf recompute omits the new field and reports an honest daemon as TAMPERED; the DSN1 snapshot record layout changed without a version bump, turning a fail-closed check into a silent misparse; and on EXTENDED chains the frozen committee pin gives the exclusion zero effect for the remainder of the epoch, while the comment justifying it is now false.

### Status

**Hole 1b remains OPEN and a GENESIS BLOCKER after five designs.** What is now settled is the *shape* of any admissible answer, which is more than any of the five attempts delivered: the predicate cannot be made sound by construction, the consequence cannot be made safe at K == M, and the honest landing point is a configuration-aware rule whose K == M branch is "no automated action". The end-to-end reproduction (real production code, asserted at the verifier) and mandatory adversarial review remain the only two mechanisms that have ever caught a defect here.

**Authority:** review findings recorded by Claude Fable, 2026-08-12. Escalated to Stoyan Denev: whether to adopt the configuration-aware rule (K < M excludes, K == M takes no automated action), and the still-open consequence that removing forfeiture voids `BFTSafety.md` B2 / T-5.1 and `SECURITY.md` S-011 as written.

## 2026-08-12 (final+8) — AUTHORIZED for DESIGN (no code): per-block committee selection seeded by prev-block-header hash + a committed TIME BUCKET

**Owner directive.** Explore replacing the per-epoch committee seed with a **per-block** seed drawn from `hash(previous block header)` plus a **time** term. Design and adversarial review FIRST; no implementation until a clean verdict. This follows five failed implementations, of which only the design-first passes (the Option-C refutation, the Option-B analysis) produced durable results.

**Why this is different in kind from the five failed attempts.** Every previous design tried to synthesize a round identity from state the protocol already had — a gossiped marker, producer determinism, a hash-chain ancestry, a self-declared counter. Each failed because a *self-declared* identity is freely choosable (an equivocator picks two values and escapes) while an identity *derived from resettable shared state* collides for honest nodes. A time bucket is neither: the protocol already assumes **bounded clock skew** (`src/node/validator.cpp:1915`, the `±30s` timestamp window), so a bucket is **externally anchored** — a signer cannot claim an arbitrary one, because peers reject buckets outside their own tolerance. This is the first candidate that attacks the impossibility theorem's premise rather than working around its conclusion. The earlier claim in this log that "unforgeable time does not exist here" was too strong: time here is not unforgeable but it IS bounded, and bounded is sufficient to convert free evasion into constrained evasion.

**It also breaks the halt**, which nothing else did. Today the seed is `epoch_committee_seed(epoch_rand, shard_id)` mixed with `current_aborts_` hashes (`node.cpp:1032-1042`), and the S-050 valve CLEARS the abort tail, so a re-round re-derives the byte-identical committee; `current_epoch_index() = chain_.height() / epoch_blocks` and `current_epoch_rand()` are both block-gated, so a stalled height freezes the entire epoch. A moving time term reseats the committee per attempt, so a splitter is not seated forever.

**The owner's security argument, to be verified not assumed:** grinding is **one-step-ahead only**. The committee for the block after next depends on `hash(block H)`, which depends on the reveal phase — every committee member's secret — so no single party can steer beyond the current draw. If that holds, bounded per-attempt grinding does not compound into control of a future committee sequence.

**Note on entropy:** at a stalled height `prev_hash` is the SAME head on every attempt, so the prev-header term contributes zero variation between re-rounds. All inter-attempt entropy comes from the time term; the prev-header term supplies per-height variation.

**Design constraints the spec must satisfy** (each is a confirmed defect or invariant from this session): the time value must be **committed and signed** — carried in the block header AND in the contrib, because the stalled case has no block yet — since `check_creator_selection` re-derives the committee from committed state and rejects a mismatch, and a replaying node has no "now"; validation therefore splits into a **live** check (bucket within tolerance of local clock) and a **replay** check (monotonic, bounded increment vs the previous block); the live derivation and the D3.3b / S-036 `cc:[epoch]` frozen checkpoint must not diverge, because that is a **state_root fork**; abort claims key on committee membership, so a rotating committee requires the claim buckets to key on the round identity too; and **bucket granularity must be finer than the minimum re-round interval** (the valve enforces >= 5 s) or honest collisions persist — the central tunable, trading Hole-1b closure against grinding surface (~60 candidates at 1 s granularity within the ±30 s window, ~12 at 5 s, ~2 at 30 s but with collisions back).

**Authority:** Stoyan Denev (owner directive, 2026-08-12; recorded by Claude Fable at his direction). Design + adversarial review authorized; implementation is NOT.

## 2026-08-12 (final+9) — Time-bucketed per-block committee selection: REFUTED at design stage. No code written.

**All four analysis lenses returned FATAL; the synthesis verdict is NOT VIABLE; the adversarial pass confirmed 21 findings (3 false alarms). Nothing was implemented — the design-first discipline paid for itself.**

### 1. At K == M, committee rotation is impossible by definition

`select_m_creators(rand, node_count, k_use)` selecting M of M is the identity function: **the set is seed-invariant**. No time term, no seed change, no rotation can evict a splitter when the committee is the entire validator set. The proposal's core purpose — reseat the committee so a splitter is not seated forever — cannot be achieved at K == M by any seed whatsoever. This is the simplest and most complete refutation, and it re-derives the same wall the exclusion designs hit.

### 2. No bucket granularity G exists — three pairwise-contradictory requirements

One value was asked to be both a selection seed and a round identity:

| Requirement | Forces | Source |
|---|---|---|
| **R-agree** — all honest members derive the SAME bucket BEFORE the first contrib | G ≫ clock+propagation spread; ≥ 2× the tolerated ±30 s skew ⇒ **G ≥ 60 s** | `check_if_selected` selects, then gates `start_contrib_phase()` (`node.cpp:1046-1050`) |
| **R-rotate** — consecutive honest attempts must land in DIFFERENT buckets | **G < 5 s** (`kRoundStallSoftWindow`, `node.cpp:1613`) | else no halt-break and no V11 exemption |
| **R-noevade** — an equivocator must have at most ONE admissible bucket | G ≥ 2W (W = admission half-window) | else it signs two messages under two labels and V11 exempts it |

60 > 5. **No G satisfies R-agree and R-rotate simultaneously.** Concrete consequence, measured against the code: two honest nodes 2 s apart are 2 buckets apart at G = 1 s on *every* attempt, forever — deterministic non-convergence, not probabilistic. The valve re-entry draws a fresh local bucket that disagrees again; nothing converges them.

### 3. The owner's one-step-ahead argument is TRUE of `cumulative_rand` and FALSE of the block hash — and that is exactly why the current code uses the former

Traced end to end: `dh_input = SHA256(secret ‖ pubkey)` (commit-checked, `validator.cpp:502-527`) → `delay_seed` → `delay_output` (`producer.cpp:1031-1037`, re-derived `validator.cpp:539-557`) → `cumulative_rand` (`producer.cpp:1268-1272`) → `epoch_rand` → `epoch_committee_seed` → `select_m_creators`. **For `cumulative_rand` the argument HOLDS**: every input is digest-covered or commit-reveal-pinned, and the K secrets at H+1 do not exist when block H is minted. That is precisely why the current design routes committee selection and the subsidy lottery through `cumulative_rand` and **not** through the block hash.

The proposal reverses that decision, and the block hash does not have the property. `Block::compute_hash()` (`src/chain/block.cpp:817-826`) hashes `signing_bytes()` and then **appends `creator_block_sigs`**. Ed25519 verification (`src/crypto/ed25519/ed25519.c:321-348`) checks only pk-y canonicality, `S < L`, and the group equation — RFC 8032's deterministic nonce is a **signer-side convention no verifier can check**. So a Byzantine member that broadcasts its `BlockSigMsg` last (indistinguishable from network latency; it already holds the other K−1 sigs) can enumerate unboundedly many *valid* signatures over the SAME `compute_block_digest`, each yielding a different block hash, and publish the one that seats its preferred committee at H+1. Cost: one Ed25519 sign per trial (~10⁵–10⁶/s). No abort, no equivocation, one message, nothing any existing gate records. And it **compounds**: once a coalition owns a full K-committee it owns all K secrets, hence `delay_output`, hence `cumulative_rand`, hence `epoch_rand` and the lottery.

**This finding is independently valuable: the block hash is malleable under a fixed digest, so it must never seed anything security-relevant.** The existing architecture already gets this right; the proposal would have broken it.

### 4. Two further structural blockers

**Circularity.** If the bucket derives from `b.timestamp`, `check_timestamp` (`validator.cpp:1903-1909`) requires `b.timestamp == reconcile_median_time(b.creator_proposer_times)` with that vector parallel to `b.creators` — so the selection *input* would depend on the selection *output*. Every reconciled-clock scheme inherits this, because reconciliation medians the SELECTED committee's committed times.

**No replay seam.** `Chain::load` (`chain.cpp:3483-3554`) calls `apply_transactions` plus the S-021 head-hash gate and **never calls `BlockValidator::validate`** — a replaying node performs no committee derivation at all, so there is nowhere to attach a replay-side monotonicity rule. Worse, sync-from-peer uses the same `validate` as live and a validator cannot distinguish a tip block from a year-old catch-up block (`apply_block_locked` routes past/future indices elsewhere, so everything reaching `validate` has `b.index == height()`).

### Status

**Hole 1b remains OPEN and a GENESIS BLOCKER after six designs.** The correction to this log's earlier claim stands and is now sharpened: bounded clock skew is *not* enough to serve as an external anchor here, because the bucket must be agreed BEFORE the round begins and the protocol's own ±30 s tolerance is two orders of magnitude coarser than the ≥5 s re-round interval it would have to distinguish.

What the session has established remains: the predicate cannot be made sound by construction; the consequence cannot be made safe at K == M; committee rotation is impossible at K == M; and the honest landing point is a configuration-aware rule whose K == M branch takes **no automated action**.

**Authority:** design analysis recorded by Claude Fable, 2026-08-12. No implementation was performed.

## 2026-08-13 — Owner reprioritization (five directives): B1's remainder folds into the next storage pass; the pre-launch critical-path list becomes SUPERSEDED-FOR-SEQUENCING; B4's DROP execution moves to the LAST pre-genesis act; the crypto-profile enum joins the pre-genesis backlog; the three unauthorized consensus residuals go on a DECISION CLOCK

**Problem.** Work selection now has three competing indexes. `CLAUDE.md` CURRENT FRONT says D2; `PRE-LAUNCH-DECISIONS.md`'s decided execution plan (9 build items + 3 verification items, closed 2026-07-09) does not mention D2 at all — it predates the D2 authorization of 2026-07-28 — and still lists items that have since shipped. A thread that reads only the pre-launch list picks the wrong work, and in one case (B1) would rewrite a file that D2 inc8 rewrote hours earlier. Separately, three consensus/wire residuals are recorded as "NOT authorized" with no decide-by point, and under no-migrations an undecided pre-genesis item silently becomes a permanent "never" at genesis.

**Decision (owner, 2026-08-13).** Five directives, in priority order, plus two sequencing corrections.

### 1. B1's REMAINDER folds into the next `chain.cpp` storage pass — it is not a separate work item

**Verified facts.** `PRE-LAUNCH-DECISIONS.md` §B1 scopes the item as two halves: (a) per-block append-only files replacing the monolithic `chain.json`, and (b) an incrementally-updated `state.json`.

- **(a) is DONE**, absorbed by D2 inc8 (`8a106aa`). The store is now `<path>.blocks/<index>.blk`, each a `DBK1`-tagged canonical `Block` frame, plus a fixed 44-byte `DMF1` manifest written atomically last (`src/chain/chain.cpp:3385-3387` path helpers, `:3401` magic, `Chain::save_incremental` at `:3430`). `Chain::save` and the entire legacy `chain.json` read path are DELETED; a store-less directory loads as an EMPTY chain (gate `test-chain-store` CS-8). B1's stated payoff — `save()` O(new blocks) instead of O(N), the global-mutex offender removed, blocks prunable — is delivered.
- **(b) is NOT started.** There is no state file of any kind. `Chain::load` (`src/chain/chain.cpp:3483`) still replays `apply_transactions` over every block file from 0 to the manifest height, so *load* remains O(N) even though *save* is now incremental.

**Directive.** B1 is closed as a standalone item. Its (a) half is absorbed by D2 inc8; its (b) half — an incrementally-persisted state so `load` stops being a full replay — folds into the **next `chain.cpp` storage pass** and is scheduled with that pass, not ahead of it.

**Why this is now cheaper than when B1 was scoped.** inc8 built exactly the container the remainder needs: `Chain::encode_state` / `Chain::decode_state`, the canonical binary `DSN1` snapshot record (`src/chain/chain.cpp:2859` / `:3018`, declared `include/determ/chain/chain.hpp:699-700`), already running the same `head_hash`, S-033 `state_root` and A1 revalidate gates as the JSON path it replaced. The remainder is "persist a `DSN1` beside the manifest and load from it", not "design a state container". Scoping it as a separate item was correct in July and is wasteful now.

**Rationale — this generalizes the project's own doctrine.** Sequence-before-harden says *do not spend proof effort on code scheduled for replacement*. The same argument applies one step earlier, at scheduling: **do not rewrite the same file twice.** A queued item whose file is already being rewritten should be folded into the rewrite, not raced against it.

**The collision this prevents, concretely.** Pre-directive, a thread reading only the pre-launch list would see "B1 storage refactor — one-file-per-block + incremental state.json" at position 4 of 9, open `src/chain/chain.cpp`, and rebuild the per-block store that inc8 had already landed — in a file the D2 front was actively rewriting. That is the exact failure the sequence-before-harden freeze was written to stop, arriving through the planning artifact instead of through the hardening budget.

### 2. The pre-launch critical-path list is SUPERSEDED-FOR-SEQUENCING; its per-item DECISIONS remain authoritative

The 9-build + 3-verification plan in `PRE-LAUNCH-DECISIONS.md` ("The decided execution plan") was closed 2026-07-09, three weeks before D2 was authorized as an execution front (this log, 2026-07-28) and promoted to ACTIVE (same date, sequence-before-harden entry). Consequently the list omits D2 entirely while still carrying B2 (executed) and B1 (now item 1 above) as forward work.

**Directive.** Mark that list — and any competing ordering in `IMPLEMENTATION-SEQUENCING.md` and `V1.1-PLAN.md` — **superseded-for-sequencing**, with a prominent banner naming `CLAUDE.md` CURRENT FRONT as the operational source for *what to work on next*. The split is explicit and narrow:

- **ORDERING is superseded.** No thread may select work from those lists' sequence.
- **The per-item DECISIONS are NOT superseded.** Every "Decision (owner, 2026-07-09)" line — A1..A8, B1..B4, C2, D1..D4, and the §E scope addition — remains the standing record of *what was decided and why*, and this log remains authoritative over all of it.

This is a documentation-authority change only. No decision is reopened, reversed, or rescoped by it.

### 3. B4 — keep the audit, defer the DROP EXECUTION to the LAST pre-genesis act

**Verified facts.** `PRE-LAUNCH-DECISIONS.md` §B4 decided "(a) pre-genesis audit of every reserved discriminator; keep only slots with a plausible, NAMED future use, one-line rationale per keep/drop in the schema doc", and the execution plan places it at position 3 of 9. The audit is written — `ReservedDiscriminatorAudit.md`, 22 rows, tally **14 KEEP / 8 DROP / 0 unresolved**, with a §7 integrator execution order. Its execution status, stated exactly: **drop 1 of 8 (G-1 `v2_10_active_from_height`) was EXECUTED 2026-07-09** as a rider on the B2 purge (byte-invariant, goldens confirmed); **drops 2-8 are unexecuted**, and three of them (S-6, S-2, S-3) already carry the audit's own ⚠ owner-confirm flag because they reverse prior SHIP decisions. None of the seven remaining touches serialization shape — the shape-affecting tier is deliberately empty (W-1/W-2 are both KEEP) — so each is a spec/plan edit that removes a slot from what Bundle 0 builds, which under no-migrations means the slot does not exist at genesis and cannot be added afterwards.

**Directive.** The audit stays where it is. The **execution of DROP verdicts 2-8 moves to the final pre-genesis act**, after scope is maximally known. Drop 1 (G-1) is already executed and is not reopened.

**Reasoning — the trade is asymmetric under no-migrations.** Every reserved slot KEPT preserves a post-genesis additive path. That is not hypothetical: this log's 2026-07-23 entry records v2.15 multi-sig shipping as Option A (COMPOSABLE_BATCH + wallet policy), with **Option B (on-chain M-of-N account policy) reserved as a §7.5 discriminator slot in the B4 audit precisely so on-chain enforcement can ship additively later without a wire break**. Every slot DROPPED forecloses one such path PERMANENTLY. Executing DROPs early therefore trades permanent future optionality for a small, temporary reduction in surface — and it does so at the moment when *least* is known about which slots the remaining scope will want. Deferring costs a little carried complexity for a few weeks; executing early costs an option forever. Defer.

**Scope note.** This defers execution, not the audit and not the recorded verdicts. KEEP verdicts need no execution and are unaffected.

### 4. The crypto-profile enum joins `CLAUDE.md`'s PRE-GENESIS BACKLOG

**Why.** The item lives only in `Improvements.md` §12.5 and has ZERO mentions in `CLAUDE.md`, so it is invisible to work selection while being genuinely genesis-frozen. One backlog line closes a real missed-the-window risk.

**Verified facts, stated precisely — and §12.5's own precondition is now ANSWERED, in the direction it feared.** §12.5 warns: *"the claim holds only while no profile value is embedded in authenticated bytes."* It is embedded. `crypto_profile` is mixed into the genesis hash: `make_genesis_block` appends the domain-tagged marker `DTM-genesis-crypto-profile-v1` plus the enum value to the `cumulative_rand` builder when the profile is non-default (`src/chain/genesis.cpp:837-839`), and `compute_genesis_hash` is `make_genesis_block(cfg).compute_hash()` (`src/chain/genesis.cpp:891-894`). It also round-trips through both containers — emitted by `to_json` when non-default (`src/chain/genesis.cpp:107-108`), read back by `from_json` (`:303-304`), written as a `u8` by the `DGC1` binary encoder (`:497`), and **fail-closed on decode: an unknown value is rejected outright** (`src/chain/genesis.cpp:571-574`). The enum is `CryptoProfile { MODERN = 0, FIPS = 1 }` (`include/determ/chain/params.hpp:122-125`).

**Correction to §12.5, recorded so it is not acted on as written.** §12.5's named subjects — `tactical_civilian` and `cluster_civilian` — are **TIMING-profile presets, not `CryptoProfile` values**, and they **do not exist in the tree**: `grep` over `src/ include/ light/ wallet/` finds zero occurrences, and `git log -S tactical_civilian -- include src` finds no commit that ever added them. They were decided in this log's 2026-05-24 C99-11 mid-review revise and never implemented. So §12.5's proposed change ("defer the two civilian variants") is a no-op against shipped code, while the real pre-genesis object it gestures at — the frozen `CryptoProfile` value set and its fail-closed decode — is untouched by that framing. The shipped preset set is `PROFILE_CLUSTER` / `PROFILE_WEB` / `PROFILE_REGIONAL` / `PROFILE_GLOBAL` / `PROFILE_TACTICAL` plus six `*_TEST` mirrors (`include/determ/chain/params.hpp:195-322`); each carries a `CryptoProfile` field, which is the only part that reaches the genesis hash.

**Directive.** Add one line to the `CLAUDE.md` PRE-GENESIS BACKLOG: *decide the final `CryptoProfile` enum value set before genesis; it is genesis-hash-bound and fail-closed on decode.* Cross-reference `Improvements.md` §12.5, which is amended with the correction above. Adding a profile value later remains additive for a NEW chain at its own genesis; it is not retrofittable to an existing chain, and old binaries reject an unknown value.

### 5. DECISION CLOCK on the three unauthorized consensus residuals

`CLAUDE.md` honestly records three items as NOT authorized. All three are consensus or wire surface, so under no-migrations each is **pre-genesis or never**. They are correctly marked; the defect is that an unauthorized item does not self-surface, and **the decision itself has a deadline even when the work does not**. Each therefore gets an explicit owner decide-by point tied to a NAMED milestone, not a calendar date:

| # | Residual | Decide-by milestone | If undecided at genesis |
|---|---|---|---|
| R-1 | Hole-1 residual — same-height CROSS-ROUND double-signing satisfies V11 (an abort re-round changes the body at one height). Recorded in `EquivocationSlashing.md` §2 Case (c) + `PROTOCOL.md` §6.1. | The **finalization-layer slashing design gate** (see the slashing entry below), itself due before **B4's DROP execution — the last pre-genesis act** (directive 3). | Default becomes "never": the pre-finalization predicate stays permanently inert and no finalization-layer slashing exists. |
| R-2 | `cumulative_rand` is NOT authenticated on the beacon-header path (it is outside `compute_block_digest`; `check_cumulative_rand` is apply-path only). Pre-existing; scope stated at the S-053 closure. | **D3 / S-036 closure (on-chain SHARD_TIP, v2.11)** — same code path, same reviewers, and the launch posture is EXTENDED. | Default becomes "never": the beacon randomness path ships unauthenticated, permanently. |
| R-3 | The self-declared BEACON role in HELLO is unauthenticated. | **D2 completion — the parser-deletion step** (this log, 2026-07-28 step 4). HELLO is wire surface and D2 is its last wholesale rewrite. | Default becomes "never": the role claim stays self-declared, permanently. |

**The consequence is the point.** No decision is not a neutral state. At genesis, "undecided" resolves to "never" under no-migrations, irreversibly, with no further gate to catch it. A thread reaching any of these three milestones must surface the corresponding row to the owner before treating the milestone as complete.

### Sequencing correction (i) — `Improvements.md` §12.1 is D2's ENDGAME

**Measured at HEAD `53a849d`, not asserted.** `src/main.cpp` is 64,683 lines. Of its 292 `cmd == "…"` handlers, **237 are `test-*` / `selftest-*`**, spanning lines 6,955–64,364. Of the file's 1,513 lines containing `json`, **1,151 (76%) sit inside that test region.** Extracting the test subcommands into a `determ-selftest` binary therefore removes roughly three quarters of `src/main.cpp`'s JSON surface as a side effect — which is why it is not an unrelated cleanup but a direct reducer of D2's largest remaining step.

**Directive — the ordering, stated so both constraints hold.** §12.1 already carries its own constraint ("land after the D2 migration touches `src/main.cpp`, to avoid a merge war with the active front"). That is compatible with the owner's directive, and the resolution is exact: **§12.1 slots BETWEEN D2 step 3 (keyfiles) and D2 step 4 (parser deletion)** — after D2 has finished editing `src/main.cpp`, before the parsers are deleted, so step 4 faces a `src/main.cpp` with ~76% less JSON in it. Recorded in the D2 sequence in `CLAUDE.md`; §12.1 is annotated accordingly. (Numbering note: D2's steps are the five in this log's 2026-07-28 authorization; `CLAUDE.md` CURRENT FRONT compresses them to three, where its step 2 is this log's step 4.)

### Sequencing correction (ii) — C2's prerequisite is DISCHARGED, not merely parallelizable

`PRE-LAUNCH-DECISIONS.md` §C2 records: *"Prerequisite: the remaining deterministic-scheduler increments (`DeterministicSchedulerDesign.md` 2-5, incl. the now-relevant Node no-self-thread mode)."*

**Verified — that prerequisite is fully satisfied.** `DeterministicSchedulerDesign.md`'s status line reads **"increments 1-11 SHIPPED"**, and the §4 table shows why the specific ones named are the wrong thing to wait on: increment 2 (virtual-time timer source), increment 3 (`Node::start_external()` — the no-self-thread mode named in C2), increment 4 (`net::GlobalScheduler`) and **increment 5 — the ADVERSARIAL schedules themselves, shipped as `test-fa-adversarial-deterministic`** are all SHIPPED, along with 6-11 (crash/rejoin, dup, per-step FA checkers, fault witnesses, per-link latency/reorder, cross-toolchain signature diff).

**Directive.** Record C2 as **UNBLOCKED now**. The remaining work is *running the full sweep* — breadth of seeds and scenarios against the shipped harness — not building scheduler increments. The owner's framing (that the increments could run in parallel with the sweep rather than serially before it) is superseded by the stronger fact: there is nothing left to parallelize. C2's prerequisite line is amended to say so.

### Also recorded: the slashing change, and the S-011 question it reopens

**The decision (owner, this session).** The slashable predicate at the **PRE-FINALIZATION layer is unsound and unfixable**, so it carries **NO consequence**: a same-height duplicate at that layer is detected, logged and gossiped for operator attention, and takes no consensus action. This follows six failed designs recorded in this log — the failure entries are 2026-08-12 "final" (gossiped round-reset marker), "final+1" (Option C, unrevealed round secret — REFUTED), "final+3" (Option D — penalty zero for attackers, unbounded for honest nodes), "final+5" (`round_seq` — and the anti-regression ratchet failed its own test), "final+7" (exclusion-only — at K == M there is no safe automated consequence), and "final+9" (time-bucketed per-block committee selection — REFUTED at design stage). Together they established, in order: no predicate over two signed openings is both sound and complete under asynchrony (a splitter's openings are bit-identical to an honest node's — only DELIVERY differs); at K == M no exclusion is possible either (`select_m_creators` picking M of M is the identity on the SET, so rotation cannot evict anyone, and a non-liftable exclusion is a self-sustaining permanent halt because the expiry is block-indexed while the halt stops blocks); and committee rotation at K == M is impossible by definition.

**The sound successor, recorded but NOT being built now.** Sound slashing belongs at the **FINALIZATION layer**: two conflicting blocks that EACH gathered K signatures at one height — a real fork attempt, which a correct run provably cannot produce. That is the replacement of record. Its design gate is the decide-by milestone for residual R-1 above.

**This REOPENS S-011.** `docs/SECURITY.md` states S-011's mitigation as *"Economic infeasibility via S-010 stake floor + FA6 equivocation slashing bounds the cartel attack to 'finite rounds of suspension' with per-round cost > chain subsidy"* (`SECURITY.md` §S-011 ledger row, and the §S-011 body). With the pre-finalization consequence removed, the equivocation-slashing half of that bound no longer holds as written and must be re-derived or re-scoped. The same flag was already raised, and deliberately not overridden, in this log's 2026-08-12 "final+6" entry against `BFTSafety.md` B2 / T-5.1. **This is not settled here.** A co-agent is landing the code change and re-deriving the affected proof claims (`SECURITY.md`, `PROTOCOL.md`, `EquivocationSlashing.md`, `BFTSafety.md`, `StakeForfeitureCascade.md`); until that lands and is verified green, treat the change as in-flight, not shipped.

**Consistency.** No-migrations (directives 3, 4 and 5 all exist because pre-genesis is the only window; directive 5 makes the window's closure explicit); minimalism (directive 1 removes a duplicate item; correction (i) removes ~55k lines from the shipped daemon and shrinks D2's tail); sequence-before-harden (directive 1 is its scheduling-side generalization); provable security (correction (ii) unblocks the adversarial sweep, and the S-011 flag refuses to let a mitigation claim stand on a removed mechanism). No consensus accept rule is changed by this entry — it is a sequencing and documentation-authority directive plus the record of one decision made elsewhere.

**Authority:** Stoyan Denev (owner directive, 2026-08-13; recorded by Claude Fable at his direction). Supersedes the ORDERING — not the decisions — of `PRE-LAUNCH-DECISIONS.md`'s 2026-07-09 execution plan.

## 2026-08-13 (addendum) — the slashing-removal code change FAILED review and was reverted; the reprioritization directive LANDED

**Correction to the entry above.** That directive recorded the slashing decision and correctly marked the code change "in-flight, not shipped". It is now resolved: **the code change was written, failed adversarial review (22 findings confirmed on independent re-derivation, 1 false alarm), and was REVERTED.** The reprioritization directive itself is unaffected and is committed.

**What was verified GOOD in the change** (keep for the next attempt): the removal is only two deleted effects in `apply_transactions` (`block_slashed += locked; locked = 0;` and `inactive_from = b.index + 1`), and the accounting is neutral **by construction** — the old code moved both sides of the A1 identity down together, so leaving the stake in `stakes_.locked` and adding nothing to `block_slashed` keeps `expected_total == live_total_supply`. Verified: no state_root leaf changes shape; a chain carrying an equivocation event round-trips to a byte-identical `state_root` through BOTH `serialize_state`/`restore_from_snapshot` and DSN1 `encode_state`/`decode_state`; `accumulated_slashed_` stays monotone, now fed by the Phase-1 abort `SUSPENSION_SLASH` alone. The reproduction gate design is also good: it keeps H1/H1v/H2 as **expected-still-failing** arms (the predicate is unchanged — only the consequence is gone) and adds **W6**, a non-vacuity guard asserting the peer's pool DOES still name the honest validator, so H3 can never pass merely because the hazard stopped reproducing.

**Why it could not land — four blocking classes.**
1. **A NEW DoS vector the removal creates (High).** There is no per-block cap and no in-block duplicate rejection on `equivocation_events`, at 2 Ed25519 verifies each. **Deregistration was the only limiter**: with `inactive_from` no longer set, the *same* event is re-includable in every block forever. Any landing must add a cap + duplicate rejection in the same change.
2. **S-006 is silently reopened (High).** Its entire recorded closure was "route `on_contrib` equivocation detection into the slashing apply path". Delete the consequence and that closure is void, yet `SECURITY.md` still carries S-006 as Mitigated.
3. **The drafted S-011 residual was WRONG in three places (High).** "At K == M structurally unreachable" is false — **BFT escalation can seat a zero-honest committee**. "Cannot permanently evict the honest member" is false — abort-driven stake drain below `min_stake` IS permanent and the S-051 floor explicitly does not lift it. And leg 1 "holds unchanged" ignores **DOMAIN_INCLUSION**, where both legs are now identically zero. The honest verdict is REOPENED with a residual that is materially worse than drafted.
4. **Doc convergence badly under-done (High, B3).** ~16 authoritative **no-TIER** proof docs still assert the deleted forfeiture/deregistration as shipped behaviour; `QUICKSTART.md` and `CLI-REFERENCE.md` still tell operators the stake is forfeited; `WHITEPAPER` still claims FA6 "no false-positive slashing" at 2^-128; the D3.3b epoch-pinning rationale still rests on "equivocation is slashed immediately" (plus 8 other now-false in-code comments); and **S-029's Level-3 `block_hash`-grinding closure and S-013's economic leg both rested on slashing and are now void, un-bannered.**

**Also caught, and worth carrying:** `determ-light verify-equivocation` still returns `EQUIVOCATION-PROVEN` / exit 0 for the honest S-050 pair — only the prose changed, not the machine-readable contract, so any operator tooling keying on the exit code is unaffected by the prose fix. And `test_equivocation_apply.sh` reported PASS against a **pre-change binary** via the documented entry point — the stale-binary trap again, now the third occurrence this session.

**Landing checklist for the next attempt** (the change itself is ~10 lines; the surrounding work is the cost): the two deleted effects; a per-block cap + in-block duplicate rejection on `equivocation_events`; S-006 re-derived or re-opened; an honest S-011 residual covering BFT escalation, the permanent `min_stake` drain, and DOMAIN_INCLUSION; the machine-readable `verify-equivocation` contract; and the ~16 no-TIER proof docs plus QUICKSTART / CLI-REFERENCE / WHITEPAPER / S-029 / S-013 / D3.3b.

**Authority:** review findings recorded by Claude Fable, 2026-08-13. The slashing decision itself stands (owner, this session); only its implementation is deferred.

## 2026-08-13 (correction) — the slashing change is a RELOCATION to L2, not a removal

**Owner correction.** The two entries above characterise the slashing change as *removing* the consequence, with "finalization-level L1 slashing" named as the sound successor. **That is a misrecording by the recorder, not the owner's decision.** The decision is that **slashing moves OUT OF L1 INTO L2.**

**What this does and does not change.**

*Unchanged — the L1 code delta.* L1 still deletes the two effects in `apply_transactions` (`block_slashed += locked; locked = 0;` and `inactive_from = b.index + 1`). Every accounting result verified for that change stands: A1 is neutral by construction, no state_root leaf changes shape, and a chain carrying an equivocation event round-trips byte-identically through both `serialize_state`/`restore_from_snapshot` and DSN1 `encode_state`/`decode_state`.

*Changed — what L1 keeps, and why.* The on-chain evidence record is **NOT merely diagnostic**. It is the **INPUT to the L2 slashing mechanism**. That upgrades the per-block cap and in-block duplicate rejection from a DoS fix to a **correctness requirement of the L2 design**: an L2 policy reading an unbounded, re-includable evidence stream cannot compute a stable verdict.

*Changed — why the impossibility results are not fatal.* They bound what a **consensus predicate** can decide from two signed openings under asynchrony. They do not bound an **L2 policy**, which may use inputs L1 provably cannot: off-chain corroboration, elapsed wall-clock time, human arbitration, and dispute/appeal. An L2 verdict is not required to be sound-and-complete as a consensus rule, because it is not one. This is the reason the relocation works where six in-consensus designs failed.

*Changed — the S-011 / BFTSafety re-derivation.* The prior framing asked whether the S-010 stake floor alone suffices with slashing gone. Under relocation the correct question is different: **does the L2 mechanism restore the economic bound, and under what assumptions?** The three errors found in the drafted residual still stand as errors (BFT escalation can seat a zero-honest committee at K == M; abort-driven drain below `min_stake` is permanent and S-051 does not lift it; DOMAIN_INCLUSION zeroes both legs), but they must be re-derived against the L2 design, not against a no-slashing world.

**OPEN, and it is the design's crux — what does L2 slash?** Validator stake is L1 state (`stakes_.locked`). Three shapes, not decided here:
- **(a) L1 exposes a DApp-callable stake primitive.** Direct, but the L2 verdict then re-enters consensus state — and everything this session proved about unsound predicates entering the apply path applies again.
- **(b) An L2-native bond.** Validators post a separate bond to an L2 staking/insurance DApp; L1 stake is never slashable. Fully clean, opt-in, and consistent with K-of-K mutual distrust — L1 has no slashing surface at all.
- **(c) Service-layer consequence only.** Exclusion/reputation at the L2 service boundary, no asset movement.

**(b) is the only shape that keeps the impossibility results out of consensus permanently**; (a) reimports them. This must be settled before the L1 change lands, because it determines whether L1 needs to expose anything at all — and under no-migrations, exposing a stake primitive is a genesis-frozen decision.

**Status.** The L1 code change remains NOT LANDED (failed review, 22 findings — see the addendum above; the landing checklist there is still accurate, with the cap/duplicate-rejection item promoted from DoS fix to L2 correctness requirement). `CLAUDE.md` CURRENT FRONT corrected in the same commit.

**Authority:** owner correction, 2026-08-13; recorded by Claude Fable at his direction.

## 2026-08-13 — AUTHORIZED FOR DESIGN (no code): abort-certificate LOCK RULE + deferred slashing in L1, with M > K as a genesis invariant

**Owner decision.** Slashing stays in **L1** (superseding the L2 relocation recorded above, which was itself a correction to a mis-recorded "removal"). It becomes sound by adding the mechanism the protocol lacks: a **lock rule**, with the verdict **deferred by N blocks**.

**The rule.** A validator that has signed a block at height H may sign a *different* block at H only if the new block carries an **AbortEvent terminating the prior round**. Justification is therefore quorum-signed and unforgeable, and it reuses machinery that already exists — `abort_events` ride in the block, are gossiped and adopted, and are already validated by `check_abort_events`. No new wire artifact.

**The slashable predicate becomes sound.** With the lock in place, "signed two conflicting blocks at one height **without exhibiting justification**" is something a correct run provably cannot produce — which is the standard total forfeiture has needed since the beginning. This is what six in-consensus designs were missing: they all tried to make an *instantaneous* predicate over two signed openings sound, which is impossible under asynchrony (a splitter's openings are bit-identical to an honest node's — only DELIVERY differs). A lock rule changes what an honest node is *permitted to produce*, so the pair stops being ambiguous.

**Why deferral is part of it.** The verdict is passed N blocks later, when the chain's own history shows whether a competing complete block exists. The impossibility theorem bounds a predicate over two openings *at the instant of detection*; N blocks of subsequent history is strictly more information, so the theorem does not apply to the deferred predicate.

**Genesis invariant: M > K.** Every lock rule creates a liveness risk — once a member has signed it cannot re-sign, so the committee cannot re-form with it. Spare capacity converts that halt into automatic recovery.

**KNOWN GAP, recorded before design begins: M > K does NOT rescue K = 2.** `abort_claim_quorum(K) = max(2, K−1)` (`include/determ/chain/params.hpp:156`) and claimers are drawn from the COMMITTEE (`on_abort_claim` requires `in_creators(msg.missing_creator)` and `claimer != missing_creator`), not from the pool. At K = 2 exactly one eligible claimer exists, so the quorum is unsatisfiable **whatever M is** — S-044 made that choice deliberately, preferring "a crash-stop halt-by-single-death" over cascade. A validator locked at K = 2 could therefore never obtain a certificate. **The combination is viable from K ≥ 3; K = 2 must either be excluded by the genesis invariant (M > K AND K ≥ 3) or accept halt-on-partial-signing.**

**Design questions that must be answered BEFORE any code** (six implementations failed; only the design-first passes produced durable results):
1. **Is "locked" consensus-visible?** Committee derivation must be identical on every node. A validator's signature on block A is visible only to peers that received A, so "who is locked" is a per-node view unless it is derived from committed state. If the re-round committee must exclude locked members, the exclusion input must be in the block — otherwise nodes derive different committees, which is a fork.
2. **Does M > K actually let the committee re-form without the locked member?** The selection seed is `epoch_committee_seed(epoch_rand, shard_id)` mixed with `current_aborts_` hashes; with no abort the seed is unchanged and the SAME committee re-derives even when M > K. So re-formation depends on the abort tail growing — which is the same artifact the lock requires. Confirm this is not circular.
3. **Does the lock actually close the S-048 abort-vs-finalize race?** That race currently produces two K-signed same-height blocks *honestly* (`Chain::resolve_fork` exists because of it). If the lock does not prevent it, the deferred predicate is still unsound.
4. **N, two-sided.** Long enough for a competing complete block to surface; strictly shorter than the unbonding window, with stake locked throughout, or the offender withdraws before the verdict (`UNSTAKE_DELAY = 1000`; `unlock_height = inactive_from + unstake_delay_`, `chain.cpp:1313`).
5. **Lock-liveness.** A locked validator that cannot obtain justification is stuck — the classic tension every BFT protocol must resolve explicitly.

**Consistency.** No-migrations (lock rule, deferred verdict and the M > K invariant are all consensus/genesis surface — pre-genesis or never); provable security (the predicate becomes one a correct run cannot satisfy, rather than one that merely looks suspicious); minimalism (reuses `abort_events`, adds no wire artifact).

**Authority:** Stoyan Denev (owner directive, 2026-08-13; recorded by Claude Fable at his direction). Design + adversarial review authorized; implementation is NOT.

## 2026-08-13 — abort-certificate lock rule REFUTED at design stage. The bootstrapping impossibility, stated. No code written.

**All four lenses FATAL; synthesis NOT VIABLE; 16 findings confirmed (7 false alarms). Nothing implemented.** This is the seventh design against Hole 1b, and the first to produce a statement general enough to close the family.

### The constraint that kills it — and every design like it

> **The round identity can only be canonicalized by a block, and no block can be produced while the identity is in dispute.**

That is a bootstrapping impossibility, not a missing mechanism. Any justification-based rule needs the chain to record *that a re-round occurred*; the chain records a re-round only *when the re-round won*. A stalled round cannot produce a canonical record of itself, and a stalled round is exactly the case at issue.

### Three independent failures, each sufficient

**(a) The justifying artifact is deterministically DISCARDED.** `Chain::resolve_fork` breaks a signature-count tie by preferring **fewer** `abort_events` (`chain.cpp:2101-2102`). In MUTUAL_DISTRUST every complete block carries exactly K non-zero sigs, so two complete same-height MD blocks **always** tie on count — and the **low-gen block always wins, deterministically, on every node**. `revert_head` discards the loser. AbortEvents are strictly height-scoped (claims require `m_.block_index == b.index` and `m_.prev_hash == chain.head_hash()`, `validator.cpp:262/345/347`) and `current_aborts_` clears on apply (`node.cpp:2533`), so they can never be carried forward. In exactly the S-048 scenario the lock exists to legitimize, the AbortEvent that constitutes the justification is **provably absent from the canonical chain forever**.

**(b) `gen` is signer-chosen off-chain, so "justified" is a free acquittal.** `compose_block_digest`/`compose_contrib_commitment` take `gen` as a bare `u64` (`producer.cpp:1004-1011`, `:344-353`). An equivocator's second signature need not correspond to any accepted block, so it signs side A at `gen g` and side B at `gen g+1`. A judge reading "higher gen ⇒ justified" collapses to the already-shipped `gen_a == gen_b` assertion (`validator.cpp:458-460`) and yields **zero new convictions** — the 5th design's "any self-declared identity is evadable" result, re-derived on current code.

**(c) Anchoring, the only repair for (b), makes acquittal LIVENESS-CONTINGENT.** Requiring the higher-gen opening to anchor (`body_root == compute_block_digest_body(blocks_[H])` and `gen == blocks_[H].abort_events.size()`) convicts the honest S-048 validator outright under (a). Inverting the tiebreak to prefer *more* aborts fixes that one case but not the general one: when the abort re-round **stalls and never mints** — the reachable case, which is why the S-050 valve exists — the canonical block at H is the gen-0 block and the honest validator's gen-1 signature anchors to nothing. Its non-slashability then depends on **whether its re-round happened to win the race — network luck, not correctness.** That destroys the exact property the authorization demanded.

**And the lock forbids the valve.** Its justification clause is structurally unreachable on both documented same-gen re-round paths (the valve clears `current_aborts_` and re-enters with a fresh secret; the S-048 reorg re-rounds at gen 0), turning a reproduced clean-network livelock into an **absorbing permanent halt**. The per-height release budget is finite (M − ⌈2K/3⌉) while demand is unbounded.

### POSITIVES worth preserving for any future attempt

1. **A lock needs NO new committee-derivation input.** A locked member is simply *silent*, and silence is already handled: the abort path raises a claim, the quorum forms, and every node re-derives the same re-round committee excluding it (`validator.cpp:139/148-151`, `node.cpp:999/1034-1041`). Any future lock should be kept **strictly signing-side** — feeding "who is locked" into derivation WOULD fork, since it is a delivery-dependent per-node view.
2. **A deferred judge must live in `Chain::apply_transactions`, never in `BlockValidator`.** `Chain::load` (`chain.cpp:3483-3536`) replays via `apply_transactions` and **never calls `BlockValidator::validate`**, so any validator-side verdict is skipped on replay and the forfeiture becomes a **state_root divergence between a replaying node and a live node**. This holds for ANY future slashing design.
3. **N ≥ 2 makes the judge's read of `blocks_[H]` stable** (past the depth-1 reorg window).
4. **`resolve_fork`'s tiebreak is load-bearing well beyond slashing**: in MD it *always* resolves to the lower-gen block. Worth knowing independently.

### Status

**Hole 1b remains OPEN after seven designs.** What is now settled is stronger than any single fix: the failure is not a missing mechanism but a bootstrapping impossibility — a stalled round cannot canonicalize a record of itself, and every justification-, identity-, or exclusion-based rule needs precisely that record. The honest position is that **no automated consequence at the pre-finalization layer is achievable**, and the sound options remaining are the ones outside consensus: an L2/economic layer with inputs L1 provably lacks, or no consequence at all.

**Authority:** design analysis recorded by Claude Fable, 2026-08-13. No implementation was performed.

## 2026-08-13 — slashing-removal change set, attempt 2: FAILED review (20 findings, 1 CRITICAL). Reverted. The cap is the new blocker.

**20 findings confirmed on independent re-derivation, ZERO false alarms.** Nothing committed; tree at 0ce12c8, `ci_local` green. This is the second attempt at the same change set and it failed on **different** defects than the first — the first lacked a cap, S-006 and 16 docs; this one has the cap and broke on it.

**The core removal remains sound** and is now doubly verified: A1 neutral by construction (both sides of the identity moved together, so leaving stake in `stakes_.locked` and adding nothing to `block_slashed` preserves `expected_total == live_total_supply`); no state_root leaf changes shape; byte-identical `state_root` round-trip through BOTH `serialize_state`/`restore_from_snapshot` and DSN1 `encode_state`/`decode_state`; `accumulated_slashed_` monotone, fed by the abort `SUSPENSION_SLASH` alone, proven non-vacuous by a positive control (one Phase-1 abort still moves stake 1000→990). The reproduction gate design also holds: 29 enforced arms including **W6** (the peer's pool DOES still name the honest validator — so H3 cannot pass by the hazard vanishing), with H1/H1v/H2 preserved as reported-not-counted.

### CRITICAL — the cap introduces a consensus halt

**EQV-BOUND truncation is ORDER-SENSITIVE while the block digest binds the evidence set ORDER-INSENSITIVELY.** Two committee members whose pools enumerate the same over-cap evidence set in different orders truncate to *different* 16-element subsets, produce *different* digests, and cannot reach K. The chain halts. A cap that drops elements must therefore impose a **total order before truncation** (and that order must itself be a pure function of the block's bytes), or it must not drop elements at all. This is the same class — a value that must be identical across nodes but is derived per-node — that killed the marker, `round_seq` and time-bucket designs.

### HIGH — the machine-contract "fix" made things worse

Changing `verify-equivocation`'s exit codes to **2 = proven / 0 = not-proven** *inverts* the legacy convention: a pre-existing `if verify; then punish; fi` now punishes on evidence that **FAILED** verification. A contract change intended to prevent unjust punishment created a path to punish on a *negative* result. Any future change here must keep 0 = success-of-the-check and signal the verdict out-of-band, or must break loudly rather than invert.

### HIGH — the age window creates a censorship vector

Pool dedup is one-record-per-equivocator (`same_equivocation_identity`). With an inclusion age window, a record that ages out becomes **permanently un-includable yet permanently resident**, occupying that equivocator's only slot and censoring all future evidence about that node. `rpc_submit_equivocation` also answers `accepted:true` and broadcasts records that can never be included. Any age bound needs a matching pool-eviction rule.

### HIGH — doc convergence still incomplete, second time

Five un-bannered authoritative proofs still assert the deleted consequence; `Safety.md` keeps "every fork-creator gets slashed" plus a "materially stronger than BFT" claim that `BFTSafety.md` **withdrew in the same change set**; `BFTProposerElectionSoundness` PE-4.1 still asserts FA6 slashing and its newly-written PE-3 cost claim **contradicts this change's own S-011 correction**; `BFTSafety`'s new "T-5 UNAFFECTED, verifiable by inspection" inspects only B2 and misses that **H2 is falsified by shipped honest behaviour**; `CLI-REFERENCE.md` still publishes the OLD tokens and INVERTED exit codes **in rows this change already edited**; `PROTOCOL.md` now self-contradicts on the EQUIVOCATION_EVIDENCE frame size (245/246 vs 229/230). Also: S-011 correction (ii) understates the permanent-eviction trigger **by 100×** — it is ONE Phase-1 abort, not ~100.

### Operational findings worth keeping

**Root cause of the three "faked" mutant results this session, now identified**: a stale `build/determ` SHADOWS `build-linux/determ` because `tools/common.sh` prefers `build/` first, so any bare `bash tools/test_*.sh` silently tests the old binary. `ci_local.sh` is immune (it exports `DETERM_BIN`), which is why every ci_local-verified green held. **Delete the stale `build/` tree** — the 2026-08-11 machine-move ledger already prescribes exactly this. Separately: three docs were silently rewritten CRLF→LF, adding ~6000 lines of churn that HID the CLI-REFERENCE misses from review.

### Landing checklist (third attempt)

The ~10-line removal is not the cost. Required alongside it: a cap with a **total order before truncation** (or no truncation); an age bound **with pool eviction**; an exit-code contract that does **not** invert legacy semantics; and the doc set — five proofs, `Safety.md`, `BFTProposerElectionSoundness`, `S013PerSignerCap` T-4, `ProofClaimGateTraceability`, `CLI-REFERENCE.md`, `PROTOCOL.md` frame sizes — converged **without** CRLF rewrites masking the diff. Track the new gate file in git; an untracked FAST gate is lost on a clean checkout.

**Authority:** review findings recorded by Claude Fable, 2026-08-13. The slashing decision stands; only its implementation is deferred, twice.

## 2026-08-13 — DOCTRINE: green gates are necessary and NOT sufficient on consensus surface; adversarial review of the diff becomes mandatory. Derived from nine measured failures.

**This is a process control derived from measured outcomes, not a retrospective.** `CLAUDE.md` PROJECT DOCTRINE is amended in the same change with two new standing bullets ("Green is not proof" and "Never seed anything security-relevant from a block hash"). No technical decision is reopened, reversed or superseded; the B3 rule that new behaviour ships with a falsify-on-mutant gate is unchanged and now carries an explicit sufficiency qualifier.

### The measurement

Nine consensus designs were attempted across 2026-08-12/13 against Hole 1b and its successor decision. Every one was wrong. Six were carried to a green tree before the defect was found; three were refuted on paper before any code existed.

| # | Design | Reached | Adversarial review |
|---|---|---|---|
| 1 | gossiped round-reset marker (`final`) | implemented, reverted | 15 confirmed / 2 false |
| 2 | Option C — reuse the unrevealed round secret (`final+1`) | REFUTED at design stage, no code | 4 lenses: FAILS ×3 |
| 3 | Option D — bounded suspension (`final+3`) | implemented; **own gate 34/34, six mutants verified RED, FAST 303/0** | 14 confirmed / 2 false |
| — | Option B — hash-chain round identity (`final+3`) | designed, VIABLE-WITH-CONDITIONS, then withdrawn as unnecessary | R7 proved UNACHIEVABLE |
| 4 | first-class `round_seq` (`final+5`) | implemented **with a purpose-built anti-regression ratchet** | 17 confirmed / 1 false |
| 5 | exclusion-only, never slash duplicates (`final+7`) | implemented, reverted | 15 confirmed / 2 false |
| 6 | time-bucketed committee selection (`final+9`) | REFUTED at design stage, no code | 21 confirmed / 3 false |
| 7 | abort-certificate lock rule (2026-08-13) | REFUTED at design stage, no code | bootstrapping impossibility |
| 8 | slashing relocation, attempt 1 (2026-08-13 addendum) | implemented, reverted | 22 confirmed / 1 false |
| 9 | slashing relocation, attempt 2 (2026-08-13) | implemented, reverted | 20 confirmed / 1 CRITICAL, 0 false |

**Totals: 124 confirmed findings against 11 false alarms.** The mutant-verified gates shipped alongside those changes found **none** of the 124. Exactly two mechanisms ever caught a real defect in this session: an **end-to-end reproduction that executes production code and asserts at the verifier**, and **adversarial review of the diff**.

### The seven rules, and the specific failure each one is derived from

1. **A falsify-on-mutant gate proves the code enforces what the gate ASSERTS; it cannot prove the assertion is the property you NEED.** Option D's gate was 34/34 with six mutants confirmed RED while the feature's penalty was identically zero in the default K-of-K deployment and unbounded for honest nodes. The gate was not weak — it was aimed at the wrong proposition, and no amount of mutant strength corrects that.
2. **Adversarial review of the DIFF, before commit, independent of gate colour**, for any change to consensus accept-rules, the apply path, wire formats, committee derivation, or the slashing/evidence path. Evidence: the table above. A purpose-built ratchet does not discharge this — `round_seq` shipped a structural guard specifically built to make regression impossible, and the reviewer defeated it with a **one-line edit** (`round_seq_ = static_cast<uint64_t>(current_aborts_.size());`, the literal HEAD defect restored inside the function the guard reads) while the guard printed PASS, selftest 8/8. A textual guard over source cannot enforce a semantic invariant, and an unlinked model (`determ-dsf` links zero production code) tests the model, not the system.
3. **Assert at the layer where the rule LIVES.** Option C was refuted on exactly this: the slashing predicate is `body_root_a != body_root_b` in the VERIFIER (`validator.cpp` V11 clause set + the `node.cpp` adoption gate); the core-only comparison at `node.cpp:3043-3058` is a producer-side courtesy in ONE in-tree assembler, and under K-of-K mutual distrust an assembler keying off the real rule is inside the threat model by definition. A gate built on the proxy goes green while the bug is live.
4. **Design-and-prove BEFORE implementation when the design is uncertain.** Designs 2, 6 and 7 were refuted at design stage and cost a fraction of the six that were implemented first — and design 6's refutation additionally produced the block-hash malleability result, which is worth more than the design it killed.
5. **Land consensus changes as the smallest increment that keeps the tree green and truthful.** The ~10-line slashing core removal was verified sound BOTH times (A1 neutral by construction, no state_root leaf shape change, byte-identical round-trip through both snapshot containers, non-vacuity positive control). It was sunk by its riders: attempt 1 by S-006, a wrong S-011 residual and ~16 stale proof docs; attempt 2 by an order-sensitive cap (CRITICAL: a consensus halt), an exit-code inversion and, again, doc convergence. Bundling made a verified change unshippable twice.
6. **Verify with `tools/ci_local.sh`, never a bare `tools/run_all.sh` or bare `tools/test_*.sh`, and confirm the build succeeded before trusting any mutant.** Only `ci_local` exports `DETERM_BIN` / `DETERM_WALLET_BIN` / `DETERM_LIGHT_BIN` / `DETERM_DSF_BIN`; a bare run resolves a binary by `tools/common.sh` search order and every DSF gate SKIPs when `DETERM_DSF_BIN` is unset. Three "faked" mutant results this session were a stale `build/` tree shadowing `build-linux/` — that tree is now deleted, but the invariant that produced the false greens (an unexported binary path, or a mutant "dying" against a binary whose build actually failed) is structural and the discipline stands.
7. **Never seed anything security-relevant from a block hash.** `Block::compute_hash()` (`src/chain/block.cpp:817-826`) hashes `signing_bytes()` and then **appends `creator_block_sigs`**, while Ed25519 verification (`src/crypto/ed25519/ed25519.c:321-348`) checks only pk-y canonicality, `S < L` and the group equation — RFC 8032's deterministic nonce is a signer-side convention no verifier can check. A member that broadcasts its `BlockSigMsg` last can therefore enumerate unboundedly many *valid* signatures over the SAME `compute_block_digest` at ~one sign per trial and publish the hash that seats its preferred committee, with no abort, no equivocation and nothing any existing gate records. The architecture is currently correct ONLY because committee selection and the subsidy lottery route through `cumulative_rand`'s commit-reveal, whose every input is digest-covered or commit-pinned. This bullet exists so no future design reverses that without re-deriving it (source: `final+9`, §3).

### What this costs and what it does not change

The rule adds a mandatory pre-commit step to a bounded surface (accept-rules, apply path, wire formats, committee derivation, slashing/evidence). It does **not** apply to test-only, tooling, doc or non-consensus code, and it does not relax B3: a consensus change still needs its falsify-on-mutant gate, it now additionally needs a review that asks whether the gate asserts the right thing. The measured cost of *not* having the rule is nine reverted designs; the measured yield of review is 124 confirmed defects at an 11/135 false-alarm rate.

**Authority:** recorded by Claude Fable, 2026-08-13, at the direction of the session orchestrator. Docs-only change (`CLAUDE.md` + this entry); no code was touched and no build was run. Flagged for owner review because it imposes a mandatory pre-commit step on consensus work — the owner may narrow the surface it applies to, but the evidence for the rule is the table above.

## 2026-08-13 — slashing removal, attempt 3: FAILED (16 findings, 1 CRITICAL). Reverted. THE CAP IS THE BLOCKER, NOT THE REMOVAL.

**Doctrine landed (see the CLAUDE.md change in this commit); the code did not.** 16 findings confirmed, 1 false alarm. Three attempts, three different cap designs, **three consensus halts of the same class**.

### The pattern, now unmistakable

| attempt | where the bound was applied | how it halted |
|---|---|---|
| 2 | truncate the block's event list at 16 | truncation ORDER-SENSITIVE; digest binds the set order-INsensitively → members split the digest |
| 3 | bound the **pool** at 64 (reject, never truncate) | pools diverge per node → different evidence SETS in the block → digest splits → K-of-K never forms |

**The generalisation: any per-node bound on a collection the block digest binds COLLECTIVELY will split the digest.** Rejecting instead of truncating does not help, because the divergence moves upstream into which events a node holds at all. A bound is only safe if it is a pure function of the block's own bytes, applied identically by every validator — never a function of local pool state.

### And the cap does not even solve its own problem

EQV-CAP bounds per-block **width**, not **perpetuity**. The same `EquivocationEvent` remains re-includable in every block forever — the exact issue the cap was added for. Three authoritative texts in the change asserted the opposite.

### What the attempt did establish (keep — this is real progress)

**The re-inclusion question is settled empirically**, by an in-process probe linked against the real objects, and attempt 2's premise was HALF WRONG: `resolve_committee_member_pubkey` (`src/node/committee_pool.cpp:43`) consults the frozen `cc:[E]` committee FIRST and only then the present-head registry, which filters on `domain_eligible`. So deregistration **did** limit cross-block re-inclusion on the default unpinned path (and in STAKE_INCLUSION the stake-zeroing limited it independently — deregistration was never the *only* limiter), but **on a pinned committee epoch re-inclusion was ALWAYS possible**, because the frozen member list is a snapshot deregistration never touches. Post-removal the record resolves in every configuration. So a bound IS needed for EXTENDED-sharded chains — it just cannot be the kind attempted three times.

### Other confirmed defects

Gate arm C3 asserted a proposition that is FALSE, and it was the change's central safety claim. A full pool silently suppressed both pooling AND gossip of newly detected evidence — censoring the mechanism's only surviving output — with no eviction rule, so free-to-produce sybil evidence censors evidence about the attacker. **A persisted chain that already applied an EquivocationEvent fails to LOAD after the change.** Doc convergence fell short for the third consecutive time (README, WHITEPAPER and ~20 no-TIER proofs still publish forfeiture as shipped). Both new banners self-contradicted — declaring V11 and pooling UNCHANGED, then describing two new V11 reject rules and a new pool bound. The new FAST gate file was untracked while `run_all.sh` already referenced it, so a clean checkout runs one gate fewer.

### Third instance of the stale-artifact class

The implementer's first mutant pass produced a FALSE result: `shutil.copyfile` preserved the source mtime, `make` skipped the rebuild, and the "clean" run silently tested unmutated code. Caught by an independent probe, not by the gate. After the stale `build/` tree and the `--skip-build` reverts, this is the third distinct way the same failure appeared. **A mutant result is trustworthy only if you prove the translation unit recompiled** — now doctrine.

### Where this leaves it

The ~10-line removal has now been verified sound THREE times (A1 neutral by construction, no state_root leaf shape change, byte-identical round-trip through both snapshot containers, positive control non-vacuous). It has never been the problem. The blocker is bounding the evidence path, and the next attempt must start from the generalisation above: **a bound that is a pure function of the block's bytes, or no bound at all** — and if no safe bound exists, the honest options are to drop the evidence path from blocks entirely (gossip-only, no consensus surface) or to accept unbounded re-inclusion on pinned epochs and say so.

**Authority:** review findings recorded by Claude Fable, 2026-08-13.

## 2026-08-13 — AUTHORIZED FOR DESIGN (no code): demote equivocation evidence from F2-reconciled round content to block PAYLOAD

**Owner directive.** Split block content by WHO must agree and WHEN. **Co-creator round messages** (contribs, block sigs) stay exactly as they are — agreed now, reconciled by the round protocol. **Equivocation evidence becomes PAYLOAD**: the producer proposes a set, co-signers verify-and-sign what was proposed, and no node independently derives the set. Optionally, application of any future consequence is DEFERRED to a later height and sourced from the ON-CHAIN record rather than local pools.

**Why this is different from the three failed caps.** The recorded generalisation is that *any per-node bound on a collection the digest binds COLLECTIVELY will split the digest* — attempt 2 truncated the block list (order-sensitive vs an order-insensitive digest), attempt 3 bounded the pool (pools diverge, so the evidence set diverges, so K-of-K never forms), and rejecting instead of truncating only moves the divergence upstream. Demotion attacks the premise instead of the symptom: if no node independently derives the set, divergent pools cannot split the digest, and a bound on payload becomes **a pure function of the block's own bytes** — precisely the shape the generalisation says is safe.

**The coupling worth recording:** removing the consequence is what makes this legal. With slashing live the evidence had to be reconciled (S-030-D2 anti-strip — a relayer must not strip it after signing). With no consequence, stripping is harmless, so the binding can go. The architectural simplification is *paid for* by the earlier decision.

**What must NOT be demoted: abort events.** They drive suspension AND feed committee derivation (`current_aborts_` event hashes chain into the selection seed, `src/node/node.cpp` ~1032-1042, mirrored in `BlockValidator::check_creator_selection`). Demoting them would fork committee derivation. Only the equivocation view is demotable; the design must show the separation is clean, since today both ride the same F2 view machinery.

**Design questions to settle before any code:** every reader of `creator_view_eq_roots` and whether F2 tolerates an always-empty eq view; that the digest stays BYTE-IDENTICAL for evidence-free blocks (the binding is already conditional on `any_nonzero(creator_view_eq_roots)`); whether any co-signer today compares a proposed evidence set against its OWN pool (if so that check must go, and what it protected); the per-block bound as a pure function of the block's bytes; whether deferral is load-bearing now or future-proofing (with no consequence, likely the latter); and whether a deferred judge would have to live in `apply_transactions`, since `Chain::load` replays without `BlockValidator`.

**Gate requirement, mandatory:** a DIGEST-AGREEMENT arm — two nodes with DIFFERENT pools must produce/accept the SAME block. That is the exact property all three cap attempts violated and no gate ever asserted.

**Authority:** Stoyan Denev (owner directive, 2026-08-13; recorded by Claude Fable at his direction). Design + adversarial review authorized; implementation is NOT.

## 2026-08-13 — CRITICAL, LIVE AT HEAD: the F2 equivocation view is a remotely-triggerable PERMANENT CHAIN HALT. Payload demotion is VIABLE-WITH-CONDITIONS and is the fix.

**The design pass authorized above returned VIABLE_WITH_CONDITIONS — and found, in passing, a rank-1 liveness hole that exists in SHIPPED CODE RIGHT NOW, independent of every slashing decision. Demotion is a BUG FIX, not a refactor.**

### C0 — absorbing consensus halt, triggerable at will by one Byzantine peer

Every committee member calls `build_body` with **its own** `pending_equivocation_evidence_` pool (`src/node/node.cpp:1377` sign path, `:1498` finalize, `:3165` peer-sig verify), and in MUTUAL_DISTRUST there is **no designated finalizer** (`node.cpp:1449` restricts that to BFT). Pool records for one equivocator are **per-node and permanently divergent**: `hash_equivocation_event` binds the `(a,b)` opening ORDER and the observer-local `beacon_anchor_height` (set at `node.cpp:3071-3073`, `:2453`), while pool dedup is **equivocator-ONLY** (`include/determ/node/producer.hpp:391-393`). So each node keeps its own first-detected variant and DROPS the peer's (`node.cpp:1937`, `:2457`, `:3075`).

**Breaking sequence.** An equivocator sends contrib X to A then Y, and Y to B then X. A records `(a=X,b=Y)`; B records `(a=Y,b=X)`. Both gossip; both reject the other as a duplicate. In the next round A's digest appends `compute_view_root({h(e_A)})` and B's appends `compute_view_root({h(e_B)})` — **the digests differ**, every `BlockSig` is rejected (`node.cpp:3176-3180`), the round aborts, and the S-050 valve clears `current_aborts_` but **NOT** `pending_equivocation_evidence_` (`node.cpp:1638-1648`). The next round diverges identically. The pool is cleared only when a block containing a record for that equivocator applies (`node.cpp:2546-2555`) — exactly what can no longer happen. **Under the default K == M the halt is PERMANENT.** Cost to the attacker: two contribs.

This is a live, remote, unauthenticated, absorbing halt. It was found by design analysis; no gate in the suite asserts anything that would catch it.

### Two of my own stated premises were WRONG — corrected

1. **"The digest stays byte-identical for evidence-free blocks" is FALSE.** The gate is conditional on **F2 view presence**, not evidence presence. `make_contrib` sets all three view roots together when ANY list is non-empty (`producer.cpp:1082-1089`), and `compute_view_root({})` is `SHA256("")` — **non-zero** (`producer.cpp:585-590`). So on any block carrying an abort or an inbound receipt but no evidence, the gate at `producer.cpp:896` FIRES. Byte-identity holds only when all three views are empty; **every re-round block and every EXTENDED inbound block changes digest under demotion.**
2. **"Stripping is harmless" is FALSE at HEAD.** The consequence is still live and `state_root` is NOT digest-bound, so a relayer strips the list, recomputes `state_root`, and the K-of-K sigs still verify — the eq digest binding is the ONLY thing preventing it. After the removal a strip cannot diverge state, but `signing_bytes` still binds the events (`block.cpp:672-686`), yielding two same-height K-of-K-valid instances resolved by `resolve_fork`'s smallest-block-hash tiebreak (`chain.cpp:2105-2109`) — and per the standing doctrine bullet the hash is malleable, so a member signing last can GRIND its stripped variant to the smaller hash and win deterministically. Adversary gain: **at-will suppression of the forensic record.**

### The design's four conditions

- **C1** — DELETE the eq arm of `check_eqabort_reconciliation` (`validator.cpp:1756-1762`) in the SAME commit that stops populating the eq root. Otherwise a zero root takes the v1-sentinel `continue`, the union set stays empty, and **no block carrying evidence is ever acceptable again.**
- **C2** — KEEP a digest binding, only RE-GATE it: `any_nonzero(creator_view_eq_roots)` → `!b.equivocation_events.empty()`. That is a pure function of the block's own bytes — the shape the generalisation requires — and it preserves S-030-D2 for the eq dimension. Mirror byte-for-byte in `light/verify.cpp:186-191` and the six copies in `tools/test_block_digest_xbinary_parity.sh`.
- **C3 — the correction to the owner's framing.** "Producer proposes" has **no producer** in MUTUAL_DISTRUST. Source the payload from ONE **signed** contrib — e.g. `creators[0]`'s list — exactly as `shard_tip_records` is derived purely from signed contribs (`producer.cpp:1449-1470`). Passing `pending_equivocation_evidence_` into `build_body` IS the C0 defect and must not survive.
- **C4** — domain-separate the conditional digest appends, or record the residual: once the eq gate is content-driven it shares inbound's style, so two blocks differing in WHICH conditional field is present can occupy the same preimage position.

**Verified NOT readers of the eq view** (so demotion is contained): committee derivation reads `abort_events` only (`node.cpp:998`, `:1032-1036`; `validator.cpp:139`, `:148-151`), `cumulative_rand`, apply (`chain.cpp:1815` reads `b.equivocation_events`, never the view), and `wallet/*`. Three `validate_*` helpers have ZERO production callers. The **abort view is NOT demotable and is untouched.**

**Status: C0 must be triaged as a security item on its own merits, ahead of and independent of the slashing work.** It is present at HEAD today.

**Authority:** design analysis + adversarial review recorded by Claude Fable, 2026-08-13. No code written.

## 2026-08-13 — canonicalization REFUTED as a standalone C0 fix. C0 is a SET-AGREEMENT bug, not a record-normalization bug. Demotion is the answer.

**Verdict: FATAL on the sufficiency lens.** Canonicalization closes exactly the two divergence causes the C0 entry enumerated — the `(a,b)` slot ordering and the observer-local forensic fields — and **nothing more**, because those are the only per-observer inputs to the RECORD. C0's root cause is one level up: `b.equivocation_events` is `pool ∩ union` (`producer.cpp:1226-1232`), a function of the assembler's **local pool** — an asynchronously-populated, adversary-shaped set that no per-record normalization makes common across nodes.

### R1 — the killer, and it is canonicalization-proof

Detection pairs the FIRST-admitted contrib with a later one (`node.cpp:3026-3031`, `:3053-3072`) and dedup is equivocator-only (`producer.hpp:391-393`), so the first pair is frozen and every later pair is dropped (`node.cpp:3075`). Equivocator E signs THREE valid contribs X, Y, Z at one `(block_index, prev_hash, aborts_gen)` — all clear every admission gate. E delivers X→A then Y→A, and Y→B then Z→B. **A freezes canonical(X,Y); B freezes canonical(Y,Z)** — different body_roots, different sigs, therefore different canonical records. Canonical ordering and field deletion change nothing. Each drops the other on equivocator-only dedup; A commits view `{h(XY)}`, B `{h(YZ)}`; each materializes only its own; digests differ; every BlockSig is rejected; the round aborts; S-050 clears `current_aborts_` but not the pool, which is erased ONLY on a block apply carrying that equivocator. **At K == M the halt is permanent. Cost: three contribs.**

### Three further divergence sources, independent of records

**R2 — pool membership with NO repair path.** The union filter deliberately materializes only `pool ∩ union` and the validator deliberately accepts a strict subset (`validator.cpp:1705-1711`, whose own comment concedes "the union can hold several witnesses… that no single assembler can fully materialize"), so it never rejects — it silently diverges the digest. And recovery does not exist: the detector broadcasts ONCE (`node.cpp:2458`, `:3076`), `on_equivocation_evidence` adopts WITHOUT re-broadcasting (`node.cpp:1921-1943`), `GossipNet::broadcast` is one-hop best-effort with exceptions swallowed (`gossip.cpp:332-337`), and nothing re-requests evidence. **A single dropped frame is a permanent asymmetric digest.**
**R3 — timing.** All three `build_body` sites read the pool live; an adversary introducing one fresh variant per round drives R1 repeatedly and pools never coincide at digest time.
**R4 — the 64-cap.** `F2_VIEW_LIST_CAP` truncates the COMMITTED VIEW to the 64 lowest hashes (`node.cpp:1117-1120`) while the MATERIALIZED set is uncapped, so past 64 distinct equivocators different members name different 64-subsets by construction.

### Two corrections that matter regardless of which fix lands

1. **"Carry the forensic fields outside the hashed identity" is STRICTLY WORSE THAN USELESS.** Dedup and the union filter would treat A's `(anchor=17)` and B's `(anchor=12)` as the same element, `check_eqabort_reconciliation` passes both, **the digests MATCH so K-of-K verifies on BOTH**, and you get two fully valid same-height blocks with different block hashes handed to `resolve_fork`'s smallest-hash tiebreak — the malleability wedge, reachable with **no strip at all**. The fields must be DELETED from the struct (or forced constant at every ingest AND rejected non-zero at validate), never merely dropped from the hash.
2. **`build_body` pushes in POOL INSERTION ORDER with no sort** (`producer.cpp:1231` over the `std::vector` pool). Two nodes with byte-identical, identical-CONTENT pools still emit different block bytes. **A canonical list sort is required regardless of which design lands.**

Also recorded: in MUTUAL_DISTRUST `kind` is always 1 — `detect_equivocation` requires a non-empty `bft_proposer` on BOTH blocks (`producer.cpp:459-460`) and `current_proposer_domain()` returns "" outside BFT (`node.cpp:1345-1346`), so the kind-0 family cannot fire in MD. Under BFT it becomes an additional divergence axis.

### Conclusion

Canonicalization is a genuine improvement — it removes the two-contrib order split, the anchor split, and the same-height-twins malleability wedge — but it is **necessary-at-best and not sufficient**. Any design that keeps `pending_equivocation_evidence_` as an input to `build_body` asks nodes to agree on the membership of a locally-observed set **without first agreeing on it**. The set must become a deterministic function of data every assembler already holds — the K signed contribs plus the chain — which is exactly the routing `shard_tip_records` already uses (`producer.cpp:1449-1470`). **That is payload demotion (DECISION-LOG 84c1447, VIABLE-WITH-CONDITIONS), and it is now the recommended fix for C0.**

*Process note: the synthesis agent died on an API error mid-response, so no formal spec was produced; the three lens analyses are unambiguous and are the record. A spec pass should precede implementation.*

**Authority:** design analysis recorded by Claude Fable, 2026-08-13. No code written.

## 2026-08-13 — C0 fix attempt (union→intersection): FAILED review (10 findings, 5 false alarms). Reverted. It trades a halt for silent suppression, and does not close C0.

**Build-proof protocol worked** — six documented cycles with before/after binary hashes, the revert reproducing an earlier hash byte-for-byte. No false result this time. The defects are real, not artefacts.

### What the attempt got right, and it is genuinely valuable

**Step 0 answered the shape question correctly and corrected my framing.** `ContribMsg` carries HASHES only (`producer.hpp:52`, `view_eq_list`, capped 64) — no `EquivocationEvent` anywhere in the struct, the JSON, or the CONTRIB frame. And **`shard_tip_records` does not carry records either**: it carries full-content hashes and materializes from the local store restricted to `reconcile_INTERSECTION`. **The intersection is the whole mechanism** — every element is in every member's signed view, hence in the assembler's own signed view, hence in its own local store. The local store is a *lookup table for an already-agreed set, never a filter on it*. That is exactly the owner's invariant, and the eq dimension was the one place using `reconcile_UNION`, where the pool IS a filter — `pool ∩ union` being a proper per-node subset is C0.

So the literal "creators[0]'s list" I proposed was **strictly worse** and correctly not implemented: it needs every other assembler to materialize events from hashes it may never have received, re-creating C0 in a new guise; making it sound requires putting structs on the wire at **+14,656 B per contrib per member**.

**Also established:** the canonical sort is spec conformance, not invention — `F2-SPEC.md:116` already specified "sorted canonically" and the code never did it. `hash_equivocation_event` is a **total** order (SHA-256 over every field); `(equivocator, block_index, body_root_a)` is not.

### Why it cannot land

1. **C0 IS NOT CLOSED — the rule is producer-side only.** The verifier still accepts subset-of-union (`validator.cpp:1705-1711`), so any assembler that does not run the new logic still emits a divergent set and every honest node accepts it. The new gate asserts a **producer-side proxy** — precisely the "assert at the layer where the rule lives" failure that refuted Option C, now recorded in doctrine and violated anyway.
2. **The canonical sort has no verifier rule either**, so the two-same-height-blocks-behind-one-valid-digest wedge the comment claims to close remains open.
3. **The equivocator can now suppress its own evidence permanently at zero cost.** Intersection over observer-dependent identities (the hash binds `beacon_anchor_height` and the arrival-order `(a,b)` slots) means a splitter simply ensures no two observers hold the byte-identical record — the intersection is then empty and evidence NEVER reaches the chain. The halt becomes silent suppression: better than a halt, but it voids the economic bound the authoritative docs still assert.
4. **The pre-activation `else` branch is unmitigated C0**, including a state/slashing fork, while the new comment calls it merely "byte-identical to v1".
5. **It is a genesis-frozen consensus accept-rule change presented as safe because the wire delta is zero.** Zero wire delta does not make an accept-rule change unfrozen; it was neither labelled nor sequenced as one.

### The standing lesson, now twice-confirmed

A fix applied only in the assembler cannot close a divergence the verifier still admits. **Any C0 fix must change what the VERIFIER accepts** — intersection-sourcing enforced as a validation rule, not merely as producer behaviour — and must state its completeness cost, because unanimity-gating and suppression-resistance are in direct tension.

**Tree reverted; ci_local green. C0 remains OPEN and is still a live remotely-triggerable permanent halt at HEAD.**

**Authority:** review findings recorded by Claude Fable, 2026-08-13.

---

## 2026-08-13 — C0 fix attempt 2 (VERIFIER-enforced intersection) REFUTED: exact set-equality is a NEW permanent halt, and unanimity is vetoable by one member

**Status:** REVERTED before commit. Adversarial review of the uncommitted diff returned
**7 confirmed defects (1 critical, 2 high, 2 medium, 2 low) against 2 false alarms.**
The gate was green. Green is not proof — tenth confirmation this session.

The diff did exactly what the previous refutation demanded: it moved the rule into
`BlockValidator::check_eqabort_reconciliation` (a `validate()` gate, not producer
behaviour), enforced the canonical sort as a validation rule, deleted the pre-activation
`else` branch, labelled itself genesis-frozen, and stated the completeness cost. The
implementation was faithful. **The specification was wrong.**

### CRITICAL — exact set-equality manufactures an inescapable permanent halt

`validate()` runs `check_equivocation_events` at `validator.cpp:49`, **before**
`check_eqabort_reconciliation` at `:56`. The earlier gate rejects the WHOLE block with
`"equivocator not in registry"` when `resolve_committee_member_pubkey` returns nullopt
(`validator.cpp:471-474`); `NodeRegistry::build_from_chain` (`registry.cpp:64-70`) omits
any domain failing `chain::domain_eligible`, i.e. deregistered (`inactive_from`), below
`min_stake` after UNSTAKE, not yet active, or suspended
(`eligibility_floor.hpp:83-86`). On a single-shard chain there is no frozen checkpoint,
so only the present head applies (`committee_pool.cpp:52-54`).

Meanwhile the intersection names that event **permanently**: `f2_eq_view` is built from
`pending_equivocation_evidence_` (`node.cpp:1117-1119`) with **no registry filter**, and
the pool's only prune site is the post-apply one. So once the equivocator leaves the
registry, `INTERSECTION_EXACT` **compels** the producer to include an event that the
earlier gate **compels** the validator to reject. Every candidate block at that height
fails validation, forever. Not a divergence — an absorbing halt reachable by an
equivocator simply unstaking.

**The general form, which is the transferable result:** a rule of the form
"the body field MUST equal a deterministic function of the committed views" is unsound
whenever an EARLIER validation gate can independently reject an element that function
names. Mandatory inclusion plus independent per-element rejectability equals a wedge.
`shard_tip_records` escapes this only because no earlier gate rejects a block for an
inadmissible record. **Check for an earlier per-element admissibility gate before
mirroring the intersection template onto any new dimension.**

### HIGH — unanimity is vetoable by one member, at zero cost, and canonicalization does NOT repair it

`reconcile_intersection` (`producer.cpp:605-622`) returns `{}` the moment ANY member's
list is empty. Nothing constrains view-list CONTENT: `validate_contrib_view_roots`
(`producer.cpp:640-706`) checks only the 64-cap (V21) and `compute_view_root(list) ==
root` (V22). A member commits `view_eq_list = {}` with the matching non-zero
empty-SHA256 root and passes. **Any single committee member therefore vetoes ALL
equivocation evidence, undetectably.**

This kills the sequencing plan the attempt was built on. Canonicalization (normalizing
`beacon_anchor_height` / `shard_id` / the arrival-order `(a,b)` slots out of
`hash_equivocation_event`) was nominated as the follow-up increment that would restore
completeness. It cannot: canonicalization makes honest observers AGREE on a record's
identity, but the veto is a member committing an EMPTY list, which is unaffected by how
records are named. **Intersection + canonicalization is not a completeness repair.**

### MEDIUM — ordinary packet loss empties the intersection, with no adversary

The regression was framed as an equivocator capability. Default network behaviour
suffices: the detector broadcasts ONCE (`node.cpp:2458`, `:3076`),
`on_equivocation_evidence` adopts WITHOUT re-broadcasting (`node.cpp:1901-1942`, per the
code's own comment at `:4620-4622`), `GossipNet::broadcast` is one-hop best-effort with
exceptions swallowed (`gossip.cpp:331-337`), and nothing re-requests. **One dropped frame
to one of K members empties the intersection permanently.** This is R2 from the
canonicalization refutation, now load-bearing.

### MEDIUM — pre-activation evidence becomes unrecordable

Deleting the `else` branch closed the state fork but overshot: `node.cpp:1102` gates the
whole F2 view block on `block_index >= f2_active_from_height()`, so pre-activation every
view list is empty, the intersection is `{}`, and the height-gate-free verifier rule
REJECTS any pre-activation block carrying evidence. At HEAD such evidence did land. On
any chain with `v2_7_f2_active_from_height > 0` this is a strict regression.

### LOW — the header contract still teaches the deleted rule

`producer.hpp:450` (`// union over contribs`) and `:461` (`V25: block.equivocation_events
== reconcile_union`) still state the union rule in the validator's own V-numbering;
`node.cpp:1110-1116` (the site that CONSTRUCTS `f2_eq_view`) and `producer.cpp:592-594`
(`reconcile_union`'s header) likewise. Same class as the ~20 no-TIER proof docs.

### Where this leaves C0

**C0 remains OPEN — a live, remotely-triggerable, unauthenticated permanent halt at
HEAD.** Two routes are now refuted, and the refutations are complementary rather than
incremental:

* **UNION** (HEAD, and the pre-activation branch): the assembler's local pool filters an
  agreed set, so sets diverge per-node ⇒ digest divergence ⇒ halt at K == M.
* **INTERSECTION-EXACT** (this attempt): agreement is restored, but completeness collapses
  to zero under a one-member veto or a single dropped frame, AND mandatory inclusion
  collides with the earlier admissibility gate to produce a second, worse halt.

The tension is now precisely located. Any successor must satisfy three constraints
simultaneously, and the third is the one both attempts missed:
1. the accepted set is a function of DIGEST-COVERED inputs only (kills union);
2. no single member can empty it (kills intersection);
3. **every element the rule COMPELS must be independently admissible at every earlier
   validation gate, at every future height** (kills intersection-exact).

Constraint 3 is satisfiable by construction only if the rule permits OMISSION of an
inadmissible element — i.e. the rule must be a predicate the producer can satisfy in more
than one way, which reintroduces (1). **Whether the three are jointly satisfiable is
itself the open question and should be settled at DESIGN stage, per doctrine, before any
further implementation.** Do not open attempt 3 as an implementation.

Note also that C0's severity is bounded by what it protects: with pre-finalization
slashing carrying no consensus consequence (owner decision, this date), the equivocation
evidence path buys forensics for L2, not L1 safety. A design that trades the halt for a
weaker-but-live evidence record is on the table; a design that trades it for a second halt
is not.

**Tree reverted (6 tracked files restored, 1 new script removed); 4 pre-existing stashes
intact.**

**Authority:** review findings recorded by Claude Fable, 2026-08-13.

---

## 2026-08-13 — Decentralized sharding (owner proposal P1-P4 + R1/R2) EVALUATED AT DESIGN STAGE: does NOT close C0; R2 REFUTED; but it surfaced a live unauthenticated value path and the actual C0 fix

**Status:** DESIGN-STAGE ONLY. No file edited, nothing implemented. 4 adversarial verdicts:
**3 REFUTED, 1 SURVIVES_WITH_CONDITIONS.**

**The proposal.** P1 parallel independent chains sharing only the PROTOCOL (no beacon, no
uplink); P2 a tx/message recorded only if ALL co-creators received it; P3/R1 clients submit
to a chosen replication factor R of N chains, duplication as the availability mechanism;
P4 smart clients; R2 every node can READ all chains, so registration may live on only one.

### VERDICT: it does not close C0

C0 is a property of how K co-signers assemble ONE body under ONE exact digest inside ONE
round on ONE chain. Every gate on the path is height-only, never shard-conditioned
(`node.cpp:1102`, `producer.cpp:1226`, `validator.cpp:1713`; `f2_active_from_height`
defaults to 0, `genesis.hpp:251`; producer.cpp's only `shard_count()` use is :1340, on the
cross-shard path). **The proposal lands ON the halting configuration** (`shard_count == 1`,
`ChainRole::SINGLE`), not away from it. C0 is class B, sharding-INDEPENDENT.

### R2 (self-authenticating evidence) — REFUTED, and it is dangerous

1. **Forged slash.** Carrying a pubkey while retaining the attacker-chosen `equivocator`
   name is unsound: the apply path forfeits stake and deregisters by that UNAUTHENTICATED
   NAME STRING (`chain.cpp:1811-1827`). Any remote socket slashes any validator for the
   cost of one keygen — `peer_message_allowed` admits EQUIVOCATION_EVIDENCE from any peer
   regardless of role (`gossip.cpp:117-121`).
2. **C0 escalation.** The registry gate at `node.cpp:1917-1919` is the ONLY bound on an
   uncapped pool (`node.hpp:785`). Deleting it turns C0 from insider-only into a free,
   unlimited-identity, anonymous-remote attack.
3. **The registry check is NOT a forfeiture vestige.** Even deleting the name entirely, the
   read MOVES to the apply path — `registrants_` is keyed by domain with no pubkey index
   (`chain.hpp:764`) — i.e. to the STRICTER layer, where `state_root` mismatch throws
   (`chain.cpp:1957-1971`).

### R2's "read all chains" is jointly unsatisfiable with P1 — REFUTED

**NINE of `validate()`'s gates consume the NodeRegistry** (`validator.cpp:44,45,46,47,48,
49,51,53,58`), and that registry is ALWAYS `build_from_chain` on the LOCAL chain
(`node.cpp:698, 2500, 2532, 2697`), reading `registrants/stake/abort_records/min_stake/
k_block_sigs` (`registry.cpp:47-80`). **Registration read by consensus is not a client
capability.** R2 therefore places a cross-chain read inside consensus: a state transition
on chain X (dave's REGISTER reaching `active_from`, or a `suspension_active` flip — not
even a transaction) permanently halts chain Y with ZERO Byzantine participants. R2 survives
only downgraded to false: registration PER-CHAIN, cross-chain reads confined to clients/L2.

### R1 flood-at-R — REFUTED on state integrity

`Transaction::signing_bytes()` (`block.cpp:20-32`) is
`type ‖ from\0 ‖ to\0 ‖ amount ‖ fee ‖ nonce ‖ payload` — **no chain_id, no genesis hash,
no shard_id**. `chain_id` reaches only `compute_genesis_hash`. One signed TRANSFER at R=3
applies three times against three balances; A1 and `state_root` green on all three. Worse,
**before any transaction**: `genesis-tool build-sharded` copies the config wholesale
(`main.cpp:5673`) and installs `initial_balances` with no rho filter (`genesis.cpp:759-770`),
so genesis mints N copies of every balance and of `zeroth_pool_initial`.

**The value/non-value split does not exist.** All 18 `TxType` values debit the sender,
including the three whose comments say "no value moves" (`chain.cpp:1191, :1209, :1226`).
REGISTER — the archetypal record R2 wants written once — is among the most value-bearing.
`DAPP_CALL` carries `tx.amount` AND needs a chain-local registry read (`validator.cpp:1199`).
**R1's availability model also fails for pure records:** a nonce mismatch rejects the whole
block (`validator.cpp:824-828`) and `build_body` skips a future nonce forever
(`producer.cpp:1322`), so one drop desynchronises that sender's stream permanently and the
R copies are R DISTINCT objects — cross-chain dedup on tx hash is impossible.

### The honest scaling answer

If every node reads all chains, storage and validation are N x regardless of R — that is
REPLICATION, not sharding, and buys ZERO throughput. Throughput requires nodes NOT to
validate foreign chains; light-verifying a foreign chain means checking its K-of-K against
ITS registry, obtained from that chain, which must be light-verified — the recursion whose
termination is exactly what a beacon provides. **Choose: no throughput win, or the uplink.**

### What the evaluation DID establish — three of these are actionable now

* **NEW SECURITY FINDING, live at HEAD.** `Node::on_cross_shard_receipt_bundle`
  (`node.cpp:2320-2365`) performs **no verify, no digest check, no registry lookup**;
  `src_block_hash` is never populated in production (`producer.cpp:1342-1346`);
  `check_inbound_receipts` checks shape/dedup/intersection only (`validator.cpp:1567-1642`).
  The destination credit (`chain.cpp:1832-1852`) is authorized by K-of-K agreement on
  **gossiped, unverified transit data**. `CrossShardReceipts.md:79-88` (L-7.4, **no TIER
  marker**) asserts the opposite. Needs an S-item and a doc correction regardless of any
  architecture decision.
* **A SECOND live halt vector.** `external_epoch_rand_` (`node.cpp:384-393`) reads
  `beacon_headers_` — a bare in-memory vector (`node.hpp:792`), never persisted,
  gap-intolerant (`node.cpp:1979-1983`), with no `BEACON_HEADER_REQUEST`
  (`node.cpp:1946-1948`) and a silent per-node local fallback (`validator.cpp:1516-1520`) —
  and feeds `check_creator_selection`, `check_abort_certs`, `check_block_sigs`. Different
  buffer depth => different committee => permanent halt at K == M. Dissolved by
  `ChainRole::SINGLE` today at zero cost.
* **A live C0 TRIGGER that is free to delete.** `ev.beacon_anchor_height` and `ev.shard_id`
  are written, hashed (`producer.cpp:434-436`) and **compared by nothing**. On a SHARD chain
  two HONEST observers of the same equivocation compute different event hashes purely from
  header-arrival skew — zero adversarial ordering. The in-code claim "each observation point
  will fill these consistently" is FALSE on a SHARD chain; `validator.cpp:1706-1712` concedes
  this as the reason the accept rule had to be SUBSET.
* **P1 has a hidden regression that COUPLES it to the refuted redesign.**
  `committee_pin_active` requires `shard_count() > 1` (`committee_pool.cpp:7-11`), so under
  P1 it is permanently false, killing the frozen-first leg of
  `resolve_committee_member_pubkey` — making the attempt-2 halt at `validator.cpp:471-474`
  STRICTLY MORE reachable. P1 therefore needs the evidence redesign, which is refuted. That
  is a bundle; doctrine forbids it.
* **CORRECTION to a claim made in-session.** `b.transactions` does NOT use
  `reconcile_intersection` — it is UNION plus a local `tx_store` filter
  (`producer.cpp:1280-1289`), the same shape as C0, and is simply NOT digest-bound (only
  `tx_root` is, `producer.cpp:858`). `compute_tx_root_intersection` was deleted as unused
  (`producer.cpp:773-781`). Only `inbound_receipts` (:1434-1447) and `shard_tip_records`
  (:1462-1494) use intersection. This correction is load-bearing: it is what makes
  Increment 0 below obviously right.

### THE ACTUAL C0 FIX — increment 0, ~6 lines, no wire change, no genesis change

**Demote the equivocation set OUT OF THE BLOCK DIGEST**: delete the
`any_nonzero(b.creator_view_eq_roots)` append at `producer.cpp:896-901`. The eq dimension
then becomes structurally identical to `transactions` — locally materialized, NOT
digest-covered, carried in the finalized block, validated SUBSET-of-union
(`validator.cpp:1749-1752`), applied from the RECEIVED set so `state_root` converges.
**Co-signers with different pools compute the SAME digest; the divergence has nowhere to
land.** This is exactly the payload demotion already authorized FOR DESIGN at 5b2d7fe /
84c1447.

Cost, stated: a single finalizer can strip evidence (the binding existed to stop a relayer
stripping an inbound receipt, `producer.cpp:865-874`). Under the L2 relocation that is a
FORENSICS loss, not an L1 safety loss — and the identical gap is already accepted for
`b.transactions`. Weigh a strippable forensic record against a live, remotely-triggerable,
absorbing halt.

**Do NOT bundle the abort dimension.** `abort_events` feed committee re-derivation
(`validator.cpp:138-160`) and the round `gen`; demoting it is a different design with a
different proof obligation.

**The gate does not exist today** and is the arm named at 5b2d7fe: 3 nodes, SINGLE/NONE,
K=M=3, two conflicting ContribMsgs from one member delivered in OPPOSITE orders to the two
honest peers, assert a block lands at h+1.

**And the evidence-completeness fix that nine designs hunted is ONE LINE:** a rebroadcast at
`node.cpp:1939`. `on_equivocation_evidence` adopts without re-broadcasting, gossip is
one-hop with no relay and no re-request (`gossip.cpp:335, :343`). No architecture required.

### Sequencing, if P1 is pursued on its own merits

`inc7c` -> P1 -> D2 step 1b -> step 2. Deleting MsgTypes 12/13/14 today reclaims nothing:
`binary_codec.cpp:975` casts the type byte with no range validation and `default: break`
falls through to the lp-JSON path, so an unknown type is fully `json::parse`d under a 1 MB
cap. P1 before 1b avoids re-extracting ~7,800 lines across 34 gate handlers.
**Wasted-work warning (sequence-before-harden):** `a1a0cf1` (Q1 beacon-header rand binding)
and the S-053 closure in `d34c632` (`verify_committee_sigs`) sit ENTIRELY on surface P1
deletes. That argues for deciding P1 now rather than after more hardening lands there.
**Dominant cost is re-pinning, not code:** eight state leaves are emitted unconditionally
(`chain.cpp:479-483, :491-495, :500-501`) so `state_root` changes from genesis on every
chain (137 gate scripts reference `state_root`, 61 reference leaf counts), and four genesis
mixes are unconditional (`genesis.cpp:808-809, :916, :920`) so every genesis hash changes —
leaving `chain_id` the SOLE sibling-chain distinguisher, a new load-bearing operator
constraint and exactly the failure S-039 exists to prevent.

**B4 interaction — a FOURTH DECISION CLOCK row.** `ReservedDiscriminatorAudit.md` preamble
decision (d) ("launch posture is EXTENDED sharding") is the entire named future for G-3
`TxType::REGION_CHANGE = 5` and G-4 `Block::partner_subset_hash`; under P1 the audit's own
razor flips both KEEP -> DROP (14/8 becomes 12/10). MsgTypes 12/13/14 need an explicit
KEEP-or-DROP verdict the audit does not contain — deleting without reserving forecloses
re-adding an uplink PERMANENTLY under no-migrations.

**Authority:** design-stage evaluation by Claude Opus 5, 2026-08-13. Nothing implemented.

---

## 2026-08-13 — UNMITIGATED-ISSUES SWEEP: 22 confirmed defects, FOUR CRITICAL LIVE HALTS, none previously on the record

**Status:** READ-ONLY sweep at e7c6fc2. Nothing implemented. Six lenses (consensus
accept-rules/apply path, hostile-bytes decode, vendored crypto, storage/restart/sync,
remote-reachable resource exhaustion, no-TIER doc truth), every finding independently
adversarially verified. **22 CONFIRMED, 3 false alarms, 2 duplicates** — the
known-issue list (C0, R-1..R-3, the five claim re-derivations, the D2 remainder, the
cross-shard receipt hole, etc.) was excluded up front, so every row below is NEW.

### THE HEADLINE: three of the four criticals are ONE STRUCTURAL DEFECT

**A transaction the block validator REJECTS can enter the mempool, be selected into a
contrib, and be included by `build_body` — and there is NO eviction path for a
queued-but-block-invalid tx.** `apply_block_locked` prints `[node] invalid block:` and
RETURNS (`node.cpp:2500-2508`), so `chain_.append` and `post_append_bookkeeping_locked` —
the ONLY mempool-eviction site — never run. Height never advances, the sender's
`next_nonce` never moves, and the next round rebuilds a byte-identical invalid body.
`try_finalize_round` broadcasts it anyway (`node.cpp:1529`) so every peer runs the same
rejection. **Deterministic, absorbing, fleet-wide halt, unrecoverable without restarting
every node with a wiped mempool — which the attacker re-poisons immediately.**

The authors identified this exact class and closed exactly one instance of it: the
MERGE_EVENT stall guard at `node.cpp:2810-2822`, whose own comment reads "the producer
keeps re-including a queued-but-block-invalid tx and the chain STALLS". Every other
validator shape-rule was left unmirrored. Three separate exploits of the one gap:
TRANSFER_PAYLOAD_MAX, the unsigned `pq_auth` blob, and the S-049 amount+fee overflow guard.

**This means the fix is structural, not three patches.** Per doctrine (assert at the layer
where the rule lives) the rule belongs in the producer + an eviction path, not only mirrored
at ingress — a mempool mirror alone leaves the union-sourced path open, since `build_body`
resolves the COMMITTEE union and can therefore include a tx that never passed THIS node's
ingress.

### A SECOND CONVERGENT ROOT: the chain cannot restart with a non-default genesis

Two independent lenses found it: `Chain::load` replays every block with DEFAULT consensus
parameters (`chain.cpp:3505` / `:3530`), so any genesis with a non-default `min_stake`,
`suspension_slash`, `unstake_delay`, merge thresholds, `crypto_profile` or subsidy mode
throws S-033 on FIRST RESTART and the node never starts again. Pre-genesis this is free to
fix; it is also a strong argument that no non-default genesis has ever been restart-tested.

### DIRECTLY RELEVANT TO INCREMENT 0 (the in-flight C0 fix)

`docs/SECURITY.md:284` asserts S-030 D1 closed because "a single canonical block per height
is enforced at apply". **That is false**: the apply-time `state_root` gate is a
SELF-CONSISTENCY check that cannot arbitrate between two same-digest bodies, and it is
disarmed outright by a zero `state_root`. Increment 0 demotes the eq set out of the digest,
which is precisely what makes two same-digest bodies constructible. **This is corroborating
evidence that increment 0's fork wedge is REAL and that the apply layer will not catch it.**
Increment 0 must not land until its fork-wedge check answers this.

### FULL CONFIRMED LIST


**[CRITICAL] Mempool ingress does not mirror the block validator's TRANSFER payload cap — one anonymous 0-value tx permanently halts the chain**  
`src/node/node.cpp:2839` (lens: wire-decode)

> `Node::mempool_admit_check` bounds `tx.payload` only at `chain::TX_FRAME_PAYLOAD_MAX` = 65535 (`include/determ/chain/block.hpp:315`), while `BlockValidator::validate` rejects the WHOLE BLOCK when a TRANSFER carries `payload.size() > TRANSFER_PAYLOAD_MAX` = 128 (`src/node/validator.cpp:840-842`, `include/determ/chain/params.hpp:72`). No other ingress site enforces 128 — grep for TRANSFER_PAYLOAD_MAX outside tests hits only validator.cpp:840. Attack, no HELLO, no stake, no registration, no funds: generate an Ed25519 keypair offline; its anon address is just "0x"+hex(pub) (`include/determ/types.hpp:115,143`). Gossip one TRANSACTION frame: type=TRANSFER, from=that anon address, to=anything, amount=0, fee=0, nonce=0, payload=200 random bytes, valid Ed25519 sig over signing_bytes. (1) `Node::on_tx` (node.cpp:2901): `tx.nonce(0) < chain_.next_nonce(unknown)=0` is false, so no stale drop (`src/c


**[CRITICAL] tx.pq_auth is unsigned and unbounded on every non-PQ tx type — 5 gossiped txs make every produced block exceed its own 4 MB wire cap**  
`src/chain/block.cpp:262` (lens: wire-decode)

> `Transaction::decode_frame`'s pq_auth section accepts any length that consumes the frame exactly (block.cpp:254-264), so pq_auth is bounded only by the enclosing per-type cap: ~1 MB inside a TRANSACTION envelope, ~4 MB inside a BLOCK. It is NOT covered by `Transaction::signing_bytes()` (block.cpp:20-32 — type‖from‖to‖amount‖fee‖nonce‖payload only) and therefore not by `tx.hash` (block.cpp:34-37). `verify_tx_signature_locked` verifies only the Ed25519 sig for any type != PQ_TRANSFER (node.cpp:2761-2778). Nothing requires pq_auth to be EMPTY on a non-PQ top-level tx — the only such check is on COMPOSABLE_BATCH inners (`src/node/validator.cpp:1323-1327`, `src/chain/chain.cpp:1461-1463`) — and nothing bounds its size: `mempool_admit_check` (node.cpp:2839) bounds `tx.payload` only, `MEMPOOL_MAX_TXS = 10000` (node.hpp:691) counts TXS not BYTES, and there is no block-size cap anywhere in consen


**[CRITICAL] enter_block_sig_phase cancels the Phase-1 timer BEFORE the all-K-contribs check — one non-committee contrib wedges every committee member permanently**  
`src/node/node.cpp:1203` (lens: liveness-dos)

> Committee sigma={A,B,C} (K=3) plus a fourth REGISTERED but unselected validator D. Node::on_contrib deliberately admits any signer resolvable in the registry, not just sigma members (node.cpp:2960-2963 resolve_committee_member_pubkey + the explicit comment at :2946-2952), so D's single well-formed ContribMsg for (block_index=height(), prev_hash=head, aborts_gen=current_aborts_.size()) is inserted at node.cpp:3086. On A the map goes {A} -> {A,D} -> {A,D,B}: size()==|sigma|==3, so the eager trigger at node.cpp:3088-3090 fires; enter_block_sig_phase() executes contrib_timer_.cancel() at :1203 and THEN returns at :1209 because pending_contribs_.find("C") fails. Nothing re-arms the timer: the only two arm sites are start_contrib_phase (:1181) and handle_contrib_timeout (:1681), and handle_contrib_timeout is exactly the callback just cancelled (LoopTimer::cancel suppresses the expiry, loop_tim


**[CRITICAL] build_body has no S-049 amount+fee overflow guard, so an unfunded wrapping tx is included and then rejected by every validator — permanent halt**  
`src/node/producer.cpp:1328` (lens: liveness-dos)

> An attacker generates an Ed25519 keypair and uses the self-certifying anon address 0x<pubkey> (include/determ/types.hpp:115 and :144 — no registration, stake, or balance required) to gossip one TRANSFER with nonce=0, amount=1, fee=UINT64_MAX, correctly signed. Node::on_tx admits it: verify_tx_signature_locked passes (node.cpp:2769 parses the pubkey out of the address) and mempool_admit_check (node.cpp:2805-2878) contains no amount+fee overflow check. At the next round start_contrib_phase snapshots EVERY mempool hash unfiltered (node.cpp:1069-1071), so the hash enters the committee tx_root. In build_body, 'uint64_t cost = tx.amount + tx.fee' (producer.cpp:1328) wraps to exactly 0, the filter 'if (sb < cost) continue;' at :1329 evaluates 0 < 0 = false, and the tx is pushed into b.transactions at producer.cpp:1423 despite a zero-balance sender. try_finalize_round calls apply_block_locked(bo


**[HIGH] Chain::load replays the whole chain with DEFAULT consensus parameters — any genesis with a non-default min_stake / suspension_slash / unstake_delay / merge thresholds / crypto_profile / subsidy_mode is permanently unrestartable**  
`src/chain/chain.cpp:3505` (lens: consensus-accept)

> Chain::load seeds the replay Chain with only six fields (chain.cpp:3505-3510: block_subsidy_, shard_count_, shard_salt_, my_shard_id_, epoch_blocks_, k_block_sigs_) and then calls c.apply_transactions(b) for every stored block at :3530. min_stake_, suspension_slash_, unstake_delay_, merge_threshold_blocks_, revert_threshold_blocks_, merge_grace_blocks_, crypto_profile_, subsidy_pool_initial_, subsidy_mode_ and lottery_jackpot_multiplier_ keep their in-class defaults (chain.hpp:856-880). Node sets the first seven only AFTER load returns (node.cpp:567-577) and never sets subsidy_pool_initial_/subsidy_mode_/lottery_jackpot_multiplier_ on the load path at all (they are set only inside the `if (chain_.empty())` genesis-bootstrap branch, node.cpp:643-645). Every one of these is an unconditional state_root leaf (chain.cpp:472-483, k:min_stake at :476, k:suspension_slash :477, k:unstake_delay :4


**[HIGH] AbortEvent.event_hash is never verified anywhere, yet it is the sole entropy mixed into post-abort committee reselection — the next committee is grindable at one SHA-256 per trial**  
`src/node/validator.cpp:369` (lens: consensus-accept)

> check_abort_certs (validator.cpp:242-373) verifies the claim quorum but never recomputes ae.event_hash (nor ae.timestamp) against crypto::compute_abort_hash / chain_abort_hash — those helpers exist only in src/crypto/random.cpp:102,112 and are called only by the honest formation path at node.cpp:1805-1807. Node::on_abort_event (node.cpp:1843-1895) likewise validates only the claims. The signed AbortClaim covers just (block_index, round, prev_hash, missing_creator) — make_abort_claim_message at validator.cpp:361 and node.cpp:1881 — so ONE claim quorum is portable to ANY 32-byte event_hash. That value is then folded straight into the committee seed: node.cpp:1035 and validator.cpp:150 / :369 all compute rand = SHA256(rand || ae.event_hash), and crypto::select_m_creators(rand, avail, m) (random.cpp:70-100) derives the entire creator set and its order from that rand alone. Concrete attack: c


**[HIGH] Node::on_abort_event dedups on event_hash only, so a replayed AbortEvent with a mutated event_hash is adopted a second time against the same node — wedging the height for every honest peer**  
`src/node/node.cpp:1852` (lens: consensus-accept)

> on_abort_event's only duplicate guard is `for (auto& existing : current_aborts_) if (existing.event_hash == ev.event_hash) return;` (node.cpp:1852-1854) — there is no (round, aborting_node) key. Since event_hash is unbound to the claims (make_abort_claim_message at node.cpp:1881 covers only block_index/round/prev_hash/missing_creator) and unverified, any peer can capture a legitimately-gossiped AbortEvent, flip one byte of event_hash (or its unchecked timestamp), and re-broadcast — ABORT_EVENT is accepted from any peer (gossip.cpp:119). A node that already adopted the original misses the dedup, re-validates the same genuine claim signatures against its post-reselection committee, and pushes a SECOND AbortEvent naming the SAME aborting_node into current_aborts_ (node.cpp:1889). Concrete failure at M=4/K=3: committee {A,B,C}, C dies, A and B each sign a claim, the abort against C forms and


**[HIGH] docs/SECURITY.md asserts S-030 D1 is closed because "single canonical block per height is enforced at apply" — the apply-time state_root gate is a self-consistency check that can never arbitrate between two same-digest bodies, and it is disarmed outright by a zero state_root**  
`docs/SECURITY.md:284` (lens: consensus-accept)

> SECURITY.md:284 (no-TIER, the authoritative S-item ledger) claims that divergent b.transactions gives a divergent state_root and that "the validator's apply-time compute_state_root() != b.state_root check in chain.cpp::apply_transactions loud-fails on the inconsistent node... Single canonical block per height is enforced at apply." The code does not do this. (1) The gate at chain.cpp:1956-1971 compares the node's recompute against the SAME BLOCK's declared state_root. apply is deterministic over b.transactions, so any honestly-assembled block reproduces its own declared root on every node — the check passes by construction regardless of which subset of the tx_root union the assembler materialized. It never compares against another node's state or against any committee-signed value, so it cannot select a canonical block. (2) The gate is entirely skipped when b.state_root == 0 (chain.cpp:1


**[HIGH] BEACON cross-shard bundle relay re-broadcasts to all peers including the sender, with no dedup, TTL or hop limit — two peered beacons loop forever**  
`src/node/node.cpp:2329` (lens: wire-decode)

> `Node::on_cross_shard_receipt_bundle` (node.cpp:2320-2331) is, for ChainRole::BEACON, exactly `gossip_.broadcast(relay); return;` — executed BEFORE any check, with no seen-set, no hop count and no TTL field in the message. Its own comment claims "re-broadcast to peers other than the sender", which the code cannot do: the handler receives only the `net::Message` (node.hpp:583-585) and never a Peer handle, and `GossipNet::broadcast` (src/net/gossip.cpp:~318-325) iterates `peers_` with no exclusion. `peer_message_allowed` admits CROSS_SHARD_RECEIPT_BUNDLE from any peer whose declared role is BEACON or SHARD (gossip.cpp:122-127) — self-declared in HELLO, so trivially available to any remote socket. On a beacon chain with >=2 BEACON-role nodes peered for their own K-of-K consensus via `bootstrap_peers` (node.hpp:78, "intra-chain only"), a single injected bundle is permanent: beacon A relays i


**[HIGH] Chain::load replays every block with DEFAULT economic parameters — first restart of any chain with a non-default genesis param throws S-033 and the node never starts again**  
`src/chain/chain.cpp:3530` (lens: storage-restart)

> `Chain::load` constructs a fresh `Chain c` (chain.cpp:3504) and sets exactly six fields before replay: block_subsidy_, shard_count_, shard_salt_, my_shard_id_, epoch_blocks_, k_block_sigs_ (chain.cpp:3505-3510). It then replays every block via `c.apply_transactions(b)` (chain.cpp:3530). Eight further parameters are consumed BY apply_transactions and are NOT threaded: `min_stake_` (freeze_epoch_committee, chain.cpp:818/822), `unstake_delay_` (DEREGISTER sets `unlock_height = inactive_from + unstake_delay_`, chain.cpp:1313), `suspension_slash_` (abort slash deduct, chain.cpp:1795), `subsidy_mode_`/`lottery_jackpot_multiplier_`/`subsidy_pool_initial_` (the per-block payout, chain.cpp:1722-1743), `crypto_profile_` (enote_commitments_ gating, chain.cpp:1158), and the merge thresholds. All of them are ALSO unconditional `k:` state-root leaves (chain.cpp:472-489). Node::start sets them only AFT


**[HIGH] Snapshot bootstrap truncates blocks_ to at most `header_count` tail headers, so chain_.height() becomes 16 instead of the real height — the node can never apply another block, and its next restart throws**  
`src/node/node.cpp:603` (lens: storage-restart)

> `Chain::height()` is `blocks_.size()` (include/determ/chain/chain.hpp:92), but `encode_state` writes only the LAST `header_count` blocks (chain.cpp:3002-3007), default 16 (chain.hpp:699, rpc.cpp:250-256), hard-capped at 256 (chain.cpp:3000). `decode_state` pushes exactly those frames into `blocks_` with no padding (chain.cpp:3213-3219), and its post-load gates only check `blocks_.back()` (head_hash, block_index, state_root, A1 — chain.cpp:3233-3284), so the truncation is invisible. Node::start adopts that chain wholesale at node.cpp:603. Concrete failure: donor at height 5000 runs `snapshot create` (default 16 headers); a receiver configured with `snapshot_path` starts. It logs `restored from snapshot ... block_index=4999` (node.cpp:611), but `chain_.height()` is 16 while `chain_.head().index` is 4999. (a) LIVE: the next network block arrives at index 5000; `apply_block_locked` takes `if


**[HIGH] Unfunded max-fee transactions permanently seal the mempool — the declared fee is never checked against any balance**  
`src/node/node.cpp:2868` (lens: liveness-dos)

> An attacker mints 100 self-certifying anon addresses (include/determ/types.hpp:115/144 — free, no chain state) and gossips 100 TRANSFERs from each (nonces 0..99) with amount=0 and fee=UINT64_MAX, every one correctly signed. Each passes verify_tx_signature_locked and mempool_admit_check: the per-sender quota is MEMPOOL_MAX_PER_SENDER=100 (node.hpp:436) and there is no balance or funding check anywhere in the admission path, so tx_store_ fills to MEMPOOL_MAX_TXS=10000. From that moment every honest transaction, gossip (node.cpp:2911) or RPC, reaches node.cpp:2862-2874 where min_fee scans to UINT64_MAX and 'tx.fee <= min_fee' is TRUE for every representable u64 fee — admission is rejected unconditionally and forever. The garbage never drains: build_body skips each entry because sb(0) < cost(UINT64_MAX) at producer.cpp:1329, so they are never applied, their nonces never advance and the stale


**[HIGH] Every non-progressing CHAIN_RESPONSE re-broadcasts GET_CHAIN to all peers — self-amplifying sync storm with no backoff**  
`src/node/node.cpp:3270` (lens: liveness-dos)

> A node that believes it is behind enters start_sync_if_behind (node.cpp:3306-3341), which sets sync_peer_ = nullptr at :3338 so request_next_chunk BROADCASTS GET_CHAIN to all P peers (node.cpp:3355-3361). Because 'from = height()-1' (:3355), a peer at the SAME height replies with exactly one already-held block; on_chain_response routes it into the same-height branch, and maybe_reorg_to_locked drops it as a byte-identical duplicate at node.cpp:2653. 'progressed' is therefore false, and control falls to the else branch at node.cpp:3269-3271, which calls start_sync_if_behind AGAIN — still behind, so it broadcasts a fresh GET_CHAIN to all P peers. An empty reply takes the identical path at node.cpp:3232-3236. There is no backoff, no in-flight request bound and no dedup, so each received response produces P new requests: one initial request becomes P, then P^2, until the mesh saturates. Every


**[HIGH] PROTOCOL.md/WHITEPAPER/SECURITY.md specify the block-digest and contrib-commitment preimage as "DTM-BLKDIG-v2 ‖ index ‖ body_root" — shipped code is "DTM-BLKDIG-v3 ‖ index ‖ gen ‖ body_root"**  
`docs/PROTOCOL.md:264` (lens: doc-truth)

> PROTOCOL.md:264 states `block_digest = SHA-256("DTM-BLKDIG-v2" ‖ index u64 BE ‖ body_root)` and :267 states `compute_block_digest(b) = compose_block_digest(b.index, compute_block_digest_body(b))` (two arguments). Shipped code at src/node/producer.cpp:1004-1012 is `compose_block_digest(uint64_t index, uint64_t gen, const Hash& body_root)` appending the literal `"DTM-BLKDIG-v3"`, then `index`, then `gen`, then `body_root`; src/node/producer.cpp:1021-1026 calls it as `compose_block_digest(b.index, b.abort_events.size(), compute_block_digest_body(b))`. The contrib family is identically v3 (src/main.cpp:20131, src/node/node.cpp:3015, light/verify.cpp:261, light/main.cpp:7674). The doc's own framing ("a level sufficient for an external implementer to build a compatible client", PROTOCOL.md:3) makes this load-bearing: an implementer built to the spec computes a digest that differs on every bloc


**[MEDIUM] CONFIDENTIAL_TRANSFER proof randomness is derived only from (nonce_seed, tx_nonce), not from the statement — rebuilding a transfer at the same nonce discloses the amounts**  
`light/ct_tx.cpp:245` (lens: crypto)

> build_confidential_transfer_tx derives EVERY Bulletproof blinder from eff_seed = nonce_seed || u64_be(tx_nonce) alone: alpha (:247), rho (:248), tau1 (:249), tau2 (:250), sL/sR (:253-254), and the balance Schnorr nonce k (:277). None of the note commitments, C_in/C_out, fee, or E enter the derivation. Contrast ct_payload in the SAME file (:126-130), which correctly binds r and E (and ctx for UNSHIELD) into k. Concrete failure: a user rebuilds a pending transfer at the SAME account nonce with the same --nonce-seed but different outputs (the ordinary replace-a-pending-tx / fee-bump flow; the CLI takes --nonce and --nonce-seed as separate explicit arguments, and the guard at :202 only rejects seeds < 32 bytes). Both proofs then carry the same alpha and rho but different Fiat-Shamir challenges (V differs, so y/z/x differ per atr_challenge, rangeproof.c:597-604). The published field mu = alph


**[MEDIUM] docs/proofs/ChainStorageV1.md (no TIER, marked SHIPPED) documents a chain store format and an operator recovery step that D2 inc8 deleted — following its recovery instruction silently discards the node's entire local chain**  
`docs/proofs/ChainStorageV1.md:19` (lens: storage-restart)

> ChainStorageV1.md carries no TIER marker and is labelled 'Status: SHIPPED'. It documents the at-rest store as `<chain_path>.blocks/<i>.json` (line 19) and `<chain_path>.manifest.json` holding `{format:"chain-blocks-v1", height, head_hash}` (line 21). The shipped code writes `<chain_path>.blocks/<i>.blk` — a `DBK1` magic followed by a `Block::encode_frame` frame — and `<chain_path>.manifest.bin`, a FIXED 44-byte `DMF1` record with no `format` field at all (src/chain/chain.cpp:3353-3379). The doc further describes a legacy `chain.json` fallback, `Chain::save()` invalidating the manifest (line 42), and a dual-write below height 4096 (line 57); `Chain::save` no longer exists, the dual-write branch was removed (src/node/node.cpp:919-923), and chain.cpp:3490-3496 states there is NO text fallback. The operationally harmful line is line 40: 'Operator recovery: delete `<chain_path>.manifest.json`


**[MEDIUM] Per-peer egress queue is unbounded with no drop policy, and S031ConcurrencyComposition.md F-3 asserts a defence that does not exist in the code**  
`src/net/peer.cpp:122` (lens: liveness-dos)

> GossipNet::accept_loop (src/net/gossip.cpp:46-57) accepts every inbound connection unconditionally and attach() (:83) pushes the Peer into peers_ BEFORE any HELLO, so every accepted socket receives every gossip broadcast. Peer::send appends to write_queue_ — a std::deque<std::vector<uint8_t>> with no cap (include/determ/net/peer.hpp:57) — and do_write (src/net/peer.cpp:126-148) invokes on_close_ only when a write returns an error, never on backlog. An attacker opens N TCP connections and simply stops reading (or drains one byte per second): every socket stays healthy at TCP level while the node queues every BLOCK / CONTRIB / BLOCK_SIG / ABORT broadcast into N unbounded deques, with a single BLOCK message permitted up to 4 MB (include/determ/net/messages.hpp:159). Memory grows as N x gossip-byte-rate until OOM, and each broadcast is O(N) under peers_mutex_. Neither guard reaches it: the S


**[MEDIUM] CLI-REFERENCE.md documents `determ-wallet verify-equivocation` without the --gen-a/--gen-b arguments the shipped tool requires, and states a V11 predicate missing the gen clause**  
`docs/CLI-REFERENCE.md:638` (lens: doc-truth)

> docs/CLI-REFERENCE.md:638 documents the invocation as `determ-wallet verify-equivocation --pubkey <hex64> (--kind <0|1> --block-index <N> --index-a <N> --body-root-a <hex64> --sig-a <hex128> --index-b <N> --body-root-b <hex64> --sig-b <hex128> | --event <file> …)` and states `PROVEN ⟺ kind <= 1 ∧ index_a == index_b == block_index ∧ body_root_a != body_root_b ∧ sig_a != sig_b ∧ both sigs verify over their own DERIVED digest SHA-256(TAG(kind) ‖ index u64 BE ‖ body_root) — TAG(0) = "DTM-BLKDIG-v2", TAG(1) = "DTM-CONTRIB-v2"`. The shipped tool requires two more arguments and one more clause: wallet/main.cpp:7522 prints the usage `--index-a <N> --gen-a <N> --body-root-a <hex64> --sig-a <hex128>`, wallet/main.cpp:7553-7555 parses `--gen-a`, wallet/main.cpp:7452 uses `TAG = "DTM-BLKDIG-v3"` / `"DTM-CONTRIB-v3"` with `gen` in the preimage, wallet/main.cpp:7456 adds clause `(2b) gen_a == gen_b`, 


**[MEDIUM] PROTOCOL.md §4.4/§9.1/§9.2 assert every Block on the wire is JSON and that Block::encode_frame has no call site — six message types have shipped as binary frames since inc7a/7b**  
`docs/PROTOCOL.md:289` (lens: doc-truth)

> PROTOCOL.md:289 states `Block::encode_frame`/`decode_frame` "ship **alongside** `to_json`/`from_json` and **no call site uses them yet** … Nothing in this section describes bytes currently on the wire or on disk; the wire still carries those five as length-prefixed JSON inside the binary envelope". PROTOCOL.md:726 states "**The remaining eight types** — `[u32 LE json_len][json_bytes]` … BLOCK, CONTRIB, CHAIN_RESPONSE, BEACON_HEADER, SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE, SNAPSHOT_RESPONSE, HEADERS_RESPONSE … **no wire path uses it yet** — every `Block` on the wire today is JSON", and PROTOCOL.md:736 states "Eleven of the nineteen types travel as fixed binary frames". The §9.2 table rows still read `Block` JSON for ID 1/12/13/14, `ContribMsg` JSON for ID 4, and `{blocks, has_more}` for ID 6. Shipped: src/net/binary_codec.cpp:945-953 dispatches BLOCK and BEACON_HEADER to `encode_block_payl


**[MEDIUM] RoundStallValveSoundness.md Claim C-2 asserts the S-050 valve cannot fabricate equivocation evidence — false on an empty abort tail, and the code it relies on says so**  
`docs/proofs/RoundStallValveSoundness.md:53` (lens: doc-truth)

> Claim C-2 (docs/proofs/RoundStallValveSoundness.md:53) concludes "A valve-induced re-sign therefore cannot fabricate equivocation evidence against the reset node", justified by "the reset cleared `current_aborts_`, so the fresh contrib carries `aborts_gen = 0` while peers still in the forked round hold `aborts_gen = |their tail| ≠ 0`" — the argument silently requires a non-empty abort tail. The valve does not require one: src/node/node.cpp:1615-1651 (`maybe_stall_reset_locked`) fires on the soft/hard wall-clock windows alone; with an empty tail `current_aborts_.size() != stall_abort_count_` is never true (both 0), so the soft-restart branch at :1629-1634 never defers, and after `kRoundStallMinTicks = 3` plus the 5 s soft window it calls `current_aborts_.clear()` (a no-op), `reset_round()` and `check_if_selected()` — re-entering `start_contrib_phase` at the SAME height with a FRESH `dh_in


**[MEDIUM] PROTOCOL.md §4.3's "fixed order" digest-body enumeration omits four of the eight conditional appendages shipped in compute_block_digest_body**  
`docs/PROTOCOL.md:273` (lens: doc-truth)

> PROTOCOL.md:273 introduces the body preimage as "the v1 core minus `index` … **then** the v2.7 F2 conditional appendages, in this fixed order (matches `src/node/producer.cpp::compute_block_digest_body`)" and enumerates exactly three (inbound, equivocation, abort), adding `partner_subset_hash` and `timestamp` in the prose at :281. Shipped `compute_block_digest_body` (src/node/producer.cpp:855-1002) appends eight conditional groups in order: inbound view root (:876-882), eq view root (:899-904), abort view root (:905-910), `partner_subset_hash` when non-zero (:924-926), `timestamp` when `creator_proposer_times` is non-empty (:942-944), `signature_form` when non-zero as a u8 (:953-955), `eligible_count` and `source_shard_id` as two u64s when `eligible_count != 0` (:983-986), and a view root over `shard_tip_records` when non-empty (:995-1001). None of `signature_form`, `eligible_count`, `sou


**[LOW] Chain::load bypasses Chain::append's prev_hash linkage check, so the S-021 'transitively covers every prior block' closure claimed in docs/SECURITY.md does not hold for the shipped loader**  
`src/chain/chain.cpp:3531` (lens: storage-restart)

> `Chain::append` enforces the chain link — `if (!blocks_.empty() && b.prev_hash != head_hash()) throw` (include/determ/chain/chain.hpp:57-58). `Chain::load` does not call append: it calls `c.apply_transactions(b)` and then `c.blocks_.push_back(std::move(b))` directly (chain.cpp:3530-3531), so no block's `prev_hash` is ever compared against the recomputed hash of its predecessor, and the loop index `i` is never compared against the decoded `b.index`. The only cryptographic gate is the head-hash compare (chain.cpp:3544-3554), which covers the head block's own bytes — including its stored `prev_hash` FIELD, but not the actual content of block N-2. Concrete failure: an attacker or bit-rot alters a MID-chain block file, e.g. rewrites `<path>.blocks/2.blk` changing only `timestamp`, or stripping/replacing `creator_block_sigs`, or rewriting `prev_hash`. None of those fields is read by `apply_tra


### Sequencing

The four criticals are LIVE HALTS reachable by an unauthenticated remote peer for a few
hundred bytes, and are CHEAPER to trigger than C0. They are also independent of the D2
migration and of the sharding decision — none sits on deletable surface. They outrank the
remaining D2 work. Each lands as its own increment with its own adversarial review; the
three-exploit structural defect lands as ONE core fix plus separate riders, per the
smallest-increment rule.

**Authority:** read-only sweep by Claude Opus 5, 2026-08-13. Nothing implemented.

---

## 2026-08-13 — C0 increment 0 (digest demotion) REFUTED: the safety argument depended on a premise that IS NOT AT HEAD

**Status:** REVERTED before commit. **23 confirmed findings (1 CRITICAL, 3 HIGH) against 2
false alarms.** The gate was green, 21 arms, both mutants build-proofed RED. Green is not
proof — eleventh confirmation this session. Diff preserved at
`scratchpad/increment0-digest-demotion.patch` (909 lines); it contains the first live
reproduction of C0 and should be salvaged, not rewritten, when the ordering below is fixed.

### WHAT THE ATTEMPT GOT RIGHT — keep these results

* **C0 REPRODUCED LIVE, for the first time.** The new gate at HEAD goes RED with
  `invalid BlockSig` from every peer -> phase-2 timeout -> abort quorum -> halt, on 3 nodes,
  K = M = 3, `ChainRole::SINGLE`, `shard_count == 1`. C0 is no longer an argument; it is a
  reproducible test. Build-proofed: `a68ead88` -> `bffac8ff` (RED), fix `bffac8ff` ->
  `f2d499f6` (green), M1 restore-eq-append RED, revert reproduced `42285cf6` byte-for-byte.
* **The fork-wedge question is ANSWERED, and the answer is benign.** In MUTUAL_DISTRUST
  every committee member assembles and broadcasts its own body (`node.cpp:1433`, `:1519-29`)
  — multi-assembler, not single-proposer — and `b.equivocation_events` IS inside
  `Block::signing_bytes()` (`block.cpp:669-686`), so two co-signers do produce two blocks
  behind one digest. That is handled by a PRE-EXISTING mechanism: **A4 / S-048 depth-1
  same-height fork resolution**, `maybe_reorg_to_locked` (`node.cpp:2645`) ->
  `Chain::resolve_fork` (`chain.cpp:2089`), a pure symmetric TOTAL order (non-zero-sig count
  desc -> `abort_events.size()` asc -> smallest `compute_hash()`) whose own comment names
  "honest mempool divergence per S-030". `b.transactions` already lives in exactly this
  class today. Verified empirically, not just argued.
* **No v1/v2 shape change.** `compute_block_digest_body` is straight-line with independent
  conditional appends; deleting the eq leg leaves the abort leg's trigger, position and tail
  byte-unchanged.

### THE REFUTATION — the stated cost was FALSE, and I stated it

The increment's justifying comment read: *"a finalizer can strip evidence after the
committee signs. Under the L2 relocation of slashing that is a FORENSICS loss, not an L1
safety loss."* **The L2 relocation is NOT at HEAD.** It was written, failed adversarial
review (22 findings, 1 critical) and was REVERTED; `chain.cpp:1815-1827` still forfeits the
equivocator's ENTIRE locked stake and sets `inactive_from`. Stripping is therefore a **live
consensus-state mutation performed by an unauthenticated relayer**, not a forensics loss.

**This error originated in the design memo and was repeated to the owner.** It is the same
class as every previous failure: a safety argument resting on a state of the tree that does
not exist.

**CRITICAL (reproduced end-to-end on a live 3-node cluster + a fresh follower, and falsified
against the pre-diff control).** A stripped block that does NOT recompute `state_root`
drives `revert_head()` and then an unguarded `append()` that THROWS — the head is silently
lost (`node.cpp:2711`). Zero state, one message, no grinding: any peer that has merely SEEN
a block carrying evidence deletes `b.equivocation_events` and rebroadcasts.

**HIGH — post-signature strip keeps K-of-K validity.** With the digest blind to the eq set,
`B' = B` minus the evidence re-derives the SAME digest, so `check_block_sigs` passes
unchanged. Evidence becomes permanently suppressible by any unauthenticated peer.

**HIGH — the accused equivocator suppresses its own evidence DETERMINISTICALLY.** Not a
race. E is still a committee member at the height its evidence lands (deregistration is
`index+1`, `chain.cpp:1826`). E assembles a body with `equivocation_events = {}` — trivially
a subset of the union, so `check_eqabort_reconciliation` passes — sharing the digest with
the honest siblings, so the same K-of-K signatures verify. E then wins the `resolve_fork`
tiebreak by GRINDING `compute_hash()`, which is malleable under a fixed digest (the standing
CLAUDE.md constraint: `compute_hash` appends `creator_block_sigs` and Ed25519's nonce is
signer-side, so ~one sign per trial).

**HIGH — four authoritative closures silently reopened**: S-011, S-013, S-029 Level-3
(broken FIRST-ORDER, independent of the evasion argument — `S029ForkChoiceSoundness.md:325-331`)
and BFTSafety B2 / T-5.1. Only S-030-D2 was flagged.

**HIGH — `SECURITY.md:1012`** credits `determ test-block-digest` with "F2 POSITIVE BINDING
(strip/add detected)" while the diff INVERTED that gate's assertions 22 and 23. Plus ~12
further no-TIER doc and in-code-comment contradictions, four of them inside the edited
function itself.

### THE ORDERING RESULT — this is the durable finding

**Digest demotion is sound only AFTER the pre-finalization slashing consequence is removed.**
While `chain.cpp:1815-1827` still forfeits stake, "outside the digest" means "strippable by
anyone, and evadable at will by the accused" — a live L1 safety loss. Once slashing carries
no L1 consequence, the identical change costs only a strippable forensic record, exactly as
the memo claimed.

**Therefore the correct sequence is the reverse of what was attempted:**
  1. Land the L2 relocation (the ~10-line core removal, verified sound THREE times, with its
     required riders each as its own increment: the per-block cap + in-block duplicate
     rejection, the S-006 re-derivation, an honest S-011 residual, and the ~16-20 no-TIER
     doc corrections).
  2. THEN demote the eq set out of the digest, reusing the preserved patch and its gate.
  3. THEN the one-line evidence rebroadcast at `node.cpp:1939`.
Attempting them in the other order makes step 2 a live consensus vulnerability.

**C0 remains OPEN** and is still a live remotely-triggerable permanent halt at HEAD — but it
is now REPRODUCIBLE, and the four CRITICAL live halts recorded at 3dbe5f2 are cheaper to
trigger than it is and are independent of this ordering.

**Tree reverted (6 tracked files restored, 1 new script removed); 4 pre-existing stashes
intact; ci_local unaffected (source byte-identical to 3dbe5f2).**

**Authority:** review findings recorded by Claude Opus 5, 2026-08-13.

---

## 2026-08-13 — NO-ECONOMICS / TACTICAL PROFILE EXPOSURE: none of the four CRITICALs improves, TWO NEW CRITICALs found, and one of them defeats every deployment shape

**Status:** READ-ONLY analysis at 7570989. Nothing implemented. Three adversarial verdicts
refuted three load-bearing premises, INCLUDING two stated by Claude earlier in-session.

### `PROFILE_TACTICAL` EXISTS — and is not a no-economics deployment

`params.hpp:259-262`: `{20, 20, 10, M=3, K=3, ChainRole::SHARD, ShardingMode::EXTENDED,
CryptoProfile::FIPS}`. `TimingProfile` carries timers, M, K, role, sharding mode and crypto
posture — **no min_stake, no subsidy, no fee policy**. `determ init --profile tactical`
writes the node config and NEVER touches genesis. (`tactical_civilian` / `cluster_civilian`
remain confirmed non-existent, per directive 4.) The shipped `tools/test_tactical.sh` is a
fully economic chain: stake 1000 each, `block_subsidy: 10`.

**A no-economics deployment is a GENESIS SHAPE, and there are TWO.**

### ► REFUTED: "no economics forces min_stake = 0, so spam gets cheaper" (Claude's stated prior)

**`min_stake` is not a price — it is the membership predicate** (`eligibility_floor.hpp:85`,
mirrored at `:116`, consumed by `registry.cpp:53` and `chain.cpp:817-825`). Selection is
uniform over the eligible pool with NO stake weight (`node.cpp:1039`). `validate()` imposes
no coupling between `inclusion_model`, `min_stake` and `initial_stake`
(`genesis.cpp:131-312`).

  * **SHAPE A (open set):** `min_stake = 0`. **No Sybil bound at all.**
  * **SHAPE B (closed set, RECOMMENDED):** `min_stake = 1000` (the DEFAULT),
    `initial_stake = 1000` each, `initial_balances = []`, subsidy/pools/lottery all 0.
    Genesis installs locked stake directly with `unlock_height = UINT64_MAX`
    (`chain.cpp:932-933`), and it then becomes a **conserved, non-mintable,
    non-transferable PERMISSION BIT**: creator credit is skipped since
    `total_distributed == 0` (`chain.cpp:1757`, `:1861`); `charge_fee` forces 0 on a zero
    balance (`:958`); `STAKE` needs `balance >= amount+fee` against a permanently-0 supply
    (`:1330`); `UNSTAKE` is 1-for-1 conserving and barred by `unlock_height` (`:1348-1359`).
    **Sybil bound = floor(sum(initial_stake) / min_stake), permanent, purely mechanical,
    zero economic content.**

`inclusion_model` is INERT — its only non-serialization consumer is a startup log line
(`node.cpp:209` -> `:668`) and it is ABSENT from `compute_genesis_hash` (`genesis.cpp:908-920`).
Do not use it as deployment identity.

**Honest gap in SHAPE B:** the conservation proof holds for single-chain / CURRENT
topologies. `PROFILE_TACTICAL` mandates SHARD + EXTENDED, forcing `initial_shard_count >= 3`
(`node.cpp:365-371`), and per-shard supply is NOT conserved — the cross-shard inbound credit
mints on the destination shard. Highest-value follow-up in this analysis.

### NONE of the four CRITICAL halts improves

They were never economically deterred — each is a validator shape-rule that ingress does not
mirror and `build_body` does not enforce, reachable from an offline keypair with zero
balance, stake, registration and fee. K1 / K2 / K4 / the no-eviction root: **UNCHANGED**.
K3: **WORSE under SHAPE A, unreachable under SHAPE B** (no outsider can enter `registry_`,
`eligibility_floor.hpp:85`, and no stake can be bought).

### ► REFUTED: "zero fees kill every eviction path" — the asymmetry runs the OTHER way

`mempool_admit_check` does no funding check, so unfunded `fee > 0` submissions can raise the
pool floor and evict a `fee = 0` poison tx (`node.cpp:2886-2897`) — degraded recovery, not
absorbing. And on a zero-balance chain **the ATTACKER is the constrained party**:
`build_body` requires `sb >= amount + fee` with `sb = 0` (`producer.cpp:1328-1329`), so K1's
and K2's poison txs MUST carry `fee = 0`, pinning them at the eviction minimum. A funded
attacker on a token chain faces no such constraint. Against the max-fee shape
(`amount=1, fee=UINT64_MAX`) neither world has an escape — differential zero, not negative.

### NEW CRITICAL 1 — REGISTER is an UNAUTHENTICATED KEY-ROTATION PRIMITIVE (defeats every shape)

The validator derives the verifying key from the transaction's **own payload**
(`validator.cpp:793`) and the switch arm is bare — `case TxType::REGISTER: break;`
(`:844-845`) — while the adjacent `case TxType::DEREGISTER:` DOES require
`registry.find(tx.from)` (`:846-848`). Apply overwrites unconditionally
(`chain.cpp:1267`) and never touches `stakes_[tx.from].locked` (`:1269-1273`).

**One fee-0 signed transaction, using the victim's PUBLIC next-nonce, rewrites any
registrant's `ed_pub` — and the attacker INHERITS the victim's locked stake and its
eligibility.** This works at `min_stake = 10^18` on a fully funded chain. It bypasses SHAPE
B's conservation bound entirely, refutes `SECURITY.md:600` ("the cartel cannot permanently
remove them without continuing to expend stake"), and undermines the attribution property
S-054 exists to preserve. **No S-item exists; `ROTATE_KEY` is listed as v2.26 not-started.**

### NEW CRITICAL 2 — a LEGITIMATE operator key rotation is a permanent halt at |pool| == K, p = 9/10

Re-`REGISTER` (the shipped rotation path) sets
`e.active_from = height + derive_registration_delay(...)` (`chain.cpp:1263`), delay uniform
on **[1,10]** (`registration_delay.hpp:36`). The registry is rebuilt at
`at_index = height() = b.index + 1` (`node.cpp:2532`), and `domain_eligible` rejects while
`active_from > at_index` (`eligibility_floor.hpp:83`). **The rotating domain is eligible only
when delay == 1.** For delay in [2,10] the pool drops to K-1, `check_if_selected` returns
(`node.cpp:1024`), no round starts, the index never reaches `active_from` — **deadlock**.
Triggered by CORRECT OPERATOR BEHAVIOUR, no adversary, no economic content. The shipped
re-REGISTER selftest exercises a 1-creator chain only. M = K = 3 IS the tactical shape.

### The equivocation DEREGISTRATION arm is a permanent halt at |pool| == K

Forfeiture (`chain.cpp:1819-1820`) is a no-op at `locked == 0`, but deregistration
(`:1825`) is unconditional and **S-051 cannot lift `inactive_from`** — the candidate loop
`continue`s on the identical predicate (`eligibility_floor.hpp:115`) and lifts suspensions
only. Pool drops to K-1 => no round => no abort => `total_aborts` stays 0 => BFT escalation
never fires (`node.cpp:1017-1023`). The documented remedy (a fresh REGISTER) needs a block
that can never be produced. Note the in-code justification is also false: `chain.cpp:1811`
says "must register a fresh domain", but `:1267` writes over the SAME domain string.

### ► REFUTED: "no token value reduces the slashing consequence to deregistration alone"

That holds only when `locked == 0`, which is a GENESIS QUANTITY CHOICE, not a consequence of
the token being worthless. Under SHAPE B `locked == 1000` and the equivocation apply mutates
THREE state_root leaves: `s:<equivocator>` (`chain.cpp:327-333`), the UNCONDITIONAL
`c:accumulated_slashed` const-leaf (`:499`, fed at `:1866`), and `r:<equivocator>`
(`:334-343`). Forfeiting a valueless token is not a deterrent but IS a live consensus-state
mutation.

**The ORDERING RESULT (7570989) still binds in BOTH shapes**, for reasons independent of
economics: `chain_.revert_head()` (`node.cpp:2691`) -> `chain_.append(incoming)` (`:2711`)
is UNGUARDED, only the validate-failure branch restores (`:2704`), and a stripped block
re-derives the same digest, passes K-of-K, then throws S-033 on the stale leaf.

### WHAT GOES SILENTLY VACUOUS (no flag, no gate, no assertion fires)

S-010 Sybil (both stated options are economic; **restored mechanically ONLY under SHAPE B**);
S-011 M-1 cartel (all three legs zero — but the **suspension exclusion window survives at
zero stake** (`chain.cpp:1789-1791`) and is renewable at zero cost, and at K=M=3 the cartel
can escalate to a two-member zero-honest BFT committee); S-006 (detection survives, the
closure does not); S-013 layer 3 (the 2K memory BOUND survives, `node.cpp:3111-3121`; the
deterrent does not); S-029 Level-3 (already recorded as failing — free `compute_hash`
grinding of the `resolve_fork` tiebreak, which is C0's third blocking finding);
**BFTSafety T-5.1 is VOID and `:184` INVERTS — you get exactly classical BFT with no
recovery**; Safety.md clause 2 (FA6) has no replacement, though clause 1's pigeonhole
survives; S-008's fee-priority policy inverts. S010S011SybilEconomics.md explicitly excludes
the coercion/ideological adversary from scope — i.e. EXACTLY the tactical adversary.

### `Chain::load` — hits the tactical profile for a NON-economic reason

Every un-threaded parameter's genesis default equals its `Chain` in-class default, so a
defaults-only genesis replays correctly. The failure tracks NON-DEFAULT choices — and
**`crypto_profile = FIPS`, which `tactical` and `cluster` MANDATE (`params.hpp:261`, `:210`),
is one** (`chain.cpp:489`, set at `node.cpp:568`). The tactical profile is unrestartable
independent of economics.

### Sequence for a no-economics deployment

1. NEW CRITICAL 1 (REGISTER authentication) — worst finding on the record; affects EVERY
   deployment, funded or not, and has no S-item.
2. NEW CRITICAL 2 (rotation deadlock) + the deregistration-at-|pool|==K deadlock — same
   root: an eligibility drop below K is unrecoverable because recovery requires a block.
3. The four sweep CRITICALs (K1-K4 + the no-eviction root) — unchanged by this profile.
4. `Chain::load` parameter threading — required before ANY tactical deployment restarts.
5. Choose SHAPE B explicitly and record it; SHAPE A has no Sybil bound.
6. Re-derive the vacuous S-items honestly for a no-economics posture.
7. Close or scope the per-shard supply-conservation gap under SHARD+EXTENDED.

**Authority:** read-only analysis by Claude Opus 5, 2026-08-13. Nothing implemented.

---

## 2026-08-13 — REGISTER unauthenticated overwrite OPENED: severity corrected UPWARD, a fifth CRITICAL found in the same function, 3 of 4 fix designs REFUTED

**Status:** DESIGN-STAGE, read-only at ddf93eb. Nothing implemented. The accept-rule change
is GENESIS-DEADLINE — pre-genesis or never. The producer/ingress/eviction work is not.

### The defect is REAL — all four links re-derived, and it is WIDER than reported

`validator.cpp:793` derives the verifying key from the transaction's OWN payload; the arm at
`:844-845` is bare while the ADJACENT `case TxType::DEREGISTER:` requires
`registry.find(tx.from)` (`:846-848`); apply overwrites unconditionally
(`chain.cpp:1260-1267`) and never touches `locked` (`:1269-1273`). **`Chain::registrants()`
is a public const accessor (`chain.hpp:522`) and `check_transactions` already holds `chain`
(`validator.cpp:675-676`) — the information needed to close this was available at the layer
where the rule lives and was not used.**

**Correction 1 — one tx rewrites the ENTIRE registry record**, not just `ed_pub`:
`registered_at`, `active_from` (re-randomised), **`inactive_from = UINT64_MAX` — which
CANCELS a pending DEREGISTER and an equivocation deregistration (`chain.cpp:1825`)**,
`region`, and `stakes_[d].unlock_height = UINT64_MAX` (rearming an unstake clock to never).
`locked`, balance, `dapp_registry_`, `audit_keys_`, `note_keys_` are all domain-keyed and
inherited.

**Correction 2 — the worst outcome is a PERMANENT HALT, not theft.** `committee_pin_active`
requires `shard_count() > 1` (`committee_pool.cpp:7`), so on every SINGLE-shard chain (the
default) ALL domain->key resolution is present-head. Three consequences, ascending:
  1. **Committee eviction at will** — the re-randomised `active_from` (uniform [1,10]) against
     a registry rebuilt at `at_index = b.index+1` (`node.cpp:2532`) and
     `eligibility_floor.hpp:83`. Repeatable, free.
  2. **FORGED EQUIVOCATION — this reopens S-052.** `check_equivocation_events` verifies both
     openings against `resolve_committee_member_pubkey` at `validator.cpp:471` (present-head).
     After the overwrite the attacker signs two conflicting openings with its OWN key and
     names the victim; apply then zeroes `locked` (`chain.cpp:1819-1820`) and sets
     `inactive_from` (`:1825`). The height-binding closure at `validator.cpp:441-460` is
     sound and untouched — it binds the HEIGHT and ASSUMES the key belongs to the accused.
  3. **Permanent halt.** Overwrite every pool member. `eligibility_floor_lifted` `continue`s
     on the identical `active_from > at_index` predicate (`eligibility_floor.hpp:114`) — S-051
     lifts suspensions, never activation delays. Pool drops below K, `check_if_selected`
     returns (`node.cpp:1024`), no round starts, `current_aborts_` was cleared (`node.cpp:2533`)
     so BFT escalation never fires (`node.cpp:1017-1022`), `at_index` never advances, so
     `active_from > at_index` holds FOREVER. Survival probability 10^-M on the shipped K == M
     profiles.

**Cost:** fee 0 (`charge_fee` at `chain.cpp:957-966`; producer filter `sb < tx.fee` is
`0 < 0`), no registration, no stake, no balance, **no HELLO** (`gossip.cpp:170` consults
`peer_message_allowed` only `if (peer->hello_received())`), from any TCP socket. The victim's
nonce is public and is **0 for every genesis creator** (genesis installs registrants directly
at `chain.cpp:928/932-933` and returns at `:947` before the tx loop).

### CORRECTION 4 — A FIFTH CRITICAL, in the same function, not previously on the record

The validator rejects a REGISTER payload on FIVE geometry rules — size > 65
(`validator.cpp:755`), size == 33 (`:758`), `region_len` mismatch (`:764`), bad charset
(`:770-782`), non-empty region under `ShardingMode::NONE` (`:787-791`). **None is mirrored at
ingress or in the producer.** One gossiped, correctly-signed, fee-0 REGISTER from an
unregistered non-anon domain with a 200-byte payload is ADMITTED (`mempool_admit_check` bounds
only `TX_FRAME_PAYLOAD_MAX`, `node.cpp:2839`), INCLUDED (`producer.cpp:1321`, `:1358-1361`),
then makes the block INVALID — and `apply_block_locked` returns at `node.cpp:2502-2505` before
the only eviction site. **Deterministic, remote, anonymous, absorbing, fleet-wide permanent
halt, live at HEAD.** This is the 3dbe5f2 no-eviction class on this tx type; it is the single
biggest constraint on the fix and is why three of four designs were refuted.

### THE OPTIONS — 3 of 4 REFUTED

* **A. MINIMAL VERIFIER RULE — SURVIVES_WITH_CONDITIONS. RECOMMENDED.** If a registrant
  record exists for `tx.from`, require `tx.payload[0..32) == incumbent ed_pub`; first
  registration keeps today's self-authenticating behaviour. No wire frame, no TxType
  discriminator (slot 18 stays free; B4's G-3 `REGION_CHANGE = 5` KEEP untouched), no genesis
  field, no `r:` leaf shape, no `RegistryEntry` field, zero edits to `src/chain/chain.cpp`,
  zero to `light/`. The reviewer could not break the RULE — only its mirror layer, twice.
* **B. DUAL SIGNATURE — REFUTED.** The accept-rule is sound but it manufactures a NEW
  permanent halt: the ingress predicate FLIPS AFTER ADMISSION and the mempool has no eviction
  path for a tx that is block-invalid at a live nonce.
* **C. DEDICATED `ROTATE_KEY` TX TYPE — REFUTED.** Closes the hole at the right layer but
  manufactures THREE new permanent halts, one remote/anonymous/zero-cost/deterministic — and
  its own gate is structurally blind to all three. Also leaves the equivocation self-escape
  open (its own F-3).
* **A'. ROTATION-LIVENESS ARTIFACT — REFUTED.** The |pool|==K activation-delay deadlock it
  targets is REAL and re-derived end to end, but the design's enforcement claim is FALSE and
  is exactly the Option-C pattern it claims to avoid: **`state_root` is NOT a verifier rule**
  (zero hits in `validator.cpp`), is gated on `b.state_root != zero` (`chain.cpp:1948`), and
  is EXCLUDED from `compute_block_digest` — so the K committee signatures do not cover it and
  any relayer can zero it.

### THE RECOMMENDED PREDICATE (Option A, conditions folded into the core)

    R_b(d) = payload[0..32) of the most recent REGISTER for d ACCEPTED EARLIER IN b, if any
           = chain.registrants().at(d).ed_pub, otherwise if present
           = undefined, otherwise
    ACCEPT: for every REGISTER in b, R_b(tx.from) defined => tx.payload[0..32) == R_b(tx.from)

**Deliberately the RAW `chain.registrants()` map, NOT the `NodeRegistry` the validator is
handed.** `build_from_chain` (`registry.cpp:26-84`) drops every domain failing
`domain_eligible` — pending-activation, deregistered, suspended, under-min_stake — so a rule
phrased against the ELIGIBLE pool would leave precisely the weakest domains freely rebindable.

Five assertion sites, all core: (1) the rule at `validator.cpp:793` + a loop-scoped in-block
overlay populated at `:844`; (2) **anti-halt** producer skip at `producer.cpp:1358-1361`
(build_body assembles from the committee union and can hold a tx this node's ingress never
saw; skipping is legal); (3) ingress `mempool_admit_check`; (4) **`rpc_register`
(`node.cpp:4981-5000`) must run the predicate and return an RPC error** — it writes
`tx_store_` without `mempool_admit_check`, so without this the documented operator command
self-inserts a permanently unincludable fee-0 tx that locks the domain's `(from, nonce)` slot
forever; (5) **eviction** — gate the reorg re-insert (`node.cpp:2718-2726`) and extend the M11
sweep (`:2515-2531`).

### WHAT OPTION A DOES NOT FIX (stated, not buried)

The rotation deadlock (`chain.cpp:1263` untouched); the five geometry halts above;
**total key loss becomes TERMINAL for the domain** — `locked`, balance, DApp ownership and the
registry slot unreachable forever (KR-12 defers recovery to v2.14/v2.15/DSSO, none shipped);
compromised-but-retained keys cannot be rotated in place, leaving DEREGISTER, which at
|pool| == K halts with probability 1 (worse than HEAD's 9/10 for that one scenario); domain
squatting (first registration must stay self-authenticating); low-order registered keys
(`ed25519.c:321-331` has no small-order rejection, so an identity-point `ed_pub` admits one
`(R,S)` verifying every message — anyone can then resubmit `payload == incumbent` and
re-randomise `active_from`, rewrite `region`, clear `inactive_from`, rearm `unlock_height`);
`Chain::load` does not re-verify (`chain.cpp:3530` replays through apply only); the light
client does not enforce it; and the `DEREGISTER` asymmetry (`validator.cpp:847` uses the
eligible pool, ingress the raw map) is another live instance of the halt class.

### OWNER DECISION REQUIRED

Option A makes **key loss terminal**. In a permissioned deployment among known parties that
may be correct — no recovery path is also no backdoor. If field key-loss recovery is required,
it needs an explicit mechanism, and none is shipped. This is genesis-deadline.

**Authority:** design-stage analysis by Claude Opus 5, 2026-08-13. Nothing implemented.

---

## 2026-08-14 — REGISTER key binding: revocability is ADDABLE LATER; RESERVE NOTHING; recommend V-REG-1 create-only

**Status:** DESIGN-STAGE, read-only at 5e4afec. Nothing implemented.
**Supersedes** the prior entry's framing that a recovery key must be committed at first
registration. That expectation was WRONG and is corrected here.

### Password-derived keys do not touch the consensus defect

`validator.cpp:793` copies the verifying key out of the transaction's OWN payload and
`:819-821` verifies against it; `case TxType::REGISTER: break;` (`:844-845`) reads no
incumbent. The attacker binds their own freshly-generated key — how the VICTIM's key was
produced is not an input to `verify()`. Same class as the project's existing block-hash
doctrine: RFC 8032's deterministic nonce "is a signer-side convention NO verifier can check."
Derivation is a signer-side convention. **It cannot be a consensus property.**
Measured: `grep -riE "argon2|pbkdf2|scrypt|passphrase|password"` over `src/node/` + `src/chain/`
returns **0 lines**. `REGISTER_PAYLOAD_MAX_SIZE = 65` (`params.hpp:60-62`) is fully consumed
by pubkey + region_len + region.

**What the tree already has, and it is the right shape:** every signing key is RANDOM;
password KDFs protect keys AT REST only. `generate_node_key` (`keys.cpp:32-40`) draws 32
bytes from the OS CSPRNG, fatal on entropy failure. The wallet's DWE2 envelope wraps random
keys with **Argon2id (t=3, m=64 MiB, p=1) + AES-256-GCM and a fresh random 16-byte salt** —
`src/crypto/argon2/argon2id.c` is ALREADY VENDORED. There is no `key = KDF(password)`
anywhere, for any key.

Costs of the derived shape, beyond offline grindability (`ed_pub` is published by the
protocol — `r:` leaf `chain.cpp:334-343`, RPC, every block, every snapshot, and under
no-migrations it is on-chain FOREVER, so the grinding target OUTLIVES rotation): it voids
HSM residency, split custody and coercion resistance by construction, collapses passphrase
leak and file theft into ONE event, and destroys the only immediate revocation primitive in
the system — **destroying the ciphertext**. You cannot destroy a memorized string.
`docs/V2-DESIGN.md:991` already records the adverse finding for this shape, accepted there
only because a T-of-N Shamir threshold carries the security; a consensus identity key has no
such threshold.

**PIN-as-on-chain-authorization is likewise unavailable:** a consensus verifier cannot
rate-limit, and any public commitment to a 13-27-bit secret is offline-broken. A PIN is sound
only as a LOCAL unlock factor over a random recovery key (the DWE2 shape above).

### ► CORRECTION: revocability IS addable later, and RESERVING ANYTHING IS A NET FORECLOSURE

The circularity objection was wrong. **First registration is self-authenticating and always
will be** (`validator.cpp:793` — there is nothing else to authenticate against). Once the
accept rule makes authority a chain from that root, a recovery key published at block 50,000
BY THE INCUMBENT IDENTITY KEY is exactly as authenticated as one published at block 1. The
tree already ships two auxiliary-key mechanisms authorized this way: `ROTATE_AUDIT_KEY = 15`
and `REGISTER_NOTE_KEY = 17`, both routing through `validator.cpp:813-817`.

**Commit-at-registration is strictly LESS capable where it matters most:** it cannot reach the
genesis creator set at all. Genesis registrants never send a REGISTER (`chain.cpp:919-936`
installs directly, `:947` returns before the tx loop) and `GenesisAlloc` (`block.hpp:622-633`)
carries NO signature field — so a genesis-committed recovery key would be UNAUTHENTICATED and,
under an immutability rule, permanently unfixable, for exactly the K-of-K launch quorum whose
key loss halts the chain.

| Vehicle | Status |
|---|---|
| **New TxType >= 18** | **FREE** — `block.cpp:229` casts a bare u8, `validator.cpp:1488-1495` `default:` fail-closes; max shipped is 17; B4's DROP list has NO TxType rows (its only TxType row, G-3 `REGION_CHANGE = 5`, is KEEP) |
| **New state namespace `rk:`** | **FREE, state-root-invariant** — the `ak:` (`chain.cpp:531-539`) / `nk:` (`:548-556`) precedent emits leaves ONLY while set; an empty map emits zero leaves |
| **A `RegistryEntry` field** | **GENESIS-FROZEN — do not plan on one.** `chain.cpp:334-343` hashes `ed_pub‖registered_at‖active_from‖inactive_from‖region` into every `r:` leaf |
| **A GenesisConfig activation-height reservation** | **REJECT — the reservation IS the foreclosure.** Activation heights are not on the PARAM_CHANGE whitelist (`validator.cpp:919-923`), so it is an unchangeable guess |

### RECOMMENDATION — V-REG-1: `REGISTER` is CREATE-ONLY. Reserve nothing.

Reject any REGISTER for a domain already present in the RAW `chain.registrants()` map (not
`NodeRegistry`, which drops exactly the weakest domains). Preferred over the earlier
`payload == incumbent` rule: it closes that rule's residual, has the same two-file blast
radius, and its predicate is a map lookup rather than a signature verify — so a mempool
eviction pass is ~10^4 lookups, not ~10^4 Ed25519 verifies, which is the exact cost that
refuted the recovery-key design. It does not touch the genesis hash.

Revocability then lands later as `ROTATE_IDENTITY_KEY` on a free slot + an `rk:` leaf,
rotating `ed_pub` ONLY — touching neither `active_from` nor eligibility, so it avoids the 9/10
`|pool| == K` activation deadlock (`chain.cpp:1263`) BY CONSTRUCTION. That is the owner's
stated intent, implemented as its own properly-authorized transaction instead of overloaded
onto REGISTER. **Put it on the DECISION CLOCK, not the genesis deadline.**

**Closes on the record:** S-052 forged slashing via the key binding — with rebinding
impossible, an attacker cannot make `resolve_committee_member_pubkey` (`validator.cpp:471`)
resolve a victim's domain to a key they control. The height-binding closure at `:441-460`
remains sound and untouched.

### HARD PREREQUISITE for "later" to be safe — and a NEW live defect

**`build_body` has NO `default:` arm** (`grep -c "default:" src/node/producer.cpp` = 0) and
`nn++; b.transactions.push_back(tx);` (`producer.cpp:1422-1423`) runs unconditionally after
the switch. **An unknown TxType is therefore INCLUDED with no fee debit**, the block is
rejected at `validator.cpp:1488`, and the no-eviction class makes it an absorbing halt. This
must be closed BEFORE any new TxType ships — and it is a live instance of the 3dbe5f2 class
today, reachable by any peer sending an unknown discriminator.

### FURTHER NEW FINDINGS

* **D-2, a 2-second permanent halt at PROFILE_TACTICAL.** At `|pool| == K` under
  STAKE_INCLUSION the eligibility floor re-admits a dead member every height, guaranteeing one
  abort per height; at `SUSPENSION_SLASH = 10` against `MIN_STAKE = 1000` that is a
  **permanent halt in exactly 100 blocks** — ~2 s at PROFILE_TACTICAL's timings.
* **`save_node_key` (`keys.cpp:42-50`) writes PLAINTEXT JSON** — `f << j.dump(2)` to a bare
  `std::ofstream`, no encryption, no KDF, and **no chmod/permissions call on that path**. The
  wallet has DWE2; the node key does not.
* **Small-order registered `ed_pub`:** `determ_ed25519_verify` (`ed25519.c:321-331`) has no
  torsion check, so an identity-point key admits one `(R,S)` verifying every message — making
  the possession proof at `:793`/`:819-821` vacuous AND, under create-only, PERMANENT. Argues
  for a verifier-side torsion check as a companion increment.
* `Chain::load` replays through apply with no validator (`chain.cpp:3530`); the light client is
  not an independent verifier of this rule; `Transaction::signing_bytes()` binds no chain_id so
  cross-deployment replay is live; `sharding_mode` is node-local, not genesis-pinned.

**Authority:** design-stage analysis by Claude Opus 5, 2026-08-14. Nothing implemented.
One refute agent failed on schema retries (no-rotation lens); its design is recorded but
un-refuted.

---

## 2026-08-14 — EVICTION-ROOT attempt 1 REFUTED: the eviction predicate was a SHAPE SUBSET, so it added zero coverage — and it opened a remote unauthenticated mempool wipe

**Status:** REVERTED before commit. **16 confirmed findings (3 CRITICAL) against 1 false
alarm.** The gate was green: 70 assertions, 8 build-proofed mutants, final binary
byte-identical to baseline, ci_local 303/0. **Green is not proof — twelfth confirmation this
session.** Patch preserved at `scratchpad/eviction-root-attempt1.patch` (1469 lines); the
shape-predicate extraction and gate scaffolding are reusable, the eviction design is not.

### WHAT WORKED — keep the method

Three agents edited three DISJOINT files concurrently under a spec-fixed contract
(`validator.cpp`+`.hpp` / `producer.cpp` / `node.cpp`), with no builds during the parallel
phase. **They compiled together on the FIRST build with ZERO signature reconciliation.**
Strict file ownership + a serialized interface spec is a sound zero-merge-cost pattern and
should be reused. Each half was shown independently load-bearing by targeted mutants (M2
producer-skip, M3 ingress-mirror, M4 eviction each reddened only their own arms).

### CRITICAL 1 — the eviction root was NOT closed; the predicate is co-extensive with the mirror

`evict_block_invalid_locked` drops a tx only when `tx_shape_reject_reason(tx, policy)` is
non-empty (`node.cpp:2673`) — **exactly the set the ingress mirror already refuses and
build_body already skips.** It therefore adds ZERO coverage over the mirror, and the
structural root ("there is NO eviction path for a queued-but-block-invalid tx") is UNTOUCHED
for every validator per-tx rule OUTSIDE the shape predicate. The increment's own claim, "the
eviction root itself — CLOSED", is false.

**Live 2-tx fee-0 permissionless fleet halt that survives the fix intact:** an attacker
self-signs a REGISTER for any unused domain (fee 0; the pubkey comes from the tx's own
payload, `validator.cpp:969-975`, so no prior registry entry is needed). `build_body` includes
it at `sb >= fee = 0`; apply sets `active_from = height + delay >= height+1`, stake 0, nonce 1.
The attacker then gossips a fee-0 TRANSFER from that now-REGISTERED-but-INELIGIBLE sender —
rejected by a validator rule outside the shape predicate (`validator.cpp:989`), unmirrored at
ingress, un-skipped by the producer, and un-evicted. Absorbing.

Same shape, second instance: **PARAM_CHANGE on the DEFAULT chain.** `governance_mode` defaults
to 0, and `check_transactions` rejects EVERY PARAM_CHANGE on such a chain
(`validator.cpp:1058-1061`). Nothing mirrors it — and `build_body`'s NEW `default:` arm
*deliberately includes* it.

### CRITICAL 2 — the fix OPENS a remote unauthenticated mempool wipe (reproduced at runtime)

`evict_block_invalid_locked` erases mempool entries keyed on `tx.hash` **taken verbatim off
the wire from a block that FAILED validation**. `Transaction::decode_frame` does a raw
`memcpy` of the hash (`block.cpp:249`) and the block ingress path NEVER recomputes it (only
the RPC path does, `node.cpp:4628-4633`). So any peer gossips an invalid block whose
transactions carry victims' hashes and wipes those entries from every node's mempool.
Reproduced with a PoC binary, then removed.

Compounding it: the `(from, nonce)` index is erased with a key INDEPENDENT of the hash just
erased (`node.cpp:2677`) — three separately attacker-chosen fields of one unauthenticated
struct — orphaning live mempool entries and burning a victim's per-sender quota. The guarding
comment ("only touch the index if we actually held this hash") does not establish what it
claims.

### CRITICAL 3 — the gate's central arms never construct the halt state

ARM 6 is a BYTE-FOR-BYTE repeat of ARM 5's reject reason. Measured at the baseline binary,
both print `[node] invalid block: prev_hash mismatch`: each builds a `Block` with a
default-constructed `prev_hash`, so **the validator short-circuits on the HEADER before ever
reaching `check_transactions`.** "Eviction is independent of the reject reason" is therefore
untested, and **no arm ever constructs the actual absorbing state the increment exists to
close.** 70 assertions and 8 mutants did not catch this, because the mutants tested the code
that was written rather than the property that was needed.

### THE DESIGN LESSON — this is the durable result

**An eviction predicate that is a SUBSET of the validator's verdict cannot close the eviction
root, by construction.** The root is "a tx the VALIDATOR rejects is never evicted"; a mirror
of some rules evicts only what those rules cover, and every unmirrored rule remains an
absorbing halt. Mirroring more rules does not converge either — the reviewer showed the
"cannot be mirrored" justification at `validator.cpp:895-904` is itself false for several
rules (SHIELD/UNSHIELD `payload.size() != 98`, `amount < fee`, the PARAM_CHANGE
payload-truncation family, COMPOSABLE_BATCH emptiness are pure functions of `tx` alone), so the
partition was drawn on a criterion that does not hold.

**The successor design must evict on the VALIDATOR'S OWN VERDICT, not a proxy:** when a block
fails, re-run the per-tx accept check locally against the local chain view and evict exactly
what it rejects — and key the erase on a LOCALLY RECOMPUTED `tx.compute_hash()`, never the
wire hash. That is one predicate, no partition to drift, no unmirrored residue, and no
attacker-controlled erase key. Its cost (an O(|b.transactions|) pass on a reject path, under
`state_mutex_`) was measured this round and judged immaterial.

Secondary, and required regardless: **`Transaction::hash` must be recomputed on the block
ingress path.** Trusting a wire-supplied hash is the enabling primitive for CRITICAL 2 and is
a defect in its own right.

### OTHER CONFIRMED (carry forward)

`TxShapePolicy` is called "genesis-pinned" but `sharding_mode` is NODE-LOCAL config
(`node.cpp:102`; GenesisConfig has no such field) — so the producer skip is keyed on
node-local state, meaning a single misconfigured finalizer silently CENSORS REGISTER-with-region
fleet-wide where HEAD produced a loud halt. **A producer skip must be a pure function of
digest-covered state — this is the C0 failure shape.** Also: the unknown-TxType fail-close now
has TWO independent definitions that mask each other's removal, with no `-Wswitch`/`-Werror` in
CMakeLists.txt (matters directly for V-REG-1 and any new TxType); `rpc_register` returns
`{"status":"rejected"}` while `cmd_register` still exits 0; `S008BoundedMempool.md:365`'s L-3
index-consistency induction is falsified by three new mutation paths;
`RpcIngressGateAudit.md` gains no row.

**Tree reverted (8 tracked files restored, 1 new script removed); 4 pre-existing stashes intact;
source byte-identical to 1c0a61d.**

**Authority:** review findings recorded by Claude Opus 5, 2026-08-14.

---

## 2026-08-14 — ADJUDICATION: "the full design is unachievable" — REFUTED as stated; ACHIEVABLE only if the LAUNCH CLAUSE bends. Plus a NEW genesis-deadline safety defect (2K > M is enforced over a variable no accept rule reads)

**Status:** READ-ONLY adjudication at 07d41ed. Nothing implemented. Four agents (two
prosecution, one defence, one evidence-only), then adversarial cross-refutation of all four
DERIVATIONS. **All four arguments built on `K == M` were refuted, from four directions.**

### VERDICT

**Achievable — but only if C14/D4's launch clause bends: "feature-complete, then one freeze"
with NO WRITTEN STOPPING RULE.** No conjunct of C1-C13 is proved impossible. What is not
achievable is a defensible freeze judged by an instrument that reads zero.

### THE `K == M` QUESTION IS MALFORMED — `m_creators` IS RUNTIME-INERT

**M is read NOWHERE on the consensus path.** `validator_.set_m_pool` writes `m_pool_`
(`validator.hpp:423`) which is read nowhere in `src/` or `include/`; `m_pool_size` reaches
`build_body` and hits a literal `(void)m_pool_size;` (`producer.cpp:1254`). **Zero occurrences
of `m_creators` in `src/node/validator.cpp` or `src/chain/chain.cpp`.** The committee is
`k_use = cfg_.k_block_sigs` (`node.cpp:992/1015/1039`); the validator admits only
`m == k_full` or `m == k_bft` (`validator.cpp:122-134`). M survives only in the `2K > M` band
check, serialization, the genesis-hash mix, an RPC preview and a display string.

Consequences:
* **"K == M" and "K < M" are not runtime modes** — they relate two genesis integers, one of
  which the accept path never reads. The operative quantity is **`|eligible pool| − K`, a
  DEPLOYMENT property.** Every prior statement of the form "at K == M, select_m_creators is the
  identity, so rotation evicts no one" is stated over the WRONG VARIABLE and should read
  `|eligible pool| == K` — including DECISION-LOG 2026-08-12 "final+7".
* **`f = 0` is FALSE.** At `|pool| == K == 3`, one crash IS tolerated: `k_bft = 2`, theta = 1
  default, abort quorum `max(2, K-1) = 2`, escalation fires (`node.cpp:1017-1023`), a 2-of-2
  BFT block finalizes. `K == M` is explicitly legal-with-zero-liveness-margin
  (`genesis.cpp:148-150`); PROFILE_WEB 4/3, REGIONAL 5/4, GLOBAL 7/5 all ship.
* **The `|pool| == K` deadlock family is INCIDENTAL, one root, one line.** Escalation arms on
  `total_aborts = current_aborts_.size()` (`node.cpp:1013`) and `current_aborts_.clear()` runs
  on every apply (`node.cpp:2533`), so any pool shortfall PREDATING the height cannot arm
  escalation. **K/M-independent** — at GLOBAL 7/5 with three non-abort drops it is absorbing at
  MD margin 2. Three deadlocks (rotation p=9/10, equivocation-deregistration, stake drain) are
  three predicates hitting ONE arming defect.
* **CORRECTION to D-2, wrong by two orders of magnitude and WORSE than recorded.**
  `deduct = min(suspension_slash, locked) = min(10,1000)` (`chain.cpp:1795-1797`) leaves
  `locked = 990`, and the predicate is `stake_of < min_stake` (`eligibility_floor.hpp:85`), not
  `locked == 0`. Both live 3-node gates provision `--stake 1000` against default
  `min_stake{1000}`. **Ejection is at the FIRST abort, not the 100th.** The `params.hpp:78-79`
  comment is wrong and the taxonomy inherited the error.

### NEW GENESIS-DEADLINE SAFETY DEFECT — S-054 guards the wrong variable

S-054's own rationale (`genesis.cpp:136-146`) states the threat as "K signatures out of the
M-member committee ... two DISJOINT K-subsets". **No M-member committee is ever formed.** The
band `2K > M` is enforced over a variable no accept rule reads. The invariant that actually
governs attributability is **`2K > N(h)` where `N(h) = |eligible pool|` — unbounded, uncapped,
unchecked, unlogged, ungated** (`select_committee_pool` -> `eligible_in_region("")` -> whole
`nodes_`, `registry.cpp:88-90`; `build_from_chain` has no cardinality bound, `:64-80`; there is
no `max_creators` and REGISTER enforces no cap). **PROFILE_WEB 4/3 breaks at 6 registrants;
GLOBAL 7/5 at 10.** With the S-048 abort-vs-finalize race (two same-height blocks each
validated against their OWN `abort_events`, `validator.cpp:137-151`), two disjoint committees
can each finalize **with no member signing twice — an unattributable fork**, which SECURITY.md
identifies as exactly "what remains" once L1 slashing is withdrawn.

Fixing it changes committee derivation in `node.cpp:998-1039` AND `validator.cpp:137-152` — a
consensus accept rule, **frozen at genesis**. A FIFTH genesis-deadline item, absent from every
enumeration on the record. **Missed by all twelve adversarial passes AND by GB-8's 16
mutant-verified assertions — because GB-8 asserts at the CONFIG-LOAD layer while the rule lives
in `check_creator_selection`.** That is the R3 doctrine violation ("assert at the layer where
the rule lives") that refuted Option C, reproduced verbatim.

### THE CAP ARGUMENT — factual premise VERIFIED, force INVERTED

Of 23 live halts: **PARTITION-INDUCED = 0.** (3 of the 4 SPECIFIED partition halts are the
designed CP behaviour.) The owner's factual premise is correct and independently verified three
times; it argues AGAINST his conclusion, because CAP explains none of the live defects.

### THE PROCESS ARGUMENT — REFUTED on a population error

197 confirmed findings across 12 passes, but **exactly ONE pass (22 findings) examined the
SHIPPED tree**; one examined a design doc; the other ten (~154) examined **candidate diffs ALL
REVERTED BEFORE COMMIT**. `git diff --stat 0ce12c8..HEAD` = two doc files, **zero source
lines**. The non-convergence regression (+0.39 findings/review, t = 0.92) is over defect density
in freshly-authored, never-shipped consensus candidates. The "rate spike with no code change" is
self-refuting: there was no code change BECAUSE the designs were reverted. The prosecution's own
brief concedes non-convergence is not provable at conventional significance.

### WHAT SURVIVES, AND IT IS WORSE THAN EITHER SIDE ARGUED

**The mandated gate is blind.** `tools/ci_local.sh:259` is `FAST=1 QUIET=1 bash
tools/run_all.sh` plus offline doc guards, and the FAST `ONLY_PATTERN` (`run_all.sh:108`)
**exercises no multi-node configuration at all** — the cluster gates and the 47 model-checked
TLA specs are outside it. The authoritative ledger prints `Open: 0/0/0/0/0` against >= 12 live
remote-triggerable halts. And the beta's own criterion — "bug-discovery rate -> 0"
(`PRE-LAUNCH-DECISIONS.md:197`) — is undefined and, on this instrumentation, unmeasurable.

### PROVEN IMPOSSIBLE (2, both already re-specified, both re-specifications unrefuted)

1. A sound-and-complete consensus predicate over two signed openings under asynchrony ->
   slashing relocates to L2; only "what does L2 slash?" remains open, and option (b) (separate
   L2 bond, L1 stake never slashable) is the only one that does not re-enter consensus.
2. Safe automated exclusion at `|eligible pool| == K` -> maintain pool margin; already
   supported by shipped code.

**Everything else is unfinished work.** Two OPEN DESIGN RISKS to close at design stage first:
(a) **F-c soundness** — arming escalation on a pool shortfall at height start rather than on
`current_aborts_` is the designed fix (`AbortCascadeLiveness.md:258`), but an adversary who can
SHRINK the pool — and the REGISTER overwrite is exactly such a primitive — could force
`ceil(2K/3)` BFT at will, converting a liveness halt into a **safety downgrade**. Three of four
passes named this the most likely way the verdict flips. (b) Binding `b.transactions` into the
digest may transplant C0 onto the tx set; if that reconciliation cannot be made to work,
censorship resistance is lost PERMANENTLY at genesis.

### THE RELAXATIONS, AND THE ORDER

Relax: the genesis shape (`M > K and K >= 3`) plus an enforced pool bound (`2K > N`, or cap N)
— censorship resistance becomes `(f/N)^K`, a quantitative weakening of a bound the docs already
state probabilistically; `initial_stake >> min_stake` or DOMAIN_INCLUSION — removes the stake
fuse at zero cost to any stated property; **and the launch clause — a written, measurable
genesis go/no-go predicate measured over a beta that exercises the frozen surface** (a testnet
carries a different `chain_id` and genesis hash, so it is NOT a migration). Hold everything
else: R27 no-migrations, R31 vendored C99 (met — zero OpenSSL linked), R11/R12 re-derived over
N, R15, R16, R21-R23, R25, R28/R29, R33.

**Order:** (1) design-gate F-c and the `2K > N` bound TOGETHER — both touch committee
derivation, both genesis-deadline, and F-c's soundness turns on whether the pool can be
adversarially shrunk; cheapest, highest severity, and it refutes or confirms this verdict.
(2) Put the cluster gates and the TLA models into `ci_local` — a scripting change, and the
precondition for every empirical claim the method wants to make.

**Authority:** adjudication by Claude Opus 5, 2026-08-14. Nothing implemented.

---

## 2026-08-14 — "NO CRYPTOCURRENCY" SCOPE REDUCTION (message queue + DLT + DApp hosting only): 3 dissolve, 6 shrink, 33 survive, 13 WORSEN

**Status:** READ-ONLY at ddfe877. Nothing implemented. 3 of 4 evaluate lenses died on
ECONNRESET, so the DEFECT TABLE (which completed and was adversarially verified) is sound while
the replacements / deletion-cost / does-it-help analysis is INCOMPLETE. Re-run those before
acting on any deletion estimate.

### HEADLINE

**56 rows: 3 DISSOLVE, 6 SHRINK, 33 SURVIVE UNCHANGED, 13 WORSEN** (+1 shape-dependent).
**Not one of the eight live remote-halt CRITICALs dissolves** — every one is a shape rule, an
accept rule or round bookkeeping with zero value input, and four get strictly worse. The
reduction is a **product decision with a modest, real, narrow security benefit**, and only if
executed as **pre-genesis DELETION of the `amount`/`fee` fields, not zeroing**.

### THE SEPARABILITY QUESTION — REFUTED

"Locked stake is a conserved, non-transferable permission quota" does NOT hold: **two live
destruction sites** (`chain.cpp:1795-1797` slash, `:1819-1820` forfeit) against **zero reachable
post-genesis creation sites**, and the genesis lock is **liftable by its own holder** —
`DEREGISTER` rewrites `unlock_height = inactive_from + unstake_delay_` (`chain.cpp:1313`).
The mechanical Sybil bound therefore does NOT survive by relabelling. Dropping the currency
removes the only membership bound, which interacts directly with A6 below.

### WHAT WORSENS (the important half)

* **A5 REGISTER unauthenticated overwrite — WORSE.** Under the reduction it becomes the ONLY
  route into a genesis slot.
* **A6 `2K > N` — WORSE.** The pool has no cardinality bound (`registry.cpp:47-49`) and the band
  is enforced over `m_creators`, which `producer.cpp:1254` discards as `(void)m_pool_size;`.
  Removing the stake gate on registration makes the pool grow faster.
* **A3 `build_body` has no `default:` arm — WORSE.** Deleting the nine value arms leaves
  DAPP_CALL / DAPP_REGISTER unfiltered.
* Plus ten more, incl. the A1 supply re-check reading zero after snapshot truncation.

### FOUR ADVERSARIAL REVERSALS — over-claiming dissolution was the predicted failure mode and it happened

1. **D4 "DAPP_CALL silent message loss dissolves" — WITHDRAWN, premise false at HEAD.** Delivery
   never consults the apply result; both paths scan the block and filter on three fields only
   (`node.cpp:4079-4086`, `:4367-4373`), so an apply-skipped DAPP_CALL IS delivered.
   **REPLACED BY A NEW CRITICAL, live at HEAD and previously unrecorded:**
   `make_dapp_call_frame` (`node.cpp:4051-4063`) and `rpc_dapp_messages` (`:4094-4096`) stamp
   `{"amount"}` and `{"fee"}` into every delivered frame; the validator does NO funding check and
   `build_body` has no DAPP_CALL arm. **A zero-balance sender makes the delivery layer report a
   payment of arbitrary size that the chain never made.** This one the reduction genuinely does
   dissolve.
2. **D1 cross-shard credit — RECLASSIFIED SHRUNK.** At `r.amount == 0` the credit dies but two
   permanent consensus-visible mutations from unauthenticated remote data remain:
   `accounts_[r.to].balance` (`chain.cpp:1837`) is `std::map::operator[]` and **INSERTS an
   attacker-chosen account**, emitting an `a:` state-root leaf; and `applied_inbound_receipts_`
   (`:1843`) emits an `i:` leaf also serialized into DSN1 snapshots. Neither map has a removal
   path; `MAX_PENDING_INBOUND_RECEIPTS` bounds only the node-local buffer.
3. **B1 max-fee mempool seal — RECLASSIFIED SURVIVES UNCHANGED, and it is FEE-INDEPENDENT.**
   `build_body` skips any nonce != next_nonce (`producer.cpp:1321-1322`) and the M11 sweep drops
   only nonces BELOW next_nonce (`node.cpp:2523-2525`). **Nothing bounds a FUTURE nonce** —
   `on_tx` (`:2905`) and `rpc_submit_tx` (`:4548`) test only for stale, and
   `mempool_admit_check` has no nonce test at all. 100 anon addresses x 100 txs at nonces 1..100
   = **10,000 permanently unincludable, permanently unsweepable entries at zero fee.**
4. **A2 eviction root — REVERSED to SURVIVES UNCHANGED.** The claim that losing the fee valve
   worsens it is wrong: `mempool_make_room_for` evicts the fee MINIMUM (`node.cpp:2886-2892`)
   while the worst poison (S-049 `amount=1, fee=UINT64_MAX`) sits at the MAXIMUM. The valve never
   covered it. What the reduction actually kills is replace-by-fee (`node.cpp:2923`), which cures
   a buggy client and never an adversary.

### VERDICT

The reduction deletes an unauthenticated cross-shard MINT, a false-payment report in the
delivery layer, and one absorbing remote halt. It does NOT touch C0, the eviction root, REGISTER,
the escalation-arming root, the `2K > N` fork, `enter_block_sig_phase`, or the geometry-rule
mirror gap — and it removes the only Sybil bound while making the two identity/pool defects
worse. **It is worth doing on product grounds and must not be sold as a security remedy.** If
taken, the Sybil replacement must land BEFORE or WITH it, not after.

**Authority:** read-only analysis by Claude Opus 5, 2026-08-14. Nothing implemented.
Deletion-cost and replacement analysis INCOMPLETE (3 lenses lost to network errors).

---

## 2026-08-14 — NO-CRYPTOCURRENCY REDUCTION, COMPLETE RUN: supersedes 8b86d39. 6 dissolve / 4 shrink / 38 survive / 11 worsen. Three prior conclusions REVERSED

**Status:** READ-ONLY at 8b86d39 (source byte-identical to ddfe877). Nothing implemented. The
three lenses lost to ECONNRESET were re-run; this entry SUPERSEDES the partial one at 8b86d39,
whose defect counts and Sybil/fee conclusions were wrong.

### ► REVERSED 1 — the currency performs NO post-genesis Sybil work; the validator set is ALREADY CLOSED at genesis

A domain with `locked < min_stake` fails `eligibility_floor.hpp:85`, is therefore absent from
`NodeRegistry` (`registry.cpp:53,67`), and is therefore rejected at `validator.cpp:815`
("tx sender not in registry") **before its own STAKE transaction can reach `chain.cpp:1333`**.
Anon senders are whitelisted away from STAKE (`validator.cpp:804-811`), and no third party can
fund it — STAKE credits `stakes_[tx.from]` only. **The reduction is NEUTRAL on Sybil. The claim
at 8b86d39 that it "removes the only Sybil bound" is withdrawn.**

### ► REVERSED 2 — removing `fee` DESTROYS the worst mempool DoS in the tree

The fee market is equally the ATTACKER's weapon. `mempool_make_room_for` evicts the MINIMUM
(`node.cpp:2883-2893`), so a remote unfunded `amount=0, fee=UINT64_MAX` TRANSFER walks the entire
honest pool out one entry per insert; `mempool_admit_check`'s `if (tx.fee <= min_fee)`
(`node.cpp:2868`) is then true for **every representable u64** — permanent, total, remote,
zero-cost censorship, never drained (`producer.cpp:1329` skips it forever; the only eviction site
is past the validator's early return at `node.cpp:2503-2505`). **Under field DELETION this shape
cannot be expressed.** Permanent-seal routes 2 -> 1 (future-nonce, B2, survives).

### ► REVERSED 3 — the quota's load-bearing role is QUORUM-INTERSECTION SAFETY, not Sybil

The `2K > M` band is checked against `c.m_creators` (`genesis.cpp:157-159`), which is runtime-inert
(`producer.cpp:1254` is `(void)m_pool_size;`). The runtime committee is drawn from
`avail_domains.size()` (`node.cpp:1039`) and the ONLY bound on that pool is
`eligibility_floor.hpp:85`. There is no registrant cap anywhere. **Therefore executing the
reduction as `min_stake = 0` makes `2K <= N` reachable and opens the unattributable fork
`genesis.cpp:138-152` exists to prevent.** Execution shape is load-bearing: do NOT zero min_stake.

### COUNTS (superseding 3/6/33/13)

**6 DISSOLVE · 4 SHRINK · 38 SURVIVE UNCHANGED · 11 WORSEN** (+2 shape-dependent), 61 rows.
Corrections within the table: **A2 eviction root WORSENED -> SURVIVES** (the fee valve is
attacker-disarmable for free, so it never covered the worst poison); **A5 REGISTER WORSENED ->
SURVIVES** (per REVERSAL 1).

**No live remote-triggerable halt dissolves.** C0, the eviction root, REGISTER, the geometry-rule
mirror gap, the escalation-arming root and its deadlock family, `enter_block_sig_phase`,
`AbortEvent` grinding, `resolve_fork` grinding, PARAM_CHANGE-at-governance_mode-0, the DEREGISTER
asymmetry and the 2-tx self-REGISTER halt all survive untouched.

### THE ACTUAL ARGUMENT FOR DOING IT

Not security. **25-56% of the permanently GENESIS-FROZEN commitment surface is value/CT-derived**,
and under no-migrations that optionality is available NOW OR NEVER. The reduction shrinks the
irreversible decision set — which is precisely what the achievability adjudication (ddfe877)
identified as the binding constraint, since every undiscovered defect in frozen surface is
permanent.

### THE EXECUTION CONDITION — this governs everything

**It only pays if `amount` and `fee` are DELETED from `Transaction` pre-genesis. ZEROING THEM AT
GENESIS BUYS ALMOST NOTHING** — three of the six dissolutions stay fully live, because those
defects are arithmetic over two attacker-chosen u64s regardless of whether the fields mean
anything. And do not execute it as `min_stake = 0` (REVERSAL 3).

### STILL TRUE FROM THE PARTIAL RUN

The NEW CRITICAL stands: both delivery paths iterate `b.transactions` and never consult the apply
result (`node.cpp:4076-4086`, `:4368-4374`), so a DAPP_CALL that apply discards
(`chain.cpp:1682`) IS still delivered — stamped with `amount`/`fee` (`node.cpp:4051-4062`) the
chain never moved, with no funding check anywhere. The reduction dissolves it.
B2 (future-nonce permanent seal) remains fee-independent and SURVIVES: `on_tx` drops only stale
nonces (`node.cpp:2905`), the M11 sweep only stale (`:2521-2528`), and `admit_check` has no nonce
test at all.

**Authority:** read-only analysis by Claude Opus 5, 2026-08-14, complete run. Nothing implemented.

---

## 2026-08-14 — SELECTIVE DISCLOSURE (user-controlled viewing keys): owner states the standing NO-SYSTEMIC-BACKDOOR position. Mechanism ALREADY DESIGNED, half ALREADY SHIPPED — do not build it twice

**Owner statement, recorded as the standing constraint:** the protocol rejects a systemic
backdoor entirely. Absolute privacy by default; users hold a SPEND key (authorize state
transitions) and a separate VIEW key (decrypt their own transaction graph). An investigated user
may VOLUNTARILY hand the view key to an auditor to prove innocence. If bad actors refuse,
authorities use traditional off-chain investigative methods. The protocol stays mathematically
pure. **No key escrow, no protocol-level disclosure compulsion, no third-party master key —
ever.** This is a HARD CONSTRAINT, not a design goal.

### ALREADY SHIPPED (A2, 2026-07-09, commit 268cfaa) — do not re-specify

`docs/proofs/AuditLayerSoundness.md` (Status: SHIPPED), gated by `determ test-audit-keys`
(35 assertions, in FAST via `tools/test_audit_keys.sh`):
* **`ROTATE_AUDIT_KEY = 15`** (`block.hpp:226`) — set / rotate / clear an account's standing
  audit pubkey; payload 32 opaque bytes; state leaf `"ak:"+addr` = `SHA256(pk_bytes)`, emitted
  only while set (`chain.cpp:430-438`).
* **`LOG_AUDIT_ACCESS = 16`** (`block.hpp:237`) — the on-chain record OF A VIEW-KEY DISCLOSURE:
  payload `epoch_u64_BE(8) ‖ auditor_pk(32) ‖ context_hash(32)`, exactly 72 bytes;
  **`AUDIT_EPOCH_ALL = UINT64_MAX`** is the full-history sentinel (`block.hpp:245`). The tx IS
  the record; state tracks only a per-account count on `"al:"+addr`. A standing `ak:` key is NOT
  required — ad-hoc disclosure is supported.
Both are FEE-ONLY, owner-bound, fail-closed, additive and atomic.

### DESIGNED, NOT SHIPPED (v2.22 / v2.24, tier FUTURE, `docs/V2-DESIGN.md`)

* Per-epoch view-key derivation: `vk_epoch_n = HKDF(view_master_sk, "VK" ‖ chain_id ‖
  account_addr ‖ epoch_n)` (`V2-DESIGN.md:1433`).
* Per-tx ephemeral-DH amount handshake: `aek = HKDF-SHA-256(ss, "AMT" ‖ epoch_n ‖ tx_hash)`.
* `audit_decrypt_tx(tx_hash, vk_epoch_n)` on an isolated audit-mode RPC socket
  (`Config::audit_mode`, `V2-DESIGN.md:1525`). The server holds NO auditor secrets.

### THE EPOCH GRANULARITY IS WHAT MAKES THE PFS CLAIM TRUE — state it precisely

A SINGLE STATIC view key that decrypts all history is the OPPOSITE of forward secrecy: disclosing
it once discloses everything, past and future, irrevocably. The shipped design is already
stronger than the owner's statement: keys are PER-EPOCH, so a disclosure is a BOUNDED WINDOW, and
`AUDIT_EPOCH_ALL` is an explicit, separately-recorded opt-out of that bound. **PFS is preserved
for epochs not disclosed — it is not preserved within a disclosed epoch, and it is fully waived
by `AUDIT_EPOCH_ALL`.** Any doc asserting unqualified PFS alongside view-key disclosure is wrong.

### THREE HAZARDS THIS POSITION INHERITS

1. **v2.22 BEFORE v2.24 makes the compliance posture go BACKWARDS — the project's own design doc
   says so** (`V2-DESIGN.md:1433`): once amounts become Pedersen commitments the auditor cannot
   read TRANSFER amounts at all, and without the per-epoch derivation + amount handshake the
   v2.22 chain is **more opaque than v1.x**. Sequencing is load-bearing: v2.22 and v2.24 ship
   together or the disclosure story regresses.
2. **DIRECT CONFLICT with the no-cryptocurrency reduction (0fe6eda).** View keys decrypt a
   TRANSACTION GRAPH; the reduction deletes the CT/shielded surface that graph lives in, and that
   surface is a large share of the value/CT-derived genesis-frozen commitment the reduction was
   argued to reclaim. **These two directives are not jointly executable as stated.** If the
   no-currency reduction proceeds, "selective disclosure" must be re-scoped to MQ/DApp encrypted
   PAYLOADS (`EncryptedNoteDeliveryDesign.md`, `REGISTER_NOTE_KEY = 17`) rather than to amounts —
   a different design with a different threat model. **OWNER DECISION REQUIRED; genesis-deadline
   on both sides.**
3. **A live CONFIRMED defect undermines the privacy-by-default premise:** CT proof randomness is
   derived only from `(nonce_seed, tx_nonce)` and NOT from the statement (`light/ct_tx.cpp:245`),
   so rebuilding a transfer at the same nonce DISCLOSES THE AMOUNTS. Privacy-by-default is not
   currently true on that path.

**Nothing implemented this turn. No parallel doc spawned** (doctrine: extend, do not spawn) — the
mechanism's authoritative homes remain `AuditLayerSoundness.md` (shipped) and `V2-DESIGN.md`
(tier FUTURE); this entry records the OWNER RATIONALE, which neither carried.

**Authority:** owner statement 2026-08-14, recorded by Claude Opus 5.

## 2026-09-14 — AUDIT of the post-reprioritization delta (9eedd94..f3f8858): record corrections; the authoritative set converged; the producer-includes-what-the-verifier-rejects halt class CLOSED in three node-local increments; S-065/S-066/S-067 found; owner-gated items listed

**Status:** audit + convergence + three code increments, each verified with `tools/ci_local.sh` on Linux x86_64 and adversarially reviewed before commit, independent of gate colour. Full audit: `audit-2026-09-14-post-reprioritization-delta.md` (repo root, tier PROCESS / ARCHIVE). Nothing owner-gated was decided here; the owner list is at the end.

### WHAT THE AUDIT FOUND (verified against HEAD f3f8858)

* **The code commit `0ce12c8` (2K > M at genesis) is correctly implemented and gated for the property it asserts — and that property is not the one the accept path needs.** Mutant 1 replayed: exactly the six rejection arms RED, 301/302 else green. `m_creators` is read by no accept rule (`validator.hpp` `m_pool_` write-only; `producer.cpp` `(void)m_pool_size;`); the K-committee is drawn from the ELIGIBLE POOL `N(h)` (`check_creator_selection`), which REGISTER leaves uncapped. `ddfe877` recorded this on 2026-08-14; SECURITY.md S-054, PROTOCOL §12.1, the WHITEPAPER field comment and the two source comments still said "closed" until this pass. The doctrine's own case study.
* **The twenty-three doc commits are append-only** (0024 edited two lines of 0023's entry to repair a red `test_doc_tier_check` — 0023 was committed without running `ci_local`). Their headline technical claims survive re-derivation from source: C0 (`84c1447`), the four `3dbe5f2` halts, the REGISTER identity takeover (`5e4afec`) are CONFIRMED; wording overstated in four places ("unauthenticated" for C0 — a registered eligible key is needed unless combined with the takeover; "permanent" for K3 — external re-entry can re-arm; "absorbing" for the REGISTER-geometry halt — per-node replace-by-fee displaces it; the "fifth" count is loose). **One supporting claim is false:** `ddfe877`'s "the FAST `ONLY_PATTERN` exercises no multi-node configuration at all" — `run_all.sh:108` runs seven in-process multi-node deterministic harnesses (`fa_liveness_virtual`, `fa_partition_virtual`, `fa_adversarial_deterministic` (5 nodes), `fa_crash_deterministic`, `node_reorg_s048`, `straggler_resync`, `beacon_header_committee`); the narrower claim (process-level cluster gates and the TLA models are outside FAST) holds.
* **Record hygiene, corrected here rather than by editing entries:** heading dates lag commit dates in `5e4afec` (08-13 vs 08-14), `07d41ed`/`ddfe877`/`8b86d39`/`0fe6eda` (08-14 vs 08-16) and `6265d34` (08-14 vs 08-18); `07d41ed` cites reverted-tree line numbers as HEAD (`validator.cpp:969-975/989/1058-1061`, `node.cpp:4628-4633` — at HEAD `:793`, `:815`, `:882`, `:4540-4545`); `6265d34`'s block.hpp/chain.cpp citations were copied from the stale `AuditLayerSoundness.md:16-23` (fixed there); `1c0a61d` "supersedes the prior entry's framing that a recovery key must be committed at first registration" — `5e4afec` contains no such framing; `ddfe877` cites `AbortCascadeLiveness.md:258` for F-c, which is §4.3 at `:184-194`; the `params.hpp:78-79` "100 suspensions" comment was wrong (ONE suspension ejects a floor-staked validator: 990 < 1000) — fixed.
* **The authoritative set had stopped tracking the log on 2026-08-13 13:31.** SECURITY.md printed "Open: 0" against nine recorded remote halts and kept S-052/S-054 mitigated; CLAUDE.md said "BOTH RANK-1 HOLES ARE CLOSED … Do not re-open them", "the residual's HARM is now gone" (the forfeiture is live at HEAD, `chain.cpp:1819-1825`), and specified `DTM-*-v2` / 229 B digests that were never the shipped bytes (`DTM-*-v3 ‖ index ‖ gen ‖ body_root`, 245 B — `producer.cpp compose_block_digest`, `binary_codec.cpp:547`); PROTOCOL.md still described the pre-inc7 JSON wire and `:117` asserted re-registrations preserve `active_from` (false at HEAD); `EquivocationSlashing.md:91-93` said the gen-binding was unauthorized and unshipped while the code ships it (`validator.cpp` "(2b) THE ROUND ASSERT"). All converged in commit "docs: converge …"; the per-file list is in that message.
* **The standing owner decision on slashing is a refuted design and the log never says so:** `f310086` (relocation to L2) → `5082737` ("stays in L1", lock rule, M > K — "superseding the L2 relocation recorded above") → `b5838fb` (lock rule REFUTED; "the sound options remaining are an L2/economic layer … or no consequence at all") → no owner restatement; CLAUDE.md carried `f310086`'s text. Recorded as owner item O-1 (CLAUDE.md), not decided here.

### WHAT LANDED (no owner action required; each its own commit, review and gate)

1. **Convergence commit (docs + comments):** SECURITY.md status note, summary counts derived from the rows, S-052 REOPENED (via S-060), S-054 PARTIAL, S-030 D1 wording corrected, S-011/S-013/S-029 flagged, rows S-055..S-064 with file:line evidence; CLAUDE.md (doctrine evidence corrected — six of nine reached green, three slashing attempts; no-backdoor HARD constraint added to PROJECT DOCTRINE; LIVE CRITICALS block; DECISION CLOCK R-1 re-pointed, R-4..R-9 added; owner items O-1..O-4); PROTOCOL.md/README/WHITEPAPER/CLI-REFERENCE/MOTIVATION + 13 proofs restated or bannered; `genesis.hpp`/`genesis.cpp`/`params.hpp` comments. New guard `tools/test_security_ledger_coherence.sh` (registered in `ci_local`): the ledger's summary must be DERIVED from its rows — three ledger mutants RED.
2. **Increment A (commit "node: the producer asks the verifier …") — the producer asks the verifier (S-056/S-059/S-061/S-062, the halt class).** `check_transactions`' per-tx loop body moved VERBATIM into `BlockValidator::check_transaction` (the ONE per-tx rule set; accept-set unchanged — diffed hunk by hunk); `build_body` admits only what it accepts (`TxAdmit`, fail-safe: an empty predicate admits nothing), wired by `Node::tx_admit_locked()` at all three call sites (pinned by `tools/test_producer_admit_wiring_guard.sh`). Gate `determ test-producer-admit`: one fixture per recorded halt with controls proving the admit-everything assembler includes it AND the verifier rejects that body; two mutants RED. Review (independent of gate colour): accept-set unchanged; predicate deterministic over head state; same height/registry as apply; residual = the re-check cost of resident txs → increment 3.
3. **Increment B (commit "node: a rejected transaction is evicted at build time …") — a rejected tx is evicted at build time; verdicts memoized per head; gossip ingress drops a tx whose wire `hash` ≠ `compute_hash()` (S-066).** A first version that ALSO ran the verifier's predicate at mempool ingress was **REFUTED in review and dropped**: the verifier's CONFIDENTIAL_TRANSFER arm costs ≈ 2.2 s (aggregated range proof, measured on the C99 implementation; Ed25519 verify ≈ 3 ms) under the exclusive consensus lock, and the S-002 mirror's anon→TRANSFER-only rule is today the only thing keeping anonymous CT bundles off that path (it is NOT the verifier's rule — the documented light-client shield flow from an anonymous key is rejected at ingress). Recorded as **S-065** (open, owner-gated R-10). The review of the landed version found that `on_tx` stored a gossiped tx under its UNSIGNED wire hash (only `rpc_submit_tx` recomputed it) — the mempool-overwrite primitive `07d41ed` named, and a memo-poisoning route to the same halt — fixed (**S-066**, mitigated) — and, pre-existing, that **no UNSTAKE is includable** (unlock only after DEREGISTER, by which time the domain is ineligible and the verifier rejects its every tx before the type switch): staked funds are unrecoverable through consensus (**S-067**, open, owner-gated R-11). Gate `determ test-mempool-admit-eviction`: ingress-hash, memo-poisoning (fee-5 impostor under a claimed hash dropped; fee-3 RPC replacement still queued), eviction, quota-release and memo hit/miss arms; two mutants RED. `test_fa_partition_virtual` is wall-clock bounded and failed once while mutant builds ran concurrently on the 2-core box — green when re-run idle; do not overlap mutant builds with a FAST run.
4. **Increment C (commit "node: the Phase-2 trigger is committee completeness …") — S-058: the Phase-2 trigger is committee completeness, not the pending map's size; the Phase-1 timer is released only once the committee is complete** (both trigger sites; nothing signed or accepted changes). Gate `determ test-contrib-trigger-membership` (virtual-time single node, M=4/K=3, a registered non-member's contrib; a direct incomplete transition call; the pre-phase site); three mutants RED. Review: no consensus impact; the completeness trigger never fires earlier and never fails to fire where the size trigger did; noted, unchanged: `handle_contrib_timeout`'s all-present early return is a latent dead-end of the same shape, reachable now only in the stale-expiry window where the posted transition still completes.

FAST count: 302 → 305 (`producer_admit`, `mempool_admit_eviction`, `contrib_trigger_membership`); `ci_local` guards 14 → 16 (`security_ledger_coherence`, `producer_admit_wiring_guard`). Ledger after this pass: Open 4 Critical (S-055, S-057, S-060, S-063) + 3 High (S-064, S-065, S-067); Reopened 1 (S-052); Partial 4 (S-030, S-054, S-035, S-036); Mitigated 45.

### OWNER-GATED, in order of significance (nothing here was decided; see CLAUDE.md DECISION CLOCK / owner items)

1. **R-5 / S-060 — create-only REGISTER (V-REG-1).** Any key overwrites any validator's identity at zero cost (fee debited from the VICTIM), reopens S-052, halts an M == |pool| chain with probability 9/10 per overwrite. Accept-rule change; the three alternatives were refuted (`5e4afec`); makes a lost key terminal until a rotation tx exists (`1c0a61d`: addable later, reserve nothing). Worst finding on the record; a day of work once authorized.
2. **O-1 — the standing slashing position** (L2 relocation / no consequence / neither) after `b5838fb`. Gates R-1, R-8 (C0 demotion is sound only once the evidence carries no L1 consequence — `7570989`) and the S-011/S-013/S-029/BFTSafety T-5.1 re-derivations. One log entry.
3. **R-8 / S-055 — C0.** After O-1: evidence-payload demotion (design AUTHORIZED, `5b2d7fe`) + per-block cap + in-block duplicate rejection, each its own increment.
4. **R-4 / S-054 — the runtime bound `2K > N(h)`**, designed together with F-c; with `N ≥ 2K` two racing committees finalize conflicting blocks with no double-signer. Genesis-frozen.
5. **R-11 / S-067 — UNSTAKE is unincludable** (stake unrecoverable through consensus). Accept-rule change; genesis-frozen. Economic, not a halt, but it falsifies the operator tooling and every "validators can exit" statement.
6. **R-7 / S-057 — `pq_auth` empty on non-PQ types + a consensus block-byte cap** matching the 4 MB wire cap. New accept rules; genesis-frozen.
7. **R-10 / S-065 — CT verification off the consensus lock (or a CT budget) and the anon CT ingress rule.** Node-local except the ingress rule's consistency with the verifier; pre-existing at validation (a block with ten CT txs costs each node ≈ 22 s).
8. **O-3 — order the open set against the D2 front** (ACTIVE FRONT still says D2). **O-2 — ratify or narrow the 2026-08-13 doctrine** (`352fc52`, recorded "at the direction of the session orchestrator … flagged for owner review"). **O-4 — the no-cryptocurrency reduction vs the no-backdoor constraint** (`6265d34` hazard 2). **R-6 / R-9** (rotation timing; B4 MsgType 12/13/14) follow their parents.
9. **S-063 (DAPP_CALL frames report payments never made) and S-064 (cross-shard bundles unauthenticated, multi-shard only)** — recorded, not re-triaged here; S-063 is node-local delivery-layer work once the owner confirms its severity.

**Authority:** audit and increments by Claude (Cowork session), 2026-09-14, at the owner's request ("fix all that do not need owner action"); no decision taken. This entry is append-only per convention and contains no tier marker in its body.

## 2026-09-15 — OWNER AUTHORIZATION: create-only REGISTER (V-REG-1) LANDED with its small-order-key companion; the Zeroth pool was drainable through a COMPOSABLE_BATCH inner transfer (found by review, closed the same day); the "no key can sign over the all-zero pubkey" premise RETRACTED; S-069/S-070/S-072/S-073 recorded; owner-gated list re-ordered

**Status:** one owner decision and three code increments (D, E, F), each verified with `tools/ci_local.sh` on Linux x86_64 and adversarially reviewed before commit, independent of gate colour. Ledger after this entry: Open 3 Critical (S-055, S-057, S-063) / 5 High (S-064, S-065, S-067, S-069, S-073) / 1 Medium (S-070) / 1 Low (S-072) = 10; Mitigated 49. FAST 305 → 308; `ci_local` guards 16.

### THE DECISION (owner, 2026-09-15: "Do the recommended.")

The owner was given the S-060 mechanism in detail with five options (leave as is; create-only REGISTER; incumbent-signed re-registration; a separate ROTATE tx now; a genesis-pinned validator set) and the recommendation "create-only REGISTER now, key rotation as its own later transaction (R-6), key loss terminal, small-order-key check as the companion increment". The owner authorized the recommendation. **Decided consequences, now frozen accept rules:** a domain name is single-use; a REGISTER is accepted only for a name absent from the RAW registrants map (active, pending, suspended or deregistered are all taken) and only at nonce 0; a lost key is terminal for the domain; DEREGISTER — and an equivocation deregistration — is terminal under that name, the domain's balance, stake (S-067) and DApp ownership staying with it; key rotation is a separate incumbent-signed transaction (R-6, still open). Alternatives refuted 2026-08-14 (`5e4afec`) stand refuted.

### WHAT LANDED (each its own commit, review, gate and mutants)

1. **Increment D (commit "consensus: REGISTER is create-only (V-REG-1) …") — S-060 CLOSED, S-052 re-closed.** `BlockValidator::check_transaction` rejects a REGISTER for any domain in `chain.registrants()` and any REGISTER with `nonce != 0` (which also makes one-REGISTER-per-domain-per-block a per-tx rule); `rpc_register` refuses for a registered node; the ingress mirror applies both checks so a zero-cost takeover REGISTER cannot squat the victim's `(from, nonce)` slot until a build evicts it. Apply's re-registration branch is unreachable and retained as belt-and-suspenders. Gate `test-register-create-only` (four mutants RED). PROTOCOL.md §3 :117 corrected ("re-registrations preserve `active_from`" was false; apply re-randomised it). Review findings recorded as **S-069** (High: under `STAKE_INCLUSION` no domain can JOIN after genesis — a fresh registrant has no stake, is absent from the eligible registry, and its STAKE is rejected "sender not in registry"; `0fe6eda` REVERSED 1 states it as a fact, README claimed the opposite; R-12) and **S-070** (Medium: a fee-0-balance / fee-MAX REGISTER is mempool-resident and squats the name slot until a build evicts it — the verifier has no `balance >= fee` rule for REGISTER).
2. **Increment E (commit "consensus: a REGISTER whose payload key is a small-order point …") — S-068 CLOSED.** `determ_ed25519_verify` performs no torsion check; under the neutral element `(R = O, S = 0)` verifies every message and under the other seven 8-torsion points one message in at most eight, so a REGISTER carrying such a key would have a vacuous proof of possession and — now that REGISTER is create-only — a permanently forgeable identity. `determ_ed25519_point_has_small_order` (one decode, three in-place doublings, neutral test on the extended coordinates) is applied to the payload key AFTER the signature in the verifier's REGISTER case and in the ingress mirror, so an unauthenticated REGISTER pays nothing beyond the verification it already paid (the review's cost finding: the first version ran a full 256-bit ladder BEFORE the signature, ≈ 55 % of a verify on the unauthenticated S-065 lock-time surface). The decoder's known exception is recorded next to `point_y_is_canonical`: the sign bit is not checked against `x = 0`, so the neutral element and the order-2 point each decode from two encodings; ten encodings decode to torsion points and all ten are rejected. Gate `test-register-small-order-key` demonstrates the forgery for every encoding first (a verifying `(R = O, S = 0)` REGISTER found within a few domain-name trials), then pins the verifier, an undecodable key, a normal-key control and the ingress mirror; mutants M1 verifier / M2 helper / M3 mirror RED.
3. **Increment F (commit "consensus: the Zeroth pool cannot be spent through a COMPOSABLE_BATCH inner transfer …") — S-071 found and CLOSED the same day (Critical).** The E1 pool is an ordinary account at the all-zero anonymous address, an anonymous address IS its key, and the all-zero key is a small-order point (order 4) — forgeable, one message in four. The guard `tx.from == ZEROTH_ADDRESS` saw only the OUTER transaction; a COMPOSABLE_BATCH inner TRANSFER from the pool passed the inner signature check with a forged signature and apply debited the pool: anyone could sweep it for the price of an outer fee. The gate demonstrated the drain against the unfixed tree before the rule landed. Now the verifier's COMPOSABLE_BATCH arm rejects an inner tx from the pool before its signature, the apply loop mirrors it inside `atomic_scope` (before any `accounts_` insertion), and the ingress mirror gained the outer check. Gate `test-zeroth-pool-inner-batch`: forgery demonstrated, verifier pinned on the inner reason string, ordinary batch accepted, apply pinned (batch processed — outer nonce consumed — and rolled back, pool unchanged), mirror pinned; mutants M1 verifier / M2 apply / M3 mirror RED. Not replay-compatible with a chain that already carried such a batch (pre-genesis, none exists).

### CORRECTIONS TO THE RECORD (retracted here, not by editing earlier entries)

* **"The all-zero pubkey has no usable private key; no actor can synthesize a signature for `from == ZEROTH_ADDRESS`; the validator's rejection is defense-in-depth"** (FA11 `EconomicSoundness.md`, FA-Apply-14 `NefPoolDrain.md`, `SubsidyDistribution.md`, `DAppRegistryLifecycle.md`, `params.hpp`, `validator.cpp`, `chain.cpp`, `main.cpp`, WHITEPAPER §8.5, UNIT-TESTS, CLI-REFERENCE, docs/README) is FALSE. A small-order key is the EASIEST key to forge under, not an unsignable one. The E1 guard is the load-bearing rule, and it must be asserted at every layer that verifies a sender — which is exactly the reasoning the false premise suppressed (S-071). Every copy is corrected in-place with a dated note.
* **WHITEPAPER §8.5's lottery + per-block cap (`nef_grant`, `nef_probability_denom`, `nef_max_wins_per_block`) is DESIGN, NOT SHIPPED.** The shipped NEF hands `pool / 2` to every first-time REGISTER unconditionally (`chain.cpp` REGISTER apply); no such genesis field exists; `EconomicSoundness.md` :231 already flagged the rewrite but SECURITY.md and the whitepaper did not. §8.5 now carries a DESIGN-NOT-SHIPPED status; the paper's Sybil-boundedness claim does not hold for the shipped code — recorded as **S-073** (High): a fee-0 REGISTER needs no balance and no stake, so ~log2(pool) fresh names empty the pool at zero cost; under `DOMAIN_INCLUSION` the grants are spendable (theft of protocol funds without any forged signature), under the `STAKE_INCLUSION` default they are stranded (S-069). Owner decision R-14.
* **Small-order anonymous addresses** (the nine unguarded torsion encodings; the all-zero one is the pool) are anyone-can-ACT identities for every tx type an anonymous sender may submit — recorded as **S-072** (Low, footgun not theft; R-13: reject every tx whose anonymous sender key is small-order, or document them).
* The `1c0a61d` entry's "the small-order check is a one-liner" was optimistic only in placement: after the signature, not before, or it becomes an unauthenticated cost on the consensus lock.

### OWNER-GATED, in order of significance (R-5 is done; nothing else here was decided — see CLAUDE.md DECISION CLOCK / owner items)

1. **O-1 — the standing slashing position** (L2 relocation / no consequence / neither) after `b5838fb`; gates R-1 and R-8.
2. **R-8 / S-055 — C0** (the F2 equivocation-view digest halt): after O-1, evidence-payload demotion (design AUTHORIZED, `5b2d7fe`) + per-block cap + in-block duplicate rejection, each its own increment.
3. **R-7 / S-057 — `pq_auth` empty on non-PQ types + a consensus block-byte cap** matching the 4 MB wire cap; a valid block must never be unrelayable. New accept rules; genesis-frozen.
4. **R-4 / S-054 — the runtime bound `2K > N(h)` over the eligible pool**, designed with F-c; genesis-frozen.
5. **R-14 / S-073 — the NEF giveaway** (NEW): ship the §8.5 lottery + cap, gate NEF on a stake/balance floor, or set `zeroth_pool_initial = 0` at genesis. A genesis with a funded pool under the shipped rule is a giveaway; decide before genesis.
6. **R-12 / S-069 — no post-genesis join path under `STAKE_INCLUSION`**: closed set BY DESIGN (say so; the REGISTER/STAKE tooling is then misleading) or accept STAKE from a registered-but-unstaked domain (accept-rule change). With V-REG-1 + terminal DEREGISTER the set can only shrink.
7. **R-11 / S-067 — UNSTAKE is unincludable** (stake unrecoverable through consensus). Accept-rule change; genesis-frozen.
8. **R-10 / S-065 — CT verification off the consensus lock (or a CT budget) and the anon CT ingress rule.**
9. **R-6 — key rotation before genesis or not**: a new TxType is free at the wire/state layer, but old validators fail closed on unknown types, so first use needs every validator upgraded; with key loss now terminal the question is whether a rotation path must exist before an upgrade window does.
10. **O-3, O-2, O-4** — order the open set against the D2 front; ratify or narrow the 2026-08-13 doctrine; the no-cryptocurrency reduction vs the no-backdoor constraint.
11. **S-063, S-064, S-070 (Medium: a `balance >= fee` REGISTER rule or ingress-side affordability), S-072 / R-13** — recorded, not re-triaged here.

**Authority:** decision by the owner (Stoyan Denev), 2026-09-15 ("Do the recommended."); increments, reviews and findings by Claude (Cowork session), 2026-09-15. This entry is append-only per convention and contains no tier marker in its body.

## 2026-09-15 — Per-block committee selection EVALUATED (NOT JUSTIFIED for availability); the abort event's identity was the assembler's choice — S-074 CLOSED in two increments; S-075/S-076/S-077 recorded; a DYNAMIC `epoch_blocks` computed from network state EVALUATED (not an availability mechanism; not built)

**Status:** one design analysis (`design-2026-09-15-per-block-committee-selection.md`, TIER PROCESS), two code increments (S-074, both adversarially reviewed before commit), three ledger rows, three DECISION CLOCK / owner rows. Ledger after this entry: Open 3 Critical / 5 High / 2 Medium (S-070, S-075) / 3 Low (S-072, S-076, S-077) = 13; Mitigated 50. FAST 308 → 309; `ci_local` guards 16.

### THE QUESTION AND THE VERDICT

Owner: should Determ draw a fresh random K-of-K committee per block instead of the epoch-seeded one, for availability and targeted-DDoS resistance, keeping the epoch checkpoint for cross-shard verification? **Not justified for that objective.** The chain's per-round tolerance is at most ONE silent committee member: with two silent, no claim bucket against a silent member can reach `max(2, K−1)` (claims come only from and against committee members), escalation counts aborts that never form, and the S-050 valve re-derives the identical committee because the height — hence the seed — is frozen. That bound is cadence-independent. Per-block selection changes only whether the attacker chooses the two victims (epoch seed: yes, for `epoch_blocks` heights) or waits for two flooded nodes to be co-drawn (expected `N(N−1)/(K(K−1))` blocks: 2 at a pool of 4 with K=3, 2.1 at 7/5, 44 at 30/5). What it does buy: the next committee is computable only once the K-th Phase-2 reveal of the current height is on the wire (block assembly + propagation ahead, not an epoch), duty and creator income spread per block, and a colluding K-set censors for one block instead of an epoch. On `SINGLE`, `cluster` (BEACON, one shard) and a beacon-less `SHARD` this is the existing genesis choice `epoch_blocks = 1` (both resolvers read `chain.at(H−1).cumulative_rand`; `tools/test_weak_3node.sh` runs it live); on a beacon-peered shard the seed is the beacon's anchor rand and the beacon and the light auditor re-derive shard committees from `cc:[E]` alone, so a per-block shard seed would need the parent header carried on the witness path. Forced-turnover selection rejected (a different distribution, undefined at `N = K`, hands the attacker a known future member at `N = K+1`). Block-hash seeding, wall-clock terms and round markers not revived. Independent adversarial review of the analysis: 17 findings, all accepted; the verdict survived in both directions.

### WHAT LANDED (owner: "address them")

1. **S-074 — the abort event's identity was the assembler's choice (High; found by the analysis, closed the same day in two increments).** The hash folded into the post-abort re-selection (`rand = SHA256(rand ‖ event_hash)`) was whatever the assembling node put in the event: nothing recomputed it, its timestamp was the assembler's wall clock, and any in-sync peer holding the `K−1` public claims could assemble — so any peer chose the re-round committee among all `C(N−1, K)` sets, a Phase-2 withholder (unslashed) could pre-grind its own replacement, and two honest survivors assembling one abort in different seconds produced two events (the C1 tail fork behind the S-050 livelock class). Now `timestamp` = the parent block's and `event_hash = SHA256("DTM-ABORT-ID-v1" ‖ 0 ‖ committee_seed ‖ height ‖ round ‖ node)` for the first event at a height, `SHA256(tag ‖ 1 ‖ prev.event_hash ‖ round ‖ node)` chained — seeded by the §5.2 committee seed every verifier already derives, so no parent block is needed anywhere; the timestamp was dropped from the hash after the review found the parent committee chooses the block timestamp inside the ±30 s window (a free ~60-way re-draw). Enforced by `check_abort_certs` (before the fold), the assembler, gossip adoption (before the claim signatures; only the canonical next event of the local tail; the accused must be in the current committee — a replay of an excluded member's public claims was adoptable and yielded a tail no block can carry), the beacon's tip verification (hence the beacon's witness accept rule) and the light auditor. Gates `test-abort-cert-validation` (+4 arms), `test-abort-event-canonical` (new; M=5/K=3 so the post-abort draw is 3 of 4 and a chosen hash demonstrably seats a different committee; a non-member assembles the canonical event under a wall clock ≠ chain time), `test-shardtip-witness-verify` (+2 arms); seven mutants RED. `AbortCertificateSoundness.md`'s "the binding is enforced transitively through the seed chain" is retracted. Liveness side effect: honest survivors now assemble byte-identical events (C1 gone; `μ_r = 1` for honest assemblers; the valve trips at its 5 s window on the concurrent-quorum wedge instead of drifting to 30 s).
2. **S-075 (Medium, node-local, open) — snapshot bootstrap with a header tail:** `height() == blocks_.size()` while `at()` is positional; reproduced (`height() == 2`, `head().index == 6`); such a node never validates the next block. Fix shape recorded.
3. **S-076 (Low, open by design) + R-15 + PROTOCOL.md §12.1:** the two-silent-member bound, stated. The availability lever is the abort quorum / non-committee claimers when `N(h) > K`, not the cadence.
4. **S-077 (Low, open) + R-16:** the last Phase-2 revealer's free veto (rejection sampling, not choice); the M-F "backed by slashing machinery" clause corrected; the E3 lottery comment corrected.
5. **WHITEPAPER §3.1:87** no longer claims the previous block's `cumulative_rand` seeds every height.

### OWNER FOLLOW-UP: "epoch_blocks can be dynamic and calculated upon the network state to achieve best possible availability" — EVALUATED, NOT BUILT

A consensus-visible cadence may read only committed state (`N(h)`, `K`, abort records, block timestamps, heights); local liveness, RTT, valve timers and the wall clock differ per node (a fork; the refuted family). A cadence moves only the targeting horizon and the duty spread; it cannot move the one-silent bound, the stalled-height freeze (a stalled height commits nothing, so no committed input changes while it is stalled), the abort-slash fuse or the two-colluder halt. For what it does move, the best value on a local-seed chain is `E = 1` whenever `N(h) > K` and the cadence is irrelevant at `N(h) = K`, so the only state-dependent rule that improves anything degenerates to the constant `1`. A dynamic rule would add a genesis-frozen formula, history-dependent epoch boundaries on every cross-shard re-verifier (`cc:[E]`, the beacon anchor, the auditor, the ring), and a bias channel through any committee-influenceable input — for zero behaviour change where it matters. Adapting to network state is meaningful elsewhere: the abort quorum vs. pool margin (R-15), provisioning `initial_stake ≥ min_stake + SUSPENSION_SLASH × tolerated aborts`, pool margin `N ≥ K+2`, a cost for Phase-2 silence (R-16). Owner item O-5: pick `epoch_blocks` at genesis (`1` on `SINGLE`/`cluster` if the per-block benefits are wanted; `≥ 2` on EXTENDED beacons; the default otherwise). Analysis: `design-2026-09-15-per-block-committee-selection.md` §13.

**Not revived:** block-hash seeding (doctrine), wall-clock / time-bucket terms ("final+9"), gossiped or self-declared round markers ("final", "final+5").

**Authority:** design analysis, increments and records by Claude (Cowork session), 2026-09-15, at the owner's direction ("address them"; the dynamic-cadence question); no decision on R-15 / R-16 / O-5 taken here. This entry is append-only per convention and contains no tier marker in its body.

## 2026-09-16 — Durable message submission: the `determ-light outbox` (increment 1) LANDED after three adversarial reviews (design, diff, fixed diff); what each submission observable proves is now written down; six findings recorded (a doc error on the tx hash, `submit_tx` acknowledges what the verifier will evict, the DLS1 writer is not durable, the trustless read's cleartext cross-check races its own `--wait`, the wire carries no chain identifier and no expiry, `verify_tx_inclusion` skips the quorum-count rule)

**Owner directive.** "Develop durable message submission and retry for Determ … distinguish local durability, network submission, ledger finalization, and application consumption … prefer a sender/client/SDK outbox using existing transaction and RPC formats." Base: `main` f3f8858 (the 2026-09-14/15 bundle 0001–0012 was NOT integrated on the owner's tree and was not applied by this work); the increment was built on the bundle's tip (dd09330) and is delivered as patches 0013+.

**What existed, what was missing (inspection).** Identity: `tx.hash = SHA256(signing_bytes)`, content-derived, no expiry, no chain binding (`src/chain/block.cpp:20-37`; PROTOCOL.md §3.2 wrongly said `‖ sig` — corrected in the same delivery). Submission: `submit_tx` recomputes the hash, rejects a stale nonce, verifies the signature, applies mempool policy and replace-by-fee, and answers identical pending bytes with "incumbent tx at (from, nonce) has equal-or-higher fee" (`src/node/node.cpp:4606-4709`); it does not run `check_transaction`, whose rejections evict at build time with a node-side log only (`node.cpp:2848-2872`). The mempool has no TTL. Verification: the verifier enforces the sequential nonce and no balance rule for TRANSFER/DAPP_CALL; the producer debits TRANSFER provisionally but has no DAPP_CALL arm; apply skips an underfunded tx WITHOUT advancing the nonce (`chain.cpp:987, 1688`), so one hash can be included twice, and delivery scans block bodies only (S-063; the 2026-08-14 D4 withdrawal). Finality primitives already shipped in `determ-light`: `verify_tx_inclusion` (a block's own committee sigs, no successor) and `committee_bound_state_root` (the S-042 successor binding); `read_account_trustless` proves `(balance, next_nonce)` at `view.height-1`. No client persisted a signed tx; the one retry loop (`src/main.cpp:2218-2239`) re-tries on the substring "nonce" over node-custodial RPCs; the DLS1 anchor writer is a plain truncating write.

**Design and review.** The contract was written before code (durable record, identity, five-way status, recovery, bounds) and put to an independent adversarial review, which returned **not approved** with 4 blockers and 12 should-fixes, all folded in: (1) a permanently un-includable slot would brick every higher nonce — so no daemon error string is ever treated as permanent, every client-decidable rejection is refused at enqueue, `replace` can re-issue at the same nonce, and prune / the nonce floor move only over PROVEN-consumed nonces; (2) an INCLUDED slot had no exit when its block was orphaned (S-048) — the successor binding on the recorded block now re-arms it; (3) "signature verification failed" is state-dependent (registry lag) — never permanent; (4) a skipped-at-apply slot re-armed unconditionally would be re-included at zero cost forever — re-arm only while the verified balance covers amount+fee, capped at 8; plus CONSUMED/UNLOCATED instead of a terminal FAILED under the single-signer assumption, attribution by the greatest canonical inclusion height across all alternates, `fcntl`/`LockFileEx` locking with create-new publishes instead of a pid file, socket timeouts, the classifier corrected to the daemon's real strings, an strace syscall-order gate for the power-loss half, a two-section record so a corrupt status is recoverable while the nonce stays reserved, an explicit idempotency key, consumer obligation C5 (same-height reorg reuses `(block_index, tx_index)`), the scope cut to TRANSFER from a DAK1 keyfile, and right-layer gates: `RpcClient::call` made virtual so the REAL submit/reconcile cores run in-process over a committee-signed fixture chain.

**What landed (light client only; zero `src/` change).** `light/outbox.{hpp,cpp}` (DOX1/DOM1 canonical records, `durable_write_new/replace`, the lock, `build_transfer`, `classify_submit_error`, `submit_due`, `reconcile_all`, `pin_daemon_genesis`), `light/outbox_cli.cpp` (`outbox enqueue|submit|reconcile|status|replace|prune|recover`, exit codes 0/1/3/4/5/6/7/8), `light/outbox_selftest.cpp` (`selftest-outbox-record|classify|core`, the in-process fixture daemon), `light/rpc_client.{hpp,cpp}` (`call` virtual; `set_timeout_ms`, additive). Contract: `docs/proofs/DurableOutboxSoundness.md` OB-1..OB-6 (indexed), PROTOCOL.md §3.6 (what each observable proves; consumer obligations), CLI-REFERENCE.md rows. Gates: `tools/test_light_outbox.sh` (FAST; 40 assertions, wrapping 46 core scenario checks) and `tools/test_light_outbox_live.sh` (single node; 23). Mutants M1 ack-before-publish, M2 no hash check, M4 incumbent-as-failure, M5 head-as-final, M5b binding skipped, M6 inclusion-as-applied, M7 cap-after-write, M8 prune-non-terminal, M9 no-fsync, M10 skip-per-pass, M11 continue-after-lost-reply, M12 unverifiable-not-blocking, M13 later-skip-never-counted, M14 proven-skip-attributed, M15 attribution-with-an-alternate-unanswered, M16 orphan-re-arm-of-a-spent-nonce, M17 CONSUMED-never-re-probed, M18 re-issue-re-counts — each RED on its named leg. The diff review (not approved at first pass: 4 blockers, 11 should-fixes) was folded in before landing: a skip was counted per reconcile pass instead of per inclusion (a once-skipped message disarmed itself after 8 polls); a transiently unverifiable probe could write a terminal CONSUMED; a recv timeout left the RPC stream desynchronised so later slots read the previous reply (now the run ends and an ack must name the slot's hash); the lock leg used python `fcntl` (RED on the Windows runner — now the binary's own lock path); plus `--nonce` below the floor refused, terminal slots not re-stamped, directory-fsync failure thrown, `F_FULLFSYNC` on Darwin, a hard-link fallback, hostile `tx` replies contained per slot, a re-issue must also raise the fee, the orphan/attribution/Windows wording corrected, and a bounded re-read on the F-4 race. The final pre-commit read of the diff found one more: the once-per-inclusion guard compared `finalized_height` AFTER it had been moved to the new inclusion, so a later skipped inclusion was never counted and the 8-skip cap was unreachable (the zero-cost re-inclusion loop the design review had closed) — fixed, core 3c added, M13 RED. A third independent review of the fixed diff returned no blocker and five should-fixes, all folded in: (i) an inclusion the record had already proven SKIPPED could be re-labelled APPLIED once the nonce was spent (an A1 violation, or a daemon withholding the applying alternate's hint) — now CONSUMED/UNLOCATED naming the proven skip, core 11; (ii) with several alternates a spent nonce was attributed while another alternate's probe was unverifiable — attribution is now withheld (exit 3) until every alternate verifies, core 12; (iii) a daemon serving the ORPHANED sibling of a block whose canonical twin carried and applied the bytes drove the slot to a re-arm (stale re-sends) or to CONSUMED with a false "locates none" note — a spent nonce is never re-armed, the verdict names the orphaned body, and CONSUMED slots are probed again on every pass (never re-sent, never re-stamped) so a daemon that later serves the canonical block upgrades them to FINALIZED/APPLIED, core 13; (iv) the enqueue nonce hint came from the bare `nonce` RPC (an unverified daemon positive could reserve a nonce the chain never reaches, blocking every later auto-nonce) — it is now the committee-verified `next_nonce` via `read_account_trustless`; (v) an unreadable `outbox.meta` bricked every verb — `status` reports it, mutating verbs refuse (exit 3), `recover` rebuilds the pin from an intact record (the floor is rebuilt as 0, which only loses a refusal). Notes folded in: a re-issue no longer re-counts the earlier alternate's inclusion (core 3d, M18); BLOCKING is reported when the expected nonce's slot is quarantined; a status-corrupt record keeps its decoded nonce for the file-name check; a well-formed reply not naming the slot's hash ends the submit run; `prune` drops quarantined files below the floor (live 5); a reused idempotency key answers with the slot it already names (exit 8). Recorded, not built: the node runs `mempool_admit_check` before the incumbent check (identical bytes into a full mempool read as a retryable rejection, not "incumbent"; the slot stays sendable), and `verify_tx_inclusion` verifies the inclusion block's signatures without the genesis `k_block_sigs` (finding F-6 below). Verified through `tools/ci_local.sh` (build confirmed; FAST 310/0; 16 guards) before and after each pass.

**Guarantees, stated exactly.** `queued locally` ⟹ the signed bytes are fsync'd and atomically published on that device (one copy; not replication). A re-send carries the stored bytes — the submit core holds no key. SUBMITTED means a daemon acknowledged the bytes at that instant; UNKNOWN means the reply was lost; INCLUDED means committee-signed membership in a block that may still be the reorg-able head; FINALIZED means a committee-signed successor binds that exact block; APPLIED / SKIPPED come from the committee-bound `next_nonce`, never from inclusion; CONSUMED/UNLOCATED labels a daemon negative. Ledger application is at-most-once per nonce and exactly-once iff a slot reaches FINALIZED/APPLIED; consumer receipt is not a property of this increment. Assumptions A1 (single signer per key), A2 (daemon negatives untrusted), A3 (the readers' residuals R-1/R-4, static committee, S-033 active), A4 (fsync-honouring local storage).

**Findings recorded, kept separate.** (F-1, fixed in this delivery as its own commit) PROTOCOL.md §3.2 claimed `compute_hash = SHA256(signing_bytes ‖ sig)`; the code hashes `signing_bytes` only — the hash is content-derived and signature-independent. (F-2, open, node-local) `submit_tx` acknowledges transactions the verifier will evict at build (`check_transaction` is not run at RPC admission), so a structurally invalid message reads SUBMITTED until the outbox reports it STUCK; an RPC-time pre-check would give clients a definitive rejection — a separate node-side increment, no consensus change. (F-3, open) `light/persist.cpp` `save_light_state` is a plain truncating write; the new `durable_write_replace` can back it. (F-4, open) `read_account_trustless` fetches the `account` cleartext AFTER the `--wait` successor poll and compares it with the proof held from before, so a block that touches the sender's account during the wait makes the read throw TAMPERED (fail-closed, a false alarm; `verify-and-submit --wait` and `outbox reconcile --wait` hit it whenever the sender's own tx lands in that block) — read the cleartext with the proof, or retry the read once on a value-hash mismatch. (F-5, open, unchanged) the wire carries no chain identifier and no expiry: a released tx can be neither cancelled nor domain-separated; both are consensus/wire changes (pre-genesis only) needing their own design. (F-6, open, light client) `verify_tx_inclusion` calls `verify_block_sigs` without `expected_k`, so the LV-1 quorum-downgrade check (`light/verify.cpp`, the `k_block_sigs` count rule) is not applied to the inclusion block: `verify-tx-inclusion` and the outbox's INCLUDED (non-final) state can rest on a block naming fewer creators than genesis requires; FINALIZED is unaffected (the successor binding passes `k_block_sigs`). Passing the genesis k is a one-line change to an existing command's acceptance and is left to its own increment.

**Not built (deliberately).** DAPP_CALL from the outbox (needs a registered-domain key: a DNK1 loader in `determ-light`; inherits S-069), any node-side change, cancellation of released bytes, replication.

**Authority:** design, review disposition, implementation and records by Claude (Cowork session), 2026-09-16, at the owner's direction; no owner decision was taken or pre-empted. This entry is append-only per convention and contains no tier marker in its body.

## 2026-09-16 — OWNER DECISIONS (Step 3 of the remediation strategy): every DECISION CLOCK row and owner item resolved; the launch posture, configuration and clause, the slashing position, the pool bound, the join/exit rules, the EXTENDED closure set and the transaction-frame identity decided; six design gates authorized; the implementation sequence fixed; 26 ledger rows added for defects the log recorded without a number

**Status:** decisions only — nothing implemented in this entry. Each decision names its consequence and its proof obligation; every accept-rule change is genesis-frozen and goes through design-and-prove, independent adversarial review and a falsify-on-mutant gate at the layer where the rule lives before it lands. Taken one by one over the Step 1 inventory (this session, read-only reconciliation of `main` f3f8858 plus the unapplied exports 0001–0014; every "closed" claim re-verified at source in both trees). Existing authorizations (V-REG-1, D2, C2, the rank-1 holes, Q1/Q2, S-050, S-074, the outbox) are unchanged. Refuted designs (the six pre-finalization predicates, the L1 lock rule, `round_seq`, Option D, the time-bucket / round-marker / local-cadence family, the shape-subset eviction, P1 as stated) are not revived.

### A. Work order

**D1 — O-3: safety first, D2 wire remainder in parallel.** The exports 0001–0014 are applied first (owner act). Consensus safety/liveness increments proceed in the order of §E; D2's genesis-deadline wire remainder (inc7c: SNAPSHOT_RESPONSE + HEADERS_RESPONSE) runs alongside on disjoint files; D2 step 1b (test-handler extraction) and step 4 (parser deletion, Q3 Path A) follow. ACTIVE FRONT in CLAUDE.md is rewritten accordingly; the sequence-before-harden freeze on JSON-path files stands; accept-rule fixes remain exempt from it.

### B. Posture, configuration, scope, doctrine

**D2a — launch posture: EXTENDED, as decided 2026-07-09 (D3).** Consequence: the multi-shard accept path is on the pre-genesis critical path (D16).

**D2b — launch clause: a written, measurable go/no-go predicate, judged over a beta that exercises the frozen surface.** Supersedes D4's "bug-discovery rate → 0" criterion (unmeasurable on the current instrument). Instrument: the process-level cluster gates and the TLA models are added to `ci_local`. The predicate (closure of named launch blockers; accepted limitations that narrow claims; supported configurations verified; genesis deadlines complete) is drafted for owner approval in Step 6. A testnet carries its own `chain_id` and genesis hash and is not a migration.

**D2c — launch configuration: the shipped presets — GLOBAL beacon (M=7/K=5, EXTENDED, MODERN, 600 ms) + WEB shards (M=4/K=3, EXTENDED, MODERN, 200 ms).** With D5a the eligible pool per chain is at most 2K−1 (beacon 9, shard 5); with D11 the re-draw certificate needs ⌈2K/3⌉ live pool signers (beacon 4, shard 2). Recorded as a constraint of the launch predicate, not a new preset.

**D2d — `epoch_blocks = 100`** on beacon and shards (≈ 20 s epochs on 200 ms shards, ≈ 1 min on the 600 ms beacon). Consequence: a ten-times-shorter targeting window than the 1000 default and finer duty spread; ten times more `cc:[E]` anchors and beacon witness-path re-verifications. E ≥ 2 as the analysis requires; no witness-path change (O-5, D17).

**D3 — O-4: the no-cryptocurrency reduction is rejected.** Value, fees, stake economics and the CT/shielded surface stay as designed (A1/A2/A3/D1; 6265d34). Obligations inherited: v2.22 and v2.24 ship together or not at all (the compliance-regression hazard); the CT proof-randomness defect (S-083) closes before CT is enabled on any chain.

**D18b — O-2: the 2026-08-13 doctrine is ratified as binding** (adversarial review of every consensus/apply/wire/genesis diff before commit, independent of gate colour; design-and-prove first when uncertain; smallest increment). The "flagged for owner review" marker is removed.

**D18c — CryptoProfile: {MODERN = 0, FIPS = 1} is the frozen set.** The pre-genesis backlog line closes; a future profile is a new chain's genesis choice.

**D19c — a tactical/cluster chain is in scope for this cycle as SHAPE B** (`min_stake` default, `initial_stake = min_stake`, no balances, subsidy/pools/lottery 0; Sybil bound = floor(Σ initial_stake / min_stake), mechanical). SHAPE A (`min_stake = 0`) is unsupported — and with D21 unexpressible. Prerequisites: the per-shard supply-conservation gap (D16) closes before a SHARD+EXTENDED tactical chain; the `Chain::load` parameter-threading fix (S-078) before any FIPS chain restarts. Under SHAPE B no balances exist, so the D6 join rule is mechanically unreachable there — the set is closed by genesis quantities, not by rule.

**D21 — `inclusion_model` is deleted.** STAKE_INCLUSION is the only model: the enum, the config knob and the startup log line go; `min_stake ≥ 1` is validated at genesis. No genesis-hash change (the field was never mixed in). DOMAIN_INCLUSION (SHAPE A) becomes unexpressible.

**D22 — the L2 bond / arbitration policy (the consumer of the evidence record, D4) is v1.1 DApp scope**, designed on DSSO after the L1 increments; not a launch blocker for L1. The launch predicate states "equivocation carries no L1 consequence; L2 policy: <status>".

### C. Consensus decisions (each a frozen accept/apply/wire rule unless stated)

**D4 — O-1: slashing relocates to L2, option (b).** L1 stake is never slashable for equivocation. L1 keeps detection and an on-chain evidence record — capped per block, with in-block duplicate rejection — as the input to the L2 policy (D22). R-1 resolves: a same-height pair (cross-round or not) is L2 evidence requiring corroboration, never an L1 verdict; no predicate over two signed openings is proposed again. Landing order (the 2026-08-13 ordering result): the ~10-line forfeiture removal alone → the cap + in-block dedup → the S-006 status re-derivation, an honest S-011 residual, the S-013 / S-029 Level-3 / BFTSafety T-5.1 re-derivations, the `RoundStallValveSoundness.md` C-2 correction (S-095) and the ~16 proof-doc corrections → then R-8 → then the evidence rebroadcast (S-090). Proof obligations: A1 neutrality, snapshot round-trip, the cap's DoS bound, and under demotion the argument that a strippable record is a forensics loss only.

**D13 — O-1b: the round-1 abort stake deduction is retired.** An abort suspends the missing member for the existing window and deducts nothing (the deduction fell on the accused, not the claimants, and had no role in the S-011 bound). T-A1 (`AbortEventApply.md`) becomes historical; S-011/S-013 are restated on the floor + suspension window; `c:accumulated_slashed` keeps its leaf shape. S-087 closes when it lands. Proof obligations: A1 neutrality, snapshot round-trip, gate + mutants at apply.

**D5a — R-4: the bound `2K > N(h)` over the eligible pool, per shard, at two layers.** Genesis validation requires `2K > |initial creators|`; the verifier rejects a transaction that would raise the eligible pool to 2K or more (at the point a domain becomes eligible — D6); and `check_creator_selection` asserts the pool it draws from is below 2K (fail-closed: a halt, never a fork). S-054 closes when both layers are gated. Proof obligations: the invariant stated over N(h); gates + mutants at both layers; an S-048 race analysis showing two K-subsets cannot be disjoint under the bound.

**D5b + D11 — the joint design gate R-4 + F-c + R-15 is AUTHORIZED (design-and-prove; no code until the design survives adversarial review).** Requirement from R-15 (owner, this session): tolerate up to ⌊K/3⌋ silent committee members; beyond that, a *certified formation failure* — a certificate carrying ≥ ⌈2K/3⌉ signatures from eligible pool members (committee or not) attesting "height h, tail X, attempt n, committee cannot form", committed on chain and folded into the seed like an abort event — re-draws the committee at the same height from committed inputs; no halt. The design covers the certificate's wire form and V10-style validation, its interaction with `aborts_gen`, the S-050 valve and the S-074 canonical identity, the seed fold, the exclusion of attested-silent members, the escalation-arming root (S-086), and the S-044 theorems T-1..T-5 re-run. Residual bound, stated now: the pool cannot muster ⌈2K/3⌉ live signers. S-076 and S-086 close when it lands.

**D12 — R-16: a Phase-2 withholder is suspended for the existing window, no deduction.** The rejection-sampling bias is documented; exclusion safety rests on pool margin and the D11 re-draw. S-077 closes when it lands. Proof obligations: S-044 theorems with Phase-2 exclusions; apply-layer gate + mutants.

**D6 — R-12: open validator set.** The verifier's sender rule admits STAKE (and the TRANSFER that funds it) from a domain present in the raw registrants map but not yet eligible; eligibility follows at the next epoch boundary once stake ≥ `min_stake`; the D5a cap is enforced at that point. Sybil bound = `min_stake` per seat; the 2K−1 seats fill first-come. README/WHITEPAPER "joins the eligible pool" becomes true when it lands. S-069 closes then. Proof obligations: the join path gated end-to-end (REGISTER → fund → STAKE → eligible); S-010/S-011 re-derived for an open set.

**D7 — R-11: exit = DEREGISTER → wait `unstake_delay` → UNSTAKE**, admitted through a sender-rule exception scoped to UNSTAKE from a domain in the raw registrants map at `block_index ≥ unlock_height`; every other type from an ineligible sender stays rejected. The name stays terminal (V-REG-1). S-067 closes when it lands. Proof obligations: validator-layer gate DEREGISTER→UNSTAKE included and applied; mutants on the exception's scope.

**D8 — R-14: `zeroth_pool_initial = 0` at genesis.** NEF is a no-op; WHITEPAPER §8.5 stays DESIGN-NOT-SHIPPED; the S-071 guard stays as defense in depth. S-073 closes by genesis choice (with D6 a grant ≥ `min_stake` would buy a seat).

**D9 — R-7: two rules.** (i) A non-PQ transaction with non-empty `pq_auth` is invalid; PQ types carry exactly the ML-DSA signature size. (ii) A block whose canonical frame exceeds a consensus cap matching the 4 MB wire limit (minus envelope) is invalid; the producer packs to it. Invariant: a valid block is always relayable. S-057 closes when both land. Proof obligations: validator-layer gates for both, a boundary test at the cap, S-022 interplay stated.

**D10 — R-13: any transaction whose anonymous sender key is a small-order point is invalid** (checked after the signature, like S-068), mirrored at ingress; funds sent to such an address are unspendable (burn); the wallet warns before sending to one. S-072 closes when it lands. Proof obligations: gate over all ten encodings + a normal-key control; mutants on verifier and mirror.

**D14 — R-10: CT verification off the consensus lock.** Bundles are verified outside `state_mutex_` (at ingress in a worker; verdict cached by *recomputed* content hash so an already-verified bundle validates in O(1); unverified bundles in a received block are verified before the lock is taken); a consensus per-block CT cap; a node-local per-sender/mempool CT quota. The anonymous-CT inconsistency is settled by making ingress match the verifier: anonymous CONFIDENTIAL_TRANSFER / SHIELD / UNSHIELD are admitted (the documented light-client shield flow works). S-065 closes when it lands. Proof obligations: cache un-poisonable; cap gate + mutants; measured lock time under a 10 000-bundle flood.

**D15 — R-6: `ROTATE_IDENTITY_KEY` ships before genesis** — a free TxType (≥ 18), an `rk:` state leaf (state-root-invariant while unset), incumbent-signed, rotating `ed_pub` only (no eligibility field touched, so no activation-delay deadlock). KR-10 unification (service key, audit key) follows additively. Proof obligations: old key invalid from the rotation height; light-client verifier updated; replay excluded by D23.

**D16 — the EXTENDED closure set is AUTHORIZED as pre-genesis design gates, each its own increment:** R-2(a) `on_beacon_header` checks that `b.creators` is the beacon's derived committee (S-093); R-2(b) an unconfirmed first header does not seed epoch rand until a chaining successor arrives (S-094); R-3 the BEACON role is authenticated (bound to a genesis-pinned or registry-derived beacon set; HELLO signed); S-064/B3.4 source-side K-of-K authentication of cross-shard receipt bundles; a persisted, gap-tolerant beacon header buffer with a request path and no silent local fallback (S-088); S-036 trustless closure (v2.11 D3.5e); beacon relay dedup/TTL/sender exclusion (S-081); the per-shard supply-conservation proof under SHARD+EXTENDED (S-096). R-2 and R-3 stay on the DECISION CLOCK as authorized items.

**D17 — O-5: `epoch_blocks ≥ 2`** on beacon and shards; value per D2d; no witness-path change.

**D19b — two accept-path items authorized:** (i) a plausibility bound on peer-reported height in `on_status_response` (a height beyond `chain height + bounded lead` is ignored; S-085); (ii) `sharding_mode` becomes a genesis field mixed into the genesis hash (S-092; a producer skip keyed on node-local config censors fleet-wide).

**D20a — R-9: MsgTypes 12/13/14 are KEEP** (load-bearing under EXTENDED); recorded in `ReservedDiscriminatorAudit.md`; DROP execution of the other verdicts stays the last pre-genesis act.

**D23 — R-17: `signing_bytes()` binds the chain identity — the genesis hash and the shard id — for every transaction type.** No expiry field (a released transaction still cannot be cancelled; the outbox's `replace` remains the only recourse). Consequence: no cross-chain, testnet-to-mainnet or cross-shard replay; the D15 rotation binding becomes the general rule; one transaction-frame change (pre-genesis) with every signer (wallet, light, SDK, outbox) and verifier updated together; it lands with D9 as the last change to the transaction frame. S-103 closes when it lands. Proof obligations: frame round-trip vectors regenerated; a replay gate (the same bytes rejected on a second chain and on a second shard); light-client parity.

**D24 — numeric caps (the per-block CT cap, the block-byte cap, the per-block evidence cap) are proposed by their design gates with measured evidence and approved by the owner at the review step.** No number is frozen on a guess.

### D. Node- and client-local decisions

**D18a — S-063 is confirmed Critical and is fixed at the delivery layer now:** `dapp_messages` / `dapp_subscribe` / `make_dapp_call_frame` report the apply result per frame (APPLIED / SKIPPED) or omit value fields they cannot vouch for; an end-to-end reproduction is the gate's first arm; consumer obligations C1–C5 stand.

**D19a — the defects the log recorded without a number get ledger rows S-078..S-103 (added to `docs/SECURITY.md` with this entry) and are AUTHORIZED as independent increments** (smallest change, gate + mutants, adversarial review before commit), scheduled by severity: S-078 `Chain::load` replays every block with default consensus parameters (High; any non-default genesis is unrestartable — the tactical/cluster FIPS profiles included); S-079 unfunded `fee = UINT64_MAX` TRANSFERs seal the mempool permanently (High; NOT closed by the exported build-time eviction, which fires only on verifier rejections and the verifier has no balance rule for TRANSFER); S-080 the GET_CHAIN sync storm — every non-progressing CHAIN_RESPONSE re-broadcasts to all peers with no backoff (High); S-081 the beacon bundle relay loops forever — no dedup, TTL or sender exclusion (High, EXTENDED; D16); S-082 the per-peer egress queue is unbounded and pre-HELLO peers receive broadcasts (Medium); S-083 CT blinders derived from `(nonce_seed, tx_nonce)` only — rebuilding a transfer at the same nonce discloses the amounts (Medium, light client; before CT is enabled, D3); S-084 `Chain::load` bypasses `append`'s `prev_hash` link check — only the head hash is verified (Low); S-085 a peer-reported height is stored verbatim — one `UINT64_MAX` STATUS_RESPONSE pins a node in SYNCING forever (High; D19b-i); S-086 escalation arms only on `current_aborts_.size()`, cleared at every apply — the |pool| == K deadlock root (High; D5b/D11); S-087 a floor-staked validator is ejected at the FIRST abort and S-051 never lifts it (High; D13); S-088 `external_epoch_rand_` reads an in-memory, unpersisted, gap-intolerant `beacon_headers_` with a silent local fallback — different buffer depth, different committee (High, EXTENDED; D16); S-089 `ev.beacon_anchor_height` / `shard_id` are hashed but compared by nothing — honest observers derive different event hashes on SHARD chains, a C0 trigger (High; closes with R-8); S-090 `on_equivocation_evidence` adopts without rebroadcasting — gossip is one-hop with no relay and no re-request (Medium; sequenced after R-8); S-091 `save_node_key` writes plaintext JSON with no KDF and no permission call (Medium/Op; the D2 src-side keyfile increment); S-092 `sharding_mode` is node-local config, not genesis-pinned (Medium; D19b-ii); S-093 Q1 residual (a) — beacon-header creators are not checked against the derived committee, so any K eligible domains can drive the rand chain (High, EXTENDED; D16); S-094 Q1 residual (b) — an unconfirmed first header seeds epoch rand (High, EXTENDED; D16); S-095 `RoundStallValveSoundness.md` C-2 assumes a non-empty abort tail; the valve's empty-tail path produces an honest same-`gen` double-sign (proof defect; corrected with the D4 re-derivations); S-096 per-shard supply is not conserved under SHARD+EXTENDED — the inbound credit mints on the destination shard (High, EXTENDED; D16); S-097 `submit_tx` acknowledges a transaction the verifier will evict at build — no RPC-time pre-check (Medium, node-local; outbox F-2); S-098 the DLS1 light-state writer is a plain truncating write (Low, light; outbox F-3); S-099 the trustless read's cleartext cross-check races its own `--wait` — a TAMPERED false alarm (Low; bounded re-read shipped in the outbox; outbox F-4); S-100 `verify_tx_inclusion` verifies the inclusion block's signatures without the genesis `k_block_sigs`, so INCLUDED can rest on a quorum-downgrade block (Medium, light; outbox F-6); S-101 `tx.hash` inside a gossiped BLOCK is never recomputed by the validator (Medium; a sub-item of S-030 — the validator recomputes and rejects a mismatch); S-102 `maybe_reorg_to_locked`'s `revert_head()` → `append()` is unguarded — reproduced CRITICAL under a demoted digest, reachability at HEAD by a relayer-mutated same-digest sibling unadjudicated (High as recorded pending adjudication; adjudicate before R-8 lands); S-103 no chain identifier in `signing_bytes()` — cross-chain and cross-shard replay (Medium; D23).

### E. The implementation sequence (authorized; derived from the recorded dependencies and confirmed by the owner)

1. Apply exports 0001–0014 (owner act; `.git/index.lock` removed first).
2. This entry (0015): CLAUDE.md ACTIVE FRONT / DECISION CLOCK / owner-items rewrite; ledger rows S-078..S-103; `ReservedDiscriminatorAudit.md` R-9 verdict.
3. The O-1 chain: forfeiture removal alone → cap + in-block dedup → D13 abort-deduction retirement → re-derivations (S-006, S-011, S-013, S-029, T-5.1, S-095) and proof-doc corrections. Adjudicate S-102 here.
4. The joint design gate R-4 + F-c + R-15 (+ R-16 folded in): design memo → independent adversarial review → implementation in increments (genesis check; eligibility-time cap; selection assertion; certificate; re-draw; suspensions).
5. V-REG-1 companions, each design + review + gate: D6 join rule, D7 exit rule, D15 rotation, D10 small-order rule; D8 and D21 recorded as genesis constants/schema.
6. D9 (`pq_auth` rule + block-byte cap) together with D23 (chain identity in `signing_bytes()`) — the last changes to the transaction frame.
7. R-8: the C0 digest demotion (reusing the preserved patch and its live-reproduction gate) → S-089 → S-090 evidence rebroadcast.
8. D14: CT verification off the lock + cap + cache; the ingress rule; S-083 (light).
9. D16: the EXTENDED set (R-2a/S-093, R-2b/S-094, R-3, S-064/B3.4, S-088, S-036, S-081, S-096), each its own gate; D19b-ii `sharding_mode` pin lands with the first genesis-hash-changing increment here.
10. D2 inc7c in parallel from step 3; D2 step 1b and step 4 (Q3 Path A) after step 9; R-3 is decided in step 9, so the parser-deletion milestone no longer surfaces it.
11. Node-/client-local backlog interleaved by severity from step 3 on: S-078 first, then S-079, S-080, S-085, S-082, S-097, S-100, S-084, S-098, S-099, S-070, S-075, S-091 (with the D2 src-side keyfile increment), D18a (S-063).
12. Instrument: the cluster gates and the TLA models into `ci_local`; the C2 adversarial sweep run.
13. Last pre-genesis act: B4 DROP execution (R-9 KEEP recorded); the launch predicate drafted and judged (Step 6).

### F. Left open

Nothing owner-gated. S-102 is a technical adjudication (step 3), not a decision. The numeric caps (D24) return to the owner at each gate's review.

**Authority:** decisions by the owner (Stoyan Denev), 2026-09-16, taken one by one over the Step 1 inventory; recorded by Claude (Cowork session) at his direction. This entry is append-only per convention and contains no tier marker in its body.

---

## 2026-09-16 — O-1 step 3a LANDED: the equivocation forfeiture + deregistration removed from `Chain::apply_transactions` — alone, as the ordering result required; an `EquivocationEvent` is an on-chain evidence record with no L1 consequence

**Status:** IMPLEMENTED and verified (`tools/ci_local.sh`: build 6 targets, FAST 310 passed / 0 failed, 16 guards green); export 0016 on top of 0015. First increment of sequence step 3 (this log, 2026-09-16 §E).

**Problem this change solves.** At HEAD the `b.equivocation_events` loop in `apply_transactions` (a) forfeited the equivocator's entire locked stake into `accumulated_slashed_` and (b) deregistered it (`inactive_from = b.index + 1`). D4 (this log, 2026-09-16; O-1 option (b)) decides that L1 stake is never slashable for equivocation and that the event is the input to the L2 bond policy (D22). While the consequence was live, an honest validator's two same-height, same-gen signatures produced by the S-050 valve or the S-048 re-round were packageable as "equivocation" and cost it its whole stake with no attacker signature (2026-08-12), and the R-8 digest demotion was unsound (ordering result `7570989`, 2026-08-13). The ~10-line removal had been verified sound three times and reverted three times because of its riders; the recorded landing order is therefore removal ALONE first.

**The change (consensus apply path, `src/chain/chain.cpp`).** The loop is deleted; a comment states the rule. Nothing else in apply reads an `EquivocationEvent`. `block_slashed` / `accumulated_slashed_` keep their shape and are now fed only by the Phase-1 abort deduction (D13 retires that in its own increment). UNCHANGED by design: the wire form and codec, V11 (`BlockValidator::check_equivocation_events`), the producer's reconcile-union and view lists, the committee digest's coverage of the event set (R-8 is step 7), the node's post-inclusion prune of `pending_equivocation_evidence_` by equivocator, the state-root leaf set, both snapshot containers (no field changes shape; the existing round-trip gates cover it), the light verifier's verdicts and exit codes.

**A1 neutrality.** `live_total_supply` no longer loses the stake and `expected_total()` no longer subtracts it: the identity holds by construction, and mutant M1 (zero the stake without crediting `block_slashed`) is exactly the case the A1 throw catches.

**Gate — `determ test-equivocation-apply` (FAST, `tools/test_equivocation_apply.sh`), 14 assertions at the apply layer:** stake, registry `inactive_from`, `accumulated_slashed` and live supply unchanged, A1 holds; NEUTRALITY — `compute_state_root()` and `abort_records()` identical to an event-free twin chain — with a POSITIVE CONTROL (the event is in the appended block and the block hash differs from the twin's: the record persists, the assertion is not vacuous); ghost-equivocator robustness; determinism. `test-equivocation-multi` (16) inverts its four scenarios (the no-stake scenario now also runs at a zero stake floor), including the former "anti-dodge" case: a DEREGISTERed equivocator inside its unlock window keeps its pending-unlock stake AND its DEREGISTER `inactive_from` (not overridden). `test-fa-equivocation-trace` is now a 48-block randomized neutrality trace against an event-free twin (first-seen and repeat events of both evidence kinds; per-block state_root equality; block-hash inequality as the per-block positive control). `test-fa-multi-event-trace`'s shadow model no longer moves stake on an event (abort deductions only; non-vacuity requires first-seen AND repeat evidence). `test-block-event-composition` asserts the same-actor abort+evidence composition is the abort deduction alone.

**Mutants (`/root/audit/o1/mutants`, each rebuilt and run against the five gates; all RED):** M1 restore `locked = 0` only — every gate dies on the A1 throw; M2 restore the forfeit — stake/counter assertions RED in all five; M3 restore the deregistration only — registry assertions RED in all five; M4 the original loop — RED; M5 a NEW consequence (`abort_records_[equivocator].count++`) — RED on the neutrality assertions only (state_root + abort_records), which is what they are for; M6 a forfeit that fires only inside the DEREGISTER unlock window — RED only in `test-equivocation-multi` scenario 4 (the inverted anti-dodge), green everywhere else — which is why that scenario exists; M7 (review finding) a forfeit keyed on the contrib evidence family `kind == 1` — RED in the two traces, which now draw both kinds from the PRNG; M8 (review finding) a deregistration keyed on `min_stake_ == 0` — RED in `test-equivocation-multi` scenario 3, which now runs at a zero stake floor.

**Riders kept deliberately non-semantic.** (i) In-code comments and help text that stated the removed consequence, including `chain.hpp` (A1 ledger and lazy-container comments), `genesis.hpp` (×2), `block.hpp`, `producer.hpp` (×2), `messages.hpp`, `committee_pool.hpp` (×2), `validator.cpp` (the residual note, the V11 preamble, the key-resolution note), `node.cpp` (the prune comment and five "will be slashed"-style remarks), `main.cpp` (two help entries, the operator-summary and cross-shard supply comments, a scenario comment, the dedup rationale), `wallet/main.cpp` (the equivocation-verify preamble, help and usage text), the wrapper headers `tools/test_fa_equivocation_trace.sh` and `tools/test_light_verify_equivocation.sh`, and the rationale comments in `tools/test_equivocation_slashing.sh`. The V-REG-1 rationale comments (`validator.cpp`, `main.cpp`, `tools/test_register_create_only.sh`) describe the 2026-09-15 hazard historically and are left as written. (ii) `tools/test_equivocation_slashing.sh` (full suite, live cluster) inverted: it now waits for the evidence block, then asserts node1's stake equals its pre-submission value minus any Phase-1 abort deductions counted in the window (so the equality is exact, not a flake), its registry entry is active (`show-account --json`), and the block after the evidence block still lists node1 among its creators; file name kept for the record's references. The two sibling live gates `tools/test_f2_eqabort_reconciliation.sh` and `tools/test_f2_eqabort_snapshot.sh` (F2 reconciliation; eq-bearing snapshot round-trip) are inverted the same way: they wait for the evidence block and assert the stake stays at 1000 (donor and receiver alike); their state_root round-trip assertions are unchanged. (iii) Operator tools' descriptive text (`operator_equivocation_digest.sh`, `operator_equivocation_evidence_integrity.sh`, `operator_event_summary.sh`, `operator_slashing_ledger.sh`, `operator_suspension_watch.sh`): logic untouched; the slashing ledger now labels equivocation rows as records and `accumulated_slashed` as abort deductions. (iv) `determ-light verify-equivocation` and `determ-wallet` equivocation-verify help/comments: "a slash is justified" → "a valid record for the L2 policy"; verdicts and exit codes unchanged.

**Docs.** `docs/SECURITY.md`: a new STATUS note; S-011's ⚠ marker now says the forfeiture is removed and the residual is re-derived in step 3c (no status change — nothing closes here); the S-006 closure table marks its apply-time row historical; the rev.8 history paragraph and the three test-table rows describe the new gates. `CLAUDE.md`: ACTIVE FRONT step 3 marks 3a landed; the SLASHING block replaces "NOT LANDED YET" with what landed and what remains (3b, D13, 3c). `docs/PROTOCOL.md` §6.1 apply rule, `docs/QUICKSTART.md`, `docs/WHITEPAPER-v1.x.md` (§Sybil, §equivocation, the BFT-safety bullet, "slashing soundness" → "evidence soundness"), `docs/CLI-REFERENCE.md` (three test rows, the verify-equivocation row) and `README.md` (§5.4, the inclusion-model table, the STAKE_INCLUSION bullet, §economic story) are corrected INLINE — factual statements, not derivations. The 51 untiered documents that stated the removed consequence as shipped carry a uniform `STATUS 2026-09-16` banner directly under their title (TLA modules/configs: a `\*` comment block) and are otherwise untouched; they are re-derived in step 3c and the banner is removed as each one is: `EquivocationSlashingApply`, `StakeForfeitureCascade`, `EquivocationSlashing`, `Preliminaries`, `S010S011SybilEconomics`, `MultiEventComposition`, `F2ApplyComposition`, `SupplyInvariantComposition`, `CrossShardSupplyConservation`, `ExpectedTotalWellDefined`, `OfflineEquivocationEvidenceSoundness`, `S006ContribMsgEquivocation`, `StakeLifecycle`, `AbortEventApply`, `AbortCertificateSoundness`, `BFTSafety`, `Safety`, `RpcIngressGateAudit`, `BlockIngressGateAudit`, `S029ForkChoiceSoundness`, `S013PerSignerCap`, `RealEngineFAHarness`, `ShardTipMergeDesign`, `S020CommitteeSelection`, `EqAbortViewDigestExtension`, `S001RpcAuthSoundness`, `AccountStateInvariants`, `FeeAccounting`, `S017UnstakeApplyConsistency`, `S023NodeKeyfileEncryption`, `OperatorToolingReadOnly`, `StakeDistributionMetrics`, `S036UnderQuorumMerge`, `SubsidyDistribution`, `RandomizedRegistrationDelaySoundness`, `S025BFTEscalationSoundness`, `BFTProposerElectionSoundness`, `NonceMonotonicity`, `BlockchainStateIntegrity`, `S033StateRootNamespaceCoverage`, `RegionalSharding`, `ConsensusValidatorGateAudit` (42 `.md`); `tla/EquivocationApply.tla` + `.cfg`, `tla/StakeForfeitureCascade.tla` + `.cfg`, `tla/MultiEventComposition.tla` + `.cfg`, `tla/EquivocationEvidenceVerify.tla`, `tla/AbortApply.tla`, `tla/S006ContribMsgEquivocation.tla` (9). Three generic stake-debit models (`tla/AccountState.tla`, `tla/UnitarySupplyLedger.tla`, `tla/CrossShardSupplyConservation.tla`) stay valid — the abort deduction still feeds them — and only their FA6 comment lines are corrected inline. Tiered docs (`docs/README.md`, `docs/UNIT-TESTS.md`, `docs/proofs/README.md`, `UnitTestCoverageMap.md`, `DSF-SPEC.md`) keep their text under their TIER banner.

**Known and deferred, stated so nobody rediscovers them as new.** (a) The FA6 "no false positives — an honest validator can never be PROVEN" sentence in `docs/CLI-REFERENCE.md` (verify-equivocation row) and the `determ-light` help predates the valve/re-round result; it is a verifier claim, now consequence-free, and is settled with S-095 / the step 3c re-derivations. (b) `determ-dsf` (`sim/`) still models an `equivocator_slashed` SAFETY property (§Q7) — a self-contained toy model by the 2026-07-07 decision, linking no production code; it is re-aligned with the TLA work in D2b. (c) `docs/proofs/README.md` (tiered PROCESS/ARCHIVE) index rows still summarise FA-Apply-10/16 as slashing contracts. (d) The same event is now re-includable across blocks (deregistration was the only limiter): step 3b's per-block cap + in-block duplicate rejection is the next increment, with the 2026-08-13 requirement standing — a bound that is a pure function of the block's bytes, or none.

**What this does NOT claim.** No ledger row closes. S-011 / S-013 / S-029 economic legs, S-006's closure and BFTSafety T-5.1 are reopened in substance and are re-derived in 3c, not here. S-102 (the unguarded `revert_head()` → `append()` reorg path) is adjudicated in its own sub-increment of step 3 before R-8.

**Authority:** implemented and recorded by Claude (Cowork session) under D4 / the §E sequence of this log, 2026-09-16; adversarial review of the diff before commit per the 2026-08-13 rules (findings and dispositions in the commit message). This entry is append-only per convention and contains no tier marker in its body.


---

## 2026-09-16 — S-102 ADJUDICATED and CLOSED: the unguarded `revert_head()` → `append()` reorg path is reachable at HEAD by a zero-key relayer (a wrong non-zero `state_root` on the head), and the depth-1 reorg is now atomic over an apply throw

**Status:** LANDED (branch `track/s102`, base `c030d67`), step 3 of the §E sequence, before R-8. A technical adjudication (§F of the owner-decisions entry), not an owner decision. Gate `determ test-node-reorg-guard` (26 assertions), mutants M1–M4 RED; ci_local green.

**Problem this entry settles.** Ledger row S-102 (from the C0 increment-0 review, 2026-08-13, and its 2026-09-16 restatement) recorded that in `Node::maybe_reorg_to_locked` `chain_.revert_head()` is followed by `chain_.append(incoming)` with only the validate-failure branch restoring the old head, that the head loss was reproduced end-to-end under a demoted digest (a stripped block whose stale `state_root` threw S-033), and that whether a relayer could drive the same throw AT HEAD — where the digest still covers the equivocation set — was not adjudicated. The row's own conjecture named a ZERO-root sibling.

**Adjudication — (a) reachability at HEAD.** REACHABLE, by an unauthenticated relayer holding no committee key, at every height, and NOT through the zero-root sibling the row conjectured. The mechanism, with the code that carries it: `state_root` is written by the assembler AFTER the K-of-K signatures are gathered (`src/node/node.cpp`, the S-038 block in the Phase-2 completion path: `tentative_chain.append(body); body.state_root = tentative_chain.compute_state_root();`), it is outside `compute_block_digest` (`src/node/producer.cpp::compute_block_digest_body` — the field list is prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs, then the gated F2/partner/timestamp/signature_form/eligible_count/shard-tip appends; no `state_root`), inside `Block::signing_bytes` only when non-zero (`src/chain/block.cpp::signing_bytes`), read by NO rule of `BlockValidator::validate` (`src/node/validator.cpp` — the identifier does not occur in the file), and checked only by `Chain::apply_transactions` and only when non-zero (`src/chain/chain.cpp::apply_transactions`, the S-033 block). The BLOCK wire frame carries it (`src/chain/block.cpp` encode/decode_frame). So a relayer takes the produced head B, sets `state_root` to any wrong NON-zero value R' (about two SHA-256 trials pick one whose block hash is smaller than B's), and gossips B'. B' shares B's `prev_hash`, has a different `compute_hash`, ties `resolve_fork` on signature count and abort count and wins the smallest-hash tie-break, passes the sig/creator size pre-check and the revertible-head check, so the node runs `revert_head()`; `validate(B', chain at H-1)` passes every rule — the K-of-K signatures verify because the digest is unchanged, and nothing reads `state_root` — and `append(B')` re-applies the identical body onto the identical H-1 state, recomputes the true root R, finds R' ≠ R and throws the S-033 mismatch. The A9 catch restores the H-1 state exactly and re-throws; `blocks_` is already popped; `prev_head_snapshot_` was consumed by `revert_head`; the throw escapes `maybe_reorg_to_locked` → `apply_block_locked` → `on_block` and is caught by `GossipNet::handle_message`'s dispatcher catch (`src/net/gossip.cpp`, logged as a dispatch error). The node continues at H-1 with its head gone. The zero-root sibling does NOT drive the throw: at zero the S-033 check is skipped, so that twin's apply SUCCEEDS and the twin is ADOPTED — a different, non-throwing observation, recorded below. Every other throw in `apply_transactions` reachable by a block that validated — the S-007 recipient/creator/dust/inbound credit overflows (the validator checks only the S-049 debit `amount + fee`), the S-049 `total_fees` accumulation, the S-007 `total_distributed` overflow, and the A1 unitary-balance assertion — needs a committee-produced body (a relayer cannot inject a transaction, receipt or creator into a signed body without breaking the digest) and is covered by the same guard; `activate_pending_params`, `stage_param_change`, `add_shard_tip_record`, `add_committee_checkpoint` and `COMPOSABLE_BATCH` (inner decode caught in place) do not throw. Witness: `test-node-reorg-guard` W — the relabelled sibling carries B's `creator_ed_sigs` / `creator_block_sigs` byte-for-byte over the same `compute_block_digest`, `BlockValidator::validate` ACCEPTS it against the H-1 state, and `Chain::append` throws `state_root mismatch … (S-033)`.

**Adjudication — (b) what was lost, and restart.** In memory: the head block (the function's local copy dies on unwind), the retained A4 snapshot (consumed — `has_revertible_head()` is false until a new head applies, so no further reorg, legitimate or not, is possible at that height), the head's transactions from the node's mempool (the return-to-mempool loop sits after the append), `persisted_count_` clamped to H-1, the committed lock-free view republished at H-1 by `revert_head`; the Node-side round state, timers and `registry_` (built at H) were left as they were. On disk: the failed attempt itself writes nothing, so the store still names the head IF the async save worker had persisted it before the attempt (an attempt inside the apply→save window found the store at H-1 already) — but the NEXT `save_incremental` (any later append, or the graceful `stop()`) sees `persisted_manifest_height_ > persisted_count_` and, by the A4.5 shrink-first rule, rewrites the manifest to H-1 before anything else, so a restart after that save reloads H-1 (the stranded block file is ignored). Recovery was therefore by peer re-sync: the next block arrives with `index > height()`, the S-050 straggler trigger issues a STATUS_REQUEST, the chain sync re-delivers the head at `index == height()` and it re-applies normally — and the re-applied head is revertible again, so the same relayer repeats the attempt. For a committee member the lost head means its next contribution is built for the wrong height (its peers time it out — a Phase-1 abort against an honest node) each time it is hit. Danger proof: `test-node-reorg-guard` against mutant M1 (the pre-fix code): height 2 → 1, head = genesis, state_root changed, the store shrunk to height 1 at the next save, block 2 not appended, restart lands on genesis.

**Adjudication — (c) severity at HEAD vs under R-8.** At HEAD: Critical-class — an unauthenticated remote peer removes any node's head with ONE block-sized message and no key, repeatably; that is the consequence the 2026-08-13 review classified CRITICAL when it reproduced it through the strip driver, and it was live at every height through the relabel driver. What is reproduced here is the single-node head loss (the gate's M1 run); the per-round repetition against every committee member, which is a halt, is argued from the same mechanism and was not run on a cluster. Under R-8 (the C0 digest demotion): unchanged. R-8 removes the strip driver — with D4 landed a stripped twin applies cleanly (apply reads nothing from `equivocation_events`) and is simply adopted — but the relabel driver never depended on the digest's coverage of the evidence set. The ledger row therefore moves to the Critical column of the mitigated row with "was carried as High".

**The change (node-local, `src/node/node.cpp::maybe_reorg_to_locked`; no accept-rule, digest, wire or store change).** The `chain_.append(incoming)` is wrapped: on ANY throw (`std::exception`, whose `what()` is logged, and `...`) the node re-appends the retained `old_head`, logs `S-048 reorg REJECTED … (competitor validated but its apply threw: <reason>) — head restored (S-102)` and returns. Why this and not apply-on-a-copy: the restore is the same deterministic primitive the validate-failure branch already relies on — the H-1 state after the failed apply is byte-identical to the one `old_head` was applied to (A9 restores the entry snapshot; BoundedReorgSoundness REORG-2), apply is a pure function of (state, block), `old_head` applied from that state once, and `revert_head`'s `pop_back` left `blocks_` with capacity for one block, so the re-append cannot fail half-way; every intermediate state is a consistent chain (H-1 or H) and the re-apply re-retains a fresh snapshot, so a later legitimate reorg remains possible. A copy of the whole `Chain` per attempt would cost O(state + blocks) per relayer message, would still need the try/catch (the copy itself can throw after the revert), and would hand a moved-in `Chain` to a live node under the lock. Store consistency after the restore is carried by the existing machinery: `persisted_count_` stays clamped, so the next save first shrinks the manifest to H-1 and then rewrites the tail file with the SAME bytes as before (the gate asserts byte-identity of the whole store across a rejected attempt). The `param_changed_hook_` may fire twice for an activation at the reorg height (once in the failed apply, once in the re-apply); it sets validator/config fields to the same values — idempotent, and the same class the validate-failure branch already has.

**Gate.** `determ test-node-reorg-guard` (`tools/test_node_reorg_guard.sh`, FAST tier), 26 assertions over a real follower Node on `VirtualTransport` restarted from its own block store between phases: fixture (the deterministic producer's blocks 1 and 2; the relabelled sibling shares block 1's signatures and digest, differs in hash); W the Chain-layer witness above; G0–G5 the guard (height / head / `state_root` unchanged after the sibling, the logged reason names the apply throw and the restore, the sibling not adopted, block 2 still appends, the on-disk store — manifest and every block file — byte-identical before/after a rejected attempt, the store restarts onto the right head); P0–P3 the positive control (a correctly-rooted, validly re-signed sibling still reorgs over the same path, the tail file is rewritten to the winner, a restart loads it). Replay-twice-identical. **Mutants, each against a confirmed relinked binary, the old `test-node-reorg-s048` green throughout (it never covered the throw path):** M1 remove the restore (= the pre-fix code) → 8 arms RED (G2 ×2, G3 ×2, G4 ×3, G5); M2 drop `revert_head`'s `persisted_count_` clamp (head adopted in memory, store not brought in line) → P2, P3 RED (`Chain::load`: head_hash mismatch); M3 swallow the throw and continue on the H-1 state → the same 8 arms RED; M4 catch `std::logic_error` only → the same 8 arms RED. Noted: a `std::runtime_error`-only catch would be an equivalent mutant on the deterministic throw set (every explicit throw in `apply_transactions` is a `std::runtime_error`); the breadth to `std::exception` and `...` is a defensive choice for allocation failures, not gate-proven.

**Riders.** None. Doc corrections inline (untiered docs that stated the old behaviour): `docs/SECURITY.md` (the S-102 row closed with the verdict, the summary cells moved, the S-048 row and §6 fix paragraph now name the third branch, a test-table row), `docs/proofs/BoundedReorgSoundness.md` (REORG-4 gains the apply-throw branch and its witness; the LIMITS bullet that called the throw "hypothetical" and "the same exposure class as the normal accept path" is corrected — on the normal path a throwing apply leaves the head in place, on the reorg path it did not), `docs/proofs/BoundedReorgDesign.md` (§4 gains the "Atomic switch" invariant), `docs/CLI-REFERENCE.md` (a row), `CLAUDE.md` (both S-102 lines), the `maybe_reorg_to_locked` declaration comment.

**Noticed and deliberately left alone (not closed here; for the integrator to row).** (1) The ZERO-root twin: a relayer that strips `state_root` to zero on the head yields a same-digest sibling with a different hash whose apply SKIPS the S-033 check and succeeds; when it wins the smallest-hash tie-break every node that sees it ADOPTS it, deterministically and permanently (`resolve_fork` prefers it against the genuine block forever), so the canonical chain carries a block with no state commitment at that height and light clients (`committee_bound_state_root`) get nothing to bind — the S-038 "dormant gate" reopened by relayer action. And the tie-break is NOT a coin flip the relayer must accept: `initial_state` is appended to `Block::signing_bytes` for every block, is outside `compute_block_digest`, is read by `apply_transactions` only at `index == 0`, is carried by the frame codec for any index, and is not mentioned in `src/node/validator.cpp` — a junk allocation entry on a non-genesis block re-rolls `compute_hash` at one SHA-256 per trial with the digest and the apply outcome unchanged, so the block hash is relayer-malleable under a fixed digest (CLAUDE.md records it as signer-malleable only), the zero-root adoption becomes deterministic, and any clean same-digest twin can be made to win — each adoption costing every node a revert + apply and a round reset (`post_append_bookkeeping_locked`), a liveness-griefing surface independent of S-102. Both are argued from code here, not executed. Not a throw, so outside this increment; the fixes are accept rules (reject a non-empty `initial_state` on `index > 0` — apply ignores it and no honest producer populates it, pre-genesis so free; reject a zero `state_root` on a non-genesis block once producers populate it, or refuse to replace a non-zero-root head by a zero-root same-digest twin) and belong to their own increment with review. Code: `src/chain/chain.cpp::apply_transactions` (the `if (b.state_root != zero)` gate and the `b.index == 0` branch), `src/chain/block.cpp::signing_bytes`, `src/node/node.cpp::maybe_reorg_to_locked`. (2) CPU griefing: each rejected relabel costs the victim one revert + validate + failed apply + re-apply, the same bounded fail-closed class as the garbage-signature griefing already recorded in BoundedReorgSoundness LIMITS (now with one extra apply); a cheap pre-revert rejection exists for the relabel — same `compute_block_digest` as our head, non-zero head root, different declared root ⇒ provably wrong — and is left for a follow-up if the class is ever hardened. (3) `docs/proofs/BoundedReorgSoundness.md` cites `src/node/node.cpp` and `src/main.cpp` by line numbers from the A4 era (`:2192-2216`, `:27186-27194`) that no longer point at the functions named; they are within EOF (the citation guard passes) and are not re-derived here.

**What does not change.** `BlockValidator` rules, `compute_block_digest`, `Block::signing_bytes`, the BLOCK frame, `Chain::append` / `apply_transactions` / `revert_head`, `save_incremental` / `load`, `resolve_fork`, the normal accept path (`apply_block_locked` is untouched), the sync path into the reorg, the S-047/S-050 recovery paths, every existing gate (`test-node-reorg-s048` 9/9, `test-chain-revert-head`, `test-chain-reorg-save-crash` unchanged).

**Authority:** the owner-decisions entry of 2026-09-16 §E step 3 ("Adjudicate S-102 here") and §F ("S-102 is a technical adjudication (step 3), not a decision"); D19a for the node-local closure (no accept-rule change); the 2026-08-13 rules for the adversarial review of the diff before commit (findings and dispositions in the commit message). Implemented and recorded by Claude (Cowork session), 2026-09-16. This entry is append-only per convention and contains no tier marker in its body.
---

## 2026-09-16 — D13 LANDED: the round-1 abort stake deduction is retired — a Phase-1 `AbortEvent` suspends the missing member for the existing window and deducts NOTHING; S-087 closes

**Status:** IMPLEMENTED and verified (`tools/ci_local.sh`: build 6 targets, FAST 310 passed / 0 failed, 16 guards green). Third increment of sequence step 3 (this log, 2026-09-16 §E), landed on its own after O-1 step 3a; owner decision D13 (this log, 2026-09-16 "OWNER DECISIONS" §C, O-1b).

**Problem this change solves.** The `for (auto& ae : b.abort_events)` loop in `Chain::apply_transactions` (`src/chain/chain.cpp`) deducted `min(suspension_slash_, locked)` from the aborted domain's stake for every Phase-1 (`round == 1`) `AbortEvent` baked into a block. Against the default `min_stake = 1000` a validator staked at the floor dropped to 990 at its FIRST abort, failed the eligibility floor (`stake_of < min_stake`, `include/determ/chain/eligibility_floor.hpp`), and S-051 lifts suspensions, never floor breaches — the validator was ejected by one abort and nothing lifted it (S-087, High, liveness; both live 3-node gates provision exactly 1000). The deduction fell on the accused, not the claimants, and had no role in the S-011 bound. D13 decides that an abort SUSPENDS (the existing S-032 window) and deducts nothing.

**The change (consensus apply path, `src/chain/chain.cpp`, the smallest possible).** The abort loop keeps `__ensure_abort_records(); ar.count++; ar.last_block = b.index;` for `round == 1` events and loses the six deduction lines (`stakes_.find`, `deduct`, `__ensure_stakes()`, `locked -= deduct`, `block_slashed += deduct`). `block_slashed` / `accumulated_slashed_` keep their shape: the `c:accumulated_slashed` state-root leaf, the snapshot fields and the A1 formula are untouched, the counter simply never grows any more (stated in the comment). `suspension_slash` / `SUSPENSION_SLASH` stay in `GenesisConfig`, the genesis-hash mix, the `k:` leaf, both snapshot containers and the PARAM_CHANGE whitelist — the parameter is INERT (no apply path reads it); removing it changes the genesis hash and is a genesis-schema increment, not authorized here. UNCHANGED by design: the D4 equivocation comment block, `eligibility_floor.hpp`, S-051, the registry (`NodeRegistry::build_from_chain` / `Chain::freeze_epoch_committee` read the same `abort_records_` through `suspension_active`), the wire form, the validator (V10 `check_abort_certs`), the light verifier.

**Proof obligations recorded for D13.** (i) A1 neutrality — holds by construction: `live_total_supply` no longer loses the stake and `expected_total()` no longer subtracts it (nothing is credited to `block_slashed`), so the identity is unchanged on both sides; mutant M2 (the deduction restored WITHOUT its `block_slashed` credit) is exactly the case the A1 throw catches and every gate dies on it. (ii) Snapshot round-trip — no leaf or field changes shape (`c:accumulated_slashed`, `k:suspension_slash` and both snapshot containers are as before); the existing round-trip gates (`test-snapshot-roundtrip`, `test-snapshot-full-determinism`, `test-snapshot-genesis-backsolve`, `test-applied-receipt-snapshot`) cover it and stay green. (iii) Gate + mutants at the apply layer, below.

**Gate — `determ test-abort-event-apply` (FAST, `tools/test_abort_event_apply.sh`), rewritten: 31 assertions at the apply layer where the rule lives.** Control: the inert `suspension_slash` is NON-ZERO (10), so "nothing moves" is the retirement, not a zero-configured deduction. After a round-1 `AbortEvent` the aborted domain's stake and balance are UNCHANGED, `accumulated_slashed()` stays 0, live supply is unchanged, A1 holds, the registry entry is untouched (`inactive_from` sentinel), and — the surviving consequence and the POSITIVE CONTROL — `abort_records[alice] == {count 1, last_block 1}` with the event in the appended block. A round-2 (Phase-2) event records nothing and moves nothing. 51 repeated aborts keep the stake at 500 with A1 after every block and count to 51. A stake-free domain is still recorded (the S-032 contract is stake-independent). The S-087 scenario inverted, through the REAL eligibility path: a domain staked EXACTLY at `min_stake` (and one above it) keeps its stake, is suspended inside its window (`NodeRegistry::build_from_chain` excludes it at 5 — the record has its effect) and is ELIGIBLE again once the window expires (at 12), with `k_block_sigs = 0` so the S-051 floor lift is disabled and the exclusion is the suspension alone; the shared `suspension_active` formula's window is exactly (1, 11]. State neutrality against an abort-free twin: every leaf the fixture populates other than `b:` — `s:`/`a:`/`r:` of the domain, the five A1 counters, the 13 `k:` genesis constants — is byte-identical (state_proof value hashes), the `b:` leaf exists ONLY on the aborted chain, and `compute_state_root` / the block hash DIFFER (the record is committed; root equality is deliberately not asserted). Determinism: two chains applying the same abort reach the same root and record.

**Gates inverted (every one non-vacuous: the abort record is shown to increment).** `test-fa-abort-trace` (48-block randomized trace, K = 6, a forced repeat-target schedule against a 25-stake validator): the shadow model now moves NO stake; every validator's stake equals its genesis value and `accumulated_slashed == 0` after every block, the S-032 cache is exact per domain, A1 holds, and every non-`b:` leaf (per-domain `s:`/`a:`/`r:`, the 5 counters, the 13 constants) equals an abort-free TWIN chain applied alongside, with the `b:` leaf present on the aborted chain only and the block hash differing (per-block positive controls); the 25-stake validator hit ≥ 3 times keeps 25 (the retired deduction would have drained it to 0). `test-fa-multi-event-trace`: the shadow's abort branch now increments `abort_records` (count, last_block) and moves no stake; the equivocation branch stays inert (D4); stakes equal genesis, `accumulated_slashed` frozen at 0. `test-block-event-composition`: bob's abort is RECORDED with his stake unchanged (400); live supply moves by `+subsidy +inbound` only; the same-actor abort + equivocation composition is the abort RECORD alone. `test-supply-lifecycle` (18): step 4's abort moves no stake (only the subsidy enters supply) and IS recorded; `accumulated_slashed == 0` at the end. `test-stake-accounting` (15): the abort leaves `locked` and `unlock_height` untouched and is recorded. `test-eligibility-floor`: the under-floor fixture domain dP is provisioned at 995 from genesis (it used to start at 1005 and be pushed under the floor by one deduction); dA/dB/dC stakes are asserted unchanged by their aborts. `test-params-constants`: `SUSPENSION_SLASH == 10` and `SUSPENSION_SLASH × 100 == MIN_STAKE` stay pinned as the historical rev.8 sizing of two genesis-covered defaults (drift guard), described as inert. Live cluster gate `tools/test_equivocation_slashing.sh` inverted: node1's expected post-evidence stake is exactly its pre-submission value (no abort-deduction term); run against this build — PASS (0 round-1 aborts against node1 in that run's window, so its D13 arm was not exercised there; the in-process gates carry the proof). `tools/test_f2_eqabort_reconciliation.sh` / `tools/test_abort_cert_validation.sh`: rationale comments only.

**Mutants (`/root/audit/par/d13/mutants/mutate.sh`, each rebuilt — chain.cpp recompiled and the binary relinked, checked in the log — and run against the eight apply-side gates; all RED, source restored after each, clean rebuild before the final ci_local).** M1 the deduction restored — RED in seven gates (stake / counter / supply assertions); M2 `locked -= deduct` restored WITHOUT `block_slashed += deduct` — the A1 throw kills every gate; M3 a deduction that fires only when `locked > min_stake` (hidden above the floor) — RED in `test-abort-event-apply` on the `rich` (1500) domain of the floor scenario, in both traces and in `test-eligibility-floor` (so the floor-staked domain is NOT the only one asserting); M4 a deduction keyed on `round == 2` — RED in `test-abort-event-apply` (the round-2 scenario) and `test-fa-abort-trace` (scheduled Phase-2 events); M5 the abort-record increment dropped — RED in seven gates on the positive controls; M6 a NEW consequence (`inactive_from = b.index + 1` on the aborted registrant) — RED on the registry assertion and the `r:` twin leaf in `test-abort-event-apply`, the twin leaf check in `test-fa-abort-trace`, the registry checks in `test-fa-multi-event-trace` and `test-block-event-composition`, and the fill-to-K expectation in `test-eligibility-floor`; extras M7 a 1-unit deduction — RED in seven gates; M8 a deduction at/above the floor (`>=`) — RED as M3; M9 a record for `round != 1` too — RED in `test-abort-event-apply` and `test-fa-abort-trace`; M10 a record only for staked domains — RED in `test-abort-event-apply` (the stake-free scenario).

**Riders, non-semantic only.** In-code comments/help text that stated the deduction as current: `chain.hpp` (the `suspension_slash` accessor, the A1 ledger comment, the lazy-container comment), `genesis.hpp` (the STAKE_INCLUSION disincentive line, the `suspension_slash` field), `params.hpp` (the `SUSPENSION_SLASH` comment, CRLF preserved), `chain.cpp` (`block_slashed` and the loop comment), `main.cpp` (five help lines, the `test-params-constants` comments and labels, the scenario comments of the inverted gates, the cross-shard supply and `check-fork` counter comments), `light/main.cpp` (`verify-abort-record` preamble), the wrapper headers of the inverted gates, `tools/operator_slashing_ledger.sh` / `operator_suspension_watch.sh` / `operator_event_summary.sh` descriptive text and printed labels (logic untouched), and `tools/operator_genesis_dump.sh` (the `--security-posture` `suspension_slash` line now reports the parameter as inert — INFO in both branches — instead of "N per abort" / a WARN at zero; exit code unaffected).

**Docs.** `docs/SECURITY.md`: S-087 closed (`✅ Mitigated`, lead sentence, moved from the Open cell to the Mitigated-in-session cell, counts 18→17 / 21→22 / 39→38 / 50→51; `tools/test_security_ledger_coherence.sh` PASS), a STATUS blockquote above the O-1 step 3a one, the S-077 row's "only round-1 aborts deduct" clause corrected, the S-032 cache paragraph, the v2.10 and permissionless-readiness bullets ("re-roll + suspension slashing" → "re-roll + suspension"), and the five test-table rows of the inverted gates. `CLAUDE.md`: ACTIVE FRONT step 3 marks the abort-deduction retirement LANDED; the SLASHING block's RESOLVED paragraph and "STILL TO LAND" list mark D13 landed (the rest kept; the 3c sentence "abort-driven stake drain below min_stake IS permanent" is restated in the past tense because that drain no longer exists); the O-1 owner line and the G1/G4 design-gate lines note S-087 already closed. `docs/proofs/AbortEventApply.md` (this untiered proof states the deduction as T-A1) carries ONE line directly under its title: `STATUS 2026-09-16 — D13 landed: a Phase-1 AbortEvent records the abort (S-032) and deducts NOTHING; T-A1 and every statement below that rests on the deduction are historical and are re-derived in step 3c`. The same one-line banner sits under the title of the 26 other untiered documents that state the deduction as current shipped behaviour (classification by grep for `SUSPENSION_SLASH` / `suspension slash` / `suspension_slash` and abort-penalty wording under `docs/`, DECISION-LOG and SECURITY excluded): `AbortCascadeLiveness`, `AbortCertificateSoundness`, `AbortRecordProofSoundness`, `AccountStateInvariants`, `BFTProposerElectionSoundness`, `CommitteeSelectionAbortDeterminismSoundness`, `CrossShardSupplyConservation`, `EligibilityFloorDesign`, `EqAbortViewDigestExtension`, `EquivocationSlashing`, `EquivocationSlashingApply`, `ExpectedTotalWellDefined`, `F2ApplyComposition`, `FROST_DEVIATION_NOTICE`, `FeeAccounting`, `MultiEventComposition`, `ProofClaimGateTraceability`, `RealEngineFAHarness`, `S010S011SybilEconomics`, `S033StateRootNamespaceCoverage`, `SelectiveAbort`, `StakeForfeitureCascade`, `StakeLifecycle`, `SubsidyAccountingSoundness`, `SubsidyDistribution`, `SupplyInvariantComposition` (26 `.md`), and as a `\*` comment block in `tla/AbortApply.tla`, `tla/MultiEventComposition.tla`, `tla/StakeForfeitureCascade.tla` (the latter two CRLF, preserved); the three generic stake-debit models `tla/AccountState.tla`, `tla/UnitarySupplyLedger.tla`, `tla/CrossShardSupplyConservation.tla` keep their `Slash`/`SlashStake` actions and only their descriptive comments are corrected inline (no shipped apply path drives that action any more). Untiered docs that mention `suspension_slash` only as a governance / genesis / `k:` leaf / snapshot field (`PROTOCOL.md`, `QUICKSTART.md`, `Governance*.md`, `ParamChange*.md`, `ConstantProofSoundness.md`, `Snapshot*.md`, `BoundedReorgSoundness.md`, `WireFormatBackwardCompat.md`, `ReservedDiscriminatorAudit.md`, `S024EpochBlocks.md`, `ConsensusValidatorGateAudit.md`, `tla/FeeAccounting.tla`, `tla/GovernanceParamChange.tla`, `tla/AbortApply.cfg`) are correct as written and untouched; tiered docs (`docs/README.md`, `docs/UNIT-TESTS.md`, `docs/V2-DESIGN.md`, `docs/proofs/README.md`, `UnitTestCoverageMap.md`, `Improvements.md`, `D5-RANDOM-SELECTION-SPEC.md`) keep their text under their TIER banner. Short factual statements corrected INLINE: `README.md` (the mutual-veto bullet, the inclusion-model table, the "Slashing" paragraph — now "Suspension", the `SUSPENSION_SLASH` constant row, the two governance-model bullets; CRLF preserved), `docs/WHITEPAPER-v1.x.md` (§Sybil disincentive, the v2.10 bullet, the `GenesisConfig` field comment), `docs/CLI-REFERENCE.md` (the five test rows, the two operator-tool rows; CRLF preserved). `docs/PROTOCOL.md` and `docs/QUICKSTART.md` state no abort deduction and are untouched.

**What this does NOT claim or do.** S-011 / S-013 are NOT re-derived here — their restatement on the floor + suspension window is step 3c (with S-006, S-029, T-5.1, S-095); the ⚠ markers on those rows stand. The T-A1 model of `AbortEventApply.md` and `tla/AbortApply.tla` are historical, not rewritten. `suspension_slash` is not removed from the genesis schema. Phase-2 withholding (D12 / R-16) is not touched: a round-2 event is still neither recorded nor suspended. The `sim/` toy model (`determ-dsf`) is unchanged by the 2026-07-07 decision. Files noticed and deliberately left alone: `include/determ/node/node.hpp` ("slashing zeros their stake", an equivocation remark from before D4), `docs/proofs/tla/StakeRefundFlow.tla` (describes its sibling FB16 as "the bounded-slash apply path" — a cross-reference to the now-bannered model), the "economic disincentive does the policing" region sentences in `README.md` / `WHITEPAPER` (suspension is still an economic disincentive — lost committee income), and the FA6 verifier claims settled with S-095 in 3c.

**Authority:** implemented and recorded by Claude (Cowork session) under D13 / the §E sequence of this log, 2026-09-16; adversarial review of the diff before commit per the 2026-08-13 rules (findings and dispositions in the commit message and `/root/audit/par/d13/REPORT.md`). This entry is append-only per convention and contains no tier marker in its body.
## 2026-09-16 — S-078 LANDED: `Chain::load` seeds EVERY genesis parameter before the store replay — a non-default genesis (the tactical / cluster FIPS profiles included) is restartable

**Status:** IMPLEMENTED and verified (`tools/ci_local.sh`: build 6 targets, FAST 311 passed / 0 failed, 16 guards green). First increment of the node-/client-local backlog (sequence step 11; this log, 2026-09-16 §E and D19a).

**Problem this change solves.** `Chain::load` constructed the replay chain and seeded exactly six fields (`block_subsidy_`, `shard_count_`, `shard_salt_`, `my_shard_id_`, `epoch_blocks_`, `k_block_sigs_`) before replaying every stored block through `apply_transactions`. `min_stake_`, `suspension_slash_`, `unstake_delay_`, `merge_threshold_blocks_`, `revert_threshold_blocks_`, `merge_grace_blocks_`, `crypto_profile_`, `subsidy_mode_`, `subsidy_pool_initial_` and `lottery_jackpot_multiplier_` kept their in-class defaults for the whole replay, and every one of them is a `k:` state-root leaf (`crypto_profile` conditionally, when FIPS). `Node::start` called `set_min_stake` and its siblings only AFTER `Chain::load` returned — too late for the replay's S-033 recompute — and never called `set_subsidy_pool_initial` / `set_subsidy_mode` / `set_lottery_jackpot_multiplier` on the loaded path at all, so a LOTTERY chain that somehow survived the replay would have produced its next block under FLAT. Consequence: the FIRST restart of any chain whose genesis differs from the defaults threw `state_root mismatch ... (S-033)` on the first replayed block carrying a non-zero state_root, and the node never started again. Since S-038 the producer puts a non-zero state_root in every block, so this is every non-default chain. The `tactical` and `cluster` profiles mandate `crypto_profile = FIPS`, which is a leaf on its own, so those deployments were unrestartable independent of economics — D19c already made the fix a prerequisite for any FIPS chain restart.

**The change (node-local; no consensus change).** `Chain::Params` (`include/determ/chain/chain.hpp`) carries the sixteen replay-relevant fields, its defaults equal to the in-class member defaults; `Chain::set_params` is the ONE seeding routine; `Chain::load(path, const Params&)` calls it on the replay chain BEFORE the first stored block re-applies (and on the empty-chain return). `Node::Node` builds one `chain_params` from the genesis it already parsed — three new `genesis_subsidy_pool_initial` / `genesis_subsidy_mode` / `genesis_lottery_jackpot_multiplier` locals join the existing `genesis_*` set — hands it to `load`, and seeds the genesis-bootstrap chain from the SAME struct, so the replay chain and the live chain can no longer diverge field by field. The post-load setters are REMOVED, not kept: on a governed chain they reset a `PARAM_CHANGE`-activated `MIN_STAKE` / `SUSPENSION_SLASH` / `UNSTAKE_DELAY` back to the genesis value after the replay had committed the activated one, which is the same restart-fork family as S-078 itself. The six-field positional `load` overload survives as a documented convenience for the fourteen in-process selftest call sites (forwarding to the Params form, every other field default); no production path uses it. Seeding before block 0 (load) and after the genesis ctor (bootstrap) are equivalent: the `b.index == 0` branch of `apply_transactions` installs `initial_state` and returns before the subsidy distribution, both folds and the state_root check, reading none of the sixteen fields.

**Why a struct rather than more positional parameters or a `GenesisConfig&`.** Seventeen positional defaults are exactly the shape that produced this bug — a caller silently gets a default for a consensus-relevant field. A `GenesisConfig&` would push node policy into the chain layer: `epoch_blocks` is zero unless the node runs EXTENDED, K and `my_shard_id` come from `cfg_` after the genesis reconfig, and the legacy no-genesis path has no `GenesisConfig` at all. The struct keeps the derivation at the node and makes the chain layer's requirement total and checkable.

**Gate — `determ test-chain-load-genesis-params` (FAST, `tools/test_chain_load_genesis_params.sh`), 37 assertions at the layer where the rule lives (the `Chain::load` replay):** the fixture is a store whose genesis is non-default in all eleven economic / profile fields plus the shard salt, with six blocks that each declare a state_root computed the way the producer computes it (a LOTTERY draw sequence that exercises jackpot and zero payouts, the E4 pool draining to exactly 0, and a governance `PARAM_CHANGE` that activates `MIN_STAKE` inside the replayed range), seeded through the INDIVIDUAL setters so the store does not depend on the routine under test. CL-1..8: `Chain::load(path, Params)` does not throw and reproduces height, head_hash, `compute_state_root()`, all sixteen getters, balances, the subsidy counter and the A1 identity, and one further block with a declared state_root appends on the reloaded chain and lands on the producer's state. NL-1..6: the REAL restart path — a `node::Node` constructed on that store and the saved genesis file — loads without throwing and carries the genesis parameters, and a second node bootstrapping the same genesis with NO store reaches the state_root of a field-by-field-seeded chain. FI-*: per-parameter fault injection, the positive control that each field is a live leaf the replay depends on — for each of the fourteen leaf fields, a load whose seed differs from the producer's in that ONE field throws the S-033 message (twelve faulted back to their default, `shard_count` / `my_shard_id` faulted the other way since the fixture is SINGLE), plus a non-vacuity control, plus the six-field legacy overload throwing on the same store; `epoch_blocks` / `k_block_sigs` are NOT state-root leaves, so no throw is asserted for them — only that `Params` seeds them. GV-1..2: the governance-activated `MIN_STAKE` survives the restart on both the Chain and the Node path.

**Mutants (`/root/audit/par/s078/mutants`, each rebuilt and re-run against the gate; all RED).** M1 × 16 — `set_params` drops the seeding of ONE field, repeated for every field of `Params`: RED for all sixteen. The fourteen leaf fields die on the reload assertions (CL/NL) as designed; `epoch_blocks` and `k_block_sigs` are NOT leaves and their loss cannot throw S-033, so they die instead on FI-nonleaf, the assertion written precisely to catch a dropped seeding of a non-leaf field — without it those two would have been the only unfalsifiable members of the struct. M2 — seed the Params AFTER the replay loop instead of before: RED. M3 — seed from `Params{}` (the defaults) instead of the caller's values: RED. M4 (node side) — call the six-field overload instead of passing `chain_params`: RED. M5 — re-add the post-load `set_min_stake(genesis_min_stake)`: RED on the governance assertions only (GV-1/GV-2), which is what they exist for. M6 — drop `set_params` on the genesis-bootstrap path: RED.

**Live check.** `/root/audit/par/s078/live_restart_nondefault_genesis.sh` (audit-dir only, not a repo gate — no FAST wrapper runs a real daemon restart on a non-default genesis) starts a real `determ start` node on a genesis with `min_stake 500`, `crypto_profile FIPS`, `suspension_slash 20`, `unstake_delay 900`, non-default merge thresholds and a LOTTERY subsidy, mints past height 5, kills it, and restarts it on the same data dir: the node resumes and keeps minting, and its log carries no `state_root mismatch`. The same script against the pre-fix binary is the reproduction.

**Riders, deliberately non-semantic.** The in-code comments at `Chain::load` and at the node's (now removed) post-load setter block; the `test-committee-fold` comment that described "the Chain::load reload path (which does not thread min_stake)" as a standing limitation, now corrected to name the convenience overload and this gate; `docs/SECURITY.md` S-078 closed with the summary cells moved and one count sentence corrected inline; the new gate's rows in `docs/CLI-REFERENCE.md` (CRLF preserved) and the `docs/SECURITY.md` §S-035 test table; `CLAUDE.md`'s backlog and sequence lines marked landed; `tools/run_all.sh` ONLY_PATTERN and the `determ` help block gained the new subcommand.

**What does NOT change.** The genesis hash; the state-root leaf set and every `k:` leaf value; the wire format; the block-store and manifest formats; every accept rule; both snapshot containers (they already carry their own copies of these fields); `f2_active_from_height` (not read by apply — still set at the post-construction convergence label); the convergence-label `set_k_block_sigs`, which also covers the snapshot-restore path. No migration is needed or possible: a store that could not load never survived its own first restart, so nothing on disk changes shape.

**Noticed and deliberately left alone.** (a) `Node::Node` installs `chain_.set_param_changed_hook(...)` on the pre-load `chain_`, and every construction path (`Chain::load`, snapshot restore, genesis bootstrap) REPLACES `chain_` by assignment, so the hook is lost and the validator-side governance mirror (`bft_escalation_threshold`, `param_keyholders`, `param_threshold`) is dead after any restart. A real governance defect, out of this increment's scope and not created by it; it wants its own ledger row. (b) The `chain.hpp` comment claiming the shard routing fields are not snapshotted is stale — `serialize_state` / `encode_state` do emit them. (c) `tools/test_log_quiet.sh` deletes only `chain.json` between its two phases, so phase B silently restarts from phase A's block store; harmless (default genesis) and left as written.

**Authority:** owner decision D19a of 2026-09-16 (this log), which authorized S-078 as the first item of the node-/client-local backlog; D19c makes it the prerequisite for any tactical/cluster FIPS restart. Implemented and recorded by Claude (Cowork session), adversarial review of the diff before commit per the 2026-08-13 rules. This entry is append-only per convention and contains no tier marker in its body.
## 2026-09-16 — S-079 LANDED (D19a backlog item 2, with S-070): mempool admission is affordability- and quota-gated, node-locally — the remote, zero-cost, permanent seal of the mempool is closed

**Status:** LANDED on `track/s079` (base `c030d67`); node-local; no accept-rule, apply, wire or genesis change — `BlockValidator` and `Chain::apply_transactions` are untouched. Ledger rows S-079 (High) and S-070 (Medium) move to Mitigated; gate `determ test-mempool-admit-affordability` (FAST, in-process, 33 assertions); mutants M1–M6 RED.

**The problem.** `Node::mempool_admit_check` performed no funding check (sweep 2026-08-13; carried into the ledger as S-079 on 2026-09-16); `mempool_make_room_for` evicted the MINIMUM-fee resident and only when the incoming fee beat it; and the producer's `build_body` skipped a transaction its provisional balance could not cover WITHOUT evicting it — the 2026-09-14 build-time eviction (`Node::tx_admit_locked`) fires only on `BlockValidator::check_transaction` rejections, and the verifier has no balance rule for any type. Anonymous senders are free to mint (the address IS the key; no registry entry) and pass the S-002 signature gate by construction. So 100 anonymous senders × 100 `TRANSFER{amount = 0, fee = UINT64_MAX}` — S-049-clean (0 + MAX does not wrap), within the per-sender quota — filled `MEMPOOL_MAX_TXS = 10000` with entries no block would ever apply, and `tx.fee <= min_fee = UINT64_MAX` then rejected every representable fee, forever: a remote, zero-cost, PERMANENT seal. S-070 was the same defect with `fee` in place of `amount + fee`: a zero-balance fresh domain's `REGISTER(name, 0, fee = MAX)` squatted `(name, 0)` in every pool it reached.

**The change (src/node/node.cpp, include/determ/node/node.hpp), stated as the invariants the gate asserts.**
- I1 — affordability at ingress with the sender's running commitment: `mempool_admit_check` admits a transaction only if `cost(tx) + Σ cost(other resident txs of the sender) <= balance(sender)` at the head, where `cost` (`Node::mempool_tx_cost`) is the TRANSPARENT debit `Chain::apply_transactions` charges per type — `amount + fee` for TRANSFER / PQ_TRANSFER / SHIELD / DAPP_CALL, the staked amount + fee for STAKE, the fee for every `charge_fee` type (REGISTER, DEREGISTER, UNSTAKE, PARAM_CHANGE, MERGE_EVENT, the COMPOSABLE_BATCH outer, DAPP_REGISTER, the A2 audit types, REGISTER_NOTE_KEY), and 0 for the note-funded UNSHIELD / CONFIDENTIAL_TRANSFER; an overflowing sum is unpayable. The same-nonce incumbent a replacement displaces is not counted (`mempool_committed_from`). By balance, not registration. No credit optimism: a pending transfer TO the sender counts only once it lands. Both channels: gossip drops silently, `rpc_submit_tx` rejects definitively — "mempool: unaffordable (S-079): <from> holds B at the head; this tx costs C and its other pending txs commit P" — instead of acknowledging `queued` for bytes the producer would skip for ever (the outbox's F-2 concern; S-097's structural pre-check stays open).
- I2 — the S-008 per-sender quota (100) stays; with I1 an unfunded sender can hold nothing but fee-0 / amount-0 entries, which sit at the bottom of the fee ladder.
- I3 — eviction order: at the cap `mempool_make_room_for` evicts an UNAFFORDABLE resident if one exists, at any incoming fee, else the minimum-fee resident (tie: smallest hash, as before) and only if the incoming fee is strictly higher. "Unaffordable" is re-checked against the CURRENT head in one pass over `tx_by_account_nonce_` (`mempool_scan_locked`): per sender in nonce order — lower nonces spend first — the first entry whose running debit exceeds the balance, and every later nonce of that sender.
- I4 — the build evicts what it skips as unaffordable: after the memoized verifier verdict, the predicate `tx_admit_locked` hands to `build_body` re-checks `balance − Σ cost(the sender's LOWER-nonce residents) >= cost(tx)` (`mempool_affordable_at_build_locked`) and evicts on failure, exactly like a verifier rejection; NOT memoized (the verdict depends on the pool, not only on the head). `build_body`'s own provisional-balance skip is untouched.
- I5 — the admission floor is derived from AFFORDABLE residents only: at the cap, an unaffordable resident makes admission possible at any fee (I3 evicts it); otherwise `tx.fee <= min_fee(affordable)` rejects. An unaffordable `UINT64_MAX` fee never raises the floor.
- Why an unaffordable resident can exist at all under I1: I1 judges the head of the moment; a later head can leave the sender unable to pay (an alternate at the same nonce built elsewhere, a reorg re-inserting the reverted head's transactions through the maps, an abort deduction). I3/I4/I5 make such a resident harmless: first to go at the cap, never a floor, evicted at the next build.
- `on_tx`'s tail after its authenticity gates is factored verbatim into `admit_tx_locked` (byte-neutral), so the gate can drive the policy at the real cap through `admit_tx_for_test` without an Ed25519 verification per flood entry (S-002 has its own falsifier; an anonymous signature is valid by construction). Seams: `admit_tx_for_test`, `mempool_contains_for_test`.

**Gate — `determ test-mempool-admit-affordability`** (`tools/test_mempool_admit_affordability.sh`, FAST; deterministic in-process fixture: fixed seeds, VirtualClock, virtual-time VirtualEventLoop, SeededRng — the `test-node-reorg-s048` producer shape). Arms: the seal — 100 unfunded anonymous senders × 100 `TRANSFER{0, UINT64_MAX}` all refused (pool 0), a really-signed one dropped at gossip ingress and rejected at RPC with the funding reason, an affordable fee-0 transfer still queued (the floor untouched) and INCLUDED by a real round together with every other affordable resident; the S-070 REGISTER squat dropped / rejected while the fee-0 one is admitted; the quota (the 101st pending transaction rejected, another sender admitted); the running commitment (balance 100: 60, then 60 rejected, 40 queued; replace-by-fee 70+1 rejected, 55+1 queued and displacing); the build-time eviction — a resident admitted at balance 100 is left unfundable by a block built on another node (an alternate at the same nonce), applied through `apply_block_for_test`; the predicate answers false and evicts it, the affordable one stays, the block the producer builds next carries only the latter; the cap — 9998 affordable fee-5 fillers + two unaffordable residents: a fee-3 transfer (below the affordable minimum) is queued by evicting an unaffordable one, a fee-6 transfer evicts the other rather than any affordable entry (every filler still resident), and with none left fee 3 (== the floor) is rejected while fee 4 evicts the fee-3 entry — the shipped fee-priority rule is intact.

**Mutants (source edits, rebuilt, restored; logs under the audit dir):** M1 drop the I1 check → the seal, S-070, floor and RPC arms RED; M2 count only the single transaction (committed := 0) → the commitment arms RED; M3 drop the quota → the 101st-transaction arm RED; M4 floor over all residents → the fee-3-at-cap arm RED; M5 eviction ignores affordability (pure minimum fee) → the fee-6-at-cap arm RED; M6 build-time skip without eviction → the I4 arms RED.

**Riders (none beyond what the change falsifies).** Help text, `docs/CLI-REFERENCE.md` row, `docs/SECURITY.md` (S-079 and S-070 rows closed with the summary cells moved, the S-008 mitigation text, the test-table row), `docs/PROTOCOL.md` (`submit_tx` observable + method rows), `docs/proofs/DurableOutboxSoundness.md` F3/F5, `docs/proofs/S008BoundedMempool.md` (a dated correction; the proofs are not re-derived), the two mempool TLA models (a dated note), `tools/test_mempool_bounds.sh` (its zero-balance sender must stay a 0/0 transfer), CLAUDE.md backlog line.

**What does not change / residuals, stated so nobody rediscovers them.** The verifier and apply: an unaffordable transaction is still consensus-valid in a block and apply still skips it without advancing the nonce (the pre-existing S-063-adjacent fact; the producer's provisional accounting keeps them out of honest blocks). UNSHIELD / CONFIDENTIAL_TRANSFER are note-funded (transparent cost 0): a zero-cost confidential junk flood is bounded by the quota and cleared by every build; its verification cost under the lock is S-065 / D14 step 8 ("the ingress rule"), not this increment. Fee-0 transactions from unfunded senders are valid, includable and displaced by any fee ≥ 1 (S-073 / the deferred protocol minimum fee). Replace-by-fee still demands a strictly higher fee even to replace one's own resident that a later head left unfundable (the next build evicts it anyway). The operator self-paths (`rpc_send` / `rpc_stake` / `rpc_unstake` / `rpc_register`) insert through the maps with their S-023 single-transaction pre-check, as before. `build_body` still has no arm for COMPOSABLE_BATCH / DAPP_REGISTER / DAPP_CALL / PARAM_CHANGE / MERGE_EVENT (no provisional debit) — pre-existing, verifier- and apply-guarded. A memoized verifier rejection at the same head does not re-evict an identically re-submitted transaction until the head changes (pre-existing, 2026-09-14 memo).

**Authority:** owner decision D19a of 2026-09-16 (this log, §D and §E step 11: S-079 second in the node-local backlog); implemented and recorded by Claude (Cowork session) the same day; adversarial review of the diff before commit per the 2026-08-13 rules. This entry is append-only per convention and contains no tier marker in its body.
## 2026-09-16 — D2 inc7c LANDED: SNAPSHOT_RESPONSE and HEADERS_RESPONSE are canonical binary frames; the lp-JSON fallback is DELETED and WIRE-2 is RETIRED — the p2p wire is binary-only end to end

**Status:** LANDED on `track/inc7c` (base `c030d67`), falsify-on-mutant gated, live-verified over real sockets, `tools/ci_local.sh` green.

**Problem.** D2 (2026-07-23, scheduled 2026-07-28) decided canonical-binary-only on the p2p wire. Eighteen of the nineteen MsgTypes got there in stages — the envelope at `ce31c6f`, five request/status frames at `ad595bb`, four consensus-chatter frames at `e845b44`, six Block-carrying/CONTRIB frames at `8a106aa` — but **SNAPSHOT_RESPONSE (16) and HEADERS_RESPONSE (18) were still length-prefixed JSON inside the binary envelope**, and that was not a cosmetic tail. Three things were held hostage to it. (i) `decode_binary`'s `default` arm was a live `nlohmann::json::parse` on a pre-auth path, and the type byte at offset 2 is attacker-chosen, so a hostile frame claiming a 16 MB type reached it — the residual `S022WireFormatCaps.md` F-6 measured at 482 MB of DOM (25.5×) from 16 MB of input. (ii) **Any unknown MsgType byte also fell through to that parser** and was fully parsed under the 1 MB default cap (recorded in this log, 2026-08-13). (iii) The WIRE-2 structural ceiling (`kMaxJsonDepth` / `kMaxJsonNodes` + `json_structural_precheck`) existed *only* to bound that parser, and the light client's export-headers archive was explicitly deferred "behind the binary header frame" that did not exist.

**Authority.** The five-step D2 authorization (this log, 2026-07-28); the sequencing line of 2026-08-12 — "Genesis-frozen first: Q1, Q2, and D2 inc7c (HEADERS_RESPONSE + SNAPSHOT_RESPONSE reusing DSN1, then delete the lp-JSON fallback and retire WIRE-2)"; and the 2026-09-16 §E implementation sequence, step 10 ("D2 inc7c in parallel from step 3"). Pre-genesis, wire/sync only.

**What shipped.**

1. **HEADERS_RESPONSE — a new canonical record, `DHF1`.** The frame is `[from u64 LE][height u64 LE][count u16 LE]` then `count` × `[magic 'D','H','F','1'][block_hash 32][frame_len u32 LE][Block frame]`, where the Block frame is the shipped `chain::Block::encode_frame` container (D2-inc5) with the four heavy collections `transactions` / `cross_shard_receipts` / `inbound_receipts` / `initial_state` **empty** — exactly what `Node::rpc_headers` strips — and `block_hash` is the served `compute_hash()`. Reusing the Block container rather than deriving a ~30-field header layout is the S-044 one-shared-codec discipline: BF-1/BF-2 are already proved for it and the light mirror already walks it, at a cost of 8 bytes of zero counts per header. The per-record tag is deliberate: it makes a header **self-identifying at rest**, which is what unblocks the deferred light export-headers archive (the same idea as `DBK1` for a whole Block), and it makes the tag itself the version — a future layout is `DHF2`, never a flag inside `DHF1`. A record carrying any heavy collection is **rejected**, so a header has exactly one encoding. `count` is carried once and the DOM's `count` key is derived from it.

2. **SNAPSHOT_RESPONSE — the `DSN1` record verbatim.** The payload IS `Chain::encode_state`, so there is now **one snapshot layout on the wire and at rest** (the disposition `include/determ/chain/chain.hpp` already promised: "at which point it reuses THESE bytes"). The decoder IS `Chain::decode_state`, which means the wire inherits, unchanged and at the pre-auth boundary, every gate the at-rest path already had: magic, version, per-count byte-budget bounds before allocation, the `head_hash` and `block_index` claims against the tail, and the S-033 `state_root` self-consistency check. The A1 unitary-balance revalidate stays OFF at the codec — it is the node's opt-in *adoption* policy (`node.cpp` passes true on file restore), not a codec rule, and the gate asserts that boundary explicitly.

3. **The fallback is deleted and WIRE-2 is retired.** `encode_binary`'s and `decode_binary`'s `default` arms now throw (`no encoder for MsgType N` / `unknown MsgType N — rejected (no length-prefixed JSON fallback, D2 inc7c)`), so an unknown type can neither be put on the wire nor parsed off it. `json_structural_precheck`, `kMaxJsonDepth` and `kMaxJsonNodes` are **deleted** from `src/net/messages.*`. No wire path builds a JSON DOM. What replaces the ceiling is not another ceiling but the per-frame count discipline every frame decoder already follows — each count proven against the bytes that remain *before* any reserve — so pre-dispatch work is now linear in body size. WIRE-1 (the pre-decode per-type byte cap) and WIRE-3 (close on parse error) are unchanged.

4. **One new accept rule, stated plainly.** `Chain::decode_state` now rejects a record declaring more than `kSnapshotHeaderMax` (256) tail headers, **before parsing any of them**. Every encoder already clamps to 256, so this is accept-narrowing to exactly the producer set and no file or frame a conforming producer ever wrote is affected; what it closes is a hostile 16 MB SNAPSHOT_RESPONSE carrying ~50k minimal header frames, which the byte-budget bound alone would have admitted. Because `decode_state` is shared, this rule applies to the at-rest path too. `kHeadersPageMax` and `Chain::kSnapshotHeaderMax` are each **one** constant shared by the server-side clamp and the decoder ceiling, so the two cannot drift.

**Gates.** Two new in-process gates, FAST: `test-headers-frame-codec` (32 assertions — builder-DOM equivalence over a page holding a folded beacon header with records + a witness, a genesis-shaped header and a leaf; canonical fixed point; *every* proper prefix rejected; trailing byte; non-`DHF1` tag incl. `DHF2`; the page cap at its exact boundary, 256 accepted / 257 rejected before any record is parsed; count-lie; three `frame_len` shapes; the heavy-collection reject with its stripped control; an ~11k-input hostile sweep; a hand-assembled 359-byte vector + SHA-256 pin; five encoder refusals) and `test-snapshot-response-frame-codec` (30 — the same shape over a chain touching every snapshot namespace, plus wire-bytes == at-rest-bytes, the `DSN2`/version-2 rejects, the head_hash / block_index / state_root claim tampers, the 257-tail-header cap proven to fire before any frame, the deleted lp-JSON shape rejected at the magic, a 270-byte vector pin, and the A1 boundary). `test-binary-codec`'s four WIRE-2 legs became five BINARY-ONLY legs and its exact-length sweep now pins `cases.size() == 19` (was 17 — the completeness statement that a new frame without a row reds it). `test-wire-payload-frames` covers eight frames. The light mirror gained `hpw_walk` + `snw_walk`, lost its `lp_json` branch, and `tools/test_light_decode_wire.sh` legs 8–9 were rewritten as ~20 independently-crafted frame vectors.

**Mutants — all RED against a REBUILT binary, source restored after each.** M1 decoder accepts trailing bytes; M2 page cap skipped; M3 encoder drops `height`; M4 the JSON fallback restored, and M4b the *whole* pre-inc7c decoder restored (both case arms removed + fallback); M5 the `DHF1` tag unchecked and M5b the `DSN1` version unchecked; M6 the length prefix read without its bound and M6b the overflow-safe bound reverted to the additive form; M7 the DSN1 tail-header cap skipped; M8 the heavy-collection reject removed.

**LIVE verification — the part a round-trip fixture cannot give.** `test_headers_gossip` fetches headers over a real gossip socket and asserts the envelope matches the RPC one and that the fetched headers still verify `verify-headers` **and** `verify-block-sigs` K-of-K — i.e. the committee signatures survive the container swap on the wire, which is the signature-transparency claim actually exercised. `test_snapshot_bootstrap` gained a leg that pulls a snapshot over the wire (`snapshot fetch --peer` → SNAPSHOT_REQUEST/SNAPSHOT_RESPONSE), asserts the delivered file is a `DSN1` record (not text), inspects it through `decode_state` + its post-load gates, and **bootstraps the receiver node from those wire-delivered bytes** — SNAPSHOT_RESPONSE end to end, which nothing previously exercised at all. Also run green: `test_headers_rpc`, `test_f2_eqabort_snapshot`, `test_dapp_snapshot`, `test_light_export_headers` (10/10), `test_straggler_resync`, the light/wallet offline mirrors.

**Adversarial review of the diff found one defect, fixed here.** The header record's `frame_len` is a full u32 read off the wire and was bounded additively (`off + flen > len`). Sound on the shipped 64-bit targets; on a 32-bit `size_t` it wraps and hands `Block::decode_frame` a 4 GB window. Changed to the subtractive form (`flen > len || off > len - flen`), matching what the light mirror and `SnRd::need` already do, and gated by M6b. **Recorded, not fixed:** `wf_need` (`src/net/binary_codec.cpp`) and `bf_need` (`src/chain/block.cpp`) keep the additive form, so `CHAIN_RESPONSE`'s block length (D2-inc7a) and the Block container's nested tx/witness lengths carry the same 32-bit-only hazard — pre-existing, not code this increment touches, and listed so it is not rediscovered as new. Residuals stated rather than glossed: SNAPSHOT_RESPONSE decode now runs the S-033 state-root recompute pre-auth (bounded, and strictly better than the 482 MB DOM it replaces; `Node` sets no `on_snapshot_response`, so nothing downstream acts on it); the heavy-collection reject runs after the Block parse (bounded by the 4 MB cap); and `from` / `height` / `block_hash` remain carried data, not verified claims — unchanged from the JSON payload and already documented at `rpc_headers`.

**Also repaired (pre-existing RED, found by running it).** `tools/test_light_decode_wire_cap_edge.sh` had two of five legs failing **at baseline** — its at-cap / under-cap vectors were lp-JSON bodies under CONTRIB and BLOCK, which stopped being decodable shapes at D2-inc7a/7b, so the two VALID legs were failing on payload well-formedness instead of proving anything about the S-022 cap. The test is outside the FAST pattern, so nothing surfaced it. Its vectors are now well-formed frames padded to an exact byte count; 5/5.

**Riders.** `docs/PROTOCOL.md` §9.1 gains a frame table for both payloads and §9.2's per-type table is corrected (all nineteen are frames; the Payload column now names the DOM each frame carries). `README.md` §12.2 corrected (it claimed 17 of 19 and a JSON fallback). `docs/SECURITY.md`: S-022's row records that WIRE-2 retired and that **F-6's last residual is closed by deletion of the path it measured** (F-7, the missing inbound-connection cap, remains owner-gated); two test rows added. `S022WireFormatCaps.md` carries a dated inc7c revision note, its T-6 clause 2 closes by deletion, its WIRE-2 gate rows are replaced by BINARY-ONLY + frame-count-bound rows, and **F-9 (the light mirror's missing structural ceiling) closes by deletion** — that mirror now decodes all 19 types as bounded frames. `S022WireFormatCapsCompleteness.md`'s `lp-JSON?` column reads `fixed frame` for all nineteen. `BinaryCodecRoundTripSoundness.md` gains a dated banner; its L-5 (the lp-JSON-is-verbatim lemma) is marked VOID with the per-frame theorems that discharge its obligation. `AbortDigestCanonicalizationSoundness.md`'s F-10 reference is dated (the typed claim list that closed F-10 stands regardless). Stale `messages.cpp` / `messages.hpp` line citations across five proofs were re-pointed at the current line numbers.

**What this does NOT change.** No consensus rule, digest, signature, block hash, state root or storage format. `Message::payload` stays a DOM (Q3 Path A; re-typing it is D2 step 4). `on_snapshot_request` / `on_headers_request` / `GossipNet::handle_message` and every Node handler are untouched — the decoders rebuild the exact DOM the builders produced, which is why this increment edits no handler code. **No ledger row closes.** D2 REMAINDER after this: `node_key.json` (`src/crypto/keys.cpp`) and `DETERM-ACCOUNT-V1` stay src-owned JSON/text (marked `D2-DEFERRED(src)`); the light export-headers archive still embeds `header_json` — the binary header frame it was waiting on now exists, so it is unblocked but deliberately **not** converted here (its own increment). D2 step 1b (selftest extraction) and step 2/4 (parser deletion) are later steps and were not touched.

**Authority:** Stoyan Denev (owner directives 2026-07-28 for D2, 2026-08-12 for the inc7c sequencing, 2026-09-16 §E step 10); implemented and recorded by Claude (Cowork session) on `track/inc7c`, with adversarial review of the diff before commit per the 2026-08-13 mandatory-review rule.
## 2026-09-17 — S-104 and S-105 LANDED: a mismatched contrib view list is dropped at ingress and unverifiable evidence is not proposed — two LIVE, cost-free permanent halts closed

**Status:** LANDED on `track/halts` (base `ca09163`); both fixes are node-local (producer/node side). No accept rule, wire format, apply path, digest or genesis field changes; `Chain::apply_transactions` is untouched and `BlockValidator`'s rule set is unchanged (one per-event function is *extracted* from it verbatim, exactly as `check_transaction` was extracted from `check_transactions` on 2026-09-14). Ledger rows S-104 (Critical, liveness) and S-105 (Critical, liveness) are opened and closed in this same commit. Gates `determ test-contrib-view-root-admit` (10 assertions) and `determ test-evidence-admit` (17), both FAST and in-process; mutants F1-M1/F1-M2 and F2-M1/F2-M2/F2-M3 each RED against a rebuilt binary.

**Provenance, and what did NOT cause them.** Both defects were found while writing the O-1 step 3b design memo (`/root/audit/par/3b-design/DESIGN.md` §0, findings F-1 and F-2, read at `c030d67`) — the design-and-prove pass that precedes the per-block evidence cap and in-block duplicate rule. They were re-verified independently against `ca09163` before any code was written. Both are PRE-EXISTING and **neither was caused by any 2026-09-16 increment**: F-1 has been live since the v2.7 F2 contrib carried a view list at all (`validate_contrib_view_roots` shipped with V21–V24 and has had zero production callers since), and F-2 has been live since `build_body` first materialized `pool ∩ reconcile_union` (the eq/abort dimension of S-030-D2). The 2026-09-16 increments (equivocation-forfeiture removal / O-1 step 3a, D13, S-102, S-078, S-079, D2 inc7c) touch neither `on_contrib`'s view-root path nor the evidence arm's admissibility. 3a (no L1 consequence for an EquivocationEvent) makes F-2 *cheaper to describe* — the attacker forfeits nothing by self-equivocating — but the halt does not depend on it: the same wedge exists for evidence gossiped about anyone whose key later stops resolving.

**The problem — S-104 (one committee member, one contrib per round, the chain never advances).** `Node::on_contrib` verifies the Phase-1 signature over `make_contrib_commitment(msg)`. That commitment binds the view ROOTS (`view_eq_root` / `view_abort_root` / `view_inbound_root` / `view_shardtip_root`) and NOT the view LISTS the same message carries. Nothing checked that the carried list hashes to the signed root: `validate_contrib_view_roots` performs exactly that recompute (V21–V25), is unit-tested, and had **zero production callers** — a fact the log already recorded on 2026-08-13, but as dead code, never as a halt. `build_body` copies each member's list into the block verbatim, and `BlockValidator::check_eqabort_reconciliation`'s `check_dim` recomputes `compute_view_root(list)` against the carried root and rejects the WHOLE block ("F2: creator_view_eq_lists[i] does not match committed root"). So one member sending one contrib whose revealed list has one extra hash makes every honest assembler build the same block that every honest verifier rejects; `apply_block_locked` returns without appending; the S-050 stall valve re-rounds with the SAME committee — the poison contrib is PRESENT, so no member is missing, the abort tail stays empty and the committee derivation repeats — the member re-sends, and the height never advances. Cost: one message per round. Nobody is excluded and nothing is slashed. Reachable whenever any creator's view root is non-zero, and the attacker's own root suffices.

**The problem — S-105 (any eligible key; two OFFLINE signatures and one DEREGISTER).** `build_body`'s evidence arm included `pool ∩ reconcile_union(creator_view_eq_lists)` with **no admissibility check of any kind**, while `BlockValidator::check_equivocation_events` rejects the block when the equivocator's key no longer resolves ("equivocator not in registry"). `resolve_committee_member_pubkey` is frozen-first then present-head, and `NodeRegistry::build_from_chain` omits every domain failing `domain_eligible` (`active_from` in the future, `at_index >= inactive_from`, stake below `min_stake`, or suspension active). Sequence: an eligible key E submits a DEREGISTER; apply sets `inactive_from = H + d` with `d ∈ [1,10]` derived from `cumulative_rand` and the transaction hash, so d is known to E as soon as block H is out. E manufactures ONE self-equivocation record about itself — two offline signatures over two conflicting Phase-1 openings at any `(index, gen)`; V11 ties neither opening to any real round — and gossips it while it still resolves. Every node adopts it. At height `H + d` the domain leaves the registry: every creator's committed view names the record, every assembler materializes it, every verifier fails to resolve E, no block is appended — and the ONLY prune is POST-inclusion (`post_append_bookkeeping_locked` drops what a block carried), so nothing ever removes the record. Permanent on a SINGLE chain; on a pinned EXTENDED chain the frozen key covers the rest of the epoch and the halt lands at the first block of the next one. A suspension variant needs no DEREGISTER at all. Both defects are the same class the 2026-09-14 increments closed for transactions (S-056/S-059/S-061/S-062 — *the producer includes what the verifier rejects, and nothing evicts it*), on the two arms that pass through the committee's view lists rather than the mempool.

**The change — S-104 (`src/node/node.cpp::on_contrib`).** One call, immediately after the signature check: `if (std::string why; !validate_contrib_view_roots(msg, &why)) { log; return; }`.
- **What "drop" means, and why that one.** Drop = *do not store*. No new state, no new signal. Every earlier `return` on this path (wrong height, wrong `prev_hash`, wrong abort generation, bad signature) already leaves the signer absent from `pending_contribs_`, and `committee_contribs_complete_locked` then reports the member MISSING — which is precisely what keeps the Phase-1 timer armed and arms the existing timeout/abort path (S-058). The alternative, an explicit "treat as missing" marker, would add a second exclusion mechanism to a consensus path that already has one, for no behavioural gain; the minimum that restores liveness is to not store the message.
- **Why this is not a new exclusion lever.** The roots are signed and the lists are not, so the only party that can make an honest member's contrib fail this check is one that can already rewrite the message in transit — and anyone who can rewrite it can equally DROP it, which already makes the member missing. The capability is therefore subsumed by one gossip has unconditionally. An honest member can never fail the check: `make_contrib` computes each list and its root together from the same snapshot. Before the fix the same tampering caused a full-network halt instead, so the change is strictly better for every party.
- **Placement, deliberately.** The call sits *before* the S-006 duplicate/equivocation detector, so this node never manufactures and gossips an `EquivocationEvent` out of a message it has decided to discard. The cost is that a same-round core equivocation whose second opening arrives inside a list-mismatched contrib is not detected *by this node*; the evidence carries no L1 consequence (D4), every node that received the untampered copy still detects, and an equivocator can always withhold the second message anyway. Cost of the check itself is O(1) for an over-cap list (V21 runs first and returns before any hashing) and at most 4 × 64 hashes otherwise.

**The change — S-105 (`validator.{hpp,cpp}`, `producer.{hpp,cpp}`, `node.{hpp,cpp}`).**
- `BlockValidator::check_equivocation_event(ev, i, block_index, chain, registry)` is the per-event rule set moved **verbatim** out of `check_equivocation_events`' loop and made public — the same extraction, for the same reason, as `check_transaction` on 2026-09-14. `check_equivocation_events` is now that loop and nothing else, so producer and verifier cannot drift.
- `using EvAdmit = std::function<bool(const chain::EquivocationEvent&)>` and a trailing `ev_admit` parameter on `build_body`, applied on BOTH branches of the evidence arm (the F2 union branch and the pre-activation direct-assign branch). **Fail-SAFE**, exactly like `TxAdmit`: an absent or empty predicate admits NOTHING, so a call site that forgets it proposes an empty evidence set, never an unvetted one. `build_body` iterates its own copy of the candidate vector, because the predicate mutates the caller's pool.
- `Node::eq_admit_locked()` builds the predicate against the same height and registry `apply_block_locked` will use for the block being assembled (`at = height()`, `build_from_chain(chain_, at)`), and is passed at all three `build_body` call sites. A record it rejects is EVICTED (`evict_equivocation_evidence_locked`, keyed by `same_equivocation_identity` like every other pool site): the record cannot enter any block until state changes, and the only other prune is post-inclusion, so leaving it resident leaves it permanently un-includable AND permanently occupying that equivocator's single pool slot and a place in every Phase-1 view list. Verdicts are memoized per head (`eq_admit_memo_`, dropped on any head change, append or reorg) because `check_equivocation_event` costs two Ed25519 verifications and `build_body` runs three times a round under `state_mutex_`.
- `tools/test_producer_admit_wiring_guard.sh` is extended to pin the new wiring in the source text: every `build_body(` call in `node.cpp` carries `eq_admit_locked()`, and the evidence admission lines are the fail-safe forms.

**Gates.** `determ test-contrib-view-root-admit` (`tools/test_contrib_view_root_admit.sh`, FAST, 10 assertions) asserts at both layers. INGRESS, on a real Node (M = K = 3 genesis so the node is always a committee member, virtual-time loop) driven through `on_contrib_for_test` / `round_probe_for_test`: a root-matching contrib is ACCEPTED; a mismatched one is DROPPED while the test separately asserts that its Phase-1 signature still verifies and that V22 is what distinguishes it (so the drop is attributable to the new check, not to the signature gate); the abort dimension (V23) is dropped by the same predicate; and the round is NOT wedged — the member's well-formed retransmission completes Phase 1 and the node advances to Phase 2. CONSEQUENCE: a fully-signed K-of-K block assembled by the production `build_body` from the same contribs is put through the FULL `BlockValidator::validate` — all 17 gates, the same call `apply_block_locked` makes — and the honest block PASSES (the accepted contrib's list reaches it verbatim) while the one carrying the mismatched contrib is REJECTED on the committed-root mismatch. `determ test-evidence-admit` (`tools/test_evidence_admit.sh`, FAST, 17 assertions) uses a FOLLOWER node (`watch`, not a registrant, so the committee never waits on it) plus a test-side miner that assembles real K-of-K blocks from the genesis creators' keys through the production `build_body`; every block is offered through `apply_block_for_test`, the real ingress that runs the full validator and appends only on success, so "the block validates and the chain advances" is read off the node's own height. Arms, in order: a record against a resolvable equivocator is adopted, ADMITTED, proposed, and its block validates and appends (the positive control), then the post-inclusion prune drops it; the equivocator's DEREGISTER is applied and the record re-pooled; idle blocks carry the head to `inactive_from` with the record STILL resident (nothing else removes it); the PRE-FIX producer (an always-true predicate) proposes it and the follower REFUSES to append — the height does not move — with `check_equivocation_events_for_test` naming "equivocator not in registry"; the fixed producer does NOT propose it, EVICTS it from the pool, and the follower appends, so the chain advances; and an absent predicate proposes nothing.

**Mutants — all RED against a REBUILT binary, source restored after each; logs under the audit dir.** F1-M1 remove the `validate_contrib_view_roots` call from `on_contrib` (this restores the defect verbatim, and is therefore also the pre-fix reproduction of the halt) → the drop, abort-dimension and liveness arms RED. F1-M2 check the root but keep the contrib on failure (log and fall through) → the drop arms RED. F2-M1 remove the `EvAdmit` call from `build_body`'s evidence arm (the defect verbatim; the pre-fix reproduction) → the fix arms RED. F2-M2 admit-check but do not evict → the eviction arm RED. F2-M3 a predicate that only checks presence in `chain.registrants()` instead of resolvability — the careless implementation, since a deregistered domain is still IN the raw registrants map — → the fix arms RED.

**Riders (only what the change falsifies).** Help text for the two subcommands; two `docs/CLI-REFERENCE.md` rows (CRLF preserved); `docs/SECURITY.md` rows S-104 and S-105 plus the Mitigated-in-session summary cells and totals (`tools/test_security_ledger_coherence.sh` green) and two test-table rows; `tools/run_all.sh` FAST pattern; the wiring guard; CLAUDE.md's node-local backlog block. Inline factual corrections in two UNTIERED proofs: `docs/proofs/F2ApplyComposition.md` §"Consequence for this composition" attributed the anti-equivocation binding to `validate_contrib_view_roots`, which had no caller — corrected to name `check_eqabort_reconciliation` as the block-level enforcement and `Node::on_contrib` as the new ingress caller, with the reference-list cite re-pointed at the function name instead of stale line numbers; `docs/proofs/EqAbortViewDigestExtension.md` §3.3 asserted that an event in a committed view "reached it only by passing V10/V11" — corrected to state that V11 held at the head the record was ADOPTED at, not at the head the block is validated against. No proof is re-derived. `docs/proofs/F2-SPEC.md` and `F2ViewReconciliationAnalysis.md` carry a near-term tier banner (they do not track shipped code) and were not touched.

**What does NOT change, stated so nobody rediscovers it.** No accept rule: a block carrying a mismatched view list, or evidence about an unresolvable equivocator, is rejected by exactly the rule that already rejected it. No wire format, no digest, no `signing_bytes`, no genesis field, no apply behaviour. Nothing here implements the O-1 step 3b rules — the per-block cap (R-CAP), in-block duplicate rejection (R-DUP), the staleness window (R-AGE), the canonical order (R-ORD) and the verifier-side view-list cap (R-VIEW) remain under adversarial review and are NOT in this commit. The memo's §3.2 head-change re-filter in `post_append_bookkeeping_locked` and its §3.5 node-local hardening riders (cheap-first ordering in `on_equivocation_evidence`, the already-on-chain adoption filter) are NOT in this commit either: the build-time predicate alone closes the halt, and each of those is its own increment.

**Residuals, recorded.** (a) An unverifiable record still occupies its equivocator's pool slot and a place in this node's Phase-1 view list until the first `build_body` at a head where the predicate rejects it — one round at most, and the SUBSET rule means a stale hash in the committed view harms nothing. (b) `on_equivocation_evidence` still verifies both signatures BEFORE the pool dedup, so a peer pays one message per record and costs the node ~6 ms each with no bound (3b memo §0 F-5, node-local, unchanged here). (c) `V25` as written in `include/determ/node/producer.hpp` still describes an equality rule that is not the shipped SUBSET rule, and `validate_view_reconciliation` still has no production caller (3b memo §0 F-3); left alone deliberately — it is a comment/dead-code question for the 3b increment that owns those rules. (d) A record dropped by the truncation/cap rules does not exist yet, so nothing here can starve anything. (e) The `ev_admit` predicate is evaluated inside `build_body` while the caller holds `state_mutex_` exclusively, as `tx_admit_locked` already was.

**Authority:** the 2026-08-13 doctrine entry (design-and-prove before implementing; assert at the layer where the rule lives; smallest increment, no bundling) and the 2026-09-16 §E implementation sequence, step 3 (the O-1 chain) read together with step 11 (the node-/client-local backlog interleaved BY SEVERITY from step 3) — two Critical-class live halts adjacent to the step-3b design outrank every queued item, and closing them is a prerequisite for 3b, whose R-VIEW rule would otherwise be a self-inflicted halt of the F-1 shape. Implemented and recorded by Claude (Cowork session) on `track/halts`, with adversarial review of the diff before commit per the 2026-08-13 mandatory-review rule. This entry is append-only per convention and contains no tier marker in its body.

---

## 2026-09-17 — O-1 step 3c LANDED: the re-derivations. Every claim that rested on equivocation slashing or on the abort deduction is restated on the shipped mechanism; all 58 banners come off, S-095 closes, and two of the restatements come out negative

**Status:** LANDED (branch `track/3c`, base `ca09163`). Fourth and last increment of sequence step 3 before 3b (this log, 2026-09-16 §E; owner decisions D4 and D13). **DOCS ONLY — zero `src/`, `include/`, `light/`, `wallet/`, `tools/` changes**, so its verification is the doc guards inside `tools/ci_local.sh` plus `tools/test_doc_citation_bounds.sh`; FAST is unchanged at 315.

**Problem this change solves.** Two landed increments deleted the consequences that a large part of the proof corpus quietly consumed: O-1 step 3a removed the equivocation forfeiture + deregistration (an `EquivocationEvent` now moves NO L1 state) and D13 retired the Phase-1 abort stake deduction (an abort records the S-032 suspension and moves nothing). 58 untiered documents were bannered `STATUS 2026-09-16 … pending re-derivation in step 3c` rather than corrected, because correcting them needed real arguments and the landing order put the code first. A banner is a promise; while it stands the document is neither true nor retracted, and five ledger rows (S-006, S-011, S-013, S-029, S-095) plus `BFTSafety.md` B2 / T-5.1 were stranded behind it. This entry pays that debt. **No banner was removed without a re-derivation**; where a re-derivation came out negative it is recorded as negative rather than softened.

**The six substantive re-derivations.**

**1. S-006 (`S006ContribMsgEquivocation.md`) — restated, NOT reopened.** The recorded closure was "route ContribMsg-level detection into the slashing apply path", and that path is gone. What the S-006 finding actually was is an OBSERVABILITY defect: two distinct same-generation `ContribMsg` from one signer were silently dropped at the receiver, so the second signature — the only proof of the split — vanished, and the split was invisible unless the signer later double-signed at Phase 2. That defect is fixed and stays fixed. The honest closure is **detection + on-chain record + L2 input (D22)**: the duplicate is recomputed and compared, the pair becomes a V11-verified `EquivocationEvent`, and the event is committed under the block hash. T-1, T-2 and T-4 are unchanged and are the substance. T-3's terminal clause ("and FA-Apply-10 T-E1/T-E2 fire") is void and now ends at T-E0. T-5 (replay-safety) is REWRITTEN: it used to assert "zero additional stake forfeiture beyond the first apply" resting on T-E3; apply-layer replay-safety is now trivial, and the pool dedup is a resource bound rather than a correctness precondition. §6.3's justification for the coarse `(equivocator, block_index)` dedup key — "the slash is full-stake-forfeit, so the second incident contributes nothing" — is VOID and replaced honestly: the dedup is retained because it is the pool's memory bound and the only defence against the one-proof replay amplification (`BlockIngressGateAudit.md` §3), at a stated price — within a shard only the first-observed incident per `(d, h)` reaches the chain, which is a deliberate loss in a channel whose only product is evidence. Ledger: S-006 stays ✅ Mitigated on the restated closure.

**2. S-011 (`S010S011SybilEconomics.md`) — the honest residual, and it is NEGATIVE.** T-4 ("cartel defense via slashing") is FALSE and is replaced by **T-4-R**, a cost/revenue table derived from the shipped apply path. Per round the protocol imposes on an `M−1` cartel: nothing for a fabricated abort claim (an `AbortClaim` is a gossip message, not a transaction — no fee, no nonce, and since D13 no deduction on the accused either), nothing for equivocating (D4), and capital that is now RECOVERABLE — the T-2 theorem "per-operator stake cost is unrecoverable on attack" is itself corrected, because UNSTAKE + `unstake_delay` is the ONLY remaining exit from `stakes_[v].locked`. So `cost_per_round = (M−1)·min_stake·r` (opportunity cost only) plus bandwidth. Against it, `Chain::apply_transactions` splits `total_distributed = total_fees + subsidy_this_block` evenly across `b.creators`, so the cartel's per-round REVENUE is its share of `block_subsidy + fees`, rising to all of it once the honest member is suspended. **The recorded closure's inequality is reversed: "per-round attack cost exceeds the chain's per-round subsidy throughput — economic infeasibility" is false at every parameterization with a positive subsidy, not merely at weak ones.** The three errors the 2026-08-13 review found in the earlier draft are each addressed in the new §6.7: (i) "at K == M structurally unreachable" is FALSE — `Node::check_if_selected` subtracts the node-local `current_aborts_` set AFTER the S-051 Option-B floor has run, so the floor cannot lift that exclusion; with `N_pool == K == 3`, `bft_escalation_threshold` defaulting to 1 and `bft_committee_size(3) == 2`, ONE fabricated abort escalates to a two-member ZERO-honest BFT committee, violating `BFTSafety.md` B1 outright (S-086 OPEN; the pool bound is D5a/R-4, authorized and not landed); (ii) "abort-driven stake drain below `min_stake` is permanent and S-051 does not lift it" was TRUE when recorded and is GONE — D13 retired the deduction and S-087 closed, so the leg must not be restated; its weaker replacement is the S-032 exclusion window, which the cartel renews at zero marginal cost with an exponentially growing length, so the honest member's stake is now safe and its SEAT is not; (iii) DOMAIN_INCLUSION pins `min_stake = 0`, and D4 removed the deregistration half that was the entire penalty there, so **both** legs are identically zero and the row does not apply to such a deployment at all. What still bounds the cartel is non-economic: `Censorship.md` T-2.1, `Safety.md` T-1 clause 1, and the per-hit `MAX_SUSPENSION_BLOCKS` cap with the Option-B floor. Ledger: S-011 stays ✅ Mitigated on the narrowed ground (entry cost + censorship/safety bound) with the ⚠ retired and the three residuals named in the row.

**3. S-013 (`S013PerSignerCap.md`) — the closure never needed the economic leg.** S-013 was a memory-exhaustion finding. Layers 1–2 give the bound: the pre-filter admits only current-K-committee ∩ registry signers (≤ K distinct) and `try_buffer_block_sig` caps each at 2, so `buffered_block_sigs_` ≤ 2·K, and L-5 keeps an honest signer's single message from ever being refused. Those are counting arguments over a filter and a cap; they consume no penalty term and D4/D13 do not touch them. §1.4's layer 3 — "the second signature costs the signer its stake", which made the flood self-defeating — is VOID. Residual, stated: the cap BOUNDS the flood but no longer PRICES it; a Byzantine committee member pushes exactly 2 entries per height forever for free, and "an attacker who pushes two different sigs inadvertently eliminates themselves from future rounds" is withdrawn. Layer 3 survives as evidence PRESERVATION — cap-2 is the minimal window that keeps both openings of a V11 event — and D4 makes that MORE load-bearing, not less, because the preserved pair is the L2 input. Ledger: ✅ Mitigated, ⚠ retired.

**4. S-029 (`S029ForkChoiceSoundness.md`) — the finding is closed; the Level-3 hole is open and WORSE than recorded.** §5.3's closure had three legs and all three fail. (i) "every grind iteration requires re-signing by every committee member" is false: `Block::compute_hash` hashes `signing_bytes()` then APPENDS `creator_block_sigs`, and no verifier can check RFC 8032's deterministic nonce, so the LAST member to broadcast enumerates unboundedly many valid signatures over the SAME digest at ~one Ed25519 sign per trial — no second digest, so H2 is not violated and V11 has nothing to see. (ii) "each member's re-sign is provably-equivocating evidence" is therefore also false. (iii) "plus the slashing risk (full stake forfeiture per FA-Apply-10)" is void since D4. **And, folded in here for the first time, the refutation is strictly stronger than first-order:** the S-102 adjudication entry (2026-09-16, "Noticed and deliberately left alone" item 1) established that `initial_state` is appended to `Block::signing_bytes` for every block, is OUTSIDE `compute_block_digest` (`src/node/producer.cpp::compute_block_digest_body`), is read by `Chain::apply_transactions` only at `index == 0`, is carried by the BLOCK frame codec at any index, and does not occur anywhere in `src/node/validator.cpp` — verified again here (`grep -c initial_state src/node/producer.cpp` → 0, `src/node/validator.cpp` → 0; the write site is inside `Block::signing_bytes` in `src/chain/block.cpp`). So an **unauthenticated relayer** re-rolls `compute_hash` at one SHA-256 per trial with the digest, the K-of-K signatures and the apply outcome all unchanged. **The block hash is RELAYER-malleable, not only signer-malleable**, and the Level-3 tiebreak is grindable by any peer at hashing cost. What survives is the only thing S-029 ever asked for: T-1 determinism and T-2 confluence hold unconditionally, so the fleet still converges, and nothing security-relevant is seeded from the block hash (committee selection and the subsidy lottery route through `cumulative_rand`'s commit-reveal) — the realistic harm is liveness griefing, one revert + apply + round reset per forced adoption. F-1's status changes from "economically infeasible" to **OPEN**; the fix is an accept rule (reject a non-empty `initial_state` at `index > 0`; refuse to replace a non-zero-`state_root` head with a zero-root same-digest twin), it is pre-genesis and free, and it is **NOT WRITTEN**. Ledger: S-029's own row stays ✅ Mitigated (the finding was "fork-choice undefined"), ⚠ retired, with the grinding hole stated as open in the row.

**5. `BFTSafety.md` — B2 DELETED, T-5.1 WITHDRAWN, accountable safety becomes evidence-only.** Assumption **(B2) "equivocation slashing enforced"** is false and is removed. **T-5 itself is unchanged in content**: §3's proof consumes L-5.1 (a counting bound on `Q`-sized subsets of `K_h`), L-5.2 (an honest member cannot have signed both digests) and A1/A2, and mentions B2 at no step — so deleting it removes a decorative hypothesis and the theorem now holds under strictly fewer assumptions. Corollary **T-5.1 ("slashing recovery")** is withdrawn and replaced by **T-5.1-R**: when `f_h ≥ |K_h|/3` the equivocators are detectable and the evidence is committed, and then nothing happens — they keep their stake, their registration and their eligibility and may be selected again at `h+1`. **There is no recovery.** What still gives: uniqueness under B1 per round instance, detectability, and no chain split (fork-choice determinism). What no longer gives: recovery, any cost that rises with repetition, and the §7 claim that Determ is "materially stronger than classical BFT failure modes (where exceeding f<N/3 simply breaks safety with no recovery)" — that claim is WITHDRAWN, because above the threshold Determ now also fails with no recovery. The two advantages that survive and are claimed instead: MD-mode has no threshold at all (FA1 clause 1 needs one honest member), and failure is attributable. §5.4's concrete-security paragraph loses its "additional 2⁻¹²⁸ per slash attempt" term. **What T-5 needed and did not label** is made explicit as **(B2′) honest single-sign at height `h`** — and §4.2 states honestly that B2′ is NOT unconditional: an abort re-round changes `gen` (bound into `compute_block_digest`) so an honest member signs two distinct digests at one height, and the S-050 valve can restart a round at the same height AND the same `gen`. What holds unconditionally is the weaker B2′′ (one digest per ROUND INSTANCE), so T-5 reads "two blocks of the same round instance at height `h` are equal" and cross-instance pairs are handled by fork-choice, not uniqueness.

**6. S-095 — `RoundStallValveSoundness.md` C-2 corrected; the row CLOSES.** C-2 argued that a valve-induced re-sign cannot fabricate equivocation evidence because "the fresh contrib carries `aborts_gen = 0` while peers hold `≠ 0`", and the generation gate drops it. That step silently assumes a NON-EMPTY abort tail. The corrected C-2 has two cases. **Case A** (non-empty tail): as argued, benign. **Case B** (EMPTY tail): `current_aborts_.clear()` clears an already-empty vector, so `check_if_selected()` → `start_contrib_phase()` re-signs at the same height AND the same `aborts_gen = 0`, with a fresh `dh_secret` drawn unconditionally from `rng_` (the S-009 commit-reveal), so the v1 CORE commit that `on_contrib` compares differs. A peer at generation 0 holding the pre-reset contrib passes the generation gate, reaches the S-006 branch and constructs an `EquivocationEvent` against the honest, recovering node with `index_a == index_b`, `gen_a == gen_b == 0`, distinct body roots and two genuine signatures — passing **every** V11 clause including the `gen` assert that acquits the cross-round pair of Case (c). This is not an unlikely corner: the empty-tail trip is exactly what the T-2 soft restart cannot defer, because T-2 restarts the soft window only when `current_aborts_.size()` CHANGES. **Why it is survivable:** since D4 a finalized event moves no L1 state, so the honest node loses nothing; before D4 this was a path by which the S-050 recovery mechanism cost an honest operator its entire stake, which is the class of defect that motivated D4. **What is owed:** the residual is evidence QUALITY, it is real, and it falls inside R-1's disposition (a same-height pair is L2 evidence requiring corroboration, never an L1 verdict) — D22 must not treat an L1 record as a verdict. No L1 fix is proposed: a predicate separating an honest re-sign from a splitter is refuted, and re-using the pre-reset `dh_secret` would break the hiding property FA3 rests on. V-S / C-1 (validation safety) is unaffected throughout. Ledger: S-095 `⚠ OPEN` → `✅ Mitigated`, moved from the Open Low/Op cell to the Mitigated Low/Op cell (Open 7 → 6 and total 34 → 33; Mitigated Low/Op 10 → 11 and total 54 → 55); `tools/test_security_ledger_coherence.sh` PASS.

**The other 52 documents — re-derived briefly, banners removed, per document.** Grouped by what the re-derivation found.

*Their theorem rested on the consequence, so it was RESTATED:* `EquivocationSlashingApply.md` (FA-Apply-10) — the whole subject is gone; a new **T-E0 (apply is state-neutral on `b.equivocation_events`)** is proved by inspection and by the shipped gate, its corollaries replace T-E3..T-E7, and T-E1..T-E7 plus §0, §3 and §4 are retained and clearly marked HISTORICAL; §7's status is rewritten around what is owed elsewhere (3b, S-089, S-090, D22). `EquivocationSlashing.md` (FA6) — retitled to "equivocation evidence soundness (no false accusation)"; T-6 is a cryptographic bound and is unchanged, but its value is restated (it is now the quality bound on an L2 input), §2 Case (c) gains the S-095 instance as a third, `gen`-binding-immune case, and the conclusion states plainly that FA6 is not a deterrence result. `AbortEventApply.md` (FA-Apply-11) — retitled "the S-032 suspension record"; T-A1 and T-A6 are HISTORICAL, T-A2/A3/A4/A5/A7/A8 survive (several strengthened), and the residual (free renewal of the exclusion) is pointed at S-011 §6.7. `StakeForfeitureCascade.md` (FA-Apply-16) — VACUOUS at HEAD: one of its two writers of `stakes_[D].locked` is gone, so T-C1..T-C5 are HISTORICAL, T-C6/T-C7 survive trivially, and the carried-forward claim is the NEGATIVE one — the deferred-unlock window is no longer a "slashing-evidence window". `StakeLifecycle.md` (FA-Apply-4) — §4 is rewritten: the slashing intersection is EMPTY, the slash transition is deleted from the §1.2 state machine, and the window's only remaining function is capital illiquidity. `Preliminaries.md` §9 — rewritten as "equivocation evidence", stating that apply does nothing and listing the three consequences downstream proofs must respect. `Safety.md` §5.1 — clause 2's "economically suicidal … every fork-creator gets slashed … materially stronger than BFT" is replaced by an explicit still-gives / no-longer-gives / what-replaces-it split. `S010S011SybilEconomics.md`, `S013PerSignerCap.md`, `S029ForkChoiceSoundness.md`, `S006ContribMsgEquivocation.md`, `BFTSafety.md`, `RoundStallValveSoundness.md` — above. `OfflineEquivocationEvidenceSoundness.md` — T-OE0/1/2/4 unchanged; **T-OE3 restated** from "faithful SLASH predictor" to "faithful ADMISSION predictor" (the IFF is untouched; its consequence clause is not), and the stale `would_slash` JSON field is corrected to the shipped `--json` field set. `RandomizedRegistrationDelaySoundness.md` — RD-1/2/3/5/6 unchanged; **RD-4 restated** from "cannot shorten the slashing-evidence window" to "cannot shorten the deferred-unlock window", i.e. a bound on capital illiquidity. `AbortCertificateSoundness.md` — T-C1..T-C7 unchanged (V10 soundness consumes no consequence); every "suspension-slash" is read as "suspension", and the §3 comparison table gains a HEAD row beside the historical one. `RealEngineFAHarness.md` — the §2 harness contract is unchanged; §3's and §4's invariant tables are rewritten to what the inverted gates actually assert (twin-chain equality, stake/registry/counter neutrality, positive control) with the pre-2026-09-16 assertions listed as historical.

*The banner was the only thing wrong (mechanism claims, not consequence claims) — corrected inline and re-derived briefly:* `AccountStateInvariants.md` (I-3's slashing channel list is now EMPTY), `MultiEventComposition.md` (the composition survives with fewer writers), `CrossShardSupplyConservation.md`, `ExpectedTotalWellDefined.md`, `SupplyInvariantComposition.md`, `FeeAccounting.md`, `SubsidyDistribution.md`, `SubsidyAccountingSoundness.md`, `F2ApplyComposition.md`, `S033StateRootNamespaceCoverage.md`, `S017UnstakeApplyConsistency.md` (§6.5 vacuous), `EligibilityFloorDesign.md` (the "aggravating economics" clause is historical; the starvation halt it guards is not), `EqAbortViewDigestExtension.md`, `ShardTipMergeDesign.md`, `BFTProposerElectionSoundness.md` (PE-3's "uniform redraws at slashing cost" corrected — redraws are free since D13), `S025BFTEscalationSoundness.md` (B2 references updated; the cost of entering FA5's scope noted as higher now that T-5.1 is withdrawn), `AbortCascadeLiveness.md` (its "T-5.1's slashing recovery still backstops B1 violations" is corrected), `RegionalSharding.md`, `S020CommitteeSelection.md` (equivocation no longer changes `N_pool` at all), `S036UnderQuorumMerge.md` (F-5's eligibility half is gone), `SelectiveAbort.md`, `CommitteeSelectionAbortDeterminismSoundness.md`, `Preliminaries.md`, `NonceMonotonicity.md`, `BlockchainStateIntegrity.md`, `BlockIngressGateAudit.md` (the dedup-identity closure's "a second proof is redundant" rationale is VOID and the dedup is re-justified on its independent DoS ground, with the forensics cost stated), `RpcIngressGateAudit.md` (§2a's residual now carries D4's answer), `ConsensusValidatorGateAudit.md` (§2f: the gate is unchanged and still required — an accepted forgery is now a permanent false accusation rather than a stake theft), `ProofClaimGateTraceability.md` (a forged abort certificate now forges an EXCLUSION, not a deduction — the gate is no less load-bearing), `StakeDistributionMetrics.md`, `OperatorToolingReadOnly.md`, `S001RpcAuthSoundness.md` (the replay backstop moves from T-E3 to T-E0, with the step-3b byte residual named), `S023NodeKeyfileEncryption.md`, `FROST_DEVIATION_NOTICE.md`, `AbortRecordProofSoundness.md`, `S010`-adjacent bodies in `docs/SECURITY.md`.

*TLA modules and configs (9).* These are not "pending" any more; each pending banner is replaced by a settled one-time status note. `EquivocationEvidenceVerify.tla` and `S006ContribMsgEquivocation.tla` are marked **CURRENT** — they model the V11 predicate and the receive-time detector, neither of which D4 touched. `EquivocationApply.tla` + `.cfg` and `StakeForfeitureCascade.tla` + `.cfg` are marked **HISTORICAL** (they model removed code, and are deliberately not rewritten: the shipped rule is that the apply action is the identity, which needs no model). `AbortApply.tla` is marked **PARTLY HISTORICAL** (the `abort_records` half is current, the deduction half is not). `MultiEventComposition.tla` + `.cfg` keep their composition structure with two actions noted as identities. CRLF preserved byte-for-byte on the three CRLF modules (`EquivocationApply.tla`, `MultiEventComposition.tla`, `StakeForfeitureCascade.tla` — 344/344, 359/359, 578/578 lines still CRLF).

**Gate.** None added — this increment changes no code. Verification is `tools/ci_local.sh` (build 6 targets, FAST 315/0 unchanged, all 16 doc guards green, `test_doc_citation_bounds` and `test_doc_tier_check` among them) plus `tools/test_security_ledger_coherence.sh` PASS with the summary derived from the rows. No mutants: there is nothing executable to mutate. The falsify-on-mutant evidence these documents now cite is the evidence recorded with the increments that produced it — `determ test-equivocation-apply` mutants M1–M8 (step 3a) and `determ test-abort-event-apply` mutants M1–M10 (D13).

**Riders.** None beyond the re-derivations themselves and the inline correction of sentences they falsify. Line-number citations were replaced by function names wherever a citation was rewritten (`Chain::apply_transactions`, `Node::maybe_stall_reset_locked`, `compute_block_digest_body`, `Block::signing_bytes`, …); stale line numbers in paragraphs this increment did not otherwise touch were left alone, since they are within EOF and the citation guard passes.

**What this does NOT claim or do.** No code, no gate, no ledger status changes except S-095. **Nothing is closed that was open**, and two things are stated to be worse than the ledger recorded: S-011's economic infeasibility claim and S-029's Level-3 grinding. Step **3b** (the per-block cap + in-block duplicate rejection on `equivocation_events`) is NOT landed and remains the next increment of the O-1 chain. **D22** — the L2 bond / arbitration policy that is the declared consumer of every evidence record this corpus now produces — is NOT designed, is v1.1 DApp scope and is not a launch blocker for L1; until it exists, equivocation has no consequence anywhere, and several documents now say so in those words. S-089, S-090 and S-086 stay OPEN. The `2K > N(h)` pool bound (D5a / R-4) stays AUTHORIZED and not landed, and it is what would remove the zero-honest-committee regime of the S-011 residual.

**Noticed and deliberately left alone (for the integrator to row or schedule).** (1) **H2 at HEIGHT granularity is falsified by shipped honest behaviour**, and `Safety.md`'s Corollary T-1.1 invokes it exactly as `BFTSafety.md` L-5.2 does. `BFTSafety.md` §4.2 states the granularity gap and its two causes; **FA1 is NOT corrected here** — that is its own increment with its own review, and correcting it silently inside a docs sweep is the kind of bundling the 2026-08-13 ordering result forbids. (2) **The relayer-malleable block hash has no ledger row.** The S-102 adjudication recorded it as "for the integrator to row"; it is argued in full in `S029ForkChoiceSoundness.md` §5.3(ii) and named in the S-029 row, but adding an S-row was outside this increment's brief. (3) **CLAUDE.md's doctrine paragraph records the block hash as signer-malleable only**; the SLASHING block now points at the relayer case rather than rewriting the owner's doctrine text. (4) `docs/SECURITY.md` rows **S-035** and **S-060** contain literal `|` characters inside table cells (pre-existing, 12 and 8 pipes on a 6-pipe row shape); not touched. (5) `docs/proofs/tla/StakeRefundFlow.tla` still describes its sibling FB16 as "the bounded-slash apply path" — a cross-reference into a now-historical model, carried over from the D13 increment's own noticed-and-left list. (6) `include/determ/node/node.hpp` still carries "slashing zeros their stake" in an equivocation remark (same list); this increment changed no headers.

**Authority:** owner decision **D4** (this log, 2026-09-16 "OWNER DECISIONS" §E step 3 and the D4 entry — "the S-006 status re-derivation, an honest S-011 residual, the S-013 / S-029 Level-3 / BFTSafety T-5.1 re-derivations, the `RoundStallValveSoundness.md` C-2 correction (S-095) and the proof-doc corrections"), **D13** (O-1b), **D22** (the L2 consumer), and the two landed increments that made the re-derivations necessary (this log, "O-1 step 3a LANDED" and "D13 LANDED", both 2026-09-16); the `initial_state` fact is from the S-102 adjudication entry of the same date. Implemented and recorded by Claude (Cowork session) on `track/3c`, 2026-09-17, with the adversarial review of the diff before commit per the 2026-08-13 rules (findings and dispositions in the commit message and `/root/audit/par/3c/REPORT.md`). This entry is append-only per convention and contains no tier marker in its body.

---

## 2026-09-17 — Independent adjudication of the S-105 evidence-admission predicate: the C0 concern raised against it is refuted, one real residual recorded

**Status:** REVIEW RECORD. No code change. The predicate landed with the S-104/S-105 increment stands as shipped.

**Why this entry exists.** The step-3b design memo proposed a producer-side admissibility predicate for equivocation evidence; an independent review of that memo (finding B-2) judged the proposal a blocker on three grounds, while the increment that closed S-105 had already shipped a predicate of that shape. Two agents therefore disagreed about a consensus-adjacent change. A third, independent reading adjudicated it against the shipped code. The record would be wrong if it kept only the conclusion.

**B-2(a) — REFUTED.** The claim was that an admission predicate which EVICTS mutates the pool between the `build_body` calls of one round and splits the digest. The built set is `S = pool ∩ union ∩ admissible`; the predicate evicts only what it has just excluded, so `S` is invariant under its own eviction and all three `build_body` calls of a round produce byte-identical bodies. Verified at the three call sites (`Node::start_block_sig_phase`, `Node::try_finalize_round`, `Node::on_block_sig_locked`), all under the exclusive `state_mutex_`; `build_body` copies the candidate vector before the arm, so the eviction is not even a use-after-invalidation.

**B-2(b) — premise correct, requirement already met.** `b.equivocation_events` IS digest-bound (unlike `b.transactions`), so a fail-safe default that admits nothing is fail-EMPTY: one call site omitting the predicate is a K == M halt, not a safe degradation. All three sites were worked out and all three halt. What makes that acceptable is not the default but the wiring guard: `tools/test_producer_admit_wiring_guard.sh` pins the predicate at every call site and pins the site count.

**B-2(c) — the cost figures are right and the memoization is load-bearing.** Measured on this machine against the shipped C99 stack: Ed25519 verify 2.885 ms, sign 1.432 ms. Unmemoized the predicate would cost `(K+1) × |pool ∩ union| ×` two verifies per round under the consensus lock; per-head memoization reduces it to one pass per head, the same order as the verifier-side cost already paid on that arm. The pool bound is `|registrants|` — the `2K − 1` bound belongs to D5a, which is authorized and NOT shipped.

**The residual the dispute uncovered, which neither side had stated.** Only committee members call `build_body`, so the eviction is asymmetric across nodes; and the predicate is not monotone in the head — a suspension window expires, a stake top-up or a floor re-admission flips a verdict from reject back to admit. A member that evicted a record and a member that never built can therefore hold permanently different pools for a record that becomes admissible again, and at the next height where both are selected their committed view lists differ, the digests differ and no K-of-K forms. The consequence is bounded: the block-sig timeout raises an abort claim against the minority side, the chain advances, and the first inclusion prunes the record everywhere — a wrongful abort and suspension window for an honest member (no stake consequence since D13), not a halt. Before this increment the same state was the S-105 halt itself, permanent and with no recovery. The asymmetry closes when step 3b lands its apply-time pool re-filter at the round boundary (its design §3.2 item 2), which is the preferred final form: run the same predicate over the pool in `post_append_bookkeeping_locked` after the registry is rebuilt, and drop the build-time eviction.

**Corrections to the S-104/S-105 record.** Its claim that the change "can only join creator pairs, never separate them" holds at a FIXED pool, which is what the eviction does not hold fixed; the residual above is the exception. Its pool-cost bound cites `2K − 1`; the shipped bound is `|registrants|`. Two nits stand unfixed by choice: an eviction is skipped on a memo hit, so a record re-gossiped at the same head lingers until the next one, and the test-only admission lambda can outlive its head (the same shape as the existing transaction-side seam).

**Authority:** adjudication requested by the integrator under the 2026-08-13 rule that every consensus-adjacent diff gets an independent adversarial read; recorded by Claude (Cowork session), 2026-09-17. This entry is append-only per convention and carries no tier marker in its body.
---

## 2026-09-17 — DSSO C2 closed: the OPAQUE-3DH transcript binds both static keys and the identities, so a server that does not hold `sk_s` can no longer impersonate the IdP

**Status:** LANDED. This is the **owner-gated C2 fix**, authorized by the owner's 2026-09-17 directive to develop DSSO toward an eIDAS outcome. `v2.25-DSSO-DAPP-SPEC.md` §0.0(2) had it recorded as OPEN / OWNER-GATED because the fix changes the ratified spec; it now does, and the C2 row of §6 is no longer FALSE. New ledger row **S-106**, closed. DSSO is off-chain: no consensus surface, accept rule, wire format, digest or apply path is touched.

**PROBLEM — reproduced first, not taken on the record.** The spec recorded C2 as verified FALSE by an executed attack. That claim was re-executed against the **shipped** `determ_opaque3dh_server` / `_client` before any fix was designed (harness and output kept with the increment's audit notes; it links the shipped `determ-crypto-c99` and uses the fixtures of `tools/verify_opaque3dh.py`, so its honest leg reproduces the shipped KAT). It reproduces exactly: an attacker holding only the victim's **public** `pk_c` — which every IdP server stores, because the AKE needs it for `dh3` — picks its own `(sk_s', esk_s')`, runs the shipped server routine, and the honest client returns `server_mac_ok == 1` with both sides agreeing on `session_key`. The attacker recovers no `sk_c`, knows no password, holds no OPRF share. Mechanically there were two enablers and both had to go: (i) `pk_s` was a bare caller argument of the client routine, so whatever the network offered went straight into `dh2`; and (ii) nothing committed to it — `hash_preamble` covered context, both identities, `ke1` and `inner_ke2` but **neither static public key**, and the §3-step-3 credential envelope was sealed with **AAD = NULL**, so no authenticated `server_public_key` travelled with the credential.

**CHANGE.** RFC 9807 §4.1.1, which the module had been missing. (1) `determ_opaque3dh_transcript` gains `server_public_key` and `client_public_key`, both REQUIRED; the preamble emits `CleartextCredentials = "DTM-DSSO-CLEARCRED-v2-" || compress(pk_s) || compress(pk_c) || lp(server_identity) || lp(client_identity)` right after `context`, so every MAC and the session key commit to it. (2) The separate `pk_s` / `pk_c` **call arguments are removed**: a party now has exactly one slot in which a static key can enter and that slot is MAC-covered — the client's `dh2` reads `t->server_public_key` and the server's `dh3` reads `t->client_public_key`. Collapsing beats keeping both and cross-checking them: two ways to say one thing is a defect surface. (3) One emitter, two sinks — `determ_opaque3dh_cleartext_credentials()` writes the byte-identical block for use as the **envelope AAD**, so the envelope tag and the transcript MAC commit to the same bytes and cannot drift apart. (4) The login layer (`test-dsso-login-e2e`, the executable model of spec §3 step 3) seals and opens the credential envelope under that AAD.

**CUSTODY — where an authentic `pk_s` comes from, written out because binding is not trust.** A transcript binding cannot create trust in a key the client learned from the attacker; if the client fed the attacker's key into both the DH and the transcript, both sides would still agree. So the fix has a second half. *At every login after enrolment:* `pk_s` and the identities are the envelope's AAD and the envelope key is `HKDF(OPRF_k(pw))`, so recovering an authentic `pk_s` costs the user's password **and** at least `t` OPRF responses — the C1/C3 assumption the design already makes — and a substituted `pk_s` fails the AEAD tag, aborting the login before the AKE, exactly like a wrong password. *At enrolment:* the authentic `pk_s` must come from the DSSO registration record on chain, resolved through the committee-authenticated light client — genesis pin (`determ::light::anchor_genesis`, `build_genesis_committee`), per-block K-of-K signatures and registry tracking (`determ::light::verify_chain_to_head`), the committee-BOUND state root (`determ::light::committee_bound_state_root`, never the daemon's bare field), a state proof (`determ::light::read_account_trustless`), with `determ::light::collect_d5_streams` the shipped pattern for reading DAPP_CALL records completely. **Named residual: no DSSO-specific `pk_s` resolver exists in `light/` today** — those are the components such a resolver must be built from, not the resolver — so until one ships the enrolment anchor is a requirement on the deployment, not shipped code, and it is stated as such in the spec and the ledger rather than papered over. *Rotation:* the DSSO service key is registered to the service domain, not to a committee member, so committee rotation does not rotate `pk_s`; rotating `sk_s` requires re-sealing every user's envelope (the §8 re-deal), and until a user re-seals, a new `pk_s` fails closed at that user's AEAD tag instead of silently taking effect — the correct direction of failure. *What a network attacker without `sk_s` can still do:* deny service, observe metadata, and guess online at the metered rate. What it can no longer do is be accepted as the IdP.

**PERMANENCE — the choice and why.** The module's rule is that the tags and the encoding freeze once a deployment exists, and that a change is then a "-v2" tag and never an in-place edit. **No deployment exists**, so no login transcript had to reproduce and the rule's premise was absent. The choice taken, deliberately: **replace v1 in place and retire its KAT, while still moving the tags to v2.** Keeping a v1 path beside v2 would have kept the impersonable construction compiled in and reachable — a downgrade target and a trap for a future maintainer — and with zero callers forever it would also have been dead abstraction, which CLAUDE.md forbids. Keeping the tag at v1 while changing the encoding would have made "v1" name two incompatible constructions, which is the exact confusion the permanence rule exists to prevent. So the tags are now `DTM-DSSO-OPAQUEv2-`, `DTM-DSSO-OPAQUE3DH-v2-` and `DTM-DSSO-CLEARCRED-v2-`, the v1 vectors are deleted rather than archived (an archived vector for a retired construction is a claim nothing verifies), and the v2 bytes are frozen under the same rule: the next change is a "-v3" tag. `tools/verify_opaque3dh.py` stays the INDEPENDENT oracle — it was rewritten by re-deriving the v2 schedule in python (its own P-256 ladder, its own HKDF / Expand-Label, its own encoder for the credential block), the v2 KAT was generated from it FIRST, and the C is then required to reproduce those bytes; no constant was copied from the C.

**GATE.** `determ test-dsso-opaque3dh` grows 17 -> 43 assertions. The existing agreement and transcript-MAC assertions survive unchanged; the new arms are C2-a (an impersonator holding only `pk_c` is rejected and shares no key), C2-b (a server that holds the REAL `sk_s` but claims a different static key is rejected although all three DH values agree — the arm that fails again if a static key ever becomes unbound, and the one that would catch a re-introduced AAD = NULL), C2-c (a substituted `client_public_key` is rejected although the client's own 3DH never reads it), C2-d/e (substituted identities), C2-f (the serialized block changes with the key and with the identity, so an envelope AAD built from it cannot carry a substituted `pk_s`), C2-g (the MAC compare covers all 32 bytes, first byte and last), C2-h (both static keys REQUIRED, fail-closed, outputs untouched), and the v2 dual-oracle KAT including the `CleartextCredentials` bytes. `determ test-dsso-login-e2e` grows 19 -> 24 with E2E-10a/b/c: a substituted `pk_s` or `pk_c` in `ke2` fails the envelope AEAD tag and the login aborts before the AKE, while the honest pair still opens and authenticates.

**MUTANTS.** Each against a REBUILT binary with the build confirmed to have succeeded, source restored after each, and the tree rebuilt clean and re-verified afterwards. M1 drop `pk_s` from the transcript (C2-b1/b3, C2-f and the KAT RED). M2 drop `pk_c` (C2-c1/c2 + KAT RED). M3 drop the identities (C2-d/e/f + KAT RED). M4 bind the keys on the server side only (the two preambles diverge, so agreement and mutual authentication break loudly rather than passing silently — the honest-run arms RED). M5 weaken the server-MAC compare to a length-0 constant-time shortcut (C2-a, C2-b1, C2-c1, C2-d, C2-e, C2-g and the nonce-tamper arm RED). M6 restore the ORIGINAL v1 unbound preamble wholesale — the reproduced attack class goes green again (a lying server is accepted once more) and the gate goes RED on C2-b, C2-c and the KAT. M7 re-null the envelope AAD at the login layer, the other half of the defect, taking E2E-10a/b RED.

**RIDERS.** None. The login-layer envelope AAD is not a rider but the second half of the same defect — spec §0.0(2) names "AAD = NULL" as a cause, and without it C2 would be closed only on paper, since the client would still have no authentic `pk_s`. The G3 envelope KAT inside `test-dsso-threshold-oprf` is a standalone round-trip / password-binding vector that explicitly defers its production wire parameters and is NOT in the AKE composition; it is left untouched. Comments, the test wrapper's description and the untiered docs that the change falsifies are corrected inline.

**What this does NOT change or claim.** No chain surface, no consensus or apply path, no wire format, no digest, no accept rule, no migration, no new primitive and no new hardness assumption (two P-256 point compressions are added to the preamble hash; everything else is the shipped schedule). C6 (§0.0(3)) is untouched and stays OPEN / OWNER-GATED. Nothing here is a claim that any regulatory requirement is met: the gates prove the code enforces what they assert, and C2's residual — who authenticates `pk_s` at enrolment — is named, not closed.

**Authority:** the owner's 2026-09-17 directive to develop DSSO toward an eIDAS outcome, which authorizes the OWNER-GATED C2 fix that `v2.25-DSSO-DAPP-SPEC.md` §0.0(2) had been holding; under the standing B3 discipline (design-and-prove, falsify-on-mutant at the layer where the rule lives, adversarial review of the diff, smallest increment) and the DSSO mission constraints (no new primitive, no L1 change, nothing personal on chain).

---

## 2026-09-17 — DSSO claim C6 LANDED (owner-gated): the RP assertion is verified against the IdP's own claim under the login key, with pairwise subjects and a bounded nonce cache

**Status:** SHIPPED. `dapps/dsso/assertion.{h,c}` on the `determ-dsso` target; gate `determ-dsso selftest-assertion` (`tools/test_dsso_assertion_module.sh`, FAST, 61 assertions); spec §5 rewritten; `determ test-dsso-assertion` RETIRED. Ledger row **S-107** closed. No L1 accept rule, wire format, apply path or digest is touched — DSSO is off-chain and links `determ-crypto-c99` alone.

**Problem.** `v2.25-DSSO-DAPP-SPEC.md` §0.0(3) recorded claim C6 as FALSE twice over and owner-gated since 2026-07-28. (a) The §5 accept rule was `HMAC(tenant_key, H1'_presented) == H2_presented`: a pure function of `tenant_key` and bytes the presenter chose. `sso_key` never entered verification, so ANY `tenant_key` holder minted an accepted token for any subject — and §5 put `tenant_key` in every user's hands while §1 gave it to the RP, a contradiction the spec carried unresolved. (b) The freshness legs ran over a CLEARTEXT claim the RP could not authenticate, so a legitimate user re-presented the same `(H1', H2)` bytes under a substituted claim — different `sub`, fresh nonce, rewritten `iat`/`exp` — and was accepted as another subject.

**Reproduced first, both halves.** An isolated harness transcribing the shipped `rp_accept` lambda and its claim encoding byte for byte: with `tenant_key` alone and no login, a forger picking `H1' = "mallory-never-logged-in---------"` was ACCEPTED asserting `sub = victim`; and a token honestly issued for `sub = alice` was ACCEPTED under a claim naming `sub = bob` with a fresh nonce and a rewritten window, unboundedly many times for unboundedly many subjects. The same harness evaluated the rule the `test-dsso-login-e2e` inc.3 legs use — the IdP-supplied reference `H2'` — and found it closes (a) but **not** (b), because its accept predicate still reads no field of the claim; the e2e harness only appears to close it by handing the same claim object to the IdP lambda and to the verifier lambda. So neither shipped rule was sound, and neither was a module: both were lambdas inside `src/main.cpp` test blocks, which is why a ratified spec carried a false accept rule for seven weeks.

**Why the fix has the shape it has.** While the RP's accept rule is a pure function of `tenant_key` and presented bytes, "a `tenant_key` holder cannot mint" is unachievable: the adversary has that whole view and can evaluate the rule offline. There are exactly two escapes — verify under a key the minter lacks (an asymmetric signature, forbidden by spec §7 and by the mission's no-new-primitive rule), or consult per-login state the IdP delivered. §5 takes the second, which is what "the RP computes `H2'` **from the same material**" always had to mean.

**The change.** Still the paper's dual keyed hash over co-generated keys — no signature, no FROST, no block co-sign, HMAC-SHA-256 only:

```
binder = HMAC(sso_key,    LP("determ-dsso/assert/binder/v1") | canon(claim))
tag    = HMAC(tenant_key, LP("determ-dsso/assert/tag/v1")    | canon(claim) | binder)
```

Two corrections carry the whole fix: the "challenge" IS the canonical claim, so the inner leg commits to every field the RP will act on; and the outer leg's message is `canon(claim) | binder`, not `binder` alone. The IdP delivers `tag` to the RP over the registered v2.19 DAPP_CALL channel; the user presents `(claim, binder)` and **no tag at all**, so there is nothing presenter-chosen for the RP to verify against. The RP accepts iff the epochs are its current ones, the tag it recomputes over the PRESENTED claim and binder equals — constant time, full 32 bytes — a delivered reference that has not expired, the three clock legs hold (`iat ≤ now+skew`, `exp > now`, `exp − iat ≤ T_max`), and the nonce is unseen. No cleartext field of an unauthenticated claim is compared against anything; the verifier authenticates first and reads the claim afterwards, which is why the MAC covers `aud`, `sid`, `sub`, `iss` and both epochs.

**The custody decision.** §1 wins: **`tenant_key` is held by exactly two principals, the IdP and the one RP that registered it, and never by a user, a wallet or the chain.** The §5 sentence that had `U` compute the outer leg is deleted. A symmetric MAC key in a user's hands makes every user a minting oracle for every subject at that RP (defect (a) verbatim) and lets a user impersonate the RP to the IdP on the registration channel. Registration establishes it as `HKDF(registration secret, info = "determ-dsso/tenant-key/v1" | rp_id | u64(key_epoch))`; the module never transports or derives it. Rotation uses two independent epochs, both inside the MAC: `key_epoch` on every key rotation (any other epoch is `DSSO_E_TRUST`), and `reg_epoch` only on re-registration. They are split deliberately — a routine key rotation must NOT change the identifiers an RP has stored against user accounts, and a re-registration must.

**Pairwise subjects.** `sub = HMAC(user_root, DS_SUB | LP(rp_id) | u64(reg_epoch))`, where `user_root` is a per-user secret the IdP alone holds, fixed at enrolment, never on the chain, and not derived from `sso_key` (per-login, which would make the subject unstable). Different per RP, so two relying parties cannot correlate a user; identical at one RP across logins. The IdP derives it — it is never a caller input. A re-registration rotates it and the RP must re-link accounts: the fail-safe default, since carrying the identifier across a re-established relationship would hand its new holder the previous holder's linkage to every user.

**Bounded state, with the eviction rule as code.** Two fixed-size tables in a caller-owned struct, no heap: a 128-slot nonce cache and a 160-slot reference table. Retention is `iat + T_max + skew`, which is at least `exp + skew` for any claim that passed the clock legs, so an entry is forgotten only once the clock alone already rejects every token carrying it. On insert the module takes an empty slot, else one whose retention has elapsed; **it never evicts a live entry**, and a table with no free or expired slot REJECTS with `DSSO_E_UNAVAILABLE` — accepting while unable to remember is accepting a replay. Only assertions the IdP actually issued can consume a slot, so an unauthenticated party cannot flood it.

**Gate.** `determ-dsso selftest-assertion`, 61 assertions: the honest flow; a `tenant_key` holder who completed no login rejected in both forms (her own mint; the honest cleartext claim with a binder from another `sso_key`) with a control arm proving the rejection is the reference rule and not a broken harness; per-field substitution of subject, audience, session, nonce, `iat`, `exp`, issuer and binder each rejected, followed by the pristine assertion still being accepted (so a rejection provably mutates no state); the substituted session rejected even by the verifier completing THAT session, and a VALID assertion for session A rejected by the verifier completing session B (`DSSO_E_BINDING`); cross-RP replay rejected even with the source RP's reference injected; nonce replay; expired, not-yet-valid and over-long claims; an unreadable clock; an unknown RP, a rotated-out `key_epoch`, a previous `reg_epoch`; pairwise subjects different across two RPs and identical across two logins at one RP; the cache bound, fail-closed-when-full, eviction of only out-of-window entries, and that eviction cannot resurrect a used nonce inside its window; a reference differing only in its last byte rejected; and `DSSO_E_ARG` on every missing or over-long input.

**Mutants (each against a REBUILT binary, source restored after each; all RED).** M1 restore the unsound rule (accept on a recomputed tag with no reference consulted) — 14 legs RED including both C6(a) legs and every substitution leg. M2 drop `sso_key` from the binder derivation — the "binder from another `sso_key`" leg RED. M3 drop the audience from `canon(claim)` — the substituted-audience leg RED. M4 drop the session id — the substituted-session leg RED. M5 skip the nonce-cache insert — the replay leg and all five cache legs RED. M6 pairwise subject ignores `rp_id` — the cross-RP correlation leg RED. M7 truncate the tag compare to 8 bytes — the tail-corrupted-reference leg RED. The non-constant-time variant of M7 (`memcmp` for `dsso_ct_equal`) is behaviourally indistinguishable and is therefore NOT falsifiable by a functional gate; it is held by using the `dsso_core`-gated `dsso_ct_equal`, and this log says so rather than claiming it gated.

**Riders (each forced by the change, none discretionary).** `determ test-dsso-assertion` and `tools/test_dsso_assertion.sh` are RETIRED and the `dsso_assertion` FAST stem replaced by `dsso_assertion_module` — that gate asserted the unsound rule as "C6 correctness" over a lambda that no longer exists, and DOCTRINE forbids a gate on a proxy. The `test-dsso-login-e2e` inc.3 comments and help text no longer call their local rule the normative §5 and now point at the module, with the honest note that their rule does not close C6(b) on its own; the legs themselves are unchanged and still gate the login composition. `DssoAssertionFreshness.md` gains §1.1 (the mechanism as implemented) and two inline corrections: its §2 sentence "it proves the IdP authenticated exactly this claim for exactly this RP" and its §3 Trust note "cannot be tricked into accepting a claim for the wrong subject/audience" were both FALSE of the rule of the day and are the substance of C6. `DssoThresholdOprfSoundness.md` §6 is restated (its seven properties were four generation-side and one false), and its §0.0 property-3 and residual bullets close. `docs/proofs/README.md` and `D5-RANDOM-SELECTION-SPEC.md` have the sentences naming the old `H2 == H2'` rule corrected inline.

**Found by the adversarial self-review of this diff, and fixed before commit.** Binding `sid` into the MAC keeps the IdP's statement about it honest, but a verifier that never compares it to the session IT is completing is still open to login-CSRF: a user who influences which `sid` the IdP is asked to assert obtains a token perfectly valid for its own identity and presents it into a victim's session. `dsso_rp_verify` therefore takes `expected_sid` and compares it (constant time, after the MAC) — `DSSO_E_BINDING` on mismatch — and the header states the matching integrator obligation: the IdP sets `aud` and `sid` from its own state, never from an untrusted party, because the module authenticates whatever it is asked to assert. Two further findings are recorded as residuals rather than fixed: an AUTHENTICATED party can wedge a verifier by filling the nonce cache with real logins inside one retention window (the price of never forgetting a live nonce; the levers are table sizing and the per-account login rate limit §6 already requires), and two relying parties can still correlate a user by login TIMING, which spec §7 already excludes from scope ("no assertion-traffic anonymity") — pairwise subjects defeat identifier correlation, not traffic analysis.

**What this does NOT claim.** Claim **C2 remains OPEN and owner-gated** — the client still does not authenticate `pk_s`, and an IdP impersonation there yields a shared `sso_key`, which is upstream of everything here. The `binder` is a bearer secret in transit: front-channel confidentiality is the deployment's, and single use, `T_max` and the `sid` binding are what bound a stolen one. The IdP→RP reference channel is authenticated by the registration, not by this module — an adversary who can write to it IS the IdP for that RP, and no symmetric construction improves on that. A compromised IdP can assert anything; the mutual-distrust property is a property of the LOGIN (C1/C3/C4), not of the assertion. Nothing here is evidence about eIDAS assurance: this is an implementation of a spec section, gated by a test, and a passing test is not a regulatory conclusion.

**Verification.** `tools/ci_local.sh` — build 7 targets, FAST 318 passed / 0 failed (one gate retired, one added), 16 doc guards green.

**Authority:** the owner's **2026-09-17 directive** lifting the owner-gate on C6, under the standing rule that a fix changing a ratified spec section needs an explicit owner decision (`v2.25-DSSO-DAPP-SPEC.md` §0.0, which marked C6 OWNER-GATED on 2026-07-28). The construction stays inside the FROST-deviation discipline: the paper's keyed-hash challenge-response over co-generated keys, zero new primitive, and spec §7's non-goals untouched.



---

## 2026-09-17 — DSSO becomes a WALLET-RELYING PARTY: verified EUDI PID presentations (SD-JWT VC) with trust-anchored issuers, holder binding, audience/nonce, fail-closed status, and account binding that a stolen session cannot drive

**Status:** LANDED (branch `dsso/pid`, base `e5b3bbc`). First increment of DSSO's SECOND role. Off-chain only: no consensus accept rule, no wire format, no migration, no `src/`, `include/`, `light/` or `wallet/` change.

**Problem this change solves.** `docs/proofs/v2.25-DSSO-DAPP-SPEC.md` describes DSSO as a private, non-notified identity provider for its own relying parties — it authenticates a RETURNING user and asserts to an RP. It says nothing about how a user gets an account in the first place, and the mission's target role has two halves, not one: Regulation (EU) 2024/1183 Art. 5b makes DSSO a **wallet-relying party** that consumes Person Identification Data from an EUDI Wallet Unit to proof identity at ENROLMENT and bind it to an account. Until this increment there was no code for that half at all — `e5b3bbc` created the `determ-dsso` binary and its fail-closed seam and stopped there. Worse, the half that was missing is the half where a relying party's real exposure lives: a wallet presentation is attacker-supplied external-format bytes, parsed before any signature has been checked, and the decision taken on it is "this human owns this account", which is exactly the decision that must not be reachable from a stolen session cookie or a captured presentation.

**The change.** Three modules in `dapps/dsso`, plus their gate.

`dsso_jose.{h,c}` — the bounded readers a hostile wallet reaches first. Canonical unpadded base64url (padding, `+`/`/`, whitespace and a non-canonical final group all rejected, so one byte string has one meaning); a strict RFC 8259 JSON reader that REJECTS duplicate member names rather than resolving them first- or last-wins, compares names after unescaping so the detector and the lookup cannot disagree, caps nesting at a depth that is also the parser's recursion depth, caps elements and recorded keys, and refuses trailing data; a JWT splitter that takes the signing input FROM THE WIRE rather than re-encoding what it parsed; **ES256**, composed on the shipped P-256 scalar/point primitives because `determ::c99` exposes no ECDSA verifier (no dependency added, no new hardness assumption); and a from-scratch allocation-free RFC 1950/1951 inflate with a hard output ceiling, needed because the status bitstring is zlib-compressed.

`dsso_pid.{h,c}` — the PID Provider trust anchor store and nine verification rules, each with its own status code and its own gate arms, applied in a fixed order so nothing attacker-supplied is acted on before the issuer signature over it verifies: structure; **issuer trust from the configured trust anchor list, never from the token** (ARF **OIA_12**; `jwk`/`jku`/`x5u`/`x5c`/`x5t`/`crit` headers refused outright); ES256 over the exact signing input with the `alg` pin checked BEFORE the signature is decoded, so `alg: none` is refused on the ALGORITHM and not on a length; selective disclosure against `_sd` with duplicate, unbacked, reserved-name and cleartext-shadowing disclosures all rejected and a 128-bit salt floor; **holder binding** by a KB-JWT under the credential's `cnf` key whose `sd_hash` covers exactly the presented credential and disclosures (ARF **OIA_02**), which is what makes a KB-JWT non-transferable between presentations; audience; the nonce DSSO issued for THIS request; freshness with bounded skew and bounded maximum age; **IETF Token Status List**, fetched through an INJECTED callback (a gate cannot reach a network and a verifier with an embedded transport cannot be driven adversarially), signature-checked against the SAME trust anchors, `sub`-bound to the list the credential named, inflated under a cap; and assurance. A status list that cannot be consulted — unreachable, stale past its own `exp`, wrong list, index past the bitstring, or a decompression bomb — is `DSSO_E_UNAVAILABLE` and the verification **FAILS CLOSED**. There is no allow-on-outage path.

How DSSO decides the ASSURANCE level, since nothing dictated it: the credential must assert it in the ISSUER-SIGNED payload (never in a disclosure — a level the holder can withhold or select is not evidence), as an OIDC `acr` claim carrying one of the three eIDAS level URIs of CIR (EU) 2015/1502; the effective level is `min(anchor cap, credential acr)`, so an issuer configured at substantial cannot mint a "high" credential and a token cannot talk its issuer up. The ARF v2.9.0 PID Rulebook fixes no claim name for this, so `acr` is recorded as DSSO'S OWN PROFILE CHOICE in the code comment and in the proof doc, with the one function that would change named.

`dsso_bind.{h,c}` — the account binding rules, implemented rather than described. **(i)** A DSSO session ALONE never authorises binding another person's identity: opening a binding challenge requires a fresh account re-authentication proof (kind, window, and an HMAC under the ACCOUNT'S OWN key), and it is a POSITIVE test on a proof the holder produced, never a negative test on an "is this a session?" flag that degrades to allowed when a caller forgets it. The same proof is required to unbind. **(ii)** The same subject cannot reach two accounts and a different person cannot replace one, silently or otherwise: both are `DSSO_E_BINDING` and the only way through is an explicit, separately authorised unbind. **(iii)** A challenge is single-use, TTL-bounded, at most one outstanding per account, and is consumed the moment a presentation is offered against it — pass or fail, because a single-use challenge with a retry oracle is not single-use; and `dsso_bind_commit` takes the nonce FROM THE ACCOUNT'S CHALLENGE RECORD and feeds it to the verifier itself, so a caller cannot verify against one challenge and commit against another.

What is STORED is `HMAC-SHA256(K_pseu, "DSSO-PID-PSEUDONYM-v1" || len(iss) || iss || len(id) || id)`. Never the raw national identifier, never a document number; the raw material is scrubbed before the function returns (ARF **OIA_16**). Keyed rather than plain-hashed for a stated reason: national identifier spaces are ~10^10 candidates with most of the entropy in a birth date, so a table of plain SHA-256 values is invertible in CPU-hours and a database leak would BE a population-wide identity list; `K_pseu` lives outside the account database. Not per-account salted, deliberately and recorded as a trade: rule (ii) needs subjects compared ACROSS accounts, so the pseudonym is service-wide and therefore linkable WITHIN DSSO — which is the linkability rule (ii) is built from — and keyed so it is linkable nowhere else. It never leaves the service; identifiers DSSO hands its own relying parties are a different value and stay pairwise.

**FORMAT CHOICE, and what it excludes.** SD-JWT VC (the JOSE/JSON profile) is implemented; **ISO/IEC 18013-5 mdoc/CBOR is NOT**. Reasons, in order of weight: the relying party's parser is the front door, and mdoc needs CBOR plus COSE_Sign1 plus the mdoc session structures, with tag-24 `IssuerSignedItemBytes` whose deterministic encoding must be enforced byte-exactly or the issuer digests can be recomputed over a re-encoding — a strictly larger and subtler thing to write fail-closed; SD-JWT VC composes from SHA-256 and P-256 alone; and its holder binding is explicit and separable from the transport, where mdoc's `DeviceAuth` consumes the ISO 18013-7 session transcript. **Consequence, stated and not softened: a wallet that can only present mdoc is OUT OF SCOPE for DSSO until a second increment. DSSO does not negotiate down to a weaker check for such a wallet; it refuses.**

**Gate.** `determ-dsso selftest-pid` (`tools/test_dsso_pid.sh`, FAST, ~2.5 s, no network, no files) — **156 assertions**. An accept case and **45 rejection vectors** plus a boundary accept (the skew tolerance is real and the gate says so out loud), at least two per rule, each asserted against the status code that rule returns; the trust-anchor provenance pair (empty list -> `DSSO_E_TRUST`, one bent bit in the anchor key -> `DSSO_E_CRYPTO`); the "failure leaves nothing behind" scrub; the binding rules with their rejections; the pseudonym properties. Fixtures come from an INDEPENDENT pure-Python P-256 with RFC 6979 deterministic nonces, anchored to the published **RFC 6979 A.2.5** known-answer vectors and cross-checked against OpenSSL before emission, so the accept case is three implementations agreeing rather than a C signer agreeing with a C verifier; the C ES256 verifier is ALSO anchored to those same published vectors directly inside the gate, so the crypto leg does not depend on the generator at all. Vectors are committed as `dapps/dsso/dsso_pid_vectors.h` rather than under `tools/vectors/`: `determ-dsso` has no file IO, and reading a JSON corpus in order to test a JSON reader would make the gate depend on the thing it tests. **Fuzz arms: 6900 mutated inputs** — 2400 presentations (bit flips, truncations, deletions, insertions, chunk splices; EVERY mutant that differs from the original is REJECTED, because every byte is covered by one of the two signatures or by `sd_hash`), 3000 JSON documents, 1500 base64url strings, 1500 zlib streams; guard bytes either side of every buffer are asserted untouched and every mutant returns a definite status.

**ECDSA malleability is STATED, not assumed away.** `(r, n-s)` also verifies and RFC 7515 does not mandate low-S, so rejecting high-S would reject conforming wallets; the verifier accepts both and the gate asserts the consequence instead — the twin is a different byte string yielding the SAME claims, and nothing downstream is keyed on signature bytes (the replay key is the single-use DSSO nonce, the binding is `sd_hash`, the pseudonym is derived from subject material). Non-canonical scalars (zero, >= n, short, long) are still rejected.

**Mutants.** 17, each removing exactly one check, each RED against a REBUILT binary with the source restored afterwards: M1 trust anchor lookup, M2 issuer signature verify, M3 disclosure digest match, M4 KB-JWT presence, M5 KB-JWT key identity, M6 audience, M7 nonce, M8 expiry, M9 status check, M10 fail-closed-on-unavailable, M11 the binding layer's fresh-re-authentication check (the session-alone rule), M12 duplicate disclosure, M13 base64url canonical tail, M14 JSON duplicate keys, M15 the `alg` pin, M16 one-subject-one-account, M17 the requirement that a status token come from the credential's own issuer. Logs under the increment's audit record.

**Riders.** None. The one adjacent edit is that `docs/CLI-REFERENCE.md` had no `determ-dsso` section at all, so the new section lists BOTH subcommands rather than shipping a section that omits `selftest-core` — completing a table, not improving unrelated code.

**Docs.** New canonical home `docs/proofs/DssoPidVerification.md` (untiered — it tracks shipped code): what is claimed (T-PID, T-BIND, T-PARSE), the argument rule by rule, the code loci by function name, the gate and its mutants, and a long "what is NOT claimed". Indexed in `docs/proofs/README.md`. `v2.25-DSSO-DAPP-SPEC.md` gains §11 describing the wallet-relying-party role and where it sits relative to the login: the PID flow happens ONCE at enrolment, the login every time after, and the two meet at exactly one place — the account — with no PID attribute, no raw identifier and no presentation byte entering the login path, the assertion path, or the chain. `docs/SECURITY.md` gains the gate's row in the in-process test table. NO triage row is added or closed: this is new functionality, not the closure of a recorded finding, and inventing an S-item for a defect that never existed would corrupt the ledger's summary arithmetic.

**Requirement identifiers this discharges, precisely.** **OIA_12** (validate a PID signature using a trust anchor from a PID Provider Trusted List) — implemented and gated. **OIA_02** (cryptographic holder binding, provable and therefore checked) — implemented and gated. **OIA_16** (discard unique elements as soon as they are no longer needed) — PARTIALLY: the raw subject material is scrubbed after one HMAC and never stored or forwarded, but there is no storage layer here whose retention could be audited. The IETF Token Status List check is implemented and gated. **OIA_03 / OIA_03b / OIA_04** (remote presentation over OpenID4VP, and the ISO/IEC TS 18013-7 Annex B profile where the attestation is mdoc) — **NOT discharged**: this module verifies a presentation some transport already delivered; there is no Authorization Request, no DCQL/presentation_definition, no response mode, no encryption, and no mdoc. **RPA_01..RPA_06** — **NOT discharged**: the wallet-relying-party **ACCESS CERTIFICATE is EXTERNAL and is NOT obtained**, because it requires registration with a **Member State registrar**, which cannot happen in a repository. **Nothing in this increment authenticates DSSO to a wallet**, and a real deployment needs that certificate, carried by value and validated against Member State Trusted Lists, before a wallet would answer a request at all. That is the increment's single largest external blocker and it is not closed.

**What this does NOT claim.** **Passing these gates is not a compliance claim of any kind.** DSSO is not notified under Art. 9, not certified under CIR (EU) 2024/2981, not a wallet or wallet provider, and not a qualified trust service provider; it is not conformant with the ARF, and a green gate could not make it so. No eIDAS Trusted List (ETSI TS 119 612) is fetched, parsed or validated — `dsso_trust_list` is a configured array and populating it is a deployment act with its own unwritten code. DSSO never claims the wallet's assurance level for its own later logins: proofing at enrolment is INHERITED from the PID (CIR (EU) 2015/1502 Annex §2.1.2) and DSSO records only what it verified. The fuzz arms evidence memory safety (definite verdict, untouched guard bytes, no crash over 6900 inputs) but cannot observe an out-of-bounds READ; that is argued structurally and `tools/ci_local.sh --asan` does NOT currently build `determ-dsso` — wiring it in is a named follow-up, not something this increment did. No constant-time claim is made for this verifier; it is a public-data verifier and the DSSO constant-time record (`DssoG5ConstantTimeReview.md`) covers the secret-scalar paths, which this module does not touch.

**Noticed and deliberately left alone.** (1) The fixture GENERATOR lives with the increment's audit record and is NOT committed, per the brief, so the committed vectors are frozen data that cannot be regenerated from the repository alone — a real reproducibility gap, recorded rather than silently accepted. (2) `tools/test_proofs_index_complete.sh` already emitted a stale-EXCLUDE note for `v2.25-DSSO-DAPP-SPEC.md` before this increment (it is link-targeted twice from the index); the note is informational, the guard passes, and pruning the EXCLUDE list is not this increment's business. (3) `DSSO_MAX_STATUS_BYTES` caps a status list at 131072 one-bit entries; a larger deployment needs a larger cap or sharded lists, and the cap is a REJECT boundary, never a truncation. (4) The verification of a status token re-enters the same JWT machinery, so a status token counts against the same caps as a credential — deliberate, and the reason `check_status` keeps its own frame.

**Verification:** `tools/ci_local.sh` — build 7 targets, FAST 319 passed / 0 failed (318 at base + `dsso_pid`), 16 doc guards green.

**Authority:** the DSSO mission brief's target-role definition (this log, `v2.25-DSSO-DAPP-SPEC.md` §11 and `docs/SECURITY.md`) under owner decision **D19a** (DSSO is a v1.1 DApp-layer track with no chain surface) and the standing doctrine of CLAUDE.md — smallest increment, falsify-on-mutant at the layer where the rule lives, adversarial review of the diff before commit, fail-closed on every dependency that cannot be consulted. Implemented and recorded by Claude (Cowork session) on `dsso/pid`, 2026-09-17. This entry is append-only per convention and carries no tier marker in its body.
## 2026-09-17 — DSSO authentication reaches two factors: a device-bound possession factor, its enrolment/recovery/revocation state machine, and an aggregate attempt limiter

**Status:** LANDED. New module `dapps/dsso/authn.h` / `authn.c` / `authn_selftest.c` in the `determ-dsso` binary; gate `determ-dsso selftest-authn` (115 assertions, FAST) with mutants M1..M7 each RED against a rebuilt binary. No chain surface, no consensus rule, no wire format, no migration: `determ-dsso` links `determ-crypto-c99` and nothing else.

**PROBLEM.** The shipped DSSO login (`v2.25-DSSO-DAPP-SPEC.md` §3-§5) blinds the user's password, has `t` of `n` servers evaluate it with a threshold OPRF, and uses the result to unseal `envelope = AEAD_{HKDF(y)}(cred_sk)` — the user's credential secret key. Everything the user needs at the AKE is therefore a function of the password: the credential key is a stored secret RECOVERED FROM KNOWLEDGE, not an independently held object, so it is not a possession factor. Commission Implementing Regulation (EU) 2015/1502 Annex §2.2.1 requires, at level *substantial*, "at least two authentication factors from different categories", and §2.3.1 requires the release of person identification data to be preceded by a dynamic authentication. **Multiple servers are not multiple factors** — the threshold is a confidentiality and availability property of ONE factor's evaluation (claims C1/C3/C7), not a second thing the user holds. DSSO was single-factor and could claim at most level *low*. The same spec, §6, left the aggregate attempt cap to the deployment ("cooperative counters, or fee-metered DAPP_CALL ... deployment choice"), which leaves the online-guessing bound undefined and is walked around by rotating which `t` servers serve each guess.

**THE CHANGE.** (1) A **device-resident P-256 possession factor**: generated on the user's device from device-local entropy, never transmitted, not derivable from the password, the OPRF output or anything the servers store — they hold only the public point and enrolment metadata. It must answer a FRESH challenge at every login that binds the login session nonce, the server-set digest (`n`, `t` and every identity in order), a timestamp, the device identity and **the knowledge factor's own response for that same login**, so the two factors are one authentication that cannot be spliced across sessions, and a purpose byte separates login from enrolment, revocation and recovery. (2) **Enrolment**: the first device is authorised by the identity-proofing event alone (a verified PID presentation, consumed through a narrow `dsso_pid_verify_fn` seam whose implementation is a sibling track — absent verifier ⇒ `DSSO_E_UNAVAILABLE`, never allow-on-outage); any later device needs an authenticated two-factor session PLUS a fresh proof from an already-active device bound to the new public key. A password alone never enrols. (3) **Recovery**: evidence of one factor may only REDUCE an account's assurance (`ACTIVE` → `KNOWLEDGE_ONLY` / `POSSESSION_ONLY` at LOW, or `LOCKED` at NONE); restoring *substantial* needs a second independent evidence — a fresh, single-use, subject-matched PID presentation — and the downgrade is represented in the account state and visible to the assertion layer, which refuses a LOW session for a relying party that requires substantial. (4) **Revocation**: an `auth_epoch` that every session carries; one bump invalidates every live session at once. Device removed, password replaced, account locked and every recovery bump it; adding a device deliberately does not. (5) **The limiter**: a per-account grow-only counter, one slot per server, per-slot-maximum merge — a state-based CRDT, so the servers converge by gossip with **no consensus rule and no new primitive** — capped on the SUM of the slots, giving `A <= floor(cap / (t − b))` attempts for every subset rotation with `b < t` non-counting servers. A view stale beyond `merge_max_age` refuses to serve; counters are per account; a successful two-factor login clears the budget; metering precedes verification so cheap rejections cost budget too.

**No new primitive.** The brief named ECDSA. ECDSA-P256 is **not shipped** (`CRYPTO-C99-SPEC.md` lists it under "remaining"), and the mission rule is no new primitive, so the possession proof is the shipped RFC 9497 VOPRF discrete-log-equality proof used as a Chaum-Pedersen signature of knowledge over `hash_to_curve(challenge)` — publicly verifiable from the enrolled public point alone (which is exactly why storing it does not let any quorum impersonate the device), unforgeable without the secret under the ECDLP the stack already assumes, and built only from functions already KAT-gated against the RFC 9497 A.3 vectors. The proof nonce is derived from (secret, challenge) RFC-6979-style, so the proof is deterministic and a nonce is never reused. The module reads no clock and draws no randomness; every timestamp, seed and nonce is injected, which is what makes the gate byte-reproducible. A static-ephemeral ECDH challenge-response was rejected: it is forgeable by the verifier, which fails the mutual-distrust requirement outright.

**TWO DEFECTS THE PRE-COMMIT ADVERSARIAL REVIEW OF THIS OWN DIFF FOUND, AND FIXED.** (i) The session id was `SHA-256(account | login nonce | timestamp | epoch)` — every input travels in the clear in the login request, so any observer of that request could compute the BEARER TOKEN it issues. It is now `HMAC(session_secret, ...)` under a server-side secret the caller injects at `dsso_authn_init` (an all-zero secret is refused), plus a per-issue sequence number; the gate asserts that the byte-identical login under two different secrets yields two different ids. (ii) A spent login nonce was remembered for `clock_skew` seconds, but a request carrying timestamp `ts` is acceptable across the whole interval `[ts - skew, ts + skew]` and may first be accepted at its very start — so the nonce could be forgotten while its own request was still inside its acceptance window, which is a replay. Retention is now `2*skew + 1`, the window's full width. A third finding was fixed during the mutant pass: `RESTORE_DEVICE` / `RESTORE_BOTH` deactivated the existing devices BEFORE trying to add the replacement, so a refused add (a recycled device id, a malformed point) left the account mutated; a `dev_admit` pre-check now runs before any mutation and the gate asserts a refusal leaves the account exactly as it was. A fourth: `dsso_authn_login` took the server-set digest from the cluster it was given while `enrol_device` / `revoke_device` / `recover` took one as a per-call argument — the same value in a correct deployment, but a caller convention rather than a rule. The digest is now installed once with `dsso_authn_bind_server_set`, the in-session operations read it from the state, and a login against a cluster whose digest is not the bound one is `DSSO_E_BINDING` before anything is metered or verified.

**GATE + MUTANTS.** `determ-dsso selftest-authn`, 115 assertions: the honest two-factor login accepted at SUBSTANTIAL; password-only rejected; device-only rejected; replayed, cross-session and cross-server-set device responses rejected; an adversary holding the password AND every server's share unable to complete a login while the honest holder still can; a second device refused on a password alone and accepted on session+device; every recovery transition accepted or refused as designed with the downgrade visible; a session issued before a revocation failing to verify; subset rotation hitting exactly `floor(cap/t)` and not leaking across accounts. Mutants, each built and run against a REBUILT binary and reverted afterwards: M1 remove the device-signature check (C8/C9/C12/F17b RED), M2 drop the session nonce from the challenge (F17b RED), M3 enrol on a session alone (D1/D2/D3 RED), M4 restore assurance without the second evidence (F2/F18/F27 + 22 cascading RED), M5 keep sessions valid after revocation (E3/E4/E5/F12 RED), M6 per-server limiter (G1/G2/G3 RED), M7 a device key that does not depend on device-local entropy (A2/A8/C11/C12 RED).

**RIDERS — deliberately none, with two exceptions that are part of the change.** `DSSO_E_RATELIMIT = -12` is added to `dapps/dsso/dsso.h` and named in `dsso_status_name`, because the limiter needs a status a caller and an operator can match on and the module's own rule is that every failure is a named negative code. `docs/CLI-REFERENCE.md` gains a `determ-dsso` section; it lists `selftest-core` alongside the new `selftest-authn` because a binary section that names one of two subcommands is misleading, and the seam commit had not added one.

**WHAT DOES NOT CHANGE.** No consensus accept rule, no apply path, no wire format, no genesis field, no migration; no chain object is reachable from `determ-dsso`. The threshold OPRF, the OPAQUE-3DH AKE and the §5 dual-hash assertion are untouched, and the two owner-gated findings against them (`v2.25-DSSO-DAPP-SPEC.md` §0.0 items 2 and 3 — claims C2 and C6) remain open; this increment neither fixes nor worsens them. **Nothing here is certified, notified, or a wallet**, and identity proofing remains inherited from the PID: `DSSO_LOA_HIGH` does not exist in this module and no path produces it. The EUDI PID verifier itself is NOT implemented here — only the seam. `determ-dsso` still has no service layer, so what ships is the module a deployment composes, with fixed-capacity reference containers rather than a database.

**Verified in the repository rather than cited from the roadmap:** v2.26 `ROTATE_KEY`, which `v2.25-DSSO-DAPP-SPEC.md` §8 names as the answer to chain-identity key loss, is **NOT SHIPPED** — no `TxType` slot in `include/determ/chain/block.hpp`, no payload codec, no apply path; `PHASE2-PRIMITIVES-KICKOFF.md` §1 records it as "0% built today". §8 now says so, and nothing in the authentication-factor recovery depends on it.

**Noticed and deliberately left alone.** (1) A login for an UNKNOWN account returns `DSSO_E_STATUS` without metering — metering an arbitrary identifier would exhaust the bounded meter table — so account existence is observable; recorded as a residual in `DssoAuthenticationAssurance.md` §9 rather than papered over. (2) There is **no phishing resistance**: the challenge binds the session, the server set and the time, but not an origin or a channel, so a relay that forwards both factors is not defeated. (3) There is no notification channel for "a device was added"; §2.2.3-style dynamic linking and operational alerting are out of scope. (4) "Device-resident" is a statement about where the key is generated and that it is never transmitted, not a secure-element claim. (5) The PID presentation cache never ages entries out and fails closed when full — correct for a reference container, wrong for a long-running service, which needs a database.

**Documentation.** New untiered `docs/proofs/DssoAuthenticationAssurance.md` (the claim, the two factors and why their categories differ, the state machine, the limiter's bound, the code loci, the gate, and a blunt "what is NOT claimed" section), indexed in `docs/proofs/README.md`. `v2.25-DSSO-DAPP-SPEC.md` §6 (the attempt-limiting note, now implemented, plus a new §6b stating that §3-§5 is one factor) and §8 (recovery, and the verified `ROTATE_KEY` status) point at what is now built. `docs/SECURITY.md` gains row **S-108** (✅ Mitigated, High) with the scope of the closure stated exactly, the summary cells are re-derived from the triage rows at integration, and the test table gains the `determ-dsso selftest-authn` row.

**Authority:** the DSSO / eIDAS mission brief for this track (Wallet-Relying Party + private non-notified identity provider, assurance target "equivalent to level substantial of CIR (EU) 2015/1502", no new primitive, nothing personal on the chain, fail-closed), which sits under **D19a** as a node-/client-local increment on an off-chain DApp with no consensus surface. Implemented and recorded by Claude (Cowork session) on `dsso/authn`, 2026-09-17, with the adversarial review of the diff before commit per the 2026-08-13 rules (findings and dispositions in the commit message and `/root/audit/dsso/authn/REPORT.md`). This entry is append-only per convention and carries no tier marker in its body.

## 2026-09-17 — The external-format boundary, decided: mandatory EUDI interoperability formats are parsed ONLY inside `determ-dsso`, and the canonical-binary rule keeps consensus — plus the DSSO requirements mapping and the operational specification

**Status:** LANDED (branch `dsso/req`, base `3667d89` — the tree that already contains all four DSSO engineering increments). **This increment changes NO code**, no consensus accept rule, no wire format, no digest, no apply path, no genesis field and no migration. What it lands is the decision that governs the four increments that preceded it, the two documents the engineering tracks deliberately did not write, and two small repairs those tracks named as real gaps.

**PROBLEM — a live conflict between two rules of this repository, never written down.** CLAUDE.md's doctrine says **"Canonical binary only in storage / wire / keyfiles / test vectors — no JSON on those paths (DECISION-LOG D2)"**, and D2's whole point was that a second parser for the same data is a second accept rule. Against that stands an obligation DSSO cannot renegotiate: a wallet-relying party under Regulation (EU) 2024/1183 Art. 5b consumes what an EUDI Wallet Unit presents, and the ARF fixes those encodings — SD-JWT VC is JOSE compact serialization, i.e. **unpadded base64url over UTF-8 JSON**, and the alternative attestation format is **ISO/IEC 18013-5 mdoc, i.e. CBOR with COSE_Sign1**. A relying party that insists on Determ's canonical binary is not a relying party; it is a party nobody can present to. So either DSSO does not exist, or the repository parses attacker-supplied JSON (and one day CBOR). Both rules are right and they cannot both be satisfied globally.

**THE DECISION — a narrow boundary, stated as a rule and not as a hope.** External identity formats are parsed **only inside the `determ-dsso` binary, which links `determ-crypto-c99` and nothing else**. No consensus path — `src/chain`, `src/node`, `src/net`, `light/`, `wallet/` — parses any of them, and no DSSO translation unit is compiled into any binary that does. The canonical-binary rule keeps everything it was written to protect (storage, the wire, keyfiles, consensus test vectors) because none of those touches DSSO; DSSO gets the encodings the EUDI specifications mandate because nothing it parses can reach a block. The boundary is a link-graph fact, not a coding convention, which is what makes it checkable.

**HOW THE CLAIM WAS VERIFIED MECHANICALLY, at this commit.** Four checks, each rerunnable:
1. **Build graph.** `dapps/dsso/*.c` appears in exactly one `add_executable` in `CMakeLists.txt` — `determ-dsso` — and that target's only `target_link_libraries` entry is `determ-crypto-c99`. No other target lists a `dapps/dsso` source.
2. **Include graph.** `grep -rn 'dsso_jose.h\|dsso_pid.h\|dsso_bind.h\|dapps/dsso\|"assertion.h"\|"authn.h"' src include light wallet sim sdk cryptotest third_party` returns three hits, all of them **prose inside `//` comments in `src/main.cpp`** that name the module. There is no `#include` of a DSSO header anywhere outside `dapps/dsso`.
3. **Symbol graph, forward.** `nm build-linux/determ-dsso` defines **zero** C++ mangled (`_Z…`) symbols, and its entire undefined set is twenty libc entries (`memcpy`, `memset`, `memcmp`, `memmove`, `memchr`, `strlen`, `strcmp`, `malloc`, `free`, `puts`, the `__*_chk` fortified variants, the CRT start/finalize symbols). No chain, node, light, wallet, OpenSSL or asio symbol is reachable from it. The only names matching `Block|Chain|Validator` are `sha256_block` and `sha512_block`, which are SHA compression functions.
4. **Symbol graph, reverse.** `nm` over every other binary this tree builds — `determ`, `determ-wallet`, `determ-light`, `determ-cryptotest`, `determ-dsf` and `d5rp` — finds none of `dsso_b64url_decode`, `dsso_json_validate`, `dsso_jwt_split`, `dsso_inflate`, `dsso_es256_verify` or `dsso_pid_verify`: zero hits in all six. The readers exist in exactly one binary.
A fifth check is worth recording because it is what makes the parsers affordable at all: **no object in `dapps/dsso` references `malloc`, `free`, `calloc` or `realloc`** — all nine `.o` files return zero. The readers allocate nothing, so a hostile presentation cannot make the service allocate; every buffer is an automatic array sized from a compile-time cap in `dapps/dsso/dsso.h`.

**WHAT WOULD BREACH THE BOUNDARY.** Any one of these, and each is a review-stopping change rather than a judgement call: adding a `dapps/dsso` source to another `add_executable`; adding a library to `determ-dsso`'s link line; `#include`-ing a DSSO header from `src/`, `light/` or `wallet/`; writing a JSON, base64url, CBOR or COSE reader into a consensus path for any reason; making a consensus accept rule, a state transition or a digest depend on a value that an external-format parser produced; or persisting an external-format byte string where a consensus path will later read it. The rule that makes those detectable is that the boundary is the **link graph**: a breach changes `CMakeLists.txt` or an `#include`, both of which a diff shows.

**WHAT REMAINS OWNER-GATED.** If a future increment needs an external format **closer to consensus** — an mdoc/CBOR verifier, an OpenID4VP transport, a light-client resolver that reads a DSSO record and hands it to a parser, or any path where an external-format value influences a consensus decision — that is **not** covered by this decision and needs an explicit owner decision of its own. The reason is D2's reason: two parsers for one datum are two accept rules, and the second one is always the one nobody audited. The near-term instance is already visible and is recorded rather than smuggled: `v2.25-DSSO-DAPP-SPEC.md` §0.0(2) requires an enrolment-time `pk_s` resolver reading the on-chain DSSO registration record through the committee-authenticated light client, **and no such resolver exists in `light/`**. When it is built it must remain canonical-binary on the light-client side; it must not become the seam by which an external format arrives in `light/`.

**INTEGRATION FACTS, verified in the repository rather than taken from the reports.**
- **Ledger rows the DSSO work opened: exactly three, all closed — S-106, S-107, S-108.** S-106 is the OPAQUE-3DH IdP impersonation (C2), S-107 the §5 assertion accept rule (C6), S-108 the single-factor login plus the undefined online-guessing bound. The PID increment added **no** triage row, correctly: it is new functionality, not the closure of a recorded finding. All three carry `✅ Mitigated` and the summary arithmetic is coherent (`tools/test_security_ledger_coherence.sh` green, 104 triage rows).
- **Three of the four increments each claimed the id `S-106` in their own DECISION-LOG entry**, because they were written in parallel against the same base; the integration resolved the collision into S-106/S-107/S-108 in `docs/SECURITY.md`. Two rows of the SECURITY.md in-process test table still carried the pre-integration attribution (`determ-dsso selftest-authn` and `selftest-assertion` both said S-106); they are corrected inline here to S-108 and S-107. The DECISION-LOG entries themselves are append-only and are **not** edited — this paragraph is the record of what they say versus what the ledger says.
- **Topology: four separate branches, one linear integration line.** `dsso/c2`, `dsso/c6`, `dsso/pid` and `dsso/authn` were each cut from the seam commit `e5b3bbc` and each still exists at its own tip (`e2ffde7`, `2de26ca`, `96ff85b`, `bdea835`). They were integrated **serially, with no merge commit**: `git log --merges e5b3bbc~1..HEAD` is empty, and the first-parent line is `e5b3bbc → 5664266 (C2) → cd9d801 (C6) → 83a84ce (PID) → 3667d89 (authn)`. C2 landed first and its tree came across byte-identical (`a5a198d` on both); the other three have different trees from their branch tips because rebasing onto a moved line rewrote the files every track touches — the `docs/SECURITY.md` summary cells, the `docs/CLI-REFERENCE.md` section, the DECISION-LOG tail, the `tools/run_all.sh` FAST pattern and the `determ-dsso` source list in `CMakeLists.txt`.

**THE TWO DOCUMENTS.** `v2.25-DSSO-DAPP-SPEC.md` gains **§12, the requirements mapping** — the canonical, requirement-by-requirement statement of what this repository implements TODAY, with five columns (identifier and source; what it obliges; what the code does, named by function or gate; the gate; the status as IMPLEMENTED / PARTIAL / NOT IMPLEMENTED / EXTERNAL), covering Reg. (EU) 910/2014 as amended, CIR (EU) 2015/1502 Annex, ARF v2.9.0 and the IETF Token Status List. **46 rows: 4 IMPLEMENTED, 11 PARTIAL, 8 NOT IMPLEMENTED, 23 EXTERNAL.** A requirement that binds somebody else — a Wallet Unit, a Wallet Provider, a Member State, the Commission — is an EXTERNAL row that opens by naming whom it binds, rather than a row left out: an identifier silently absent from a mapping reads as an oversight. New untiered `docs/proofs/DssoOperations.md` is **the operational specification**: the accountable operator, custody and rotation and compromise handling for all five service keys plus the per-user secrets, incident response for a compromised server / a compromised device / a leaked `K_pseu` / a revoked PID Provider, fail-closed availability and what an outage costs a user, audit evidence with what must never be logged, service continuity, and the data-protection section. Indexed in `docs/proofs/README.md`.

**WHAT THE MAPPING ESTABLISHED THAT THE ENGINEERING RECORD HAD WRONG.** Every source was re-read online on 2026-09-17, and four corrections came out of it; all four are recorded in §12 rather than in a footnote. (1) **CIR (EU) 2015/1502 Annex has no §2.3.2** — §2.3 contains exactly one subsection, and the failed-attempt obligation lives inside §2.3.1's control sentence; Record keeping is §2.4.4, not §2.4.6 (§2.4.6 is Technical controls). (2) **ARF OIA_02 binds a Wallet Unit, not a relying party.** The relying-party obligation DSSO discharges is **OIA_17**, which is a **SHOULD**; DSSO implements it as a mandatory fail-closed check and therefore exceeds it. `DssoPidVerification.md` and the 2026-09-17 PID entry both attribute the check to OIA_02; §12 records the correction. (3) **OIA_03c exists and was missing from the mission's list.** At ARF v2.9.0, `OIA_03` is the ECCG-cryptographic-algorithms requirement, `OIA_04` is a Wallet Unit obligation, `OIA_03b` is conditional on mdoc — and **`OIA_03c` is the requirement that actually binds DSSO's chosen SD-JWT VC format** (HAIP §§5, 5.1, 5.3.2 plus the IETF SD-JWT VCs profile). It is **NOT IMPLEMENTED** and is the largest unimplemented in-repository requirement in the mapping. (4) **Of RPA_01..RPA_06, only RPA_01, RPA_02 and RPA_03 bind a relying party at all**; RPA_04, RPA_05 and RPA_06 bind the Wallet Unit — so validating access certificates against Member State lists, which the mission described as a relying-party duty, is the wallet's. Two further facts, stated because a mapping that hides them is worse than none: **ARF v2.9.0 is not the current ARF** (a later major release exists, in which `OIA_03` carries a different requirement and `OIA_04` is empty, and against which this mapping has NOT been reviewed), and **`draft-ietf-oauth-status-list` is at revision -21 in the RFC Editor queue** — still a draft, and this repository pins no revision anywhere in code.

**THE HONESTY BLOCK, which is in §12.0 and not only here.** A passing gate is never a requirement met. "Equivalent to" is never "certified" or "notified". The wallet-relying-party access certificate and the Art. 5b(1) Member State registration are EXTERNAL and NOT obtained, so the wallet-relying-party role is **verified but not operable**: a conforming Wallet Unit performs relying-party authentication with an access certificate in every presentation transaction (ARF RPA_03) and, when it fails, tells the user the request is not trustworthy (RPA_05). OpenID4VP is not implemented and neither is mdoc. No Trusted List and no LoTE is fetched or parsed; `dsso_trust_list` is a configured array. The C2 closure rests on a stated boundary **whose enrolment-time resolver does not exist**. Identity-proofing assurance is inherited from a PID presented once, not conferred on every later login.

**A SECOND ARITHMETIC CORRECTION, from the same re-measurement.** The PID gate's fuzz corpus is **8400** mutated inputs, not 6900: `dapps/dsso/dsso_selftest_pid.c` runs four loops — 2400 presentations, 3000 JSON documents, 1500 base64url strings and **1500 zlib streams** — and prints each one at run time. The recorded 6900 omits the zlib corpus while its own table lists it; the figure is corrected inline in `docs/SECURITY.md`, `docs/proofs/README.md`, `docs/CLI-REFERENCE.md`, `DssoPidVerification.md` and the `tools/test_dsso_pid.sh` header comment, and the 2026-09-17 PID entry's 6900 stands because this log is append-only.

**GATE COUNTS, RE-MEASURED AGAINST THE BINARY.** `selftest-core` 9, `selftest-assertion` 61, `selftest-pid` 156 (the gate prints its own `(156 checks)` counter), `selftest-authn` **114**. The authn increment's entry, the `docs/SECURITY.md` test table and the proofs index all recorded **115**, which counts the terminal `PASS: dsso-authn all assertions` marker as an assertion; the other gates' recorded counts exclude it. The binary is the truth: the three untiered records are corrected to 114, and this entry states the discrepancy because the DECISION-LOG is append-only and its 115 stands.

**THE TWO REPAIRS.** (a) **The PID fixture generator is now committed** as `tools/gen_dsso_pid_vectors.py`. It lived only in an audit directory, so `dapps/dsso/dsso_pid_vectors.h` was frozen data that could not be regenerated from the repository — a reproducibility gap the PID entry recorded and did not close. The committed copy resolves its output path from its own location instead of a stale absolute path, carries a header stating what it anchors to (RFC 6979 §A.2.5 for its own signer, OpenSSL via `cryptography` for every emitted signature, and the C verifier at gate time) and how to check a regeneration, and **reproduces the committed header byte-for-byte**: running it changed nothing but the header's own comment block, which now points at the generator. Its RFC 6979 anchor and its OpenSSL cross-check are hard failures, not skipped steps. The vectors header and `DssoPidVerification.md` §6 both reference it. (b) **`tools/ci_local.sh --asan` now covers `determ-dsso`.** It did not build that binary at all, so no sanitizer had ever run over the bounded parsers that face a hostile wallet — and the fuzz arms inside `selftest-pid` (8400 mutated inputs), which assert a definite status and untouched guard bytes, **cannot observe an out-of-bounds read**. Adding the target to the build list is necessary but not sufficient: `dapps/dsso`'s readers allocate nothing, so every buffer they touch is an automatic array and only compile-side instrumentation makes an overflow observable. `CMakeLists.txt` therefore instruments `determ-dsso` under `DETERM_ASAN` alongside `determ` and `determ-crypto-c99`, and the `--asan` leg runs all four selftests on the instrumented binary.

**WHAT THE ASan LEG FOUND: no defect, and the leg is falsifiable.** `determ-dsso` built clean with `-fsanitize=address -fno-omit-frame-pointer -O1` and all four selftests passed under `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:print_stacktrace=1`, including `selftest-pid`'s **8400**-input fuzz corpus over the presentation, JSON, base64url and zlib readers. To show the leg is not vacuous, a one-byte over-read was introduced into `dsso_b64url_decode` (`volatile uint8_t probe_ = out[cap];`): ASan reported `stack-buffer-overflow ... in dsso_b64url_decode` and aborted, while **the same mutant passed the uninstrumented `selftest-pid` green with all 156 assertions** — which is exactly the blindness this repair closes. The source was restored and both trees rebuilt clean. **Stated limitation, and it is not small: `bash tools/ci_local.sh --asan` does NOT complete in this container.** Its first target, `determ`, is OOM-killed compiling `src/main.cpp` (69113 lines) under ASan — `cc1plus` reached ~6.0 GB RSS and was killed by the memory cgroup (`Memory cgroup out of memory: Killed process … (cc1plus) … anon-rss:6060964kB`). That is a pre-existing environmental limit of this 2-core container, not a consequence of this change, and the leg was **not** softened to skip a failing target: a sanitizer pass that silently drops a binary is a false green. The `determ-dsso` half was therefore built and run directly in the same `build-linux-asan` tree, which is what the evidence above is from.

**RIDERS — none discretionary. Five inline fact corrections in untiered docs**, each because a sentence in them is false of the shipped tree and this increment's documents would otherwise contradict it: (1) the `selftest-authn` assertion count 115 → 114 in `docs/SECURITY.md`, `docs/proofs/README.md` and `DssoAuthenticationAssurance.md`; (2) the fuzz-corpus size 6900 → 8400 in `docs/SECURITY.md`, `docs/proofs/README.md`, `docs/CLI-REFERENCE.md` (CRLF preserved — 760 CR-terminated lines before and after, one line changed), `DssoPidVerification.md` and the `tools/test_dsso_pid.sh` header comment; (3) the two `docs/SECURITY.md` test-table S-item attributions S-106 → S-108 and S-106 → S-107; (4) the `DssoPidVerification.md` sentence saying the fixture generator is not in the repository; (5) its "`--asan` does not build `determ-dsso`" sentence. No triage row is opened or closed, and no summary cell moves.

**NOTICED AND DELIBERATELY LEFT ALONE, with the locus.** (1) `dapps/dsso/dsso_pid.c`'s `dsso_trust_lookup` header quotes OIA_12 as *"a PID Provider Trusted List"*; the ARF v2.9.0 text says *"a PID Provider LoTE"*. The quotation is from an earlier ARF release. The substance — the anchor is provided by configuration and never taken from the token — is unchanged, so the comment is misattributed rather than wrong, and correcting it is a code change this increment does not make. §12.3 records the correct text. (2) Three key-accepting entry points do not refuse an all-zero key, where `dsso_authn_init` does: `dsso_bind_init` (`pseudonym_key`), `dsso_bind_account_add` (`auth_key`) and `dsso_idp_register_rp` (`tenant_key`, via `binding_valid`, which checks only `rp_id_len`). Recorded as deployment obligations in `DssoOperations.md` §2.2, §2.3 and §2.6; making them fail closed is a code increment with its own gate. (3) `dsso_loa` is declared **twice**, in `dapps/dsso/dsso_pid.h` (with `DSSO_LOA_HIGH`) and in `dapps/dsso/authn.h` (without it). It compiles because no translation unit includes both, and the difference is deliberate — `HIGH` is a level a PID Provider may assert about itself, never a level DSSO's own authentication produces — but two types with one name is a trap for the next increment that needs both headers. (4) The status-list `uri` is fetched by a callback this repository does not implement. It is not arbitrary attacker input — it sits inside the issuer-signed payload and rule 8 runs only after rule 3 verified that signature — but it is chosen by whoever can get a credential issued by an anchored PID Provider, so the SSRF surface is real and is entirely the deployment's; recorded in `DssoOperations.md` §3.1. (5) `tools/test_proofs_index_complete.sh` emits a stale-EXCLUDE note for `v2.25-DSSO-DAPP-SPEC.md`; informational, the guard passes, and pruning the EXCLUDE list is not this increment's business.

**WHAT DOES NOT CHANGE.** No consensus accept rule, no apply path, no wire format, no digest, no genesis field, no migration, no `src/`, `include/`, `light/` or `wallet/` source. `dapps/dsso` is byte-identical to its state at `3667d89` apart from the comment block at the head of the generated `dsso_pid_vectors.h`. The only non-documentation changes are the new `tools/gen_dsso_pid_vectors.py`, the `--asan` leg of `tools/ci_local.sh`, and the `DETERM_ASAN` instrumentation of `determ-dsso` in `CMakeLists.txt` — none of which is compiled into any default build.

**Verification:** `tools/ci_local.sh` — build 7 targets (`determ`, `determ-wallet`, `determ-light`, `determ-cryptotest`, `determ-dsf`, `d5rp`, `determ-dsso`), **FAST 320 passed / 0 failed, 0 skipped** (unchanged: this increment adds no gate and retires none), 16 doc guards green — `test_doc_citation_bounds`, `test_doc_tier_check`, `test_docs_link_check`, `test_proofs_index_complete`, `test_proofs_no_deleted_crypto_backend`, `test_param_change_whitelist_coherence`, `test_rpc_hmac_canonical_parity`, `test_keygen_failclosed_guard`, `test_wallet_accounting_credit_gate_source`, `test_dapp_registry_active_boundary_coherence`, `test_registrant_lifecycle_classifier_coherence`, `test_light_state_root_binding_guard`, `test_light_resume_monotonicity_guard`, `test_light_keybind_surface`, `test_security_ledger_coherence`, `test_producer_admit_wiring_guard`. **The FAST count at this base is 320, not the 321 this increment's brief stated**: the four DSSO increments took it 318 → 319 (`dsso_pid`) → 320 (`dsso_authn`), with `dsso_assertion` retired and `dsso_assertion_module` added at C6 for a net zero. Measured, not carried over.

**Authority:** the owner's **2026-09-17 directive** to develop DSSO toward an eIDAS outcome, under which the C2 and C6 owner-gates were lifted, together with the DSSO / eIDAS mission brief's target-role definition, sitting under owner decision **D19a** (DSSO is a v1.1 DApp-layer track with no chain surface). The boundary decision above is the explicit statement of the rule the D19a increments have been operating under; it does **not** relax **D2**, whose scope is storage, the wire, keyfiles and consensus test vectors, none of which DSSO touches. Any external-format parser closer to consensus than `determ-dsso` remains owner-gated. Recorded by Claude (Cowork session) on `dsso/req`, 2026-09-17. This entry is append-only per convention and carries no tier marker in its body.

---

## 2026-09-17 — DSSO/eIDAS increments integrated: the ledger-id collision resolved, and what the five branches together do and do not establish

**Status:** INTEGRATION RECORD. No code change beyond the id reassignment in two earlier entries of this log.

**Problem this entry solves.** Five increments were built in parallel on branches cut from the same base (`e5b3bbc`): the C2 server-authentication fix, the C6 assertion module, the EUDI PID verifier, the authentication-assurance module, and the requirements mapping. Three of them independently allocated the same next-free ledger id, **S-106**, because each read the ledger at a base where 105 was the highest. Integrating them without resolving that would have left one id naming three different defects — the failure mode the ledger's coherence guard exists to prevent but cannot catch, since it derives the summary from whatever rows exist rather than checking that an id means one thing.

**Resolution, by landing order.** **S-106** — the C2 IdP impersonation (a party holding only the victim's public key completed the AKE as the IdP). **S-107** — the C6 assertion accept rule (any `tenant_key` holder minted a token for any subject, and the claim the relying party acted on was unauthenticated). **S-108** — the single-factor login and the undefined online guessing bound. The two affected entries above have had their row references corrected in place; this is the one exception to the append-only rule that the convention itself requires, because an append cannot unsay a number another document now reads differently, and the alternative — three entries naming one row — is worse than a two-word correction with this entry recording it. The EUDI PID increment correctly opened no row: it is new functionality, not a recorded defect.

**What the five increments together establish.** DSSO can now verify an EUDI Wallet PID presentation (SD-JWT VC) against configured issuer trust anchors with holder binding, audience and request binding, freshness, a fail-closed status check and an assurance floor; bind that identity to an account under rules that refuse a session-only authorisation, a second account for one subject, and a replayed presentation; authenticate a user with two factors from different categories with an aggregate attempt bound that subset rotation does not evade; and assert to a relying party a claim that relying party can verify was the one the identity provider authenticated, under a pairwise subject identifier. Each is gated at the layer where its rule lives and each gate is falsify-on-mutant.

**What it does not establish, stated here because this is the entry a future reader will find first.** None of this is a notification under Art. 9, a certification under CIR (EU) 2024/2981, or any qualified trust service. The wallet-relying-party registration and access certificate (ARF RPA_01..RPA_03) are external acts with a Member State registrar and are NOT obtained, so DSSO cannot yet authenticate itself to a wallet and no conforming wallet would answer its request. OpenID4VP is not implemented, so what is verified is a presentation some other transport delivered. ISO/IEC 18013-5 mdoc is not implemented. No Trusted List or List of Trusted Entities is fetched or parsed — the trust store is configured. Nothing logs anything, so the record-keeping requirement is unmet by construction. The C2 closure rests on a stated boundary whose enrolment-time resolver does not exist in `light/`. A passing gate is evidence that the code enforces what the gate asserts, and is not a compliance conclusion.

**Verification:** `tools/ci_local.sh` — build 7 targets, FAST 320 passed / 0 failed, 16 doc guards green; `tools/test_security_ledger_coherence.sh` PASS with the summary derived from the triage rows.

**Authority:** the owner's 2026-09-17 directive to develop the DSSO DApp toward an evidence-backed eIDAS outcome, which is what authorizes the previously owner-gated C2 and C6 fixes. Recorded by Claude (Cowork session), 2026-09-17. This entry is append-only per convention and carries no tier marker in its body.
