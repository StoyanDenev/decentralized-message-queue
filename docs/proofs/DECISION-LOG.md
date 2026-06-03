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

*End of decision log. Append new entries below as future deliberations conclude.*
