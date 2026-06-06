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

*End of decision log. Append new entries below as future deliberations conclude.*
