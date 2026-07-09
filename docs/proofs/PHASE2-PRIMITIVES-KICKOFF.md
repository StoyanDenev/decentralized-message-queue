# Phase-2 primitives — kickoff (v2.26 ROTATE_KEY · v2.15 multi-sig · v2.22 PFS/OTPK)

> **TIER: FUTURE — post-1.0, non-authoritative, AI-drafted for owner review** (future-tier index: `../ROADMAP.md`). The §2 multi-sig
> content is a **stub proposal**, not a committed design; it requires owner sign-off before it enters
> any immutable/consensus surface (per `FROST_DEVIATION_NOTICE.md §4` AI-drafted-design discipline).
> §1 and §3 point to already-owner-reviewed specs. Decision context: `DECISION-LOG.md` 2026-07-09.

**Purpose.** The v1.1/v1.2 split (2026-07-09) puts DSSO + Tier-1 DApps in v1.1. Two Tier-1 DApps sit on
three primitives that are **0% built today**: D.2 B2B settlement needs multi-sig + ROTATE_KEY; D.3
journalism needs PFS/OTPK + ROTATE_KEY. This doc gets Phase 2 moving: for the two that are already
spec'd it gives an implementation checklist; for multi-sig (no spec) it stubs a design for review.

**Sequencing note.** These are DApp prerequisites, not core-chain blockers — they parallelize with the
Phase-1 core. Priority order within Phase 2: **ROTATE_KEY → PFS/OTPK → multi-sig** (ROTATE_KEY gates two
DApps and is also a v2.8 PQ prerequisite; multi-sig gates only D.2). D.1/D.5/D.9 need none of these, so
they can validate the DSSO+DApp path first while Phase 2 runs.

---

## 1. v2.26 ROTATE_KEY — spec exists, implement

**Gates:** D.2 (key churn for settlement accounts), D.3 (emergency rotation for at-risk sources), D.4 (v1.2, delegate revocation). Also a hard prerequisite for v2.8 on-chain PQ (per `V2-DESIGN.md`).

**Spec:** `v2.26-ROTATION-SPEC.md` (present, owner-reviewed 2026-06-07). No new design needed.

**What it is.** An on-chain `ROTATE_KEY` tx that retires a compromised/rotated key without losing the account identity: a short on-chain address resolves to the current pubkey via the registry, so txs carry the address (not a per-tx pubkey), and rotation republishes the pubkey the address resolves to.

**Implementation increments (additive, KAT/vector-gated per the shipped-primitive pattern):**

1. `ROTATE_KEY` TxType + payload (new pubkey + old-key signature over the rotation) + enum slot.
2. Registry-resolution change: address → current pubkey indirection; rotation-aware sig verification at apply.
3. Rotation cooldown + replay guard (nonce/`next_nonce` already present).
4. `signature_form`-aware (A6) so an Ed25519→ML-DSA rotation is expressible — aligns with the PQ freeze.
5. Wallet: `determ-wallet rotate-key` build/sign; light-client verification of the resolution.
6. Soundness proof-doc (rotation cannot forge control of an account; old key inert post-rotation).

**Open items:** confirm KR-10 unification (rotation covers account key + DApp `service_pubkey` + audit key with one mechanism) survives the current scope; reconcile with A5/A6 PQ-address freeze so the resolution indirection is the thing that absorbs PQ pubkey bloat.

---

## 2. v2.15 multi-sig — STUB (design proposal, owner review required)

**Gates:** D.2 B2B settlement (M-of-N vendor-invoice authorization). Only Tier-1 consumer.

**Spec status:** none. `V2-DESIGN.md §v2.15` is a one-line sketch ("Wallet HD derivation + multi-sig", ⏳ not started). This section is the first design pass — **stub, not committed.**

**What it is (proposed).** An M-of-N authorization policy on an account: a tx spending from a multi-sig account is valid iff it carries ≥ M valid signatures from the account's N registered signer keys.

**Key grounding — reuse, don't invent.** Determ already ships the load-bearing pieces:

- **`COMPOSABLE_BATCH` (v2.4, shipped)** already supports "multi-sig parallel approval — M signers act independently, commit iff all M land in the batch." For many B2B flows this *is* the multi-sig primitive (a relayer bundles independently-signed inner txs; atomic all-or-nothing). **Option A below leans entirely on this — possibly zero new consensus code.**
- **Shamir (shipped, `test_wallet_shamir*`)** covers threshold *key-splitting* (one logical key, T-of-N shares) — a different model (threshold signature vs multi-party authorization).
- **HD derivation** (the other half of v2.15) is wallet-side key management, orthogonal to the consensus authorization question.

**Design options (for owner decision):**

- **Option A — no new consensus; multi-sig = COMPOSABLE_BATCH pattern + a wallet policy layer.** The account is ordinary; "M-of-N" is enforced by the DApp/wallet requiring M independently-signed inner txs in a batch. Cheapest, additive-free, ships fastest. Limitation: the M-of-N policy is not *on-chain-enforced* at the account level — a single-sig spend from the same key is still valid unless the key is only ever held split.
- **Option B — on-chain M-of-N account policy.** New account field `{signers: [pubkey; N], threshold: M}` (a `§7.5` discriminator slot) + apply-path check that a spend from such an account carries ≥ M valid signer sigs. True account-level enforcement; costs a schema slot (permanent under no-migrations) + apply-path logic + a soundness proof. Composes with ROTATE_KEY for signer-set churn.
- **Option C — threshold signature (FROST-style single aggregate sig).** Rejected pre-emptively: FROST was removed from the consensus path (`FROST_DEVIATION_NOTICE.md`); reintroducing it for multi-sig contradicts that decision. Shamir threshold-sig has the same "one key, hidden quorum" property, which is *not* what B2B multi-party authorization wants (it wants *visible* M-of-N accountability).

**Recommendation (for review):** **Option A for v1.1** (validates D.2 with zero consensus risk), with **Option B reserved as a `§7.5` discriminator slot** decided in the B4 pre-genesis reserved-bit audit — so on-chain M-of-N can ship additively later without a wire break. This keeps v1.1 lean while preserving the permanent option.

**If Option B is chosen, implementation increments:**

1. Reserve the account-policy discriminator in the B4 pass (pre-genesis — permanent).
2. Account-state `{signers, threshold}` field + serialize/restore (S-037-class: include in snapshot round-trip).
3. Apply-path: spend from a policy account requires ≥ threshold distinct valid signer sigs; bind the signer set into `state_root`.
4. Signer-set rotation via ROTATE_KEY (§1) — reuse, don't add a second rotation path.
5. Wallet: `determ-wallet multisig-*` (create policy, co-sign, assemble); light-client verification.
6. Soundness proof: no spend with < M sigs; signer-set changes are ROTATE_KEY-authenticated.

**Open questions for owner:** (i) is on-chain enforcement (B) actually required for the B2B use case, or does the COMPOSABLE_BATCH pattern (A) suffice? (ii) if B, is the signer set mutable (ROTATE_KEY) or genesis-of-account fixed? (iii) interaction with confidential amounts (multi-sig over a SHIELD/CONFIDENTIAL_TRANSFER — do all signers need view access?).

---

## 3. v2.22 PFS / PRIV-6 OTPK — design exists, implement + verify coverage

**Gates:** D.3 journalism (per-tx forward secrecy so a later key compromise can't retro-expose a source's payment amounts), D.4 (v1.2, principal protection).

**Spec:** `v2.22-PRIVACY-SPEC.md` PRIV-6 (one-time-pubkey stream) + `PFS_DEPLOYMENT_GUIDANCE.md`. **Action item:** confirm the PRIV-6/OTPK design survived the B3 as-built rewrite (653→116 lines) — if it was trimmed to the shipped shielded-pool core, restore the OTPK section as an increment of the consolidated design doc before building.

**What it is.** Per-tx PFS: the recipient publishes a batch of one-time pubkeys (`PUBLISH_OTPK_BATCH`); a sender encrypts the amount to a fresh OTPK per tx; once consumed, the OTPK is retired, so the amount is irrecoverable after — independent of the account's long-term view key. This is the piece that makes D.3's "protect the source even if the platform is later compromised" real.

**Implementation increments:**

1. `PUBLISH_OTPK_BATCH` TxType + apply (recipient publishes 32 fresh OTPKs; allowed unless `confidential_policy = AUDITABLE_ONLY`).
2. OTPK lifecycle state: `Unused → UsedMarker{SHA256(id||pk)}` atomic replacement at apply; nullifier-adjacent (reuse the shielded-pool nullifier machinery where possible).
3. Sender wallet auto-replenish when recipient's unused OTPK count drops below 8.
4. Recipient wallet: `AMT_PFS_UNDECRYPTABLE` incoming state + reconciliation-tuple importer (the sender is the only recovery channel — PRIV-6.1).
5. Compose with the A1/A2 view-key layer: PFS mode substitutes an OTPK for `view_master_pk` as the recipient pubkey in the amount handshake.
6. Soundness proof: consumed OTPK ⇒ amount irrecoverable; PFS does not weaken the balance/range invariants.

**Interaction to settle:** PFS (irrecoverable) vs the FULL audit layer (A2, scoped disclosure) are in tension per account — PRIV-6 is opt-in per `confidential_policy`, and `AUDITABLE_ONLY` accounts cannot use OTPK PFS. D.3 (journalism) wants PFS; D.1 (gambling) wants auditable. Confirm the policy enum cleanly expresses both and the DApps pick correctly.

---

## Phase-2 exit criteria

- ROTATE_KEY: tx + resolution + rotation-aware verify shipped, KAT-gated, proof-doc landed.
- Multi-sig: owner picks A or B; if A, wallet policy layer + D.2 integration test; if B, the increments above.
- PFS/OTPK: OTPK lifecycle + wallet replenish + PFS-mode amount handshake shipped; coverage restored in the consolidated spec.
- All three: fold into the D1 adversarial audit scope and the C2 FA/DSF sweep before the single beta soak (D4).
