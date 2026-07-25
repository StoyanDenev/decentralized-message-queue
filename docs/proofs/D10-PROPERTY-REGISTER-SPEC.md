# D.10 — Confidential government property register (DApp spec sketch)

**Status:** DRAFT SKETCH — owner-approved catalog entry (DECISION-LOG 2026-07-25). **Not
scheduled**: D.5 remains the first DApp (active-front directive, 2026-07-23). Tier-1 — every
primitive used here is shipped or already authorized; no zk-VM dependency.
**License:** BUSL-1.1 (dapps/LICENSE map; production by a public-sector body = paid grant).

## 0. Motivation

**The failure this DApp exists to prevent happened in mid-July 2026.** Romania's national land
registry (ANCPI) was breached via compromised credentials; after a failed extortion attempt the
attacker **wiped the registry databases**, freezing property transactions nationwide while
backups were restored, with the stolen data offered for sale. (Reports: The Record
<https://therecord.media/romania-cyberattack-land-registry>; Cybernews
<https://cybernews.com/security/hacker-deletes-romanian-land-registry-database/>; Help Net
Security <https://www.helpnetsecurity.com/2026/07/16/romania-ancpi-cyber-attack/>.)

A centralized register is one credential away from national paralysis: a single point of
compromise for **wiping**, a single point of trust for **silent rewriting**, and a single
insider away from **unlogged browsing** of who owns what. D.10 is the mutual-distrust answer:
history that no single party — insider, vendor, or attacker — can wipe or rewrite; ownership
that no one can read without a quorum and a mandatory, citizen-visible audit trail.

**Deployment economics (licensing v3.1):** the Determ core is Apache-2.0 — a government runs
the chain at zero license cost, on its own K-of-K nodes (cadastre agency, notary chamber,
judiciary, municipality — mutually distrusting institutions). The D.10 DApp is the paid layer:
production deployment by a public-sector body is a BUSL production grant. The state buys the
protection, not the infrastructure.

## 1. Requirements

- **R1 Integrity.** Title history is append-only and fork-free; no operator, insider, or
  attacker below the BFT threshold can wipe or rewrite it (K-of-K consensus + no-migrations).
- **R2 Confidentiality.** parcel -> owner is not derivable by the public, by a single node, or
  by an unauthorized service. Parcel identifiers (cadastral numbers) are public; owners are not.
- **R3 Audited access.** Every plaintext read by an authorized service is preceded by an
  on-chain `LOG_AUDIT_ACCESS` record (who, which parcel, legal basis, when) — by construction,
  not by policy. Owners can enumerate all accesses to their own parcels.
- **R4 Owner rights.** An owner can always read their own record, and can selectively prove
  ownership to a counterparty of their choice without a government intermediary.
- **R5 Authorized transfer.** Ownership changes require joint authorization (owner + notary +
  cadastre service) in one atomic transaction.
- **R6 Judicial inverse lookup.** "All parcels of person Y" exists only as a separately
  protected query class gated on a court-order flag in its audit record.

## 2. Data model

Per parcel `p` (state leaves; all binary, canonical codec — no JSON):

| Field | Content | Visibility |
|---|---|---|
| `parcel_id` | cadastral number | public (already public today) |
| `C_p` | `H(parcel_id ‖ owner_id ‖ salt)` — ownership commitment | public, binds owner without revealing it |
| `E_p` | AEAD ciphertext of the ownership record (owner identity, deed hash, encumbrances) under per-parcel key `K_p` | public bytes, private content |
| shares of `K_p` | **user-dealt Shamir t-of-n shares across the K-of-K node set** (same no-DKG pattern as the v2.25 threshold-OPAQUE stack, applied to data) | one share per node; no party ever holds `K_p` whole |

The authorization policy — which services may request reads, and with which legal-basis codes —
is an **on-chain public register**, changed only via the existing PARAM_CHANGE
distinct-keyholder multisig. Policy public, data private.

## 3. Read path (the core mechanism)

1. Service authenticates via DSSO (threshold-OPAQUE) and submits `READ(parcel_id, basis)`.
2. Each responding node checks the policy register, **writes/validates a `LOG_AUDIT_ACCESS`
   entry first**, then releases its share of `K_p`.
3. At threshold t, the service reconstructs `K_p`, decrypts `E_p`, reads.

Properties: unauthorized party -> no shares; single corrupt insider -> below threshold, nothing,
and any attempt is itself logged; authorized service -> plaintext, but **never silently** — the
audit record precedes the data cryptographically, because the shares are the data path. The
owner reads their own parcel the same way, free of charge.

## 4. Write path

- **Transfer** = one v2.15 `COMPOSABLE_BATCH`: co-signed by current owner (DSSO-bound key),
  notary, cadastre service. Emits fresh `salt`, fresh `K_p`, new `C_p`/`E_p`, new share set.
- **Service key rotation** = v2.26 `ROTATE_KEY` (KR-10 unified key_target).
- **Policy change** = PARAM_CHANGE multisig (distinct keyholders, threshold — already
  gate-pinned in the validator).
- Public verifiability: any citizen with the Apache light client verifies append-only history
  and that every `C_p` is bound under `state_root`. Nobody learns ownership from it.

## 5. Selective proof (no zk needed)

Owner reveals `(owner_id, salt)` privately to a chosen counterparty, who checks
`H(parcel_id ‖ owner_id ‖ salt) = C_p` against the chain. Tier-2 upgrade path (D.8 machinery):
prove "I own a parcel in class X" without revealing which — optional, later, out of scope here.

## 6. Leak table (stated per B3 discipline — what an adversary still sees)

| Observable | Leak | Mitigation |
|---|---|---|
| Transfer tx on parcel `p` | *that* `p` changed hands (not to whom) | periodic re-randomization writes indistinguishable from transfers (cost: write volume); or accept event-level visibility |
| Access log | that service S read parcel `p` under basis B | intended — this is the feature |
| Inverse index (R6) | full holdings of a person, to a court | separate threshold class + court-order flag; never derivable from forward records |
| Traffic/timing at nodes | request patterns | standard gossip-layer noise; out of DApp scope |

## 7. GDPR

On-chain: ciphertext + commitments only. Register basis: Art. 6(1)(c) legal obligation.
Erasure/rectification reconciliation with no-migrations: **crypto-shredding** — destroying a
superseded share-set renders its `E_p` permanently inert without touching chain history.
Operative analysis is counsel work (same shortlist as licensing v3.1).

## 8. Claims and green gates

| # | Claim | Gate |
|---|---|---|
| C1 | History append-only; no sub-threshold coalition can rewrite or wipe | inherited: consensus soundness + bounded-reorg gates (shipped); D.10 adds a register-replay gate |
| C2 | No plaintext read without a prior on-chain audit record | G1: falsify-on-mutant — node serving a share without the log write must fail the gate |
| C3 | No single node/service can reconstruct `K_p` | G2: t-1 shares reveal nothing (Shamir property test + KAT vectors) |
| C4 | Commitment binds ownership (no equivocation) | G3: open `C_p` two ways must be infeasible — hash binding test |
| C5 | Transfer requires owner+notary+cadastre jointly | G4: batch missing any signer rejected (validator gate, extends the pinned COMPOSABLE_BATCH inner-sig checks) |
| C6 | Crypto-shred kills readability, not history | G5: post-shred decrypt fails; chain replay byte-identical |

## 9. Primitives (all shipped / authorized — Tier-1)

DSSO threshold-OPAQUE (v2.25) · user-dealt Shamir t-of-n (v2.25 stack pattern) ·
`LOG_AUDIT_ACCESS` · `COMPOSABLE_BATCH` (v2.15 Option A) · `ROTATE_KEY` (v2.26, authorized) ·
PARAM_CHANGE multisig · canonical binary codec (D2, no JSON) · Apache light client.

## 10. Cross-references

`docs/V2-DAPP-DESIGN.md` (substrate: DAPP_REGISTER / DAPP_CALL, economics) ·
`docs/proofs/v2.25-DSSO-DAPP-SPEC.md` (threshold stack) · `LICENSING.md` +
`COMMERCIAL-LICENSE.md` (BUSL grant = the royalty event) · `docs/proofs/DECISION-LOG.md`
2026-07-25 (catalog entry) · `dapps/LICENSE` (map).
