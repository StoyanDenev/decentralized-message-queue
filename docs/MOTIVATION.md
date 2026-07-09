# Project motivation — why Determ exists

**Source document.** `docs/Confrontation_against_public_unjustice_i.odt` — open letter to cryptographers and Bulgarian cybersecurity officials. This file is the project's public-interest mandate. Determ's technical design choices are answers to the adversarial threat model the letter describes.

**Audience.** Future implementation threads, security reviewers, ecosystem partners, regulators. The letter explains *why* certain Determ design choices are non-negotiable; this doc maps the letter's claims to the specific specs that implement the answer.

---

## 1. The originating problem

Per the open letter:

1. **Bulgaria, 2011** — government regulation introduced requiring random judge-assignment to court cases.
2. **The implementation in use is closed-source and the audit is classified** ([judicialreports.bg](https://judicialreports.bg/)). EU monitoring papers flag this every six months without resolution.
3. **The author's distributed-RNG solution from 7 years prior** ([academia.edu/79703805/Secure_Distributed_Random_Number_Generator](https://www.academia.edu/79703805/Secure_Distributed_Random_Number_Generator)) is compliant with the current regulation but has not been adopted by any government, media, or academic body.
4. **The systemic problem is broader** — the public-private company building Bulgarian government information systems ([is-bg.net](https://www.is-bg.net/bg/)) confirmed it has no cryptographers and no security model. No key management service, no separation-of-responsibilities, no auditable architecture.
5. **The cryptographic principle being violated** — Kerckhoffs's principle (per [NIST SP 800-123](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf)): security must not depend on secrecy of implementation. In a context of hybrid warfare against public trust, closed-source government cryptography is structurally vulnerable to insider compromise.

**Threat model implied by the letter:**
- Government information systems are compromised from within (potentially by foreign hybrid-warfare actors per the letter's framing)
- Closed-source implementations prevent independent audit
- Personnel-based controls fail when personnel themselves are compromised
- Trace-removal by insiders defeats forensic accountability
- Centralized RNG / IdP / record-keeping infrastructure provides single points of capture

Determ is designed to deliver public-interest cryptographic infrastructure that **does not depend on trusting any single operator, vendor, or insider** — addressable from this threat model and provable per Kerckhoffs's principle.

---

## 2. How Determ design decisions answer the letter

| Letter's concern | Determ design answer | Spec reference |
|---|---|---|
| **Closed-source government cryptography violates Kerckhoffs's principle** | All Determ chain code, specs, and design deliberation are public. CRYPTO-C99 discipline vendors only audited, from-scratch C99 primitives (SHA-2/SHA-3, Ed25519, X25519, NIST P-256, AES-256-GCM, ChaCha20-Poly1305, Argon2id) — each validated byte-for-byte against published test vectors — into the chain; no closed-source crypto in the apply path. (secp256k1 was never vendored and was rejected 2026-07-07; libsodium was removed from the tree entirely.) | `CRYPTO-C99-SPEC.md`, `DECISION-LOG.md` (the deliberation history itself is published) |
| **No security model in current government systems** | K-of-K mutual-distrust posture means no single party (operator, vendor, regulator) can corrupt the system. Every consensus operation requires the agreement of K independent committee members; compromise of K-1 leaves the system intact. | `Beaconless-v2-SPEC.md` (light-client mesh, manifest co-signing) |
| **No key management service / separation of responsibilities** | v2.10 FROST-Ed25519 distributes signing authority across K committee members; no single member holds a complete signing key. v2.15 multi-sig + v2.26 ROTATE_KEY enable per-account separation-of-responsibilities. v2.22 confidential transactions separate amount-confidentiality keys from signing keys (audit-by-disclosure rather than audit-by-master-trust). | `v2.26-ROTATION-SPEC.md`, `v2.22-PRIVACY-SPEC.md` |
| **Insiders can erase traces in closed systems** | All state mutations contribute to v2.1 state Merkle root, bound by K-of-K committee signatures in every block. Light clients verify state via v2.2 trustless proofs against on-chain commitments. `no-migrations` constraint (post-v1.0 mainnet) makes historical state structurally immutable — once committed, no validator-coordinated rewrite is possible without security-critical hard fork. | `dlt-no-migrations-constraint` memory; `V2-DESIGN.md §v2.1` |
| **Random judge selection requires verifiable distributed randomness** | v1.x **commit-reveal** block randomness (`R = SHA256(delay_seed ‖ ordered_secrets)`; unbiasable under SHA-256 preimage resistance; selective abort defeated); Beaconless-v2 cross-shard randomness via a per-epoch accumulator over per-shard commit-reveal randomness with subset recording (BL-6). Anyone can verify the randomness derivation deterministically; biasing requires controlling K-of-K committee members simultaneously. (FROST removed from the chain path per `proofs/FROST_DEVIATION_NOTICE.md`.) | `Beaconless-v2-SPEC.md §Q6` |
| **No federated identity primitive for government services** | DSSO (Distributed SSO) ships as a chain-aware DApp on the Determ substrate post-v1.0 — K-of-K-distributed authentication where no single party (Determ operator, DSSO DApp instance, identity provider) can impersonate users or forge assertions. | `Improvements.md §8.1` (DSSO-as-DApp); `Beaconless-v2-SPEC.md` (committee continuity foundation) |
| **Hybrid warfare against public trust requires transparency** | Every design deliberation is documented (`DECISION-LOG.md`); every rejected alternative is preserved with reasoning (`Improvements.md`); every operational policy is operator-facing (`PFS_DEPLOYMENT_GUIDANCE.md`, `DAPP_SDK_GUIDANCE.md`). The audit surface for the entire system — code, specs, deliberation, regulatory interpretation, browser-side strategy — is public and reproducible. | All planning artifacts |
| **Compromised personnel can exfiltrate records** | v2.22 PFS mode (PRIV-6) provides per-tx forward secrecy — compromised long-term keys cannot decrypt past confidential traffic. v2.26 ROTATE_KEY with `reason_code=1` enables emergency rotation without losing on-chain identity continuity. | `v2.22-PRIVACY-SPEC.md §Q5 (PRIV-6)`, `v2.26-ROTATION-SPEC.md §2 (KR-1, KR-3, KR-4)` |
| **Audit is classified; no independent verification** | v2.22 dual-mode audit disclosure (PRIV-4) lets account holders disclose either full or per-epoch keys to auditors off-chain, with no chain-level audit-key escrow. v2.24 audit hooks can ship with `LOG_AUDIT_ACCESS` tx for operator-required disclosure auditability. PFS_DEPLOYMENT_GUIDANCE provides operator-facing regulatory framework so each jurisdiction's compliance posture is informed rather than imposed. | `v2.22-PRIVACY-SPEC.md §Q4 (PRIV-4)`, `PFS_DEPLOYMENT_GUIDANCE.md` |
| **"Public-private company has no cryptographers"** | CRYPTO-C99 + DSF + the entire review-week deliberation pattern is designed to be auditable by any cryptographer in the world. Vendored primitives are from-scratch C99 implementations of public standards (Ed25519 = RFC 8032; X25519 = RFC 7748; SHA-2 = FIPS 180-4; NIST P-256 = FIPS 186-5; AES-256-GCM = FIPS 197 + SP 800-38D; Argon2id = RFC 9106; FROST = RFC 9591 reference, library-only), each validated byte-for-byte against published test vectors; no proprietary cryptographic black-box anywhere. (No libsecp256k1 or libsodium is vendored — secp256k1 was rejected 2026-07-07 and libsodium was removed.) | `CRYPTO-C99-SPEC.md`, `DSF-SPEC.md` |

---

## 3. Design choices that aren't arbitrary

Several decisions from this session look like ordinary engineering trade-offs but are actually direct answers to the letter's threat model:

**No migrations at all (post-v1.0 immutability)**
- Engineering reading: "Reduces operational complexity for upgrade discipline"
- Public-interest reading: defeats the "insiders erase traces" failure mode. Once mainnet ships, no validator-coordinated rewrite is possible except via security-critical hard fork (which would itself be publicly visible). Historical state is structurally protected from after-the-fact modification.

**Closed-beta + clean-break handoff + open-ended duration + no external audit**
- Engineering reading: "Cost-conscious QA strategy"
- Public-interest reading: matches a posture of self-reliance against potentially-compromised institutions. External audit by jurisdiction-specific firms could be a capture vector under hybrid warfare; internal team output + closed-beta with vetted partners + open-ended timeline preserves the team's ability to make calls based on cryptographic evidence rather than institutional pressure.

**DSSO-as-DApp with K committee-hosted instances**
- Engineering reading: "Reduces v1.0 critical path"
- Public-interest reading: avoids creating a chain-level IdP substrate that would itself become a high-value capture target. K-of-K-instance DApp distributes the identity-provider trust to the same set of committee members that already secure consensus — no separate trusted IdP operator that could be compromised independently.

**KR-10 unification of ROTATE_KEY across REGISTER + DAPP_REGISTER**
- Engineering reading: "API coherence"
- Public-interest reading: DSSO DApp instances (post-v1.0) need rapid emergency rotation under v2.26's dual-validity + PoP + audit-trail protections. Without unification, DSSO key compromise would lack the rotation primitive's protections — exactly the failure mode the letter describes for current government IdP systems.

**Pre-v1.0 schema discriminators (§7.5.1–§7.5.7)**
- Engineering reading: "Cheap optionality preservation"
- Public-interest reading: PQ migration is foreseeable; foreclosing it would lock the chain into a quantum-vulnerable cryptographic substrate. For a public-interest infrastructure designed to outlast the political cycles described in the letter (multi-decade horizon), preserving migration paths is structural, not optional.

**Transparent deliberation history (DECISION-LOG.md, Improvements.md)**
- Engineering reading: "Maintenance discipline for parallel-thread development"
- Public-interest reading: practiced version of Kerckhoffs's principle. Every design decision's reasoning, every rejected alternative's basis, every operator-facing trade-off is published. An independent cryptographer can audit not just the code but the design process itself. This is the inverse of the "classified audit" status quo the letter describes.

---

## 4. Cross-references

| Artifact | Connection to motivation |
|---|---|
| `docs/Confrontation_against_public_unjustice_i.odt` | Source document; project mandate |
| `docs/proofs/CRYPTO-C99-SPEC.md` | Kerckhoffs-principle-compliant cryptographic substrate |
| `docs/proofs/v2.22-PRIVACY-SPEC.md` | Confidentiality + dual-mode audit (informed-disclosure vs imposed-surveillance) |
| `docs/proofs/v2.26-ROTATION-SPEC.md` | Identity-continuity-with-rotation (insider-compromise recovery) |
| `docs/proofs/Beaconless-v2-SPEC.md` | K-of-K mutual-distrust at the cross-shard layer (no single-operator capture point) |
| `docs/proofs/Improvements.md §8.1` | DSSO-as-DApp (federated identity without single-trusted-IdP) |
| `docs/proofs/PFS_DEPLOYMENT_GUIDANCE.md` | Operator-facing regulatory framework (informed deployment per jurisdiction) |
| `docs/proofs/DAPP_SDK_GUIDANCE.md` | Browser-side crypto strategy per profile (Smart-client web UI for FIPS deployments) |
| `docs/proofs/DECISION-LOG.md` | Public deliberation record (Kerckhoffs's principle applied to the design process itself) |
| `docs/proofs/IMPLEMENTATION-SEQUENCING.md` | Public execution plan |
| `docs/proofs/IMPLEMENTATION-SEQUENCING.md` §4.4 + `docs/proofs/DECISION-LOG.md` 2026-05-24 | Public mainnet-readiness criteria (no opaque "we'll launch when we feel ready") — the `MAINNET_READINESS.md` tracking scaffold was deleted 2026-07-09 (never populated; git history); the criteria + sole-declaration-authority record lives at the cited sections, and the beta model is single-soak-at-feature-complete per the pre-launch register (D4, 2026-07-09) |

Memory entries that encode the public-interest constraints:
- `dlt-pre-mainnet-status` — confirms pre-mainnet posture (architectural decisions made before live-chain commitment)
- `dlt-team-composition` — 4-32 fungible AI threads (transparent capacity, no single-engineer capture point)
- `dlt-no-migrations-constraint` — post-v1.0 immutability against insider trace-removal
- `dlt-qa-strategy` — closed-beta posture against capture-vector audit firms
- `dlt-dsso-as-dapp` — DSSO without single-trusted-IdP

---

## 5. What this doc is NOT

- **Not a political statement.** Determ is a public-interest cryptographic infrastructure project. The letter's framing of specific actors (named governments, named officials) is the project author's personal position from the source document and is not endorsed or shared by every component of the technical work; this doc maps the letter's *cryptographic-architecture concerns* to Determ's design answers without taking positions on the geopolitical framing.

- **Not regulatory guidance.** Operators evaluating Determ for compliance with their jurisdiction's laws should follow `PFS_DEPLOYMENT_GUIDANCE.md` and obtain jurisdiction-specific counsel.

- **Not exclusive scope.** Determ's design serves the use cases in the letter (government random selection, federated identity, audit-without-surveillance) but is general-purpose infrastructure — commercial deployments, B2B settlement, journalism source-protection, and other public-interest applications are equally valid use cases.

- **Not a substitute for independent audit.** The project's transparency posture aims to make independent audit possible; it does not replace it. Any operator or regulator considering deployment should audit the actual code + specs + this deliberation record.

---

*The technical work is the answer. This doc is the question.*
