> **TIER: FUTURE — accepted long-term goals and verification process; implementation, target qualification and regulatory conformity are not established.** Roadmap index: docs/ROADMAP.md

# ADR 008: C99 Assurance, PQC and Regulatory Alignment

**Date:** 2026-09-25
**Status:** ACCEPTED — goals and development process only
**Authority:** owner request to add the supplied audit/rewrite prompt to the development
plan for Claude; Decision Log entry of this date. The request was planning-only:
adopting this ADR changes no C/C++ implementation.

## 1. Context and corrected premises

The final implementation target remains strict freestanding C99 in a single-address-space
unikernel/MicroVM, with no heap, libc or external target runtime libraries. The existing
C++ reference and hosted C99 experiment remain under the port-then-retire rule in
[C99-MINIX-PORT §0](../C99-MINIX-PORT.md). Neither is the qualified target image.

The owner adds long-term regulatory alignment, a complete local C/C++ audit and
the associated migration work to that plan. The supplied prompt is a set of
hypotheses and desired outcomes, not an audit result or compliance certificate.
The following corrections are part of the adopted scope:

| Premise in the supplied prompt | Adopted interpretation |
|---|---|
| A recent CISA emergency directive requires this rewrite | No directive identifier, applicable entity or deadline was supplied or verified. Require that evidence before asserting a mandate. Audit the named vulnerability classes independently of that claim. |
| C99/static allocation mathematically eliminates UAF, OOB, races and DoS | These are design constraints requiring proof and implementation evidence. Stale pool handles, generation wrap, bad pointer arithmetic, interrupts/DMA, unbounded work and capacity exhaustion remain possible. A flat address space makes their consequences severe. |
| C++ prevents formal verification | Language choice does not establish or preclude a proof. Audit the actual C++ ownership, lifetime, arithmetic and concurrency contracts; port the surviving behavior and prove the C99 implementation's contracts. |
| A unikernel bypasses all OS vulnerabilities | Guest dependency reduction does not remove device, firmware, compiler, hypervisor, host or side-channel assumptions. State the actual deployed trust boundary and failure model. |
| NIS2 mandates C99, no heap and a specific zero-trust architecture | NIS2 sets risk-management and governance obligations for entities in scope; it does not prescribe this language, allocator policy or architecture. These remain owner-selected engineering constraints. |
| NIST CSF mandates all three PQ algorithms for all uses | CSF is a risk-outcome framework. FIPS 203, 204 and 205 specify different algorithms and roles, not a universal three-algorithm switch for every deployment. |
| OPAQUE plus new fields provides selective disclosure and eIDAS compliance | Authentication and credential presentation are different protocols. A reviewed credential/proof layer, applicable wallet profile and conformity evidence are still needed. |

NIS2 Articles 20 (governance), 21 (cybersecurity risk-management measures,
including secure development, vulnerability handling and a cryptography policy) and
23 (reporting) set entity obligations; Article 22 concerns Union-level coordinated
risk assessments of critical supply chains, and Article 24 lets Member States
require certified ICT products, services or processes. Applicability depends on
the entity, activity and relevant national implementation. A code audit cannot
settle those facts. [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng).
The EU Cyber Resilience Act, [Regulation (EU) 2024/2847](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act),
is the product-level regime: its reporting obligations apply from 2026-09-11 and
its main obligations from 2027-12-11. Whether and in which role (manufacturer,
open-source steward or non-commercial) it applies to this project is unresolved.

CISA's guidance is non-binding. It recommends memory-safe languages and published
memory-safety roadmaps, and the CISA/FBI Product Security Bad Practices (version 2,
January 2025) call developing new product lines for critical infrastructure in a
memory-unsafe language such as C or C++, where memory-safe alternatives are readily
available, dangerous. The owner-selected C99 target is therefore a recorded
deviation that needs a rationale, compensating assurance evidence and a published
roadmap; it is not evidence of alignment.
[CISA, The Case for Memory Safe Roadmaps](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps),
[Product Security Bad Practices v2](https://www.cisa.gov/resources-tools/resources/product-security-bad-practices).

CSF 2.0 describes cybersecurity outcomes without prescribing their implementation.
[NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20).
The finalized standards define ML-KEM for key encapsulation, ML-DSA for signatures,
and SLH-DSA for stateless hash-based signatures. Review the current errata alongside
the pinned versions. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
An approved algorithm, local conformance vectors or algorithm validation does not
by itself establish FIPS 140-3 module validation.
[NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules).

The European Digital Identity Framework provides for user-controlled selective
disclosure and wallet certification. The applicable role, implementing acts and
interoperability profile must be established before making a conformity claim.
The repository already implements one side of this: DSSO verifies SD-JWT VC person
identification data as a wallet-relying party, with a requirement-by-requirement
mapping that is explicitly not a compliance claim
([v2.25-DSSO-DAPP-SPEC §11–12](../proofs/v2.25-DSSO-DAPP-SPEC.md),
[DssoPidVerification.md](../proofs/DssoPidVerification.md)). Extend that record
rather than starting a parallel one.
[Regulation (EU) 2024/1183](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1183),
[European Commission news item on the first wallet implementing acts (2024-11-28), including wallet certification](https://digital-strategy.ec.europa.eu/en/news/commission-adopts-technical-standards-cross-border-european-digital-identity-wallets).
OPAQUE is an augmented password-authenticated key exchange, not a selective-disclosure
credential scheme. [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html).

## 2. Decision and implementation boundaries

1. **Audit before patching.** Inventory the whole local repository, including C++,
   and record coverage, real call paths, trust boundaries and target dependencies.
   Confirm or refute each preliminary allegation. Reuse the scoped findings in
   [ADR-006](ADR-006-C99-Memory-Safety.md); do not present that C99 audit as a completed
   C++ or whole-repository review. Do not fetch or pull a different baseline.
2. **Memory and temporal contracts.** Use bounded caller-owned storage, checked
   cursors, explicit ownership and lifecycle transitions. Prove allocation/index
   arithmetic and generation identity under stated bounds, including wrap and
   exhaustion behavior. Specify nonblocking device/transport operations, monotonic
   absolute deadlines, bounded per-event work and fail-closed parsing. Do not
   convert a local resource timeout into consensus replacement authority.
3. **Crypto and PQ coverage.** Inventory every signature, KEM/DH, KDF, password,
   identity, storage and consensus dependency. Plan applicable ML-KEM/ML-DSA
   integration and assess a defined role for SLH-DSA under explicit profiles;
   complete PQ coverage is a goal, not a property of the current classical stack.
   Parameter sets, hybrid composition, key lifecycle, entropy, wire budgets and
   migration consequences require reviewed decisions. Existing ML-DSA code is
   not evidence that all callers or the target are qualified. The earlier
   design input is V2-DESIGN v2.8's recorded choice (Dilithium-3 as the primary
   consensus signature, SPHINCS+-128s as a backup wallet-root signature); a
   decision on SLH-DSA's role starts from it. No automatic replacement of every
   signature, no implicit KDF change, no FROST reintroduction.
4. **Identity separation.** Keep password authentication separate from holder-controlled
   credential issuance/presentation. Design selective attribute disclosure and, where
   the chosen privacy requirement needs it, a reviewed zero-knowledge proof scheme.
   Specify issuer trust, holder binding, verifier challenge/audience, replay and
   revocation rules, metadata/linkability and disclosure consent before C structs
   or wire messages. Merely filtering plaintext fields is not a cryptographic proof.
   Do not place person identification data, credential attributes or reusable
   identifying proofs on a public ledger (registered domain names and public keys
   are ledger data by design).
   Target holder-controlled credential storage without introducing a central identity
   database; document any issuer/revocation services and their trust/privacy costs.
5. **Evidence before claims.** Formal arguments state premises and exact properties;
   implementation gates test those properties at receiver/apply boundaries. Qualify
   generated artifacts for a pinned compiler/flags/ISA and actual platform. Neither
   `volatile`, an assembly barrier, a sanitizer pass nor static linking proves
   universal constant time, memory safety, DoS immunity or regulatory conformity.
6. **Preserve existing constraints.** No key escrow, compelled protocol disclosure
   or third-party master key. No post-genesis migration or silent change to frozen
   consensus/state formats. No weakening the secret-independent target requirement
   to admit current Argon2id. An incompatible requirement is recorded for decision,
   not implemented as a backdoor, algorithm downgrade or unproved exception.

The selected combined consensus design, H obligations and ADR-004 §9.6 resource
decisions retain their scope and priority. This ADR adds independent audit and
qualification work; it neither closes those obligations nor authorizes speculative
production consensus/sharding. The implementation order and Claude prompt live in
[C99-MINIX-PORT §§12–14](../C99-MINIX-PORT.md#14-local-audit-regulatory-alignment-and-target-qualification-2026-09-25).

## 3. Required regulatory evidence record

Claude must maintain this matrix as the work proceeds, with specific applicable
clauses/profile revisions, evidence links, responsible operator/owner and remaining
gaps. Code, operational controls and external assessment are separate evidence.
Unknown applicability stays **UNRESOLVED**; it is not a pass or an exemption.

| Area | Evidence required before any relevant claim | Current disposition |
|---|---|---|
| NIS2 | Entity/sector/jurisdiction determination; governance and risk assessment; incident handling/reporting; continuity/recovery; supply-chain and vulnerability-management controls; effectiveness evidence | Applicability and organizational controls unresolved; C99 design alone insufficient |
| CISA Secure by Design | Exact referenced guidance/directive and audience; ownership of security outcomes; vulnerability disclosure/response; memory and resource assurance evidence | C99 deviates from the non-binding memory-safe-language recommendation: rationale, roadmap and compensating evidence required; alleged emergency mandate unverified |
| NIST CSF 2.0 | Current/target outcome profiles across Govern, Identify, Protect, Detect, Respond and Recover, with assigned owners and measurable evidence | Planned; not a certification |
| FIPS 203/204/205 | Applicable algorithm/parameter profile, current errata, independent vectors, implementation review, misuse/failure tests and target leakage evidence; FIPS 140-3 module validation separately if required | ML-DSA-44/65/87 authenticates only PQ_TRANSFER; no ML-KEM or SLH-DSA exists in the repository; every key-exchange, OPRF, credential and non-PQ signature path is classical (inventory: ADR-006 §7). ML-DSA signing is not target-qualified (divisions at `-Os`, rejected-challenge dependence). Module status unestablished |
| eIDAS / EUDI wallet | Product role and applicable acts/profile; issuer/relying-party trust, privacy and selective-disclosure analysis; interoperability and required certification evidence | Relying-party PID verification and a requirements mapping exist (v2.25-DSSO-DAPP-SPEC §11–12, DssoPidVerification.md; not a conformity claim); the 2026-09-25 review found the pseudonym-spelling defect S-121 and the ADR-006 §7 R2 items open. Relying-party registration and access certificate, presentation protocol, trusted lists and any holder/issuer credential layer are unresolved; OPAQUE alone is insufficient |
| EU Cyber Resilience Act | Manufacturer, open-source steward or non-commercial determination; if in scope, essential requirements, vulnerability handling, SBOM, reporting and conformity assessment | Applicability UNRESOLVED |
| Target operation | Reproducible image/toolchain/dependency inventory, measured resource limits, crash/recovery and device tests, incident/backup/restore procedures and operator ownership | Complete unikernel image and deployment evidence absent |

Source checks above were made on 2026-09-25. Recheck the applicable legal texts,
implementing acts, standards and errata when choosing a deployment profile. Do
not assert certification, a compliance deadline or legal applicability from this ADR.

## 4. Acceptance and status changes

Acceptance of this ADR means the goals and work are scheduled. Future completion
requires a coverage-backed audit, independently reviewed designs, exact C99
patches for confirmed surviving defects, meaningful regression/mutant gates and
target evidence, plus the applicable operational/conformity record. Each increment
updates existing proof/security/plan records with its actual scope. Reference
retirement, production deployment and any certification claim are separate gates.
No ledger finding is closed and no code is described as shipped by this decision.
