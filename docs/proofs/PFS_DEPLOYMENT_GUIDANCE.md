> **TIER: FUTURE — post-1.0, non-authoritative.** Design-stage; does NOT describe shipped code and is NOT coherence-maintained against src/. Roadmap index: docs/ROADMAP.md

# PFS_ONLY deployment guidance — regulatory framework for operators

**Audience.** Operator legal, compliance, and risk teams evaluating whether to deploy Determ accounts in `PFS_ONLY` mode (per v2.22-PRIVACY-SPEC.md §Q5 PRIV-6). Regulators reviewing a deployment that uses `PFS_ONLY`.

**Purpose.** Provide a starting framework so each operator's counsel can evaluate `PFS_ONLY` for their specific jurisdiction and use case without rebuilding the cryptographic analysis from scratch.

**This is not legal advice.** This document describes the cryptographic property and maps it to broad regulatory categories. Specific deployment decisions require jurisdiction-specific counsel. The framework here is a *starting point* for that counsel's analysis, not a substitute for it.

---

## 1. What PFS_ONLY does (in plain language)

`PFS_ONLY` is one of three modes a Determ account can be created in:

- **`AUDITABLE_ONLY`** — every confidential transaction is decryptable by anyone who has the account's `view_master_sk` (typically the account holder; optionally a regulator with standing audit access). This is the default for regulated deployments.
- **`MIXED`** — sender picks per transaction between auditable and PFS modes.
- **`PFS_ONLY`** — every confidential transaction is decryptable only by the sender and recipient at the moment of the transaction. **No third party at any time holds a key that can decrypt the transaction amount.**

The cryptographic property of `PFS_ONLY`, stated precisely:

> For any confidential transaction received by a `PFS_ONLY` account, no key in existence at any time after the recipient processes the transaction can decrypt the amount. The recipient deletes the only such key immediately after decryption. Sender and recipient each retain their own knowledge of the amount, but the on-chain record alone does not yield the amount to any party — including the recipient themselves if their wallet state is later lost.

This is called **Perfect Forward Secrecy** (PFS) — a standard cryptographic guarantee, well-understood in messaging protocols (Signal, WhatsApp, TLS with ECDHE). Applied to financial transactions, it means there is no master key that, if compelled by subpoena or compromised by attack, could decrypt the account's history of confidential transaction amounts.

**What `PFS_ONLY` does NOT hide:**

| On-chain element | Visibility |
|---|---|
| Sender address | Public |
| Recipient address | Public |
| Transaction existence | Public |
| Transaction timing | Public |
| Transaction fee | Public |
| Account having `PFS_ONLY` policy | Public (the policy field is on-chain) |
| Transaction amount | **Hidden** (Pedersen commitment) |
| Range of valid amounts (proves amount ≥ 0) | Public (range proof) |

`PFS_ONLY` is exclusively about *amount confidentiality with forward secrecy*. Graph privacy (hiding who pays whom) is out of scope; chain analysis can still trace counterparty relationships.

---

## 2. Auditor reconciliation procedure

Because no master key exists, auditors evaluating a `PFS_ONLY` deployment cannot perform unilateral decryption. The audit path is **compelled disclosure from the sender**, analogous to forensic accounting of cash transactions.

**The procedure:**

1. **Auditor identifies a transaction** of interest from on-chain records (sender, recipient, height, tx_hash).
2. **Auditor compels the sender** (via subpoena, regulatory order, or contractual cooperation) to produce the reconciliation tuple for that transaction:
   - `recipient_addr`
   - `otpk_id` (one-time pubkey identifier consumed by the tx)
   - `amount` (plaintext)
   - `blinding_factor` (used to construct the Pedersen commitment)
   - `tx_hash`

3. **Auditor verifies the disclosure cryptographically** in five steps (no trust in sender's word required):
   a. Fetch tx_hash from chain → confirm `tx.to == recipient_addr` and tx is in `AMT_PFS` mode.
   b. Fetch the original `PUBLISH_OTPK_BATCH` from chain history → recover the OTPK pubkey for `otpk_id`.
   c. Recompute the Pedersen commitment: `commitment = amount · G + blinding_factor · H` (on secp256k1).
   d. Compare against `tx.amount_commitment` on-chain.
   e. If equal → sender's disclosure is cryptographically verified. If unequal → sender is providing false information; auditor knows the disclosed amount is wrong but does not learn the true amount.

**Sender retention requirement.** Sender wallets retain a `PfsOutboundRecord` for every `AMT_PFS` transaction (blinding factor + amount + tx_hash + timestamp + recipient address). Recommended retention period: 7+ years, matching typical jurisdiction tax-record requirements. This is a wallet-software discipline, not a chain-enforced rule.

**What this audit path provides:**
- ✅ Cryptographic verifiability of disclosed amounts (sender cannot lie undetected)
- ✅ Compellability via existing legal mechanisms (subpoena, regulatory order)
- ✅ Cooperative-counterparty disclosure (recipient can also provide their record if available)

**What this audit path does NOT provide:**
- ❌ Unilateral access by any third party (no master key exists to compel)
- ❌ Recovery from uncooperative sender + recipient wallet loss (amount is structurally unrecoverable)
- ❌ Real-time monitoring (audit is retrospective by request, not continuous)

This audit model is closer to **forensic accounting of cash payments** than to traditional financial-records auditing. The legal mechanism for compelling records exists; the mechanism for continuous visibility does not.

---

## 3. Regulatory-category mapping (broad strokes)

The following categorization is **not jurisdiction-specific**. It identifies which regulatory frameworks have positions broadly aligned with, broadly incompatible with, or ambiguous regarding `PFS_ONLY`'s properties. Each operator's counsel must determine the position in their specific jurisdiction.

### 3.1 Likely compatible

Frameworks where `PFS_ONLY`'s property (no master key; compellable records exist with sender) is generally accepted:

| Framework category | Why generally compatible |
|---|---|
| **Privacy / data-minimization frameworks** (GDPR Art. 5(1)(c), similar globally) | Data-minimization principle may *favor* PFS_ONLY for handling sensitive amount data. Pseudonymization + amount confidentiality reduces personal-data exposure. |
| **AML/KYC frameworks** where focus is on counterparty identity rather than amounts | Sender/recipient addresses remain public; KYC-at-onboarding still applies. Amount-blinding doesn't impede sanctions screening (operates on addresses). |
| **Whistleblower-protection regimes** | PFS_ONLY structurally protects source identity by hiding amounts that could reveal payment patterns to specific informants. |
| **Journalistic source protection** (US Shield Laws, EU Press Freedom) | Same reasoning — amount opacity prevents inference of source relationships from payment patterns. |
| **Charitable-donation privacy** in jurisdictions recognizing donor confidentiality | PFS_ONLY enables anonymous donation amounts while keeping recipient identity public. |
| **B2B settlement** where amounts are commercially sensitive but jurisdictions don't require continuous third-party visibility | Compellable records via sender remain available for tax/dispute purposes. |

### 3.2 Likely incompatible

Frameworks that typically require continuous third-party visibility into transaction amounts:

| Framework category | Why generally incompatible |
|---|---|
| **Banking supervision** (Fed, OCC, ECB, BoE prudential supervision) | Banks face continuous reporting requirements on customer transaction amounts (BSA, large-cash-transaction reports, suspicious-activity reports requiring amount thresholds). Continuous visibility cannot be satisfied by retrospective subpoena. |
| **Securities transaction reporting** (SEC, ESMA, FCA) | Trade reporting typically requires amount + price visibility per transaction in near-real-time. PFS_ONLY's compelled-disclosure model is too slow. |
| **MSB / money-transmitter licenses with amount-threshold reporting** | Many state and national MSB regimes require amount-based reporting (e.g., FinCEN CTR for transactions ≥$10K). Without continuous visibility, the reporting trigger cannot be reliably detected. |
| **Sanctions enforcement requiring amount-based screening** | If sanctions screening triggers on amount (e.g., per-day-aggregate against a sanctioned counterparty), continuous amount visibility is required. |
| **Tax-authority real-time invoicing** (e.g., Italy, several Latin American countries) | Some jurisdictions require near-real-time transaction-level reporting to tax authorities. PFS_ONLY's retrospective audit path doesn't satisfy this. |

### 3.3 Ambiguous / consult counsel

Frameworks where position depends on interpretation, use-case specifics, or unsettled regulatory questions:

| Framework category | Why ambiguous |
|---|---|
| **MiCA (EU)** | MiCA's treatment of confidential-amount cryptoassets is unsettled at time of writing; positions may vary by issuer category. |
| **Most APAC crypto frameworks** (Singapore MAS, Hong Kong SFC, Japan PSA) | Recent regulatory updates; specific treatment of forward-secret amount confidentiality varies. |
| **Tax record-keeping in jurisdictions accepting electronic records** | PFS_ONLY satisfies retention via sender records; whether this is acceptable for a specific jurisdiction depends on whether self-custody electronic records are accepted as primary documentation. |
| **Regulated gambling** with jurisdiction-specific player-protection rules | Amount-visibility requirements vary by jurisdiction; some require regulator standing access, others accept on-demand disclosure. |
| **Insurance / payment-processor licenses** | Highly variable per jurisdiction; some accept compellable-records model, others require continuous visibility. |

---

## 4. Operator decision framework

A four-step process for operators evaluating `PFS_ONLY` for a specific deployment:

### Step 1: Classify the use case

What is the deployment serving? Common categories:

- Commercial B2B settlement (vendor invoicing, supply-chain payments)
- Consumer-to-consumer payments (peer-to-peer, remittance)
- Regulated financial service (banking, MSB, broker-dealer, payment processor)
- Charity / non-profit
- Journalism / source-protection
- Internal treasury / corporate cash management
- Other

### Step 2: Identify the regulatory frameworks

For the use case + jurisdiction(s) of operation, list applicable regulatory frameworks. Counsel will know these — they typically include:

- AML/KYC framework (always applicable)
- Licensing framework specific to the use case (MSB, banking, securities, etc.)
- Tax / record-keeping framework
- Sanctions framework
- Privacy / data-protection framework
- Use-case-specific regulations (gambling, healthcare, etc.)

### Step 3: Map each framework to §3 categories

For each applicable framework, determine whether it falls into:

- **§3.1 Likely compatible** → `PFS_ONLY` is a viable choice; counsel confirms jurisdiction-specific interpretation
- **§3.2 Likely incompatible** → `PFS_ONLY` is unlikely to be deployable; use `AUDITABLE_ONLY` instead
- **§3.3 Ambiguous** → counsel makes the call based on jurisdiction-specific guidance

### Step 4: Apply the conservative-disjunction rule

If ANY applicable framework falls in §3.2 (likely incompatible), the deployment as a whole likely cannot use `PFS_ONLY`. Regulatory compliance is conjunctive — passing four frameworks but failing one means failing overall.

If all applicable frameworks fall in §3.1 (likely compatible), `PFS_ONLY` is the default-acceptable choice subject to counsel confirmation.

If the mix includes §3.3 (ambiguous) entries, counsel determines deployment posture per-jurisdiction. Common outcomes:
- `PFS_ONLY` permitted with additional operational controls (e.g., enhanced sender-record retention)
- `MIXED` mode used as middle ground (sender picks per tx)
- `AUDITABLE_ONLY` chosen defensively pending regulatory clarity

### Fallback option: MIXED mode

Operators uncertain about a `PFS_ONLY` deployment can use `MIXED` mode and have the sender wallet default to `AMT_AUDITABLE` for all outbound transactions. This provides operational equivalence to `AUDITABLE_ONLY` while preserving the option to use `AMT_PFS` for specific transactions where it's clearly appropriate (and counsel-approved).

---

## 5. Disclaimers

This document is published as engineering reference material, not as legal advice. It does not establish an attorney-client relationship. It does not represent the position of any regulator. Regulatory positions evolve; this document may not reflect current positions in any specific jurisdiction.

Before deploying any account in `PFS_ONLY` mode (or any `MIXED` account that uses `AMT_PFS` transactions), operators must obtain jurisdiction-specific legal counsel. Counsel should evaluate:

- All applicable regulatory frameworks for the operator's specific use case and jurisdictions of operation
- The cryptographic properties described in §1 and the audit procedure described in §2
- Whether the §3 categorization holds in the operator's jurisdiction (regulatory positions vary)
- Whether the operator's specific deployment posture (sender-record retention, wallet UX, audit cooperation procedures) satisfies applicable requirements

Failure to obtain appropriate counsel before deployment may result in regulatory enforcement action, fines, license revocation, or criminal liability depending on jurisdiction and use case.

The Determ project (chain code, specs, this document) accepts no liability for deployment decisions made by operators. The chain code ships `PFS_ONLY` as a technical capability; whether to deploy it is the operator's responsibility.

---

## 6. Maintenance

**Trigger for review.** This document should be re-examined at least quarterly, or whenever:

- A jurisdiction relevant to active deployments issues new guidance on confidential-amount cryptoassets
- A regulatory enforcement action involves PFS-style cryptographic properties
- An operator reports a counsel determination that conflicts with the §3 categorization
- A new use case is added to operator-facing materials that requires §4 framework extension

**Update procedure.** Any update should preserve the framework structure; jurisdiction-specific positions should not be added (this is operator counsel's responsibility, not the framework doc's). Updates should be additive (new categories, refined categorization) rather than retroactive corrections (preserve the original framework for audit purposes; note revisions explicitly).

---

*End of guidance.*
