# Mainnet Readiness — tracking artifact

**Status:** scaffold (created 2026-05-24). Beta has not started; criteria status fields are placeholders to be populated by integration threads as Bundle 5 completes and beta progresses.

**Purpose.** Single source of truth for mainnet-declaration readiness. Three internal-quality criteria categories (chosen 2026-05-24) feed into one human decision. Updated continuously by integration threads during beta; reviewed by sole declaration authority when criteria converge.

---

## 1. Declaration authority

**Sole authority:** the user (project lead). No advisory veto, no committee, no partner-vote gate. AI threads provide criteria-status reports as input; declaration itself is unilateral.

**Rationale:** AI threads cannot meaningfully bear permanence-of-launch responsibility under the no-migrations constraint (see memory `dlt-no-migrations-constraint`). The human-in-the-loop is the only entity with standing to commit.

**Reversal:** declaration is one-way. If post-mainnet conditions deteriorate, only security-critical hard fork is available as remediation per the no-migrations constraint.

---

## 2. Criteria categories

Three categories chosen 2026-05-24. Partner-activity-threshold deliberately NOT included — closed beta serves as bug-finder, not legitimacy validator.

### 2.1 DSF Byzantine coverage

**Definition.** All Bundle 5 (Beaconless v2) Byzantine scenarios pass deterministic-simulation cleanly. Specifically, every Byzantine-shard scenario in the DSF coverage matrix executes without consensus violation, liveness loss, or state divergence.

**Specific scenarios** (populated when Bundle 4 DSF is feature-complete; placeholder list):
- [ ] k=1 Byzantine shard, merge-detection triggers correctly
- [ ] k=2 Byzantine shards (with num_shards ≥ 7), Merritt-witness affidavits collected correctly
- [ ] Manifest-mutation under Byzantine cosigning attempts
- [ ] Cross-shard receipt validation under inclusion-proof tampering attempts
- [ ] Light-client header verification under signature-chain tampering attempts
- [ ] Randomness aggregation under late-shard adversarial timing
- [ ] *(populate remaining scenarios from DSF coverage matrix)*

**Status:** N/A (Bundle 4 DSF not yet implemented).

### 2.2 Bug-finding trajectory

**Definition.** Rate of new bug discovery approaching zero in beta partner reports; zero open Sev-1 bugs for a sustained window.

**Specific metrics** (specific numbers TBD pre-beta):
- New Sev-1 bug discovery rate: 0 per [TBD: e.g., 30 days] consecutively
- New Sev-2 bug discovery rate: ≤ [TBD: e.g., 2 per 30 days] consecutively
- Open Sev-1 bug count: 0 for [TBD: e.g., 60 days] consecutively
- Open Sev-2 bug count: ≤ [TBD: e.g., 5] at declaration time

**Severity definitions** (populated pre-beta; placeholder):
- Sev-1: consensus failure, state corruption, fund loss, cryptographic vulnerability
- Sev-2: liveness degradation, operator-facing data loss, recoverable consistency violation
- Sev-3: UX issue, performance degradation, minor inconsistency
- Sev-4: cosmetic, doc issue

**Status:** N/A (beta has not started).

### 2.3 Subsystem zero-bug windows

**Definition.** Specific load-bearing subsystems show zero known bugs at any severity for a defined window prior to declaration.

**Subsystems requiring zero-bug windows** (populated pre-beta; placeholder list):
- Consensus apply path (block validation, state transition): zero bugs in last [TBD] days
- Cryptographic primitives (secp256k1 ECDSA + ECDH + Bulletproofs, FROST-Ed25519): zero bugs in last [TBD] days
- Wallet (key management, tx construction, OTPK lifecycle): zero bugs in last [TBD] days
- Beaconless v2 manifest validation: zero bugs in last [TBD] days
- v2.22 confidential-amount apply path (Pedersen, range-proof verify): zero bugs in last [TBD] days

**Status:** N/A.

---

## 3. Status dashboard (updated continuously during beta)

| Criterion | Status | Last updated |
|---|---|---|
| 2.1 DSF Byzantine coverage | scaffold (pending Bundle 4) | 2026-05-24 |
| 2.2 Bug-finding trajectory | scaffold (pending beta start) | 2026-05-24 |
| 2.3 Subsystem zero-bug windows | scaffold (pending beta start) | 2026-05-24 |

**Convergence test:** all three categories simultaneously in green status → notify sole authority for declaration review. Authority may declare or request additional observation period.

---

## 4. Update discipline (for integration threads)

- Status updates by integration threads ONLY. Implementation threads file bug reports; integration threads triage to severity and update this doc.
- Status updates are append-only in the dashboard's "Last updated" column; historical state preserved via git history.
- Severity-level disputes escalate to sole authority for adjudication.
- Pre-beta: this doc remains scaffold-only. No status changes until Bundle 5 feature-complete.

---

## 5. What this doc is NOT

- **Not a calendar gate.** Beta duration is open-ended per `IMPLEMENTATION-SEQUENCING.md §4.4`. Criteria convergence triggers declaration review, not automatic launch.
- **Not a substitute for judgment.** Criteria are inputs to a human decision, not a replacement for it. Authority may decline to declare even if all criteria green; may defer if confidence is otherwise lacking.
- **Not a partner-facing artifact.** Internal tracking only; partner communications about beta progress should not reference this doc directly.

---

*End of readiness tracking artifact. Updated by integration threads through beta; reviewed by sole authority at convergence.*
