> **TIER: FUTURE — accepted research direction, not implemented.** Nothing in this ADR is shipped consensus; the C++ K-of-K rules remain the implemented protocol. Roadmap index: [ROADMAP.md](../ROADMAP.md)

# ADR 004: Fault Model Correction (Proof of Sequential Work)
**Date:** 2026-09-22 (tier marker and design-note references added 2026-09-23)
**Status:** Research direction accepted by the owner; not implemented, production protocol and security proof incomplete. (The owner's separate goal, restated 2026-09-23, is the C99 migration — docs/C99-MINIX-PORT.md §0.)

## 1. Equivocation and finality

The K=2 experiment does not establish instant, fork-free finality. A participant
can produce conflicting candidates, and a deterministic computation for each
candidate does not make the candidates unique. PoSW with validated cumulative-work
fork choice is the intended research direction. The current C99 driver has no
production block admission, chain adoption or reorganization path. Unused helpers
that compared caller-supplied work totals have been removed; they were not an
implementation of secure fork choice.

## 2. Precomputation and grinding

Colluding participants know their payloads before the commit window and can
precompute candidates. The former economic argument assumed competing honest
pairs with sufficient chain growth without specifying who those pairs are or
bounding adversarial work. That conclusion is withdrawn. A sequential dependency
within one evaluation does not prevent parallel evaluation of independent
candidates, private histories or independent shards.

A production design needs a membership/Sybil model, eligible producer and recovery
rules, a canonical fresh challenge, a specified delay construction and hardness
assumption, timestamp validity, validated work accounting, data availability and
atomic reorganization semantics. Honest/adversarial growth bounds and a finality
policy must be derived from those rules. No confirmation depth is selected here.

## 3. Current implementation contract

C99 `determ-node` is a bounded local two-party experiment. Two commitments and two
matching reveals are required; a missing party fails the attempt. An explicit
retry is not an election or a guarantee of eventual success. Evaluation output is
not a finalized ledger block. See [K2_VDF_Soundness.md](../proofs/K2_VDF_Soundness.md)
for the exact contract, tests and limits.

## 4. Supersession and sharding

The previous C99 claims of fork-free finality, absolute liveness, 1-of-2 fallback,
zero bias and hardware-independent enforced blindness are withdrawn. This ADR
does not replace the existing C++ accept rules or validate their separate claims.
[ADR-005](ADR-005-Temporal-Sharding.md) records the proposed sharding design gate;
beacon deprecation and sharding security do not follow from choosing PoSW.

## 5. Design notes (not proofs)

[PoSW_Nakamoto_Safety.md](../proofs/PoSW_Nakamoto_Safety.md),
[PoSW_Economic_Soundness.md](../proofs/PoSW_Economic_Soundness.md),
[VRF_Sharding_Safety.md](../proofs/VRF_Sharding_Safety.md) and
[tla/PoSWForkChoiceDesign.tla](../proofs/tla/PoSWForkChoiceDesign.tla) sketch parts of this
direction. Each is a future-tier design note whose review-status section lists the
unproven steps and the mechanisms missing from the code; none discharges an obligation
of §2.
