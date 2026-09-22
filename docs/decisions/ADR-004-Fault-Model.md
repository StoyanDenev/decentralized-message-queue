# ADR 004: Fault Model Correction (Proof of Sequential Work)
**Date:** 2026-09-22
**Status:** Direction accepted; production protocol and security proof incomplete.

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
