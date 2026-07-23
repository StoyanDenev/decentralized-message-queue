# Determ DApps (Apache-2.0)

The reference DApp catalog. **All code here is Apache-2.0** (owner decision 2026-07-23 —
`../LICENSING.md`, `../docs/proofs/DECISION-LOG.md`), so third-party and commercial DApp builders
reuse it without copyleft friction. DApps consume only shipped chain primitives + DSSO; they are
**not** part of the AGPL consensus core.

## Catalog (V1.1-PLAN Bundle D / PRE-LAUNCH §E2)

Tier-1 (DSSO + shipped primitives):
- `d5-random-selection/` — government random judge/jury assignment (founding `MOTIVATION.md` use case; DSSO + commit-reveal randomness + audit hooks). **First DApp (active front, DECISION-LOG 2026-07-23).**
- `d1-liberty-bell/` — provably-fair Liberty Bell lottery (CT + audit + verifiable randomness).
- `d9-merritt-voting/` — Byzantine-fault-tolerant elections (Merritt 1984) + DSSO + confidential ballots.
- `d2-b2b-settlement/` — confidential vendor-invoice settlement (v2.15 multi-sig Option A + ROTATE_KEY).
- `d3-journalism/` — source-protection payments (PFS/OTPK + ROTATE_KEY).

Tier-2 (v1.2, zk-VM): `d4-ai-agent/`, `d6-private-rollup/`, `d7-verifiable-inference/`, `d8-anon-credentials/`.

Serialization is the canonical binary codec — **no JSON** (DECISION-LOG 2026-07-23 D2).
