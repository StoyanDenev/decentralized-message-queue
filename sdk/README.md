# Determ SDK (Apache-2.0)

Client / DApp / relying-party developer libraries — **Apache-2.0** (`../LICENSING.md`). Target
bindings: JS + Python + Go.

Planned components:
- `rp/` — relying-party SDK: verify DSSO hash-challenge-response tokens + light-client block-sig / tx-inclusion proofs.
- `dsso/` — DSSO client: threshold-OPAQUE (t-of-n OPRF, credential envelope, the paper's dual-hash assertion).
- `dapp/` — DApp SDK: DAPP_REGISTER / DAPP_CALL helpers + canonical binary-codec bindings.

All wire/serialization is the canonical binary codec — **no JSON** (DECISION-LOG 2026-07-23 D2).
