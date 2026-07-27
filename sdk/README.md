# Determ SDK (Apache-2.0)

Client / DApp / relying-party developer libraries — **Apache-2.0** (`../LICENSING.md`). Target
bindings: JS + Python + Go.

Components:
- `rp/` — relying-party / citizen verification SDK.
  - `rp/python/determ_rp/d5.py` — **SHIPPED** (extracted from the working D.5 build, SPEC §12 item 8):
    verify a published D.5 government random-selection from its `DAPP_CALL` streams (envelope +
    d5codec decode + lowest-hash `d5_draw` re-derivation) — never a false SELECTED. `verify_result`
    REQUIRES the caller-supplied, S-042-authenticated beacon seed: there is no seedless "verify"
    path, so self-consistency against the RP's own (untrusted) seed claim can never be mistaken for a
    real refutation (provable security, doctrine B3). Dependency-free (stdlib only). Gated +
    falsified via the reference `tools/verify_d5rp.py` (which dogfoods it) + `tools/test_d5rp.sh`.
  - *planned:* verify DSSO hash-challenge-response tokens + light-client block-sig / tx-inclusion
    proofs; JS + Go bindings of the above.
- `dsso/` *(planned)* — DSSO client: threshold-OPAQUE (t-of-n OPRF, credential envelope, the paper's dual-hash assertion).
- `dapp/` *(planned)* — DApp SDK: DAPP_REGISTER / DAPP_CALL helpers + canonical binary-codec bindings.

All wire/serialization is the canonical binary codec — **no JSON** (DECISION-LOG 2026-07-23 D2).
