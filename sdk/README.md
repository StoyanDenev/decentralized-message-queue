# Determ SDK (Apache-2.0)

Client / DApp / relying-party developer libraries — **Apache-2.0** (`../LICENSING.md`). Target
bindings: JS + Python + Go.

Components:
- `rp/` — relying-party / citizen verification SDK.
  - `rp/python/determ_rp/d5.py` — **SHIPPED** (extracted from the working D.5 build, SPEC §12 item 8):
    a D.5 **draw-consistency** check over ONE already-canonicalized triple (a single `ROSTER_ADD`
    envelope + its `case-open` + the published `result`): DAPP_CALL envelope + d5codec decode (with
    the C codec's fail-closed `D5_MAX_ROSTER`/`D5_MAX_FIELD` bounds) + lowest-hash `d5_draw`
    re-derivation vs the published result. `verify_result` REQUIRES the caller-supplied,
    S-042-authenticated beacon seed (no seedless "verify" path — self-consistency against the RP's
    own untrusted seed can never be mistaken for a refutation, doctrine B3). **SCOPE (honest, not
    aspirational):** it does NOT — and structurally cannot (it sees no chain, no block heights, no
    committee signatures) — establish the rest of the SPEC soundness chain. The CALLER is responsible
    for committee-authenticating the blocks + seed, the §9 `h_r ≤ h_o < H < h_s` ordering, the roster
    ADD/REMOVE fold to the cutoff (the SDK refuses a non-ADD op rather than mis-treat a lone REMOVE as
    the eligible set), first-open-wins, and stream completeness. **A citizen facing an untrusted
    daemon uses `determ-light verify-selection`, which does ALL of the above; this SDK alone is not a
    standalone trustless verifier.** Dependency-free (stdlib only). Gated + falsified (incl. the
    lone-REMOVE + codec-bounds NEGs) via the reference `tools/verify_d5rp.py` (which dogfoods it) +
    `tools/test_d5rp.sh`.
  - *planned:* verify DSSO hash-challenge-response tokens + light-client block-sig / tx-inclusion
    proofs; JS + Go bindings of the above.
- `dsso/` *(planned)* — DSSO client: threshold-OPAQUE (t-of-n OPRF, credential envelope, the paper's dual-hash assertion).
- `dapp/` *(planned)* — DApp SDK: DAPP_REGISTER / DAPP_CALL helpers + canonical binary-codec bindings.

All wire/serialization is the canonical binary codec — **no JSON** (DECISION-LOG 2026-07-23 D2).
