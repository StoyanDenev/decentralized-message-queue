<!-- SPDX-License-Identifier: BUSL-1.1 -->
# d5 — Government random-selection (reference RP)

**BUSL-1.1** (the dapps catalog default — `../README.md`, `../../LICENSING.md`). Source-available;
free for development/test/CI and for noncommercial production; commercial or public-sector
production use requires a paid grant; converts to Apache-2.0 four years after each release. The
citizen-verifier surface it is checked against stays **Apache-2.0** (`determ-light
verify-selection`), so any member of the public can refute a draw for free.

## What this is

The **reference relying-party (RP) producer** for D.5 — the founding `docs/MOTIVATION.md` use case
(Bulgaria 2011: closed-source, classified random judge-assignment). It is the orchestrator side of
the DApp: it *produces* the three canonical-binary `DAPP_CALL` streams a court authority publishes
for a case, using **only** shipped Apache-2.0 chain primitives:

| Stream (`DAPP_CALL` topic) | Content | Primitive |
|---|---|---|
| `roster` | add/remove non-PII candidate ids | `d5_roster_encode` (d5codec) |
| `case-open` | freeze the eligible roster as of `roster_cutoff_height`; pre-commit `draw_height`, N, M **before** the strictly-future seed is knowable | `d5_case_open_encode` |
| `result` | the N-primary + M-alternate lowest-hash selection over the frozen roster + the authenticated beacon seed | `d5_draw` + `d5_result_encode` |

It has **no consensus authority** and the chain never parses these payloads (`consensus_change_required = false`, `../../docs/proofs/D5-RANDOM-SELECTION-SPEC.md §1`). Its
honesty is enforced **adversarially** by the independent citizen verifier: given the same
committee-authenticated `cumulative_rand[draw_height]` beacon seed (S-042 binding) and the frozen
roster, `determ-light verify-selection` re-derives the identical `SHA256(seed ‖ ctx ‖ id)` draw and
refutes any published `result` that disagrees — never a false `SELECTED`.

## Files

- `d5rp.h` / `d5rp.c` — the producer core: `d5_rp_build_roster`, `d5_rp_build_case_open`,
  `d5_rp_open_and_draw` (compute the canonical draw **and** build the `result` payload). Each emits
  a complete `DAPP_CALL` payload — a d5codec body wrapped in the chain envelope
  (`[u8 topic_len][topic][u32 LE ct_len][ct]`), encoded in place with no oversized temporary.
- `d5rp_main.c` — the `d5rp` CLI (`selftest`, `emit`).

This module is the substrate from which the Apache-2.0 RP SDK (`../../sdk/rp`) is later extracted
(CURRENT FRONT item 3, DECISION-LOG 2026-07-26).

## Gate — `d5rp selftest`

The FAST offline gate produces the three streams for a fixed scenario, strips each `DAPP_CALL`
envelope, decodes via d5codec, and **independently re-derives** the lowest-hash draw over the
decoded roster + seed — asserting it **equals the published `result`**. This is exactly the contract
`verify_selection_core` enforces, so an honest RP's output is provably re-derivable. A **tamper NEG**
flips one byte of a published selected id and confirms the round-trip catches it. Falsify-on-mutant:
mutating `d5_rp_open_and_draw` to publish a non-canonical result flips **only** the
"published == canonical" assertions RED. Wrapper: `../../tools/test_d5rp.sh`.

```bash
cmake --build build --config Release --target d5rp
./build/Release/d5rp selftest     # 9 pass / 0 fail
./build/Release/d5rp emit         # the demo scenario's three payloads, hex
```

## Status

- **Verifier (Apache-2.0):** shipped — `roster`/`case-open`/`result` codecs, the S-042 `verify-rand`
  beacon read, and the `verify-selection` citizen verifier (SPEC §12 inc.2–5c).
- **Producer (this module, BUSL-1.1):** shipped — SPEC §12 inc.6a (producer core + round-trip gate).
- **Next:** the live end-to-end on a 3-of-5 fixture (submit the produced streams; run the real
  `verify-selection` against them) — SPEC §12 inc.6b.
