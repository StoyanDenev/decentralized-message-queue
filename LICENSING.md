# Determ — licensing (Apache-2.0 core, free for all / BUSL-1.1 DApps)

> **Authoritative license map.** Determ is **multi-licensed**, two tiers:
>
> 1. **Everything except `dapps/**`** — daemon / consensus core, C99 crypto library, light
>    client, wallet, SDK, DSSO client libs, tools, docs — **Apache-2.0. Free for everyone,
>    for any use, forever.**
> 2. **All reference DApps (`dapps/**`, D.1–D.10) — BUSL-1.1** (source-available): free for
>    development / evaluation / test / CI, **and free for noncommercial production** (natural
>    persons and noncommercial organizations). **Production use by or for a commercial entity
>    or a government / public-sector body requires a paid grant** — this is the royalty. Each
>    release converts to Apache-2.0 on its Change Date (4 years after publication).
>
> **The Licensor operates reference instances of the DApps on the network free of charge for
> end users.** Using a hosted instance requires no code license — the license governs
> deploying/operating the code, not consuming a service.
>
> **This is not legal advice.** Grant drafting (the commercial / public-sector / noncommercial
> definitions) is **PENDING-COUNSEL** (`docs/proofs/DECISION-LOG.md` 2026-07-25, licensing
> v3.1, which supersedes v3's dual core and per-DApp split).

## Why this structure

Problem: royalties from commercial and public-sector operators, without taxing the ecosystem,
the end users, or the founding public-interest mission. The core through the 2026-07-21 push is
already irrevocably published under Apache-2.0 (public GitHub remote, many clones), and an L1's
real moat is the running network — the K-of-K operator set, audits, certification, trademark —
not source secrecy. So:

- **Apache core, free for all** — zero procurement friction for the government-first market,
  zero integration friction for wallets/clients/DApp builders, credibly un-capturable by
  openness rather than by copyleft. Sole copyright preserves the option to tighten *future*
  releases if a capture threat materializes (a ratchet that only tightens forward).
- **All DApps BUSL-1.1** — the deployables are where paying entities show up. Source stays
  fully visible (the provable-security posture needs source availability, not OSI approval).
  The noncommercial production grant keeps the public-interest cases free (journalists,
  communities, individuals self-hosting); ministries and companies deploying their own pay.
- **Non-license lanes** (no code-license impact): trademark / "Determ Certified" certification,
  and a compliance-evidence + security-update subscription (audit reports, FIPS/NIS2 evidence
  packages, patch SLA).

## The rules (mechanically checkable)

1. A file under `dapps/<name>/` => **BUSL-1.1** (all nine DApps; the owner may re-grant a DApp
   before its first public release).
2. A file under `third_party/**` => its upstream license (do **not** relicense).
3. Every other file in the repository => **Apache-2.0**.

Leaf rule: Apache-2.0 code may be used inside the BUSL DApps; **BUSL code never enters anything
outside `dapps/**`** — each DApp is a leaf: it links the Apache SDK/clients, nothing links it.

## Component map

| Component | Paths | License |
|---|---|---|
| `determ` daemon + chain | `src/**` (all), `include/**` | Apache-2.0 |
| `determ-crypto-c99` | `src/crypto/**` | Apache-2.0 |
| `determ-light`, `determ-wallet` | `light/**`, `wallet/**` | Apache-2.0 |
| SDK + DSSO client libs | `sdk/**` | Apache-2.0 |
| sim / tools / tests / docs | `sim/`, `tools/`, `test*/`, `docs/` | Apache-2.0 |
| **All reference DApps (D.1–D.10)** | `dapps/**` | **BUSL-1.1** |
| Vendored deps | `third_party/**` | unchanged upstream |

## BUSL-1.1 parameters (fixed per DApp release)

| Field | Value |
|---|---|
| Licensor | owner legal name / entity — **counsel to fix** |
| Licensed Work | the specific DApp release (name + version) |
| Additional Use Grant | development, evaluation, testing, CI; **and production use by natural persons and noncommercial organizations for noncommercial purposes**. Production use by or for a commercial entity, or by or for a government / public-sector body, requires a commercial license from the Licensor. *(Recorded intent — exact definitions are counsel work; PolyForm-Noncommercial-style definitions are the reference precedent.)* |
| Change Date | 4 years after that release's first publication |
| Change License | Apache License 2.0 |

## Files in this repo

- `/LICENSE` — multi-license pointer. `/NOTICE` — Apache NOTICE for the Apache components.
- `/LICENSES/Apache-2.0.txt` — canonical text. `/LICENSES/BUSL-1.1.txt` — **deliberate
  placeholder**: paste verbatim from <https://mariadb.com/bsl11/>; legal text must be verbatim.
  `/LICENSES/AGPL-3.0.txt` — tombstoned (unused since v3.1; safe to delete).
- `/COMMERCIAL-LICENSE.md` — draft-for-counsel structure of the paid lanes (not an offer).
- `src/crypto/LICENSE`, `light/LICENSE`, `wallet/LICENSE`, `sdk/LICENSE` — Apache markers;
  `dapps/LICENSE` — the DApp tier (all BUSL-1.1).
- `tools/apply_spdx_headers.sh` — SPDX stamper per the rules above (idempotent; review first).

## Owner action items (before the structure is legally effective)

1. **Counsel:** BUSL grant drafting (commercial / public-sector / noncommercial definitions),
   a CLA for any external `dapps/**` contribution (sole copyright in the DApps is what "owning
   them" means), trademark filing for "Determ" / "Determ Certified", sanctions/end-use
   screening clauses for commercial grants, and the Bulgarian Electronic Governance Act /
   EU-procurement check **before D.5 is priced**.
2. **Paste the canonical BUSL-1.1 text** into its placeholder file.
3. **Forward-only:** everything pushed through 2026-07-21 remains Apache-2.0 for its holders;
   this map applies from the next release.
4. **Review + run** `tools/apply_spdx_headers.sh`; stamp DApp code `BUSL-1.1` when it lands.

## Downstream effect (plain English)

- **Everyone, for the entire core:** free, Apache-2.0, explicit patent grant — run, modify,
  embed, resell, no obligations beyond attribution.
- **End users of the DApps:** free — they use the Licensor's hosted instances, which is not a
  licensed activity at all.
- **Individuals / noncommercial organizations self-hosting a DApp:** free, even in production.
- **Companies and public-sector bodies deploying a DApp:** buy the production grant (the
  royalty) — or wait out that release's 4-year Change Date, after which it is Apache-2.0.
- **Everyone:** all source stays published and inspectable — the provable-security story loses
  nothing.
