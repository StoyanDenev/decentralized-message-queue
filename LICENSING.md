# Determ — licensing (split: AGPL-3.0 core / Apache-2.0 libraries & clients)

> **Authoritative license map.** Determ is **multi-licensed**. The daemon / consensus-execution
> core is **AGPL-3.0-or-later**; the reusable C99 crypto library, the light client, the wallet, and
> the future SDK / DSSO client libraries are **Apache-2.0**.
>
> **This is not legal advice.** Relicensing and contributor consent are decisions for the copyright
> holder and counsel. Prepared 2026-07-23; the repo was previously all-Apache-2.0.

## Why split

The consensus/node code is where **capture** would hurt — AGPL's network clause (§13) stops anyone
running an *improved, closed* fork of the Determ daemon as a service without offering source, which
matches the project's mutual-distrust / public-interest posture. The **libraries and clients** are
where **adoption** happens — permissive Apache-2.0 (with its explicit patent grant) lets governments,
regulated operators, wallet vendors, and DApp builders reuse the crypto, verification, and identity
code in closed products with zero copyleft friction. Split licensing gets both: an un-capturable core
and a frictionless ecosystem.

## The rule (unambiguous, mechanically checkable)

> A source file is **Apache-2.0** if it is compiled into any client/library target
> (`determ-crypto-c99`, `determ-light`, `determ-wallet`, the SDK, all DApps (D.1-D.9), and DSSO client libs). A file compiled
> **only** into the `determ` daemon is **AGPL-3.0-or-later**.

This direction is forced by license compatibility: **Apache-2.0 code may be incorporated into an
(A)GPLv3 work, but not the reverse** (FSF-confirmed, one-way). So the AGPL daemon may freely link the
Apache libraries, but **no Apache binary may contain AGPL code** — hence any file a client compiles
must be Apache.

## Component map (from `CMakeLists.txt`)

| Target | Paths | License |
|---|---|---|
| `determ-crypto-c99` (static lib) | `src/crypto/**` (all `.c` and `.cpp`) | **Apache-2.0** |
| `determ-light` (light client) | `light/**` + reused `src/chain/block.cpp`, `src/chain/genesis.cpp`, `src/crypto/*.cpp` | **Apache-2.0** |
| `determ-wallet` | `wallet/**` | **Apache-2.0** |
| DApps + SDK + DSSO client | `dapps/**`, `sdk/**`, DSSO client libs (wherever they land) | **Apache-2.0** (owner decision 2026-07-23) |
| `determ` (daemon) | `src/node/**`, `src/net/**`, `src/rpc/**`, `src/main.cpp`, and `src/chain/**` *except* the two shared files below | **AGPL-3.0-or-later** |
| `third_party/**` | vendored deps (e.g. nlohmann/json) | **unchanged** — their own upstream licenses (do **not** relicense) |
| `sim/`, `tools/`, `test*/`, `docs/` | dev / test / docs | AGPL-3.0-or-later by default, unless a file is compiled into a client target |

### Boundary files — Apache-2.0 even though they live under `src/chain/`

The Apache light client compiles these directly, so they **must** be Apache-2.0; they carry an
explicit `SPDX-License-Identifier: Apache-2.0` header:

- `src/chain/block.cpp` + `include/determ/chain/block.hpp` — block wire format / codec
- `src/chain/genesis.cpp` (+ its header) — genesis construction

Keeping the consensus **data structures + genesis** permissive is intentional and desirable: it lets
third parties build interoperable clients and verifiers. The AGPL teeth are over the **node
execution** — consensus apply/validate, networking, RPC — which is what a competitor would fork.

## Files in this repo

- `/LICENSE` — short multi-license pointer (this split).
- `/LICENSES/AGPL-3.0.txt`, `/LICENSES/Apache-2.0.txt` — the canonical full texts.
- `/NOTICE` — Apache-2.0 NOTICE for the Apache components.
- `src/crypto/LICENSE`, `light/LICENSE`, `wallet/LICENSE` — Apache-2.0 per-component markers.
- `tools/apply_spdx_headers.sh` — stamps every source file with its `SPDX-License-Identifier` per the rule (idempotent; review before running).

## Owner action items (before the split is legally effective)

1. **Paste the canonical AGPL-3.0 text** into `/LICENSES/AGPL-3.0.txt` from
   <https://www.gnu.org/licenses/agpl-3.0.txt>. It is deliberately **not** reproduced here — legal
   text must be verbatim, and hand-copying risks a defective license.
2. **Confirm copyright ownership** for the relicense. The daemon files move Apache-2.0 → AGPL-3.0;
   that is only yours to do if you hold, or have consent for, all copyright in those files. A
   solo/owner-held project can relicense freely; any externally-Apache-contributed *daemon* code
   stays Apache unless its author agrees.
3. **Confirm the boundary.** The consensus wire-format/genesis substrate is Apache because the light
   client currently compiles it. If you wanted those AGPL, the light client must stop compiling them
   directly (refactor into a small Apache "protocol" library it links). Recommended: leave as Apache.
4. **Review and run** `tools/apply_spdx_headers.sh`, then commit.

## Downstream effect (plain English)

- Anyone may reuse the **Apache** libraries — crypto, light client, wallet, SDK/DSSO — in closed or
  commercial products, with the Apache patent grant, no source-sharing obligation.
- Anyone who runs a **modified daemon** as a network-accessible service must offer that daemon's
  source to its users (AGPL §13). Running the *unmodified* daemon triggers no such obligation.
- The combined daemon binary is effectively AGPL (the strongest license in the combination governs
  the whole executable), with the Apache components remaining independently reusable in source form.
