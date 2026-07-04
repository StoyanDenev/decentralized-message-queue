> **TIER: PROCESS / COVERAGE.** Integration/coverage artifact — a lifecycle map over the R58 at-rest KDF migration, NOT a new crypto proof. It introduces no theorems; it draws the edges between the shipped code paths and the existing envelope/keyfile proofs. Roadmap index: docs/ROADMAP.md

# AtRestKdfMigrationCoverage — end-to-end coverage map of the at-rest KDF migration (PBKDF2 → Argon2id)

This is a **coverage map**, not a proof. R58 (2026-07-04) flipped the default keyfile KDF from PBKDF2-HMAC-SHA-256 (the `DWE1` wire layout) to memory-hard Argon2id (the `DWE2` layout) — `wallet/envelope.cpp` + `wallet/envelope.hpp` + `include/determ/crypto/argon2/argon2id.h`. The soundness *delta* is proved in [`KeyfileArgon2Migration.md`](KeyfileArgon2Migration.md) (KM-1..KM-5); the underlying AEAD primitive in [`EnvelopeKeyfileCrypto.md`](EnvelopeKeyfileCrypto.md) (KE-1..KE-4); the application layer in [`S004KeyfileAtRest.md`](S004KeyfileAtRest.md) (T-1..T-5). What no single one of those supplies is the **lifecycle picture**: for every stage an at-rest secret passes through — creation, daemon read-back, inspection, upgrade, operator audit — *which KDF is in force and why*. This document assembles that, cites `file:line` for each edge, and states honestly what remains PBKDF2 on disk.

No new theorems. Every `KM-*` / `KE-*` / `T-*` label used here is defined and proved in its home document; this map only records which code path each backs.

**The two wire layouts (the discriminant everything keys on).** Both serialize as 6 dot-separated hex parts — `magic . salt . params . nonce . aad . ciphertext` (`serialize`, `wallet/envelope.cpp:208-228`). The 4-byte magic is the sole discriminant:

| Layout | Magic | KDF | `params` slot | Source |
|---|---|---|---|---|
| **DWE1** | `0x31455744` "DWE1" | PBKDF2-HMAC-SHA-256 | 4 bytes (`iters` u32 LE) | `wallet/envelope.cpp:25`, `:217-218`, `:258-262` |
| **DWE2** | `0x32455744` "DWE2" | Argon2id (RFC 9106) | 12 bytes (`t \| m_kib \| p`, u32 LE ×3) | `wallet/envelope.cpp:26`, `:211-216`, `:250-257` |

The AEAD leg (AES-256-GCM, 12-byte nonce, 16-byte tag) is **byte-identical** across both — same `fill_salt_nonce` (`:77-83`), same `seal` (`:64-75`), same `decrypt` tag-verify (`:158-165`). Only the derived-key provenance differs (KM-1). DWE2 defaults: `t=3`, `m=64 MiB` (65 536 KiB), `p=1` (`wallet/envelope.hpp:64-66`) — above the OWASP Argon2id floor.

---

## 1. The at-rest lifecycle (the coverage table)

Each stage below handles an envelope-wrapped secret at rest. The **KDF column** is *what that stage produces or consumes*; the **why** is the design reason.

| # | Stage | Code path | KDF in force | Why |
|---|---|---|---|---|
| 1 | **CREATION** | `envelope::encrypt` → `encrypt_argon2id` | **DWE2 / Argon2id** | R58 default flip: `encrypt` delegates to `encrypt_argon2id` with the §defaults (`wallet/envelope.cpp:126-131`). Every fresh envelope is memory-hard. |
| 2 | **DAEMON READ-BACK** | `envelope::decrypt` (auto-detect) | **either** (magic-selected) | The `determ` binary links `wallet/envelope.cpp` (`src/main.cpp:34-36`) and decrypts via `envelope::decrypt`, which routes on `env.kdf` set by `deserialize` from the magic (`wallet/envelope.cpp:144-152`). A DWE2 envelope is read back with zero call-site change. |
| 3 | **INSPECTION** | `inspect-envelope` / `keyfile-info` | **reported, not run** | Both report `format`/`kdf`/params from the deserialized header **without decrypting** — no passphrase, no KDF execution (`wallet/main.cpp:1157-1210`, `:6033-6066`). |
| 4 | **UPGRADE** | `keyfile-reencrypt` | **DWE1/2 → DWE2** | Opportunistic re-wrap: decrypt under old passphrase, re-`encrypt` (=Argon2id default) under new (`wallet/main.cpp:4740`, `:4823`). Not in-place, not bulk. |
| 5 | **OPERATOR AUDIT** | inspect-envelope `--json` `.kdf` sweep | **classifies** | An operator flags remaining DWE1 files by parsing `inspect-envelope --json`'s `kdf` field (`wallet/main.cpp:1160-1187`). No dedicated audit script ships (see §3.5). |

### 1.1 CREATION — every fresh envelope is Argon2id

`encrypt(plaintext, password, aad)` unconditionally delegates to `encrypt_argon2id` with the `wallet/envelope.hpp:64-66` defaults (`wallet/envelope.cpp:126-131`). Every producer of an at-rest secret routes through this single entry point:

- **`keyfile-create`** (encrypted node keyfile) — `envelope::encrypt(pt_bytes, passphrase, aad=pubkey_hex_bytes)` (`wallet/main.cpp:3627`), AAD-bound to the validator pubkey (`:3622`), with a decrypt round-trip self-test before write (`:3646`).
- **`account create --passphrase`** (encrypted `DETERM-ACCOUNT-V1` file) — `envelope::encrypt(pt_bytes, passphrase, aad)` (`src/main.cpp:5046`), the daemon-binary path, AAD-bound to the address.
- **`backup-create`** (per-share Shamir envelopes) — `envelope::encrypt(s.y, pw_by_index[idx])` per share (`wallet/main.cpp:3278`).
- **`create-recovery`** (persisted T-of-N recovery setup) — `recovery::create` wraps each share via `envelope::encrypt(shares[i].y, password, aad)` (`wallet/recovery.cpp:91`); the CLI (`wallet/main.cpp:6577`) routes through it.

All four therefore emit **DWE2** after R58 (KM-1 gives them the unchanged AEAD guarantees; KM-2 the hardened dictionary bound). *(Note: there is no `account-create-with-passphrase` subcommand; the encrypted-account path is `account create --passphrase`, and `create-recovery` reaches `envelope::encrypt` transitively through `recovery::create`, not directly — the coverage is the same.)*

### 1.2 DAEMON READ-BACK — a DWE2 keyfile is fully readable by `determ`

`decrypt` selects the KDF from `env.kdf` and runs the shared AEAD tag-verify regardless of layout (`wallet/envelope.cpp:144-165`). `deserialize` sets `env.kdf` from the magic: `MAGIC2_LE` → `Kdf::ARGON2ID` + 12-byte params (`:250-257`), `MAGIC1_LE` → `Kdf::PBKDF2` + 4-byte params (`:258-262`). The `determ` daemon binary links `wallet/envelope.cpp` (`src/main.cpp:34-36`) and exercises `envelope::deserialize` + `envelope::decrypt` at `src/main.cpp:5119`/`:5125` (the `account decrypt` read-back path). Because that path is KDF-agnostic, **a DWE2 envelope produced by `keyfile-create` decrypts on the daemon binary with no change** — the migration required no daemon-side edit. The daemon's own node key is loaded via `crypto::load_node_key` (plaintext keyfile shape); the envelope decrypt surface it links is the passphrase-encrypted read-back, and it auto-detects the KDF exactly as the wallet binary does.

### 1.3 INSPECTION — KDF reported without decrypting

`inspect-envelope --in <file> [--json]` deserializes and prints `format` (DWE1/DWE2), `kdf`, and the active param set — `argon2_t_cost`/`argon2_m_cost_kib`/`argon2_lanes` for DWE2, `pbkdf2_iters` for DWE1 (`wallet/main.cpp:1157-1210`). `keyfile-info --in <file> [--json]` does the same for a `DETERM-NODE-V1` keyfile (`:6033-6066`). **Neither decrypts** — no passphrase, no KDF run — so inspection is safe on any file and is the primitive an operator sweep is built on (§3.5). The `--json` schema is flat and always emits both param sets (the inactive one reads 0), so a consumer keyed on `pbkdf2_iters` keeps parsing across the migration (`:1167-1187`).

### 1.4 UPGRADE — `keyfile-reencrypt` re-wraps to DWE2, opportunistically

`keyfile-reencrypt --in <old> --out <new>` decrypts the input under the old passphrase (`envelope::decrypt`, `wallet/main.cpp:4740` — auto-detecting DWE1 or DWE2) and re-encrypts under the new passphrase via `envelope::encrypt` (`:4823`), which is the Argon2id default. A DWE1 input therefore **upgrades to DWE2** on re-wrap (fresh salt + fresh nonce, `:4818`), with a decrypt round-trip self-test before write (`:4842`). This is the documented upgrade lever (KM-5.4). It is **opportunistic, not in-place and not bulk**: it produces a new file and only runs when an operator invokes it. A keyfile never re-encrypted keeps its original KDF.

### 1.5 OPERATOR AUDIT — flagging remaining DWE1 files

The audit primitive is `inspect-envelope --json`'s `kdf` field (`wallet/main.cpp:1160`, emitted `:1172`) — an operator walks a keyfile directory, runs `inspect-envelope --json` per file, and flags any whose `kdf` is `pbkdf2-hmac-sha256` (equivalently `format == "DWE1"`) as pending upgrade, feeding the §1.4 re-wrap. `keyfile-info --json` (`:6033`) is the equivalent for `DETERM-NODE-V1` node keyfiles. *(Honesty: no `tools/operator_keyfile_kdf_audit.sh` currently ships — the classifier is the JSON `kdf` field, and a one-line `jq`/loop over it is the audit. If a dedicated script lands it should wrap exactly this field.)*

---

## 2. Why each stage's KDF is what it is (the rationale spine)

- **Creation = Argon2id** because that is the *only* place the KDF is *chosen*. `encrypt` hard-codes the memory-hard default (`wallet/envelope.cpp:130`); nothing downstream re-derives, so choosing correctly once at creation propagates to every later stage. KM-2 is the payoff: a 64 MiB working set per guess denies the GPU/ASIC parallelism PBKDF2 concedes.
- **Read-back / upgrade = whatever the magic says** because the KDF is *self-describing on the wire*. `decrypt` never assumes a KDF; it routes on `env.kdf` (`:144`). This is what makes the migration back-compatible (KM-3): the same binary reads both layouts, so no DWE1 file is orphaned and no flag-day is needed.
- **Inspection = neither KDF, just the label** because reading the 4-byte magic + params slot needs no key material. This keeps audit read-only and passphrase-free (§1.3).
- **Fail-closed on unknown** at every read edge: an unrecognized magic → `deserialize` returns `nullopt` (`:243`); a degenerate param set (t=0, p=0, `m < 8·p`, wrong slot width) → `nullopt` at both deserialize and decrypt (`:251`, `:256-257`, `:145-146`); a wrong passphrase → AEAD tag fail → `nullopt` (`:165`). This is KM-4 (fail-closed param validation) extended across the lifecycle.

---

## 3. Honest residual — what is still PBKDF2

R58 hardens *fresh* envelopes. It does **not** re-key anything already on disk. The residual PBKDF2 surface:

### 3.1 Pre-R58 keyfiles on disk (until reencrypted)

Every DWE1 envelope written before R58 — encrypted node keyfiles, `DETERM-ACCOUNT-V1` files, Shamir backup shares, recovery setups — stays PBKDF2 and keeps decrypting byte-for-byte (KM-3, regression-locked by `tools/test_wallet_envelope_compat.sh`'s pinned pre-R58 fixture). It hardens to Argon2id **only** on the next `keyfile-reencrypt` / `envelope encrypt` re-wrap (§1.4, KM-5.4). An operator who never re-encrypts retains the original PBKDF2 cost — a deliberate, documented choice, not a silent downgrade.

### 3.2 The DWE1 interop write path (`envelope encrypt --iters`)

DWE1 is still **writable** on request: `envelope encrypt --iters N` routes to `encrypt_pbkdf2` (`wallet/main.cpp:1037-1038`), emitting a fresh DWE1 blob. This is retained for interop and to exercise the legacy path in tests. It is opt-in — the default `envelope encrypt` (no `--iters`) emits DWE2.

### 3.3 Non-claims inherited from KeyfileArgon2Migration.md (KM-5)

- **KM-5.1 — Argon2id's data-dependent passes are NOT constant-time, by design.** Pass-0 first half is data-independent (Argon2i); the remainder is data-dependent, so its memory-access pattern is a function of the password (`include/determ/crypto/argon2/argon2id.h:13-25`). A host-resident cache/power side-channel adversary *during KDF execution* could in principle learn password bits. This is the Argon2d GPU-resistance component, not a defect; the threat model trusts the host against fine-grained microarchitectural side channels (same posture as the AES/GHASH primitives). **At-rest only** — it does not affect the disk-theft bounds KM-1..KM-4.
- **KM-5.2 — No specific bit-security uplift is quantified.** KM-2 asserts a qualitative-but-real hardening; the memory-hardness `+bits` depends on attacker memory economics and is not a clean `log2`.
- **KM-5.3 — On-wire / consensus surface unchanged.** At-rest keyfile KDF only; no transaction, block, snapshot, RPC, or consensus byte changes. The wallet-envelope TCB is disjoint from the chain path.
- **KM-5.4 — No in-place re-keying** of existing DWE1 files (this is §3.1 above).

### 3.4 Passphrase entropy still dominates

Both KDFs are conditioned on operator passphrase min-entropy `H_pw` (KE-4 / T-3). Argon2id raises the per-guess cost but does not rescue a weak passphrase; the `H_pw ≥ 80`-bit recommendation of `EnvelopeKeyfileCrypto.md` §6 still governs.

### 3.5 No dedicated audit script

The operator audit (§1.5) is the `inspect-envelope --json` / `keyfile-info --json` `kdf` field, not a shipped `tools/*.sh`. Documented here so a reviewer does not look for a script that does not exist.

---

## 4. Cross-references

| Document | Labels | Role in the lifecycle |
|---|---|---|
| [KeyfileArgon2Migration.md](KeyfileArgon2Migration.md) | KM-1..KM-5 | The migration delta proof. KM-1 (AEAD carry-over), KM-2 (memory-hard bound), KM-3 (back-compat / no orphans), KM-4 (fail-closed params), KM-5 (non-claims = §3.3). |
| [EnvelopeKeyfileCrypto.md](EnvelopeKeyfileCrypto.md) | KE-1..KE-4 | The AEAD-with-KDF primitive (caller-independent). KE-1/2/3 carry to DWE2 verbatim; KE-4 is the dictionary bound KM-2 sharpens. |
| [S004KeyfileAtRest.md](S004KeyfileAtRest.md) | T-1..T-5 | The application layer (`DETERM-NODE-V1` / `DETERM-ACCOUNT-V1`, AAD-binding, offline/online adversary bounds). Unaffected by R58 — KDF-only migration. |
| SECURITY.md §S-004 | — | Plaintext-private-key finding; option 2 (passphrase envelope) + the R58 Argon2id hardening note. |
| [CRYPTO-C99-SPEC.md](CRYPTO-C99-SPEC.md) §3.6 | — | The `determ_argon2id` primitive (RFC 9106 on C99 BLAKE2b), byte-equal vs libsodium `crypto_pwhash_argon2id` (12/12 grid). |

### Implementation & test surface

| Surface | Location |
|---|---|
| Two-layout API + Argon2id defaults | `wallet/envelope.hpp:40-93` (Kdf enum; `encrypt`=Argon2id; `t=3`/`m=64MiB`/`p=1`) |
| `encrypt` default = Argon2id | `wallet/envelope.cpp:126-131` |
| Magic discriminants + serialize/deserialize | `wallet/envelope.cpp:25-26`, `:208-274` |
| Decrypt (KDF auto-detect + fail-closed) | `wallet/envelope.cpp:133-167` |
| Creation call sites | `keyfile-create` `wallet/main.cpp:3627`; `account create --passphrase` `src/main.cpp:5046`; `backup-create` `wallet/main.cpp:3278`; `create-recovery` `wallet/recovery.cpp:91` |
| Daemon read-back (links envelope) | `src/main.cpp:34-36`, `:5119`/`:5125` |
| Inspection (no decrypt) | `inspect-envelope` `wallet/main.cpp:1157-1210`; `keyfile-info` `:6033-6066` |
| Upgrade (opportunistic re-wrap) | `keyfile-reencrypt` `wallet/main.cpp:4740`, `:4823` |
| DWE1 interop write path | `envelope encrypt --iters` `wallet/main.cpp:1037-1038` |
| Migration + format-freeze tests | `tools/test_wallet_keyfile_argon2.sh` (5 legs), `tools/test_wallet_envelope_compat.sh` (pinned pre-R58 DWE1) |

---

## 5. Status

- **Coverage map only — no new theorems.** This document draws the lifecycle edges over the R58 migration and pins each to `file:line` + its home-document label.
- **Every fresh envelope is Argon2id (DWE2)** at creation; every read path auto-detects the KDF from the magic; inspection reports it without decrypting; `keyfile-reencrypt` upgrades DWE1→DWE2 opportunistically; the operator audit is the `inspect-envelope --json` `kdf` field.
- **Honest residual:** pre-R58 files stay PBKDF2 until re-wrapped (KM-3), the `--iters` interop path still writes DWE1, and the KM-5 non-claims (side-channel, no bit number, at-rest-only, no in-place re-key) are inherited unchanged. Passphrase entropy still dominates (KE-4 / T-3).
- **Audience.** A reviewer uses §1 + §2 to confirm the migration reaches every at-rest stage; an operator uses §1.4 + §1.5 + §3 to know what is still PBKDF2 and how to upgrade it.
