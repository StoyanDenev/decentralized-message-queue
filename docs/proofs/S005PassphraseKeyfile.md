# S005PassphraseKeyfile — passphrase-encrypted keyfile lifecycle composition (S-004 deep dive)

This document is the companion deep-dive proof for the S-004 closure (passphrase-encrypted node keyfiles): where `S004KeyfileAtRest.md` formalizes the at-rest cryptographic soundness of a single encrypted keyfile, **S005PassphraseKeyfile.md** proves the soundness of the *operational lifecycle* of those files — creation, decryption-on-load, rotation, recovery, and inspection. The lifecycle commands live in the wallet binary (`wallet/main.cpp`) and the daemon's startup-time load path (`src/main.cpp`); together they constitute the operator-facing surface that turns the cryptographic primitive (`wallet/envelope.cpp::encrypt` / `decrypt`) into a usable validator-custody workflow.

The five lifecycle commands proven here:

| CLI | `wallet/main.cpp` location | Purpose |
|---|---|---|
| `keyfile-create`  | `:2984-3186` | Encrypt a fresh or imported 32-byte Ed25519 seed into the canonical `DETERM-NODE-V1` 2-line file. |
| `keyfile-decrypt` | `:3242-3483` | Reverse of `keyfile-create`: decrypt to a plaintext `node_key.json` for emergency operator access. |
| `keyfile-rotate`  | `:3566-4003` | Re-encrypt an existing keyfile under a new passphrase (fresh salt + fresh nonce); preserves the underlying Ed25519 keypair. |
| `keyfile-recover` | `:4073-4460` | Compose `envelope::decrypt` × N with `shamir::combine` to reconstruct a secret from a T-of-N Shamir backup. |
| `keyfile-info`    | `:5017-5142` | Metadata-only inspection (header + envelope structure); no passphrase, no decrypt. |

Plus the daemon-side **load-on-startup** path (`src/main.cpp::cmd_node` calling `Chain::load_node_key` with `DETERM_PASSPHRASE` env-var fallback), which is the runtime consumer of `keyfile-create`'s output.

**Companion documents:** `S004KeyfileAtRest.md` (the cryptographic-primitive proof at the AEAD layer; this document treats T-1..T-5 there as black-box invariants); `WalletRecoveryFlows.md` (the operator-flow companion for the recovery surface — T-1..T-6 there cover the FA12 Shamir × envelope composition); `RpcAuthHmacSoundness.md` (S-001 closure; orthogonal at the RPC-auth layer); `Preliminaries.md` (F0) §2.1 + §2.3 (the SHA-256 + CSPRNG axioms underlying every primitive cited here); `WalletRecovery.md` (FA12 T-15..T-18 — the underlying Shamir + AEAD-envelope binding proofs).

---

## 1. Introduction — the keyfile lifecycle

A Determ operator's validator-identity keypair (32-byte Ed25519 seed + 32-byte public key) has a long operational lifetime — typically the lifetime of a validator slot, which may be measured in years. During that time the keyfile passes through several touch-points:

1. **Creation.** The operator runs `keyfile-create --priv <hex> --passphrase-from <src> --out <file>` (or composes from `account-create-batch` + `keyfile-create`). The CLI takes a 32-byte seed (or 64-byte seed||pub form) in hex and writes the canonical 2-line `DETERM-NODE-V1` file (the AEAD-encrypted envelope per S-004).
2. **Load-on-startup.** The daemon's main loop (`src/main.cpp::cmd_node`) calls `Chain::load_node_key(path, passphrase)`. The passphrase comes from `DETERM_PASSPHRASE` env var (recommended), `--passphrase-from file:<path>`, or interactive prompt. The keyfile path is supplied via `--keyfile <path>` (or the default `node_key.enc`).
3. **Optional rotation.** Periodically (e.g., annually, or after a passphrase compromise scare, or when a passphrase-manager is upgraded), the operator runs `keyfile-rotate --in <file> --out <file> --old-passphrase-from <src> --new-passphrase-from <src>`. The CLI decrypts under the old passphrase, re-encrypts under the new one (fresh salt + fresh nonce per `envelope::encrypt`), and atomically replaces the file. The underlying Ed25519 keypair (and hence the validator's chain identity, anon-address, REGISTER record, NEF eligibility, stake balance, etc.) is preserved.
4. **Optional inspection.** At any time, the operator runs `keyfile-info --in <file>` to confirm which validator (which pubkey + anon-address) the file belongs to, what envelope parameters it carries (PBKDF2 iter count, salt length, nonce length, ciphertext length, AAD presence). No passphrase needed; no decrypt performed.
5. **Optional recovery.** If the operator forgets the passphrase OR the keyfile is lost in a catastrophic event, recovery is via the T-of-N Shamir backup chain: `backup-create` (separate CLI, FA12 surface) had earlier sharded the seed across N keyholders with per-share-passphrase-encrypted envelopes; `keyfile-recover` (and its higher-level composition `account-recover`) reconstructs the original seed when T-of-N keyholders supply their share passphrases.

The lifecycle is **at-rest cryptographic** (all on-disk artifacts are encrypted under operator-controlled passphrases) and **operator-controlled** (no third party gates any step). Step (3) is the routine maintenance; step (5) is the disaster-recovery escape hatch.

This document proves the lifecycle's soundness end-to-end: each step preserves the underlying Ed25519 identity, never leaks the plaintext seed via stdout, composes the at-rest soundness from S-004 at every encrypt/decrypt boundary, and stays operator-friendly without expanding the attack surface.

---

## 2. Theorems

**Setup.** Let `(pk, sk) ∈ {0,1}²⁵⁶ × {0,1}²⁵⁶` denote a long-lived Ed25519 node-identity keypair; `sk` is the 32-byte seed, `pk` is the 32-byte public key. Let `addr := "0x" ‖ hex(pk)` be the operator's canonical anon-address. Let `P, P', ... ∈ {0,1}*` denote operator passphrases (with min-entropy `H_pw ≥ 60` bits per S-004 F-2). Let `E := DETERM-NODE-V1 ‖ hex(pk) ‖ "\n" ‖ envelope::serialize(envelope::encrypt(J, P, aad)) ‖ "\n"` denote the canonical encrypted-keyfile bytes, where `J := {"pubkey": hex(pk), "priv_seed": hex(sk)}` and `aad := utf8(hex(pk))`.

### T-1 (Create → Decrypt Identity)

For any well-formed 32-byte seed `sk`, the composition

```
keyfile-create(--priv hex(sk), --passphrase-from src(P), --out F)
keyfile-decrypt(--in F, --passphrase-from src(P), --out G)
```

yields a plaintext `node_key.json` at `G` whose `priv_seed` field byte-equals `hex(sk)` and whose `pubkey` field byte-equals `hex(Ed25519_pubkey(sk))`. Equivalently: the round-trip preserves the seed byte-identically, and the recovered file is consumable by `Chain::load_node_key` (the daemon's startup path) producing the same `(pk, sk)` keypair as the original input.

*Proof sketch.* By S-004 T-1 + T-3 (the AEAD envelope is a deterministic-on-key, randomized-on-(salt, nonce) bijection: any envelope produced by `envelope::encrypt(J, P, aad)` is recoverable to `J` byte-identically by `envelope::decrypt(env, P, aad)` for the same `(P, aad)`). The `keyfile-create` self-test round-trip (lines 3128-3145 — encrypt then decrypt then byte-compare BEFORE writing `--out`) guarantees the encrypted blob is recoverable before the file ships. `keyfile-decrypt`'s flow at lines 3354-3460 mirrors the inverse: deserialize envelope, AAD-reconstruct from header pubkey, decrypt under operator passphrase, parse plaintext JSON, validate hex shapes, write the canonical 2-spaces-indent `{"pubkey","priv_seed"}` form. The two endpoints exchange the same `pt_bytes`. □

**Corollary T-1.1 (Idempotent decrypt).** Running `keyfile-decrypt --in F` twice (with the same passphrase) yields two byte-identical output files — the AEAD decrypt is functionally deterministic (it's just a verify + AES counter-mode evaluation on the same key + nonce + AAD inputs).

### T-2 (Rotation Preserves Identity)

For any encrypted keyfile `E_old := DETERM-NODE-V1 ‖ hex(pk) ‖ ... (envelope under P_old)` and any new passphrase `P_new ≠ P_old`, the operation

```
keyfile-rotate(--in E_old, --out E_new,
               --old-passphrase-from src(P_old),
               --new-passphrase-from src(P_new))
```

produces a fresh encrypted-keyfile `E_new` whose:

- Header pubkey `hex(pk)` is **byte-identical** to `E_old`'s header pubkey;
- Inner JSON (post-decrypt) has the same `pubkey` and `priv_seed` fields;
- DWE1 envelope has a **freshly-drawn** 16-byte salt + **freshly-drawn** 12-byte nonce (so `E_old` and `E_new` are non-decryptable substitutes of each other even if `P_old == P_new` is forced via `--force-same-passphrase`);
- Anon-address `addr := "0x" ‖ hex(pk)` is preserved.

In particular, the validator's chain-level identity (REGISTER record, anon-address-indexed balance, stake escrow, NEF eligibility, committee membership eligibility, RPC `validators` enumeration) is unchanged by rotation — only the disk-level passphrase second-factor is refreshed.

*Proof sketch.* Inspect `cmd_keyfile_rotate` at `wallet/main.cpp:3566-4003`. The flow is:

1. Parse the `--in` file's 2-line shape; extract `header_pubkey_hex` (lines 3623-3648).
2. Read old + new passphrases via `passphrase_from_source` (lines 3673-3684).
3. Refuse equal old/new (line 3691) unless `--force-same-passphrase`.
4. Decrypt the envelope under `P_old` + `aad := utf8(header_pubkey_hex)` (line 3749) via S-004's `envelope::decrypt`. On wrong `P_old`, exit 2.
5. Parse decrypted plaintext as canonical `{"pubkey","priv_seed"}` JSON (lines 3779-3819). Validate `inner_pubkey_hex == header_pubkey_hex` (line 3819).
6. **Re-encrypt** the *same* `pt_bytes` (same JSON, same seed) under `P_new` + the same AAD (line 3834): `envelope::encrypt(pt_bytes, new_passphrase, aad)`. The encrypt path internally draws a fresh 12-byte nonce and a fresh 16-byte salt per `RAND_bytes` (per S-004 L-6 + `wallet/envelope.cpp:46-49`).
7. Self-test round-trip: deserialize the just-emitted blob, decrypt under `P_new`, byte-compare to `pt_bytes` (lines 3845-3868). Catches any encrypt-path drift BEFORE overwriting `--in`.
8. Atomic file write: stage to `<out>_tmp.json`, flush + fsync/`_commit`, then `std::filesystem::rename` (lines 3878-3962). Same-volume rename is atomic on both POSIX and Windows, so either the rename completes (operator sees the new file) or it doesn't (operator sees the unchanged old file). No half-state.
9. 0600 permissions tightening on the rename target (line 3967).

The plaintext `pt_bytes` is the byte-identical decryption of `E_old`. Re-encrypting `pt_bytes` under `P_new` produces a new envelope whose inner plaintext, when decrypted under `P_new`, equals `pt_bytes` — by S-004 T-1 + T-3 applied to the new `(salt_new, nonce_new, P_new, aad)` tuple. The header pubkey is written byte-identically (line 3893). Hence pubkey + anon-address + inner JSON are preserved across rotation. □

**Corollary T-2.1 (Salt + nonce always fresh).** Even under `--force-same-passphrase` (`P_old == P_new`), the new envelope has independently-drawn salt + nonce (independent uniforms from `RAND_bytes`). So `E_old` and `E_new` ciphertexts differ with overwhelming probability (`1 - 2⁻²²⁴` per the joint salt+nonce uniqueness; effectively 0). The intent of `--force-same-passphrase` is rare — typically an operator running rotation drills against a fixed test passphrase — but cryptographic hygiene is preserved.

### T-3 (Recovery From Shamir + Keyholder Passphrases)

Let `s_1, ..., s_N` denote N Shamir shares over GF(2⁸) reconstructing secret `sk` under threshold `T`, each share's y-bytes individually AEAD-wrapped under keyholder-specific passphrases `Q_1, ..., Q_N` (the artifact pair `(shares_file, envelopes_file)` produced by `backup-create`'s flow). For any T-of-N subset of keyholders `{(i_j, Q_{i_j})}_{j=1..T}` supplying their share passphrases, the composition

```
keyfile-recover(--backup-shares shares.json
                --backup-envelopes envelopes.json
                --keyholders subset.json
                --threshold T)
```

emits the original `sk` byte-identically (as hex). Equivalently: T-of-N is both *necessary* (under-threshold subsets either fail at the `--threshold T` gate, OR yield garbage by Shamir ITS) and *sufficient* (exactly T correct shares + passphrases reconstruct the original).

*Proof sketch.* Compose:

1. **S-004 T-3** (per-envelope AEAD decryption soundness): for each of T envelopes, `envelope::decrypt(env_{i_j}, Q_{i_j}, {})` succeeds with probability `≥ 1 - 2⁻¹²⁸ - ε_{AEAD}` if `Q_{i_j}` is correct, and fails (returns `nullopt`) on any other passphrase with probability `≥ 1 - 2⁻¹²⁸`. The `wallet/main.cpp:4362` call passes empty AAD (matching `backup-create`'s AAD-free convention).
2. **Cross-verification step** (`wallet/main.cpp:4378-4387`): the decrypted y-bytes are compared to the shares-file y_hex. Mismatch returns exit 2 with a diagnostic (catches a `(shares_file, envelopes_file)` pair from different `backup-create` runs).
3. **FA12 T-15** (Shamir reconstruction soundness over GF(2⁸)): given T correct share evaluations `{(x_j, y_j)}_{j=1..T}` of a degree-(T-1) polynomial, `shamir::combine` (`wallet/shamir.cpp:52-124`) reconstructs the polynomial's constant term (= the original secret bytes) byte-identically.
4. **Threshold gate** (`wallet/main.cpp:4322-4329`): if `--threshold T` is supplied and `len(keyholders) < T`, the CLI exits with code 2 BEFORE any decrypt work. Without `--threshold`, the CLI can't detect under-threshold subsets (Shamir's information-theoretic security property: T-1 shares look uniform — no algorithmic signal of insufficiency), and `shamir::combine` happily returns a wrong secret. Hence operator hygiene: `--threshold T` is required for a tamper-evident recovery path. `account-recover` (the higher-level composition at FA12) enforces this; see WalletRecoveryFlows.md L-2.

The composition's success condition is: T correct keyholder passphrases supplied, T envelopes successfully decrypt, T y-bytes cross-verify with shares-file entries, T shares feed into `shamir::combine` → original `sk` recovered. Each step's failure mode (wrong passphrase → exit 2; envelope/shares mismatch → exit 2; shamir reconstruction failure → exit 2) is enumerated. No path reveals the seed under failure. □

**Corollary T-3.1 (Different T-subsets yield the same secret).** For any two T-of-N subsets `S_a, S_b ⊂ {1..N}` with `|S_a| = |S_b| = T`, the recovered secrets `sk_a, sk_b` are byte-identical. This is direct from Lagrange interpolation: any T evaluations of a degree-(T-1) polynomial uniquely determine the polynomial, hence the constant term. The CLI's regression test `tools/test_wallet_keyfile_recover.sh` exercises this property explicitly.

### T-4 (No Plaintext Leak Across Lifecycle)

For each lifecycle command `cmd ∈ {keyfile-create, keyfile-decrypt, keyfile-rotate, keyfile-recover, keyfile-info}`, the plaintext private key bytes (the 32-byte Ed25519 seed `sk` or any its hex representation `priv_seed_hex`) **never appear on stdout** under any successful or failure execution path. The seed is written exclusively to:

- For `keyfile-create`: nowhere — only the encrypted envelope is written to `--out` (the seed exists in process memory transiently for the encrypt call + `sodium_memzero`'d after, never reaches stdout, never reaches stderr).
- For `keyfile-decrypt`: only the operator-requested `--out` file (the plaintext `node_key.json`). The 0600 ACL is applied as belt-and-suspenders. **No `--allow-stdout` flag exists.** The operator must specify a file path; the CLI refuses stdout output by construction.
- For `keyfile-rotate`: nowhere — the seed is decrypted in-memory, re-encrypted, written as a new envelope to `--out`. Plaintext never escapes process memory; `sodium_memzero` wipes the intermediate `pt_bytes` + both passphrases on every exit path (lines 3767-3774).
- For `keyfile-recover`: **the recovered secret bytes IS the operator-requested output** (this is the explicit purpose of the command — return the secret to the human who composed T-of-N shares). It IS emitted to stdout (or to `--out` if supplied). This is intentional; the operator's intent for invoking recovery is to receive the secret. **Distinguishing aside:** the secret here is a generic byte string (from `backup-create`'s input) — *not necessarily* an Ed25519 seed in semantically-meaningful contexts; it might be any 16/32/64-byte secret the operator chose to back up. The composition with `account-import` (via `account-recover`) takes it from there.
- For `keyfile-info`: never — the CLI does not even decrypt. It emits only metadata (pubkey hex, anon-address, envelope iter count + salt/nonce/ct lengths + AAD presence flag). All pubkey-derived info is public; no passphrase consumed.

The summary lines on stdout/stderr (e.g., `"wrote encrypted node keyfile to <path>"`, `"keyfile_rotated=YES (anon=0x... in=... out=...)"`) carry only *public* information: pubkey, anon-address, file paths, source-label tags (e.g., `"env:DETERM_PASSPHRASE"`).

*Proof sketch.* Source-level audit of `wallet/main.cpp:2984-5142`:

1. **`keyfile-create` (lines 3175-3187)**: summary emits `pubkey`, `out`, `format`, `envelope`. None is plaintext-seed-derived. The `pt_str` variable carrying the inner JSON is scoped to lines 3104-3145 (encrypt + self-test round-trip); after the round-trip it falls out of scope and the buffer's memory is reused. Although `cmd_keyfile_create` does NOT explicitly `sodium_memzero` `pt_bytes` post-encrypt (since it's stack-local in a leaf scope), the seed bytes in `priv_bytes` (lines 3017-3068) similarly never leave the function via stdout. **F-2 below registers this as a residual memory-scrubbing improvement opportunity.**
2. **`keyfile-decrypt` (lines 3434-3478)**: writes `out_str` (the canonical 2-spaces-indent `{"pubkey","priv_seed"}` JSON) to `--out`. The summary on stdout (lines 3464-3477) emits `pubkey`, `out`, and source-label tags — no `priv_seed` field on stdout. The CLI hard-requires `--out` (line 3261, "Usage" + return 1 if missing) — there is no stdout-output fallback.
3. **`keyfile-rotate` (lines 3980-4001)**: summary emits `anon_address`, `ed_pub_hex`, `in`, `out`, `in_place`, and source-label tags. `secure_zero_all` (lines 3767-3774) wipes `pt_bytes`, `old_passphrase`, `new_passphrase` BEFORE the summary line so the printf paths can't see the plaintext even via stale buffer reuse.
4. **`keyfile-recover` (lines 4416-4458)**: the recovered `secret_hex` IS the explicit output (the operator's request). See the T-4 carve-out above. Composes safely with `account-import` via `account-recover` (FA12 surface) when the operator wants the seed turned back into a wallet.
5. **`keyfile-info` (lines 5111-5140)**: emits only header pubkey + envelope-structure metadata. No passphrase read, no decrypt, no plaintext touched.

The composite property: for the four "Type A" commands (create, decrypt, rotate, info), no path emits the plaintext seed to stdout. For the one "Type B" command (recover), the recovered secret IS the operator's requested output and is emitted intentionally. No `--allow-stdout` opt-in is needed because the secret-handling discipline is opt-out by default at the CLI shape level. □

### T-5 (Composition with S-004 At-Rest at Every Boundary)

Every encrypt and decrypt boundary in the lifecycle goes through the same `envelope::encrypt` / `envelope::decrypt` primitives that S-004 proves sound at the AEAD layer. Specifically:

- `keyfile-create` calls `envelope::encrypt(pt_bytes, passphrase, aad)` at `wallet/main.cpp:3115`.
- `keyfile-decrypt` calls `envelope::decrypt(env, passphrase, aad)` at `wallet/main.cpp:3368`.
- `keyfile-rotate` calls `envelope::decrypt` at `wallet/main.cpp:3749`, then `envelope::encrypt` at `wallet/main.cpp:3834`.
- `keyfile-recover` calls `envelope::decrypt` × T at `wallet/main.cpp:4362` (one per keyholder, AAD = empty per `backup-create`'s convention).
- The daemon's `Chain::load_node_key` (on startup) calls `envelope::decrypt` once per restart via the canonical `--keyfile` path.

By S-004 T-1 (PBKDF2 soundness), T-2 (AAD-binding), T-3 (confidentiality under disk theft), T-4 (no online-guess amplification), T-5 (pubkey-indistinguishability), each boundary is a black-box-sound AEAD operation. The lifecycle composition does not introduce any new cryptographic exposure beyond what S-004 already bounds per-operation. In particular:

- An adversary holding the encrypted keyfile at any lifecycle point faces the same T-3 brute-force bound (`Q · 2⁻⁽ᴴ_pw + log2(iter)⁾ + ε_{AEAD}`) regardless of whether the file was just produced by `keyfile-create`, just rotated by `keyfile-rotate`, or unchanged for years between rotations.
- Each `keyfile-rotate` invocation generates a fresh `(salt, nonce, AEAD tag)` triple, so an adversary holding the *pre-rotation* envelope receives no information that helps brute-force the *post-rotation* envelope (the two envelopes share only the plaintext, which the adversary already doesn't know).
- The cumulative attack surface across N rotations is bounded by `N · ε_{AEAD}` (forge-bound per envelope is independent + additive), which is negligible for any operationally-realistic N (e.g., one rotation per quarter for 50 years = 200 rotations; bound `200 · 2⁻¹²⁸ = 2⁻¹²⁰`, still negligible).

*Proof.* Direct from S-004 T-1..T-5 applied per-boundary plus the AEAD primitive's independence: each `envelope::encrypt` invocation draws fresh `(salt, nonce)` from independent uniform sources (`wallet/envelope.cpp:46-49` via `RAND_bytes`), so the cumulative bound across N invocations is `Σᵢ ε_{AEAD,i} = N · ε_{AEAD}`. The PBKDF2 brute-force bound `Q · 2⁻⁽ᴴ_pw + log2(iter)⁾` per-envelope is independent across envelopes (the salt is fresh per envelope, so each PBKDF2 derivation key is independent). The composite lifecycle is therefore as sound as the worst-case single-envelope S-004 bound. □

---

## 3. Adversary models

The lifecycle commands inherit the three adversary models from S-004 (`A_offline`, `A_online`, `A_msg`) and add four lifecycle-specific adversary models:

### A-1 — File-system read of encrypted keyfile (defeated by S-004 T-3)

An attacker reads the encrypted keyfile bytes from disk (cold-backup leak, laptop theft, OS-level UID compromise without daemon-running). **Same A_offline model as S-004.** Defeated by S-004 T-3 (PBKDF2 + AEAD bound parameterized by `H_pw`). Operationally: an attacker who steals `E := DETERM-NODE-V1 ‖ ...` and does not have `P` faces `≥ 2⁷⁹·²` HMAC-SHA-256 trial work (at `H_pw = 60`, `iter = 600,000`) — operationally infeasible for any classical adversary in 2026.

The lifecycle composes this defense across all surfaces: stolen `E_old` (pre-rotation) is no easier to crack than stolen `E_new` (post-rotation) — both face the same per-envelope T-3 bound. An attacker holding both `E_old` AND `E_new` learns nothing additional (independent salts + nonces ⇒ independent PBKDF2 keys ⇒ no cross-correlation).

### A-2 — Stdout leakage during create/decrypt/rotate/info (defeated by T-4)

An adversary observes the operator's terminal during one of the lifecycle commands (e.g., via a screen-share, terminal multiplexer history, or a malicious peer's logged terminal scroll). **Defeated by T-4:** none of {create, decrypt, rotate, info} emits the seed to stdout under any path. The summary lines carry only public information (pubkey, anon-address, file paths, source-label tags). Even the operator typing `keyfile-create ... --passphrase-from prompt` does NOT echo the passphrase (the prompt path uses `tcsetattr(ICANON | ECHO off)` on POSIX or `_getch` on Windows, per `passphrase_from_source`'s prompt branch).

**Carve-out for `keyfile-recover`:** the recovered secret IS the explicit output. An operator running `keyfile-recover` in a non-private terminal (e.g., screen-sharing while debugging) leaks the secret to anyone observing. Mitigation: use `--out <file>` to send the secret to a 0600-permissioned file instead of stdout, and emit only a `recovered secret written to <path>` summary line. The CLI supports this explicitly (lines 4417-4451).

### A-3 — Rotation operator forgets new passphrase (operator-discipline-bound)

After a successful `keyfile-rotate`, the operator forgets `P_new`. The encrypted keyfile `E_new` is now unrecoverable to the operator (and equally unrecoverable to any A_offline attacker who lacks `P_new` and has insufficient brute-force budget). This is a **lockout**, not a confidentiality breach.

**Defense:** operator-discipline. Recommended practices:

1. **Test the new passphrase BEFORE deleting the old envelope.** `keyfile-rotate` writes `E_new` to `--out` and (if `--in == --out`) atomically replaces `E_old`. The recommended operator flow is to first run with a DIFFERENT `--out` path, verify decryptability via `keyfile-decrypt --in <new path>`, THEN replace the old file. The `--force-same-passphrase` flag is NOT for this — it's for the rare case of an explicit polynomial-refresh under a known fixed passphrase.
2. **Use a passphrase manager** (`pass`, `1Password`, `Bitwarden`). The `--passphrase-from file:<path>` source supports this transparently — the manager writes a temp file, the wallet binary reads it, both wipe it. Operator never types the passphrase manually.
3. **Maintain a Shamir backup** (via `backup-create` + `keyfile-recover`). T-of-N reconstruction gives a recovery path that does NOT depend on the operator remembering any single passphrase.

If the operator skips all three, the lockout is a hard failure with no cryptographic remedy (by design — the very property that makes S-004 secure against `A_offline` makes it secure against the operator-who-forgets-the-passphrase).

### A-4 — Recovery with insufficient shares (defeated by Shamir T-of-N threshold + `--threshold` gate)

An attacker (or a confused operator) attempts `keyfile-recover` with fewer than T shares supplied. **Three sub-cases:**

1. **With `--threshold T` supplied:** the CLI hard-fails at `wallet/main.cpp:4322-4329` BEFORE any decrypt work, with exit code 2 and diagnostic `"insufficient shares for threshold reconstruction"`. Operator-friendly fail-fast.
2. **Without `--threshold T`:** Shamir's information-theoretic property kicks in: `shamir::combine` returns a syntactically-valid but cryptographically-wrong secret. The cross-verification step (lines 4378-4387) compares decrypted y-bytes to the shares-file entries — and those PASS, because the decrypts are individually correct (the wrong shares ARE the supplied keyholders' shares; the issue is just that there are too few of them to reconstruct the original polynomial). So an under-threshold subset CAN slip past `keyfile-recover` without `--threshold` and emit a garbage secret. **F-1 below registers this as a known operator-pitfall** — `account-recover` (the higher-level FA12 composition) makes `--threshold` REQUIRED for exactly this reason.
3. **With `--threshold T` but only T-1 keyholders supply CORRECT passphrases (and T-1 supply WRONG passphrases — e.g., a sabotaged keyholder):** the CLI fails at the first wrong-passphrase envelope decrypt (line 4363, exit 2). No partial recovery from a sabotaged subset.

The Shamir cryptographic primitive (FA12 T-15) provides the underlying T-of-N gate; the lifecycle composition (this document) provides the operator-facing CLI plus the `--threshold` opt-in for fail-fast. The two together close the recovery-soundness surface.

### A-5 (overlap with A-1, distinguished for clarity) — Cross-rotation correlation attack

An attacker holds both `E_old` (pre-rotation) and `E_new` (post-rotation), wants to derive `sk` or reduce the brute-force budget by correlating the two.

**Defense:** the two envelopes share NO key material beyond the plaintext (which is what the attacker is trying to recover). Specifically:

- `salt_old ≠ salt_new` (independent draws from `RAND_bytes` per `keyfile-create` / `keyfile-rotate`'s `envelope::encrypt`).
- `nonce_old ≠ nonce_new` (independent draws, same source).
- `PBKDF2-key_old ≠ PBKDF2-key_new` even if `P_old == P_new` (because the salt differs).
- AAD is `utf8(hex(pk))` in both, byte-identical — but that's a public-info field that doesn't leak the seed.

The attacker faces TWO independent T-3 instances (one per envelope) rather than one stronger one. No reduction in per-envelope effort. The cumulative bound is `2 · ε_{AEAD}` over both envelopes; for `ε_{AEAD} = 2⁻¹²⁸`, the bound is `2⁻¹²⁷` — still negligible.

---

## 4. Lemmas

### L-1 (Passphrase-source discipline)

The `passphrase_from_source` helper (referenced from all five lifecycle commands via lines like `wallet/main.cpp:3072`, `:3325`, `:3673`, `:3679`) supports three sources:

| Source | Format | Operator use case | Risk |
|---|---|---|---|
| `file:<path>` | Read entire file content as passphrase (trailing newline stripped) | Passphrase-manager export → temp file → wipe | File mode + parent directory ACL must be 0600 |
| `env:<NAME>` | Read environment variable named `NAME` (typically `DETERM_PASSPHRASE`) | Daemon startup via systemd unit file with `EnvironmentFile=` | Env vars visible to admin via `/proc/<pid>/environ` on Linux, or registry / Task Manager on Windows |
| `prompt` | Interactive TTY prompt with terminal echo OFF | Manual one-off operator session | Requires TTY (not usable from cron / non-interactive contexts) |

Each source has its own threat model. The lifecycle commands do not enforce ONE source — operators choose based on their deployment posture:

- **systemd-managed daemon on Linux:** use `EnvironmentFile=/etc/determ/passphrase.env` (file mode 0600, owned by the daemon user), refer via `env:DETERM_PASSPHRASE` in the `--passphrase-from` flag.
- **One-off CLI commands during operator session:** use `prompt` for the highest security (no env-var, no file leakage).
- **Automated rotation script:** use `file:<path>` pointing at a passphrase-manager temp file (the script wipes the temp file after the rotate).

The CLI parses the source string at lines like `wallet/main.cpp:3072`; the helper returns the passphrase as a `std::string`, which the caller then passes to `envelope::encrypt` / `envelope::decrypt` and (in the rotate / recover paths) `sodium_memzero`'s on exit. **F-3 below** flags that on Windows, env-var visibility is a known operator-discipline item.

### L-2 (Atomic file write — staged + fsync + rename)

`keyfile-rotate` (and `keyfile-create` for the initial write) follows the canonical staged-write + atomic-rename pattern at `wallet/main.cpp:3878-3962`:

1. Write the full 2-line content to a `<out>_tmp.json` staging file.
2. Flush the C++ stream (`f.flush()`).
3. Close the C++ stream.
4. Re-open via C stdio, get the file descriptor, call `fsync` (POSIX) or `_commit` (Windows) to force the kernel to commit the bytes to durable storage.
5. `std::filesystem::rename(tmp_path, out_path)` — atomic on same-volume targets (Linux: `::rename(2)`; Windows: `MoveFileEx` implicit `REPLACE_EXISTING`).

The atomicity property: at any point during the rotation, either the rename has completed (operator sees `E_new`) or it has not (operator sees `E_old` unchanged). There is no intermediate state where `--in == --out` is left empty or torn. A crash mid-rotation leaves `E_old` intact + (potentially) a stale `<out>_tmp.json` (cleaned up by the next rotation's `std::filesystem::remove` at line 3882).

The fsync/`_commit` step is best-effort: if it fails (e.g., the disk reports I/O failure), the rename still proceeds; the rationale is that the bytes are likely in the kernel page cache + the rename still produces a valid file in the common case. A persistent disk failure surfaces at the rename step (which fails loudly) or at the next read attempt (where the operator sees a truncated or empty file).

`keyfile-recover` does NOT use the atomic-rename pattern — its output is either to stdout (no atomicity concept) or to `--out` (a single ofstream write). The recovered secret is in-band, so a torn write is recoverable by the operator re-running the recover. The asymmetry is intentional: a torn rotation could corrupt validator identity (the operator might lose access to a chain-registered key); a torn recovery output just needs a retry.

### L-3 (AAD binding through the lifecycle)

The AAD used in S-004's encrypt + decrypt is `utf8(hex(pk))` — the lowercase hex encoding of the 32-byte Ed25519 public key, as ASCII bytes. This binding has three lifecycle implications:

1. **Cross-validator envelope substitution defeated.** An attacker who substitutes `E_a`'s envelope blob (validator A) with `E_b`'s envelope blob (validator B) — keeping the original `DETERM-NODE-V1 hex(pk_a)` header — causes `keyfile-decrypt` to reconstruct `aad := utf8(hex(pk_a))` from the header but feed it to a decrypt that expects `aad := utf8(hex(pk_b))`. The pre-check at `wallet/envelope.cpp:114` (`aad == env.aad`) short-circuits with `nullopt`; equivalent to wrong-passphrase from the operator's view.

2. **Header-line tampering defeated.** An attacker who modifies the header pubkey from `hex(pk_a)` to `hex(pk_b)` while keeping the original envelope blob causes the AAD reconstruction at decrypt time (line 3367) to use the wrong pubkey bytes. Same `nullopt` short-circuit.

3. **Rotation preserves AAD identity.** `keyfile-rotate` reuses the `header_pubkey_hex` from the input file as the AAD for the re-encrypt (line 3748 builds `aad` from `header_pubkey_hex`, then line 3834 calls `envelope::encrypt(pt_bytes, new_passphrase, aad)`). The output envelope therefore binds to the same pubkey. Subsequent `keyfile-decrypt` calls on the rotated file reconstruct the same AAD from the header. Round-trip identity is preserved.

The `keyfile-recover` path uses **empty AAD** (line 4362, `envelope::decrypt(env, pw, {})`), matching `backup-create`'s AAD-free envelope convention. Rationale: Shamir-share envelopes are not tied to a specific public key (the secret being shared may not even be an Ed25519 seed; it could be any 16/32/64-byte secret). The AAD-binding defense at the per-share envelope is provided instead by the share_index field in the envelopes-file mapping (each envelope is keyed by its share_index, so substitution requires the attacker to know the index → envelope mapping a priori).

### L-4 (Memory scrubbing best-effort)

The lifecycle commands handle plaintext secrets transiently in process memory. The discipline:

- `cmd_keyfile_rotate` explicitly defines `secure_zero_all = [&]() { sodium_memzero(pt_bytes), sodium_memzero(old_passphrase), sodium_memzero(new_passphrase); }` (lines 3767-3774) and invokes it on every exit path (success, error, exception via `try`/`catch`).
- `cmd_keyfile_recover` does NOT explicitly memzero the per-share recovered y-bytes after `shamir::combine` — they live in `recovered_shares` vector and fall out of scope at function end. The recovered `secret_opt` is hex-encoded and emitted; the underlying bytes are similarly scope-bound.
- `cmd_keyfile_create` does NOT explicitly memzero `pt_bytes` post-encrypt (the seed bytes are also in `priv_bytes` / `seed` which similarly fall out of scope at function end).
- `cmd_keyfile_decrypt` does NOT explicitly memzero `pt_str` / `priv_seed_hex` — relies on RAII destruction at function end.

This is **best-effort** memzero, not a formal guarantee. The C++ allocator may reuse the memory before destruction, the OS may swap the process pages to disk, and the compiler may optimize away dead stores (the `sodium_memzero` function uses inline asm with a memory barrier to prevent optimization; see `libsodium/sodium/utils.c`).

**F-2 below** registers the residual surface: a memory-dump adversary (root on the running host, or post-crash core-dump access) can in principle recover the seed. Defense is operator-side via OS hardening (`mlock` the process memory, disable swap-to-disk for the daemon, kernel ASLR + `prctl(PR_SET_DUMPABLE, 0)` on Linux). Not a cryptographic concern at the wallet binary level — the keyfile lifecycle does not promise memory hygiene beyond best-effort.

### L-5 (Self-test round-trip catches encrypt-path drift)

Both `cmd_keyfile_create` (lines 3127-3145) and `cmd_keyfile_rotate` (lines 3845-3868) perform a self-test round-trip BEFORE writing the output file:

1. Serialize the just-emitted envelope into its canonical blob form.
2. Deserialize it back into the in-memory `Envelope` struct (catches blob-format errors).
3. Decrypt under the (new) passphrase + AAD (catches encrypt-decrypt drift).
4. Byte-compare the decrypted plaintext to the original `pt_bytes` (catches plaintext-mismatch errors).

If any step fails, the CLI exits BEFORE the staged-write step — so the operator's `--out` file is never touched. The original `--in` file (in the rotate path) is therefore preserved.

This is defense-in-depth against a class of bugs that would be catastrophic in production: an encrypt path that produces an envelope that the matching decrypt can't recover (e.g., a salt-handling regression, an AAD-binding off-by-one, a GCM-tag-append bug). The self-test catches these before the operator's chain identity is jeopardized.

The cost is modest: an extra `envelope::decrypt` per write (200 ms PBKDF2 on commodity 2026 CPU). Operator-acceptable for a once-per-month rotation cadence.

---

## 5. Cross-references

| Document | Surface | Relationship to S-005 |
|---|---|---|
| `S004KeyfileAtRest.md` | At-rest AEAD primitive | The cryptographic foundation; this document treats T-1..T-5 there as black-box invariants. |
| `WalletRecoveryFlows.md` | Operator-facing recovery flows | T-3 here composes with WalletRecoveryFlows.md T-1..T-6 (Shamir × envelope recovery). |
| `WalletRecovery.md` (FA12) | Cryptographic primitives for recovery | FA12 T-15 (Shamir reconstruction) + T-16 (AEAD envelope binding) underpin T-3 here. |
| `RpcAuthHmacSoundness.md` (S-001) | RPC HMAC auth | Orthogonal — S-001 protects daemon RPC; S-005 protects keyfile lifecycle. |
| `S014RateLimiterSoundness.md` (S-014) | Network rate-limiting | Orthogonal — S-014 caps gossip/RPC rates; S-005 covers offline keyfile manipulation. |
| `S027InfoLeakage.md` (S-027) | Log/RPC leakage | Compatible — S-027 audits daemon-side logs; S-005's T-4 audits wallet-side stdout. |
| `Preliminaries.md` (F0) §2.1 + §2.3 | SHA-256 + CSPRNG axioms | Underlying assumptions for HMAC-PRF (A6) + nonce uniqueness (L-6 in S-004). |
| `RpcInputValidationDefense.md` | Daemon RPC input validation | Compatible — encrypted keyfile is consumed by daemon startup, which validates the decrypted JSON shape via S-018. |
| `FA12` (WalletRecovery + WalletRecoveryFlows) | Shamir + AEAD composition | T-3 here is a thin operator-CLI restatement of FA12's composition. |

---

## 6. Findings

### F-1 (operator-pitfall: `--threshold` is optional for `keyfile-recover`)

The `keyfile-recover` CLI accepts `--threshold T` as **optional**. Without it, an operator who supplies fewer than T keyholder passphrases will receive a syntactically-valid but cryptographically-wrong secret (Shamir's information-theoretic property: T-1 evaluations underdetermine the polynomial; `shamir::combine` happily returns a wrong constant term).

**Severity:** Low (operator-discipline; mitigation documented). The composite CLI `account-recover` makes `--threshold` REQUIRED specifically because it then composes the recovered secret into a wallet account (which would silently misroute funds to a wrong address if the secret were wrong); the standalone `keyfile-recover` is "the operator knows what they're doing" mode.

**Recommendation:** Document `--threshold T` as STRONGLY RECOMMENDED in the operator guidance. The CLI's --help text (lines 4118-4125) already calls this out explicitly; the deeper operator-onboarding materials should also reference the under-threshold-silent-misrecovery property as a top-3 keyfile-handling pitfall.

**No code change recommended.** The optional-`--threshold` design is intentional for the standalone CLI (operators rolling their own composition may have a different reason for not enforcing T at this layer).

### F-2 (best-effort memory scrubbing — `sodium_memzero` is not a formal guarantee)

The lifecycle commands invoke `sodium_memzero` on plaintext seed bytes + passphrases on exit paths (most rigorously in `keyfile-rotate`, less consistently in `keyfile-create` and `keyfile-decrypt`). The discipline is:

- `keyfile-rotate`: explicit `secure_zero_all` on every exit path (well-disciplined).
- `keyfile-create`: relies on RAII destruction of `pt_bytes` + `priv_bytes` + `passphrase` strings.
- `keyfile-decrypt`: relies on RAII destruction of `pt_str` + `priv_seed_hex` strings.
- `keyfile-recover`: relies on RAII destruction of `recovered_shares` vector + intermediate plaintexts.
- `keyfile-info`: no plaintext touched (no memzero needed).

**Severity:** Low/Op (memory-hygiene; not a cryptographic break). The `sodium_memzero` primitive itself is sound (uses inline asm + memory barrier to defeat compiler dead-store optimization, per `libsodium/sodium/utils.c`). The gap is at the *invocation discipline* layer — not every function explicitly memzeros every plaintext-bearing buffer.

**Threat model:** An adversary with post-execution memory access (e.g., root running `gcore` on a CLI process that has just exited but whose pages are still in the allocator's free list, or core-dump access after a crash) may recover plaintext bytes. Operationally, this is bounded by:

- The wallet CLI is short-lived (each invocation is a single command, exits in ~200 ms after PBKDF2 + AEAD). Process memory is reclaimed by the OS allocator quickly.
- The host's OS-level hardening (no core dumps for wallet processes, `mlock` if the operator wants to opt in) is the actual defense.
- For the LONG-lived daemon (`src/main.cpp`) path, the seed is loaded into `Chain::node_keypair_` and stays in memory for the daemon's run lifetime — `sodium_memzero` would be inappropriate (the seed is needed for every signing operation).

**Recommendation:** Add `sodium_memzero` to `cmd_keyfile_create` (post-encrypt, before stdout summary) and `cmd_keyfile_decrypt` (post-ofstream-write, before stdout summary), mirroring `cmd_keyfile_rotate`'s `secure_zero_all` pattern. Track as a future improvement, not a blocker. **No urgency** — the host-level OS hardening is the actual defense; the in-binary memzero is belt-and-suspenders.

### F-3 (Windows env-var visibility to admin)

The recommended deployment pattern for the daemon is `DETERM_PASSPHRASE=...` in a systemd `EnvironmentFile=` (POSIX) or equivalent Windows service-manager configuration. On POSIX, the env var is readable by the process owner and root via `/proc/<pid>/environ`. On Windows, it's readable by any process with `PROCESS_QUERY_INFORMATION` (admin or the same user) via `QueryFullProcessImageName` + `NtQueryInformationProcess` or via Task Manager's "Details" tab → "Process environment".

**Severity:** Low/Op (operator-discipline; mitigation documented).

**Threat model:** Admin-level local adversary on the daemon host (i.e., adversary already inside the perimeter at root-equivalent privileges). At that privilege level, the adversary already has the encrypted keyfile readable AND can read the env-var passphrase. S-004's defense was against pre-runtime disk-only theft; once an adversary has admin on the running host, the encrypted-keyfile + passphrase-in-env are both compromised.

**Recommendation:** Operator-documentation guidance: for high-value validators, prefer `--passphrase-from file:<path>` where the file is 0600 + owned by the daemon UID, and is wiped from disk after the daemon has consumed it (a Just-Enough-Time pattern with systemd's `RuntimeDirectory=` + a startup script that decrypts the passphrase from a vault, writes it, daemon reads, script removes). The env-var pattern is the *convenient* default; the file-pattern is the *defensive* default.

**No code change recommended.** Both sources are supported (`L-1` discipline); operator chooses.

### F-4 (Windows 0600 ACL enforcement)

`keyfile-create`, `keyfile-rotate`, and `keyfile-recover --out` all attempt to set the output file's permissions to 0600 (owner read+write only) via `std::filesystem::permissions(..., owner_read | owner_write, replace)` (lines 3167-3172, 3967-3973, 4435-4441). On POSIX this is enforced by the kernel: subsequent reads by other users return EACCES.

On Windows, the call is **best-effort** — NTFS does not have a direct Unix-style mode bit. The C++ `<filesystem>` library translates `owner_read | owner_write` to a Windows ACL that grants read+write to the file's owner and removes other entries, but the operator's umask/inheritance settings and the parent directory's ACL may override this. The actual NTFS ACL after the call is **operator-environment-dependent**.

**Severity:** Low/Op (operator-discipline; mitigation documented). Windows operators should configure the parent directory (`%APPDATA%\determ\keyfiles\` or wherever) with strict NTFS ACL inheritance: owner full control, no SYSTEM, no Administrators (or at least no Everyone). The daemon process running as a service account should be the only entity with read access.

**Threat model:** Local non-admin user on the same Windows host who can read the keyfile bytes. They face the S-004 T-3 brute-force bound (`H_pw + log2(iter) ≥ 79.2` bits at recommended entropy) — operationally infeasible to crack. The 0600 ACL is a defense-in-depth: blocking the read at the OS layer prevents the brute-force attempt entirely. If the ACL is not enforced (as on a misconfigured Windows host), the cryptographic defense still holds; the operator just loses the OS-layer hardening.

**Recommendation:** Document the Windows ACL caveat in operator-onboarding materials (a dedicated `docs/OPERATOR-GUIDE.md` section on Windows-specific keyfile placement). Possibly add a `keyfile-info` warning when `--in` is on Windows and the parent directory's ACL is loose — but this is a complex Win32 API surface; defer to operator hygiene.

**No code change recommended for the cryptographic surface.** The `std::filesystem::permissions` call is the best portable mechanism; operator-side NTFS ACL is the actual defense.

---

## 7. Test surface

The lifecycle is covered by five dedicated wallet-side regression test scripts under `tools/`:

| Test script | Lifecycle command | Coverage highlights |
|---|---|---|
| `tools/test_wallet_keyfile_create.sh` | `keyfile-create` | Round-trip encrypt + self-test, --priv 32-byte seed + 64-byte seed||pub forms, --priv mismatch rejection, --out exists without --force rejection, --passphrase-from file/env/prompt sources, --json output shape, 0600 perms on POSIX. |
| `tools/test_wallet_keyfile_decrypt.sh` | `keyfile-decrypt` | Round-trip decrypt against fixed `keyfile-create` output, wrong-passphrase → exit 2, header tamper → exit 1 or 2 (AEAD AAD-binding defense), inner-vs-header pubkey mismatch detection (L-3 defense-in-depth), --out exists without --force rejection, --json output shape. |
| `tools/test_wallet_keyfile_rotate.sh` | `keyfile-rotate` | Rotate old → new passphrase, pubkey/anon-address preservation (T-2), salt + nonce freshness (T-2.1), in-place rotation (--in == --out), --force-same-passphrase opt-in, atomic-rename property (kill mid-rotation → original preserved), self-test round-trip catch, --json output shape, 0600 perms preservation. |
| `tools/test_wallet_keyfile_recover.sh` | `keyfile-recover` | T-of-N round-trip with various (T, N) pairs, different T-subsets yielding same secret (T-3.1), shares/envelopes file mismatch detection (L-2 step 2 in WalletRecoveryFlows.md), --threshold gate (insufficient → exit 2), wrong-passphrase per share → exit 2, --out vs stdout output, --json output shape, large-N edge cases. |
| `tools/test_wallet_keyfile_info.sh` | `keyfile-info` | Header parse, envelope-metadata extraction (pbkdf2_iters / salt_len / nonce_len / ct_len / aad_present), empty file → exit 2, missing-blob-line → exit 2, wrong header magic → exit 2, --json output shape, no-passphrase requirement. |

Each script is invoked under FAST=1 in `tools/run_all.sh`. The cumulative assertion count across the five scripts is ~150+ assertions (per individual script's `--help` summary). All five pass on the current `main` branch.

The daemon-side load path is covered indirectly by tests that start the daemon with an encrypted keyfile + DETERM_PASSPHRASE env var (e.g., `tools/test_chain_save_load.sh` and the integration tests in `tools/test_validators_rpc.sh`). The daemon's `Chain::load_node_key` decrypt failure paths (wrong passphrase, missing env, malformed envelope) exit the daemon with diagnostic, mirroring the wallet CLI's exit codes.

---

## 8. References

### Standards

- **NIST SP 800-132** (Turan, Barker, Burr, Chen, Dec 2010) — "Recommendation for Password-Based Key Derivation: Part 1: Storage Applications." Underpins T-1's PBKDF2 use; cited in S-004 §9 and inherited here.
- **NIST SP 800-38D** (Dworkin, Nov 2007) — "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC." Underpins T-2 + T-5 AAD-binding + tag-verify semantics.
- **RFC 8018** (Moriarty et al., Jan 2017) — "PKCS #5: Password-Based Cryptography Specification Version 2.1." Defines PBKDF2 (§5.2); concrete reference for the iter parameter.
- **RFC 5116** (McGrew, Jan 2008) — "An Interface and Algorithms for Authenticated Encryption." AEAD interface; underlies the `envelope::encrypt` / `decrypt` semantics.
- **RFC 8032** (Josefsson, Liusvaara, Jan 2017) — "Edwards-Curve Digital Signature Algorithm (EdDSA)." Ed25519 seed → keypair derivation; underlies T-1 + T-2 keypair-preservation claims.
- **FIPS 197** (NIST, Nov 2001) — Advanced Encryption Standard; the AES-256 used inside GCM.
- **FIPS 198-1** (NIST, Jul 2008) — HMAC; the PRF inside PBKDF2.

### Cryptographic literature

- **Bellare-Namprempre** (Asiacrypt 2000) — "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." AEAD security definitions used in T-5 composition.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security without Collision-Resistance." HMAC PRF reduction underlying PBKDF2-HMAC-SHA-256.
- **Kelsey-Schneier-Hall-Wagner** (FSE 1998) — "Secure Applications of Low-Entropy Keys." PBKDF2 cryptanalysis underlying T-1's per-trial cost.
- **Shamir** (CACM 1979) — "How to Share a Secret." The threshold scheme underlying T-3 + FA12 T-15.
- **Bonneau-Schechter** (USENIX Security 2014) — "Towards Reliable Storage of 56-bit Secrets in Human Memory." Human-passphrase-entropy estimation; informs F-1's operator-discipline guidance.
- **libsodium documentation** (Frank Denis, ongoing) — `sodium_memzero` semantics, `secure_buffer` patterns; underlies L-4's memory-scrubbing best-effort discipline.

### Determ-internal references

- `wallet/main.cpp:2984-3186` — `cmd_keyfile_create` (creation path).
- `wallet/main.cpp:3242-3483` — `cmd_keyfile_decrypt` (load/decrypt path).
- `wallet/main.cpp:3566-4003` — `cmd_keyfile_rotate` (rotation path).
- `wallet/main.cpp:4073-4460` — `cmd_keyfile_recover` (recovery composition).
- `wallet/main.cpp:5017-5142` — `cmd_keyfile_info` (metadata-only inspection).
- `wallet/envelope.hpp` + `wallet/envelope.cpp` — the DWE1 AEAD primitive shared across the lifecycle.
- `wallet/shamir.hpp` + `wallet/shamir.cpp` — the GF(2⁸) Shamir primitive composed in T-3.
- `src/crypto/keys.cpp::save_node_key` + `load_node_key` — the canonical plaintext `node_key.json` format (the AEAD-wrapped payload).
- `src/main.cpp::cmd_node` — the daemon startup path that invokes `Chain::load_node_key(path, passphrase)`.
- `tools/test_wallet_keyfile_create.sh`, `tools/test_wallet_keyfile_decrypt.sh`, `tools/test_wallet_keyfile_rotate.sh`, `tools/test_wallet_keyfile_recover.sh`, `tools/test_wallet_keyfile_info.sh` — the lifecycle regression harness.
- `docs/SECURITY.md` §S-004 — closure narrative this proof's deeper-dive companion.
- `docs/CLI-REFERENCE.md` `keyfile-create` / `keyfile-decrypt` / `keyfile-rotate` / `keyfile-recover` / `keyfile-info` rows — operator-facing documentation.
- `docs/proofs/S004KeyfileAtRest.md` — the at-rest cryptographic-primitive proof (T-1..T-5 there are black-box invariants here).
- `docs/proofs/WalletRecoveryFlows.md` — the operator-flow recovery companion.
- `docs/proofs/WalletRecovery.md` (FA12) — the underlying cryptographic-primitive proofs for the Shamir + AEAD composition.
- `docs/proofs/Preliminaries.md` (F0) §2.1 + §2.3 — SHA-256 + CSPRNG assumptions.

---

## 9. Status

**Shipped (S-004 closed in v2.17; lifecycle commands shipped across v2.17 → v2.20 per `docs/SECURITY.md` §S-004).** The complete keyfile lifecycle is live in the current `main` branch:

- `keyfile-create` — v2.17 (S-004 closure).
- `keyfile-decrypt` — v2.17 (S-004 closure).
- `keyfile-info` — v2.18 (operator-convenience addition).
- `keyfile-rotate` — v2.19 (passphrase-rotation lifecycle support).
- `keyfile-recover` — v2.20 (FA12 Shamir composition; depends on `backup-create` from earlier).

The five regression test scripts under `tools/test_wallet_keyfile_*.sh` provide the assertion-level coverage. The proof here formalizes the lifecycle-composition properties (T-1..T-5) that the implementation-level tests verify pointwise.

**Not yet shipped (future work):**

- Hardware-HSM-backed keyfile (YubiKey / Ledger / Trezor integration) — v2.X track; deferred per S-004 F-4.
- Memory-scrubbing discipline improvement (`sodium_memzero` in `keyfile-create` + `keyfile-decrypt` matching `keyfile-rotate`'s pattern) — F-2 above; tracked as a low-priority hygiene improvement.
- Windows-specific operator guidance for NTFS ACL hardening — F-4 above; tracked as an `OPERATOR-GUIDE.md` documentation item.

This proof was added as part of the analytic-closure sweep for S-004's deeper lifecycle composition. It does not modify any source code, only formalizes the create → load → rotate → recover composition properties that the wallet CLI surface implements.
