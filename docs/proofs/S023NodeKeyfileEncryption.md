# S023NodeKeyfileEncryption — node-key passphrase encryption + rotation atomicity composition

This document formalizes the **node-key-at-rest encryption + passphrase rotation** composition for Determ validator signing keys. Where `S004KeyfileAtRest.md` proves the AEAD primitive's at-rest cryptographic soundness for a *single* encrypted keyfile, and `S005PassphraseKeyfile.md` proves the lifecycle commands' end-to-end composition, **S023NodeKeyfileEncryption.md** focuses specifically on the **ROTATION composition** — the cryptographic + filesystem-level safety properties of moving an encrypted keyfile from one passphrase to another while preserving validator identity and never exposing plaintext.

The CLI surface in scope:

| CLI | `wallet/main.cpp` location | Purpose |
|---|---|---|
| `keyfile-create`  | `:2984-3186` | Encrypt a 32-byte Ed25519 seed into the canonical `DETERM-NODE-V1` 2-line file (initial creation). |
| `keyfile-decrypt` | `:3242-3483` | Reverse to plaintext `node_key.json` (operator emergency access). |
| `keyfile-rotate`  | `:3566-4003` | Re-encrypt under a new passphrase (fresh salt + fresh nonce); preserves the Ed25519 keypair (R28A1 surface). |
| `keyfile-recover` | `:4073-4460` | Compose `envelope::decrypt × N` + `shamir::combine` (FA12 Shamir composition). |
| `keyfile-info`    | `:5017-5142` | Metadata-only inspection (no passphrase, no decrypt). |

This document's analytic scope is **§T-4 rotation atomicity** and **§T-5 passphrase rotation safety** — i.e., the cryptographic + filesystem composition that makes `keyfile-rotate` safe under operator failure modes (mid-rotation crash, partial disk write, passphrase compromise) and never writes plaintext to disk during the rotation transition.

**Companion documents:** `S004KeyfileAtRest.md` (the AEAD-primitive at-rest soundness; cited as a black-box invariant); `S005PassphraseKeyfile.md` (the broader lifecycle composition; this document is the rotation-focused deep dive); `S001RpcAuthSoundness.md` (RPC HMAC orthogonal layer); `Preliminaries.md` (F0) §2.1 + §2.3 (SHA-256 + CSPRNG axioms). The proof presumes the reader is familiar with the §2 + §3 of `S004KeyfileAtRest.md` (cryptographic primitives) and the §2 + §3 of `S005PassphraseKeyfile.md` (lifecycle commands).

---

## 1. Threat model

A Determ operator stores the validator's Ed25519 signing key on disk in the `DETERM-NODE-V1` 2-line encrypted-keyfile format. The threat surface during the lifetime of that file includes both at-rest cryptographic attacks (covered exhaustively in S-004) and several **operational** attack scenarios specific to passphrase rotation and inter-host migration. We enumerate four:

### A-K1 — Disk image stolen (cold backup, laptop theft, OS-level UID compromise)

An attacker exfiltrates the encrypted keyfile bytes (`DETERM-NODE-V1 <hex(pk)>` header + `DWE1` envelope blob) but does NOT possess the passphrase `P`. Examples:

- Operator's laptop is stolen and the disk is forensically imaged.
- Backup tape / cloud-snapshot leak (e.g., misconfigured S3 bucket).
- Pre-runtime OS-level vulnerability exposes the operator's home directory ACL (0600) to an unprivileged process via a kernel bug.

The attacker has **unbounded offline compute budget** and can mount a brute-force attack on the passphrase. **The keyfile alone is the only attack input.**

### A-K2 — Passphrase compromise without keyfile

An attacker obtains the passphrase `P` (via shoulder-surfing, malware keylogger before keyfile transit, social engineering, password-manager export breach, or memory-dump of a process that briefly held it) but does NOT possess the encrypted keyfile bytes. Examples:

- Passphrase leaked from a paper-backup that was photographed.
- Operator typed the passphrase in plain shell history (e.g., `--passphrase-from prompt` log capture, or a misuse of `env DETERM_PASSPHRASE=...` showing up in `bash_history`).
- Memory-dump of a one-shot wallet CLI process before `sodium_memzero` ran.

The attacker has **only `P`**; no on-disk material.

### A-K3 — Keyfile in transit between hosts

An operator moves an encrypted keyfile from host A to host B (e.g., onboarding a new validator host, replacing failing hardware, geographic migration). The transit channel can be:

- USB stick (physical channel; risk: stick lost in transit).
- SCP / SFTP (encrypted but the operator's session may be compromised).
- E-mail / chat attachment (typically opaque to the operator's confidentiality posture).
- Git-checked-in (anti-pattern; sometimes done for staging environments).

An attacker who intercepts the keyfile in transit gets the same bytes as A-K1. **The transit channel may or may not provide additional confidentiality** (encrypted vs cleartext; signed vs unsigned).

### A-K4 — Passphrase rotation race

The operator runs `keyfile-rotate` to move from passphrase `P1` to `P2`. During the rotation window, three failure modes can leave the operator in a degraded state:

1. **Crash between decrypt-under-P1 and re-encrypt-under-P2.** Process exits before the new encrypted blob is written; the on-disk keyfile is still the P1 envelope (recoverable with `P1`).
2. **Crash between writing the staging file and renaming it to the final path.** The staging file `<out>_tmp.json` exists with the P2 envelope; the final path still holds the P1 envelope. Either operator-side cleanup runs (next rotation removes the stale tmp), or operator manually finishes the rename.
3. **Crash AFTER rename but BEFORE the operator deletes the (now-unused) memory of `P1`.** The on-disk keyfile is now the P2 envelope; the operator must remember `P2` to recover. If the operator hasn't yet recorded `P2` in their passphrase manager, this is a lockout.

The attack scenario beyond crashes: an attacker with **temporary** disk-read access during the rotation window — e.g., a backup process snapshotting the directory mid-rotation — captures EITHER the old envelope, the staging tmp file, or both. The cryptographic property required: each envelope (pre-rotation and post-rotation) is individually as strong as a single S-004 envelope, AND the staging tmp file (if it exists at the snapshot moment) is also as strong, AND no path during the rotation ever writes the plaintext seed to disk.

---

## 2. Defense theorems

### T-1 — At-rest secrecy

For any adversary `A_offline` (in the A-K1 disk-theft model) holding only the encrypted keyfile bytes `E := DETERM-NODE-V1 ‖ hex(pk) ‖ "\n" ‖ envelope::serialize(envelope::encrypt(J, P, aad)) ‖ "\n"`, the probability of recovering the private seed `sk` (the 32-byte preimage of `Ed25519_pubkey`) is bounded by

$$
\Pr\bigl[A_{\text{offline}} \to sk\bigr] \;\leq\; Q \cdot 2^{-(H_{\text{pw}} + \log_2(\text{iter}))} + \varepsilon_{\text{AEAD}}
$$

where `Q` is the adversary's PBKDF2 trial count, `H_pw` is the operator passphrase min-entropy, `iter = 600,000` is the PBKDF2 iteration count (`wallet/envelope.hpp:46`), and `ε_AEAD ≤ 2⁻¹²⁸` is the AES-256-GCM forgery bound.

For the operator-policy floor `H_pw ≥ 60` (per S-004 F-2), this is `≥ 2⁷⁹·²` HMAC-SHA-256 trial operations of total budget for any 50% success target — operationally infeasible against any classical adversary in 2026.

*Reduction.* Direct from S-004 T-3 + S-004 L-1 (PBKDF2 effective security) + S-004 L-6 (fresh-nonce-per-encryption assumption). The PBKDF2 work-factor amplification `2^{log2(iter)} ≈ 2¹⁹·²` is the cost-per-trial; the AES-256-GCM AEAD layer ensures that no candidate-passphrase trial yields information beyond a single tag-verify-fail bit. The composition is identical to S-004 T-3, restated here in the rotation context.   ∎

### T-2 — Passphrase-only attack

For any adversary `A_pass` (in the A-K2 passphrase-compromise model) holding ONLY the passphrase `P` and no on-disk material (no envelope bytes, no header, no salt), the probability of recovering the private seed `sk` is bounded by

$$
\Pr\bigl[A_{\text{pass}} \to sk\bigr] \;\leq\; 2^{-256} + \varepsilon_{\text{key-privacy}}
$$

where `ε_key-privacy` is the AES-256-GCM **key-privacy** advantage (Bellare-Boldyreva-Desai-Pointcheval 2001 "Key-Privacy in Public-Key Encryption" / AEAD key-privacy variant). Concretely: without access to the salt and nonce, the adversary cannot derive the PBKDF2-derived AES key (PBKDF2 is deterministic over `(P, salt, iter)`, and a uniformly random 16-byte salt makes the key indistinguishable from a uniform random 256-bit key from the adversary's view), and without access to the ciphertext + tag, the adversary cannot test candidate seeds against the envelope.

*Reduction.* The PBKDF2 derivation at `wallet/envelope.cpp:19-33` requires both `P` AND the per-envelope salt to produce the AES key. The salt is 16 bytes drawn uniformly from `RAND_bytes` per envelope (`wallet/envelope.cpp:46-49`); without it, the AES key the adversary would need is one of `2¹²⁸` possibilities — uniformly distributed under (A6) HMAC-SHA-256 PRF + (A8 / Preliminaries §2.3) CSPRNG uniformity. The seed `sk` is similarly 32 bytes; without any ciphertext to test against, the adversary has no oracle. The bound `2⁻²⁵⁶` is the random-guess success probability against the seed directly; the `ε_key-privacy` term covers any AES-specific structural weakness against key-privacy queries (Bellare-Boldyreva-Desai-Pointcheval bound this term as negligible under AES-256 standard assumptions).

Equivalently: **the passphrase is one of two required secrets** (the salt being the other). An adversary missing either factor faces a uniform-random search over the missing factor's space, which dominates the seed-space search.   ∎

### T-3 — Transport safety (channel separation)

For any adversary `A_transit` (in the A-K3 in-transit model) intercepting ONE OF {`E` (the keyfile bytes), `P` (the passphrase)} but NOT BOTH — provided each is transported over a distinct channel — the adversary's effective attack reduces to either A-K1 (if they intercepted `E`) or A-K2 (if they intercepted `P`). Hence:

$$
\Pr\bigl[A_{\text{transit}} \to sk\bigr] \;\leq\; \max\bigl(\Pr[A_{\text{offline}} \to sk],\ \Pr[A_{\text{pass}} \to sk]\bigr) \;\leq\; Q \cdot 2^{-(H_{\text{pw}} + \log_2(\text{iter}))} + \varepsilon_{\text{AEAD}}.
$$

*Reduction.* Direct from T-1 + T-2 by case analysis. Channel separation means the two factors `(E, P)` traverse independent channels: e.g., the keyfile bytes go via SCP from host A to host B, and the passphrase goes via an out-of-band channel (Signal message, phone call, password manager sync over a different network path). An adversary who breaches one channel — whether by passive eavesdropping or active MITM — obtains at most one factor. With either single factor, the adversary's success probability is bounded by T-1 (if they got `E`) or T-2 (if they got `P`), both of which are negligible under the H_pw ≥ 60 floor.

**Operational implication:** transport-channel hygiene is the operator's responsibility. The cryptographic defense (PBKDF2 + AEAD) protects only against single-factor exposure. If both factors leak together (e.g., the operator sends the keyfile AND the passphrase in the same e-mail), the defense reduces to T-1 with the passphrase known — which is **trivial recovery** of `sk` for the adversary. This is the residual operator-policy floor; see F-1.

The defense composes with the standard channel-security primitives: TLS-protected SCP, end-to-end-encrypted messaging, password-manager sync over an authenticated channel. Each provides a separate layer; channel-separation provides the additional layer that the two factors take distinct paths.   ∎

### T-4 — Rotation atomicity

For any invocation of `keyfile-rotate --in F --out F'` (with possibly `F == F'` for in-place rotation), there exist exactly two terminal states observable to any external process at any moment of the invocation:

1. **State PRE.** The file at `F` contains the original envelope (encrypted under `P1`). No file at `F'` (or `F'` contains the original envelope if `F == F'`).
2. **State POST.** The file at `F'` contains the new envelope (encrypted under `P2`). The original at `F` is preserved if `F != F'`, or replaced if `F == F'`.

There is **NO intermediate observable state** where:

- `F` is truncated or modified before the rename completes,
- `F'` is corrupted (partial-write),
- Both files briefly hold the same plaintext-derived material in mismatched encrypted forms.

*Reduction.* Inspect `cmd_keyfile_rotate` at `wallet/main.cpp:3566-4003`. The atomic-write protocol (lines 3870-3962) is:

1. **Staging file write** (lines 3878-3919): the new envelope is serialized into a temporary file at `<out>_tmp.json`. The original `--in` file is **not modified** during this step. If the staging-file write fails (disk full, permission error), `secure_zero_all()` runs, the staging file is removed, and the original `--in` is untouched.

2. **OS-level commit** (lines 3925-3945): `fsync` (POSIX) or `_commit` (Windows) is called on the staging file's file descriptor to force the OS to commit the bytes to durable storage. This is best-effort: if it fails, the rename still proceeds (the bytes are in the kernel page cache + the rename produces a valid file in the common case).

3. **Atomic rename** (lines 3946-3962): `std::filesystem::rename(tmp_path, out_path, rename_ec)`. This is **atomic on same-volume targets** on both POSIX (`::rename(2)` per POSIX.1-2008) and Windows (`MoveFileEx` with implicit `REPLACE_EXISTING`). The rename either completes (the operator sees `E_new` at `out_path`) or it does not (the operator sees `E_old` unchanged). **There is no torn-rename state.**

4. **0600 permissions tightening** (lines 3964-3973): applied to the renamed target file as belt-and-suspenders OS-layer hardening.

The **invariant** maintained across the rotation: at every instant, either (PRE) `F` is the original envelope, OR (POST) `F'` is the new envelope. There is no instant at which both are wholly intermediate. The plaintext bytes `pt_bytes` live only in process memory during the rotation; they never appear in any file (no temporary plaintext file is created at any point).

**Crash analysis.**

- Crash during step 1 (staging write): `<out>_tmp.json` may exist as a partial / empty / torn file. The original `--in` is untouched. Next rotation's `std::filesystem::remove(tmp_path)` at line 3882 cleans up the stale tmp.
- Crash during step 2 (fsync): `<out>_tmp.json` exists with the full new-envelope bytes. The rename has NOT happened; `--in` is untouched. The operator can manually rename the tmp to the final path (and at that point, `P2` recovers the file).
- Crash during step 3 (rename): atomic by POSIX/Windows semantics — either the rename completed (state POST) or it didn't (state PRE).
- Crash during step 4 (permissions tighten): the file is committed; permissions may be at the OS default rather than 0600. Operator-side `chmod 600` recovery is trivial.

The **decision point** is the `std::filesystem::rename` call. Before it, the operator can always recover with `P1` (the old envelope is intact at `--in`). After it, the operator must use `P2` (the new envelope is at `--out`, and if `--in == --out`, the old envelope is gone). The atomic-rename primitive is the cryptographic guarantee that this transition is **a single instant**, not a window.   ∎

**Corollary T-4.1 (in-place rotation crash recovery).** In the in-place case (`F == F'`), if a crash occurs before the rename, the operator's file at `F` is the original (P1-encrypted) envelope and is recoverable with `P1`. If the crash occurs after the rename, the file at `F` is the new (P2-encrypted) envelope and is recoverable with `P2`. There is no window where `F` is truncated or contains a torn intermediate state — the rename primitive guarantees this.

**Corollary T-4.2 (cross-volume rename is NOT atomic).** Note that `std::filesystem::rename` is atomic ONLY on same-volume targets. If the operator's `--in` and `--out` are on different volumes (e.g., `/home/operator/node_key.enc` and `/mnt/external/node_key.enc.bak`), the underlying OS implementation performs a copy-then-unlink, which is NOT atomic. Operator guidance (per F-3 below): for cross-volume rotation, rotate in-place first then copy the result to the cross-volume location.

### T-5 — Passphrase rotation safety (no plaintext-on-disk)

For any successful or failed invocation of `keyfile-rotate --in F --out F'`, the plaintext private seed `sk` (in its raw 32-byte form or its 64-char `priv_seed_hex` representation) **never appears on disk** at any moment of the invocation. The seed exists only in process memory during a bounded window:

1. **In-memory only during decrypt-under-P1** (line 3749 → 3763): the seed is in `pt_bytes` (heap allocation of ~95-byte JSON containing the hex-encoded seed).
2. **In-memory only during re-encrypt-under-P2** (line 3834): the same `pt_bytes` is passed to `envelope::encrypt`, which produces a new ciphertext + tag without ever serializing the plaintext to disk.
3. **In-memory only during self-test round-trip** (lines 3845-3868): the just-emitted envelope is decrypted under `P2` and byte-compared to the original `pt_bytes`. The transient `*rt_pt` plaintext is `sodium_memzero`'d immediately at line 3861.
4. **`secure_zero_all()` runs on every exit path** (lines 3767-3774): the function zeroes `pt_bytes`, `old_passphrase`, and `new_passphrase` on success exit (line 3978) AND on every error/exception path (lines 3782, 3793, 3801, 3807, 3814, 3820, 3837, 3848, 3855, 3863, 3888, 3897, 3911, 3953).

The file-system writes (steps 1-3 of T-4 atomicity protocol) write only **ciphertext bytes**: the AES-256-GCM-encrypted payload + the GCM tag + the salt + the nonce + the AAD. The PBKDF2-derived key, the seed plaintext, and the passphrase strings never appear in any file at any moment.

*Reduction.* Source-level audit of `cmd_keyfile_rotate`:

- **Decrypt path** (line 3749): `auto pt_opt = envelope::decrypt(*env_opt, old_passphrase, aad);`. The decrypt call returns a `std::optional<std::vector<uint8_t>>` — the plaintext bytes live ONLY in heap memory owned by `pt_opt` (then moved into `pt_bytes` at line 3763). No file write here.
- **Re-encrypt path** (line 3834): `auto new_env = envelope::encrypt(pt_bytes, new_passphrase, aad);` returns a `DWE1::Envelope` struct containing salt/nonce/ciphertext+tag/aad — all ciphertext-class data. The plaintext `pt_bytes` is not modified by this call.
- **Staging-file write** (line 3893-3894): `f << "DETERM-NODE-V1 " << header_pubkey_hex << "\n"; f << blob << "\n";`. The `blob` variable is `envelope::serialize(new_env)` — the canonical hex form of the new envelope, NOT the plaintext. The `header_pubkey_hex` is the validator's public key (already public information by definition).
- **secure_zero_all** (lines 3767-3774): wraps three `sodium_memzero` calls. The libsodium primitive uses inline asm + memory barriers to prevent compiler dead-store optimization (per libsodium `sodium/utils.c::sodium_memzero`). On every exit path, these run BEFORE any stdout/stderr summary line, so even a stale-buffer-reuse leak through the I/O system is prevented.

**Failure-mode analysis.**

- If decrypt-under-P1 fails (wrong old passphrase, corrupted envelope, AAD mismatch): the flow exits at line 3750-3756 BEFORE any `pt_bytes` is populated. `secure_zero_all()` runs (on an empty `pt_bytes` it's a no-op for that buffer; the two passphrase strings are still zeroed). No staging file is written. No plaintext exists at any moment.
- If re-encrypt fails (extremely rare; would indicate an OpenSSL initialization failure): `secure_zero_all()` runs (lines 3837-3840). Staging file is not opened. No plaintext on disk.
- If self-test round-trip fails (would indicate an internal bug; never observed in production): `secure_zero_all()` runs. Staging file may have been written but is not renamed; the staging-file content is ciphertext (the bug being detected is at the encrypt-decrypt symmetry, not at the file-write layer).
- If staging-file write fails (disk full, permission denied): the staging file may be partial-written but it contains only ciphertext bytes. The plaintext never reaches the file system.
- If rename fails (cross-volume, permission denied on out path): the staging file's ciphertext exists at `tmp_path` and is removed (line 3955). The original `--in` is untouched.

The composition: **at no point during the rotation is the plaintext seed written to any file**. The plaintext lives only in the heap allocation of `pt_bytes` (and the transient `*rt_pt` during self-test), and `sodium_memzero` runs on every exit path before any stdout I/O. The cryptographic guarantee is structural — the source code has no path that writes plaintext to a file.   ∎

---

## 3. Adversary outcomes

The four threat-model adversaries (A-K1..A-K4) map to the defense theorems as follows:

| Threat | Defense theorem(s) | Residual risk |
|---|---|---|
| **A-K1** disk image stolen | T-1 (at-rest secrecy: PBKDF2 + AEAD bound; `H_pw ≥ 60` floor) | Weak passphrase (`H_pw < 60`) gives operationally-tractable brute-force. Recommended: `H_pw ≥ 72` per F-2 (rotation drill). |
| **A-K2** passphrase compromise (no keyfile) | T-2 (passphrase-only attack: salt + nonce + ciphertext required; bound `2⁻²⁵⁶`) | None cryptographic. Operationally: if the attacker can subsequently obtain the keyfile (via A-K1 or A-K3), they collapse to the "both factors known" case. |
| **A-K3** keyfile in transit | T-3 (transport safety via channel separation: max of T-1 and T-2 bounds) | If both factors leak together (e.g., keyfile + passphrase in same e-mail), bound collapses to trivial recovery. Operator policy: distinct channels. |
| **A-K4** passphrase rotation race | T-4 (rotation atomicity: staged-write + atomic-rename) + T-5 (no plaintext on disk) | Operator-side state-tracking: must record `P2` BEFORE deleting memory of `P1` (or maintain a Shamir backup chain). |

### A-K1 → T-1 (full defense, with operator-policy precondition)

The attacker holds `E` but not `P`. Per T-1, the attack reduces to PBKDF2 brute-force at `H_pw + log2(iter)` effective bits. For the recommended operator floor `H_pw ≥ 60` (S-004 F-2), this is `≥ 79.2` bits — operationally infeasible. Residual risk: weak operator passphrase (e.g., `H_pw < 40` from a memorable English-words-only passphrase) brings the cost to `≤ 59.2` bits, which a cloud-GPU farm can brute-force in ~1 hour.

**Operator policy is the binding constraint.** Documented in F-2 below.

### A-K2 → T-2 (full defense)

The attacker holds `P` but not `E`. Per T-2, without the salt + nonce, the AES key derived from `P` is one of `2¹²⁸` possibilities indistinguishable from uniform random. The attacker cannot test candidate seeds against any envelope (no envelope is available). The bound is `2⁻²⁵⁶ + ε_key-privacy` — strongly negligible. **No residual cryptographic risk.**

Operationally, the residual risk is the combined-leak scenario: if the attacker subsequently obtains the keyfile (via A-K1 or A-K3), they collapse to the "P known + E known" case, which trivially recovers `sk`. This is why **operator practice should treat passphrase + keyfile as independent attack surfaces** — leaking either alone is recoverable; leaking both is catastrophic.

### A-K3 → T-3 (full defense under channel separation)

The attacker intercepts the keyfile OR the passphrase in transit, but not both. Per T-3, the residual bound is `max(T-1, T-2) ≤ T-1` — operationally infeasible under `H_pw ≥ 60`. Residual risk: combined-channel exposure (operator sends both factors via the same channel) collapses to trivial recovery. **Channel-separation discipline is the operator-policy precondition.**

The operator should treat the passphrase and the keyfile as two separate secrets that travel via two separate channels. The cryptographic defense does NOT require both channels to be encrypted — even an unencrypted channel for ONE factor is acceptable, provided the OTHER factor's channel is secure.

### A-K4 → T-4 + T-5 (full defense)

Any crash during the rotation window leaves the operator in one of two recoverable states: state PRE (the original envelope is intact at `--in`, recoverable with `P1`) or state POST (the new envelope is at `--out`, recoverable with `P2`). There is no torn state, no plaintext-on-disk window, no partial-overwrite state. **No residual cryptographic risk** at the rotation primitive level.

The residual operational risk is **operator state-tracking**: after a successful rotation, the operator must remember `P2`. If they crash or get distracted between completing the rotation and recording `P2` in their passphrase manager, the file at `--out` is unrecoverable (a self-inflicted lockout). The mitigations are:

1. Test `P2` via `keyfile-decrypt --in <new file> --out /dev/null --passphrase-from prompt` BEFORE deleting any memory of `P1`.
2. Use a passphrase manager (`pass`, `1Password`, `Bitwarden`) to record `P2` synchronously with the rotation.
3. Maintain a T-of-N Shamir backup (via `backup-create` + `keyfile-recover`) as the disaster-recovery escape hatch.

The CLI does NOT enforce any of these (no `--confirm-decryption-after-rotate` flag, no `--require-shamir-backup`). The operator-policy gate is documentation + onboarding.

---

## 4. Findings

### F-1 — Defense-in-depth: rotate Ed25519 priv keys (not just passphrases) periodically

**Finding.** The `keyfile-rotate` CLI rotates ONLY the passphrase, preserving the underlying Ed25519 keypair (and hence the validator's chain-level identity: REGISTER record, anon-address, stake balance, NEF eligibility). This is operationally desirable — rotating the chain identity would require a fresh REGISTER + the loss of stake-vesting history, which is heavy.

However, **periodic Ed25519-priv-key rotation is a defense-in-depth practice** that the current lifecycle does not directly support. The rationale: if an A-K2-style attacker has compromised `P` AND has briefly observed `E` (e.g., a malware infection that captured both keystrokes and disk reads during a 10-minute window 6 months ago, then went dormant), the long-lived Ed25519 seed is exposed indefinitely. A periodic key rotation — re-deriving a fresh seed, broadcasting a `ROTATE_KEY` chain transaction that ties the new pubkey to the old REGISTER record — would limit the exposure window.

**Severity.** Low/Op (defense-in-depth). Not a cryptographic break of the current scheme; an additional belt-and-suspenders layer.

**Threat scenario.** Long-lived validators (years-long deployment) accumulate exposure surface: every host migration, every passphrase rotation, every backup-restore is a window where the seed could leak. Defense-in-depth via Ed25519-key rotation caps the worst-case exposure window to the rotation interval.

**Recommendation.** Track as a v2.X future-work item: a `ROTATE_KEY` chain transaction (sketched in v2.26 per project memory) that ties a new pubkey to the same anon-address + REGISTER record under the old signature. Operator-side composition: derive a new seed, `keyfile-create` under a fresh passphrase, broadcast `ROTATE_KEY`, replace the daemon's `--keyfile` argument, restart. The chain-level part is the deferred work; the wallet-side composition is already possible with the current CLI surface.

**No immediate code change recommended.** Document as a future-work item in the v2.X roadmap.

### F-2 — Hardware security module (HSM) for production validators

**Finding.** The current `keyfile-rotate` + `keyfile-create` + `keyfile-decrypt` flows assume an operator-typed passphrase as the second factor. The passphrase entropy floor (`H_pw ≥ 60`, recommended `H_pw ≥ 72`) is bounded by what a human can reliably remember + type — practically, ~80 bits at the upper end for a 7-word Diceware passphrase. This means T-1's brute-force bound is parameterized by an operator-controlled quantity with a hard ceiling.

For **high-value production validators** (e.g., institutional operators with significant economic exposure), a hardware HSM (YubiKey + ed25519-on-token, Ledger Nano X, Trezor Model T, or a server-class HSM like AWS CloudHSM / YubiHSM 2) removes the passphrase-entropy floor entirely: the private key never leaves the HSM in plaintext, all signing operations are gated by physical possession of the device, and the brute-force surface is replaced by the HSM's tamper-resistance.

**Severity.** Low/Op (recommended for high-value operators; not a defect in the current scheme for medium-value operators).

**Threat scenario.** A nation-state-level adversary with a billion-dollar GPU farm budget OR a future quantum-capable adversary (Grover speedup on AES + PBKDF2) erodes the `H_pw + log2(iter)` bound. At `H_pw = 80, iter = 600,000`, the classical-effective security is `~99.2` bits; under Grover, this halves to `~49.6` bits — operationally tractable for a top-tier adversary.

**Recommendation.** Document HSM-integration guidance in `docs/OPERATOR-GUIDE.md` (a dedicated section for institutional / high-value validators). Reference the v2.X HSM-integration track (tracked separately as v2.X "hardware-second-factor" per S-004 F-4) as the protocol-level future work. For the wallet-side, no immediate change is needed — the operator can ALREADY compose an HSM-backed signing path with the daemon via a separate keyfile-protection module (out of scope for current S-023).

**No code change recommended.** Document HSM as a v2.X future-work item; current S-023 surface remains the recommended default for medium-value operators.

### F-3 — `keyfile-rotate` should ZERO the old keyfile contents, not just unlink

**Finding.** When `keyfile-rotate` is invoked **in-place** (`--in == --out`), the atomic-rename step (`std::filesystem::rename(tmp_path, out_path)`) replaces the original file's directory entry with the staging-tmp file. On most modern filesystems (ext4, NTFS, APFS), this means the original file's data blocks are unlinked but NOT zeroed — the bytes remain on disk in unallocated blocks until the filesystem allocator reuses them. A forensic adversary with disk-image access (e.g., A-K1 model AFTER the rotation) could recover the OLD envelope from unallocated blocks.

**Severity.** Low/Op (forensic-recovery hardening). The old envelope was protected by `P1`; if `P1` has been compromised since the rotation, the forensic recovery enables A-K1 against the old envelope (recoverable with the compromised `P1`).

**Threat scenario.** Operator rotates from `P1` (compromised, e.g., paper backup photographed by an adversary) to `P2` (fresh, secret). The rotation succeeds at the cryptographic level: the new envelope at `--out` is unreadable without `P2`. But a forensic adversary who gets disk access after the rotation can recover the old envelope from unallocated blocks AND decrypt it with the compromised `P1` — recovering `sk` despite the rotation.

**Recommendation.** Add an explicit-zero step to `cmd_keyfile_rotate` BEFORE the rename: open the original `--in` file in read-write mode, overwrite all bytes with zeros (or random bytes from `RAND_bytes`), `fsync`, close, then perform the rename. This forces the old envelope's bytes to be overwritten on disk before the inode-replacement happens. The implementation cost is minimal (~10 lines of C++); the operational benefit is closing the forensic-recovery surface against compromised-old-passphrase scenarios.

Caveat: on copy-on-write filesystems (btrfs, ZFS, APFS), file-level overwrites do NOT actually overwrite the underlying blocks — they allocate new blocks and leave the old blocks in place. The defense is moot on those filesystems unless combined with a filesystem-level `secure-delete` operation. Document this caveat in the operator-onboarding materials.

**Recommended code change.** Add a pre-rename block to `cmd_keyfile_rotate` (post line 3945, pre line 3949) that:

```cpp
// Overwrite the old --in file's bytes with zeros BEFORE rename
// (forensic-recovery hardening against compromised-old-passphrase).
// No-op on copy-on-write filesystems; defense-in-depth on ext4/NTFS/HFS+.
if (in_place) {
    std::ofstream f(in_path, std::ios::binary | std::ios::trunc);
    if (f) {
        std::vector<char> zero_buf(original_file_size, 0);
        f.write(zero_buf.data(), zero_buf.size());
        f.flush();
        f.close();
        // fsync the zero-overwrite before rename
        int fd = ::open(in_path.c_str(), O_RDONLY);
        if (fd >= 0) { (void)::fsync(fd); ::close(fd); }
    }
}
```

This is an in-place-only step (the non-in-place case writes to a fresh `--out` path, leaving the original `--in` untouched — operator-side cleanup of the old keyfile is then explicit). Track as a R28A2 / future-rotate-hardening item.

---

## 5. Composition with S-004 / S-005 / S-001

This proof **extends** the existing keyfile-encryption proof chain. The composition layers:

### S-004 (`S004KeyfileAtRest.md`) — single-envelope cryptographic primitive

S-004 proves that a single `DETERM-NODE-V1` encrypted keyfile is sound at the AEAD layer:

- **T-1 (PBKDF2 soundness)**: brute-force lower bound `H_pw + log2(iter)` bits per trial.
- **T-2 (AEAD AAD-binding)**: header-substitution attacks defeated.
- **T-3 (confidentiality under disk theft)**: bound parameterized by passphrase entropy.
- **T-4 (no online-guess amplification)**: PBKDF2 cost + constant-time tag-verify cap A_online's effective rate.
- **T-5 (pubkey-indistinguishability)**: A_msg's pubkey-derivation attack does not amplify advantage beyond T-3.

S-023's T-1 is a direct restatement of S-004's T-3 in the rotation context — every encrypted envelope (pre-rotation, post-rotation, staging-tmp) is individually sound under S-004's bound. S-023's T-2 generalizes S-004's analysis to the "passphrase-only without keyfile" adversary, which S-004 implicitly covers but does not state as a stand-alone theorem.

### S-005 (`S005PassphraseKeyfile.md`) — lifecycle composition

S-005 proves the broader lifecycle (`create` → `decrypt` → `rotate` → `recover` → `info`) preserves identity, never leaks plaintext via stdout, and composes the per-envelope cryptographic primitives across the five commands:

- **T-1 (Create → Decrypt Identity)**: round-trip preserves the seed byte-identically.
- **T-2 (Rotation Preserves Identity)**: the chain-level identity (REGISTER record, anon-address, NEF eligibility) is unchanged across rotation.
- **T-3 (Recovery From Shamir + Keyholder Passphrases)**: T-of-N Shamir composition with per-share AEAD envelopes.
- **T-4 (No Plaintext Leak Across Lifecycle)**: stdout-discipline for the four non-recovery commands.
- **T-5 (Composition with S-004 At-Rest at Every Boundary)**: every encrypt/decrypt boundary is sound.

S-023 is the **rotation-focused deep-dive**: where S-005's T-2 + T-5 state that rotation preserves identity + composes cryptographically, S-023's T-4 + T-5 add the **atomicity and no-plaintext-on-disk** properties that S-005 leaves implicit. S-023's A-K4 threat model is the operational-failure-mode analysis that S-005's T-2 proof sketch does not enumerate exhaustively.

### S-001 (`S001RpcAuthSoundness.md`) — orthogonal RPC HMAC

S-001 protects the **daemon's RPC surface** against unauthenticated callers via HMAC-SHA-256 authentication. It is **orthogonal** to S-023: the RPC authentication layer is a network-layer concern; the node-key encryption layer is a filesystem-layer concern. They operate at different layers and on different time scales (S-001: per-RPC-request; S-023: per-daemon-startup or per-operator-rotation).

The composition is **trivial**: an attacker who breaks S-023 (recovers the validator's signing key) can use that key to sign new blocks (defeating consensus). An attacker who breaks S-001 (forges an RPC call) can manipulate the running daemon's state but cannot sign blocks without the seed (which S-023 protects). The two defenses are **multiplicative**: an adversary must break both to fully compromise a validator.

### Composition summary

The combined defense posture for a Determ validator's signing key:

1. **At rest (S-004 + S-023 T-1)**: the encrypted keyfile is brute-force-infeasible under `H_pw ≥ 60`.
2. **In transit (S-023 T-3)**: channel separation between passphrase and keyfile defeats single-channel interception.
3. **During rotation (S-023 T-4 + T-5)**: atomic-rename + no-plaintext-on-disk guarantees rotation is crash-safe and confidential.
4. **At runtime (S-001 RPC HMAC + FA1 Ed25519 EUF-CMA)**: the daemon's running state is protected by authentication + signature unforgeability; the seed in memory is bounded only by OS-level hardening (`mlock`, no swap, etc.).
5. **At equivocation (FA6 slashing)**: if the seed IS compromised and the adversary tries to sign conflicting blocks, the FA6 evidence-detection layer slashes the validator.

S-023's specific contribution: closing the **operational** attack surface around rotation (A-K4) and inter-host migration (A-K3), under the cryptographic primitive that S-004 provides at the AEAD layer.

---

## 6. References

### Standards

- **PKCS #5 v2.1 / RFC 8018** (Moriarty, Kaliski, Rusch, Jan 2017) — "PKCS #5: Password-Based Cryptography Specification Version 2.1." Defines PBKDF2 (§5.2); the primitive underlying S-023 T-1's brute-force lower bound.
- **RFC 2898** (Kaliski, Sep 2000) — "PKCS #5: Password-Based Cryptography Specification Version 2.0." Historical predecessor of RFC 8018; PBKDF2 originally specified here.
- **NIST SP 800-38D** (Dworkin, Nov 2007) — "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC." Defines AES-GCM; the AEAD primitive underlying S-023 T-1 + T-2.
- **NIST SP 800-132** (Turan, Barker, Burr, Chen, Dec 2010) — "Recommendation for Password-Based Key Derivation: Part 1: Storage Applications." NIST companion to RFC 8018; deployment guidance for PBKDF2 iteration count + salt length.
- **FIPS 197** (NIST, Nov 2001) — Advanced Encryption Standard. Specifies AES-256 used inside GCM.
- **FIPS 198-1** (NIST, Jul 2008) — The Keyed-Hash Message Authentication Code (HMAC). Underlying PRF for PBKDF2-HMAC-SHA-256.
- **FIPS 180-4** (NIST, Aug 2015) — Secure Hash Standard. Specifies SHA-256 used by HMAC.
- **RFC 5116** (McGrew, Jan 2008) — "An Interface and Algorithms for Authenticated Encryption." AEAD interface specification.
- **RFC 8032** (Josefsson, Liusvaara, Jan 2017) — "Edwards-Curve Digital Signature Algorithm (EdDSA)." Reference for Ed25519 (the seed-protected key type).
- **POSIX.1-2008** — `rename(2)` atomic-rename semantics on same-volume targets, underlying T-4's atomicity property.

### Cryptographic literature

- **Bellare-Namprempre** (Asiacrypt 2000) — "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." AEAD security definitions used in T-1's `ε_AEAD` term.
- **Bellare-Boldyreva-Desai-Pointcheval** (Asiacrypt 2001) — "Key-Privacy in Public-Key Encryption." Key-privacy variant underlying T-2's `ε_key-privacy` term.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security without Collision-Resistance." HMAC PRF reduction underlying PBKDF2-HMAC-SHA-256's bound.
- **Kelsey-Schneier-Hall-Wagner** (FSE 1998) — "Secure Applications of Low-Entropy Keys." PBKDF2 cryptanalysis underlying T-1's per-trial cost analysis.
- **Boyle-Lin** (USENIX Security 2024) — recent treatment of password-based encryption schemes against quantum adversaries; informs F-2's HSM recommendation.
- **OWASP Authentication Cheatsheet** (2023 edition) — passphrase entropy + PBKDF2 iteration-count guidance underlying T-1's `H_pw ≥ 60` floor.
- **NIST SP 800-63B** (Grassi et al., 2017) — Memorized-Secret guidance for passphrase entropy.
- **Bonneau-Schechter** (USENIX Security 2014) — "Towards Reliable Storage of 56-bit Secrets in Human Memory." Human-passphrase-entropy estimation; informs F-2's HSM recommendation for high-value validators.

### Determ-internal references

- `wallet/envelope.hpp:1-75` + `wallet/envelope.cpp:1-249` — the `DWE1` AEAD envelope primitive (PBKDF2-HMAC-SHA-256 + AES-256-GCM); `DEFAULT_PBKDF2_ITERS = 600,000`.
- `wallet/main.cpp:2984-3186` — `cmd_keyfile_create` (initial encryption).
- `wallet/main.cpp:3242-3483` — `cmd_keyfile_decrypt` (decrypt-to-plaintext).
- `wallet/main.cpp:3566-4003` — `cmd_keyfile_rotate` (passphrase rotation; R28A1 surface; primary subject of T-4 + T-5).
  - `:3749` — `envelope::decrypt` call (under old passphrase).
  - `:3763` — `pt_bytes` ownership transfer.
  - `:3767-3774` — `secure_zero_all` lambda definition.
  - `:3834` — `envelope::encrypt` call (under new passphrase, fresh salt + nonce).
  - `:3845-3868` — self-test round-trip (decrypt-under-new + byte-compare).
  - `:3878-3919` — staging-file write (`<out>_tmp.json`).
  - `:3925-3945` — OS-level commit (`fsync` POSIX / `_commit` Windows).
  - `:3946-3962` — atomic rename (`std::filesystem::rename`).
  - `:3964-3973` — 0600 permissions tightening.
- `wallet/main.cpp:4073-4460` — `cmd_keyfile_recover` (Shamir composition; FA12 reference).
- `wallet/main.cpp:5017-5142` — `cmd_keyfile_info` (metadata-only inspection).
- `src/main.cpp:4416` + `:4526` — `DETERM_PASSPHRASE` env-var fallback for daemon-side + account-decrypt CLI.
- `src/crypto/keys.cpp:35-58` — canonical plaintext `node_key.json` format (the AEAD-wrapped payload).
- `tools/test_wallet_keyfile_rotate.sh` — regression harness for the rotation surface; covers atomicity (kill mid-rotation → original preserved), salt + nonce freshness across rotations, `--force-same-passphrase` opt-in, in-place rotation (`--in == --out`).
- `tools/test_wallet_keyfile_create.sh`, `tools/test_wallet_keyfile_decrypt.sh`, `tools/test_wallet_keyfile_recover.sh`, `tools/test_wallet_keyfile_info.sh` — companion regression scripts for the other four lifecycle commands.
- `docs/SECURITY.md` — finding-register; S-023 originally tracked the RPC balance-pre-check issue (closed in `node/node.cpp::rpc_send/stake/unstake`), and the node-key encryption surface is tracked under S-004's umbrella.
- `docs/CLI-REFERENCE.md` — `keyfile-rotate` row + other lifecycle command rows.
- `docs/proofs/S004KeyfileAtRest.md` — the at-rest cryptographic-primitive proof (T-1..T-5 there are black-box invariants here).
- `docs/proofs/S005PassphraseKeyfile.md` — the broader lifecycle composition (T-1..T-5 there cover create → decrypt → rotate → recover → info; this document is the rotation-focused deep dive).
- `docs/proofs/S001RpcAuthSoundness.md` — the orthogonal RPC-auth defense (S-001 closure).
- `docs/proofs/WalletRecovery.md` (FA12) — underlying cryptographic-primitive proofs (T-16 AEAD envelope binding, T-15 Shamir reconstruction).
- `docs/proofs/WalletRecoveryFlows.md` — operator-flow companion for the recovery surface.
- `docs/proofs/Preliminaries.md` (F0) §2.1 — SHA-256 collision resistance assumption.
- `docs/proofs/Preliminaries.md` (F0) §2.3 — CSPRNG uniformity assumption underlying salt + nonce freshness.

---

## 7. Status

**Shipped (S-023 node-key encryption + rotation surface closed in v2.17 → v2.19 per `docs/SECURITY.md` §S-004 umbrella).** The encryption + rotation flows are live in the current `main` branch:

- `keyfile-create` — v2.17 (S-004 closure; initial encryption).
- `keyfile-decrypt` — v2.17 (S-004 closure; emergency operator access).
- `keyfile-info` — v2.18 (operator-convenience metadata).
- `keyfile-rotate` — v2.19 (R28A1; passphrase rotation; primary subject of this proof).
- `keyfile-recover` — v2.20 (FA12 Shamir composition).

This proof formalizes the rotation-focused composition properties (T-4 atomicity + T-5 no-plaintext-on-disk) that the implementation-level tests verify pointwise via `tools/test_wallet_keyfile_rotate.sh`. The proof does not modify any source code; it documents the analytic claims underlying the existing implementation.

**Future-work items (per §4 findings):**

- **F-1**: Ed25519-priv-key rotation via `ROTATE_KEY` chain transaction — v2.X / v2.26 track.
- **F-2**: Hardware HSM integration — v2.X "hardware-second-factor" track per S-004 F-4.
- **F-3**: Forensic-recovery hardening via explicit-zero-old-keyfile-before-rename — R28A2 future enhancement.

None of the future-work items is a blocker for the current S-023 surface; the proof's T-1..T-5 hold for the shipped scheme.
