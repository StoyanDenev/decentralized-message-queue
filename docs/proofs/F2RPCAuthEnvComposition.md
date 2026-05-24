# F2RPCAuthEnvComposition — composed RPC auth flow with env-var loading

This proof formalizes the **composed RPC auth flow** from operator-set environment variable, through process boot, into the daemon's runtime HMAC verification path. It composes three previously-proved layers — (a) the env-var loading mechanism at `src/rpc/rpc.cpp:289–307`, (b) the HMAC-SHA-256 cryptographic gate established in `RpcAuthHmacSoundness.md` (T-1..T-5), (c) the five-layer input-validation defense established in `RpcInputValidationDefense.md` — into a single end-to-end soundness statement: under the standard PRF assumption on HMAC-SHA-256 and the operating-system per-process env-var access-control model, the secret loaded from the environment is bound into every authenticated request, every authenticated request still passes the input-validation pipeline, and the operator's threat-model coverage (cross-tenant on the same host) is preserved across the loading-boundary.

The novelty of this proof relative to its siblings is the **loading-boundary** analysis. `S001RpcAuthSoundness.md` composes the runtime-side gates (HMAC + input-validation + apply-layer); `RpcAuthHmacSoundness.md` proves the HMAC primitive's soundness in isolation; `RpcInputValidationDefense.md` proves the five-layer defense. None of these documents pins the operator-experience surface where the secret enters the process: the env-var loading mechanism is documented in `SECURITY.md` §S-001 ("Client side (CLI + `rpc_call`): if `DETERM_RPC_AUTH_SECRET` env var is set, every outgoing request automatically gets the auth field computed from the env-var secret") and `CLI-REFERENCE.md` §17, but no proof formalizes its threat model, no proof exhaustively enumerates the env-var-specific adversary classes (process-listing visibility, shell history persistence, /proc exposure), and no proof composes the loading mechanism with the runtime gates. **This document closes that gap.**

It also surfaces, as F-1 below, a concrete implementation finding discovered during the audit: the env-var loading path exists ONLY on the client side (`src/rpc/rpc.cpp:294`); the daemon side reads `rpc_auth_secret` exclusively from the config JSON via `Config::from_json` (`src/node/node.cpp:68`) → `Config::load` (`src/node/node.cpp:110`) → `main.cpp:1147` (constructor argument to `RpcServer`). An operator who exports `DETERM_RPC_AUTH_SECRET` expecting the daemon to pick it up is silently misled — the daemon launches with `auth_secret_.empty() == true` and accepts unauthenticated requests on whatever interface the config's `rpc_localhost_only` flag selects. The single-tenant localhost-only default per S-001 Option 1 keeps this asymmetry safe in practice, but the asymmetry itself is a real operator-UX gap and motivates F-2 below (recommend daemon-side env-var fallback symmetric with the client).

**Companion documents:** `S001RpcAuthSoundness.md` (R27A3 / S-001 composition theorem; this proof extends with the loading-boundary arm); `RpcAuthHmacSoundness.md` (R20-ish HMAC primitive soundness; T-1..T-5 composed here as the cryptographic gate); `RpcInputValidationDefense.md` (R26A7 five-layer defense; composed as T-5 below for the per-method semantic gates); `JsonValidationSoundness.md` (S-018 closure; composed via T-5 here as the Layer B structural arm); `NonceMonotonicity.md` (FA-Apply-3; composed as the apply-layer replay backstop); `S014RateLimiterSoundness.md` (rate-limiter pre-gate; composed in §4); `S027InfoLeakage.md` (info-leakage closure on the secret-confidentiality surface; cross-references the operator-log audit); `SECURITY.md` §S-001 closure narrative (the operator-experience surface this proof formalizes); `SECURITY.md` §S-004 (passphrase-encrypted keyfile pattern; cross-referenced under F-2's medium-term mitigation path); `Preliminaries.md` §2.1 (A2 / H1 SHA-256 collision resistance), §2.3 (CSPRNG / uniform key distribution).

---

## 1. Composed auth flow

### 1.1 End-to-end timeline

The composed flow has six discrete steps from operator action to request acceptance:

1. **Operator-side secret generation.** Operator runs `openssl rand -hex 32` to produce a 64-character lowercase hex string `K_hex` carrying 256 bits of entropy from OpenSSL's CSPRNG (`/dev/urandom` on Linux; `BCryptGenRandom` on Windows). This is the standard recommendation per `CLI-REFERENCE.md` §17 + `RpcAuthHmacSoundness.md` §2.2 (K_random assumption).

2. **Operator-side secret installation — env-var path.** Operator sets the environment variable in their shell:

   ```sh
   export DETERM_RPC_AUTH_SECRET="<K_hex>"
   ```

   This places `K_hex` into the operator's process environment block. Subsequent child processes inherit the environment per POSIX `execve(2)` (Linux) / `CreateProcessW` with `lpEnvironment=NULL` (Windows). The env-var lives in the OS-managed per-process memory region traditionally exposed under `/proc/$pid/environ` on Linux.

3. **Daemon launch — config-driven path** (the path actually shipped). Operator runs `determ --config <path>` (or `determ --domain ...` with default config path). `Config::load` at `src/node/node.cpp:110–114` parses the config JSON; `Config::from_json` at `src/node/node.cpp:62–108` extracts `rpc_auth_secret` at line 68 via `j.value("rpc_auth_secret", std::string{})`. The result is stored in the `Config` struct's `rpc_auth_secret` field.

4. **Daemon RPC server construction.** `main.cpp:1145–1149` constructs `RpcServer` passing `cfg.rpc_auth_secret` as the `auth_secret_hex` constructor argument. The `RpcServer` constructor at `src/rpc/rpc.cpp:79–90` calls `hex_to_bytes(auth_secret_hex)` and stores the resulting byte vector in `auth_secret_`. The startup banner at `src/rpc/rpc.cpp:95–104` emits the secret's *length in bytes* (`auth_secret_.size()`), never its value, plus the deliberate `[WARNING: external bind without HMAC auth ...]` line when `!localhost_only && auth_secret_.empty()`.

5. **Client request — env-var path** (the path that DOES consume the env-var). Operator runs a CLI subcommand backed by `rpc_call` at `src/rpc/rpc.cpp:276–321`. The client at line 292 takes the explicit `auth_secret_hex` argument; if empty, falls back at line 294 to `std::getenv("DETERM_RPC_AUTH_SECRET")`. If both are empty, no `auth` field is added to the request; if either is set, the client computes `auth = hex(HMAC-SHA-256(hex_to_bytes(K_hex), method ‖ "|" ‖ params.dump()))` (lines 297–307) and embeds it in the request.

6. **Server verify.** The server at `src/rpc/rpc.cpp:179` calls `verify_auth` (lines 112–129); if `auth_secret_.empty()` returns `""` (pass — auth disabled). Otherwise: recompute the expected HMAC over the canonical bytes, constant-time compare to the request's `auth` field, return `""` on match or `"auth_failed"` on mismatch. The dispatch at line 184 fires only on the `""` (pass) path.

### 1.2 The asymmetry — env-var loading lives only on the client

Steps 3–4 above describe the **daemon-side** secret loading: it reads exclusively from the config JSON. Step 5 describes the **client-side** env-var loading. The env-var is consulted only at the client; the daemon's `auth_secret_` field is populated only from the config JSON parameter.

This asymmetry is not documented in `SECURITY.md` §S-001 (which lumps both sides under a single "operator distribution responsibility" paragraph) and is not stated in `RpcAuthHmacSoundness.md` §6 F-2 (which mentions the env var as a leakage surface but does not pin which side reads it). The composition theorem in §3 below is stated against the actual shipped behavior; F-1 surfaces the discrepancy with the documented operator-experience expectations; F-2 recommends the symmetric daemon-side fallback as a medium-term hardening.

### 1.3 Threat surface partition

The composed flow exposes a different threat surface at each step. The breakdown:

| Step | Threat surface | Defended by |
|---|---|---|
| 1 (generation) | CSPRNG weakness / entropy starvation | Operator follows `openssl rand -hex 32` per `CLI-REFERENCE.md` §17 (OpenSSL `RAND_bytes` is the underlying source, identical to the Preliminaries §2.3 assumption). |
| 2 (env-var install) | Process listing (`ps eww`), `/proc/$pid/environ`, shell history file | A-E1..A-E3 below; OS-level access controls + `hidepid=2` mount + `read -s` prompt |
| 3 (config load) | Config-file read access | F-1 of `RpcAuthHmacSoundness.md` (passphrase-encrypted keyfile pattern, v2.17 — recommended); `chmod 0600` + per-user filesystem ACL (short-term) |
| 4 (server construction) | Memory dump of running process; startup log | Process-isolation by OS; startup log emits length only (audited in `RpcAuthHmacSoundness.md` L-4) |
| 5 (client request) | TLS / TCP eavesdropping on the auth field on the wire | HMAC-SHA-256 PRF security (per `RpcAuthHmacSoundness.md` T-1) — the `auth` field reveals no information about `K`; replay-defense via T-2 below + apply-layer nonce gate (NonceMonotonicity FA-Apply-3) |
| 6 (server verify) | Constant-time compare timing channel; HMAC primitive defects | `RpcAuthHmacSoundness.md` T-3 + T-5 (constant-time compare + OpenSSL `HMAC(EVP_sha256(), ...)`); cross-references S014RateLimiterSoundness.md for online-brute-force defense |

The composition theorem in §3 below operates on the joint surface — every step's defense must hold for the end-to-end statement to hold.

---

## 2. Threat model

The adversary model extends the `A_outside` + `A_inside` partition from `S001RpcAuthSoundness.md` §2.3 with **env-var-specific** adversary classes A-E1..A-E5. The runtime adversaries (`A_outside`, `A_inside`) continue to apply against the request-handling surface (steps 5–6 above); the env-var adversaries apply against the loading surface (steps 1–4 above).

### A-E1 — Env-var leaked via `/proc/$pid/environ`

The adversary has the OS-level capability to read `/proc/$pid/environ` for the operator's shell process (the parent that exported the variable) or any child process that inherited the env block. On Linux, by default any process owned by the same user can read `/proc/$pid/environ`; with `hidepid=2` mount option on `/proc`, only the owning UID can see the entry. With `hidepid=0` (the historical default on many distributions), processes of other UIDs in the same process namespace can read the entry — exposing the secret to any same-host attacker who landed an unprivileged account.

**Capability assumed:** read access to the operator's `/proc/$pid/environ` (or BSD equivalent via `ps eww`, or Windows equivalent via `GetEnvironmentStringsW` on a token-holding process).

**Impact if successful:** full recovery of `K_hex`; equivalent to `A_inside` for the runtime gates. The cross-tenant defense established by HMAC (S-001 Option 3) is bypassed.

**Defense:** OS-level access controls. On Linux: `hidepid=2` on `/proc` mount. On BSD: per-user `kern.proc.allproc` sysctl restrictions. On Windows: per-process token access controls. The defense is OS-policy, not a Determ-code-level defense.

### A-E2 — Env-var passed via shell command-line (visible in `ps`)

The operator launches the determ daemon (or any client) with the secret on the command line, e.g.:

```sh
DETERM_RPC_AUTH_SECRET=DEADBEEF... determ
# or
determ --auth-secret DEADBEEF...
```

The argument vector `argv` is visible via `ps auxww` to any same-host process owned by any UID (the default kernel policy). The env-var inline-prefix form (`KEY=VALUE cmd`) is also visible in `ps eww`. The `argv` exposure is independent of `/proc/$pid/environ` access controls.

**Capability assumed:** read access to `/proc/$pid/cmdline` or `ps auxww` output (same-host, any UID by default on Linux/BSD; same-session on Windows).

**Impact if successful:** full recovery of `K_hex`; equivalent to `A_inside` for the runtime gates.

**Defense:** operator hygiene. Recommended pattern: `export` the variable in a shell-rc file with `chmod 600` permissions on that file (e.g., `~/.config/determ/env` sourced by the operator's shell), or use a secrets manager that injects the env-var into the process at spawn time without exposing it on the launching command line.

### A-E3 — Operator includes auth-secret in shell history file

The operator pastes the secret into an interactive shell command:

```sh
$ export DETERM_RPC_AUTH_SECRET=DEADBEEF1234...
```

Bash's `~/.bash_history`, Zsh's `~/.zsh_history`, and similar shell history files persist command lines (subject to per-shell `HISTCONTROL` / `HISTIGNORE` settings). On most operator boxes the history file is `chmod 0600`, but the operator's own backup, dotfile sync (e.g., GitHub-published dotfiles), or accidental shell-history paste reveals the secret long after the operational window closes.

**Capability assumed:** read access to the operator's shell history file at any time — including post-revocation, if the operator rotated the secret but the history still carries the old value (and the operator forgot to also rotate the database where the old value was stored, or the attacker has a backup snapshot that captures the pre-rotation moment).

**Impact if successful:** full recovery of the secret at the time it was set; equivalent to `A_inside` for the runtime gates at that point in time. Rotation closes the window forward (the old secret stops being accepted as soon as the operator restarts the daemon with a new value), but does not retroactively protect any requests sent with the old secret nor any state changes those requests caused.

**Defense:** operator hygiene. Recommended pattern: use a read-from-tty prompt (`read -s DETERM_RPC_AUTH_SECRET` followed by `export DETERM_RPC_AUTH_SECRET`) so the secret is never typed as a literal in the shell command line; or load the value from a `chmod 0600` file at the start of the operator's working session (`export DETERM_RPC_AUTH_SECRET="$(cat ~/.config/determ/auth_secret)"` — note this still puts the secret in the env-var, but does not record it in shell history).

### A-E4 — Auth-secret persisted in `Config::to_json` (plaintext at-rest)

This is the existing `RpcAuthHmacSoundness.md` F-1 finding, restated here in the composed setting for completeness. `Config::to_json` at `src/node/node.cpp:23–60` serializes `rpc_auth_secret` to JSON at line 30 in plaintext. When `Config::save` (`src/node/node.cpp:116–121`) writes the config to disk, the secret persists at-rest in the operator's config file.

The composition impact: when the operator opts for the **config-file loading path** (the actually-shipped daemon path per step 3 in §1.1) over the env-var loading path, the config-file at-rest persistence becomes the attack surface. An attacker with read access to the config file recovers `K_hex` directly.

**Capability assumed:** read access to the operator's config JSON file (default `~/.config/determ/config.json` on Linux; `%APPDATA%\determ\config.json` on Windows).

**Impact if successful:** full recovery of `K_hex`; equivalent to `A_inside`.

**Defense:** short-term, `chmod 0600` on the config file + per-user filesystem ACL. Medium-term, apply the v2.17 / S-004 passphrase-encrypted keyfile pattern (already shipped for the Ed25519 node key) to `rpc_auth_secret` — the operator types a passphrase at startup, the daemon decrypts the secret in memory, the at-rest representation is encrypted. Long-term, integrate with a secrets manager (HashiCorp Vault, AWS Secrets Manager, K8s secrets) so the daemon fetches the secret over a separate authenticated channel at startup.

### A-E5 — Auth-secret loaded from a config file (alternative — but file access controls become the new attack surface)

This is the **mirror-image** of A-E4: even if the operator avoids env-var leakage paths A-E1..A-E3 by putting the secret in a config file (and the daemon reads it from there per the actually-shipped path), the secret is then at-rest on the filesystem. The attack surface shifts from "env-var visibility in /proc / ps / shell history" to "filesystem read access on the config file". Neither path is strictly safer; each defends against a different set of adversaries.

**Capability assumed:** read access to the config file (same as A-E4).

**Impact if successful:** full recovery of `K_hex`.

**Defense:** as for A-E4. The cross-mitigation choice is: env-var path defends against filesystem snapshots (e.g., backup tapes, container image leaks, dotfile sync) but exposes via `/proc` + `ps` + shell history; config-file path defends against `/proc` and `ps` but exposes via filesystem snapshots. The composition theorem in §3 covers both paths under their respective threat models; the operator's deployment policy chooses which adversary class to optimize against.

### Composition statement

The runtime adversaries (`A_outside`, `A_inside`) per `S001RpcAuthSoundness.md` §2.3 continue to apply against the request-handling surface independently of which loading path the secret took. A-E1..A-E5 promote a successful loading-surface attack to `A_inside` for the runtime gates. The end-to-end soundness statement therefore requires:

```
Sound(F2RPCAuthEnvComposition)  :=
    (no successful A-E1..A-E5 attack on the loading surface)
  ∧ (S001 runtime gates hold against A_outside and A_inside)
  ∧ (apply-layer FA-Apply-3 nonce gate provides replay backstop)
```

The §3 theorems below pin each conjunct.

---

## 3. Defense theorems

### Theorem T-1 (Env-var loading soundness)

**Statement.** If the operator sets `DETERM_RPC_AUTH_SECRET=K_hex` in their process environment and launches a Determ **client** (any CLI subcommand backed by `rpc_call` at `src/rpc/rpc.cpp:276–321`), the client picks up the secret via `std::getenv("DETERM_RPC_AUTH_SECRET")` at line 294 and uses it to compute the HMAC over each outgoing request. The value never appears in `argv`, never appears in any log emitted by `rpc_call`, and reduces to the OS-managed per-process env-var ACL.

**Proof.** Audit of `src/rpc/rpc.cpp:276–321` confirms:

1. **Single read site.** The only call to `std::getenv("DETERM_RPC_AUTH_SECRET")` in the client is at line 294. The result is assigned to a `const char*` local and immediately copied into `std::string effective_secret`. No global capture; no logging; no further env reads.
2. **No argv reflection.** The client does not parse argv inside `rpc_call`; the auth secret enters via the `auth_secret_hex` function parameter (explicitly passed by callers) or the env-var (lines 292–296). Neither path writes the secret back to argv.
3. **No log emission.** `rpc_call` has no logging statements between lines 292 and 309; the only emission is `req["auth"] = hmac_sha256_hex(...)` at line 305, which is the HMAC output, not the secret bytes themselves. The HMAC primitive is a PRF (per `RpcAuthHmacSoundness.md` T-5), so observing arbitrarily many HMACs reveals at most `q² / 2^256` distinguishing advantage about `K` — negligible.
4. **OS-managed env-var ACL is the underlying defense.** The env-var lives in the process's environment block, which the OS allocates in the process's virtual address space. Per-process env-var access is governed by the OS's process-memory access controls (Linux: `ptrace_scope` + `/proc/$pid/environ` per `proc(5)` + the `hidepid=2` mount option; Windows: `OpenProcess` with `PROCESS_VM_READ` + token ACLs). The Determ code does not relax these controls; the OS's per-process isolation IS the defense, and the env-var loading path inherits its strength entirely.

The reduction: env-var loading soundness ⇒ (OS per-process env-var ACL is effective AND `getenv` returns the value the operator set). Both are properties of the OS, not of Determ. Determ's correctness reduces to "we call `getenv` exactly once, on the right name, with no reflection paths."   ∎

**Critical scope note (cross-references F-1):** T-1 covers the **client** side only. The daemon does NOT read `DETERM_RPC_AUTH_SECRET` from the environment in the currently-shipped code — `main.cpp:1147` passes `cfg.rpc_auth_secret` (the config JSON value) directly to the `RpcServer` constructor. F-1 below details this asymmetry; F-2 recommends adding the daemon-side env-var fallback as a hardening.

### Theorem T-2 (Constant-time compare)

**Statement.** The auth comparison at `src/rpc/rpc.cpp:122–128` is constant-time per `RpcAuthHmacSoundness.md` T-3 + L-3. No timing side channel reveals per-byte information about `K`. The constant-time property is preserved across the loading-boundary: regardless of how `K` was loaded (env-var, config-file, future passphrase-decryption), the compare path is identical.

**Proof.** Cited from `RpcAuthHmacSoundness.md` T-3 (Constant-Time Comparison) and L-3 (`verify_auth` HMAC compare is constant-time). The compare logic is independent of the loading path: it operates on the in-memory `auth_secret_` byte vector after `hex_to_bytes` decoding in the constructor. The constructor's logic at `src/rpc/rpc.cpp:79–90` calls `hex_to_bytes(auth_secret_hex)` regardless of which source produced `auth_secret_hex`. The decode is itself constant-time per the `hex_to_bytes` helper (it does not vary timing on the value of the hex digits, only on the length — which is the documented 64 hex chars / 32 bytes for the recommended secret).

The post-load compare path is byte-for-byte the same across loading paths. T-2 inherits `RpcAuthHmacSoundness.md` T-3's audit conclusion unchanged.   ∎

### Theorem T-3 (Composition with HMAC)

**Statement.** Once `K` is loaded into `auth_secret_` (regardless of source), every authenticated request goes through the canonical HMAC pipeline: client computes `auth = hex(HMAC-SHA-256(K, method ‖ "|" ‖ params.dump()))`, server recomputes the expected HMAC, constant-time compares. The forgery probability per attempt reduces to `RpcAuthHmacSoundness.md` T-1's bound `≤ 2^-256 + q² / 2^256` under assumptions A1 (Ed25519 EUF-CMA — not directly invoked by HMAC but cited by composition with `submit_tx`'s Layer C signature gate; see `S001RpcAuthSoundness.md` §2.2) + A3 (HMAC-SHA-256 PRF security; equivalent to A_HMAC in `RpcAuthHmacSoundness.md` §2.1).

**Proof.** The HMAC primitive's soundness is independent of the loading boundary. The reduction is:

1. **Pre-condition (from T-1).** The env-var loading path placed the operator-set `K_hex` into the client's `effective_secret` string. The config-file loading path placed the operator-stored `rpc_auth_secret` into the daemon's `Config::rpc_auth_secret` field, then into `auth_secret_` via the constructor's `hex_to_bytes`.
2. **HMAC computation.** Client: `hmac_sha256_hex(key, canonical_for_hmac(method, params))` at `src/rpc/rpc.cpp:305–306`. Server: identical call at `src/rpc/rpc.cpp:119–120` inside `verify_auth`. Both invocations use OpenSSL's `HMAC(EVP_sha256(), ...)` per `RpcAuthHmacSoundness.md` §3.
3. **Verify.** Constant-time compare per T-2.
4. **Soundness.** By `RpcAuthHmacSoundness.md` T-1, the probability that an attacker without `K` produces a valid `(method*, params*, auth*)` triple is `≤ 2^-256 + q² / 2^256` per attempt — negligible for any operational `q`.

The composition: env-var-loaded `K` produces byte-identical `auth_secret_` to config-file-loaded `K` provided both paths produce the same `K_hex` (which they do; both are passed through `hex_to_bytes` with no transformation). The downstream HMAC + constant-time-compare pipeline is byte-identical across loading paths.

The single-call reduction: `T-3 ⇐ T-1 ∧ RpcAuthHmacSoundness.md T-1`. Loading + crypto compose without cross-layer interference.   ∎

### Theorem T-4 (No-fallback safety — actual shipped behavior)

**Statement.** When the env-var `DETERM_RPC_AUTH_SECRET` is missing AND no config-file entry for `rpc_auth_secret` exists, the daemon's `auth_secret_` field is empty. The shipped behavior is:

1. `verify_auth` at `src/rpc/rpc.cpp:113` returns `""` (pass) unconditionally on every request. **This is documented "silent no-auth" — the daemon accepts unauthenticated requests.**
2. The startup banner at `src/rpc/rpc.cpp:98–104` emits `[WARNING: external bind without HMAC auth — set rpc_auth_secret in config or enable rpc_localhost_only]` IFF `!localhost_only && auth_secret_.empty()`.
3. The default `rpc_localhost_only=true` per `src/node/node.cpp:75` (defensive default — legacy configs without the field get the secure default) restricts the no-auth surface to loopback. An attacker without same-host access cannot reach the RPC port; an attacker WITH same-host access is the cross-tenant adversary that S-001 Option 3 (HMAC) was meant to defend against — but it is not active here.

The shipped behavior is therefore (b)-like ("bind only to localhost") per the user-prompt's two-option taxonomy, NOT (a) ("reject all RPC requests"). The composition does NOT reject all requests when both loading paths produce empty; it falls through to the localhost-only escape hatch.

**Audit citation.** The audit pins the actual code paths:

- `src/rpc/rpc.cpp:112-113`: `if (auth_secret_.empty()) return ""; // Auth disabled, pass.`
- `src/rpc/rpc.cpp:98-104`: external-bind warning emit IFF `!localhost_only && auth_secret_.empty()`.
- `src/node/node.cpp:75`: `c.rpc_localhost_only = j.value("rpc_localhost_only", true);` — default `true`.

**Threat-model implications.** Under `A_outside` (no same-host access), the localhost-only default at step 3 closes the surface; the silent no-auth at step 1 is operationally a no-op against this adversary. Under `A_inside` (same-host, any-UID access), the localhost-only default does NOT close the surface; an attacker can connect to `127.0.0.1:rpc_port` and dispatch any state-mutating RPC method. **This is the S-001 cross-tenant adversary the HMAC layer was meant to defend against, but the daemon launched without the secret loaded.** The composition has degraded to S-001's pre-Option-3 closure (Option 1 alone).

**Finding (registered as F-3 below):** the "silent no-auth" behavior at line 113 is a documented operator-experience pitfall. A safer alternative would be to make the daemon refuse to start in external-bind mode without an auth secret — i.e., `if (!localhost_only && auth_secret_.empty()) { std::cerr << "[determ] FATAL: external bind requires rpc_auth_secret"; std::exit(1); }`. The current code emits only a warning. Cross-references `S001RpcAuthSoundness.md` §5's threat-model matrix row "State-mutation under no-auth", which surfaces the same observation.

**Proof.** Direct audit of the lines cited above. The shipped behavior at the three code sites is exactly as described. No proof obligation beyond the audit citation; the security property reduces to the operator's deployment policy choice (single-tenant + localhost-only vs multi-tenant + must-set-auth).   ∎

**Documented silent-no-auth bug status:** This is **not a code defect** — the localhost-only default at the config layer plus the external-bind warning at the startup banner jointly defend against the worst-case combination (external bind + no auth) by surfacing operator awareness. It IS however a UX/policy choice that an operator misconfiguring their daemon (e.g., setting `rpc_localhost_only=false` without also setting `rpc_auth_secret`) gets a warning-only path rather than a fatal-startup path. F-3 below promotes this from "documented choice" to "recommended hardening" alongside the v2.16 implementation.

### Theorem T-5 (Composition with input validation per `RpcInputValidationDefense.md`)

**Statement.** Even with valid HMAC auth (T-3 passed), the request must still pass the semantic-layer input validation gates per `RpcInputValidationDefense.md`. Each layer is independent: HMAC catches forgery, Layer B (JSON structural + S-018 hardened `from_json`) catches malformedness, Layer C (per-method semantic gates) catches out-of-contract content, FA-Apply-3 (NonceMonotonicity) catches replay. The layers compose in canonical order at `src/rpc/rpc.cpp:142–195`: rate-limit → parse → auth → dispatch → semantic-gate → mempool admit → apply.

**Proof.** Cited from `RpcInputValidationDefense.md` T-1 (Layered Defense Completeness) + `S001RpcAuthSoundness.md` T-1 (Auth-then-Validate Pipeline Soundness). The composition properties:

1. **Layer independence.** Each layer's accept/reject decision is independent of every other layer's. A request that passes the HMAC gate (T-3) but fails Layer B (S-018 `Transaction::from_json` rejects a missing `sig` field) gets `{"error": "S-018: sig"}` and no state mutation. A request that passes both HMAC and Layer B but fails Layer C (signature verification at `src/node/node.cpp:3163–3168`) gets `{"error": "signature invalid"}` and no mempool admit.
2. **Canonical ordering preserved.** The dispatch ordering at `src/rpc/rpc.cpp:172–187` is rate-limit → parse → auth → dispatch. The dispatch then calls into `Node::rpc_*` which applies Layer C's per-method semantic gates. Mempool admission triggers the apply-layer FA-Apply-3 nonce gate (`src/chain/chain.cpp:739`).
3. **Replay backstop.** If an attacker captures a valid `(method, params, auth)` triple and replays it, the HMAC layer accepts (T-3 has no nonce binding per `RpcAuthHmacSoundness.md` T-2's known-limitation finding), but the apply-layer FA-Apply-3 silently drops the second application (`tx.nonce != sender.next_nonce` → `continue` at `chain.cpp:739`). No double-spend.

The composition statement: env-var-loaded auth + HMAC verify + semantic-gate-validated request + apply-layer-nonce-checked tx ⇒ either accepted into chain state with correct effects, OR rejected at some gate with no state mutation. The end-to-end statement is the conjunction over all five gates (rate-limit + parse + auth + semantic + apply).   ∎

---

## 4. Adversary outcomes

| Adversary | Loading-path defense | Runtime defense | Residual risk | Mitigation |
|---|---|---|---|---|
| A-E1 (`/proc/$pid/environ` read) | OS `hidepid=2` mount + per-UID ACL on `/proc` | None at runtime — attacker now has `K`, equivalent to `A_inside` | Promotes to `A_inside`: attacker can forge any RPC request; `S001RpcAuthSoundness.md` T-1 (`A_inside` arm) reduces to input-validation gates (Layers B+C) + apply-layer (FA-Apply-3) for residual safety | Linux: mount `/proc` with `hidepid=2,gid=<determ-admin-group>`. Document in operator deployment checklist (F-1 of this document; cross-references `RpcAuthHmacSoundness.md` F-2). |
| A-E2 (env-var via shell command line, visible in `ps`) | None at OS layer; operator hygiene | Same as A-E1 — promotes to `A_inside` | Same as A-E1 | Operator pattern: `export DETERM_RPC_AUTH_SECRET="$(cat ~/.config/determ/auth_secret)"` from a `chmod 0600` file, not as a literal in shell commands. Or use `read -s` prompt. Or use a secrets manager. F-3 below recommends documenting this pattern in `CLI-REFERENCE.md` §17. |
| A-E3 (shell history file persistence) | None at OS layer; operator hygiene | Same as A-E1 — promotes to `A_inside` | Captures the value at the time of setting; rotation closes forward but not backward | Operator pattern: `read -s DETERM_RPC_AUTH_SECRET` interactive prompt followed by manual `export`. Or `HISTCONTROL=ignorespace` + prefix the command with a space. Documented in F-3 below. |
| A-E4 (config-file plaintext at-rest) | Filesystem `chmod 0600` + per-user ACL | Same as A-E1 — promotes to `A_inside` | Existing `RpcAuthHmacSoundness.md` F-1; medium-term mitigation = v2.17 / S-004 passphrase-encrypted keyfile pattern applied to `rpc_auth_secret` | Short-term: doc `chmod 0600` in deployment checklist. Medium-term: passphrase-encrypted secret loading via the same `crypto::load_passphrase_keyfile` machinery shipped for the node Ed25519 key. F-2 below tracks the daemon-side env-var fallback as a paired hardening (operator could then export `DETERM_RPC_AUTH_SECRET` to bypass the config-file at-rest path). |
| A-E5 (config-file alternative) | Same as A-E4 | Same as A-E4 | Same as A-E4 | Same as A-E4 |
| `A_outside` (no secret access, runtime forgery attempt) | N/A (loading-side adversary cannot affect this) | HMAC-SHA-256 PRF security per `RpcAuthHmacSoundness.md` T-1: forgery probability `≤ 2^-256 + q² / 2^256` per attempt | Negligible per any operational `Q · q` | None required. S-014 rate-limiter (per `S014RateLimiterSoundness.md`) further caps the attempt rate at `≤ 100/s` per peer-IP under the web profile default. |
| `A_outside` + replay of legitimate `auth` field | Captured in transit (eavesdropping on the wire) | Apply-layer FA-Apply-3 nonce gate at `src/chain/chain.cpp:739` silently drops the second application | None — replay is no-op'd | None required. T-2 in `RpcAuthHmacSoundness.md` flagged HMAC's no-nonce-binding as a known limitation; FA-Apply-3 provides the backstop. |
| `A_outside` + denial-of-service on the verify path | S-014 rate-limiter | Bounded per peer-IP at the rate-limit budget per window | Aggregate from N coordinated IPs scales linearly; even at N=10^6 the per-account effects are still bounded by FA-Apply-3 + the apply-layer's per-block tx capacity | F-1 of `RpcInputValidationDefense.md` (per-RPC-method body cap, future hardening). |

---

## 5. Findings

### F-1 (Daemon-side env-var loading asymmetry — operator UX gap)

**Severity:** Low (functional gap; not a security regression because the localhost-only default per S-001 Option 1 + the external-bind warning per `src/rpc/rpc.cpp:98–104` jointly defend against the worst-case misconfiguration).

**Description.** `DETERM_RPC_AUTH_SECRET` is consumed by the client only (`src/rpc/rpc.cpp:294`). The daemon side loads `rpc_auth_secret` exclusively from the config JSON via `Config::from_json` at `src/node/node.cpp:68`. An operator who exports `DETERM_RPC_AUTH_SECRET` expecting the daemon to inherit it is silently misled — the daemon launches with `auth_secret_.empty() == true` and accepts unauthenticated requests on the configured bind interface.

The documentation in `SECURITY.md` §S-001 (paragraph: "Client side (CLI + `rpc_call`): if `DETERM_RPC_AUTH_SECRET` env var is set, every outgoing request automatically gets the auth field computed from the env-var secret") correctly scopes the env var to the client side, but is easy to miss-read as "both sides honor the env var" given the symmetric usage of the same env-var name in adjacent literature. `CLI-REFERENCE.md` §17 has the same wording.

**Recommended mitigation:** add an explicit "Note: this env var is consumed by the CLI / `rpc_call` only. The daemon reads `rpc_auth_secret` from the config JSON; see F-2 below for the recommended daemon-side fallback." paragraph in both `SECURITY.md` §S-001 and `CLI-REFERENCE.md` §17. Document the asymmetry surface in this proof file's §1.2.

**Effort:** ~10 LOC docs. Estimated 0.25d.

### F-2 (Add daemon-side env-var fallback, symmetric with the client)

**Severity:** Low (defense-in-depth; closes F-1 at the operator-UX layer rather than the docs layer).

**Description.** Add a fallback in `main.cpp` (around line 1130, between `Config::load` and `Node` construction): if `cfg.rpc_auth_secret.empty()` AND `std::getenv("DETERM_RPC_AUTH_SECRET")` is non-empty, populate `cfg.rpc_auth_secret` from the env var before constructing `RpcServer`. This mirrors the client-side semantics at `src/rpc/rpc.cpp:294`; the operator experience becomes symmetric (export the env var, both sides honor it).

The medium-term mitigation path benefits compound: the operator can avoid the A-E4 config-file at-rest persistence path entirely by exporting the env var and leaving `rpc_auth_secret=""` in the config. The threat surface partition shifts from filesystem (A-E4) to env-var (A-E1..A-E3), which are typically narrower in deployment (env-var lives only in the running process's memory; the config file persists across reboots).

**Recommended mitigation:** ~5 LOC in `main.cpp` between lines 1130 and 1145:

```cpp
if (cfg.rpc_auth_secret.empty()) {
    const char* env = std::getenv("DETERM_RPC_AUTH_SECRET");
    if (env && *env) cfg.rpc_auth_secret = env;
}
```

Plus a regression test in `tools/test_rpc_hmac_auth_env.sh` exercising the env-var-only loading path. Plus a doc update in `SECURITY.md` §S-001 + `CLI-REFERENCE.md` §17 + this proof's T-1 statement (to drop the "client side only" scope note).

**Critical constraint:** Operator must verify `Config::to_json` NEVER writes `rpc_auth_secret` to a re-saved config file when the secret originated from the env var. Today, `Config::to_json` at `src/node/node.cpp:30` always serializes the field; the fallback would need to either (a) carry an in-memory-only flag preventing re-save, or (b) defer the env-var read to inside `RpcServer` rather than mutating `cfg`. Option (b) is the cleaner refactor and aligns with the client-side pattern at `src/rpc/rpc.cpp:294` (the secret never enters the Config struct).

**Effort:** ~20 LOC code + ~50 LOC test + docs. Estimated 0.5d.

### F-3 (Operator shell-history risk — recommend `read -s` prompt or env-var-file with `chmod 600`)

**Severity:** Low (operator-hygiene; not a Determ-code defect).

**Description.** Per A-E3, operators who set `DETERM_RPC_AUTH_SECRET` interactively in a shell session may persist the secret in `~/.bash_history` / `~/.zsh_history` indefinitely. The operator's mental model is "I exported it for this session", but the history file outlives the session.

**Recommended mitigation:** document the safer patterns in `CLI-REFERENCE.md` §17:

1. **Interactive prompt pattern:**
   ```sh
   read -s -p "Determ RPC auth secret: " DETERM_RPC_AUTH_SECRET
   export DETERM_RPC_AUTH_SECRET
   ```
   The `read -s` prompt is not recorded in history; the `export` of an existing variable is recorded but reveals no value.

2. **Env-var-file pattern:**
   ```sh
   # ~/.config/determ/env_secret  (chmod 0600)
   export DETERM_RPC_AUTH_SECRET="DEADBEEF..."
   ```
   The operator sources this file at session start: `source ~/.config/determ/env_secret`. The history records the `source` command, not the value. The file itself is `chmod 0600` (owned by the determ-admin user).

3. **Inline-from-file pattern** (avoids exposing the file to the shell at all):
   ```sh
   export DETERM_RPC_AUTH_SECRET="$(cat ~/.config/determ/auth_secret)"
   ```
   The history records the `$(cat ...)` substitution, not the value. The file remains `chmod 0600`.

4. **`HISTCONTROL=ignorespace` + prefix space:** for one-off sessions where the operator chooses not to persist the secret to a file:
   ```sh
   $ export HISTCONTROL=ignorespace
   $  export DETERM_RPC_AUTH_SECRET="DEADBEEF..."   # note leading space
   ```
   The space-prefixed command is not recorded.

**Effort:** ~30 LOC docs in `CLI-REFERENCE.md` §17 (new subsection "Recommended env-var hygiene patterns"). Estimated 0.25d.

### F-4 (No-fallback safety hardening — promote silent no-auth to fatal startup error in external-bind mode)

**Severity:** Low to Medium (defense-in-depth; operationally surface-exposing).

**Description.** Per T-4, when `auth_secret_.empty() && !localhost_only`, the daemon launches with a warning to stderr and accepts unauthenticated external requests. A safer alternative: refuse to start under this combination, requiring the operator to either set the auth secret OR explicitly enable localhost-only.

**Recommended mitigation:** in `main.cpp` (around line 1145, before `RpcServer` construction):

```cpp
if (!cfg.rpc_localhost_only && cfg.rpc_auth_secret.empty()) {
    std::cerr << "[determ] FATAL: external bind (rpc_localhost_only=false) "
              << "requires rpc_auth_secret to be set. Either set the secret "
              << "or enable rpc_localhost_only=true.\n";
    return 1;
}
```

Plus a regression test in `tools/test_rpc_external_bind_requires_auth.sh` confirming the fatal-startup behavior under the misconfig.

**Effort:** ~10 LOC code + ~30 LOC test + docs. Estimated 0.25d.

The five findings are advisory; none invalidates T-1..T-5. They are surfaced for completeness so an external auditor can confirm the scope of the composition argument and so an operator deploying Determ can match their deployment policy to the actual shipped behavior.

---

## 6. References

### Specifications + standards

- **RFC 2104** (Krawczyk, Bellare, Canetti, Feb 1997) — "HMAC: Keyed-Hashing for Message Authentication." Normative reference for the HMAC construction underpinning T-3.
- **RFC 8032** (Josefsson, Liusvaara, Jan 2017) — "Edwards-Curve Digital Signature Algorithm (EdDSA)." Normative reference for Ed25519 (A1), invoked by the composition with `submit_tx`'s Layer C signature gate per `S001RpcAuthSoundness.md` §2.2.
- **FIPS 198-1** (NIST, Jul 2008) — "The Keyed-Hash Message Authentication Code (HMAC)." NIST normative for HMAC-SHA-256.
- **NIST FIPS 180-4** — Secure Hash Standard, SHA-256 specification.
- **POSIX.1-2017 `execve(2)` + `environ(7)`** — POSIX-normative behavior of env-var inheritance across `execve` and process-environment access via `getenv(3)`.
- **`proc(5)`** (Linux man-pages) — `/proc/$pid/environ` semantics + the `hidepid=2` mount option (Linux 3.3+).

### Cryptographic literature

- **Bellare, Canetti, Krawczyk** (CRYPTO 1996) — "Keying Hash Functions for Message Authentication." Original HMAC paper; PRF security under the compression-function collision-resistance assumption. Invoked by T-3 via `RpcAuthHmacSoundness.md` §2.1.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security Without Collision-Resistance." Tighter PRF reduction; the standard-model bound this proof uses.
- **Bellare, Goldwasser, Micali** (J.ACM 1986) — "How to construct random functions." PRF-to-MAC reduction underlying `RpcAuthHmacSoundness.md` L-1, invoked here transitively via T-3.
- **Bellare, Rogaway** — "Introduction to Modern Cryptography" §5.3 — textbook treatment of SHA family collision-resistance + HMAC PRF.

### Determ-internal references

#### Companion proofs (per-layer soundness)

- **`docs/proofs/S001RpcAuthSoundness.md`** — R27A3 / S-001 composition; T-1 (Auth-then-Validate Pipeline Soundness), T-2 (Replay Defense Composition), T-3 (Authentication Bypass Surfaces — Exhaustive), T-4 (Constant-Time Verify Audit Under Composition), T-5 (Secret Lifecycle Composition). This document extends with the loading-boundary arm.
- **`docs/proofs/RpcAuthHmacSoundness.md`** — R20-ish HMAC primitive soundness; T-1 (auth soundness, the `≤ 2^-256 + q²/2^256` bound), T-2 (replay analysis — known limitation), T-3 (constant-time compare audit), T-4 (secret confidentiality at RPC surface), T-5 (HMAC PRF q²/2^256 q-query bound). Findings F-1 (configuration-surface plaintext at-rest — referenced here as A-E4), F-2 (env-var leakage surface — referenced here as A-E1..A-E3), F-3 (compiler-attribute constant-time hardening).
- **`docs/proofs/RpcInputValidationDefense.md`** — R26A7 five-layer defense; T-1..T-5 composed in T-5 of this document.
- **`docs/proofs/JsonValidationSoundness.md`** — S-018 closure; the structural-validation portion of Layer B (composed in T-5 here).
- **`docs/proofs/NonceMonotonicity.md`** — FA-Apply-3 apply-layer nonce gate; the replay-defense backstop composed in T-5 here.
- **`docs/proofs/S014RateLimiterSoundness.md`** — S-014 rate-limiter closure; the pre-gate that defeats online HMAC brute-force at the rate budget.
- **`docs/proofs/S027InfoLeakage.md`** — Info-leakage closure on the secret-confidentiality surface; the operator-log audit cross-referenced under §1.3 step-4 of this document.
- **`docs/proofs/F2ApplyComposition.md`** — F2-naming-convention sibling; this document follows the same F2-* naming pattern for composed flows.
- **`docs/proofs/Preliminaries.md`** — F0 notation + assumptions; A2 / H1 (SHA-256 collision resistance) referenced under T-3 via the HMAC reduction; A3 (HMAC-SHA-256 PRF) named explicitly.

#### Implementation sites

- **`src/rpc/rpc.cpp:60–70`** — `hmac_sha256_hex` OpenSSL HMAC primitive wrapper.
- **`src/rpc/rpc.cpp:79–90`** — `RpcServer` constructor; loads `auth_secret_` from the `auth_secret_hex` parameter via `hex_to_bytes`.
- **`src/rpc/rpc.cpp:95–104`** — Startup banner; length-only secret emission + external-bind warning emit.
- **`src/rpc/rpc.cpp:112–129`** — `verify_auth` (T-4 audit's primary object).
- **`src/rpc/rpc.cpp:142–195`** — `handle_session` (T-5 canonical control flow at the heart of the layer ordering).
- **`src/rpc/rpc.cpp:172`** — Layer D rate-limit consume call.
- **`src/rpc/rpc.cpp:176`** — Layer B `json::parse` call.
- **`src/rpc/rpc.cpp:179`** — Layer E `verify_auth` call (auth gate).
- **`src/rpc/rpc.cpp:184`** — Dispatch invocation (post-auth).
- **`src/rpc/rpc.cpp:276–321`** — Client-side `rpc_call`; lines 287–296 carry the env-var fallback the T-1 statement covers.
- **`src/rpc/rpc.cpp:294`** — The only `std::getenv("DETERM_RPC_AUTH_SECRET")` call site in the codebase; T-1 audit pin.
- **`src/node/node.cpp:23–60`** — `Config::to_json`; line 30 is the plaintext-at-rest persistence path (A-E4).
- **`src/node/node.cpp:62–108`** — `Config::from_json`; line 68 reads `rpc_auth_secret` from the config JSON (the actually-shipped daemon loading path).
- **`src/node/node.cpp:75`** — `rpc_localhost_only` default-to-true (defensive default per S-001 Option 1).
- **`src/node/node.cpp:110–114`** — `Config::load`; opens the config file and routes through `from_json`.
- **`src/node/node.cpp:116–121`** — `Config::save`; writes the config (including `rpc_auth_secret`) to disk.
- **`src/main.cpp:1130–1149`** — Daemon startup: `Config::load` → `Node` construction → `RpcServer` construction passing `cfg.rpc_auth_secret` (NOT the env var; F-1's audit pin).
- **`src/chain/chain.cpp:739`** — Apply-layer FA-Apply-3 nonce gate; T-5 replay-defense backstop.

#### SECURITY.md + spec docs

- **`docs/SECURITY.md` §S-001** — Closure narrative for the v2.16 RPC HMAC auth; the operator-experience surface this proof formalizes. Threat-model coverage matrix (cross-tenant on the same host: closed via Option 3; replay: known limitation tracked in T-2 of `RpcAuthHmacSoundness.md` and T-5 of this document).
- **`docs/SECURITY.md` §S-004** — Passphrase-encrypted keyfile closure; cross-referenced under F-2's medium-term mitigation path.
- **`docs/SECURITY.md` §S-014** — Rate-limiter closure; cited in the §4 adversary-outcomes table.
- **`docs/SECURITY.md` §S-018** — JSON validation closure; the input-validation arm composed in T-5.
- **`docs/SECURITY.md` §S-027** — Info-leakage closure; the operator-log audit composed under §1.3 step 4.
- **`docs/PROTOCOL.md` §10.2** — Wire-level documentation of the `auth` field requirement.
- **`docs/CLI-REFERENCE.md` §17** — Operator-facing documentation of `rpc_auth_secret` + the env-var name. F-1 + F-3 of this proof recommend extending §17 with the env-var asymmetry note + the shell-hygiene patterns.

#### Tests

- **`tools/test_rpc_hmac_auth.sh`** — 5-assertion regression for the HMAC auth scheme (Layer E / `RpcAuthHmacSoundness.md`).
- **`tools/test_rpc_localhost_only.sh`** — Layer E + localhost-bind default regression (3 assertions; composed with T-4's localhost-only escape hatch).
- **`tools/test_rpc_rate_limit.sh`** — Layer D RPC integration (4 assertions; composed in §4's adversary-outcomes table).
- **`tools/test_s018_json_validation.sh`** — Layer B (S-018) regression (10 assertions; composed in T-5).
- **`tools/test_anon_address_case.sh`** — Layer C (S-028) regression (6 assertions; composed in T-5).
- **`tools/test_tx_replay_protection.sh`** — FA-Apply-3 backstop regression (composed in T-5's replay arm).

F-2 + F-4 register two new test recommendations: `tools/test_rpc_hmac_auth_env.sh` (env-var loading path end-to-end) and `tools/test_rpc_external_bind_requires_auth.sh` (no-fallback-safety hardening regression). Neither exists yet; both are chip-task candidates surfaced for the next operator-hardening sweep.
