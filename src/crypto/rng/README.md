# src/crypto/rng — OS-entropy source (C99)

Per-module provenance + audit README required by CRYPTO-C99-SPEC.md §3.16.
Part of the libsodium-free C99 crypto stack; shipped with the **§3.15**
consensus-path migration off OpenSSL (replaces `RAND_bytes` at the daemon's
entropy sites).

## 1. What this module implements

One entry point (`include/determ/crypto/rng/rng.h`):

| Function | Role |
|---|---|
| `determ_rng_bytes(buf, n)` | fill `buf[0..n)` from the OS CSPRNG; 0 on success, −1 on failure (`buf` then undefined and MUST NOT be used); `n == 0` is a no-op success |

This is the one primitive the from-scratch stack cannot synthesize: every
other module in `src/crypto/` is a deterministic function of its inputs and
can be written and cross-validated from the published standard, but fresh
unpredictable secrets can only come from outside the process. The module is
therefore deliberately a **thin shim over the operating system's CSPRNG** —
no userspace RNG state, no seeding logic, no DRBG:

- **Windows:** `BCryptGenRandom(NULL, …, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`
  (CNG system-preferred RNG). `BCryptGenRandom` takes a `ULONG`, so requests
  are chunked at 2^31−1 bytes for the theoretical `n > 2^31−1` case.
- **Linux:** `getrandom(2)` with flags 0 — blocks only until the kernel pool
  is initialized once at boot, never returns weak bytes. `EINTR` is retried;
  any other error (e.g. `ENOSYS` on pre-3.17 kernels) falls through to the
  `/dev/urandom` path for the remaining bytes.
- **Other POSIX:** `/dev/urandom` read loop (`EINTR` retried; `open` failure,
  read error, or EOF → −1).

**Fail-fatal contract:** if the OS source fails, the call returns −1 and the
caller must treat it as fatal — there is no fallback to anything weaker
(no time/PID seeding, no userspace pool). An all-zero or partial secret must
never be used. In-tree consumers all enforce this:

- `src/crypto/keys.cpp` `generate_node_key` — the 32-byte RFC 8032 Ed25519
  seed (node identity); throws on failure.
- `src/node/node.cpp` — the per-round `dh_secret` behind the Phase-1
  commit-reveal; throws on failure (a predictable secret breaks the
  selective-abort defense).
- `src/main.cpp` genesis builder — fresh `shard_address_salt` when the input
  doesn't supply one; aborts genesis creation on failure.

## 2. Provenance + construction

Written from scratch against the platform API documentation (MSDN
`BCryptGenRandom`, `getrandom(2)` / `urandom(4)` man pages); no vendored
code, no upstream to version-pin — the pins are the OS interfaces
themselves. License posture: **public domain**, matching the family. Build
wiring: `CMakeLists.txt` adds `rng.c` to `determ-crypto-c99` and links
`bcrypt` PUBLIC on Windows.

The design choice IS the construction: kernel CSPRNGs (CNG, the Linux
`random.c` pool) are the best-maintained entropy sources on each platform,
and any userspace layer on top would add attack surface (state to seed,
fork-safety, zeroization) without adding entropy. So the module adds none.

## 3. Validation evidence

**`determ test-rng-c99`** (shipped with this module, same round) is the
direct smoke gate: contract edges (n==0 no-op, draws succeed), all-zero
output, repeated consecutive draws, a constant 256-byte window inside a
64 KiB chunked fill, and coarse byte-value uniformity bounds — catastrophic-
breakage detection, not a randomness proof. Additional posture:

- **Exercised indirectly on every keygen/sign path**: `test-ed25519` calls
  `generate_node_key` directly (fresh keys for its sign/verify checks), the
  cluster suite generates node identities on every boot, and every
  multi-node round drives the `dh_secret` site — a failing or stuck source
  turns those gates red. (`test-ed25519-vectors` is NOT such a gate: it
  builds its keys from the fixed RFC 8032 seeds and never draws entropy.)
- The fail-fatal contract at all three call sites is enforced by code review
  (each site checks the return and throws/aborts, per §1).
- Not yet covered by `docs/proofs/C99CryptoStackAudit.md` — the audit
  predates this module; a source review pass is the remaining owed item.

Note the intrinsic limit: statistical tests cannot distinguish a CSPRNG from
a backdoored PRNG. The real assurance is the construction — a direct,
auditable-in-one-screen call into the platform CSPRNG.

## 4. Constant-time / hygiene posture

- No secrets flow **in**: the output buffer is the only secret-bearing
  object, and it is caller-owned — callers must scrub it
  (`determ_secure_zero`) when the derived secret's lifetime ends. The module
  holds no state to zeroize.
- Control flow depends only on the public length `n` and OS return codes;
  there are no secret-dependent branches or table lookups.
- On failure the buffer may hold partial output; the header contract marks
  the contents undefined, which is why callers must fail fatally rather than
  consume them.

## 5. Known limitations / future work

- **No DRBG layer** — direct OS calls per request; a userspace SP 800-90A
  DRBG (buffering, prediction-resistance reseed) is deliberately out of
  scope (see §2). Consequence: per-call syscall cost, irrelevant at the
  current call frequency (keygen + one 32-byte draw per round + a one-time
  genesis salt).
- **Not CMVP/FIPS-validated**: the underlying CNG RNG is FIPS-validated on
  Windows, but this shim and the stack around it carry no CMVP certificate
  — same posture as every module in the C99 stack.
- **Windows chunking at 2^31−1** bytes is theoretical dead code at current
  usage (largest request is 32 bytes) and has no direct test.
- **Generic-POSIX `n == 0` corner**: on the non-Windows, non-Linux
  `/dev/urandom` path, an `n == 0` call still opens the device (and returns
  −1 if it cannot) — a deviation from the header's "no-op success" on that
  theoretical platform. Windows and Linux, the two verified toolchains,
  return 0 with no OS call.
- **Audit pass owed** — `determ test-rng-c99` shipped (§3), but the module
  is not yet covered by `docs/proofs/C99CryptoStackAudit.md` (which predates
  it); a source-review pass is the open item.
