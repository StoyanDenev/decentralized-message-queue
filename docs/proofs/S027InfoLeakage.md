# S027InfoLeakage — no-secret-in-log audit + log_quiet composition + RPC auth env-var pattern (S-027 closure)

This document gives the meta-pattern proof for S-027: information leakage through node logs (stdout, stderr, log files captured by `journald` or operator-controlled redirection). Pre-closure, an operator running `determ start` at default verbosity could not, from inspection of the log stream alone, demonstrate that no secret material (private key bytes, freshly-revealed `dh_secret` bytes, RPC HMAC auth tokens, plaintext wallet passphrases, keyfile recovery envelopes) ever reaches a logged line. The closure consists of two parts: (a) an exhaustive audit pass over every `std::cout` / `std::cerr` call site in `src/node/*.cpp`, `src/rpc/*.cpp`, `src/net/*.cpp`, `src/chain/*.cpp` confirming that the logged content is restricted to chain-public state, peer transport addresses, and protocol-timing markers; and (b) a new `Config::log_quiet` flag (default `false`) that operators set to suppress the chatty per-block / per-connection / per-bundle diagnostic lines while leaving WARN- and ERROR-class diagnostics surfacing. The proof complements `RpcAuthHmacSoundness.md` T-4 (secret confidentiality at the RPC surface) and `S004KeyfileAtRest.md` (passphrase confidentiality at the keyfile surface) by establishing the orthogonal log-surface confidentiality property.

The proof is structural rather than novel: each per-call-site audit reduces to "the format-string argument list contains only chain-public values" by direct inspection of the source. The contribution here is to enumerate the audit comprehensively (so a future contributor adding a log statement can verify in seconds whether they have broken the invariant), document the methodology so it is reproducible, articulate the composition with the RPC HMAC env-var pattern (`DETERM_RPC_AUTH_SECRET` is the operator's canonical secret-delivery channel and is itself not visible in process-listing surfaces), and surface findings that no single per-line audit catches in isolation (third-party library log statements, crash-dump exposure, log-file ACL hygiene).

**Companion documents:** `docs/SECURITY.md` §S-027 (closure narrative this proof formalizes); `docs/proofs/RpcAuthHmacSoundness.md` (T-4 secret confidentiality at the RPC surface — composed in T-5 here); `docs/proofs/S004KeyfileAtRest.md` (passphrase + recovery-envelope confidentiality — composed in §5 here); `docs/proofs/S001RpcAuthSoundness.md` (RPC auth composition theorem — referenced in T-5 here); `tools/test_log_quiet.sh` (the `log_quiet=false` vs `log_quiet=true` differential regression — 3 assertions covering verbose emits per-block lines, quiet suppresses them, quiet still surfaces startup diagnostics).

**Status:** Mitigated (Low/Op). Audit pass complete; `Config::log_quiet` flag shipped (`include/determ/node/node.hpp:158`); regression test in `tools/test_log_quiet.sh`. SECURITY.md classifies S-027 as Mitigated. Effort remaining: zero for the code closure; operator-side discipline (log-file permissions, log-rotation, public-forum redaction) is documented in §6 below as the orthogonal operations-scope concern.

---

## 1. Introduction

### 1.1 The pre-closure threat model

Pre-S-027, the Determ node binary emitted a heterogeneous mix of diagnostic lines covering startup, peer-handshake, block-accept, sync-progress, equivocation-detection, beacon-header verification, snapshot-restore, and error paths. Each line was written via `std::cout << ...` (informational) or `std::cerr << ...` (warning/error). No log-level filtering was in place: every call site emitted unconditionally, except for a handful of code paths gated by per-feature toggles (e.g. snapshot-bootstrap only emits if `cfg_.snapshot_path` is non-empty and the file exists).

The S-027 finding observed that this default-verbose posture exposes the operator to three orthogonal adversary scenarios:

1. **Local filesystem read.** An attacker (e.g. a co-tenant on a shared host, a misconfigured backup process, an unprivileged user who can read `journalctl -u determ` because the unit file was installed without `LogsDirectoryMode=0700`) could harvest the running log file. If any secret material were ever written to the log, this attack class would extract it. The pre-closure question: was any secret material written?

2. **Log-shipping pipeline egress.** Production operators frequently ship logs to a third-party aggregator (e.g. Datadog, Splunk, ELK, Loki). The aggregator's storage perimeter is necessarily wider than the operator's host's perimeter — multiple log sources, multiple tenancy levels at the aggregator, potentially log-as-data analytics surfaces (regex extractions over historical logs) that future-self has not anticipated. Any secret in a log line that passes the aggregator becomes a secret stored at the aggregator. Even if the aggregator is trusted, the operator loses fine-grained control over secret lifecycle.

3. **Operator-initiated leakage via paste.** Operators debugging an issue often paste log snippets into chat (Slack, Discord, GitHub issues, vendor support tickets, pair-programming streams). The pasted snippet might span hundreds of lines; the operator may not visually scan every byte. If any secret-bearing line is in the snippet, it is now visible to every reader of the paste — many of whom are not the operator's trust boundary.

In addition to these three scenarios, a fourth structural risk exists:

4. **Crash-dump or assertion-failure surface.** If the node crashes via an unhandled exception or assertion failure, the OS may emit a coredump that includes process memory at the time of the crash. The coredump's contents are outside the log-surface scope (they are a kernel-controlled artifact), but the operator should be aware that secrets in memory at crash time are exposed via this surface.

The S-027 closure addresses (1)–(3) by removing the secret material from the log stream at the source; (4) is addressed by operator-side hardening (`ulimit -c 0` to suppress coredumps in production; `sysctl kernel.core_pattern` to direct dumps to a permissioned location), not by the chain code.

### 1.2 The two-part closure

The closure has two structural components:

1. **Audit pass.** Every `std::cout` / `std::cerr` call site in the chain's production source tree was enumerated and inspected. For each call, the audit confirmed that the format-string argument list is restricted to one of these chain-public categories:

   - **Block-level public state:** `block.index`, `block.creators.size()`, `to_hex(block.compute_hash())`, transaction counts, block-acceptance markers.
   - **Peer transport addresses:** `peer->address()` (resolves to the wire IP + port pair, e.g. `127.0.0.1:7842`). This is operationally visible to any peer that this node connects to via TCP `SYN`; it is not secret.
   - **Protocol-timing markers:** "phase1 timeout", "phase2 timeout", "abort quorum (round N)", "caught up to height N". These are observable from the wire by any well-positioned peer; they are not secret.
   - **Configuration round-trip readback:** "M=3 K=3 subsidy=10 mode=strong". Operator-supplied via `genesis.json`; not secret (in fact published on-chain as part of the genesis block).
   - **Network-error diagnostics:** "[gossip] connect to host:port failed: <asio-error-message>", "[node] snapshot restore failed: <exception.what()>". The exception messages are chain-internal diagnostics (asio errors are wire-level only; chain restore errors enumerate the failed snapshot field name, not the field value).

   The audit did NOT find any of these forbidden categories:

   - **Private-key material:** `priv_seed` (the 32-byte Ed25519 seed loaded from the operator's keyfile), `ed_sk` (any intermediate 64-byte Ed25519 secret-key form).
   - **Phase-2 reveal material:** `dh_secret` (the 32-byte freshly-generated DH secret revealed in `BlockSigMsg`). NOTE: dh_secrets are technically chain-public AFTER reveal — they are gossiped as part of the consensus protocol — but the audit confirms that they are not logged regardless, because logging them would amount to publishing per-block randomness in two places (consensus message + node log), creating an asymmetric observability surface that complicates fair-witness analysis.
   - **RPC auth token:** `rpc_auth_secret` (the operator's HMAC secret). Cited only by `.size()` at the startup banner; never by value.
   - **Wallet passphrase:** the `DETERM_PASSPHRASE` env var or stdin-read passphrase used to decrypt a passphrase-encrypted keyfile per S-004.
   - **Recovery envelope:** the Shamir recovery shares or backup envelopes produced by the `determ-wallet` companion binary. Note: the wallet CLI itself prints these to stdout by design (the user is explicitly asking for their own recovery secrets); the audit excludes wallet-CLI stdout from the no-secret-in-log invariant because the user is the audience of their own output.

2. **`Config::log_quiet` flag.** A new operator-controllable boolean was added to `Config` at `include/determ/node/node.hpp:158`. When `true`, the chatty per-block / per-bundle / per-connection diagnostic lines are suppressed; the WARN/ERROR-class lines (which are by definition rare and structural) continue to surface. The default `false` preserves the pre-S-027 behavior so the upgrade is opt-in: existing operators do not see a sudden change in their log volume.

The flag is propagated from `Node::cfg_.log_quiet` to `GossipNet::log_quiet_` at construction (`src/node/node.cpp:531` calls `gossip_.set_log_quiet(cfg_.log_quiet)`). Per-line gates check `if (!cfg_.log_quiet)` (in `node.cpp`) or `if (!log_quiet_)` (in `gossip.cpp`) before emitting. Lines that are structural (startup banner, ERROR/WARN diagnostics, equivocation detection, abort-quorum announcement, beacon-header verification, snapshot-restore confirmation) are NOT gated — they continue to surface regardless of `log_quiet`.

### 1.3 Why this composition document

Each per-file audit is mechanical. The composition exists for four reasons:

1. **Single-statement end-to-end posture.** An auditor asking "does the Determ node leak secrets via its logs?" reads this document and confirms the joint posture, not three files.

2. **Reproducible methodology.** The Grep-based audit pattern (`grep -rn 'std::cout\|std::cerr' src/node/ src/rpc/ src/net/ src/chain/`) is documented in §4, so a future contributor adding a log statement can run it themselves and confirm that their new line is in scope.

3. **Composition with RPC auth (S-001).** Even when `log_quiet=false`, the RPC auth secret is delivered via the `DETERM_RPC_AUTH_SECRET` environment variable (or via the `auth_secret_hex` argument to `rpc_call`, used by the `determ-wallet` CLI). The env-var pattern composes with S-027: the secret is never visible in the process command-line (`ps auxe` reveals env vars to the same UID but not to other users on a `hidepid=2`-mounted `/proc`), never in shell history (because the operator writes the env var to a sourced shell file rather than typing it on the command line), and never in `--help` output. This composition closes a residual gap that S-001 alone cannot address: even a perfect HMAC layer leaks the secret if the secret-delivery channel is the command line.

4. **Cross-cutting findings.** Observations that are visible only at the composition layer: third-party library log statements (libsodium, OpenSSL) are not audited by this document but are inspected and confirmed to not log secrets; crash-dump exposure is outside the audit scope but is surfaced as F-2; operator-side log-file hygiene is surfaced as F-3 with concrete recommendations.

---

## 2. Theorems T-1..T-5

### Theorem T-1 (No-Secret-In-Log invariant)

Let `S` denote the set of secret-material categories whose leakage would compromise the operator: `S = {priv_seed, ed_sk, dh_secret_pre_reveal, rpc_auth_secret, wallet_passphrase, recovery_envelope}`.

Let `L` denote the set of strings ever emitted to `std::cout` or `std::cerr` by any function in `src/node/*.cpp`, `src/rpc/*.cpp`, `src/net/*.cpp`, or `src/chain/*.cpp` during normal operation of a `Node`.

**Claim:** For every secret category `s ∈ S` and every emitted line `l ∈ L`, the byte-string of `s`'s current value does not appear as a substring of `l`.

**Proof:** By structural enumeration. §4 below lists every call site by file and line number, and for each call site documents the format-string argument list. Inspection of each argument list confirms that no argument is a byte-string-typed representation of any secret category. The enumeration is exhaustive (`grep -rn 'std::cout\|std::cerr' src/node/ src/rpc/ src/net/ src/chain/` returns the complete set of call sites that the audit covers).

Two specific sub-claims warrant explicit citation:

- **Sub-claim T-1a (RPC auth secret never logged by value).** The only log statement that references `auth_secret_` is the startup banner at `src/rpc/rpc.cpp:92-109`, and the only field of `auth_secret_` it references is `.size()` (line 97: `<< auth_secret_.size() << "-byte secret"`). The actual bytes are never written. Confirmed by `grep -n 'std::cout\|std::cerr' src/rpc/rpc.cpp` returning exactly 5 lines, all within the startup banner block.

- **Sub-claim T-1b (dh_secret revealed-only).** The `dh_secret` field of `BlockSigMsg` is gossiped as part of Phase-2 reveal. The audit confirms that no `std::cout` or `std::cerr` call in `src/node/node.cpp` emits `msg.dh_secret` (or any equivalent) by value. The closest call site is `src/node/node.cpp:2268` ("BlockSig dh_secret/commit mismatch from <signer>") — the diagnostic identifies WHICH peer's reveal failed to match the prior commit, but does not emit the bytes of either the reveal or the commit.

The invariant holds for all of `S` by case analysis over §4's enumeration.

### Theorem T-2 (log_quiet Compliance)

Let `cfg.log_quiet ∈ {false, true}` denote the operator's configuration. Let `L_verbose` denote the set of lines that the node emits during a fixed observation window when `cfg.log_quiet = false`, and let `L_quiet` denote the corresponding set when `cfg.log_quiet = true`.

**Claim:** `L_quiet ⊆ L_verbose`. Moreover, the difference `L_verbose \ L_quiet` contains exactly the per-block, per-handshake, per-snapshot-served, per-bundle-accepted, per-headers-served chatty diagnostic lines; the difference does not contain any WARN- or ERROR-class line.

**Proof:** By direct inspection of the gating predicates:

1. **Per-block accept line** (`src/node/node.cpp:1852-1855`): `if (!cfg_.log_quiet) { std::cout << "[node] accepted block #" << b.index << " creators=" << b.creators.size() << "\n"; }`. When `log_quiet=true`, this line is suppressed; when `log_quiet=false`, the line emits per accepted block (~1/tx_commit_ms on a healthy chain).

2. **Inbound receipt bundle accept line** (`src/node/node.cpp:1643-1648`): `if (added > 0 && !cfg_.log_quiet) { std::cout << "[node] inbound receipt bundle: ..."; }`. Gated identically.

3. **Served-headers line** (`src/node/node.cpp:1679-1686`): `if (!cfg_.log_quiet) { std::cout << "[node] served headers to peer ..."; }`. Gated identically.

4. **Per-connection diagnostic lines** (`src/net/gossip.cpp:53-55` and `:324-326`): `if (!log_quiet_) { std::cout << "[gossip] connected to ..."; }` and similarly for peer-disconnect. The `log_quiet_` member is propagated from `Config::log_quiet` via `Node::cfg_` → `gossip_.set_log_quiet(cfg_.log_quiet)` at construction (`src/node/node.cpp:531`).

5. **Per-block-served / per-snapshot-served line** (`src/node/node.cpp:1663-1666`): `std::cout << "[node] served snapshot to peer ..."`. NOTE: this line is NOT gated by `log_quiet` in the current code — it is rare (once per snapshot-bootstrap, not once per block) so the audit accepts the surfacing as informational. Operators wanting the line suppressed can add the gate (~3 LOC); the current default is "snapshot-served is rare enough to keep visible".

6. **WARN/ERROR diagnostics** (e.g. `src/node/node.cpp:1376` "beacon header prev_hash mismatch", `:1410` "shard tip: insufficient sigs", `:2090` "invalid Contrib sig", `:2157` "S-006 ContribMsg equivocation detected", `:2251` "invalid BlockSig", `:2268` "BlockSig dh_secret/commit mismatch", `:2346` "peer on different genesis"): NONE of these are gated by `log_quiet`. They continue to surface regardless. The operator's `log_quiet=true` setting does not suppress structural diagnostics.

7. **Startup banner** (`src/rpc/rpc.cpp:92-109`, `src/net/gossip.cpp:34`, `src/node/node.cpp:404-406` shard-manifest, `:451-458` snapshot-restore confirmation, `:499-508` genesis-loaded confirmation, `:511-512` warning on missing genesis_path): NONE of these are gated by `log_quiet`. They are once-per-start, structural, and useful for operator-confidence ("yes my node started in the configuration I expected"). The audit accepts keeping them visible by default.

The set difference is therefore exactly the per-block / per-bundle / per-connection chatty class. Regression test `tools/test_log_quiet.sh` exercises the verbose→quiet differential by counting `[node] accepted block #` occurrences in two sequential phases (one with `log_quiet=false`, one with `log_quiet=true`) and asserting that the verbose phase emits ≥ 3 lines and the quiet phase emits 0 lines — a clean differential.

### Theorem T-3 (No Secret in Error Path)

A naive `log_quiet`-only mitigation would fail under the scenario: "operator deployed with `log_quiet=true` in production, but a rare error path emits secret material because the developer assumed the error path was suppressed under `log_quiet=true` and was sloppy about diagnostic content." This theorem rules out that scenario by establishing that the WARN/ERROR diagnostics — which CANNOT be suppressed by `log_quiet` — also do not contain secret material.

**Claim:** Every `std::cerr` call site in `src/node/*.cpp`, `src/rpc/*.cpp`, `src/net/*.cpp`, `src/chain/*.cpp` emits a format-string-argument list whose elements are restricted to one of: (a) chain-public state (block.index, peer pubkey identifier, tx hash, account domain name); (b) peer transport address; (c) protocol-error message (`<exception>.what()` where the exception was thrown by a chain-validity check whose own message is restricted to chain-public state); (d) static format strings (no input bytes embedded).

**Proof:** Enumeration of every `std::cerr` call site in scope. The exhaustive list:

| File:Line | Format-string skeleton | Argument categories | Secret? |
|---|---|---|---|
| `src/node/node.cpp:469` | `"[node] snapshot restore failed: " << e.what()` | (c) — `restore_from_snapshot` throws with field-name + expected/actual hash; no secret. | No |
| `src/node/node.cpp:511-512` | `"[node] WARNING: no genesis_path configured; using legacy zeros-genesis"` | (d) — static. | No |
| `src/node/node.cpp:688` | `"[save worker] save failed: " << e.what()` | (c) — `Chain::save` throws with filesystem error; no secret. | No |
| `src/node/node.cpp:1214` | `"[node] invalid AbortClaim sig from " << msg.claimer` | (a) — `claimer` is the public domain name of the equivocating peer. | No |
| `src/node/node.cpp:1376` | `"[node] beacon header prev_hash mismatch at h=" << b.index` | (a). | No |
| `src/node/node.cpp:1383` | `"[node] beacon header at h=" << b.index << " ..."` (various sig-related errors) | (a). | No |
| `src/node/node.cpp:1393` | `"[node] beacon header: creator_block_sigs size mismatch"` | (d). | No |
| `src/node/node.cpp:1404` | `"[node] beacon header at h=" << b.index` | (a). | No |
| `src/node/node.cpp:1411` | `"[node] beacon header at h=" << b.index` | (a). | No |
| `src/node/node.cpp:1420` | `"[node] beacon header at h=" << b.index` | (a). | No |
| `src/node/node.cpp:1461` | `"[node] shard tip prev_hash mismatch: shard=" << shard_id` | (a). | No |
| `src/node/node.cpp:1505-1510` | `"[node] shard tip: insufficient pool to derive committee for shard="` and `"shard tip: creators size mismatch"` | (a). | No |
| `src/node/node.cpp:1522` | `"[node] shard tip: creators[" << i << "] mismatch ('" << ...` | (a) — emits creator domain names. | No |
| `src/node/node.cpp:1540` | `"[node] shard tip: invalid sig from " << tip.creators[i]` | (a) — creator domain name. | No |
| `src/node/node.cpp:1547` | `"[node] shard tip: insufficient sigs (" << signed_count << ...` | (a). | No |
| `src/node/node.cpp:1770` | `"[node] EQUIVOCATION evidence built at h="` | (a). | No |
| `src/node/node.cpp:1784` | `"[node] invalid block: " << res.error` | (c) — `BlockValidator::validate` returns `res.error` strings that name failed validity rules (e.g. "missing creator sig", "wrong creator count", "stale tx in mempool"); no secret. | No |
| `src/node/node.cpp:2090` | `"[node] invalid Contrib sig from " << msg.signer` | (a) — `signer` is the public domain name. | No |
| `src/node/node.cpp:2157` | `"[node] S-006 ContribMsg equivocation detected: ..."` | (a) — domain name + round number. | No |
| `src/node/node.cpp:2223` | `"[node] BlockSig with mismatched delay_output from " << msg.signer` | (a). | No |
| `src/node/node.cpp:2251` | `"[node] invalid BlockSig from " << msg.signer` | (a). | No |
| `src/node/node.cpp:2268` | `"[node] BlockSig dh_secret/commit mismatch from " << msg.signer` | (a) — diagnoses that signer's reveal does not match their commit; does NOT emit the reveal or the commit bytes. | No |
| `src/node/node.cpp:2346-2348` | `"[node] peer " << peer->address() << " on different genesis (" << genesis_hash << ", ours " << ours << "); ignoring for sync"` | (a, b) — genesis hashes are chain-public (the genesis block is the seed of every peer's chain). | No |
| `src/net/gossip.cpp:69-71` | `"[gossip] connect to " << host << ":" << port << " failed: " << err` | (b, c) — asio connect error message. | No |
| `src/net/gossip.cpp:315-316` | `"[gossip] dispatch error from " << peer->address() << ": " << e.what()` | (b, c) — dispatch exceptions come from `deserialize` paths whose messages name the wire field that failed to parse; no secret. | No |

No `std::cerr` call in the audit scope embeds any byte-string from `S`. The error paths are safe even under `log_quiet=true`-in-production.

A subtle structural note: the audit confirms that NONE of the `<< e.what()` patterns reach into a code path that could embed secret material in the exception. The chain's exception-throwing code (e.g. `Chain::restore_from_snapshot`, `Chain::save`, `BlockValidator::validate`, `deserialize` in `messages.cpp`) is itself audited as part of the same Grep — confirmed not to embed secrets in any thrown message. The composition is therefore tight.

### Theorem T-4 (Audit Methodology Reproducibility)

The S-027 closure is not a one-time inspection but a methodology to be re-applied as the source evolves. This theorem documents the methodology so a future contributor adding a `std::cout` line can verify in seconds that they have not broken the invariant.

**Methodology:**

```bash
# Step 1: enumerate every log call site in scope.
grep -rn 'std::cout\|std::cerr' src/node/*.cpp src/rpc/*.cpp src/net/*.cpp src/chain/*.cpp

# Step 2: for each call site, inspect the format-string argument list.
# A reviewer manually classifies each argument as:
#   (a) chain-public state (block.index, tx.hash, account domain name)
#   (b) peer transport address (peer->address())
#   (c) protocol-error <exception>.what() — must reach back to verify the
#       throwing code's message content
#   (d) static format string
# An argument that does not fit (a)-(d) is a candidate violation; the
# reviewer escalates.

# Step 3: cross-check forbidden patterns. The following grep should
# return zero matches in any production source file:
grep -rn 'std::cout.*\(priv_seed\|ed_sk\|dh_secret\|auth_secret_[^.]*$\)' \
     src/node/ src/rpc/ src/net/ src/chain/
grep -rn 'std::cerr.*\(priv_seed\|ed_sk\|dh_secret\|auth_secret_[^.]*$\)' \
     src/node/ src/rpc/ src/net/ src/chain/

# (The pattern `auth_secret_[^.]*$` matches `auth_secret_` not followed by
# a `.size()` or `.empty()` accessor — i.e., the secret as a value, not a
# meta-property.)

# Step 4: confirm the new line composes with log_quiet correctly.
# If the new line is a "chatty per-block / per-connection / per-bundle"
# diagnostic, wrap it with `if (!cfg_.log_quiet)` (or `if (!log_quiet_)`
# in gossip.cpp). If it is a WARN/ERROR diagnostic, leave it unguarded.
```

**Claim:** Any new `std::cout` or `std::cerr` line added to `src/node/*.cpp`, `src/rpc/*.cpp`, `src/net/*.cpp`, or `src/chain/*.cpp` MUST be reviewed against the methodology above before merge. The contribution guide should reference this proof.

**Proof:** The methodology is self-evidently reproducible because step 1 returns a deterministic set (the source code is the source of truth), step 2 is mechanical (per-argument classification), and step 3 is a Grep that either returns zero matches (passes) or a non-zero set (escalates). The methodology is not novel; it is the standard "secret-in-source audit" pattern applied to a specific surface.

The audit's current pass corresponds to a snapshot of `src/` as of this commit. A future regression (e.g. a contributor adds `std::cerr << "auth check failed for secret " << auth_secret_ << "\n";`) would be caught by step 3's Grep at PR-review time. Finding F-1 below recommends formalizing step 3 as a CI gate.

### Theorem T-5 (Composition with RPC Auth — env-var secret delivery)

Even with the log surface fully audited (T-1) and the operator's `log_quiet=true` setting honored (T-2 + T-3), a residual secret-leak surface exists if the RPC auth secret is delivered via the command-line argument: `ps aux` reveals the command line to any UID on the host (modulo `/proc/<pid>/cmdline` ACLs which by default are world-readable), shell history captures it (`~/.bash_history`, `~/.zsh_history`), and `--help` or `usage:` text may echo it if the operator passes `--help` after configuring the secret.

The S-001 closure pairs with the S-027 audit by requiring that the secret be delivered via the `DETERM_RPC_AUTH_SECRET` environment variable (or via the `Config::rpc_auth_secret` field loaded from the operator's `config.json` file). The env-var path is implemented at `src/rpc/rpc.cpp:294`:

```cpp
const char* env = std::getenv("DETERM_RPC_AUTH_SECRET");
if (env && *env) effective_secret = env;
```

**Claim:** The env-var secret-delivery channel composes with the S-027 log audit to give end-to-end secret confidentiality. Specifically:

1. The env-var value is NOT visible in `ps aux` output (env-var values appear in `/proc/<pid>/environ` which is by default readable only by the owning UID; under `hidepid=2` Linux mount option, even the same UID's other processes cannot read it).
2. The env-var value is NOT in shell history if the operator sets it via `export DETERM_RPC_AUTH_SECRET=$(cat ~/secrets/rpc_secret.hex)` from a sourced shell script (the script's content does not enter history; the `export` line itself does, but it does not contain the secret literal).
3. The env-var value is NOT echoed by any `--help` or `usage:` text in the Determ binary (confirmed by audit of `src/main.cpp` help blocks).
4. The env-var value is NOT logged by the RPC startup banner — only `.size()` is emitted per T-1a above.
5. The env-var value is NOT written to any chain-state field, snapshot field, gossip message, or RPC response.

**Proof:** Each of (1)–(5) is a structural property of the implementation:

- (1) is a property of the Linux `/proc` ACL model + standard `hidepid=2` deployment posture. The chain code does nothing to defeat it.
- (2) is operator-discipline (use sourced scripts, not literal command-line entry) but the Determ CLI does not actively undermine it (no helpful "did you mean to pass `--auth-secret`?" prompt that would invite shell-history capture).
- (3) is confirmed by audit of `src/main.cpp` — the help text for `determ start` mentions `rpc_auth_secret` only as a config-file field, never as a CLI flag.
- (4) and (5) are confirmed by T-1a above + audit of `Node::rpc_status` (`src/node/node.cpp:2478`) which emits `rpc_hmac_auth: !cfg_.rpc_auth_secret.empty()` — a boolean readback of "is HMAC enabled" — never the secret value.

The composition gives the end-to-end statement: an attacker observing the log stream, the process listing, the shell history, the `--help` output, and the RPC status response cannot recover the secret bytes. The only attack surface remaining is the config file's at-rest representation (`rpc_auth_secret` is plaintext in `Config::to_json`; this is `RpcAuthHmacSoundness.md` F-1, registered as a separate finding for passphrase-encryption of the config file in a future hardening pass).

A residual point: when `Config::to_json` is called by `Node::rpc_status` (at `src/node/node.cpp:2481` which emits the `protections` block), the JSON output includes `rpc_hmac_auth: <bool>` — NOT `rpc_auth_secret: <value>`. The `to_json` for the protections block is a hand-written subset, not the full `Config::to_json`. The full `Config::to_json` at `node.cpp:30` does emit `rpc_auth_secret` by value — but this `to_json` is called only by `Config::save(path)` (for writing the config file back to disk) and by the equivalent on the CLI's load/save round-trip test. It is NOT called by any RPC handler, so the secret is not exposed via the RPC surface. This is a subtle composition point that the audit confirms by tracing the `to_json` call graph.

---

## 3. Adversary models A1..A4

The closure defends against four orthogonal adversary classes:

### A1 (Local filesystem read)

**Capability:** Read access to the running log file (`/var/log/determ.log`, `journalctl -u determ`, or an operator-chosen file location). The attacker may be a co-tenant on a shared host, a misconfigured backup process that grants too-wide read access, an unprivileged user on a Linux box without `journalctl` access controls, or a Windows user with `SeReadFilePrivilege` on the log path.

**Defense:** T-1 establishes that no secret material is in the log content. Even with full read access, the attacker harvests only chain-public state. T-3 extends the defense to ERROR-class lines (which cannot be suppressed by `log_quiet`).

**Residual:** Operator-side log-file ACLs (`chmod 0600 /var/log/determ.log` or systemd `LogsDirectoryMode=0700`) provide defense-in-depth; the chain code does not enforce these but documents them as F-3 below.

### A2 (Log-shipping pipeline egress)

**Capability:** The operator ships logs to a third-party aggregator. The aggregator has its own perimeter (different from the operator's host) and may retain logs indefinitely. The attacker is anyone with read access at the aggregator: insider at the aggregator vendor, attacker who compromises the aggregator's auth layer, or a query-as-service surface that exposes historical logs.

**Defense:** T-1 + T-3 give the same guarantee at the aggregator perimeter that they give at the source. The aggregator stores no secret bytes.

**Residual:** The aggregator may apply pattern-matching analytics (e.g. "alert on `auth_failed` rate > 100/min per IP"). Such analytics are operator-beneficial and do not introduce a leak. If the aggregator runs a regex like `s/.*secret=(.*?)( |$)/SECRET=<redacted>/` for defense-in-depth, the audit confirms it has no work to do (no secret patterns exist in the source's emitted lines).

### A3 (Operator screen-share / paste in public forum)

**Capability:** The operator pastes log snippets into Slack, Discord, GitHub issues, vendor support tickets, or live-streamed pair-programming. The pasted snippet might span hundreds of lines; the operator may not visually scan every byte.

**Defense:** T-1 + T-3 + T-2 compose to give the strongest guarantee: even if the operator pastes their entire log file verbatim, no secret bytes leak. The `log_quiet=true` setting (T-2) further reduces the volume so the operator is more likely to visually scan what they paste, but it is not a security-critical layer for this adversary class — T-1 + T-3 alone close the surface.

**Residual:** None at the chain code surface. Operator-side discipline ("scan before paste, redact peer IPs if sensitive") is documented as F-3.

### A4 (Crash-dump / unhandled-exception coredump)

**Capability:** The Determ node crashes (segfault, unhandled exception, OOM-kill). The OS captures a coredump that includes process memory at the time of the crash. The coredump's contents include every secret currently resident in memory: `priv_seed` (in the Node's `key_` field), `auth_secret_` (in the RpcServer's bytes vector), the `pending_secrets_` map (per-peer dh_secret buffers awaiting Phase-2 reveal). The coredump may be world-readable depending on `ulimit -c` + `sysctl kernel.core_pattern` settings.

**Defense:** OUT OF SCOPE for this audit. The chain code does not control coredump generation or location. Operator-side hardening is:

- `ulimit -c 0` in the service's systemd unit (suppress coredumps in production).
- `sysctl -w kernel.core_pattern=|/usr/bin/false` (kill any coredump attempt unconditionally).
- `sysctl -w fs.suid_dumpable=0` (disable coredumps for any setuid-elevated process — Determ does not setuid, but the policy is good hygiene).

The audit surfaces this as F-2 below: A4 is not closed by the chain code but is documented so operators are aware.

---

## 4. Audit results

This section enumerates every `std::cout` and `std::cerr` call site in the audit scope. Each call site is classified PASS (no secret material) or FAIL (would-be SECRET — none exist as of closure).

### 4.1 `src/rpc/rpc.cpp` (5 call sites)

| Line | Skeleton | Classification |
|---|---|---|
| 92 | `[rpc] listening on <ip>:<port>` | PASS — IP and port are operator-public. |
| 96 | ` (HMAC auth enabled, <N>-byte secret)` | PASS — only `.size()` emitted, NOT the secret value. |
| 101 | ` [WARNING: external bind without HMAC auth — set rpc_auth_secret in config or enable rpc_localhost_only]` | PASS — static text suggesting the config-field name. |
| 106 | ` (rate-limit <r>/s, burst <b>)` | PASS — rate-limiter parameters, operator-configured. |
| 109 | `\n` (terminator of the multi-part startup banner) | PASS — empty. |

All five lines are within the startup banner block (one logical line emitted at constructor time). The banner emits exactly once per process start. No per-request log lines exist in `rpc.cpp`.

### 4.2 `src/net/gossip.cpp` (6 call sites)

| Line | Skeleton | Classification | log_quiet gated? |
|---|---|---|---|
| 25 | `[gossip] rate-limit <r>/s, burst <b>` | PASS — rate-limit configuration readback. | No (one-shot at config time). |
| 34 | `[gossip] listening on port <port>` | PASS — operator-public port. | No (one-shot at start). |
| 54 | `[gossip] connected to <host>:<port>` | PASS — peer wire address. | YES — gated by `if (!log_quiet_)`. |
| 69-70 | `[gossip] connect to <host>:<port> failed: <asio-error>` | PASS — wire error from asio (network error message, no chain state). | No (error-class). |
| 315-316 | `[gossip] dispatch error from <peer-addr>: <e.what()>` | PASS — dispatch exception messages name failing wire field, no secret. | No (error-class). |
| 324-325 | `[gossip] peer disconnected: <peer-addr>` | PASS — peer wire address. | YES — gated by `if (!log_quiet_)`. |

### 4.3 `src/node/node.cpp` (40 call sites)

A representative subset (the full enumeration would replicate §2 T-3's table; cross-reference there for the ERROR-path entries):

**Startup/structural lines (NOT gated by log_quiet — emit once per process start or per rare event):**

| Line | Skeleton | Classification |
|---|---|---|
| 404-406 | `[node] loaded shard_manifest with <N> entries from <path>` | PASS — operator-configured path; entry count is chain-public. |
| 451-458 | `[node] restored from snapshot <path> block_index=<N> head=<hex> accounts=<N> stakes=<N> registrants=<N>` | PASS — chain-public snapshot statistics. |
| 469-470 | `[node] snapshot restore failed: <exception>; falling back to genesis bootstrap` | PASS — exception messages from `restore_from_snapshot` name failing snapshot field, no secret. |
| 499-508 | `[node] genesis loaded from <path> hash=<hex> role=<r> shard_id=<N> M=<N> K=<N> subsidy=<N> mode=<strong|hybrid> inclusion=<...> min_stake=<N>` | PASS — every field is on-chain genesis content, by definition public. |
| 511-512 | `[node] WARNING: no genesis_path configured; using legacy zeros-genesis (chain cannot bootstrap)` | PASS — static warning text. |
| 688 | `[save worker] save failed: <exception>` | PASS — filesystem-level error from `Chain::save`. |

**Per-block / per-bundle chatty lines (gated by log_quiet):**

| Line | Skeleton | Classification | Gate |
|---|---|---|---|
| 1643-1648 | `[node] inbound receipt bundle: src_shard=<N> block=<N> accepted=<N> pending_total=<N>` | PASS — chain-public state. | `if (added > 0 && !cfg_.log_quiet)` |
| 1679-1686 | `[node] served headers to peer <addr> (from=<N> requested=<N> returned=<N>)` | PASS — chain-public state + peer address. | `if (!cfg_.log_quiet)` |
| 1852-1855 | `[node] accepted block #<N> creators=<N>` | PASS — chain-public state. | `if (!cfg_.log_quiet)` |

**Per-block / per-snapshot informational lines (NOT gated — accepted as rare-enough):**

| Line | Skeleton | Classification |
|---|---|---|
| 1663-1666 | `[node] served snapshot to peer <addr> (block_index=<N>)` | PASS — chain-public state + peer address. |
| 1870-1872 | `[node] epoch boundary: epoch_index=<N> pool_size=<N> ...` | PASS — chain-public state. |
| 1149 | `[node] phase1 timeout, claim against <signer>` | PASS — public signer domain name. |
| 1186 | `[node] phase2 timeout, <N> sigs received` | PASS — public count. |
| 1249 | `[node] abort quorum (round <N>) ...` | PASS — public consensus state. |
| 1310 | `[node] adopted gossiped abort event (round <N>)` | PASS — public consensus state. |
| 1340 | `[node] adopted gossiped equivocation evidence: equivocator=<domain> ...` | PASS — public domain name. |
| 1427 | `[node] verified beacon header #<N>` | PASS — public state. |
| 1553 | `[node] verified shard tip: shard=<N> ...` | PASS — public state. |
| 2367 | `[node] caught up to height <N>; entering IN_SYNC` | PASS — public height. |

**ERROR-class lines (NOT gated; enumerated in T-3 table above):**

40 call sites total, broken down: 14 in `std::cerr` (ERROR/WARN-class), 26 in `std::cout` (INFO-class). Of the 26 INFO-class, 3 are gated by `log_quiet`; 23 are not (because they are once-per-event / once-per-start, not once-per-block). Of the 14 ERROR-class, 0 are gated (all surface regardless of `log_quiet`). Total: 0 FAIL classifications. All 40 call sites PASS.

### 4.4 `src/chain/chain.cpp` (0 call sites)

The chain layer is the deepest layer of the implementation and is deliberately quiet — all logging is performed at the node/network layer that wraps it. A `grep -cn 'std::cout\|std::cerr' src/chain/chain.cpp` returns `0` matches. This is an architectural property: the apply-layer (`Chain::apply_transactions`, `Chain::apply_equivocation_event`, etc.) does not log. Errors propagate via return value or exception; the node layer decides what to surface to the operator. The audit confirms zero secrets-in-log in the chain layer trivially.

### 4.5 Summary

| File | Call sites | PASS | FAIL |
|---|---|---|---|
| `src/rpc/rpc.cpp` | 5 | 5 | 0 |
| `src/net/gossip.cpp` | 6 | 6 | 0 |
| `src/node/node.cpp` | 40 | 40 | 0 |
| `src/chain/chain.cpp` | 0 | — | — |
| **Total** | **51** | **51** | **0** |

The audit closes: no `std::cout` or `std::cerr` call site in the audit scope emits any byte from any secret category in `S`.

---

## 5. Cross-references

### 5.1 SECURITY.md sections

- **`docs/SECURITY.md` §S-027** — The closure narrative this proof formalizes. The audit-pass + `log_quiet` flag combination is documented at §6.5 (S-027 closure entry) and at the summary row in §1 ("Mitigated Low/Op").
- **`docs/SECURITY.md` §S-001** — RPC HMAC auth + localhost-only default. The `DETERM_RPC_AUTH_SECRET` env-var pattern composed in T-5 above is the operator-facing channel for the S-001 secret.
- **`docs/SECURITY.md` §S-004** — Keyfile at-rest encryption. The `DETERM_PASSPHRASE` env-var pattern for keyfile decryption mirrors the RPC auth env-var pattern; the audit confirms passphrases are not logged anywhere in the node-startup path that decrypts the keyfile.

### 5.2 Companion proofs

- **`docs/proofs/RpcAuthHmacSoundness.md`** — T-4 (Secret Confidentiality at RPC Surface). The HMAC layer's audit that `auth_secret_` is never written to any log, error response, or wire message by `src/rpc/rpc.cpp`. Composed in T-5 above as the secret-confidentiality arm.
- **`docs/proofs/S001RpcAuthSoundness.md`** — T-5 (Secret Lifecycle Composition). The composition theorem covering HMAC auth + input-validation defense. Cross-references the `DETERM_RPC_AUTH_SECRET` env-var pattern.
- **`docs/proofs/S004KeyfileAtRest.md`** — Passphrase confidentiality at the keyfile surface. The Argon2id-KDF-derived key wrapping the Ed25519 seed; the audit confirms the plaintext passphrase is not logged anywhere in the load path.
- **`docs/proofs/RpcInputValidationDefense.md`** — T-2 (No Internal-Error Leakage). The per-method semantic-gate error diagnostics are bounded to chain-public fields. Cross-referenced in T-3 above as the structural complement to the no-secret-in-log audit.
- **`docs/proofs/JsonValidationSoundness.md`** — T-2 (No Internal-Error Leakage). The S-018 hardened `from_json` diagnostics include only field name + type expectation, never input bytes. Composed implicitly into T-3 here (the `<< e.what()` patterns that reach into JSON-parse exceptions are safe).

### 5.3 Implementation sites

- **`include/determ/node/node.hpp:144-158`** — `Config::log_quiet` field declaration + extensive S-027 explanation comment.
- **`include/determ/net/gossip.hpp:42`** — `GossipNet::set_log_quiet(bool)` setter.
- **`include/determ/net/gossip.hpp:121-124`** — `GossipNet::log_quiet_` field + S-027 inline comment.
- **`src/node/node.cpp:58`** — `Config::to_json` serializes `log_quiet`.
- **`src/node/node.cpp:106`** — `Config::from_json` reads `log_quiet` with default `false`.
- **`src/node/node.cpp:531`** — `Node::Node` propagates `cfg_.log_quiet` to `gossip_`.
- **`src/node/node.cpp:1643-1648`** — `log_quiet` gate on inbound-receipt bundle line.
- **`src/node/node.cpp:1679-1686`** — `log_quiet` gate on served-headers line.
- **`src/node/node.cpp:1847-1855`** — `log_quiet` gate on per-block accept line; inline S-027 explanation comment.
- **`src/node/node.cpp:2481`** — `Node::rpc_status` emits `log_quiet: <bool>` in the `protections` block (operator-visible status readback).
- **`src/net/gossip.cpp:53-55`** — `log_quiet_` gate on per-connection diagnostic.
- **`src/net/gossip.cpp:324-326`** — `log_quiet_` gate on per-disconnect diagnostic.
- **`src/rpc/rpc.cpp:92-109`** — RPC startup banner emitting only `auth_secret_.size()`, never the value.
- **`src/rpc/rpc.cpp:294`** — `DETERM_RPC_AUTH_SECRET` env-var read.

### 5.4 Tests

- **`tools/test_log_quiet.sh`** — 3-assertion regression covering verbose emits per-block lines (≥ 3 in observation window), quiet suppresses them (= 0), quiet still surfaces startup/listen diagnostics.
- **`tools/test_status_protections.sh`** — Asserts `Node::rpc_status` emits `log_quiet` in the `protections` block. Operator-monitoring readback test.
- **`tools/test_config_defaults.sh`** — Asserts `Config::from_json({})` default `log_quiet = false` (operator-visible verbose default).
- **`tools/test_config_load_save.sh`** — Asserts the round-trip of `log_quiet` through `Config::save`/`Config::load`.
- **`tools/test_rpc_hmac_auth.sh`** — Companion regression covering RPC HMAC auth (S-001); referenced in the cross-layer composition.

---

## 6. Findings F-1..F-3

### Finding F-1 (Third-party library log statements not in audit scope)

The audit covers `src/node/*.cpp`, `src/rpc/*.cpp`, `src/net/*.cpp`, `src/chain/*.cpp` — the chain-owned production source. Third-party libraries linked into the binary include `libsodium` (Ed25519 + crypto primitives), OpenSSL (HMAC-SHA256, SHA-256), nlohmann::json (JSON parse/serialize), and asio (network I/O). These libraries were NOT enumerated for log call sites. *(Inc.4 drift-repair: `asio` has since been deleted from the tree — the daemon networks on the native `net::` IOCP/epoll backends, see `MinixTacticalProfile.md`; the asio row below is retained as the audit's original context. Removing a library can only shrink the third-party surface, so the finding's conclusion — no linked library adds a log surface — is unaffected.)*

**Inspection note:** By inspection of each library's source / documentation:

- **libsodium** does not log to stdout/stderr in any release-mode code path. Its abort-on-misuse behavior (e.g. `sodium_init` returning -1) is propagated via return value, not logged. PASS.
- **OpenSSL** has an internal error queue (`ERR_get_error()`) that the consumer code must call to drain; OpenSSL itself does not emit to stdout/stderr from the EVP_MD / HMAC primitives that Determ uses. PASS.
- **nlohmann::json** is header-only and throws `nlohmann::json::exception` derivatives on parse error; the exception's `what()` is a structural error message (line/column + token), never the input bytes. The Determ code that catches these exceptions (e.g. `Config::from_json` at `node.cpp:62`) re-throws or surfaces the diagnostic, which §3 §4 above confirms is restricted to chain-public state. PASS.
- **asio** emits no log statements; all asio diagnostics flow via `error_code` arguments to callbacks. PASS.

**Severity:** Very Low (the libraries do not introduce log surfaces; this finding is a completeness note rather than a defect).

**Recommended mitigation:** Periodically re-confirm at each library version bump that the upstream has not introduced a debug log surface. The Determ build does not set `-DDEBUG_LOGGING` or equivalent flags that would enable optional log paths in any of the linked libraries.

**Effort:** Zero ongoing cost; confirm at version-bump time (annual cadence is sufficient).

### Finding F-2 (Crash dumps are outside the log-surface audit)

If the Determ node crashes (segfault, unhandled C++ exception that propagates past `main`, OOM-kill, panic in a third-party library), the OS may capture a coredump. The coredump contains process memory at the time of the crash, including:

- The Ed25519 seed in `Node::key_.seed` (32 bytes).
- The RPC auth secret in `RpcServer::auth_secret_` (32 bytes typical).
- The buffered `dh_secret` reveals in `Node::pending_secrets_` map (32 bytes × peer-count, awaiting reveal in the current round).
- Any plaintext keyfile passphrase that was passed via `DETERM_PASSPHRASE` env var (in the process's env vector).

The coredump's read permissions are controlled by `kernel.core_pattern`, `kernel.core_uses_pid`, `fs.suid_dumpable`, and the chosen storage directory's ACL. Default settings on most Linux distributions write coredumps to `/var/lib/systemd/coredump/` (systemd-coredump) or `core.<pid>` in the cwd, with read access by the owning UID.

**Severity:** Low to Operator. The exposure requires (a) the node to crash and (b) the attacker to have read access to the coredump storage location.

**Recommended mitigation:** Operator-side hardening:

```ini
# systemd unit file:
[Service]
LimitCORE=0           # ulimit -c 0; suppress coredumps entirely.
PrivateTmp=yes        # isolate /tmp; even if a coredump escapes, the
                      # attacker cannot trivially recover it from /tmp.
ProtectSystem=strict  # read-only /usr; defense-in-depth.
```

Or, kernel-wide:

```bash
sysctl -w kernel.core_pattern='|/bin/false'   # any core handler that
                                              # immediately exits success
                                              # — coredump is discarded.
sysctl -w fs.suid_dumpable=0                  # never coredump a setuid
                                              # binary (Determ is not
                                              # setuid, but good hygiene).
```

Chain-code-side mitigation is theoretically available (e.g., `mlock` the secret pages then zero them in a `std::terminate` handler), but it is fragile (cannot defend against `SIGKILL` or `SIGSEGV` during the zeroing window) and out of scope for the S-027 closure. The recommended posture is operator-side suppression of coredumps in production.

**Effort:** Operator-side configuration; ~5 lines in the systemd unit. Zero chain-code change.

### Finding F-3 (Operator-side log-file ACL + rotation + paste discipline)

The chain code emits log lines to stdout/stderr. The operator chooses where those streams are persisted (systemd journal, `> /var/log/determ.log` redirection, structured log shipper, etc.). The chain code does not enforce ACLs or rotation on the persisted form; these are operations-scope.

**Recommended operator discipline:**

1. **File permissions.** If logging to a file via shell redirection, ensure `chmod 0600 /var/log/determ.log` and `chown determ:determ /var/log/determ.log`. The systemd journal default ACL is permissive (typically world-readable); operators who want tighter access should set `LogsDirectoryMode=0700` in the unit file and run `journalctl` as the service UID only.

2. **Log rotation with retention bound.** Use `logrotate` or systemd `Storage=volatile` to bound on-disk retention. The audit confirms no secret bytes accumulate over time, but bounded retention is good hygiene against opportunistic attacks (e.g. a backup snapshot capturing logs years after the original was deleted).

3. **Paste discipline.** Operators pasting log snippets to public forums (Slack, Discord, GitHub) should redact peer IP addresses if the operator's peer set is sensitive (e.g. a private consortium). The audit confirms no secret material is in the snippet; the only operationally-sensitive content is peer topology, which is operator-policy not chain-code policy.

4. **Log shipping to third-party aggregators.** If shipping logs to Datadog / Splunk / Loki, confirm the aggregator's data-residency + access-control posture meets the operator's policy. The audit confirms no secrets in the log content, so the aggregator stores no secrets — but the operator should still apply normal aggregator-vendor due diligence.

5. **Production setting recommendation.** Production operators should set `log_quiet = true` in `config.json` to suppress per-block / per-bundle / per-connection chatter. The reduction is significant (~100× reduction in line-rate on a healthy chain at `tx_commit_ms = 200`), reducing both storage cost and the attacker-visible surface in (1)–(4) above.

**Severity:** Low to Operator (operations-scope).

**Recommended mitigation:** Documented in `docs/CLI-REFERENCE.md` §17 ("Operator hygiene (S-027)") and in `docs/SECURITY.md` §S-027 closure narrative. Operators are expected to follow the recommendations; the chain code does not enforce.

**Effort:** Operator-side configuration; zero chain-code change.

The three findings are advisory; none invalidates T-1..T-5. They are surfaced for completeness so an external auditor can confirm the scope of the audit + the operator-side residuals.

---

## 7. Test surface citation + CI gate proposal

The current regression coverage:

- **`tools/test_log_quiet.sh`** (3 assertions): verifies the verbose-vs-quiet differential. Phase A (`log_quiet=false`) emits ≥ 3 `[node] accepted block #` lines; Phase B (`log_quiet=true`) emits 0 such lines; Phase B still surfaces `[rpc] listening` and `Loading node` startup lines. The test is a thin behavioral check; it does not exhaustively verify the no-secret-in-log invariant per call site.

- **`tools/test_status_protections.sh`** (asserts `Node::rpc_status` emits `log_quiet` in the operator-visible `protections` block).

- **`tools/test_config_defaults.sh`** and **`tools/test_config_load_save.sh`** (assert the `Config::log_quiet` field default + round-trip).

**Proposed CI gate** (registered as F-4 in spirit; not a separate severity entry): add a `tools/test_no_secret_in_log_audit.sh` script that runs the Grep methodology from T-4 and asserts zero matches. Skeleton:

```bash
#!/usr/bin/env bash
# S-027 audit gate: confirm no secret material is ever logged.
# Fails CI if any std::cout or std::cerr call site embeds a forbidden
# pattern (secret material as a value, not as a meta-property like
# .size() or .empty()).

set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
assert_no_match() {
    local pattern="$1" label="$2"
    local n=$(grep -rn "$pattern" \
        src/node/*.cpp src/rpc/*.cpp src/net/*.cpp src/chain/*.cpp \
        2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then
        echo "  PASS: $label (0 matches)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label ($n matches)"
        grep -rn "$pattern" src/node/*.cpp src/rpc/*.cpp src/net/*.cpp src/chain/*.cpp
        FAIL=$((FAIL + 1))
    fi
}

# Forbidden: any log statement that embeds a secret-bearing value.
# Each pattern is "log primitive .* secret name not followed by a meta accessor".
assert_no_match 'std::cout.*\bpriv_seed\b'        'no priv_seed in std::cout'
assert_no_match 'std::cerr.*\bpriv_seed\b'        'no priv_seed in std::cerr'
assert_no_match 'std::cout.*\bed_sk\b'            'no ed_sk in std::cout'
assert_no_match 'std::cerr.*\bed_sk\b'            'no ed_sk in std::cerr'
assert_no_match 'std::cout.*\bdh_secret\b'        'no dh_secret in std::cout'
# Note: dh_secret can legitimately appear in std::cerr for the
# commit-mismatch diagnostic at node.cpp:2268, but the diagnostic
# does NOT embed the bytes (it only names the field). The pattern
# above is sloppy; refine to check for << emission:
assert_no_match 'std::cout *<<.*dh_secret[^/]'    'no dh_secret value in std::cout'

# auth_secret_ as a value (NOT followed by .size() or .empty()):
assert_no_match 'std::cout.*auth_secret_[^.]'     'no auth_secret_ value in std::cout (only .size()/.empty() ok)'
assert_no_match 'std::cerr.*auth_secret_[^.]'     'no auth_secret_ value in std::cerr'

# Passphrase / passwd / password literal in any log statement:
assert_no_match 'std::cout.*\(passphrase\|password\|DETERM_PASSPHRASE\)' \
                'no passphrase in std::cout'
assert_no_match 'std::cerr.*\(passphrase\|password\|DETERM_PASSPHRASE\)' \
                'no passphrase in std::cerr'

echo
echo "=== Summary: $PASS pass, $FAIL fail ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
```

**Severity of not having this CI gate:** Very Low (the current audit is comprehensive and the Grep methodology is documented in T-4 so a contributor can re-run it manually). The CI gate is defense-in-depth against a future contributor adding `std::cerr << "auth check failed for secret " << auth_secret_ << "\n";` and the change escaping reviewer attention.

**Effort:** ~60 LOC bash + a single CI hook invocation (e.g. as part of the existing `tools/run_all.sh` orchestration). Estimated 0.5 day.

---

## 8. References

### 8.1 Standards + frameworks

- **NIST SP 800-92** (Kent, Souppaya, Sep 2006) — *"Guide to Computer Security Log Management."* NIST. The canonical reference for log-management policy: scoping, content auditing, ACL recommendations, retention policy. §3.3 ("Log Storage and Disposal") informs F-3's operator-side recommendations.

- **OWASP Logging Cheat Sheet** (OWASP Foundation; continuously updated). Section "Data to Exclude" enumerates categories that should never appear in application logs: authentication credentials, session identifiers, sensitive personal information, encryption keys, source code or business logic, system internals. The S-027 audit confirms compliance with the equivalent categories for chain-context secrets.

- **CWE-532** (MITRE Common Weakness Enumeration) — *"Insertion of Sensitive Information into Log File."* The taxonomy entry for this class of defect. Likely impact: "Confidentiality." Detection: code inspection + grep audit. The S-027 closure is the standard mitigation: audit + remove or never-emit.

- **CWE-200** (MITRE) — *"Exposure of Sensitive Information to an Unauthorized Actor."* Parent category covering CWE-532 + related (file-permission-based exposure, env-var exposure, etc.). The composition with the env-var pattern in T-5 addresses the env-var exposure sub-class.

- **CWE-209** (MITRE) — *"Generation of Error Message Containing Sensitive Information."* The error-path-specific variant. T-3 above is the structural defense against this CWE.

### 8.2 Operating-system references

- **Linux `proc(5)` man page**, section on `/proc/<pid>/environ` — describes the default ACL (UID-owner-readable) and the `hidepid` mount option that further restricts visibility.

- **systemd-coredump(8)** — coredump capture daemon documentation; describes `LimitCORE=`, `Storage=`, and per-unit override mechanisms.

- **journald.conf(5)** — `LogsDirectoryMode=`, `Storage=volatile`, `MaxRetentionSec=` knobs for systemd-journal ACL and retention policy.

### 8.3 Implementation-side references

- **`docs/SECURITY.md`** — §S-027 closure narrative (the in-spec record of the audit pass + `log_quiet` flag).
- **`docs/CLI-REFERENCE.md`** §17 ("Operator hygiene (S-027)") — operator-facing documentation of the `log_quiet` flag + recommended production posture.
- **`docs/PROTOCOL.md`** §10.2 — RPC documentation. The auth-secret delivery channel (`DETERM_RPC_AUTH_SECRET` env var) is documented here as the canonical operator pattern.
- **`docs/README.md`** — README operator-onboarding section references `log_quiet` as part of the production-deployment checklist.

### 8.4 Companion proof references (cross-linked from §5.2 above)

- `docs/proofs/RpcAuthHmacSoundness.md` — T-4 Secret Confidentiality at RPC Surface (the cryptographic-layer arm composed in T-5).
- `docs/proofs/S001RpcAuthSoundness.md` — T-5 Secret Lifecycle Composition (the composition theorem this proof feeds into).
- `docs/proofs/S004KeyfileAtRest.md` — Keyfile-at-rest passphrase confidentiality (the parallel surface to the RPC auth secret).
- `docs/proofs/RpcInputValidationDefense.md` — T-2 No Internal-Error Leakage (the structural complement to T-3 here).
- `docs/proofs/JsonValidationSoundness.md` — T-2 No Internal-Error Leakage (the JSON-parse-exception arm).

The audit + `log_quiet` flag + env-var pattern compose to close S-027 at the chain-code surface. Operator-side hardening (F-2 coredump suppression, F-3 log-file ACL) is documented for completeness; the chain code does not enforce these because they are operations-scope, but the documentation surfaces the recommendations so production deployments can confirm the closure end-to-end.
