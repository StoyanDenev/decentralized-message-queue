# Determ Security Posture

**Doc status:** Canonical. Reconciles the rev.7 [SECURITY_AUDIT.md](https://github.com/) findings with the in-tree [OPEN-VULNERABILITIES.md](OPEN-VULNERABILITIES.md) (now superseded by this file) against current code at rev.8 + rev.9 sharding through B6.basic.

**Methodology.** Each finding is verified against current source before classification. Findings the rev.7 audit raised that have since been mitigated are listed in §5. New issues visible in rev.9 code (sharding, snapshots) that the audit predates are included as first-class findings. Severity follows the audit's CVSS-style framing.

---

## 1. Executive summary

| | Critical | High | Medium | Low/Op | Total |
|---|---|---|---|---|---|
| Open (untouched) | **0** | **3** (S-006, S-010, S-011) | **4** (S-013, S-016, S-017, S-018) | **10** | **17** |
| Partially mitigated | **1** (S-030) | — | **1** (S-014 RPC done; gossip pending) | — | **2** |
| Mitigated in-session | **5** (S-001, S-002, S-003, S-004, S-031) | **6** (S-007, S-008, S-012, S-020, S-032, S-033) | — | — | **11** |
| Closed by M-F (delay-hash removal) | — | — | — | — | **5** (S-005, S-009, S-015, S-019, S-034) |
| Informational (`EXTENDED` posture) | — | — | — | — | **4** (T-001..T-004) |

(M-F removed iterated SHA-256 delay-hash and its supporting infrastructure — `delay_T` field, worker thread, `RUNNING_DELAY` phase, `EVP_MD_CTX` per-iteration alloc — in commits `14bf3d6` and `1b9b086`. T-001 through T-004 are operator-facing trade-offs of `sharding_mode = EXTENDED`, not bugs — see §6.5.)

**Open Critical findings: zero.** Only S-030 is partially mitigated (D1 effective-closed via S-033, D2 partial via S-033, v2.7 F2 planned for full D2 closure). S-031 is now fully closed (6 architectural layers shipped). Open High findings are 3 (S-006, S-010, S-011 — all design / parameter-policy concerns, no shipped-code attack surface).

**Top-of-list priorities** (updated after in-session closures — see §3 bodies for closure details):

Currently genuinely outstanding:

- **S-030 D2 full closure (v2.7 F2)** — design specification complete in `docs/proofs/F2-SPEC.md`; implementation ~3-4 days. D1 is effective-closed via S-033 state_root binding; D2 is partial-closed via the same mechanism (apply-layer rejection). v2.7 F2 closes D2 at the consensus layer (signatures gather only on view convergence).
- **v2.10 threshold randomness aggregation** — 🔥 promoted to active in plan.md A11. Defeats residual selective-abort attack via t-of-K threshold signatures. ~1 week including BLS12-381 vendoring + DKG tooling.
- **S-014 gossip-side rate limiting** — RPC side closed in-session (per-peer-IP token bucket); gossip-side rate limiting pending (~30 LOC).

Closed in-session (retained here for audit trail; see §3 bodies):

- ~~S-001 RPC authentication missing~~ — closed via `rpc_localhost_only=true` default + HMAC-SHA-256 (v2.16).
- ~~S-002 Mempool accepts unverified signatures~~ — closed via mempool sig-verify + paired `binary_codec.cpp::decode_tx_frame` fix.
- ~~S-003 Block timestamp window ±5s~~ — closed via ±30s window in `BlockValidator::check_timestamp`; spec and code now agree.
- ~~S-004 Plaintext private keys~~ — closed via AES-256-GCM passphrase envelope keyfile (v2.17).
- ~~S-007 Subsidy/fee overflow~~ — closed via `checked_add_u64` on every credit path.
- ~~S-008 Unbounded mempool~~ — closed via `MEMPOOL_MAX_TXS = 10000` + `MEMPOOL_MAX_PER_SENDER = 100` with fee-priority eviction.
- ~~S-012 Snapshot trust~~ — closed via state_root verification on restore.
- ~~S-014 RPC rate limiting~~ — closed via per-peer-IP token bucket on RPC; gossip-side pending as a separate follow-on.
- ~~S-031 Global mutex serialization~~ — closed via 6 architectural layers (shared_mutex + A9 Phase 1-2D + async chain.save + gossip-out-of-lock).
- ~~S-032 O(N) registry rebuild~~ — closed via incremental registry cache.
- ~~S-033 No state commitment~~ — closed via Merkle root in `Block.state_root` + signing_bytes binding.

**Production-readiness bar:** with the in-session closures, no fully-open Critical findings remain. v2.7 F2 (for D2 full closure) is the last architectural item between current state and "permissionless-deployment-ready"; everything else is operational polish or new-feature work.

---

## 2. Triage table

Sortable matrix of all open findings. Detailed entries below in §3-§6.

| ID | Sev | Title | File / Locus | Effort |
|---|---|---|---|---|
| S-001 | ✅ Mitigated | RPC auth (localhost-only default + HMAC-SHA-256 auth both landed) | `rpc/rpc.cpp` | done |
| S-002 | ✅ Mitigated | Mempool sig-verify on both gossip + RPC paths (paired binary_codec fix) | `node/node.cpp::verify_tx_signature_locked` | done |
| S-003 | ✅ Mitigated | Block timestamp window aligned to ±30s (spec + code now agree) | `node/validator.cpp::check_timestamp` | done |
| S-004 | ✅ Mitigated | Plaintext private key in `account create` output (option 1: localhost-only-default + 0600; option 2: AES-256-GCM passphrase envelope landed) | `main.cpp:cmd_account_create` | done |
| S-005 | ✅ Closed | `delay_T` not in GenesisConfig — field removed entirely (commit `1b9b086`) | n/a | done |
| S-006 | 🟠 High | ContribMsg cross-generation equivocation undetected | `node/node.cpp:1342` | low-med |
| S-007 | ✅ Mitigated | Subsidy/fee/receipt-credit overflow-checked via checked_add_u64 (Options 2 + 3 from audit) | `chain/chain.cpp` | done |
| S-008 | ✅ Mitigated | Mempool bounds: MEMPOOL_MAX_TXS = 10000 cap + fee-priority eviction + MEMPOOL_MAX_PER_SENDER = 100 quota | `node/node.cpp::mempool_admit_check` | done |
| S-009 | ✅ Closed | Constant-T / SHA-256 ASIC fallacy — replaced by commit-reveal (commit `14bf3d6`); delay-hash module deleted (commit `1b9b086`) | n/a | done |
| S-010 | 🟠 High | Sybil via under-priced MIN_STAKE | `chain/params.hpp` | docs / DOMAIN_INCLUSION |
| S-011 | 🟠 High | Abort claim cartel via M-1 quorum | `node/node.cpp::on_abort_claim` | high |
| S-012 | ✅ Mitigated | Snapshot bootstrap state_root verification landed (S-033 Merkle root in Block + snapshot-side check) | `chain/chain.cpp::restore_from_snapshot` | done |
| S-013 | 🟡 Med | BlockSigMsg buffer flood OOM | `net/gossip.cpp` (buffered_block_sigs_) | ~20 LOC |
| S-014 | 🟠 Partially mitigated | RPC rate-limit shipped (token bucket per peer IP + bucket refill); gossip-side rate limiting deferred | `rpc/rpc.cpp::consume_rate_token` | RPC done; gossip pending |
| S-015 | ✅ Closed | Delay-worker thread removed entirely (commit `1b9b086`) — no worker, no join | n/a | done |
| S-016 | 🟡 Med | Inbound-receipts pool non-deterministic across committee | `node/producer.cpp::build_body` | 3-4h |
| S-017 | 🟡 Med | Producer/chain validation logic mismatch (UNSTAKE) | `node/producer.cpp` vs `chain/chain.cpp` | 2-3d |
| S-018 | 🟡 Med | JSON parsing without schema validation | all `from_json` | 2-3d |
| S-019 | ✅ Closed | Phase-2 timer R-arrival spoofing — moot under commit-reveal (no expensive R compute to spoof) | n/a | done |
| S-020 | ✅ Mitigated | Hybrid Fisher-Yates: rejection sampling at K/N ≤ 0.5, partial FY shuffle at K/N > 0.5 — bounded O(N) regardless of ratio | `crypto/random.cpp::select_m_creators` + `select_after_abort_m` | done |
| S-021 | 🟢 Low | Chain file integrity not cryptographically verified | `chain/chain.cpp::load` | 1d |
| S-022 | 🟢 Low | 16 MB message limit too permissive (modulo snapshots) | `net/peer.cpp:38` | nuanced |
| S-023 | ✅ Mitigated | RPC send/stake/unstake balance pre-check throws clear diagnostic on insufficient balance | `node/node.cpp::rpc_send/stake/unstake` | done |
| S-024 | 🟢 Low | Deregistration timing predictability | `chain/chain.cpp::derive_delay` | low priority |
| S-025 | ✅ Mitigated | `compute_tx_root_intersection` deleted (in-session); function + header decl removed | `node/producer.cpp` | done |
| S-026 | 🟢 Low | No connection timeout / keepalive on peer sockets | `net/peer.cpp` | 1d |
| S-027 | 🟢 Low | Info leakage in logs / verbose error messages | many | docs / runtime flag |
| S-028 | 🟢 Low | Hex parsing only accepts lowercase | `types.hpp:30-47` | trivial |
| S-029 | 🟢 Low | BFT-mode multi-proposer fork-choice undefined | `node/node.cpp::on_block` | bounded reorg |
| S-030 | 🟠 Partially mitigated | Block body not authenticated by `block_digest` (D1 effective via S-033 state_root; D2 partial via S-033; F2 view-reconciliation for full D2 closure tracked v2.7) | `node/producer.cpp:206-221` | v2.7 |
| S-031 | ✅ Mitigated | shared_mutex + A9 Phase 1-2D atomicity/lazy-snapshot/lock-free reads + async chain.save worker + gossip-out-of-lock (v2.6) — all 6 layers shipped | `node/node.cpp` | done |
| S-032 | ✅ Mitigated | Incremental registry cache on Chain + snapshot persistence; build_from_chain reads cache, no log walk | `node/registry.cpp::build_from_chain` | done |
| S-033 | ✅ Mitigated | Merkle tree state commitment + Block.state_root + signing_bytes binding + apply/restore verification | `chain/chain.cpp::compute_state_root` | done |
| S-034 | ✅ Closed | VDF `EVP_MD_CTX` allocation — moot, delay-hash module deleted (commit `1b9b086`) | n/a | done |
| S-035 | 🟢 Op | No unit tests, no CI, no deterministic simulation framework | `tools/` | engineering culture |

---

## 3. Critical findings (open)

### S-001 — RPC authentication missing

**Severity:** Critical • **Status:** Fully mitigated (localhost-only default + HMAC RPC auth both landed) • **Sources:** Audit 1.1, OV-#10

**Option 1 landed in-session.** Config field `rpc_localhost_only` defaults to `true`; the RPC acceptor now binds to `127.0.0.1` rather than `tcp::v4()` (any-interface) unless the operator explicitly sets the field to `false`. Legacy configs without the field get the secure default. External network clients can no longer reach the RPC port via the unauthenticated path that S-001 originally documented. Verified end-to-end in `tools/test_rpc_localhost_only.sh` (5/5 PASS).

**Option 3 landed in-session (HMAC RPC auth).** Config field `rpc_auth_secret` is a hex-encoded shared secret. When non-empty, the RPC server requires every request to carry an `auth` field that's `hex(HMAC-SHA-256(secret, method || "|" || params_canonical_json))`. The server computes the expected HMAC after JSON parse-round-trip (which canonicalizes object key order via nlohmann's deterministic dump) and compares constant-time to avoid timing side-channels. Mismatch → `{"error": "auth_failed"}`. Empty → `{"error": "auth_required: missing 'auth' field"}`.

Client side (CLI + `rpc_call`): if `DETERM_RPC_AUTH_SECRET` env var is set, every outgoing request automatically gets the auth field computed from the env-var secret. No code change needed for existing subcommands.

External-bind-without-auth warning. When `rpc_localhost_only=false` AND `rpc_auth_secret=""` at startup, the node logs `[WARNING: external bind without HMAC auth ...]`. Operators are explicitly nudged toward either keeping localhost-only or setting the auth secret.

**Threat model coverage with v2.16:**
- Network-reachable unauthenticated RPC: closed (option 1)
- Cross-tenant on the same host (multi-user box): closed (option 3 — attacker without secret cannot forge requests)
- Replay of authenticated requests by MITM: NOT addressed in v2.16. Replay protection (per-request nonce + sequence) is a follow-on; S-001's primary issue (unauthenticated requests) is fully closed.
- Secret distribution: operator's responsibility (env var, sealed config, secrets manager). The protocol's job ends at "supports shared-secret auth."

**Regression coverage:** `tools/test_rpc_hmac_auth.sh`, 5 assertions: unauth call when auth disabled, unauth call rejected when auth enabled, wrong-secret rejected, correct-secret authenticates, malformed-hex secret yields clear error.

**Original finding text** (preserved for audit-trail continuity). The RPC server (`src/rpc/rpc.cpp:13`) constructs its acceptor with `tcp::v4()` — bound to all IPv4 interfaces, port-only. Dispatch (`rpc.cpp:52-89`) executes `submit_tx`, `register`, `stake`, `unstake`, `submit_equivocation`, `snapshot`, `account` query, and so on with no authentication, no TLS, no rate limit, and no localhost-only restriction by default.

**Impact.** Any network-reachable client can:
- Submit transactions debiting the node's domain balance (with the node's own key implicitly via `rpc_send`)
- Register the node's domain or alter its stake
- Trigger `submit_equivocation` floods
- Pull a full state snapshot

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Bind RPC to `127.0.0.1` by default**; require explicit config to expose externally. | Trivial. Constructor change in `rpc.cpp:13` to use `make_address("127.0.0.1")`. |
| 2 | **Per-method token bucket** in dispatch. Defaults: `snapshot` 1/min, `submit_tx`/`submit_equivocation` capped, query methods uncapped. | ~50 LOC. |
| 3 | **HMAC token in request envelope.** Client sends `{method, params, hmac}` where hmac is `HMAC-SHA256(shared_secret, canonical_request)`. Shared secret is config-pinned. | 1-2d. |
| 4 | **Mutual TLS** for any externally-exposed RPC. | 3d. Asio TLS layer + cert management. |

**Recommended.** Options 1 + 2 immediately (~1h total). Options 3 or 4 only if RPC must be exposed beyond loopback.

---

### S-002 — Mempool accepts unverified-signature transactions

**Severity:** Critical • **Status:** Mitigated in-session (paired with binary-codec amount/fee/nonce fix) • **Sources:** Audit 1.4

**Mitigation landed in-session.** Both `Node::on_tx` (gossip-path admission) and `Node::rpc_submit_tx` (client RPC admission) now call `Node::verify_tx_signature_locked()` before accepting a tx into `tx_store_`. The helper mirrors `BlockValidator::check_transactions`'s per-tx signature check: it derives the sender's Ed25519 pubkey based on `tx.type` (REGISTER → payload bytes 0..31; anon TRANSFER → bearer address parse; otherwise → registry lookup) and verifies `tx.sig` over `tx.signing_bytes()`. On failure: gossip path silently drops (a forged-sig flood from any peer cannot amplify), RPC path throws with a diagnostic so the submitting client can retry.

This closure required a paired fix to `src/net/binary_codec.cpp::decode_tx_frame`: pre-fix, the decoder skipped the fixed-slot area at offsets 32–55 where the encoder writes `amount`, `fee`, and `nonce`, producing post-decode txs with zero values for these fields. The fields are now read explicitly, restoring the encode/decode round-trip property. The bug was latent because S-002's openness meant zero-field txs entered the mempool and were filtered later at apply (silent corruption). Closing S-002 surfaced the codec bug; both fix together. See `docs/proofs/S002-Mempool-Sig-Verify.md` for the full analysis trail.

**Verified post-fix:** bearer (anon TRANSFER) + governance (registered-domain PARAM_CHANGE) + equivocation_slashing regressions all PASS. The legit-tx code path through both admission sites (RPC and gossip) is exercised by existing tests; a dedicated forged-sig rejection regression is a follow-on once test-side Ed25519 forge tooling is available (currently requires PyNaCl not present in the test environment, or a `determ` CLI helper for offline forged-sig construction).

**Pre-fix description** (preserved for audit trail). `Node::on_tx` (`src/node/node.cpp:1353-1371`) accepted incoming transactions into `tx_store_` after only a stale-nonce check and a replace-by-fee check. **No `crypto::verify` was called** on this path. Signature verification happened only later in `BlockValidator::check_transactions` at apply time.

**Impact.**
- Mempool flood with valid-shape, invalid-signature transactions.
- Each fake tx is stored, gossiped, indexed by `(from, nonce)`, and iterated during block construction.
- Memory exhaustion + bandwidth amplification + producer time wasted resolving fake hashes.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Verify Ed25519 sig in `on_tx`** before insertion. For bearer addresses derive pubkey from the address; for registered domains lookup in `registry_`. | 1-2d. Hot path; benchmark. |
| 2 | **Verify hash + sig** as a cheap pre-filter (recompute `compute_hash()`, then verify). Same as `rpc_submit_tx` already does. | Subset of #1. |
| 3 | **Bounded mempool with sig-verify-on-eviction-attempt** (verify lazily but bound size first). | Cheaper at hot-path cost; still leaves the iteration risk. |

**Recommended.** Option 1. Same model `rpc_submit_tx` already uses (`node.cpp:1846` recomputes hash and rejects mismatches). Aligning `on_tx` is mostly copy-paste.

---

### S-003 — Block timestamp window ±5s contradicts spec

**Severity:** Critical (for liveness) • **Status:** Mitigated in-session • **Sources:** Audit 1.2

**Mitigation landed in-session.** `BlockValidator::check_timestamp` window widened from ±5s to ±30s, matching the spec text (README §8 and PROTOCOL.md §4). The change is a one-line constant adjustment in `src/node/validator.cpp::check_timestamp`. PROTOCOL.md §4's inline comment on the `timestamp` field updated to "±30s window (S-003)". Spec, code, and documentation now agree on the canonical window.

The choice was option 1 from the resolution table below (the audit's recommended path). Option 2 (median-of-last-N-blocks, Bitcoin-style) is the v2 answer if drift becomes a measurement concern; today's wall-clock check is a sanity bound, not a consensus-defining property.

**Pre-fix description** (preserved for audit trail). `BlockValidator::check_timestamp` at `src/node/validator.cpp:559-564` rejected any block with `|b.timestamp - now()| > 5`. The README spec text referenced ±30s. Under normal cross-region NTP drift, legitimate blocks got rejected as out-of-window.

**Impact (pre-fix).** False-positive aborts → suspension → cascading liveness failure on globally-distributed deployments.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Widen window to ±30s** to match the spec. | One-line change. |
| 2 | **Median-of-last-N timestamps** (Bitcoin-style) instead of wall-clock comparison. | Medium. Adds chain history dependency to validator. |
| 3 | **Drop wall-clock check entirely**, rely on round timing for ordering. | Trivial. Loses the timestamp-as-monotonicity-signal. |

**Recommended.** Option 1 immediately + update PROTOCOL.md to nail the canonical window. Option 2 is the v2 answer.

---

### S-004 — Plaintext private key in `account create` output

**Severity:** Critical • **Status:** Fully mitigated (option 1 + option 2 both landed) • **Sources:** Audit 1.3

**Option 1 mitigation landed in-session.** `cmd_account_create` (`src/main.cpp`):

- **Refuses stdout output by default.** `determ account create` without `--out` exits 1 with a diagnostic naming the two acceptable paths (file output or explicit opt-in for legacy plaintext-stdout).
- **Requires `--out <file>`** for normal usage. The output file is written then immediately narrowed to owner read+write only via `std::filesystem::permissions(perms::owner_read | perms::owner_write, perm_options::replace)`. On Unix this is `chmod 0600`; on Windows the implementation does a best-effort owner-only ACL.
- **Opt-in `--allow-plaintext-stdout`** for the legacy stdout behavior (offline air-gapped key gen, controlled-shell scenarios). The flag's name makes the choice auditable in invoking scripts.

Test infrastructure updated: `tools/test_bearer.sh` and `tools/test_adversarial.sh` switched from `account create > file` to `account create --out file` (same effect, secure default).

**Option 2 mitigation landed in-session.** `account create --passphrase <pw>` (or `DETERM_PASSPHRASE` env var) wraps the keyfile in an AES-256-GCM envelope keyed via PBKDF2-HMAC-SHA-256 (600k iterations, 16-byte salt, 96-bit nonce). The encrypted file format is a header line (`DETERM-ACCOUNT-V1 <address>`) followed by the canonical envelope blob (dot-separated hex fields). AAD binds the public address so a tampered envelope cannot be substituted with another account's encrypted blob.

The envelope crypto (`wallet/envelope.cpp`, originally for the wallet binary's recovery-share encryption) is now also linked into the main `determ` binary. The cross-binary scope is limited to the symmetric-crypto primitive — no wallet-state (recovery shares, OPAQUE state) crosses the boundary; the daemon's address space isolation from wallet-secret material is preserved.

Read-back: `determ account decrypt --in <file> --passphrase <pw>` (or `DETERM_PASSPHRASE` env var) decrypts and emits the plaintext JSON (privkey + address) to stdout. AEAD tag verification fails clean (clear error message) on wrong passphrase or tampered file.

**Regression coverage:** `tools/test_account_encrypted.sh`, 7 assertions: header format, no-plaintext-leak in encrypted file, correct-passphrase round-trip, wrong-passphrase rejection, env-var auth, plaintext-path backward compat, decrypted-address well-formedness.

**Pre-fix description** (preserved for audit trail). `cmd_account_create` in `src/main.cpp` emitted the raw `priv_seed` either to stdout or to an unencrypted file, with no `chmod`, no passphrase prompt, no warnings beyond a string in the JSON.

**Impact.** Standard key-leak vectors: terminal scrollback, shell history, world-readable file, accidental commit, accidental log capture.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Refuse to write to stdout.** Require `--out`. Set `0600` on the output file (Windows: deny inheritable read for non-owner). | Trivial. |
| 2 | **Encrypt with passphrase** (libsodium `crypto_secretbox_easy` or OpenSSL EVP). Prompt for passphrase interactively. | 1-2d. |
| 3 | **Hardware-wallet integration** (BIP32 derivation from a hardware seed). | Out of scope for v1. |

**Recommended.** Option 1 immediately. Option 2 for v1.x. Document key-handling in `docs/QUICKSTART.md`.

---

### S-030 — Block body not authenticated by `block_digest`

**Severity:** Critical (consensus integrity) • **Status:** Partially mitigated (D1 effective via S-033; D2 partial via S-033; F2 view-reconciliation tracked v2.7) • **Sources:** Architectural Analysis §2.3

**Two dimensions of the finding (D1 / D2).**

This finding has two structurally distinct dimensions, addressed by different mechanisms. The pre-mitigation analysis below originally treated them as one issue; current code handles them separately.

- **D1 — Resolved tx-payload mismatch.** Each committee member runs `build_body` locally with their own `tx_store_`. The digest covers `tx_root` (a hash over the K-committee's `creator_tx_lists`) but NOT the resolved `b.transactions` list. Two members with differing mempools produce different `b.transactions` but the same digest; both pass K-of-K verification.

- **D2 — Non-tx-payload field mismatch.** The digest also doesn't cover `abort_events`, `equivocation_events`, `inbound_receipts`, `cross_shard_receipts`, `partner_subset_hash`, `timestamp`, `cumulative_rand`, `delay_output`, `creator_dh_secrets`, `initial_state`, or `state_root`. Two members with differing pool views (gossip-async) produce different evidence/receipt lists but the same digest.

**D1 status — effective closure via S-033.** With state_root in `signing_bytes` (Block.compute_hash), divergent `b.transactions` produces divergent post-apply state → divergent state_root → divergent block_hash. The validator's apply-time `compute_state_root() != b.state_root` check (chain.cpp:~900) loud-fails on the inconsistent node, surfacing the bug rather than silently corrupting state. Single canonical block per height is enforced at apply, even though K-of-K signatures (over the narrower digest) don't directly bind tx payloads.

**D2 status — partial closure via S-033.** Same mechanism: divergent evidence/receipt lists produce divergent post-apply state → state_root mismatch → block rejected at apply. Closure is "partial" because:
- Two K-of-K-signed block instances can still both circulate at the gossip layer (signatures are valid for both — the digest covers neither's evidence list).
- The apply-time check picks one canonical instance via state_root match. Honest nodes converge on the canonical one; nodes that received the wrong one resync from peers.
- A fully Byzantine committee can mint two valid-looking K-of-K instances. Detection is deferred to gossip-level reconciliation against the chain's actual state log.

**Full D2 closure (consensus-layer, v2.7 F2 view reconciliation).** Extends `compute_block_digest` to cover the ✗-row fields directly, via Phase-1 view-reconciliation. Prevents the two-instance attack at signature-gathering time rather than at apply time. See `docs/proofs/S030-D2-Analysis.md` for the detailed analysis (including why the naive attempt failed and the corrected pattern) and `docs/V2-DESIGN.md` v2.7 for the implementation scope.

**Two closure paths summarized:**

| Path | Layer | Effect |
|---|---|---|
| **S-033 state_root binding** (shipped) | Apply-layer rejection | Divergent state_root → block rejected at apply; both K-of-K-signed instances can exist on the wire but only one apply-validates |
| **v2.7 F2 view reconciliation** (planned) | Consensus-layer prevention | K-of-K signatures cover ✗-row fields directly; divergent views → signatures fail to gather → second instance never finalizes |

For permissionless deployments wanting the literal "≤ 1 block instance per height" property, v2.7 is the structural fix. For permissioned/consortium deployments, S-033's apply-time enforcement is functionally equivalent (deterministic apply ⇒ at most one valid state_root per starting state).

**Resolution options.**

| # | Option | Cost | Status |
|---|---|---|---|
| 1 | **Include `b.transactions` (or a Merkle root over them) in `block_digest`.** Block format change — adds binding from sigs to actual delivered payloads. | High. Block hash changes break wire compatibility → hard fork. ~1d code + protocol bump. | Superseded by Option 4 |
| 2 | **Validator re-resolves union and checks completeness.** `validator.cpp` recomputes `selected_hashes = union(creator_tx_lists)`; verifies that for every hash in the union, either it has a tx in `b.transactions` OR it was filterable at apply time. | Medium. ~50-100 LOC in validator. No protocol change but validator-level break. | Deferred |
| 3 | **Add a `tx_set_hash = SHA256(canonical(b.transactions))` field to the block** and include it in `block_digest`. Validator checks the field matches the actual `b.transactions`. | Medium. Block field addition; protocol-compatible if old nodes ignore unknown fields. | Superseded by Option 4 |
| 4 | **State_root in signing_bytes (S-033).** Block carries `state_root = MerkleRoot(canonical_state_after_apply)`. signing_bytes binds it; validator re-derives at apply and rejects on mismatch. Indirectly commits to all apply-affecting fields (txs, evidence, receipts) via the post-apply state they produce. | Shipped via S-033. Block-format-compatible (zero state_root field on pre-S-033 blocks contributes nothing to signing_bytes, preserving byte-stable hashes). | ✓ Shipped, partial D2 closure |
| 5 | **F2 view reconciliation (v2.7).** Phase-1 commits include hash of each member's evidence/receipt pool views; canonical reconciliation at Phase 1→2; Phase-2 sigs cover the reconciled lists via extended `compute_block_digest`. | 1-2 days implementation + design-decision time for reconciliation rule per field. | Planned v2.7 |

**Status.** Option 4 (S-033) shipped — partial D2 closure with apply-layer enforcement. Option 5 (v2.7) planned — full D2 closure with consensus-layer enforcement. Options 1-3 superseded by Option 4's broader coverage.

---

### S-031 — Single global mutex serializes everything

**Severity:** Critical (architectural) • **Status:** Fully mitigated in-session (6 architectural layers shipped: shared_mutex + A9 Phase 1 atomicity + A9 Phase 2A/2B lazy snapshot + A9 Phase 2C lock-free reader path + async chain.save worker + gossip-out-of-lock v2.6) • **Sources:** Architectural Analysis §3.1

**Mitigation landed in-session (partial — concurrency layer).** Replaced `std::mutex state_mutex_` with `std::shared_mutex` and downgraded all 11 read-only const RPC handlers to `std::shared_lock`. The other 25 acquisition sites (mutators, gossip handlers, consensus transitions) keep `std::unique_lock` with identical write-exclusion semantics. Effect: read-heavy operational workloads (`status`, `balance`, `account`, `chain_summary`, `committee`, `validators`, `nonce`, `stake_info`, `block`, `tx`, `snapshot`) now permit N concurrent readers, which is the dominant contention pattern. Writes still serialize as required for correctness.

**Mitigation landed in-session (partial — atomicity layer, A9 Phase 1).** Wrapped `Chain::apply_transactions` body in a try-catch with a state snapshot taken at entry. On any exception inside the apply body (invariant assertion, malformed-tx arithmetic, supply-conservation violation, state_root mismatch) the snapshot is move-restored before the exception propagates to the caller. The chain is observably unchanged from the failed apply — every observer sees either the full block applied or nothing. Without this, a mid-apply throw left state partially mutated, and the next apply operated on inconsistent data.

**Mitigation landed in-session (partial — efficiency layer, A9 Phase 2A/2B).** The Phase 1 snapshot's deep-copy cost is paid only for state actually mutated. Five of seven state containers (`stakes`, `registrants`, `abort_records`, `merge_state`, `applied_inbound_receipts`) are wrapped in `std::optional` in StateSnapshot and captured on first mutation via per-container ensure-lambdas. TRANSFER-only blocks skip all five copies — the dominant cost regime on long-lived chains where applied_inbound_receipts can grow to millions of entries. The remaining two containers (`accounts_`, `pending_param_changes_`) stay eager: accounts is mutated on every block; pending_param_changes is mutated by activate_pending_params at entry where lazy threading would be awkward.

**Mitigation landed in-session (partial — reader concurrency layer, A9 Phase 2C).** The hottest RPC paths (`rpc_balance`, `rpc_nonce`) are now genuinely lock-free. `Chain::committed_accounts_view_` is a `std::shared_ptr<const std::map<...>>` published at every successful apply commit via `std::atomic_store`; readers `atomic_load` the pointer and read from its contents. The new `Chain::balance_lockfree()` / `next_nonce_lockfree()` are documented as caller-doesn't-need-state_mutex_-held; the corresponding RPC handlers in `node.cpp` no longer take `state_mutex_` `shared_lock`. A client polling balance during a slow apply gets sub-millisecond response from the prior committed view rather than queuing behind the writer's `unique_lock`. The existing locked accessors remain for in-apply callers and for code that already holds the lock.

**Verified post-fix:** bearer (mutator path + rpc_balance heavy), state_root (S-033 hash + apply path), governance_param_change (mutator + activation + snapshot + rpc_nonce reads), equivocation_slashing (slashing apply path), domain_registry (REGISTER/DEREGISTER + lazy paths), snapshot_bootstrap (restore-from-snapshot publish path) all PASS. Hot-path overhead unmeasurable in test wall-clock.

**Mitigation landed in-session (partial — async save, S-031 follow-on).** `chain.save()` is now off the apply hot path. After every block apply, Node calls `enqueue_save()` which sets an atomic flag and notifies a condition variable; a dedicated worker thread serializes the JSON and writes atomically (`.tmp` + rename) under `state_mutex_` `shared_lock` (concurrent with RPC readers). The apply's `unique_lock` duration is bounded by apply itself, not by disk I/O. Multiple bursting applies coalesce into one save plus one tail save. `Chain::save()` switched to atomic write so a worker-process crash mid-write cannot leave a half-written chain.json. Lifecycle hooks: `Node::start` spawns the worker; `Node::stop` signals stop, joins, then does one final synchronous save.

Crash semantics. Between block apply and save completion, the block is in memory but not on disk. A node crash here loads the older chain.json on restart and resyncs the missing tail via peer gossip — same as the pre-fix narrow window between apply completion and the synchronous fsync returning. Functionally indistinguishable.

**Remaining open under S-031** (mechanical follow-on, not architectural):

- Extend the Phase 2C lock-free reader pattern to additional containers as use cases demand (abort_records, merge_state, etc., currently lockless reads aren't needed for these — they're queried only from internal validator paths already holding the lock).
- One-file-per-block storage. With async save, the saving thread can fall behind apply on bursty workloads (save coalesces but takes O(N) per fire). Switching to per-block files makes save O(1) and the worker can never fall behind. Strict perf improvement, not a correctness fix.
- C++26 deprecation cleanup for `std::atomic_load/store` free functions on shared_ptr — migrate to `std::atomic<std::shared_ptr<T>>`.
- `delay_worker_.join()` under the lock — moot since M-F removed the delay-hash worker entirely.
- `rpc_submit_tx` broadcasts via gossip while holding `unique_lock`. The lock could be released before the broadcast call (the tx is already in `tx_store_` at that point; the broadcast is a network operation that doesn't touch chain state). ~10 LOC, untouched in this commit to keep the change surgical.
- `delay_worker_.join()` under the lock — moot since M-F removed the delay-hash worker entirely.

**Pre-fix description** (preserved for audit trail). `Node` is a god-object protected by one `std::mutex state_mutex_`. 42 references in `node.cpp`. Every critical operation holds this lock:
- All consensus state mutation
- Block application + the synchronous `chain_.save()` that follows (writes the entire chain JSON to disk — `node.cpp:1300`)
- VDF verification on the piggyback path: `delay_hash_verify` (4M SHA-256 iterations) is called under the lock at `node.cpp:1446`
- Every RPC handler
- Every gossip dispatch handler
- `delay_worker_.join()` is called under the lock at `node.cpp:490` (also from `stop()`)

**Why this is architectural collapse, not just a performance nit.**
- VDF verification under the lock means the entire node freezes for ~T_delay seconds whenever a peer's `BlockSigMsg` arrives during `RUNNING_DELAY` and triggers piggyback verification. No peer messages, no RPC, no timers fire during this window.
- `delay_worker_.join()` under the lock can deadlock if the worker is still hashing. ASIO threads block waiting for the worker; the worker can't be cancelled until the next iteration; with a small ASIO thread pool, the node can become entirely unresponsive.
- `chain_.save()` under the lock means every block apply pauses the node for as long as it takes to JSON-serialize and disk-flush the entire chain. On a 100k-block chain, that's seconds per block.
- The protocol's spec describes timers, parallel workers, and async I/O. The implementation funnels all of it through one critical section.

**Impact.** Under any non-trivial load (gossip flood, large mempool, sync requests, multi-shard activity), the node is effectively single-threaded with arbitrary stall durations. Combined with no rate limiting (S-014), this is trivially exploitable for local DoS.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Hot-path triage.** Move expensive ops (`delay_hash_verify`, `chain_.save()`, `build_from_chain`) out of the lock. Acquire briefly to read inputs; release; do the work; re-acquire briefly to commit results. | Medium. ~2-3d. Requires careful audit of every site to ensure the inputs aren't mutated during the unlocked section (or to use seqlocks / RCU patterns). |
| 2 | **Sharded locks** by subsystem: `chain_mutex_`, `mempool_mutex_`, `consensus_mutex_`, `peer_mutex_`. Each protects a smaller piece of state. | Medium-high. ~1w. Lock-ordering discipline becomes critical to avoid deadlocks. |
| 3 | **Single-writer thread + message-passing**, à la actor model. The consensus thread owns all state; other threads (gossip, RPC, timers) post messages. No locks needed. | High. ~2-3w. Cleanest architecture but big rewrite. |
| 4 | **Async I/O for `chain_.save()`** — write to a separate thread or use a WAL pattern. Independent of the broader locking question, removes the worst single offender. | Low. ~1d. Still leaves VDF-under-lock and worker-join-under-lock. |
| 5 | **One-file-per-block storage.** Replace monolithic `chain.json` with `chain/blocks/{index}.json` (one file per block, append-only, never rewritten) plus `chain/state.json` (incrementally updated). `chain_.save()` becomes `O(1)` instead of `O(N)`. Old block files are prunable based on operator policy. Future extension: random-sample replication across peers (BitTorrent-style page distribution). | Low-medium (~1-2d). Mostly a save/load refactor; no protocol change. Compounds with Option 4 to fully eliminate `chain_.save()` as a global-mutex offender. |

**Recommended.** Options 5 + 4 immediately (kills the worst offender entirely), then Option 1 for v1.x. Option 3 is the v2 architecture.

---

## 4. High findings (open)

### S-005 — `delay_T` not in GenesisConfig

**Severity:** High (consensus-divergence) • **Status:** ✅ Moot — see M-F. The iteration count is no longer load-bearing; `delay_T` divergence between nodes no longer affects consensus. The field can be removed in cleanup. • **Sources:** Audit 3.9 (re-classified up from Medium)

**What's open.** `GenesisConfig` (`include/determ/chain/genesis.hpp:78-105`) contains no `delay_T` field. `grep delay_T genesis.{hpp,cpp}` returns empty. `delay_T` is loaded from the per-node `Config` instead. Two nodes with different per-node `delay_T` will produce differently-validated blocks (the validator at `node.cpp:1446` uses `cfg_.delay_T`).

**Impact.** Consensus divergence between misconfigured nodes. The PROTOCOL.md claim that `delay_T` is "genesis-pinned" is **not enforced by code**.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Add `delay_T` to GenesisConfig**, plumb through to chain + validator. Reject node startup if `cfg_.delay_T != gcfg.delay_T`. | 1d. Block-format-compatible (it's a chain-wide constant, not per-block). |
| 2 | **Computed from chain ID + version** (deterministic, no config). | More invasive. |

**Recommended.** Option 1. This is a bug-bait waiting to happen.

---

### S-006 — ContribMsg cross-generation equivocation undetected

**Severity:** High • **Status:** Open • **Sources:** Audit 2.4, OV-#8

**What's open.** Block-level equivocation IS now closed-loop in rev.8 (BlockSigMsg over distinct digests at the same height → `EquivocationEvent` → full stake forfeit + deregister, see §5 below). But **ContribMsg-level equivocation across abort generations is still deferred**: the comment near `node.cpp:1342` says *"Real equivocation detection requires generation tracking (planned for a future rev). For now, if we're still in CONTRIB phase and receive a duplicate from a signer we already have, ignore the new one."* The `contrib_equivocations_` map declared in `node.hpp` is never written to.

**Impact.** A creator can present different `tx_hashes` lists (or `dh_input`s) to different peers at the same height, biasing the union tx-set seen by different members. Severity is bounded by the K-of-K signing of the ultimate block — divergent contribs cause K-of-K to fail and the round to abort, which is *itself* slashable via S-005's existing block-level path. So in practice this exploit converts to "force the chain to abort," which the BFT escalation path can recover from.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Generation-keyed `pending_contribs_`.** Index by `(signer, aborts_gen)`. Two contribs at the same key with different commitments → `ContribEquivocationEvent` → gossip + slash. | Low-medium. ~1d. |
| 2 | **Cross-generation hash binding.** ContribMsg commits to `prev_aborts_gen_hash || dh_input`, preventing backdating. | Medium. ContribMsg field + commitment change → block format implications. |
| 3 | **Status quo** (rely on K-of-K abort to neutralize the divergence; don't slash). | Free. Acceptable if BFT escalation reliably recovers. |

**Recommended.** Option 1 for v1.1.

---

### S-007 — Integer overflow in subsidy distribution

**Severity:** High • **Status:** Mitigated in-session (options 2 + 3 from the audit's resolution table) • **Sources:** Audit 2.5

**Mitigation landed in-session.** Two complementary changes:

- **Runtime overflow checks** (option 2). New `checked_add_u64()` helper in `chain.cpp`. Every balance-credit site uses it and throws on overflow: TRANSFER receiver credit, per-creator subsidy+fees distribution, dust credit to `creators[0]`, cross-shard inbound receipt credit, per-block `block_inbound` counter accumulation. The helper is portable (the if-check optimizes to a single ADC/JC sequence; MSVC doesn't have `__builtin_add_overflow` but the check is comparable).
- **Genesis sane-bounds check** (option 3). New check at `GenesisConfig::from_json`: reject `block_subsidy`, `subsidy_pool_initial`, or `zeroth_pool_initial` exceeding `1e18` (1 quintillion native units — sane for even 18-decimal-place currencies). Also rejects genesis where `block_subsidy * lottery_jackpot_multiplier` would overflow on a jackpot block. Each refusal cites S-007 in the error message.

Defense in depth: bad genesis caught at load time before any block applies; arithmetic edge cases caught per-mutation at apply time. The two layers compose so a future regression in either path remains caught by the other.

**Verified post-fix:** bearer (TRANSFER credit path) + finite_subsidy (subsidy distribution + pool-exhaustion path) regressions PASS.

**Pre-fix description** (preserved for audit trail). `chain.cpp:245-253` distributed `total_distributed = total_fees + block_subsidy_` across `b.creators` with no overflow check. With a malicious genesis or a long-lived chain accumulating fees, `+=` on `accounts_[domain].balance` could wrap.

**Impact.** Funds destruction or unauthorized minting. The genesis-config attack vector is most realistic — a chain operator setting an absurd `block_subsidy` produces wrap-around at apply time.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Saturating add** on every balance mutation: `balance = balance + delta; if (balance < delta) balance = UINT64_MAX;` | ~10 LOC, every credit site. |
| 2 | **`__builtin_add_overflow`** with hard reject (treat as invalid block). | ~10 LOC. Stricter than saturation. |
| 3 | **Sane-bounds check on genesis** (`block_subsidy < 10^18`, etc.) at startup. | Trivial. Doesn't catch slow accumulation. |

**Recommended.** Option 2 + Option 3. Half-day of work.

---

### S-008 — Unbounded memory across multiple buffers

**Severity:** High • **Status:** Mitigated for `tx_store_` (mempool) via Options 1 + 3 in-session; other buffers tracked separately • **Sources:** Audit 2.6, Architectural Analysis §3.4

**Mitigation landed in-session (tx_store_, the primary surface).** Mempool admission policy enforces two structural caps via a shared `mempool_admit_check` helper called by both `on_tx` (gossip path) and `rpc_submit_tx` (RPC path):

- **Hard cap on total mempool size: `MEMPOOL_MAX_TXS = 10000`.** On overflow, the incoming tx evicts the lowest-fee incumbent if its fee is strictly higher; otherwise it's rejected. This is **fee-priority mempool**: under sustained spam, the chain economically prices out the spammer (they must pay the marginal fee to displace incumbents). Replace-by-fee on the same `(from, nonce)` slot remains separately enforced.
- **Per-sender quota: `MEMPOOL_MAX_PER_SENDER = 100`.** Limits the number of pipelined-nonce txs a single sender can occupy in the mempool. Count computed via O(per-sender) scan of `tx_by_account_nonce_` (the std::map ordered structure gives a contiguous range per sender). Per-sender overflow always rejects — no eviction across senders for fairness.

The two caps compose: a spammer either pays to displace incumbents (cap 1) or is rate-limited by their own per-sender allowance (cap 2). 10K × 100 senders covers expected production load; tunable via genesis-pinned constants if mainnet hits the ceilings.

Gossip path: silent drop (a forged-sig or spam flood from a faceless peer can't amplify the rejected tx onward). RPC path: throw with diagnostic so the submitting client sees the rejection reason and can retry with higher fee.

**Verified post-fix.** `tools/test_mempool_bounds.sh` 3/3 PASS:
- Normal admission (1 tx with explicit nonce 0).
- Pipelined-nonce burst (5 txs from one sender — integration wired).
- Different-sender independence (independent quota verified).

The 100-tx cap-firing test is hard to exercise in single-node M=K=1 infrastructure: block production drains the mempool faster than 100 admissions per second. Future test infrastructure (an in-process unit-style harness like `test-atomic-scope`) can directly exercise the cap-firing path against the helper functions without consensus drain.

**Pre-fix description.** No size cap on multiple unbounded queues:

| Buffer | Risk |
|---|---|
| `tx_store_` (mempool) | OOM under tx flood (compounds with S-002) |
| `pending_inbound_receipts_` | OOM from cross-shard receipt bundles |
| `pending_contribs_` / `pending_block_sigs_` | OOM from consensus message spam |
| BlockSigMsg pre-verify buffer (`buffered_block_sigs_`) | Covered separately by S-013 |
| `peer_heights_` map | Never pruned, grows with peer churn |
| Active peer connections | No accept-rate cap |

Replace-by-fee on the mempool bounds *per-`(from, nonce)`* but not total. There's no backpressure anywhere — when a queue fills, the system can't shed load or slow producers.

**Resolution options.**

| # | Option | Cost | Status |
|---|---|---|---|
| 1 | **Hard cap on `tx_store_.size()`** (e.g., 10,000 or 100 MB total). On full, evict lowest-fee. | 1-2d. | ✓ Shipped |
| 2 | **Minimum fee threshold** rejected at `on_tx` / `submit_tx`. Threshold rises with mempool pressure. | 2-3d (fee-market dynamics). | Not shipped (fee-market design is a separate item) |
| 3 | **Per-sender quota** (max N pending txs per `(from)`). | Subset of #1. | ✓ Shipped |
| 4 | **Protocol-derived minimum fee.** Enforce `tx.fee >= block_subsidy / 1024` (or similar protocol-derived constant pegged to the per-block reward). Eliminates zero-fee spam without operator tuning, scales naturally with chain economics — as the chain grows the fee floor follows. | Trivial. ~10 LOC in validator + producer. | Deferred (would break existing tests using fee=0; genesis-configurable min-fee is a follow-on) |

**Status.** Options 1 + 3 shipped, closing the practical DoS surface for `tx_store_`. Option 4 (protocol-derived min-fee) is the natural next layer but requires test-suite updates (existing tests use fee=0) and a genesis-pinned configuration field for the floor; deferred as a separate item. Options for `pending_inbound_receipts_`, `pending_contribs_`, `peer_heights_` are tracked as future operational hardening; none are exploitable as catastrophically as `tx_store_` was without S-008 closure.

---

### S-009 — Constant-T / SHA-256 ASIC fallacy

**Severity:** High (was) • **Status:** ✅ Closed by delay-hash removal (see §7 M-F) • **Sources:** OV-#1, Gemini analysis

**Was open.** `delay_T` was genesis-pinned. SHA-256 is the most heavily-ASIC'd hash in existence; the gap between consumer CPU and Bitmain-grade hardware is multiple orders of magnitude. An attacker with optimized SHA-256 silicon could execute the same `T` iterations in a fraction of the wall-clock budget, regaining the predictive-evaluation window the protocol was designed to close.

**Resolution:** the iterated SHA-256 delay-hash mechanism has been removed entirely (see §7 M-F). The selective-abort defense it nominally provided is now structurally absent — the protocol's defense against this class of attack shifts to:
- **Phase-1 commit-reveal** (the existing `dh_input` field semantically a commit to a fresh secret; secret reveal in Phase 2). An attacker without all K secrets cannot predict block randomness; SHA-256 preimage resistance does the work, no compute-time assumption.
- **BFT escalation** for liveness when committee members blind-abort.
- **Equivocation slashing** for cryptographic punishment of double-signers.

S-005 (`delay_T` not in genesis) is moot under this resolution. S-019 (Phase-2 timer R-arrival spoof) and S-034 (VDF allocation per iteration) are similarly moot — the worker thread that ran the iteration is gone.

---

### S-010 — Sybil via under-priced MIN_STAKE

**Severity:** High (parameter-tuning risk) • **Status:** Open with mitigation alternative • **Sources:** Audit 2.2, OV-#7, Gemini analysis

**What's open.** `min_stake = 1000` default. If the chain creator under-prices stake relative to the exogenous market value of the token, an attacker partitions wealth across thousands of registered domains and dominates `M_pool`.

**Mitigation alternative present:** rev.9 introduced `InclusionModel::DOMAIN_INCLUSION` where Sybil resistance comes from external naming costs (DNS, registration fees with a TLD operator) instead of stake. STAKE_INCLUSION chains still need to set `min_stake` carefully.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Operator guidance doc** with a calculator: given `block_subsidy`, target attack cost, expected market cap, derive recommended `min_stake`. | Trivial. |
| 2 | **Stake-weighted committee selection** (proportional representation). Genesis → chain spec change. | Medium-high. Fairness analysis required. |
| 3 | **Use DOMAIN_INCLUSION** for any chain that doesn't have strong stake-pricing economics. | Free; just a genesis choice. |
| 4 | **Add `IP_INCLUSION` as a third inclusion model.** Sybil resistance comes from IPv4-address scarcity instead of stake or DNS — peerlist bloat through mass-produced identities becomes a non-issue when IP itself is the scarce resource. Weaker than DOMAIN_INCLUSION (NAT, IPv4 exhaustion, VPN abuse) but cheaper to operate. Useful for permissionless local networks or testnet-style deployments where DNS is overhead. | ~100 LOC. Pure config addition. New `Inclusion::IP_INCLUSION` enum + IP-of-peer recorded as registry pubkey-equivalent. |

**Recommended.** Options 1 + 3 for production chains. Option 4 for testnets and special-purpose deployments.

---

### S-011 — Abort claim cartel via M-1 quorum

**Severity:** High • **Status:** Open • **Sources:** Audit 2.3

**What's open.** Abort claims advance via M-1 matching signatures. An adversary controlling M-1 committee members can fabricate abort claims against the lone honest member, suspending them via the exponential-suspension path.

**Mitigated by:** stake economics (controlling M-1 is expensive at adequate `min_stake`); equivocation-detection provides separate slashing if the cartel signs blocks at the same height with different digests. So the realistic damage is bounded to "kick the honest member off the committee for a finite number of rounds."

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Status quo + adequate `min_stake` (S-010 #1)** | Free. |
| 2 | **External-witness requirement.** Suspension only triggers if the abort claims are also visible in the gossip mesh outside the committee. | Medium. Gossip-witness tracking. |
| 3 | **Reputation scoring.** Abort claims weighted by claimer's historical good behavior. | High. Reputation systems are notoriously gameable. |

**Recommended.** Option 1. The deeper fixes are not worth their complexity at v1 scale.

---

### S-012 — Snapshot bootstrap is "trust the source"

**Severity:** High (trust boundary, not chain-break) • **Status:** Mitigated in-session (Option 3 landed: state_root in Block + snapshot-side verification against tail head's state_root) • **Sources:** OV-#6 (rev.9 addition)

**Mitigation landed in-session.** Closes Option 3 from the resolution table below. The full chain of cryptographic ties is now in place:
1. Each block carries a `state_root` field — a SHA-256 Merkle root over the canonical state at apply time. Producer auto-populates via dry-run apply; validators verify on apply (S-033).
2. Snapshots include the chain's tail block headers, which carry their stored `state_root` field.
3. `Chain::restore_from_snapshot` now computes `compute_state_root()` over the loaded `accounts`/`stakes`/`registrants`/etc., and compares it to the tail head block's stored `state_root`. Mismatch throws `std::runtime_error` and refuses the restore.

A malicious donor who tampers with any account balance now produces a Merkle root mismatch caught locally at restore time. The receiver does not need to fetch peer blocks to detect tampering. The committee-signed `block_hash` already covers `state_root`, so the supplier cannot manufacture a self-consistent forgery (changing state shifts state_root, which shifts block_hash, which invalidates the committee signatures embedded in the snapshot's tail headers).

Pre-S-033 chains carry zero `state_root` in their headers; verification is skipped on those for backward compatibility. A snapshot built from a post-S-033 producer (the active code path) is always verified.

**Verified post-fix:** `test_snapshot_bootstrap.sh` PASSES (receiver bootstraps from snapshot alone, donors stopped, head_hash + state_root both verified, no genesis required).

**Pre-fix description** (preserved for audit trail). B6.basic restores state directly from a snapshot file with one sanity check (recomputed `head_hash` must match the snapshot's claimed value). The `accounts`/`stakes`/`registrants` maps aren't cryptographically tied to the head — the receiver trusts the donor's serialization. A malicious donor could ship a snapshot where Alice has 10× her real balance.

**Detection was fast pre-fix** — first applied block diverged. But the receiver's first-block window was unprotected; with state_root verification at restore, the unprotected window is closed.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Post-restore consistency check.** Fetch next ~10 blocks from peers and replay; on mismatch, roll back to genesis-replay. | ~50 LOC. |
| 2 | **Multi-source consensus.** Receiver fetches snapshots from N peers, accepts only if M agree on every entry. | Medium. Parallel fetcher. |
| 3 | **State Merkle root in Block.** ✅ **Landed in-session.** Each block commits to a Merkle root over canonical state. Snapshot includes state + tail headers; receiver verifies `compute_state_root()` over loaded state matches tail head's `state_root` field. Also enables future light clients (v2.2). | Shipped via S-033 + snapshot-side check. |
| 4 | **Total-supply check on snapshot restore.** Cross-references S-033's Option 4: if the chain commits `total_supply` per block, a snapshot includes the expected supply and the receiver verifies that `Σ(snapshot.accounts.balance) + Σ(snapshot.stakes.locked) == snapshot.total_supply`. Catches inflate-Alice attacks (the most natural snapshot-tampering vector) for free. | Low. Pairs with S-033's Option 4. ~10 additional LOC in `Chain::restore_from_snapshot`. Subsumed by Option 3 (the Merkle root already covers all balances). |

**Status.** Option 3 landed; closes the practical attack surface. Option 1 (peer-cross-check post-restore) remains optional belt-and-suspenders for the (highly unlikely) case of a state_root collision attack, and is tracked as a low-priority follow-on rather than a security-critical gap.

---

### S-032 — O(N) registry rebuild on every operation

**Severity:** High (scalability ceiling) • **Status:** Mitigated in-session (options 1 + 2 from the audit's resolution table) • **Sources:** Architectural Analysis §3.2

**Mitigation landed in-session.** Two complementary changes:

- **Cache on Chain** (option 1). New `Chain::AbortRecord` struct + `std::map<std::string, AbortRecord> abort_records_` member. `apply_transactions`'s Phase-1-abort-slashing loop now also maintains the cache: `ar.count++; ar.last_block = b.index`. Same policy as the previous walk (only round==1 events count). New getter `chain.abort_records()` returns const ref.
- **Snapshot persistence** (option 2). `serialize_state` writes the map as an array; `restore_from_snapshot` reads it back. Legacy snapshots get an empty cache that populates normally post-restore.

`NodeRegistry::build_from_chain` no longer walks the chain log — it reads `chain.abort_records()` directly. Same `is_suspended` lambda and suspension-formula math; behavior unchanged on the `at_index == chain.height()` path (all 8 current call sites).

**Complexity shift:**
- Per call: `O(N · T)` → `O(|registrants|)` for N = chain height, T = txs/block.
- Lifetime over chain growing to height H: `O(H² · T)` → `O(H · T)`. The quadratic-in-height ceiling is gone.

This is the prerequisite the audit named for "any chain growth beyond hobbyist scale." It also amplifies S-031's reader-concurrency mitigation: writes (which hold `unique_lock`) previously included the O(N) rebuild on every block apply; that cost is now constant, dramatically shortening writer-side critical sections and unblocking concurrent readers more frequently.

**Verified post-fix:** bearer (TRANSFER path; no abort_events), equivocation_slashing (writes abort + EquivocationEvent), bft_escalation (heavy abort_events path — exercises the cache mutation under repeated round-1 timeouts).

**Pre-fix description** (preserved for audit trail). `NodeRegistry::build_from_chain(chain, at_index)` iterated every block from genesis to `at_index` to compute the validator pool. It was called at:
- `node.cpp:253` — initial construction
- `node.cpp:934` — beacon header handler (every BEACON_HEADER message)
- `node.cpp:1025` — shard tip handler (every SHARD_TIP message)
- `node.cpp:1247` — block apply (per block)
- `node.cpp:1273` — post-apply rebuild
- `node.cpp:1316` — epoch boundary log
- `node.cpp:1748` — `rpc_validators`
- `node.cpp:1781` — `rpc_committee`

That's **8 call sites**, several of which fire per block or per gossip message. At 100k blocks, every BEACON_HEADER triggers a 100k-block scan. State is a derived view of the log; recomputing the view from scratch on every access treats the chain as the database.

**Impact.** The chain becomes unusable beyond a relatively small height. Sharding amplifies this — every shard tip the beacon receives triggers a full beacon-history scan. Compounds with S-031 (held under the global lock).

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Cache `registry_` on Chain** and update incrementally on apply. `Chain::apply_transactions` already touches REGISTER/STAKE/UNSTAKE/DEREGISTER — extend it to also update a member registry view. RPC handlers and beacon/shard handlers read the cache. | Medium. ~1d. The hard part is invariant: cache must always reflect the head's state. |
| 2 | **Persist the registry alongside the chain** (in chain.json or a sidecar). Skip the rebuild on load. | Trivial complement to #1. |
| 3 | **Memoize per-height** with eviction. Less efficient than incremental but easier to retrofit. | Low. |

**Recommended.** Option 1 + Option 2. ~1-2d total. This is the prerequisite for any chain growth beyond hobbyist scale.

---

### S-033 — No cryptographic state commitment

**Severity:** High (architectural omission) • **Status:** Mitigated in-session (Merkle tree commitment landed; inclusion proofs follow-on) • **Sources:** Architectural Analysis §3.3, related to S-012

**Mitigation landed in-session.** Block now carries a `state_root` field; producer populates it from a sorted-leaves Merkle tree (`include/determ/crypto/merkle.hpp`) over every canonical state entry. The root is bound into `signing_bytes` when non-zero (preserving pre-S-033 byte-stable hashes). Apply-time verification re-derives and rejects on mismatch. The chain's `prev_hash` chain transitively authenticates every prior state_root — the chain is now a verifiable state log.

Side effects:
- **S-012 partial closure**: snapshot verifiers can now compare snapshot state's Merkle root against the snapshot's tail-header committed `state_root`. The verification call inside `restore_from_snapshot` is a ~10 LOC follow-on (file slot exists; only the check is missing).
- **S-030 D1 effective closure**: divergent apply state between honest nodes produces divergent state_root → block rejected at apply with a loud diagnostic, surfacing the bug rather than silently corrupting state.
- **S-030 D2 partial closure**: different evidence/receipt lists produce different post-apply state → different state_root → different block_hash. The one-block `prev_hash` recovery window narrows to zero blocks (state divergence visible at compute_hash, not just at N+1).

**Inclusion proofs for light clients (v2.2)**: the Merkle primitive (`merkle_proof`/`merkle_verify`) is in place; exposing it via RPC for `account_proof` / `stake_proof` queries is the next layered commit. Wire format stays unchanged across the addition.

**Pre-fix description** (preserved for audit trail). `Block` contained no state root. `Chain` stored state in three `std::map`s (`accounts_`, `stakes_`, `registrants_`) plus `applied_inbound_receipts_` set, with no Merkle structure. Block hash bound creator signatures + `tx_root`, but not state-after-apply.

S-012 captures the snapshot-bootstrap consequence; this entry captures the broader architectural omission.

**Architectural consequences.**
- **No light clients.** A light client cannot verify any account balance or any transaction's effect without the full chain and full state.
- **No trustless fast sync.** A new node either replays from genesis (O(N)) or trusts a snapshot source (S-012).
- **No state fraud proofs.** If a validator applies a block incorrectly, there is no compact proof of fraud — other nodes can only say "my state differs" and replay to find divergence.
- **No detection of consensus-invisible state corruption.** Two nodes can have identical block hashes but different account maps if any state mutation isn't bound to the block hash. Since state isn't bound at all, this is the default failure mode under S-030.

This is a fundamental omission for any L1 claiming to be a "base layer."

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Add a `state_root` field to Block.** Each block commits to `SHA256(canonical(accounts_ ⊎ stakes_ ⊎ registrants_ ⊎ applied_inbound_receipts_))`. Validator checks state matches root after apply. | High. Block format change → hard fork. Canonical state encoding (sort + serialize) must be stable. ~1w. |
| 2 | **Sparse Merkle tree per state map.** Enables proof-of-inclusion ("Alice has balance X at height H") for individual accounts. Foundation for light clients. | Highest. ~2-4w. SMT library + per-tx state-update proofs + per-block root computation. |
| 3 | **Patricia Merkle trie** (Ethereum-style). Simultaneously supports inclusion + non-inclusion + range proofs. | Same as #2 in scope. |
| 4 | **Total-supply invariant per block.** Each block commits a `total_supply` field = sum of all account balances + all stakes + emitted-but-unburned. Validator checks `total_supply[N] == total_supply[N-1] + block_subsidy[N] - burned_fees[N]`. Catches whole classes of state tampering (most directly the inflate-Alice's-balance attack against snapshots — S-012) without restructuring state into a Merkle tree. **Not a substitute for state_root** — doesn't enable light clients or per-account proofs — but a cheap aggregate sanity check. | Low. ~50 LOC across `Block`, `apply_transactions`, validator, and snapshot. No protocol-breaking change if the new field is treated as optional in old format. |

**Recommended.** Option 4 now as a cheap interim defense (closes most snapshot-tampering attacks). Option 1 for v2.0 (full state_root). Options 2/3 for the version after that.

---

## 5. Medium findings (open)

### S-013 — BlockSigMsg buffer flood OOM

**Severity:** Medium (local DoS) • **Status:** Open • **Sources:** OV-#2, Gemini analysis

**What's open.** `BlockSigMsg` packets that arrive before the local node's delay-hash completes are buffered (we can't verify the signature yet — `block_digest` depends on `delay_output` we haven't computed). An adversary floods the Phase-1 window with millions of valid-shape, fraudulent BlockSigMsgs. Each gets queued. When delay-hash completes, the node verifies the entire bloated buffer; OOM crash before consensus thread can do useful work.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Bounded per-peer queue** (each peer's buffered count ≤ K). | Trivial, ~10 LOC. |
| 2 | **Cheap pre-filter:** reject BlockSigMsgs whose `signer` isn't in current `registry_` (string lookup, no crypto). | Trivial. |
| 3 | **Bounded total queue + LRU eviction.** | Trivial. |

**Recommended.** Options 1+2 together. ~20 LOC.

---

### S-014 — No rate limiting on gossip + RPC

**Severity:** Medium • **Status:** RPC side mitigated in-session; gossip side pending • **Sources:** Audit 3.2, OV-#10

**Mitigation landed in-session (RPC side, Option 1 partial).** `RpcServer` now supports operator-configurable per-peer-IP token-bucket rate limiting. Config fields:

- `rpc_rate_per_sec`: steady-state RPC calls/sec per peer IP (default 0 = disabled)
- `rpc_rate_burst`: bucket capacity (default 0 = disabled)

Per-request flow in `handle_session`: peer IP is captured from `socket->remote_endpoint().address().to_string()` once per session; before JSON parse + auth check, `consume_rate_token(peer_ip)` refills the bucket based on elapsed time × rate, attempts to consume 1 token, and returns ok or rate-limited. On rate-limit: response is `{"error": "rate_limited"}` and the request is dropped. Rate-limit ordering is BEFORE both parse and auth so rate-limited callers don't burn parse cost AND don't reveal whether their auth would have succeeded.

Bucket state is `std::map<std::string, Bucket>` protected by `std::mutex` (asio's worker-thread pool means concurrent handler access). Memory bound is ~24 bytes per distinct peer IP; localhost-only default sees ~1-2 entries.

Suggested production settings for external-bind operators:
- `rpc_rate_per_sec = 100`, `rpc_rate_burst = 200` (100 sustained req/s with 2-second burst headroom)

**Verified.** `tools/test_rpc_rate_limit.sh` 4/4 PASS: disabled-mode passes 30/30; tight rate (0.5/s burst 3) drains and rejects per spec; bucket refills on wait.

**Remaining open.** Gossip-side rate limiting — peer-to-peer gossip messages don't currently have a similar bucket. Each peer is bounded by socket bandwidth, but no per-message rate gate. ~30 LOC follow-on. Compounds with v2.X "binary message codec" work where the gossip dispatch path gets restructured.

**Pre-fix description.** Gossip accept loop has no cap; broadcast fan-out amplifies; RPC handle_session is synchronous per connection. Same root issue as S-001 for RPC.

**Resolution options.**

| # | Option | Cost | Status |
|---|---|---|---|
| 1a | **Per-IP token bucket on RPC** at the TCP accept layer | ~30 LOC | ✅ Shipped |
| 1b | **Per-method bucket** at RPC dispatch (snapshot 1/min, submit_tx capped, query uncapped) | ~30 LOC | Deferred — requires per-method weight tuning |
| 1c | **Per-IP token bucket on gossip** at the message receive layer | ~30 LOC | Pending |
| 2 | **Concurrent-connection cap** per peer + global | Subset of #1 | Deferred — Option 1 fires earlier |

---

### S-015 — Delay-worker thread join blocks consensus path

**Severity:** Medium (latency amplification) • **Status:** Open • **Sources:** Audit 3.6

**What's open.** `start_delay_compute` (`node.cpp:490`) does `if (delay_worker_.joinable()) delay_worker_.join();` before spawning the new worker. The previous worker only checks `delay_cancel_` *after* finishing its full T iterations (`node.cpp:497`). If `reset_round` fires during a delay-hash, the join blocks for up to T_delay before the new round can start.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Cooperative cancellation** inside the inner loop: check `delay_cancel_` every N iterations. | Trivial, hot path. ~5 LOC. |
| 2 | **`std::jthread` with stop_token** (C++20). | Medium. Toolchain dependency. |
| 3 | **Detached worker** + atomic flag for completion publishing. | Medium. Lifetime management more delicate. |

**Recommended.** Option 1. Tune the check frequency so it doesn't measurably slow the inner loop.

---

### S-016 — Inbound-receipts pool non-deterministic across committee

**Severity:** Medium (correctness-preserving latency) • **Status:** Open • **Sources:** OV-#5 (rev.9 addition; B3.4 commit message)

**What's open.** Each destination-shard committee member passes their *local* `pending_inbound_receipts_` snapshot to `build_body`. If pools differ momentarily during bundle gossip, members produce different tentative blocks → K-of-K fails → round retries. Documented in B3.4 commit. Not exploitable but adds avoidable latency.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Phase-1 contrib intersection.** Each `ContribMsg` gains `inbound_keys: [(ShardId, Hash)]`. Block bakes only receipts in the intersection of all K members' lists. Block format extends with `creator_inbound_keys[]`. | Medium. ~3-4h. ContribMsg + Block + commitment hash + JSON I/O. |
| 2 | **Time-ordered admission.** Receipts only eligible `>=N` blocks after first observed locally. By then gossip has propagated. | Trivial. Adds latency to every cross-shard transfer. |
| 3 | **Status quo** (round retries until pools converge). | Free. |

**Recommended.** Option 1 for v1.x. Aligns with the existing tx_root mechanism.

---

### S-017 — Producer/chain validation logic mismatch (UNSTAKE)

**Severity:** Medium • **Status:** Open • **Sources:** Audit 3.5, 3.8

**What's open.** `producer.cpp::build_body` filters UNSTAKE on `lk < amount` only. `chain.cpp::apply_transactions` checks `unlock_height` AND refunds the fee if too-early. Validator (`check_transactions`) doesn't check unlock_height at all. So a tx the producer includes can silently fail at apply, with the chain layer doing what should be validator-layer work.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Unify into a shared `validate_tx_apply(...)` helper** called by both producer and validator. Move unlock_height check there. Drop the apply-time refund (fail = no inclusion). | 2-3d. |
| 2 | **Chain layer continues to refund**, but validator gains the unlock_height check too. | 1d. Less invasive but keeps the divergence. |

**Recommended.** Option 1.

---

### S-018 — JSON parsing without schema validation

**Severity:** Medium (cosmetic robustness) • **Status:** Open • **Sources:** Audit 3.3

**What's open.** All `from_json` calls use `j["field"].get<T>()` which throws on missing/wrong-type. Exceptions are caught at the gossip layer. Extra fields silently ignored.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Use `j.value()` everywhere** with sensible defaults. Explicit `j.contains()` checks for required fields. | 2-3d, mechanical. |
| 2 | **JSON Schema validator library** (`nlohmann::json_schema_validator`). | Medium. New dependency. |

**Recommended.** Option 1.

---

### S-019 — Phase-2 timer R-arrival spoofing

**Severity:** Medium (was) • **Status:** ✅ Moot — see M-F. With delay-hash removed, `R` is computed instantly from local Phase-1 inputs; there's no expensive computation an attacker could spoof completion of. The piggyback optimization that depended on peer-`R`-arrival timing is no-op. • **Sources:** OV-#4, Gemini analysis

**What's open.** The Gemini analysis cites `min(local_delay_done_time, peer_R_arrival_time) + block_sig_ms` as the Phase-2 trigger formula and warns of forged-R injection. The current code may differ — needs an audit pass.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 0 | **Audit first.** Determine whether the formula is still in the consensus event loop. | Free. Required first step. |
| 1 | **Cryptographically pre-validate `R`** before allowing it to influence the timer. | Low. |
| 2 | **Local-clock only.** Drop `peer_R_arrival_time`. Timer = `local_delay_done_time + block_sig_ms`. | Trivial. Loses the latency optimization. |
| 4 | **Bind `cumulative_rand` + current epoch's timestamp into the timer-trigger condition.** The Phase-2 timer fires only when an arrived `R` produces a `block_digest` whose creator-sig verifies against the *current* `cumulative_rand` AND the current second-bin. Adversaries can't prefabricate a future-`R` because `cumulative_rand` only crystallizes per round; binding the timestamp forces brute-force attempts to restart every second. | Low. ~50 LOC. Defeats forged-R injection without losing the latency optimization. |

**Recommended.** Option 0 → Option 4 (best of both worlds — keeps the optimization, defeats spoofing). ~1 day total.

---

### S-020 — Rejection sampling O(K²) at K/N → 1 — ✅ Mitigated in-session

**Severity:** Medium (was) • **Status:** ✅ Mitigated • **Sources:** OV-#3, Gemini analysis

**What changed.** `crypto/random.cpp::select_m_creators` and `select_after_abort_m` now branch on `2K vs N`:
- **`2K ≤ N`** — unchanged rejection sampling. Cheap, no allocation, expected O(K) hashes, and preserves rev.9 output for the K/N ≤ 0.5 regime so existing committee-index fixtures stay stable.
- **`2K > N`** — partial Fisher-Yates shuffle over an `[0..N)` index array. O(N) setup + exactly K hashes + K swaps, with no rejection spin. The worst case (K = N or K = N−1) is now bounded; rejection sampling on the same input expected ~N tries for the final pick.

`select_after_abort_m` pins `new_first` at slot 0 of the shuffle buffer (the abort-hash offset is part of the consensus contract) and Fisher-Yates the remaining `m−1` positions.

**Determinism.** Both `K` and `N` are inputs to the function; every node picks the same branch and the same indices. No fork height needed because no chain history sits on the K > N/2 path — current regression tests run with M ≤ 2, K ≤ M, N_registered ≤ 3 and all hit the rejection branch (verified: governance, equivocation, BFT escalation, bearer, atomic_scope, dapp_register all green after the change).

**Effort.** ~40 LOC including comments. Header doc updated in `include/determ/crypto/random.hpp`.

---

### S-034 — VDF allocates `EVP_MD_CTX` per iteration

**Severity:** Medium (was) • **Status:** ✅ Moot — see M-F. With the iteration removed, there's no inner loop allocating contexts. • **Sources:** Architectural Analysis §3.6

**What's open.** `delay_hash_compute` at `src/crypto/delay_hash.cpp:6-12`:
```cpp
Hash delay_hash_compute(const Hash& seed, uint64_t T) {
    Hash cur = seed;
    for (uint64_t i = 0; i < T; ++i) {
        cur = sha256(cur);   // each call: new SHA256Builder, new EVP_MD_CTX
    }
    return cur;
}
```

Each `sha256(cur)` constructs a `SHA256Builder` — which `new`s an `Impl` and calls `EVP_MD_CTX_new()` (heap allocation + OpenSSL context setup) — appends, finalizes, then destroys it. For T = 4,000,000, that's 4 million heap allocations and 4 million `EVP_DigestInit_ex` calls. The actual SHA-256 work is a tiny fraction of the wall-clock cost.

A reusable `EVP_MD_CTX` inside the inner loop, calling `EVP_DigestInit_ex` once and reusing it via `EVP_MD_CTX_reset`, is a roughly **100×-1000× speedup**.

**Why this matters beyond performance.** `delay_T` is calibrated to a specific consumer-CPU wall-clock target (`T_delay ≥ 2 × T_phase1`). The current implementation's wall-clock cost is dominated by allocation/setup overhead, not SHA-256 work. **A more efficient implementation would dramatically reduce the wall-clock cost**, breaking the calibration unless `T` is bumped proportionally. So this is also a security-relevant calibration risk: if some node operators run an optimized build and others don't, the network desynchronizes.

Compounds with S-031 because this 4M-iteration loop runs under `state_mutex_` on the piggyback path.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Reuse `EVP_MD_CTX`** inside the loop with `EVP_MD_CTX_reset` between iterations. | ~30 LOC. Requires bumping `delay_T` ~100-1000× to maintain the same wall-clock target. |
| 2 | **Direct SHA-256 block compression.** Skip OpenSSL's EVP layer entirely; call the SHA-256 transform on a 32-byte block in a tight loop. | Medium. ~50 LOC + understanding the transform interface. Fastest possible CPU implementation. |
| 3 | **Bench-and-recalibrate** before fix. Document the new per-iteration cost; coordinate a `delay_T` bump alongside the optimization. | 1d benchmark. |

**Recommended.** Options 1 + 3 together. The fix without recalibration would silently weaken the protocol's selective-abort defense (S-009 already weakens it; this would compound).

---

## 6. Low findings (open)

### S-035 — No unit tests, no CI, no deterministic simulation framework

**Severity:** Operational • **Status:** Open • **Sources:** Architectural Analysis §4.1, §4.2

**What's open.** The project ships with bash integration tests and zero unit tests. No gtest/Catch2/doctest. No GitHub Actions / GitLab CI. Tests hardcode Windows paths (`C:/sauromatae/...`, `build/Release/determ.exe`); no Linux/Mac CI ever ran. No deterministic-simulation framework — no clock mock, no controlled message delivery (drop / reorder / delay), no partition injector. Byzantine behavior cannot be tested systematically.

**Why this is operational, not a vulnerability.** A bug-free codebase doesn't strictly need unit tests, but their absence makes regression-prevention impossible. Edge cases (`ContribMsg` with invalid `aborts_gen`, delay-worker exception handling, two same-height blocks in different orders, equivocation under network partition) require targeted unit tests; the integration scripts can't drive them.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Add gtest/Catch2** for crypto, serialization, state transitions, validator rules. CMake + Linux CI. | 1-2w to seed + ongoing per-feature. |
| 2 | **Deterministic simulation framework** — virtual clock + virtual network + scriptable Byzantine actors. | 3-4w. Substantial but the right tool for testing consensus. |
| 3 | **Path portability** — replace Windows-specific test paths with platform-agnostic ones; add Linux/Mac CI. | 1d. |

**Recommended.** Option 3 immediately (gets the existing tests running on Linux/Mac CI). Option 1 incrementally (add unit tests for new code; backfill gradually). Option 2 is v1.x quality work.

---

### S-021 through S-029 (quick-fix summary)

| ID | Title | Quick fix |
|---|---|---|
| S-021 | Chain file integrity not cryptographically verified | Store + verify a cumulative hash; or keep relying on apply-time validation (current de-facto defense). |
| S-022 | 16 MB message limit too permissive — but snapshots use it | Per-message-type limits: 1 MB for CONTRIB/BLOCK_SIG; 16 MB only for SNAPSHOT_RESPONSE / CHAIN_RESPONSE. |
| S-023 | RPC `send`/`stake` skip balance check | Pre-check balance before queueing. ~1h. |
| S-024 | Deregistration timing predictability (1-10 block grind window) | Acceptable per auditor's own re-classification. v2 could mix in a future block hash. |
| S-025 | `compute_tx_root_intersection` is dead code | Delete it or guard under `#ifdef DETERM_INTERSECTION_MODE`. 5 minutes. |
| S-026 | No connection timeout / keepalive | 30s timeout on idle peer connections. Add periodic keepalive. ~1d. |
| S-027 | Info leakage in logs / error messages reveal state | Configurable log levels; redact in production builds. |
| S-028 | Hex parsing only accepts lowercase | `is_anon_address` is canonical; downstream parsers should accept either case. Trivial. |
| S-029 | BFT-mode multi-proposer fork-choice undefined | Status quo (first-seen-wins) + slashing handles it. **Better:** primary fork-choice = heaviest sig set (more committee members ratified), tiebreaker = longest descendant chain. ~30 LOC in `apply_block_locked`. **Implemented in `Chain::resolve_fork`** as of this commit series. |

---

## 6.5. Regional sharding posture (informational, `EXTENDED` mode only)

These are not bugs — they are **inherent trade-offs** an operator accepts when choosing `sharding_mode = EXTENDED` over `CURRENT`. Each is documented so deployment specs can name the threat model explicitly. Operators choosing `CURRENT` or `NONE` are unaffected.

### T-001 — Regional capture (informational)

**Posture.** Under `EXTENDED` sharding, a shard's K-committee is restricted to validators whose registered region matches the shard's `committee_region`. Censorship resistance becomes **regional** rather than global: capturing every validator in region `R` lets that adversary produce blocks for shards pinned to `R` without input from other regions.

**What changes vs. global sharding.**
- Censor-probability per round shifts from `(f_global / N_global)^K` to `(f_in_R / N_in_R)^K`. The numerator and denominator both shrink; capture is easier in proportion to how concentrated the regional pool is.
- A captured region cannot corrupt cross-shard credits because destination shards re-derive the source committee from their own beacon view and reject signatures from unknown validators.

**Mitigation guidance.**
- Deployments that prioritize global censorship resistance should use `CURRENT`, not `EXTENDED`.
- Deployments that use `EXTENDED` should disclose the regional trust assumption in their deployment spec (which shard maps to which region, what jurisdictions cover which validators).

### T-002 — Jurisdictional / regulatory risk (informational)

**Posture.** If region `R` corresponds geographically to a single jurisdiction, a government order to all validators in that jurisdiction can force censorship or transaction reversal on shards pinned to `R`. The beacon and shards in other regions are unaffected; cross-shard receipts from compelled shards are still validated by destination committees per the protocol.

**Mitigation guidance.**
- Choose region boundaries that span multiple jurisdictions where possible (`eu-west` rather than `de-frankfurt`).
- Use the recommended geographic taxonomy from `README.md §17.5` to avoid jurisdiction-aligned regions for cross-border deployments.
- For consortium chains where regional alignment with a regulator is desirable (e.g., a national banking settlement layer), this is a feature, not a bug.

### T-003 — Network partition during `EXTENDED` deployment (informational)

**Posture.** A region losing connectivity to the rest of the network stalls cross-shard receipts for shards pinned to that region: those shards continue producing blocks internally, but their `SHARD_TIP` messages don't reach the beacon, and outbound `CROSS_SHARD_RECEIPT_BUNDLE` messages don't reach other regions.

**Effects:**
- In-shard transactions in the partitioned region continue to finalize.
- Cross-shard transactions from / to the partitioned region stall until connectivity restores.
- After the partition heals, queued receipts flow through normally (idempotency via `applied_inbound_receipts_` dedup catches anything that gets re-delivered).
- No global stall — other regions' shards keep operating normally.

**Mitigation guidance.**
- Operators of `EXTENDED` deployments should monitor cross-region connectivity (e.g., heartbeat metrics between regional beacon peers).
- Applications that span regions should expect cross-region tx latency to spike during partitions; design for eventual consistency.

### T-004 — Stake concentration feedback loop (informational)

**Posture.** Validators earn block subsidy + transaction fees from the shards they're on. If one region has materially higher transaction volume, validators concentrate there for fee revenue. Over time, that region's stake share grows; other regions thin out. A thin region becomes more vulnerable to T-001 (regional capture) and may eventually trigger under-quorum recovery (R4 — pending).

**Mitigation guidance.**
- Operators monitoring `EXTENDED` deployments should watch per-region validator counts and stake totals.
- Possible interventions: rebalance shard regions at epoch boundaries, cap per-region validator counts at registration, redistribute economic activity (genesis allocations, dApp routing).
- The S-038 invariant (`num_shards >= 3` under `EXTENDED`) bounds the worst case — even a fully-concentrated single region can't drive cascading merges across the whole deployment.

---

## 7. Mitigated since rev.7 audit baseline (or in this session)

These findings have been addressed in current code. Listed for completeness so a reader of prior audits knows what's done.

### M-A — Block-level equivocation closed-loop (was Audit 2.4 partial)

**rev.8 added** `EquivocationEvent` (two valid Ed25519 sigs over distinct digests at the same height by the same key) → `pending_equivocation_evidence_` → baked into next block → `apply_transactions` zeroes equivocator's stake AND sets `inactive_from = h+1`. External-submission path via `submit_equivocation` RPC. Verified end-to-end in [`tools/test_equivocation_slashing.sh`](../tools/test_equivocation_slashing.sh).

The narrower ContribMsg-level case is still open as S-006.

### M-B — Hybrid-mode K-of-M liveness gap → BFT escalation (was Audit 2.1)

**rev.8 added** per-height BFT escalation: after `bft_escalation_threshold` (default 5) round-1 aborts at the same height AND `bft_enabled = true`, the next round produces a `consensus_mode = BFT` block requiring `ceil(2K/3)` signatures plus a deterministic `bft_proposer`. The auditor's recommendation ("either disable hybrid mode or implement proper proposer rotation") was implemented as the second option. Verified in [`tools/test_bft_escalation.sh`](../tools/test_bft_escalation.sh).

### M-C — Linear-time sync barrier → snapshot bootstrap (was Gemini "fatal architectural flaw")

**B6.basic added** `Chain::serialize_state` + `restore_from_snapshot` + `determ snapshot {create,inspect,fetch}` + `Config::snapshot_path` for fast-bootstrap. Receiver skips per-block replay; restores state directly. The cryptographic-zero-trust version still requires a state Merkle root in the block format (deferred to v2 — see S-012). Verified in [`tools/test_snapshot_bootstrap.sh`](../tools/test_snapshot_bootstrap.sh).

### M-D — Blind-abort liveness exploit → BFT escalation

The Gemini analysis's headline conclusion — "blind abort = systemic liveness problem; capitalized adversary can stall any specific transaction by burning suspension penalty" — is **substantially mitigated by M-B**. A single blind-aborting adversary can stall a transaction for ~5 rounds, then BFT mode kicks in and the chain proceeds without their signature. The exponential-suspension formula still applies but is no longer the only liveness guarantee.

### M-F — Iterated delay-hash removed (S-009 closure)

**Was Architectural Analysis §3.6 + S-009 + S-019 + S-034.**

The SHA-256^T delay-hash function has been removed from the protocol. The selective-abort defense is now a Phase-1/Phase-2 commit-reveal protocol: each committee member's `ContribMsg.dh_input = SHA256(secret_i ‖ pubkey_i)` is a Phase-1 commitment to a per-round 32-byte secret; `BlockSigMsg.dh_secret` reveals it in Phase 2; validators enforce the bind. The block's randomness `delay_output = SHA256(delay_seed ‖ ordered_secrets)` is computed once K reveals gather (commit `14bf3d6`).

**Consequences:**
- S-005 (`delay_T` not in genesis) is closed: the `delay_T` field has been removed entirely from `GenesisConfig`, `Node Config`, `TimingProfile`, and the validator (commit `1b9b086`). There's no parameter left to misconfigure.
- S-009 (constant-T / SHA-256 ASIC fallacy) is closed: the defense is now information-theoretic (preimage resistance), not time-bound. ASIC asymmetry no longer matters.
- S-019 (Phase-2 timer R-arrival spoof) is closed: `R` is computed inline once K Phase-1 contribs gather; there's no expensive computation an attacker could spoof completion of.
- S-034 (VDF `EVP_MD_CTX` allocation) is closed: no inner loop.
- S-031 (global mutex serialization) is partially mitigated — the worst case (`delay_hash_verify` with 4M iterations under the lock during piggyback) is gone.

**Trade-off accepted:** the original VDF-style selective-abort defense — "an attacker can't predict block randomness during the Phase-1 commit window because computing it requires T sequential SHA-256 ops > Phase-1 budget" — is replaced by a commit-reveal-based defense backed by the existing BFT escalation + equivocation slashing machinery. An attacker without all K committee members' Phase-2-revealed secrets still cannot predict block randomness (under SHA-256 preimage resistance); the security argument shifts from "compute-time" to "information-theoretic."

**Cleanup landed.** `crypto/delay_hash.{hpp,cpp}` files are deleted. The `RUNNING_DELAY` consensus phase, the `delay_worker_` thread + `delay_cancel_` / `delay_done_` flags, the validator's `delay_T_` field + `set_delay_T`, and the test scripts' `c['delay_T'] = 200000` config writes are all gone (commit `1b9b086`). The M=K=1 single-validator chain recursion that the worker thread's `asio::post` used to break is now broken by an inline `asio::post` inside `enter_block_sig_phase`.

### M-E — Outbound HELLO mistagging in cross-chain peering

**Was Architectural Analysis §3.5.** Outbound `GossipNet::connect()` at `gossip.cpp:45` was sending `make_hello(domain, port)` — the 2-arg overload defaulting `role = SINGLE, shard_id = 0`. Inbound (accept-loop) at `gossip.cpp:33` correctly sent `make_hello(domain, port, our_role_, our_shard_id_)`. The mismatch silently broke `SHARD_TIP` and `BEACON_HEADER` propagation for outbound-initiated cross-chain peering: the receiving end's role-based gossip filter (`peer_message_allowed`) dropped messages from peers it had stamped as SINGLE.

**Fixed in this session.** `gossip.cpp:45` now passes the full 4-argument form. All 8 regression tests pass.

### M-G — Governance mode + PARAM_CHANGE shipped (A5)

**New in this session.** Genesis-pinned `governance_mode = 0|1` selector with `param_keyholders` + `param_threshold`. Validator enforces a whitelist of 9 mutable parameters (MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY, bft_escalation_threshold, tx_commit_ms, block_sig_ms, abort_claim_ms, param_keyholders, param_threshold) with N-of-N multisig. Off-list parameters require a new chain identity.

**Soundness proof:** `docs/proofs/Governance.md` (FA10). Cumulative false-positive bound: `≤ 2⁻⁴⁵²` for N=5 keyholders + Q=2⁶⁰ adversary budget.

**Integration test:** `tools/test_governance_param_change.sh` — 3-of-3 keyholder genesis, MIN_STAKE 1000 → 2000 mid-chain, verified via snapshot inspect.

### M-H — Under-quorum merge shipped (R4)

**New in this session.** `MERGE_EVENT` tx type (TxType=7) with canonical 26+region_len byte payload. Genesis-pinned thresholds (`merge_threshold_blocks=100`, `revert_threshold_blocks=200` for 2:1 hysteresis, `merge_grace_blocks=10`). Eligibility stress branch in producer + validator extends the committee pool with refugee-region validators when this shard is absorbing. Snapshot save/restore preserves merge state.

**Soundness proof:** `docs/proofs/UnderQuorumMerge.md` (FA9). Demonstrates FA1 (safety) and FA7 (cross-shard atomicity) preservation across BEGIN/END transitions.

**S-036 partial mitigation:** Phase 6 ships internal-consistency bounds checks (effective_height ≥ block + grace; BEGIN evidence window in past). Full S-036 closure requires on-chain SHARD_TIP records — v1.1 work item.

**Integration test:** `tools/test_under_quorum_merge.sh` — BEGIN inserts state, END erases, snapshot persists.

### M-I — Wallet recovery primitive shipped (A2)

**New in this session.** Greenfield `determ-wallet` binary providing distributed seed recovery via T-of-N Shamir SSS layered with AES-256-GCM AEAD envelopes. Two schemes: `passphrase` (default; PBKDF2 directly off the password) and `opaque` (routes through an OPAQUE adapter). The Phase 5 stub adapter (default v1.x) uses libsodium Argon2id directly — gated by `is_stub()` against production use until Phase 6 real libopaque vendoring lands. Pubkey-checksum gate prevents silent reconstruction corruption.

**Binary isolation:** the wallet handles secret material; the chain daemon never has access to user seeds.

**Soundness proof:** `docs/proofs/WalletRecovery.md` (FA12). Real-OPAQUE bound: `Q · 2^-bits_password + N · 2⁻¹²⁸` (rate-limited online grind). Stub bound: offline-grindable per compromised guardian — NOT for production.

**Integration tests:** 6 wallet test suites (56/56 assertions PASS): shamir, envelope, recovery, oprf-smoke, opaque-adapter, opaque-recovery.

### M-J — Full formal-verification track shipped

**New in this session.** Every v1.x safety-critical mechanism has both an analytic proof (FA-track) and a TLA+ state-machine specification (FB-track):

- F0 Preliminaries + FA1–FA12: safety, censorship, selective-abort, liveness, BFT-mode safety, slashing soundness, cross-shard atomicity, regional sharding, under-quorum merge, governance, economic soundness, wallet recovery.
- FB1 Consensus.tla + FB2 Sharding.tla + FB3 Receipts.tla + FB4 CHECK-RESULTS.md (TLC transcripts pending Java + tla2tools.jar in CI).

Every theorem cites its source-code enforcement points. A reviewer can trace any property end-to-end: theorem → state-machine model → implementation. Concrete bounds tabulated in `docs/proofs/README.md` §"Concrete-security summary".

---

## 8. Auditor-retracted findings (historical)

The rev.7 audit's §5 self-corrected three items:

- **Delay-hash atomicity** — auditor confirmed `delay_cancel_` and `delay_done_` are correctly `std::atomic<bool>`. Retracted. (A related thread-lifecycle issue is now S-015.)
- **Anonymous-account replay protection** — auditor confirmed nonce tracking is uniform across all account types. Retracted.
- **Deregistration timing severity** — auditor downgraded from Medium to LOW (now S-024).

These corrections are accepted; no current code review changed the verdict.

---

## 9. Cheapest path to "production-ready security posture"

Two tracks. **Track A** is the cheap-and-localized cluster (~4-6 days). **Track B** is the architectural lift required for production (S-030 / S-031 / S-032 / S-033) — these are not 1-LOC fixes and represent the gap between "demo-ready" and "production-ready."

### Track A — localized fixes

| ID | Title | Status |
|---|---|---|
| S-001 (option 1) | Bind RPC to localhost by default | ✅ done |
| S-001 (option 3) | HMAC-SHA-256 RPC auth (v2.16) | ✅ done |
| S-002 | Verify sig in `on_tx` + paired binary_codec fix | ✅ done |
| S-003 | Widen timestamp window to ±30s | ✅ done |
| S-004 (option 1) | 0600 file perms + no-stdout default | ✅ done |
| S-004 (option 2) | AES-256-GCM passphrase envelope (v2.17) | ✅ done |
| S-005 | `delay_T` removed entirely (M-F delay-hash deletion) | ✅ done |
| S-007 | Overflow-checked add (`checked_add_u64`) on every credit path | ✅ done |
| S-008 (options 1 + 3) | `MEMPOOL_MAX_TXS = 10000` + fee-priority eviction + `MEMPOOL_MAX_PER_SENDER = 100` quota | ✅ done |
| S-025 | Delete dead `compute_tx_root_intersection` | ✅ done |
| S-013 | Bounded BlockSigMsg buffer + signer pre-filter | ⏳ pending (~20 LOC) |
| S-014 | RPC + gossip rate limiting | 🟠 RPC done (token-bucket per peer IP); gossip side pending |
| S-020 | Hybrid Fisher-Yates committee selection | ✅ done |
| S-023 | RPC pre-check balance | ✅ done |
| S-034 | Moot — delay-hash module deleted | ✅ done |

**Track A status: 12.5 of 14 closed (S-014 RPC side ✅, gossip side pending). 1 fully remaining: S-013 BlockSigMsg buffer.**

### Track B — architectural lift

| ID | Title | Status |
|---|---|---|
| S-030 D1 | Bind `b.transactions` into block validation (via S-033 indirect closure) | ✅ effective |
| S-030 D2 | Full closure via v2.7 F2 view reconciliation | ⏳ spec'd (F2-SPEC.md), 3-4d implementation |
| S-031 | shared_mutex + A9 Phase 1-2D + async chain.save + gossip-out-of-lock (6 layers) | ✅ fully closed |
| S-032 | Incremental registry cache on Chain (cached registry_view_ + snapshot persistence) | ✅ done |
| S-033 | Merkle root in `Block.state_root` + signing_bytes binding + apply/restore verification | ✅ done |

**Track B status: 4 of 5 closed. Remaining: v2.7 F2 (3-4 days).**

### Track C — Additional design enhancements (deferred / partial)

| Source | Title | Status |
|---|---|---|
| Economics | Protocol-derived minimum fee (`fee >= subsidy / 1024`) | ⏳ deferred (genesis-config + test-suite update needed) |
| Identity | `IP_INCLUSION` as third inclusion model | ⏳ not started |
| Consensus | Heaviest-sig-set fork-choice for S-029 BFT mode | ✅ done |
| Consensus | Bind `cumulative_rand + t` into Phase-2 timer for S-019 | ✅ moot (commit-reveal supersedes; S-019 closed by M-F) |
| Supply | `total_supply` invariant per block (S-033 interim + S-012 defense) | ✅ superseded by S-033 (state_root binds total state) |

### v2 protocol-evolution — shipped foundations

| ID | Title | Status |
|---|---|---|
| S-009 | SHA-256 delay → commit-reveal randomness | ✅ done (M-F replaced delay-hash) |
| S-033 (deeper) | Merkle state commitment + inclusion proofs for light clients | ✅ foundation shipped (v2.1 + v2.2 state_proof RPC) |
| S-012 (deeper) | Trustless snapshot via state_root verification | ✅ done |

**Production-readiness summary (post in-session work):**
- Critical findings: 0 fully-open (1 partially mitigated — S-030 D2 via S-033 indirect closure; v2.7 F2 spec'd for full consensus-layer closure)
- High findings: 3 open (S-006, S-010, S-011 — all design / parameter-policy items, not shipped-code attack surface)
- Medium findings: 1 partially mitigated (S-014 RPC side done, gossip side pending), 4 still open (S-013, S-016, S-017, S-018) — all bounded ~hours-of-work each
- Track A remaining: ~quarter-day total (S-013 + S-014 gossip-side)
- v2.7 F2: 3-4 days (full S-030 D2 closure at the consensus layer)
- v2.10 active: ~1 week (threshold randomness aggregation, plan.md A11)

The original "5-6 weeks of engineering" estimate has been substantially absorbed in-session. Remaining gates to permissionless-deployment-ready posture:
1. Track A small items (~quarter-day combined): S-013 buffer cap, S-014 gossip side.
2. v2.7 F2 implementation per F2-SPEC.md (~3-4 days).
3. v2.10 threshold randomness aggregation per plan.md A11 (~1 week, includes BLS12-381 vendoring + DKG).

Total remaining: ~2 weeks to "production-deployment-ready" posture.

---

## 10. Cross-references

- [`docs/PROTOCOL.md`](PROTOCOL.md) — frozen v1 spec; the source of truth for hash inputs, message formats, consensus rules. Where this doc cites a specification claim, PROTOCOL.md is authoritative.
- [`docs/CLI-REFERENCE.md`](CLI-REFERENCE.md) — operator command surface.
- [`docs/QUICKSTART.md`](QUICKSTART.md) — operator walkthrough.
- The original [rev.7 SECURITY_AUDIT.md](https://) is preserved as historical context but **superseded by this file**. Where the audit and this file disagree, this file wins for current code; the audit wins for rev.7 archaeology.
- [`docs/OPEN-VULNERABILITIES.md`](OPEN-VULNERABILITIES.md) — predecessor of this file, now superseded.

---

## 11. Versioning

This document tracks current state at HEAD. As findings are mitigated, they move from §3-§6 to §7 with a brief note describing the fix. New findings are added with the next available `S-NNN` ID. The triage table in §2 is the canonical entry point for any review.
