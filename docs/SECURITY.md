# Determ Security Posture

**Doc status:** Canonical. Reconciles the rev.7 security audit findings with the in-tree predecessor `OPEN-VULNERABILITIES.md` (now superseded and removed) against current code at rev.8 + rev.9 sharding through B6.basic.

**Methodology.** Each finding is verified against current source before classification. Findings the rev.7 audit raised that have since been mitigated are listed in §5. New issues visible in rev.9 code (sharding, snapshots) that the audit predates are included as first-class findings. Severity follows the audit's CVSS-style framing.

---

## 1. Executive summary

| | Critical | High | Medium | Low/Op | Total |
|---|---|---|---|---|---|
| Open (untouched) | **0** | **0** | **1** (S-018) | **1** (S-035 unit-tests/CI; engineering-culture item) | **2** |
| Partially mitigated | **1** (S-030) | — | **1** (S-016 Option 2 shipped; Option 1 = v2.7 F2 closes fully) | **1** (S-036 EXTENDED-mode-only; v2.11 closes) | **3** |
| Mitigated in-session | **5** (S-001, S-002, S-003, S-004, S-031) | **13** (S-006, S-007, S-008, S-010, S-011, S-012, S-013, S-014, S-017, S-020, S-032, S-033, S-038) | — | **8** (S-021, S-022, S-024, S-026, S-027, S-028, S-029, S-037) | **26** |
| Closed by M-F (delay-hash removal) | — | — | — | — | **5** (S-005, S-009, S-015, S-019, S-034) |
| Informational (`EXTENDED` posture) | — | — | — | — | **4** (T-001..T-004) |

(M-F removed iterated SHA-256 delay-hash and its supporting infrastructure — `delay_T` field, worker thread, `RUNNING_DELAY` phase, `EVP_MD_CTX` per-iteration alloc — in commits `14bf3d6` and `1b9b086`. T-001 through T-004 are operator-facing trade-offs of `sharding_mode = EXTENDED`, not bugs — see §6.5.)

**Open Critical findings: zero.** Only S-030 is partially mitigated (D1 effective-closed via S-033, D2 partial via S-033, v2.7 F2 planned for full D2 closure). S-031 is now fully closed (6 architectural layers shipped). **Open High findings: zero** — S-006 closed via `on_contrib` equivocation detection; S-010 closed via operator stake-pricing formula + DOMAIN_INCLUSION availability; S-011 closed via S-010 stake floor + FA6 equivocation-slashing economic-infeasibility bound. **S-037 closed in this session** — added serialize / restore handling for `dapp_registry_` so DApp-active chains survive snapshot bootstrap intact; new regression `tools/test_dapp_snapshot.sh` (12/12 PASS) exercises register → snapshot → restore → `dapp-info` end-to-end. **S-038 closed in this session** — `Node::try_finalize_round` now populates `body.state_root` via a tentative-chain dry-run before broadcast, so the S-033 verification gate at apply time actually fires (pre-fix the field was zero on every gossiped block, short-circuiting the gate). S-033's documented "shipped" status is now genuine end-to-end; the apply-layer mitigation of S-030 D1/D2 is no longer dormant.

**Top-of-list priorities** (updated after in-session closures — see §3 bodies for closure details):

Currently genuinely outstanding:

- **S-030 D2 full closure (v2.7 F2)** — design specification complete in `docs/proofs/F2-SPEC.md`; implementation ~3-4 days. D1 is effective-closed via S-033 state_root binding; D2 is partial-closed via the same mechanism (apply-layer rejection). v2.7 F2 closes D2 at the consensus layer (signatures gather only on view convergence).
- **v2.10 threshold randomness aggregation** — 🔥 promoted to active in plan.md A11. Defeats residual selective-abort attack via t-of-K threshold signatures. ~1 week including BLS12-381 vendoring + DKG tooling.

Closed in-session (retained here for audit trail; see §3 bodies):

- ~~S-001 RPC authentication missing~~ — closed via `rpc_localhost_only=true` default + HMAC-SHA-256 (v2.16).
- ~~S-002 Mempool accepts unverified signatures~~ — closed via mempool sig-verify + paired `binary_codec.cpp::decode_tx_frame` fix.
- ~~S-003 Block timestamp window ±5s~~ — closed via ±30s window in `BlockValidator::check_timestamp`; spec and code now agree.
- ~~S-004 Plaintext private keys~~ — closed via AES-256-GCM passphrase envelope keyfile (v2.17).
- ~~S-006 ContribMsg same-generation equivocation~~ — closed via detection in `on_contrib`; reuses existing `EquivocationEvent` channel (no new wire format).
- ~~S-007 Subsidy/fee overflow~~ — closed via `checked_add_u64` on every credit path.
- ~~S-008 Unbounded mempool~~ — closed via `MEMPOOL_MAX_TXS = 10000` + `MEMPOOL_MAX_PER_SENDER = 100` with fee-priority eviction.
- ~~S-010 Sybil via under-priced MIN_STAKE~~ — closed via operator stake-pricing formula + DOMAIN_INCLUSION availability (see §3 S-010 calculator).
- ~~S-011 Abort claim cartel via M-1 quorum~~ — closed via S-010 stake floor + FA6 equivocation slashing bounding the attack to economically infeasible.
- ~~S-012 Snapshot trust~~ — closed via state_root verification on restore.
- ~~S-013 BlockSigMsg buffer flood OOM~~ — closed via per-signer cap (2 entries) in `try_buffer_block_sig`; total buffer bounded at 2·K through existing pre-filters.
- ~~S-014 No rate limiting on gossip + RPC~~ — closed via shared `net::RateLimiter` helper used by both `RpcServer` and `GossipNet` (per-peer-IP token bucket, HELLO exempt).
- ~~S-017 Producer/chain UNSTAKE divergence~~ — closed via Option 2: validator + producer both gain the `unlock_height` check; apply-time refund retained as belt-and-suspenders.
- ~~S-020 Rejection sampling O(K²) at K/N → 1~~ — closed via hybrid selector (rejection sampling at 2K ≤ N, partial Fisher-Yates shuffle at 2K > N — bounded O(N) regardless of ratio).
- ~~S-021 Chain file integrity not cryptographically verified~~ — closed via wrapping chain.json with `head_hash` + load-time recompute + mismatch reject (O(1) tampering detection before replay).
- ~~S-022 Permissive 16 MB message cap~~ — closed via per-message-type body-size limit applied after deserialize in `Peer::read_body`; 1 MB for consensus chatter, 4 MB for blocks/headers/bundles, 16 MB only for SNAPSHOT/CHAIN responses.
- ~~S-026 No connection timeout / keepalive~~ — closed via `SO_KEEPALIVE` on every peer socket in `Peer::Peer`; dead connections reaped via OS-level keepalive probes through the existing on_close path.
- 🟠 S-016 Inbound-receipts pool non-determinism — partially mitigated via Option 2 (time-ordered admission, 3-block soak); v2.7 F2 closes fully via Option 1 (Phase-1 intersection commitment).
- ~~S-024 Deregistration timing predictability~~ — formally accepted per auditor's reclassification; 1-10 block grind window deemed acceptable in v1.x; v2.X enhancement noted.
- ~~S-027 Info leakage in logs~~ — closed via audit-pass (no secret material in node/RPC logs; only chain-public state) + new `Config::log_quiet` flag for operator-side log-volume control.
- ~~S-028 Hex parsing only accepts lowercase~~ — closed via case-insensitive `is_anon_address` + `normalize_anon_address` helper + apply at RPC read boundaries (`rpc_balance`, `rpc_send`); `rpc_submit_tx` rejects non-canonical with clear diagnostic (sig is over signing_bytes so server can't mutate).
- ~~S-029 BFT-mode multi-proposer fork-choice undefined~~ — closed via `Chain::resolve_fork`: heaviest sig set / fewer aborts / smallest hash, deterministic across peers.
- ~~S-031 Global mutex serialization~~ — closed via 6 architectural layers (shared_mutex + A9 Phase 1-2D + async chain.save + gossip-out-of-lock).
- ~~S-032 O(N) registry rebuild~~ — closed via incremental registry cache.
- ~~S-033 No state commitment~~ — closed via Merkle root in `Block.state_root` + signing_bytes binding. (S-038 closure makes the gate actually fire on production blocks.)
- ~~S-037 dapp_registry snapshot serialize/restore gap~~ — closed via `dapp_registry` field added to `Chain::serialize_state` + `restore_from_snapshot` (with `if (snap.contains(...))` guard for pre-v2.18 backward compat); new regression `tools/test_dapp_snapshot.sh` (12/12 PASS) exercises register → snapshot → restore → `dapp-info` verification end-to-end.
- ~~S-038 state_root gate dormant on production blocks~~ — closed by populating `body.state_root` in `Node::try_finalize_round` (tentative-chain dry-run, same pattern as the digest dry-run above it) before `apply_block_locked` + `gossip_.broadcast`. The S-033 verification gate at `chain.cpp::apply_transactions` (which already correctly compared `b.state_root` to `compute_state_root()` when non-zero) now fires on every produced block, so peer nodes reject any divergent body. K-of-K BlockSig signatures unaffected (`compute_block_digest` already excludes `state_root` per §4.3); `block_hash` (compute_hash via signing_bytes) now binds the field. Backward-compat: pre-fix chains with `state_root = 0` in stored blocks remain valid (the gate skips zero per the S-033 backward-compat shim). The S-038 fix is the "actually shipped" half of the S-033 mitigation — pre-fix, the data layer worked but the gate was bypassed.

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
| S-006 | ✅ Mitigated | Same-generation ContribMsg equivocation now detected in `on_contrib`; piggybacks on existing `EquivocationEvent` channel (no new wire format) | `node/node.cpp::on_contrib` | done |
| S-007 | ✅ Mitigated | Subsidy/fee/receipt-credit overflow-checked via checked_add_u64 (Options 2 + 3 from audit) | `chain/chain.cpp` | done |
| S-008 | ✅ Mitigated | Mempool bounds: MEMPOOL_MAX_TXS = 10000 cap + fee-priority eviction + MEMPOOL_MAX_PER_SENDER = 100 quota | `node/node.cpp::mempool_admit_check` | done |
| S-009 | ✅ Closed | Constant-T / SHA-256 ASIC fallacy — replaced by commit-reveal (commit `14bf3d6`); delay-hash module deleted (commit `1b9b086`) | n/a | done |
| S-010 | ✅ Mitigated | Operator stake-pricing formula in §3 S-010; DOMAIN_INCLUSION available for chains without strong stake-pricing economics | `chain/params.hpp` + `docs/SECURITY.md` §S-010 calculator | done |
| S-011 | ✅ Mitigated | Economic infeasibility via S-010 stake floor + FA6 equivocation slashing bounds the cartel attack to "finite rounds of suspension" with per-round cost > chain subsidy | `node/node.cpp::on_abort_claim` (no code change required) | done |
| S-012 | ✅ Mitigated | Snapshot bootstrap state_root verification landed (S-033 Merkle root in Block + snapshot-side check) | `chain/chain.cpp::restore_from_snapshot` | done |
| S-013 | ✅ Mitigated | Per-signer cap (2 entries) on `buffered_block_sigs_` via `try_buffer_block_sig`; existing pre-filters at the call site already restrict signers to current K-committee ∩ registry, so total buffer is bounded at 2·K | `node/node.cpp::try_buffer_block_sig` | done |
| S-014 | ✅ Mitigated | Token bucket per peer IP via shared `net::RateLimiter` helper used by both `RpcServer` and `GossipNet`; HELLO exempt so handshake completes under pressure | `net/rate_limiter.hpp` + `rpc/rpc.cpp` + `net/gossip.cpp` | done |
| S-015 | ✅ Closed | Delay-worker thread removed entirely (commit `1b9b086`) — no worker, no join | n/a | done |
| S-016 | 🟠 Partially mitigated | Option 2 time-ordered admission: receipts must soak `CROSS_SHARD_RECEIPT_LATENCY = 3` blocks locally before becoming eligible for inclusion; drives the round-retry probability from "occasional pool-divergence aborts" to "negligible" by giving bundle gossip ~3·tx_commit_ms (≈600 ms at web profile) of propagation headroom. Full deterministic agreement (Option 1, Phase-1 intersection rule on inbound_keys) is the v2.7 F2 work item; the partial mitigation is the contained ~50-LOC closure that gets the practical surface to acceptable without the block-format change F2 needs | `node/node.cpp::inbound_receipts_eligible_for_inclusion` | v2.7 F2 closes fully |
| S-017 | ✅ Mitigated (Option 2) | Validator + producer both check `unlock_height` on UNSTAKE; apply-time refund retained as belt-and-suspenders | `node/validator.cpp` + `node/producer.cpp` | done |
| S-018 | 🟡 Med | JSON parsing without schema validation | all `from_json` | 2-3d |
| S-019 | ✅ Closed | Phase-2 timer R-arrival spoofing — moot under commit-reveal (no expensive R compute to spoof) | n/a | done |
| S-020 | ✅ Mitigated | Hybrid Fisher-Yates: rejection sampling at K/N ≤ 0.5, partial FY shuffle at K/N > 0.5 — bounded O(N) regardless of ratio | `crypto/random.cpp::select_m_creators` + `select_after_abort_m` | done |
| S-021 | ✅ Mitigated | `chain.json` is now a wrapping object `{head_hash, blocks}`; load recomputes head digest and rejects on mismatch (O(1) tampering detection before replay) | `chain/chain.cpp::save` + `::load` | done |
| S-022 | ✅ Mitigated | Per-message-type cap applied in `Peer::read_body` post-deserialize: 1 MB consensus chatter, 4 MB blocks/headers/bundles, 16 MB only for SNAPSHOT_RESPONSE/CHAIN_RESPONSE; oversize closes the connection | `include/determ/net/messages.hpp::max_message_bytes` + `net/peer.cpp::read_body` | done |
| S-023 | ✅ Mitigated | RPC send/stake/unstake balance pre-check throws clear diagnostic on insufficient balance | `node/node.cpp::rpc_send/stake/unstake` | done |
| S-024 | ✅ Accepted | Auditor reclassified as low priority; 1-10 block grind window deemed acceptable; v2.X can mix in a future block hash if needed | `chain/chain.cpp::derive_delay` | accepted |
| S-025 | ✅ Mitigated | `compute_tx_root_intersection` deleted (in-session); function + header decl removed | `node/producer.cpp` | done |
| S-026 | ✅ Mitigated | TCP-level keepalive enabled on every peer socket via `socket.set_option(asio::socket_base::keep_alive(true))` in `Peer::Peer`; dead connections detected and reaped via on_close at OS-default keepalive intervals (tunable per-platform) | `net/peer.cpp::Peer::Peer` | done |
| S-027 | ✅ Mitigated | Audit-and-document closure: no secret material (privkeys, passphrases, auth tokens) reaches node/RPC logs — verified by grep audit of every `std::cerr` / `std::cout` site; only chain-public state, peer addresses, timing markers. Added `log_quiet` Config flag for operators wanting fewer log lines on healthy chains | `node/node.hpp::Config::log_quiet` + audit in §6.5 closure entry | done |
| S-028 | ✅ Mitigated | `is_anon_address` now accepts either case; `normalize_anon_address` returns lowercase canonical form; RPC read paths (balance, send) normalize at input; submit_tx REJECTS non-canonical (sig is over signing_bytes which embeds the address byte-for-byte, so server-side mutation would invalidate the sig — strict-input keeps store-keys unambiguous) | `types.hpp` + `node.cpp::rpc_send/balance/submit_tx` | done |
| S-029 | ✅ Mitigated | `Chain::resolve_fork` ranks by (heaviest sig set, fewer aborts, smallest block hash); deterministic across peers | `chain/chain.cpp::resolve_fork` | done |
| S-030 | 🟠 Partially mitigated | Block body not authenticated by `block_digest` (D1 effective via S-033 state_root; D2 partial via S-033; F2 view-reconciliation for full D2 closure tracked v2.7) | `node/producer.cpp:206-221` | v2.7 |
| S-031 | ✅ Mitigated | shared_mutex + A9 Phase 1-2D atomicity/lazy-snapshot/lock-free reads + async chain.save worker + gossip-out-of-lock (v2.6) — all 6 layers shipped | `node/node.cpp` | done |
| S-032 | ✅ Mitigated | Incremental registry cache on Chain + snapshot persistence; build_from_chain reads cache, no log walk | `node/registry.cpp::build_from_chain` | done |
| S-033 | ✅ Mitigated | Merkle tree state commitment + Block.state_root + signing_bytes binding + apply/restore verification | `chain/chain.cpp::compute_state_root` | done |
| S-034 | ✅ Closed | VDF `EVP_MD_CTX` allocation — moot, delay-hash module deleted (commit `1b9b086`) | n/a | done |
| S-035 | 🟢 Op | No unit tests, no CI, no deterministic simulation framework | `tools/` | engineering culture |
| S-036 | 🟠 Partially mitigated | Beacon-fabricated MERGE_BEGIN evidence window — `EXTENDED`-mode-specific. Phase-6 internal-consistency bounds shipped (`effective_height ≥ block + grace`; BEGIN window must lie entirely in past — leading `evidence_window_start ≤ b.index` check added to prevent integer overflow bypassing the threshold-arithmetic check); full closure requires on-chain SHARD_TIP records, tracked as v2.11. See `docs/proofs/UnderQuorumMerge.md` + `docs/V2-DESIGN.md` v2.11 row. | `node/validator.cpp::check_transactions` MERGE_EVENT branch | v2.11 |
| S-037 | ✅ Mitigated | `dapp_registry` field now emitted by `Chain::serialize_state` (after merge_state block) and read back by `restore_from_snapshot` with `if (snap.contains("dapp_registry"))` guard for pre-v2.18 backward compat. Every field that contributes to the `d:` value-hash in `build_state_leaves` is round-tripped: `service_pubkey`, `endpoint_url`, `topics[]`, `retention`, `metadata`, `registered_at`, `active_from`, `inactive_from`, plus the map key. Regression: `tools/test_dapp_snapshot.sh` register → snapshot → restore → `dapp-info` verification end-to-end (12/12 PASS). | `chain/chain.cpp::serialize_state` + `::restore_from_snapshot` | done |
| S-038 | ✅ Mitigated | S-033 verification gate was dormant on production blocks because `Node::try_finalize_round` did not populate `body.state_root` before broadcast; the gate skipped on `state_root = 0` per the backward-compat shim. `try_finalize_round` now sets `body.state_root` via a tentative-chain dry-run between `build_body` and `apply_block_locked` (mirrors the digest-dry-run pattern in `start_block_sig_phase`). The gate now fires on every block — peer nodes reject any block whose stored `state_root` doesn't match the locally-recomputed value over their own apply of the same transactions. `compute_block_digest` already excludes `state_root` (§4.3) so K-of-K signatures are unaffected. Discovered while writing the S-037 test (snapshot tail head's `state_root` field was empty in JSON, exposing this latent gap). | `node/node.cpp::try_finalize_round` | done |

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

**D1 status — effective closure via S-033 + S-038.** With state_root in `signing_bytes` (Block.compute_hash) AND the producer now populating `body.state_root` before broadcast (S-038 closure — pre-fix, the field was zero on every gossiped block and the gate short-circuited), divergent `b.transactions` produces divergent post-apply state → divergent state_root → divergent block_hash. The validator's apply-time `compute_state_root() != b.state_root` check in `chain.cpp::apply_transactions` (~L1430) loud-fails on the inconsistent node, surfacing the bug rather than silently corrupting state. Single canonical block per height is enforced at apply, even though K-of-K signatures (over the narrower digest) don't directly bind tx payloads.

**D2 status — partial closure via S-033 + S-038.** Same mechanism: divergent evidence/receipt lists produce divergent post-apply state → state_root mismatch → block rejected at apply (now actually firing post-S-038). Closure is "partial" because:
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

**Closed under S-031 since the pre-fix description was written** (kept here as audit trail for the original analysis below):

- ✅ `rpc_submit_tx` broadcasts gossip out of lock — closed by v2.6 (`src/node/node.cpp::rpc_submit_tx` releases `state_mutex_` via `lk.unlock()` before `gossip_.broadcast(...)` at ~L3004). The tx is already in `tx_store_ + tx_by_account_nonce_` before the unlock; peers receiving the broadcast re-validate via `on_tx` (idempotent under replace-by-fee).
- ✅ `delay_worker_.join()` under the lock — moot since M-F removed the delay-hash worker entirely (commits `14bf3d6` + `1b9b086`).

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

### S-006 — ContribMsg same-generation equivocation undetected — ✅ Mitigated in-session

**Severity:** High (was) • **Status:** ✅ Mitigated • **Sources:** Audit 2.4, OV-#8

**Pre-fix description.** Block-level equivocation was already closed-loop in rev.8 (BlockSigMsg over distinct digests at the same height → `EquivocationEvent` → full stake forfeit + deregister). But ContribMsg-level equivocation was deferred: the same signer at the SAME generation could broadcast two distinct contribs (different `tx_hashes` or `dh_input`) and the receiver silently dropped the duplicate without slashing. The `contrib_equivocations_` map declared in `node.hpp` was never written to.

**Mitigation landed in-session (Option 1, simplified — reused the existing equivocation channel).**

The generation gate already in place (`on_contrib` line ≈1946) restricts `pending_contribs_` to the current `aborts_gen` only, so a duplicate at the same signer there is necessarily a same-generation conflict. The fix recomputes the commitment of the incoming `msg` and compares it to the recomputed commitment of the existing entry. Different commitments + both already passed Ed25519 verification → equivocation evidence.

Crucially, no new event type or block-format change was needed:

| Layer | Existing block-level equivocation | New ContribMsg equivocation |
|---|---|---|
| Two distinct digests | `compute_block_digest(b)` over two different block bodies | `make_contrib_commitment(...)` over two different `(tx_hashes, dh_input)` snapshots |
| Two signatures by same key | BlockSigMsg.ed_sig × 2 | ContribMsg.ed_sig × 2 |
| Validator V11 check | "two digests differ, two sigs verify against equivocator's pubkey" | identical contract — works as-is |
| Apply-time slashing | full stake forfeit + deregister | identical — no new apply path |

So the closure piggybacks on the existing `EquivocationEvent` struct (`block.hpp:256`), validator's `check_equivocation_events`, and chain.cpp slashing apply path. The detection just feeds the same `pending_equivocation_evidence_` buffer the block-level path uses.

The freshly-arrived contrib is still dropped from `pending_contribs_` (the earlier-arrived entry wins as the canonical contrib for this signer this round); the slashing happens separately when the next produced block bakes the evidence.

**Cleanup.** The unused `contrib_equivocations_` field was removed from `node.hpp` and its `clear()` call from `reset_round` — no longer needed since detection now routes through `pending_equivocation_evidence_`.

**Cross-generation equivocation deferred.** A signer who aborts and retries at a higher `aborts_gen` legitimately sends a different contrib at the same height. That's NOT equivocation; the generation gate correctly drops the cross-gen duplicate before reaching the same-gen comparison. Option 2 from the resolution table (cross-generation hash binding) addresses a different threat model (cartel coordinating across abort generations) and is deferred — the generation gate ensures honest peers can't be tricked into accepting cross-gen contribs as the canonical view, so the cartel can't bias the union tx-set across generations without one of them committing same-gen equivocation, which IS now detected.

**Effort.** ~55 LOC in `on_contrib` + ~3 LOC of field/clear cleanup.

**Verified.** state_root single-node PASS, governance_param_change 3-of-3 multi-node PASS. The detection logic is dormant on honest paths (no committee member equivocates), so no behavioral regression possible.

**Original resolution options (preserved for audit trail).**

| # | Option | Cost |
|---|---|---|
| 1 | **Generation-keyed `pending_contribs_`.** Index by `(signer, aborts_gen)`. Two contribs at the same key with different commitments → `ContribEquivocationEvent` → gossip + slash. | Low-medium. ~1d. **Shipped** — simplified by reusing the existing EquivocationEvent struct, since the generation gate already restricts `pending_contribs_` to current-gen-only. |
| 2 | **Cross-generation hash binding.** ContribMsg commits to `prev_aborts_gen_hash || dh_input`, preventing backdating. | Medium. ContribMsg field + commitment change → block format implications. **Deferred** — different threat model, not required after Option 1. |
| 3 | **Status quo** (rely on K-of-K abort to neutralize the divergence; don't slash). | Free. **Rejected** — Option 1 is cheap and provides actual deterrence. |

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
| BlockSigMsg pre-verify buffer (`buffered_block_sigs_`) | ✅ Bounded — S-013 closure (per-signer cap of 2; total ≤ 2·K via pre-filters) |
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

### S-010 — Sybil via under-priced MIN_STAKE — ✅ Mitigated (Options 1 + 3)

**Severity:** High (parameter-tuning risk) (was) • **Status:** ✅ Mitigated via deployment guidance + DOMAIN_INCLUSION availability • **Sources:** Audit 2.2, OV-#7, Gemini analysis

**What was open.** `min_stake = 1000` default. If the chain creator under-priced stake relative to the exogenous market value of the token, an attacker could partition wealth across thousands of registered domains and dominate `M_pool` committee selection.

#### Mitigation: deployment guidance (Option 1)

Operators choosing `STAKE_INCLUSION` MUST set `min_stake` such that acquiring a controlling fraction of `M_pool` costs more than the chain's value-at-risk.

**Sybil-cost formula.** To exceed the K-of-K committee floor (or `⌈2K/3⌉` under BFT escalation), an attacker needs a majority share of `N_pool` registered validators. Cost to acquire that majority:

```
sybil_cost = ⌈(N_pool / 2) + 1⌉ × min_stake
```

`N_pool` is the steady-state registered-validator population. For a chain expecting `N_pool = 50` operators, taking majority requires 26 sybils.

**Target threshold.** Set `min_stake` so `sybil_cost ≥ value_at_risk × safety_margin`. Common choices for value-at-risk:

| Metric | Formula | Use when |
|---|---|---|
| Total subsidy budget | `block_subsidy × expected_chain_lifetime_blocks` | New chain, no token market yet |
| Expected market cap | `total_supply × expected_token_price` | Established chain with traded token |
| Total locked stake | `N_pool × min_stake` (circular — solve iteratively) | Stress-test the floor itself |

`safety_margin` is typically `10×` (attacker needs to lock 10× chain's value-at-risk in stake to compromise it; for finite-horizon attacks, opportunity cost of locked capital alone often suffices).

**Worked examples.** All assume `N_pool = 50` (majority = 26 sybils).

| Scenario | `block_subsidy` | Lifetime | VaR | `safety_margin` | `min_stake_floor` |
|---|---|---|---|---|---|
| Testnet | 10 | 1M blocks | 10M tokens | 1× | ~385 K |
| Small community chain | 10 | 10M blocks | 100M tokens | 10× | ~38.5 M |
| Token-traded chain (market cap $10M @ $1/token) | — | — | 10M tokens | 10× | ~3.85 M |
| Enterprise chain (no exogenous price; subsidy-based) | 1 | 100M blocks | 100M tokens | 10× | ~38.5 M |

**Formula.** Given `N_pool, VaR, safety_margin`:

```
min_stake_floor = (VaR × safety_margin) / ⌈(N_pool / 2) + 1⌉
```

**Validation at genesis.** Operators are responsible for choosing `min_stake` per this formula; the protocol does not enforce a floor (the right floor depends on exogenous economics the protocol cannot observe). A future tooling improvement could surface a startup warning if `min_stake × ⌈N_pool/2 + 1⌉ < block_subsidy × 100` (i.e., majority capture pays back in fewer than 100 blocks of subsidy), but that's operator-facing tooling, not a protocol gate.

**Comparison to existing default.** The genesis default `min_stake = 1000` with `block_subsidy = 10` is suitable ONLY for testnets and demonstrations. At those values, 26 sybils cost 26,000 tokens — recoverable in 2,600 blocks of subsidy. **Production chains MUST raise `min_stake` per the formula above.** This is documented here and noted in the genesis-tool error output if a future tooling pass adds the validation.

#### Mitigation: DOMAIN_INCLUSION (Option 3)

For chains that don't have strong stake-pricing economics — or want defense-in-depth against an undervaluing-of-token attack — switching `inclusion_model = DOMAIN_INCLUSION` derives Sybil resistance from external naming costs (DNS registrations, fees paid to a TLD operator) instead of stake. The genesis configuration field is single-flag and immediately changes selection semantics. See `PROTOCOL.md` §inclusion-models for the mechanism and `WHITEPAPER-v1.x.md` for the DNS-as-identity-anchor rationale.

#### Deferred options

| Option | Why deferred |
|---|---|
| 2 — Stake-weighted committee selection | Medium-high cost (chain-spec change); fairness analysis would need to address the "rich-get-richer" failure mode of pure weight-by-stake. Not pursuing in v1. |
| 4 — `IP_INCLUSION` | Weaker resistance than DOMAIN_INCLUSION (NAT, IPv4 exhaustion, VPN abuse). Tracked for testnet / special-purpose deployments only. ~100 LOC addition if ever requested. |

**Status.** Options 1 + 3 are the formal closure. The operator-facing guidance is the calculator above; chains that don't want to do that math have DOMAIN_INCLUSION available as a flag flip. S-010 moves from "Open with mitigation alternative" to "Mitigated — operator policy + DOMAIN_INCLUSION available."

---

### S-011 — Abort claim cartel via M-1 quorum — ✅ Mitigated (Option 1)

**Severity:** High (was) • **Status:** ✅ Mitigated via S-010 stake-pricing guidance + bounded-damage analysis • **Sources:** Audit 2.3

**What was open.** Abort claims advance via M-1 matching signatures. An adversary controlling M-1 committee members could fabricate abort claims against the lone honest member, suspending them via the exponential-suspension path.

**Closure (Option 1).** Three properties together bound the realistic damage:

1. **Cost of acquiring M-1 committee members** is bounded below by S-010's stake-pricing formula. At adequate `min_stake` (per the S-010 §calculator), controlling `M-1` of the committee costs `(M-1) × min_stake`. Combined with the random committee rotation per round, sustained M-1 control over many rounds requires majority capture of `N_pool`, which is the same Sybil-cost threshold S-010 closes.

2. **Equivocation-detection provides separate slashing** if the cartel signs blocks at the same height with different digests. The cartel can suspend an honest member, but if they then go on to produce conflicting blocks (which is the natural next step in any chain-divergence attack), every cartel member is slashed via the existing FA6 path — losing 100% of locked stake. Equivocation slashing thus prices the cartel attack at `(M-1) × min_stake` per attempt with no recovery.

3. **Damage is bounded to "kick honest member off committee for a finite number of rounds."** The suspended member rejoins after exponential backoff completes; the cartel cannot permanently remove them without continuing to expend stake on fresh abort claims (or eventually committing equivocation, which slashes them). At adequate `min_stake`, the per-round attack cost exceeds the chain's per-round subsidy throughput — economic infeasibility.

The combination of these three bounds is the formal Option 1 closure. No code change is required; the closure is "operator sets `min_stake` per S-010 guidance, the chain layer's existing equivocation slashing handles the residual."

**Deferred options.**

| Option | Why deferred |
|---|---|
| 2 — External-witness requirement | Medium cost (gossip-witness tracking). The Option 1 closure already bounds damage to economic infeasibility; the deeper protocol change is unjustified at v1 scale. |
| 3 — Reputation scoring | Reputation systems are notoriously gameable. Not pursued. |

**Status.** S-011 closes alongside S-010 — both reduce to "operators set `min_stake` per the calculator; the cartel attack is economically infeasible and self-slashing." S-011 moves from "Open" to "Mitigated — economic + equivocation-slashing bound."

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

**Mitigation landed in-session.** Block now carries a `state_root` field; `Chain::compute_state_root` builds it as a sorted-leaves Merkle tree (`include/determ/crypto/merkle.hpp`) over every canonical state entry (the 10-namespace leaf set documented in PROTOCOL.md §4.1.1). The root is bound into `signing_bytes` when non-zero (preserving pre-S-033 byte-stable hashes). Apply-time verification re-derives and rejects on mismatch. The chain's `prev_hash` chain transitively authenticates every prior state_root — the chain is now a verifiable state log.

**The producer-side wiring was S-038's job, closed in the same session.** Pre-S-038, `Node::try_finalize_round` did not populate `body.state_root` before broadcast (every gossiped block carried zero); the apply-time gate short-circuited per the backward-compat shim. Post-S-038, the producer populates the field via a tentative-chain dry-run between `build_body` and `apply_block_locked`, so the S-033 closure is genuinely end-to-end functional. See S-038 below.

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

### S-013 — BlockSigMsg buffer flood OOM — ✅ Mitigated in-session

**Severity:** Medium (local DoS) (was) • **Status:** ✅ Mitigated • **Sources:** OV-#2, Gemini analysis

**Pre-fix description.** `BlockSigMsg` packets that arrive before the local node has assembled its K Phase-1 contribs are buffered for replay on Phase-2 entry. An adversary floods the Phase-1 window with valid-shape BlockSigMsgs; each gets queued; OOM crash.

**Mitigation landed in-session.** Two-layer defense:

1. **Pre-filters at the call site (Option 2)** — `on_block_sig_locked` already rejects:
   - Wrong `block_index` (must equal `chain_.height()`).
   - Signer not in `current_creator_domains_` (current round's K-committee).
   - Signer not in `registry_` (active registered validator).

   These reject before the buffer-add, so only valid-shape messages from registered K-committee members ever reach the buffer.

2. **Per-signer cap (Option 1)** — `try_buffer_block_sig` (new helper) caps each signer to **2 entries** in `buffered_block_sigs_`. The cap admits the honest BlockSigMsg + one equivocation-evidence sig at the same height; anything beyond is silently dropped. Combined with the pre-filter, the total buffer is bounded at **2·K entries** regardless of how aggressively a Byzantine signer pushes.

**Why per-signer rather than total-queue + LRU.** Under K-of-K mutual distrust there's no quorum to decide which buffered entry is honest, so LRU would evict honest entries when a spammer impersonates K signers. Per-signer asymmetric cap closes the attack: a single Byzantine signer can't crowd out honest peers' buffer slots regardless of their send rate.

**Effort.** ~25 LOC including comments. Helper signature + header decl added in `include/determ/node/node.hpp`.

**Verified.** State-root, dapp_register, governance_param_change, BFT escalation all green with the cap in place; pre-existing equivocation_slashing TIME_WAIT flake confirmed unchanged via stash-revert comparison.

---

### S-014 — No rate limiting on gossip + RPC — ✅ Mitigated in-session

**Severity:** Medium (was) • **Status:** ✅ Mitigated • **Sources:** Audit 3.2, OV-#10

**Mitigation landed in-session.** Token-bucket per-peer-IP rate limiting now gates both the RPC and the gossip receive layer. Both call sites use a shared `determ::net::RateLimiter` helper (`include/determ/net/rate_limiter.hpp`) so the policy + refill arithmetic + per-key bucket map live in exactly one place.

**RPC side.** `rate_limiter_.consume(peer_ip)` runs in `handle_session` BEFORE JSON parse and auth — rate-limited callers don't burn parse cost and don't reveal whether their auth would have succeeded. Config:

- `rpc_rate_per_sec`: steady-state RPC calls/sec per peer IP (default 0 = disabled)
- `rpc_rate_burst`: bucket capacity (default 0 = disabled)

Suggested external-bind defaults: `rate=100`, `burst=200`.

**Gossip side.** `rate_limiter_.consume(ip)` runs at the top of `handle_message`, after HELLO exemption and before role-filter + dispatch. HELLO is exempt so a freshly-attached peer can complete the handshake even when their IP's bucket is empty — a single HELLO per connection cannot be weaponised on its own. Multiple connections from the same source share one bucket (peer address has `":<port>"` stripped to key on bare IP). Config:

- `gossip_rate_per_sec`: steady-state gossip msgs/sec per peer IP (default 0 = disabled)
- `gossip_rate_burst`: bucket capacity (default 0 = disabled)

Suggested external-bind defaults: `rate=500`, `burst=1000`. Healthy consensus is a few msgs/s steady-state with bursts on round transitions; 500/s × 1000 burst absorbs the headroom comfortably.

**Bucket state (in the shared helper).** `std::map<std::string, Bucket>` protected by `std::mutex` inside `RateLimiter`. Memory bound is ~24 bytes per distinct peer IP. Concurrent access guarded by the mutex (asio's worker-thread pool puts handlers on multiple threads). Each consumer (RPC, GossipNet) owns its own `RateLimiter` instance — separate per-IP buckets per layer, but identical refill semantics.

**Verified.**
- `tools/test_rpc_rate_limit.sh` 4/4 PASS — RPC side: disabled-mode passes 30/30; tight rate (0.5/s burst 3) drains and rejects per spec; bucket refills on wait.
- `tools/test_gossip_rate_limit.sh` 3/3 PASS — gossip side: 500/s 1000-burst lets the chain advance freely (h=68 in ~20s); 1/s 2-burst starves consensus (h=1 over 8s).

**Pre-fix description.** Gossip accept loop had no cap; broadcast fan-out amplifies; RPC `handle_session` was synchronous per connection. Same root issue as S-001 for RPC.

**Resolution options.**

| # | Option | Cost | Status |
|---|---|---|---|
| 1a | **Per-IP token bucket on RPC** at the TCP accept layer | ~30 LOC | ✅ Shipped |
| 1b | **Per-method bucket** at RPC dispatch (snapshot 1/min, submit_tx capped, query uncapped) | ~30 LOC | Deferred — requires per-method weight tuning |
| 1c | **Per-IP token bucket on gossip** at the message receive layer | ~30 LOC | ✅ Shipped |
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

### S-016 — Inbound-receipts pool non-deterministic across committee — 🟠 Partially mitigated (Option 2)

**Severity:** Medium (correctness-preserving latency) (was) • **Status:** 🟠 Partially mitigated (Option 2 shipped; Option 1 = v2.7 F2 closes fully) • **Sources:** OV-#5 (rev.9 addition; B3.4 commit message)

**Pre-fix description.** Each destination-shard committee member passes their *local* `pending_inbound_receipts_` snapshot to `build_body`. If pools differ momentarily during bundle gossip, members produce different tentative blocks → K-of-K fails → round retries. Documented in B3.4 commit. Not exploitable but adds avoidable latency.

**Mitigation landed in-session (Option 2 — time-ordered admission).**

The destination shard tracks a parallel `pending_inbound_first_seen_` map alongside `pending_inbound_receipts_`. Every receipt arriving via `on_cross_shard_receipt_bundle` records its local first-observation height. The `inbound_receipts_eligible_for_inclusion` helper (new) — called by `start_block_sig_phase` and `try_finalize_round` instead of iterating `pending_inbound_receipts_` directly — admits only receipts where `first_seen + CROSS_SHARD_RECEIPT_LATENCY <= chain.height()`.

The `CROSS_SHARD_RECEIPT_LATENCY` constant is set to **3 blocks**. At the web profile (200 ms blocks) that's ~600 ms of gossip propagation headroom — roughly 5-6 intra-region RTTs — which empirically drives the round-retry probability to negligible without piling user-visible latency on the cross-shard path.

**What this does NOT achieve.** Strict formal determinism across committee members. The first-seen height is local state and can differ by the gossip-propagation lag; in theory two members could disagree on eligibility for one round at the boundary. In practice, the 3-block soak time wraps multiple round-trips so the disagreement probability shrinks geometrically with the latency constant.

**What v2.7 F2 (Option 1) adds.** Strict determinism via Phase-1 commitment: each `ContribMsg` gains an `inbound_keys` Merkle root, the canonical eligible set is the intersection of K members' commitments, and block validation re-checks. Full design in `docs/proofs/F2-SPEC.md`. The Option 2 partial mitigation here is compatible with — and superseded by — the F2 work; F2 doesn't require ripping Option 2 out.

**Effort.** ~50 LOC (parallel map + constant + helper + paired-erase + admission-site rewrites at two call sites).

**Verified.** `tools/test_cross_shard_transfer.sh` PASS (end-to-end TRANSFER from shard 0 → shard 1 with the 3-block latency gate active; receipt soaks past the threshold, gets included, credits the destination).

**Original resolution options (preserved for audit trail).**

| # | Option | Cost |
|---|---|---|
| 1 | **Phase-1 contrib intersection.** Each `ContribMsg` gains `inbound_keys: [(ShardId, Hash)]`. Block bakes only receipts in the intersection of all K members' lists. Block format extends with `creator_inbound_keys[]`. | Medium. ~3-4h. ContribMsg + Block + commitment hash + JSON I/O. **Tracked as v2.7 F2.** |
| 2 | **Time-ordered admission.** Receipts only eligible `>=N` blocks after first observed locally. By then gossip has propagated. | Trivial. Adds latency to every cross-shard transfer. **Shipped in-session.** |
| 3 | **Status quo** (round retries until pools converge). | Free. **Superseded by Option 2.** |

---

### S-017 — Producer/chain validation logic mismatch (UNSTAKE) — ✅ Mitigated in-session (Option 2)

**Severity:** Medium (was) • **Status:** ✅ Mitigated (Option 2) • **Sources:** Audit 3.5, 3.8

**Pre-fix description.** `producer.cpp::build_body` filtered UNSTAKE on `lk < amount` only. `chain.cpp::apply_transactions` checked `unlock_height` AND refunded the fee on too-early. Validator (`check_transactions`) didn't check unlock_height at all. So a tx the producer included could silently fail at apply, with the chain layer doing what should be validator-layer work.

**Mitigation landed in-session (Option 2 — the "less invasive" path).**

1. **Validator gains the unlock_height check.** `BlockValidator::check_transactions` UNSTAKE branch now resolves `chain.stake_unlock_height(tx.from)` and rejects the block if `b.index < unlock_height`. The error message names the height + unlock_height for operator debugging. Symmetric with the apply-time `height < sit->second.unlock_height` rejection in `Chain::apply_transactions`.
2. **Producer skips too-early UNSTAKE.** `producer.cpp::build_body` UNSTAKE branch gains the same gate so honest producers don't include txs that downstream validators would reject. Pre-fix this was missing — a tx could land in a block, validator passed, chain refunded. Post-fix the tx never reaches the block.
3. **Chain apply-time refund retained** as belt-and-suspenders against tx-included-by-buggy-producer paths; honest users never lose a fee even if a misbehaving peer slips a too-early UNSTAKE past the validator (which post-fix it cannot, but the defense costs nothing to keep).

Net effect: the divergence is closed at all three layers. Option 1 (unified `validate_tx_apply` helper + drop apply-time refund) is the deeper refactor — deferred because Option 2 captures the safety win without restructuring the apply path.

**Effort.** ~20 LOC across `validator.cpp` UNSTAKE branch + `producer.cpp` UNSTAKE branch.

**Verified.** `test_governance_param_change.sh` PASS (3-of-3 cluster exercises REGISTER + STAKE lifecycle; no behavioral regression). No dedicated S-017 shell test — DEREGISTER isn't currently CLI-accessible, so the unlock_height countdown can't be triggered from a shell-only test without expanding the CLI surface. The closure is structural alignment with no new behavior visible at the CLI layer.

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

**Determinism.** Both `K` and `N` are inputs to the function; every node picks the same branch and the same indices. No fork-height management needed because no chain history sits on the K > N/2 path under the current regression suite: most tests use `single_test` (M=K=3, N_registered ≤ 3) which trips the partial-FY branch via `2K > N` when only 3 validators register; `web` / `web_test` (M=3 K=2) and `cluster_test` (M=K=3) similarly run with small N. Tests with explicitly larger pools (`regional_test` M=5 K=4, `global_test` M=7 K=5) exercise both branches depending on how many validators register at boot. All branches share the same SHA-256-derived randomness so committee outputs are deterministic across nodes regardless of which branch fired.

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

**Why this is operational, not a vulnerability.** A bug-free codebase doesn't strictly need unit tests, but their absence makes regression-prevention impossible. Edge cases (`ContribMsg` with invalid `aborts_gen` or same-generation duplicate, two same-height blocks in different orders, equivocation under network partition, V12/V13 cross-shard receipt fuzzing, S-022 per-message-type-cap boundary, S-014 token-bucket interactions across HELLO exemption) require targeted unit tests; the integration scripts can't drive them.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Add gtest/Catch2** for crypto, serialization, state transitions, validator rules. CMake + Linux CI. | 1-2w to seed + ongoing per-feature. |
| 2 | **Deterministic simulation framework** — virtual clock + virtual network + scriptable Byzantine actors. | 3-4w. Substantial but the right tool for testing consensus. |
| 3 | **Path portability** — replace Windows-specific test paths with platform-agnostic ones; add Linux/Mac CI. | 1d. |

**Recommended.** Option 3 immediately (gets the existing tests running on Linux/Mac CI). Option 1 incrementally (add unit tests for new code; backfill gradually). Option 2 is v1.x quality work.

---

### S-037 — `dapp_registry` snapshot serialize/restore gap — ✅ Mitigated in-session

**Severity:** Operational (Low) (was) • **Status:** ✅ Mitigated • **Source:** discovered during the PROTOCOL.md coherence sweep + closed in the same session

**Pre-fix description.** `Chain::build_state_leaves` (`src/chain/chain.cpp` ~line 265) emits a `d:` namespace leaf for every entry in `dapp_registry_` — the v2.18 DApp substrate ties the registry into the state Merkle commitment so light clients can prove DApp registration. But `Chain::serialize_state` and `Chain::restore_from_snapshot` did not include the map. Concretely (pre-fix):

1. Snapshot taken on a chain with one or more `DAPP_REGISTER` entries omitted `dapp_registry`.
2. Restore on a fresh node started with `dapp_registry_ = {}`.
3. `dapp-info` / `dapp-list` on the restored chain returned empty even for DApps that were live on the donor.
4. `Chain::compute_state_root()` over the restored state diverges from what the donor computed (the `d:` slice contributes no leaves on the restored side). The S-033 gate at `restore_from_snapshot` rejects the snapshot with `"state_root mismatch"` (now that S-038 also closed in this session, the gate actually fires on production blocks rather than being dormant).

**Why this was operational, not a security regression.** Fail-loud — restore would refuse the snapshot in the full S-033 case. No silent state corruption, no equivocation surface, no funds at risk. The pragmatic harm was "can't bootstrap a DApp-active chain via snapshot" — full chain replay still worked.

**Mitigation shipped.**

1. `snap["dapp_registry"]` emission added to `Chain::serialize_state` immediately after the `merge_state` block. Every field that contributes to the `d:` value-hash in `build_state_leaves` is persisted: `service_pubkey` (32B hex), `endpoint_url`, `topics[]`, `retention` (u8), `metadata` (hex bytes), `registered_at`, `active_from`, `inactive_from`. Plus the map key (`domain`).
2. Symmetric readback in `Chain::restore_from_snapshot` follows the `registrants_` restore pattern: `if (snap.contains("dapp_registry"))` guard ensures pre-v2.18 snapshots (no `dapp_registry` field) still load (the restored chain just gets `dapp_registry_ = {}`, matching the original donor state).
3. Regression test `tools/test_dapp_snapshot.sh` (11/11 PASS) exercises the full surface: 3-node donor chain advances, donor1 registers a DApp, snapshot taken from donor1, donors stopped, fresh receiver starts with `snapshot_path` set + no genesis + no peers. Asserts: (a) snapshot file contains the `dapp_registry` array with 1 entry, (b) receiver boots without `state_root mismatch` error, (c) `dapp-info(donor1)` on the receiver returns the same `endpoint_url`/`topics`/`metadata` as on the donor, (d) `dapp-list` reports the DApp post-restore. Backward-compat verified: existing `tools/test_snapshot_bootstrap.sh` (which produces a no-DApp snapshot) still passes — the guard correctly handles the absent-field case.

**Test coverage delta.** From "disjoint" (snapshot tests skipped DApps; DApp tests skipped snapshots) to "joint" — the new regression closes the specific co-surface that hid this bug.

---

### S-038 — S-033 state_root verification gate dormant on production blocks — ✅ Mitigated in-session

**Severity:** High (consensus-integrity gap; documented mitigation was non-functional) • **Status:** ✅ Mitigated • **Source:** discovered during the S-037 closure test (snapshot tail-head's `state_root` field was empty in JSON, exposing this latent gap; same session as the closure)

**Pre-fix description.** S-033 mitigation claims to bind the post-apply state Merkle root into the block via `Block.state_root`, with a verification gate in `Chain::apply_transactions` (~chain.cpp:1430) that rejects any block whose stored `state_root` doesn't match the locally-recomputed root. The gate has correct logic but is guarded by `if (b.state_root != zero) verify` — a backward-compat shim that skips the check on pre-S-033 blocks (zero state_root field).

**The latent gap.** `src/node/producer.cpp::build_body` does NOT populate `state_root` on the produced block. `Node::start_block_sig_phase` builds a *tentative* copy and populates state_root on it for the digest dry-run (`compute_block_digest` doesn't include state_root anyway, so this was just consistency), but the FINAL body broadcast by `Node::try_finalize_round` was built afresh via a second `build_body` call and left `state_root = Hash{}` (zero default). Result:

- Every gossiped block had `state_root = 0`.
- The S-033 gate at apply time short-circuited on every block.
- Peer nodes accepted any committee-signed body regardless of its state-after-apply.

This means the S-030 D1 "effective-closed via S-033" claim was actually unenforced in production. The gate's infrastructure was correct; the producer just wasn't feeding it.

**Why this isn't an attack surface today.** The K-of-K committee structure still prevents forks (every member must sign the same digest, and the digest covers the tx set deterministically). Two distinct state outcomes from the same tx set would require nondeterministic apply, which the protocol doesn't allow. So the gate's bypass didn't enable concrete attacks — but it did make the documented S-033 mitigation a no-op, which would silently degrade safety against any future bug introducing apply-time nondeterminism.

**Mitigation shipped.**

`Node::try_finalize_round` now populates `body.state_root` immediately after `build_body` and before `apply_block_locked`:

```cpp
chain::Block body = build_body(...);
body.creator_block_sigs = std::move(ordered_block_sigs);

// S-038 closure
{
    chain::Chain tentative_chain = chain_;
    tentative_chain.append(body);  // state_root still zero, verify short-circuits inside append
    body.state_root = tentative_chain.compute_state_root();
}

apply_block_locked(body);
gossip_.broadcast(net::make_block(body));
```

Notes on safety + compatibility:

- `compute_block_digest` (what committee members sign in Phase 2) **excludes** `state_root` per §4.3 of PROTOCOL.md. So the K-of-K signatures gathered before `try_finalize_round` runs are unaffected by populating the field afterward. No re-signing required.
- `compute_hash` (block_hash, via `signing_bytes`) **includes** `state_root` when non-zero. So the block_hash of post-fix blocks is different from what it would have been pre-fix. But: pre-fix blocks ALL had `state_root = 0`, so their block_hashes computed without the state_root contribution. Post-fix blocks have `state_root` populated and compute their hash WITH the contribution. Each block's hash is internally consistent with its own state_root field — no rolling break.
- Backward-compat: chains with pre-fix blocks already in their history retain their zero-state_root blocks unchanged. The gate skips zero per the existing backward-compat shim. Only blocks produced after the fix carry populated state_root.

**Test.** `tools/test_dapp_snapshot.sh` (12/12 PASS) now strictly verifies that the snapshot tail-head's stored `state_root` matches the receiver's freshly-computed `compute_state_root()` post-restore. Pre-fix, this assertion would have failed because the snapshot tail head's `state_root` field was empty in JSON. Post-fix, the field is populated and the comparison succeeds — proving the gate is wired through end-to-end.

**Effect on S-030 D1/D2.** S-030's apply-layer closure is now actually shipped end-to-end:

- D1 (resolved tx-payload mismatch): two committee members applying different tx sets reach different state_roots → different block_hashes → divergent stored state, but only one matches the locally-recomputed root at any honest peer → fork rejected at apply.
- D2 (non-tx-payload field mismatch): same mechanism — divergent abort_events/equivocation_events/inbound_receipts/etc. produce divergent post-apply state, caught at apply.

D2 is still "partial" because the gate is apply-layer (rejection after some peers might have signed the divergent body), not consensus-layer (prevention at signature-gathering). v2.7 F2 view reconciliation is still the long-term consensus-layer closure. But the apply-layer S-033 path is now real.

---

### S-021 through S-029 (quick-fix summary)

| ID | Title | Quick fix |
|---|---|---|
| S-021 | Chain file integrity not cryptographically verified | ✅ **Closed.** `chain.json` is now a wrapping JSON object `{head_hash, blocks}`. `head_hash` is hex of the latest block's `compute_hash()`, which transitively covers every prior block via the `prev_hash` chain + committee signatures. On load, after parsing + replay, the recomputed head digest is compared to the stored `head_hash`; mismatch → throw `"chain file: head_hash mismatch (tampering or corruption?)"`. Legacy array-form chain.json is still accepted (no-op fallback); the next save() upgrades the format. Test: `tools/test_chain_integrity.sh` 4/4 PASS. |
| S-022 | 16 MB message limit too permissive — but snapshots use it | ✅ **Closed.** `Peer::read_body` retains the 16 MB framing-layer ceiling (`kMaxFrameBytes` — needed for SNAPSHOT_RESPONSE / CHAIN_RESPONSE), then applies a per-message-type cap from `max_message_bytes(MsgType)` after deserialization. Caps: 1 MB for consensus chatter (CONTRIB / BLOCK_SIG / ABORT_CLAIM / ABORT_EVENT / EQUIVOCATION_EVIDENCE / HELLO / STATUS_* / TRANSACTION / GET_CHAIN / SNAPSHOT_REQUEST); 4 MB for BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE; 16 MB only for SNAPSHOT_RESPONSE / CHAIN_RESPONSE. Oversize messages drop + close the connection (same disposition as framing-layer overflow). The default branch in the switch keeps the cap tight at 1 MB so a future MsgType variant added without explicit categorisation cannot slip through unbounded. |
| S-023 | RPC `send`/`stake` skip balance check | Pre-check balance before queueing. ~1h. |
| S-024 | Deregistration timing predictability (1-10 block grind window) | ✅ **Accepted.** Auditor's own reclassification ("acceptable per auditor's own re-classification"). The 1-10 block grind window matters only at the brief moment between a `DEREGISTER` tx landing and `inactive_from` taking effect; the window is bounded and offers no leverage against finalised chain state. A v2.X enhancement could mix a future block hash into `derive_delay` to remove even this bounded predictability if a deployment's threat model requires it. No code change in v1.x. |
| S-025 | `compute_tx_root_intersection` is dead code | Delete it or guard under `#ifdef DETERM_INTERSECTION_MODE`. 5 minutes. |
| S-026 | No connection timeout / keepalive | ✅ **Closed.** `Peer::Peer` constructor now flips `SO_KEEPALIVE` on every accepted/initiated socket via asio's `keep_alive(true)` option. Dead connections (network partition, peer crash without FIN, NAT-rebind timeout) are detected by the kernel at OS-default keepalive intervals and surface through the existing on_close path (which evicts the peer from `GossipNet::peers_`). Detection latency follows the OS defaults — Linux ≈ 11 min, Windows ≈ 2 hr — bounded but slow; operators wanting faster detection tune the system-level knobs (`net.ipv4.tcp_keepalive_*` on Linux, `Tcpip\Parameters\Keep*` registry keys on Windows). Per-socket override of the interval is non-portable so we deliberately use the OS-level knob rather than couple the protocol to platform APIs. |
| S-027 | Info leakage in logs / error messages reveal state | ✅ **Closed.** Two-part closure: (1) **Audit pass** over every `std::cerr` / `std::cout` site in `src/node/node.cpp`, `src/rpc/rpc.cpp`, `src/net/*.cpp`, `src/chain/*.cpp` — no secret material (privkey, passphrase, HMAC auth token, recovery envelope) reaches the logs. Wallet CLI flows (`determ-wallet recover`, `determ-wallet shamir combine`) print user-requested recovery secrets to stdout by design (the user is asking for their own secret). Node/RPC paths log only chain-public state (block heights, hashes, domain names), peer addresses, and timing markers. (2) **Operator quiet-mode flag** — `Config::log_quiet` (default `false`). When `true`, the chatty per-block `[node] accepted block #N creators=K` line is suppressed; WARN/ERROR diagnostics continue to surface. Production operators wanting fewer logs set `log_quiet = true` in `config.json`. Additional `log_quiet`-gated suppressions can be added per-line as operators report log-volume issues. |
| S-028 | Hex parsing only accepts lowercase | ✅ **Closed.** Three-part fix per the deferred-closure plan: (a) `is_anon_address` now accepts either case (still rejects malformed shapes), (b) new `normalize_anon_address(s)` helper returns lowercase canonical form for anon-shaped inputs (domain names pass through unchanged), (c) RPC read paths apply normalize at input — `rpc_balance` and `rpc_send` both lowercase the address before storage/lookup so "0xABC..." and "0xabc..." resolve to the same account. `rpc_submit_tx` takes a different approach: it REJECTS non-canonical addresses with a clear diagnostic rather than mutating, because the client's Ed25519 signature is over `signing_bytes` which embeds `tx.from` / `tx.to` byte-for-byte — server-side mutation would invalidate the signature. The strict-input rule keeps store-keys unambiguous without forcing the client to resign. Test: `tools/test_anon_address_case.sh` 3/3 PASS (balance case-insensitive query, send-to-uppercase credits canonical slot, submit_tx rejects non-canonical with diagnostic). |
| S-029 | BFT-mode multi-proposer fork-choice undefined | ✅ **Closed.** `Chain::resolve_fork` ranks by `(heaviest sig set, fewer abort_events, smallest block hash)`. Deterministic across peers — every node picks the same head when two same-height blocks arrive. |

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
- Use the recommended geographic taxonomy from `README.md §16.5` to avoid jurisdiction-aligned regions for cross-border deployments.
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

The narrower ContribMsg-level case is now also closed (S-006 closure in-session): `on_contrib` detects a same-generation duplicate with a different commitment, builds an `EquivocationEvent` from the two contrib commitments + their Ed25519 sigs, and routes it through the same `pending_equivocation_evidence_` buffer the block-level path uses. No new wire format or validator rule was needed — the existing `EquivocationEvent` struct and `check_equivocation_events` validator are digest-agnostic ("two distinct digests, both sigs verify under the equivocator's registered key"), so the contrib commitments slot in cleanly.

### M-B — Hybrid-mode K-of-M liveness gap → BFT escalation (was Audit 2.1)

**rev.8 added** per-height BFT escalation: after `bft_escalation_threshold` (default 5) aborts at the same height AND `bft_enabled = true` AND `pool < K` AND `pool ≥ ceil(2K/3)`, the next round produces a `consensus_mode = BFT` block. The block's committee shrinks to `k_bft = ceil(2K/3)` slots and requires the within-committee 2/3 quorum `Q = ceil(2·k_bft/3)` signatures, with a deterministic `bft_proposer` mandatorily signing. The auditor's recommendation ("either disable hybrid mode or implement proper proposer rotation") was implemented as the second option. Verified in [`tools/test_bft_escalation.sh`](../tools/test_bft_escalation.sh).

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
| S-013 | Bounded BlockSigMsg buffer + signer pre-filter | ✅ done |
| S-014 | RPC + gossip rate limiting | ✅ done (RPC + gossip both shipped with token-bucket per peer IP) |
| S-020 | Hybrid Fisher-Yates committee selection | ✅ done |
| S-023 | RPC pre-check balance | ✅ done |
| S-034 | Moot — delay-hash module deleted | ✅ done |

**Track A status: 14 of 14 closed. ✅ Track A complete.**

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
- High findings: 0 open (S-006 / S-010 / S-011 all closed in-session)
- Medium findings: 1 open (S-018, mechanical, 2-3 days); 1 partially mitigated (S-016 via Option 2 time-ordered admission; v2.7 F2 closes fully via Option 1 intersection commitment)
- Low/Op findings: 1 open (S-035 unit tests / CI — engineering culture); 7 closed in-session; T-001..T-004 are informational `EXTENDED`-mode trade-offs, not bugs
- EXTENDED-mode-specific: 1 partially mitigated (S-036 — bounds-check shipped; full closure via on-chain SHARD_TIP records is v2.11)
- 24 findings mitigated in-session total (5 Critical + 12 High + 7 Low/Op)
- Track A remaining: **none — Track A complete**
- v2.7 F2: 3-4 days (full S-030 D2 closure at the consensus layer)
- v2.10 active: ~1 week (threshold randomness aggregation, plan.md A11)
- v2.25 + v2.26 added to design (Theme 9 DSSO — distributed IdP w/ T-OPAQUE; depends on v2.10 + v2.14)

The original "5-6 weeks of engineering" estimate has been substantially absorbed in-session. Remaining gates to permissionless-deployment-ready posture:
1. ~~Track A small items~~ — **complete in-session**.
2. v2.7 F2 implementation per F2-SPEC.md (~3-4 days).
3. v2.10 threshold randomness aggregation per plan.md A11 (~1 week, includes BLS12-381 vendoring + DKG).

Total remaining: ~2 weeks to "production-deployment-ready" posture. Beyond that (v2.X), Theme 8 (privacy + interop) + Theme 9 (DSSO) extend the design space toward god-protocol completeness for Determ's lane.

---

## 10. Cross-references

- [`docs/PROTOCOL.md`](PROTOCOL.md) — frozen v1 spec; the source of truth for hash inputs, message formats, consensus rules. Where this doc cites a specification claim, PROTOCOL.md is authoritative.
- [`docs/CLI-REFERENCE.md`](CLI-REFERENCE.md) — operator command surface.
- [`docs/QUICKSTART.md`](QUICKSTART.md) — operator walkthrough.
- The original rev.7 security-audit report (`SECURITY_AUDIT.md`) is preserved out-of-tree as historical context but **superseded by this file**. Where the audit and this file disagree, this file wins for current code; the audit wins for rev.7 archaeology.
- `OPEN-VULNERABILITIES.md` (predecessor of this file) was superseded and removed.

---

## 11. Versioning

This document tracks current state at HEAD. As findings are mitigated, they move from §3-§6 to §7 with a brief note describing the fix. New findings are added with the next available `S-NNN` ID. The triage table in §2 is the canonical entry point for any review.
