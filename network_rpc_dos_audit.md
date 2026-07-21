# Network / RPC / DoS Proof-Cluster Audit (subagent report)

Auditor: skeptical protocol-security proof auditor (subagent). Scope: 23 proof docs under `docs/proofs/`.
Method: every doc read in full; per-doc verdict on internal validity + consistency with `Preliminaries.md` (F0);
source cross-refs spot-checked against the live tree (post-asio→native-transport migration; `rpc.cpp`, `node.cpp`,
`node.hpp` git-dirty). Verdicts: SOUND | SOUND-WITH-GAPS | FLAWED | OPEN | EMPIRICAL-ONLY.

## Cluster: 网络 / RPC / 拒绝服务 (gossip + RPC transport, rate limiting, resource bounds, keyfile/log surfaces)

### Per-document verdicts

- **S001RpcAuthSoundness.md** — RPC HMAC auth composition — **SOUND-WITH-GAPS**. T-1 states the forgery bound as
  `2^-256 + q²/2^256`, but the base proof it composes (RpcAuthHmacSoundness T-1) carries an extra `+2^-128`
  compression-function PRF term — a bound-stating inconsistency (MINOR). Replay is honestly scoped to the
  apply-layer nonce gate; verified that gate is strict equality at `src/chain/chain.cpp:952` (doc cited :739 —
  drifted). verify_auth ordering and constant-time compare verified exact at `src/rpc/rpc.cpp:112-129`.
- **RpcAuthHmacSoundness.md** — HMAC-SHA-256 PRF reduction — **SOUND**. The reduction and T-2 replay-openness are
  internally consistent. Caveat: the quoted OpenSSL `HMAC()` call is stale — the shipped code uses the in-tree C99
  `determ_hmac_sha256` (`src/rpc/rpc.cpp:60-73`, "§3.15 swap" comment, OpenSSL kept only as test oracle); the
  fail-closed empty-string path the proof leans on is present. Constant-time caveat (compiler-dependent) is honest.
- **RpcAuthReplayWindowSoundness.md** — ts+nonce replay window — **OPEN**. Marked TIER: NEAR-TERM, spec-only, NOT
  shipped; a full read of `src/rpc/rpc.cpp` confirms no timestamp/nonce/SEEN-cache anywhere in the envelope path.
  The proof itself is plausible, but the mechanism it proves does not exist in the tree.
- **RpcInputValidationDefense.md** — RPC input-validation defense-in-depth — **SOUND-WITH-GAPS**. Layer ordering
  (rate-limit → parse → auth → dispatch) verified at `rpc.cpp:164/168/171/202`. F-1 confirmed LIVE on the native
  transport: `ReactorConnection::read_line` (`src/net/reactor_transport.cpp:229-256`) and
  `IocpConnection::read_line` (`src/net/iocp_transport.cpp:318-331`) still append to `carry_` with no byte cap —
  a newline-less stream grows memory unboundedly while consuming zero rate tokens (limiter is per-line).
- **S002-Mempool-Sig-Verify.md** — sig-verify before mempool admission — **SOUND**. Verified: gossip path
  `node.cpp:2819` (`verify_tx_signature_locked`, silent drop), RPC path `node.cpp:4433` (hard error). Closure
  record; the forged-sig regression test is an admitted follow-on.
- **S008BoundedMempool.md** — bounded mempool — **SOUND-WITH-GAPS**. Full mechanism verified:
  `mempool_admit_check` `node.cpp:2734-2786`, `mempool_make_room_for` `:2792-2808` (lowest-fee eviction,
  tie favors incumbent), RBF `:2829-2835`, constants `MEMPOOL_MAX_TXS=10000`/`MEMPOOL_MAX_PER_SENDER=100` at
  `node.hpp:624-625` (docs cited :459-460 — drifted). Cap-overflow/eviction/RBF boundary paths have NO direct
  tests (doc admits); T-4's 15GB-worst-case vs 7.5MB-realistic framing is honest.
- **S013PerSignerCap.md** — per-signer BlockSig buffer cap — **SOUND-WITH-GAPS**. Mechanism verified:
  `MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER = 2` (`node.cpp:3013`), cap loop `:3015-3022`, committee-membership
  pre-filter before buffering `:3031-3033`, three `buffered_block_sigs_.clear()` sites `:1071/:1234/:2331`
  (doc-cited lines all drifted). Cites "Preliminaries §4 H1" for one-signature-per-round — wrong label; F0 H2(a)
  is the correct citation (MINOR). T-5's `min(2K, arrival-bound)·cap` formula is formally sloppy (real bound 2K·cap);
  no direct cap test (F-3).
- **S014ConcurrencyAnalysis.md** — rate-limiter mutex correctness — **SOUND-WITH-GAPS**. Mutex discipline,
  refill arithmetic, and sweep cadence verified in `include/determ/net/rate_limiter.hpp:93-150`. Citations
  drifted: `consume` cited at :86-117 (actual :93-124); worker-pool spawn cited at both `node.cpp:586-588` and
  :646-648 (actual :800-802 — the doc is internally inconsistent AND both are stale). Timing figures are
  empirical but only operationally load-bearing.
- **S014RateLimiterDDOSResistance.md** — DDoS algebra — **SOUND**. The token-bucket bounds are consistent with
  the verified `consume` implementation (first-touch-full, `min(burst, tokens+elapsed·rate)`, no partial
  deduction on weighted consume).
- **S014RateLimiterSoundness.md** — rate-limiter soundness — **SOUND**. Cites `consume` at
  `rate_limiter.hpp:42-58`; actual :93-124 (file grew via the F-1 eviction closure — drifted). F-1 closure
  verified: `configure_eviction` :56-59, amortized sweep :102-110, `sweep_idle_locked` :135-150, defaults 600s/60s.
- **RateLimiterKeyDerivationSoundness.md** — IP-key derivation — **SOUND-WITH-GAPS**. IPv4 arm verified:
  `rfind(':')` strip at `gossip.cpp:161-162` and `rpc.cpp:149-150`; port appended last by
  `format_endpoint` (`reactor_transport.cpp:30-34`), so the strip is correct. The IPv6 arm (marked
  "re-verification pending" in-doc) is in fact VACUOUS: both native transports are AF_INET-only
  (`iocp_transport.cpp:341` `WSASocketW(AF_INET,…)`; reactor `sockaddr_in`/`inet_ntop` only) — no IPv6
  connection can reach the daemon, so the pending arm is moot rather than broken (also means zero IPv6 support,
  an operational NOTE).
- **S019DAppEndpointSpoof.md** — dapp_subscribe endpoint-spoof resistance — **SOUND**. The subscribe takeover
  path and 99-token weighted consume are verified (`rpc.cpp:175-200`). Crypto argument is fine, but the doc
  repeatedly cites "FA1 (Ed25519 EUF-CMA)" — violates F0 §2.0: FA1 is the Safety theorem index; the assumption
  label is A1 (MINOR label violation).
- **S022WireFormatCaps.md** — wire-format size caps — **SOUND-WITH-GAPS**. Verified EXACT:
  `kMaxFrameBytes = 16MB` at `messages.hpp:101`, `max_message_bytes` tiered caps at `:124-152`, framing guard
  `peer.cpp:54` (close on `len==0 || len>kMaxFrameBytes`), per-type cap + close at `peer.cpp:80-87`. The doc
  explicitly scopes the post-deserialize metering question to S-018 — which is precisely where the confirmed
  unmetered-parse gap lives (see Composition gaps).
- **S022WireFormatCapsCompleteness.md** — cap-completeness over MsgType — **SOUND**. Verified:
  `enum class MsgType : uint8_t` (`messages.hpp:13`); unknown type bytes deserialize via
  `json_require<uint8_t>` (`messages.cpp:44`), take the default 1 MB cap, consume a rate token, and hit the
  `default: break` drop at `gossip.cpp:320-321`; `make_hello` at `:181-201` exact.
- **S023NodeKeyfileEncryption.md** — keyfile encryption + rotation — **SOUND-WITH-GAPS**. Rotate verified in
  `wallet/main.cpp:4473-4529`: stage→rename atomic, 0600 tighten, in-memory `secure_zero_all()`. F-3 confirmed:
  in-place rotate renames over the old file WITHOUT zeroing its on-disk bytes — forensic recovery surface stands.
  T-2 cites "(A8 / Preliminaries §2.3)" — A8 is undefined in F0; correct label is A4 (MINOR).
- **S026TcpKeepalive.md** — SO_KEEPALIVE dead-peer reap — **SOUND-WITH-GAPS**. Critical migration check PASSES:
  the mechanism survived asio deletion — `peer.cpp:27` calls `conn_->set_keep_alive(true)`, implemented as real
  `setsockopt(SO_KEEPALIVE)` in both transports (`reactor_transport.cpp:193-195`, `iocp_transport.cpp:250-252`).
  All quoted asio code/line numbers are stale. T-2 arithmetic slip: it calls `~1360` peers "well under the
  typical `ulimit -n = 1024`" — false (1360 > 1024; only true for tuned limits) (MINOR). F-3 honestly admits the
  application-layer slow-loris class is unclosed (no HELLO timeout, no activity timeout, no per-IP connection
  cap). No automated test (justified as kernel behavior; source-audit + operator monitoring instead).
- **S027InfoLeakage.md** — no-secret-in-log audit + log_quiet — **SOUND-WITH-GAPS**. Spot checks pass:
  banner emits only `auth_secret_.size()` (`rpc.cpp:96-97`), `rpc_hmac_auth` boolean readback at `node.cpp:3347`,
  `log_quiet` at `node.hpp:162`, env-var read at `rpc.cpp:318` (all line-cited values drifted). Confirmed the
  registered residual: `Config::to_json` emits `rpc_auth_secret` in plaintext at `node.cpp:36`. The audit is a
  point-in-time enumeration; the proposed CI gate is unimplemented, so T-1 is a snapshot claim, not a standing one.
- **S031ConcurrencyComposition.md** — six-layer concurrency composition — **SOUND-WITH-GAPS**. Architecture
  verified: `state_mutex_` shared_mutex at `node.hpp:865` (cited :617), worker spawn `:800-802`,
  `save_worker_loop` `:890-941` with shared_lock at `:914` (cited :661-695/:685), `enqueue_save` `:943` called
  from `:2504` (cited :697-703/:1845), A9 snapshot/restore at `chain.cpp:815-828` + `:739-785` (lazy optionals).
  Count drift: doc says 11 read-only shared_lock sites; grep finds ~17. L-5's no-starvation argument is
  empirical (250ns critical sections + S-014 aggregate bound). G-4/G-5 in-lock broadcasts honestly disclosed.
- **JsonValidationSoundness.md** — S-018 json_require contract — **SOUND**. Verified: envelope deserialize
  (`messages.cpp:33-53`), gossip sub-envelope guards (`gossip.cpp:221-225, 247-250, 261-265`), keyfile
  `json_require_hex` (`keys.cpp:62-63`), RPC dispatch's `params.value(key, default)` pattern
  (`rpc.cpp:215-300`). The `producer.cpp:212` residual is honestly registered as non-security-relevant.
  T-2's no-internal-leakage holds at the RPC surface — `e.what()` goes to the client (`rpc.cpp:208`) but
  carries field names only.
- **NefPoolDrain.md** — NEF apply mechanics — **SOUND**. Code verified: `first_time_register` find-before-insert
  at `chain.cpp:1216-1217`, four conjunctive guards `:1244-1247`, halving `:1248`, `nef>0` tail guard `:1249`,
  two-leg transfer `:1250-1251` (doc-cited :795-833 drifted; logic identical). T-N1..T-N7 internally consistent.
- **NefSybilDrainBound.md** — NEF Sybil-drain economics — **SOUND**. NS-1..NS-5 arithmetic checks out
  (nested-ceiling identity, telescoping extraction, logarithmic stopping bound). Exemplary F0 hygiene: it
  explicitly distinguishes assumption A1 from the "A1 accounting identity" per the F0 §2.0 disclaimer — the only
  doc in the cluster that navigates that collision correctly.
- **MultiPeerCrossCheckSoundness.md** — light-client multi-peer cross-check — **SOUND**. Correct A1/A2 usage;
  honest all-peers-collude limitation; per-peer verify-then-compare composition is sound; the `(H·K+1)·2^-128`
  bound is plausible.
- **TimestampReconciliationSoundness.md** — timestamp median reconciliation — **SOUND-WITH-GAPS**. TIER:
  NEAR-TERM (explicitly not 1.0-authoritative). T-2 honest-flanked order-statistic proof is correct (`f < K/3`
  correctly scoped to robustness, not safety). T-6 liveness is hand-waved: the proof derives `|m - now| <= 60s`
  against the deployed ±30s window, then asserts "comfortably inside for any reasonable skew budget" — worst-case
  honest clock spread CAN reject an honest block; the "no honest block newly rejected" claim is unproven (MINOR,
  softened by the NEAR-TERM tier).

### Assumption consistency findings

1. **"H1" has three colliding meanings across the series** (MINOR→MAJOR label hygiene): SHA-256 collision
   resistance ("A2/H1" in S001, RpcAuthHmacSoundness, RpcInputValidationDefense), "at least one honest validator
   exists" (RpcInputValidationDefense §2.3), and F0 §4's canonical H1 (fresh Phase-1 secret per round). Any
   cross-document citation of "H1" is ambiguous.
2. **S013PerSignerCap** cites "Preliminaries §4 H1" for the one-BlockSigMsg-per-round honest behavior; the correct
   citation is F0 §4 H2(a). MINOR.
3. **S019DAppEndpointSpoof** uses "FA1 (Ed25519 EUF-CMA)" as an assumption label, violating F0 §2.0's explicit
   warning that FA1–FA12 are theorem indices, not assumptions (correct label: A1). MINOR; argument unaffected.
4. **S023NodeKeyfileEncryption** T-2 cites "(A8 / Preliminaries §2.3)" for CSPRNG uniformity; A8 is undefined in
   F0 — correct label is A4. MINOR.
5. **Bound mismatch between composition and base**: S001 T-1 (`2^-256 + q²/2^256`) vs RpcAuthHmacSoundness T-1
   (adds `+2^-128`). The composition understates its own base theorem's bound. MINOR.
6. **Positive**: NefSybilDrainBound explicitly and correctly navigates the F0 §2.0 A1-assumption vs
   A1-accounting-identity collision; TimestampReconciliationSoundness correctly confines `f < K/3` to the
   robustness (non-safety) theorem. NOTE.
7. **RateLimiterKeyDerivation's IPv6 conditional arm** resolves vacuously: the native transports are IPv4-only,
   so the unverified IPv6 key-derivation path is unreachable (and IPv6 deployments are impossible outright).
   NOTE — the doc should be updated to say so rather than "re-verification pending".

### Code cross-reference spot checks

Citation → status (all against the live, post-migration tree):

- `RpcServer::verify_auth` rpc.cpp:112-129 → **VERIFIED** (exact lines; constant-time compare :123-128).
- `canonical_for_hmac` rpc.cpp:52-58 → **VERIFIED** (exact; `method|params.dump`).
- HMAC via OpenSSL (RpcAuthHmacSoundness §3) → **STALE-SUBSTANCE**: now C99 `determ_hmac_sha256` (rpc.cpp:60-73);
  fail-closed semantics preserved; OpenSSL retained only as test oracle.
- RPC startup banner :92-109, size-only secret → **VERIFIED** (exact).
- Ordering rate-limit→parse→auth→dispatch → **VERIFIED** (rpc.cpp:164/168/171/202; cited consume :172 drifted).
- `DETERM_RPC_AUTH_SECRET` env read → **VERIFIED** at rpc.cpp:318 (S027/S001 cited :294 — drifted).
- `Config::to_json` plaintext `rpc_auth_secret` → **VERIFIED** at node.cpp:36 (cited :30 — drifted; residual live).
- `read_line` byte cap (RpcInputValidation F-1) → **CONFIRMED ABSENT** in both native transports
  (reactor :229-256, iocp :318-331); finding status unchanged by the migration.
- RateLimiter `consume` → **DRIFTED**: cited :42-58 (Soundness) and :86-117 (Concurrency); actual :93-124.
- RateLimiter eviction closure → **VERIFIED** (`sweep_idle_locked` :135-150, sweep cadence :102-110).
- Gossip `rate_limiter_.consume(ip)` → **VERIFIED** at gossip.cpp:163 (cited :154 — drifted); HELLO exemption :157;
  `rfind(':')` strip :161-162.
- `kMaxFrameBytes` messages.hpp:101 / `max_message_bytes` :124-152 / `make_hello` :181-201 /
  `enum class MsgType : uint8_t` :13 → **VERIFIED** (all exact).
- `Peer::read_header` framing guard → **VERIFIED** at peer.cpp:54 (cited :50-70 — drifted).
- `Peer::read_body` per-type cap + close → **VERIFIED** at :80-87; catch-and-log-continue at :89-93
  (cited :72-105/:99-102 — drifted; this is the unmetered-parse site, see gaps).
- SO_KEEPALIVE in Peer ctor → **VERIFIED** at peer.cpp:27 via `conn_->set_keep_alive(true)`
  (S026's quoted asio `set_option` at :8-38 — stale form, mechanism intact; both transports implement the syscall).
- `GossipNet::handle_peer_closed` sole-removal → **VERIFIED** at gossip.cpp:329-336 (cited :320-327 — drifted).
- Worker-pool spawn → **VERIFIED** at node.cpp:800-802 (`loop_.run()` × hardware_concurrency); S014Concurrency's
  :586-588 and S031's/:env-note's :646-648 both **DRIFTED** (and mutually inconsistent).
- `save_worker_loop`/`enqueue_save` → **VERIFIED** at :890-941/:943, call site :2504 (cited :661-703/:1845 — drifted).
- Mempool fns → **VERIFIED** (`mempool_count_from` :2716, `mempool_admit_check` :2734, `mempool_make_room_for`
  :2792, on_tx :2810-2845); cited :1943-2054 — heavily **DRIFTED**.
- MEMPOOL constants → **VERIFIED** node.hpp:624-625 (cited :459-460 — drifted).
- BlockSig per-signer cap → **VERIFIED** (:3013-3022; committee pre-filter :3031-3033; clears :1071/:1234/:2331);
  cited :2177-2213/:820/:899-901/:1692 — **DRIFTED**.
- `rpc_submit_tx` gates + unlock-before-broadcast → **VERIFIED** at :4420-4471 (unlock :4469); cited :3137-3204 —
  **DRIFTED**.
- Apply-layer nonce strict-equality gate → **VERIFIED** at chain.cpp:952 (cited :739 — **DRIFTED**; gate is `!=`
  → skip, so replays are no-ops at apply).
- NEF branch → **VERIFIED** at chain.cpp:1216-1254 (cited :790-836 — drifted; logic byte-equivalent to the proof's
  quotation).
- `state_mutex_` shared_mutex → **VERIFIED** node.hpp:865 (S031 cited :617 — drifted); reader-site count drift
  (doc says 11, grep shows ~17).
- `log_quiet` → **VERIFIED** node.hpp:162 (cited :158 — drifted); `rpc_hmac_auth` bool at node.cpp:3347
  (cited :2478/:2481 — drifted).
- S023 keyfile-rotate → **VERIFIED** wallet/main.cpp:4473-4529 (stage→rename, 0600, in-memory zeroing; no on-disk
  wipe of the old file — F-3 confirmed).
- Native endpoint formatting IPv4-only → **VERIFIED** (`format_endpoint` reactor :30-34 `inet_ntop(AF_INET)`;
  `WSASocketW(AF_INET)` iocp :341) — settles the RateLimiterKeyDerivation IPv6 question as vacuous.

Net assessment: **zero citations were found substantively wrong** (every mechanism the proofs cite exists and does
what the proof claims), but **~70% of line-number citations are drifted**, two code quotations are stale in
substance (OpenSSL HMAC; asio keepalive), and the git-dirty files guarantee further drift. Treat every
"code enforces X at line N" sentence in this cluster as prose-backed until re-anchored.

### Composition gaps

- **MAJOR — Unmetered parse-failure path on gossip (S-014 bypass).** Verified: `Peer::read_body`
  (`peer.cpp:71-93`) calls `Message::deserialize` BEFORE any rate-limit accounting; a deserialize-throwing frame
  (any framing-valid ≤16 MB body that isn't parseable JSON/a valid envelope) hits the catch at :89-92, logs, and
  loops `read_header()` at :93 — no token consumed (the consume lives in `GossipNet::handle_message`,
  gossip.cpp:163, reached only via `on_msg_` after successful deserialize + cap check) and the connection stays
  open. A peer can therefore burn unbounded node CPU (full JSON parse of up to 16 MB per frame) and a 16 MB
  `body_buf_` per frame at line rate forever, completely outside the S-014 token bucket that the cluster's DDoS
  story relies on. S022WireFormatCaps scopes this out ("governed by S-018"); S-018 meters nothing. Bounded only by
  TCP bandwidth. Fix direction: consume a token (or close) on deserialize failure in `read_body`.
- **MAJOR — Uncapped RPC request-body accumulation (slow-loris memory growth).** Verified live post-migration:
  both native `read_line` implementations append to `carry_` with no ceiling until `\n` arrives; the RPC rate
  limiter meters completed lines, not bytes. A client (even an unauthenticated one — consume happens per line,
  before auth) can stream newline-less data and grow per-connection memory without bound, one FD each.
  RpcInputValidationDefense F-1 called the equivalent asio `streambuf` issue "operational, not structural" and
  left the mitigation unimplemented; the migration preserved the defect.
- **MAJOR — Silent-connection (slow-loris) class unclosed on both ports.** S026 F-3 admits it for gossip (no
  HELLO timeout, no activity timeout, no per-IP connection-count cap; SO_KEEPALIVE cannot see an alive-but-silent
  host); the same class exists on the RPC port (handle_session blocks in `read_line` per connection with no idle
  bound). Each silent connection costs an FD + session state up to `ulimit -n`; S-014 never fires because no
  message ever arrives. Documented in parts (S026 F-3 Medium) but the cross-surface class is nowhere bounded.
- **MAJOR — RPC-layer replay freshness is spec-only.** RpcAuthReplayWindowSoundness is OPEN (NEAR-TERM tier, no
  code). Until shipped, HMAC-authenticated requests have no freshness: a captured valid `send`/`stake`/`unstake`/
  `register` request is re-playable by anyone on the wire (localhost binding + operator network posture are the
  only mitigations). The apply-layer nonce gate (chain.cpp:952, verified) makes tx-carrying replays no-ops at
  apply, but read methods and non-tx mutations have no replay defense at all. Honestly disclosed in S001 but a
  real residual.
- **MINOR — S026 T-2 arithmetic slip.** "~1360 peers — well under the typical `ulimit -n = 1024`": 1360 > 1024.
  The conclusion survives only under tuned limits; the sentence as written is wrong.
- **MINOR — Label-hygiene cluster** (H1 triple-collision; FA1-as-assumption in S019; A8 in S023; H1-vs-H2(a) in
  S013; S001-vs-base bound mismatch). Each individually small; collectively they degrade the auditability the
  proof series exists to provide.
- **MINOR — TimestampReconciliation T-6 liveness hand-wave** (derived 60s vs deployed 30s window, resolved by
  assertion). NEAR-TERM tier mitigates impact.
- **NOTE — Deliberate double budget.** Two RateLimiter instances (RPC + gossip) give a per-host 2× aggregate
  token budget; documented and intentional.
- **NOTE — Untested boundary paths.** S008 cap-overflow/eviction/RBF and S013 cap paths have no direct tests
  (R-1..R-4 deferred; F-3). Inductions are simple, but the exact boundary behavior is EMPIRICAL-ONLY.
- **NOTE — Verified residuals (already registered in-doc).** S023 F-3 old-keyfile disk bytes unzeroed
  (wallet/main.cpp:4473-4505 confirms); Config plaintext `rpc_auth_secret` (node.cpp:36 confirms).
- **NOTE — Systemic citation drift.** Env-notes cover the asio deletion in some docs, but ~70% of line numbers
  across the cluster are stale. No correctness impact found; large auditability impact.

### Cluster bottom line

The cluster's algebra is genuinely sound: every mechanism the proofs cite (token bucket, caps, mempool admission,
per-signer cap, keepalive, HMAC verify, A9 snapshot/restore) exists in the live tree and does what the proofs
claim, and no substantively wrong citation was found. The real DoS residuals are compositional, not algebraic:
the gossip deserialize-failure path consumes no rate token (verified peer.cpp:89-93), the RPC line buffer is
uncapped in both native transports (verified), the silent-connection class is unbounded on both ports, and RPC
replay protection remains an unshipped spec. Assumption labels need a hygiene pass (H1/FA1/A8/H2 collisions), and
pervasive post-migration line drift means the documents currently prove properties of code snapshots, not of the
checked-out tree — a re-anchoring pass plus CI-gated greps (already proposed in S027) would restore the chain of
custody.
