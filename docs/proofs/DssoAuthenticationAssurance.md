# DssoAuthenticationAssurance.md — DSSO user authentication at level *substantial* of CIR (EU) 2015/1502

**Status:** AUTHORITATIVE for the shipped `dapps/dsso/authn.*` module. Untiered: it tracks shipped code, not a roadmap. Companion to `v2.25-DSSO-DAPP-SPEC.md` (the protocol) and `DssoThresholdOprfSoundness.md` (the threshold-OPRF login it builds on).

**The claim, in one sentence.** DSSO's user authentication is **equivalent to level *substantial*** of Commission Implementing Regulation (EU) 2015/1502 Annex §2.2.1 (two authentication factors from different categories) and §2.3.1 (dynamic authentication), and the enrolment, replacement, recovery and revocation machinery around it preserves that level rather than quietly dropping below it.

"Equivalent to" is the whole claim. DSSO is **not** notified, **not** certified, **not** a wallet and **not** a qualified trust service. See §9.

---

## 1. The defect this closes

The shipped login (`v2.25-DSSO-DAPP-SPEC.md` §3–§5) is:

1. the user blinds the password and broadcasts it;
2. any `t` of `n` servers return a blinded OPRF evaluation with a DLEQ proof;
3. the user Lagrange-combines them, unblinds, finalizes `y`;
4. `y` unseals `envelope = AEAD_{HKDF(y)}(cred_sk)` — the **credential secret key**;
5. `cred_sk` runs the OPAQUE-3DH AKE and co-generates `sso_key`.

Every value the user needs at step 5 is a **function of the password**. The credential key is a stored secret *recovered from knowledge*, so it is not an independently held object and cannot be a possession factor: whoever knows the password and can reach `t` servers reconstructs it. §2.2.1 asks for two factors **from different categories**; a knowledge factor recovered once and a knowledge factor recovered twice are one category.

**Multiple servers are not multiple factors.** The threshold is a confidentiality and availability property of *one* factor's evaluation (spec claims C1/C3/C7), not a second thing the user must hold. A `t`-of-`n` OPRF over a password is still a password.

So, before this increment: DSSO authentication was **single-factor** and equivalent to at most level *low*.

Second defect, from the same spec: §6's closing note — *"with t-of-n the cap must be aggregate (cooperative counters, or fee-metered DAPP_CALL) since an attacker can rotate subsets — deployment choice."* Leaving the aggregate cap to the deployment leaves the online-guessing bound **undefined**, and a per-server counter is walked around by rotating which `t` servers each guess uses. §2.3.2's requirement that the means "limits the number of failed authentication attempts" cannot be met by a limiter that does not exist.

## 2. The two factors, and why they are in different categories

| Factor | Category (2015/1502 Annex §2.2.1) | What the user holds | What the servers hold |
|---|---|---|---|
| The password, evaluated by the shipped `t`-of-`n` OPRF and the OPAQUE-3DH AKE | **knowledge** | the password | their Shamir share `k_i`, the account's `knowledge_verifier` (the co-generated server-side secret) |
| A P-256 key generated **on the device** from device-local entropy | **possession** | `sk_dev`, which never leaves the device | `pk_dev` (a public point) and enrolment metadata — `dsso_authn_device_rec` |

The categories are different because the two secrets have **independent origins**:

- `sk_dev = HashToScalar(seed_device)` where `seed_device` is drawn on the device. `dsso_authn_device_keygen` takes the seed as its only input; nothing in the module derives a device key from a password, an OPRF output, an envelope or any server-held value.
- Compromising every server yields `pk_dev` and `knowledge_verifier`; neither is a function of `sk_dev`, and `pk_dev = sk_dev·G` is a one-way image under ECDLP on P-256 — the same assumption the OPRF, the AKE and the DLEQ proofs already make.
- Compromising the password yields the knowledge factor and nothing else: the device seed is not in its preimage.

The gate asserts both directions: that two device seeds give two device keys (so the seed is load-bearing), and that a device key derived from *everything a full-quorum adversary can see* (`pk_dev ‖ knowledge_verifier ‖ server-set digest`) is **not** the enrolled key and **cannot** complete a login.

## 3. The dynamic authentication (§2.3.1)

At every login the device must answer a challenge it has never answered before. The verifier **computes the challenge itself** — nothing the client sends decides what was signed:

```
challenge = SHA-256( len‖"DSSO-authn-v1-challenge" ‖ version ‖ purpose
                   ‖ account ‖ device ‖ session_nonce ‖ server_set_digest
                   ‖ be64(timestamp) ‖ bind ‖ aux )
```

`bind` is the **knowledge factor's own response for this same login** (`HMAC(knowledge_verifier, …)`), so the two factors are one authentication and cannot be spliced from two different sessions. `server_set_digest` covers `n`, `t` and every server identity in order, so a proof produced for one server set does not verify in another. The digest is not a per-call argument: the operator installs it once with `dsso_authn_bind_server_set`, every in-session operation reads it from there, and `dsso_authn_login` refuses a cluster whose own digest is not the bound one (`DSSO_E_BINDING`) — a binding a caller re-supplies on every call is a convention, and this has to be a rule. `purpose` separates login from enrolment, revocation and recovery, so a captured login proof authorises nothing else. The nonce is single-use per account and the timestamp window is two-sided.

**The possession proof itself.** The brief for this increment named ECDSA. **ECDSA-P256 is not shipped in this repository** — `CRYPTO-C99-SPEC.md` lists it under "remaining: ECDSA-P256 (only if a FIPS-profile signing consumer appears)" — and the mission rule is *no new primitive*. The module therefore uses the shipped RFC 9497 **VOPRF discrete-log-equality proof as a signature of knowledge**:

```
blinded = compress(hash_to_curve(challenge, "DSSO-authn-v1-possession-H2C"))
eval    = sk_dev · blinded                      (determ_p256_oprf_evaluate)
proof   = DLEQ(pk_dev; blinded, eval)           (determ_p256_voprf_prove, mode 0x01)
verify  = determ_p256_voprf_verify(pk_dev, blinded, eval, proof, 0x01)
```

That is Chaum–Pedersen under Fiat–Shamir: the RFC 9497 §2.2.1 transcript hashes `pk`, the composite of `(blinded, eval)` and the two commitments, so the proof is bound to the challenge point and therefore to the challenge bytes. It is **publicly verifiable from `pk_dev` alone** — which is exactly why storing `pk_dev` does not let any server, or all of them, impersonate the device — and unforgeable without `sk_dev` under ECDLP. Every call is to a function already KAT-gated byte-exactly against the RFC 9497 A.3 vectors (`determ test-p256-oprf-c99`). **Zero new primitive, zero new hardness assumption.**

The proof nonce is derived as `HashToScalar(sk_dev ‖ challenge)` — RFC 6979 in spirit. Two consequences: the proof is a deterministic function of (secret, challenge), so the gate is byte-reproducible without a CSPRNG; and a nonce can never be reused across two challenges, which in a Schnorr-family proof would leak the secret.

**Why not a challenge-response over ECDH.** A static-ephemeral ECDH plus MAC would be verifiable only by the party that chose the ephemeral — i.e. a server could *forge* the device's response from `pk_dev` and its own ephemeral secret. That fails the "nothing the servers store lets them impersonate the device" requirement outright. A publicly verifiable signature is the only shape that survives the mutual-distrust model this DApp is built for.

## 4. Enrolment

| Event | Authorised by | Refused when |
|---|---|---|
| First device | the **identity-proofing event** — a verified PID presentation (§2.1.2 is inherited from the wallet's notified scheme) | no attestation (`DSSO_E_ASSURANCE`); no verifier installed (`DSSO_E_UNAVAILABLE`); a presentation id already used (`DSSO_E_REPLAY`) |
| Any later device | an authenticated **two-factor session** AND a fresh possession proof from an already-active device, bound to the new device's public key | a session that is not two-factor / below SUBSTANTIAL (`DSSO_E_ASSURANCE`); no possession proof (`DSSO_E_ASSURANCE`); a proof made for another purpose (`DSSO_E_CRYPTO`); a device id already enrolled (`DSSO_E_REPLAY`) |

The second row is the load-bearing one. **A password alone must never enrol a device**: if it could, the knowledge factor would mint the possession factor and the account would be single-factor again with a two-factor label on it. A stolen session token alone is equally insufficient, because the current device must sign the new device's public key.

**The PID seam is narrow and is a dependency, not a claim.** `dsso_pid_verify_fn` takes a `dsso_pid_attestation` — a pairwise `subject_binding`, a unique `presentation_id`, and the verifier's `verified_at` — and returns a status. The actual verifier (OpenID4VP presentation, OIA_12 trust-list validation of the PID signature, OIA_02 holder binding, Token Status List check) is **a sibling track's work and is not implemented here**. This module enforces two things the verdict cannot carry on its own: the subject binding must equal the one recorded at first enrolment (so a valid PID belonging to someone else recovers nothing), and each presentation id is single-use (so a captured presentation is not replayable). With no verifier installed every PID-authorised transition is `DSSO_E_UNAVAILABLE` — **fail-closed, never "allow on outage"**.

## 5. Replacement, recovery and revocation — the state machine

**The binding rule.** *Evidence of one factor may only REDUCE an account's assurance. Restoring it needs a second, independent evidence.* A recovery path that handed back full assurance on one factor would make the account single-factor silently, which is the defect this whole document exists to close.

States and what they report to the assertion layer:

| State | Meaning | `dsso_authn_account_loa` |
|---|---|---|
| `DSSO_ACC_ACTIVE` | knowledge + at least one active device | `DSSO_LOA_SUBSTANTIAL` |
| `DSSO_ACC_KNOWLEDGE_ONLY` | the device is gone; only the password remains | `DSSO_LOA_LOW` |
| `DSSO_ACC_POSSESSION_ONLY` | the password is gone; only the device remains | `DSSO_LOA_LOW` |
| `DSSO_ACC_LOCKED` | neither is usable | `DSSO_LOA_NONE` |

Transitions (`dsso_authn_recover`):

| Event | From | Evidence required | To | Assurance |
|---|---|---|---|---|
| `DEVICE_LOST` | ACTIVE | knowledge tag | KNOWLEDGE_ONLY | **downgraded to LOW, visibly** |
| `PASSWORD_LOST` | ACTIVE | possession proof | POSSESSION_ONLY | **downgraded to LOW, visibly** |
| `BOTH_LOST` | any live state | either surviving factor | LOCKED | NONE |
| `RESTORE_DEVICE` | ACTIVE or KNOWLEDGE_ONLY | knowledge tag **+** fresh subject-matched PID | ACTIVE | SUBSTANTIAL |
| `RESTORE_PASSWORD` | ACTIVE or POSSESSION_ONLY | possession proof **+** fresh subject-matched PID | ACTIVE | SUBSTANTIAL |
| `RESTORE_BOTH` | any state incl. LOCKED | fresh subject-matched PID | ACTIVE | SUBSTANTIAL |

The three realistic losses, answered:

- **Device lost, password known.** With a fresh PID presentation: `RESTORE_DEVICE` re-establishes two factors, assurance stays *substantial*. Without one: only `DEVICE_LOST` is available, the account **drops to LOW and stays there**. From LOW it cannot enrol a device (that would be password-only enrolment) and cannot obtain a substantial assertion. The one-factor route exists so a user whose device is stolen can revoke it immediately without waiting for a wallet presentation; it costs assurance, which is the correct price.
- **Password forgotten, device held.** Symmetric: possession + PID restores, possession alone degrades to `POSSESSION_ONLY` at LOW, and a password reset from a LOW session is refused.
- **Both lost.** Only `RESTORE_BOTH` on a fresh PID presentation, which deactivates every device, installs a new device and a new knowledge verifier, and bumps the auth epoch. This is *enrolment re-run under a fresh proofing event*, not a bypass: the evidence is exactly the evidence that authorised the account in the first place. It does mean that **whoever can present the subject's PID can take the account** — that is the eIDAS trust root, and it is stated here rather than hidden.

**Revocation and concurrent sessions.** Every account record carries `auth_epoch`; every session records the epoch at issue; `dsso_authn_session_verify` refuses when they differ. So a single counter bump invalidates every live session at once, with no session table to walk and nothing to miss. What bumps it:

| Change | Sessions | Why |
|---|---|---|
| device revoked (`dsso_authn_revoke_device`) | **all invalidated** | a session issued while the revoked device was trusted may have been obtained with it |
| any recovery transition | **all invalidated** | the factor set changed |
| password replaced (`RESTORE_PASSWORD`) | **all invalidated** | the old knowledge factor is gone |
| account locked | **all invalidated** | plus `LOCKED` refuses verification outright |
| **device added** (`dsso_authn_enrol_device`) | **kept** | an addition removes no capability from any existing session, and killing them would be hostile without being safer |

Revoking a device requires a live SUBSTANTIAL session **and** a fresh possession proof from an active device bound to the target — so a stolen session token cannot revoke the legitimate device. A device the user no longer holds is removed through `DEVICE_LOST` instead, which costs the account its second factor until it is re-proofed.

## 6. The aggregate attempt limiter, and its bound

**Mechanism.** One grow-only counter per account: a vector with one slot per server (a state-based G-Counter CRDT). A server increments **only its own slot**; two views merge by per-slot maximum, with a newer `(window, reset_seq)` winning wholesale. Merge is idempotent, commutative and associative, so the servers converge by gossip alone — **no consensus rule, no new primitive, no ordering requirement**, which is the same "unordered, not-all-nodes" property the t-of-n OPRF already has. The cap is compared against the **sum** of the slots.

**Why this is the right choice over fee-metering.** Fee-metered `DAPP_CALL` would bind guesses to an on-chain spend, but it puts a consensus-path dependency and a real cost in front of every honest login, and it prices an attack rather than bounding it. A cooperative counter costs nothing per login, needs no chain interaction, and yields a hard bound rather than a price.

**Theorem (the bound).** Let `cap` be the per-window cap on the slot sum, `t` the login threshold, and `b < t` the number of servers in a serving subset that are byzantine (serve without counting). Every accepted attempt requires `t` distinct servers to serve, of which at least `t − b` count, so after `A` attempts the sum is at least `A·(t − b)`. A server refuses once the sum reaches `cap`. Therefore

```
A  ≤  floor( cap / (t − b) )
```

for **every** sequence of subsets the attacker chooses, including one that rotates through all `C(n, t)` of them. With `b = 0` this is `floor(cap/t)`. The gate pins the honest case exactly: `n = 5, t = 3, cap = 12` → **exactly 4 attempts, then `DSSO_E_RATELIMIT`, whichever of the ten 3-subsets is used**.

**What the bound does not cover, stated plainly.** At `b ≥ t` the adversary controls an evaluation quorum and can evaluate the OPRF offline; no online limiter of any design bounds that, and it is exactly the case the spec's C1/C3 threshold assumption exists to exclude. Separately, the counter bounds *attempts served*, not *passwords tried offline by a quorum*.

**Partition is not a bypass.** A server whose view has not merged within `merge_max_age` cannot know what the rest of the set has served, so it **refuses to serve** (`DSSO_E_UNAVAILABLE`) rather than serving on a stale view. Splitting the servers costs the attacker the service, not the bound.

**No cross-user leak, and no self-lockout of the innocent.** Counters are keyed by account, so one account's failures never touch another's budget. A successful two-factor login clears the account's counter across the set (a `reset_seq` bump that merge prefers wholesale), so a user who mistyped is not held hostage by their own failures. Metering happens **before** any factor is verified, so the cheap rejections — stale timestamp, replayed nonce — cost budget too.

## 7. Code loci

| What | Where |
|---|---|
| The whole contract, and the regulatory reading | `dapps/dsso/authn.h` |
| Device key generation from device-local entropy | `dsso_authn_device_keygen` (`dapps/dsso/authn.c`) |
| The challenge both sides compute independently | `dsso_authn_challenge` |
| The knowledge factor's response | `dsso_authn_knowledge_tag` |
| The possession proof (sign / verify) | `dsso_authn_possession_sign`, `dsso_authn_possession_verify` |
| Enrolment (first / later) | `dsso_authn_enrol_first`, `dsso_authn_enrol_device` |
| The dynamic authentication | `dsso_authn_login` |
| Sessions, the auth-epoch rule | `dsso_authn_session_verify` |
| **What the assertion layer consumes** | `dsso_authn_assertion_authorize`, `dsso_authn_account_loa` |
| Revocation | `dsso_authn_revoke_device` |
| The loss / recovery state machine | `dsso_authn_recover` |
| The bound server set | `dsso_authn_bind_server_set` |
| The aggregate limiter | `dsso_authn_cluster_init`, `dsso_authn_cluster_gossip`, `dsso_authn_cluster_meter`, `dsso_authn_meter_total` |
| The gate | `dapps/dsso/authn_selftest.c`, wrapper `tools/test_dsso_authn.sh` |

The module reads no clock and draws no randomness: `now` is a parameter of every entry point, the device seed and every nonce are caller-supplied, and the possession proof is deterministic. That is what makes the gate reproducible byte-for-byte.

## 8. The gate

`determ-dsso selftest-authn` (`tools/test_dsso_authn.sh`, FAST) — **114 assertions**:

- **A (16)** state init (an all-zero server-side session secret is refused; the deployment's server set is installed once rather than passed per call) and the possession primitive: two seeds give two keys; the same seed reproduces its key; sign/verify round trip; a proof for another challenge, under another key, with a flipped proof byte or a flipped response byte is rejected; a malformed public key is rejected rather than dereferenced; NULL arguments fail closed.
- **B (8)** enrolment: fail-closed with no verifier; refused with no presentation; accepted with a verified one; the account reports ACTIVE/SUBSTANTIAL; a presentation cannot be replayed into a second account; an existing account cannot be re-enrolled over.
- **C (16)** login: the honest two-factor login accepted at SUBSTANTIAL; **password-only rejected**; **device-only rejected**; a wrong password rejected; a **replayed** device response rejected; a response bound to **another session** rejected; a response bound to **another server set** rejected; a cluster whose set digest is not the deployment's bound one refused outright; stale and future-dated timestamps rejected. Then the §2.2.1 adversary: a device key derived from `pk_dev ‖ knowledge_verifier ‖ server-set digest` is **not** the enrolled key, that adversary **cannot complete a login**, and the honest holder still can.
- **D (5)** second device: **password alone refused**; a login-purpose proof refused for an enrolment; session + current-device proof accepted; the enrolling session survives; the new device logs in.
- **E (8)** revocation: the live session verifies before; **a stolen session token without the device revokes nothing**; revoke succeeds; **the session issued before the revocation stops verifying**; every concurrent session dies; the assertion layer refuses it; the revoked device cannot authenticate; the surviving device is unaffected.
- **F (35)** the state machine: every transition above accepted or refused as designed — including `RESTORE_DEVICE`/`RESTORE_PASSWORD`/`RESTORE_BOTH` **refused without the PID**, the **downgrade to LOW being visible to the assertion layer**, a LOW session unable to enrol, a PID for another subject refused, a rejected verdict and an unreachable verifier both failing closed, a device id never recycled, a refusal leaving the account untouched, and a captured device response unable to move to another session when no knowledge tag binds it.
- **G (15)** the limiter: subset rotation yields exactly `floor(cap/t)`; the next fresh subset is `DSSO_E_RATELIMIT`; every server agrees the aggregate is the cap; another account is untouched; a stale view refuses; a new window resets; a failed login still costs budget; three failures across two subsets are seen by a server that served none of them; a success clears the budget set-wide; malformed subsets refused.
- **H (12)** the report: an unknown account is NONE; an unknown session does not verify; an expired session does not verify; a two-factor session authorises SUBSTANTIAL; **nothing reaches above SUBSTANTIAL**; names for operators; and the byte-identical login under two different server-side session secrets yields two different session ids — the bearer token is not a function of the request.

**Falsify-on-mutant.** Each mutant restores the defect, is built into a REBUILT binary, and is reverted afterwards:

| # | Mutation | Arms that go RED |
|---|---|---|
| M1 | the device-signature check is removed from the login path | C8, C9, C12, F17b |
| M2 | the challenge no longer binds the session nonce | F17b |
| M3 | a session alone enrols a device | D1, D2, D3 |
| M4 | recovery restores assurance without the second evidence | F2, F18, F27 (+22 cascading) |
| M5 | sessions stay valid after a revocation | E3, E4, E5, F12 |
| M6 | the limiter counts per server again | G1, G2, G3 |
| M7 | the device key stops depending on device-local entropy | A2, A8, C11, C12 |

M2 is worth a note: in a two-factor login the knowledge tag already carries the nonce, so a cross-session replay fails on `bind` even if the challenge forgets the nonce. The arm that isolates the session field is therefore the **possession-only** one (F17b), where no knowledge tag exists and the challenge's own nonce is all that stands between a captured device response and a replay into a fresh session.

## 9. What is NOT claimed

- **Not notified.** DSSO is not a Member State-notified electronic identification scheme. Notification is an Art. 9 act by a Member State and is not achievable in this repository.
- **Not certified.** Nothing here is certified under CIR (EU) 2024/2981 or any other scheme. "Equivalent to level substantial" is an engineering reading of the Annex, not a conformity assessment. No test passing here means a regulatory requirement is met.
- **Not a wallet.** DSSO is a Wallet-Relying Party and a private identity provider, never a European Digital Identity Wallet or a Wallet Provider.
- **Identity proofing is inherited, and it does not make later logins "high".** §2.1.2 proofing assurance comes from the PID the wallet issued under a notified scheme. This module records *what it verified* and binds it to an account. A later login is judged only by the factors presented at that login; `DSSO_LOA_HIGH` does not exist in this module and no path produces it.
- **The PID verifier is not implemented here.** The interface is defined, the dependency is named, and everything behind it is a sibling track's work. Until a verifier is installed, every PID-authorised transition returns `DSSO_E_UNAVAILABLE`.
- **No notification, alerting or out-of-band confirmation.** There is no "a new device was added to your account" channel. §2.2.3's dynamic-linking language and operational notification practice are out of scope.
- **No phishing resistance claim.** The challenge binds the session, the server set and the time; it does **not** bind an origin or a channel. A relay that sits between the user and the real server set and forwards both factors is not defeated by this design. WebAuthn-style origin binding would be a different construction.
- **No secure-element claim.** "Device-resident" here means the key is generated from device-local entropy and never transmitted. Whether the platform keeps it in a secure element, and §2.2.1's "protected against duplication" language, is a deployment property this code cannot assert.
- **Revoked device records are not retained forever.** `dev_admit` refuses a device id that is still on the account, so an id is not recycled while its record exists; but the fixed four-slot device array reuses a revoked slot when it runs out, and an id whose record was overwritten could be enrolled again. A deployment with a database keeps revoked records and must keep refusing their ids.
- **No service layer.** `determ-dsso` has no network listener and no persistent store. What ships is the module and its gate; composing it into a running DSSO deployment (and swapping the fixed-capacity containers for a database) is not done here. The fixed caps — 8 accounts, 4 devices, 32 sessions, 128 cached nonces, 8 servers — are reference-implementation bounds, not deployment sizing.
- **Chain-identity rotation is still not shipped.** `v2.25-DSSO-DAPP-SPEC.md` §8 names v2.26 `ROTATE_KEY` as the answer to chain-identity key loss. Verified 2026-09-17: `ROTATE_KEY` has **no `TxType` slot, no payload codec and no apply path** anywhere in the repository — it exists only as design text (`PHASE2-PRIMITIVES-KICKOFF.md` §1 calls it "0% built today"). Nothing in this module depends on it; the authentication-factor recovery described in §5 is complete without it, and the chain-identity dependency remains open.
- **The knowledge factor's own soundness is unchanged.** This module consumes `knowledge_verifier` as an opaque server-side secret. The open findings on the shipped OPAQUE stack (`v2.25-DSSO-DAPP-SPEC.md` §0.0 items 2 and 3 — claims C2 and C6, both owner-gated) are untouched by this increment and remain open.
- **The session id is a keyed bearer token, by construction.** Account, login nonce and timestamp all travel in the login request, so a session id hashed from those alone would be computable by anyone who saw the request. It is an `HMAC(session_secret, …)` under a server-side secret the caller injects at `dsso_authn_init` (an all-zero secret is refused), plus a per-issue sequence number. A deployment that shares that secret across servers shares the ability to mint tokens; a deployment that does not must route session verification to the issuing server. Neither choice is made here.
- **Residual: an account-existence oracle.** A login for an unknown account returns `DSSO_E_STATUS` without metering, because metering an arbitrary identifier would let an attacker exhaust the bounded meter table. A deployment that cares about account enumeration must meter unknown accounts against a separate, hashed-key structure.

## 10. Cross-references

`v2.25-DSSO-DAPP-SPEC.md` (the protocol, §4 login / §5 assertion / §6 claims / §8 recovery), `DssoThresholdOprfSoundness.md` (the t-of-n OPRF and the AKE this composes with), `DssoAssertionFreshness.md` (the RP-side freshness discipline the assurance report feeds), `CRYPTO-C99-SPEC.md` §3.8c/§3.9b (the P-256 and RFC 9497 primitives used), `DssoG5ConstantTimeReview.md` (the constant-time posture of the secret-scalar paths this reuses).
