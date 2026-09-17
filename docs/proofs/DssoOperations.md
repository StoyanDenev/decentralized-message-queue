# DSSO Operations — what a deployment must have that code cannot supply

**What this document is.** `dapps/dsso` ships modules: a wallet-relying-party verifier, an
account-binding rule set, a two-factor authentication state machine, an aggregate attempt
limiter, and a relying-party assertion. None of that is a service. This document is the
operational specification for the target role of
[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §11 — the accountable operator, the
custody of every key the system holds, incident response, availability and what
fail-closed means for a user, the audit evidence the assurance level requires, service
continuity, and data protection.

**Read it with [§12 of the spec](v2.25-DSSO-DAPP-SPEC.md#12-the-requirements-mapping--requirement-by-requirement-what-is-implemented-today).**
That mapping says which obligations are discharged by code. This document is the other
half: the obligations that are discharged by an organisation, or not at all. Where code
already enforces something, the function is named. Where it is purely organisational, the
row says so plainly rather than implying that a module covers it.

**Nothing here is implemented.** This is a specification of duties, not a description of
shipped behaviour — with the single exception of the sentences that cite a function, which
describe code that exists in this repository today. There is no configuration file, no
deployment script, no key-ceremony tool, no logging subsystem and no runbook in the tree.

---

## 1. The accountable operator

**A relying party is a legal person, not a binary.** Regulation (EU) No 910/2014 as amended
by (EU) 2024/1183 Art. 5b(1) obliges "the relying party" to register in the Member State
where it is established; Art. 5b(6) obliges it to keep that registration correct; Art.
5b(8) obliges it to identify itself to the user; Art. 5b(9) makes it responsible for the
authentication and validation procedure. Every one of those attaches to an entity that can
be registered, supervised and held liable. **This repository contains no such entity, and
no code can create one.**

Before DSSO is operated in either role, the operator must be able to answer, in writing:

| Question | Why it is not optional |
|---|---|
| **Which legal person is the relying party?** | It is the entity that registers under Art. 5b(1), that appears in the access certificate's registered name (ARF Reg_31) and trade names (RPA_06), and that a wallet displays to the user. An unregistered relying party has no access certificate, so it cannot perform the relying-party authentication a conforming wallet requires in every presentation transaction (RPA_03) — see the paragraph below this table. |
| **Which legal person is the data controller?** | DSSO processes personal data from the moment a PID presentation arrives. The controller determines purposes and means; it answers data-subject requests, runs the DPIA, and is the addressee of a supervisory authority. If DSSO is run for a third party, the controller/processor split must be written down before the first enrolment, not after. |
| **Who operates the `t`-of-`n` server set, and are they the same legal person?** | The whole security model is **K-of-K mutual distrust**: claims C1/C3/C7 hold only while fewer than `t` servers collude. `n` servers operated by one legal person under one administrator is `1` server wearing `n` hats, and the threshold assumption is then false. If the operators differ, the contractual arrangement between them is part of the security argument and must be documented as such. |
| **Who may authorise a key ceremony, a rotation, a revocation or a recovery?** | §2 and §4 below are duties; a duty without a named holder is not discharged. |
| **Who is the security contact, and where is it published?** | CIR (EU) 2015/1502 Annex §2.4.2. See §8. |

**The registration act, named.** The act that Art. 5b(1) requires is registration by the
accountable operator with the Registrar of its Member State, under the process that Member
State publishes (ARF Reg_02, Reg_24). It is **EXTERNAL and NOT obtained**. Its consequence
is concrete and is not a formality: an Access Certificate Authority notified by a Member
State issues an access certificate only to a registered relying party (ARF Reg_10a), the
wallet performs relying-party authentication with that certificate in **every** presentation
transaction (RPA_03) and, when that authentication fails, tells the user that the identity
of the relying party could not be verified and that the request is **not trustworthy**
(RPA_05). **Until the registration exists, DSSO's wallet-relying-party role is verified but
unreachable.**

---

## 2. Key management

DSSO holds five service-side key kinds (§2.1–§2.5) plus the per-user secrets of §2.6. Every module takes keys
as caller-owned byte arrays and none of them generates, stores, transports or rotates a
key: **key custody is entirely the deployment's, and the code's contribution is confined to
using keys correctly and scrubbing them.**

### 2.1 `sk_s` — the DSSO service static key (P-256 scalar, 32 bytes)

| | |
|---|---|
| **What it is** | The long-term secret of the threshold IdP in the OPAQUE-3DH AKE. Its public point `pk_s` is what a client anchors. |
| **Who generates it** | The operator, in a key ceremony, from a CSPRNG. `determ_opaque3dh_server` takes `sk_s` as an argument; nothing in the repository generates it. |
| **Where it lives** | It must live in an HSM or KMS, not in a process image or a file. **No HSM or KMS integration exists** — `determ_opaque3dh_server` takes a raw 32-byte scalar, so today it necessarily lives in the address space of whatever runs it. A deployment that cannot change that has not met CIR (EU) 2015/1502 Annex §2.4.6's "protected from tampering". |
| **What the code already enforces** | The AKE transcript binds `CleartextCredentials{server_public_key, client_public_key, server_identity, client_identity}` (RFC 9807 §4.1.1) and the separate `pk_s`/`pk_c` call arguments are GONE, so a static key enters a party through exactly one MAC-covered field. A party that does not hold `sk_s` is rejected (`server_mac_ok == 0`) and derives no shared key. Every secret buffer on that path — `ikm`, `prk`, the handshake secret, `Km2`/`Km3`, the DH points — is secure-zeroed on success and on every reachable error path. |
| **How it rotates** | Badly, and the operator must plan for it. `pk_s` sits inside the `CleartextCredentials` block that is the AAD under which every user's credential envelope is sealed, so rotating `sk_s` requires **re-sealing every user's envelope** (spec §8's re-deal, user-as-dealer). Until a given user re-seals, the new `pk_s` fails closed at that user's AEAD tag rather than silently taking effect — which is correct, and means a rotation is a migration of the whole user base, not an operation. Rotation must therefore be scheduled, staged and completed, with a per-user completion metric. |
| **On compromise** | Treat as a **total compromise of the IdP identity**. An attacker holding `sk_s` simply **is** the IdP as far as the AKE is concerned: it completes the server half for every user who anchored the matching `pk_s`, and it needs to influence no anchor to do it. (The separate enrolment-anchor weakness in the residual below is an additional exposure, not the same one.) Required: rotate `sk_s`; force every user to re-seal; invalidate every live session (`auth_epoch` bump per account, §4); and treat every account enrolled during the exposure window as unproofed until re-proofed by a fresh PID presentation. |
| **Residual, stated** | The C2 closure binds `pk_s` into the transcript; it does not make the client's anchored `pk_s` authentic. At login the anchor is the envelope AAD (password plus at least `t` OPRF responses). **At enrolment the anchor is supposed to be the on-chain DSSO registration record read through the committee-authenticated light client, and no DSSO-specific resolver exists in `light/`** (spec §0.0(2)). Until it does, the enrolment anchor is a requirement on the deployment, not shipped code, and **an attacker who controls enrolment owns the account from the start**. |

### 2.2 `tenant_key` — the per-relying-party MAC key (32 bytes)

| | |
|---|---|
| **What it is** | The outer-leg HMAC key of the §5 assertion. **Held by exactly two principals: the IdP and the one relying party that registered it. Never by a user, a wallet, or the chain.** A `tenant_key` in a user's hands makes every user a minting oracle for every subject at that relying party — that was defect C6(a). |
| **Who generates it** | Established at registration as `HKDF(registration secret, info = "determ-dsso/tenant-key/v1" ‖ rp_id ‖ u64(key_epoch))`. The module neither derives nor transports it. |
| **Where it lives** | One copy at the IdP, one at that relying party, both in a secret store. It is a symmetric key: **anyone who reads either copy can mint for that relying party**, subject to the reference-delivery rule below. |
| **What the code already enforces** | `dsso_rp_verify` accepts only a tag it recomputes that matches a reference the IdP delivered over the registered channel — the presenter supplies no tag at all — so a `tenant_key` holder who completed no login still cannot mint (that is the C6 repair). Both epochs are inside the MAC: a claim whose `key_epoch` or `reg_epoch` is not this verifier's current one is `DSSO_E_TRUST`. |
| **How it rotates** | Bump `key_epoch` and re-derive. **Pairwise subjects do NOT change** — that is why the two epochs are split. Old references stop verifying at once, so rotation is a brief outage for in-flight logins, which is the correct trade. A re-registration bumps `reg_epoch` instead and **does** rotate every pairwise subject at that relying party, forcing it to re-link accounts; that is the fail-safe default, because carrying identifiers across a re-established relationship hands the new holder the old holder's linkage to every user. |
| **On compromise** | Bump `key_epoch` immediately, re-derive, re-deliver. Then assess: an attacker with `tenant_key` **and** write access to the IdP→RP reference channel is the IdP for that relying party, and no symmetric construction improves on that — the channel's authentication is the registration's, not this module's. If the reference channel may also have been reached, bump `reg_epoch` as well and re-link. |
| **Residual, stated** | `dsso_idp_register_rp` validates only `rp_id_len` (`binding_valid`); **an all-zero `tenant_key` is accepted**. A deployment must refuse an unset key itself. |

### 2.3 `K_pseu` — the pseudonym key (32 bytes)

| | |
|---|---|
| **What it is** | The HMAC key of `pseudonym = HMAC-SHA256(K_pseu, "DSSO-PID-PSEUDONYM-v1" ‖ len(iss) ‖ iss ‖ len(id) ‖ id)` — the only persistent identifier DSSO keeps for a PID subject. |
| **Who generates it** | The operator, once, from a CSPRNG, in the same ceremony as `sk_s`. `dsso_bind_init` copies it in. |
| **Where it lives** | **Outside the account database, and in different custody from it.** This is the entire security argument for using a keyed function: a national identifier space is around 10^10 candidates with most of the entropy in a birth date, so a table of plain SHA-256 values is invertible in CPU-hours and a database leak would **be** a population-wide identity list. `K_pseu` in the same backup, the same dump or the same operator's hands as the `pseudonym` column defeats the construction completely. |
| **What the code already enforces** | `dsso_pseudonym_derive` is keyed and domain-separated and secure-zeroes its scratch buffer; `dsso_pid_subject_material` length-separates `iss` and the identifier so `("ab","c")` and `("a","bc")` cannot collide; `dsso_bind_commit` scrubs the raw identifier before returning (ARF OIA_16) and the raw value is never stored. |
| **How it rotates** | **It effectively cannot, in place.** The pseudonym is derived from material DSSO deliberately does not keep, so re-deriving under a new key requires every user to present a PID again. A rotation is therefore a re-enrolment campaign. Plan for that before choosing a retention policy, not after. |
| **On compromise (a leaked `K_pseu`)** | See §4.3. In short: the leak is only dangerous **together with** the pseudonym column, and it converts stored pseudonyms into a rainbow-table target against the national identifier space. Assume both are gone unless custody separation is demonstrable; then re-key, which means re-enrolment, and notify under Art. 33/34 GDPR if the conditions are met. |
| **Residual, stated** | `dsso_bind_init` does **not** refuse an all-zero `K_pseu` — unlike `dsso_authn_init`, which refuses an all-zero session secret. A deployment must check. |
| **Deliberate limitation** | The pseudonym is **service-wide, not per-account salted**, because the one-subject-one-account rule requires comparing subjects ACROSS accounts. It is therefore linkable WITHIN DSSO by design, and keyed so it is linkable nowhere else. See §7.2. |

### 2.4 The session secret (32 bytes)

| | |
|---|---|
| **What it is** | The server-side HMAC key session identifiers are derived under. A session id is a **bearer token**, and every other input to it — the account, the login nonce, the timestamp — travels in the clear in the login request, so keying it is the only thing that stops an observer of that request from computing the token. |
| **Who generates it** | The operator, from a CSPRNG, and injects it at `dsso_authn_init`. |
| **Where it lives** | In the authenticating process's memory, and nowhere else. It must be identical across every front-end that verifies sessions and must never be written to a log, a crash dump or a configuration file in cleartext. |
| **What the code already enforces** | `dsso_authn_init` **refuses an all-zero secret** (`all_zero`), which is the fail-closed guard against an unset one. A per-issue sequence number is folded in so two issues can never collide. The gate asserts that the byte-identical login under two different secrets yields two different session ids. |
| **How it rotates** | Rotating it invalidates every live session immediately (no session id derived under the old secret will be recomputed). That is an acceptable, cheap operation — unlike `sk_s` — and should be routine. |
| **On compromise** | Rotate at once. Then assume every session id issued under the old secret was forgeable for any account whose login request was observed, and bump `auth_epoch` on every account so that even correctly-guessed session ids stop verifying (`dsso_authn_session_verify` checks the epoch). |

### 2.5 The OPRF shares `k_i` (one P-256 scalar per server)

| | |
|---|---|
| **What they are** | Shamir shares over `Z_n` of the user's own OPRF key `k`, one held by each of the `n` servers. `t` of them reconstruct the OPRF evaluation; fewer than `t` learn nothing about the password beyond online guessing (claims C1/C3). |
| **Who generates them** | **The user, as dealer.** There is no DKG and none is wanted (`FROST_DEVIATION_NOTICE.md`). Each server receives its own share at registration. |
| **Where they live** | One share per server, in that server's secret store, under that server's own administration. **Two shares in one custody is one share for threshold purposes.** If the operator of the set is a single legal person (§1), the threshold is organisational, not cryptographic, and the deployment must say so in its risk assessment rather than quoting C1/C3. |
| **What the code already enforces** | Per-response DLEQ proofs against each server's published `PK_i` (RFC 9497 VOPRF), so a byzantine server's tampered response is detected and discarded rather than silently corrupting the login (claim C4); the constant-time review of the secret-scalar paths returned CT-clean and the G6 zeroization worklist shipped ([`DssoG5ConstantTimeReview.md`](DssoG5ConstantTimeReview.md)). The aggregate limiter binds the server **set** into every possession challenge via `set_digest`, and `dsso_authn_login` refuses a cluster whose digest is not the deployment's bound one (`dsso_authn_bind_server_set`). |
| **How they rotate** | Share refresh and server churn are the user-as-dealer re-deal of spec §8, authorised under the user's chain identity key. A deployment cannot rotate a user's shares on the user's behalf. |
| **On compromise of `b` shares** | While `b < t`: the limiter's bound degrades to `A ≤ floor(cap / (t − b))` attempts per window — the compromised servers can refuse to count — so **reduce `cap` accordingly** and force a re-deal. At `b ≥ t` the adversary holds an evaluation quorum and can evaluate the OPRF **offline**: no online limiter of any design bounds that case, every affected user's password must be treated as subject to offline dictionary attack, and every affected account must be re-enrolled. Do not report this case as rate-limited; it is not. |

### 2.6 Per-user secrets the service holds

| Secret | Custody | Notes |
|---|---|---|
| `user_root` (32 bytes, per user) | **The IdP alone.** Fixed at enrolment, never on the chain, not derived from `sso_key`. | It is the key of `dsso_pairwise_subject`. Its compromise lets an attacker compute every pairwise subject for that user at every relying party — i.e. it defeats exactly the correlation resistance §7.2 claims, for that user. It cannot be rotated without every relying party re-linking that user's account. |
| `knowledge_verifier` (32 bytes, per account) | The servers. | The knowledge factor's server-side secret. It is, by construction, derivable from the password together with `t` shares — which is precisely why it cannot be the whole authentication (§12 of the spec, CIR §2.2.1). |
| Account `auth_key` (32 bytes, per account) | The binding layer. | Keys the account re-authentication proof `dsso_bind_challenge_new` demands. `dsso_bind_account_add` does **not** refuse an all-zero key; a deployment must. |
| `sk_dev` (32 bytes, per device) | **The user's device, and nowhere else.** | Generated on the device from device-local entropy (`dsso_authn_device_keygen`); the servers hold only the public point, so no quorum of servers can impersonate the device. "Device-resident" is a statement about where it is generated and that it is never transmitted — **it is not a secure-element claim**. |
| `sso_key` / `binder` | Per login, transient. | The `binder` is a bearer secret in transit; front-channel confidentiality is the deployment's, and single use, `T_max` and the `sid` binding are what bound a stolen one. |

---

## 3. Dependencies, fail-closed behaviour, and what an outage means for a user

**The house rule, and it is not negotiable: a dependency that cannot be consulted is
`DSSO_E_UNAVAILABLE` and the operation FAILS. There is no allow-on-outage path anywhere in
`dapps/dsso`, and adding one would be a defect, not a feature.** This section states what
that costs, because an operator who is surprised by it at 03:00 will be tempted to add the
path the code refuses to contain.

### 3.1 A status list that cannot be consulted

`check_status` fails closed in five distinct ways, each `DSSO_E_UNAVAILABLE`: the fetch
callback returns non-zero (unreachable, refused, too large); the token is past its own
`exp` (stale); the token's `sub` is not the list the credential named; the index is past the
end of the inflated bitstring; the stream will not inflate under the cap. A status that IS
readable and is not `0x00` is `DSSO_E_STATUS` — `0x01` revoked, `0x02` suspended, anything
else an extension this verifier refuses.

**What a user experiences:** an enrolment or a re-proofing that cannot complete. That is
all. Because the PID flow happens **once**, at enrolment, and the §4 login happens every
time afterwards (spec §11), **a status-list outage does not lock existing users out** — it
blocks new enrolments and PID-authorised recoveries. The operator's obligations are: to
state this in the published service description (§8); to monitor status-list reachability
as a first-class dependency with its own alert; and to cache nothing beyond the token's own
`exp`, because the code will reject a stale token and a cache that hides staleness is an
allow-on-outage path wearing a disguise.

**The fetch itself is not implemented.** `dsso_status_fetch_fn` is a callback seam. There is
no HTTP client, no TLS, no cache, no retry and no discovery in this repository. Everything
about the security of that path — certificate validation, pinning, timeouts, redirect
policy, SSRF defence — is the deployment's.

**How far to trust the `uri`, stated precisely.** It is **not** arbitrary attacker input: it
lives inside the issuer-signed payload, and rule 8 runs only after rule 3 has verified the
issuer signature against a configured trust anchor, so a `uri` that reaches the fetch was
chosen by a PID Provider on the trust list. It is **not** trusted input either: **whoever
can get a credential issued by an anchored provider chooses it**, and a compromised or
careless anchor can point it anywhere. Treat it as semi-trusted and defend accordingly —
allow-list the hosts (a real deployment knows its PID Providers' status endpoints), refuse
redirects to private address space, set a hard timeout, and bound the response to
`DSSO_MAX_TOKEN`. A fetch layer that resolves an arbitrary host because "the credential was
signed" is an SSRF primitive with a signature on it.

### 3.2 A trust list that is stale, unreachable, or wrong

There is no trust list. `dsso_trust_list` is a configured C array of `{iss, kid, pk,
max_loa}` and `dsso_trust_lookup` matches `iss` and `kid` exactly, returning `DSSO_E_TRUST`
for anything not in it — no fallback, no discovery, no "unknown issuer at reduced
assurance". **Populating and refreshing that array from a Member State's published PID
Provider list is a deployment act with its own unwritten code** (spec §12.3, OIA_12).

The operational consequences are therefore the operator's entirely:

- **A newly notified PID Provider is invisible** until someone updates the array and
  redeploys. Enrolments from wallets holding that provider's PID fail `DSSO_E_TRUST`.
- **A withdrawn PID Provider stays trusted** until someone removes it. This is the
  dangerous direction, and it is the reason §4.4 exists.
- **A rotated PID Provider key breaks every enrolment from that provider** until the new
  `kid` is added; `kid` is matched exactly, so an unannounced rotation is an outage.
- The refresh cadence, the authentication of the source, and who may approve a change to
  the array are all operator duties, and an unapproved change to that array is equivalent
  to adding a trusted identity issuer.

### 3.3 The server set

`dsso_authn_login` requires `k >= t` and refuses a cluster whose `set_digest` is not the one
installed by `dsso_authn_bind_server_set` — a substituted or misconfigured set is
`DSSO_E_BINDING` **before** anything is metered or verified. A server whose limiter view has
not been merged within `merge_max_age` **refuses to serve** rather than serve on a stale
view, so partitioning the set costs the attacker the service and not the guessing bound.
**What a user experiences during a partition: logins fail.** That is the intended trade and
the operator must size `merge_max_age` and the gossip cadence knowing it.

### 3.4 Capacity, and the fail-closed edges that look like outages

Three bounded tables fail closed when full rather than evicting something live, and each
is an availability lever a deployment must size:

| Table | Bound | What happens when it is full |
|---|---|---|
| Relying-party nonce cache | `DSSO_ASSERT_NONCE_SLOTS` (128) | `dsso_rp_verify` returns `DSSO_E_UNAVAILABLE`. It **never** evicts a live entry, because accepting while unable to remember is accepting a replay. **Named residual:** an AUTHENTICATED party can wedge a verifier by completing that many real logins inside one retention window. The levers are deployment ones — size the table above peak, and apply the per-account login rate limit. A per-subject slot quota would bound it further and is **not implemented**. |
| Reference table | `DSSO_ASSERT_REF_SLOTS` (160) | `dsso_rp_deliver` returns `DSSO_E_UNAVAILABLE`. Deliberately larger than the nonce cache, because it also carries logins issued but not yet presented. |
| PID presentation cache | `DSSO_AUTHN_MAX_SEEN` (128) | Fails closed. **It never ages entries out** — correct for a reference container, wrong for a long-running service, which needs a database. Recorded as a known limitation of the reference implementation, not of the rule. |

---

## 4. Incident response

Each subsection below is a concrete sequence. The first step of every one of them is the
same and is stated once: **establish the exposure window**, because every later step is
scoped by it and because §6's logging is what makes it answerable at all.

### 4.1 A compromised DSSO server

Assume the attacker has the process image and the filesystem of one server of the `t`-of-`n`
set.

1. **Isolate** the server from the gossip mesh and from clients. Do not wipe it; it is
   evidence (§6).
2. **Assume disclosed:** that server's OPRF share `k_i`; the session secret if that server
   authenticates sessions; `tenant_key` for every relying party it serves; `K_pseu` if it
   holds the binding context; `sk_s` if it holds the service static key; and every
   `user_root` and `knowledge_verifier` in its memory. In the shipped modules **all of
   these are plain byte arrays in the process**, so "assume disclosed" is the only defensible
   default until an HSM/KMS integration exists (§2.1).
3. **Count the shares.** With `b` compromised servers and `b < t`, the OPRF key is still
   safe and the limiter's bound degrades to `A ≤ floor(cap / (t − b))`: reduce `cap` to
   restore the intended bound. **At `b >= t`, stop treating this as a rate-limited system** —
   the adversary can evaluate the OPRF offline, every affected password is subject to
   offline dictionary attack, and every affected account must be re-enrolled.
4. **Rotate, in this order:** session secret (cheap, kills every live session); `tenant_key`
   for every affected relying party with a `key_epoch` bump; then `sk_s` if it was exposed,
   which is the whole-user-base re-seal of §2.1 and must be scheduled, not improvised.
5. **Kill sessions that a rotation does not reach.** Bump `auth_epoch` on every affected
   account; `dsso_authn_session_verify` then refuses every session issued before the bump,
   including the attacker's.
6. **Force a re-deal.** Share refresh is user-as-dealer (spec §8), so this is a user-facing
   campaign with a completion metric, not a server-side operation.
7. **Re-proof the exposure window.** Every account enrolled while the server was
   compromised must be treated as unproofed and re-bound by a fresh PID presentation —
   `dsso_authn_recover` with `DSSO_AUTHN_EV_RESTORE_BOTH` is enrolment re-run under a fresh
   proofing event.
8. **Notify** the supervisory authority and affected users where GDPR Art. 33/34 conditions
   are met (§7), and the Member State registrar under Art. 5b(6) if registered information
   changed.

### 4.2 A compromised user device

Assume the attacker holds the device and therefore `sk_dev`.

1. **If the user still has a second active device:** `dsso_authn_revoke_device` with a live
   `SUBSTANTIAL` session plus a fresh possession proof from an active device, bound to the
   target. It **bumps `auth_epoch`**, so every live session — including the one that asked —
   stops verifying at once, and the revoked device cannot authenticate afterwards.
2. **If it was the only device:** `DSSO_AUTHN_EV_DEVICE_LOST`. The account degrades to
   `KNOWLEDGE_ONLY`, which is **LOW**, and `dsso_authn_assertion_authorize` then refuses to
   mint a §5 token for any relying party that requires substantial. That degradation is the
   point and it must be visible to the user, not silently absorbed.
3. **Restoring substantial requires a second, independent evidence:** knowledge **plus** a
   fresh, single-use, subject-matched PID presentation
   (`DSSO_AUTHN_EV_RESTORE_DEVICE`). A recovery path that handed back full assurance on one
   factor would make the account single-factor, which is the defect the whole module exists
   to close. **A device id is never recycled** (`dev_admit`), and a refused add leaves the
   account exactly as it was.
4. **What the code does NOT give you:** there is **no notification channel**. Nothing tells
   a user that a device was added, revoked, or that their account degraded. Building that
   channel — and the out-of-band contact details it needs — is an operator duty (§5), and
   without it step 1 depends on the user noticing.
5. **Phishing and relay are not defeated.** The challenge binds the session, the server set,
   the device, the purpose and the time — **but not an origin or a channel** — so an attacker
   who relays both factors in real time succeeds. Treat a report of a relayed login as a
   compromise of the account, not as a false alarm.

### 4.3 A leaked pseudonym key `K_pseu`

1. **Determine whether the pseudonym column leaked with it.** `K_pseu` alone is a 32-byte
   secret with nothing to apply it to; the stored pseudonyms alone are uncorrelatable
   32-byte strings. **Together they are a population-wide identity list**, because the key
   turns a 10^10-candidate national identifier space into an enumerable one. If custody
   separation (§2.3) cannot be **demonstrated** from the evidence, assume both are gone.
2. **Assess as a personal-data breach immediately.** The reconstructible data is national
   identifiers linked to DSSO accounts. Under GDPR Art. 33 this is a supervisory-authority
   notification within 72 hours of awareness; under Art. 34 it is very likely a
   communication to the data subjects, and the operator should plan on doing it rather than
   arguing about it.
3. **Re-key.** There is **no in-place rotation** — the pseudonym is derived from material
   DSSO deliberately does not keep — so re-keying is a **re-enrolment campaign**: every user
   presents a PID again, and the new pseudonym is derived under the new key. Budget for this
   at design time.
4. **In the meantime, treat the old pseudonym as a public identifier.** It still functions —
   the one-subject-one-account rule still holds — but it must not be treated as protecting
   anything, and it must not be exported, shared or used as a key in any downstream system.
5. **It does not compromise authentication.** `K_pseu` is not an authentication key; no
   session, assertion or factor is derived from it. Say so explicitly in the incident
   report, so the response is scoped correctly.

### 4.4 A PID Provider that is revoked, suspended or compromised

This is the case the missing trust list (§3.2) makes dangerous, because **nothing notices
automatically**.

1. **Remove the provider's anchor from `dsso_trust_list` and redeploy.** Until that
   happens `dsso_trust_lookup` keeps returning its key and `dsso_pid_verify` keeps
   accepting its credentials. There is no revocation of a trust anchor in this code, only
   configuration.
2. **Do not rely on the status list to do it.** `check_status` requires the status token to
   come from the **credential's own issuer** — a deliberate tightening over
   `draft-ietf-oauth-status-list`, adopted because "signed by SOME anchor on the list"
   would let one compromised provider un-revoke another Member State's credentials. The
   consequence here is the other side of that trade: **a compromised provider controls its
   own revocation feed**, so its status answers are worthless once it is compromised.
3. **Identify the affected bindings.** Every `dsso_binding_record` stores `iss`, so the
   bindings made against that provider are enumerable without touching any identifier.
4. **Decide per binding, and record the decision.** Suspension of a provider is not the same
   as compromise: a suspended provider's past proofing may still be sound, while a
   compromised one's is not. For a compromise, degrade the affected accounts and require
   re-proofing against a different provider. `dsso_bind_unbind` — which needs the account
   holder's own fresh re-authentication — is the only path from one subject to another, and
   it is deliberately not an administrative action.
5. **Reassess the assurance cap.** Each anchor carries a `max_loa` that caps what its issuer
   may assert (the effective level is `min(anchor.max_loa, credential acr)`). Lowering a
   provider's cap is a lighter intervention than removal and is available.

---

## 5. Service continuity and user-facing operations

Nothing in this section is code. All of it is required for the authentication to be
operable at all.

| Duty | Why | State today |
|---|---|---|
| **Device delivery, provisioning and activation** | CIR §2.2.2 requires the means to reach only the intended person and be activated only by them. `dsso_authn_enrol_first` and `dsso_authn_enrol_device` implement the **authorisation** rules; they say nothing about how a device is provisioned. | **Not implemented.** No out-of-band channel, no activation code, no provisioning flow. |
| **Notification of security-relevant events** | A device added, a device revoked, an account degraded to LOW, a recovery performed. Without it, §4.2 step 1 depends on the user noticing. | **Not implemented, and explicitly out of scope of the module.** Operational alerting and the out-of-band contact details it needs are an operator build. |
| **A help-desk / assisted-recovery path, and its identity checks** | Users lose both factors. `DSSO_AUTHN_EV_BOTH_LOST` → `LOCKED` and `DSSO_AUTHN_EV_RESTORE_BOTH` require a PID presentation, which is the right rule — but somebody has to operate the conversation around it. | **The rule is implemented; the process is not.** An assisted path that bypasses the PID requirement would silently make the account single-factor. It must not exist. |
| **Account existence is observable** | A login for an unknown account returns `DSSO_E_STATUS` **without metering** — metering an arbitrary identifier would exhaust the bounded meter table. So an enumeration oracle exists. | **Known residual**, recorded in [`DssoAuthenticationAssurance.md`](DssoAuthenticationAssurance.md) §9. Mitigation is a front-end rate limit on unknown-account attempts; there is none in the module. |
| **Capacity planning against the fail-closed tables** | §3.4. Each of the three tables turns into an availability incident when it fills. | Sizes are compile-time constants in the reference implementation. |
| **Backup and restore** | A restore that rolls back the nonce caches, the `seen` tables or `auth_epoch` **re-enables replays and resurrects revoked sessions**. A restore is therefore a security operation, not an availability one. | **No persistence exists**, so this is entirely a property of whatever database a deployment substitutes. The rule it must preserve: single-use state and `auth_epoch` are monotonic and must never move backwards. |
| **Clock discipline** | Freshness, skew windows, nonce retention (`2·skew + 1`), session TTL and status-token `exp` all depend on the clock. `dsso_rp_verify` treats `now == 0` as `DSSO_E_UNAVAILABLE` — an unreadable clock is an outage, not a pass. | The modules read **no clock at all**; every `now` is injected. Supplying a correct, monotonic, synchronised time is the deployment's. |

---

## 6. Audit evidence: what must be logged, what must never be logged, and for how long

**CIR (EU) 2015/1502 Annex §2.4.4 (Record keeping)** requires the operator to *"record and
maintain relevant information using an effective record-management system, taking into
account applicable legislation and good practice in relation to data protection and data
retention"*, and to *"retain … and protect records for as long as they are required for the
purpose of auditing and investigation of security breaches"*. At level substantial the
requirement is **the same as at level low** — the difficulty is not the level, it is that
**nothing in this repository logs anything**. `determ-dsso` performs no IO except writing
selftest output to stdout. What follows is therefore a specification for a logging
subsystem that does not exist.

### 6.1 What MUST be recorded

| Event | Minimum fields |
|---|---|
| Enrolment (first) | account id, pseudonym, PID issuer `iss`, effective assurance level, presentation id, timestamp, outcome |
| Binding, unbinding, re-binding refusal | account id, pseudonym, purpose, outcome and the exact status code |
| Device enrolment, revocation, and every `auth_epoch` bump | account id, device id, **a keyed truncation of** the authorising session id (never the id itself — see §6.2), outcome, the reason for the bump |
| Every authentication attempt | account id, outcome, the status code, which factors were presented, the resulting assurance level, the server subset that served it |
| Every limiter decision | account id, the aggregate at decision time, `DSSO_E_RATELIMIT` or not, and the staleness refusal |
| Every recovery transition | account id, the event, the evidences relied on, the before and after account state |
| Every assertion issued and every relying-party verification outcome | relying party id, `key_epoch`, `reg_epoch`, outcome and status code — **never the subject, the binder or the tag** |
| Trust-anchor configuration changes | who, when, which anchor, and the approval |
| Key ceremonies, rotations and compromises | who, when, which key, the authorisation |
| Every `DSSO_E_UNAVAILABLE` | which dependency, so a fail-closed outage is distinguishable from an attack |

The status codes of `dsso.h` are stable and named (`dsso_status_name`) precisely so that
operators and gates can match on them; log the **name**, not a bare integer.

### 6.2 What must NEVER be recorded

This list is not advisory. Writing any of it to a log converts a log store into the asset
the whole design exists to avoid creating.

- **No PID attribute.** Not a name, not a date of birth, not a document number, not an
  address — nothing out of `dsso_pid_result.claims`. Log the issuer and the level; never a
  claim value.
- **No raw identifier.** Never `personal_administrative_number`, and never the output of
  `dsso_pid_subject_material`, which is the raw national identifier with a length prefix.
  The code scrubs that buffer before `dsso_bind_commit` returns; a logger that captured it
  first would undo the one thing ARF OIA_16 is about. **Log the pseudonym or nothing.**
- **No reusable secret.** Not `sk_s`, `tenant_key`, `K_pseu`, the session secret, a
  `user_root`, a `knowledge_verifier`, an account `auth_key`, an OPRF share, `sso_key`, a
  `binder`, or a reference `tag`. Not in a debug build, not at trace level, not in a crash
  dump.
- **No session id and no bearer token in cleartext.** A session id is a bearer credential;
  a log line carrying one is a credential store. If session correlation is needed, log a
  keyed truncation of it, under a key that is not the session secret.
- **No full presentation, and no KB-JWT.** A presentation is a signed document containing
  attributes; storing one stores the attributes. If a rejected presentation must be kept
  for forensics, keep the **status code and the rule that rejected it**, not the bytes —
  and if the bytes are genuinely required for an investigation, that is a separate,
  time-boxed, access-controlled evidence store under §7.3, not the operational log.
- **No status-list token payload**, which is a revocation map for a whole population.

### 6.3 Retention

The regulation sets no number; it sets a purpose — *"as long as they are required for the
purpose of auditing and investigation of security breaches"* — and subordinates it to data
protection law. The operator must therefore choose periods, justify them against that
purpose, and **delete on expiry**, which is itself a mechanism that has to exist. The
shape of a defensible policy:

| Record class | Suggested floor | Ceiling driver |
|---|---|---|
| Security events (enrolment, binding, device lifecycle, `auth_epoch` bumps, key operations, trust-anchor changes) | long enough to investigate a breach discovered late. **The regulation names no number** and neither does this document: a common starting point is 12 to 24 months, offered as a starting point to be justified, not as a cited requirement | Necessity under GDPR Art. 5(1)(e); these records name accounts and therefore are personal data |
| Authentication attempt logs | short — days to a few months | They are the highest-volume personal-data class and the least individually useful after the fact |
| Limiter decisions | short; they are operational | — |
| Assertion issue/verify outcomes | short | They are the traffic-analysis surface §7.2 names |
| Key ceremony and rotation records | the life of the key plus the longest audit cycle | §2 |
| Forensic evidence captured during an incident | time-boxed to the investigation, then deleted | §7.3 |

**Protection of the records is part of the requirement, not an extra.** Append-only or
write-once storage, integrity protection, access control separate from the account
database's, and an audit trail of access to the audit trail. **A log store that an
application account can rewrite is not a record-management system.**

---

## 7. Data protection

### 7.1 What personal data DSSO holds at rest — stated bluntly

At rest, in the modules as written, DSSO holds:

- **a keyed pseudonym of a national identifier** — `HMAC(K_pseu, label ‖ iss ‖ id)` in
  every `dsso_binding_record`;
- **the PID issuer** `iss` of each binding, which is a Member State-level attribute of the
  data subject;
- **the assurance level** and the **time** of each binding;
- **an account identifier, device identifiers and device public keys**, plus enrolment
  timestamps and the account's state and `auth_epoch`;
- **per-account secrets** (`knowledge_verifier`, `auth_key`, `user_root`) that are not
  themselves personal data but are bound one-to-one to a person.

**It does not hold** a name, a date of birth, a document number, an address, any other PID
attribute, or the raw national identifier: claims live only in a `dsso_pid_result` on the
stack and are zeroed by `dsso_pid_result_scrub`, and `dsso_bind_commit` scrubs the raw
subject material before it returns.

**This is still personal data.** A keyed pseudonym is pseudonymous data, not anonymous
data: it is re-identifiable by whoever holds `K_pseu` and the subject material, which is
exactly the design. GDPR applies in full. A deployment that describes its store as
"anonymised" is wrong, and this document says so in advance so that nobody has to discover
it during an audit.

### 7.2 Data minimisation, and what pairwise pseudonyms do and do not protect against

**What is minimised, and by what mechanism:**

- DSSO consumes **one** PID attribute — `personal_administrative_number` — and holds a
  keyed derivation of it. Every other disclosed attribute is held on the stack for the
  duration of one verification and then zeroed. **The module's restraint is not a
  guarantee about the deployment**: a caller holds the `dsso_pid_result` until it scrubs
  it, and `dsso_pid_claim_value` will hand it any disclosed attribute by name. Minimisation
  beyond what the module itself uses is an operator rule, and it needs the attribute
  allow-list bound to the declared purpose that Art. 5b(2)(c)/(3) requires and that
  [§12.1 of the spec](v2.25-DSSO-DAPP-SPEC.md) records as missing.
- Identifiers handed to DSSO's own relying parties are **pairwise**:
  `sub = HMAC(user_root, DS_SUB ‖ LP(rp_id) ‖ u64(reg_epoch))`. It is the same for one
  relying party across every login and different across relying parties, and the key is one
  **neither relying party holds**. The IdP derives it; it is never a caller input
  (`dsso_assert_issue`).
- The internal pseudonym **never leaves the service**. The value a relying party sees and
  the value the account database holds are different values derived under different keys.

**What pairwise pseudonyms do NOT protect against. This list is the point of this
subsection.**

1. **They do not stop the identity provider correlating.** DSSO holds `user_root` and
   derives every relying party's subject from it, so **DSSO can link a user's activity
   across every relying party at will**. Pairwise subjects defeat correlation *between
   relying parties*; they do nothing about the party in the middle. Any privacy claim that
   omits this sentence is false.
2. **They do not stop the internal pseudonym linking accounts within DSSO.** That is
   deliberate — the one-subject-one-account rule of `dsso_bind_commit` requires comparing
   subjects across accounts, which a per-account salt would make impossible. The pseudonym
   is service-wide, and keyed so that it is linkable nowhere else.
3. **They do not defeat traffic analysis.** Two relying parties comparing login **timings**
   can still correlate a user. Spec §7 excludes assertion-traffic anonymity from scope;
   pairwise subjects defeat identifier correlation, not observation.
4. **They do not survive a `user_root` compromise** (§2.6), nor a `K_pseu`-plus-database
   compromise (§4.3).
5. **They do not hide the attributes a relying party learns by other means.** DSSO asserts a
   subject and an assurance level; whatever else a relying party knows about that subject is
   outside this system.
6. **A re-registration rotates them** (`reg_epoch`), which is a privacy default and an
   operational cost: the relying party must re-link its accounts.

### 7.3 Retention, deletion and access control

- **Retention** of the account and binding records is the operator's decision under GDPR
  Art. 5(1)(e), and it must have an end. The one constraint the code imposes is that
  deleting a binding is **not** the same as forgetting a subject: the one-subject-one-account
  rule is enforced against the stored pseudonym, so a deleted binding must remove the
  pseudonym or the subject can never re-enrol.
- **Deletion** must reach the pseudonym, the `iss`, the device records and the per-account
  secrets, plus every backup and every log line derived from them (§6.3). `dsso_bind_unbind`
  clears the binding in the reference container; it is not a data-erasure implementation and
  a deployment must build one.
- **Access control** must separate at least four things that the reference implementation
  keeps in one address space: `K_pseu` from the pseudonym column (§2.3); the audit log from
  the application (§6.3); each OPRF share from every other (§2.5); and the ability to change
  `dsso_trust_list` from the ability to run the service, because changing that array is
  equivalent to adding a trusted identity issuer (§3.2).
- **Data subject rights.** Access, rectification and erasure requests must be answerable
  without the raw identifier, because DSSO does not hold it: the subject is located by
  presenting a PID and deriving the pseudonym again, which is `dsso_pseudonym_derive` over
  fresh subject material. That is a process the operator must build; there is no lookup by
  name in this system and there must not be one.
- **A DPIA is required before operation**, not after: the processing is large-scale
  identity data derived from a national identifier under a new technology, and §7.1 is its
  starting inventory.

---

## 8. Published notices, compliance and audit

| Obligation | Source | State |
|---|---|---|
| Publish the service definition, terms and conditions, privacy policy, fees and a contact point | CIR (EU) 2015/1502 Annex §2.4.2 | **EXTERNAL.** Nothing in code. The published description must state the fail-closed behaviour of §3, because a user who cannot enrol during a status-list outage is entitled to know why. |
| Maintain an information security management system adhering to proven standards | Annex §2.4.3 | **EXTERNAL.** §2 and §4 of this document are inputs to it, not a substitute. |
| Physical and personnel security proportionate to the risk | Annex §2.4.5 | **EXTERNAL.** §2's custody requirements are unenforceable without it. |
| Protect sensitive cryptographic material from tampering | Annex §2.4.6 | **PARTIAL.** In-process hygiene is implemented (secure zeroization on every path, constant-time comparisons, the CT review); **no HSM or KMS integration exists** for any of the five service keys. |
| Periodic internal audit; external assessment where the scheme requires it | Annex §2.4.7 | **EXTERNAL.** The operator commissions it; for a notified scheme a conformity assessment body performs it. **DSSO is not notified and is not seeking to be** (spec §11). |
| Keep the Member State registration correct | Reg. (EU) 910/2014 Art. 5b(6), ARF Reg_08 | **EXTERNAL**, and conditional on a registration that does not exist (§1). |

---

## 9. What this document is not

1. **It is not evidence of compliance with anything.** It is a statement of duties. A duty
   written down is not a duty discharged, and no part of this document may be cited as
   showing that DSSO meets a requirement.
2. **It is not a claim that DSSO is certified, notified, or a wallet.** It is not notified
   under Art. 9, not certified under CIR (EU) 2024/2981, and not a qualified trust service
   provider.
3. **It is not a runbook.** There is no configuration, no deployment tooling, no ceremony
   script and no monitoring in this repository, and this document does not pretend
   otherwise.
4. **It does not make the wallet-relying-party role operable.** That is blocked on the
   Member State registration and the access certificate of §1, both EXTERNAL and neither
   obtained.
5. **Every sentence about code is checkable; every sentence about an organisation is not.**
   Where a function is named, the behaviour is in `dapps/dsso` or `src/crypto/dsso` at this
   commit and is exercised by `determ-dsso selftest-core` / `selftest-assertion` /
   `selftest-pid` / `selftest-authn` or by `determ test-dsso-opaque3dh`. A gate passing is
   evidence about the code and is never a regulatory conclusion.

## 10. Cross-references

- [`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) — the mechanism, the roles, and §12's
  requirement-by-requirement mapping.
- [`DssoPidVerification.md`](DssoPidVerification.md) — the wallet-relying-party verifier.
- [`DssoAuthenticationAssurance.md`](DssoAuthenticationAssurance.md) — the two factors, the
  state machine and the limiter's bound.
- [`DssoAssertionFreshness.md`](DssoAssertionFreshness.md) — the §5 assertion's freshness
  rule.
- [`DssoThresholdOprfSoundness.md`](DssoThresholdOprfSoundness.md) — the threshold OPRF and
  the AKE.
- [`DssoG5ConstantTimeReview.md`](DssoG5ConstantTimeReview.md) — the constant-time review
  and the zeroization worklist.
- [`../SECURITY.md`](../SECURITY.md) — the S-item ledger and the gate table.
