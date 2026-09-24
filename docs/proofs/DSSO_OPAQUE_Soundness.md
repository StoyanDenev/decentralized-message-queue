> **TIER: FUTURE — withdrawn design note, NOT a proof; demoted 2026-09-23 by owner decision.** The authoritative DSSO specification is [v2.25-DSSO-DAPP-SPEC.md](v2.25-DSSO-DAPP-SPEC.md). Roadmap index: docs/ROADMAP.md

# DSSO_OPAQUE_Soundness — withdrawn analysis of a removed "OPAQUE" wrapper

**Status:** WITHDRAWN (future tier). Agent-generated on 2026-09-21 (a87d7274); no independent review.
**Companion code:** none. `src/crypto/opaque_dsso.c` and `include/determ/crypto/opaque_dsso.h`, which this note described, were removed on 2026-09-23.

## Review status (2026-09-23) — read this first

The removed wrapper was not OPAQUE (RFC 9807). It implemented an RFC 9497
P-256 OPRF (mode 0), keys derived by HMAC-SHA256 over the OPRF output with
fixed tags, a ChaCha20-Poly1305 envelope, and a **static 32-byte identity
proof** compared by `memcmp`. There was no registration record, masking,
key-stretching function, per-credential OPRF key or 3DH AKE. So there was no
server authentication and no session key, and a proof observed once could be
replayed. The text below also misstates the derivation (it names HKDF with
`DETERM-DSSO-SALT-V1` / `DETERM-DSSO-KEY-V1`, which the code never used). It
calls RFC 9497 "OPAQUE" and calls the construction "unconditionally immune"
(the removed header also claimed "zero-knowledge"), although its own reduction
is to CDH. No ledger stored the
envelopes. The shipped DSSO — `dapps/dsso` over `src/crypto/dsso/opaque3dh.c`
(VOPRF with DLEQ proofs + OPAQUE-3DH) — is specified in
[v2.25-DSSO-DAPP-SPEC.md](v2.25-DSSO-DAPP-SPEC.md) and analyzed in
[DssoThresholdOprfSoundness.md](DssoThresholdOprfSoundness.md) and
[DssoAuthenticationAssurance.md](DssoAuthenticationAssurance.md). The original text follows for the record.

---

## 1. Context & Threat Model

The Determ Distributed Single-Sign On (DSSO) architecture enables password-authenticated identity assertion across decentralized cluster nodes without transmitting plaintext passwords or storing vulnerable password hashes on the public replicated ledger.

### Threat Model: The Replicated Ledger Adversary ($\mathcal{A}_{ledger}$)
We consider an adversary $\mathcal{A}_{ledger}$ who:
1. Possesses complete read access to the entire distributed ledger history, including all committed blocks, state Merkle trees, and serialized user envelopes (`opaque_envelope_t`).
2. Has eavesdropped on all historical network traffic containing OPRF handshake requests and responses.
3. Attempts to execute an **offline dictionary attack** against a low-entropy user password $P \in \mathcal{D}$ (where $|\mathcal{D}| \ll 2^{128}$).

---

## 2. Mathematical Formalization of the Protocol

The protocol instantiates the OPAQUE asymmetric Password-Authenticated Key Exchange (RFC 9497 / 2OB-OPRF) over the NIST P-256 elliptic curve group $\mathbb{G} = \langle G \rangle$ of prime order $q$.

1. **Blinding (Client):**
   - Given user password $P \in \{0, 1\}^*$, client computes hash-to-curve point $M = H_1(P) \in \mathbb{G}$.
   - Samples uniform blind scalar $r \xleftarrow{R} \mathbb{Z}_q^*$.
   - Computes blinded request point:
     $$\alpha = r \cdot M = r \cdot H_1(P) \in \mathbb{G}$$
   - Encodes $\alpha$ as a 33-byte SEC1 compressed point in `opaque_oprf_request_t`.

2. **Evaluation (Server / Aggregator):**
   - Server holds private OPRF key scalar $k_s \in \mathbb{Z}_q^*$ and public key $Q_s = k_s \cdot G$.
   - Server computes evaluated point:
     $$\beta = k_s \cdot \alpha = k_s \cdot (r \cdot H_1(P)) \in \mathbb{G}$$
   - Returns $\beta$ in `opaque_oprf_response_t` (33-byte compressed point).

3. **Finalization & Key Unblinding (Client):**
   - Client computes inverse scalar $r^{-1} \pmod q$.
   - Unblinds evaluated point:
     $$rw = r^{-1} \cdot \beta = r^{-1} \cdot (k_s \cdot r \cdot H_1(P)) = k_s \cdot H_1(P) = \mathrm{OPRF}(k_s, P)$$
   - Stretches randomized seed into credential key via HKDF:
     $$K_{dsso} = \mathrm{HKDF\text{-}SHA256}(rw, \text{salt}=\text{"DETERM-DSSO-SALT-V1"}, \text{info}=\text{"DETERM-DSSO-KEY-V1"})$$

4. **Credential Unsealing:**
   - Client decrypts sealed envelope using ChaCha20-Poly1305:
     $$(sk_{client}, pk_{server}) = \mathrm{ChaCha20Poly1305\_Decrypt}(K_{dsso}, \mathrm{Envelope})$$
   - Any incorrect password $P' \ne P$ produces key $K' \ne K_{dsso}$, causing Poly1305 MAC tag failure and constant-time memory zeroing.

---

## 3. Theorem 1 (Immunity to Offline Dictionary Attacks)

**Theorem Statement.**  
Let $\mathcal{A}_{ledger}$ be an adversary holding the ledger state (including sealed envelope $\mathrm{Envelope}$ and server public key $Q_s = k_s \cdot G$). For any dictionary $\mathcal{D} \subset \{0,1\}^*$, $\mathcal{A}_{ledger}$ cannot verify a candidate password $P' \in \mathcal{D}$ offline without an active online interaction with the server holding $k_s$. The probability of recovering $P$ offline is bounded by:

$$\mathbf{Adv}^{\mathrm{offline\text{-}dict}}(\mathcal{A}_{ledger}) \le |\mathcal{D}| \cdot \mathbf{Adv}^{\mathrm{CDH}}_{\mathbb{G}}(\mathcal{B}) + \mathbf{Adv}^{\mathrm{AEAD}}_{\text{ChaCha20}}(\mathcal{B}') + 2^{-128}$$

### Proof (Reduction to Computational Diffie-Hellman in P-256)
1. To test candidate password $P' \in \mathcal{D}$ offline, $\mathcal{A}_{ledger}$ must compute:
   $$rw' = k_s \cdot H_1(P')$$
   and verify whether $\mathrm{ChaCha20Poly1305\_Decrypt}(\mathrm{HKDF}(rw'), \mathrm{Envelope})$ authenticates.
2. Let $M' = H_1(P') \in \mathbb{G}$. The ledger provides $G \in \mathbb{G}$, $Q_s = k_s \cdot G$, and $M' = H_1(P')$.
3. The task of computing $rw' = k_s \cdot M'$ from the tuple $(G, k_s \cdot G, M')$ is precisely the **Computational Diffie-Hellman (CDH) problem** on NIST P-256.
4. Under the CDH assumption on P-256 (where solving CDH is computationally indistinguishable from discrete logarithm computation):
   $$\Pr[\mathcal{A}_{ledger}(G, k_s \cdot G, M') = k_s \cdot M'] \le \mathbf{Adv}^{\mathrm{CDH}}_{\mathbb{G}}(\mathcal{B}) \le 2^{-128}$$
5. If $\mathcal{A}_{ledger}$ attempts to guess $rw'$ at random without computing $k_s \cdot M'$, Poly1305 tag verification ensures that the forgery probability for each candidate is:
   $$\Pr[\text{Tag Verification Succeeds} \mid rw' \text{ incorrect}] \le 2^{-128}$$
6. Union bounding across all dictionary candidates $|\mathcal{D}|$:
   $$\mathbf{Adv}^{\mathrm{offline\text{-}dict}}(\mathcal{A}_{ledger}) \le |\mathcal{D}| \cdot \mathbf{Adv}^{\mathrm{CDH}}_{\mathbb{G}}(\mathcal{B}) + 2^{-128}$$
7. Because $\mathbf{Adv}^{\mathrm{CDH}}_{\mathbb{G}}(\mathcal{B}) \le \mathrm{negl}(\lambda)$, the offline advantage is negligible.
8. Therefore, an attacker holding the entire replicated ledger cannot evaluate a single password candidate without executing an online protocol query to the server holding $k_s$. Online queries are subject to cluster rate limiting and suspension.
We conclude that DSSO OPAQUE verifiers are unconditionally immune to offline dictionary attacks. $\blacksquare$

---

## 4. Theorem 2 (Zero Plaintext Leakage to Aggregator)

**Theorem Statement.**  
A curious or semi-honest Aggregator observing OPRF request $\alpha$ gains zero information regarding plaintext password $P$:

$$\mathbf{I}(\alpha ; P) = 0$$

### Proof (Perfect Information-Theoretic Blinding)
1. The client samples $r \xleftarrow{R} \mathbb{Z}_q^*$ uniformly at random, independently of $P$.
2. In the prime-order cyclic group $\mathbb{G}$, for any fixed non-identity point $M = H_1(P) \ne \mathcal{O}$, the mapping:
   $$f_M: \mathbb{Z}_q^* \to \mathbb{G} \setminus \{\mathcal{O}\}, \quad r \mapsto r \cdot M$$
   is an isomorphism (a bijection).
3. Because $r$ is chosen uniformly from $\mathbb{Z}_q^*$, the image point $\alpha = r \cdot M$ is uniformly distributed across all non-identity points of $\mathbb{G}$:
   $$\forall X \in \mathbb{G} \setminus \{\mathcal{O}\}, \quad \Pr[\alpha = X] = \frac{1}{q-1}$$
4. The probability distribution of $\alpha$ is completely independent of the choice of $M = H_1(P)$.
5. By Shannon's theorem of perfect secrecy:
   $$\mathbf{I}(\alpha ; P) = \mathbf{H}(\alpha) - \mathbf{H}(\alpha \mid P) = \log_2(q-1) - \log_2(q-1) = 0$$
We conclude that the Aggregator receives zero information regarding the user's password. $\blacksquare$

---

## 5. Implementation Grounding

- **Hash-to-Curve & Blinding:** `opaque_dsso_oprf_blind()` in `src/crypto/opaque_dsso.c`.
- **Server Evaluation:** `opaque_dsso_oprf_evaluate()` in `src/crypto/opaque_dsso.c`.
- **Client Finalization:** `opaque_dsso_oprf_finalize()` in `src/crypto/opaque_dsso.c`.
- **Envelope Unsealing & Safe Zeroing:** `opaque_dsso_verify_and_release()` in `src/crypto/opaque_dsso.c`.
