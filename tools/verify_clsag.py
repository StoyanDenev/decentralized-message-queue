#!/usr/bin/env python3
# Independent Python reference for the Determ CLSAG concise linkable ring signature
# over NIST P-256 — CRYPTO-C99-SPEC.md §3.23b (input-unlinkability increment 2). The
# Goodell-Noether-RandomRun 2019 "Concise Linkable Spontaneous Anonymous Group"
# signature — Monero's current RingCT membership + balance primitive. It generalises
# the §3.23 LSAG to TWO key layers signed by ONE concise ring (n+1 scalars, NOT 2n):
#
#   layer 0 (spend key):  ring key P_i,  signer secret p  (P_l = p*G),  image I = p*H_p(P_l)
#   layer 1 (commitment): ring key C_i,  signer secret z  (C_l - Coffset = z*G),
#                         auxiliary image D = z*H_p(P_l)
#
# The two layers are folded by hash-derived aggregation coefficients mu_P, mu_C into a
# single ring over the aggregated keys W_i = mu_P*P_i + mu_C*(C_i - Coffset) with the
# aggregated image  Wimg = mu_P*I + mu_C*D.  Signing knowledge of BOTH secrets is
# proven concisely; forgery against adversarial commitment keys is prevented by the
# unpredictable mu (the paper's core result). I is the linking/double-spend image;
# proving C_l - Coffset is a pure-G multiple (no H component) is exactly the RingCT
# balance statement "the pseudo-out commits to the same amount as the real input".
#
# H_p is the RFC 9380 P256_XMD:SHA-256_SSWU_RO_ hash-to-curve (same map as §3.19 H /
# §3.23 LSAG, distinct DST). Signing is DETERMINISTIC (RFC-6979-style nonces bound to
# BOTH secrets + a prefix hash) so the bytes are reproducible and dual-oracle-frozen
# against the C port (src/crypto/ringsig/clsag.c).
#
# Wire: ringP, ringC = n compressed pubkeys each (33 B); Coffset = 33 B; key image
#       I = 33 B, aux image D = 33 B; signature = c0(32) || s_0..s_{n-1}(32 each)
#       = 32*(n+1) bytes.
import hashlib, json, os
import verify_pedersen as vp

N = vp.N
P = vp.P
G = vp.G

DOM       = b"DETERM-CLSAG-P256-v1"
KI_DST    = b"DETERM-CLSAG-P256-keyimage-v1"
CHAL_DST  = b"DETERM-CLSAG-P256-challenge-v1"
NONCE_DST = b"DETERM-CLSAG-P256-nonce-v1"
AGG0_DST  = b"DETERM-CLSAG-P256-agg0-v1"
AGG1_DST  = b"DETERM-CLSAG-P256-agg1-v1"


def _s32(x):
    return x.to_bytes(32, "big")


def neg(pt):
    """The inverse point -(x, y) = (x, p - y); identity-aware. Equal to (n-1)*pt,
    which is how the C port computes it (byte-identical compressed form)."""
    if pt is None:
        return None
    return (pt[0], (P - pt[1]) % P)


def hash_to_curve(msg, dst):
    """RFC 9380 P256_XMD:SHA-256_SSWU_RO_ (count=2), same as vp.derive_h()."""
    ub = vp.expand_xmd(msg, dst, 96)
    u0 = int.from_bytes(ub[:48], "big") % P
    u1 = int.from_bytes(ub[48:], "big") % P
    return vp.pt_add(vp.map_sswu(u0), vp.map_sswu(u1))


def hash_to_scalar(msg, dst):
    """determ_p256_hash_to_scalar: expand_xmd L=48, big-endian, mod n."""
    return int.from_bytes(vp.expand_xmd(msg, dst, 48), "big") % N


def key_images(p, z, P_signer):
    """I = p*H_p(P_signer); D = z*H_p(P_signer)."""
    Hp = hash_to_curve(vp.compress(P_signer), KI_DST)
    return vp.pt_mul(p, Hp), vp.pt_mul(z, Hp)


def _agg_input(ringP, ringC, I, D, Coffset):
    # P_0..P_{n-1} || C_0..C_{n-1} || I || D || Coffset  (all 33 B compressed).
    b = b"".join(vp.compress(Q) for Q in ringP)
    b += b"".join(vp.compress(Q) for Q in ringC)
    b += vp.compress(I) + vp.compress(D) + vp.compress(Coffset)
    return b


def _agg_coeffs(ringP, ringC, I, D, Coffset):
    agg = _agg_input(ringP, ringC, I, D, Coffset)
    return hash_to_scalar(agg, AGG0_DST), hash_to_scalar(agg, AGG1_DST)


def _prefix(ringP, ringC, Coffset, I, D, msg):
    h = hashlib.sha256()
    h.update(DOM)
    h.update(len(ringP).to_bytes(4, "big"))
    for Q in ringP:
        h.update(vp.compress(Q))
    for Q in ringC:
        h.update(vp.compress(Q))
    h.update(vp.compress(Coffset))
    h.update(vp.compress(I))
    h.update(vp.compress(D))
    h.update(msg)
    return h.digest()


def _chal(pre, L, R):
    return hash_to_scalar(pre + vp.compress(L) + vp.compress(R), CHAL_DST)


def _agg_keys(ringP, ringC, Coffset, I, D, muP, muC):
    negC = neg(Coffset)
    W = [vp.pt_add(vp.pt_mul(muP, ringP[i]),
                   vp.pt_mul(muC, vp.pt_add(ringC[i], negC)))
         for i in range(len(ringP))]
    Wimg = vp.pt_add(vp.pt_mul(muP, I), vp.pt_mul(muC, D))
    return W, Wimg


def sign(msg, ringP, ringC, Coffset, p, z, ell):
    """Concise ring signature by the holder of (p, z): p = privkey of ringP[ell]
    (P_ell = p*G) and z = the commitment blinding difference (ringC[ell] - Coffset
    = z*G). Returns (I, D, sig_bytes). Deterministic."""
    n = len(ringP)
    assert len(ringC) == n, "ringP / ringC length mismatch"
    assert vp.pt_mul(p, G) == ringP[ell], "p is not the private key of ringP[ell]"
    assert vp.pt_add(ringC[ell], neg(Coffset)) == vp.pt_mul(z, G), \
        "z is not the blinding difference ringC[ell] - Coffset"
    Hp = [hash_to_curve(vp.compress(Q), KI_DST) for Q in ringP]
    I = vp.pt_mul(p, Hp[ell])
    D = vp.pt_mul(z, Hp[ell])
    muP, muC = _agg_coeffs(ringP, ringC, I, D, Coffset)
    W, Wimg = _agg_keys(ringP, ringC, Coffset, I, D, muP, muC)
    w_ell = (muP * p + muC * z) % N
    pre = _prefix(ringP, ringC, Coffset, I, D, msg)
    pb, zb = _s32(p % N), _s32(z % N)
    alpha = hash_to_scalar(b"alpha" + pb + zb + pre, NONCE_DST) or 1
    s = [0] * n
    c = [0] * n
    L = vp.pt_mul(alpha, G)
    R = vp.pt_mul(alpha, Hp[ell])
    c[(ell + 1) % n] = _chal(pre, L, R)
    for step in range(1, n):
        i = (ell + step) % n
        s[i] = hash_to_scalar(b"s" + pb + zb + pre + i.to_bytes(4, "big"), NONCE_DST) or 1
        Li = vp.pt_add(vp.pt_mul(s[i], G), vp.pt_mul(c[i], W[i]))
        Ri = vp.pt_add(vp.pt_mul(s[i], Hp[i]), vp.pt_mul(c[i], Wimg))
        c[(i + 1) % n] = _chal(pre, Li, Ri)
    # Close the ring at the real index: s_ell = alpha - c_ell * w_ell (mod n).
    s[ell] = (alpha - c[ell] * w_ell) % N
    sig = _s32(c[0]) + b"".join(_s32(si) for si in s)
    return I, D, sig


def verify(msg, ringP, ringC, Coffset, I, D, sig):
    """True iff the concise ring signature closes for key image I / aux image D."""
    n = len(ringP)
    if len(ringC) != n or len(sig) != 32 * (n + 1):
        return False
    try:
        c0 = int.from_bytes(sig[:32], "big")
        s = [int.from_bytes(sig[32 + 32 * i: 64 + 32 * i], "big") for i in range(n)]
        if c0 % N == 0 or any(si % N == 0 for si in s):
            return False
        Hp = [hash_to_curve(vp.compress(Q), KI_DST) for Q in ringP]
        muP, muC = _agg_coeffs(ringP, ringC, I, D, Coffset)
        W, Wimg = _agg_keys(ringP, ringC, Coffset, I, D, muP, muC)
        pre = _prefix(ringP, ringC, Coffset, I, D, msg)
        c = c0
        for i in range(n):
            Li = vp.pt_add(vp.pt_mul(s[i], G), vp.pt_mul(c, W[i]))
            Ri = vp.pt_add(vp.pt_mul(s[i], Hp[i]), vp.pt_mul(c, Wimg))
            if Li is None or Ri is None:
                return False
            c = _chal(pre, Li, Ri)
        return c == c0
    except (ValueError, ZeroDivisionError):
        return False


def _mk_ring(spend_keys, amounts, blindings, Hgen):
    """Build (ringP, ringC): P_i = x_i*G, C_i = a_i*Hgen + b_i*G."""
    ringP = [vp.pt_mul(x, G) for x in spend_keys]
    ringC = [vp.pt_add(vp.pt_mul(amounts[i], Hgen), vp.pt_mul(blindings[i], G))
             for i in range(len(spend_keys))]
    return ringP, ringC


def _selftest():
    Hgen = vp.derive_h()
    # Ring of 4; signer owns index 2. Real member's commitment amount a=1000.
    xs = [0x1111, 0x2222, 0x3333, 0x4444]
    amts = [10, 20, 1000, 40]
    blinds = [0x0a, 0x0b, 0x0c1d, 0x0d]
    ell = 2
    ringP, ringC = _mk_ring(xs, amts, blinds, Hgen)
    # Pseudo-out Coffset commits to the SAME amount (1000) with a fresh blinding x'.
    xprime = 0x0abc
    Coffset = vp.pt_add(vp.pt_mul(amts[ell], Hgen), vp.pt_mul(xprime, G))
    z = (blinds[ell] - xprime) % N
    p = xs[ell]
    msg = b"clsag spend note #7"
    I, D, sig = sign(msg, ringP, ringC, Coffset, p, z, ell)
    assert verify(msg, ringP, ringC, Coffset, I, D, sig), "valid CLSAG rejected"
    # Linkability: the image I is deterministic in the spend key — a DIFFERENT
    # message / different pseudo-out with the same key yields the SAME I.
    xprime2 = 0x0def
    Coffset2 = vp.pt_add(vp.pt_mul(amts[ell], Hgen), vp.pt_mul(xprime2, G))
    z2 = (blinds[ell] - xprime2) % N
    I2, _, sig2 = sign(b"another", ringP, ringC, Coffset2, p, z2, ell)
    assert I2 == I, "key image not deterministic in the spend key (double-spend link broken)"
    assert sig2 != sig, "signature did not change with message/offset"
    # A different signer (index 0), with its own self-consistent pseudo-out.
    Coff0 = vp.pt_add(vp.pt_mul(amts[0], Hgen), vp.pt_mul(0x55, G))
    z0 = (blinds[0] - 0x55) % N
    I0, _, _ = sign(msg, ringP, ringC, Coff0, xs[0], z0, 0)
    assert I0 != I, "different spend keys collided on one image"
    # Tamper: flip a signature byte -> reject.
    bad = bytearray(sig); bad[40] ^= 1
    assert not verify(msg, ringP, ringC, Coffset, I, D, bytes(bad)), "accepted a tampered signature"
    # Wrong message -> reject.
    assert not verify(b"different", ringP, ringC, Coffset, I, D, sig), "accepted wrong-message"
    # Wrong aux image D -> reject (D is bound into agg coeffs + prefix).
    Dbad = vp.pt_mul(2, D)
    assert not verify(msg, ringP, ringC, Coffset, I, Dbad, sig), "accepted a wrong aux image"
    # Wrong Coffset -> reject (bound into agg coeffs + prefix + the W_i offset).
    assert not verify(msg, ringP, ringC, Coffset2, I, D, sig), "accepted a wrong pseudo-out"
    # Balance-binding is a SOUNDNESS property, not a runtime forge: if the real
    # input commitment and Coffset differ in AMOUNT then C_l - Coffset has a
    # nonzero a*H term and NO z with C_l - Coffset = z*G exists, so an honest
    # signer cannot even construct the signature (sign()'s precondition rejects
    # it). Demonstrate the precondition fires:
    Coff_badamt = vp.pt_add(vp.pt_mul(amts[ell] + 1, Hgen), vp.pt_mul(xprime, G))
    try:
        sign(msg, ringP, ringC, Coff_badamt, p, z, ell)
        raise SystemExit("balance precondition failed to reject an amount mismatch")
    except AssertionError:
        pass
    print("verify_clsag selftest: sign/verify + linkable image + balance-binding + "
          "tamper/wrong-msg/wrong-D/wrong-offset reject OK")


def emit():
    Hgen = vp.derive_h()
    vectors = []
    cases = [
        ("clsag ring4 idx2", [0x1111, 0x2222, 0x3333, 0x4444],
         [10, 20, 1000, 40], [0x0a, 0x0b, 0x0c1d, 0x0d], 2, 0x0abc, b"clsag spend note #7"),
        ("clsag ring2 idx0", [0xAAAA, 0xBBBB],
         [7, 8], [0x21, 0x22], 0, 0x0033, b"m"),
        ("clsag ring8 idx5", [0x10 + i for i in range(8)],
         [100 + i for i in range(8)], [0x40 + i for i in range(8)], 5, 0x0777,
         b"eight-member concise ring"),
    ]
    for name, xs, amts, blinds, ell, xprime, msg in cases:
        ringP, ringC = _mk_ring(xs, amts, blinds, Hgen)
        Coffset = vp.pt_add(vp.pt_mul(amts[ell], Hgen), vp.pt_mul(xprime, G))
        z = (blinds[ell] - xprime) % N
        I, D, sig = sign(msg, ringP, ringC, Coffset, xs[ell], z, ell)
        assert verify(msg, ringP, ringC, Coffset, I, D, sig)
        vectors.append({
            "name": name, "type": "clsag",
            "ringP_hex": [vp.compress(Q).hex() for Q in ringP],
            "ringC_hex": [vp.compress(Q).hex() for Q in ringC],
            "coffset_hex": vp.compress(Coffset).hex(),
            "p_hex": _s32(xs[ell] % N).hex(), "z_hex": _s32(z % N).hex(),
            "index": ell, "msg_hex": msg.hex(),
            "image_hex": vp.compress(I).hex(), "daux_hex": vp.compress(D).hex(),
            "sig_hex": sig.hex(),
        })
    doc = {"primitive": "clsag",
           "source": ("Generated by tools/verify_clsag.py (Determ CRYPTO-C99-SPEC §3.23b); "
                      "CLSAG concise linkable ring signature over NIST P-256 (Goodell-Noether-"
                      "RandomRun 2019), Monero's RingCT membership + balance primitive. "
                      "From-scratch Python reference (own P-256 ladder + RFC 9380 hash-to-curve)."),
           "note": ("Two key layers (spend P, commitment C) folded by hash-derived "
                    "aggregation coefficients mu_P/mu_C into ONE concise ring. ringP, ringC = "
                    "n compressed pubkeys; Coffset = pseudo-out commitment; I = p*H_p(P_signer) "
                    "(link/nullifier), D = z*H_p(P_signer) (aux); signature = c0(32) || "
                    "s_0..s_{n-1} (32 each). Deterministic nonces bound to (p,z,prefix). DSTs "
                    "DETERM-CLSAG-P256-{keyimage,challenge,nonce,agg0,agg1}-v1."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "clsag.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
