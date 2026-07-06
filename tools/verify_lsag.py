#!/usr/bin/env python3
# Independent Python reference for the Determ LSAG linkable ring signature over NIST
# P-256 — CRYPTO-C99-SPEC.md §3.23 (input-unlinkability increment 1). The Liu-Wei-Wong
# 2004 Linkable Spontaneous Anonymous Group signature (the CryptoNote / early-Monero
# RingCT membership primitive): a signer who knows the private key x of ONE of N ring
# public keys {P_0..P_{N-1}} (P_i = x_i*G) proves membership WITHOUT revealing which,
# and publishes a KEY IMAGE I = x*H_p(P_signer) that is deterministic in the signing
# key — so spending the same note twice reveals the SAME image (double-spend / nullifier)
# while remaining unlinkable to the commitment. H_p is the RFC 9380 P256_XMD:SHA-256_
# _SSWU_RO_ hash-to-curve (same map that derives the Pedersen H generator).
#
# Signing is DETERMINISTIC (RFC-6979-style nonces derived from the key + a prefix hash
# over ring+image+message) so the bytes are reproducible and can be dual-oracle-frozen
# against the C port (src/crypto/ringsig/lsag.c).
#
# Wire: ring = N compressed pubkeys (33 B each); key image I = 33 B compressed;
#       signature = c0(32) || s_0(32) || ... || s_{N-1}(32)  = 32*(N+1) bytes.
import hashlib, json, os
import verify_pedersen as vp

N = vp.N
G = vp.G

DOM       = b"DETERM-LSAG-P256-v1"
KI_DST    = b"DETERM-LSAG-P256-keyimage-v1"
CHAL_DST  = b"DETERM-LSAG-P256-challenge-v1"
NONCE_DST = b"DETERM-LSAG-P256-nonce-v1"


def _s32(x):
    return x.to_bytes(32, "big")


def hash_to_curve(msg, dst):
    """RFC 9380 P256_XMD:SHA-256_SSWU_RO_ (count=2), same as vp.derive_h()."""
    ub = vp.expand_xmd(msg, dst, 96)
    u0 = int.from_bytes(ub[:48], "big") % vp.P
    u1 = int.from_bytes(ub[48:], "big") % vp.P
    return vp.pt_add(vp.map_sswu(u0), vp.map_sswu(u1))


def hash_to_scalar(msg, dst):
    """determ_p256_hash_to_scalar: expand_xmd L=48, big-endian, mod n."""
    return int.from_bytes(vp.expand_xmd(msg, dst, 48), "big") % N


def key_image(x, P):
    """I = x * H_p(compress(P))."""
    Hp = hash_to_curve(vp.compress(P), KI_DST)
    return vp.pt_mul(x, Hp)


def _prefix(ring, I, msg):
    h = hashlib.sha256()
    h.update(DOM)
    h.update(len(ring).to_bytes(4, "big"))
    for P in ring:
        h.update(vp.compress(P))
    h.update(vp.compress(I))
    h.update(msg)
    return h.digest()


def sign(msg, ring, x, ell):
    """Ring signature by the holder of x = privkey of ring[ell] (P_ell = x*G).
    Returns (I, sig_bytes). Deterministic."""
    n = len(ring)
    assert vp.pt_mul(x, G) == ring[ell], "x is not the private key of ring[ell]"
    Hp = [hash_to_curve(vp.compress(P), KI_DST) for P in ring]
    I = vp.pt_mul(x, Hp[ell])
    pre = _prefix(ring, I, msg)
    xb = _s32(x % N)
    # Deterministic real-index nonce alpha, and the decoy responses s_i (i != ell).
    alpha = hash_to_scalar(b"alpha" + xb + pre, NONCE_DST) or 1
    s = [0] * n
    c = [0] * n
    L = vp.pt_mul(alpha, G)
    R = vp.pt_mul(alpha, Hp[ell])
    c[(ell + 1) % n] = hash_to_scalar(pre + vp.compress(L) + vp.compress(R), CHAL_DST)
    for step in range(1, n):
        i = (ell + step) % n
        s[i] = hash_to_scalar(b"s" + xb + pre + i.to_bytes(4, "big"), NONCE_DST) or 1
        Li = vp.pt_add(vp.pt_mul(s[i], G), vp.pt_mul(c[i], ring[i]))
        Ri = vp.pt_add(vp.pt_mul(s[i], Hp[i]), vp.pt_mul(c[i], I))
        c[(i + 1) % n] = hash_to_scalar(pre + vp.compress(Li) + vp.compress(Ri), CHAL_DST)
    # Close the ring at the real index: s_ell = alpha - c_ell * x  (mod n).
    s[ell] = (alpha - c[ell] * x) % N
    sig = _s32(c[0]) + b"".join(_s32(si) for si in s)
    return I, sig


def verify(msg, ring, I, sig):
    """True iff the ring signature closes for key image I."""
    n = len(ring)
    if len(sig) != 32 * (n + 1):
        return False
    try:
        c0 = int.from_bytes(sig[:32], "big")
        s = [int.from_bytes(sig[32 + 32 * i: 64 + 32 * i], "big") for i in range(n)]
        if c0 % N == 0 or any(si % N == 0 for si in s):
            return False
        Hp = [hash_to_curve(vp.compress(P), KI_DST) for P in ring]
        pre = _prefix(ring, I, msg)
        c = c0
        for i in range(n):
            Li = vp.pt_add(vp.pt_mul(s[i], G), vp.pt_mul(c, ring[i]))
            Ri = vp.pt_add(vp.pt_mul(s[i], Hp[i]), vp.pt_mul(c, I))
            if Li is None or Ri is None:
                return False
            c = hash_to_scalar(pre + vp.compress(Li) + vp.compress(Ri), CHAL_DST)
        return c == c0
    except (ValueError, ZeroDivisionError):
        return False


def _selftest():
    # Ring of 4 keys; signer owns index 2.
    xs = [0x1111, 0x2222, 0x3333, 0x4444]
    ring = [vp.pt_mul(x, G) for x in xs]
    msg = b"spend note #7"
    ell = 2
    I, sig = sign(msg, ring, xs[ell], ell)
    assert verify(msg, ring, I, sig), "valid ring signature rejected"
    # Unlinkability sanity: I is independent of which decoys are present, but linkable
    # to the key — signing a DIFFERENT message with the same key gives the SAME image.
    I2, sig2 = sign(b"another spend", ring, xs[ell], ell)
    assert I2 == I, "key image not deterministic in the signing key (double-spend link broken)"
    assert sig2 != sig, "signature did not change with the message"
    # A different key -> a different image.
    ell3 = 0
    I3, _ = sign(msg, ring, xs[ell3], ell3)
    assert I3 != I, "different keys collided on one image"
    # Tamper: flip a byte of the signature -> reject.
    bad = bytearray(sig); bad[40] ^= 1
    assert not verify(msg, ring, I, bytes(bad)), "accepted a tampered signature"
    # Wrong message -> reject.
    assert not verify(b"different msg", ring, I, sig), "accepted a wrong-message signature"
    # Wrong key image -> reject.
    assert not verify(msg, ring, I3, sig), "accepted a wrong key image"
    # Forgery: an attacker who does NOT know any ring key cannot forge. Emulate by
    # signing with a key whose pubkey is NOT in the ring, then presenting it against
    # the honest ring — must fail.
    outsider = 0x9999
    ring_out = [vp.pt_mul(outsider, G)] + ring[1:]  # replace index 0's key
    Iout, sigout = sign(msg, ring_out, outsider, 0)
    assert not verify(msg, ring, Iout, sigout), "accepted a signature over the wrong ring"
    print("verify_lsag selftest: sign/verify + linkable key image + tamper/wrong-msg/"
          "wrong-image/wrong-ring reject OK")


def emit():
    # Deterministic vectors for the dual-oracle byte-freeze against the C port.
    vectors = []
    for name, xs, ell, msg in [
        ("lsag ring4 idx2", [0x1111, 0x2222, 0x3333, 0x4444], 2, b"spend note #7"),
        ("lsag ring2 idx0", [0xAAAA, 0xBBBB], 0, b"m"),
        ("lsag ring8 idx5", [0x10 + i for i in range(8)], 5, b"eight-member ring"),
    ]:
        ring = [vp.pt_mul(x, G) for x in xs]
        I, sig = sign(msg, ring, xs[ell], ell)
        assert verify(msg, ring, I, sig)
        vectors.append({"name": name, "type": "lsag",
                        "ring_hex": [vp.compress(P).hex() for P in ring],
                        "x_hex": _s32(xs[ell] % N).hex(), "index": ell,
                        "msg_hex": msg.hex(),
                        "image_hex": vp.compress(I).hex(), "sig_hex": sig.hex()})
    doc = {"primitive": "lsag",
           "source": ("Generated by tools/verify_lsag.py (Determ CRYPTO-C99-SPEC §3.23); "
                      "LSAG linkable ring signature over NIST P-256 (Liu-Wei-Wong 2004), "
                      "the CryptoNote membership + key-image nullifier primitive. From-scratch "
                      "Python reference (own P-256 ladder + RFC 9380 hash-to-curve)."),
           "note": ("ring = N compressed pubkeys; key image I = x*H_p(P_signer) (33 B); "
                    "signature = c0(32) || s_0..s_{N-1} (32 each). Deterministic nonces "
                    "(RFC-6979-style over key + prefix). Challenge/nonce DSTs "
                    "DETERM-LSAG-P256-{challenge,nonce,keyimage}-v1."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "lsag.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
