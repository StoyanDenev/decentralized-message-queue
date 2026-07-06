#!/usr/bin/env python3
# Independent Python oracle for the Determ RingCT SPEND-STATEMENT composition over NIST
# P-256 — CRYPTO-C99-SPEC.md §3.23c (input-unlinkability increment 3, LIBRARY-only).
# It stitches the shipped privacy layers into ONE end-to-end confidential + unlinkable
# spend statement, WITHOUT touching consensus:
#
#   * §3.23b CLSAG  — proves the spender owns ONE of n ring notes and that the pseudo-out
#                     Coffset_H commits to the SAME amount as their real input, hiding which
#                     (input-unlinkable); publishes the key image I (double-spend nullifier).
#                     CLSAG commitments are RingCT-convention: amount on H, blinding on G
#                     (the balance C_l - Coffset = z*G lands the blinding-difference on G).
#   * §3.23c TRANSPOSE — the reconciliation this increment adds. CLSAG is amount-on-H;
#                     the §3.19/§3.22c range+balance stack is amount-on-G. A commitment-
#                     transposition proof (a Schnorr AND-proof with a SHARED value response)
#                     certifies a value-on-H commitment C_H = v*H + a*G and a value-on-G
#                     commitment C_G = v*G + b*H hide the SAME amount v — the bridge between
#                     the two conventions.
#   * §3.22c DCT1   — the amount-on-G confidential-transfer bundle: proves Coffset_G's amount
#                     = Sum(output amounts) + fee (balance) and each output in [0, 2^n) (range).
#
# Composition: CLSAG(Coffset_H) -> TRANSPOSE(Coffset_H == Coffset_G in amount) -> DCT1(C_in =
# [Coffset_G]). The amount flows from a hidden ring member, through the transposed pseudo-out,
# to hidden in-range outputs — all amounts secret, the input unlinkable, value conserved.
# NAIVELY sharing Coffset across the two conventions FAILS (the H-amount != the G-amount); the
# transpose proof is exactly what makes the composition sound.
#
# The transpose proof is the only NEW crypto and is dual-oracle byte-frozen against the C port
# (src/crypto/ringsig/ringct_spend.c). CLSAG + DCT1 are reused verbatim.
#
# Wire (transpose proof, 162 B): A_H(33) || A_G(33) || sv(32) || sa(32) || sb(32).
import hashlib, json, os, sys
import verify_pedersen as vp
import verify_clsag as clsag
import verify_bp_agg_rangeproof as agg
import verify_p256_balance as bal
import verify_ctx_bundle as ctxb

N = vp.N
G = vp.G
H = vp.derive_h()

CHAL_T = b"DETERM-RINGCT-TRANSPOSE-P256-challenge-v1"
NONCE_T = b"DETERM-RINGCT-TRANSPOSE-P256-nonce-v1"


def _s32(x):
    return (x % N).to_bytes(32, "big")


def _hts(msg, dst):
    return int.from_bytes(vp.expand_xmd(msg, dst, 48), "big") % N


# ── §3.23c commitment-transposition proof ───────────────────────────────────────
def transpose_commitments(v, a, b):
    """C_H = v*H + a*G (RingCT/CLSAG convention); C_G = v*G + b*H (§3.19 convention)."""
    C_H = vp.pt_add(vp.pt_mul(v, H), vp.pt_mul(a, G))
    C_G = vp.pt_add(vp.pt_mul(v, G), vp.pt_mul(b, H))
    return C_H, C_G


def _transpose_challenge(C_H, C_G, A_H, A_G):
    msg = vp.compress(C_H) + vp.compress(C_G) + vp.compress(A_H) + vp.compress(A_G)
    return _hts(msg, CHAL_T)


def transpose_prove(v, a, b):
    """Prove C_H = v*H + a*G and C_G = v*G + b*H hide the SAME v (deterministic).
    Returns (C_H, C_G, proof_bytes)."""
    C_H, C_G = transpose_commitments(v, a, b)
    vb, ab, bb = _s32(v), _s32(a), _s32(b)
    pre = vp.compress(C_H) + vp.compress(C_G)
    rv = _hts(b"rv" + vb + ab + bb + pre, NONCE_T) or 1
    ra = _hts(b"ra" + vb + ab + bb + pre, NONCE_T) or 1
    rb = _hts(b"rb" + vb + ab + bb + pre, NONCE_T) or 1
    A_H = vp.pt_add(vp.pt_mul(rv, H), vp.pt_mul(ra, G))   # rv*H + ra*G
    A_G = vp.pt_add(vp.pt_mul(rv, G), vp.pt_mul(rb, H))   # rv*G + rb*H
    c = _transpose_challenge(C_H, C_G, A_H, A_G)
    sv = (rv + c * v) % N
    sa = (ra + c * a) % N
    sb = (rb + c * b) % N
    proof = vp.compress(A_H) + vp.compress(A_G) + _s32(sv) + _s32(sa) + _s32(sb)
    return C_H, C_G, proof


def transpose_verify(C_H, C_G, proof):
    """True iff `proof` (162 B) certifies C_H (value-on-H) and C_G (value-on-G) hide the
    same amount. The SHARED response sv in BOTH equations is what binds the two amounts."""
    if len(proof) != 162:
        return False
    try:
        A_H = vp.decompress(proof[0:33])
        A_G = vp.decompress(proof[33:66])
        sv = int.from_bytes(proof[66:98], "big")
        sa = int.from_bytes(proof[98:130], "big")
        sb = int.from_bytes(proof[130:162], "big")
        if any(s >= N for s in (sv, sa, sb)):
            return False
        c = _transpose_challenge(C_H, C_G, A_H, A_G)
        # sv*H + sa*G == A_H + c*C_H
        lhs1 = vp.pt_add(vp.pt_mul(sv, H), vp.pt_mul(sa, G))
        rhs1 = vp.pt_add(A_H, vp.pt_mul(c, C_H))
        # sv*G + sb*H == A_G + c*C_G
        lhs2 = vp.pt_add(vp.pt_mul(sv, G), vp.pt_mul(sb, H))
        rhs2 = vp.pt_add(A_G, vp.pt_mul(c, C_G))
        return lhs1 == rhs1 and lhs2 == rhs2
    except (ValueError, ZeroDivisionError):
        return False


# ── the DCT1 bundle for a SINGLE value-on-G input (the transposed pseudo-out) ────
def build_single_input_bundle(A, rG, v_out, r_out, n_bits, fee, rnd):
    """A DCT1 bundle with n_in=1, C_in = [A*G + rG*H] (value-on-G), m outputs.
    Requires A == sum(v_out) + fee. Reuses ctxb's serialization + agg/bal oracles."""
    assert A == sum(v_out) + fee, "unbalanced demo inputs"
    m = len(v_out)
    C_in_pt = vp.commit_pt(A, rG)                       # A*G + rG*H (value-on-G)
    C_out_pts = [vp.commit_pt(v, r) for v, r in zip(v_out, r_out)]
    C_in_bytes = vp.compress(C_in_pt)
    C_out_bytes = b"".join(vp.compress(p) for p in C_out_pts)
    # aggregated range proof over the m outputs; gammas = r_out so V == C_out.
    pf = agg.prove(list(v_out), list(r_out), n_bits, rnd)
    assert b"".join(vp.compress(V) for V in pf["Vs"]) == C_out_bytes, "V != C_out"
    assert agg.verify(pf, m, n_bits), "agg range proof self-verify failed"
    agg_bytes = ctxb.serialize_agg_rangeproof(pf, m, n_bits)
    # balance proof: excess E = C_in - sum(C_out) - fee*G = (rG - sum(r_out))*H.
    E = bal.balance_excess([C_in_pt], C_out_pts, fee)
    x = (rG - sum(r_out)) % N
    assert E == vp.pt_mul(x, bal.H()), "balanced excess not x*H"
    k = 0x6d2c
    bproof = bal.balance_prove(E, x, k)
    assert bal.balance_verify(E, bproof), "balance proof self-verify failed"
    bundle = bytearray(b"DCT1")
    bundle += bytes([1, m, n_bits])
    bundle += int(fee).to_bytes(8, "big")
    bundle += C_in_bytes
    bundle += C_out_bytes
    bundle += agg_bytes
    bundle += bproof
    return bytes(bundle), C_in_pt


# ── the full RingCT spend statement ──────────────────────────────────────────────
def build_spend(xs, amts, blinds, ell, xprime, rG, v_out, r_out, n_bits, fee, msg, rnd):
    """CLSAG (value-on-H) -> transpose -> DCT1 (value-on-G). Returns a dict of all parts."""
    # (1) CLSAG side: ring commitments value-on-H, pseudo-out Coffset_H = A*H + xprime*G.
    ringP, ringC = clsag._mk_ring(xs, amts, blinds, H)   # C_i = amt_i*H + blind_i*G
    A = amts[ell]
    Coffset_H = vp.pt_add(vp.pt_mul(A, H), vp.pt_mul(xprime, G))
    z = (blinds[ell] - xprime) % N
    I, D, sig = clsag.sign(msg, ringP, ringC, Coffset_H, xs[ell], z, ell)
    assert clsag.verify(msg, ringP, ringC, Coffset_H, I, D, sig), "CLSAG self-verify failed"

    # (2) transpose: Coffset_H (v=A, a=xprime) <-> Coffset_G (v=A, b=rG).
    C_H, C_G, tproof = transpose_prove(A, xprime, rG)
    assert C_H == Coffset_H, "transpose C_H != CLSAG Coffset_H"
    assert transpose_verify(C_H, C_G, tproof), "transpose self-verify failed"

    # (3) DCT1 bundle over the single transposed input C_G.
    bundle, C_in_pt = build_single_input_bundle(A, rG, v_out, r_out, n_bits, fee, rnd)
    assert C_in_pt == C_G, "bundle C_in != transposed Coffset_G"

    return {
        "ringP": ringP, "ringC": ringC, "coffset_H": Coffset_H, "coffset_G": C_G,
        "I": I, "D": D, "clsag_sig": sig, "transpose_proof": tproof,
        "bundle": bundle, "msg": msg,
    }


def _verify_bundle_balance_and_link(bundle, coffset_G):
    """Parse the single-input DCT1 bundle from bytes, check C_in[0] == coffset_G, and
    verify the Schnorr balance proof against the recomputed excess. (The aggregated range
    proof is verified at build time; the C determ_ringct_spend_verify re-checks it in full
    via determ_ctx_bundle_verify.)"""
    try:
        if bundle[:4] != b"DCT1":
            return False
        n_in, m, n = bundle[4], bundle[5], bundle[6]
        if n_in != 1:
            return False
        fee = int.from_bytes(bundle[7:15], "big")
        off = 15
        C_in = vp.decompress(bundle[off:off + 33])
        if vp.compress(C_in) != vp.compress(coffset_G):
            return False
        off += 33
        C_out = [vp.decompress(bundle[off + i * 33: off + (i + 1) * 33]) for i in range(m)]
        off += m * 33
        agg_len = 228 + (ctxb._ipa_rounds(m * n) * 66 + 64)
        off += agg_len
        bproof = bundle[off:off + 65]
        off += 65
        if off != len(bundle):
            return False
        E = bal.balance_excess([C_in], C_out, fee)
        return bal.balance_verify(E, bproof)
    except (ValueError, ZeroDivisionError, IndexError):
        return False


def spend_verify(s):
    """Independent end-to-end check (mirrors the C determ_ringct_spend_verify): CLSAG
    closes AND the transpose bridges coffset_H<->coffset_G AND the DCT1 bundle balances
    against C_in == coffset_G."""
    ok = clsag.verify(s["msg"], s["ringP"], s["ringC"], s["coffset_H"], s["I"], s["D"], s["clsag_sig"])
    ok = ok and transpose_verify(s["coffset_H"], s["coffset_G"], s["transpose_proof"])
    ok = ok and _verify_bundle_balance_and_link(s["bundle"], s["coffset_G"])
    return ok


# ── demo parameters (shared by self-test + emit + the C test) ────────────────────
XS = [0x1111, 0x2222, 0x3333, 0x4444]
AMTS = [5, 9, 3, 12]          # real member (ell=2) amount A = 3
BLINDS = [0x0a1, 0x0b2, 0x0c3, 0x0d4]
ELL = 2
XPRIME = 0x0abc               # pseudo-out blinding on G (value-on-H side)
RG = 0x0d1f                   # pseudo-out blinding on H (value-on-G side)
V_OUT = [1, 1]                # outputs sum 2 = A(3) - fee(1)
R_OUT = [0x211, 0x322]
N_BITS = 4
FEE = 1
MSG = b"ringct spend note #7"


def _demo_rnd():
    nm = len(V_OUT) * N_BITS
    return {"alpha": 17 % N, "rho": 19 % N,
            "sL": [(31 + 7 * i) % N for i in range(nm)],
            "sR": [(41 + 11 * i) % N for i in range(nm)],
            "tau1": 23 % N, "tau2": 29 % N}


def build_demo():
    return build_spend(XS, AMTS, BLINDS, ELL, XPRIME, RG, V_OUT, R_OUT, N_BITS, FEE, MSG, _demo_rnd())


def _selftest():
    # (a) transpose proof standalone.
    C_H, C_G, pf = transpose_prove(3, 0xabc, 0xd1f)
    assert transpose_verify(C_H, C_G, pf), "honest transpose rejected"
    # different amount on the G side -> the SAME proof must not verify.
    C_G_bad = vp.pt_add(vp.pt_mul(4, G), vp.pt_mul(0xd1f, H))
    assert not transpose_verify(C_H, C_G_bad, pf), "accepted a transpose to a DIFFERENT amount"
    # tamper a response byte -> reject.
    bad = bytearray(pf); bad[70] ^= 1
    assert not transpose_verify(C_H, C_G, bytes(bad)), "accepted a tampered transpose proof"

    # (b) full spend composition.
    s = build_demo()
    assert spend_verify(s), "honest RingCT spend rejected"
    # The bridge is load-bearing: an honest CLSAG proof binds amount A on H, an honest
    # DCT1 bundle binds amount A on G, but ONLY the transpose proof certifies those are the
    # same A. Reusing the honest transpose proof against a wrong-amount C_G (A+1 on G) fails.
    C_G_wrong = vp.pt_add(vp.pt_mul(AMTS[ELL] + 1, G), vp.pt_mul(RG, H))
    assert not transpose_verify(s["coffset_H"], C_G_wrong, s["transpose_proof"]), \
        "bridge failed to catch an amount mismatch"
    # tamper the CLSAG sig -> whole spend rejects.
    s2 = dict(s); bad_sig = bytearray(s["clsag_sig"]); bad_sig[40] ^= 1
    s2["clsag_sig"] = bytes(bad_sig)
    assert not spend_verify(s2), "spend accepted a tampered CLSAG"
    # tamper the transpose proof -> whole spend rejects.
    s3 = dict(s); bad_t = bytearray(s["transpose_proof"]); bad_t[70] ^= 1
    s3["transpose_proof"] = bytes(bad_t)
    assert not spend_verify(s3), "spend accepted a tampered transpose"
    # tamper the bundle -> whole spend rejects.
    s4 = dict(s); bad_b = bytearray(s["bundle"]); bad_b[-1] ^= 1
    s4["bundle"] = bytes(bad_b)
    assert not spend_verify(s4), "spend accepted a tampered bundle"
    print("verify_ringct_spend selftest: transpose (honest/wrong-amount/tamper) + full "
          "CLSAG->transpose->DCT1 compose + reject-on-any-layer-tamper OK")


def emit():
    s = build_demo()
    doc = {
        "primitive": "ringct_spend",
        "source": ("Generated by tools/verify_ringct_spend.py (Determ CRYPTO-C99-SPEC §3.23c); "
                   "the library-only RingCT spend-statement composition — CLSAG (input "
                   "membership + balance, value-on-H) -> a commitment-transposition proof "
                   "(the value-on-H <-> value-on-G bridge) -> the §3.22c DCT1 bundle (range + "
                   "balance, value-on-G). Only the transpose proof is new crypto; CLSAG + DCT1 "
                   "are reused. From-scratch Python reference."),
        "note": ("transpose proof (162 B) = A_H(33) || A_G(33) || sv(32) || sa(32) || sb(32); "
                 "proves C_H = v*H + a*G and C_G = v*G + b*H share v via a shared response sv. "
                 "spend = CLSAG sig + transpose + DCT1 bundle; determ_ringct_spend_verify checks "
                 "all three plus the structural links coffset_H==CLSAG pseudo-out and "
                 "coffset_G==bundle C_in[0]."),
        "vector": {
            "name": "ringct spend ring4 idx2 (A=3 -> out[1,1] fee1)",
            "ringP_hex": [vp.compress(P).hex() for P in s["ringP"]],
            "ringC_hex": [vp.compress(C).hex() for C in s["ringC"]],
            "coffset_H_hex": vp.compress(s["coffset_H"]).hex(),
            "coffset_G_hex": vp.compress(s["coffset_G"]).hex(),
            "image_hex": vp.compress(s["I"]).hex(),
            "daux_hex": vp.compress(s["D"]).hex(),
            "msg_hex": s["msg"].hex(),
            "clsag_sig_hex": s["clsag_sig"].hex(),
            "transpose_proof_hex": s["transpose_proof"].hex(),
            "bundle_hex": s["bundle"].hex(),
            "bundle_len": len(s["bundle"]),
        },
    }
    out = os.path.join(os.path.dirname(__file__), "vectors", "ringct_spend.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (transpose=%dB bundle=%dB)"
          % (out, len(s["transpose_proof"]), len(s["bundle"])))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
