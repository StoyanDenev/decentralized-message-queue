#!/usr/bin/env python3
# tools/verify_notekey.py — independent, DEPENDENCY-FREE Python oracle for the
# NC-8 recipient NOTE-KEY derivation (shielded-pool wiring, profile-keyed note
# delivery, owner-decided 2026-07-18). It reproduces the frozen scalar/pubkey a
# recipient's note key is derived to, and gates the C implementation
# (determ_p256_hash_to_scalar + the note-key derivation, being written
# separately from the SAME spec) byte-for-byte against the two committed KAT
# corpora tools/vectors/notekey_modern.json and tools/vectors/notekey_fips.json.
#
#   python3 tools/verify_notekey.py             # (re)emit both JSONs + self-verify, print PASS
#   python3 tools/verify_notekey.py --emit      # regenerate the two vector files
#   python3 tools/verify_notekey.py --verify    # verify against the committed JSONs only
#
# This oracle is PURE PYTHON on the standard library only (hashlib, json) —
# matching every other tools/verify_*.py in the tree (verify_enote.py,
# verify_pedersen.py, verify_p256_balance.py, …). It imports NO third-party
# package (no `cryptography`, no `ecdsa`): the primitives (the P-256 EC ladder +
# SEC1 compress, and the RFC 9380 expand_message_xmd used by hash_to_scalar) are
# implemented from scratch below, copied VERBATIM from the sibling oracles so a
# shared bug in the determ C stack cannot hide behind a wrapper around it. This
# is the INDEPENDENT half of a dual-oracle gate: a C port is written separately
# from the same spec, and the two must agree on every stored scalar/pubkey byte.
#
# The from-scratch routines are copied, not reinvented: the P-256 EC ladder +
# SEC1 compress from tools/verify_pedersen.py / tools/verify_enote.py, and the
# RFC 9380 §5.3 expand_message_xmd(SHA-256) from tools/verify_pedersen.py
# (expand_xmd). hash_to_scalar here is the RFC 9497 (VOPRF) HashToScalar shape,
# identical to the in-tree determ_p256_hash_to_scalar used by the balance/IPA
# oracles: hash_to_field with the P-256 group order n as the modulus, m=1, L=48,
# count=1 — i.e. int(expand_message_xmd(msg, DST, 48)) mod n.
#
# ─── EXACT CONSTRUCTION (note-key derivation) ────────────────────────────────
# The construction below mirrors the frozen spec / the C port line-for-line:
#
#   derive(ikm[32], chain_id, addr, index):
#     msg      = ikm(32)
#             || u64_be(len(chain_id)) || chain_id
#             || u64_be(len(addr))     || addr
#             || u64_be(index)
#     note_sk  = hash_to_scalar(msg, DST)          # canonical 32-byte BE scalar in [1, n)
#     note_pk  = compress( note_sk · G )           # 33-byte SEC1 compressed (0x02/0x03)
#
#   * u64_be = 8-byte big-endian; chain_id / addr are RAW byte strings (the ASCII
#     bytes of e.g. "determ-mainnet" and "alice"); index is a uint64.
#   * MODERN profile (1a): DST = b"determ-notekey-modern-v1"; ikm = an independent
#     32-byte note seed.
#   * FIPS   profile (1b): DST = b"determ-notekey-fips-v1"; ikm = the account's
#     32-byte A2 view_master_sk (the same secret verify_view_key.py / viewkey.c
#     consume). The two profiles differ ONLY in the DST (and the semantic source
#     of the IKM); the derivation is otherwise byte-identical.
#   * Fail-closed (raises) when: ikm is not 32 bytes; chain_id empty; addr empty;
#     len(chain_id) or len(addr) > 256; index outside [0, 2^64); or note_sk == 0.
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC_MODERN = os.path.join(HERE, "tools", "vectors", "notekey_modern.json")
VEC_FIPS = os.path.join(HERE, "tools", "vectors", "notekey_fips.json")

# Profile domain-separation tags (RFC 9380 DST, used directly — assumed < 256 B,
# so no DST-hashing prefix). MUST match the frozen C determ note-key DSTs.
DST_MODERN = b"determ-notekey-modern-v1"
DST_FIPS = b"determ-notekey-fips-v1"

MAX_LABEL = 256                      # max byte length of chain_id / addr
U64_MAX = (1 << 64) - 1

# ─── P-256 EC ladder + SEC1 compress (copied from tools/verify_pedersen.py) ──
# Public FIPS 186 / SEC 2 domain parameters for NIST P-256 (secp256r1).
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = (P - 3) % P
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
# Group order n. Equals the note-key modulus; hash_to_scalar reduces mod this.
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                              # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pt_mul(k, pt):
    k %= N
    r, q = None, pt
    while k:
        if k & 1:
            r = pt_add(r, q)
        q = pt_add(q, q)
        k >>= 1
    return r


def compress(pt):
    if pt is None:
        raise ValueError("cannot compress the identity")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


# ─── RFC 9380 §5.3 expand_message_xmd(SHA-256) (copied from verify_pedersen.py) ─
def expand_xmd(msg, dst, length):
    ell = -(-length // 32)
    if ell > 255 or length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd bounds exceeded")
    dst_p = dst + bytes([len(dst)])
    b0 = hashlib.sha256(b"\x00" * 64 + msg + length.to_bytes(2, "big")
                        + b"\x00" + dst_p).digest()
    bi = hashlib.sha256(b0 + b"\x01" + dst_p).digest()
    out = bi
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, bi))
                            + bytes([i]) + dst_p).digest()
        out += bi
    return out[:length]


def hash_to_scalar(msg, dst):
    """RFC 9497 HashToScalar / RFC 9380 hash_to_field with modulus = the P-256
    group order n, m=1, L=48, count=1. Identical to determ_p256_hash_to_scalar."""
    return int.from_bytes(expand_xmd(msg, dst, 48), "big") % N


# ─── note-key derivation (mirrors the frozen spec / the C port) ──────────────
def _u64_be(x):
    if not (0 <= x <= U64_MAX):
        raise ValueError("value out of uint64 range")
    return x.to_bytes(8, "big")


def note_key_message(ikm, chain_id, addr, index):
    """msg = ikm || u64_be(len(chain_id)) || chain_id || u64_be(len(addr)) ||
    addr || u64_be(index). Fail-closed on any malformed input."""
    if len(ikm) != 32:
        raise ValueError("ikm must be exactly 32 bytes")
    if len(chain_id) == 0:
        raise ValueError("chain_id must be non-empty")
    if len(addr) == 0:
        raise ValueError("addr must be non-empty")
    if len(chain_id) > MAX_LABEL:
        raise ValueError("chain_id longer than %d bytes" % MAX_LABEL)
    if len(addr) > MAX_LABEL:
        raise ValueError("addr longer than %d bytes" % MAX_LABEL)
    return (ikm
            + _u64_be(len(chain_id)) + chain_id
            + _u64_be(len(addr)) + addr
            + _u64_be(index))


def derive_note_key(ikm, chain_id, addr, index, dst):
    """Return (note_sk[32B big-endian], note_pk[33B SEC1 compressed]).
    note_sk = hash_to_scalar(msg, dst); note_pk = compress(note_sk·G)."""
    msg = note_key_message(ikm, chain_id, addr, index)
    sk = hash_to_scalar(msg, dst)
    if sk == 0:                                  # negligible; a zero key is unusable
        raise ValueError("degenerate note_sk == 0")
    note_sk = sk.to_bytes(32, "big")
    note_pk = compress(pt_mul(sk, G))
    return note_sk, note_pk


# ─── deterministic KAT inputs (shared across both profiles so the note_sk /
#     note_pk differ ONLY by the DST) ──────────────────────────────────────────
# chain_id / addr are the raw ASCII bytes of the labels; index is a uint64.
_ANON_A = "0x" + "a3f1" * 16          # 66-char anon-style address (len 66)
_ANON_B = "0x" + "deadbeef" * 8       # 66-char anon-style address (len 66)

KAT_INPUTS = [
    # (ikm(32B), chain_id, addr, index)
    (bytes([0x01] * 32), b"determ-mainnet", b"alice", 0),
    (bytes([0x02] * 32), b"determ-test", b"bob", 1),
    (bytes([0x03] * 32), b"determ-mainnet", _ANON_A.encode("ascii"), 7),
    (bytes(range(1, 33)), b"determ-mainnet", b"carol", 1 << 32),
    (bytes([0xab] * 32), b"determ-test", _ANON_B.encode("ascii"), U64_MAX),
    (bytes([0xff] * 32), b"d", b"x", 42),
]


def _vector(ikm, chain_id, addr, index, dst):
    note_sk, note_pk = derive_note_key(ikm, chain_id, addr, index, dst)
    return {
        "ikm": ikm.hex(),
        "chain_id": chain_id.hex(),
        "addr": addr.hex(),
        "index": index,
        "note_sk": note_sk.hex(),
        "note_pk": note_pk.hex(),
    }


def build_vectors(dst):
    return [_vector(ikm, cid, addr, idx, dst) for (ikm, cid, addr, idx) in KAT_INPUTS]


def _write_json(path, vectors):
    # 2-space indent, lowercase hex, deterministic LF newlines + one trailing
    # newline (matching tools/vectors/enote.json's formatting). Explicit newline
    # keeps the bytes identical on every platform (no Windows text-mode CRLF drift).
    text = json.dumps(vectors, indent=2) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def emit():
    _write_json(VEC_MODERN, build_vectors(DST_MODERN))
    _write_json(VEC_FIPS, build_vectors(DST_FIPS))


# ─── primitive KATs (gate the from-scratch code before any vector) ───────────
def _kat_p256():
    # 1·G is the SEC 2 base point; n·G = O (G has order n).
    assert compress(pt_mul(1, G)).hex() == (
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), \
        "P-256 base point compression"
    assert pt_mul(N, G) is None, "P-256 n·G == O"


def _kat_expand_xmd():
    # RFC 9380 Appendix K.1 expand_message_xmd(SHA-256) published KATs — pins the
    # copied expand_xmd (and thus hash_to_scalar) to the standard, independently
    # of any determ code.
    dst = b"QUUX-V01-CS02-with-expander-SHA256-128"
    assert expand_xmd(b"", dst, 0x20).hex() == (
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"), \
        "RFC 9380 K.1 expand_message_xmd(\"\", 32)"
    assert expand_xmd(b"abc", dst, 0x20).hex() == (
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"), \
        "RFC 9380 K.1 expand_message_xmd(\"abc\", 32)"


# ─── corpus verification against the FROZEN JSONs ────────────────────────────
def _recheck_vector(v, dst):
    """Re-derive note_sk / note_pk from a vector's inputs; return failure text
    or None. Also enforces the canonical-scalar / compressed-prefix invariants."""
    ikm = bytes.fromhex(v["ikm"])
    chain_id = bytes.fromhex(v["chain_id"])
    addr = bytes.fromhex(v["addr"])
    index = v["index"]
    note_sk, note_pk = derive_note_key(ikm, chain_id, addr, index, dst)
    sk_int = int.from_bytes(note_sk, "big")
    if not (0 < sk_int < N):
        return "note_sk not a canonical scalar in [1, n)"
    if note_pk[0] not in (0x02, 0x03):
        return "note_pk is not a 0x02/0x03 compressed point"
    if note_sk.hex() != v["note_sk"]:
        return "note_sk mismatch: got %s... want %s..." % (
            note_sk.hex()[:16], v["note_sk"][:16])
    if note_pk.hex() != v["note_pk"]:
        return "note_pk mismatch: got %s... want %s..." % (
            note_pk.hex()[:16], v["note_pk"][:16])
    return None


def verify_corpus(path, dst, label, verbose=False):
    with open(path, encoding="utf-8") as f:
        vecs = json.load(f)
    failures = []
    for i, v in enumerate(vecs):
        err = _recheck_vector(v, dst)
        if err is not None:
            failures.append("%s[%d]: %s" % (label, i, err))
        if verbose:
            print("  %s %s[%d] chain_id=%s addr=%s index=%d"
                  % ("ok  " if err is None else "FAIL", label, i,
                     bytes.fromhex(v["chain_id"]).decode("ascii", "replace"),
                     bytes.fromhex(v["addr"]).decode("ascii", "replace"),
                     v["index"]))
    return len(vecs), failures


def main():
    _kat_p256()
    _kat_expand_xmd()

    do_emit = ("--verify" not in sys.argv)       # default: emit then verify
    verify_only = "--verify" in sys.argv
    emit_only = "--emit" in sys.argv
    verbose = ("--selftest" in sys.argv) or emit_only

    if do_emit or emit_only:
        emit()

    if emit_only and not verify_only:
        # still self-verify what we just wrote (an emit that doesn't round-trip
        # is worse than useless).
        pass

    total = 0
    failures = []
    for path, dst, label in ((VEC_MODERN, DST_MODERN, "modern"),
                             (VEC_FIPS, DST_FIPS, "fips")):
        n, fails = verify_corpus(path, dst, label, verbose=verbose)
        total += n
        failures += fails

    if failures:
        for msg in failures:
            print("  DIFF %s" % msg)
        print("[verify_notekey] %d FAILURE(S) across notekey_{modern,fips}.json"
              % len(failures))
        return 1

    print("PASS: verify_notekey %d vectors (modern+fips) recomputed byte-equal "
          "through the independent pure-python oracle "
          "(P-256 + RFC 9380 expand_message_xmd / hash_to_scalar)" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
