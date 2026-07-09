#!/usr/bin/env python3
# tools/verify_view_key.py — independent Python reference for the A1 per-epoch
# view-key derivation (pre-launch register A1, ratified 2026-07-09: Option C).
# This is the python-prove-first groundwork: the mapping below is reviewed and
# frozen BEFORE the C implementation exists, because the formula is permanent
# once accounts exist.
#
#   python tools/verify_view_key.py            # verify the committed corpus
#   python tools/verify_view_key.py --write    # (re)generate the corpus
#                                              # (--emit accepted as an alias,
#                                              #  matching verify_pqauth.py)
#
# ─── Exact RFC 5869 mapping (resolves the spec shorthand) ────────────────────
#
# Spec shorthand (V2-DESIGN.md v2.22 / PRE-LAUNCH-DECISIONS.md A1):
#     vk_epoch_n = HKDF(view_master_sk, "VK" || chain_id || addr || epoch_n)
#
# Resolved to RFC 5869 HKDF-SHA-256 (the shipped determ_hkdf_sha256 in
# include/determ/crypto/sha2/sha2.h — salt, ikm, info parameter order, SHA-256):
#
#     IKM  = view_master_sk                  (exactly 32 bytes, else ERROR)
#     salt = "determ-view-key-v1"            (18 ASCII bytes, no NUL)
#     info = len64_be(chain_id) || chain_id
#         || len64_be(addr)     || addr
#         || epoch_u64_be                    (fixed-width 8-byte big-endian)
#     L    = 32                              (one SHA-256 expand block)
#
#     vk_epoch_n = HKDF-Expand(HKDF-Extract(salt, IKM), info, 32)
#
# Rationale, per repo convention (each point verifiable in-tree):
#
#  * salt as the versioned DST. The shorthand's "VK" tag becomes a full
#    domain-separation constant in the repo's established style — lowercase
#    "determ-<feature>-v1" ("determ-unshield-v1" in
#    include/determ/chain/shielded.hpp, "determ-pqtx-v1" in src/crypto/
#    pqauth.cpp). RFC 5869 salt keys the Extract HMAC, so the tag separates
#    this KDF from every other HKDF use of the same master secret, and the
#    "-v1" suffix gives a clean upgrade path (a future v2 derivation cannot
#    collide with v1 outputs).
#
#  * Big-endian, len64-prefixed info. Preliminaries §1.3 mandates big-endian
#    multi-byte integers in all hash inputs (SHA256Builder::append(uint64_t)
#    in src/crypto/sha256.cpp is BE; gated by `determ test-sha256`). The
#    length prefix is u64-of-length BEFORE each variable-width string —
#    byte-identical to unshield_spend_ctx_hash in shielded.hpp
#    (b.append(u64(s.size())); b.append(s)). This kills concatenation
#    ambiguity: ("ab","c") and ("a","bc") encode differently, so distinct
#    (chain_id, addr) pairs can never alias (asserted in self_test below,
#    and pinned as vector pair in the corpus).
#
#  * epoch as fixed-width u64 BE, no length prefix. Fixed-width fields need
#    no prefix (same as nonce/amount in unshield_spend_ctx_hash). Epochs are
#    unbounded counters -> u64.
#
#  * L = 32: one expand block, matches the 32-byte symmetric-key size used
#    by the v2.22 amount-AEAD layer.
#
#  * ERROR edges (fail closed, never derive a weak/ambiguous key):
#      - view_master_sk length != 32   -> ValueError
#      - empty addr                    -> ValueError (DECIDED: an addr-less
#        view key has no owner; deriving one would create an "anonymous"
#        key that any integration bug could silently fall into)
#      - empty chain_id                -> ValueError (same reasoning: a
#        chain-less key would be replayable across networks)
#      - epoch outside [0, 2^64)      -> ValueError
#
# The HKDF-SHA-256 below is implemented from scratch on stdlib hashlib/hmac
# (RFC 5869 extract-then-expand) and gated against RFC 5869 Appendix A test
# cases 1 and 2 before anything else runs — an independent oracle for the C
# determ_hkdf_sha256, not a wrapper around it.
import hashlib, hmac, json, os, sys

HERE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "view_key.json")

DST = b"determ-view-key-v1"          # salt; must match the C constant byte-for-byte
VK_LEN = 32

# ─── RFC 5869 HKDF-SHA-256, from scratch ─────────────────────────────────────
def hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 32          # RFC 5869 §2.2: default salt = HashLen zeros
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    if length > 255 * 32:
        raise ValueError("HKDF-SHA256 output limit is 255*32 bytes")
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

def hkdf(salt, ikm, info, length):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)

# ─── the A1 derivation ───────────────────────────────────────────────────────
def len64_be(n):
    return n.to_bytes(8, "big")

def view_key_info(chain_id, addr, epoch):
    """The exact HKDF `info` bytes. chain_id/addr are UTF-8 strings."""
    cid, adr = chain_id.encode("utf-8"), addr.encode("utf-8")
    if not cid:
        raise ValueError("empty chain_id rejected (cross-network replay)")
    if not adr:
        raise ValueError("empty addr rejected (ownerless view key)")
    if not (0 <= epoch < 2 ** 64):
        raise ValueError("epoch out of u64 range")
    return (len64_be(len(cid)) + cid +
            len64_be(len(adr)) + adr +
            epoch.to_bytes(8, "big"))

def derive_view_key(view_master_sk, chain_id, addr, epoch):
    """vk_epoch_n = HKDF-SHA256(salt=DST, ikm=view_master_sk, info, L=32)."""
    if len(view_master_sk) != 32:
        raise ValueError("view_master_sk must be exactly 32 bytes")
    return hkdf(DST, view_master_sk, view_key_info(chain_id, addr, epoch), VK_LEN)

# ─── self-test: RFC 5869 Appendix A KATs + the mapping's own invariants ──────
def self_test():
    # RFC 5869 A.1 (basic test case with SHA-256)
    ikm  = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk  = hkdf_extract(salt, ikm)
    assert prk.hex() == ("077709362c2e32df0ddc3f0dc47bba63"
                         "90b6c73bb50f9c3122ec844ad7c2b3e5"), "RFC A.1 PRK"
    assert hkdf_expand(prk, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"), "RFC A.1 OKM"

    # RFC 5869 A.2 (longer inputs/outputs)
    ikm  = bytes(range(0x00, 0x50))
    salt = bytes(range(0x60, 0xb0))
    info = bytes(range(0xb0, 0x100))
    assert hkdf(salt, ikm, info, 82).hex() == (
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"), "RFC A.2 OKM"

    sk = bytes(range(32))

    # rotation property: adjacent epochs differ
    assert derive_view_key(sk, "determ-mainnet", "alice", 0) != \
           derive_view_key(sk, "determ-mainnet", "alice", 1), "epoch rotation"

    # concatenation-ambiguity: ("ab","c") vs ("a","bc") must differ — this is
    # why the info fields are length-prefixed. Checked at BOTH layers: the raw
    # info bytes and the derived key.
    assert view_key_info("ab", "c", 9) != view_key_info("a", "bc", 9), \
        "len-prefix ambiguity (info bytes)"
    assert derive_view_key(sk, "ab", "c", 9) != \
           derive_view_key(sk, "a", "bc", 9), "len-prefix ambiguity (vk)"

    # one-char chain_id distinctness, one-bit sk distinctness
    assert derive_view_key(sk, "determ-mainnet-a", "alice", 3) != \
           derive_view_key(sk, "determ-mainnet-b", "alice", 3), "chain_id 1-char"
    sk_a = bytes([0x0b] * 32)
    sk_b = sk_a[:31] + bytes([sk_a[31] ^ 0x01])
    assert derive_view_key(sk_a, "determ-mainnet", "alice", 5) != \
           derive_view_key(sk_b, "determ-mainnet", "alice", 5), "sk 1-bit"

    # ERROR edges fail closed
    for bad in (lambda: derive_view_key(sk, "determ-mainnet", "", 0),
                lambda: derive_view_key(sk, "", "alice", 0),
                lambda: derive_view_key(sk[:31], "determ-mainnet", "alice", 0),
                lambda: derive_view_key(sk + b"\x00", "determ-mainnet", "alice", 0),
                lambda: derive_view_key(sk, "determ-mainnet", "alice", -1),
                lambda: derive_view_key(sk, "determ-mainnet", "alice", 2 ** 64)):
        try:
            bad()
        except ValueError:
            pass
        else:
            raise AssertionError("an invalid input derived a key (must reject)")

# ─── corpus definition ───────────────────────────────────────────────────────
SK      = bytes(range(32))                       # 000102...1f
SK_A    = bytes([0x0b] * 32)
SK_B    = SK_A[:31] + bytes([SK_A[31] ^ 0x01])   # one-bit flip in the last byte
LONGADDR = "a" * 40 + "0123456789abcdef0123456789abcdef"   # 72 chars

# (name, sk, chain_id, addr, epoch)
VECS = [
    ("epoch 0 baseline",                    SK,   "determ-mainnet",   "alice", 0),
    ("epoch 1 (adjacent to epoch 0 — rotation must change the key)",
                                            SK,   "determ-mainnet",   "alice", 1),
    ("epoch 2^32 (past u32 width)",         SK,   "determ-mainnet",   "alice", 2 ** 32),
    ("epoch 2^32+1",                        SK,   "determ-mainnet",   "alice", 2 ** 32 + 1),
    ("epoch max u64",                       SK,   "determ-mainnet",   "alice", 2 ** 64 - 1),
    ("long addr (72 chars)",                SK,   "determ-mainnet",   LONGADDR, 7),
    ("addr distinctness (bob vs alice at epoch 0)",
                                            SK,   "determ-mainnet",   "bob",   0),
    ("chain_id one-char pair A",            SK,   "determ-mainnet-a", "alice", 3),
    ("chain_id one-char pair B (differs from pair A in one char)",
                                            SK,   "determ-mainnet-b", "alice", 3),
    ("sk one-bit pair A",                   SK_A, "determ-mainnet",   "alice", 5),
    ("sk one-bit pair B (last byte 0x0b -> 0x0a)",
                                            SK_B, "determ-mainnet",   "alice", 5),
    ("concat-ambiguity pair A: chain_id='ab' addr='c'",
                                            SK,   "ab",               "c",     9),
    ("concat-ambiguity pair B: chain_id='a' addr='bc' (MUST differ from pair A)",
                                            SK,   "a",                "bc",    9),
    ("minimal 1-char chain_id and addr",    SK,   "x",                "y",     0),
]

def make_corpus():
    out = []
    for name, sk, chain_id, addr, epoch in VECS:
        out.append({
            "name": name,
            "view_master_sk_hex": sk.hex(),
            "chain_id": chain_id,
            "addr": addr,
            # decimal STRING: max-u64 epochs overflow the exact-integer range
            # of double-based JSON parsers; a string is unambiguous everywhere.
            "epoch": str(epoch),
            # the exact HKDF info bytes — pins the len64-BE encoding itself,
            # so a C encoding bug is caught separately from an HKDF bug.
            "info_hex": view_key_info(chain_id, addr, epoch).hex(),
            "vk_hex": derive_view_key(sk, chain_id, addr, epoch).hex(),
        })
    return out

def emit():
    doc = {
        "primitive": "view_key",
        "source": ("Generated by tools/verify_view_key.py (A1 pre-launch decision, "
                   "Option C per-epoch view-key derivation, ratified 2026-07-09); "
                   "from-scratch RFC 5869 HKDF-SHA-256 on python hmac/hashlib, "
                   "gated on RFC 5869 Appendix A test cases 1 and 2 before write."),
        "note": ("vk_epoch_n = HKDF-SHA256(salt=\"determ-view-key-v1\", "
                 "ikm=view_master_sk (32 bytes), info=len64_be(chain_id)||chain_id"
                 "||len64_be(addr)||addr||epoch_u64_be, L=32). All integers "
                 "big-endian (Preliminaries §1.3); length prefixes are u64-of-"
                 "length before each variable-width string (the shielded.hpp "
                 "unshield_spend_ctx_hash convention). epoch is a decimal string "
                 "in this file (max-u64 exceeds double-exact JSON integers). "
                 "Empty chain_id, empty addr, sk length != 32, and epoch outside "
                 "u64 are ERRORS — no key is derived."),
        "vectors": make_corpus(),
    }
    with open(CORPUS, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("[emit] wrote %s (%d vectors)" % (CORPUS, len(doc["vectors"])))

def verify():
    with open(CORPUS) as f:
        doc = json.load(f)
    vecs = doc["vectors"]
    fail = 0
    for v in vecs:
        sk    = bytes.fromhex(v["view_master_sk_hex"])
        epoch = int(v["epoch"])
        info  = view_key_info(v["chain_id"], v["addr"], epoch)
        vk    = derive_view_key(sk, v["chain_id"], v["addr"], epoch)
        if info.hex() != v["info_hex"]:
            print("  FAIL %s: info encoding mismatch\n    got  %s\n    want %s"
                  % (v["name"], info.hex(), v["info_hex"]))
            fail += 1
        if vk.hex() != v["vk_hex"]:
            print("  FAIL %s: vk mismatch\n    got  %s\n    want %s"
                  % (v["name"], vk.hex(), v["vk_hex"]))
            fail += 1
    # cross-vector properties, asserted on the FROZEN file contents (not just
    # the live derivation): the pinned pairs really are distinct.
    def pin(prefix_a, prefix_b, what):
        a = next(v for v in vecs if v["name"].startswith(prefix_a))
        b = next(v for v in vecs if v["name"].startswith(prefix_b))
        if a["vk_hex"] == b["vk_hex"]:
            print("  FAIL frozen-pair equality (%s): %r == %r" % (what, a["name"], b["name"]))
            return 1
        return 0
    fail += pin("epoch 0 baseline", "epoch 1 ", "rotation")
    fail += pin("chain_id one-char pair A", "chain_id one-char pair B", "chain_id 1-char")
    fail += pin("sk one-bit pair A", "sk one-bit pair B", "sk 1-bit")
    fail += pin("concat-ambiguity pair A", "concat-ambiguity pair B", "len-prefix ambiguity")
    if fail:
        print("[verify] view_key.json: %d FAILURE(S)" % fail)
        return 1
    print("[verify] view_key.json: %d vector(s) recomputed byte-equal through the "
          "independent python HKDF oracle; frozen distinctness pairs hold" % len(vecs))
    return 0

if __name__ == "__main__":
    self_test()
    print("[self-test] RFC 5869 A.1/A.2 KATs + mapping invariants: PASS")
    if "--write" in sys.argv or "--emit" in sys.argv:
        emit()
    else:
        sys.exit(verify())
