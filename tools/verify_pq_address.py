#!/usr/bin/env python3
# tools/verify_pq_address.py — python-prove-first reference for the A5 PQ
# anon-address derivation (pre-launch register 2026-07-09, item A5: "build
# hash-based (Option A) PQ anon-address now"). Stdlib-only. This file is the
# PROPOSAL + independent oracle; no C/C++ lands until this passes adversarial
# integrator review. The format is PERMANENT once frozen at genesis.
#
#   python tools/verify_pq_address.py            # verify tools/vectors/pq_address.json
#   python tools/verify_pq_address.py --write    # (re)generate the vector file
#
# ─── 1. The EXISTING Ed25519 anon-address derivation (as shipped) ────────────
#
#   make_anon_address(pk_32B) = "0x" + hex_lowercase(pk_32B)          [66 chars]
#
# Source: include/determ/types.hpp:153-155 (`"0x" + to_hex(pk)`). It is an
# IDENTITY encoding — no hash, no discriminator, no checksum. The address IS
# the Ed25519 public key (bearer semantics); parse_anon_pubkey inverts it.
# Canonical form is lowercase (S-028); is_anon_address pins length == 66.
# Pinned in-repo goldens (src/main.cpp `test-anon-address-derivation`
# Scenario 7) are reused verbatim as cross-check fixtures below.
#
# ─── 2. The PROPOSED Option A PQ anon-address derivation ─────────────────────
#
#   DST = "determ-pq-anon-addr-v1"                                   (22 bytes)
#   preimage = u8(len(DST)) || DST || u8(form) || u32_be(len(pk)) || pk
#   pq_anon_address(form, pk) = "0x" + hex_lowercase(SHA256(preimage))
#                                                                    [66 chars]
#   form: 0x01 = ML-DSA-44 (pk 1312 B), 0x02 = ML-DSA-65 (pk 1952 B),
#         0x03 = ML-DSA-87 (pk 2592 B)   — any other form, or a pk whose
#   length is not EXACTLY the form's pk_bytes, is an ERROR (reject, never
#   derive). pk is the full FIPS 204 encoded public key (rho || t1).
#
# Why each choice:
#   * SHA-256 — the chain's canonical hash (SHA256Builder: block digests,
#     state roots, tx hashes). Same hash family as everything consensus
#     already relies on; matches the in-repo Option A sketch
#     (docs/proofs/AnonAddressDerivationMigration.md §3.1).
#   * "0x" + 64 lowercase hex, 66 chars, no checksum — mirrors the Ed25519
#     anon-address shape exactly (same emit case, same S-028 lowercase
#     canonicalization story, same length), and is FIXED-length regardless of
#     pk size (criterion C3 of the migration analysis): a 2592-byte ML-DSA-87
#     key still yields a 66-char address.
#   * length-framed DST (u8(len)||DST) — injective, self-delimiting preimage
#     framing, mirroring pqauth's len(CTX)||CTX binding (src/crypto/pqauth.cpp,
#     CTX "determ-pqtx-v1"). DST name follows the repo's lowercase
#     determ-<thing>-v1 convention ("determ-pqtx-v1", "determ-unshield-v1").
#   * form byte in the preimage — the §7.6.7 requirement (Improvements.md):
#     the pubkey_form discriminator MUST be inside the address-derivation
#     preimage, so ML-DSA-44/65/87 keys with related bytes can never share an
#     address and the binding cannot be stripped post-launch.
#   * u32_be(len(pk)) — matches the migration doc's body_len_be4; framing by
#     length keeps the preimage injective even if a future form ever has a
#     variable-length key (belt-and-braces: today form implies length).
#   * FULL pk hashed, never truncated — the address must commit to the entire
#     ML-DSA verification key. Hashing a truncation would let two ML-DSA keys
#     differing only outside the hashed window share an address, silently
#     voiding the "address == commitment to the verification key" property.
#     With the full pk, spending from an address reduces cleanly: a forger
#     must either produce an ML-DSA forgery under some pk with H(pk) == addr
#     (EUF-CMA of FIPS 204), or find a second preimage / collision on SHA-256
#     (2^128+). Nothing weaker than the weakest of the two primitives.
#
# Cross-scheme separation argument (PQ vs Ed25519, adversarial key choice):
#   An Ed25519 anon address is the identity encoding of a curve point whose
#   discrete log the spender knows. A PQ address is a SHA-256 output over a
#   DST-framed preimage. For one address string to be spendable under BOTH
#   schemes, an adversary must exhibit an Ed25519 keypair (sk, pk_ed) and an
#   ML-DSA pk_pq with pk_ed == SHA256(dst-framed pq preimage). They cannot
#   choose pk_ed bytes freely (pk_ed = a*B; hitting a target needs a discrete
#   log), and they cannot invert SHA-256 toward a pk_ed they control; grinding
#   both sides is a generic birthday search over a 256-bit space (~2^128 work,
#   the chain's uniform security level) — and the colliding hash output must
#   additionally decode to a valid curve point with a KNOWN dlog. The DST
#   further separates this hash use from every other SHA-256 use in the chain
#   (tx hashes, Merkle/consensus digests, any future hash-derived address
#   family), so no other protocol artifact can double as an address preimage.
#   The cross_scheme vectors below pin the concrete non-aliasing case: an
#   Ed25519 pubkey embedded at the head of a PQ-length buffer derives a PQ
#   address unrelated to the Ed25519 address of those same 32 bytes.
#
# OPEN QUESTIONS the integrator must decide before any C lands:
#   Q1. Shape routing. A 66-char Option A PQ address is shape-identical to an
#       Ed25519 anon address, so is_anon_address can no longer route by shape
#       alone; the verifier must route on the carried from_pubkey record and
#       check derive(form, pk) == from (exactly the Option A wire change
#       already priced in AnonAddressDerivationMigration.md §4/§5.4). If
#       shape-routing MUST survive, the alternative is a 68-char visible-form
#       variant ("0x" + hex(form) + hex(SHA256(...)) — the migration doc's
#       Option D, rejected there as dominated). Decide explicitly.
#   Q2. Does the Ed25519 derivation itself also migrate to hashed form at
#       genesis (§7.6.7 wants the discriminator in EVERY form's preimage)?
#       This file assumes Ed25519 STAYS "0x" + hex(pk) as shipped and pinned;
#       if Ed25519 migrates too, its DST/form must be assigned in the same
#       family and the goldens regenerate.
#   Q3. Fate of the shipped Option B bearer format (src/crypto/pq_address.cpp,
#       "0x" + hex(form) + hex(pk), 2628/3908/5188 chars): replace or keep?
#       Two live PQ address forms for the same key would be a footgun.
#   Q4. Checksum: the Ed25519 format has none, so this mirror has none. If one
#       is ever wanted it must be added to both families or the mirror breaks.
import hashlib
import json
import os
import sys

HERE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "pq_address.json")

# ─── The two derivations ─────────────────────────────────────────────────────

DST = b"determ-pq-anon-addr-v1"

FORM_PK_BYTES = {0x01: 1312, 0x02: 1952, 0x03: 2592}   # ML-DSA-44 / 65 / 87
FORM_NAME     = {0x01: "ML-DSA-44", 0x02: "ML-DSA-65", 0x03: "ML-DSA-87"}


def ed25519_anon_address(pk: bytes) -> str:
    """The SHIPPED derivation: include/determ/types.hpp make_anon_address."""
    if len(pk) != 32:
        raise ValueError(f"ed25519 pubkey must be 32 bytes, got {len(pk)}")
    return "0x" + pk.hex()


def pq_anon_address(form: int, pk: bytes) -> str:
    """The PROPOSED Option A derivation (see header §2). Fail-closed."""
    expect = FORM_PK_BYTES.get(form)
    if expect is None:
        raise ValueError(f"unknown pq form byte 0x{form:02x}")
    if len(pk) != expect:
        raise ValueError(
            f"pq pubkey length {len(pk)} != {expect} required by form 0x{form:02x}")
    preimage = bytes([len(DST)]) + DST + bytes([form]) \
        + len(pk).to_bytes(4, "big") + pk
    return "0x" + hashlib.sha256(preimage).hexdigest()


# ─── Deterministic vector pubkeys (reproducible WITHOUT an ML-DSA impl) ──────
# Byte-fill rule: the pk is a SHA-256 counter expansion, truncated to the
# form's pk length —
#   block_j = SHA256( FILL_TAG || u8(form) || u64_be(seed) || u32_be(j) )
#   pk      = (block_0 || block_1 || ...)[: FORM_PK_BYTES[form]]
# These are NOT valid ML-DSA keys (irrelevant: the derivation hashes any
# correct-length bytes); they exist so the fixtures are reproducible a priori
# by anyone with a SHA-256, exactly like the SHA-256(tag, i) pubkeys in
# src/main.cpp test-anon-address-derivation.

FILL_TAG = b"determ-pq-address-vector-fill-v1"


def fill_pk(form: int, seed: int) -> bytes:
    n = FORM_PK_BYTES[form]
    out = bytearray()
    j = 0
    while len(out) < n:
        out += hashlib.sha256(
            FILL_TAG + bytes([form]) + seed.to_bytes(8, "big")
            + j.to_bytes(4, "big")).digest()
        j += 1
    return bytes(out[:n])


def flip_bit(pk: bytes, byte_index: int, bit: int) -> bytes:
    mut = bytearray(pk)
    mut[byte_index] ^= (1 << bit)
    return bytes(mut)


# ─── In-repo pinned Ed25519 goldens (REUSED, not invented) ───────────────────
# src/main.cpp `test-anon-address-derivation` Scenario 7 hardcodes these two;
# our reimplementation must reproduce them byte-for-byte.

ED_GOLDENS = [
    ("ed25519-golden-zero",
     bytes(32),
     "0x0000000000000000000000000000000000000000000000000000000000000000"),
    ("ed25519-golden-seq",
     bytes(range(32)),
     "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
]

# ─── Corpus construction ─────────────────────────────────────────────────────

def make_corpus():
    vecs = []

    # (a) Ed25519 cross-check fixtures (pinned in-repo goldens).
    for name, pk, golden in ED_GOLDENS:
        addr = ed25519_anon_address(pk)
        assert addr == golden, f"{name}: reimplementation disagrees with repo golden"
        vecs.append({
            "kind": "ed25519_golden",
            "name": name,
            "pk_hex": pk.hex(),
            "address": addr,
            "provenance": "src/main.cpp test-anon-address-derivation Scenario 7",
        })

    # (b) PQ vectors: fill-rule pks across all three forms + literal boundary
    # pks (all-0x00 / all-0xFF at the ML-DSA-65 length).
    pq_inputs = [("pq-mldsa44-seed1", 0x01, ("fill", 1)),
                 ("pq-mldsa44-seed2", 0x01, ("fill", 2)),
                 ("pq-mldsa65-seed1", 0x02, ("fill", 1)),
                 ("pq-mldsa65-seed2", 0x02, ("fill", 2)),
                 ("pq-mldsa65-seed3", 0x02, ("fill", 3)),
                 ("pq-mldsa65-seed4", 0x02, ("fill", 4)),
                 ("pq-mldsa87-seed1", 0x03, ("fill", 1)),
                 ("pq-mldsa87-seed2", 0x03, ("fill", 2)),
                 ("pq-mldsa65-all00", 0x02, ("literal", bytes(1952))),
                 ("pq-mldsa65-allff", 0x02, ("literal", bytes([0xFF]) * 1952))]
    for name, form, src in pq_inputs:
        if src[0] == "fill":
            pk = fill_pk(form, src[1])
            fill = {"fill_seed": src[1]}
        else:
            pk = src[1]
            fill = {}
        vecs.append({
            "kind": "pq",
            "name": name,
            "form": form,
            "form_name": FORM_NAME[form],
            "pk_len": len(pk),
            **fill,
            "pk_sha256": hashlib.sha256(pk).hexdigest(),
            "pk_hex": pk.hex(),
            "address": pq_anon_address(form, pk),
        })

    # (c) Single-bit-flip distinctness pair. The flipped bit sits in the LAST
    # byte of the 1952-byte key — the exact byte a truncated-key hash would
    # silently drop.
    base = fill_pk(0x02, 0xB17)
    mut  = flip_bit(base, len(base) - 1, 0)
    vecs.append({
        "kind": "bitflip_pair",
        "name": "bitflip-mldsa65-lastbyte",
        "form": 0x02,
        "fill_seed": 0xB17,
        "flip_byte_index": len(base) - 1,
        "flip_bit": 0,
        "base_pk_sha256": hashlib.sha256(base).hexdigest(),
        "base_pk_hex": base.hex(),
        "mut_pk_hex": mut.hex(),
        "base_address": pq_anon_address(0x02, base),
        "mut_address": pq_anon_address(0x02, mut),
    })

    # (d) Cross-scheme separation: the repo's pinned sequential Ed25519 pubkey
    # embedded at the head of an ML-DSA-65-length buffer (zero padding). The
    # PQ address of that buffer must NOT alias the Ed25519 address of the same
    # leading 32 bytes.
    ed_pk = bytes(range(32))
    embedded = ed_pk + bytes(1952 - 32)
    vecs.append({
        "kind": "cross_scheme",
        "name": "cross-scheme-ed25519-embedded",
        "form": 0x02,
        "ed_pk_hex": ed_pk.hex(),
        "ed_address": ed25519_anon_address(ed_pk),
        "embedded_pk_hex": embedded.hex(),
        "pq_address": pq_anon_address(0x02, embedded),
    })

    # (e) Wrong-length / unknown-form pks — MUST be rejected, never derived.
    err_inputs = [
        ("err-mldsa65-truncated", 0x02, fill_pk(0x02, 1)[:1951]),
        ("err-mldsa65-ed25519-raw", 0x02, bytes(range(32))),
        ("err-form-length-mismatch", 0x01, fill_pk(0x02, 1)),
        ("err-unknown-form", 0x04, fill_pk(0x02, 1)),
    ]
    for name, form, pk in err_inputs:
        vecs.append({
            "kind": "error_wrong_length",
            "name": name,
            "form": form,
            "pk_len": len(pk),
            "pk_hex": pk.hex(),
            "expect": "error",
        })
    return vecs


# ─── Modes ───────────────────────────────────────────────────────────────────

def write_corpus():
    vecs = make_corpus()
    os.makedirs(os.path.dirname(CORPUS), exist_ok=True)
    with open(CORPUS, "w") as f:
        json.dump({"dst": DST.decode(),
                   "formula": "0x + hex(SHA256(u8(len(DST))||DST||u8(form)||"
                              "u32_be(len(pk))||pk))",
                   "form_pk_bytes": {f"0x{k:02x}": v
                                     for k, v in FORM_PK_BYTES.items()},
                   "vectors": vecs}, f, indent=1)
        f.write("\n")
    print(f"[write] wrote {len(vecs)} vector(s) -> {CORPUS}")
    for v in vecs:
        tag = v.get("address") or v.get("base_address") \
            or v.get("pq_address") or v.get("expect")
        print(f"  {v['name']:32s} {v['kind']:18s} {tag}")


def verify():
    fails = []

    def check(cond, msg):
        print(("  PASS: " if cond else "  FAIL: ") + msg)
        if not cond:
            fails.append(msg)

    with open(CORPUS) as f:
        doc = json.load(f)
    check(doc.get("dst") == DST.decode(),
          "corpus header DST matches the script's DST")
    vecs = doc["vectors"]

    shape_ok = lambda a: (len(a) == 66 and a[:2] == "0x"
                          and all(c in "0123456789abcdef" for c in a[2:]))
    ed_addrs, pq_addrs = [], []

    for v in vecs:
        kind, name = v["kind"], v["name"]
        if kind == "ed25519_golden":
            pk = bytes.fromhex(v["pk_hex"])
            addr = ed25519_anon_address(pk)
            check(addr == v["address"],
                  f"{name}: ed25519 derivation matches stored address")
            golden = {n: g for n, _, g in ED_GOLDENS}.get(name)
            check(golden is not None and v["address"] == golden,
                  f"{name}: stored address equals the in-repo pinned golden")
            ed_addrs.append(v["address"])
        elif kind == "pq":
            pk = bytes.fromhex(v["pk_hex"])
            if "fill_seed" in v:
                check(fill_pk(v["form"], v["fill_seed"]) == pk,
                      f"{name}: pk reproduces from the documented fill rule")
            check(hashlib.sha256(pk).hexdigest() == v["pk_sha256"],
                  f"{name}: pk_sha256 matches pk bytes")
            check(len(pk) == v["pk_len"] == FORM_PK_BYTES[v["form"]],
                  f"{name}: pk length == {FORM_PK_BYTES[v['form']]} for "
                  f"{FORM_NAME[v['form']]}")
            addr = pq_anon_address(v["form"], pk)
            check(addr == v["address"],
                  f"{name}: pq derivation matches stored address")
            check(shape_ok(addr),
                  f"{name}: address matches ^0x[0-9a-f]{{64}}$ (66 chars, "
                  f"lowercase -- mirrors the Ed25519 shape)")
            pq_addrs.append(addr)
        elif kind == "bitflip_pair":
            base = bytes.fromhex(v["base_pk_hex"])
            mut  = bytes.fromhex(v["mut_pk_hex"])
            check(fill_pk(v["form"], v["fill_seed"]) == base,
                  f"{name}: base pk reproduces from the documented fill rule")
            diff = [(i, base[i] ^ mut[i]) for i in range(len(base))
                    if base[i] != mut[i]]
            check(len(diff) == 1 and diff[0][0] == v["flip_byte_index"]
                  and diff[0][1] == (1 << v["flip_bit"]),
                  f"{name}: pair differs in exactly one bit "
                  f"(byte {v['flip_byte_index']}, bit {v['flip_bit']} -- the "
                  f"LAST key byte, the truncation canary)")
            a_base = pq_anon_address(v["form"], base)
            a_mut  = pq_anon_address(v["form"], mut)
            check(a_base == v["base_address"] and a_mut == v["mut_address"],
                  f"{name}: both derivations match stored addresses")
            check(a_base != a_mut,
                  f"{name}: single-bit flip changes the address (full pk is "
                  f"bound; no truncated-key hashing)")
            pq_addrs += [a_base, a_mut]
        elif kind == "cross_scheme":
            ed_pk = bytes.fromhex(v["ed_pk_hex"])
            emb   = bytes.fromhex(v["embedded_pk_hex"])
            check(emb[:32] == ed_pk and emb[32:] == bytes(len(emb) - 32),
                  f"{name}: embedded buffer = ed25519 pk || zero padding")
            ed_addr = ed25519_anon_address(ed_pk)
            pq_addr = pq_anon_address(v["form"], emb)
            check(ed_addr == v["ed_address"] and pq_addr == v["pq_address"],
                  f"{name}: both derivations match stored addresses")
            check(pq_addr != ed_addr,
                  f"{name}: PQ address of the embedded buffer does NOT alias "
                  f"the Ed25519 address of the same leading 32 bytes "
                  f"(cross-scheme domain separation)")
            ed_addrs.append(ed_addr)
            pq_addrs.append(pq_addr)
        elif kind == "error_wrong_length":
            try:
                pq_anon_address(v["form"], bytes.fromhex(v["pk_hex"]))
                rejected = False
            except ValueError:
                rejected = True
            check(rejected,
                  f"{name}: wrong-length/unknown-form pk is REJECTED "
                  f"(form 0x{v['form']:02x}, len {v['pk_len']})")
        else:
            check(False, f"{name}: unknown vector kind '{kind}'")

    check(len(set(pq_addrs)) == len(pq_addrs),
          f"global: all {len(pq_addrs)} PQ addresses are mutually distinct")
    check(set(pq_addrs).isdisjoint(ed_addrs),
          f"global: the PQ address set ({len(set(pq_addrs))}) is disjoint "
          f"from the Ed25519 address set ({len(set(ed_addrs))}) -- no "
          f"cross-scheme aliasing anywhere in the corpus")
    n_derived = sum(1 for v in vecs if v["kind"] != "error_wrong_length")
    print(f"\n[verify] pq_address.json: {len(vecs)} vector(s) "
          f"({n_derived} derivations + "
          f"{len(vecs) - n_derived} rejection cases), "
          f"{len(fails)} failure(s)")
    return 0 if not fails else 1


if __name__ == "__main__":
    if "--write" in sys.argv or "--emit" in sys.argv:
        write_corpus()
    else:
        sys.exit(verify())
