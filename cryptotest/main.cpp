// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-cryptotest — the standalone OpenSSL test-oracle binary.
//
// Minix OpenSSL split (docs/proofs/MinixTacticalProfile.md §6): the 11
// pure-oracle `test-*-c99` subcommands are MOVED VERBATIM out of src/main.cpp
// into this binary so the determ daemon links ZERO OpenSSL while the
// independent §Q9 cross-validation of the from-scratch determ C99 crypto
// stack lives on unchanged. Every handler body below is byte-identical to
// its pre-split src/main.cpp form (stdout byte-identical, so the tools/
// wrapper summary-pins stay green); only this dispatcher scaffolding is new.
//
// OpenSSL here is the TEST ORACLE (vendored 1.1.1w, §Q9) — never a
// production dependency. The production crypto is the in-tree C99 stack.

// determ C99 crypto under test (in-tree, from scratch).
#include <determ/crypto/sha256.hpp>            // determ::crypto::sha256 / determ::Hash (test-sha2-c99 backend-parity leg)
#include <determ/crypto/sha2/sha2.h>           // SHA-256/512 + HMAC + HKDF + PBKDF2 (§3.1)
#include <determ/crypto/chacha20/chacha20.h>   // ChaCha20 + Poly1305 + AEAD (§3.4)
#include <determ/crypto/chacha20/xchacha20_poly1305.h> // HChaCha20 + XChaCha20-Poly1305 (§3.4)
#include <determ/crypto/aes/aes.h>             // AES-256 + GCM (§3.5)
#include <determ/crypto/ed25519/ed25519.h>     // Ed25519 sign/verify (§3.2)
#include <determ/crypto/x25519/x25519.h>       // X25519 (RFC 7748, §3.3)
#include <determ/crypto/blake2/blake2b.h>      // BLAKE2b (RFC 7693, §3.6 prereq)
#include <determ/crypto/sha3/sha3.h>           // SHA-3/SHAKE (FIPS 202)
#include <determ/crypto/p256/p256.h>           // NIST P-256 (§3.8c) + mod-n/h2c (§3.9b)

// The OpenSSL oracle (same include set the handlers used in src/main.cpp;
// the vestigial openssl/rand.h include did NOT move — no handler uses RAND_*).
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>       // test-p256-c99: EC_GROUP/EC_POINT cross-validation oracle
#include <openssl/obj_mac.h>  // test-p256-c99: NID_X9_62_prime256v1
#include <openssl/bn.h>       // test-p256-c99: BIGNUM scalar/coordinate plumbing

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static void usage() {
    std::cout << R"(determ-cryptotest — standalone OpenSSL cross-validation oracle for the
from-scratch determ C99 crypto stack (the MinixTacticalProfile.md §6 split:
the daemon links zero OpenSSL; the §Q9 oracle gates live here, VERBATIM,
stdout byte-identical to the pre-split `determ` handlers).

Usage:
  determ-cryptotest <subcommand>

Subcommands:
  test-sha2-c99      C99 SHA-256/512 + HMAC + HKDF + PBKDF2 byte-equal vs
                     OpenSSL + NIST/RFC KATs (CRYPTO-C99-SPEC §Q9 gate)
  test-chacha20-c99  C99 ChaCha20 + Poly1305 + AEAD (RFC 8439) byte-equal vs
                     OpenSSL EVP_chacha20/EVP_chacha20_poly1305 (§3.4)
  test-aes-c99       C99 AES-256-GCM (FIPS-197 + SP 800-38D) byte-equal vs
                     OpenSSL + FIPS-197 KAT (§3.5)
  test-ed25519-c99   C99 Ed25519 (RFC 8032) byte-equal vs OpenSSL
                     EVP_PKEY_ED25519 + the RFC 8032 §7.1 KAT (§3.2)
  test-x25519-c99    C99 X25519 (RFC 7748) byte-equal vs OpenSSL
                     EVP_PKEY_X25519 + the RFC 7748 §6.1 KAT (§3.3)
  test-blake2b-c99   C99 BLAKE2b (RFC 7693) byte-equal vs OpenSSL
                     EVP_blake2b512 + hashlib.blake2b KATs (§3.6 prereq)
  test-sha3-c99      C99 SHA-3/SHAKE (FIPS 202) byte-equal vs OpenSSL
                     EVP_sha3/shake + FIPS 202 KATs (ML-DSA XOF prereq)
  test-xchacha-c99   C99 XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) vs
                     OpenSSL inner AEAD + HChaCha20 §2.2.1 KAT (§3.4)
  test-p256-c99      C99 NIST P-256: constants + [k]G + ECDH byte-equal vs
                     the OpenSSL EC oracle; reject gates (§3.8c)
  test-p256-h2c-c99  P-256 mod-n scalar ops vs OpenSSL BIGNUM; RFC 9380
                     SSWU hash-to-curve structural contract (§3.9b)

Exit codes: 0 = all assertions passed, 1 = assertion failure, 2 = usage error.
)";
}

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd.empty() || cmd == "--help" || cmd == "-h" || cmd == "help") {
        usage();
        return cmd.empty() ? 2 : 0;
    }

    if (cmd == "test-aes-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.5: validate the libsodium-free C99
        // AES-256-GCM AEAD against (0) an exhaustive constant-time-S-box selftest
        // (the arithmetic S-box == the canonical FIPS-197 table over all 256
        // inputs), (1) the FIPS-197 Appendix C.3 known-answer vector, (2) byte-
        // equal vs OpenSSL EVP_aes_256_ecb over fuzzed key/blocks, (3) the full
        // AES-256-GCM (ct + tag) byte-equal vs OpenSSL EVP_aes_256_gcm over a
        // (pt,aad)-length grid — the §Q9 gate, and (4) GCM decrypt round-trip +
        // tamper rejection. The S-box is now constant-time (arithmetic, no key-
        // dependent table lookup); GHASH is branchless — see aes.h / aes_gcm.c.
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const std::string& m) {
            if (cond) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };
        auto to_hexs = [](const uint8_t* p, size_t n) {
            static const char* H = "0123456789abcdef";
            std::string s; for (size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xf]); } return s;
        };

        // (0) Constant-time S-box exhaustively equals the canonical FIPS-197 table.
        check(determ_aes256_sbox_selftest()==1,
              "AES-256 constant-time S-box == FIPS-197 table over all 256 inputs");

        // (1) FIPS-197 C.3 AES-256 known-answer vector.
        {
            uint8_t key[32], in[16], out[16];
            for (int i=0;i<32;i++) key[i]=(uint8_t)i;             /* 000102...1f */
            for (int i=0;i<16;i++) in[i]=(uint8_t)(0x00 + i*0x11); /* 00112233...ff */
            determ_aes256_ctx ctx; determ_aes256_init(&ctx, key);
            determ_aes256_encrypt_block(&ctx, in, out);
            check(to_hexs(out,16)=="8ea2b7ca516745bfeafc49904b496089",
                  "AES-256 encrypt matches FIPS-197 C.3 KAT");
        }

        // (2) Byte-equal vs OpenSSL EVP_aes_256_ecb over fuzzed (key, block).
        {
            bool xval = true; long at = -1;
            for (int t=0; t<256 && xval; ++t) {
                uint8_t key[32], in[16], mine[16], ossl[16];
                for (int i=0;i<32;i++) key[i]=(uint8_t)((i*53u+t*7u+1u)&0xffu);
                for (int i=0;i<16;i++) in[i]=(uint8_t)((i*29u+t*3u+5u)&0xffu);
                determ_aes256_ctx ctx; determ_aes256_init(&ctx, key);
                determ_aes256_encrypt_block(&ctx, in, mine);
                EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                int outl=0;
                EVP_EncryptInit_ex(c, EVP_aes_256_ecb(), nullptr, key, nullptr);
                EVP_CIPHER_CTX_set_padding(c, 0);
                EVP_EncryptUpdate(c, ossl, &outl, in, 16);
                EVP_CIPHER_CTX_free(c);
                if (std::memcmp(mine, ossl, 16)!=0){ xval=false; at=t; }
            }
            check(xval, xval ? "AES-256 block C99 == OpenSSL EVP_aes_256_ecb over 256 fuzzed (key,block) pairs"
                             : "AES-256 diverges from OpenSSL at iter=" + std::to_string(at));
        }

        // (3) AES-256-GCM cross-validation vs OpenSSL EVP_aes_256_gcm (ct + tag)
        // over a (plaintext,aad)-length grid.
        {
            bool g_ok = true; long g_at = -1;
            const size_t ptl[]  = {0,1,16,63,64,65,128,200};
            const size_t aadl[] = {0,1,12,16,20};
            for (size_t pi=0; pi<sizeof(ptl)/sizeof(ptl[0]) && g_ok; ++pi)
            for (size_t ai=0; ai<sizeof(aadl)/sizeof(aadl[0]) && g_ok; ++ai) {
                size_t pl=ptl[pi], al=aadl[ai];
                uint8_t key[32], iv[12];
                for(int i=0;i<32;i++) key[i]=(uint8_t)((i*61u+pi*5u+ai+3u)&0xffu);
                for(int i=0;i<12;i++) iv[i]=(uint8_t)((i*19u+pi+ai*2u+1u)&0xffu);
                std::vector<uint8_t> pt(pl), aad(al), ct(pl), octt(pl);
                for(size_t i=0;i<pl;i++) pt[i]=(uint8_t)((i*23u+pi+5u)&0xffu);
                for(size_t i=0;i<al;i++) aad[i]=(uint8_t)((i*31u+ai+9u)&0xffu);
                uint8_t mytag[16], otag[16];
                determ_aes256_gcm_encrypt(key,iv, al?aad.data():nullptr,al,
                                          pl?pt.data():nullptr,pl, ct.data(), mytag);
                EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                int outl=0;
                EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
                EVP_EncryptInit_ex(c, nullptr, nullptr, key, iv);
                if (al) EVP_EncryptUpdate(c, nullptr, &outl, aad.data(), (int)al);
                if (pl) EVP_EncryptUpdate(c, octt.data(), &outl, pt.data(), (int)pl);
                EVP_EncryptFinal_ex(c, octt.data() + (pl?(size_t)outl:0), &outl);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, otag);
                EVP_CIPHER_CTX_free(c);
                bool ctm = (pl==0) || (std::memcmp(ct.data(), octt.data(), pl)==0);
                bool tgm = std::memcmp(mytag, otag, 16)==0;
                if(!ctm||!tgm){ g_ok=false; g_at=(long)(pl*100+al); }
            }
            check(g_ok, g_ok ? "AES-256-GCM C99 == OpenSSL EVP_aes_256_gcm (ciphertext + tag)"
                             : "AES-256-GCM diverges from OpenSSL (pl*100+al=" + std::to_string(g_at) + ")");
        }

        // (4) GCM decrypt round-trip + tamper rejection (tag + ciphertext).
        {
            uint8_t key[32], iv[12];
            for(int i=0;i<32;i++) key[i]=(uint8_t)(i*5+9);
            for(int i=0;i<12;i++) iv[i]=(uint8_t)(i*2+1);
            const char* msg="the quick brown fox jumps over"; size_t pl=std::strlen(msg);
            uint8_t aad[6]={9,8,7,6,5,4};
            std::vector<uint8_t> ct(pl), back(pl); uint8_t tag[16];
            determ_aes256_gcm_encrypt(key,iv, aad,6, (const uint8_t*)msg,pl, ct.data(), tag);
            check(determ_aes256_gcm_decrypt(key,iv, aad,6, ct.data(),pl, tag, back.data())==0
                  && std::memcmp(back.data(), msg, pl)==0, "AES-256-GCM decrypt round-trips the plaintext");
            uint8_t badtag[16]; std::memcpy(badtag,tag,16); badtag[0]^=0x01;
            check(determ_aes256_gcm_decrypt(key,iv, aad,6, ct.data(),pl, badtag, back.data())==-1,
                  "AES-256-GCM decrypt rejects a tampered tag");
            std::vector<uint8_t> ct2=ct; if(pl) ct2[0]^=0x01;
            check(determ_aes256_gcm_decrypt(key,iv, aad,6, ct2.data(),pl, tag, back.data())==-1,
                  "AES-256-GCM decrypt rejects tampered ciphertext");
            // AAD-binding (the property S004KeyfileAtRest.md T-2 relies on): a flipped
            // or length-changed AAD must fail even with a valid ciphertext + tag.
            uint8_t aad2[6]={9,8,7,6,5,3};
            check(determ_aes256_gcm_decrypt(key,iv, aad2,6, ct.data(),pl, tag, back.data())==-1,
                  "AES-256-GCM decrypt rejects tampered AAD (AAD-binding)");
            check(determ_aes256_gcm_decrypt(key,iv, aad,5, ct.data(),pl, tag, back.data())==-1,
                  "AES-256-GCM decrypt rejects an AAD-length mismatch");
        }

        // (5) Arbitrary-IV-length entry points (SP 800-38D §7.1 GHASH-J0
        //     derivation for ivlen != 12): cross-validate ciphertext + tag
        //     against OpenSSL EVP (SET_IVLEN) per IV length, then round-trip
        //     + tamper-reject + the ivlen==0/==12 contract edges.
        {
            bool iv_ok = true; long iv_at = -1;
            const size_t ivlens[] = {1, 8, 16, 20, 32, 60};
            uint8_t key[32];
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 3);
            const char* msg = "arbitrary-IV GHASH J0 derivation";
            size_t pl = std::strlen(msg);
            uint8_t aad[4] = {1, 2, 3, 4};
            for (size_t vi = 0; vi < sizeof(ivlens)/sizeof(ivlens[0]); ++vi) {
                size_t il = ivlens[vi];
                std::vector<uint8_t> iv(il);
                for (size_t i = 0; i < il; i++) iv[i] = (uint8_t)(i * 7 + vi + 1);
                std::vector<uint8_t> ct(pl), octt(pl), back(pl);
                uint8_t mytag[16], otag[16];
                if (determ_aes256_gcm_encrypt_iv(key, iv.data(), il, aad, 4,
                        (const uint8_t*)msg, pl, ct.data(), mytag) != 0) {
                    iv_ok = false; iv_at = (long)il; break;
                }
                // OpenSSL oracle with the same non-default IV length.
                EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                int outl = 0;
                EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, (int)il, nullptr);
                EVP_EncryptInit_ex(c, nullptr, nullptr, key, iv.data());
                EVP_EncryptUpdate(c, nullptr, &outl, aad, 4);
                EVP_EncryptUpdate(c, octt.data(), &outl, (const uint8_t*)msg, (int)pl);
                EVP_EncryptFinal_ex(c, octt.data() + outl, &outl);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, otag);
                EVP_CIPHER_CTX_free(c);
                if (std::memcmp(ct.data(), octt.data(), pl) != 0 ||
                    std::memcmp(mytag, otag, 16) != 0) { iv_ok = false; iv_at = (long)il; break; }
                // Round-trip + tamper on the same IV length.
                if (determ_aes256_gcm_decrypt_iv(key, iv.data(), il, aad, 4,
                        ct.data(), pl, mytag, back.data()) != 0 ||
                    std::memcmp(back.data(), msg, pl) != 0) { iv_ok = false; iv_at = (long)il; break; }
                uint8_t badtag[16]; std::memcpy(badtag, mytag, 16); badtag[15] ^= 0x80;
                if (determ_aes256_gcm_decrypt_iv(key, iv.data(), il, aad, 4,
                        ct.data(), pl, badtag, back.data()) != -1) { iv_ok = false; iv_at = (long)il; break; }
            }
            check(iv_ok, iv_ok ? "GCM arbitrary-IV (1/8/16/20/32/60B): C99 == OpenSSL + round-trip + tamper-reject"
                               : "GCM arbitrary-IV diverges at ivlen=" + std::to_string(iv_at));
            // Contract edges: ivlen==0 rejected; ivlen==12 via _iv == fixed-IV entry point.
            {
                uint8_t iv12[12]; for (int i = 0; i < 12; i++) iv12[i] = (uint8_t)(90 - i);
                std::vector<uint8_t> ct1(pl), ct2(pl); uint8_t t1[16], t2[16], dummy[16];
                check(determ_aes256_gcm_encrypt_iv(key, iv12, 0, nullptr, 0,
                        (const uint8_t*)msg, pl, ct1.data(), dummy) == -1,
                      "GCM _iv rejects ivlen == 0 (SP 800-38D: len(IV) >= 1)");
                (void)determ_aes256_gcm_encrypt_iv(key, iv12, 12, aad, 4,
                        (const uint8_t*)msg, pl, ct1.data(), t1);
                determ_aes256_gcm_encrypt(key, iv12, aad, 4,
                        (const uint8_t*)msg, pl, ct2.data(), t2);
                check(std::memcmp(ct1.data(), ct2.data(), pl) == 0 && std::memcmp(t1, t2, 16) == 0,
                      "GCM _iv with ivlen==12 is byte-identical to the fixed-IV entry point");
            }
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": aes-c99 "
                  << (fail==0 ? "all cross-validation + KATs matched" : "had failures")
                  << " (libsodium-free C99 AES-256-GCM vs OpenSSL — the §Q9 gate; constant-time S-box + branchless GHASH)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-ed25519-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.2: validate the libsodium-free C99
        // Ed25519 (RFC 8032) against (1) the RFC 8032 §7.1 TEST 1 public-key
        // anchor, (2) byte-equal public-key + signature cross-validation vs
        // OpenSSL EVP_PKEY_ED25519 over a fuzzed (seed,message) grid — the §Q9
        // gate, and (3) verify accept / tamper-reject semantics.
        int fail = 0;
        auto check = [&](bool cond, const std::string& m) {
            if (cond) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };
        auto to_hexs = [](const uint8_t* p, size_t n) {
            static const char* H = "0123456789abcdef";
            std::string s; for (size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xf]); } return s;
        };
        auto from_hex = [](const std::string& h) {
            std::vector<uint8_t> v; for (size_t i=0;i+1<h.size();i+=2)
                v.push_back((uint8_t)std::stoul(h.substr(i,2), nullptr, 16)); return v;
        };

        // (1) RFC 8032 §7.1 TEST 1 (empty message): a published anchor independent
        //     of OpenSSL, validating both pubkey derivation and signing.
        {
            auto seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            uint8_t pk[32], sig[64];
            determ_ed25519_pubkey_from_seed(seed.data(), pk);
            check(to_hexs(pk,32)=="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                  "Ed25519 pubkey matches RFC 8032 §7.1 TEST 1 vector");
            determ_ed25519_sign(seed.data(), pk, nullptr, 0, sig);
            check(to_hexs(sig,64)=="e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                   "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                  "Ed25519 signature matches RFC 8032 §7.1 TEST 1 vector (empty message)");
        }

        // (2) Byte-equal vs OpenSSL EVP_PKEY_ED25519: public key + signature over
        //     a fuzzed (seed, message-length) grid.
        {
            bool pk_ok = true, sg_ok = true; long pk_at=-1, sg_at=-1;
            const size_t mlens[] = {0,1,2,31,32,33,64,127,128,200};
            for (size_t mi=0; mi<sizeof(mlens)/sizeof(mlens[0]) && pk_ok && sg_ok; ++mi) {
                size_t ml = mlens[mi];
                uint8_t seed[32];
                for (int i=0;i<32;i++) seed[i]=(uint8_t)((i*37u + mi*11u + 5u)&0xffu);
                std::vector<uint8_t> msg(ml);
                for (size_t i=0;i<ml;i++) msg[i]=(uint8_t)((i*19u + mi*7u + 3u)&0xffu);

                uint8_t my_pk[32], my_sig[64];
                determ_ed25519_pubkey_from_seed(seed, my_pk);
                determ_ed25519_sign(seed, my_pk, ml?msg.data():nullptr, ml, my_sig);

                // OpenSSL oracle
                EVP_PKEY* sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, 32);
                uint8_t o_pk[32]; size_t o_pk_len = 32;
                EVP_PKEY_get_raw_public_key(sk, o_pk, &o_pk_len);
                uint8_t o_sig[64]; size_t o_sig_len = 64;
                EVP_MD_CTX* mc = EVP_MD_CTX_new();
                EVP_DigestSignInit(mc, nullptr, nullptr, nullptr, sk);
                EVP_DigestSign(mc, o_sig, &o_sig_len, ml?msg.data():(const uint8_t*)"", ml);
                EVP_MD_CTX_free(mc);
                EVP_PKEY_free(sk);

                if (std::memcmp(my_pk, o_pk, 32)!=0) { pk_ok=false; pk_at=(long)ml; }
                if (o_sig_len!=64 || std::memcmp(my_sig, o_sig, 64)!=0) { sg_ok=false; sg_at=(long)ml; }
            }
            check(pk_ok, pk_ok ? "Ed25519 pubkey C99 == OpenSSL EVP_PKEY_ED25519 (fuzzed seeds)"
                               : "Ed25519 pubkey diverges from OpenSSL (mlen="+std::to_string(pk_at)+")");
            check(sg_ok, sg_ok ? "Ed25519 signature C99 == OpenSSL EVP_DigestSign (fuzzed seed,msg) — the §Q9 gate"
                               : "Ed25519 signature diverges from OpenSSL (mlen="+std::to_string(sg_at)+")");
        }

        // (2b) extreme-length correctness: a large multi-block message exercises the
        //      SHA-512 streaming inside sign/verify well past the grid above (which
        //      tops out at 200 B). Cross-validate the signature vs OpenSSL at 100000 B.
        {
            const size_t ml=100000;
            uint8_t seed[32]; for(int i=0;i<32;i++) seed[i]=(uint8_t)(i*13+7);
            std::vector<uint8_t> msg(ml);
            for(size_t i=0;i<ml;i++) msg[i]=(uint8_t)((i*131u+17u)&0xffu);
            uint8_t my_pk[32], my_sig[64];
            determ_ed25519_pubkey_from_seed(seed, my_pk);
            determ_ed25519_sign(seed, my_pk, msg.data(), ml, my_sig);
            EVP_PKEY* sk=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed,32);
            uint8_t o_sig[64]; size_t o_sig_len=64;
            EVP_MD_CTX* mc=EVP_MD_CTX_new(); EVP_DigestSignInit(mc,nullptr,nullptr,nullptr,sk);
            EVP_DigestSign(mc, o_sig, &o_sig_len, msg.data(), ml);
            EVP_MD_CTX_free(mc); EVP_PKEY_free(sk);
            check(o_sig_len==64 && std::memcmp(my_sig,o_sig,64)==0,
                  "Ed25519 signature C99 == OpenSSL over a 100000-byte message (extreme-length)");
            check(determ_ed25519_verify(my_pk, msg.data(), ml, my_sig)==0,
                  "Ed25519 verify accepts the 100000-byte-message signature");
        }

        // (3) verify: accept a valid signature; reject tampered tag / message / key.
        {
            uint8_t seed[32]; for (int i=0;i<32;i++) seed[i]=(uint8_t)(i*9+1);
            uint8_t pk[32], sig[64];
            const char* m = "the quick brown fox"; size_t ml = std::strlen(m);
            determ_ed25519_pubkey_from_seed(seed, pk);
            determ_ed25519_sign(seed, pk, (const uint8_t*)m, ml, sig);
            check(determ_ed25519_verify(pk, (const uint8_t*)m, ml, sig)==0,
                  "Ed25519 verify accepts a valid signature");
            uint8_t bad[64]; std::memcpy(bad,sig,64); bad[10]^=0x01;
            check(determ_ed25519_verify(pk, (const uint8_t*)m, ml, bad)==-1,
                  "Ed25519 verify rejects a tampered signature");
            check(determ_ed25519_verify(pk, (const uint8_t*)"the quick brown box", ml, sig)==-1,
                  "Ed25519 verify rejects a tampered message");
            uint8_t badpk[32]; std::memcpy(badpk,pk,32); badpk[0]^=0x01;
            check(determ_ed25519_verify(badpk, (const uint8_t*)m, ml, sig)==-1,
                  "Ed25519 verify rejects a wrong public key");
            // anti-malleability (RFC 8032 §5.1.7): (R, S+L) must be REJECTED, so a
            // valid signature has no second distinct-but-valid form.
            {
                static const uint8_t Lb[32]={0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
                    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
                uint8_t mal[64]; std::memcpy(mal,sig,64);
                unsigned int carry=0;
                for(int i=0;i<32;i++){ unsigned int t=(unsigned int)mal[32+i]+Lb[i]+carry;
                    mal[32+i]=(uint8_t)t; carry=t>>8; }
                check(determ_ed25519_verify(pk,(const uint8_t*)m,ml,sig)==0 &&
                      determ_ed25519_verify(pk,(const uint8_t*)m,ml,mal)==-1,
                      "Ed25519 verify rejects the malleable (R, S+L) signature (S < L gate)");
            }
            // cross-binary: OpenSSL must verify our signature
            EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pk, 32);
            EVP_MD_CTX* mc = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(mc, nullptr, nullptr, nullptr, pub);
            int ov = EVP_DigestVerify(mc, sig, 64, (const uint8_t*)m, ml);
            EVP_MD_CTX_free(mc); EVP_PKEY_free(pub);
            check(ov==1, "Ed25519 signature C99 verifies under OpenSSL EVP_DigestVerify");
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": ed25519-c99 "
                  << (fail==0 ? "all cross-validation + RFC 8032 KAT matched" : "had failures")
                  << " (libsodium-free C99 Ed25519 vs OpenSSL — the §Q9 gate; constant-time gf[16] ladder)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-x25519-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.3: validate the libsodium-free C99
        // X25519 (RFC 7748) two ways — (1) byte-equal vs OpenSSL EVP_PKEY_X25519
        // (public-key derivation + ECDH EVP_PKEY_derive) over a fuzzed scalar grid —
        // the §Q9 gate — and (2) the canonical RFC 7748 §6.1 known-answer vectors.
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const std::string& m){
            if (cond) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };
        auto hx = [](const uint8_t* p, size_t n){ static const char* H="0123456789abcdef";
            std::string s; for(size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xf]); } return s; };
        auto unhex = [](const std::string& s){ std::vector<uint8_t> v;
            for(size_t i=0;i+1<s.size();i+=2) v.push_back((uint8_t)std::stoi(s.substr(i,2),nullptr,16)); return v; };

        auto ossl_pub = [](const uint8_t sk[32], uint8_t pub[32])->bool{
            EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32);
            if(!k) return false; size_t l=32; int ok=EVP_PKEY_get_raw_public_key(k, pub, &l);
            EVP_PKEY_free(k); return ok==1 && l==32; };
        auto ossl_ecdh = [](const uint8_t sk[32], const uint8_t peer[32], uint8_t out[32])->int{
            EVP_PKEY* a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32);
            EVP_PKEY* p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer, 32);
            int rc=-1; if(a&&p){ EVP_PKEY_CTX* c=EVP_PKEY_CTX_new(a,nullptr);
                if(c && EVP_PKEY_derive_init(c)==1 && EVP_PKEY_derive_set_peer(c,p)==1){
                    size_t l=32; if(EVP_PKEY_derive(c,out,&l)==1 && l==32) rc=0; }
                if(c) EVP_PKEY_CTX_free(c); }
            if(a) EVP_PKEY_free(a); if(p) EVP_PKEY_free(p); return rc; };

        // (1) cross-validation vs OpenSSL: pubkey derivation + ECDH + DH symmetry.
        {
            bool pub_ok=true, dh_ok=true, sym_ok=true; long at=-1;
            for(int t=0;t<64 && pub_ok && dh_ok && sym_ok;++t){
                uint8_t a[32], b[32];
                for(int i=0;i<32;i++){ a[i]=(uint8_t)((i*37u+t*7u+1u)&0xff); b[i]=(uint8_t)((i*53u+t*11u+9u)&0xff); }
                uint8_t myA[32], myB[32], oA[32], oB[32];
                determ_x25519_base(myA, a); determ_x25519_base(myB, b);
                if(!ossl_pub(a,oA) || !ossl_pub(b,oB)){ pub_ok=false; at=t; continue; }
                if(std::memcmp(myA,oA,32)!=0 || std::memcmp(myB,oB,32)!=0){ pub_ok=false; at=t; continue; }
                uint8_t ssAB[32], ssBA[32], oss[32];
                determ_x25519(ssAB, a, myB); determ_x25519(ssBA, b, myA);
                ossl_ecdh(a, oB, oss);
                if(std::memcmp(ssAB,oss,32)!=0){ dh_ok=false; at=t; continue; }
                if(std::memcmp(ssAB,ssBA,32)!=0){ sym_ok=false; at=t; continue; }
            }
            check(pub_ok, pub_ok ? "X25519 base-mult C99 == OpenSSL EVP_PKEY_X25519 public key (fuzzed scalars)"
                                 : "X25519 pubkey diverges from OpenSSL (t="+std::to_string(at)+")");
            check(dh_ok, dh_ok ? "X25519 ECDH C99 == OpenSSL EVP_PKEY_derive (the §Q9 gate)"
                               : "X25519 ECDH diverges from OpenSSL (t="+std::to_string(at)+")");
            check(sym_ok, sym_ok ? "X25519 DH is symmetric: X25519(a,[b]B) == X25519(b,[a]B)"
                                 : "X25519 DH asymmetry (t="+std::to_string(at)+")");
        }

        // (2) RFC 7748 §6.1 known-answer vectors (OpenSSL-independent anchor).
        {
            auto a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            auto b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            uint8_t pa[32], pb[32], kab[32], kba[32];
            determ_x25519_base(pa, a.data()); determ_x25519_base(pb, b.data());
            check(hx(pa,32)=="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                  "X25519 RFC 7748 §6.1: Alice public key matches KAT");
            check(hx(pb,32)=="de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                  "X25519 RFC 7748 §6.1: Bob public key matches KAT");
            determ_x25519(kab, a.data(), pb); determ_x25519(kba, b.data(), pa);
            check(hx(kab,32)=="4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                  "X25519 RFC 7748 §6.1: shared secret matches KAT");
            check(std::memcmp(kab,kba,32)==0, "X25519 RFC 7748 §6.1: both parties derive the same secret");
        }

        // (3) low-order point rejection: X25519(scalar, all-zero u) is the all-zero
        //     low-order result and must return -1 (RFC 7748 contributory check).
        {
            uint8_t sk[32], lo[32]={0}, out[32];
            for(int i=0;i<32;i++) sk[i]=(uint8_t)(i*3+1);
            check(determ_x25519(out, sk, lo)==-1, "X25519 rejects the all-zero low-order point (-1)");
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": x25519-c99 "
                  << (fail==0 ? "all cross-validation + RFC 7748 KATs matched" : "had failures")
                  << " (libsodium-free C99 X25519 vs OpenSSL — the §Q9 gate; constant-time Montgomery ladder)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-p256-c99") {
        // CRYPTO-C99-SPEC §3.8c — the from-scratch C99 NIST P-256 vs the
        // OpenSSL EC oracle. ORDERING MATTERS: assertion (1) proves our
        // in-source curve constants byte-equal OpenSSL's EC_GROUP — that is
        // what converts the hand-transcribed p/n/b/Gx/Gy from "trusted from
        // memory" into "mechanically verified" before any arithmetic is
        // trusted. Then base-mult byte-equality over a scalar grid (the §Q9
        // gate), ECDH parity + symmetry, commutativity, and the reject paths.
        int fail = 0;
        auto check = [&](bool c, const std::string& m) {
            if (c) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };

        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        BN_CTX* bnctx = BN_CTX_new();
        if (!grp || !bnctx) { std::cout << "  FAIL: OpenSSL P-256 group init\n"; return 1; }

        // (1) Curve-constant parity: our p/n/b/Gx/Gy == OpenSSL EC_GROUP.
        {
            uint8_t p_be[32], n_be[32], b_be[32], gx_be[32], gy_be[32];
            determ_p256_params(p_be, n_be, b_be, gx_be, gy_be);
            BIGNUM *bp = BN_new(), *ba = BN_new(), *bb = BN_new(), *bn = BN_new(),
                   *bx = BN_new(), *by = BN_new();
            uint8_t o[32];
            bool ok = EC_GROUP_get_curve_GFp(grp, bp, ba, bb, bnctx) == 1;
            ok = ok && EC_GROUP_get_order(grp, bn, bnctx) == 1;
            const EC_POINT* g = EC_GROUP_get0_generator(grp);
            ok = ok && EC_POINT_get_affine_coordinates_GFp(grp, g, bx, by, bnctx) == 1;
            ok = ok && BN_bn2binpad(bp, o, 32) == 32 && std::memcmp(o, p_be, 32) == 0;
            ok = ok && BN_bn2binpad(bn, o, 32) == 32 && std::memcmp(o, n_be, 32) == 0;
            ok = ok && BN_bn2binpad(bb, o, 32) == 32 && std::memcmp(o, b_be, 32) == 0;
            ok = ok && BN_bn2binpad(bx, o, 32) == 32 && std::memcmp(o, gx_be, 32) == 0;
            ok = ok && BN_bn2binpad(by, o, 32) == 32 && std::memcmp(o, gy_be, 32) == 0;
            // a = -3 mod p: a + 3 == p
            ok = ok && BN_add_word(ba, 3) == 1 && BN_cmp(ba, bp) == 0;
            BN_free(bp); BN_free(ba); BN_free(bb); BN_free(bn); BN_free(bx); BN_free(by);
            check(ok, "(1) curve constants p/n/b/Gx/Gy byte-equal OpenSSL EC_GROUP; a == -3 mod p "
                      "(the gate that makes the in-source constants trustworthy)");
        }

        // OpenSSL-side scalar mult helper: out65 = [k] (Q or G).
        auto ossl_mul = [&](uint8_t out65[65], const uint8_t k_be[32],
                            const uint8_t* q65 /* nullptr = base */) -> bool {
            BIGNUM* k = BN_bin2bn(k_be, 32, nullptr);
            EC_POINT* r = EC_POINT_new(grp);
            EC_POINT* q = nullptr;
            bool ok = k && r;
            if (ok && q65) {
                q = EC_POINT_new(grp);
                ok = q && EC_POINT_oct2point(grp, q, q65, 65, bnctx) == 1;
            }
            if (ok) ok = EC_POINT_mul(grp, r, q65 ? nullptr : k, q, q65 ? k : nullptr, bnctx) == 1;
            if (ok) ok = EC_POINT_point2oct(grp, r, POINT_CONVERSION_UNCOMPRESSED,
                                            out65, 65, bnctx) == 65;
            if (q) EC_POINT_free(q);
            if (r) EC_POINT_free(r);
            if (k) BN_free(k);
            return ok;
        };
        // Deterministic in-range scalars (top byte forced low => < n).
        auto mk_scalar = [](uint8_t s[32], uint32_t seed) {
            for (int i = 0; i < 32; i++) s[i] = (uint8_t)((seed * 2654435761u + i * 40503u) >> ((i % 3) * 8));
            s[0] &= 0x0f;
            s[31] |= 1;          /* never zero */
        };

        // (2) base_mul byte-equal vs OpenSSL over a scalar grid (incl. k=1, k=2).
        {
            bool ok = true; uint32_t at = 0;
            for (uint32_t it = 0; it < 12 && ok; it++) {
                uint8_t k[32] = {0}, mine[65], theirs[65];
                if (it == 0) k[31] = 1;
                else if (it == 1) k[31] = 2;
                else mk_scalar(k, it * 0x9e37u + 7);
                if (determ_p256_base_mul(mine, k) != 0
                    || !ossl_mul(theirs, k, nullptr)
                    || std::memcmp(mine, theirs, 65) != 0) { ok = false; at = it; }
            }
            check(ok, ok ? "(2) [k]G byte-equal vs OpenSSL over 12-scalar grid incl. k=1,2 — the §Q9 gate"
                         : "(2) base_mul diverged from OpenSSL at grid index " + std::to_string(at));
        }

        // (3) point_mul parity + ECDH symmetry: [a]([b]G) == [b]([a]G) == OpenSSL.
        {
            uint8_t a[32], b[32], pa[65], pb[65], s1[65], s2[65], theirs[65];
            mk_scalar(a, 101); mk_scalar(b, 202);
            bool ok = determ_p256_base_mul(pa, a) == 0 && determ_p256_base_mul(pb, b) == 0
                   && determ_p256_point_mul(s1, a, pb) == 0
                   && determ_p256_point_mul(s2, b, pa) == 0
                   && std::memcmp(s1, s2, 65) == 0
                   && ossl_mul(theirs, a, pb)
                   && std::memcmp(s1, theirs, 65) == 0;
            check(ok, "(3) ECDH: [a]([b]G) == [b]([a]G) and byte-equal vs OpenSSL point-mult");
        }

        // (4) commutativity chain on a non-generator base: [k1]([k2]P) == [k2]([k1]P).
        {
            uint8_t k1[32], k2[32], k3[32], p0[65], t1[65], t2[65], r1[65], r2[65];
            mk_scalar(k1, 11); mk_scalar(k2, 22); mk_scalar(k3, 33);
            bool ok = determ_p256_base_mul(p0, k3) == 0
                   && determ_p256_point_mul(t1, k2, p0) == 0
                   && determ_p256_point_mul(r1, k1, t1) == 0
                   && determ_p256_point_mul(t2, k1, p0) == 0
                   && determ_p256_point_mul(r2, k2, t2) == 0
                   && std::memcmp(r1, r2, 65) == 0;
            check(ok, "(4) scalar-mult commutativity on a non-generator base point");
        }

        // (5) on-curve checks: valid point accepted; tampered coordinate,
        //     bad prefix, and coordinate >= p each rejected.
        {
            uint8_t k[32], p0[65], bad[65];
            mk_scalar(k, 55);
            bool ok = determ_p256_base_mul(p0, k) == 0
                   && determ_p256_point_check(p0) == 0;
            std::memcpy(bad, p0, 65); bad[40] ^= 1;          /* off-curve Y */
            ok = ok && determ_p256_point_check(bad) == -1;
            std::memcpy(bad, p0, 65); bad[0] = 0x02;         /* compressed prefix */
            ok = ok && determ_p256_point_check(bad) == -1;
            std::memcpy(bad, p0, 65);
            std::memset(bad + 1, 0xff, 32);                  /* X >= p */
            ok = ok && determ_p256_point_check(bad) == -1;
            ok = ok && determ_p256_point_mul(p0, k, bad) == -1;  /* mul refuses bad point */
            check(ok, "(5) point checks: valid accepted; off-curve / bad-prefix / X>=p rejected (mul refuses too)");
        }

        // (6) scalar validity gates: 0 and n rejected; n-1 accepted and
        //     [n-1]G == -G (same X as G, Y = p - Gy).
        {
            uint8_t zero[32] = {0}, nval[32], nm1[32], out[65];
            uint8_t p_be[32], n_be[32], b_be[32], gx_be[32], gy_be[32];
            determ_p256_params(p_be, n_be, b_be, gx_be, gy_be);
            std::memcpy(nval, n_be, 32);
            std::memcpy(nm1, n_be, 32); nm1[31] -= 1;        /* n ends 0x51 — no borrow */
            bool ok = determ_p256_base_mul(out, zero) == -1
                   && determ_p256_base_mul(out, nval) == -1
                   && determ_p256_base_mul(out, nm1) == 0
                   && std::memcmp(out + 1, gx_be, 32) == 0
                   && std::memcmp(out + 33, gy_be, 32) != 0;
            // Y((n-1)G) == p - Gy: verify by big-endian byte addition Y + Gy == p.
            if (ok) {
                uint32_t carry = 0; uint8_t sum[32];
                for (int i = 31; i >= 0; i--) {
                    uint32_t v = (uint32_t)out[33 + i] + gy_be[i] + carry;
                    sum[i] = (uint8_t)v; carry = v >> 8;
                }
                ok = (carry == 0) && std::memcmp(sum, p_be, 32) == 0;
            }
            check(ok, "(6) scalar gates: 0 and n rejected; [n-1]G == -G (X matches G, Y + Gy == p)");
        }

        EC_GROUP_free(grp); BN_CTX_free(bnctx);
        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": p256-c99 " << (fail == 0
                      ? "constants + scalar-mult byte-equal vs OpenSSL; reject gates held (CRYPTO-C99-SPEC §3.8c)"
                      : "had assertion failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    if (cmd == "test-p256-h2c-c99") {
        // CRYPTO-C99-SPEC §3.9b groundwork — mod-n scalar arithmetic vs the
        // OpenSSL BIGNUM oracle, and the RFC 9380 P256_XMD:SHA-256_SSWU_RO_
        // hash-to-curve's structural contract (on-curve always, deterministic,
        // msg- and DST-sensitive, bounds rejected). The RFC appendix
        // byte-vectors live in tools/vectors/p256_h2c.json and are consumed by
        // `determ test-c99-vectors` (binary half) + the file-side runner —
        // this subcommand is the oracle/structural leg.
        int fail = 0;
        auto check = [&](bool c, const std::string& m) {
            if (c) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };
        auto mk_scalar = [](uint8_t s[32], uint32_t seed) {
            for (int i = 0; i < 32; i++) s[i] = (uint8_t)((seed * 2654435761u + i * 40503u) >> ((i % 3) * 8));
            s[0] &= 0x0f; s[31] |= 1;
        };

        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        BN_CTX* bnctx = BN_CTX_new();
        BIGNUM* order = BN_new();
        if (!grp || !bnctx || !order || EC_GROUP_get_order(grp, order, bnctx) != 1) {
            std::cout << "  FAIL: OpenSSL group/order init\n"; return 1;
        }

        // (1) scalar_mul_mod_n == BN_mod_mul over a grid.
        {
            bool ok = true; uint32_t at = 0;
            for (uint32_t it = 0; it < 10 && ok; it++) {
                uint8_t a[32], b[32], mine[32], theirs[32];
                mk_scalar(a, it * 3 + 1); mk_scalar(b, it * 7 + 2);
                BIGNUM *ba = BN_bin2bn(a, 32, nullptr), *bb = BN_bin2bn(b, 32, nullptr),
                       *br = BN_new();
                bool step = determ_p256_scalar_mul_mod_n(mine, a, b) == 0
                         && BN_mod_mul(br, ba, bb, order, bnctx) == 1
                         && BN_bn2binpad(br, theirs, 32) == 32
                         && std::memcmp(mine, theirs, 32) == 0;
                BN_free(ba); BN_free(bb); BN_free(br);
                if (!step) { ok = false; at = it; }
            }
            check(ok, ok ? "(1) scalar_mul_mod_n == OpenSSL BN_mod_mul over a 10-pair grid"
                         : "(1) mod-n mul diverged at grid index " + std::to_string(at));
        }

        // (2) scalar_inv_mod_n == BN_mod_inverse; a * a^{-1} == 1 through OUR mul.
        {
            bool ok = true;
            for (uint32_t it = 0; it < 6 && ok; it++) {
                uint8_t a[32], inv[32], theirs[32], prod[32], one[32] = {0};
                one[31] = 1;
                mk_scalar(a, it * 11 + 5);
                BIGNUM *ba = BN_bin2bn(a, 32, nullptr), *br = BN_new();
                ok = determ_p256_scalar_inv_mod_n(inv, a) == 0
                  && BN_mod_inverse(br, ba, order, bnctx) != nullptr
                  && BN_bn2binpad(br, theirs, 32) == 32
                  && std::memcmp(inv, theirs, 32) == 0
                  && determ_p256_scalar_mul_mod_n(prod, a, inv) == 0
                  && std::memcmp(prod, one, 32) == 0;
                BN_free(ba); BN_free(br);
            }
            check(ok, "(2) scalar_inv_mod_n == BN_mod_inverse; a * a^-1 == 1 through our own mul");
        }

        // (3) mod-n validity gates: zero / >= n rejected on both entry points.
        {
            uint8_t zero[32] = {0}, big[32], a[32], out[32];
            std::memset(big, 0xff, 32);
            mk_scalar(a, 99);
            bool ok = determ_p256_scalar_inv_mod_n(out, zero) == -1
                   && determ_p256_scalar_inv_mod_n(out, big) == -1
                   && determ_p256_scalar_mul_mod_n(out, big, a) == -1
                   && determ_p256_scalar_mul_mod_n(out, a, big) == -1;
            check(ok, "(3) mod-n gates: zero and >= n rejected by mul (both operands) and inv");
        }

        // (4) expand_message_xmd: deterministic; outlen-exact; bounds rejected.
        {
            const uint8_t* m = (const uint8_t*)"determ h2c";
            const uint8_t* d = (const uint8_t*)"DETERM-TEST-DST";
            uint8_t o1[96], o2[96], o3[32];
            bool ok = determ_p256_expand_message_xmd(o1, 96, m, 10, d, 15) == 0
                   && determ_p256_expand_message_xmd(o2, 96, m, 10, d, 15) == 0
                   && std::memcmp(o1, o2, 96) == 0
                   && determ_p256_expand_message_xmd(o3, 32, m, 10, d, 15) == 0
                   /* len_in_bytes is bound into b0 (I2OSP(outlen,2)) — outputs
                    * for DIFFERENT lengths are domain-separated, so the 32B
                    * output must NOT be the 96B prefix (RFC 9380 §5.3.1). */
                   && std::memcmp(o1, o3, 32) != 0
                   && determ_p256_expand_message_xmd(o1, 0, m, 10, d, 15) == -1;
            std::vector<uint8_t> longdst(256, 0x41);
            ok = ok && determ_p256_expand_message_xmd(o1, 96, m, 10, longdst.data(), 256) == -1;
            check(ok, "(4) expand_message_xmd: deterministic; outlen domain-separated (32B != 96B prefix); outlen=0 / dstlen>255 rejected");
        }

        // (5) hash_to_curve structural: ALWAYS on-curve over a message grid;
        //     deterministic; msg-sensitive; DST-sensitive.
        {
            const uint8_t* dst = (const uint8_t*)"DETERM-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_";
            size_t dstlen = 46;
            bool ok = true; uint32_t at = 0;
            uint8_t prev[65] = {0};
            for (uint32_t it = 0; it < 16 && ok; it++) {
                uint8_t msg[40], pt_[65], pt2[65];
                for (int i = 0; i < 40; i++) msg[i] = (uint8_t)(it * 17 + i * 3);
                size_t mlen = (it % 5) * 9;          /* lengths 0,9,18,27,36 */
                if (determ_p256_hash_to_curve(pt_, msg, mlen, dst, dstlen) != 0
                    || determ_p256_point_check(pt_) != 0) { ok = false; at = it; break; }
                if (determ_p256_hash_to_curve(pt2, msg, mlen, dst, dstlen) != 0
                    || std::memcmp(pt_, pt2, 65) != 0) { ok = false; at = it; break; }
                if (it > 0 && (it % 5) != 0 && std::memcmp(pt_, prev, 65) == 0) { ok = false; at = it; break; }
                std::memcpy(prev, pt_, 65);
            }
            check(ok, ok ? "(5) hash_to_curve: on-curve + deterministic over a 16-msg grid (lengths 0..36)"
                         : "(5) h2c structural failure at grid index " + std::to_string(at));
            uint8_t a1[65], a2[65];
            const uint8_t* m2 = (const uint8_t*)"same-msg";
            bool ok2 = determ_p256_hash_to_curve(a1, m2, 8, dst, dstlen) == 0
                    && determ_p256_hash_to_curve(a2, m2, 8, (const uint8_t*)"OTHER-DST", 9) == 0
                    && std::memcmp(a1, a2, 65) != 0;
            check(ok2, "(6) hash_to_curve: DST-sensitivity (same msg, different DST -> different point)");
        }

        // (7) point_add == OpenSSL EC_POINT_add over a grid; [a]G + [b]G ==
        //     [a+b mod n]G through our own mod-n add path; P + (-P) -> -1.
        {
            bool ok = true;
            for (uint32_t it = 0; it < 6 && ok; it++) {
                uint8_t a[32], b[32], pa[65], pb[65], mine[65], theirs[65], sum[32], ps[65];
                mk_scalar(a, it * 13 + 3); mk_scalar(b, it * 29 + 8);
                ok = determ_p256_base_mul(pa, a) == 0 && determ_p256_base_mul(pb, b) == 0
                  && determ_p256_point_add(mine, pa, pb) == 0;
                // OpenSSL side
                if (ok) {
                    EC_POINT *qa = EC_POINT_new(grp), *qb = EC_POINT_new(grp), *qr = EC_POINT_new(grp);
                    ok = qa && qb && qr
                      && EC_POINT_oct2point(grp, qa, pa, 65, bnctx) == 1
                      && EC_POINT_oct2point(grp, qb, pb, 65, bnctx) == 1
                      && EC_POINT_add(grp, qr, qa, qb, bnctx) == 1
                      && EC_POINT_point2oct(grp, qr, POINT_CONVERSION_UNCOMPRESSED, theirs, 65, bnctx) == 65
                      && std::memcmp(mine, theirs, 65) == 0;
                    if (qa) EC_POINT_free(qa); if (qb) EC_POINT_free(qb); if (qr) EC_POINT_free(qr);
                }
                // [a]G + [b]G == [(a+b) mod n]G via our mod-n machinery:
                // sum = (a*1 + b*1)... no add API exported; use mul trick:
                // (a + b) mod n == (a*inv(x) ... ) — simplest: BN computes sum.
                if (ok) {
                    BIGNUM *ba = BN_bin2bn(a, 32, nullptr), *bb = BN_bin2bn(b, 32, nullptr), *bs = BN_new();
                    ok = BN_mod_add(bs, ba, bb, order, bnctx) == 1
                      && BN_bn2binpad(bs, sum, 32) == 32
                      && determ_p256_base_mul(ps, sum) == 0
                      && std::memcmp(mine, ps, 65) == 0;
                    BN_free(ba); BN_free(bb); BN_free(bs);
                }
            }
            // P + (-P) = infinity -> -1 (negate by flipping Y: y' = p - y).
            if (ok) {
                uint8_t k[32], p0[65], pn[65], o[65];
                uint8_t p_be[32], n_be[32], b_be[32], gx_be[32], gy_be[32];
                determ_p256_params(p_be, n_be, b_be, gx_be, gy_be);
                mk_scalar(k, 77);
                ok = determ_p256_base_mul(p0, k) == 0;
                if (ok) {
                    std::memcpy(pn, p0, 65);
                    uint32_t borrow = 0;                  /* y' = p - y, big-endian */
                    for (int i = 31; i >= 0; i--) {
                        int32_t d = (int32_t)p_be[i] - pn[33 + i] - (int32_t)borrow;
                        borrow = d < 0; if (d < 0) d += 256;
                        pn[33 + i] = (uint8_t)d;
                    }
                    ok = determ_p256_point_check(pn) == 0
                      && determ_p256_point_add(o, p0, pn) == -1;
                }
            }
            check(ok, "(7) point_add == OpenSSL EC_POINT_add; [a]G+[b]G == [(a+b) mod n]G; P + (-P) -> -1");
        }

        // (8) hash_to_scalar: output < n always; deterministic; DST-sensitive.
        {
            uint8_t n_be[32], p_be[32], b_be[32], gx_be[32], gy_be[32];
            determ_p256_params(p_be, n_be, b_be, gx_be, gy_be);
            const uint8_t* dst = (const uint8_t*)"DETERM-HashToScalar-TEST";
            bool ok = true;
            uint8_t s1[32], s2[32], s3[32];
            for (uint32_t it = 0; it < 12 && ok; it++) {
                uint8_t msg[24];
                for (int i = 0; i < 24; i++) msg[i] = (uint8_t)(it * 31 + i);
                ok = determ_p256_hash_to_scalar(s1, msg, 24, dst, 24) == 0
                  && determ_p256_hash_to_scalar(s2, msg, 24, dst, 24) == 0
                  && std::memcmp(s1, s2, 32) == 0;
                // < n: byte compare
                if (ok) { int lt = 0; for (int i = 0; i < 32; i++) { if (s1[i] < n_be[i]) { lt = 1; break; } if (s1[i] > n_be[i]) { lt = 0; break; } } ok = lt == 1; }
            }
            ok = ok && determ_p256_hash_to_scalar(s3, (const uint8_t*)"m", 1, (const uint8_t*)"OTHER", 5) == 0
                    && determ_p256_hash_to_scalar(s1, (const uint8_t*)"m", 1, dst, 24) == 0
                    && std::memcmp(s1, s3, 32) != 0;
            check(ok, "(8) hash_to_scalar: < n over a 12-msg grid; deterministic; DST-sensitive");
        }

        BN_free(order); EC_GROUP_free(grp); BN_CTX_free(bnctx);
        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": p256-h2c-c99 " << (fail == 0
                      ? "mod-n ops == OpenSSL BIGNUM; hash-to-curve structural contract held (§3.9b groundwork)"
                      : "had assertion failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }

    if (cmd == "test-sha3-c99") {
        // PQ prerequisite (FIPS 202): validate the C99 SHA-3/SHAKE (Keccak-f[1600])
        // the ML-DSA/Dilithium XOF sits on. (1) SHA3-256/512 byte-equal vs OpenSSL
        // EVP over a fuzzed length grid (the §Q9 oracle gate — full sponge absorb/
        // pad10*1/permute); (2) SHAKE128/256 byte-equal vs OpenSSL EVP DigestFinalXOF
        // over fuzzed lengths × output sizes incl. > rate (forces squeeze-permute);
        // (3) FIPS 202 KATs (empty + "abc"); (4) incremental absorb/squeeze == one-
        // shot across a squeeze-permute; (5) rate-boundary byte-by-byte == one-shot.
        using namespace determ;
        int fail=0;
        auto check=[&](bool c,const std::string&m){ if(c) std::cout<<"  PASS: "<<m<<"\n"; else {std::cout<<"  FAIL: "<<m<<"\n"; fail++;} };
        auto hx=[](const uint8_t*p,size_t n){ static const char*H="0123456789abcdef";
            std::string s; for(size_t i=0;i<n;i++){s.push_back(H[p[i]>>4]);s.push_back(H[p[i]&0xf]);} return s; };

        // (1) SHA3-256 + SHA3-512 vs OpenSSL EVP over fuzzed lengths (rate boundaries).
        {
            bool ok256=true, ok512=true; long at=-1;
            const size_t lens[]={0,1,71,72,73,135,136,137,168,200,255,256,272,1000};
            for(size_t li=0; li<sizeof(lens)/sizeof(lens[0]); ++li){
                size_t L=lens[li]; std::vector<uint8_t> in(L);
                for(size_t i=0;i<L;i++) in[i]=(uint8_t)((i*151u+L*11u+5u)&0xff);
                const uint8_t* ip = L?in.data():(const uint8_t*)"";
                uint8_t m256[32]; determ_sha3_256(m256, ip, L);
                uint8_t m512[64]; determ_sha3_512(m512, ip, L);
                uint8_t o256[32], o512[64]; unsigned int ol=0;
                EVP_Digest(ip, L, o256, &ol, EVP_sha3_256(), nullptr);
                EVP_Digest(ip, L, o512, &ol, EVP_sha3_512(), nullptr);
                if(std::memcmp(m256,o256,32)!=0){ ok256=false; at=(long)L; }
                if(std::memcmp(m512,o512,64)!=0){ ok512=false; at=(long)L; }
            }
            check(ok256, ok256 ? "SHA3-256 C99 == OpenSSL EVP_sha3_256 over fuzzed lengths (§Q9 gate)"
                               : "SHA3-256 diverges from OpenSSL (len="+std::to_string(at)+")");
            check(ok512, ok512 ? "SHA3-512 C99 == OpenSSL EVP_sha3_512 over fuzzed lengths (§Q9 gate)"
                               : "SHA3-512 diverges from OpenSSL (len="+std::to_string(at)+")");
        }

        // (2) SHAKE128 + SHAKE256 vs OpenSSL EVP DigestFinalXOF (fuzzed len × outlen incl. > rate).
        {
            bool ok128=true, ok256=true; long at=-1;
            const size_t lens[]={0,1,135,136,137,167,168,169,300};
            const size_t outs[]={1,16,31,32,136,168,200,512};
            for(size_t li=0; li<sizeof(lens)/sizeof(lens[0]) && ok128 && ok256; ++li){
                size_t L=lens[li]; std::vector<uint8_t> in(L);
                for(size_t i=0;i<L;i++) in[i]=(uint8_t)((i*97u+L*13u+7u)&0xff);
                const uint8_t* ip=L?in.data():(const uint8_t*)"";
                for(size_t oi=0; oi<sizeof(outs)/sizeof(outs[0]); ++oi){
                    size_t O=outs[oi];
                    std::vector<uint8_t> m128(O), m256v(O), o128(O), o256v(O);
                    determ_shake128(m128.data(),O,ip,L);
                    determ_shake256(m256v.data(),O,ip,L);
                    EVP_MD_CTX* c=EVP_MD_CTX_new();
                    EVP_DigestInit_ex(c,EVP_shake128(),nullptr); EVP_DigestUpdate(c,ip,L); EVP_DigestFinalXOF(c,o128.data(),O); EVP_MD_CTX_free(c);
                    c=EVP_MD_CTX_new();
                    EVP_DigestInit_ex(c,EVP_shake256(),nullptr); EVP_DigestUpdate(c,ip,L); EVP_DigestFinalXOF(c,o256v.data(),O); EVP_MD_CTX_free(c);
                    if(std::memcmp(m128.data(),o128.data(),O)!=0){ ok128=false; at=(long)(L*1000+O); }
                    if(std::memcmp(m256v.data(),o256v.data(),O)!=0){ ok256=false; at=(long)(L*1000+O); }
                }
            }
            check(ok128, ok128 ? "SHAKE128 C99 == OpenSSL EVP_shake128 over fuzzed len × outlen (incl. > rate)"
                               : "SHAKE128 diverges from OpenSSL (code="+std::to_string(at)+")");
            check(ok256, ok256 ? "SHAKE256 C99 == OpenSSL EVP_shake256 over fuzzed len × outlen (incl. > rate)"
                               : "SHAKE256 diverges from OpenSSL (code="+std::to_string(at)+")");
        }

        // (3) FIPS 202 known-answer vectors (independent of the OpenSSL oracle).
        {
            uint8_t d[64];
            determ_sha3_256(d,(const uint8_t*)"",0);
            check(hx(d,32)=="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a","SHA3-256(\"\") FIPS 202 KAT");
            determ_sha3_256(d,(const uint8_t*)"abc",3);
            check(hx(d,32)=="3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532","SHA3-256(\"abc\") FIPS 202 KAT");
            determ_sha3_512(d,(const uint8_t*)"",0);
            check(hx(d,64)=="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26","SHA3-512(\"\") FIPS 202 KAT");
            uint8_t s[32];
            determ_shake128(s,32,(const uint8_t*)"",0);
            check(hx(s,32)=="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26","SHAKE128(\"\",32) FIPS 202 KAT");
            determ_shake256(s,32,(const uint8_t*)"",0);
            check(hx(s,32)=="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f","SHAKE256(\"\",32) FIPS 202 KAT");
        }

        // (4) incremental absorb/squeeze == one-shot, output spanning a squeeze-permute.
        {
            std::vector<uint8_t> msg(500); for(size_t i=0;i<msg.size();i++) msg[i]=(uint8_t)(i*7+1);
            uint8_t one[137]; determ_shake256(one,137,msg.data(),msg.size());
            determ_keccak_ctx ctx; determ_shake256_init(&ctx);
            size_t off=0; const size_t chunks[]={1,5,63,136,137,100};
            for(size_t ci=0; off<msg.size(); ci=(ci+1)%(sizeof(chunks)/sizeof(chunks[0]))){
                size_t c=chunks[ci]; if(off+c>msg.size()) c=msg.size()-off;
                determ_keccak_absorb(&ctx,msg.data()+off,c); off+=c;
            }
            uint8_t inc[137]; size_t so=0; const size_t sc[]={1,7,128,1};
            for(size_t ci=0; so<137; ci=(ci+1)%(sizeof(sc)/sizeof(sc[0]))){
                size_t c=sc[ci]; if(so+c>137) c=137-so;
                determ_keccak_squeeze(&ctx,inc+so,c); so+=c;
            }
            check(std::memcmp(one,inc,137)==0, "SHAKE256 incremental absorb/squeeze == one-shot (137 B, spans squeeze-permute)");
        }

        // (5) rate-boundary byte-by-byte absorb == one-shot (SHA3-256, rate 136).
        {
            bool ok=true; long at=-1;
            const size_t bl[]={135u,136u,137u,272u};
            for(size_t bi=0; bi<sizeof(bl)/sizeof(bl[0]); ++bi){
                size_t L=bl[bi]; std::vector<uint8_t> in(L); for(size_t i=0;i<L;i++) in[i]=(uint8_t)(i&0xff);
                uint8_t a[32]; determ_sha3_256(a,in.data(),L);
                determ_keccak_ctx ctx; determ_keccak_init(&ctx,DETERM_SHA3_256_RATE,DETERM_SHA3_DOMAIN);
                for(size_t i=0;i<L;i++) determ_keccak_absorb(&ctx,in.data()+i,1);
                uint8_t b[32]; determ_keccak_squeeze(&ctx,b,32);
                if(std::memcmp(a,b,32)!=0){ ok=false; at=(long)L; }
            }
            check(ok, ok ? "SHA3-256 rate-boundary (135/136/137/272 B) byte-by-byte absorb == one-shot"
                         : "SHA3-256 rate-boundary mismatch (len="+std::to_string(at)+")");
        }

        std::cout << (fail? "  FAIL: sha3-c99 unit test\n" : "  PASS: sha3-c99 unit test\n");
        return fail?1:0;
    }

    if (cmd == "test-blake2b-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.6 prerequisite: validate the
        // libsodium-free C99 BLAKE2b (RFC 7693) — (1) the unkeyed 64-byte digest
        // byte-equal vs OpenSSL EVP_blake2b512 over a fuzzed message-length grid
        // (the §Q9 gate: full compression / G / SIGMA / IV / finalize); (2) keyed +
        // variable-length outputs vs python hashlib.blake2b reference vectors
        // (OpenSSL's EVP exposes only the unkeyed 64-byte digest); (3) incremental
        // update == one-shot; (4) keyed/varlen wiring + parameter-error handling.
        using namespace determ;
        int fail=0;
        auto check=[&](bool c,const std::string&m){ if(c) std::cout<<"  PASS: "<<m<<"\n"; else {std::cout<<"  FAIL: "<<m<<"\n"; fail++;} };
        auto hx=[](const uint8_t*p,size_t n){ static const char*H="0123456789abcdef";
            std::string s; for(size_t i=0;i<n;i++){s.push_back(H[p[i]>>4]);s.push_back(H[p[i]&0xf]);} return s; };

        // (1) unkeyed 64-byte vs OpenSSL EVP_blake2b512 over fuzzed lengths.
        {
            bool ok=true; long at=-1;
            const size_t lens[]={0,1,63,64,65,127,128,129,200,255,256,1000};
            for(size_t li=0; li<sizeof(lens)/sizeof(lens[0]) && ok; ++li){
                size_t L=lens[li]; std::vector<uint8_t> in(L);
                for(size_t i=0;i<L;i++) in[i]=(uint8_t)((i*131u+L*7u+3u)&0xff);
                uint8_t mine[64]; determ_blake2b(mine,64,nullptr,0, L?in.data():nullptr, L);
                uint8_t o[64]; unsigned int ol=64;
                EVP_Digest(L?in.data():(const uint8_t*)"", L, o, &ol, EVP_blake2b512(), nullptr);
                if(ol!=64 || std::memcmp(mine,o,64)!=0){ ok=false; at=(long)L; }
            }
            check(ok, ok ? "BLAKE2b-512 (unkeyed) C99 == OpenSSL EVP_blake2b512 over fuzzed lengths — the §Q9 gate"
                         : "BLAKE2b-512 diverges from OpenSSL (len="+std::to_string(at)+")");
        }

        // (2) keyed + variable-length vs python hashlib.blake2b reference vectors
        //     (independent BLAKE2 implementation; key="determ-blake2b-key", msg="the quick brown fox").
        {
            const uint8_t* key=(const uint8_t*)"determ-blake2b-key"; size_t kl=18;
            const uint8_t* msg=(const uint8_t*)"the quick brown fox"; size_t ml=19;
            uint8_t e[64], k64[64], k32[32];
            determ_blake2b(e,32,nullptr,0,(const uint8_t*)"",0);
            check(hx(e,32)=="0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                  "BLAKE2b-256(\"\") matches hashlib.blake2b KAT");
            uint8_t a32[32]; determ_blake2b(a32,32,nullptr,0,(const uint8_t*)"abc",3);
            check(hx(a32,32)=="bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
                  "BLAKE2b-256(\"abc\") matches hashlib.blake2b KAT");
            determ_blake2b(k64,64,key,kl,msg,ml);
            check(hx(k64,64)=="467b88348d04e56da92f5a3e1104c105f52d2ab78d7ca7a3254960a421f1c52a"
                              "8179527f3078f36f6b580fa780006accb53de5c4542682a5f2e028931513bd31",
                  "BLAKE2b-512 keyed matches hashlib.blake2b KAT");
            determ_blake2b(k32,32,key,kl,msg,ml);
            check(hx(k32,32)=="445f0e39ac1104d8617762a91cef6cfb95b0426f15d5ede9087cf4b7d07a1106",
                  "BLAKE2b-256 keyed matches hashlib.blake2b KAT");
        }

        // (3) incremental update == one-shot (unkeyed-64, keyed-64, unkeyed-32, keyed-32).
        {
            std::vector<uint8_t> msg(250); for(size_t i=0;i<msg.size();i++) msg[i]=(uint8_t)(i*7+1);
            uint8_t key[40]; for(int i=0;i<40;i++) key[i]=(uint8_t)(i*5+2);
            struct { size_t outlen, keylen; } cfg[]={{64,0},{64,40},{32,0},{32,40}};
            bool inc_ok=true;
            for(auto&c:cfg){
                uint8_t one[64], inc[64];
                determ_blake2b(one, c.outlen, c.keylen?key:nullptr, c.keylen, msg.data(), msg.size());
                determ_blake2b_ctx ctx; determ_blake2b_init(&ctx, c.outlen, c.keylen?key:nullptr, c.keylen);
                size_t off=0; const size_t chunks[]={1,63,64,1,121};   // sums to 250
                for(size_t ci=0; ci<5; ++ci){ determ_blake2b_update(&ctx, msg.data()+off, chunks[ci]); off+=chunks[ci]; }
                determ_blake2b_final(&ctx, inc);
                if(std::memcmp(one,inc,c.outlen)!=0) inc_ok=false;
            }
            check(inc_ok, "BLAKE2b incremental update == one-shot (unkeyed/keyed x 64/32-byte out)");
        }

        // (4) keyed != unkeyed; output-length is in the param block; parameter errors.
        {
            const char* m="determ"; size_t ml=6; uint8_t k[16]; for(int i=0;i<16;i++) k[i]=(uint8_t)(i+1);
            uint8_t a[64], b[64], c32[32], junk[64];
            determ_blake2b(a,64,nullptr,0,(const uint8_t*)m,ml);
            determ_blake2b(b,64,k,16,(const uint8_t*)m,ml);
            check(std::memcmp(a,b,64)!=0, "BLAKE2b keyed output differs from unkeyed");
            determ_blake2b(c32,32,nullptr,0,(const uint8_t*)m,ml);
            check(std::memcmp(a,c32,32)!=0, "BLAKE2b-256 is not a prefix of BLAKE2b-512 (output-length in param block)");
            check(determ_blake2b(junk,0,nullptr,0,(const uint8_t*)m,ml)==-1, "BLAKE2b rejects outlen=0");
            check(determ_blake2b(junk,65,nullptr,0,(const uint8_t*)m,ml)==-1, "BLAKE2b rejects outlen>64");
            check(determ_blake2b(junk,64,k,65,(const uint8_t*)m,ml)==-1, "BLAKE2b rejects keylen>64");
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": blake2b-c99 "
                  << (fail==0 ? "all cross-validation + KATs matched" : "had failures")
                  << " (libsodium-free C99 BLAKE2b vs OpenSSL EVP_blake2b512 + hashlib.blake2b KATs — RFC 7693; Argon2id prereq)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-xchacha-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.4: validate the libsodium-free C99
        // XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) — (1) HChaCha20 vs the draft
        // §2.2.1 KAT (an independent from-scratch reference); (2) the full AEAD
        // byte-equal vs OpenSSL's inner ChaCha20-Poly1305 on the derived
        // (subkey, 96-bit nonce) — XChaCha20-Poly1305 is DEFINED as that composition
        // and (1) pins HChaCha20, so this is the §Q9 gate; (3) decrypt round-trip +
        // tamper rejection (tag / ciphertext / AAD / nonce).
        using namespace determ;
        int fail=0;
        auto check=[&](bool c,const std::string&m){ if(c) std::cout<<"  PASS: "<<m<<"\n"; else {std::cout<<"  FAIL: "<<m<<"\n"; fail++;} };
        auto hx=[](const uint8_t*p,size_t n){ static const char*H="0123456789abcdef";
            std::string s; for(size_t i=0;i<n;i++){s.push_back(H[p[i]>>4]);s.push_back(H[p[i]&0xf]);} return s; };

        // (1) HChaCha20 draft §2.2.1 KAT (key=00..1f, nonce=00000009 0000004a 00000000 31415927).
        {
            uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)i;
            uint8_t n16[16]={0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0, 0x31,0x41,0x59,0x27};
            uint8_t sub[32]; determ_hchacha20(sub,key,n16);
            check(hx(sub,32)=="82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
                  "HChaCha20 matches draft-irtf-cfrg-xchacha §2.2.1 KAT");
        }

        // (2) full AEAD byte-equal vs OpenSSL ChaCha20-Poly1305 on the derived
        //     (subkey, 0x00000000||nonce24[16:24]) across a (pt,aad)-length grid.
        {
            bool ct_ok=true, tag_ok=true; long at=-1;
            const size_t ptl[]={0,1,16,63,64,65,128,200};
            const size_t aadl[]={0,1,12,16,20};
            for(size_t pi=0;pi<sizeof(ptl)/sizeof(ptl[0])&&ct_ok&&tag_ok;++pi)
            for(size_t ai=0;ai<sizeof(aadl)/sizeof(aadl[0])&&ct_ok&&tag_ok;++ai){
                size_t pl=ptl[pi], al=aadl[ai];
                uint8_t key[32], n24[24];
                for(int i=0;i<32;i++) key[i]=(uint8_t)((i*41u+pi*7u+ai+1u)&0xff);
                for(int i=0;i<24;i++) n24[i]=(uint8_t)((i*17u+pi+ai*3u+2u)&0xff);
                std::vector<uint8_t> pt(pl), aad(al), ct(pl);
                for(size_t i=0;i<pl;i++) pt[i]=(uint8_t)((i*23u+pi+5u)&0xff);
                for(size_t i=0;i<al;i++) aad[i]=(uint8_t)((i*31u+ai+9u)&0xff);
                uint8_t mytag[16];
                determ_xchacha20_poly1305_encrypt(key,n24, al?aad.data():nullptr,al, pl?pt.data():nullptr,pl, ct.data(), mytag);
                uint8_t sub[32], n12[12]; determ_hchacha20(sub,key,n24);
                n12[0]=n12[1]=n12[2]=n12[3]=0; std::memcpy(n12+4,n24+16,8);
                std::vector<uint8_t> octt(pl); uint8_t otag[16];
                EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); int outl=0;
                EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
                EVP_EncryptInit_ex(c, nullptr, nullptr, sub, n12);
                if(al) EVP_EncryptUpdate(c, nullptr, &outl, aad.data(), (int)al);
                if(pl) EVP_EncryptUpdate(c, octt.data(), &outl, pt.data(), (int)pl);
                EVP_EncryptFinal_ex(c, octt.data()+(pl?(size_t)outl:0), &outl);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, otag);
                EVP_CIPHER_CTX_free(c);
                if(pl && std::memcmp(ct.data(),octt.data(),pl)!=0){ ct_ok=false; at=(long)(pl*100+al); }
                if(std::memcmp(mytag,otag,16)!=0){ tag_ok=false; at=(long)(pl*100+al); }
            }
            check(ct_ok && tag_ok, (ct_ok&&tag_ok)
                  ? "XChaCha20-Poly1305 C99 == OpenSSL inner ChaCha20-Poly1305 on the derived (subkey,nonce) — the §Q9 gate"
                  : "XChaCha20-Poly1305 diverges from OpenSSL (pl*100+al="+std::to_string(at)+")");
        }

        // (3) decrypt round-trip + tamper rejection.
        {
            uint8_t key[32], n24[24];
            for(int i=0;i<32;i++) key[i]=(uint8_t)(i*3+7);
            for(int i=0;i<24;i++) n24[i]=(uint8_t)(i+1);
            const char* m="the quick brown fox jumps over the lazy dog"; size_t pl=std::strlen(m);
            uint8_t aad[6]={9,8,7,6,5,4}; std::vector<uint8_t> ct(pl), back(pl); uint8_t tag[16];
            determ_xchacha20_poly1305_encrypt(key,n24, aad,6, (const uint8_t*)m,pl, ct.data(), tag);
            check(determ_xchacha20_poly1305_decrypt(key,n24, aad,6, ct.data(),pl, tag, back.data())==0
                  && std::memcmp(back.data(),m,pl)==0, "XChaCha20-Poly1305 decrypt round-trips the plaintext");
            uint8_t bad[16]; std::memcpy(bad,tag,16); bad[0]^=1;
            check(determ_xchacha20_poly1305_decrypt(key,n24, aad,6, ct.data(),pl, bad, back.data())==-1,
                  "XChaCha20-Poly1305 rejects a tampered tag");
            std::vector<uint8_t> ct2=ct; if(pl) ct2[0]^=1;
            check(determ_xchacha20_poly1305_decrypt(key,n24, aad,6, ct2.data(),pl, tag, back.data())==-1,
                  "XChaCha20-Poly1305 rejects tampered ciphertext");
            uint8_t aad2[6]={9,8,7,6,5,3};
            check(determ_xchacha20_poly1305_decrypt(key,n24, aad2,6, ct.data(),pl, tag, back.data())==-1,
                  "XChaCha20-Poly1305 rejects tampered AAD");
            uint8_t n24b[24]; std::memcpy(n24b,n24,24); n24b[20]^=1;
            check(determ_xchacha20_poly1305_decrypt(key,n24b, aad,6, ct.data(),pl, tag, back.data())==-1,
                  "XChaCha20-Poly1305 rejects a tampered nonce");
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": xchacha-c99 "
                  << (fail==0 ? "all cross-validation + KATs matched" : "had failures")
                  << " (libsodium-free C99 XChaCha20-Poly1305 + HChaCha20 — draft-irtf-cfrg-xchacha; the §Q9 gate)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-chacha20-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.4: validate the libsodium-free C99
        // ChaCha20 (RFC 8439) — the cipher half of the ChaCha20-Poly1305 AEAD
        // family — byte-equal against OpenSSL EVP_chacha20 over fuzzed
        // (key,counter,nonce,length) inputs. OpenSSL's EVP_chacha20 takes a
        // 16-byte IV = [32-bit counter LE][96-bit nonce], matching RFC 8439, so a
        // direct byte-equal comparison is the §Q9 gate (no transcribed vector).
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const std::string& m) {
            if (cond) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };

        // (1) Cross-validation vs OpenSSL EVP_chacha20 over a length/counter grid.
        bool xval = true; long at = -1;
        const size_t lens[] = {0,1,16,63,64,65,127,128,191,256,300};
        // Counter values stay well below 2^32 so no block-counter overflow occurs
        // within a message: RFC 8439 §2.3 leaves 32-bit-counter overflow undefined
        // (a message would need 2^32 blocks = 256 GiB to reach it), and impls
        // legitimately differ there (we wrap the 32-bit word per the RFC; OpenSSL
        // carries into the nonce). The AEAD always starts at counter 0/1 and never
        // overflows, so this is not a reachable correctness case.
        const uint32_t ctrs[] = {0,1,7,123456u};
        for (size_t ci=0; ci<sizeof(ctrs)/sizeof(ctrs[0]) && xval; ++ci)
        for (size_t li=0; li<sizeof(lens)/sizeof(lens[0]) && xval; ++li) {
            size_t len = lens[li]; uint32_t ctr = ctrs[ci];
            uint8_t key[32], nonce[12];
            for (int i=0;i<32;i++) key[i]=(uint8_t)((i*73u+ci*11u+len*3u+1u)&0xffu);
            for (int i=0;i<12;i++) nonce[i]=(uint8_t)((i*53u+li*7u+5u)&0xffu);
            std::vector<uint8_t> in(len), mine(len), ossl(len);
            for (size_t i=0;i<len;i++) in[i]=(uint8_t)((i*29u+ci+li+2u)&0xffu);
            determ_chacha20(key, ctr, nonce, in.data(), len, mine.data());
            uint8_t iv[16]; iv[0]=(uint8_t)ctr; iv[1]=(uint8_t)(ctr>>8); iv[2]=(uint8_t)(ctr>>16); iv[3]=(uint8_t)(ctr>>24);
            std::memcpy(iv+4, nonce, 12);
            EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
            int outl = 0;
            EVP_EncryptInit_ex(c, EVP_chacha20(), nullptr, key, iv);
            if (len) EVP_EncryptUpdate(c, ossl.data(), &outl, in.data(), (int)len);
            EVP_CIPHER_CTX_free(c);
            if (len && std::memcmp(mine.data(), ossl.data(), len)!=0){ xval=false; at=(long)(ctr*1000+len); }
        }
        check(xval, xval ? "ChaCha20 C99 == OpenSSL EVP_chacha20 over the (counter,length) grid"
                         : "ChaCha20 diverges (ctr*1000+len=" + std::to_string(at) + ")");

        // (2) Self-inverse: applying the keystream twice returns the plaintext.
        {
            uint8_t key[32], nonce[12];
            for (int i=0;i<32;i++) key[i]=(uint8_t)(i+1);
            for (int i=0;i<12;i++) nonce[i]=(uint8_t)(i*9+3);
            std::vector<uint8_t> pt(200), ct(200), back(200);
            for (size_t i=0;i<pt.size();i++) pt[i]=(uint8_t)(i*7+1);
            determ_chacha20(key, 5, nonce, pt.data(), pt.size(), ct.data());
            determ_chacha20(key, 5, nonce, ct.data(), ct.size(), back.data());
            check(std::memcmp(pt.data(), back.data(), pt.size())==0,
                  "ChaCha20 is self-inverse (encrypt twice -> plaintext)");
        }

        // (3) Counter sensitivity: changing the block counter changes the keystream.
        {
            uint8_t key[32]={0}, nonce[12]={0}, z[64]={0};
            uint8_t a[64], b[64];
            determ_chacha20(key, 0, nonce, z, 64, a);
            determ_chacha20(key, 1, nonce, z, 64, b);
            check(std::memcmp(a,b,64)!=0, "ChaCha20 keystream depends on the block counter");
        }

        // (4) Poly1305 RFC 8439 §2.5.2 known-answer vector.
        {
            auto hx = [](const uint8_t* p, size_t n){ static const char* H="0123456789abcdef";
                std::string s; for(size_t i=0;i<n;i++){ s.push_back(H[p[i]>>4]); s.push_back(H[p[i]&0xf]); } return s; };
            uint8_t pkey[32] = {0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
                                0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b};
            const char* pmsg = "Cryptographic Forum Research Group";
            uint8_t ptag[16];
            determ_poly1305(pkey, (const uint8_t*)pmsg, std::strlen(pmsg), ptag);
            check(hx(ptag,16)=="a8061dc1305136c6c22b8baf0c0127a9", "Poly1305 matches RFC 8439 §2.5.2 KAT");
        }

        // (5) ChaCha20-Poly1305 AEAD cross-validation vs OpenSSL EVP_chacha20_poly1305
        // (ciphertext AND tag) over a (plaintext,aad)-length grid.
        {
            bool aead_ok = true; long aat = -1;
            const size_t ptl[]  = {0,1,16,63,64,65,128,200};
            const size_t aadl[] = {0,1,12,16,20};
            for (size_t pi=0; pi<sizeof(ptl)/sizeof(ptl[0]) && aead_ok; ++pi)
            for (size_t ai=0; ai<sizeof(aadl)/sizeof(aadl[0]) && aead_ok; ++ai) {
                size_t pl=ptl[pi], al=aadl[ai];
                uint8_t key[32], nonce[12];
                for(int i=0;i<32;i++) key[i]=(uint8_t)((i*41u+pi*7u+ai+1u)&0xffu);
                for(int i=0;i<12;i++) nonce[i]=(uint8_t)((i*17u+pi+ai*3u+2u)&0xffu);
                std::vector<uint8_t> pt(pl), aad(al), ct(pl), octt(pl);
                for(size_t i=0;i<pl;i++) pt[i]=(uint8_t)((i*23u+pi+5u)&0xffu);
                for(size_t i=0;i<al;i++) aad[i]=(uint8_t)((i*31u+ai+9u)&0xffu);
                uint8_t mytag[16], otag[16];
                determ_chacha20_poly1305_encrypt(key,nonce, al?aad.data():nullptr,al,
                                                 pl?pt.data():nullptr,pl, ct.data(), mytag);
                EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
                int outl=0;
                EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
                EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce);
                if (al) EVP_EncryptUpdate(c, nullptr, &outl, aad.data(), (int)al);
                if (pl) EVP_EncryptUpdate(c, octt.data(), &outl, pt.data(), (int)pl);
                EVP_EncryptFinal_ex(c, octt.data() + (pl?(size_t)outl:0), &outl);
                EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, otag);
                EVP_CIPHER_CTX_free(c);
                bool ctmatch  = (pl==0) || (std::memcmp(ct.data(), octt.data(), pl)==0);
                bool tagmatch = std::memcmp(mytag, otag, 16)==0;
                if (!ctmatch || !tagmatch){ aead_ok=false; aat=(long)(pl*100+al); }
            }
            check(aead_ok, aead_ok ? "ChaCha20-Poly1305 AEAD C99 == OpenSSL EVP_chacha20_poly1305 (ciphertext + tag)"
                                   : "AEAD diverges from OpenSSL (pl*100+al=" + std::to_string(aat) + ")");
        }

        // (6) AEAD decrypt round-trip + tamper rejection (tag + ciphertext).
        {
            uint8_t key[32], nonce[12];
            for(int i=0;i<32;i++) key[i]=(uint8_t)(i*3+7);
            for(int i=0;i<12;i++) nonce[i]=(uint8_t)(i+1);
            const char* msg = "the quick brown fox jumps"; size_t pl=std::strlen(msg);
            uint8_t aad[5]={1,2,3,4,5};
            std::vector<uint8_t> ct(pl), back(pl); uint8_t tag[16];
            determ_chacha20_poly1305_encrypt(key,nonce, aad,5, (const uint8_t*)msg,pl, ct.data(), tag);
            int r = determ_chacha20_poly1305_decrypt(key,nonce, aad,5, ct.data(),pl, tag, back.data());
            check(r==0 && std::memcmp(back.data(), msg, pl)==0, "AEAD decrypt round-trips the plaintext");
            uint8_t badtag[16]; std::memcpy(badtag,tag,16); badtag[0]^=0x01;
            check(determ_chacha20_poly1305_decrypt(key,nonce, aad,5, ct.data(),pl, badtag, back.data())==-1,
                  "AEAD decrypt rejects a tampered tag");
            std::vector<uint8_t> ct2=ct; if(pl) ct2[0]^=0x01;
            check(determ_chacha20_poly1305_decrypt(key,nonce, aad,5, ct2.data(),pl, tag, back.data())==-1,
                  "AEAD decrypt rejects tampered ciphertext");
            // AAD-binding (the property S004KeyfileAtRest.md T-2 relies on): a flipped
            // or length-changed AAD must fail even with a valid ciphertext + tag.
            uint8_t aad2[5]={1,2,3,4,6};
            check(determ_chacha20_poly1305_decrypt(key,nonce, aad2,5, ct.data(),pl, tag, back.data())==-1,
                  "AEAD decrypt rejects tampered AAD (AAD-binding)");
            check(determ_chacha20_poly1305_decrypt(key,nonce, aad,4, ct.data(),pl, tag, back.data())==-1,
                  "AEAD decrypt rejects an AAD-length mismatch");
        }

        std::cout << "\n  " << (fail==0 ? "PASS" : "FAIL")
                  << ": chacha20-c99 "
                  << (fail==0 ? "all cross-validation + KATs matched" : "had failures")
                  << " (libsodium-free C99 ChaCha20 + Poly1305 + AEAD vs OpenSSL — the §Q9 gate)\n";
        return fail==0 ? 0 : 1;
    }

    if (cmd == "test-sha2-c99") {
        // v2.10 Phase 0 / CRYPTO-C99-SPEC §3.1 first vendored primitive: validate
        // the libsodium-free C99 SHA-256 / SHA-512 (src/crypto/sha2/) two ways —
        // (1) byte-equal cross-validation against the daemon's current OpenSSL
        // backend over EVERY message length across the block + padding boundaries
        // (the §Q9 "C99 output == backend output, byte-equal" gate; needs no
        // transcribed digest, so it is immune to KAT-transcription error), and
        // (2) the canonical NIST FIPS 180-4 known-answer vectors as independent
        // anchors. This module is additive — not yet wired into any call site.
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const std::string& m) {
            if (cond) std::cout << "  PASS: " << m << "\n";
            else { std::cout << "  FAIL: " << m << "\n"; fail++; }
        };
        auto to_hexs = [](const uint8_t* p, size_t n) {
            static const char* H = "0123456789abcdef";
            std::string s; s.reserve(n * 2);
            for (size_t i = 0; i < n; i++) { s.push_back(H[p[i] >> 4]); s.push_back(H[p[i] & 0xf]); }
            return s;
        };

        // (1) Cross-validation vs OpenSSL over lengths 0..300 (single-block,
        // multi-block, and both padding edges: 55/56 for SHA-256, 111/112 for SHA-512).
        bool s256_ok = true, s512_ok = true;
        size_t s256_at = 0, s512_at = 0;
        for (size_t len = 0; len <= 300 && (s256_ok || s512_ok); ++len) {
            std::vector<uint8_t> buf(len);
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)((i * 131u + len * 17u + 7u) & 0xffu);
            if (s256_ok) {
                uint8_t c99[32]; determ_sha256(buf.data(), len, c99);
                Hash ossl = crypto::sha256(buf.data(), len);
                if (std::memcmp(c99, ossl.data(), 32) != 0) { s256_ok = false; s256_at = len; }
            }
            if (s512_ok) {
                uint8_t c99[64]; determ_sha512(buf.data(), len, c99);
                uint8_t ossl[64]; unsigned int ol = 64;
                EVP_Digest(buf.data(), len, ossl, &ol, EVP_sha512(), nullptr);
                if (std::memcmp(c99, ossl, 64) != 0) { s512_ok = false; s512_at = len; }
            }
        }
        check(s256_ok, s256_ok ? "SHA-256 C99 == OpenSSL over lengths 0..300 (block + padding boundaries)"
                               : "SHA-256 C99 diverges from OpenSSL at len=" + std::to_string(s256_at));
        check(s512_ok, s512_ok ? "SHA-512 C99 == OpenSSL over lengths 0..300 (block + padding boundaries)"
                               : "SHA-512 C99 diverges from OpenSSL at len=" + std::to_string(s512_at));

        // (2) NIST FIPS 180-4 known-answer vectors (independent anchors).
        { uint8_t d[32]; determ_sha256((const uint8_t*)"abc", 3, d);
          check(to_hexs(d, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA-256(\"abc\") matches NIST KAT"); }
        { uint8_t d[32]; determ_sha256((const uint8_t*)"", 0, d);
          check(to_hexs(d, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "SHA-256(\"\") matches NIST KAT"); }
        { uint8_t d[64]; determ_sha512((const uint8_t*)"abc", 3, d);
          check(to_hexs(d, 64) == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "SHA-512(\"abc\") matches NIST KAT"); }
        { uint8_t d[64]; determ_sha512((const uint8_t*)"", 0, d);
          check(to_hexs(d, 64) == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                                  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "SHA-512(\"\") matches NIST KAT"); }

        // (3) Long multi-block message (1 MiB) must still agree with OpenSSL.
        {
            std::vector<uint8_t> big(1u << 20, 0x5au);
            uint8_t c99[32]; determ_sha256(big.data(), big.size(), c99);
            Hash ossl = crypto::sha256(big.data(), big.size());
            check(std::memcmp(c99, ossl.data(), 32) == 0, "SHA-256 C99 == OpenSSL on 1 MiB message");
            uint8_t c99b[64]; determ_sha512(big.data(), big.size(), c99b);
            uint8_t osslb[64]; unsigned int ol = 64;
            EVP_Digest(big.data(), big.size(), osslb, &ol, EVP_sha512(), nullptr);
            check(std::memcmp(c99b, osslb, 64) == 0, "SHA-512 C99 == OpenSSL on 1 MiB message");
        }

        // (4) HMAC-SHA-256 / SHA-512 vs OpenSSL HMAC() over a (key,msg)-length
        // grid including the key>block-size hashing path (RFC 2104). No
        // transcribed digest — pure byte-equality.
        {
            const size_t klens[] = {0,1,16,31,32,33,63,64,65,100,200};
            const size_t mlens[] = {0,1,13,32,55,56,63,64,100,200};
            bool h256_ok = true, h512_ok = true; long h_at = -1;
            uint8_t one = 0;
            for (size_t ki = 0; ki < sizeof(klens)/sizeof(klens[0]) && (h256_ok||h512_ok); ++ki)
            for (size_t mi = 0; mi < sizeof(mlens)/sizeof(mlens[0]) && (h256_ok||h512_ok); ++mi) {
                size_t kl = klens[ki], ml = mlens[mi];
                std::vector<uint8_t> key(kl), msg(ml);
                for (size_t i=0;i<kl;i++) key[i]=(uint8_t)((i*97u+kl*3u+1u)&0xffu);
                for (size_t i=0;i<ml;i++) msg[i]=(uint8_t)((i*61u+ml*5u+9u)&0xffu);
                const uint8_t* kp = kl ? key.data() : &one;
                const uint8_t* mp = ml ? msg.data() : &one;
                if (h256_ok) {
                    uint8_t c[32]; determ_hmac_sha256(kp,kl,mp,ml,c);
                    uint8_t o[32]; unsigned int ol=32; HMAC(EVP_sha256(), kp,(int)kl, mp, ml, o, &ol);
                    if (std::memcmp(c,o,32)!=0){ h256_ok=false; h_at=(long)(kl*1000+ml); }
                }
                if (h512_ok) {
                    uint8_t c[64]; determ_hmac_sha512(kp,kl,mp,ml,c);
                    uint8_t o[64]; unsigned int ol=64; HMAC(EVP_sha512(), kp,(int)kl, mp, ml, o, &ol);
                    if (std::memcmp(c,o,64)!=0){ h512_ok=false; h_at=(long)(kl*1000+ml); }
                }
            }
            check(h256_ok, h256_ok ? "HMAC-SHA-256 C99 == OpenSSL over the (key,msg)-length grid"
                                   : "HMAC-SHA-256 diverges (kl*1000+ml=" + std::to_string(h_at) + ")");
            check(h512_ok, h512_ok ? "HMAC-SHA-512 C99 == OpenSSL over the (key,msg)-length grid"
                                   : "HMAC-SHA-512 diverges (kl*1000+ml=" + std::to_string(h_at) + ")");
        }

        // (4b) HMAC RFC 4231 known-answer vectors — an OpenSSL-INDEPENDENT anchor.
        // The grid above proves we agree with OpenSSL; these pin the canonical
        // published digests so a shared (us-and-OpenSSL) blind spot cannot hide.
        {
            uint8_t m256[32], m512[64];
            // Test Case 1: key = 20 x 0x0b, data = "Hi There".
            uint8_t k1[20]; std::memset(k1, 0x0b, 20);
            const char* d1 = "Hi There";
            determ_hmac_sha256(k1, 20, (const uint8_t*)d1, std::strlen(d1), m256);
            determ_hmac_sha512(k1, 20, (const uint8_t*)d1, std::strlen(d1), m512);
            check(to_hexs(m256,32)=="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                  "HMAC-SHA-256 matches RFC 4231 Test Case 1");
            check(to_hexs(m512,64)=="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                  "HMAC-SHA-512 matches RFC 4231 Test Case 1");
            // Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
            const char* k2 = "Jefe"; const char* d2 = "what do ya want for nothing?";
            determ_hmac_sha256((const uint8_t*)k2, 4, (const uint8_t*)d2, std::strlen(d2), m256);
            determ_hmac_sha512((const uint8_t*)k2, 4, (const uint8_t*)d2, std::strlen(d2), m512);
            check(to_hexs(m256,32)=="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                  "HMAC-SHA-256 matches RFC 4231 Test Case 2");
            check(to_hexs(m512,64)=="164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
                  "HMAC-SHA-512 matches RFC 4231 Test Case 2");
        }

        // (5) HKDF-SHA-256 against the RFC 5869 known-answer vectors. HKDF is
        // built entirely on the HMAC cross-validated above, so these vectors
        // anchor the extract/expand glue (multi-block expand + the empty-salt /
        // empty-info default path). OpenSSL's EVP_KDF API arrived in OpenSSL 3.0
        // and this build vendors 1.1.1w (the janbar/openssl-cmake FetchContent pin
        // in CMakeLists.txt), so the RFC vectors are the anchor;
        // the §Q9 byte-equal-vs-OpenSSL gate runs through the HMAC building block.
        {
            uint8_t ikm[22]; std::memset(ikm, 0x0b, 22);
            // Test Case 1: 13-byte salt + 10-byte info, L=42 (two expand blocks).
            {
                uint8_t salt[13]; for (int i=0;i<13;i++) salt[i]=(uint8_t)i;
                uint8_t info[10]; for (int i=0;i<10;i++) info[i]=(uint8_t)(0xf0+i);
                uint8_t okm[42];
                determ_hkdf_sha256(salt,13, ikm,22, info,10, okm,42);
                check(to_hexs(okm,42)=="3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                      "HKDF-SHA-256 matches RFC 5869 Test Case 1 (salt + info)");
            }
            // Test Case 3: empty salt + empty info (the zero-salt default path), L=42.
            {
                uint8_t okm[42];
                determ_hkdf_sha256(nullptr,0, ikm,22, nullptr,0, okm,42);
                check(to_hexs(okm,42)=="8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                      "HKDF-SHA-256 matches RFC 5869 Test Case 3 (no salt, no info)");
            }
        }

        // (6) PBKDF2-HMAC-SHA-256 vs OpenSSL PKCS5_PBKDF2_HMAC over a
        // (pw,salt,iters,outlen) grid (small iter counts keep it fast — the
        // construction is exercised identically regardless of count) + a KAT.
        {
            const uint32_t iters[] = {1,2,5,10,100,1000};
            const size_t   olens[] = {1,16,31,32,33,48,64,100};
            bool pb_ok = true; long pb_at = -1; uint8_t one = 0;
            for (size_t ii=0; ii<sizeof(iters)/sizeof(iters[0]) && pb_ok; ++ii)
            for (size_t oi=0; oi<sizeof(olens)/sizeof(olens[0]) && pb_ok; ++oi) {
                size_t pl = 4 + (oi*7)%30, sl = (ii*5 + oi*3)%40, outlen = olens[oi];
                std::vector<uint8_t> pw(pl), salt(sl), c(outlen), o(outlen);
                for (size_t i=0;i<pl;i++) pw[i]=(uint8_t)((i*29u+oi+1u)&0xffu);
                for (size_t i=0;i<sl;i++) salt[i]=(uint8_t)((i*7u+ii*3u+5u)&0xffu);
                determ_pbkdf2_hmac_sha256(pw.data(),pl, sl?salt.data():nullptr,sl, iters[ii], c.data(), outlen);
                PKCS5_PBKDF2_HMAC((const char*)pw.data(),(int)pl, sl?salt.data():&one,(int)sl,
                                  (int)iters[ii], EVP_sha256(),(int)outlen, o.data());
                if (std::memcmp(c.data(),o.data(),outlen)!=0){ pb_ok=false; pb_at=(long)(iters[ii]*100+outlen); }
            }
            check(pb_ok, pb_ok ? "PBKDF2-HMAC-SHA-256 C99 == OpenSSL over the (pw,salt,iters,outlen) grid"
                               : "PBKDF2-HMAC-SHA-256 diverges (iters*100+outlen=" + std::to_string(pb_at) + ")");
            // Known-answer: P="password", S="salt", c=4096, dkLen=32 (RFC-style vector).
            {
                const char* P = "password"; const char* S = "salt";
                uint8_t dk[32];
                determ_pbkdf2_hmac_sha256((const uint8_t*)P,8,(const uint8_t*)S,4,4096, dk,32);
                check(to_hexs(dk,32)=="c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
                      "PBKDF2-HMAC-SHA-256(\"password\",\"salt\",4096,32) matches KAT");
            }
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": sha2-c99 "
                  << (fail == 0 ? "all cross-validation + NIST/RFC KATs matched" : "had failures")
                  << " (libsodium-free C99 SHA-2 + HMAC + HKDF + PBKDF2 vs OpenSSL — the §Q9 gate)\n";
        return fail == 0 ? 0 : 1;
    }

    std::cout << "determ-cryptotest: unknown subcommand '" << cmd << "'\n\n";
    usage();
    return 2;
}
