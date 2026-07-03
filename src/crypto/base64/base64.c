/* Determ C99 Base64 (RFC 4648 §4). See base64.h for the strictness contract. */
#include "determ/crypto/base64/base64.h"

static const char ENC[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t determ_base64_encode(const uint8_t *in, size_t inlen, char *out) {
    size_t i = 0, o = 0;
    while (inlen - i >= 3u) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = ENC[(v >> 18) & 0x3f];
        out[o++] = ENC[(v >> 12) & 0x3f];
        out[o++] = ENC[(v >> 6) & 0x3f];
        out[o++] = ENC[v & 0x3f];
        i += 3u;
    }
    if (inlen - i == 1u) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = ENC[(v >> 18) & 0x3f];
        out[o++] = ENC[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (inlen - i == 2u) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = ENC[(v >> 18) & 0x3f];
        out[o++] = ENC[(v >> 12) & 0x3f];
        out[o++] = ENC[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    return o;
}

/* Map one base64 character to its 6-bit value, or -1. */
static int dec1(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

long determ_base64_decode(const char *in, size_t inlen, uint8_t *out) {
    size_t i, o = 0;
    if (inlen == 0u) return 0;
    if (inlen % 4u != 0u) return -1;
    for (i = 0; i < inlen; i += 4u) {
        int a = dec1(in[i]);
        int b = dec1(in[i + 1]);
        int c, d;
        int pad = 0;
        if (a < 0 || b < 0) return -1;
        /* '=' may appear only in the final quantum, only in positions 3 / 3+4. */
        if (in[i + 2] == '=') {
            if (in[i + 3] != '=' || i + 4u != inlen) return -1;
            c = 0; d = 0; pad = 2;
        } else if (in[i + 3] == '=') {
            if (i + 4u != inlen) return -1;
            c = dec1(in[i + 2]);
            if (c < 0) return -1;
            d = 0; pad = 1;
        } else {
            c = dec1(in[i + 2]);
            d = dec1(in[i + 3]);
            if (c < 0 || d < 0) return -1;
        }
        {
            uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                         ((uint32_t)c << 6) | (uint32_t)d;
            out[o++] = (uint8_t)(v >> 16);
            if (pad < 2) out[o++] = (uint8_t)(v >> 8);
            if (pad < 1) out[o++] = (uint8_t)v;
            /* Canonicality: the discarded low bits of a padded final quantum
             * must be zero (rejects non-canonical encodings like "QQ=="
             * vs "QR==" for the same byte). */
            if (pad == 2 && (v & 0xffffu) != 0u) return -1;
            if (pad == 1 && (v & 0xffu) != 0u) return -1;
        }
    }
    return (long)o;
}
