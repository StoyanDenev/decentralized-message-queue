#include "shamir.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <set>

namespace determ::wallet::shamir {

// GF(2^8) arithmetic. AES irreducible polynomial 0x11b. Multiplication
// via the runtime double-and-add ladder; small enough that lookup tables
// give no readability win. All ops constant-time in their inputs.

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t mask = -static_cast<uint8_t>(b & 1);
        result ^= a & mask;
        // hi-bit predicate for the modular reduction
        uint8_t hi   = -static_cast<uint8_t>((a >> 7) & 1);
        a = static_cast<uint8_t>((a << 1) ^ (hi & 0x1b));
        b >>= 1;
    }
    return result;
}

// Fermat's little theorem: a^(p^n - 2) is the multiplicative inverse in
// GF(p^n). Here a^254 = a^-1 in GF(2^8). Square-and-multiply.
static uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;                  // formally undefined; caller must avoid x_i = 0
    uint8_t result = 1, base = a;
    uint8_t exp = 254;
    while (exp) {
        if (exp & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}

// Evaluate polynomial p(x) = c[0] + c[1]·x + c[2]·x^2 + ... at x using
// Horner's rule for byte-stride efficiency.
static uint8_t poly_eval(const uint8_t* coeffs, size_t degree_plus_one,
                          uint8_t x) {
    uint8_t acc = coeffs[degree_plus_one - 1];
    for (size_t i = degree_plus_one - 1; i-- > 0;) {
        acc = gf_mul(acc, x) ^ coeffs[i];
    }
    return acc;
}

std::vector<Share> split(const std::vector<uint8_t>& secret,
                          uint8_t threshold,
                          uint8_t share_count) {
    if (threshold == 0)
        throw std::invalid_argument("shamir: threshold must be >= 1");
    if (share_count < threshold)
        throw std::invalid_argument("shamir: share_count must be >= threshold");
    if (share_count > 255)
        throw std::invalid_argument("shamir: share_count must be <= 255");

    const size_t n     = secret.size();
    const size_t T     = threshold;
    std::vector<Share> shares(share_count);

    // Per-share x in 1..N (must be non-zero; reconstruction evaluates
    // at x=0 via Lagrange and 0 would invalidate the basis).
    for (uint8_t i = 0; i < share_count; ++i) {
        shares[i].x = static_cast<uint8_t>(i + 1);
        shares[i].y.resize(n);
    }

    // Per secret byte: generate T-1 random coefficients, build the
    // polynomial p(x) = secret_byte + a_1·x + ... + a_{T-1}·x^{T-1},
    // then evaluate at each share's x.
    std::vector<uint8_t> coeffs(T);
    for (size_t b = 0; b < n; ++b) {
        coeffs[0] = secret[b];
        if (T > 1) {
            if (RAND_bytes(coeffs.data() + 1, static_cast<int>(T - 1)) != 1)
                throw std::runtime_error("shamir: RAND_bytes failed");
        }
        for (auto& share : shares) {
            share.y[b] = poly_eval(coeffs.data(), T, share.x);
        }
    }
    return shares;
}

std::optional<std::vector<uint8_t>>
combine(const std::vector<Share>& shares) {
    if (shares.empty()) return std::nullopt;
    const size_t secret_len = shares[0].y.size();
    if (secret_len == 0) return std::nullopt;

    // Validate: distinct non-zero x, matching y sizes.
    std::set<uint8_t> xs;
    for (auto& s : shares) {
        if (s.x == 0)                  return std::nullopt;
        if (s.y.size() != secret_len)  return std::nullopt;
        if (!xs.insert(s.x).second)    return std::nullopt;
    }

    // Lagrange interpolation evaluated at x = 0. For each byte position:
    //   secret_byte = Σ_{i} y_i · Π_{j≠i} (-x_j) / (x_i - x_j)
    //               = Σ_{i} y_i · Π_{j≠i}   x_j  /   (x_i ^ x_j)
    // in GF(2^8) where subtraction == XOR and negation is identity.
    std::vector<uint8_t> secret(secret_len);
    for (size_t b = 0; b < secret_len; ++b) {
        uint8_t acc = 0;
        for (size_t i = 0; i < shares.size(); ++i) {
            uint8_t num = 1, den = 1;
            for (size_t j = 0; j < shares.size(); ++j) {
                if (j == i) continue;
                num = gf_mul(num, shares[j].x);
                den = gf_mul(den, shares[i].x ^ shares[j].x);
            }
            uint8_t term = gf_mul(shares[i].y[b], gf_mul(num, gf_inv(den)));
            acc ^= term;
        }
        secret[b] = acc;
    }
    return secret;
}

} // namespace determ::wallet::shamir
