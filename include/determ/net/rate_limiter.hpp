// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <string>

namespace determ::net {

// S-014 token-bucket rate limiter, per opaque key (typically a peer IP).
// Used identically by RpcServer (`consume_rate_token` in `handle_session`)
// and GossipNet (`consume_rate_token` in `handle_message`); consolidated
// here so the policy and refill arithmetic live in exactly one place.
//
// Refill model: each key gets a bucket with `burst_` capacity. On `consume`,
// the bucket refills proportional to `elapsed × rate_per_sec_` (capped at
// `burst_`), then one token is consumed. First touch of a key starts the
// bucket full, so legitimate callers don't get hit cold.
//
// Memory: one `Bucket` (~24 bytes) per distinct key. The map grows with
// observed sources; v2.X follow-on is a periodic prune of buckets idle
// for > N minutes (not critical at current scale — 10K entries is < 300 KB).
class RateLimiter {
public:
    RateLimiter() = default;

    // Configure rate and burst. Both > 0 enables the limiter; either ≤ 0
    // disables it (all `consume` calls return true, no bucket allocation).
    void configure(double per_sec, double burst) {
        rate_per_sec_ = per_sec;
        burst_        = burst;
    }

    bool enabled() const { return rate_per_sec_ > 0.0 && burst_ > 0.0; }
    double rate_per_sec() const { return rate_per_sec_; }
    double burst()        const { return burst_; }

    // Consume one token for `key`. Returns true on success; false if the
    // bucket is empty (caller should drop / reject the request).
    bool consume(const std::string& key) {
        if (!enabled()) return true;
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();
        auto& b = buckets_[key];
        if (b.last.time_since_epoch().count() == 0) {
            b.tokens = burst_;
            b.last   = now;
        } else {
            double elapsed_sec = std::chrono::duration<double>(now - b.last).count();
            b.tokens = std::min(burst_, b.tokens + elapsed_sec * rate_per_sec_);
            b.last   = now;
        }
        if (b.tokens < 1.0) return false;
        b.tokens -= 1.0;
        return true;
    }

private:
    struct Bucket {
        double                                tokens{0.0};
        std::chrono::steady_clock::time_point last;
    };
    double                        rate_per_sec_{0.0};
    double                        burst_{0.0};
    mutable std::mutex            mu_;
    std::map<std::string, Bucket> buckets_;
};

} // namespace determ::net
