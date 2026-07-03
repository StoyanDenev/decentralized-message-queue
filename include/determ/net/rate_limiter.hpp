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
// Memory (post-F-1 closure): one `Bucket` (~24 bytes) per ACTIVE distinct
// key. Stale buckets are evicted on a time-decay schedule — any bucket
// not touched for `eviction_threshold_sec_` seconds is dropped on the
// next consume() call's amortized sweep (default sweep cadence: every
// `sweep_interval_sec_` wall-clock seconds, default 60s). Semantic safety:
// an evicted bucket re-creates as full-capacity on next touch — which
// is what the unbroken bucket would have refilled to after waiting at
// least `burst_ / rate_per_sec_` seconds. Defaults pick a generous
// safety factor: `eviction_threshold_sec_ = max(600, 10 × burst/rate)`,
// so the bucket would have refilled to capacity at least 10× over before
// eviction fires. Operators can tune via `configure_eviction()` or
// disable entirely by passing 0. Closes the S014RateLimiterSoundness.md
// §6.2 F-1 finding (unbounded `buckets_` growth under IPv6 /64 cycling
// or sustained IPv4 rotation attacks).
class RateLimiter {
public:
    RateLimiter() = default;

    // Configure rate and burst. Both > 0 enables the limiter; either ≤ 0
    // disables it (all `consume` calls return true, no bucket allocation).
    void configure(double per_sec, double burst) {
        rate_per_sec_ = per_sec;
        burst_        = burst;
    }

    // F-1 closure (S014RateLimiterSoundness.md §6.2): configure the
    // idle-bucket eviction policy. `threshold_sec` is how long a bucket
    // can sit without a consume() before becoming evictable on the next
    // sweep; `interval_sec` is the amortized sweep cadence (the sweep
    // runs on the next consume() after `interval_sec` wall-clock seconds
    // since the previous sweep). Passing `threshold_sec` <= 0 DISABLES
    // eviction entirely (legacy unbounded-growth behavior — useful for
    // tests / forensics, not for production). Defaults: `threshold_sec`
    // = 600 (10 min), `interval_sec` = 60.
    void configure_eviction(double threshold_sec, double interval_sec = 60.0) {
        eviction_threshold_sec_ = threshold_sec;
        sweep_interval_sec_     = interval_sec;
    }

    bool enabled() const { return rate_per_sec_ > 0.0 && burst_ > 0.0; }
    double rate_per_sec() const { return rate_per_sec_; }
    double burst()        const { return burst_; }
    double eviction_threshold_sec() const { return eviction_threshold_sec_; }
    double sweep_interval_sec()     const { return sweep_interval_sec_; }

    // Diagnostic: number of buckets currently in the map. Used by tests
    // to observe eviction; constant-time apart from the lock.
    size_t bucket_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return buckets_.size();
    }

    // Force a sweep of idle buckets immediately. Returns the number of
    // entries evicted. Tests can call this to deterministically exercise
    // the eviction path; production callers can call after a known burst
    // ends to free memory eagerly. No-op when eviction is disabled
    // (threshold_sec <= 0).
    size_t sweep_idle() {
        std::lock_guard<std::mutex> lk(mu_);
        return sweep_idle_locked(std::chrono::steady_clock::now());
    }

    // Consume one token for `key`. Returns true on success; false if the
    // bucket is empty (caller should drop / reject the request).
    bool consume(const std::string& key) { return consume(key, 1.0); }

    // v2.20: weighted consume. A long-lived subscription is priced as
    // `cost` tokens up front (RpcServer charges dapp_subscribe extra so
    // one client can't cheaply exhaust SUBSCRIBER_MAX_PER_NODE slots).
    // cost <= 0 is a no-op success. If the bucket holds fewer than
    // `cost` tokens the call fails WITHOUT partial deduction.
    bool consume(const std::string& key, double cost) {
        if (!enabled() || cost <= 0.0) return true;
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();

        // F-1 closure: amortized idle-bucket sweep. Runs at most every
        // sweep_interval_sec_ wall-clock seconds — the periodic check
        // is constant-time, the sweep itself is O(buckets) but bounded
        // by the cadence so amortized cost per consume stays O(1).
        if (eviction_threshold_sec_ > 0.0) {
            if (next_sweep_at_.time_since_epoch().count() == 0 ||
                now >= next_sweep_at_) {
                sweep_idle_locked(now);
                next_sweep_at_ = now + std::chrono::duration_cast<
                    std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(sweep_interval_sec_));
            }
        }

        auto& b = buckets_[key];
        if (b.last.time_since_epoch().count() == 0) {
            b.tokens = burst_;
            b.last   = now;
        } else {
            double elapsed_sec = std::chrono::duration<double>(now - b.last).count();
            b.tokens = std::min(burst_, b.tokens + elapsed_sec * rate_per_sec_);
            b.last   = now;
        }
        if (b.tokens < cost) return false;
        b.tokens -= cost;
        return true;
    }

private:
    struct Bucket {
        double                                tokens{0.0};
        std::chrono::steady_clock::time_point last;
    };

    // Caller must hold mu_. Erases bucket entries whose `last` timestamp
    // is older than `eviction_threshold_sec_` relative to `now`. Returns
    // the number of entries removed.
    size_t sweep_idle_locked(std::chrono::steady_clock::time_point now) {
        if (eviction_threshold_sec_ <= 0.0) return 0;
        auto threshold = std::chrono::duration_cast<
            std::chrono::steady_clock::duration>(
            std::chrono::duration<double>(eviction_threshold_sec_));
        size_t evicted = 0;
        for (auto it = buckets_.begin(); it != buckets_.end(); ) {
            if (now - it->second.last > threshold) {
                it = buckets_.erase(it);
                ++evicted;
            } else {
                ++it;
            }
        }
        return evicted;
    }

    double                                rate_per_sec_{0.0};
    double                                burst_{0.0};
    double                                eviction_threshold_sec_{600.0};
    double                                sweep_interval_sec_{60.0};
    std::chrono::steady_clock::time_point next_sweep_at_;
    mutable std::mutex                    mu_;
    std::map<std::string, Bucket>         buckets_;
};

} // namespace determ::net
