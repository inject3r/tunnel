#pragma once

#include "core.h"

namespace tunnel {

// Proxy pool
bool proxy_supports_udp(const ProxySpec& p) {
    return !p.no_udp && (p.scheme == "socks5" || p.scheme == "socks5h");
}

struct ProxyState {
    ProxySpec spec;
    std::atomic<int> failures{0};
    std::atomic<int> successes{0};
    std::atomic<double> cooldown_until{0.0};
    std::atomic<double> latency_ms{-1.0};
    std::atomic<double> last_check{0.0};
    std::atomic<bool> healthy{false};
    std::atomic<bool> udp_capable{true};
    std::string last_error;
};

struct ProxyPingResult {
    ProxySpec proxy;
    bool ok = false;
    double latency_ms = std::numeric_limits<double>::infinity();
    std::string error;
};

ProxyPingResult measure_proxy_latency(const ProxySpec& p, double timeout, bool remote_dns,
                                      const std::string& target_host = kDefaultPingTargetHost,
                                      uint16_t target_port = kDefaultPingTargetPort);

class ProxyPool {
public:
    ProxyPool(std::vector<ProxySpec> proxies, std::optional<ProxySpec> fixed, bool rotate)
        : fixed_(std::move(fixed)), rotate_(rotate)
    {
        if (proxies.empty()) throw std::runtime_error("proxy pool cannot be empty");
        for (auto& p : proxies) {
            auto st = std::make_shared<ProxyState>();
            st->spec = p;
            states_.push_back(st);
            by_key_[p.key()] = st;
        }
        if (fixed_) active_key_ = fixed_->key();
    }

    ProxySpec choose(const std::unordered_set<std::string>& exclude = {}, bool udp_only = false) {
        std::lock_guard<std::mutex> lk(lock_);
        if (fixed_) {
            if (udp_only && !proxy_supports_udp(*fixed_))
                throw std::runtime_error("fixed upstream proxy does not support SOCKS5 UDP");
            return *fixed_;
        }

        auto active_it = by_key_.find(active_key_);
        if (!active_key_.empty() && active_it != by_key_.end()) {
            const auto& st = active_it->second;
            if (!exclude.count(st->spec.key()) &&
                (!udp_only || (proxy_supports_udp(st->spec) && st->udp_capable.load())) &&
                st->cooldown_until.load() <= now_monotonic() && st->healthy.load()) {
                return st->spec;
            }
        }

        const double now = now_monotonic();
        std::vector<std::shared_ptr<ProxyState>> cands;
        cands.reserve(states_.size());
        for (auto& st : states_) {
            if (exclude.count(st->spec.key())) continue;
            if (udp_only && (!proxy_supports_udp(st->spec) || !st->udp_capable.load())) continue;
            cands.push_back(st);
        }
        if (cands.empty()) {
            if (udp_only) throw std::runtime_error("no SOCKS5 upstream proxies available for UDP");
            cands = states_;
        }

        std::vector<std::shared_ptr<ProxyState>> avail;
        for (auto& st : cands) {
            if (st->cooldown_until.load() <= now) avail.push_back(st);
        }
        if (avail.empty()) avail = cands;

        auto rank = [](const std::shared_ptr<ProxyState>& st) {
            const bool healthy = st->healthy.load();
            const double ms = st->latency_ms.load();
            const int failures = st->failures.load();
            const bool known = healthy && std::isfinite(ms) && ms >= 0.0;
            return std::tuple<int, double, int>(
                known ? 0 : 1,
                known ? ms : std::numeric_limits<double>::infinity(),
                failures);
        };

        auto best = std::min_element(avail.begin(), avail.end(), [&](const auto& a, const auto& b) {
            return rank(a) < rank(b);
        });
        active_key_ = (*best)->spec.key();
        return (*best)->spec;
    }

    void update_health(const ProxySpec& p, bool ok, double latency_ms, const std::string& err) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key());
        if (it == by_key_.end()) return;
        auto& st = it->second;
        st->last_check.store(now_monotonic());
        st->healthy.store(ok);
        if (ok) {
            st->latency_ms.store(latency_ms);
            st->cooldown_until.store(0.0);
            st->last_error.clear();
        } else {
            st->latency_ms.store(-1.0);
            st->last_error = err;
            if (active_key_ == p.key()) active_key_.clear();
        }
    }

    std::vector<ProxyPingResult> refresh_pings(double timeout, bool remote_dns,
                                               const std::string& target_host = kDefaultPingTargetHost,
                                               uint16_t target_port = kDefaultPingTargetPort,
                                               bool update_state = true) {
        std::vector<std::shared_ptr<ProxyState>> snapshot;
        {
            std::lock_guard<std::mutex> lk(lock_);
            snapshot = states_;
        }

        std::vector<ProxyPingResult> results(snapshot.size());
        std::atomic<size_t> next{0};
        const unsigned hc = std::thread::hardware_concurrency();
        const size_t suggested = hc ? static_cast<size_t>(hc) * 4u : 8u;
        const size_t worker_count = std::min(snapshot.size(), std::min<size_t>(64, std::max<size_t>(4, suggested)));
        std::vector<std::thread> workers;
        workers.reserve(worker_count);
        for (size_t w = 0; w < worker_count; ++w) {
            workers.emplace_back([&] {
                while (true) {
                    const size_t i = next.fetch_add(1);
                    if (i >= snapshot.size()) break;
                    results[i] = measure_proxy_latency(snapshot[i]->spec, timeout, remote_dns, target_host, target_port);
                    if (update_state) {
                        update_health(snapshot[i]->spec, results[i].ok, results[i].latency_ms, results[i].error);
                        if (results[i].ok) success(snapshot[i]->spec);
                        else note_health_failure(snapshot[i]->spec, results[i].error);
                    }
                }
            });
        }
        for (auto& t : workers) t.join();
        return results;
    }

    std::optional<ProxyPingResult> best_ping() const {
        std::lock_guard<std::mutex> lk(lock_);
        std::optional<ProxyPingResult> best;
        for (const auto& st : states_) {
            if (!st->healthy.load()) continue;
            const double ms = st->latency_ms.load();
            if (!std::isfinite(ms) || ms < 0.0) continue;
            ProxyPingResult cur;
            cur.proxy = st->spec;
            cur.ok = true;
            cur.latency_ms = ms;
            if (!best || ms < best->latency_ms) best = std::move(cur);
        }
        return best;
    }

    std::optional<ProxySpec> active() const {
        std::lock_guard<std::mutex> lk(lock_);
        if (active_key_.empty()) return std::nullopt;
        auto it = by_key_.find(active_key_);
        if (it == by_key_.end()) return std::nullopt;
        return it->second->spec;
    }

    bool set_active(const ProxySpec& p) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key());
        if (it == by_key_.end()) return false;
        active_key_ = it->first;
        return true;
    }

    bool force_best() {
        std::lock_guard<std::mutex> lk(lock_);
        if (fixed_) return false;
        std::shared_ptr<ProxyState> best;
        for (const auto& st : states_) {
            if (!st->healthy.load()) continue;
            const double ms = st->latency_ms.load();
            if (!std::isfinite(ms) || ms < 0.0) continue;
            if (!best || ms < best->latency_ms.load()) best = st;
        }
        if (!best) return false;
        const bool changed = active_key_ != best->spec.key();
        active_key_ = best->spec.key();
        return changed;
    }

    void success(const ProxySpec& p) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key()); if (it == by_key_.end()) return;
        it->second->successes.fetch_add(1);
        int f = it->second->failures.load();
        if (f > 0) it->second->failures.store(f-1);
        it->second->cooldown_until.store(0.0);
        it->second->healthy.store(true);
        it->second->last_error.clear();
        if (!fixed_ && active_key_.empty()) active_key_ = p.key();
    }

    void note_health_failure(const ProxySpec& p, const std::string& err) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key()); if (it == by_key_.end()) return;
        int f = it->second->failures.fetch_add(1) + 1;
        double delay = std::min(60.0, std::pow(2.0, std::min(f-1, 6)));
        it->second->cooldown_until.store(now_monotonic() + delay);
        it->second->last_error = err;
        it->second->healthy.store(false);
        if (!fixed_ && active_key_ == p.key()) active_key_.clear();
    }

    void failure(const ProxySpec& p, const std::string& err) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key()); if (it == by_key_.end()) return;
        int f = it->second->failures.fetch_add(1) + 1;
        double delay = std::min(60.0, std::pow(2.0, std::min(f-1, 6)));
        it->second->cooldown_until.store(now_monotonic() + delay);
        it->second->latency_ms.store(-1.0);
        it->second->healthy.store(false);
        it->second->last_error = err;
        if (!fixed_ && active_key_ == p.key()) active_key_.clear();
    }

    void mark_udp_unavailable(const ProxySpec& p, const std::string& err) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key());
        if (it == by_key_.end()) return;
        it->second->udp_capable.store(false);
        it->second->last_error = err;
    }

    void mark_udp_available(const ProxySpec& p) {
        std::lock_guard<std::mutex> lk(lock_);
        auto it = by_key_.find(p.key());
        if (it == by_key_.end()) return;
        it->second->udp_capable.store(true);
    }

    size_t size() const { return states_.size(); }
    bool rotate() const { return rotate_; }
    std::optional<ProxySpec> fixed() const { return fixed_; }

private:
    std::vector<std::shared_ptr<ProxyState>> states_;
    std::unordered_map<std::string, std::shared_ptr<ProxyState>> by_key_;
    std::optional<ProxySpec> fixed_;
    bool rotate_;
    std::string active_key_;
    mutable std::mutex lock_;
};


class ProxyAutoSwitchMonitor {
public:
    ProxyAutoSwitchMonitor(std::shared_ptr<ProxyPool> pool, double interval_s, double timeout_s,
                           bool remote_dns, bool verbose, std::string target_host = kDefaultPingTargetHost,
                           uint16_t target_port = kDefaultPingTargetPort)
        : pool_(std::move(pool)),
          interval_s_(interval_s <= 0.0 ? 0.0 : std::max(1.0, interval_s)),
          timeout_s_(std::max(0.5, timeout_s)), remote_dns_(remote_dns), verbose_(verbose),
          target_host_(std::move(target_host)), target_port_(target_port) {}

    ~ProxyAutoSwitchMonitor() { stop(); }

    void start() {
        if (!pool_ || pool_->fixed().has_value() || interval_s_ <= 0.0 || running_.exchange(true)) return;
        worker_ = std::thread([this]{ loop(); });
    }

    void stop() {
        if (!running_.exchange(false)) return;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

private:
    void check_once() {
        auto before = pool_->active();
        auto results = pool_->refresh_pings(timeout_s_, remote_dns_, target_host_, target_port_);
        auto best = pool_->best_ping();
        if (!best) {
            if (verbose_) log_err("[auto-switch] no healthy upstream proxies available; keeping current selection");
            return;
        }
        pool_->force_best();
        const auto after = pool_->active();
        size_t ok = 0;
        for (const auto& r : results) if (r.ok) ++ok;
        if (verbose_) {
            char buf[192];
            std::snprintf(buf, sizeof buf,
                          "[auto-switch] %zu/%zu reachable | best %.1f ms | %s%s",
                          ok, results.size(), best->latency_ms, mask_proxy(best->proxy).c_str(),
                          (before && after && before->key() != after->key()) ? " | switched" : "");
            log_line(buf);
        } else if (before && after && before->key() != after->key()) {
            log_line("[auto-switch] switched upstream: " + mask_proxy(*before) + " -> " + mask_proxy(*after));
        }
    }

    void loop() {
        std::unique_lock<std::mutex> lk(cv_mutex_);
        auto next_run = std::chrono::steady_clock::now() +
                        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                            std::chrono::duration<double>(interval_s_));
        while (running_) {
            lk.unlock();
            check_once();
            next_run += std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::duration<double>(interval_s_));
            lk.lock();
            cv_.wait_until(lk, next_run, [this]{ return !running_.load(); });
            if (std::chrono::steady_clock::now() > next_run) next_run = std::chrono::steady_clock::now();
        }
    }

    std::shared_ptr<ProxyPool> pool_;
    double interval_s_;
    double timeout_s_;
    bool remote_dns_;
    bool verbose_;
    std::string target_host_;
    uint16_t target_port_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
};

int cmd_check_ping(const Args& args, const std::vector<ProxySpec>& proxies) {
    std::vector<ProxySpec> targets;
    if (args.proxy) {
        targets.clear();
        ProxySpec p;
        std::string err;
        if (!parse_proxy_url(*args.proxy, p, err)) {
            log_err("Error: invalid --proxy: " + err);
            return 2;
        }
        p.no_udp = args.tor;
        targets.push_back(std::move(p));
    } else {
        targets = proxies;
    }
    if (targets.empty()) {
        log_err("Error: no valid proxies available for --check-ping");
        return 1;
    }

    const double timeout = std::min(args.connect_timeout, args.ping_timeout);
    log_line("[ping] Target: " + args.ping_host + ":" + std::to_string(args.ping_port));
    log_line("[ping] Checking " + std::to_string(targets.size()) + " proxies in parallel...");

    std::vector<ProxyPingResult> results(targets.size());
    std::atomic<size_t> next{0};
    const unsigned hc = std::thread::hardware_concurrency();
    const size_t suggested = hc ? static_cast<size_t>(hc) * 4u : 8u;
    const size_t worker_count = std::min(targets.size(), std::min<size_t>(64, std::max<size_t>(4, suggested)));
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (size_t w = 0; w < worker_count; ++w) {
        workers.emplace_back([&] {
            while (true) {
                const size_t i = next.fetch_add(1);
                if (i >= targets.size()) break;
                results[i] = measure_proxy_latency(targets[i], timeout, !args.local_dns, args.ping_host, args.ping_port);
            }
        });
    }
    for (auto& t : workers) t.join();

    std::sort(results.begin(), results.end(), [](const ProxyPingResult& a, const ProxyPingResult& b) {
        if (a.ok != b.ok) return a.ok > b.ok;
        if (a.ok && b.ok) return a.latency_ms < b.latency_ms;
        return a.proxy.key() < b.proxy.key();
    });

    size_t rank = 0, ok_count = 0;
    for (const auto& r : results) {
        if (r.ok) {
            ++ok_count;
            ++rank;
            char msbuf[32];
            std::snprintf(msbuf, sizeof msbuf, "%.1f ms", r.latency_ms);
            std::cout << std::left << std::setw(5) << (std::to_string(rank) + ".")
                      << std::setw(12) << msbuf
                      << mask_proxy(r.proxy) << "\n";
        } else {
            std::cout << std::left << std::setw(5) << "-"
                      << std::setw(12) << "FAILED"
                      << mask_proxy(r.proxy);
            if (!r.error.empty()) std::cout << " | " << r.error;
            std::cout << "\n";
        }
    }
    std::cout.flush();

    if (ok_count == 0) {
        log_err("[ping] no reachable proxies");
        return 1;
    }

    const auto& best = results.front();
    char buf[128];
    std::snprintf(buf, sizeof buf, "[ping] Best: %.1f ms | %s | reachable %zu/%zu",
                  best.latency_ms, mask_proxy(best.proxy).c_str(), ok_count, results.size());
    log_line(buf);
    return 0;
}

} // namespace tunnel
