#pragma once

#include "servers.h"

namespace tunnel {

// Proxy health checks
ProxyPingResult measure_proxy_latency(const ProxySpec& p, double timeout, bool remote_dns,
                                                const std::string& target_host, uint16_t target_port) {
    ProxyPingResult result;
    result.proxy = p;
    result.ok = false;
    result.latency_ms = std::numeric_limits<double>::infinity();

    const double t0 = now_monotonic();
    std::string err;
    Stream s = open_through_proxy(p, target_host, target_port, timeout, remote_dns, err);
    if (!s.valid()) {
        result.error = err.empty() ? "FAILED" : err;
        return result;
    }

    result.ok = true;
    result.latency_ms = (now_monotonic() - t0) * 1000.0;
    return result;
}

bool verify_proxy(const ProxySpec& p, double timeout, bool remote_dns, std::string& category) {
    auto r = measure_proxy_latency(p, timeout, remote_dns);
    if (!r.ok) { category = r.error.empty() ? "FAILED" : r.error; return false; }
    char buf[96];
    std::snprintf(buf, sizeof buf, "REACHABLE (%.1f ms, proxy TCP+CONNECT)", r.latency_ms);
    category = buf;
    return true;
}

// Firefox command helpers
bool is_firefox_command(const std::vector<std::string>& cmd) {
    if (cmd.empty()) return false;
    std::string base = cmd[0];
    auto slash = base.find_last_of('/');
    if (slash != std::string::npos) base = base.substr(slash + 1);
    return base == "firefox" || base == "firefox-esr" ||
           base == "firefox-bin" || base == "firefox-developer-edition";
}
bool has_firefox_isolation_args(const std::vector<std::string>& cmd) {
    for (size_t i = 1; i < cmd.size(); ++i) {
        const auto& a = cmd[i];
        if (a == "--no-remote" || a == "--new-instance") return true;
        if (a == "-profile" || a == "--profile") return true;
        if (starts_with(a, "-profile=") || starts_with(a, "--profile=")) return true;
    }
    return false;
}
struct TempDir {
    std::string path;
    TempDir() {
        char tmpl[] = "/tmp/tunnel-firefox-XXXXXX";
        char* r = ::mkdtemp(tmpl);
        if (r) path = r;
    }
    ~TempDir() {
        if (!path.empty()) {
            std::string cmd = "rm -rf -- '" + path + "'";
            int rc = std::system(cmd.c_str()); (void)rc;
        }
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};
std::string build_firefox_profile(const std::string& host, uint16_t port, TempDir& td) {
    std::string user_js = td.path + "/user.js";
    std::ofstream f(user_js, std::ios::trunc);
    f << "user_pref(\"network.proxy.type\", 1);\n";
    f << "user_pref(\"network.proxy.socks\", \"" << host << "\");\n";
    f << "user_pref(\"network.proxy.socks_port\", " << port << ");\n";
    f << "user_pref(\"network.proxy.socks_version\", 5);\n";
    f << "user_pref(\"network.proxy.socks_remote_dns\", true);\n";
    f << "user_pref(\"network.proxy.share_proxy_settings\", true);\n";
    f << "user_pref(\"network.proxy.no_proxies_on\", \"\");\n";
    f << "user_pref(\"network.trr.mode\", 5);\n";
    return td.path;
}

// Runtime mode handlers
int run_server_mode(const Args& args, std::vector<ProxySpec> proxies) {
    std::optional<ProxySpec> fixed;
    if (args.proxy) {
        ProxySpec p; std::string err;
        if (!parse_proxy_url(*args.proxy, p, err)) { log_err("Error: invalid --proxy: " + err); return 2; }
        p.no_udp = args.tor;
        fixed = p;
    }
    if (fixed && args.rotate) { log_err("Error: --rotate cannot be combined with --proxy."); return 2; }

    std::vector<ProxySpec> pool_items;
    if (fixed) {
        bool found = false;
        for (auto& p : proxies) if (p.key() == fixed->key()) { found = true; break; }
        if (!found)
            log_err("[tunnel] warning: " + mask_proxy(*fixed) + " is not in " + args.file + "; using it anyway.");
        pool_items.push_back(*fixed);
    } else pool_items = std::move(proxies);

    std::string host = args.host;
    if (host == "localhost") host = "127.0.0.1";
    auto auth_user = args.auth_user; auto auth_pass = args.auth_pass;
    if (auth_user.has_value() != auth_pass.has_value()) {
        log_err("Error: --auth-user and --auth-pass must be provided together."); return 2;
    }
    bool loopback = (host == "127.0.0.1" || host == "::1" || host == "localhost");
    if (!loopback) {
        struct in_addr a4; struct in6_addr a6;
        if (::inet_pton(AF_INET, host.c_str(), &a4) == 1) loopback = (ntohl(a4.s_addr) >> 24) == 127;
        else if (::inet_pton(AF_INET6, host.c_str(), &a6) == 1) loopback = IN6_IS_ADDR_LOOPBACK(&a6);
    }
    if (!loopback && (!auth_user || !auth_pass)) {
        log_err("Error: non-loopback SOCKS5 binds require --auth-user and --auth-pass."); return 2;
    }
    if (auth_user) {
        if (auth_user->empty() || auth_user->size() > 255) { log_err("Error: local SOCKS username must be 1..255 bytes."); return 2; }
        if (auth_pass->empty() || auth_pass->size() > 255) { log_err("Error: local SOCKS password must be 1..255 bytes."); return 2; }
    }

    auto pool = std::make_shared<ProxyPool>(std::move(pool_items), fixed, args.rotate);
    if (!fixed) {
        auto results = pool->refresh_pings(std::min(args.connect_timeout, args.ping_timeout), !args.local_dns, args.ping_host, args.ping_port);
        auto best = pool->best_ping();
        if (!best) { log_err("[tunnel] no reachable upstream proxies"); return 1; }
        pool->set_active(best->proxy);
        char buf[160];
        size_t ok = 0; for (const auto& r : results) if (r.ok) ++ok;
        std::snprintf(buf, sizeof buf, "[ping] Initial best: %.1f ms | %s | %zu/%zu reachable",
                      best->latency_ms, mask_proxy(best->proxy).c_str(), ok, results.size());
        log_line(buf);
    } else if (args.verify) {
        ProxySpec sel = *fixed;
        std::string cat;
        if (!verify_proxy(sel, args.connect_timeout, !args.local_dns, cat)) {
            log_err("[FAIL] " + mask_proxy(sel) + " | " + cat); return 1;
        }
        log_line("[OK] " + mask_proxy(sel) + " | " + cat);
    }

    SocksServer app(pool, host, args.port,
                    args.connect_timeout, args.idle_timeout,
                    args.max_clients, auth_user, auth_pass,
                    args.verbose, !args.local_dns);
    std::string err;
    if (!app.start(err)) { log_err("Error: " + err); return 1; }

    log_line("========================================================================");
    log_line("[tunnel] Local SOCKS5 server started");
    log_line("[tunnel] Listen:  " + host + ":" + std::to_string(app.port()));
    log_line(std::string("[tunnel] Auth:    ") + (auth_user ? "username/password" : "none"));
    log_line("[tunnel] Pool:    smart lowest-latency upstream");
    log_line("[tunnel] Clients: max " + std::to_string(args.max_clients));
    char buf[64]; std::snprintf(buf, sizeof buf, "[tunnel] Idle:    %.0fs", args.idle_timeout);
    log_line(buf);
    log_line("========================================================================");
    if (fixed) log_line("[tunnel] Upstream: " + mask_proxy(*fixed));
    else {
        if (auto best = pool->best_ping()) {
            char buf[128];
            std::snprintf(buf, sizeof buf, "[tunnel] Upstream pool: %zu proxies | current best %.1f ms | %s",
                          pool->size(), best->latency_ms, mask_proxy(best->proxy).c_str());
            log_line(buf);
        } else {
            log_line("[tunnel] Upstream pool: " + std::to_string(pool->size()) + " proxies");
        }
    }
    ProxyAutoSwitchMonitor monitor(pool, args.auto_switch_interval,
                                   std::min(args.connect_timeout, args.ping_timeout),
                                   !args.local_dns, args.verbose, args.ping_host, args.ping_port);
    monitor.start();
    if (!fixed && args.auto_switch_interval > 0.0)
        log_line("[auto-switch] enabled every " + std::to_string(args.auto_switch_interval) + "s");
    else if (!fixed)
        log_line("[tunnel] Sticky upstream selection: switch only after connection failure");

    static std::atomic<bool> stop_flag{false};
    stop_flag.store(false);
    struct sigaction sa{};
    sa.sa_handler = [](int){ stop_flag.store(true); };
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    while (!stop_flag.load()) std::this_thread::sleep_for(std::chrono::milliseconds(200));

    monitor.stop();
    app.stop();
    log_line("");
    log_line("[tunnel] Server stopped");
    log_line("[tunnel] Total clients: " + std::to_string(app.stats().total_clients.load()));
    log_line("[tunnel] Failed clients: " + std::to_string(app.stats().failed_clients.load()));
    log_line("[tunnel] Uploaded: " + std::to_string(app.stats().bytes_up.load()) + " bytes");
    log_line("[tunnel] Downloaded: " + std::to_string(app.stats().bytes_down.load()) + " bytes");
    return 0;
}

int run_command_mode(const Args& args, std::vector<ProxySpec> proxies) {
    if (args.command.empty()) {
        log_err("Error: no command given. Example: tunnel curl https://ifconfig.me");
        return 2;
    }
    std::optional<ProxySpec> fixed;
    if (args.proxy) {
        ProxySpec p; std::string err;
        if (!parse_proxy_url(*args.proxy, p, err)) { log_err("Error: invalid --proxy: " + err); return 2; }
        p.no_udp = args.tor;
        fixed = p;
    }
    std::vector<ProxySpec> pool_items;
    if (fixed) pool_items.push_back(*fixed);
    else       pool_items = std::move(proxies);

    auto pool = std::make_shared<ProxyPool>(pool_items, fixed, args.rotate);
    ProxySpec selected = fixed ? *fixed : pool->choose();
    if (!fixed) {
        auto results = pool->refresh_pings(std::min(args.connect_timeout, args.ping_timeout), !args.local_dns, args.ping_host, args.ping_port);
        auto best = pool->best_ping();
        if (!best) { log_err("[tunnel] no reachable upstream proxies"); return 1; }
        selected = best->proxy;
        pool->set_active(best->proxy);
        char buf[160];
        size_t ok = 0; for (const auto& r : results) if (r.ok) ++ok;
        std::snprintf(buf, sizeof buf, "[ping] Initial best: %.1f ms | %s | %zu/%zu reachable",
                      best->latency_ms, mask_proxy(best->proxy).c_str(), ok, results.size());
        log_line(buf);
    }
    if (args.verify) {
        std::string cat;
        if (!verify_proxy(selected, args.connect_timeout, !args.local_dns, cat)) {
            log_err("[FAIL] " + mask_proxy(selected) + " | " + cat); return 1;
        }
        log_line("[OK] " + mask_proxy(selected) + " | " + cat);
    }
    log_line("[tunnel] Initial upstream: " + mask_proxy(selected));

    SocksServer app(pool, "127.0.0.1", 0,
                    args.connect_timeout, args.idle_timeout,
                    args.max_clients, std::nullopt, std::nullopt,
                    false, !args.local_dns);
    std::string err;
    if (!app.start(err)) { log_err("Error: " + err); return 1; }

    uint16_t local_port = app.port();
    log_line("[tunnel] Local bridge: 127.0.0.1:" + std::to_string(local_port));
    log_line(std::string("[tunnel] Client mode: ") +
             (fixed ? "fixed upstream" : (args.auto_switch_interval > 0.0 ? "opt-in auto-switching upstream" : "sticky upstream; switch on connection failure")));

    std::vector<std::string> cmd = args.command;
    TempDir firefox_td;
    bool firefox_mode = is_firefox_command(cmd) && !args.no_firefox_special;

    if (firefox_mode && !has_firefox_isolation_args(cmd)) {
        std::string profile = build_firefox_profile("127.0.0.1", local_port, firefox_td);
        if (profile.empty()) { log_err("Error: cannot create Firefox profile directory."); app.stop(); return 1; }
        cmd.push_back("--no-remote");
        cmd.push_back("--new-instance");
        cmd.push_back("-profile");
        cmd.push_back(profile);
        log_line("[tunnel] Firefox isolation enabled: new instance + dedicated profile");
    }
    log_line("[tunnel] Command output begins below.");
    log_line("");

    pid_t pid = ::fork();
    if (pid == 0) {
        std::string proxy_url = "socks5://127.0.0.1:" + std::to_string(local_port);
        ::setenv("TELEGRAM_PROXY", proxy_url.c_str(), 1);
        ::setenv("ALL_PROXY", proxy_url.c_str(), 1);
        ::setenv("all_proxy", proxy_url.c_str(), 1);
        ::setenv("MOZ_NO_REMOTE", "1", 1);
        std::vector<char*> argv;
        for (auto& s : cmd) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        ::execvp(cmd[0].c_str(), argv.data());
        std::perror("exec");
        _exit(127);
    }
    if (pid < 0) { log_err("Error: fork failed."); app.stop(); return 1; }

    ProxyAutoSwitchMonitor monitor(pool, args.auto_switch_interval,
                                   std::min(args.connect_timeout, args.ping_timeout),
                                   !args.local_dns, args.verbose, args.ping_host, args.ping_port);
    monitor.start();
    if (!fixed && args.auto_switch_interval > 0.0)
        log_line("[auto-switch] enabled every " + std::to_string(args.auto_switch_interval) + "s");

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    int rc = 1;
    if (WIFEXITED(status)) rc = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) rc = 128 + WTERMSIG(status);

    if (firefox_mode && app.stats().total_clients.load() == 0) {
        log_err("[tunnel] WARNING: Firefox exited without opening any tunnel connection.");
    }
    monitor.stop();
    app.stop();
    return rc;
}

} // namespace tunnel
