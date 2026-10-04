#include "config.h"
#include "core.h"
#include "proxy.h"
#include "servers.h"
#include "global.h"
#include "cli.h"
#include "modes.h"

namespace tunnel {

std::string random_token(size_t length = 20) {
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937_64 gen((static_cast<uint64_t>(rd()) << 32) ^ rd() ^ static_cast<uint64_t>(::getpid()));
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphabet) - 2);
    std::string out;
    out.reserve(length);
    for (size_t i = 0; i < length; ++i) out.push_back(alphabet[dist(gen)]);
    return out;
}

std::string tor_proxy_url(const Args& args) {
    std::string host = args.tor_host;
    if (host.find(':') != std::string::npos && (host.empty() || host.front() != '[')) host = "[" + host + "]";
    std::string userinfo;
    if (args.tor_isolate) userinfo = random_token(20) + ":" + random_token(24) + "@";
    return "socks5h://" + userinfo + host + ":" + std::to_string(args.tor_port);
}

bool configure_tor_proxy(Args& args, std::string& err) {
    if (!args.tor) return true;
    if (args.proxy) { err = "--tor cannot be combined with --proxy"; return false; }
    if (args.tor_browser && !args.tor_port_explicit) args.tor_port = 9150;
    if (args.tor_host.empty()) { err = "--tor-host must not be empty"; return false; }
    args.proxy = tor_proxy_url(args);
    return true;
}

} // namespace tunnel

int main(int argc, char** argv) {
    using namespace tunnel;
    ::signal(SIGPIPE, SIG_IGN);

    Args args;
    std::string err;
    if (!parse_args(argc, argv, args, err)) {
        log_err("Error: " + err);
        print_usage(argv[0]);
        return 2;
    }
    if (args.tor_check && !args.check_ping) args.check_ping = true;
    if (!configure_tor_proxy(args, err)) {
        log_err("Error: " + err);
        return 2;
    }

    if (args.version) { std::cout << "Tunnel " << kVersion << "\n"; return 0; }
    if (args.doctor) {
        struct utsname u{};
        if (::uname(&u) == 0) log_line(std::string("[doctor] kernel: ") + u.sysname + " " + u.release);
        log_line(std::string("[doctor] nft: ") + (nft_available() ? "available" : "missing"));
        log_line(std::string("[doctor] root: ") + (::geteuid() == 0 ? "yes" : "no"));
        log_line(std::string("[doctor] /run: ") + ((::access("/run", W_OK) == 0) ? "writable" : "not writable"));
        if (auto f = read_default_proxy_file()) log_line("[doctor] configured proxy file: " + *f);
        else log_line("[doctor] configured proxy file: none");
        return 0;
    }

    if (args.set_proxy_file) {
        std::string e;
        if (!set_default_proxy_file(args.file, e)) { log_err("Error: " + e); return 1; }
        log_line("[config] default proxy file set to: " + args.file);
        return 0;
    }
    if (args.clear_proxy_file) {
        std::string e;
        if (!clear_default_proxy_file(e)) { log_err("Error: " + e); return 1; }
        log_line("[config] default proxy file cleared.");
        return 0;
    }
    if (args.show_proxy_file) {
        if (auto f = read_default_proxy_file()) log_line("[config] default proxy file: " + *f);
        else log_line("[config] default proxy file: none");
        return 0;
    }
    if (args.emergency_disable_global) return cmd_emergency_disable_global();
    if (args.global_status) return cmd_global_status();
    if (args.disable_global) return cmd_disable_global();

    if (args.enable_global && ::geteuid() != 0) {
        log_err("Error: --enable-global requires root. Run it with sudo.");
        return 2;
    }

    if (!args.file_explicit && !args.proxy && !args.global_status && !args.disable_global &&
        !args.doctor && !args.version) {
        if (auto configured = read_default_proxy_file()) {
            args.file = *configured;
            args.file_explicit = true;
            log_line("[config] using configured proxy file: " + args.file);
        } else {
            log_err("Error: no proxy file configured. Use --file PATH or set a default with --set-proxy-file PATH.");
            return 2;
        }
    }

    if (args.check_ping && (args.server || !args.command.empty() || args.enable_global || args.daemon_global)) {
        log_err("Error: --check-ping is a standalone command and cannot be combined with server/global/command modes.");
        return 2;
    }
    if (args.server && !args.command.empty()) {
        log_err("Error: do not provide a command together with --server.");
        return 2;
    }

    std::vector<ProxySpec> proxies;
    if (!args.enable_global && (args.file_explicit || !args.proxy)) {
        try {
            proxies = load_proxies(args.file);
        } catch (const std::exception& e) {
            log_err(std::string("Error: ") + e.what());
            return 1;
        }
    }

    try {
        if (args.list_proxies) {
            if (args.server || !args.command.empty() || args.enable_global || args.daemon_global || args.check_ping) {
                log_err("Error: --list-proxies is a standalone action and cannot be combined with a runtime mode.");
                return 2;
            }
            if (args.proxy) {
                ProxySpec p; std::string e;
                if (!parse_proxy_url(*args.proxy, p, e)) { log_err("Error: invalid --proxy: " + e); return 2; }
                p.no_udp = args.tor;
                std::cout << "1. " << mask_proxy(p) << "\n";
            } else {
                for (size_t i = 0; i < proxies.size(); ++i)
                    std::cout << (i + 1) << ". " << mask_proxy(proxies[i]) << "\n";
                std::cout << "Total: " << proxies.size() << "\n";
            }
            return 0;
        }
        if (args.check_ping) return cmd_check_ping(args, proxies);
        if (args.enable_global) return cmd_enable_global(args, std::move(proxies));
        if (args.daemon_global) return run_global_daemon(args, std::move(proxies));
        if (args.server) return run_server_mode(args, std::move(proxies));
        return run_command_mode(args, std::move(proxies));
    } catch (const std::exception& e) {
        log_err(std::string("[tunnel] fatal error: ") + e.what());
        return 1;
    }
}
