#pragma once

#include "global.h"

namespace tunnel {

// Command-line interface and option parsing
void print_usage(const char* argv0) {
    std::cout <<
"Usage: " << argv0 << " [mode/options] [command...]\n"
"\n"
"Common examples:\n"
"  " << argv0 << " --tor curl https://example.com\n"
"  " << argv0 << " --tor --server --port 9050\n"
"  " << argv0 << " --server --file /etc/tunnel/proxies.txt\n"
"  sudo " << argv0 << " --enable-global --file /etc/tunnel/proxies.txt\n"
"  sudo " << argv0 << " --enable-global --tor\n"
"\n"
"Modes / actions:\n"
"  --server               Start local SOCKS5 server\n"
"  --enable-global         Start fail-closed global transparent mode\n"
"  --disable-global        Stop global mode and clean owned firewall state\n"
"  --emergency-disable-global\n"
"                         Hard recovery: remove firewall state + stop daemon\n"
"  --global-status          Show global daemon/firewall status\n"
"  --daemon-global          Internal foreground global daemon entrypoint\n"
"  --check-ping             Test upstream proxies and sort by latency\n"
"  --list-proxies           List configured/selected proxies with masked credentials\n"
"  --doctor                 Check Linux runtime prerequisites\n"
"  --version                Show version\n"
"  -h, --help               Show this help\n"
"\n"
"Upstream selection:\n"
"  --proxy URL              Use one fixed upstream proxy\n"
"  --file PATH              Proxy list file (overrides configured default)\n"
"  --set-proxy-file PATH    Persist PATH as the default proxy list\n"
"  --clear-proxy-file       Remove the persisted proxy-list default\n"
"  --show-proxy-file        Show the configured default proxy list path\n"
"  --rotate                 Compatibility flag; connection failover is always enabled\n"
"  --verify                 Verify selected upstream before starting command/server\n"
"  --auto-switch SEC        Re-test/select fastest proxy every SEC seconds\n"
"  --ping-interval SEC      Alias for --auto-switch\n"
"  --ping-timeout SEC       Ping/preflight timeout (default 8)\n"
"  --ping-host HOST         Ping target host (default api.telegram.org)\n"
"  --ping-port PORT         Ping target port (default 443)\n"
"\n"
"Tor integration:\n"
"  --tor                    Use local Tor SOCKS5h at HOST:PORT (default 127.0.0.1:9050)\n"
"  --tor-host HOST          Tor SOCKS listen host (default 127.0.0.1)\n"
"  --tor-port PORT          Tor SOCKS listen port (default 9050)\n"
"  --tor-browser            Shortcut for Tor Browser's usual SOCKS port 9150\n"
"  --tor-isolate            Use a fresh SOCKS username/password for Tor stream isolation\n"
"  --tor-check              Alias for --tor --check-ping\n"
"\n"
"Local SOCKS5 server:\n"
"  --host HOST              Bind host (default 127.0.0.1)\n"
"  --port PORT              Server SOCKS port / global SOCKS port (default 39481/1080)\n"
"  --auth-user USER         Local SOCKS5 username\n"
"  --auth-pass PASS         Local SOCKS5 password\n"
"  --local-dns              Resolve destination names locally instead of remotely\n"
"  --max-clients N          Max simultaneous clients (default 256)\n"
"\n"
"Global mode:\n"
"  --http-port PORT         Local global HTTP CONNECT port (default 8118)\n"
"  --system-proxy           Opt-in desktop/system proxy integration\n"
"  --connect-timeout SEC    Upstream connection timeout (default 8)\n"
"  --idle-timeout SEC       Idle timeout per direction (default 300)\n"
"  -v, --verbose            Verbose diagnostics\n"
"\n"
"Command mode:\n"
"  " << argv0 << " firefox\n"
"  " << argv0 << " --tor curl https://ifconfig.me\n"
"  " << argv0 << " --proxy socks5h://user:pass@proxy.example:1080 curl https://example.com\n"
"\n"
"Notes:\n"
"  - Supported upstream schemes: http://, socks4://, socks4a://, socks5://, socks5h://\n"
"  - https:// upstream proxies are rejected because Tunnel has no TLS proxy backend.\n"
"  - --tor uses SOCKS5h so DNS can remain inside Tor unless --local-dns is explicitly set.\n"
"  - --proxy and --tor do not require a proxy list file.\n";
}

bool parse_args(int argc, char** argv, Args& out, std::string& err) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { err = std::string("missing value for ") + name; return {}; }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") { print_usage(argv[0]); std::exit(0); }
        else if (a == "--server") out.server = true;
        else if (a == "--host") { out.host = need("--host"); if (!err.empty()) return false; }
        else if (a == "--port") {
            std::string v = need("--port"); if (!err.empty()) return false;
            try { int p = std::stoi(v); if (p < 1 || p > 65535) throw std::out_of_range(""); out.port = (uint16_t)p; }
            catch (...) { err = "invalid port: " + v; return false; }
        }
        else if (a == "--proxy") { out.proxy = need("--proxy"); if (!err.empty()) return false; }
        else if (a == "--tor") out.tor = true;
        else if (a == "--tor-browser") { out.tor = true; out.tor_browser = true; out.tor_port = 9150; }
        else if (a == "--tor-isolate") { out.tor = true; out.tor_isolate = true; }
        else if (a == "--tor-check") { out.tor = true; out.tor_check = true; out.check_ping = true; }
        else if (a == "--tor-host") { out.tor_host = need("--tor-host"); if (!err.empty()) return false; }
        else if (a == "--tor-port") {
            std::string v = need("--tor-port"); if (!err.empty()) return false;
            try { int p = std::stoi(v); if (p < 1 || p > 65535) throw std::out_of_range(""); out.tor_port = (uint16_t)p; out.tor_port_explicit = true; }
            catch (...) { err = "invalid tor port: " + v; return false; }
        }
        else if (a == "--file") { out.file = need("--file"); if (!err.empty()) return false; out.file_explicit = true; }
        else if (a == "--rotate") out.rotate = true;
        else if (a == "--auto-switch") {
            std::string v = need("--auto-switch"); if (!err.empty()) return false;
            try { double d = std::stod(v); if (d < 1.0) throw std::out_of_range(""); out.auto_switch_interval = d; }
            catch (...) { err = "invalid auto-switch interval: " + v; return false; }
        }
        else if (a == "--verify") out.verify = true;
        else if (a == "--check-ping") out.check_ping = true;
        else if (a == "--ping-interval") {
            std::string v = need("--ping-interval"); if (!err.empty()) return false;
            try { double d = std::stod(v); if (d < 1.0) throw std::out_of_range(""); out.auto_switch_interval = d; }
            catch (...) { err = "invalid ping interval: " + v; return false; }
        }
        else if (a == "--ping-timeout") {
            std::string v = need("--ping-timeout"); if (!err.empty()) return false;
            try { double d = std::stod(v); if (d <= 0) throw std::out_of_range(""); out.ping_timeout = d; }
            catch (...) { err = "invalid ping timeout: " + v; return false; }
        }
        else if (a == "--ping-host") { out.ping_host = need("--ping-host"); if (!err.empty()) return false; if (out.ping_host.empty()) { err = "ping host must not be empty"; return false; } }
        else if (a == "--ping-port") {
            std::string v = need("--ping-port"); if (!err.empty()) return false;
            try { int p = std::stoi(v); if (p < 1 || p > 65535) throw std::out_of_range(""); out.ping_port = (uint16_t)p; }
            catch (...) { err = "invalid ping port: " + v; return false; }
        }
        else if (a == "--bot-token") { out.bot_token = need("--bot-token"); if (!err.empty()) return false; }
        else if (a == "--connect-timeout") {
            std::string v = need("--connect-timeout"); if (!err.empty()) return false;
            try { double d = std::stod(v); if (d <= 0) throw std::out_of_range(""); out.connect_timeout = d; }
            catch (...) { err = "invalid connect timeout: " + v; return false; }
        }
        else if (a == "--idle-timeout") {
            std::string v = need("--idle-timeout"); if (!err.empty()) return false;
            try { double d = std::stod(v); if (d <= 0) throw std::out_of_range(""); out.idle_timeout = d; }
            catch (...) { err = "invalid idle timeout: " + v; return false; }
        }
        else if (a == "--http-port") {
            std::string v = need("--http-port"); if (!err.empty()) return false;
            try { int p = std::stoi(v); if (p < 1 || p > 65535) throw std::out_of_range(""); out.http_port = (uint16_t)p; }
            catch (...) { err = "invalid http port: " + v; return false; }
        }
        else if (a == "--list-proxies") out.list_proxies = true;
        else if (a == "--max-clients") {
            std::string v = need("--max-clients"); if (!err.empty()) return false;
            try { int n = std::stoi(v); if (n < 1) throw std::out_of_range(""); out.max_clients = n; }
            catch (...) { err = "invalid max-clients: " + v; return false; }
        }
        else if (a == "--auth-user") { out.auth_user = need("--auth-user"); if (!err.empty()) return false; }
        else if (a == "--auth-pass") { out.auth_pass = need("--auth-pass"); if (!err.empty()) return false; }
        else if (a == "--local-dns") out.local_dns = true;
        else if (a == "--no-firefox-special") out.no_firefox_special = true;
        else if (a == "-v" || a == "--verbose") out.verbose = true;
        else if (a == "--enable-global") out.enable_global = true;
        else if (a == "--system-proxy") out.system_proxy = true;
        else if (a == "--disable-global") out.disable_global = true;
        else if (a == "--emergency-disable-global") out.emergency_disable_global = true;
        else if (a == "--set-proxy-file") { out.file = need("--set-proxy-file"); if (!err.empty()) return false; out.set_proxy_file = true; }
        else if (a == "--clear-proxy-file") out.clear_proxy_file = true;
        else if (a == "--show-proxy-file") out.show_proxy_file = true;
        else if (a == "--global-status") out.global_status = true;
        else if (a == "--daemon-global") out.daemon_global = true;
        else if (a == "--doctor") out.doctor = true;
        else if (a == "--version") out.version = true;
        else if (a == "--") {
            for (int j = i + 1; j < argc; ++j) out.command.push_back(argv[j]);
            break;
        }
        else if (!a.empty() && a[0] == '-' && a != "-") { err = "unknown option: " + a; return false; }
        else {
            for (int j = i; j < argc; ++j) out.command.push_back(argv[j]);
            break;
        }
    }
    return true;
}

} // namespace tunnel
