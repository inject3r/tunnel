#pragma once

#include "servers.h"

namespace tunnel {

// Global mode support
// ====================================================================
struct GlobalState {
    uint16_t    socks_port = 0;
    uint16_t    http_port = 0;
    uint16_t    transparent_tcp_port = kTransparentTcpPort;
    uint16_t    transparent_udp_port = kTransparentUdpPort;
    uint16_t    dns_proxy_port = kDnsProxyPort;
    pid_t       pid = 0;
    pid_t       guardian_pid = 0;
    bool        firewall_enforced = false;
    bool        system_proxy_applied = false;
    std::string started_at;
};

bool write_global_state(const GlobalState& gs) {
    std::ofstream f(kStateFile, std::ios::trunc);
    if (!f.is_open()) return false;
    f << "socks_port=" << gs.socks_port << "\n";
    f << "http_port="  << gs.http_port  << "\n";
    f << "transparent_tcp_port=" << gs.transparent_tcp_port << "\n";
    f << "transparent_udp_port=" << gs.transparent_udp_port << "\n";
    f << "dns_proxy_port=" << gs.dns_proxy_port << "\n";
    f << "pid="        << gs.pid        << "\n";
    f << "guardian_pid=" << gs.guardian_pid << "\n";
    f << "firewall_enforced=" << (gs.firewall_enforced ? 1 : 0) << "\n";
    f << "system_proxy_applied=" << (gs.system_proxy_applied ? 1 : 0) << "\n";
    f << "started_at=" << gs.started_at << "\n";
    f.close();
    ::chmod(kStateFile, 0644);
    return true;
}

bool read_global_state(GlobalState& gs) {
    std::ifstream f(kStateFile);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq + 1));
        if (k == "socks_port") { try { gs.socks_port = (uint16_t)std::stoi(v); } catch (...) {} }
        else if (k == "http_port") { try { gs.http_port = (uint16_t)std::stoi(v); } catch (...) {} }
        else if (k == "transparent_tcp_port") { try { gs.transparent_tcp_port = (uint16_t)std::stoi(v); } catch (...) {} }
        else if (k == "transparent_udp_port") { try { gs.transparent_udp_port = (uint16_t)std::stoi(v); } catch (...) {} }
        else if (k == "dns_proxy_port") { try { gs.dns_proxy_port = (uint16_t)std::stoi(v); } catch (...) {} }
        else if (k == "pid") { try { gs.pid = (pid_t)std::stoi(v); } catch (...) {} }
        else if (k == "guardian_pid") { try { gs.guardian_pid = (pid_t)std::stoi(v); } catch (...) {} }
        else if (k == "firewall_enforced") { gs.firewall_enforced = (v == "1"); }
        else if (k == "system_proxy_applied") { gs.system_proxy_applied = (v == "1"); }
        else if (k == "started_at") gs.started_at = v;
    }
    return true;
}

void remove_global_state() {
    ::unlink(kStateFile);
    ::unlink(kPidFile);
    ::unlink(kGuardianPidFile);
}

bool process_exists(pid_t pid) {
    if (pid <= 0) return false;
    errno = 0;
    if (::kill(pid, 0) == 0) return true;
    // A normal user cannot signal a root-owned daemon, but EPERM still proves
    // that the process exists. Global status must report it as ALIVE.
    return errno == EPERM;
}

int run_shell(const std::string& cmd, bool quiet = true) {
    std::string full = cmd;
    if (quiet) full += " >/dev/null 2>&1";
    int rc = std::system(full.c_str());
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

class GlobalLock {
public:
    GlobalLock() {
        fd_ = ::open(kGlobalLockFile, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
        if (fd_ >= 0) {
            if (::flock(fd_, LOCK_EX) != 0) { ::close(fd_); fd_ = -1; }
        }
    }
    ~GlobalLock() {
        if (fd_ >= 0) { ::flock(fd_, LOCK_UN); ::close(fd_); }
    }
    GlobalLock(const GlobalLock&) = delete;
    GlobalLock& operator=(const GlobalLock&) = delete;
    bool valid() const { return fd_ >= 0; }
private:
    int fd_ = -1;
};

std::string nft_binary() {
    static const char* candidates[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft" };
    for (const char* c : candidates) if (::access(c, X_OK) == 0) return c;
    const char* path = std::getenv("PATH");
    if (path) {
        for (const auto& dir : split(path, ':')) {
            if (dir.empty()) continue;
            std::string p = dir + "/nft";
            if (::access(p.c_str(), X_OK) == 0) return p;
        }
    }
    return {};
}

int run_argv_timeout(const std::vector<std::string>& args, double timeout_s) {
    if (args.empty()) return -1;
    pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        std::vector<char*> av;
        av.reserve(args.size() + 1);
        for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr);
        ::execv(av[0], av.data());
        _exit(127);
    }
    const double deadline = now_monotonic() + std::max(0.1, timeout_s);
    while (now_monotonic() < deadline) {
        int status = 0;
        pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    ::kill(pid, SIGKILL);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return -ETIMEDOUT;
}

int run_nft(const std::vector<std::string>& nft_args, double timeout_s = 2.0) {
    const std::string bin = nft_binary();
    if (bin.empty()) return -ENOENT;
    std::vector<std::string> av;
    av.reserve(nft_args.size() + 1);
    av.push_back(bin);
    for (const auto& a : nft_args) av.push_back(a);
    return run_argv_timeout(av, timeout_s);
}

std::string get_invoking_user() {
    const char* sudo_user = ::getenv("SUDO_USER");
    if (sudo_user && *sudo_user) return sudo_user;
    const char* user = ::getenv("USER");
    if (user && *user) return user;
    struct passwd* pw = ::getpwuid(::getuid());
    if (pw && pw->pw_name) return pw->pw_name;
    return "";
}

std::optional<std::string> user_config_file() {
    const char* sudo_user = ::getenv("SUDO_USER");
    struct passwd* pw = nullptr;
    if (sudo_user && *sudo_user) pw = ::getpwnam(sudo_user);
    if (!pw) pw = ::getpwuid(::getuid());
    if (!pw || !pw->pw_dir || !*pw->pw_dir) return std::nullopt;

    const char* xdg = ::getenv("XDG_CONFIG_HOME");
    if (!(sudo_user && *sudo_user) && xdg && *xdg)
        return std::string(xdg) + "/tunnel/tunnel.conf";
    return std::string(pw->pw_dir) + "/.config/tunnel/tunnel.conf";
}

std::optional<std::string> read_config_proxy_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return std::nullopt;
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        if (trim(line.substr(0, eq)) != "proxy_file") continue;
        std::string value = trim(line.substr(eq + 1));
        if (!value.empty()) return value;
    }
    return std::nullopt;
}

std::optional<std::string> read_default_proxy_file() {
    if (auto system = read_config_proxy_file(kSystemConfigFile)) return system;
    if (auto user_path = user_config_file())
        return read_config_proxy_file(*user_path);
    return std::nullopt;
}

bool set_default_proxy_file(const std::string& path, std::string& err) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        err = "proxy file does not exist or is not a regular file: " + path;
        return false;
    }
    try {
        const auto parsed = load_proxies(path);
        if (parsed.empty()) { err = "proxy file contains no valid proxies: " + path; return false; }
    } catch (const std::exception& e) {
        err = "proxy file is invalid: " + std::string(e.what());
        return false;
    }

    const std::string config_file = (::geteuid() == 0)
        ? std::string(kSystemConfigFile)
        : user_config_file().value_or(std::string());
    if (config_file.empty()) {
        err = "cannot determine a user configuration directory";
        return false;
    }
    // Create the parent directory hierarchy with std::filesystem to keep the
    // persistent configuration path independent of the current directory.
    try {
        std::filesystem::create_directories(std::filesystem::path(config_file).parent_path());
    } catch (const std::exception& e) {
        err = "cannot create configuration directory: " + std::string(e.what());
        return false;
    }

    const std::string tmp = config_file + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) { err = "cannot write " + tmp; return false; }
        f << "proxy_file=" << path << "\n";
    }
    ::chmod(tmp.c_str(), 0644);
    if (::rename(tmp.c_str(), config_file.c_str()) != 0) {
        ::unlink(tmp.c_str());
        err = "cannot install " + config_file + ": " + strerror(errno);
        return false;
    }
    return true;
}

bool clear_default_proxy_file(std::string& err) {
    const std::string config_file = (::geteuid() == 0)
        ? std::string(kSystemConfigFile)
        : user_config_file().value_or(std::string());
    if (config_file.empty()) {
        err = "cannot determine a user configuration directory";
        return false;
    }
    if (::unlink(config_file.c_str()) != 0 && errno != ENOENT) {
        err = "cannot remove " + config_file + ": " + strerror(errno);
        return false;
    }
    return true;
}

std::optional<pid_t> read_pid_file(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) return std::nullopt;
    long long v = 0;
    f >> v;
    if (!f || v <= 0) return std::nullopt;
    return static_cast<pid_t>(v);
}

bool write_pid_file(const char* path, pid_t pid) {
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;
    f << pid << "\n";
    f.close();
    ::chmod(path, 0644);
    return true;
}

bool command_exists(const std::string& name) {
    return run_shell("command -v " + name) == 0;
}

void set_gnome_proxy(uint16_t http_port, uint16_t socks_port, bool enable) {
    if (!command_exists("gsettings")) return;
    std::string user = get_invoking_user();
    std::string prefix;
    if (::geteuid() == 0 && !user.empty()) prefix = "sudo -u " + user + " ";

    if (enable) {
        run_shell(prefix + "gsettings set org.gnome.system.proxy mode 'manual'");
        run_shell(prefix + "gsettings set org.gnome.system.proxy.http host '127.0.0.1'");
        run_shell(prefix + "gsettings set org.gnome.system.proxy.http port " + std::to_string(http_port));
        run_shell(prefix + "gsettings set org.gnome.system.proxy.https host '127.0.0.1'");
        run_shell(prefix + "gsettings set org.gnome.system.proxy.https port " + std::to_string(http_port));
        run_shell(prefix + "gsettings set org.gnome.system.proxy.ftp host '127.0.0.1'");
        run_shell(prefix + "gsettings set org.gnome.system.proxy.ftp port " + std::to_string(http_port));
        run_shell(prefix + "gsettings set org.gnome.system.proxy.socks host '127.0.0.1'");
        run_shell(prefix + "gsettings set org.gnome.system.proxy.socks port " + std::to_string(socks_port));
        run_shell(prefix + "gsettings set org.gnome.system.proxy ignore-hosts "
                  "'[\"localhost\", \"127.0.0.0/8\", \"::1\"]'");
    } else {
        run_shell(prefix + "gsettings set org.gnome.system.proxy mode 'none'");
    }
}

bool set_etc_environment(uint16_t http_port, uint16_t socks_port, bool enable) {
    const char* path = "/etc/environment";
    std::string begin = "# >>> tunnel-global begin >>>";
    std::string end   = "# <<< tunnel-global end <<<";

    std::string content;
    { std::ifstream f(path); if (f.is_open()) { std::ostringstream ss; ss << f.rdbuf(); content = ss.str(); } }

    std::string cleaned;
    size_t pos = 0;
    while (pos < content.size()) {
        auto b = content.find(begin, pos);
        if (b == std::string::npos) { cleaned.append(content, pos, std::string::npos); break; }
        cleaned.append(content, pos, b - pos);
        auto e = content.find(end, b);
        if (e == std::string::npos) break;
        pos = e + end.size();
        if (pos < content.size() && content[pos] == '\n') ++pos;
    }

    if (enable) {
        std::ostringstream o;
        o << cleaned;
        if (!cleaned.empty() && cleaned.back() != '\n') o << "\n";
        o << begin << "\n";
        o << "http_proxy=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "https_proxy=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "HTTP_PROXY=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "HTTPS_PROXY=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "ftp_proxy=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "FTP_PROXY=\"http://127.0.0.1:" << http_port << "\"\n";
        o << "all_proxy=\"socks5://127.0.0.1:" << socks_port << "\"\n";
        o << "ALL_PROXY=\"socks5://127.0.0.1:" << socks_port << "\"\n";
        o << "no_proxy=\"localhost,127.0.0.1,::1\"\n";
        o << "NO_PROXY=\"localhost,127.0.0.1,::1\"\n";
        o << end << "\n";
        cleaned = o.str();
    }

    std::string tmp = std::string(path) + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) return false;
        f << cleaned;
    }
    ::chmod(tmp.c_str(), 0644);
    if (::rename(tmp.c_str(), path) != 0) { ::unlink(tmp.c_str()); return false; }
    return true;
}

void set_apt_proxy(uint16_t http_port, bool enable) {
    const char* path = "/etc/apt/apt.conf.d/95tunnel-proxy";
    if (!enable) { ::unlink(path); return; }
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return;
    f << "// Generated by tunnel --enable-global\n";
    f << "Acquire::http::Proxy \"http://127.0.0.1:" << http_port << "\";\n";
    f << "Acquire::https::Proxy \"http://127.0.0.1:" << http_port << "\";\n";
    f.close();
    ::chmod(path, 0644);
}

void set_systemd_proxy(uint16_t http_port, uint16_t socks_port, bool enable) {
    const std::string dir = "/etc/systemd/system.conf.d";
    const std::string file = dir + "/tunnel-proxy.conf";
    if (!enable) {
        ::unlink(file.c_str());
        run_shell("systemctl daemon-reexec");
        return;
    }
    ::mkdir(dir.c_str(), 0755);
    std::ofstream f(file, std::ios::trunc);
    if (!f.is_open()) return;
    f << "# Generated by tunnel --enable-global\n";
    f << "[Manager]\n";
    f << "DefaultEnvironment=HTTP_PROXY=http://127.0.0.1:" << http_port << "\n";
    f << "DefaultEnvironment=HTTPS_PROXY=http://127.0.0.1:" << http_port << "\n";
    f << "DefaultEnvironment=ALL_PROXY=socks5://127.0.0.1:" << socks_port << "\n";
    f << "DefaultEnvironment=NO_PROXY=localhost,127.0.0.1,::1\n";
    f.close();
    ::chmod(file.c_str(), 0644);
    run_shell("systemctl daemon-reexec");
}

void set_kde_proxy(uint16_t http_port, uint16_t socks_port, bool enable) {
    if (!command_exists("kwriteconfig5") && !command_exists("kwriteconfig6")) return;
    std::string tool = command_exists("kwriteconfig6") ? "kwriteconfig6" : "kwriteconfig5";
    std::string user = get_invoking_user();
    std::string prefix;
    if (::geteuid() == 0 && !user.empty()) prefix = "sudo -u " + user + " ";

    if (enable) {
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key ProxyType 1");
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key httpProxy 'http://127.0.0.1:" + std::to_string(http_port) + "'");
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key httpsProxy 'http://127.0.0.1:" + std::to_string(http_port) + "'");
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key ftpProxy 'http://127.0.0.1:" + std::to_string(http_port) + "'");
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key socksProxy 'socks://127.0.0.1:" + std::to_string(socks_port) + "'");
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key NoProxyFor 'localhost,127.0.0.1,::1'");
    } else {
        run_shell(prefix + tool + " --file kioslaverc --group 'Proxy Settings' --key ProxyType 0");
    }
}

void apply_system_proxy(uint16_t http_port, uint16_t socks_port, bool enable) {
    set_gnome_proxy(http_port, socks_port, enable);
    set_kde_proxy(http_port, socks_port, enable);
    set_etc_environment(http_port, socks_port, enable);
    set_apt_proxy(http_port, enable);
    if (command_exists("systemctl")) set_systemd_proxy(http_port, socks_port, enable);
}

// Kernel firewall
std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

bool nft_available() {
    return !nft_binary().empty();
}

bool global_firewall_active();

bool remove_global_firewall_unlocked() {
    if (nft_binary().empty()) return false;
    bool removed = false;
    const std::vector<std::vector<std::string>> commands = {
        {"delete", "table", "ip",   "tunnel_global"},
        {"delete", "table", "ip6",  "tunnel_global6"},
        {"delete", "table", "inet", "tunnel_global"},
        {"delete", "table", "inet6", "tunnel_global6"}
    };
    for (const auto& c : commands) {
        const int rc = run_nft(c, 2.0);
        if (rc == 0) removed = true;
    }
    return removed || !global_firewall_active();
}

bool remove_global_firewall() {
    GlobalLock lock;
    if (!lock.valid()) return false;
    return remove_global_firewall_unlocked();
}

std::string nft_address_set(const std::vector<ProxySpec>& proxies, int family) {
    std::unordered_set<std::string> seen;
    std::ostringstream o;
    bool first = true;
    for (const auto& p : proxies) {
        for (const auto& ss : p.resolved_endpoints) {
            if (ss.ss_family != family) continue;
            char buf[INET6_ADDRSTRLEN]{};
            if (family == AF_INET) {
                const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
                if (!::inet_ntop(AF_INET, &a->sin_addr, buf, sizeof buf)) continue;
            } else {
                const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
                if (!::inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof buf)) continue;
            }
            if (!seen.insert(buf).second) continue;
            if (!first) o << ", ";
            first = false;
            o << buf;
        }
    }
    return o.str();
}

bool any_udp_capable(const std::vector<ProxySpec>& proxies) {
    for (const auto& p : proxies) if (proxy_supports_udp(p)) return true;
    return false;
}

bool install_global_firewall(uint16_t tcp_port, uint16_t udp_port,
                             bool udp_proxy_available,
                             const std::vector<ProxySpec>& proxies,
                             std::string& err) {
    if (::geteuid() != 0) { err = "global firewall requires root"; return false; }
    if (nft_binary().empty()) { err = "nft command is required for kernel-enforced global mode"; return false; }
    GlobalLock lock;
    if (!lock.valid()) { err = "cannot acquire global firewall lock"; return false; }
    remove_global_firewall_unlocked();
    char tmpl[] = "/tmp/tunnel-nft-XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) { err = "mkstemp(): " + std::string(strerror(errno)); return false; }
    const std::string path = tmpl;
    const std::string v4 = nft_address_set(proxies, AF_INET);
    const std::string v6 = nft_address_set(proxies, AF_INET6);
    const std::string set_v4 = v4.empty() ? "" : ("  set proxy_v4 { type ipv4_addr; flags interval; elements = { " + v4 + " } }\n");
    const std::string set_v6 = v6.empty() ? "" : ("  set proxy_v6 { type ipv6_addr; flags interval; elements = { " + v6 + " } }\n");
    const std::string p4 = v4.empty() ? "" : "    ip daddr @proxy_v4 accept\n";
    const std::string p6 = v6.empty() ? "" : "    ip6 daddr @proxy_v6 accept\n";
    const std::string u4 =
        "    udp dport 53 redirect to :" + std::to_string(kDnsProxyPort) + "\n" +
        (udp_proxy_available ? ("    udp dport != 53 redirect to :" + std::to_string(udp_port) + "\n") : std::string{});
    const std::string u6 =
        "    udp dport 53 redirect to :" + std::to_string(kDnsProxyPort) + "\n" +
        (udp_proxy_available ? ("    udp dport != 53 redirect to :" + std::to_string(udp_port) + "\n") : std::string{});
    const std::string script =
        "table ip tunnel_global {\n" + set_v4 +
        "  chain output_nat { type nat hook output priority -100; policy accept;\n"
        "    meta mark " + std::to_string(kGlobalFwMark) + " accept\n"
        "    ip daddr 127.0.0.0/8 accept\n"
        "    ip daddr 10.0.0.0/8 accept\n"
        "    ip daddr 172.16.0.0/12 accept\n"
        "    ip daddr 192.168.0.0/16 accept\n"
        "    ip daddr 169.254.0.0/16 accept\n" + p4 +
        "    udp dport { 67, 68 } accept\n"
        "    meta l4proto icmp accept\n"
        "    meta l4proto tcp redirect to :" + std::to_string(tcp_port) + "\n" + u4 +
        "  }\n"
        "  chain output_filter { type filter hook output priority 0; policy accept;\n"
        "    meta mark " + std::to_string(kGlobalFwMark) + " accept\n"
        "    ip daddr 127.0.0.0/8 accept\n"
        "    ip daddr 10.0.0.0/8 accept\n"
        "    ip daddr 172.16.0.0/12 accept\n"
        "    ip daddr 192.168.0.0/16 accept\n"
        "    ip daddr 169.254.0.0/16 accept\n" + p4 +
        "    udp sport { 67, 68 } accept\n"
        "    meta l4proto icmp accept\n"
        "    drop\n"
        "  }\n"
        "}\n"
        "table ip6 tunnel_global6 {\n" + set_v6 +
        "  chain output_nat { type nat hook output priority -100; policy accept;\n"
        "    meta mark " + std::to_string(kGlobalFwMark) + " accept\n"
        "    ip6 daddr ::1 accept\n"
        "    ip6 daddr fe80::/10 accept\n"
        "    ip6 daddr fc00::/7 accept\n"
        "    ip6 daddr ff00::/8 accept\n" + p6 +
        "    udp dport { 546, 547 } accept\n"
        "    meta l4proto icmpv6 accept\n"
        "    meta l4proto tcp redirect to :" + std::to_string(tcp_port) + "\n" + u6 +
        "  }\n"
        "  chain output_filter { type filter hook output priority 0; policy accept;\n"
        "    meta mark " + std::to_string(kGlobalFwMark) + " accept\n"
        "    ip6 daddr ::1 accept\n"
        "    ip6 daddr fe80::/10 accept\n"
        "    ip6 daddr fc00::/7 accept\n"
        "    ip6 daddr ff00::/8 accept\n" + p6 +
        "    udp sport { 546, 547 } accept\n"
        "    meta l4proto icmpv6 accept\n"
        "    drop\n"
        "  }\n"
        "}\n";
    ssize_t off=0;
    while(off<(ssize_t)script.size()){
        ssize_t n=::write(fd,script.data()+off,script.size()-(size_t)off);
        if(n<0){if(errno==EINTR)continue;::close(fd);::unlink(path.c_str());err="write nft script failed";return false;}
        off+=n;
    }
    ::fsync(fd);::close(fd);
    const int check_rc=run_nft({"-c", "-f", path}, 5.0);
    if(check_rc!=0){::unlink(path.c_str());remove_global_firewall_unlocked();err="nft validation failed for generated global firewall rules";return false;}
    const int rc=run_nft({"-f", path}, 5.0);
    ::unlink(path.c_str());
    if(rc!=0){remove_global_firewall_unlocked();err="nft rejected the global firewall rules";return false;}
    return true;
}

bool ensure_runtime_paths(std::string& err) {
    if (::geteuid() != 0) { err = "runtime directories require root"; return false; }
    if (::mkdir(kRuntimeDir, 0755) != 0 && errno != EEXIST) {
        err = "mkdir(" + std::string(kRuntimeDir) + "): " + std::string(strerror(errno));
        return false;
    }
    const std::string logdir = "/var/log/tunnel";
    if (::mkdir(logdir.c_str(), 0755) != 0 && errno != EEXIST) {
        err = "mkdir(" + logdir + "): " + std::string(strerror(errno));
        return false;
    }
    return true;
}

bool global_firewall_active() {
    if (!nft_available()) return false;
    return run_shell("nft list table ip tunnel_global", true) == 0 &&
           run_shell("nft list table ip6 tunnel_global6", true) == 0;
}

// Transparent transport handlers
std::string endpoint_string(const sockaddr_storage& ss) {
    char host[NI_MAXHOST]{};
    char serv[NI_MAXSERV]{};
    socklen_t len = (ss.ss_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (::getnameinfo(reinterpret_cast<const sockaddr*>(&ss), len, host, sizeof host, serv, sizeof serv,
                      NI_NUMERICHOST | NI_NUMERICSERV) != 0) return "?";
    return std::string(host) + ":" + serv;
}

std::string flow_key(const sockaddr_storage& client, const sockaddr_storage& dest) {
    return std::to_string(client.ss_family) + "|" + endpoint_string(client) + "|" + endpoint_string(dest);
}

bool get_original_destination(int fd, sockaddr_storage& out, socklen_t& out_len) {
    struct sockaddr_storage local{}; socklen_t local_len = sizeof local;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_len) != 0) return false;

    if (local.ss_family == AF_INET) {
        struct sockaddr_in dst{}; socklen_t len = sizeof dst;
        if (::getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dst, &len) != 0) return false;
        std::memcpy(&out, &dst, sizeof dst); out_len = len; return true;
    }
    if (local.ss_family == AF_INET6) {
        struct sockaddr_in6 dst{}; socklen_t len = sizeof dst;
        if (::getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &dst, &len) != 0) return false;
        std::memcpy(&out, &dst, sizeof dst); out_len = len; return true;
    }
    return false;
}

#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR 74
#endif
#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR 74
#endif

class TransparentTcpServer {
public:
    TransparentTcpServer(std::shared_ptr<ProxyPool> pool, uint16_t port, double connect_timeout,
                         double idle_timeout, int max_clients, bool verbose)
        : pool_(std::move(pool)), port_(port), connect_timeout_(connect_timeout),
          idle_timeout_(idle_timeout), max_clients_(max_clients), verbose_(verbose) {}
    ~TransparentTcpServer() { stop(); }

    bool start(std::string& err) {
        v4_ = make_listener(AF_INET, err); if (v4_ < 0) return false;
        v6_ = make_listener(AF_INET6, err); if (v6_ < 0) { ::close(v4_); v4_=-1; return false; }
        running_.store(true);
        t4_ = std::thread([this]{ accept_loop(v4_); });
        t6_ = std::thread([this]{ accept_loop(v6_); });
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        for (int* p : {&v4_, &v6_}) { if (*p >= 0) { ::shutdown(*p, SHUT_RDWR); ::close(*p); *p=-1; } }
        if (t4_.joinable()) t4_.join();
        if (t6_.joinable()) t6_.join();
        std::unique_lock<std::mutex> lk(workers_mutex_);
        workers_cv_.wait(lk, [this]{ return workers_.load() == 0; });
    }

private:
    int make_listener(int family, std::string& err) {
        int fd = ::socket(family, SOCK_STREAM, 0);
        if (fd < 0) { err = "transparent TCP socket(): " + std::string(strerror(errno)); return -1; }
        int one=1; ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (family == AF_INET) {
            sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port_); ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) { err="transparent TCP bind IPv4: "+std::string(strerror(errno)); ::close(fd); return -1; }
        } else {
            int off=1; ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
            sockaddr_in6 sa{}; sa.sin6_family=AF_INET6; sa.sin6_port=htons(port_); ::inet_pton(AF_INET6, "::1", &sa.sin6_addr);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) { err="transparent TCP bind IPv6: "+std::string(strerror(errno)); ::close(fd); return -1; }
        }
        if (::listen(fd, 512) != 0) { err="transparent TCP listen: "+std::string(strerror(errno)); ::close(fd); return -1; }
        return fd;
    }

    void accept_loop(int lfd) {
        while (running_.load()) {
            int cfd = ::accept(lfd, nullptr, nullptr);
            if (cfd < 0) { if (!running_.load()) break; if (errno == EINTR) continue; break; }
            // Replies written back to the application are local OUTPUT packets.
            // Mark the accepted transparent socket so the global OUTPUT policy
            // cannot mistake those replies for new internet traffic.
            if (!mark_socket_if_needed(cfd)) { ::close(cfd); continue; }
            if ((int)active_.load() >= max_clients_) { ::close(cfd); continue; }
            active_.fetch_add(1); workers_.fetch_add(1);
            std::thread([this,cfd]{ handle_client(cfd); workers_.fetch_sub(1); active_.fetch_sub(1); workers_cv_.notify_all(); }).detach();
        }
    }

    void relay(Stream& client, Stream& upstream) {
        std::atomic<bool> c_done{false}, u_done{false};
        std::mutex m; std::condition_variable cv;
        auto notify=[&]{ std::lock_guard<std::mutex> lk(m); cv.notify_all(); };
        std::thread a([&]{
            std::vector<char> buf(kBufferSize);
            while (true) { ssize_t r=client.read_some(buf.data(),buf.size(),idle_timeout_); if(r<=0) break; if(!upstream.write_all(buf.data(),(size_t)r,idle_timeout_)) break; c_bytes_.fetch_add((uint64_t)r); }
            ::shutdown(upstream.fd,SHUT_WR); c_done.store(true); notify();
        });
        std::thread b([&]{
            std::vector<char> buf(kBufferSize);
            while (true) { ssize_t r=upstream.read_some(buf.data(),buf.size(),idle_timeout_); if(r<=0) break; if(!client.write_all(buf.data(),(size_t)r,idle_timeout_)) break; u_bytes_.fetch_add((uint64_t)r); }
            ::shutdown(client.fd,SHUT_WR); u_done.store(true); notify();
        });
        { std::unique_lock<std::mutex> lk(m); cv.wait_for(lk,std::chrono::seconds(1),[&]{return c_done.load()&&u_done.load();}); }
        for(int i=0;i<50 && !(c_done.load()&&u_done.load());++i) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (!c_done.load()) ::shutdown(client.fd, SHUT_RDWR);
        if (!u_done.load()) ::shutdown(upstream.fd, SHUT_RDWR);
        a.join(); b.join();
    }

    void handle_client(int cfd) {
        Stream client(cfd); sockaddr_storage dst{}; socklen_t dst_len=0;
        if (!get_original_destination(cfd,dst,dst_len)) { if(verbose_) log_err("[global] transparent TCP: SO_ORIGINAL_DST unavailable"); return; }
        std::unordered_set<std::string> tried;
        Stream upstream; std::string last_err;
        const int attempts=std::min<int>(kDefaultProxyAttempts,(int)pool_->size());
        for(int i=0;i<std::max(1,attempts);++i) {
            ProxySpec p=pool_->choose(tried); tried.insert(p.key()); std::string e;
            std::string host; uint16_t port=0;
            if(dst.ss_family==AF_INET) { char h[INET_ADDRSTRLEN]; auto* d=reinterpret_cast<sockaddr_in*>(&dst); ::inet_ntop(AF_INET,&d->sin_addr,h,sizeof h); host=h; port=ntohs(d->sin_port); }
            else { char h[INET6_ADDRSTRLEN]; auto* d=reinterpret_cast<sockaddr_in6*>(&dst); ::inet_ntop(AF_INET6,&d->sin6_addr,h,sizeof h); host=h; port=ntohs(d->sin6_port); }
            Stream up=open_through_proxy(p,host,port,connect_timeout_,true,e);
            if(up.valid()){ upstream=std::move(up); pool_->success(p); if(verbose_) log_line("[global] TCP "+endpoint_string(dst)+" via "+mask_proxy(p)); break; }
            pool_->failure(p,e); last_err=e;
        }
        if(!upstream.valid()){ if(verbose_) log_err("[global] transparent TCP failed: "+last_err); return; }
        relay(client,upstream);
    }

    std::shared_ptr<ProxyPool> pool_; uint16_t port_; double connect_timeout_,idle_timeout_; int max_clients_; bool verbose_;
    int v4_=-1,v6_=-1; std::atomic<bool> running_{false}; std::thread t4_,t6_;
    std::atomic<int> active_{0},workers_{0}; std::mutex workers_mutex_; std::condition_variable workers_cv_;
    std::atomic<uint64_t> c_bytes_{0},u_bytes_{0};
};

class UdpFlow {
public:
    UdpFlow(std::shared_ptr<ProxyPool> pool, int listener_fd, sockaddr_storage client, socklen_t client_len,
            double timeout, bool verbose)
        : pool_(std::move(pool)), listener_fd_(listener_fd), client_(client),
          client_len_(client_len), timeout_(timeout), verbose_(verbose) {}
    ~UdpFlow(){ stop(); }

    bool start(const ProxySpec& proxy, std::string& err) {
        if (!proxy_supports_udp(proxy)) { err="upstream is not SOCKS5 UDP capable"; return false; }
        int cfd=tcp_connect_proxy(proxy,timeout_);
        if(cfd<0){err="UDP-associate TCP connection failed";return false;}
        control_=Stream(cfd);
        if(!socks5_negotiate(proxy,err)) return false;
        uint8_t req[10]={5,3,0,1,0,0,0,0,0,0};
        if(!control_.write_all(req,sizeof req,timeout_)){err="SOCKS5 UDP ASSOCIATE write failed";return false;}
        uint8_t hdr[4]; if(!control_.read_exact(hdr,4,timeout_)){err="SOCKS5 UDP ASSOCIATE header read failed";return false;}
        if(hdr[0]!=5||hdr[1]!=0){err="SOCKS5 UDP ASSOCIATE rejected (code "+std::to_string(hdr[1])+")";return false;}
        sockaddr_storage relay{}; socklen_t relay_len=0;
        if(hdr[3]==1){ uint8_t ip[4]; if(!control_.read_exact(ip,4,timeout_)) return fail(err,"SOCKS5 UDP relay IPv4 read failed"); sockaddr_in r{}; r.sin_family=AF_INET; std::memcpy(&r.sin_addr,ip,4); relay_len=sizeof r; std::memcpy(&relay,&r,sizeof r);}
        else if(hdr[3]==4){ uint8_t ip[16]; if(!control_.read_exact(ip,16,timeout_)) return fail(err,"SOCKS5 UDP relay IPv6 read failed"); sockaddr_in6 r{}; r.sin6_family=AF_INET6; std::memcpy(&r.sin6_addr,ip,16); relay_len=sizeof r; std::memcpy(&relay,&r,sizeof r);}
        else if(hdr[3]==3){ uint8_t l; if(!control_.read_exact(&l,1,timeout_)) return fail(err,"SOCKS5 UDP relay hostname length read failed"); std::string h(l,'\0'); if(l&&!control_.read_exact(h.data(),l,timeout_)) return fail(err,"SOCKS5 UDP relay hostname read failed"); uint8_t pb[2]; if(!control_.read_exact(pb,2,timeout_)) return fail(err,"SOCKS5 UDP relay port read failed"); uint16_t rp=((uint16_t)pb[0]<<8)|pb[1]; struct addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_DGRAM; struct addrinfo* ar=nullptr; if(::getaddrinfo(h.c_str(),std::to_string(rp).c_str(),&hints,&ar)!=0||!ar) return fail(err,"cannot resolve SOCKS5 UDP relay host"); std::memcpy(&relay,ar->ai_addr,ar->ai_addrlen); relay_len=ar->ai_addrlen; ::freeaddrinfo(ar); }
        else return fail(err,"SOCKS5 UDP unknown relay address type");
        uint16_t relay_port=0;
        if(relay.ss_family==AF_INET) relay_port=ntohs(reinterpret_cast<sockaddr_in*>(&relay)->sin_port);
        else relay_port=ntohs(reinterpret_cast<sockaddr_in6*>(&relay)->sin6_port);
        if(relay_port==0) return fail(err,"SOCKS5 UDP relay returned port 0");
        if(relay.ss_family==AF_INET && reinterpret_cast<sockaddr_in*>(&relay)->sin_addr.s_addr==INADDR_ANY){ struct addrinfo hints{}; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_DGRAM; struct addrinfo* ar=nullptr; if(::getaddrinfo(proxy.host.c_str(),std::to_string(relay_port).c_str(),&hints,&ar)!=0||!ar) return fail(err,"cannot resolve UDP proxy host"); auto* r=reinterpret_cast<sockaddr_in*>(ar->ai_addr); r->sin_port=htons(relay_port); std::memcpy(&relay,r,sizeof *r); relay_len=sizeof(sockaddr_in); ::freeaddrinfo(ar); }
        if(relay.ss_family==AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&reinterpret_cast<sockaddr_in6*>(&relay)->sin6_addr)){ struct addrinfo hints{}; hints.ai_family=AF_INET6; hints.ai_socktype=SOCK_DGRAM; struct addrinfo* ar=nullptr; if(::getaddrinfo(proxy.host.c_str(),std::to_string(relay_port).c_str(),&hints,&ar)!=0||!ar) return fail(err,"cannot resolve UDP proxy host"); auto* r=reinterpret_cast<sockaddr_in6*>(ar->ai_addr); r->sin6_port=htons(relay_port); std::memcpy(&relay,r,sizeof *r); relay_len=sizeof(sockaddr_in6); ::freeaddrinfo(ar); }
        udp_fd_=::socket(relay.ss_family,SOCK_DGRAM,0); if(udp_fd_<0) return fail(err,"SOCKS5 UDP socket(): "+std::string(strerror(errno)));
        if(!mark_socket_if_needed(udp_fd_)){return fail(err,"SO_MARK failed for SOCKS5 UDP socket");}
        if(::connect(udp_fd_,reinterpret_cast<sockaddr*>(&relay),relay_len)!=0) return fail(err,"connect UDP relay failed: "+std::string(strerror(errno)));
        relay_=relay; relay_len_=relay_len; running_.store(true); thread_=std::thread([this]{recv_loop();}); return true;
    }

    bool send_packet(const sockaddr_storage& dest, const uint8_t* data, size_t len){
        if(!running_.load()) return false;
        std::vector<uint8_t> p; p.reserve(3+1+16+2+len); p.push_back(0);p.push_back(0);p.push_back(0);
        if(dest.ss_family==AF_INET){ p.push_back(1); auto* d=reinterpret_cast<const sockaddr_in*>(&dest); const uint8_t* ip=reinterpret_cast<const uint8_t*>(&d->sin_addr); p.insert(p.end(),ip,ip+4); uint16_t port=ntohs(d->sin_port); p.push_back((uint8_t)(port>>8));p.push_back((uint8_t)port); }
        else { p.push_back(4); auto* d=reinterpret_cast<const sockaddr_in6*>(&dest); const uint8_t* ip=reinterpret_cast<const uint8_t*>(&d->sin6_addr); p.insert(p.end(),ip,ip+16); uint16_t port=ntohs(d->sin6_port); p.push_back((uint8_t)(port>>8));p.push_back((uint8_t)port);}
        p.insert(p.end(),data,data+len); ssize_t n=::send(udp_fd_,p.data(),p.size(),MSG_NOSIGNAL); if(n==(ssize_t)p.size()){last_activity_.store(now_monotonic());return true;} return false;
    }

    void stop(){ if(!running_.exchange(false)) return; if(udp_fd_>=0){::shutdown(udp_fd_,SHUT_RDWR);::close(udp_fd_);udp_fd_=-1;} if(thread_.joinable()) thread_.join(); control_.close(); }
    double last_activity() const { return last_activity_.load(); }
    const sockaddr_storage& client() const { return client_; }

private:
    bool fail(std::string& err,const std::string& e){err=e;return false;}
    bool socks5_negotiate(const ProxySpec& proxy,std::string& err){ bool auth=proxy.username.has_value(); uint8_t g[4]={5,2,0,2}; if(!auth) g[1]=1; if(!control_.write_all(g,auth?4:3,timeout_)) return fail(err,"SOCKS5 UDP greeting write failed"); uint8_t sel[2]; if(!control_.read_exact(sel,2,timeout_)) return fail(err,"SOCKS5 UDP greeting read failed"); if(sel[0]!=5||sel[1]==0xff) return fail(err,"SOCKS5 UDP no acceptable auth"); if(auth){ if(sel[1]!=2)return fail(err,"SOCKS5 UDP auth method rejected"); std::string u=*proxy.username,p=proxy.password?*proxy.password:""; if(u.size()>255||p.size()>255)return fail(err,"SOCKS5 UDP credentials too long"); std::vector<uint8_t>a{1,(uint8_t)u.size()}; a.insert(a.end(),u.begin(),u.end()); a.push_back((uint8_t)p.size()); a.insert(a.end(),p.begin(),p.end()); if(!control_.write_all(a.data(),a.size(),timeout_))return fail(err,"SOCKS5 UDP auth write failed"); uint8_t ar[2]; if(!control_.read_exact(ar,2,timeout_))return fail(err,"SOCKS5 UDP auth read failed"); if(ar[1]!=0)return fail(err,"SOCKS5 UDP authentication failed"); } return true; }
    void recv_loop(){ uint8_t b[64*1024]; while(running_.load()){ ssize_t n=::recv(udp_fd_,b,sizeof b,0); if(n<=0){ if(errno==EINTR)continue; if(verbose_) log_err("[global] SOCKS5 UDP relay closed"); break;} if(n<4)continue; if(b[0]!=0||b[1]!=0||b[2]!=0)continue; size_t pos=3; sockaddr_storage src{}; if(b[pos]==1){if(n<(ssize_t)(pos+1+4+2))continue; ++pos; sockaddr_in s{}; s.sin_family=AF_INET; std::memcpy(&s.sin_addr,b+pos,4);pos+=4;s.sin_port=htons(((uint16_t)b[pos]<<8)|b[pos+1]);pos+=2;std::memcpy(&src,&s,sizeof s);} else if(b[pos]==4){if(n<(ssize_t)(pos+1+16+2))continue;++pos;sockaddr_in6 s{};s.sin6_family=AF_INET6;std::memcpy(&s.sin6_addr,b+pos,16);pos+=16;s.sin6_port=htons(((uint16_t)b[pos]<<8)|b[pos+1]);pos+=2;std::memcpy(&src,&s,sizeof s);} else if(b[pos]==3){uint8_t l; if(n<(ssize_t)(pos+1))continue; ++pos;l=b[pos++];if(n<(ssize_t)(pos+l+2))continue; std::string host(reinterpret_cast<char*>(b+pos),l);pos+=l;uint16_t port=((uint16_t)b[pos]<<8)|b[pos+1];pos+=2;struct addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_DGRAM;struct addrinfo*ar=nullptr;if(::getaddrinfo(host.c_str(),std::to_string(port).c_str(),&hints,&ar)!=0||!ar)continue;std::memcpy(&src,ar->ai_addr,ar->ai_addrlen);::freeaddrinfo(ar);} else continue; if(pos>=(size_t)n)continue; if(::sendto(listener_fd_,b+pos,(size_t)n-pos,0,reinterpret_cast<sockaddr*>(&client_),client_len_)>=0) last_activity_.store(now_monotonic()); } }

    std::shared_ptr<ProxyPool> pool_; int listener_fd_; sockaddr_storage client_{}; socklen_t client_len_=0; double timeout_; bool verbose_;
    Stream control_; int udp_fd_=-1; sockaddr_storage relay_{}; socklen_t relay_len_=0; std::atomic<bool> running_{false}; std::thread thread_; std::atomic<double> last_activity_{0.0};
};

class DnsProxyServer {
public:
    DnsProxyServer(std::shared_ptr<ProxyPool> pool, uint16_t port, double timeout, bool verbose)
        : pool_(std::move(pool)), port_(port), timeout_(timeout), verbose_(verbose) {}
    ~DnsProxyServer(){ stop(); }
    bool start(std::string& err){
        v4_=make_socket(AF_INET,err); if(v4_<0)return false;
        v6_=make_socket(AF_INET6,err); if(v6_<0){::close(v4_);v4_=-1;return false;}
        running_.store(true);t4_=std::thread([this]{loop(v4_);});t6_=std::thread([this]{loop(v6_);});return true;
    }
    void stop(){
        if(!running_.exchange(false))return;
        for(int* p:{&v4_,&v6_})if(*p>=0){::shutdown(*p,SHUT_RDWR);::close(*p);*p=-1;}
        if(t4_.joinable()) t4_.join();
        if(t6_.joinable()) t6_.join();
    }
private:
    int make_socket(int family,std::string& err){
        int fd=::socket(family,SOCK_DGRAM,0);if(fd<0){err="DNS proxy socket(): "+std::string(strerror(errno));return -1;}
        int one=1;::setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
        if(!mark_socket_if_needed(fd)){err="DNS proxy SO_MARK failed";::close(fd);return -1;}
        if(family==AF_INET){sockaddr_in sa{};sa.sin_family=AF_INET;sa.sin_port=htons(port_);::inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);if(::bind(fd,(sockaddr*)&sa,sizeof sa)!=0){err="DNS proxy bind IPv4: "+std::string(strerror(errno));::close(fd);return -1;}}
        else{int vo=1;::setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&vo,sizeof vo);sockaddr_in6 sa{};sa.sin6_family=AF_INET6;sa.sin6_port=htons(port_);::inet_pton(AF_INET6,"::1",&sa.sin6_addr);if(::bind(fd,(sockaddr*)&sa,sizeof sa)!=0){err="DNS proxy bind IPv6: "+std::string(strerror(errno));::close(fd);return -1;}}
        return fd;
    }
    bool exchange(const std::vector<uint8_t>& q,std::vector<uint8_t>& r){
        const std::array<std::pair<std::string,uint16_t>,2> resolvers{{{"1.1.1.1",53},{"1.0.0.1",53}}};
        for(const auto& resolver:resolvers){
            std::unordered_set<std::string> tried;
            const int attempts=std::min<int>(kDefaultProxyAttempts,(int)pool_->size());
            for(int i=0;i<std::max(1,attempts);++i){
                ProxySpec p=pool_->choose(tried);tried.insert(p.key());std::string e;
                Stream up=open_through_proxy(p,resolver.first,resolver.second,timeout_,true,e);
                if(!up.valid()){pool_->failure(p,e);continue;}
                if(q.size()>65535){pool_->failure(p,"DNS query too large");continue;}
                uint16_t qlen=htons((uint16_t)q.size());
                if(!up.write_all(&qlen,2,timeout_)||!up.write_all(q.data(),q.size(),timeout_)){pool_->failure(p,"DNS TCP query write failed");continue;}
                uint16_t rlen=0;if(!up.read_exact(&rlen,2,timeout_)){pool_->failure(p,"DNS TCP response length failed");continue;}
                rlen=ntohs(rlen);if(rlen==0){pool_->failure(p,"DNS TCP response length invalid");continue;}
                r.resize(rlen);if(!up.read_exact(r.data(),r.size(),timeout_)){pool_->failure(p,"DNS TCP response read failed");continue;}
                pool_->success(p);return true;
            }
        }
        return false;
    }
    void loop(int fd){
        uint8_t buf[4096];
        while(running_.load()){
            sockaddr_storage client{};socklen_t len=sizeof client;
            ssize_t n=::recvfrom(fd,buf,sizeof buf,0,(sockaddr*)&client,&len);
            if(n<=0){if(!running_.load())break;if(errno==EINTR)continue;continue;}
            if(n<12)continue;
            std::vector<uint8_t> q(buf,buf+n),r;
            if(!exchange(q,r)){if(verbose_)log_err("[global] DNS fallback failed through all upstreams");continue;}
            ::sendto(fd,r.data(),r.size(),0,(sockaddr*)&client,len);
        }
    }
    std::shared_ptr<ProxyPool> pool_;uint16_t port_;double timeout_;bool verbose_;int v4_=-1,v6_=-1;std::atomic<bool> running_{false};std::thread t4_,t6_;
};

class TransparentUdpServer {
public:
    TransparentUdpServer(std::shared_ptr<ProxyPool> pool,
                         uint16_t port,
                         double timeout,
                         bool verbose)
        : pool_(std::move(pool)), port_(port), timeout_(timeout), verbose_(verbose) {}

    ~TransparentUdpServer() { stop(); }

    bool start(std::string& err) {
        v4_ = make_socket(AF_INET, err);
        if (v4_ < 0) return false;
        v6_ = make_socket(AF_INET6, err);
        if (v6_ < 0) {
            ::close(v4_);
            v4_ = -1;
            return false;
        }
        running_.store(true);
        t4_ = std::thread([this]{ loop(v4_); });
        t6_ = std::thread([this]{ loop(v6_); });
        cleaner_ = std::thread([this]{ cleanup_loop(); });
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        for (int* p : {&v4_, &v6_}) {
            if (*p >= 0) {
                ::shutdown(*p, SHUT_RDWR);
                ::close(*p);
                *p = -1;
            }
        }
        if (t4_.joinable()) t4_.join();
        if (t6_.joinable()) t6_.join();

        std::vector<std::shared_ptr<UdpFlow>> flows;
        {
            std::lock_guard<std::mutex> lk(flows_m_);
            for (auto& kv : flows_) flows.push_back(kv.second);
            flows_.clear();
        }
        for (auto& flow : flows) flow->stop();

        cv_.notify_all();
        if (cleaner_.joinable()) cleaner_.join();
    }

private:
    int make_socket(int family, std::string& err) {
        int fd = ::socket(family, SOCK_DGRAM, 0);
        if (fd < 0) {
            err = "transparent UDP socket(): " + std::string(strerror(errno));
            return -1;
        }
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (!mark_socket_if_needed(fd)) {
            err = "transparent UDP SO_MARK failed";
            ::close(fd);
            return -1;
        }
        if (family == AF_INET) {
            if (::setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &one, sizeof one) != 0) {
                err = "transparent UDP IPv4 original-destination support unavailable";
                ::close(fd);
                return -1;
            }
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port_);
            ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
                err = "transparent UDP bind IPv4: " + std::string(strerror(errno));
                ::close(fd);
                return -1;
            }
        } else {
            if (::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof one) != 0) {
                err = "transparent UDP IPv6 original-destination support unavailable";
                ::close(fd);
                return -1;
            }
            int v6only = 1;
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
            sockaddr_in6 sa{};
            sa.sin6_family = AF_INET6;
            sa.sin6_port = htons(port_);
            ::inet_pton(AF_INET6, "::1", &sa.sin6_addr);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
                err = "transparent UDP bind IPv6: " + std::string(strerror(errno));
                ::close(fd);
                return -1;
            }
        }
        return fd;
    }

    bool recv_packet(int fd,
                     std::vector<uint8_t>& data,
                     sockaddr_storage& client,
                     socklen_t& client_len,
                     sockaddr_storage& dest,
                     socklen_t& dest_len) {
        uint8_t buf[64 * 1024];
        char control[CMSG_SPACE(sizeof(sockaddr_in6))]{};
        iovec iov{buf, sizeof buf};
        msghdr msg{};
        msg.msg_name = &client;
        msg.msg_namelen = sizeof client;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof control;

        const ssize_t n = ::recvmsg(fd, &msg, 0);
        if (n <= 0) return false;
        client_len = msg.msg_namelen;

        bool got_dest = false;
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (client.ss_family == AF_INET &&
                c->cmsg_level == SOL_IP && c->cmsg_type == IP_ORIGDSTADDR) {
                std::memcpy(&dest, CMSG_DATA(c), sizeof(sockaddr_in));
                dest_len = sizeof(sockaddr_in);
                got_dest = true;
                break;
            }
            if (client.ss_family == AF_INET6 &&
                c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_ORIGDSTADDR) {
                std::memcpy(&dest, CMSG_DATA(c), sizeof(sockaddr_in6));
                dest_len = sizeof(sockaddr_in6);
                got_dest = true;
                break;
            }
        }
        if (!got_dest) return false;
        data.assign(buf, buf + n);
        return true;
    }

    void loop(int fd) {
        while (running_.load()) {
            std::vector<uint8_t> data;
            sockaddr_storage client{};
            sockaddr_storage dest{};
            socklen_t client_len = 0;
            socklen_t dest_len = 0;
            if (!recv_packet(fd, data, client, client_len, dest, dest_len)) {
                if (!running_.load()) break;
                continue;
            }

            const std::string key = flow_key(client, dest);
            std::shared_ptr<UdpFlow> flow;
            {
                std::lock_guard<std::mutex> lk(flows_m_);
                auto it = flows_.find(key);
                if (it != flows_.end()) flow = it->second;
            }

            if (!flow) {
                try {
                    std::unordered_set<std::string> tried;
                    std::shared_ptr<UdpFlow> candidate;
                    bool created = false;
                    const int attempts = std::min<int>(kDefaultProxyAttempts, (int)pool_->size());

                    for (int i = 0; i < std::max(1, attempts); ++i) {
                        ProxySpec proxy = pool_->choose(tried, true);
                        tried.insert(proxy.key());
                        candidate = std::make_shared<UdpFlow>(
                            pool_, fd, client, client_len, timeout_, verbose_);
                        std::string assoc_err;
                        if (candidate->start(proxy, assoc_err)) {
                            pool_->mark_udp_available(proxy);
                            created = true;
                            break;
                        }
                        pool_->mark_udp_unavailable(proxy, assoc_err);
                    }

                    if (!created) continue;

                    std::lock_guard<std::mutex> lk(flows_m_);
                    auto [it, inserted] = flows_.emplace(key, candidate);
                    flow = inserted ? candidate : it->second;
                    if (!inserted) candidate->stop();
                } catch (const std::exception& e) {
                    if (verbose_) log_err(std::string("[global] UDP flow unavailable: ") + e.what());
                    continue;
                }
            }

            if (!flow->send_packet(dest, data.data(), data.size())) {
                flow->stop();
                std::lock_guard<std::mutex> lk(flows_m_);
                flows_.erase(key);
            }
        }
    }

    void cleanup_loop() {
        std::unique_lock<std::mutex> lk(cv_m_);
        while (running_.load()) {
            cv_.wait_for(lk, std::chrono::seconds(5));
            if (!running_.load()) break;

            const double cutoff = now_monotonic() - kUdpFlowTimeoutSec;
            std::vector<std::shared_ptr<UdpFlow>> dead;
            {
                std::lock_guard<std::mutex> gl(flows_m_);
                for (auto it = flows_.begin(); it != flows_.end();) {
                    if (it->second->last_activity() > 0.0 &&
                        it->second->last_activity() < cutoff) {
                        dead.push_back(it->second);
                        it = flows_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            for (auto& flow : dead) flow->stop();
        }
    }

    std::shared_ptr<ProxyPool> pool_;
    uint16_t port_;
    double timeout_;
    bool verbose_;
    int v4_ = -1;
    int v6_ = -1;
    std::atomic<bool> running_{false};
    std::thread t4_;
    std::thread t6_;
    std::thread cleaner_;
    std::unordered_map<std::string, std::shared_ptr<UdpFlow>> flows_;
    std::mutex flows_m_;
    std::mutex cv_m_;
    std::condition_variable cv_;
};

// Firewall guardian and network recovery
pid_t start_global_firewall_guardian(pid_t daemon_pid) {
    pid_t child = ::fork();
    if (child < 0) return -1;
    if (child == 0) {
        ::setsid();
        (void)write_pid_file(kGuardianPidFile, ::getpid());
        for (;;) {
            errno = 0;
            if (::kill(daemon_pid, 0) == 0 || errno == EPERM) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            GlobalLock lock;
            GlobalState gs;
            const bool same_generation = read_global_state(gs) && gs.pid == daemon_pid;
            if (!same_generation) {
                // A newer daemon may have taken ownership of the firewall.
                ::unlink(kGuardianPidFile);
                _exit(0);
            }
            remove_global_firewall_unlocked();
            remove_global_state();
            _exit(0);
        }
    }
    return child;
}

void stop_global_firewall_guardian(pid_t guardian_pid) {
    if (guardian_pid > 0) {
        ::kill(guardian_pid, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            if (!process_exists(guardian_pid)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        if (process_exists(guardian_pid)) ::kill(guardian_pid, SIGKILL);
    }
    ::unlink(kGuardianPidFile);
}

class GlobalNetworkRecoveryMonitor {
public:
    GlobalNetworkRecoveryMonitor(std::shared_ptr<ProxyPool> pool, double timeout,
                                  bool remote_dns, bool verbose, std::string target_host = kDefaultPingTargetHost,
                                  uint16_t target_port = kDefaultPingTargetPort)
        : pool_(std::move(pool)), timeout_(std::max(1.0, timeout)),
          remote_dns_(remote_dns), verbose_(verbose), target_host_(std::move(target_host)), target_port_(target_port) {}

    ~GlobalNetworkRecoveryMonitor() { stop(); }

    void start() {
        if (running_.exchange(true)) return;
        worker_ = std::thread([this]{ loop(); });
    }

    void stop() {
        if (!running_.exchange(false)) return;
        if (nl_fd_ >= 0) ::shutdown(nl_fd_, SHUT_RDWR);
        if (worker_.joinable()) worker_.join();
        if (nl_fd_ >= 0) { ::close(nl_fd_); nl_fd_ = -1; }
    }

private:
    bool open_netlink() {
        nl_fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (nl_fd_ < 0) return false;
        sockaddr_nl sa{};
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                       RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
        if (::bind(nl_fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
            ::close(nl_fd_); nl_fd_ = -1; return false;
        }
        return true;
    }

    void drain_events() {
        if (nl_fd_ < 0) return;
        char buf[16 * 1024];
        for (;;) {
            ssize_t n = ::recv(nl_fd_, buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0) break;
        }
    }

    void recover() {
        if (!pool_ || pool_->fixed()) return;
        auto active = pool_->active();
        if (active) {
            auto r = measure_proxy_latency(*active, timeout_, remote_dns_, target_host_, target_port_);
            if (r.ok) {
                pool_->success(*active);
                if (verbose_) log_line("[global] network change detected; current upstream recovered: " + mask_proxy(*active));
                return;
            }
            pool_->failure(*active, r.error);
            if (verbose_) log_err("[global] network change detected; current upstream failed: " + mask_proxy(*active) + " | " + r.error);
        }

        const auto results = pool_->refresh_pings(timeout_, remote_dns_, target_host_, target_port_);
        const auto best = pool_->best_ping();
        if (best) {
            pool_->set_active(best->proxy);
            size_t ok = 0; for (const auto& x : results) if (x.ok) ++ok;
            log_line("[global] network recovery selected upstream: " + mask_proxy(best->proxy) +
                     " | " + std::to_string(ok) + "/" + std::to_string(results.size()) + " reachable");
        } else {
            log_err("[global] network recovery: no reachable upstream proxy yet; firewall remains fail-closed and recovery will retry on network events");
        }
    }

    void loop() {
        if (!open_netlink()) {
            if (verbose_) log_err("[global] network recovery monitor unavailable: netlink route socket could not be opened");
            return;
        }
        double last_recovery = -10.0;
        while (running_) {
            pollfd pfd{nl_fd_, POLLIN, 0};
            int rc = ::poll(&pfd, 1, 1000);
            if (!running_) break;
            if (rc <= 0) continue;
            if (!(pfd.revents & POLLIN)) continue;
            drain_events();
            const double now = now_monotonic();
            if (now - last_recovery < 1.5) continue;
            last_recovery = now;
            // Let DHCP/NetworkManager finish installing the new route/address.
            std::this_thread::sleep_for(std::chrono::milliseconds(750));
            if (running_) recover();
        }
    }

    std::shared_ptr<ProxyPool> pool_;
    double timeout_;
    bool remote_dns_;
    bool verbose_;
    std::string target_host_;
    uint16_t target_port_;
    std::atomic<bool> running_{false};
    int nl_fd_ = -1;
    std::thread worker_;
};

// Global daemon
int run_global_daemon(const Args& args, std::vector<ProxySpec> proxies) {
    std::string runtime_err;
    if (!ensure_runtime_paths(runtime_err)) { log_err("Error: " + runtime_err); return 1; }
    std::optional<ProxySpec> fixed;
    if (args.proxy) {
        ProxySpec p; std::string err;
        if (!parse_proxy_url(*args.proxy, p, err)) {
            log_err("Error: invalid --proxy: " + err);
            return 2;
        }
        p.no_udp = args.tor;
        fixed = p;
    }
    std::vector<ProxySpec> pool_items;
    if (fixed) pool_items.push_back(*fixed);
    else       pool_items = std::move(proxies);

    // Resolve proxy endpoints before fail-closed OUTPUT rules can intercept DNS.
    for (auto& p : pool_items) {
        std::string resolve_err;
        if (!resolve_proxy_endpoints(p, resolve_err)) {
            log_err("Error: cannot resolve upstream proxy " + mask_proxy(p) + ": " + resolve_err);
            return 1;
        }
    }
    if (fixed) for (const auto& p : pool_items) if (p.key() == fixed->key()) { fixed = p; break; }

    auto pool = std::make_shared<ProxyPool>(pool_items, fixed, args.rotate);

    // The marked sockets are the only direct egress sockets allowed through
    // the kernel firewall. Every normal local TCP/UDP flow is intercepted.
    g_egress_mark.store((int)kGlobalFwMark);

    uint16_t socks_port = args.port ? args.port : (uint16_t)kDefaultGlobalSocksPort;
    uint16_t http_port  = args.http_port;

    SocksServer socks(pool, "127.0.0.1", socks_port,
                      args.connect_timeout, args.idle_timeout,
                      args.max_clients, std::nullopt, std::nullopt,
                      args.verbose, !args.local_dns);

    HttpProxyServer http(pool, "127.0.0.1", http_port,
                         args.connect_timeout, args.idle_timeout,
                         args.max_clients, args.verbose, !args.local_dns);

    TransparentTcpServer transparent_tcp(pool, kTransparentTcpPort,
                                         args.connect_timeout, args.idle_timeout,
                                         args.max_clients, args.verbose);
    const bool udp_proxy_available = any_udp_capable(pool_items);
    if (args.tor) log_line("[global] Tor upstream selected: transparent UDP is disabled because the Tor SOCKS interface is TCP-only; DNS still uses the local DNS fallback.");
    // Dedicated DNS proxy is always started: normal system DNS commonly uses
    // UDP/53, while upstream proxy pools may be TCP-only.
    auto dns_fallback = std::make_unique<DnsProxyServer>(
        pool, kDnsProxyPort,
        std::min(args.connect_timeout, args.ping_timeout), args.verbose);
    std::unique_ptr<TransparentUdpServer> transparent_udp;
    if (udp_proxy_available) {
        transparent_udp = std::make_unique<TransparentUdpServer>(
            pool, kTransparentUdpPort,
            std::min(args.connect_timeout, args.ping_timeout), args.verbose);
    }


    std::string err;
    if (!socks.start(err)) { g_egress_mark.store(0); log_err("Error: SOCKS5 server: " + err); return 1; }
    if (!http.start(err))  { socks.stop(); g_egress_mark.store(0); log_err("Error: HTTP proxy server: " + err); return 1; }
    if (!transparent_tcp.start(err)) { http.stop(); socks.stop(); g_egress_mark.store(0); log_err("Error: transparent TCP interceptor: " + err); return 1; }
    if (!dns_fallback->start(err)) { transparent_tcp.stop(); http.stop(); socks.stop(); g_egress_mark.store(0); log_err("Error: DNS fallback interceptor: " + err); return 1; }
    if (transparent_udp && !transparent_udp->start(err)) { dns_fallback->stop(); transparent_tcp.stop(); http.stop(); socks.stop(); g_egress_mark.store(0); log_err("Error: transparent UDP interceptor: " + err); return 1; }

    // Safety gate: perform a real upstream TCP + proxy CONNECT preflight while
    // the listeners are already ready, but BEFORE fail-closed nftables rules are
    // installed. If every upstream fails, the firewall is never committed.
    auto results = pool->refresh_pings(std::min(args.connect_timeout, args.ping_timeout), !args.local_dns);
    auto best = pool->best_ping();
    if (!best) {
        if (transparent_udp) transparent_udp->stop();
        dns_fallback->stop();
        transparent_tcp.stop();
        http.stop();
        socks.stop();
        g_egress_mark.store(0);
        log_err("[global] upstream preflight failed: no reachable proxy; firewall NOT installed");
        return 1;
    }
    pool->set_active(best->proxy);
    {
        size_t ok = 0; for (const auto& r : results) if (r.ok) ++ok;
        char b[192];
        std::snprintf(b, sizeof b, "[ping] Preflight PASS: %.1f ms | %s | %zu/%zu reachable",
                      best->latency_ms, mask_proxy(best->proxy).c_str(), ok, results.size());
        log_line(b);
    }

    pid_t guardian_pid = start_global_firewall_guardian(::getpid());
    if (guardian_pid < 0) {
        if (transparent_udp) transparent_udp->stop();
        dns_fallback->stop();
        transparent_tcp.stop();
        http.stop();
        socks.stop();
        g_egress_mark.store(0);
        log_err("Error: cannot start independent global firewall guardian");
        return 1;
    }

    std::string fw_err;
    // Validate the generated nftables transaction first, then commit it.
    if (!install_global_firewall(kTransparentTcpPort, kTransparentUdpPort, udp_proxy_available, pool_items, fw_err)) {
        stop_global_firewall_guardian(guardian_pid);
        if (transparent_udp) transparent_udp->stop();
        dns_fallback->stop();
        transparent_tcp.stop();
        http.stop();
        socks.stop();
        g_egress_mark.store(0);
        log_err("Error: cannot enable kernel-enforced global mode: " + fw_err);
        return 1;
    }

    // Publish readiness only after listeners, upstream preflight, nft syntax
    // validation, and firewall commit have all succeeded.
    GlobalState gs;
    gs.socks_port = socks.port();
    gs.http_port  = http.port();
    gs.transparent_tcp_port = kTransparentTcpPort;
    gs.transparent_udp_port = kTransparentUdpPort;
    gs.dns_proxy_port = kDnsProxyPort;
    gs.pid        = ::getpid();
    gs.guardian_pid = guardian_pid;
    gs.firewall_enforced = true;
    gs.system_proxy_applied = args.system_proxy;
    {
        std::time_t t = std::time(nullptr);
        char buf[64];
        std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        gs.started_at = buf;
    }
    if (!write_global_state(gs)) {
        stop_global_firewall_guardian(guardian_pid);
        if (transparent_udp) transparent_udp->stop();
        dns_fallback->stop();
        transparent_tcp.stop();
        http.stop();
        socks.stop();
        remove_global_firewall();
        g_egress_mark.store(0);
        log_err("Error: cannot write global state file");
        return 1;
    }
    { std::ofstream f(kPidFile, std::ios::trunc); f << gs.pid << "\n"; }

    log_line("[global] listeners + upstream preflight + nft firewall commit: READY");

    if (args.system_proxy) {
        apply_system_proxy(gs.http_port, gs.socks_port, true);
        log_line("[global] system proxy integration applied (--system-proxy).");
    }

    ProxyAutoSwitchMonitor monitor(pool, args.auto_switch_interval,
                                   std::min(args.connect_timeout, args.ping_timeout),
                                   !args.local_dns, args.verbose, args.ping_host, args.ping_port);
    monitor.start();
    GlobalNetworkRecoveryMonitor network_recovery(
        pool, std::min(args.connect_timeout, args.ping_timeout), !args.local_dns, args.verbose,
        args.ping_host, args.ping_port);
    network_recovery.start();
    if (args.auto_switch_interval > 0.0)
        log_line("[global] auto-switch enabled every " + std::to_string(args.auto_switch_interval) + "s");

    log_line("[global] ================================================================");
    log_line("[global] KERNEL-ENFORCED GLOBAL MODE: ACTIVE");
    log_line("[global] SOCKS5 local endpoint: 127.0.0.1:" + std::to_string(gs.socks_port));
    log_line("[global] HTTP   local endpoint: 127.0.0.1:" + std::to_string(gs.http_port));
    log_line("[global] Transparent TCP: 127.0.0.1:" + std::to_string(gs.transparent_tcp_port));
    log_line("[global] Transparent UDP: " + std::string(udp_proxy_available ? "127.0.0.1:" + std::to_string(gs.transparent_udp_port) : "disabled (no SOCKS5 UDP upstream)"));
    log_line("[global] DNS fallback: 127.0.0.1:" + std::to_string(gs.dns_proxy_port) + " (TCP via upstream proxy)");
    log_line("[global] UDP backend: " + std::string(udp_proxy_available ? "SOCKS5 UDP" : "DNS-over-TCP fallback; non-DNS UDP fail-closed"));
    log_line("[global] All normal local TCP/UDP egress is intercepted; unmarked non-loopback IP traffic is dropped.");
    if (args.auto_switch_interval > 0.0)
        log_line("[global] Opt-in proxy auto-switch every " + std::to_string(args.auto_switch_interval) + "s");
    else
        log_line("[global] Sticky upstream selection: switch only after connection failure");
    log_line("[global] ================================================================");

    static std::atomic<bool> stop_flag{false};
    stop_flag.store(false);
    struct sigaction sa{};
    sa.sa_handler = [](int){ stop_flag.store(true); };
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);

    while (!stop_flag.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    log_line("[global] Shutting down...");
    network_recovery.stop();
    monitor.stop();
    if (transparent_udp) transparent_udp->stop();
    dns_fallback->stop();
    transparent_tcp.stop();
    http.stop();
    socks.stop();
    stop_global_firewall_guardian(guardian_pid);
    remove_global_firewall();
    g_egress_mark.store(0);
    if (gs.system_proxy_applied) apply_system_proxy(gs.http_port, gs.socks_port, false);
    remove_global_state();

    log_line("[global] kernel firewall enforcement removed.");
    log_line("[global] Stats: total=" + std::to_string(socks.stats().total_clients.load() + http.stats().total_clients.load()) +
             " failed=" + std::to_string(socks.stats().failed_clients.load() + http.stats().failed_clients.load()));
    return 0;
}

int cmd_enable_global(const Args& args, std::vector<ProxySpec> proxies) {
    std::string runtime_err;
    if (!ensure_runtime_paths(runtime_err)) { log_err("Error: " + runtime_err); return 1; }
    (void)proxies;  // proxies are loaded by the daemon child from --file
    if (::geteuid() != 0) {
        log_err("Error: --enable-global requires root (use sudo).");
        return 1;
    }
    if (!args.file_explicit || args.file.empty()) {
        log_err("Error: --enable-global requires --file PATH.");
        return 2;
    }

    // Validate the proxy file before daemonizing so the caller gets the real
    // error immediately instead of a misleading READY timeout.
    try {
        (void)load_proxies(args.file);
    } catch (const std::exception& e) {
        log_err(std::string("Error: ") + e.what());
        return 1;
    }

    GlobalState existing;
    if (read_global_state(existing) && existing.pid > 0) {
        if (process_exists(existing.pid)) {
            log_err("[global] already running (pid " + std::to_string(existing.pid) + ")");
            log_err("[global] use --disable-global first, or --global-status to inspect.");
            return 1;
        }
        remove_global_state();
    }

    // Remove orphaned fail-closed rules left by a previous crash now that we
    // know there is no active daemon using them.
    remove_global_firewall();

    pid_t pid = ::fork();
    if (pid < 0) { log_err("Error: fork failed."); return 1; }
    if (pid > 0) {
        for (int i = 0; i < 300; ++i) {
            GlobalState gs;
            if (read_global_state(gs) && process_exists(gs.pid)) {
                log_line("[global] daemon pid " + std::to_string(gs.pid));
                log_line("[global] SOCKS5 127.0.0.1:" + std::to_string(gs.socks_port));
                log_line("[global] HTTP   127.0.0.1:" + std::to_string(gs.http_port));
                log_line("[global] Transparent TCP 127.0.0.1:" + std::to_string(gs.transparent_tcp_port));
                log_line("[global] Transparent UDP 127.0.0.1:" + std::to_string(gs.transparent_udp_port));
                if (args.system_proxy) log_line("[global] system proxy integration requested; daemon will apply it.");
                log_line("[global] To disable: sudo tunnel --disable-global");
                return 0;
            }

            int status = 0;
            pid_t wr = ::waitpid(pid, &status, WNOHANG);
            if (wr == pid) {
                log_err("[global] daemon exited before becoming ready.");
                std::ifstream lf(kGlobalLog);
                if (lf.is_open()) {
                    std::vector<std::string> lines;
                    std::string line;
                    while (std::getline(lf, line)) {
                        lines.push_back(line);
                        if (lines.size() > 12) lines.erase(lines.begin());
                    }
                    for (const auto& line2 : lines) log_err("[global] " + line2);
                }
                if (WIFEXITED(status))
                    log_err("[global] daemon exit code: " + std::to_string(WEXITSTATUS(status)));
                else if (WIFSIGNALED(status))
                    log_err("[global] daemon signal: " + std::to_string(WTERMSIG(status)));
                return 1;
            }
            if (wr < 0 && errno != EINTR) {
                log_err("[global] waitpid() failed: " + std::string(strerror(errno)));
                return 1;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        log_err("Error: daemon did not become ready within 30s.");
        log_err("[global] Check: sudo tail -n 100 " + std::string(kGlobalLog));
        return 1;
    }

    // Re-exec as the global daemon process.
    ::setsid();
    ::signal(SIGHUP, SIG_IGN);
    int logfd = ::open(kGlobalLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd >= 0) {
        ::dup2(logfd, 1);
        ::dup2(logfd, 2);
        if (logfd > 2) ::close(logfd);
    }
    int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) { ::dup2(devnull, 0); if (devnull > 2) ::close(devnull); }

    std::vector<std::string> a;
    a.push_back("tunnel");
    a.push_back("--daemon-global");
    a.push_back("--port"); a.push_back(std::to_string(args.port ? args.port : kDefaultGlobalSocksPort));
    a.push_back("--connect-timeout"); a.push_back(std::to_string(args.connect_timeout));
    if (args.auto_switch_interval > 0.0) { a.push_back("--auto-switch"); a.push_back(std::to_string(args.auto_switch_interval)); }
    a.push_back("--ping-timeout"); a.push_back(std::to_string(args.ping_timeout));
    a.push_back("--idle-timeout"); a.push_back(std::to_string(args.idle_timeout));
    a.push_back("--max-clients"); a.push_back(std::to_string(args.max_clients));
    if (args.rotate) a.push_back("--rotate");
    if (args.system_proxy) a.push_back("--system-proxy");
    if (args.local_dns) a.push_back("--local-dns");
    if (args.verbose) a.push_back("--verbose");
    if (args.proxy) { a.push_back("--proxy"); a.push_back(*args.proxy); }
    a.push_back("--file"); a.push_back(args.file);

    std::vector<char*> argv;
    for (auto& s : a) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    ::execvp("/proc/self/exe", argv.data());
    _exit(127);
}

bool pid_is_tunnel_process(pid_t pid) {
    if (!process_exists(pid)) return false;
    const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    std::string cmd((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return cmd.find("--daemon-global") != std::string::npos ||
           cmd.find("/tunnel") != std::string::npos;
}

int terminate_global_daemon(pid_t pid) {
    if (pid <= 0 || !pid_is_tunnel_process(pid)) return 0;
    if (::kill(pid, SIGTERM) == 0) {
        for (int i = 0; i < 40; ++i) {
            if (!process_exists(pid)) return 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        log_err("[global] daemon did not exit after SIGTERM; sending SIGKILL");
        ::kill(pid, SIGKILL);
        for (int i = 0; i < 20; ++i) {
            if (!process_exists(pid)) return 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return process_exists(pid) ? 1 : 0;
    }
    if (errno == ESRCH) return 0;
    return 1;
}

int cmd_disable_global_impl(bool emergency) {
    if (::geteuid() != 0) {
        log_err(std::string("Error: ") + (emergency ? "--emergency-disable-global" : "--disable-global") + " requires root (use sudo).");
        return 1;
    }

    GlobalState gs;
    const bool have_state = read_global_state(gs);
    pid_t daemon_pid = have_state ? gs.pid : 0;
    if (daemon_pid <= 0) {
        if (auto p = read_pid_file(kPidFile)) daemon_pid = *p;
    }
    pid_t guardian_pid = have_state ? gs.guardian_pid : 0;
    if (guardian_pid <= 0) {
        if (auto p = read_pid_file(kGuardianPidFile)) guardian_pid = *p;
    }

    // First action is the firewall rollback. This path does not depend on the
    // daemon being responsive, on a live network, or on the state file.
    const bool removed_first = remove_global_firewall();
    g_egress_mark.store(0);
    if (!removed_first && global_firewall_active())
        log_err("[global] WARNING: firewall cleanup did not confirm removal; retrying immediately.");

    (void)terminate_global_daemon(daemon_pid);
    stop_global_firewall_guardian(guardian_pid);

    // The daemon/guardian may have raced with the first cleanup. Run a second,
    // independent rollback after both are stopped.
    const bool removed_second = remove_global_firewall();
    const bool still_active = global_firewall_active();
    if (still_active) {
        log_err("[global] CRITICAL: nftables global firewall is still active after cleanup attempts.");
        log_err("[global] Run: sudo tunnel --emergency-disable-global");
        return 1;
    }

    if (have_state && gs.system_proxy_applied) {
        apply_system_proxy(gs.http_port, gs.socks_port, false);
        log_line("[global] system proxy integration reverted.");
    }
    remove_global_state();
    if (removed_first || removed_second)
        log_line("[global] firewall enforcement removed; global mode is OFF.");
    else
        log_line("[global] firewall was already inactive; global mode is OFF.");
    return 0;
}

int cmd_disable_global() {
    return cmd_disable_global_impl(false);
}

int cmd_emergency_disable_global() {
    return cmd_disable_global_impl(true);
}

int cmd_global_status() {
    GlobalState gs;
    if (!read_global_state(gs)) {
        const bool fw = global_firewall_active();
        const auto guardian = read_pid_file(kGuardianPidFile);
        if (fw) {
            log_line("[global] ORPHANED FIREWALL: ACTIVE (state file missing)");
            if (guardian) log_line("[global] guardian pid: " + std::to_string(*guardian) + (process_exists(*guardian) ? " (alive)" : " (dead)"));
            log_line("[global] Emergency cleanup: sudo tunnel --emergency-disable-global");
            return 1;
        }
        log_line("[global] not active (no state file, firewall inactive).");
        return 0;
    }
    bool alive = process_exists(gs.pid);
    log_line("[global] state file: " + std::string(kStateFile));
    log_line("[global] daemon pid: " + std::to_string(gs.pid) + (alive ? " (alive)" : " (dead)"));
    if (gs.guardian_pid > 0) log_line("[global] guardian pid: " + std::to_string(gs.guardian_pid) + (process_exists(gs.guardian_pid) ? " (alive)" : " (dead)"));
    log_line("[global] SOCKS5: 127.0.0.1:" + std::to_string(gs.socks_port));
    log_line("[global] HTTP:   127.0.0.1:" + std::to_string(gs.http_port));
    log_line("[global] transparent TCP: 127.0.0.1:" + std::to_string(gs.transparent_tcp_port));
    log_line("[global] transparent UDP: 127.0.0.1:" + std::to_string(gs.transparent_udp_port));
    log_line(std::string("[global] kernel enforcement: ") + (global_firewall_active() ? "ACTIVE" : "NOT ACTIVE"));
    log_line("[global] system proxy integration: " + std::string(gs.system_proxy_applied ? "enabled by tunnel" : "not managed"));
    log_line("[global] started: " + gs.started_at);
    return alive ? 0 : 1;
}

} // namespace tunnel
