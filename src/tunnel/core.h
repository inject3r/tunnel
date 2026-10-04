#pragma once

#include "config.h"

namespace tunnel {

// Logging
std::mutex g_log_mutex;
void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cout << s << "\n"; std::cout.flush();
}
void log_err(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cerr << s << "\n"; std::cerr.flush();
}

// Time helpers
double now_monotonic() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

struct TunnelStats {
    std::atomic<uint64_t> active_clients{0};
    std::atomic<uint64_t> total_clients{0};
    std::atomic<uint64_t> failed_clients{0};
    std::atomic<uint64_t> bytes_up{0};
    std::atomic<uint64_t> bytes_down{0};
    double started_at = now_monotonic();
};

// String helpers
std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}
std::string trim(std::string_view sv) {
    size_t b = 0, e = sv.size();
    while (b < e && std::isspace((unsigned char)sv[b])) ++b;
    while (e > b && std::isspace((unsigned char)sv[e-1])) --e;
    return std::string(sv.substr(b, e - b));
}
bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out; size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}
std::string url_decode(std::string_view s) {
    std::string out; out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hx=[](char c)->int{
                if (c>='0'&&c<='9') return c-'0';
                if (c>='a'&&c<='f') return c-'a'+10;
                if (c>='A'&&c<='F') return c-'A'+10;
                return -1;
            };
            int hi=hx(s[i+1]), lo=hx(s[i+2]);
            if (hi>=0&&lo>=0){ out.push_back((char)((hi<<4)|lo)); i+=2; continue; }
        }
        out.push_back(s[i]);
    }
    return out;
}
std::string url_encode_userinfo(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') out.push_back((char)c);
        else { char buf[8]; std::snprintf(buf,sizeof buf,"%%%02X",c); out+=buf; }
    }
    return out;
}

struct ProxySpec {
    std::string url, scheme, host;
    uint16_t port = 0;
    std::optional<std::string> username, password;
    // Tor's SOCKS interface is TCP-only; keep this marker explicit instead of
    // guessing from host/port because ordinary SOCKS5 proxies may support UDP.
    bool no_udp = false;
    std::vector<sockaddr_storage> resolved_endpoints;
    std::string key() const { return to_lower(url); }
};

std::string mask_proxy(const ProxySpec& p) {
    if (!p.username) return p.url;
    std::string host = p.host;
    if (host.find(':') != std::string::npos && host.front() != '[')
        host = "[" + host + "]";
    return p.scheme + "://" + url_encode_userinfo(*p.username) +
           ":****@" + host + ":" + std::to_string(p.port);
}

struct ParsedUrl {
    std::string scheme, userinfo, host;
    std::optional<uint16_t> port;
    std::string path, query, fragment;
};


bool parse_url(const std::string& raw, ParsedUrl& out, std::string& err) {
    auto colon = raw.find("://");
    if (colon == std::string::npos) { err = "missing scheme separator"; return false; }
    out.scheme = to_lower(raw.substr(0, colon));
    std::string rest = raw.substr(colon + 3);

    auto hash = rest.find('#');
    if (hash != std::string::npos) { out.fragment = rest.substr(hash + 1); rest = rest.substr(0, hash); }
    auto q = rest.find('?');
    if (q != std::string::npos) { out.query = rest.substr(q + 1); rest = rest.substr(0, q); }
    auto slash = rest.find('/');
    if (slash != std::string::npos) { out.path = rest.substr(slash); rest = rest.substr(0, slash); }

    auto at = rest.rfind('@');
    if (at != std::string::npos) { out.userinfo = rest.substr(0, at); rest = rest.substr(at + 1); }

    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close == std::string::npos) { err = "unterminated IPv6 literal"; return false; }
        out.host = rest.substr(1, close - 1);
        std::string after = rest.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':') { err = "invalid characters after IPv6 literal"; return false; }
            std::string ps = after.substr(1);
            if (ps.empty()) { err = "invalid port"; return false; }
            unsigned long v = 0;
            for (char c : ps) { if (!std::isdigit((unsigned char)c)) { err = "invalid port"; return false; } v = v*10+(c-'0'); if (v>65535){err="invalid port";return false;} }
            out.port = (uint16_t)v;
        }
    } else {
        auto c2 = rest.rfind(':');
        if (c2 != std::string::npos && rest.find(':') == c2) {
            out.host = rest.substr(0, c2);
            std::string ps = rest.substr(c2 + 1);
            if (ps.empty()) { err = "invalid port"; return false; }
            unsigned long v = 0;
            for (char c : ps) { if (!std::isdigit((unsigned char)c)) { err = "invalid port"; return false; } v = v*10+(c-'0'); if (v>65535){err="invalid port";return false;} }
            out.port = (uint16_t)v;
        } else out.host = rest;
    }
    if (out.host.empty()) { err = "proxy host is missing"; return false; }
    return true;
}
bool parse_proxy_url(const std::string& raw, ProxySpec& out, std::string& err) {
    ParsedUrl pu;
    if (!parse_url(trim(raw), pu, err)) return false;
    static const std::unordered_set<std::string> supported = {
        "http","https","socks4","socks4a","socks5","socks5h"
    };
    if (!supported.count(pu.scheme)) {
        err = "unsupported proxy scheme '" + (pu.scheme.empty() ? std::string("<none>") : pu.scheme) + "'";
        return false;
    }
    if (pu.path != "" && pu.path != "/") { err = "proxy URL must not contain a path"; return false; }
    if (!pu.query.empty())    { err = "proxy URL must not contain query";    return false; }
    if (!pu.fragment.empty()) { err = "proxy URL must not contain fragment"; return false; }
    if (!pu.port || *pu.port == 0) { err = "proxy port must be between 1 and 65535"; return false; }
    out.url = trim(raw); out.scheme = pu.scheme; out.host = pu.host; out.port = *pu.port;
    if (!pu.userinfo.empty()) {
        auto c = pu.userinfo.find(':');
        if (c == std::string::npos) { out.username = url_decode(pu.userinfo); out.password = std::string{}; }
        else { out.username = url_decode(pu.userinfo.substr(0, c)); out.password = url_decode(pu.userinfo.substr(c+1)); }
    }
    return true;
}

bool resolve_proxy_endpoints(ProxySpec& p, std::string& err) {
    if (!p.resolved_endpoints.empty()) return true;
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo* res = nullptr;
    const std::string port_s = std::to_string(p.port);
    const int rc = ::getaddrinfo(p.host.c_str(), port_s.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        err = "cannot resolve upstream proxy host '" + p.host + "': " + gai_strerror(rc);
        return false;
    }
    for (auto* ai = res; ai; ai = ai->ai_next) {
        if ((ai->ai_family == AF_INET || ai->ai_family == AF_INET6) && ai->ai_addrlen <= sizeof(sockaddr_storage)) {
            sockaddr_storage ss{};
            std::memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
            p.resolved_endpoints.push_back(ss);
        }
    }
    ::freeaddrinfo(res);
    if (p.resolved_endpoints.empty()) {
        err = "proxy host resolved but returned no IPv4/IPv6 endpoints";
        return false;
    }
    return true;
}

std::vector<ProxySpec> load_proxies(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) throw std::runtime_error("cannot open " + path);
    std::vector<ProxySpec> out; std::unordered_set<std::string> seen;
    std::string line; int line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        ProxySpec spec; std::string err;
        if (!parse_proxy_url(t, spec, err)) {
            log_err("[tunnel] ignoring invalid proxy on line " + std::to_string(line_no) + ": " + err);
            continue;
        }
        std::string resolve_err;
        if (!resolve_proxy_endpoints(spec, resolve_err) && !resolve_err.empty())
            log_err("[tunnel] warning: deferred proxy DNS for line " + std::to_string(line_no) + ": " + resolve_err);
        std::string k = spec.key();
        if (seen.count(k)) continue;
        seen.insert(k);
        out.push_back(std::move(spec));
    }
    if (out.empty()) throw std::runtime_error("no valid proxies found in " + path);
    return out;
}

// File-descriptor guard
struct FdGuard {
    int fd = -1;
    FdGuard() = default;
    explicit FdGuard(int f) : fd(f) {}
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    FdGuard(FdGuard&& o) noexcept : fd(o.fd) { o.fd = -1; }
    FdGuard& operator=(FdGuard&& o) noexcept { if (this != &o) { reset(); fd = o.fd; o.fd = -1; } return *this; }
    ~FdGuard() { reset(); }
    void reset(int f = -1) { if (fd >= 0) ::close(fd); fd = f; }
    operator int() const { return fd; }
    bool valid() const { return fd >= 0; }
};

// Socket helpers
bool set_blocking(int fd, bool blocking) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (blocking) flags &= ~O_NONBLOCK; else flags |= O_NONBLOCK;
    return ::fcntl(fd, F_SETFL, flags) == 0;
}
bool wait_readable(int fd, double timeout_s) {
    struct pollfd p{fd, POLLIN, 0};
    int rc = ::poll(&p, 1, (int)(timeout_s * 1000.0));
    if (rc <= 0) return false;
    return (p.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}
bool mark_socket_if_needed(int fd) {
    const int mark = g_egress_mark.load();
    if (mark == 0) return true;
    if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) return false;
    return true;
}

int tcp_connect(const std::string& host, uint16_t port, double timeout_s) {
    struct addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_protocol=IPPROTO_TCP;
    struct addrinfo* res=nullptr; std::string port_s=std::to_string(port);
    if(::getaddrinfo(host.c_str(),port_s.c_str(),&hints,&res)!=0)return -1;
    std::unique_ptr<struct addrinfo,decltype(&::freeaddrinfo)> guard(res,::freeaddrinfo);
    double deadline=now_monotonic()+timeout_s;
    for(auto* ai=res;ai;ai=ai->ai_next){
        int fd=::socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol); if(fd<0)continue;
        if(!mark_socket_if_needed(fd)||!set_blocking(fd,false)){::close(fd);continue;}
        int rc=::connect(fd,ai->ai_addr,ai->ai_addrlen); if(rc==0){set_blocking(fd,true);return fd;}
        if(errno!=EINPROGRESS){::close(fd);continue;}
        double rem=deadline-now_monotonic(); if(rem<=0){::close(fd);break;}
        struct pollfd p{fd,POLLOUT,0}; rc=::poll(&p,1,(int)(rem*1000.0)); if(rc<=0){::close(fd);continue;}
        int soerr=0; socklen_t sl=sizeof soerr; if(::getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&sl)<0||soerr!=0){::close(fd);continue;}
        set_blocking(fd,true); return fd;
    }
    return -1;
}

int tcp_connect_proxy(const ProxySpec& proxy, double timeout_s) {
    std::vector<sockaddr_storage> endpoints=proxy.resolved_endpoints;
    if(endpoints.empty()){
        ProxySpec tmp=proxy; std::string err; if(!resolve_proxy_endpoints(tmp,err))return -1; endpoints=std::move(tmp.resolved_endpoints);
    }
    const double deadline=now_monotonic()+timeout_s;
    for(const auto& original:endpoints){
        sockaddr_storage ss=original; int family=ss.ss_family; int fd=::socket(family,SOCK_STREAM,IPPROTO_TCP); if(fd<0)continue;
        if(!mark_socket_if_needed(fd)||!set_blocking(fd,false)){::close(fd);continue;}
        socklen_t sl=0;
        if(family==AF_INET){reinterpret_cast<sockaddr_in*>(&ss)->sin_port=htons(proxy.port);sl=sizeof(sockaddr_in);}
        else if(family==AF_INET6){reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port=htons(proxy.port);sl=sizeof(sockaddr_in6);}
        else {::close(fd);continue;}
        int rc=::connect(fd,reinterpret_cast<sockaddr*>(&ss),sl); if(rc==0){set_blocking(fd,true);return fd;}
        if(errno!=EINPROGRESS){::close(fd);continue;}
        double rem=deadline-now_monotonic(); if(rem<=0){::close(fd);break;}
        struct pollfd p{fd,POLLOUT,0}; rc=::poll(&p,1,(int)(rem*1000.0)); if(rc<=0){::close(fd);continue;}
        int soerr=0; socklen_t esl=sizeof soerr; if(::getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&esl)<0||soerr!=0){::close(fd);continue;}
        set_blocking(fd,true); return fd;
    }
    return -1;
}

// Stream
struct Stream {
    int fd = -1;
    Stream() = default;
    explicit Stream(int f) : fd(f) {}
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&& o) noexcept : fd(o.fd) { o.fd = -1; }
    Stream& operator=(Stream&& o) noexcept { if (this != &o) { close(); fd = o.fd; o.fd = -1; } return *this; }
    ~Stream() { close(); }
    void close() { if (fd >= 0) { ::shutdown(fd, SHUT_RDWR); ::close(fd); fd = -1; } }
    bool valid() const { return fd >= 0; }

    bool read_exact(void* buf, size_t n, double timeout_s) {
        char* p = (char*)buf;
        double deadline = now_monotonic() + timeout_s;
        while (n > 0) {
            double remaining = deadline - now_monotonic();
            if (remaining <= 0) return false;
            if (!wait_readable(fd, remaining)) return false;
            ssize_t r = ::recv(fd, p, n, 0);
            if (r == 0) return false;
            if (r < 0) { if (errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK) continue; return false; }
            p += r; n -= (size_t)r;
        }
        return true;
    }
    ssize_t read_some(void* buf, size_t n, double timeout_s) {
        if (!wait_readable(fd, timeout_s)) return -1;
        ssize_t r = ::recv(fd, buf, n, 0);
        if (r < 0 && (errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)) return 0;
        return r;
    }
    bool write_all(const void* buf, size_t n, double timeout_s) {
        const char* p = (const char*)buf;
        double deadline = now_monotonic() + timeout_s;
        while (n > 0) {
            double remaining = deadline - now_monotonic();
            if (remaining <= 0) return false;
            struct pollfd pf{fd, POLLOUT, 0};
            int rc = ::poll(&pf, 1, (int)(remaining * 1000.0));
            if (rc <= 0) return false;
            ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
            if (w < 0) { if (errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK) continue; return false; }
            p += w; n -= (size_t)w;
        }
        return true;
    }
    int read_until(const std::string& delim, std::string& out, size_t limit, double timeout_s) {
        out.clear();
        double deadline = now_monotonic() + timeout_s;
        char buf[4096];
        while (out.size() < limit) {
            double remaining = deadline - now_monotonic();
            if (remaining <= 0) return -1;
            if (!wait_readable(fd, remaining)) return -1;
            ssize_t r = ::recv(fd, buf, sizeof buf, 0);
            if (r == 0) return out.empty() ? 0 : 1;
            if (r < 0) { if (errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK) continue; return -1; }
            size_t old_size = out.size();
            out.append(buf, (size_t)r);
            size_t search_from = old_size > delim.size() ? old_size - delim.size() : 0;
            if (out.find(delim, search_from) != std::string::npos) return 1;
        }
        return -2;
    }
};

// Base64
std::string base64_encode(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size()+2)/3)*4);
    size_t i = 0;
    while (i + 2 < in.size()) {
        uint32_t v = ((uint8_t)in[i]<<16)|((uint8_t)in[i+1]<<8)|(uint8_t)in[i+2];
        out.push_back(tbl[(v>>18)&63]); out.push_back(tbl[(v>>12)&63]);
        out.push_back(tbl[(v>>6)&63]);  out.push_back(tbl[v&63]);
        i += 3;
    }
    if (i < in.size()) {
        uint32_t v = ((uint8_t)in[i]<<16);
        if (i+1 < in.size()) v |= ((uint8_t)in[i+1]<<8);
        out.push_back(tbl[(v>>18)&63]); out.push_back(tbl[(v>>12)&63]);
        out.push_back(i+1 < in.size() ? tbl[(v>>6)&63] : '=');
        out.push_back('=');
    }
    return out;
}

// Upstream protocols
Stream http_connect(const ProxySpec& proxy, const std::string& dest_host,
                    uint16_t dest_port, double timeout_s, std::string& err) {
    int fd = tcp_connect_proxy(proxy, timeout_s);
    if (fd < 0) { err = "TCP connect to proxy failed: " + std::string(strerror(errno)); return {}; }
    Stream s(fd);
    std::ostringstream req;
    req << "CONNECT " << dest_host << ":" << dest_port << " HTTP/1.1\r\n";
    req << "Host: " << dest_host << ":" << dest_port << "\r\n";
    req << "User-Agent: " << kUserAgent << "\r\n";
    req << "Proxy-Connection: Keep-Alive\r\n";
    if (proxy.username) {
        std::string creds = *proxy.username + ":" + (proxy.password ? *proxy.password : "");
        req << "Proxy-Authorization: Basic " << base64_encode(creds) << "\r\n";
    }
    req << "\r\n";
    std::string r = req.str();
    if (!s.write_all(r.data(), r.size(), timeout_s)) { err = "write CONNECT failed"; return {}; }

    std::string head;
    int rc = s.read_until("\r\n\r\n", head, kHttpHeaderLimit, timeout_s);
    if (rc == -2) { err = "HTTP proxy response headers too large"; return {}; }
    if (rc != 1) { err = "HTTP proxy response read failed"; return {}; }

    auto eol = head.find("\r\n");
    if (eol == std::string::npos) { err = "invalid HTTP proxy response"; return {}; }
    std::string status_line = head.substr(0, eol);
    auto sp = status_line.find(' ');
    if (sp == std::string::npos) { err = "invalid HTTP status line"; return {}; }
    std::string version = status_line.substr(0, sp);
    if (!starts_with(version, "HTTP/")) { err = "invalid HTTP protocol"; return {}; }
    std::string rest = status_line.substr(sp + 1);
    auto sp2 = rest.find(' ');
    std::string code_s = (sp2 == std::string::npos) ? rest : rest.substr(0, sp2);
    int status = 0;
    try { status = std::stoi(code_s); } catch (...) { err = "invalid HTTP status code"; return {}; }
    if (status < 200 || status >= 300) { err = "HTTP proxy CONNECT failed with " + std::to_string(status); return {}; }
    return s;
}

Stream socks4_connect(const ProxySpec& proxy, const std::string& dest_host,
                      uint16_t dest_port, double timeout_s, bool remote_dns,
                      std::string& err) {
    int fd = tcp_connect_proxy(proxy, timeout_s);
    if (fd < 0) { err = "TCP connect to proxy failed: " + std::string(strerror(errno)); return {}; }
    Stream s(fd);
    uint32_t ip = 0;
    bool is_v4 = ::inet_pton(AF_INET, dest_host.c_str(), &ip) == 1;
    std::vector<uint8_t> req;
    req.push_back(4); req.push_back(1);
    req.push_back((dest_port>>8)&0xff); req.push_back(dest_port&0xff);
    std::string user = proxy.username ? *proxy.username : "";
    if (is_v4) {
        uint8_t* p = (uint8_t*)&ip;
        req.insert(req.end(), p, p+4);
        req.insert(req.end(), user.begin(), user.end());
        req.push_back(0);
    } else {
        if (!remote_dns) { err = "SOCKS4 requires IPv4 destination"; return {}; }
        req.push_back(0); req.push_back(0); req.push_back(0); req.push_back(1);
        req.insert(req.end(), user.begin(), user.end());
        req.push_back(0);
        req.insert(req.end(), dest_host.begin(), dest_host.end());
        req.push_back(0);
    }
    if (!s.write_all(req.data(), req.size(), timeout_s)) { err = "SOCKS4 request write failed"; return {}; }
    uint8_t resp[8];
    if (!s.read_exact(resp, 8, timeout_s)) { err = "SOCKS4 response read failed"; return {}; }
    if (resp[0] != 0) { err = "SOCKS4 invalid version in response"; return {}; }
    if (resp[1] != 90) { err = "SOCKS4 request rejected (code " + std::to_string(resp[1]) + ")"; return {}; }
    return s;
}

Stream socks5_connect(const ProxySpec& proxy, const std::string& dest_host,
                      uint16_t dest_port, double timeout_s, bool remote_dns,
                      std::string& err) {
    int fd = tcp_connect_proxy(proxy, timeout_s);
    if (fd < 0) { err = "TCP connect to proxy failed: " + std::string(strerror(errno)); return {}; }
    Stream s(fd);
    bool use_auth = proxy.username.has_value();

    uint8_t greet[3] = {5, 1, use_auth ? (uint8_t)0x02 : (uint8_t)0x00};
    if (!s.write_all(greet, 3, timeout_s)) { err = "SOCKS5 greeting write failed"; return {}; }
    uint8_t sel[2];
    if (!s.read_exact(sel, 2, timeout_s)) { err = "SOCKS5 method selection read failed"; return {}; }
    if (sel[0] != 5) { err = "SOCKS5 invalid version"; return {}; }
    if (sel[1] == 0xFF) { err = "SOCKS5 no acceptable auth method"; return {}; }

    if (use_auth) {
        if (sel[1] != 0x02) { err = "SOCKS5 proxy did not select user/pass auth"; return {}; }
        std::string u = *proxy.username, p = proxy.password ? *proxy.password : "";
        if (u.size() > 255 || p.size() > 255) { err = "SOCKS5 credentials too long"; return {}; }
        std::vector<uint8_t> ar;
        ar.push_back(1); ar.push_back((uint8_t)u.size());
        ar.insert(ar.end(), u.begin(), u.end());
        ar.push_back((uint8_t)p.size());
        ar.insert(ar.end(), p.begin(), p.end());
        if (!s.write_all(ar.data(), ar.size(), timeout_s)) { err = "SOCKS5 auth write failed"; return {}; }
        uint8_t arresp[2];
        if (!s.read_exact(arresp, 2, timeout_s)) { err = "SOCKS5 auth response read failed"; return {}; }
        if (arresp[1] != 0) { err = "SOCKS5 authentication failed"; return {}; }
    } else {
        if (sel[1] != 0x00) { err = "SOCKS5 proxy requires authentication"; return {}; }
    }

    std::vector<uint8_t> req;
    req.push_back(5); req.push_back(1); req.push_back(0);
    uint32_t ip4 = 0; uint8_t ip6[16];
    bool is_v4 = ::inet_pton(AF_INET, dest_host.c_str(), &ip4) == 1;
    bool is_v6 = !is_v4 && ::inet_pton(AF_INET6, dest_host.c_str(), ip6) == 1;
    if (is_v4) {
        req.push_back(1);
        uint8_t* p = (uint8_t*)&ip4;
        req.insert(req.end(), p, p+4);
    } else if (is_v6 && !remote_dns) {
        req.push_back(4);
        req.insert(req.end(), ip6, ip6+16);
    } else {
        if (dest_host.size() > 255) { err = "SOCKS5 destination hostname too long"; return {}; }
        req.push_back(3);
        req.push_back((uint8_t)dest_host.size());
        req.insert(req.end(), dest_host.begin(), dest_host.end());
    }
    req.push_back((dest_port>>8)&0xff); req.push_back(dest_port&0xff);
    if (!s.write_all(req.data(), req.size(), timeout_s)) { err = "SOCKS5 CONNECT write failed"; return {}; }

    uint8_t hdr[4];
    if (!s.read_exact(hdr, 4, timeout_s)) { err = "SOCKS5 reply header read failed"; return {}; }
    if (hdr[0] != 5) { err = "SOCKS5 invalid reply version"; return {}; }
    if (hdr[1] != 0) { err = "SOCKS5 CONNECT failed (code " + std::to_string(hdr[1]) + ")"; return {}; }
    size_t addr_len = 0;
    if (hdr[3] == 1) addr_len = 4;
    else if (hdr[3] == 4) addr_len = 16;
    else if (hdr[3] == 3) {
        uint8_t l;
        if (!s.read_exact(&l, 1, timeout_s)) { err = "SOCKS5 reply read failed"; return {}; }
        addr_len = l;
    } else { err = "SOCKS5 unknown address type"; return {}; }
    uint8_t skip[18];
    if (addr_len + 2 > sizeof skip) { err = "SOCKS5 reply too long"; return {}; }
    if (!s.read_exact(skip, addr_len + 2, timeout_s)) { err = "SOCKS5 reply body read failed"; return {}; }
    return s;
}

Stream open_through_proxy(const ProxySpec& proxy, const std::string& dest_host,
                          uint16_t dest_port, double timeout_s,
                          bool remote_dns, std::string& err) {
    if (proxy.scheme == "http") return http_connect(proxy, dest_host, dest_port, timeout_s, err);
    if (proxy.scheme == "https") { err = "https:// upstream proxies are not supported (no TLS backend)"; return {}; }
    if (proxy.scheme == "socks4" || proxy.scheme == "socks4a") return socks4_connect(proxy, dest_host, dest_port, timeout_s, remote_dns, err);
    if (proxy.scheme == "socks5" || proxy.scheme == "socks5h") return socks5_connect(proxy, dest_host, dest_port, timeout_s, remote_dns, err);
    err = "unsupported proxy scheme: " + proxy.scheme;
    return {};
}

} // namespace tunnel
