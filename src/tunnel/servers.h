#pragma once

#include "proxy.h"

namespace tunnel {

// SOCKS5 server
class SocksServer {
public:
    SocksServer(std::shared_ptr<ProxyPool> pool,
                std::string listen_host, uint16_t listen_port,
                double connect_timeout, double idle_timeout,
                int max_clients,
                std::optional<std::string> auth_user,
                std::optional<std::string> auth_pass,
                bool verbose, bool remote_dns)
        : pool_(std::move(pool)), listen_host_(std::move(listen_host)),
          listen_port_(listen_port), connect_timeout_(connect_timeout),
          idle_timeout_(idle_timeout), max_clients_(max_clients),
          auth_user_(std::move(auth_user)), auth_pass_(std::move(auth_pass)),
          verbose_(verbose), remote_dns_(remote_dns) {}
    ~SocksServer() { stop(); }

    bool start(std::string& err) {
        listen_fd_ = ::socket(AF_INET6, SOCK_STREAM, 0);
        bool v6 = listen_fd_ >= 0;
        if (!v6) listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) { err = "socket(): " + std::string(strerror(errno)); return false; }
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (v6) { int off = 0; ::setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off); }

        std::string host = listen_host_;
        if (host == "localhost") host = "127.0.0.1";

        if (v6) {
            struct sockaddr_in6 sa{};
            sa.sin6_family = AF_INET6;
            sa.sin6_port = htons(listen_port_);
            if (::inet_pton(AF_INET6, host.c_str(), &sa.sin6_addr) != 1) {
                if (host == "127.0.0.1") ::inet_pton(AF_INET6, "::ffff:127.0.0.1", &sa.sin6_addr);
                else {
                    struct addrinfo hints{}; hints.ai_family = AF_INET6; hints.ai_socktype = SOCK_STREAM;
                    struct addrinfo* res = nullptr;
                    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
                        err = "cannot resolve bind host " + host;
                        ::close(listen_fd_); listen_fd_ = -1; return false;
                    }
                    sa.sin6_addr = ((struct sockaddr_in6*)res->ai_addr)->sin6_addr;
                    ::freeaddrinfo(res);
                }
            }
            if (::bind(listen_fd_, (struct sockaddr*)&sa, sizeof sa) < 0) {
                err = "bind(): " + std::string(strerror(errno));
                ::close(listen_fd_); listen_fd_ = -1; return false;
            }
        } else {
            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(listen_port_);
            if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
                struct addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
                struct addrinfo* res = nullptr;
                if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
                    err = "cannot resolve bind host " + host;
                    ::close(listen_fd_); listen_fd_ = -1; return false;
                }
                sa.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
                ::freeaddrinfo(res);
            }
            if (::bind(listen_fd_, (struct sockaddr*)&sa, sizeof sa) < 0) {
                err = "bind(): " + std::string(strerror(errno));
                ::close(listen_fd_); listen_fd_ = -1; return false;
            }
        }
        if (::listen(listen_fd_, 128) < 0) {
            err = "listen(): " + std::string(strerror(errno));
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        if (listen_port_ == 0) {
            struct sockaddr_storage ss{}; socklen_t sl = sizeof ss;
            if (::getsockname(listen_fd_, (struct sockaddr*)&ss, &sl) == 0) {
                if (ss.ss_family == AF_INET6) listen_port_ = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
                else if (ss.ss_family == AF_INET) listen_port_ = ntohs(((struct sockaddr_in*)&ss)->sin_port);
            }
        }
        running_.store(true);
        accept_thread_ = std::thread([this]{ accept_loop(); });
        return true;
    }

    void stop() {
        bool expected = true;
        if (!running_.compare_exchange_strong(expected, false)) return;
        if (listen_fd_ >= 0) { ::shutdown(listen_fd_, SHUT_RDWR); ::close(listen_fd_); listen_fd_ = -1; }
        if (accept_thread_.joinable()) accept_thread_.join();
        {
            std::unique_lock<std::mutex> lk(workers_mutex_);
            workers_cv_.wait(lk, [this]{ return worker_count_.load() == 0; });
        }
    }

    uint16_t port() const { return listen_port_; }
    TunnelStats& stats() { return stats_; }

private:
    void accept_loop() {
        while (running_.load()) {
            struct sockaddr_storage ss{}; socklen_t sl = sizeof ss;
            int cfd = ::accept(listen_fd_, (struct sockaddr*)&ss, &sl);
            if (cfd < 0) {
                if (!running_.load()) break;
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                break;
            }
            if ((int)stats_.active_clients.load() >= max_clients_) {
                uint8_t rep[10] = {5, 1, 0, 1, 0,0,0,0, 0,0};
                ::send(cfd, rep, sizeof rep, MSG_NOSIGNAL);
                ::close(cfd);
                stats_.failed_clients.fetch_add(1);
                continue;
            }
            stats_.active_clients.fetch_add(1);
            stats_.total_clients.fetch_add(1);
            worker_count_.fetch_add(1);
            std::thread([this, cfd]{
                handle_client(cfd);
                worker_count_.fetch_sub(1);
                workers_cv_.notify_all();
            }).detach();
        }
    }
    static std::string peer_str(int fd) {
        struct sockaddr_storage ss{}; socklen_t sl = sizeof ss;
        if (::getpeername(fd, (struct sockaddr*)&ss, &sl) != 0) return "?";
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
        if (::getnameinfo((struct sockaddr*)&ss, sl, hbuf, sizeof hbuf,
                          sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV) != 0)
            return "?";
        return std::string(hbuf) + ":" + sbuf;
    }
    bool socks5_handshake(Stream& s, std::string& out_host, uint16_t& out_port) {
        uint8_t hdr[2];
        if (!s.read_exact(hdr, 2, connect_timeout_)) return false;
        if (hdr[0] != 5) { uint8_t r[2]={5,0xff}; s.write_all(r,2,connect_timeout_); return false; }
        std::vector<uint8_t> methods(hdr[1]);
        if (hdr[1] > 0 && !s.read_exact(methods.data(), methods.size(), connect_timeout_)) return false;

        bool need_auth = auth_user_.has_value() && auth_pass_.has_value();
        if (need_auth) {
            bool has_userpass = std::find(methods.begin(), methods.end(), 0x02) != methods.end();
            if (!has_userpass) { uint8_t r[2]={5,0xff}; s.write_all(r,2,connect_timeout_); return false; }
            uint8_t sel[2]={5,0x02};
            if (!s.write_all(sel, 2, connect_timeout_)) return false;
            uint8_t ver;
            if (!s.read_exact(&ver, 1, connect_timeout_)) return false;
            if (ver != 1) return false;
            uint8_t ulen;
            if (!s.read_exact(&ulen, 1, connect_timeout_)) return false;
            std::string user(ulen, '\0');
            if (ulen > 0 && !s.read_exact(user.data(), ulen, connect_timeout_)) return false;
            uint8_t plen;
            if (!s.read_exact(&plen, 1, connect_timeout_)) return false;
            std::string pass(plen, '\0');
            if (plen > 0 && !s.read_exact(pass.data(), plen, connect_timeout_)) return false;
            auto ct_eq = [](const std::string& a, const std::string& b) {
                if (a.size() != b.size()) return false;
                unsigned char diff = 0;
                for (size_t i = 0; i < a.size(); ++i) diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
                return diff == 0;
            };
            bool ok = ct_eq(user, *auth_user_) && ct_eq(pass, *auth_pass_);
            uint8_t ar[2] = {1, (uint8_t)(ok ? 0 : 1)};
            s.write_all(ar, 2, connect_timeout_);
            if (!ok) return false;
        } else {
            bool has_none = std::find(methods.begin(), methods.end(), 0x00) != methods.end();
            if (!has_none) { uint8_t r[2]={5,0xff}; s.write_all(r,2,connect_timeout_); return false; }
            uint8_t sel[2] = {5, 0x00};
            if (!s.write_all(sel, 2, connect_timeout_)) return false;
        }
        uint8_t req[4];
        if (!s.read_exact(req, 4, connect_timeout_)) return false;
        if (req[0] != 5) return false;
        if (req[1] != 1) { uint8_t rep[10]={5,7,0,1,0,0,0,0,0,0}; s.write_all(rep,sizeof rep,connect_timeout_); return false; }
        uint8_t atype = req[3];
        std::string host;
        if (atype == 1) {
            uint8_t ip[4];
            if (!s.read_exact(ip, 4, connect_timeout_)) return false;
            char buf[INET_ADDRSTRLEN]; ::inet_ntop(AF_INET, ip, buf, sizeof buf); host = buf;
        } else if (atype == 3) {
            uint8_t l;
            if (!s.read_exact(&l, 1, connect_timeout_)) return false;
            if (l == 0) { uint8_t rep[10]={5,8,0,1,0,0,0,0,0,0}; s.write_all(rep,sizeof rep,connect_timeout_); return false; }
            host.resize(l);
            if (!s.read_exact(host.data(), l, connect_timeout_)) return false;
        } else if (atype == 4) {
            uint8_t ip[16];
            if (!s.read_exact(ip, 16, connect_timeout_)) return false;
            char buf[INET6_ADDRSTRLEN]; ::inet_ntop(AF_INET6, ip, buf, sizeof buf); host = buf;
        } else { uint8_t rep[10]={5,8,0,1,0,0,0,0,0,0}; s.write_all(rep,sizeof rep,connect_timeout_); return false; }
        uint8_t port_b[2];
        if (!s.read_exact(port_b, 2, connect_timeout_)) return false;
        out_host = host;
        out_port = ((uint16_t)port_b[0] << 8) | port_b[1];
        return true;
    }
    static void send_socks5_reply(Stream& s, uint8_t code) {
        uint8_t rep[10] = {5, code, 0, 1, 0,0,0,0, 0,0};
        s.write_all(rep, sizeof rep, 5.0);
    }

    void handle_client(int cfd) {
        Stream client(cfd);
        Stream upstream;
        std::string peer = peer_str(cfd);
        bool failed = false;
        try {
            std::string dest_host; uint16_t dest_port = 0;
            if (!socks5_handshake(client, dest_host, dest_port)) { failed = true; goto done; }
            if (verbose_)
                log_line("[tunnel] " + peer + " -> " + dest_host + ":" + std::to_string(dest_port));
            {
                int attempts = pool_->fixed()
                    ? 1
                    : std::min<int>(kDefaultProxyAttempts, (int)pool_->size());
                std::unordered_set<std::string> tried;
                std::string last_err;
                bool ok = false;
                for (int i = 0; i < std::max(1, attempts); ++i) {
                    ProxySpec p = pool_->choose(tried);
                    tried.insert(p.key());
                    std::string err;
                    Stream up = open_through_proxy(p, dest_host, dest_port,
                                                   connect_timeout_, remote_dns_, err);
                    if (up.valid()) { upstream = std::move(up); pool_->success(p); ok = true; break; }
                    last_err = err;
                    pool_->failure(p, err);
                    if (verbose_) log_err("[tunnel] upstream failed " + mask_proxy(p) + ": " + err);
                }
                if (!ok) {
                    send_socks5_reply(client, 1);
                    failed = true;
                    if (verbose_ && !last_err.empty()) log_err("[tunnel] no upstream available: " + last_err);
                    goto done;
                }
            }
            send_socks5_reply(client, 0);
            {
                std::atomic<bool> client_done{false}, upstream_done{false};
                std::mutex done_m;
                std::condition_variable done_cv;
                auto notify_done = [&]{ std::lock_guard<std::mutex> lk(done_m); done_cv.notify_all(); };
                std::thread t_up([&]{
                    std::vector<char> buf(kBufferSize);
                    while (true) {
                        ssize_t r = client.read_some(buf.data(), buf.size(), idle_timeout_);
                        if (r <= 0) break;
                        if (!upstream.write_all(buf.data(), (size_t)r, idle_timeout_)) break;
                        stats_.bytes_up.fetch_add((uint64_t)r);
                    }
                    ::shutdown(upstream.fd, SHUT_WR);
                    client_done.store(true);
                    notify_done();
                });
                std::thread t_down([&]{
                    std::vector<char> buf(kBufferSize);
                    while (true) {
                        ssize_t r = upstream.read_some(buf.data(), buf.size(), idle_timeout_);
                        if (r <= 0) break;
                        if (!client.write_all(buf.data(), (size_t)r, idle_timeout_)) break;
                        stats_.bytes_down.fetch_add((uint64_t)r);
                    }
                    ::shutdown(client.fd, SHUT_WR);
                    upstream_done.store(true);
                    notify_done();
                });
                {
                    std::unique_lock<std::mutex> lk(done_m);
                    done_cv.wait_for(lk, std::chrono::seconds(1), [&]{
                        return client_done.load() && upstream_done.load();
                    });
                }
                for (int i = 0; i < 50 && !(client_done.load() && upstream_done.load()); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                if (!client_done.load()) ::shutdown(client.fd, SHUT_RDWR);
                if (!upstream_done.load()) ::shutdown(upstream.fd, SHUT_RDWR);
                t_up.join();
                t_down.join();
            }
        } catch (const std::exception& e) {
            failed = true;
            if (verbose_) log_err("[tunnel] client " + peer + " error: " + e.what());
        } catch (...) { failed = true; }
    done:
        upstream.close();
        client.close();
        stats_.active_clients.fetch_sub(1);
        if (failed) stats_.failed_clients.fetch_add(1);
    }

    std::shared_ptr<ProxyPool> pool_;
    std::string listen_host_;
    uint16_t listen_port_;
    double connect_timeout_;
    double idle_timeout_;
    int max_clients_;
    std::optional<std::string> auth_user_, auth_pass_;
    bool verbose_, remote_dns_;

    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    TunnelStats stats_;

    std::atomic<int> worker_count_{0};
    std::mutex workers_mutex_;
    std::condition_variable workers_cv_;
};

// HTTP CONNECT server
class HttpProxyServer {
public:
    HttpProxyServer(std::shared_ptr<ProxyPool> pool,
                    std::string listen_host, uint16_t listen_port,
                    double connect_timeout, double idle_timeout,
                    int max_clients, bool verbose, bool remote_dns)
        : pool_(std::move(pool)), listen_host_(std::move(listen_host)),
          listen_port_(listen_port), connect_timeout_(connect_timeout),
          idle_timeout_(idle_timeout), max_clients_(max_clients),
          verbose_(verbose), remote_dns_(remote_dns) {}
    ~HttpProxyServer() { stop(); }

    bool start(std::string& err) {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) { err = "socket(): " + std::string(strerror(errno)); return false; }
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(listen_port_);
        if (::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) != 1) {
            err = "invalid bind address"; ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        if (::bind(listen_fd_, (struct sockaddr*)&sa, sizeof sa) < 0) {
            err = "bind(): " + std::string(strerror(errno));
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        if (::listen(listen_fd_, 128) < 0) {
            err = "listen(): " + std::string(strerror(errno));
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        if (listen_port_ == 0) {
            struct sockaddr_in actual{}; socklen_t sl = sizeof actual;
            if (::getsockname(listen_fd_, (struct sockaddr*)&actual, &sl) == 0)
                listen_port_ = ntohs(actual.sin_port);
        }
        running_.store(true);
        accept_thread_ = std::thread([this]{ accept_loop(); });
        return true;
    }

    void stop() {
        bool expected = true;
        if (!running_.compare_exchange_strong(expected, false)) return;
        if (listen_fd_ >= 0) { ::shutdown(listen_fd_, SHUT_RDWR); ::close(listen_fd_); listen_fd_ = -1; }
        if (accept_thread_.joinable()) accept_thread_.join();
        {
            std::unique_lock<std::mutex> lk(workers_mutex_);
            workers_cv_.wait(lk, [this]{ return worker_count_.load() == 0; });
        }
    }

    uint16_t port() const { return listen_port_; }
    TunnelStats& stats() { return stats_; }

private:
    void accept_loop() {
        while (running_.load()) {
            struct sockaddr_storage ss{}; socklen_t sl = sizeof ss;
            int cfd = ::accept(listen_fd_, (struct sockaddr*)&ss, &sl);
            if (cfd < 0) {
                if (!running_.load()) break;
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                break;
            }
            if ((int)stats_.active_clients.load() >= max_clients_) {
                const char* resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                ::send(cfd, resp, strlen(resp), MSG_NOSIGNAL);
                ::close(cfd);
                stats_.failed_clients.fetch_add(1);
                continue;
            }
            stats_.active_clients.fetch_add(1);
            stats_.total_clients.fetch_add(1);
            worker_count_.fetch_add(1);
            std::thread([this, cfd]{
                handle_client(cfd);
                worker_count_.fetch_sub(1);
                workers_cv_.notify_all();
            }).detach();
        }
    }

    bool read_http_head(Stream& s, std::string& head, size_t limit, double timeout) {
        int rc = s.read_until("\r\n\r\n", head, limit, timeout);
        return rc == 1;
    }

    void handle_client(int cfd) {
        Stream client(cfd);
        Stream upstream;
        bool failed = false;
        try {
            std::string head;
            if (!read_http_head(client, head, kHttpHeaderLimit, connect_timeout_)) {
                failed = true; goto done;
            }
            auto eol = head.find("\r\n");
            if (eol == std::string::npos) { failed = true; goto done; }
            std::string req_line = head.substr(0, eol);
            auto parts = split(req_line, ' ');
            if (parts.size() < 3) { failed = true; goto done; }
            std::string method = parts[0];
            std::string target = parts[1];

            if (method != "CONNECT") {
                const char* resp = "HTTP/1.1 405 Method Not Allowed\r\n"
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n\r\n";
                client.write_all(resp, strlen(resp), connect_timeout_);
                failed = true; goto done;
            }

            std::string host; uint16_t port = 443;
            auto c = target.rfind(':');
            if (c == std::string::npos) { host = target; }
            else {
                host = target.substr(0, c);
                try { port = (uint16_t)std::stoi(target.substr(c + 1)); } catch (...) { port = 443; }
            }

            int attempts = pool_->fixed() ? 1 : std::min<int>(kDefaultProxyAttempts, (int)pool_->size());
            std::unordered_set<std::string> tried;
            bool connected = false;
            for (int i = 0; i < std::max(1, attempts); ++i) {
                ProxySpec p = pool_->choose(tried);
                tried.insert(p.key());
                std::string err;
                Stream up = open_through_proxy(p, host, port, connect_timeout_, remote_dns_, err);
                if (up.valid()) {
                    pool_->success(p);
                    upstream = std::move(up);
                    connected = true;
                    break;
                }
                pool_->failure(p, err);
                if (verbose_) log_err("[http] upstream failed " + mask_proxy(p) + ": " + err);
            }
            if (!connected) {
                const char* resp = "HTTP/1.1 502 Bad Gateway\r\n"
                                   "Content-Length: 0\r\n\r\n";
                client.write_all(resp, strlen(resp), connect_timeout_);
                failed = true; goto done;
            }

            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (!client.write_all(ok, strlen(ok), connect_timeout_)) { failed = true; goto done; }

            {
                std::atomic<bool> c_done{false}, u_done{false};
                std::mutex m; std::condition_variable cv;
                auto notify = [&]{ std::lock_guard<std::mutex> lk(m); cv.notify_all(); };
                std::thread t1([&]{
                    std::vector<char> b(kBufferSize);
                    while (true) {
                        ssize_t r = client.read_some(b.data(), b.size(), idle_timeout_);
                        if (r <= 0) break;
                        if (!upstream.write_all(b.data(), (size_t)r, idle_timeout_)) break;
                        stats_.bytes_up.fetch_add((uint64_t)r);
                    }
                    ::shutdown(upstream.fd, SHUT_WR);
                    c_done.store(true); notify();
                });
                std::thread t2([&]{
                    std::vector<char> b(kBufferSize);
                    while (true) {
                        ssize_t r = upstream.read_some(b.data(), b.size(), idle_timeout_);
                        if (r <= 0) break;
                        if (!client.write_all(b.data(), (size_t)r, idle_timeout_)) break;
                        stats_.bytes_down.fetch_add((uint64_t)r);
                    }
                    ::shutdown(client.fd, SHUT_WR);
                    u_done.store(true); notify();
                });
                {
                    std::unique_lock<std::mutex> lk(m);
                    cv.wait_for(lk, std::chrono::seconds(1), [&]{ return c_done.load() && u_done.load(); });
                }
                for (int i = 0; i < 50 && !(c_done.load() && u_done.load()); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                if (!c_done.load()) ::shutdown(client.fd, SHUT_RDWR);
                if (!u_done.load()) ::shutdown(upstream.fd, SHUT_RDWR);
                t1.join(); t2.join();
            }
        } catch (const std::exception& e) {
            failed = true;
            if (verbose_) log_err(std::string("[http] error: ") + e.what());
        } catch (...) { failed = true; }
    done:
        upstream.close(); client.close();
        stats_.active_clients.fetch_sub(1);
        if (failed) stats_.failed_clients.fetch_add(1);
    }

    std::shared_ptr<ProxyPool> pool_;
    std::string listen_host_;
    uint16_t listen_port_;
    double connect_timeout_, idle_timeout_;
    int max_clients_;
    bool verbose_, remote_dns_;

    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    TunnelStats stats_;

    std::atomic<int> worker_count_{0};
    std::mutex workers_mutex_;
    std::condition_variable workers_cv_;
};

// ====================================================================

} // namespace tunnel
