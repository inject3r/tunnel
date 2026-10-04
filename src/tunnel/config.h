#pragma once

#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tunnel {

constexpr int kDefaultServerPort = 39481;
constexpr int kDefaultGlobalSocksPort = 1080;
constexpr int kDefaultGlobalHttpPort = 8118;
constexpr double kDefaultConnectTimeout = 8.0;
constexpr double kDefaultIdleTimeout = 300.0;
constexpr int kDefaultMaxClients = 256;
constexpr size_t kBufferSize = 64 * 1024;
constexpr int kDefaultProxyAttempts = 4;
constexpr double kDefaultPingTimeout = 8.0;
constexpr const char* kDefaultPingTargetHost = "api.telegram.org";
constexpr uint16_t kDefaultPingTargetPort = 443;
constexpr size_t kHttpHeaderLimit = 64 * 1024;
constexpr const char* kVersion = "1.1.0";
constexpr const char* kUserAgent = "Tunnel/1.0";
constexpr const char* kRuntimeDir = "/run/tunnel";
constexpr const char* kStateFile = "/run/tunnel/global.state";
constexpr const char* kPidFile = "/run/tunnel/global.pid";
constexpr const char* kGuardianPidFile = "/run/tunnel/global.guardian.pid";
constexpr const char* kGlobalLockFile = "/run/tunnel/global.lock";
constexpr const char* kGlobalLog = "/var/log/tunnel/global.log";
constexpr const char* kSystemConfigDir = "/etc/tunnel";
constexpr const char* kSystemConfigFile = "/etc/tunnel/tunnel.conf";
constexpr uint32_t kGlobalFwMark = 0x54554e4c;
constexpr uint16_t kTransparentTcpPort = 18080;
constexpr uint16_t kTransparentUdpPort = 18081;
constexpr uint16_t kDnsProxyPort = 15353;
constexpr unsigned kUdpFlowTimeoutSec = 120;

std::atomic<int> g_egress_mark{0};

struct Args {
    bool server = false;
    std::string host = "127.0.0.1";
    uint16_t port = kDefaultServerPort;
    std::optional<std::string> proxy;
    std::string file;
    bool file_explicit = false;
    bool rotate = false;
    double auto_switch_interval = 0.0;
    bool verify = false;
    bool check_ping = false;
    std::optional<std::string> bot_token;
    double connect_timeout = kDefaultConnectTimeout;
    double ping_timeout = kDefaultPingTimeout;
    double idle_timeout = kDefaultIdleTimeout;
    int max_clients = kDefaultMaxClients;
    std::optional<std::string> auth_user, auth_pass;
    bool local_dns = false;
    bool no_firefox_special = false;
    bool verbose = false;
    bool enable_global = false;
    bool system_proxy = false;
    bool disable_global = false;
    bool emergency_disable_global = false;
    bool global_status = false;
    bool set_proxy_file = false;
    bool clear_proxy_file = false;
    bool show_proxy_file = false;
    bool daemon_global = false;
    bool doctor = false;
    bool version = false;
    bool tor = false;
    bool tor_browser = false;
    bool tor_isolate = false;
    bool tor_check = false;
    bool list_proxies = false;
    uint16_t http_port = kDefaultGlobalHttpPort;
    std::string tor_host = "127.0.0.1";
    uint16_t tor_port = 9050;
    bool tor_port_explicit = false;
    std::string ping_host = kDefaultPingTargetHost;
    uint16_t ping_port = kDefaultPingTargetPort;
    std::vector<std::string> command;
};

} // namespace tunnel
