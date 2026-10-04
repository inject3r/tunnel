#!/usr/bin/env bash
set -euo pipefail
SRC=${1:-src/tunnel}
grep -RInq 'constexpr double kDefaultConnectTimeout = 8.0;' "$SRC"
grep -RInq 'double auto_switch_interval = 0.0' "$SRC"
grep -RInq 'class ProxyAutoSwitchMonitor' "$SRC"
grep -RInq 'pool->set_active(best->proxy)' "$SRC"
grep -RInq 'firewall NOT installed' "$SRC"
grep -RInq 'bool process_exists(pid_t pid)' "$SRC"
grep -RInq 'system_proxy_applied' "$SRC"
grep -RInq 'int fd = tcp_connect_proxy(proxy, timeout_s);' "$SRC"
if grep -RInq 'int fd = tcp_connect(proxy.host, proxy.port, timeout_s);' "$SRC"; then
  echo 'FAIL: SOCKS5 still resolves the proxy hostname after firewall activation' >&2
  exit 1
fi
echo "Proxy selection audit: PASS"
