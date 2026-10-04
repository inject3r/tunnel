#!/usr/bin/env bash
set -euo pipefail
SRC=${1:-src/tunnel}
if grep -RInEq '"[[:space:]]*(tcp|udp)[[:space:]]+redirect' "$SRC"; then
  echo "FAIL: bare tcp/udp redirect expression still present" >&2
  exit 1
fi
grep -RInq 'meta l4proto tcp redirect' "$SRC"
grep -RInq 'udp dport 53 redirect' "$SRC"
grep -RInq 'run_nft({"-c", "-f"' "$SRC"
grep -RInq 'SO_MARK' "$SRC"
grep -RInq 'resolve_proxy_endpoints' "$SRC"
grep -RInq 'DnsProxyServer' "$SRC"
echo "Static firewall audit: PASS"
