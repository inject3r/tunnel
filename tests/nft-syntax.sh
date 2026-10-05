#!/usr/bin/env bash
set -euo pipefail

if ! command -v nft >/dev/null 2>&1; then
  echo "nft is not installed; syntax test SKIPPED (exit 77)"
  exit 77
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<'NFT'
table ip tunnel_syntax_test {
  chain output_nat {
    type nat hook output priority -100; policy accept;
    meta l4proto tcp redirect to :18080
    udp dport 53 redirect to :15353
    meta l4proto udp udp dport != 53 redirect to :18081
  }
  chain output_filter {
    type filter hook output priority 0; policy accept;
    meta mark 1414870604 accept
    ip daddr 127.0.0.0/8 accept
    meta l4proto icmp accept
    drop
  }
}
table ip6 tunnel_syntax_test6 {
  chain output_nat {
    type nat hook output priority -100; policy accept;
    meta l4proto tcp redirect to :18080
    udp dport 53 redirect to :15353
    meta l4proto udp udp dport != 53 redirect to :18081
  }
  chain output_filter {
    type filter hook output priority 0; policy accept;
    meta mark 1414870604 accept
    ip6 daddr ::1 accept
    meta l4proto icmpv6 accept
    drop
  }
}
NFT

if [[ "$EUID" -eq 0 ]]; then
  nft -c -f "$TMP"
elif sudo -n true 2>/dev/null; then
  sudo -n nft -c -f "$TMP"
else
  echo "nft syntax test SKIPPED: CAP_NET_ADMIN/root privilege is unavailable (exit 77)"
  exit 77
fi

echo "nft syntax: PASS"
