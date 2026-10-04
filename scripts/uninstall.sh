#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

systemctl disable --now tunnel.service 2>/dev/null || true
for tunnel_bin in /usr/bin/tunnel /usr/local/bin/tunnel; do
  if [[ -x "$tunnel_bin" ]]; then
    "$tunnel_bin" --disable-global 2>/dev/null || true
  fi
done
rm -f /usr/bin/tunnel /usr/local/bin/tunnel
rm -f /usr/lib/systemd/system/tunnel.service /usr/local/lib/systemd/system/tunnel.service
rm -f /etc/systemd/system/tunnel.service
auto_rm=/var/log/tunnel
rm -rf "$auto_rm" /run/tunnel
systemctl daemon-reload

echo "Tunnel binary/service removed. /etc/tunnel was preserved."
