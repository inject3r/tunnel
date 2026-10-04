#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$ROOT/build" -j"$(nproc)"
cmake --install "$ROOT/build"

install -d -m 0755 /etc/tunnel
install -m 0644 "$ROOT/config/proxies.txt" /etc/tunnel/proxies.txt

systemctl daemon-reload

echo "Installed Tunnel 1.1.0."
echo "Create your proxy list at /etc/tunnel/proxies.txt, then:"
echo "  sudo /usr/bin/tunnel --set-proxy-file /etc/tunnel/proxies.txt"
echo "  sudo systemctl enable --now tunnel.service"
echo "Or run manually without --file after setting the persistent default."
echo "Emergency disable: sudo /usr/bin/tunnel --emergency-disable-global"
