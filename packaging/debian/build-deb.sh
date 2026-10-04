#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?output .deb path}
VERSION=${VERSION:-$(sed -n 's/^project(tunnel VERSION \([^)]*\).*/\1/p' "$ROOT/CMakeLists.txt" | head -1)}
ARCH=${DPKG_ARCH:-$(dpkg --print-architecture)}
WORK=${WORKDIR:-"$(mktemp -d)"}
trap 'rm -rf "$WORK"' EXIT

cmake -S "$ROOT" -B "$WORK/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DTUNNEL_STATIC_CXX=ON
cmake --build "$WORK/build" --parallel
DESTDIR="$WORK/root" cmake --install "$WORK/build"

PKG="$WORK/pkg"
mkdir -p "$PKG/DEBIAN"
cp -a "$WORK/root/." "$PKG/"
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: tunnel
Version: ${VERSION}
Architecture: ${ARCH}
Section: net
Priority: optional
Maintainer: Tunnel Project
Depends: libc6 (>= 2.31), nftables
Recommends: systemd
Description: Linux proxy tunnel with nftables-backed global mode
 Tunnel provides SOCKS5/HTTP proxy pooling and an nftables-backed
 fail-closed global transparent proxy mode on Linux.
CONTROL

mkdir -p "$(dirname "$OUT")"
dpkg-deb --build --root-owner-group "$PKG" "$OUT" >/dev/null
echo "Built $OUT"
