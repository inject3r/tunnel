#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?output .tar.gz path}
MODE=${2:-portable-glibc}
PREFIX=${PREFIX:-/usr}
WORK=${WORKDIR:-"$(mktemp -d)"}
trap 'rm -rf "$WORK"' EXIT

EXTRA=()
case "$MODE" in
  portable-glibc) EXTRA+=( -DTUNNEL_STATIC_CXX=ON ) ;;
  musl-static) EXTRA+=( -DTUNNEL_STATIC_CXX=ON -DTUNNEL_FULL_STATIC=ON ) ;;
  *) echo "Unknown tarball mode: $MODE" >&2; exit 2 ;;
esac

cmake -S "$ROOT" -B "$WORK/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  "${EXTRA[@]}"
cmake --build "$WORK/build" --parallel
DESTDIR="$WORK/root" cmake --install "$WORK/build"
mkdir -p "$(dirname "$OUT")"
mkdir -p "$WORK/archive"
# Keep a flat top-level /usr tree so the archive can be unpacked into /. 
tar -C "$WORK/root" -czf "$OUT" .
echo "Built $OUT"
