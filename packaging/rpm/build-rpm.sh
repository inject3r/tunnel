#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?output .rpm path}
VERSION=${VERSION:-$(sed -n 's/^project(tunnel VERSION \([^)]*\).*/\1/p' "$ROOT/CMakeLists.txt" | head -1)}
WORK=${WORKDIR:-"$(mktemp -d)"}
trap 'rm -rf "$WORK"' EXIT

TOP="$WORK/rpmbuild"
mkdir -p "$TOP/BUILD" "$TOP/RPMS" "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS"
cp "$ROOT/packaging/rpm/tunnel.spec" "$TOP/SPECS/tunnel.spec"
sed -i "s/^Version:[[:space:]]*.*/Version:        $VERSION/" "$TOP/SPECS/tunnel.spec"
tar -C "$ROOT" -czf "$TOP/SOURCES/tunnel-$VERSION.tar.gz" --exclude=.git --transform="s,^\./,tunnel-$VERSION/," .
# Keep the source archive deterministic enough for repeatable release builds.
rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/tunnel.spec"
RPM=$(find "$TOP/RPMS" -type f -name 'tunnel-*.rpm' | head -1)
[[ -n "$RPM" ]]
mkdir -p "$(dirname "$OUT")"
cp "$RPM" "$OUT"
echo "Built $OUT"
