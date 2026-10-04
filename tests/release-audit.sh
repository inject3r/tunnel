#!/usr/bin/env bash
set -euo pipefail

grep -Fq 'TUNNEL_STATIC_CXX' CMakeLists.txt
grep -Fq 'TUNNEL_FULL_STATIC' CMakeLists.txt
grep -Fq 'ExecStart=/usr/bin/env tunnel --daemon-global' systemd/tunnel.service
grep -Fq 'ExecStopPost=/usr/bin/env tunnel --emergency-disable-global' systemd/tunnel.service
test -x packaging/debian/build-deb.sh
test -x packaging/rpm/build-rpm.sh
test -x packaging/release/build-tarball.sh
test -f packaging/rpm/tunnel.spec
grep -Fq "arch=('x86_64' 'aarch64')" packaging/arch/PKGBUILD
test -f .github/workflows/release.yml
echo 'Release packaging audit: PASS'
