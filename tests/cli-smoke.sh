#!/usr/bin/env bash
set -euo pipefail
BIN=${1:-./build/tunnel}
[[ -x "$BIN" ]]
[[ "$("$BIN" --version)" == "Tunnel 1.1.0" ]]
$BIN --doctor >/tmp/tunnel-doctor.out
cat /tmp/tunnel-doctor.out
rm -f /tmp/tunnel-doctor.out
if "$BIN" >/tmp/tunnel-no-file.out 2>&1; then
  echo 'FAIL: proxy-backed invocation unexpectedly succeeded without a proxy source' >&2
  cat /tmp/tunnel-no-file.out >&2
  rm -f /tmp/tunnel-no-file.out
  exit 1
fi
grep -q -- 'no proxy file configured' /tmp/tunnel-no-file.out
rm -f /tmp/tunnel-no-file.out
[[ "$(sed -n '1p' <(printf '%s\n' "$($BIN --help)"))" == Usage:* ]]
grep -q -- '--set-proxy-file PATH' <("$BIN" --help)
grep -q -- '--clear-proxy-file' <("$BIN" --help)
grep -q -- '--show-proxy-file' <("$BIN" --help)
grep -q -- '--emergency-disable-global' <("$BIN" --help)
grep -q -- '--tor' <("$BIN" --help)
grep -q -- '--tor-check' <("$BIN" --help)
grep -q -- '--list-proxies' <("$BIN" --help)
TMP=$(mktemp)
printf '%s\n' 'socks5://127.0.0.1:1' > "$TMP"
"$BIN" --set-proxy-file "$TMP" >/tmp/tunnel-set.out
"$BIN" --show-proxy-file | grep -Fq "$TMP"
"$BIN" --clear-proxy-file >/tmp/tunnel-clear.out
"$BIN" --show-proxy-file | grep -Fq 'none'
echo 'socks5://127.0.0.1:1' > "$TMP"
"$BIN" --list-proxies --file "$TMP" | grep -Fq '127.0.0.1:1'
"$BIN" --list-proxies --tor | grep -Fq '127.0.0.1:9050'
rm -f "$TMP" /tmp/tunnel-set.out /tmp/tunnel-clear.out
echo "CLI smoke: PASS"
