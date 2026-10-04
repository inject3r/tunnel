#!/usr/bin/env bash
set -euo pipefail
SRC=${1:-src/tunnel}
grep -RInq 'start_global_firewall_guardian' "$SRC"
grep -RInq 'remove_global_firewall_unlocked' "$SRC"
grep -RInq 'GlobalNetworkRecoveryMonitor' "$SRC"
grep -RInq 'NETLINK_ROUTE' "$SRC"
grep -RInq 'RTMGRP_IPV4_ROUTE' "$SRC"
grep -RInq 'cmd_emergency_disable_global' "$SRC"
grep -RInq 'kGlobalLockFile' "$SRC"
grep -RInq 'kSystemConfigFile' "$SRC"
grep -RInq -- '--set-proxy-file' "$SRC"
grep -RInq -- '--clear-proxy-file' "$SRC"
grep -RInq -- '--show-proxy-file' "$SRC"
if grep -RInq 'worked\.txt' "$SRC"; then
  echo 'FAIL: obsolete proxy filename remains in source' >&2
  exit 1
fi
echo 'Static recovery audit: PASS'
