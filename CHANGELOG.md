## 1.0.0

- First public release.
- Modularized the Linux tunnel source into dedicated headers and a small entry point.
- Global Mode keeps the selected upstream sticky by default and fails over only on connection failure.
- Periodic upstream switching remains disabled unless explicitly enabled with `--auto-switch SEC`.
- Added persistent proxy-list configuration with `--set-proxy-file`, `--show-proxy-file`, and `--clear-proxy-file`.
- Added emergency Global cleanup and orphan-firewall recovery.
- Global startup validates the upstream before committing nftables rules.
- System proxy integration remains opt-in with `--system-proxy`.

## 1.1.0 packaging/CI hardening

- Added portable C++ runtime-linking options for distro builds.
- Added Debian, RPM, Arch, and musl release packaging helpers.
- Added native x86_64/aarch64 GitHub Actions release matrix.
- Added SHA-256 release checksums and source archive generation.
- Made the systemd unit resolve the installed `tunnel` binary through a standard PATH instead of hard-coding `/usr/local/bin`.

## 1.1.0

- Added first-class local Tor integration via `--tor`, `--tor-port`, `--tor-host`, `--tor-browser`, `--tor-isolate`, and `--tor-check`.
- `--tor` uses `socks5h://` so hostname resolution can remain inside Tor by default.
- Fixed fixed-upstream usage: `--proxy` and `--tor` no longer require a proxy-list file.
- Added `--list-proxies`, configurable ping targets, and configurable global HTTP CONNECT port.
