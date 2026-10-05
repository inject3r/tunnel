# Tunnel

Linux SOCKS5/HTTP proxy pool with command mode, local SOCKS5 server, HTTP CONNECT proxy, and a fail-closed global transparent proxy mode.

## Build

Build from source with CMake, Make, or the included `build.sh` script.

### Tor

```bash
# System Tor, usually on 127.0.0.1:9050
./build/tunnel --tor curl https://ifconfig.me

# Tor Browser, usually on 127.0.0.1:9150
./build/tunnel --tor-browser curl https://ifconfig.me

# Custom Tor listener
./build/tunnel --tor-host 127.0.0.1 --tor-port 9050 curl https://ifconfig.me

# Request Tor SOCKS stream isolation for this invocation
./build/tunnel --tor --tor-isolate curl https://ifconfig.me

# Check the Tor SOCKS listener with the normal proxy preflight
./build/tunnel --tor-check
```

```bash
./build.sh
./build/tunnel --version
./tests/cli-smoke.sh ./build/tunnel
./tests/static-firewall-audit.sh
./tests/nft-syntax.sh
```

## CLI helpers

```bash
./build/tunnel --list-proxies --file /path/to/proxies.txt
./build/tunnel --check-ping --file /path/to/proxies.txt --ping-host api.telegram.org --ping-port 443
```

`--proxy` and `--tor` are standalone upstream selectors and do not require a configured proxy-list file.

## Global mode

When `--tor` is selected, Global Mode uses the Tor SOCKS5h listener for TCP and disables transparent UDP interception because the Tor SOCKS interface is TCP-oriented. DNS/53 still uses Tunnel's local DNS fallback.

```bash
sudo ./build/tunnel --disable-global
sudo ./build/tunnel --enable-global --file /path/to/proxies.txt
sudo ./build/tunnel --global-status

# Optional: change to the best proxy every 15 seconds
sudo ./build/tunnel --enable-global --auto-switch 15 --file /path/to/proxies.txt

# Optional: integrate desktop/system proxy settings (disabled by default)
sudo ./build/tunnel --enable-global --system-proxy --file /path/to/proxies.txt
```

Persistent proxy-file default:

```bash
# User-level default; works without sudo.
./build/tunnel --set-proxy-file /home/me/proxies.txt
./build/tunnel --show-proxy-file

# System-wide default.
sudo ./build/tunnel --set-proxy-file /etc/tunnel/proxies.txt
sudo ./build/tunnel --show-proxy-file
sudo ./build/tunnel --enable-global

# Override the configured default for one run:
sudo ./build/tunnel --enable-global --file /tmp/other-proxies.txt

# Remove the persistent default:
sudo ./build/tunnel --clear-proxy-file
```

Emergency recovery:

```bash
sudo ./build/tunnel --disable-global
# Hard cleanup path if the daemon is wedged or the state file is missing:
sudo ./build/tunnel --emergency-disable-global
```

## References

- Linux transparent proxy support: https://docs.kernel.org/networking/tproxy.html
- Linux `SO_MARK`: https://www.man7.org/linux/man-pages/man7/socket.7.html
- Linux `recvmmsg(2)`: https://www.man7.org/linux/man-pages/man2/recvmmsg.2.html
- Linux `sendmmsg(2)`: https://www.man7.org/linux/man-pages/man2/sendmmsg.2.html
- Linux `splice(2)`: https://man7.org/linux/man-pages/man2/splice.2.html
