Name:           tunnel
Version:        1.1.0
Release:        1%{?dist}
Summary:        Linux proxy tunnel with nftables-backed global mode
License:        MIT
URL:            https://github.com/inject3r/tunnel
Source0:        tunnel-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  make
Requires:       nftables

%description
Tunnel provides SOCKS5/HTTP proxy pooling, command mode, a local SOCKS5
server, an HTTP CONNECT listener, and an nftables-backed fail-closed global
transparent proxy mode on Linux.

%prep
%setup -q

%build
cmake -S . -B build   -DCMAKE_BUILD_TYPE=Release   -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --parallel

%install
rm -rf %{buildroot}
DESTDIR=%{buildroot} cmake --install build

%files
%license %{_datadir}/doc/tunnel/LICENSE
%{_bindir}/tunnel
%{_prefix}/lib/systemd/system/tunnel.service
%{_datadir}/doc/tunnel/proxies.txt

%changelog
* Mon Oct 05 2026 Tunnel Project - 1.1.0-1
- Initial distro package.
