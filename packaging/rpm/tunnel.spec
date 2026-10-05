Name:           tunnel
Version:        1.1.0
Release:        1%{?dist}
Summary:        Linux proxy tunnel with nftables-backed global mode
License:        MIT
URL:            https://github.com/inject3r/tunnel
BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  make
Requires:       nftables

%description
Tunnel provides SOCKS5/HTTP proxy pooling, command mode, a local SOCKS5
server, an HTTP CONNECT listener, and an nftables-backed fail-closed global
transparent proxy mode on Linux.

Source0:        tunnel-%{version}.tar.gz

%prep
%setup -q

%build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DTUNNEL_STATIC_CXX=ON
cmake --build build --parallel

%install
rm -rf %{buildroot}
DESTDIR=%{buildroot} cmake --install build

%files
%license LICENSE
%{_bindir}/tunnel
%{_prefix}/lib/systemd/system/tunnel.service
%{_datadir}/doc/tunnel/LICENSE
%{_datadir}/doc/tunnel/config/proxies.txt
%{_datadir}/doc/tunnel/*-documentation.html

%changelog
* Wed Oct 01 2026 Tunnel Project - 1.1.0-1
- Initial distro package.
