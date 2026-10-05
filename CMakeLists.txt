cmake_minimum_required(VERSION 3.20)
project(tunnel VERSION 1.1.0 LANGUAGES CXX)

option(TUNNEL_ENABLE_ASAN "Enable AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(TUNNEL_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(TUNNEL_WERROR "Treat warnings as errors" OFF)
option(TUNNEL_STATIC_CXX "Statically link libstdc++ and libgcc for broader glibc portability" OFF)
option(TUNNEL_FULL_STATIC "Fully static executable; intended for musl builds" OFF)

set(TUNNEL_SOURCES
    src/tunnel/main.cpp
    src/tunnel/config.h
    src/tunnel/core.h
    src/tunnel/proxy.h
    src/tunnel/servers.h
    src/tunnel/global.h
    src/tunnel/cli.h
    src/tunnel/modes.h
)

add_executable(tunnel ${TUNNEL_SOURCES})
target_compile_features(tunnel PRIVATE cxx_std_20)
target_compile_options(tunnel PRIVATE
    -O2 -Wall -Wextra -Wpedantic -pthread
)
target_link_options(tunnel PRIVATE -pthread)

if(TUNNEL_STATIC_CXX)
    target_link_options(tunnel PRIVATE -static-libstdc++ -static-libgcc)
endif()

if(TUNNEL_FULL_STATIC)
    target_link_options(tunnel PRIVATE -static)
endif()
target_compile_definitions(tunnel PRIVATE _GNU_SOURCE)

if(TUNNEL_WERROR)
    target_compile_options(tunnel PRIVATE -Werror)
endif()

if(TUNNEL_ENABLE_ASAN AND TUNNEL_ENABLE_TSAN)
    message(FATAL_ERROR "ASAN and TSAN cannot be enabled together")
elseif(TUNNEL_ENABLE_ASAN)
    target_compile_options(tunnel PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
    target_link_options(tunnel PRIVATE -fsanitize=address,undefined)
elseif(TUNNEL_ENABLE_TSAN)
    target_compile_options(tunnel PRIVATE -fsanitize=thread -fno-omit-frame-pointer -g)
    target_link_options(tunnel PRIVATE -fsanitize=thread)
endif()

include(GNUInstallDirs)
install(TARGETS tunnel RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES LICENSE DESTINATION share/doc/tunnel)
install(FILES systemd/tunnel.service DESTINATION lib/systemd/system)
install(FILES config/proxies.txt DESTINATION share/doc/tunnel)
file(GLOB TUNNEL_DOCUMENTATION_FILES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/*-documentation.html")
if(TUNNEL_DOCUMENTATION_FILES)
    install(FILES ${TUNNEL_DOCUMENTATION_FILES} DESTINATION share/doc/tunnel)
endif()