BUILD_DIR ?= build
PREFIX ?= /usr/local

.PHONY: all release debug asan tsan test clean install

all: release

release:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(PREFIX)
	cmake --build $(BUILD_DIR) -j$$(nproc)

basic:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) -j$$(nproc)

asan:
	cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTUNNEL_ENABLE_ASAN=ON
	cmake --build build-asan -j$$(nproc)

tsan:
	cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DTUNNEL_ENABLE_TSAN=ON
	cmake --build build-tsan -j$$(nproc)

test: release
	./tests/cli-smoke.sh ./$(BUILD_DIR)/tunnel
	./tests/static-firewall-audit.sh
	./tests/static-proxy-selection-audit.sh
	./tests/static-recovery-audit.sh
	./tests/release-audit.sh
	./tests/nft-syntax.sh

install: release
	cmake --install $(BUILD_DIR)

clean:
	rm -rf build build-asan build-tsan
