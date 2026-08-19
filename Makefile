# lunarblock Makefile
# Build, test, and lint targets for the Bitcoin full node

.PHONY: test lint check run help build

# Default target
help:
	@echo "lunarblock - Bitcoin full node in Lua"
	@echo ""
	@echo "Targets:"
	@echo "  test   - Run the test suite with busted"
	@echo "  lint   - Run luacheck linter"
	@echo "  check  - Run both lint and test"
	@echo "  run    - Run the node (requires dependencies)"
	@echo "  help   - Show this help message"

# Build C helpers (FFI shared libraries)
# Note: HDOG-format snapshot importer (csrc/hdog_import.c) was retired in
# favor of a pure-Lua Core-format loader; see src/utxo.lua load_snapshot
# and src/main.lua run_import_utxo.
#
# sha256_accel: SHA-NI / AVX2 SHA-256, the same instruction path Bitcoin Core
# uses (csrc/sha256_accel.c is modelled on Core's sha256_x86_shani.cpp).
#
# This target previously printed "(no FFI helpers to build)" and built NOTHING,
# so lib/ held only parallel_verify.so and src/crypto.lua's init_sha256_accel
# failed on all five of its search paths — silently, because the loader is
# pcall'd and falls back. EVERY SHA-256 in the node therefore took the generic
# path at crypto.lua:129, which runs a full EVP_MD_CTX create/init/update/
# final/free per call; since hash256 = sha256(sha256(x)), a double-SHA cost TWO
# complete OpenSSL context lifecycles. At ~12-14 of those per transaction input
# that is a large constant on the hottest path in the node.
#
# No -msha/-mavx2 needed globally: the accelerated routines carry
# __attribute__((target("sha,sse4.1"))) per-function (csrc/sha256_accel.c:81,
# 272, 325) and sha256_accel_init() probes CPUID at runtime, returning
# 1=SHA-NI, 2=AVX2, 0=generic. So the .so is safe to build and ship on hosts
# without the instructions — it just reports generic.
build: lib/sha256_accel.so

lib/sha256_accel.so: csrc/sha256_accel.c
	@mkdir -p lib
	$(CC) -O3 -fPIC -shared -o $@ $< -lcrypto
	@echo "built $@"

# Run tests with busted using LuaJIT
test:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/

# Run individual test files
test-crypto:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/crypto_spec.lua

test-serialize:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/serialize_spec.lua

test-script:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/script_spec.lua

test-p2p:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/p2p_spec.lua

test-peer:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/peer_spec.lua

test-handshake:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/p2p_handshake_spec.lua

test-sync:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/sync_spec.lua

test-header-sync:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/header_sync_spec.lua

test-miniscript:
	LD_LIBRARY_PATH=./lib busted --lua=luajit spec/miniscript_spec.lua

# Run luacheck linter
lint:
	luacheck src/ spec/

# Run both lint and tests
check: lint test

# Run the node (requires luasocket, rocksdb, openssl)
run:
	LD_LIBRARY_PATH=./lib luajit src/main.lua

# Run with regtest for local development
run-regtest:
	LD_LIBRARY_PATH=./lib luajit src/main.lua --regtest --nowalletcreate

# Run with testnet
run-testnet:
	LD_LIBRARY_PATH=./lib luajit src/main.lua --testnet
