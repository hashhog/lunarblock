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

# busted is installed under ~/.luarocks but its own modules are NOT on the
# default LuaJIT search path, so `busted` fails at `require 'busted.runner'`
# before running a single spec. That made the whole suite look unrunnable on a
# stock checkout (2026-08-29) -- a HARNESS fact that reads like a broken node.
# Export the luarocks tree so `make test` works out of the box.
LUAROCKS_TREE ?= $(HOME)/.luarocks
BUSTED_ENV = LD_LIBRARY_PATH=./lib \
  LUA_PATH="$(LUAROCKS_TREE)/share/lua/5.1/?.lua;$(LUAROCKS_TREE)/share/lua/5.1/?/init.lua;;" \
  LUA_CPATH="$(LUAROCKS_TREE)/lib/lua/5.1/?.so;;"

# Run tests with busted using LuaJIT
test:
	$(BUSTED_ENV) busted --lua=luajit spec/

# Run individual test files
test-crypto:
	$(BUSTED_ENV) busted --lua=luajit spec/crypto_spec.lua

test-serialize:
	$(BUSTED_ENV) busted --lua=luajit spec/serialize_spec.lua

test-script:
	$(BUSTED_ENV) busted --lua=luajit spec/script_spec.lua

test-p2p:
	$(BUSTED_ENV) busted --lua=luajit spec/p2p_spec.lua

test-peer:
	$(BUSTED_ENV) busted --lua=luajit spec/peer_spec.lua

test-handshake:
	$(BUSTED_ENV) busted --lua=luajit spec/p2p_handshake_spec.lua

test-sync:
	$(BUSTED_ENV) busted --lua=luajit spec/sync_spec.lua

test-header-sync:
	$(BUSTED_ENV) busted --lua=luajit spec/header_sync_spec.lua

test-miniscript:
	$(BUSTED_ENV) busted --lua=luajit spec/miniscript_spec.lua

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
