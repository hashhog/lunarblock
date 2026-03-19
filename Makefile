# lunarblock Makefile
# Build, test, and lint targets for the Bitcoin full node

.PHONY: test lint check run help

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
