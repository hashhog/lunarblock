# lunarblock

A Bitcoin full node implementation in Lua, targeting LuaJIT 2.1.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
lunarblock is a from-scratch Bitcoin full node written in Lua (LuaJIT) that does
exactly that. It uses FFI bindings for performance-critical crypto operations.

## Current status

- [x] Project scaffold and CLI entry point
- [x] Bitcoin primitive types (hash256, hash160, outpoint, txin, txout, transaction, block)
- [x] Binary serialization (buffer reader/writer, varint, block/tx serialization)
- [ ] Cryptographic operations (SHA256, RIPEMD160, secp256k1)
- [ ] Script interpreter
- [ ] Block storage (RocksDB)
- [ ] P2P networking
- [ ] Initial block download
- [ ] Mempool
- [ ] RPC server
- [ ] Wallet functionality

## Quick start

```bash
# Run the node
luajit src/main.lua

# Show help
luajit src/main.lua --help

# Run with testnet
luajit src/main.lua --testnet
```

## Project structure

```
src/
  main.lua       - CLI entry point
  types.lua      - Bitcoin primitive types (hash256, transactions, blocks)
  serialize.lua  - Binary serialization/deserialization
  crypto.lua     - Hash functions and secp256k1 bindings
  address.lua    - Address encoding/decoding
  script.lua     - Script interpreter
  consensus.lua  - Consensus rules
  storage.lua    - Block/UTXO storage
  p2p.lua        - P2P network manager
  peer.lua       - Individual peer connection
  sync.lua       - Block synchronization
  mempool.lua    - Transaction mempool
  rpc.lua        - JSON-RPC server
  wallet.lua     - Wallet functionality
spec/
  *_spec.lua     - Test files
```

## Running tests

```bash
busted spec/
```
