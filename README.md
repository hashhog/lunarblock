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
- [x] Cryptographic operations (SHA256, RIPEMD160, secp256k1, Schnorr)
- [x] Address encoding (Base58Check, Bech32/Bech32m for P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Script interpreter (stack-based VM, all standard opcodes, P2SH support)
- [x] Consensus parameters (block rewards, difficulty, network configs)
- [x] Block storage (RocksDB with column families, batch writes, iterators)
- [x] Block & transaction validation (txid/wtxid, sigops, sighash, PoW, merkle root)
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
  crypto.lua     - Hash functions and secp256k1 bindings (OpenSSL + libsecp256k1)
  address.lua    - Address encoding (Base58Check, Bech32/Bech32m)
  script.lua     - Bitcoin Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
  consensus.lua  - Consensus parameters, difficulty, network configs
  storage.lua    - RocksDB storage layer (blocks, headers, UTXO, chain state)
  validation.lua - Block & transaction validation (PoW, merkle root, sighash)
spec/
  *_spec.lua     - Test files
lib/
  libsecp256k1   - ECDSA/Schnorr library
```

## Running tests

```bash
# Requires: luajit, busted, rocksdb, openssl
LD_LIBRARY_PATH=./lib busted spec/
```
