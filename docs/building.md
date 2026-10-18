# Building lunarblock

lunarblock is Lua source run by LuaJIT, so "building" means installing the runtime and
libraries, and compiling three optional C helpers.

## Requirements

| What | Why | Debian 13 package |
|---|---|---|
| LuaJIT 2.1 | runs the node | `luajit`, `libluajit-5.1-dev` (headers for the C helpers) |
| LuaSocket 3.x | TCP for P2P, RPC, REST | `lua-socket` |
| lua-cjson 2.1 | JSON-RPC encoding | `lua-cjson` |
| OpenSSL (libcrypto) | SHA-256, RIPEMD-160, AES for wallet encryption | `libssl-dev` |
| libsecp256k1 | ECDSA and Schnorr signatures | `libsecp256k1-dev` |
| RocksDB (C API) | blocks, chain state, UTXO set, indexes | `librocksdb-dev` |
| C compiler, make | the helpers in `csrc/` | `build-essential` |

The three libraries are loaded at run time through LuaJIT's FFI by their unversioned
names (`libcrypto.so`, `libsecp256k1.so`, `librocksdb.so`). Debian ships those names only
in the `-dev` packages, so install the `-dev` packages even if you never run `make build`.

Optional:

| What | Enables | Debian 13 package |
|---|---|---|
| libzmq | `--zmqpub*` notifications (without it the node prints a warning and publishes nothing) | `libzmq3-dev` |
| LuaSec | RPC over TLS (`--rpc-tls-cert`, `--rpc-tls-key`) | `lua-sec` |
| busted | the test suite | see [Test tools](#test-tools) |

On Debian 13 (trixie):

```bash
sudo apt-get install -y build-essential git luajit libluajit-5.1-dev lua-socket lua-cjson libssl-dev libsecp256k1-dev librocksdb-dev
sudo apt-get install -y libzmq3-dev lua-sec   # optional
```

## Build

```bash
git clone https://github.com/hashhog/lunarblock.git
cd lunarblock
make build
LD_LIBRARY_PATH=./lib luajit src/main.lua --version
```

`make build` writes three shared libraries into `lib/` (ignored by git):

| Library | Source | Effect |
|---|---|---|
| `lib/sha256_accel.so` | `csrc/sha256_accel.c` | SHA-256 with SHA-NI or AVX2 when the CPU has them (checked at run time) |
| `lib/parallel_verify.so` | `csrc/parallel_verify.c` | script checks on worker threads (`--par`) |
| `lib/coin_prefetch.so` | `csrc/coin_prefetch.c` | parallel UTXO reads from RocksDB when connecting a block |

Each one is optional; without it the node falls back to a slower pure-Lua or serial path.
At startup the node prints which SHA-256 path it uses, for example
`SHA-256: hardware-accelerated (sha_ni)` or `SHA-256: GENERIC (no acceleration)`.

Always start the node with `LD_LIBRARY_PATH=./lib` from the repository root, so the
helpers are found and `require("lunarblock.<module>")` resolves through the shims in
`lunarblock/`.

## LuaRocks

`lunarblock-scm-1.rockspec` lists the Lua dependencies. To install them with LuaRocks
instead of apt (LuaSec is listed but only needed for TLS):

```bash
luarocks --local --lua-version=5.1 install --only-deps lunarblock-scm-1.rockspec
```

## Test tools

The test suite runs under [busted](https://lunarmodules.github.io/busted/) 2.x. Install it
for Lua 5.1 (LuaJIT's language level) into your user tree:

```bash
sudo apt-get install -y lua5.1 luarocks
luarocks --local --lua-version=5.1 install busted
export PATH="$HOME/.luarocks/bin:$PATH"
make test
```

`make test` points busted at `~/.luarocks`; set `LUAROCKS_TREE=<dir>` if you installed it
elsewhere. Run the suite through `make test` rather than calling `busted` directly: busted's
own modules are not on LuaJIT's default search path, so a bare `busted` stops with
`module 'busted.runner' not found` unless `LUA_PATH` and `LUA_CPATH` are set the way the
`Makefile` sets them.

## Reproducible builds

There are no release binaries. What runs is the Lua source at a git commit plus the
three helpers compiled from `csrc/` by your C compiler, so pin a commit and record your
LuaJIT and library versions (`luajit -v`, `dpkg -l librocksdb-dev libsecp256k1-dev`).

## Docker

The `Dockerfile` and `docker-compose.yml` in this repository are not maintained and
are not known to work; build from source as above.
