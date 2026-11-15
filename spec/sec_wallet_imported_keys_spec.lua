-- Security regression: importprivkey keys in an ENCRYPTED wallet.
--
-- Two defects, one cause (imported keys were never brought under the wallet's
-- encryption):
--   H3  an imported key was written to the wallet file as plaintext hex even
--       when the wallet was encrypted, so `cat wallet.json` leaked it;
--   H4  an encrypted wallet loaded LOCKED skipped its imported keys entirely,
--       so the next save() erased them from disk (1 -> 0).
--
-- Core (wallet/wallet.cpp, wallet/scriptpubkeyman.cpp): EncryptKeys encrypts
-- every private key under the master key, AddCryptedKey stores only the
-- ciphertext + pubkey, and a locked wallet loads its crypted keys and keeps
-- them in encrypted form until Unlock decrypts them.

local function setup_loader()
  local loaders = package.loaders or package.searchers
  table.insert(loaders, 2, function(module)
    local name = module:match("^lunarblock%.(.+)")
    if name then
      local filename = "src/" .. name .. ".lua"
      local f = io.open(filename)
      if f then
        f:close()
        return function() return dofile(filename) end
      end
    end
    return nil, "not found"
  end)
end

local SEED = ("a"):rep(32)
local PRIV = ("\x11"):rep(31) .. "\x07"   -- fixed, valid secp256k1 scalar
local PASS = "correct horse battery staple"

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, data)
  local f = assert(io.open(path, "wb"))
  f:write(data)
  f:close()
end

local function count(t)
  local n = 0
  for _ in pairs(t or {}) do n = n + 1 end
  return n
end

describe("encrypted wallet imported keys (H3+H4)", function()
  local wallet, consensus, address
  local tmpdir, wpath, priv_hex, wif

  setup(function()
    setup_loader()
    wallet = require("lunarblock.wallet")
    consensus = require("lunarblock.consensus")
    address = require("lunarblock.address")
    priv_hex = wallet.hex_encode(PRIV)
    wif = address.base58check_encode(consensus.networks.regtest.wif_prefix,
                                     PRIV .. "\x01")
  end)

  before_each(function()
    tmpdir = os.tmpname() .. "_sec_imported_keys"
    os.execute("rm -f " .. tmpdir .. "; mkdir -p " .. tmpdir)
    wpath = tmpdir .. "/wallet.json"
  end)

  after_each(function()
    if tmpdir then os.execute("rm -rf " .. tmpdir) end
  end)

  -- importprivkey, then encryptwallet, then save (the RPC order).
  local function encrypted_wallet_with_import()
    local w = wallet.from_seed(SEED, consensus.networks.regtest, nil)
    local addr = w:import_privkey(wif)
    w:encrypt(PASS)
    assert.is_true(w:save(wpath))
    return w, addr
  end

  it("writes no plaintext imported secret to an encrypted wallet file", function()
    encrypted_wallet_with_import()
    local raw = read_file(wpath)
    assert.is_not_nil(raw)
    assert.is_nil(raw:lower():find(priv_hex, 1, true),
      "imported private key found as plaintext hex in encrypted wallet file")
  end)

  it("keeps imported keys across a locked load + save, then unlocks them", function()
    local _, addr = encrypted_wallet_with_import()

    -- Load LOCKED (no passphrase) and save straight back.
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    assert.is_true(w2.is_locked)
    assert.is_true(w2:save(wpath))
    assert.is_nil(read_file(wpath):lower():find(priv_hex, 1, true))

    -- The in-memory locked wallet still knows the imported address ...
    assert.is_not_nil(w2.keys[addr], "imported key dropped on locked load")
    assert.is_nil(w2.keys[addr].privkey)
    -- ... and recovers the secret on unlock.
    assert.is_true(w2:unlock(PASS))
    assert.are.equal(PRIV, w2.keys[addr].privkey)

    -- A fresh load of the file written while locked still has the key.
    local w3 = assert(wallet.load(wpath, consensus.networks.regtest, nil, PASS))
    assert.are.equal(1, count(w3.imported_keys))
    assert.is_not_nil(w3.keys[addr], "imported key erased by locked save")
    assert.are.equal(PRIV, w3.keys[addr].privkey)
    assert.are.equal(wif, w3:dump_privkey(addr))
  end)

  it("imports into an already-encrypted unlocked wallet without plaintext", function()
    local w = wallet.from_seed(SEED, consensus.networks.regtest, nil)
    w:encrypt(PASS)
    local addr = w:import_privkey(wif)
    assert.is_true(w:save(wpath))
    assert.is_nil(read_file(wpath):lower():find(priv_hex, 1, true))
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil, PASS))
    assert.are.equal(PRIV, w2.keys[addr].privkey)
  end)

  it("refuses to import into a locked encrypted wallet", function()
    local w = wallet.from_seed(SEED, consensus.networks.regtest, nil)
    w:encrypt(PASS)
    w:lock()
    assert.has_error(function() w:import_privkey(wif) end)
  end)

  it("lock() drops the imported secret from memory; unlock() restores it", function()
    local w, addr = encrypted_wallet_with_import()
    w:lock()
    assert.is_nil(w.keys[addr].privkey)
    assert.is_nil(w.imported_keys[addr].privkey)
    assert.is_true(w:save(wpath))
    assert.is_true(w:unlock(PASS))
    assert.are.equal(PRIV, w.keys[addr].privkey)
  end)

  it("a wrong passphrase does not unlock and leaves imported keys sealed", function()
    local _, addr = encrypted_wallet_with_import()
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    assert.is_not_nil(w2.keys[addr], "imported key dropped on locked load")
    local ok = w2:unlock("wrong passphrase")
    assert.is_falsy(ok)
    assert.is_true(w2.is_locked)
    assert.is_nil(w2.keys[addr].privkey)
  end)

  it("a corrupt imported ciphertext fails unlock and leaves the wallet locked", function()
    local _, addr = encrypted_wallet_with_import()
    local cjson = require("cjson")
    local data = cjson.decode(read_file(wpath))
    local rec = data.imported_keys and data.imported_keys[addr]
    assert.is_not_nil(rec and rec.crypted_privkey, "no imported ciphertext on disk")
    -- Flip the first ciphertext byte.
    local first = tonumber(rec.crypted_privkey:sub(1, 2), 16)
    rec.crypted_privkey = string.format("%02x", (first + 1) % 256)
      .. rec.crypted_privkey:sub(3)
    write_file(wpath, cjson.encode(data))
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    local ok, err = w2:unlock(PASS)
    assert.is_falsy(ok)
    assert.are.equal("Imported key decryption failed", err)
    assert.is_true(w2.is_locked)
    assert.is_nil(w2.master_key)
  end)

  it("lists imported addresses after the HD addresses on load", function()
    local w, addr = encrypted_wallet_with_import()
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil, PASS))
    assert.are.equal(addr, w2.addresses[#w2.addresses])
    assert.are.equal(w.addresses[1], w2.addresses[1])
  end)

  it("re-encrypts imported keys under a changed passphrase", function()
    local w, addr = encrypted_wallet_with_import()
    assert.is_true(w:change_passphrase(PASS, "new pass"))
    assert.is_true(w:save(wpath))
    assert.is_nil(read_file(wpath):lower():find(priv_hex, 1, true))
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil, "new pass"))
    assert.are.equal(PRIV, w2.keys[addr].privkey)
  end)

  it("still loads an old-format encrypted file with plaintext imported keys", function()
    -- Old format: encrypted master key, imported_keys[addr].privkey = hex.
    local w, addr = encrypted_wallet_with_import()
    local cjson = require("cjson")
    local data = cjson.decode(read_file(wpath))
    data.imported_keys = {
      [addr] = { privkey = priv_hex, compressed = true,
                 type = w.imported_keys[addr].type },
    }
    write_file(wpath, cjson.encode(data))

    -- Locked load + save must not lose the key.
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    assert.is_not_nil(w2.keys[addr])
    assert.is_true(w2:save(wpath))
    -- Unlock upgrades it: the next save holds no plaintext.
    local w3 = assert(wallet.load(wpath, consensus.networks.regtest, nil, PASS))
    assert.are.equal(PRIV, w3.keys[addr].privkey)
    assert.is_true(w3:save(wpath))
    assert.is_nil(read_file(wpath):lower():find(priv_hex, 1, true))
    local w4 = assert(wallet.load(wpath, consensus.networks.regtest, nil, PASS))
    assert.are.equal(PRIV, w4.keys[addr].privkey)
  end)

  it("unencrypted wallets still round-trip imported keys", function()
    local w = wallet.from_seed(SEED, consensus.networks.regtest, nil)
    local addr = w:import_privkey(wif)
    assert.is_true(w:save(wpath))
    local w2 = assert(wallet.load(wpath, consensus.networks.regtest, nil))
    assert.are.equal(PRIV, w2.keys[addr].privkey)
  end)
end)
