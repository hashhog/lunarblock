-- Fixed-seed last-resort fallback (Bitcoin Core net.cpp:2606-2645).
--
-- Verifies the curated IPv4:8333 fixed-seed list and the
-- PeerManager:maybe_add_fixed_seeds() predicate:
--   * mainnet carries exactly 40 routable IPv4:8333 fixed seeds
--   * non-mainnet (testnet/regtest) carries none
--   * the fallback FIRES on an empty book once the predicate is satisfied
--     (DNS disabled => immediate; otherwise after the 60s grace window)
--   * the fallback does NOT fire when the book is non-empty
--   * the fallback does NOT fire under --connect pin mode (max_outbound == 0)
--   * the one-shot guard makes subsequent ticks no-ops
local peerman = require("lunarblock.peerman")
local p2p = require("lunarblock.p2p")
local consensus = require("lunarblock.consensus")

describe("fixed-seed fallback", function()

  -- A mainnet-shaped network table carrying the curated fixed_seeds list,
  -- but with EMPTY dns_seeds so discover_from_dns() is a no-op in the loop.
  local function mainnet_network()
    return {
      name = "mainnet",
      magic_bytes = "\xf9\xbe\xb4\xd9",
      port = 8333,
      default_port = 8333,
      dns_seeds = {},
      fixed_seeds = consensus.networks.mainnet.fixed_seeds,
    }
  end

  describe("seed list", function()

    it("mainnet carries exactly 40 fixed seeds", function()
      assert.is_table(consensus.networks.mainnet.fixed_seeds)
      assert.equals(40, #consensus.networks.mainnet.fixed_seeds)
    end)

    it("every fixed seed is a routable IPv4:8333 entry", function()
      for _, entry in ipairs(consensus.networks.mainnet.fixed_seeds) do
        local ip, port = entry:match("^(%d+%.%d+%.%d+%.%d+):(%d+)$")
        assert.is_truthy(ip, "not dotted-quad ip:port: " .. tostring(entry))
        assert.equals("8333", port, "wrong port for " .. tostring(entry))
        assert.is_true(peerman.is_routable(ip),
          "non-routable fixed seed: " .. tostring(entry))
      end
    end)

    it("non-mainnet chains carry no fixed seeds", function()
      assert.is_nil(consensus.networks.testnet.fixed_seeds)
      assert.is_nil(consensus.networks.testnet4.fixed_seeds)
      assert.is_nil(consensus.networks.regtest.fixed_seeds)
    end)
  end)

  describe("add_fixed_seeds", function()

    it("injects all 40 routable seeds into the book", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      pm.known_addresses = {}  -- start from an empty book
      local added = pm:add_fixed_seeds()
      assert.equals(40, added)
      assert.equals(40, pm:get_known_address_count())
      -- spot-check a couple of entries parsed correctly
      assert.is_not_nil(pm.known_addresses["2.121.116.198:8333"])
      assert.is_not_nil(pm.known_addresses["77.38.72.37:8333"])
      assert.equals(8333, pm.known_addresses["2.121.116.198:8333"].port)
    end)
  end)

  describe("maybe_add_fixed_seeds predicate", function()

    it("FIRES on empty book with DNS disabled (immediate)", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      pm.known_addresses = {}
      -- Simulate DNS-disabled (proxy_dns) — discover_from_dns would return 0.
      pm.proxy_config = { proxy_dns = true }
      -- _start_ts is "now", so the 60s grace has NOT elapsed; only the
      -- DNS-disabled immediate-fire branch can trip here.
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(40, added)
      assert.is_true(pm._fixed_seeds_added)
      assert.equals(40, pm:get_known_address_count())
    end)

    it("FIRES on empty book after the 60s grace window", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      pm.known_addresses = {}
      pm.proxy_config = nil       -- DNS enabled, so no immediate fire
      pm._start_ts = os.time() - 61 -- backdate so > 60s has elapsed
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(40, added)
      assert.is_true(pm._fixed_seeds_added)
    end)

    it("does NOT fire within the 60s grace window when DNS is enabled", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      pm.known_addresses = {}
      pm.proxy_config = nil
      pm._start_ts = os.time()  -- 0s elapsed
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(0, added)
      assert.is_falsy(pm._fixed_seeds_added)
      assert.equals(0, pm:get_known_address_count())
    end)

    it("does NOT fire when the book is non-empty", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      -- Non-empty book: a peer was already learned (e.g. from DNS/addnode).
      pm.known_addresses = {}
      pm:add_known_address("8.8.8.8", 8333, p2p.SERVICES.NODE_NETWORK)
      pm.proxy_config = { proxy_dns = true }  -- DNS disabled, would otherwise fire
      pm._start_ts = os.time() - 120          -- well past the grace window
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(0, added)
      assert.is_falsy(pm._fixed_seeds_added)
      -- book unchanged (still just the one learned addr)
      assert.equals(1, pm:get_known_address_count())
    end)

    it("does NOT fire under --connect pin mode (max_outbound == 0)", function()
      local pm = peerman.new(mainnet_network(), nil, { max_outbound = 0 })
      pm.known_addresses = {}
      pm.proxy_config = { proxy_dns = true }
      pm._start_ts = os.time() - 120
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(0, added)
      assert.is_falsy(pm._fixed_seeds_added)
    end)

    it("does NOT fire when the network carries no fixed seeds", function()
      local net = mainnet_network()
      net.fixed_seeds = nil  -- e.g. testnet/regtest
      local pm = peerman.new(net, nil, nil)
      pm.known_addresses = {}
      pm.proxy_config = { proxy_dns = true }
      pm._start_ts = os.time() - 120
      local added = pm:maybe_add_fixed_seeds()
      assert.equals(0, added)
      assert.is_falsy(pm._fixed_seeds_added)
    end)

    it("is one-shot: subsequent ticks are no-ops after firing", function()
      local pm = peerman.new(mainnet_network(), nil, nil)
      pm.known_addresses = {}
      pm.proxy_config = { proxy_dns = true }
      local first = pm:maybe_add_fixed_seeds()
      assert.equals(40, first)
      -- Even with an empty book again, the guard blocks a second injection.
      pm.known_addresses = {}
      local second = pm:maybe_add_fixed_seeds()
      assert.equals(0, second)
    end)
  end)
end)
