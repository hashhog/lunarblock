#!/usr/bin/env luajit
-- getpeerinfo RPC parity — last_inv_sequence / inv_to_send / no startingheight
--
-- Ported from rustoshi 077eb2f (add last_inv_sequence + inv_to_send) and
-- 528045a (remove startingheight).  Core src/rpc/net.cpp getpeerinfo:
--   * emits NUM `last_inv_sequence` and NUM `inv_to_send` immediately after
--     `relaytxes` (net.cpp:243-244);
--   * v31.99 NO LONGER emits `startingheight` (the legacy m_starting_height
--     was removed from the RPC output — it lives only inside net_processing's
--     version handling, never surfaced via entryToJSON).
--
-- lunarblock does not track per-peer mempool inv sequence / queued-inv counts
-- at the manager layer, so it emits 0 for both — the same convention rustoshi
-- and Core (addr_processed/addr_rate_limited when untracked) use.
--
-- This is a pure RPC response-shape test (getpeerinfo); it touches NO block,
-- script, or connect-block validation path.

package.path = "src/?.lua;" .. package.path

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

local rpc = require("lunarblock.rpc")

local tests_passed = 0
local tests_failed = 0

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    io.write("PASS: " .. name .. "\n")
    tests_passed = tests_passed + 1
  else
    io.write("FAIL: " .. name .. "\n")
    io.write("      " .. tostring(err) .. "\n")
    tests_failed = tests_failed + 1
  end
end

local function expect_eq(a, b, msg)
  if a ~= b then
    error((msg or "mismatch") .. ": got " .. tostring(a) .. ", expected " .. tostring(b))
  end
end

local function expect_nil(v, msg)
  if v ~= nil then error((msg or "expected nil") .. ": got " .. tostring(v)) end
end

-- Build an RPC server with a single mock peer and invoke getpeerinfo.
local function get_first_peer()
  local mock_pm = { peer_list = { {
    ip = "1.2.3.4", port = 8333, services = 9,
    version_info = { relay = true, version = 70016, timestamp = 0 },
    last_send = 100, last_recv = 200, bytes_sent = 5, bytes_recv = 6,
    conn_time = 50, latency_ms = 10, user_agent = "/lunarblock/",
    start_height = 800000, inbound = false,
  } } }
  local server = rpc.new({ peer_manager = mock_pm })
  local result = server.methods["getpeerinfo"](server, {})
  if type(result) ~= "table" or result[1] == nil then
    error("getpeerinfo returned no peer entry")
  end
  return result[1]
end

-- G1: last_inv_sequence is present and numeric (0 when untracked).
test("getpeerinfo emits numeric last_inv_sequence", function()
  local p = get_first_peer()
  expect_eq(type(p.last_inv_sequence), "number",
    "last_inv_sequence must be a number (Core net.cpp:243)")
  expect_eq(p.last_inv_sequence, 0, "last_inv_sequence value (untracked => 0)")
end)

-- G2: inv_to_send is present and numeric (0 when untracked).
test("getpeerinfo emits numeric inv_to_send", function()
  local p = get_first_peer()
  expect_eq(type(p.inv_to_send), "number",
    "inv_to_send must be a number (Core net.cpp:244)")
  expect_eq(p.inv_to_send, 0, "inv_to_send value (untracked => 0)")
end)

-- G3: startingheight must be ABSENT (removed in Core v31.99 / rustoshi 528045a).
test("getpeerinfo does NOT emit startingheight", function()
  local p = get_first_peer()
  expect_nil(p.startingheight,
    "startingheight must be absent — removed from getpeerinfo in Core v31.99")
end)

io.write("\n")
io.write(string.format("Total: %d passed, %d failed\n", tests_passed, tests_failed))
os.exit(tests_failed == 0 and 0 or 1)
