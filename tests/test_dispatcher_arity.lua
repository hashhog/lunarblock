-- Dispatcher arity check — Core rpc/util.cpp:644 / IsValidNumArgs (:733).
--
-- Core validates argument COUNT centrally before any handler runs; a violation
-- is error -1. lunarblock's handle_single_request had no such check, so surplus
-- positional arguments were silently ignored. savemempool failed this in 10 of
-- 10 fleet implementations, clearbanned in 9 of 10.
--
-- Fails at the parent commit: without check_core_arity the surplus-argument
-- calls are dispatched and succeed.

-- Same bootstrap the other rpc tests use (see test_w125_error_parity.lua).
package.path = "src/?.lua;./?.lua;" .. package.path
local cjson = require("cjson")
local rpc = require("rpc")
local consensus_mod = require("lunarblock.consensus")

local passed, failed = 0, 0
-- On success lunarblock sets error = cjson.null (a userdata sentinel), NOT nil
-- -- Core's response shape. Comparing against nil would call every successful
-- call a failure, which is how the controls first tripped.
local function no_error(resp)
  return type(resp.error) ~= "table" or resp.error.code == nil
end

local function ok(cond, name)
  if cond then passed = passed + 1
  else failed = failed + 1; io.write("  FAIL: ", name, "\n") end
end

-- Load the same table the server loads, by the same means.
local f = io.open("src/core-arity.json", "r")
local arity = f and cjson.decode(f:read("*a")) or nil
if f then f:close() end

-- Guard: every assertion below is vacuous if the table did not load.
ok(arity ~= nil, "core-arity.json loads")
ok(arity and arity["savemempool"] ~= nil, "savemempool present in table")
ok(arity and arity["clearbanned"] ~= nil, "clearbanned present in table")

local n = 0
if arity then for _ in pairs(arity) do n = n + 1 end end
ok(n >= 80, "table has >= 80 methods (got " .. n .. ")")

-- Core's own signatures: both take zero arguments.
ok(arity and arity["savemempool"].declared == 0, "savemempool declares 0 args")
ok(arity and arity["clearbanned"].declared == 0, "clearbanned declares 0 args")

-- The server must reject a surplus argument. Exercised through the live
-- dispatcher so this tests the wiring, not a reimplementation of the rule.
-- rpc.new() is the public constructor (subsystems left nil are fine: these
-- probes never reach a handler that needs them).
local srv = rpc.new({ network = consensus_mod.networks.regtest })
srv.methods["savemempool"] = function() return true end
srv.methods["clearbanned"] = function() return true end
srv.methods["getblockhash"] = function() return "h" end

for _, m in ipairs({"savemempool", "clearbanned"}) do
  local resp = srv:handle_single_request({method = m, params = {"r5-probe-extra-arg"}, id = 1})
  ok(not no_error(resp) and resp.error.code == -1, m .. " surplus arg -> error -1")
end

-- CONTROL: correct calls must still work. Without this, a dispatcher that
-- rejected everything would pass the assertions above.
for _, m in ipairs({"savemempool", "clearbanned"}) do
  local resp = srv:handle_single_request({method = m, params = {}, id = 1})
  ok(no_error(resp), m .. " zero-arg call still accepted (control)")
end
local resp = srv:handle_single_request({method = "getblockhash", params = {100000}, id = 1})
ok(no_error(resp), "getblockhash with its 1 declared arg accepted (control)")

-- CONTROL: an unknown method must fail OPEN, not be treated as zero-arg.
srv.methods["not-in-the-table"] = function() return true end
resp = srv:handle_single_request({method = "not-in-the-table", params = {"a","b"}, id = 1})
ok(no_error(resp), "method absent from table is not arity-checked (control)")

io.write(string.format("\ndispatcher arity: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
