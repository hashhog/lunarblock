-- Test IsFinalTx consensus rule (Core ContextualCheckBlock parity)
-- Reference: Bitcoin Core validation.cpp:4146

-- Set up package path for running from repo root
package.path = "./src/?.lua;" .. package.path
package.cpath = "./lib/?.so;" .. package.cpath

local mining = require("lunarblock.mining")
local types = require("lunarblock.types")

local SEQUENCE_FINAL = 0xFFFFFFFF

local function make_tx(locktime, sequences)
  local inputs = {}
  for _, seq in ipairs(sequences) do
    table.insert(inputs, { sequence = seq, prev_out = { hash = string.rep("\0", 32), index = 0 } })
  end
  return {
    version = 1,
    locktime = locktime,
    inputs = inputs,
    outputs = {},
  }
end

local pass = 0
local fail = 0

local function check(name, cond)
  if cond then
    print("PASS: " .. name)
    pass = pass + 1
  else
    print("FAIL: " .. name)
    fail = fail + 1
  end
end

-- 1. locktime=0 → always final
check("zero locktime always final",
  mining.is_final_tx(make_tx(0, {0}), 1000, 900000001))

-- 2. height-based locktime satisfied (locktime < height)
check("height-based satisfied",
  mining.is_final_tx(make_tx(100, {0}), 101, 900000001))

-- 3. height-based locktime NOT satisfied, non-SEQUENCE_FINAL → non-final
check("height-based not satisfied with non-final seq",
  not mining.is_final_tx(make_tx(200, {1}), 100, 900000001))

-- 4. SEQUENCE_FINAL on all inputs → final even if locktime unsatisfied
check("sequence_final overrides locktime",
  mining.is_final_tx(make_tx(999999999, {SEQUENCE_FINAL}), 100, 900000001))

-- 5. Mixed inputs: one non-SEQUENCE_FINAL, locktime unsatisfied → non-final
check("mixed inputs: one non-final seq → non-final",
  not mining.is_final_tx(make_tx(500, {SEQUENCE_FINAL, 0}), 100, 900000001))

-- 6. time-based locktime satisfied (locktime >= 500M, locktime < block_mtp)
check("time-based satisfied",
  mining.is_final_tx(make_tx(500000001, {0}), 100, 500000002))

-- 7. time-based NOT satisfied → non-final if sequence not FINAL
check("time-based not satisfied with non-final seq",
  not mining.is_final_tx(make_tx(500000002, {0}), 100, 500000001))

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  os.exit(1)
end
