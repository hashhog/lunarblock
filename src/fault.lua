-- System faults: a resource failure is never a consensus decision.
--
-- Bitcoin Core keeps two disjoint channels.  A block or transaction that
-- breaks a rule gets a BlockValidationState / TxValidationState verdict.  A
-- failure of the node itself (disk full, I/O error, allocation failure, a
-- script-check worker that did not run) goes to FatalError -> AbortNode
-- (validation.cpp, node/abort.cpp): the block is NOT marked invalid, no peer
-- is punished, the node stops connecting and exits non-zero, and the coins
-- cache is not flushed over the failure.
--
-- lunarblock reports both kinds as Lua errors (strings), so this module gives
-- the system kind a tag that survives every tostring/concat/re-raise on the
-- way to a classifier, plus the process-wide latch (AbortNode).
--
--   fault.raise(msg)            raise a tagged system fault
--   fault.is_system_fault(err)  true for a tagged fault or a LuaJIT
--                               allocation failure ("not enough memory")
--   fault.script_raise_handler  xpcall handler for the script interpreter:
--                               classifies a raise as SCRIPT_ERROR (an
--                               explicit error()/assert() in the consensus
--                               modules) or INTERNAL (everything else)
--   fault.latch(reason)         AbortNode: sets the process-wide latch, logs,
--                               and asks main.lua to shut down with exit 1
--   fault.note_block_fault(key) retry-once bookkeeping: the second system
--                               fault on the same block latches
--
-- Test hooks (fault.hooks) are nil in production: fault.hook() is a single
-- table read that returns nil.

local M = {}

M.TAG = "[SYSTEM-FAULT] "

local latched = false
local latch_reason = nil
local latch_listeners = {}
local block_faults = {}

-- Test-only injection points.  nil in production.
M.hooks = nil

--- Run test hook `name` if one is installed.
function M.hook(name, ...)
  local h = M.hooks
  if h == nil then return nil end
  local f = h[name]
  if f == nil then return nil end
  return f(...)
end

--- Raise a tagged system fault.  Never returns.
function M.raise(msg)
  local s = tostring(msg)
  if s:find(M.TAG, 1, true) then
    error(s, 0)
  end
  error(M.TAG .. s, 0)
end

--- Is `err` a system fault (not a verdict on any block or transaction)?
-- Allow-list: the tag, or LuaJIT's LUA_ERRMEM message.  LUA_ERRMEM bypasses
-- xpcall handlers and arrives as exactly "not enough memory"; once wrapped
-- by a caller it is a substring.
function M.is_system_fault(err)
  if err == nil then return false end
  local s = type(err) == "string" and err or tostring(err)
  if s:find(M.TAG, 1, true) then return true end
  if s:find("not enough memory", 1, true) then return true end
  return false
end

-- Modules whose explicit error()/assert() raises ARE consensus failures
-- (script.lua's EvalScript tokens, validation.lua's checker / witness /
-- taproot asserts).  An explicit raise anywhere else on the script path
-- (crypto.lua's "expected string", serialize.lua's reader) is a bug in the
-- node, not a property of the script.
local CONSENSUS_SOURCES = {
  "script.lua",
  "validation.lua",
}

local function is_consensus_source(src)
  if type(src) ~= "string" then return false end
  for i = 1, #CONSENSUS_SOURCES do
    local name = CONSENSUS_SOURCES[i]
    if src:sub(-#name) == name then
      -- Reject e.g. "fault_validation.lua": require a path separator or the
      -- start of the chunk name before the module name.
      local prev = src:sub(-#name - 1, -#name - 1)
      if prev == "/" or prev == "@" or prev == "" then
        return true
      end
    end
  end
  return false
end
M._is_consensus_source = is_consensus_source

--- xpcall message handler for one script check.
-- Returns a table {internal = bool, msg = string}.
--   * tagged fault / allocation failure          -> internal
--   * error()/assert() called from script.lua or
--     validation.lua                             -> script error (verdict)
--   * anything else: a VM runtime error ("attempt to index a nil value"),
--     a library argument error, an explicit raise from a non-consensus
--     module                                      -> internal
-- Core's model: the interpreter returns a ScriptError for every malformed
-- input; an exception out of it is a node bug, never a verdict.
function M.script_raise_handler(e)
  if M.is_system_fault(e) then
    return { internal = true, msg = tostring(e) }
  end
  local raiser = debug.getinfo(2, "f")
  local f = raiser and raiser.func
  if f == error or f == assert then
    local caller = debug.getinfo(3, "S")
    if caller and is_consensus_source(caller.source) then
      return { internal = false, msg = tostring(e) }
    end
    return { internal = true,
             msg = "non-consensus raise in script check: " .. tostring(e) }
  end
  return { internal = true,
           msg = "runtime error in script check: " .. tostring(e) }
end

--- Classify the second return of xpcall(f, script_raise_handler).
-- @return internal (bool), message (string)
function M.classify_script_raise(r)
  if type(r) == "table" and r.msg ~= nil then
    return r.internal and true or false, r.msg
  end
  -- The handler did not run (LUA_ERRMEM, or an error inside the handler):
  -- never a verdict.
  return true, "script check aborted: " .. tostring(r)
end

--------------------------------------------------------------------------------
-- The latch (Core AbortNode)
--------------------------------------------------------------------------------

function M.is_latched()
  return latched
end

function M.reason()
  return latch_reason
end

--- Register a function called once when the latch is set (main.lua: stop the
-- main loop; the shutdown path then skips the chainstate flush and exits 1).
function M.on_latch(fn)
  latch_listeners[#latch_listeners + 1] = fn
  if latched then pcall(fn, latch_reason) end
end

--- Set the process-wide fatal latch.  Idempotent.
function M.latch(reason)
  if latched then return end
  latched = true
  latch_reason = tostring(reason)
  io.stderr:write("[FATAL] (AbortNode) A fatal internal error occurred: "
    .. latch_reason .. " -- no block or transaction was judged by this "
    .. "failure; stopping without flushing the chainstate, exit 1\n")
  print("[FATAL] (AbortNode) A fatal internal error occurred: " .. latch_reason)
  io.stderr:write(debug.traceback("[FATAL] latched at", 2) .. "\n")
  for i = 1, #latch_listeners do
    pcall(latch_listeners[i], latch_reason)
  end
end

--- Raise if the latch is set (entry points: connect, submitblock, mempool).
function M.check_latch(what)
  if latched then
    M.raise("node halted after a fatal internal error (" .. tostring(latch_reason)
      .. ")" .. (what and ("; refusing " .. what) or ""))
  end
end

--- Retry-once bookkeeping for system faults while connecting a block.
-- The first fault on `key` is recorded (the caller drops its partial state
-- and the block is retried); a second fault on the same key latches.
-- @return true if this call latched
function M.note_block_fault(key, err)
  key = tostring(key)
  local n = (block_faults[key] or 0) + 1
  block_faults[key] = n
  if n >= 2 then
    M.latch(string.format("system fault connecting block %s twice: %s",
      key, tostring(err)))
    return true
  end
  return false
end

function M.clear_block_fault(key)
  block_faults[tostring(key)] = nil
end

--- Test-only: reset all state.
function M._reset_for_tests()
  latched = false
  latch_reason = nil
  latch_listeners = {}
  block_faults = {}
  M.hooks = nil
end

return M
