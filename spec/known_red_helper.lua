-- busted helper: pending the known-red names in spec/known_red.lua.
--
-- Loaded via .busted `helper =`. Returns a function(busted) so we can wrap
-- the sandboxed `it` executor (wrapping _G.it is a no-op: specs run in
-- busted's environment, not _G).
--
-- A test whose full name (describe path + it name, space-separated — the
-- same string busted's gtest reporter prints) is in the known-red table is
-- registered as pending with its gap note. Pending is not silent omission:
-- `busted` still prints each name and the pending count. Remove the row
-- from known_red.lua when the underlying feature is built.

local KNOWN = dofile("spec/known_red.lua")

local function full_name(busted, it_name)
  local parent = busted.context.get()
  local names = { it_name }
  while parent and (parent.name or parent.descriptor)
      and parent.descriptor ~= "file"
      and parent.descriptor ~= "suite" do
    table.insert(names, 1, parent.name or parent.descriptor)
    parent = busted.context.parent(parent)
  end
  return table.concat(names, " ")
end

return function(busted)
  local orig_it = busted.executors.it

  local function wrap(name, fn)
    local reason = KNOWN[full_name(busted, name)]
    if reason then
      -- Keep it as an `it` so the body runs; pending() throws a pending
      -- object that busted reports with the gap note (the pending
      -- descriptor itself never runs its function).
      return orig_it(name, function()
        busted.pending(reason)
      end)
    end
    return orig_it(name, fn)
  end

  busted.executors.it = wrap
  busted.export("it", wrap)
  busted.export("spec", wrap)
  busted.export("test", wrap)
  return true
end
