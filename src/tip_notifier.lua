--------------------------------------------------------------------------------
-- tip_notifier.lua — tip-change notification primitive for the wait-family RPCs
--------------------------------------------------------------------------------
--
-- Bitcoin Core registers a WaitTipChanged condition variable (kernel
-- Notifications / KernelNotifications::blockTip) that is signalled on every
-- active-chain tip update.  The waitfornewblock / waitforblock /
-- waitforblockheight RPCs (rpc/blockchain.cpp:290-471) block on it with a
-- deadline, re-checking their predicate (new tip / hash match / height >=)
-- after each wake and returning the current tip {hash, height} on match OR
-- timeout.
--
-- TipNotifier is the lunarblock analogue.  It mirrors the proven ouroboros
-- pilot (ouroboros/src/ouroboros/tip_notifier.py) but is adapted to
-- lunarblock's cooperative SINGLE-THREADED event-loop model (main.lua runs
-- one tick() per loop iteration; there is no asyncio scheduler, no threads).
--
-- Design notes
-- ------------
-- * The waiter's predicate is ALWAYS evaluated against the AUTHORITATIVE
--   chain tip (ChainState.tip_hash / .tip_height), never against state carried
--   inside this object.  The notifier only provides a prompt wake-up;
--   correctness does not depend on a notify ever firing for a specific tip
--   value.  This makes the primitive robust to coalesced / missed
--   notifications (e.g. two blocks connected back-to-back, or a reorg that
--   disconnects then connects, before a waiter re-checks): the waiter re-reads
--   the real tip after every wake and after the timeout, exactly like Core.
--
-- * A monotonically increasing `generation` counter lets a waiter detect a tip
--   change that happened *between* its predicate check and its next wait slice
--   (the classic lost-wakeup race).  A waiter captures the generation, checks
--   its predicate, then — if unsatisfied — pumps the event loop a slice and
--   re-reads the generation.  A notify that races in after the snapshot but
--   before the next slice merely bumps the generation, which the waiter
--   observes on its very next iteration, so it is NOT lost.
--
-- * There is no condition variable / asyncio.Event here.  In a single-threaded
--   cooperative loop the "wake" is implemented by the waiter PUMPING the node's
--   main-loop work (P2P tick, block-download scheduling, nested RPC accept) so
--   the tip can actually advance while the wait RPC is "blocked".  The
--   generation counter is what makes that pump-loop correct under races: the
--   waiter only sleeps when generation is unchanged AND the predicate is
--   unmet, and any notify() bumps the generation so the next check sees it.
--
-- notify() is wired at EVERY tip-advance chokepoint:
--   * block-connect during IBD and post-IBD, plus the submitblock / generate
--     accept path  -> ChainState.callbacks.on_block_connected
--   * BOTH halves of a reorg: the disconnect-to-fork half
--     (ChainState.callbacks.on_block_disconnected) AND the connect-new-branch
--     half (the reorg's per-block connect_block routes through
--     on_block_connected as well).
-- Missing a chokepoint = a waiter that wakes only at the timeout.

local M = {}

local TipNotifier = {}
TipNotifier.__index = TipNotifier

--- Construct a fresh notifier with generation 0.
function M.new()
  local self = setmetatable({}, TipNotifier)
  -- Monotonic counter bumped on every notify().  Waiters snapshot it before
  -- checking their predicate so a notify that races in between the check and
  -- the next wait slice is observed (no lost wakeup).  A plain Lua number is
  -- exact for integers well past any realistic block count.
  self._generation = 0
  return self
end

--- Current tip-change generation (bumped on every notify()).
-- @return number
function TipNotifier:generation()
  return self._generation
end

--- Signal that the active-chain tip advanced.
--
-- Bumps the generation counter.  Safe to call from any connect / reorg
-- chokepoint on the single-threaded event loop.  Intentionally trivial: in the
-- cooperative model there is nothing to "wake" synchronously — the wake is the
-- waiter's pump loop observing the bumped generation on its next slice.
function TipNotifier:notify()
  self._generation = self._generation + 1
end

return M
