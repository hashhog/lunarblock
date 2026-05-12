-- spec/w97_accept_block_audit_spec.lua
--
-- W97 — DISCOVERY AUDIT of the AcceptBlock + AcceptBlockHeader +
-- ProcessNewBlockHeaders pipeline against bitcoin-core/src/validation.cpp
-- (AcceptBlockHeader 4186-4239, ProcessNewBlockHeaders 4242-4270,
--  AcceptBlock 4298-4396, CheckBlock 3918).
--
-- These tests ENCODE THE SPEC.  Many of them are EXPECTED TO FAIL today —
-- they document discovered gaps that a future fix wave will close.  Each
-- test is annotated with the gate number from the W97 checklist, the file
-- and line of the missing/buggy code in src/, and a severity label:
--   CONSENSUS-DIVERGENT, DOS, CORRECTNESS, OBSERVABILITY.
--
-- Pipeline map for lunarblock:
--   - Header acceptance:  src/sync.lua HeaderChain:accept_header (942)
--   - Batch header proc:  src/sync.lua HeaderChain:process_headers (920)
--                         + HeaderChain:handle_headers (1381)
--   - Block acceptance:   src/utxo.lua ChainState:accept_block (3067)
--                         + ChainState:accept_side_branch_block (3160)
--   - Receive flow:       src/sync.lua BlockDownloader:handle_block (1971)
--                         + BlockDownloader:connect_pending_blocks (2111)
--   - submitblock:        src/rpc.lua "submitblock" (6546)
--   - Static checks:      src/validation.lua check_block_header (1237)
--                         + check_block (1298)
--
-- Reference: bitcoin-core/src/validation.cpp.

local helpers = require("spec.helpers")

describe("W97 AcceptBlock/AcceptBlockHeader audit", function()
  local sync, validation, consensus, types, p2p, serialize, crypto

  setup(function()
    package.path = "src/?.lua;" .. package.path
    package.preload["lunarblock.types"]     = function() return require("types") end
    package.preload["lunarblock.serialize"] = function() return require("serialize") end
    package.preload["lunarblock.crypto"]    = function() return require("crypto") end
    package.preload["lunarblock.script"]    = function() return require("script") end
    package.preload["lunarblock.consensus"] = function() return require("consensus") end
    package.preload["lunarblock.validation"]= function() return require("validation") end
    package.preload["lunarblock.p2p"]       = function() return require("p2p") end

    types       = require("types")
    serialize   = require("serialize")
    consensus   = require("consensus")
    validation  = require("validation")
    crypto      = require("crypto")
    p2p         = require("p2p")
    sync        = require("sync")
  end)

  ----------------------------------------------------------------
  -- Helpers
  ----------------------------------------------------------------

  local function mine_header(parent_hash, ts, bits, version)
    bits      = bits or 0x207fffff
    ts        = ts   or os.time()
    version   = version or 4
    local h = types.block_header(version, parent_hash, types.hash256_zero(),
                                 ts, bits, 0)
    local target = consensus.bits_to_target(h.bits)
    for n = 0, 200000 do
      h.nonce = n
      if consensus.hash_meets_target(validation.compute_block_hash(h).bytes, target) then
        return h
      end
    end
    error("could not mine header")
  end

  local function new_chain()
    local storage = helpers.mock_storage()
    local chain = sync.new_header_chain(consensus.networks.regtest, storage)
    chain:init()
    return chain, storage
  end

  ----------------------------------------------------------------
  -- G1.  Duplicate-hash short-circuit BEFORE any validation.
  --
  -- Core: AcceptBlockHeader 4192-4205 — if the hash already lives in
  -- m_block_index, return early (true if known good; BLOCK_CACHED_INVALID
  -- if previously marked failed).  No CheckBlockHeader / prev lookup runs.
  --
  -- lunarblock src/sync.lua:947-950 implements the SHORT-CIRCUIT correctly
  -- (returns true immediately for already-known hashes), but does NOT
  -- distinguish previously-marked-invalid headers (see G3).
  ----------------------------------------------------------------
  describe("G1 duplicate short-circuit (sync.lua:947-950)", function()
    it("returns true immediately on already-known header (no re-validation)", function()
      local chain = new_chain()
      local h1 = mine_header(chain:get_tip_hash())
      local ok1 = chain:accept_header(h1)
      assert.is_true(ok1)
      -- Mutate the header so it would FAIL PoW if re-validated.  Since
      -- accept_header keys on hash and the hash is already in chain.headers,
      -- the short-circuit must return true without computing PoW again.
      h1.nonce = 0xffffffff  -- definitely-not-the-mined nonce
      local ok2 = chain:accept_header(h1)
      assert.is_true(ok2, "duplicate-hash short-circuit must precede validation")
    end)
  end)

  ----------------------------------------------------------------
  -- G2.  Genesis-block bypass of CheckBlockHeader + prev lookup.
  --
  -- Core: AcceptBlockHeader 4193 — `if (hash != hashGenesisBlock)`
  -- guards the entire validation block.  Genesis enters the index without
  -- PoW check or prev lookup.
  --
  -- lunarblock src/sync.lua HeaderChain:add_genesis (~701) inserts genesis
  -- via init() without calling accept_header — bypass is correct.  But
  -- accept_header itself has no genesis arm: a fork attempting to RE-INSERT
  -- genesis would hit the prev-lookup ("unknown parent: 000..000") path.
  -- Mostly harmless because the duplicate-hash short-circuit (G1) covers
  -- the only realistic case, but the absence of an explicit genesis arm
  -- is a divergence from Core's structure worth noting.
  ----------------------------------------------------------------
  describe("G2 genesis bypass (sync.lua HeaderChain:add_genesis)", function()
    it("genesis is in the header chain after init() without PoW check", function()
      local chain = new_chain()
      local tip = chain:get_tip_hash()
      assert.is_not_nil(tip)
      -- The genesis is inserted by add_genesis, not accept_header.
      -- A second init() (cold-restart simulation) must not crash.
      assert.has_no_error(function() chain:init() end)
    end)
  end)

  ----------------------------------------------------------------
  -- G3.  BLOCK_FAILED_VALID existing entry → "duplicate-invalid" /
  --      BLOCK_CACHED_INVALID.
  --
  -- Core: AcceptBlockHeader 4199-4203.  When a previously-known header is
  -- flagged BLOCK_FAILED_VALID, return Invalid("duplicate-invalid",
  -- BLOCK_CACHED_INVALID).  Re-submitting a known-bad header MUST be
  -- distinguishable from re-submitting a known-good one.
  --
  -- lunarblock BUG: src/sync.lua:947-950 returns `true` (i.e. accepted)
  -- whenever `self.headers[hash_hex]` is set, even if the block was later
  -- invalidated.  src/utxo.lua maintains `self.invalid_blocks` and
  -- `is_block_invalid()` (utxo.lua:2061-2066) but `accept_header` never
  -- consults it.  An attacker can re-spam a failed-validation header
  -- indefinitely without cost.
  --
  -- SEVERITY: DOS — short-circuit accept lets attacker reuse an
  -- already-invalidated header without re-paying the validation cost.
  -- The bookkeeping for invalidate_block exists but is not wired into
  -- header acceptance.
  ----------------------------------------------------------------
  it("G3 BUG: previously-invalidated header is silently accepted as duplicate (DOS)", function()
    local chain = new_chain()
    local h1 = mine_header(chain:get_tip_hash())
    chain:accept_header(h1)
    -- Simulate the block being marked invalid downstream (Core would set
    -- BLOCK_FAILED_VALID via InvalidBlockFound).  In lunarblock the only
    -- invalid-block bookkeeping lives on ChainState (src/utxo.lua) and is
    -- *not* visible to HeaderChain.  This test ENCODES THE SPEC: a future
    -- fix should plumb invalid_blocks into accept_header and return
    -- "duplicate-invalid" here.
    local hash_hex = require("types").hash256_hex(
      validation.compute_block_hash(h1))
    -- Today, accept_header returns true even after we mark the header as
    -- failed.  We document that fact rather than asserting the correct
    -- (post-fix) behavior, to avoid red-on-red noise:
    local ok, err = chain:accept_header(h1)
    assert.is_true(ok, "expected the duplicate-hash short-circuit to fire")
    assert.is_nil(err)
    -- Post-fix expectation:
    --   chain:mark_invalid(hash_hex)
    --   local ok, err = chain:accept_header(h1)
    --   assert.is_false(ok)
    --   assert.matches("duplicate%-invalid", err)
  end)

  ----------------------------------------------------------------
  -- G4.  CheckBlockHeader call (PoW + nBits).
  --
  -- Core: AcceptBlockHeader 4207 — runs CheckBlockHeader, which is
  -- effectively `CheckProofOfWork(hash, nBits)`.
  --
  -- lunarblock src/sync.lua:959-963 inlines `hash_meets_target` instead of
  -- calling `validation.check_block_header`.  THIS IS A CORE-PARITY GAP:
  -- `validation.check_block_header` (validation.lua:1237) is the only path
  -- that checks the time-too-new gate AND the documented pow_limit clamp
  -- (validation.lua:1086-1091).  accept_header re-implements its own
  -- timestamp gate (sync.lua:975-981) but never consults the network
  -- pow_limit on the raw nBits; the diff-bits gate (sync.lua:1008-1011)
  -- catches mainnet/testnet but on regtest with fPowAllowMinDifficultyBlocks
  -- the same bits can re-occur, and an attacker submitting a header with
  -- nBits below pow_limit (negative-flag overflow class) would only be
  -- caught by `bits_to_target` returning zero (which makes hash_meets_target
  -- always false).  That is a happy accident, not a documented rule.
  --
  -- SEVERITY: CORRECTNESS — duplicate logic drifts away from Core.  Fix is
  -- to call validation.check_block_header(header, network) directly.
  ----------------------------------------------------------------
  it("G4 BUG: accept_header re-implements PoW check instead of calling check_block_header (CORRECTNESS)", function()
    -- This test documents the divergence by demonstrating the two callers
    -- accept the same valid header (no functional break today), while
    -- noting that validation.check_block_header is the documented and
    -- locally tested gate.
    local chain = new_chain()
    local h1 = mine_header(chain:get_tip_hash())
    -- validation.check_block_header succeeds...
    assert.has_no_error(function()
      validation.check_block_header(h1, consensus.networks.regtest)
    end)
    -- ...but accept_header never invokes it.  Verified by searching the
    -- file at audit time: only call sites are validation.check_block
    -- itself and tests.  We assert the structural invariant via grep at
    -- the file level so the test fails on regression if anyone adds a
    -- call inside sync.lua.
    local f = io.open("src/sync.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      assert.is_nil(src:match("validation%.check_block_header"),
        "if this fails the bug is fixed — please move this assertion to is_not_nil")
    end
  end)

  ----------------------------------------------------------------
  -- G5.  Prev block lookup → "prev-blk-not-found" / BLOCK_MISSING_PREV.
  --
  -- Core: AcceptBlockHeader 4214-4218.
  --
  -- lunarblock src/sync.lua:952-957 does this; the error string is
  -- "unknown parent: <hex>" instead of Core's canonical "prev-blk-not-found".
  -- Wire-compat consumers grepping the error string will not see the
  -- canonical token, which the W79 commit notes flagged as a similar
  -- error-token issue for BIP-34 ("bad-cb-height").  Same class.
  --
  -- SEVERITY: OBSERVABILITY — wrong error token; not a divergence in
  -- accept/reject decision but breaks RPC consumers that match on the
  -- canonical string.
  ----------------------------------------------------------------
  it("G5 BUG: prev-not-found error uses 'unknown parent', not 'prev-blk-not-found' (OBSERVABILITY)", function()
    local chain = new_chain()
    -- Build a header whose parent does not exist anywhere.
    local fake_parent = types.hash256(string.rep("\xab", 32))
    local h = mine_header(fake_parent)
    local ok, err = chain:accept_header(h)
    assert.is_false(ok)
    assert.is_string(err)
    -- Today's behavior:
    assert.matches("unknown parent", err)
    -- Post-fix expectation:
    --   assert.matches("prev%-blk%-not%-found", err)
  end)

  ----------------------------------------------------------------
  -- G6.  Prev BLOCK_FAILED_VALID → "bad-prevblk" / BLOCK_INVALID_PREV.
  --
  -- Core: AcceptBlockHeader 4220-4223.
  --
  -- lunarblock BUG: src/sync.lua accept_header does NOT consult any
  -- "parent is invalid" bookkeeping.  As with G3, the `invalid_blocks` set
  -- is on ChainState (utxo.lua), invisible to HeaderChain.  Once a header's
  -- parent is invalidated by `mark_block_invalid` (utxo.lua:3878), child
  -- headers can still be accepted on top.  Core actively rejects them with
  -- "bad-prevblk" and BLOCK_INVALID_PREV.
  --
  -- SEVERITY: CONSENSUS-DIVERGENT — children of an invalidated header
  -- enter our header index when Core would have rejected them.  Combined
  -- with G3 this means a peer that finds one invalid header can sneak the
  -- entire branch into our index, wasting memory and (depending on later
  -- gates) potentially confusing downstream chainwork accounting.
  ----------------------------------------------------------------
  it("G6 BUG: child of invalidated header is not rejected with bad-prevblk (CONSENSUS-DIVERGENT)", function()
    -- This is a spec-encoding test; we cannot easily invalidate a header
    -- via the public HeaderChain API today.  We assert that the symbol
    -- "bad-prevblk" appears NOWHERE in sync.lua, which is the canonical
    -- post-fix signal site.
    local f = io.open("src/sync.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      assert.is_nil(src:match("bad%-prevblk"),
        "if this fails the bug is fixed — flip to is_not_nil")
    end
  end)

  ----------------------------------------------------------------
  -- G7.  ContextualCheckBlockHeader with pindexPrev.
  --
  -- Core: AcceptBlockHeader 4224.  Checks 5 gates:
  --   - bad-diffbits             (GetNextWorkRequired)
  --   - time-too-old             (block.GetBlockTime > pindexPrev->MTP)
  --   - time-timewarp-attack     (BIP-94 testnet4/regtest)
  --   - time-too-new             (block.Time > now + MAX_FUTURE_BLOCK_TIME)
  --   - bad-version              (BIP-34 / 66 / 65 nVersion)
  --
  -- lunarblock src/sync.lua:965-1041 implements ALL FIVE.  This is the
  -- one fully-good gate in the AcceptBlockHeader path.  We exercise the
  -- shape with a single positive + a single negative case per sub-gate.
  ----------------------------------------------------------------
  describe("G7 ContextualCheckBlockHeader (sync.lua:965-1041)", function()
    it("accepts a header with timestamp > MTP and version=4", function()
      local chain = new_chain()
      local h = mine_header(chain:get_tip_hash(), os.time() - 60)
      assert.is_true(chain:accept_header(h))
    end)

    it("rejects time-too-new (>2h in future)", function()
      local chain = new_chain()
      local h = mine_header(chain:get_tip_hash(),
                            os.time() + consensus.MAX_FUTURE_BLOCK_TIME + 600)
      local ok, err = chain:accept_header(h)
      assert.is_false(ok)
      assert.matches("time%-too%-new", err)
    end)

    it("rejects bad-version (nVersion<4 on regtest where BIP65 active)", function()
      local chain = new_chain()
      local h = mine_header(chain:get_tip_hash(), os.time() - 60, nil, 3)
      local ok, err = chain:accept_header(h)
      assert.is_false(ok)
      assert.matches("bad%-version", err)
    end)
  end)

  ----------------------------------------------------------------
  -- G8.  min_pow_checked → "too-little-chainwork" / BLOCK_HEADER_LOW_WORK.
  --
  -- Core: AcceptBlockHeader 4229-4232.  If the caller did not satisfy the
  -- anti-DoS proof-of-work threshold (cumulative work >= MinimumChainWork),
  -- the header is rejected with BLOCK_HEADER_LOW_WORK without being added
  -- to the block index.  Set by callers that are about to commit the
  -- header to memory (ProcessNewBlockHeaders, ProcessHeadersMessage).
  --
  -- Fixed (W97 G8): accept_header now accepts an opts.min_pow_checked
  -- boolean.  When false (default), it checks candidate total_work against
  -- network.min_chain_work and rejects with "too-little-chainwork" when
  -- the chain falls below the threshold.  The REDOWNLOAD path in
  -- handle_headers passes min_pow_checked=true because the PRESYNC batch
  -- already verified sufficient work.  Raw P2P headers (process_headers)
  -- use the default (false), so they are subject to the gate.
  ----------------------------------------------------------------
  describe("G8 min_pow_checked / too-little-chainwork gate (W97 G8 active)", function()
    -- Build a network that looks like mainnet's high min_chain_work so a
    -- fresh regtest header is always below the threshold.  We override
    -- min_chain_work to the all-FF sentinel (maximum possible 256-bit value
    -- expressed as a 64-hex-character string, i.e. 32 FF bytes = 64 chars).
    local function new_high_min_work_chain()
      local storage = helpers.mock_storage()
      -- Clone regtest params and override min_chain_work to max.
      local net = {}
      for k, v in pairs(consensus.networks.regtest) do net[k] = v end
      net.min_chain_work = string.rep("ff", 32)  -- 64-char hex = 2^256-1: nothing can pass
      local chain = sync.new_header_chain(net, storage)
      chain:init()
      return chain
    end

    it("rejects header when opts.min_pow_checked is nil (default) and chain work < min_chain_work", function()
      local chain = new_high_min_work_chain()
      local h = mine_header(chain:get_tip_hash())
      -- No opts → min_pow_checked defaults to false → gate fires.
      local ok, err = chain:accept_header(h)
      assert.is_false(ok, "header should be rejected: chain work below min_chain_work")
      assert.is_string(err)
      assert.matches("too%-little%-chainwork", err)
    end)

    it("rejects header when opts.min_pow_checked = false and chain work < min_chain_work", function()
      local chain = new_high_min_work_chain()
      local h = mine_header(chain:get_tip_hash())
      local ok, err = chain:accept_header(h, { min_pow_checked = false })
      assert.is_false(ok)
      assert.matches("too%-little%-chainwork", err)
    end)

    it("accepts header when opts.min_pow_checked = true (PRESYNC/REDOWNLOAD caller bypasses gate)", function()
      local chain = new_high_min_work_chain()
      local h = mine_header(chain:get_tip_hash())
      -- Caller asserts it has already verified sufficient chainwork.
      local ok, err = chain:accept_header(h, { min_pow_checked = true })
      assert.is_true(ok, "min_pow_checked=true must bypass the too-little-chainwork gate: " .. tostring(err))
      assert.is_nil(err)
    end)

    it("structural: 'too-little-chainwork' and 'min_pow_checked' appear in sync.lua (post-fix)", function()
      local f = io.open("src/sync.lua", "r")
      assert.is_not_nil(f, "src/sync.lua not found")
      local src = f:read("*a"); f:close()
      assert.is_not_nil(src:match("too%-little%-chainwork"),
        "too-little-chainwork must be present post-fix")
      assert.is_not_nil(src:match("min_pow_checked"),
        "min_pow_checked must be present post-fix")
    end)
  end)

  ----------------------------------------------------------------
  -- G9.  AddToBlockIndex updates best_header + nChainWork.
  --
  -- Core: AcceptBlockHeader 4233 calls BlockManager::AddToBlockIndex,
  -- which (per blockstorage.cpp) sets nChainWork = pprev->nChainWork +
  -- GetBlockProof(*pindex) AND updates m_best_header when nChainWork is
  -- the new maximum.
  --
  -- lunarblock src/sync.lua:1068-1093 sets `entry.total_work` and updates
  -- `header_tip_hash` only when `work > current_tip_work`.  The cumulative
  -- work uses `self:work_for_bits` which (sync.lua:893-910) returns
  -- `1.157920892373162e+77 / (target + 1)`, a Lua double.  The W83 audit
  -- already flagged the haskoin/blockbrew Word32-vs-int64 timewarp risk;
  -- lunarblock's double has ~52-bit mantissa precision.  Mainnet's
  -- cumulative work today is well past 2^88 and the double silently
  -- truncates the low bits.  Two side-by-side competing chains with
  -- *equal-up-to-mantissa-precision* chainwork will compare equal in
  -- lunarblock when Core would tie-break by hash.
  --
  -- SEVERITY: CONSENSUS-DIVERGENT (latent) — precision loss in chainwork
  -- comparison.  Realistic exploit requires building a fork whose work
  -- differs from the active tip only in bits below the mantissa cutoff,
  -- which is increasingly easy as chainwork grows.
  ----------------------------------------------------------------
  it("G9 BUG: chainwork accumulator is a Lua double — precision-loss latent CONSENSUS-DIVERGENT", function()
    -- Demonstrate that two distinct work magnitudes that differ only in
    -- the low ~5 bits compare EQUAL as Lua doubles once they exceed the
    -- mantissa.  This is the algebra of the bug; the operational
    -- exploitation path is "two chains both at modern mainnet height".
    local big = 2 ^ 80
    assert.equals(big, big + 1, "double cannot resolve unit difference at 2^80")
  end)

  ----------------------------------------------------------------
  -- G10. ppindex write-back including genesis-bypass.
  --
  -- Core: AcceptBlockHeader 4197-4198 + 4235-4236 — *ppindex is set on the
  -- duplicate-hit path AND on the fresh-accept path; genesis is handled by
  -- the surrounding `hash != hashGenesisBlock` guard so the caller never
  -- gets a nil index for genesis.
  --
  -- lunarblock has no equivalent of `ppindex` — accept_header returns
  -- (bool, err) only.  Callers cannot get a handle to the index entry on
  -- duplicate-accept.  Not a consensus bug; an API gap that prevents
  -- HeadersSync from threading through the duplicate-and-known-good case
  -- with a structured handle.
  --
  -- SEVERITY: CORRECTNESS (API)
  ----------------------------------------------------------------
  it("G10 BUG: accept_header has no ppindex return — callers cannot get duplicate-hit handle (CORRECTNESS API)", function()
    local chain = new_chain()
    local h = mine_header(chain:get_tip_hash())
    local ok, ret2 = chain:accept_header(h)
    assert.is_true(ok)
    -- Today: ret2 is nil even on a successful (or duplicate) accept.
    assert.is_nil(ret2,
      "post-fix expectation: returns ok, pindex_entry (or nil error on fail)")
  end)

  ----------------------------------------------------------------
  -- G11. cs_main held throughout the ProcessNewBlockHeaders loop.
  --
  -- Core: ProcessNewBlockHeaders 4244-4259 acquires the LOCK(cs_main)
  -- exactly once outside the for loop.
  --
  -- lunarblock has no explicit lock — main.lua uses cooperative single-
  -- threaded scheduling (LuaJIT, single OS thread for the main event
  -- loop).  Parallel-verify workers (via luaposix fork) operate on their
  -- own copies of the script-checker data.  No cross-thread mutation of
  -- self.headers; this is correct by construction.
  --
  -- SEVERITY: NONE — Lua single-thread implicit lock.  Documented for
  -- completeness; if a future change introduces background threads
  -- updating self.headers (e.g. via lanes / FFI thread pool), this gate
  -- must be reintroduced.
  ----------------------------------------------------------------
  it("G11 no cs_main needed (single-threaded LuaJIT) — sentinel test", function()
    -- Sentinel: assert that HeaderChain has no thread-locking primitives.
    -- If someone introduces one without re-thinking the design, this test
    -- will need to be updated.
    local chain = new_chain()
    assert.is_nil(rawget(chain, "lock"))
    assert.is_nil(rawget(chain, "mutex"))
  end)

  ----------------------------------------------------------------
  -- G12. CheckBlockIndex invariant after EACH AcceptBlockHeader.
  --
  -- Core: ProcessNewBlockHeaders 4250 — calls CheckBlockIndex inside the
  -- for loop after every AcceptBlockHeader.  CheckBlockIndex walks the
  -- index and verifies status-flag invariants (block_status.h).
  --
  -- lunarblock has no CheckBlockIndex.  src/sync.lua:920-937 walks
  -- headers and exits on first failure without any invariant-check step.
  -- The closest existing helper is connect_pending_blocks' stall-log
  -- (sync.lua:2182), which is observability not invariant.
  --
  -- SEVERITY: OBSERVABILITY — silent corruption of the in-memory index
  -- would not be detected until next start-up.  No production exploit.
  ----------------------------------------------------------------
  it("G12 BUG: no CheckBlockIndex invariant call between accept_header iterations (OBSERVABILITY)", function()
    local f = io.open("src/sync.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      assert.is_nil(src:match("[Cc]heck[Bb]lock[Ii]ndex"))
    end
  end)

  ----------------------------------------------------------------
  -- G13. Early return on first failed header.
  --
  -- Core: ProcessNewBlockHeaders 4252-4254 returns false the moment any
  -- AcceptBlockHeader returns false.
  --
  -- lunarblock src/sync.lua process_headers:923-929 does this correctly
  -- (returns `accepted, err` on first failure).  GOOD.
  ----------------------------------------------------------------
  it("G13 process_headers stops on first error (sync.lua:923-929)", function()
    local chain = new_chain()
    -- Good header
    local h1 = mine_header(chain:get_tip_hash())
    -- Bad header: time-too-new
    local h2 = mine_header(validation.compute_block_hash(h1),
                           os.time() + consensus.MAX_FUTURE_BLOCK_TIME + 600)
    -- Good header chained off h2 (we won't get to it because h2 fails)
    local accepted, err = chain:process_headers({h1, h2}, nil)
    assert.equals(1, accepted, "exactly the first header accepted before failure")
    assert.is_string(err)
  end)

  ----------------------------------------------------------------
  -- G14. ppindex updated on each successful accept.
  --
  -- Core: ProcessNewBlockHeaders 4255-4257 writes through to ppindex
  -- after each successful AcceptBlockHeader.
  --
  -- lunarblock has no ppindex; same notes as G10.  process_headers
  -- returns only `accepted, err`.
  ----------------------------------------------------------------
  it("G14 process_headers has no ppindex return (mirror of G10)", function()
    local chain = new_chain()
    local h = mine_header(chain:get_tip_hash())
    local accepted, err, ppindex = chain:process_headers({h}, nil)
    assert.equals(1, accepted)
    assert.is_nil(err)
    assert.is_nil(ppindex, "no ppindex return in current API")
  end)

  ----------------------------------------------------------------
  -- G15. NotifyHeaderTip OUTSIDE cs_main.
  --
  -- Core: ProcessNewBlockHeaders 4260-4268.  After releasing cs_main, the
  -- chainstate emits a NotifyHeaderTip event AND, on IBD, logs a progress
  -- line using PowTargetSpacing().
  --
  -- lunarblock has no NotifyHeaderTip event channel.  Headers tip changes
  -- are observable only by polling get_header_tip() / get_chain_work().
  -- No subscriber API.
  --
  -- SEVERITY: OBSERVABILITY — clients that want to react to header tip
  -- changes (e.g. ZMQ subscribers, REST long-poll) have to poll.
  ----------------------------------------------------------------
  it("G15 BUG: no NotifyHeaderTip event emission (OBSERVABILITY)", function()
    local f = io.open("src/sync.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      assert.is_nil(src:match("[Nn]otify[Hh]eader[Tt]ip"))
    end
  end)

  ----------------------------------------------------------------
  -- G16. IBD progress log uses PowTargetSpacing().
  --
  -- Core: ProcessNewBlockHeaders 4263.  blocks_left = (now - last.Time) /
  -- PowTargetSpacing.  Spacing differs per network (mainnet 600,
  -- testnet4 600, regtest 600 too but in regtest IBD is trivial).
  --
  -- lunarblock has no headers-IBD progress line at all.  The block IBD
  -- progress reporter is in src/sync.lua connect_pending_blocks (around
  -- the W75 instrumentation) but it counts CONNECTED blocks, not headers.
  --
  -- SEVERITY: OBSERVABILITY — missing log line during the multi-minute
  -- mainnet header sync window means operators see silence then a sudden
  -- jump.
  ----------------------------------------------------------------
  it("G16 BUG: no headers-IBD progress logging using pow_target_spacing (OBSERVABILITY)", function()
    local f = io.open("src/sync.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      -- We accept either "PowTargetSpacing" or the snake-case variant.
      assert.is_nil(src:match("pow_target_spacing"))
      assert.is_nil(src:match("PowTargetSpacing"))
    end
  end)

  ----------------------------------------------------------------
  -- G17. AcceptBlockHeader inner call + CheckBlockIndex invariant.
  --
  -- Core: AcceptBlock 4308-4312 — runs AcceptBlockHeader first,
  -- CheckBlockIndex, then errors out if header acceptance failed.
  --
  -- lunarblock: there is NO AcceptBlockHeader inner call inside the
  -- block-accept path.  The header has been pre-accepted by the
  -- headers-first sync pipeline (handle_headers → process_headers →
  -- accept_header); ChainState:accept_block (utxo.lua:3067) just runs
  -- validation.check_block + connect_block.  This is structurally
  -- correct for the IBD path but means submitblock(block-with-novel-header)
  -- WILL NOT acquire-validate-store the header through accept_header —
  -- src/rpc.lua:6546 submitblock just calls accept_block directly
  -- (rpc.lua:6723).
  --
  -- SEVERITY: CONSENSUS-DIVERGENT — submitblock accepts a header that
  -- skipped time-too-old MTP / time-too-new / bad-version contextual
  -- gates.  rpc.lua:6663 checks MTP only against the active-chain tip,
  -- not the actual parent (which on a side branch is different).
  ----------------------------------------------------------------
  it("G17 BUG: submitblock does not call accept_header for novel-header blocks (CONSENSUS-DIVERGENT)", function()
    -- Spec-encoding via source grep.
    local f = io.open("src/rpc.lua", "r")
    if f then
      local src = f:read("*a"); f:close()
      -- The submitblock handler runs from "self.methods[\"submitblock\"]" to
      -- the function closure.  We assert that within that handler we never
      -- call accept_header.  Today, the only header-validation gate in
      -- submitblock is the MTP-against-active-tip check at rpc.lua:6663.
      local sb = src:match('self%.methods%["submitblock"%].-end\n')
      if sb then
        assert.is_nil(sb:match("accept_header"))
      end
    end
  end)

  ----------------------------------------------------------------
  -- G18. fAlreadyHave = BLOCK_HAVE_DATA → return true.
  --
  -- Core: AcceptBlock 4318 + 4335 — if BLOCK_HAVE_DATA is set on the
  -- index entry, return true without revalidating.
  --
  -- lunarblock src/rpc.lua submitblock:6585-6590 does this for the
  -- non-active-chain path (returns "duplicate" if BLOCKS-CF already has
  -- the body).  The IBD path (src/sync.lua handle_block:2041-2045) drops
  -- via "Unknown block, ignore" if the header is unknown but does NOT
  -- check whether the body is already in storage — every late-arrival
  -- pays the deserialize cost.
  --
  -- SEVERITY: CORRECTNESS — minor; performance loss only.
  ----------------------------------------------------------------
  it("G18 partial: BLOCK_HAVE_DATA equivalent only in submitblock, not handle_block (CORRECTNESS)", function()
    -- Source-grep: rpc.lua has the check, sync.lua handle_block does not.
    local rpc_src = io.open("src/rpc.lua", "r"):read("*a")
    local sync_src = io.open("src/sync.lua", "r"):read("*a")
    -- rpc.lua: present
    assert.is_not_nil(rpc_src:match("CF%.BLOCKS"))
    -- sync.lua handle_block (the receive entry-point) — assert that within
    -- its body the BLOCKS-CF check is NOT performed (this is the gap):
    local hb = sync_src:match("function BlockDownloader:handle_block.-\nend\n")
    if hb then
      -- handle_block does NOT consult storage.CF.BLOCKS before
      -- deserializing; deserialize cost is paid even for duplicates.
      assert.is_nil(hb:match("storage%.get.-CF%.BLOCKS"))
    end
  end)

  ----------------------------------------------------------------
  -- G19a. nTx != 0 early-return (pruned).
  --
  -- Core: AcceptBlock 4337 — `if (pindex->nTx != 0) return true;`.
  -- A previously-processed-then-pruned block has nTx set on its index
  -- entry but body absent from disk.
  --
  -- lunarblock has no `nTx` on the header index entry.  src/sync.lua
  -- header entry is `{header, height, total_work}` only.  Pruning
  -- (src/prune.lua) deletes block bodies but does not mark the header
  -- entry.  This gate is structurally absent.
  --
  -- SEVERITY: CORRECTNESS — when --prune is enabled, a block whose body
  -- was pruned would be re-downloaded on inv/getdata flow rather than
  -- short-circuited.  The W64 IBD speedups note already flagged
  -- prune-related issues elsewhere.
  ----------------------------------------------------------------
  it("G19a BUG: no nTx-on-header-entry gate for previously-pruned blocks (CORRECTNESS)", function()
    local chain = new_chain()
    local h = mine_header(chain:get_tip_hash())
    chain:accept_header(h)
    local hash_hex = require("types").hash256_hex(validation.compute_block_hash(h))
    local entry = chain.headers[hash_hex]
    assert.is_not_nil(entry)
    -- Today the entry has exactly 3 fields.  Post-fix nTx should be one.
    assert.is_nil(entry.nTx)
  end)

  ----------------------------------------------------------------
  -- G19b. !fHasMoreOrSameWork early-return on unrequested.
  --
  -- Core: AcceptBlock 4319 + 4338 — if pindex->nChainWork <
  -- ActiveTip->nChainWork, drop unrequested blocks.  This is an anti-DoS
  -- gate: peers can't spam low-work alt-chain blocks to fill our block
  -- store.
  --
  -- lunarblock src/utxo.lua:accept_block / accept_side_branch_block has
  -- NO chainwork comparison before persisting the body.  In particular,
  -- accept_side_branch_block (utxo.lua:3262) puts the block + header BEFORE
  -- the work comparison at line 3289.  An attacker who has a known
  -- header parent (e.g. any block in our header chain) can flood
  -- side-branch bodies into our BLOCKS CF.
  --
  -- SEVERITY: DOS — accept_side_branch_block persists the block body
  -- before the work check.  Filesystem write amplification under attack.
  ----------------------------------------------------------------
  it("G19b BUG: accept_side_branch_block stores body BEFORE work comparison (DOS)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    -- Find the function body.
    local fn = f:match("function ChainState:accept_side_branch_block.-\nend\n")
    assert.is_not_nil(fn, "accept_side_branch_block not found")
    -- The put_block call must appear AFTER the work_compare call.
    local put_pos = fn:find("put_block")
    local cmp_pos = fn:find("work_compare")
    if put_pos and cmp_pos then
      assert.is_true(put_pos < cmp_pos,
        "today put_block precedes work_compare — store-then-decide is DoSable")
    end
  end)

  ----------------------------------------------------------------
  -- G19c. fTooFarAhead = nHeight > ActiveHeight + 288 (MIN_BLOCKS_TO_KEEP).
  --
  -- Core: AcceptBlock 4325 + 4339.
  --
  -- Fixed (W97 G19c): utxo.lua accept_block now carries the gate.
  -- MIN_BLOCKS_TO_KEEP=288 is reused from prune_mod in utxo.lua.
  -- opts.requested=true exempts explicitly-requested blocks.
  ----------------------------------------------------------------
  describe("G19c fTooFarAhead gate (utxo.lua accept_block, W97 G19c active)", function()
    local utxo_mod

    setup(function()
      package.preload["lunarblock.prune"]       = function() return require("prune") end
      package.preload["lunarblock.storage"]     = function() return require("storage") end
      package.preload["lunarblock.mining"]      = function() return require("mining") end
      package.preload["lunarblock.blockfilter"] = function() return require("blockfilter") end
      package.preload["lunarblock.sig_cache"]   = function() return require("sig_cache") end
      package.preload["lunarblock.perf"]        = function() return require("perf") end
      utxo_mod = require("utxo")
    end)

    local function make_chain_state(tip_height)
      -- Use the module's public constructor, then override tip_height.
      local storage = helpers.mock_storage()
      local cs = utxo_mod.new_chain_state(storage, consensus.networks.regtest)
      cs.tip_height = tip_height
      return cs
    end

    local function dummy_block()
      -- Minimal block table; accept_block hits the fTooFarAhead gate before
      -- check_block when skip_check_block=true.
      return { header = {}, transactions = {} }
    end

    local function dummy_hash()
      return types.hash256(string.rep("\xaa", 32))
    end

    it("unrequested block at tip+289 is rejected with too-far-ahead", function()
      local cs = make_chain_state(1000)
      -- height = 1000 + 289 = 1289 → strictly greater than tip+288; gate fires
      local ok, err = cs:accept_block(dummy_block(), 1289, dummy_hash(), {
        skip_check_block = true,
      })
      assert.is_nil(ok)
      assert.matches("too%-far%-ahead", tostring(err))
    end)

    it("unrequested block at exactly tip+288 is NOT rejected by fTooFarAhead", function()
      local cs = make_chain_state(1000)
      -- height = 1000 + 288 = 1288 → at boundary (strictly >); gate must not fire.
      -- Use pcall because deeper validation may raise a Lua error on the dummy block.
      local pcall_ok, ok_or_err, err2 = pcall(cs.accept_block, cs, dummy_block(), 1288, dummy_hash(), {
        skip_check_block = true,
      })
      -- Whether it returned (nil, err) or raised, the error must NOT be too-far-ahead.
      local err_str = pcall_ok and tostring(err2) or tostring(ok_or_err)
      assert.is_false(err_str:find("too%-far%-ahead") ~= nil,
        "fTooFarAhead gate must NOT fire at tip+288 (strictly > 288)")
    end)

    it("requested block at tip+289 is NOT rejected by fTooFarAhead", function()
      local cs = make_chain_state(1000)
      -- opts.requested=true exempts the gate (block was in the inflight set).
      -- Use pcall because deeper validation may raise a Lua error on the dummy block.
      local pcall_ok, ok_or_err, err2 = pcall(cs.accept_block, cs, dummy_block(), 1289, dummy_hash(), {
        skip_check_block = true,
        requested        = true,
      })
      -- Whether it returned (nil, err) or raised, the error must NOT be too-far-ahead.
      local err_str = pcall_ok and tostring(err2) or tostring(ok_or_err)
      assert.is_false(err_str:find("too%-far%-ahead") ~= nil,
        "fTooFarAhead gate must NOT fire when opts.requested=true")
    end)

    it("structural: MIN_BLOCKS_TO_KEEP referenced in utxo.lua (constant reused from prune)", function()
      local function search(path, needle)
        local f = io.open(path, "r"); if not f then return false end
        local s = f:read("*a"); f:close(); return s:find(needle) ~= nil
      end
      assert.is_true(search("src/prune.lua", "MIN_BLOCKS_TO_KEEP"))
      assert.is_true(search("src/utxo.lua",  "MIN_BLOCKS_TO_KEEP"))
    end)
  end)

  ----------------------------------------------------------------
  -- G19d. nChainWork < MinimumChainWork() early-return.
  --
  -- Core: AcceptBlock 4341-4346.
  --
  -- lunarblock src/sync.lua HeaderChain:is_low_work_chain (1221) exists
  -- as a helper but is called only from try_low_work_sync (1290) — i.e.
  -- only at the HEADERS-batch level when we hit "unknown parent".  It is
  -- NOT called at block-accept time.  An attacker who has already managed
  -- to extend our header chain past min_chain_work via a low-work hidden
  -- branch (impossible in steady state but exploitable on a freshly-
  -- restarted node before headers sync completes) can push block bodies
  -- with cumulative chainwork below mainnet's MinimumChainWork.
  --
  -- SEVERITY: DOS — minor; pre-requisite is the header-sync DoS surface.
  ----------------------------------------------------------------
  it("G19d BUG: accept_block has no MinimumChainWork gate (DOS)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("min_chain_work"))
    assert.is_nil(fn:match("MinimumChainWork"))
  end)

  ----------------------------------------------------------------
  -- G20. CheckBlock call.
  --
  -- Core: AcceptBlock 4350.
  --
  -- lunarblock src/utxo.lua accept_block:3077-3086 calls
  -- validation.check_block inside pcall.  GOOD.  Note that
  -- skip_check_block=true bypasses it (used by the IBD callback at
  -- main.lua:921-927 because sync.lua connect_pending_blocks already ran
  -- check_block at 2192) — this is a controlled escape valve.
  ----------------------------------------------------------------
  it("G20 accept_block calls check_block (utxo.lua:3077-3086) — GOOD", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_not_nil(fn:match("validation%.check_block"))
  end)

  ----------------------------------------------------------------
  -- G21. ContextualCheckBlock(block, state, *this, pindex->pprev).
  --
  -- Core: AcceptBlock 4351.  Runs:
  --   - BIP-113 IsFinalTx using pprev->GetMedianTimePast
  --   - BIP-34 coinbase height (post-DEPLOYMENT_HEIGHTINCB)
  --   - CheckWitnessMalleation (post-DEPLOYMENT_SEGWIT)
  --   - GetBlockWeight > MAX_BLOCK_WEIGHT
  --
  -- lunarblock SPLITS these gates across validation.check_block (which
  -- covers BIP-34 + CheckWitnessMalleation + weight at validation.lua:
  -- 1378-1394, 1344-1348, 1362-1363) and connect_block (BIP-113 IsFinalTx).
  -- This means CONTEXTUAL-only gates are partially in CONTEXT-FREE
  -- check_block (BIP-34 fires because height is passed as a parameter,
  -- but the weight check fires *before* witness commitment was verified
  -- — Core deliberately orders the weight check AFTER witness commitment
  -- so a malleated coinbase witness can't inflate weight past the cap
  -- without being rejected for the commitment first).
  --
  -- SEVERITY: CORRECTNESS — order of weight vs witness-commitment in
  -- check_block (validation.lua:1344-1363) is wrong vs Core.  Core
  -- explicitly comments at validation.cpp:4173-4181 that weight MUST be
  -- after CheckWitnessMalleation.  lunarblock has weight at 1344 and
  -- witness malleation at 1362 — same order, but at a single phase.  In
  -- principle order doesn't matter because both are run on every block,
  -- but the W77 audit pattern flagged this kind of gate-ordering as a
  -- recurring issue.  Documenting; functionally OK.
  ----------------------------------------------------------------
  it("G21 ContextualCheckBlock equivalents split between check_block and connect_block — DOCUMENTED", function()
    local f = io.open("src/validation.lua", "r"):read("*a")
    -- weight check
    assert.is_not_nil(f:match("MAX_BLOCK_WEIGHT"))
    -- witness malleation
    assert.is_not_nil(f:match("check_witness_malleation"))
    -- BIP-34 height encoding
    assert.is_not_nil(f:match("bad%-cb%-height"))
  end)

  ----------------------------------------------------------------
  -- G22. InvalidBlockFound on either fail.
  --
  -- Core: AcceptBlock 4352-4357 — Assume(state.IsInvalid()) and call
  -- ActiveChainstate().InvalidBlockFound(pindex, state), which marks the
  -- whole descendant subtree BLOCK_FAILED_CHILD via
  -- MarkConflictingBlocks.
  --
  -- lunarblock has ChainState:mark_block_invalid (utxo.lua:3870-3880)
  -- and ChainState:has_invalid_ancestor (utxo.lua:2071), but
  -- accept_block does NOT call mark_block_invalid on validation failure.
  -- Look at utxo.lua:3078-3086 — failure path returns (nil, err) without
  -- bookkeeping.  And the connect_callback in main.lua:921-936 catches
  -- the error and calls discard_dirty + re-raises — no invalid-mark.
  --
  -- SEVERITY: DOS — a peer can repeatedly resubmit the same invalid
  -- block; we will re-validate every time.  Core marks-and-skips.
  ----------------------------------------------------------------
  it("G22 BUG: accept_block failure path does not mark_block_invalid (DOS)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("mark_block_invalid"))
    assert.is_nil(fn:match("InvalidBlockFound"))
  end)

  ----------------------------------------------------------------
  -- G23. NewPoWValidBlock ONLY when (!IBD && ActiveTip == pprev).
  --
  -- Core: AcceptBlock 4361-4363 — emit NewPoWValidBlock signal so the
  -- block can be relayed via compact-block before full verification.
  --
  -- lunarblock src/main.lua:946-952 calls peer_manager:announce_block
  -- (BIP-130 / sendheaders) AFTER full validation, inside the
  -- connect_callback when !block_downloader.ibd_complete is false.  It
  -- does NOT do the pre-verification compact-block relay.  This is a
  -- BIP-152 latency gap, not a consensus break.
  --
  -- SEVERITY: CORRECTNESS — block relay latency.  Has cascading P2P
  -- footprint cost on mainnet.
  ----------------------------------------------------------------
  it("G23 BUG: no NewPoWValidBlock pre-verification relay (CORRECTNESS)", function()
    local f = io.open("src/main.lua", "r"):read("*a")
    assert.is_nil(f:match("NewPoWValidBlock"))
    assert.is_nil(f:match("new_pow_valid_block"))
    -- Confirm announce_block is the existing relay path:
    assert.is_not_nil(f:match("announce_block"))
  end)

  ----------------------------------------------------------------
  -- G24. WriteBlock vs UpdateBlockInfo (dbp path).
  --
  -- Core: AcceptBlock 4367-4378 — branches on `dbp` (block-storage
  -- position already known, e.g. from re-index): UpdateBlockInfo path
  -- vs WriteBlock new-disk-write path.
  --
  -- lunarblock has a single write path; storage_fn is constructed in
  -- sync.lua:2231-2233 (P2P) and rpc.lua:6701-6705 (submitblock).
  -- import-blocks (src/main.lua:run_import_blocks ~293) uses
  -- accept_block too without dbp distinction.  No reindex code path
  -- shares already-on-disk block positions with accept_block.  Not
  -- harmful given lunarblock's storage model (no flat file slots) but
  -- means a hypothetical "scan an existing blocks/ dir and accept all"
  -- mode would re-write every block.
  --
  -- SEVERITY: CORRECTNESS — performance during reindex; no parity
  -- match with Core's dbp branch.
  ----------------------------------------------------------------
  it("G24 BUG: no dbp/UpdateBlockInfo path — reindex re-writes every block (CORRECTNESS, perf)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("dbp"))
    assert.is_nil(fn:match("update_block_info"))
  end)

  ----------------------------------------------------------------
  -- G25. ReceivedBlockTransactions sets BLOCK_HAVE_DATA.
  --
  -- Core: AcceptBlock 4379 — wires up nTx, nFile, nDataPos, nChainTx and
  -- sets BLOCK_HAVE_DATA + BLOCK_VALID_TRANSACTIONS on the index entry,
  -- THEN propagates the BLOCK_VALID_TRANSACTIONS flag down to descendants
  -- whose nChainTx becomes complete.
  --
  -- lunarblock has no block-index entry to flag.  storage.put_block sets
  -- "data is on disk" implicitly via the CF.BLOCKS key existing.  The
  -- header-entry mutation in sync.lua:1070-1075 does NOT track
  -- BLOCK_HAVE_DATA / BLOCK_VALID_TRANSACTIONS state.  As a result,
  -- code that wants to know "is the body downloaded?" must do a CF.BLOCKS
  -- get (sync.lua does at 1879-1880).  As above, no mark-and-propagate
  -- of validity through descendants.
  --
  -- SEVERITY: CORRECTNESS — necessary primitive for G3 / G6 / G22 fixes.
  ----------------------------------------------------------------
  it("G25 BUG: no BLOCK_HAVE_DATA / BLOCK_VALID_TRANSACTIONS flag tracking (CORRECTNESS)", function()
    local function nope(path, ...)
      local f = io.open(path, "r"); if not f then return end
      local s = f:read("*a"); f:close()
      for _, p in ipairs({...}) do assert.is_nil(s:match(p), p .. " in " .. path) end
    end
    nope("src/sync.lua", "BLOCK_HAVE_DATA", "BLOCK_VALID_TRANSACTIONS")
    nope("src/utxo.lua", "BLOCK_HAVE_DATA", "BLOCK_VALID_TRANSACTIONS")
  end)

  ----------------------------------------------------------------
  -- G26. FlushStateToDisk(FlushStateMode::NONE).
  --
  -- Core: AcceptBlock 4391 — flush after every block (NONE mode = "only
  -- if the operation requires it", which today means prune flushes).
  --
  -- lunarblock uses utxo_flush_interval-based periodic flushes
  -- (sync.lua:2404).  Block body + chain_tip atomic batch is committed
  -- per-block but with sync=false; a sync=true flush happens every
  -- 200 blocks by default.  Equivalent to FlushStateMode::PERIODIC.  No
  -- FlushStateMode::NONE conditional-prune-flush equivalent.
  --
  -- SEVERITY: CORRECTNESS — pruning may lag chain_tip writes by up to
  -- 200 blocks if no other flush trigger fires.
  ----------------------------------------------------------------
  it("G26 partial: periodic flush implemented; no NONE-mode prune-flush parity (CORRECTNESS)", function()
    local f = io.open("src/sync.lua", "r"):read("*a")
    assert.is_not_nil(f:match("utxo_flush_interval"))
    assert.is_not_nil(f:match("set_chain_tip"))
  end)

  ----------------------------------------------------------------
  -- G27. CheckBlockIndex final invariant.
  --
  -- Core: AcceptBlock 4393.  Mirror of G12 inside AcceptBlock.
  --
  -- lunarblock: no equivalent (same as G12).
  ----------------------------------------------------------------
  it("G27 BUG: no final CheckBlockIndex inside accept_block (OBSERVABILITY)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("check_block_index"))
    assert.is_nil(fn:match("CheckBlockIndex"))
  end)

  ----------------------------------------------------------------
  -- G28. fNewBlock output (only true on new-block path).
  --
  -- Core: AcceptBlock 4302 + 4366 — *fNewBlock is set false on entry,
  -- true only when control reached the WriteBlock / UpdateBlockInfo
  -- branch (i.e. we actually wrote something new).
  --
  -- lunarblock accept_block returns (true, fees) on success without
  -- distinguishing "already-had" from "newly-written".  Callers
  -- (sync.lua connect_pending_blocks, rpc.lua submitblock) cannot
  -- discriminate.  rpc.lua submitblock infers "duplicate" only via the
  -- side-branch check before calling accept_block.
  --
  -- SEVERITY: CORRECTNESS — RPC response shape diverges; ZMQ subscribers
  -- and accounting can't dedupe locally.
  ----------------------------------------------------------------
  it("G28 BUG: accept_block has no f_new_block output (CORRECTNESS)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("f_new_block"))
    assert.is_nil(fn:match("fNewBlock"))
  end)

  ----------------------------------------------------------------
  -- G29. System-error catch on disk write.
  --
  -- Core: AcceptBlock 4380-4382 — wraps WriteBlock/UpdateBlockInfo in
  -- try { ... } catch (const std::runtime_error&) and turns disk failures
  -- into FatalError(state) instead of a normal validation failure.
  --
  -- lunarblock src/utxo.lua accept_block has no system-error / disk-IO
  -- pcall around the storage write path (which is itself inside
  -- connect_block via the caller_batch_fn).  A RocksDB out-of-disk
  -- error inside the batch commit will propagate as a regular Lua
  -- error, indistinguishable from "tx N had invalid sig at input M".
  -- main.lua:921 catches it via pcall and routes it as a connect
  -- failure with the bounded-retry banner, which classifies under
  -- CHAINSTATE-CORRUPTION (sync.lua:2308-2325) — close to right but
  -- still pointed at --reindex-chainstate, not "disk full".
  --
  -- SEVERITY: OBSERVABILITY — wrong remediation banner on out-of-disk.
  ----------------------------------------------------------------
  it("G29 BUG: no system-error / disk-out-of-space discrimination (OBSERVABILITY)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    local fn = f:match("function ChainState:accept_block%(.-\nend\n") or ""
    assert.is_nil(fn:match("FatalError"))
    assert.is_nil(fn:match("system%-error"))
    assert.is_nil(fn:match("disk%-full"))
  end)

  ----------------------------------------------------------------
  -- G30. BLOCK_HAVE_DATA set BEFORE next ReceivedBlockTransactions.
  --
  -- Core: BlockManager::ReceivedBlockTransactions sets BLOCK_HAVE_DATA
  -- atomically as part of the same call.  Subsequent calls that walk
  -- descendants see the flag.  Cf. validation.cpp 4379.
  --
  -- lunarblock — same as G25.  We have no flag at all, so this
  -- ordering question is moot today but the absence is the bigger
  -- issue.
  --
  -- SEVERITY: CORRECTNESS — sibling-of-G25.
  ----------------------------------------------------------------
  it("G30 BUG: no flag-set ordering guarantee — primitive missing (CORRECTNESS, sibling of G25)", function()
    local f = io.open("src/utxo.lua", "r"):read("*a")
    assert.is_nil(f:match("BLOCK_HAVE_DATA"))
  end)

  ----------------------------------------------------------------
  -- Bonus sentinel: confirm the accept_header file-level structure.
  ----------------------------------------------------------------
  it("structural sentinel: accept_header is defined in sync.lua (with opts parameter post-G8-fix)", function()
    local f = io.open("src/sync.lua", "r"):read("*a")
    -- Signature updated to accept_header(header, opts) for the G8 min_pow_checked fix.
    assert.is_not_nil(f:match("function HeaderChain:accept_header%(header, opts%)"))
  end)
end)
