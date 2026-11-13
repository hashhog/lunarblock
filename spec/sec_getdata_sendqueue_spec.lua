-- spec/sec_getdata_sendqueue_spec.lua
--
-- Security finding C3 (critical): one getdata froze the node for minutes.
--
-- A peer sent a 1.8 MB getdata (50,000 block items) and then stopped reading.
-- The node served the whole request inside one handler call, on the thread
-- that also runs the RPC server: every block was decoded and re-encoded even
-- after the peer had been dropped, and the outbound queue was a single string
-- that was copied in full on every append and every partial flush.  RPC calls
-- stalled for 207 s and 426.5 s.
--
-- Core (net_processing.cpp ProcessGetData) keeps the request in
-- m_getdata_requests, serves it a little per ProcessMessages pass, stops when
-- the send buffer is over its limit (pfrom.fPauseSend) and resumes on a later
-- pass; the send buffer is a deque of per-message buffers (net.cpp
-- PushMessage / vSendMsg).
--
-- The peers here are real loopback TCP connections.  `serve` is the per-item
-- body of main.lua's getdata handler (peerman.getdata_response + send).  On a
-- tree without Peer:queue_getdata the handler is the base commit's handler:
-- the same per-item body run in one synchronous loop with one `notfound` at
-- the end.

package.path = "src/?.lua;" .. package.path

local socket = require("socket")
local peer_module = require("lunarblock.peer")
local peerman = require("lunarblock.peerman")
local p2p = require("lunarblock.p2p")
local types = require("lunarblock.types")
local serialize = require("lunarblock.serialize")
local validation = require("lunarblock.validation")
local consensus = require("lunarblock.consensus")

local REGTEST = consensus.networks.regtest
local MAGIC = REGTEST.magic_bytes
local T = p2p.INV_TYPE

-- A block of roughly `size` bytes: one coinbase-shaped tx with a large output.
local function make_block(size, tag)
  local cb = types.transaction(1,
    { types.txin(types.outpoint(types.hash256(string.rep("\0", 32)), 0xFFFFFFFF),
                 "\1" .. string.char(tag)) },
    { types.txout(5000000000, string.rep("\106", size)) }, 0)
  local hdr = types.block_header(1, types.hash256(string.rep("\0", 32)),
    validation.compute_txid(cb), 1700000000 + tag, 0x207fffff, tag)
  return types.block(hdr, { cb })
end

local function block_hash(blk)
  return types.hash256(require("lunarblock.crypto").hash256(
    serialize.serialize_block_header(blk.header)))
end

-- Connected loopback pair: the node-side socket wrapped in an established
-- lunarblock Peer, and the remote end the test drives.
local listener
local function loopback_peer()
  if not listener then
    listener = assert(socket.bind("127.0.0.1", 0))
    listener:settimeout(5)
  end
  local _, port = listener:getsockname()
  local remote = assert(socket.tcp())
  remote:settimeout(5)
  assert(remote:connect("127.0.0.1", port))
  local conn = assert(listener:accept())
  conn:settimeout(0)
  remote:settimeout(0)
  local p = peer_module.new("127.0.0.1", port, REGTEST)
  p.socket = conn
  p.state = peer_module.STATE.ESTABLISHED
  p.version_received = true
  p.handshake_complete = true
  return p, remote
end

-- Non-blocking writer for the remote side: queue bytes, push a little per tick.
local function writer(remote)
  local w = { buf = "" }
  function w.queue(data) w.buf = w.buf .. data end
  function w.pump()
    if #w.buf == 0 then return end
    local sent, err, last = remote:send(w.buf)
    local n = sent or last or 0
    if n > 0 then w.buf = w.buf:sub(n + 1) end
  end
  return w
end

-- Remote-side reader: accumulate bytes and split into {command, payload}.
local function reader(remote)
  local r = { buf = "", msgs = {} }
  function r.pump()
    while true do
      local data, err, partial = remote:receive(1048576)
      data = data or partial
      if not data or #data == 0 then break end
      r.buf = r.buf .. data
    end
    while #r.buf >= 24 do
      local h = p2p.parse_header(r.buf:sub(1, 24))
      if #r.buf < 24 + h.length then break end
      r.msgs[#r.msgs + 1] = { command = h.command, payload = r.buf:sub(25, 24 + h.length) }
      r.buf = r.buf:sub(25 + h.length)
    end
  end
  return r
end

-- Bytes queued for the peer; on the base commit the queue was one string.
local function queued(p)
  if type(p.send_queue_size) == "function" then return p:send_queue_size() end
  return #(p.send_buffer or "")
end

local function pending(p)
  return type(p.getdata_pending) == "function" and p:getdata_pending() or false
end

local function getdata_msg(items)
  return p2p.make_message(MAGIC, "getdata", p2p.serialize_inv(items))
end

-- Per-item serving body of main.lua's getdata handler, with a counting
-- get_block that decodes the stored bytes the way storage's db.get_block does.
-- `hook(st, peer)` runs after each item; st.by_peer counts items per peer.
local function make_server(blocks, hook)
  local st = { calls = 0, by_peer = {} }
  local deps = {
    get_block = function(hash)
      st.calls = st.calls + 1
      local raw = blocks[hash.bytes]
      return raw and serialize.deserialize_block(raw) or nil
    end,
  }
  function st.serve(peer, item, not_found)
    local cmd, data, status = peerman.getdata_response(item, deps)
    if status == "served" then
      peer:send_message(cmd, data)
    elseif status == "notfound" then
      not_found[#not_found + 1] = item
    end
    st.by_peer[peer] = (st.by_peer[peer] or 0) + 1
    if hook then hook(st, peer) end
  end
  return st
end

local function make_handler(serve)
  local probe = peer_module.new("127.0.0.1", 1, REGTEST)
  if type(probe.queue_getdata) == "function" then
    return function(peer, payload)
      peer:queue_getdata(p2p.deserialize_inv(payload), serve)
    end
  end
  -- Base commit: main.lua's handler served every item in one call.
  return function(peer, payload)
    local not_found = {}
    for _, item in ipairs(p2p.deserialize_inv(payload)) do
      serve(peer, item, not_found)
    end
    if #not_found > 0 then
      peer:send_message("notfound", p2p.serialize_notfound(not_found))
    end
  end
end

-- One event-loop tick over the given peers (PeerManager:tick's per-peer part).
local function tick(peers)
  for _, p in ipairs(peers) do
    if p.state ~= peer_module.STATE.DISCONNECTED then
      p:process_messages()
      p:check_timeouts()
    end
  end
end

-- The base commit can spend many minutes inside one handler call; a watchdog
-- in get_block aborts it after WATCHDOG seconds so the spec finishes and the
-- assertion, not the clock, reports the failure.
local WATCHDOG = 3
local phase2 = false

describe("C3 getdata send-queue / event-loop stall", function()
  local BLK = make_block(20000, 1)
  local H = block_hash(BLK)
  local blocks = { [H.bytes] = serialize.serialize_block(BLK) }

  it("keeps every event-loop tick under 1 s (RPC latency) while a non-reading peer holds a 50,000-item getdata, and still serves peer B", function()
    local started
    local srv = make_server(blocks, function(st)
      started = started or socket.gettime()
      if socket.gettime() - started > WATCHDOG then
        error("watchdog: getdata serving ran past " .. WATCHDOG .. " s in one call")
      end
    end)
    local handler = make_handler(srv.serve)
    local a, a_remote = loopback_peer()
    local b, b_remote = loopback_peer()
    a:on("getdata", handler)
    b:on("getdata", handler)

    local items = {}
    for i = 1, p2p.MAX_INV_SIZE do items[i] = { type = T.MSG_WITNESS_BLOCK, hash = H } end
    local aw = writer(a_remote)      -- A writes its request and never reads
    aw.queue(getdata_msg(items))
    local bw, br = writer(b_remote), reader(b_remote)

    local max_tick, b_got_block, ticks_after = 0, false, 0
    local deadline = socket.gettime() + 20
    while socket.gettime() < deadline do
      aw.pump()
      -- B asks once the node has started serving A's request.
      if (srv.by_peer[a] or 0) > 0 and not bw.sent then
        bw.queue(getdata_msg({ { type = T.MSG_WITNESS_BLOCK, hash = H } }))
        bw.sent = true
      end
      bw.pump()
      local t0 = socket.gettime()
      tick({ a, b })
      -- The RPC server runs right after the P2P tick on the same thread, so a
      -- getblockcount issued at t0 is answered after this long.
      local rpc_latency = socket.gettime() - t0
      if rpc_latency > max_tick then max_tick = rpc_latency end
      br.pump()
      for _, m in ipairs(br.msgs) do
        if m.command == "block" then b_got_block = true end
      end
      if b_got_block then
        ticks_after = ticks_after + 1
        if ticks_after >= 10 then break end
      end
    end

    assert.is_true(max_tick < 1.0,
      string.format("an event-loop tick took %.2f s (RPC blocked that long)", max_tick))
    assert.is_true(b_got_block, "peer B was not served")
    -- A's request reached the node, and A is paused on its full send queue
    -- rather than served to completion.
    assert.is_true((srv.by_peer[a] or 0) > 0)
    assert.is_true(srv.by_peer[a] < p2p.MAX_INV_SIZE)
    a:disconnect("test done"); b:disconnect("test done")
    a_remote:close(); b_remote:close()
  end)

  it("stops serving a getdata once the requesting peer is disconnected", function()
    local started
    local srv = make_server(blocks, function(st, peer)
      started = started or socket.gettime()
      if st.calls == 10 then peer:disconnect("send failed: test") end
      if socket.gettime() - started > WATCHDOG then
        error("watchdog: getdata serving ran past " .. WATCHDOG .. " s in one call")
      end
    end)
    local a, a_remote = loopback_peer()
    a:on("getdata", make_handler(srv.serve))
    local items = {}
    for i = 1, p2p.MAX_INV_SIZE do items[i] = { type = T.MSG_WITNESS_BLOCK, hash = H } end
    local aw = writer(a_remote)
    aw.queue(getdata_msg(items))
    local deadline = socket.gettime() + 20
    while socket.gettime() < deadline and a.state ~= peer_module.STATE.DISCONNECTED do
      aw.pump()
      tick({ a })
    end
    for _ = 1, 5 do tick({ a }) end
    assert.equal(peer_module.STATE.DISCONNECTED, a.state)
    assert.equal(10, srv.calls)
    assert.is_falsy(a.getdata_queue)
    a_remote:close()
  end)

  it("keeps the send queue as a list of messages, so a non-draining peer costs linear time", function()
    -- A socket whose kernel buffer is full: accepts nothing until `cap` rises.
    -- send(data, i) follows luasocket: bytes from index i, returns the index
    -- of the last byte sent.
    local sock = { wire = {}, cap = 0 }
    function sock:send(data, i)
      i = i or 1
      local avail = #data - i + 1
      if self.cap == 0 then return nil, "timeout", i - 1 end
      if avail <= self.cap then
        self.wire[#self.wire + 1] = data:sub(i)
        return #data
      end
      self.wire[#self.wire + 1] = data:sub(i, i + self.cap - 1)
      return nil, "timeout", i + self.cap - 1
    end
    function sock:close() end
    local p = peer_module.new("127.0.0.1", 18444, REGTEST)
    p.socket = sock
    p.state = peer_module.STATE.ESTABLISHED

    local payload = string.rep("z", 30000)
    local n_msgs = 1000                       -- 30 MB, under MAX_SEND_BUFFER
    local t0 = socket.gettime()
    local accepted = 0
    for _ = 1, n_msgs do
      assert.is_true(p:send_message("block", payload))
      accepted = accepted + 1
      if socket.gettime() - t0 > 2 then break end   -- quadratic: give up
    end
    local elapsed = socket.gettime() - t0
    assert.equal(n_msgs, accepted)
    assert.is_true(elapsed < 1.0,
      string.format("queueing %d x 30 kB took %.2f s", accepted, elapsed))
    assert.equal("table", type(p.send_queue))
    local one = p2p.make_message(MAGIC, "block", payload)
    assert.equal(n_msgs * #one, queued(p))

    -- Drain in small slices: every byte arrives once, in order.
    sock.cap = 65536
    local guard = 0
    while queued(p) > 0 and guard < 100000 do
      p:check_timeouts()
      guard = guard + 1
    end
    assert.equal(0, queued(p))
    local wire = table.concat(sock.wire)
    assert.equal(n_msgs * #one, #wire)
    assert.equal(string.rep(one, n_msgs), wire)
  end)

  it("still answers a valid getdata with every requested block, in order, with notfound for the rest", function()
    local blk2 = make_block(3000, 2)
    local h2 = block_hash(blk2)
    local all = { [H.bytes] = serialize.serialize_block(BLK),
                  [h2.bytes] = serialize.serialize_block(blk2) }
    local missing = types.hash256(string.rep("\7", 32))
    local srv = make_server(all)
    local a, a_remote = loopback_peer()
    a:on("getdata", make_handler(srv.serve))

    local saved = peer_module.MAX_GETDATA_ITEMS_PER_TICK
    peer_module.MAX_GETDATA_ITEMS_PER_TICK = 7     -- force many passes
    local items, expect_blocks, expect_nf = {}, {}, {}
    for i = 1, 300 do
      local r = i % 5
      if r == 0 then
        items[i] = { type = T.MSG_WITNESS_BLOCK, hash = missing }
        expect_nf[#expect_nf + 1] = missing.bytes
      elseif r == 1 then
        items[i] = { type = T.MSG_BLOCK, hash = h2 }
        expect_blocks[#expect_blocks + 1] = serialize.serialize_block_without_witness(blk2)
      else
        items[i] = { type = T.MSG_WITNESS_BLOCK, hash = H }
        expect_blocks[#expect_blocks + 1] = serialize.serialize_block(BLK)
      end
    end
    local aw, ar = writer(a_remote), reader(a_remote)
    -- A ping right behind the getdata: its pong must come after every block.
    aw.queue(getdata_msg(items) .. p2p.make_message(MAGIC, "ping", p2p.serialize_ping(42)))
    local got_blocks, got_nf, pong_at = {}, {}, nil
    local deadline = socket.gettime() + 30
    local ok, err = pcall(function()
      while socket.gettime() < deadline do
        aw.pump()
        tick({ a })
        ar.pump()
        if pong_at and #got_blocks == #expect_blocks then break end
        for _, m in ipairs(ar.msgs) do
          if m.command == "block" then
            got_blocks[#got_blocks + 1] = m.payload
          elseif m.command == "notfound" then
            for _, it in ipairs(p2p.deserialize_inv(m.payload)) do
              got_nf[#got_nf + 1] = it.hash.bytes
            end
          elseif m.command == "pong" then
            pong_at = #got_blocks
          end
        end
        ar.msgs = {}
      end
    end)
    peer_module.MAX_GETDATA_ITEMS_PER_TICK = saved
    assert(ok, err)
    assert.equal(#expect_blocks, #got_blocks)
    for i = 1, #expect_blocks do
      assert.is_true(expect_blocks[i] == got_blocks[i], "block reply " .. i .. " differs")
    end
    assert.same(expect_nf, got_nf)
    assert.equal(#expect_blocks, pong_at)
    a:disconnect("test done")
    a_remote:close()
  end)

  it("resumes a paused getdata once the peer drains, and serves every item exactly once", function()
    local started
    local srv = make_server(blocks, function()
      started = started or socket.gettime()
      if socket.gettime() - started > 2 * WATCHDOG and not phase2 then
        error("watchdog: getdata serving ran past " .. 2 * WATCHDOG .. " s in one call")
      end
    end)
    local a, a_remote = loopback_peer()
    a:on("getdata", make_handler(srv.serve))
    local n = 1500                                 -- ~30 MB of replies
    local items = {}
    for i = 1, n do items[i] = { type = T.MSG_WITNESS_BLOCK, hash = H } end
    local aw, ar = writer(a_remote), reader(a_remote)
    aw.queue(getdata_msg(items))
    -- Phase 1: A does not read.  The node pauses rather than serving it all.
    for _ = 1, 50 do aw.pump(); tick({ a }) end
    assert.is_true(srv.calls < n, "served " .. srv.calls .. " of " .. n .. " with a non-reading peer")
    assert.is_true(queued(a) <= 5000 * 1000 + 2 * 21000)
    -- Phase 2: A reads.  Everything arrives.
    phase2 = true
    local count = 0
    local deadline = socket.gettime() + 60
    while count < n and socket.gettime() < deadline do
      tick({ a })
      ar.pump()
      for _, m in ipairs(ar.msgs) do
        if m.command == "block" then count = count + 1 end
      end
      ar.msgs = {}
    end
    assert.equal(n, count)
    assert.equal(n, srv.calls)
    assert.is_falsy(pending(a))
    a:disconnect("test done")
    a_remote:close()
  end)
end)
