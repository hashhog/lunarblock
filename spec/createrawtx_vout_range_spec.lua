-- createrawtransaction -- `vout` must be range-checked against int32
--
-- THE DEFECT (regression pinned by this spec)
-- ------------------------------------------
-- createrawtransaction's input parser only asked "is vout negative?".  It
-- never asked "is vout too big?".  The value was then narrowed to the 32-bit
-- `vout` field of the outpoint, so anything at or above 2^32 silently WRAPPED:
--
--     vout 4294967296 (2^32)  -->  outpoint index 0
--     vout 8589934592 (2^33)  -->  outpoint index 0
--
-- Both were observed on the live mainnet node.  The RPC returned SUCCESS and a
-- perfectly well-formed transaction hex -- one that spends a COMPLETELY
-- DIFFERENT outpoint from the one the caller asked for, and index 0 of a real
-- txid is very likely a real, fundable output.  A caller that signs and
-- broadcasts what it was handed spends the wrong coin, with no error and no
-- log line anywhere.  Silent redirection of a spend is the worst shape a bug
-- can take in this RPC.
--
-- WHAT BITCOIN CORE DOES
-- ----------------------
-- Core reads the field with `find_value(o, "vout").getInt<int>()` -- `int`,
-- i.e. THIRTY-TWO bits (bitcoin-core/src/rpc/rawtransaction_util.cpp,
-- AddInputs:38-45).  univalue's `getInt<Int>`
-- (src/univalue/include/univalue.h) range-checks the parsed integer against
-- the destination type and throws `std::runtime_error("JSON integer out of
-- range")` when it does not fit; the RPC layer surfaces that as
-- RPC_MISC_ERROR (-1).
--
-- The ORDERING IS DELIBERATE AND IS UNIVALUE'S, NOT OURS: the range check
-- lives inside the *conversion*, so it fires BEFORE the handler's own
-- `if (nOutput < 0) throw ... "vout cannot be negative"` sign test ever runs.
-- That is why -1 gets the vout-specific -8 message while 2147483648 -- also
-- "not a valid vout" in any human sense -- gets the generic -1 "JSON integer
-- out of range" instead.  Matching Core here means matching that ORDER, not
-- just the two checks.
--
-- The fix therefore adds, BEFORE the existing sign test:
--     if vout < -2147483648 or vout > 2147483647 then
--       error({code = M.ERROR.MISC_ERROR, message = "JSON integer out of range"})
--     end
--
-- TEETH
-- -----
-- Cases 1-6 are all rejections, and a handler that rejected EVERY input would
-- satisfy every one of them.  The two CONTROL cases exist to make that
-- impossible: they drive the real handler to success and then DECODE the
-- returned hex with the node's own deserializer, asserting the outpoint index
-- that actually landed in the bytes.  In particular the int32-MAX control
-- (2147483647) fails loudly if the new bound is off by one in the tight
-- direction.
--
-- References:
--   bitcoin-core/src/rpc/rawtransaction_util.cpp:38-45   AddInputs
--   bitcoin-core/src/univalue/include/univalue.h         getInt<Int>
--   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
--                                                        RPC_INVALID_PARAMETER = -8
--
--
-- ============================================================================
-- SECOND DEFECT (same RPC, same file): an EXPLICIT `replaceable=true` that the
-- supplied sequence numbers contradict was silently accepted
-- ============================================================================
--
-- THE DEFECT
-- ----------
-- `createrawtransaction(ins, outs, 0, true)` asks for a REPLACEABLE
-- transaction.  BIP-125 opt-in signalling means at least one input carrying
-- nSequence <= MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD); a sequence ABOVE that
-- value is precisely the opt-OUT.  So a caller who passes replaceable=true and
-- also pins every input to 0xFFFFFFFE or 0xFFFFFFFF has asked for two things
-- that cannot both be true.
--
-- Pre-fix, this node resolved the contradiction silently and in favour of the
-- sequence: it returned a well-formed transaction hex that CANNOT be
-- fee-bumped, with no error, no warning and no log line.  The caller learns
-- the truth only when the bump is actually needed and the replacement is
-- refused by the network -- at which point the transaction is already
-- broadcast and stuck.  Nine of the ten nodes in this repo still behave this
-- way.  Core refuses to guess which of the two the caller meant.
--
-- WHAT BITCOIN CORE DOES
-- ----------------------
-- The LAST statement of ConstructTransaction
-- (bitcoin-core/src/rpc/rawtransaction_util.cpp:166), after AddInputs AND
-- AddOutputs have both run:
--
--     if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
--         !SignalsOptInRBF(CTransaction(rawTx))) {
--         throw JSONRPCError(RPC_INVALID_PARAMETER,
--             "Invalid parameter combination: Sequence number(s) contradict "
--             "replaceable option");
--     }
--
-- with SignalsOptInRBF (bitcoin-core/src/util/rbf.cpp) returning true if ANY
-- input has nSequence <= MAX_BIP125_RBF_SEQUENCE (util/rbf.h = 0xfffffffd).
-- "Any" rather than "all" is deliberate upstream: in a multi-party protocol a
-- single participant must not be able to disable replacement by opting out in
-- their own input.
--
-- THE ABSENT-vs-EXPLICIT ASYMMETRY (the subtle part)
-- --------------------------------------------------
-- `rbf` is a std::optional<bool>, left `nullopt` when the JSON param is
-- absent/null.  TWO DIFFERENT QUESTIONS are asked of it:
--   • AddInputs asks `rbf.value_or(true)` -- absent counts as TRUE, which is
--     what makes 0xFFFFFFFD the DEFAULT sequence.
--   • this check asks `rbf.has_value() && rbf.value()` -- absent counts as NOT
--     SET, so no check fires at all.
-- Consequence, verified against a live Core node: an omitted `replaceable`
-- with an explicit final sequence is ACCEPTED, while the same call with
-- `replaceable=true` spelled out is REJECTED.  A check that keyed off the
-- effective boolean instead of has_value() would break the first case, which
-- is ordinary, legal usage.
--
-- ORDERING
-- --------
-- Core runs the check after AddOutputs, so an OUTPUT error still wins over it.
-- A request that is wrong in both ways must report the output error.  The
-- ordering case below pins that.
--
-- TEETH
-- -----
-- Only two of the eight oracle rows are rejections.  The four ACCEPT rows
-- (absent-rbf, signalling sequence, no inputs at all, one-of-two inputs
-- signalling) plus replaceable=false and the defaulted sequence are the real
-- guard: an over-eager check that ignored has_value(), or scanned for "all
-- inputs signal" instead of "any input signals", or forgot the vin-empty
-- guard, passes both rejections and fails these.  Where the tx is built
-- successfully the assertions DECODE the returned hex with the node's own
-- deserializer and read the sequence that actually landed in the wire bytes.
--
-- References:
--   bitcoin-core/src/rpc/rawtransaction_util.cpp:147-171  ConstructTransaction
--   bitcoin-core/src/rpc/rawtransaction_util.cpp:47-66    AddInputs sequence
--   bitcoin-core/src/util/rbf.cpp                         SignalsOptInRBF
--   bitcoin-core/src/util/rbf.h                           MAX_BIP125_RBF_SEQUENCE
--                                                           = 0xfffffffd

local rpc = require("lunarblock.rpc")
local serialize = require("lunarblock.serialize")
local consensus = require("lunarblock.consensus")
local cjson = require("cjson")

describe("createrawtransaction vout int32 range", function()

  -- Well-formed 64-hex txid; the content is irrelevant -- createrawtransaction
  -- builds an UNSIGNED transaction and never looks the outpoint up.
  local TXID =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

  -- A single OP_RETURN output. Deliberately data-only: it keeps the spec
  -- independent of address encoding/network, so a failure here can only mean
  -- the INPUT parser, never the output parser.
  local OUTPUTS = '{"data":"deadbeef"}'

  -- The request body is written as LITERAL JSON text so the large integers
  -- reach the handler exactly as they arrive off the wire, not via a Lua
  -- literal that some encoder might reshape.
  local function call(inputs_json, extra_json)
    local server = rpc.new({network = consensus.networks.mainnet})
    local body = '{"method":"createrawtransaction","params":[' ..
      inputs_json .. ',' .. OUTPUTS .. (extra_json or "") .. '],"id":1}'
    -- handle_request returns (body, status_override); bind the first return
    -- value explicitly so the status does not become a second argument to
    -- cjson.decode (which rejects a second argument).
    local response = server:handle_request(body)
    return cjson.decode(response)
  end

  local function call_vout(vout_json)
    return call('[{"txid":"' .. TXID .. '","vout":' .. vout_json .. '}]')
  end

  -- Assert a rejection. A SUCCESS is reported as a distinct, loud failure
  -- rather than being silently tolerated.
  local function assert_error(decoded, code, message, what)
    if type(decoded.error) ~= "table" then
      assert.truthy(false, what ..
        ": expected an error object but the call SUCCEEDED with result " ..
        tostring(decoded.result))
    end
    assert.truthy(decoded.error.code == code, what .. ": expected error code " ..
      tostring(code) .. ", got " .. tostring(decoded.error.code))
    assert.truthy(decoded.error.message == message, what ..
      ": expected message " .. string.format("%q", message) .. ", got " ..
      string.format("%q", tostring(decoded.error.message)))
  end

  -- Decode with the node's own transaction deserializer and report the
  -- outpoint index that actually reached the wire bytes.
  local function first_input_vout(hex)
    local tx = serialize.deserialize_transaction(rpc.hex_decode(hex))
    assert.truthy(#tx.inputs == 1,
      "expected exactly one input in the built tx, got " .. tostring(#tx.inputs))
    return tx.inputs[1].prev_out.index
  end

  local function assert_accepted(decoded, expected_vout, what)
    if decoded.error ~= nil and decoded.error ~= cjson.null then
      assert.truthy(false, what .. ": expected success but got error " ..
        tostring(decoded.error.code) .. " " .. tostring(decoded.error.message))
    end
    assert.truthy(type(decoded.result) == "string",
      what .. ": expected a hex string result, got " .. type(decoded.result))
    assert.truthy(#decoded.result > 0, what .. ": hex must be non-empty")
    local got = first_input_vout(decoded.result)
    assert.truthy(got == expected_vout, what ..
      ": outpoint index in the tx bytes -- expected " ..
      tostring(expected_vout) .. ", got " .. tostring(got))
  end

  describe("REGRESSION: out-of-int32 vout is -1 JSON integer out of range",
  function()

    it("rejects vout 4294967296 (2^32) -- pre-fix this WRAPPED to 0", function()
      assert_error(call_vout("4294967296"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2^32")
    end)

    it("rejects vout 8589934592 (2^33) -- pre-fix this ALSO wrapped to 0",
    function()
      assert_error(call_vout("8589934592"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2^33")
    end)

    it("rejects vout 2147483648 (int32 MAX + 1) -- the exact boundary",
    function()
      assert_error(call_vout("2147483648"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout 2147483648")
    end)

    it("rejects vout -2147483649 with the RANGE message, not the sign one",
    function()
      -- Negative AND out of int32 range. Core's range check lives inside the
      -- conversion, so it wins over "cannot be negative". Ordering assertion.
      assert_error(call_vout("-2147483649"), rpc.ERROR.MISC_ERROR,
        "JSON integer out of range", "vout -2147483649")
    end)
  end)

  describe("neighbouring guards still report Core's own codes", function()

    it("rejects vout -1 with -8 vout cannot be negative", function()
      -- In int32 range, so the range check passes and the sign test speaks.
      assert_error(call_vout("-1"), rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, vout cannot be negative", "vout -1")
    end)

    it("rejects sequence 4294967296 with -8 sequence out of range", function()
      local decoded = call('[{"txid":"' .. TXID ..
        '","vout":0,"sequence":4294967296}]')
      assert_error(decoded, rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, sequence number is out of range", "sequence 2^32")
    end)

    it("rejects locktime -1 with -8 locktime out of range", function()
      local decoded = call('[{"txid":"' .. TXID .. '","vout":0}]', ',-1')
      assert_error(decoded, rpc.ERROR.INVALID_PARAMETER,
        "Invalid parameter, locktime out of range", "locktime -1")
    end)
  end)

  describe("CONTROLS -- an over-tight bound must FAIL these", function()

    it("accepts vout 2147483647 (int32 MAX) and carries it into the tx bytes",
    function()
      -- Mandatory teeth: proves the new upper bound is `> 2147483647`, not
      -- `>= 2147483647` or some smaller cap.
      assert_accepted(call_vout("2147483647"), 2147483647,
        "vout 2147483647 (int32 MAX)")
    end)

    it("accepts an ordinary vout 7 and carries it into the tx bytes",
    function()
      -- Mandatory teeth: proves the handler still does its normal job, so the
      -- rejection tests above cannot be satisfied by a reject-everything stub.
      assert_accepted(call_vout("7"), 7, "vout 7 (ordinary)")
    end)
  end)

  -- ==========================================================================
  -- explicit replaceable=true contradicted by the sequence numbers
  -- (ConstructTransaction:166 + SignalsOptInRBF).  Every case below is a row
  -- of the oracle table captured from a LIVE Bitcoin Core node.
  -- ==========================================================================
  describe("replaceable option contradicted by sequence numbers", function()

    local CONTRADICT_MSG =
      "Invalid parameter combination: Sequence number(s) contradict replaceable option"

    -- MAX_BIP125_RBF_SEQUENCE and its two neighbours, spelled decimal because
    -- that is how they travel in JSON.
    local SEQ_RBF      = 4294967293  -- 0xFFFFFFFD  MAX_BIP125_RBF_SEQUENCE
    local SEQ_NONFINAL = 4294967294  -- 0xFFFFFFFE  MAX_SEQUENCE_NONFINAL
    local SEQ_FINAL    = 4294967295  -- 0xFFFFFFFF  SEQUENCE_FINAL

    -- One input, optional explicit sequence, optional trailing args. `rbf_json`
    -- is spliced in as literal JSON text so that ABSENT (nil here) and the
    -- JSON literals `true` / `false` / `null` reach the handler exactly as they
    -- would off the wire -- the absent/present distinction is the whole point
    -- of these cases and must not be laundered through a Lua encoder.
    local function call_rbf(sequence_json, rbf_json)
      local seq_part = ""
      if sequence_json then
        seq_part = ',"sequence":' .. sequence_json
      end
      local extra = nil
      if rbf_json then
        extra = ',0,' .. rbf_json    -- locktime 0, then replaceable
      end
      return call('[{"txid":"' .. TXID .. '","vout":0' .. seq_part .. '}]', extra)
    end

    -- Read back the sequence numbers that actually reached the wire bytes,
    -- using the node's own deserializer (same technique as first_input_vout).
    local function tx_sequences(hex)
      local tx = serialize.deserialize_transaction(rpc.hex_decode(hex))
      local seqs = {}
      for i = 1, #tx.inputs do
        seqs[i] = tx.inputs[i].sequence
      end
      return seqs
    end

    local function assert_sequences(decoded, expected, what)
      if decoded.error ~= nil and decoded.error ~= cjson.null then
        assert.truthy(false, what .. ": expected success but got error " ..
          tostring(decoded.error.code) .. " " .. tostring(decoded.error.message))
      end
      assert.truthy(type(decoded.result) == "string",
        what .. ": expected a hex string result, got " .. type(decoded.result))
      local got = tx_sequences(decoded.result)
      assert.truthy(#got == #expected, what .. ": expected " ..
        tostring(#expected) .. " input(s) in the tx bytes, got " ..
        tostring(#got))
      for i = 1, #expected do
        assert.truthy(got[i] == expected[i], what .. ": input " .. tostring(i) ..
          " sequence in the tx bytes -- expected " .. tostring(expected[i]) ..
          ", got " .. tostring(got[i]))
      end
    end

    -- ---- ROW 1 ----
    it("ACCEPTS an ABSENT replaceable with a FINAL sequence (has_value() is false)",
    function()
      -- The asymmetry case. Absent still DEFAULTS to replaceable for choosing
      -- the sequence, but has_value() is false so the contradiction check is
      -- skipped entirely. A check keyed off the effective boolean rather than
      -- has_value() breaks this ordinary, legal call.
      assert_sequences(call_rbf(tostring(SEQ_FINAL), nil), {SEQ_FINAL},
        "row 1: rbf absent, sequence 0xFFFFFFFF")
    end)

    -- ---- ROW 2 ----
    it("ACCEPTS replaceable=true with sequence 0xFFFFFFFD (it signals)",
    function()
      -- Exactly MAX_BIP125_RBF_SEQUENCE: SignalsOptInRBF is `<=`, so this
      -- signals. Fails loudly if the comparison is written `<`.
      assert_sequences(call_rbf(tostring(SEQ_RBF), "true"), {SEQ_RBF},
        "row 2: rbf true, sequence 0xFFFFFFFD")
    end)

    -- ---- ROW 3 ----
    it("REJECTS replaceable=true with sequence 0xFFFFFFFE (-8)", function()
      -- One above MAX_BIP125_RBF_SEQUENCE: the tight boundary on the other
      -- side. This is MAX_SEQUENCE_NONFINAL -- still non-final for locktime
      -- purposes, but NOT RBF-signalling.
      assert_error(call_rbf(tostring(SEQ_NONFINAL), "true"),
        rpc.ERROR.INVALID_PARAMETER, CONTRADICT_MSG,
        "row 3: rbf true, sequence 0xFFFFFFFE")
    end)

    -- ---- ROW 4 ----
    it("REJECTS replaceable=true with sequence 0xFFFFFFFF (-8)", function()
      assert_error(call_rbf(tostring(SEQ_FINAL), "true"),
        rpc.ERROR.INVALID_PARAMETER, CONTRADICT_MSG,
        "row 4: rbf true, sequence 0xFFFFFFFF")
    end)

    -- ---- ROW 5 ----
    it("ACCEPTS replaceable=true with NO inputs at all (vin.size() > 0 guard)",
    function()
      -- A transaction with no inputs cannot signal, and Core does not punish
      -- it for that: rawTx.vin.size() > 0 short-circuits first. Dropping that
      -- guard turns this legal call into an error.
      local decoded = call('[]', ',0,true')
      if decoded.error ~= nil and decoded.error ~= cjson.null then
        assert.truthy(false,
          "row 5: rbf true, zero inputs: expected success but got error " ..
          tostring(decoded.error.code) .. " " .. tostring(decoded.error.message))
      end
      assert.truthy(type(decoded.result) == "string",
        "row 5: expected a hex string result, got " .. type(decoded.result))
      -- Assert on the SERIALIZED BYTES, but not via deserialize_transaction:
      -- a zero-input legacy tx begins `02000000 00 01 ...`, whose 0x00 0x01 is
      -- byte-identical to the segwit marker+flag, so any BIP-144 deserializer
      -- (ours and Core's alike) mis-reads it. Read the input-count CompactSize
      -- directly instead: bytes 1-4 are the version, byte 5 is the count.
      assert.truthy(decoded.result:sub(9, 10) == "00",
        "row 5: input-count byte in the tx bytes -- expected \"00\", got \"" ..
        tostring(decoded.result:sub(9, 10)) .. "\" (full hex " ..
        tostring(decoded.result) .. ")")
    end)

    -- ---- ROW 6 ----
    it("ACCEPTS replaceable=true when ONE of two inputs signals", function()
      -- SignalsOptInRBF is ANY, not ALL -- deliberately, so that in a
      -- multi-party protocol one participant cannot disable replacement by
      -- opting out in their own input. A check written as "every input must
      -- signal" passes rows 3 and 4 and fails here.
      local decoded = call(
        '[{"txid":"' .. TXID .. '","vout":0,"sequence":' .. SEQ_FINAL .. '},' ..
        '{"txid":"' .. TXID .. '","vout":1,"sequence":0}]', ',0,true')
      assert_sequences(decoded, {SEQ_FINAL, 0},
        "row 6: rbf true, sequences {0xFFFFFFFF, 0}")
    end)

    -- ---- ROW 7 ----
    it("ACCEPTS replaceable=false with a FINAL sequence (rbf.value() is false)",
    function()
      -- The caller asserted NON-replaceable and supplied a matching sequence.
      -- Nothing contradicts anything; the second conjunct is false.
      assert_sequences(call_rbf(tostring(SEQ_FINAL), "false"), {SEQ_FINAL},
        "row 7: rbf false, sequence 0xFFFFFFFF")
    end)

    -- ---- ROW 8 ----
    it("ACCEPTS replaceable=true with NO explicit sequence (default signals)",
    function()
      -- With no `sequence` key, AddInputs picks MAX_BIP125_RBF_SEQUENCE
      -- because rbf.value_or(true) is true -- so the default sequence is
      -- itself signalling and the check is satisfied. This is the single most
      -- common RBF call there is; breaking it would be catastrophic.
      assert_sequences(call_rbf(nil, "true"), {SEQ_RBF},
        "row 8: rbf true, sequence defaulted")
    end)

    -- ---- Extra: the JSON null spelling of "absent" ----
    it("ACCEPTS an explicit JSON null replaceable with a FINAL sequence",
    function()
      -- Core's test is `request.params[3].isNull()`, so a literal null is the
      -- same as omitting the argument: nullopt, has_value() false, no check.
      assert_sequences(call_rbf(tostring(SEQ_FINAL), "null"), {SEQ_FINAL},
        "rbf JSON null, sequence 0xFFFFFFFF")
    end)

    -- ---- Extra: ordering, an output error still wins ----
    it("reports the OUTPUT error, not the contradiction, when both are wrong",
    function()
      -- Core runs the contradiction check as the LAST statement of
      -- ConstructTransaction, after AddOutputs. Hoisting it up next to the
      -- input loop -- where it reads more naturally -- would silently change
      -- which error this request reports. Pins the placement.
      local server = rpc.new({network = consensus.networks.mainnet})
      local body = '{"method":"createrawtransaction","params":[' ..
        '[{"txid":"' .. TXID .. '","vout":0,"sequence":' .. SEQ_FINAL .. '}],' ..
        '{"notanaddress":0.1},0,true],"id":1}'
      local decoded = cjson.decode((server:handle_request(body)))
      assert_error(decoded, rpc.ERROR.INVALID_ADDRESS,
        "Invalid Bitcoin address: notanaddress",
        "output error must outrank the replaceable contradiction")
    end)
  end)
end)
