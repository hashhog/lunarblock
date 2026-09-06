--- Runner for lunarblock's standalone script-style tests.
--
-- WHY THIS FILE EXISTS
-- --------------------
-- lunarblock has TWO bodies of tests:
--
--   1. spec/*_spec.lua  -- busted specs.  `.busted` pins ROOT={"spec/"} with
--      pattern="_spec", and the Makefile's `test` target is `busted spec/`.
--      These run.
--
--   2. tests/*.lua and ./test_*.lua -- 106 standalone LuaJIT scripts, each with
--      its own PASS/FAIL counters, run as `luajit tests/test_foo.lua` from the
--      repo root.  NONE of them match pattern="_spec" and NONE of them live
--      under ROOT, so `busted spec/` could never see them.  They executed
--      nowhere.  All 106 parse cleanly; several fail.
--
-- Every one of the 106 shares one shape: a standalone script that counts its
-- own passes/failures and signals the verdict through its EXIT CODE
-- (`os.exit(FAIL == 0 and 0 or 1)`).  102 of 106 honour that contract.  Given
-- one uniform shape, a single runner busted can see is the right tool --
-- rewriting 100+ scripts into describe/it by hand would be a large mechanical
-- diff with a real chance of dropping assertions in transit, which is the very
-- failure mode that produced this situation.
--
-- So: one `it()` per script, running it as a subprocess and asserting its exit
-- code.  Scripts that are deliberately NOT run are listed in EXCLUDED below
-- with a reason and reported as pending on every run -- silent omission is what
-- created the orphan pile in the first place.
--
-- MAINTENANCE: a new standalone script under tests/ or ./test_*.lua must be
-- added to INCLUDED (or EXCLUDED with a reason).  The "manifest covers every
-- orphan script on disk" test at the bottom fails if one is left out.

local REPO_MARKER = "src/main.lua"

-- Scripts that ARE run.  102 files.
local INCLUDED = {
  "tests/test_addrman_persist.lua",
  "tests/test_assumeutxo_work_gate.lua",
  "tests/test_bip155_services_compactsize.lua",
  "tests/test_chain_sync_probe_locator.lua",
  "tests/test_dispatcher_arity.lua",
  "tests/test_fix37_bloom_wiring.lua",
  "tests/test_fix_3g_addr_timestamp_clamp.lua",
  "tests/test_fix_4f_5b_4g.lua",
  "tests/test_fix59_bip32_ckd.lua",
  "tests/test_fix61_bumpfee.lua",
  "tests/test_fix62_bip21.lua",
  "tests/test_fix63_decode_address_network.lua",
  "tests/test_fix65_payjoin_receiver.lua",
  "tests/test_fix66_payjoin_sender.lua",
  "tests/test_fix67_payjoin_cleanup.lua",
  "tests/test_fix71_compact_filters_gate.lua",
  "tests/test_fix81_bip157_dispatch.lua",
  "tests/test_fundrawtransaction.lua",
  "tests/test_gate2_work_not_height.lua",
  "tests/test_getindexinfo.lua",
  "tests/test_getnodeaddresses.lua",
  "tests/test_getpeerinfo_inv_fields.lua",
  "tests/test_inbound_eviction.lua",
  "tests/test_listdescriptors.lua",
  "tests/test_p2_1_p2_2_wallet_security.lua",
  "tests/test_p2_3_bip43_purpose_table.lua",
  "tests/test_p2_4_p2tr_signer.lua",
  "tests/test_presync_genesis_locator.lua",
  "tests/test_script_flag_exceptions.lua",
  "tests/test_script_vectors.lua",
  "tests/test_send_drop_reverts.lua",
  "tests/test_service_flags_full_node.lua",
  "tests/test_sighash_vectors.lua",
  "tests/test_sigop_partial_count.lua",
  "tests/test_submitblock_discard_dirty.lua",
  "tests/test_superfluous_witness.lua",
  "tests/test_w111_wallet.lua",
  "tests/test_w112_compact_blocks.lua",
  "tests/test_w113_coin_selection.lua",
  "tests/test_w114_fee_estimation.lua",
  "tests/test_w115_asmap.lua",
  "tests/test_w116_package_relay.lua",
  "tests/test_w117_bip155_networks.lua",
  "tests/test_w118_wallet.lua",
  "tests/test_w119_payjoin.lua",
  "tests/test_w120_mempool_rbf.lua",
  "tests/test_w121_compact_filters.lua",
  "tests/test_w122_bip158_codec_stress.lua",
  "tests/test_w123_mining_gbt.lua",
  "tests/test_w124_operator.lua",
  "tests/test_w125_error_parity.lua",
  "tests/test_w126_bip152_compact_blocks.lua",
  "tests/test_w127_taproot.lua",
  "tests/test_w128_addrman.lua",
  "tests/test_w129_coin_selection.lua",
  "tests/test_w130_bip125_feebumper_rule3.lua",
  "tests/test_w132_nsequence_csv_mtp.lua",
  "tests/test_w133_index_databases.lua",
  "tests/test_w134_bip37_bloom_filter.lua",
  "tests/test_w135_standardness.lua",
  "tests/test_w136_relay_flags.lua",
  "tests/test_w137_psbt.lua",
  "tests/test_w138_assumeutxo.lua",
  "tests/test_w139_fee_estimation.lua",
  "tests/test_w140_http_rpcauth.lua",
  "tests/test_w141_zmq_rest_notify.lua",
  "tests/test_w156_bip152_uint16_caps.lua",
  "tests/test_w157_feeler_anti_eclipse.lua",
  "tests/test_witness_malleated_p2sh.lua",
  "test_accept_block.lua",
  "test_bip141_witness_commitment.lua",
  "test_bip30_bip34_w79.lua",
  "test_bip30.lua",
  "test_connect_block_w93.lua",
  "test_descriptor.lua",
  "test_disconnect_block_w92.lua",
  "test_dump_snapshot_atomic.lua",
  "test_filterindex_revert_on_reorg.lua",
  "test_getblockfrompeer_rpc.lua",
  "test_getchainstates_rpc.lua",
  "test_gettxoutsetinfo_hash.lua",
  "test_is_final_tx.lua",
  "test_mempool_eviction.lua",
  "test_mempool_isstandard.lua",
  "test_mempool_limits.lua",
  "test_mempool_witness_standard.lua",
  "test_native_p2tr_parity.lua",
  "test_native_p2tr_validation_weight.lua",
  "test_noassumevalid.lua",
  "test_op_success.lua",
  "test_package.lua",
  "test_presync.lua",
  "test_prioritise_transaction.lua",
  "test_psbt.lua",
  "test_psbt_rpc.lua",
  "test_reason_token_parity.lua",
  "test_reorg_atomicity.lua",
  "test_reorg_via_submitblock.lua",
  "test_sigops_w74.lua",
  "test_txindex_revert_on_reorg.lua",
  "test_unconnecting_headers.lua",
  "test_w144_block_weight_checksigadd_varint.lua",
}

-- Scripts that are deliberately NOT run, each with the reason.  Printed on
-- every run and reported as pending, so the exclusions stay visible.
local EXCLUDED = {
  {
    file = "tests/test_ffi_reader.lua",
    reason = "NOT A TEST: a corpus-dependent benchmark/verification tool. It " ..
             "asserts open of an external corpus (/tmp/w72-test-blocks.hex) " ..
             "that is not in the repo and dies immediately when it is absent. " ..
             "Its own header says the authoritative perf number comes from the " ..
             "[W72-DESER] log on a live node, not this bench.",
  },
  {
    file = "tests/test_w131_descriptors_miniscript.lua",
    reason = "NOT A TEST: self-described 'Discovery-only audit: report " ..
             "findings; exit 0 even on failures'. It ends in a hardcoded " ..
             "os.exit(0) and has no regression gate at all, so there is no " ..
             "verdict for a runner to assert. It is a report, not a test.",
  },
  {
    file = "tests/test_w110_bloom_filter.lua",
    reason = "SUPERSEDED by spec/w110_bloom_filter_spec.lua (same day, 797 " ..
             "lines, 81 it(), covering BUG-1..19 / G1..G30 -- a strict " ..
             "superset of this script's BUG-3/8/9/10 + G25/26/27). Its only " ..
             "non-duplicated part (Sections 2-4) asserts against a local " ..
             "bloom_guard_sim() that the file itself describes as replicating " ..
             "main.lua's closure, i.e. it tests a copy of the logic rather " ..
             "than the node, so it carries no coverage the spec lacks.",
  },
  {
    file = "tests/test_fix64_tls.lua",
    reason = "PORT SAFETY: binds a real TCP socket via " ..
             "socket.tcp4():bind('127.0.0.1', 0) and shells out to curl. " ..
             "Port 0 means a kernel-assigned ephemeral port, and Linux's " ..
             "default ephemeral range (32768-60999) overlaps the 48300-48400 " ..
             "band reserved for the live fleet, so the port it grabs cannot " ..
             "be constrained. Excluded until it takes an explicit port.",
  },
}

-- Three scripts assert real things but their test() helper pcall()s the body
-- and never records the result in an exit code, so they exit 0 even when
-- assertions fail. For these the exit code is not a verdict, and the runner
-- additionally rejects any "FAIL:" marker in their output. This is a defect in
-- the scripts' own harness, not in the node -- see the report.
local SWALLOWS_FAILURES = {
  ["test_package.lua"]  = true,
  ["test_psbt.lua"]     = true,
  ["test_psbt_rpc.lua"] = true,
}

local LUA_PATH_CHILD =
  "./src/?.lua;./src/?/init.lua;./?.lua;" ..
  (os.getenv("HOME") or "") .. "/.luarocks/share/lua/5.1/?.lua;" ..
  (os.getenv("HOME") or "") .. "/.luarocks/share/lua/5.1/?/init.lua;;"
local LUA_CPATH_CHILD =
  "./lib/?.so;" .. (os.getenv("HOME") or "") .. "/.luarocks/lib/lua/5.1/?.so;;"

-- io.popen():close() does not report a child exit status on LuaJIT (5.1
-- semantics), so the status is echoed into the stream and parsed back out.
local function run_script(path)
  local cmd = string.format(
    "LD_LIBRARY_PATH=./lib LUA_PATH=%s LUA_CPATH=%s timeout 120 luajit %s 2>&1; " ..
    "echo \"__LB_RC__=$?\"",
    ("%q"):format(LUA_PATH_CHILD), ("%q"):format(LUA_CPATH_CHILD), ("%q"):format(path))
  local p = assert(io.popen(cmd, "r"))
  local out = p:read("*a") or ""
  p:close()
  local rc = tonumber(out:match("__LB_RC__=(%d+)%s*$"))
  out = out:gsub("__LB_RC__=%d+%s*$", "")
  return rc, out
end

local function tail(s, n)
  local lines = {}
  for line in s:gmatch("[^\n]*") do lines[#lines + 1] = line end
  local from = math.max(1, #lines - n)
  return table.concat(lines, "\n", from, #lines)
end

io.write("\n[orphan-scripts] running ", #INCLUDED,
         " standalone script tests from tests/ and ./test_*.lua\n")
io.write("[orphan-scripts] ", #EXCLUDED, " excluded (reported pending below):\n")
for _, e in ipairs(EXCLUDED) do
  io.write("[orphan-scripts]   - ", e.file, "\n")
  io.write("[orphan-scripts]     ", e.reason, "\n")
end

describe("orphan standalone scripts", function()
  -- These scripts write scratch into /tmp via hardcoded paths and via
  -- os.tmpname() (which ignores TMPDIR), and most do not clean up after
  -- themselves. One full pass leaks well over a gigabyte, and /tmp on maxbox is
  -- a RAM-backed tmpfs, so the leak costs RAM and then swap rather than disk --
  -- the same pathology that once put 44 GiB of abandoned lunarblock harness
  -- scratch into swap. So sweep what this run created.
  --
  -- The sweep is marker-scoped (only entries newer than a marker taken at
  -- setup) and prefix-matched (only the scratch names these scripts actually
  -- use), so nothing predating the run is touched. Note that several scripts
  -- os.remove() their tmpname and mkdir it back as a DIRECTORY, which is how a
  -- /tmp/lua_* entry ends up holding a whole rocksdb -- those are swept only
  -- when they are directories, never as plain files, which could belong to any
  -- other Lua process on the box.
  --
  -- Set LB_NO_TMP_SWEEP=1 to disable (e.g. when debugging a script's scratch,
  -- or if two suites are ever run concurrently against the same checkout).
  local marker

  setup(function()
    assert(io.open(REPO_MARKER, "r"),
      "orphan script runner must be run from the lunarblock repo root " ..
      "(expected to find " .. REPO_MARKER .. "); the scripts resolve their " ..
      "requires relative to the working directory")
    marker = os.tmpname()
  end)

  teardown(function()
    if not marker then return end
    if os.getenv("LB_NO_TMP_SWEEP") ~= "1" then
      os.execute(string.format(
        "find /tmp -maxdepth 1 -newer %q \\( -name 'lb_*' -o -name 'test_w1*' " ..
        "-o -name 'test_bad_asmap_*' -o -name 'test_i2p_key' " ..
        "-o -name 'lunarblock-*' \\) -exec rm -rf {} + 2>/dev/null", marker))
      os.execute(string.format(
        "find /tmp -maxdepth 1 -newer %q -type d -name 'lua_*' " ..
        "-exec rm -rf {} + 2>/dev/null", marker))
    end
    os.remove(marker)
  end)

  describe("excluded", function()
    for _, e in ipairs(EXCLUDED) do
      it(e.file .. " -- " .. e.reason, function()
        pending("excluded by manifest")
      end)
    end
  end)

  describe("included", function()
    for _, path in ipairs(INCLUDED) do
      it(path, function()
        local rc, out = run_script(path)
        assert.is_truthy(rc)
        if rc == 124 then
          assert(false, path .. " timed out after 120s\n--- output tail ---\n" ..
                        tail(out, 25))
        end
        if rc ~= 0 then
          assert(false, path .. " exited " .. tostring(rc) ..
                        "\n--- output tail ---\n" .. tail(out, 25))
        end
        if SWALLOWS_FAILURES[path] then
          local marks = {}
          for line in out:gmatch("[^\n]+") do
            if line:find("FAIL:", 1, true) then marks[#marks + 1] = line end
          end
          if #marks > 0 then
            assert(false, path .. " reported " .. #marks ..
              " failure(s) but exited 0 (its test() helper pcalls and never " ..
              "sets an exit code)\n--- failures ---\n" ..
              table.concat(marks, "\n"))
          end
        end
      end)
    end
  end)

  -- Guard against a new standalone script being added and silently orphaned
  -- all over again.
  it("manifest covers every standalone script on disk", function()
    local seen = {}
    for _, p in ipairs(INCLUDED) do seen[p] = true end
    for _, e in ipairs(EXCLUDED) do seen[e.file] = true end

    local found, missing = {}, {}
    local p = assert(io.popen(
      "ls -1 tests/*.lua test_*.lua 2>/dev/null", "r"))
    for line in p:lines() do found[#found + 1] = line end
    p:close()

    for _, f in ipairs(found) do
      if not seen[f] then missing[#missing + 1] = f end
    end
    assert(#missing == 0,
      "standalone script(s) not listed in INCLUDED or EXCLUDED -- add them, " ..
      "or they run nowhere:\n  " .. table.concat(missing, "\n  "))
    assert(#found == #INCLUDED + #EXCLUDED, string.format(
      "manifest lists %d scripts but %d are on disk",
      #INCLUDED + #EXCLUDED, #found))
  end)
end)
