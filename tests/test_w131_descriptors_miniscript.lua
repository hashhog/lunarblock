#!/usr/bin/env luajit
-- W131 — Descriptors + Miniscript (BIP-380 / BIP-385 / BIP-389 / BIP-379)
-- Discovery-only audit; 30 gates against Bitcoin Core.
--
-- PASS = behavior matches Core's reference impl.
-- FAIL = divergence (bug) — flagged with bug ID.
-- SKIP = feature MISSING entirely (advisory).
--
-- See audit/w131_descriptors_miniscript.md for full matrix.

package.path = "src/?.lua;lunarblock/?.lua;" .. package.path

local address = require("address")
local miniscript = require("lunarblock.miniscript")

local pass, fail, skip = 0, 0, 0
local function out(tag, name, msg)
  print(("[%s] %s%s"):format(tag, name, msg and (" — " .. msg) or ""))
end
local function gate(name, ok, msg)
  if ok then pass = pass + 1; out("PASS", name) else fail = fail + 1; out("FAIL", name, msg) end
end
local function gate_skip(name, msg)
  skip = skip + 1; out("SKIP", name, msg)
end

local function hex(s)
  local t = {}; for i = 1, #s do t[i] = string.format("%02x", s:byte(i)) end
  return table.concat(t)
end

local function hex2bin(h)
  return (h:gsub("..", function(c) return string.char(tonumber(c, 16)) end))
end

------------------------------------------------------------------------
-- G1 — PolyMod constants
------------------------------------------------------------------------
-- The constants are private to address.lua; we exercise them indirectly
-- via known-good vectors (G4). The function exists.
gate("G1 PolyMod constants present",
  type(address.descriptor_checksum) == "function")

------------------------------------------------------------------------
-- G2 — INPUT_CHARSET length 96, contains all expected glyphs
------------------------------------------------------------------------
-- All 96 characters of Core's INPUT_CHARSET should be accepted (no errors).
local function chk(s) local c = address.descriptor_checksum(s); return c ~= nil end
gate("G2 INPUT_CHARSET accepts hex+()[],",
  chk("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"))

------------------------------------------------------------------------
-- G3 — CHECKSUM_CHARSET (bech32) — checksums use only this alphabet
------------------------------------------------------------------------
local cksum = address.descriptor_checksum("raw(deadbeef)")
gate("G3 cksum length 8",   #cksum == 8)
gate("G3 cksum uses bech32 alphabet",
  cksum:match("^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$") ~= nil)

------------------------------------------------------------------------
-- G4 — Golden cross-check vs Bitcoin Core's Python descsum_create
------------------------------------------------------------------------
-- Each pair computed by `bitcoin-core/test/functional/test_framework/descriptors.py`
-- on the same descriptor text. PASS = byte-identical.
local golden = {
  {"raw(deadbeef)", "89f8spxm"},
  {"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", "gn28ywm7"},
  {"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)", "qd6k7hnr"},
  {"wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", "8zl0zxma"},
  {"wpkh([d34db33f/44h/0h/0h/0/0]0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c)", "cxu278k0"},
  -- Known from Core descriptor_tests.cpp (h-form, canonical):
  {"sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))", "hgmsckna"},
}
local all_match = true
local diffs = {}
for _, gt in ipairs(golden) do
  local c = address.descriptor_checksum(gt[1])
  if c ~= gt[2] then all_match = false; diffs[#diffs + 1] = gt[1]:sub(1, 30) .. " -> " .. tostring(c) end
end
gate("G4 golden vs Python descsum_create (6/6 cases)", all_match,
  all_match and nil or table.concat(diffs, "; "))

------------------------------------------------------------------------
-- G5 — Checksum length boundary distinguishes "wrong length" from "wrong content"
------------------------------------------------------------------------
-- Core: "Expected 8 character checksum, not 7 characters"
-- lunarblock: just "invalid checksum"
-- This is BUG-1 (P2 — error granularity, not consensus impact).
local _, e_short = address.parse_descriptor(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)#1234567")
local _, e_long = address.parse_descriptor(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)#123456789")
local granular = e_short ~= nil and e_long ~= nil
  and e_short:lower():find("length") or e_short:lower():find("character")
gate("G5 length-mismatch error granular (BUG-1: should be 'not N characters')",
  granular ~= nil and granular ~= false,
  "lunarblock returns generic 'invalid checksum' regardless of length")

------------------------------------------------------------------------
-- G6 — Multiple '#' rejected
------------------------------------------------------------------------
local d, err = address.parse_descriptor(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)##aaaaaaaa")
gate("G6 double-# rejected", d == nil)

------------------------------------------------------------------------
-- G7 — pk/pkh/wpkh/combo at top level
-- combo() expansion (BUG-2) flagged here.
------------------------------------------------------------------------
local d_combo = address.parse_descriptor(
  "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)")
local s_combo = address.descriptor_to_script(d_combo, 0, "mainnet")
-- BUG-2: combo should emit 4 scripts; lunarblock emits 1 (P2PKH).
-- For test purposes, we assert combo PARSES; expansion gap noted separately.
gate("G7 combo() parses", d_combo and d_combo.type == "combo")
-- Forward-looking check: 4-script expansion not supported (advisory).
gate_skip("G7b combo() expands to 4 scripts (BUG-2)",
  "lunarblock returns single P2PKH; Core returns P2PK+P2PKH+P2WPKH+P2SH-P2WPKH")

------------------------------------------------------------------------
-- G8 — wpkh() rejects uncompressed pubkey (BUG-3, P0)
------------------------------------------------------------------------
local d_uncompressed = address.parse_descriptor(
  "wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
  .. "5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)")
-- Core: REJECTS. lunarblock: ACCEPTS (produces invalid P2WPKH).
gate("G8 wpkh(uncompressed) rejected (BUG-3 P0)",
  d_uncompressed == nil,
  "lunarblock accepts uncompressed pubkey in wpkh(); produces non-standard scriptPubKey")

------------------------------------------------------------------------
-- G9 — Context enforcement: sh(sh()), wsh(wsh()), wsh(wpkh()) (BUG-4)
------------------------------------------------------------------------
local d_shsh = address.parse_descriptor(
  "sh(sh(pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)))")
local d_wshwsh = address.parse_descriptor(
  "wsh(wsh(pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)))")
local d_wshwpkh = address.parse_descriptor(
  "wsh(wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00))")
gate("G9 sh(sh()) rejected (BUG-4)",   d_shsh == nil,   "Core: 'Can only have sh() at top level'")
gate("G9 wsh(wsh()) rejected (BUG-4)", d_wshwsh == nil, "Core: 'Can only have wsh() at top level or inside sh()'")
gate("G9 wsh(wpkh()) rejected (BUG-4)", d_wshwpkh == nil,
  "Core: wpkh inside wsh is illegal (no native segwit in segwit)")

------------------------------------------------------------------------
-- G10 — addr() top-level only (BUG-5)
------------------------------------------------------------------------
local d_shaddr = address.parse_descriptor(
  "sh(addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4))")
gate("G10 sh(addr()) rejected (BUG-5)", d_shaddr == nil,
  "Core: 'Can only have addr() at top level'")

------------------------------------------------------------------------
-- G11 — raw() / rawtr() top-level only (BUG-6, paired with G9/G10)
------------------------------------------------------------------------
local d_shraw = address.parse_descriptor("sh(raw(76a91400000000000000000000000000000000000000000088ac))")
local d_shrawtr = address.parse_descriptor("sh(rawtr(" .. string.rep("ab", 32) .. "))")
gate("G11 sh(raw()) rejected (BUG-6)", d_shraw == nil)
gate("G11 sh(rawtr()) rejected (BUG-6)", d_shrawtr == nil)

------------------------------------------------------------------------
-- G12 — multi() bounds: 1 ≤ k ≤ n; n ≤ 20 (P2WSH); n ≤ 999 (multi_a / Tapscript)
-- BUG-7: lunarblock returns parsed multi with bogus k=0 or k>n; only fails at
-- descriptor_to_script (silently). Core REJECTS at parse time.
------------------------------------------------------------------------
local d_k0 = address.parse_descriptor(
  "multi(0,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)")
local d_kgtn = address.parse_descriptor(
  "multi(3,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,"
  .. "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)")
gate("G12 multi(k=0) rejected (BUG-7 P0)", d_k0 == nil,
  "lunarblock accepts k=0; emits invalid OP_0 ... OP_CHECKMULTISIG")
gate("G12 multi(k>n) rejected (BUG-7 P0)", d_kgtn == nil,
  "lunarblock accepts k=3,n=2; emits invalid OP_3 OP_2 OP_CHECKMULTISIG")

------------------------------------------------------------------------
-- G13 — sortedmulti lex-sorts pubkey bytes
------------------------------------------------------------------------
local pk1 = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
local pk2 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
-- Declared order: pk1 (03…), pk2 (02…). Sorted lex: pk2 first.
local d_sm = address.parse_descriptor("sortedmulti(1," .. pk1 .. "," .. pk2 .. ")")
local s_sm = address.descriptor_to_script(d_sm, 0, "mainnet")
local sm_hex = hex(s_sm)
-- Expected: 51 21 <pk2-starting-with-02> 21 <pk1-starting-with-03> 52 ae
gate("G13 sortedmulti lex-sorts (pk2 first)",
  sm_hex == "5121" .. pk2 .. "21" .. pk1 .. "52ae",
  "got: " .. sm_hex)

------------------------------------------------------------------------
-- G14 — tr() requires x-only key (BUG-8 P1)
------------------------------------------------------------------------
local d_tr_compressed = address.parse_descriptor(
  "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)")
gate("G14 tr(33-byte compressed) rejected (BUG-8 P1)",
  d_tr_compressed == nil,
  "lunarblock accepts 33-byte key, silently strips prefix byte; Core rejects")

------------------------------------------------------------------------
-- G15 — tr() script-tree compiled into output key (BUG-9 P0 — HIGHEST SEVERITY)
------------------------------------------------------------------------
local xonly = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
local cs_no_tree = address.descriptor_checksum("tr(" .. xonly .. ")")
local cs_with_tree = address.descriptor_checksum(
  "tr(" .. xonly .. ",pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))")
local addrs_no_tree = address.derive_addresses("tr(" .. xonly .. ")#" .. cs_no_tree,
  0, 0, "mainnet")
local addrs_with_tree = address.derive_addresses(
  "tr(" .. xonly .. ",pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))#" .. cs_with_tree,
  0, 0, "mainnet")
gate("G15 tr(K,TREE) ≠ tr(K) address (BUG-9 P0)",
  addrs_no_tree and addrs_with_tree
    and addrs_no_tree[1] ~= addrs_with_tree[1],
  "BUG-9: both produce same address (" .. tostring(addrs_no_tree and addrs_no_tree[1])
    .. "); tree silently dropped — funds locked to wrong output if user expected script-path")

------------------------------------------------------------------------
-- G16 — rawtr() emits OP_1 + raw x-only, no tweak (BIP-385)
------------------------------------------------------------------------
local d_rawtr = address.parse_descriptor("rawtr(" .. string.rep("ab", 32) .. ")")
local s_rawtr = address.descriptor_to_script(d_rawtr, 0, "mainnet")
gate("G16 rawtr() script = OP_1 + 32-byte x-only literal",
  hex(s_rawtr) == "5120" .. string.rep("ab", 32))

------------------------------------------------------------------------
-- G17 — Range on raw pubkey (no xpub/xprv) ERRORS at derive (BUG-10 P1)
------------------------------------------------------------------------
local cs_raw_range = address.descriptor_checksum(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*)")
local addrs_raw_range, err_raw_range = address.derive_addresses(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00/0/*)#" .. cs_raw_range,
  0, 3, "mainnet")
-- Core: "Key path that ends with /*: cannot be extended" — parse rejects.
-- lunarblock: parses + derives 4 IDENTICAL addresses.
local addrs_identical = addrs_raw_range and #addrs_raw_range == 4
  and addrs_raw_range[1] == addrs_raw_range[2]
  and addrs_raw_range[2] == addrs_raw_range[3]
  and addrs_raw_range[3] == addrs_raw_range[4]
gate("G17 range on raw pubkey rejected/errored (BUG-10)",
  addrs_raw_range == nil,
  "lunarblock returns 4 identical addresses (#addrs=" ..
    tostring(addrs_raw_range and #addrs_raw_range) ..
    ", all-identical=" .. tostring(addrs_identical) .. ")")

------------------------------------------------------------------------
-- G18 — Hardened-from-xpub gives clear error at derive
------------------------------------------------------------------------
local xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
local cs_hxpub = address.descriptor_checksum("wpkh(" .. xpub .. "/0h/*)")
local addrs_hxpub, err_hxpub = address.derive_addresses(
  "wpkh(" .. xpub .. "/0h/*)#" .. cs_hxpub, 0, 0, "mainnet")
gate("G18 hardened-from-xpub errors at derive", addrs_hxpub == nil)

------------------------------------------------------------------------
-- G19 — get_descriptor_info hasprivatekeys (BUG-11 P2)
------------------------------------------------------------------------
local info_xprv = address.get_descriptor_info(
  "wpkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U)")
gate("G19 hasprivatekeys=true for xprv (BUG-11)",
  info_xprv and info_xprv.hasprivatekeys == true,
  "lunarblock hardcodes hasprivatekeys=false regardless of key types")

------------------------------------------------------------------------
-- G20 — issolvable correct for addr()/raw() vs others
------------------------------------------------------------------------
local info_addr = address.get_descriptor_info("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)")
local info_raw  = address.get_descriptor_info("raw(76a91400000000000000000000000000000000000000000088ac)")
local info_wpkh = address.get_descriptor_info(
  "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00)")
gate("G20 issolvable=false for addr()",
  info_addr and info_addr.issolvable == false)
gate("G20 issolvable=false for raw()",
  info_raw and info_raw.issolvable == false)
gate("G20 issolvable=true for wpkh()",
  info_wpkh and info_wpkh.issolvable == true)

------------------------------------------------------------------------
-- G21 — BIP-389 multipath <0;1>/* (BUG-12 MISSING)
------------------------------------------------------------------------
local d_mp = address.parse_descriptor("wpkh(" .. xpub .. "/<0;1>/*)")
gate("G21 BIP-389 multipath <0;1>/* parses (BUG-12 MISSING)",
  d_mp ~= nil,
  "lunarblock rejects with 'invalid path element: <0;1>'")

------------------------------------------------------------------------
-- G22 — Origin path accepts both `h` and `'` for hardened
------------------------------------------------------------------------
local k_h = address.parse_key_expression(
  "[d34db33f/44h/0h/0h]02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00")
local apo = string.char(0x27)
local k_apo = address.parse_key_expression(
  "[d34db33f/44" .. apo .. "/0" .. apo .. "/0" .. apo .. "]"
  .. "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00")
gate("G22 h/apostrophe interchangeable (both → same index+0x80000000)",
  k_h and k_apo
    and k_h.origin.path[1] == k_apo.origin.path[1]
    and k_h.origin.path[1] == (44 + 0x80000000))

------------------------------------------------------------------------
-- G23 — Origin fingerprint must be 8 hex chars
------------------------------------------------------------------------
local k_short = address.parse_key_expression(
  "[deadbee/0]02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00")
gate("G23 fingerprint <8 hex rejected", k_short == nil)

------------------------------------------------------------------------
-- G24 — Miniscript THRESH type: subs[0]=Bdu, rest=Wdu (BUG-13 P1)
------------------------------------------------------------------------
-- Build pk + s:pk + s:pk; lunarblock's thresh() rejects this valid form.
local function dummy_pk(prefix)
  return string.char(prefix) .. string.rep("\xab", 32)
end
local k1 = miniscript.pk(dummy_pk(0x02))
local k2 = miniscript.pk(dummy_pk(0x03))
local k3 = miniscript.pk(dummy_pk(0x02))
local ok_thresh, _ = pcall(function()
  return miniscript.thresh(2, {k1, miniscript.wrap_s(k2), miniscript.wrap_s(k3)})
end)
gate("G24 thresh(2, pk, s:pk, s:pk) constructs (BUG-13 P1)",
  ok_thresh,
  "lunarblock requires ALL subs to be Bdu; Core requires subs[0]=Bdu, rest=Wdu")

------------------------------------------------------------------------
-- G25 — older(n) type bit uses SEQUENCE_LOCKTIME_TYPE_FLAG bit (BUG-15 P0)
------------------------------------------------------------------------
-- bit 22 = 0x400000 = 4194304. With this bit set, OLDER is RELATIVE-TIME (g).
-- Without it, OLDER is RELATIVE-HEIGHT (h).
-- lunarblock uses >= 500_000_000 (the CLTV threshold) — wrong for OP_CSV.
local older_with_bit22 = miniscript.older(0x400001)  -- bit 22 set: should be g (time)
local older_without_bit22 = miniscript.older(100)    -- bit 22 not set: should be h (height)
local t_g = miniscript.Type.g
local t_h = miniscript.Type.h
local bit_lib = require("bit")
local function has_g(n) return bit_lib.band(n.type, t_g) ~= 0 end
local function has_h(n) return bit_lib.band(n.type, t_h) ~= 0 end
gate("G25 older(0x400001) classified as relative-time (g) (BUG-15 P0)",
  has_g(older_with_bit22) and not has_h(older_with_bit22),
  ("got g=%s h=%s; lunarblock uses 500M threshold not bit-22"):format(
    tostring(has_g(older_with_bit22)), tostring(has_h(older_with_bit22))))
gate("G25 older(100) classified as relative-height (h)",
  has_h(older_without_bit22) and not has_g(older_without_bit22))

------------------------------------------------------------------------
-- G26 — d: wrapper has `u` under Tapscript (BUG-16 P1)
------------------------------------------------------------------------
-- Core: WRAP_D produces `u` if `IsTapscript(ms_ctx)`.
-- lunarblock: never adds `u`. No MiniscriptContext distinction.
local v1 = miniscript.wrap_v(miniscript.just_1())     -- V from B = Vzfmxk
local d_v1 = miniscript.wrap_d(v1)                     -- B from V z = Bondfmxk (no u)
local t_u = miniscript.Type.u
local has_u = bit_lib.band(d_v1.type, t_u) ~= 0
-- We can't easily express tapscript-context here because lunarblock has no context.
-- Mark as FAIL: even setting `tapscript=true` on node, d:v:1 lacks `u`.
gate("G26 d:v:1 type tracks Tapscript context (BUG-16 P1)",
  false,
  "lunarblock has no MiniscriptContext; d:v:1 type=" ..
    miniscript.type_string(d_v1.type) ..
    " (Core under Tapscript would set 'u' bit)")

------------------------------------------------------------------------
-- G27 — from_policy compiles or() and and()
------------------------------------------------------------------------
local ok_pol, node_pol = pcall(function()
  return miniscript.from_policy(
    "and(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),older(100))")
end)
gate("G27 from_policy(and(pk,older)) compiles",
  ok_pol and node_pol and miniscript.is_valid_top_level(node_pol))

------------------------------------------------------------------------
-- G28 — wsh(<miniscript>) parses as descriptor (BUG-17 P1, MISSING)
------------------------------------------------------------------------
local d_wsh_ms = address.parse_descriptor(
  "wsh(or_d(pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00),"
  .. "and_v(v:pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),older(100))))")
gate("G28 wsh(<miniscript>) descriptor parses (BUG-17 MISSING)",
  d_wsh_ms ~= nil,
  "miniscript is not wired into descriptor parser; only fixed names accepted")

------------------------------------------------------------------------
-- G29 — Miniscript-from-script decoder (BUG-18 MISSING)
------------------------------------------------------------------------
gate_skip("G29 miniscript.from_script/InferScript (BUG-18 MISSING)",
  "no from_script function exported; cannot round-trip script→miniscript")

------------------------------------------------------------------------
-- G30 — BIP-381 musig(...) descriptor (BUG-19 MISSING)
------------------------------------------------------------------------
local d_musig = address.parse_descriptor(
  "wpkh(musig(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abf2d91d92e47e00,"
  .. "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))")
gate("G30 musig(K1,K2) inside wpkh() parses (BUG-19 MISSING)",
  d_musig ~= nil,
  "lunarblock has no musig() parser; Core supports BIP-381 MuSig2 since v28")

------------------------------------------------------------------------
-- Summary
------------------------------------------------------------------------
print()
print(string.rep("=", 60))
print(("W131 DESCRIPTORS + MINISCRIPT (lunarblock) — %d PASS, %d FAIL, %d SKIP"):format(pass, fail, skip))
print(("Discovery: %d bugs catalogued; see audit/w131_descriptors_miniscript.md"):format(19))
print(string.rep("=", 60))

-- Discovery-only audit: report findings; exit 0 even on failures (each FAIL
-- documents a known divergence we are not fixing in this wave).
os.exit(0)
