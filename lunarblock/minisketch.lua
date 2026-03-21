--- Minisketch implementation for BIP330 Erlay transaction reconciliation.
-- Provides FFI bindings to libminisketch when available, with a pure Lua
-- fallback implementation using GF(2^32) arithmetic.
local ffi = require("ffi")
local M = {}

--------------------------------------------------------------------------------
-- FFI Bindings (if libminisketch is available)
--------------------------------------------------------------------------------

local minisketch_lib = nil
local use_ffi = false

-- Try to load libminisketch
local function init_minisketch_ffi()
  if minisketch_lib ~= nil then
    return minisketch_lib
  end

  -- Define the minisketch C interface
  pcall(function()
    ffi.cdef[[
      typedef struct minisketch minisketch;

      minisketch* minisketch_create(uint32_t bits, uint32_t implementation, size_t capacity);
      void minisketch_destroy(minisketch* sketch);
      minisketch* minisketch_clone(const minisketch* sketch);

      uint32_t minisketch_bits(const minisketch* sketch);
      size_t minisketch_capacity(const minisketch* sketch);
      size_t minisketch_serialized_size(const minisketch* sketch);

      void minisketch_add_uint64(minisketch* sketch, uint64_t element);

      size_t minisketch_serialize(const minisketch* sketch, unsigned char* output);
      void minisketch_deserialize(minisketch* sketch, const unsigned char* input);

      void minisketch_merge(minisketch* sketch, const minisketch* other);

      ptrdiff_t minisketch_decode(const minisketch* sketch, size_t max_elements, uint64_t* output);
    ]]
  end)

  -- Try to load the library from various paths
  local paths = {
    "minisketch",
    "libminisketch",
    "./lib/libminisketch.so",
    "libminisketch.so.0",
  }

  for _, path in ipairs(paths) do
    local ok, lib = pcall(ffi.load, path)
    if ok then
      minisketch_lib = lib
      use_ffi = true
      return lib
    end
  end

  return nil
end

-- Initialize on module load
init_minisketch_ffi()

--------------------------------------------------------------------------------
-- Pure Lua GF(2^32) Arithmetic for Minisketch Fallback
--------------------------------------------------------------------------------

-- GF(2^32) with primitive polynomial x^32 + x^7 + x^3 + x^2 + 1
-- This is the polynomial used by Bitcoin Core's minisketch for 32-bit elements
local GF32_POLY = 0x8D  -- x^7 + x^3 + x^2 + 1 (lower bits after x^32 reduction)

local bit = require("bit")
local band, bxor, lshift, rshift = bit.band, bit.bxor, bit.lshift, bit.rshift

-- GF(2^32) multiplication using Russian peasant algorithm
local function gf32_mul(a, b)
  local result = 0
  while b ~= 0 do
    if band(b, 1) ~= 0 then
      result = bxor(result, a)
    end
    local high_bit = band(a, 0x80000000)
    a = lshift(a, 1)
    if high_bit ~= 0 then
      a = bxor(a, GF32_POLY)
    end
    a = band(a, 0xFFFFFFFF)  -- Keep 32 bits
    b = rshift(b, 1)
  end
  return result
end

-- GF(2^32) inverse using extended Euclidean algorithm
-- For field elements, a^(2^32 - 2) = a^(-1)
local function gf32_inv(a)
  if a == 0 then return 0 end

  -- Use Fermat's little theorem: a^(-1) = a^(2^32 - 2)
  -- This is slow but correct; for production, use lookup tables
  local result = 1
  local base = a
  local exp = 0xFFFFFFFE  -- 2^32 - 2

  while exp > 0 do
    if band(exp, 1) ~= 0 then
      result = gf32_mul(result, base)
    end
    base = gf32_mul(base, base)
    exp = rshift(exp, 1)
  end
  return result
end

-- GF(2^32) division
local function gf32_div(a, b)
  return gf32_mul(a, gf32_inv(b))
end

--------------------------------------------------------------------------------
-- Pure Lua Minisketch Implementation
--------------------------------------------------------------------------------

-- A sketch is represented as a polynomial in GF(2^32)
-- For capacity c, we store c coefficients (syndromes)
local LuaSketch = {}
LuaSketch.__index = LuaSketch

function LuaSketch.new(field_bits, capacity)
  assert(field_bits == 32, "Pure Lua minisketch only supports field_bits=32")
  local self = setmetatable({}, LuaSketch)
  self.field_bits = field_bits
  self.capacity = capacity
  self.syndromes = {}
  -- Initialize syndromes to 0
  for i = 1, capacity do
    self.syndromes[i] = 0
  end
  return self
end

function LuaSketch:clone()
  local copy = LuaSketch.new(self.field_bits, self.capacity)
  for i = 1, self.capacity do
    copy.syndromes[i] = self.syndromes[i]
  end
  return copy
end

-- Add an element to the sketch
-- For syndrome S_i, adding element e computes S_i = S_i XOR e^i
function LuaSketch:add(element)
  element = band(element, 0xFFFFFFFF)
  if element == 0 then return end  -- 0 is not a valid element

  local power = element
  for i = 1, self.capacity do
    self.syndromes[i] = bxor(self.syndromes[i], power)
    power = gf32_mul(power, element)
  end
end

-- Serialize the sketch to bytes (4 bytes per syndrome, little-endian)
function LuaSketch:serialize()
  local bytes = {}
  for i = 1, self.capacity do
    local v = self.syndromes[i]
    bytes[#bytes + 1] = string.char(
      band(v, 0xFF),
      band(rshift(v, 8), 0xFF),
      band(rshift(v, 16), 0xFF),
      band(rshift(v, 24), 0xFF)
    )
  end
  return table.concat(bytes)
end

-- Deserialize bytes into the sketch
function LuaSketch:deserialize(data)
  assert(#data == self.capacity * 4, "Invalid serialized sketch size")
  for i = 1, self.capacity do
    local offset = (i - 1) * 4 + 1
    local b1, b2, b3, b4 = data:byte(offset, offset + 3)
    self.syndromes[i] = b1 + lshift(b2, 8) + lshift(b3, 16) + lshift(b4, 24)
  end
end

-- Merge another sketch into this one (XOR syndromes)
function LuaSketch:merge(other)
  assert(self.capacity == other.capacity, "Capacity mismatch")
  for i = 1, self.capacity do
    self.syndromes[i] = bxor(self.syndromes[i], other.syndromes[i])
  end
end

-- Berlekamp-Massey algorithm to find the error locator polynomial
local function berlekamp_massey(syndromes)
  local n = #syndromes
  -- Connection polynomial C(x) and previous polynomial B(x)
  local C = {1}
  local B = {1}
  local L = 0  -- Current LFSR length
  local m = 1  -- Number of iterations since L changed
  local b = 1  -- Previous discrepancy

  for i = 1, n do
    -- Calculate discrepancy
    local d = syndromes[i]
    for j = 1, L do
      if C[j + 1] then
        d = bxor(d, gf32_mul(C[j + 1], syndromes[i - j] or 0))
      end
    end

    if d == 0 then
      m = m + 1
    else
      local T = {}
      for j = 1, #C do T[j] = C[j] end

      -- C(x) = C(x) - d * b^(-1) * x^m * B(x)
      local scale = gf32_mul(d, gf32_inv(b))
      for j = 1, #B do
        local idx = j + m
        C[idx] = bxor(C[idx] or 0, gf32_mul(scale, B[j]))
      end

      if 2 * L <= i - 1 then
        L = i - L
        B = T
        b = d
        m = 1
      else
        m = m + 1
      end
    end
  end

  return C, L
end

-- Find roots of the error locator polynomial using Chien search
local function chien_search(poly, max_roots)
  local roots = {}
  local degree = #poly - 1

  -- Try all possible field elements
  for elem = 1, 0xFFFFFFFF do
    if #roots >= max_roots then break end

    -- Evaluate polynomial at elem
    local sum = 0
    local power = 1
    for i = 1, #poly do
      sum = bxor(sum, gf32_mul(poly[i], power))
      power = gf32_mul(power, elem)
    end

    if sum == 0 then
      -- elem is a root; the element that was added is 1/elem
      roots[#roots + 1] = gf32_inv(elem)
    end

    -- Limit search for performance (we can't actually search 2^32 elements)
    if elem > 100000 then break end
  end

  return roots
end

-- Decode the sketch to recover set differences
-- Returns nil if decoding fails (more differences than capacity)
function LuaSketch:decode(max_elements)
  max_elements = max_elements or self.capacity

  -- Check if all syndromes are zero (no differences)
  local all_zero = true
  for i = 1, self.capacity do
    if self.syndromes[i] ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return {}
  end

  -- Use Berlekamp-Massey to find error locator polynomial
  local locator, num_errors = berlekamp_massey(self.syndromes)

  if num_errors > max_elements then
    return nil, "too many differences"
  end

  -- Note: Full Chien search is infeasible for 32-bit field
  -- In practice, we'd use a more sophisticated algorithm or lookup tables
  -- For this implementation, we return an error for the pure Lua case
  -- when there are differences (the FFI version should be used)
  if num_errors > 0 then
    return nil, "pure Lua decode not fully implemented for non-zero differences"
  end

  return {}
end

function LuaSketch:destroy()
  -- No resources to free in Lua
  self.syndromes = nil
end

function LuaSketch:serialized_size()
  return self.capacity * 4
end

--------------------------------------------------------------------------------
-- FFI Minisketch Wrapper
--------------------------------------------------------------------------------

local FFISketch = {}
FFISketch.__index = FFISketch

function FFISketch.new(field_bits, capacity)
  local self = setmetatable({}, FFISketch)
  self.field_bits = field_bits
  self.capacity = capacity
  self.sketch = minisketch_lib.minisketch_create(field_bits, 0, capacity)
  if self.sketch == nil then
    error("Failed to create minisketch")
  end
  return self
end

function FFISketch:clone()
  local copy = setmetatable({}, FFISketch)
  copy.field_bits = self.field_bits
  copy.capacity = self.capacity
  copy.sketch = minisketch_lib.minisketch_clone(self.sketch)
  return copy
end

function FFISketch:add(element)
  minisketch_lib.minisketch_add_uint64(self.sketch, element)
end

function FFISketch:serialize()
  local size = minisketch_lib.minisketch_serialized_size(self.sketch)
  local buf = ffi.new("unsigned char[?]", size)
  minisketch_lib.minisketch_serialize(self.sketch, buf)
  return ffi.string(buf, size)
end

function FFISketch:deserialize(data)
  minisketch_lib.minisketch_deserialize(self.sketch, data)
end

function FFISketch:merge(other)
  minisketch_lib.minisketch_merge(self.sketch, other.sketch)
end

function FFISketch:decode(max_elements)
  max_elements = max_elements or self.capacity
  local output = ffi.new("uint64_t[?]", max_elements)
  local count = minisketch_lib.minisketch_decode(self.sketch, max_elements, output)
  if count < 0 then
    return nil, "decode failed"
  end
  local result = {}
  for i = 0, count - 1 do
    result[i + 1] = tonumber(output[i])
  end
  return result
end

function FFISketch:destroy()
  if self.sketch ~= nil then
    minisketch_lib.minisketch_destroy(self.sketch)
    self.sketch = nil
  end
end

function FFISketch:serialized_size()
  return tonumber(minisketch_lib.minisketch_serialized_size(self.sketch))
end

--------------------------------------------------------------------------------
-- Public API: Minisketch Class
--------------------------------------------------------------------------------

local Minisketch = {}
Minisketch.__index = Minisketch

--- Create a new Minisketch.
-- @param field_bits number: field size in bits (typically 32 for Erlay)
-- @param capacity number: maximum number of differences that can be recovered
-- @return Minisketch: new sketch object
function M.new(field_bits, capacity)
  local self = setmetatable({}, Minisketch)
  self.field_bits = field_bits
  self.capacity = capacity

  if use_ffi and minisketch_lib then
    self._impl = FFISketch.new(field_bits, capacity)
  else
    self._impl = LuaSketch.new(field_bits, capacity)
  end

  return self
end

--- Add an element to the sketch.
-- @param element number: element to add (32-bit for field_bits=32)
function Minisketch:add(element)
  self._impl:add(element)
end

--- Serialize the sketch to bytes.
-- @return string: serialized sketch data
function Minisketch:serialize()
  return self._impl:serialize()
end

--- Deserialize bytes into the sketch.
-- @param data string: serialized sketch data
function Minisketch:deserialize(data)
  self._impl:deserialize(data)
end

--- Merge another sketch into this one.
-- After merging, this sketch contains the XOR of both sketches,
-- which represents the symmetric difference of their element sets.
-- @param other Minisketch: sketch to merge
function Minisketch:merge(other)
  self._impl:merge(other._impl)
end

--- Decode the sketch to recover set differences.
-- @param max_elements number: maximum elements to decode (optional)
-- @return table|nil: list of differing elements, or nil on failure
-- @return string|nil: error message on failure
function Minisketch:decode(max_elements)
  return self._impl:decode(max_elements)
end

--- Free resources associated with the sketch.
function Minisketch:destroy()
  self._impl:destroy()
end

--- Get the serialized size of the sketch.
-- @return number: size in bytes
function Minisketch:serialized_size()
  return self._impl:serialized_size()
end

--- Clone the sketch.
-- @return Minisketch: copy of this sketch
function Minisketch:clone()
  local copy = setmetatable({}, Minisketch)
  copy.field_bits = self.field_bits
  copy.capacity = self.capacity
  copy._impl = self._impl:clone()
  return copy
end

-- Export class via module
M.Minisketch = Minisketch

--- Check if FFI minisketch is available.
-- @return boolean: true if using native libminisketch
function M.has_ffi()
  return use_ffi and minisketch_lib ~= nil
end

--- Compute the serialized size for a given capacity.
-- @param field_bits number: field size in bits
-- @param capacity number: sketch capacity
-- @return number: serialized size in bytes
function M.serialized_size(field_bits, capacity)
  return math.ceil(field_bits * capacity / 8)
end

return M
