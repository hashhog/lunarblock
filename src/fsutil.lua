-- lunarblock.fsutil — filesystem helpers that never spawn a shell.
--
-- Every helper here replaces an os.execute / io.popen that used to build a
-- shell command line out of a path ("mkdir -p '<dir>'", "ls -1 '<dir>'",
-- "du -sb '<dir>'", "test -d <dir>"). Some of those paths came from RPC input
-- (wallet names, backup destinations), so a name containing a quote ran
-- arbitrary commands as the node's user. These helpers call libc directly
-- through the FFI, so a path is only ever a path.

local ffi = require("ffi")
local bit = require("bit")

local M = {}

-- Each declaration is cdef'd separately and under pcall: other modules
-- (wallet.lua, storage.lua) cdef some of the same libc symbols, and LuaJIT
-- refuses to redefine a declaration.
local function cdef(s) pcall(ffi.cdef, s) end
cdef("int mkdir(const char *pathname, unsigned int mode);")
cdef("int chmod(const char *pathname, unsigned int mode);")
cdef("typedef struct __lunarblock_DIR lunarblock_DIR;")
cdef([[
struct lunarblock_dirent {
  uint64_t d_ino;
  int64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[256];
};
]])
cdef("lunarblock_DIR *opendir(const char *name);")
cdef("struct lunarblock_dirent *readdir(lunarblock_DIR *dirp);")
cdef("int closedir(lunarblock_DIR *dirp);")
cdef("int open(const char *pathname, int flags, ...);")
cdef("int close(int fd);")
cdef("long write(int fd, const void *buf, unsigned long count);")
cdef("int fsync(int fd);")

local C = ffi.C

local EEXIST = 17
local DT_DIR, DT_LNK, DT_UNKNOWN = 4, 10, 0
local O_WRONLY, O_CREAT, O_TRUNC = 1, 64, 512

local function valid_path(p)
  return type(p) == "string" and p ~= "" and not p:find("\0", 1, true)
end

--- True when `path` names an existing directory (or a symlink to one).
function M.is_dir(path)
  if not valid_path(path) then return false end
  local d = C.opendir(path)
  if d == nil then return false end
  C.closedir(d)
  return true
end

--- mkdir -p without a shell. Returns true when `path` is a directory
-- afterwards, or false plus an error message.
function M.mkdir_p(path, mode)
  if not valid_path(path) then return false, "invalid path" end
  mode = mode or 493  -- 0755
  local acc = path:sub(1, 1) == "/" and "" or nil
  for comp in path:gmatch("[^/]+") do
    acc = acc and (acc .. "/" .. comp) or comp
    if C.mkdir(acc, mode) ~= 0 then
      local e = ffi.errno()
      if e ~= EEXIST then
        return false, "mkdir " .. acc .. " failed (errno " .. tostring(e) .. ")"
      end
    end
  end
  if not M.is_dir(path) then return false, path .. " is not a directory" end
  return true
end

--- Directory entries (excluding "." and ".."), or nil when `path` cannot be
-- opened. Each entry is {name = string, type = d_type}.
function M.list_dir(path)
  if not valid_path(path) then return nil end
  local d = C.opendir(path)
  if d == nil then return nil end
  local out = {}
  while true do
    local ent = C.readdir(d)
    if ent == nil then break end
    local name = ffi.string(ent.d_name)
    if name ~= "." and name ~= ".." then
      out[#out + 1] = {name = name, type = ent.d_type}
    end
  end
  C.closedir(d)
  table.sort(out, function(a, b) return a.name < b.name end)
  return out
end

local function file_size(path)
  local f = io.open(path, "rb")
  if not f then return 0 end
  local n = f:seek("end") or 0
  f:close()
  return n
end

--- Total apparent size in bytes of the regular files under `path`
-- (recursive; symlinks are not followed). 0 when `path` cannot be read.
function M.dir_size(path)
  local entries = M.list_dir(path)
  if not entries then return 0 end
  local total = 0
  for _, e in ipairs(entries) do
    local child = path .. "/" .. e.name
    if e.type == DT_DIR or (e.type == DT_UNKNOWN and M.is_dir(child)) then
      total = total + M.dir_size(child)
    elseif e.type ~= DT_LNK then
      total = total + file_size(child)
    end
  end
  return total
end

--- Create (or truncate) `path` with permission bits `mode` and write `data`.
-- The mode is applied at open(2) time and re-asserted with chmod(2), so the
-- file is never readable by others even for an instant. Returns true or
-- false plus an error message.
function M.write_file_mode(path, data, mode)
  if not valid_path(path) then return false, "invalid path" end
  -- open(2)'s mode is variadic: pass a real C int, not a Lua double.
  local fd = C.open(path, bit.bor(O_WRONLY, O_CREAT, O_TRUNC), ffi.cast("int", mode))
  if fd < 0 then
    return false, "cannot open " .. path .. " (errno " .. tostring(ffi.errno()) .. ")"
  end
  local off = 0
  while off < #data do
    local chunk = data:sub(off + 1)
    local n = tonumber(C.write(fd, chunk, #chunk))
    if n <= 0 then
      C.close(fd)
      return false, "write to " .. path .. " failed"
    end
    off = off + n
  end
  C.fsync(fd)
  C.close(fd)
  if C.chmod(path, mode) ~= 0 then
    return false, "chmod " .. path .. " failed"
  end
  return true
end

return M
