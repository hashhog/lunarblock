#!/usr/bin/env bash
# Parse-check Lua sources without writing bytecode.
#
# Replaces `for f in src/*.lua; do luajit -b "$f" /dev/null; done`, which
# segfaults intermittently (~35-50% of runs) on src/peerman.lua inside
# LuaJIT 2.1's bytecode writer (-b), while `luajit -bl` and loadfile() parse the
# same file cleanly 20/20. loadfile() runs the full parser, so a syntax error
# still fails; it never emits bytecode, so the writer bug is not reachable.
#
# Usage: tools/parse-check.sh [file.lua ...]   (default: src/*.lua)
# Exit 0 if every file parses; 1 (naming each file) otherwise.
set -u
cd "$(dirname "$0")/.."
files=("$@")
[ ${#files[@]} -gt 0 ] || files=(src/*.lua)
fail=0
for f in "${files[@]}"; do
    # File goes in via the environment, NOT as a script argument: `luajit -e
    # CODE file` would also EXECUTE file (src/main.lua would start a node).
    if ! out=$(PARSE_CHECK_FILE="$f" luajit -e 'local f,e=loadfile(os.getenv("PARSE_CHECK_FILE")); if not f then io.stderr:write(e,"\n") os.exit(1) end' </dev/null 2>&1); then
        echo "PARSE FAIL $f: $out" >&2
        fail=1
    fi
done
exit $fail
