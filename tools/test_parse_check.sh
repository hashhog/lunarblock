#!/usr/bin/env bash
# Controls for tools/parse-check.sh: good file passes, syntax error fails,
# and the checked file is parsed but never executed.
set -u
cd "$(dirname "$0")/.."
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
printf 'local x = 1\n' > "$d/good.lua"
printf 'local x = = 1\n' > "$d/bad.lua"
printf 'io.open("%s/ran","w"):close()\n' "$d" > "$d/side.lua"
bash tools/parse-check.sh "$d/good.lua" 2>/dev/null || { echo "FAIL good file rejected"; fail=1; }
bash tools/parse-check.sh "$d/bad.lua" 2>/dev/null && { echo "FAIL syntax error accepted"; fail=1; }
bash tools/parse-check.sh "$d/side.lua" 2>/dev/null
[ -e "$d/ran" ] && { echo "FAIL checked file was executed"; fail=1; }
bash tools/parse-check.sh >/dev/null 2>&1 || { echo "FAIL src/*.lua rejected"; fail=1; }
[ $fail -eq 0 ] && echo "parse-check: 4/4 ok"
exit $fail
