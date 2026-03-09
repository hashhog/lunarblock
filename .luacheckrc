std = "luajit"
include_files = { "src/**/*.lua", "spec/**/*.lua" }
exclude_files = { "src/vendor/**" }
max_line_length = 120
globals = { "describe", "it", "before_each", "after_each", "setup", "teardown", "pending", "spy", "stub", "mock" }
new_read_globals = { "jit", "bit" }
ignore = { "212", "213" }  -- unused arguments, unused loop variables
