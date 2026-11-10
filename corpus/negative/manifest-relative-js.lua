-- Ordinary script paths in a manifest-like table: relative, parent and glob entries are not hidden files.
local scripts = { './server/main.js', '../shared/util.js', 'server/*.js', 'html/app.min.js' }
print("ggWP", #scripts)
