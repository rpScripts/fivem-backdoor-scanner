-- Defanged shape: the name of load kept in a table as hex text, nothing else. No URL, no payload.
string.fromhex = function(s) return (s:gsub("..", function(c) return string.char(tonumber(c, 16)) end)) end
Lib = { localize = _G[("6C6F6164"):fromhex()] }
