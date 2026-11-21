-- Legitimate: encoded text that is not the name of load, load by its name, a 32-hex hash, placeholders.
local greeting = ("48656C6C6F"):fromhex()
local short = string.char(72, 105)
local label = "pay" .. "load"
local plain = _G["load"]
local hash = "0123456789ABCDEF0123456789ABCDEF"
local placeholder = { steamApiKey = "YOUR_STEAM_KEY" }
local url = ("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=%s"):format(Config.SteamKey)
PerformHttpRequest("https://example.invalid/i?to=abcde", function(status, body) print(body) end)
