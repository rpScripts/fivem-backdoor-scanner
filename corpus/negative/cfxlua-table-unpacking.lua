-- Legitimate CfxLua: table unpacking in a local declaration must parse, so the Lua checks run on the file.
local function notify(data)
    local title, duration in data
    print(title, duration)
end
