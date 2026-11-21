# Ruleset changelog

Versions are `YYYY.MM.N`, the same as the ruleset of https://rpscripts.net/tools/fivem-backdoor-scanner/. A rule code
never changes meaning.

## 2026.11.17

- No LAB-SEC or LAB-PKG rule changed. The web scanner now counts exports from modules loaded with `require`, reads only manifest-loaded files for its ox_lib check, treats nil comparisons as probes and ignores a `__resource.lua` shadowed by an `fxmanifest.lua`. These are resource checks, which this scanner does not have.

## 2026.11.16

- No LAB-SEC or LAB-PKG rule changed. The web scanner's framework API check no longer reads a player taken from another framework's export (`exports['echorp']:GetPlayerFromId`) as an ESX xPlayer. This is a resource check, which this scanner does not have.

## 2026.11.15

- No LAB-SEC or LAB-PKG rule changed. The web scanner's ox_lib manifest check no longer reads a legacy `__resource.lua` as code and accepts ox_lib's manual import `load(LoadResourceFile('ox_lib', 'init.lua'))`. This is a resource check, which this scanner does not have.

## 2026.11.14

- No LAB-SEC or LAB-PKG rule changed. The web scanner now counts global functions a manifest loads from another resource of the same pack (`@res/file.lua`), leaves exports of a resource with obfuscated JavaScript undecided, reads a player from `<core>.Functions.GetPlayer` as a QBCore-style player whatever the variable is called, and accepts a field the code tests before using it. These are resource and pack checks, which this scanner does not have.

## 2026.11.13

- No LAB-SEC or LAB-PKG rule changed. The web scanner now reads bundled JavaScript that keeps `exports` in a variable (`var e = global.exports; e("name", …)`) as defining those exports, treats an export call inside a function passed straight to `pcall` as a caught probe, and treats a manifest that ships `-- '@ox_lib/init.lua'` commented out as optional ox_lib. These are resource checks, which this scanner does not have.

## 2026.11.12

- No LAB-SEC or LAB-PKG rule changed. The web scanner's manifest check treats `if not lib or … then return end` before a `lib.*` call as a check for ox_lib; that is a resource check, which this scanner does not have.

## 2026.11.11

- No LAB-SEC or LAB-PKG rule changed. The web scanner's framework API index knows ox_lib's `lib.name` and `lib.context`; that is a resource check, which this scanner does not have.

## 2026.11.10

- No LAB-SEC or LAB-PKG rule changed. The web scanner's framework API check accepts calls into a resource a server pack ships when that copy defines the export or player method; that is a resource check, which this scanner does not have.

## 2026.11.9

- No LAB-SEC or LAB-PKG rule changed. The web scanner's framework API check reads `local qbx = exports.qbx_core` then `qbx:GetPlayer()` as an export call, and code that checks `if lib and lib.x then` no longer needs `@ox_lib/init.lua`; both are resource checks, which this scanner does not have.

## 2026.11.8

- No LAB-SEC or LAB-PKG rule changed. The web scanner no longer reports a manifest entry inside the output folder of a `webpack_config` as a missing file (FXServer builds it when the resource starts); that is a resource check, which this scanner does not have.

## 2026.11.7

- CfxLua table unpacking (`local title, duration in data`) is read as `= data`, so the Lua checks run on such files instead of reporting them as not parsed.

## 2026.11.6

- New LAB-SEC-115 (error): the name of `load` / `loadstring` written in encoded form anywhere in a Lua file: its hex or base64 text, escaped bytes, `string.char(108, 111, 97, 100)`, `("…"):fromhex()` or a literal concatenation (`"lo".."ad"`); one per file. A licence loader keeps `_G[("6C6F6164"):fromhex()]` in a table and runs its server's answer through it, which no call-shape check followed.
- LAB-SEC-103 names a file with a Boronide VM header.

## 2026.11.5

- No LAB-SEC or LAB-PKG rule changed. The web scanner's false-alarm fixes of this version concern its resource checks, which this scanner does not have.

## 2026.11.4

- No change to the rules of this scanner. The web scanner's new takeover hosts for LAB-SEC-114 apply to `<script src>` in NUI HTML, which this scanner does not read.

## 2026.11.3

- LAB-SEC-112 knows two more loader hosts, and the family's loader shape on any host: a `PerformHttpRequest` whose URL literal contains `/i?to=` and whose callback runs the reply with `load`.
- LAB-SEC-101, LAB-SEC-102 and LAB-SEC-110 follow `_G[("6C6F6164"):fromhex()]` and `_G[string.char(108, …)]` (the literal is decoded statically) and `_G.load(…)` / `_G[…](…)` called directly. A name computed at runtime is not followed.
- LAB-SEC-108 reports a Steam Web API key (32 hex characters in an `api.steampowered.com/…key=` URL, or assigned to a `steam…key` name). The value is never echoed.
- LAB-SEC-111 (2026-11-12): `Buffer.from(` and a `'base64'` argument are matched apart, so a base64 literal of any length or one split across lines is reported, and a file of unclosed `Buffer.from(` calls is scanned in linear time.

## 2026.11.2

- New LAB-SEC-112: a string of the Blum / Warden / Cipher / GFX Panel family in any file (C2 hosts, operator handles and keys, txAdmin tampering markers such as `helpEmptyCode`, `onServerResourceFail`, `RESOURCE_EXCLUDE`), or a manifest that loads a `.js` from a dot file or dot folder, or after a commented-out entry and 20+ spaces. Indicators from https://github.com/ImJer/blum-panel-fivem-backdoor-analysis (iocs 2026.08.07).
- LAB-SEC-101, LAB-SEC-102 and LAB-SEC-110 follow `pcall(load, code)` and `xpcall(load, handler, code)`.
- LAB-SEC-103 names a file with a Luraph header.

## 2026.11.1

- New LAB-SEC-109: `ExecuteCommand` with `add_principal` / `add_ace identifier.<type>:<hex>` (a hard-coded person added to a group).
- New LAB-SEC-110: `load` / `loadstring` on a parameter of an event handler.
- New LAB-SEC-111: JavaScript that uses `eval`, `new Function` or `vm.run*` in a file that also fetches (`fetch`, `http(s)`) or decodes (`atob`, base64, `fromCharCode`) text. Text check only.
- LAB-SEC-101 and LAB-SEC-102 follow aliases of `load`: `local run = loadstring`, `_G.load`, `_G["lo".."ad"]`.
- `child_process` in JavaScript is reported as LAB-SEC-106.

## 2026.10.6

- LAB-SEC-101 … LAB-SEC-108, LAB-PKG-004, LAB-PKG-005 as used by the web scanner.
- LAB-SEC-107 treats space, tab, vertical tab and form feed as blanks and runs in linear time on very long lines.
- LAB-SEC-108 reports a real-shaped Discord bot token or webhook, Cfx license key or GitHub token in the files (the value is never echoed).
- LAB-PKG-004 also matches `.dll` and `.cmd`. `.dll` files are not flagged when the package contains a `*.net.dll` (a C# resource).
