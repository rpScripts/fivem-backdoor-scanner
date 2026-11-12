# Ruleset changelog

Versions are `YYYY.MM.N`, the same as the ruleset of https://rpscripts.net/tools/fivem-backdoor-scanner/. A rule code
never changes meaning.

## Unreleased

- LAB-SEC-111 (2026-11-12): `Buffer.from(` and a `'base64'` argument are matched apart, so a base64 literal of any length or one split across lines is reported, and a file of unclosed `Buffer.from(` calls is scanned in linear time. Same change as the web scanner; the ruleset version is unchanged so far.

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
