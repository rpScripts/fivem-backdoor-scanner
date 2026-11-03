# FiveM Backdoor Scanner

Checks FiveM resources for backdoors before you start them. It reads `.lua` and `.js` files, parses the Lua and looks
for the patterns known FiveM backdoors use: a loader hidden behind thousands of spaces, code downloaded over HTTP and
passed to `load()`, obfuscated payloads, reads of your license key or RCON password, and tokens left in the files.
It also flags executables and unsafe paths in a package.

Nothing is executed and nothing is uploaded. Same rules as the free
[browser version on RPScripts](https://rpscripts.net/tools/fivem-backdoor-scanner/?utm_source=github&utm_medium=referral&utm_campaign=backdoor-scanner),
which also takes a ZIP or a whole server folder by drag and drop.

## Usage

Node.js 18 or newer. No install needed:

```sh
npx github:rpScripts/fivem-backdoor-scanner ./resources
```

Scan a single resource, several folders, a ZIP (up to 300 MB), or get JSON for your own tooling:

```sh
npx github:rpScripts/fivem-backdoor-scanner ./resources/[shops]/my_shop ./resources/[jobs]
npx github:rpScripts/fivem-backdoor-scanner ./downloaded-pack.zip
npx github:rpScripts/fivem-backdoor-scanner ./resources --json > report.json
```

Exit code `0` = nothing found, `1` = findings, `2` = wrong usage, `3` = a scan could not run (missing path, ZIP that is
not readable or over 300 MB). That makes it usable as a CI step:

```yaml
# .github/workflows/backdoor-scan.yml
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes github:rpScripts/fivem-backdoor-scanner ./resources
```

## What it checks

| Code | Severity | Finds |
|---|---|---|
| LAB-SEC-107 | error | Code pushed out of view after 400+ spaces or tabs (the loader trick of a known backdoor family) |
| LAB-SEC-101 | warning | `load()` / `loadstring()` on the body of an HTTP response |
| LAB-SEC-102 | warning | `load()` on text decoded at runtime (`string.char`, escaped bytes, base64/hex decoders) |
| LAB-SEC-103 | warning | Obfuscated data: long escaped-byte strings, 400+ character base64/hex, long `string.char` lists |
| LAB-SEC-104 | warning | Reads `sv_licenseKey`, `rcon_password`, `sv_tebexSecret`, or the MySQL string in a file that sends HTTP |
| LAB-SEC-105 | warning | HTTP requests to a public raw IP or to an address decoded at runtime |
| LAB-SEC-106 | warning | `os.execute`, `io.popen`, writes outside the own resource, `SaveResourceFile` into other resources |
| LAB-SEC-108 | warning | A real-shaped Discord bot token, Discord webhook, Cfx license key or GitHub token in the files |
| LAB-PKG-004 | warning | `.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.sh`, `.vbs`, `.jar`, `.scr` in a folder or archive (`.dll` is expected next to a `*.net.dll`, a C# resource) |
| LAB-PKG-005 | warning | Archive entry with `..`, an absolute path or a drive letter: extracting it can write outside the target folder |

Warnings are patterns, not proof: a webhook logger can legitimately call a raw IP. Read the reported line and decide.
An error (LAB-SEC-107) means treat the package as compromised. Every finding carries `severity`, `confidence`,
`method`, a fix text and references; the texts are in [`rules/catalog.json`](rules/catalog.json), versions in
[`rules/CHANGELOG.md`](rules/CHANGELOG.md). Rule codes never change meaning.

## Verdicts

- **hidden**: hidden code found.
- **suspicious**: at least one warning.
- **partial**: nothing found, but some files could not be checked in full (escrow-encrypted `.fxap` folders, compiled
  Lua, Lua that did not parse, JavaScript where only the text checks run, files over 2 MB, archives inside the upload).
- **clean**: every Lua file was parsed and checked, nothing found.

Findings always win over coverage. A clean result covers these patterns only. It does not prove a resource is safe.

## Limits

- Escrow-protected code can only be read by FXServer, so no scanner can check it.
- The Lua checks need a parse. CfxLua syntax (`+=`, `?.`, `<const>`, backtick hashes, `/* */`) is supported.
- JavaScript gets the hidden-code and credential checks, not the Lua rules.
- Archives inside a ZIP (`.zip`, `.rar`, `.7z`) are listed, not unpacked. Only `.zip` is read.
- 2 MB per file and 120 MB of code in total. ZIP entries whose header, size or CRC disagree with the central directory,
  or that an extractor would write under another name, are reported as unreadable, never as clean.
- `node_modules` and `.git` are skipped in a folder scan. `stream` folders are scanned.

## Library use

```js
import { scanFiles, scanPath, securityRules } from "fivem-backdoor-scanner";

const one = securityRules("server.lua", source); // { findings, parsed }
const report = await scanPath("./resources"); // folder, ZIP or file
const inMemory = scanFiles({ "server.lua": source });
console.log(report.verdict, report.findings);
```

## Contributing

Found a backdoor the scanner misses, or a false positive in a well-known resource? Open an issue with the pattern
(never a live payload or a token); see [CONTRIBUTING.md](CONTRIBUTING.md). To report a family without publishing it,
see [SECURITY.md](SECURITY.md).

```sh
git clone https://github.com/rpScripts/fivem-backdoor-scanner.git
cd fivem-backdoor-scanner && npm ci && npm test
```

Maintained by [RPScripts](https://rpscripts.net/?utm_source=github&utm_medium=referral&utm_campaign=backdoor-scanner).
MIT licensed. The software is provided "as is", without warranty of any kind.
