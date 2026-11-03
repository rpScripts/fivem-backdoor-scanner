# Contributing

Thanks for helping server owners catch backdoors earlier.

## Ground rules

- **No live malware.** Defang every sample: replace hosts with `example.com`, `example.invalid` or TEST-NET addresses
  (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), and cut payloads to the smallest code that still matches.
- **No credentials or personal data.** No webhooks, tokens, license keys, player identifiers or dumps from real servers,
  even "dead" ones. A sample for LAB-SEC-108 uses an invented id and filler characters in the shape of the real value.
- **No naming and shaming.** Describe a pattern, not a seller or a server.
- **One change per pull request**: one new rule, one false-positive fix, or one corpus addition.

## A new rule or a rule change

1. Open an issue with the pattern, where it was seen (resource type, not a link to a leak), and why existing rules miss it.
2. Add the rule to `rules/catalog.json` (severity, confidence, method, title, fix) and the check to `src/rules.js`.
3. Add a positive sample to `corpus/positive/<code>-<short-name>.lua` and its expected codes to `corpus/positive/expected.json`.
4. Add at least one negative sample that looks similar but is legitimate (common in ox_lib, qb-core, esx, txAdmin-era resources).
5. Keep the check linear in input size; a single 500 KB line must finish in under 100 ms (see `test/corpus.test.js`).
6. Run `npm test`. Every corpus file must give exactly its expected codes.
7. Add the change to `rules/CHANGELOG.md`. A rule code never changes meaning.

The web scanner at rpscripts.net runs the same rules. A rule change is released there and here with the same ruleset version.

## False positives

Open an issue with the smallest snippet that triggers the rule wrongly. If you can, send a pull request that adds it to
`corpus/negative/` together with the fix.

## Code style

Plain JavaScript (ES modules, Node 18+), no build step, so `npx github:rpScripts/fivem-backdoor-scanner` works. Runtime
dependencies are `luaparse` (Lua parsing) and `fflate` (ZIP inflation). Commit messages follow Conventional Commits
(`feat(rules): …`, `fix(sec-105): …`).

## License of contributions

By opening a pull request you agree that your contribution is licensed under the license of this repository (MIT).
