#!/usr/bin/env node
import { existsSync } from "node:fs";
import { scanPath } from "../src/scan.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
const targets = args.filter((a) => !a.startsWith("--"));
if (!targets.length || args.includes("--help")) {
  console.log(`Usage: fivem-backdoor-scanner <resource or server folder> [more folders] [--json]

Static check of .lua and .js files for hidden loaders, remote code, obfuscated payloads, secret reads and leaked tokens.
Nothing is executed or uploaded. Exit code: 0 clean or partial, 1 findings, 2 usage error.
Browser version: https://rpscripts.net/tools/fivem-backdoor-scanner/`);
  process.exit(targets.length ? 0 : 2);
}
for (const t of targets)
  if (!existsSync(t)) {
    console.error(`Not found: ${t}`);
    process.exit(2);
  }

const reports = targets.map((target) => ({ target, ...scanPath(target) }));
if (json) console.log(JSON.stringify(reports, null, 2));
else
  for (const r of reports) {
    console.log(`\n${r.target}: ${r.verdict.toUpperCase()} (${r.scanned} Lua files analysed, ${r.findings.length} findings)`);
    for (const f of r.findings) console.log(`  ${f.severity === "error" ? "ERROR" : "warn "} ${f.code} ${f.path}${f.line ? `:${f.line}` : ""}\n        ${f.title}: ${f.message}\n        ${f.fix}`);
    const notes = [
      [r.escrowed, "escrow-encrypted folders (only FXServer can read them)"],
      [r.unparsed, "Lua files that did not parse (only text checks ran)"],
      [r.javascript, "JavaScript files (only text checks ran)"],
      [r.unreadable, "compiled Lua (not readable)"],
      [r.skipped, "files over 2 MB (not read)"],
    ];
    for (const [list, label] of notes) if (list.length) console.log(`  ${list.length} ${label}: ${list.slice(0, 5).join(", ")}${list.length > 5 ? ", …" : ""}`);
  }
process.exit(reports.some((r) => r.findings.length) ? 1 : 0);
