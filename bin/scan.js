#!/usr/bin/env node
import { scanPath } from "../src/path.js";

const USAGE = `Usage: fivem-backdoor-scanner <resource folder, server folder or ZIP> [more paths] [--json]

Static check of .lua and .js files for hidden loaders, remote code, obfuscated payloads, secret reads and leaked tokens,
plus executables and unsafe paths in the package. Nothing is executed or uploaded.
Exit code: 0 nothing found (clean or partial), 1 findings, 2 usage error, 3 a scan could not run.
Browser version: https://rpscripts.net/tools/fivem-backdoor-scanner/`;

const args = process.argv.slice(2);
const json = args.includes("--json");
const unknown = args.find((a) => a.startsWith("-") && a !== "--json" && a !== "--help" && a !== "-h");
const targets = args.filter((a) => !a.startsWith("-"));
if (args.includes("--help") || args.includes("-h")) {
  console.log(USAGE);
  process.exit(0);
}
if (unknown || !targets.length) {
  if (unknown) console.error(`Unknown option: ${unknown}`);
  console.error(USAGE);
  process.exit(2);
}

const failureText = (message) => (message === "too_large" ? "the ZIP is larger than 300 MB; scan the unpacked folder instead" : message === "invalid_zip" ? "not a valid ZIP" : message);

const reports = [];
for (const target of targets) {
  try {
    reports.push({ target, ...(await scanPath(target)) });
  } catch (e) {
    console.error(`${target}: ${failureText(e instanceof Error ? e.message : String(e))}`);
    process.exit(3);
  }
}

if (json) console.log(JSON.stringify(reports, null, 2));
else
  for (const r of reports) {
    console.log(`\n${r.target}: ${r.verdict.toUpperCase()} (${r.scanned} Lua files analysed, ${r.notAnalyzed} not fully analysed, ${r.findings.length} findings)`);
    for (const f of r.findings) console.log(`  ${f.severity === "error" ? "ERROR" : "warn "} ${f.code} ${f.path ?? ""}${f.line ? `:${f.line}` : ""}\n        ${f.title}: ${f.message}\n        ${f.fix}`);
    const notes = [
      [r.escrowed, "escrow-encrypted folders (only FXServer can read them)"],
      [r.unparsed, "Lua files that did not parse (only text checks ran)"],
      [r.javascript, "JavaScript files (only text checks ran)"],
      [r.unreadable, "files that could not be read (compiled Lua, corrupt or aliased ZIP entries)"],
      [r.skipped, "files over the size limits (not read)"],
      [r.archives, "archives inside the upload (not unpacked)"],
    ];
    for (const [list, label] of notes) if (list.length) console.log(`  ${list.length} ${label}: ${list.slice(0, 5).join(", ")}${list.length > 5 ? ", …" : ""}`);
  }
process.exit(reports.some((r) => r.findings.length) ? 1 : 0);
