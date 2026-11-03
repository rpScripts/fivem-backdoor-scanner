import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { securityRules } from "./rules.js";

export const MAX_FILE = 2 * 1024 * 1024;
const SCANNED = /\.(?:lua|js)$/i;
const SKIP_DIRS = new Set(["node_modules", ".git"]);

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const latin1 = new TextDecoder("latin1");
/** Lua reads source as bytes: non-UTF-8 files are read as Latin-1 so no byte is dropped from the checks. */
function decode(bytes) {
  try {
    return utf8.decode(bytes);
  } catch {
    return latin1.decode(bytes);
  }
}

function* files(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* files(full);
    } else if (entry.isFile()) yield full;
  }
}

/**
 * Scans a file or folder. Verdict: hidden (hidden code found), suspicious (other findings), partial (nothing found but
 * something could not be analysed), clean (every Lua file analysed in full, nothing found).
 */
export function scanPath(target) {
  const root = statSync(target).isDirectory() ? target : null;
  const report = { findings: [], scanned: 0, javascript: [], unparsed: [], unreadable: [], skipped: [], escrowed: [] };
  const escrowed = new Set();
  for (const file of root ? files(root) : [target]) {
    const path = (root ? relative(root, file) : file).split(sep).join("/");
    if (path.endsWith(".fxap")) escrowed.add(path.split("/").slice(0, -1).join("/") || ".");
    if (!SCANNED.test(path)) continue;
    if (statSync(file).size > MAX_FILE) {
      report.skipped.push(path);
      continue;
    }
    const bytes = readFileSync(file);
    if (bytes[0] === 0x1b && bytes.subarray(1, 4).toString() === "Lua") {
      report.unreadable.push(path); // compiled Lua bytecode
      continue;
    }
    const { findings, parsed } = securityRules(path, decode(bytes));
    report.findings.push(...findings);
    if (path.toLowerCase().endsWith(".js")) report.javascript.push(path);
    else if (parsed) report.scanned++;
    else report.unparsed.push(path);
  }
  report.escrowed = [...escrowed].sort();
  const limits = report.unparsed.length + report.unreadable.length + report.skipped.length + report.escrowed.length + report.javascript.length;
  report.verdict = report.findings.some((f) => f.severity === "error")
    ? "hidden"
    : report.findings.length
      ? "suspicious"
      : report.scanned === 0 || limits
        ? "partial"
        : "clean";
  return report;
}
