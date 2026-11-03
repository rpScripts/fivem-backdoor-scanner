import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import { decodeSource, MAX_SCAN_ZIP, plan } from "./limits.js";
import { scanEntries, scanFiles, scanZip } from "./scan.js";

// Not `stream`: asset folders can hold Lua too, and a backdoor in one is still a backdoor.
const SKIP_DIRS = new Set(["node_modules", ".git"]);

function walk(root) {
  const out = [];
  const visit = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      throw new Error(`cannot read ${dir}: ${e instanceof Error ? e.message : e}`);
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) visit(full);
      } else if (ent.isFile()) out.push({ name: relative(root, full).split(sep).join("/"), full, size: statSync(full).size });
    }
  };
  visit(root);
  return out;
}

function scanFolder(root) {
  const entries = walk(root);
  const { wanted, skipped } = plan(entries.map((e) => ({ name: e.name, size: e.size })));
  const files = {};
  const unreadable = [];
  for (const entry of entries) {
    if (!wanted.has(entry.name)) continue;
    try {
      files[entry.name] = decodeSource(new Uint8Array(readFileSync(entry.full)));
    } catch {
      unreadable.push(entry.name);
    }
  }
  return scanEntries(entries.map((e) => e.name), files, { unreadable, skipped });
}

/**
 * A resource folder, a whole server folder, a ZIP or one file. Rejects with "too_large" / "invalid_zip" / "cannot read …"
 * when the scan could not run; a report is never a guess.
 */
export async function scanPath(target) {
  let st;
  try {
    st = statSync(target);
  } catch {
    throw new Error(`cannot read ${target}`);
  }
  if (st.isDirectory()) return scanFolder(target);
  if (!st.isFile()) throw new Error(`cannot read ${target}`);
  if (target.toLowerCase().endsWith(".zip")) {
    if (st.size > MAX_SCAN_ZIP) throw new Error("too_large");
    return scanZip(new Uint8Array(readFileSync(target)));
  }
  return scanFiles({ [basename(target)]: decodeSource(new Uint8Array(readFileSync(target))) });
}
