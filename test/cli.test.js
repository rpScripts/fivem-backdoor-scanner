import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scanPath } from "../src/scan.js";

const server = (files) => {
  const dir = mkdtempSync(join(tmpdir(), "fbs-"));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
};
const cli = (...args) => spawnSync(process.execPath, [new URL("../bin/scan.js", import.meta.url).pathname, ...args], { encoding: "utf8" });

test("verdicts: clean, partial, suspicious, hidden", () => {
  assert.equal(scanPath(server({ "shop/fxmanifest.lua": "fx_version 'cerulean'", "shop/server.lua": "print(1)" })).verdict, "clean");
  assert.equal(scanPath(server({ "shop/server.lua": "print(1)", "esc/client.fxap": "x", "esc/c.lua": "print(2)" })).verdict, "partial");
  assert.equal(scanPath(server({ "a/server.lua": "os.execute('x')" })).verdict, "suspicious");
  assert.equal(scanPath(server({ "a/server.lua": `a()${" ".repeat(500)}load(x)()` })).verdict, "hidden");
});

test("skips node_modules, reads compiled Lua as unreadable, reports escrow folders", () => {
  const r = scanPath(server({ "a/node_modules/x/evil.js": `a${" ".repeat(500)}b`, "a/b.lua": "\x1bLua\x54", "enc/x.fxap": "", "ok.lua": "print(1)" }));
  assert.deepEqual([r.findings.length, r.unreadable, r.escrowed], [0, ["a/b.lua"], ["enc"]]);
});

test("CLI exit codes and JSON", () => {
  assert.equal(cli(server({ "s.lua": "print(1)" })).status, 0);
  const bad = cli(server({ "s.lua": "os.execute('x')" }), "--json");
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout)[0].findings[0].code, "LAB-SEC-106");
  assert.equal(cli().status, 2);
  assert.equal(cli("/does/not/exist").status, 2);
});
