import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { strToU8, zipSync } from "fflate";
import { scanPath } from "../src/index.js";

const tmp = () => mkdtempSync(join(tmpdir(), "fbs-"));
const server = (files) => {
  const dir = tmp();
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
};
const cli = (...args) => spawnSync(process.execPath, [new URL("../bin/scan.js", import.meta.url).pathname, ...args], { encoding: "utf8" });

test("verdicts: clean, partial, suspicious, hidden", async () => {
  assert.equal((await scanPath(server({ "shop/fxmanifest.lua": "fx_version 'cerulean'", "shop/server.lua": "print(1)" }))).verdict, "clean");
  assert.equal((await scanPath(server({ "shop/server.lua": "print(1)", "esc/client.fxap": "x", "esc/c.lua": "print(2)" }))).verdict, "partial");
  assert.equal((await scanPath(server({ "a/server.lua": "os.execute('x')" }))).verdict, "suspicious");
  assert.equal((await scanPath(server({ "a/server.lua": `a()${" ".repeat(500)}load(x)()` }))).verdict, "hidden");
});

test("skips node_modules, reads compiled Lua as unreadable, reports escrow folders", async () => {
  const r = await scanPath(server({ "a/node_modules/x/evil.js": `a${" ".repeat(500)}b`, "a/b.lua": "\x1bLua\x54", "enc/x.fxap": "", "ok.lua": "print(1)" }));
  assert.deepEqual([r.findings.length, r.unreadable, r.escrowed], [0, ["a/b.lua"], ["enc/"]]);
});

test("a stream folder is scanned like any other", async () => {
  const r = await scanPath(server({ "r/stream/loader.lua": "os.execute('x')" }));
  assert.deepEqual(r.findings.map((f) => f.code), ["LAB-SEC-106"]);
});

test("a folder with an executable or unsafe archive path gets the package findings", async () => {
  const r = await scanPath(server({ "r/server.lua": "print(1)", "r/install.bat": "echo" }));
  assert.deepEqual(r.findings.map((f) => f.code), ["LAB-PKG-004"]);
});

test("a ZIP is scanned like a folder", async () => {
  const file = join(tmp(), "pack.zip");
  writeFileSync(file, zipSync({ "server.lua": strToU8("os.execute('x')") }));
  const out = cli(file, "--json");
  assert.equal(out.status, 1);
  assert.ok(JSON.parse(out.stdout)[0].findings.some((f) => f.code === "LAB-SEC-106"));
});

test("CLI exit codes: 0 nothing found, 1 findings, 2 usage, 3 the scan could not run", () => {
  assert.equal(cli(server({ "s.lua": "print(1)" })).status, 0);
  const bad = cli(server({ "s.lua": "os.execute('x')" }), "--json");
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout)[0].findings[0].code, "LAB-SEC-106");
  assert.equal(cli().status, 2);
  assert.equal(cli("--nope", "x").status, 2);
  assert.equal(cli("/does/not/exist").status, 3);
  const notZip = join(tmp(), "bad.zip");
  writeFileSync(notZip, "not a zip");
  assert.equal(cli(notZip).status, 3);
});
