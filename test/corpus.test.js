import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { securityRules } from "../src/index.js";

const dir = (name) => new URL(`../corpus/${name}/`, import.meta.url);
const luaFiles = (name) => readdirSync(dir(name)).filter((f) => /\.(?:lua|js)$/.test(f)).sort();
const scan = (name, f) => securityRules(f, readFileSync(new URL(f, dir(name)), "utf8"));

test("corpus: every positive sample gives exactly the codes in expected.json", () => {
  const expected = JSON.parse(readFileSync(new URL("expected.json", dir("positive")), "utf8"));
  const files = luaFiles("positive");
  assert.deepEqual(Object.keys(expected).sort(), files);
  for (const f of files) {
    const r = scan("positive", f);
    assert.equal(r.parsed, true, f);
    assert.deepEqual(r.findings.map((x) => x.code).sort(), [...expected[f]].sort(), f);
  }
});

test("corpus: negative samples stay clean", () => {
  const files = luaFiles("negative");
  assert.ok(files.length > 0);
  for (const f of files) {
    const r = scan("negative", f);
    assert.equal(r.parsed, true, f);
    assert.deepEqual(r.findings, [], f);
  }
});

test("LAB-SEC-107 stays linear: a 500 KB line of blanks finishes in under 100 ms", () => {
  const start = performance.now();
  const r = securityRules("server.lua", `print('ok')${" ".repeat(500_000)}`);
  assert.ok(performance.now() - start < 100);
  assert.deepEqual(r.findings, []);
  assert.equal(r.parsed, true);
});

test("LAB-SEC-111 stays linear: 40,000 unclosed Buffer.from( calls finish in under 2 s", () => {
  const start = performance.now();
  const r = securityRules("server.js", `eval(x);\n${"Buffer.from(".repeat(40_000)}`);
  assert.ok(performance.now() - start < 2_000);
  assert.deepEqual(r.findings, []);
});
