// The backdoor checks of the RPScripts FiveM Backdoor Scanner (https://rpscripts.net/tools/fivem-backdoor-scanner/).
// Static only: files are parsed, never run. Codes never change meaning; same codes as the web scanner's reports.
import { readFileSync } from "node:fs";
import { memberPath, parseLua, stringValue, walk } from "./lua.js";

// Rule texts live in rules/catalog.json, the same entries as the web scanner's rule catalog.
const catalog = JSON.parse(readFileSync(new URL("../rules/catalog.json", import.meta.url), "utf8"));
export const RULESET_VERSION = catalog.rulesetVersion;
export const RULES = catalog.rules;

/** A finding with the rule's texts from the catalog. Codes never change meaning; retired rules keep their code unused. */
export function finding(code, message, at = {}, extraRefs = []) {
  const rule = RULES[code];
  if (!rule) throw new Error(`unknown rule ${code}`);
  return { code, ...rule, message, ...at, refs: [...rule.refs, ...extraRefs], ruleVersion: RULESET_VERSION };
}

const ORDER = { error: 0, warning: 1, info: 2 };
export const sortFindings = (list) =>
  [...list].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (a.path ?? "").localeCompare(b.path ?? "") || (a.line ?? 0) - (b.line ?? 0));

const isCall = (n) => n.type === "CallExpression" || n.type === "StringCallExpression" || n.type === "TableCallExpression";
const argsOf = (c) => (c.type === "CallExpression" ? c.arguments : c.type === "StringCallExpression" ? [c.argument] : [c.arguments]);
const calleeOf = (c) => memberPath(c.base)?.join(".") ?? null;
const lastOf = (name) => name.slice(name.lastIndexOf(".") + 1);
const literal = (e) => (e?.type === "StringLiteral" ? stringValue(e.raw) : null);
const lineOf = (n) => n.loc?.start.line;

function calls(root) {
  const out = [];
  walk(root, (n) => {
    if (isCall(n)) out.push({ call: n, name: calleeOf(n) });
  });
  return out;
}

const ESCAPE = /\\(?:x[0-9a-fA-F]{2}|\d{1,3})/g;
/** Escaped bytes in one literal from which it counts as hidden text (a few \n-style escapes are normal). */
const MIN_ESCAPES = 40;
/** base64 or hex without spaces, this long, is data or code, not text. */
const BLOB = /^(?:[A-Za-z0-9+/]{400,}={0,2}|[0-9a-fA-F]{400,})$/;
/** string.char(…) with this many arguments spells out text byte by byte. */
const MIN_CHAR_ARGS = 20;
const DECODER = /(?:decode|unhex|fromhex|base64|b64|deobf)/i;
const SECRET = /^(?:sv_licenseKey|rcon_password|sv_tebexSecret)$/i;
const DB_SECRET = /^mysql_connection_string$/i;
// A literal URL whose host is a public IPv4 address (private ranges and loopback are local services).
const IP_URL = /^(?:https?:)?\/\/(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}(?:[:/?]|$)/i;
const HTTP = new Set(["PerformHttpRequest", "PerformHttpRequestAwait"]);
const LOADERS = new Set(["load", "loadstring"]);
// `add_principal identifier.license:<hex> …` / `add_ace identifier.…` with a hard-coded person: an admin planted in the file.
const GRANT = /\badd_(?:principal|ace)\s+identifier\.[a-z0-9]+:[0-9a-f]{6,}/i;
const JS_FILE = /\.(?:[cm]?js)$/i;
const JS_RUN = /\b(?:eval|runIn(?:This|New)Context)\s*\(|\bnew\s+(?:Function|vm\.Script)\s*\(/;
const JS_NET = /\b(?:fetch|axios|got)\s*\(|\bhttps?\.(?:get|request)\s*\(|require\(\s*['"](?:node:)?https?['"]\s*\)|\bXMLHttpRequest\b/;
const JS_DECODE = /\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]|String\.fromCharCode|\bunescape\s*\(/;
const JS_PROCESS = /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]/;

/** A string built only from literals (`"lo".."ad"`), else null. */
function folded(e) {
  if (e?.type === "StringLiteral") return stringValue(e.raw);
  if (e?.type === "BinaryExpression" && e.operator === "..") {
    const left = folded(e.left);
    const right = folded(e.right);
    return left !== null && right !== null ? left + right : null;
  }
  return null;
}

/** Names that stand for load/loadstring: `local run = loadstring`, `_G.load`, `_G["lo".."ad"]`, aliases of aliases. */
function loaderNames(root) {
  const names = new Set(LOADERS);
  const global = (b) => b.type === "Identifier" && (b.name === "_G" || b.name === "_ENV");
  const isLoader = (e) =>
    e.type === "Identifier" ? names.has(e.name)
    : e.type === "MemberExpression" ? global(e.base) && LOADERS.has(e.identifier.name)
    : e.type === "IndexExpression" ? global(e.base) && LOADERS.has(folded(e.index) ?? "")
    : false;
  walk(root, (n) => {
    if (n.type === "LocalStatement" || n.type === "AssignmentStatement")
      n.init.forEach((e, i) => {
        const v = n.variables[i];
        if (v?.type === "Identifier" && isLoader(e)) names.add(v.name);
      });
  });
  return names;
}

// JavaScript has no parser here: text checks only. Runs fetched or decoded text, or starts programs on the host.
function jsRules(path, source) {
  const out = [];
  const run = JS_RUN.exec(source);
  if (run && (JS_NET.test(source) || JS_DECODE.test(source)))
    out.push(finding("LAB-SEC-111", "This JavaScript runs text with eval/new Function/vm and also fetches or decodes text.", { path, line: lineAt(source, run.index) }));
  const proc = JS_PROCESS.exec(source);
  if (proc) out.push(finding("LAB-SEC-106", "child_process runs programs on the server's host.", { path, line: lineAt(source, proc.index) }));
  return out;
}

const escapes = (raw) => raw.match(ESCAPE)?.length ?? 0;

/** Text decoded at runtime: string.char, decoder functions or literals written as escaped bytes. */
function hidden(e) {
  let found = false;
  walk(e, (n) => {
    if (found) return;
    if (n.type === "StringLiteral" && escapes(n.raw) >= 8) found = true;
    if (isCall(n)) {
      const name = calleeOf(n);
      if (name === "string.char" || (name && DECODER.test(lastOf(name)))) found = true;
    }
  });
  return found;
}

// Code pushed far past the right edge by a long run of spaces: how a known FiveM backdoor family hides its loader.
// A comment after the gap is no code. The run is matched atomically (lookahead + backreference) so a long run without
// code after it cannot backtrack quadratically. Blanks are Lua's in-line whitespace: space, tab, \v, \f.
const HIDDEN_CODE = /(?<![ \t\v\f])(?=([ \t\v\f]{400,}))\1(?!--|\/\/|\/\*)\S/;

const lineAt = (source, index) => source.slice(0, index).split("\n").length;

function hiddenCode(path, source) {
  const m = HIDDEN_CODE.exec(source);
  return m ? [finding("LAB-SEC-107", "Code continues after a long run of spaces, out of view in any editor.", { path, line: lineAt(source, m.index) })] : [];
}

// Credential shapes precise enough to be real, never placeholders like "YOUR_TOKEN". The value is never echoed.
const CREDENTIALS = [
  ["a Discord bot token", /(?<![\w.-])[MNO][\w-]{23,27}\.[\w-]{6}\.[\w-]{27,40}(?![\w-])/],
  ["a Discord webhook URL", /discord(?:app)?\.com\/api\/webhooks\/\d{15,20}\/[\w-]{30,}/],
  ["a Cfx license key", /\bcfxk_[A-Za-z0-9]{20,}/],
  ["a GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36}\b/],
];

function shippedCredentials(path, source) {
  return CREDENTIALS.flatMap(([kind, re]) => {
    const m = re.exec(source);
    return m ? [finding("LAB-SEC-108", `${path} contains ${kind}. Whoever has the file can use it.`, { path, line: lineAt(source, m.index) })] : [];
  });
}

// Indicators of the Blum / Warden / Cipher / GFX Panel family (github.com/ImJer/blum-panel-fivem-backdoor-analysis,
// iocs 2026.08.07): C2 hosts, operator handles and keys, txAdmin tampering markers. Exact strings only; left out as too
// common: "ggWP" alone, decompressFromUTF16 (lz-string), the dropper file names (main.js, index.js, …).
const BLUM_HOSTS =
  "0xchitado.com 2312321321321213.com 2nit32.com 2ns3.net 5mscripts.net 9ns1.com bhlool.com blum-panel.com blum-panel.me bybonvieux.com cipher-panel.me ciphercheats.com dark-utilities.xyz fivemgtax.com fivems.lt flowleakz.org gfxpanel.org giithub.net iwantaticket.org jking.lt keyx.club kutingplays.com l00x.org monloox.com noanimeisgay.com ryenz.net spacedev.fr trezz.org useer.it.com warden-panel.me wsichkidolu.com z1lly.org";
const BLUM = new RegExp(
  String.raw`(?<![\w-])(?:${BLUM_HOSTS.replaceAll(".", String.raw`\.`).replaceAll(" ", "|")})(?![\w-])|(?<![A-Za-z])[bB]ert[jJ][jJ]|miaus(?:s|as)|GlobalState\.ggWP|txadmin:js_create|\b(?:helpEmptyCode|onServerResourceFail|RESOURCE_EXCLUDE|isExcludedResource|JohnsUrUncle|installed_notices|VB8mdVjrzd|UARZT6|1470175544682217685|(?:anon|blum|city|dev|gang|mafia|null|panel|roleplay|zXeAH)JJ)\b`,
);
// A manifest entry that the family smuggles in: a .js after a commented-out entry and a run of spaces, a .js dot file
// (`html/.env.js`), or a .js under `node_modules/.…`. `./x.js`, `../x.js` and build folders like `.next/` are ordinary.
// Both run per line on lines up to MANIFEST_LINE characters: on a whole file they are quadratic (review 2026-11-10).
const MANIFEST_DECOY = /--\[=*\[.*?\]=*\][ \t]{20,}['"][^'"]*\.js['"]/;
const MANIFEST_DOT = /(['"])(?:(?:[^'"]*[\\/])?\.[^'"\\/*]+\.js|(?:[^'"]*[\\/])?node_modules[\\/]\.[^'"]*\.js)\1/;
const MANIFEST_LINE = 2000;
const uncommented = (line) => line.replace(/--\[=*\[.*?\]=*\]/g, "").replace(/--.*$/, "");
const MANIFEST = /(?:^|\/)(?:fxmanifest|__resource)\.lua$/;

function knownBackdoor(path, source) {
  const at = (m) => ({ path, line: lineAt(source, m.index) });
  const out = [];
  const ioc = /\.(?:lua|[cm]?js)$/i.test(path) ? BLUM.exec(source) : null;
  if (ioc) out.push(finding("LAB-SEC-112", `Contains '${ioc[0]}', an indicator of the Blum Panel backdoor family.`, at(ioc)));
  if (MANIFEST.test(path)) {
    const line = source.split("\n").findIndex((l) => l.length <= MANIFEST_LINE && (MANIFEST_DECOY.test(l) || MANIFEST_DOT.test(uncommented(l))));
    if (line >= 0) out.push(finding("LAB-SEC-112", "The manifest loads a JavaScript file from a hidden place (a dot file, node_modules/.…, or after a commented-out entry).", { path, line: line + 1 }));
  }
  // Luraph's header is a comment, which the parser drops; the code below it can't be read by any static check.
  const luraph = path.toLowerCase().endsWith(".lua") ? /Luraph Obfuscator/.exec(source) : null;
  if (luraph) out.push(finding("LAB-SEC-103", "This file is obfuscated with Luraph.", at(luraph)));
  return out;
}

/** A loader call and the arguments it gets, also through `pcall(load, code)` / `xpcall(load, handler, code)`. */
function loadCall(call, name, loaders) {
  const args = argsOf(call);
  if (name && loaders.has(name)) return { name, args };
  const skip = name === "pcall" ? 1 : name === "xpcall" ? 2 : 0;
  const fn = args[0];
  return skip && fn?.type === "Identifier" && loaders.has(fn.name) ? { name: fn.name, args: args.slice(skip) } : null;
}

function luaRules(path, chunk) {
  const out = [];
  const list = calls(chunk);
  const http = list.filter(({ name }) => name && HTTP.has(name));
  const loaders = loaderNames(chunk);
  const remote = new Set();
  // io.popen('ls "…"') / ('dir "…" /b') to list a folder is common in legitimate loaders.
  let lists = false;
  walk(chunk, (n) => {
    if (n.type === "StringLiteral" && /^(?:ls|dir)(?:\s|$)/.test(stringValue(n.raw))) lists = true;
  });

  // Code loaded inside an HTTP response handler: `PerformHttpRequest(url, function(_, body) assert(load(body))() end)`.
  for (const { call } of http)
    for (const fn of argsOf(call).filter((a) => a.type === "FunctionDeclaration"))
      for (const inner of calls(fn)) {
        const run = loadCall(inner.call, inner.name, loaders);
        if (run) {
          remote.add(inner.call);
          out.push(finding("LAB-SEC-101", `${run.name}() runs the body of an HTTP response: whoever controls that server can run any code on yours.`, { path, line: lineOf(inner.call) }));
        }
      }

  for (const { call, name } of list) {
    if (!name) continue;
    const args = argsOf(call);
    const run = loadCall(call, name, loaders);
    if (run && !remote.has(call) && run.args[0] && hidden(run.args[0]))
      out.push(finding("LAB-SEC-102", `${run.name}() runs text that is only decoded at runtime.`, { path, line: lineOf(call) }));
    if ((name === "GetConvar" || name === "GetConvarInt") && args[0]) {
      const convar = literal(args[0]);
      if (convar && (SECRET.test(convar) || (DB_SECRET.test(convar) && http.length > 0)))
        out.push(finding("LAB-SEC-104", `Reads the convar '${convar}'${http.length ? " in a file that also sends HTTP requests" : ""}.`, { path, line: lineOf(call) }));
    }
    if (HTTP.has(name) && args[0] && hidden(args[0]))
      out.push(finding("LAB-SEC-105", "The address of this HTTP request is only decoded at runtime.", { path, line: lineOf(call) }));
    if (name === "ExecuteCommand" && GRANT.test(literal(args[0]) ?? ""))
      out.push(finding("LAB-SEC-109", "ExecuteCommand grants server permissions to a hard-coded identifier.", { path, line: lineOf(call) }));
    if (name === "os.execute" || (name === "io.popen" && !lists))
      out.push(finding("LAB-SEC-106", `${name} runs a program on the server's host.`, { path, line: lineOf(call) }));
    if (name === "io.open" && /^[wa]|\+/.test(literal(args[1]) ?? "") && !JSON.stringify(args[0] ?? null).includes("GetResourcePath"))
      out.push(finding("LAB-SEC-106", "io.open writes to a path that isn't built from GetResourcePath(…).", { path, line: lineOf(call) }));
  }

  // A handler that runs the text its event delivers: whoever can trigger the event runs code on this side.
  for (const { call, name } of list) {
    if (!name || !(name === "RegisterNetEvent" || name === "RegisterServerEvent" || name === "AddEventHandler")) continue;
    for (const fn of argsOf(call).filter((x) => x.type === "FunctionDeclaration")) {
      const params = new Set(fn.parameters.flatMap((x) => (x.type === "Identifier" ? [x.name] : [])));
      for (const inner of calls(fn)) {
        const run = loadCall(inner.call, inner.name, loaders);
        const arg = run?.args[0];
        if (run && arg?.type === "Identifier" && params.has(arg.name))
          out.push(finding("LAB-SEC-110", `${run.name}() runs text delivered by an event.`, { path, line: lineOf(inner.call) }));
      }
    }
  }

  // SaveResourceFile into a resource computed at runtime (e.g. every resource from GetResourceByFindIndex): how
  // backdoors spread. A literal resource name is explicit and not reported.
  const own = new Set();
  walk(chunk, (n) => {
    if (n.type === "LocalStatement" || n.type === "AssignmentStatement")
      n.init.forEach((e, i) => {
        const v = n.variables[i];
        if (v?.type === "Identifier" && isCall(e) && calleeOf(e) === "GetCurrentResourceName") own.add(v.name);
      });
  });
  for (const { call, name } of list) {
    if (name !== "SaveResourceFile") continue;
    const target = argsOf(call)[0];
    const mine =
      !target ||
      (isCall(target) && calleeOf(target) === "GetCurrentResourceName") ||
      (target.type === "Identifier" && own.has(target.name)) ||
      literal(target) !== null;
    if (!mine) out.push(finding("LAB-SEC-106", "SaveResourceFile writes into a resource that may not be this one.", { path, line: lineOf(call) }));
  }

  // Obfuscated data and raw-IP addresses: one finding per file, at the first occurrence.
  const first = {};
  walk(chunk, (n) => {
    if (n.type === "StringLiteral") {
      const value = stringValue(n.raw);
      const count = escapes(n.raw);
      if (count >= MIN_ESCAPES) first.blob ??= { line: lineOf(n), what: `a string of ${count} escaped bytes` };
      if (BLOB.test(value)) first.blob ??= { line: lineOf(n), what: `a ${value.length}-character base64/hex string` };
      if (http.length && IP_URL.test(value)) first.ip ??= { line: lineOf(n), url: value.slice(0, 60) };
    }
    if (isCall(n) && calleeOf(n) === "string.char" && argsOf(n).length >= MIN_CHAR_ARGS) first.blob ??= { line: lineOf(n), what: `string.char with ${argsOf(n).length} bytes` };
  });
  if (first.blob) out.push(finding("LAB-SEC-103", `This file contains ${first.blob.what}.`, { path, line: first.blob.line }));
  if (first.ip) out.push(finding("LAB-SEC-105", `A file that sends HTTP requests contains the raw-IP address '${first.ip.url}'.`, { path, line: first.ip.line }));
  return out;
}

/**
 * All checks on one file. Hidden code and credentials are looked for in any text file; the Lua checks need a parse.
 * `parsed: false` = the Lua did not parse, so only the text checks ran.
 */
export function securityRules(path, source) {
  const text = [...hiddenCode(path, source), ...shippedCredentials(path, source), ...knownBackdoor(path, source)];
  if (JS_FILE.test(path)) return { findings: [...text, ...jsRules(path, source)], parsed: true };
  if (!path.toLowerCase().endsWith(".lua")) return { findings: text, parsed: true };
  try {
    return { findings: [...luaRules(path, parseLua(source)), ...text], parsed: true };
  } catch {
    return { findings: text, parsed: false };
  }
}
