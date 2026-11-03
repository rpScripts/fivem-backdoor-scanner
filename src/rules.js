// The backdoor checks of the RPScripts FiveM Backdoor Scanner (https://rpscripts.net/tools/fivem-backdoor-scanner/).
// Static only: files are parsed, never run. Codes never change meaning; same codes as the web scanner's reports.
import { memberPath, parseLua, stringValue, walk } from "./lua.js";

export const RULESET_VERSION = "2026.10.6";

const SECURITY_DOCS = "https://docs.fivem.net/docs/developers/server-security/";

export const RULES = {
  "LAB-SEC-101": { severity: "warning", title: "Possible backdoor: runs code downloaded over HTTP", fix: "Code from a web response should never reach load(); this is how known FiveM backdoors take over a server. Remove it unless you wrote it and trust the server it calls." },
  "LAB-SEC-102": { severity: "warning", title: "Runs code built from encoded or obfuscated text", fix: "Find out what the decoded text does before starting the resource; ship readable source (or Cfx escrow) instead of hidden code." },
  "LAB-SEC-103": { severity: "warning", title: "Obfuscated data in the code", fix: "Long escaped-byte, base64 or hex strings and long string.char lists hide what the code does. Check what they decode to." },
  "LAB-SEC-104": { severity: "warning", title: "Reads a server secret", fix: "A resource has no reason to read the license key or RCON password; database credentials only belong in the database resource. Find out where the value goes." },
  "LAB-SEC-105": { severity: "warning", title: "HTTP request to a raw IP or a hidden address", fix: "Legitimate integrations call named, documented hosts. Find out who runs the address and what is sent there." },
  "LAB-SEC-106": { severity: "warning", title: "Runs shell commands or writes outside its own resource", fix: "os.execute and io.popen run programs on the host; writing other resources' files is how backdoors spread. Keep file writes inside GetResourcePath(GetCurrentResourceName())." },
  "LAB-SEC-107": { severity: "error", title: "Code hidden behind a long run of spaces", fix: "Legitimate code is never pushed out of view. This is how a known FiveM backdoor hides a loader that runs remote code on player clients: delete the hidden part and treat the package as compromised." },
  "LAB-SEC-108": { severity: "warning", title: "Ships a credential", fix: "Someone's token, webhook or key is in the download, so every buyer gets it. Replace it with an empty value and let the server owner enter their own." },
};

const finding = (code, message, at) => ({ code, ...RULES[code], message, ...at, docs: SECURITY_DOCS, ruleVersion: RULESET_VERSION });

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

function luaRules(path, chunk) {
  const out = [];
  const list = calls(chunk);
  const http = list.filter(({ name }) => name && HTTP.has(name));
  const remote = new Set();
  // io.popen('ls "…"') / ('dir "…" /b') to list a folder is common in legitimate loaders.
  let lists = false;
  walk(chunk, (n) => {
    if (n.type === "StringLiteral" && /^(?:ls|dir)(?:\s|$)/.test(stringValue(n.raw))) lists = true;
  });

  // Code loaded inside an HTTP response handler: `PerformHttpRequest(url, function(_, body) assert(load(body))() end)`.
  for (const { call } of http)
    for (const fn of argsOf(call).filter((a) => a.type === "FunctionDeclaration"))
      for (const inner of calls(fn))
        if (inner.name && LOADERS.has(inner.name)) {
          remote.add(inner.call);
          out.push(finding("LAB-SEC-101", `${inner.name}() runs the body of an HTTP response: whoever controls that server can run any code on yours.`, { path, line: lineOf(inner.call) }));
        }

  for (const { call, name } of list) {
    if (!name) continue;
    const args = argsOf(call);
    if (LOADERS.has(name) && !remote.has(call) && args[0] && hidden(args[0]))
      out.push(finding("LAB-SEC-102", `${name}() runs text that is only decoded at runtime.`, { path, line: lineOf(call) }));
    if ((name === "GetConvar" || name === "GetConvarInt") && args[0]) {
      const convar = literal(args[0]);
      if (convar && (SECRET.test(convar) || (DB_SECRET.test(convar) && http.length > 0)))
        out.push(finding("LAB-SEC-104", `Reads the convar '${convar}'${http.length ? " in a file that also sends HTTP requests" : ""}.`, { path, line: lineOf(call) }));
    }
    if (HTTP.has(name) && args[0] && hidden(args[0]))
      out.push(finding("LAB-SEC-105", "The address of this HTTP request is only decoded at runtime.", { path, line: lineOf(call) }));
    if (name === "os.execute" || (name === "io.popen" && !lists))
      out.push(finding("LAB-SEC-106", `${name} runs a program on the server's host.`, { path, line: lineOf(call) }));
    if (name === "io.open" && /^[wa]|\+/.test(literal(args[1]) ?? "") && !JSON.stringify(args[0] ?? null).includes("GetResourcePath"))
      out.push(finding("LAB-SEC-106", "io.open writes to a path that isn't built from GetResourcePath(…).", { path, line: lineOf(call) }));
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
  const text = [...hiddenCode(path, source), ...shippedCredentials(path, source)];
  if (!path.toLowerCase().endsWith(".lua")) return { findings: text, parsed: true };
  try {
    return { findings: [...luaRules(path, parseLua(source)), ...text], parsed: true };
  } catch {
    return { findings: text, parsed: false };
  }
}
