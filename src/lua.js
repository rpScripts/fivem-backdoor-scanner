// Lua parsing helpers. FiveM's CfxLua accepts syntax luaparse (Lua 5.3) rejects; it is rewritten to plain Lua of the
// same length first, so line numbers stay right.
import luaparse from "luaparse";

const longBracket = (src, i) => /^\[(=*)\[/.exec(src.slice(i, i + 64));

/** Splits Lua source into code, strings ('…', "…", [[…]]), backtick hashes, comments and C-style comments. */
export function luaSpans(src) {
  const spans = [];
  let start = 0;
  let i = 0;
  const push = (kind, end) => {
    if (start < i) spans.push({ kind: "code", text: src.slice(start, i) });
    spans.push({ kind, text: src.slice(i, end) });
    i = start = end;
  };
  const closeLong = (from, eq) => {
    const end = src.indexOf(`]${eq}]`, from);
    return end < 0 ? src.length : end + eq.length + 2;
  };
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      push("ccomment", end < 0 ? src.length : end + 2);
    } else if (c === "-" && src[i + 1] === "-") {
      const long = longBracket(src, i + 2);
      push("comment", long ? closeLong(i + 2 + long[0].length, long[1]) : src.indexOf("\n", i) + 1 || src.length);
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      push(c === "`" ? "hash" : "string", Math.min(j + 1, src.length));
    } else if (c === "[" && longBracket(src, i)) {
      const long = longBracket(src, i);
      push("string", closeLong(i + long[0].length, long[1]));
    } else i++;
  }
  if (start < src.length) spans.push({ kind: "code", text: src.slice(start) });
  return spans;
}

const ATTRIB = /<\s*(?:const|close)\s*>/g;
const COMPOUND = /(?:\/\/|<<|>>|\.\.|[-+*/%^&|])=(?!=)/g;
const SAFE_NAV = /\?(?=[.[:])/g;
export const toPlainLua = (source) =>
  luaSpans(source)
    .map((s) =>
      s.kind === "hash"
        ? s.text.length > 1 && s.text.endsWith("`") ? `"${s.text.slice(1, -1)}"` : s.text
        : s.kind === "ccomment"
          ? s.text.replace(/[^\n]/g, " ")
          : s.kind !== "code"
            ? s.text
            : s.text
                .replace(ATTRIB, (m) => " ".repeat(m.length))
                .replace(COMPOUND, (m) => `${" ".repeat(m.length - 1)}=`)
                .replace(SAFE_NAV, " "),
    )
    .join("");

export const parseLua = (source) => luaparse.parse(toPlainLua(source), { luaVersion: "5.3", locations: true });

/** `a.b.c` / `a.b:c` → ["a", "b", "c"]; null when any part isn't a plain identifier. */
export function memberPath(e) {
  if (e.type === "Identifier") return [e.name];
  if (e.type !== "MemberExpression") return null;
  const base = memberPath(e.base);
  return base && [...base, e.identifier.name];
}

const isNode = (v) => typeof v === "object" && v !== null && typeof v.type === "string";

/** Depth-first over every node. */
export function walk(node, visit) {
  visit(node);
  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "range") continue;
    if (Array.isArray(value)) {
      for (const v of value) if (isNode(v)) walk(v, visit);
    } else if (isNode(value)) walk(value, visit);
  }
}

/** String literal content, read from raw (luaparse leaves `value` empty for non-Latin-1 text). */
export const stringValue = (raw) => (/^['"]/.test(raw) ? raw.slice(1, -1) : raw.replace(/^\[=*\[\n?|\]=*\]$/g, ""));
