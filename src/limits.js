export const MAX_SCAN_ZIP = 300 * 1024 * 1024;
export const MAX_FILE = 2 * 1024 * 1024;
const MAX_TEXT = 120 * 1024 * 1024;
const SCANNED = /\.(?:lua|js)$/i;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// Lua reads source as bytes: Latin-1 maps every byte to one character, so nothing is dropped from the checks.
const latin1 = new TextDecoder("latin1");
/** File bytes as the checks see them, the same for ZIP entries and picked files. */
export function decodeSource(bytes) {
    try {
        return utf8.decode(bytes);
    }
    catch {
        return latin1.decode(bytes);
    }
}
/** The limits a report lists. */
export const LIMITS = ["escrowed", "unreadable", "javascript", "unparsed", "skipped", "archives"];
export function verdictOf(r) {
    if (r.findings.some((f) => f.severity === "error"))
        return "hidden";
    if (r.findings.length)
        return "suspicious";
    return r.scanned === 0 || LIMITS.some((k) => r[k].length) ? "partial" : "clean";
}
// Directories only. macOS metadata (`._x`, `__MACOSX/`) is recognised by its content, not its name (scan.ts).
export const ignored = (name) => name.endsWith("/");
/** Which entries to read: Lua/JS within the size limits. Shared by ZIP uploads and folder picks. */
export function plan(entries) {
    const skipped = [];
    let total = 0;
    const wanted = entries
        .filter((e) => !ignored(e.name) && SCANNED.test(e.name))
        .filter((e) => {
        total += e.size;
        if (e.size <= MAX_FILE && total <= MAX_TEXT)
            return true;
        skipped.push(e.name);
        return false;
    })
        .map((e) => e.name);
    return { wanted: new Set(wanted), skipped };
}
