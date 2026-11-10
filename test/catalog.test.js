import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { RULES, RULESET_VERSION } from "../src/index.js";

const PUBLISHED = ["LAB-PKG-004", "LAB-PKG-005", "LAB-SEC-101", "LAB-SEC-102", "LAB-SEC-103", "LAB-SEC-104", "LAB-SEC-105", "LAB-SEC-106", "LAB-SEC-107", "LAB-SEC-108", "LAB-SEC-109", "LAB-SEC-110", "LAB-SEC-111", "LAB-SEC-112"];

test("rules/catalog.json is the only source of the rule texts, with the public codes only", () => {
  const catalog = JSON.parse(readFileSync(new URL("../rules/catalog.json", import.meta.url), "utf8"));
  assert.equal(RULESET_VERSION, catalog.rulesetVersion);
  assert.deepEqual(Object.keys(RULES).sort(), PUBLISHED);
  for (const [code, rule] of Object.entries(RULES)) {
    assert.ok(["error", "warning", "info"].includes(rule.severity), code);
    assert.ok(["confirmed", "likely", "heuristic"].includes(rule.confidence), code);
    assert.ok(rule.title && rule.fix && Array.isArray(rule.refs), code);
  }
  assert.match(readFileSync(new URL("../rules/CHANGELOG.md", import.meta.url), "utf8"), new RegExp(`## ${RULESET_VERSION.replaceAll(".", "\\.")}`));
});
