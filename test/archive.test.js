import assert from "node:assert/strict";
import { test } from "node:test";
import { archiveRisks } from "../src/index.js";

test("archive entry names: executables and unsafe paths; C# assemblies are expected", () => {
  assert.deepEqual(archiveRisks(["r/fxmanifest.lua", "r/setup.EXE", "r/run.bat", "r/tools/fix.ps1", "__MACOSX/r/._x.sh", "r/ui/app.js"]), {
    executables: ["r/setup.EXE", "r/run.bat", "r/tools/fix.ps1"],
    unsafePaths: [],
  });
  assert.deepEqual(archiveRisks(["r/Game.Client.net.dll", "r/Newtonsoft.Json.dll"]).executables, []);
  assert.deepEqual(archiveRisks(["r/helper.dll"]).executables, ["r/helper.dll"]);
  assert.deepEqual(archiveRisks(["../evil.lua", "r/../../x.lua", "/etc/passwd", "C:/x.lua", "r\\..\\x.lua", "r/ok..lua"]).unsafePaths, [
    "../evil.lua",
    "r/../../x.lua",
    "/etc/passwd",
    "C:/x.lua",
    "r\\..\\x.lua",
  ]);
});
