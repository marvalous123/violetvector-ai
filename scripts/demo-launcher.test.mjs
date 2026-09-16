import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));
const launcher = readFileSync(new URL("start-demo.ps1", import.meta.url), "utf8");

test("demo entry point is available in paths with spaces and preserves errors", () => {
  const entry = readFileSync(new URL("../Start VioletVector Demo.cmd", import.meta.url), "utf8");
  assert.ok(entry.includes('-File "%~dp0scripts\\start-demo.ps1"'));
  assert.ok(entry.includes("if errorlevel 1"));
});

test("demo launcher never builds native components and overrides live adapters", () => {
  assert.match(launcher, /WAR_ROOM_MCPWN_VERSION_ENABLED = '0'/);
  assert.match(launcher, /WAR_ROOM_REDMI_EXECUTION_ENABLED = '0'/);
  assert.match(launcher, /RandomNumberGenerator/);
  assert.match(launcher, /SetEnvironmentVariable\(\$name, \$savedEnvironment\[\$name\]/);
  assert.doesNotMatch(launcher, /& (?:dotnet|wsl|docker)|npm\.cmd run build\s|install-local\.ps1/);
  assert.match(launcher, /ReparsePoint/);
});

test("Windows plan is non-mutating and isolates demo data", { skip: process.platform !== "win32" }, () => {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-File", "scripts/start-demo.ps1", "-Plan", "-Port", "4316"], {
    cwd: root, encoding: "utf8", timeout: 15_000
  });
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.product, "VioletVector AI");
  assert.equal(plan.nativeSensorRequired, false);
  assert.equal(plan.mcpwnEnabled, false);
  assert.equal(plan.redmiExecutionEnabled, false);
  assert.equal(plan.address, "http://127.0.0.1:4316");
  assert.match(plan.dataRoot, /\.violetvector-preview[\\/][a-f0-9]{16}[\\/]runtime$/);
  assert.notEqual(plan.dataRoot, plan.webRoot);
});

test("invalid demo ports fail before setup", { skip: process.platform !== "win32" }, () => {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-File", "scripts/start-demo.ps1", "-Plan", "-Port", "80"], {
    cwd: root, encoding: "utf8", timeout: 15_000
  });
  assert.notEqual(result.status, 0);
  assert.ok(!result.stdout.includes("downloading"));
});
