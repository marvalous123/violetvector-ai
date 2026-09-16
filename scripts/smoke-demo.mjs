import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir, homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

assert.equal(process.platform, "win32", "The fresh demo smoke requires Windows.");
const source = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary = realpathSync.native(mkdtempSync(join(tmpdir(), "violetvector-fresh-demo-")));
const checkout = join(temporary, "Source folder with spaces");
mkdirSync(checkout);
let demoRoot;
let child;
let output = "";
const pause = (ms) => new Promise((done) => setTimeout(done, ms));

try {
  const inventory = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
    cwd: source, encoding: "utf8", timeout: 10_000
  });
  assert.equal(inventory.status, 0, inventory.stderr);
  for (const file of new Set(inventory.stdout.split("\0").filter(Boolean))) {
    assert.ok(!isAbsolute(file) && !file.split(/[\\/]/).includes(".."));
    cpSync(join(source, file), join(checkout, file), { recursive: false });
  }
  const planResult = spawnSync("powershell.exe", ["-NoProfile", "-File", "scripts/start-demo.ps1", "-Plan"], {
    cwd: checkout, encoding: "utf8", timeout: 15_000
  });
  assert.equal(planResult.status, 0, planResult.stderr);
  const plan = JSON.parse(planResult.stdout);
  demoRoot = dirname(plan.dataRoot);
  const expectedBase = join(homedir(), ".violetvector-preview");
  const demoRelative = relative(expectedBase, demoRoot);
  assert.match(demoRelative, /^[a-f0-9]{16}$/);

  const probe = createServer();
  await new Promise((done) => probe.listen(0, "127.0.0.1", done));
  const port = probe.address().port;
  await new Promise((done) => probe.close(done));
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 120_000;
  child = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/start-demo.ps1", "-NoBrowser", "-Port", String(port)], {
    cwd: checkout,
    env: { ...process.env, WAR_ROOM_MCPWN_VERSION_ENABLED: "1", WAR_ROOM_REDMI_EXECUTION_ENABLED: "1", WAR_ROOM_OPERATOR_BOOTSTRAP: "inherited-secret-must-not-be-used" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  let errors = "";
  child.stderr.on("data", (chunk) => { errors += chunk.toString(); });
  let health;
  while (Date.now() < deadline) {
    assert.equal(child.exitCode, null, `Launcher exited before readiness: ${errors}`);
    try {
      const response = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) { health = await response.json(); break; }
    } catch { /* Startup is bounded by the deadline. */ }
    await pause(500);
  }
  assert.ok(health, "Demo did not become ready within two minutes.");
  assert.equal(health.executionEnabled, false);
  const bootstrap = output.match(/One-time bootstrap secret: ([A-Za-z0-9_-]{43})/)?.[1];
  assert.ok(bootstrap, "A fresh 256-bit bootstrap secret was not printed.");
  assert.ok(!output.includes("inherited-secret-must-not-be-used"));
  const page = await fetch(url);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /VioletVector AI/);
  const unlock = await fetch(`${url}/api/session/unlock`, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: url },
    body: JSON.stringify({ operator: "Fresh installation smoke", bootstrapSecret: bootstrap })
  });
  assert.equal(unlock.status, 200);
  const session = await unlock.json();
  const headers = {
    "Content-Type": "application/json", Origin: url,
    Cookie: unlock.headers.get("set-cookie").split(";")[0],
    "x-war-room-csrf": session.csrfToken, "x-war-room-tab": session.tabCapability
  };
  const capabilitiesResponse = await fetch(`${url}/api/capabilities`, { headers });
  assert.equal(capabilitiesResponse.status, 200);
  const { capabilities } = await capabilitiesResponse.json();
  assert.equal(capabilities.find((item) => item.id === "mcpwn.version.v1").status, "unavailable");
  assert.ok(capabilities.filter((item) => item.targetRequired).every((item) => item.status !== "enabled"));
  const guided = await fetch(`${url}/api/guided-demo`, { method: "POST", headers, body: "{}" });
  assert.equal(guided.status, 201);
  const { demo } = await guided.json();
  assert.equal(demo.boundary, "offline-synthetic-only");
  assert.equal(demo.targetContact, false);
  assert.equal(demo.commandExecution, false);
  for (const format of ["json", "html"]) {
    const report = await fetch(`${url}/api/reports/${demo.reportSnapshotId}/outputs/${format}`, { headers });
    assert.equal(report.status, 200);
    assert.match(await report.text(), /Synthetic detection pipeline exercised/);
  }
  assert.ok(readFileSync(join(checkout, "node_modules", ".violetvector-demo-lock"), "utf8").length === 64);
  const occupied = spawnSync("powershell.exe", ["-NoProfile", "-File", "scripts/start-demo.ps1", "-NoBrowser", "-Port", String(port)], {
    cwd: checkout, encoding: "utf8", timeout: 10_000
  });
  assert.notEqual(occupied.status, 0);
  assert.match(occupied.stderr, /already occupied/);
  assert.ok(!occupied.stdout.includes("One-time bootstrap secret"));
  spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { encoding: "utf8", timeout: 15_000 });
  await pause(1000);
  output = "";
  child = spawn("powershell.exe", ["-NoProfile", "-File", "scripts/start-demo.ps1", "-NoBrowser", "-Port", String(port)], {
    cwd: checkout, stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr.on("data", () => {});
  let restarted = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    assert.equal(child.exitCode, null, "Second demo launch failed.");
    try {
      const response = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) { restarted = true; break; }
    } catch { /* Wait for this restart, without any external contact. */ }
    await pause(500);
  }
  assert.ok(restarted, "Second launch timed out.");
  const newBootstrap = output.match(/One-time bootstrap secret: ([A-Za-z0-9_-]{43})/)?.[1];
  assert.ok(newBootstrap && newBootstrap !== bootstrap);
  assert.ok(!output.includes("downloading locked"), "Unchanged dependencies should not be downloaded again.");
  const secondUnlock = await fetch(`${url}/api/session/unlock`, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: url },
    body: JSON.stringify({ operator: "Restart smoke", bootstrapSecret: newBootstrap })
  });
  assert.equal(secondUnlock.status, 200);
  const secondSession = await secondUnlock.json();
  const persistedReport = await fetch(`${url}/api/reports/${demo.reportSnapshotId}/outputs/json`, {
    headers: {
      Cookie: secondUnlock.headers.get("set-cookie").split(";")[0],
      "x-war-room-tab": secondSession.tabCapability
    }
  });
  assert.equal(persistedReport.status, 200);
  console.log("Fresh source ZIP-equivalent smoke passed: independent npm ci, protected session, synthetic mission and JSON/HTML reports; disabled live adapters, occupied-port recovery, fresh restart secret and preserved report.");
} finally {
  if (child && child.exitCode === null) {
    spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { encoding: "utf8", timeout: 15_000 });
    await pause(1000);
  }
  // Only these explicitly created, validated smoke directories are removed.
  if (demoRoot && /^[a-f0-9]{16}$/.test(relative(join(homedir(), ".violetvector-preview"), demoRoot))) {
    rmSync(demoRoot, { recursive: true, force: true });
  }
  rmSync(temporary, { recursive: true, force: true });
}
