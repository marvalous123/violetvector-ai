import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { resolveLocalAiModel } from "../src/config/local-ai.js";
import { buildServer } from "../src/server.js";

interface Session {
  cookie: string;
  csrfToken: string;
}

const temporaryPrefix = "war-room-local-ai-smoke-";
const temporaryRoot = mkdtempSync(join(tmpdir(), temporaryPrefix));
const bootstrapSecret = randomBytes(32).toString("hex");
const configuredModel = resolveLocalAiModel();
const server = buildServer({
  databasePath: join(temporaryRoot, "war-room.sqlite"),
  evidenceRoot: join(temporaryRoot, "evidence"),
  bootstrapSecret,
  localAiModel: configuredModel
});

async function responseJson<T>(response: Response): Promise<T> {
  const body = (await response.json()) as T;
  if (!response.ok) {
    throw new Error(`LOCAL_AI_SMOKE_HTTP_${response.status}:${JSON.stringify(body)}`);
  }
  return body;
}

function authenticatedFetch(base: string, session: Session, path: string, init: RequestInit = {}) {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Cookie", session.cookie);
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("Origin", base);
    headers.set("X-War-Room-CSRF", session.csrfToken);
  }
  return fetch(`${base}${path}`, { ...init, headers });
}

function removeTemporaryRoot(path: string): void {
  const resolvedRoot = resolve(path);
  const resolvedTemporaryDirectory = resolve(tmpdir());
  if (
    dirname(resolvedRoot) !== resolvedTemporaryDirectory ||
    !basename(resolvedRoot).startsWith(temporaryPrefix)
  ) {
    throw new Error("LOCAL_AI_SMOKE_CLEANUP_PATH_INVALID");
  }
  rmSync(resolvedRoot, { recursive: true, force: true });
}

try {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}`;

  const unlockResponse = await fetch(`${base}/api/session/unlock`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: base },
    body: JSON.stringify({
      bootstrapSecret,
      operator: "local-ai-smoke"
    })
  });
  const unlockBody = await responseJson<{ csrfToken: string }>(unlockResponse);
  const cookie = unlockResponse.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie, "Operator session cookie was not returned");
  const session = { cookie, csrfToken: unlockBody.csrfToken };
  const post = (path: string, body: unknown) =>
    authenticatedFetch(base, session, path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

  const demo = await responseJson<{
    demo: {
      missionId: string;
      boundary: string;
      targetContact: boolean;
      commandExecution: boolean;
    };
  }>(await post("/api/guided-demo", {}));
  assert.equal(demo.demo.boundary, "offline-synthetic-only");
  assert.equal(demo.demo.targetContact, false);
  assert.equal(demo.demo.commandExecution, false);

  const result = await responseJson<{
    invocation: {
      id: string;
      status: string;
      model: string;
      latency_ms: number | null;
    };
    plan: {
      objective: string;
      assumptions: string[];
      steps: Array<{
        description: string;
        rationale: string;
        requiresHumanReview: boolean;
      }>;
      openQuestions: string[];
    };
  }>(await post("/api/model/plan", {
    missionId: demo.demo.missionId,
    objective: "Prepare a cautious evidence-review plan for this offline synthetic mission."
  }));
  assert.equal(result.invocation.status, "succeeded");
  assert.equal(result.invocation.model, configuredModel);
  assert.ok(result.plan.steps.length <= 20);

  const modelStatus = await responseJson<{
    health: { healthy: boolean; model: string };
    capabilities: {
      taskTier: string;
      toolAccess: boolean;
      filesystemAccess: boolean;
      commandAccess: boolean;
      mcpAccess: boolean;
      targetNetworkAccess: boolean;
    };
    invocations: Array<{ id: string; status: string; model: string }>;
  }>(await authenticatedFetch(base, session, "/api/system/model"));
  assert.equal(modelStatus.health.healthy, true);
  assert.equal(modelStatus.health.model, configuredModel);
  assert.equal(modelStatus.capabilities.taskTier, "T0");
  assert.equal(modelStatus.capabilities.toolAccess, false);
  assert.equal(modelStatus.capabilities.filesystemAccess, false);
  assert.equal(modelStatus.capabilities.commandAccess, false);
  assert.equal(modelStatus.capabilities.mcpAccess, false);
  assert.equal(modelStatus.capabilities.targetNetworkAccess, false);
  assert.equal(modelStatus.invocations.some((invocation) =>
    invocation.id === result.invocation.id &&
    invocation.status === "succeeded" &&
    invocation.model === configuredModel
  ), true);

  const audit = await responseJson<{
    verification: { valid: boolean };
  }>(await authenticatedFetch(base, session, "/api/system/audit"));
  assert.equal(audit.verification.valid, true);

  console.log(JSON.stringify({
    status: "passed",
    model: configuredModel,
    missionBoundary: demo.demo.boundary,
    targetContact: demo.demo.targetContact,
    commandExecution: demo.demo.commandExecution,
    invocationStatus: result.invocation.status,
    invocationLatencyMs: result.invocation.latency_ms,
    structuredPlanSteps: result.plan.steps.length,
    authority: "none",
    auditValid: audit.verification.valid
  }, null, 2));
} finally {
  if (server.listening) {
    await new Promise<void>((resolveClose, rejectClose) => {
      server.close((error) => error ? rejectClose(error) : resolveClose());
    });
  }
  removeTemporaryRoot(temporaryRoot);
}
