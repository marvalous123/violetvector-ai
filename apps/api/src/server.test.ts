import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, it } from "node:test";
import type { AddressInfo } from "node:net";
import { ModelProviderError, type ModelProvider } from "@war-room/model-provider";
import { stableJson } from "./domain/stable-json.js";
import { buildServer } from "./server.js";
import {
  endpointCapabilityReportHash,
  endpointFactBatchHash,
  type EndpointFactFieldName
} from "./services/endpoint-fact-correlation-service.js";

const servers: ReturnType<typeof buildServer>[] = [];
afterEach(() => servers.splice(0).forEach((server) => server.close()));
const bootstrapSecret = "server-test-bootstrap-secret-that-is-long-enough";

interface TestSession {
  cookie: string;
  csrfToken: string;
  tabCapability: string;
}

async function unlock(base: string, operator = "test operator"): Promise<TestSession> {
  const response = await fetch(`${base}/api/session/unlock`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: base },
    body: JSON.stringify({ bootstrapSecret, operator })
  });
  assert.equal(response.status, 200);
  const body = (await response.json()) as { csrfToken: string; tabCapability: string };
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie);
  return { cookie, csrfToken: body.csrfToken, tabCapability: body.tabCapability };
}

function authenticatedFetch(base: string, session: TestSession, path: string, init: RequestInit = {}) {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Cookie", session.cookie);
  headers.set("X-War-Room-Tab", session.tabCapability);
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("Origin", base);
    headers.set("X-War-Room-CSRF", session.csrfToken);
  }
  return fetch(`${base}${path}`, { ...init, headers });
}

const fakeModelProvider: ModelProvider = {
  capabilities: () => ({
    provider: "ollama",
    taskTier: "T0",
    profiles: ["structured-planning", "evidence-summary", "finding-draft"],
    structuredOutput: true,
    toolAccess: false,
    filesystemAccess: false,
    commandAccess: false,
    mcpAccess: false,
    targetNetworkAccess: false
  }),
  health: async () => ({
    healthy: true,
    provider: "ollama",
    baseUrl: "http://127.0.0.1:11434",
    model: "test-model",
    latencyMs: 1,
    checkedAt: new Date().toISOString()
  }),
  generate: async (request) => ({
    output: {
      objective: request.profile === "structured-planning" ? request.input.objective : "Advisory task",
      assumptions: [],
      steps: [{ description: "Review scope", rationale: "Keep the task bounded", requiresHumanReview: true }],
      openQuestions: []
    },
    metadata: {
      provider: "ollama",
      model: "test-model",
      profile: request.profile,
      taskTier: "T0",
      authority: "none",
      latencyMs: 2,
      usage: { inputTokens: 10, outputTokens: 10 },
      providerDurationsNs: { total: null, load: null, promptEvaluation: null, evaluation: null }
    }
  })
};

describe("API", () => {
  it("reports that execution is disabled", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    assert.equal(response.status, 200);
    const body = (await response.json()) as { status: string; executionEnabled: boolean };
    assert.equal(body.status, "ok");
    assert.equal(body.executionEnabled, false);
    assert.match(response.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  });

  it("exposes authenticated redacted support diagnostics without local paths", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "support operator");
    const response = await authenticatedFetch(base, session, "/api/system/diagnostics");
    assert.equal(response.status, 200);
    const body = (await response.json()) as {
      diagnostics: {
        integrity: { databaseQuickCheck: boolean; audit: { valid: boolean }; evidenceInvalid: number };
        storage: { pathsDisclosed: boolean };
        safeToShare: boolean;
      };
    };
    assert.equal(body.diagnostics.integrity.databaseQuickCheck, true);
    assert.equal(body.diagnostics.integrity.audit.valid, true);
    assert.equal(body.diagnostics.integrity.evidenceInvalid, 0);
    assert.equal(body.diagnostics.storage.pathsDisclosed, false);
    assert.equal(body.diagnostics.safeToShare, true);
    assert.doesNotMatch(JSON.stringify(body), /[A-Z]:\\/i);
  });

  it("creates a draft mission and exact scope through strict same-origin routes", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base);
    const missionResponse = await authenticatedFetch(base, session, "/api/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "API-controlled lab mission" })
    });
    assert.equal(missionResponse.status, 201);
    const missionBody = (await missionResponse.json()) as { mission: { id: string } };
    const startsAt = new Date(Date.now() - 60_000);
    const expiresAt = new Date(Date.now() + 60 * 60_000);
    const scopeResponse = await authenticatedFetch(base, session, `/api/missions/${missionBody.mission.id}/scope`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        startsAt: startsAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        authorizationStatement: "I own and authorize this isolated API test target.",
        targets: [{ address: "8.8.8.8" }]
      })
    });
    assert.equal(scopeResponse.status, 201);
    const dashboardResponse = await authenticatedFetch(base, session, "/api/dashboard");
    const dashboard = (await dashboardResponse.json()) as { missions: Array<{ status: string }>; executionEnabled: boolean };
    assert.equal(dashboard.missions[0]?.status, "scope_validated");
    assert.equal(dashboard.executionEnabled, false);
  });

  it("runs a synthetic blue-team detection lab without target or command access", async () => {
    const server = buildServer({ bootstrapSecret, modelProvider: fakeModelProvider }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "blue analyst");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Offline blue-team detection lab" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;

    const poisoned = await post("/api/blue/simulations", {
      missionId,
      scenarioId: "combined-incident",
      command: "run something"
    });
    assert.equal(poisoned.status, 400);
    assert.deepEqual(await poisoned.json(), { error: "SCHEMA_INVALID" });

    const simulated = await post("/api/blue/simulations", { missionId, scenarioId: "combined-incident" });
    assert.equal(simulated.status, 201);
    const simulatedBody = (await simulated.json()) as {
      run: {
        alertCount: number;
        eventCount: number;
        integrityValid: boolean;
        evidenceArtifactId: string;
        result: { alerts: Array<{ disposition: string }>; events: Array<{ source: string }> };
      };
    };
    assert.equal(simulatedBody.run.alertCount, 30);
    assert.equal(simulatedBody.run.eventCount, 30);
    assert.equal(simulatedBody.run.integrityValid, true);
    assert.equal(simulatedBody.run.result.alerts.every((alert) => alert.disposition === "needs-review"), true);
    assert.equal(simulatedBody.run.result.events.every((event) => event.source === "synthetic"), true);

    const unscopedBlueResponse = await authenticatedFetch(base, session, "/api/blue");
    const unscopedBlue = (await unscopedBlueResponse.json()) as {
      runs: unknown[];
      validationMatrix: Array<{ syntheticValidation: { status: string; evidenceArtifactId: string | null } }>;
    };
    assert.equal(unscopedBlueResponse.status, 200);
    assert.equal(unscopedBlue.runs.length, 0);
    assert.equal(unscopedBlue.validationMatrix.every((item) => item.syntheticValidation.status === "not-run"), true);
    assert.equal(
      unscopedBlue.validationMatrix.every((item) => item.syntheticValidation.evidenceArtifactId === null),
      true
    );

    const blueResponse = await authenticatedFetch(base, session, `/api/blue?missionId=${encodeURIComponent(missionId)}`);
    assert.equal(blueResponse.status, 200);
    const blue = (await blueResponse.json()) as {
      rules: unknown[];
      scenarios: unknown[];
      runs: Array<{ evidenceArtifactId: string; integrityValid: boolean }>;
      validationMatrix: Array<{
        syntheticValidation: { status: string; evidenceArtifactId: string | null };
        liveValidation: { status: string; endpointEvidencePresent: boolean };
      }>;
      endpointAccess: { commandExecution: boolean; remoteShell: boolean; status: string };
    };
    assert.equal(blue.rules.length, 30);
    assert.equal(blue.scenarios.length, 4);
    assert.equal(blue.runs[0]?.evidenceArtifactId, simulatedBody.run.evidenceArtifactId);
    assert.equal(blue.runs[0]?.integrityValid, true);
    assert.equal(blue.validationMatrix.length, 30);
    assert.equal(blue.validationMatrix.every((item) => item.syntheticValidation.status === "detected"), true);
    assert.equal(
      blue.validationMatrix.every(
        (item) => item.syntheticValidation.evidenceArtifactId === simulatedBody.run.evidenceArtifactId
      ),
      true
    );
    assert.equal(blue.validationMatrix.every((item) => item.liveValidation.status === "connector-required"), true);
    assert.equal(blue.validationMatrix.every((item) => item.liveValidation.endpointEvidencePresent === false), true);
    assert.deepEqual(blue.endpointAccess, {
      mode: "read-only-telemetry",
      status: "enrollment-ready",
      commandExecution: false,
      remoteShell: false,
      note: "The signed intake boundary is configured; live support still requires an approved endpoint identity, healthy telemetry and rule correlation."
    });

    const evidenceResponse = await authenticatedFetch(base, session, "/api/evidence");
    const evidence = (await evidenceResponse.json()) as {
      artifacts: Array<{ id: string; verified: boolean; latest_observation: { mission_id: string } }>;
    };
    const artifact = evidence.artifacts.find((item) => item.id === simulatedBody.run.evidenceArtifactId);
    assert.equal(artifact?.verified, true);
    assert.equal(artifact?.latest_observation.mission_id, missionId);
  });

  it("prepares an exact isolated target approval without accepting a caller target or executing", async () => {
    let isolationChecks = 0;
    const targetIsolationVerifier = {
      verify: async () => {
        isolationChecks += 1;
        return {
          verificationId: "redmi:test-attestation",
          targetAddress: "192.168.42.129" as const,
          sourceAddress: "192.168.42.42" as const,
          interfaceName: "eth5" as const,
          networkName: "war-room-redmi-isolated" as const,
          bridgeName: "wr15-redmi" as const,
          imageId: "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3" as const,
          verifiedAt: new Date().toISOString()
        };
      }
    };
    const server = buildServer({ bootstrapSecret, targetIsolationVerifier }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base);
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Exact isolated Redmi target" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    await post(`/api/missions/${missionId}/scope`, {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      authorizationStatement: "I own and authorize this exact isolated Redmi test target.",
      targets: [{ address: "192.168.42.129", isolatedPrivateTargetApproved: true }]
    });

    const poisoned = await post("/api/target/service-version/approvals", {
      missionId,
      ports: [80],
      intensity: 1,
      targetAddress: "192.168.1.1"
    });
    assert.equal(poisoned.status, 400);
    assert.deepEqual(await poisoned.json(), { error: "SCHEMA_INVALID" });
    assert.equal(isolationChecks, 0);

    const prepared = await post("/api/target/service-version/approvals", {
      missionId,
      ports: [443, 80],
      intensity: 1
    });
    assert.equal(prepared.status, 201);
    const preparedBody = (await prepared.json()) as {
      approval: { id: string; status: string };
      proposal: { parameters: { ports: number[] }; targetId: string };
      isolation: { targetAddress: string };
    };
    assert.equal(preparedBody.approval.status, "pending");
    assert.deepEqual(preparedBody.proposal.parameters.ports, [80, 443]);
    assert.notEqual(preparedBody.proposal.targetId, "192.168.42.129");
    assert.equal(preparedBody.isolation.targetAddress, "192.168.42.129");
    assert.equal(isolationChecks, 1);

    const approved = await post(`/api/approvals/${preparedBody.approval.id}/approve`, { note: "Reviewed exact bounds" });
    assert.equal(approved.status, 200);
    assert.equal(isolationChecks, 1);

    const poisonedAllTcp = await post("/api/target/all-tcp-ports/approvals", {
      missionId,
      ports: "1-65535"
    });
    assert.equal(poisonedAllTcp.status, 400);
    assert.deepEqual(await poisonedAllTcp.json(), { error: "SCHEMA_INVALID" });
    assert.equal(isolationChecks, 1);

    const allTcp = await post("/api/target/all-tcp-ports/approvals", { missionId });
    assert.equal(allTcp.status, 201);
    const allTcpBody = (await allTcp.json()) as {
      approval: { status: string };
      proposal: { capabilityId: string; timeoutMs: number; parameters: Record<string, unknown> };
    };
    assert.equal(allTcpBody.approval.status, "pending");
    assert.equal(allTcpBody.proposal.capabilityId, "network.tcp-port-discovery");
    assert.equal(allTcpBody.proposal.timeoutMs, 120_000);
    assert.deepEqual(allTcpBody.proposal.parameters, { profile: "all-tcp", maxRate: 1_000 });
    assert.equal(isolationChecks, 2);

    const poisonedProfile = await post("/api/target/http-metadata/approvals", {
      missionId,
      ports: [80],
      script: "vuln"
    });
    assert.equal(poisonedProfile.status, 400);
    assert.deepEqual(await poisonedProfile.json(), { error: "SCHEMA_INVALID" });
    assert.equal(isolationChecks, 2);

    const lowNoise = await post("/api/target/tcp-port-state/approvals", {
      missionId,
      ports: [443, 22]
    });
    assert.equal(lowNoise.status, 201);
    const lowNoiseBody = (await lowNoise.json()) as {
      proposal: { capabilityId: string; riskTier: string; timeoutMs: number; parameters: Record<string, unknown> };
    };
    assert.equal(lowNoiseBody.proposal.capabilityId, "network.tcp-port-state");
    assert.equal(lowNoiseBody.proposal.riskTier, "T1");
    assert.equal(lowNoiseBody.proposal.timeoutMs, 20_000);
    assert.deepEqual(lowNoiseBody.proposal.parameters, {
      ports: [22, 443], transport: "tcp", profile: "low-noise"
    });

    const tlsCiphers = await post("/api/target/tls-ciphers/approvals", {
      missionId,
      ports: [8443, 443]
    });
    assert.equal(tlsCiphers.status, 201);
    const tlsCiphersBody = (await tlsCiphers.json()) as {
      proposal: { capabilityId: string; riskTier: string; timeoutMs: number; parameters: Record<string, unknown> };
    };
    assert.equal(tlsCiphersBody.proposal.capabilityId, "tls.cipher-enumeration");
    assert.equal(tlsCiphersBody.proposal.riskTier, "T2");
    assert.equal(tlsCiphersBody.proposal.timeoutMs, 60_000);
    assert.deepEqual(tlsCiphersBody.proposal.parameters, {
      ports: [443, 8443], transport: "tcp", profile: "cipher-posture"
    });
    assert.equal(isolationChecks, 4);

    const catalogueResponse = await authenticatedFetch(base, session, "/api/capabilities");
    assert.equal(catalogueResponse.status, 200);
    const catalogueBody = (await catalogueResponse.json()) as {
      capabilities: Array<{ id: string; status: string; destructive: boolean; prepareRoute: string | null }>;
    };
    assert.equal(catalogueBody.capabilities.find((item) => item.id === "network.tcp-port-state")?.status, "enabled");
    assert.equal(
      catalogueBody.capabilities.find((item) => item.id === "simulation.credential-canary")?.status,
      "enabled"
    );
    assert.equal(catalogueBody.capabilities.every((item) => item.destructive === false), true);
  });

  it("captures operator fix evidence and binds a fresh pending approval to the exact direct retest", async () => {
    let executionCount = 0;
    const targetIsolationVerifier = {
      verify: async () => ({
        verificationId: `redmi:server-retest-${executionCount}`,
        targetAddress: "192.168.42.129" as const,
        sourceAddress: "192.168.42.42" as const,
        interfaceName: "eth5" as const,
        networkName: "war-room-redmi-isolated" as const,
        bridgeName: "wr15-redmi" as const,
        imageId: "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3" as const,
        verifiedAt: new Date().toISOString()
      })
    };
    const targetExecutorFactory = () => ({
      execute: async () => {
        executionCount += 1;
        const stdout = `bounded target fixture result ${executionCount}`;
        return {
          stdout,
          stderr: "",
          outputBytes: Buffer.byteLength(stdout),
          durationMs: 5,
          exitCode: 0,
          invocation: {
            executable: String.raw`C:\Windows\System32\wsl.exe`,
            args: [],
            spawnOptions: { shell: false as const, windowsHide: true as const },
            timeoutMs: 15_000,
            maxStdoutBytes: 262_144,
            maxStderrBytes: 32_768,
            imageReference: "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3",
            isolationVerificationId: "redmi:server-retest",
            containerName: "war-room-server-retest",
            distro: "kali-linux"
          }
        };
      }
    });
    const server = buildServer({ bootstrapSecret, targetIsolationVerifier, targetExecutorFactory }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "retest reviewer");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

    const missionResponse = await post("/api/missions", { name: "Bound direct retest API mission" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    await post(`/api/missions/${missionId}/scope`, {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      authorizationStatement: "I own and authorize this exact isolated target and one separately approved direct retest.",
      targets: [{ address: "192.168.42.129", isolatedPrivateTargetApproved: true }]
    });
    const originalPreparedResponse = await post("/api/target/service-version/approvals", {
      missionId,
      ports: [53],
      intensity: 1
    });
    const originalPrepared = (await originalPreparedResponse.json()) as {
      approval: { id: string };
      proposal: { runId: string; capabilityId: string; parameters: Record<string, unknown> };
    };
    await post(`/api/approvals/${originalPrepared.approval.id}/approve`, { note: "Reviewed original exact bounds" });
    const originalExecutionResponse = await post("/api/target/execute", { approvalId: originalPrepared.approval.id });
    assert.equal(originalExecutionResponse.status, 201);
    const originalExecution = (await originalExecutionResponse.json()) as {
      execution: { artifact: { id: string } };
    };
    assert.equal(executionCount, 1);
    const findingResponse = await post("/api/findings", {
      missionId,
      title: "Bound target service observation",
      severity: "low",
      description: "The exact authorized target run produced a bounded service observation for retest integration.",
      remediation: "Record the operator change and complete a separately approved direct retest.",
      confidence: "high",
      evidenceArtifactIds: [originalExecution.execution.artifact.id]
    });
    const findingId = ((await findingResponse.json()) as { findingId: string }).findingId;
    await post(`/api/findings/${findingId}/accept`, {});
    const dueDate = new Date(Date.now() + 24 * 60 * 60_000).toISOString().slice(0, 10);
    const remediationResponse = await post(`/api/findings/${findingId}/remediation`, {
      owner: "Device owner",
      dueDate,
      priority: "low"
    });
    const remediationId = ((await remediationResponse.json()) as { remediation: { id: string } }).remediation.id;
    await post(`/api/remediations/${remediationId}/status`, { status: "in-progress" });
    const poisonedCapture = await post(`/api/remediations/${remediationId}/fix-evidence/captures`, {
      changeType: "device-configuration",
      actionPerformedAt: new Date().toISOString(),
      actionSummary: "A bounded operator change was recorded for the isolated device.",
      observedState: "The operator observed the intended post-change configuration state.",
      artifactIds: [originalExecution.execution.artifact.id]
    });
    assert.equal(poisonedCapture.status, 400);
    const captureResponse = await post(`/api/remediations/${remediationId}/fix-evidence/captures`, {
      changeType: "device-configuration",
      actionPerformedAt: new Date().toISOString(),
      actionSummary: "A bounded operator change was recorded for the isolated device.",
      observedState: "The operator observed the intended post-change configuration state."
    });
    assert.equal(captureResponse.status, 201);
    const capture = (await captureResponse.json()) as { artifact: { id: string } };
    assert.notEqual(capture.artifact.id, originalExecution.execution.artifact.id);
    await post(`/api/remediations/${remediationId}/status`, { status: "fix-ready" });
    const retestRequestResponse = await post(`/api/remediations/${remediationId}/retests`, {
      reason: "Verify the recorded change using the exact original target and parameters."
    });
    const requestId = ((await retestRequestResponse.json()) as { requestId: string }).requestId;
    const poisonedPreparation = await post(
      `/api/remediations/${remediationId}/retests/${requestId}/target-approval`,
      { autoApprove: true }
    );
    assert.equal(poisonedPreparation.status, 400);
    const preparedResponse = await post(
      `/api/remediations/${remediationId}/retests/${requestId}/target-approval`,
      {}
    );
    assert.equal(preparedResponse.status, 201);
    const prepared = (await preparedResponse.json()) as {
      approval: { id: string; status: string };
      proposal: { runId: string; capabilityId: string; parameters: Record<string, unknown> };
      binding: { requestId: string; parentRunId: string; retestRunId: string; approvalId: string };
      remediation: { retests: Array<{ directRetest: { retestRunId: string } }> };
    };
    assert.equal(prepared.approval.status, "pending");
    assert.equal(prepared.binding.requestId, requestId);
    assert.equal(prepared.binding.parentRunId, originalPrepared.proposal.runId);
    assert.equal(prepared.binding.retestRunId, prepared.proposal.runId);
    assert.equal(prepared.binding.approvalId, prepared.approval.id);
    assert.equal(prepared.remediation.retests[0]?.directRetest.retestRunId, prepared.proposal.runId);
    assert.equal(prepared.proposal.capabilityId, originalPrepared.proposal.capabilityId);
    assert.deepEqual(prepared.proposal.parameters, originalPrepared.proposal.parameters);
    assert.equal(executionCount, 1, "preparing and binding a retest must not execute it");

    const prematureOutcome = await post(`/api/remediations/${remediationId}/retests/outcome`, {
      requestId,
      outcome: "remediated",
      summary: "A pending approval cannot support a technical remediation outcome.",
      reviewer: "Retest reviewer",
      evidenceArtifactIds: [originalExecution.execution.artifact.id]
    });
    assert.equal(prematureOutcome.status, 400);
    await post(`/api/approvals/${prepared.approval.id}/approve`, { note: "Reviewed exact cloned retest bounds" });
    const retestExecutionResponse = await post("/api/target/execute", { approvalId: prepared.approval.id });
    assert.equal(retestExecutionResponse.status, 201);
    const retestExecution = (await retestExecutionResponse.json()) as {
      execution: { artifact: { id: string } };
    };
    assert.equal(executionCount, 2);
    const outcomeResponse = await post(`/api/remediations/${remediationId}/retests/outcome`, {
      requestId,
      outcome: "remediated",
      summary: "The separately approved bound retest artifact supports the reviewed remediation outcome.",
      reviewer: "Retest reviewer",
      evidenceArtifactIds: [retestExecution.execution.artifact.id]
    });
    assert.equal(outcomeResponse.status, 200);
    const outcome = (await outcomeResponse.json()) as { remediation: { status: string } };
    assert.equal(outcome.remediation.status, "remediated");
  });

  it("enforces Starter and Professional product tiers in the backend catalogue and routes", async () => {
    const server = buildServer({ bootstrapSecret, productEdition: "starter" }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base);
    const catalogueResponse = await authenticatedFetch(base, session, "/api/capabilities");
    const catalogue = (await catalogueResponse.json()) as {
      edition: string;
      capabilities: Array<{ id: string; minimumEdition: string; status: string }>;
    };
    assert.equal(catalogue.edition, "starter");
    assert.equal(catalogue.capabilities.find((item) => item.id === "network.tcp-port-state")?.status, "unavailable");
    assert.equal(catalogue.capabilities.find((item) => item.id === "web.http-metadata")?.minimumEdition, "professional");

    const professionalOnly = await authenticatedFetch(base, session, "/api/target/http-metadata/approvals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ missionId: "mission", ports: [80] })
    });
    assert.equal(professionalOnly.status, 403);
    assert.deepEqual(await professionalOnly.json(), { error: "PROFESSIONAL_EDITION_REQUIRED" });
  });

  it("rejects unknown fields, non-JSON writes, and generic executor-shaped routes", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base);
    const poisoned = await authenticatedFetch(base, session, "/api/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Valid mission name", command: "whoami" })
    });
    assert.equal(poisoned.status, 400);
    assert.deepEqual(await poisoned.json(), { error: "SCHEMA_INVALID" });
    const wrongType = await authenticatedFetch(base, session, "/api/missions", { method: "POST", body: "name=test" });
    assert.equal(wrongType.status, 400);
    const misleadingJsonType = await authenticatedFetch(base, session, "/api/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json-evil" },
      body: JSON.stringify({ name: "Misleading media type" })
    });
    assert.equal(misleadingJsonType.status, 400);
    assert.deepEqual(await misleadingJsonType.json(), { error: "CONTENT_TYPE_REQUIRED" });
    const genericApproval = await authenticatedFetch(base, session, "/api/approvals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proposal: {} })
    });
    assert.equal(genericApproval.status, 404);
    const execute = await authenticatedFetch(base, session, "/api/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "nmap" })
    });
    assert.equal(execute.status, 404);
    const poisonedReportGeneration = await authenticatedFetch(base, session, "/api/reports/not-a-report/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "whoami" })
    });
    assert.equal(poisonedReportGeneration.status, 400);
    assert.deepEqual(await poisonedReportGeneration.json(), { error: "SCHEMA_INVALID" });
    const malformedPath = await authenticatedFetch(base, session, "/api/reports/%E0%A4%A/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
    assert.equal(malformedPath.status, 400);
    assert.deepEqual(await malformedPath.json(), { error: "REQUEST_FAILED" });
    const hostileOrigin = await fetch(`${base}/api/health`, { headers: { Origin: "https://attacker.example" } });
    assert.equal(hostileOrigin.status, 403);
    assert.deepEqual(await hostileOrigin.json(), { error: "LOOPBACK_ORIGIN_REQUIRED" });
    const wrongLoopbackPort = await fetch(`${base}/api/health`, { headers: { Origin: "http://127.0.0.1:65535" } });
    assert.equal(wrongLoopbackPort.status, 403);
  });

  it("exposes only a fixed mission-bound T0 planning route", async () => {
    const server = buildServer({ modelProvider: fakeModelProvider, bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base);
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Model route mission" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    await post(`/api/missions/${missionId}/scope`, {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      authorizationStatement: "I own and authorize this exact isolated model-route scope.",
      targets: [{ address: "8.8.8.8" }]
    });
    const planResponse = await post("/api/model/plan", {
      missionId,
      objective: "Prepare a cautious review plan"
    });
    assert.equal(planResponse.status, 201);
    const result = (await planResponse.json()) as { plan: { steps: Array<{ requiresHumanReview: boolean }> } };
    assert.equal(result.plan.steps[0]?.requiresHumanReview, true);
    const statusResponse = await authenticatedFetch(base, session, "/api/system/model");
    const status = (await statusResponse.json()) as { capabilities: { commandAccess: boolean }; invocations: unknown[] };
    assert.equal(status.capabilities.commandAccess, false);
    assert.equal(status.invocations.length, 1);
    const arbitrary = await post("/api/model/generate", { prompt: "run a command" });
    assert.equal(arbitrary.status, 404);
  });

  it("emergency stop aborts an in-flight model request and prevents success", async () => {
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const abortableProvider: ModelProvider = {
      ...fakeModelProvider,
      generate: async (_request, control) =>
        new Promise((_resolve, reject) => {
          markStarted();
          const rejectAborted = () => reject(new ModelProviderError("cancelled", "REQUEST_ABORTED"));
          if (control?.signal?.aborted) rejectAborted();
          else control?.signal?.addEventListener("abort", rejectAborted, { once: true });
        })
    };
    const server = buildServer({ modelProvider: abortableProvider, bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "stop operator");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Model cancellation mission" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    await post(`/api/missions/${missionId}/scope`, {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      authorizationStatement: "I own and authorize this exact cancellation test scope.",
      targets: [{ address: "8.8.8.8" }]
    });

    const pendingPlan = post("/api/model/plan", { missionId, objective: "Prepare a bounded plan" });
    await started;
    const stopped = await post("/api/emergency-stop", { reason: "Cancel the active model request now" });
    assert.equal(stopped.status, 200);
    const stoppedBody = (await stopped.json()) as { modelRequestsAborted: number };
    assert.equal(stoppedBody.modelRequestsAborted, 1);
    const planResponse = await pendingPlan;
    assert.equal(planResponse.status, 400);
    assert.deepEqual(await planResponse.json(), { error: "REQUEST_ABORTED" });

    const statusResponse = await authenticatedFetch(base, session, "/api/system/model");
    const status = (await statusResponse.json()) as { invocations: Array<{ status: string }> };
    assert.equal(status.invocations[0]?.status, "failed");
  });

  it("completes the manual evidence, reviewed finding, and deterministic report API flow", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "evidence reviewer");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Reporting API mission" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    await post(`/api/missions/${missionId}/scope`, {
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      authorizationStatement: "I own and authorize this isolated report API test target.",
      targets: [{ address: "8.8.8.8" }]
    });
    const evidenceResponse = await post("/api/evidence", { content: "sanitized training banner", mediaType: "text/plain" });
    assert.equal(evidenceResponse.status, 201);
    const artifactId = ((await evidenceResponse.json()) as { artifact: { id: string } }).artifact.id;
    const findingResponse = await post("/api/findings", {
      missionId,
      title: "Sanitized training banner observed",
      severity: "info",
      description: "The manually supplied sanitized evidence contains a training service banner.",
      remediation: "Remove unnecessary version details from the banner.",
      confidence: "high",
      evidenceArtifactIds: [artifactId]
    });
    assert.equal(findingResponse.status, 201);
    const findingId = ((await findingResponse.json()) as { findingId: string }).findingId;
    const revisionResponse = await post(`/api/findings/${findingId}/revisions`, {
      severity: "info",
      description: "A controlled retest reproduced the same sanitized training service banner observation.",
      remediation: "Keep the sanitized training service banner free of unnecessary version details.",
      confidence: "high",
      evidenceArtifactIds: [artifactId]
    });
    assert.equal(revisionResponse.status, 201);
    const findingsResponse = await authenticatedFetch(base, session, "/api/findings");
    const findingsBody = (await findingsResponse.json()) as {
      findings: Array<{
        id: string;
        status: string;
        revision: number;
        description: string;
        remediation: string;
        evidence_artifact_ids: string[];
      }>;
    };
    assert.equal(findingsBody.findings[0]?.id, findingId);
    assert.equal(findingsBody.findings[0]?.status, "unverified");
    assert.equal(findingsBody.findings[0]?.revision, 2);
    assert.match(findingsBody.findings[0]?.description ?? "", /controlled retest/);
    assert.match(findingsBody.findings[0]?.remediation ?? "", /version details/);
    assert.deepEqual(findingsBody.findings[0]?.evidence_artifact_ids, [artifactId]);
    const evidenceRegisterResponse = await authenticatedFetch(base, session, "/api/evidence");
    const evidenceRegister = (await evidenceRegisterResponse.json()) as {
      artifacts: Array<{
        id: string;
        verified: boolean;
        observation_count: number;
        latest_observation: { mission_id: string };
      }>;
    };
    const registeredArtifact = evidenceRegister.artifacts.find((artifact) => artifact.id === artifactId);
    assert.equal(registeredArtifact?.verified, true);
    assert.equal(registeredArtifact?.observation_count, 1);
    assert.equal(registeredArtifact?.latest_observation.mission_id, missionId);
    assert.equal((await post(`/api/findings/${findingId}/accept`, {})).status, 200);
    const freezeResponse = await post("/api/reports/freeze", { missionId, templateVersion: "template-v1" });
    assert.equal(freezeResponse.status, 201);
    const reportId = ((await freezeResponse.json()) as { report: { id: string } }).report.id;
    const generateResponse = await post(`/api/reports/${reportId}/generate`, {});
    assert.equal(generateResponse.status, 200);
    const generatedOutputs = (await generateResponse.json()) as {
      outputs: { jsonArtifactId: string; htmlArtifactId: string };
    };
    const reportsResponse = await authenticatedFetch(base, session, "/api/reports");
    const reportsBody = (await reportsResponse.json()) as {
      reports: Array<{ status: string; json_artifact_id: string; html_artifact_id: string }>;
    };
    assert.equal(reportsBody.reports[0]?.status, "generated");
    assert.equal(reportsBody.reports[0]?.json_artifact_id, generatedOutputs.outputs.jsonArtifactId);
    assert.equal(reportsBody.reports[0]?.html_artifact_id, generatedOutputs.outputs.htmlArtifactId);
    const openQaResponse = await post(`/api/reports/${reportId}/qa/open`, {});
    assert.equal(openQaResponse.status, 201);
    const openedQa = (await openQaResponse.json()) as {
      review: { id: string; status: string; publicationReady: boolean; outputs: unknown[] };
    };
    assert.equal(openedQa.review.status, "pending");
    assert.equal(openedQa.review.publicationReady, false);
    assert.equal(openedQa.review.outputs.length, 2);
    const invalidQaApproval = await post(`/api/report-qa/${openedQa.review.id}/approve`, {
      checklist: {
        scopeReviewed: true,
        claimsSupported: true,
        evidenceLinksVerified: true,
        remediationReviewed: true,
        sensitiveDataReviewed: true,
        layoutReviewed: false
      },
      note: "This should not pass the strict publication checklist."
    });
    assert.equal(invalidQaApproval.status, 400);
    assert.deepEqual(await invalidQaApproval.json(), { error: "SCHEMA_INVALID" });
    const approveQaResponse = await post(`/api/report-qa/${openedQa.review.id}/approve`, {
      checklist: {
        scopeReviewed: true,
        claimsSupported: true,
        evidenceLinksVerified: true,
        remediationReviewed: true,
        sensitiveDataReviewed: true,
        layoutReviewed: true
      },
      note: "Exact JSON and HTML outputs reviewed against the evidence register."
    });
    assert.equal(approveQaResponse.status, 200);
    const approvedQa = (await approveQaResponse.json()) as {
      review: { status: string; publicationReady: boolean; integrityValid: boolean };
    };
    assert.equal(approvedQa.review.status, "approved");
    assert.equal(approvedQa.review.publicationReady, true);
    assert.equal(approvedQa.review.integrityValid, true);
    const reviewedReportsResponse = await authenticatedFetch(base, session, "/api/reports");
    const reviewedReports = (await reviewedReportsResponse.json()) as {
      reports: Array<{ qa: { status: string; publicationReady: boolean } | null }>;
    };
    assert.equal(reviewedReports.reports[0]?.qa?.status, "approved");
    assert.equal(reviewedReports.reports[0]?.qa?.publicationReady, true);
    const generateExportResponse = await post(`/api/reports/${reportId}/exports/generate`, {});
    assert.equal(generateExportResponse.status, 201);
    const generatedExport = (await generateExportResponse.json()) as {
      bundle: { id: string; status: string; publicationReady: boolean };
    };
    assert.equal(generatedExport.bundle.status, "pending");
    assert.equal(generatedExport.bundle.publicationReady, false);
    const pdfDownload = await authenticatedFetch(
      base,
      session,
      `/api/report-exports/${generatedExport.bundle.id}/outputs/pdf?download=1`
    );
    assert.equal(pdfDownload.status, 200);
    assert.equal(Buffer.from(await pdfDownload.arrayBuffer()).subarray(0, 5).toString("ascii"), "%PDF-");
    const docxDownload = await authenticatedFetch(
      base,
      session,
      `/api/report-exports/${generatedExport.bundle.id}/outputs/docx?download=1`
    );
    assert.equal(docxDownload.status, 200);
    assert.equal(Buffer.from(await docxDownload.arrayBuffer()).subarray(0, 2).toString("ascii"), "PK");
    const approveExportResponse = await post(
      `/api/report-exports/${generatedExport.bundle.id}/approve`,
      {
        checklist: {
          pdfLayoutReviewed: true,
          docxLayoutReviewed: true,
          pageBreaksReviewed: true,
          evidenceReferencesReadable: true,
          sensitiveDataReviewed: true
        },
        note: "The exact PDF and DOCX downloads were opened and visually reviewed."
      }
    );
    assert.equal(approveExportResponse.status, 200);
    const approvedExport = (await approveExportResponse.json()) as {
      bundle: { status: string; publicationReady: boolean };
    };
    assert.equal(approvedExport.bundle.status, "approved");
    assert.equal(approvedExport.bundle.publicationReady, true);
    const htmlOutput = await authenticatedFetch(base, session, `/api/reports/${reportId}/outputs/html`);
    assert.equal(htmlOutput.status, 200);
    assert.match(htmlOutput.headers.get("content-type") ?? "", /^text\/html/);
    assert.match(htmlOutput.headers.get("content-disposition") ?? "", /^inline;/);
    assert.match(await htmlOutput.text(), /Sanitized training banner observed/);
    const jsonDownload = await authenticatedFetch(
      base,
      session,
      `/api/reports/${reportId}/outputs/json?download=1`
    );
    assert.equal(jsonDownload.status, 200);
    assert.match(jsonDownload.headers.get("content-disposition") ?? "", /^attachment;/);
    assert.equal(((await jsonDownload.json()) as { mission: { id: string } }).mission.id, missionId);
    const duplicateFreeze = await post("/api/reports/freeze", { missionId, templateVersion: "template-v1" });
    assert.equal(duplicateFreeze.status, 400);
    assert.deepEqual(await duplicateFreeze.json(), { error: "REPORT_ALREADY_CURRENT" });
  });

  it("requires a protected session and CSRF token and rejects operator spoofing", async () => {
    const server = buildServer({
      bootstrapSecret,
      operatorSessionOptions: { idleTtlMs: 1_000, absoluteTtlMs: 2_000 }
    }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;

    const unauthenticated = await fetch(`${base}/api/dashboard`);
    assert.equal(unauthenticated.status, 401);
    const missingOrigin = await fetch(`${base}/api/session/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bootstrapSecret, operator: "real operator" })
    });
    assert.equal(missingOrigin.status, 403);
    const wrongSecret = await fetch(`${base}/api/session/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: base },
      body: JSON.stringify({ bootstrapSecret: "wrong", operator: "real operator" })
    });
    assert.equal(wrongSecret.status, 401);

    const session = await unlock(base, "real operator");
    const cookieOnlyReplay = await fetch(`${base}/api/session`, {
      headers: { Cookie: session.cookie }
    });
    assert.equal(cookieOnlyReplay.status, 403);
    assert.deepEqual(await cookieOnlyReplay.json(), { error: "TAB_CAPABILITY_INVALID" });
    const cookieHeader = (await fetch(`${base}/api/session/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: base },
      body: JSON.stringify({ bootstrapSecret, operator: "second operator" })
    })).headers.get("set-cookie") ?? "";
    assert.match(cookieHeader, /HttpOnly/i);
    assert.match(cookieHeader, /SameSite=Strict/i);

    const noCsrf = await fetch(`${base}/api/missions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: base, Cookie: session.cookie },
      body: JSON.stringify({ name: "No CSRF mission" })
    });
    assert.equal(noCsrf.status, 403);
    const duplicateCookie = await fetch(`${base}/api/dashboard`, {
      headers: { Cookie: `${session.cookie}; ${session.cookie}` }
    });
    assert.equal(duplicateCookie.status, 403);

    const spoofedStop = await authenticatedFetch(base, session, "/api/emergency-stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operator: "forged operator", reason: "Stop the controlled test safely" })
    });
    assert.equal(spoofedStop.status, 400);
    const stopped = await authenticatedFetch(base, session, "/api/emergency-stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "Stop the controlled test safely" })
    });
    assert.equal(stopped.status, 200);
    const stoppedBody = (await stopped.json()) as { emergencyStop: { requested_by: string } };
    assert.equal(stoppedBody.emergencyStop.requested_by, "real operator");
  });

  it("creates a complete guided demo and mission cockpit without target authority", async () => {
    const server = buildServer({ bootstrapSecret, modelProvider: fakeModelProvider }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "guided demo operator");
    const poisoned = await authenticatedFetch(base, session, "/api/guided-demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: "run anything" })
    });
    assert.equal(poisoned.status, 400);
    assert.deepEqual(await poisoned.json(), { error: "SCHEMA_INVALID" });
    const created = await authenticatedFetch(base, session, "/api/guided-demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
    assert.equal(created.status, 201);
    const demo = (await created.json()) as {
      demo: {
        missionId: string;
        targetContact: boolean;
        commandExecution: boolean;
        reportSnapshotId: string;
      };
    };
    assert.equal(demo.demo.targetContact, false);
    assert.equal(demo.demo.commandExecution, false);
    const cockpitResponse = await authenticatedFetch(
      base,
      session,
      `/api/missions/${encodeURIComponent(demo.demo.missionId)}/cockpit`
    );
    assert.equal(cockpitResponse.status, 200);
    const cockpit = (await cockpitResponse.json()) as {
      cockpit: {
        profile: { mode: string; executionPermitted: boolean };
        authorization: { targetCount: number };
        purple: { exercised: number; total: number };
        checklist: Array<{ status: string }>;
        latestReport: { id: string; status: string } | null;
      };
    };
    assert.equal(cockpit.cockpit.profile.mode, "synthetic_demo");
    assert.equal(cockpit.cockpit.profile.executionPermitted, false);
    assert.equal(cockpit.cockpit.authorization.targetCount, 0);
    assert.equal(cockpit.cockpit.purple.exercised, 30);
    assert.equal(cockpit.cockpit.purple.total, 30);
    assert.equal(cockpit.cockpit.checklist.every((step) => step.status === "complete"), true);
    assert.equal(cockpit.cockpit.latestReport?.id, demo.demo.reportSnapshotId);
    assert.equal(cockpit.cockpit.latestReport?.status, "generated");
  });

  it("exposes immutable operator-owned test plans and bounded mission search", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "engagement planner");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const demoResponse = await post("/api/guided-demo", {});
    const demo = (await demoResponse.json()) as {
      demo: { missionId: string; evidenceArtifactId: string };
    };
    const planBody = {
      missionId: demo.demo.missionId,
      title: "Guided professional engagement plan",
      objective: "Track explicit authorized procedures and bind completion to verified evidence.",
      procedures: [{
        key: "blue-pipeline-validation",
        title: "Validate the defensive evidence pipeline",
        objective: "Confirm the synthetic Blue rule pipeline stores mission-bound evidence.",
        steps: ["Run the safe combined defensive scenario and review the sealed output."],
        state: "completed",
        rationale: "The guided demonstration already produced the exact verified evidence.",
        capabilityId: "simulation.evasion-detection",
        blueRuleId: null,
        runId: null,
        evidenceArtifactIds: [demo.demo.evidenceArtifactId]
      }]
    };
    const spoofed = await post("/api/test-plans", {
      ...planBody,
      createdBy: "spoofed operator"
    });
    assert.equal(spoofed.status, 400);
    assert.deepEqual(await spoofed.json(), { error: "SCHEMA_INVALID" });
    const createResponse = await post("/api/test-plans", planBody);
    assert.equal(createResponse.status, 201);
    const created = (await createResponse.json()) as {
      plan: {
        id: string;
        createdBy: string;
        integrityValid: boolean;
        summary: { completed: number };
      };
    };
    assert.equal(created.plan.createdBy, "engagement planner");
    assert.equal(created.plan.integrityValid, true);
    assert.equal(created.plan.summary.completed, 1);
    const listResponse = await authenticatedFetch(
      base,
      session,
      `/api/test-plans?missionId=${encodeURIComponent(demo.demo.missionId)}`
    );
    const plans = (await listResponse.json()) as { plans: Array<{ id: string }> };
    assert.equal(plans.plans[0]?.id, created.plan.id);
    const searchResponse = await post("/api/search", {
      missionId: demo.demo.missionId,
      query: "defensive",
      kinds: ["test-plan", "procedure"],
      limit: 10
    });
    assert.equal(searchResponse.status, 200);
    const search = (await searchResponse.json()) as {
      search: { returned: number; results: Array<{ kind: string; id: string }> };
    };
    assert.equal(search.search.returned, 1);
    assert.equal(search.search.results[0]?.kind, "procedure");
  });

  it("wires inert imports and evidence-backed remediation into the mission workflow", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "workflow reviewer");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

    const demoResponse = await post("/api/guided-demo", {});
    const demo = (await demoResponse.json()) as {
      demo: { missionId: string; findingId: string; evidenceArtifactId: string };
    };
    const sarif = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "Fixture Scanner", rules: [{ id: "SAFE-001" }] } },
          results: [
            {
              ruleId: "SAFE-001",
              level: "note",
              kind: "review",
              message: { text: "Fixture result requiring human evidence review." }
            }
          ]
        }
      ]
    };
    const importedResponse = await post("/api/imports/sarif", {
      missionId: demo.demo.missionId,
      contentBase64: Buffer.from(JSON.stringify(sarif), "utf8").toString("base64")
    });
    assert.equal(importedResponse.status, 201);
    const imported = (await importedResponse.json()) as {
      imported: { missionId: string; resultCount: number; candidateCount: number; integrityValid: boolean };
    };
    assert.equal(imported.imported.missionId, demo.demo.missionId);
    assert.equal(imported.imported.resultCount, 1);
    assert.equal(imported.imported.candidateCount, 1);
    assert.equal(imported.imported.integrityValid, true);

    const dueDate = new Date(Date.now() + 24 * 60 * 60_000).toISOString().slice(0, 10);
    const createdResponse = await post(`/api/findings/${demo.demo.findingId}/remediation`, {
      owner: "Lab owner",
      dueDate,
      priority: "low"
    });
    assert.equal(createdResponse.status, 201);
    const created = (await createdResponse.json()) as { remediation: { id: string; status: string } };
    const remediationId = created.remediation.id;
    assert.equal(created.remediation.status, "open");

    await post(`/api/remediations/${remediationId}/status`, { status: "in-progress" });
    const rejectedCapture = await post(`/api/remediations/${remediationId}/fix-evidence/captures`, {
      changeType: "operational-mitigation",
      actionPerformedAt: new Date().toISOString(),
      actionSummary: "Reviewed the synthetic workflow and recorded the bounded training follow-up.",
      observedState: "The operator confirmed that the demonstration remained offline and synthetic.",
      command: "not-allowed"
    });
    assert.equal(rejectedCapture.status, 400);
    const capturedResponse = await post(`/api/remediations/${remediationId}/fix-evidence/captures`, {
      changeType: "operational-mitigation",
      actionPerformedAt: new Date().toISOString(),
      actionSummary: "Reviewed the synthetic workflow and recorded the bounded training follow-up.",
      observedState: "The operator confirmed that the demonstration remained offline and synthetic."
    });
    assert.equal(capturedResponse.status, 201);
    const captured = (await capturedResponse.json()) as {
      artifact: { id: string };
      remediation: { fixEvidence: Array<{ artifactId: string }> };
    };
    assert.equal(captured.remediation.fixEvidence[0]?.artifactId, captured.artifact.id);
    assert.notEqual(captured.artifact.id, demo.demo.evidenceArtifactId);
    await post(`/api/remediations/${remediationId}/status`, { status: "fix-ready" });
    const retestResponse = await post(`/api/remediations/${remediationId}/retests`, {
      reason: "Confirm the safe training workflow remains reproducible after review."
    });
    assert.equal(retestResponse.status, 201);
    const retest = (await retestResponse.json()) as { requestId: string };
    const outcomeResponse = await post(`/api/remediations/${remediationId}/retests/outcome`, {
      requestId: retest.requestId,
      outcome: "remediated",
      summary: "The controlled synthetic workflow was repeated and the reviewed follow-up is complete.",
      reviewer: "Workflow reviewer",
      evidenceArtifactIds: [demo.demo.evidenceArtifactId]
    });
    assert.equal(outcomeResponse.status, 200);
    const outcome = (await outcomeResponse.json()) as {
      remediation: { status: string; integrityValid: boolean; retests: Array<{ outcome: string }> };
    };
    assert.equal(outcome.remediation.status, "remediated");
    assert.equal(outcome.remediation.integrityValid, true);
    assert.equal(outcome.remediation.retests[0]?.outcome, "remediated");
    const cockpitResponse = await authenticatedFetch(
      base,
      session,
      `/api/missions/${encodeURIComponent(demo.demo.missionId)}/cockpit`
    );
    const cockpit = (await cockpitResponse.json()) as {
      cockpit: { counts: { remediations: number; openRemediations: number; imports: number } };
    };
    assert.equal(cockpit.cockpit.counts.remediations, 1);
    assert.equal(cockpit.cockpit.counts.openRemediations, 1);
    assert.equal(cockpit.cockpit.counts.imports, 1);
  });

  it("enrolls a real local key and correlates signed minimized facts without trusting sensor labels", async () => {
    const server = buildServer({ bootstrapSecret }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    const session = await unlock(base, "endpoint reviewer");
    const post = (path: string, body: unknown) =>
      authenticatedFetch(base, session, path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const submitSensor = (path: string, body: unknown) =>
      fetch(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    const missionResponse = await post("/api/missions", { name: "Endpoint intake fixture mission" });
    const missionId = ((await missionResponse.json()) as { mission: { id: string } }).mission.id;
    const keyPair = generateKeyPairSync("ed25519");
    const publicKeySpki = keyPair.publicKey.export({ format: "der", type: "spki" });
    const publicKeySpkiBase64 = publicKeySpki.toString("base64");
    const fingerprint = createHash("sha256").update(publicKeySpki).digest("hex");
    const challengeResponse = await post("/api/endpoints/enrollment-challenges", {
      missionId,
      certificateFingerprintSha256: fingerprint,
      identityExpiresAt: new Date(Date.now() + 60 * 60_000).toISOString()
    });
    assert.equal(challengeResponse.status, 201);
    const challenge = (await challengeResponse.json()) as {
      challenge: {
        id: string;
        payload: { connectorId: string; endpointId: string } & Record<string, unknown>;
      };
    };
    const keyRegistrationResponse = await post(
      `/api/endpoints/enrollment-challenges/${challenge.challenge.id}/public-key`,
      { publicKeySpkiBase64 }
    );
    assert.equal(keyRegistrationResponse.status, 201);
    const challengePayload = stableJson(challenge.challenge.payload);
    const approvalResponse = await post(
      `/api/endpoints/enrollment-challenges/${challenge.challenge.id}/approve`,
      {
        confirmedCertificateFingerprintSha256: fingerprint,
        proofSignatureBase64: sign(
          null,
          Buffer.from(challengePayload, "utf8"),
          keyPair.privateKey
        ).toString("base64")
      }
    );
    assert.equal(approvalResponse.status, 200);

    const now = Date.now();
    const capabilityCore = {
      schemaVersion: 1 as const,
      missionId,
      connectorId: challenge.challenge.payload.connectorId,
      endpointId: challenge.challenge.payload.endpointId,
      certificateFingerprintSha256: fingerprint,
      provider: "windows-security" as const,
      channel: "security" as const,
      eventFamily: "event-log-clear" as const,
      fields: [
        "action",
        "actorTrust",
        "objectClass",
        "outcome",
        "subjectClass"
      ] as EndpointFactFieldName[],
      filterHash: "c".repeat(64),
      collectorVersion: "fixture-sensor-0.1.0",
      loss: { state: "none" as const, lostRecordCount: 0 as const },
      continuity: "continuous" as const,
      continuousSince: new Date(now - 120_000).toISOString(),
      lastSuccessfulReadAt: new Date(now).toISOString(),
      observedAt: new Date(now).toISOString(),
      freshnessSeconds: 120
    };
    const capabilityPayload = stableJson(capabilityCore);
    const capabilityResponse = await submitSensor("/api/endpoints/capabilities", {
      ...capabilityCore,
      reportHash: endpointCapabilityReportHash(capabilityCore),
      signatureBase64: sign(
        null,
        Buffer.from(capabilityPayload, "utf8"),
        keyPair.privateKey
      ).toString("base64")
    });
    assert.equal(capabilityResponse.status, 201);
    const capability = (await capabilityResponse.json()) as {
      capability: { id: string; health: string };
    };
    assert.equal(capability.capability.health, "healthy");

    const factCore = {
      schemaVersion: 1 as const,
      missionId,
      connectorId: challenge.challenge.payload.connectorId,
      endpointId: challenge.challenge.payload.endpointId,
      certificateFingerprintSha256: fingerprint,
      capabilitySnapshotId: capability.capability.id,
      bootId: "boot-fixture-0001",
      batchSequence: 0,
      previousBatchHash: null,
      provider: "windows-security" as const,
      channel: "security" as const,
      eventFamily: "event-log-clear" as const,
      filterHash: capabilityCore.filterHash,
      facts: [{
        factId: "fact-fixture-0001",
        occurredAt: new Date(now - 20_000).toISOString(),
        sourceRecordIdHash: "d".repeat(64),
        fields: {
          actorTrust: "untrusted" as const,
          action: "clear" as const,
          subjectClass: "admin-tool" as const,
          objectClass: "event-log" as const,
          outcome: "success" as const
        }
      }]
    };
    const factPayload = stableJson(factCore);
    const signedFactBatch = {
      ...factCore,
      batchHash: endpointFactBatchHash(factCore),
      signatureBase64: sign(
        null,
        Buffer.from(factPayload, "utf8"),
        keyPair.privateKey
      ).toString("base64")
    };
    const intakeResponse = await submitSensor("/api/endpoints/facts", signedFactBatch);
    assert.equal(intakeResponse.status, 202);
    const intake = await intakeResponse.json();
    assert.deepEqual(intake, {
      receipt: {
        schemaVersion: 1,
        status: "accepted",
        batchHash: signedFactBatch.batchHash,
        batchSequence: 0,
        factCount: 1
      }
    });
    assert.equal(JSON.stringify(intake).includes("evidenceArtifactId"), false);
    assert.deepEqual(
      await (await submitSensor("/api/endpoints/facts", signedFactBatch)).json(),
      intake
    );

    const correlationResponse = await post("/api/blue/live-correlations", {
      missionId,
      endpointId: challenge.challenge.payload.endpointId,
      ruleIds: ["BR-EVASION-003"],
      windowStart: new Date(now - 60_000).toISOString(),
      windowEnd: new Date(now).toISOString()
    });
    assert.equal(correlationResponse.status, 201);
    const correlation = (await correlationResponse.json()) as {
      run: {
        integrityValid: boolean;
        result: { verdict: string; alerts: Array<{ ruleId: string; matchedFactIds: string[] }> };
      };
    };
    assert.equal(correlation.run.integrityValid, true);
    assert.equal(correlation.run.result.verdict, "reviewable-alerts-produced");
    assert.equal(correlation.run.result.alerts[0]?.ruleId, "BR-EVASION-003");
    assert.deepEqual(correlation.run.result.alerts[0]?.matchedFactIds, ["fact-fixture-0001"]);

    const endpointResponse = await authenticatedFetch(
      base,
      session,
      `/api/endpoints?missionId=${encodeURIComponent(missionId)}`
    );
    const endpoints = (await endpointResponse.json()) as {
      trustConfigured: boolean;
      endpoints: Array<{ missionId: string }>;
      intake: { commandChannel: boolean; remoteShell: boolean; responseActions: boolean };
    };
    assert.equal(endpoints.trustConfigured, true);
    assert.equal(endpoints.endpoints[0]?.missionId, missionId);
    assert.deepEqual(endpoints.intake, {
      direction: "endpoint-to-war-room-only",
      commandChannel: false,
      remoteShell: false,
      responseActions: false
    });
    const capabilitiesResponse = await authenticatedFetch(
      base,
      session,
      `/api/endpoints/${encodeURIComponent(challenge.challenge.payload.endpointId)}/capabilities?missionId=${encodeURIComponent(missionId)}`
    );
    const capabilities = (await capabilitiesResponse.json()) as {
      capabilities: Array<{ health: string; eventFamily: string }>;
    };
    assert.equal(capabilities.capabilities[0]?.health, "healthy");
    assert.equal(capabilities.capabilities[0]?.eventFamily, "event-log-clear");
    const blueResponse = await authenticatedFetch(
      base,
      session,
      `/api/blue?missionId=${encodeURIComponent(missionId)}`
    );
    const blue = (await blueResponse.json()) as {
      coverage: { liveSupportedRuleIds: string[]; liveStatus: string };
      liveRuns: unknown[];
      validationMatrix: Array<{
        ruleId: string;
        liveValidation: { status: string; endpointEvidencePresent: boolean };
      }>;
    };
    assert.deepEqual(blue.coverage.liveSupportedRuleIds, ["BR-EVASION-003"]);
    assert.equal(blue.coverage.liveStatus, "window-validated");
    assert.equal(blue.liveRuns.length, 1);
    const liveRow = blue.validationMatrix.find((row) => row.ruleId === "BR-EVASION-003");
    assert.equal(liveRow?.liveValidation.status, "live-supported");
    assert.equal(liveRow?.liveValidation.endpointEvidencePresent, true);

    const replacementKeyPair = generateKeyPairSync("ed25519");
    const replacementSpki = replacementKeyPair.publicKey.export({
      format: "der",
      type: "spki"
    });
    const replacementFingerprint = createHash("sha256")
      .update(replacementSpki)
      .digest("hex");
    const renewalResponse = await post(
      `/api/endpoints/${encodeURIComponent(challenge.challenge.payload.endpointId)}/renewal-challenges`,
      {
        certificateFingerprintSha256: replacementFingerprint,
        identityExpiresAt: new Date(Date.now() + 2 * 60 * 60_000).toISOString(),
        reason: "Routine fixture identity rotation before expiry."
      }
    );
    assert.equal(renewalResponse.status, 201);
    const renewal = (await renewalResponse.json()) as {
      renewal: { id: string; status: string; previousEndpointId: string };
      challenge: {
        id: string;
        payload: { endpointId: string } & Record<string, unknown>;
      };
    };
    assert.equal(renewal.renewal.status, "pending");
    assert.equal(
      renewal.renewal.previousEndpointId,
      challenge.challenge.payload.endpointId
    );
    assert.equal(
      (
        await post(
          `/api/endpoints/enrollment-challenges/${renewal.challenge.id}/public-key`,
          { publicKeySpkiBase64: replacementSpki.toString("base64") }
        )
      ).status,
      201
    );
    const renewalApprovalResponse = await post(
      `/api/endpoints/renewal-challenges/${renewal.challenge.id}/approve`,
      {
        confirmedCertificateFingerprintSha256: replacementFingerprint,
        proofSignatureBase64: sign(
          null,
          Buffer.from(stableJson(renewal.challenge.payload), "utf8"),
          replacementKeyPair.privateKey
        ).toString("base64")
      }
    );
    assert.equal(renewalApprovalResponse.status, 200);
    const renewalApproval = (await renewalApprovalResponse.json()) as {
      renewal: { status: string };
      previousIdentity: { status: string };
      replacementIdentity: { status: string; endpointId: string };
    };
    assert.equal(renewalApproval.renewal.status, "activated");
    assert.equal(renewalApproval.previousIdentity.status, "revoked");
    assert.equal(renewalApproval.replacementIdentity.status, "active");
    assert.equal(
      renewalApproval.replacementIdentity.endpointId,
      renewal.challenge.payload.endpointId
    );
    const renewedEndpointsResponse = await authenticatedFetch(
      base,
      session,
      `/api/endpoints?missionId=${encodeURIComponent(missionId)}`
    );
    const renewedEndpoints = (await renewedEndpointsResponse.json()) as {
      endpoints: Array<{ endpointId: string; status: string }>;
      renewals: Array<{ id: string; status: string }>;
    };
    assert.equal(
      renewedEndpoints.endpoints.find(
        (endpoint) => endpoint.endpointId === challenge.challenge.payload.endpointId
      )?.status,
      "revoked"
    );
    assert.equal(
      renewedEndpoints.endpoints.find(
        (endpoint) => endpoint.endpointId === renewal.challenge.payload.endpointId
      )?.status,
      "active"
    );
    assert.equal(renewedEndpoints.renewals[0]?.status, "activated");

    const retiredTelemetry = await post("/api/endpoints/telemetry", { retired: true });
    assert.equal(retiredTelemetry.status, 400);
    assert.deepEqual(await retiredTelemetry.json(), {
      error: "ENDPOINT_TELEMETRY_SCHEMA_RETIRED"
    });
    const cockpitResponse = await authenticatedFetch(
      base,
      session,
      `/api/missions/${encodeURIComponent(missionId)}/cockpit`
    );
    const cockpit = (await cockpitResponse.json()) as {
      cockpit: { counts: { endpoints: number } };
    };
    assert.equal(cockpit.cockpit.counts.endpoints, 2);
  });
});
