import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { ModelProvider } from "@war-room/model-provider";
import { openDatabase } from "../db/database.js";
import { MissionService } from "./mission-service.js";
import { ModelService } from "./model-service.js";

const now = new Date("2026-07-17T08:00:00.000Z");

function fakeProvider(): ModelProvider {
  return {
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
      checkedAt: now.toISOString()
    }),
    generate: async (request) => {
      assert.equal(request.profile, "structured-planning");
      assert.doesNotMatch(JSON.stringify(request), /8\.8\.8\.8/);
      return {
        output: {
          objective: "Review the authorized lab safely",
          assumptions: ["Exact scope remains active"],
          steps: [
            {
              description: "Review the stored authorization and scope",
              rationale: "Confirm constraints before any separate action proposal",
              requiresHumanReview: true
            }
          ],
          openQuestions: []
        },
        metadata: {
          provider: "ollama",
          model: "test-model",
          profile: "structured-planning",
          taskTier: "T0",
          authority: "none",
          latencyMs: 12,
          usage: { inputTokens: 40, outputTokens: 30 },
          providerDurationsNs: { total: null, load: null, promptEvaluation: null, evaluation: null }
        }
      };
    }
  };
}

describe("model service", () => {
  it("stores a bounded T0 advisory plan without exposing target addresses", async () => {
    const database = openDatabase();
    const missions = new MissionService(database);
    const mission = missions.createMission("T0 planning test", now);
    missions.createScopeVersion(
      {
        missionId: mission.id,
        startsAt: "2026-07-17T07:00:00.000Z",
        expiresAt: "2026-07-17T09:00:00.000Z",
        policyVersion: "policy-v1",
        authorizationStatement: "I own and authorize this exact isolated test scope.",
        targets: [{ address: "8.8.8.8" }]
      },
      now
    );
    const service = new ModelService(database, fakeProvider());
    const result = await service.createPlan({ missionId: mission.id, objective: "Prepare a safe review plan", now });
    assert.equal(result.invocation.status, "succeeded");
    assert.ok(result.invocation.run_id);
    assert.equal(result.invocation.prompt_tokens, 40);
    assert.equal(result.invocation.completion_tokens, 30);
    assert.equal(result.plan.steps[0]?.requiresHumanReview, true);
    assert.equal(service.listInvocations().length, 1);
    const run = database.prepare("SELECT status FROM runs WHERE id = ?").get(result.invocation.run_id) as { status: string };
    assert.equal(run.status, "succeeded");
    const usage = database
      .prepare("SELECT model_tokens, request_count FROM usage_ledger WHERE run_id = ?")
      .get(result.invocation.run_id) as { model_tokens: number; request_count: number };
    assert.equal(usage.model_tokens, 70);
    assert.equal(usage.request_count, 1);
    database.close();
  });

  it("fails closed when a provider claims execution authority", async () => {
    const database = openDatabase();
    const missions = new MissionService(database);
    const mission = missions.createMission("Authority rejection test", now);
    missions.createScopeVersion(
      {
        missionId: mission.id,
        startsAt: "2026-07-17T07:00:00.000Z",
        expiresAt: "2026-07-17T09:00:00.000Z",
        policyVersion: "policy-v1",
        authorizationStatement: "I own and authorize this exact isolated test scope.",
        targets: [{ address: "8.8.4.4" }]
      },
      now
    );
    const unsafe = fakeProvider();
    unsafe.capabilities = () => ({ ...fakeProvider().capabilities(), commandAccess: true as false });
    await assert.rejects(
      () => new ModelService(database, unsafe).createPlan({ missionId: mission.id, objective: "Prepare a plan", now }),
      /MODEL_AUTHORITY_INVALID/
    );
    database.close();
  });
});
