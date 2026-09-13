import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { MissionService } from "./mission-service.js";
import { RunControlService } from "./run-control-service.js";

const now = new Date("2026-07-16T22:00:00.000Z");
const budget = {
  wallTimeMsLimit: 60_000,
  toolTimeMsLimit: 30_000,
  modelTokensLimit: 1_000,
  outputBytesLimit: 64_000,
  requestCountLimit: 10
};

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Run control test mission", now);
  missions.createScopeVersion(
    {
      missionId: mission.id,
      startsAt: "2026-07-16T21:00:00.000Z",
      expiresAt: "2026-07-16T23:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize this isolated test target.",
      targets: [{ address: "8.8.8.8" }]
    },
    now
  );
  const controls = new RunControlService(database, audit);
  return { database, audit, mission, controls };
}

describe("run budgets and lineage", () => {
  it("records bounded usage and rejects the first over-budget delta", () => {
    const { database, controls, mission } = setup();
    const runId = controls.createRun({ missionId: mission.id, budget, now });
    assert.deepEqual(controls.recordUsage(runId, { modelTokens: 400, requestCount: 1 }, "model plan", now), {
      wallTimeMs: 0,
      toolTimeMs: 0,
      modelTokens: 400,
      outputBytes: 0,
      requestCount: 1
    });
    assert.throws(
      () => controls.recordUsage(runId, { modelTokens: 601 }, "over budget", now),
      /BUDGET_EXCEEDED:modelTokens/
    );
    assert.equal(controls.getUsage(runId).modelTokens, 400);
    database.close();
  });

  it("creates replay and retest runs with explicit parent lineage", () => {
    const { database, controls, mission } = setup();
    const original = controls.createRun({ missionId: mission.id, budget, now });
    const replay = controls.createRun({ missionId: mission.id, budget, parentRunId: original, lineageType: "replay", now });
    const row = database.prepare("SELECT parent_run_id, lineage_type FROM runs WHERE id = ?").get(replay) as {
      parent_run_id: string;
      lineage_type: string;
    };
    assert.equal(row.parent_run_id, original);
    assert.equal(row.lineage_type, "replay");
    assert.throws(() => controls.createRun({ missionId: mission.id, budget, lineageType: "retest", now }), /RUN_PARENT_REQUIRED/);
    database.close();
  });
});

describe("emergency stop", () => {
  it("blocks new runs until the stop lifecycle is completed and reset", () => {
    const { database, audit, controls, mission } = setup();
    controls.createRun({ missionId: mission.id, budget, now });
    assert.equal(controls.requestStop("operator", "safety test stop", now).state, "stop_requested");
    assert.throws(() => controls.createRun({ missionId: mission.id, budget, now }), /EMERGENCY_STOP_ACTIVE/);
    assert.equal(controls.transitionStop("phase1_halted", "system", now).state, "phase1_halted");
    assert.equal(controls.transitionStop("draining", "system", now).state, "draining");
    assert.equal(controls.transitionStop("stopped", "system", now).state, "stopped");
    assert.equal(controls.transitionStop("ready", "operator", now).state, "ready");
    assert.doesNotThrow(() => controls.createRun({ missionId: mission.id, budget, now }));
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects unsafe stop-state jumps", () => {
    const { database, controls } = setup();
    controls.requestStop("operator", "safety test stop", now);
    assert.throws(() => controls.transitionStop("ready", "operator", now), /STOP_TRANSITION_INVALID/);
    database.close();
  });
});
