import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { BlueDetectionService } from "./blue-detection-service.js";
import { EvidenceService } from "./evidence-service.js";
import { FindingService } from "./finding-service.js";
import { GuidedDemoService } from "./guided-demo-service.js";
import { MissionCockpitService } from "./mission-cockpit-service.js";
import { MissionService } from "./mission-service.js";
import { ReportService } from "./report-service.js";

const now = new Date("2026-07-19T14:00:00.000Z");

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-guided-demo-")), audit);
  const blue = new BlueDetectionService(database, evidence, audit);
  const findings = new FindingService(database, evidence, audit);
  const reports = new ReportService(database, evidence, audit);
  const demo = new GuidedDemoService(database, missions, blue, findings, reports, audit);
  const cockpit = new MissionCockpitService(database, blue, audit);
  return { database, audit, missions, evidence, demo, cockpit };
}

describe("guided synthetic mission", () => {
  it("creates the complete evidence journey without target or command authority", () => {
    const { database, audit, missions, evidence, demo, cockpit } = setup();
    const result = demo.create("demo operator", now);
    assert.equal(result.boundary, "offline-synthetic-only");
    assert.equal(result.targetContact, false);
    assert.equal(result.commandExecution, false);
    assert.equal(evidence.verify(result.evidenceArtifactId), true);
    assert.equal(evidence.verify(result.jsonArtifactId), true);
    assert.equal(evidence.verify(result.htmlArtifactId), true);
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM scope_targets st JOIN scope_versions sv ON sv.id = st.scope_version_id WHERE sv.mission_id = ?").get(result.missionId) as { count: number }).count,
      0
    );
    assert.equal(
      (database.prepare("SELECT execution_permitted FROM mission_profiles WHERE mission_id = ?").get(result.missionId) as { execution_permitted: number }).execution_permitted,
      0
    );
    assert.throws(
      () =>
        missions.createScopeVersion({
          missionId: result.missionId,
          startsAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + 60_000).toISOString(),
          policyVersion: "policy-v1",
          authorizationStatement: "Attempt to replace the locked demo scope.",
          targets: [{ address: "8.8.8.8" }]
        }),
      /MISSION_SCOPE_LOCKED/
    );
    const view = cockpit.get(result.missionId);
    assert.equal(view.profile.mode, "synthetic_demo");
    assert.equal(view.profile.executionPermitted, false);
    assert.equal(view.authorization.targetCount, 0);
    assert.equal(view.purple.exercised, 30);
    assert.equal(view.purple.integrityFailed, 0);
    assert.equal(view.checklist.every((step) => step.status === "complete"), true);
    assert.equal(view.latestReport?.status, "generated");
    assert.equal(view.integrity.auditValid, true);
    assert.equal(audit.verify().valid, true);
    assert.throws(
      () => database.prepare("UPDATE guided_demo_instances SET created_by = 'other' WHERE mission_id = ?").run(result.missionId),
      /GUIDED_DEMO_INSTANCE_IMMUTABLE/
    );
    database.close();
  });

  it("keeps ordinary draft missions pending and separate", () => {
    const { database, missions, cockpit } = setup();
    const ordinary = missions.createMission("Ordinary authorized lab", now);
    const view = cockpit.get(ordinary.id);
    assert.equal(view.profile.mode, "standard");
    assert.equal(view.profile.executionPermitted, false);
    assert.equal(view.authorization.present, false);
    assert.equal(view.purple.exercised, 0);
    assert.equal(view.checklist.find((step) => step.key === "authorization")?.status, "pending");
    assert.equal(view.checklist.find((step) => step.key === "report")?.status, "pending");
    database.close();
  });
});
