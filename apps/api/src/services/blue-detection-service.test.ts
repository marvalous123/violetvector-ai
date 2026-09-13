import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import {
  analyseSyntheticTelemetry,
  BLUE_RULES,
  BLUE_SCENARIOS,
  BlueDetectionService,
  scenarioTelemetry
} from "./blue-detection-service.js";
import { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";

const now = new Date("2026-07-19T12:00:00.000Z");

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Offline blue-team training lab", now);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-blue-")), audit);
  const service = new BlueDetectionService(database, evidence, audit);
  return { database, audit, missions, mission, evidence, service };
}

describe("offline blue-team detections", () => {
  it("exposes closed defensive rules and synthetic scenarios only", () => {
    assert.equal(BLUE_RULES.length, 30);
    assert.equal(BLUE_SCENARIOS.length, 4);
    assert.deepEqual(new Set(BLUE_RULES.map((rule) => rule.id)).size, BLUE_RULES.length);
    assert.deepEqual(new Set(BLUE_RULES.map((rule) => rule.signal)).size, BLUE_RULES.length);
    for (const category of ["credential-access", "payload-execution", "defense-evasion"]) {
      assert.equal(BLUE_RULES.filter((rule) => rule.category === category).length, 10);
    }
    assert.equal(BLUE_SCENARIOS.every((scenario) => scenario.synthetic), true);
    assert.equal(BLUE_RULES.every((rule) => rule.readiness === "synthetic-validated"), true);
    assert.equal(BLUE_RULES.every((rule) => rule.liveStatus === "connector-required"), true);
    const serialized = JSON.stringify({ rules: BLUE_RULES, scenarios: BLUE_SCENARIOS });
    assert.doesNotMatch(serialized, /commandLine|rawCommand|payloadBytes|passwordValue|secretValue|tokenValue/);
  });

  it("matches each built-in behaviour without accepting operational instructions", () => {
    const expected = new Map([
      ["credential-access", 10],
      ["payload-execution", 10],
      ["defense-evasion", 10],
      ["combined-incident", 30]
    ]);
    for (const [scenarioId, alertCount] of expected) {
      const alerts = analyseSyntheticTelemetry(
        scenarioTelemetry(scenarioId as Parameters<typeof scenarioTelemetry>[0], now)
      );
      assert.equal(alerts.length, alertCount);
      assert.equal(alerts.every((item) => item.disposition === "needs-review"), true);
    }
  });

  it("does not alert on a managed benign baseline", () => {
    const alerts = analyseSyntheticTelemetry([
      {
        eventId: "evt-benign-process",
        occurredAt: now.toISOString(),
        assetId: "lab-endpoint-01",
        source: "synthetic",
        telemetryClass: "endpoint",
        signal: "security-tool-impairment",
        actorTrust: "managed",
        normalizedBy: "war-room-blue-v1"
      }
    ]);
    assert.deepEqual(alerts, []);
  });

  it("shows evidence-bound synthetic coverage without implying live endpoint support", () => {
    const { database, missions, mission, service } = setup();
    const initial = service.validationMatrix(mission.id);
    assert.equal(initial.length, 30);
    assert.equal(initial.every((item) => item.syntheticValidation.status === "not-run"), true);
    assert.equal(initial.every((item) => item.liveValidation.status === "connector-required"), true);
    assert.equal(initial.every((item) => item.liveValidation.endpointEvidencePresent === false), true);

    const run = service.runSimulation(mission.id, "credential-access", "blue analyst", now);
    const exercised = service.validationMatrix(mission.id);
    const credentialRows = exercised.filter((item) => item.category === "credential-access");
    assert.equal(credentialRows.length, 10);
    assert.equal(credentialRows.every((item) => item.syntheticValidation.status === "detected"), true);
    assert.equal(credentialRows.every((item) => item.syntheticValidation.latestRunId === run.id), true);
    assert.equal(
      credentialRows.every((item) => item.syntheticValidation.evidenceArtifactId === run.evidenceArtifactId),
      true
    );
    assert.equal(
      exercised.filter((item) => item.category !== "credential-access")
        .every((item) => item.syntheticValidation.status === "not-run"),
      true
    );
    const otherMission = missions.createMission("Separate blue-team mission", new Date(now.getTime() + 1_000));
    const otherMissionMatrix = service.validationMatrix(otherMission.id);
    assert.equal(otherMissionMatrix.every((item) => item.syntheticValidation.status === "not-run"), true);
    assert.equal(
      otherMissionMatrix.every((item) => item.syntheticValidation.evidenceArtifactId === null),
      true
    );
    database.close();
  });

  it("seals a mission-bound combined result and keeps the run immutable", () => {
    const { database, audit, mission, evidence, service } = setup();
    const run = service.runSimulation(mission.id, "combined-incident", "blue analyst", now);
    assert.equal(run.alertCount, 30);
    assert.equal(run.eventCount, 30);
    assert.equal(run.integrityValid, true);
    assert.equal(evidence.verify(run.evidenceArtifactId), true);
    assert.equal(evidence.observationForMission(run.evidenceArtifactId, mission.id).mission_id, mission.id);
    assert.equal(audit.verify().valid, true);
    assert.throws(
      () => database.prepare("UPDATE blue_detection_runs SET alert_count = 0 WHERE id = ?").run(run.id),
      /BLUE_DETECTION_RUN_IMMUTABLE/
    );
    database.close();
  });

  it("detects result-record or evidence tampering during readback", () => {
    const { database, mission, service } = setup();
    const run = service.runSimulation(mission.id, "credential-access", "blue analyst", now);
    database.exec("DROP TRIGGER blue_detection_runs_immutable_update");
    database.prepare("UPDATE blue_detection_runs SET result_hash = ? WHERE id = ?").run("0".repeat(64), run.id);
    assert.equal(service.get(run.id).integrityValid, false);
    database.close();
  });
});
