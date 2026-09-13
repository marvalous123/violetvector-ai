import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";
import { TestPlanService } from "./test-plan-service.js";

const now = new Date("2026-07-19T14:00:00.000Z");

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-test-plan-")), audit);
  const service = new TestPlanService(database, evidence, audit);
  const mission = missions.createMission("Versioned engagement plan lab", now);
  return { database, audit, missions, evidence, service, mission };
}

function insertRun(database: ReturnType<typeof openDatabase>, missionId: string): string {
  const runId = randomUUID();
  database
    .prepare(
      `INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at)
       VALUES (?, ?, NULL, 'original', 'succeeded', ?, ?)`
    )
    .run(runId, missionId, now.toISOString(), now.toISOString());
  return runId;
}

describe("versioned engagement test plans", () => {
  it("seals explicit procedure dispositions, mappings and verified evidence as immutable versions", () => {
    const { database, audit, evidence, service, mission } = setup();
    const runId = insertRun(database, mission.id);
    const completedEvidence = evidence.seal("completed procedure proof", "application/json", {
      missionId: mission.id,
      runId,
      capturedAt: now,
      provenance: { sourceType: "test-plan-procedure" }
    });
    const versionOne = service.createVersion(
      {
        missionId: mission.id,
        title: "Authorized lab validation plan",
        objective: "Record bounded test coverage and explicit reasons for every procedure disposition.",
        procedures: [
          {
            key: "service-metadata",
            title: "Review bounded service metadata",
            objective: "Review the evidence produced by the approved service metadata capability.",
            steps: ["Open the sealed same-mission result and review its bounded output."],
            state: "completed",
            rationale: "The authorized capability completed and produced verified same-mission evidence.",
            capabilityId: "network.service-version",
            runId,
            evidenceArtifactIds: [completedEvidence.id]
          },
          {
            key: "credential-canary",
            title: "Run credential canary simulation",
            objective: "Record whether the credential-access simulation belongs in this engagement.",
            steps: ["Review the simulation requirement against the signed engagement objective."],
            state: "skipped",
            rationale: "The operator deferred this simulation to a separately approved training window.",
            capabilityId: "simulation.credential-canary"
          },
          {
            key: "evasion-rule",
            title: "Validate evasion detection coverage",
            objective: "Map the expected detection to the documented defensive validation rule.",
            steps: ["Confirm the required endpoint telemetry is available before starting validation."],
            state: "blocked",
            rationale: "Required endpoint telemetry is not yet connected, so no detection claim is made.",
            blueRuleId: "BR-EVASION-001"
          },
          {
            key: "payload-rule",
            title: "Review payload rule applicability",
            objective: "Decide whether the inert payload rule applies to the agreed engagement scope.",
            steps: ["Compare the rule prerequisites with the authorized engagement boundaries."],
            state: "not-applicable",
            rationale: "The agreed engagement excludes this scenario and the exclusion is recorded explicitly.",
            blueRuleId: "BR-PAYLOAD-001"
          }
        ],
        createdBy: "engagement lead"
      },
      now
    );

    assert.equal(versionOne.version, 1);
    assert.equal(versionOne.supersedesPlanId, null);
    assert.deepEqual(versionOne.summary, {
      completed: 1,
      skipped: 1,
      blocked: 1,
      "not-applicable": 1
    });
    assert.equal(versionOne.procedures[0]?.evidence[0]?.sha256, completedEvidence.sha256);
    assert.equal(versionOne.integrityValid, true);
    assert.match(versionOne.claimLimitation, /not evidence that a target is secure/i);

    const versionTwo = service.createVersion(
      {
        missionId: mission.id,
        expectedPreviousPlanId: versionOne.id,
        title: "Authorized lab validation plan",
        objective: "Record bounded test coverage and explicit reasons for every procedure disposition.",
        procedures: versionOne.procedures.map((procedure) => ({
          key: procedure.key,
          title: procedure.title,
          objective: procedure.objective,
          steps: [...procedure.steps],
          state: procedure.key === "credential-canary" ? ("blocked" as const) : procedure.state,
          rationale:
            procedure.key === "credential-canary"
              ? "The simulation remains blocked until the separately reviewed training window is active."
              : procedure.rationale,
          capabilityId: procedure.capabilityId,
          blueRuleId: procedure.blueRuleId,
          runId: procedure.runId,
          evidenceArtifactIds: procedure.evidence.map((item) => item.artifactId)
        })),
        createdBy: "engagement lead"
      },
      new Date(now.getTime() + 60_000)
    );
    assert.equal(versionTwo.version, 2);
    assert.equal(versionTwo.supersedesPlanId, versionOne.id);
    assert.equal(service.latest(mission.id).id, versionTwo.id);
    assert.deepEqual(service.list(mission.id).map((plan) => plan.version), [2, 1]);
    assert.equal(audit.verify().valid, true);

    assert.throws(
      () => database.prepare("UPDATE engagement_test_plans SET title = ? WHERE id = ?").run("Changed", versionOne.id),
      /TEST_PLAN_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("UPDATE test_plan_procedures SET rationale = ? WHERE id = ?")
          .run("Changed rationale", versionOne.procedures[0]!.id),
      /TEST_PLAN_PROCEDURE_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("DELETE FROM test_plan_procedure_evidence WHERE procedure_id = ?")
          .run(versionOne.procedures[0]!.id),
      /TEST_PLAN_EVIDENCE_IMMUTABLE/
    );
    database.close();
  });

  it("rejects unsupported completion, unknown mappings, stale version writes and cross-mission evidence", () => {
    const { database, missions, evidence, service, mission } = setup();
    const otherMission = missions.createMission("Separate engagement plan lab", now);
    const otherEvidence = evidence.seal("other mission proof", "text/plain", {
      missionId: otherMission.id,
      capturedAt: now,
      provenance: { sourceType: "other-plan" }
    });
    const base = {
      missionId: mission.id,
      title: "Strict engagement plan",
      objective: "Exercise plan validation without making unsupported security or completion claims.",
      createdBy: "engagement lead"
    };

    assert.throws(
      () =>
        service.createVersion({
          ...base,
          procedures: [
            {
              key: "unsupported-completion",
              title: "Unsupported completed procedure",
              objective: "Ensure a completed procedure cannot be stored without verified evidence.",
              steps: ["Attempt to record completion without a same-mission artifact."],
              state: "completed",
              rationale: "This rationale alone cannot support a completed procedure disposition.",
              capabilityId: "network.service-version",
              evidenceArtifactIds: []
            }
          ]
        }),
      /Completed procedures require verified evidence/
    );
    assert.throws(
      () =>
        service.createVersion({
          ...base,
          procedures: [
            {
              key: "unknown-capability",
              title: "Unknown capability mapping",
              objective: "Ensure procedures cannot map to an unregistered execution capability.",
              steps: ["Attempt to reference an unregistered capability identifier."],
              state: "blocked",
              rationale: "The mapping is intentionally invalid for this strict validation test.",
              capabilityId: "payload.unrestricted"
            }
          ]
        }),
      /TEST_PLAN_CAPABILITY_UNKNOWN/
    );
    assert.throws(
      () =>
        service.createVersion({
          ...base,
          procedures: [
            {
              key: "cross-mission-evidence",
              title: "Cross-mission evidence rejection",
              objective: "Ensure plan completion cannot cite evidence from a different engagement.",
              steps: ["Attempt to cite the sealed artifact from the separate mission."],
              state: "completed",
              rationale: "This invalid completion is used only to verify the mission boundary.",
              blueRuleId: "BR-CRED-001",
              evidenceArtifactIds: [otherEvidence.id]
            }
          ]
        }),
      /TEST_PLAN_EVIDENCE_MISSION_MISMATCH/
    );

    const first = service.createVersion({
      ...base,
      procedures: [
        {
          key: "blocked-collector",
          title: "Blocked collector validation",
          objective: "Record that the required collector is unavailable without inferring coverage.",
          steps: ["Record the missing collector prerequisite and stop this procedure."],
          state: "blocked",
          rationale: "No approved collector is enrolled, so the defensive procedure cannot run.",
          blueRuleId: "BR-CRED-001"
        }
      ]
    });
    assert.throws(
      () =>
        service.createVersion({
          ...base,
          expectedPreviousPlanId: null,
          procedures: [
            {
              key: "blocked-collector",
              title: "Blocked collector validation",
              objective: "Record that the required collector is unavailable without inferring coverage.",
              steps: ["Record the missing collector prerequisite and stop this procedure."],
              state: "blocked",
              rationale: "No approved collector is enrolled, so the defensive procedure cannot run.",
              blueRuleId: "BR-CRED-001"
            }
          ]
        }),
      /TEST_PLAN_VERSION_CONFLICT/
    );
    assert.equal(service.get(first.id).integrityValid, true);
    database.close();
  });
});
