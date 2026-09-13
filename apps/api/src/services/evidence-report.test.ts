import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { FindingService } from "./finding-service.js";
import { MissionService } from "./mission-service.js";
import { ReportService } from "./report-service.js";
import { RemediationService } from "./remediation-service.js";

const now = new Date("2026-07-16T22:00:00.000Z");

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const evidenceRoot = mkdtempSync(join(tmpdir(), "war-room-evidence-"));
  const evidence = new EvidenceService(database, evidenceRoot, audit);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Evidence report test", now);
  missions.createScopeVersion(
    {
      missionId: mission.id,
      startsAt: "2026-07-16T21:00:00.000Z",
      expiresAt: "2026-07-16T23:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize the isolated evidence test target.",
      targets: [{ address: "8.8.8.8" }]
    },
    now
  );
  return { database, audit, evidenceRoot, evidence, mission };
}

describe("content-addressed evidence", () => {
  it("deduplicates bytes while retaining immutable mission observations", () => {
    const { database, evidence, evidenceRoot, mission } = setup();
    const first = evidence.seal("bounded tool output", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "test-fixture", ordinal: 1 }
    });
    const second = evidence.seal("bounded tool output", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "test-fixture", ordinal: 2 }
    });
    assert.equal(first.id, second.id);
    const observations = evidence.observations(first.id, mission.id);
    assert.equal(observations.length, 2);
    assert.notEqual(observations[0]!.id, observations[1]!.id);
    assert.throws(
      () =>
        database
          .prepare("UPDATE evidence_observations SET source_event_id = 'changed' WHERE id = ?")
          .run(observations[0]!.id),
      /EVIDENCE_OBSERVATION_IMMUTABLE/
    );
    assert.equal(evidence.verify(first.id), true);
    writeFileSync(join(evidenceRoot, first.storage_name), "tampered");
    assert.equal(evidence.verify(first.id), false);
    database.close();
  });

  it("derives storage from the sealed digest and rejects database path rebinding", () => {
    const { database, evidence, evidenceRoot, mission } = setup();
    const artifact = evidence.seal("sealed evidence", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    assert.throws(
      () => database.prepare("UPDATE artifacts SET storage_name = '../outside' WHERE id = ?").run(artifact.id),
      /ARTIFACT_STORAGE_BINDING_IMMUTABLE/
    );
    database.exec("DROP TRIGGER artifacts_storage_binding_immutable");
    database.prepare("UPDATE artifacts SET storage_name = '../outside' WHERE id = ?").run(artifact.id);
    assert.equal(evidence.verify(artifact.id), false);
    assert.throws(() => evidence.read(artifact.id), /ARTIFACT_STORAGE_BINDING_INVALID/);

    database.prepare("UPDATE artifacts SET storage_name = sha256 WHERE id = ?").run(artifact.id);
    writeFileSync(join(evidenceRoot, artifact.sha256), "replacement");
    assert.equal(evidence.verify(artifact.id), false);
    database.close();
  });
});

describe("evidence-backed findings and reports", () => {
  it("blocks unsupported findings and produces deterministic JSON/HTML artifacts", () => {
    const { database, audit, evidence, mission } = setup();
    const findings = new FindingService(database, evidence, audit);
    assert.throws(
      () =>
        findings.createCandidate(mission.id, "Unsupported issue", {
          severity: "low",
          description: "A claim without evidence must not be accepted.",
          remediation: "Collect evidence.",
          confidence: "low",
          evidenceArtifactIds: []
        }),
      /FINDING_EVIDENCE_REQUIRED/
    );
    assert.equal((database.prepare("SELECT COUNT(*) AS count FROM findings").get() as { count: number }).count, 0);
    const artifact = evidence.seal("service banner: training-only", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const findingId = findings.createCandidate(
      mission.id,
      "Training <script>alert(1)</script> banner",
      {
        severity: "info",
        description: "The captured training response contains a service identification banner.",
        remediation: "Remove unnecessary version details from the training service banner.",
        confidence: "high",
        evidenceArtifactIds: [artifact.id]
      },
      now
    );
    const reports = new ReportService(database, evidence, audit);
    assert.throws(
      () => reports.freeze(mission.id, "report-template-v1", now),
      /REPORT_ACCEPTED_FINDINGS_REQUIRED/
    );
    findings.accept(findingId, "reviewer", now);
    const snapshot = reports.freeze(mission.id, "report-template-v1", now);
    assert.throws(
      () => reports.freeze(mission.id, "report-template-v1", new Date(now.valueOf() + 1_000)),
      /REPORT_ALREADY_CURRENT/
    );
    const outputs = reports.generate(snapshot.id, now);
    assert.equal(evidence.verify(outputs.jsonArtifactId), true);
    assert.equal(evidence.verify(outputs.htmlArtifactId), true);
    assert.equal(reports.output(snapshot.id, "json").artifactId, outputs.jsonArtifactId);
    assert.equal(reports.output(snapshot.id, "html").artifactId, outputs.htmlArtifactId);
    const html = evidence.read(outputs.htmlArtifactId).toString("utf8");
    assert.match(html, /Training &lt;script&gt;alert\(1\)&lt;\/script&gt; banner/);
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("blocks report generation after evidence tampering", () => {
    const { database, audit, evidence, evidenceRoot, mission } = setup();
    const findings = new FindingService(database, evidence, audit);
    const artifact = evidence.seal("original evidence", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const findingId = findings.createCandidate(
      mission.id,
      "Evidence integrity test",
      {
        severity: "info",
        description: "This finding exists to verify tamper detection before reporting.",
        remediation: "Preserve the original evidence bytes.",
        confidence: "high",
        evidenceArtifactIds: [artifact.id]
      },
      now
    );
    findings.accept(findingId, "reviewer", now);
    const reports = new ReportService(database, evidence, audit);
    const snapshot = reports.freeze(mission.id, "report-template-v1", now);
    writeFileSync(join(evidenceRoot, artifact.storage_name), "changed after freeze");
    assert.throws(() => reports.generate(snapshot.id, now), /REPORT_EVIDENCE_INVALID/);
    database.close();
  });

  it("rejects cross-mission citations even when artifact bytes are valid", () => {
    const { database, audit, evidence, mission } = setup();
    const missions = new MissionService(database, audit);
    const otherMission = missions.createMission("Other evidence mission", now);
    const artifact = evidence.seal("mission-bound observation", "text/plain", {
      missionId: otherMission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const findings = new FindingService(database, evidence, audit);
    assert.throws(
      () =>
        findings.createCandidate(mission.id, "Cross mission citation", {
          severity: "low",
          description: "Evidence from another mission cannot support this finding.",
          remediation: "Capture evidence inside the correct mission.",
          confidence: "low",
          evidenceArtifactIds: [artifact.id]
        }),
      /FINDING_EVIDENCE_MISSION_MISMATCH/
    );
    database.close();
  });

  it("checks frozen artifact metadata and the current audit chain before generation", () => {
    const { database, audit, evidence, mission } = setup();
    const artifact = evidence.seal("metadata-bound evidence", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const findings = new FindingService(database, evidence, audit);
    const findingId = findings.createCandidate(
      mission.id,
      "Frozen metadata integrity",
      {
        severity: "info",
        description: "Frozen reports bind the exact artifact metadata as well as its bytes.",
        remediation: "Preserve content and metadata throughout report generation.",
        confidence: "high",
        evidenceArtifactIds: [artifact.id]
      },
      now
    );
    findings.accept(findingId, "reviewer", now);
    const reports = new ReportService(database, evidence, audit);
    const snapshot = reports.freeze(mission.id, "report-template-v1", now);
    database.prepare("UPDATE artifacts SET media_type = 'application/octet-stream' WHERE id = ?").run(artifact.id);
    assert.throws(() => reports.generate(snapshot.id, now), /REPORT_EVIDENCE_INVALID/);
    database.close();
  });

  it("freezes and renders the evidence-backed remediation and retest result", () => {
    const { database, audit, evidence, mission } = setup();
    const findingEvidence = evidence.seal("original observation", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const fixEvidence = evidence.seal("operator fix record", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "operator-fix" }
    });
    const retestEvidence = evidence.seal("retest observation", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-retest" }
    });
    const findings = new FindingService(database, evidence, audit);
    const findingId = findings.createCandidate(mission.id, "Closed-loop finding", {
      severity: "low",
      description: "The original authorized test produced a supported observation.",
      remediation: "Apply the documented lab fix and complete a separate retest.",
      confidence: "high",
      evidenceArtifactIds: [findingEvidence.id]
    }, now);
    findings.accept(findingId, "reviewer", now);
    const remediation = new RemediationService(database, evidence, audit);
    let record = remediation.create(findingId, {
      owner: "Local operator",
      dueDate: "2026-07-23",
      priority: "medium"
    }, "Local operator", now);
    record = remediation.changeStatus(record.id, { status: "in-progress" }, "Local operator", now);
    record = remediation.changeStatus(record.id, { status: "fix-ready" }, "Local operator", now);
    record = remediation.addFixEvidence(record.id, {
      artifactIds: [fixEvidence.id],
      note: "The lab configuration change is retained as fix evidence."
    }, "Local operator", now);
    const requestId = remediation.requestRetest(record.id, {
      reason: "Verify the exact finding after the recorded fix."
    }, "Local operator", now);
    remediation.recordRetestOutcome(record.id, {
      requestId,
      outcome: "remediated",
      summary: "The separately reviewed retest did not reproduce the original observation.",
      reviewer: "Local operator",
      evidenceArtifactIds: [retestEvidence.id]
    }, "Local operator", now);

    const reports = new ReportService(database, evidence, audit);
    const snapshot = reports.freeze(mission.id, "report-template-v1", now);
    const outputs = reports.generate(snapshot.id, now);
    const json = JSON.parse(evidence.read(outputs.jsonArtifactId).toString("utf8")) as {
      findings: Array<{ remediationWorkflow: { status: string; fixEvidence: unknown[]; retests: Array<{ outcome: string }> } }>;
    };
    assert.equal(json.findings[0]!.remediationWorkflow.status, "remediated");
    assert.equal(json.findings[0]!.remediationWorkflow.fixEvidence.length, 1);
    assert.equal(json.findings[0]!.remediationWorkflow.retests[0]!.outcome, "remediated");
    assert.match(evidence.read(outputs.htmlArtifactId).toString("utf8"), /Closed-loop remediation result/);
    database.close();
  });

  it("blocks generation when the audit chain changes after freeze", () => {
    const { database, audit, evidence, mission } = setup();
    const artifact = evidence.seal("audit-bound evidence", "text/plain", {
      missionId: mission.id,
      capturedAt: now,
      provenance: { sourceType: "authorized-test" }
    });
    const findings = new FindingService(database, evidence, audit);
    const findingId = findings.createCandidate(
      mission.id,
      "Audit chain integrity",
      {
        severity: "info",
        description: "Report generation requires the complete audit chain to remain intact.",
        remediation: "Preserve the append-only audit record.",
        confidence: "high",
        evidenceArtifactIds: [artifact.id]
      },
      now
    );
    findings.accept(findingId, "reviewer", now);
    const reports = new ReportService(database, evidence, audit);
    const snapshot = reports.freeze(mission.id, "report-template-v1", now);
    database.exec("DROP TRIGGER audit_events_immutable_update");
    database.prepare("UPDATE audit_events SET payload_json = '{}' WHERE sequence = 1").run();
    assert.throws(() => reports.generate(snapshot.id, now), /REPORT_AUDIT_INVALID/);
    database.close();
  });
});
