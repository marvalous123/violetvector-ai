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
import { ReportQaService, type ApproveReportQaInput } from "./report-qa-service.js";
import { ReportService } from "./report-service.js";

const now = new Date("2026-07-19T13:00:00.000Z");
const approval: ApproveReportQaInput = {
  checklist: {
    scopeReviewed: true,
    claimsSupported: true,
    evidenceLinksVerified: true,
    remediationReviewed: true,
    sensitiveDataReviewed: true,
    layoutReviewed: true
  },
  note: "The exact generated outputs were reviewed against the frozen evidence and scope."
};

function setup(options: { generate?: boolean } = { generate: true }) {
  const database = openDatabase();
  const audit = new AuditService(database);
  const evidenceRoot = mkdtempSync(join(tmpdir(), "war-room-report-qa-"));
  const evidence = new EvidenceService(database, evidenceRoot, audit);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Report QA test mission", now);
  missions.createScopeVersion(
    {
      missionId: mission.id,
      startsAt: "2026-07-19T12:00:00.000Z",
      expiresAt: "2026-07-19T15:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize this isolated report quality test target.",
      targets: [{ address: "8.8.8.8" }]
    },
    now
  );
  const artifact = evidence.seal("bounded report quality evidence", "text/plain", {
    missionId: mission.id,
    capturedAt: now,
    provenance: { sourceType: "report-qa-test" }
  });
  const findings = new FindingService(database, evidence, audit);
  const findingId = findings.createCandidate(
    mission.id,
    "Report quality fixture",
    {
      severity: "info",
      description: "This reviewed fixture proves the report quality workflow is evidence bound.",
      remediation: "Retain the evidence and complete the explicit report quality checklist.",
      confidence: "high",
      evidenceArtifactIds: [artifact.id]
    },
    now
  );
  findings.accept(findingId, "finding reviewer", now);
  const reports = new ReportService(database, evidence, audit);
  const snapshot = reports.freeze(mission.id, "report-qa-v1", now);
  const outputs = options.generate === false ? null : reports.generate(snapshot.id, now);
  const qa = new ReportQaService(database, evidence, audit);
  return {
    database,
    audit,
    evidence,
    evidenceRoot,
    mission,
    snapshot,
    outputs,
    reports,
    qa
  };
}

describe("report QA workflow", () => {
  it("binds an explicit approval to exact verified generated outputs", () => {
    const { database, audit, mission, snapshot, qa } = setup();
    const opened = qa.open(snapshot.id, "quality reviewer", now);
    assert.equal(opened.status, "pending");
    assert.equal(opened.outputs.length, 2);
    assert.equal(opened.outputs.map((output) => output.format).join(","), "html,json");
    assert.equal(opened.publicationReady, false);
    const approved = qa.approve(
      opened.id,
      approval,
      "quality reviewer",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(approved.status, "approved");
    assert.equal(approved.publicationReady, true);
    assert.equal(approved.reviewer, "quality reviewer");
    assert.equal(approved.checklist?.layoutReviewed, true);
    assert.equal(approved.history.length, 2);
    assert.equal(qa.list(mission.id)[0]?.id, opened.id);
    assert.equal(audit.verify().valid, true);
    assert.throws(
      () =>
        database
          .prepare("UPDATE report_qa_reviews SET opened_by = 'changed reviewer' WHERE id = ?")
          .run(opened.id),
      /REPORT_QA_REVIEW_IMMUTABLE/
    );
    assert.throws(
      () =>
        qa.approve(
          opened.id,
          approval,
          "quality reviewer",
          new Date(now.valueOf() + 2_000)
        ),
      /REPORT_QA_NOT_PENDING/
    );
    database.close();
  });

  it("requires generated outputs and a complete literal-true checklist", () => {
    const frozen = setup({ generate: false });
    assert.throws(
      () => frozen.qa.open(frozen.snapshot.id, "quality reviewer", now),
      /REPORT_QA_GENERATED_REPORT_REQUIRED/
    );
    frozen.database.close();

    const generated = setup();
    const opened = generated.qa.open(generated.snapshot.id, "quality reviewer", now);
    assert.throws(
      () =>
        generated.qa.approve(
          opened.id,
          {
            checklist: {
              ...approval.checklist,
              layoutReviewed: false
            },
            note: approval.note
          } as unknown as ApproveReportQaInput,
          "quality reviewer",
          now
        ),
      /Invalid literal value/
    );
    assert.throws(
      () =>
        generated.qa.approve(
          opened.id,
          { ...approval, unexpected: "field" } as unknown as ApproveReportQaInput,
          "quality reviewer",
          now
        ),
      /unrecognized_keys/
    );
    generated.database.close();
  });

  it("records requested changes as terminal for the immutable snapshot", () => {
    const { database, snapshot, qa } = setup();
    const opened = qa.open(snapshot.id, "quality reviewer", now);
    const changed = qa.requestChanges(
      opened.id,
      {
        issues: ["claims", "layout"],
        note: "The claim wording and generated layout require a new reviewed snapshot."
      },
      "quality reviewer",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(changed.status, "changes-requested");
    assert.deepEqual(changed.issues, ["claims", "layout"]);
    assert.equal(changed.publicationReady, false);
    assert.throws(
      () =>
        qa.approve(
          opened.id,
          approval,
          "quality reviewer",
          new Date(now.valueOf() + 2_000)
        ),
      /REPORT_QA_NOT_PENDING/
    );
    database.close();
  });

  it("fails closed after output or QA history tampering", () => {
    const outputTamper = setup();
    const outputReview = outputTamper.qa.open(
      outputTamper.snapshot.id,
      "quality reviewer",
      now
    );
    const htmlOutput = outputReview.outputs.find((output) => output.format === "html")!;
    const htmlArtifact = outputTamper.evidence.get(htmlOutput.artifactId);
    writeFileSync(join(outputTamper.evidenceRoot, htmlArtifact.storage_name), "tampered output");
    assert.throws(
      () => outputTamper.qa.get(outputReview.id),
      /REPORT_QA_OUTPUT_INVALID/
    );
    outputTamper.database.close();

    const historyTamper = setup();
    const historyReview = historyTamper.qa.open(
      historyTamper.snapshot.id,
      "quality reviewer",
      now
    );
    historyTamper.database.exec("DROP TRIGGER report_qa_events_immutable_update");
    historyTamper.database
      .prepare(
        "UPDATE report_qa_events SET payload_json = '{}' WHERE review_id = ? AND sequence = 1"
      )
      .run(historyReview.id);
    assert.throws(
      () => historyTamper.qa.get(historyReview.id),
      /REPORT_QA_HISTORY_INVALID/
    );
    historyTamper.database.close();
  });
});
