import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { PDFDocument } from "pdf-lib";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { FindingService } from "./finding-service.js";
import { MissionService } from "./mission-service.js";
import { ReportExportService } from "./report-export-service.js";
import { ReportQaService } from "./report-qa-service.js";
import { ReportService } from "./report-service.js";

const now = new Date("2026-07-19T15:00:00.000Z");
const sourceApproval = {
  checklist: {
    scopeReviewed: true as const,
    claimsSupported: true as const,
    evidenceLinksVerified: true as const,
    remediationReviewed: true as const,
    sensitiveDataReviewed: true as const,
    layoutReviewed: true as const
  },
  note: "The exact generated JSON and HTML outputs were reviewed against evidence."
};
const exportApproval = {
  checklist: {
    pdfLayoutReviewed: true as const,
    docxLayoutReviewed: true as const,
    pageBreaksReviewed: true as const,
    evidenceReferencesReadable: true as const,
    sensitiveDataReviewed: true as const
  },
  note: "The exact PDF and DOCX downloads were opened and visually reviewed."
};

function setup(approveSource = true) {
  const database = openDatabase();
  const audit = new AuditService(database);
  const evidence = new EvidenceService(
    database,
    mkdtempSync(join(tmpdir(), "war-room-report-export-")),
    audit
  );
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Professional export fixture", now);
  missions.createScopeVersion({
    missionId: mission.id,
    startsAt: "2026-07-19T14:00:00.000Z",
    expiresAt: "2026-07-19T18:00:00.000Z",
    policyVersion: "policy-v1",
    authorizationStatement: "I own and authorize this isolated professional export fixture.",
    targets: [{ address: "8.8.8.8" }]
  }, now);
  const artifact = evidence.seal("bounded export evidence", "text/plain", {
    missionId: mission.id,
    capturedAt: now,
    provenance: { sourceType: "report-export-test" }
  });
  const findings = new FindingService(database, evidence, audit);
  const findingId = findings.createCandidate(
    mission.id,
    "Evidence-backed export finding",
    {
      severity: "medium",
      description:
        "The report export fixture contains enough explanatory text to exercise line wrapping while remaining fully evidence bound.",
      remediation:
        "Retain the exact evidence references and complete separate visual review for the PDF and DOCX outputs.",
      confidence: "high",
      evidenceArtifactIds: [artifact.id]
    },
    now
  );
  findings.accept(findingId, "finding reviewer", now);
  const reports = new ReportService(database, evidence, audit);
  const snapshot = reports.freeze(mission.id, "professional-export-v1", now);
  reports.generate(snapshot.id, now);
  const qa = new ReportQaService(database, evidence, audit);
  const review = qa.open(snapshot.id, "source reviewer", now);
  if (approveSource) qa.approve(review.id, sourceApproval, "source reviewer", now);
  const exports = new ReportExportService(database, evidence, audit, qa);
  return { database, audit, evidence, mission, snapshot, exports };
}

describe("evidence-bound report exports", () => {
  it("generates sealed PDF and DOCX outputs only after source QA", async () => {
    const { database, audit, evidence, snapshot, exports } = setup();
    const bundle = await exports.generate(snapshot.id, "export operator", now);
    assert.equal(bundle.status, "pending");
    assert.equal(bundle.publicationReady, false);
    assert.equal(bundle.integrityValid, true);
    const pdf = exports.output(bundle.id, "pdf");
    const docx = exports.output(bundle.id, "docx");
    assert.equal(pdf.bytes.subarray(0, 5).toString("ascii"), "%PDF-");
    assert.equal(docx.bytes.subarray(0, 2).toString("ascii"), "PK");
    assert.equal(evidence.verify(pdf.artifactId), true);
    assert.equal(evidence.verify(docx.artifactId), true);
    const parsedPdf = await PDFDocument.load(pdf.bytes);
    assert.ok(parsedPdf.getPageCount() >= 1);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("requires literal visual checks before PDF and DOCX are publication-ready", async () => {
    const { database, snapshot, exports } = setup();
    const bundle = await exports.generate(snapshot.id, "export operator", now);
    assert.throws(
      () => exports.approve(
        bundle.id,
        {
          checklist: { ...exportApproval.checklist, docxLayoutReviewed: false },
          note: exportApproval.note
        } as never,
        "export reviewer",
        now
      ),
      /Invalid literal value/
    );
    const approved = exports.approve(
      bundle.id,
      exportApproval,
      "export reviewer",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(approved.status, "approved");
    assert.equal(approved.publicationReady, true);
    assert.equal(approved.reviewer, "export reviewer");
    assert.throws(
      () => exports.approve(bundle.id, exportApproval, "export reviewer", now),
      /REPORT_EXPORT_QA_NOT_PENDING/
    );
    database.close();
  });

  it("records requested export changes as terminal and never publication-ready", async () => {
    const { database, audit, snapshot, exports } = setup();
    const bundle = await exports.generate(snapshot.id, "export operator", now);
    const changed = exports.requestChanges(
      bundle.id,
      {
        issues: ["pdf-layout", "redaction"],
        note: "The PDF layout and redaction review require a newly generated export bundle."
      },
      "export reviewer",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(changed.status, "changes-requested");
    assert.deepEqual(changed.issues, ["pdf-layout", "redaction"]);
    assert.equal(changed.publicationReady, false);
    assert.equal(changed.reviewer, "export reviewer");
    assert.equal(audit.verify().valid, true);
    assert.throws(
      () => exports.approve(
        bundle.id,
        exportApproval,
        "export reviewer",
        new Date(now.valueOf() + 2_000)
      ),
      /REPORT_EXPORT_QA_NOT_PENDING/
    );
    database.close();
  });

  it("fails closed without approved source QA or after derived artifact tampering", async () => {
    const sourcePending = setup(false);
    await assert.rejects(
      () => sourcePending.exports.generate(
        sourcePending.snapshot.id,
        "export operator",
        now
      ),
      /REPORT_EXPORT_SOURCE_QA_REQUIRED/
    );
    sourcePending.database.close();

    const tamper = setup();
    const bundle = await tamper.exports.generate(
      tamper.snapshot.id,
      "export operator",
      now
    );
    tamper.database.exec("DROP TRIGGER report_export_bundles_immutable_update");
    tamper.database
      .prepare("UPDATE report_export_bundles SET pdf_sha256 = ? WHERE id = ?")
      .run("f".repeat(64), bundle.id);
    assert.throws(
      () => tamper.exports.get(bundle.id),
      /REPORT_EXPORT_INTEGRITY_INVALID/
    );
    tamper.database.close();
  });

  it("blocks export generation and publication when the global audit chain is damaged", async () => {
    const generationTamper = setup();
    generationTamper.database.exec("DROP TRIGGER audit_events_immutable_update");
    generationTamper.database
      .prepare("UPDATE audit_events SET event_type = ? WHERE sequence = 1")
      .run("tampered");
    assert.equal(generationTamper.audit.verify().valid, false);
    await assert.rejects(
      () => generationTamper.exports.generate(
        generationTamper.snapshot.id,
        "export operator",
        now
      ),
      /REPORT_EXPORT_AUDIT_INVALID/
    );
    generationTamper.database.close();

    const publicationTamper = setup();
    const bundle = await publicationTamper.exports.generate(
      publicationTamper.snapshot.id,
      "export operator",
      now
    );
    publicationTamper.database.exec("DROP TRIGGER audit_events_immutable_update");
    publicationTamper.database
      .prepare("UPDATE audit_events SET payload_json = ? WHERE sequence = 1")
      .run('{"tampered":true}');
    assert.equal(publicationTamper.audit.verify().valid, false);
    assert.throws(
      () => publicationTamper.exports.approve(
        bundle.id,
        exportApproval,
        "export reviewer",
        new Date(now.valueOf() + 1_000)
      ),
      /REPORT_EXPORT_AUDIT_INVALID/
    );
    assert.throws(
      () => publicationTamper.exports.get(bundle.id),
      /REPORT_EXPORT_AUDIT_INVALID/
    );
    publicationTamper.database.close();
  });
});
