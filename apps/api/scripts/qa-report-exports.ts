import { mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { openDatabase } from "../src/db/database.js";
import { AuditService } from "../src/services/audit-service.js";
import { EvidenceService } from "../src/services/evidence-service.js";
import { FindingService } from "../src/services/finding-service.js";
import { MissionService } from "../src/services/mission-service.js";
import { ReportExportService } from "../src/services/report-export-service.js";
import { ReportQaService } from "../src/services/report-qa-service.js";
import { ReportService } from "../src/services/report-service.js";

const outputArgument = process.argv[2];
if (!outputArgument || !isAbsolute(outputArgument)) {
  throw new Error("Pass an absolute QA output directory.");
}
const outputRoot = resolve(outputArgument);
mkdirSync(outputRoot, { recursive: true });
const now = new Date("2026-07-19T15:00:00.000Z");
const database = openDatabase();
const audit = new AuditService(database);
const evidence = new EvidenceService(database, resolve(outputRoot, "evidence"), audit);
const missions = new MissionService(database, audit);
const mission = missions.createMission("WAR-R00M Professional Assessment", now);
missions.createScopeVersion({
  missionId: mission.id,
  startsAt: "2026-07-19T14:00:00.000Z",
  expiresAt: "2026-07-19T18:00:00.000Z",
  policyVersion: "policy-v1",
  authorizationStatement:
    "The owner authorized this isolated fixture solely for report-render quality assurance.",
  targets: [{ address: "8.8.8.8" }]
}, now);
const artifact = evidence.seal(
  "Bounded quality-assurance evidence with no secret or private target data.",
  "text/plain",
  {
    missionId: mission.id,
    capturedAt: now,
    provenance: { sourceType: "report-export-visual-qa" }
  }
);
const findings = new FindingService(database, evidence, audit);
const fixtures = [
  {
    title: "Administrative service exposes unnecessary version metadata",
    severity: "medium" as const,
    description:
      "The reviewed service response contains product and version details. This long paragraph intentionally exercises wrapping across the available report width while retaining a concise, evidence-supported claim.",
    remediation:
      "Remove unnecessary version disclosure, retain operational logging, and repeat the same bounded metadata check after the change."
  },
  {
    title: "Legacy cipher configuration remains enabled",
    severity: "high" as const,
    description:
      "The sealed assessment evidence records a legacy cipher configuration on the authorized fixture. The finding does not claim exploitation or compromise.",
    remediation:
      "Disable the reviewed legacy configuration, preserve a rollback plan, and perform a controlled configuration-equivalent retest."
  },
  {
    title: "Security response headers require review",
    severity: "low" as const,
    description:
      "The authorized metadata review found that the fixture response does not include the complete expected defensive header baseline.",
    remediation:
      "Review application compatibility, add the approved header baseline, and verify the exact response in a bounded retest."
  }
];
for (const fixture of fixtures) {
  const findingId = findings.createCandidate(
    mission.id,
    fixture.title,
    {
      severity: fixture.severity,
      description: fixture.description,
      remediation: fixture.remediation,
      confidence: "high",
      evidenceArtifactIds: [artifact.id]
    },
    now
  );
  findings.accept(findingId, "visual QA reviewer", now);
}
const reports = new ReportService(database, evidence, audit);
const snapshot = reports.freeze(mission.id, "professional-export-v1", now);
reports.generate(snapshot.id, now);
const reportQa = new ReportQaService(database, evidence, audit);
const sourceReview = reportQa.open(snapshot.id, "visual QA reviewer", now);
reportQa.approve(
  sourceReview.id,
  {
    checklist: {
      scopeReviewed: true,
      claimsSupported: true,
      evidenceLinksVerified: true,
      remediationReviewed: true,
      sensitiveDataReviewed: true,
      layoutReviewed: true
    },
    note: "The deterministic source outputs were reviewed for the visual export fixture."
  },
  "visual QA reviewer",
  now
);
const exports = new ReportExportService(database, evidence, audit, reportQa);
const bundle = await exports.generate(snapshot.id, "visual QA generator", now);
writeFileSync(resolve(outputRoot, "war-room-report.pdf"), exports.output(bundle.id, "pdf").bytes);
writeFileSync(resolve(outputRoot, "war-room-report.docx"), exports.output(bundle.id, "docx").bytes);
database.close();
process.stdout.write(`${outputRoot}\n`);
