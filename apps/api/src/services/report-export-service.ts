import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  AlignmentType,
  Document,
  Footer,
  Header,
  HeadingLevel,
  PageNumber,
  Packer,
  Paragraph,
  TextRun
} from "docx";
import {
  PDFDocument,
  StandardFonts,
  rgb,
  type PDFFont,
  type PDFPage
} from "pdf-lib";
import { z } from "zod";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";
import type { ReportQaService } from "./report-qa-service.js";

const GENESIS_HASH = "0".repeat(64);
const uuidSchema = z.string().uuid();
const actorSchema = z.string().trim().min(2).max(120);
const noteSchema = z.string().trim().min(10).max(4_000);
const formatSchema = z.enum(["pdf", "docx"]);

export const reportExportQaChecklistSchema = z.object({
  pdfLayoutReviewed: z.literal(true),
  docxLayoutReviewed: z.literal(true),
  pageBreaksReviewed: z.literal(true),
  evidenceReferencesReadable: z.literal(true),
  sensitiveDataReviewed: z.literal(true)
}).strict();

export const approveReportExportInputSchema = z.object({
  checklist: reportExportQaChecklistSchema,
  note: noteSchema
}).strict();

export const requestReportExportChangesInputSchema = z.object({
  issues: z.array(z.enum(["pdf-layout", "docx-layout", "page-breaks", "evidence", "redaction", "other"]))
    .min(1)
    .max(6)
    .refine((items) => new Set(items).size === items.length, "Export QA issues must be unique"),
  note: noteSchema
}).strict();

const exportOpenedPayloadSchema = z.object({
  pdfArtifactId: uuidSchema,
  pdfSha256: z.string().regex(/^[a-f0-9]{64}$/),
  docxArtifactId: uuidSchema,
  docxSha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();

const exportEventPayloadSchemas = {
  opened: exportOpenedPayloadSchema,
  approved: approveReportExportInputSchema,
  "changes-requested": requestReportExportChangesInputSchema
} as const;

type ExportChecklist = z.infer<typeof reportExportQaChecklistSchema>;

interface SnapshotPayload {
  schemaVersion: number;
  templateVersion: string;
  frozenAt: string;
  mission: { id: string; name: string };
  scope: {
    startsAt?: string;
    expiresAt?: string;
    authorization?: {
      statement?: string;
      attachmentSha256?: string | null;
      recordedAt?: string;
    };
    targets?: Array<{ address?: string }>;
  };
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    confidence: string;
    description: string;
    remediation: string;
    evidence: Array<{ id: string; sha256: string; capturedAt: string; mediaType: string }>;
    remediationWorkflow?: {
      status: string;
      regressionState: string;
      owner: string;
      dueDate: string;
      fixEvidence: Array<{ artifactId: string; note: string }>;
      retests: Array<{
        outcome: string | null;
        summary: string | null;
        evidence: Array<{ artifactId: string }>;
      }>;
      claimLimitation: string;
    } | null;
  }>;
}

interface BundleRow {
  id: string;
  snapshot_id: string;
  mission_id: string;
  source_qa_review_id: string;
  source_snapshot_hash: string;
  json_artifact_id: string;
  json_sha256: string;
  html_artifact_id: string;
  html_sha256: string;
  pdf_artifact_id: string;
  pdf_sha256: string;
  docx_artifact_id: string;
  docx_sha256: string;
  generator_version: string;
  generated_by: string;
  generated_at: string;
}

interface EventRow {
  id: string;
  bundle_id: string;
  sequence: number;
  event_type: "opened" | "approved" | "changes-requested";
  payload_json: string;
  payload_hash: string;
  actor: string;
  occurred_at: string;
  previous_event_hash: string;
  event_hash: string;
}

export interface ReportExportBundle {
  readonly id: string;
  readonly snapshotId: string;
  readonly missionId: string;
  readonly sourceQaReviewId: string;
  readonly sourceSnapshotHash: string;
  readonly status: "pending" | "approved" | "changes-requested";
  readonly outputs: {
    readonly pdf: { artifactId: string; sha256: string };
    readonly docx: { artifactId: string; sha256: string };
  };
  readonly generatedBy: string;
  readonly generatedAt: string;
  readonly reviewer: string | null;
  readonly reviewedAt: string | null;
  readonly note: string | null;
  readonly issues: readonly string[];
  readonly checklist: ExportChecklist | null;
  readonly publicationReady: boolean;
  readonly integrityValid: true;
  readonly limitation: string;
}

function eventHash(
  previousHash: string,
  bundleId: string,
  sequence: number,
  occurredAt: string,
  type: EventRow["event_type"],
  actor: string,
  payloadJson: string
): string {
  return sha256(`${previousHash}\n${bundleId}\n${sequence}\n${occurredAt}\n${type}\n${actor}\n${payloadJson}`);
}

function pdfSafe(value: string): string {
  return value
    .replaceAll("\u2018", "'")
    .replaceAll("\u2019", "'")
    .replaceAll("\u201c", '"')
    .replaceAll("\u201d", '"')
    .replaceAll("\u2013", "-")
    .replaceAll("\u2014", "-")
    .replaceAll("\u2022", "-")
    .normalize("NFKD")
    .replace(/[^\x20-\x7E]/g, "?");
}

function wrapText(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const lines: string[] = [];
  for (const paragraph of pdfSafe(text).split(/\r?\n/)) {
    const words = paragraph.trim().split(/\s+/).filter(Boolean);
    if (!words.length) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
        line = candidate;
      } else {
        if (line) lines.push(line);
        if (font.widthOfTextAtSize(word, size) <= maxWidth) {
          line = word;
        } else {
          let chunk = "";
          for (const character of word) {
            const next = `${chunk}${character}`;
            if (font.widthOfTextAtSize(next, size) > maxWidth && chunk) {
              lines.push(chunk);
              chunk = character;
            } else {
              chunk = next;
            }
          }
          line = chunk;
        }
      }
    }
    if (line) lines.push(line);
  }
  return lines;
}

async function renderPdf(
  snapshot: SnapshotPayload,
  snapshotId: string,
  snapshotHash: string
): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  document.setTitle(`${snapshot.mission.name} - Security Assessment Report`);
  document.setAuthor("VioletVector AI");
  document.setSubject("Evidence-backed authorized security assessment");
  document.setCreator("VioletVector AI report-export-v1");
  const fixedDate = new Date(snapshot.frozenAt);
  document.setCreationDate(fixedDate);
  document.setModificationDate(fixedDate);
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 72;
  const contentWidth = pageWidth - margin * 2;
  let page: PDFPage;
  let y: number;
  let pageNumber = 0;

  const newPage = () => {
    page = document.addPage([pageWidth, pageHeight]);
    pageNumber += 1;
    page.drawText("VIOLETVECTOR AI | EVIDENCE-BACKED ASSESSMENT", {
      x: margin,
      y: pageHeight - 42,
      size: 8,
      font: bold,
      color: rgb(0.34, 0.43, 0.4)
    });
    page.drawLine({
      start: { x: margin, y: pageHeight - 49 },
      end: { x: pageWidth - margin, y: pageHeight - 49 },
      thickness: 0.5,
      color: rgb(0.78, 0.82, 0.8)
    });
    page.drawText(`Page ${pageNumber}`, {
      x: pageWidth - margin - 38,
      y: 34,
      size: 8,
      font: regular,
      color: rgb(0.34, 0.43, 0.4)
    });
    y = pageHeight - 78;
  };
  const ensure = (height: number) => {
    if (y - height < 58) newPage();
  };
  const add = (
    text: string,
    options: { size?: number; font?: PDFFont; color?: ReturnType<typeof rgb>; after?: number; indent?: number } = {}
  ) => {
    const size = options.size ?? 10.5;
    const font = options.font ?? regular;
    const after = options.after ?? 7;
    const indent = options.indent ?? 0;
    const lines = wrapText(text, font, size, contentWidth - indent);
    const lineHeight = size * 1.28;
    ensure(lines.length * lineHeight + after);
    for (const line of lines) {
      page.drawText(line, {
        x: margin + indent,
        y,
        size,
        font,
        color: options.color ?? rgb(0.09, 0.13, 0.12)
      });
      y -= lineHeight;
    }
    y -= after;
  };

  newPage();
  add("SECURITY ASSESSMENT REPORT", {
    size: 8.5,
    font: bold,
    color: rgb(0.18, 0.45, 0.35),
    after: 8
  });
  add(snapshot.mission.name, { size: 23, font: bold, after: 5 });
  add("Authorized, evidence-backed findings and remediation", {
    size: 12,
    color: rgb(0.34, 0.43, 0.4),
    after: 18
  });
  add(`Frozen: ${snapshot.frozenAt}`, { font: bold, after: 3 });
  add(`Snapshot: ${snapshotId}`, { size: 9, after: 2 });
  add(`Snapshot SHA-256: ${snapshotHash}`, { size: 8.5, after: 16 });
  add("Executive summary", { size: 16, font: bold, color: rgb(0.18, 0.45, 0.35), after: 7 });
  add(
    `${snapshot.findings.length} human-accepted finding(s) are included. Every claim is bound to the frozen snapshot and cited content-addressed evidence.`
  );
  add("Scope and authorization", { size: 16, font: bold, color: rgb(0.18, 0.45, 0.35), after: 7 });
  add(`Authorization: ${snapshot.scope.authorization?.statement ?? "Stored in the frozen scope record."}`);
  add(`Window: ${snapshot.scope.startsAt ?? "not stated"} to ${snapshot.scope.expiresAt ?? "not stated"}`);
  const targets = snapshot.scope.targets ?? [];
  add(`Frozen target count: ${targets.length}. Exact target details require the sensitive-data review before release.`);

  for (const [index, finding] of snapshot.findings.entries()) {
    ensure(220);
    add(`Finding ${index + 1}: ${finding.title}`, {
      size: 16,
      font: bold,
      color: rgb(0.18, 0.45, 0.35),
      after: 6
    });
    add(`Severity: ${finding.severity.toUpperCase()} | Confidence: ${finding.confidence.toUpperCase()}`, {
      font: bold,
      after: 8
    });
    add(finding.description, { after: 10 });
    ensure(78);
    add("Remediation", { size: 12, font: bold, after: 5 });
    add(finding.remediation, { after: 10 });
    if (finding.remediationWorkflow) {
      ensure(108);
      add("Closed-loop remediation result", { size: 12, font: bold, after: 5 });
      add(
        `Status: ${finding.remediationWorkflow.status} | Regression: ${finding.remediationWorkflow.regressionState} | Owner: ${finding.remediationWorkflow.owner} | Due: ${finding.remediationWorkflow.dueDate}`,
        { after: 5 }
      );
      add(
        `Fix evidence: ${finding.remediationWorkflow.fixEvidence.map((item) => item.artifactId).join(", ") || "None recorded"}`,
        { size: 8.5, after: 5 }
      );
      for (const retest of finding.remediationWorkflow.retests.filter((item) => item.outcome)) {
        add(`Retest outcome: ${retest.outcome}. ${retest.summary ?? ""}`, { after: 4 });
        add(`Retest evidence: ${retest.evidence.map((item) => item.artifactId).join(", ")}`, { size: 8.5, after: 4 });
      }
      add(finding.remediationWorkflow.claimLimitation, { size: 8.5, after: 10 });
    }
    ensure(74);
    add("Evidence references", { size: 12, font: bold, after: 5 });
    for (const evidence of finding.evidence) {
      add(`${evidence.sha256} | ${evidence.mediaType} | captured ${evidence.capturedAt}`, {
        size: 8.5,
        indent: 12,
        after: 4
      });
    }
  }
  add("Report limitations", { size: 16, font: bold, color: rgb(0.18, 0.45, 0.35), after: 7 });
  add(
    "This report contains only stored, reviewed evidence claims. A missing finding, blocked test, empty result or successful retest is not proof that a target is secure."
  );
  return document.save({ useObjectStreams: false });
}

function docxText(value: string): string {
  return value.replaceAll("\u2011", "-");
}

async function renderDocx(
  snapshot: SnapshotPayload,
  snapshotId: string,
  snapshotHash: string
): Promise<Buffer> {
  const children: Paragraph[] = [
    new Paragraph({
      style: "Kicker",
      children: [new TextRun("SECURITY ASSESSMENT REPORT")]
    }),
    new Paragraph({
      style: "ReportTitle",
      children: [new TextRun(docxText(snapshot.mission.name))]
    }),
    new Paragraph({
      style: "Subtitle",
      children: [new TextRun("Authorized, evidence-backed findings and remediation")]
    }),
    new Paragraph({ children: [new TextRun({ text: `Frozen: ${snapshot.frozenAt}`, bold: true })] }),
    new Paragraph({ children: [new TextRun(`Snapshot: ${snapshotId}`)] }),
    new Paragraph({ children: [new TextRun(`Snapshot SHA-256: ${snapshotHash}`)] }),
    new Paragraph({ text: "Executive summary", heading: HeadingLevel.HEADING_1 }),
    new Paragraph(
      `${snapshot.findings.length} human-accepted finding(s) are included. Every claim is bound to the frozen snapshot and cited content-addressed evidence.`
    ),
    new Paragraph({ text: "Scope and authorization", heading: HeadingLevel.HEADING_1 }),
    new Paragraph(`Authorization: ${docxText(snapshot.scope.authorization?.statement ?? "Stored in the frozen scope record.")}`),
    new Paragraph(`Window: ${snapshot.scope.startsAt ?? "not stated"} to ${snapshot.scope.expiresAt ?? "not stated"}`),
    new Paragraph(
      `Frozen target count: ${(snapshot.scope.targets ?? []).length}. Exact target details require the sensitive-data review before release.`
    )
  ];
  for (const [index, finding] of snapshot.findings.entries()) {
    children.push(
      new Paragraph({
        text: `Finding ${index + 1}: ${docxText(finding.title)}`,
        heading: HeadingLevel.HEADING_1,
        pageBreakBefore: index > 0
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `Severity: ${finding.severity.toUpperCase()} | Confidence: ${finding.confidence.toUpperCase()}`,
            bold: true
          })
        ]
      }),
      new Paragraph(docxText(finding.description)),
      new Paragraph({ text: "Remediation", heading: HeadingLevel.HEADING_2 }),
      new Paragraph(docxText(finding.remediation))
    );
    if (finding.remediationWorkflow) {
      children.push(
        new Paragraph({ text: "Closed-loop remediation result", heading: HeadingLevel.HEADING_2 }),
        new Paragraph(
          `Status: ${finding.remediationWorkflow.status} | Regression: ${finding.remediationWorkflow.regressionState} | Owner: ${docxText(finding.remediationWorkflow.owner)} | Due: ${finding.remediationWorkflow.dueDate}`
        ),
        new Paragraph(
          `Fix evidence: ${finding.remediationWorkflow.fixEvidence.map((item) => item.artifactId).join(", ") || "None recorded"}`
        )
      );
      for (const retest of finding.remediationWorkflow.retests.filter((item) => item.outcome)) {
        children.push(
          new Paragraph(`Retest outcome: ${retest.outcome}. ${docxText(retest.summary ?? "")}`),
          new Paragraph(`Retest evidence: ${retest.evidence.map((item) => item.artifactId).join(", ")}`)
        );
      }
      children.push(new Paragraph(docxText(finding.remediationWorkflow.claimLimitation)));
    }
    children.push(new Paragraph({ text: "Evidence references", heading: HeadingLevel.HEADING_2 }));
    for (const evidence of finding.evidence) {
      children.push(
        new Paragraph({
          style: "EvidenceReference",
          children: [
            new TextRun(`${evidence.sha256} | ${evidence.mediaType} | captured ${evidence.capturedAt}`)
          ]
        })
      );
    }
  }
  children.push(
    new Paragraph({ text: "Report limitations", heading: HeadingLevel.HEADING_1 }),
    new Paragraph(
      "This report contains only stored, reviewed evidence claims. A missing finding, blocked test, empty result or successful retest is not proof that a target is secure."
    )
  );
  const document = new Document({
    creator: "VioletVector AI",
    title: `${snapshot.mission.name} - Security Assessment Report`,
    description: "Evidence-backed authorized security assessment",
    styles: {
      default: {
        document: {
          run: { font: "Calibri", size: 22, color: "17211E" },
          paragraph: { spacing: { after: 120, line: 264, lineRule: "auto" } }
        },
        heading1: {
          run: { font: "Calibri", size: 32, bold: true, color: "2E7459" },
          paragraph: { spacing: { before: 320, after: 160 }, keepNext: true }
        },
        heading2: {
          run: { font: "Calibri", size: 26, bold: true, color: "2E7459" },
          paragraph: { spacing: { before: 240, after: 120 }, keepNext: true }
        }
      },
      paragraphStyles: [
        {
          id: "ReportTitle",
          name: "Report Title",
          basedOn: "Normal",
          next: "Normal",
          run: { font: "Calibri", size: 46, bold: true, color: "17211E" },
          paragraph: { spacing: { before: 0, after: 100 }, keepNext: true }
        },
        {
          id: "Subtitle",
          name: "Subtitle",
          basedOn: "Normal",
          next: "Normal",
          run: { font: "Calibri", size: 24, color: "576D66" },
          paragraph: { spacing: { before: 0, after: 360 }, keepNext: true }
        },
        {
          id: "Kicker",
          name: "Kicker",
          basedOn: "Normal",
          next: "ReportTitle",
          run: { font: "Calibri", size: 17, bold: true, color: "2E7459" },
          paragraph: { spacing: { before: 0, after: 120 }, keepNext: true }
        },
        {
          id: "EvidenceReference",
          name: "Evidence Reference",
          basedOn: "Normal",
          next: "Normal",
          run: { font: "Consolas", size: 17, color: "334B43" },
          paragraph: {
            indent: { left: 360, hanging: 0 },
            spacing: { before: 0, after: 80, line: 240, lineRule: "auto" }
          }
        }
      ]
    },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440, header: 708, footer: 708 }
        }
      },
      headers: {
        default: new Header({
          children: [
            new Paragraph({
              children: [new TextRun({ text: "VIOLETVECTOR AI | EVIDENCE-BACKED ASSESSMENT", size: 16, bold: true, color: "576D66" })]
            })
          ]
        })
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              children: [
                new TextRun({ text: "Page ", size: 16, color: "576D66" }),
                new TextRun({ children: [PageNumber.CURRENT], size: 16, color: "576D66" })
              ]
            })
          ]
        })
      },
      children
    }]
  });
  return Packer.toBuffer(document);
}

export class ReportExportService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService,
    private readonly reportQa: ReportQaService
  ) {}

  async generate(snapshotIdInput: string, actorInput: string, now = new Date()): Promise<ReportExportBundle> {
    const snapshotId = uuidSchema.parse(snapshotIdInput);
    const actor = actorSchema.parse(actorInput);
    if (!this.audit.verify().valid) throw new Error("REPORT_EXPORT_AUDIT_INVALID");
    if (this.database.prepare("SELECT id FROM report_export_bundles WHERE snapshot_id = ?").get(snapshotId)) {
      throw new Error("REPORT_EXPORT_ALREADY_EXISTS");
    }
    const qaRow = this.database
      .prepare("SELECT id FROM report_qa_reviews WHERE snapshot_id = ?")
      .get(snapshotId) as { id: string } | undefined;
    if (!qaRow) throw new Error("REPORT_EXPORT_SOURCE_QA_REQUIRED");
    const sourceQa = this.reportQa.get(qaRow.id);
    if (!sourceQa.publicationReady) throw new Error("REPORT_EXPORT_SOURCE_QA_REQUIRED");
    const jsonBinding = sourceQa.outputs.find((output) => output.format === "json")!;
    const htmlBinding = sourceQa.outputs.find((output) => output.format === "html")!;
    const snapshotRow = this.database
      .prepare("SELECT mission_id, snapshot_hash FROM report_snapshots WHERE id = ?")
      .get(snapshotId) as { mission_id: string; snapshot_hash: string } | undefined;
    if (!snapshotRow) throw new Error("REPORT_SNAPSHOT_NOT_FOUND");
    let jsonBytes: Buffer;
    try {
      jsonBytes = this.evidence.readVerified(jsonBinding.artifactId).bytes;
      this.evidence.readVerified(htmlBinding.artifactId);
    } catch {
      throw new Error("REPORT_EXPORT_SOURCE_INVALID");
    }
    let snapshot: SnapshotPayload;
    try {
      snapshot = JSON.parse(jsonBytes.toString("utf8")) as SnapshotPayload;
    } catch {
      throw new Error("REPORT_EXPORT_SOURCE_INVALID");
    }
    if (
      snapshot.mission?.id !== snapshotRow.mission_id ||
      !Array.isArray(snapshot.findings)
    ) {
      throw new Error("REPORT_EXPORT_SOURCE_INVALID");
    }
    const [pdfBytes, docxBytes] = await Promise.all([
      renderPdf(snapshot, snapshotId, snapshotRow.snapshot_hash),
      renderDocx(snapshot, snapshotId, snapshotRow.snapshot_hash)
    ]);
    const provenance = {
      sourceType: "report-derived-export",
      schemaVersion: 1,
      snapshotId,
      snapshotHash: snapshotRow.snapshot_hash,
      sourceQaReviewId: sourceQa.id,
      jsonArtifactId: jsonBinding.artifactId,
      jsonSha256: jsonBinding.sha256,
      htmlArtifactId: htmlBinding.artifactId,
      htmlSha256: htmlBinding.sha256,
      generatorVersion: "report-export-v1"
    };
    const pdf = this.evidence.seal(pdfBytes, "application/pdf", {
      missionId: snapshotRow.mission_id,
      capturedAt: now,
      provenance: { ...provenance, format: "pdf" }
    });
    const docx = this.evidence.seal(
      docxBytes,
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      {
        missionId: snapshotRow.mission_id,
        capturedAt: now,
        provenance: { ...provenance, format: "docx" }
      }
    );
    const bundleId = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.prepare(
        `INSERT INTO report_export_bundles(
           id, snapshot_id, mission_id, source_qa_review_id, source_snapshot_hash,
           json_artifact_id, json_sha256, html_artifact_id, html_sha256,
           pdf_artifact_id, pdf_sha256, docx_artifact_id, docx_sha256,
           generator_version, generated_by, generated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'report-export-v1', ?, ?)`
      ).run(
        bundleId,
        snapshotId,
        snapshotRow.mission_id,
        sourceQa.id,
        snapshotRow.snapshot_hash,
        jsonBinding.artifactId,
        jsonBinding.sha256,
        htmlBinding.artifactId,
        htmlBinding.sha256,
        pdf.id,
        pdf.sha256,
        docx.id,
        docx.sha256,
        actor,
        now.toISOString()
      );
      this.appendEvent(bundleId, "opened", {
        pdfArtifactId: pdf.id,
        pdfSha256: pdf.sha256,
        docxArtifactId: docx.id,
        docxSha256: docx.sha256
      }, actor, now);
      this.audit.append("report.export.generated", {
        bundleId,
        snapshotId,
        missionId: snapshotRow.mission_id,
        sourceQaReviewId: sourceQa.id,
        pdfArtifactId: pdf.id,
        pdfSha256: pdf.sha256,
        docxArtifactId: docx.id,
        docxSha256: docx.sha256,
        actor
      }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(bundleId);
  }

  approve(
    bundleIdInput: string,
    input: z.input<typeof approveReportExportInputSchema>,
    actorInput: string,
    now = new Date()
  ): ReportExportBundle {
    const bundleId = uuidSchema.parse(bundleIdInput);
    const body = approveReportExportInputSchema.parse(input);
    const actor = actorSchema.parse(actorInput);
    const current = this.get(bundleId);
    if (current.status !== "pending") throw new Error("REPORT_EXPORT_QA_NOT_PENDING");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.appendEvent(bundleId, "approved", body, actor, now);
      this.audit.append("report.export.qa-approved", {
        bundleId,
        snapshotId: current.snapshotId,
        missionId: current.missionId,
        actor
      }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(bundleId);
  }

  requestChanges(
    bundleIdInput: string,
    input: z.input<typeof requestReportExportChangesInputSchema>,
    actorInput: string,
    now = new Date()
  ): ReportExportBundle {
    const bundleId = uuidSchema.parse(bundleIdInput);
    const body = requestReportExportChangesInputSchema.parse(input);
    const actor = actorSchema.parse(actorInput);
    const current = this.get(bundleId);
    if (current.status !== "pending") throw new Error("REPORT_EXPORT_QA_NOT_PENDING");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.appendEvent(bundleId, "changes-requested", body, actor, now);
      this.audit.append("report.export.qa-changes-requested", {
        bundleId,
        snapshotId: current.snapshotId,
        missionId: current.missionId,
        issueCount: body.issues.length,
        actor
      }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(bundleId);
  }

  get(bundleIdInput: string): ReportExportBundle {
    const bundleId = uuidSchema.parse(bundleIdInput);
    if (!this.audit.verify().valid) throw new Error("REPORT_EXPORT_AUDIT_INVALID");
    const row = this.database
      .prepare("SELECT * FROM report_export_bundles WHERE id = ?")
      .get(bundleId) as unknown as BundleRow | undefined;
    if (!row) throw new Error("REPORT_EXPORT_NOT_FOUND");
    const sourceQa = this.reportQa.get(row.source_qa_review_id);
    if (
      !sourceQa.publicationReady ||
      sourceQa.snapshotId !== row.snapshot_id ||
      sourceQa.missionId !== row.mission_id ||
      sourceQa.snapshotHash !== row.source_snapshot_hash
    ) {
      throw new Error("REPORT_EXPORT_BINDING_INVALID");
    }
    for (const binding of [
      [row.json_artifact_id, row.json_sha256],
      [row.html_artifact_id, row.html_sha256],
      [row.pdf_artifact_id, row.pdf_sha256],
      [row.docx_artifact_id, row.docx_sha256]
    ] as const) {
      if (!this.evidence.verify(binding[0]) || this.evidence.get(binding[0]).sha256 !== binding[1]) {
        throw new Error("REPORT_EXPORT_INTEGRITY_INVALID");
      }
    }
    const events = this.events(row);
    const opened = exportOpenedPayloadSchema.parse(JSON.parse(events[0]!.payload_json));
    if (
      opened.pdfArtifactId !== row.pdf_artifact_id ||
      opened.pdfSha256 !== row.pdf_sha256 ||
      opened.docxArtifactId !== row.docx_artifact_id ||
      opened.docxSha256 !== row.docx_sha256
    ) {
      throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
    }
    const terminal = events[1];
    let status: ReportExportBundle["status"] = "pending";
    let reviewer: string | null = null;
    let reviewedAt: string | null = null;
    let note: string | null = null;
    let checklist: ExportChecklist | null = null;
    let issues: string[] = [];
    if (terminal?.event_type === "approved") {
      const payload = approveReportExportInputSchema.parse(JSON.parse(terminal.payload_json));
      status = "approved";
      reviewer = terminal.actor;
      reviewedAt = terminal.occurred_at;
      note = payload.note;
      checklist = payload.checklist;
    } else if (terminal?.event_type === "changes-requested") {
      const payload = requestReportExportChangesInputSchema.parse(JSON.parse(terminal.payload_json));
      status = "changes-requested";
      reviewer = terminal.actor;
      reviewedAt = terminal.occurred_at;
      note = payload.note;
      issues = payload.issues;
    } else if (terminal) {
      throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
    }
    return {
      id: row.id,
      snapshotId: row.snapshot_id,
      missionId: row.mission_id,
      sourceQaReviewId: row.source_qa_review_id,
      sourceSnapshotHash: row.source_snapshot_hash,
      status,
      outputs: {
        pdf: { artifactId: row.pdf_artifact_id, sha256: row.pdf_sha256 },
        docx: { artifactId: row.docx_artifact_id, sha256: row.docx_sha256 }
      },
      generatedBy: row.generated_by,
      generatedAt: row.generated_at,
      reviewer,
      reviewedAt,
      note,
      issues,
      checklist,
      publicationReady: status === "approved",
      integrityValid: true,
      limitation:
        "PDF and DOCX publication readiness requires a human visual review of these exact derived artifacts. Source QA, evidence integrity and export QA are separate gates."
    };
  }

  forSnapshot(snapshotIdInput: string): ReportExportBundle | null {
    const snapshotId = uuidSchema.parse(snapshotIdInput);
    const row = this.database
      .prepare("SELECT id FROM report_export_bundles WHERE snapshot_id = ?")
      .get(snapshotId) as { id: string } | undefined;
    return row ? this.get(row.id) : null;
  }

  output(bundleIdInput: string, formatInput: string): {
    artifactId: string;
    mediaType: string;
    bytes: Buffer;
  } {
    const bundle = this.get(bundleIdInput);
    const format = formatSchema.parse(formatInput);
    const binding = bundle.outputs[format];
    let verified: ReturnType<EvidenceService["readVerified"]>;
    try {
      verified = this.evidence.readVerified(binding.artifactId);
    } catch {
      throw new Error("REPORT_EXPORT_INTEGRITY_INVALID");
    }
    const artifact = verified.artifact;
    const expected = format === "pdf"
      ? "application/pdf"
      : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    if (artifact.media_type !== expected) throw new Error("REPORT_EXPORT_MEDIA_TYPE_INVALID");
    return {
      artifactId: artifact.id,
      mediaType: artifact.media_type,
      bytes: verified.bytes
    };
  }

  private appendEvent(
    bundleId: string,
    type: EventRow["event_type"],
    payload: unknown,
    actor: string,
    now: Date
  ): void {
    const parsedPayload = exportEventPayloadSchemas[type].parse(payload);
    const payloadJson = stableJson(parsedPayload);
    const latest = this.database
      .prepare(
        `SELECT sequence, event_hash FROM report_export_qa_events
         WHERE bundle_id = ? ORDER BY sequence DESC LIMIT 1`
      )
      .get(bundleId) as { sequence: number; event_hash: string } | undefined;
    const sequence = (latest?.sequence ?? 0) + 1;
    const previousHash = latest?.event_hash ?? GENESIS_HASH;
    const occurredAt = now.toISOString();
    const hash = eventHash(previousHash, bundleId, sequence, occurredAt, type, actor, payloadJson);
    this.database.prepare(
      `INSERT INTO report_export_qa_events(
         id, bundle_id, sequence, event_type, payload_json, payload_hash,
         actor, occurred_at, previous_event_hash, event_hash
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      randomUUID(),
      bundleId,
      sequence,
      type,
      payloadJson,
      canonicalHash(parsedPayload),
      actor,
      occurredAt,
      previousHash,
      hash
    );
  }

  private events(row: BundleRow): EventRow[] {
    const events = this.database
      .prepare("SELECT * FROM report_export_qa_events WHERE bundle_id = ? ORDER BY sequence")
      .all(row.id) as unknown as EventRow[];
    if (events.length < 1 || events.length > 2 || events[0]?.event_type !== "opened") {
      throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
    }
    let previousHash = GENESIS_HASH;
    for (const [index, event] of events.entries()) {
      let payload: unknown;
      try {
        payload = JSON.parse(event.payload_json);
      } catch {
        throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
      }
      try {
        payload = exportEventPayloadSchemas[event.event_type].parse(payload);
      } catch {
        throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
      }
      const expected = eventHash(
        previousHash,
        row.id,
        event.sequence,
        event.occurred_at,
        event.event_type,
        event.actor,
        event.payload_json
      );
      if (
        event.sequence !== index + 1 ||
        event.previous_event_hash !== previousHash ||
        canonicalHash(payload) !== event.payload_hash ||
        stableJson(payload) !== event.payload_json ||
        expected !== event.event_hash
      ) {
        throw new Error("REPORT_EXPORT_QA_HISTORY_INVALID");
      }
      previousHash = event.event_hash;
    }
    return events;
  }
}
