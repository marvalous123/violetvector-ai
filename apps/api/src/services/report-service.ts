import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";
import { RemediationService, type RemediationRecord } from "./remediation-service.js";

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

interface SnapshotRow {
  id: string;
  mission_id: string;
  snapshot_json: string;
  snapshot_hash: string;
  template_version: string;
  status: "frozen" | "generated" | "blocked";
  frozen_at: string;
}

interface SnapshotFinding {
  id: string;
  revisionId: string;
  title: string;
  severity: string;
  description: string;
  remediation: string;
  confidence: string;
  evidence: Array<{
    id: string;
    observationId: string;
    sha256: string;
    mediaType: string;
    sizeBytes: number;
    capturedAt: string;
    sealedAt: string;
  }>;
  remediationWorkflow: SnapshotRemediationWorkflow | null;
}

interface SnapshotRemediationWorkflow {
  id: string;
  owner: string;
  dueDate: string;
  priority: string;
  status: string;
  regressionState: string;
  fixEvidence: Array<{
    artifactId: string;
    observationId: string;
    note: string;
    addedAt: string;
  }>;
  retests: Array<{
    requestId: string;
    reason: string;
    requestedAt: string;
    outcome: string | null;
    summary: string | null;
    outcomeRecordedAt: string | null;
    evidence: Array<{ artifactId: string; observationId: string }>;
  }>;
  historyHeadHash: string;
  claimLimitation: string;
}

interface FindingSnapshotRow {
  id: string;
  title: string;
  revision_id: string;
  severity: string;
  description: string;
  remediation: string;
  confidence: string;
}

interface ReportContent {
  templateVersion: string;
  mission: { id: string; name: string };
  scope: unknown;
  findings: Array<Omit<SnapshotFinding, "revisionId">>;
}

function reportContent(
  templateVersion: string,
  mission: { id: string; name: string },
  scope: unknown,
  findings: SnapshotFinding[]
): ReportContent {
  return {
    templateVersion,
    mission,
    scope,
    findings: findings.map(({ revisionId: _revisionId, ...finding }) => finding)
  };
}

export class ReportService {
  private readonly audit: AuditService;
  private readonly missions: MissionService;
  private readonly remediation: RemediationService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    audit?: AuditService
  ) {
    this.audit = audit ?? new AuditService(database);
    this.missions = new MissionService(database, this.audit);
    this.remediation = new RemediationService(database, evidence, this.audit);
  }

  freeze(missionId: string, templateVersion: string, now = new Date()): SnapshotRow {
    const mission = this.missions.getMission(missionId);
    const scope = this.missions.getLatestScope(missionId);
    const authorization = this.database
      .prepare(
        `SELECT statement, attachment_sha256, recorded_at
         FROM authorization_records WHERE scope_version_id = ?`
      )
      .get(scope.scopeVersionId) as {
        statement: string;
        attachment_sha256: string | null;
        recorded_at: string;
      } | undefined;
    if (!authorization) throw new Error("REPORT_AUTHORIZATION_REQUIRED");
    const reportScope = {
      ...scope,
      authorization: {
        statement: authorization.statement,
        attachmentSha256: authorization.attachment_sha256,
        recordedAt: authorization.recorded_at
      }
    };
    const findingRows = this.database
      .prepare(
        `SELECT f.id, f.title, fr.id AS revision_id, fr.severity, fr.description, fr.remediation, fr.confidence
         FROM findings f
         JOIN finding_revisions fr ON fr.id = (
           SELECT id FROM finding_revisions WHERE finding_id = f.id ORDER BY revision DESC LIMIT 1
         )
         WHERE f.mission_id = ? AND f.status = 'accepted'
         ORDER BY f.title, f.id`
      )
      .all(missionId) as unknown as FindingSnapshotRow[];
    if (findingRows.length < 1) throw new Error("REPORT_ACCEPTED_FINDINGS_REQUIRED");
    const findings: SnapshotFinding[] = findingRows.map((finding) => {
      const evidenceRows = this.database
        .prepare(
          `SELECT a.id, a.sha256, a.media_type, a.size_bytes, a.captured_at, a.sealed_at,
                  feo.observation_id
           FROM finding_evidence_observations feo
           JOIN artifacts a ON a.id = feo.artifact_id
           JOIN evidence_observations eo ON eo.id = feo.observation_id
           WHERE feo.finding_revision_id = ? AND eo.mission_id = ?
           ORDER BY a.sha256, feo.observation_id`
        )
        .all(finding.revision_id, missionId) as unknown as Array<{
        id: string;
        observation_id: string;
        sha256: string;
        media_type: string;
        size_bytes: number;
        captured_at: string;
        sealed_at: string;
      }>;
      if (
        evidenceRows.length < 1 ||
        !evidenceRows.every(
          (artifact) =>
            this.evidence.verify(artifact.id) &&
            this.evidence.verifyObservation(artifact.observation_id, artifact.id, missionId)
        )
      ) {
        throw new Error("REPORT_EVIDENCE_INVALID");
      }
      const remediationRow = this.database
        .prepare("SELECT id FROM remediation_records WHERE finding_id = ?")
        .get(finding.id) as { id: string } | undefined;
      const remediationWorkflow = remediationRow
        ? this.snapshotRemediation(this.remediation.get(remediationRow.id))
        : null;
      return {
        id: finding.id,
        revisionId: finding.revision_id,
        title: finding.title,
        severity: finding.severity,
        description: finding.description,
        remediation: finding.remediation,
        confidence: finding.confidence,
        evidence: evidenceRows.map((artifact) => ({
          id: artifact.id,
          observationId: artifact.observation_id,
          sha256: artifact.sha256,
          mediaType: artifact.media_type,
          sizeBytes: artifact.size_bytes,
          capturedAt: artifact.captured_at,
          sealedAt: artifact.sealed_at
        })),
        remediationWorkflow
      };
    });
    const missionIdentity = { id: mission.id, name: mission.name };
    const contentHash = canonicalHash(
      reportContent(templateVersion, missionIdentity, reportScope, findings)
    );
    const latestSnapshot = this.database
      .prepare(
        `SELECT snapshot_json FROM report_snapshots
         WHERE mission_id = ? AND template_version = ?
         ORDER BY frozen_at DESC LIMIT 1`
      )
      .get(missionId, templateVersion) as { snapshot_json: string } | undefined;
    if (latestSnapshot) {
      try {
        const previous = JSON.parse(latestSnapshot.snapshot_json) as {
          contentHash?: string;
          templateVersion: string;
          mission: { id: string; name: string };
          scope: unknown;
          findings: SnapshotFinding[];
        };
        const previousContentHash =
          previous.contentHash ??
          canonicalHash(reportContent(previous.templateVersion, previous.mission, previous.scope, previous.findings));
        if (previousContentHash === contentHash) throw new Error("REPORT_ALREADY_CURRENT");
      } catch (error) {
        if (error instanceof Error && error.message === "REPORT_ALREADY_CURRENT") throw error;
        throw new Error("REPORT_SNAPSHOT_INVALID", { cause: error });
      }
    }
    const auditVerification = this.audit.verify();
    if (!auditVerification.valid) throw new Error("REPORT_AUDIT_INVALID");
    const auditHead = this.database
      .prepare("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
      .get() as { sequence: number; event_hash: string } | undefined;
    const frozenAt = now.toISOString();
    const snapshot = {
      schemaVersion: 4,
      templateVersion,
      contentHash,
      frozenAt,
      mission: missionIdentity,
      scope: reportScope,
      findings,
      auditHead: auditHead ?? { sequence: 0, event_hash: "0".repeat(64) }
    };
    const snapshotJson = stableJson(snapshot);
    const snapshotHash = canonicalHash(snapshot);
    const id = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO report_snapshots(id, mission_id, snapshot_json, snapshot_hash, template_version, status, frozen_at)
           VALUES (?, ?, ?, ?, ?, 'frozen', ?)`
        )
        .run(id, missionId, snapshotJson, snapshotHash, templateVersion, frozenAt);
      this.audit.append("report.frozen", { snapshotId: id, missionId, snapshotHash }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(id);
  }

  get(id: string): SnapshotRow {
    const row = this.database.prepare("SELECT * FROM report_snapshots WHERE id = ?").get(id) as unknown as SnapshotRow | undefined;
    if (!row) throw new Error("REPORT_SNAPSHOT_NOT_FOUND");
    return row;
  }

  generate(snapshotId: string, now = new Date()): { jsonArtifactId: string; htmlArtifactId: string } {
    const row = this.get(snapshotId);
    if (row.status !== "frozen") throw new Error("REPORT_SNAPSHOT_NOT_FROZEN");
    const snapshot = JSON.parse(row.snapshot_json) as {
      mission: { id: string; name: string };
      findings: SnapshotFinding[];
      frozenAt: string;
      auditHead: { sequence: number; event_hash: string };
    };
    if (canonicalHash(snapshot) !== row.snapshot_hash) throw new Error("REPORT_SNAPSHOT_TAMPERED");
    if (snapshot.mission.id !== row.mission_id) throw new Error("REPORT_SNAPSHOT_TAMPERED");
    const auditVerification = this.audit.verify();
    if (!auditVerification.valid) throw new Error("REPORT_AUDIT_INVALID");
    const freezeEvents = this.database
      .prepare("SELECT payload_json FROM audit_events WHERE event_type = 'report.frozen' ORDER BY sequence")
      .all() as unknown as Array<{ payload_json: string }>;
    const matchingFreezeEvent = freezeEvents.some(({ payload_json }) => {
      try {
        const payload = JSON.parse(payload_json) as {
          snapshotId?: string;
          missionId?: string;
          snapshotHash?: string;
        };
        return (
          payload.snapshotId === snapshotId &&
          payload.missionId === row.mission_id &&
          payload.snapshotHash === row.snapshot_hash
        );
      } catch {
        return false;
      }
    });
    if (!matchingFreezeEvent) throw new Error("REPORT_FREEZE_RECORD_INVALID");
    if (snapshot.auditHead.sequence > 0) {
      const frozenAuditHead = this.database
        .prepare("SELECT event_hash FROM audit_events WHERE sequence = ?")
        .get(snapshot.auditHead.sequence) as { event_hash: string } | undefined;
      if (!frozenAuditHead || frozenAuditHead.event_hash !== snapshot.auditHead.event_hash) {
        throw new Error("REPORT_AUDIT_PREFIX_INVALID");
      }
    } else if (snapshot.auditHead.event_hash !== "0".repeat(64)) {
      throw new Error("REPORT_AUDIT_PREFIX_INVALID");
    }
    for (const finding of snapshot.findings) {
      if (
        !finding.evidence.every((frozen) => {
          if (!this.evidence.verify(frozen.id)) return false;
          const current = this.evidence.get(frozen.id);
          return (
            current.sha256 === frozen.sha256 &&
            current.size_bytes === frozen.sizeBytes &&
            current.media_type === frozen.mediaType &&
            current.captured_at === frozen.capturedAt &&
            current.sealed_at === frozen.sealedAt &&
            this.evidence.verifyObservation(frozen.observationId, frozen.id, row.mission_id)
          );
        })
      ) {
        throw new Error("REPORT_EVIDENCE_INVALID");
      }
      for (const reference of [
        ...(finding.remediationWorkflow?.fixEvidence ?? []),
        ...(finding.remediationWorkflow?.retests.flatMap((retest) => retest.evidence) ?? [])
      ]) {
        if (
          !this.evidence.verify(reference.artifactId) ||
          !this.evidence.verifyObservation(reference.observationId, reference.artifactId, row.mission_id)
        ) {
          throw new Error("REPORT_REMEDIATION_EVIDENCE_INVALID");
        }
      }
    }
    const outputProvenance = { sourceType: "report-output", snapshotId, snapshotHash: row.snapshot_hash };
    const jsonArtifact = this.evidence.seal(`${row.snapshot_json}\n`, "application/json", {
      missionId: row.mission_id,
      capturedAt: now,
      provenance: outputProvenance
    });
    const findingHtml = snapshot.findings
      .map(
        (finding) =>
          `<article><h2>${escapeHtml(finding.title)}</h2><p><strong>Severity:</strong> ${escapeHtml(finding.severity)}</p>` +
          `<p>${escapeHtml(finding.description)}</p><h3>Remediation</h3><p>${escapeHtml(finding.remediation)}</p>` +
          this.remediationHtml(finding.remediationWorkflow) +
          `<p><strong>Evidence:</strong> ${finding.evidence.map((artifact) => escapeHtml(artifact.sha256)).join(", ")}</p></article>`
      )
      .join("");
    const html =
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(snapshot.mission.name)}</title>` +
      `<style>body{font:16px system-ui;max-width:900px;margin:40px auto;color:#17211e}article{border-top:1px solid #bbb;padding:20px 0}</style>` +
      `</head><body><h1>${escapeHtml(snapshot.mission.name)}</h1><p>Frozen: ${escapeHtml(snapshot.frozenAt)}</p>${findingHtml}</body></html>`;
    const htmlArtifact = this.evidence.seal(html, "text/html", {
      missionId: row.mission_id,
      capturedAt: now,
      provenance: outputProvenance
    });
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const insert = this.database.prepare(
        `INSERT INTO report_outputs(id, snapshot_id, format, artifact_id, generated_at) VALUES (?, ?, ?, ?, ?)`
      );
      insert.run(randomUUID(), snapshotId, "json", jsonArtifact.id, now.toISOString());
      insert.run(randomUUID(), snapshotId, "html", htmlArtifact.id, now.toISOString());
      this.database.prepare("UPDATE report_snapshots SET status = 'generated' WHERE id = ?").run(snapshotId);
      this.audit.append(
        "report.generated",
        { snapshotId, jsonArtifactId: jsonArtifact.id, htmlArtifactId: htmlArtifact.id },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return { jsonArtifactId: jsonArtifact.id, htmlArtifactId: htmlArtifact.id };
  }

  private snapshotRemediation(record: RemediationRecord): SnapshotRemediationWorkflow {
    return {
      id: record.id,
      owner: record.owner,
      dueDate: record.dueDate,
      priority: record.priority,
      status: record.status,
      regressionState: record.regressionState,
      fixEvidence: record.fixEvidence.map((evidence) => ({
        artifactId: evidence.artifactId,
        observationId: evidence.observationId,
        note: evidence.note,
        addedAt: evidence.addedAt
      })),
      retests: record.retests.map((retest) => ({
        requestId: retest.requestId,
        reason: retest.reason,
        requestedAt: retest.requestedAt,
        outcome: retest.outcome ?? null,
        summary: retest.summary ?? null,
        outcomeRecordedAt: retest.outcomeRecordedAt ?? null,
        evidence: retest.evidence.map((evidence) => ({
          artifactId: evidence.artifactId,
          observationId: evidence.observationId
        }))
      })),
      historyHeadHash: record.history.at(-1)?.eventHash ?? "0".repeat(64),
      claimLimitation: record.claimLimitation
    };
  }

  private remediationHtml(workflow: SnapshotRemediationWorkflow | null): string {
    if (!workflow) return "";
    const completedRetests = workflow.retests.filter((retest) => retest.outcome);
    const retestHtml = completedRetests.length === 0
      ? "<p><strong>Retest:</strong> No evidence-backed outcome recorded.</p>"
      : completedRetests.map((retest) =>
          `<p><strong>Retest outcome:</strong> ${escapeHtml(retest.outcome!)}. ${escapeHtml(retest.summary ?? "")}</p>` +
          `<p><strong>Retest evidence:</strong> ${retest.evidence.map((item) => escapeHtml(item.artifactId)).join(", ")}</p>`
        ).join("");
    return `<section><h3>Closed-loop remediation result</h3>` +
      `<p><strong>Status:</strong> ${escapeHtml(workflow.status)}; <strong>regression:</strong> ${escapeHtml(workflow.regressionState)}; ` +
      `<strong>owner:</strong> ${escapeHtml(workflow.owner)}; <strong>due:</strong> ${escapeHtml(workflow.dueDate)}</p>` +
      `<p><strong>Fix evidence:</strong> ${workflow.fixEvidence.map((item) => escapeHtml(item.artifactId)).join(", ") || "None recorded"}</p>` +
      retestHtml + `<p>${escapeHtml(workflow.claimLimitation)}</p></section>`;
  }

  output(
    snapshotId: string,
    format: "json" | "html"
  ): { artifactId: string; mediaType: string; bytes: Buffer } {
    const row = this.database
      .prepare(
        `SELECT ro.artifact_id, a.media_type
         FROM report_outputs ro
         JOIN artifacts a ON a.id = ro.artifact_id
         WHERE ro.snapshot_id = ? AND ro.format = ?`
      )
      .get(snapshotId, format) as { artifact_id: string; media_type: string } | undefined;
    if (!row) throw new Error("REPORT_OUTPUT_NOT_FOUND");
    const expectedMediaType = format === "json" ? "application/json" : "text/html";
    let verified: ReturnType<EvidenceService["readVerified"]>;
    try {
      verified = this.evidence.readVerified(row.artifact_id);
    } catch {
      throw new Error("REPORT_OUTPUT_INVALID");
    }
    if (row.media_type !== expectedMediaType || verified.artifact.media_type !== expectedMediaType) {
      throw new Error("REPORT_OUTPUT_INVALID");
    }
    return {
      artifactId: row.artifact_id,
      mediaType: row.media_type,
      bytes: verified.bytes
    };
  }
}
