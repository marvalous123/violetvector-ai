import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";

interface RevisionInput {
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  remediation: string;
  confidence: "low" | "medium" | "high";
  evidenceArtifactIds: string[];
}

export class FindingService {
  private readonly audit: AuditService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    audit?: AuditService
  ) {
    this.audit = audit ?? new AuditService(database);
  }

  createCandidate(missionId: string, title: string, revision: RevisionInput, now = new Date()): string {
    const mission = this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId);
    if (!mission) throw new Error("MISSION_NOT_FOUND");
    if (title.trim().length < 5 || title.trim().length > 160) throw new Error("FINDING_TITLE_INVALID");
    const evidence = this.validateRevision(revision, missionId);
    const findingId = randomUUID();
    const timestamp = now.toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO findings(id, mission_id, status, title, created_at, updated_at)
           VALUES (?, ?, 'candidate', ?, ?, ?)`
        )
        .run(findingId, missionId, title.trim(), timestamp, timestamp);
      const revisionId = this.insertRevision(findingId, 1, revision, evidence, now);
      this.audit.append(
        "finding.created",
        { findingId, missionId, revisionId, title: title.trim(), evidenceCount: evidence.length },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return findingId;
  }

  addRevision(findingId: string, input: RevisionInput, now = new Date()): string {
    const finding = this.database.prepare("SELECT id, mission_id FROM findings WHERE id = ?").get(findingId) as
      | { id: string; mission_id: string }
      | undefined;
    if (!finding) throw new Error("FINDING_NOT_FOUND");
    const evidence = this.validateRevision(input, finding.mission_id);
    const row = this.database
      .prepare("SELECT COALESCE(MAX(revision), 0) + 1 AS revision FROM finding_revisions WHERE finding_id = ?")
      .get(findingId) as { revision: number };
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const revisionId = this.insertRevision(findingId, row.revision, input, evidence, now);
      this.audit.append(
        "finding.revised",
        { findingId, revisionId, revision: row.revision, evidenceCount: evidence.length },
        now
      );
      this.database.exec("COMMIT");
      return revisionId;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private validateRevision(
    input: RevisionInput,
    missionId: string
  ): Array<{ artifactId: string; observationId: string }> {
    if (input.description.trim().length < 10 || input.remediation.trim().length < 5) throw new Error("FINDING_CONTENT_INVALID");
    if (input.evidenceArtifactIds.length < 1) throw new Error("FINDING_EVIDENCE_REQUIRED");
    const uniqueEvidence = [...new Set(input.evidenceArtifactIds)];
    if (!uniqueEvidence.every((id) => this.evidence.verify(id))) throw new Error("FINDING_EVIDENCE_INVALID");
    return uniqueEvidence.map((artifactId) => {
      try {
        return { artifactId, observationId: this.evidence.observationForMission(artifactId, missionId).id };
      } catch {
        throw new Error("FINDING_EVIDENCE_MISSION_MISMATCH");
      }
    });
  }

  private insertRevision(
    findingId: string,
    revision: number,
    input: RevisionInput,
    evidence: Array<{ artifactId: string; observationId: string }>,
    now: Date
  ): string {
    const revisionId = randomUUID();
    this.database
      .prepare(
        `INSERT INTO finding_revisions(
           id, finding_id, revision, severity, description, remediation, confidence, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        revisionId,
        findingId,
        revision,
        input.severity,
        input.description.trim(),
        input.remediation.trim(),
        input.confidence,
        now.toISOString()
      );
    for (const citation of evidence) {
      this.database
        .prepare(
          `INSERT INTO finding_evidence_observations(
             finding_revision_id, artifact_id, observation_id
           ) VALUES (?, ?, ?)`
        )
        .run(revisionId, citation.artifactId, citation.observationId);
      this.database
        .prepare("INSERT INTO finding_evidence(finding_revision_id, artifact_id) VALUES (?, ?)")
        .run(revisionId, citation.artifactId);
    }
    this.database
      .prepare("UPDATE findings SET status = 'unverified', updated_at = ? WHERE id = ?")
      .run(now.toISOString(), findingId);
    return revisionId;
  }

  accept(findingId: string, operator: string, now = new Date()): void {
    if (operator.trim().length < 2) throw new Error("OPERATOR_INVALID");
    const latest = this.database
      .prepare(
        `SELECT fr.id FROM finding_revisions fr
         WHERE fr.finding_id = ? ORDER BY fr.revision DESC LIMIT 1`
      )
      .get(findingId) as { id: string } | undefined;
    if (!latest) throw new Error("FINDING_REVISION_NOT_FOUND");
    const finding = this.database.prepare("SELECT mission_id FROM findings WHERE id = ?").get(findingId) as
      | { mission_id: string }
      | undefined;
    if (!finding) throw new Error("FINDING_NOT_FOUND");
    const evidence = this.database
      .prepare(
        `SELECT artifact_id, observation_id
         FROM finding_evidence_observations WHERE finding_revision_id = ?`
      )
      .all(latest.id) as unknown as Array<{ artifact_id: string; observation_id: string }>;
    if (
      evidence.length < 1 ||
      !evidence.every((row) => {
        if (!this.evidence.verify(row.artifact_id)) return false;
        return this.evidence.verifyObservation(row.observation_id, row.artifact_id, finding.mission_id);
      })
    ) {
      throw new Error("FINDING_EVIDENCE_INVALID");
    }
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare("UPDATE findings SET status = 'accepted', updated_at = ? WHERE id = ?")
        .run(now.toISOString(), findingId);
      this.audit.append("finding.accepted", { findingId, revisionId: latest.id, operator: operator.trim() }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}
