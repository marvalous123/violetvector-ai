import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { AuditService } from "./audit-service.js";
import type { BlueDetectionService } from "./blue-detection-service.js";
import type { FindingService } from "./finding-service.js";
import type { MissionService } from "./mission-service.js";
import type { ReportService } from "./report-service.js";

export interface GuidedDemoResult {
  readonly missionId: string;
  readonly blueDetectionRunId: string;
  readonly evidenceArtifactId: string;
  readonly findingId: string;
  readonly reportSnapshotId: string;
  readonly jsonArtifactId: string;
  readonly htmlArtifactId: string;
  readonly boundary: "offline-synthetic-only";
  readonly targetContact: false;
  readonly commandExecution: false;
}

export class GuidedDemoService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly missions: MissionService,
    private readonly blueDetections: BlueDetectionService,
    private readonly findings: FindingService,
    private readonly reports: ReportService,
    private readonly audit: AuditService
  ) {}

  create(operator: string, now = new Date()): GuidedDemoResult {
    const normalizedOperator = operator.trim();
    if (normalizedOperator.length < 2 || normalizedOperator.length > 120) throw new Error("OPERATOR_INVALID");
    const mission = this.missions.createMission(
      `VioletVector AI Guided Demo ${now.toISOString().slice(0, 16).replace("T", " ")}`,
      now
    );
    const scopeVersionId = randomUUID();
    const authorizationId = randomUUID();
    const boundaryText =
      "Offline synthetic demonstration only. No target, network contact, endpoint access, command, payload or credential activity is authorized.";
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO mission_profiles(
             mission_id, mode, template_version, execution_permitted,
             boundary_text, created_by, created_at
           ) VALUES (?, 'synthetic_demo', 'guided-demo-v1', 0, ?, ?, ?)`
        )
        .run(mission.id, boundaryText, normalizedOperator, now.toISOString());
      this.database
        .prepare(
          `INSERT INTO scope_versions(
             id, mission_id, version, starts_at, expires_at, policy_version, created_at
           ) VALUES (?, ?, 1, ?, ?, 'offline-demo-v1', ?)`
        )
        .run(
          scopeVersionId,
          mission.id,
          now.toISOString(),
          new Date(now.getTime() + 24 * 60 * 60 * 1_000).toISOString(),
          now.toISOString()
        );
      this.database
        .prepare(
          `INSERT INTO authorization_records(
             id, scope_version_id, statement, attachment_sha256, recorded_at
           ) VALUES (?, ?, ?, NULL, ?)`
        )
        .run(authorizationId, scopeVersionId, boundaryText, now.toISOString());
      this.database.prepare("UPDATE missions SET status = 'ready', updated_at = ? WHERE id = ?").run(now.toISOString(), mission.id);
      this.audit.append(
        "guided_demo.boundary_recorded",
        {
          missionId: mission.id,
          scopeVersionId,
          boundary: "offline-synthetic-only",
          executionPermitted: false,
          targetCount: 0,
          operator: normalizedOperator
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    const blueRun = this.blueDetections.runSimulation(
      mission.id,
      "combined-incident",
      normalizedOperator,
      new Date(now.getTime() + 1_000)
    );
    const findingId = this.findings.createCandidate(
      mission.id,
      "Synthetic detection pipeline exercised",
      {
        severity: "info",
        description:
          "The guided offline fixture exercised thirty versioned defensive rules and sealed the deterministic result. This is training evidence only: no endpoint was contacted and no compromise, vulnerability or exploitability is inferred.",
        remediation:
          "No technical remediation is required. Use this artifact to review the evidence, approval and reporting workflow before an authorized live lab engagement.",
        confidence: "high",
        evidenceArtifactIds: [blueRun.evidenceArtifactId]
      },
      new Date(now.getTime() + 2_000)
    );
    this.findings.accept(findingId, normalizedOperator, new Date(now.getTime() + 3_000));
    const report = this.reports.freeze(mission.id, "guided-demo-v1", new Date(now.getTime() + 4_000));
    const outputs = this.reports.generate(report.id, new Date(now.getTime() + 5_000));
    const instanceId = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO guided_demo_instances(
             id, mission_id, blue_detection_run_id, finding_id,
             report_snapshot_id, json_artifact_id, html_artifact_id,
             created_by, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          instanceId,
          mission.id,
          blueRun.id,
          findingId,
          report.id,
          outputs.jsonArtifactId,
          outputs.htmlArtifactId,
          normalizedOperator,
          new Date(now.getTime() + 5_000).toISOString()
        );
      this.audit.append(
        "guided_demo.completed",
        {
          instanceId,
          missionId: mission.id,
          blueDetectionRunId: blueRun.id,
          findingId,
          reportSnapshotId: report.id,
          operator: normalizedOperator
        },
        new Date(now.getTime() + 5_000)
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return {
      missionId: mission.id,
      blueDetectionRunId: blueRun.id,
      evidenceArtifactId: blueRun.evidenceArtifactId,
      findingId,
      reportSnapshotId: report.id,
      jsonArtifactId: outputs.jsonArtifactId,
      htmlArtifactId: outputs.htmlArtifactId,
      boundary: "offline-synthetic-only",
      targetContact: false,
      commandExecution: false
    };
  }
}
