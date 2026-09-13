import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { BlueDetectionService, BlueValidationMatrixRow } from "./blue-detection-service.js";
import type { AuditService } from "./audit-service.js";

interface MissionRow {
  id: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

interface MissionProfileRow {
  mode: "synthetic_demo";
  template_version: "guided-demo-v1";
  execution_permitted: 0;
  boundary_text: string;
  created_by: string;
  created_at: string;
}

interface ScopeSummaryRow {
  id: string;
  version: number;
  starts_at: string;
  expires_at: string;
  policy_version: string;
  statement: string;
  target_count: number;
}

export interface MissionCockpit {
  mission: MissionRow;
  profile: {
    mode: "standard" | "synthetic_demo";
    templateVersion: string | null;
    executionPermitted: boolean;
    boundaryText: string;
  };
  authorization: {
    present: boolean;
    scopeVersionId: string | null;
    version: number | null;
    startsAt: string | null;
    expiresAt: string | null;
    policyVersion: string | null;
    statement: string | null;
    targetCount: number;
  };
  counts: {
    runs: number;
    activeRuns: number;
    approvalsPending: number;
    evidenceArtifacts: number;
    findings: number;
    acceptedFindings: number;
    remediations: number;
    openRemediations: number;
    imports: number;
    endpoints: number;
    blueRuns: number;
    generatedReports: number;
  };
  purple: {
    exercised: number;
    total: number;
    integrityFailed: number;
    matrix: BlueValidationMatrixRow[];
  };
  checklist: Array<{
    key: "mission" | "authorization" | "blue-validation" | "evidence" | "finding-review" | "report";
    title: string;
    status: "complete" | "pending" | "blocked";
    detail: string;
  }>;
  latestReport: {
    id: string;
    status: string;
    templateVersion: string;
    frozenAt: string;
    jsonArtifactId: string | null;
    htmlArtifactId: string | null;
  } | null;
  timeline: Array<{
    sequence: number;
    occurredAt: string;
    eventType: string;
    eventHash: string;
  }>;
  integrity: {
    auditValid: boolean;
    eventsChecked: number;
  };
}

function count(database: DatabaseSync, sql: string, ...params: SQLInputValue[]): number {
  return (database.prepare(sql).get(...params) as { count: number }).count;
}

export class MissionCockpitService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly blueDetections: BlueDetectionService,
    private readonly audit: AuditService
  ) {}

  get(missionId: string): MissionCockpit {
    const mission = this.database.prepare("SELECT * FROM missions WHERE id = ?").get(missionId) as
      | MissionRow
      | undefined;
    if (!mission) throw new Error("MISSION_NOT_FOUND");
    const profile = this.database
      .prepare(
        `SELECT mode, template_version, execution_permitted, boundary_text, created_by, created_at
         FROM mission_profiles WHERE mission_id = ?`
      )
      .get(missionId) as MissionProfileRow | undefined;
    const scope = this.database
      .prepare(
        `SELECT sv.id, sv.version, sv.starts_at, sv.expires_at, sv.policy_version,
                ar.statement,
                (SELECT COUNT(*) FROM scope_targets st WHERE st.scope_version_id = sv.id) AS target_count
         FROM scope_versions sv
         JOIN authorization_records ar ON ar.scope_version_id = sv.id
         WHERE sv.mission_id = ?
         ORDER BY sv.version DESC LIMIT 1`
      )
      .get(missionId) as ScopeSummaryRow | undefined;
    const findingIds = (
      this.database.prepare("SELECT id FROM findings WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const runIds = (
      this.database.prepare("SELECT id FROM runs WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const blueRunIds = (
      this.database.prepare("SELECT id FROM blue_detection_runs WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const reportIds = (
      this.database.prepare("SELECT id FROM report_snapshots WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const remediationIds = (
      this.database.prepare("SELECT id FROM remediation_records WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const importIds = (
      this.database.prepare("SELECT id FROM inert_imports WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const endpointIds = (
      this.database.prepare("SELECT endpoint_id AS id FROM endpoint_identities WHERE mission_id = ?").all(missionId) as unknown as Array<{ id: string }>
    ).map((row) => row.id);
    const relatedIds = new Set([
      missionId,
      ...findingIds,
      ...runIds,
      ...blueRunIds,
      ...reportIds,
      ...remediationIds,
      ...importIds,
      ...endpointIds
    ]);
    const auditRows = this.database
      .prepare(
        `SELECT sequence, occurred_at, event_type, event_hash, payload_json
         FROM audit_events ORDER BY sequence DESC LIMIT 500`
      )
      .all() as unknown as Array<{
        sequence: number;
        occurred_at: string;
        event_type: string;
        event_hash: string;
        payload_json: string;
      }>;
    const timeline = auditRows
      .filter((row) => {
        try {
          const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
          return Object.values(payload).some((value) => typeof value === "string" && relatedIds.has(value));
        } catch {
          return false;
        }
      })
      .slice(0, 50)
      .map((row) => ({
        sequence: row.sequence,
        occurredAt: row.occurred_at,
        eventType: row.event_type,
        eventHash: row.event_hash
      }));
    const matrix = this.blueDetections.validationMatrix(missionId);
    const latestReport = this.database
      .prepare(
        `SELECT rs.id, rs.status, rs.template_version, rs.frozen_at,
                (SELECT artifact_id FROM report_outputs WHERE snapshot_id = rs.id AND format = 'json') AS json_artifact_id,
                (SELECT artifact_id FROM report_outputs WHERE snapshot_id = rs.id AND format = 'html') AS html_artifact_id
         FROM report_snapshots rs
         WHERE rs.mission_id = ?
         ORDER BY rs.frozen_at DESC, rs.id DESC LIMIT 1`
      )
      .get(missionId) as
      | {
          id: string;
          status: string;
          template_version: string;
          frozen_at: string;
          json_artifact_id: string | null;
          html_artifact_id: string | null;
        }
      | undefined;
    const counts = {
      runs: count(this.database, "SELECT COUNT(*) AS count FROM runs WHERE mission_id = ?", missionId),
      activeRuns: count(
        this.database,
        "SELECT COUNT(*) AS count FROM runs WHERE mission_id = ? AND status IN ('armed', 'running', 'awaiting_approval')",
        missionId
      ),
      approvalsPending: count(
        this.database,
        `SELECT COUNT(*) AS count FROM approval_execution_bindings aeb
         JOIN approval_requests ar ON ar.id = aeb.approval_id
         WHERE aeb.mission_id = ? AND ar.status = 'pending'`,
        missionId
      ),
      evidenceArtifacts: count(
        this.database,
        "SELECT COUNT(DISTINCT artifact_id) AS count FROM evidence_observations WHERE mission_id = ?",
        missionId
      ),
      findings: findingIds.length,
      acceptedFindings: count(
        this.database,
        "SELECT COUNT(*) AS count FROM findings WHERE mission_id = ? AND status = 'accepted'",
        missionId
      ),
      remediations: remediationIds.length,
      openRemediations: count(
        this.database,
        `SELECT COUNT(*) AS count
         FROM remediation_records record
         WHERE record.mission_id = ?
           AND COALESCE(
             (
               SELECT CASE
                 WHEN event.event_type = 'retest-outcome-recorded'
                   THEN json_extract(event.payload_json, '$.outcome')
                 ELSE json_extract(event.payload_json, '$.to')
               END
               FROM remediation_events event
               WHERE event.remediation_id = record.id
                 AND event.event_type IN ('status-changed', 'retest-outcome-recorded')
               ORDER BY event.sequence DESC LIMIT 1
             ),
             'open'
           ) <> 'closed'`,
        missionId
      ),
      imports: importIds.length,
      endpoints: endpointIds.length,
      blueRuns: blueRunIds.length,
      generatedReports: count(
        this.database,
        "SELECT COUNT(*) AS count FROM report_snapshots WHERE mission_id = ? AND status = 'generated'",
        missionId
      )
    };
    const authorizationComplete = Boolean(scope) && (profile?.mode === "synthetic_demo" || scope!.target_count > 0);
    const blueComplete = matrix.some((row) => row.syntheticValidation.status === "detected");
    const auditVerification = this.audit.verify();
    const checklist: MissionCockpit["checklist"] = [
      { key: "mission", title: "Mission created", status: "complete", detail: mission.name },
      {
        key: "authorization",
        title: profile ? "Offline boundary recorded" : "Exact scope and authorization",
        status: authorizationComplete ? "complete" : "pending",
        detail: authorizationComplete
          ? profile?.boundary_text ?? `${scope!.target_count} exact target(s)`
          : "Record the authorized boundary before target work."
      },
      {
        key: "blue-validation",
        title: "Defensive validation",
        status: blueComplete ? "complete" : "pending",
        detail: blueComplete ? `${matrix.filter((row) => row.syntheticValidation.status === "detected").length}/30 rules exercised` : "Run a safe Blue scenario."
      },
      {
        key: "evidence",
        title: "Evidence captured",
        status: counts.evidenceArtifacts > 0 ? "complete" : "pending",
        detail: `${counts.evidenceArtifacts} mission-bound artifact(s)`
      },
      {
        key: "finding-review",
        title: "Finding reviewed",
        status: counts.acceptedFindings > 0 ? "complete" : counts.findings > 0 ? "blocked" : "pending",
        detail: `${counts.acceptedFindings} accepted of ${counts.findings}`
      },
      {
        key: "report",
        title: "Report generated",
        status: counts.generatedReports > 0 ? "complete" : "pending",
        detail: counts.generatedReports > 0 ? "Verified JSON and HTML outputs exist." : "Generate only from accepted evidence-backed findings."
      }
    ];
    return {
      mission,
      profile: {
        mode: profile?.mode ?? "standard",
        templateVersion: profile?.template_version ?? null,
        executionPermitted:
          profile ? false : mission.status === "scope_validated" && Boolean(scope && scope.target_count > 0),
        boundaryText:
          profile?.boundary_text ??
          "Exact target work remains capability-specific, approval-gated and subject to live isolation checks."
      },
      authorization: {
        present: authorizationComplete,
        scopeVersionId: scope?.id ?? null,
        version: scope?.version ?? null,
        startsAt: scope?.starts_at ?? null,
        expiresAt: scope?.expires_at ?? null,
        policyVersion: scope?.policy_version ?? null,
        statement: scope?.statement ?? null,
        targetCount: scope?.target_count ?? 0
      },
      counts,
      purple: {
        exercised: matrix.filter((row) => row.syntheticValidation.status === "detected").length,
        total: matrix.length,
        integrityFailed: matrix.filter((row) => row.syntheticValidation.status === "integrity-failed").length,
        matrix
      },
      checklist,
      latestReport: latestReport
        ? {
            id: latestReport.id,
            status: latestReport.status,
            templateVersion: latestReport.template_version,
            frozenAt: latestReport.frozen_at,
            jsonArtifactId: latestReport.json_artifact_id,
            htmlArtifactId: latestReport.html_artifact_id
          }
        : null,
      timeline,
      integrity: {
        auditValid: auditVerification.valid,
        eventsChecked: auditVerification.eventsChecked
      }
    };
  }
}
