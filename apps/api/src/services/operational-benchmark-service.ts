import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";
import { MissionComparisonSearchService } from "./mission-comparison-search-service.js";
import { RemediationService, type RemediationRecord, type RetestOutcome } from "./remediation-service.js";
import { ReportExportService } from "./report-export-service.js";
import { ReportQaService } from "./report-qa-service.js";

const GENESIS_HASH = "0".repeat(64);
const uuidSchema = z.string().uuid();
const actorSchema = z.string().trim().min(2).max(120);
const noteSchema = z.string().trim().min(10).max(4_000);
export const benchmarkMilestoneSchema = z.enum([
  "scope-authorized",
  "original-executed",
  "evidence-reviewed",
  "finding-accepted",
  "fix-evidence-attached",
  "retest-executed",
  "comparison-reviewed",
  "report-qa-approved",
  "recovery-verified"
]);
const requiredMilestones = new Set(z.enum(benchmarkMilestoneSchema.options).options);
export const startBenchmarkInputSchema = z.object({
  missionId: uuidSchema,
  note: noteSchema
}).strict();
export const recordBenchmarkMilestoneInputSchema = z.object({
  milestone: benchmarkMilestoneSchema,
  note: noteSchema
}).strict();
export const completeBenchmarkInputSchema = z.object({
  operatorSteps: z.number().int().min(9).max(10_000),
  policyDenials: z.number().int().nonnegative().max(10_000),
  unsupportedClaimsRejected: z.number().int().nonnegative().max(10_000),
  recoveryResult: z.enum(["recovered", "failed"]),
  recoveryElapsedMs: z.number().int().nonnegative().max(86_400_000),
  modelSuggestions: z.object({
    accepted: z.number().int().nonnegative().max(10_000),
    edited: z.number().int().nonnegative().max(10_000),
    rejected: z.number().int().nonnegative().max(10_000)
  }).strict(),
  note: noteSchema
}).strict();

type Milestone = z.infer<typeof benchmarkMilestoneSchema>;
type EventType = "milestone" | "completed";

interface BenchmarkRow {
  id: string;
  mission_id: string;
  started_by: string;
  start_note: string;
  started_at: string;
  scope_version_id: string | null;
  authorization_record_id: string | null;
}
interface EventRow {
  id: string;
  benchmark_id: string;
  sequence: number;
  event_type: EventType;
  payload_json: string;
  payload_hash: string;
  actor: string;
  occurred_at: string;
  previous_event_hash: string;
  event_hash: string;
}
interface WorkflowMetrics {
  succeededOriginalRuns: number;
  succeededRetestRuns: number;
  blockedOrFailedRuns: number;
  evidenceArtifacts: number;
  findings: number;
  acceptedFindings: number;
  completedRemediations: number;
  approvedReportQa: number;
  approvedReportExports: number;
  approvalLatencyMsAverage: number | null;
}

interface CorrelatedWorkflow {
  scopeVersionId: string;
  authorizationRecordId: string;
  originalRunId: string;
  originalApprovalId: string;
  findingId: string;
  findingRevisionId: string;
  remediationId: string;
  fixEvidenceArtifactIds: string[];
  retestRequestId: string;
  retestRunId: string;
  retestApprovalId: string;
  retestProposalId: string;
  retestOutcome: RetestOutcome;
  comparisonAssessment: string;
  reportSnapshotId: string;
  sourceQaReviewId: string;
  exportBundleId: string;
}

interface SnapshotDocument {
  scope?: { scopeVersionId?: string };
  findings?: Array<{
    id?: string;
    revisionId?: string;
    evidence?: Array<{ id?: string; observationId?: string }>;
    remediationWorkflow?: {
      id?: string;
      fixEvidence?: Array<{ artifactId?: string; observationId?: string }>;
      retests?: Array<{
        requestId?: string;
        outcome?: string | null;
        evidence?: Array<{ artifactId?: string; observationId?: string }>;
      }>;
    } | null;
  }>;
}

export interface OperationalBenchmark {
  id: string;
  missionId: string;
  status: "running" | "completed";
  startedBy: string;
  startNote: string;
  startedAt: string;
  scopeVersionId: string | null;
  authorizationRecordId: string | null;
  completedAt: string | null;
  elapsedMs: number | null;
  milestones: Array<{ milestone: Milestone; note: string; actor: string; occurredAt: string }>;
  result: Record<string, unknown> | null;
  resultHash: string | null;
  integrityValid: true;
}

function eventHash(row: {
  previousHash: string;
  benchmarkId: string;
  sequence: number;
  eventType: EventType;
  actor: string;
  occurredAt: string;
  payloadJson: string;
}): string {
  return sha256([
    row.previousHash,
    row.benchmarkId,
    String(row.sequence),
    row.eventType,
    row.actor,
    row.occurredAt,
    row.payloadJson
  ].join("\n"));
}

export class OperationalBenchmarkService {
  private readonly evidence: EvidenceService;
  private readonly remediation: RemediationService;
  private readonly comparisons: MissionComparisonSearchService;
  private readonly reportQa: ReportQaService;
  private readonly reportExports: ReportExportService;

  constructor(
    private readonly database: DatabaseSync,
    evidence: EvidenceService,
    private readonly audit: AuditService
  ) {
    this.evidence = evidence;
    this.remediation = new RemediationService(database, evidence, audit);
    this.comparisons = new MissionComparisonSearchService(database, evidence, this.remediation);
    this.reportQa = new ReportQaService(database, evidence, audit);
    this.reportExports = new ReportExportService(database, evidence, audit, this.reportQa);
  }

  start(inputValue: z.input<typeof startBenchmarkInputSchema>, actorValue: string, now = new Date()): OperationalBenchmark {
    const input = startBenchmarkInputSchema.parse(inputValue);
    const actor = actorSchema.parse(actorValue);
    const id = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const mission = this.database.prepare("SELECT id FROM missions WHERE id = ?").get(input.missionId);
      if (!mission) throw new Error("MISSION_NOT_FOUND");
      const scope = this.database.prepare(
        "SELECT id, starts_at, expires_at FROM scope_versions WHERE mission_id = ? ORDER BY version DESC LIMIT 1"
      ).get(input.missionId) as { id: string; starts_at: string; expires_at: string } | undefined;
      if (!scope) throw new Error("BENCHMARK_SCOPE_NOT_FOUND");
      if (now < new Date(scope.starts_at) || now >= new Date(scope.expires_at)) {
        throw new Error("BENCHMARK_SCOPE_NOT_ACTIVE");
      }
      const authorization = this.database.prepare(
        `SELECT id FROM authorization_records
         WHERE scope_version_id = ? AND recorded_at <= ?
         ORDER BY recorded_at DESC, id DESC LIMIT 1`
      ).get(scope.id, now.toISOString()) as { id: string } | undefined;
      if (!authorization) throw new Error("BENCHMARK_AUTHORIZATION_REQUIRED");
      const existing = this.list(input.missionId).find((benchmark) => benchmark.status === "running");
      if (existing) throw new Error("BENCHMARK_ALREADY_RUNNING");
      this.database.prepare(
        "INSERT INTO operational_benchmarks(id, mission_id, started_by, start_note, started_at) VALUES (?, ?, ?, ?, ?)"
      ).run(id, input.missionId, actor, input.note, now.toISOString());
      this.database.prepare(
        `INSERT INTO operational_benchmark_scope_bindings(
          benchmark_id, scope_version_id, authorization_record_id, bound_at
        ) VALUES (?, ?, ?, ?)`
      ).run(id, scope.id, authorization.id, now.toISOString());
      this.audit.append("benchmark.started", {
        benchmarkId: id,
        missionId: input.missionId,
        scopeVersionId: scope.id,
        authorizationRecordId: authorization.id,
        note: input.note
      }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(id);
  }

  recordMilestone(
    benchmarkId: string,
    inputValue: z.input<typeof recordBenchmarkMilestoneInputSchema>,
    actorValue: string,
    now = new Date()
  ): OperationalBenchmark {
    const input = recordBenchmarkMilestoneInputSchema.parse(inputValue);
    const actor = actorSchema.parse(actorValue);
    const current = this.get(benchmarkId);
    if (!current.scopeVersionId || !current.authorizationRecordId) {
      throw new Error("BENCHMARK_SCOPE_BINDING_REQUIRED");
    }
    if (current.status !== "running") throw new Error("BENCHMARK_ALREADY_COMPLETED");
    if (current.milestones.some((item) => item.milestone === input.milestone)) {
      throw new Error("BENCHMARK_MILESTONE_ALREADY_RECORDED");
    }
    this.append(current.id, "milestone", input, actor, now);
    return this.get(current.id);
  }

  complete(
    benchmarkId: string,
    inputValue: z.input<typeof completeBenchmarkInputSchema>,
    actorValue: string,
    now = new Date()
  ): OperationalBenchmark {
    const input = completeBenchmarkInputSchema.parse(inputValue);
    const actor = actorSchema.parse(actorValue);
    const current = this.get(benchmarkId);
    if (!current.scopeVersionId || !current.authorizationRecordId) {
      throw new Error("BENCHMARK_SCOPE_BINDING_REQUIRED");
    }
    if (current.status !== "running") throw new Error("BENCHMARK_ALREADY_COMPLETED");
    const seen = new Set(current.milestones.map((item) => item.milestone));
    if ([...requiredMilestones].some((milestone) => !seen.has(milestone))) {
      throw new Error("BENCHMARK_MILESTONES_INCOMPLETE");
    }
    const metrics = this.workflowMetrics(current.missionId, current.startedAt);
    if (
      metrics.succeededOriginalRuns < 1 ||
      metrics.succeededRetestRuns < 1 ||
      metrics.evidenceArtifacts < 1 ||
      metrics.acceptedFindings < 1 ||
      metrics.completedRemediations < 1 ||
      metrics.approvedReportQa < 1 ||
      metrics.approvedReportExports < 1
    ) {
      throw new Error("BENCHMARK_WORKFLOW_INCOMPLETE");
    }
    const correlatedWorkflow = this.correlatedWorkflow(current, now);
    if (!correlatedWorkflow) throw new Error("BENCHMARK_WORKFLOW_NOT_CORRELATED");
    const elapsedMs = Math.max(0, now.getTime() - new Date(current.startedAt).getTime());
    const recoveryPassed = input.recoveryResult === "recovered";
    const retestOutcomeAccepted = correlatedWorkflow.retestOutcome === "remediated";
    const result = {
      schemaVersion: 2,
      elapsedMs,
      operatorSteps: input.operatorSteps,
      policyDenials: input.policyDenials,
      unsupportedClaimsRejected: input.unsupportedClaimsRejected,
      recovery: { result: input.recoveryResult, elapsedMs: input.recoveryElapsedMs },
      modelSuggestions: input.modelSuggestions,
      workflow: metrics,
      correlatedWorkflow,
      releaseGate: { recoveryPassed, retestOutcomeAccepted },
      note: input.note,
      releaseReady: recoveryPassed && retestOutcomeAccepted
    };
    this.append(current.id, "completed", { result, resultHash: canonicalHash(result) }, actor, now);
    return this.get(current.id);
  }

  get(idValue: string): OperationalBenchmark {
    const id = uuidSchema.parse(idValue);
    const row = this.database.prepare(
      `SELECT benchmark.*, binding.scope_version_id, binding.authorization_record_id
       FROM operational_benchmarks benchmark
       LEFT JOIN operational_benchmark_scope_bindings binding ON binding.benchmark_id = benchmark.id
       WHERE benchmark.id = ?`
    ).get(id) as BenchmarkRow | undefined;
    if (!row) throw new Error("BENCHMARK_NOT_FOUND");
    const events = this.database.prepare(
      "SELECT * FROM operational_benchmark_events WHERE benchmark_id = ? ORDER BY sequence"
    ).all(id) as unknown as EventRow[];
    let previousHash = GENESIS_HASH;
    const milestones: OperationalBenchmark["milestones"] = [];
    let result: Record<string, unknown> | null = null;
    let resultHash: string | null = null;
    let completedAt: string | null = null;
    for (const [index, event] of events.entries()) {
      if (event.sequence !== index + 1 || event.previous_event_hash !== previousHash) {
        throw new Error("BENCHMARK_HISTORY_INVALID");
      }
      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(event.payload_json) as Record<string, unknown>;
      } catch {
        throw new Error("BENCHMARK_HISTORY_INVALID");
      }
      if (
        canonicalHash(payload) !== event.payload_hash ||
        eventHash({
          previousHash,
          benchmarkId: id,
          sequence: event.sequence,
          eventType: event.event_type,
          actor: event.actor,
          occurredAt: event.occurred_at,
          payloadJson: event.payload_json
        }) !== event.event_hash
      ) {
        throw new Error("BENCHMARK_HISTORY_INVALID");
      }
      if (event.event_type === "milestone") {
        const parsed = recordBenchmarkMilestoneInputSchema.parse(payload);
        milestones.push({ ...parsed, actor: event.actor, occurredAt: event.occurred_at });
      } else {
        if (result) throw new Error("BENCHMARK_HISTORY_INVALID");
        result = payload.result as Record<string, unknown>;
        resultHash = String(payload.resultHash ?? "");
        if (canonicalHash(result) !== resultHash) throw new Error("BENCHMARK_HISTORY_INVALID");
        completedAt = event.occurred_at;
      }
      previousHash = event.event_hash;
    }
    return {
      id,
      missionId: row.mission_id,
      status: result ? "completed" : "running",
      startedBy: row.started_by,
      startNote: row.start_note,
      startedAt: row.started_at,
      scopeVersionId: row.scope_version_id,
      authorizationRecordId: row.authorization_record_id,
      completedAt,
      elapsedMs: completedAt ? Math.max(0, new Date(completedAt).getTime() - new Date(row.started_at).getTime()) : null,
      milestones,
      result,
      resultHash,
      integrityValid: true
    };
  }

  list(missionIdValue?: string): OperationalBenchmark[] {
    const missionId = missionIdValue ? uuidSchema.parse(missionIdValue) : undefined;
    const rows = (missionId
      ? this.database.prepare("SELECT id FROM operational_benchmarks WHERE mission_id = ? ORDER BY started_at DESC").all(missionId)
      : this.database.prepare("SELECT id FROM operational_benchmarks ORDER BY started_at DESC LIMIT 100").all()
    ) as unknown as Array<{ id: string }>;
    return rows.map((row) => this.get(row.id));
  }

  private append(id: string, type: EventType, payload: unknown, actor: string, now: Date): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const latest = this.database.prepare(
        "SELECT sequence, event_hash FROM operational_benchmark_events WHERE benchmark_id = ? ORDER BY sequence DESC LIMIT 1"
      ).get(id) as { sequence: number; event_hash: string } | undefined;
      const sequence = (latest?.sequence ?? 0) + 1;
      const previousHash = latest?.event_hash ?? GENESIS_HASH;
      const occurredAt = now.toISOString();
      const payloadJson = stableJson(payload);
      const hash = eventHash({ previousHash, benchmarkId: id, sequence, eventType: type, actor, occurredAt, payloadJson });
      this.database.prepare(
        `INSERT INTO operational_benchmark_events(
          id, benchmark_id, sequence, event_type, payload_json, payload_hash,
          actor, occurred_at, previous_event_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(randomUUID(), id, sequence, type, payloadJson, canonicalHash(payload), actor, occurredAt, previousHash, hash);
      this.audit.append(`benchmark.${type}`, { benchmarkId: id, sequence, eventHash: hash }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private correlatedWorkflow(current: OperationalBenchmark, now: Date): CorrelatedWorkflow | null {
    const scopeVersionId = current.scopeVersionId!;
    const authorizationRecordId = current.authorizationRecordId!;
    const startedAtMs = new Date(current.startedAt).getTime();
    const milestones = new Map(current.milestones.map((item) => [item.milestone, new Date(item.occurredAt).getTime()]));
    const originals = this.database
      .prepare(
        `SELECT run.id AS run_id, run.updated_at, approval.id AS approval_id
         FROM runs run
         JOIN run_scope_bindings run_scope
           ON run_scope.run_id = run.id AND run_scope.scope_version_id = ?
         JOIN proposals proposal ON proposal.id = (
           SELECT id FROM proposals WHERE run_id = run.id ORDER BY created_at DESC LIMIT 1
         )
         JOIN scope_targets scope_target
           ON scope_target.scope_version_id = run_scope.scope_version_id
          AND scope_target.target_id = proposal.target_id
         JOIN approval_requests approval
           ON approval.proposal_id = proposal.id AND approval.status = 'consumed'
         JOIN approval_execution_bindings execution
           ON execution.approval_id = approval.id
          AND execution.run_id = run.id
          AND execution.mission_id = run.mission_id
          AND execution.scope_version_id = run_scope.scope_version_id
          AND execution.target_id = proposal.target_id
         WHERE run.mission_id = ?
           AND run.status = 'succeeded'
           AND COALESCE(run.lineage_type, 'original') = 'original'
           AND run.created_at >= ? AND run.updated_at >= ?
           AND proposal.created_at >= ?
           AND approval.requested_at >= ? AND approval.decided_at >= ? AND approval.consumed_at >= ?
           AND execution.authorization_starts_at <= run.created_at
           AND run.updated_at < execution.authorization_expires_at
         ORDER BY run.created_at, run.id`
      )
      .all(
        scopeVersionId,
        current.missionId,
        current.startedAt,
        current.startedAt,
        current.startedAt,
        current.startedAt,
        current.startedAt,
        current.startedAt
      ) as unknown as Array<{
        run_id: string;
        updated_at: string;
        approval_id: string;
      }>;

    for (const original of originals) {
      if ((milestones.get("original-executed") ?? 0) < new Date(original.updated_at).getTime()) continue;
      const findings = this.database
        .prepare(
          `SELECT finding.id AS finding_id, finding.updated_at, revision.id AS revision_id,
                  citation.artifact_id, citation.observation_id,
                  observation.captured_at, observation.recorded_at,
                  observation.source_event_id, observation.provenance_json,
                  lifecycle.status AS lifecycle_status,
                  lifecycle.mission_id AS lifecycle_mission_id,
                  lifecycle.run_id AS lifecycle_run_id
           FROM findings finding
           JOIN finding_revisions revision ON revision.id = (
             SELECT id FROM finding_revisions
             WHERE finding_id = finding.id ORDER BY revision DESC LIMIT 1
           )
           JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
           JOIN evidence_observations observation
             ON observation.id = citation.observation_id
            AND observation.artifact_id = citation.artifact_id
           LEFT JOIN execution_lifecycles lifecycle ON lifecycle.id = observation.source_event_id
           WHERE finding.mission_id = ? AND finding.status = 'accepted'
             AND observation.mission_id = finding.mission_id
             AND observation.run_id = ?
             AND finding.created_at >= ? AND finding.updated_at >= ?
             AND observation.captured_at >= ? AND observation.recorded_at >= ?
           ORDER BY finding.id, citation.artifact_id`
        )
        .all(
          current.missionId,
          original.run_id,
          current.startedAt,
          current.startedAt,
          current.startedAt,
          current.startedAt
        ) as unknown as Array<{
          finding_id: string;
          updated_at: string;
          revision_id: string;
          artifact_id: string;
          observation_id: string;
          captured_at: string;
          recorded_at: string;
          source_event_id: string | null;
          provenance_json: string;
          lifecycle_status: string | null;
          lifecycle_mission_id: string | null;
          lifecycle_run_id: string | null;
        }>;
      const groupedFindings = new Map<string, typeof findings>();
      for (const finding of findings) {
        const group = groupedFindings.get(finding.finding_id) ?? [];
        group.push(finding);
        groupedFindings.set(finding.finding_id, group);
      }

      for (const citations of groupedFindings.values()) {
        const finding = citations[0]!;
        if ((milestones.get("evidence-reviewed") ?? 0) < Math.max(...citations.map((row) => new Date(row.captured_at).getTime()))) continue;
        if ((milestones.get("finding-accepted") ?? 0) < new Date(finding.updated_at).getTime()) continue;
        if (!citations.every((row) => {
          if (
            !this.evidence.verify(row.artifact_id) ||
            !this.evidence.verifyObservation(row.observation_id, row.artifact_id, current.missionId) ||
            !row.source_event_id ||
            row.lifecycle_status !== "succeeded" ||
            row.lifecycle_mission_id !== current.missionId ||
            row.lifecycle_run_id !== original.run_id
          ) return false;
          try {
            const provenance = JSON.parse(row.provenance_json) as { source?: Record<string, unknown> };
            return provenance.source?.sourceType === "restricted-target-execution" &&
              provenance.source.approvalId === original.approval_id &&
              provenance.source.executionId === row.source_event_id;
          } catch {
            return false;
          }
        })) continue;

        let remediation: RemediationRecord;
        try {
          remediation = this.remediation.getForFinding(finding.finding_id, now);
        } catch {
          continue;
        }
        if (new Date(remediation.createdAt).getTime() < startedAtMs || remediation.fixEvidence.length < 1) continue;
        const fixEvidenceValid = remediation.fixEvidence.every((reference) => {
          const observation = this.database
            .prepare(
              `SELECT captured_at, recorded_at FROM evidence_observations
               WHERE id = ? AND artifact_id = ? AND mission_id = ?`
            )
            .get(reference.observationId, reference.artifactId, current.missionId) as
            | { captured_at: string; recorded_at: string }
            | undefined;
          return Boolean(
            observation &&
            new Date(reference.addedAt).getTime() >= startedAtMs &&
            new Date(observation.captured_at).getTime() >= startedAtMs &&
            new Date(observation.recorded_at).getTime() >= startedAtMs
          );
        });
        if (!fixEvidenceValid) continue;
        const latestFixAt = Math.max(...remediation.fixEvidence.map((item) => new Date(item.addedAt).getTime()));
        if ((milestones.get("fix-evidence-attached") ?? 0) < latestFixAt) continue;

        for (const retest of [...remediation.retests].reverse()) {
          if (!retest.outcome || !retest.outcomeRecordedAt || !retest.directRetest) continue;
          if (
            retest.directRetest.parentRunId !== original.run_id ||
            new Date(retest.requestedAt).getTime() < startedAtMs ||
            new Date(retest.outcomeRecordedAt).getTime() < startedAtMs
          ) continue;
          const retestRun = this.database
            .prepare(
              `SELECT run.updated_at, approval.status AS approval_status
               FROM runs run
               JOIN run_scope_bindings run_scope
                 ON run_scope.run_id = run.id AND run_scope.scope_version_id = ?
               JOIN proposals proposal
                 ON proposal.id = ? AND proposal.run_id = run.id AND proposal.mission_id = run.mission_id
               JOIN scope_targets scope_target
                 ON scope_target.scope_version_id = run_scope.scope_version_id
                AND scope_target.target_id = proposal.target_id
               JOIN approval_requests approval
                 ON approval.id = ? AND approval.proposal_id = proposal.id
               JOIN approval_execution_bindings execution
                 ON execution.approval_id = approval.id
                AND execution.run_id = run.id
                AND execution.mission_id = run.mission_id
                AND execution.scope_version_id = run_scope.scope_version_id
                AND execution.target_id = proposal.target_id
               WHERE run.id = ? AND run.mission_id = ? AND run.parent_run_id = ?
                 AND run.lineage_type = 'retest' AND run.status = 'succeeded'
                 AND run.created_at >= ? AND run.updated_at >= ? AND proposal.created_at >= ?
                 AND approval.requested_at >= ? AND approval.decided_at >= ? AND approval.consumed_at >= ?
                 AND execution.authorization_starts_at <= run.created_at
                 AND run.updated_at < execution.authorization_expires_at`
            )
            .get(
              scopeVersionId,
              retest.directRetest.proposalId,
              retest.directRetest.approvalId,
              retest.directRetest.retestRunId,
              current.missionId,
              original.run_id,
              current.startedAt,
              current.startedAt,
              current.startedAt,
              current.startedAt,
              current.startedAt,
              current.startedAt
            ) as { updated_at: string; approval_status: string } | undefined;
          if (!retestRun || retestRun.approval_status !== "consumed") continue;
          if ((milestones.get("retest-executed") ?? 0) < new Date(retestRun.updated_at).getTime()) continue;

          let comparison;
          try {
            comparison = this.comparisons.compare({
              missionId: current.missionId,
              originalRunId: original.run_id,
              retestRunId: retest.directRetest.retestRunId
            }, now);
          } catch {
            continue;
          }
          const comparedFinding = comparison.findings.find((item) => item.findingId === finding.finding_id);
          const retestArtifactIds = [...retest.evidence.map((item) => item.artifactId)].sort();
          if (
            !comparison.configurationEquivalent ||
            comparison.original.status !== "succeeded" ||
            comparison.retest.status !== "succeeded" ||
            !comparison.original.proposalIntegrityValid ||
            !comparison.retest.proposalIntegrityValid ||
            !citations.every((citation) => comparison.original.evidence.some((item) =>
              item.integrityValid &&
              item.artifactId === citation.artifact_id &&
              item.observationId === citation.observation_id
            )) ||
            !comparedFinding ||
            comparedFinding.explicitOutcome !== retest.outcome ||
            comparedFinding.assessment !== `explicit-${retest.outcome}` ||
            stableJson([...comparedFinding.supportingRetestArtifactIds].sort()) !== stableJson(retestArtifactIds) ||
            !retest.evidence.every((reference) => comparison.retest.evidence.some((item) =>
              item.integrityValid &&
              item.artifactId === reference.artifactId &&
              item.observationId === reference.observationId
            ))
          ) continue;
          if ((milestones.get("comparison-reviewed") ?? 0) < new Date(retest.outcomeRecordedAt).getTime()) continue;

          const snapshots = this.database
            .prepare(
              `SELECT id, snapshot_json, snapshot_hash, frozen_at
               FROM report_snapshots
               WHERE mission_id = ? AND status = 'generated' AND frozen_at >= ?
               ORDER BY frozen_at DESC, id DESC`
            )
            .all(current.missionId, retest.outcomeRecordedAt) as unknown as Array<{
              id: string;
              snapshot_json: string;
              snapshot_hash: string;
              frozen_at: string;
            }>;
          for (const snapshot of snapshots) {
            let document: SnapshotDocument;
            try {
              document = JSON.parse(snapshot.snapshot_json) as SnapshotDocument;
              if (canonicalHash(document) !== snapshot.snapshot_hash) continue;
            } catch {
              continue;
            }
            const snapshotFinding = document.findings?.find((item) =>
              item.id === finding.finding_id && item.revisionId === finding.revision_id
            );
            const snapshotRetest = snapshotFinding?.remediationWorkflow?.retests?.find((item) =>
              item.requestId === retest.requestId && item.outcome === retest.outcome
            );
            if (
              document.scope?.scopeVersionId !== scopeVersionId ||
              snapshotFinding?.remediationWorkflow?.id !== remediation.id ||
              !citations.every((citation) => snapshotFinding.evidence?.some((item) =>
                item.id === citation.artifact_id && item.observationId === citation.observation_id
              )) ||
              !remediation.fixEvidence.every((reference) => snapshotFinding.remediationWorkflow?.fixEvidence?.some((item) =>
                item.artifactId === reference.artifactId && item.observationId === reference.observationId
              )) ||
              !snapshotRetest ||
              !retest.evidence.every((reference) => snapshotRetest.evidence?.some((item) =>
                item.artifactId === reference.artifactId && item.observationId === reference.observationId
              ))
            ) continue;

            const qaRow = this.database
              .prepare("SELECT id FROM report_qa_reviews WHERE snapshot_id = ?")
              .get(snapshot.id) as { id: string } | undefined;
            if (!qaRow) continue;
            let sourceQa;
            try {
              sourceQa = this.reportQa.get(qaRow.id);
            } catch {
              continue;
            }
            if (
              !sourceQa.publicationReady ||
              !sourceQa.reviewedAt ||
              new Date(sourceQa.openedAt).getTime() < new Date(snapshot.frozen_at).getTime() ||
              new Date(sourceQa.reviewedAt).getTime() < new Date(sourceQa.openedAt).getTime() ||
              (milestones.get("report-qa-approved") ?? 0) < new Date(sourceQa.reviewedAt).getTime()
            ) continue;
            let bundle;
            try {
              bundle = this.reportExports.forSnapshot(snapshot.id);
            } catch {
              continue;
            }
            if (
              !bundle?.publicationReady ||
              !bundle.reviewedAt ||
              bundle.sourceQaReviewId !== sourceQa.id ||
              new Date(bundle.generatedAt).getTime() < new Date(sourceQa.reviewedAt).getTime() ||
              new Date(bundle.reviewedAt).getTime() < new Date(bundle.generatedAt).getTime()
            ) continue;

            return {
              scopeVersionId,
              authorizationRecordId,
              originalRunId: original.run_id,
              originalApprovalId: original.approval_id,
              findingId: finding.finding_id,
              findingRevisionId: finding.revision_id,
              remediationId: remediation.id,
              fixEvidenceArtifactIds: remediation.fixEvidence.map((item) => item.artifactId).sort(),
              retestRequestId: retest.requestId,
              retestRunId: retest.directRetest.retestRunId,
              retestApprovalId: retest.directRetest.approvalId,
              retestProposalId: retest.directRetest.proposalId,
              retestOutcome: retest.outcome,
              comparisonAssessment: comparedFinding.assessment,
              reportSnapshotId: snapshot.id,
              sourceQaReviewId: sourceQa.id,
              exportBundleId: bundle.id
            };
          }
        }
      }
    }
    return null;
  }

  private workflowMetrics(missionId: string, startedAt: string): WorkflowMetrics {
    const scalar = (sql: string, ...params: string[]) =>
      Number((this.database.prepare(sql).get(...params) as { count: number }).count);
    const approvalRows = this.database.prepare(
      `SELECT ar.requested_at, ar.decided_at
       FROM approval_requests ar
       JOIN proposals p ON p.id = ar.proposal_id
       JOIN runs r ON r.id = p.run_id
       WHERE p.mission_id = ? AND r.mission_id = p.mission_id
         AND r.created_at >= ? AND p.created_at >= ? AND ar.requested_at >= ?
         AND ar.decided_at >= ? AND ar.status IN ('approved', 'consumed')`
    ).all(missionId, startedAt, startedAt, startedAt, startedAt) as unknown as Array<{ requested_at: string; decided_at: string }>;
    const latencies = approvalRows.map((row) =>
      Math.max(0, new Date(row.decided_at).getTime() - new Date(row.requested_at).getTime())
    );
    return {
      succeededOriginalRuns: scalar(
        "SELECT COUNT(*) AS count FROM runs WHERE mission_id = ? AND status = 'succeeded' AND COALESCE(lineage_type, 'original') = 'original' AND created_at >= ? AND updated_at >= ?",
        missionId, startedAt, startedAt
      ),
      succeededRetestRuns: scalar(
        `SELECT COUNT(*) AS count
         FROM runs retest JOIN runs parent ON parent.id = retest.parent_run_id
         WHERE retest.mission_id = ? AND parent.mission_id = retest.mission_id
           AND retest.status = 'succeeded' AND retest.lineage_type = 'retest'
           AND parent.status = 'succeeded' AND COALESCE(parent.lineage_type, 'original') = 'original'
           AND retest.created_at >= ? AND retest.updated_at >= ? AND parent.created_at >= ?`,
        missionId, startedAt, startedAt, startedAt
      ),
      blockedOrFailedRuns: scalar(
        "SELECT COUNT(*) AS count FROM runs WHERE mission_id = ? AND status IN ('failed', 'stopped', 'stop_incomplete') AND created_at >= ?",
        missionId, startedAt
      ),
      evidenceArtifacts: scalar(
        "SELECT COUNT(DISTINCT artifact_id) AS count FROM evidence_observations WHERE mission_id = ? AND captured_at >= ? AND recorded_at >= ?",
        missionId, startedAt, startedAt
      ),
      findings: scalar(
        "SELECT COUNT(*) AS count FROM findings WHERE mission_id = ? AND created_at >= ?",
        missionId, startedAt
      ),
      acceptedFindings: scalar(
        "SELECT COUNT(*) AS count FROM findings WHERE mission_id = ? AND status = 'accepted' AND created_at >= ? AND updated_at >= ?",
        missionId, startedAt, startedAt
      ),
      completedRemediations: scalar(
        `SELECT COUNT(DISTINCT record.id) AS count
         FROM remediation_records record
         JOIN findings finding ON finding.id = record.finding_id AND finding.mission_id = record.mission_id
         WHERE record.mission_id = ? AND record.created_at >= ? AND finding.created_at >= ?
           AND EXISTS (
             SELECT 1 FROM remediation_events event
             JOIN remediation_evidence_links link ON link.remediation_event_id = event.id AND link.purpose = 'fix'
             JOIN evidence_observations observation ON observation.id = link.observation_id AND observation.artifact_id = link.artifact_id
             WHERE event.remediation_id = record.id AND event.event_type = 'fix-evidence-added'
               AND event.occurred_at >= ? AND observation.mission_id = record.mission_id
               AND observation.captured_at >= ? AND observation.recorded_at >= ?
           )
           AND EXISTS (
             SELECT 1 FROM remediation_events event
             JOIN remediation_evidence_links link ON link.remediation_event_id = event.id AND link.purpose = 'retest'
             JOIN evidence_observations observation ON observation.id = link.observation_id AND observation.artifact_id = link.artifact_id
             WHERE event.remediation_id = record.id AND event.event_type = 'retest-outcome-recorded'
               AND event.occurred_at >= ? AND observation.mission_id = record.mission_id
               AND observation.captured_at >= ? AND observation.recorded_at >= ?
           )`,
        missionId, startedAt, startedAt,
        startedAt, startedAt, startedAt,
        startedAt, startedAt, startedAt
      ),
      approvedReportQa: scalar(
        `SELECT COUNT(*) AS count
         FROM report_qa_reviews review
         JOIN report_snapshots snapshot ON snapshot.id = review.snapshot_id
         WHERE snapshot.mission_id = ? AND snapshot.frozen_at >= ? AND review.opened_at >= ? AND EXISTS (
           SELECT 1 FROM report_qa_events event
           WHERE event.review_id = review.id AND event.event_type = 'approved' AND event.occurred_at >= ?
         )`,
        missionId, startedAt, startedAt, startedAt
      ),
      approvedReportExports: scalar(
        `SELECT COUNT(*) AS count
         FROM report_export_bundles bundle
         JOIN report_snapshots snapshot ON snapshot.id = bundle.snapshot_id
         WHERE bundle.mission_id = ? AND bundle.generated_at >= ? AND snapshot.frozen_at >= ? AND EXISTS (
           SELECT 1 FROM report_export_qa_events event
           WHERE event.bundle_id = bundle.id AND event.event_type = 'approved' AND event.occurred_at >= ?
         )`,
        missionId, startedAt, startedAt, startedAt
      ),
      approvalLatencyMsAverage: latencies.length
        ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length)
        : null
    };
  }
}
