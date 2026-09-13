import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { getCapabilitySchemaHash } from "@war-room/policy";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { ExecutionLifecycleService } from "./execution-lifecycle-service.js";
import { FindingService } from "./finding-service.js";
import { MissionService } from "./mission-service.js";
import { OperationalBenchmarkService, benchmarkMilestoneSchema } from "./operational-benchmark-service.js";
import { RemediationService } from "./remediation-service.js";
import { ReportExportService } from "./report-export-service.js";
import { ReportQaService } from "./report-qa-service.js";
import { ReportService } from "./report-service.js";
import type { RetestOutcome } from "./remediation-service.js";

const startedAt = new Date("2026-09-08T08:00:00.000Z");
const operator = "Local operator";

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "benchmark-evidence-")), audit);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Retained authorized benchmark", startedAt);
  missions.createScopeVersion({
    missionId: mission.id,
    startsAt: "2026-09-08T07:00:00.000Z",
    expiresAt: "2026-09-08T10:00:00.000Z",
    policyVersion: "policy-v1",
    authorizationStatement: "I own and authorize this isolated benchmark lab target.",
    targets: [{ address: "8.8.8.8" }]
  }, startedAt);
  return { database, audit, evidence, mission };
}

async function completeWorkflow(
  database: ReturnType<typeof openDatabase>,
  audit: AuditService,
  evidence: EvidenceService,
  missionId: string,
  eventAt: Date,
  finalOutcome: RetestOutcome = "remediated"
) {
  const timestamp = eventAt.toISOString();
  const scope = database.prepare(
    `SELECT scope.id AS scope_version_id, target.id AS target_id, target.canonical_address
     FROM scope_versions scope
     JOIN scope_targets scoped ON scoped.scope_version_id = scope.id
     JOIN targets target ON target.id = scoped.target_id
     WHERE scope.mission_id = ? ORDER BY scope.version DESC LIMIT 1`
  ).get(missionId) as { scope_version_id: string; target_id: string; canonical_address: string };
  const originalRunId = randomUUID();
  database.prepare(
    "INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at) VALUES (?, ?, NULL, 'original', 'succeeded', ?, ?)"
  ).run(originalRunId, missionId, timestamp, timestamp);
  database.prepare(
    "INSERT INTO run_scope_bindings(run_id, scope_version_id, bound_at) VALUES (?, ?, ?)"
  ).run(originalRunId, scope.scope_version_id, timestamp);
  const originalProposalId = randomUUID();
  const toolSchemaHash = getCapabilitySchemaHash("network.service-version");
  const originalProposal = {
    proposalId: originalProposalId,
    missionId,
    runId: originalRunId,
    targetId: scope.target_id,
    capabilityId: "network.service-version",
    riskTier: "T1",
    timeoutMs: 15_000,
    maxOutputBytes: 262_144,
    parameters: { ports: [53], transport: "tcp", intensity: 1 }
  };
  const originalProposalHash = canonicalHash(originalProposal);
  database.prepare(
    `INSERT INTO proposals(
       id, mission_id, run_id, target_id, capability_id, risk_tier, proposal_json,
       proposal_hash, policy_version, tool_schema_hash, created_at
     ) VALUES (?, ?, ?, ?, 'network.service-version', 'T1', ?, ?, 'policy-v1', ?, ?)`
  ).run(
    originalProposalId,
    missionId,
    originalRunId,
    scope.target_id,
    stableJson(originalProposal),
    originalProposalHash,
    toolSchemaHash,
    timestamp
  );
  const originalApprovalId = randomUUID();
  database.prepare(
    `INSERT INTO approval_requests(
       id, proposal_id, proposal_hash, policy_version, tool_schema_hash, status,
       requested_at, expires_at, decided_at, decided_by, consumed_at, decision_note
     ) VALUES (?, ?, ?, 'policy-v1', ?, 'consumed', ?, ?, ?, ?, ?, ?)`
  ).run(
    originalApprovalId,
    originalProposalId,
    originalProposalHash,
    toolSchemaHash,
    timestamp,
    new Date(eventAt.getTime() + 60_000).toISOString(),
    timestamp,
    operator,
    timestamp,
    "Approved for the exact isolated benchmark scope."
  );
  insertExecutionBinding(
    database,
    originalApprovalId,
    originalRunId,
    missionId,
    scope.scope_version_id,
    scope.target_id,
    scope.canonical_address,
    toolSchemaHash
  );
  const originalLifecycles = new ExecutionLifecycleService(database);
  let originalLifecycle = originalLifecycles.create({
    capabilityId: "mcpwn.nmap.service-version.v1",
    operator,
    missionId,
    runId: originalRunId
  }, eventAt);
  originalLifecycle = originalLifecycles.transition(originalLifecycle.id, "starting", { now: eventAt });
  originalLifecycle = originalLifecycles.transition(originalLifecycle.id, "running", { now: eventAt });
  originalLifecycle = originalLifecycles.transition(originalLifecycle.id, "succeeded", { now: eventAt });

  const originalEvidence = evidence.seal("original result", "text/plain", {
    missionId,
    runId: originalRunId,
    sourceEventId: originalLifecycle.id,
    capturedAt: eventAt,
    provenance: {
      sourceType: "restricted-target-execution",
      executionId: originalLifecycle.id,
      approvalId: originalApprovalId
    }
  });
  const findings = new FindingService(database, evidence, audit);
  const findingId = findings.createCandidate(missionId, "Measured finding", {
    severity: "low",
    description: "The original authorized test produced a supported observation.",
    remediation: "Apply the lab fix and complete a separately approved retest.",
    confidence: "high",
    evidenceArtifactIds: [originalEvidence.id]
  }, eventAt);
  findings.accept(findingId, operator, eventAt);
  const remediations = new RemediationService(database, evidence, audit);
  let remediation = remediations.create(findingId, {
    owner: operator, dueDate: "2026-09-15", priority: "medium"
  }, operator, eventAt);
  remediation = remediations.changeStatus(remediation.id, { status: "in-progress" }, operator, eventAt);
  remediation = remediations.changeStatus(remediation.id, { status: "fix-ready" }, operator, eventAt);
  remediation = remediations.captureOperatorFixEvidence(remediation.id, {
    changeType: "device-configuration",
    actionPerformedAt: eventAt.toISOString(),
    actionSummary: "Applied the bounded lab configuration change for the measured finding.",
    observedState: "The intended lab configuration is present and ready for a separate retest."
  }, operator, eventAt).remediation;
  const requestId = remediations.requestRetest(remediation.id, {
    reason: "Verify the original observation after the retained fix."
  }, operator, eventAt);
  const firstOutcome = finalOutcome === "regressed" ? "remediated" : finalOutcome;
  let retestResult = completeDirectRetest(
    database,
    evidence,
    remediations,
    remediation.id,
    requestId,
    originalRunId,
    originalProposal,
    scope,
    missionId,
    firstOutcome,
    eventAt
  );
  if (finalOutcome === "regressed") {
    const regressionRequestId = remediations.requestRetest(remediation.id, {
      reason: "Perform the separately approved regression check against the remediated baseline."
    }, operator, eventAt);
    retestResult = completeDirectRetest(
      database,
      evidence,
      remediations,
      remediation.id,
      regressionRequestId,
      originalRunId,
      originalProposal,
      scope,
      missionId,
      "regressed",
      eventAt
    );
  }

  const reports = new ReportService(database, evidence, audit);
  const snapshot = reports.freeze(missionId, "report-template-v1", eventAt);
  reports.generate(snapshot.id, eventAt);
  const qa = new ReportQaService(database, evidence, audit);
  const review = qa.open(snapshot.id, operator, eventAt);
  qa.approve(review.id, {
    checklist: {
      scopeReviewed: true,
      claimsSupported: true,
      evidenceLinksVerified: true,
      remediationReviewed: true,
      sensitiveDataReviewed: true,
      layoutReviewed: true
    },
    note: "The exact generated JSON and HTML outputs were reviewed."
  }, operator, eventAt);
  const exports = new ReportExportService(database, evidence, audit, qa);
  const bundle = await exports.generate(snapshot.id, operator, eventAt);
  exports.approve(bundle.id, {
    checklist: {
      pdfLayoutReviewed: true,
      docxLayoutReviewed: true,
      pageBreaksReviewed: true,
      evidenceReferencesReadable: true,
      sensitiveDataReviewed: true
    },
    note: "The exact PDF and DOCX outputs were opened and visually reviewed."
  }, operator, eventAt);
  return {
    originalRunId,
    originalApprovalId,
    findingId,
    remediationId: remediation.id,
    retestRunId: retestResult.retestRunId,
    retestOutcome: finalOutcome,
    snapshotId: snapshot.id,
    sourceQaReviewId: review.id,
    exportBundleId: bundle.id
  };
}

function insertExecutionBinding(
  database: ReturnType<typeof openDatabase>,
  approvalId: string,
  runId: string,
  missionId: string,
  scopeVersionId: string,
  targetId: string,
  canonicalTarget: string,
  toolSchemaHash: string
) {
  database.prepare(
    `INSERT INTO approval_execution_bindings(
       approval_id, run_id, mission_id, scope_version_id, target_id, canonical_target,
       authorization_starts_at, authorization_expires_at, capability_schema_hash,
       safety_epoch, wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit,
       output_bytes_limit, request_count_limit
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 15000, 15000, 1000, 262144, 1)`
  ).run(
    approvalId,
    runId,
    missionId,
    scopeVersionId,
    targetId,
    canonicalTarget,
    "2026-09-08T07:00:00.000Z",
    "2026-09-08T10:00:00.000Z",
    toolSchemaHash
  );
  database.prepare(
    `INSERT INTO run_budgets(
       run_id, wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit,
       output_bytes_limit, request_count_limit
     ) VALUES (?, 15000, 15000, 1000, 262144, 1)`
  ).run(runId);
}

function completeDirectRetest(
  database: ReturnType<typeof openDatabase>,
  evidence: EvidenceService,
  remediations: RemediationService,
  remediationId: string,
  requestId: string,
  originalRunId: string,
  originalProposal: Record<string, unknown>,
  scope: { scope_version_id: string; target_id: string; canonical_address: string },
  missionId: string,
  outcome: RetestOutcome,
  eventAt: Date
) {
  const timestamp = eventAt.toISOString();
  const toolSchemaHash = getCapabilitySchemaHash("network.service-version");
  const retestRunId = randomUUID();
  const retestProposalId = randomUUID();
  const approvalId = randomUUID();
  database.prepare(
    "INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at) VALUES (?, ?, ?, 'retest', 'awaiting_approval', ?, ?)"
  ).run(retestRunId, missionId, originalRunId, timestamp, timestamp);
  database.prepare(
    "INSERT INTO run_scope_bindings(run_id, scope_version_id, bound_at) VALUES (?, ?, ?)"
  ).run(retestRunId, scope.scope_version_id, timestamp);
  const retestProposal = { ...originalProposal, proposalId: retestProposalId, runId: retestRunId };
  const retestProposalHash = canonicalHash(retestProposal);
  database.prepare(
    `INSERT INTO proposals(
       id, mission_id, run_id, target_id, capability_id, risk_tier, proposal_json,
       proposal_hash, policy_version, tool_schema_hash, created_at
     ) VALUES (?, ?, ?, ?, 'network.service-version', 'T1', ?, ?, 'policy-v1', ?, ?)`
  ).run(
    retestProposalId,
    missionId,
    retestRunId,
    scope.target_id,
    stableJson(retestProposal),
    retestProposalHash,
    toolSchemaHash,
    timestamp
  );
  database.prepare(
    `INSERT INTO approval_requests(
       id, proposal_id, proposal_hash, policy_version, tool_schema_hash, status, requested_at, expires_at
     ) VALUES (?, ?, ?, 'policy-v1', ?, 'pending', ?, ?)`
  ).run(
    approvalId,
    retestProposalId,
    retestProposalHash,
    toolSchemaHash,
    timestamp,
    new Date(eventAt.getTime() + 60_000).toISOString()
  );
  insertExecutionBinding(
    database,
    approvalId,
    retestRunId,
    missionId,
    scope.scope_version_id,
    scope.target_id,
    scope.canonical_address,
    toolSchemaHash
  );
  remediations.bindDirectRetest(remediationId, {
    requestId,
    parentRunId: originalRunId,
    retestRunId,
    approvalId,
    proposalId: retestProposalId
  }, operator, eventAt);
  database.prepare(
    `UPDATE approval_requests
     SET status = 'consumed', decided_at = ?, decided_by = ?, consumed_at = ?, decision_note = ?
     WHERE id = ?`
  ).run(timestamp, operator, timestamp, "Approved and consumed for the exact direct retest.", approvalId);
  database.prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ?")
    .run(timestamp, retestRunId);
  const lifecycles = new ExecutionLifecycleService(database);
  let lifecycle = lifecycles.create({
    capabilityId: "mcpwn.nmap.service-version.v1",
    operator,
    missionId,
    runId: retestRunId
  }, eventAt);
  lifecycle = lifecycles.transition(lifecycle.id, "starting", { now: eventAt });
  lifecycle = lifecycles.transition(lifecycle.id, "running", { now: eventAt });
  lifecycle = lifecycles.transition(lifecycle.id, "succeeded", { now: eventAt });
  const retestEvidence = evidence.seal(`retest result: ${outcome}`, "text/plain", {
    missionId,
    runId: retestRunId,
    sourceEventId: lifecycle.id,
    capturedAt: eventAt,
    provenance: {
      sourceType: "restricted-target-execution",
      executionId: lifecycle.id,
      approvalId
    }
  });
  remediations.recordRetestOutcome(remediationId, {
    requestId,
    outcome,
    summary: `The separately approved retest produced the explicit reviewed outcome: ${outcome}.`,
    reviewer: operator,
    evidenceArtifactIds: [retestEvidence.id]
  }, operator, eventAt);
  return { retestRunId, retestProposalId, approvalId, retestEvidence };
}

describe("retained operational benchmark", () => {
  it("requires the real closed-loop workflow and seals measured results", async () => {
    const { database, audit, evidence, mission } = setup();
    const service = new OperationalBenchmarkService(database, evidence, audit);
    let benchmark = service.start({
      missionId: mission.id,
      note: "Measure the authorized scope-to-report operator workflow."
    }, operator, startedAt);
    const expectedBinding = database.prepare(
      `SELECT scope.id AS scope_version_id, authorization.id AS authorization_record_id
       FROM scope_versions scope
       JOIN authorization_records authorization ON authorization.scope_version_id = scope.id
       WHERE scope.mission_id = ? ORDER BY scope.version DESC, authorization.recorded_at DESC LIMIT 1`
    ).get(mission.id) as { scope_version_id: string; authorization_record_id: string };
    assert.equal(benchmark.scopeVersionId, expectedBinding.scope_version_id);
    assert.equal(benchmark.authorizationRecordId, expectedBinding.authorization_record_id);
    for (const [index, milestone] of benchmarkMilestoneSchema.options.entries()) {
      benchmark = service.recordMilestone(benchmark.id, {
        milestone,
        note: "Retained operator checkpoint for the measured workflow."
      }, operator, new Date(startedAt.getTime() + (index + 1) * 1_000));
    }
    assert.throws(
      () => service.complete(benchmark.id, {
        operatorSteps: 12,
        policyDenials: 1,
        unsupportedClaimsRejected: 1,
        recoveryResult: "recovered",
        recoveryElapsedMs: 2_000,
        modelSuggestions: { accepted: 0, edited: 0, rejected: 1 },
        note: "The workflow and recovery measurements were reviewed."
      }, operator, new Date(startedAt.getTime() + 60_000)),
      /BENCHMARK_WORKFLOW_INCOMPLETE/
    );

    const workflow = await completeWorkflow(database, audit, evidence, mission.id, startedAt);

    benchmark = service.complete(benchmark.id, {
      operatorSteps: 12,
      policyDenials: 1,
      unsupportedClaimsRejected: 1,
      recoveryResult: "recovered",
      recoveryElapsedMs: 2_000,
      modelSuggestions: { accepted: 0, edited: 0, rejected: 1 },
      note: "The complete workflow and recovery measurements were reviewed."
    }, operator, new Date(startedAt.getTime() + 120_000));
    assert.equal(benchmark.status, "completed");
    assert.equal(benchmark.elapsedMs, 120_000);
    assert.equal(benchmark.integrityValid, true);
    const result = benchmark.result as {
      releaseReady: boolean;
      releaseGate: { recoveryPassed: boolean; retestOutcomeAccepted: boolean };
      correlatedWorkflow: {
        originalRunId: string;
        originalApprovalId: string;
        findingId: string;
        remediationId: string;
        retestRunId: string;
        retestOutcome: string;
        reportSnapshotId: string;
        sourceQaReviewId: string;
        exportBundleId: string;
      };
    };
    assert.equal(result.releaseReady, true);
    assert.deepEqual(result.releaseGate, { recoveryPassed: true, retestOutcomeAccepted: true });
    assert.equal(result.correlatedWorkflow.originalRunId, workflow.originalRunId);
    assert.equal(result.correlatedWorkflow.originalApprovalId, workflow.originalApprovalId);
    assert.equal(result.correlatedWorkflow.findingId, workflow.findingId);
    assert.equal(result.correlatedWorkflow.remediationId, workflow.remediationId);
    assert.equal(result.correlatedWorkflow.retestRunId, workflow.retestRunId);
    assert.equal(result.correlatedWorkflow.retestOutcome, "remediated");
    assert.equal(result.correlatedWorkflow.reportSnapshotId, workflow.snapshotId);
    assert.equal(result.correlatedWorkflow.sourceQaReviewId, workflow.sourceQaReviewId);
    assert.equal(result.correlatedWorkflow.exportBundleId, workflow.exportBundleId);
    assert.match(benchmark.resultHash!, /^[a-f0-9]{64}$/);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects mission-wide workflow counts when the chain is not bound to the benchmark scope", async () => {
    const { database, audit, evidence, mission } = setup();
    const service = new OperationalBenchmarkService(database, evidence, audit);
    let benchmark = service.start({
      missionId: mission.id,
      note: "Require one exact scope-bound chain instead of unrelated mission-wide counts."
    }, operator, startedAt);
    for (const [index, milestone] of benchmarkMilestoneSchema.options.entries()) {
      benchmark = service.recordMilestone(benchmark.id, {
        milestone,
        note: "Retained operator checkpoint for the deliberately uncorrelated workflow."
      }, operator, new Date(startedAt.getTime() + (index + 1) * 1_000));
    }
    const missions = new MissionService(database, audit);
    missions.createScopeVersion({
      missionId: mission.id,
      startsAt: "2026-09-08T07:00:00.000Z",
      expiresAt: "2026-09-08T10:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and separately authorize this later isolated benchmark scope.",
      targets: [{ address: "1.1.1.1" }]
    }, startedAt);
    await completeWorkflow(database, audit, evidence, mission.id, startedAt);
    assert.throws(
      () => service.complete(benchmark.id, {
        operatorSteps: 12,
        policyDenials: 0,
        unsupportedClaimsRejected: 0,
        recoveryResult: "recovered",
        recoveryElapsedMs: 1_000,
        modelSuggestions: { accepted: 0, edited: 0, rejected: 0 },
        note: "Mission-wide counts cannot replace the original benchmark scope binding."
      }, operator, new Date(startedAt.getTime() + 120_000)),
      /BENCHMARK_WORKFLOW_NOT_CORRELATED/
    );
    database.close();
  });

  it("never marks persists, regressed or inconclusive correlated outcomes release-ready", async () => {
    for (const outcome of ["persists", "regressed", "inconclusive"] as const) {
      const { database, audit, evidence, mission } = setup();
      const service = new OperationalBenchmarkService(database, evidence, audit);
      let benchmark = service.start({
        missionId: mission.id,
        note: `Measure a complete correlated workflow whose outcome is ${outcome}.`
      }, operator, startedAt);
      for (const [index, milestone] of benchmarkMilestoneSchema.options.entries()) {
        benchmark = service.recordMilestone(benchmark.id, {
          milestone,
          note: `Retained operator checkpoint for the explicit ${outcome} outcome.`
        }, operator, new Date(startedAt.getTime() + (index + 1) * 1_000));
      }
      await completeWorkflow(database, audit, evidence, mission.id, startedAt, outcome);
      benchmark = service.complete(benchmark.id, {
        operatorSteps: 12,
        policyDenials: 0,
        unsupportedClaimsRejected: 0,
        recoveryResult: "recovered",
        recoveryElapsedMs: 1_000,
        modelSuggestions: { accepted: 0, edited: 0, rejected: 0 },
        note: `The ${outcome} workflow completed, but the release gate must remain closed.`
      }, operator, new Date(startedAt.getTime() + 120_000));
      const result = benchmark.result as {
        releaseReady: boolean;
        releaseGate: { recoveryPassed: boolean; retestOutcomeAccepted: boolean };
        correlatedWorkflow: { retestOutcome: string };
      };
      assert.equal(result.correlatedWorkflow.retestOutcome, outcome);
      assert.deepEqual(result.releaseGate, { recoveryPassed: true, retestOutcomeAccepted: false });
      assert.equal(result.releaseReady, false);
      assert.equal(audit.verify().valid, true);
      database.close();
    }
  });

  it("requires the latest scope to be active and exactly authorized", () => {
    {
      const { database, audit, evidence, mission } = setup();
      database.prepare(
        `INSERT INTO scope_versions(id, mission_id, version, starts_at, expires_at, policy_version, created_at)
         VALUES (?, ?, 2, ?, ?, 'policy-v1', ?)`
      ).run(
        randomUUID(),
        mission.id,
        "2026-09-08T06:00:00.000Z",
        "2026-09-08T07:59:59.999Z",
        "2026-09-08T07:00:00.000Z"
      );
      const service = new OperationalBenchmarkService(database, evidence, audit);
      assert.throws(
        () => service.start({ missionId: mission.id, note: "Reject the expired latest scope authority." }, operator, startedAt),
        /BENCHMARK_SCOPE_NOT_ACTIVE/
      );
      assert.equal(
        (database.prepare("SELECT COUNT(*) AS count FROM operational_benchmarks").get() as { count: number }).count,
        0
      );
      database.close();
    }

    {
      const { database, audit, evidence, mission } = setup();
      database.prepare(
        `INSERT INTO scope_versions(id, mission_id, version, starts_at, expires_at, policy_version, created_at)
         VALUES (?, ?, 2, ?, ?, 'policy-v1', ?)`
      ).run(
        randomUUID(),
        mission.id,
        "2026-09-08T07:30:00.000Z",
        "2026-09-08T09:30:00.000Z",
        "2026-09-08T07:30:00.000Z"
      );
      const service = new OperationalBenchmarkService(database, evidence, audit);
      assert.throws(
        () => service.start({ missionId: mission.id, note: "Reject authority inherited from an older scope." }, operator, startedAt),
        /BENCHMARK_AUTHORIZATION_REQUIRED/
      );
      assert.equal(
        (database.prepare("SELECT COUNT(*) AS count FROM operational_benchmark_scope_bindings").get() as { count: number }).count,
        0
      );
      database.close();
    }
  });

  it("does not complete from a closed-loop workflow recorded before the timer", async () => {
    const { database, audit, evidence, mission } = setup();
    await completeWorkflow(database, audit, evidence, mission.id, startedAt);
    const benchmarkStartedAt = new Date("2026-09-08T09:00:00.000Z");
    const service = new OperationalBenchmarkService(database, evidence, audit);
    let benchmark = service.start({
      missionId: mission.id,
      note: "Measure only workflow evidence created inside this timer window."
    }, operator, benchmarkStartedAt);
    for (const [index, milestone] of benchmarkMilestoneSchema.options.entries()) {
      benchmark = service.recordMilestone(benchmark.id, {
        milestone,
        note: "Retained checkpoint cannot substitute for pre-window workflow data."
      }, operator, new Date(benchmarkStartedAt.getTime() + (index + 1) * 1_000));
    }
    assert.throws(
      () => service.complete(benchmark.id, {
        operatorSteps: 12,
        policyDenials: 0,
        unsupportedClaimsRejected: 0,
        recoveryResult: "recovered",
        recoveryElapsedMs: 1_000,
        modelSuggestions: { accepted: 0, edited: 0, rejected: 0 },
        note: "Historical records must not satisfy this benchmark result."
      }, operator, new Date(benchmarkStartedAt.getTime() + 60_000)),
      /BENCHMARK_WORKFLOW_INCOMPLETE/
    );
    database.close();
  });
});
