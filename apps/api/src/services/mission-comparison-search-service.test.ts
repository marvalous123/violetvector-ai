import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { getCapabilitySchemaHash } from "@war-room/policy";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { openDatabase } from "../db/database.js";
import { ApprovalService } from "./approval-service.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { ExecutionLifecycleService } from "./execution-lifecycle-service.js";
import { FindingService } from "./finding-service.js";
import { MissionComparisonSearchService } from "./mission-comparison-search-service.js";
import { MissionService } from "./mission-service.js";
import { RemediationService } from "./remediation-service.js";
import { TestPlanService } from "./test-plan-service.js";

const now = new Date("2026-07-19T15:00:00.000Z");

function at(minutes: number): Date {
  return new Date(now.getTime() + minutes * 60_000);
}

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-comparison-")), audit);
  const findings = new FindingService(database, evidence, audit);
  const remediation = new RemediationService(database, evidence, audit);
  const plans = new TestPlanService(database, evidence, audit);
  const service = new MissionComparisonSearchService(database, evidence, remediation);
  const mission = missions.createMission("Original and retest comparison lab", now);
  return { database, audit, missions, evidence, findings, remediation, plans, service, mission };
}

function insertRunPair(
  database: ReturnType<typeof openDatabase>,
  missionId: string,
  retestStatus: "awaiting_approval" | "succeeded" = "succeeded"
) {
  const targetId = randomUUID();
  const scopeVersionId = randomUUID();
  const originalRunId = randomUUID();
  const retestRunId = randomUUID();
  const canonicalAddress = `192.168.42.${Math.floor(Math.random() * 100) + 1}`;
  const toolSchemaHash = getCapabilitySchemaHash("network.service-version");
  let retestProposalId = "";
  database
    .prepare(
      `INSERT INTO targets(id, canonical_address, address_family, classification)
       VALUES (?, ?, 'ipv4', 'private')`
    )
    .run(targetId, canonicalAddress);
  database
    .prepare(
      `INSERT INTO scope_versions(id, mission_id, version, starts_at, expires_at, policy_version, created_at)
       VALUES (?, ?, 1, ?, ?, 'policy-v1', ?)`
    )
    .run(scopeVersionId, missionId, now.toISOString(), at(30).toISOString(), now.toISOString());
  database
    .prepare(
      "INSERT INTO scope_targets(scope_version_id, target_id, isolated_private_target_approved) VALUES (?, ?, 1)"
    )
    .run(scopeVersionId, targetId);
  for (const [runId, parentRunId, lineageType, status] of [
    [originalRunId, null, "original", "succeeded"],
    [retestRunId, originalRunId, "retest", retestStatus]
  ] as const) {
    database
      .prepare(
        `INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(runId, missionId, parentRunId, lineageType, status, now.toISOString(), now.toISOString());
    database
      .prepare("INSERT INTO run_scope_bindings(run_id, scope_version_id, bound_at) VALUES (?, ?, ?)")
      .run(runId, scopeVersionId, now.toISOString());
    database
      .prepare(
        `INSERT INTO run_budgets(
           run_id, wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit,
           output_bytes_limit, request_count_limit
         ) VALUES (?, 15000, 15000, 1000, 262144, 1)`
      )
      .run(runId);
    const proposalId = randomUUID();
    if (lineageType === "retest") retestProposalId = proposalId;
    const proposal = {
      proposalId,
      missionId,
      runId,
      targetId,
      capabilityId: "network.service-version",
      riskTier: "T1",
      timeoutMs: 15_000,
      maxOutputBytes: 262_144,
      parameters: { ports: [443], transport: "tcp", intensity: 1 }
    };
    const proposalJson = stableJson(proposal);
    database
      .prepare(
        `INSERT INTO proposals(
           id, mission_id, run_id, target_id, capability_id, risk_tier,
           proposal_json, proposal_hash, policy_version, tool_schema_hash, created_at
         ) VALUES (?, ?, ?, ?, ?, 'T1', ?, ?, 'policy-v1', ?, ?)`
      )
      .run(
        proposalId,
        missionId,
        runId,
        targetId,
        "network.service-version",
        proposalJson,
        canonicalHash(proposal),
        toolSchemaHash,
        now.toISOString()
      );
  }
  return { canonicalAddress, originalRunId, retestRunId, retestProposalId, scopeVersionId, targetId, toolSchemaHash };
}

describe("evidence-backed original and retest comparison", () => {
  it("uses run lineage, hashes and an explicit reviewed remediation outcome without absence inference", () => {
    const { database, audit, evidence, findings, remediation, service, mission } = setup();
    const {
      canonicalAddress,
      originalRunId,
      retestRunId,
      retestProposalId,
      scopeVersionId,
      targetId,
      toolSchemaHash
    } = insertRunPair(
      database,
      mission.id,
      "awaiting_approval"
    );
    const originalEvidence = evidence.seal("original observed service", "application/json", {
      missionId: mission.id,
      runId: originalRunId,
      capturedAt: at(1),
      provenance: { sourceType: "comparison-original" }
    });
    const findingId = findings.createCandidate(
      mission.id,
      "Reviewed service configuration observation",
      {
        severity: "medium",
        description: "The original run produced a reviewed observation requiring a controlled remediation retest.",
        remediation: "Apply the reviewed isolated-lab correction and retain exact retest evidence.",
        confidence: "high",
        evidenceArtifactIds: [originalEvidence.id]
      },
      at(4)
    );
    findings.accept(findingId, "finding reviewer", at(5));
    let record = remediation.create(
      findingId,
      { owner: "lab owner", dueDate: "2026-08-01", priority: "high" },
      "engagement lead",
      at(6)
    );
    record = remediation.changeStatus(record.id, { status: "in-progress" }, "lab owner", at(7));
    record = remediation.captureOperatorFixEvidence(
      record.id,
      {
        changeType: "device-configuration",
        actionPerformedAt: at(8).toISOString(),
        actionSummary: "The reviewed isolated-lab service configuration was changed before the controlled retest.",
        observedState: "The operator observed the intended corrected configuration and retained this bounded record."
      },
      "lab owner",
      at(8)
    ).remediation;
    record = remediation.changeStatus(record.id, { status: "fix-ready" }, "lab owner", at(9));
    const requestId = remediation.requestRetest(
      record.id,
      { reason: "Compare the fresh bounded retest evidence with the original reviewed observation." },
      "engagement lead",
      at(10)
    );
    const approvalId = randomUUID();
    const retestProposal = database
      .prepare(
        `SELECT proposal_hash, policy_version, tool_schema_hash
         FROM proposals WHERE id = ? AND run_id = ?`
      )
      .get(retestProposalId, retestRunId) as {
        proposal_hash: string;
        policy_version: string;
        tool_schema_hash: string;
      };
    database
      .prepare(
        `INSERT INTO approval_requests(
           id, proposal_id, proposal_hash, policy_version, tool_schema_hash, status, requested_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
      )
      .run(
        approvalId,
        retestProposalId,
        retestProposal.proposal_hash,
        retestProposal.policy_version,
        retestProposal.tool_schema_hash,
        at(10).toISOString(),
        at(20).toISOString()
      );
    database
      .prepare("INSERT INTO approval_scope_bindings(approval_id, scope_version_id) VALUES (?, ?)")
      .run(approvalId, scopeVersionId);
    database
      .prepare(
        `INSERT INTO approval_execution_bindings(
           approval_id, run_id, mission_id, scope_version_id, target_id, canonical_target,
           authorization_starts_at, authorization_expires_at, capability_schema_hash, safety_epoch,
           wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit, output_bytes_limit, request_count_limit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 15000, 15000, 1000, 262144, 1)`
      )
      .run(
        approvalId,
        retestRunId,
        mission.id,
        scopeVersionId,
        targetId,
        canonicalAddress,
        now.toISOString(),
        at(30).toISOString(),
        toolSchemaHash
      );
    remediation.bindDirectRetest(
      record.id,
      {
        requestId,
        parentRunId: originalRunId,
        retestRunId,
        approvalId,
        proposalId: retestProposalId
      },
      "engagement lead",
      at(10)
    );
    const approvals = new ApprovalService(database, audit);
    const lifecycles = new ExecutionLifecycleService(database, audit);
    let lifecycle = lifecycles.create(
      {
        capabilityId: "mcpwn.nmap.service-version.v1",
        operator: "security reviewer",
        missionId: mission.id,
        runId: retestRunId
      },
      at(11)
    );
    lifecycle = lifecycles.transition(lifecycle.id, "starting", { now: at(11) });
    approvals.approve(approvalId, "security reviewer", "Reviewed exact comparison retest bounds", at(11));
    const retestProposalBody = JSON.parse(
      (database.prepare("SELECT proposal_json FROM proposals WHERE id = ?").get(retestProposalId) as { proposal_json: string })
        .proposal_json
    );
    approvals.consumeForExecution({ approvalId, proposal: retestProposalBody, now: at(11) });
    lifecycle = lifecycles.transition(lifecycle.id, "running", { now: at(11) });
    const retestEvidence = evidence.seal("retest observed service", "application/json", {
      missionId: mission.id,
      runId: retestRunId,
      sourceEventId: lifecycle.id,
      capturedAt: at(11),
      provenance: {
        sourceType: "restricted-target-execution",
        executionId: lifecycle.id,
        approvalId
      }
    });
    database
      .prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ?")
      .run(at(11).toISOString(), retestRunId);
    lifecycles.transition(lifecycle.id, "succeeded", { now: at(11) });
    remediation.recordRetestOutcome(
      record.id,
      {
        requestId,
        outcome: "persists",
        summary: "The reviewed retest evidence supports that the scoped observation still persists.",
        reviewer: "security reviewer",
        evidenceArtifactIds: [retestEvidence.id]
      },
      "security reviewer",
      at(12)
    );

    const comparison = service.compare({
      missionId: mission.id,
      originalRunId,
      retestRunId
    });
    assert.equal(comparison.configurationEquivalent, true);
    assert.equal(comparison.original.proposalIntegrityValid, true);
    assert.equal(comparison.retest.proposalIntegrityValid, true);
    assert.deepEqual(comparison.evidenceHashComparison.shared, []);
    assert.deepEqual(comparison.evidenceHashComparison.originalOnly, [originalEvidence.sha256]);
    assert.deepEqual(comparison.evidenceHashComparison.retestOnly, [retestEvidence.sha256]);
    assert.equal(comparison.findings.length, 1);
    assert.equal(comparison.findings[0]?.findingId, findingId);
    assert.equal(comparison.findings[0]?.originalEvidencePresent, true);
    assert.equal(comparison.findings[0]?.retestEvidencePresent, false);
    assert.equal(comparison.findings[0]?.assessment, "explicit-persists");
    assert.equal(comparison.findings[0]?.explicitOutcome, "persists");
    assert.deepEqual(comparison.findings[0]?.supportingRetestArtifactIds, [retestEvidence.id]);
    assert.match(comparison.claimLimitation, /missing finding.*does not establish/i);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("labels an original-only finding not assessed and rejects non-retest or cross-mission pairs", () => {
    const { database, missions, evidence, findings, service, mission } = setup();
    const { originalRunId, retestRunId } = insertRunPair(database, mission.id);
    const originalEvidence = evidence.seal("original-only proof", "text/plain", {
      missionId: mission.id,
      runId: originalRunId,
      capturedAt: at(1),
      provenance: { sourceType: "comparison-original-only" }
    });
    const findingId = findings.createCandidate(
      mission.id,
      "Original-only reviewed observation",
      {
        severity: "low",
        description: "The original run has evidence but no reviewed remediation outcome is recorded.",
        remediation: "Do not infer remediation; perform and review a separately evidenced retest.",
        confidence: "medium",
        evidenceArtifactIds: [originalEvidence.id]
      },
      at(2)
    );
    findings.accept(findingId, "finding reviewer", at(3));
    const comparison = service.compare({ missionId: mission.id, originalRunId, retestRunId });
    assert.equal(comparison.findings[0]?.assessment, "original-only-not-assessed");
    assert.equal(comparison.findings[0]?.explicitOutcome, null);

    const unrelatedRunId = randomUUID();
    database
      .prepare(
        `INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at)
         VALUES (?, ?, NULL, 'original', 'succeeded', ?, ?)`
      )
      .run(unrelatedRunId, mission.id, now.toISOString(), now.toISOString());
    assert.throws(
      () => service.compare({ missionId: mission.id, originalRunId, retestRunId: unrelatedRunId }),
      /COMPARISON_RETEST_LINEAGE_INVALID/
    );
    const otherMission = missions.createMission("Separate comparison mission", now);
    assert.throws(
      () => service.compare({ missionId: otherMission.id, originalRunId, retestRunId }),
      /COMPARISON_RUN_MISSION_MISMATCH/
    );
    database.close();
  });
});

describe("bounded mission search", () => {
  it("searches selected workflow records without crossing mission boundaries or treating wildcards as syntax", () => {
    const { database, missions, evidence, findings, plans, service, mission } = setup();
    const keyword = "collector-delta";
    plans.createVersion({
      missionId: mission.id,
      title: `Validation plan ${keyword}`,
      objective: `Record why ${keyword} coverage is blocked until its prerequisite exists.`,
      procedures: [
        {
          key: keyword,
          title: `Review ${keyword} readiness`,
          objective: `Verify whether ${keyword} has the required approved telemetry source.`,
          steps: ["Review the endpoint registry and record the prerequisite state."],
          state: "blocked",
          rationale: "The collector prerequisite is absent, so no live coverage claim is supported.",
          blueRuleId: "BR-EVASION-001"
        }
      ],
      createdBy: "engagement lead"
    });
    const findingEvidence = evidence.seal("search finding proof", "text/plain", {
      missionId: mission.id,
      capturedAt: at(1),
      provenance: { sourceType: "search-test" }
    });
    findings.createCandidate(
      mission.id,
      `Finding for ${keyword}`,
      {
        severity: "info",
        description: `This evidence-backed finding mentions ${keyword} for bounded mission search.`,
        remediation: "Review the workflow record and retain the same-mission evidence citation.",
        confidence: "high",
        evidenceArtifactIds: [findingEvidence.id]
      },
      at(2)
    );

    const otherMission = missions.createMission("Separate search mission", now);
    plans.createVersion({
      missionId: otherMission.id,
      title: `Other plan ${keyword}`,
      objective: `This ${keyword} record belongs to another mission and must never appear.`,
      procedures: [
        {
          key: keyword,
          title: `Other ${keyword} procedure`,
          objective: "Keep this procedure isolated to the separate mission boundary.",
          steps: ["Retain this record only inside its own mission."],
          state: "not-applicable",
          rationale: "This separate mission exists only to verify tenant-style mission isolation.",
          capabilityId: "planning.note"
        }
      ],
      createdBy: "engagement lead"
    });

    const result = service.search({
      missionId: mission.id,
      query: keyword,
      kinds: ["test-plan", "procedure", "finding"],
      limit: 2
    });
    assert.equal(result.returned, 2);
    assert.equal(result.truncated, true);
    assert.equal(result.results.every((item) => !item.title.startsWith("Other")), true);
    assert.equal(result.results.every((item) => item.kind !== "evidence"), true);
    const wildcard = service.search({
      missionId: mission.id,
      query: "%_",
      kinds: ["test-plan", "procedure", "finding"],
      limit: 10
    });
    assert.equal(wildcard.returned, 0);
    assert.throws(
      () =>
        service.search({
          missionId: mission.id,
          query: keyword,
          limit: 51
        }),
      /Number must be less than or equal to 50/
    );
    database.close();
  });
});
