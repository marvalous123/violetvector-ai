import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { ActionProposal } from "@war-room/policy";
import { openDatabase } from "../db/database.js";
import { ApprovalService } from "./approval-service.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { ExecutionLifecycleService } from "./execution-lifecycle-service.js";
import { FindingService } from "./finding-service.js";
import { MissionService } from "./mission-service.js";
import { RemediationService } from "./remediation-service.js";
import { RunControlService } from "./run-control-service.js";

const now = new Date("2026-07-19T12:00:00.000Z");

function at(minutes: number): Date {
  return new Date(now.getTime() + minutes * 60_000);
}

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-remediation-")), audit);
  const findings = new FindingService(database, evidence, audit);
  const service = new RemediationService(database, evidence, audit);

  const mission = missions.createMission("Remediation workflow lab", now);
  const findingEvidence = evidence.seal("reviewed finding evidence", "text/plain", {
    missionId: mission.id,
    capturedAt: now,
    provenance: { sourceType: "remediation-test-finding" }
  });
  const findingId = findings.createCandidate(
    mission.id,
    "Evidence-backed training observation",
    {
      severity: "medium",
      description: "A reviewed training observation exists for remediation workflow testing.",
      remediation: "Apply the documented lab configuration correction and retain verification evidence.",
      confidence: "high",
      evidenceArtifactIds: [findingEvidence.id]
    },
    at(1)
  );
  findings.accept(findingId, "finding reviewer", at(2));

  return { database, audit, missions, evidence, findings, service, mission, findingId };
}

function sealWorkflowEvidence(
  evidence: EvidenceService,
  missionId: string,
  label: string,
  capturedAt: Date
) {
  return evidence.seal(label, "application/json", {
    missionId,
    capturedAt,
    provenance: { sourceType: "remediation-workflow-test", label }
  });
}

function makeRunBackedFinding(fixture: ReturnType<typeof setup>) {
  const scope = fixture.missions.createScopeVersion(
    {
      missionId: fixture.mission.id,
      startsAt: now.toISOString(),
      expiresAt: at(30).toISOString(),
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize this exact isolated remediation test target.",
      targets: [{ address: "192.168.42.129", isolatedPrivateTargetApproved: true }]
    },
    now
  );
  const targetId = scope.targets[0]!.id;
  const originalRunId = randomUUID();
  const originalProposalId = randomUUID();
  fixture.database
    .prepare(
      "INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at) VALUES (?, ?, NULL, 'original', 'succeeded', ?, ?)"
    )
    .run(originalRunId, fixture.mission.id, at(2).toISOString(), at(2).toISOString());
  const proposal: ActionProposal = {
    proposalId: originalProposalId,
    missionId: fixture.mission.id,
    runId: originalRunId,
    targetId,
    capabilityId: "network.service-version",
    riskTier: "T1",
    timeoutMs: 15_000,
    maxOutputBytes: 262_144,
    parameters: { ports: [53], transport: "tcp", intensity: 1 }
  };
  fixture.database
    .prepare(
      `INSERT INTO proposals(
         id, mission_id, run_id, target_id, capability_id, risk_tier, proposal_json,
         proposal_hash, policy_version, tool_schema_hash, created_at
       ) VALUES (?, ?, ?, ?, 'network.service-version', 'T1', ?, ?, 'policy-v1', ?, ?)`
    )
    .run(
      originalProposalId,
      fixture.mission.id,
      originalRunId,
      targetId,
      JSON.stringify(proposal),
      "a".repeat(64),
      "b".repeat(64),
      at(2).toISOString()
    );
  const artifact = fixture.evidence.seal("run-backed original evidence", "application/json", {
    missionId: fixture.mission.id,
    runId: originalRunId,
    capturedAt: at(2),
    provenance: { sourceType: "authorized-target-test" }
  });
  fixture.findings.addRevision(
    fixture.findingId,
    {
      severity: "low",
      description: "The authorized target run produced a bounded service observation for remediation testing.",
      remediation: "Record an operator change and complete a separately approved direct retest.",
      confidence: "high",
      evidenceArtifactIds: [artifact.id]
    },
    at(2)
  );
  fixture.findings.accept(fixture.findingId, "finding reviewer", at(2));
  return { targetId, originalRunId, originalProposalId, originalProposal: proposal, originalArtifact: artifact };
}

describe("remediation workflow", () => {
  it("keeps assignment, review, evidence, retest and regression as immutable mission-bound history", () => {
    const { database, audit, evidence, service, mission, findingId } = setup();
    const fixEvidence = sealWorkflowEvidence(evidence, mission.id, "fix-evidence", at(8));
    const firstRetestEvidence = sealWorkflowEvidence(evidence, mission.id, "first-retest", at(11));
    const regressionEvidence = sealWorkflowEvidence(evidence, mission.id, "regression-retest", at(14));

    let remediation = service.create(
      findingId,
      { owner: "endpoint engineering", dueDate: "2026-08-01", priority: "high" },
      "engagement lead",
      at(3)
    );
    remediation = service.changeOwner(remediation.id, { owner: "platform engineering" }, "engagement lead", at(4));
    remediation = service.changeDueDate(remediation.id, { dueDate: "2026-08-05" }, "engagement lead", at(5));
    remediation = service.changePriority(remediation.id, { priority: "critical" }, "engagement lead", at(6));
    remediation = service.changeStatus(remediation.id, { status: "in-progress" }, "platform engineering", at(7));
    remediation = service.addReviewerComment(
      remediation.id,
      {
        reviewer: "security reviewer",
        comment: "The proposed correction is suitable for an evidence-backed retest in the isolated lab."
      },
      "security reviewer",
      at(8)
    );
    remediation = service.recordRiskAcceptance(
      remediation.id,
      {
        reason: "The short test delay is accepted while the controlled configuration change is reviewed.",
        reviewer: "risk reviewer",
        expiresAt: "2026-08-15T12:00:00.000Z"
      },
      "risk reviewer",
      at(9)
    );
    remediation = service.addFixEvidence(
      remediation.id,
      {
        artifactIds: [fixEvidence.id],
        note: "Configuration-change evidence was captured from the same authorized mission."
      },
      "platform engineering",
      at(10)
    );
    remediation = service.changeStatus(remediation.id, { status: "fix-ready" }, "platform engineering", at(11));

    const firstRequestId = service.requestRetest(
      remediation.id,
      { reason: "Verify the reviewed correction with a separately recorded controlled retest." },
      "engagement lead",
      at(12)
    );
    remediation = service.recordRetestOutcome(
      remediation.id,
      {
        requestId: firstRequestId,
        outcome: "remediated",
        summary: "The controlled retest evidence supports the reviewed remediation outcome for this finding.",
        reviewer: "security reviewer",
        evidenceArtifactIds: [firstRetestEvidence.id]
      },
      "security reviewer",
      at(13)
    );
    remediation = service.changeStatus(remediation.id, { status: "closed" }, "engagement lead", at(14));

    const regressionRequestId = service.requestRetest(
      remediation.id,
      { reason: "Perform a later controlled regression check against the previously remediated observation." },
      "engagement lead",
      at(15)
    );
    remediation = service.recordRetestOutcome(
      remediation.id,
      {
        requestId: regressionRequestId,
        outcome: "regressed",
        summary: "The later same-mission evidence supports a reviewed regression state for the observation.",
        reviewer: "security reviewer",
        evidenceArtifactIds: [regressionEvidence.id]
      },
      "security reviewer",
      at(16)
    );

    assert.equal(remediation.missionId, mission.id);
    assert.equal(remediation.findingId, findingId);
    assert.equal(remediation.owner, "platform engineering");
    assert.equal(remediation.dueDate, "2026-08-05");
    assert.equal(remediation.priority, "critical");
    assert.equal(remediation.status, "regressed");
    assert.equal(remediation.regressionState, "regressed");
    assert.equal(remediation.riskAcceptance?.status, "active");
    assert.equal(remediation.fixEvidence[0]?.artifactId, fixEvidence.id);
    assert.equal(remediation.retests.length, 2);
    assert.equal(remediation.retests[0]?.outcome, "remediated");
    assert.equal(remediation.retests[1]?.outcome, "regressed");
    assert.equal(remediation.reviewerComments.length, 1);
    assert.equal(remediation.history.length, 14);
    assert.deepEqual(
      remediation.history.map((event) => event.sequence),
      Array.from({ length: 14 }, (_, index) => index + 1)
    );
    assert.equal(remediation.integrityValid, true);
    assert.match(remediation.claimLimitation, /finding is never changed automatically/i);
    assert.equal(service.verifyHistory(remediation.id), true);
    assert.equal(service.getForFinding(findingId, at(16)).id, remediation.id);
    assert.equal(service.list(mission.id, at(16)).length, 1);
    assert.equal(audit.verify().valid, true);

    const finding = database.prepare("SELECT status FROM findings WHERE id = ?").get(findingId) as { status: string };
    assert.equal(finding.status, "accepted");
    database.close();
  });

  it("expires and revokes reviewed risk acceptance without changing technical remediation status", () => {
    const { database, service, findingId } = setup();
    let remediation = service.create(
      findingId,
      { owner: "application owner", dueDate: "2026-08-10", priority: "medium" },
      "engagement lead",
      at(3)
    );
    remediation = service.recordRiskAcceptance(
      remediation.id,
      {
        reason: "A bounded delay is accepted while the lab owner schedules the reviewed correction.",
        reviewer: "risk reviewer",
        expiresAt: "2026-07-20T12:00:00.000Z"
      },
      "risk reviewer",
      at(4)
    );
    assert.equal(remediation.riskAcceptance?.status, "active");
    assert.equal(service.get(remediation.id, new Date("2026-07-21T12:00:00.000Z")).riskAcceptance?.status, "expired");
    assert.throws(
      () =>
        service.revokeRiskAcceptance(
          remediation.id,
          { reason: "The expired decision cannot be revoked as though it were active." },
          "risk reviewer",
          new Date("2026-07-21T12:00:00.000Z")
        ),
      /REMEDIATION_RISK_ACCEPTANCE_NOT_ACTIVE/
    );
    remediation = service.recordRiskAcceptance(
      remediation.id,
      {
        reason: "A replacement short-lived decision records the new review period and rationale.",
        reviewer: "risk reviewer",
        expiresAt: "2026-07-25T12:00:00.000Z"
      },
      "risk reviewer",
      new Date("2026-07-21T12:00:00.000Z")
    );
    remediation = service.revokeRiskAcceptance(
      remediation.id,
      { reason: "The exception is withdrawn because remediation work can now proceed." },
      "risk reviewer",
      new Date("2026-07-22T12:00:00.000Z")
    );
    assert.equal(remediation.riskAcceptance?.status, "revoked");
    assert.equal(remediation.status, "open");
    database.close();
  });

  it("rejects unaccepted findings, unknown fields, invalid outcome claims and cross-mission evidence", () => {
    const { database, missions, evidence, findings, service, mission, findingId } = setup();
    const unacceptedEvidence = sealWorkflowEvidence(evidence, mission.id, "unaccepted-finding", at(3));
    const unacceptedFindingId = findings.createCandidate(
      mission.id,
      "Unaccepted workflow observation",
      {
        severity: "low",
        description: "This candidate is intentionally left unaccepted for the remediation gate test.",
        remediation: "Review the supporting evidence before assigning remediation ownership.",
        confidence: "medium",
        evidenceArtifactIds: [unacceptedEvidence.id]
      },
      at(4)
    );
    assert.throws(
      () =>
        service.create(
          unacceptedFindingId,
          { owner: "application owner", dueDate: "2026-08-10", priority: "medium" },
          "engagement lead",
          at(5)
        ),
      /REMEDIATION_ACCEPTED_FINDING_REQUIRED/
    );
    assert.throws(
      () =>
        service.create(
          findingId,
          {
            owner: "application owner",
            dueDate: "2026-08-10",
            priority: "medium",
            script: "not-allowed"
          } as never,
          "engagement lead",
          at(5)
        ),
      /unrecognized_key/
    );

    const remediation = service.create(
      findingId,
      { owner: "application owner", dueDate: "2026-08-10", priority: "medium" },
      "engagement lead",
      at(5)
    );
    assert.throws(
      () => service.changeStatus(remediation.id, { status: "remediated" } as never, "application owner", at(6)),
      /Invalid enum value/
    );
    assert.throws(
      () =>
        service.recordRiskAcceptance(
          remediation.id,
          {
            reason: "This decision has an invalid non-expiring historical deadline and must be rejected.",
            reviewer: "risk reviewer",
            expiresAt: "2026-07-18T12:00:00.000Z"
          },
          "risk reviewer",
          at(6)
        ),
      /REMEDIATION_RISK_ACCEPTANCE_EXPIRY_INVALID/
    );

    const otherMission = missions.createMission("Other authorized mission", at(6));
    const otherEvidence = sealWorkflowEvidence(evidence, otherMission.id, "other-mission-fix", at(7));
    assert.throws(
      () =>
        service.addFixEvidence(
          remediation.id,
          {
            artifactIds: [otherEvidence.id],
            note: "This otherwise valid artifact belongs to another mission and must not be cited."
          },
          "application owner",
          at(8)
        ),
      /REMEDIATION_EVIDENCE_MISSION_MISMATCH/
    );
    assert.equal(remediation.status, "open");
    database.close();
  });

  it("requires fix evidence, a pending request and compatible evidence-backed retest outcomes", () => {
    const { database, evidence, service, mission, findingId } = setup();
    const fixEvidence = sealWorkflowEvidence(evidence, mission.id, "fix-proof", at(6));
    const retestEvidence = sealWorkflowEvidence(evidence, mission.id, "retest-proof", at(9));
    let remediation = service.create(
      findingId,
      { owner: "service owner", dueDate: "2026-08-12", priority: "high" },
      "engagement lead",
      at(3)
    );
    remediation = service.changeStatus(remediation.id, { status: "in-progress" }, "service owner", at(4));
    remediation = service.changeStatus(remediation.id, { status: "fix-ready" }, "service owner", at(5));
    assert.throws(
      () =>
        service.requestRetest(
          remediation.id,
          { reason: "A retest cannot proceed until fix evidence is attached to the workflow." },
          "engagement lead",
          at(6)
        ),
      /REMEDIATION_FIX_EVIDENCE_REQUIRED/
    );
    remediation = service.changeStatus(remediation.id, { status: "in-progress" }, "service owner", at(6));
    remediation = service.addFixEvidence(
      remediation.id,
      {
        artifactIds: [fixEvidence.id],
        note: "The same-mission change record is attached before requesting verification."
      },
      "service owner",
      at(7)
    );
    remediation = service.changeStatus(remediation.id, { status: "fix-ready" }, "service owner", at(8));
    const requestId = service.requestRetest(
      remediation.id,
      { reason: "Verify whether the accepted observation persists after the documented correction." },
      "engagement lead",
      at(9)
    );
    assert.throws(
      () =>
        service.recordRetestOutcome(
          remediation.id,
          {
            requestId,
            outcome: "regressed",
            summary: "A first remediation retest cannot be labelled as a regression without a prior remediated baseline.",
            reviewer: "security reviewer",
            evidenceArtifactIds: [retestEvidence.id]
          },
          "security reviewer",
          at(10)
        ),
      /REMEDIATION_RETEST_OUTCOME_INVALID/
    );
    remediation = service.recordRetestOutcome(
      remediation.id,
      {
        requestId,
        outcome: "persists",
        summary: "The controlled retest evidence shows that the accepted observation still persists.",
        reviewer: "security reviewer",
        evidenceArtifactIds: [retestEvidence.id]
      },
      "security reviewer",
      at(10)
    );
    assert.equal(remediation.status, "persists");
    assert.equal(remediation.regressionState, "not-assessed");
    assert.equal(remediation.retests[0]?.evidence[0]?.artifactId, retestEvidence.id);
    assert.throws(
      () =>
        service.recordRetestOutcome(
          remediation.id,
          {
            requestId,
            outcome: "remediated",
            summary: "The resolved request cannot receive a second contradictory outcome.",
            reviewer: "security reviewer",
            evidenceArtifactIds: [retestEvidence.id]
          },
          "security reviewer",
          at(11)
        ),
      /REMEDIATION_RETEST_ALREADY_RESOLVED/
    );
    database.close();
  });

  it("captures a post-remediation operator fix record and rejects original evidence reuse", () => {
    const fixture = setup();
    const runBacked = makeRunBackedFinding(fixture);
    let remediation = fixture.service.create(
      fixture.findingId,
      { owner: "device owner", dueDate: "2026-08-20", priority: "low" },
      "engagement lead",
      at(3)
    );
    remediation = fixture.service.changeStatus(remediation.id, { status: "in-progress" }, "device owner", at(4));
    assert.throws(
      () =>
        fixture.service.captureOperatorFixEvidence(
          remediation.id,
          {
            changeType: "operational-mitigation",
            actionPerformedAt: at(2).toISOString(),
            actionSummary: "The mitigation predates this remediation record and cannot be claimed as new fix work.",
            observedState: "The operator observed the earlier isolated lab configuration only."
          },
          "device owner",
          at(4)
        ),
      /REMEDIATION_FIX_ACTION_TIME_INVALID/
    );
    assert.throws(
      () =>
        fixture.service.addFixEvidence(
          remediation.id,
          {
            artifactIds: [runBacked.originalArtifact.id],
            note: "The original target observation cannot be relabelled as evidence of a later fix."
          },
          "device owner",
          at(4)
        ),
      /REMEDIATION_FIX_EVIDENCE_REUSES_FINDING/
    );
    const capture = fixture.service.captureOperatorFixEvidence(
      remediation.id,
      {
        changeType: "operational-mitigation",
        actionPerformedAt: at(4).toISOString(),
        actionSummary: "USB tethering was disabled outside attended isolated testing and the exact-target firewall was retained.",
        observedState: "The operator reviewed the device setting and recorded the intended disabled-by-default state."
      },
      "device owner",
      at(4)
    );
    remediation = capture.remediation;
    assert.notEqual(capture.artifact.id, runBacked.originalArtifact.id);
    assert.equal(remediation.fixEvidence[0]?.artifactId, capture.artifact.id);
    const observation = fixture.evidence.observationForMission(capture.artifact.id, fixture.mission.id);
    const provenance = JSON.parse(observation.provenance_json) as { source: Record<string, unknown> };
    assert.equal(observation.captured_at, at(4).toISOString());
    assert.equal(provenance.source.sourceType, "operator-remediation-fix");
    assert.equal(provenance.source.remediationId, remediation.id);
    assert.equal(provenance.source.findingId, fixture.findingId);
    assert.match(fixture.evidence.read(capture.artifact.id).toString("utf8"), /separately approved direct retest/i);
    assert.equal(fixture.audit.verify().valid, true);
    fixture.database.close();
  });

  it("binds a pending direct retest and accepts only its succeeded run evidence", () => {
    const fixture = setup();
    const original = makeRunBackedFinding(fixture);
    let remediation = fixture.service.create(
      fixture.findingId,
      { owner: "device owner", dueDate: "2026-08-20", priority: "low" },
      "engagement lead",
      at(3)
    );
    remediation = fixture.service.changeStatus(remediation.id, { status: "in-progress" }, "device owner", at(4));
    remediation = fixture.service.captureOperatorFixEvidence(
      remediation.id,
      {
        changeType: "device-configuration",
        actionPerformedAt: at(4).toISOString(),
        actionSummary: "The reviewed device configuration was changed before the controlled verification run.",
        observedState: "The operator observed the intended configuration state and retained this bounded record."
      },
      "device owner",
      at(4)
    ).remediation;
    remediation = fixture.service.changeStatus(remediation.id, { status: "fix-ready" }, "device owner", at(5));
    const requestId = fixture.service.requestRetest(
      remediation.id,
      { reason: "Verify the recorded change using the same exact target and parameters under a fresh approval." },
      "engagement lead",
      at(6)
    );

    const controls = new RunControlService(fixture.database, fixture.audit);
    const approvals = new ApprovalService(fixture.database, fixture.audit);
    const retestRunId = controls.createRun({
      missionId: fixture.mission.id,
      parentRunId: original.originalRunId,
      lineageType: "retest",
      budget: {
        wallTimeMsLimit: 30_000,
        toolTimeMsLimit: 30_000,
        modelTokensLimit: 1,
        outputBytesLimit: 262_144,
        requestCountLimit: 1
      },
      now: at(7)
    });
    const retestProposalId = randomUUID();
    const retestProposal = {
      ...original.originalProposal,
      proposalId: retestProposalId,
      runId: retestRunId
    };
    const approval = approvals.request({ proposal: retestProposal, ttlMs: 10 * 60_000, now: at(7) });
    assert.throws(
      () =>
        fixture.service.bindDirectRetest(
          remediation.id,
          {
            requestId,
            parentRunId: original.originalRunId,
            retestRunId,
            approvalId: approval.id,
            proposalId: retestProposalId
          },
          "engagement lead",
          at(18)
        ),
      /APPROVAL_NOT_FRESH/
    );
    const binding = fixture.service.bindDirectRetest(
      remediation.id,
      {
        requestId,
        parentRunId: original.originalRunId,
        retestRunId,
        approvalId: approval.id,
        proposalId: retestProposalId
      },
      "engagement lead",
      at(7)
    );
    assert.equal(binding.retestRunId, retestRunId);
    assert.equal(fixture.service.get(remediation.id, at(7)).retests[0]?.directRetest?.approvalId, approval.id);
    assert.throws(
      () => fixture.database.prepare("UPDATE remediation_direct_retest_bindings SET bound_by = ? WHERE request_id = ?").run("other", requestId),
      /REMEDIATION_DIRECT_RETEST_BINDING_IMMUTABLE/
    );

    const unrelated = sealWorkflowEvidence(fixture.evidence, fixture.mission.id, "unrelated same-mission evidence", at(8));
    assert.throws(
      () =>
        fixture.service.recordRetestOutcome(
          remediation.id,
          {
            requestId,
            outcome: "remediated",
            summary: "An awaiting-approval run and unrelated artifact cannot support a remediation outcome.",
            reviewer: "security reviewer",
            evidenceArtifactIds: [unrelated.id]
          },
          "security reviewer",
          at(8)
        ),
      /REMEDIATION_DIRECT_RETEST_RUN_INVALID/
    );
    fixture.database.prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ?").run(at(9).toISOString(), retestRunId);
    assert.throws(
      () =>
        fixture.service.recordRetestOutcome(
          remediation.id,
          {
            requestId,
            outcome: "remediated",
            summary: "A same-mission artifact not produced by the bound direct retest must be rejected.",
            reviewer: "security reviewer",
            evidenceArtifactIds: [unrelated.id]
          },
          "security reviewer",
          at(10)
        ),
      /REMEDIATION_DIRECT_RETEST_RUN_INVALID/
    );
    fixture.database.prepare("UPDATE runs SET status = 'awaiting_approval', updated_at = ? WHERE id = ?").run(at(9).toISOString(), retestRunId);
    const lifecycle = new ExecutionLifecycleService(fixture.database, fixture.audit).create(
      {
        capabilityId: "mcpwn.nmap.service-version.v1",
        operator: "security reviewer",
        missionId: fixture.mission.id,
        runId: retestRunId
      },
      at(9)
    );
    const lifecycles = new ExecutionLifecycleService(fixture.database, fixture.audit);
    lifecycles.transition(lifecycle.id, "starting", { now: at(9) });
    approvals.approve(approval.id, "security reviewer", "Reviewed exact direct retest bounds", at(9));
    approvals.consumeForExecution({ approvalId: approval.id, proposal: retestProposal, now: at(9) });
    lifecycles.transition(lifecycle.id, "running", { now: at(9) });
    const executedArtifact = fixture.evidence.seal("consumed direct retest evidence", "application/json", {
      missionId: fixture.mission.id,
      runId: retestRunId,
      sourceEventId: lifecycle.id,
      capturedAt: at(9),
      provenance: {
        sourceType: "restricted-target-execution",
        executionId: lifecycle.id,
        approvalId: approval.id
      }
    });
    fixture.database.prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ? AND status = 'running'").run(at(9).toISOString(), retestRunId);
    lifecycles.transition(lifecycle.id, "succeeded", { now: at(9) });
    remediation = fixture.service.recordRetestOutcome(
      remediation.id,
      {
        requestId,
        outcome: "remediated",
        summary: "The bound direct retest artifact supports the reviewed remediation outcome for this observation.",
        reviewer: "security reviewer",
        evidenceArtifactIds: [executedArtifact.id]
      },
      "security reviewer",
      at(10)
    );
    assert.equal(remediation.status, "remediated");
    assert.equal(remediation.retests[0]?.evidence[0]?.artifactId, executedArtifact.id);
    assert.equal(remediation.retests[0]?.directRetest?.parentRunId, original.originalRunId);
    assert.equal(fixture.audit.verify().valid, true);
    fixture.database.close();
  });

  it("revokes and fails an unbound direct-retest preparation as one audited compensation", () => {
    const fixture = setup();
    const original = makeRunBackedFinding(fixture);
    const remediation = fixture.service.create(
      fixture.findingId,
      { owner: "device owner", dueDate: "2026-08-20", priority: "low" },
      "engagement lead",
      at(3)
    );
    const controls = new RunControlService(fixture.database, fixture.audit);
    const approvals = new ApprovalService(fixture.database, fixture.audit);
    const retestRunId = controls.createRun({
      missionId: fixture.mission.id,
      parentRunId: original.originalRunId,
      lineageType: "retest",
      budget: {
        wallTimeMsLimit: 30_000,
        toolTimeMsLimit: 30_000,
        modelTokensLimit: 1,
        outputBytesLimit: 262_144,
        requestCountLimit: 1
      },
      now: at(7)
    });
    const proposalId = randomUUID();
    const proposal = {
      ...original.originalProposal,
      proposalId,
      runId: retestRunId
    };
    const approval = approvals.request({ proposal, ttlMs: 10 * 60_000, now: at(7) });
    fixture.service.abandonDirectRetestPreparation(
      remediation.id,
      {
        requestId: randomUUID(),
        parentRunId: original.originalRunId,
        retestRunId,
        approvalId: approval.id,
        proposalId
      },
      "engagement lead",
      at(8)
    );

    assert.equal(approvals.get(approval.id).status, "revoked");
    assert.equal(
      (fixture.database.prepare("SELECT status FROM runs WHERE id = ?").get(retestRunId) as { status: string }).status,
      "failed"
    );
    assert.equal(
      (
        fixture.database
          .prepare("SELECT COUNT(*) AS count FROM remediation_direct_retest_bindings WHERE retest_run_id = ?")
          .get(retestRunId) as { count: number }
      ).count,
      0
    );
    assert.throws(
      () => approvals.approve(approval.id, "security reviewer", "Must remain non-executable", at(8)),
      /APPROVAL_NOT_PENDING/
    );
    assert.equal(
      (
        fixture.database
          .prepare("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'remediation.direct-retest-preparation-abandoned'")
          .get() as { count: number }
      ).count,
      1
    );
    assert.equal(fixture.audit.verify().valid, true);
    fixture.database.close();
  });

  it("enforces immutable rows and detects history tampering", () => {
    const { database, audit, evidence, service, mission, findingId } = setup();
    const fixEvidence = sealWorkflowEvidence(evidence, mission.id, "immutable-fix-proof", at(5));
    let remediation = service.create(
      findingId,
      { owner: "system owner", dueDate: "2026-08-20", priority: "low" },
      "engagement lead",
      at(3)
    );
    remediation = service.changeStatus(remediation.id, { status: "in-progress" }, "system owner", at(4));
    remediation = service.addFixEvidence(
      remediation.id,
      {
        artifactIds: [fixEvidence.id],
        note: "The immutable evidence-link path is exercised by this same-mission artifact."
      },
      "system owner",
      at(5)
    );
    const event = database
      .prepare("SELECT id FROM remediation_events WHERE remediation_id = ? ORDER BY sequence LIMIT 1")
      .get(remediation.id) as { id: string };
    assert.throws(
      () => database.prepare("UPDATE remediation_records SET mission_id = ? WHERE id = ?").run(mission.id, remediation.id),
      /REMEDIATION_RECORD_IMMUTABLE/
    );
    assert.throws(
      () => database.prepare("UPDATE remediation_events SET actor = ? WHERE id = ?").run("tampered actor", event.id),
      /REMEDIATION_EVENT_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("DELETE FROM remediation_evidence_links WHERE remediation_event_id = ?")
          .run(remediation.fixEvidence[0]!.eventId),
      /REMEDIATION_EVIDENCE_LINK_IMMUTABLE/
    );
    assert.equal(audit.verify().valid, true);

    database.exec("DROP TRIGGER remediation_events_immutable_update");
    database
      .prepare("UPDATE remediation_events SET payload_json = ? WHERE id = ?")
      .run('{"owner":"tampered"}', event.id);
    assert.equal(service.verifyHistory(remediation.id), false);
    assert.throws(() => service.get(remediation.id, at(6)), /REMEDIATION_HISTORY_INVALID|ZodError/);
    database.close();
  });
});
