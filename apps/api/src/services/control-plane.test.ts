import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { ActionProposal } from "@war-room/policy";
import { openDatabase } from "../db/database.js";
import { ApprovalService } from "./approval-service.js";
import { AuditService } from "./audit-service.js";
import { MissionService } from "./mission-service.js";
import { RunControlService } from "./run-control-service.js";

const now = new Date("2026-07-16T22:00:00.000Z");

function createAuthorizedScope() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Owned isolated training target", now);
  const scope = missions.createScopeVersion(
    {
      missionId: mission.id,
      startsAt: "2026-07-16T21:00:00.000Z",
      expiresAt: "2026-07-16T23:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and explicitly authorize this isolated training target.",
      targets: [{ address: "8.8.8.8" }]
    },
    now
  );
  return { database, audit, missions, mission, scope };
}

const budget = {
  wallTimeMsLimit: 60_000,
  toolTimeMsLimit: 30_000,
  modelTokensLimit: 1_000,
  outputBytesLimit: 64_000,
  requestCountLimit: 10
};

function createApprovalContext() {
  const context = createAuthorizedScope();
  const controls = new RunControlService(context.database, context.audit);
  const runId = controls.createRun({ missionId: context.mission.id, budget, now });
  const proposal: ActionProposal = {
    proposalId: "proposal-1",
    missionId: context.mission.id,
    runId,
    targetId: context.scope.targets[0]!.id,
    capabilityId: "network.discovery",
    riskTier: "T1",
    parameters: { profile: "version-only" },
    timeoutMs: 5_000,
    maxOutputBytes: 32_768
  };
  return { ...context, controls, runId, proposal };
}

describe("mission and scope service", () => {
  it("creates a versioned exact scope and authorization record", () => {
    const { database, audit, mission, scope } = createAuthorizedScope();
    assert.equal(scope.missionId, mission.id);
    assert.equal(scope.targets.length, 1);
    assert.equal(scope.targets[0]?.address, "8.8.8.8");
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM authorization_records").get() as { count: number }).count,
      1
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects duplicate canonical targets and weak authorization", () => {
    const database = openDatabase();
    const missions = new MissionService(database);
    const mission = missions.createMission("Duplicate target test", now);
    const base = {
      missionId: mission.id,
      startsAt: "2026-07-16T21:00:00.000Z",
      expiresAt: "2026-07-16T23:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize the isolated target for testing."
    };
    assert.throws(
      () => missions.createScopeVersion({ ...base, targets: [{ address: "8.8.8.8" }, { address: "8.8.8.8" }] }, now),
      /DUPLICATE_TARGET/
    );
    assert.throws(
      () => missions.createScopeVersion({ ...base, authorizationStatement: "yes", targets: [{ address: "8.8.4.4" }] }, now),
      /AUTHORIZATION_STATEMENT_REQUIRED/
    );
    database.close();
  });

  it("requires private isolation and denies Tailscale scope at creation", () => {
    const database = openDatabase();
    const missions = new MissionService(database);
    const mission = missions.createMission("Private isolated target", now);
    const scope = missions.createScopeVersion(
      {
        missionId: mission.id,
        startsAt: "2026-07-16T21:00:00.000Z",
        expiresAt: "2026-07-16T23:00:00.000Z",
        policyVersion: "policy-v1",
        authorizationStatement: "I own and authorize this isolated private lab target.",
        targets: [{ address: "192.168.50.7", isolatedPrivateTargetApproved: true }]
      },
      now
    );
    assert.equal(scope.targets[0]?.isolatedPrivateTargetApproved, true);
    const secondMission = missions.createMission("Unsafe private target", now);
    const unsafeBase = {
      missionId: secondMission.id,
      startsAt: "2026-07-16T21:00:00.000Z",
      expiresAt: "2026-07-16T23:00:00.000Z",
      policyVersion: "policy-v1",
      authorizationStatement: "I own and authorize this target for an isolated test."
    };
    assert.throws(
      () => missions.createScopeVersion({ ...unsafeBase, targets: [{ address: "192.168.50.8" }] }, now),
      /PRIVATE_TARGET_ISOLATION_REQUIRED/
    );
    assert.throws(
      () => missions.createScopeVersion({ ...unsafeBase, targets: [{ address: "100.64.0.1", isolatedPrivateTargetApproved: true }] }, now),
      /TARGET_CLASS_DENIED/
    );
    database.close();
  });
});

describe("parameter-bound approvals", () => {
  it("approves and consumes exactly once", () => {
    const { database, audit, proposal, runId } = createApprovalContext();
    const approvals = new ApprovalService(database, audit);
    const request = approvals.request({ proposal, now });
    assert.equal(request.status, "pending");
    assert.equal(approvals.approve(request.id, "operator", "Exact action reviewed", now).status, "approved");
    assert.equal(approvals.consumeForExecution({ approvalId: request.id, proposal, now }).status, "consumed");
    assert.equal(
      (database.prepare("SELECT status FROM runs WHERE id = ?").get(runId) as { status: string }).status,
      "running"
    );
    assert.throws(
      () => approvals.consume({ approvalId: request.id, proposal, now }),
      /APPROVAL_NOT_APPROVED/
    );
    const consumedEvent = database.prepare(
      "SELECT payload_json FROM audit_events WHERE event_type = 'approval.consumed' ORDER BY sequence DESC LIMIT 1"
    ).get() as { payload_json: string };
    const payload = JSON.parse(consumedEvent.payload_json) as Record<string, unknown>;
    assert.deepEqual(
      {
        approvalId: payload.approvalId,
        proposalId: payload.proposalId,
        runId: payload.runId,
        missionId: payload.missionId,
        targetId: payload.targetId,
        capabilityId: payload.capabilityId,
        runStatus: payload.runStatus
      },
      {
        approvalId: request.id,
        proposalId: proposal.proposalId,
        runId: proposal.runId,
        missionId: proposal.missionId,
        targetId: proposal.targetId,
        capabilityId: proposal.capabilityId,
        runStatus: "running"
      }
    );
    assert.match(String(payload.proposalHash), /^[a-f0-9]{64}$/);
    assert.match(String(payload.capabilitySchemaHash), /^[a-f0-9]{64}$/);
    assert.equal((payload.budget as { reservedForExecution: { requestCount: number } }).reservedForExecution.requestCount, 1);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects proposal drift and derives the capability schema identity backend-side", () => {
    const { database, proposal } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const request = approvals.request({ proposal: { ...proposal, proposalId: "proposal-drift" }, now });
    approvals.approve(request.id, "operator", "reviewed", now);
    assert.throws(
      () =>
        approvals.consume({
          approvalId: request.id,
          proposal: { ...proposal, proposalId: "proposal-drift", timeoutMs: 5_001 },
          now
        }),
      /APPROVAL_BINDING_MISMATCH/
    );
    const stored = database.prepare("SELECT tool_schema_hash FROM approval_requests WHERE id = ?").get(request.id) as {
      tool_schema_hash: string;
    };
    assert.match(stored.tool_schema_hash, /^[a-f0-9]{64}$/);
    database.close();
  });

  it("rejects an approval after scope changes or emergency stop activates", () => {
    const { database, mission, missions, proposal, controls } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const request = approvals.request({ proposal: { ...proposal, proposalId: "proposal-scope-binding" }, now });
    approvals.approve(request.id, "operator", "reviewed", now);
    missions.createScopeVersion(
      {
        missionId: mission.id,
        startsAt: "2026-07-16T21:00:00.000Z",
        expiresAt: "2026-07-16T23:00:00.000Z",
        policyVersion: "policy-v1",
        authorizationStatement: "I own and authorize the replacement isolated target.",
        targets: [{ address: "8.8.4.4" }]
      },
      now
    );
    assert.equal(approvals.get(request.id).status, "revoked");
    assert.throws(() => approvals.consume({
      approvalId: request.id, proposal: { ...proposal, proposalId: "proposal-scope-binding" }, now
    }), /APPROVAL_NOT_APPROVED/);
    assert.throws(() => approvals.request({ proposal: { ...proposal, proposalId: "stale-run" }, now }), /APPROVAL_RUN_SCOPE_STALE|APPROVAL_RUN_NOT_LIVE/);

    const latestScope = missions.getLatestScope(mission.id);
    const freshRunId = controls.createRun({ missionId: mission.id, budget, now });
    const replacement: ActionProposal = {
      ...proposal, proposalId: "proposal-stop-binding", runId: freshRunId, targetId: latestScope.targets[0]!.id
    };
    const stoppedRequest = approvals.request({ proposal: replacement, now });
    approvals.approve(stoppedRequest.id, "operator", "reviewed", now);
    controls.requestStop("operator", "Revoke all live approvals", now);
    assert.equal(approvals.get(stoppedRequest.id).status, "revoked");
    controls.transitionStop("phase1_halted", "operator", now);
    controls.transitionStop("stopped", "operator", now);
    controls.transitionStop("ready", "operator", now);
    assert.throws(() => approvals.consume({ approvalId: stoppedRequest.id, proposal: replacement, now }), /APPROVAL_NOT_APPROVED/);
    database.close();
  });

  it("expires without approval, refuses T0, and enforces run budgets", () => {
    const { database, proposal } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const base = { ...proposal, proposalId: "proposal-expiry" };
    const request = approvals.request({ proposal: base, ttlMs: 1_000, now });
    assert.throws(() => approvals.approve(request.id, "operator", "", new Date(now.valueOf() + 2_000)), /APPROVAL_EXPIRED/);
    assert.throws(
      () =>
        approvals.request({
          proposal: {
            ...base, proposalId: "t0", capabilityId: "planning.note",
            riskTier: "T0", parameters: { note: "advisory only" }
          },
          now
        }),
      /APPROVAL_NOT_AVAILABLE/
    );
    assert.throws(
      () => approvals.request({
        proposal: { ...base, proposalId: "over-budget", maxOutputBytes: 64_001 }, now
      }),
      /APPROVAL_RUN_OUTPUT_BUDGET_INSUFFICIENT/
    );
    database.close();
  });

  it("rejects missing run bindings and detects budget mutation before approval", () => {
    const { database, proposal, runId } = createApprovalContext();
    const approvals = new ApprovalService(database);
    assert.throws(
      () => approvals.request({ proposal: { ...proposal, proposalId: "missing-run", runId: "invented" }, now }),
      /APPROVAL_RUN_BINDING_NOT_FOUND/
    );
    const request = approvals.request({ proposal: { ...proposal, proposalId: "budget-bound" }, now });
    database.prepare("UPDATE run_budgets SET output_bytes_limit = output_bytes_limit + 1 WHERE run_id = ?").run(runId);
    assert.throws(
      () => approvals.approve(request.id, "operator", "reviewed", now),
      /APPROVAL_BUDGET_BINDING_MISMATCH/
    );
    database.close();
  });

  it("fails atomically when the run cannot transition directly into execution", () => {
    const { database, proposal, runId } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const request = approvals.request({ proposal: { ...proposal, proposalId: "transition-race" }, now });
    approvals.approve(request.id, "operator", "reviewed", now);
    database.prepare("UPDATE runs SET status = 'armed' WHERE id = ?").run(runId);

    assert.throws(
      () => approvals.consumeForExecution({
        approvalId: request.id,
        proposal: { ...proposal, proposalId: "transition-race" },
        now
      }),
      /APPROVAL_RUN_NOT_AWAITING_APPROVAL/
    );
    assert.equal(approvals.get(request.id).status, "approved");
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'approval.consumed'").get() as { count: number }).count,
      0
    );
    database.close();
  });

  it("rechecks remaining execution budgets at consumption time and rolls back cleanly", () => {
    const { database, controls, proposal, runId } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const exactProposal = { ...proposal, proposalId: "usage-changed" };
    const request = approvals.request({ proposal: exactProposal, now });
    approvals.approve(request.id, "operator", "reviewed", now);
    controls.recordUsage(runId, { wallTimeMs: 56_000, toolTimeMs: 26_000 }, "prior bounded work", now);

    assert.throws(
      () => approvals.consumeForExecution({ approvalId: request.id, proposal: exactProposal, now }),
      /APPROVAL_RUN_WALL_BUDGET_INSUFFICIENT/
    );
    assert.equal(approvals.get(request.id).status, "approved");
    assert.equal(
      (database.prepare("SELECT status FROM runs WHERE id = ?").get(runId) as { status: string }).status,
      "awaiting_approval"
    );
    database.close();
  });

  it("rejects stored policy, schema, and proposal-record drift before execution", () => {
    for (const mutation of ["policy", "schema", "proposal"] as const) {
      const { database, proposal } = createApprovalContext();
      const approvals = new ApprovalService(database);
      const exactProposal = { ...proposal, proposalId: `stored-drift-${mutation}` };
      const request = approvals.request({ proposal: exactProposal, now });
      approvals.approve(request.id, "operator", "reviewed", now);
      if (mutation === "policy") {
        database.prepare("UPDATE approval_requests SET policy_version = 'tampered' WHERE id = ?").run(request.id);
      } else if (mutation === "schema") {
        database.prepare("UPDATE approval_requests SET tool_schema_hash = ? WHERE id = ?").run("0".repeat(64), request.id);
      } else {
        database.prepare("UPDATE proposals SET proposal_json = '{}' WHERE id = ?").run(exactProposal.proposalId);
      }

      assert.throws(
        () => approvals.consumeForExecution({ approvalId: request.id, proposal: exactProposal, now }),
        /APPROVAL_POLICY_OR_SCHEMA_STALE|APPROVAL_STORED_PROPOSAL_MISMATCH/
      );
      assert.equal(approvals.get(request.id).status, "approved");
      database.close();
    }
  });

  it("rejects canonical target binding drift before execution", () => {
    const { database, proposal } = createApprovalContext();
    const approvals = new ApprovalService(database);
    const exactProposal = { ...proposal, proposalId: "target-binding-drift" };
    const request = approvals.request({ proposal: exactProposal, now });
    approvals.approve(request.id, "operator", "reviewed", now);
    database.prepare(
      "UPDATE approval_execution_bindings SET canonical_target = '8.8.4.4' WHERE approval_id = ?"
    ).run(request.id);

    assert.throws(
      () => approvals.consumeForExecution({ approvalId: request.id, proposal: exactProposal, now }),
      /APPROVAL_TARGET_BINDING_MISMATCH/
    );
    assert.equal(approvals.get(request.id).status, "approved");
    database.close();
  });
});

describe("audit chain", () => {
  it("detects a modified event", () => {
    const { database, audit } = createAuthorizedScope();
    assert.equal(audit.verify().valid, true);
    assert.throws(
      () => database.prepare("UPDATE audit_events SET payload_json = ? WHERE sequence = 1").run('{"tampered":true}'),
      /AUDIT_EVENT_IMMUTABLE/
    );
    database.exec("DROP TRIGGER audit_events_immutable_update");
    database.prepare("UPDATE audit_events SET payload_json = ? WHERE sequence = 1").run('{"tampered":true}');
    assert.equal(audit.status().valid, true, "constant-time status must not rescan request-time history");
    const verification = audit.verify();
    assert.equal(verification.valid, false);
    assert.equal(verification.brokenAtSequence, 1);
    assert.deepEqual(audit.status(), verification);
    database.close();
  });

  it("rejects an empty audit history when application state remains", () => {
    const { database } = createAuthorizedScope();
    database.exec("DROP TRIGGER audit_events_immutable_delete");
    database.exec("DELETE FROM audit_events");
    const audit = new AuditService(database);
    assert.deepEqual(audit.verify(), { valid: false, eventsChecked: 0, brokenAtSequence: 1 });
    database.close();
  });
});
