import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { ApprovalService } from "./approval-service.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { ExecutionLifecycleService } from "./execution-lifecycle-service.js";
import { MissionService } from "./mission-service.js";
import type { TargetIsolationVerifier } from "./redmi-isolation-service.js";
import { RunControlService } from "./run-control-service.js";
import {
  executorOperatorId,
  TargetExecutionService,
  type TargetExecutorFactory
} from "./target-execution-service.js";

function isolationVerifier(onVerify?: () => void): TargetIsolationVerifier {
  return {
    verify: async () => {
      onVerify?.();
      return {
        verificationId: "redmi:retest-attestation",
        targetAddress: "192.168.42.129",
        sourceAddress: "192.168.42.42",
        interfaceName: "eth5",
        networkName: "war-room-redmi-isolated",
        bridgeName: "wr15-redmi",
        imageId: "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3",
        verifiedAt: new Date().toISOString()
      };
    }
  };
}

function setup(
  startsAt: Date,
  expiresAt: Date,
  isolation: TargetIsolationVerifier,
  createExecutor?: TargetExecutorFactory,
  isolationTimeoutMs?: number
) {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Controlled Redmi retest");
  missions.createScopeVersion({
    missionId: mission.id,
    startsAt: startsAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    policyVersion: "policy-v1",
    authorizationStatement: "I own and authorize this exact isolated Redmi retest target.",
    targets: [{ address: "192.168.42.129", isolatedPrivateTargetApproved: true }]
  });
  const approvals = new ApprovalService(database, audit);
  const controls = new RunControlService(database, audit);
  const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-retest-")), audit);
  const lifecycles = new ExecutionLifecycleService(database, audit);
  const service = new TargetExecutionService(
    database,
    isolation,
    controls,
    approvals,
    evidence,
    lifecycles,
    audit,
    createExecutor,
    isolationTimeoutMs
  );
  return { database, audit, mission, approvals, controls, lifecycles, service };
}

describe("controlled target retests", () => {
  it("binds readable operator names to stable executor-safe identities", () => {
    assert.equal(
      executorOperatorId("Owner-authorized Vega"),
      executorOperatorId(" Owner-authorized Vega ")
    );
    assert.match(executorOperatorId("Owner-authorized Vega"), /^operator:[a-f0-9]{32}$/);
  });

  it("creates no run or approval when isolation verification times out", async () => {
    const clock = new Date();
    const isolation: TargetIsolationVerifier = {
      verify: async () => await new Promise<never>(() => undefined)
    };
    const { database, mission, service } = setup(
      new Date(clock.valueOf() - 60_000),
      new Date(clock.valueOf() + 60 * 60_000),
      isolation,
      undefined,
      10
    );

    await assert.rejects(
      service.requestApproval(
        { missionId: mission.id, ports: [53], intensity: 1 },
        "operator"
      ),
      /ISOLATION_VERIFICATION_TIMED_OUT/
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM runs").get() as { count: number }).count,
      0
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM approval_requests").get() as { count: number }).count,
      0
    );
  });

  it("reuses exact capability parameters while creating fresh approval and retest lineage", async () => {
    const clock = new Date();
    const { database, audit, mission, approvals, service } = setup(
      new Date(clock.valueOf() - 60_000),
      new Date(clock.valueOf() + 60 * 60_000),
      isolationVerifier()
    );
    const original = await service.requestApproval(
      { missionId: mission.id, ports: [443, 53], intensity: 2 },
      "operator"
    );
    approvals.approve(original.approval.id, "operator", "Original exact action reviewed");
    approvals.consumeForExecution({ approvalId: original.approval.id, proposal: original.proposal });
    database
      .prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ?")
      .run(new Date().toISOString(), original.proposal.runId);

    const retest = await service.requestRetestApproval(original.proposal.runId, "operator");
    assert.equal(retest.approval.status, "pending");
    assert.equal(retest.proposal.capabilityId, original.proposal.capabilityId);
    assert.deepEqual(retest.proposal.parameters, original.proposal.parameters);
    assert.notEqual(retest.proposal.runId, original.proposal.runId);
    const lineage = database
      .prepare("SELECT parent_run_id, lineage_type, status FROM runs WHERE id = ?")
      .get(retest.proposal.runId) as { parent_run_id: string; lineage_type: string; status: string };
    assert.equal(lineage.parent_run_id, original.proposal.runId);
    assert.equal(lineage.lineage_type, "retest");
    assert.equal(lineage.status, "awaiting_approval");
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("fails before isolation verification when the latest authorization has expired", async () => {
    let isolationChecks = 0;
    const clock = new Date();
    const { database, mission, service } = setup(
      new Date(clock.valueOf() - 2 * 60 * 60_000),
      new Date(clock.valueOf() - 60 * 60_000),
      isolationVerifier(() => {
        isolationChecks += 1;
      })
    );
    await assert.rejects(
      () => service.requestApproval({ missionId: mission.id, ports: [53], intensity: 1 }, "operator"),
      /RUN_SCOPE_NOT_ACTIVE/
    );
    assert.equal(isolationChecks, 0);
    database.close();
  });

  it("fails closed when emergency stop races a successful target process", async () => {
    const clock = new Date();
    const harness: { controls?: RunControlService } = {};
    const createExecutor: TargetExecutorFactory = () => ({
      execute: async () => {
        harness.controls!.requestStop(
          "audit operator",
          "Audit emergency-stop completion race",
          clock
        );
        return {
          stdout: "completed before abort delivery",
          stderr: "",
          outputBytes: 31,
          durationMs: 10,
          exitCode: 0,
          invocation: {
            executable: String.raw`C:\Windows\System32\wsl.exe`,
            args: [],
            spawnOptions: { shell: false, windowsHide: true },
            timeoutMs: 15_000,
            maxStdoutBytes: 262_144,
            maxStderrBytes: 32_768,
            imageReference:
              "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3",
            isolationVerificationId: "redmi:retest-attestation",
            containerName: "war-room-audit-race",
            distro: "kali-linux"
          }
        };
      }
    });
    const fixture = setup(
      new Date(clock.valueOf() - 60_000),
      new Date(clock.valueOf() + 60 * 60_000),
      isolationVerifier(),
      createExecutor
    );
    harness.controls = fixture.controls;
    const prepared = await fixture.service.requestApproval(
      { missionId: fixture.mission.id, ports: [53], intensity: 1 },
      "audit operator"
    );
    fixture.approvals.approve(
      prepared.approval.id,
      "audit operator",
      "Exact audit race action reviewed"
    );

    await assert.rejects(
      () => fixture.service.execute(prepared.approval.id, "audit operator"),
      /Restricted target execution completed during emergency stop/
    );
    const run = fixture.database
      .prepare("SELECT status FROM runs WHERE id = ?")
      .get(prepared.proposal.runId) as { status: string };
    assert.equal(run.status, "stop_requested");
    const lifecycle = fixture.database
      .prepare(
        "SELECT status FROM execution_lifecycles WHERE run_id = ? ORDER BY created_at DESC LIMIT 1"
      )
      .get(prepared.proposal.runId) as { status: string };
    assert.equal(lifecycle.status, "cancelled");
    assert.equal(
      (
        fixture.database
          .prepare("SELECT COUNT(*) AS count FROM artifacts")
          .get() as { count: number }
      ).count,
      0
    );
    assert.equal(fixture.audit.verify().valid, true);
    fixture.database.close();
  });
});
