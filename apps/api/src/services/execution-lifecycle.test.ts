import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { ExecutionLifecycleService } from "./execution-lifecycle-service.js";

const createdAt = new Date("2026-07-17T10:00:00.000Z");
const startedAt = new Date("2026-07-17T10:00:01.000Z");
const runningAt = new Date("2026-07-17T10:00:02.000Z");
const finishedAt = new Date("2026-07-17T10:00:03.000Z");
const binarySha256 = "a".repeat(64);
const configSha256 = "b".repeat(64);

describe("execution lifecycle", () => {
  it("persists immutable bindings and legal transitions without raw output", () => {
    const database = openDatabase();
    const audit = new AuditService(database);
    const lifecycles = new ExecutionLifecycleService(database, audit);
    const created = lifecycles.create(
      {
        capabilityId: "mcpwn.version.v1",
        operator: "Ian",
        binarySha256,
        configSha256
      },
      createdAt
    );

    assert.equal(created.status, "queued");
    assert.equal(created.binarySha256, binarySha256);
    assert.equal(lifecycles.transition(created.id, "starting", { now: startedAt }).status, "starting");
    assert.equal(lifecycles.transition(created.id, "running", { now: runningAt }).startedAt, runningAt.toISOString());
    const completed = lifecycles.transition(created.id, "succeeded", { now: finishedAt });
    assert.equal(completed.status, "succeeded");
    assert.equal(completed.finishedAt, finishedAt.toISOString());
    assert.deepEqual(lifecycles.summary(), { total: 1, nonterminal: 0, orphaned: 0 });
    assert.equal(lifecycles.list()[0]?.id, created.id);

    assert.throws(
      () => database.prepare("UPDATE execution_lifecycles SET operator = 'other' WHERE id = ?").run(created.id),
      /EXECUTION_BINDING_IMMUTABLE/
    );
    assert.throws(
      () => database.prepare("UPDATE execution_lifecycles SET status = 'running' WHERE id = ?").run(created.id),
      /EXECUTION_STATUS_TRANSITION_INVALID/
    );
    assert.throws(
      () => database.prepare("UPDATE execution_lifecycle_transitions SET reason_code = 'TAMPERED' WHERE execution_id = ?").run(created.id),
      /EXECUTION_TRANSITION_HISTORY_IMMUTABLE/
    );
    const stored = database.prepare("SELECT * FROM execution_lifecycles WHERE id = ?").get(created.id) as Record<
      string,
      unknown
    >;
    assert.equal("output" in stored, false);
    assert.equal("secret" in stored, false);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects illegal transitions and unsafe reason codes", () => {
    const database = openDatabase();
    const lifecycles = new ExecutionLifecycleService(database);
    const created = lifecycles.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);

    assert.throws(
      () => lifecycles.transition(created.id, "succeeded", { now: finishedAt }),
      /EXECUTION_TRANSITION_INVALID:queued:succeeded/
    );
    assert.throws(
      () => lifecycles.transition(created.id, "cancel_requested", { reasonCode: "raw secret text", now: finishedAt }),
      /EXECUTION_REASON_CODE_INVALID/
    );
    assert.equal(lifecycles.get(created.id).status, "queued");
    database.close();
  });

  it("supports cancellation and failure terminal paths", () => {
    const database = openDatabase();
    const lifecycles = new ExecutionLifecycleService(database);
    const cancellation = lifecycles.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);
    lifecycles.transition(cancellation.id, "cancel_requested", {
      reasonCode: "OPERATOR_CANCELLED",
      now: startedAt
    });
    assert.equal(
      lifecycles.transition(cancellation.id, "cancelled", {
        reasonCode: "PROCESS_TERMINATED",
        now: finishedAt
      }).status,
      "cancelled"
    );

    const failure = lifecycles.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);
    lifecycles.transition(failure.id, "starting", { now: startedAt });
    const failed = lifecycles.transition(failure.id, "failed", {
      reasonCode: "EXECUTOR_FAILED",
      now: finishedAt
    });
    assert.equal(failed.failureCode, "EXECUTOR_FAILED");
    assert.equal(failed.finishedAt, finishedAt.toISOString());
    database.close();
  });

  it("marks every persisted nonterminal execution orphaned on startup recovery", () => {
    const database = openDatabase();
    const audit = new AuditService(database);
    const firstProcess = new ExecutionLifecycleService(database, audit);
    const queued = firstProcess.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);
    const running = firstProcess.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);
    firstProcess.transition(running.id, "starting", { now: startedAt });
    firstProcess.transition(running.id, "running", { now: runningAt });
    const completed = firstProcess.create({ capabilityId: "mcpwn.version.v1", operator: "Ian" }, createdAt);
    firstProcess.transition(completed.id, "starting", { now: startedAt });
    firstProcess.transition(completed.id, "running", { now: runningAt });
    firstProcess.transition(completed.id, "succeeded", { now: finishedAt });

    const restartedProcess = new ExecutionLifecycleService(database, audit);
    const reconciled = restartedProcess.reconcileStartup(new Date("2026-07-17T10:01:00.000Z"));
    assert.deepEqual(
      reconciled.map((record) => [record.id, record.status]).sort(),
      [
        [queued.id, "orphaned"],
        [running.id, "orphaned"]
      ].sort()
    );
    assert.equal(restartedProcess.get(completed.id).status, "succeeded");
    assert.equal(restartedProcess.reconcileStartup().length, 0);
    assert.equal(audit.verify().valid, true);

    const orphanEvents = database
      .prepare("SELECT payload_json FROM audit_events WHERE event_type = 'execution.lifecycle.orphaned'")
      .all() as Array<{ payload_json: string }>;
    assert.equal(orphanEvents.length, 2);
    assert.ok(orphanEvents.every((event) => !event.payload_json.includes("pid")));
    database.close();
  });
});
