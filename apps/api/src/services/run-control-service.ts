import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { AuditService } from "./audit-service.js";

export interface RunBudget {
  wallTimeMsLimit: number;
  toolTimeMsLimit: number;
  modelTokensLimit: number;
  outputBytesLimit: number;
  requestCountLimit: number;
}

export interface UsageDelta {
  wallTimeMs?: number;
  toolTimeMs?: number;
  modelTokens?: number;
  outputBytes?: number;
  requestCount?: number;
}

export interface UsageTotal {
  wallTimeMs: number;
  toolTimeMs: number;
  modelTokens: number;
  outputBytes: number;
  requestCount: number;
}

interface StopRow {
  state: "ready" | "stop_requested" | "phase1_halted" | "draining" | "stopped" | "stop_incomplete";
  requested_at: string | null;
  requested_by: string | null;
  reason: string | null;
  updated_at: string;
}

const stopTransitions: Record<StopRow["state"], StopRow["state"][]> = {
  ready: ["stop_requested"],
  stop_requested: ["phase1_halted", "stop_incomplete"],
  phase1_halted: ["draining", "stopped", "stop_incomplete"],
  draining: ["stopped", "stop_incomplete"],
  stopped: ["ready"],
  stop_incomplete: ["stopped", "ready"]
};

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`BUDGET_INVALID:${name}`);
  return value;
}

function nonNegativeInteger(value: number | undefined, name: string): number {
  const normalized = value ?? 0;
  if (!Number.isSafeInteger(normalized) || normalized < 0) throw new Error(`USAGE_INVALID:${name}`);
  return normalized;
}

export class RunControlService {
  private readonly audit: AuditService;

  constructor(private readonly database: DatabaseSync, audit?: AuditService) {
    this.audit = audit ?? new AuditService(database);
  }

  getStopState(): StopRow {
    return this.database.prepare("SELECT state, requested_at, requested_by, reason, updated_at FROM emergency_stop_state WHERE id = 1").get() as unknown as StopRow;
  }

  assertReady(): void {
    if (this.getStopState().state !== "ready") throw new Error("EMERGENCY_STOP_ACTIVE");
  }

  requestStop(operator: string, reason: string, now = new Date()): StopRow {
    if (this.getStopState().state !== "ready") throw new Error("STOP_ALREADY_ACTIVE");
    if (operator.trim().length < 2 || reason.trim().length < 5) throw new Error("STOP_REQUEST_INVALID");
    const timestamp = now.toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `UPDATE emergency_stop_state
           SET state = 'stop_requested', requested_at = ?, requested_by = ?, reason = ?, updated_at = ?
           WHERE id = 1 AND state = 'ready'`
        )
        .run(timestamp, operator.trim(), reason.trim(), timestamp);
      this.database
        .prepare(
          `UPDATE runs SET status = 'stop_requested', updated_at = ?
           WHERE status IN ('queued', 'awaiting_approval', 'armed', 'running')`
        )
        .run(timestamp);
      this.database
        .prepare(
          `UPDATE approval_requests
           SET status = 'revoked', decided_at = ?, decided_by = ?, decision_note = ?
           WHERE status IN ('pending', 'approved')`
        )
        .run(timestamp, operator.trim(), `Emergency stop: ${reason.trim()}`);
      this.database.prepare("UPDATE safety_epochs SET epoch = epoch + 1 WHERE id = 1").run();
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    this.audit.append("emergency_stop.requested", { operator: operator.trim(), reason: reason.trim() }, now);
    return this.getStopState();
  }

  transitionStop(nextState: StopRow["state"], operator: string, now = new Date()): StopRow {
    const current = this.getStopState();
    if (!stopTransitions[current.state].includes(nextState)) throw new Error("STOP_TRANSITION_INVALID");
    if (nextState === "ready" && operator.trim().length < 2) throw new Error("OPERATOR_INVALID");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare("UPDATE emergency_stop_state SET state = ?, updated_at = ? WHERE id = 1 AND state = ?")
        .run(nextState, now.toISOString(), current.state);
      if (nextState === "ready") {
        this.database.prepare("UPDATE safety_epochs SET epoch = epoch + 1 WHERE id = 1").run();
        this.database.prepare(
          `UPDATE approval_requests SET status = 'revoked', decided_at = ?, decided_by = ?,
             decision_note = 'Safety reset invalidated pre-reset approval'
           WHERE status IN ('pending', 'approved')`
        ).run(now.toISOString(), operator.trim());
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    this.audit.append("emergency_stop.transitioned", { from: current.state, to: nextState, operator: operator.trim() }, now);
    return this.getStopState();
  }

  createRun(input: {
    missionId: string;
    budget: RunBudget;
    parentRunId?: string;
    lineageType?: "original" | "replay" | "retest";
    now?: Date;
  }): string {
    this.assertReady();
    const mission = this.database.prepare("SELECT status FROM missions WHERE id = ?").get(input.missionId) as
      | { status: string }
      | undefined;
    if (!mission || !["scope_validated", "ready", "active"].includes(mission.status)) throw new Error("MISSION_NOT_RUNNABLE");
    const lineageType = input.lineageType ?? "original";
    if (lineageType === "original" && input.parentRunId) throw new Error("RUN_LINEAGE_INVALID");
    if (lineageType !== "original" && !input.parentRunId) throw new Error("RUN_PARENT_REQUIRED");
    if (input.parentRunId) {
      const parent = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(input.parentRunId) as
        | { mission_id: string }
        | undefined;
      if (!parent || parent.mission_id !== input.missionId) throw new Error("RUN_PARENT_INVALID");
    }

    const budget = {
      wallTimeMsLimit: positiveInteger(input.budget.wallTimeMsLimit, "wallTimeMsLimit"),
      toolTimeMsLimit: positiveInteger(input.budget.toolTimeMsLimit, "toolTimeMsLimit"),
      modelTokensLimit: positiveInteger(input.budget.modelTokensLimit, "modelTokensLimit"),
      outputBytesLimit: positiveInteger(input.budget.outputBytesLimit, "outputBytesLimit"),
      requestCountLimit: positiveInteger(input.budget.requestCountLimit, "requestCountLimit")
    };
    const id = randomUUID();
    const now = input.now ?? new Date();
    const timestamp = now.toISOString();
    const scope = this.database
      .prepare("SELECT id, starts_at, expires_at FROM scope_versions WHERE mission_id = ? ORDER BY version DESC LIMIT 1")
      .get(input.missionId) as { id: string; starts_at: string; expires_at: string } | undefined;
    if (!scope) throw new Error("RUN_SCOPE_NOT_FOUND");
    if (now < new Date(scope.starts_at) || now >= new Date(scope.expires_at)) throw new Error("RUN_SCOPE_NOT_ACTIVE");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO runs(id, mission_id, parent_run_id, lineage_type, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'queued', ?, ?)`
        )
        .run(id, input.missionId, input.parentRunId ?? null, lineageType, timestamp, timestamp);
      this.database
        .prepare(
          `INSERT INTO run_budgets(
             run_id, wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit, output_bytes_limit, request_count_limit
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          budget.wallTimeMsLimit,
          budget.toolTimeMsLimit,
          budget.modelTokensLimit,
          budget.outputBytesLimit,
          budget.requestCountLimit
        );
      this.database
        .prepare("INSERT INTO run_scope_bindings(run_id, scope_version_id, bound_at) VALUES (?, ?, ?)")
        .run(id, scope.id, timestamp);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    this.audit.append("run.created", { runId: id, missionId: input.missionId, lineageType, parentRunId: input.parentRunId ?? null }, now);
    return id;
  }

  getUsage(runId: string): UsageTotal {
    const row = this.database
      .prepare(
        `SELECT
           COALESCE(SUM(wall_time_ms), 0) AS wallTimeMs,
           COALESCE(SUM(tool_time_ms), 0) AS toolTimeMs,
           COALESCE(SUM(model_tokens), 0) AS modelTokens,
           COALESCE(SUM(output_bytes), 0) AS outputBytes,
           COALESCE(SUM(request_count), 0) AS requestCount
         FROM usage_ledger WHERE run_id = ?`
      )
      .get(runId) as unknown as UsageTotal;
    return row;
  }

  recordUsage(runId: string, delta: UsageDelta, reason: string, now = new Date()): UsageTotal {
    const budget = this.database.prepare("SELECT * FROM run_budgets WHERE run_id = ?").get(runId) as
      | Record<string, number>
      | undefined;
    if (!budget) throw new Error("RUN_BUDGET_NOT_FOUND");
    const normalized = {
      wallTimeMs: nonNegativeInteger(delta.wallTimeMs, "wallTimeMs"),
      toolTimeMs: nonNegativeInteger(delta.toolTimeMs, "toolTimeMs"),
      modelTokens: nonNegativeInteger(delta.modelTokens, "modelTokens"),
      outputBytes: nonNegativeInteger(delta.outputBytes, "outputBytes"),
      requestCount: nonNegativeInteger(delta.requestCount, "requestCount")
    };
    const current = this.getUsage(runId);
    const next: UsageTotal = {
      wallTimeMs: current.wallTimeMs + normalized.wallTimeMs,
      toolTimeMs: current.toolTimeMs + normalized.toolTimeMs,
      modelTokens: current.modelTokens + normalized.modelTokens,
      outputBytes: current.outputBytes + normalized.outputBytes,
      requestCount: current.requestCount + normalized.requestCount
    };
    const checks: Array<[keyof UsageTotal, string]> = [
      ["wallTimeMs", "wall_time_ms_limit"],
      ["toolTimeMs", "tool_time_ms_limit"],
      ["modelTokens", "model_tokens_limit"],
      ["outputBytes", "output_bytes_limit"],
      ["requestCount", "request_count_limit"]
    ];
    const exceeded = checks.find(([usageKey, budgetKey]) => next[usageKey] > Number(budget[budgetKey]));
    if (exceeded) {
      this.audit.append("budget.exceeded", { runId, dimension: exceeded[0], attempted: next[exceeded[0]] }, now);
      throw new Error(`BUDGET_EXCEEDED:${exceeded[0]}`);
    }
    this.database
      .prepare(
        `INSERT INTO usage_ledger(
           id, run_id, wall_time_ms, tool_time_ms, model_tokens, output_bytes, request_count, recorded_at, reason
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        randomUUID(),
        runId,
        normalized.wallTimeMs,
        normalized.toolTimeMs,
        normalized.modelTokens,
        normalized.outputBytes,
        normalized.requestCount,
        now.toISOString(),
        reason.trim() || "unspecified"
      );
    this.audit.append("usage.recorded", { runId, delta: normalized, total: next }, now);
    return next;
  }
}
