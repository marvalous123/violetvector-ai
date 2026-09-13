import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { AuditService } from "./audit-service.js";

export type ExecutionLifecycleStatus =
  | "queued"
  | "starting"
  | "running"
  | "succeeded"
  | "failed"
  | "cancel_requested"
  | "cancelled"
  | "timed_out"
  | "orphaned";

export interface ExecutionLifecycleRecord {
  id: string;
  missionId: string | null;
  runId: string | null;
  capabilityId: string;
  operator: string;
  binarySha256: string | null;
  configSha256: string | null;
  status: ExecutionLifecycleStatus;
  failureCode: string | null;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface ExecutionLifecycleSummary {
  total: number;
  nonterminal: number;
  orphaned: number;
}

interface ExecutionLifecycleRow {
  id: string;
  mission_id: string | null;
  run_id: string | null;
  capability_id: string;
  operator: string;
  binary_sha256: string | null;
  config_sha256: string | null;
  status: ExecutionLifecycleStatus;
  failure_code: string | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

const terminalStates = new Set<ExecutionLifecycleStatus>([
  "succeeded",
  "failed",
  "cancelled",
  "timed_out",
  "orphaned"
]);

const legalTransitions: Record<ExecutionLifecycleStatus, readonly ExecutionLifecycleStatus[]> = {
  queued: ["starting", "cancel_requested"],
  starting: ["running", "failed", "cancel_requested", "timed_out"],
  running: ["succeeded", "failed", "cancel_requested", "timed_out"],
  cancel_requested: ["cancelled", "failed", "timed_out"],
  succeeded: [],
  failed: [],
  cancelled: [],
  timed_out: [],
  orphaned: []
};

function normalizeIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(normalized)) {
    throw new Error(`EXECUTION_BINDING_INVALID:${field}`);
  }
  return normalized;
}

function normalizeOperator(value: string): string {
  const normalized = value.trim();
  const hasControlCharacter = [...normalized].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
  if (normalized.length < 2 || normalized.length > 128 || hasControlCharacter) {
    throw new Error("EXECUTION_BINDING_INVALID:operator");
  }
  return normalized;
}

function normalizeHash(value: string | undefined, field: string): string | null {
  if (value === undefined) return null;
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(`EXECUTION_BINDING_INVALID:${field}`);
  return normalized;
}

function normalizeReasonCode(value: string | undefined): string | null {
  if (value === undefined) return null;
  const normalized = value.trim();
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(normalized)) throw new Error("EXECUTION_REASON_CODE_INVALID");
  return normalized;
}

function toRecord(row: ExecutionLifecycleRow): ExecutionLifecycleRecord {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    capabilityId: row.capability_id,
    operator: row.operator,
    binarySha256: row.binary_sha256,
    configSha256: row.config_sha256,
    status: row.status,
    failureCode: row.failure_code,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at
  };
}

export class ExecutionLifecycleService {
  private readonly audit: AuditService;

  constructor(private readonly database: DatabaseSync, audit?: AuditService) {
    this.audit = audit ?? new AuditService(database);
  }

  create(
    input: {
      capabilityId: string;
      operator: string;
      missionId?: string;
      runId?: string;
      binarySha256?: string;
      configSha256?: string;
    },
    now = new Date()
  ): ExecutionLifecycleRecord {
    const id = randomUUID();
    const timestamp = now.toISOString();
    const binding = {
      capabilityId: normalizeIdentifier(input.capabilityId, "capabilityId"),
      operator: normalizeOperator(input.operator),
      missionId: input.missionId === undefined ? null : normalizeIdentifier(input.missionId, "missionId"),
      runId: input.runId === undefined ? null : normalizeIdentifier(input.runId, "runId"),
      binarySha256: normalizeHash(input.binarySha256, "binarySha256"),
      configSha256: normalizeHash(input.configSha256, "configSha256")
    };

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO execution_lifecycles(
             id, mission_id, run_id, capability_id, operator, binary_sha256, config_sha256,
             status, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`
        )
        .run(
          id,
          binding.missionId,
          binding.runId,
          binding.capabilityId,
          binding.operator,
          binding.binarySha256,
          binding.configSha256,
          timestamp,
          timestamp
        );
      this.database
        .prepare(
          `INSERT INTO execution_lifecycle_transitions(
             execution_id, from_status, to_status, occurred_at, reason_code
           ) VALUES (?, NULL, 'queued', ?, NULL)`
        )
        .run(id, timestamp);
      this.audit.append(
        "execution.lifecycle.created",
        {
          executionId: id,
          capabilityId: binding.capabilityId,
          operator: binding.operator,
          missionId: binding.missionId,
          runId: binding.runId,
          binarySha256: binding.binarySha256,
          configSha256: binding.configSha256,
          status: "queued"
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(id);
  }

  get(executionId: string): ExecutionLifecycleRecord {
    const row = this.database
      .prepare("SELECT * FROM execution_lifecycles WHERE id = ?")
      .get(executionId) as unknown as ExecutionLifecycleRow | undefined;
    if (!row) throw new Error("EXECUTION_LIFECYCLE_NOT_FOUND");
    return toRecord(row);
  }

  list(limit = 100): ExecutionLifecycleRecord[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new Error("EXECUTION_LIST_LIMIT_INVALID");
    }
    return (this.database
      .prepare("SELECT * FROM execution_lifecycles ORDER BY created_at DESC, id DESC LIMIT ?")
      .all(limit) as unknown as ExecutionLifecycleRow[]).map(toRecord);
  }

  summary(): ExecutionLifecycleSummary {
    const row = this.database
      .prepare(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN status IN ('queued', 'starting', 'running', 'cancel_requested') THEN 1 ELSE 0 END) AS nonterminal,
           SUM(CASE WHEN status = 'orphaned' THEN 1 ELSE 0 END) AS orphaned
         FROM execution_lifecycles`
      )
      .get() as { total: number; nonterminal: number | null; orphaned: number | null };
    return {
      total: row.total,
      nonterminal: row.nonterminal ?? 0,
      orphaned: row.orphaned ?? 0
    };
  }

  transition(
    executionId: string,
    nextStatus: ExecutionLifecycleStatus,
    options: { reasonCode?: string; now?: Date } = {}
  ): ExecutionLifecycleRecord {
    const now = options.now ?? new Date();
    const reasonCode = normalizeReasonCode(options.reasonCode);
    const current = this.get(executionId);
    if (!legalTransitions[current.status].includes(nextStatus)) {
      throw new Error(`EXECUTION_TRANSITION_INVALID:${current.status}:${nextStatus}`);
    }
    const timestamp = now.toISOString();
    const startedAt = nextStatus === "running" && current.startedAt === null ? timestamp : current.startedAt;
    const finishedAt = terminalStates.has(nextStatus) ? timestamp : null;
    const failureCode = nextStatus === "failed" || nextStatus === "timed_out" ? reasonCode : null;

    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = this.database
        .prepare(
          `UPDATE execution_lifecycles
           SET status = ?, failure_code = ?, updated_at = ?, started_at = ?, finished_at = ?
           WHERE id = ? AND status = ?`
        )
        .run(nextStatus, failureCode, timestamp, startedAt, finishedAt, executionId, current.status);
      if (result.changes !== 1) throw new Error("EXECUTION_TRANSITION_CONFLICT");
      this.database
        .prepare(
          `INSERT INTO execution_lifecycle_transitions(
             execution_id, from_status, to_status, occurred_at, reason_code
           ) VALUES (?, ?, ?, ?, ?)`
        )
        .run(executionId, current.status, nextStatus, timestamp, reasonCode);
      this.audit.append(
        "execution.lifecycle.transitioned",
        {
          executionId,
          capabilityId: current.capabilityId,
          from: current.status,
          to: nextStatus,
          reasonCode
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(executionId);
  }

  reconcileStartup(now = new Date()): ExecutionLifecycleRecord[] {
    const rows = this.database
      .prepare(
        `SELECT * FROM execution_lifecycles
         WHERE status IN ('queued', 'starting', 'running', 'cancel_requested')
         ORDER BY created_at, id`
      )
      .all() as unknown as ExecutionLifecycleRow[];
    if (rows.length === 0) return [];
    const timestamp = now.toISOString();

    this.database.exec("BEGIN IMMEDIATE");
    try {
      for (const row of rows) {
        const result = this.database
          .prepare(
            `UPDATE execution_lifecycles
             SET status = 'orphaned', failure_code = NULL, updated_at = ?, finished_at = ?
             WHERE id = ? AND status = ?`
          )
          .run(timestamp, timestamp, row.id, row.status);
        if (result.changes !== 1) throw new Error("EXECUTION_RECONCILIATION_CONFLICT");
        this.database
          .prepare(
            `INSERT INTO execution_lifecycle_transitions(
               execution_id, from_status, to_status, occurred_at, reason_code
             ) VALUES (?, ?, 'orphaned', ?, 'PROCESS_OWNERSHIP_LOST')`
          )
          .run(row.id, row.status, timestamp);
        this.audit.append(
          "execution.lifecycle.orphaned",
          {
            executionId: row.id,
            capabilityId: row.capability_id,
            previousStatus: row.status,
            reasonCode: "PROCESS_OWNERSHIP_LOST"
          },
          now
        );
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return rows.map((row) => this.get(row.id));
  }
}
