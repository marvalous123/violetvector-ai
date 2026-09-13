import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";

const GENESIS_HASH = "0".repeat(64);
const uuidSchema = z.string().uuid();
const actorSchema = z.string().trim().min(2).max(120);
const noteSchema = z.string().trim().min(10).max(4_000);
const outputFormatSchema = z.enum(["html", "json"]);
const qaIssueSchema = z.enum([
  "scope",
  "claims",
  "evidence",
  "remediation",
  "redaction",
  "layout",
  "other"
]);

export const reportQaChecklistSchema = z
  .object({
    scopeReviewed: z.literal(true),
    claimsSupported: z.literal(true),
    evidenceLinksVerified: z.literal(true),
    remediationReviewed: z.literal(true),
    sensitiveDataReviewed: z.literal(true),
    layoutReviewed: z.literal(true)
  })
  .strict();

export const approveReportQaInputSchema = z
  .object({
    checklist: reportQaChecklistSchema,
    note: noteSchema
  })
  .strict();

export const requestReportQaChangesInputSchema = z
  .object({
    issues: z
      .array(qaIssueSchema)
      .min(1)
      .max(7)
      .refine((issues) => new Set(issues).size === issues.length, "QA issues must be unique"),
    note: noteSchema
  })
  .strict();

export type ReportQaChecklist = z.infer<typeof reportQaChecklistSchema>;
export type ApproveReportQaInput = z.infer<typeof approveReportQaInputSchema>;
export type RequestReportQaChangesInput = z.infer<typeof requestReportQaChangesInputSchema>;

interface ReviewRow {
  id: string;
  snapshot_id: string;
  mission_id: string;
  snapshot_hash: string;
  opened_by: string;
  opened_at: string;
}

interface SnapshotRow {
  id: string;
  mission_id: string;
  snapshot_hash: string;
  status: "frozen" | "generated" | "blocked";
}

interface EventRow {
  id: string;
  review_id: string;
  sequence: number;
  event_type: "opened" | "changes-requested" | "approved";
  payload_json: string;
  payload_hash: string;
  actor: string;
  occurred_at: string;
  previous_event_hash: string;
  event_hash: string;
}

export interface ReportQaOutputBinding {
  readonly format: "html" | "json";
  readonly artifactId: string;
  readonly observationId: string;
  readonly sha256: string;
  readonly mediaType: "application/json" | "text/html";
  readonly sizeBytes: number;
}

interface OpenedPayload {
  readonly snapshotId: string;
  readonly snapshotHash: string;
  readonly outputs: readonly ReportQaOutputBinding[];
}

interface ChangesRequestedPayload {
  readonly issues: readonly z.infer<typeof qaIssueSchema>[];
  readonly note: string;
}

interface ApprovedPayload {
  readonly checklist: ReportQaChecklist;
  readonly note: string;
  readonly outputs: readonly ReportQaOutputBinding[];
}

export interface ReportQaHistoryEvent {
  readonly id: string;
  readonly sequence: number;
  readonly type: EventRow["event_type"];
  readonly actor: string;
  readonly occurredAt: string;
  readonly eventHash: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export interface ReportQaRecord {
  readonly id: string;
  readonly snapshotId: string;
  readonly missionId: string;
  readonly snapshotHash: string;
  readonly status: "pending" | "changes-requested" | "approved";
  readonly openedBy: string;
  readonly openedAt: string;
  readonly outputs: readonly ReportQaOutputBinding[];
  readonly issues: readonly z.infer<typeof qaIssueSchema>[];
  readonly note: string | null;
  readonly reviewer: string | null;
  readonly reviewedAt: string | null;
  readonly checklist: ReportQaChecklist | null;
  readonly history: readonly ReportQaHistoryEvent[];
  readonly integrityValid: true;
  readonly publicationReady: boolean;
  readonly limitation: string;
}

const outputBindingSchema = z
  .object({
    format: outputFormatSchema,
    artifactId: uuidSchema,
    observationId: uuidSchema,
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    mediaType: z.enum(["application/json", "text/html"]),
    sizeBytes: z.number().int().nonnegative().max(10 * 1024 * 1024)
  })
  .strict();

const eventPayloadSchemas = {
  opened: z
    .object({
      snapshotId: uuidSchema,
      snapshotHash: z.string().regex(/^[a-f0-9]{64}$/),
      outputs: z.array(outputBindingSchema).length(2)
    })
    .strict(),
  "changes-requested": requestReportQaChangesInputSchema,
  approved: z
    .object({
      checklist: reportQaChecklistSchema,
      note: noteSchema,
      outputs: z.array(outputBindingSchema).length(2)
    })
    .strict()
} as const;

function eventHash(
  previousHash: string,
  reviewId: string,
  sequence: number,
  occurredAt: string,
  eventType: EventRow["event_type"],
  actor: string,
  payloadJson: string
): string {
  return sha256(
    `${previousHash}\n${reviewId}\n${sequence}\n${occurredAt}\n${eventType}\n${actor}\n${payloadJson}`
  );
}

function sameOutputs(
  left: readonly ReportQaOutputBinding[],
  right: readonly ReportQaOutputBinding[]
): boolean {
  return stableJson(left) === stableJson(right);
}

export class ReportQaService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService
  ) {}

  open(snapshotIdInput: string, actorInput: string, now = new Date()): ReportQaRecord {
    const snapshotId = uuidSchema.parse(snapshotIdInput);
    const actor = actorSchema.parse(actorInput);
    const snapshot = this.snapshot(snapshotId);
    if (snapshot.status !== "generated") throw new Error("REPORT_QA_GENERATED_REPORT_REQUIRED");
    if (this.database.prepare("SELECT id FROM report_qa_reviews WHERE snapshot_id = ?").get(snapshotId)) {
      throw new Error("REPORT_QA_ALREADY_OPEN");
    }
    const outputs = this.validatedOutputs(snapshot);
    if (!this.audit.verify().valid) throw new Error("REPORT_QA_AUDIT_INVALID");
    const reviewId = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO report_qa_reviews(
             id, snapshot_id, mission_id, snapshot_hash, opened_by, opened_at
           ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          reviewId,
          snapshot.id,
          snapshot.mission_id,
          snapshot.snapshot_hash,
          actor,
          now.toISOString()
        );
      this.appendEvent(
        reviewId,
        "opened",
        {
          snapshotId: snapshot.id,
          snapshotHash: snapshot.snapshot_hash,
          outputs
        },
        actor,
        now
      );
      this.audit.append(
        "report_qa.opened",
        {
          reviewId,
          snapshotId: snapshot.id,
          missionId: snapshot.mission_id,
          snapshotHash: snapshot.snapshot_hash,
          outputCount: outputs.length,
          actor
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(reviewId);
  }

  approve(
    reviewIdInput: string,
    input: ApproveReportQaInput,
    actorInput: string,
    now = new Date()
  ): ReportQaRecord {
    const reviewId = uuidSchema.parse(reviewIdInput);
    const body = approveReportQaInputSchema.parse(input);
    const actor = actorSchema.parse(actorInput);
    const current = this.get(reviewId);
    if (current.status !== "pending") throw new Error("REPORT_QA_NOT_PENDING");
    if (!this.audit.verify().valid) throw new Error("REPORT_QA_AUDIT_INVALID");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.appendEvent(
        reviewId,
        "approved",
        {
          checklist: body.checklist,
          note: body.note,
          outputs: current.outputs
        },
        actor,
        now
      );
      this.audit.append(
        "report_qa.approved",
        {
          reviewId,
          snapshotId: current.snapshotId,
          missionId: current.missionId,
          snapshotHash: current.snapshotHash,
          outputCount: current.outputs.length,
          actor
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(reviewId);
  }

  requestChanges(
    reviewIdInput: string,
    input: RequestReportQaChangesInput,
    actorInput: string,
    now = new Date()
  ): ReportQaRecord {
    const reviewId = uuidSchema.parse(reviewIdInput);
    const body = requestReportQaChangesInputSchema.parse(input);
    const actor = actorSchema.parse(actorInput);
    const current = this.get(reviewId);
    if (current.status !== "pending") throw new Error("REPORT_QA_NOT_PENDING");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.appendEvent(reviewId, "changes-requested", body, actor, now);
      this.audit.append(
        "report_qa.changes_requested",
        {
          reviewId,
          snapshotId: current.snapshotId,
          missionId: current.missionId,
          snapshotHash: current.snapshotHash,
          issueCount: body.issues.length,
          actor
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(reviewId);
  }

  get(reviewIdInput: string): ReportQaRecord {
    const reviewId = uuidSchema.parse(reviewIdInput);
    const row = this.database
      .prepare("SELECT * FROM report_qa_reviews WHERE id = ?")
      .get(reviewId) as ReviewRow | undefined;
    if (!row) throw new Error("REPORT_QA_NOT_FOUND");
    const snapshot = this.snapshot(row.snapshot_id);
    if (
      snapshot.status !== "generated" ||
      snapshot.mission_id !== row.mission_id ||
      snapshot.snapshot_hash !== row.snapshot_hash
    ) {
      throw new Error("REPORT_QA_SNAPSHOT_BINDING_INVALID");
    }
    const outputs = this.validatedOutputs(snapshot);
    const events = this.verifiedEvents(row);
    const opened = events[0]!;
    const openedPayload = opened.payload as unknown as OpenedPayload;
    if (
      opened.type !== "opened" ||
      openedPayload.snapshotId !== row.snapshot_id ||
      openedPayload.snapshotHash !== row.snapshot_hash ||
      !sameOutputs(openedPayload.outputs, outputs)
    ) {
      throw new Error("REPORT_QA_HISTORY_INVALID");
    }
    if (events.length > 2) throw new Error("REPORT_QA_HISTORY_INVALID");
    const terminal = events[1];
    let status: ReportQaRecord["status"] = "pending";
    let issues: ChangesRequestedPayload["issues"] = [];
    let note: string | null = null;
    let reviewer: string | null = null;
    let reviewedAt: string | null = null;
    let checklist: ReportQaChecklist | null = null;
    if (terminal?.type === "changes-requested") {
      const payload = terminal.payload as unknown as ChangesRequestedPayload;
      status = "changes-requested";
      issues = payload.issues;
      note = payload.note;
      reviewer = terminal.actor;
      reviewedAt = terminal.occurredAt;
    } else if (terminal?.type === "approved") {
      const payload = terminal.payload as unknown as ApprovedPayload;
      if (!sameOutputs(payload.outputs, outputs)) throw new Error("REPORT_QA_OUTPUT_BINDING_INVALID");
      status = "approved";
      note = payload.note;
      reviewer = terminal.actor;
      reviewedAt = terminal.occurredAt;
      checklist = payload.checklist;
    } else if (terminal) {
      throw new Error("REPORT_QA_HISTORY_INVALID");
    }
    return {
      id: row.id,
      snapshotId: row.snapshot_id,
      missionId: row.mission_id,
      snapshotHash: row.snapshot_hash,
      status,
      openedBy: row.opened_by,
      openedAt: row.opened_at,
      outputs,
      issues,
      note,
      reviewer,
      reviewedAt,
      checklist,
      history: events,
      integrityValid: true,
      publicationReady: status === "approved",
      limitation:
        "QA approval attests that the exact generated JSON/HTML outputs were reviewed. It does not replace evidence integrity checks, authorize target activity or prove that a future PDF/DOCX render is visually correct."
    };
  }

  list(missionIdInput?: string): ReportQaRecord[] {
    const missionId = missionIdInput ? uuidSchema.parse(missionIdInput) : undefined;
    const rows = (missionId
      ? this.database
          .prepare(
            "SELECT id FROM report_qa_reviews WHERE mission_id = ? ORDER BY opened_at DESC, id DESC LIMIT 200"
          )
          .all(missionId)
      : this.database
          .prepare("SELECT id FROM report_qa_reviews ORDER BY opened_at DESC, id DESC LIMIT 200")
          .all()) as unknown as Array<{ id: string }>;
    return rows.map((row) => this.get(row.id));
  }

  private snapshot(snapshotId: string): SnapshotRow {
    const row = this.database
      .prepare(
        "SELECT id, mission_id, snapshot_hash, status FROM report_snapshots WHERE id = ?"
      )
      .get(snapshotId) as SnapshotRow | undefined;
    if (!row) throw new Error("REPORT_SNAPSHOT_NOT_FOUND");
    return row;
  }

  private validatedOutputs(snapshot: SnapshotRow): ReportQaOutputBinding[] {
    const rows = this.database
      .prepare(
        `SELECT output.format, output.artifact_id, artifact.sha256, artifact.media_type,
                artifact.size_bytes,
                (
                  SELECT observation.id
                  FROM evidence_observations observation
                  WHERE observation.artifact_id = output.artifact_id
                    AND observation.mission_id = ?
                  ORDER BY observation.recorded_at DESC, observation.id DESC
                  LIMIT 1
                ) AS observation_id
         FROM report_outputs output
         JOIN artifacts artifact ON artifact.id = output.artifact_id
         WHERE output.snapshot_id = ?
         ORDER BY output.format`
      )
      .all(snapshot.mission_id, snapshot.id) as unknown as Array<{
        format: "html" | "json";
        artifact_id: string;
        observation_id: string | null;
        sha256: string;
        media_type: string;
        size_bytes: number;
      }>;
    if (
      rows.length !== 2 ||
      rows[0]?.format !== "html" ||
      rows[1]?.format !== "json" ||
      rows.some(
        (row) =>
          !row.observation_id ||
          !this.evidence.verify(row.artifact_id) ||
          !this.evidence.verifyObservation(
            row.observation_id,
            row.artifact_id,
            snapshot.mission_id
          )
      )
    ) {
      throw new Error("REPORT_QA_OUTPUT_INVALID");
    }
    return rows.map((row) =>
      outputBindingSchema.parse({
        format: row.format,
        artifactId: row.artifact_id,
        observationId: row.observation_id,
        sha256: row.sha256,
        mediaType: row.media_type,
        sizeBytes: row.size_bytes
      })
    );
  }

  private appendEvent(
    reviewId: string,
    type: EventRow["event_type"],
    payloadInput: unknown,
    actor: string,
    now: Date
  ): void {
    const payload = eventPayloadSchemas[type].parse(payloadInput) as Record<string, unknown>;
    const payloadJson = stableJson(payload);
    const latest = this.database
      .prepare(
        `SELECT sequence, event_hash
         FROM report_qa_events
         WHERE review_id = ?
         ORDER BY sequence DESC LIMIT 1`
      )
      .get(reviewId) as { sequence: number; event_hash: string } | undefined;
    const sequence = (latest?.sequence ?? 0) + 1;
    if (sequence > 100) throw new Error("REPORT_QA_HISTORY_LIMIT_REACHED");
    const previousHash = latest?.event_hash ?? GENESIS_HASH;
    const occurredAt = now.toISOString();
    const hash = eventHash(previousHash, reviewId, sequence, occurredAt, type, actor, payloadJson);
    this.database
      .prepare(
        `INSERT INTO report_qa_events(
           id, review_id, sequence, event_type, payload_json, payload_hash,
           actor, occurred_at, previous_event_hash, event_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        randomUUID(),
        reviewId,
        sequence,
        type,
        payloadJson,
        canonicalHash(payload),
        actor,
        occurredAt,
        previousHash,
        hash
      );
  }

  private verifiedEvents(row: ReviewRow): ReportQaHistoryEvent[] {
    const rows = this.database
      .prepare("SELECT * FROM report_qa_events WHERE review_id = ? ORDER BY sequence")
      .all(row.id) as unknown as EventRow[];
    if (rows.length < 1) throw new Error("REPORT_QA_HISTORY_INVALID");
    let previousHash = GENESIS_HASH;
    return rows.map((event, index) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(event.payload_json) as unknown;
      } catch {
        throw new Error("REPORT_QA_HISTORY_INVALID");
      }
      let payload: Record<string, unknown>;
      try {
        payload = eventPayloadSchemas[event.event_type].parse(parsed) as Record<string, unknown>;
      } catch {
        throw new Error("REPORT_QA_HISTORY_INVALID");
      }
      const expectedHash = eventHash(
        previousHash,
        row.id,
        event.sequence,
        event.occurred_at,
        event.event_type,
        event.actor,
        event.payload_json
      );
      if (
        event.sequence !== index + 1 ||
        event.previous_event_hash !== previousHash ||
        stableJson(payload) !== event.payload_json ||
        canonicalHash(payload) !== event.payload_hash ||
        expectedHash !== event.event_hash
      ) {
        throw new Error("REPORT_QA_HISTORY_INVALID");
      }
      previousHash = event.event_hash;
      return {
        id: event.id,
        sequence: event.sequence,
        type: event.event_type,
        actor: event.actor,
        occurredAt: event.occurred_at,
        eventHash: event.event_hash,
        payload
      };
    });
  }
}
