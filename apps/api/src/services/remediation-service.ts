import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import { ApprovalService } from "./approval-service.js";
import { AuditService } from "./audit-service.js";
import type { ArtifactRow, EvidenceService } from "./evidence-service.js";

const GENESIS_HASH = "0".repeat(64);
const MAX_RISK_ACCEPTANCE_MS = 366 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

const uuidSchema = z.string().uuid();
const personSchema = z.string().trim().min(2).max(120);
const narrativeSchema = z.string().trim().min(10).max(4_000);
const evidenceIdsSchema = z.array(uuidSchema).min(1).max(16).refine((ids) => new Set(ids).size === ids.length, {
  message: "Evidence artifact IDs must be unique"
});
const dateOnlySchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const [year, month, day] = value.split("-").map(Number);
    const date = new Date(Date.UTC(year!, month! - 1, day));
    return date.getUTCFullYear() === year && date.getUTCMonth() === month! - 1 && date.getUTCDate() === day;
  }, "Due date must be a real calendar date");

export const remediationPrioritySchema = z.enum(["low", "medium", "high", "critical"]);
export const remediationStatusSchema = z.enum([
  "open",
  "in-progress",
  "fix-ready",
  "retest-pending",
  "remediated",
  "persists",
  "regressed",
  "inconclusive",
  "closed"
]);
export const retestOutcomeSchema = z.enum(["remediated", "persists", "regressed", "inconclusive"]);

const manualStatusSchema = z.enum(["open", "in-progress", "fix-ready", "closed"]);

export const createRemediationInputSchema = z
  .object({
    owner: personSchema,
    dueDate: dateOnlySchema,
    priority: remediationPrioritySchema
  })
  .strict();

export const changeOwnerInputSchema = z.object({ owner: personSchema }).strict();
export const changeDueDateInputSchema = z.object({ dueDate: dateOnlySchema }).strict();
export const changePriorityInputSchema = z.object({ priority: remediationPrioritySchema }).strict();
export const changeRemediationStatusInputSchema = z.object({ status: manualStatusSchema }).strict();
export const reviewerCommentInputSchema = z
  .object({
    reviewer: personSchema,
    comment: narrativeSchema
  })
  .strict();
export const riskAcceptanceInputSchema = z
  .object({
    reason: narrativeSchema,
    reviewer: personSchema,
    expiresAt: z.string().datetime({ offset: true })
  })
  .strict();
export const revokeRiskAcceptanceInputSchema = z.object({ reason: narrativeSchema }).strict();
export const fixEvidenceInputSchema = z
  .object({
    artifactIds: evidenceIdsSchema,
    note: narrativeSchema
  })
  .strict();
export const operatorFixEvidenceInputSchema = z
  .object({
    changeType: z.enum(["device-configuration", "software-update", "operational-mitigation", "other"]),
    actionPerformedAt: z.string().datetime({ offset: true }),
    actionSummary: narrativeSchema,
    observedState: narrativeSchema
  })
  .strict();
export const requestRetestInputSchema = z.object({ reason: narrativeSchema }).strict();
export const retestOutcomeInputSchema = z
  .object({
    requestId: uuidSchema,
    outcome: retestOutcomeSchema,
    summary: narrativeSchema,
    reviewer: personSchema,
    evidenceArtifactIds: evidenceIdsSchema
  })
  .strict();

export type RemediationPriority = z.infer<typeof remediationPrioritySchema>;
export type RemediationStatus = z.infer<typeof remediationStatusSchema>;
export type RetestOutcome = z.infer<typeof retestOutcomeSchema>;
export type CreateRemediationInput = z.infer<typeof createRemediationInputSchema>;
export type RiskAcceptanceInput = z.infer<typeof riskAcceptanceInputSchema>;
export type FixEvidenceInput = z.infer<typeof fixEvidenceInputSchema>;
export type OperatorFixEvidenceInput = z.infer<typeof operatorFixEvidenceInputSchema>;
export type RetestOutcomeInput = z.infer<typeof retestOutcomeInputSchema>;

export interface DirectRetestBindingInput {
  readonly requestId: string;
  readonly parentRunId: string;
  readonly retestRunId: string;
  readonly approvalId: string;
  readonly proposalId: string;
}

export interface DirectRetestBinding extends DirectRetestBindingInput {
  readonly remediationId: string;
  readonly boundBy: string;
  readonly boundAt: string;
}

const remediationEventTypeSchema = z.enum([
  "created",
  "owner-changed",
  "due-date-changed",
  "priority-changed",
  "status-changed",
  "reviewer-commented",
  "risk-acceptance-recorded",
  "risk-acceptance-revoked",
  "fix-evidence-added",
  "retest-requested",
  "retest-outcome-recorded"
]);
type RemediationEventType = z.infer<typeof remediationEventTypeSchema>;

const eventPayloadSchemas: Record<RemediationEventType, z.ZodTypeAny> = {
  created: z
    .object({
      owner: personSchema,
      dueDate: dateOnlySchema,
      priority: remediationPrioritySchema,
      status: z.literal("open")
    })
    .strict(),
  "owner-changed": z.object({ from: personSchema, to: personSchema }).strict(),
  "due-date-changed": z.object({ from: dateOnlySchema, to: dateOnlySchema }).strict(),
  "priority-changed": z.object({ from: remediationPrioritySchema, to: remediationPrioritySchema }).strict(),
  "status-changed": z.object({ from: remediationStatusSchema, to: manualStatusSchema }).strict(),
  "reviewer-commented": z.object({ reviewer: personSchema, comment: narrativeSchema }).strict(),
  "risk-acceptance-recorded": z
    .object({
      acceptanceId: uuidSchema,
      reason: narrativeSchema,
      reviewer: personSchema,
      expiresAt: z.string().datetime({ offset: true })
    })
    .strict(),
  "risk-acceptance-revoked": z
    .object({
      acceptanceId: uuidSchema,
      reason: narrativeSchema
    })
    .strict(),
  "fix-evidence-added": z.object({ artifactIds: evidenceIdsSchema, note: narrativeSchema }).strict(),
  "retest-requested": z
    .object({
      requestId: uuidSchema,
      reason: narrativeSchema,
      baselineStatus: remediationStatusSchema
    })
    .strict(),
  "retest-outcome-recorded": z
    .object({
      requestId: uuidSchema,
      outcome: retestOutcomeSchema,
      summary: narrativeSchema,
      reviewer: personSchema,
      artifactIds: evidenceIdsSchema
    })
    .strict()
};

interface RemediationRow {
  id: string;
  finding_id: string;
  mission_id: string;
  created_at: string;
  finding_title: string;
  finding_status: string;
}

interface RemediationEventRow {
  id: string;
  remediation_id: string;
  sequence: number;
  event_type: string;
  payload_json: string;
  payload_hash: string;
  actor: string;
  occurred_at: string;
  previous_event_hash: string;
  event_hash: string;
}

interface RemediationEvidenceLinkRow {
  remediation_event_id: string;
  artifact_id: string;
  observation_id: string;
  purpose: "fix" | "retest";
}

interface EvidenceReference {
  readonly artifactId: string;
  readonly observationId: string;
}

interface VerifiedEvent {
  readonly id: string;
  readonly sequence: number;
  readonly type: RemediationEventType;
  readonly payload: Record<string, unknown>;
  readonly actor: string;
  readonly occurredAt: string;
  readonly eventHash: string;
  readonly evidence: readonly EvidenceReference[];
}

export interface RemediationHistoryEvent {
  readonly id: string;
  readonly sequence: number;
  readonly type: RemediationEventType;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly actor: string;
  readonly occurredAt: string;
  readonly eventHash: string;
  readonly evidence: readonly EvidenceReference[];
}

export interface RemediationRiskAcceptance {
  readonly acceptanceId: string;
  readonly reason: string;
  readonly reviewer: string;
  readonly expiresAt: string;
  readonly recordedBy: string;
  readonly recordedAt: string;
  readonly status: "active" | "expired" | "revoked";
  readonly revokedBy?: string;
  readonly revokedAt?: string;
  readonly revocationReason?: string;
}

export interface RemediationFixEvidence extends EvidenceReference {
  readonly eventId: string;
  readonly note: string;
  readonly addedBy: string;
  readonly addedAt: string;
}

export interface RemediationRetest {
  readonly requestId: string;
  readonly reason: string;
  readonly requestedBy: string;
  readonly requestedAt: string;
  readonly baselineStatus: RemediationStatus;
  readonly outcome?: RetestOutcome;
  readonly summary?: string;
  readonly reviewer?: string;
  readonly outcomeRecordedBy?: string;
  readonly outcomeRecordedAt?: string;
  readonly evidence: readonly EvidenceReference[];
  readonly directRetest?: DirectRetestBinding;
}

export interface RemediationReviewerComment {
  readonly eventId: string;
  readonly reviewer: string;
  readonly comment: string;
  readonly recordedBy: string;
  readonly recordedAt: string;
}

export interface RemediationRecord {
  readonly id: string;
  readonly findingId: string;
  readonly missionId: string;
  readonly findingTitle: string;
  readonly findingStatus: string;
  readonly owner: string;
  readonly dueDate: string;
  readonly priority: RemediationPriority;
  readonly status: RemediationStatus;
  readonly regressionState: "not-assessed" | "not-regressed" | "regressed" | "inconclusive";
  readonly riskAcceptance: RemediationRiskAcceptance | null;
  readonly fixEvidence: readonly RemediationFixEvidence[];
  readonly retests: readonly RemediationRetest[];
  readonly reviewerComments: readonly RemediationReviewerComment[];
  readonly history: readonly RemediationHistoryEvent[];
  readonly createdAt: string;
  readonly integrityValid: true;
  readonly claimLimitation: string;
}

interface MutableState {
  owner: string;
  dueDate: string;
  priority: RemediationPriority;
  status: RemediationStatus;
  regressionState: RemediationRecord["regressionState"];
  riskAcceptance: RemediationRiskAcceptance | null;
  fixEvidence: RemediationFixEvidence[];
  retests: RemediationRetest[];
  reviewerComments: RemediationReviewerComment[];
}

const manualTransitions: Readonly<Record<RemediationStatus, readonly RemediationStatus[]>> = {
  open: ["in-progress"],
  "in-progress": ["open", "fix-ready"],
  "fix-ready": ["in-progress"],
  "retest-pending": [],
  remediated: ["closed"],
  persists: ["in-progress", "fix-ready"],
  regressed: ["in-progress", "fix-ready"],
  inconclusive: ["in-progress", "fix-ready"],
  closed: []
};

const retestEligibleStatuses = new Set<RemediationStatus>([
  "fix-ready",
  "persists",
  "regressed",
  "inconclusive",
  "remediated",
  "closed"
]);

function remediationEventHash(
  previousHash: string,
  remediationId: string,
  sequence: number,
  occurredAt: string,
  eventType: RemediationEventType,
  actor: string,
  payloadJson: string
): string {
  return sha256(
    `${previousHash}\n${remediationId}\n${sequence}\n${occurredAt}\n${eventType}\n${actor}\n${payloadJson}`
  );
}

function assertManualTransition(from: RemediationStatus, to: RemediationStatus): void {
  if (!manualTransitions[from].includes(to)) throw new Error("REMEDIATION_STATUS_TRANSITION_INVALID");
}

function assertRetestOutcome(baseline: RemediationStatus, outcome: RetestOutcome): void {
  const regressionCheck = baseline === "remediated" || baseline === "closed";
  const allowed = regressionCheck
    ? new Set<RetestOutcome>(["remediated", "regressed", "inconclusive"])
    : new Set<RetestOutcome>(["remediated", "persists", "inconclusive"]);
  if (!allowed.has(outcome)) throw new Error("REMEDIATION_RETEST_OUTCOME_INVALID");
}

function asPayload<T>(event: VerifiedEvent): T {
  return event.payload as T;
}

export class RemediationService {
  private readonly audit: AuditService;
  private readonly approvals: ApprovalService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    audit?: AuditService,
    approvals?: ApprovalService
  ) {
    this.audit = audit ?? new AuditService(database);
    this.approvals = approvals ?? new ApprovalService(database, this.audit);
  }

  create(
    findingIdInput: string,
    input: CreateRemediationInput,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const findingId = uuidSchema.parse(findingIdInput);
    const body = createRemediationInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const finding = this.assertAcceptedFinding(findingId);
    if (this.database.prepare("SELECT id FROM remediation_records WHERE finding_id = ?").get(findingId)) {
      throw new Error("REMEDIATION_ALREADY_EXISTS");
    }
    const remediationId = randomUUID();
    this.transact(() => {
      this.database
        .prepare(
          `INSERT INTO remediation_records(id, finding_id, mission_id, created_at)
           VALUES (?, ?, ?, ?)`
        )
        .run(remediationId, findingId, finding.mission_id, now.toISOString());
      this.appendEvent(
        { id: remediationId, findingId, missionId: finding.mission_id },
        "created",
        { ...body, status: "open" },
        actor,
        now
      );
    });
    return this.get(remediationId, now);
  }

  changeOwner(
    remediationId: string,
    input: z.infer<typeof changeOwnerInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = changeOwnerInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (current.owner === body.owner) throw new Error("REMEDIATION_NO_CHANGE");
    this.appendInTransaction(current, "owner-changed", { from: current.owner, to: body.owner }, actor, now);
    return this.get(current.id, now);
  }

  changeDueDate(
    remediationId: string,
    input: z.infer<typeof changeDueDateInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = changeDueDateInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (current.dueDate === body.dueDate) throw new Error("REMEDIATION_NO_CHANGE");
    this.appendInTransaction(current, "due-date-changed", { from: current.dueDate, to: body.dueDate }, actor, now);
    return this.get(current.id, now);
  }

  changePriority(
    remediationId: string,
    input: z.infer<typeof changePriorityInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = changePriorityInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (current.priority === body.priority) throw new Error("REMEDIATION_NO_CHANGE");
    this.appendInTransaction(
      current,
      "priority-changed",
      { from: current.priority, to: body.priority },
      actor,
      now
    );
    return this.get(current.id, now);
  }

  changeStatus(
    remediationId: string,
    input: z.infer<typeof changeRemediationStatusInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = changeRemediationStatusInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    assertManualTransition(current.status, body.status);
    this.appendInTransaction(current, "status-changed", { from: current.status, to: body.status }, actor, now);
    return this.get(current.id, now);
  }

  addReviewerComment(
    remediationId: string,
    input: z.infer<typeof reviewerCommentInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = reviewerCommentInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    this.appendInTransaction(current, "reviewer-commented", body, actor, now);
    return this.get(current.id, now);
  }

  recordRiskAcceptance(
    remediationId: string,
    input: RiskAcceptanceInput,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = riskAcceptanceInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (current.status === "closed") throw new Error("REMEDIATION_CLOSED");
    if (current.riskAcceptance?.status === "active") throw new Error("REMEDIATION_RISK_ACCEPTANCE_ACTIVE");
    const expiry = new Date(body.expiresAt);
    if (expiry.getTime() <= now.getTime() || expiry.getTime() - now.getTime() > MAX_RISK_ACCEPTANCE_MS) {
      throw new Error("REMEDIATION_RISK_ACCEPTANCE_EXPIRY_INVALID");
    }
    this.appendInTransaction(
      current,
      "risk-acceptance-recorded",
      { ...body, acceptanceId: randomUUID() },
      actor,
      now
    );
    return this.get(current.id, now);
  }

  revokeRiskAcceptance(
    remediationId: string,
    input: z.infer<typeof revokeRiskAcceptanceInputSchema>,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = revokeRiskAcceptanceInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (!current.riskAcceptance || current.riskAcceptance.status !== "active") {
      throw new Error("REMEDIATION_RISK_ACCEPTANCE_NOT_ACTIVE");
    }
    this.appendInTransaction(
      current,
      "risk-acceptance-revoked",
      { acceptanceId: current.riskAcceptance.acceptanceId, reason: body.reason },
      actor,
      now
    );
    return this.get(current.id, now);
  }

  addFixEvidence(
    remediationId: string,
    input: FixEvidenceInput,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = fixEvidenceInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    if (current.status === "closed" || current.status === "retest-pending") throw new Error("REMEDIATION_EVIDENCE_STATE_INVALID");
    const references = this.validateFixEvidence(body.artifactIds, current, now);
    this.transact(() => {
      this.appendEvent(
        { id: current.id, findingId: current.findingId, missionId: current.missionId },
        "fix-evidence-added",
        { artifactIds: body.artifactIds, note: body.note },
        actor,
        now,
        "fix",
        references
      );
    });
    return this.get(current.id, now);
  }

  captureOperatorFixEvidence(
    remediationId: string,
    input: OperatorFixEvidenceInput,
    actorInput: string,
    now = new Date()
  ): { artifact: ArtifactRow; remediation: RemediationRecord } {
    const body = operatorFixEvidenceInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    this.assertAcceptedFinding(current.findingId);
    if (current.status === "closed" || current.status === "retest-pending") {
      throw new Error("REMEDIATION_EVIDENCE_STATE_INVALID");
    }
    const performedAt = new Date(body.actionPerformedAt);
    if (
      performedAt.getTime() < new Date(current.createdAt).getTime() ||
      performedAt.getTime() > now.getTime() + MAX_CLOCK_SKEW_MS
    ) {
      throw new Error("REMEDIATION_FIX_ACTION_TIME_INVALID");
    }
    const recordedAt = now.toISOString();
    const evidencePayload = stableJson({
      schemaVersion: 1,
      evidenceType: "operator-remediation-fix",
      remediationId: current.id,
      findingId: current.findingId,
      missionId: current.missionId,
      changeType: body.changeType,
      actionPerformedAt: performedAt.toISOString(),
      recordedAt,
      recordedBy: actor,
      actionSummary: body.actionSummary,
      observedState: body.observedState,
      claimLimitation:
        "This is an authenticated operator-attested change record. Only a separately approved direct retest can establish the technical outcome."
    });
    const artifact = this.evidence.seal(evidencePayload, "application/json", {
      missionId: current.missionId,
      capturedAt: performedAt,
      provenance: {
        sourceType: "operator-remediation-fix",
        remediationId: current.id,
        findingId: current.findingId,
        actionPerformedAt: performedAt.toISOString(),
        recordedBy: actor
      }
    });
    const remediation = this.addFixEvidence(
      current.id,
      {
        artifactIds: [artifact.id],
        note: `Authenticated operator-attested ${body.changeType} change record captured for this remediation.`
      },
      actor,
      now
    );
    return { artifact, remediation };
  }

  requestRetest(
    remediationId: string,
    input: z.infer<typeof requestRetestInputSchema>,
    actorInput: string,
    now = new Date()
  ): string {
    const body = requestRetestInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    this.assertAcceptedFinding(current.findingId);
    if (!retestEligibleStatuses.has(current.status)) throw new Error("REMEDIATION_RETEST_STATE_INVALID");
    if (current.fixEvidence.length < 1) throw new Error("REMEDIATION_FIX_EVIDENCE_REQUIRED");
    if (current.retests.some((retest) => !retest.outcome)) throw new Error("REMEDIATION_RETEST_ALREADY_PENDING");
    const requestId = randomUUID();
    this.appendInTransaction(
      current,
      "retest-requested",
      { requestId, reason: body.reason, baselineStatus: current.status },
      actor,
      now
    );
    return requestId;
  }

  bindDirectRetest(
    remediationId: string,
    input: DirectRetestBindingInput,
    actorInput: string,
    now = new Date()
  ): DirectRetestBinding {
    const body = {
      requestId: uuidSchema.parse(input.requestId),
      parentRunId: uuidSchema.parse(input.parentRunId),
      retestRunId: uuidSchema.parse(input.retestRunId),
      approvalId: uuidSchema.parse(input.approvalId),
      proposalId: uuidSchema.parse(input.proposalId)
    };
    const actor = personSchema.parse(actorInput);
    this.transact(() => {
      const current = this.get(remediationId, now);
      this.assertAcceptedFinding(current.findingId);
      const request = current.retests.find((item) => item.requestId === body.requestId);
      if (!request || request.outcome || current.status !== "retest-pending") {
        throw new Error("REMEDIATION_RETEST_STATE_INVALID");
      }
      if (request.directRetest) throw new Error("REMEDIATION_DIRECT_RETEST_ALREADY_BOUND");
      const sourceRunIds = this.acceptedFindingRunIds(current.findingId);
      if (sourceRunIds.length !== 1 || sourceRunIds[0] !== body.parentRunId) {
        throw new Error("REMEDIATION_DIRECT_RETEST_PARENT_INVALID");
      }
      const rows = this.database
        .prepare(
          `SELECT child.mission_id, child.parent_run_id, child.lineage_type, child.status,
                  parent.status AS parent_status,
                  child_proposal.proposal_json AS child_proposal_json,
                  parent_proposal.proposal_json AS parent_proposal_json
           FROM runs child
           JOIN runs parent ON parent.id = child.parent_run_id
           JOIN proposals child_proposal ON child_proposal.id = ? AND child_proposal.run_id = child.id
           JOIN proposals parent_proposal ON parent_proposal.run_id = parent.id
           WHERE child.id = ? AND parent.id = ?
           ORDER BY parent_proposal.created_at DESC LIMIT 1`
        )
        .get(body.proposalId, body.retestRunId, body.parentRunId) as
        | {
            mission_id: string;
            parent_run_id: string;
            lineage_type: string;
            status: string;
            parent_status: string;
            child_proposal_json: string;
            parent_proposal_json: string;
          }
        | undefined;
      if (
        !rows ||
        rows.mission_id !== current.missionId ||
        rows.parent_run_id !== body.parentRunId ||
        rows.lineage_type !== "retest" ||
        rows.status !== "awaiting_approval" ||
        rows.parent_status !== "succeeded"
      ) {
        throw new Error("REMEDIATION_DIRECT_RETEST_BINDING_INVALID");
      }
      if (!this.proposalsMatchForRetest(rows.parent_proposal_json, rows.child_proposal_json)) {
        throw new Error("REMEDIATION_DIRECT_RETEST_PARAMETERS_CHANGED");
      }
      this.approvals.assertPendingExactExecutionBinding(
        {
          approvalId: body.approvalId,
          proposalId: body.proposalId,
          runId: body.retestRunId,
          missionId: current.missionId
        },
        now
      );
      this.database
        .prepare(
          `INSERT INTO remediation_direct_retest_bindings(
             request_id, remediation_id, parent_run_id, retest_run_id, approval_id, proposal_id, bound_by, bound_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          body.requestId,
          current.id,
          body.parentRunId,
          body.retestRunId,
          body.approvalId,
          body.proposalId,
          actor,
          now.toISOString()
        );
      this.audit.append("remediation.direct-retest-bound", {
        remediationId: current.id,
        requestId: body.requestId,
        parentRunId: body.parentRunId,
        retestRunId: body.retestRunId,
        approvalId: body.approvalId,
        proposalId: body.proposalId,
        actor
      }, now);
    });
    return this.getDirectRetestBinding(uuidSchema.parse(remediationId), body.requestId);
  }

  abandonDirectRetestPreparation(
    remediationIdInput: string,
    input: DirectRetestBindingInput,
    actorInput: string,
    now = new Date()
  ): void {
    const remediationId = uuidSchema.parse(remediationIdInput);
    const body = {
      requestId: uuidSchema.parse(input.requestId),
      parentRunId: uuidSchema.parse(input.parentRunId),
      retestRunId: uuidSchema.parse(input.retestRunId),
      approvalId: uuidSchema.parse(input.approvalId),
      proposalId: uuidSchema.parse(input.proposalId)
    };
    const actor = personSchema.parse(actorInput);
    this.transact(() => {
      const record = this.remediationRow(remediationId);
      const existing = this.database
        .prepare(
          `SELECT request_id FROM remediation_direct_retest_bindings
           WHERE approval_id = ? OR proposal_id = ? OR retest_run_id = ?`
        )
        .get(body.approvalId, body.proposalId, body.retestRunId);
      if (existing) throw new Error("REMEDIATION_DIRECT_RETEST_ALREADY_BOUND");
      const prepared = this.database
        .prepare(
          `SELECT approval.status AS approval_status, run.status AS run_status
           FROM runs run
           JOIN proposals proposal ON proposal.id = ? AND proposal.run_id = run.id
           JOIN approval_requests approval ON approval.id = ? AND approval.proposal_id = proposal.id
           WHERE run.id = ? AND run.parent_run_id = ? AND run.lineage_type = 'retest'
             AND run.mission_id = ? AND proposal.mission_id = run.mission_id`
        )
        .get(
          body.proposalId,
          body.approvalId,
          body.retestRunId,
          body.parentRunId,
          record.mission_id
        ) as { approval_status: string; run_status: string } | undefined;
      if (!prepared) throw new Error("REMEDIATION_DIRECT_RETEST_COMPENSATION_BINDING_INVALID");
      if (prepared.approval_status === "consumed" || ["running", "succeeded"].includes(prepared.run_status)) {
        throw new Error("REMEDIATION_DIRECT_RETEST_COMPENSATION_UNSAFE");
      }
      if (["pending", "approved"].includes(prepared.approval_status)) {
        const approvalResult = this.database
          .prepare(
            `UPDATE approval_requests
             SET status = 'revoked', decided_at = ?, decided_by = ?,
                 decision_note = 'Remediation retest binding failed; prepared approval revoked'
             WHERE id = ? AND status IN ('pending', 'approved')`
          )
          .run(now.toISOString(), actor, body.approvalId);
        if (approvalResult.changes !== 1) throw new Error("REMEDIATION_DIRECT_RETEST_COMPENSATION_RACE");
      }
      if (["queued", "awaiting_approval", "armed"].includes(prepared.run_status)) {
        const runResult = this.database
          .prepare(
            `UPDATE runs SET status = 'failed', updated_at = ?
             WHERE id = ? AND status IN ('queued', 'awaiting_approval', 'armed')`
          )
          .run(now.toISOString(), body.retestRunId);
        if (runResult.changes !== 1) throw new Error("REMEDIATION_DIRECT_RETEST_COMPENSATION_RACE");
      }
      this.audit.append("remediation.direct-retest-preparation-abandoned", {
        remediationId,
        requestId: body.requestId,
        parentRunId: body.parentRunId,
        retestRunId: body.retestRunId,
        approvalId: body.approvalId,
        proposalId: body.proposalId,
        actor,
        approvalStatusBefore: prepared.approval_status,
        runStatusBefore: prepared.run_status
      }, now);
    });
  }

  getDirectRetestBinding(remediationId: string, requestId: string): DirectRetestBinding {
    const row = this.database
      .prepare(
        `SELECT request_id, remediation_id, parent_run_id, retest_run_id, approval_id, proposal_id,
                bound_by, bound_at
         FROM remediation_direct_retest_bindings
         WHERE remediation_id = ? AND request_id = ?`
      )
      .get(uuidSchema.parse(remediationId), uuidSchema.parse(requestId)) as
      | {
          request_id: string;
          remediation_id: string;
          parent_run_id: string;
          retest_run_id: string;
          approval_id: string;
          proposal_id: string;
          bound_by: string;
          bound_at: string;
        }
      | undefined;
    if (!row) throw new Error("REMEDIATION_DIRECT_RETEST_NOT_BOUND");
    return {
      requestId: row.request_id,
      remediationId: row.remediation_id,
      parentRunId: row.parent_run_id,
      retestRunId: row.retest_run_id,
      approvalId: row.approval_id,
      proposalId: row.proposal_id,
      boundBy: row.bound_by,
      boundAt: row.bound_at
    };
  }

  recordRetestOutcome(
    remediationId: string,
    input: RetestOutcomeInput,
    actorInput: string,
    now = new Date()
  ): RemediationRecord {
    const body = retestOutcomeInputSchema.parse(input);
    const actor = personSchema.parse(actorInput);
    const current = this.get(remediationId, now);
    this.assertAcceptedFinding(current.findingId);
    const retest = current.retests.find((item) => item.requestId === body.requestId);
    if (!retest) throw new Error("REMEDIATION_RETEST_NOT_FOUND");
    if (retest.outcome) throw new Error("REMEDIATION_RETEST_ALREADY_RESOLVED");
    if (current.status !== "retest-pending") throw new Error("REMEDIATION_RETEST_STATE_INVALID");
    assertRetestOutcome(retest.baselineStatus, body.outcome);
    const sourceRunIds = this.acceptedFindingRunIds(current.findingId);
    const references = sourceRunIds.length > 0
      ? this.validateDirectRetestEvidence(current, body.requestId, body.evidenceArtifactIds)
      : this.validateEvidence(body.evidenceArtifactIds, current.missionId);
    this.transact(() => {
      this.appendEvent(
        { id: current.id, findingId: current.findingId, missionId: current.missionId },
        "retest-outcome-recorded",
        {
          requestId: body.requestId,
          outcome: body.outcome,
          summary: body.summary,
          reviewer: body.reviewer,
          artifactIds: body.evidenceArtifactIds
        },
        actor,
        now,
        "retest",
        references
      );
    });
    return this.get(current.id, now);
  }

  get(remediationIdInput: string, now = new Date()): RemediationRecord {
    const remediationId = uuidSchema.parse(remediationIdInput);
    const row = this.remediationRow(remediationId);
    const events = this.loadVerifiedEvents(row);
    return this.buildRecord(row, events, now);
  }

  getForFinding(findingIdInput: string, now = new Date()): RemediationRecord {
    const findingId = uuidSchema.parse(findingIdInput);
    const row = this.database
      .prepare("SELECT id FROM remediation_records WHERE finding_id = ?")
      .get(findingId) as { id: string } | undefined;
    if (!row) throw new Error("REMEDIATION_NOT_FOUND");
    return this.get(row.id, now);
  }

  list(missionIdInput?: string, now = new Date()): RemediationRecord[] {
    const missionId = missionIdInput ? uuidSchema.parse(missionIdInput) : undefined;
    const rows = (missionId
      ? this.database
          .prepare("SELECT id FROM remediation_records WHERE mission_id = ? ORDER BY created_at DESC, id DESC LIMIT 200")
          .all(missionId)
      : this.database
          .prepare("SELECT id FROM remediation_records ORDER BY created_at DESC, id DESC LIMIT 200")
          .all()) as unknown as Array<{ id: string }>;
    return rows.map((row) => this.get(row.id, now));
  }

  verifyHistory(remediationIdInput: string): boolean {
    try {
      const remediationId = uuidSchema.parse(remediationIdInput);
      const row = this.remediationRow(remediationId);
      const events = this.loadVerifiedEvents(row);
      this.buildRecord(row, events, new Date());
      return true;
    } catch {
      return false;
    }
  }

  private appendInTransaction(
    current: RemediationRecord,
    type: RemediationEventType,
    payload: Record<string, unknown>,
    actor: string,
    now: Date
  ): void {
    this.transact(() => {
      this.appendEvent(
        { id: current.id, findingId: current.findingId, missionId: current.missionId },
        type,
        payload,
        actor,
        now
      );
    });
  }

  private appendEvent(
    remediation: { id: string; findingId: string; missionId: string },
    type: RemediationEventType,
    payloadInput: unknown,
    actor: string,
    now: Date,
    evidencePurpose?: "fix" | "retest",
    evidenceReferences: readonly EvidenceReference[] = []
  ): string {
    const payload = eventPayloadSchemas[type].parse(payloadInput) as Record<string, unknown>;
    const payloadJson = stableJson(payload);
    if (Buffer.byteLength(payloadJson, "utf8") > 32_768) throw new Error("REMEDIATION_EVENT_TOO_LARGE");
    const latest = this.database
      .prepare(
        `SELECT sequence, event_hash
         FROM remediation_events WHERE remediation_id = ?
         ORDER BY sequence DESC LIMIT 1`
      )
      .get(remediation.id) as { sequence: number; event_hash: string } | undefined;
    const sequence = (latest?.sequence ?? 0) + 1;
    if (sequence > 2_000) throw new Error("REMEDIATION_HISTORY_LIMIT_REACHED");
    const previousHash = latest?.event_hash ?? GENESIS_HASH;
    const occurredAt = now.toISOString();
    const eventHash = remediationEventHash(
      previousHash,
      remediation.id,
      sequence,
      occurredAt,
      type,
      actor,
      payloadJson
    );
    const eventId = randomUUID();
    this.database
      .prepare(
        `INSERT INTO remediation_events(
           id, remediation_id, sequence, event_type, payload_json, payload_hash,
           actor, occurred_at, previous_event_hash, event_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        eventId,
        remediation.id,
        sequence,
        type,
        payloadJson,
        canonicalHash(payload),
        actor,
        occurredAt,
        previousHash,
        eventHash
      );
    if (evidenceReferences.length > 0 && !evidencePurpose) {
      throw new Error("REMEDIATION_EVIDENCE_PURPOSE_INVALID");
    }
    for (const reference of evidenceReferences) {
      this.database
        .prepare(
          `INSERT INTO remediation_evidence_links(
             remediation_event_id, artifact_id, observation_id, purpose
          ) VALUES (?, ?, ?, ?)`
        )
        .run(eventId, reference.artifactId, reference.observationId, evidencePurpose!);
    }
    this.audit.append(
      `remediation.${type}`,
      {
        remediationId: remediation.id,
        findingId: remediation.findingId,
        missionId: remediation.missionId,
        eventId,
        sequence,
        eventHash,
        actor,
        evidenceCount: evidenceReferences.length
      },
      now
    );
    return eventId;
  }

  private validateEvidence(artifactIds: readonly string[], missionId: string): EvidenceReference[] {
    return artifactIds.map((artifactId) => {
      if (!this.evidence.verify(artifactId)) throw new Error("REMEDIATION_EVIDENCE_INVALID");
      try {
        const observation = this.evidence.observationForMission(artifactId, missionId);
        if (!this.evidence.verifyObservation(observation.id, artifactId, missionId)) {
          throw new Error("REMEDIATION_EVIDENCE_INVALID");
        }
        return { artifactId, observationId: observation.id };
      } catch {
        throw new Error("REMEDIATION_EVIDENCE_MISSION_MISMATCH");
      }
    });
  }

  private validateFixEvidence(
    artifactIds: readonly string[],
    remediation: RemediationRecord,
    now: Date
  ): EvidenceReference[] {
    const findingEvidence = this.acceptedFindingEvidenceIds(remediation.findingId);
    if (artifactIds.some((artifactId) => findingEvidence.has(artifactId))) {
      throw new Error("REMEDIATION_FIX_EVIDENCE_REUSES_FINDING");
    }
    const references = this.validateEvidence(artifactIds, remediation.missionId);
    const sourceRunBacked = this.acceptedFindingRunIds(remediation.findingId).length > 0;
    for (const reference of references) {
      const observation = this.database
        .prepare(
          `SELECT provenance_json, captured_at FROM evidence_observations
           WHERE id = ? AND artifact_id = ? AND mission_id = ?`
        )
        .get(reference.observationId, reference.artifactId, remediation.missionId) as
        | { provenance_json: string; captured_at: string }
        | undefined;
      if (!observation || new Date(observation.captured_at).getTime() < new Date(remediation.createdAt).getTime()) {
        throw new Error("REMEDIATION_FIX_EVIDENCE_PRE_ACTION");
      }
      if (new Date(observation.captured_at).getTime() > now.getTime() + MAX_CLOCK_SKEW_MS) {
        throw new Error("REMEDIATION_FIX_EVIDENCE_TIME_INVALID");
      }
      if (sourceRunBacked) {
        const provenance = JSON.parse(observation.provenance_json) as {
          source?: Record<string, unknown>;
        };
        if (
          provenance.source?.sourceType !== "operator-remediation-fix" ||
          provenance.source.remediationId !== remediation.id ||
          provenance.source.findingId !== remediation.findingId ||
          provenance.source.actionPerformedAt !== observation.captured_at
        ) {
          throw new Error("REMEDIATION_FIX_EVIDENCE_PROVENANCE_INVALID");
        }
      }
    }
    return references;
  }

  private validateDirectRetestEvidence(
    remediation: RemediationRecord,
    requestId: string,
    artifactIds: readonly string[]
  ): EvidenceReference[] {
    const binding = this.getDirectRetestBinding(remediation.id, requestId);
    const run = this.database
      .prepare(
        `SELECT child.status, child.mission_id, child.parent_run_id, child.lineage_type,
                child_proposal.proposal_json AS child_proposal_json,
                parent_proposal.proposal_json AS parent_proposal_json,
                approval.status AS approval_status, approval.consumed_at AS approval_consumed_at,
                approval.requested_at AS approval_requested_at, approval.expires_at AS approval_expires_at
         FROM runs child
         JOIN runs parent ON parent.id = child.parent_run_id
         JOIN proposals child_proposal ON child_proposal.id = ? AND child_proposal.run_id = child.id
         JOIN proposals parent_proposal ON parent_proposal.run_id = parent.id
         JOIN approval_requests approval
           ON approval.id = ? AND approval.proposal_id = child_proposal.id
          AND approval.proposal_hash = child_proposal.proposal_hash
          AND approval.policy_version = child_proposal.policy_version
          AND approval.tool_schema_hash = child_proposal.tool_schema_hash
         JOIN approval_execution_bindings execution_binding
           ON execution_binding.approval_id = approval.id
          AND execution_binding.run_id = child.id
          AND execution_binding.mission_id = child.mission_id
          AND execution_binding.target_id = child_proposal.target_id
         WHERE child.id = ? AND parent.id = ?
         ORDER BY parent_proposal.created_at DESC LIMIT 1`
      )
      .get(binding.proposalId, binding.approvalId, binding.retestRunId, binding.parentRunId) as
      | {
          status: string;
          mission_id: string;
          parent_run_id: string;
          lineage_type: string;
          child_proposal_json: string;
          parent_proposal_json: string;
          approval_status: string;
          approval_consumed_at: string | null;
          approval_requested_at: string;
          approval_expires_at: string;
        }
      | undefined;
    const consumedAt = run?.approval_consumed_at ? new Date(run.approval_consumed_at) : null;
    const requestedAt = run ? new Date(run.approval_requested_at) : null;
    const expiresAt = run ? new Date(run.approval_expires_at) : null;
    const boundAt = new Date(binding.boundAt);
    if (
      !run ||
      run.status !== "succeeded" ||
      run.mission_id !== remediation.missionId ||
      run.parent_run_id !== binding.parentRunId ||
      run.lineage_type !== "retest" ||
      run.approval_status !== "consumed" ||
      !consumedAt ||
      !requestedAt ||
      !expiresAt ||
      !Number.isFinite(consumedAt.valueOf()) ||
      !Number.isFinite(requestedAt.valueOf()) ||
      !Number.isFinite(expiresAt.valueOf()) ||
      !Number.isFinite(boundAt.valueOf()) ||
      consumedAt < requestedAt ||
      consumedAt < boundAt ||
      consumedAt >= expiresAt ||
      !this.proposalsMatchForRetest(run.parent_proposal_json, run.child_proposal_json)
    ) {
      throw new Error("REMEDIATION_DIRECT_RETEST_RUN_INVALID");
    }
    const observed = this.database
      .prepare(
        `SELECT observation.id, observation.artifact_id, observation.source_event_id,
                observation.provenance_json, lifecycle.status AS lifecycle_status,
                lifecycle.mission_id AS lifecycle_mission_id, lifecycle.run_id AS lifecycle_run_id
         FROM evidence_observations observation
         LEFT JOIN execution_lifecycles lifecycle ON lifecycle.id = observation.source_event_id
         WHERE observation.mission_id = ? AND observation.run_id = ?
         ORDER BY observation.artifact_id, observation.recorded_at, observation.id`
      )
      .all(remediation.missionId, binding.retestRunId) as unknown as Array<{
        id: string;
        artifact_id: string;
        source_event_id: string | null;
        provenance_json: string;
        lifecycle_status: string | null;
        lifecycle_mission_id: string | null;
        lifecycle_run_id: string | null;
      }>;
    const expectedIds = [...new Set(observed.map((row) => row.artifact_id))].sort();
    const suppliedIds = [...artifactIds].sort();
    if (expectedIds.length < 1 || stableJson(expectedIds) !== stableJson(suppliedIds)) {
      throw new Error("REMEDIATION_DIRECT_RETEST_EVIDENCE_MISMATCH");
    }
    const prohibited = new Set([
      ...this.acceptedFindingEvidenceIds(remediation.findingId),
      ...remediation.fixEvidence.map((item) => item.artifactId)
    ]);
    if (expectedIds.some((artifactId) => prohibited.has(artifactId))) {
      throw new Error("REMEDIATION_DIRECT_RETEST_EVIDENCE_REUSED");
    }
    return expectedIds.map((artifactId) => {
      if (!this.evidence.verify(artifactId)) throw new Error("REMEDIATION_EVIDENCE_INVALID");
      const observation = observed.find((row) => {
        if (row.artifact_id !== artifactId || !row.source_event_id) return false;
        try {
          const provenance = JSON.parse(row.provenance_json) as { source?: Record<string, unknown> };
          return (
            provenance.source?.sourceType === "restricted-target-execution" &&
            provenance.source.approvalId === binding.approvalId &&
            provenance.source.executionId === row.source_event_id &&
            row.lifecycle_status === "succeeded" &&
            row.lifecycle_mission_id === remediation.missionId &&
            row.lifecycle_run_id === binding.retestRunId
          );
        } catch {
          return false;
        }
      });
      if (
        !observation ||
        !this.evidence.verifyObservation(observation.id, artifactId, remediation.missionId)
      ) {
        throw new Error("REMEDIATION_DIRECT_RETEST_EVIDENCE_MISMATCH");
      }
      return { artifactId, observationId: observation.id };
    });
  }

  private acceptedFindingEvidenceIds(findingId: string): Set<string> {
    const rows = this.database
      .prepare(
        `SELECT feo.artifact_id
         FROM finding_revisions revision
         JOIN finding_evidence_observations feo ON feo.finding_revision_id = revision.id
         WHERE revision.id = (
           SELECT id FROM finding_revisions WHERE finding_id = ? ORDER BY revision DESC LIMIT 1
         )`
      )
      .all(findingId) as unknown as Array<{ artifact_id: string }>;
    return new Set(rows.map((row) => row.artifact_id));
  }

  private acceptedFindingRunIds(findingId: string): string[] {
    const rows = this.database
      .prepare(
        `SELECT DISTINCT observation.run_id
         FROM finding_revisions revision
         JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
         JOIN evidence_observations observation
           ON observation.id = citation.observation_id AND observation.artifact_id = citation.artifact_id
         WHERE revision.id = (
           SELECT id FROM finding_revisions WHERE finding_id = ? ORDER BY revision DESC LIMIT 1
         ) AND observation.run_id IS NOT NULL
         ORDER BY observation.run_id`
      )
      .all(findingId) as unknown as Array<{ run_id: string }>;
    return rows.map((row) => row.run_id);
  }

  private proposalsMatchForRetest(parentJson: string, childJson: string): boolean {
    try {
      const parent = JSON.parse(parentJson) as Record<string, unknown>;
      const child = JSON.parse(childJson) as Record<string, unknown>;
      return stableJson({
        capabilityId: parent.capabilityId,
        targetId: parent.targetId,
        riskTier: parent.riskTier,
        timeoutMs: parent.timeoutMs,
        maxOutputBytes: parent.maxOutputBytes,
        parameters: parent.parameters
      }) === stableJson({
        capabilityId: child.capabilityId,
        targetId: child.targetId,
        riskTier: child.riskTier,
        timeoutMs: child.timeoutMs,
        maxOutputBytes: child.maxOutputBytes,
        parameters: child.parameters
      });
    } catch {
      return false;
    }
  }

  private assertAcceptedFinding(findingId: string): { id: string; mission_id: string } {
    const finding = this.database
      .prepare("SELECT id, mission_id, status FROM findings WHERE id = ?")
      .get(findingId) as { id: string; mission_id: string; status: string } | undefined;
    if (!finding) throw new Error("FINDING_NOT_FOUND");
    if (finding.status !== "accepted") throw new Error("REMEDIATION_ACCEPTED_FINDING_REQUIRED");
    return finding;
  }

  private remediationRow(remediationId: string): RemediationRow {
    const row = this.database
      .prepare(
        `SELECT rr.id, rr.finding_id, rr.mission_id, rr.created_at,
                f.title AS finding_title, f.status AS finding_status
         FROM remediation_records rr
         JOIN findings f ON f.id = rr.finding_id AND f.mission_id = rr.mission_id
         WHERE rr.id = ?`
      )
      .get(remediationId) as RemediationRow | undefined;
    if (!row) throw new Error("REMEDIATION_NOT_FOUND");
    return row;
  }

  private loadVerifiedEvents(row: RemediationRow): VerifiedEvent[] {
    const eventRows = this.database
      .prepare("SELECT * FROM remediation_events WHERE remediation_id = ? ORDER BY sequence")
      .all(row.id) as unknown as RemediationEventRow[];
    if (eventRows.length < 1 || eventRows[0]!.event_type !== "created") {
      throw new Error("REMEDIATION_HISTORY_INVALID");
    }
    const linkRows = this.database
      .prepare(
        `SELECT rel.*
         FROM remediation_evidence_links rel
         JOIN remediation_events re ON re.id = rel.remediation_event_id
         WHERE re.remediation_id = ?
         ORDER BY re.sequence, rel.artifact_id`
      )
      .all(row.id) as unknown as RemediationEvidenceLinkRow[];
    const linksByEvent = new Map<string, RemediationEvidenceLinkRow[]>();
    for (const link of linkRows) {
      const links = linksByEvent.get(link.remediation_event_id) ?? [];
      links.push(link);
      linksByEvent.set(link.remediation_event_id, links);
    }

    let previousHash = GENESIS_HASH;
    const verified: VerifiedEvent[] = [];
    for (const [index, event] of eventRows.entries()) {
      let type: RemediationEventType;
      let parsedJson: unknown;
      let payload: Record<string, unknown>;
      try {
        type = remediationEventTypeSchema.parse(event.event_type);
        parsedJson = JSON.parse(event.payload_json);
        payload = eventPayloadSchemas[type].parse(parsedJson) as Record<string, unknown>;
      } catch {
        throw new Error("REMEDIATION_HISTORY_INVALID");
      }
      const expectedHash = remediationEventHash(
        previousHash,
        row.id,
        event.sequence,
        event.occurred_at,
        type,
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
        throw new Error("REMEDIATION_HISTORY_INVALID");
      }
      const links = linksByEvent.get(event.id) ?? [];
      const expectedPurpose = type === "fix-evidence-added" ? "fix" : type === "retest-outcome-recorded" ? "retest" : null;
      const payloadArtifactIds =
        type === "fix-evidence-added" || type === "retest-outcome-recorded"
          ? ([...(payload.artifactIds as string[])].sort())
          : [];
      if (
        (expectedPurpose === null && links.length !== 0) ||
        links.some((link) => link.purpose !== expectedPurpose) ||
        stableJson(links.map((link) => link.artifact_id).sort()) !== stableJson(payloadArtifactIds)
      ) {
        throw new Error("REMEDIATION_EVIDENCE_LINK_INVALID");
      }
      for (const link of links) {
        if (
          !this.evidence.verify(link.artifact_id) ||
          !this.evidence.verifyObservation(link.observation_id, link.artifact_id, row.mission_id)
        ) {
          throw new Error("REMEDIATION_EVIDENCE_INVALID");
        }
      }
      verified.push({
        id: event.id,
        sequence: event.sequence,
        type,
        payload,
        actor: event.actor,
        occurredAt: event.occurred_at,
        eventHash: event.event_hash,
        evidence: links.map((link) => ({ artifactId: link.artifact_id, observationId: link.observation_id }))
      });
      previousHash = event.event_hash;
    }
    if (verified.filter((event) => event.type === "created").length !== 1) {
      throw new Error("REMEDIATION_HISTORY_INVALID");
    }
    return verified;
  }

  private buildRecord(row: RemediationRow, events: VerifiedEvent[], now: Date): RemediationRecord {
    const created = events[0]!;
    const initial = asPayload<{
      owner: string;
      dueDate: string;
      priority: RemediationPriority;
      status: "open";
    }>(created);
    const state: MutableState = {
      owner: initial.owner,
      dueDate: initial.dueDate,
      priority: initial.priority,
      status: initial.status,
      regressionState: "not-assessed",
      riskAcceptance: null,
      fixEvidence: [],
      retests: [],
      reviewerComments: []
    };

    for (const event of events.slice(1)) {
      switch (event.type) {
        case "created":
          throw new Error("REMEDIATION_HISTORY_INVALID");
        case "owner-changed": {
          const payload = asPayload<{ from: string; to: string }>(event);
          if (payload.from !== state.owner || payload.to === state.owner) throw new Error("REMEDIATION_HISTORY_INVALID");
          state.owner = payload.to;
          break;
        }
        case "due-date-changed": {
          const payload = asPayload<{ from: string; to: string }>(event);
          if (payload.from !== state.dueDate || payload.to === state.dueDate) throw new Error("REMEDIATION_HISTORY_INVALID");
          state.dueDate = payload.to;
          break;
        }
        case "priority-changed": {
          const payload = asPayload<{ from: RemediationPriority; to: RemediationPriority }>(event);
          if (payload.from !== state.priority || payload.to === state.priority) {
            throw new Error("REMEDIATION_HISTORY_INVALID");
          }
          state.priority = payload.to;
          break;
        }
        case "status-changed": {
          const payload = asPayload<{ from: RemediationStatus; to: RemediationStatus }>(event);
          if (payload.from !== state.status) throw new Error("REMEDIATION_HISTORY_INVALID");
          assertManualTransition(payload.from, payload.to);
          state.status = payload.to;
          break;
        }
        case "reviewer-commented": {
          const payload = asPayload<{ reviewer: string; comment: string }>(event);
          state.reviewerComments.push({
            eventId: event.id,
            reviewer: payload.reviewer,
            comment: payload.comment,
            recordedBy: event.actor,
            recordedAt: event.occurredAt
          });
          break;
        }
        case "risk-acceptance-recorded": {
          const payload = asPayload<{
            acceptanceId: string;
            reason: string;
            reviewer: string;
            expiresAt: string;
          }>(event);
          if (
            state.riskAcceptance &&
            state.riskAcceptance.status !== "revoked" &&
            new Date(state.riskAcceptance.expiresAt).getTime() > new Date(event.occurredAt).getTime()
          ) {
            throw new Error("REMEDIATION_HISTORY_INVALID");
          }
          state.riskAcceptance = {
            ...payload,
            recordedBy: event.actor,
            recordedAt: event.occurredAt,
            status: "active"
          };
          break;
        }
        case "risk-acceptance-revoked": {
          const payload = asPayload<{ acceptanceId: string; reason: string }>(event);
          if (
            !state.riskAcceptance ||
            state.riskAcceptance.acceptanceId !== payload.acceptanceId ||
            state.riskAcceptance.status === "revoked"
          ) {
            throw new Error("REMEDIATION_HISTORY_INVALID");
          }
          state.riskAcceptance = {
            ...state.riskAcceptance,
            status: "revoked",
            revokedBy: event.actor,
            revokedAt: event.occurredAt,
            revocationReason: payload.reason
          };
          break;
        }
        case "fix-evidence-added": {
          const payload = asPayload<{ artifactIds: string[]; note: string }>(event);
          for (const reference of event.evidence) {
            state.fixEvidence.push({
              eventId: event.id,
              ...reference,
              note: payload.note,
              addedBy: event.actor,
              addedAt: event.occurredAt
            });
          }
          break;
        }
        case "retest-requested": {
          const payload = asPayload<{
            requestId: string;
            reason: string;
            baselineStatus: RemediationStatus;
          }>(event);
          if (
            payload.baselineStatus !== state.status ||
            !retestEligibleStatuses.has(state.status) ||
            state.retests.some((item) => !item.outcome)
          ) {
            throw new Error("REMEDIATION_HISTORY_INVALID");
          }
          const directRetest = this.directRetestForRequest(row.id, payload.requestId);
          state.retests.push({
            requestId: payload.requestId,
            reason: payload.reason,
            requestedBy: event.actor,
            requestedAt: event.occurredAt,
            baselineStatus: payload.baselineStatus,
            evidence: [],
            ...(directRetest ? { directRetest } : {})
          });
          state.status = "retest-pending";
          break;
        }
        case "retest-outcome-recorded": {
          const payload = asPayload<{
            requestId: string;
            outcome: RetestOutcome;
            summary: string;
            reviewer: string;
            artifactIds: string[];
          }>(event);
          const index = state.retests.findIndex((item) => item.requestId === payload.requestId);
          const request = state.retests[index];
          if (!request || request.outcome || state.status !== "retest-pending") {
            throw new Error("REMEDIATION_HISTORY_INVALID");
          }
          assertRetestOutcome(request.baselineStatus, payload.outcome);
          state.retests[index] = {
            ...request,
            outcome: payload.outcome,
            summary: payload.summary,
            reviewer: payload.reviewer,
            outcomeRecordedBy: event.actor,
            outcomeRecordedAt: event.occurredAt,
            evidence: event.evidence
          };
          state.status = payload.outcome;
          if (payload.outcome === "remediated") state.regressionState = "not-regressed";
          if (payload.outcome === "regressed") state.regressionState = "regressed";
          if (payload.outcome === "inconclusive") state.regressionState = "inconclusive";
          break;
        }
      }
    }

    if (
      state.riskAcceptance &&
      state.riskAcceptance.status !== "revoked" &&
      new Date(state.riskAcceptance.expiresAt).getTime() <= now.getTime()
    ) {
      state.riskAcceptance = { ...state.riskAcceptance, status: "expired" };
    }

    return {
      id: row.id,
      findingId: row.finding_id,
      missionId: row.mission_id,
      findingTitle: row.finding_title,
      findingStatus: row.finding_status,
      owner: state.owner,
      dueDate: state.dueDate,
      priority: state.priority,
      status: state.status,
      regressionState: state.regressionState,
      riskAcceptance: state.riskAcceptance,
      fixEvidence: state.fixEvidence,
      retests: state.retests,
      reviewerComments: state.reviewerComments,
      history: events,
      createdAt: row.created_at,
      integrityValid: true,
      claimLimitation:
        "Remediation state records reviewed workflow decisions. Only same-mission verified evidence and an explicit retest outcome can support remediated, persists or regressed status; the finding is never changed automatically."
    };
  }

  private transact<T>(action: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = action();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private directRetestForRequest(remediationId: string, requestId: string): DirectRetestBinding | null {
    try {
      return this.getDirectRetestBinding(remediationId, requestId);
    } catch (error) {
      if (error instanceof Error && error.message === "REMEDIATION_DIRECT_RETEST_NOT_BOUND") return null;
      throw error;
    }
  }
}
