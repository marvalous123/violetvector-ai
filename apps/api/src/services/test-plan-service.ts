import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import { BLUE_RULES } from "./blue-detection-service.js";
import { buildCapabilityCatalogue } from "./capability-catalogue.js";
import type { EvidenceService } from "./evidence-service.js";

const personSchema = z.string().trim().min(2).max(120);
const narrativeSchema = z.string().trim().min(10).max(4_000);
const procedureStateSchema = z.enum(["completed", "skipped", "blocked", "not-applicable"]);
const procedureKeySchema = z.string().regex(/^[a-z0-9][a-z0-9._-]{1,79}$/);
const mappingIdSchema = z.string().trim().min(2).max(120);
const evidenceIdSchema = z
  .array(z.string().uuid())
  .max(16)
  .refine((ids) => new Set(ids).size === ids.length, "Evidence artifact IDs must be unique");

export const testPlanProcedureInputSchema = z
  .object({
    key: procedureKeySchema,
    title: z.string().trim().min(5).max(160),
    objective: narrativeSchema,
    steps: z.array(z.string().trim().min(5).max(1_000)).min(1).max(20),
    state: procedureStateSchema,
    rationale: narrativeSchema,
    capabilityId: mappingIdSchema.nullable().optional(),
    blueRuleId: mappingIdSchema.nullable().optional(),
    runId: z.string().uuid().nullable().optional(),
    evidenceArtifactIds: evidenceIdSchema.default([])
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.capabilityId && !value.blueRuleId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Each procedure must map to a capability or Blue rule"
      });
    }
    if (value.state === "completed" && value.evidenceArtifactIds.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Completed procedures require verified evidence"
      });
    }
  });

export const createTestPlanVersionInputSchema = z
  .object({
    missionId: z.string().uuid(),
    title: z.string().trim().min(5).max(160),
    objective: narrativeSchema,
    expectedPreviousPlanId: z.string().uuid().nullable().optional(),
    procedures: z.array(testPlanProcedureInputSchema).min(1).max(200),
    createdBy: personSchema
  })
  .strict()
  .superRefine((value, context) => {
    const keys = value.procedures.map((procedure) => procedure.key);
    if (new Set(keys).size !== keys.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "Procedure keys must be unique" });
    }
  });

export type TestPlanProcedureState = z.infer<typeof procedureStateSchema>;
export type CreateTestPlanVersionInput = z.input<typeof createTestPlanVersionInputSchema>;

interface PlanRow {
  id: string;
  mission_id: string;
  version: number;
  title: string;
  objective: string;
  supersedes_plan_id: string | null;
  procedure_count: number;
  content_hash: string;
  created_by: string;
  created_at: string;
}

interface ProcedureRow {
  id: string;
  plan_id: string;
  procedure_key: string;
  ordinal: number;
  title: string;
  objective: string;
  procedure_json: string;
  state: TestPlanProcedureState;
  rationale: string;
  capability_id: string | null;
  blue_rule_id: string | null;
  run_id: string | null;
  evidence_count: number;
  created_at: string;
}

interface ProcedureEvidenceRow {
  procedure_id: string;
  artifact_id: string;
  observation_id: string;
  artifact_sha256: string;
}

interface EvidenceReference {
  readonly artifactId: string;
  readonly observationId: string;
  readonly sha256: string;
}

export interface TestPlanProcedure {
  readonly id: string;
  readonly key: string;
  readonly ordinal: number;
  readonly title: string;
  readonly objective: string;
  readonly steps: readonly string[];
  readonly state: TestPlanProcedureState;
  readonly rationale: string;
  readonly capabilityId: string | null;
  readonly blueRuleId: string | null;
  readonly runId: string | null;
  readonly evidence: readonly EvidenceReference[];
}

export interface EngagementTestPlan {
  readonly id: string;
  readonly missionId: string;
  readonly version: number;
  readonly title: string;
  readonly objective: string;
  readonly supersedesPlanId: string | null;
  readonly contentHash: string;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly procedures: readonly TestPlanProcedure[];
  readonly summary: Readonly<Record<TestPlanProcedureState, number>>;
  readonly integrityValid: boolean;
  readonly claimLimitation: string;
}

const capabilityIds = new Set(
  buildCapabilityCatalogue({
    targetExecutionEnabled: true,
    versionProofEnabled: true,
    emergencyStopState: "ready",
    edition: "professional"
  }).map((capability) => capability.id)
);
const blueRuleIds = new Set(BLUE_RULES.map((rule) => rule.id));

function planHashMaterial(input: {
  missionId: string;
  title: string;
  objective: string;
  procedures: ReadonlyArray<{
    key: string;
    ordinal: number;
    title: string;
    objective: string;
    steps: readonly string[];
    state: TestPlanProcedureState;
    rationale: string;
    capabilityId: string | null;
    blueRuleId: string | null;
    runId: string | null;
    evidence: readonly EvidenceReference[];
  }>;
}): string {
  return canonicalHash(input);
}

export class TestPlanService {
  private readonly audit: AuditService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    audit?: AuditService
  ) {
    this.audit = audit ?? new AuditService(database);
  }

  createVersion(inputValue: CreateTestPlanVersionInput, now = new Date()): EngagementTestPlan {
    const input = createTestPlanVersionInputSchema.parse(inputValue);
    this.assertMission(input.missionId);
    const previous = this.latestRow(input.missionId);
    const expectedPrevious = input.expectedPreviousPlanId ?? null;
    if ((previous?.id ?? null) !== expectedPrevious) throw new Error("TEST_PLAN_VERSION_CONFLICT");

    const version = (previous?.version ?? 0) + 1;
    const preparedProcedures = input.procedures.map((procedure, index) => {
      const capabilityId = procedure.capabilityId ?? null;
      const blueRuleId = procedure.blueRuleId ?? null;
      if (capabilityId && !capabilityIds.has(capabilityId)) throw new Error("TEST_PLAN_CAPABILITY_UNKNOWN");
      if (blueRuleId && !blueRuleIds.has(blueRuleId)) throw new Error("TEST_PLAN_BLUE_RULE_UNKNOWN");
      if (procedure.runId) this.assertRunMission(procedure.runId, input.missionId);
      const references = procedure.evidenceArtifactIds.map((artifactId) => {
        if (!this.evidence.verify(artifactId)) throw new Error("TEST_PLAN_EVIDENCE_INVALID");
        const observations = this.evidence
          .observations(artifactId, input.missionId)
          .filter((observation) =>
            this.evidence.verifyObservation(observation.id, artifactId, input.missionId)
          );
        const observation = procedure.runId
          ? observations.find((candidate) => candidate.run_id === procedure.runId)
          : observations.at(-1);
        if (!observation) {
          if (procedure.runId) throw new Error("TEST_PLAN_RUN_EVIDENCE_REQUIRED");
          throw new Error("TEST_PLAN_EVIDENCE_MISSION_MISMATCH");
        }
        return {
          artifactId,
          observationId: observation.id,
          sha256: this.evidence.get(artifactId).sha256,
          runId: observation.run_id
        };
      });
      if (
        procedure.state === "completed" &&
        procedure.runId &&
        !references.some((reference) => reference.runId === procedure.runId)
      ) {
        throw new Error("TEST_PLAN_RUN_EVIDENCE_REQUIRED");
      }
      return {
        key: procedure.key,
        ordinal: index + 1,
        title: procedure.title,
        objective: procedure.objective,
        steps: procedure.steps,
        state: procedure.state,
        rationale: procedure.rationale,
        capabilityId,
        blueRuleId,
        runId: procedure.runId ?? null,
        evidence: references.map(({ runId: _runId, ...reference }) => reference)
      };
    });

    const planId = randomUUID();
    const contentHash = planHashMaterial({
      missionId: input.missionId,
      title: input.title,
      objective: input.objective,
      procedures: preparedProcedures
    });
    if (
      this.database
        .prepare("SELECT id FROM engagement_test_plans WHERE mission_id = ? AND content_hash = ?")
        .get(input.missionId, contentHash)
    ) {
      throw new Error("TEST_PLAN_NO_CHANGE");
    }

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO engagement_test_plans(
             id, mission_id, version, title, objective, supersedes_plan_id,
             procedure_count, content_hash, created_by, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          planId,
          input.missionId,
          version,
          input.title,
          input.objective,
          previous?.id ?? null,
          preparedProcedures.length,
          contentHash,
          input.createdBy,
          now.toISOString()
        );
      for (const procedure of preparedProcedures) {
        const procedureId = randomUUID();
        this.database
          .prepare(
            `INSERT INTO test_plan_procedures(
               id, plan_id, procedure_key, ordinal, title, objective, procedure_json,
               state, rationale, capability_id, blue_rule_id, run_id, evidence_count, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            procedureId,
            planId,
            procedure.key,
            procedure.ordinal,
            procedure.title,
            procedure.objective,
            stableJson({ steps: procedure.steps }),
            procedure.state,
            procedure.rationale,
            procedure.capabilityId,
            procedure.blueRuleId,
            procedure.runId,
            procedure.evidence.length,
            now.toISOString()
          );
        for (const reference of procedure.evidence) {
          this.database
            .prepare(
              `INSERT INTO test_plan_procedure_evidence(
                 procedure_id, artifact_id, observation_id, artifact_sha256
               ) VALUES (?, ?, ?, ?)`
            )
            .run(procedureId, reference.artifactId, reference.observationId, reference.sha256);
        }
      }
      this.audit.append(
        "test_plan.version.created",
        {
          planId,
          missionId: input.missionId,
          version,
          supersedesPlanId: previous?.id ?? null,
          procedureCount: preparedProcedures.length,
          contentHash,
          createdBy: input.createdBy
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(planId);
  }

  latest(missionId: string): EngagementTestPlan {
    this.assertMission(missionId);
    const row = this.latestRow(missionId);
    if (!row) throw new Error("TEST_PLAN_NOT_FOUND");
    return this.toPlan(row);
  }

  list(missionId: string, limit = 25): EngagementTestPlan[] {
    this.assertMission(missionId);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("TEST_PLAN_LIMIT_INVALID");
    const rows = this.database
      .prepare(
        `SELECT * FROM engagement_test_plans
         WHERE mission_id = ? ORDER BY version DESC LIMIT ?`
      )
      .all(missionId, limit) as unknown as PlanRow[];
    return rows.map((row) => this.toPlan(row));
  }

  get(planId: string): EngagementTestPlan {
    const row = this.database
      .prepare("SELECT * FROM engagement_test_plans WHERE id = ?")
      .get(planId) as unknown as PlanRow | undefined;
    if (!row) throw new Error("TEST_PLAN_NOT_FOUND");
    return this.toPlan(row);
  }

  private latestRow(missionId: string): PlanRow | undefined {
    return this.database
      .prepare(
        `SELECT * FROM engagement_test_plans
         WHERE mission_id = ? ORDER BY version DESC LIMIT 1`
      )
      .get(missionId) as unknown as PlanRow | undefined;
  }

  private toPlan(row: PlanRow): EngagementTestPlan {
    const procedures = this.database
      .prepare(
        `SELECT * FROM test_plan_procedures
         WHERE plan_id = ? ORDER BY ordinal`
      )
      .all(row.id) as unknown as ProcedureRow[];
    const evidenceRows = this.database
      .prepare(
        `SELECT evidence.*
         FROM test_plan_procedure_evidence evidence
         JOIN test_plan_procedures procedure ON procedure.id = evidence.procedure_id
         WHERE procedure.plan_id = ?
         ORDER BY procedure.ordinal, evidence.artifact_sha256`
      )
      .all(row.id) as unknown as ProcedureEvidenceRow[];
    const evidenceByProcedure = new Map<string, EvidenceReference[]>();
    for (const evidence of evidenceRows) {
      const references = evidenceByProcedure.get(evidence.procedure_id) ?? [];
      references.push({
        artifactId: evidence.artifact_id,
        observationId: evidence.observation_id,
        sha256: evidence.artifact_sha256
      });
      evidenceByProcedure.set(evidence.procedure_id, references);
    }
    const mapped = procedures.map((procedure): TestPlanProcedure => {
      const parsed = z.object({ steps: z.array(z.string()).min(1).max(20) }).strict().parse(
        JSON.parse(procedure.procedure_json)
      );
      return {
        id: procedure.id,
        key: procedure.procedure_key,
        ordinal: procedure.ordinal,
        title: procedure.title,
        objective: procedure.objective,
        steps: parsed.steps,
        state: procedure.state,
        rationale: procedure.rationale,
        capabilityId: procedure.capability_id,
        blueRuleId: procedure.blue_rule_id,
        runId: procedure.run_id,
        evidence: evidenceByProcedure.get(procedure.id) ?? []
      };
    });
    const contentHash = planHashMaterial({
      missionId: row.mission_id,
      title: row.title,
      objective: row.objective,
      procedures: mapped.map((procedure) => ({
        key: procedure.key,
        ordinal: procedure.ordinal,
        title: procedure.title,
        objective: procedure.objective,
        steps: procedure.steps,
        state: procedure.state,
        rationale: procedure.rationale,
        capabilityId: procedure.capabilityId,
        blueRuleId: procedure.blueRuleId,
        runId: procedure.runId,
        evidence: procedure.evidence
      }))
    });
    const summary: Record<TestPlanProcedureState, number> = {
      completed: 0,
      skipped: 0,
      blocked: 0,
      "not-applicable": 0
    };
    for (const procedure of mapped) summary[procedure.state] += 1;
    const evidenceValid = mapped.every((procedure) =>
      procedure.evidence.every(
        (reference) =>
          this.evidence.verify(reference.artifactId) &&
          this.evidence.verifyObservation(reference.observationId, reference.artifactId, row.mission_id) &&
          this.evidence.get(reference.artifactId).sha256 === reference.sha256
      )
    );
    return {
      id: row.id,
      missionId: row.mission_id,
      version: row.version,
      title: row.title,
      objective: row.objective,
      supersedesPlanId: row.supersedes_plan_id,
      contentHash: row.content_hash,
      createdBy: row.created_by,
      createdAt: row.created_at,
      procedures: mapped,
      summary,
      integrityValid:
        row.procedure_count === mapped.length &&
        row.content_hash === contentHash &&
        evidenceValid &&
        procedures.every(
          (procedure) =>
            procedure.evidence_count === (evidenceByProcedure.get(procedure.id)?.length ?? 0) &&
            (procedure.state !== "completed" || procedure.evidence_count > 0)
        ),
      claimLimitation:
        "Procedure dispositions describe this immutable plan version only. Skipped, blocked, not-applicable and absent findings are not evidence that a target is secure."
    };
  }

  private assertMission(missionId: string): void {
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
  }

  private assertRunMission(runId: string, missionId: string): void {
    const run = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as
      | { mission_id: string }
      | undefined;
    if (!run) throw new Error("TEST_PLAN_RUN_NOT_FOUND");
    if (run.mission_id !== missionId) throw new Error("TEST_PLAN_RUN_MISSION_MISMATCH");
  }
}
