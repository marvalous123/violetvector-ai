import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  ModelProviderError,
  type ModelHealth,
  type ModelProvider,
  type ModelTaskRequest,
  type ModelTaskResult,
  type StructuredPlanOutput
} from "@war-room/model-provider";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import { MissionService } from "./mission-service.js";
import { RunControlService } from "./run-control-service.js";

const PROFILE = "structured-planning";
const PROMPT_TEMPLATE_HASH = sha256("project15:t0-structured-planning:v1");
const OUTPUT_SCHEMA_HASH = sha256("project15:structured-plan-output:v1");

export interface StoredModelInvocation {
  id: string;
  mission_id: string;
  run_id: string;
  task_profile: string;
  provider: string;
  model: string;
  status: "started" | "succeeded" | "failed" | "rejected";
  prompt_tokens: number | null;
  completion_tokens: number | null;
  latency_ms: number | null;
  result_json: string | null;
  error_code: string | null;
  created_at: string;
  completed_at: string | null;
}

export class ModelService {
  private readonly audit: AuditService;
  private readonly missions: MissionService;
  private readonly controls: RunControlService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly provider: ModelProvider,
    audit?: AuditService
  ) {
    this.audit = audit ?? new AuditService(database);
    this.missions = new MissionService(database, this.audit);
    this.controls = new RunControlService(database, this.audit);
  }

  health(): Promise<ModelHealth> {
    return this.provider.health();
  }

  listInvocations(): StoredModelInvocation[] {
    return this.database
      .prepare(
        `SELECT id, mission_id, run_id, task_profile, provider, model, status, prompt_tokens,
                completion_tokens, latency_ms, result_json, error_code, created_at, completed_at
         FROM model_invocations ORDER BY created_at DESC LIMIT 100`
      )
      .all() as unknown as StoredModelInvocation[];
  }

  async createPlan(input: {
    missionId: string;
    objective: string;
    signal?: AbortSignal;
    now?: Date;
  }): Promise<{ invocation: StoredModelInvocation; plan: StructuredPlanOutput }> {
    const now = input.now ?? new Date();
    this.controls.assertReady();
    const cleanObjective = input.objective.trim();
    if (cleanObjective.length < 5 || cleanObjective.length > 2_000) throw new Error("MODEL_OBJECTIVE_INVALID");
    const mission = this.missions.getMission(input.missionId);
    const scope = this.missions.getLatestScope(mission.id);
    if (now < new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) throw new Error("SCOPE_NOT_ACTIVE");

    const providerCapabilities = this.provider.capabilities();
    if (
      providerCapabilities.taskTier !== "T0" ||
      providerCapabilities.toolAccess ||
      providerCapabilities.commandAccess ||
      providerCapabilities.mcpAccess ||
      providerCapabilities.targetNetworkAccess
    ) {
      throw new Error("MODEL_AUTHORITY_INVALID");
    }

    const request: ModelTaskRequest = {
      profile: PROFILE,
      input: {
        objective: cleanObjective,
        authorizedScopeSummary: stableJson({
          missionId: mission.id,
          scopeVersionId: scope.scopeVersionId,
          startsAt: scope.startsAt,
          expiresAt: scope.expiresAt,
          targets: scope.targets.map((target) => ({ targetId: target.id, classification: "authorized-exact-target" }))
        }),
        capabilitySummaries: [
          "Advisory planning only. No commands, tool calls, targets, URLs, or action envelopes may be emitted."
        ]
      }
    };
    const invocationId = randomUUID();
    const runId = this.controls.createRun({
      missionId: mission.id,
      budget: {
        // The 20B local model has a 90-second provider timeout; retain a small
        // bounded margin for response parsing and usage-ledger bookkeeping.
        wallTimeMsLimit: 95_000,
        toolTimeMsLimit: 1,
        modelTokensLimit: 6_000,
        outputBytesLimit: 256_000,
        requestCountLimit: 1
      },
      now
    });
    this.database
      .prepare("UPDATE runs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'")
      .run(now.toISOString(), runId);
    const createdAt = now.toISOString();
    const requestHash = canonicalHash(request);
    this.database
      .prepare(
        `INSERT INTO model_invocations(
           id, mission_id, run_id, task_profile, provider, model, status, request_hash,
           prompt_template_hash, output_schema_hash, input_characters, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'started', ?, ?, ?, ?, ?)`
      )
      .run(
        invocationId,
        mission.id,
        runId,
        PROFILE,
        providerCapabilities.provider,
        "pinned-local-model",
        requestHash,
        PROMPT_TEMPLATE_HASH,
        OUTPUT_SCHEMA_HASH,
        stableJson(request).length,
        createdAt
      );
    this.audit.append(
      "model.invocation.started",
      { invocationId, missionId: mission.id, runId, profile: PROFILE, requestHash },
      now
    );

    try {
      const result = (await this.provider.generate(
        request,
        input.signal ? { signal: input.signal } : {}
      )) as ModelTaskResult<StructuredPlanOutput>;
      const completedAt = new Date();
      const resultJson = stableJson(result.output);
      if (input.signal?.aborted) throw new Error("MODEL_REQUEST_ABORTED");
      this.controls.assertReady();
      const inputTokens = result.metadata.usage.inputTokens ?? 0;
      const outputTokens = result.metadata.usage.outputTokens ?? 0;
      this.controls.recordUsage(
        runId,
        {
          wallTimeMs: Math.round(result.metadata.latencyMs),
          modelTokens: inputTokens + outputTokens,
          outputBytes: Buffer.byteLength(resultJson, "utf8"),
          requestCount: 1
        },
        "t0-model-invocation",
        completedAt
      );
      this.database
        .prepare(
          `UPDATE model_invocations
           SET status = 'succeeded', model = ?, output_characters = ?, prompt_tokens = ?,
               completion_tokens = ?, latency_ms = ?, result_json = ?, completed_at = ?
           WHERE id = ? AND status = 'started'`
        )
        .run(
          result.metadata.model,
          resultJson.length,
          result.metadata.usage.inputTokens,
          result.metadata.usage.outputTokens,
          Math.round(result.metadata.latencyMs),
          resultJson,
          completedAt.toISOString(),
          invocationId
        );
      this.database
        .prepare("UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ? AND status = 'running'")
        .run(completedAt.toISOString(), runId);
      this.audit.append(
        "model.invocation.succeeded",
        {
          invocationId,
          runId,
          outputHash: sha256(resultJson),
          usage: result.metadata.usage,
          latencyMs: result.metadata.latencyMs
        },
        completedAt
      );
      return { invocation: this.getInvocation(invocationId), plan: result.output };
    } catch (error) {
      const completedAt = new Date();
      const errorCode = error instanceof ModelProviderError
        ? error.code
        : error instanceof Error
          ? error.message.split(":")[0]!.slice(0, 120)
          : "MODEL_FAILED";
      this.database
        .prepare(
          `UPDATE model_invocations
           SET status = 'failed', error_code = ?, completed_at = ?
           WHERE id = ? AND status = 'started'`
        )
        .run(errorCode, completedAt.toISOString(), invocationId);
      this.database
        .prepare("UPDATE runs SET status = 'failed', updated_at = ? WHERE id = ? AND status = 'running'")
        .run(completedAt.toISOString(), runId);
      this.audit.append("model.invocation.failed", { invocationId, runId, errorCode }, completedAt);
      throw new Error(errorCode, { cause: error });
    }
  }

  private getInvocation(id: string): StoredModelInvocation {
    const row = this.database
      .prepare(
        `SELECT id, mission_id, run_id, task_profile, provider, model, status, prompt_tokens,
                completion_tokens, latency_ms, result_json, error_code, created_at, completed_at
         FROM model_invocations WHERE id = ?`
      )
      .get(id) as unknown as StoredModelInvocation | undefined;
    if (!row) throw new Error("MODEL_INVOCATION_NOT_FOUND");
    return row;
  }
}
