import type {
  VersionExecutionResult,
  VersionExecutorStatus,
  VersionOnlyExecutor
} from "@war-room/executor-contract";
import { MCPWN_VERSION_CAPABILITY } from "@war-room/executor-contract";
import { stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { ArtifactRow, EvidenceService } from "./evidence-service.js";
import type {
  ExecutionLifecycleRecord,
  ExecutionLifecycleStatus,
  ExecutionLifecycleService
} from "./execution-lifecycle-service.js";
import type { RunControlService } from "./run-control-service.js";

export interface VersionExecutionRecord {
  execution: VersionExecutionResult;
  artifact: ArtifactRow;
}

function safeFailureCode(error: unknown): string {
  if (typeof error !== "object" || error === null) return "EXECUTOR_FAILED";
  const code = Reflect.get(error, "code");
  if (typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)) return code;
  const message = Reflect.get(error, "message");
  if (typeof message === "string") {
    const prefix = message.split(":")[0];
    if (prefix && /^[A-Z][A-Z0-9_]{0,63}$/.test(prefix)) return prefix;
  }
  return "EXECUTOR_FAILED";
}

/**
 * API-facing orchestration for the single network-free diagnostic capability.
 * This service has no target, command, tool-name or argument input.
 */
export class VersionExecutionService {
  readonly #active = new Map<string, { controller: AbortController; lifecycleId: string }>();

  constructor(
    private readonly executor: VersionOnlyExecutor,
    private readonly controls: RunControlService,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService,
    private readonly lifecycles: ExecutionLifecycleService
  ) {}

  status(): Promise<VersionExecutorStatus> {
    return this.executor.status();
  }

  activeCount(): number {
    return this.#active.size;
  }

  abortAll(): number {
    const count = this.#active.size;
    for (const { controller, lifecycleId } of this.#active.values()) {
      const lifecycle = this.lifecycles.get(lifecycleId);
      if (["queued", "starting", "running"].includes(lifecycle.status)) {
        this.lifecycles.transition(lifecycleId, "cancel_requested", {
          reasonCode: "EMERGENCY_STOP"
        });
      }
      controller.abort();
    }
    return count;
  }

  async execute(operator: string): Promise<VersionExecutionRecord> {
    this.controls.assertReady();
    if (this.#active.size > 0) throw new Error("EXECUTOR_BUSY");

    const controller = new AbortController();
    const lifecycle = this.lifecycles.create({
      capabilityId: MCPWN_VERSION_CAPABILITY,
      operator
    });
    const requestId = lifecycle.id;
    this.#active.set(requestId, { controller, lifecycleId: lifecycle.id });
    this.audit.append("executor.version.requested", {
      requestId,
      capabilityId: MCPWN_VERSION_CAPABILITY,
      operator
    });

    try {
      this.lifecycles.transition(lifecycle.id, "starting");
      this.lifecycles.transition(lifecycle.id, "running");
      const execution = await this.executor.executeVersion({ signal: controller.signal });
      this.controls.assertReady();
      if (controller.signal.aborted) throw new Error("EXECUTION_CANCELLED");

      const artifact = this.evidence.seal(stableJson(execution.output), "application/json");
      this.audit.append("executor.version.completed", {
        requestId,
        executionId: execution.executionId,
        capabilityId: execution.capabilityId,
        operator,
        artifactId: artifact.id,
        artifactSha256: artifact.sha256,
        outputBytes: execution.outputBytes,
        durationMs: execution.durationMs,
        binarySha256: execution.binarySha256,
        configSha256: execution.configSha256
      });
      this.lifecycles.transition(lifecycle.id, "succeeded");
      return { execution, artifact };
    } catch (error) {
      this.finishFailure(lifecycle.id, safeFailureCode(error));
      this.audit.append("executor.version.failed", {
        requestId,
        capabilityId: MCPWN_VERSION_CAPABILITY,
        operator,
        failureCode: safeFailureCode(error)
      });
      throw error;
    } finally {
      this.#active.delete(requestId);
    }
  }

  private finishFailure(executionId: string, failureCode: string): ExecutionLifecycleRecord {
    const current = this.lifecycles.get(executionId);
    let nextStatus: ExecutionLifecycleStatus = "failed";
    let reasonCode = failureCode;
    if (current.status === "cancel_requested" || failureCode.includes("CANCEL")) {
      if (current.status !== "cancel_requested") {
        this.lifecycles.transition(executionId, "cancel_requested", {
          reasonCode: "EXECUTION_CANCELLED"
        });
      }
      nextStatus = "cancelled";
      reasonCode = "PROCESS_TERMINATED";
    } else if (failureCode === "TIMED_OUT") {
      nextStatus = "timed_out";
    }
    return this.lifecycles.transition(executionId, nextStatus, { reasonCode });
  }
}
