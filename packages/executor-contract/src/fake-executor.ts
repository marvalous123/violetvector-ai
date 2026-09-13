import { createHash } from "node:crypto";
import { EXECUTOR_SCHEMA_HASH } from "./canonical.js";
import type { ExecutionHandle, McpwnAdapter } from "./contract.js";
import {
  adapterHealthSchema,
  cancellationResultSchema,
  evidenceMetadataSchema,
  lifecycleEventSchema,
  MAX_OUTPUT_CHUNK_BYTES,
  outputChunkSchema,
  type AdapterHealth,
  type BrokerExecutionRequest,
  type CancellationResult,
  type LifecycleEvent
} from "./schemas.js";
import { validateBrokerExecutionRequest } from "./validate.js";

export type FakeExecutionPlan =
  | { outcome: "success"; output?: readonly string[] }
  | { outcome: "timeout"; output?: readonly string[] }
  | { outcome: "await-cancel"; output?: readonly string[] };

class EventQueue implements AsyncIterable<LifecycleEvent> {
  private readonly queued: LifecycleEvent[] = [];
  private readonly waiters: Array<(result: IteratorResult<LifecycleEvent>) => void> = [];
  private closed = false;

  push(event: LifecycleEvent): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter({ value: event, done: false });
    else this.queued.push(event);
  }

  close(): void {
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) waiter({ value: undefined, done: true });
  }

  [Symbol.asyncIterator](): AsyncIterator<LifecycleEvent> {
    return {
      next: async () => {
        const event = this.queued.shift();
        if (event) return { value: event, done: false };
        if (this.closed) return { value: undefined, done: true };
        return new Promise<IteratorResult<LifecycleEvent>>((resolve) => this.waiters.push(resolve));
      }
    };
  }
}

function timestamp(offsetMs: number): string {
  return new Date(Date.parse("2026-01-01T00:00:00.000Z") + offsetMs).toISOString();
}

type FakeState = { queue: EventQueue; outputBytes: number; terminal: boolean };

export class FakeExecutor implements McpwnAdapter {
  readonly didSpawnProcess = false;
  readonly didOpenNetworkConnection = false;
  private readonly plans = new Map<string, FakeExecutionPlan>();
  private readonly active = new Map<string, FakeState>();

  constructor(plans: Readonly<Record<string, FakeExecutionPlan>> = {}) {
    for (const [proposalId, plan] of Object.entries(plans)) this.plans.set(proposalId, plan);
  }

  async health(): Promise<AdapterHealth> {
    return adapterHealthSchema.parse({
      adapterId: "mcpwn-adapter",
      instanceId: "fake-executor-1",
      status: "ready",
      contractVersion: "executor-contract.v2",
      schemaHash: EXECUTOR_SCHEMA_HASH,
      capabilities: [
        "mcpwn.nmap.host-discovery.v1",
        "mcpwn.nmap.service-version.v1",
        "mcpwn.nmap.tcp-port-discovery.v1",
        "mcpwn.nmap.tcp-port-state.v1",
        "mcpwn.nmap.http-metadata.v1",
        "mcpwn.nmap.tls-certificate.v1",
        "mcpwn.nmap.tls-ciphers.v1"
      ],
      checkedAt: timestamp(0),
      executionEnabled: false
    });
  }

  async start(input: BrokerExecutionRequest): Promise<ExecutionHandle> {
    const request = validateBrokerExecutionRequest(input, new Date(input.submittedAt));
    if (this.active.has(request.executionId)) throw new Error("Duplicate executionId");

    const state: FakeState = { queue: new EventQueue(), outputBytes: 0, terminal: false };
    this.active.set(request.executionId, state);
    const plan = this.plans.get(request.proposal.proposalId) ?? { outcome: "success", output: [] };
    state.queue.push(lifecycleEventSchema.parse({
      type: "accepted", executionId: request.executionId, occurredAt: timestamp(1)
    }));
    state.queue.push(lifecycleEventSchema.parse({
      type: "started", executionId: request.executionId, occurredAt: timestamp(2),
      adapterInstanceId: "fake-executor-1"
    }));
    this.emitOutput(request, plan.output ?? [], state);
    if (plan.outcome === "success") this.complete(request, state);
    if (plan.outcome === "timeout") this.timeout(request, state);

    return {
      executionId: request.executionId,
      events: state.queue,
      cancel: async (reason) => this.cancel(request.executionId, reason)
    };
  }

  private emitOutput(request: BrokerExecutionRequest, output: readonly string[], state: FakeState): void {
    output.forEach((content, sequence) => {
      const contentBytes = Buffer.byteLength(content, "utf8");
      if (contentBytes > MAX_OUTPUT_CHUNK_BYTES) throw new Error("Fake output chunk exceeds contract limit");
      const remaining = request.limits.maxOutputBytes - state.outputBytes;
      const accepted = remaining > 0 ? truncateUtf8(content, remaining) : "";
      const acceptedBytes = Buffer.byteLength(accepted, "utf8");
      state.outputBytes += acceptedBytes;
      state.queue.push(lifecycleEventSchema.parse({
        type: "output",
        executionId: request.executionId,
        occurredAt: timestamp(3 + sequence),
        chunk: outputChunkSchema.parse({
          sequence, stream: "stdout", encoding: "utf8", content: accepted,
          contentBytes: acceptedBytes, cumulativeOutputBytes: state.outputBytes,
          truncated: acceptedBytes < contentBytes
        })
      }));
    });
  }

  private complete(request: BrokerExecutionRequest, state: FakeState): void {
    const content = JSON.stringify({
      executionId: request.executionId, result: "fake-success", outputBytes: state.outputBytes
    });
    const evidence = evidenceMetadataSchema.parse({
      evidenceId: `evidence-${request.executionId}`,
      executionId: request.executionId,
      sha256: createHash("sha256").update(content).digest("hex"),
      byteLength: Buffer.byteLength(content),
      mediaType: "application/json",
      storageKey: `fake/${request.executionId}.json`,
      createdAt: timestamp(20)
    });
    state.queue.push(lifecycleEventSchema.parse({
      type: "evidence_stored", executionId: request.executionId, occurredAt: timestamp(20), evidence
    }));
    state.queue.push(lifecycleEventSchema.parse({
      type: "completed", executionId: request.executionId, occurredAt: timestamp(21),
      durationMs: 20, outputBytes: state.outputBytes, evidenceIds: [evidence.evidenceId]
    }));
    state.terminal = true;
    state.queue.close();
  }

  private timeout(request: BrokerExecutionRequest, state: FakeState): void {
    state.queue.push(lifecycleEventSchema.parse({
      type: "timed_out", executionId: request.executionId,
      occurredAt: timestamp(request.limits.timeoutMs),
      durationMs: request.limits.timeoutMs, outputBytes: state.outputBytes
    }));
    state.terminal = true;
    state.queue.close();
  }

  private async cancel(
    executionId: string,
    reason: "operator" | "emergency-stop" | "budget-exhausted"
  ): Promise<CancellationResult> {
    const state = this.active.get(executionId);
    const requestedAt = timestamp(30);
    if (!state) return cancellationResultSchema.parse({ executionId, status: "not-found", requestedAt });
    if (state.terminal) {
      return cancellationResultSchema.parse({ executionId, status: "already-terminal", requestedAt });
    }
    state.queue.push(lifecycleEventSchema.parse({
      type: "cancelled", executionId, occurredAt: requestedAt, reason, outputBytes: state.outputBytes
    }));
    state.terminal = true;
    state.queue.close();
    return cancellationResultSchema.parse({ executionId, status: "cancel-requested", requestedAt });
  }
}

function truncateUtf8(value: string, maxBytes: number): string {
  let result = Buffer.from(value, "utf8").subarray(0, maxBytes).toString("utf8");
  if (result.endsWith("\uFFFD")) result = result.slice(0, -1);
  return result;
}
