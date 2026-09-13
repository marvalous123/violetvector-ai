import type {
  AdapterHealth, BrokerExecutionRequest, CancellationResult,
  EmergencyStopResult, LifecycleEvent
} from "./schemas.js";

export interface ExecutionHandle {
  readonly executionId: string;
  readonly events: AsyncIterable<LifecycleEvent>;
  cancel(reason: "operator" | "emergency-stop" | "budget-exhausted"): Promise<CancellationResult>;
}

export interface McpwnAdapter {
  health(): Promise<AdapterHealth>;
  start(request: BrokerExecutionRequest): Promise<ExecutionHandle>;
}

export interface ExecutionBroker {
  submit(request: BrokerExecutionRequest): Promise<ExecutionHandle>;
  cancel(
    executionId: string,
    reason: "operator" | "emergency-stop" | "budget-exhausted"
  ): Promise<CancellationResult>;
  emergencyStop(requestedBy: string): Promise<EmergencyStopResult>;
}
