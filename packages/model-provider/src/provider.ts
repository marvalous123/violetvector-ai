import type {
  EvidenceSummaryOutput,
  FindingDraftOutput,
  ModelTaskRequest,
  StructuredPlanOutput
} from "./schemas.js";

export type ModelTaskProfile = ModelTaskRequest["profile"];

export interface ModelCapabilities {
  readonly provider: "ollama";
  readonly taskTier: "T0";
  readonly profiles: readonly ModelTaskProfile[];
  readonly structuredOutput: true;
  readonly toolAccess: false;
  readonly filesystemAccess: false;
  readonly commandAccess: false;
  readonly mcpAccess: false;
  readonly targetNetworkAccess: false;
}

export interface ModelHealth {
  readonly healthy: boolean;
  readonly provider: "ollama";
  readonly baseUrl: string;
  readonly model: string;
  readonly version?: string;
  readonly latencyMs: number;
  readonly checkedAt: string;
  readonly error?: string;
}

export interface ModelMetadata {
  readonly provider: "ollama";
  readonly model: string;
  readonly profile: ModelTaskProfile;
  readonly taskTier: "T0";
  readonly authority: "none";
  readonly latencyMs: number;
  readonly usage: {
    readonly inputTokens: number | null;
    readonly outputTokens: number | null;
  };
  readonly providerDurationsNs: {
    readonly total: number | null;
    readonly load: number | null;
    readonly promptEvaluation: number | null;
    readonly evaluation: number | null;
  };
}

export type ModelTaskOutput =
  | StructuredPlanOutput
  | EvidenceSummaryOutput
  | FindingDraftOutput;

export interface ModelTaskResult<TOutput extends ModelTaskOutput = ModelTaskOutput> {
  readonly output: TOutput;
  readonly metadata: ModelMetadata;
}

export interface ModelGenerationControl {
  readonly signal?: AbortSignal;
}

export interface ModelProvider {
  health(): Promise<ModelHealth>;
  capabilities(): ModelCapabilities;
  generate(request: ModelTaskRequest, control?: ModelGenerationControl): Promise<ModelTaskResult>;
}

export class ModelProviderError extends Error {
  constructor(
    message: string,
    readonly code:
      | "CONFIG_INVALID"
      | "INPUT_LIMIT_EXCEEDED"
      | "OUTPUT_LIMIT_EXCEEDED"
      | "PROVIDER_UNAVAILABLE"
      | "PROVIDER_RESPONSE_INVALID"
      | "STRUCTURED_OUTPUT_INVALID"
      | "REQUEST_ABORTED"
      | "REQUEST_TIMED_OUT",
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "ModelProviderError";
  }
}
