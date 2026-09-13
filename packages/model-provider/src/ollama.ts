import type { z } from "zod";
import { buildPrompt, outputJsonSchema, SYSTEM_PROMPT } from "./prompts.js";
import {
  ModelProviderError,
  type ModelCapabilities,
  type ModelGenerationControl,
  type ModelHealth,
  type ModelProvider,
  type ModelTaskOutput,
  type ModelTaskResult
} from "./provider.js";
import {
  evidenceSummaryOutputSchema,
  findingDraftOutputSchema,
  modelTaskRequestSchema,
  ollamaChatResponseSchema,
  ollamaConfigSchema,
  ollamaVersionResponseSchema,
  structuredPlanOutputSchema,
  type ModelTaskRequest,
  type ResolvedOllamaConfig
} from "./schemas.js";

const PROFILES = ["structured-planning", "evidence-summary", "finding-draft"] as const;

export class OllamaModelProvider implements ModelProvider {
  readonly #config: ResolvedOllamaConfig;
  readonly #fetch: typeof fetch;

  constructor(config: z.input<typeof ollamaConfigSchema>, fetchImplementation: typeof fetch = fetch) {
    const parsed = ollamaConfigSchema.safeParse(config);
    if (!parsed.success) {
      throw new ModelProviderError("Invalid Ollama provider configuration", "CONFIG_INVALID", {
        cause: parsed.error
      });
    }
    this.#config = parsed.data;
    this.#fetch = fetchImplementation;
  }

  capabilities(): ModelCapabilities {
    return {
      provider: "ollama",
      taskTier: "T0",
      profiles: PROFILES,
      structuredOutput: true,
      toolAccess: false,
      filesystemAccess: false,
      commandAccess: false,
      mcpAccess: false,
      targetNetworkAccess: false
    };
  }

  async health(): Promise<ModelHealth> {
    const startedAt = performance.now();
    const checkedAt = new Date().toISOString();
    try {
      const body = await this.#requestJson("/api/version", { method: "GET" });
      const version = ollamaVersionResponseSchema.parse(body).version;
      return {
        healthy: true,
        provider: "ollama",
        baseUrl: this.#config.baseUrl,
        model: this.#config.model,
        version,
        latencyMs: elapsedMs(startedAt),
        checkedAt
      };
    } catch (error) {
      return {
        healthy: false,
        provider: "ollama",
        baseUrl: this.#config.baseUrl,
        model: this.#config.model,
        latencyMs: elapsedMs(startedAt),
        checkedAt,
        error: safeErrorMessage(error)
      };
    }
  }

  async generate(untrustedRequest: ModelTaskRequest, control: ModelGenerationControl = {}): Promise<ModelTaskResult> {
    const request = modelTaskRequestSchema.parse(untrustedRequest);
    const userPrompt = buildPrompt(request);
    const inputChars = SYSTEM_PROMPT.length + userPrompt.length;
    if (inputChars > this.#config.maxInputChars) {
      throw new ModelProviderError(
        `Model input exceeds the ${this.#config.maxInputChars} character limit`,
        "INPUT_LIMIT_EXCEEDED"
      );
    }

    const startedAt = performance.now();
    const rawBody = await this.#requestJson("/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: this.#config.model,
        stream: false,
        // GPT-OSS requires an explicit low/medium/high thinking level. The
        // bounded trace is parsed and discarded; only strict final JSON leaves
        // the provider.
        think: this.#config.thinkingLevel,
        keep_alive: 0,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userPrompt }
        ],
        format: outputJsonSchema(request),
        options: {
          num_ctx: this.#config.maxContextTokens,
          num_predict: this.#config.maxOutputTokens,
          temperature: 0
        }
      })
    }, control.signal);
    const providerResponse = parseOrProviderError(ollamaChatResponseSchema, rawBody);
    const output = parseStructuredOutput(request, providerResponse.message.content);
    validateEvidenceReferences(request, output);

    return {
      output,
      metadata: {
        provider: "ollama",
        model: providerResponse.model,
        profile: request.profile,
        taskTier: "T0",
        authority: "none",
        latencyMs: elapsedMs(startedAt),
        usage: {
          inputTokens: providerResponse.prompt_eval_count ?? null,
          outputTokens: providerResponse.eval_count ?? null
        },
        providerDurationsNs: {
          total: providerResponse.total_duration ?? null,
          load: providerResponse.load_duration ?? null,
          promptEvaluation: providerResponse.prompt_eval_duration ?? null,
          evaluation: providerResponse.eval_duration ?? null
        }
      }
    };
  }

  async #requestJson(path: "/api/version" | "/api/chat", init: RequestInit, externalSignal?: AbortSignal): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#config.timeoutMs);
    const abortFromExternal = () => controller.abort();
    externalSignal?.addEventListener("abort", abortFromExternal, { once: true });
    if (externalSignal?.aborted) controller.abort();
    try {
      const response = await this.#fetch(new URL(path, normalizedBaseUrl(this.#config.baseUrl)), {
        ...init,
        signal: controller.signal,
        redirect: "error"
      });
      if (!response.ok) {
        throw new ModelProviderError(
          `Ollama returned HTTP ${response.status}`,
          "PROVIDER_UNAVAILABLE"
        );
      }
      return await readBoundedJson(response, this.#config.maxResponseBytes);
    } catch (error) {
      if (error instanceof ModelProviderError) throw error;
      if (externalSignal?.aborted) {
        throw new ModelProviderError("Ollama request was cancelled", "REQUEST_ABORTED", {
          cause: error
        });
      }
      if (controller.signal.aborted) {
        throw new ModelProviderError("Ollama request timed out", "REQUEST_TIMED_OUT", {
          cause: error
        });
      }
      throw new ModelProviderError("Ollama is unavailable", "PROVIDER_UNAVAILABLE", {
        cause: error
      });
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromExternal);
    }
  }
}

function validateEvidenceReferences(request: ModelTaskRequest, output: ModelTaskOutput): void {
  if (request.profile === "structured-planning") return;
  const allowedIds = new Set(request.input.evidence.map((item) => item.id));
  const references =
    request.profile === "evidence-summary"
      ? [
          ...outputEvidenceRefs(output, "facts"),
          ...outputEvidenceRefs(output, "candidateFindings")
        ]
      : outputEvidenceRefs(output, "finding");
  if (references.some((reference) => !allowedIds.has(reference))) {
    throw new ModelProviderError(
      "Ollama output referenced evidence that was not supplied",
      "STRUCTURED_OUTPUT_INVALID"
    );
  }
}

function outputEvidenceRefs(
  output: ModelTaskOutput,
  source: "facts" | "candidateFindings" | "finding"
): string[] {
  if (source === "facts" && "facts" in output) {
    return output.facts.flatMap((fact) => fact.evidenceRefs);
  }
  if (source === "candidateFindings" && "candidateFindings" in output) {
    return output.candidateFindings.flatMap((finding) => finding.evidenceRefs);
  }
  return "evidenceRefs" in output ? output.evidenceRefs : [];
}

function parseStructuredOutput(request: ModelTaskRequest, content: string): ModelTaskOutput {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch (error) {
    throw new ModelProviderError("Ollama returned invalid JSON", "STRUCTURED_OUTPUT_INVALID", {
      cause: error
    });
  }
  const schema =
    request.profile === "structured-planning"
      ? structuredPlanOutputSchema
      : request.profile === "evidence-summary"
        ? evidenceSummaryOutputSchema
        : findingDraftOutputSchema;
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    throw new ModelProviderError(
      "Ollama output did not match the strict advisory schema",
      "STRUCTURED_OUTPUT_INVALID",
      { cause: parsed.error }
    );
  }
  return parsed.data;
}

function parseOrProviderError<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new ModelProviderError(
      "Ollama returned an invalid response envelope",
      "PROVIDER_RESPONSE_INVALID",
      { cause: parsed.error }
    );
  }
  return parsed.data;
}

async function readBoundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    await response.body?.cancel();
    throw new ModelProviderError("Ollama response exceeded its byte limit", "OUTPUT_LIMIT_EXCEEDED");
  }
  if (!response.body) {
    throw new ModelProviderError("Ollama response had no body", "PROVIDER_RESPONSE_INVALID");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteCount = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteCount += value.byteLength;
      if (byteCount > maximumBytes) {
        await reader.cancel();
        throw new ModelProviderError(
          "Ollama response exceeded its byte limit",
          "OUTPUT_LIMIT_EXCEEDED"
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(byteCount);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new ModelProviderError("Ollama response was not valid JSON", "PROVIDER_RESPONSE_INVALID", {
      cause: error
    });
  }
}

function normalizedBaseUrl(baseUrl: string): URL {
  return new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Math.round((performance.now() - startedAt) * 100) / 100);
}

function safeErrorMessage(error: unknown): string {
  return error instanceof ModelProviderError ? error.message : "Ollama health check failed";
}
