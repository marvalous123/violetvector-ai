export const DEFAULT_LOCAL_AI_MODEL = "vega-war-room:latest" as const;

export const SUPPORTED_LOCAL_AI_MODELS = [
  DEFAULT_LOCAL_AI_MODEL,
  "gpt-oss:20b"
] as const;

export type SupportedLocalAiModel = (typeof SUPPORTED_LOCAL_AI_MODELS)[number];

const supportedModelNames = new Set<string>(SUPPORTED_LOCAL_AI_MODELS);

export function resolveLocalAiModel(
  configuredModel: string | undefined = process.env.WAR_ROOM_OLLAMA_MODEL
): SupportedLocalAiModel {
  if (configuredModel === undefined) return DEFAULT_LOCAL_AI_MODEL;
  const candidate = configuredModel.trim();
  if (!supportedModelNames.has(candidate)) throw new Error("LOCAL_AI_MODEL_NOT_ALLOWED");
  return candidate as SupportedLocalAiModel;
}

export const LOCAL_AI_PROVIDER_LIMITS = Object.freeze({
  baseUrl: "http://127.0.0.1:11434",
  timeoutMs: 90_000,
  maxInputChars: 48_000,
  maxResponseBytes: 256_000,
  maxContextTokens: 4_096,
  maxOutputTokens: 700
});
