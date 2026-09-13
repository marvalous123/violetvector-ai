import { z } from "zod";

const nonEmptyText = (maximum: number) => z.string().trim().min(1).max(maximum);
const evidenceReferenceSchema = nonEmptyText(128);

export const evidenceItemSchema = z
  .object({ id: evidenceReferenceSchema, content: nonEmptyText(12_000) })
  .strict();

export const structuredPlanInputSchema = z
  .object({
    objective: nonEmptyText(2_000),
    authorizedScopeSummary: nonEmptyText(4_000),
    capabilitySummaries: z.array(nonEmptyText(500)).max(32).default([])
  })
  .strict();

export const evidenceSummaryInputSchema = z
  .object({
    question: nonEmptyText(2_000),
    evidence: z.array(evidenceItemSchema).min(1).max(24)
  })
  .strict();

export const findingDraftInputSchema = z
  .object({
    observation: nonEmptyText(4_000),
    evidence: z.array(evidenceItemSchema).min(1).max(24)
  })
  .strict();

export const structuredPlanOutputSchema = z
  .object({
    objective: nonEmptyText(2_000),
    assumptions: z.array(nonEmptyText(500)).max(12),
    steps: z
      .array(
        z
          .object({
            description: nonEmptyText(1_000),
            rationale: nonEmptyText(1_000),
            requiresHumanReview: z.boolean()
          })
          .strict()
      )
      .max(20),
    openQuestions: z.array(nonEmptyText(500)).max(12)
  })
  .strict();

export const evidenceSummaryOutputSchema = z
  .object({
    facts: z
      .array(
        z
          .object({
            statement: nonEmptyText(1_000),
            evidenceRefs: z.array(evidenceReferenceSchema).min(1).max(12),
            uncertainty: nonEmptyText(500).nullable()
          })
          .strict()
      )
      .max(32),
    candidateFindings: z
      .array(
        z
          .object({
            title: nonEmptyText(300),
            evidenceRefs: z.array(evidenceReferenceSchema).min(1).max(12),
            confidence: z.enum(["low", "medium", "high"])
          })
          .strict()
      )
      .max(12),
    limitations: z.array(nonEmptyText(500)).max(12)
  })
  .strict();

export const findingDraftOutputSchema = z
  .object({
    title: nonEmptyText(300),
    summary: nonEmptyText(2_000),
    impact: nonEmptyText(2_000),
    remediation: nonEmptyText(2_000),
    evidenceRefs: z.array(evidenceReferenceSchema).min(1).max(24),
    confidence: z.enum(["low", "medium", "high"]),
    limitations: z.array(nonEmptyText(500)).max(12)
  })
  .strict();

export const modelTaskRequestSchema = z.discriminatedUnion("profile", [
  z.object({ profile: z.literal("structured-planning"), input: structuredPlanInputSchema }).strict(),
  z.object({ profile: z.literal("evidence-summary"), input: evidenceSummaryInputSchema }).strict(),
  z.object({ profile: z.literal("finding-draft"), input: findingDraftInputSchema }).strict()
]);

export const ollamaConfigSchema = z
  .object({
    baseUrl: z.string().url().default("http://127.0.0.1:11434"),
    model: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/),
    timeoutMs: z.number().int().min(100).max(120_000).default(30_000),
    maxInputChars: z.number().int().min(1_000).max(100_000).default(48_000),
    maxResponseBytes: z.number().int().min(1_024).max(2_000_000).default(256_000),
    maxContextTokens: z.number().int().min(512).max(8_192).default(4_096),
    maxOutputTokens: z.number().int().min(32).max(1_500).default(700),
    thinkingLevel: z.enum(["low", "medium", "high"]).default("low")
  })
  .strict()
  .superRefine((config, context) => {
    const url = new URL(config.baseUrl);
    const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
    if (url.protocol !== "http:" || !loopbackHosts.has(url.hostname)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["baseUrl"],
        message: "Ollama must use plain HTTP on an exact loopback host"
      });
    }
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.pathname !== "" && url.pathname !== "/")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["baseUrl"],
        message: "Ollama baseUrl cannot include credentials, paths, queries, or fragments"
      });
    }
  });

export const ollamaChatResponseSchema = z
  .object({
    model: nonEmptyText(128),
    created_at: z.string().max(128).optional(),
    message: z
      .object({
        role: z.literal("assistant"),
        content: z.string(),
        thinking: z.string().max(200_000).optional()
      })
      .strict(),
    done: z.literal(true),
    done_reason: z.string().max(128).optional(),
    total_duration: z.number().int().nonnegative().optional(),
    load_duration: z.number().int().nonnegative().optional(),
    prompt_eval_count: z.number().int().nonnegative().optional(),
    prompt_eval_duration: z.number().int().nonnegative().optional(),
    eval_count: z.number().int().nonnegative().optional(),
    eval_duration: z.number().int().nonnegative().optional()
  })
  .strict();

export const ollamaVersionResponseSchema = z.object({ version: nonEmptyText(128) }).strict();

export type ModelTaskRequest = z.infer<typeof modelTaskRequestSchema>;
export type StructuredPlanOutput = z.infer<typeof structuredPlanOutputSchema>;
export type EvidenceSummaryOutput = z.infer<typeof evidenceSummaryOutputSchema>;
export type FindingDraftOutput = z.infer<typeof findingDraftOutputSchema>;
export type OllamaConfig = z.input<typeof ollamaConfigSchema>;
export type ResolvedOllamaConfig = z.output<typeof ollamaConfigSchema>;
