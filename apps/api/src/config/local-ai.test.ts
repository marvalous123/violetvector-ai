import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DEFAULT_LOCAL_AI_MODEL,
  LOCAL_AI_PROVIDER_LIMITS,
  resolveLocalAiModel,
  SUPPORTED_LOCAL_AI_MODELS
} from "./local-ai.js";

describe("Local AI configuration", () => {
  it("defaults to the guarded WAR-R00M gpt-oss profile", () => {
    assert.equal(resolveLocalAiModel(undefined), "vega-war-room:latest");
    assert.equal(DEFAULT_LOCAL_AI_MODEL, "vega-war-room:latest");
    assert.deepEqual(SUPPORTED_LOCAL_AI_MODELS, [
      "vega-war-room:latest",
      "gpt-oss:20b"
    ]);
  });

  it("permits only the exact reviewed gpt-oss model names", () => {
    assert.equal(resolveLocalAiModel(" vega-war-room:latest "), "vega-war-room:latest");
    assert.equal(resolveLocalAiModel("gpt-oss:20b"), "gpt-oss:20b");
    for (const rejected of ["", "llama3.2:3b", "gpt-oss:latest", "unreviewed-model:latest"]) {
      assert.throws(
        () => resolveLocalAiModel(rejected),
        (error: unknown) => error instanceof Error && error.message === "LOCAL_AI_MODEL_NOT_ALLOWED"
      );
    }
  });

  it("keeps the provider loopback-only and bounded", () => {
    assert.equal(LOCAL_AI_PROVIDER_LIMITS.baseUrl, "http://127.0.0.1:11434");
    assert.equal(LOCAL_AI_PROVIDER_LIMITS.timeoutMs, 90_000);
    assert.equal(LOCAL_AI_PROVIDER_LIMITS.maxContextTokens, 4_096);
    assert.equal(LOCAL_AI_PROVIDER_LIMITS.maxOutputTokens, 700);
  });
});
