import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { afterEach, test } from "node:test";
import { OllamaModelProvider } from "./ollama.js";
import { PROMPT_INJECTION_FIXTURES } from "./prompt-injection.fixtures.js";
import { ModelProviderError } from "./provider.js";

type Handler = (request: IncomingMessage, response: ServerResponse, body: string) => void;
const cleanups: Array<() => Promise<void>> = [];
const TEST_MODEL = "vega-war-room:latest";

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

async function mockOllama(handler: Handler): Promise<{ baseUrl: string }> {
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    handler(request, response, Buffer.concat(chunks).toString("utf8"));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address === "object");
  cleanups.push(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      )
  );
  return { baseUrl: `http://127.0.0.1:${address.port}` };
}

function chatEnvelope(content: unknown): string {
  return JSON.stringify({
    model: TEST_MODEL,
    created_at: "2026-07-17T00:00:00Z",
    message: {
      role: "assistant",
      content: JSON.stringify(content),
      thinking: "Bounded provider reasoning is deliberately discarded."
    },
    done: true,
    total_duration: 1000,
    load_duration: 100,
    prompt_eval_count: 41,
    prompt_eval_duration: 200,
    eval_count: 17,
    eval_duration: 700
  });
}

test("health uses only the fixed loopback version endpoint", async () => {
  const seenPaths: string[] = [];
  const mock = await mockOllama((request, response) => {
    seenPaths.push(request.url ?? "");
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ version: "0.31.2" }));
  });
  const provider = new OllamaModelProvider({ baseUrl: mock.baseUrl, model: TEST_MODEL });
  const health = await provider.health();
  assert.equal(health.healthy, true);
  assert.equal(health.version, "0.31.2");
  assert.deepEqual(seenPaths, ["/api/version"]);
});

test("rejects non-loopback, credentialed, and path-bearing base URLs", () => {
  for (const baseUrl of [
    "https://example.com",
    "http://192.168.1.20:11434",
    "http://user:pass@127.0.0.1:11434",
    "http://127.0.0.1:11434/custom"
  ]) {
    assert.throws(
      () => new OllamaModelProvider({ baseUrl, model: TEST_MODEL }),
      (error: unknown) => error instanceof ModelProviderError && error.code === "CONFIG_INVALID"
    );
  }
});

test("sends bounded structured-output settings and returns usage metadata", async () => {
  let received: Record<string, unknown> | undefined;
  const mock = await mockOllama((_request, response, body) => {
    received = JSON.parse(body) as Record<string, unknown>;
    response.setHeader("content-type", "application/json");
    response.end(
      chatEnvelope({
        objective: "Review the evidence safely",
        assumptions: [],
        steps: [
          {
            description: "Review the stored evidence",
            rationale: "Establish supported facts",
            requiresHumanReview: true
          }
        ],
        openQuestions: []
      })
    );
  });
  const provider = new OllamaModelProvider({
    baseUrl: mock.baseUrl,
    model: TEST_MODEL,
    maxContextTokens: 2048,
    maxOutputTokens: 300
  });
  const result = await provider.generate({
    profile: "structured-planning",
    input: {
      objective: "Review evidence",
      authorizedScopeSummary: "Offline evidence review only",
      capabilitySummaries: []
    }
  });
  assert.equal(result.metadata.authority, "none");
  assert.equal(result.metadata.taskTier, "T0");
  assert.deepEqual(result.metadata.usage, { inputTokens: 41, outputTokens: 17 });
  assert.equal(result.metadata.providerDurationsNs.total, 1000);
  assert.equal(received?.["stream"], false);
  assert.equal(received?.["think"], "low");
  assert.equal(received?.["keep_alive"], 0);
  assert.equal("tools" in (received ?? {}), false);
  assert.deepEqual(received?.["options"], {
    num_ctx: 2048,
    num_predict: 300,
    temperature: 0
  });
});

test("prompt injection in evidence remains quoted data and output has no authority", async () => {
  const mock = await mockOllama((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(
      chatEnvelope({
        facts: [
          {
            statement: "The evidence contains instruction-like text",
            evidenceRefs: ["ev-1"],
            uncertainty: null
          }
        ],
        candidateFindings: [],
        limitations: ["Instruction-like text was treated as untrusted data"]
      })
    );
  });
  const provider = new OllamaModelProvider({ baseUrl: mock.baseUrl, model: TEST_MODEL });
  for (const fixture of PROMPT_INJECTION_FIXTURES) {
    const result = await provider.generate({
      profile: "evidence-summary",
      input: { question: "What is supported?", evidence: [{ id: "ev-1", content: fixture }] }
    });
    assert.equal(result.metadata.authority, "none");
    assert.equal("action" in result.output, false);
    assert.equal("tool" in result.output, false);
    assert.equal("arguments" in result.output, false);
  }
});

test("fails closed when model output tries to become an action envelope", async () => {
  const mock = await mockOllama((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(
      chatEnvelope({
        facts: [],
        candidateFindings: [],
        limitations: [],
        action: { tool: "shell", arguments: ["whoami"] }
      })
    );
  });
  const provider = new OllamaModelProvider({ baseUrl: mock.baseUrl, model: TEST_MODEL });
  await assert.rejects(
    provider.generate({
      profile: "evidence-summary",
      input: {
        question: "Summarize",
        evidence: [{ id: "ev-1", content: PROMPT_INJECTION_FIXTURES[0] }]
      }
    }),
    (error: unknown) =>
      error instanceof ModelProviderError && error.code === "STRUCTURED_OUTPUT_INVALID"
  );
});

test("fails closed when model output invents an evidence reference", async () => {
  const mock = await mockOllama((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(
      chatEnvelope({
        title: "Candidate finding",
        summary: "A claim",
        impact: "Unknown",
        remediation: "Review manually",
        evidenceRefs: ["not-supplied"],
        confidence: "low",
        limitations: []
      })
    );
  });
  const provider = new OllamaModelProvider({ baseUrl: mock.baseUrl, model: TEST_MODEL });
  await assert.rejects(
    provider.generate({
      profile: "finding-draft",
      input: {
        observation: "Review the observation",
        evidence: [{ id: "ev-1", content: "bounded evidence" }]
      }
    }),
    (error: unknown) =>
      error instanceof ModelProviderError && error.code === "STRUCTURED_OUTPUT_INVALID"
  );
});

test("enforces input, response-byte, and timeout limits", async (context) => {
  await context.test("input characters", async () => {
    const provider = new OllamaModelProvider({
      baseUrl: "http://127.0.0.1:11434",
      model: TEST_MODEL,
      maxInputChars: 1000
    });
    await assert.rejects(
      provider.generate({
        profile: "structured-planning",
        input: {
          objective: "x".repeat(900),
          authorizedScopeSummary: "offline",
          capabilitySummaries: []
        }
      }),
      (error: unknown) =>
        error instanceof ModelProviderError && error.code === "INPUT_LIMIT_EXCEEDED"
    );
  });
  await context.test("response bytes", async () => {
    const mock = await mockOllama((_request, response) => {
      response.end("x".repeat(2048));
    });
    const provider = new OllamaModelProvider({
      baseUrl: mock.baseUrl,
      model: TEST_MODEL,
      maxResponseBytes: 1024
    });
    await assert.rejects(
      provider.generate({
        profile: "structured-planning",
        input: {
          objective: "Review",
          authorizedScopeSummary: "offline",
          capabilitySummaries: []
        }
      }),
      (error: unknown) =>
        error instanceof ModelProviderError && error.code === "OUTPUT_LIMIT_EXCEEDED"
    );
  });
  await context.test("timeout", async () => {
    const mock = await mockOllama((_request, response) => {
      response.write("{");
      setTimeout(() => response.end("\"version\":\"late\"}"), 300);
    });
    const provider = new OllamaModelProvider({
      baseUrl: mock.baseUrl,
      model: TEST_MODEL,
      timeoutMs: 100
    });
    const health = await provider.health();
    assert.equal(health.healthy, false);
    assert.match(health.error ?? "", /timed out/);
  });
});

test("an external emergency-stop signal aborts active generation", async () => {
  const mock = await mockOllama((_request, response) => {
    setTimeout(() => response.end(chatEnvelope({
      objective: "Too late",
      assumptions: [],
      steps: [],
      openQuestions: []
    })), 500);
  });
  const provider = new OllamaModelProvider({
    baseUrl: mock.baseUrl,
    model: TEST_MODEL,
    timeoutMs: 2_000
  });
  const controller = new AbortController();
  const generation = provider.generate(
    {
      profile: "structured-planning",
      input: {
        objective: "Review",
        authorizedScopeSummary: "offline",
        capabilitySummaries: []
      }
    },
    { signal: controller.signal }
  );
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(
    generation,
    (error: unknown) => error instanceof ModelProviderError && error.code === "REQUEST_ABORTED"
  );
});

test("capabilities are T0-only and expose no execution surfaces", () => {
  const provider = new OllamaModelProvider({
    baseUrl: "http://localhost:11434",
    model: TEST_MODEL
  });
  assert.deepEqual(provider.capabilities(), {
    provider: "ollama",
    taskTier: "T0",
    profiles: ["structured-planning", "evidence-summary", "finding-draft"],
    structuredOutput: true,
    toolAccess: false,
    filesystemAccess: false,
    commandAccess: false,
    mcpAccess: false,
    targetNetworkAccess: false
  });
});
