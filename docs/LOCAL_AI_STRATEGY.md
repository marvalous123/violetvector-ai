# Local AI Strategy

## Decision

Use a task-oriented provider abstraction. The first loopback-only Ollama adapter is implemented; LM Studio remains an optional benchmarking and debugging runtime, not a current dependency.

WAR-R00M defaults to the local `vega-war-room:latest` profile, which is built on `gpt-oss:20b` and adds the product brief and advisory-only safety boundary. The raw `gpt-oss:20b` model is the only reviewed fallback. The removed `llama3.2:3b` model is no longer part of this application's configuration or tests.

The operator may set `WAR_ROOM_OLLAMA_MODEL` before startup to one of those two exact names. Any other value fails closed with `LOCAL_AI_MODEL_NOT_ALLOWED`. The model name is resolved in backend code; it is not a browser field, request argument or model-controlled value.

## Provider Contract

The internal contract should support:

- `generate(task, messages, schema, limits, untrustedEvidence)`
- `health()` and `capabilities()`
- Model load and unload lifecycle where supported.
- Structured output, context control, output limits, thinking control and usage reporting.
- Stable profiles such as `fast-summary`, `quality-plan`, `finding-draft` and `report-section`.

The implemented adapter uses Ollama's fixed native `/api/version` and `/api/chat` paths, rejects redirects, and accepts only the fixed plain-HTTP loopback base URL. Callers cannot select a model, provider URL, arbitrary prompt, messages or tools. Requests use GPT-OSS's required `low` thinking level; the bounded thinking trace is parsed and discarded, while only the final strict JSON is returned. Requests remain bounded to a 4K context, 700 output tokens, 256 KB response and 90-second timeout. LM Studio is not wired into the application.

The first application route exposes only `structured-planning`. It derives the authorized scope summary in backend code and replaces literal target addresses with opaque target IDs before inference. Model results are stored as untrusted advisory data and cannot create approvals, findings or execution requests.

## Initial Task Routing

| Workload | Candidate | Context target | Output cap |
|---|---|---:|---:|
| Tool-output extraction and summarization | `vega-war-room:latest` | 4K | 400-700 |
| Structured planning | `vega-war-room:latest` | 4K | 700 |
| Finding drafting | `vega-war-room:latest` | 4K | 700 |
| Raw-model fallback | `gpt-oss:20b` | 4K | 700 |

Keep one request active at a time and retain measured 4K/700-token limits for the current 20B model. Raising context or output limits requires a separate benchmark and budget review.

## Current Compatibility Sample

One strictly sequential zero-target comparison used the guarded `smoke:local-ai` flow with one request active at a time. `vega-war-room:latest` returned seven schema-valid steps in 47,405 ms; exact fallback `gpt-oss:20b` returned seven in 48,975 ms. Both produced identical recorded safety results: `offline-synthetic-only`, no target contact, no command execution, no authority, a succeeded invocation and a valid audit chain. Each ephemeral API/database/evidence root was removed before the next request, and the final check found no smoke process, temporary smoke directory or loaded Ollama model.

Retain `vega-war-room:latest` as the product-aware default and `gpt-oss:20b` as the exact reviewed fallback. The timing difference from one pair is observational only and does not establish performance or quality superiority.

The later native/TypeScript minimized-fact interoperability review is deterministic contract work and does not change this model-routing result. No local model signs, validates, ingests or controls sensor telemetry.

## Prompt-Injection Isolation

- The planner receives scope and an approved capability catalogue, not raw security-tool output.
- A separate summarizer receives bounded untrusted evidence but has no tools, secrets, network or filesystem authority.
- Summarizer output contains only facts, evidence references, uncertainty and candidate findings.
- Invalid JSON, unknown fields, unsupported claims and missing evidence fail closed.
- Model output cannot enter the execution queue without deterministic policy and human approval.

Local inference improves data locality. It does not make target content trustworthy.

## Codex Role

Codex is the engineering and assurance layer: implementation, review, tests, adversarial fixtures, evaluation and integration. It is not the default runtime provider or target-facing executor.
