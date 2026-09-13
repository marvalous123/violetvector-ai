# Architecture

## System Shape

```text
Human operator
  -> React operator console
  -> local Node API on 127.0.0.1
     -> mission and scope service
     -> model task router
     -> deterministic policy engine
     -> parameter-bound approval service
     -> execution broker and emergency stop
        -> restricted Kali WSL runner
        -> MCPwn over local stdio
        -> explicitly enabled tool adapter
        -> exact isolated target
     -> append-only event log
     -> content-addressed evidence store
     -> inert import and remediation services
     -> evidence-only report renderer
```

Only the execution broker holds an MCPwn connection. The model receives a small proposal schema, not MCP transport details, operating-system command access, secrets, or direct tool credentials.

The live Blue boundary is implemented and fixture-tested as a separate data plane. The native Windows Service is installed as manual-start LocalService with the exact non-exportable Software KSP machine identity. Direct LocalService startup signing, exact probe cleanup, real machine-restart validation and identity-preserving uninstall/reinstall recovery are proven. Telemetry Gate A proves exact `System` and `Application` log metadata under LocalService while reading zero events. Gate B0 proves exactly two fixed synthetic signed local batches and protected persistence under the real service identity. Gate B1 machine-proves one bounded genuine SCM metadata fact under the same identity. Gate C0a source-proves one exact loopback sender contract but deliberately does not register it, so installed transport remains absent. The TPM provider remains deferred until its provider-managed ACL can be validated safely:

```text
Authorized Windows lab endpoint
  -> least-privilege outbound-only sensor
  -> signed capability reports and minimized primitive facts
  -> separate telemetry-only intake
  -> algorithm-agile endpoint registry, continuity and source-health checks
  -> server-owned correlation and normalized evidence
  -> deterministic Blue alerts and coverage health
  -> WAR-R00M API and UI on 127.0.0.1
```

The sensor receives only a bounded data acknowledgement. It has no command, job, action, shell or model channel. The collector does not expose the browser, mission mutation, model or executor routes.

## Trust Boundaries

1. **Browser to API:** UI data is untrusted. Bind locally, protect the session, validate every request, use CSRF protection, and apply a restrictive content security policy.
2. **Model boundary:** model output and all target/tool content are untrusted data. A model has no authorization authority.
3. **Policy boundary:** deterministic code independently validates the target, tool ID, typed arguments, risk, limits, active scope, and policy version.
4. **Approval boundary:** each approval is single-use, expiring, and bound to a canonical proposal hash, tool schema hash, and policy version.
5. **Windows to Kali:** invoke fixed programs with argument arrays and no shell. Do not expose a generic command or unrestricted argument field.
6. **Network boundary:** execution may reach only an exact approved target. The normal home network and Atlas remain denied.
7. **Evidence boundary:** stdout, stderr, pages, banners, and scan results are evidence, never instructions. Reports consume verified records only.
8. **Endpoint telemetry boundary:** connector identity and mission binding come from a server-owned registry. Signed batches are untrusted until schema, signature, continuity, size, redaction and evidence checks pass.
9. **Collector boundary:** a future remote-lab collector is a separate minimal process on the exact isolated adapter; the main WAR-R00M UI/API remains loopback-only.

## Current Intake Isolation Checkpoint

The current API is fixture-only for endpoint intake and remains hard-bound to `127.0.0.1`. Its request guard requires the socket peer and Host header to be loopback. Only `POST /api/endpoints/capabilities` and `POST /api/endpoints/facts` are exempt from browser-session and Origin checks so a local signed fixture can submit data; they remain loopback-only, strictly schema-bound, size-bounded, signature-verified and data-only. The facts route now returns only the exact Gate C0a receipt. Enrollment, approval, renewal, revocation and every operator mutation remain protected by the local session and CSRF boundary.

Do not expose those routes by rebinding the main API. The production data plane must be a separate minimal process that exposes only the reviewed capability/fact intake and bounded receipt on one exact isolated adapter, adds connection/rate/concurrency/backpressure limits and has no browser, model, mission mutation, execution, command or response-action route.

## Initial Components

| Component | Responsibility |
|---|---|
| Web app | Missions, cockpit, scope, plans, approvals, Blue validation, workflow, findings, evidence, reports and system health |
| API | Local session, validation, orchestration and SSE event delivery |
| Policy engine | Default-deny target and capability decisions with explainable reason codes |
| Approval service | Exact, expiring, single-use authorization for one proposal |
| Execution broker | MCPwn lifecycle, time/output limits, cancellation and process reconciliation |
| Provider layer | Task profiles over Ollama and LM Studio with structured outputs |
| Evidence store | Content-addressed files and SHA-256 metadata |
| Event store | Append-only audit sequence with a hash chain |
| Finding service | Evidence-grounded revisions, confidence and taxonomy mapping |
| Report renderer | Deterministic HTML/JSON plus evidence-bound PDF/DOCX with separate source and visual QA approvals |
| Guided mission and cockpit | Zero-target first-run journey plus mission authorization, Purple, workflow, report and audit status |
| Inert import service | Bounded SARIF 2.1.0 source retention, versioned normalization, unverified candidates and mission-scoped deduplication |
| Remediation service | Append-only owner, due-date, risk, fix-evidence and retest history without automatic finding mutation |
| Endpoint fixture | Data-only capability/fact schemas, Ed25519 signatures and no response-action channel; not a production Windows service |
| Windows identity-only sensor service | Installed manual-start LocalService .NET 8 host with a provisioned non-exportable Software KSP ECDSA P-256 identity, startup proof and protected installer; contains no collector or transport |
| Endpoint registry and intake | Server-owned challenge, stored SPKI key, proof, atomic replacement-key renewal, revocation, persisted continuity, exact source health and thirty server-owned rule correlations |
| Test plan and comparison | Immutable engagement-plan versions, bounded mission search and evidence-backed direct-retest comparison |
| Support diagnostics | Redacted database, audit and evidence integrity snapshot with no targets, content, secrets or paths |

## Technology Baseline

- TypeScript monorepo.
- A narrowly scoped .NET 8 Windows Service for native CNG key-handle access; it has no model, executor or command dependency.
- React and Vite for the operator console.
- Node for the local API and execution broker.
- SQLite in WAL mode for the MVP.
- Hash-recorded, fail-closed SQLite migration history.
- Zod or equivalent strict schemas at every boundary.
- Server-sent events for one-way live updates.
- Vitest for unit and integration tests, plus Playwright for operator workflows.

## Evidence Integrity

SQLite is not immutable. The MVP will be described as tamper-evident, not tamper-proof.

- Store artifacts by SHA-256 content hash.
- Link every artifact to its source event and execution.
- Hash-chain append-only audit events.
- Freeze report inputs into an immutable report snapshot.
- Fail report generation when an artifact hash or audit link does not verify.

## References

- [Parrot Security MCPwn](https://gitlab.com/parrotsec/project/mcpwn)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
