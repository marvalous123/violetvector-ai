# Implemented Security Controls

Last verified: 2026-07-19

## Current Boundary

The application exposes an authenticated network-free MCPwn endpoint, `POST /api/executor/version`. It accepts only the strict empty object `{}` and maps internally to `mcpwn.version.v1`, which calls MCPwn's fixed `nmap_version` tool with empty arguments.

The target-bearing library is restricted to closed, backend-owned profiles. Before proposal and again before execution, the verifier checks a direct route to exactly `192.168.42.129`, discovers the current `ethN` USB interface and source inside `192.168.42.0/24`, verifies that exact `/24` interface address, then checks the Docker bridge/subnet, empty execution network, exact ordered firewall and immutable local image ID. The bridge jump must be the first rule and the only rule mentioning the dedicated bridge. The target chain must contain exactly target-TCP-allow then drop. Approval and execution are separate operator actions.

Enabled profiles are low-noise TCP state (maximum 16 ports), service version (maximum 32 ports, intensity 0-2), HTTP title/header metadata (maximum four ports), TLS certificate metadata (maximum four ports), TLS cipher posture (T2, maximum two ports) and all-TCP discovery. HTTP/TLS NSE script names are hard-coded in the adapter. No API or UI field accepts a script name, script argument, command, URL, destination, wordlist or raw flag.

The second target profile, `network.tcp-port-discovery`, is fixed to TCP ports 1-65535, a maximum rate of 1,000 probes/second, zero retries and a two-minute hard limit. It performs no UDP scan, service detection, scripts or caller-selected flags. It uses the same exact-target resolution, live isolation, approval, cleanup, lifecycle and evidence controls.

The runtime binds to `127.0.0.1`. API history and mutations require a memory-only operator session. Unsafe requests require the exact HTTP Origin plus a per-session CSRF token; the opaque cookie is HttpOnly and `SameSite=Strict`. JSON writes have a 64 KiB request ceiling, require `application/json` and use strict schemas that reject unknown fields.

Starter and Professional editions share every security control. Professional-only HTTP/TLS and intensive-discovery routes return `PROFESSIONAL_EDITION_REQUIRED` in Starter; hiding a UI button is not treated as enforcement.

## Blue Team boundary

- Thirty defensive coverage areas are implemented as a closed, versioned catalogue: ten credential-access, ten payload-execution and ten defense-evasion rules.
- Built-in scenarios use server-generated synthetic normalized signals only. They cannot read a credential store, produce or execute a payload, alter a security control or contact an endpoint.
- Results and alerts are mission-bound evidence, immutable and marked `needs-review`.
- Every rule retains a `synthetic-validated` state and has a server-owned primitive-fact correlation definition. One attended C2g ceremony genuinely observed exactly one matching Security 4663 metadata event through the bounded one-shot path; it did not enable a live stream or prove continuous rule coverage. No endpoint is described as protected or clean.
- The endpoint contract accepts only minimized allowlisted primitive fields, rejects detection labels, unknown command or secret-bearing fields and binds every fact to an endpoint, connector, boot and monotonic sequence.
- Batches are bounded, hash-bound, signed with the enrolled Ed25519 key and chainable to the previous batch. Rebinding, gaps, duplicates, bad hashes and bad signatures fail closed.
- Endpoint acknowledgements can contain only a batch ID, accepted sequence, receipt hash and bounded retry delay. There is no job, action, script, argument or command response.
- Missing, incomplete, lossy, gapped or stale capability state prevents a live correlation.
- The main WAR-R00M UI/API remains loopback-only. A future remote-lab collector must be a separate minimal service on the exact isolated adapter and source.

## Endpoint trust and intake

- Enrollment material is generated server-side and binds a nonce, expiry, certificate fingerprint, connector, endpoint and mission into a canonical challenge hash.
- Approval requires the signed-in operator, exact fingerprint confirmation and valid proof from the stored Ed25519 SPKI public key.
- The default local server uses the same concrete verifier as the API tests; it has no permissive or accept-all trust callback.
- Active identities expire and can be revoked with an audited reason. Replacement-key renewal approves a new proved identity and revokes the old identity atomically. Identity, renewal and accepted-batch bindings are immutable.
- The first batch starts at sequence zero; later batches must be contiguous and chain to the last accepted batch. Boot changes may reset sequence only while preserving the prior-batch chain.
- Immediate duplicate retry is idempotent. Older replay, fork, rollback, gap, mixed boot, wrong mission, wrong certificate, expiry and revocation fail closed.
- Acknowledgements remain data-only. Registry and intake code adds no listener, job, script, response action, command or shell channel.
- Exact capability snapshots bind provider, channel, event family, primitive fields, filter hash, loss, continuity and freshness.
- The server alone maps primitive facts to thirty versioned live Blue rule definitions; sensor-supplied verdicts and labels are structurally rejected.

## Inert import and remediation

- SARIF intake accepts only version 2.1.0 through a strict authenticated route, with a 2 MiB, 16-run and 500-result ceiling.
- The exact source bytes are retained as mission-bound content-addressed evidence. The parser never fetches a URL, resolves a path, renders embedded content, launches a tool or creates a finding.
- Narratives and locations are hashed in normalized records; safe tool/rule labels are bounded; every candidate remains `unverified`.
- Candidate fingerprints are deterministic and mission-scoped. Reimport deduplicates candidates while retaining every immutable observation and explicit lineage.
- Remediation requires an already accepted finding. Its event chain is append-only and binds owner, due date, priority, comments, risk acceptance, fix evidence and retest history.
- Only same-mission verified evidence plus a pending retest can support `remediated`, `persists`, `regressed` or `inconclusive`. Manual status updates cannot forge those outcomes and never mutate the canonical finding.

## Guided mission boundary

- The guided path creates a mission profile whose execution flag is false and whose scope contains zero targets.
- Its authorization statement explicitly denies network contact, endpoint access, commands, payloads and credential activity.
- It uses only server-owned synthetic Blue fixtures, an informational training finding and deterministic report outputs.
- The cockpit reads stored mission records and audit links; it does not confer authorization or launch capabilities.

## Scope Policy

- Proposals carry a backend-owned target ID rather than a destination string.
- Only literal IPv4 and IPv6 targets are accepted.
- URLs, hostnames, CIDR, padded or encoded IPv4, shorthand IPv4 and IPv4-mapped IPv6 fail closed.
- Loopback, link-local, multicast, unspecified, carrier-grade/Tailscale and reserved ranges cannot become validated scope.
- Private targets require a deliberate isolation acknowledgement at scope creation.
- The mission ID, exact target, authorization window, capability, risk tier and policy version are checked for each proposal.
- A valid T1 proposal still returns `REQUIRE_APPROVAL`; it does not execute.

## Approval Control

An approval is bound to:

- Canonical SHA-256 hash of the complete proposal.
- Policy version.
- Tool-schema hash.
- Expiry timestamp.
- Run, immutable scope version, canonical target, authorization window, safety epoch and budget snapshot.

Approvals are single-use. Execution-time consumption runs in one database transaction: it revalidates the stored proposal, mission, run, immutable scope, canonical target, authorization window, policy and schema identities, safety epoch, emergency-stop state, budget snapshot and remaining budgets before consuming the approval and transitioning the run. Any failure rolls the transaction back. Expired, denied and consumed approvals cannot be reused.

## Operational Control

- Each run receives hard wall-time, tool-time, model-token, output-byte and request-count budgets.
- Target execution holds a one-at-a-time lease from request entry through adapter cleanup.
- Stdout and stderr share the proposal's total output ceiling; neither stream receives a separate copy of the budget.
- The serialized evidence envelope is checked against a separate maximum before sealing.
- The usage ledger rejects the first over-budget delta.
- Replay and retest operations create new runs with explicit parent lineage.
- Emergency stop state is persisted and blocks new runs while active.
- Stop-state transitions are constrained and recorded in the audit chain.
- Emergency stop revokes live approvals and aborts active local-model HTTP requests.
- Emergency stop aborts an active version-only MCPwn process and prevents it from recording success.
- Executions are stored with immutable mission/run/capability bindings and an append-only transition history.
- Database triggers reject illegal lifecycle changes and mutation or deletion of transition history.
- Startup reconciliation marks persisted nonterminal executions `orphaned`; no process ID or raw output is persisted.
- The broker verifies the pinned MCPwn binary and sibling configuration SHA-256 values before each launch.
- MCPwn is spawned through direct `wsl.exe` arguments with `shell: false`; stdout, stderr and wall time are bounded.
- Human-readable operator names remain in the local session audit, while executor grants receive a deterministic opaque `operator:<sha256-prefix>` identity that satisfies the typed executor schema without exposing a raw session name.

## Exact Target Adapter

- `network.service-version` accepts one backend-resolved canonical IPv4 target, TCP only, at most 32 unique ports and Nmap version intensity 0-2.
- The adapter rejects URLs, hostnames, CIDR, UDP, scripts, raw arguments, target drift, unverified isolation and non-digest-pinned images.
- It compiles direct `wsl.exe` and Docker argument arrays with no shell, `--pull=never`, a read-only filesystem, non-root user, dropped capabilities, no-new-privileges and CPU, memory and PID limits.
- The authenticated API exposes only fixed proposal, approval, execution and same-parameter retest actions; it exposes no generic spawn, tool, command or destination route.
- `scripts/prepare-redmi-isolation.ps1` fail-closes unless the dedicated empty Docker network, fixed bridge/subnet, direct exact-target USB route and pinned image all match. It removes duplicate jumps, inserts the dedicated bridge jump first, restores exact-target TCP allow followed by drop, and verifies the canonical rules.
- The reviewed local-only container is pinned at image ID `sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3`; it was not pushed to a registry.

## Evidence and Reporting

- Evidence files are stored by SHA-256 content hash and deduplicated while each observation retains immutable mission/run/model provenance.
- Findings cannot cite an observation from another mission.
- Size and hash are reverified before findings are accepted or reports are generated.
- A finding requires at least one valid evidence artifact.
- Finding changes create immutable revisions through a strict authenticated route; earlier wording and evidence links are not overwritten.
- Report snapshots freeze mission, scope, accepted finding revisions, exact evidence metadata, template version and audit head.
- Generation revalidates exact frozen evidence metadata plus the current audit chain and frozen audit prefix.
- JSON and HTML renderers make no model calls and perform no live lookups.
- HTML output escapes untrusted finding content.
- Audit events form a SHA-256 hash chain. The project describes this as tamper-evident, not tamper-proof.

## Deliberately Absent

- No shell or generic process execution.
- No generic target, tool, command, script, UDP, CIDR, URL or raw-argument execution route.
- No model-to-executor path.
- No caller-controlled MCP, tool, command or argument field.
- No credential, payload, exploitation, dumping or post-exploitation capability.
- No operational stealth, evasion, obfuscation or anti-detection capability.
- No upload-and-run script, payload, binary, MCP definition or plugin path.
- No public listener, cloud service, telemetry or external font request.
