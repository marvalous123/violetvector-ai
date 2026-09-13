# Threat Model

## Protected Assets

- Scope and authorization records.
- Approval decisions and operator identity.
- MCPwn and tool execution authority.
- Evidence integrity and confidentiality.
- Endpoint connector identity, telemetry continuity and telemetry privacy.
- Findings and final report accuracy.
- Atlas, the home LAN, the Windows host, and other out-of-scope systems.

## Primary Threats

| Threat | Required control |
|---|---|
| Prompt injection in target or tool output | Isolated summarizer, schema-only output, no tools, deterministic validation |
| Model attempts to expand scope | Target IDs resolved by the backend; no model-provided destination strings |
| Command or argument injection | Fixed adapters, strict typed schemas, argument arrays, no shell, no `extra_args` |
| Approval replay or bait-and-switch | Hash-bound single-use approval with expiry and full parameter display |
| Private/home network scope escape | Reserved/private ranges denied by default plus exact target exception and network egress control |
| Orphaned scans after stop or crash | Tracked process group, two-phase stop, startup reconciliation and fail-closed state |
| Tool or MCPwn supply-chain drift | Pin versions and hashes; schema drift blocks execution |
| Fabricated or hallucinated findings | Evidence references required by database and report validation |
| Evidence tampering | Content hashes, audit hash chain and report snapshot verification |
| Resource exhaustion | Per-call time, output, rate, concurrency and model-token ceilings |
| Counterfeit, expired, revoked or rebound endpoint sensor | Server-owned enrollment registry binds certificate fingerprint, connector, endpoint and mission |
| Telemetry replay, fork, sequence rollback or false reboot | Atomic persisted chain head, event uniqueness, boot transition rules and idempotent receipts |
| Endpoint supplies a forged detection conclusion | Sensor emits minimized primitive facts; versioned server-owned rules derive detections |
| Credential, token, script or private-path leakage | Endpoint and collector field allowlists, dual redaction, bounded retention and prohibited-field tests |
| Connector flooding, oversized batches or parser failure | Separate collector, mTLS, byte/rate/concurrency limits, backpressure, fuzzing and fail-closed parsing |
| Missing or stale telemetry is reported as clean | Per-channel health and loss state downgrade rule readiness to partial, blind, stale or inconclusive |
| A telemetry channel becomes remote control | Outbound-only sensor, no listener or job polling, and a data-only acknowledgement schema |
| Collector compromise reaches UI, model or executor | Separate minimal process and network boundary with no browser, model, mission mutation or execution routes |

## Capability Tiers

| Tier | Description | MVP policy |
|---|---|---|
| T0 | Planning, evidence review and report drafting | No security-tool execution |
| T1 | Bounded discovery against one exact target | Explicit approval, strict timeout and rate limit |
| T2 | Active enumeration or template validation | Stronger confirmation and lower budgets |
| T3 | Exploitation, payloads, dumping, brute force, interactive consoles or state change | Adapters absent and server-side denied |

## Required Security Tests

1. A model-generated direct MCPwn request cannot reach an executable or broker route.
2. Every private or reserved destination is denied unless it exactly matches the active isolated target.
3. Alternate IP encodings, IPv4-mapped IPv6, hostnames, redirects, CIDR input, and unknown JSON properties fail closed in the MVP.
4. Shell metacharacters remain inert data and no shell appears in the process tree.
5. Any parameter, policy, or tool-schema change invalidates an existing approval.
6. Expired, revoked, consumed, or superseded approvals cannot execute.
7. T3 capabilities fail server-side even if the UI is bypassed.
8. Emergency stop halts new work, terminates child work, records the outcome, and clearly reports incomplete cleanup.
9. Startup reconciliation marks interrupted work and handles verified orphans before accepting a new run.
10. Altered evidence blocks finding verification and report generation.
11. A finding without valid evidence cannot be accepted into a report.
12. Replay creates a new proposal and new approval; reading audit history never executes tools.
13. Prompt injection and HTML in tool output cannot create actions, approvals, or executable UI.
14. Time, output, request-rate, concurrency, and token limits terminate over-budget work.
15. Unknown, expired, revoked, wrong-mission and wrong-schema endpoint identities are rejected.
16. Certificate, connector, endpoint and mission bindings come from the server registry, not caller fields.
17. Replayed, duplicated, forked, rollback and mixed-boot telemetry batches fail atomically.
18. Batch signature, prior-hash, evidence and event-index tampering are detected.
19. Forbidden secret fields, raw file content, memory bytes, oversized data and decompression bombs fail closed.
20. Redaction is verified before transmission and again before evidence persistence.
21. The sensor exposes no listener, command, job, shell, action or model-controlled configuration channel.
22. Missing channels, loss counters, sequence gaps or stale telemetry prevent a live-supported or clean claim.
23. Endpoint alerts cite same-mission event evidence and cannot create proposals, approvals or executor calls.
24. A future remote collector cannot expose the main WAR-R00M UI/API beyond loopback.
