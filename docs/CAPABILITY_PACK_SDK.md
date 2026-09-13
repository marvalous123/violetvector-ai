# Capability Pack SDK Boundary

WAR-R00M can grow through reviewed capability packs without becoming an arbitrary-code launcher.

## Pack Contract

Every pack starts with a `war-room-capability-pack.v1` manifest validated by `@war-room/executor-contract`. The manifest binds:

- A versioned local capability and adapter ID.
- A fixed T0, T1 or T2 risk tier.
- A parameter-schema hash and source hash.
- Exact network, process and filesystem permissions.
- Hard time, output, evidence and request budgets.
- Evidence media types.
- `destructive: false`.
- Literal denials for credential access, payload execution and evasion controls.

An exact-target pack must declare `network: exact-target`, require a target, and use a fresh single-use approval. A T0 pack must be offline, process-free and target-free.

## Review and Registration

A valid manifest is necessary but not sufficient to execute. A developer must:

1. Implement a typed adapter in source control; WAR-R00M never loads an uploaded script or binary.
2. Compile fixed argument arrays with no shell, raw command, URL, script name or arbitrary-argument fields.
3. Add policy tests for scope, risk, parameters, expiry, emergency stop and hostile extra fields.
4. Add executor tests for exact arguments, cancellation, shared output limits, cleanup and evidence limits.
5. Add evidence parsing and cautious report wording.
6. Register the capability in the closed backend catalogue.
7. Pass `npm run verify` and record the review in the handoff.

New packs remain unavailable until those steps are complete. The browser and local model cannot register, approve or enable one.

## Deliberately Unsupported

- Upload-and-run PowerShell, shell, Python, binaries or MCP tool definitions.
- Credential collection or access to browser, password, token or key stores.
- Payload generation, delivery or execution.
- Stealth, evasion, obfuscation or anti-detection controls.
- Caller-selected Nmap scripts, script arguments, wordlists or raw flags.
- Generic process, shell, URL or destination fields.

Safe simulation packs may use synthetic credential canaries, inert payload fixtures and offline evasion-detection telemetry because they do not perform the prohibited action.
