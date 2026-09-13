# Roadmap

## Phase 0: Foundation

- [x] Create separate Project 15 folder and Git repository on `main`.
- [x] Record product boundaries and agent guidance.
- [x] Draft architecture, threat model, product model and local AI strategy.
- [x] Record verified MCPwn integration research.
- [x] Create the initial local commit after reviewing the starter documents.
- [x] Make tracked-secret/artifact, PowerShell syntax and Git integrity checks repeatable in the complete gate.

## Phase 1: Policy-First Skeleton

- [x] Scaffold the TypeScript workspace, React console, Node API and SQLite migrations.
- [x] Implement canonical target parsing and reserved-range denial.
- [x] Implement mission, scope version, target and authorization services.
- [x] Implement proposal schemas, risk tiers and explainable policy decisions.
- [x] Complete the initial policy acceptance suite before adding any live security tool.
- [x] Add a bounded external-sandbox mutation sentinel for twenty-three critical target, scope-schema and policy boundaries.

## Phase 2: Human Control and Audit

- [x] Implement parameter-bound, expiring and single-use approvals.
- [x] Add append-only audit events and hash chaining.
- [x] Add hard usage budgets and persisted emergency-stop state.
- [x] Bind approvals to real runs, immutable scope versions, backend capability schemas and safety epochs.
- [x] Add memory-only operator sessions, exact-origin writes and CSRF protection.
- [x] Abort active local-model requests when emergency stop is requested.
- [x] Connect emergency stop to active MCPwn process cancellation for the network-free capability.
- [ ] Add a distinct pause/resume workflow if operational evidence shows it is needed.
- [x] Persist execution lifecycle transitions and reconcile nonterminal work to `orphaned` at startup.
- [x] Consume approvals atomically with execution-time policy, schema, scope, target, safety-epoch and remaining-budget revalidation.
- [x] Define executor-contract v2 with complete resolved-target and limit bindings, plus a deterministic no-network fake.
- [x] Recheck approval expiry against executor current time before an Nmap target process can spawn.
- [x] Add a separate bounded external-sandbox mutation suite for thirty-eight executor-contract, capability-pack and selected real adapter/executor boundaries.
- [ ] Complete plan and live-event interfaces. Mission/scope, target proposal and approval-decision interfaces now work.

## Phase 3: MCPwn Proof of Concept

- [x] Pin, test and build MCPwn in a contained Kali location.
- [x] Prove the real MCP stdio transport with fixed `nmap --version` and no target.
- [x] Connect through a restricted War Room broker with no generic MCP/tool arguments.
- [x] Verify pinned hashes, direct `wsl.exe` argv, timeout/output bounds, cancellation, audit metadata and evidence capture.
- [x] Define and test one disabled exact-target TCP service-version capability with no raw arguments.
- [x] Compile a fixed, digest-pinned, resource-bounded Docker invocation without exposing a spawn path.
- [x] Build and review the pinned Nmap image, then record its immutable local image ID.
- [x] Enable the capability only after verified Redmi isolation and a written authorization record.
- [ ] Verify cancellation, time/output limits, evidence capture and scope denial in the isolated lab.
- [x] Add a separately approved all-TCP discovery profile with a fixed rate and no service, UDP, script or raw-argument controls.
- [x] Add reviewed low-noise TCP state, HTTP metadata, TLS certificate and T2 cipher-posture profiles.
- [x] Harden firewall ordering/uniqueness, combined output limits, evidence limits and single-execution leasing before exposing the expanded library.
- [ ] Add later capabilities one at a time only after focused policy tests pass.

## Phase 4: Evidence, Findings and Reports

- [x] Add the content-addressed evidence store.
- [x] Add finding revisions, confidence and reviewer state.
- [ ] Add versioned taxonomy references.
- [x] Enforce evidence-backed acceptance and report inclusion.
- [x] Generate deterministic HTML and JSON reports with a frozen manifest.
- [x] Bind evidence observations to missions/runs/model invocations and deny cross-mission citations.
- [x] Verify exact frozen evidence metadata and audit-chain prefixes during report generation.
- [ ] Add PDF only after render and reproducibility checks.

## Phase 5: Local AI and Evaluation

- [x] Implement the first Ollama provider adapter. LM Studio remains an optional later adapter.
- [x] Add strict T0 task profiles, bounded structured output and prompt-injection isolation.
- [x] Persist model identity, hashes, token usage, latency and advisory output.
- [x] Add the first mission-bound advisory planning interface with no execution authority.
- Benchmark the existing 3B model.
- Evaluate one 7-8B quantized quality model under 6 GB VRAM constraints.
- Track schema validity, evidence grounding, hallucination rate, latency, tokens and VRAM.

## Phase 6: Isolated Target Assessment

- [x] Design and verify Redmi network isolation.
- [x] Create a written target and authorization record.
- [x] Run one controlled, low-risk end-to-end assessment.
- [x] Produce evidence, accepted findings, report and retest lineage.
- [ ] Review portfolio wording against the real evidence.

## Phase 7: Capability Productization

- [x] Add a backend-authoritative capability catalogue with risk, difficulty, noise, limits and readiness.
- [x] Add Starter/Lab and Professional/Business packaging with backend route enforcement.
- [x] Add a Capability Pack v1 manifest boundary with hashes, permissions and hard budgets.
- [x] Keep operational credential access, payload execution and evasion controls structurally denied.
- [x] Add a 30-rule offline Blue Team lab for credential access, payload execution and defense evasion with mission-bound evidence.
- [x] Add a strict signed, sequenced and data-only endpoint telemetry contract with coverage fallback.
- [x] Extend the threat model and architecture for endpoint identity, replay, chain forks, boot changes, privacy leakage, flooding, stale coverage and collector compromise.
- [x] Add a server-owned endpoint registry with enrollment approval, certificate-to-connector/endpoint/mission binding, bounded identity lifetime and revocation.
- [x] Add an explicit replacement-key renewal ceremony that atomically activates the new identity and revokes the old identity.
- [x] Persist and atomically verify cross-batch sequence, prior-hash, boot, event uniqueness and idempotent receipt state.
- [x] Replace broad telemetry-class readiness with exact provider, channel, event-family, field, filter-hash, loss and freshness capability state.
- [x] Prove the intake state machine with a fixture-only collector before opening a live listener.
- [x] Replace live pre-classified signals with minimized normalized facts and versioned server-owned correlation rules for all thirty Blue rules.
- [ ] Complete the least-privilege single-endpoint Windows sensor and isolated telemetry-only collector; one genuine minimized event, C0b/C0c and the bounded C1c snapshot are machine-proven, while continuous collection and remote transport remain absent. Gate C2d/C2e and C2f's approval/empty-slot ceremonies are machine-complete. The operator reported C2f's controlled reinstall/live exercise complete and independent checks prove clean rollback, but exact result JSON/read state was not retained. Next add a bounded privacy-safe ceremony receipt and repeat one controlled exercise before genuine-source promotion. No continuous reader or transport is authorized.
- [x] Build the native .NET 8 Windows Service and exact non-exportable Software KSP ECDSA P-256 identity boundary.
- [x] Extend endpoint proof verification to algorithm-derived fixture Ed25519 and native-compatible ECDSA P-256 signatures.
- [x] Build the separate elevated Software KSP machine-key provisioner with exact protected-ACL read-back, non-exportability and signing-proof checks.
- [x] Freeze the source-only service-SID authority and v2 identity-rotation plan with native negative tests; installer wiring and the controlled machine migration remain open.
- [x] Run real elevated Software KSP provisioning and record its verified ACL, blocked export and public signing proof.
- [x] Install the identity-only service under LocalService and prove startup signing plus ordinary-user denial.
- [x] Add exact diagnostic-probe cleanup, post-reboot validation and identity-preserving service uninstall semantics.
- [x] Run the real elevated probe cleanup, post-reboot restart check and controlled uninstall/reinstall recovery exercise.
- [x] Add a separate metadata-only readiness plan/check for exact `System` and `Application` logs with no caller channels, event reads, raw content, service claim or transport.
- [x] Prove the exact Gate A source metadata under the installed LocalService identity without collecting events.
- [x] Implement Gate B0 as exactly two synthetic, signer-bound and hash-chained local batches with a fixed protected proof file and no event reader or transport.
- [x] Reinstall the Gate B0 package and validate the real LocalService proof, file ACL, machine-key signatures and continuity with the external no-argument checker.
- [x] Design Gate B1 as one bounded genuine SCM 7045 metadata fact with no raw content, polling, transport or command channel.
- [x] Implement and fully source-verify Gate B1 without changing the completed Gate B0 boundary.
- [x] Machine-prove Gate B1 through one clean controlled reinstall and the external genuine-batch checker.
- [x] Freeze and source-verify Gate C0a: one fixed loopback POST, exact data-only receipt, hard size/time limits, no retry and no service registration.
- [x] Add the first C0b slice: exact public identity disclosure and bounded canonical enrollment-challenge signing with no service registration.
- [x] Source-implement Gate C0b with the operator-present browser ceremony, exact protected manifest-bound descriptor, native one-shot proof and external checker.
- [x] Run the controlled Gate C0b reinstall and real pending/proof/API/final operator ceremony.
- [x] Source-implement Gate C0c with a pre-network claim, one exact loopback attempt, protected terminal receipt and external checker.
- [x] Reinstall and run Gate C0c as one explicit loopback machine-delivery proof, then leave automatic retry and remote transport disabled.
- [ ] Revisit the TPM provider only through a separately reviewed profile after its provider-managed ACL can satisfy a documented least-privilege policy.
- [ ] Add outbound-only enrollment, event collection and telemetry behind a separate one-way transport gate; the identity lifecycle prerequisite is complete.
- [x] Add fail-closed Windows ACL verification and an elevated external-key provisioner as pre-service groundwork; this is not a native machine keystore.
- [x] Add per-endpoint connector health, channel availability, sequence-gap and stale-telemetry views before claiming live support.
- [x] Extend server-owned primitive-fact correlation definitions to the remaining 23 Blue rules with a complete thirty-rule fixture gate.
- [ ] Add reviewed pack registration without runtime upload-and-run code.

## Phase 8: Professional Workflow

The order below follows the [official-product benchmark](PRODUCT_BENCHMARK.md): complete the evidence and remediation loop before expanding execution breadth.
The [operational value gate](OPERATIONAL_VALUE_GATE.md) is also release-blocking:
WAR-R00M must complete a real authorized scope-to-retest workflow and measure
analyst effort; an LLM summary or alert dashboard is not a product outcome.

- [x] Freeze the first release-candidate scope and defer continuous telemetry,
  autonomous operation, broader adapters and enterprise deployment.

- [x] Add the first mission-bound purple validation matrix joining safe scenarios, required telemetry, expected Blue rules, observed alerts or misses and sealed evidence.
- [ ] Extend the purple validation matrix to authorized target steps, remediation state and separately approved retest outcomes.
- [x] Add the first inert allowlisted result importer (bounded SARIF 2.1.0) with original-artifact retention, parser identity, deterministic normalization and deduplication.
- [x] Add remediation ownership, due dates, status, expiring risk acceptance, reviewer comments, fix evidence and regression history.
- [x] Add versioned engagement test plans with completed, skipped, blocked and not-applicable procedure coverage.
- [ ] Add reusable finding narratives.
- [x] Add an immutable report QA workflow bound to the exact JSON/HTML outputs.
- [x] Add reproducible evidence-bound PDF/DOCX templates with a separate visual-QA gate.
- [ ] Add portfolio and attack-path views only after the underlying evidence relationships are explicit and tested.
- [ ] Run and retain one end-to-end operational-value benchmark: the 2026-09-13
  record has valid integrity and 9/9 milestones, bounded execution, evidence,
  an accepted finding, explicit persistent remediation outcome, approved
  retest, comparison, source/export QA and verified recovery. Final completion
  remains correctly blocked because the original run was created 37 seconds
  before the timer. Do not alter timestamps or repeat target contact only to
  make this checkbox green; a future benchmark must start before its original
  run and requires fresh approvals.
- [ ] Defer multi-user RBAC, client portals and external ticketing until the local single-operator workflow is mature.

## Phase 9: Operator and Product Polish

- [x] Add a selected-mission cockpit containing authorization, exact scope, readiness blockers, approvals, run timeline, Purple outcomes, workflow counts and report state.
- [x] Add a fully synthetic guided demo mission and six-step first-run checklist that requires no phone or endpoint.
- [x] Add side-by-side original/retest comparison using existing lineage, evidence hashes and finding state.
- [x] Add bounded mission search across the implemented workflow records.
- [ ] Add saved views, richer integrity/status filters and a human-readable activity timeline.
- [ ] Add an edition comparison driven by backend feature metadata; retain identical safety controls in every edition.
- [x] Add Windows local setup, per-launch in-memory bootstrap secret, protected runtime ACL, verified backup/non-overwriting restore and redacted support diagnostics.
- [ ] Add signed MSI/MSIX installation, uninstall, updater and longer-term recovery exercises before business use.

## Deferred

- Broader mutation coverage beyond the two curated suites and independent application/sensor assurance before commercial claims.
- SQL dumping.
- Payload generation.
- Metasploit or interactive consoles.
- Credential attacks and post-exploitation.
- Unrestricted argument passthrough.
- Multi-tenancy, public hosting and cloud execution.
