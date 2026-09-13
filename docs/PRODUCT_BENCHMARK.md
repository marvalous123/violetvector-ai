# Product Benchmark

Checked against official product material on 2026-07-19. This is a feature benchmark, not an endorsement and not a claim that WAR-R00M currently matches mature commercial platforms.

## Where WAR-R00M Fits

There is no exact like-for-like product in this review. Existing products tend to specialise in one of three areas:

1. Pentest engagement management, collaboration and reporting.
2. Vulnerability ingestion, deduplication and remediation tracking.
3. Adversary emulation, purple-team exercises or continuous security validation.

WAR-R00M's intended position is the controlled junction between them: a local-first mission console that can run a small reviewed capability catalogue, preserve evidence provenance, measure defensive coverage and keep the local model outside the execution trust boundary.

## Comparable Products and Lessons

| Product | Strongest relevant capabilities | Lesson for WAR-R00M | Boundary |
| --- | --- | --- | --- |
| [PlexTrac](https://plextrac.com/platform/overview/) | Engagement lifecycle, scanner ingestion, reusable findings, collaborative reporting, remediation workflow and retest | Make findings reusable, reports easier to QA and remediation progress visible | Do not imitate cloud-first scale claims before local evidence exists |
| [Faraday](https://faradaysec.com/platform/penetration-testing-reporting/) | Shared workspaces, tool imports, risk-based prioritisation, report versioning and audit history | Add normalized imports and cross-mission portfolio views | Imported tool output must remain untrusted data |
| [AttackForge](https://attackforge.app/) | Scoping, project workflow, asset management, team QA and template-driven reporting | Add structured engagement checklists and a report-template lifecycle | Multi-user and client-portal work stays deferred until local single-operator controls are mature |
| [Dradis](https://dradis.com/) | Self-hosting, reusable issue libraries, scanner translation rules, collaboration and remediation portal | Preserve the local-first advantage and add operator-owned normalization rules | Translation rules must not create unsupported findings |
| [PwnDoc](https://pwndoc.github.io/pwndoc/) | Reusable vulnerability data, collaborative review, retest workflow and customizable DOCX reports | Add review comments, reusable narratives and reproducible document templates | Rich document output must pass render and evidence checks |
| [DefectDojo](https://docs.defectdojo.com/) | Imports from many tools, finding deduplication, reimport history, risk acceptance, ownership and issue tracking | Build a small schema-first importer with deterministic deduplication and retained history | Never accept a scanner severity or conclusion as proof without evidence review |
| [MITRE Caldera](https://caldera.readthedocs.io/en/stable/) | Agent-based operations, reusable adversary profiles, plugins, planners and operation logs | Use repeatable test plans and technique coverage, but retain stricter human approval and closed capabilities | Do not add a general agent command channel or unrestricted ability execution |
| [VECTR](https://docs.vectr.io/user/important-concepts/) | Repeatable purple-team test cases and defensive-control measurement | Join authorized test steps to expected telemetry, observed alerts and retest outcomes | A detection miss is a coverage result, not permission to escalate execution |
| [Pentera](https://pentera.io/pentera-platform/) | Continuous validation, attack-path context, risk prioritisation, remediation assignment and revalidation | Show measurable risk reduction and controlled retest lineage | Do not claim production-safe autonomous attack validation |
| [NodeZero](https://horizon3.ai/) | Autonomous testing, fix guidance and one-click verification | Make the operator journey from evidence to fix to controlled verification short and obvious | WAR-R00M remains human-controlled and exact-scope only |

## Current Differentiators

- The model has advisory authority only and cannot call MCPwn or an operating-system command.
- Exact targets, typed capability arguments, risk, approvals, expiry and budgets are revalidated in deterministic backend code.
- Execution, approvals, evidence, findings and reports are mission-bound and auditable.
- Blue Team rule readiness distinguishes synthetic validation from real endpoint support.
- The same console now joins authorized plans, evidence, synthetic defensive results, thirty fixture-tested and source-verified correlation definitions, atomic endpoint-key renewal, remediation and direct-retest comparison. A production Windows collector remains future work.
- It is local-first and intentionally useful in a small owned lab before any multi-tenant or cloud ambitions.

## HexStrike AI v6 Benchmark

Reviewed against the public
[HexStrike AI v6 repository](https://github.com/0x4m4/hexstrike-ai) on
2026-08-13. HexStrike is stronger today as a broad offensive toolbox: its
project advertises 150+ security tools, 12+ autonomous agents, process
management and automated tool selection. WAR-R00M is stronger as an engagement
control plane: deterministic scope, typed capabilities, expiring approvals,
evidence provenance, report support and defensive-validation lineage.

WAR-R00M will adopt the useful product lessons without copying HexStrike's trust
model:

- add a visible tool catalogue and health inventory;
- add bounded execution progress, elapsed time, output limits and stop controls;
- let the model recommend tools and recovery alternatives without execution
  authority;
- add a small reviewed adapter set before attempting broad coverage; and
- provide mission-scoped low-risk autopilot that rechecks scope, budgets and
  emergency stop before every step.

WAR-R00M will not expose a generic command endpoint, `shell=True`, arbitrary
Python/package/file execution, prompt-only authorization or direct model-to-tool
authority. HexStrike may be used as an external benchmark in an isolated lab,
not as a core executor dependency.

## Product Priorities

### P0: Production endpoint evidence

The fixture trust slices cover endpoint threat tests, Ed25519 enrollment, atomic renewal and revocation, persisted cross-batch continuity, exact source-capability health, fixture-only intake and server-owned primitive-fact definitions for all thirty rules. The installed LocalService adds an exact non-exportable Software KSP ECDSA P-256 machine key, completed lifecycle gates, LocalService Gate A, machine-proven synthetic Gate B0 and one machine-proven bounded genuine SCM metadata fact at Gate B1. The outbound-only collector and isolated telemetry intake remain later separate work. Do not add commands, jobs, remote shell or response actions.

### P1: Purple validation matrix

Connect each reviewed assessment or safe simulation to:

- the expected ATT&CK behaviour;
- required endpoint telemetry;
- the Blue rule expected to detect it;
- observed alert or miss;
- evidence references;
- remediation state; and
- a separately approved retest.

This is the clearest feature for making WAR-R00M more than a scanner front end.

### P1A: Mission cockpit and guided demo

Turn the separate registers into one selected-mission journey: authorization, scope, blockers, plan, approvals, timeline, evidence, Purple outcomes, remediation and report. Add a fully synthetic first-run mission so a new user or recruiter can understand the complete safe workflow without a phone or live endpoint.

### P2: Normalized import and deduplication

Add inert parsers for a small allowlist of report formats. Store the original artifact, parser identity and hashes, normalize findings without executing embedded content, and deduplicate deterministically while preserving every observation.

### P3: Remediation workflow

Add owner, due date, status, risk acceptance with reason and expiry, reviewer comments, fix evidence and retest outcome. Reports should show open, accepted, fixed and regressed findings without losing history.

### P4: Repeatable test plans and coverage — first version implemented

Immutable engagement checklists can now map to registered capabilities and Blue rules and record completed, skipped, blocked and not-applicable procedures without treating absence as proof of security. Next, embed selected plan coverage into the report and add reusable plan templates.

### P5: Reporting quality — QA gate implemented

Source-output QA and reproducible evidence-bound PDF/DOCX templates now require literal human approval after render verification. Reusable finding narratives and client template customization remain future work.

### Later enterprise work

Multi-user RBAC, client portals, ticketing integrations, portfolio analytics and attack-path visualization are valuable, but should follow the single-operator endpoint, purple-validation and remediation workflows.

## Product Test

WAR-R00M should not be judged by how many commands it can launch. A stronger release should answer these questions clearly:

1. What exact work was authorized?
2. What ran, under which approval and budget?
3. What evidence supports each conclusion?
4. Which defensive control was expected to observe the behaviour?
5. Was telemetry healthy enough for that result to mean anything?
6. Who owns the fix and when is it due?
7. Did a separately approved retest prove measurable improvement?
