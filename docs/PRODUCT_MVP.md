# Product and Data Model

## Product Direction

Build a mission-centric operational console, not a chat interface.

- **Mission:** durable engagement, authorization, exact scope and reporting boundary.
- **Plan version:** operator-reviewed sequence of steps.
- **Run:** one immutable execution of a plan version.
- **Retest:** targeted validation of a finding.
- **Replay:** a new run using pinned prior configuration, followed by variance analysis.

The MVP uses supervised autonomy. A discovered system can never silently become an authorized target.

## Navigation

Main navigation:

`Missions` | `Approvals` | `Findings` | `Evidence` | `Reports` | `System`

Mission navigation:

`Scope` | `Plan` | `Live` | `Findings` | `Evidence` | `Report` | `Runs`

The default view is a dense missions table showing status, exact targets, current run, pending approvals, findings, elapsed time, token usage, and last activity.

## Live War Room

- Fixed command bar: mission, environment, target health, runtime, usage budget, pause and emergency stop.
- Plan pane: ordered steps, dependencies, target and state.
- Event pane: UTC time, source, exact target, action, result, duration, evidence count and correlation ID.
- Inspector pane: typed parameters, policy decision, approval context, bounded output and artifact links.

Approvals show the exact action, canonical target, scope result, expected impact, limits, rollback notes and expiry. Approve, deny and defer remain explicit commands.

## Core Entities

```text
Mission 1--N ScopeVersion 1--N ScopeTarget N--1 Target
Mission 1--N PlanVersion 1--N PlanStep N--1 TechniqueVersion
Mission 1--N Run 1--N StepExecution 1--N Event
StepExecution 1--N ToolInvocation / ModelInvocation / ApprovalRequest
Mission 1--N Finding 1--N FindingRevision N--N TaxonomyReference
Artifact N--N Event/Finding/Invocation through EvidenceLink
Run 1--N UsageLedger
Run N--1 parent_run for replay/retest lineage
Report 1--1 ReportSnapshot 1--N ReportOutput
```

Tools receive a backend-resolved `target_id`, never a model-generated destination string. Events are append-only. Artifacts are content-addressed. Model invocations record provider, exact model, prompt-template hash, token counts and latency.

## Status Model

```text
Mission: draft -> scope_validated -> ready -> active -> complete -> closed
Run: queued -> awaiting_approval -> armed -> running -> succeeded | failed
Run stop: running -> stop_requested -> phase1_halted -> draining -> stopped | stop_incomplete
Step: proposed -> awaiting_approval -> approved -> queued -> running -> succeeded | failed
Approval: pending -> approved | denied | expired; approved -> revoked | superseded
Finding: candidate -> unverified -> confirmed -> accepted -> retest_pending -> remediated | persists
Report: draft -> validating -> blocked | frozen -> generating -> generated -> signed
Artifact: capturing -> sealed | capture_failed
```

## MVP Scope

1. Mission wizard with exact targets, exclusions, test window and authorization attachment.
2. Versioned linear plan with dependencies, risk and approval gates.
3. A very small set of typed low-risk adapters after policy tests pass.
4. Live event stream, pause, two-phase emergency stop and target-health checks.
5. Finding workbench with evidence, confidence and OWASP/CWE references.
6. Deterministic HTML and JSON reports; verified PDF follows.
7. Model-token, wall-time, tool-time and output budgets with hard ceilings.
8. Retest and replay with lineage and side-by-side variance.
9. Operator and reviewer roles only.

Defer multi-tenancy, autonomous exploitation chains, attack graphs, cloud integrations, custom report designers and chat-first control.

## Reporting Rule

Freezing a report records exact scope, plan/run versions, accepted finding revisions, evidence hashes, taxonomy versions, template version and generation timestamp. The renderer makes no model calls and performs no live lookups.

The project may describe itself as informed by [OWASP APTS](https://owasp.org/APTS/), but it must not claim formal conformance without completing and evidencing the standard's requirements.
