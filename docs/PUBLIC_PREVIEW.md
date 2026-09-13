# Public Preview Guide

## What reviewers can evaluate

- The offline guided mission and selected-mission cockpit.
- Exact scope and authorization data modelling.
- Human approval, budgets, emergency stop and audit history.
- Synthetic Blue Team validation with explicit limitations.
- Evidence, finding, remediation, retest comparison and report workflows.
- Source architecture, deterministic tests and fail-closed boundaries.

## What reviewers must not do

- Point the software at public, employer, client or third-party systems.
- Modify the sealed maintainer target to reach another host.
- Submit credentials, private evidence, target details or raw security output.
- Describe synthetic detections as production endpoint protection.

## Useful feedback

The most valuable early feedback is whether installation is clear, the guided
demo explains the product, approval boundaries are understandable, reports are
useful, failure messages identify the next safe action and the source is easy to
navigate. Use the structured GitHub issue forms so feedback remains actionable.

## Known preview limitations

- Windows 11 is the only supported preview host.
- There is no signed MSI/MSIX installer or automatic updater.
- The live Redmi adapter is maintainer-specific, not a general target feature.
- Continuous Windows collection and remote telemetry remain disabled.
- There is no multi-user service, client portal or hosted deployment.
