# Contributing to VioletVector AI

Thank you for helping improve VioletVector AI. This public preview accepts
small, reviewable changes that preserve its local-first and human-controlled
security boundary.

## Before opening an issue

- Use the guided demo or network-free diagnostic unless you are working in an
  explicitly authorized isolated lab.
- Search existing issues first.
- Remove credentials, tokens, target addresses, private paths, raw logs,
  evidence, packet captures and client data.
- Report suspected vulnerabilities privately through GitHub's private
  vulnerability reporting flow, not a public issue.

## Development workflow

1. Create a focused branch from `main`.
2. Install the exact dependency graph with `npm ci` on Windows 11 and Node 24.12+.
3. Add or update deterministic tests for policy and workflow changes.
4. Run `npm run verify` before opening a pull request.
5. Explain the safety impact, tests and recovery path in the pull request.

## Non-negotiable boundaries

- Do not add autonomous target selection or execution.
- Do not let a model call MCPwn, a shell or an operating-system command.
- Do not add caller-supplied destinations, raw command strings, scripts,
  payloads, credential collection, evasion or post-exploitation authority.
- Preserve exact scope, fresh expiring approval, bounded execution, emergency
  stop, audit history and evidence-backed reporting.
- Never commit secrets, runtime databases, raw evidence or tool output.

Contributions that widen operational authority without a deterministic policy,
tests and an explicit maintainer decision will be closed.

By submitting a contribution, you agree that it is licensed under Apache-2.0.
