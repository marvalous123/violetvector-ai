# VioletVector AI

VioletVector AI is a local-first, human-controlled security assessment control plane for authorized labs. It combines an original operator interface and policy gateway with Parrot Security's MCPwn tool bridge, local AI providers, Kali WSL2, and isolated practice targets.

## Naming

**VioletVector AI** is the public product name. Existing `WAR-R00M` service,
path, environment-variable and source identifiers are legacy technical names
that will be migrated separately after installed-state compatibility planning.

In this project, **Parrot AI** means the MCPwn project published by Parrot Security. It does not mean Parrot OS, and MCPwn is not itself an AI model.

## Public Preview

VioletVector AI `0.1.x` is an engineering preview for evaluation and feedback,
not a production pentest service or autonomous attack tool. New users should
start with the zero-target guided demo and network-free diagnostic. The current
maintainer target adapter is deliberately sealed to one isolated, owner-approved
lab device and is not a general target configuration mechanism.

Use the project only on systems you own or have explicit written authorization
to test. Do not post credentials, raw logs, target addresses, private evidence,
client data or exploit material in public issues.

- Report ordinary bugs through [GitHub Issues](https://github.com/marvalous123/violetvector-ai/issues).
- Propose improvements through the feature-request template.
- Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## Intended Architecture

```text
Operator
  -> VioletVector AI UI and API
     -> scope and policy validation
     -> risk classification and approval
     -> audited execution gateway
        -> MCPwn
           -> approved Kali tools
              -> isolated, user-owned lab target

Local AI provider
  -> proposes structured actions
  -> summarizes evidence
  -> never invokes MCPwn directly
```

## Project Boundaries

- Project 14 T3MP3ST remains separate and unchanged.
- Atlas, the home server, employer assets, public systems, and third-party systems are out of scope.
- The Redmi may become a target only after network isolation and a written target record are verified.
- A model can propose an action, but only the policy-controlled backend can invoke MCPwn.
- Findings and reports must be traceable to captured evidence.

## Current Status

The safe local control plane is implemented and verified: a React operator console, protected local operator sessions, loopback-only Node API, SQLite persistence, strict target policy, atomic run-bound approval consumption, audit chaining, budgets, emergency-stop cancellation, a persistent execution lifecycle, mission-bound evidence, reviewed findings and deterministic reports. Unchanged evidence cannot create duplicate current reports. A selected-mission cockpit and fully offline guided mission make the complete authorization-to-report journey visible without a phone or endpoint. The professional workflow adds an inert bounded SARIF importer, deterministic mission-scoped candidate deduplication, append-only remediation ownership and retest history, immutable engagement-plan versions, mission-bounded search and evidence-backed original/retest comparison.

A hash-pinned broker exposes one network-free MCPwn diagnostic, `mcpwn.version.v1`. A separate exact-target adapter exposes reviewed TCP profiles only after live Redmi USB isolation verification, an expiring parameter-bound approval, and a second deliberate execute action. Completed target runs can prepare a same-target, same-parameter retest with explicit parent lineage, but only inside a fresh active scope and through a new approval. A separate Blue Team workspace provides thirty synthetic-validated detection coverage areas, a per-rule Purple Validation Matrix and mission-bound simulation evidence. The source-verified data boundary has real algorithm-derived Ed25519/ECDSA P-256 proof verification, immutable endpoint-key binding, atomic identity renewal, exact source-capability health, signed minimized primitive facts and server-owned correlation definitions for all thirty rules. Stale, lossy, gapped, incomplete or tampered streams fail closed. A native .NET Windows Service and exact Software KSP machine-identity provisioner now build and pass boundary tests, and the machine key plus Gate B1 service have real elevated proofs. The protected C0b lifecycle was machine-completed, and one attended C2g ceremony genuinely observed exactly one matching Security 4663 metadata event through the bounded one-shot path. This proves that single observation and protected lifecycle only. The service still has no continuous collector or transport, so the normal laptop runtime makes no production live-support or endpoint-protection claim. The TPM provider is explicitly deferred until its provider-managed ACL can be validated safely.

The exact-target workflows accept no caller-supplied destination, command, script name or raw arguments. The backend resolves the sole stored target and rechecks the direct USB route, interface address, exact ordered firewall, empty Docker network and immutable image before proposal and execution. The capability catalogue includes low-noise selected-port state, bounded service fingerprinting, HTTP title/header metadata, TLS certificate metadata, T2 cipher posture and all-TCP discovery. HTTP/TLS script names are hard-coded backend allowlists. Profiles are labelled by risk, operator difficulty and network noise; none is covert or destructive.

The isolated Redmi workflow has completed an original assessment and one controlled same-parameter retest. Both observations were sealed as evidence and cited by an accepted informational finding and final deterministic JSON/HTML report. The retest confirmed that the isolated TCP 53 `dnsmasq 2.51` service remained observable; it did not establish a vulnerability or exploitability. New report snapshots can also produce sealed PDF and DOCX derivatives, but neither format becomes publication-ready until source QA and a second exact-output visual QA decision are both approved.

The current MCPwn integration is the network-free version proof. Target-bearing profiles use the separate deterministic, digest-pinned Nmap container adapter; do not describe those target runs as MCPwn-driven until each one is routed through a reviewed restricted MCPwn configuration.

## Capability Packs

Developers can extend the closed architecture through the reviewed [Capability Pack SDK boundary](docs/CAPABILITY_PACK_SDK.md). The v1 manifest binds hashes, risk, permissions, budgets and evidence types while literally denying credential access, payload execution and evasion controls. A manifest never loads or executes uploaded code; an adapter must still be implemented, reviewed, registered and pass the complete verification gate.

## Product Editions

- `Starter`: missions, local planning, low-noise TCP state, targeted service checks, the 30-rule synthetic Blue Team lab, evidence, findings and reports.
- `Professional`: adds HTTP/TLS posture, intensive all-TCP discovery, advanced retest workflows, engagement-plan versions, bounded comparison/search and capability-pack development.

Both editions retain the same scope, approval, isolation, audit and evidence controls. Set `WAR_ROOM_EDITION=starter` before launch to exercise the Starter gate; the current local build defaults to `professional`. Edition checks are enforced in backend routes as well as shown in the UI. This is a packaging boundary, not a payment or licence server.

The Blue Team design is documented in [docs/BLUE_TEAM_DETECTION.md](docs/BLUE_TEAM_DETECTION.md). The first non-collecting Windows source-readiness boundary is recorded in [docs/WINDOWS_TELEMETRY_GATE_A.md](docs/WINDOWS_TELEMETRY_GATE_A.md). Live endpoint detection still requires an enrolled read-only telemetry sensor; it does not require or receive a remote shell.

## Local Development

### Supported preview environment

- Windows 11 with PowerShell 7
- Node.js 24.12 or newer and npm
- .NET 8 SDK for the Windows sensor build and boundary tests
- Optional: Ollama for local advisory planning
- Optional and maintainer-only: Kali WSL2 plus Docker for the sealed Redmi lane

Clone the repository, install the exact lockfile and run the complete gate:

```powershell
npm ci
npm run verify
```

To build and run the integrated local console, then open
`http://127.0.0.1:4315`:

```powershell
.\scripts\install-local.ps1
.\scripts\start-local.ps1
```

Community evaluation should use the guided demo and must not enable live target
execution. Maintainers working with the owned Redmi must deliberately isolate it,
record fresh written authorization and restore the exact-target Docker firewall
before starting:

```powershell
.\scripts\prepare-redmi-isolation.ps1
```

The startup script creates a fresh 256-bit bootstrap secret in process memory and prints it only in that terminal. Open `http://127.0.0.1:4315`, enter an operator name and that secret, then the browser receives a memory-only, HttpOnly session. The environment value is cleared when the process stops. A deliberately preconfigured `WAR_ROOM_OPERATOR_BOOTSTRAP` remains supported for controlled automation.

Create a consistent, manifest-hashed backup of the SQLite database and every registered evidence artifact:

```powershell
.\scripts\backup-local.ps1
```

Restore is deliberately non-overwriting and accepts only a verified backup into a new destination:

```powershell
.\scripts\restore-local.ps1 -BackupRoot 'C:\path\to\war-room-backup-...' -DestinationRoot 'C:\path\to\empty-new-runtime'
```

The authenticated System screen provides a redacted support snapshot with database, audit and bounded evidence-integrity state. It verifies at most 500 artifacts or 32 MiB per request, labels larger stores `PARTIAL`, and omits targets, evidence content, secrets and local paths.

Generated production files and runtime data are written outside the repository
so build output, databases and evidence cannot be committed accidentally. See
the [public-preview installation guide](docs/INSTALL.md) for first-run and
recovery instructions.

See [Why WAR-R00M Exists](docs/WHY_WAR_ROOM.md), [Installation](docs/INSTALL.md),
[Implemented Security Controls](docs/SECURITY_CONTROLS.md), [Public Preview](docs/PUBLIC_PREVIEW.md),
[Capability Pack SDK Boundary](docs/CAPABILITY_PACK_SDK.md) and the
[Product Benchmark](docs/PRODUCT_BENCHMARK.md).

Internal maintainer handoffs are intentionally excluded from public-preview
source snapshots.
