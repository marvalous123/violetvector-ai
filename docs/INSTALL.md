# Public Preview Installation

VioletVector AI `0.1.x` supports Windows 11 for evaluation and feedback. Start
with the zero-target guided demo. Community users should not configure or run
the maintainer-only Redmi execution lane.

## Requirements

- Git
- PowerShell 7
- Node.js 22 or newer with npm
- .NET 8 SDK
- A current Windows account that can create files under its own profile

Ollama is optional. Kali WSL2 and Docker are not required for the guided demo.

## Install and verify

From an ordinary, non-elevated PowerShell:

```powershell
git clone https://github.com/marvalous123/violetvector-ai.git
Set-Location -LiteralPath '.\violetvector-ai'
npm ci
npm run verify
.\scripts\install-local.ps1
.\scripts\start-local.ps1
```

Open `http://127.0.0.1:4315`. The launcher prints a one-time bootstrap secret in
the same terminal. Enter a local operator name and that secret, then create the
guided demo from the Missions screen.

The launcher binds only to loopback. Do not expose port 4315 through a firewall,
reverse proxy, tunnel or port-forward.

## Stop

Press `Ctrl+C` in the launcher terminal. The in-process bootstrap value is
cleared when the launcher exits.

## Backup

```powershell
.\scripts\backup-local.ps1
```

The command creates a manifest-hashed backup outside the repository. Backups
are not encrypted by VioletVector AI; retain them only in protected storage.

Restore is non-overwriting and requires a new empty destination:

```powershell
.\scripts\restore-local.ps1 `
  -BackupRoot 'C:\path\to\war-room-backup-...' `
  -DestinationRoot 'C:\path\to\empty-new-runtime'
```

## Getting help

Use the structured GitHub issue forms with synthetic data. Never attach runtime
databases, target addresses, credentials, raw logs, private evidence or client
information. Follow `SECURITY.md` for private vulnerability reporting.
