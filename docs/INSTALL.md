# Public Preview Installation

VioletVector AI `0.1.x` supports Windows 11 for evaluation and feedback. Start
with the zero-target guided demo. Community users should not configure or run
the maintainer-only Redmi execution lane.

## Quick start: guided demo

For the synthetic demo you need **Windows 11 and Node.js 24.12 or newer with
npm**. Windows PowerShell is included with Windows. Git is optional: either
clone the repository or download and extract its source ZIP from GitHub.
Do not run from inside the ZIP preview.

1. Install Node.js if needed, then extract the source into a folder you own.
2. Double-click **Start VioletVector Demo.cmd**. First setup downloads the locked
   dependencies, validates and builds the interface, then opens your browser.
3. Keep the terminal open. Enter your name and the one-time secret printed there,
   click **Create guided demo** on Missions, then review the finding and report.

The demo launcher disables MCPwn and Redmi execution even if your environment
previously enabled them. It does not build or install a native sensor, and needs
no .NET, Ollama, WSL, Docker, administrator access or real target. Dependencies
need internet access during setup; the guided mission itself uses synthetic
local data. Optional AI planning is a separate user-initiated operation, not part
of the guided demo.
An unavailable local-AI provider is expected if Ollama is not installed; it does
not prevent the synthetic mission, finding or report.

Each extracted checkout keeps its demo data and interface under a separate
`.violetvector-preview` folder in your user profile. It never opens the existing
maintainer `.war-room-project15` database. Relaunching the same checkout preserves
your demo history and creates a fresh bootstrap secret. The secret is not put in
the browser URL or written to a file.

### If something goes wrong

- **Node missing or too old:** install Node.js 24.12+, then retry the launcher.
- **Download failed:** check internet access and retry; setup repeats safely.
- **Browser did not open:** open the localhost URL printed in the terminal.
- **Port already occupied:** stop your previous console, or use
  `powershell -NoProfile -File .\scripts\start-demo.ps1 -Port 4316`.
- **Invalid secret:** use the secret from the currently running terminal.
- **Stop:** press `Ctrl+C` in that terminal. Closing a browser tab does not stop
  the server. Do not expose its port through a tunnel or port-forward.

Developers can run `npm run demo`, or prepare without starting a server using
`powershell -NoProfile -File .\scripts\start-demo.ps1 -PrepareOnly`.
The launcher is unsigned source, not a signed Windows installer.

## Developer / maintainer requirements

- Git
- PowerShell 7
- Node.js 24.12 or newer with npm
- .NET 8 SDK
- A current Windows account that can create files under its own profile

Ollama is optional. Kali WSL2 and Docker are not required for the guided demo.

## Developer install and complete verification

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

The maintainer launcher binds only to loopback. Do not expose port 4315 through a firewall,
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
