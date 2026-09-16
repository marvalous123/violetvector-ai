# VioletVector AI v0.1.1 candidate: easier first run

This candidate separates synthetic community evaluation from the full
developer/native-sensor verification workflow.

- New `Start VioletVector Demo.cmd` entry point and `npm run demo`.
- Node-only setup builds the interface without .NET, WSL or Docker.
- Separate checkout-specific demo data; inherited live-adapter settings are
  overridden and a fresh bootstrap secret is generated for each launch.
- Browser opening waits for the local execution-disabled health endpoint.
- Three-step installation instructions and common recovery actions.

No new live capabilities, endpoint collection or execution authority are added.
The complete maintainer verification gate remains required before publication.
This is a release candidate note, not a claim that v0.1.1 has been published.

## Local verification — 2026-09-16

- Complete `npm run verify` passed: full workspace/native tests, type checks,
  lint, production/native builds, guarded receipt/package checks, repository
  safety and Git integrity. All 18 tracked PowerShell scripts parsed.
- Native Windows boundary tests: 177/177; bounded security mutations: 61/61.
- Final launcher-focused tests: 4/4; final lint passed after launcher edits.
- `npm run smoke:demo` passed on a fresh source-only folder with spaces and no
  dependency link: independent `npm ci`, protected unlock, disabled MCPwn and
  target catalogue, synthetic mission, JSON/HTML report contents, occupied-port
  rejection, fresh restart secret and retained report.

The smoke test used this existing Windows laptop, not a separate clean Windows
machine. Browser auto-opening was not exercised by the headless smoke. External
tester feedback and hosted CI for this candidate remain unverified until it is
published. No machine sensor was installed or live target contacted.
