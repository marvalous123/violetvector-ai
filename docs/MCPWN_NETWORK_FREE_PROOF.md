# MCPwn Network-Free Proof

Verified: 2026-07-17

## Outcome

Pinned MCPwn source was tested and built inside Kali WSL2, then exercised through its real newline-delimited JSON-RPC stdio transport. The only configured command was the fixed, argument-free `nmap --version`.

No target, destination, port, URL, hostname, CIDR or caller-controlled argument was supplied. The War Room application still has no executor route and did not invoke this proof.

## Pinned Inputs

- Upstream: `https://gitlab.com/parrotsec/project/mcpwn.git`
- Detached commit: `b953965cd084dbfb2cf8a6fb879ec0741aef60d1`
- Source archive SHA-256: `489f93b9886f0c5cf3045a951d248648e5efd30e07bb5778edc80c7e9c6269f0`
- `go.mod` SHA-256: `09cd4d7a65cbcd72dce446f195c0edbb7ccc147166be4788f42099cdac2e1531`
- `go.sum` SHA-256: `19f760acff189c1837cdb67b4ef434d366923a6a9cd3b79e2b5a49ce0181644f`
- Restricted configuration SHA-256: `d94bb971a14632c5107c5e13f2389d530f2cd658e714011a2cee05896bd26b7b`
- Built binary SHA-256: `178d7a7cd254789ee8f197b54b38f3baa5146fd5a515b640999c69bcb51b5e12`

The source checkout is outside this repository at:

`/home/kali/.local/share/war-room-project15/tools/mcpwn-src`

It is detached at the pinned commit, clean, and has its push URL disabled.

## Environment

- Kali WSL2
- Go `1.26.2`
- Docker `28.5.2+dfsg4`
- Nmap `7.99`
- MCP protocol negotiated: `2025-06-18`

Docker responded to `docker info`, although systemd still described the service as `activating`. Docker was not needed for the version-only proof.

## Offline Build Verification

Tests and the build used the committed vendor tree with module networking disabled:

```text
GOTOOLCHAIN=local
GOPROXY=off
go test -mod=vendor -count=1 ./...
go build -mod=vendor -trimpath -buildvcs=true ./cmd/mcpwn
```

Passing packages:

- `internal/config`
- `internal/executor`
- `internal/output`
- `internal/server`

The binary build metadata records the exact `b953965c...` Git revision and `vcs.modified=false`.

## Stdio Proof

The deterministic smoke client:

1. Started the pinned binary with the restricted configuration.
2. Completed MCP `initialize`.
3. Sent `notifications/initialized`.
4. Listed tools.
5. Called `nmap_version` with an empty argument object.
6. Confirmed successful output beginning with `Nmap version 7.99`.
7. Terminated the MCPwn process.

Exposed tools were:

- `nmap_version`
- `mcpwn_read_output`
- `mcpwn_search_output`
- `mcpwn_tail_output`

The latter three are MCPwn's built-in stored-output readers, not operating-system command tools.

The output file was created with mode `0600`, size 253 bytes, and SHA-256:

`5f44e256e974cd9a1c65ffba56823c895de901b200feed1ad658da8025a46a9c`

No MCPwn process or Nmap network connection remained after the proof.

## Remaining Gates

- Do not expose this binary through an API route yet.
- Implement a broker that accepts only typed backend capability IDs and never arbitrary commands or MCP arguments.
- Recheck binary and configuration hashes at every launch.
- Use direct `wsl.exe` argv rather than a shell in the final adapter.
- Bound process lifetime, stdout/stderr and persisted output.
- Connect cancellation to the persisted emergency-stop lifecycle.
- Move target-facing tools into reviewed digest-pinned containers.
- Verify Redmi isolation before any target-bearing capability exists.
