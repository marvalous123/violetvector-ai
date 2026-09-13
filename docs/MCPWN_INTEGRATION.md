# MCPwn Integration Research

Verified: 2026-07-17

## Current Upstream

- Current reviewed commit: [`b953965c`](https://gitlab.com/parrotsec/project/mcpwn/-/commit/b953965cd084dbfb2cf8a6fb879ec0741aef60d1), dated 2026-07-15.
- The commit follows the [`v1.3.0` tag](https://gitlab.com/parrotsec/project/mcpwn/-/tags/v1.3.0) and improves raw-argument array handling.
- The public releases page does not currently provide a v1.3.0 binary. Build and test pinned source rather than using an older binary release.
- MCPwn is a stdio MCP server. JSON-RPC uses stdin/stdout and logs use stderr.

## Recommended Placement

```text
Windows War Room API
  -> wsl.exe stdio child process
  -> pinned MCPwn binary inside Kali WSL2
  -> Docker inside Kali
  -> restricted containerized tool
  -> exact isolated target
```

This avoids installing Docker, Podman or Go on Windows. Avoid `bash -lc` in the final bridge because shell startup output can corrupt MCP stdio.

## Verified Environment Direction

The discovery pass found that Kali already has Go, Docker and the seven tools represented in MCPwn's default configuration. This must be rechecked in the Project 15 task immediately before building or executing MCPwn.

MCPwn's current default tool set is:

- nmap
- gobuster
- ffuf
- httpx
- sqlmap
- msfvenom
- msfconsole

The default configuration is **not** the Project 15 policy. Project 15 will provide a restricted configuration and its own deterministic gateway.

## Network-Free Proof Status

The pinned source build, offline vendor tests and real MCP stdio `nmap --version` call are complete. See [MCPwn Network-Free Proof](MCPWN_NETWORK_FREE_PROOF.md).

The War Room now contains a second proof layer: a TypeScript broker and authenticated operator route for the version check. The broker rehashes the exact binary and sibling `mcpwn.yaml`, launches `wsl.exe` without a shell, accepts no caller-controlled MCP fields, bounds both output streams and time, supports emergency cancellation, and records only safe metadata in the audit chain. General and target-bearing execution remain disabled.

The tracked restricted configuration is [mcpwn-network-free.yaml](../config/mcpwn-network-free.yaml):

```yaml
tools:
  - name: nmap_version
    description: Report the installed Nmap version without scanning.
    command: nmap
    fixed_args: ["--version"]
    args: []
    timeout: "15s"
    max_output_bytes: 65536
    success_exit_codes: [0]
```

This first proof deliberately used Kali's native Nmap because it accepted no target or dynamic argument and avoided pulling an unreviewed container image. Target-facing capabilities must use a reviewed image pinned by digest.

## Important Risks

- `extra_args` is unrestricted CLI passthrough. It is excluded from Project 15 adapters.
- MCPwn does not validate ownership, scope or target allowlists.
- A positional value beginning with `-` may become another tool flag unless the adapter prevents it.
- File arguments may expose files visible to native execution or mounted containers.
- `msfconsole_run.commands` is a powerful internal command language.
- The default Metasploit configuration uses host networking.
- The default msfvenom configuration persists generated files through a host mount.
- Docker group access is highly privileged inside Kali. Rootless Podman is a possible later hardening step.
- Default container image references are not pinned by digest.

## Output Retention

MCPwn stores complete stdout and stderr for each invocation. `MCPWN_OUTPUT_DIR` should point to a Project 15-specific private runtime directory. Output files are sensitive runtime data and remain outside Git.

There is no built-in retention policy or delete tool in the reviewed version. Project 15 must add reviewable retention and cleanup behavior. Container `--rm` does not delete MCPwn logs, images or host-mounted files.

## Progressive Enablement

1. Network-free `nmap --version` proof of plumbing.
2. Fixed loopback connectivity test in an isolated container network.
3. Fixed target for one deliberately deployed training service.
4. Bounded HTTP inspection against the exact target.
5. Bounded content discovery with fixed wordlist and low concurrency.
6. Template validation against a disposable training application.
7. SQL detection only after separate policy tests.

Payload generation, Metasploit, dumping, interactive consoles and raw argument passthrough remain disabled.

## Mandatory Verification Before Use

- Recheck the upstream commit and source diff.
- Run all Go tests locally.
- Verify container image digests and inspect the restricted YAML.
- Verify the exact MCP client framing through `wsl.exe`.
- Verify Kali Docker health and note any degraded services.
- Prove the scope policy and emergency stop before using any network target.

## References

- [MCPwn repository](https://gitlab.com/parrotsec/project/mcpwn)
- [Default MCPwn configuration](https://gitlab.com/parrotsec/project/mcpwn/-/blob/b953965cd084dbfb2cf8a6fb879ec0741aef60d1/mcpwn.yaml)
- [MCPwn executor](https://gitlab.com/parrotsec/project/mcpwn/-/blob/b953965cd084dbfb2cf8a6fb879ec0741aef60d1/internal/executor/run.go)
- [MCPwn output store](https://gitlab.com/parrotsec/project/mcpwn/-/blob/b953965cd084dbfb2cf8a6fb879ec0741aef60d1/internal/output/store.go)
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [Microsoft WSL command interoperability](https://learn.microsoft.com/en-us/windows/wsl/filesystems)
