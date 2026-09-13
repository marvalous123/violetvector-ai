# Blue Team Detection Lane

## Product boundary

WAR-R00M now contains a defensive Blue Team workspace with thirty curated coverage areas:

- 10 credential-access detections.
- 10 payload-execution detections.
- 10 defense-evasion detections.

“Top ten” means ten high-value coverage areas selected for a useful training and business baseline. It is not a frequency ranking, and ATT&CK does not rank techniques by prevalence.

All thirty areas have a **synthetic-validated** lane. Four built-in scenarios generate bounded normalized labels, run the closed `blue-rules-v1` matcher, seal the result as mission-bound evidence and mark every alert `needs-review`. They never read a credential store, create or execute a payload, change a security control or contact an endpoint.

All thirty rules now also have a versioned server-owned live-correlation definition over signed primitive facts. The mappings use only strict normalized enums and privacy-safe hashes; the sensor cannot submit a rule ID, alert or verdict. A rule becomes live-supported for one exact endpoint/run only when its declared provider, channel, event family, required fields and filter are complete, continuous, loss-free, fresh and cryptographically bound. This is narrow mapping coverage rather than proof that every supporting enterprise source is collected. The repository includes a synthetic fixture sensor to prove the boundary; it is not an installed production collector.

Gate C2a now audits those definitions against documented Windows sources. Gate C2b makes unsupported sources unconditionally block genuine-live eligibility. Gate C2c has inert Security 1102/4663 parsers and a pure HMAC-bound classifier. Gate C2d has a non-mutating least-privilege plan, read-only checker and completed guarded apply/check/recovery rollback for the Security channel, File System auditing and inert SACL targets. Gate C2e freezes a non-mutating one-shot plan with exact approval, record, time, profile and privacy bounds plus a pure fake-reader coordinator. Gate C2f now has separate signed live-read approval/result boundaries and an exact one-shot LocalService read/normalize/write branch. Its controlled reinstall/live exercise was reported complete and clean rollback independently verified, but exact result JSON/read state was not retained. Every result therefore remains blocked from genuine-live eligibility. Continuous collection and transport remain absent; see `WINDOWS_GENUINE_SOURCE_VALIDATION.md`.

## Credential-access coverage

| Rule | ATT&CK coverage | Defensive focus |
|---|---|---|
| BR-CRED-001 | [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) | Unexpected access to sensitive authentication memory or credential-bearing registry data. |
| BR-CRED-002 | [T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/) | Non-owner process access to classified browser, operating-system, keyring or vault stores. |
| BR-CRED-003 | [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) | Rare-process access to classified configuration, history, key or metadata locations. |
| BR-CRED-004 | [T1056 Input Capture](https://attack.mitre.org/techniques/T1056/) | Unexpected input hooks, device access or related permission changes. |
| BR-CRED-005 | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Authentication failure bursts, spray shapes and failures followed by success. |
| BR-CRED-006 | [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) | Abnormal ticket fields, encryption, sequence or service-account activity. |
| BR-CRED-007 | [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) | Non-browser session-store access correlated with new session context. |
| BR-CRED-008 | [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) | Token or metadata access followed by API use in a new context. |
| BR-CRED-009 | [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) | Unexpected authentication package, PAM, MFA or identity-policy changes. |
| BR-CRED-010 | [T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) | Unusual private-key access, enrollment, export, CA change or certificate use. |

## Payload-execution coverage

| Rule | ATT&CK coverage | Defensive focus |
|---|---|---|
| BR-PAYLOAD-001 | [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) | Delivered file followed by an unusual document-child execution chain. |
| BR-PAYLOAD-002 | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Unusual parent plus suspicious script, module, child or network behavior. |
| BR-PAYLOAD-003 | [T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005/) | Unusual Mshta lineage with remote, file or child activity. |
| BR-PAYLOAD-004 | [T1218.007 Msiexec](https://attack.mitre.org/techniques/T1218/007/) | Untrusted installer origin followed by rare child, module or service activity. |
| BR-PAYLOAD-005 | [T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010/) | Untrusted module, writable path, remote content or network activity. |
| BR-PAYLOAD-006 | [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011/) | Atypical DLL path or load combined with unusual execution context. |
| BR-PAYLOAD-007 | [T1574.001 Hijack Execution Flow: DLL](https://attack.mitre.org/techniques/T1574/001/) | Trusted process loads an unexpected DLL from a writable or non-standard path. |
| BR-PAYLOAD-008 | [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/) | Cross-process memory access, writes, allocation or remote-thread-like activity. |
| BR-PAYLOAD-009 | [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | New or altered task followed by suspicious execution. |
| BR-PAYLOAD-010 | [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/) | New or modified service with an unusual binary, path, signer or creator. |

## Defense-evasion coverage

The live ATT&CK catalogue changed in 2026. Current mappings use the new Defense Impairment techniques `T1685` and `T1686`; older material may still show former `T1562` or `T1070.001` mappings.

| Rule | ATT&CK coverage | Defensive focus |
|---|---|---|
| BR-EVASION-001 | [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) | Security-agent process, service, policy, driver, update or heartbeat impairment. |
| BR-EVASION-002 | [T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/) | Logging service, audit policy, registry or record-continuity drift. |
| BR-EVASION-003 | [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Log clearing correlated with process, file and sequence evidence. |
| BR-EVASION-004 | [T1686 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686/) | Unauthorized firewall rule, profile, service or policy change. |
| BR-EVASION-005 | [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/) | Cross-process manipulation used to move behavior into another process. |
| BR-EVASION-006 | [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) | Trusted binary with unusual parent/content and follow-on behavior. |
| BR-EVASION-007 | [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Encoded or high-entropy content with suspicious execution context. |
| BR-EVASION-008 | [T1036 Masquerading](https://attack.mitre.org/techniques/T1036/) | Filename, path, signer, metadata and software-inventory mismatch. |
| BR-EVASION-009 | [T1564 Hide Artifacts](https://attack.mitre.org/techniques/T1564/) | Hidden attributes, alternate streams and visibility/inventory changes. |
| BR-EVASION-010 | [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004/) | Deletion shortly after artifact creation or execution. |

## Why live detection needs endpoint access

Network scans cannot observe process ancestry, process access, DLL loads, file and registry changes, authentication flows, task or service creation, security-control changes or event-log integrity. Live support therefore requires telemetry access to the protected machine and, for some credential rules, identity, cloud or certificate-authority audit sources.

That access does not need to be a remote shell. The intended boundary is:

```text
Endpoint or identity event source
  -> least-privilege read-only collector
  -> local redaction and normalization
  -> signed, sequenced outbound batch
  -> isolated telemetry-only intake
  -> deterministic rules
  -> mission-bound evidence and reviewable alerts
```

The implemented endpoint path now enforces:

- Ed25519 SPKI public-key enrollment proof and immutable connector/endpoint/mission identity binding.
- Atomic replacement-key renewal: a fresh proved identity becomes active in the same transaction that revokes the replaced identity.
- Exact provider, channel, event-family, primitive-field and filter-hash capability reports.
- Explicit continuity, loss count, freshness, continuous-since and last-successful-read measurements.
- A strict primitive-fact allowlist with no raw command, path, script, credential, token, memory or file-content fields.
- Connector, endpoint, boot, sequence and previous-batch bindings.
- Contiguous sequence validation, previous-batch hash, batch hash and endpoint signatures.
- Server-owned live correlations that never trust a sensor-supplied rule, alert or verdict.
- Data-only acknowledgements with no action, command or job field.
- Per-run status that fails closed when a required stream is missing, incomplete, lossy, gapped or stale.

The Windows Service is installed as manual-start LocalService and can open its exact non-exportable Software KSP ECDSA P-256 machine key, validate the protected ACL and complete a startup signature. The exact elevated probe cleanup, real-restart validation and controlled identity-preserving uninstall/reinstall exercise passed on 2026-07-29. Telemetry Gate A proves exact `System` and `Application` log metadata under LocalService while reading zero events. Gate B0 proves exactly two fixed synthetic signed local batches and protected persistence under the real service identity. Gate B1 now machine-proves one bounded genuine SCM 7045 metadata fact with no raw content. The installed service still has no continuous collector or transport, and the separate isolated telemetry intake is not installed. The normal laptop runtime therefore remains connector-required unless an explicitly enrolled fixture submits a healthy signed stream. Gate B1 proves only its single metadata family, not broad detection coverage or endpoint protection.

## Purple Validation Matrix

The Blue Team workspace exposes a mission-scoped 30-row matrix joining every defensive rule to its safe scenario, required telemetry, latest observed alert or miss and sealed evidence artifact. With no mission selected, all rows remain `not-run` and no run or evidence ID is returned. A synthetic row can be `not-run`, `detected`, `not-detected` or `integrity-failed`. Live results are displayed separately with endpoint capability health and sealed correlation evidence; an offline rule match cannot become endpoint proof.

## Windows-first production connector

The lifecycle gates, LocalService Gate A, synthetic Gate B0, genuine Gate B1, C0b enrollment, C0c one-shot loopback delivery and C1c protected two-family snapshot have completed their bounded machine ceremonies. Gate C2a freezes the documented-source audit before any broader reader is designed. Later reviewed channels may include Sysmon, Windows Security, Defender Operational, PowerShell Operational and Task Scheduler. Each extension must retain the installed least-privilege identity. No sensor may listen on a port or accept jobs.

Microsoft documents the useful Sysmon event families for process creation, network connections, image loads, process access, remote threads, registry activity and file deletion in the [official Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

The main WAR-R00M browser/API must remain on loopback. A separate collector process can accept mutually authenticated telemetry on an exact isolated lab adapter only after the separate transport gate passes, without exposing the UI, model, executor or mission APIs.

## Evidence and claims

- Every simulation result stores its exact normalized events, rule snapshot, alert reasons, response guidance and limitation.
- The evidence artifact and database result must both match the canonical result hash.
- Detection runs are immutable.
- Alerts remain `needs-review`.
- “No match” with partial or stale telemetry must never be reported as “endpoint clean.”
- A Blue alert cannot create a red-team proposal, approval or executor call.
