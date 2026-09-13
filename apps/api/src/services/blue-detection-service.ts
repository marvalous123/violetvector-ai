import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";

export const blueScenarioIdSchema = z.enum([
  "credential-access",
  "payload-execution",
  "defense-evasion",
  "combined-incident"
]);
export type BlueScenarioId = z.infer<typeof blueScenarioIdSchema>;

const signalIds = [
  "sensitive-auth-memory-access",
  "password-store-read",
  "unsecured-secret-access",
  "input-capture-registration",
  "authentication-failure-burst",
  "anomalous-ticket-use",
  "session-cookie-store-read",
  "application-token-access",
  "authentication-component-change",
  "authentication-certificate-access",
  "document-child-execution",
  "suspicious-powershell-chain",
  "mshta-proxy-execution",
  "msiexec-untrusted-package",
  "regsvr32-untrusted-module",
  "rundll32-untrusted-module",
  "unexpected-dll-load",
  "cross-process-memory-manipulation",
  "scheduled-task-persistence",
  "new-untrusted-service",
  "security-tool-impairment",
  "windows-event-log-impairment",
  "windows-event-log-clear",
  "firewall-policy-impairment",
  "trusted-binary-proxy-chain",
  "obfuscated-execution-chain",
  "masquerading-metadata-mismatch",
  "hidden-artifact-change",
  "post-execution-file-deletion",
  "process-injection-concealment"
] as const;

export const blueSignalIdSchema = z.enum(signalIds);
export type BlueSignalId = z.infer<typeof blueSignalIdSchema>;

const syntheticTelemetryEventSchema = z.object({
  eventId: z.string().regex(/^evt-[a-z0-9-]{1,60}$/),
  occurredAt: z.string().datetime({ offset: true }),
  assetId: z.string().regex(/^lab-[a-z0-9-]{2,60}$/),
  source: z.literal("synthetic"),
  telemetryClass: z.enum(["endpoint", "identity", "cloud", "certificate-authority"]),
  signal: blueSignalIdSchema,
  actorTrust: z.enum(["managed", "untrusted"]),
  normalizedBy: z.literal("war-room-blue-v1")
}).strict();

const syntheticTelemetrySchema = z.array(syntheticTelemetryEventSchema).min(1).max(64);
export type SyntheticTelemetryEvent = z.infer<typeof syntheticTelemetryEventSchema>;

export interface BlueRuleDescriptor {
  readonly id: string;
  readonly title: string;
  readonly category: "credential-access" | "payload-execution" | "defense-evasion";
  readonly severity: "medium" | "high";
  readonly attackTechniqueId: string;
  readonly attackTechniqueName: string;
  readonly referenceUrl: string;
  readonly signal: BlueSignalId;
  readonly requiredTelemetry: string[];
  readonly telemetryClasses: Array<"endpoint" | "identity" | "cloud" | "certificate-authority">;
  readonly detectionLogic: string;
  readonly likelyFalsePositives: string;
  readonly responseGuidance: string;
  readonly readiness: "synthetic-validated";
  readonly liveStatus: "connector-required";
}

export interface BlueAlert {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly category: BlueRuleDescriptor["category"];
  readonly severity: BlueRuleDescriptor["severity"];
  readonly confidence: "high";
  readonly attackTechniqueId: string;
  readonly attackTechniqueName: string;
  readonly matchedEventIds: string[];
  readonly reason: string;
  readonly responseGuidance: string;
  readonly disposition: "needs-review";
}

export interface BlueScenarioDescriptor {
  readonly id: BlueScenarioId;
  readonly name: string;
  readonly description: string;
  readonly synthetic: true;
  readonly expectedRuleIds: string[];
}

export interface BlueDetectionResult {
  readonly schemaVersion: 1;
  readonly ruleSetVersion: "blue-rules-v1";
  readonly scenario: BlueScenarioDescriptor;
  readonly generatedAt: string;
  readonly events: SyntheticTelemetryEvent[];
  readonly alerts: BlueAlert[];
  readonly summary: {
    readonly eventCount: number;
    readonly alertCount: number;
    readonly highestSeverity: "none" | "medium" | "high";
    readonly verdict: "no-rule-match" | "suspicious-behaviour-detected";
    readonly limitation: string;
  };
}

export interface BlueDetectionRun {
  readonly id: string;
  readonly missionId: string;
  readonly scenarioId: BlueScenarioId;
  readonly ruleSetVersion: string;
  readonly eventCount: number;
  readonly alertCount: number;
  readonly resultHash: string;
  readonly evidenceArtifactId: string;
  readonly operator: string;
  readonly createdAt: string;
  readonly integrityValid: boolean;
  readonly result: BlueDetectionResult;
}

export interface BlueValidationMatrixRow {
  readonly testCaseId: string;
  readonly ruleId: string;
  readonly title: string;
  readonly category: BlueRuleDescriptor["category"];
  readonly attackTechniqueId: string;
  readonly attackTechniqueName: string;
  readonly scenarioId: Exclude<BlueScenarioId, "combined-incident">;
  readonly requiredTelemetry: string[];
  readonly syntheticValidation: {
    readonly status: "not-run" | "detected" | "not-detected" | "integrity-failed";
    readonly latestRunId: string | null;
    readonly observedAlertId: string | null;
    readonly evidenceArtifactId: string | null;
    readonly validatedAt: string | null;
  };
  readonly liveValidation: {
    readonly status: "connector-required";
    readonly endpointEvidencePresent: false;
  };
}

type RuleInput = Omit<BlueRuleDescriptor, "referenceUrl" | "readiness" | "liveStatus">;

function rule(input: RuleInput): BlueRuleDescriptor {
  return {
    ...input,
    referenceUrl: `https://attack.mitre.org/techniques/${input.attackTechniqueId.replace(".", "/")}/`,
    readiness: "synthetic-validated",
    liveStatus: "connector-required"
  };
}

export const BLUE_RULES: readonly BlueRuleDescriptor[] = [
  rule({
    id: "BR-CRED-001",
    title: "Sensitive authentication memory access",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1003",
    attackTechniqueName: "OS Credential Dumping",
    signal: "sensitive-auth-memory-access",
    requiredTelemetry: ["Process access", "Process ancestry", "Signer and hash", "Protected-memory target"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Correlate an unexpected process opening sensitive authentication memory or credential-bearing registry data with elevated execution or follow-on activity.",
    likelyFalsePositives: "EDR, approved incident-response tools, debuggers, backup agents and crash collection.",
    responseGuidance: "Isolate the endpoint, preserve volatile evidence, validate the process signer and revoke only credentials shown to be exposed."
  }),
  rule({
    id: "BR-CRED-002",
    title: "Suspicious password-store access",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1555",
    attackTechniqueName: "Credentials from Password Stores",
    signal: "password-store-read",
    requiredTelemetry: ["Credential-store file access", "Process identity", "API access", "Cloud-vault audit"],
    telemetryClasses: ["endpoint", "cloud"],
    detectionLogic: "Detect non-owner or newly observed processes reading classified browser, operating-system, keyring or vault credential stores.",
    likelyFalsePositives: "Browsers, password managers, profile migration, backup, indexing, DLP and approved security tooling.",
    responseGuidance: "Contain the source process, identify affected stores, revoke sessions and rotate confirmed exposed credentials."
  }),
  rule({
    id: "BR-CRED-003",
    title: "Unsecured credential material accessed",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1552",
    attackTechniqueName: "Unsecured Credentials",
    signal: "unsecured-secret-access",
    requiredTelemetry: ["File and registry access", "Process creation", "Container or repository audit", "Cloud metadata access"],
    telemetryClasses: ["endpoint", "cloud"],
    detectionLogic: "Detect unusual access to classified shell history, configuration, private-key, container-secret or metadata locations by a rare process.",
    likelyFalsePositives: "Secret scanners, DLP, configuration management, developers, backup and certificate automation.",
    responseGuidance: "Identify the exact exposed material, rotate it, remove plaintext copies and hunt for downstream use."
  }),
  rule({
    id: "BR-CRED-004",
    title: "Unexpected input-capture registration",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1056",
    attackTechniqueName: "Input Capture",
    signal: "input-capture-registration",
    requiredTelemetry: ["Input API activity", "DLL or driver loads", "Privacy permissions", "Process ancestry"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect an unsigned or newly observed process registering input hooks, accessing input devices or changing input-related permissions.",
    likelyFalsePositives: "Accessibility tools, hotkey utilities, RMM, gaming overlays, input-method editors and EDR.",
    responseGuidance: "Isolate the host, preserve the activity timeline and reset credentials entered after the suspected collection began."
  }),
  rule({
    id: "BR-CRED-005",
    title: "Authentication failure burst and success",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1110",
    attackTechniqueName: "Brute Force",
    signal: "authentication-failure-burst",
    requiredTelemetry: ["Authentication failures and successes", "Account", "Source", "Device", "Conditional-access result"],
    telemetryClasses: ["identity"],
    detectionLogic: "Correlate failure bursts by account and source, password-spray shapes, or many failures followed by a success.",
    likelyFalsePositives: "Mistyped passwords, stale service credentials, rotations, SSO faults, scanners and authorized testing.",
    responseGuidance: "Confirm any following success, protect targeted accounts, revoke suspect sessions and investigate the successful device."
  }),
  rule({
    id: "BR-CRED-006",
    title: "Anomalous Kerberos ticket activity",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1558",
    attackTechniqueName: "Steal or Forge Kerberos Tickets",
    signal: "anomalous-ticket-use",
    requiredTelemetry: ["KDC ticket events", "Encryption type", "SPN", "Account and client", "Sensitive-process access"],
    telemetryClasses: ["identity", "endpoint"],
    detectionLogic: "Detect abnormal ticket encryption or fields, service-ticket requests without a normal preceding flow, or unusual service-account activity.",
    likelyFalsePositives: "Legacy encryption, high-volume service accounts, migrations and approved Kerberos diagnostics.",
    responseGuidance: "Contain the source account and endpoint, invalidate affected tickets and invoke domain recovery if key compromise is credible."
  }),
  rule({
    id: "BR-CRED-007",
    title: "Suspicious web-session store access",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1539",
    attackTechniqueName: "Steal Web Session Cookie",
    signal: "session-cookie-store-read",
    requiredTelemetry: ["Browser store access", "Process access", "Extension inventory", "Identity sign-ins and session use"],
    telemetryClasses: ["endpoint", "identity"],
    detectionLogic: "Correlate non-browser access to cookie stores or browser memory with session use from a new device, source or user agent.",
    likelyFalsePositives: "Browser sync and updates, backup, profile migration, DLP and browser-management tooling.",
    responseGuidance: "Revoke active sessions, force reauthentication, isolate the source endpoint and inspect extensions and SaaS activity."
  }),
  rule({
    id: "BR-CRED-008",
    title: "Application token accessed from a new context",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1528",
    attackTechniqueName: "Steal Application Access Token",
    signal: "application-token-access",
    requiredTelemetry: ["Token-store access", "Metadata-service flow", "Cloud and Kubernetes audit", "Application consent"],
    telemetryClasses: ["endpoint", "cloud", "identity"],
    detectionLogic: "Correlate token or metadata access with API use by a new process, workload identity, device or location.",
    likelyFalsePositives: "CI/CD agents, controllers, managed-identity refresh, approved OAuth apps and scheduled automation.",
    responseGuidance: "Revoke the grant or token, disable the suspect workload identity, rotate its credential and review accessed resources."
  }),
  rule({
    id: "BR-CRED-009",
    title: "Authentication component changed",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1556",
    attackTechniqueName: "Modify Authentication Process",
    signal: "authentication-component-change",
    requiredTelemetry: ["Authentication DLL and module changes", "Registry or PAM changes", "MFA and identity-policy audit"],
    telemetryClasses: ["endpoint", "identity"],
    detectionLogic: "Detect unexpected authentication package, plugin, PAM, MFA, conditional-access or trust configuration changes.",
    likelyFalsePositives: "OS patches, VPN or authentication-agent installs, EDR upgrades, MFA rollout and approved policy changes.",
    responseGuidance: "Compare with change control, isolate affected authentication hosts, revert unauthorized changes and revoke suspect access."
  }),
  rule({
    id: "BR-CRED-010",
    title: "Authentication certificate or key accessed",
    category: "credential-access",
    severity: "high",
    attackTechniqueId: "T1649",
    attackTechniqueName: "Steal or Forge Authentication Certificates",
    signal: "authentication-certificate-access",
    requiredTelemetry: ["Certificate-store and private-key access", "Enrollment events", "Template and CA changes", "Certificate use"],
    telemetryClasses: ["endpoint", "certificate-authority", "identity"],
    detectionLogic: "Detect unusual private-key access, export, enrollment identity or template combinations, CA changes or use from a new device.",
    likelyFalsePositives: "Auto-enrollment, PKI administration, MDM enrollment, certificate migration and approved TLS automation.",
    responseGuidance: "Revoke affected certificates, disable suspect enrollment paths and invoke the PKI compromise procedure if CA integrity is uncertain."
  }),
  rule({
    id: "BR-PAYLOAD-001",
    title: "Document-triggered executable chain",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1204.002",
    attackTechniqueName: "User Execution: Malicious File",
    signal: "document-child-execution",
    requiredTelemetry: ["File origin", "Process ancestry", "Hash and signer", "Child process", "Network connection"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Correlate a recently delivered file with a document reader or archiver spawning an unusual executable, interpreter or network-active child.",
    likelyFalsePositives: "Legitimate installers, support packages, internally distributed scripts and software deployment.",
    responseGuidance: "Preserve the originating file and process tree, isolate on strong correlation and identify other recipients."
  }),
  rule({
    id: "BR-PAYLOAD-002",
    title: "Suspicious PowerShell execution chain",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1059.001",
    attackTechniqueName: "Command and Scripting Interpreter: PowerShell",
    signal: "suspicious-powershell-chain",
    requiredTelemetry: ["Process ancestry", "Script-block or AMSI telemetry", "Module loads", "Child process", "Network connection"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect PowerShell launched by an unusual parent with suspicious script behavior and follow-on network, module or child-process activity.",
    likelyFalsePositives: "Software deployment, administration, configuration management and developer automation.",
    responseGuidance: "Preserve script telemetry, identify the parent and user, isolate on download or execution behavior and hunt matching script hashes."
  }),
  rule({
    id: "BR-PAYLOAD-003",
    title: "Mshta proxy-execution chain",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1218.005",
    attackTechniqueName: "System Binary Proxy Execution: Mshta",
    signal: "mshta-proxy-execution",
    requiredTelemetry: ["Process ancestry", "Script or HTA reference", "Network retrieval", "File and child-process activity"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect mshta invoked by an unusual parent or followed by remote retrieval, file creation or child execution.",
    likelyFalsePositives: "Legacy enterprise HTA applications and older administrative workflows.",
    responseGuidance: "Capture referenced content and process lineage, isolate remote-content execution and validate whether HTA use is required."
  }),
  rule({
    id: "BR-PAYLOAD-004",
    title: "Untrusted installer execution",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1218.007",
    attackTechniqueName: "System Binary Proxy Execution: Msiexec",
    signal: "msiexec-untrusted-package",
    requiredTelemetry: ["Installer origin and signature", "Process ancestry", "Network", "Child process", "Service creation"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect installer packages from unusual paths or destinations when followed by rare modules, child processes or services.",
    likelyFalsePositives: "Enterprise deployment, software updates and remote-management products.",
    responseGuidance: "Validate publisher and deployment ownership, retain the package and review resulting files, services and persistence."
  }),
  rule({
    id: "BR-PAYLOAD-005",
    title: "Untrusted Regsvr32 module chain",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1218.010",
    attackTechniqueName: "System Binary Proxy Execution: Regsvr32",
    signal: "regsvr32-untrusted-module",
    requiredTelemetry: ["Process ancestry", "Module path and signer", "Image load", "Network connection"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect anomalous Regsvr32 execution involving user-writable paths, untrusted modules, remote content or outbound traffic.",
    likelyFalsePositives: "Application installation, COM registration and repair workflows.",
    responseGuidance: "Preserve the registered object and parent, verify authorization and hunt the module hash across endpoints."
  }),
  rule({
    id: "BR-PAYLOAD-006",
    title: "Untrusted Rundll32 module chain",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1218.011",
    attackTechniqueName: "System Binary Proxy Execution: Rundll32",
    signal: "rundll32-untrusted-module",
    requiredTelemetry: ["Process ancestry", "Module loads", "DLL hash and signer", "File access", "Network connection"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect atypical Rundll32 module paths or unexpected DLL loads combined with script-like or network activity.",
    likelyFalsePositives: "Control Panel functions, device software, installers and legitimate shell extensions.",
    responseGuidance: "Retain the loaded DLL and lineage, compare with a known-good baseline and isolate untrusted network-connected cases."
  }),
  rule({
    id: "BR-PAYLOAD-007",
    title: "Unexpected DLL loaded from writable path",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1574.001",
    attackTechniqueName: "Hijack Execution Flow: DLL",
    signal: "unexpected-dll-load",
    requiredTelemetry: ["Image loads", "File creation", "Hash and signer", "Registry changes", "Known-good load paths"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect trusted processes loading unexpected DLLs from user-writable or non-standard directories after a related write or change.",
    likelyFalsePositives: "Developer builds, plugins, portable software and poorly packaged legacy applications.",
    responseGuidance: "Preserve the executable and DLL pair, compare signers and hashes and repair confirmed substitutions from trusted media."
  }),
  rule({
    id: "BR-PAYLOAD-008",
    title: "Cross-process memory manipulation",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1055",
    attackTechniqueName: "Process Injection",
    signal: "cross-process-memory-manipulation",
    requiredTelemetry: ["Process access", "Memory allocation and write", "Remote thread", "Module load", "Process ancestry"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Correlate cross-process memory access, allocation, writes or remote-thread-like activity with unusual source and target behavior.",
    likelyFalsePositives: "Debuggers, accessibility tools, security products, profilers, overlays and compatibility software.",
    responseGuidance: "Isolate on a high-confidence chain, preserve process memory where policy permits and investigate both source and target."
  }),
  rule({
    id: "BR-PAYLOAD-009",
    title: "Suspicious scheduled-task execution",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1053.005",
    attackTechniqueName: "Scheduled Task/Job: Scheduled Task",
    signal: "scheduled-task-persistence",
    requiredTelemetry: ["Task creation and definition", "Creator identity", "Process ancestry", "Registry and file changes", "Execution result"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect a new or changed task followed by execution, especially rare creators, privileged context or user-writable payload paths.",
    likelyFalsePositives: "Maintenance, software updates, backup products and administrative automation.",
    responseGuidance: "Preserve the task definition and creator, validate ownership and inspect prior runs before disabling it."
  }),
  rule({
    id: "BR-PAYLOAD-010",
    title: "Untrusted service installation or change",
    category: "payload-execution",
    severity: "high",
    attackTechniqueId: "T1543.003",
    attackTechniqueName: "Create or Modify System Process: Windows Service",
    signal: "new-untrusted-service",
    requiredTelemetry: ["Service-control events", "Service registry", "Process ancestry", "Binary signer and hash", "Driver load"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect new or modified services using rare names, unsigned binaries, user-writable paths or unexpected privileged execution.",
    likelyFalsePositives: "Application installs, endpoint management, drivers and software updates.",
    responseGuidance: "Preserve service configuration and binary, validate the installer and disable only after evidence capture."
  }),
  rule({
    id: "BR-EVASION-001",
    title: "Security tool impairment",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1685",
    attackTechniqueName: "Disable or Modify Tools",
    signal: "security-tool-impairment",
    requiredTelemetry: ["Security-agent health", "Service and process changes", "Policy and exclusions", "Driver load", "Heartbeat"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect security-agent process, service, policy, exclusion, driver or update changes and heartbeat loss following privileged activity.",
    likelyFalsePositives: "Product upgrades, maintenance, troubleshooting and security-agent replacement.",
    responseGuidance: "Check approved changes, preserve preceding telemetry, restore protection from known-good policy and isolate if unauthorized."
  }),
  rule({
    id: "BR-EVASION-002",
    title: "Windows event logging impaired",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1685.001",
    attackTechniqueName: "Disable or Modify Tools: Disable or Modify Windows Event Log",
    signal: "windows-event-log-impairment",
    requiredTelemetry: ["Event Log service state", "Audit policy", "Registry configuration", "Record continuity", "Forwarding heartbeat"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Correlate logging-service changes, audit-policy drift, Event Log registry changes and unexpected record gaps.",
    likelyFalsePositives: "GPO rollout, OS upgrades, logging troubleshooting and approved audit-policy redesign.",
    responseGuidance: "Preserve forwarded events, compare with policy, restore logging and investigate activity immediately before the gap."
  }),
  rule({
    id: "BR-EVASION-003",
    title: "Windows event log clear attempt",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1685.005",
    attackTechniqueName: "Disable or Modify Tools: Clear Windows Event Logs",
    signal: "windows-event-log-clear",
    requiredTelemetry: ["Log clear event", "Process ancestry", "Log-file deletion", "Remote copies", "Record identifiers"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect log clearing plus related privileged process activity, log-file deletion or record-sequence reset.",
    likelyFalsePositives: "Approved rotation, lab resets, image preparation and support cleanup.",
    responseGuidance: "Rely on remote copies, preserve volatile evidence and investigate the account and process tree preceding the clear."
  }),
  rule({
    id: "BR-EVASION-004",
    title: "System firewall impaired",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1686",
    attackTechniqueName: "Disable or Modify System Firewall",
    signal: "firewall-policy-impairment",
    requiredTelemetry: ["Firewall policy diff", "Service state", "Registry or config", "Process ancestry", "Listening socket and flow"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect unauthorized firewall additions, deletions, profile changes, service changes or sudden rule-count drops.",
    likelyFalsePositives: "VPN clients, security software, GPO, remote management and developer test rules.",
    responseGuidance: "Preserve the exact policy diff, compare with central policy, revert through the approved plane and inspect exposed traffic."
  }),
  rule({
    id: "BR-EVASION-005",
    title: "Process injection used for concealment",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1055",
    attackTechniqueName: "Process Injection",
    signal: "process-injection-concealment",
    requiredTelemetry: ["Process access", "Remote thread", "Process tampering", "Image loads", "Source and target baseline"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect anomalous cross-process memory manipulation or process-image tampering that shifts activity into another process.",
    likelyFalsePositives: "Debuggers, profilers, accessibility tools, endpoint security and compatibility software.",
    responseGuidance: "Isolate, preserve memory where practical, validate source and target signers and hunt the same pair fleet-wide."
  }),
  rule({
    id: "BR-EVASION-006",
    title: "Trusted binary proxy execution",
    category: "defense-evasion",
    severity: "high",
    attackTechniqueId: "T1218",
    attackTechniqueName: "System Binary Proxy Execution",
    signal: "trusted-binary-proxy-chain",
    requiredTelemetry: ["Process command context", "Parent", "Signer and path", "Network", "File creation", "Module load"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect trusted operating-system binaries with unusual parents and content origins followed by network, file or child activity.",
    likelyFalsePositives: "Installers, management automation, patch systems and vendor updaters.",
    responseGuidance: "Validate the business workflow and content origin, preserve lineage and quarantine suspicious fetched content."
  }),
  rule({
    id: "BR-EVASION-007",
    title: "Obfuscated execution chain",
    category: "defense-evasion",
    severity: "medium",
    attackTechniqueId: "T1027",
    attackTechniqueName: "Obfuscated Files or Information",
    signal: "obfuscated-execution-chain",
    requiredTelemetry: ["Script inspection", "Process ancestry", "File entropy and metadata", "Archive activity", "Network context"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Score encoded or high-entropy content only when correlated with suspicious parents, decode activity, temporary writes and execution.",
    likelyFalsePositives: "Software packages, backups, compressed logs, signed installers and legitimate administration.",
    responseGuidance: "Preserve the original artifact and chain, hash and inspect it safely, and quarantine only with sufficient context."
  }),
  rule({
    id: "BR-EVASION-008",
    title: "Executable masquerading mismatch",
    category: "defense-evasion",
    severity: "medium",
    attackTechniqueId: "T1036",
    attackTechniqueName: "Masquerading",
    signal: "masquerading-metadata-mismatch",
    requiredTelemetry: ["Filename and path", "Signer", "Binary metadata", "Hash", "Software inventory", "Service or task registration"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Compare name, path, signer, metadata and inventory to detect misleading extensions or legitimate-looking binaries in abnormal locations.",
    likelyFalsePositives: "Generic vendor names, portable applications, packaging mistakes and internally renamed tools.",
    responseGuidance: "Validate against inventory and publisher records, preserve the file and inspect any persistence references."
  }),
  rule({
    id: "BR-EVASION-009",
    title: "Hidden artifact or visibility change",
    category: "defense-evasion",
    severity: "medium",
    attackTechniqueId: "T1564",
    attackTechniqueName: "Hide Artifacts",
    signal: "hidden-artifact-change",
    requiredTelemetry: ["File and registry changes", "Attributes", "Alternate streams", "Task and service inventory"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect hidden or system attribute changes, alternate streams and visibility or inventory mismatches created by an unusual process.",
    likelyFalsePositives: "OS and application caches, normal dotfiles, browser metadata and backup tooling.",
    responseGuidance: "Preserve visible and hidden metadata, compare with inventory and inspect the creating process before removal."
  }),
  rule({
    id: "BR-EVASION-010",
    title: "Post-execution artifact deletion",
    category: "defense-evasion",
    severity: "medium",
    attackTechniqueId: "T1070.004",
    attackTechniqueName: "Indicator Removal: File Deletion",
    signal: "post-execution-file-deletion",
    requiredTelemetry: ["File deletion", "Prior creation or execution", "Hash and path", "Process ancestry", "Filesystem journal"],
    telemetryClasses: ["endpoint"],
    detectionLogic: "Detect deletion of recently created or executed artifacts, especially in temporary, log or security locations.",
    likelyFalsePositives: "Uninstallers, updates, scheduled cleanup, browser cleanup and antivirus quarantine.",
    responseGuidance: "Preserve recoverable copies and journal evidence, identify the deleting process and correlate preceding execution."
  })
] as const;

function categoryRuleIds(category: BlueRuleDescriptor["category"]): string[] {
  return BLUE_RULES.filter((item) => item.category === category).map((item) => item.id);
}

export const BLUE_SCENARIOS: readonly BlueScenarioDescriptor[] = [
  {
    id: "credential-access",
    name: "Credential-access coverage pack",
    description: "Validates ten synthetic normalized signals covering credential access without touching a real credential store.",
    synthetic: true,
    expectedRuleIds: categoryRuleIds("credential-access")
  },
  {
    id: "payload-execution",
    name: "Payload-execution coverage pack",
    description: "Validates ten synthetic normalized signals covering suspicious execution without creating or launching a payload.",
    synthetic: true,
    expectedRuleIds: categoryRuleIds("payload-execution")
  },
  {
    id: "defense-evasion",
    name: "Defense-evasion coverage pack",
    description: "Validates ten synthetic normalized signals covering impairment and concealment without changing a security control.",
    synthetic: true,
    expectedRuleIds: categoryRuleIds("defense-evasion")
  },
  {
    id: "combined-incident",
    name: "Combined 30-rule blue-team incident",
    description: "Exercises every synthetic coverage signal as one review, triage and evidence workflow.",
    synthetic: true,
    expectedRuleIds: BLUE_RULES.map((item) => item.id)
  }
] as const;

function telemetryClass(ruleDescriptor: BlueRuleDescriptor): SyntheticTelemetryEvent["telemetryClass"] {
  return ruleDescriptor.telemetryClasses[0] ?? "endpoint";
}

export function scenarioTelemetry(scenarioId: BlueScenarioId, now: Date): SyntheticTelemetryEvent[] {
  const scenario = BLUE_SCENARIOS.find((item) => item.id === scenarioId);
  if (!scenario) throw new Error("BLUE_SCENARIO_NOT_FOUND");
  return syntheticTelemetrySchema.parse(
    scenario.expectedRuleIds.map((ruleId, index) => {
      const ruleDescriptor = BLUE_RULES.find((item) => item.id === ruleId)!;
      return {
        eventId: `evt-${ruleId.toLowerCase()}`,
        occurredAt: new Date(now.getTime() + index * 1_000).toISOString(),
        assetId: `lab-${telemetryClass(ruleDescriptor)}-01`,
        source: "synthetic",
        telemetryClass: telemetryClass(ruleDescriptor),
        signal: ruleDescriptor.signal,
        actorTrust: "untrusted",
        normalizedBy: "war-room-blue-v1"
      };
    })
  );
}

function makeAlert(ruleDescriptor: BlueRuleDescriptor, eventId: string): BlueAlert {
  return {
    id: `alert-${ruleDescriptor.id.toLowerCase()}-${eventId}`,
    ruleId: ruleDescriptor.id,
    title: ruleDescriptor.title,
    category: ruleDescriptor.category,
    severity: ruleDescriptor.severity,
    confidence: "high",
    attackTechniqueId: ruleDescriptor.attackTechniqueId,
    attackTechniqueName: ruleDescriptor.attackTechniqueName,
    matchedEventIds: [eventId],
    reason: `Synthetic normalized signal '${ruleDescriptor.signal}' matched the versioned defensive rule.`,
    responseGuidance: ruleDescriptor.responseGuidance,
    disposition: "needs-review"
  };
}

export function analyseSyntheticTelemetry(input: readonly SyntheticTelemetryEvent[]): BlueAlert[] {
  const events = syntheticTelemetrySchema.parse(input);
  const alerts: BlueAlert[] = [];
  const matchedRuleIds = new Set<string>();
  for (const event of events) {
    if (event.actorTrust !== "untrusted") continue;
    for (const ruleDescriptor of BLUE_RULES.filter((item) => item.signal === event.signal)) {
      if (matchedRuleIds.has(ruleDescriptor.id)) continue;
      matchedRuleIds.add(ruleDescriptor.id);
      alerts.push(makeAlert(ruleDescriptor, event.eventId));
    }
  }
  return alerts;
}

function buildResult(scenarioId: BlueScenarioId, now: Date): BlueDetectionResult {
  const scenario = BLUE_SCENARIOS.find((item) => item.id === scenarioId)!;
  const events = scenarioTelemetry(scenarioId, now);
  const alerts = analyseSyntheticTelemetry(events);
  return {
    schemaVersion: 1,
    ruleSetVersion: "blue-rules-v1",
    scenario,
    generatedAt: now.toISOString(),
    events,
    alerts,
    summary: {
      eventCount: events.length,
      alertCount: alerts.length,
      highestSeverity: alerts.some((item) => item.severity === "high")
        ? "high"
        : alerts.some((item) => item.severity === "medium")
          ? "medium"
          : "none",
      verdict: alerts.length ? "suspicious-behaviour-detected" : "no-rule-match",
      limitation:
        "Synthetic signal matches validate the WAR-R00M pipeline, not live raw-event collection or proof that an endpoint was compromised."
    }
  };
}

interface DetectionRunRow {
  id: string;
  mission_id: string;
  scenario_id: string;
  rule_set_version: string;
  event_count: number;
  alert_count: number;
  result_json: string;
  result_hash: string;
  evidence_artifact_id: string;
  operator: string;
  created_at: string;
}

export class BlueDetectionService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService
  ) {}

  catalogue(missionId?: string): {
    rules: readonly BlueRuleDescriptor[];
    scenarios: readonly BlueScenarioDescriptor[];
    validationMatrix: BlueValidationMatrixRow[];
    coverage: {
      syntheticValidatedRuleIds: string[];
      liveSupportedRuleIds: string[];
      liveStatus: "connector-required";
    };
  } {
    return {
      rules: BLUE_RULES,
      scenarios: BLUE_SCENARIOS,
      validationMatrix: this.validationMatrix(missionId),
      coverage: {
        syntheticValidatedRuleIds: BLUE_RULES.map((item) => item.id),
        liveSupportedRuleIds: [],
        liveStatus: "connector-required"
      }
    };
  }

  validationMatrix(missionId?: string): BlueValidationMatrixRow[] {
    const runs = missionId ? this.list(missionId) : [];
    return BLUE_RULES.map((ruleDescriptor) => {
      const latestRun = runs.find(
        (run) => run.scenarioId === ruleDescriptor.category || run.scenarioId === "combined-incident"
      );
      const alert = latestRun?.result.alerts.find((item) => item.ruleId === ruleDescriptor.id);
      const status = !latestRun
        ? "not-run"
        : !latestRun.integrityValid
          ? "integrity-failed"
          : alert
            ? "detected"
            : "not-detected";
      return {
        testCaseId: `blue-safe-${ruleDescriptor.id.toLowerCase()}`,
        ruleId: ruleDescriptor.id,
        title: ruleDescriptor.title,
        category: ruleDescriptor.category,
        attackTechniqueId: ruleDescriptor.attackTechniqueId,
        attackTechniqueName: ruleDescriptor.attackTechniqueName,
        scenarioId: ruleDescriptor.category,
        requiredTelemetry: [...ruleDescriptor.requiredTelemetry],
        syntheticValidation: {
          status,
          latestRunId: latestRun?.id ?? null,
          observedAlertId: alert?.id ?? null,
          evidenceArtifactId: latestRun?.evidenceArtifactId ?? null,
          validatedAt: latestRun?.createdAt ?? null
        },
        liveValidation: {
          status: "connector-required",
          endpointEvidencePresent: false
        }
      };
    });
  }

  runSimulation(missionId: string, scenarioInput: BlueScenarioId, operator: string, now = new Date()): BlueDetectionRun {
    const scenarioId = blueScenarioIdSchema.parse(scenarioInput);
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
    const normalizedOperator = operator.trim();
    if (normalizedOperator.length < 2 || normalizedOperator.length > 120) throw new Error("OPERATOR_INVALID");
    const result = buildResult(scenarioId, now);
    const resultJson = stableJson(result);
    if (Buffer.byteLength(resultJson, "utf8") > 262_144) throw new Error("BLUE_RESULT_TOO_LARGE");
    const resultHash = canonicalHash(result);
    const artifact = this.evidence.seal(resultJson, "application/json", {
      missionId,
      capturedAt: now,
      provenance: {
        sourceType: "blue-team-synthetic-simulation",
        scenarioId,
        ruleSetVersion: result.ruleSetVersion,
        synthetic: true
      }
    });
    const runId = randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO blue_detection_runs(
             id, mission_id, scenario_id, schema_version, rule_set_version,
             event_count, alert_count, result_json, result_hash,
             evidence_artifact_id, operator, created_at
           ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          runId,
          missionId,
          scenarioId,
          result.ruleSetVersion,
          result.events.length,
          result.alerts.length,
          resultJson,
          resultHash,
          artifact.id,
          normalizedOperator,
          now.toISOString()
        );
      this.audit.append(
        "blue_detection.completed",
        {
          runId,
          missionId,
          scenarioId,
          ruleSetVersion: result.ruleSetVersion,
          eventCount: result.events.length,
          alertCount: result.alerts.length,
          evidenceArtifactId: artifact.id,
          resultHash,
          operator: normalizedOperator
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(runId);
  }

  list(missionId?: string): BlueDetectionRun[] {
    const rows = missionId
      ? this.database
          .prepare(
            "SELECT * FROM blue_detection_runs WHERE mission_id = ? ORDER BY created_at DESC, id DESC LIMIT 200"
          )
          .all(missionId)
      : this.database
          .prepare("SELECT * FROM blue_detection_runs ORDER BY created_at DESC, id DESC LIMIT 200")
          .all();
    return (rows as unknown as DetectionRunRow[]).map((row) => this.toRun(row));
  }

  get(id: string): BlueDetectionRun {
    const row = this.database.prepare("SELECT * FROM blue_detection_runs WHERE id = ?").get(id) as
      | DetectionRunRow
      | undefined;
    if (!row) throw new Error("BLUE_DETECTION_RUN_NOT_FOUND");
    return this.toRun(row);
  }

  private toRun(row: DetectionRunRow): BlueDetectionRun {
    let result: BlueDetectionResult;
    let integrityValid = false;
    try {
      result = JSON.parse(row.result_json) as BlueDetectionResult;
      const storedEvidence = this.evidence.read(row.evidence_artifact_id).toString("utf8");
      integrityValid =
        canonicalHash(result) === row.result_hash &&
        this.evidence.verify(row.evidence_artifact_id) &&
        storedEvidence === row.result_json;
    } catch {
      result = buildResult(blueScenarioIdSchema.parse(row.scenario_id), new Date(row.created_at));
    }
    return {
      id: row.id,
      missionId: row.mission_id,
      scenarioId: blueScenarioIdSchema.parse(row.scenario_id),
      ruleSetVersion: row.rule_set_version,
      eventCount: row.event_count,
      alertCount: row.alert_count,
      resultHash: row.result_hash,
      evidenceArtifactId: row.evidence_artifact_id,
      operator: row.operator,
      createdAt: row.created_at,
      integrityValid,
      result
    };
  }
}
