export type CapabilityStatus = "enabled" | "unavailable" | "planned";
export type ProductEdition = "starter" | "professional";

export interface CapabilityDescriptor {
  readonly id: string;
  readonly minimumEdition: ProductEdition;
  readonly name: string;
  readonly category: "advisory" | "diagnostic" | "network" | "web" | "tls" | "simulation";
  readonly description: string;
  readonly status: CapabilityStatus;
  readonly unavailableReason: string | null;
  readonly riskTier: "T0" | "T1" | "T2";
  readonly operatorDifficulty: "beginner" | "intermediate" | "advanced";
  readonly networkNoise: "none" | "low" | "medium" | "high";
  readonly approvalPolicy: "none" | "fresh-single-use";
  readonly targetRequired: boolean;
  readonly destructive: false;
  readonly maxRuntimeMs: number;
  readonly maxOutputBytes: number;
  readonly portLimit: number | null;
  readonly fixedTechnique: string;
  readonly evidenceOutput: string;
  readonly safetyNote: string;
  readonly prepareRoute: string | null;
}

interface CatalogueState {
  readonly targetExecutionEnabled: boolean;
  readonly versionProofEnabled: boolean;
  readonly emergencyStopState: string;
  readonly edition: ProductEdition;
}

const targetStatus = (state: CatalogueState): Pick<CapabilityDescriptor, "status" | "unavailableReason"> =>
  !state.targetExecutionEnabled
    ? { status: "unavailable", unavailableReason: "Exact-target adapter is not configured." }
    : state.emergencyStopState !== "ready"
      ? { status: "unavailable", unavailableReason: "Emergency stop is active." }
      : { status: "enabled", unavailableReason: null };

export function buildCapabilityCatalogue(state: CatalogueState): CapabilityDescriptor[] {
  const target = targetStatus(state);
  const targetBase = {
    ...target,
    approvalPolicy: "fresh-single-use" as const,
    targetRequired: true,
    destructive: false as const,
    maxOutputBytes: 262_144,
    evidenceOutput: "Content-addressed JSON with exact parameters, stdout, stderr and provenance.",
    safetyNote: "Exact stored target only. Live isolation is reverified before proposal and execution."
  };
  const catalogue: CapabilityDescriptor[] = [
    {
      id: "planning.note",
      minimumEdition: "starter",
      name: "Local advisory plan",
      category: "advisory",
      description: "Create a bounded local-AI plan with no tool, command, MCP or approval authority.",
      status: "enabled",
      unavailableReason: null,
      riskTier: "T0",
      operatorDifficulty: "beginner",
      networkNoise: "none",
      approvalPolicy: "none",
      targetRequired: false,
      destructive: false,
      maxRuntimeMs: 30_000,
      maxOutputBytes: 256_000,
      portLimit: null,
      fixedTechnique: "Structured local-model inference",
      evidenceOutput: "Stored model identity, hashes, latency, token usage and structured advisory output.",
      safetyNote: "The model cannot approve, execute or see raw target addresses.",
      prepareRoute: null
    },
    {
      id: "mcpwn.version.v1",
      minimumEdition: "starter",
      name: "MCPwn network-free proof",
      category: "diagnostic",
      description: "Verify the pinned MCPwn bridge and Nmap version without accepting or contacting a target.",
      status: state.versionProofEnabled ? "enabled" : "unavailable",
      unavailableReason: state.versionProofEnabled ? null : "Pinned MCPwn broker is unavailable.",
      riskTier: "T0",
      operatorDifficulty: "beginner",
      networkNoise: "none",
      approvalPolicy: "none",
      targetRequired: false,
      destructive: false,
      maxRuntimeMs: 15_000,
      maxOutputBytes: 65_536,
      portLimit: null,
      fixedTechnique: "Fixed nmap_version MCP call",
      evidenceOutput: "Content-addressed normalized JSON and lifecycle audit.",
      safetyNote: "No destination, command, tool name or argument is accepted.",
      prepareRoute: null
    },
    {
      id: "network.discovery",
      minimumEdition: "starter",
      name: "Host reachability",
      category: "network",
      description: "Reserved typed contract for exact-host reachability; not wired to the target adapter.",
      status: "planned",
      unavailableReason: "No reviewed host-discovery adapter is registered.",
      riskTier: "T1",
      operatorDifficulty: "beginner",
      networkNoise: "low",
      approvalPolicy: "fresh-single-use",
      targetRequired: true,
      destructive: false,
      maxRuntimeMs: 0,
      maxOutputBytes: 0,
      portLimit: null,
      fixedTechnique: "Planned exact-host reachability profile",
      evidenceOutput: "Planned content-addressed reachability observation.",
      safetyNote: "The existing executor contract is not advertised as runnable until an adapter and tests exist.",
      prepareRoute: null
    },
    {
      ...targetBase,
      id: "network.tcp-port-state",
      minimumEdition: "starter",
      name: "Low-noise TCP state",
      category: "network",
      description: "Check open or closed state and reason for a short explicit port list.",
      riskTier: "T1",
      operatorDifficulty: "beginner",
      networkNoise: "low",
      maxRuntimeMs: 20_000,
      portLimit: 16,
      fixedTechnique: "TCP connect, 250 ms scan delay, zero retries, maximum 20 probes/second",
      prepareRoute: "/api/target/tcp-port-state/approvals"
    },
    {
      ...targetBase,
      id: "network.service-version",
      minimumEdition: "starter",
      name: "Targeted service fingerprint",
      category: "network",
      description: "Identify a service on no more than 32 explicit TCP ports with bounded version intensity.",
      riskTier: "T1",
      operatorDifficulty: "intermediate",
      networkNoise: "medium",
      maxRuntimeMs: 15_000,
      portLimit: 32,
      fixedTechnique: "TCP connect service detection, version intensity 0-2",
      prepareRoute: "/api/target/service-version/approvals"
    },
    {
      ...targetBase,
      id: "web.http-metadata",
      minimumEdition: "professional",
      name: "HTTP metadata",
      category: "web",
      description: "Collect response titles and headers from no more than four explicit TCP ports.",
      riskTier: "T1",
      operatorDifficulty: "intermediate",
      networkNoise: "medium",
      maxRuntimeMs: 30_000,
      portLimit: 4,
      fixedTechnique: "Hard-coded http-title and http-headers NSE allowlist",
      prepareRoute: "/api/target/http-metadata/approvals"
    },
    {
      ...targetBase,
      id: "tls.certificate-metadata",
      minimumEdition: "professional",
      name: "TLS certificate metadata",
      category: "tls",
      description: "Collect certificate subjects, issuers, validity and fingerprints from up to four ports.",
      riskTier: "T1",
      operatorDifficulty: "intermediate",
      networkNoise: "medium",
      maxRuntimeMs: 30_000,
      portLimit: 4,
      fixedTechnique: "Hard-coded ssl-cert NSE script",
      prepareRoute: "/api/target/tls-certificate/approvals"
    },
    {
      ...targetBase,
      id: "tls.cipher-enumeration",
      minimumEdition: "professional",
      name: "TLS cipher posture",
      category: "tls",
      description: "Enumerate accepted TLS cipher suites on no more than two explicit ports.",
      riskTier: "T2",
      operatorDifficulty: "advanced",
      networkNoise: "high",
      maxRuntimeMs: 60_000,
      portLimit: 2,
      fixedTechnique: "Hard-coded ssl-enum-ciphers NSE script",
      prepareRoute: "/api/target/tls-ciphers/approvals"
    },
    {
      ...targetBase,
      id: "network.tcp-port-discovery",
      minimumEdition: "professional",
      name: "All-TCP discovery",
      category: "network",
      description: "Discover open TCP ports across one exact host using the fixed intensive profile.",
      riskTier: "T1",
      operatorDifficulty: "advanced",
      networkNoise: "high",
      maxRuntimeMs: 120_000,
      portLimit: 65_535,
      fixedTechnique: "TCP connect ports 1-65535, maximum 1,000 probes/second, zero retries",
      prepareRoute: "/api/target/all-tcp-ports/approvals"
    },
    {
      id: "simulation.evasion-detection",
      minimumEdition: "starter",
      name: "Defense-evasion detection lab",
      category: "simulation",
      description: "Validate ten defense-evasion coverage rules using inert normalized telemetry fixtures.",
      status: "enabled",
      unavailableReason: null,
      riskTier: "T0",
      operatorDifficulty: "intermediate",
      networkNoise: "none",
      approvalPolicy: "none",
      targetRequired: false,
      destructive: false,
      maxRuntimeMs: 2_000,
      maxOutputBytes: 262_144,
      portLimit: null,
      fixedTechnique: "Closed blue-rules-v1 matcher over server-generated synthetic telemetry",
      evidenceOutput: "Mission-bound synthetic events, rule matches, ATT&CK mappings, limitations and result hash.",
      safetyNote: "No bypass, obfuscation or endpoint change is performed.",
      prepareRoute: null
    },
    {
      id: "simulation.credential-canary",
      minimumEdition: "starter",
      name: "Credential-access detection lab",
      category: "simulation",
      description: "Validate ten credential-access coverage rules without accessing a real credential store.",
      status: "enabled",
      unavailableReason: null,
      riskTier: "T0",
      operatorDifficulty: "beginner",
      networkNoise: "none",
      approvalPolicy: "none",
      targetRequired: false,
      destructive: false,
      maxRuntimeMs: 2_000,
      maxOutputBytes: 262_144,
      portLimit: null,
      fixedTechnique: "Closed blue-rules-v1 matcher over server-generated synthetic telemetry",
      evidenceOutput: "Mission-bound synthetic events, rule matches, ATT&CK mappings, limitations and result hash.",
      safetyNote: "No passwords, browser stores, tokens or real secrets are read.",
      prepareRoute: null
    },
    {
      id: "simulation.inert-payload-triage",
      minimumEdition: "starter",
      name: "Payload-execution detection lab",
      category: "simulation",
      description: "Validate ten payload-execution coverage rules without creating, delivering or launching a payload.",
      status: "enabled",
      unavailableReason: null,
      riskTier: "T0",
      operatorDifficulty: "intermediate",
      networkNoise: "none",
      approvalPolicy: "none",
      targetRequired: false,
      destructive: false,
      maxRuntimeMs: 2_000,
      maxOutputBytes: 262_144,
      portLimit: null,
      fixedTechnique: "Closed blue-rules-v1 matcher over server-generated synthetic telemetry",
      evidenceOutput: "Mission-bound synthetic events, rule matches, ATT&CK mappings, limitations and result hash.",
      safetyNote: "No executable payload is created or launched.",
      prepareRoute: null
    }
  ];
  return catalogue.map((capability) =>
    state.edition === "starter" &&
    capability.minimumEdition === "professional" &&
    capability.status === "enabled"
      ? {
          ...capability,
          status: "unavailable",
          unavailableReason: "Requires the Professional edition."
        }
      : capability
  );
}
