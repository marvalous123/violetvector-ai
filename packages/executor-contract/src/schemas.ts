import { z } from "zod";

const idSchema = z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/);
const isoDateSchema = z.string().datetime({ offset: true });
export const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
export const EXECUTOR_CONTRACT_VERSION = "executor-contract.v2" as const;
export const MAX_OUTPUT_CHUNK_BYTES = 16_384;

export const capabilityIdSchema = z.enum([
  "mcpwn.nmap.host-discovery.v1",
  "mcpwn.nmap.service-version.v1",
  "mcpwn.nmap.tcp-port-discovery.v1",
  "mcpwn.nmap.tcp-port-state.v1",
  "mcpwn.nmap.http-metadata.v1",
  "mcpwn.nmap.tls-certificate.v1",
  "mcpwn.nmap.tls-ciphers.v1"
]);
export type CapabilityId = z.infer<typeof capabilityIdSchema>;

export const capabilityCatalogue = Object.freeze({
  "mcpwn.nmap.host-discovery.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Discover whether one exact, backend-resolved host is reachable"
  }),
  "mcpwn.nmap.service-version.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Identify services on an explicit bounded port list for one exact host"
  }),
  "mcpwn.nmap.tcp-port-discovery.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Discover open TCP ports across one exact host with a fixed rate limit"
  }),
  "mcpwn.nmap.tcp-port-state.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Check state and reason for no more than 16 explicit TCP ports at a low fixed rate"
  }),
  "mcpwn.nmap.http-metadata.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Collect bounded HTTP title and response-header metadata from no more than four explicit ports"
  }),
  "mcpwn.nmap.tls-certificate.v1": Object.freeze({
    riskTier: "T1", targetRequired: true,
    description: "Collect TLS certificate metadata from no more than four explicit ports"
  }),
  "mcpwn.nmap.tls-ciphers.v1": Object.freeze({
    riskTier: "T2", targetRequired: true,
    description: "Enumerate TLS cipher posture on no more than two explicit ports"
  })
} satisfies Record<CapabilityId, Readonly<{
  riskTier: "T1" | "T2"; targetRequired: true; description: string;
}>>);

const commonProposalSchema = z.object({
  contractVersion: z.literal(EXECUTOR_CONTRACT_VERSION),
  proposalId: idSchema,
  missionId: idSchema,
  targetId: idSchema,
  policyVersion: z.string().min(1).max(64),
  requestedBy: idSchema,
  requestedAt: isoDateSchema
});

const hostDiscoveryProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.host-discovery.v1"),
  parameters: z.object({
    probe: z.enum(["arp", "icmp-echo", "tcp-syn"]),
    tcpPort: z.number().int().min(1).max(65_535).optional()
  }).strict().superRefine((value, context) => {
    if (value.probe === "tcp-syn" && value.tcpPort === undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "tcpPort is required for tcp-syn" });
    }
    if (value.probe !== "tcp-syn" && value.tcpPort !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "tcpPort is valid only for tcp-syn" });
    }
  })
}).strict();

const serviceVersionProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.service-version.v1"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(32)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    intensity: z.number().int().min(0).max(2)
  }).strict()
}).strict();

const tcpPortDiscoveryProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.tcp-port-discovery.v1"),
  parameters: z.object({
    profile: z.literal("all-tcp"),
    maxRate: z.literal(1_000)
  }).strict()
}).strict();

const tcpPortStateProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.tcp-port-state.v1"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(16)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("low-noise")
  }).strict()
}).strict();

const httpMetadataProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.http-metadata.v1"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(4)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("headers-title")
  }).strict()
}).strict();

const tlsCertificateProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.tls-certificate.v1"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(4)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("certificate")
  }).strict()
}).strict();

const tlsCiphersProposalSchema = commonProposalSchema.extend({
  capabilityId: z.literal("mcpwn.nmap.tls-ciphers.v1"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(2)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("cipher-posture")
  }).strict()
}).strict();

export const canonicalProposalBindingSchema = z.discriminatedUnion("capabilityId", [
  hostDiscoveryProposalSchema,
  serviceVersionProposalSchema,
  tcpPortDiscoveryProposalSchema,
  tcpPortStateProposalSchema,
  httpMetadataProposalSchema,
  tlsCertificateProposalSchema,
  tlsCiphersProposalSchema
]);

export const canonicalApprovalBindingSchema = z.object({
  contractVersion: z.literal(EXECUTOR_CONTRACT_VERSION),
  approvalId: idSchema,
  proposalDigest: sha256Schema,
  executionBindingDigest: sha256Schema,
  missionId: idSchema,
  targetId: idSchema,
  capabilityId: capabilityIdSchema,
  approvedBy: idSchema,
  approvedAt: isoDateSchema,
  expiresAt: isoDateSchema,
  maxUses: z.literal(1)
}).strict().refine(
  (value) => Date.parse(value.expiresAt) > Date.parse(value.approvedAt),
  { message: "approval must expire after it is created", path: ["expiresAt"] }
);

export const resolvedTargetSchema = z.object({
  targetId: idSchema,
  canonicalAddress: z.string().ip(),
  addressFamily: z.enum(["ipv4", "ipv6"]),
  resolutionSource: z.literal("scope-registry"),
  scopeRevision: z.string().min(1).max(128),
  resolvedAt: isoDateSchema
}).strict().superRefine((target, context) => {
  const expected = target.canonicalAddress.includes(":") ? "ipv6" : "ipv4";
  if (target.addressFamily !== expected) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "addressFamily does not match canonicalAddress" });
  }
});

export const executionLimitsSchema = z.object({
  timeoutMs: z.number().int().min(100).max(120_000),
  maxOutputBytes: z.number().int().min(1).max(1_000_000),
  maxEvidenceBytes: z.number().int().min(1).max(5_000_000)
}).strict();

export const executionBindingSchema = z.object({
  target: resolvedTargetSchema,
  limits: executionLimitsSchema
}).strict();

export const brokerExecutionRequestSchema = z.object({
  executionId: idSchema,
  proposal: canonicalProposalBindingSchema,
  proposalDigest: sha256Schema,
  approval: canonicalApprovalBindingSchema,
  approvalDigest: sha256Schema,
  target: resolvedTargetSchema,
  limits: executionLimitsSchema,
  submittedAt: isoDateSchema
}).strict();

export const outputChunkSchema = z.object({
  sequence: z.number().int().nonnegative(),
  stream: z.enum(["stdout", "stderr"]),
  encoding: z.literal("utf8"),
  content: z.string().max(MAX_OUTPUT_CHUNK_BYTES),
  contentBytes: z.number().int().nonnegative().max(MAX_OUTPUT_CHUNK_BYTES),
  cumulativeOutputBytes: z.number().int().nonnegative().max(1_000_000),
  truncated: z.boolean()
}).strict().superRefine((chunk, context) => {
  if (Buffer.byteLength(chunk.content, "utf8") !== chunk.contentBytes) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "contentBytes does not match UTF-8 content" });
  }
  if (chunk.cumulativeOutputBytes < chunk.contentBytes) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "cumulativeOutputBytes is too small" });
  }
});

export const evidenceMetadataSchema = z.object({
  evidenceId: idSchema,
  executionId: idSchema,
  sha256: sha256Schema,
  byteLength: z.number().int().nonnegative().max(5_000_000),
  mediaType: z.enum(["application/json", "text/plain"]),
  storageKey: z.string().min(1).max(256).regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/),
  createdAt: isoDateSchema
}).strict();

const lifecycleBaseSchema = z.object({ executionId: idSchema, occurredAt: isoDateSchema });
export const lifecycleEventSchema = z.discriminatedUnion("type", [
  lifecycleBaseSchema.extend({ type: z.literal("accepted") }).strict(),
  lifecycleBaseSchema.extend({ type: z.literal("started"), adapterInstanceId: idSchema }).strict(),
  lifecycleBaseSchema.extend({ type: z.literal("output"), chunk: outputChunkSchema }).strict(),
  lifecycleBaseSchema.extend({ type: z.literal("evidence_stored"), evidence: evidenceMetadataSchema }).strict(),
  lifecycleBaseSchema.extend({
    type: z.literal("completed"), durationMs: z.number().int().nonnegative(),
    outputBytes: z.number().int().nonnegative(), evidenceIds: z.array(idSchema).max(16)
  }).strict(),
  lifecycleBaseSchema.extend({
    type: z.literal("timed_out"), durationMs: z.number().int().nonnegative(),
    outputBytes: z.number().int().nonnegative()
  }).strict(),
  lifecycleBaseSchema.extend({
    type: z.literal("cancelled"),
    reason: z.enum(["operator", "emergency-stop", "budget-exhausted"]),
    outputBytes: z.number().int().nonnegative()
  }).strict(),
  lifecycleBaseSchema.extend({
    type: z.literal("failed"),
    failureCode: z.enum(["ADAPTER_UNAVAILABLE", "INVALID_ADAPTER_RESPONSE", "INTERNAL_ERROR"]),
    safeMessage: z.string().min(1).max(512)
  }).strict()
]);

export const cancellationResultSchema = z.object({
  executionId: idSchema,
  status: z.enum(["cancel-requested", "already-terminal", "not-found"]),
  requestedAt: isoDateSchema
}).strict();

export const emergencyStopResultSchema = z.object({
  stopId: idSchema, requestedAt: isoDateSchema, requestedBy: idSchema,
  matchedExecutionIds: z.array(idSchema).max(1_000),
  cancellationRequestedCount: z.number().int().nonnegative(),
  status: z.enum(["accepted", "nothing-active"])
}).strict();

export const adapterHealthSchema = z.object({
  adapterId: z.literal("mcpwn-adapter"),
  instanceId: idSchema,
  status: z.enum(["ready", "degraded", "offline"]),
  contractVersion: z.literal(EXECUTOR_CONTRACT_VERSION),
  schemaHash: sha256Schema,
  capabilities: z.array(capabilityIdSchema).length(Object.keys(capabilityCatalogue).length)
    .refine((items) => new Set(items).size === items.length, "capabilities must be unique"),
  checkedAt: isoDateSchema,
  executionEnabled: z.boolean()
}).strict();

export type CanonicalProposalBinding = z.infer<typeof canonicalProposalBindingSchema>;
export type CanonicalApprovalBinding = z.infer<typeof canonicalApprovalBindingSchema>;
export type ResolvedTarget = z.infer<typeof resolvedTargetSchema>;
export type ExecutionLimits = z.infer<typeof executionLimitsSchema>;
export type ExecutionBinding = z.infer<typeof executionBindingSchema>;
export type BrokerExecutionRequest = z.infer<typeof brokerExecutionRequestSchema>;
export type OutputChunk = z.infer<typeof outputChunkSchema>;
export type EvidenceMetadata = z.infer<typeof evidenceMetadataSchema>;
export type LifecycleEvent = z.infer<typeof lifecycleEventSchema>;
export type CancellationResult = z.infer<typeof cancellationResultSchema>;
export type EmergencyStopResult = z.infer<typeof emergencyStopResultSchema>;
export type AdapterHealth = z.infer<typeof adapterHealthSchema>;
