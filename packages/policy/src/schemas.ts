import { createHash } from "node:crypto";
import { z } from "zod";

export const riskTierSchema = z.enum(["T0", "T1", "T2", "T3"]);

export const targetRecordSchema = z
  .object({
    id: z.string().min(1).max(128),
    address: z.string().min(1).max(128),
    isolatedPrivateTargetApproved: z.boolean().default(false)
  })
  .strict();

export const scopeSchema = z
  .object({
    scopeVersionId: z.string().min(1).max(128),
    missionId: z.string().min(1).max(128),
    startsAt: z.string().datetime({ offset: true }),
    expiresAt: z.string().datetime({ offset: true }),
    targets: z.array(targetRecordSchema).min(1).max(16)
      .refine(
        (targets) => new Set(targets.map((target) => target.id)).size === targets.length,
        "target IDs must be unique"
      ),
    policyVersion: z.string().min(1).max(64)
  })
  .strict();

const proposalBaseSchema = z.object({
  proposalId: z.string().min(1).max(128),
  missionId: z.string().min(1).max(128),
  runId: z.string().min(1).max(128),
  targetId: z.string().min(1).max(128),
  riskTier: riskTierSchema,
  timeoutMs: z.number().int().positive().max(120_000),
  maxOutputBytes: z.number().int().positive().max(1_000_000)
});

const planningNoteProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("planning.note"),
  parameters: z.object({ note: z.string().min(1).max(2_000) }).strict()
}).strict();

const networkDiscoveryProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("network.discovery"),
  parameters: z.object({ profile: z.literal("version-only") }).strict()
}).strict();

const networkServiceVersionProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("network.service-version"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(32)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    intensity: z.number().int().min(0).max(2)
  }).strict()
}).strict();

const networkTcpPortDiscoveryProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("network.tcp-port-discovery"),
  parameters: z.object({
    profile: z.literal("all-tcp"),
    maxRate: z.literal(1_000)
  }).strict()
}).strict();

const networkTcpPortStateProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("network.tcp-port-state"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(16)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("low-noise")
  }).strict()
}).strict();

const webHttpMetadataProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("web.http-metadata"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(4)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("headers-title")
  }).strict()
}).strict();

const tlsCertificateMetadataProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("tls.certificate-metadata"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(4)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("certificate")
  }).strict()
}).strict();

const tlsCipherEnumerationProposalSchema = proposalBaseSchema.extend({
  capabilityId: z.literal("tls.cipher-enumeration"),
  parameters: z.object({
    ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(2)
      .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
    transport: z.literal("tcp"),
    profile: z.literal("cipher-posture")
  }).strict()
}).strict();

export const actionProposalSchema = z.discriminatedUnion("capabilityId", [
  planningNoteProposalSchema,
  networkDiscoveryProposalSchema,
  networkServiceVersionProposalSchema,
  networkTcpPortDiscoveryProposalSchema,
  networkTcpPortStateProposalSchema,
  webHttpMetadataProposalSchema,
  tlsCertificateMetadataProposalSchema,
  tlsCipherEnumerationProposalSchema
]);

export const capabilityDefinitions = Object.freeze({
  "planning.note": Object.freeze({
    version: 1, riskTier: "T0", parameterContract: Object.freeze({ note: "string:1..2000" })
  }),
  "network.discovery": Object.freeze({
    version: 1, riskTier: "T1", parameterContract: Object.freeze({ profile: "literal:version-only" })
  }),
  "network.service-version": Object.freeze({
    version: 1,
    riskTier: "T1",
    parameterContract: Object.freeze({
      ports: "integer[]:unique:1..32:1..65535",
      transport: "literal:tcp",
      intensity: "integer:0..2"
    })
  }),
  "network.tcp-port-discovery": Object.freeze({
    version: 1,
    riskTier: "T1",
    parameterContract: Object.freeze({
      profile: "literal:all-tcp",
      maxRate: "literal:1000"
    })
  }),
  "network.tcp-port-state": Object.freeze({
    version: 1,
    riskTier: "T1",
    parameterContract: Object.freeze({
      ports: "integer[]:unique:1..16:1..65535",
      transport: "literal:tcp",
      profile: "literal:low-noise"
    })
  }),
  "web.http-metadata": Object.freeze({
    version: 1,
    riskTier: "T1",
    parameterContract: Object.freeze({
      ports: "integer[]:unique:1..4:1..65535",
      transport: "literal:tcp",
      profile: "literal:headers-title"
    })
  }),
  "tls.certificate-metadata": Object.freeze({
    version: 1,
    riskTier: "T1",
    parameterContract: Object.freeze({
      ports: "integer[]:unique:1..4:1..65535",
      transport: "literal:tcp",
      profile: "literal:certificate"
    })
  }),
  "tls.cipher-enumeration": Object.freeze({
    version: 1,
    riskTier: "T2",
    parameterContract: Object.freeze({
      ports: "integer[]:unique:1..2:1..65535",
      transport: "literal:tcp",
      profile: "literal:cipher-posture"
    })
  })
});

export type CapabilityId = keyof typeof capabilityDefinitions;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

const capabilitySchemaHashes = Object.freeze(Object.fromEntries(
  Object.entries(capabilityDefinitions).map(([capabilityId, definition]) => [
    capabilityId,
    createHash("sha256").update(canonicalJson({ capabilityId, definition }), "utf8").digest("hex")
  ])
) as Record<CapabilityId, string>);

export function getCapabilitySchemaHash(capabilityId: CapabilityId): string {
  return capabilitySchemaHashes[capabilityId];
}

export type ActionProposal = z.infer<typeof actionProposalSchema>;
export type Scope = z.infer<typeof scopeSchema>;
export type TargetRecord = z.infer<typeof targetRecordSchema>;
