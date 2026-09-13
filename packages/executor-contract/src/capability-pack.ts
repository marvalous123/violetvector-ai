import { z } from "zod";
import { sha256Schema } from "./schemas.js";

const packIdSchema = z.string().min(3).max(96).regex(/^[a-z][a-z0-9.-]+$/);
const capabilityIdSchema = z.string().min(5).max(128).regex(/^local\.[a-z][a-z0-9.-]+\.v[1-9][0-9]*$/);

export const capabilityPackManifestSchema = z.object({
  manifestVersion: z.literal("war-room-capability-pack.v1"),
  packId: packIdSchema,
  name: z.string().min(3).max(120),
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/),
  capabilityId: capabilityIdSchema,
  adapterId: z.string().min(3).max(96).regex(/^[a-z][a-z0-9.-]+$/),
  riskTier: z.enum(["T0", "T1", "T2"]),
  approvalPolicy: z.enum(["none", "fresh-single-use"]),
  targetRequired: z.boolean(),
  destructive: z.literal(false),
  parameterSchemaHash: sha256Schema,
  sourceHash: sha256Schema,
  permissions: z.object({
    network: z.enum(["none", "exact-target"]),
    process: z.enum(["none", "reviewed-adapter"]),
    filesystem: z.enum(["none", "evidence-only"]),
    credentialAccess: z.literal(false),
    payloadExecution: z.literal(false),
    evasionControls: z.literal(false)
  }).strict(),
  limits: z.object({
    timeoutMs: z.number().int().min(100).max(120_000),
    maxOutputBytes: z.number().int().min(1).max(1_000_000),
    maxEvidenceBytes: z.number().int().min(1).max(5_000_000),
    maxRequests: z.number().int().min(1).max(16)
  }).strict(),
  evidenceMediaTypes: z.array(z.enum(["application/json", "text/plain"])).min(1).max(2)
}).strict().superRefine((manifest, context) => {
  if (manifest.riskTier === "T0" &&
      (manifest.targetRequired ||
       manifest.permissions.network !== "none" ||
       manifest.permissions.process !== "none" ||
       manifest.approvalPolicy !== "none")) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "T0 packs cannot require a target, network, process, or approval"
    });
  }
  if (manifest.permissions.network === "exact-target" &&
      (!manifest.targetRequired || manifest.approvalPolicy !== "fresh-single-use")) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "exact-target packs require a target and fresh single-use approval"
    });
  }
  if (manifest.targetRequired && manifest.permissions.network !== "exact-target") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "target packs must use exact-target network permission"
    });
  }
});

export type CapabilityPackManifest = z.infer<typeof capabilityPackManifestSchema>;

export function validateCapabilityPackManifest(input: unknown): CapabilityPackManifest {
  return capabilityPackManifestSchema.parse(input);
}
