import { z } from "zod";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import {
  blueSignalIdSchema,
  type BlueRuleDescriptor
} from "./blue-detection-service.js";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const endpointIdSchema = z.string().regex(/^endpoint-[a-z0-9-]{8,80}$/);
const connectorIdSchema = z.string().regex(/^connector-[a-z0-9-]{8,80}$/);

export const liveEndpointEventSchema = z.object({
  mode: z.literal("live"),
  schemaVersion: z.literal(1),
  eventId: z.string().regex(/^event-[a-z0-9-]{8,96}$/),
  occurredAt: z.string().datetime({ offset: true }),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  bootId: z.string().regex(/^boot-[a-z0-9-]{8,80}$/),
  sequence: z.number().int().nonnegative(),
  telemetryClass: z.enum(["endpoint", "identity", "cloud", "certificate-authority"]),
  signal: blueSignalIdSchema,
  actorTrust: z.enum(["managed", "untrusted", "unknown"]),
  sourceRecordIdHash: sha256Schema,
  mappingVersion: z.literal("windows-blue-v1"),
  redaction: z.object({
    applied: z.literal(true),
    fieldsRemoved: z.number().int().nonnegative().max(64),
    valuesHashed: z.number().int().nonnegative().max(64)
  }).strict()
}).strict();

export type LiveEndpointEvent = z.infer<typeof liveEndpointEventSchema>;

const telemetryBatchCoreSchema = z.object({
  schemaVersion: z.literal(1),
  missionId: z.string().min(1).max(128),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: sha256Schema,
  sequenceStart: z.number().int().nonnegative(),
  sequenceEnd: z.number().int().nonnegative(),
  previousBatchHash: sha256Schema.nullable(),
  events: z.array(liveEndpointEventSchema).min(1).max(256)
}).strict();

export const signedTelemetryBatchSchema = telemetryBatchCoreSchema.extend({
  batchHash: sha256Schema,
  signatureBase64: z.string().min(40).max(2_048).regex(/^[A-Za-z0-9+/=]+$/)
}).strict();

export type SignedTelemetryBatch = z.infer<typeof signedTelemetryBatchSchema>;

export const telemetryReceiptSchema = z.object({
  batchId: z.string().regex(/^batch-[a-z0-9-]{8,96}$/),
  acceptedSequence: z.number().int().nonnegative(),
  receiptHash: sha256Schema,
  retryAfterMs: z.number().int().min(100).max(60_000).optional()
}).strict();

export type TelemetryReceipt = z.infer<typeof telemetryReceiptSchema>;

export function telemetryBatchHash(
  batch: Omit<SignedTelemetryBatch, "batchHash" | "signatureBase64">
): string {
  return canonicalHash(telemetryBatchCoreSchema.parse(batch));
}

export function validateSignedTelemetryBatch(
  input: unknown,
  verifySignature: (payload: string, signatureBase64: string, certificateFingerprintSha256: string) => boolean
): SignedTelemetryBatch {
  const batch = signedTelemetryBatchSchema.parse(input);
  if (batch.sequenceEnd < batch.sequenceStart) throw new Error("ENDPOINT_SEQUENCE_INVALID");
  if (batch.events.length !== batch.sequenceEnd - batch.sequenceStart + 1) {
    throw new Error("ENDPOINT_SEQUENCE_INVALID");
  }
  const sequences = batch.events.map((event) => event.sequence);
  if (
    sequences.some((sequence, index) => sequence !== batch.sequenceStart + index) ||
    new Set(sequences).size !== sequences.length
  ) {
    throw new Error("ENDPOINT_SEQUENCE_INVALID");
  }
  if (
    batch.events.some(
      (event) =>
        event.connectorId !== batch.connectorId ||
        event.endpointId !== batch.endpointId
    )
  ) {
    throw new Error("ENDPOINT_BINDING_MISMATCH");
  }
  const core = {
    schemaVersion: batch.schemaVersion,
    missionId: batch.missionId,
    connectorId: batch.connectorId,
    endpointId: batch.endpointId,
    certificateFingerprintSha256: batch.certificateFingerprintSha256,
    sequenceStart: batch.sequenceStart,
    sequenceEnd: batch.sequenceEnd,
    previousBatchHash: batch.previousBatchHash,
    events: batch.events
  } as const;
  const calculatedHash = telemetryBatchHash(core);
  if (calculatedHash !== batch.batchHash) throw new Error("ENDPOINT_BATCH_HASH_MISMATCH");
  if (!verifySignature(stableJson(core), batch.signatureBase64, batch.certificateFingerprintSha256)) {
    throw new Error("ENDPOINT_SIGNATURE_INVALID");
  }
  return batch;
}

export interface EndpointCoverageInput {
  readonly connectorId: string;
  readonly endpointId: string;
  readonly health: "healthy" | "degraded" | "stale" | "revoked" | "incompatible";
  readonly lastEventAt: string;
  readonly availableTelemetryClasses: ReadonlyArray<LiveEndpointEvent["telemetryClass"]>;
}

export interface EndpointRuleCoverage {
  readonly ruleId: string;
  readonly readiness: "synthetic-validated" | "live-supported";
  readonly health: EndpointCoverageInput["health"];
  readonly missingTelemetryClasses: LiveEndpointEvent["telemetryClass"][];
  readonly limitation: string;
}

export function assessEndpointCoverage(
  rules: readonly BlueRuleDescriptor[],
  endpoint: EndpointCoverageInput,
  now = new Date(),
  maxStalenessMs = 120_000
): EndpointRuleCoverage[] {
  const lastEvent = new Date(endpoint.lastEventAt).valueOf();
  const fresh = Number.isFinite(lastEvent) && now.valueOf() - lastEvent <= maxStalenessMs && lastEvent <= now.valueOf() + 30_000;
  const available = new Set(endpoint.availableTelemetryClasses);
  return rules.map((rule) => {
    const missing = rule.telemetryClasses.filter((item) => !available.has(item));
    const live =
      endpoint.health === "healthy" &&
      fresh &&
      missing.length === 0 &&
      rule.readiness === "synthetic-validated";
    return {
      ruleId: rule.id,
      readiness: live ? "live-supported" : "synthetic-validated",
      health: fresh ? endpoint.health : "stale",
      missingTelemetryClasses: missing,
      limitation: live
        ? "Live support means required normalized telemetry is currently available; a no-match result is not proof that the endpoint is clean."
        : `Live detection unsupported for this endpoint: ${
            !fresh ? "telemetry is stale" : missing.length ? `missing ${missing.join(", ")}` : `connector is ${endpoint.health}`
          }.`
    };
  });
}
