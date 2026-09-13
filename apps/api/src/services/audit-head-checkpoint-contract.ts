import { z } from "zod";
import { sha256, stableJson } from "../domain/stable-json.js";

export const AUDIT_HEAD_CHECKPOINT_PURPOSE_V1 =
  "project15.audit-head-checkpoint.v1" as const;
export const AUDIT_HEAD_CHAIN_PURPOSE_V1 =
  "project15.audit-head-chain.v1" as const;
export const AUDIT_HEAD_SIGNER_PROFILE_V1 =
  "project15-audit-head-signer-v1" as const;
export const AUDIT_HEAD_SIGNER_ALGORITHM_V1 =
  "ecdsa-p256-sha256" as const;
export const AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1 = "spki-der" as const;
export const AUDIT_HEAD_KEY_PERSISTENCE_V1 =
  "non-exportable-machine-cng-audit-v1" as const;

export const AUDIT_HEAD_GENESIS_HASH = "0".repeat(64);
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const nonGenesisHashSchema = hashSchema.refine(
  (value) => value !== AUDIT_HEAD_GENESIS_HASH
);
const sequenceSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const positiveSequenceSchema = sequenceSchema.refine((value) => value > 0);

export const auditHeadCheckpointCoreV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    purpose: z.literal(AUDIT_HEAD_CHECKPOINT_PURPOSE_V1),
    chainId: nonGenesisHashSchema,
    priorSequence: sequenceSchema,
    priorEventHash: hashSchema,
    priorCheckpointHash: hashSchema,
    sequence: positiveSequenceSchema,
    eventHash: nonGenesisHashSchema,
    signerProfile: z.literal(AUDIT_HEAD_SIGNER_PROFILE_V1),
    signerAlgorithm: z.literal(AUDIT_HEAD_SIGNER_ALGORITHM_V1),
    signerPublicKeyFingerprintSha256: nonGenesisHashSchema
  })
  .strict();

const canonicalP1363SignatureSchema = z
  .string()
  .min(80)
  .max(128)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/)
  .refine((value) => {
    const bytes = Buffer.from(value, "base64");
    return bytes.length === 64 && bytes.toString("base64") === value;
  });

export const signedAuditHeadCheckpointV1Schema = auditHeadCheckpointCoreV1Schema
  .extend({
    checkpointHash: nonGenesisHashSchema,
    signatureBase64: canonicalP1363SignatureSchema
  })
  .strict();

export const auditHeadCheckpointStateV1Schema = z
  .object({
    chainId: nonGenesisHashSchema,
    sequence: positiveSequenceSchema,
    eventHash: nonGenesisHashSchema,
    checkpointHash: nonGenesisHashSchema
  })
  .strict();

const canonicalBase64Schema = z
  .string()
  .min(80)
  .max(512)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/)
  .refine((value) => {
    const bytes = Buffer.from(value, "base64");
    return bytes.length > 0 && bytes.toString("base64") === value;
  });

export const auditHeadSignerDescriptorV1Schema = z
  .object({
    profile: z.literal(AUDIT_HEAD_SIGNER_PROFILE_V1),
    chainId: nonGenesisHashSchema,
    algorithm: z.literal(AUDIT_HEAD_SIGNER_ALGORITHM_V1),
    publicKeyFormat: z.literal(AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1),
    publicKeySpkiBase64: canonicalBase64Schema,
    publicKeyFingerprintSha256: nonGenesisHashSchema,
    keyPersistence: z.literal(AUDIT_HEAD_KEY_PERSISTENCE_V1)
  })
  .strict();

export const auditHeadProtectedDocumentV1Schema = z
  .object({
    signer: auditHeadSignerDescriptorV1Schema,
    checkpoint: signedAuditHeadCheckpointV1Schema
  })
  .strict();

export const auditHeadCheckpointObservationV1Schema = z
  .object({
    databaseHeadSequence: sequenceSchema,
    checkpointEventHashAtSequence: hashSchema.nullable(),
    priorCheckpointEventHashAtSequence: hashSchema.nullable()
  })
  .strict();

export type AuditHeadCheckpointCoreV1 = z.infer<
  typeof auditHeadCheckpointCoreV1Schema
>;
export type SignedAuditHeadCheckpointV1 = z.infer<
  typeof signedAuditHeadCheckpointV1Schema
>;
export type AuditHeadCheckpointStateV1 = z.infer<
  typeof auditHeadCheckpointStateV1Schema
>;
export type AuditHeadCheckpointObservationV1 = z.infer<
  typeof auditHeadCheckpointObservationV1Schema
>;
export type AuditHeadSignerDescriptorV1 = z.infer<
  typeof auditHeadSignerDescriptorV1Schema
>;
export type AuditHeadProtectedDocumentV1 = z.infer<
  typeof auditHeadProtectedDocumentV1Schema
>;

export type AuditHeadCheckpointSignatureVerifierV1 = (
  canonicalPayload: string,
  signatureBase64: string,
  signerPublicKeyFingerprintSha256: string
) => boolean;

export function auditHeadCheckpointHashV1(
  core: AuditHeadCheckpointCoreV1
): string {
  return sha256(stableJson(auditHeadCheckpointCoreV1Schema.parse(core)));
}

function checkpointCore(
  checkpoint: SignedAuditHeadCheckpointV1
): AuditHeadCheckpointCoreV1 {
  return {
    schemaVersion: checkpoint.schemaVersion,
    purpose: checkpoint.purpose,
    chainId: checkpoint.chainId,
    priorSequence: checkpoint.priorSequence,
    priorEventHash: checkpoint.priorEventHash,
    priorCheckpointHash: checkpoint.priorCheckpointHash,
    sequence: checkpoint.sequence,
    eventHash: checkpoint.eventHash,
    signerProfile: checkpoint.signerProfile,
    signerAlgorithm: checkpoint.signerAlgorithm,
    signerPublicKeyFingerprintSha256:
      checkpoint.signerPublicKeyFingerprintSha256
  };
}

function fail(code: string): never {
  throw new Error(code);
}

export function advanceAuditHeadCheckpointStateV1(input: {
  candidate: unknown;
  currentState: unknown | null;
  observation: unknown;
  expectedChainId: string;
  expectedSignerPublicKeyFingerprintSha256: string;
  verifySignature: AuditHeadCheckpointSignatureVerifierV1;
}): AuditHeadCheckpointStateV1 {
  let candidate: SignedAuditHeadCheckpointV1;
  let currentState: AuditHeadCheckpointStateV1 | null;
  let observation: AuditHeadCheckpointObservationV1;
  let expectedChainId: string;
  let expectedSignerFingerprint: string;
  try {
    candidate = signedAuditHeadCheckpointV1Schema.parse(input.candidate);
    currentState =
      input.currentState === null
        ? null
        : auditHeadCheckpointStateV1Schema.parse(input.currentState);
    observation = auditHeadCheckpointObservationV1Schema.parse(input.observation);
    expectedChainId = nonGenesisHashSchema.parse(input.expectedChainId);
    expectedSignerFingerprint = nonGenesisHashSchema.parse(
      input.expectedSignerPublicKeyFingerprintSha256
    );
  } catch {
    return fail("AUDIT_HEAD_CHECKPOINT_SCHEMA_INVALID");
  }

  if (
    candidate.chainId !== expectedChainId ||
    (currentState !== null && currentState.chainId !== expectedChainId)
  ) {
    return fail("AUDIT_HEAD_CHECKPOINT_CHAIN_MISMATCH");
  }
  if (
    candidate.signerPublicKeyFingerprintSha256 !== expectedSignerFingerprint
  ) {
    return fail("AUDIT_HEAD_CHECKPOINT_SIGNER_MISMATCH");
  }
  if (candidate.sequence <= candidate.priorSequence) {
    return fail("AUDIT_HEAD_CHECKPOINT_ROLLBACK");
  }

  const core = checkpointCore(candidate);
  const canonicalPayload = stableJson(core);
  if (candidate.checkpointHash !== sha256(canonicalPayload)) {
    return fail("AUDIT_HEAD_CHECKPOINT_HASH_INVALID");
  }

  let signatureValid: boolean;
  try {
    signatureValid = input.verifySignature(
      canonicalPayload,
      candidate.signatureBase64,
      candidate.signerPublicKeyFingerprintSha256
    );
  } catch {
    return fail("AUDIT_HEAD_CHECKPOINT_SIGNATURE_INVALID");
  }
  if (!signatureValid) return fail("AUDIT_HEAD_CHECKPOINT_SIGNATURE_INVALID");

  if (
    observation.databaseHeadSequence < candidate.sequence ||
    observation.checkpointEventHashAtSequence !== candidate.eventHash
  ) {
    return fail("AUDIT_HEAD_CHECKPOINT_PREFIX_INVALID");
  }

  if (currentState === null) {
    if (
      candidate.priorSequence !== 0 ||
      candidate.priorEventHash !== AUDIT_HEAD_GENESIS_HASH ||
      candidate.priorCheckpointHash !== AUDIT_HEAD_GENESIS_HASH ||
      observation.priorCheckpointEventHashAtSequence !== null
    ) {
      return fail("AUDIT_HEAD_CHECKPOINT_GENESIS_INVALID");
    }
  } else {
    if (candidate.sequence <= currentState.sequence) {
      return fail("AUDIT_HEAD_CHECKPOINT_ROLLBACK");
    }
    if (
      candidate.priorSequence !== currentState.sequence ||
      candidate.priorEventHash !== currentState.eventHash ||
      candidate.priorCheckpointHash !== currentState.checkpointHash
    ) {
      return fail("AUDIT_HEAD_CHECKPOINT_CONTINUITY_INVALID");
    }
    if (
      observation.priorCheckpointEventHashAtSequence !== currentState.eventHash
    ) {
      return fail("AUDIT_HEAD_CHECKPOINT_CHAIN_RECOMPUTED");
    }
  }

  return auditHeadCheckpointStateV1Schema.parse({
    chainId: candidate.chainId,
    sequence: candidate.sequence,
    eventHash: candidate.eventHash,
    checkpointHash: candidate.checkpointHash
  });
}
