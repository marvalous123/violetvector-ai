import { verifyAuditHeadProtectedDocumentV1 } from "./audit-head-checkpoint-proof.js";
import {
  AUDIT_WITNESS_BOOTSTRAP_PURPOSE_V1,
  createAuditWitnessCheckpointBootstrapStateV1,
  type AuditWitnessStateV1
} from "./audit-witness-contract.js";
import { verifyAuditWitnessDatabaseHeadV1 } from "./audit-witness-database-head.js";

function fail(code: string): never {
  throw new Error(code);
}

export function createTrustedAuditWitnessBootstrapV1(input: {
  protectedDocument: unknown;
  expectedSignerPublicKeyFingerprintSha256: string;
  databaseSnapshot: {
    metadata: unknown;
    rows: unknown;
  };
}): AuditWitnessStateV1 {
  const protectedDocument = verifyAuditHeadProtectedDocumentV1({
    document: input.protectedDocument,
    expectedSignerPublicKeyFingerprintSha256:
      input.expectedSignerPublicKeyFingerprintSha256
  });
  const observation = verifyAuditWitnessDatabaseHeadV1(input.databaseSnapshot);

  const { checkpoint, signer } = protectedDocument;
  if (
    observation.status !== "ready" ||
    observation.bootstrapAllowed !== true ||
    observation.databaseHeadSequence !== checkpoint.sequence ||
    observation.databaseHeadEventHash !== checkpoint.eventHash
  ) {
    return fail("AUDIT_WITNESS_BOOTSTRAP_DATABASE_MISMATCH");
  }

  return createAuditWitnessCheckpointBootstrapStateV1({
    schemaVersion: 1,
    purpose: AUDIT_WITNESS_BOOTSTRAP_PURPOSE_V1,
    chainId: checkpoint.chainId,
    sequence: checkpoint.sequence,
    eventHash: checkpoint.eventHash,
    checkpointHash: checkpoint.checkpointHash,
    signerPublicKeyFingerprintSha256:
      signer.publicKeyFingerprintSha256
  });
}
