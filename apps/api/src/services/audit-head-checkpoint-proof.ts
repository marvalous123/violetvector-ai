import { z } from "zod";
import { createHash, createPublicKey, verify as verifyCrypto } from "node:crypto";
import { sha256, stableJson } from "../domain/stable-json.js";
import {
  AUDIT_HEAD_GENESIS_HASH,
  AUDIT_HEAD_CHAIN_PURPOSE_V1,
  advanceAuditHeadCheckpointStateV1,
  auditHeadCheckpointHashV1,
  auditHeadProtectedDocumentV1Schema,
  auditHeadCheckpointStateV1Schema,
  signedAuditHeadCheckpointV1Schema,
  type AuditHeadCheckpointCoreV1,
  type AuditHeadCheckpointSignatureVerifierV1,
  type AuditHeadCheckpointStateV1,
  type AuditHeadProtectedDocumentV1
} from "./audit-head-checkpoint-contract.js";

export const AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS = 256;
export const AUDIT_HEAD_MAXIMUM_UNCHECKPOINTED_TAIL = 256;
export const AUDIT_HEAD_MAXIMUM_PENDING_BYTES = 131_072;

const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const sequenceSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const positiveSequenceSchema = sequenceSchema.refine((value) => value > 0);
const canonicalUtcTimestampSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  .refine((value) => {
    const parsed = new Date(value);
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
  });

export const auditRowSnapshotV1Schema = z
  .object({
    sequence: positiveSequenceSchema,
    id: z.string().uuid(),
    occurred_at: z.string().datetime({ offset: true }),
    event_type: z.string().min(1).max(128),
    payload_json: z.string().min(2).max(1_048_576),
    previous_hash: hashSchema,
    event_hash: hashSchema
  })
  .strict();

export const auditHeadCheckpointLinkV1Schema = z
  .object({
    sequence: positiveSequenceSchema,
    previousHash: hashSchema,
    eventHash: hashSchema
  })
  .strict();

export const auditHeadCheckpointPendingRowV1Schema = z
  .object({
    sequence: positiveSequenceSchema,
    occurredAt: canonicalUtcTimestampSchema,
    eventType: z.string().min(1).max(128),
    payloadJson: z.string().min(2).max(65_536),
    previousHash: hashSchema,
    eventHash: hashSchema
  })
  .strict();

export const auditHeadCheckpointProofV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    priorSequence: sequenceSchema,
    priorEventHash: hashSchema,
    priorCheckpointHash: hashSchema,
    rows: z
      .array(auditHeadCheckpointPendingRowV1Schema)
      .min(1)
      .max(AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS)
  })
  .strict();

export const auditHeadDatabaseHeadV1Schema = z
  .object({
    sequence: positiveSequenceSchema,
    eventHash: hashSchema
  })
  .strict();

export type AuditRowSnapshotV1 = z.infer<typeof auditRowSnapshotV1Schema>;
export type AuditHeadCheckpointProofV1 = z.infer<
  typeof auditHeadCheckpointProofV1Schema
>;

export type AuditHeadTailClassificationV1 =
  | { status: "checkpointed"; count: 0 }
  | {
      status: "uncheckpointed";
      count: number;
      sequenceStart: number;
      sequenceEnd: number;
      headEventHash: string;
    };

function fail(code: string): never {
  throw new Error(code);
}

export function verifyAuditHeadProtectedDocumentV1(input: {
  document: unknown;
  expectedSignerPublicKeyFingerprintSha256: string;
}
): AuditHeadProtectedDocumentV1 {
  let document: AuditHeadProtectedDocumentV1;
  let expectedFingerprint: string;
  try {
    document = auditHeadProtectedDocumentV1Schema.parse(input.document);
    expectedFingerprint = hashSchema.parse(
      input.expectedSignerPublicKeyFingerprintSha256
    );
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_DOCUMENT_SCHEMA_INVALID");
  }

  const { signer, checkpoint } = document;
  const expectedChainId = sha256(
    `${AUDIT_HEAD_CHAIN_PURPOSE_V1}\n${expectedFingerprint}`
  );
  if (
    expectedFingerprint === AUDIT_HEAD_GENESIS_HASH ||
    signer.publicKeyFingerprintSha256 !== expectedFingerprint ||
    signer.chainId !== expectedChainId
  ) {
    return fail("AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH");
  }
  let publicKey;
  try {
    const spki = Buffer.from(signer.publicKeySpkiBase64, "base64");
    if (
      createHash("sha256").update(spki).digest("hex") !==
      signer.publicKeyFingerprintSha256
    ) {
      return fail("AUDIT_HEAD_PROTECTED_SIGNER_INVALID");
    }
    publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    if (
      publicKey.asymmetricKeyType !== "ec" ||
      publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      return fail("AUDIT_HEAD_PROTECTED_SIGNER_INVALID");
    }
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_SIGNER_INVALID");
  }

  if (
    checkpoint.chainId !== signer.chainId ||
    checkpoint.signerProfile !== signer.profile ||
    checkpoint.signerAlgorithm !== signer.algorithm ||
    checkpoint.signerPublicKeyFingerprintSha256 !==
      signer.publicKeyFingerprintSha256 ||
    checkpoint.sequence <= checkpoint.priorSequence ||
    (checkpoint.priorSequence === 0 &&
      (checkpoint.priorEventHash !== AUDIT_HEAD_GENESIS_HASH ||
        checkpoint.priorCheckpointHash !== AUDIT_HEAD_GENESIS_HASH)) ||
    (checkpoint.priorSequence > 0 &&
      (checkpoint.priorEventHash === AUDIT_HEAD_GENESIS_HASH ||
        checkpoint.priorCheckpointHash === AUDIT_HEAD_GENESIS_HASH))
  ) {
    return fail("AUDIT_HEAD_PROTECTED_DOCUMENT_INVALID");
  }

  const core: AuditHeadCheckpointCoreV1 = {
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
  const canonicalPayload = stableJson(core);
  if (
    checkpoint.checkpointHash !== auditHeadCheckpointHashV1(core) ||
    !verifyCrypto(
      "sha256",
      Buffer.from(canonicalPayload, "utf8"),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(checkpoint.signatureBase64, "base64")
    )
  ) {
    return fail("AUDIT_HEAD_PROTECTED_SIGNATURE_INVALID");
  }
  return document;
}

function rowEventHash(row: AuditRowSnapshotV1): string {
  return sha256(
    `${row.previous_hash}\n${row.occurred_at}\n${row.event_type}\n${row.payload_json}`
  );
}

function parseState(value: unknown | null): AuditHeadCheckpointStateV1 | null {
  try {
    return value === null ? null : auditHeadCheckpointStateV1Schema.parse(value);
  } catch {
    return fail("AUDIT_HEAD_PROOF_SCHEMA_INVALID");
  }
}

function parseRows(value: unknown, maximum: number): AuditRowSnapshotV1[] {
  if (!Array.isArray(value)) return fail("AUDIT_HEAD_PROOF_SCHEMA_INVALID");
  if (value.length > maximum) return fail("AUDIT_HEAD_PROOF_TOO_LARGE");
  try {
    return z.array(auditRowSnapshotV1Schema).parse(value);
  } catch {
    return fail("AUDIT_HEAD_PROOF_SCHEMA_INVALID");
  }
}

function verifyRows(
  rows: readonly AuditRowSnapshotV1[],
  startSequence: number,
  startPreviousHash: string
): void {
  let expectedSequence = startSequence;
  let expectedPreviousHash = startPreviousHash;
  for (const row of rows) {
    if (
      row.sequence !== expectedSequence ||
      row.previous_hash !== expectedPreviousHash
    ) {
      return fail("AUDIT_HEAD_PROOF_CONTINUITY_INVALID");
    }
    if (row.event_hash !== rowEventHash(row)) {
      return fail("AUDIT_HEAD_PROOF_HASH_INVALID");
    }
    expectedSequence += 1;
    expectedPreviousHash = row.event_hash;
  }
}

export function prepareAuditHeadCheckpointProofV1(input: {
  rows: unknown;
  currentState: unknown | null;
}): AuditHeadCheckpointProofV1 {
  const currentState = parseState(input.currentState);
  const rows = parseRows(input.rows, AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS);
  if (rows.length === 0) return fail("AUDIT_HEAD_PROOF_EMPTY");

  const priorSequence = currentState?.sequence ?? 0;
  const priorEventHash = currentState?.eventHash ?? AUDIT_HEAD_GENESIS_HASH;
  const priorCheckpointHash =
    currentState?.checkpointHash ?? AUDIT_HEAD_GENESIS_HASH;
  verifyRows(rows, priorSequence + 1, priorEventHash);

  const proof = auditHeadCheckpointProofV1Schema.parse({
    schemaVersion: 1,
    priorSequence,
    priorEventHash,
    priorCheckpointHash,
    rows: rows.map((row) => ({
      sequence: row.sequence,
      occurredAt: row.occurred_at,
      eventType: row.event_type,
      payloadJson: row.payload_json,
      previousHash: row.previous_hash,
      eventHash: row.event_hash
    }))
  });
  if (Buffer.byteLength(JSON.stringify(proof), "utf8") >
      AUDIT_HEAD_MAXIMUM_PENDING_BYTES) {
    return fail("AUDIT_HEAD_PROOF_TOO_LARGE");
  }
  return proof;
}

export function verifyProtectedAuditHeadReceiptV1(input: {
  receipt: unknown;
  currentState: unknown | null;
  rows: unknown;
  databaseHead: unknown;
  expectedChainId: string;
  expectedSignerPublicKeyFingerprintSha256: string;
  verifySignature: AuditHeadCheckpointSignatureVerifierV1;
}): {
  state: AuditHeadCheckpointStateV1;
  tail: AuditHeadTailClassificationV1;
} {
  let receipt: z.infer<typeof signedAuditHeadCheckpointV1Schema>;
  let databaseHead: z.infer<typeof auditHeadDatabaseHeadV1Schema>;
  try {
    receipt = signedAuditHeadCheckpointV1Schema.parse(input.receipt);
    databaseHead = auditHeadDatabaseHeadV1Schema.parse(input.databaseHead);
  } catch {
    return fail("AUDIT_HEAD_RECEIPT_SCHEMA_INVALID");
  }
  const currentState = parseState(input.currentState);
  const anchorRows = currentState === null ? 0 : 1;
  const maximumRows =
    anchorRows +
    AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS +
    AUDIT_HEAD_MAXIMUM_UNCHECKPOINTED_TAIL;
  const rows = parseRows(input.rows, maximumRows);
  if (rows.length === 0) return fail("AUDIT_HEAD_DATABASE_SNAPSHOT_TRUNCATED");

  const expectedFirstSequence = currentState?.sequence ?? 1;
  const firstPreviousHash =
    currentState === null ? AUDIT_HEAD_GENESIS_HASH : rows[0]!.previous_hash;
  verifyRows(rows, expectedFirstSequence, firstPreviousHash);

  if (currentState !== null) {
    const anchor = rows[0]!;
    if (
      anchor.sequence !== currentState.sequence ||
      anchor.event_hash !== currentState.eventHash
    ) {
      return fail("AUDIT_HEAD_CHECKPOINT_CHAIN_RECOMPUTED");
    }
  }

  const last = rows.at(-1)!;
  if (
    last.sequence !== databaseHead.sequence ||
    last.event_hash !== databaseHead.eventHash
  ) {
    return fail("AUDIT_HEAD_DATABASE_SNAPSHOT_TRUNCATED");
  }

  const checkpointIndex = rows.findIndex(
    (row) => row.sequence === receipt.sequence
  );
  if (checkpointIndex < 0) return fail("AUDIT_HEAD_DATABASE_SNAPSHOT_TRUNCATED");
  const priorIndex =
    receipt.priorSequence === 0
      ? -1
      : rows.findIndex((row) => row.sequence === receipt.priorSequence);
  if (receipt.priorSequence > 0 && priorIndex < 0) {
    return fail("AUDIT_HEAD_DATABASE_SNAPSHOT_TRUNCATED");
  }
  if (checkpointIndex - priorIndex > AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS) {
    return fail("AUDIT_HEAD_PROOF_TOO_LARGE");
  }

  const state = advanceAuditHeadCheckpointStateV1({
    candidate: receipt,
    currentState,
    observation: {
      databaseHeadSequence: databaseHead.sequence,
      checkpointEventHashAtSequence: rows[checkpointIndex]!.event_hash,
      priorCheckpointEventHashAtSequence:
        priorIndex < 0 ? null : rows[priorIndex]!.event_hash
    },
    expectedChainId: input.expectedChainId,
    expectedSignerPublicKeyFingerprintSha256:
      input.expectedSignerPublicKeyFingerprintSha256,
    verifySignature: input.verifySignature
  });

  const tailCount = databaseHead.sequence - receipt.sequence;
  if (tailCount === 0) return { state, tail: { status: "checkpointed", count: 0 } };
  if (tailCount > AUDIT_HEAD_MAXIMUM_UNCHECKPOINTED_TAIL) {
    return fail("AUDIT_HEAD_UNCHECKPOINTED_TAIL_TOO_LARGE");
  }
  return {
    state,
    tail: {
      status: "uncheckpointed",
      count: tailCount,
      sequenceStart: receipt.sequence + 1,
      sequenceEnd: databaseHead.sequence,
      headEventHash: databaseHead.eventHash
    }
  };
}
