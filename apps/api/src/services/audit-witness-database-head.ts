import { z } from "zod";
import { sha256, stableJson } from "../domain/stable-json.js";
import { AUDIT_HEAD_GENESIS_HASH } from "./audit-head-checkpoint-contract.js";
import {
  auditRowSnapshotV1Schema,
  type AuditRowSnapshotV1
} from "./audit-head-checkpoint-proof.js";

export const AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1 =
  "project15.audit-witness-database-snapshot.v1" as const;
export const AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1 =
  "single-read-transaction-complete-prefix" as const;
export const AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1 =
  "verified-complete-prefix-input-only" as const;
export const AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS = 4096;
export const AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES = 8_388_608;

const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const sequenceSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

export const auditWitnessDatabaseSnapshotMetadataV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    purpose: z.literal(AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1),
    capture: z.literal(AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1),
    rowCount: sequenceSchema.max(
      AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS
    ),
    minimumSequence: sequenceSchema,
    maximumSequence: sequenceSchema,
    headEventHash: hashSchema
  })
  .strict();

const auditWitnessDatabaseHeadInputV1Schema = z
  .object({
    metadata: auditWitnessDatabaseSnapshotMetadataV1Schema,
    rows: z.unknown()
  })
  .strict();

export type AuditWitnessDatabaseSnapshotMetadataV1 = z.infer<
  typeof auditWitnessDatabaseSnapshotMetadataV1Schema
>;

export type VerifiedAuditWitnessDatabaseHeadV1 = Readonly<{
  schemaVersion: 1;
  claim: typeof AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1;
  status: "empty" | "ready";
  bootstrapAllowed: boolean;
  rowsVerified: number;
  databaseHeadSequence: number;
  databaseHeadEventHash: string;
  verifiedPrefixSha256: string;
}>;

function fail(code: string): never {
  throw new Error(code);
}

function parseRows(value: unknown): AuditRowSnapshotV1[] {
  if (!Array.isArray(value)) {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID");
  }
  if (value.length > AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS) {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_TOO_LARGE");
  }
  try {
    return z.array(auditRowSnapshotV1Schema).parse(value);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_ROW_INVALID");
  }
}

export function verifyAuditWitnessDatabaseHeadV1(input: {
  metadata: unknown;
  rows: unknown;
}): VerifiedAuditWitnessDatabaseHeadV1 {
  let parsedInput: z.infer<typeof auditWitnessDatabaseHeadInputV1Schema>;
  try {
    parsedInput = auditWitnessDatabaseHeadInputV1Schema.parse(input);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID");
  }
  const metadata = parsedInput.metadata;
  const rows = parseRows(parsedInput.rows);
  if (
    Buffer.byteLength(stableJson(rows), "utf8") >
    AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES
  ) {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_TOO_LARGE");
  }

  if (rows.length === 0) {
    if (
      metadata.rowCount !== 0 ||
      metadata.minimumSequence !== 0 ||
      metadata.maximumSequence !== 0 ||
      metadata.headEventHash !== AUDIT_HEAD_GENESIS_HASH
    ) {
      return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_METADATA_MISMATCH");
    }
    return {
      schemaVersion: 1,
      claim: AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1,
      status: "empty",
      bootstrapAllowed: false,
      rowsVerified: 0,
      databaseHeadSequence: 0,
      databaseHeadEventHash: AUDIT_HEAD_GENESIS_HASH,
      verifiedPrefixSha256: sha256(stableJson(rows))
    };
  }

  const last = rows.at(-1)!;
  if (
    metadata.rowCount !== rows.length ||
    metadata.minimumSequence !== 1 ||
    metadata.maximumSequence !== rows.length ||
    metadata.maximumSequence !== last.sequence ||
    metadata.headEventHash !== last.event_hash
  ) {
    return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_METADATA_MISMATCH");
  }

  const ids = new Set<string>();
  const eventHashes = new Set<string>();
  let previousHash = AUDIT_HEAD_GENESIS_HASH;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index]!;
    if (row.sequence !== index + 1) {
      return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_SEQUENCE_INVALID");
    }
    if (row.previous_hash !== previousHash) {
      return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_CHAIN_BROKEN");
    }
    const expectedHash = sha256(
      `${row.previous_hash}\n${row.occurred_at}\n${row.event_type}\n${row.payload_json}`
    );
    if (row.event_hash !== expectedHash) {
      return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_HASH_INVALID");
    }
    if (ids.has(row.id) || eventHashes.has(row.event_hash)) {
      return fail("AUDIT_WITNESS_DATABASE_ACQUISITION_DUPLICATE_INVALID");
    }
    ids.add(row.id);
    eventHashes.add(row.event_hash);
    previousHash = row.event_hash;
  }

  return {
    schemaVersion: 1,
    claim: AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1,
    status: "ready",
    bootstrapAllowed: true,
    rowsVerified: rows.length,
    databaseHeadSequence: last.sequence,
    databaseHeadEventHash: last.event_hash,
    verifiedPrefixSha256: sha256(stableJson(rows))
  };
}
