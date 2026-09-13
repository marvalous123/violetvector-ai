import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS,
  verifyAuditWitnessDatabaseHeadV1,
  type VerifiedAuditWitnessDatabaseHeadV1
} from "./audit-witness-database-head.js";

export const AUDIT_WITNESS_DATABASE_READ_PURPOSE_V1 =
  "project15.audit-witness-database-read.v1" as const;

const columns = Object.freeze([
  "sequence",
  "id",
  "occurred_at",
  "event_type",
  "payload_json",
  "previous_hash",
  "event_hash"
] as const);

const orderBy = Object.freeze({
  column: "sequence" as const,
  direction: "ASC" as const
});

export const AUDIT_WITNESS_DATABASE_READ_REQUEST_V1 = Object.freeze({
  schemaVersion: 1 as const,
  purpose: AUDIT_WITNESS_DATABASE_READ_PURPOSE_V1,
  capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  table: "audit_events" as const,
  columns,
  orderBy,
  maximumRows: AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS,
  readOnly: true as const,
  runtimeWiringEnabled: false as const
});

export type AuditWitnessDatabaseReadRequestV1 =
  typeof AUDIT_WITNESS_DATABASE_READ_REQUEST_V1;

export interface AuditWitnessDatabaseSnapshotReaderV1 {
  readCompletePrefixSnapshot(
    request: AuditWitnessDatabaseReadRequestV1
  ): unknown;
}

function fail(code: string): never {
  throw new Error(code);
}

export function acquireAuditWitnessDatabaseHeadV1(
  reader: AuditWitnessDatabaseSnapshotReaderV1
): VerifiedAuditWitnessDatabaseHeadV1 {
  let response: unknown;
  try {
    response = reader.readCompletePrefixSnapshot(
      AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
    );
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_READ_FAILED");
  }

  if (
    response === null ||
    typeof response !== "object" ||
    Array.isArray(response) ||
    !Object.hasOwn(response, "metadata") ||
    !Object.hasOwn(response, "rows") ||
    Object.keys(response).length !== 2
  ) {
    return fail("AUDIT_WITNESS_DATABASE_READ_RESPONSE_INVALID");
  }
  const fields = response as { metadata: unknown; rows: unknown };
  return verifyAuditWitnessDatabaseHeadV1({
    metadata: fields.metadata,
    rows: fields.rows
  });
}
