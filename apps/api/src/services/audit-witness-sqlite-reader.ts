import type { DatabaseSync } from "node:sqlite";
import { AUDIT_HEAD_GENESIS_HASH } from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_WITNESS_DATABASE_READ_REQUEST_V1,
  type AuditWitnessDatabaseReadRequestV1,
  type AuditWitnessDatabaseSnapshotReaderV1
} from "./audit-witness-database-read-adapter.js";
import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1
} from "./audit-witness-database-head.js";

export const AUDIT_WITNESS_SQLITE_READER_RUNTIME_WIRING_ENABLED = false;

const beginReadTransaction = "BEGIN DEFERRED";
const rollbackReadTransaction = "ROLLBACK";
const queryOnlyStatement = "PRAGMA query_only";
const preflightStatement = `SELECT
  sequence,
  typeof(sequence) AS sequence_type,
  typeof(id) AS id_type,
  length(CAST(id AS BLOB)) AS id_bytes,
  typeof(occurred_at) AS occurred_at_type,
  length(CAST(occurred_at AS BLOB)) AS occurred_at_bytes,
  typeof(event_type) AS event_type_type,
  length(CAST(event_type AS BLOB)) AS event_type_bytes,
  typeof(payload_json) AS payload_json_type,
  length(CAST(payload_json AS BLOB)) AS payload_json_bytes,
  typeof(previous_hash) AS previous_hash_type,
  length(CAST(previous_hash AS BLOB)) AS previous_hash_bytes,
  typeof(event_hash) AS event_hash_type,
  length(CAST(event_hash AS BLOB)) AS event_hash_bytes
FROM audit_events
ORDER BY sequence ASC
LIMIT ?`;
const rowsStatement = `SELECT
  sequence,
  id,
  occurred_at,
  event_type,
  payload_json,
  previous_hash,
  event_hash
FROM audit_events
ORDER BY sequence ASC
LIMIT ?`;

const textColumns = [
  "id",
  "occurred_at",
  "event_type",
  "payload_json",
  "previous_hash",
  "event_hash"
] as const;

type PreflightRow = {
  sequence: unknown;
  sequence_type: unknown;
  id_type: unknown;
  id_bytes: unknown;
  occurred_at_type: unknown;
  occurred_at_bytes: unknown;
  event_type_type: unknown;
  event_type_bytes: unknown;
  payload_json_type: unknown;
  payload_json_bytes: unknown;
  previous_hash_type: unknown;
  previous_hash_bytes: unknown;
  event_hash_type: unknown;
  event_hash_bytes: unknown;
};

// JSON string escaping can expand one input byte to at most six UTF-8 bytes
// (for example, an ASCII control character becomes "\\u00xx"). The fixed
// allowance covers keys, punctuation and the decimal sequence value.
const maximumJsonExpansion = 6;
const fixedJsonBytesPerRow = 256;
const fixedJsonArrayBytes = 2;

function fail(code: string): never {
  throw new Error(code);
}

function isBoundaryError(error: unknown): error is Error {
  return (
    error instanceof Error &&
    error.message.startsWith("AUDIT_WITNESS_DATABASE_SQLITE_")
  );
}

export class UnwiredAuditWitnessSqliteReaderV1
  implements AuditWitnessDatabaseSnapshotReaderV1
{
  constructor(private readonly database: DatabaseSync) {}

  readCompletePrefixSnapshot(
    request: AuditWitnessDatabaseReadRequestV1
  ): unknown {
    if (request !== AUDIT_WITNESS_DATABASE_READ_REQUEST_V1) {
      return fail("AUDIT_WITNESS_DATABASE_SQLITE_REQUEST_INVALID");
    }
    if (
      AUDIT_WITNESS_SQLITE_READER_RUNTIME_WIRING_ENABLED ||
      !this.database.isOpen ||
      this.database.isTransaction
    ) {
      return fail("AUDIT_WITNESS_DATABASE_SQLITE_CONNECTION_INVALID");
    }

    let began = false;
    let response: unknown;
    let failure: Error | null = null;
    try {
      this.database.exec(beginReadTransaction);
      began = true;
      const queryOnly = this.database.prepare(queryOnlyStatement).get() as
        | { query_only?: unknown }
        | undefined;
      if (queryOnly?.query_only !== 1) {
        return fail("AUDIT_WITNESS_DATABASE_SQLITE_QUERY_ONLY_REQUIRED");
      }

      const preflightRows = this.database
        .prepare(preflightStatement)
        .all(request.maximumRows + 1) as PreflightRow[];
      if (preflightRows.length > request.maximumRows) {
        return fail("AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE");
      }

      let projectedBytes = fixedJsonArrayBytes;
      for (const row of preflightRows) {
        if (
          row.sequence_type !== "integer" ||
          typeof row.sequence !== "number" ||
          !Number.isSafeInteger(row.sequence) ||
          row.sequence < 1
        ) {
          return fail("AUDIT_WITNESS_DATABASE_SQLITE_ROW_INVALID");
        }
        projectedBytes += fixedJsonBytesPerRow;
        for (const column of textColumns) {
          const type = row[`${column}_type`];
          const byteLength = row[`${column}_bytes`];
          if (
            type !== "text" ||
            typeof byteLength !== "number" ||
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0
          ) {
            return fail("AUDIT_WITNESS_DATABASE_SQLITE_ROW_INVALID");
          }
          if (byteLength > AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES) {
            return fail("AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE");
          }
          projectedBytes += byteLength * maximumJsonExpansion;
          if (
            projectedBytes > AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES
          ) {
            return fail("AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE");
          }
        }
      }

      const rows = this.database
        .prepare(rowsStatement)
        .all(request.maximumRows + 1);
      if (rows.length !== preflightRows.length) {
        return fail("AUDIT_WITNESS_DATABASE_SQLITE_SNAPSHOT_INCOMPLETE");
      }
      const rowCount = rows.length;
      const first = rows.at(0) as { sequence?: unknown } | undefined;
      const last = rows.at(-1) as
        | { sequence?: unknown; event_hash?: unknown }
        | undefined;
      response = {
        metadata: {
          schemaVersion: 1,
          purpose: AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
          capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
          rowCount,
          minimumSequence: first?.sequence ?? 0,
          maximumSequence: last?.sequence ?? 0,
          headEventHash: last?.event_hash ?? AUDIT_HEAD_GENESIS_HASH
        },
        rows
      };
    } catch (error) {
      failure = isBoundaryError(error)
        ? error
        : new Error("AUDIT_WITNESS_DATABASE_SQLITE_READ_FAILED");
    } finally {
      if (began) {
        try {
          this.database.exec(rollbackReadTransaction);
        } catch {
          failure = new Error(
            "AUDIT_WITNESS_DATABASE_SQLITE_ROLLBACK_FAILED"
          );
        }
      }
    }

    if (failure !== null) throw failure;
    if (this.database.isTransaction) {
      return fail("AUDIT_WITNESS_DATABASE_SQLITE_ROLLBACK_FAILED");
    }
    return response;
  }
}
