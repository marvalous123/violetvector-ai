import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { sha256, stableJson } from "../domain/stable-json.js";
import { AUDIT_HEAD_GENESIS_HASH } from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_WITNESS_DATABASE_READ_REQUEST_V1,
  acquireAuditWitnessDatabaseHeadV1
} from "./audit-witness-database-read-adapter.js";
import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES
} from "./audit-witness-database-head.js";
import {
  AUDIT_WITNESS_SQLITE_READER_RUNTIME_WIRING_ENABLED,
  UnwiredAuditWitnessSqliteReaderV1
} from "./audit-witness-sqlite-reader.js";

function databaseWithOneRow(queryOnly = true): DatabaseSync {
  const database = new DatabaseSync(":memory:");
  database.exec(`CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
  )`);
  const occurredAt = "2026-08-22T20:00:00.000Z";
  const eventType = "audit.sqlite-reader.test";
  const payloadJson = stableJson({ fixture: true });
  const eventHash = sha256(
    `${AUDIT_HEAD_GENESIS_HASH}\n${occurredAt}\n${eventType}\n${payloadJson}`
  );
  database
    .prepare(`INSERT INTO audit_events (
      id, occurred_at, event_type, payload_json, previous_hash, event_hash
    ) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(
      randomUUID(),
      occurredAt,
      eventType,
      payloadJson,
      AUDIT_HEAD_GENESIS_HASH,
      eventHash
    );
  if (queryOnly) database.exec("PRAGMA query_only = ON");
  return database;
}

describe("unwired audit-witness SQLite reader", () => {
  it("reads one complete prefix inside a rolled-back query-only transaction", () => {
    const database = databaseWithOneRow();
    try {
      const result = acquireAuditWitnessDatabaseHeadV1(
        new UnwiredAuditWitnessSqliteReaderV1(database)
      );
      assert.equal(AUDIT_WITNESS_SQLITE_READER_RUNTIME_WIRING_ENABLED, false);
      assert.equal(result.status, "ready");
      assert.equal(result.rowsVerified, 1);
      assert.equal(database.isTransaction, false);
      assert.equal(
        (
          database.prepare("PRAGMA query_only").get() as {
            query_only: number;
          }
        ).query_only,
        1
      );
    } finally {
      database.close();
    }
  });

  it("requires SQLite query-only mode and rolls back after refusal", () => {
    const database = databaseWithOneRow(false);
    try {
      assert.throws(
        () =>
          new UnwiredAuditWitnessSqliteReaderV1(
            database
          ).readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_QUERY_ONLY_REQUIRED/
      );
      assert.equal(database.isTransaction, false);
    } finally {
      database.close();
    }
  });

  it("rejects caller-built requests and existing transactions", () => {
    const database = databaseWithOneRow();
    try {
      const reader = new UnwiredAuditWitnessSqliteReaderV1(database);
      assert.throws(
        () =>
          reader.readCompletePrefixSnapshot({
            ...AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          }),
        /AUDIT_WITNESS_DATABASE_SQLITE_REQUEST_INVALID/
      );
      database.exec("BEGIN DEFERRED");
      assert.throws(
        () =>
          reader.readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_CONNECTION_INVALID/
      );
      database.exec("ROLLBACK");
    } finally {
      database.close();
    }
  });

  it("fails before returning a prefix larger than the fixed ceiling", () => {
    const database = new DatabaseSync(":memory:");
    try {
      database.exec(`CREATE TABLE audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        occurred_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE
      )`);
      database.exec(`WITH RECURSIVE numbers(value) AS (
        SELECT 1
        UNION ALL
        SELECT value + 1 FROM numbers WHERE value < 4097
      )
      INSERT INTO audit_events (
        id, occurred_at, event_type, payload_json, previous_hash, event_hash
      )
      SELECT
        printf('00000000-0000-4000-8000-%012d', value),
        '2026-08-22T20:00:00.000Z',
        'audit.sqlite-reader.bound',
        '{}',
        printf('%064x', value - 1),
        printf('%064x', value)
      FROM numbers`);
      database.exec("PRAGMA query_only = ON");
      assert.throws(
        () =>
          new UnwiredAuditWitnessSqliteReaderV1(
            database
          ).readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE/
      );
      assert.equal(database.isTransaction, false);
    } finally {
      database.close();
    }
  });

  it("rejects an oversized text value before fetching full rows", () => {
    const database = databaseWithOneRow(false);
    try {
      database
        .prepare("UPDATE audit_events SET payload_json = ?")
        .run("x".repeat(AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_BYTES + 1));
      database.exec("PRAGMA query_only = ON");
      assert.throws(
        () =>
          new UnwiredAuditWitnessSqliteReaderV1(
            database
          ).readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_TOO_LARGE/
      );
      assert.equal(database.isTransaction, false);
    } finally {
      database.close();
    }
  });

  it("rolls back after a native preflight query failure", () => {
    const database = new DatabaseSync(":memory:");
    try {
      database.exec("PRAGMA query_only = ON");
      assert.throws(
        () =>
          new UnwiredAuditWitnessSqliteReaderV1(
            database
          ).readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_READ_FAILED/
      );
      assert.equal(database.isTransaction, false);
    } finally {
      database.close();
    }
  });

  it("fails closed when SQLite cannot roll back its read transaction", () => {
    const database = databaseWithOneRow();
    const originalExec = database.exec.bind(database);
    Object.defineProperty(database, "exec", {
      configurable: true,
      value(statement: string) {
        if (statement === "ROLLBACK") throw new Error("simulated rollback failure");
        return originalExec(statement);
      }
    });
    try {
      assert.throws(
        () =>
          new UnwiredAuditWitnessSqliteReaderV1(
            database
          ).readCompletePrefixSnapshot(
            AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
          ),
        /AUDIT_WITNESS_DATABASE_SQLITE_ROLLBACK_FAILED/
      );
      assert.equal(database.isTransaction, true);
    } finally {
      Object.defineProperty(database, "exec", {
        configurable: true,
        value: originalExec
      });
      if (database.isTransaction) database.exec("ROLLBACK");
      database.close();
    }
  });

  it("fails closed when the connection is closed", () => {
    const database = databaseWithOneRow();
    database.close();
    assert.throws(
      () =>
        new UnwiredAuditWitnessSqliteReaderV1(
          database
        ).readCompletePrefixSnapshot(
          AUDIT_WITNESS_DATABASE_READ_REQUEST_V1
        ),
      /AUDIT_WITNESS_DATABASE_SQLITE_CONNECTION_INVALID/
    );
  });
});
