import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { constants, DatabaseSync } from "node:sqlite";
import { afterEach, describe, it } from "node:test";
import { stableJson } from "../src/domain/stable-json.js";
import { AUDIT_HEAD_GENESIS_HASH } from "../src/services/audit-head-checkpoint-contract.js";
import {
  authorizeAuditWitnessDatabaseReadV1,
  executeAuditWitnessDatabaseReadCeremonyV1,
  type AuditWitnessDatabaseReadCeremonyDependencies
} from "./audit-witness-database-read-ceremony.js";

const acknowledgement =
  "I_ACKNOWLEDGE_PROJECT15_DATABASE_SELF_CONSISTENCY_READ_ONCE";
const sourceReceiptSha256 = "a".repeat(64);
const temporaryHomes: string[] = [];
const exactBoundaries = {
  authoritativeBootstrapCreated: false,
  protectedAnchorCompared: false,
  sourceReceiptVerifiedByCeremony: false,
  logicalAuditRowsWritten: false,
  sqliteSharedMemoryMayMutate: true,
  filesystemWriteFreeClaimed: false,
  witnessWritten: false,
  signerExecuted: false,
  runtimeWiringEnabled: false,
  serviceMutated: false,
  ipcEnabled: false,
  telemetryEnabled: false,
  transportEnabled: false,
  commandChannelEnabled: false
};

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function makeHome(): string {
  const home = mkdtempSync(join(tmpdir(), "project15-read-ceremony-"));
  temporaryHomes.push(home);
  return resolve(home);
}

function databasePath(home: string): string {
  return join(home, ".war-room-project15", "war-room.sqlite");
}

function createAuditTable(database: DatabaseSync): void {
  database.exec(`CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
  )`);
}

function insertValidRow(database: DatabaseSync): void {
  const occurredAt = "2026-08-22T20:00:00.000Z";
  const eventType = "audit.database-read-ceremony.test";
  const payloadJson = stableJson({ fixture: true });
  const eventHash = sha256(
    `${AUDIT_HEAD_GENESIS_HASH}\n${occurredAt}\n${eventType}\n${payloadJson}`
  );
  database
    .prepare(`INSERT INTO audit_events (
      id, occurred_at, event_type, payload_json, previous_hash, event_hash
    ) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(
      "12345678-1234-4234-8234-123456789abc",
      occurredAt,
      eventType,
      payloadJson,
      AUDIT_HEAD_GENESIS_HASH,
      eventHash
    );
}

function createDatabase(home: string, mode: "ready" | "empty" | "broken") {
  const path = databasePath(home);
  mkdirSync(dirname(path), { recursive: true });
  const database = new DatabaseSync(path);
  try {
    createAuditTable(database);
    if (mode !== "empty") {
      insertValidRow(database);
      if (mode === "broken") {
        database.exec("DROP TABLE audit_events");
        createAuditTable(database);
        database
          .prepare(`INSERT INTO audit_events (
            id, occurred_at, event_type, payload_json, previous_hash, event_hash
          ) VALUES (?, ?, ?, ?, ?, ?)`)
          .run(
            "12345678-1234-4234-8234-123456789abc",
            "2026-08-22T20:00:00.000Z",
            "audit.database-read-ceremony.test",
            stableJson({ fixture: true }),
            AUDIT_HEAD_GENESIS_HASH,
            "b".repeat(64)
          );
      }
    }
  } finally {
    database.close();
  }
  return path;
}

function dependencies(
  home: string,
  overrides: Partial<AuditWitnessDatabaseReadCeremonyDependencies> = {}
): AuditWitnessDatabaseReadCeremonyDependencies {
  const times = [
    new Date("2026-08-22T20:00:00.000Z"),
    new Date("2026-08-22T20:00:01.000Z")
  ];
  return {
    platform: "win32",
    dataRootOverride: undefined,
    environmentHome: home,
    trustedHome: home,
    lstat: lstatSync,
    realpath: realpathSync.native,
    openDatabase: (path, options) => new DatabaseSync(path, options),
    now: () => times.shift() ?? new Date("2026-08-22T20:00:01.000Z"),
    randomUuid: () => "12345678-1234-4234-8234-123456789abc",
    ...overrides
  };
}

function readOnceArgs(hash = sourceReceiptSha256): string[] {
  return [
    "read-once",
    "--ack",
    acknowledgement,
    "--source-receipt-sha256",
    hash
  ];
}

afterEach(() => {
  for (const home of temporaryHomes.splice(0)) {
    rmSync(home, { recursive: true, force: true });
  }
});

describe("audit-witness database read ceremony", () => {
  it("plans without opening or disclosing a database path", () => {
    const home = makeHome();
    let opens = 0;
    const plan = executeAuditWitnessDatabaseReadCeremonyV1(
      ["plan"],
      dependencies(home, {
        openDatabase: (path, options) => {
          opens += 1;
          return new DatabaseSync(path, options);
        }
      })
    ) as Record<string, unknown>;
    assert.equal(plan.command, "plan");
    assert.equal(plan.claim, "database-self-consistency-observation-only");
    assert.deepEqual(plan.boundaries, exactBoundaries);
    assert.equal(opens, 0);
    assert.doesNotMatch(stableJson(plan), /war-room\.sqlite|project15-read-ceremony/i);
  });

  it("emits a sealed ready observation with exact open options and closure", () => {
    const home = makeHome();
    const path = createDatabase(home, "ready");
    const beforeHash = sha256(readFileSync(path));
    let opens = 0;
    const envelope = executeAuditWitnessDatabaseReadCeremonyV1(
      readOnceArgs(),
      dependencies(home, {
        openDatabase: (openedPath, options) => {
          opens += 1;
          assert.equal(openedPath, path);
          assert.deepEqual(options, {
            readOnly: true,
            timeout: 1000,
            allowExtension: false
          });
          return new DatabaseSync(openedPath, options);
        }
      })
    ) as { receipt: Record<string, unknown>; seal: Record<string, unknown> };
    assert.equal(opens, 1);
    assert.equal(envelope.receipt.status, "observed-ready");
    assert.equal(envelope.receipt.rowsVerified, 1);
    assert.equal(envelope.receipt.databaseHeadSequence, 1);
    assert.equal(envelope.receipt.sourceReceiptSha256, sourceReceiptSha256);
    assert.deepEqual(envelope.receipt.boundaries, exactBoundaries);
    assert.equal(envelope.seal.algorithm, "sha256");
    assert.equal(envelope.seal.receiptSha256, sha256(stableJson(envelope.receipt)));
    assert.equal(sha256(readFileSync(path)), beforeHash);
    assert.doesNotMatch(
      stableJson(envelope),
      /audit\.database-read-ceremony|fixture|SELECT|war-room\.sqlite/i
    );
    const renamed = `${path}.closed`;
    renameSync(path, renamed);
    renameSync(renamed, path);
  });

  it("reports empty without bootstrap and discloses the WAL/SHM claim limit", () => {
    const home = makeHome();
    createDatabase(home, "empty");
    const envelope = executeAuditWitnessDatabaseReadCeremonyV1(
      readOnceArgs(),
      dependencies(home)
    ) as { receipt: Record<string, unknown> };
    assert.equal(envelope.receipt.status, "observed-empty");
    assert.equal(envelope.receipt.rowsVerified, 0);
    assert.equal(envelope.receipt.databaseHeadSequence, 0);
    assert.equal(envelope.receipt.databaseHeadEventHash, AUDIT_HEAD_GENESIS_HASH);
    assert.deepEqual(envelope.receipt.boundaries, exactBoundaries);
  });

  it("keeps logical rows and WAL bytes unchanged while acknowledging SHM mutation", () => {
    const home = makeHome();
    const path = databasePath(home);
    mkdirSync(dirname(path), { recursive: true });
    const writer = new DatabaseSync(path);
    try {
      writer.exec("PRAGMA journal_mode = WAL");
      writer.exec("PRAGMA wal_autocheckpoint = 0");
      createAuditTable(writer);
      insertValidRow(writer);
      const walPath = `${path}-wal`;
      const mainBefore = sha256(readFileSync(path));
      const walBefore = sha256(readFileSync(walPath));
      const envelope = executeAuditWitnessDatabaseReadCeremonyV1(
        readOnceArgs(),
        dependencies(home)
      ) as { receipt: { boundaries: Record<string, unknown>; rowsVerified: number } };
      assert.equal(envelope.receipt.rowsVerified, 1);
      assert.equal(sha256(readFileSync(path)), mainBefore);
      assert.equal(sha256(readFileSync(walPath)), walBefore);
      assert.equal(envelope.receipt.boundaries.logicalAuditRowsWritten, false);
      assert.equal(envelope.receipt.boundaries.sqliteSharedMemoryMayMutate, true);
      assert.equal(envelope.receipt.boundaries.filesystemWriteFreeClaimed, false);
    } finally {
      writer.close();
    }
  });

  it("requires exact arguments and a trusted OS home independent of environment", () => {
    const home = makeHome();
    for (const args of [
      ["read-once"],
      ["read-once", "--source-receipt-sha256", sourceReceiptSha256, "--ack", acknowledgement],
      ["read-once", "--ack", `${acknowledgement}!`, "--source-receipt-sha256", sourceReceiptSha256],
      readOnceArgs("A".repeat(64)),
      [...readOnceArgs(), "extra"],
      ["PLAN"]
    ]) {
      assert.throws(
        () => executeAuditWitnessDatabaseReadCeremonyV1(args, dependencies(home)),
        /AUDIT_WITNESS_DATABASE_READ_CEREMONY_COMMAND_INVALID/
      );
    }
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          ["plan"],
          dependencies(home, { environmentHome: resolve(home, "spoofed") })
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_HOME_MISMATCH/
    );
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          ["plan"],
          dependencies(home, { dataRootOverride: "C:\\untrusted" })
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_DATA_ROOT_OVERRIDE_INVALID/
    );
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          ["plan"],
          dependencies(home, { platform: "linux" })
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_WINDOWS_REQUIRED/
    );
  });

  it("rejects missing, directory and hardlinked fixed database shapes", () => {
    const missingHome = makeHome();
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          readOnceArgs(),
          dependencies(missingHome)
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID/
    );

    const rootFileHome = makeHome();
    writeFileSync(join(rootFileHome, ".war-room-project15"), "not a directory");
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          readOnceArgs(),
          dependencies(rootFileHome)
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID/
    );

    const directoryHome = makeHome();
    mkdirSync(databasePath(directoryHome), { recursive: true });
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          readOnceArgs(),
          dependencies(directoryHome)
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID/
    );

    const hardlinkHome = makeHome();
    const hardlinkPath = createDatabase(hardlinkHome, "empty");
    linkSync(hardlinkPath, `${hardlinkPath}.alias`);
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          readOnceArgs(),
          dependencies(hardlinkHome)
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID/
    );
  });

  it("fails closed on a broken chain and leaves the handle closed", () => {
    const home = makeHome();
    const path = createDatabase(home, "broken");
    const beforeHash = sha256(readFileSync(path));
    assert.throws(
      () =>
        executeAuditWitnessDatabaseReadCeremonyV1(
          readOnceArgs(),
          dependencies(home)
        ),
      /AUDIT_WITNESS_DATABASE_READ_CEREMONY_READ_FAILED/
    );
    assert.equal(sha256(readFileSync(path)), beforeHash);
    const renamed = `${path}.closed`;
    renameSync(path, renamed);
    renameSync(renamed, path);
  });

  it("authorizes only the exact reader operations", () => {
    assert.equal(
      authorizeAuditWitnessDatabaseReadV1(
        constants.SQLITE_SELECT,
        null,
        null,
        null,
        null
      ),
      constants.SQLITE_OK
    );
    for (const column of [
      "sequence",
      "id",
      "occurred_at",
      "event_type",
      "payload_json",
      "previous_hash",
      "event_hash"
    ]) {
      assert.equal(
        authorizeAuditWitnessDatabaseReadV1(
          constants.SQLITE_READ,
          "audit_events",
          column,
          "main",
          null
        ),
        constants.SQLITE_OK
      );
    }
    const deniedOperations: ReadonlyArray<
      readonly [number, string | null, string | null, string | null, string | null]
    > = [
      [constants.SQLITE_INSERT, "audit_events", null, "main", null],
      [constants.SQLITE_READ, "schema_migrations", "name", "main", null],
      [constants.SQLITE_READ, "audit_events", "secret", "main", null],
      [constants.SQLITE_FUNCTION, null, "load_extension", null, null],
      [constants.SQLITE_PRAGMA, "journal_mode", null, null, null],
      [constants.SQLITE_TRANSACTION, "COMMIT", null, null, null]
    ];
    for (const [action, arg1, arg2, databaseName, triggerOrView] of deniedOperations) {
      assert.equal(
        authorizeAuditWitnessDatabaseReadV1(
          action,
          arg1,
          arg2,
          databaseName,
          triggerOrView
        ),
        constants.SQLITE_DENY
      );
    }
  });
});
