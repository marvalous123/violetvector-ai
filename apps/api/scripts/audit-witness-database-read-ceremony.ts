import { createHash, randomUUID } from "node:crypto";
import { lstatSync, realpathSync, type Stats } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { constants, DatabaseSync } from "node:sqlite";
import { stableJson } from "../src/domain/stable-json.js";
import { acquireAuditWitnessDatabaseHeadV1 } from "../src/services/audit-witness-database-read-adapter.js";
import { UnwiredAuditWitnessSqliteReaderV1 } from "../src/services/audit-witness-sqlite-reader.js";

const purpose = "project15.audit-witness-database-read-ceremony.v1";
const claim = "database-self-consistency-observation-only";
const acknowledgement =
  "I_ACKNOWLEDGE_PROJECT15_DATABASE_SELF_CONSISTENCY_READ_ONCE";
const maximumReceiptBytes = 16_384;
const databaseDirectoryName = ".war-room-project15";
const databaseFileName = "war-room.sqlite";
const allowedColumns = new Set([
  "sequence",
  "id",
  "occurred_at",
  "event_type",
  "payload_json",
  "previous_hash",
  "event_hash"
]);
const boundaries = Object.freeze({
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
});

type DatabaseOptions = NonNullable<
  ConstructorParameters<typeof DatabaseSync>[1]
>;

export type AuditWitnessDatabaseReadCeremonyDependencies = Readonly<{
  platform: string;
  dataRootOverride: string | undefined;
  environmentHome: string;
  trustedHome: string;
  lstat(path: string): Stats;
  realpath(path: string): string;
  openDatabase(path: string, options: DatabaseOptions): DatabaseSync;
  now(): Date;
  randomUuid(): string;
}>;

const systemDependencies: AuditWitnessDatabaseReadCeremonyDependencies = {
  platform: process.platform,
  dataRootOverride: process.env.WAR_ROOM_DATA_ROOT,
  environmentHome: resolve(homedir()),
  trustedHome: resolve(userInfo().homedir),
  lstat: lstatSync,
  realpath: realpathSync.native,
  openDatabase: (path, options) => new DatabaseSync(path, options),
  now: () => new Date(),
  randomUuid: randomUUID
};

class AuditWitnessDatabaseReadCeremonyError extends Error {}

function fail(code: string): never {
  throw new AuditWitnessDatabaseReadCeremonyError(code);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseCommand(args: readonly string[]):
  | Readonly<{ command: "plan" }>
  | Readonly<{ command: "read-once"; sourceReceiptSha256: string }> {
  if (args.length === 1 && args[0] === "plan") return { command: "plan" };
  if (
    args.length === 5 &&
    args[0] === "read-once" &&
    args[1] === "--ack" &&
    args[2] === acknowledgement &&
    args[3] === "--source-receipt-sha256" &&
    /^[a-f0-9]{64}$/.test(args[4] ?? "")
  ) {
    return { command: "read-once", sourceReceiptSha256: args[4]! };
  }
  return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_COMMAND_INVALID");
}

function validateEnvironment(
  dependencies: AuditWitnessDatabaseReadCeremonyDependencies
): void {
  if (dependencies.platform !== "win32") {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_WINDOWS_REQUIRED");
  }
  if (dependencies.dataRootOverride !== undefined) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_DATA_ROOT_OVERRIDE_INVALID");
  }
  if (dependencies.environmentHome !== dependencies.trustedHome) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_HOME_MISMATCH");
  }
}

function fixedDatabasePath(
  dependencies: AuditWitnessDatabaseReadCeremonyDependencies
): string {
  const root = join(dependencies.trustedHome, databaseDirectoryName);
  const databasePath = join(root, databaseFileName);
  let rootEntry: Stats;
  let databaseEntry: Stats;
  try {
    rootEntry = dependencies.lstat(root);
    databaseEntry = dependencies.lstat(databasePath);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID");
  }
  if (
    !rootEntry.isDirectory() ||
    rootEntry.isSymbolicLink() ||
    !databaseEntry.isFile() ||
    databaseEntry.isSymbolicLink() ||
    databaseEntry.nlink !== 1 ||
    databaseEntry.size <= 0
  ) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID");
  }
  let rootReal: string;
  let databaseReal: string;
  try {
    rootReal = dependencies.realpath(root);
    databaseReal = dependencies.realpath(databasePath);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID");
  }
  if (
    rootReal !== root ||
    databaseReal !== databasePath ||
    dirname(databaseReal) !== rootReal
  ) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_FILE_SHAPE_INVALID");
  }
  return databasePath;
}

export function authorizeAuditWitnessDatabaseReadV1(
  actionCode: number,
  arg1: string | null,
  arg2: string | null,
  databaseName: string | null,
  triggerOrView: string | null
): number {
  if (
    actionCode === constants.SQLITE_SELECT &&
    arg1 === null &&
    arg2 === null &&
    databaseName === null &&
    triggerOrView === null
  ) {
    return constants.SQLITE_OK;
  }
  if (
    actionCode === constants.SQLITE_READ &&
    arg1 === "audit_events" &&
    arg2 !== null &&
    allowedColumns.has(arg2) &&
    databaseName === "main" &&
    triggerOrView === null
  ) {
    return constants.SQLITE_OK;
  }
  if (
    actionCode === constants.SQLITE_FUNCTION &&
    arg1 === null &&
    (arg2 === "typeof" || arg2 === "length") &&
    databaseName === null &&
    triggerOrView === null
  ) {
    return constants.SQLITE_OK;
  }
  if (
    actionCode === constants.SQLITE_TRANSACTION &&
    (arg1 === "BEGIN" || arg1 === "ROLLBACK") &&
    arg2 === null &&
    databaseName === null &&
    triggerOrView === null
  ) {
    return constants.SQLITE_OK;
  }
  if (
    actionCode === constants.SQLITE_PRAGMA &&
    arg1 === "query_only" &&
    arg2 === null &&
    databaseName === null &&
    triggerOrView === null
  ) {
    return constants.SQLITE_OK;
  }
  return constants.SQLITE_DENY;
}

function observeDatabase(
  databasePath: string,
  dependencies: AuditWitnessDatabaseReadCeremonyDependencies
) {
  let database: DatabaseSync | undefined;
  let failure: Error | null = null;
  let observation:
    | ReturnType<typeof acquireAuditWitnessDatabaseHeadV1>
    | undefined;
  try {
    database = dependencies.openDatabase(databasePath, {
      readOnly: true,
      timeout: 1000,
      allowExtension: false
    });
    database.enableDefensive(true);
    database.exec("PRAGMA query_only = ON");
    database.setAuthorizer(authorizeAuditWitnessDatabaseReadV1);
    observation = acquireAuditWitnessDatabaseHeadV1(
      new UnwiredAuditWitnessSqliteReaderV1(database)
    );
  } catch {
    failure = new Error("AUDIT_WITNESS_DATABASE_READ_CEREMONY_READ_FAILED");
  } finally {
    if (database?.isOpen) {
      try {
        database.close();
      } catch {
        failure = new Error("AUDIT_WITNESS_DATABASE_READ_CEREMONY_CLOSE_FAILED");
      }
    }
  }
  if (failure !== null) throw failure;
  if (observation === undefined) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_READ_FAILED");
  }
  return observation;
}

export function executeAuditWitnessDatabaseReadCeremonyV1(
  args: readonly string[],
  dependencies: AuditWitnessDatabaseReadCeremonyDependencies = systemDependencies
): unknown {
  const parsed = parseCommand(args);
  validateEnvironment(dependencies);
  if (parsed.command === "plan") {
    return {
      schemaVersion: 1,
      command: "plan",
      purpose,
      claim,
      acknowledgement,
      sourceReceiptSha256Required: true,
      databaseLocation: "fixed-windows-os-user-profile",
      maximumReceiptBytes,
      boundaries
    };
  }

  const startedAtUtc = dependencies.now().toISOString();
  const observation = observeDatabase(
    fixedDatabasePath(dependencies),
    dependencies
  );
  const completedAtUtc = dependencies.now().toISOString();
  const receipt = {
    schemaVersion: 1,
    purpose,
    claim,
    ceremonyId: dependencies.randomUuid(),
    startedAtUtc,
    completedAtUtc,
    sourceReceiptSha256: parsed.sourceReceiptSha256,
    status:
      observation.status === "ready" ? "observed-ready" : "observed-empty",
    rowsVerified: observation.rowsVerified,
    databaseHeadSequence: observation.databaseHeadSequence,
    databaseHeadEventHash: observation.databaseHeadEventHash,
    verifiedPrefixSha256: observation.verifiedPrefixSha256,
    boundaries
  };
  return {
    receipt,
    seal: {
      algorithm: "sha256",
      receiptSha256: sha256(stableJson(receipt))
    }
  };
}

function writeCanonical(value: unknown): void {
  const serialized = stableJson(value);
  if (Buffer.byteLength(serialized, "utf8") > maximumReceiptBytes) {
    return fail("AUDIT_WITNESS_DATABASE_READ_CEREMONY_RECEIPT_TOO_LARGE");
  }
  process.stdout.write(`${serialized}\n`);
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    writeCanonical(
      executeAuditWitnessDatabaseReadCeremonyV1(process.argv.slice(2))
    );
  } catch (error) {
    const message =
      error instanceof AuditWitnessDatabaseReadCeremonyError
        ? error.message
        : error instanceof Error &&
            error.message.startsWith("AUDIT_WITNESS_DATABASE_READ_CEREMONY_")
          ? error.message
          : "AUDIT_WITNESS_DATABASE_READ_CEREMONY_FAILED";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
