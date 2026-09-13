import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  realpathSync,
  writeSync,
  type Stats
} from "node:fs";
import {
  auditWitnessRecordV1Schema,
  serializeAuditWitnessRecordV1,
  type AuditWitnessRecordV1
} from "./audit-witness-contract.js";

export const AUDIT_WITNESS_APPEND_ROOT =
  "C:\\ProgramData\\Project15 Audit Head\\Witness" as const;
export const AUDIT_WITNESS_APPEND_PATH =
  `${AUDIT_WITNESS_APPEND_ROOT}\\audit-witness-v1.log` as const;
export const AUDIT_WITNESS_MAXIMUM_BYTES = 1_048_576 as const;

export type AuditWitnessAppendFileSystemV1 = Readonly<{
  lstat(path: string): Stats;
  realpath(path: string): string;
  open(path: string, flags: number): number;
  fstat(descriptor: number): Stats;
  write(descriptor: number, bytes: Uint8Array): number;
  fsync(descriptor: number): void;
  close(descriptor: number): void;
}>;

const nativeFileSystem: AuditWitnessAppendFileSystemV1 = {
  lstat: lstatSync,
  realpath: realpathSync.native,
  open: openSync,
  fstat: fstatSync,
  write: (descriptor, bytes) => writeSync(descriptor, bytes, 0, bytes.length),
  fsync: fsyncSync,
  close: closeSync
};

function fail(code: string): never {
  throw new Error(code);
}

function isSingleRegularFile(state: Stats): boolean {
  return (
    state.isFile() &&
    !state.isSymbolicLink() &&
    state.nlink === 1 &&
    state.size >= 0 &&
    state.size <= AUDIT_WITNESS_MAXIMUM_BYTES
  );
}

export function auditWitnessAppendFlagsV1(): number {
  const noFollow =
    "O_NOFOLLOW" in constants
      ? (constants as typeof constants & { O_NOFOLLOW: number }).O_NOFOLLOW
      : 0;
  return constants.O_APPEND | constants.O_WRONLY | constants.O_SYNC | noFollow;
}

export function appendAuditWitnessRecordV1(
  record: AuditWitnessRecordV1,
  fileSystem: AuditWitnessAppendFileSystemV1 = nativeFileSystem
): void {
  let parsed: AuditWitnessRecordV1;
  try {
    parsed = auditWitnessRecordV1Schema.parse(record);
  } catch {
    return fail("AUDIT_WITNESS_APPEND_RECORD_INVALID");
  }
  const bytes = serializeAuditWitnessRecordV1(parsed);
  if (bytes.byteLength > AUDIT_WITNESS_MAXIMUM_BYTES) {
    return fail("AUDIT_WITNESS_APPEND_RECORD_INVALID");
  }

  let pathState: Stats;
  try {
    pathState = fileSystem.lstat(AUDIT_WITNESS_APPEND_PATH);
    if (!isSingleRegularFile(pathState)) {
      return fail("AUDIT_WITNESS_APPEND_FILE_INVALID");
    }
    if (
      fileSystem.realpath(AUDIT_WITNESS_APPEND_PATH).toLowerCase() !==
      AUDIT_WITNESS_APPEND_PATH.toLowerCase()
    ) {
      return fail("AUDIT_WITNESS_APPEND_FILE_INVALID");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("AUDIT_WITNESS_")) {
      throw error;
    }
    return fail("AUDIT_WITNESS_APPEND_FILE_INVALID");
  }

  let descriptor: number;
  try {
    descriptor = fileSystem.open(
      AUDIT_WITNESS_APPEND_PATH,
      auditWitnessAppendFlagsV1()
    );
  } catch {
    return fail("AUDIT_WITNESS_APPEND_OPEN_FAILED");
  }

  try {
    const before = fileSystem.fstat(descriptor);
    if (
      !isSingleRegularFile(before) ||
      before.dev !== pathState.dev ||
      before.ino !== pathState.ino ||
      before.size !== pathState.size ||
      before.size + bytes.byteLength > AUDIT_WITNESS_MAXIMUM_BYTES
    ) {
      return fail("AUDIT_WITNESS_APPEND_HANDLE_INVALID");
    }

    if (fileSystem.write(descriptor, bytes) !== bytes.byteLength) {
      return fail("AUDIT_WITNESS_APPEND_SHORT_WRITE");
    }
    fileSystem.fsync(descriptor);

    const after = fileSystem.fstat(descriptor);
    if (
      !isSingleRegularFile(after) ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size + bytes.byteLength
    ) {
      return fail("AUDIT_WITNESS_APPEND_POSTCONDITION_FAILED");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("AUDIT_WITNESS_")) {
      throw error;
    }
    return fail("AUDIT_WITNESS_APPEND_FAILED");
  } finally {
    fileSystem.close(descriptor);
  }
}
