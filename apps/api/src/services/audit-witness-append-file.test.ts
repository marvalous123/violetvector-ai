import assert from "node:assert/strict";
import { constants, type Stats } from "node:fs";
import { describe, it } from "node:test";
import {
  appendAuditWitnessRecordV1,
  AUDIT_WITNESS_APPEND_PATH,
  auditWitnessAppendFlagsV1,
  type AuditWitnessAppendFileSystemV1
} from "./audit-witness-append-file.js";
import {
  createAuditWitnessGenesisStateV1,
  createAuditWitnessPrepareV1
} from "./audit-witness-contract.js";

function record() {
  return createAuditWitnessPrepareV1({
    currentState: createAuditWitnessGenesisStateV1("a".repeat(64)),
    eventHash: "b".repeat(64),
    occurredAtUtc: "2026-08-22T13:00:00.000Z"
  });
}

function state(overrides: Partial<Stats> = {}): Stats {
  return {
    dev: 7,
    ino: 11,
    nlink: 1,
    size: 0,
    isFile: () => true,
    isSymbolicLink: () => false,
    ...overrides
  } as Stats;
}

function fake(input: {
  shortWrite?: boolean;
  pathState?: Stats;
  beforeState?: Stats;
  afterState?: Stats;
  realpath?: string;
}) {
  const calls: string[] = [];
  let written = 0;
  const pathState = input.pathState ?? state();
  const before = input.beforeState ?? state();
  const fileSystem: AuditWitnessAppendFileSystemV1 = {
    lstat: (path) => {
      calls.push(`lstat:${path}`);
      return pathState;
    },
    realpath: (path) => {
      calls.push(`realpath:${path}`);
      return input.realpath ?? AUDIT_WITNESS_APPEND_PATH;
    },
    open: (path, flags) => {
      calls.push(`open:${path}:${flags}`);
      return 19;
    },
    fstat: () => {
      calls.push("fstat");
      return written === 0
        ? before
        : input.afterState ?? state({ size: written });
    },
    write: (descriptor, bytes) => {
      calls.push(`write:${descriptor}`);
      written = input.shortWrite ? bytes.length - 1 : bytes.length;
      return written;
    },
    fsync: (descriptor) => calls.push(`fsync:${descriptor}`),
    close: (descriptor) => calls.push(`close:${descriptor}`)
  };
  return { calls, fileSystem };
}

describe("protected audit-witness append handle", () => {
  it("opens only the fixed existing file and durably appends one whole record", () => {
    const fixture = fake({});
    appendAuditWitnessRecordV1(record(), fixture.fileSystem);
    assert.deepEqual(fixture.calls.map((call) => call.split(":")[0]), [
      "lstat",
      "realpath",
      "open",
      "fstat",
      "write",
      "fsync",
      "fstat",
      "close"
    ]);
    assert.ok(
      fixture.calls.includes(
        `open:${AUDIT_WITNESS_APPEND_PATH}:${auditWitnessAppendFlagsV1()}`
      )
    );
    assert.equal(auditWitnessAppendFlagsV1() & constants.O_APPEND, constants.O_APPEND);
    assert.equal(auditWitnessAppendFlagsV1() & constants.O_WRONLY, constants.O_WRONLY);
    assert.equal(auditWitnessAppendFlagsV1() & constants.O_TRUNC, 0);
    assert.equal(auditWitnessAppendFlagsV1() & constants.O_CREAT, 0);
  });

  it("fails closed on alias, replacement, hardlink, short write and growth drift", () => {
    const cases: Array<[ReturnType<typeof fake>, RegExp]> = [
      [fake({ realpath: `${AUDIT_WITNESS_APPEND_PATH}.alias` }), /APPEND_FILE_INVALID/],
      [fake({ pathState: state({ nlink: 2 }) }), /APPEND_FILE_INVALID/],
      [fake({ beforeState: state({ ino: 12 }) }), /APPEND_HANDLE_INVALID/],
      [fake({ shortWrite: true }), /APPEND_SHORT_WRITE/],
      [fake({ afterState: state({ size: 9999 }) }), /APPEND_POSTCONDITION_FAILED/]
    ];
    for (const [fixture, expected] of cases) {
      assert.throws(
        () => appendAuditWitnessRecordV1(record(), fixture.fileSystem),
        expected
      );
    }
  });
});
