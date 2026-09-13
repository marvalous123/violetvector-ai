import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const checker = join(
  root,
  "scripts",
  "check-audit-witness-database-read-ceremony-receipt.mjs"
);
const sourceReceiptSha256 = "a".repeat(64);
const boundaries = {
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

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function makeEnvelope(status = "observed-ready") {
  const empty = status === "observed-empty";
  const receipt = {
    schemaVersion: 1,
    purpose: "project15.audit-witness-database-read-ceremony.v1",
    claim: "database-self-consistency-observation-only",
    ceremonyId: "12345678-1234-4234-8234-123456789abc",
    startedAtUtc: "2026-08-22T20:00:00.000Z",
    completedAtUtc: "2026-08-22T20:00:01.000Z",
    sourceReceiptSha256,
    status,
    rowsVerified: empty ? 0 : 3,
    databaseHeadSequence: empty ? 0 : 3,
    databaseHeadEventHash: empty ? "0".repeat(64) : "b".repeat(64),
    verifiedPrefixSha256: empty ? sha256("[]") : "c".repeat(64),
    boundaries: structuredClone(boundaries)
  };
  return {
    receipt,
    seal: { algorithm: "sha256", receiptSha256: sha256(canonicalJson(receipt)) }
  };
}

function reseal(envelope) {
  envelope.seal.receiptSha256 = sha256(canonicalJson(envelope.receipt));
  return canonicalJson(envelope);
}

function invoke(text, options = {}) {
  const args =
    options.args ?? [
      "--expected-sha256",
      options.expectedSha256 ?? sha256(text),
      "--expected-source-receipt-sha256",
      options.expectedSourceReceiptSha256 ?? sourceReceiptSha256
    ];
  return spawnSync(process.execPath, [checker, ...args], {
    cwd: root,
    input: options.input ?? `${text}\n`,
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    maxBuffer: 1_048_576
  });
}

describe("audit-witness database-read ceremony receipt checker", () => {
  it("accepts exact ready and empty receipts over LF or CRLF transport", () => {
    const ready = canonicalJson(makeEnvelope());
    const readyResult = invoke(ready);
    assert.equal(readyResult.status, 0, readyResult.stderr);
    assert.equal(JSON.parse(readyResult.stdout).status, "observed-ready");

    const empty = canonicalJson(makeEnvelope("observed-empty"));
    const emptyResult = invoke(empty, { input: `${empty}\r\n` });
    assert.equal(emptyResult.status, 0, emptyResult.stderr);
    assert.equal(JSON.parse(emptyResult.stdout).rowsVerified, 0);
  });

  it("rejects external hash, source binding, embedded seal and strict schema drift", () => {
    const text = canonicalJson(makeEnvelope());
    assert.match(
      invoke(text, { expectedSha256: "0".repeat(64) }).stderr,
      /EXPECTED_HASH_MISMATCH/
    );
    assert.match(
      invoke(text, { expectedSourceReceiptSha256: "0".repeat(64) }).stderr,
      /SOURCE_RECEIPT_MISMATCH/
    );

    const badSeal = makeEnvelope();
    badSeal.seal.receiptSha256 = "0".repeat(64);
    assert.match(invoke(canonicalJson(badSeal)).stderr, /SEAL_INVALID/);

    const extra = makeEnvelope();
    extra.receipt.extra = false;
    assert.match(invoke(reseal(extra)).stderr, /SCHEMA_INVALID/);
  });

  it("rejects every authority flip, result drift and unsafe time windows", () => {
    for (const key of Object.keys(boundaries)) {
      const changed = makeEnvelope();
      changed.receipt.boundaries[key] = !changed.receipt.boundaries[key];
      assert.match(invoke(reseal(changed)).stderr, /BOUNDARY_INVALID/, key);
    }

    const badReady = makeEnvelope();
    badReady.receipt.databaseHeadSequence = 2;
    assert.match(invoke(reseal(badReady)).stderr, /RESULT_INVALID/);

    const badEmpty = makeEnvelope("observed-empty");
    badEmpty.receipt.databaseHeadEventHash = "b".repeat(64);
    assert.match(invoke(reseal(badEmpty)).stderr, /RESULT_INVALID/);

    const slow = makeEnvelope();
    slow.receipt.completedAtUtc = "2026-08-22T20:00:31.000Z";
    assert.match(invoke(reseal(slow)).stderr, /TIME_INVALID/);
  });

  it("rejects noncanonical, oversized and invalid-argument input", () => {
    const envelope = makeEnvelope();
    const pretty = JSON.stringify(envelope, null, 2);
    assert.match(invoke(pretty).stderr, /CANONICAL_INVALID/);

    const oversized = "x".repeat(16_385);
    assert.match(invoke(oversized).stderr, /RECEIPT_TOO_LARGE/);

    for (const args of [
      [],
      ["--expected-sha256", "ABC"],
      [
        "--expected-source-receipt-sha256",
        sourceReceiptSha256,
        "--expected-sha256",
        "0".repeat(64)
      ]
    ]) {
      assert.match(invoke("{}", { args }).stderr, /ARGUMENT_INVALID/);
    }
  });
});
