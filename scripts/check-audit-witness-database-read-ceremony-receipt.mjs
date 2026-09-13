import { createHash } from "node:crypto";

const purpose = "project15.audit-witness-database-read-ceremony.v1";
const claim = "database-self-consistency-observation-only";
const maximumReceiptBytes = 16_384;
const maximumRows = 4096;
const maximumDurationMilliseconds = 30_000;
const genesisHash = "0".repeat(64);
const emptyPrefixSha256 = createHash("sha256").update("[]").digest("hex");
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

class AuditWitnessDatabaseCeremonyReceiptError extends Error {}

function fail(code) {
  throw new AuditWitnessDatabaseCeremonyReceiptError(code);
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_VALUE_INVALID");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function hasExactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

async function readStandardInput() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > maximumReceiptBytes) {
      return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_TOO_LARGE");
    }
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, length);
  if (bytes.length === 0) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_INPUT_INVALID");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_UTF8_INVALID");
  }
  if (text.endsWith("\r\n")) {
    text = text.slice(0, -2);
  } else if (text.endsWith("\n")) {
    text = text.slice(0, -1);
  }
  if (text.length === 0 || text.includes("\r") || text.endsWith("\n")) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_CANONICAL_INVALID");
  }
  return text;
}

function parseArguments(args) {
  if (
    args.length !== 4 ||
    args[0] !== "--expected-sha256" ||
    !/^[a-f0-9]{64}$/.test(args[1] ?? "") ||
    args[2] !== "--expected-source-receipt-sha256" ||
    !/^[a-f0-9]{64}$/.test(args[3] ?? "")
  ) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_ARGUMENT_INVALID");
  }
  return { expectedSha256: args[1], expectedSourceReceiptSha256: args[3] };
}

function parseTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_TIME_INVALID");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_TIME_INVALID");
  }
  return milliseconds;
}

function verifyEnvelope(text, expectedSha256, expectedSourceReceiptSha256) {
  if (sha256(text) !== expectedSha256) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_EXPECTED_HASH_MISMATCH");
  }
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_SCHEMA_INVALID");
  }
  if (canonicalJson(envelope) !== text) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_CANONICAL_INVALID");
  }
  if (!hasExactKeys(envelope, ["receipt", "seal"])) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_SCHEMA_INVALID");
  }
  const { receipt, seal } = envelope;
  if (
    !hasExactKeys(seal, ["algorithm", "receiptSha256"]) ||
    seal.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(seal.receiptSha256 ?? "") ||
    seal.receiptSha256 !== sha256(canonicalJson(receipt))
  ) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_SEAL_INVALID");
  }
  if (
    !hasExactKeys(receipt, [
      "schemaVersion",
      "purpose",
      "claim",
      "ceremonyId",
      "startedAtUtc",
      "completedAtUtc",
      "sourceReceiptSha256",
      "status",
      "rowsVerified",
      "databaseHeadSequence",
      "databaseHeadEventHash",
      "verifiedPrefixSha256",
      "boundaries"
    ]) ||
    receipt.schemaVersion !== 1 ||
    receipt.purpose !== purpose ||
    receipt.claim !== claim ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
      receipt.ceremonyId ?? ""
    ) ||
    !/^[a-f0-9]{64}$/.test(receipt.sourceReceiptSha256 ?? "") ||
    !["observed-empty", "observed-ready"].includes(receipt.status) ||
    !Number.isSafeInteger(receipt.rowsVerified) ||
    receipt.rowsVerified < 0 ||
    receipt.rowsVerified > maximumRows ||
    !Number.isSafeInteger(receipt.databaseHeadSequence) ||
    receipt.databaseHeadSequence < 0 ||
    !/^[a-f0-9]{64}$/.test(receipt.databaseHeadEventHash ?? "") ||
    !/^[a-f0-9]{64}$/.test(receipt.verifiedPrefixSha256 ?? "")
  ) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_SCHEMA_INVALID");
  }
  if (receipt.sourceReceiptSha256 !== expectedSourceReceiptSha256) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_SOURCE_RECEIPT_MISMATCH");
  }
  if (canonicalJson(receipt.boundaries) !== canonicalJson(boundaries)) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_BOUNDARY_INVALID");
  }
  const started = parseTimestamp(receipt.startedAtUtc);
  const completed = parseTimestamp(receipt.completedAtUtc);
  if (completed < started || completed - started > maximumDurationMilliseconds) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_TIME_INVALID");
  }
  if (receipt.status === "observed-empty") {
    if (
      receipt.rowsVerified !== 0 ||
      receipt.databaseHeadSequence !== 0 ||
      receipt.databaseHeadEventHash !== genesisHash ||
      receipt.verifiedPrefixSha256 !== emptyPrefixSha256
    ) {
      return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_RESULT_INVALID");
    }
  } else if (
    receipt.rowsVerified < 1 ||
    receipt.databaseHeadSequence !== receipt.rowsVerified ||
    receipt.databaseHeadEventHash === genesisHash
  ) {
    return fail("AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_RESULT_INVALID");
  }
  return receipt;
}

async function main() {
  const { expectedSha256, expectedSourceReceiptSha256 } = parseArguments(
    process.argv.slice(2)
  );
  const text = await readStandardInput();
  const receipt = verifyEnvelope(
    text,
    expectedSha256,
    expectedSourceReceiptSha256
  );
  process.stdout.write(`${canonicalJson({
    ok: true,
    purpose,
    claim,
    ceremonyId: receipt.ceremonyId,
    sourceReceiptSha256: receipt.sourceReceiptSha256,
    status: receipt.status,
    rowsVerified: receipt.rowsVerified,
    databaseHeadSequence: receipt.databaseHeadSequence,
    databaseHeadEventHash: receipt.databaseHeadEventHash,
    verifiedPrefixSha256: receipt.verifiedPrefixSha256,
    boundariesVerified: true
  })}\n`);
}

main().catch((error) => {
  const message =
    error instanceof AuditWitnessDatabaseCeremonyReceiptError
      ? error.message
      : "AUDIT_WITNESS_DATABASE_CEREMONY_RECEIPT_CHECK_FAILED";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
