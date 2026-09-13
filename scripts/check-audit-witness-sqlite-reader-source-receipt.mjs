import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const purpose = "project15.audit-witness-sqlite-reader-source-receipt.v1";
const claim = "historical-rewrite-detection-only";
const maximumReceiptBytes = 65_536;
const maximumFileBytes = 2_097_152;
const maximumTotalBytes = 8_388_608;
const sourceFiles = Object.freeze([
  "scripts/build-audit-witness-sqlite-reader-source-receipt.mjs",
  "scripts/check-audit-witness-sqlite-reader-source-receipt.mjs",
  "scripts/audit-witness-sqlite-reader-source-receipt.test.mjs",
  "scripts/check-audit-witness-database-read-ceremony-receipt.mjs",
  "scripts/audit-witness-database-read-ceremony-receipt.test.mjs",
  "package.json",
  "package-lock.json",
  "apps/api/package.json",
  "apps/api/scripts/audit-witness-database-read-ceremony.ts",
  "apps/api/scripts/audit-witness-database-read-ceremony.test.ts",
  "apps/api/src/domain/stable-json.ts",
  "apps/api/src/services/audit-head-checkpoint-contract.ts",
  "apps/api/src/services/audit-head-checkpoint-proof.ts",
  "apps/api/src/services/audit-witness-database-head.ts",
  "apps/api/src/services/audit-witness-database-head.test.ts",
  "apps/api/src/services/audit-witness-database-read-adapter.ts",
  "apps/api/src/services/audit-witness-database-read-adapter.test.ts",
  "apps/api/src/services/audit-witness-sqlite-reader.ts",
  "apps/api/src/services/audit-witness-sqlite-reader.test.ts",
  "apps/api/src/services/audit-witness-contract.ts",
  "apps/api/src/services/audit-witness-contract.test.ts",
  "apps/api/src/services/audit-witness-bootstrap.ts",
  "apps/api/src/services/audit-witness-bootstrap.test.ts",
  "scripts/verify.ps1"
]);
const boundaries = Object.freeze({
  runtimeWiringEnabled: false,
  databaseOpened: false,
  databaseRowsRead: 0,
  pathInputAccepted: false,
  signerExecuted: false,
  serviceMutated: false,
  ipcEnabled: false,
  telemetryEnabled: false,
  transportEnabled: false,
  commandChannelEnabled: false,
});

class AuditWitnessSqliteReceiptError extends Error {}

function fail(code) {
  throw new AuditWitnessSqliteReceiptError(code);
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
  return fail("AUDIT_WITNESS_SQLITE_RECEIPT_VALUE_INVALID");
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

function runGit(root, args) {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    shell: false
  });
  if (result.status !== 0 || result.signal !== null) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_FAILED");
  }
  return result.stdout.trim();
}

function hashGitBlob(root, path, bytes) {
  const result = spawnSync("git", ["hash-object", "--stdin", "--path", path], {
    cwd: root,
    input: bytes,
    encoding: "utf8",
    windowsHide: true,
    shell: false
  });
  if (result.status !== 0 || result.signal !== null) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_FAILED");
  }
  const blob = result.stdout.trim();
  if (!/^[a-f0-9]{40}$/.test(blob)) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_BLOB_INVALID");
  }
  return blob;
}

function readCommittedBlob(root, commit, path) {
  const blob = runGit(root, ["rev-parse", "--verify", `${commit}:${path}`]);
  if (!/^[a-f0-9]{40}$/.test(blob)) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_BLOB_INVALID");
  }
  return blob;
}

function readGitState(root) {
  const commit = runGit(root, ["rev-parse", "--verify", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(commit)) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_COMMIT_INVALID");
  }
  if (
    runGit(root, ["status", "--porcelain=v1", "--untracked-files=all"]) !== ""
  ) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_DIRTY");
  }
  return commit;
}

async function readStandardInput() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > maximumReceiptBytes) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_TOO_LARGE");
    }
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, length);
  if (bytes.length === 0) return fail("AUDIT_WITNESS_SQLITE_RECEIPT_INPUT_INVALID");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_UTF8_INVALID");
  }
  if (text.endsWith("\r\n")) {
    text = text.slice(0, -2);
  } else if (text.endsWith("\n")) {
    text = text.slice(0, -1);
  }
  if (text.length === 0 || text.includes("\r") || text.endsWith("\n")) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_CANONICAL_INVALID");
  }
  return text;
}

function parseEnvelope(text, expectedSha256) {
  if (sha256(text) !== expectedSha256) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_EXPECTED_HASH_MISMATCH");
  }
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_SCHEMA_INVALID");
  }
  if (canonicalJson(envelope) !== text) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_CANONICAL_INVALID");
  }
  if (!hasExactKeys(envelope, ["receipt", "seal"])) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_SCHEMA_INVALID");
  }
  const { receipt, seal } = envelope;
  if (
    !hasExactKeys(seal, ["algorithm", "receiptSha256"]) ||
    seal.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(seal.receiptSha256 ?? "") ||
    seal.receiptSha256 !== sha256(canonicalJson(receipt))
  ) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_SEAL_INVALID");
  }
  if (
    !hasExactKeys(receipt, [
      "schemaVersion",
      "purpose",
      "claim",
      "sourceCommit",
      "sourceSetSha256",
      "files",
      "totalBytes",
      "boundaries"
    ]) ||
    receipt.schemaVersion !== 1 ||
    receipt.purpose !== purpose ||
    receipt.claim !== claim ||
    !/^[a-f0-9]{40}$/.test(receipt.sourceCommit ?? "") ||
    !/^[a-f0-9]{64}$/.test(receipt.sourceSetSha256 ?? "") ||
    !Number.isSafeInteger(receipt.totalBytes) ||
    receipt.totalBytes < 0 ||
    receipt.totalBytes > maximumTotalBytes
  ) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_SCHEMA_INVALID");
  }
  if (canonicalJson(receipt.boundaries) !== canonicalJson(boundaries)) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_BOUNDARY_INVALID");
  }
  if (!Array.isArray(receipt.files) || receipt.files.length !== sourceFiles.length) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILESET_INVALID");
  }
  let totalBytes = 0;
  for (let index = 0; index < sourceFiles.length; index += 1) {
    const file = receipt.files[index];
    if (
      !hasExactKeys(file, ["path", "bytes", "sha256"]) ||
      file.path !== sourceFiles[index] ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes < 0 ||
      file.bytes > maximumFileBytes ||
      !/^[a-f0-9]{64}$/.test(file.sha256 ?? "")
    ) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILESET_INVALID");
    }
    totalBytes += file.bytes;
    if (totalBytes > maximumTotalBytes) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_TOO_LARGE");
    }
  }
  if (
    totalBytes !== receipt.totalBytes ||
    sha256(canonicalJson(receipt.files)) !== receipt.sourceSetSha256
  ) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILESET_INVALID");
  }
  return receipt;
}

async function verifyFiles(root, receipt, commit) {
  const rootReal = await realpath(root);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (const expectedFile of receipt.files) {
    const expected = resolve(rootReal, ...expectedFile.path.split("/"));
    const entry = await lstat(expected).catch(() => fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILE_INVALID"));
    if (!entry.isFile() || entry.isSymbolicLink() || entry.size !== expectedFile.bytes) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILE_INVALID");
    }
    const actual = await realpath(expected).catch(() => fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILE_INVALID"));
    if (actual !== expected || relative(rootReal, actual).split("\\").includes("..")) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILE_INVALID");
    }
    const bytes = await readFile(actual);
    if (bytes.length !== expectedFile.bytes || sha256(bytes) !== expectedFile.sha256) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_FILE_HASH_MISMATCH");
    }
    if (
      hashGitBlob(rootReal, expectedFile.path, bytes) !==
      readCommittedBlob(rootReal, commit, expectedFile.path)
    ) {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_HEAD_BLOB_MISMATCH");
    }
    try {
      decoder.decode(bytes);
    } catch {
      return fail("AUDIT_WITNESS_SQLITE_RECEIPT_UTF8_INVALID");
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (
    args.length !== 2 ||
    args[0] !== "--expected-sha256" ||
    !/^[a-f0-9]{64}$/.test(args[1] ?? "")
  ) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_ARGUMENT_INVALID");
  }
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const text = await readStandardInput();
  const receipt = parseEnvelope(text, args[1]);
  const beforeCommit = readGitState(root);
  if (beforeCommit !== receipt.sourceCommit) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_COMMIT_MISMATCH");
  }
  await verifyFiles(root, receipt, beforeCommit);
  const afterCommit = readGitState(root);
  if (afterCommit !== beforeCommit) {
    return fail("AUDIT_WITNESS_SQLITE_RECEIPT_GIT_CHANGED");
  }
  process.stdout.write(`${canonicalJson({
    ok: true,
    purpose,
    claim,
    sourceCommit: receipt.sourceCommit,
    sourceSetSha256: receipt.sourceSetSha256,
    fileCount: receipt.files.length,
    totalBytes: receipt.totalBytes,
    boundariesVerified: true
  })}\n`);
}

main().catch((error) => {
  const message =
    error instanceof AuditWitnessSqliteReceiptError
      ? error.message
      : "AUDIT_WITNESS_SQLITE_RECEIPT_CHECK_FAILED";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
