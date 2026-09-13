import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const purpose = "project15.audit-witness-sqlite-reader-source-receipt.v1";
const claim = "historical-rewrite-detection-only";
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

class AuditWitnessSqliteSourceError extends Error {}

function fail(code) {
  throw new AuditWitnessSqliteSourceError(code);
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
  return fail("AUDIT_WITNESS_SQLITE_SOURCE_VALUE_INVALID");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function runGit(root, args, code) {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    shell: false
  });
  if (result.status !== 0 || result.signal !== null) return fail(code);
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
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_FAILED");
  }
  const blob = result.stdout.trim();
  if (!/^[a-f0-9]{40}$/.test(blob)) {
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_BLOB_INVALID");
  }
  return blob;
}

function readCommittedBlob(root, commit, path) {
  const blob = runGit(
    root,
    ["rev-parse", "--verify", `${commit}:${path}`],
    "AUDIT_WITNESS_SQLITE_SOURCE_GIT_FAILED"
  );
  if (!/^[a-f0-9]{40}$/.test(blob)) {
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_BLOB_INVALID");
  }
  return blob;
}

function readGitState(root) {
  const commit = runGit(root, ["rev-parse", "--verify", "HEAD"], "AUDIT_WITNESS_SQLITE_SOURCE_GIT_FAILED");
  if (!/^[a-f0-9]{40}$/.test(commit)) {
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_COMMIT_INVALID");
  }
  const status = runGit(
    root,
    ["status", "--porcelain=v1", "--untracked-files=all"],
    "AUDIT_WITNESS_SQLITE_SOURCE_GIT_FAILED"
  );
  if (status !== "") return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_DIRTY");
  return commit;
}

async function readFixedSources(root, commit) {
  const rootReal = await realpath(root);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const files = [];
  let totalBytes = 0;
  for (const path of sourceFiles) {
    const expected = resolve(rootReal, ...path.split("/"));
    const entry = await lstat(expected).catch(() => fail("AUDIT_WITNESS_SQLITE_SOURCE_FILE_INVALID"));
    if (!entry.isFile() || entry.isSymbolicLink()) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_FILE_INVALID");
    }
    const actual = await realpath(expected).catch(() => fail("AUDIT_WITNESS_SQLITE_SOURCE_FILE_INVALID"));
    if (actual !== expected || relative(rootReal, actual).split("\\").includes("..")) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_FILE_INVALID");
    }
    if (entry.size > maximumFileBytes) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_TOO_LARGE");
    }
    totalBytes += entry.size;
    if (totalBytes > maximumTotalBytes) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_TOO_LARGE");
    }
    const bytes = await readFile(actual);
    if (bytes.length !== entry.size) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_FILE_CHANGED");
    }
    try {
      decoder.decode(bytes);
    } catch {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_UTF8_INVALID");
    }
    if (hashGitBlob(rootReal, path, bytes) !== readCommittedBlob(rootReal, commit, path)) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_HEAD_BLOB_MISMATCH");
    }
    files.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
  }
  return { files, totalBytes };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !["plan", "build"].includes(args[0])) {
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_COMMAND_INVALID");
  }
  const command = args[0];
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const beforeCommit = readGitState(root);

  if (command === "plan") {
    const afterCommit = readGitState(root);
    if (afterCommit !== beforeCommit) {
      return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_CHANGED");
    }
    process.stdout.write(`${canonicalJson({
      schemaVersion: 1,
      command: "plan",
      purpose,
      claim,
      sourceCommit: beforeCommit,
      sourceFiles,
      maximumFileBytes,
      maximumTotalBytes,
      writesFiles: false,
      boundaries
    })}\n`);
    return;
  }

  const { files, totalBytes } = await readFixedSources(root, beforeCommit);
  const afterCommit = readGitState(root);
  if (afterCommit !== beforeCommit) {
    return fail("AUDIT_WITNESS_SQLITE_SOURCE_GIT_CHANGED");
  }
  const receipt = {
    schemaVersion: 1,
    purpose,
    claim,
    sourceCommit: beforeCommit,
    sourceSetSha256: sha256(canonicalJson(files)),
    files,
    totalBytes,
    boundaries
  };
  const envelope = {
    receipt,
    seal: {
      algorithm: "sha256",
      receiptSha256: sha256(canonicalJson(receipt))
    }
  };
  process.stdout.write(`${canonicalJson(envelope)}\n`);
}

main().catch((error) => {
  const message =
    error instanceof AuditWitnessSqliteSourceError
      ? error.message
      : "AUDIT_WITNESS_SQLITE_SOURCE_BUILD_FAILED";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
