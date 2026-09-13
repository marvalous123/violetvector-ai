import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  rm,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceFiles = [
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
];
const expectedBoundaries = {
  runtimeWiringEnabled: false,
  databaseOpened: false,
  databaseRowsRead: 0,
  pathInputAccepted: false,
  signerExecuted: false,
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

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd,
    input: options.input,
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    maxBuffer: 16 * 1024 * 1024
  });
}

function git(root, args) {
  const result = run("git", args, { cwd: root });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), "project15-sqlite-receipt-"));
  for (const [index, path] of sourceFiles.entries()) {
    const target = join(root, ...path.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, `export const fixture${index} = ${index};\n`, "utf8");
  }
  for (const name of [
    "build-audit-witness-sqlite-reader-source-receipt.mjs",
    "check-audit-witness-sqlite-reader-source-receipt.mjs"
  ]) {
    await copyFile(join(projectRoot, "scripts", name), join(root, "scripts", name));
  }
  git(root, ["init", "--quiet"]);
  git(root, ["config", "user.email", "project15-test@example.invalid"]);
  git(root, ["config", "user.name", "Project 15 Test"]);
  git(root, ["add", "--all"]);
  git(root, ["commit", "--quiet", "-m", "fixture"]);
  return root;
}

function invokeBuilder(root, command, extraArgs = []) {
  return run(
    process.execPath,
    [join(root, "scripts", "build-audit-witness-sqlite-reader-source-receipt.mjs"), command, ...extraArgs],
    { cwd: root }
  );
}

function invokeChecker(root, text, expected = sha256(text), args = null) {
  return run(
    process.execPath,
    [
      join(root, "scripts", "check-audit-witness-sqlite-reader-source-receipt.mjs"),
      ...(args ?? ["--expected-sha256", expected])
    ],
    { cwd: root, input: `${text}\n` }
  );
}

function parseBuild(result) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /\n$/);
  const text = result.stdout.slice(0, -1);
  const envelope = JSON.parse(text);
  assert.equal(canonicalJson(envelope), text);
  return { text, envelope };
}

function reseal(envelope) {
  envelope.seal.receiptSha256 = sha256(canonicalJson(envelope.receipt));
  return canonicalJson(envelope);
}

describe("audit-witness SQLite reader source receipt", () => {
  let root;
  let validText;
  let validEnvelope;

  before(async () => {
    root = await createFixture();
    const built = parseBuild(invokeBuilder(root, "build"));
    validText = built.text;
    validEnvelope = built.envelope;
  });

  after(async () => {
    if (root) await rm(root, { recursive: true, force: true });
  });

  it("builds a canonical sealed fixed-fileset receipt and independently checks it", () => {
    assert.equal(sourceFiles.length, 24);
    assert.equal(validEnvelope.receipt.files.length, sourceFiles.length);
    assert.deepEqual(validEnvelope.receipt.files.map((file) => file.path), sourceFiles);
    assert.deepEqual(validEnvelope.receipt.files.slice(19, 21).map((file) => file.path), [
      "apps/api/src/services/audit-witness-contract.ts",
      "apps/api/src/services/audit-witness-contract.test.ts"
    ]);
    assert.deepEqual(validEnvelope.receipt.files.slice(0, 3).map((file) => file.path), [
      "scripts/build-audit-witness-sqlite-reader-source-receipt.mjs",
      "scripts/check-audit-witness-sqlite-reader-source-receipt.mjs",
      "scripts/audit-witness-sqlite-reader-source-receipt.test.mjs"
    ]);
    assert.deepEqual(validEnvelope.receipt.boundaries, expectedBoundaries);
    const checked = invokeChecker(root, validText);
    assert.equal(checked.status, 0, checked.stderr);
    const summary = JSON.parse(checked.stdout);
    assert.equal(summary.ok, true);
    assert.equal(summary.boundariesVerified, true);
    assert.equal(summary.fileCount, sourceFiles.length);
  });

  it("supports only exact plan and build commands", () => {
    const plan = invokeBuilder(root, "plan");
    assert.equal(plan.status, 0, plan.stderr);
    const planText = plan.stdout.slice(0, -1);
    assert.equal(canonicalJson(JSON.parse(planText)), planText);
    assert.equal(JSON.parse(planText).writesFiles, false);
    for (const args of [[], ["build", "extra"], ["BUILD"]]) {
      const result = run(
        process.execPath,
        [join(root, "scripts", "build-audit-witness-sqlite-reader-source-receipt.mjs"), ...args],
        { cwd: root }
      );
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /AUDIT_WITNESS_SQLITE_SOURCE_COMMAND_INVALID/);
    }
  });

  it("rejects expected-hash, seal and strict-schema tampering", () => {
    const wrongHash = invokeChecker(root, validText, "0".repeat(64));
    assert.notEqual(wrongHash.status, 0);
    assert.match(wrongHash.stderr, /EXPECTED_HASH_MISMATCH/);

    const sealTamper = structuredClone(validEnvelope);
    sealTamper.seal.receiptSha256 = "0".repeat(64);
    const sealText = canonicalJson(sealTamper);
    const sealed = invokeChecker(root, sealText);
    assert.notEqual(sealed.status, 0);
    assert.match(sealed.stderr, /RECEIPT_SEAL_INVALID/);

    const schemaTamper = structuredClone(validEnvelope);
    schemaTamper.receipt.extra = false;
    const schemaText = reseal(schemaTamper);
    const schema = invokeChecker(root, schemaText);
    assert.notEqual(schema.status, 0);
    assert.match(schema.stderr, /RECEIPT_SCHEMA_INVALID/);
  });

  it("rejects fileset, every boundary flip and real-file hash tampering", () => {
    const filesetTamper = structuredClone(validEnvelope);
    filesetTamper.receipt.files.reverse();
    filesetTamper.receipt.sourceSetSha256 = sha256(
      canonicalJson(filesetTamper.receipt.files)
    );
    const filesetText = reseal(filesetTamper);
    const fileset = invokeChecker(root, filesetText);
    assert.notEqual(fileset.status, 0);
    assert.match(fileset.stderr, /RECEIPT_FILESET_INVALID/);

    for (const [key, value] of Object.entries(expectedBoundaries)) {
      const boundaryTamper = structuredClone(validEnvelope);
      boundaryTamper.receipt.boundaries[key] =
        typeof value === "boolean" ? !value : value + 1;
      const boundaryText = reseal(boundaryTamper);
      const boundary = invokeChecker(root, boundaryText);
      assert.notEqual(boundary.status, 0, key);
      assert.match(boundary.stderr, /RECEIPT_BOUNDARY_INVALID/, key);
    }

    const hashTamper = structuredClone(validEnvelope);
    hashTamper.receipt.files[0].sha256 = "0".repeat(64);
    hashTamper.receipt.sourceSetSha256 = sha256(canonicalJson(hashTamper.receipt.files));
    const hashText = reseal(hashTamper);
    const hashResult = invokeChecker(root, hashText);
    assert.notEqual(hashResult.status, 0);
    assert.match(hashResult.stderr, /RECEIPT_FILE_HASH_MISMATCH/);
  });

  it("rejects noncanonical input, invalid arguments and oversized stdin", () => {
    const windowsPipeline = run(
      process.execPath,
      [
        join(root, "scripts", "check-audit-witness-sqlite-reader-source-receipt.mjs"),
        "--expected-sha256",
        sha256(validText)
      ],
      { cwd: root, input: `${validText}\r\n` }
    );
    assert.equal(windowsPipeline.status, 0, windowsPipeline.stderr);

    const pretty = JSON.stringify(validEnvelope, null, 2);
    const canonical = invokeChecker(root, pretty);
    assert.notEqual(canonical.status, 0);
    assert.match(canonical.stderr, /RECEIPT_CANONICAL_INVALID/);

    for (const args of [[], ["--expected-sha256", "ABC"], ["--other", "0".repeat(64)]]) {
      const result = invokeChecker(root, validText, undefined, args);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /RECEIPT_ARGUMENT_INVALID/);
    }

    const oversized = invokeChecker(root, "x".repeat(65_537));
    assert.notEqual(oversized.status, 0);
    assert.match(oversized.stderr, /RECEIPT_TOO_LARGE/);
  });

  it("fails closed on dirty Git state and per-file bounds", async () => {
    const boundedRoot = await createFixture();
    try {
      await writeFile(
        join(boundedRoot, ...sourceFiles[6].split("/")),
        "x".repeat(2_097_153),
        "utf8"
      );
      git(boundedRoot, ["add", "--all"]);
      git(boundedRoot, ["commit", "--quiet", "-m", "oversized"]);
      const oversized = invokeBuilder(boundedRoot, "build");
      assert.notEqual(oversized.status, 0);
      assert.match(oversized.stderr, /AUDIT_WITNESS_SQLITE_SOURCE_TOO_LARGE/);

      await writeFile(join(boundedRoot, "untracked.txt"), "dirty\n", "utf8");
      const dirty = invokeBuilder(boundedRoot, "plan");
      assert.notEqual(dirty.status, 0);
      assert.match(dirty.stderr, /AUDIT_WITNESS_SQLITE_SOURCE_GIT_DIRTY/);
    } finally {
      await rm(boundedRoot, { recursive: true, force: true });
    }
  });

  it("rejects assume-unchanged worktree bytes that do not match HEAD", async () => {
    const hiddenRoot = await createFixture();
    try {
      const hiddenPath = sourceFiles[6];
      const built = parseBuild(invokeBuilder(hiddenRoot, "build"));
      git(hiddenRoot, ["update-index", "--assume-unchanged", hiddenPath]);
      const hiddenText = "export const hiddenWorktreeChange = true;\n";
      await writeFile(
        join(hiddenRoot, ...hiddenPath.split("/")),
        hiddenText,
        "utf8"
      );
      assert.equal(git(hiddenRoot, ["status", "--porcelain=v1", "--untracked-files=all"]), "");

      const builder = invokeBuilder(hiddenRoot, "build");
      assert.notEqual(builder.status, 0);
      assert.match(builder.stderr, /AUDIT_WITNESS_SQLITE_SOURCE_HEAD_BLOB_MISMATCH/);

      const hiddenEnvelope = structuredClone(built.envelope);
      const previousBytes = hiddenEnvelope.receipt.files[6].bytes;
      hiddenEnvelope.receipt.files[6].bytes = Buffer.byteLength(hiddenText, "utf8");
      hiddenEnvelope.receipt.files[6].sha256 = sha256(hiddenText);
      hiddenEnvelope.receipt.totalBytes +=
        hiddenEnvelope.receipt.files[6].bytes - previousBytes;
      hiddenEnvelope.receipt.sourceSetSha256 = sha256(
        canonicalJson(hiddenEnvelope.receipt.files)
      );
      const checker = invokeChecker(hiddenRoot, reseal(hiddenEnvelope));
      assert.notEqual(checker.status, 0);
      assert.match(checker.stderr, /AUDIT_WITNESS_SQLITE_RECEIPT_HEAD_BLOB_MISMATCH/);
    } finally {
      await rm(hiddenRoot, { recursive: true, force: true });
    }
  });

  it("maps unexpected builder and checker failures to path-free stable codes", async () => {
    const failingRoot = await createFixture();
    try {
      const builderPath = join(
        failingRoot,
        "scripts",
        "build-audit-witness-sqlite-reader-source-receipt.mjs"
      );
      const builderSource = await import("node:fs/promises").then(({ readFile }) =>
        readFile(builderPath, "utf8")
      );
      await writeFile(
        builderPath,
        builderSource.replace(
          "async function main() {",
          'async function main() {\n  throw new Error("C:\\\\private\\\\builder-path");'
        ),
        "utf8"
      );
      const builder = invokeBuilder(failingRoot, "plan");
      assert.notEqual(builder.status, 0);
      assert.equal(builder.stderr, "AUDIT_WITNESS_SQLITE_SOURCE_BUILD_FAILED\n");

      const checkerPath = join(
        failingRoot,
        "scripts",
        "check-audit-witness-sqlite-reader-source-receipt.mjs"
      );
      const checkerSource = await import("node:fs/promises").then(({ readFile }) =>
        readFile(checkerPath, "utf8")
      );
      await writeFile(
        checkerPath,
        checkerSource.replace(
          "async function main() {",
          'async function main() {\n  throw new Error("C:\\\\private\\\\checker-path");'
        ),
        "utf8"
      );
      const checker = invokeChecker(failingRoot, validText);
      assert.notEqual(checker.status, 0);
      assert.equal(checker.stderr, "AUDIT_WITNESS_SQLITE_RECEIPT_CHECK_FAILED\n");
    } finally {
      await rm(failingRoot, { recursive: true, force: true });
    }
  });
});
