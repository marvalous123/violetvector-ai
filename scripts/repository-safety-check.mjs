import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { extname, dirname, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const maximumTrackedFileBytes = 2 * 1024 * 1024;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const allowedSpecialPaths = new Set([
  ".env.example",
  "evidence/readme.md",
  "tools/.gitkeep"
]);

const forbiddenDirectoryNames = new Set([
  ".vite",
  "bin",
  "build",
  "coverage",
  "data",
  "dist",
  "logs",
  "node_modules",
  "obj",
  "secrets"
]);

const forbiddenExtensions = new Set([
  ".7z",
  ".bin",
  ".db",
  ".dll",
  ".dmp",
  ".exe",
  ".gz",
  ".har",
  ".key",
  ".log",
  ".msi",
  ".msix",
  ".p12",
  ".pcap",
  ".pcapng",
  ".pem",
  ".pfx",
  ".rar",
  ".sqlite",
  ".sqlite3",
  ".tar",
  ".tmp",
  ".zip"
]);

const allowedBinaryExtensions = new Set([
  ".gif",
  ".ico",
  ".jpeg",
  ".jpg",
  ".png",
  ".webp",
  ".woff",
  ".woff2"
]);

const secretPatterns = [
  {
    rule: "private-key-material",
    expression: new RegExp(["-----BEGIN ", "PRIVATE", " KEY-----"].join(""))
  },
  {
    rule: "rsa-private-key-material",
    expression: new RegExp(["-----BEGIN ", "RSA", " PRIVATE", " KEY-----"].join(""))
  },
  {
    rule: "ec-private-key-material",
    expression: new RegExp(["-----BEGIN ", "EC", " PRIVATE", " KEY-----"].join(""))
  },
  {
    rule: "openssh-private-key-material",
    expression: new RegExp(["-----BEGIN ", "OPENSSH", " PRIVATE", " KEY-----"].join(""))
  },
  {
    rule: "aws-access-key",
    expression: new RegExp(`${["A", "K", "I", "A"].join("")}[0-9A-Z]{16}`)
  },
  {
    rule: "aws-temporary-access-key",
    expression: new RegExp(`${["A", "S", "I", "A"].join("")}[0-9A-Z]{16}`)
  },
  {
    rule: "github-token",
    expression: new RegExp(`${["g", "h"].join("")}[pousr]_[A-Za-z0-9]{30,}`)
  },
  {
    rule: "github-fine-grained-token",
    expression: new RegExp(`${["github", "_pat_"].join("")}[A-Za-z0-9_]{30,}`)
  },
  {
    rule: "openai-api-key",
    expression: new RegExp(`(?<![A-Za-z0-9])${["s", "k", "-"].join("")}[A-Za-z0-9_-]{20,}`)
  },
  {
    rule: "google-api-key",
    expression: new RegExp(`${["A", "I", "z", "a"].join("")}[A-Za-z0-9_-]{30,}`)
  },
  {
    rule: "slack-token",
    expression: new RegExp(`${["x", "o", "x"].join("")}[baprs]-[A-Za-z0-9-]{20,}`)
  },
  {
    rule: "stripe-live-secret",
    expression: new RegExp(`(?<![A-Za-z0-9])${["s", "k", "_live", "_"].join("")}[A-Za-z0-9]{20,}`)
  },
  {
    rule: "npm-access-token",
    expression: new RegExp(`${["n", "p", "m", "_"].join("")}[A-Za-z0-9]{30,}`)
  }
];

function normalizeRepositoryPath(value) {
  return value.replaceAll("\\", "/").replace(/^\.\/+/, "");
}

function forbiddenArtifactRule(repositoryPath) {
  const normalized = normalizeRepositoryPath(repositoryPath);
  const lower = normalized.toLowerCase();
  if (allowedSpecialPaths.has(lower)) return undefined;

  const segments = lower.split("/");
  const basename = segments.at(-1) ?? "";
  if (basename === ".env" || basename.startsWith(".env.")) {
    return "environment-file";
  }
  if (lower.startsWith("evidence/")) return "raw-evidence-path";
  if (lower.startsWith("tools/")) return "tool-cache-path";
  if (lower.startsWith("reports/generated/")) return "generated-report-path";
  if (segments.some((segment) => forbiddenDirectoryNames.has(segment))) {
    return "generated-or-runtime-path";
  }
  if (forbiddenExtensions.has(extname(lower))) return "forbidden-artifact-extension";
  if (basename.endsWith(".db-shm") || basename.endsWith(".db-wal")) {
    return "runtime-database-sidecar";
  }
  return undefined;
}

function findSecretRules(text) {
  return secretPatterns
    .filter(({ expression }) => expression.test(text))
    .map(({ rule }) => rule);
}

function trackedEntries() {
  const result = spawnSync("git", ["ls-files", "--stage", "-z"], {
    cwd: projectRoot,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    windowsHide: true
  });
  if (result.error || result.status !== 0) {
    throw new Error("Unable to enumerate Git-tracked files");
  }

  return result.stdout
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const match = /^(\d{6}) [0-9a-f]+ (\d+)\t([\s\S]+)$/.exec(entry);
      if (!match) throw new Error("Git returned an unexpected tracked-file record");
      return {
        mode: match[1],
        stage: Number(match[2]),
        path: normalizeRepositoryPath(match[3])
      };
    });
}

function stagedContentPaths() {
  const result = spawnSync(
    "git",
    ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
    {
      cwd: projectRoot,
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      shell: false,
      windowsHide: true
    }
  );
  if (result.error || result.status !== 0) {
    throw new Error("Unable to enumerate staged Git content");
  }
  return new Set(
    result.stdout.split("\0").filter(Boolean).map(normalizeRepositoryPath)
  );
}

function readStagedBytes(repositoryPath) {
  const result = spawnSync("git", ["show", `:${repositoryPath}`], {
    cwd: projectRoot,
    encoding: "buffer",
    maxBuffer: maximumTrackedFileBytes + 1,
    shell: false,
    windowsHide: true
  });
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    return undefined;
  }
  return result.stdout;
}

function resolveTrackedPath(repositoryPath) {
  const absolutePath = resolve(projectRoot, ...repositoryPath.split("/"));
  const allowedPrefix = `${projectRoot}${sep}`.toLowerCase();
  if (!absolutePath.toLowerCase().startsWith(allowedPrefix)) {
    throw new Error("Git returned a tracked path outside the repository");
  }
  return absolutePath;
}

async function scanRepository() {
  const entries = trackedEntries();
  const stagedPaths = stagedContentPaths();
  const violations = new Map();
  let scannedTextFiles = 0;
  let allowedBinaryFiles = 0;
  let stagedContentFiles = 0;

  const addViolation = (path, rule) => {
    violations.set(`${path}\0${rule}`, { path, rule });
  };

  const scanBytes = (path, bytes, countWorkingTreeStats) => {
    if (bytes.length > maximumTrackedFileBytes) {
      addViolation(path, "tracked-file-too-large");
      return;
    }
    if (bytes.includes(0)) {
      if (allowedBinaryExtensions.has(extname(path).toLowerCase())) {
        if (countWorkingTreeStats) allowedBinaryFiles += 1;
      } else {
        addViolation(path, "unexpected-binary-file");
      }
      return;
    }

    let text;
    try {
      text = utf8Decoder.decode(bytes);
    } catch {
      addViolation(path, "invalid-utf8-text");
      return;
    }
    if (countWorkingTreeStats) scannedTextFiles += 1;
    for (const rule of findSecretRules(text)) {
      addViolation(path, rule);
    }
  };

  for (const entry of entries) {
    const artifactRule = forbiddenArtifactRule(entry.path);
    if (artifactRule) {
      addViolation(entry.path, artifactRule);
      continue;
    }
    if (entry.stage !== 0) {
      addViolation(entry.path, "unmerged-index-entry");
      continue;
    }
    if (entry.mode === "120000") {
      addViolation(entry.path, "tracked-symbolic-link");
      continue;
    }

    const absolutePath = resolveTrackedPath(entry.path);
    let metadata;
    try {
      metadata = await lstat(absolutePath);
    } catch {
      addViolation(entry.path, "tracked-file-missing");
      continue;
    }
    if (!metadata.isFile()) {
      addViolation(entry.path, "tracked-entry-not-regular-file");
      continue;
    }
    if (metadata.size > maximumTrackedFileBytes) {
      addViolation(entry.path, "tracked-file-too-large");
      continue;
    }

    const bytes = await readFile(absolutePath);
    scanBytes(entry.path, bytes, true);

    if (stagedPaths.has(entry.path)) {
      const stagedBytes = readStagedBytes(entry.path);
      if (stagedBytes) {
        stagedContentFiles += 1;
        scanBytes(entry.path, stagedBytes, false);
      } else {
        addViolation(entry.path, "staged-content-unreadable");
      }
    }
  }

  const sortedViolations = [...violations.values()].sort((left, right) =>
    left.path.localeCompare(right.path) || left.rule.localeCompare(right.rule)
  );
  const summary = {
    schemaVersion: 1,
    command: "repository-safety-check",
    ok: sortedViolations.length === 0,
    trackedFileCount: entries.length,
    scannedTextFiles,
    stagedContentFiles,
    allowedBinaryFiles,
    maximumTrackedFileBytes,
    violations: sortedViolations
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (!summary.ok) process.exitCode = 1;
}

function runSelfTest() {
  assert.equal(forbiddenArtifactRule(".env"), "environment-file");
  assert.equal(forbiddenArtifactRule("config/.env.local"), "environment-file");
  assert.equal(forbiddenArtifactRule("secrets/token.txt"), "generated-or-runtime-path");
  assert.equal(forbiddenArtifactRule("data/runtime.sqlite"), "generated-or-runtime-path");
  assert.equal(forbiddenArtifactRule("capture.pcap"), "forbidden-artifact-extension");
  assert.equal(forbiddenArtifactRule("payload.exe"), "forbidden-artifact-extension");
  assert.equal(forbiddenArtifactRule("reports/generated/report.pdf"), "generated-report-path");
  assert.equal(forbiddenArtifactRule("evidence/private.json"), "raw-evidence-path");
  assert.equal(forbiddenArtifactRule("tools/cache.json"), "tool-cache-path");
  assert.equal(forbiddenArtifactRule(".env.example"), undefined);
  assert.equal(forbiddenArtifactRule("evidence/README.md"), undefined);
  assert.equal(forbiddenArtifactRule("tools/.gitkeep"), undefined);
  assert.equal(forbiddenArtifactRule("packages/policy/src/policy.ts"), undefined);

  const privateKeyMarker = ["-----BEGIN ", "PRIVATE", " KEY-----"].join("");
  const awsKey = `${["A", "K", "I", "A"].join("")}${"A".repeat(16)}`;
  const githubToken = `${["g", "h", "p", "_"].join("")}${"a".repeat(36)}`;
  const openAiKey = `${["s", "k", "-"].join("")}${"b".repeat(24)}`;
  assert.deepEqual(findSecretRules("ordinary source text"), []);
  assert.ok(findSecretRules(privateKeyMarker).includes("private-key-material"));
  assert.ok(findSecretRules(awsKey).includes("aws-access-key"));
  assert.ok(findSecretRules(githubToken).includes("github-token"));
  assert.ok(findSecretRules(openAiKey).includes("openai-api-key"));

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    command: "repository-safety-self-test",
    ok: true,
    forbiddenArtifactCases: 13,
    secretPatternCases: 5
  }, null, 2)}\n`);
}

if (process.argv.includes("--self-test")) {
  runSelfTest();
} else {
  await scanRepository();
}
