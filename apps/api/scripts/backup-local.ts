import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { backup, DatabaseSync } from "node:sqlite";
import { AuditService } from "../src/services/audit-service.js";
import { assertExactBackupEvidenceSet } from "../src/services/backup-evidence-contract.js";

interface ArtifactRow {
  storage_name: string;
  sha256: string;
  size_bytes: number;
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function requireAbsolute(path: string, label: string): string {
  if (!isAbsolute(path)) throw new Error(`${label}_MUST_BE_ABSOLUTE`);
  return resolve(path);
}

function isInside(child: string, parent: string): boolean {
  const candidate = relative(resolve(parent), resolve(child));
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}

const dataRoot = requireAbsolute(
  process.argv[2] ?? join(homedir(), ".war-room-project15"),
  "DATA_ROOT"
);
const outputRoot = requireAbsolute(
  process.argv[3] ?? join(homedir(), "WAR-R00M Backups"),
  "OUTPUT_ROOT"
);
if (isInside(outputRoot, dataRoot) || isInside(dataRoot, outputRoot)) {
  throw new Error("BACKUP_ROOT_MUST_BE_SEPARATE");
}
const sourceDatabasePath = join(dataRoot, "war-room.sqlite");
const sourceEvidenceRoot = join(dataRoot, "evidence");
if (!existsSync(sourceDatabasePath) || !lstatSync(sourceDatabasePath).isFile()) {
  throw new Error("SOURCE_DATABASE_NOT_FOUND");
}
if (!existsSync(sourceEvidenceRoot) || !lstatSync(sourceEvidenceRoot).isDirectory()) {
  throw new Error("SOURCE_EVIDENCE_STORE_NOT_FOUND");
}

mkdirSync(outputRoot, { recursive: true });
const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
const finalRoot = join(outputRoot, `war-room-backup-${timestamp}`);
const partialRoot = join(outputRoot, `.partial-${randomUUID()}`);
const destinationDatabasePath = join(partialRoot, "war-room.sqlite");
const destinationEvidenceRoot = join(partialRoot, "evidence");
mkdirSync(destinationEvidenceRoot, { recursive: true });

try {
  const source = new DatabaseSync(sourceDatabasePath, { readOnly: true });
  try {
    const quickCheck = source.prepare("PRAGMA quick_check").get() as Record<string, unknown>;
    if (!Object.values(quickCheck).includes("ok")) throw new Error("SOURCE_DATABASE_INTEGRITY_FAILED");
    await backup(source, destinationDatabasePath);
  } finally {
    source.close();
  }

  const snapshot = new DatabaseSync(destinationDatabasePath, { readOnly: true });
  let auditVerification: ReturnType<AuditService["verify"]>;
  let artifacts: ArtifactRow[];
  try {
    const quickCheck = snapshot.prepare("PRAGMA quick_check").get() as Record<string, unknown>;
    if (!Object.values(quickCheck).includes("ok")) throw new Error("BACKUP_DATABASE_INTEGRITY_FAILED");
    auditVerification = new AuditService(snapshot).verify();
    if (!auditVerification.valid) throw new Error("BACKUP_AUDIT_INTEGRITY_FAILED");
    artifacts = snapshot
      .prepare("SELECT storage_name, sha256, size_bytes FROM artifacts ORDER BY storage_name")
      .all() as unknown as ArtifactRow[];
  } finally {
    snapshot.close();
  }

  const fileRecords: Array<{ path: string; sizeBytes: number; sha256: string }> = [];
  const databaseBytes = readFileSync(destinationDatabasePath);
  fileRecords.push({
    path: "war-room.sqlite",
    sizeBytes: databaseBytes.byteLength,
    sha256: createHash("sha256").update(databaseBytes).digest("hex")
  });
  for (const artifact of artifacts) {
    if (
      artifact.storage_name !== artifact.sha256 ||
      !/^[a-f0-9]{64}$/.test(artifact.storage_name) ||
      artifact.size_bytes < 0 ||
      artifact.size_bytes > 10 * 1024 * 1024
    ) {
      throw new Error("BACKUP_ARTIFACT_METADATA_INVALID");
    }
    const source = join(sourceEvidenceRoot, artifact.storage_name);
    if (!existsSync(source) || !lstatSync(source).isFile()) {
      throw new Error("BACKUP_ARTIFACT_MISSING");
    }
    if (lstatSync(source).size !== artifact.size_bytes || sha256(source) !== artifact.sha256) {
      throw new Error("BACKUP_ARTIFACT_INTEGRITY_FAILED");
    }
    const destination = join(destinationEvidenceRoot, artifact.storage_name);
    copyFileSync(source, destination);
    fileRecords.push({
      path: `evidence/${artifact.storage_name}`,
      sizeBytes: artifact.size_bytes,
      sha256: artifact.sha256
    });
  }
  assertExactBackupEvidenceSet(fileRecords, artifacts, artifacts.length);
  const manifest = {
    schemaVersion: 1,
    product: "WAR-R00M",
    createdAt: new Date().toISOString(),
    source: {
      databaseQuickCheck: true,
      audit: auditVerification,
      evidenceArtifacts: artifacts.length
    },
    files: fileRecords
  };
  writeFileSync(join(partialRoot, "backup-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx"
  });
  if (existsSync(finalRoot)) throw new Error("BACKUP_DESTINATION_EXISTS");
  renameSync(partialRoot, finalRoot);
  console.log(JSON.stringify({
    backupRoot: finalRoot,
    database: basename(destinationDatabasePath),
    evidenceArtifacts: artifacts.length,
    auditEventsChecked: auditVerification.eventsChecked
  }));
} catch (error) {
  if (isInside(partialRoot, outputRoot) && existsSync(partialRoot)) {
    rmSync(partialRoot, { recursive: true, force: true });
  }
  throw error;
}
