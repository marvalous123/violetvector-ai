import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync
} from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { AuditService } from "../src/services/audit-service.js";
import {
  assertExactBackupEvidenceSet,
  type BackupArtifactRecord
} from "../src/services/backup-evidence-contract.js";

const manifestSchema = z.object({
  schemaVersion: z.literal(1),
  product: z.literal("WAR-R00M"),
  createdAt: z.string().datetime({ offset: true }),
  source: z.object({
    databaseQuickCheck: z.literal(true),
    audit: z.object({
      valid: z.literal(true),
      eventsChecked: z.number().int().nonnegative(),
      brokenAtSequence: z.number().int().positive().optional()
    }).strict(),
    evidenceArtifacts: z.number().int().nonnegative()
  }).strict(),
  files: z.array(z.object({
    path: z.string().regex(/^(?:war-room\.sqlite|evidence\/[a-f0-9]{64})$/),
    sizeBytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/)
  }).strict()).min(1)
}).strict();

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

const backupRoot = requireAbsolute(process.argv[2] ?? "", "BACKUP_ROOT");
const destinationRoot = requireAbsolute(process.argv[3] ?? "", "DESTINATION_ROOT");
if (!existsSync(backupRoot) || !lstatSync(backupRoot).isDirectory()) {
  throw new Error("BACKUP_ROOT_NOT_FOUND");
}
if (existsSync(destinationRoot)) throw new Error("RESTORE_DESTINATION_MUST_NOT_EXIST");
if (isInside(destinationRoot, backupRoot) || isInside(backupRoot, destinationRoot)) {
  throw new Error("RESTORE_DESTINATION_MUST_BE_SEPARATE");
}

const manifest = manifestSchema.parse(
  JSON.parse(readFileSync(join(backupRoot, "backup-manifest.json"), "utf8"))
);
const uniquePaths = new Set(manifest.files.map((file) => file.path));
if (uniquePaths.size !== manifest.files.length || !uniquePaths.has("war-room.sqlite")) {
  throw new Error("BACKUP_MANIFEST_FILE_SET_INVALID");
}
for (const file of manifest.files) {
  const source = join(backupRoot, ...file.path.split("/"));
  if (
    !isInside(source, backupRoot) ||
    !existsSync(source) ||
    !lstatSync(source).isFile() ||
    lstatSync(source).size !== file.sizeBytes ||
    sha256(source) !== file.sha256
  ) {
    throw new Error("BACKUP_FILE_INTEGRITY_FAILED");
  }
}

const backupDatabase = new DatabaseSync(join(backupRoot, "war-room.sqlite"), { readOnly: true });
try {
  const quickCheck = backupDatabase.prepare("PRAGMA quick_check").get() as Record<string, unknown>;
  if (!Object.values(quickCheck).includes("ok")) throw new Error("BACKUP_DATABASE_INTEGRITY_FAILED");
  if (!new AuditService(backupDatabase).verify().valid) throw new Error("BACKUP_AUDIT_INTEGRITY_FAILED");
  const artifactRows = backupDatabase
    .prepare("SELECT storage_name, sha256, size_bytes FROM artifacts ORDER BY storage_name")
    .all() as unknown as BackupArtifactRecord[];
  assertExactBackupEvidenceSet(
    manifest.files,
    artifactRows,
    manifest.source.evidenceArtifacts
  );
} finally {
  backupDatabase.close();
}

const destinationParent = resolve(destinationRoot, "..");
mkdirSync(destinationParent, { recursive: true });
const partialRoot = join(destinationParent, `.war-room-restore-${randomUUID()}`);
mkdirSync(join(partialRoot, "evidence"), { recursive: true });
try {
  for (const file of manifest.files) {
    const source = join(backupRoot, ...file.path.split("/"));
    const destination = join(partialRoot, ...file.path.split("/"));
    copyFileSync(source, destination);
  }
  for (const file of manifest.files) {
    const copied = join(partialRoot, ...file.path.split("/"));
    if (
      !existsSync(copied) ||
      !lstatSync(copied).isFile() ||
      lstatSync(copied).size !== file.sizeBytes ||
      sha256(copied) !== file.sha256
    ) {
      throw new Error("RESTORED_FILE_INTEGRITY_FAILED");
    }
  }
  const restoredDatabase = new DatabaseSync(join(partialRoot, "war-room.sqlite"), { readOnly: true });
  try {
    const quickCheck = restoredDatabase.prepare("PRAGMA quick_check").get() as Record<string, unknown>;
    if (!Object.values(quickCheck).includes("ok")) throw new Error("RESTORED_DATABASE_INTEGRITY_FAILED");
    if (!new AuditService(restoredDatabase).verify().valid) {
      throw new Error("RESTORED_AUDIT_INTEGRITY_FAILED");
    }
    const restoredArtifacts = restoredDatabase
      .prepare("SELECT storage_name, sha256, size_bytes FROM artifacts ORDER BY storage_name")
      .all() as unknown as BackupArtifactRecord[];
    try {
      assertExactBackupEvidenceSet(
        manifest.files,
        restoredArtifacts,
        manifest.source.evidenceArtifacts
      );
    } catch {
      throw new Error("RESTORED_EVIDENCE_SET_INVALID");
    }
  } finally {
    restoredDatabase.close();
  }
  renameSync(partialRoot, destinationRoot);
  console.log(JSON.stringify({
    restoredRoot: destinationRoot,
    evidenceArtifacts: manifest.source.evidenceArtifacts,
    sourceCreatedAt: manifest.createdAt
  }));
} catch (error) {
  if (isInside(partialRoot, destinationParent) && existsSync(partialRoot)) {
    rmSync(partialRoot, { recursive: true, force: true });
  }
  throw error;
}
