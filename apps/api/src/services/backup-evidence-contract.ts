export interface BackupFileRecord {
  readonly path: string;
  readonly sizeBytes: number;
  readonly sha256: string;
}

export interface BackupArtifactRecord {
  readonly storage_name: string;
  readonly sha256: string;
  readonly size_bytes: number;
}

export function assertExactBackupEvidenceSet(
  files: readonly BackupFileRecord[],
  artifacts: readonly BackupArtifactRecord[],
  declaredEvidenceArtifacts: number
): void {
  if (
    !Number.isSafeInteger(declaredEvidenceArtifacts) ||
    declaredEvidenceArtifacts < 0 ||
    artifacts.length !== declaredEvidenceArtifacts
  ) {
    throw new Error("BACKUP_EVIDENCE_SET_INVALID");
  }
  const byPath = new Map(files.map((file) => [file.path, file]));
  if (byPath.size !== files.length || !byPath.has("war-room.sqlite")) {
    throw new Error("BACKUP_EVIDENCE_SET_INVALID");
  }
  const expectedPaths = new Set(["war-room.sqlite"]);
  for (const artifact of artifacts) {
    if (
      artifact.storage_name !== artifact.sha256 ||
      !/^[a-f0-9]{64}$/.test(artifact.storage_name) ||
      !Number.isSafeInteger(artifact.size_bytes) ||
      artifact.size_bytes < 0 ||
      artifact.size_bytes > 10 * 1024 * 1024
    ) {
      throw new Error("BACKUP_EVIDENCE_SET_INVALID");
    }
    const path = `evidence/${artifact.storage_name}`;
    const file = byPath.get(path);
    if (
      !file ||
      file.sha256 !== artifact.sha256 ||
      file.sizeBytes !== artifact.size_bytes
    ) {
      throw new Error("BACKUP_EVIDENCE_SET_INVALID");
    }
    expectedPaths.add(path);
  }
  if (
    expectedPaths.size !== files.length ||
    files.some((file) => !expectedPaths.has(file.path))
  ) {
    throw new Error("BACKUP_EVIDENCE_SET_INVALID");
  }
}
