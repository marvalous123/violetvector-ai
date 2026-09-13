import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assertExactBackupEvidenceSet } from "./backup-evidence-contract.js";

const artifactHash = "a".repeat(64);
const databaseHash = "b".repeat(64);
const files = [
  { path: "war-room.sqlite", sizeBytes: 100, sha256: databaseHash },
  { path: `evidence/${artifactHash}`, sizeBytes: 12, sha256: artifactHash }
];
const artifacts = [
  { storage_name: artifactHash, sha256: artifactHash, size_bytes: 12 }
];

describe("backup evidence contract", () => {
  it("accepts one exact database-bound evidence file set", () => {
    assert.doesNotThrow(() => assertExactBackupEvidenceSet(files, artifacts, 1));
  });

  it("rejects manifest substitution, metadata drift, duplicates and extra files", () => {
    const rejected = [
      files.map((file) => file.path.startsWith("evidence/") ? { ...file, sha256: "c".repeat(64) } : file),
      files.map((file) => file.path.startsWith("evidence/") ? { ...file, sizeBytes: 13 } : file),
      [...files, files[1]!],
      [...files, { path: `evidence/${"d".repeat(64)}`, sizeBytes: 1, sha256: "d".repeat(64) }]
    ];
    for (const candidate of rejected) {
      assert.throws(
        () => assertExactBackupEvidenceSet(candidate, artifacts, 1),
        /BACKUP_EVIDENCE_SET_INVALID/
      );
    }
    assert.throws(
      () => assertExactBackupEvidenceSet(files, artifacts, 2),
      /BACKUP_EVIDENCE_SET_INVALID/
    );
  });
});
