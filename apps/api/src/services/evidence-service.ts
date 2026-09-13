import { constants } from "node:fs";
import {
  accessSync,
  closeSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";

export interface ArtifactRow {
  id: string;
  sha256: string;
  size_bytes: number;
  media_type: string;
  storage_name: string;
  captured_at: string;
  sealed_at: string;
  source_event_id: string | null;
}

export interface EvidenceObservationRow {
  id: string;
  artifact_id: string;
  mission_id: string;
  run_id: string | null;
  model_invocation_id: string | null;
  source_event_id: string | null;
  provenance_json: string;
  provenance_hash: string;
  captured_at: string;
  recorded_at: string;
}

interface SealOptions {
  missionId?: string;
  runId?: string;
  modelInvocationId?: string;
  sourceEventId?: string;
  capturedAt?: Date;
  provenance?: Readonly<Record<string, unknown>>;
}

export class EvidenceService {
  private readonly audit: AuditService;
  private readonly resolvedRoot: string;

  constructor(
    private readonly database: DatabaseSync,
    private readonly root: string,
    audit?: AuditService
  ) {
    this.audit = audit ?? new AuditService(database);
    mkdirSync(root, { recursive: true });
    this.resolvedRoot = realpathSync.native(root);
  }

  seal(
    content: string | Uint8Array,
    mediaType: string,
    options: SealOptions = {}
  ): ArtifactRow {
    if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(mediaType)) throw new Error("MEDIA_TYPE_INVALID");
    const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);
    if (bytes.byteLength > 10 * 1024 * 1024) throw new Error("ARTIFACT_TOO_LARGE");
    const missions = !options.missionId
      ? (this.database.prepare("SELECT id FROM missions ORDER BY created_at LIMIT 2").all() as unknown as Array<{ id: string }>)
      : [];
    const observationOptions: SealOptions =
      !options.missionId && missions.length === 1
        ? {
            ...options,
            missionId: missions[0]!.id,
            provenance: { sourceType: "legacy-single-mission-capture", ...(options.provenance ?? {}) }
          }
        : options;
    this.validateObservationBindings(observationOptions);
    const hash = sha256(bytes);
    const storageName = hash;
    const destination = join(this.root, storageName);
    try {
      accessSync(destination, constants.F_OK);
    } catch {
      writeFileSync(destination, bytes, { flag: "wx" });
    }
    const existing = this.database.prepare("SELECT * FROM artifacts WHERE sha256 = ?").get(hash) as unknown as
      | ArtifactRow
      | undefined;
    const capturedAt = observationOptions.capturedAt ?? new Date();
    const sealedAt = new Date();
    if (existing && (existing.size_bytes !== bytes.byteLength || existing.media_type !== mediaType)) {
      throw new Error("ARTIFACT_METADATA_CONFLICT");
    }
    const artifactId = existing?.id ?? randomUUID();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      if (!existing) {
        this.database
          .prepare(
            `INSERT INTO artifacts(
               id, sha256, size_bytes, media_type, storage_name, captured_at, sealed_at, source_event_id
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            artifactId,
            hash,
            bytes.byteLength,
            mediaType,
            storageName,
            capturedAt.toISOString(),
            sealedAt.toISOString(),
            observationOptions.sourceEventId ?? null
          );
        this.audit.append(
          "artifact.sealed",
          { artifactId, sha256: hash, sizeBytes: bytes.byteLength, mediaType },
          sealedAt
        );
      }
      if (observationOptions.missionId) {
        this.insertObservation(artifactId, observationOptions, capturedAt, sealedAt);
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(artifactId);
  }

  get(id: string): ArtifactRow {
    const row = this.database.prepare("SELECT * FROM artifacts WHERE id = ?").get(id) as unknown as ArtifactRow | undefined;
    if (!row) throw new Error("ARTIFACT_NOT_FOUND");
    return row;
  }

  read(id: string): Buffer {
    return this.readVerified(id).bytes;
  }

  readVerified(id: string): { artifact: ArtifactRow; bytes: Buffer } {
    const artifact = this.get(id);
    if (!/^[a-f0-9]{64}$/.test(artifact.sha256) || artifact.storage_name !== artifact.sha256) {
      throw new Error("ARTIFACT_STORAGE_BINDING_INVALID");
    }
    const path = join(this.resolvedRoot, artifact.sha256);
    const pathState = lstatSync(path);
    if (!pathState.isFile() || pathState.isSymbolicLink()) throw new Error("ARTIFACT_PATH_INVALID");
    const resolvedPath = realpathSync.native(path);
    if (dirname(resolvedPath) !== this.resolvedRoot || basename(resolvedPath) !== artifact.sha256) {
      throw new Error("ARTIFACT_PATH_INVALID");
    }
    const noFollow = "O_NOFOLLOW" in constants
      ? (constants as typeof constants & { O_NOFOLLOW: number }).O_NOFOLLOW
      : 0;
    const descriptor = openSync(path, constants.O_RDONLY | noFollow);
    try {
      const before = fstatSync(descriptor);
      if (!before.isFile()) throw new Error("ARTIFACT_PATH_INVALID");
      const bytes = readFileSync(descriptor);
      const after = fstatSync(descriptor);
      if (
        before.dev !== after.dev ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        bytes.byteLength !== artifact.size_bytes ||
        sha256(bytes) !== artifact.sha256
      ) {
        throw new Error("ARTIFACT_INTEGRITY_INVALID");
      }
      return { artifact, bytes };
    } finally {
      closeSync(descriptor);
    }
  }

  verify(id: string): boolean {
    try {
      this.readVerified(id);
      return true;
    } catch {
      return false;
    }
  }

  observations(artifactId: string, missionId?: string): EvidenceObservationRow[] {
    return (missionId
      ? this.database
          .prepare(
            `SELECT * FROM evidence_observations
             WHERE artifact_id = ? AND mission_id = ? ORDER BY recorded_at, id`
          )
          .all(artifactId, missionId)
      : this.database
          .prepare("SELECT * FROM evidence_observations WHERE artifact_id = ? ORDER BY recorded_at, id")
          .all(artifactId)) as unknown as EvidenceObservationRow[];
  }

  observationForMission(artifactId: string, missionId: string): EvidenceObservationRow {
    const row = this.database
      .prepare(
        `SELECT * FROM evidence_observations
         WHERE artifact_id = ? AND mission_id = ? ORDER BY recorded_at DESC, id DESC LIMIT 1`
      )
      .get(artifactId, missionId) as unknown as EvidenceObservationRow | undefined;
    if (!row || canonicalHash(JSON.parse(row.provenance_json)) !== row.provenance_hash) {
      throw new Error("EVIDENCE_OBSERVATION_INVALID");
    }
    return row;
  }

  verifyObservation(observationId: string, artifactId: string, missionId: string): boolean {
    try {
      const row = this.database
        .prepare(
          `SELECT * FROM evidence_observations
           WHERE id = ? AND artifact_id = ? AND mission_id = ?`
        )
        .get(observationId, artifactId, missionId) as unknown as EvidenceObservationRow | undefined;
      return Boolean(row && canonicalHash(JSON.parse(row.provenance_json)) === row.provenance_hash);
    } catch {
      return false;
    }
  }

  private validateObservationBindings(options: SealOptions): void {
    if ((options.runId || options.modelInvocationId || options.provenance) && !options.missionId) {
      throw new Error("EVIDENCE_MISSION_REQUIRED");
    }
    if (!options.missionId) return;
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(options.missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
    if (options.runId) {
      const run = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(options.runId) as
        | { mission_id: string }
        | undefined;
      if (!run || run.mission_id !== options.missionId) throw new Error("EVIDENCE_RUN_MISSION_MISMATCH");
    }
    if (options.modelInvocationId) {
      const invocation = this.database
        .prepare("SELECT mission_id FROM model_invocations WHERE id = ?")
        .get(options.modelInvocationId) as { mission_id: string | null } | undefined;
      if (!invocation || invocation.mission_id !== options.missionId) {
        throw new Error("EVIDENCE_MODEL_MISSION_MISMATCH");
      }
    }
    const provenanceJson = stableJson(options.provenance ?? {});
    if (provenanceJson.length > 16_384 || /"(?:password|secret|token|credential)"\s*:/i.test(provenanceJson)) {
      throw new Error("EVIDENCE_PROVENANCE_INVALID");
    }
  }

  private insertObservation(
    artifactId: string,
    options: SealOptions & { missionId?: string },
    capturedAt: Date,
    recordedAt: Date
  ): void {
    const missionId = options.missionId!;
    const provenance = {
      schemaVersion: 1,
      source: options.provenance ?? {},
      artifactId,
      missionId,
      runId: options.runId ?? null,
      modelInvocationId: options.modelInvocationId ?? null,
      sourceEventId: options.sourceEventId ?? null,
      capturedAt: capturedAt.toISOString(),
      recordedAt: recordedAt.toISOString()
    };
    const provenanceJson = stableJson(provenance);
    const provenanceHash = canonicalHash(provenance);
    const observationId = randomUUID();
    this.database
      .prepare(
        `INSERT INTO evidence_observations(
           id, artifact_id, mission_id, run_id, model_invocation_id, source_event_id,
           provenance_json, provenance_hash, captured_at, recorded_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        observationId,
        artifactId,
        missionId,
        options.runId ?? null,
        options.modelInvocationId ?? null,
        options.sourceEventId ?? null,
        provenanceJson,
        provenanceHash,
        capturedAt.toISOString(),
        recordedAt.toISOString()
      );
    this.audit.append(
      "evidence.observation.recorded",
      { observationId, artifactId, missionId, provenanceHash },
      recordedAt
    );
  }
}
