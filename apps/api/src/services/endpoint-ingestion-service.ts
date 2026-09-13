import type { DatabaseSync } from "node:sqlite";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";
import {
  type SignedTelemetryBatch,
  type TelemetryReceipt,
  telemetryReceiptSchema,
  validateSignedTelemetryBatch
} from "./endpoint-telemetry-contract.js";
import type {
  EndpointIdentityRow,
  EndpointRegistryService
} from "./endpoint-registry-service.js";

export type TelemetrySignatureVerifier = (
  payload: string,
  signatureBase64: string,
  certificateFingerprintSha256: string
) => boolean;

interface BatchRow {
  batch_id: string;
  batch_hash: string;
  mission_id: string;
  connector_id: string;
  endpoint_id: string;
  certificate_fingerprint_sha256: string;
  schema_version: number;
  boot_id: string;
  sequence_start: number;
  sequence_end: number;
  previous_batch_hash: string | null;
  event_count: number;
  evidence_artifact_id: string;
  receipt_json: string;
  receipt_hash: string;
  accepted_at: string;
}

function assertBatchBinding(batch: SignedTelemetryBatch): string {
  const bootId = batch.events[0]!.bootId;
  if (batch.events.some((event) => event.bootId !== bootId)) {
    throw new Error("ENDPOINT_BOOT_BINDING_MISMATCH");
  }
  return bootId;
}

function assertContinuity(
  identity: EndpointIdentityRow,
  batch: SignedTelemetryBatch,
  bootId: string
): void {
  if (identity.last_sequence === null) {
    if (
      identity.current_boot_id !== null ||
      identity.last_batch_hash !== null ||
      identity.last_receipt_hash !== null ||
      batch.sequenceStart !== 0 ||
      batch.previousBatchHash !== null
    ) {
      throw new Error("ENDPOINT_SEQUENCE_ORIGIN_INVALID");
    }
    return;
  }
  if (
    identity.current_boot_id === null ||
    identity.last_batch_hash === null ||
    identity.last_receipt_hash === null
  ) {
    throw new Error("ENDPOINT_CONTINUITY_INVALID");
  }
  if (batch.previousBatchHash !== identity.last_batch_hash) {
    throw new Error("ENDPOINT_PREVIOUS_BATCH_MISMATCH");
  }
  if (bootId === identity.current_boot_id) {
    if (batch.sequenceStart !== identity.last_sequence + 1) {
      throw new Error("ENDPOINT_SEQUENCE_CONTINUITY_INVALID");
    }
    return;
  }
  if (batch.sequenceStart !== 0) {
    throw new Error("ENDPOINT_BOOT_TRANSITION_INVALID");
  }
}

function receiptFromRow(row: BatchRow): TelemetryReceipt {
  const parsed = telemetryReceiptSchema.parse(JSON.parse(row.receipt_json));
  const expectedHash = canonicalHash({
    batchId: row.batch_id,
    acceptedSequence: row.sequence_end,
    batchHash: row.batch_hash,
    connectorId: row.connector_id,
    endpointId: row.endpoint_id,
    missionId: row.mission_id,
    evidenceArtifactId: row.evidence_artifact_id
  });
  if (
    parsed.batchId !== row.batch_id ||
    parsed.receiptHash !== row.receipt_hash ||
    parsed.receiptHash !== expectedHash ||
    parsed.acceptedSequence !== row.sequence_end
  ) {
    throw new Error("ENDPOINT_RECEIPT_INVALID");
  }
  return parsed;
}

export class EndpointIngestionService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly registry: EndpointRegistryService,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService,
    private readonly verifyTelemetrySignature: TelemetrySignatureVerifier
  ) {}

  ingest(input: unknown, now = new Date()): TelemetryReceipt {
    const batch = validateSignedTelemetryBatch(input, this.verifyTelemetrySignature);
    const bootId = assertBatchBinding(batch);
    let identity = this.registry.authenticateBatch(
      {
        missionId: batch.missionId,
        connectorId: batch.connectorId,
        endpointId: batch.endpointId,
        certificateFingerprintSha256: batch.certificateFingerprintSha256
      },
      now
    );

    const existing = this.database
      .prepare("SELECT * FROM endpoint_telemetry_batches WHERE batch_hash = ?")
      .get(batch.batchHash) as unknown as BatchRow | undefined;
    if (existing) {
      if (
        existing.mission_id !== batch.missionId ||
        existing.connector_id !== batch.connectorId ||
        existing.endpoint_id !== batch.endpointId ||
        existing.certificate_fingerprint_sha256 !== batch.certificateFingerprintSha256
      ) {
        throw new Error("ENDPOINT_BATCH_BINDING_MISMATCH");
      }
      if (identity.last_batch_hash !== batch.batchHash) {
        throw new Error("ENDPOINT_BATCH_REPLAY");
      }
      if (!this.evidence.verify(existing.evidence_artifact_id)) {
        throw new Error("ENDPOINT_BATCH_EVIDENCE_INVALID");
      }
      try {
        const observation = this.evidence.observationForMission(
          existing.evidence_artifact_id,
          batch.missionId
        );
        if (observation.source_event_id !== existing.batch_id) {
          throw new Error("ENDPOINT_BATCH_EVIDENCE_INVALID");
        }
      } catch {
        throw new Error("ENDPOINT_BATCH_EVIDENCE_INVALID");
      }
      return receiptFromRow(existing);
    }

    assertContinuity(identity, batch, bootId);
    const batchId = `batch-${batch.batchHash.slice(0, 40)}`;
    const artifact = this.evidence.seal(stableJson(batch), "application/json", {
      missionId: batch.missionId,
      sourceEventId: batchId,
      capturedAt: now,
      provenance: {
        sourceType: "endpoint-telemetry-batch",
        schemaVersion: batch.schemaVersion,
        connectorId: batch.connectorId,
        endpointId: batch.endpointId,
        bootId,
        sequenceStart: batch.sequenceStart,
        sequenceEnd: batch.sequenceEnd,
        batchHash: batch.batchHash,
        certificateFingerprintSha256: batch.certificateFingerprintSha256
      }
    });
    const receiptCore = {
      batchId,
      acceptedSequence: batch.sequenceEnd,
      batchHash: batch.batchHash,
      connectorId: batch.connectorId,
      endpointId: batch.endpointId,
      missionId: batch.missionId,
      evidenceArtifactId: artifact.id
    };
    const receipt = telemetryReceiptSchema.parse({
      batchId,
      acceptedSequence: batch.sequenceEnd,
      receiptHash: canonicalHash(receiptCore)
    });
    const receiptJson = stableJson(receipt);

    this.database.exec("BEGIN IMMEDIATE");
    try {
      identity = this.registry.authenticateBatch(
        {
          missionId: batch.missionId,
          connectorId: batch.connectorId,
          endpointId: batch.endpointId,
          certificateFingerprintSha256: batch.certificateFingerprintSha256
        },
        now
      );
      assertContinuity(identity, batch, bootId);
      this.database
        .prepare(
          `INSERT INTO endpoint_telemetry_batches(
             batch_id, batch_hash, mission_id, connector_id, endpoint_id,
             certificate_fingerprint_sha256, schema_version, boot_id,
             sequence_start, sequence_end, previous_batch_hash, event_count,
             evidence_artifact_id, receipt_json, receipt_hash, accepted_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          batchId,
          batch.batchHash,
          batch.missionId,
          batch.connectorId,
          batch.endpointId,
          batch.certificateFingerprintSha256,
          batch.schemaVersion,
          bootId,
          batch.sequenceStart,
          batch.sequenceEnd,
          batch.previousBatchHash,
          batch.events.length,
          artifact.id,
          receiptJson,
          receipt.receiptHash,
          now.toISOString()
        );
      const changed = this.database
        .prepare(
          `UPDATE endpoint_identities
           SET current_boot_id = ?, last_sequence = ?, last_batch_hash = ?,
               last_receipt_hash = ?, last_seen_at = ?
           WHERE endpoint_id = ? AND status = 'active'
             AND current_boot_id IS ?
             AND last_sequence IS ?
             AND last_batch_hash IS ?
             AND last_receipt_hash IS ?`
        )
        .run(
          bootId,
          batch.sequenceEnd,
          batch.batchHash,
          receipt.receiptHash,
          now.toISOString(),
          identity.endpoint_id,
          identity.current_boot_id,
          identity.last_sequence,
          identity.last_batch_hash,
          identity.last_receipt_hash
        );
      if (Number(changed.changes) !== 1) throw new Error("ENDPOINT_CONTINUITY_CHANGED");
      this.audit.append(
        "endpoint.telemetry.accepted",
        {
          batchId,
          batchHash: batch.batchHash,
          missionId: batch.missionId,
          connectorId: batch.connectorId,
          endpointId: batch.endpointId,
          bootId,
          sequenceStart: batch.sequenceStart,
          sequenceEnd: batch.sequenceEnd,
          eventCount: batch.events.length,
          evidenceArtifactId: artifact.id,
          receiptHash: receipt.receiptHash
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return receipt;
  }
}
