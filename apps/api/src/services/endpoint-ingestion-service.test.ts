import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EndpointIngestionService } from "./endpoint-ingestion-service.js";
import {
  type LiveEndpointEvent,
  telemetryBatchHash
} from "./endpoint-telemetry-contract.js";
import {
  EndpointRegistryService,
  type EndpointIdentity
} from "./endpoint-registry-service.js";
import { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";

const now = new Date("2026-07-19T12:00:00.000Z");
const enrollmentProof = "A".repeat(64);
const batchSignature = "B".repeat(64);

function setup(identityExpiresAt = new Date(now.valueOf() + 60 * 60_000)) {
  const database = openDatabase();
  const audit = new AuditService(database);
  const mission = new MissionService(database, audit).createMission("Endpoint ingestion test", now);
  const fingerprint = "a".repeat(64);
  const registry = new EndpointRegistryService(
    database,
    audit,
    (_payload, signature, candidateFingerprint) =>
      signature === enrollmentProof && candidateFingerprint === fingerprint,
    { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
  );
  const challenge = registry.requestEnrollment(
    {
      missionId: mission.id,
      certificateFingerprintSha256: fingerprint,
      identityExpiresAt: identityExpiresAt.toISOString()
    },
    "endpoint operator",
    now
  );
  const identity = registry.approveEnrollment(
    {
      challengeId: challenge.id,
      confirmedCertificateFingerprintSha256: fingerprint,
      proofSignatureBase64: enrollmentProof
    },
    "approving operator",
    now
  );
  const evidence = new EvidenceService(
    database,
    mkdtempSync(join(tmpdir(), "war-room-endpoint-ingestion-")),
    audit
  );
  const ingestion = new EndpointIngestionService(
    database,
    registry,
    evidence,
    audit,
    (_payload, signature, candidateFingerprint) =>
      signature === batchSignature && candidateFingerprint === fingerprint
  );
  return { database, audit, mission, fingerprint, registry, identity, evidence, ingestion };
}

function event(
  identity: EndpointIdentity,
  bootId: string,
  sequence: number,
  signal: LiveEndpointEvent["signal"] = "password-store-read"
): LiveEndpointEvent {
  return {
    mode: "live",
    schemaVersion: 1,
    eventId: `event-lab-${String(sequence).padStart(8, "0")}`,
    occurredAt: new Date(now.valueOf() + sequence * 1_000).toISOString(),
    connectorId: identity.connectorId,
    endpointId: identity.endpointId,
    bootId,
    sequence,
    telemetryClass: "endpoint",
    signal,
    actorTrust: "untrusted",
    sourceRecordIdHash: "c".repeat(64),
    mappingVersion: "windows-blue-v1",
    redaction: { applied: true, fieldsRemoved: 2, valuesHashed: 3 }
  };
}

function batch(
  identity: EndpointIdentity,
  bootId: string,
  sequenceStart: number,
  previousBatchHash: string | null,
  signals: LiveEndpointEvent["signal"][] = ["password-store-read"],
  overrides: Partial<{
    missionId: string;
    connectorId: string;
    endpointId: string;
    certificateFingerprintSha256: string;
  }> = {}
) {
  const binding = {
    missionId: overrides.missionId ?? identity.missionId,
    connectorId: overrides.connectorId ?? identity.connectorId,
    endpointId: overrides.endpointId ?? identity.endpointId,
    certificateFingerprintSha256:
      overrides.certificateFingerprintSha256 ?? identity.certificateFingerprintSha256
  };
  const events = signals.map((signal, index) => ({
    ...event(identity, bootId, sequenceStart + index, signal),
    connectorId: binding.connectorId,
    endpointId: binding.endpointId
  }));
  const core = {
    schemaVersion: 1 as const,
    ...binding,
    sequenceStart,
    sequenceEnd: sequenceStart + events.length - 1,
    previousBatchHash,
    events
  };
  return {
    ...core,
    batchHash: telemetryBatchHash(core),
    signatureBase64: batchSignature
  };
}

describe("endpoint telemetry intake foundation", () => {
  it("accepts a first batch, seals evidence and returns the same data-only receipt on immediate retry", () => {
    const { database, audit, identity, evidence, ingestion } = setup();
    const first = batch(identity, "boot-lab-00000001", 0, null);
    const receipt = ingestion.ingest(first, now);
    assert.deepEqual(Object.keys(receipt).sort(), ["acceptedSequence", "batchId", "receiptHash"]);
    assert.equal(receipt.acceptedSequence, 0);
    assert.equal(ingestion.ingest(first, new Date(now.valueOf() + 1_000)).receiptHash, receipt.receiptHash);

    const stored = database
      .prepare("SELECT evidence_artifact_id, receipt_hash FROM endpoint_telemetry_batches")
      .get() as { evidence_artifact_id: string; receipt_hash: string };
    assert.equal(stored.receipt_hash, receipt.receiptHash);
    assert.equal(evidence.verify(stored.evidence_artifact_id), true);
    assert.equal(evidence.observationForMission(stored.evidence_artifact_id, identity.missionId).mission_id, identity.missionId);
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM endpoint_telemetry_batches").get() as { count: number }).count,
      1
    );
    database.exec("DROP TRIGGER endpoint_batch_immutable_update");
    database
      .prepare("UPDATE endpoint_telemetry_batches SET receipt_hash = ? WHERE batch_hash = ?")
      .run("d".repeat(64), first.batchHash);
    assert.throws(
      () => ingestion.ingest(first, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_RECEIPT_INVALID/
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("persists sequence continuity and rejects old replay, fork, rollback and chain drift", () => {
    const { database, identity, ingestion } = setup();
    const first = batch(identity, "boot-lab-00000001", 0, null);
    ingestion.ingest(first, now);
    const second = batch(
      identity,
      "boot-lab-00000001",
      1,
      first.batchHash,
      ["security-tool-impairment"]
    );
    ingestion.ingest(second, new Date(now.valueOf() + 1_000));

    assert.throws(
      () => ingestion.ingest(first, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_BATCH_REPLAY/
    );
    const fork = batch(
      identity,
      "boot-lab-00000001",
      1,
      first.batchHash,
      ["windows-event-log-clear"]
    );
    assert.throws(
      () => ingestion.ingest(fork, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_PREVIOUS_BATCH_MISMATCH/
    );
    const rollback = batch(
      identity,
      "boot-lab-00000001",
      1,
      second.batchHash,
      ["post-execution-file-deletion"]
    );
    assert.throws(
      () => ingestion.ingest(rollback, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_SEQUENCE_CONTINUITY_INVALID/
    );
    const drift = batch(
      identity,
      "boot-lab-00000001",
      2,
      "d".repeat(64),
      ["post-execution-file-deletion"]
    );
    assert.throws(
      () => ingestion.ingest(drift, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_PREVIOUS_BATCH_MISMATCH/
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM endpoint_telemetry_batches").get() as { count: number }).count,
      2
    );
    database.close();
  });

  it("allows one chained boot reset and rejects mixed, rollback and unchained boot transitions", () => {
    const { database, identity, ingestion } = setup();
    const first = batch(identity, "boot-lab-00000001", 0, null);
    ingestion.ingest(first, now);
    const reboot = batch(
      identity,
      "boot-lab-00000002",
      0,
      first.batchHash,
      ["scheduled-task-persistence"]
    );
    ingestion.ingest(reboot, new Date(now.valueOf() + 1_000));

    const oldBoot = batch(
      identity,
      "boot-lab-00000001",
      1,
      reboot.batchHash,
      ["new-untrusted-service"]
    );
    assert.throws(
      () => ingestion.ingest(oldBoot, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_BOOT_TRANSITION_INVALID/
    );
    const unchainedBoot = batch(
      identity,
      "boot-lab-00000003",
      0,
      first.batchHash,
      ["new-untrusted-service"]
    );
    assert.throws(
      () => ingestion.ingest(unchainedBoot, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_PREVIOUS_BATCH_MISMATCH/
    );

    const mixed = batch(
      identity,
      "boot-lab-00000002",
      1,
      reboot.batchHash,
      ["new-untrusted-service", "post-execution-file-deletion"]
    );
    mixed.events[1] = { ...mixed.events[1]!, bootId: "boot-lab-00000003" };
    const mixedCore = {
      schemaVersion: mixed.schemaVersion,
      missionId: mixed.missionId,
      connectorId: mixed.connectorId,
      endpointId: mixed.endpointId,
      certificateFingerprintSha256: mixed.certificateFingerprintSha256,
      sequenceStart: mixed.sequenceStart,
      sequenceEnd: mixed.sequenceEnd,
      previousBatchHash: mixed.previousBatchHash,
      events: mixed.events
    };
    mixed.batchHash = telemetryBatchHash(mixedCore);
    assert.throws(
      () => ingestion.ingest(mixed, new Date(now.valueOf() + 2_000)),
      /ENDPOINT_BOOT_BINDING_MISMATCH/
    );
    database.close();
  });

  it("rejects wrong mission, certificate, schema, revoked and expired identities", () => {
    const firstSetup = setup();
    const wrongMission = batch(
      firstSetup.identity,
      "boot-lab-00000001",
      0,
      null,
      ["password-store-read"],
      { missionId: "wrong-mission" }
    );
    assert.throws(
      () => firstSetup.ingestion.ingest(wrongMission, now),
      /ENDPOINT_IDENTITY_BINDING_MISMATCH/
    );
    const wrongCertificate = batch(
      firstSetup.identity,
      "boot-lab-00000001",
      0,
      null,
      ["password-store-read"],
      { certificateFingerprintSha256: "b".repeat(64) }
    );
    assert.throws(
      () => firstSetup.ingestion.ingest(wrongCertificate, now),
      /ENDPOINT_SIGNATURE_INVALID/
    );
    const wrongSchema = { ...batch(firstSetup.identity, "boot-lab-00000001", 0, null), schemaVersion: 2 };
    assert.throws(() => firstSetup.ingestion.ingest(wrongSchema, now));

    firstSetup.registry.revokeEndpoint(
      firstSetup.identity.endpointId,
      "security operator",
      "Connector was removed from the authorized lab.",
      now
    );
    assert.throws(
      () => firstSetup.ingestion.ingest(batch(firstSetup.identity, "boot-lab-00000001", 0, null), now),
      /ENDPOINT_IDENTITY_NOT_ACTIVE/
    );
    firstSetup.database.close();

    const expiredSetup = setup(new Date(now.valueOf() + 31_000));
    assert.throws(
      () =>
        expiredSetup.ingestion.ingest(
          batch(expiredSetup.identity, "boot-lab-00000001", 0, null),
          new Date(now.valueOf() + 31_001)
        ),
      /ENDPOINT_IDENTITY_EXPIRED/
    );
    expiredSetup.database.close();
  });

  it("keeps accepted metadata immutable", () => {
    const { database, identity, ingestion } = setup();
    const first = batch(identity, "boot-lab-00000001", 0, null);
    ingestion.ingest(first, now);
    assert.throws(
      () =>
        database
          .prepare("UPDATE endpoint_telemetry_batches SET sequence_end = 9 WHERE batch_hash = ?")
          .run(first.batchHash),
      /ENDPOINT_BATCH_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("DELETE FROM endpoint_telemetry_batches WHERE batch_hash = ?")
          .run(first.batchHash),
      /ENDPOINT_BATCH_IMMUTABLE/
    );
    database.close();
  });
});
