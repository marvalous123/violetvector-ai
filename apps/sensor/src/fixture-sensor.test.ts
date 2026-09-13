import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  verify
} from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  FixtureCollectorClient,
  LocalFixtureSensor,
  SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT,
  fixtureStableJson
} from "./fixture-sensor.js";

function enrollmentPayload(fingerprint: string): string {
  return fixtureStableJson({
    schemaVersion: 1,
    challengeId: "enrollment-00000000-0000-0000-0000-000000000001",
    missionId: "mission-fixture",
    connectorId: "connector-lab-12345678",
    endpointId: "endpoint-lab-12345678",
    certificateFingerprintSha256: fingerprint,
    nonceBase64Url: "A".repeat(43),
    requestedAt: "2026-07-19T12:00:00.000Z",
    challengeExpiresAt: "2026-07-19T12:05:00.000Z",
    identityExpiresAt: "2026-07-20T12:00:00.000Z"
  });
}

describe("least-privilege fixture sensor", () => {
  it("keeps fixture keys ephemeral and produces bound Ed25519 signatures", () => {
    const sensor = LocalFixtureSensor.createEphemeral();
    const descriptor = sensor.descriptor();
    assert.equal(descriptor.algorithm, "ed25519");
    assert.equal(descriptor.privateKeyPersistence, "none");
    assert.match(descriptor.certificateFingerprintSha256, /^[a-f0-9]{64}$/);
    assert.ok(sensor.signEnrollmentChallenge(enrollmentPayload(descriptor.certificateFingerprintSha256)));

    const capability = sensor.createSignedCapabilityReport({
      acknowledgement: SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT,
      missionId: "mission-fixture",
      connectorId: "connector-00000000-0000-4000-8000-000000000001",
      endpointId: "endpoint-00000000-0000-4000-8000-000000000002",
      provider: "windows-eventlog",
      channel: "eventlog-admin",
      eventFamily: "event-log-clear",
      filterHash: "b".repeat(64),
      fields: ["action", "actorTrust", "objectClass", "outcome", "subjectClass"],
      collectorVersion: "fixture-0.1.0",
      loss: { state: "none", lostRecordCount: 0 },
      continuity: "continuous",
      continuousSince: "2026-07-19T11:55:00.000Z",
      lastSuccessfulReadAt: "2026-07-19T12:00:00.000Z",
      observedAt: "2026-07-19T12:00:00.000Z",
      freshnessSeconds: 120
    });
    const capabilityCore = { ...capability };
    delete capabilityCore.reportHash;
    delete capabilityCore.signatureBase64;
    const publicKey = createPublicKey({
      key: Buffer.from(descriptor.publicKeySpkiBase64, "base64"),
      format: "der",
      type: "spki"
    });
    assert.equal(
      verify(
        null,
        Buffer.from(fixtureStableJson(capabilityCore), "utf8"),
        publicKey,
        Buffer.from(String(capability.signatureBase64), "base64")
      ),
      true
    );

    const batch = sensor.createSignedFactBatch({
      acknowledgement: SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT,
      missionId: "mission-fixture",
      connectorId: "connector-00000000-0000-4000-8000-000000000001",
      endpointId: "endpoint-00000000-0000-4000-8000-000000000002",
      provider: "windows-eventlog",
      channel: "eventlog-admin",
      eventFamily: "event-log-clear",
      filterHash: "b".repeat(64),
      capabilitySnapshotId: "capability-00000000-0000-4000-8000-000000000003",
      bootId: "boot-lab-12345678",
      batchSequence: 0,
      previousBatchHash: null,
      facts: [{
        factId: "fact-lab-12345678",
        occurredAt: "2026-07-19T12:00:00.000Z",
        sourceRecordIdHash: "a".repeat(64),
        fields: {
          actorTrust: "untrusted",
          action: "clear",
          subjectClass: "admin-tool",
          objectClass: "event-log",
          outcome: "success"
        }
      }]
    });
    assert.equal(batch.batchSequence, 0);
    assert.match(String(batch.batchHash), /^[a-f0-9]{64}$/);
    assert.ok(String(batch.signatureBase64).length >= 80);
    assert.equal("command" in batch, false);
    assert.equal("action" in batch, false);
    assert.equal("signal" in (batch.facts as Array<Record<string, unknown>>)[0]!, false);
  });

  it("requires an explicit synthetic acknowledgement and rejects extra raw fields", () => {
    const sensor = LocalFixtureSensor.createEphemeral();
    const fact = {
      factId: "fact-lab-12345678",
      occurredAt: "2026-07-19T12:00:00.000Z",
      sourceRecordIdHash: "a".repeat(64),
      fields: {
        actorTrust: "untrusted" as const,
        action: "clear" as const,
        subjectClass: "admin-tool" as const,
        objectClass: "event-log" as const,
        outcome: "success" as const
      },
      commandLine: "must never leave the endpoint"
    };
    const input = {
      acknowledgement: SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT,
      missionId: "mission-fixture",
      connectorId: "connector-00000000-0000-4000-8000-000000000001",
      endpointId: "endpoint-00000000-0000-4000-8000-000000000002",
      provider: "windows-eventlog" as const,
      channel: "eventlog-admin" as const,
      eventFamily: "event-log-clear" as const,
      filterHash: "b".repeat(64),
      capabilitySnapshotId: "capability-00000000-0000-4000-8000-000000000003",
      bootId: "boot-lab-12345678",
      batchSequence: 0,
      previousBatchHash: null,
      facts: [fact]
    };
    assert.throws(
      () => sensor.createSignedFactBatch(input),
      /FIXTURE_FACT_FIELD_INVALID/
    );
    const validFact = {
      factId: fact.factId,
      occurredAt: fact.occurredAt,
      sourceRecordIdHash: fact.sourceRecordIdHash,
      fields: fact.fields
    };
    assert.throws(
      () =>
        sensor.createSignedFactBatch({
          ...input,
          acknowledgement: "wrong" as typeof SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT,
          facts: [validFact]
        }),
      /FIXTURE_ACKNOWLEDGEMENT_REQUIRED/
    );
  });

  it("loads only externally stored, pre-protected Ed25519 private keys", () => {
    const root = mkdtempSync(join(tmpdir(), "war-room-sensor-"));
    const projectRoot = join(root, "project");
    const runtimeRoot = join(root, "runtime");
    const externalRoot = join(root, "external");
    mkdirSync(projectRoot);
    mkdirSync(runtimeRoot);
    mkdirSync(externalRoot);
    const { privateKey } = generateKeyPairSync("ed25519");
    const privateKeyPath = join(externalRoot, "identity.key");
    writeFileSync(
      privateKeyPath,
      privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 }
    );
    assert.throws(
      () =>
        LocalFixtureSensor.loadExternal({
          privateKeyPath,
          projectRoot,
          runtimeDataRoot: runtimeRoot,
          verifyFileProtection: () => false
        }),
      /FIXTURE_PRIVATE_KEY_PROTECTION_UNVERIFIED/
    );
    assert.equal(
      LocalFixtureSensor.loadExternal({
        privateKeyPath,
        projectRoot,
        runtimeDataRoot: runtimeRoot,
        verifyFileProtection: () => true
      }).descriptor().privateKeyPersistence,
      "external-preprotected-file"
    );
    const forbiddenPath = join(projectRoot, "identity.key");
    writeFileSync(forbiddenPath, privateKey.export({ format: "pem", type: "pkcs8" }));
    assert.throws(
      () =>
        LocalFixtureSensor.loadExternal({
          privateKeyPath: forbiddenPath,
          projectRoot,
          runtimeDataRoot: runtimeRoot,
          verifyFileProtection: () => true
        }),
      /FIXTURE_PRIVATE_KEY_LOCATION_FORBIDDEN/
    );
  });

  it("accepts only a data-only outbound receipt and has no response action channel", async () => {
    const client = new FixtureCollectorClient();
    const receipt = await client.submit(
      { batchHash: "a".repeat(64) },
      async () => ({
        id: "fact-batch-00000000-0000-4000-8000-000000000004",
        batchHash: "b".repeat(64),
        missionId: "mission-fixture",
        connectorId: "connector-00000000-0000-4000-8000-000000000001",
        endpointId: "endpoint-00000000-0000-4000-8000-000000000002",
        capabilitySnapshotId: "capability-00000000-0000-4000-8000-000000000003",
        bootId: "boot-lab-12345678",
        batchSequence: 0,
        previousBatchHash: null,
        factCount: 1,
        evidenceArtifactId: "00000000-0000-4000-8000-000000000005",
        acceptedAt: "2026-07-19T12:00:00.000Z"
      })
    );
    assert.equal(receipt.batchSequence, 0);
    await assert.rejects(
      client.submit(
        { batchHash: "a".repeat(64) },
        async () => ({
          id: "fact-batch-00000000-0000-4000-8000-000000000004",
          batchHash: "b".repeat(64),
          missionId: "mission-fixture",
          connectorId: "connector-00000000-0000-4000-8000-000000000001",
          endpointId: "endpoint-00000000-0000-4000-8000-000000000002",
          capabilitySnapshotId: "capability-00000000-0000-4000-8000-000000000003",
          bootId: "boot-lab-12345678",
          batchSequence: 0,
          previousBatchHash: null,
          factCount: 1,
          evidenceArtifactId: "00000000-0000-4000-8000-000000000005",
          acceptedAt: "2026-07-19T12:00:00.000Z",
          action: "run-command"
        })
      ),
      /FIXTURE_RECEIPT_ACTION_FORBIDDEN/
    );
  });
});
