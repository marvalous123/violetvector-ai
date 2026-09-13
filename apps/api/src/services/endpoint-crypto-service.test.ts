import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject
} from "node:crypto";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import { EndpointCryptoService } from "./endpoint-crypto-service.js";
import { EndpointRegistryService } from "./endpoint-registry-service.js";
import { MissionService } from "./mission-service.js";

const now = new Date("2026-07-19T12:00:00.000Z");

function keyMaterial(type: "ed25519" | "ecdsa-p256" | "rsa" = "ed25519") {
  const pair =
    type === "ed25519"
      ? generateKeyPairSync("ed25519")
      : type === "ecdsa-p256"
        ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
        : generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = pair.publicKey.export({ format: "der", type: "spki" });
  return {
    privateKey: pair.privateKey,
    spkiBase64: spki.toString("base64"),
    fingerprint: createHash("sha256").update(spki).digest("hex")
  };
}

function signature(privateKey: KeyObject, payload: string): string {
  return (
    privateKey.asymmetricKeyType === "ec"
      ? sign(
          "sha256",
          Buffer.from(payload, "utf8"),
          { key: privateKey, dsaEncoding: "ieee-p1363" }
        )
      : sign(null, Buffer.from(payload, "utf8"), privateKey)
  ).toString("base64");
}

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const crypto = new EndpointCryptoService(database, audit);
  const mission = new MissionService(database, audit).createMission("Endpoint crypto test", now);
  const registry = new EndpointRegistryService(
    database,
    audit,
    crypto.verifyEnrollmentProof,
    { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
  );
  return { database, audit, crypto, mission, registry };
}

describe("endpoint signature identity foundation", () => {
  it("binds a stored public key to enrollment proof and active telemetry signatures", () => {
    const { database, audit, crypto, mission, registry } = setup();
    const key = keyMaterial();
    const challenge = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
      },
      "endpoint operator",
      now
    );
    const payload = stableJson(challenge.payload);
    assert.equal(crypto.verifyEnrollmentProof(payload, signature(key.privateKey, payload), key.fingerprint), false);

    const registered = crypto.registerEnrollmentPublicKey(
      { challengeId: challenge.id, publicKeySpkiBase64: key.spkiBase64 },
      now
    );
    assert.equal(registered.certificateFingerprintSha256, key.fingerprint);
    assert.equal(registered.endpointId, challenge.payload.endpointId);
    assert.equal(crypto.verifyEnrollmentProof(payload, signature(key.privateKey, payload), key.fingerprint), true);

    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: key.fingerprint,
        proofSignatureBase64: signature(key.privateKey, payload)
      },
      "approving operator",
      now
    );
    const telemetryCore = {
      schemaVersion: 1,
      missionId: identity.missionId,
      connectorId: identity.connectorId,
      endpointId: identity.endpointId,
      certificateFingerprintSha256: identity.certificateFingerprintSha256,
      sequenceStart: 0,
      sequenceEnd: 0,
      previousBatchHash: null,
      events: [{
        mode: "live",
        schemaVersion: 1,
        eventId: "event-lab-12345678",
        occurredAt: now.toISOString(),
        connectorId: identity.connectorId,
        endpointId: identity.endpointId,
        bootId: "boot-lab-12345678",
        sequence: 0,
        telemetryClass: "endpoint",
        signal: "security-tool-impairment",
        actorTrust: "untrusted",
        sourceRecordIdHash: "a".repeat(64),
        mappingVersion: "windows-blue-v1",
        redaction: { applied: true, fieldsRemoved: 2, valuesHashed: 2 }
      }]
    };
    const telemetryPayload = stableJson(telemetryCore);
    assert.equal(
      crypto.verifyTelemetrySignature(
        telemetryPayload,
        signature(key.privateKey, telemetryPayload),
        key.fingerprint
      ),
      true
    );
    assert.equal(
      crypto.verifyTelemetrySignature(
        `${telemetryPayload} `,
        signature(key.privateKey, telemetryPayload),
        key.fingerprint
      ),
      false
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("accepts the native CNG-compatible ECDSA P-256 signature profile", () => {
    const { database, audit, crypto, mission, registry } = setup();
    const key = keyMaterial("ecdsa-p256");
    const challenge = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
      },
      "native sensor operator",
      now
    );
    const payload = stableJson(challenge.payload);
    const registered = crypto.registerEnrollmentPublicKey(
      { challengeId: challenge.id, publicKeySpkiBase64: key.spkiBase64 },
      now
    );
    assert.equal(registered.algorithm, "ecdsa-p256-sha256");
    assert.equal(
      crypto.verifyEnrollmentProof(
        payload,
        signature(key.privateKey, payload),
        key.fingerprint
      ),
      true
    );
    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: key.fingerprint,
        proofSignatureBase64: signature(key.privateKey, payload)
      },
      "native sensor approver",
      now
    );
    const telemetryPayload = stableJson({
      schemaVersion: 1,
      missionId: identity.missionId,
      connectorId: identity.connectorId,
      endpointId: identity.endpointId,
      certificateFingerprintSha256: identity.certificateFingerprintSha256,
      sequenceStart: 0,
      sequenceEnd: 0,
      previousBatchHash: null,
      events: []
    });
    assert.equal(
      crypto.verifyTelemetrySignature(
        telemetryPayload,
        signature(key.privateKey, telemetryPayload),
        key.fingerprint
      ),
      true
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rebinds the same immutable public key after an unapproved challenge expires", () => {
    const { database, audit, crypto, mission, registry } = setup();
    const key = keyMaterial("ecdsa-p256");
    const first = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
      },
      "native sensor operator",
      now
    );
    crypto.registerEnrollmentPublicKey(
      { challengeId: first.id, publicKeySpkiBase64: key.spkiBase64 },
      now
    );
    const firstPayload = stableJson(first.payload);
    const afterExpiry = new Date(now.valueOf() + 31_000);
    assert.throws(
      () =>
        registry.approveEnrollment(
          {
            challengeId: first.id,
            confirmedCertificateFingerprintSha256: key.fingerprint,
            proofSignatureBase64: signature(key.privateKey, firstPayload)
          },
          "late operator",
          afterExpiry
        ),
      /ENDPOINT_ENROLLMENT_EXPIRED/
    );

    const second = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(afterExpiry.valueOf() + 60 * 60_000).toISOString()
      },
      "native sensor operator",
      afterExpiry
    );
    const rebound = crypto.registerEnrollmentPublicKey(
      { challengeId: second.id, publicKeySpkiBase64: key.spkiBase64 },
      afterExpiry
    );
    const secondPayload = stableJson(second.payload);
    assert.equal(rebound.endpointId, second.payload.endpointId);
    assert.equal(rebound.enrollmentChallengeId, second.id);
    assert.equal(
      crypto.verifyEnrollmentProof(
        firstPayload,
        signature(key.privateKey, firstPayload),
        key.fingerprint
      ),
      false
    );
    assert.equal(
      crypto.verifyEnrollmentProof(
        secondPayload,
        signature(key.privateKey, secondPayload),
        key.fingerprint
      ),
      true
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects a mismatched fingerprint, unsupported key and immutable key replacement", () => {
    const { database, crypto, mission, registry } = setup();
    const key = keyMaterial();
    const wrongKey = keyMaterial();
    const challenge = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
      },
      "endpoint operator",
      now
    );
    assert.throws(
      () =>
        crypto.registerEnrollmentPublicKey(
          { challengeId: challenge.id, publicKeySpkiBase64: wrongKey.spkiBase64 },
          now
        ),
      /ENDPOINT_PUBLIC_KEY_FINGERPRINT_MISMATCH/
    );
    const rsa = keyMaterial("rsa");
    assert.throws(
      () =>
        crypto.registerEnrollmentPublicKey(
          { challengeId: challenge.id, publicKeySpkiBase64: rsa.spkiBase64 },
          now
        ),
      /ENDPOINT_PUBLIC_KEY_ALGORITHM_INVALID/
    );
    crypto.registerEnrollmentPublicKey(
      { challengeId: challenge.id, publicKeySpkiBase64: key.spkiBase64 },
      now
    );
    assert.throws(
      () =>
        database
          .prepare(
            `UPDATE endpoint_public_keys
             SET public_key_spki_base64 = ?
             WHERE certificate_fingerprint_sha256 = ?`
          )
          .run(wrongKey.spkiBase64, key.fingerprint),
      /ENDPOINT_PUBLIC_KEY_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare(
            "DELETE FROM endpoint_public_keys WHERE certificate_fingerprint_sha256 = ?"
          )
          .run(key.fingerprint),
      /ENDPOINT_PUBLIC_KEY_IMMUTABLE/
    );
    database.close();
  });

  it("fails closed for bad proofs, post-approval registration and revoked identities", () => {
    const { database, crypto, mission, registry } = setup();
    const key = keyMaterial();
    const other = keyMaterial();
    const challenge = registry.requestEnrollment(
      {
        missionId: mission.id,
        certificateFingerprintSha256: key.fingerprint,
        identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
      },
      "endpoint operator",
      now
    );
    crypto.registerEnrollmentPublicKey(
      { challengeId: challenge.id, publicKeySpkiBase64: key.spkiBase64 },
      now
    );
    const payload = stableJson(challenge.payload);
    assert.equal(
      crypto.verifyEnrollmentProof(payload, signature(other.privateKey, payload), key.fingerprint),
      false
    );
    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: key.fingerprint,
        proofSignatureBase64: signature(key.privateKey, payload)
      },
      "approving operator",
      now
    );
    assert.throws(
      () =>
        crypto.registerEnrollmentPublicKey(
          { challengeId: challenge.id, publicKeySpkiBase64: key.spkiBase64 },
          now
        ),
      /ENDPOINT_ENROLLMENT_NOT_PENDING/
    );

    const telemetryCore = {
      schemaVersion: 1,
      missionId: identity.missionId,
      connectorId: identity.connectorId,
      endpointId: identity.endpointId,
      certificateFingerprintSha256: identity.certificateFingerprintSha256,
      sequenceStart: 0,
      sequenceEnd: 0,
      previousBatchHash: null,
      events: [{}]
    };
    const telemetryPayload = stableJson(telemetryCore);
    assert.equal(
      crypto.verifyTelemetrySignature(
        telemetryPayload,
        signature(key.privateKey, telemetryPayload),
        key.fingerprint
      ),
      true
    );
    registry.revokeEndpoint(
      identity.endpointId,
      "security operator",
      "Fixture endpoint was deliberately removed.",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(
      crypto.verifyTelemetrySignature(
        telemetryPayload,
        signature(key.privateKey, telemetryPayload),
        key.fingerprint
      ),
      false
    );
    database.close();
  });
});
