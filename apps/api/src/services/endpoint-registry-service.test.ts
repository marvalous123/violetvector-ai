import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import {
  EndpointRegistryService,
  type EnrollmentChallenge
} from "./endpoint-registry-service.js";
import { MissionService } from "./mission-service.js";

const now = new Date("2026-07-19T12:00:00.000Z");
const proof = "A".repeat(64);

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Endpoint trust test", now);
  const registry = new EndpointRegistryService(
    database,
    audit,
    (payload, signature, fingerprint) =>
      payload.includes('"schemaVersion":1') &&
      signature === proof &&
      fingerprint === "a".repeat(64),
    { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
  );
  return { database, audit, mission, registry };
}

function request(
  registry: EndpointRegistryService,
  missionId: string,
  fingerprint = "a".repeat(64),
  at = now,
  expiresAt = new Date(at.valueOf() + 60 * 60_000)
): EnrollmentChallenge {
  return registry.requestEnrollment(
    {
      missionId,
      certificateFingerprintSha256: fingerprint,
      identityExpiresAt: expiresAt.toISOString()
    },
    "endpoint operator",
    at
  );
}

describe("endpoint registry trust boundary", () => {
  it("matches the native Gate C0b canonical enrollment vector", () => {
    const payload = {
      schemaVersion: 1,
      challengeId: "enrollment-11111111-1111-4111-8111-111111111111",
      missionId: "22222222-2222-4222-8222-222222222222",
      connectorId: "connector-33333333-3333-4333-8333-333333333333",
      endpointId: "endpoint-44444444-4444-4444-8444-444444444444",
      certificateFingerprintSha256: "a".repeat(64),
      nonceBase64Url: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
      requestedAt: "2026-08-03T09:00:00.000Z",
      challengeExpiresAt: "2026-08-03T09:05:00.000Z",
      identityExpiresAt: "2026-08-10T09:00:00.000Z"
    };
    assert.equal(
      stableJson(payload),
      '{"certificateFingerprintSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","challengeExpiresAt":"2026-08-03T09:05:00.000Z","challengeId":"enrollment-11111111-1111-4111-8111-111111111111","connectorId":"connector-33333333-3333-4333-8333-333333333333","endpointId":"endpoint-44444444-4444-4444-8444-444444444444","identityExpiresAt":"2026-08-10T09:00:00.000Z","missionId":"22222222-2222-4222-8222-222222222222","nonceBase64Url":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","requestedAt":"2026-08-03T09:00:00.000Z","schemaVersion":1}'
    );
    assert.equal(
      canonicalHash(payload),
      "6724de9d24699049abd9c66a5b0f819018551e4227f64855a97e9eed5cb2dc82"
    );
  });

  it("creates server-owned challenge material and requires explicit proof-bound approval", () => {
    const { database, audit, mission, registry } = setup();
    const challenge = request(registry, mission.id);
    assert.match(challenge.payload.connectorId, /^connector-[a-f0-9-]{36}$/);
    assert.match(challenge.payload.endpointId, /^endpoint-[a-f0-9-]{36}$/);
    assert.equal(challenge.payload.missionId, mission.id);
    assert.equal(challenge.payload.certificateFingerprintSha256, "a".repeat(64));
    assert.equal(canonicalHash(challenge.payload), challenge.challengeHash);

    assert.throws(
      () =>
        registry.approveEnrollment(
          {
            challengeId: challenge.id,
            confirmedCertificateFingerprintSha256: "a".repeat(64),
            proofSignatureBase64: "B".repeat(64)
          },
          "approving operator",
          now
        ),
      /ENDPOINT_ENROLLMENT_PROOF_INVALID/
    );
    assert.throws(
      () =>
        registry.approveEnrollment(
          {
            challengeId: challenge.id,
            confirmedCertificateFingerprintSha256: "b".repeat(64),
            proofSignatureBase64: proof
          },
          "approving operator",
          now
        ),
      /ENDPOINT_CERTIFICATE_MISMATCH/
    );

    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: "a".repeat(64),
        proofSignatureBase64: proof
      },
      "approving operator",
      now
    );
    assert.equal(identity.endpointId, challenge.payload.endpointId);
    assert.equal(identity.connectorId, challenge.payload.connectorId);
    assert.equal(identity.missionId, mission.id);
    assert.equal(identity.status, "active");
    assert.equal(identity.currentBootId, null);
    assert.throws(
      () =>
        registry.approveEnrollment(
          {
            challengeId: challenge.id,
            confirmedCertificateFingerprintSha256: "a".repeat(64),
            proofSignatureBase64: proof
          },
          "approving operator",
          now
        ),
      /ENDPOINT_ENROLLMENT_NOT_PENDING/
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("expires unused challenges and identities fail closed", () => {
    const { database, mission, registry } = setup();
    const challenge = request(registry, mission.id);
    assert.throws(
      () =>
        registry.approveEnrollment(
          {
            challengeId: challenge.id,
            confirmedCertificateFingerprintSha256: "a".repeat(64),
            proofSignatureBase64: proof
          },
          "approving operator",
          new Date(now.valueOf() + 30_001)
        ),
      /ENDPOINT_ENROLLMENT_EXPIRED/
    );
    const challengeStatus = database
      .prepare("SELECT status FROM endpoint_enrollment_challenges WHERE id = ?")
      .get(challenge.id) as { status: string };
    assert.equal(challengeStatus.status, "expired");
    const retried = request(registry, mission.id, "a".repeat(64), new Date(now.valueOf() + 31_000));
    assert.notEqual(retried.id, challenge.id);

    const secondMission = new MissionService(database).createMission(
      "Second endpoint trust test",
      new Date(now.valueOf() + 1)
    );
    const secondRegistry = new EndpointRegistryService(
      database,
      new AuditService(database),
      (_payload, signature, fingerprint) => signature === proof && fingerprint === "b".repeat(64),
      { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
    );
    const shortIdentity = request(
      secondRegistry,
      secondMission.id,
      "b".repeat(64),
      now,
      new Date(now.valueOf() + 31_000)
    );
    const identity = secondRegistry.approveEnrollment(
      {
        challengeId: shortIdentity.id,
        confirmedCertificateFingerprintSha256: "b".repeat(64),
        proofSignatureBase64: proof
      },
      "approving operator",
      now
    );
    assert.throws(
      () =>
        secondRegistry.authenticateBatch(
          {
            missionId: identity.missionId,
            connectorId: identity.connectorId,
            endpointId: identity.endpointId,
            certificateFingerprintSha256: identity.certificateFingerprintSha256
          },
          new Date(now.valueOf() + 31_001)
        ),
      /ENDPOINT_IDENTITY_EXPIRED/
    );
    assert.equal(secondRegistry.getIdentity(identity.endpointId).status, "expired");
    database.close();
  });

  it("binds mission, connector, endpoint and certificate and supports audited revocation", () => {
    const { database, audit, mission, registry } = setup();
    const challenge = request(registry, mission.id);
    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: "a".repeat(64),
        proofSignatureBase64: proof
      },
      "approving operator",
      now
    );
    assert.throws(
      () =>
        registry.authenticateBatch({
          missionId: "wrong-mission",
          connectorId: identity.connectorId,
          endpointId: identity.endpointId,
          certificateFingerprintSha256: identity.certificateFingerprintSha256
        }),
      /ENDPOINT_IDENTITY_BINDING_MISMATCH/
    );
    assert.throws(
      () =>
        registry.authenticateBatch({
          missionId: identity.missionId,
          connectorId: identity.connectorId,
          endpointId: identity.endpointId,
          certificateFingerprintSha256: "b".repeat(64)
        }),
      /ENDPOINT_IDENTITY_BINDING_MISMATCH/
    );

    const revoked = registry.revokeEndpoint(
      identity.endpointId,
      "security operator",
      "Connector was deliberately removed from the lab.",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(revoked.status, "revoked");
    assert.throws(
      () =>
        registry.authenticateBatch({
          missionId: identity.missionId,
          connectorId: identity.connectorId,
          endpointId: identity.endpointId,
          certificateFingerprintSha256: identity.certificateFingerprintSha256
        }),
      /ENDPOINT_IDENTITY_NOT_ACTIVE/
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rotates to a fresh identity atomically and revokes the replaced key", () => {
    const { database, audit, mission, registry } = setup();
    const originalChallenge = request(registry, mission.id);
    const original = registry.approveEnrollment(
      {
        challengeId: originalChallenge.id,
        confirmedCertificateFingerprintSha256: "a".repeat(64),
        proofSignatureBase64: proof
      },
      "approving operator",
      now
    );
    const renewalRegistry = new EndpointRegistryService(
      database,
      audit,
      (_payload, signature, candidateFingerprint) =>
        signature === proof &&
        (candidateFingerprint === "a".repeat(64) ||
          candidateFingerprint === "b".repeat(64)),
      { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
    );
    assert.throws(
      () =>
        renewalRegistry.requestRenewal(
          original.endpointId,
          {
            certificateFingerprintSha256: "a".repeat(64),
            identityExpiresAt: new Date(now.valueOf() + 2 * 60 * 60_000).toISOString(),
            reason: "Routine protected-key rotation."
          },
          "renewal operator",
          now
        ),
      /ENDPOINT_RENEWAL_KEY_REUSE_FORBIDDEN/
    );
    const requested = renewalRegistry.requestRenewal(
      original.endpointId,
      {
        certificateFingerprintSha256: "b".repeat(64),
        identityExpiresAt: new Date(now.valueOf() + 2 * 60 * 60_000).toISOString(),
        reason: "Routine protected-key rotation."
      },
      "renewal operator",
      now
    );
    assert.equal(requested.renewal.status, "pending");
    assert.equal(requested.renewal.previousEndpointId, original.endpointId);
    assert.notEqual(requested.renewal.replacementEndpointId, original.endpointId);
    assert.throws(
      () =>
        renewalRegistry.requestRenewal(
          original.endpointId,
          {
            certificateFingerprintSha256: "c".repeat(64),
            identityExpiresAt: new Date(now.valueOf() + 2 * 60 * 60_000).toISOString(),
            reason: "A second overlapping rotation must be denied."
          },
          "renewal operator",
          now
        ),
      /ENDPOINT_RENEWAL_ALREADY_PENDING/
    );

    const activated = renewalRegistry.approveRenewal(
      {
        challengeId: requested.challenge.id,
        confirmedCertificateFingerprintSha256: "b".repeat(64),
        proofSignatureBase64: proof
      },
      "renewal approver",
      new Date(now.valueOf() + 1_000)
    );
    assert.equal(activated.renewal.status, "activated");
    assert.equal(activated.previousIdentity.status, "revoked");
    assert.equal(activated.replacementIdentity.status, "active");
    assert.equal(
      activated.replacementIdentity.certificateFingerprintSha256,
      "b".repeat(64)
    );
    assert.throws(
      () =>
        renewalRegistry.authenticateBatch({
          missionId: original.missionId,
          connectorId: original.connectorId,
          endpointId: original.endpointId,
          certificateFingerprintSha256: original.certificateFingerprintSha256
        }, new Date(now.valueOf() + 1_000)),
      /ENDPOINT_IDENTITY_NOT_ACTIVE/
    );
    assert.equal(
      renewalRegistry.authenticateBatch({
        missionId: activated.replacementIdentity.missionId,
        connectorId: activated.replacementIdentity.connectorId,
        endpointId: activated.replacementIdentity.endpointId,
        certificateFingerprintSha256:
          activated.replacementIdentity.certificateFingerprintSha256
      }, new Date(now.valueOf() + 1_000)).status,
      "active"
    );
    assert.throws(
      () =>
        database
          .prepare("UPDATE endpoint_identity_renewals SET reason = ? WHERE id = ?")
          .run("tampered reason", activated.renewal.id),
      /ENDPOINT_RENEWAL_CORE_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare(
            "UPDATE endpoint_identity_renewals SET activated_by = ? WHERE id = ?"
          )
          .run("tampered approver", activated.renewal.id),
      /ENDPOINT_RENEWAL_ACTIVATION_IMMUTABLE/
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("keeps enrollment and identity bindings immutable", () => {
    const { database, mission, registry } = setup();
    const challenge = request(registry, mission.id);
    const identity = registry.approveEnrollment(
      {
        challengeId: challenge.id,
        confirmedCertificateFingerprintSha256: "a".repeat(64),
        proofSignatureBase64: proof
      },
      "approving operator",
      now
    );
    assert.throws(
      () =>
        database
          .prepare("UPDATE endpoint_identities SET connector_id = ? WHERE endpoint_id = ?")
          .run("connector-00000000-0000-0000-0000-000000000000", identity.endpointId),
      /ENDPOINT_IDENTITY_BINDING_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("DELETE FROM endpoint_enrollment_challenges WHERE id = ?")
          .run(challenge.id),
      /ENDPOINT_ENROLLMENT_IMMUTABLE/
    );
    database.close();
  });
});
