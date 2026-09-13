import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import { BLUE_RULES } from "./blue-detection-service.js";
import {
  EndpointFactCorrelationService,
  LIVE_ENDPOINT_RULE_IDS,
  endpointCapabilityReportHash,
  endpointFactBatchHash,
  endpointFactReceiptSchema,
  signedEndpointCapabilityReportSchema,
  signedEndpointFactBatchSchema,
  type EndpointFactFieldName,
  type EndpointFactFields,
  type EndpointFactEventFamily,
  type EndpointFactProvider,
  type EndpointFactChannel,
  type SignedEndpointCapabilityReport,
  type SignedEndpointFactBatch
} from "./endpoint-fact-correlation-service.js";
import {
  EndpointRegistryService,
  type EndpointIdentity
} from "./endpoint-registry-service.js";
import { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";
import {
  WINDOWS_GENUINE_SOURCE_VALIDATIONS,
  isGenuineLiveEligible
} from "./windows-genuine-source-validation.js";

const now = new Date("2026-07-19T12:00:00.000Z");
const proofSignature = "A".repeat(64);
const connectorSignature = "B".repeat(64);
const fingerprint = "a".repeat(64);

interface NativeTelemetryWireVector {
  readonly vectorVersion: 1;
  readonly core: Omit<SignedEndpointFactBatch, "batchHash" | "signatureBase64">;
  readonly canonicalPayload: string;
  readonly batchHash: string;
  readonly publicKeySpkiBase64: string;
  readonly signatureBase64: string;
}

const nativeTelemetryWireVector = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../../../test-vectors/windows-sensor/minimized-fact-batch-v1.json",
        import.meta.url
      )
    ),
    "utf8"
  )
) as NativeTelemetryWireVector;

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const mission = new MissionService(database, audit).createMission(
    "Endpoint fact correlation test",
    now
  );
  const registry = new EndpointRegistryService(
    database,
    audit,
    (_payload, signature, candidateFingerprint) =>
      signature === proofSignature && candidateFingerprint === fingerprint,
    { challengeTtlMs: 30_000, maxIdentityTtlMs: 24 * 60 * 60_000 }
  );
  const challenge = registry.requestEnrollment(
    {
      missionId: mission.id,
      certificateFingerprintSha256: fingerprint,
      identityExpiresAt: new Date(now.valueOf() + 60 * 60_000).toISOString()
    },
    "endpoint operator",
    now
  );
  const identity = registry.approveEnrollment(
    {
      challengeId: challenge.id,
      confirmedCertificateFingerprintSha256: fingerprint,
      proofSignatureBase64: proofSignature
    },
    "approving operator",
    now
  );
  const evidence = new EvidenceService(
    database,
    mkdtempSync(join(tmpdir(), "war-room-endpoint-facts-")),
    audit
  );
  const service = new EndpointFactCorrelationService(
    database,
    registry,
    evidence,
    audit,
    (_payload, signature, candidateFingerprint) =>
      signature === connectorSignature && candidateFingerprint === fingerprint
  );
  return { database, audit, mission, identity, evidence, service };
}

function streamForFamily(eventFamily: EndpointFactEventFamily): {
  provider: EndpointFactProvider;
  channel: EndpointFactChannel;
} {
  switch (eventFamily) {
    case "event-log-impairment":
      return { provider: "windows-eventlog", channel: "eventlog-admin" };
    case "process-access":
    case "file-access":
    case "image-load":
    case "file-attribute-change":
      return { provider: "windows-sysmon", channel: "sysmon-operational" };
    case "process-start":
    case "authentication":
    case "ticket-request":
    case "authentication-component-change":
    case "certificate-key-access":
    case "event-log-clear":
    case "scheduled-task-change":
    case "service-change":
      return { provider: "windows-security", channel: "security" };
    case "security-control-change":
      return { provider: "windows-defender", channel: "defender-operational" };
    case "firewall-policy-change":
      return { provider: "windows-firewall", channel: "firewall-operational" };
  }
}

function capabilityReport(
  identity: EndpointIdentity,
  overrides: Partial<{
    provider: EndpointFactProvider;
    channel: EndpointFactChannel;
    eventFamily: EndpointFactEventFamily;
    fields: EndpointFactFieldName[];
    filterHash: string;
    loss: SignedEndpointCapabilityReport["loss"];
    continuity: SignedEndpointCapabilityReport["continuity"];
    continuousSince: string;
    lastSuccessfulReadAt: string;
    observedAt: string;
    freshnessSeconds: number;
  }> = {}
): SignedEndpointCapabilityReport {
  const eventFamily = overrides.eventFamily ?? "event-log-clear";
  const stream = streamForFamily(eventFamily);
  const core = {
    schemaVersion: 1 as const,
    missionId: identity.missionId,
    connectorId: identity.connectorId,
    endpointId: identity.endpointId,
    certificateFingerprintSha256: identity.certificateFingerprintSha256,
    provider: overrides.provider ?? stream.provider,
    channel: overrides.channel ?? stream.channel,
    eventFamily,
    fields: (
      overrides.fields ?? ["action", "actorTrust", "objectClass", "outcome", "subjectClass"]
    ).slice().sort() as EndpointFactFieldName[],
    filterHash: overrides.filterHash ?? "c".repeat(64),
    collectorVersion: "windows-sensor-0.1.0",
    loss: overrides.loss ?? { state: "none" as const, lostRecordCount: 0 as const },
    continuity: overrides.continuity ?? "continuous",
    continuousSince:
      overrides.continuousSince ??
      new Date(now.valueOf() - 5 * 60_000).toISOString(),
    lastSuccessfulReadAt: overrides.lastSuccessfulReadAt ?? now.toISOString(),
    observedAt: overrides.observedAt ?? now.toISOString(),
    freshnessSeconds: overrides.freshnessSeconds ?? 120
  };
  return {
    ...core,
    reportHash: endpointCapabilityReportHash(core),
    signatureBase64: connectorSignature
  };
}

function factBatch(
  identity: EndpointIdentity,
  capability: {
    id: string;
    provider: EndpointFactProvider;
    channel: EndpointFactChannel;
    eventFamily: EndpointFactEventFamily;
    filterHash: string;
  },
  fields: EndpointFactFields,
  overrides: Partial<{
    bootId: string;
    batchSequence: number;
    previousBatchHash: string | null;
    factId: string;
    occurredAt: string;
    sourceRecordIdHash: string;
    filterHash: string;
  }> = {}
): SignedEndpointFactBatch {
  const core = {
    schemaVersion: 1 as const,
    missionId: identity.missionId,
    connectorId: identity.connectorId,
    endpointId: identity.endpointId,
    certificateFingerprintSha256: identity.certificateFingerprintSha256,
    capabilitySnapshotId: capability.id,
    bootId: overrides.bootId ?? "boot-test-00000001",
    batchSequence: overrides.batchSequence ?? 0,
    previousBatchHash: overrides.previousBatchHash ?? null,
    provider: capability.provider,
    channel: capability.channel,
    eventFamily: capability.eventFamily,
    filterHash: overrides.filterHash ?? capability.filterHash,
    facts: [
      {
        factId: overrides.factId ?? "fact-eventlog-00000001",
        occurredAt:
          overrides.occurredAt ??
          new Date(now.valueOf() - 30_000).toISOString(),
        sourceRecordIdHash: overrides.sourceRecordIdHash ?? "d".repeat(64),
        fields
      }
    ]
  };
  return {
    ...core,
    batchHash: endpointFactBatchHash(core),
    signatureBase64: connectorSignature
  };
}

const logClearFields: EndpointFactFields = {
  actorTrust: "untrusted",
  action: "clear",
  subjectClass: "admin-tool",
  objectClass: "event-log",
  outcome: "success"
};

const allFactFields: EndpointFactFieldName[] = [
  "action",
  "actorTrust",
  "baselineState",
  "contentState",
  "elevated",
  "failureCountBucket",
  "metadataState",
  "objectClass",
  "originZone",
  "outcome",
  "parentClass",
  "recentExecution",
  "signerState",
  "subjectClass",
  "visibilityState"
];

const liveRuleFixtures: Array<{
  ruleId: string;
  eventFamily: EndpointFactEventFamily;
  provider?: EndpointFactProvider;
  channel?: EndpointFactChannel;
  fields: EndpointFactFields;
}> = [
  { ruleId: "BR-CRED-001", eventFamily: "process-access", fields: { actorTrust: "untrusted", action: "open-process", subjectClass: "other", objectClass: "auth-memory" } },
  { ruleId: "BR-CRED-002", eventFamily: "file-access", provider: "windows-security", channel: "security", fields: { actorTrust: "untrusted", action: "read", subjectClass: "other", objectClass: "credential-store", baselineState: "rare" } },
  { ruleId: "BR-CRED-003", eventFamily: "file-access", provider: "windows-security", channel: "security", fields: { actorTrust: "untrusted", action: "read", subjectClass: "other", objectClass: "unsecured-secret", baselineState: "rare" } },
  { ruleId: "BR-CRED-004", eventFamily: "process-access", fields: { actorTrust: "untrusted", action: "register", subjectClass: "other", objectClass: "input-device", signerState: "unsigned" } },
  { ruleId: "BR-CRED-005", eventFamily: "authentication", fields: { actorTrust: "unknown", action: "authenticate", subjectClass: "other", objectClass: "authentication", failureCountBucket: "burst", outcome: "success" } },
  { ruleId: "BR-CRED-006", eventFamily: "ticket-request", fields: { actorTrust: "unknown", action: "request", subjectClass: "other", objectClass: "kerberos-ticket", baselineState: "rare", outcome: "success" } },
  { ruleId: "BR-CRED-007", eventFamily: "file-access", fields: { actorTrust: "untrusted", action: "read", subjectClass: "other", objectClass: "session-store", baselineState: "new" } },
  { ruleId: "BR-CRED-008", eventFamily: "file-access", fields: { actorTrust: "untrusted", action: "read", subjectClass: "other", objectClass: "application-token", baselineState: "new" } },
  { ruleId: "BR-CRED-009", eventFamily: "authentication-component-change", fields: { actorTrust: "untrusted", action: "modify", subjectClass: "admin-tool", objectClass: "authentication-component", outcome: "success" } },
  { ruleId: "BR-CRED-010", eventFamily: "certificate-key-access", fields: { actorTrust: "untrusted", action: "export", subjectClass: "other", objectClass: "authentication-key", baselineState: "new", outcome: "success" } },
  { ruleId: "BR-PAYLOAD-001", eventFamily: "process-start", provider: "windows-sysmon", channel: "sysmon-operational", fields: { actorTrust: "untrusted", action: "start", subjectClass: "other", objectClass: "executable-artifact", parentClass: "office", signerState: "unsigned", originZone: "remote" } },
  { ruleId: "BR-PAYLOAD-002", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "powershell", objectClass: "encoded-content", parentClass: "browser" } },
  { ruleId: "BR-PAYLOAD-003", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "mshta", objectClass: "other", originZone: "remote" } },
  { ruleId: "BR-PAYLOAD-004", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "msiexec", objectClass: "installer-package", originZone: "remote", signerState: "unsigned" } },
  { ruleId: "BR-PAYLOAD-005", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "regsvr32", objectClass: "module", originZone: "user-writable", signerState: "signed-untrusted" } },
  { ruleId: "BR-PAYLOAD-006", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "rundll32", objectClass: "module", originZone: "user-writable", signerState: "unsigned" } },
  { ruleId: "BR-PAYLOAD-007", eventFamily: "image-load", fields: { actorTrust: "unknown", action: "load", subjectClass: "system-binary", objectClass: "module", originZone: "user-writable", signerState: "unsigned", baselineState: "new" } },
  { ruleId: "BR-PAYLOAD-008", eventFamily: "process-access", fields: { actorTrust: "untrusted", action: "write-memory", subjectClass: "other", objectClass: "process-memory", baselineState: "rare" } },
  { ruleId: "BR-PAYLOAD-009", eventFamily: "scheduled-task-change", fields: { actorTrust: "untrusted", action: "create", subjectClass: "admin-tool", objectClass: "scheduled-task", originZone: "user-writable" } },
  { ruleId: "BR-PAYLOAD-010", eventFamily: "service-change", fields: { actorTrust: "untrusted", action: "create", subjectClass: "admin-tool", objectClass: "service", signerState: "unsigned", originZone: "user-writable" } },
  { ruleId: "BR-EVASION-001", eventFamily: "security-control-change", fields: { actorTrust: "untrusted", action: "disable", subjectClass: "admin-tool", objectClass: "security-control", outcome: "success" } },
  { ruleId: "BR-EVASION-002", eventFamily: "event-log-impairment", provider: "windows-security", channel: "security", fields: { actorTrust: "untrusted", action: "disable", subjectClass: "admin-tool", objectClass: "audit-policy", outcome: "success" } },
  { ruleId: "BR-EVASION-003", eventFamily: "event-log-clear", fields: { actorTrust: "untrusted", action: "clear", subjectClass: "admin-tool", objectClass: "event-log", outcome: "success" } },
  { ruleId: "BR-EVASION-004", eventFamily: "firewall-policy-change", provider: "windows-security", channel: "security", fields: { actorTrust: "untrusted", action: "remove-rule", subjectClass: "admin-tool", objectClass: "firewall-policy", outcome: "success" } },
  { ruleId: "BR-EVASION-005", eventFamily: "process-access", fields: { actorTrust: "untrusted", action: "write-memory", subjectClass: "other", objectClass: "process-memory", baselineState: "new" } },
  { ruleId: "BR-EVASION-006", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "mshta", objectClass: "other", originZone: "remote" } },
  { ruleId: "BR-EVASION-007", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "powershell", objectClass: "encoded-content", parentClass: "shell", contentState: "encoded" } },
  { ruleId: "BR-EVASION-008", eventFamily: "process-start", fields: { actorTrust: "untrusted", action: "start", subjectClass: "system-binary", objectClass: "binary-metadata", originZone: "user-writable", metadataState: "mismatch" } },
  { ruleId: "BR-EVASION-009", eventFamily: "file-attribute-change", provider: "windows-security", channel: "security", fields: { actorTrust: "untrusted", action: "hide", subjectClass: "other", objectClass: "hidden-artifact", visibilityState: "hidden" } },
  { ruleId: "BR-EVASION-010", eventFamily: "file-access", fields: { actorTrust: "untrusted", action: "delete", subjectClass: "other", objectClass: "executable-artifact", recentExecution: true } }
];

describe("minimized endpoint facts and server-owned correlation", () => {
  it("keeps Gate C0a receipts exact and data-only", () => {
    const receipt = {
      schemaVersion: 1,
      status: "accepted",
      batchHash: "a".repeat(64),
      batchSequence: 0,
      factCount: 1
    };
    assert.equal(endpointFactReceiptSchema.safeParse(receipt).success, true);
    assert.equal(
      endpointFactReceiptSchema.safeParse({ ...receipt, command: "whoami" }).success,
      false
    );
    assert.equal(
      endpointFactReceiptSchema.safeParse({ ...receipt, retryAfter: 1 }).success,
      false
    );
  });

  it("matches the native minimized-fact canonical wire vector", () => {
    const vector = nativeTelemetryWireVector;
    assert.equal(vector.vectorVersion, 1);
    assert.equal(stableJson(vector.core), vector.canonicalPayload);
    assert.equal(endpointFactBatchHash(vector.core), vector.batchHash);
    assert.equal(
      createHash("sha256")
        .update(Buffer.from(vector.publicKeySpkiBase64, "base64"))
        .digest("hex"),
      vector.core.certificateFingerprintSha256
    );
    const publicKey = createPublicKey({
      key: Buffer.from(vector.publicKeySpkiBase64, "base64"),
      format: "der",
      type: "spki"
    });
    assert.equal(
      verifySignature(
        "sha256",
        Buffer.from(vector.canonicalPayload, "utf8"),
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(vector.signatureBase64, "base64")
      ),
      true
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse({
        ...vector.core,
        batchHash: vector.batchHash,
        signatureBase64: vector.signatureBase64
      }).success,
      true
    );
  });

  it("enforces the native minimized-fact sequence and timestamp boundaries", () => {
    const signedVector = {
      ...nativeTelemetryWireVector.core,
      batchHash: nativeTelemetryWireVector.batchHash,
      signatureBase64: nativeTelemetryWireVector.signatureBase64
    };
    const withOccurredAt = (occurredAt: string) => ({
      ...signedVector,
      facts: signedVector.facts.map((fact, index) =>
        index === 0 ? { ...fact, occurredAt } : fact
      )
    });

    assert.equal(
      signedEndpointFactBatchSchema.safeParse({
        ...signedVector,
        batchSequence: Number.MAX_SAFE_INTEGER
      }).success,
      true
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse({
        ...signedVector,
        batchSequence: Number.MAX_SAFE_INTEGER + 1
      }).success,
      false
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse(
        withOccurredAt("2026-07-19T12:00:00.1234567890Z")
      ).success,
      false
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse(
        withOccurredAt("2026-07-19T12:00:00+14:01")
      ).success,
      false
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse(
        withOccurredAt("2026-02-30T12:00:00Z")
      ).success,
      false
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse(
        withOccurredAt("2026-07-19T12:00:00+14:00")
      ).success,
      true
    );
    assert.equal(
      signedEndpointFactBatchSchema.safeParse(
        withOccurredAt("9999-12-31T23:59:59.999999999+14:00")
      ).success,
      true
    );
  });

  it("accepts the exact SCM System stream without satisfying BR-PAYLOAD-010", () => {
    const { database, identity, service } = setup();
    const fields: EndpointFactFields = {
      actorTrust: "unknown",
      action: "create",
      subjectClass: "other",
      objectClass: "service",
      outcome: "unknown"
    };
    const report = capabilityReport(identity, {
      provider: "windows-scm",
      channel: "system",
      eventFamily: "service-change",
      fields: [
        "actorTrust",
        "action",
        "subjectClass",
        "objectClass",
        "outcome"
      ]
    });

    assert.equal(signedEndpointCapabilityReportSchema.safeParse(report).success, true);
    const capability = service.recordCapability(report, now);
    const batch = factBatch(identity, capability, fields);
    assert.equal(signedEndpointFactBatchSchema.safeParse(batch).success, true);
    service.ingestFacts(batch, now);

    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: ["BR-PAYLOAD-010"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.result.status, "blocked-coverage");
    assert.equal(run.result.verdict, "coverage-blocked");
    assert.equal(run.result.alerts.length, 0);
    assert.equal(run.result.coverage[0]?.provider, "windows-security");
    assert.equal(run.result.coverage[0]?.channel, "security");
    assert.match(run.result.coverage[0]?.reason ?? "", /exact required stream/);
    assert.throws(
      () =>
        service.recordCapability(
          capabilityReport(identity, {
            provider: "windows-scm",
            channel: "system",
            eventFamily: "service-change",
            fields: [
              "actorTrust",
              "action",
              "subjectClass",
              "objectClass",
              "signerState",
              "originZone"
            ]
          }),
          now
        ),
      /ENDPOINT_SCM_FIELD_PROFILE_INVALID/
    );
    assert.throws(
      () =>
        service.ingestFacts(
          factBatch(identity, capability, {
            actorTrust: "untrusted",
            action: "create",
            subjectClass: "admin-tool",
            objectClass: "service",
            signerState: "unsigned",
            originZone: "user-writable"
          }),
          now
        ),
      /ENDPOINT_SCM_FACT_PROFILE_INVALID/
    );
    assert.throws(
      () =>
        service.recordCapability(
          capabilityReport(identity, {
            provider: "windows-scm",
            channel: "security",
            eventFamily: "service-change"
          }),
          now
        ),
      /ENDPOINT_FACT_STREAM_INVALID/
    );
    database.close();
  });

  it("accepts one fresh coverage-blocked SCM bootstrap fact without enabling live coverage", () => {
    const { database, identity, service } = setup();
    const capability = service.recordCapability(
      capabilityReport(identity, {
        provider: "windows-scm",
        channel: "system",
        eventFamily: "service-change",
        fields: ["action", "actorTrust", "objectClass", "outcome", "subjectClass"],
        loss: { state: "unknown", lostRecordCount: null },
        continuity: "unknown",
        continuousSince: now.toISOString(),
        lastSuccessfulReadAt: now.toISOString(),
        observedAt: now.toISOString(),
        freshnessSeconds: 300
      }),
      now
    );
    assert.equal(capability.health, "degraded");
    const fields: EndpointFactFields = {
      actorTrust: "unknown",
      action: "create",
      subjectClass: "other",
      objectClass: "service",
      outcome: "unknown"
    };
    const accepted = service.ingestFacts(
      factBatch(identity, capability, fields),
      now
    );
    assert.equal(accepted.batchSequence, 0);
    assert.equal(accepted.factCount, 1);
    assert.throws(
      () =>
        service.ingestFacts(
          factBatch(identity, capability, fields, {
            batchSequence: 1,
            previousBatchHash: accepted.batchHash,
            factId: "fact-scm-bootstrap-00000002",
            sourceRecordIdHash: "e".repeat(64)
          }),
          now
        ),
      /ENDPOINT_FACT_CAPABILITY_NOT_HEALTHY/
    );
    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: ["BR-PAYLOAD-010"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.result.status, "blocked-coverage");
    assert.equal(run.result.verdict, "coverage-blocked");
    assert.equal(run.result.alerts.length, 0);
    database.close();
  });

  it("covers every defensive rule while unsupported genuine sources fail closed", () => {
    assert.deepEqual(
      [...LIVE_ENDPOINT_RULE_IDS].sort(),
      BLUE_RULES.map((rule) => rule.id).sort()
    );
    assert.equal(liveRuleFixtures.length, 30);
    const { database, identity, service } = setup();
    const fixtureStreamKey = (fixture: (typeof liveRuleFixtures)[number]) => {
      const stream = streamForFamily(fixture.eventFamily);
      return `${fixture.provider ?? stream.provider}|${fixture.channel ?? stream.channel}|${fixture.eventFamily}`;
    };
    const capabilities = new Map<string, ReturnType<typeof service.recordCapability>>();
    for (const fixture of liveRuleFixtures) {
      const key = fixtureStreamKey(fixture);
      if (capabilities.has(key)) continue;
      const stream = streamForFamily(fixture.eventFamily);
      capabilities.set(
        key,
        service.recordCapability(
          capabilityReport(identity, {
            eventFamily: fixture.eventFamily,
            provider: fixture.provider ?? stream.provider,
            channel: fixture.channel ?? stream.channel,
            fields: allFactFields
          }),
          now
        )
      );
    }
    let previousBatchHash: string | null = null;
    liveRuleFixtures.forEach((fixture, index) => {
      const capability = capabilities.get(fixtureStreamKey(fixture))!;
      const accepted = service.ingestFacts(
        factBatch(identity, capability, fixture.fields, {
          batchSequence: index,
          previousBatchHash,
          factId: `fact-live-rule-${String(index + 1).padStart(3, "0")}`,
          sourceRecordIdHash: (index + 1).toString(16).padStart(64, "0")
        }),
        now
      );
      previousBatchHash = accepted.batchHash;
    });
    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: [...LIVE_ENDPOINT_RULE_IDS],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.result.ruleSetVersion, "live-fact-rules-v2");
    const sourceBlockedRuleIds = WINDOWS_GENUINE_SOURCE_VALIDATIONS
      .filter((validation) => !isGenuineLiveEligible(validation.assessment))
      .map((validation) => validation.ruleId)
      .sort();
    assert.equal(run.result.status, "blocked-coverage");
    assert.equal(run.result.verdict, "coverage-blocked");
    assert.equal(run.result.coverage.length, 30);
    assert.deepEqual(
      run.result.coverage
        .filter((item) => item.status === "blocked")
        .map((item) => item.ruleId)
        .sort(),
      sourceBlockedRuleIds
    );
    assert.equal(
      run.result.coverage
        .filter((item) => item.status === "blocked")
        .every((item) => item.reason.includes("Documented-source assessment")),
      true
    );
    assert.equal(run.result.alerts.length, 0);

    const eligibleRuleIds = WINDOWS_GENUINE_SOURCE_VALIDATIONS
      .filter((validation) => isGenuineLiveEligible(validation.assessment))
      .map((validation) => validation.ruleId);
    const eligibleRun = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: eligibleRuleIds,
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(eligibleRun.result.status, "completed");
    assert.equal(eligibleRun.result.coverage.length, 26);
    assert.equal(
      eligibleRun.result.coverage.every(
        (item) => item.status === "live-supported"
      ),
      true
    );
    assert.deepEqual(
      eligibleRun.result.alerts.map((alert) => alert.ruleId).sort(),
      eligibleRuleIds.sort()
    );
    database.close();
  });

  it("records signed exact-stream capability measurements and derives health over time", () => {
    const { database, audit, identity, evidence, service } = setup();
    const input = capabilityReport(identity);
    const capability = service.recordCapability(input, now);
    assert.equal(capability.health, "healthy");
    assert.equal(capability.provider, "windows-security");
    assert.equal(capability.channel, "security");
    assert.deepEqual(capability.fields, [
      "action",
      "actorTrust",
      "objectClass",
      "outcome",
      "subjectClass"
    ]);
    assert.equal(evidence.verify(capability.evidenceArtifactId), true);
    assert.equal(service.recordCapability(input, now).id, capability.id);
    assert.equal(
      service.listCapabilities(
        identity.missionId,
        identity.endpointId,
        new Date(now.valueOf() + 120_000)
      )[0]!.health,
      "stale"
    );

    const wrongStream = capabilityReport(identity, {
      provider: "windows-sysmon",
      channel: "eventlog-admin"
    });
    assert.throws(
      () => service.recordCapability(wrongStream, now),
      /ENDPOINT_FACT_STREAM_INVALID/
    );
    assert.throws(
      () =>
        service.recordCapability(
          { ...input, reportHash: "e".repeat(64) },
          now
        ),
      /ENDPOINT_CAPABILITY_HASH_MISMATCH/
    );
    assert.throws(
      () =>
        service.recordCapability(
          {
            ...input,
            fields: [...input.fields, "rawPath"]
          },
          now
        )
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("fails closed when capability storage no longer matches its sealed mission evidence", () => {
    const { database, identity, service } = setup();
    const capability = service.recordCapability(capabilityReport(identity), now);
    database.exec("DROP TRIGGER endpoint_capability_immutable_update");
    database
      .prepare("UPDATE endpoint_capability_snapshots SET report_hash = ? WHERE id = ?")
      .run("f".repeat(64), capability.id);

    assert.equal(
      service.listCapabilities(identity.missionId, identity.endpointId, now)[0]?.health,
      "degraded"
    );
    assert.throws(
      () => service.ingestFacts(factBatch(identity, capability, logClearFields), now),
      /ENDPOINT_FACT_CAPABILITY_EVIDENCE_INVALID/
    );
    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.result.status, "blocked-coverage");
    assert.match(run.result.coverage[0]!.reason, /failed integrity verification/);
    database.close();
  });

  it("accepts only signed primitive facts and creates a reviewable server-side alert", () => {
    const { database, audit, identity, evidence, service } = setup();
    const capability = service.recordCapability(capabilityReport(identity), now);
    const input = factBatch(identity, capability, logClearFields);
    const accepted = service.ingestFacts(input, now);
    assert.equal(accepted.factCount, 1);
    assert.equal(evidence.verify(accepted.evidenceArtifactId), true);
    assert.equal(service.ingestFacts(input, now).id, accepted.id);

    const stored = database
      .prepare(
        "SELECT fields_json FROM endpoint_minimized_facts WHERE batch_id = ?"
      )
      .get(accepted.id) as { fields_json: string };
    assert.equal(stored.fields_json.includes("signal"), false);
    assert.equal(stored.fields_json.includes("path"), false);
    assert.equal(stored.fields_json.includes("script"), false);

    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.integrityValid, true);
    assert.equal(run.result.status, "completed");
    assert.equal(run.result.verdict, "reviewable-alerts-produced");
    assert.equal(run.result.coverage[0]!.status, "live-supported");
    assert.equal(run.result.alerts.length, 1);
    assert.equal(run.result.alerts[0]!.signal, "windows-event-log-clear");
    assert.equal(run.result.alerts[0]!.disposition, "needs-review");
    assert.deepEqual(run.result.alerts[0]!.matchedFactIds, [
      "fact-eventlog-00000001"
    ]);
    assert.equal(
      (
        database
          .prepare("SELECT COUNT(*) AS count FROM endpoint_live_blue_alerts")
          .get() as { count: number }
      ).count,
      1
    );
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("rejects raw paths, scripts, undeclared fields, wrong filters and unsigned facts", () => {
    const { database, identity, service } = setup();
    const capability = service.recordCapability(capabilityReport(identity), now);
    const valid = factBatch(identity, capability, logClearFields);
    assert.throws(() =>
      service.ingestFacts(
        {
          ...valid,
          facts: [
            {
              ...valid.facts[0],
              fields: { ...logClearFields, rawPath: "C:\\private\\secret.txt" }
            }
          ]
        },
        now
      )
    );
    assert.throws(() =>
      service.ingestFacts(
        {
          ...valid,
          facts: [
            {
              ...valid.facts[0],
              fields: { ...logClearFields, script: "encoded content" }
            }
          ]
        },
        now
      )
    );
    const wrongFilter = factBatch(identity, capability, logClearFields, {
      filterHash: "f".repeat(64)
    });
    assert.throws(
      () => service.ingestFacts(wrongFilter, now),
      /ENDPOINT_FACT_CAPABILITY_BINDING_MISMATCH/
    );
    assert.throws(
      () =>
        service.ingestFacts(
          { ...valid, signatureBase64: "Z".repeat(64) },
          now
        ),
      /ENDPOINT_FACT_BATCH_SIGNATURE_INVALID/
    );
    database.close();
  });

  it("enforces fact-batch continuity, chained reboot and immutable storage", () => {
    const { database, identity, service } = setup();
    const capability = service.recordCapability(capabilityReport(identity), now);
    const firstInput = factBatch(identity, capability, logClearFields);
    const first = service.ingestFacts(firstInput, now);
    const secondInput = factBatch(identity, capability, logClearFields, {
      batchSequence: 1,
      previousBatchHash: first.batchHash,
      factId: "fact-eventlog-00000002",
      occurredAt: new Date(now.valueOf() - 20_000).toISOString(),
      sourceRecordIdHash: "e".repeat(64)
    });
    const second = service.ingestFacts(secondInput, now);
    assert.equal(second.batchSequence, 1);

    const fork = factBatch(identity, capability, logClearFields, {
      batchSequence: 1,
      previousBatchHash: first.batchHash,
      factId: "fact-eventlog-00000003",
      occurredAt: new Date(now.valueOf() - 10_000).toISOString(),
      sourceRecordIdHash: "f".repeat(64)
    });
    assert.throws(
      () => service.ingestFacts(fork, now),
      /ENDPOINT_FACT_PREVIOUS_BATCH_MISMATCH/
    );
    const reboot = factBatch(identity, capability, logClearFields, {
      bootId: "boot-test-00000002",
      batchSequence: 0,
      previousBatchHash: second.batchHash,
      factId: "fact-eventlog-00000004",
      occurredAt: new Date(now.valueOf() - 5_000).toISOString(),
      sourceRecordIdHash: "1".repeat(64)
    });
    service.ingestFacts(reboot, now);

    assert.throws(
      () =>
        database
          .prepare(
            "UPDATE endpoint_minimized_facts SET fields_json = ? WHERE fact_id = ?"
          )
          .run("{}", "fact-eventlog-00000001"),
      /ENDPOINT_MINIMIZED_FACT_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare("DELETE FROM endpoint_fact_batches WHERE id = ?")
          .run(first.id),
      /ENDPOINT_FACT_BATCH_IMMUTABLE/
    );
    database.close();
  });

  it("fails closed for stale, gapped, lossy, incomplete or uncovered capability state", () => {
    const gapSetup = setup();
    const gapCapability = gapSetup.service.recordCapability(
      capabilityReport(gapSetup.identity, {
        continuity: "gap"
      }),
      now
    );
    assert.equal(gapCapability.health, "gapped");
    const gapRun = gapSetup.service.correlate(
      {
        missionId: gapSetup.identity.missionId,
        endpointId: gapSetup.identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(gapRun.result.status, "blocked-coverage");
    assert.equal(gapRun.result.verdict, "coverage-blocked");
    assert.equal(gapRun.result.alerts.length, 0);
    assert.match(gapRun.result.limitation, /No negative detection claim/);
    assert.throws(
      () =>
        gapSetup.service.ingestFacts(
          factBatch(gapSetup.identity, gapCapability, logClearFields),
          now
        ),
      /ENDPOINT_FACT_CAPABILITY_NOT_HEALTHY/
    );
    gapSetup.database.close();

    const lossSetup = setup();
    lossSetup.service.recordCapability(
      capabilityReport(lossSetup.identity, {
        loss: { state: "reported", lostRecordCount: 3 }
      }),
      now
    );
    assert.equal(
      lossSetup.service.correlate(
        {
          missionId: lossSetup.identity.missionId,
          endpointId: lossSetup.identity.endpointId,
          ruleIds: ["BR-EVASION-003"],
          windowStart: new Date(now.valueOf() - 60_000).toISOString(),
          windowEnd: now.toISOString()
        },
        "blue reviewer",
        now
      ).result.status,
      "blocked-coverage"
    );
    lossSetup.database.close();

    const staleSetup = setup();
    staleSetup.service.recordCapability(
      capabilityReport(staleSetup.identity, { freshnessSeconds: 30 }),
      now
    );
    const staleNow = new Date(now.valueOf() + 31_000);
    assert.equal(
      staleSetup.service.correlate(
        {
          missionId: staleSetup.identity.missionId,
          endpointId: staleSetup.identity.endpointId,
          ruleIds: ["BR-EVASION-003"],
          windowStart: new Date(now.valueOf() - 60_000).toISOString(),
          windowEnd: now.toISOString()
        },
        "blue reviewer",
        staleNow
      ).result.status,
      "blocked-coverage"
    );
    staleSetup.database.close();

    const missingSetup = setup();
    missingSetup.service.recordCapability(
      capabilityReport(missingSetup.identity, {
        fields: ["action", "actorTrust", "objectClass", "subjectClass"]
      }),
      now
    );
    const missingRun = missingSetup.service.correlate(
      {
        missionId: missingSetup.identity.missionId,
        endpointId: missingSetup.identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(missingRun.result.status, "blocked-coverage");
    assert.match(missingRun.result.coverage[0]!.reason, /outcome/);
    missingSetup.database.close();

    const uncoveredSetup = setup();
    const uncoveredRun = uncoveredSetup.service.correlate(
      {
        missionId: uncoveredSetup.identity.missionId,
        endpointId: uncoveredSetup.identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(uncoveredRun.result.status, "blocked-coverage");
    assert.match(uncoveredRun.result.coverage[0]!.reason, /No signed capability/);
    uncoveredSetup.database.close();
  });

  it("does not turn a covered non-match into proof of endpoint safety", () => {
    const { database, identity, service } = setup();
    const capability = service.recordCapability(capabilityReport(identity), now);
    service.ingestFacts(
      factBatch(identity, capability, {
        ...logClearFields,
        actorTrust: "managed"
      }),
      now
    );
    const run = service.correlate(
      {
        missionId: identity.missionId,
        endpointId: identity.endpointId,
        ruleIds: ["BR-EVASION-003"],
        windowStart: new Date(now.valueOf() - 60_000).toISOString(),
        windowEnd: now.toISOString()
      },
      "blue reviewer",
      now
    );
    assert.equal(run.result.status, "completed");
    assert.equal(run.result.verdict, "no-rule-match-observed");
    assert.equal(run.result.alerts.length, 0);
    assert.match(run.result.limitation, /not proof that the endpoint is clean/i);
    assert.throws(
      () =>
        service.correlate(
          {
            missionId: "another-mission",
            endpointId: identity.endpointId,
            ruleIds: ["BR-EVASION-003"],
            windowStart: new Date(now.valueOf() - 60_000).toISOString(),
            windowEnd: now.toISOString()
          },
          "blue reviewer",
          now
        ),
      /ENDPOINT_IDENTITY_BINDING_MISMATCH/
    );
    database.close();
  });
});
