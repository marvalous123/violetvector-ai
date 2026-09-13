import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject
} from "node:crypto";
import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync
} from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const SHA256 = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[a-z0-9-]{8,96}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PROVIDERS = new Set([
  "windows-security",
  "windows-sysmon",
  "windows-defender",
  "windows-eventlog",
  "windows-firewall"
]);
const CHANNELS = new Set([
  "security",
  "sysmon-operational",
  "defender-operational",
  "eventlog-admin",
  "firewall-operational"
]);
const EVENT_FAMILIES = new Set([
  "process-start",
  "process-access",
  "file-access",
  "authentication",
  "ticket-request",
  "authentication-component-change",
  "certificate-key-access",
  "image-load",
  "file-attribute-change",
  "security-control-change",
  "event-log-impairment",
  "event-log-clear",
  "firewall-policy-change",
  "scheduled-task-change",
  "service-change"
]);
const FIELD_NAMES = new Set([
  "actorTrust",
  "action",
  "subjectClass",
  "objectClass",
  "parentClass",
  "signerState",
  "originZone",
  "elevated",
  "outcome",
  "baselineState",
  "contentState",
  "visibilityState",
  "metadataState",
  "failureCountBucket",
  "recentExecution"
]);
const STREAM_BINDINGS = new Set([
  "windows-security|security|process-start",
  "windows-security|security|authentication",
  "windows-security|security|ticket-request",
  "windows-security|security|authentication-component-change",
  "windows-security|security|certificate-key-access",
  "windows-security|security|scheduled-task-change",
  "windows-security|security|service-change",
  "windows-sysmon|sysmon-operational|process-start",
  "windows-sysmon|sysmon-operational|process-access",
  "windows-sysmon|sysmon-operational|file-access",
  "windows-sysmon|sysmon-operational|image-load",
  "windows-sysmon|sysmon-operational|file-attribute-change",
  "windows-defender|defender-operational|security-control-change",
  "windows-eventlog|eventlog-admin|event-log-impairment",
  "windows-eventlog|eventlog-admin|event-log-clear",
  "windows-firewall|firewall-operational|firewall-policy-change"
]);
const PRIMITIVE_VALUES = {
  actorTrust: new Set(["managed", "untrusted", "unknown"]),
  action: new Set([
    "start", "open-process", "read", "create", "modify", "delete",
    "clear", "stop", "disable", "add-rule", "remove-rule", "access",
    "export", "register", "authenticate", "request", "load", "write-memory",
    "execute", "decode", "hide"
  ]),
  subjectClass: new Set([
    "powershell", "office", "browser", "document-reader", "password-manager",
    "mshta", "msiexec", "regsvr32", "rundll32", "system-binary",
    "security-tool", "admin-tool", "other"
  ]),
  objectClass: new Set([
    "auth-memory", "credential-store", "security-control", "event-log",
    "firewall-policy", "scheduled-task", "service", "unsecured-secret",
    "input-device", "authentication", "kerberos-ticket", "session-store",
    "application-token", "authentication-component", "authentication-key",
    "installer-package", "module", "process-memory", "audit-policy",
    "encoded-content", "binary-metadata", "hidden-artifact",
    "executable-artifact", "other"
  ]),
  parentClass: new Set(["office", "browser", "shell", "service-manager", "unknown"]),
  signerState: new Set(["signed-trusted", "signed-untrusted", "unsigned", "unknown"]),
  originZone: new Set(["system", "program-files", "user-writable", "remote", "unknown"]),
  outcome: new Set(["success", "failure", "unknown"]),
  baselineState: new Set(["expected", "new", "rare", "unknown"]),
  contentState: new Set(["plain", "encoded", "high-entropy", "unknown"]),
  visibilityState: new Set(["visible", "hidden", "alternate-stream", "unknown"]),
  metadataState: new Set(["consistent", "mismatch", "unknown"]),
  failureCountBucket: new Set(["none", "low", "burst", "unknown"])
} as const;

export const FIXTURE_IDENTITY_PROFILE = "sha256-spki-der-ed25519" as const;
export const SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT =
  "SYNTHETIC_FIXTURE_ONLY_NO_LIVE_CLAIMS" as const;

export interface FixtureIdentityDescriptor {
  readonly algorithm: "ed25519";
  readonly publicKeyFormat: "spki-der";
  readonly publicKeySpkiBase64: string;
  readonly certificateFingerprintSha256: string;
  readonly privateKeyPersistence: "none" | "external-preprotected-file";
}

export type FixtureProvider =
  | "windows-security"
  | "windows-sysmon"
  | "windows-defender"
  | "windows-eventlog"
  | "windows-firewall";
export type FixtureChannel =
  | "security"
  | "sysmon-operational"
  | "defender-operational"
  | "eventlog-admin"
  | "firewall-operational";
export type FixtureEventFamily =
  | "process-start"
  | "process-access"
  | "file-access"
  | "authentication"
  | "ticket-request"
  | "authentication-component-change"
  | "certificate-key-access"
  | "image-load"
  | "file-attribute-change"
  | "security-control-change"
  | "event-log-impairment"
  | "event-log-clear"
  | "firewall-policy-change"
  | "scheduled-task-change"
  | "service-change";
export type FixtureFieldName =
  | "actorTrust"
  | "action"
  | "subjectClass"
  | "objectClass"
  | "parentClass"
  | "signerState"
  | "originZone"
  | "elevated"
  | "outcome"
  | "baselineState"
  | "contentState"
  | "visibilityState"
  | "metadataState"
  | "failureCountBucket"
  | "recentExecution";

export interface FixturePrimitiveFields {
  readonly actorTrust: "managed" | "untrusted" | "unknown";
  readonly action:
    | "start" | "open-process" | "read" | "create" | "modify" | "delete"
    | "clear" | "stop" | "disable" | "add-rule" | "remove-rule" | "access"
    | "export" | "register" | "authenticate" | "request" | "load"
    | "write-memory" | "execute" | "decode" | "hide";
  readonly subjectClass:
    | "powershell" | "office" | "browser" | "document-reader" | "password-manager"
    | "mshta" | "msiexec" | "regsvr32" | "rundll32" | "system-binary"
    | "security-tool" | "admin-tool" | "other";
  readonly objectClass:
    | "auth-memory" | "credential-store" | "security-control" | "event-log"
    | "firewall-policy" | "scheduled-task" | "service" | "unsecured-secret"
    | "input-device" | "authentication" | "kerberos-ticket" | "session-store"
    | "application-token" | "authentication-component" | "authentication-key"
    | "installer-package" | "module" | "process-memory" | "audit-policy"
    | "encoded-content" | "binary-metadata" | "hidden-artifact"
    | "executable-artifact" | "other";
  readonly parentClass?: "office" | "browser" | "shell" | "service-manager" | "unknown";
  readonly signerState?: "signed-trusted" | "signed-untrusted" | "unsigned" | "unknown";
  readonly originZone?: "system" | "program-files" | "user-writable" | "remote" | "unknown";
  readonly elevated?: boolean;
  readonly outcome?: "success" | "failure" | "unknown";
  readonly baselineState?: "expected" | "new" | "rare" | "unknown";
  readonly contentState?: "plain" | "encoded" | "high-entropy" | "unknown";
  readonly visibilityState?: "visible" | "hidden" | "alternate-stream" | "unknown";
  readonly metadataState?: "consistent" | "mismatch" | "unknown";
  readonly failureCountBucket?: "none" | "low" | "burst" | "unknown";
  readonly recentExecution?: boolean;
}

export interface FixtureMinimizedFact {
  readonly factId: string;
  readonly occurredAt: string;
  readonly sourceRecordIdHash: string;
  readonly fields: FixturePrimitiveFields;
}

interface FixtureStreamBinding {
  readonly acknowledgement: typeof SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT;
  readonly missionId: string;
  readonly connectorId: string;
  readonly endpointId: string;
  readonly provider: FixtureProvider;
  readonly channel: FixtureChannel;
  readonly eventFamily: FixtureEventFamily;
  readonly filterHash: string;
}

export interface FixtureCapabilityInput extends FixtureStreamBinding {
  readonly fields: readonly FixtureFieldName[];
  readonly collectorVersion: string;
  readonly loss:
    | { readonly state: "none"; readonly lostRecordCount: 0 }
    | { readonly state: "reported"; readonly lostRecordCount: number }
    | { readonly state: "unknown"; readonly lostRecordCount: null };
  readonly continuity: "continuous" | "gap" | "unknown";
  readonly continuousSince: string;
  readonly lastSuccessfulReadAt: string;
  readonly observedAt: string;
  readonly freshnessSeconds: number;
}

export interface FixtureFactBatchInput extends FixtureStreamBinding {
  readonly capabilitySnapshotId: string;
  readonly bootId: string;
  readonly batchSequence: number;
  readonly previousBatchHash: string | null;
  readonly facts: readonly FixtureMinimizedFact[];
}

export interface ExternalPrivateKeyOptions {
  readonly privateKeyPath: string;
  readonly projectRoot: string;
  readonly runtimeDataRoot: string;
  readonly verifyFileProtection: (resolvedPrivateKeyPath: string) => boolean;
}

export interface AcceptedFixtureFactBatch {
  readonly id: string;
  readonly batchHash: string;
  readonly missionId: string;
  readonly connectorId: string;
  readonly endpointId: string;
  readonly capabilitySnapshotId: string;
  readonly bootId: string;
  readonly batchSequence: number;
  readonly previousBatchHash: string | null;
  readonly factCount: number;
  readonly evidenceArtifactId: string;
  readonly acceptedAt: string;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, normalize(entry)])
    );
  }
  return value;
}

export function fixtureStableJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isInside(child: string, parent: string): boolean {
  const candidate = relative(resolve(parent), resolve(child));
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}

function assertExactKeys(value: object, allowed: readonly string[], errorCode: string): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) throw new Error(errorCode);
}

function assertBinding(input: FixtureStreamBinding): void {
  if (input.acknowledgement !== SYNTHETIC_FIXTURE_ACKNOWLEDGEMENT) {
    throw new Error("FIXTURE_ACKNOWLEDGEMENT_REQUIRED");
  }
  if (input.missionId.length < 1 || input.missionId.length > 128) {
    throw new Error("FIXTURE_MISSION_INVALID");
  }
  for (const [label, value] of [
    ["CONNECTOR", input.connectorId],
    ["ENDPOINT", input.endpointId],
  ] as const) {
    if (!IDENTIFIER.test(value)) throw new Error(`FIXTURE_${label}_INVALID`);
  }
  if (
    !PROVIDERS.has(input.provider) ||
    !CHANNELS.has(input.channel) ||
    !EVENT_FAMILIES.has(input.eventFamily) ||
    !STREAM_BINDINGS.has(`${input.provider}|${input.channel}|${input.eventFamily}`) ||
    !SHA256.test(input.filterHash)
  ) {
    throw new Error("FIXTURE_STREAM_INVALID");
  }
}

function assertFactBatchBinding(input: FixtureFactBatchInput): void {
  assertBinding(input);
  for (const [label, value] of [
    ["BOOT", input.bootId]
  ] as const) {
    if (!IDENTIFIER.test(value)) throw new Error(`FIXTURE_${label}_INVALID`);
  }
  if (
    !/^capability-[a-f0-9-]{36}$/.test(input.capabilitySnapshotId) ||
    !Number.isSafeInteger(input.batchSequence) ||
    input.batchSequence < 0
  ) {
    throw new Error("FIXTURE_SEQUENCE_INVALID");
  }
  if (input.previousBatchHash !== null && !SHA256.test(input.previousBatchHash)) {
    throw new Error("FIXTURE_PREVIOUS_HASH_INVALID");
  }
  if (input.facts.length < 1 || input.facts.length > 128) {
    throw new Error("FIXTURE_FACT_COUNT_INVALID");
  }
}

function assertFact(fact: FixtureMinimizedFact): void {
  assertExactKeys(
    fact,
    ["factId", "occurredAt", "sourceRecordIdHash", "fields"],
    "FIXTURE_FACT_FIELD_INVALID"
  );
  assertExactKeys(
    fact.fields,
    [
      "actorTrust", "action", "subjectClass", "objectClass", "parentClass",
      "signerState", "originZone", "elevated", "outcome", "baselineState",
      "contentState", "visibilityState", "metadataState", "failureCountBucket",
      "recentExecution"
    ],
    "FIXTURE_REDACTION_FIELD_INVALID"
  );
  if (!/^fact-[a-z0-9-]{8,96}$/.test(fact.factId)) throw new Error("FIXTURE_FACT_ID_INVALID");
  if (!Number.isFinite(new Date(fact.occurredAt).valueOf())) throw new Error("FIXTURE_TIME_INVALID");
  if (!SHA256.test(fact.sourceRecordIdHash)) throw new Error("FIXTURE_SOURCE_HASH_INVALID");
  for (const key of ["actorTrust", "action", "subjectClass", "objectClass"] as const) {
    if (!PRIMITIVE_VALUES[key].has(fact.fields[key])) {
      throw new Error("FIXTURE_PRIMITIVE_FIELDS_INVALID");
    }
  }
  for (const key of [
    "parentClass",
    "signerState",
    "originZone",
    "outcome",
    "baselineState",
    "contentState",
    "visibilityState",
    "metadataState",
    "failureCountBucket"
  ] as const) {
    const value = fact.fields[key];
    if (value !== undefined && !PRIMITIVE_VALUES[key].has(value)) {
      throw new Error("FIXTURE_PRIMITIVE_FIELDS_INVALID");
    }
  }
  if (fact.fields.elevated !== undefined && typeof fact.fields.elevated !== "boolean") {
    throw new Error("FIXTURE_PRIMITIVE_FIELDS_INVALID");
  }
  if (
    fact.fields.recentExecution !== undefined &&
    typeof fact.fields.recentExecution !== "boolean"
  ) {
    throw new Error("FIXTURE_PRIMITIVE_FIELDS_INVALID");
  }
}

function descriptorFromPrivateKey(
  privateKey: KeyObject,
  persistence: FixtureIdentityDescriptor["privateKeyPersistence"]
): FixtureIdentityDescriptor {
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("FIXTURE_PRIVATE_KEY_ALGORITHM_INVALID");
  const canonicalSpki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(canonicalSpki)) throw new Error("FIXTURE_PUBLIC_KEY_INVALID");
  return {
    algorithm: "ed25519",
    publicKeyFormat: "spki-der",
    publicKeySpkiBase64: canonicalSpki.toString("base64"),
    certificateFingerprintSha256: sha256(canonicalSpki),
    privateKeyPersistence: persistence
  };
}

export class LocalFixtureSensor {
  readonly #descriptor: FixtureIdentityDescriptor;

  private constructor(
    private readonly privateKey: KeyObject,
    persistence: FixtureIdentityDescriptor["privateKeyPersistence"]
  ) {
    this.#descriptor = descriptorFromPrivateKey(privateKey, persistence);
  }

  static createEphemeral(): LocalFixtureSensor {
    const { privateKey } = generateKeyPairSync("ed25519");
    return new LocalFixtureSensor(privateKey, "none");
  }

  static loadExternal(options: ExternalPrivateKeyOptions): LocalFixtureSensor {
    if (!isAbsolute(options.privateKeyPath)) throw new Error("FIXTURE_PRIVATE_KEY_PATH_NOT_ABSOLUTE");
    const pathInfo = lstatSync(options.privateKeyPath);
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
      throw new Error("FIXTURE_PRIVATE_KEY_PATH_INVALID");
    }
    const privateKeyPath = realpathSync(options.privateKeyPath);
    if (
      isInside(privateKeyPath, options.projectRoot) ||
      isInside(privateKeyPath, options.runtimeDataRoot)
    ) {
      throw new Error("FIXTURE_PRIVATE_KEY_LOCATION_FORBIDDEN");
    }
    const size = statSync(privateKeyPath).size;
    if (size < 32 || size > 16_384) throw new Error("FIXTURE_PRIVATE_KEY_SIZE_INVALID");
    const accessVerified = (() => {
      try {
        return options.verifyFileProtection(privateKeyPath) === true;
      } catch {
        return false;
      }
    })();
    if (!accessVerified) throw new Error("FIXTURE_PRIVATE_KEY_PROTECTION_UNVERIFIED");

    const encoded = readFileSync(privateKeyPath);
    try {
      const privateKey = createPrivateKey(encoded);
      return new LocalFixtureSensor(privateKey, "external-preprotected-file");
    } catch {
      throw new Error("FIXTURE_PRIVATE_KEY_INVALID");
    } finally {
      encoded.fill(0);
    }
  }

  descriptor(): FixtureIdentityDescriptor {
    return { ...this.#descriptor };
  }

  signEnrollmentChallenge(payload: string): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      throw new Error("FIXTURE_ENROLLMENT_PAYLOAD_INVALID");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("FIXTURE_ENROLLMENT_PAYLOAD_INVALID");
    }
    const candidate = parsed as Record<string, unknown>;
    assertExactKeys(
      candidate,
      [
        "schemaVersion",
        "challengeId",
        "missionId",
        "connectorId",
        "endpointId",
        "certificateFingerprintSha256",
        "nonceBase64Url",
        "requestedAt",
        "challengeExpiresAt",
        "identityExpiresAt"
      ],
      "FIXTURE_ENROLLMENT_FIELD_INVALID"
    );
    if (
      candidate.schemaVersion !== 1 ||
      candidate.certificateFingerprintSha256 !== this.#descriptor.certificateFingerprintSha256 ||
      fixtureStableJson(candidate) !== payload
    ) {
      throw new Error("FIXTURE_ENROLLMENT_BINDING_INVALID");
    }
    return sign(null, Buffer.from(payload, "utf8"), this.privateKey).toString("base64");
  }

  createSignedCapabilityReport(input: FixtureCapabilityInput): Record<string, unknown> {
    assertExactKeys(
      input,
      [
        "acknowledgement", "missionId", "connectorId", "endpointId", "provider",
        "channel", "eventFamily", "filterHash", "fields", "collectorVersion",
        "loss", "continuity", "continuousSince", "lastSuccessfulReadAt",
        "observedAt", "freshnessSeconds"
      ],
      "FIXTURE_CAPABILITY_FIELD_INVALID"
    );
    assertBinding(input);
    const fields = [...new Set(input.fields)].sort();
    if (
      fields.length !== input.fields.length ||
      fields.length < 4 ||
      fields.length > 15 ||
      fields.some((field) => !FIELD_NAMES.has(field)) ||
      !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(input.collectorVersion) ||
      !Number.isInteger(input.freshnessSeconds) ||
      input.freshnessSeconds < 30 ||
      input.freshnessSeconds > 3_600
    ) {
      throw new Error("FIXTURE_CAPABILITY_INVALID");
    }
    const continuousSince = new Date(input.continuousSince);
    const lastSuccessfulReadAt = new Date(input.lastSuccessfulReadAt);
    const observedAt = new Date(input.observedAt);
    if (
      !Number.isFinite(continuousSince.valueOf()) ||
      continuousSince > lastSuccessfulReadAt ||
      lastSuccessfulReadAt > observedAt
    ) {
      throw new Error("FIXTURE_CAPABILITY_TIME_INVALID");
    }
    const core = {
      schemaVersion: 1,
      missionId: input.missionId,
      connectorId: input.connectorId,
      endpointId: input.endpointId,
      certificateFingerprintSha256: this.#descriptor.certificateFingerprintSha256,
      provider: input.provider,
      channel: input.channel,
      eventFamily: input.eventFamily,
      fields,
      filterHash: input.filterHash,
      collectorVersion: input.collectorVersion,
      loss: input.loss,
      continuity: input.continuity,
      continuousSince: input.continuousSince,
      lastSuccessfulReadAt: input.lastSuccessfulReadAt,
      observedAt: input.observedAt,
      freshnessSeconds: input.freshnessSeconds
    };
    const payload = fixtureStableJson(core);
    return {
      ...core,
      reportHash: sha256(payload),
      signatureBase64: sign(null, Buffer.from(payload, "utf8"), this.privateKey).toString("base64")
    };
  }

  createSignedFactBatch(input: FixtureFactBatchInput): Record<string, unknown> {
    assertExactKeys(
      input,
      [
        "acknowledgement", "missionId", "connectorId", "endpointId", "provider",
        "channel", "eventFamily", "filterHash", "capabilitySnapshotId", "bootId",
        "batchSequence", "previousBatchHash", "facts"
      ],
      "FIXTURE_BATCH_FIELD_INVALID"
    );
    assertFactBatchBinding(input);
    input.facts.forEach(assertFact);
    const core = {
      schemaVersion: 1,
      missionId: input.missionId,
      connectorId: input.connectorId,
      endpointId: input.endpointId,
      certificateFingerprintSha256: this.#descriptor.certificateFingerprintSha256,
      capabilitySnapshotId: input.capabilitySnapshotId,
      bootId: input.bootId,
      batchSequence: input.batchSequence,
      previousBatchHash: input.previousBatchHash,
      provider: input.provider,
      channel: input.channel,
      eventFamily: input.eventFamily,
      filterHash: input.filterHash,
      facts: input.facts.map((fact) => ({
        factId: fact.factId,
        occurredAt: fact.occurredAt,
        sourceRecordIdHash: fact.sourceRecordIdHash,
        fields: { ...fact.fields }
      }))
    };
    const payload = fixtureStableJson(core);
    return {
      ...core,
      batchHash: sha256(payload),
      signatureBase64: sign(null, Buffer.from(payload, "utf8"), this.privateKey).toString("base64")
    };
  }
}

export class FixtureCollectorClient {
  async submit(
    batch: Readonly<Record<string, unknown>>,
    outboundSubmit: (batch: Readonly<Record<string, unknown>>) => Promise<unknown>
  ): Promise<AcceptedFixtureFactBatch> {
    const response = await outboundSubmit(batch);
    if (!response || typeof response !== "object" || Array.isArray(response)) {
      throw new Error("FIXTURE_RECEIPT_INVALID");
    }
    assertExactKeys(
      response,
      [
        "id", "batchHash", "missionId", "connectorId", "endpointId",
        "capabilitySnapshotId", "bootId", "batchSequence", "previousBatchHash",
        "factCount", "evidenceArtifactId", "acceptedAt"
      ],
      "FIXTURE_RECEIPT_ACTION_FORBIDDEN"
    );
    const receipt = response as Record<string, unknown>;
    if (
      typeof receipt.id !== "string" ||
      !/^fact-batch-[a-f0-9-]{36}$/.test(receipt.id) ||
      typeof receipt.batchHash !== "string" ||
      !SHA256.test(receipt.batchHash) ||
      typeof receipt.missionId !== "string" ||
      typeof receipt.connectorId !== "string" ||
      typeof receipt.endpointId !== "string" ||
      typeof receipt.capabilitySnapshotId !== "string" ||
      typeof receipt.bootId !== "string" ||
      !Number.isSafeInteger(receipt.batchSequence) ||
      (receipt.batchSequence as number) < 0 ||
      !Number.isSafeInteger(receipt.factCount) ||
      (receipt.factCount as number) < 1 ||
      typeof receipt.evidenceArtifactId !== "string" ||
      !UUID.test(receipt.evidenceArtifactId) ||
      typeof receipt.acceptedAt !== "string" ||
      !Number.isFinite(new Date(receipt.acceptedAt).valueOf())
    ) {
      throw new Error("FIXTURE_RECEIPT_INVALID");
    }
    return receipt as unknown as AcceptedFixtureFactBatch;
  }
}
