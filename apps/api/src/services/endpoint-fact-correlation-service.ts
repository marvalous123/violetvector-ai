import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import {
  BLUE_RULES,
  type BlueRuleDescriptor,
  type BlueSignalId
} from "./blue-detection-service.js";
import type { EndpointRegistryService } from "./endpoint-registry-service.js";
import type { EvidenceService } from "./evidence-service.js";
import {
  WINDOWS_GENUINE_SOURCE_VALIDATIONS,
  isGenuineLiveEligible
} from "./windows-genuine-source-validation.js";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const endpointIdSchema = z.string().regex(/^endpoint-[a-f0-9-]{36}$/);
const connectorIdSchema = z.string().regex(/^connector-[a-f0-9-]{36}$/);
const bootIdSchema = z.string().regex(/^boot-[a-z0-9-]{8,80}$/);
const signatureSchema = z.string().min(40).max(2_048).regex(/^[A-Za-z0-9+/=]+$/);
const minimizedFactTimestampPattern =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function isValidMinimizedFactTimestamp(input: string): boolean {
  const match = minimizedFactTimestampPattern.exec(input);
  if (!match) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false;
  }

  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31
  ][month - 1]!;
  if (day < 1 || day > daysInMonth) return false;

  if (match[8]) {
    const offsetHours = Number(match[9]);
    const offsetMinutes = Number(match[10]);
    if (
      offsetHours > 14 ||
      offsetMinutes > 59 ||
      (offsetHours === 14 && offsetMinutes !== 0)
    ) {
      return false;
    }
  }
  return true;
}

const minimizedFactTimestampSchema = z
  .string()
  .refine(isValidMinimizedFactTimestamp, "Invalid minimized-fact timestamp");

export const endpointFactProviderSchema = z.enum([
  "windows-security",
  "windows-scm",
  "windows-sysmon",
  "windows-defender",
  "windows-eventlog",
  "windows-firewall"
]);
export type EndpointFactProvider = z.infer<typeof endpointFactProviderSchema>;

export const endpointFactChannelSchema = z.enum([
  "security",
  "system",
  "sysmon-operational",
  "defender-operational",
  "eventlog-admin",
  "firewall-operational"
]);
export type EndpointFactChannel = z.infer<typeof endpointFactChannelSchema>;

export const endpointFactEventFamilySchema = z.enum([
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
export type EndpointFactEventFamily = z.infer<typeof endpointFactEventFamilySchema>;

export const endpointFactFieldNameSchema = z.enum([
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
export type EndpointFactFieldName = z.infer<typeof endpointFactFieldNameSchema>;

export const endpointFactFieldsSchema = z.object({
  actorTrust: z.enum(["managed", "untrusted", "unknown"]),
  action: z.enum([
    "start",
    "open-process",
    "read",
    "create",
    "modify",
    "delete",
    "clear",
    "stop",
    "disable",
    "add-rule",
    "remove-rule",
    "access",
    "export",
    "register",
    "authenticate",
    "request",
    "load",
    "write-memory",
    "execute",
    "decode",
    "hide"
  ]),
  subjectClass: z.enum([
    "powershell",
    "office",
    "browser",
    "document-reader",
    "password-manager",
    "mshta",
    "msiexec",
    "regsvr32",
    "rundll32",
    "system-binary",
    "security-tool",
    "admin-tool",
    "other"
  ]),
  objectClass: z.enum([
    "auth-memory",
    "credential-store",
    "security-control",
    "event-log",
    "firewall-policy",
    "scheduled-task",
    "service",
    "unsecured-secret",
    "input-device",
    "authentication",
    "kerberos-ticket",
    "session-store",
    "application-token",
    "authentication-component",
    "authentication-key",
    "installer-package",
    "module",
    "process-memory",
    "audit-policy",
    "encoded-content",
    "binary-metadata",
    "hidden-artifact",
    "executable-artifact",
    "other"
  ]),
  parentClass: z.enum(["office", "browser", "shell", "service-manager", "unknown"]).optional(),
  signerState: z.enum(["signed-trusted", "signed-untrusted", "unsigned", "unknown"]).optional(),
  originZone: z.enum(["system", "program-files", "user-writable", "remote", "unknown"]).optional(),
  elevated: z.boolean().optional(),
  outcome: z.enum(["success", "failure", "unknown"]).optional(),
  baselineState: z.enum(["expected", "new", "rare", "unknown"]).optional(),
  contentState: z.enum(["plain", "encoded", "high-entropy", "unknown"]).optional(),
  visibilityState: z.enum(["visible", "hidden", "alternate-stream", "unknown"]).optional(),
  metadataState: z.enum(["consistent", "mismatch", "unknown"]).optional(),
  failureCountBucket: z.enum(["none", "low", "burst", "unknown"]).optional(),
  recentExecution: z.boolean().optional()
}).strict();
export type EndpointFactFields = z.infer<typeof endpointFactFieldsSchema>;

const providerChannelFamilies: Readonly<
  Record<EndpointFactProvider, {
    readonly channel: EndpointFactChannel;
    readonly families: readonly EndpointFactEventFamily[];
  }>
> = {
  "windows-security": {
    channel: "security",
    families: [
      "process-start",
      "authentication",
      "ticket-request",
      "authentication-component-change",
      "certificate-key-access",
      "file-access",
      "file-attribute-change",
      "event-log-impairment",
      "event-log-clear",
      "firewall-policy-change",
      "scheduled-task-change",
      "service-change"
    ]
  },
  "windows-scm": {
    channel: "system",
    families: ["service-change"]
  },
  "windows-sysmon": {
    channel: "sysmon-operational",
    families: [
      "process-start",
      "process-access",
      "file-access",
      "image-load",
      "file-attribute-change"
    ]
  },
  "windows-defender": {
    channel: "defender-operational",
    families: ["security-control-change"]
  },
  "windows-eventlog": {
    channel: "eventlog-admin",
    families: ["event-log-impairment", "event-log-clear"]
  },
  "windows-firewall": {
    channel: "firewall-operational",
    families: ["firewall-policy-change"]
  }
};

function assertStream(
  provider: EndpointFactProvider,
  channel: EndpointFactChannel,
  eventFamily: EndpointFactEventFamily
): void {
  const allowed = providerChannelFamilies[provider];
  if (allowed.channel !== channel || !allowed.families.includes(eventFamily)) {
    throw new Error("ENDPOINT_FACT_STREAM_INVALID");
  }
}

const scmSystemFieldProfile: readonly EndpointFactFieldName[] = [
  "action",
  "actorTrust",
  "objectClass",
  "outcome",
  "subjectClass"
];

function assertScmCapabilityFields(
  provider: EndpointFactProvider,
  channel: EndpointFactChannel,
  eventFamily: EndpointFactEventFamily,
  fields: readonly EndpointFactFieldName[]
): void {
  if (provider !== "windows-scm") return;
  if (
    channel !== "system" ||
    eventFamily !== "service-change" ||
    sortedUniqueFields(fields).join(",") !== scmSystemFieldProfile.join(",")
  ) {
    throw new Error("ENDPOINT_SCM_FIELD_PROFILE_INVALID");
  }
}

function assertScmFactFields(
  provider: EndpointFactProvider,
  fields: EndpointFactFields
): void {
  if (provider !== "windows-scm") return;
  if (
    Object.keys(fields).sort().join(",") !== scmSystemFieldProfile.join(",") ||
    fields.actorTrust !== "unknown" ||
    fields.action !== "create" ||
    fields.subjectClass !== "other" ||
    fields.objectClass !== "service" ||
    fields.outcome !== "unknown"
  ) {
    throw new Error("ENDPOINT_SCM_FACT_PROFILE_INVALID");
  }
}

const capabilityCoreSchema = z.object({
  schemaVersion: z.literal(1),
  missionId: z.string().min(1).max(128),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: sha256Schema,
  provider: endpointFactProviderSchema,
  channel: endpointFactChannelSchema,
  eventFamily: endpointFactEventFamilySchema,
  fields: z.array(endpointFactFieldNameSchema).min(4).max(15),
  filterHash: sha256Schema,
  collectorVersion: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
  loss: z.discriminatedUnion("state", [
    z.object({ state: z.literal("none"), lostRecordCount: z.literal(0) }).strict(),
    z.object({
      state: z.literal("reported"),
      lostRecordCount: z.number().int().positive().max(1_000_000_000)
    }).strict(),
    z.object({ state: z.literal("unknown"), lostRecordCount: z.null() }).strict()
  ]),
  continuity: z.enum(["continuous", "gap", "unknown"]),
  continuousSince: z.string().datetime({ offset: true }),
  lastSuccessfulReadAt: z.string().datetime({ offset: true }),
  observedAt: z.string().datetime({ offset: true }),
  freshnessSeconds: z.number().int().min(30).max(3_600)
}).strict();

export const signedEndpointCapabilityReportSchema = capabilityCoreSchema.extend({
  reportHash: sha256Schema,
  signatureBase64: signatureSchema
}).strict();
export type SignedEndpointCapabilityReport = z.infer<
  typeof signedEndpointCapabilityReportSchema
>;

const minimizedFactSchema = z.object({
  factId: z.string().regex(/^fact-[a-z0-9-]{8,96}$/),
  occurredAt: minimizedFactTimestampSchema,
  sourceRecordIdHash: sha256Schema,
  fields: endpointFactFieldsSchema
}).strict();
export type MinimizedEndpointFact = z.infer<typeof minimizedFactSchema>;

const factBatchCoreSchema = z.object({
  schemaVersion: z.literal(1),
  missionId: z.string().min(1).max(128),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: sha256Schema,
  capabilitySnapshotId: z.string().regex(/^capability-[a-f0-9-]{36}$/),
  bootId: bootIdSchema,
  batchSequence: z.number().int().nonnegative().safe(),
  previousBatchHash: sha256Schema.nullable(),
  provider: endpointFactProviderSchema,
  channel: endpointFactChannelSchema,
  eventFamily: endpointFactEventFamilySchema,
  filterHash: sha256Schema,
  facts: z.array(minimizedFactSchema).min(1).max(128)
}).strict();

export const signedEndpointFactBatchSchema = factBatchCoreSchema.extend({
  batchHash: sha256Schema,
  signatureBase64: signatureSchema
}).strict();
export type SignedEndpointFactBatch = z.infer<typeof signedEndpointFactBatchSchema>;

export type EndpointConnectorHealth = "healthy" | "degraded" | "stale" | "gapped";

export interface EndpointCapabilitySnapshot {
  readonly id: string;
  readonly reportHash: string;
  readonly missionId: string;
  readonly connectorId: string;
  readonly endpointId: string;
  readonly certificateFingerprintSha256: string;
  readonly provider: EndpointFactProvider;
  readonly channel: EndpointFactChannel;
  readonly eventFamily: EndpointFactEventFamily;
  readonly fields: EndpointFactFieldName[];
  readonly fieldsHash: string;
  readonly filterHash: string;
  readonly collectorVersion: string;
  readonly loss: {
    readonly state: "none" | "reported" | "unknown";
    readonly lostRecordCount: number | null;
  };
  readonly continuity: "continuous" | "gap" | "unknown";
  readonly continuousSince: string;
  readonly lastSuccessfulReadAt: string;
  readonly observedAt: string;
  readonly freshUntil: string;
  readonly evidenceArtifactId: string;
  readonly recordedAt: string;
  readonly health: EndpointConnectorHealth;
  readonly limitation: string;
}

export interface AcceptedEndpointFactBatch {
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

export const endpointFactReceiptSchema = z.object({
  schemaVersion: z.literal(1),
  status: z.literal("accepted"),
  batchHash: sha256Schema,
  batchSequence: z.number().int().nonnegative().safe(),
  factCount: z.number().int().min(1).max(128)
}).strict();
export type EndpointFactReceipt = z.infer<typeof endpointFactReceiptSchema>;

export function endpointFactReceipt(
  batch: AcceptedEndpointFactBatch
): EndpointFactReceipt {
  return endpointFactReceiptSchema.parse({
    schemaVersion: 1,
    status: "accepted",
    batchHash: batch.batchHash,
    batchSequence: batch.batchSequence,
    factCount: batch.factCount
  });
}

interface CapabilityRow {
  id: string;
  report_hash: string;
  mission_id: string;
  connector_id: string;
  endpoint_id: string;
  certificate_fingerprint_sha256: string;
  provider: EndpointFactProvider;
  channel: EndpointFactChannel;
  event_family: EndpointFactEventFamily;
  fields_json: string;
  fields_hash: string;
  filter_hash: string;
  collector_version: string;
  loss_state: "none" | "reported" | "unknown";
  lost_record_count: number | null;
  continuity_state: "continuous" | "gap" | "unknown";
  continuous_since: string;
  last_successful_read_at: string;
  observed_at: string;
  fresh_until: string;
  evidence_artifact_id: string;
  recorded_at: string;
}

interface FactBatchRow {
  id: string;
  batch_hash: string;
  mission_id: string;
  connector_id: string;
  endpoint_id: string;
  capability_snapshot_id: string;
  boot_id: string;
  batch_sequence: number;
  previous_batch_hash: string | null;
  fact_count: number;
  evidence_artifact_id: string;
  accepted_at: string;
}

interface FactRow {
  fact_id: string;
  fact_hash: string;
  batch_id: string;
  mission_id: string;
  connector_id: string;
  endpoint_id: string;
  capability_snapshot_id: string;
  provider: EndpointFactProvider;
  channel: EndpointFactChannel;
  event_family: EndpointFactEventFamily;
  filter_hash: string;
  occurred_at: string;
  source_record_id_hash: string;
  fields_json: string;
  fields_hash: string;
}

interface StreamHeadRow {
  boot_id: string;
  last_batch_sequence: number;
  last_batch_hash: string;
}

interface RuleRequirement {
  readonly ruleId: string;
  readonly signal: BlueSignalId;
  readonly provider: EndpointFactProvider;
  readonly channel: EndpointFactChannel;
  readonly eventFamily: EndpointFactEventFamily;
  readonly requiredFields: readonly EndpointFactFieldName[];
  readonly matches: (fields: EndpointFactFields) => boolean;
}

const LIVE_RULE_REQUIREMENTS: readonly RuleRequirement[] = [
  {
    ruleId: "BR-CRED-001",
    signal: "sensitive-auth-memory-access",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "process-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "open-process" &&
      fields.objectClass === "auth-memory"
  },
  {
    ruleId: "BR-CRED-002",
    signal: "password-store-read",
    provider: "windows-security",
    channel: "security",
    eventFamily: "file-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "read" &&
      fields.objectClass === "credential-store" &&
      fields.subjectClass !== "browser" &&
      fields.subjectClass !== "password-manager" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-CRED-003",
    signal: "unsecured-secret-access",
    provider: "windows-security",
    channel: "security",
    eventFamily: "file-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "read" &&
      fields.objectClass === "unsecured-secret" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-CRED-004",
    signal: "input-capture-registration",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "process-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "signerState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "register" &&
      fields.objectClass === "input-device" &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted")
  },
  {
    ruleId: "BR-CRED-005",
    signal: "authentication-failure-burst",
    provider: "windows-security",
    channel: "security",
    eventFamily: "authentication",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "failureCountBucket",
      "outcome"
    ],
    matches: (fields) =>
      fields.action === "authenticate" &&
      fields.objectClass === "authentication" &&
      fields.failureCountBucket === "burst" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-CRED-006",
    signal: "anomalous-ticket-use",
    provider: "windows-security",
    channel: "security",
    eventFamily: "ticket-request",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState", "outcome"],
    matches: (fields) =>
      fields.action === "request" &&
      fields.objectClass === "kerberos-ticket" &&
      fields.baselineState === "rare" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-CRED-007",
    signal: "session-cookie-store-read",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "file-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "read" &&
      fields.objectClass === "session-store" &&
      fields.subjectClass !== "browser" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-CRED-008",
    signal: "application-token-access",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "file-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "read" &&
      fields.objectClass === "application-token" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-CRED-009",
    signal: "authentication-component-change",
    provider: "windows-security",
    channel: "security",
    eventFamily: "authentication-component-change",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "create" || fields.action === "modify") &&
      fields.objectClass === "authentication-component" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-CRED-010",
    signal: "authentication-certificate-access",
    provider: "windows-security",
    channel: "security",
    eventFamily: "certificate-key-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "read" || fields.action === "export") &&
      fields.objectClass === "authentication-key" &&
      (fields.baselineState === "new" || fields.baselineState === "rare") &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-PAYLOAD-001",
    signal: "document-child-execution",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "parentClass",
      "signerState",
      "originZone"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      (fields.parentClass === "office" || fields.subjectClass === "document-reader") &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted") &&
      (fields.originZone === "user-writable" || fields.originZone === "remote")
  },
  {
    ruleId: "BR-PAYLOAD-002",
    signal: "suspicious-powershell-chain",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "parentClass"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.subjectClass === "powershell" &&
      (fields.parentClass === "office" || fields.parentClass === "browser")
  },
  {
    ruleId: "BR-PAYLOAD-003",
    signal: "mshta-proxy-execution",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "originZone"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.subjectClass === "mshta" &&
      (fields.originZone === "remote" || fields.originZone === "user-writable")
  },
  {
    ruleId: "BR-PAYLOAD-004",
    signal: "msiexec-untrusted-package",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "originZone",
      "signerState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.subjectClass === "msiexec" &&
      fields.objectClass === "installer-package" &&
      (fields.originZone === "remote" || fields.originZone === "user-writable") &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted")
  },
  {
    ruleId: "BR-PAYLOAD-005",
    signal: "regsvr32-untrusted-module",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "originZone",
      "signerState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.subjectClass === "regsvr32" &&
      fields.objectClass === "module" &&
      (fields.originZone === "remote" || fields.originZone === "user-writable") &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted")
  },
  {
    ruleId: "BR-PAYLOAD-006",
    signal: "rundll32-untrusted-module",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "originZone",
      "signerState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.subjectClass === "rundll32" &&
      fields.objectClass === "module" &&
      (fields.originZone === "remote" || fields.originZone === "user-writable") &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted")
  },
  {
    ruleId: "BR-PAYLOAD-007",
    signal: "unexpected-dll-load",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "image-load",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "originZone",
      "signerState",
      "baselineState"
    ],
    matches: (fields) =>
      fields.action === "load" &&
      fields.objectClass === "module" &&
      fields.originZone === "user-writable" &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted") &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-PAYLOAD-008",
    signal: "cross-process-memory-manipulation",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "process-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "write-memory" &&
      fields.objectClass === "process-memory" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-PAYLOAD-009",
    signal: "scheduled-task-persistence",
    provider: "windows-security",
    channel: "security",
    eventFamily: "scheduled-task-change",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "originZone"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "create" || fields.action === "modify") &&
      fields.objectClass === "scheduled-task" &&
      (fields.originZone === "user-writable" || fields.originZone === "remote")
  },
  {
    ruleId: "BR-PAYLOAD-010",
    signal: "new-untrusted-service",
    provider: "windows-security",
    channel: "security",
    eventFamily: "service-change",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "signerState",
      "originZone"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "create" || fields.action === "modify") &&
      fields.objectClass === "service" &&
      (fields.signerState === "unsigned" || fields.signerState === "signed-untrusted") &&
      (fields.originZone === "user-writable" || fields.originZone === "remote")
  },
  {
    ruleId: "BR-EVASION-001",
    signal: "security-tool-impairment",
    provider: "windows-defender",
    channel: "defender-operational",
    eventFamily: "security-control-change",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      ["stop", "disable", "modify"].includes(fields.action) &&
      fields.objectClass === "security-control" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-EVASION-002",
    signal: "windows-event-log-impairment",
    provider: "windows-security",
    channel: "security",
    eventFamily: "event-log-impairment",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "disable" || fields.action === "modify" || fields.action === "stop") &&
      fields.objectClass === "audit-policy" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-EVASION-003",
    signal: "windows-event-log-clear",
    provider: "windows-security",
    channel: "security",
    eventFamily: "event-log-clear",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "clear" &&
      fields.objectClass === "event-log" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-EVASION-004",
    signal: "firewall-policy-impairment",
    provider: "windows-security",
    channel: "security",
    eventFamily: "firewall-policy-change",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "outcome"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      (fields.action === "disable" || fields.action === "remove-rule") &&
      fields.objectClass === "firewall-policy" &&
      fields.outcome === "success"
  },
  {
    ruleId: "BR-EVASION-005",
    signal: "process-injection-concealment",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "process-access",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "baselineState"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "write-memory" &&
      fields.objectClass === "process-memory" &&
      (fields.baselineState === "new" || fields.baselineState === "rare")
  },
  {
    ruleId: "BR-EVASION-006",
    signal: "trusted-binary-proxy-chain",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: ["actorTrust", "action", "subjectClass", "objectClass", "originZone"],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      ["mshta", "msiexec", "regsvr32", "rundll32"].includes(fields.subjectClass) &&
      (fields.originZone === "remote" || fields.originZone === "user-writable")
  },
  {
    ruleId: "BR-EVASION-007",
    signal: "obfuscated-execution-chain",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "parentClass",
      "contentState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.objectClass === "encoded-content" &&
      (fields.contentState === "encoded" || fields.contentState === "high-entropy") &&
      (fields.parentClass === "office" ||
        fields.parentClass === "browser" ||
        fields.parentClass === "shell")
  },
  {
    ruleId: "BR-EVASION-008",
    signal: "masquerading-metadata-mismatch",
    provider: "windows-security",
    channel: "security",
    eventFamily: "process-start",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "originZone",
      "metadataState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "start" &&
      fields.objectClass === "binary-metadata" &&
      fields.metadataState === "mismatch" &&
      (fields.originZone === "remote" || fields.originZone === "user-writable")
  },
  {
    ruleId: "BR-EVASION-009",
    signal: "hidden-artifact-change",
    provider: "windows-security",
    channel: "security",
    eventFamily: "file-attribute-change",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "visibilityState"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "hide" &&
      fields.objectClass === "hidden-artifact" &&
      (fields.visibilityState === "hidden" || fields.visibilityState === "alternate-stream")
  },
  {
    ruleId: "BR-EVASION-010",
    signal: "post-execution-file-deletion",
    provider: "windows-sysmon",
    channel: "sysmon-operational",
    eventFamily: "file-access",
    requiredFields: [
      "actorTrust",
      "action",
      "subjectClass",
      "objectClass",
      "recentExecution"
    ],
    matches: (fields) =>
      fields.actorTrust === "untrusted" &&
      fields.action === "delete" &&
      fields.objectClass === "executable-artifact" &&
      fields.recentExecution === true
  }
];

export const LIVE_ENDPOINT_RULE_IDS = LIVE_RULE_REQUIREMENTS.map(
  (requirement) => requirement.ruleId
) as readonly string[];

export const LIVE_ENDPOINT_RULE_SOURCE_REQUIREMENTS = LIVE_RULE_REQUIREMENTS.map(
  ({ ruleId, provider, channel, eventFamily, requiredFields }) => ({
    ruleId,
    provider,
    channel,
    eventFamily,
    requiredFields
  })
);

const GENUINE_SOURCE_VALIDATION_BY_RULE = new Map<
  string,
  (typeof WINDOWS_GENUINE_SOURCE_VALIDATIONS)[number]
>(
  WINDOWS_GENUINE_SOURCE_VALIDATIONS.map((validation) => [
    validation.ruleId,
    validation
  ])
);

const correlationInputSchema = z.object({
  missionId: z.string().min(1).max(128),
  endpointId: endpointIdSchema,
  ruleIds: z.array(z.string().regex(/^BR-(?:CRED|PAYLOAD|EVASION)-\d{3}$/)).min(1).max(30),
  windowStart: z.string().datetime({ offset: true }),
  windowEnd: z.string().datetime({ offset: true })
}).strict();

export interface LiveRuleCoverage {
  readonly ruleId: string;
  readonly status: "live-supported" | "blocked";
  readonly capabilitySnapshotId: string | null;
  readonly provider: EndpointFactProvider;
  readonly channel: EndpointFactChannel;
  readonly eventFamily: EndpointFactEventFamily;
  readonly fields: EndpointFactFieldName[];
  readonly filterHash: string | null;
  readonly reason: string;
}

export interface LiveBlueAlert {
  readonly id: string;
  readonly ruleId: string;
  readonly signal: BlueSignalId;
  readonly title: string;
  readonly category: BlueRuleDescriptor["category"];
  readonly severity: BlueRuleDescriptor["severity"];
  readonly attackTechniqueId: string;
  readonly attackTechniqueName: string;
  readonly matchedFactIds: string[];
  readonly reason: string;
  readonly disposition: "needs-review";
}

export interface LiveCorrelationResult {
  readonly schemaVersion: 1;
  readonly ruleSetVersion: "live-fact-rules-v2";
  readonly missionId: string;
  readonly endpointId: string;
  readonly windowStart: string;
  readonly windowEnd: string;
  readonly generatedAt: string;
  readonly status: "completed" | "blocked-coverage";
  readonly verdict:
    | "reviewable-alerts-produced"
    | "no-rule-match-observed"
    | "coverage-blocked";
  readonly coverage: LiveRuleCoverage[];
  readonly matchedFactIds: string[];
  readonly alerts: LiveBlueAlert[];
  readonly limitation: string;
}

export interface LiveCorrelationRun {
  readonly id: string;
  readonly missionId: string;
  readonly endpointId: string;
  readonly operator: string;
  readonly createdAt: string;
  readonly evidenceArtifactId: string;
  readonly resultHash: string;
  readonly integrityValid: boolean;
  readonly result: LiveCorrelationResult;
}

interface CorrelationRunRow {
  id: string;
  mission_id: string;
  endpoint_id: string;
  result_json: string;
  result_hash: string;
  evidence_artifact_id: string;
  operator: string;
  created_at: string;
}

export type EndpointFactSignatureVerifier = (
  payload: string,
  signatureBase64: string,
  certificateFingerprintSha256: string
) => boolean;

function cleanOperator(input: string): string {
  const operator = input.trim();
  if (operator.length < 2 || operator.length > 120) throw new Error("OPERATOR_INVALID");
  return operator;
}

function sortedUniqueFields(fields: readonly EndpointFactFieldName[]): EndpointFactFieldName[] {
  const normalized = [...new Set(fields)].sort();
  if (normalized.length !== fields.length) throw new Error("ENDPOINT_CAPABILITY_FIELDS_INVALID");
  return normalized;
}

function capabilityHealth(row: CapabilityRow, now: Date): {
  health: EndpointConnectorHealth;
  limitation: string;
} {
  if (now.valueOf() >= new Date(row.fresh_until).valueOf()) {
    return {
      health: "stale",
      limitation: "Capability heartbeat is stale; correlation is blocked until a fresh successful read is reported."
    };
  }
  if (row.continuity_state === "gap") {
    return {
      health: "gapped",
      limitation: "The connector reported an event-record continuity gap; no negative detection claim is permitted."
    };
  }
  if (row.continuity_state === "unknown" || row.loss_state !== "none") {
    return {
      health: "degraded",
      limitation:
        row.loss_state === "reported"
          ? `The connector reported ${row.lost_record_count ?? 0} lost records; correlation is blocked.`
          : "Record continuity or loss is unknown; correlation is blocked."
    };
  }
  return {
    health: "healthy",
    limitation:
      "Healthy means the signed connector measurement is fresh, continuous and reports no record loss; it does not prove endpoint safety."
  };
}

function permitsCoverageBlockedScmBootstrap(
  capability: CapabilityRow,
  batch: SignedEndpointFactBatch,
  now: Date
): boolean {
  if (
    capabilityHealth(capability, now).health !== "degraded" ||
    capability.loss_state !== "unknown" ||
    capability.lost_record_count !== null ||
    capability.continuity_state !== "unknown" ||
    capability.continuous_since !== capability.observed_at ||
    capability.last_successful_read_at !== capability.observed_at ||
    capability.collector_version !== "windows-sensor-0.1.0" ||
    capability.provider !== "windows-scm" ||
    capability.channel !== "system" ||
    capability.event_family !== "service-change" ||
    batch.provider !== "windows-scm" ||
    batch.channel !== "system" ||
    batch.eventFamily !== "service-change" ||
    batch.batchSequence !== 0 ||
    batch.previousBatchHash !== null ||
    batch.facts.length !== 1
  ) {
    return false;
  }
  const fields = endpointFactFieldNameSchema.array().parse(
    JSON.parse(capability.fields_json)
  );
  return fields.join(",") === scmSystemFieldProfile.join(",");
}

function validateSignedHashAndSignature(
  core: unknown,
  suppliedHash: string,
  signature: string,
  fingerprint: string,
  verifier: EndpointFactSignatureVerifier,
  hashError: string,
  signatureError: string
): void {
  if (canonicalHash(core) !== suppliedHash) throw new Error(hashError);
  const valid = (() => {
    try {
      return verifier(stableJson(core), signature, fingerprint);
    } catch {
      return false;
    }
  })();
  if (!valid) throw new Error(signatureError);
}

export function endpointCapabilityReportHash(
  input: Omit<SignedEndpointCapabilityReport, "reportHash" | "signatureBase64">
): string {
  const parsed = capabilityCoreSchema.parse(input);
  return canonicalHash({
    ...parsed,
    fields: sortedUniqueFields(parsed.fields)
  });
}

export function endpointFactBatchHash(
  input: Omit<SignedEndpointFactBatch, "batchHash" | "signatureBase64">
): string {
  return canonicalHash(factBatchCoreSchema.parse(input));
}

export class EndpointFactCorrelationService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly registry: EndpointRegistryService,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService,
    private readonly verifySignature: EndpointFactSignatureVerifier
  ) {}

  recordCapability(
    input: unknown,
    now = new Date()
  ): EndpointCapabilitySnapshot {
    const report = signedEndpointCapabilityReportSchema.parse(input);
    assertStream(report.provider, report.channel, report.eventFamily);
    const fields = sortedUniqueFields(report.fields);
    assertScmCapabilityFields(
      report.provider,
      report.channel,
      report.eventFamily,
      fields
    );
    const core = capabilityCoreSchema.strip().parse({ ...report, fields });
    validateSignedHashAndSignature(
      core,
      report.reportHash,
      report.signatureBase64,
      report.certificateFingerprintSha256,
      this.verifySignature,
      "ENDPOINT_CAPABILITY_HASH_MISMATCH",
      "ENDPOINT_CAPABILITY_SIGNATURE_INVALID"
    );
    this.registry.authenticateBatch(
      {
        missionId: report.missionId,
        connectorId: report.connectorId,
        endpointId: report.endpointId,
        certificateFingerprintSha256: report.certificateFingerprintSha256
      },
      now
    );
    const continuousSince = new Date(report.continuousSince);
    const lastRead = new Date(report.lastSuccessfulReadAt);
    const observed = new Date(report.observedAt);
    if (
      continuousSince.valueOf() > lastRead.valueOf() ||
      lastRead.valueOf() > observed.valueOf() ||
      observed.valueOf() > now.valueOf() + 30_000
    ) {
      throw new Error("ENDPOINT_CAPABILITY_TIME_INVALID");
    }
    const existing = this.database
      .prepare("SELECT * FROM endpoint_capability_snapshots WHERE report_hash = ?")
      .get(report.reportHash) as unknown as CapabilityRow | undefined;
    if (existing) return this.toCapability(existing, now);

    const fieldsHash = canonicalHash(fields);
    const previous = this.database
      .prepare(
        `SELECT * FROM endpoint_capability_snapshots
         WHERE mission_id = ? AND endpoint_id = ?
           AND provider = ? AND channel = ? AND event_family = ?
         ORDER BY observed_at DESC, recorded_at DESC LIMIT 1`
      )
      .get(
        report.missionId,
        report.endpointId,
        report.provider,
        report.channel,
        report.eventFamily
      ) as unknown as CapabilityRow | undefined;
    if (previous) {
      if (observed.valueOf() <= new Date(previous.observed_at).valueOf()) {
        throw new Error("ENDPOINT_CAPABILITY_ROLLBACK");
      }
      const configurationChanged =
        previous.filter_hash !== report.filterHash || previous.fields_hash !== fieldsHash;
      if (
        configurationChanged &&
        continuousSince.valueOf() < new Date(previous.last_successful_read_at).valueOf()
      ) {
        throw new Error("ENDPOINT_CAPABILITY_CONTINUITY_RESET_REQUIRED");
      }
      if (
        !configurationChanged &&
        continuousSince.valueOf() < new Date(previous.continuous_since).valueOf()
      ) {
        throw new Error("ENDPOINT_CAPABILITY_CONTINUITY_ROLLBACK");
      }
    }

    const id = `capability-${randomUUID()}`;
    const freshUntil = new Date(lastRead.valueOf() + report.freshnessSeconds * 1_000);
    const artifact = this.evidence.seal(
      stableJson({ ...core, reportHash: report.reportHash }),
      "application/json",
      {
        missionId: report.missionId,
        sourceEventId: id,
        capturedAt: observed,
        provenance: {
          sourceType: "endpoint-capability-measurement",
          schemaVersion: 1,
          connectorId: report.connectorId,
          endpointId: report.endpointId,
          provider: report.provider,
          channel: report.channel,
          eventFamily: report.eventFamily,
          filterHash: report.filterHash,
          reportHash: report.reportHash
        }
      }
    );
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO endpoint_capability_snapshots(
             id, report_hash, mission_id, connector_id, endpoint_id,
             certificate_fingerprint_sha256, schema_version, provider, channel,
             event_family, fields_json, fields_hash, filter_hash, collector_version,
             loss_state, lost_record_count, continuity_state, continuous_since,
             last_successful_read_at, observed_at, fresh_until,
             evidence_artifact_id, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          report.reportHash,
          report.missionId,
          report.connectorId,
          report.endpointId,
          report.certificateFingerprintSha256,
          report.provider,
          report.channel,
          report.eventFamily,
          stableJson(fields),
          fieldsHash,
          report.filterHash,
          report.collectorVersion,
          report.loss.state,
          report.loss.lostRecordCount,
          report.continuity,
          report.continuousSince,
          report.lastSuccessfulReadAt,
          report.observedAt,
          freshUntil.toISOString(),
          artifact.id,
          now.toISOString()
        );
      this.audit.append(
        "endpoint.capability.recorded",
        {
          capabilitySnapshotId: id,
          reportHash: report.reportHash,
          missionId: report.missionId,
          connectorId: report.connectorId,
          endpointId: report.endpointId,
          provider: report.provider,
          channel: report.channel,
          eventFamily: report.eventFamily,
          fieldsHash,
          filterHash: report.filterHash,
          lossState: report.loss.state,
          lostRecordCount: report.loss.lostRecordCount,
          continuity: report.continuity,
          freshUntil: freshUntil.toISOString(),
          evidenceArtifactId: artifact.id
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getCapability(id, now);
  }

  ingestFacts(input: unknown, now = new Date()): AcceptedEndpointFactBatch {
    const batch = signedEndpointFactBatchSchema.parse(input);
    assertStream(batch.provider, batch.channel, batch.eventFamily);
    batch.facts.forEach((fact) => assertScmFactFields(batch.provider, fact.fields));
    const core = factBatchCoreSchema.strip().parse(batch);
    validateSignedHashAndSignature(
      core,
      batch.batchHash,
      batch.signatureBase64,
      batch.certificateFingerprintSha256,
      this.verifySignature,
      "ENDPOINT_FACT_BATCH_HASH_MISMATCH",
      "ENDPOINT_FACT_BATCH_SIGNATURE_INVALID"
    );
    this.registry.authenticateBatch(
      {
        missionId: batch.missionId,
        connectorId: batch.connectorId,
        endpointId: batch.endpointId,
        certificateFingerprintSha256: batch.certificateFingerprintSha256
      },
      now
    );
    const existing = this.database
      .prepare("SELECT * FROM endpoint_fact_batches WHERE batch_hash = ?")
      .get(batch.batchHash) as unknown as FactBatchRow | undefined;
    if (existing) {
      if (
        existing.mission_id !== batch.missionId ||
        existing.connector_id !== batch.connectorId ||
        existing.endpoint_id !== batch.endpointId
      ) {
        throw new Error("ENDPOINT_FACT_BATCH_BINDING_MISMATCH");
      }
      if (!this.evidence.verify(existing.evidence_artifact_id)) {
        throw new Error("ENDPOINT_FACT_BATCH_EVIDENCE_INVALID");
      }
      return this.toFactBatch(existing);
    }

    const capability = this.getCapabilityRow(batch.capabilitySnapshotId);
    if (
      capability.mission_id !== batch.missionId ||
      capability.connector_id !== batch.connectorId ||
      capability.endpoint_id !== batch.endpointId ||
      capability.certificate_fingerprint_sha256 !== batch.certificateFingerprintSha256 ||
      capability.provider !== batch.provider ||
      capability.channel !== batch.channel ||
      capability.event_family !== batch.eventFamily ||
      capability.filter_hash !== batch.filterHash
    ) {
      throw new Error("ENDPOINT_FACT_CAPABILITY_BINDING_MISMATCH");
    }
    if (!this.capabilityEvidenceValid(capability)) {
      throw new Error("ENDPOINT_FACT_CAPABILITY_EVIDENCE_INVALID");
    }
    const capabilityIsHealthy = capabilityHealth(capability, now).health === "healthy";
    const coverageBlockedBootstrap =
      permitsCoverageBlockedScmBootstrap(capability, batch, now) &&
      !this.database
        .prepare("SELECT 1 FROM endpoint_fact_stream_heads WHERE endpoint_id = ?")
        .get(batch.endpointId);
    if (!capabilityIsHealthy && !coverageBlockedBootstrap) {
      throw new Error("ENDPOINT_FACT_CAPABILITY_NOT_HEALTHY");
    }
    const availableFields = new Set(
      endpointFactFieldNameSchema.array().parse(JSON.parse(capability.fields_json))
    );
    const factIds = new Set<string>();
    const sourceRecordIds = new Set<string>();
    let previousOccurredAt = -Infinity;
    for (const fact of batch.facts) {
      if (factIds.has(fact.factId) || sourceRecordIds.has(fact.sourceRecordIdHash)) {
        throw new Error("ENDPOINT_FACT_DUPLICATE");
      }
      factIds.add(fact.factId);
      sourceRecordIds.add(fact.sourceRecordIdHash);
      const occurredAt = new Date(fact.occurredAt).valueOf();
      if (
        occurredAt < previousOccurredAt ||
        occurredAt > now.valueOf() + 30_000 ||
        occurredAt > new Date(capability.last_successful_read_at).valueOf() + 30_000 ||
        now.valueOf() - occurredAt > 24 * 60 * 60_000
      ) {
        throw new Error("ENDPOINT_FACT_TIME_INVALID");
      }
      previousOccurredAt = occurredAt;
      const presentFields = Object.keys(fact.fields) as EndpointFactFieldName[];
      if (presentFields.some((field) => !availableFields.has(field))) {
        throw new Error("ENDPOINT_FACT_FIELD_NOT_DECLARED");
      }
    }
    this.assertFactContinuity(batch);

    const id = `fact-batch-${randomUUID()}`;
    const artifact = this.evidence.seal(
      stableJson({ ...core, batchHash: batch.batchHash }),
      "application/json",
      {
        missionId: batch.missionId,
        sourceEventId: id,
        capturedAt: new Date(batch.facts.at(-1)!.occurredAt),
        provenance: {
          sourceType: "endpoint-minimized-fact-batch",
          schemaVersion: 1,
          connectorId: batch.connectorId,
          endpointId: batch.endpointId,
          capabilitySnapshotId: batch.capabilitySnapshotId,
          provider: batch.provider,
          channel: batch.channel,
          eventFamily: batch.eventFamily,
          filterHash: batch.filterHash,
          batchHash: batch.batchHash,
          factCount: batch.facts.length
        }
      }
    );
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.assertFactContinuity(batch);
      this.database
        .prepare(
          `INSERT INTO endpoint_fact_batches(
             id, batch_hash, mission_id, connector_id, endpoint_id,
             certificate_fingerprint_sha256, capability_snapshot_id, schema_version,
             boot_id, batch_sequence, previous_batch_hash, provider, channel,
             event_family, filter_hash, fact_count, first_occurred_at,
             last_occurred_at, evidence_artifact_id, accepted_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          batch.batchHash,
          batch.missionId,
          batch.connectorId,
          batch.endpointId,
          batch.certificateFingerprintSha256,
          batch.capabilitySnapshotId,
          batch.bootId,
          batch.batchSequence,
          batch.previousBatchHash,
          batch.provider,
          batch.channel,
          batch.eventFamily,
          batch.filterHash,
          batch.facts.length,
          batch.facts[0]!.occurredAt,
          batch.facts.at(-1)!.occurredAt,
          artifact.id,
          now.toISOString()
        );
      const insertFact = this.database.prepare(
        `INSERT INTO endpoint_minimized_facts(
           fact_id, fact_hash, batch_id, mission_id, connector_id, endpoint_id,
           capability_snapshot_id, provider, channel, event_family, filter_hash,
           occurred_at, source_record_id_hash, fields_json, fields_hash, accepted_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const fact of batch.facts) {
        const fieldsJson = stableJson(fact.fields);
        insertFact.run(
          fact.factId,
          canonicalHash({
            missionId: batch.missionId,
            connectorId: batch.connectorId,
            endpointId: batch.endpointId,
            capabilitySnapshotId: batch.capabilitySnapshotId,
            provider: batch.provider,
            channel: batch.channel,
            eventFamily: batch.eventFamily,
            filterHash: batch.filterHash,
            ...fact
          }),
          id,
          batch.missionId,
          batch.connectorId,
          batch.endpointId,
          batch.capabilitySnapshotId,
          batch.provider,
          batch.channel,
          batch.eventFamily,
          batch.filterHash,
          fact.occurredAt,
          fact.sourceRecordIdHash,
          fieldsJson,
          canonicalHash(fact.fields),
          now.toISOString()
        );
      }
      const head = this.database
        .prepare("SELECT endpoint_id FROM endpoint_fact_stream_heads WHERE endpoint_id = ?")
        .get(batch.endpointId);
      if (head) {
        this.database
          .prepare(
            `UPDATE endpoint_fact_stream_heads
             SET boot_id = ?, last_batch_sequence = ?, last_batch_hash = ?, updated_at = ?
             WHERE endpoint_id = ?`
          )
          .run(
            batch.bootId,
            batch.batchSequence,
            batch.batchHash,
            now.toISOString(),
            batch.endpointId
          );
      } else {
        this.database
          .prepare(
            `INSERT INTO endpoint_fact_stream_heads(
               endpoint_id, mission_id, connector_id, boot_id,
               last_batch_sequence, last_batch_hash, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            batch.endpointId,
            batch.missionId,
            batch.connectorId,
            batch.bootId,
            batch.batchSequence,
            batch.batchHash,
            now.toISOString()
          );
      }
      this.audit.append(
        "endpoint.facts.accepted",
        {
          factBatchId: id,
          batchHash: batch.batchHash,
          missionId: batch.missionId,
          connectorId: batch.connectorId,
          endpointId: batch.endpointId,
          capabilitySnapshotId: batch.capabilitySnapshotId,
          bootId: batch.bootId,
          batchSequence: batch.batchSequence,
          factCount: batch.facts.length,
          provider: batch.provider,
          channel: batch.channel,
          eventFamily: batch.eventFamily,
          filterHash: batch.filterHash,
          evidenceArtifactId: artifact.id
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getFactBatch(id);
  }

  correlate(input: unknown, requestedBy: string, now = new Date()): LiveCorrelationRun {
    const parsed = correlationInputSchema.parse(input);
    const operator = cleanOperator(requestedBy);
    const ruleIds = [...new Set(parsed.ruleIds)].sort();
    if (ruleIds.length !== parsed.ruleIds.length) throw new Error("LIVE_RULE_SELECTION_INVALID");
    const requirements = ruleIds.map((ruleId) => {
      const requirement = LIVE_RULE_REQUIREMENTS.find((item) => item.ruleId === ruleId);
      if (!requirement) throw new Error("LIVE_RULE_NOT_SUPPORTED");
      return requirement;
    });
    const identity = this.database
      .prepare(
        `SELECT mission_id, status, expires_at FROM endpoint_identities
         WHERE endpoint_id = ?`
      )
      .get(parsed.endpointId) as
      | { mission_id: string; status: string; expires_at: string }
      | undefined;
    if (!identity) throw new Error("ENDPOINT_IDENTITY_NOT_FOUND");
    if (identity.mission_id !== parsed.missionId) {
      throw new Error("ENDPOINT_IDENTITY_BINDING_MISMATCH");
    }
    if (
      identity.status !== "active" ||
      now.valueOf() >= new Date(identity.expires_at).valueOf()
    ) {
      throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
    }
    const windowStart = new Date(parsed.windowStart);
    const windowEnd = new Date(parsed.windowEnd);
    if (
      windowStart.valueOf() >= windowEnd.valueOf() ||
      windowEnd.valueOf() > now.valueOf() + 30_000 ||
      windowEnd.valueOf() - windowStart.valueOf() > 24 * 60 * 60_000
    ) {
      throw new Error("LIVE_CORRELATION_WINDOW_INVALID");
    }

    let coverage = requirements.map((requirement) =>
      this.coverageForRule(
        parsed.missionId,
        parsed.endpointId,
        requirement,
        windowStart,
        windowEnd,
        now
      )
    );
    const factCount = this.factCountForWindow(
      parsed.missionId,
      parsed.endpointId,
      windowStart,
      windowEnd
    );
    if (factCount > 10_000) {
      coverage = coverage.map((item) =>
        item.status === "live-supported"
          ? {
              ...item,
              status: "blocked" as const,
              reason:
                "The bounded correlation limit was exceeded; narrow the time window before drawing a result."
            }
          : item
      );
    }
    let blocked = coverage.some((item) => item.status === "blocked");
    let facts = blocked
      ? []
      : this.factsForWindow(
          parsed.missionId,
          parsed.endpointId,
          windowStart,
          windowEnd
        );
    if (!blocked && !this.factsIntegrityValid(facts, parsed.missionId)) {
      coverage = coverage.map((item) =>
        item.status === "live-supported"
          ? {
              ...item,
              status: "blocked" as const,
              reason:
                "Stored fact or sealed batch evidence integrity failed; correlation is blocked."
            }
          : item
      );
      blocked = true;
      facts = [];
    }
    const alerts: LiveBlueAlert[] = [];
    if (!blocked) {
      for (const requirement of requirements) {
        const descriptor = BLUE_RULES.find((item) => item.id === requirement.ruleId);
        if (!descriptor) throw new Error("BLUE_RULE_NOT_FOUND");
        const ruleCoverage = coverage.find((item) => item.ruleId === requirement.ruleId)!;
        const matches = facts.filter(
          (fact) =>
            fact.provider === requirement.provider &&
            fact.channel === requirement.channel &&
            fact.event_family === requirement.eventFamily &&
            fact.filter_hash === ruleCoverage.filterHash &&
            requirement.matches(endpointFactFieldsSchema.parse(JSON.parse(fact.fields_json)))
        );
        if (!matches.length) continue;
        const matchedFactIds = matches.map((item) => item.fact_id).sort();
        alerts.push({
          id: `live-alert-${randomUUID()}`,
          ruleId: descriptor.id,
          signal: requirement.signal,
          title: descriptor.title,
          category: descriptor.category,
          severity: descriptor.severity,
          attackTechniqueId: descriptor.attackTechniqueId,
          attackTechniqueName: descriptor.attackTechniqueName,
          matchedFactIds,
          reason:
            `Server rule ${descriptor.id} correlated ${matchedFactIds.length} stored, mission-bound minimized fact(s). ` +
            "This is a reviewable defensive signal, not a compromise conclusion.",
          disposition: "needs-review"
        });
      }
    }
    const matchedFactIds = [...new Set(alerts.flatMap((item) => item.matchedFactIds))].sort();
    const status = blocked ? "blocked-coverage" : "completed";
    const verdict = blocked
      ? "coverage-blocked"
      : alerts.length
        ? "reviewable-alerts-produced"
        : "no-rule-match-observed";
    const result: LiveCorrelationResult = {
      schemaVersion: 1,
      ruleSetVersion: "live-fact-rules-v2",
      missionId: parsed.missionId,
      endpointId: parsed.endpointId,
      windowStart: parsed.windowStart,
      windowEnd: parsed.windowEnd,
      generatedAt: now.toISOString(),
      status,
      verdict,
      coverage,
      matchedFactIds,
      alerts,
      limitation: blocked
        ? "Coverage is incomplete, stale, gapped or lossy. No negative detection claim was produced and no facts were correlated."
        : alerts.length
          ? "Alerts are deterministic matches over minimized facts and require human review; they do not prove compromise."
          : "No configured rule matched during a covered window. This is not proof that the endpoint is clean or that uncollected behaviour did not occur."
    };
    return this.storeCorrelation(result, ruleIds, operator, now);
  }

  listCapabilities(
    missionId: string,
    endpointId: string,
    now = new Date()
  ): EndpointCapabilitySnapshot[] {
    const rows = this.database
      .prepare(
        `SELECT * FROM endpoint_capability_snapshots
         WHERE mission_id = ? AND endpoint_id = ?
         ORDER BY observed_at DESC, id DESC LIMIT 200`
      )
      .all(missionId, endpointId) as unknown as CapabilityRow[];
    return rows.map((row) => this.toCapability(row, now));
  }

  listRuns(missionId: string, endpointId?: string): LiveCorrelationRun[] {
    const rows = endpointId
      ? this.database
          .prepare(
            `SELECT * FROM endpoint_live_correlation_runs
             WHERE mission_id = ? AND endpoint_id = ?
             ORDER BY created_at DESC, id DESC LIMIT 200`
          )
          .all(missionId, endpointId)
      : this.database
          .prepare(
            `SELECT * FROM endpoint_live_correlation_runs
             WHERE mission_id = ? ORDER BY created_at DESC, id DESC LIMIT 200`
          )
          .all(missionId);
    return (rows as unknown as CorrelationRunRow[]).map((row) => this.toRun(row));
  }

  private getCapability(id: string, now: Date): EndpointCapabilitySnapshot {
    return this.toCapability(this.getCapabilityRow(id), now);
  }

  private getCapabilityRow(id: string): CapabilityRow {
    const row = this.database
      .prepare("SELECT * FROM endpoint_capability_snapshots WHERE id = ?")
      .get(id) as unknown as CapabilityRow | undefined;
    if (!row) throw new Error("ENDPOINT_CAPABILITY_NOT_FOUND");
    return row;
  }

  private toCapability(row: CapabilityRow, now: Date): EndpointCapabilitySnapshot {
    const evidenceValid = this.capabilityEvidenceValid(row);
    const status = evidenceValid
      ? capabilityHealth(row, now)
      : {
          health: "degraded" as const,
          limitation: "The sealed capability measurement or its mission observation failed integrity verification."
        };
    return {
      id: row.id,
      reportHash: row.report_hash,
      missionId: row.mission_id,
      connectorId: row.connector_id,
      endpointId: row.endpoint_id,
      certificateFingerprintSha256: row.certificate_fingerprint_sha256,
      provider: row.provider,
      channel: row.channel,
      eventFamily: row.event_family,
      fields: endpointFactFieldNameSchema.array().parse(JSON.parse(row.fields_json)),
      fieldsHash: row.fields_hash,
      filterHash: row.filter_hash,
      collectorVersion: row.collector_version,
      loss: {
        state: row.loss_state,
        lostRecordCount: row.lost_record_count
      },
      continuity: row.continuity_state,
      continuousSince: row.continuous_since,
      lastSuccessfulReadAt: row.last_successful_read_at,
      observedAt: row.observed_at,
      freshUntil: row.fresh_until,
      evidenceArtifactId: row.evidence_artifact_id,
      recordedAt: row.recorded_at,
      health: status.health,
      limitation: status.limitation
    };
  }

  private capabilityEvidenceValid(row: CapabilityRow): boolean {
    try {
      const fields = endpointFactFieldNameSchema.array().parse(JSON.parse(row.fields_json));
      if (canonicalHash(fields) !== row.fields_hash) return false;
      const freshnessSeconds =
        (new Date(row.fresh_until).valueOf() - new Date(row.last_successful_read_at).valueOf()) / 1_000;
      if (!Number.isInteger(freshnessSeconds)) return false;
      const core = capabilityCoreSchema.parse({
        schemaVersion: 1,
        missionId: row.mission_id,
        connectorId: row.connector_id,
        endpointId: row.endpoint_id,
        certificateFingerprintSha256: row.certificate_fingerprint_sha256,
        provider: row.provider,
        channel: row.channel,
        eventFamily: row.event_family,
        fields,
        filterHash: row.filter_hash,
        collectorVersion: row.collector_version,
        loss: {
          state: row.loss_state,
          lostRecordCount: row.lost_record_count
        },
        continuity: row.continuity_state,
        continuousSince: row.continuous_since,
        lastSuccessfulReadAt: row.last_successful_read_at,
        observedAt: row.observed_at,
        freshnessSeconds
      });
      if (
        canonicalHash(core) !== row.report_hash ||
        !this.evidence.verify(row.evidence_artifact_id) ||
        this.evidence.read(row.evidence_artifact_id).toString("utf8") !==
          stableJson({ ...core, reportHash: row.report_hash })
      ) {
        return false;
      }
      const observation = this.evidence.observationForMission(
        row.evidence_artifact_id,
        row.mission_id
      );
      return observation.source_event_id === row.id;
    } catch {
      return false;
    }
  }

  private assertFactContinuity(batch: SignedEndpointFactBatch): void {
    const head = this.database
      .prepare("SELECT * FROM endpoint_fact_stream_heads WHERE endpoint_id = ?")
      .get(batch.endpointId) as unknown as StreamHeadRow | undefined;
    if (!head) {
      if (batch.batchSequence !== 0 || batch.previousBatchHash !== null) {
        throw new Error("ENDPOINT_FACT_SEQUENCE_ORIGIN_INVALID");
      }
      return;
    }
    if (batch.previousBatchHash !== head.last_batch_hash) {
      throw new Error("ENDPOINT_FACT_PREVIOUS_BATCH_MISMATCH");
    }
    if (batch.bootId === head.boot_id) {
      if (batch.batchSequence !== head.last_batch_sequence + 1) {
        throw new Error("ENDPOINT_FACT_SEQUENCE_CONTINUITY_INVALID");
      }
      return;
    }
    if (batch.batchSequence !== 0) {
      throw new Error("ENDPOINT_FACT_BOOT_TRANSITION_INVALID");
    }
  }

  private getFactBatch(id: string): AcceptedEndpointFactBatch {
    const row = this.database
      .prepare("SELECT * FROM endpoint_fact_batches WHERE id = ?")
      .get(id) as unknown as FactBatchRow | undefined;
    if (!row) throw new Error("ENDPOINT_FACT_BATCH_NOT_FOUND");
    return this.toFactBatch(row);
  }

  private toFactBatch(row: FactBatchRow): AcceptedEndpointFactBatch {
    return {
      id: row.id,
      batchHash: row.batch_hash,
      missionId: row.mission_id,
      connectorId: row.connector_id,
      endpointId: row.endpoint_id,
      capabilitySnapshotId: row.capability_snapshot_id,
      bootId: row.boot_id,
      batchSequence: row.batch_sequence,
      previousBatchHash: row.previous_batch_hash,
      factCount: row.fact_count,
      evidenceArtifactId: row.evidence_artifact_id,
      acceptedAt: row.accepted_at
    };
  }

  private coverageForRule(
    missionId: string,
    endpointId: string,
    requirement: RuleRequirement,
    windowStart: Date,
    windowEnd: Date,
    now: Date
  ): LiveRuleCoverage {
    const sourceValidation = GENUINE_SOURCE_VALIDATION_BY_RULE.get(
      requirement.ruleId
    );
    if (!sourceValidation) throw new Error("GENUINE_SOURCE_VALIDATION_MISSING");
    if (!isGenuineLiveEligible(sourceValidation.assessment)) {
      return {
        ruleId: requirement.ruleId,
        provider: requirement.provider,
        channel: requirement.channel,
        eventFamily: requirement.eventFamily,
        fields: [...requirement.requiredFields],
        status: "blocked",
        capabilitySnapshotId: null,
        filterHash: null,
        reason:
          `Documented-source assessment blocks genuine-live eligibility: ` +
          `${sourceValidation.limitationCode}.`
      };
    }
    const row = this.database
      .prepare(
        `SELECT * FROM endpoint_capability_snapshots
         WHERE mission_id = ? AND endpoint_id = ?
           AND provider = ? AND channel = ? AND event_family = ?
           AND observed_at <= ?
         ORDER BY observed_at DESC, recorded_at DESC LIMIT 1`
      )
      .get(
        missionId,
        endpointId,
        requirement.provider,
        requirement.channel,
        requirement.eventFamily,
        now.toISOString()
      ) as unknown as CapabilityRow | undefined;
    const base = {
      ruleId: requirement.ruleId,
      provider: requirement.provider,
      channel: requirement.channel,
      eventFamily: requirement.eventFamily,
      fields: [...requirement.requiredFields]
    };
    if (!row) {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: null,
        filterHash: null,
        reason: "No signed capability measurement exists for the exact required stream."
      };
    }
    if (!this.capabilityEvidenceValid(row)) {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: row.id,
        filterHash: row.filter_hash,
        reason: "The sealed capability measurement or its mission observation failed integrity verification."
      };
    }
    const status = capabilityHealth(row, now);
    if (status.health !== "healthy") {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: row.id,
        filterHash: row.filter_hash,
        reason: status.limitation
      };
    }
    const availableFields = new Set(
      endpointFactFieldNameSchema.array().parse(JSON.parse(row.fields_json))
    );
    const missing = requirement.requiredFields.filter((field) => !availableFields.has(field));
    if (missing.length) {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: row.id,
        filterHash: row.filter_hash,
        reason: `Required normalized fields are missing: ${missing.join(", ")}.`
      };
    }
    if (
      new Date(row.continuous_since).valueOf() > windowStart.valueOf() ||
      new Date(row.last_successful_read_at).valueOf() + 30_000 < windowEnd.valueOf()
    ) {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: row.id,
        filterHash: row.filter_hash,
        reason: "The signed continuous-read interval does not cover the requested correlation window."
      };
    }
    const configurationDrift = this.database
      .prepare(
        `SELECT 1 FROM endpoint_minimized_facts
         WHERE mission_id = ? AND endpoint_id = ?
           AND provider = ? AND channel = ? AND event_family = ?
           AND occurred_at >= ? AND occurred_at <= ?
           AND filter_hash <> ?
         LIMIT 1`
      )
      .get(
        missionId,
        endpointId,
        requirement.provider,
        requirement.channel,
        requirement.eventFamily,
        windowStart.toISOString(),
        windowEnd.toISOString(),
        row.filter_hash
      );
    if (configurationDrift) {
      return {
        ...base,
        status: "blocked",
        capabilitySnapshotId: row.id,
        filterHash: row.filter_hash,
        reason: "Facts collected under a different filter overlap the requested window."
      };
    }
    return {
      ...base,
      status: "live-supported",
      capabilitySnapshotId: row.id,
      filterHash: row.filter_hash,
      reason:
        "Exact stream, fields, filter, continuity, loss and freshness measurements cover this window."
    };
  }

  private factsForWindow(
    missionId: string,
    endpointId: string,
    windowStart: Date,
    windowEnd: Date
  ): FactRow[] {
    return this.database
      .prepare(
        `SELECT * FROM endpoint_minimized_facts
         WHERE mission_id = ? AND endpoint_id = ?
           AND occurred_at >= ? AND occurred_at <= ?
         ORDER BY occurred_at, fact_id
         LIMIT 10000`
      )
      .all(
        missionId,
        endpointId,
        windowStart.toISOString(),
        windowEnd.toISOString()
      ) as unknown as FactRow[];
  }

  private factCountForWindow(
    missionId: string,
    endpointId: string,
    windowStart: Date,
    windowEnd: Date
  ): number {
    const row = this.database
      .prepare(
        `SELECT COUNT(*) AS count FROM endpoint_minimized_facts
         WHERE mission_id = ? AND endpoint_id = ?
           AND occurred_at >= ? AND occurred_at <= ?`
      )
      .get(
        missionId,
        endpointId,
        windowStart.toISOString(),
        windowEnd.toISOString()
      ) as { count: number };
    return row.count;
  }

  private factsIntegrityValid(facts: readonly FactRow[], missionId: string): boolean {
    try {
      for (const fact of facts) {
        const fields = endpointFactFieldsSchema.parse(JSON.parse(fact.fields_json));
        if (
          canonicalHash(fields) !== fact.fields_hash ||
          canonicalHash({
            missionId: fact.mission_id,
            connectorId: fact.connector_id,
            endpointId: fact.endpoint_id,
            capabilitySnapshotId: fact.capability_snapshot_id,
            provider: fact.provider,
            channel: fact.channel,
            eventFamily: fact.event_family,
            filterHash: fact.filter_hash,
            factId: fact.fact_id,
            occurredAt: fact.occurred_at,
            sourceRecordIdHash: fact.source_record_id_hash,
            fields
          }) !== fact.fact_hash
        ) {
          return false;
        }
      }
      for (const batchId of new Set(facts.map((fact) => fact.batch_id))) {
        const batch = this.database
          .prepare(
            `SELECT evidence_artifact_id FROM endpoint_fact_batches
             WHERE id = ? AND mission_id = ?`
          )
          .get(batchId, missionId) as { evidence_artifact_id: string } | undefined;
        if (!batch || !this.evidence.verify(batch.evidence_artifact_id)) return false;
        const observation = this.evidence.observationForMission(
          batch.evidence_artifact_id,
          missionId
        );
        if (observation.source_event_id !== batchId) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  private storeCorrelation(
    result: LiveCorrelationResult,
    ruleIds: string[],
    operator: string,
    now: Date
  ): LiveCorrelationRun {
    const id = `live-correlation-${randomUUID()}`;
    const resultJson = stableJson(result);
    if (Buffer.byteLength(resultJson, "utf8") > 262_144) {
      throw new Error("LIVE_CORRELATION_RESULT_TOO_LARGE");
    }
    const resultHash = canonicalHash(result);
    const artifact = this.evidence.seal(resultJson, "application/json", {
      missionId: result.missionId,
      sourceEventId: id,
      capturedAt: now,
      provenance: {
        sourceType: "endpoint-live-correlation",
        schemaVersion: 1,
        endpointId: result.endpointId,
        ruleSetVersion: result.ruleSetVersion,
        status: result.status,
        verdict: result.verdict,
        resultHash
      }
    });
    const coverageJson = stableJson(result.coverage);
    const matchedFactIdsJson = stableJson(result.matchedFactIds);
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO endpoint_live_correlation_runs(
             id, mission_id, endpoint_id, schema_version, rule_set_version,
             selected_rule_ids_json, selected_rule_ids_hash, window_start, window_end,
             coverage_json, coverage_hash, matched_fact_ids_json, matched_fact_ids_hash,
             status, verdict, alert_count, result_json, result_hash,
             evidence_artifact_id, operator, created_at
           ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          result.missionId,
          result.endpointId,
          result.ruleSetVersion,
          stableJson(ruleIds),
          canonicalHash(ruleIds),
          result.windowStart,
          result.windowEnd,
          coverageJson,
          canonicalHash(result.coverage),
          matchedFactIdsJson,
          canonicalHash(result.matchedFactIds),
          result.status,
          result.verdict,
          result.alerts.length,
          resultJson,
          resultHash,
          artifact.id,
          operator,
          now.toISOString()
        );
      const insertAlert = this.database.prepare(
        `INSERT INTO endpoint_live_blue_alerts(
           id, run_id, mission_id, endpoint_id, rule_id, signal, severity,
           matched_fact_ids_json, matched_fact_ids_hash, reason, disposition, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'needs-review', ?)`
      );
      for (const alert of result.alerts) {
        insertAlert.run(
          alert.id,
          id,
          result.missionId,
          result.endpointId,
          alert.ruleId,
          alert.signal,
          alert.severity,
          stableJson(alert.matchedFactIds),
          canonicalHash(alert.matchedFactIds),
          alert.reason,
          now.toISOString()
        );
      }
      this.audit.append(
        "endpoint.live-correlation.completed",
        {
          correlationRunId: id,
          missionId: result.missionId,
          endpointId: result.endpointId,
          ruleSetVersion: result.ruleSetVersion,
          selectedRuleIdsHash: canonicalHash(ruleIds),
          coverageHash: canonicalHash(result.coverage),
          matchedFactIdsHash: canonicalHash(result.matchedFactIds),
          status: result.status,
          verdict: result.verdict,
          alertCount: result.alerts.length,
          resultHash,
          evidenceArtifactId: artifact.id,
          operator
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getRun(id);
  }

  private getRun(id: string): LiveCorrelationRun {
    const row = this.database
      .prepare("SELECT * FROM endpoint_live_correlation_runs WHERE id = ?")
      .get(id) as unknown as CorrelationRunRow | undefined;
    if (!row) throw new Error("ENDPOINT_LIVE_CORRELATION_NOT_FOUND");
    return this.toRun(row);
  }

  private toRun(row: CorrelationRunRow): LiveCorrelationRun {
    const result = JSON.parse(row.result_json) as LiveCorrelationResult;
    const integrityValid =
      canonicalHash(result) === row.result_hash &&
      this.evidence.verify(row.evidence_artifact_id) &&
      this.evidence.read(row.evidence_artifact_id).toString("utf8") === row.result_json;
    return {
      id: row.id,
      missionId: row.mission_id,
      endpointId: row.endpoint_id,
      operator: row.operator,
      createdAt: row.created_at,
      evidenceArtifactId: row.evidence_artifact_id,
      resultHash: row.result_hash,
      integrityValid,
      result
    };
  }
}
