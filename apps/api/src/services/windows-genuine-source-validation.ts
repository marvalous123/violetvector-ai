import type {
  EndpointFactChannel,
  EndpointFactEventFamily,
  EndpointFactProvider
} from "./endpoint-fact-correlation-service.js";

export type GenuineSourceAssessment =
  | "correlation-required"
  | "enrichment-required"
  | "external-source-required"
  | "synthetic-only"
  | "source-mismatch";

export function isGenuineLiveEligible(
  assessment: GenuineSourceAssessment
): boolean {
  return assessment === "correlation-required" ||
    assessment === "enrichment-required";
}

export const WINDOWS_GENUINE_SOURCE_REFERENCES = {
  sysmon: "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
  advancedAudit:
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration",
  event4688:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688",
  event4624:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
  auditLogon:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon",
  kerberos:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service",
  event4610:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4610",
  event4657:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657",
  event4663:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663",
  event5061:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5061",
  event4698:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698",
  event4702:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702",
  event4697:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697",
  defender:
    "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",
  event1102:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
  event4946:
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4946"
} as const;

export type GenuineSourceReferenceId = keyof typeof WINDOWS_GENUINE_SOURCE_REFERENCES;

export interface WindowsGenuineSourceValidation {
  readonly ruleId: string;
  readonly provider: EndpointFactProvider;
  readonly channel: EndpointFactChannel;
  readonly eventFamily: EndpointFactEventFamily;
  readonly assessment: GenuineSourceAssessment;
  readonly sourceRefs: readonly GenuineSourceReferenceId[];
  readonly eventIds: readonly number[];
  readonly limitationCode: string;
}

export const WINDOWS_GENUINE_SOURCE_VALIDATIONS = [
  { ruleId: "BR-CRED-001", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "process-access", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [10], limitationCode: "TARGET_AND_ACCESS_MASK_CLASSIFICATION_REQUIRED" },
  { ruleId: "BR-CRED-002", provider: "windows-security", channel: "security", eventFamily: "file-access", assessment: "correlation-required", sourceRefs: ["event4663"], eventIds: [4663], limitationCode: "TARGET_SACL_AND_PROTECTED_STORE_CLASSIFICATION_REQUIRED" },
  { ruleId: "BR-CRED-003", provider: "windows-security", channel: "security", eventFamily: "file-access", assessment: "correlation-required", sourceRefs: ["event4663"], eventIds: [4663], limitationCode: "TARGET_SACL_AND_SECRET_LOCATION_CLASSIFICATION_REQUIRED" },
  { ruleId: "BR-CRED-004", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "process-access", assessment: "synthetic-only", sourceRefs: ["sysmon"], eventIds: [], limitationCode: "NO_DOCUMENTED_LOCAL_EVENT_FOR_INPUT_HOOK_REGISTRATION" },
  { ruleId: "BR-CRED-005", provider: "windows-security", channel: "security", eventFamily: "authentication", assessment: "correlation-required", sourceRefs: ["auditLogon", "event4624"], eventIds: [4624, 4625], limitationCode: "FAILURE_BURST_AND_LATER_SUCCESS_REQUIRE_STATEFUL_CORRELATION" },
  { ruleId: "BR-CRED-006", provider: "windows-security", channel: "security", eventFamily: "ticket-request", assessment: "external-source-required", sourceRefs: ["kerberos"], eventIds: [4768, 4769], limitationCode: "KERBEROS_TICKET_SOURCE_REQUIRES_DOMAIN_CONTROLLER" },
  { ruleId: "BR-CRED-007", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "file-access", assessment: "synthetic-only", sourceRefs: ["sysmon", "event4663"], eventIds: [4663], limitationCode: "SESSION_READ_REQUIRES_UNIMPLEMENTED_NEW_SESSION_CONTEXT" },
  { ruleId: "BR-CRED-008", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "file-access", assessment: "external-source-required", sourceRefs: ["sysmon", "event4663"], eventIds: [4663], limitationCode: "TOKEN_READ_REQUIRES_UNBOUND_APPLICATION_API_AUDIT_SOURCE" },
  { ruleId: "BR-CRED-009", provider: "windows-security", channel: "security", eventFamily: "authentication-component-change", assessment: "correlation-required", sourceRefs: ["event4610", "event4657"], eventIds: [4610, 4622, 4657], limitationCode: "LOAD_AND_REGISTRY_CHANGE_SOURCES_REQUIRE_NORMALIZED_CORRELATION" },
  { ruleId: "BR-CRED-010", provider: "windows-security", channel: "security", eventFamily: "certificate-key-access", assessment: "correlation-required", sourceRefs: ["event5061"], eventIds: [5061], limitationCode: "KSP_AUDITING_AND_KEY_BASELINE_REQUIRED_EXPORT_NOT_DIRECT" },

  { ruleId: "BR-PAYLOAD-001", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "process-start", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [1, 7, 15], limitationCode: "PROCESS_ORIGIN_AND_SIGNATURE_REQUIRE_MULTI_EVENT_CORRELATION" },
  { ruleId: "BR-PAYLOAD-002", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "PROCESS_CLASS_AND_TRUST_REQUIRE_LOCAL_NORMALIZATION" },
  { ruleId: "BR-PAYLOAD-003", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "ORIGIN_ZONE_REQUIRES_LOCAL_PATH_OR_ZONE_NORMALIZATION" },
  { ruleId: "BR-PAYLOAD-004", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "PACKAGE_ORIGIN_AND_SIGNER_REQUIRE_LOCAL_ENRICHMENT" },
  { ruleId: "BR-PAYLOAD-005", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "MODULE_ORIGIN_AND_SIGNER_REQUIRE_LOCAL_ENRICHMENT" },
  { ruleId: "BR-PAYLOAD-006", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "MODULE_ORIGIN_AND_SIGNER_REQUIRE_LOCAL_ENRICHMENT" },
  { ruleId: "BR-PAYLOAD-007", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "image-load", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [7], limitationCode: "IMAGE_LOAD_IS_OPT_IN_AND_REQUIRES_PATH_BASELINE" },
  { ruleId: "BR-PAYLOAD-008", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "process-access", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [8, 10], limitationCode: "ACCESS_MASK_OR_REMOTE_THREAD_AND_BASELINE_REQUIRED" },
  { ruleId: "BR-PAYLOAD-009", provider: "windows-security", channel: "security", eventFamily: "scheduled-task-change", assessment: "correlation-required", sourceRefs: ["event4698", "event4702"], eventIds: [4698, 4702], limitationCode: "TASK_XML_MUST_BE_NORMALIZED_LOCALLY_WITHOUT_RAW_FORWARDING" },
  { ruleId: "BR-PAYLOAD-010", provider: "windows-security", channel: "security", eventFamily: "service-change", assessment: "correlation-required", sourceRefs: ["event4697"], eventIds: [4697], limitationCode: "SERVICE_IMAGE_ORIGIN_AND_SIGNER_REQUIRE_LOCAL_ENRICHMENT" },

  { ruleId: "BR-EVASION-001", provider: "windows-defender", channel: "defender-operational", eventFamily: "security-control-change", assessment: "correlation-required", sourceRefs: ["defender"], eventIds: [5001, 5007, 5010, 5012, 5013], limitationCode: "DEFENDER_CHANGE_EVENTS_NEED_ACTOR_AND_OUTCOME_CORRELATION" },
  { ruleId: "BR-EVASION-002", provider: "windows-security", channel: "security", eventFamily: "event-log-impairment", assessment: "correlation-required", sourceRefs: ["advancedAudit", "event4657"], eventIds: [1100, 4719, 4657], limitationCode: "AUDIT_POLICY_AND_REGISTRY_EVENTS_REQUIRE_CORRELATION" },
  { ruleId: "BR-EVASION-003", provider: "windows-security", channel: "security", eventFamily: "event-log-clear", assessment: "correlation-required", sourceRefs: ["event1102"], eventIds: [1102], limitationCode: "ACCOUNT_TRUST_CLASSIFICATION_REQUIRED" },
  { ruleId: "BR-EVASION-004", provider: "windows-security", channel: "security", eventFamily: "firewall-policy-change", assessment: "correlation-required", sourceRefs: ["event4946"], eventIds: [4946, 4947, 4948, 5025], limitationCode: "FIREWALL_RULE_AND_SERVICE_EVENTS_REQUIRE_NORMALIZED_CORRELATION" },
  { ruleId: "BR-EVASION-005", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "process-access", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [8, 10, 25], limitationCode: "INJECTION_INDICATORS_REQUIRE_MULTI_EVENT_CORRELATION" },
  { ruleId: "BR-EVASION-006", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "TRUSTED_BINARY_CLASS_AND_ORIGIN_REQUIRE_LOCAL_NORMALIZATION" },
  { ruleId: "BR-EVASION-007", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "COMMAND_LINE_AUDIT_IS_OPT_IN_AND_CONTENT_MUST_BE_CLASSIFIED_LOCALLY" },
  { ruleId: "BR-EVASION-008", provider: "windows-security", channel: "security", eventFamily: "process-start", assessment: "enrichment-required", sourceRefs: ["event4688"], eventIds: [4688], limitationCode: "PE_METADATA_COMPARISON_REQUIRES_LOCAL_ENRICHMENT" },
  { ruleId: "BR-EVASION-009", provider: "windows-security", channel: "security", eventFamily: "file-attribute-change", assessment: "correlation-required", sourceRefs: ["event4663"], eventIds: [4663], limitationCode: "TARGET_SACL_AND_HIDDEN_ATTRIBUTE_CLASSIFICATION_REQUIRED" },
  { ruleId: "BR-EVASION-010", provider: "windows-sysmon", channel: "sysmon-operational", eventFamily: "file-access", assessment: "correlation-required", sourceRefs: ["sysmon"], eventIds: [1, 23, 26], limitationCode: "RECENT_EXECUTION_REQUIRES_PROCESS_TO_FILE_HISTORY" }
] as const satisfies readonly WindowsGenuineSourceValidation[];
