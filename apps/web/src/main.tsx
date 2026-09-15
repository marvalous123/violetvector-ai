import { StrictMode, useEffect, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import {
  parseEnrollmentIdentity,
  parseEnrollmentProof,
  parseSignedCapabilityReport,
  SCM_COLLECTOR_VERSION,
  SCM_FIELDS,
  SCM_FILTER_HASH,
  validateAcceptedCapability,
  validateApprovedEndpointIdentity,
  validateCapabilityReportHash,
  validateEnrollmentChallenge,
  validateRegisteredEnrollmentKey,
  type ApprovedEndpointIdentity,
  type AcceptedCapability,
  type EnrollmentChallenge,
  type NativeEnrollmentIdentity
} from "./enrollment-ceremony";
import "./styles.css";

function localDateTimeInputValue(date = new Date()): string {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

interface Mission {
  id: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

interface Dashboard {
  missions: Mission[];
  counts: { activeRuns: number; pendingApprovals: number; findings: number; artifacts: number };
  emergencyStop: { state: string };
  audit: { valid: boolean; eventsChecked: number };
  executionEnabled: boolean;
  productEdition: "starter" | "professional";
}

interface MissionCockpit {
  mission: Mission;
  profile: {
    mode: "standard" | "synthetic_demo";
    templateVersion: string | null;
    executionPermitted: boolean;
    boundaryText: string;
  };
  authorization: {
    present: boolean;
    scopeVersionId: string | null;
    version: number | null;
    startsAt: string | null;
    expiresAt: string | null;
    policyVersion: string | null;
    statement: string | null;
    targetCount: number;
  };
  counts: {
    runs: number;
    activeRuns: number;
    approvalsPending: number;
    evidenceArtifacts: number;
    findings: number;
    acceptedFindings: number;
    remediations: number;
    openRemediations: number;
    imports: number;
    endpoints: number;
    blueRuns: number;
    generatedReports: number;
  };
  purple: {
    exercised: number;
    total: number;
    integrityFailed: number;
  };
  checklist: Array<{
    key: string;
    title: string;
    status: "complete" | "pending" | "blocked";
    detail: string;
  }>;
  latestReport: {
    id: string;
    status: string;
    templateVersion: string;
    frozenAt: string;
    jsonArtifactId: string | null;
    htmlArtifactId: string | null;
  } | null;
  timeline: Array<{
    sequence: number;
    occurredAt: string;
    eventType: string;
    eventHash: string;
  }>;
  integrity: {
    auditValid: boolean;
    eventsChecked: number;
  };
}

interface ModelStatus {
  health: { healthy: boolean; provider: string; model: string; version?: string; latencyMs: number; error?: string };
  capabilities: { taskTier: string; authority?: string; toolAccess: boolean; commandAccess: boolean; mcpAccess: boolean };
  invocations: Array<Record<string, unknown>>;
}

interface AdvisoryPlan {
  objective: string;
  assumptions: string[];
  steps: Array<{ description: string; rationale: string; requiresHumanReview: boolean }>;
  openQuestions: string[];
}

interface OperatorSession {
  authenticated: boolean;
  operator?: string;
  csrfToken?: string;
  tabCapability?: string;
  expiresAt?: string;
}

interface ExecutorStatus {
  available: boolean;
  versionProofEnabled: boolean;
  targetExecutionEnabled: boolean;
  capabilityId: "mcpwn.version.v1";
  activeExecutions?: number;
  status?: Record<string, unknown>;
  error?: string;
}

interface SupportDiagnostics {
  generatedAt: string;
  product: { name: string; version: string; edition: string };
  runtime: { node: string; platform: string; architecture: string; loopbackOnly: boolean };
  integrity: {
    databaseQuickCheck: boolean;
    audit: { valid: boolean; eventsChecked: number; brokenAtSequence?: number };
    evidenceTotal: number;
    evidenceChecked: number;
    evidenceValid: number;
    evidenceInvalid: number;
    evidenceComplete: boolean;
  };
  records: Record<string, number>;
  storage: { databaseConfigured: boolean; evidenceStoreConfigured: boolean; pathsDisclosed: false };
  safeToShare: true;
  limitations: string[];
}

interface VersionExecution {
  capabilityId: string;
  executionId: string;
  output: string;
  outputBytes: number;
  durationMs: number;
  binarySha256: string;
  configSha256: string;
  completedAt: string;
}

interface VersionResult {
  execution: VersionExecution;
  artifact: { id: string; sha256: string; size_bytes: number; media_type: string };
}

interface ExecutionLifecycle {
  id: string;
  capabilityId: string;
  operator: string;
  status: string;
  failureCode: string | null;
  createdAt: string;
  finishedAt: string | null;
}

interface ExecutionRegistry {
  summary: { total: number; nonterminal: number; orphaned: number };
  executions: ExecutionLifecycle[];
}

interface CapabilityDescriptor {
  id: string;
  minimumEdition: "starter" | "professional";
  name: string;
  category: string;
  description: string;
  status: "enabled" | "unavailable" | "planned";
  unavailableReason: string | null;
  riskTier: "T0" | "T1" | "T2";
  operatorDifficulty: string;
  networkNoise: "none" | "low" | "medium" | "high";
  approvalPolicy: string;
  targetRequired: boolean;
  destructive: false;
  maxRuntimeMs: number;
  maxOutputBytes: number;
  portLimit: number | null;
  fixedTechnique: string;
  evidenceOutput: string;
  safetyNote: string;
  prepareRoute: string | null;
}

interface BlueRule {
  id: string;
  title: string;
  category: "credential-access" | "payload-execution" | "defense-evasion";
  severity: "medium" | "high";
  attackTechniqueId: string;
  attackTechniqueName: string;
  referenceUrl: string;
  requiredTelemetry: string[];
  detectionLogic: string;
  likelyFalsePositives: string;
  responseGuidance: string;
  readiness: "synthetic-validated";
  liveStatus: "connector-required";
}

interface BlueScenario {
  id: "credential-access" | "payload-execution" | "defense-evasion" | "combined-incident";
  name: string;
  description: string;
  synthetic: true;
  expectedRuleIds: string[];
}

interface BlueAlert {
  id: string;
  ruleId: string;
  title: string;
  category: BlueRule["category"];
  severity: "medium" | "high";
  confidence: "high";
  attackTechniqueId: string;
  attackTechniqueName: string;
  matchedEventIds: string[];
  reason: string;
  responseGuidance: string;
  disposition: "needs-review";
}

interface BlueRun {
  id: string;
  missionId: string;
  scenarioId: BlueScenario["id"];
  ruleSetVersion: string;
  eventCount: number;
  alertCount: number;
  resultHash: string;
  evidenceArtifactId: string;
  operator: string;
  createdAt: string;
  integrityValid: boolean;
  result: {
    scenario: BlueScenario;
    alerts: BlueAlert[];
    summary: {
      highestSeverity: "none" | "medium" | "high";
      verdict: "no-rule-match" | "suspicious-behaviour-detected";
      limitation: string;
    };
  };
}

interface BlueValidationMatrixRow {
  testCaseId: string;
  ruleId: string;
  title: string;
  category: BlueRule["category"];
  attackTechniqueId: string;
  attackTechniqueName: string;
  scenarioId: Exclude<BlueScenario["id"], "combined-incident">;
  requiredTelemetry: string[];
  syntheticValidation: {
    status: "not-run" | "detected" | "not-detected" | "integrity-failed";
    latestRunId: string | null;
    observedAlertId: string | null;
    evidenceArtifactId: string | null;
    validatedAt: string | null;
  };
  liveValidation: {
    status: "connector-required" | "live-supported" | "blocked";
    endpointEvidencePresent: boolean;
    latestRunId?: string;
    endpointId?: string;
    evidenceArtifactId?: string;
    validatedAt?: string;
    reason?: string;
  };
}

interface EndpointCapabilitySnapshot {
  id: string;
  provider: string;
  channel: string;
  eventFamily: string;
  health: "healthy" | "degraded" | "stale" | "gapped";
  lastSuccessfulReadAt: string;
  freshUntil: string;
  evidenceArtifactId: string;
  limitation: string;
}

interface LiveCorrelationRun {
  id: string;
  endpointId: string;
  createdAt: string;
  evidenceArtifactId: string;
  resultHash: string;
  integrityValid: boolean;
  result: {
    status: "completed" | "blocked-coverage";
    verdict: "reviewable-alerts-produced" | "no-rule-match-observed" | "coverage-blocked";
    alerts: Array<{
      id: string;
      ruleId: string;
      title: string;
      reason: string;
      matchedFactIds: string[];
    }>;
    coverage: Array<{
      ruleId: string;
      status: "live-supported" | "blocked";
      reason: string;
    }>;
    limitation: string;
  };
}

interface BlueWorkspace {
  rules: BlueRule[];
  scenarios: BlueScenario[];
  runs: BlueRun[];
  validationMatrix: BlueValidationMatrixRow[];
  coverage: {
    syntheticValidatedRuleIds: string[];
    liveSupportedRuleIds: string[];
    liveStatus: "connector-required" | "window-validated";
  };
  liveRuns: LiveCorrelationRun[];
  liveRuleIds: string[];
  liveEndpoints: Array<{
    identity: {
      endpointId: string;
      missionId: string;
      status: string;
      lastSeenAt: string | null;
    };
    capabilities: EndpointCapabilitySnapshot[];
  }>;
  endpointAccess: {
    mode: "read-only-telemetry";
    status: "connector-required" | "enrollment-ready";
    commandExecution: false;
    remoteShell: false;
    note: string;
  };
}

interface WorkflowWorkspace {
  benchmarks: Array<Record<string, unknown>>;
  remediations: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  artifacts: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  imports: Array<Record<string, unknown>>;
  endpoints: Array<Record<string, unknown>>;
  renewals: Array<Record<string, unknown>>;
  endpointTrustConfigured: boolean;
  intake: {
    direction: string;
    commandChannel: false;
    remoteShell: false;
    responseActions: false;
  };
}

interface ReportQaRecord {
  id: string;
  status: "pending" | "changes-requested" | "approved";
  publicationReady: boolean;
  integrityValid: true;
  reviewer: string | null;
  reviewedAt: string | null;
  issues: string[];
  note: string | null;
}

interface ReportExportBundle {
  id: string;
  status: "pending" | "approved" | "changes-requested";
  publicationReady: boolean;
  integrityValid: true;
  reviewer: string | null;
  reviewedAt: string | null;
  note: string | null;
  issues: string[];
  outputs: {
    pdf: { artifactId: string; sha256: string };
    docx: { artifactId: string; sha256: string };
  };
}

interface EngagementTestPlan {
  id: string;
  missionId: string;
  version: number;
  title: string;
  objective: string;
  contentHash: string;
  createdBy: string;
  createdAt: string;
  integrityValid: boolean;
  summary: Record<"completed" | "skipped" | "blocked" | "not-applicable", number>;
  procedures: Array<{
    id: string;
    key: string;
    title: string;
    state: "completed" | "skipped" | "blocked" | "not-applicable";
    rationale: string;
    capabilityId: string | null;
    blueRuleId: string | null;
    evidence: Array<{ artifactId: string }>;
  }>;
  claimLimitation: string;
}

interface MissionSearchResult {
  kind: string;
  id: string;
  title: string;
  detail: string;
  status: string | null;
  occurredAt: string;
}

interface OriginalRetestComparison {
  configurationEquivalent: boolean;
  original: { runId: string; status: string; evidence: unknown[] };
  retest: { runId: string; status: string; evidence: unknown[] };
  evidenceHashComparison: { shared: string[]; originalOnly: string[]; retestOnly: string[] };
  findings: Array<{ title: string; assessment: string }>;
  claimLimitation: string;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function formatBytes(value: unknown): string {
  return typeof value === "number" ? `${value.toLocaleString()} bytes` : "unknown size";
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32_768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
  }
  return btoa(binary);
}

const emptyDashboard: Dashboard = {
  missions: [],
  counts: { activeRuns: 0, pendingApprovals: 0, findings: 0, artifacts: 0 },
  emergencyStop: { state: "ready" },
  audit: { valid: true, eventsChecked: 0 },
  executionEnabled: false,
  productEdition: "professional"
};

let csrfToken = "";
const tabCapabilityStorageKey = "war-room-tab-capability";
let tabCapability = sessionStorage.getItem(tabCapabilityStorageKey) ?? "";
const targetControlCheckTimeoutMs = 65_000;

async function api<T>(path: string, init: RequestInit = {}, timeoutMs?: number): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (tabCapability) headers.set("X-War-Room-Tab", tabCapability);
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("X-War-Room-CSRF", csrfToken);
  }
  const controller = timeoutMs === undefined ? null : new AbortController();
  const timer = controller === null ? undefined : setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...init,
      headers,
      credentials: "same-origin",
      ...(controller ? { signal: controller.signal } : {})
    });
    const body = (await response.json()) as T & { error?: string };
    if (!response.ok) throw new Error(body.error ?? `HTTP_${response.status}`);
    return body;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("TARGET_CONTROL_CHECK_TIMED_OUT", { cause: error });
    }
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function App() {
  const [view, setView] = useState("Missions");
  const [dashboard, setDashboard] = useState<Dashboard>(emptyDashboard);
  const [connection, setConnection] = useState<"loading" | "online" | "offline">("loading");
  const [newMissionOpen, setNewMissionOpen] = useState(false);
  const [missionName, setMissionName] = useState("");
  const [selectedMission, setSelectedMission] = useState<Mission | null>(null);
  const [cockpit, setCockpit] = useState<MissionCockpit | null>(null);
  const [cockpitBusyId, setCockpitBusyId] = useState("");
  const [demoBusy, setDemoBusy] = useState(false);
  const [targetAddress, setTargetAddress] = useState("");
  const [authorization, setAuthorization] = useState("");
  const [privateIsolation, setPrivateIsolation] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [records, setRecords] = useState<Array<Record<string, unknown>>>([]);
  const [recordsLoading, setRecordsLoading] = useState(false);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [aiMissionId, setAiMissionId] = useState("");
  const [aiObjective, setAiObjective] = useState("");
  const [plan, setPlan] = useState<AdvisoryPlan | null>(null);
  const [modelBusy, setModelBusy] = useState(false);
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [operatorName, setOperatorName] = useState("");
  const [bootstrapSecret, setBootstrapSecret] = useState("");
  const [executorStatus, setExecutorStatus] = useState<ExecutorStatus | null>(null);
  const [supportDiagnostics, setSupportDiagnostics] = useState<SupportDiagnostics | null>(null);
  const [executorStatusError, setExecutorStatusError] = useState("");
  const [executorBusy, setExecutorBusy] = useState(false);
  const [executorResult, setExecutorResult] = useState<VersionResult | null>(null);
  const [executorError, setExecutorError] = useState("");
  const [executionRegistry, setExecutionRegistry] = useState<ExecutionRegistry | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityDescriptor[]>([]);
  const [productEdition, setProductEdition] = useState<"starter" | "professional">("professional");
  const [targetMissionId, setTargetMissionId] = useState("");
  const [targetPorts, setTargetPorts] = useState("22,80,443,8080");
  const [targetIntensity, setTargetIntensity] = useState(1);
  const [targetBusy, setTargetBusy] = useState(false);
  const [targetResult, setTargetResult] = useState<Record<string, unknown> | null>(null);
  const [reviewBusyId, setReviewBusyId] = useState("");
  const [reportMissionId, setReportMissionId] = useState("");
  const [reportBusyId, setReportBusyId] = useState("");
  const [reportQaConfirmedId, setReportQaConfirmedId] = useState("");
  const [reportExportConfirmedId, setReportExportConfirmedId] = useState("");
  const [reportQaNote, setReportQaNote] = useState("");
  const [reportQaIssue, setReportQaIssue] = useState("claims");
  const [blueWorkspace, setBlueWorkspace] = useState<BlueWorkspace | null>(null);
  const [blueMissionId, setBlueMissionId] = useState("");
  const [blueScenarioId, setBlueScenarioId] = useState<BlueScenario["id"]>("combined-incident");
  const [blueBusy, setBlueBusy] = useState(false);
  const [blueEndpointId, setBlueEndpointId] = useState("");
  const [blueLiveRuleId, setBlueLiveRuleId] = useState("BR-EVASION-003");
  const [workflow, setWorkflow] = useState<WorkflowWorkspace | null>(null);
  const [workflowBusy, setWorkflowBusy] = useState(false);
  const [workflowEditorId, setWorkflowEditorId] = useState("");
  const [workflowNote, setWorkflowNote] = useState("");
  const [workflowEvidenceIds, setWorkflowEvidenceIds] = useState("");
  const [workflowOutcome, setWorkflowOutcome] = useState("remediated");
  const [workflowFixChangeType, setWorkflowFixChangeType] = useState("device-configuration");
  const [workflowFixActionAt, setWorkflowFixActionAt] = useState("");
  const [workflowFixSummary, setWorkflowFixSummary] = useState("");
  const [workflowFixObservedState, setWorkflowFixObservedState] = useState("");
  const [benchmarkMissionId, setBenchmarkMissionId] = useState("");
  const [benchmarkNote, setBenchmarkNote] = useState("");
  const [benchmarkMilestone, setBenchmarkMilestone] = useState("scope-authorized");
  const [benchmarkRecoveryResult, setBenchmarkRecoveryResult] = useState<"" | "recovered" | "failed">("");
  const [benchmarkMetrics, setBenchmarkMetrics] = useState({
    operatorSteps: 9,
    policyDenials: 0,
    unsupportedClaimsRejected: 0,
    recoveryElapsedMs: 0,
    modelAccepted: 0,
    modelEdited: 0,
    modelRejected: 0
  });
  const [importMissionId, setImportMissionId] = useState("");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [enrollmentMissionId, setEnrollmentMissionId] = useState("");
  const [enrollmentIdentityJson, setEnrollmentIdentityJson] = useState("");
  const [enrollmentIdentity, setEnrollmentIdentity] = useState<NativeEnrollmentIdentity | null>(null);
  const [enrollmentChallenge, setEnrollmentChallenge] = useState<EnrollmentChallenge | null>(null);
  const [enrollmentProofJson, setEnrollmentProofJson] = useState("");
  const [enrollmentFingerprint, setEnrollmentFingerprint] = useState("");
  const [enrollmentConfirmed, setEnrollmentConfirmed] = useState(false);
  const [enrollmentEndpoint, setEnrollmentEndpoint] = useState<ApprovedEndpointIdentity | null>(null);
  const [capabilityReportJson, setCapabilityReportJson] = useState("");
  const [acceptedCapability, setAcceptedCapability] = useState<AcceptedCapability | null>(null);
  const [enrollmentBusy, setEnrollmentBusy] = useState(false);
  const [planMissionId, setPlanMissionId] = useState("");
  const [testPlans, setTestPlans] = useState<EngagementTestPlan[]>([]);
  const [planBusy, setPlanBusy] = useState(false);
  const [missionSearchQuery, setMissionSearchQuery] = useState("");
  const [missionSearchResults, setMissionSearchResults] = useState<MissionSearchResult[]>([]);
  const [originalRunId, setOriginalRunId] = useState("");
  const [retestRunId, setRetestRunId] = useState("");
  const [comparison, setComparison] = useState<OriginalRetestComparison | null>(null);

  const refresh = async () => {
    try {
      const state = await api<Dashboard>("/api/dashboard");
      setDashboard(state);
      setConnection("online");
    } catch {
      setConnection("offline");
    }
  };

  useEffect(() => {
    void api<OperatorSession>("/api/session")
      .then(async (state) => {
        csrfToken = state.csrfToken ?? "";
        tabCapability = state.tabCapability ?? tabCapability;
        setSession(state);
        setConnection("online");
        if (state.authenticated) await refresh();
      })
      .catch(() => {
        setSession({ authenticated: false });
        setConnection("offline");
      });
  }, []);

  useEffect(() => {
    if (
      view === "Missions" ||
      view === "Local AI" ||
      view === "Workflow" ||
      view === "Plan & Compare"
    ) return;
    const routes: Record<string, { path: string; key: string }> = {
      Approvals: { path: "/api/approvals", key: "approvals" },
      Findings: { path: "/api/findings", key: "findings" },
      Evidence: { path: "/api/evidence", key: "artifacts" },
      Reports: { path: "/api/reports", key: "reports" },
      System: { path: "/api/system/audit", key: "events" }
    };
    const route = routes[view];
    if (!route) return;
    setRecordsLoading(true);
    void api<Record<string, unknown>>(route.path)
      .then((body) => setRecords((body[route.key] as Array<Record<string, unknown>> | undefined) ?? []))
      .catch((error) => setFeedback(error instanceof Error ? error.message : "View failed to load"))
      .finally(() => setRecordsLoading(false));
  }, [view]);

  useEffect(() => {
    if (view !== "Local AI") return;
    void api<ModelStatus>("/api/system/model")
      .then(setModelStatus)
      .catch((error) => setFeedback(error instanceof Error ? error.message : "Model status failed to load"));
  }, [view]);

  useEffect(() => {
    if (view !== "Capabilities" && view !== "Approvals") return;
    void api<{ capabilities: CapabilityDescriptor[]; edition: "starter" | "professional" }>("/api/capabilities")
      .then((body) => {
        setCapabilities(body.capabilities);
        setProductEdition(body.edition);
      })
      .catch((error) => setFeedback(error instanceof Error ? error.message : "Capability catalogue failed to load"));
  }, [view]);

  const refreshBlueWorkspace = async (missionId = blueMissionId) => {
    const query = missionId ? `?missionId=${encodeURIComponent(missionId)}` : "";
    const state = await api<BlueWorkspace>(`/api/blue${query}`);
    setBlueWorkspace(state);
    if (
      missionId &&
      (!blueEndpointId ||
        !state.liveEndpoints.some((endpoint) => endpoint.identity.endpointId === blueEndpointId))
    ) {
      setBlueEndpointId(state.liveEndpoints[0]?.identity.endpointId ?? "");
    }
  };

  useEffect(() => {
    if (view !== "Blue Team") return;
    void refreshBlueWorkspace()
      .catch((error) => setFeedback(error instanceof Error ? error.message : "Blue Team workspace failed to load"));
  }, [view, blueMissionId]);

  const refreshWorkflow = async () => {
    const [benchmarks, remediations, approvals, artifacts, findings, imports, endpoints] = await Promise.all([
      api<{ benchmarks: Array<Record<string, unknown>> }>("/api/benchmarks"),
      api<{ remediations: Array<Record<string, unknown>> }>("/api/remediations"),
      api<{ approvals: Array<Record<string, unknown>> }>("/api/approvals"),
      api<{ artifacts: Array<Record<string, unknown>> }>("/api/evidence"),
      api<{ findings: Array<Record<string, unknown>> }>("/api/findings"),
      api<{ imports: Array<Record<string, unknown>> }>("/api/imports"),
      api<{
        endpoints: Array<Record<string, unknown>>;
        renewals: Array<Record<string, unknown>>;
        trustConfigured: boolean;
        intake: WorkflowWorkspace["intake"];
      }>("/api/endpoints")
    ]);
    setWorkflow({
      benchmarks: benchmarks.benchmarks,
      remediations: remediations.remediations,
      approvals: approvals.approvals,
      artifacts: artifacts.artifacts,
      findings: findings.findings,
      imports: imports.imports,
      endpoints: endpoints.endpoints,
      renewals: endpoints.renewals,
      endpointTrustConfigured: endpoints.trustConfigured,
      intake: endpoints.intake
    });
  };

  useEffect(() => {
    if (view !== "Workflow") return;
    setWorkflowBusy(true);
    void refreshWorkflow()
      .catch((error) => setFeedback(error instanceof Error ? error.message : "Workflow failed to load"))
      .finally(() => setWorkflowBusy(false));
  }, [view]);

  const refreshTestPlans = async (missionId = planMissionId) => {
    if (!missionId) {
      setTestPlans([]);
      return;
    }
    const body = await api<{ plans: EngagementTestPlan[] }>(
      `/api/test-plans?missionId=${encodeURIComponent(missionId)}`
    );
    setTestPlans(body.plans);
  };

  useEffect(() => {
    if (view !== "Plan & Compare") return;
    setPlanBusy(true);
    void refreshTestPlans()
      .catch((error) => setFeedback(error instanceof Error ? error.message : "Test plans failed to load"))
      .finally(() => setPlanBusy(false));
  }, [view, planMissionId]);

  const createProfessionalTestPlan = async () => {
    if (!planMissionId) {
      setFeedback("Select the engagement mission first.");
      return;
    }
    const previous = testPlans[0] ?? null;
    setPlanBusy(true);
    setFeedback("");
    try {
      await api("/api/test-plans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          missionId: planMissionId,
          title: `Professional engagement plan version ${(previous?.version ?? 0) + 1}`,
          objective: "Track authorized assessment coverage, explicit omissions, evidence and controlled retests without inferring safety from absence.",
          expectedPreviousPlanId: previous?.id ?? null,
          procedures: [
            {
              key: "scope-and-authorization",
              title: "Confirm exact scope and authorization",
              objective: "Review the active mission boundary before any assessment activity.",
              steps: ["Verify the current authorization window and exact approved target identifiers."],
              state: "blocked",
              rationale: "Awaiting an operator-reviewed evidence artifact for this plan version.",
              capabilityId: "planning.note",
              blueRuleId: null,
              runId: null,
              evidenceArtifactIds: []
            },
            {
              key: "bounded-network-baseline",
              title: "Record a bounded network baseline",
              objective: "Capture a low-noise explicit-port baseline under a fresh approval.",
              steps: ["Prepare and execute the low-noise TCP state capability for explicit ports only."],
              state: "blocked",
              rationale: "Awaiting a scoped run and its sealed mission-bound evidence.",
              capabilityId: "network.tcp-port-state",
              blueRuleId: null,
              runId: null,
              evidenceArtifactIds: []
            },
            {
              key: "defensive-rule-validation",
              title: "Validate defensive detection evidence",
              objective: "Exercise a safe defensive rule and review the resulting evidence and limitations.",
              steps: ["Run the synthetic rule pipeline or a fully covered signed endpoint correlation."],
              state: "blocked",
              rationale: "Awaiting a reviewed Blue Team evidence artifact for this exact plan version.",
              capabilityId: null,
              blueRuleId: "BR-EVASION-003",
              runId: null,
              evidenceArtifactIds: []
            },
            {
              key: "report-publication-qa",
              title: "Complete publication quality review",
              objective: "Bind a human review to exact report outputs before external publication.",
              steps: ["Review scope, claims, evidence links, remediation, redaction and final layout."],
              state: "blocked",
              rationale: "Awaiting generated outputs and an immutable publication QA decision.",
              capabilityId: "planning.note",
              blueRuleId: null,
              runId: null,
              evidenceArtifactIds: []
            }
          ]
        })
      });
      setFeedback("A new immutable engagement-plan version was sealed with explicit blocked work.");
      await refreshTestPlans(planMissionId);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Test plan creation failed");
    } finally {
      setPlanBusy(false);
    }
  };

  const searchMissionHistory = async (event: FormEvent) => {
    event.preventDefault();
    if (!planMissionId) return;
    setPlanBusy(true);
    setFeedback("");
    try {
      const body = await api<{ search: { results: MissionSearchResult[] } }>("/api/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          missionId: planMissionId,
          query: missionSearchQuery,
          kinds: ["test-plan", "procedure", "run", "evidence", "finding", "remediation"],
          limit: 25
        })
      });
      setMissionSearchResults(body.search.results);
      setFeedback(`Search returned ${body.search.results.length} bounded mission record(s).`);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Mission search failed");
    } finally {
      setPlanBusy(false);
    }
  };

  const compareRuns = async (event: FormEvent) => {
    event.preventDefault();
    if (!planMissionId) return;
    setPlanBusy(true);
    setFeedback("");
    try {
      const body = await api<{ comparison: OriginalRetestComparison }>(
        "/api/comparisons/original-retest",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            missionId: planMissionId,
            originalRunId,
            retestRunId
          })
        }
      );
      setComparison(body.comparison);
      setFeedback("Original and direct retest compared using stored lineage and verified evidence.");
    } catch (error) {
      setComparison(null);
      setFeedback(error instanceof Error ? error.message : "Run comparison failed");
    } finally {
      setPlanBusy(false);
    }
  };

  const refreshExecutorStatus = async () => {
    setExecutorStatusError("");
    try {
      const [status, registry] = await Promise.all([
        api<ExecutorStatus>("/api/system/executor"),
        api<ExecutionRegistry>("/api/system/executions")
      ]);
      setExecutorStatus(status);
      setExecutionRegistry(registry);
    } catch (error) {
      setExecutorStatus(null);
      setExecutionRegistry(null);
      setExecutorStatusError(error instanceof Error ? error.message : "Executor status failed to load");
    }
  };

  useEffect(() => {
    if (view !== "System") return;
    void Promise.all([
      refreshExecutorStatus(),
      api<{ diagnostics: SupportDiagnostics }>("/api/system/diagnostics")
        .then((body) => setSupportDiagnostics(body.diagnostics))
    ]).catch((error) => {
      setFeedback(error instanceof Error ? error.message : "System diagnostics failed to load");
    });
  }, [view]);

  const runVersionCheck = async () => {
    setExecutorBusy(true);
    setExecutorResult(null);
    setExecutorError("");
    setFeedback("");
    try {
      const result = await api<VersionResult>("/api/executor/version", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      setExecutorResult(result);
      setFeedback("Network-free MCPwn version check completed and was logged.");
      const audit = await api<{ events: Array<Record<string, unknown>> }>("/api/system/audit");
      setRecords(audit.events);
      await Promise.all([refreshExecutorStatus(), refresh()]);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Version check failed";
      setExecutorError(message);
      setFeedback(message);
    } finally {
      setExecutorBusy(false);
    }
  };

  const executorAvailable = executorStatus?.available === true && executorStatus.versionProofEnabled === true;

  const createMission = async (event: FormEvent) => {
    event.preventDefault();
    setFeedback("");
    try {
      await api("/api/missions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: missionName })
      });
      setMissionName("");
      setNewMissionOpen(false);
      setFeedback("Mission created in draft state.");
      await refresh();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Mission creation failed");
    }
  };

  const openMissionCockpit = async (missionId: string) => {
    setCockpitBusyId(missionId);
    setFeedback("");
    try {
      const body = await api<{ cockpit: MissionCockpit }>(
        `/api/missions/${encodeURIComponent(missionId)}/cockpit`
      );
      setCockpit(body.cockpit);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Mission cockpit failed to load");
    } finally {
      setCockpitBusyId("");
    }
  };

  const createGuidedDemo = async () => {
    setDemoBusy(true);
    setFeedback("");
    try {
      const body = await api<{ demo: { missionId: string } }>("/api/guided-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      await refresh();
      await openMissionCockpit(body.demo.missionId);
      setFeedback("Guided offline mission created: no target, endpoint, command or payload was used.");
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Guided demo creation failed");
    } finally {
      setDemoBusy(false);
    }
  };

  const addScope = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedMission) return;
    setFeedback("");
    const startsAt = new Date();
    const expiresAt = new Date(startsAt.valueOf() + 60 * 60_000);
    try {
      await api(`/api/missions/${encodeURIComponent(selectedMission.id)}/scope`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          startsAt: startsAt.toISOString(),
          expiresAt: expiresAt.toISOString(),
          authorizationStatement: authorization,
          targets: [{ address: targetAddress, isolatedPrivateTargetApproved: privateIsolation }]
        })
      });
      setSelectedMission(null);
      setTargetAddress("");
      setAuthorization("");
      setPrivateIsolation(false);
      setFeedback("Exact scope recorded for a one-hour authorization window.");
      await refresh();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Scope validation failed");
    }
  };

  const createAdvisoryPlan = async (event: FormEvent) => {
    event.preventDefault();
    setFeedback("");
    setPlan(null);
    setModelBusy(true);
    try {
      const result = await api<{ plan: AdvisoryPlan }>("/api/model/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ missionId: aiMissionId, objective: aiObjective })
      });
      setPlan(result.plan);
      setFeedback("T0 advisory plan stored. It has no execution or approval authority.");
      const state = await api<ModelStatus>("/api/system/model");
      setModelStatus(state);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Advisory plan failed");
    } finally {
      setModelBusy(false);
    }
  };

  const refreshApprovals = async () => {
    const body = await api<{ approvals: Array<Record<string, unknown>> }>("/api/approvals");
    setRecords(body.approvals);
    await refresh();
  };

  const prepareCatalogueApproval = async (capability: CapabilityDescriptor) => {
    if (!capability.prepareRoute || capability.status !== "enabled") return;
    if (!targetMissionId) {
      setFeedback("Select the authorized isolated mission first.");
      return;
    }
    const ports = targetPorts.split(",").map((value) => Number(value.trim()));
    const body =
      capability.id === "network.tcp-port-discovery"
        ? { missionId: targetMissionId }
        : capability.id === "network.service-version"
          ? { missionId: targetMissionId, ports, intensity: targetIntensity }
          : { missionId: targetMissionId, ports };
    setTargetBusy(true);
    setFeedback("");
    try {
      await api(capability.prepareRoute, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }, targetControlCheckTimeoutMs);
      setFeedback(`${capability.name} prepared. Review the exact fixed profile in Approvals.`);
      setView("Approvals");
      await refreshApprovals();
    } catch (error) {
      setFeedback(
        error instanceof Error && error.message === "TARGET_CONTROL_CHECK_TIMED_OUT"
          ? "Isolation check timed out. Refresh Approvals before retrying; target execution did not occur."
          : error instanceof Error
            ? error.message
            : "Capability approval preparation failed"
      );
    } finally {
      setTargetBusy(false);
    }
  };

  const decideApproval = async (approvalId: string, decision: "approve" | "deny") => {
    setTargetBusy(true);
    setFeedback("");
    try {
      await api(`/api/approvals/${encodeURIComponent(approvalId)}/${decision}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: decision === "approve" ? "Operator reviewed exact target, ports and limits." : "Operator denied target contact." })
      });
      setFeedback(decision === "approve" ? "Approval granted once. Target has not been contacted yet." : "Approval denied.");
      await refreshApprovals();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Approval decision failed");
    } finally {
      setTargetBusy(false);
    }
  };

  const executeTargetApproval = async (approvalId: string) => {
    setTargetBusy(true);
    setTargetResult(null);
    setFeedback("");
    try {
      const body = await api<{ execution: Record<string, unknown> }>("/api/target/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvalId })
      });
      setTargetResult(body.execution);
      setFeedback("Restricted Redmi check completed. Evidence was sealed and the run was audited.");
      await refreshApprovals();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Restricted target check failed");
    } finally {
      setTargetBusy(false);
    }
  };

  const refreshFindings = async () => {
    const body = await api<{ findings: Array<Record<string, unknown>> }>("/api/findings");
    setRecords(body.findings);
    await refresh();
  };

  const acceptFinding = async (findingId: string) => {
    setReviewBusyId(findingId);
    setFeedback("");
    try {
      await api(`/api/findings/${encodeURIComponent(findingId)}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      setFeedback("Finding accepted by the signed-in operator. It is now eligible for a frozen report.");
      await refreshFindings();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Finding acceptance failed");
    } finally {
      setReviewBusyId("");
    }
  };

  const createRemediation = async (findingId: string) => {
    setReviewBusyId(findingId);
    setFeedback("");
    try {
      const dueDate = new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString().slice(0, 10);
      await api(`/api/findings/${encodeURIComponent(findingId)}/remediation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner: session?.operator ?? "Local operator",
          dueDate,
          priority: "medium"
        })
      });
      setView("Workflow");
      setFeedback("Remediation opened with a seven-day review date. Ownership and history are auditable.");
    } catch (error) {
      if (error instanceof Error && error.message.includes("REMEDIATION_ALREADY_EXISTS")) {
        await refreshWorkflow();
        setView("Workflow");
        setFeedback("Existing remediation opened. Its ownership, fix evidence and retest history remain auditable.");
      } else {
        setFeedback(error instanceof Error ? error.message : "Remediation creation failed");
      }
    } finally {
      setReviewBusyId("");
    }
  };

  const remediationAction = async (
    remediationId: string,
    path: string,
    body: Record<string, unknown>,
    success: string
  ) => {
    setWorkflowBusy(true);
    setFeedback("");
    try {
      await api(`/api/remediations/${encodeURIComponent(remediationId)}/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      setFeedback(success);
      setWorkflowNote("");
      setWorkflowEvidenceIds("");
      setWorkflowFixActionAt("");
      setWorkflowFixSummary("");
      setWorkflowFixObservedState("");
      await refreshWorkflow();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Remediation action failed");
    } finally {
      setWorkflowBusy(false);
    }
  };

  const parsedWorkflowEvidenceIds = () =>
    workflowEvidenceIds.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);

  const benchmarkAction = async (
    path: string,
    body: Record<string, unknown>,
    success: string
  ) => {
    setWorkflowBusy(true);
    setFeedback("");
    try {
      await api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      setFeedback(success);
      setBenchmarkNote("");
      setBenchmarkRecoveryResult("");
      await refreshWorkflow();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Benchmark action failed");
    } finally {
      setWorkflowBusy(false);
    }
  };

  const importSarif = async (event: FormEvent) => {
    event.preventDefault();
    if (!importMissionId || !importFile) {
      setFeedback("Select a mission and SARIF file first.");
      return;
    }
    if (importFile.size > 2 * 1024 * 1024) {
      setFeedback("SARIF import is limited to 2 MiB.");
      return;
    }
    setWorkflowBusy(true);
    setFeedback("");
    try {
      const bytes = new Uint8Array(await importFile.arrayBuffer());
      const body = await api<{ imported: { resultCount: number; candidateCount: number } }>(
        "/api/imports/sarif",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            missionId: importMissionId,
            contentBase64: bytesToBase64(bytes)
          })
        }
      );
      setImportFile(null);
      setFeedback(
        `Inert SARIF import stored ${body.imported.resultCount} observation(s) as ${body.imported.candidateCount} unverified candidate(s).`
      );
      await Promise.all([refreshWorkflow(), refresh()]);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "SARIF import failed");
    } finally {
      setWorkflowBusy(false);
    }
  };

  const beginEndpointEnrollment = async () => {
    if (!enrollmentMissionId) {
      setFeedback("Select the mission that will own this endpoint.");
      return;
    }
    setEnrollmentBusy(true);
    setFeedback("");
    try {
      const identity = parseEnrollmentIdentity(enrollmentIdentityJson);
      const challengeResponse = await api<{ challenge: unknown }>("/api/endpoints/enrollment-challenges", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          missionId: enrollmentMissionId,
          certificateFingerprintSha256: identity.certificateFingerprintSha256,
          identityExpiresAt: new Date(Date.now() + 6 * 24 * 60 * 60_000).toISOString()
        })
      });
      const challenge = validateEnrollmentChallenge(challengeResponse.challenge, identity, enrollmentMissionId);
      const keyResponse = await api<{ key: unknown }>(`/api/endpoints/enrollment-challenges/${encodeURIComponent(challenge.id)}/public-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ publicKeySpkiBase64: identity.publicKeySpkiBase64 })
      });
      validateRegisteredEnrollmentKey(keyResponse.key, challenge, identity);
      setEnrollmentIdentity(identity);
      setEnrollmentChallenge(challenge);
      setEnrollmentProofJson("");
      setEnrollmentFingerprint("");
      setEnrollmentConfirmed(false);
      setEnrollmentEndpoint(null);
      setCapabilityReportJson("");
      setAcceptedCapability(null);
      setFeedback("Bound challenge created. Sign the exact JSON locally before it expires.");
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Endpoint enrollment failed");
    } finally {
      setEnrollmentBusy(false);
    }
  };

  const copyEnrollmentChallenge = async () => {
    if (!enrollmentChallenge) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify({ challenge: enrollmentChallenge }, null, 2));
      setFeedback("Exact challenge copied. The native signer accepts this JSON only.");
    } catch {
      setFeedback("Clipboard access failed. Select and copy the challenge JSON manually.");
    }
  };

  const approveEndpointEnrollment = async () => {
    if (!enrollmentChallenge || !enrollmentIdentity || !enrollmentConfirmed) {
      setFeedback("Complete the explicit fingerprint confirmation first.");
      return;
    }
    if (enrollmentFingerprint !== enrollmentIdentity.certificateFingerprintSha256) {
      setFeedback("The re-entered fingerprint does not match the machine identity.");
      return;
    }
    setEnrollmentBusy(true);
    setFeedback("");
    try {
      const proof = parseEnrollmentProof(enrollmentProofJson, enrollmentChallenge, enrollmentIdentity);
      const body = await api<{ endpoint: unknown }>(
        `/api/endpoints/enrollment-challenges/${encodeURIComponent(enrollmentChallenge.id)}/approve`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            confirmedCertificateFingerprintSha256: enrollmentFingerprint,
            proofSignatureBase64: proof.proofSignatureBase64
          })
        }
      );
      setEnrollmentEndpoint(validateApprovedEndpointIdentity(body.endpoint, enrollmentChallenge));
      setFeedback("Endpoint identity approved. Telemetry remains disabled until capability proof is complete.");
      await Promise.all([refreshWorkflow(), refresh()]);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Endpoint proof approval failed");
    } finally {
      setEnrollmentBusy(false);
    }
  };

  const resetEndpointEnrollment = () => {
    setEnrollmentIdentityJson("");
    setEnrollmentIdentity(null);
    setEnrollmentChallenge(null);
    setEnrollmentProofJson("");
    setEnrollmentFingerprint("");
    setEnrollmentConfirmed(false);
    setEnrollmentEndpoint(null);
    setCapabilityReportJson("");
    setAcceptedCapability(null);
    setFeedback("Enrollment form reset. Any server challenge remains short-lived and unusable after expiry.");
  };

  const submitCapabilityProof = async () => {
    if (!enrollmentEndpoint) return;
    setEnrollmentBusy(true);
    setFeedback("");
    try {
      const report = parseSignedCapabilityReport(capabilityReportJson, enrollmentEndpoint);
      await validateCapabilityReportHash(report);
      const body = await api<{ capability: unknown }>("/api/endpoints/capabilities", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report)
      });
      setAcceptedCapability(validateAcceptedCapability(body.capability, report));
      setFeedback("Read-access proof accepted and sealed with unknown loss/continuity. Coverage and transport remain blocked.");
      await Promise.all([refreshWorkflow(), refresh()]);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Capability proof failed");
    } finally {
      setEnrollmentBusy(false);
    }
  };

  const refreshReports = async () => {
    const body = await api<{ reports: Array<Record<string, unknown>> }>("/api/reports");
    setRecords(body.reports);
    await refresh();
  };

  const freezeReport = async () => {
    if (!reportMissionId) {
      setFeedback("Select the mission whose accepted findings should be frozen.");
      return;
    }
    setReportBusyId("freeze");
    setFeedback("");
    try {
      await api("/api/reports/freeze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ missionId: reportMissionId, templateVersion: "war-room-report-v1" })
      });
      setFeedback("Report snapshot frozen. Its evidence claims and audit head can no longer change.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report freeze failed");
    } finally {
      setReportBusyId("");
    }
  };

  const generateReport = async (reportId: string) => {
    setReportBusyId(reportId);
    setFeedback("");
    try {
      await api(`/api/reports/${encodeURIComponent(reportId)}/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      setFeedback("Deterministic JSON and HTML report artifacts generated and sealed.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report generation failed");
    } finally {
      setReportBusyId("");
    }
  };

  const openReportQa = async (reportId: string) => {
    setReportBusyId(`qa-open:${reportId}`);
    setFeedback("");
    try {
      await api(`/api/reports/${encodeURIComponent(reportId)}/qa/open`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      setReportQaConfirmedId("");
      setReportQaNote("");
      setFeedback("QA review opened and cryptographically bound to these exact JSON and HTML artifacts.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report QA review could not be opened");
    } finally {
      setReportBusyId("");
    }
  };

  const approveReportQa = async (reviewId: string) => {
    setReportBusyId(`qa-approve:${reviewId}`);
    setFeedback("");
    try {
      await api(`/api/report-qa/${encodeURIComponent(reviewId)}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          checklist: {
            scopeReviewed: true,
            claimsSupported: true,
            evidenceLinksVerified: true,
            remediationReviewed: true,
            sensitiveDataReviewed: true,
            layoutReviewed: true
          },
          note: reportQaNote
        })
      });
      setReportQaConfirmedId("");
      setReportQaNote("");
      setFeedback("Report QA approved. The reviewed JSON and HTML artifacts are publication-ready.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report QA approval failed");
    } finally {
      setReportBusyId("");
    }
  };

  const requestReportQaChanges = async (reviewId: string) => {
    setReportBusyId(`qa-changes:${reviewId}`);
    setFeedback("");
    try {
      await api(`/api/report-qa/${encodeURIComponent(reviewId)}/request-changes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ issues: [reportQaIssue], note: reportQaNote })
      });
      setReportQaConfirmedId("");
      setReportQaNote("");
      setFeedback("Changes requested. This immutable review remains non-publishable.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report QA change request failed");
    } finally {
      setReportBusyId("");
    }
  };

  const generateReportExports = async (reportId: string) => {
    setReportBusyId(`export:${reportId}`);
    setFeedback("");
    try {
      await api(`/api/reports/${encodeURIComponent(reportId)}/exports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      setReportExportConfirmedId("");
      setReportQaNote("");
      setFeedback("Evidence-bound PDF and DOCX exports generated. They remain non-publishable until visual QA.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report export generation failed");
    } finally {
      setReportBusyId("");
    }
  };

  const approveReportExports = async (bundleId: string) => {
    setReportBusyId(`export-approve:${bundleId}`);
    setFeedback("");
    try {
      await api(`/api/report-exports/${encodeURIComponent(bundleId)}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          checklist: {
            pdfLayoutReviewed: true,
            docxLayoutReviewed: true,
            pageBreaksReviewed: true,
            evidenceReferencesReadable: true,
            sensitiveDataReviewed: true
          },
          note: reportQaNote
        })
      });
      setReportExportConfirmedId("");
      setReportQaNote("");
      setFeedback("PDF and DOCX visual QA approved for these exact sealed downloads.");
      await refreshReports();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Report export QA failed");
    } finally {
      setReportBusyId("");
    }
  };

  const runBlueSimulation = async (event: FormEvent) => {
    event.preventDefault();
    if (!blueMissionId) {
      setFeedback("Select a mission to bind the defensive evidence.");
      return;
    }
    setBlueBusy(true);
    setFeedback("");
    try {
      const body = await api<{ run: BlueRun }>("/api/blue/simulations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ missionId: blueMissionId, scenarioId: blueScenarioId })
      });
      setFeedback(
        `Blue simulation completed: ${body.run.alertCount} reviewable alerts from ${body.run.eventCount} synthetic events. Evidence was sealed.`
      );
      await Promise.all([refreshBlueWorkspace(blueMissionId), refresh()]);
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Blue Team simulation failed");
    } finally {
      setBlueBusy(false);
    }
  };

  const runLiveCorrelation = async () => {
    if (!blueMissionId || !blueEndpointId || !blueLiveRuleId) {
      setFeedback("Select a mission, enrolled endpoint and supported live rule.");
      return;
    }
    setBlueBusy(true);
    setFeedback("");
    try {
      const windowEnd = new Date();
      const windowStart = new Date(windowEnd.valueOf() - 5 * 60_000);
      const body = await api<{ run: LiveCorrelationRun }>("/api/blue/live-correlations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          missionId: blueMissionId,
          endpointId: blueEndpointId,
          ruleIds: [blueLiveRuleId],
          windowStart: windowStart.toISOString(),
          windowEnd: windowEnd.toISOString()
        })
      });
      setFeedback(
        body.run.result.status === "blocked-coverage"
          ? "Live correlation was safely blocked because the exact stream was stale, incomplete, gapped or unavailable."
          : `Live correlation completed: ${body.run.result.verdict}.`
      );
      await refreshBlueWorkspace(blueMissionId);
      await refresh();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Live correlation failed");
    } finally {
      setBlueBusy(false);
    }
  };

  const unlock = async (event: FormEvent) => {
    event.preventDefault();
    setFeedback("");
    try {
      const state = await api<OperatorSession>("/api/session/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bootstrapSecret, operator: operatorName })
      });
      csrfToken = state.csrfToken ?? "";
      tabCapability = state.tabCapability ?? "";
      sessionStorage.setItem(tabCapabilityStorageKey, tabCapability);
      setSession(state);
      setBootstrapSecret("");
      setConnection("online");
      await refresh();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Operator unlock failed");
    }
  };

  const logout = async () => {
    try {
      await api<OperatorSession>("/api/session/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
    } finally {
      csrfToken = "";
      tabCapability = "";
      sessionStorage.removeItem(tabCapabilityStorageKey);
      setBootstrapSecret("");
      setOperatorName("");
      setSession({ authenticated: false });
      setDashboard(emptyDashboard);
      setRecords([]);
    }
  };

  if (!session?.authenticated) {
    return (
      <main className="operator-lock">
        <form className="panel unlock-panel" onSubmit={unlock} autoComplete="off">
          <div className="panel-title"><div><p>LOCAL OPERATOR SESSION</p><h1>Unlock VioletVector AI</h1></div><span>{session === null ? "CHECKING" : "LOCKED"}</span></div>
          <div className="unlock-body">
          <div className="warning">Use the per-launch bootstrap secret shown in the local startup terminal. It is never stored in the browser or audit log.</div>
            <label>Operator name<input value={operatorName} onChange={(event) => setOperatorName(event.target.value)} minLength={2} maxLength={120} autoComplete="off" required /></label>
            <label>Bootstrap secret<input type="password" value={bootstrapSecret} onChange={(event) => setBootstrapSecret(event.target.value)} autoComplete="one-time-code" required /></label>
            <button className="primary" disabled={session === null}>Unlock local console</button>
            {feedback && <div className="feedback" role="status">{feedback}</div>}
          </div>
        </form>
      </main>
    );
  }

  return (
    <div className="shell">
      <aside>
        <div className="brand"><span>VV</span> VioletVector AI</div>
        <nav>
          {['Missions', 'Capabilities', 'Blue Team', 'Workflow', 'Plan & Compare', 'Local AI', 'Approvals', 'Findings', 'Evidence', 'Reports', 'System'].map((item) => (
            <button className={view === item ? 'active' : ''} key={item} onClick={() => setView(item)}>{item}</button>
          ))}
        </nav>
        <div className="safety"><i /> CONTROLLED OPERATIONS<strong>Red assessment + blue detection lanes</strong></div>
      </aside>
      <main>
        <header>
          <div><p>OPERATOR CONSOLE</p><h1>{view}</h1></div>
          <div className="header-actions">
            <span className="operator-name">{session.operator}</span>
            <span className="edition-badge">{dashboard.productEdition.toUpperCase()}</span>
            <span className={`connection ${connection}`}>{connection}</span>
            <button className="secondary" onClick={() => void logout()}>Lock</button>
            {view === "Missions" && <button className="primary" onClick={() => setNewMissionOpen(true)}>+ New mission</button>}
          </div>
        </header>
        {feedback && <div className="feedback" role="status">{feedback}</div>}
        {view === "Missions" ? <>
          <section className="metrics">
            <article><small>ACTIVE RUNS</small><strong>{dashboard.counts.activeRuns}</strong><span>{dashboard.executionEnabled ? "Approval gated" : "Execution disabled"}</span></article>
            <article><small>PENDING APPROVALS</small><strong>{dashboard.counts.pendingApprovals}</strong><span>Human review queue</span></article>
            <article><small>POLICY</small><strong>v1</strong><span className="green">Default deny</span></article>
            <article><small>EVIDENCE</small><strong>{dashboard.counts.artifacts}</strong><span>{dashboard.audit.valid ? 'Audit chain valid' : 'Integrity warning'}</span></article>
          </section>
          <section className="panel demo-callout">
            <div className="panel-title">
              <div><p>GUIDED GOLDEN PATH</p><h2>See the complete safe workflow</h2></div>
              <span>OFFLINE · NO TARGET</span>
            </div>
            <div className="demo-callout-body">
              <div>
                <p>Create a fully synthetic mission containing a recorded offline boundary, 30-rule Blue validation, sealed evidence, a reviewed training finding and generated JSON/HTML report.</p>
                <small>No network contact, endpoint access, command execution, payload or credential activity occurs.</small>
              </div>
              <button className="primary" disabled={demoBusy} onClick={() => void createGuidedDemo()}>
                {demoBusy ? "Building guided mission…" : "Create guided demo"}
              </button>
            </div>
          </section>
          <section className="panel">
            <div className="panel-title"><div><p>MISSION REGISTER</p><h2>Authorized workspaces</h2></div><span>{dashboard.missions.length} total</span></div>
            <div className="table-head"><span>MISSION</span><span>STATUS</span><span>EXACT TARGET</span><span>FINDINGS</span><span>ACTION</span></div>
            {dashboard.missions.length === 0 ? (
              <div className="empty"><strong>No missions yet</strong><span>Create a draft, then add exact scope and authorization.</span></div>
            ) : dashboard.missions.map((mission) => (
              <div className="row" key={mission.id}>
                <span><b>{mission.name}</b><small>{mission.id}</small></span>
                <span><em>{mission.status.toUpperCase()}</em></span>
                <span>{mission.status === 'draft' ? 'Not authorized' : mission.status === "ready" ? "Offline boundary" : 'Exact scope stored'}</span>
                <span>{dashboard.counts.findings}</span>
                <span className="mission-actions">
                  <button className="secondary" disabled={Boolean(cockpitBusyId)} onClick={() => void openMissionCockpit(mission.id)}>
                    {cockpitBusyId === mission.id ? "Opening…" : "Open cockpit"}
                  </button>
                  {["draft", "scope_validated"].includes(mission.status) && <button className="secondary" onClick={() => setSelectedMission(mission)}>
                    {mission.status === "draft" ? "Add scope" : "Renew scope"}
                  </button>}
                </span>
              </div>
            ))}
          </section>
          {cockpit && (
            <section className="panel mission-cockpit">
              <div className="panel-title">
                <div><p>MISSION COCKPIT</p><h2>{cockpit.mission.name}</h2></div>
                <div className="status-row">
                  <span className={`status-chip ${cockpit.profile.mode === "synthetic_demo" ? "neutral" : "accepted"}`}>
                    {cockpit.profile.mode === "synthetic_demo" ? "SYNTHETIC DEMO" : "AUTHORIZED LAB"}
                  </span>
                  <span className={`status-chip ${cockpit.profile.executionPermitted ? "unverified" : "accepted"}`}>
                    {cockpit.profile.executionPermitted ? "TARGET ELIGIBLE" : "NO TARGET AUTHORITY"}
                  </span>
                </div>
              </div>
              <div className="cockpit-boundary">
                <strong>{cockpit.profile.executionPermitted ? "Approval still required" : "Execution blocked by mission boundary"}</strong>
                <span>{cockpit.profile.boundaryText}</span>
              </div>
              <div className="cockpit-metrics">
                <span>CHECKLIST<strong>{cockpit.checklist.filter((step) => step.status === "complete").length}/{cockpit.checklist.length}</strong></span>
                <span>PURPLE<strong>{cockpit.purple.exercised}/{cockpit.purple.total}</strong></span>
                <span>EVIDENCE<strong>{cockpit.counts.evidenceArtifacts}</strong></span>
                <span>FINDINGS<strong>{cockpit.counts.acceptedFindings}/{cockpit.counts.findings}</strong></span>
                <span>FIX WORK<strong>{cockpit.counts.openRemediations}/{cockpit.counts.remediations}</strong></span>
                <span>IMPORTS<strong>{cockpit.counts.imports}</strong></span>
                <span>ENDPOINTS<strong>{cockpit.counts.endpoints}</strong></span>
                <span>REPORTS<strong>{cockpit.counts.generatedReports}</strong></span>
                <span>AUDIT<strong>{cockpit.integrity.auditValid ? "VALID" : "FAILED"}</strong></span>
              </div>
              <div className="cockpit-grid">
                <article>
                  <h3>READINESS JOURNEY</h3>
                  <div className="checklist-list">
                    {cockpit.checklist.map((step, index) => (
                      <div key={step.key}>
                        <span className={`check-index ${step.status}`}>{step.status === "complete" ? "✓" : index + 1}</span>
                        <p><strong>{step.title}</strong><small>{step.detail}</small></p>
                      </div>
                    ))}
                  </div>
                </article>
                <article>
                  <h3>AUTHORIZATION</h3>
                  <div className="cockpit-facts">
                    <span>MODE<strong>{cockpit.profile.mode.replace("_", " ").toUpperCase()}</strong></span>
                    <span>TARGETS<strong>{cockpit.authorization.targetCount}</strong></span>
                    <span>POLICY<strong>{cockpit.authorization.policyVersion ?? "NOT SET"}</strong></span>
                    <span>SCOPE VERSION<strong>{cockpit.authorization.version ?? "NONE"}</strong></span>
                  </div>
                  <p>{cockpit.authorization.statement ?? "No authorization record exists yet."}</p>
                  {cockpit.latestReport && (
                    <div className="cockpit-report">
                      <small>LATEST VERIFIED REPORT · {cockpit.latestReport.templateVersion}</small>
                      <strong>{cockpit.latestReport.status.toUpperCase()}</strong>
                      <div>
                        <a href={`/api/reports/${encodeURIComponent(cockpit.latestReport.id)}/outputs/html`} target="_blank" rel="noreferrer">View HTML</a>
                        <a href={`/api/reports/${encodeURIComponent(cockpit.latestReport.id)}/outputs/json?download=1`}>Download JSON</a>
                      </div>
                    </div>
                  )}
                </article>
              </div>
              <div className="cockpit-timeline">
                <h3>MISSION ACTIVITY</h3>
                {cockpit.timeline.length === 0 ? <small>No mission activity recorded yet.</small> : cockpit.timeline.slice(0, 12).map((event) => (
                  <div key={event.sequence}>
                    <span>#{event.sequence}</span>
                    <strong>{event.eventType}</strong>
                    <small>{event.occurredAt}</small>
                  </div>
                ))}
              </div>
            </section>
          )}
          <section className="panel capability-callout">
            <div className="panel-title"><div><p>CONTROLLED CAPABILITY LIBRARY</p><h2>Choose the right depth for the mission</h2></div><span>FIXED PROFILES</span></div>
            <div className="ai-body">
              <div className="warning">Every target profile is backend-fixed, exact-target only and approval-gated. Script names, commands and raw arguments never come from the browser or model.</div>
              <button className="primary" onClick={() => setView("Capabilities")}>Open capability catalogue</button>
            </div>
          </section>
        </> : view === "Capabilities" ? (
          <section className="capability-workspace">
            <div className="edition-grid">
              <article className={`panel edition-card ${productEdition === "starter" ? "current" : ""}`}>
                <small>STARTER / LAB</small>
                <h2>Learn the controlled workflow</h2>
                <p>Local planning, exact scope, low-noise TCP state, targeted service checks, the 30-rule synthetic Blue Team lab, evidence, findings and reports.</p>
              </article>
              <article className={`panel edition-card ${productEdition === "professional" ? "current" : ""}`}>
                <small>PROFESSIONAL / BUSINESS</small>
                <h2>Advanced assessment depth</h2>
                <p>Adds HTTP/TLS posture, intensive discovery, advanced retests and reviewed capability-pack development.</p>
              </article>
            </div>
            <article className="panel capability-control">
              <div className="panel-title"><div><p>MISSION BINDING</p><h2>Exact target controls</h2></div><span>NO CONTACT UNTIL APPROVED</span></div>
              <div className="ai-body">
                <div className="warning">“Low noise” means rate-limited and observable—not covert. Operational evasion, credential theft and payload delivery are deliberately absent.</div>
                <label>Authorized mission
                  <select value={targetMissionId} onChange={(event) => setTargetMissionId(event.target.value)} required>
                    <option value="">Select the isolated mission</option>
                    {dashboard.missions.filter((mission) => mission.status === "scope_validated").map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <label>Explicit TCP ports
                  <input value={targetPorts} onChange={(event) => setTargetPorts(event.target.value)} pattern="[0-9, ]+" />
                </label>
                <label>Service version intensity
                  <select value={targetIntensity} onChange={(event) => setTargetIntensity(Number(event.target.value))}>
                    <option value={0}>0 · lightest</option>
                    <option value={1}>1 · cautious</option>
                    <option value={2}>2 · bounded detail</option>
                  </select>
                </label>
                <small>Each card shows its own port limit, traffic level, runtime and approval tier. All-port discovery ignores the explicit port field.</small>
              </div>
            </article>
            <div className="capability-grid">
              {capabilities.map((capability) => (
                <article className={`panel capability-card ${capability.status}`} key={capability.id}>
                  <div className="capability-card-head">
                    <div><small>{capability.category.toUpperCase()}</small><h2>{capability.name}</h2></div>
                    <span className={`status-chip ${capability.status}`}>{capability.status.toUpperCase()}</span>
                  </div>
                  <p className="capability-description">{capability.description}</p>
                  <div className="capability-badges">
                    <span>{capability.minimumEdition}+</span>
                    <span>{capability.riskTier}</span>
                    <span>{capability.operatorDifficulty}</span>
                    <span>{capability.networkNoise} noise</span>
                    <span>{capability.approvalPolicy}</span>
                  </div>
                  <dl>
                    <div><dt>FIXED TECHNIQUE</dt><dd>{capability.fixedTechnique}</dd></div>
                    <div><dt>LIMITS</dt><dd>{capability.maxRuntimeMs ? `${capability.maxRuntimeMs / 1000}s · ${formatBytes(capability.maxOutputBytes)}` : "Offline / planned"}{capability.portLimit ? ` · ${capability.portLimit.toLocaleString()} port max` : ""}</dd></div>
                    <div><dt>EVIDENCE</dt><dd>{capability.evidenceOutput}</dd></div>
                  </dl>
                  <div className="capability-safety">{capability.safetyNote}</div>
                  {capability.category === "simulation" && capability.status === "enabled" ? (
                    <button className="primary" onClick={() => setView("Blue Team")}>Open Blue Team lab</button>
                  ) : capability.prepareRoute ? (
                    <button
                      className="primary"
                      disabled={targetBusy || capability.status !== "enabled" || !targetMissionId}
                      onClick={() => void prepareCatalogueApproval(capability)}
                    >
                      {targetBusy ? "Checking controls…" : "Prepare approval"}
                    </button>
                  ) : (
                    <button className="secondary" disabled>{capability.unavailableReason ?? "Use its dedicated workspace"}</button>
                  )}
                  {capability.unavailableReason && <small className="error-text">{capability.unavailableReason}</small>}
                </article>
              ))}
            </div>
          </section>
        ) : view === "Blue Team" ? (
          <section className="blue-workspace">
            <article className="panel blue-control">
              <div className="panel-title">
                <div><p>DEFENSIVE DETECTION LAB</p><h2>Credential, payload and evasion coverage</h2></div>
                <span>OFFLINE · T0</span>
              </div>
              <form className="ai-body" onSubmit={runBlueSimulation}>
                <div className="warning">
                  Built-in scenarios contain synthetic labels only. They do not access credential stores, create payloads, impair defenses or contact an endpoint.
                </div>
                <label>Evidence mission
                  <select value={blueMissionId} onChange={(event) => setBlueMissionId(event.target.value)} required>
                    <option value="">Select any local training mission</option>
                    {dashboard.missions.map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <label>Detection scenario
                  <select value={blueScenarioId} onChange={(event) => setBlueScenarioId(event.target.value as BlueScenario["id"])}>
                    {(blueWorkspace?.scenarios ?? []).map((scenario) => (
                      <option key={scenario.id} value={scenario.id}>{scenario.name}</option>
                    ))}
                  </select>
                </label>
                <button className="primary" disabled={blueBusy || !blueMissionId}>
                  {blueBusy ? "Running deterministic rules…" : "Run safe detection simulation"}
                </button>
                <small>Every result is mission-bound, content-addressed and marked for human review. A rule match is not automatic proof of compromise.</small>
              </form>
            </article>
            <article className="panel endpoint-boundary">
              <div className="panel-title">
                <div><p>LIVE ENDPOINT BOUNDARY</p><h2>Signed minimized-fact connector</h2></div>
                <span>{blueWorkspace?.endpointAccess.status.toUpperCase() ?? "CHECKING"}</span>
              </div>
              <div className="ai-body">
                <div className="authority-grid">
                  <span>FACTS<strong>MINIMIZED</strong></span>
                  <span>REMOTE SHELL<strong>NONE</strong></span>
                  <span>COMMANDS<strong>NONE</strong></span>
                  <span>ENDPOINTS<strong>{blueWorkspace?.liveEndpoints.length ?? 0}</strong></span>
                </div>
                <p className="blue-copy">
                  The server accepts signed primitive facts and exact health measurements only. Detection labels are calculated here in VioletVector AI; commands never travel back to the endpoint.
                </p>
                <div className="control-note">{blueWorkspace?.endpointAccess.note ?? "Loading endpoint boundary…"}</div>
                <label>Enrolled endpoint
                  <select value={blueEndpointId} onChange={(event) => setBlueEndpointId(event.target.value)}>
                    <option value="">No endpoint enrolled for this mission</option>
                    {(blueWorkspace?.liveEndpoints ?? []).map((endpoint) => (
                      <option key={endpoint.identity.endpointId} value={endpoint.identity.endpointId}>
                        {endpoint.identity.endpointId} · {endpoint.identity.status}
                      </option>
                    ))}
                  </select>
                </label>
                <label>Server-owned live rule
                  <select value={blueLiveRuleId} onChange={(event) => setBlueLiveRuleId(event.target.value)}>
                    {(blueWorkspace?.liveRuleIds ?? []).map((ruleId) => (
                      <option key={ruleId} value={ruleId}>{ruleId}</option>
                    ))}
                  </select>
                </label>
                <button
                  className="primary"
                  disabled={blueBusy || !blueMissionId || !blueEndpointId}
                  onClick={() => void runLiveCorrelation()}
                >
                  {blueBusy ? "Checking signed coverage…" : "Correlate last 5 minutes"}
                </button>
                {(blueWorkspace?.liveEndpoints.find(
                  (endpoint) => endpoint.identity.endpointId === blueEndpointId
                )?.capabilities ?? []).map((capability) => (
                  <div className="connector-health" key={capability.id}>
                    <div className="review-heading">
                      <strong>{capability.provider} · {capability.eventFamily}</strong>
                      <span className={`status-chip ${
                        capability.health === "healthy" ? "accepted" : "integrity-failed"
                      }`}>{capability.health.toUpperCase()}</span>
                    </div>
                    <small>last read {capability.lastSuccessfulReadAt} · fresh until {capability.freshUntil}</small>
                    <span>{capability.limitation}</span>
                  </div>
                ))}
              </div>
            </article>
            <section className="blue-metrics">
              <article><small>RULES</small><strong>{blueWorkspace?.rules.length ?? 0}</strong><span>deterministic coverage</span></article>
              <article><small>SCENARIOS</small><strong>{blueWorkspace?.scenarios.length ?? 0}</strong><span>synthetic validation</span></article>
              <article><small>RUNS</small><strong>{blueWorkspace?.runs.length ?? 0}</strong><span>sealed evidence</span></article>
              <article><small>LIVE SUPPORTED</small><strong>{blueWorkspace?.coverage.liveSupportedRuleIds.length ?? 0}</strong><span>latest covered windows</span></article>
            </section>
            <section className="panel blue-matrix">
              <div className="panel-title">
                <div><p>PURPLE VALIDATION MATRIX</p><h2>Expected control versus observed evidence</h2></div>
                <span>
                  {blueWorkspace?.validationMatrix.filter((item) => item.syntheticValidation.status === "detected").length ?? 0}
                  /{blueWorkspace?.validationMatrix.length ?? 30} EXERCISED
                </span>
              </div>
              <div className="matrix-note">
                A synthetic detection proves the versioned rule pipeline matched its safe test signal. It does not prove that endpoint telemetry or a production control detected real activity.
              </div>
              <div className="matrix-groups">
                {(["credential-access", "payload-execution", "defense-evasion"] as const).map((category) => (
                  <article key={category}>
                    <h3>{category.replace("-", " ").toUpperCase()}</h3>
                    {(blueWorkspace?.validationMatrix ?? []).filter((item) => item.category === category).map((item) => (
                      <div className="matrix-row" key={item.testCaseId}>
                        <div>
                          <strong>{item.ruleId} · {item.title}</strong>
                          <small>{item.attackTechniqueId} · {item.scenarioId}</small>
                        </div>
                        <div className="matrix-state">
                          <span className={`status-chip ${
                            item.syntheticValidation.status === "detected"
                              ? "accepted"
                              : item.syntheticValidation.status === "integrity-failed"
                                ? "integrity-failed"
                                : "neutral"
                          }`}>
                            SYNTHETIC {item.syntheticValidation.status.toUpperCase()}
                          </span>
                          <span className={`status-chip ${
                            item.liveValidation.status === "live-supported"
                              ? "accepted"
                              : item.liveValidation.status === "blocked"
                                ? "integrity-failed"
                                : "unverified"
                          }`}>LIVE {item.liveValidation.status.toUpperCase()}</span>
                        </div>
                        {item.syntheticValidation.evidenceArtifactId && (
                          <code>{item.syntheticValidation.evidenceArtifactId}</code>
                        )}
                        {item.liveValidation.reason && <small>{item.liveValidation.reason}</small>}
                      </div>
                    ))}
                  </article>
                ))}
              </div>
            </section>
            <section className="blue-rule-grid">
              {(blueWorkspace?.rules ?? []).map((rule) => (
                <article className="panel blue-rule-card" key={rule.id}>
                  <div className="review-heading">
                    <div><small>{rule.category.toUpperCase()}</small><strong>{rule.title}</strong></div>
                    <span className="status-chip unverified">{rule.severity.toUpperCase()}</span>
                  </div>
                  <div className="capability-badges">
                    <span>{rule.id}</span>
                    <span>{rule.readiness}</span>
                    <span>live: {rule.liveStatus}</span>
                    <a className="attack-link" href={rule.referenceUrl} target="_blank" rel="noreferrer">
                      {rule.attackTechniqueId} · {rule.attackTechniqueName}
                    </a>
                  </div>
                  <div className="review-copy">
                    <div><small>DETECTION LOGIC</small><p>{rule.detectionLogic}</p></div>
                    <div><small>RESPONSE</small><p>{rule.responseGuidance}</p></div>
                  </div>
                  <div className="false-positive"><small>LIKELY FALSE POSITIVES</small><p>{rule.likelyFalsePositives}</p></div>
                  <div className="evidence-links">
                    <small>REQUIRED ENDPOINT TELEMETRY</small>
                    <span>{rule.requiredTelemetry.join(" · ")}</span>
                  </div>
                </article>
              ))}
            </section>
            <section className="panel blue-runs">
              <div className="panel-title">
                <div><p>LIVE CORRELATION REGISTER</p><h2>Signed coverage and server-owned matches</h2></div>
                <span>{blueWorkspace?.liveRuns.length ?? 0} records</span>
              </div>
              {!blueWorkspace || blueWorkspace.liveRuns.length === 0 ? (
                <div className="empty">
                  <strong>No live correlation records</strong>
                  <span>Enroll the fixture sensor, submit a fresh signed capability measurement and minimized facts, then run a covered window.</span>
                </div>
              ) : (
                <div className="record-list review-list">{blueWorkspace.liveRuns.map((run) => (
                  <article key={run.id}>
                    <div className="review-heading">
                      <div><strong>{run.result.verdict}</strong><small>{run.endpointId} · {run.createdAt}</small></div>
                      <div className="status-row">
                        <span className={`status-chip ${run.integrityValid ? "accepted" : "integrity-failed"}`}>
                          {run.integrityValid ? "EVIDENCE VERIFIED" : "INTEGRITY FAILED"}
                        </span>
                        <span className={`status-chip ${
                          run.result.status === "completed" ? "accepted" : "integrity-failed"
                        }`}>{run.result.status.toUpperCase()}</span>
                      </div>
                    </div>
                    <div className="artifact-hash"><small>RESULT HASH</small><code>{run.resultHash}</code></div>
                    <div className="evidence-links"><small>EVIDENCE ARTIFACT</small><code>{run.evidenceArtifactId}</code></div>
                    <div className="blue-alerts">
                      {run.result.alerts.map((alert) => (
                        <div key={alert.id}>
                          <strong>{alert.ruleId} · {alert.title}</strong>
                          <span>{alert.reason}</span>
                          <small>minimized facts {alert.matchedFactIds.join(", ")}</small>
                        </div>
                      ))}
                      {run.result.coverage.filter((item) => item.status === "blocked").map((coverage) => (
                        <div key={coverage.ruleId}>
                          <strong>{coverage.ruleId} · COVERAGE BLOCKED</strong>
                          <span>{coverage.reason}</span>
                        </div>
                      ))}
                    </div>
                    <small>{run.result.limitation}</small>
                  </article>
                ))}</div>
              )}
            </section>
            <section className="panel blue-runs">
              <div className="panel-title">
                <div><p>DETECTION REGISTER</p><h2>Evidence-backed simulation runs</h2></div>
                <span>{blueWorkspace?.runs.length ?? 0} records</span>
              </div>
              {!blueWorkspace || blueWorkspace.runs.length === 0 ? (
                <div className="empty"><strong>No Blue Team runs yet</strong><span>Select a mission and run a synthetic scenario to validate the rules.</span></div>
              ) : (
                <div className="record-list review-list">{blueWorkspace.runs.map((run) => (
                  <article key={run.id}>
                    <div className="review-heading">
                      <div><strong>{run.result.scenario.name}</strong><small>{run.id} · {run.createdAt}</small></div>
                      <div className="status-row">
                        <span className={`status-chip ${run.integrityValid ? "accepted" : "integrity-failed"}`}>
                          {run.integrityValid ? "EVIDENCE VERIFIED" : "INTEGRITY FAILED"}
                        </span>
                        <span className="status-chip neutral">{run.alertCount} ALERTS · {run.eventCount} EVENTS</span>
                      </div>
                    </div>
                    <div className="artifact-hash"><small>RESULT HASH</small><code>{run.resultHash}</code></div>
                    <div className="evidence-links"><small>EVIDENCE ARTIFACT</small><code>{run.evidenceArtifactId}</code></div>
                    <div className="blue-alerts">
                      {run.result.alerts.map((alert) => (
                        <div key={alert.id}>
                          <strong>{alert.ruleId} · {alert.title}</strong>
                          <span>{alert.reason}</span>
                          <small>{alert.attackTechniqueId} · {alert.disposition.toUpperCase()} · events {alert.matchedEventIds.join(", ")}</small>
                        </div>
                      ))}
                    </div>
                    <small>{run.result.summary.limitation}</small>
                  </article>
                ))}</div>
              )}
            </section>
          </section>
        ) : view === "Workflow" ? (
          <section className="report-grid workflow-workspace">
            <article className="panel report-control">
              <div className="panel-title">
                <div><p>INERT RESULT INTAKE</p><h2>Import reviewed SARIF</h2></div>
                <span>DATA ONLY</span>
              </div>
              <form className="ai-body" onSubmit={importSarif}>
                <div className="warning">
                  The original file is sealed as evidence. Narratives and locations stay inert, candidates remain unverified and imported content cannot create findings or execute anything.
                </div>
                <label>Mission
                  <select value={importMissionId} onChange={(event) => setImportMissionId(event.target.value)} required>
                    <option value="">Select the evidence mission</option>
                    {dashboard.missions.map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <label>SARIF 2.1.0 file
                  <input
                    type="file"
                    accept=".sarif,.json,application/sarif+json,application/json"
                    onChange={(event) => setImportFile(event.target.files?.[0] ?? null)}
                    required
                  />
                </label>
                <button className="primary" disabled={workflowBusy || !importMissionId || !importFile}>
                  {workflowBusy ? "Verifying import…" : "Seal inert import"}
                </button>
                <small>Maximum 2 MiB and 500 results. Deduplication is deterministic and mission-scoped.</small>
              </form>
            </article>
            <article className="panel endpoint-boundary">
              <div className="panel-title">
                <div><p>ENDPOINT TRUST</p><h2>One-way telemetry foundation</h2></div>
                <span>{workflow?.endpointTrustConfigured ? "CRYPTO CONFIGURED" : "NOT ENROLLED"}</span>
              </div>
              <div className="ai-body">
                <div className="authority-grid">
                  <span>DIRECTION<strong>INBOUND DATA</strong></span>
                  <span>COMMANDS<strong>NONE</strong></span>
                  <span>REMOTE SHELL<strong>NONE</strong></span>
                  <span>ENDPOINTS<strong>{workflow?.endpoints.length ?? 0}</strong></span>
                  <span>KEY RENEWALS<strong>{workflow?.renewals.length ?? 0}</strong></span>
                </div>
                <div className="warning">
                  Enrollment proves possession of the non-exportable machine key. It does not enable telemetry, commands, remote shell or response actions.
                </div>
                <label>Owning mission
                  <select value={enrollmentMissionId} onChange={(event) => setEnrollmentMissionId(event.target.value)} disabled={enrollmentBusy || enrollmentChallenge !== null}>
                    <option value="">Select the authorized mission</option>
                    {dashboard.missions.map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <label>Native machine identity JSON
                  <textarea
                    rows={5}
                    value={enrollmentIdentityJson}
                    onChange={(event) => setEnrollmentIdentityJson(event.target.value)}
                    placeholder="Paste the exact enrollment-identity JSON from elevated PowerShell"
                    disabled={enrollmentBusy || enrollmentChallenge !== null}
                  />
                </label>
                {!enrollmentChallenge ? (
                  <button className="primary" type="button" disabled={enrollmentBusy || !enrollmentMissionId || !enrollmentIdentityJson} onClick={() => void beginEndpointEnrollment()}>
                    {enrollmentBusy ? "Binding identity…" : "Create bound challenge"}
                  </button>
                ) : !enrollmentEndpoint ? (
                  <>
                    <div className="control-note">
                      Run elevated: <code>$challenge = Get-Clipboard -Raw; .\scripts\provision-windows-sensor-identity.ps1 -Command sign-enrollment-challenge -ChallengeJson $challenge</code>
                    </div>
                    <label>Exact challenge JSON
                      <textarea rows={8} readOnly value={JSON.stringify({ challenge: enrollmentChallenge }, null, 2)} />
                    </label>
                    <button type="button" onClick={() => void copyEnrollmentChallenge()}>Copy exact challenge</button>
                    <button type="button" disabled={enrollmentBusy} onClick={resetEndpointEnrollment}>Discard and restart</button>
                    <label>Native proof JSON
                      <textarea rows={6} value={enrollmentProofJson} onChange={(event) => setEnrollmentProofJson(event.target.value)} placeholder="Paste the exact sign-enrollment-challenge JSON" />
                    </label>
                    <label>Re-enter the full SHA-256 fingerprint
                      <input value={enrollmentFingerprint} onChange={(event) => setEnrollmentFingerprint(event.target.value)} maxLength={64} autoComplete="off" />
                    </label>
                    <label className="checkbox"><input type="checkbox" checked={enrollmentConfirmed} onChange={(event) => setEnrollmentConfirmed(event.target.checked)} /> I reviewed the mission, endpoint identity, expiry and exact fingerprint.</label>
                    <button className="primary" type="button" disabled={enrollmentBusy || !enrollmentProofJson || !enrollmentConfirmed || enrollmentFingerprint.length !== 64} onClick={() => void approveEndpointEnrollment()}>
                      {enrollmentBusy ? "Verifying proof…" : "Approve proved identity"}
                    </button>
                  </>
                ) : !acceptedCapability ? (
                  <>
                    <div className="control-note">Identity active. Install this pending binding through the fixed elevated installer, perform one explicit service start, then paste its signed capability report.</div>
                    <label>Identity binding candidate
                      <textarea rows={12} readOnly value={JSON.stringify({
                        schemaVersion: 1,
                        profile: "gate-c0b-identity-binding-candidate-v1",
                        state: "capability-pending",
                        missionId: enrollmentEndpoint.missionId,
                        connectorId: enrollmentEndpoint.connectorId,
                        endpointId: enrollmentEndpoint.endpointId,
                        enrollmentChallengeId: enrollmentEndpoint.enrollmentChallengeId,
                        certificateFingerprintSha256: enrollmentEndpoint.certificateFingerprintSha256,
                        identityIssuedAt: enrollmentEndpoint.issuedAt,
                        identityExpiresAt: enrollmentEndpoint.expiresAt,
                        provider: "windows-scm",
                        channel: "system",
                        eventFamily: "service-change",
                        fields: SCM_FIELDS,
                        filterHash: SCM_FILTER_HASH,
                        collectorVersion: SCM_COLLECTOR_VERSION
                      }, null, 2)} />
                    </label>
                    <label>Signed capability report JSON
                      <textarea rows={8} value={capabilityReportJson} onChange={(event) => setCapabilityReportJson(event.target.value)} placeholder="Paste the exact protected local capability proof" />
                    </label>
                    <button className="primary" type="button" disabled={enrollmentBusy || !capabilityReportJson} onClick={() => void submitCapabilityProof()}>
                      {enrollmentBusy ? "Verifying capability…" : "Seal signed capability"}
                    </button>
                  </>
                ) : (
                  <>
                    <div className="control-note">Read access is evidence-sealed, but one shot cannot prove loss-free continuity. Finalize this blocked descriptor through the fixed elevated installer; telemetry and transport remain disabled.</div>
                    <label>Final descriptor input
                      <textarea rows={16} readOnly value={JSON.stringify({
                        schemaVersion: 1,
                        profile: "gate-c0b-final-binding-input-v1",
                        state: "coverage-blocked",
                        missionId: enrollmentEndpoint.missionId,
                        connectorId: enrollmentEndpoint.connectorId,
                        endpointId: enrollmentEndpoint.endpointId,
                        enrollmentChallengeId: enrollmentEndpoint.enrollmentChallengeId,
                        certificateFingerprintSha256: enrollmentEndpoint.certificateFingerprintSha256,
                        identityIssuedAt: enrollmentEndpoint.issuedAt,
                        identityExpiresAt: enrollmentEndpoint.expiresAt,
                        provider: acceptedCapability.provider,
                        channel: acceptedCapability.channel,
                        eventFamily: acceptedCapability.eventFamily,
                        fields: acceptedCapability.fields,
                        filterHash: acceptedCapability.filterHash,
                        collectorVersion: acceptedCapability.collectorVersion,
                        capabilitySnapshotId: acceptedCapability.id,
                        capabilityReportHash: acceptedCapability.reportHash,
                        capabilityFreshUntil: acceptedCapability.freshUntil
                      }, null, 2)} />
                    </label>
                  </>
                )}
                <p className="blue-copy">
                  Enrollment binds a key fingerprint, connector, endpoint and mission. Renewal activates a fresh proved key and revokes the replaced identity atomically. Intake rejects replay, sequence gaps, forks, expiry and revocation.
                </p>
                <div className="control-note">
                  {workflow?.endpointTrustConfigured
                    ? "The proof-verifier boundary is configured. Live rule support still needs a real least-privilege sensor, channel health and server-owned correlation."
                    : "No certificate verifier or live sensor is configured. Synthetic validation remains clearly separate from live support."}
                </div>
                {(workflow?.renewals ?? []).slice(0, 5).map((renewal, index) => (
                  <div className="connector-health" key={String(renewal.id ?? index)}>
                    <div className="review-heading">
                      <strong>KEY ROTATION · {String(renewal.previousEndpointId ?? "")}</strong>
                      <span className={`status-chip ${
                        renewal.status === "activated" ? "accepted" : "unverified"
                      }`}>{String(renewal.status ?? "unknown").toUpperCase()}</span>
                    </div>
                    <small>
                      replacement {String(renewal.replacementEndpointId ?? "")}
                      {" · "}{String(renewal.requestedAt ?? "")}
                    </small>
                    <span>{String(renewal.reason ?? "")}</span>
                  </div>
                ))}
              </div>
            </article>
            <article className="panel report-register">
              <div className="panel-title">
                <div><p>OPERATIONAL VALUE BENCHMARK</p><h2>Retained scope-to-report timer</h2></div>
                <span>{workflow?.benchmarks.length ?? 0} retained</span>
              </div>
              <div className="control-note">
                The recorder is append-only and mission-bound. Completion checks the real original/retest runs, evidence, accepted finding, fix evidence, retest outcome, approved source report and approved PDF/DOCX QA.
              </div>
              {(() => {
                const active = workflow?.benchmarks.find((item) => item.status === "running");
                const milestones = active && Array.isArray(active.milestones) ? active.milestones : [];
                const milestoneOptions = [
                  "scope-authorized", "original-executed", "evidence-reviewed", "finding-accepted",
                  "fix-evidence-attached", "retest-executed", "comparison-reviewed",
                  "report-qa-approved", "recovery-verified"
                ];
                const recorded = new Set(milestones.map((item) => String(item.milestone)));
                const remaining = milestoneOptions.filter((item) => !recorded.has(item));
                return <div className="ai-body benchmark-body">
                  {!active ? <>
                    <label>Authorized mission
                      <select value={benchmarkMissionId} onChange={(event) => setBenchmarkMissionId(event.target.value)}>
                        <option value="">Select a mission</option>
                        {dashboard.missions.map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                      </select>
                    </label>
                    <label>Start note
                      <textarea value={benchmarkNote} onChange={(event) => setBenchmarkNote(event.target.value)} placeholder="State the authorized benchmark objective." />
                    </label>
                    <button
                      className="primary"
                      disabled={workflowBusy || !benchmarkMissionId || benchmarkNote.trim().length < 10}
                      onClick={() => void benchmarkAction(
                        "/api/benchmarks",
                        { missionId: benchmarkMissionId, note: benchmarkNote },
                        "Retained benchmark timer started. Record each milestone as the real workflow completes."
                      )}
                    >Start retained benchmark</button>
                  </> : <>
                    <div className="artifact-facts">
                      <span>MISSION<strong>{String(active.missionId)}</strong></span>
                      <span>STARTED<strong>{String(active.startedAt)}</strong></span>
                      <span>MILESTONES<strong>{milestones.length}/9</strong></span>
                      <span>INTEGRITY<strong>{active.integrityValid === true ? "VALID" : "FAILED"}</strong></span>
                    </div>
                    <div className="control-note">Objective: {String(active.startNote)}</div>
                    {remaining.length > 0 && <>
                      <label>Completed milestone
                        <select value={remaining.includes(benchmarkMilestone) ? benchmarkMilestone : remaining[0]} onChange={(event) => setBenchmarkMilestone(event.target.value)}>
                          {remaining.map((item) => <option key={item} value={item}>{item}</option>)}
                        </select>
                      </label>
                      <label>Milestone note
                        <textarea value={benchmarkNote} onChange={(event) => setBenchmarkNote(event.target.value)} placeholder="Record what completed and where its evidence is retained." />
                      </label>
                      <button
                        className="secondary"
                        disabled={workflowBusy || benchmarkNote.trim().length < 10}
                        onClick={() => void benchmarkAction(
                          `/api/benchmarks/${encodeURIComponent(String(active.id))}/milestones`,
                          { milestone: remaining.includes(benchmarkMilestone) ? benchmarkMilestone : remaining[0], note: benchmarkNote },
                          "Benchmark milestone retained in the append-only record."
                        )}
                      >Record milestone</button>
                    </>}
                    {remaining.length === 0 && <>
                      <div className="warning">Completion derives workflow counts from the database. Enter only measured operator/recovery/model figures.</div>
                      <div className="scope-grid">
                        {[
                          ["operatorSteps", "Operator steps"],
                          ["policyDenials", "Policy denials"],
                          ["unsupportedClaimsRejected", "Unsupported claims rejected"],
                          ["recoveryElapsedMs", "Recovery elapsed ms"],
                          ["modelAccepted", "Model suggestions accepted"],
                          ["modelEdited", "Model suggestions edited"],
                          ["modelRejected", "Model suggestions rejected"]
                        ].map(([key, label]) => <label key={key}>{label}
                          <input
                            type="number"
                            min={key === "operatorSteps" ? 9 : 0}
                            value={benchmarkMetrics[key as keyof typeof benchmarkMetrics]}
                            onChange={(event) => setBenchmarkMetrics({ ...benchmarkMetrics, [key]: Number(event.target.value) })}
                          />
                        </label>)}
                      </div>
                      <label>Completion note
                        <textarea value={benchmarkNote} onChange={(event) => setBenchmarkNote(event.target.value)} placeholder="Summarize the measured outcome and recovery evidence." />
                      </label>
                      <label>Recovery result
                        <select value={benchmarkRecoveryResult} onChange={(event) => setBenchmarkRecoveryResult(event.target.value as "" | "recovered" | "failed")}>
                          <option value="">Select the observed result</option>
                          <option value="recovered">Recovered and verified</option>
                          <option value="failed">Recovery failed</option>
                        </select>
                      </label>
                      <button
                        className="primary"
                        disabled={workflowBusy || benchmarkNote.trim().length < 10 || !benchmarkRecoveryResult}
                        onClick={() => void benchmarkAction(
                          `/api/benchmarks/${encodeURIComponent(String(active.id))}/complete`,
                          {
                            operatorSteps: benchmarkMetrics.operatorSteps,
                            policyDenials: benchmarkMetrics.policyDenials,
                            unsupportedClaimsRejected: benchmarkMetrics.unsupportedClaimsRejected,
                            recoveryResult: benchmarkRecoveryResult,
                            recoveryElapsedMs: benchmarkMetrics.recoveryElapsedMs,
                            modelSuggestions: {
                              accepted: benchmarkMetrics.modelAccepted,
                              edited: benchmarkMetrics.modelEdited,
                              rejected: benchmarkMetrics.modelRejected
                            },
                            note: benchmarkNote
                          },
                          "Benchmark completed with a hash-bound result derived from the retained mission workflow."
                        )}
                      >Complete retained benchmark</button>
                    </>}
                  </>}
                </div>;
              })()}
              {(workflow?.benchmarks ?? []).filter((item) => item.status === "completed").slice(0, 3).map((item) => (
                <div className="connector-health" key={String(item.id)}>
                  <div className="review-heading">
                    <strong>COMPLETED · {String(item.missionId)}</strong>
                    <span className="status-chip accepted">HASH BOUND</span>
                  </div>
                  <small>{String(item.completedAt)} · {String(item.elapsedMs)} ms</small>
                  <code>{String(item.resultHash)}</code>
                </div>
              ))}
            </article>
            <article className="panel report-register">
              <div className="panel-title">
                <div><p>REMEDIATION REGISTER</p><h2>Owner, fix evidence and retest history</h2></div>
                <span>{workflow?.remediations.length ?? 0} records</span>
              </div>
              <div className="control-note">
                Outcomes cannot be set through a simple status change. Remediated, persists and regressed require a pending retest plus same-mission verified evidence.
              </div>
              {workflowBusy && !workflow ? (
                <div className="empty"><strong>Loading workflow…</strong></div>
              ) : !workflow || workflow.remediations.length === 0 ? (
                <div className="empty"><strong>No remediation records yet</strong><span>Accept a finding, then open its remediation from the Findings register.</span></div>
              ) : (
                <div className="record-list review-list">{workflow.remediations.map((record, index) => {
                  const fixEvidence = Array.isArray(record.fixEvidence) ? record.fixEvidence : [];
                  const retests = Array.isArray(record.retests) ? record.retests : [];
                  const history = Array.isArray(record.history) ? record.history : [];
                  return <article key={String(record.id ?? index)}>
                    <div className="review-heading">
                      <div>
                        <strong>{String(record.findingTitle ?? "Remediation")}</strong>
                        <small>{String(record.id ?? "")} · owner {String(record.owner ?? "unassigned")}</small>
                      </div>
                      <div className="status-row">
                        <span className={`status-chip ${String(record.status ?? "")}`}>{String(record.status ?? "unknown").toUpperCase()}</span>
                        <span className="status-chip neutral">{String(record.priority ?? "").toUpperCase()} · DUE {String(record.dueDate ?? "")}</span>
                      </div>
                    </div>
                    <div className="artifact-facts">
                      <span>FIX EVIDENCE<strong>{fixEvidence.length}</strong></span>
                      <span>RETESTS<strong>{retests.length}</strong></span>
                      <span>HISTORY<strong>{history.length} chained events</strong></span>
                      <span>REGRESSION<strong>{String(record.regressionState ?? "not-assessed").toUpperCase()}</strong></span>
                    </div>
                    <small>{String(record.claimLimitation ?? "")}</small>
                    <div className="review-action">
                      <span>Record the fix and the separately reviewed retest without bypassing the execution approval gate.</span>
                      <button
                        className="secondary"
                        disabled={workflowBusy}
                        onClick={() => {
                          const opening = workflowEditorId !== String(record.id);
                          setWorkflowEditorId(opening ? String(record.id) : "");
                          if (opening && !workflowFixActionAt) setWorkflowFixActionAt(localDateTimeInputValue());
                        }}
                      >
                        {workflowEditorId === String(record.id) ? "Close controls" : "Manage remediation"}
                      </button>
                    </div>
                    {workflowEditorId === String(record.id) && (() => {
                      const recordId = String(record.id);
                      const status = String(record.status ?? "");
                      const pendingRetest = retests.find((retest) => !retest.outcome) as Record<string, unknown> | undefined;
                      const directRetest = pendingRetest?.directRetest && typeof pendingRetest.directRetest === "object"
                        ? pendingRetest.directRetest as Record<string, unknown>
                        : undefined;
                      const finding = workflow.findings.find((item) => String(item.id) === String(record.findingId));
                      const findingArtifactIds = Array.isArray(finding?.evidence_artifact_ids)
                        ? finding.evidence_artifact_ids.map(String)
                        : [];
                      const runBackedFinding = workflow.artifacts.some((artifact) => {
                        const observation = artifact.latest_observation as Record<string, unknown> | null | undefined;
                        return findingArtifactIds.includes(String(artifact.id)) && typeof observation?.run_id === "string";
                      });
                      const boundApproval = directRetest
                        ? workflow.approvals.find((item) => String(item.id) === String(directRetest.approvalId))
                        : undefined;
                      const boundRunArtifacts = directRetest
                        ? workflow.artifacts.filter((artifact) => {
                            const observation = artifact.latest_observation as Record<string, unknown> | null | undefined;
                            return String(observation?.run_id ?? "") === String(directRetest.retestRunId);
                          })
                        : [];
                      const boundRunSucceeded = boundApproval?.status === "consumed" && boundApproval.run_status === "succeeded";
                      const boundRunArtifactIds = boundRunArtifacts.map((artifact) => String(artifact.id));
                      const selectedRetestEvidenceIds = parsedWorkflowEvidenceIds();
                      const selectedEvidenceIsBound = selectedRetestEvidenceIds.length > 0 &&
                        selectedRetestEvidenceIds.every((artifactId) => boundRunArtifactIds.includes(artifactId));
                      const validFixActionAt = Number.isFinite(new Date(workflowFixActionAt).getTime());
                      return <div className="ai-body workflow-editor-body">
                        <div className="qa-actions">
                          {status === "open" && <button
                            className="secondary"
                            disabled={workflowBusy}
                            onClick={() => void remediationAction(recordId, "status", { status: "in-progress" }, "Remediation work started.")}
                          >Begin fix work</button>}
                          {status === "in-progress" && <button
                            className="secondary"
                            disabled={workflowBusy}
                            onClick={() => void remediationAction(recordId, "status", { status: "fix-ready" }, "Fix marked ready for evidence and retest.")}
                          >Mark fix ready</button>}
                        </div>
                        {!pendingRetest && status !== "open" && status !== "closed" && <div className="workflow-step">
                          <div className="review-heading">
                            <div><strong>Capture operator fix evidence</strong><small>Creates and seals a same-mission attestation; it does not prove the technical outcome.</small></div>
                            <span className="status-chip neutral">HUMAN ATTESTATION</span>
                          </div>
                          <label>Change type
                            <select value={workflowFixChangeType} onChange={(event) => setWorkflowFixChangeType(event.target.value)}>
                              <option value="device-configuration">Device configuration</option>
                              <option value="software-update">Software update</option>
                              <option value="operational-mitigation">Operational mitigation</option>
                              <option value="other">Other bounded change</option>
                            </select>
                          </label>
                          <label>Action performed at
                            <input
                              type="datetime-local"
                              value={workflowFixActionAt}
                              max={localDateTimeInputValue(new Date(Date.now() + 5 * 60_000))}
                              onChange={(event) => setWorkflowFixActionAt(event.target.value)}
                            />
                          </label>
                          <label>Action performed
                            <textarea
                              value={workflowFixSummary}
                              onChange={(event) => setWorkflowFixSummary(event.target.value)}
                              placeholder="Describe the exact operator action performed on the owned device."
                            />
                          </label>
                          <label>Observed state after the action
                            <textarea
                              value={workflowFixObservedState}
                              onChange={(event) => setWorkflowFixObservedState(event.target.value)}
                              placeholder="Record only what the operator directly observed after the change."
                            />
                          </label>
                          <button
                            className="secondary"
                            disabled={
                              workflowBusy ||
                              !validFixActionAt ||
                              workflowFixSummary.trim().length < 10 ||
                              workflowFixObservedState.trim().length < 10
                            }
                            onClick={() => void remediationAction(
                              recordId,
                              "fix-evidence/captures",
                              {
                                changeType: workflowFixChangeType,
                                actionPerformedAt: new Date(workflowFixActionAt).toISOString(),
                                actionSummary: workflowFixSummary,
                                observedState: workflowFixObservedState
                              },
                              "Operator fix record captured, sealed and attached. A separate approved retest is still required to establish outcome."
                            )}
                          >Capture and seal fix record</button>
                        </div>}
                        {!pendingRetest && status !== "closed" && <label>Evidence artifact IDs
                          <textarea
                            value={workflowEvidenceIds}
                            onChange={(event) => setWorkflowEvidenceIds(event.target.value)}
                            placeholder="Optional: attach existing same-mission artifact IDs, separated by commas."
                          />
                        </label>}
                        {!pendingRetest && status !== "closed" && <label>Fix evidence note or retest reason
                          <textarea
                            value={workflowNote}
                            onChange={(event) => setWorkflowNote(event.target.value)}
                            placeholder="State exactly what the evidence supports (minimum 10 characters)."
                          />
                        </label>}
                        {!pendingRetest && status !== "closed" && <div className="qa-actions">
                          <button
                            className="secondary"
                            disabled={workflowBusy || parsedWorkflowEvidenceIds().length === 0 || workflowNote.trim().length < 10}
                            onClick={() => void remediationAction(
                              recordId,
                              "fix-evidence",
                              { artifactIds: parsedWorkflowEvidenceIds(), note: workflowNote },
                              "Fix evidence attached to the append-only remediation record."
                            )}
                          >Attach fix evidence</button>
                          {fixEvidence.length > 0 && ["fix-ready", "persists", "regressed", "inconclusive", "remediated"].includes(status) && <button
                            className="primary"
                            disabled={workflowBusy || workflowNote.trim().length < 10}
                            onClick={() => void remediationAction(
                              recordId,
                              "retests",
                              { reason: workflowNote },
                              "Retest requested. Target execution still requires a fresh approval and deliberate execute action."
                            )}
                          >Request evidence-backed retest</button>}
                        </div>}
                        {pendingRetest && <>
                          <div className="workflow-step">
                            <div className="review-heading">
                              <div><strong>Direct retest binding</strong><small>{String(pendingRetest.reason ?? "Pending remediation retest")}</small></div>
                              <span className={`status-chip ${directRetest ? "accepted" : "pending"}`}>{directRetest ? "BOUND" : "NOT PREPARED"}</span>
                            </div>
                            {!directRetest && runBackedFinding && <>
                              <div className="control-note">This creates a fresh, exact-parameter retest proposal and pending approval. It does not approve, execute or record an outcome.</div>
                              <button
                                className="primary"
                                disabled={workflowBusy}
                                onClick={() => void remediationAction(
                                  recordId,
                                  `retests/${encodeURIComponent(String(pendingRetest.requestId))}/target-approval`,
                                  {},
                                  "Exact retest proposal prepared and bound. Review its fresh approval separately; no target contact has occurred."
                                )}
                              >Prepare fresh retest approval</button>
                            </>}
                            {!directRetest && !runBackedFinding && <div className="warning">The accepted finding is not backed by exactly one original run, so a direct target retest cannot be prepared here.</div>}
                            {directRetest && <>
                              <div className="artifact-facts">
                                <span>PARENT RUN<strong>{String(directRetest.parentRunId)}</strong></span>
                                <span>RETEST RUN<strong>{String(directRetest.retestRunId)}</strong></span>
                                <span>APPROVAL<strong>{String(directRetest.approvalId)}</strong></span>
                                <span>STATE<strong>{String(boundApproval?.status ?? "loading").toUpperCase()}</strong></span>
                              </div>
                              {!boundRunSucceeded && <div className="control-note">Approval review and execution remain separate deliberate actions in Approvals. Returning here never runs the target check automatically.</div>}
                              {!boundRunSucceeded && <button
                                className="secondary"
                                disabled={workflowBusy}
                                onClick={() => setView("Approvals")}
                              >Open separate approval gate</button>}
                              {boundRunSucceeded && boundRunArtifacts.length === 0 && <div className="warning">The bound retest succeeded, but no sealed artifact is available yet. Refresh before reviewing an outcome.</div>}
                              {boundRunSucceeded && boundRunArtifacts.length > 0 && <>
                                <div className="connector-health">
                                  <strong>Bound retest evidence</strong>
                                  {boundRunArtifacts.map((artifact) => <code key={String(artifact.id)}>{String(artifact.id)}</code>)}
                                </div>
                                <button
                                  className="secondary"
                                  disabled={workflowBusy}
                                  onClick={() => setWorkflowEvidenceIds(boundRunArtifactIds.join(", "))}
                                >Select bound retest evidence</button>
                              </>}
                            </>}
                          </div>
                          {boundRunSucceeded && boundRunArtifacts.length > 0 && <div className="workflow-step">
                            <div className="review-heading">
                              <div><strong>Human outcome review</strong><small>The operator must select the evidence and enter the supported conclusion.</small></div>
                              <span className="status-chip pending">REVIEW REQUIRED</span>
                            </div>
                            <label>Reviewed outcome
                              <select value={workflowOutcome} onChange={(event) => setWorkflowOutcome(event.target.value)}>
                                <option value="remediated">Remediated</option>
                                <option value="persists">Persists</option>
                                <option value="regressed">Regressed</option>
                                <option value="inconclusive">Inconclusive</option>
                              </select>
                            </label>
                            <label>Retest evidence artifact IDs
                              <textarea
                                value={workflowEvidenceIds}
                                onChange={(event) => setWorkflowEvidenceIds(event.target.value)}
                                placeholder="Select or paste artifact IDs from the bound successful retest."
                              />
                            </label>
                            {!selectedEvidenceIsBound && selectedRetestEvidenceIds.length > 0 && <div className="warning">Every selected artifact must come from the bound successful retest run.</div>}
                            <label>Outcome summary
                              <textarea
                                value={workflowNote}
                                onChange={(event) => setWorkflowNote(event.target.value)}
                                placeholder="Record only the conclusion supported by the retest evidence."
                              />
                            </label>
                            <button
                              className="primary"
                              disabled={workflowBusy || !selectedEvidenceIsBound || workflowNote.trim().length < 10}
                              onClick={() => void remediationAction(
                                recordId,
                                "retests/outcome",
                                {
                                  requestId: String(pendingRetest.requestId),
                                  outcome: workflowOutcome,
                                  summary: workflowNote,
                                  reviewer: session?.operator ?? "Local operator",
                                  evidenceArtifactIds: selectedRetestEvidenceIds
                                },
                                "Evidence-backed retest outcome recorded. A new report freeze will include this closed-loop result."
                              )}
                            >Record reviewed retest outcome</button>
                          </div>}
                        </>}
                      </div>;
                    })()}
                  </article>;
                })}</div>
              )}
            </article>
            <article className="panel report-register">
              <div className="panel-title">
                <div><p>IMPORT REGISTER</p><h2>Original artifacts and deduplicated candidates</h2></div>
                <span>{workflow?.imports.length ?? 0} records</span>
              </div>
              {!workflow || workflow.imports.length === 0 ? (
                <div className="empty"><strong>No inert imports yet</strong><span>Use the bounded SARIF intake to retain an original without trusting its conclusions.</span></div>
              ) : (
                <div className="record-list">{workflow.imports.map((record, index) => (
                  <article key={String(record.id ?? index)}>
                    <div className="review-heading">
                      <div><strong>{String(record.parserId)} · {String(record.parserVersion)}</strong><small>{String(record.id)}</small></div>
                      <span className={`status-chip ${record.integrityValid === true ? "accepted" : "integrity-failed"}`}>
                        {record.integrityValid === true ? "SOURCE VERIFIED" : "INTEGRITY FAILED"}
                      </span>
                    </div>
                    <div className="artifact-facts">
                      <span>RESULTS<strong>{String(record.resultCount ?? 0)}</strong></span>
                      <span>CANDIDATES<strong>{String(record.candidateCount ?? 0)}</strong></span>
                      <span>MISSION<strong>{String(record.missionId ?? "")}</strong></span>
                      <span>SIZE<strong>{formatBytes(record.sourceSizeBytes)}</strong></span>
                    </div>
                    <div className="artifact-hash"><small>SOURCE SHA-256</small><code>{String(record.sourceSha256 ?? "")}</code></div>
                  </article>
                ))}</div>
              )}
            </article>
          </section>
        ) : view === "Plan & Compare" ? (
          <section className="report-grid plan-workspace">
            <article className="panel report-control">
              <div className="panel-title">
                <div><p>VERSIONED TEST PLAN</p><h2>Engagement coverage ledger</h2></div>
                <span>IMMUTABLE VERSIONS</span>
              </div>
              <div className="ai-body">
                <div className="warning">
                  Completed procedures require verified same-mission evidence. Skipped, blocked and not-applicable work stays explicit and never becomes a “secure” claim.
                </div>
                <label>Mission
                  <select value={planMissionId} onChange={(event) => setPlanMissionId(event.target.value)}>
                    <option value="">Select an engagement mission</option>
                    {dashboard.missions.map((mission) => (
                      <option key={mission.id} value={mission.id}>{mission.name}</option>
                    ))}
                  </select>
                </label>
                <button
                  className="primary"
                  disabled={planBusy || !planMissionId}
                  onClick={() => void createProfessionalTestPlan()}
                >
                  {planBusy ? "Sealing plan…" : testPlans.length ? "Create next plan version" : "Create professional starter plan"}
                </button>
                <small>The starter creates explicit scope, baseline, defensive validation and publication-QA procedures. Operators can later bind each completion to stored run evidence.</small>
              </div>
            </article>
            <article className="panel report-register">
              <div className="panel-title">
                <div><p>PLAN REGISTER</p><h2>Sealed versions and dispositions</h2></div>
                <span>{testPlans.length} versions</span>
              </div>
              {!planMissionId ? (
                <div className="empty"><strong>Select a mission</strong><span>Plans are strictly mission-scoped.</span></div>
              ) : testPlans.length === 0 ? (
                <div className="empty"><strong>No test plan versions</strong><span>Create the professional starter, then update it through immutable successor versions.</span></div>
              ) : (
                <div className="record-list review-list">{testPlans.map((planRecord) => (
                  <article key={planRecord.id}>
                    <div className="review-heading">
                      <div><strong>v{planRecord.version} · {planRecord.title}</strong><small>{planRecord.createdBy} · {planRecord.createdAt}</small></div>
                      <span className={`status-chip ${planRecord.integrityValid ? "accepted" : "integrity-failed"}`}>
                        {planRecord.integrityValid ? "INTEGRITY VERIFIED" : "INTEGRITY FAILED"}
                      </span>
                    </div>
                    <div className="artifact-hash"><small>CONTENT HASH</small><code>{planRecord.contentHash}</code></div>
                    <div className="artifact-facts">
                      <span>COMPLETED<strong>{planRecord.summary.completed}</strong></span>
                      <span>BLOCKED<strong>{planRecord.summary.blocked}</strong></span>
                      <span>SKIPPED<strong>{planRecord.summary.skipped}</strong></span>
                      <span>N/A<strong>{planRecord.summary["not-applicable"]}</strong></span>
                    </div>
                    <div className="plan-procedures">{planRecord.procedures.map((procedure) => (
                      <div key={procedure.id}>
                        <div className="review-heading">
                          <strong>{procedure.title}</strong>
                          <span className={`status-chip ${procedure.state === "completed" ? "accepted" : "neutral"}`}>
                            {procedure.state.toUpperCase()}
                          </span>
                        </div>
                        <small>{procedure.capabilityId ?? procedure.blueRuleId} · evidence {procedure.evidence.length}</small>
                        <span>{procedure.rationale}</span>
                      </div>
                    ))}</div>
                    <small>{planRecord.claimLimitation}</small>
                  </article>
                ))}</div>
              )}
            </article>
            <form className="panel report-control" onSubmit={searchMissionHistory}>
              <div className="panel-title">
                <div><p>BOUNDED SEARCH</p><h2>Find mission evidence and history</h2></div>
                <span>MISSION ONLY</span>
              </div>
              <div className="ai-body">
                <label>Search term
                  <input
                    value={missionSearchQuery}
                    onChange={(event) => setMissionSearchQuery(event.target.value)}
                    minLength={2}
                    maxLength={80}
                    placeholder="finding, capability, evidence or owner"
                    required
                  />
                </label>
                <button className="primary" disabled={planBusy || !planMissionId || missionSearchQuery.trim().length < 2}>
                  Search mission records
                </button>
                <div className="search-results">{missionSearchResults.map((result) => (
                  <div key={`${result.kind}:${result.id}`}>
                    <strong>{result.kind.toUpperCase()} · {result.title}</strong>
                    <span>{result.detail}</span>
                    <small>{result.status ?? "record"} · {result.occurredAt} · {result.id}</small>
                  </div>
                ))}</div>
              </div>
            </form>
            <form className="panel report-control" onSubmit={compareRuns}>
              <div className="panel-title">
                <div><p>CONTROLLED RETEST</p><h2>Original versus direct retest</h2></div>
                <span>NO ABSENCE CLAIMS</span>
              </div>
              <div className="ai-body">
                <label>Original run ID
                  <input value={originalRunId} onChange={(event) => setOriginalRunId(event.target.value)} placeholder="UUID from mission search" required />
                </label>
                <label>Direct retest run ID
                  <input value={retestRunId} onChange={(event) => setRetestRunId(event.target.value)} placeholder="UUID with retest lineage" required />
                </label>
                <button className="primary" disabled={planBusy || !planMissionId || !originalRunId || !retestRunId}>
                  Compare verified evidence
                </button>
                {comparison && (
                  <div className="comparison-result">
                    <div className="artifact-facts">
                      <span>CONFIG<strong>{comparison.configurationEquivalent ? "EQUIVALENT" : "DIFFERENT"}</strong></span>
                      <span>SHARED HASHES<strong>{comparison.evidenceHashComparison.shared.length}</strong></span>
                      <span>ORIGINAL ONLY<strong>{comparison.evidenceHashComparison.originalOnly.length}</strong></span>
                      <span>RETEST ONLY<strong>{comparison.evidenceHashComparison.retestOnly.length}</strong></span>
                    </div>
                    {comparison.findings.map((finding) => (
                      <div key={`${finding.title}:${finding.assessment}`}>
                        <strong>{finding.title}</strong><span>{finding.assessment}</span>
                      </div>
                    ))}
                    <small>{comparison.claimLimitation}</small>
                  </div>
                )}
              </div>
            </form>
          </section>
        ) : view === "Local AI" ? (
          <section className="ai-grid">
            <article className="panel ai-status">
              <div className="panel-title"><div><p>LOCAL PROVIDER</p><h2>Ollama · T0 advisory lane</h2></div><span>{modelStatus?.health.healthy ? "READY" : "OFFLINE"}</span></div>
              <div className="ai-body">
                <div className="provider-line">
                  <strong>{modelStatus?.health.model ?? "Server-configured local model"}</strong>
                  <span>{modelStatus?.health.healthy ? `Ollama ${modelStatus.health.version ?? ""} · ${modelStatus.health.latencyMs}ms` : modelStatus?.health.error ?? "Checking local runtime…"}</span>
                </div>
                <div className="authority-grid">
                  <span>TOOLS<strong>NONE</strong></span><span>COMMANDS<strong>NONE</strong></span><span>MCP<strong>NONE</strong></span><span>TIER<strong>T0</strong></span>
                </div>
                <div className="warning">The model receives a bounded task profile and opaque target IDs—not raw target addresses. Its output cannot approve or launch anything.</div>
              </div>
            </article>
            <form className="panel ai-form" onSubmit={createAdvisoryPlan}>
              <div className="panel-title"><div><p>STRUCTURED PLANNING</p><h2>Create an advisory plan</h2></div><span>{modelStatus?.invocations.length ?? 0} logged calls</span></div>
              <div className="ai-body">
                <label>Authorized mission
                  <select value={aiMissionId} onChange={(event) => setAiMissionId(event.target.value)} required>
                    <option value="">Select a scope-validated mission</option>
                    {dashboard.missions.filter((mission) => mission.status !== "draft").map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <label>Planning objective
                  <textarea value={aiObjective} onChange={(event) => setAiObjective(event.target.value)} minLength={5} maxLength={2000} placeholder="Prepare a cautious, reviewable assessment plan for this authorized training mission." required />
                </label>
                <button className="primary" disabled={modelBusy || !modelStatus?.health.healthy}>{modelBusy ? "Generating locally…" : "Generate T0 plan"}</button>
              </div>
            </form>
            {plan && <article className="panel plan-output">
              <div className="panel-title"><div><p>UNTRUSTED ADVISORY OUTPUT</p><h2>{plan.objective}</h2></div><span>HUMAN REVIEW REQUIRED</span></div>
              <div className="plan-steps">{plan.steps.map((step, index) => <div key={`${index}-${step.description}`}><b>{String(index + 1).padStart(2, "0")}</b><span><strong>{step.description}</strong><small>{step.rationale}</small></span><em>{step.requiresHumanReview ? "REVIEW" : "ADVISORY"}</em></div>)}</div>
            </article>}
          </section>
        ) : view === "Approvals" ? (
          <section className="panel records-panel">
            <div className="panel-title"><div><p>HUMAN CONTROL GATE</p><h2>Parameter-bound approvals</h2></div><span>{records.length} records</span></div>
            <div className="control-note">Approving does not run the tool. Execution remains a separate deliberate action and every approval is expiring and single-use.</div>
            {targetResult && <div className="executor-result"><strong>Latest completed target run</strong><pre>{JSON.stringify(targetResult, null, 2)}</pre></div>}
            {recordsLoading ? <div className="empty"><strong>Loading approvals…</strong></div> : records.length === 0 ? (
              <div className="empty"><strong>No approval requests yet</strong><span>Prepare the bounded Redmi check from Missions.</span></div>
            ) : (
              <div className="record-list">{records.map((record, index) => {
                const proposal = (() => {
                  try {
                    return JSON.parse(String(record.proposal_json ?? "{}")) as Record<string, unknown>;
                  } catch {
                    return {};
                  }
                })();
                const descriptor = capabilities.find((item) => item.id === String(record.capability_id));
                return <article key={String(record.id ?? index)}>
                  <div className="review-heading">
                    <div>
                      <strong>{descriptor?.name ?? String(record.capability_id)}</strong>
                      <small>{String(record.capability_id)}</small>
                    </div>
                    <div className="status-row">
                      <span className={`status-chip ${String(record.status)}`}>{String(record.status).toUpperCase()}</span>
                      <span className="status-chip neutral">
                        {descriptor ? `${descriptor.riskTier} · ${descriptor.networkNoise.toUpperCase()} NOISE · ${descriptor.operatorDifficulty.toUpperCase()}` : String(record.risk_tier)}
                      </span>
                    </div>
                  </div>
                  <small>
                    target: {String(record.canonical_address)} · risk: {String(record.risk_tier)} · approval expires: {String(record.expires_at)}
                    {record.lineage_type ? ` · lineage: ${String(record.lineage_type)}` : ""}
                  </small>
                  {descriptor && <div className="artifact-facts">
                    <span>RUNTIME<strong>{descriptor.maxRuntimeMs / 1000}s maximum</strong></span>
                    <span>OUTPUT<strong>{formatBytes(descriptor.maxOutputBytes)}</strong></span>
                    <span>APPROVAL<strong>{descriptor.approvalPolicy}</strong></span>
                    <span>TECHNIQUE<strong>{descriptor.fixedTechnique}</strong></span>
                  </div>}
                  <details className="proposal-details">
                    <summary>Review exact immutable proposal JSON</summary>
                    <pre>{JSON.stringify(proposal, null, 2)}</pre>
                  </details>
                  {record.status === "pending" && <div className="modal-actions">
                    <button className="secondary" disabled={targetBusy} onClick={() => void decideApproval(String(record.id), "deny")}>Deny</button>
                    <button className="primary" disabled={targetBusy} onClick={() => void decideApproval(String(record.id), "approve")}>Approve once</button>
                  </div>}
                  {record.status === "approved" && <button className="primary" disabled={targetBusy} onClick={() => void executeTargetApproval(String(record.id))}>{targetBusy ? "Running…" : "Run approved check"}</button>}
                  {record.status === "consumed" && record.run_status === "succeeded" && record.lineage_type === "original" && (
                    <div className="control-note">
                      Retests are prepared from a pending remediation request so the new run, approval and reviewed outcome remain bound to the finding.
                    </div>
                  )}
                </article>;
              })}</div>
            )}
          </section>
        ) : view === "Findings" ? (
          <section className="panel records-panel review-register">
            <div className="panel-title"><div><p>HUMAN FINDING REVIEW</p><h2>Evidence-backed claims</h2></div><span>{records.length} records</span></div>
            <div className="control-note">Acceptance records the signed-in operator and the exact revision. A service observation is not automatically a vulnerability claim.</div>
            {recordsLoading ? <div className="empty"><strong>Loading findings…</strong></div> : records.length === 0 ? (
              <div className="empty"><strong>No findings yet</strong><span>Sealed evidence must support every candidate before it can appear here.</span></div>
            ) : (
              <div className="record-list review-list">{records.map((record, index) => {
                const findingId = String(record.id ?? index);
                const evidenceIds = stringArray(record.evidence_artifact_ids);
                return <article key={findingId}>
                  <div className="review-heading">
                    <div>
                      <strong>{String(record.title ?? "Untitled finding")}</strong>
                      <small>revision {String(record.revision ?? "?")} · mission {String(record.mission_id ?? "unknown")}</small>
                    </div>
                    <div className="status-row">
                      <span className={`status-chip ${String(record.status ?? "")}`}>{String(record.status ?? "unknown").toUpperCase()}</span>
                      <span className="status-chip neutral">{String(record.severity ?? "unknown").toUpperCase()} · {String(record.confidence ?? "unknown").toUpperCase()} CONFIDENCE</span>
                    </div>
                  </div>
                  <div className="review-copy">
                    <div><small>SUPPORTED OBSERVATION</small><p>{String(record.description ?? "")}</p></div>
                    <div><small>CAUTIOUS REMEDIATION</small><p>{String(record.remediation ?? "")}</p></div>
                  </div>
                  <div className="evidence-links">
                    <small>SEALED EVIDENCE</small>
                    {evidenceIds.map((artifactId) => <code key={artifactId}>{artifactId}</code>)}
                  </div>
                  {record.status === "unverified" && (
                    <div className="review-action">
                      <span>Review the wording and evidence link before accepting this exact revision.</span>
                      <button className="primary" disabled={Boolean(reviewBusyId)} onClick={() => void acceptFinding(findingId)}>
                        {reviewBusyId === findingId ? "Recording review…" : "Accept evidence-backed finding"}
                      </button>
                    </div>
                  )}
                  {record.status === "accepted" && (
                    <div className="review-action">
                      <span>Assign the fix, due date and evidence-backed retest in the workflow register.</span>
                      <button className="secondary" disabled={Boolean(reviewBusyId)} onClick={() => void createRemediation(findingId)}>
                        {reviewBusyId === findingId ? "Opening workflow…" : "Open remediation"}
                      </button>
                    </div>
                  )}
                </article>;
              })}</div>
            )}
          </section>
        ) : view === "Evidence" ? (
          <section className="panel records-panel review-register">
            <div className="panel-title"><div><p>IMMUTABLE EVIDENCE STORE</p><h2>Sealed artifacts and provenance</h2></div><span>{records.length} records</span></div>
            <div className="control-note">The integrity check reads the stored bytes and recalculates SHA-256. Observations bind an artifact to its mission and run.</div>
            {recordsLoading ? <div className="empty"><strong>Verifying artifacts…</strong></div> : records.length === 0 ? (
              <div className="empty"><strong>No evidence artifacts yet</strong><span>Completed controlled runs will seal their output here.</span></div>
            ) : (
              <div className="record-list evidence-list">{records.map((record, index) => {
                const latest = typeof record.latest_observation === "object" && record.latest_observation !== null
                  ? record.latest_observation as Record<string, unknown>
                  : null;
                return <article key={String(record.id ?? index)}>
                  <div className="review-heading">
                    <div><strong>{String(record.media_type ?? "Artifact")}</strong><small>{String(record.id ?? "")}</small></div>
                    <span className={`status-chip ${record.verified === true ? "accepted" : "integrity-failed"}`}>
                      {record.verified === true ? "SHA-256 VERIFIED" : "INTEGRITY FAILED"}
                    </span>
                  </div>
                  <div className="artifact-hash"><small>CONTENT HASH</small><code>{String(record.sha256 ?? "")}</code></div>
                  <div className="artifact-facts">
                    <span>SIZE<strong>{formatBytes(record.size_bytes)}</strong></span>
                    <span>OBSERVATIONS<strong>{String(record.observation_count ?? 0)}</strong></span>
                    <span>MISSION<strong>{String(latest?.mission_id ?? "unbound")}</strong></span>
                    <span>RUN<strong>{String(latest?.run_id ?? "manual or report output")}</strong></span>
                  </div>
                  {latest && <small>latest observation: {String(latest.id)} · provenance hash: {String(latest.provenance_hash)} · sealed: {String(record.sealed_at)}</small>}
                </article>;
              })}</div>
            )}
          </section>
        ) : view === "Reports" ? (
          <section className="report-grid">
            <article className="panel report-control">
              <div className="panel-title"><div><p>DETERMINISTIC REPORTING</p><h2>Freeze accepted evidence</h2></div><span>NO MODEL CALLS</span></div>
              <div className="ai-body">
                <div className="warning">Only human-accepted findings enter a report. Freezing captures the exact wording, evidence metadata, scope and audit head.</div>
                <label>Mission
                  <select value={reportMissionId} onChange={(event) => setReportMissionId(event.target.value)}>
                    <option value="">Select a reviewed mission</option>
                    {dashboard.missions.filter((mission) => mission.status !== "draft").map((mission) => <option key={mission.id} value={mission.id}>{mission.name}</option>)}
                  </select>
                </label>
                <button className="primary" disabled={!reportMissionId || Boolean(reportBusyId)} onClick={() => void freezeReport()}>
                  {reportBusyId === "freeze" ? "Freezing snapshot…" : "Freeze evidence-backed report"}
                </button>
                <small>If no accepted finding exists, the backend refuses to create a report.</small>
              </div>
            </article>
            <article className="panel report-register">
              <div className="panel-title"><div><p>REPORT REGISTER</p><h2>Frozen snapshots and outputs</h2></div><span>{records.length} records</span></div>
              {recordsLoading ? <div className="empty"><strong>Loading reports…</strong></div> : records.length === 0 ? (
                <div className="empty"><strong>No report snapshots yet</strong><span>Accept a supported finding, then freeze its mission here.</span></div>
              ) : (
                <div className="record-list">{records.map((record, index) => {
                  const reportId = String(record.id ?? index);
                  const qa = (record.qa ?? null) as ReportQaRecord | null;
                  const exportBundle = (record.exportBundle ?? null) as ReportExportBundle | null;
                  return <article key={reportId}>
                    <div className="review-heading">
                      <div><strong>{String(record.template_version ?? "Report snapshot")}</strong><small>{reportId}</small></div>
                      <span className={`status-chip ${String(record.status ?? "")}`}>{String(record.status ?? "unknown").toUpperCase()}</span>
                    </div>
                    <div className="artifact-hash"><small>SNAPSHOT HASH</small><code>{String(record.snapshot_hash ?? "")}</code></div>
                    <small>mission: {String(record.mission_id)} · frozen: {String(record.frozen_at)}</small>
                    {record.status === "frozen" && (
                      <div className="review-action">
                        <span>Rendering revalidates the audit prefix and every frozen evidence artifact.</span>
                        <button className="primary" disabled={Boolean(reportBusyId)} onClick={() => void generateReport(reportId)}>
                          {reportBusyId === reportId ? "Generating outputs…" : "Generate JSON + HTML"}
                        </button>
                      </div>
                    )}
                    {record.status === "generated" && <div className="report-outputs">
                      <div>
                        <small>JSON ARTIFACT</small><code>{String(record.json_artifact_id ?? "")}</code>
                        <div className="output-actions">
                          <a className="secondary" href={`/api/reports/${encodeURIComponent(reportId)}/outputs/json`} target="_blank" rel="noreferrer">View JSON</a>
                          <a className="secondary" href={`/api/reports/${encodeURIComponent(reportId)}/outputs/json?download=1`}>Download JSON</a>
                        </div>
                      </div>
                      <div>
                        <small>HTML ARTIFACT</small><code>{String(record.html_artifact_id ?? "")}</code>
                        <div className="output-actions">
                          <a className="secondary" href={`/api/reports/${encodeURIComponent(reportId)}/outputs/html`} target="_blank" rel="noreferrer">View HTML</a>
                          <a className="secondary" href={`/api/reports/${encodeURIComponent(reportId)}/outputs/html?download=1`}>Download HTML</a>
                        </div>
                      </div>
                    </div>}
                    {record.status === "generated" && !qa && (
                      <div className="review-action">
                        <span>Open a human QA gate bound to the exact generated artifacts before publication.</span>
                        <button
                          className="primary"
                          disabled={Boolean(reportBusyId)}
                          onClick={() => void openReportQa(reportId)}
                        >
                          {reportBusyId === `qa-open:${reportId}` ? "Opening QA…" : "Open QA review"}
                        </button>
                      </div>
                    )}
                    {qa?.status === "pending" && (
                      <div className="report-qa">
                        <div className="review-heading">
                          <div><strong>Publication QA</strong><small>review {qa.id}</small></div>
                          <span className="status-chip frozen">PENDING</span>
                        </div>
                        <label>Review note
                          <textarea
                            value={reportQaNote}
                            onChange={(event) => setReportQaNote(event.target.value)}
                            placeholder="Record what was checked and any limitations (minimum 10 characters)."
                          />
                        </label>
                        <label className="check-row">
                          <input
                            type="checkbox"
                            checked={reportQaConfirmedId === qa.id}
                            onChange={(event) => setReportQaConfirmedId(event.target.checked ? qa.id : "")}
                          />
                          I reviewed scope, supported claims, evidence links, remediation, sensitive data and the exact HTML layout.
                        </label>
                        <div className="qa-actions">
                          <button
                            className="primary"
                            disabled={
                              Boolean(reportBusyId) ||
                              reportQaConfirmedId !== qa.id ||
                              reportQaNote.trim().length < 10
                            }
                            onClick={() => void approveReportQa(qa.id)}
                          >
                            {reportBusyId === `qa-approve:${qa.id}` ? "Approving…" : "Approve exact outputs"}
                          </button>
                          <select value={reportQaIssue} onChange={(event) => setReportQaIssue(event.target.value)}>
                            <option value="scope">Scope</option>
                            <option value="claims">Unsupported claim</option>
                            <option value="evidence">Evidence link</option>
                            <option value="remediation">Remediation</option>
                            <option value="redaction">Sensitive data</option>
                            <option value="layout">Layout</option>
                            <option value="other">Other</option>
                          </select>
                          <button
                            className="secondary"
                            disabled={Boolean(reportBusyId) || reportQaNote.trim().length < 10}
                            onClick={() => void requestReportQaChanges(qa.id)}
                          >
                            {reportBusyId === `qa-changes:${qa.id}` ? "Recording…" : "Request changes"}
                          </button>
                        </div>
                      </div>
                    )}
                    {qa?.status === "approved" && (
                      <div className="report-qa approved">
                        <div className="review-heading">
                          <div><strong>Publication QA passed</strong><small>{qa.reviewer} · {qa.reviewedAt}</small></div>
                          <span className="status-chip accepted">PUBLICATION READY</span>
                        </div>
                        <small>Integrity verified: {String(qa.integrityValid)} · approval is bound to these exact JSON and HTML artifacts.</small>
                      </div>
                    )}
                    {qa?.status === "approved" && !exportBundle && (
                      <div className="review-action">
                        <span>Create polished PDF and DOCX derivatives bound to the approved source artifacts.</span>
                        <button
                          className="primary"
                          disabled={Boolean(reportBusyId)}
                          onClick={() => void generateReportExports(reportId)}
                        >
                          {reportBusyId === `export:${reportId}` ? "Generating exports…" : "Generate PDF + DOCX"}
                        </button>
                      </div>
                    )}
                    {exportBundle?.status === "pending" && (
                      <div className="report-qa">
                        <div className="review-heading">
                          <div><strong>PDF + DOCX visual QA</strong><small>bundle {exportBundle.id}</small></div>
                          <span className="status-chip frozen">VISUAL REVIEW REQUIRED</span>
                        </div>
                        <div className="report-outputs">
                          <div>
                            <small>PDF SHA-256</small><code>{exportBundle.outputs.pdf.sha256}</code>
                            <a className="secondary" href={`/api/report-exports/${encodeURIComponent(exportBundle.id)}/outputs/pdf?download=1`}>
                              Download PDF
                            </a>
                          </div>
                          <div>
                            <small>DOCX SHA-256</small><code>{exportBundle.outputs.docx.sha256}</code>
                            <a className="secondary" href={`/api/report-exports/${encodeURIComponent(exportBundle.id)}/outputs/docx?download=1`}>
                              Download DOCX
                            </a>
                          </div>
                        </div>
                        <label>Visual QA note
                          <textarea
                            value={reportQaNote}
                            onChange={(event) => setReportQaNote(event.target.value)}
                            placeholder="Record the PDF and DOCX visual checks (minimum 10 characters)."
                          />
                        </label>
                        <label className="check-row">
                          <input
                            type="checkbox"
                            checked={reportExportConfirmedId === exportBundle.id}
                            onChange={(event) =>
                              setReportExportConfirmedId(event.target.checked ? exportBundle.id : "")
                            }
                          />
                          I opened both exact downloads and reviewed layout, page breaks, evidence readability and sensitive data.
                        </label>
                        <button
                          className="primary"
                          disabled={
                            Boolean(reportBusyId) ||
                            reportExportConfirmedId !== exportBundle.id ||
                            reportQaNote.trim().length < 10
                          }
                          onClick={() => void approveReportExports(exportBundle.id)}
                        >
                          {reportBusyId === `export-approve:${exportBundle.id}` ? "Approving…" : "Approve PDF + DOCX"}
                        </button>
                      </div>
                    )}
                    {exportBundle?.status === "approved" && (
                      <div className="report-qa approved">
                        <div className="review-heading">
                          <div><strong>PDF + DOCX publication QA passed</strong><small>{exportBundle.reviewer} · {exportBundle.reviewedAt}</small></div>
                          <span className="status-chip accepted">PUBLICATION READY</span>
                        </div>
                        <div className="output-actions">
                          <a className="secondary" href={`/api/report-exports/${encodeURIComponent(exportBundle.id)}/outputs/pdf?download=1`}>Download PDF</a>
                          <a className="secondary" href={`/api/report-exports/${encodeURIComponent(exportBundle.id)}/outputs/docx?download=1`}>Download DOCX</a>
                        </div>
                      </div>
                    )}
                    {exportBundle?.status === "changes-requested" && (
                      <div className="report-qa changes-requested">
                        <div className="review-heading">
                          <div><strong>PDF + DOCX changes requested</strong><small>{exportBundle.reviewer} · {exportBundle.reviewedAt}</small></div>
                          <span className="status-chip integrity-failed">NOT PUBLISHABLE</span>
                        </div>
                        <small>issues: {exportBundle.issues.join(", ")} · {exportBundle.note}</small>
                      </div>
                    )}
                    {qa?.status === "changes-requested" && (
                      <div className="report-qa changes-requested">
                        <div className="review-heading">
                          <div><strong>Changes requested</strong><small>{qa.reviewer} · {qa.reviewedAt}</small></div>
                          <span className="status-chip integrity-failed">NOT PUBLISHABLE</span>
                        </div>
                        <small>issues: {qa.issues.join(", ")} · {qa.note}</small>
                      </div>
                    )}
                  </article>;
                })}</div>
              )}
            </article>
          </section>
        ) : view === "System" ? (
          <section className="system-grid">
            <article className="panel records-panel system-records">
              <div className="panel-title">
                <div><p>REDACTED SUPPORT SNAPSHOT</p><h2>Local integrity diagnostics</h2></div>
                <span>
                  {supportDiagnostics?.integrity.databaseQuickCheck &&
                  supportDiagnostics.integrity.audit.valid &&
                  supportDiagnostics.integrity.evidenceComplete &&
                  supportDiagnostics.integrity.evidenceInvalid === 0
                    ? "HEALTHY"
                    : supportDiagnostics ? "REVIEW" : "LOADING"}
                </span>
              </div>
              {!supportDiagnostics ? (
                <div className="empty"><strong>Checking the local control plane…</strong></div>
              ) : (
                <>
                  <div className="executor-facts">
                    <span>DATABASE<strong>{supportDiagnostics.integrity.databaseQuickCheck ? "OK" : "FAILED"}</strong></span>
                    <span>AUDIT<strong>{supportDiagnostics.integrity.audit.valid ? "VALID" : "FAILED"}</strong></span>
                    <span>EVIDENCE<strong>{
                      supportDiagnostics.integrity.evidenceInvalid > 0
                        ? `${supportDiagnostics.integrity.evidenceInvalid} INVALID`
                        : supportDiagnostics.integrity.evidenceComplete ? "VALID" : "PARTIAL"
                    }</strong></span>
                    <span>BINDING<strong>{supportDiagnostics.runtime.loopbackOnly ? "LOOPBACK" : "REVIEW"}</strong></span>
                  </div>
                  <div className="control-note">
                    {supportDiagnostics.product.name} {supportDiagnostics.product.version} · {supportDiagnostics.product.edition} · Node {supportDiagnostics.runtime.node} ·
                    checked {supportDiagnostics.generatedAt}. This view deliberately omits targets, evidence content, secrets and local paths.
                  </div>
                  <div className="record-list">
                    <article>
                      <strong>{supportDiagnostics.integrity.evidenceValid}/{supportDiagnostics.integrity.evidenceTotal} evidence artifacts verified</strong>
                      <small>{supportDiagnostics.integrity.audit.eventsChecked} audit events checked · storage configured: {String(supportDiagnostics.storage.databaseConfigured && supportDiagnostics.storage.evidenceStoreConfigured)}</small>
                    </article>
                    <article>
                      <strong>Redacted record counts</strong>
                      <small>{Object.entries(supportDiagnostics.records).map(([key, value]) => `${key}: ${value}`).join(" · ")}</small>
                    </article>
                  </div>
                </>
              )}
            </article>
            <article className="panel executor-panel">
              <div className="panel-title">
                <div><p>RESTRICTED MCPWN BROKER</p><h2>Network-free version proof</h2></div>
                <span>{executorBusy ? "RUNNING" : executorAvailable ? "READY" : "UNAVAILABLE"}</span>
              </div>
              <div className="executor-body">
                <div className="warning">
                  No target is accepted or contacted. This fixed capability can only run <code>nmap --version</code>; arbitrary commands and arguments are rejected.
                </div>
                <div className="executor-facts">
                  <span>NETWORK<strong>NONE</strong></span>
                  <span>TARGET<strong>NONE</strong></span>
                  <span>COMMAND<strong>nmap --version</strong></span>
                  <span>INPUT<strong>{`{}`}</strong></span>
                </div>
                <div className="executor-status">
                  <strong>Broker status</strong>
                  {executorStatusError
                    ? <span className="error-text">{executorStatusError}</span>
                    : <pre>{executorStatus ? JSON.stringify(executorStatus, null, 2) : "Checking local broker…"}</pre>}
                </div>
                <button
                  className="primary"
                  disabled={!executorAvailable || executorBusy}
                  onClick={() => void runVersionCheck()}
                >
                  {executorBusy ? "Running fixed check…" : "Run network-free version check"}
                </button>
              </div>
            </article>
            <article className="panel executor-output">
              <div className="panel-title">
                <div><p>BOUNDED RESULT</p><h2>Recorded output</h2></div>
                <span>{executorBusy ? "RUNNING" : executorError ? "FAILED" : executorResult ? "COMPLETE" : "NOT RUN"}</span>
              </div>
              <div className="executor-body">
                {!executorResult && !executorError ? (
                  <div className="empty"><strong>No version check in this session</strong><span>Run the fixed capability to display its logged result.</span></div>
                ) : (
                  <>
                    {executorError && <div className="executor-error"><strong>Error</strong><pre>{executorError}</pre></div>}
                    {executorResult && <>
                      <div className="executor-result"><strong>Output</strong><pre>{executorResult.execution.output}</pre></div>
                      <div className="executor-result"><strong>Execution metadata</strong><pre>{JSON.stringify({
                        capabilityId: executorResult.execution.capabilityId,
                        executionId: executorResult.execution.executionId,
                        outputBytes: executorResult.execution.outputBytes,
                        durationMs: executorResult.execution.durationMs,
                        binarySha256: executorResult.execution.binarySha256,
                        configSha256: executorResult.execution.configSha256,
                        completedAt: executorResult.execution.completedAt
                      }, null, 2)}</pre></div>
                      <div className="executor-result"><strong>Evidence artifact</strong><pre>{JSON.stringify(executorResult.artifact, null, 2)}</pre></div>
                    </>}
                  </>
                )}
              </div>
            </article>
            <article className="panel records-panel system-records">
              <div className="panel-title">
                <div><p>EXECUTION LIFECYCLE</p><h2>Persistent recovery register</h2></div>
                <span>{executionRegistry?.summary.total ?? 0} records</span>
              </div>
              <div className="control-note">
                Nonterminal: {executionRegistry?.summary.nonterminal ?? 0}. Orphaned after restart: {executionRegistry?.summary.orphaned ?? 0}.
              </div>
              {!executionRegistry || executionRegistry.executions.length === 0 ? (
                <div className="empty"><strong>No persisted executions yet</strong><span>Lifecycle state will survive an API restart without storing process IDs or raw output.</span></div>
              ) : (
                <div className="record-list">{executionRegistry.executions.map((execution) => (
                  <article key={execution.id}>
                    <strong>{execution.capabilityId} · {execution.status}</strong>
                    <small>
                      executionId: {execution.id} · operator: {execution.operator} · created: {execution.createdAt}
                      {execution.finishedAt ? ` · finished: ${execution.finishedAt}` : ""}
                      {execution.failureCode ? ` · failure: ${execution.failureCode}` : ""}
                    </small>
                  </article>
                ))}</div>
              )}
            </article>
            <article className="panel records-panel system-records">
              <div className="panel-title"><div><p>SYSTEM REGISTER</p><h2>Verified local records</h2></div><span>{records.length} records</span></div>
              <div className="control-note">Emergency stop: {dashboard.emergencyStop.state}. Audit valid: {String(dashboard.audit.valid)}.</div>
              {recordsLoading ? <div className="empty"><strong>Loading local records…</strong></div> : records.length === 0 ? (
                <div className="empty"><strong>No system records yet</strong><span>Completed broker activity will be preserved in the audit trail.</span></div>
              ) : (
                <div className="record-list">{records.map((record, index) => (
                  <article key={String(record.id ?? record.sequence ?? index)}>
                    <strong>{String(record.title ?? record.event_type ?? record.capability_id ?? record.sha256 ?? record.id ?? "Record")}</strong>
                    <small>{Object.entries(record).slice(0, 5).map(([key, value]) => `${key}: ${String(value)}`).join(" · ")}</small>
                  </article>
                ))}</div>
              )}
            </article>
          </section>
        ) : (
          <section className="panel records-panel">
            <div className="panel-title"><div><p>{view.toUpperCase()} REGISTER</p><h2>Verified local records</h2></div><span>{records.length} records</span></div>
            <div className="control-note">
              {view === "Approvals" && "Approvals are parameter-bound, expiring and single-use."}
              {view === "Findings" && "Only evidence-backed revisions can be accepted."}
              {view === "Evidence" && "Artifacts are content-addressed and verified by SHA-256."}
              {view === "Reports" && "Frozen snapshots render without model calls or live lookups."}
              {view === "System" && `Emergency stop: ${dashboard.emergencyStop.state}. Audit valid: ${String(dashboard.audit.valid)}.`}
            </div>
            {recordsLoading ? <div className="empty"><strong>Loading local records…</strong></div> : records.length === 0 ? (
              <div className="empty"><strong>No {view.toLowerCase()} records yet</strong><span>The control is implemented and waiting for an authorized workflow.</span></div>
            ) : (
              <div className="record-list">{records.map((record, index) => (
                <article key={String(record.id ?? record.sequence ?? index)}>
                  <strong>{String(record.title ?? record.event_type ?? record.capability_id ?? record.sha256 ?? record.id ?? 'Record')}</strong>
                  <small>{Object.entries(record).slice(0, 5).map(([key, value]) => `${key}: ${String(value)}`).join(' · ')}</small>
                </article>
              ))}</div>
            )}
          </section>
        )}
        <footer><span>LOCAL ONLY · 127.0.0.1</span><span>MODEL HAS NO EXECUTION AUTHORITY</span></footer>
      </main>

      {newMissionOpen && (
        <div className="modal-backdrop">
          <form className="modal" onSubmit={createMission}>
            <p>NEW MISSION</p><h2>Create a controlled workspace</h2>
            <label>Mission name<input autoFocus value={missionName} onChange={(event) => setMissionName(event.target.value)} minLength={3} maxLength={120} required /></label>
            <div className="modal-actions"><button type="button" className="secondary" onClick={() => setNewMissionOpen(false)}>Cancel</button><button className="primary">Create draft</button></div>
          </form>
        </div>
      )}

      {selectedMission && (
        <div className="modal-backdrop">
          <form className="modal wide" onSubmit={addScope}>
            <p>EXACT SCOPE</p><h2>{selectedMission.name}</h2>
            <div className="warning">Only enter a target you own and have isolated. Atlas, the home LAN and third-party systems remain out of scope.</div>
            <label>Literal IP address<input value={targetAddress} onChange={(event) => setTargetAddress(event.target.value)} placeholder="192.168.50.7" required /></label>
            <label>Authorization statement<textarea value={authorization} onChange={(event) => setAuthorization(event.target.value)} minLength={12} required /></label>
            <label className="checkbox"><input type="checkbox" checked={privateIsolation} onChange={(event) => setPrivateIsolation(event.target.checked)} /> Private target has been deliberately isolated</label>
            <small>The fresh authorization window is one hour. This records scope only; it cannot launch a tool.</small>
            <div className="modal-actions"><button type="button" className="secondary" onClick={() => setSelectedMission(null)}>Cancel</button><button className="primary">Validate fresh scope</button></div>
          </form>
        </div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
