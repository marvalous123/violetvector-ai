import { createReadStream, existsSync, statSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { extname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { z } from "zod";
import { MCPWN_VERSION_CAPABILITY, type VersionOnlyExecutor } from "@war-room/executor-contract";
import { OllamaModelProvider, type ModelProvider } from "@war-room/model-provider";
import { actionProposalSchema, evaluateProposal } from "@war-room/policy";
import {
  LOCAL_AI_PROVIDER_LIMITS,
  resolveLocalAiModel,
  type SupportedLocalAiModel
} from "./config/local-ai.js";
import { openDatabase } from "./db/database.js";
import { AuditService } from "./services/audit-service.js";
import { ApprovalService } from "./services/approval-service.js";
import {
  BlueDetectionService,
  blueScenarioIdSchema
} from "./services/blue-detection-service.js";
import { EvidenceService } from "./services/evidence-service.js";
import type { TelemetrySignatureVerifier } from "./services/endpoint-ingestion-service.js";
import { EndpointCryptoService } from "./services/endpoint-crypto-service.js";
import {
  endpointFactReceipt,
  EndpointFactCorrelationService,
  LIVE_ENDPOINT_RULE_IDS
} from "./services/endpoint-fact-correlation-service.js";
import {
  EndpointRegistryService,
  type EnrollmentProofVerifier
} from "./services/endpoint-registry-service.js";
import { ExecutionLifecycleService } from "./services/execution-lifecycle-service.js";
import { FindingService } from "./services/finding-service.js";
import { GuidedDemoService } from "./services/guided-demo-service.js";
import { InertImportService } from "./services/inert-import-service.js";
import { MissionCockpitService } from "./services/mission-cockpit-service.js";
import {
  MissionComparisonSearchService,
  missionSearchInputSchema
} from "./services/mission-comparison-search-service.js";
import { MissionService } from "./services/mission-service.js";
import { ModelService } from "./services/model-service.js";
import {
  completeBenchmarkInputSchema,
  OperationalBenchmarkService,
  recordBenchmarkMilestoneInputSchema,
  startBenchmarkInputSchema
} from "./services/operational-benchmark-service.js";
import {
  OPERATOR_SESSION_COOKIE,
  OperatorSessionService,
  type OperatorSessionOptions
} from "./services/operator-session-service.js";
import { ReportService } from "./services/report-service.js";
import {
  changeDueDateInputSchema,
  changeOwnerInputSchema,
  changePriorityInputSchema,
  changeRemediationStatusInputSchema,
  createRemediationInputSchema,
  fixEvidenceInputSchema,
  operatorFixEvidenceInputSchema,
  remediationStatusSchema,
  requestRetestInputSchema,
  retestOutcomeInputSchema,
  reviewerCommentInputSchema,
  revokeRiskAcceptanceInputSchema,
  riskAcceptanceInputSchema,
  RemediationService
} from "./services/remediation-service.js";
import {
  approveReportQaInputSchema,
  ReportQaService,
  requestReportQaChangesInputSchema
} from "./services/report-qa-service.js";
import {
  approveReportExportInputSchema,
  ReportExportService,
  requestReportExportChangesInputSchema
} from "./services/report-export-service.js";
import { RunControlService } from "./services/run-control-service.js";
import {
  buildCapabilityCatalogue,
  type ProductEdition
} from "./services/capability-catalogue.js";
import type { TargetIsolationVerifier } from "./services/redmi-isolation-service.js";
import { TargetExecutionService, type TargetExecutorFactory } from "./services/target-execution-service.js";
import {
  TestPlanService,
  testPlanProcedureInputSchema
} from "./services/test-plan-service.js";
import { SupportDiagnosticsService } from "./services/support-diagnostics-service.js";
import { VersionExecutionService } from "./services/version-execution-service.js";

const host = "127.0.0.1";
const port = Number(process.env.WAR_ROOM_PORT ?? 4315);
const MAX_BODY_BYTES = 64 * 1024;
const MAX_INERT_IMPORT_BODY_BYTES = 3 * 1024 * 1024;
const ENDPOINT_DATA_PLANE_PATHS = new Set([
  "/api/endpoints/capabilities",
  "/api/endpoints/facts"
]);

function isEndpointDataPlaneRequest(method: string | undefined, pathname: string): boolean {
  return method === "POST" && ENDPOINT_DATA_PLANE_PATHS.has(pathname);
}

const createMissionSchema = z.object({ name: z.string().min(3).max(120) }).strict();
const createScopeSchema = z
  .object({
    startsAt: z.string().datetime({ offset: true }),
    expiresAt: z.string().datetime({ offset: true }),
    authorizationStatement: z.string().min(12).max(4_000),
    authorizationAttachmentSha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    targets: z
      .array(
        z
          .object({
            address: z.string().min(1).max(128),
            isolatedPrivateTargetApproved: z.boolean().optional()
          })
          .strict()
      )
      .min(1)
      .max(16)
  })
  .strict();
const approvalDecisionSchema = z.object({ note: z.string().max(1_000).default("") }).strict();
const stopRequestSchema = z.object({ reason: z.string().min(5).max(1_000) }).strict();
const evidenceSchema = z.object({ content: z.string().max(50_000), mediaType: z.enum(["text/plain", "application/json"]) }).strict();
const findingSchema = z
  .object({
    missionId: z.string().min(1).max(128),
    title: z.string().min(5).max(160),
    severity: z.enum(["info", "low", "medium", "high", "critical"]),
    description: z.string().min(10).max(10_000),
    remediation: z.string().min(5).max(10_000),
    confidence: z.enum(["low", "medium", "high"]),
    evidenceArtifactIds: z.array(z.string().min(1).max(128)).min(1).max(32)
  })
  .strict();
const findingRevisionSchema = findingSchema.omit({ missionId: true, title: true }).strict();
const reviewerSchema = z.object({}).strict();
const reportGenerationSchema = z.object({}).strict();
const guidedDemoSchema = z.object({}).strict();
const freezeReportSchema = z.object({ missionId: z.string().min(1).max(128), templateVersion: z.string().min(1).max(80) }).strict();
const unlockSchema = z
  .object({
    bootstrapSecret: z.string().min(1).max(256),
    operator: z.string().trim().min(2).max(120)
  })
  .strict();
const modelPlanSchema = z
  .object({ missionId: z.string().min(1).max(128), objective: z.string().min(5).max(2_000) })
  .strict();
const versionExecutionSchema = z.object({}).strict();
const targetApprovalSchema = z.object({
  missionId: z.string().min(1).max(128),
  ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(32)
    .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
  intensity: z.number().int().min(0).max(2)
}).strict();
const allTcpApprovalSchema = z.object({
  missionId: z.string().min(1).max(128)
}).strict();
const targetProfileApprovalSchema = (maxPorts: number) => z.object({
  missionId: z.string().min(1).max(128),
  ports: z.array(z.number().int().min(1).max(65_535)).min(1).max(maxPorts)
    .refine((ports) => new Set(ports).size === ports.length, "ports must be unique")
}).strict();
const tcpPortStateApprovalSchema = targetProfileApprovalSchema(16);
const httpMetadataApprovalSchema = targetProfileApprovalSchema(4);
const tlsCertificateApprovalSchema = targetProfileApprovalSchema(4);
const tlsCiphersApprovalSchema = targetProfileApprovalSchema(2);
const retestApprovalSchema = z.object({}).strict();
const targetExecutionSchema = z.object({ approvalId: z.string().min(1).max(128) }).strict();
const blueSimulationSchema = z.object({
  missionId: z.string().min(1).max(128),
  scenarioId: blueScenarioIdSchema
}).strict();
const blueWorkspaceQuerySchema = z.object({
  missionId: z.string().min(1).max(128).optional()
}).strict();
const missionQuerySchema = z.object({
  missionId: z.string().uuid().optional()
}).strict();
const endpointMissionQuerySchema = z.object({
  missionId: z.string().uuid()
}).strict();
const liveCorrelationListQuerySchema = z.object({
  missionId: z.string().uuid(),
  endpointId: z.string().regex(/^endpoint-[a-f0-9-]{36}$/).optional()
}).strict();
const testPlanListQuerySchema = z.object({
  missionId: z.string().uuid(),
  limit: z.coerce.number().int().min(1).max(100).default(25)
}).strict();
const createTestPlanRequestSchema = z.object({
  missionId: z.string().uuid(),
  title: z.string().trim().min(5).max(160),
  objective: z.string().trim().min(10).max(4_000),
  expectedPreviousPlanId: z.string().uuid().nullable().optional(),
  procedures: z.array(testPlanProcedureInputSchema).min(1).max(200)
}).strict().superRefine((value, context) => {
  const keys = value.procedures.map((procedure) => procedure.key);
  if (new Set(keys).size !== keys.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Procedure keys must be unique"
    });
  }
});
const runComparisonSchema = z.object({
  missionId: z.string().uuid(),
  originalRunId: z.string().uuid(),
  retestRunId: z.string().uuid()
}).strict();
const enrollmentRequestSchema = z.object({
  missionId: z.string().uuid(),
  certificateFingerprintSha256: z.string().regex(/^[a-f0-9]{64}$/),
  identityExpiresAt: z.string().datetime({ offset: true })
}).strict();
const enrollmentApprovalSchema = z.object({
  confirmedCertificateFingerprintSha256: z.string().regex(/^[a-f0-9]{64}$/),
  proofSignatureBase64: z.string().min(40).max(2_048).regex(/^[A-Za-z0-9+/=]+$/)
}).strict();
const endpointPublicKeyRegistrationSchema = z.object({
  publicKeySpkiBase64: z.string().min(56).max(4_096).regex(/^[A-Za-z0-9+/=]+$/)
}).strict();
const endpointRevocationSchema = z.object({
  reason: z.string().trim().min(5).max(500)
}).strict();
const endpointRenewalRequestSchema = z.object({
  certificateFingerprintSha256: z.string().regex(/^[a-f0-9]{64}$/),
  identityExpiresAt: z.string().datetime({ offset: true }),
  reason: z.string().trim().min(10).max(500)
}).strict();
const inertSarifImportSchema = z.object({
  missionId: z.string().uuid(),
  contentBase64: z
    .string()
    .min(4)
    .max(2_796_204)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  parentImportId: z.string().uuid().optional()
}).strict();
const remediationListQuerySchema = z.object({
  missionId: z.string().uuid().optional(),
  status: remediationStatusSchema.optional()
}).strict();
function securityHeaders(response: ServerResponse): void {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Cache-Control", "no-store");
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function readJson(request: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<unknown> {
  const contentType = (request.headers["content-type"] ?? "")
    .split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new Error("CONTENT_TYPE_REQUIRED");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maxBytes) throw new Error("REQUEST_TOO_LARGE");
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("JSON_INVALID");
  }
}

function publicError(error: unknown): { status: number; code: string } {
  if (error instanceof z.ZodError) return { status: 400, code: "SCHEMA_INVALID" };
  const explicitCode =
    typeof error === "object" && error !== null && typeof Reflect.get(error, "code") === "string"
      ? String(Reflect.get(error, "code"))
      : undefined;
  const messageCode = error instanceof Error ? error.message.split(":")[0] : undefined;
  const candidate = explicitCode ?? messageCode;
  const code = candidate && /^[A-Z][A-Z0-9_]{0,63}$/.test(candidate)
    ? candidate
    : "REQUEST_FAILED";
  if (code === "SESSION_REQUIRED" || code === "SESSION_EXPIRED" || code === "SESSION_UNLOCK_FAILED") {
    return { status: 401, code };
  }
  if (code === "CSRF_INVALID" || code === "SESSION_COOKIE_INVALID" || code === "TAB_CAPABILITY_INVALID") {
    return { status: 403, code };
  }
  if (code === "PROFESSIONAL_EDITION_REQUIRED") return { status: 403, code };
  if (
    code === "EXECUTOR_UNAVAILABLE" ||
    code === "ENDPOINT_CONNECTOR_UNAVAILABLE" ||
    code === "SPAWN_FAILED" ||
    code === "ARTIFACT_UNAVAILABLE"
  ) {
    return { status: 503, code };
  }
  if (code === "PROTOCOL_ERROR") return { status: 502, code };
  if (code.endsWith("NOT_FOUND")) return { status: 404, code };
  if (
    code.includes("LOCKED") ||
    code.includes("STOP") ||
    code.includes("EXPIRED") ||
    code.includes("CANCEL") ||
    code.includes("TIMED_OUT") ||
    code.includes("OUTPUT_LIMIT") ||
    code.includes("HASH_MISMATCH") ||
    code === "EXECUTOR_BUSY"
  ) {
    return { status: 409, code };
  }
  return { status: 400, code };
}

function isUnsafeMethod(method: string | undefined): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

function hasExactOrigin(request: IncomingMessage): boolean {
  try {
    const hostHeader = request.headers.host;
    const origin = request.headers.origin;
    if (!hostHeader || !origin) return false;
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === "http:" && parsedOrigin.origin.toLowerCase() === `http://${hostHeader}`.toLowerCase();
  } catch {
    return false;
  }
}

function sessionCookie(value: string): string {
  return `${OPERATOR_SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`;
}

function expiredSessionCookie(): string {
  return `${OPERATOR_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
}

function isLoopbackRequest(request: IncomingMessage): boolean {
  try {
    const remoteAddress = request.socket.remoteAddress;
    if (!remoteAddress || !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(remoteAddress)) return false;
    const hostHeader = request.headers.host;
    if (!hostHeader) return false;
    const hostname = new URL(`http://${hostHeader}`).hostname.toLowerCase();
    if (hostname !== "127.0.0.1" && hostname !== "localhost") return false;
    const origin = request.headers.origin;
    if (!origin) return true;
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === "http:" && parsedOrigin.origin.toLowerCase() === `http://${hostHeader}`.toLowerCase();
  } catch {
    return false;
  }
}

const mediaTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function serveStatic(webRoot: string, pathname: string, response: ServerResponse): boolean {
  const root = resolve(webRoot);
  const requested = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const candidate = resolve(root, normalize(requested));
  const fromRoot = relative(root, candidate);
  if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) return false;
  const path = existsSync(candidate) && statSync(candidate).isFile() ? candidate : join(root, "index.html");
  if (!existsSync(path)) return false;
  response.writeHead(200, { "Content-Type": mediaTypes[extname(path)] ?? "application/octet-stream" });
  createReadStream(path).pipe(response);
  return true;
}

export interface ServerOptions {
  databasePath?: string;
  evidenceRoot?: string;
  webRoot?: string;
  modelProvider?: ModelProvider;
  localAiModel?: SupportedLocalAiModel;
  executor?: VersionOnlyExecutor;
  targetIsolationVerifier?: TargetIsolationVerifier;
  targetExecutorFactory?: TargetExecutorFactory;
  endpointEnrollmentProofVerifier?: EnrollmentProofVerifier;
  endpointTelemetrySignatureVerifier?: TelemetrySignatureVerifier;
  bootstrapSecret?: string;
  operatorSessionOptions?: OperatorSessionOptions;
  productEdition?: ProductEdition;
}

export function buildServer(options: ServerOptions = {}) {
  const productEdition: ProductEdition =
    options.productEdition ??
    (process.env.WAR_ROOM_EDITION === "starter" ? "starter" : "professional");
  const assertProfessionalEdition = (): void => {
    if (productEdition !== "professional") throw new Error("PROFESSIONAL_EDITION_REQUIRED");
  };
  const database = openDatabase(options.databasePath ?? ":memory:");
  const audit = new AuditService(database);
  const missions = new MissionService(database, audit);
  const approvals = new ApprovalService(database, audit);
  const controls = new RunControlService(database, audit);
  // Instantiated here so every server has a bounded local evidence root even before evidence routes are enabled.
  const evidence = new EvidenceService(database, options.evidenceRoot ?? mkdtempSync(join(tmpdir(), "war-room-api-evidence-")), audit);
  const supportDiagnostics = new SupportDiagnosticsService(
    database,
    audit,
    evidence,
    productEdition,
    Boolean(options.databasePath && options.databasePath !== ":memory:" && options.evidenceRoot)
  );
  const blueDetections = new BlueDetectionService(database, evidence, audit);
  const findings = new FindingService(database, evidence, audit);
  const reports = new ReportService(database, evidence, audit);
  const benchmarks = new OperationalBenchmarkService(database, evidence, audit);
  const reportQa = new ReportQaService(database, evidence, audit);
  const reportExports = new ReportExportService(database, evidence, audit, reportQa);
  const remediation = new RemediationService(database, evidence, audit, approvals);
  const testPlans = new TestPlanService(database, evidence, audit);
  const comparisonSearch = new MissionComparisonSearchService(
    database,
    evidence,
    remediation
  );
  const inertImports = new InertImportService(database, evidence, audit);
  const endpointCrypto = new EndpointCryptoService(database, audit);
  const endpointRegistry = new EndpointRegistryService(
    database,
    audit,
    options.endpointEnrollmentProofVerifier ?? endpointCrypto.verifyEnrollmentProof
  );
  const endpointFactCorrelation = new EndpointFactCorrelationService(
    database,
    endpointRegistry,
    evidence,
    audit,
    options.endpointTelemetrySignatureVerifier ?? endpointCrypto.verifyTelemetrySignature
  );
  const endpointTrustConfigured = true;
  const missionCockpit = new MissionCockpitService(database, blueDetections, audit);
  const guidedDemo = new GuidedDemoService(database, missions, blueDetections, findings, reports, audit);
  const lifecycles = new ExecutionLifecycleService(database, audit);
  const recoveredExecutions = lifecycles.reconcileStartup();
  const modelProvider =
    options.modelProvider ??
    new OllamaModelProvider({
      ...LOCAL_AI_PROVIDER_LIMITS,
      model: resolveLocalAiModel(options.localAiModel)
    });
  const model = new ModelService(database, modelProvider, audit);
  const activeModelRequests = new Map<string, AbortController>();
  const versionExecution = options.executor
    ? new VersionExecutionService(options.executor, controls, evidence, audit, lifecycles)
    : undefined;
  const targetExecution = options.targetIsolationVerifier
    ? new TargetExecutionService(
        database,
        options.targetIsolationVerifier,
        controls,
        approvals,
        evidence,
        lifecycles,
        audit,
        options.targetExecutorFactory
      )
    : undefined;
  const sessions = new OperatorSessionService(
    options.bootstrapSecret ?? OperatorSessionService.generateBootstrapSecret(),
    options.operatorSessionOptions
  );

  const server = createServer(async (request, response) => {
    securityHeaders(response);
    if (!isLoopbackRequest(request)) {
      json(response, 403, { error: "LOOPBACK_ORIGIN_REQUIRED" });
      return;
    }
    const url = new URL(request.url ?? "/", `http://${host}`);
    const pathname = url.pathname;
    try {
      const endpointDataPlaneRequest = isEndpointDataPlaneRequest(request.method, pathname);
      if (isUnsafeMethod(request.method) && !endpointDataPlaneRequest && !hasExactOrigin(request)) {
        json(response, 403, { error: "EXACT_ORIGIN_REQUIRED" });
        return;
      }

      if (request.method === "GET" && pathname === "/api/health") {
        json(response, 200, {
          status: "ok",
          executionEnabled: Boolean(targetExecution),
          targetExecutionEnabled: Boolean(targetExecution),
          policyVersion: "policy-v1",
          productEdition,
          emergencyStop: controls.getStopState().state,
          endpointTrustConfigured,
          audit: audit.status()
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/session/unlock") {
        const body = unlockSchema.parse(await readJson(request));
        const unlocked = sessions.unlock(body.bootstrapSecret, body.operator);
        response.setHeader("Set-Cookie", sessionCookie(unlocked.cookieValue));
        json(response, 200, { authenticated: true, ...unlocked.session });
        return;
      }

      if (request.method === "GET" && pathname === "/api/session") {
        const session = sessions.current(
          request.headers.cookie,
          typeof request.headers["x-war-room-tab"] === "string" ? request.headers["x-war-room-tab"] : undefined
        );
        json(response, 200, session ? { authenticated: true, ...session } : { authenticated: false });
        return;
      }

      let authenticated: { operator: string } | undefined;
      if (pathname.startsWith("/api/") && !endpointDataPlaneRequest) {
        authenticated = isUnsafeMethod(request.method)
          ? sessions.authorize(
              request.headers.cookie,
              typeof request.headers["x-war-room-csrf"] === "string" ? request.headers["x-war-room-csrf"] : undefined,
              typeof request.headers["x-war-room-tab"] === "string" ? request.headers["x-war-room-tab"] : undefined
            )
          : sessions.authenticate(
              request.headers.cookie,
              typeof request.headers["x-war-room-tab"] === "string" ? request.headers["x-war-room-tab"] : undefined
            );
      }

      if (request.method === "POST" && pathname === "/api/session/logout") {
        sessions.logout(
          request.headers.cookie,
          typeof request.headers["x-war-room-tab"] === "string" ? request.headers["x-war-room-tab"] : undefined
        );
        response.setHeader("Set-Cookie", expiredSessionCookie());
        json(response, 200, { authenticated: false });
        return;
      }

      if (request.method === "GET" && pathname === "/api/dashboard") {
        const pendingApprovals = database
          .prepare("SELECT COUNT(*) AS count FROM approval_requests WHERE status = 'pending'")
          .get() as { count: number };
        const findings = database.prepare("SELECT COUNT(*) AS count FROM findings").get() as { count: number };
        const artifacts = database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number };
        const activeRuns = database
          .prepare("SELECT COUNT(*) AS count FROM runs WHERE status IN ('armed', 'running', 'awaiting_approval')")
          .get() as { count: number };
        json(response, 200, {
          missions: missions.listMissions(),
          counts: {
            activeRuns: activeRuns.count,
            pendingApprovals: pendingApprovals.count,
            findings: findings.count,
            artifacts: artifacts.count
          },
          emergencyStop: controls.getStopState(),
          audit: audit.verify(),
          executionEnabled: Boolean(targetExecution),
          productEdition
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/capabilities") {
        json(response, 200, {
          capabilities: buildCapabilityCatalogue({
            targetExecutionEnabled: Boolean(targetExecution),
            versionProofEnabled: Boolean(versionExecution),
            emergencyStopState: controls.getStopState().state,
            edition: productEdition
          }),
          edition: productEdition,
          editions: {
            starter: "Core missions, local planning, low-noise TCP state, targeted service checks, the synthetic Blue Team lab, evidence and reports.",
            professional: "Adds HTTP/TLS posture, intensive discovery, advanced retests and capability-pack development."
          }
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/guided-demo") {
        controls.assertReady();
        guidedDemoSchema.parse(await readJson(request));
        json(response, 201, { demo: guidedDemo.create(authenticated!.operator) });
        return;
      }

      const missionCockpitMatch = pathname.match(/^\/api\/missions\/([^/]+)\/cockpit$/);
      if (request.method === "GET" && missionCockpitMatch) {
        const missionId = decodeURIComponent(missionCockpitMatch[1]!);
        json(response, 200, { cockpit: missionCockpit.get(missionId) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/blue") {
        if (url.searchParams.getAll("missionId").length > 1) throw new Error("SCHEMA_INVALID");
        const query = blueWorkspaceQuerySchema.parse(Object.fromEntries(url.searchParams.entries()));
        if (query.missionId) missions.getMission(query.missionId);
        const catalogue = blueDetections.catalogue(query.missionId);
        const liveRuns = query.missionId ? endpointFactCorrelation.listRuns(query.missionId) : [];
        const latestCoverage = new Map<string, (typeof liveRuns)[number]>();
        for (const run of liveRuns) {
          for (const coverage of run.result.coverage) {
            if (!latestCoverage.has(coverage.ruleId)) latestCoverage.set(coverage.ruleId, run);
          }
        }
        const validationMatrix = catalogue.validationMatrix.map((row) => {
          const latest = latestCoverage.get(row.ruleId);
          const coverage = latest?.result.coverage.find((item) => item.ruleId === row.ruleId);
          return {
            ...row,
            liveValidation: coverage
              ? {
                  status: coverage.status,
                  endpointEvidencePresent: Boolean(coverage.capabilitySnapshotId),
                  latestRunId: latest!.id,
                  endpointId: latest!.endpointId,
                  evidenceArtifactId: latest!.evidenceArtifactId,
                  validatedAt: latest!.createdAt,
                  reason: coverage.reason
                }
              : row.liveValidation
          };
        });
        const liveSupportedRuleIds = validationMatrix
          .filter((row) => row.liveValidation.status === "live-supported")
          .map((row) => row.ruleId);
        const liveEndpointRows = query.missionId
          ? database
              .prepare(
                `SELECT endpoint_id FROM endpoint_identities
                 WHERE mission_id = ? ORDER BY issued_at DESC LIMIT 50`
              )
              .all(query.missionId) as unknown as Array<{ endpoint_id: string }>
          : [];
        const liveEndpoints = liveEndpointRows.map((row) => ({
          identity: endpointRegistry.getIdentity(row.endpoint_id),
          capabilities: endpointFactCorrelation.listCapabilities(
            query.missionId!,
            row.endpoint_id
          )
        }));
        json(response, 200, {
          ...catalogue,
          validationMatrix,
          coverage: {
            ...catalogue.coverage,
            liveSupportedRuleIds,
            liveStatus: liveSupportedRuleIds.length ? "window-validated" : "connector-required"
          },
          liveRuns,
          liveEndpoints,
          liveRuleIds: LIVE_ENDPOINT_RULE_IDS,
          runs: query.missionId ? blueDetections.list(query.missionId) : [],
          endpointAccess: {
            mode: "read-only-telemetry",
            status: endpointTrustConfigured ? "enrollment-ready" : "connector-required",
            commandExecution: false,
            remoteShell: false,
            note: endpointTrustConfigured
              ? "The signed intake boundary is configured; live support still requires an approved endpoint identity, healthy telemetry and rule correlation."
              : "Live monitoring requires a separately enrolled least-privilege endpoint telemetry connector."
          }
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/blue/simulations") {
        controls.assertReady();
        const body = blueSimulationSchema.parse(await readJson(request));
        json(response, 201, {
          run: blueDetections.runSimulation(body.missionId, body.scenarioId, authenticated!.operator)
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/blue/live-correlations") {
        if (
          url.searchParams.getAll("missionId").length !== 1 ||
          url.searchParams.getAll("endpointId").length > 1
        ) {
          throw new Error("SCHEMA_INVALID");
        }
        const query = liveCorrelationListQuerySchema.parse(
          Object.fromEntries(url.searchParams.entries())
        );
        json(response, 200, {
          runs: endpointFactCorrelation.listRuns(query.missionId, query.endpointId)
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/blue/live-correlations") {
        controls.assertReady();
        json(response, 201, {
          run: endpointFactCorrelation.correlate(
            await readJson(request),
            authenticated!.operator
          )
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/endpoints") {
        if (url.searchParams.getAll("missionId").length > 1) throw new Error("SCHEMA_INVALID");
        const query = missionQuerySchema.parse(Object.fromEntries(url.searchParams.entries()));
        const rows = (query.missionId
          ? database
              .prepare(
                "SELECT endpoint_id FROM endpoint_identities WHERE mission_id = ? ORDER BY issued_at DESC"
              )
              .all(query.missionId)
          : database
              .prepare("SELECT endpoint_id FROM endpoint_identities ORDER BY issued_at DESC")
              .all()) as unknown as Array<{ endpoint_id: string }>;
        json(response, 200, {
          endpoints: rows.map((row) => endpointRegistry.getIdentity(row.endpoint_id)),
          renewals: endpointRegistry.listRenewals(query.missionId),
          trustConfigured: endpointTrustConfigured,
          intake: {
            direction: "endpoint-to-war-room-only",
            commandChannel: false,
            remoteShell: false,
            responseActions: false
          }
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/endpoints/enrollment-challenges") {
        const body = enrollmentRequestSchema.parse(await readJson(request));
        json(response, 201, {
          challenge: endpointRegistry.requestEnrollment(body, authenticated!.operator)
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/endpoints/capabilities") {
        json(response, 201, {
          capability: endpointFactCorrelation.recordCapability(
            await readJson(request, 256 * 1024)
          )
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/endpoints/facts") {
        json(response, 202, {
          receipt: endpointFactReceipt(
            endpointFactCorrelation.ingestFacts(
              await readJson(request, 32 * 1024)
            )
          )
        });
        return;
      }

      const endpointCapabilitiesMatch = pathname.match(
        /^\/api\/endpoints\/(endpoint-[a-f0-9-]{36})\/capabilities$/
      );
      if (request.method === "GET" && endpointCapabilitiesMatch) {
        if (url.searchParams.getAll("missionId").length !== 1) {
          throw new Error("SCHEMA_INVALID");
        }
        const query = endpointMissionQuerySchema.parse(
          Object.fromEntries(url.searchParams.entries())
        );
        json(response, 200, {
          capabilities: endpointFactCorrelation.listCapabilities(
            query.missionId,
            endpointCapabilitiesMatch[1]!
          )
        });
        return;
      }

      const endpointEnrollmentPublicKeyMatch = pathname.match(
        /^\/api\/endpoints\/enrollment-challenges\/([^/]+)\/public-key$/
      );
      if (request.method === "POST" && endpointEnrollmentPublicKeyMatch) {
        const challengeId = decodeURIComponent(endpointEnrollmentPublicKeyMatch[1]!);
        const body = endpointPublicKeyRegistrationSchema.parse(await readJson(request));
        json(response, 201, {
          key: endpointCrypto.registerEnrollmentPublicKey({
            challengeId,
            publicKeySpkiBase64: body.publicKeySpkiBase64
          })
        });
        return;
      }

      const endpointEnrollmentApprovalMatch = pathname.match(
        /^\/api\/endpoints\/enrollment-challenges\/([^/]+)\/approve$/
      );
      if (request.method === "POST" && endpointEnrollmentApprovalMatch) {
        const challengeId = decodeURIComponent(endpointEnrollmentApprovalMatch[1]!);
        const body = enrollmentApprovalSchema.parse(await readJson(request));
        json(response, 200, {
          endpoint: endpointRegistry.approveEnrollment(
            { challengeId, ...body },
            authenticated!.operator
          )
        });
        return;
      }

      const endpointRenewalRequestMatch = pathname.match(
        /^\/api\/endpoints\/(endpoint-[a-f0-9-]{36})\/renewal-challenges$/
      );
      if (request.method === "POST" && endpointRenewalRequestMatch) {
        const body = endpointRenewalRequestSchema.parse(await readJson(request));
        json(response, 201, endpointRegistry.requestRenewal(
          endpointRenewalRequestMatch[1]!,
          body,
          authenticated!.operator
        ));
        return;
      }

      const endpointRenewalApprovalMatch = pathname.match(
        /^\/api\/endpoints\/renewal-challenges\/([^/]+)\/approve$/
      );
      if (request.method === "POST" && endpointRenewalApprovalMatch) {
        const challengeId = decodeURIComponent(endpointRenewalApprovalMatch[1]!);
        const body = enrollmentApprovalSchema.parse(await readJson(request));
        json(response, 200, endpointRegistry.approveRenewal(
          { challengeId, ...body },
          authenticated!.operator
        ));
        return;
      }

      const endpointRevocationMatch = pathname.match(/^\/api\/endpoints\/([^/]+)\/revoke$/);
      if (request.method === "POST" && endpointRevocationMatch) {
        const endpointId = decodeURIComponent(endpointRevocationMatch[1]!);
        const body = endpointRevocationSchema.parse(await readJson(request));
        json(response, 200, {
          endpoint: endpointRegistry.revokeEndpoint(
            endpointId,
            authenticated!.operator,
            body.reason
          )
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/endpoints/telemetry") {
        throw new Error("ENDPOINT_TELEMETRY_SCHEMA_RETIRED");
      }

      if (request.method === "GET" && pathname === "/api/missions") {
        json(response, 200, { missions: missions.listMissions() });
        return;
      }
      if (request.method === "POST" && pathname === "/api/missions") {
        const body = createMissionSchema.parse(await readJson(request));
        json(response, 201, { mission: missions.createMission(body.name) });
        return;
      }

      const scopeMatch = pathname.match(/^\/api\/missions\/([^/]+)\/scope$/);
      if (request.method === "POST" && scopeMatch) {
        const body = createScopeSchema.parse(await readJson(request));
        const missionId = decodeURIComponent(scopeMatch[1]!);
        json(response, 201, {
          scope: missions.createScopeVersion({
            missionId,
            policyVersion: "policy-v1",
            startsAt: body.startsAt,
            expiresAt: body.expiresAt,
            authorizationStatement: body.authorizationStatement,
            ...(body.authorizationAttachmentSha256 ? { authorizationAttachmentSha256: body.authorizationAttachmentSha256 } : {}),
            targets: body.targets.map((target) => ({
              address: target.address,
              ...(target.isolatedPrivateTargetApproved === undefined
                ? {}
                : { isolatedPrivateTargetApproved: target.isolatedPrivateTargetApproved })
            }))
          })
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/policy/evaluate") {
        const proposal = actionProposalSchema.parse(await readJson(request));
        const scope = missions.getLatestScope(proposal.missionId);
        json(response, 200, { decision: evaluateProposal({ proposal, scope }) });
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/service-version/approvals") {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = targetApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestApproval(body, authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/all-tcp-ports/approvals") {
        assertProfessionalEdition();
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = allTcpApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestAllTcpApproval(body.missionId, authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/tcp-port-state/approvals") {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = tcpPortStateApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestProfileApproval({
          ...body, capabilityId: "network.tcp-port-state"
        }, authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/http-metadata/approvals") {
        assertProfessionalEdition();
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = httpMetadataApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestProfileApproval({
          ...body, capabilityId: "web.http-metadata"
        }, authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/tls-certificate/approvals") {
        assertProfessionalEdition();
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = tlsCertificateApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestProfileApproval({
          ...body, capabilityId: "tls.certificate-metadata"
        }, authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/tls-ciphers/approvals") {
        assertProfessionalEdition();
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = tlsCiphersApprovalSchema.parse(await readJson(request));
        json(response, 201, await targetExecution.requestProfileApproval({
          ...body, capabilityId: "tls.cipher-enumeration"
        }, authenticated!.operator));
        return;
      }

      const retestApprovalMatch = pathname.match(/^\/api\/target\/runs\/([^/]+)\/retest-approvals$/);
      if (request.method === "POST" && retestApprovalMatch) {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        retestApprovalSchema.parse(await readJson(request));
        const parentRunId = decodeURIComponent(retestApprovalMatch[1]!);
        json(response, 201, await targetExecution.requestRetestApproval(parentRunId, authenticated!.operator));
        return;
      }

      const approvalMatch = pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
      if (request.method === "POST" && approvalMatch) {
        const body = approvalDecisionSchema.parse(await readJson(request));
        const approvalId = decodeURIComponent(approvalMatch[1]!);
        const approval = approvalMatch[2] === "approve"
          ? approvals.approve(approvalId, authenticated!.operator, body.note)
          : approvals.deny(approvalId, authenticated!.operator, body.note);
        json(response, 200, { approval });
        return;
      }

      if (request.method === "POST" && pathname === "/api/emergency-stop") {
        const body = stopRequestSchema.parse(await readJson(request));
        const emergencyStop = controls.requestStop(authenticated!.operator, body.reason);
        const executorRequestsAborted = versionExecution?.abortAll() ?? 0;
        const targetRequestsAborted = targetExecution?.abortAll() ?? 0;
        for (const controller of activeModelRequests.values()) controller.abort();
        json(response, 200, {
          emergencyStop,
          modelRequestsAborted: activeModelRequests.size,
          executorRequestsAborted,
          targetRequestsAborted
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/approvals") {
        const rows = database
          .prepare(
            `SELECT ar.id, ar.proposal_id, ar.status, ar.requested_at, ar.expires_at, ar.decided_at,
                    ar.decided_by, ar.decision_note, ar.consumed_at,
                    ar.proposal_hash, ar.policy_version, ar.tool_schema_hash,
                    p.capability_id, p.risk_tier, p.mission_id, p.target_id, p.run_id, p.proposal_json,
                    r.parent_run_id, r.lineage_type, r.status AS run_status,
                    t.canonical_address, b.scope_version_id,
                    (SELECT starts_at FROM scope_versions
                     WHERE mission_id = p.mission_id ORDER BY version DESC LIMIT 1) AS latest_scope_starts_at,
                    (SELECT expires_at FROM scope_versions
                     WHERE mission_id = p.mission_id ORDER BY version DESC LIMIT 1) AS latest_scope_expires_at
             FROM approval_requests ar
             JOIN proposals p ON p.id = ar.proposal_id
             LEFT JOIN runs r ON r.id = p.run_id
             JOIN targets t ON t.id = p.target_id
             JOIN approval_scope_bindings b ON b.approval_id = ar.id
             ORDER BY ar.requested_at DESC LIMIT 200`
          )
          .all();
        json(response, 200, { approvals: rows });
        return;
      }

      if (request.method === "GET" && pathname === "/api/evidence") {
        const rows = database
          .prepare("SELECT id, sha256, size_bytes, media_type, captured_at, sealed_at FROM artifacts ORDER BY sealed_at DESC LIMIT 500")
          .all() as unknown as Array<{
            id: string;
            sha256: string;
            size_bytes: number;
            media_type: string;
            captured_at: string;
            sealed_at: string;
          }>;
        const artifacts = rows.map((artifact) => {
          const latestObservation = database
            .prepare(
              `SELECT id, mission_id, run_id, provenance_hash, recorded_at
               FROM evidence_observations
               WHERE artifact_id = ?
               ORDER BY recorded_at DESC, id DESC LIMIT 1`
            )
            .get(artifact.id) as
            | {
                id: string;
                mission_id: string;
                run_id: string | null;
                provenance_hash: string;
                recorded_at: string;
              }
            | undefined;
          const observationCount = database
            .prepare("SELECT COUNT(*) AS count FROM evidence_observations WHERE artifact_id = ?")
            .get(artifact.id) as { count: number };
          return {
            ...artifact,
            verified: evidence.verify(artifact.id),
            observation_count: observationCount.count,
            latest_observation: latestObservation ?? null
          };
        });
        json(response, 200, { artifacts });
        return;
      }
      if (request.method === "POST" && pathname === "/api/evidence") {
        const body = evidenceSchema.parse(await readJson(request));
        json(response, 201, { artifact: evidence.seal(body.content, body.mediaType) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/imports") {
        if (url.searchParams.getAll("missionId").length > 1) throw new Error("SCHEMA_INVALID");
        const query = missionQuerySchema.parse(Object.fromEntries(url.searchParams.entries()));
        const rows = (query.missionId
          ? database
              .prepare(
                "SELECT id FROM inert_imports WHERE mission_id = ? ORDER BY imported_at DESC, id DESC LIMIT 200"
              )
              .all(query.missionId)
          : database
              .prepare("SELECT id FROM inert_imports ORDER BY imported_at DESC, id DESC LIMIT 200")
              .all()) as unknown as Array<{ id: string }>;
        json(response, 200, { imports: rows.map((row) => inertImports.get(row.id)) });
        return;
      }

      if (request.method === "POST" && pathname === "/api/imports/sarif") {
        controls.assertReady();
        const body = inertSarifImportSchema.parse(
          await readJson(request, MAX_INERT_IMPORT_BODY_BYTES)
        );
        const bytes = Buffer.from(body.contentBase64, "base64");
        if (bytes.toString("base64") !== body.contentBase64) throw new Error("SARIF_BASE64_INVALID");
        json(response, 201, {
          imported: inertImports.importSarif(body.missionId, bytes, {
            operator: authenticated!.operator,
            ...(body.parentImportId ? { parentImportId: body.parentImportId } : {})
          })
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/findings") {
        const rows = database
          .prepare(
            `SELECT f.id, f.mission_id, f.status, f.title, f.created_at, f.updated_at,
                    fr.id AS revision_id, fr.severity, fr.confidence, fr.revision,
                    fr.description, fr.remediation,
                    COALESCE((
                      SELECT json_group_array(feo.artifact_id)
                      FROM finding_evidence_observations feo
                      WHERE feo.finding_revision_id = fr.id
                    ), '[]') AS evidence_artifact_ids_json
             FROM findings f LEFT JOIN finding_revisions fr ON fr.id = (
               SELECT id FROM finding_revisions WHERE finding_id = f.id ORDER BY revision DESC LIMIT 1
             ) ORDER BY f.updated_at DESC LIMIT 500`
          )
          .all() as unknown as Array<Record<string, unknown> & { evidence_artifact_ids_json: string }>;
        const findingRecords = rows.map(({ evidence_artifact_ids_json: evidenceArtifactIdsJson, ...finding }) => ({
          ...finding,
          evidence_artifact_ids: JSON.parse(evidenceArtifactIdsJson) as string[]
        }));
        json(response, 200, { findings: findingRecords });
        return;
      }
      if (request.method === "POST" && pathname === "/api/findings") {
        const body = findingSchema.parse(await readJson(request));
        const findingId = findings.createCandidate(body.missionId, body.title, {
          severity: body.severity,
          description: body.description,
          remediation: body.remediation,
          confidence: body.confidence,
          evidenceArtifactIds: body.evidenceArtifactIds
        });
        json(response, 201, { findingId });
        return;
      }
      const reviseFindingMatch = pathname.match(/^\/api\/findings\/([^/]+)\/revisions$/);
      if (request.method === "POST" && reviseFindingMatch) {
        const body = findingRevisionSchema.parse(await readJson(request));
        const findingId = decodeURIComponent(reviseFindingMatch[1]!);
        const revisionId = findings.addRevision(findingId, {
          severity: body.severity,
          description: body.description,
          remediation: body.remediation,
          confidence: body.confidence,
          evidenceArtifactIds: body.evidenceArtifactIds
        });
        json(response, 201, { findingId, revisionId, status: "unverified" });
        return;
      }
      const acceptFindingMatch = pathname.match(/^\/api\/findings\/([^/]+)\/accept$/);
      if (request.method === "POST" && acceptFindingMatch) {
        reviewerSchema.parse(await readJson(request));
        const findingId = decodeURIComponent(acceptFindingMatch[1]!);
        findings.accept(findingId, authenticated!.operator);
        json(response, 200, { findingId, status: "accepted" });
        return;
      }

      if (request.method === "GET" && pathname === "/api/benchmarks") {
        if (url.searchParams.getAll("missionId").length > 1) throw new Error("SCHEMA_INVALID");
        const missionId = url.searchParams.get("missionId") ?? undefined;
        json(response, 200, { benchmarks: benchmarks.list(missionId) });
        return;
      }
      if (request.method === "POST" && pathname === "/api/benchmarks") {
        const body = startBenchmarkInputSchema.parse(await readJson(request));
        json(response, 201, { benchmark: benchmarks.start(body, authenticated!.operator) });
        return;
      }
      const benchmarkMilestoneMatch = pathname.match(/^\/api\/benchmarks\/([^/]+)\/milestones$/);
      if (request.method === "POST" && benchmarkMilestoneMatch) {
        const body = recordBenchmarkMilestoneInputSchema.parse(await readJson(request));
        json(response, 200, {
          benchmark: benchmarks.recordMilestone(
            decodeURIComponent(benchmarkMilestoneMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }
      const benchmarkCompleteMatch = pathname.match(/^\/api\/benchmarks\/([^/]+)\/complete$/);
      if (request.method === "POST" && benchmarkCompleteMatch) {
        const body = completeBenchmarkInputSchema.parse(await readJson(request));
        json(response, 200, {
          benchmark: benchmarks.complete(
            decodeURIComponent(benchmarkCompleteMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/remediations") {
        if (
          url.searchParams.getAll("missionId").length > 1 ||
          url.searchParams.getAll("status").length > 1
        ) {
          throw new Error("SCHEMA_INVALID");
        }
        const query = remediationListQuerySchema.parse(
          Object.fromEntries(url.searchParams.entries())
        );
        const records = remediation.list(query.missionId).filter(
          (record) => !query.status || record.status === query.status
        );
        json(response, 200, { remediations: records });
        return;
      }

      const findingRemediationMatch = pathname.match(/^\/api\/findings\/([^/]+)\/remediation$/);
      if (request.method === "GET" && findingRemediationMatch) {
        const findingId = decodeURIComponent(findingRemediationMatch[1]!);
        json(response, 200, { remediation: remediation.getForFinding(findingId) });
        return;
      }
      if (request.method === "POST" && findingRemediationMatch) {
        const findingId = decodeURIComponent(findingRemediationMatch[1]!);
        const body = createRemediationInputSchema.parse(await readJson(request));
        json(response, 201, {
          remediation: remediation.create(findingId, body, authenticated!.operator)
        });
        return;
      }

      const remediationOwnerMatch = pathname.match(/^\/api\/remediations\/([^/]+)\/owner$/);
      if (request.method === "POST" && remediationOwnerMatch) {
        const body = changeOwnerInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.changeOwner(
            decodeURIComponent(remediationOwnerMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationDueDateMatch = pathname.match(/^\/api\/remediations\/([^/]+)\/due-date$/);
      if (request.method === "POST" && remediationDueDateMatch) {
        const body = changeDueDateInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.changeDueDate(
            decodeURIComponent(remediationDueDateMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationPriorityMatch = pathname.match(/^\/api\/remediations\/([^/]+)\/priority$/);
      if (request.method === "POST" && remediationPriorityMatch) {
        const body = changePriorityInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.changePriority(
            decodeURIComponent(remediationPriorityMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationStatusMatch = pathname.match(/^\/api\/remediations\/([^/]+)\/status$/);
      if (request.method === "POST" && remediationStatusMatch) {
        const body = changeRemediationStatusInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.changeStatus(
            decodeURIComponent(remediationStatusMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationCommentMatch = pathname.match(/^\/api\/remediations\/([^/]+)\/comments$/);
      if (request.method === "POST" && remediationCommentMatch) {
        const body = reviewerCommentInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.addReviewerComment(
            decodeURIComponent(remediationCommentMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationRiskAcceptanceMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/risk-acceptance$/
      );
      if (request.method === "POST" && remediationRiskAcceptanceMatch) {
        const body = riskAcceptanceInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.recordRiskAcceptance(
            decodeURIComponent(remediationRiskAcceptanceMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationRiskRevocationMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/risk-acceptance\/revoke$/
      );
      if (request.method === "POST" && remediationRiskRevocationMatch) {
        const body = revokeRiskAcceptanceInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.revokeRiskAcceptance(
            decodeURIComponent(remediationRiskRevocationMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationFixEvidenceMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/fix-evidence$/
      );
      if (request.method === "POST" && remediationFixEvidenceMatch) {
        const body = fixEvidenceInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.addFixEvidence(
            decodeURIComponent(remediationFixEvidenceMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      const remediationFixCaptureMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/fix-evidence\/captures$/
      );
      if (request.method === "POST" && remediationFixCaptureMatch) {
        const body = operatorFixEvidenceInputSchema.parse(await readJson(request));
        const result = remediation.captureOperatorFixEvidence(
          decodeURIComponent(remediationFixCaptureMatch[1]!),
          body,
          authenticated!.operator
        );
        json(response, 201, result);
        return;
      }

      const remediationRetestRequestMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/retests$/
      );
      if (request.method === "POST" && remediationRetestRequestMatch) {
        const remediationId = decodeURIComponent(remediationRetestRequestMatch[1]!);
        const body = requestRetestInputSchema.parse(await readJson(request));
        const requestId = remediation.requestRetest(
          remediationId,
          body,
          authenticated!.operator
        );
        json(response, 201, {
          requestId,
          remediation: remediation.get(remediationId)
        });
        return;
      }

      const remediationTargetRetestMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/retests\/([^/]+)\/target-approval$/
      );
      if (request.method === "POST" && remediationTargetRetestMatch) {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        retestApprovalSchema.parse(await readJson(request));
        const remediationId = decodeURIComponent(remediationTargetRetestMatch[1]!);
        const requestId = decodeURIComponent(remediationTargetRetestMatch[2]!);
        const current = remediation.get(remediationId);
        const pending = current.retests.find((item) => item.requestId === requestId);
        if (!pending || pending.outcome || current.status !== "retest-pending") {
          throw new Error("REMEDIATION_RETEST_STATE_INVALID");
        }
        if (pending.directRetest) throw new Error("REMEDIATION_DIRECT_RETEST_ALREADY_BOUND");
        const sourceRuns = database
          .prepare(
            `SELECT DISTINCT observation.run_id
             FROM remediation_records record
             JOIN finding_revisions revision ON revision.finding_id = record.finding_id
             JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
             JOIN evidence_observations observation
               ON observation.id = citation.observation_id
              AND observation.artifact_id = citation.artifact_id
             WHERE record.id = ?
               AND revision.id = (
                 SELECT id FROM finding_revisions
                 WHERE finding_id = record.finding_id ORDER BY revision DESC LIMIT 1
               )
               AND observation.run_id IS NOT NULL
             ORDER BY observation.run_id`
          )
          .all(remediationId) as unknown as Array<{ run_id: string }>;
        if (sourceRuns.length !== 1) throw new Error("REMEDIATION_DIRECT_RETEST_PARENT_INVALID");
        const prepared = await targetExecution.requestRetestApproval(
          sourceRuns[0]!.run_id,
          authenticated!.operator
        );
        const bindingInput = {
          requestId,
          parentRunId: sourceRuns[0]!.run_id,
          retestRunId: prepared.proposal.runId,
          approvalId: prepared.approval.id,
          proposalId: prepared.proposal.proposalId
        };
        let binding: ReturnType<RemediationService["bindDirectRetest"]>;
        try {
          binding = remediation.bindDirectRetest(
            remediationId,
            bindingInput,
            authenticated!.operator
          );
        } catch (bindingError) {
          try {
            remediation.abandonDirectRetestPreparation(
              remediationId,
              bindingInput,
              authenticated!.operator
            );
          } catch {
            audit.append("remediation.direct-retest-compensation-failed", {
              remediationId,
              requestId,
              parentRunId: bindingInput.parentRunId,
              retestRunId: bindingInput.retestRunId,
              approvalId: bindingInput.approvalId,
              proposalId: bindingInput.proposalId,
              bindingErrorCode: "REMEDIATION_DIRECT_RETEST_BINDING_FAILED",
              compensationErrorCode: "REMEDIATION_DIRECT_RETEST_COMPENSATION_FAILED"
            });
            throw new Error("REMEDIATION_DIRECT_RETEST_COMPENSATION_FAILED");
          }
          throw bindingError;
        }
        json(response, 201, {
          ...prepared,
          binding,
          remediation: remediation.get(remediationId)
        });
        return;
      }

      const remediationRetestOutcomeMatch = pathname.match(
        /^\/api\/remediations\/([^/]+)\/retests\/outcome$/
      );
      if (request.method === "POST" && remediationRetestOutcomeMatch) {
        const body = retestOutcomeInputSchema.parse(await readJson(request));
        json(response, 200, {
          remediation: remediation.recordRetestOutcome(
            decodeURIComponent(remediationRetestOutcomeMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/reports") {
        const rows = database
          .prepare(
            `SELECT rs.id, rs.mission_id, rs.snapshot_hash, rs.template_version, rs.status, rs.frozen_at,
                    (SELECT artifact_id FROM report_outputs
                     WHERE snapshot_id = rs.id AND format = 'json') AS json_artifact_id,
                    (SELECT artifact_id FROM report_outputs
                     WHERE snapshot_id = rs.id AND format = 'html') AS html_artifact_id,
                    (SELECT id FROM report_qa_reviews
                     WHERE snapshot_id = rs.id) AS qa_review_id
             FROM report_snapshots rs ORDER BY rs.frozen_at DESC`
          )
          .all() as unknown as Array<Record<string, unknown> & { qa_review_id: string | null }>;
        json(response, 200, {
          reports: rows.map(({ qa_review_id: qaReviewId, ...row }) => ({
            ...row,
            qa: qaReviewId ? reportQa.get(qaReviewId) : null,
            exportBundle: reportExports.forSnapshot(String(row.id))
          }))
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/test-plans") {
        if (
          url.searchParams.getAll("missionId").length !== 1 ||
          url.searchParams.getAll("limit").length > 1
        ) {
          throw new Error("SCHEMA_INVALID");
        }
        const query = testPlanListQuerySchema.parse(
          Object.fromEntries(url.searchParams.entries())
        );
        json(response, 200, {
          plans: testPlans.list(query.missionId, query.limit)
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/test-plans") {
        const body = createTestPlanRequestSchema.parse(await readJson(request));
        json(response, 201, {
          plan: testPlans.createVersion({
            ...body,
            createdBy: authenticated!.operator
          })
        });
        return;
      }

      const testPlanMatch = pathname.match(/^\/api\/test-plans\/([^/]+)$/);
      if (request.method === "GET" && testPlanMatch) {
        json(response, 200, {
          plan: testPlans.get(decodeURIComponent(testPlanMatch[1]!))
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/comparisons/original-retest") {
        const body = runComparisonSchema.parse(await readJson(request));
        json(response, 200, {
          comparison: comparisonSearch.compare(body)
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/search") {
        const body = missionSearchInputSchema.parse(await readJson(request));
        json(response, 200, {
          search: comparisonSearch.search(body)
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/report-qa") {
        if (url.searchParams.getAll("missionId").length > 1) throw new Error("SCHEMA_INVALID");
        const query = missionQuerySchema.parse(Object.fromEntries(url.searchParams.entries()));
        json(response, 200, { reviews: reportQa.list(query.missionId) });
        return;
      }
      if (request.method === "POST" && pathname === "/api/reports/freeze") {
        const body = freezeReportSchema.parse(await readJson(request));
        json(response, 201, { report: reports.freeze(body.missionId, body.templateVersion) });
        return;
      }
      const openReportQaMatch = pathname.match(/^\/api\/reports\/([^/]+)\/qa\/open$/);
      if (request.method === "POST" && openReportQaMatch) {
        reviewerSchema.parse(await readJson(request));
        json(response, 201, {
          review: reportQa.open(
            decodeURIComponent(openReportQaMatch[1]!),
            authenticated!.operator
          )
        });
        return;
      }
      const reportQaMatch = pathname.match(/^\/api\/report-qa\/([^/]+)$/);
      if (request.method === "GET" && reportQaMatch) {
        json(response, 200, {
          review: reportQa.get(decodeURIComponent(reportQaMatch[1]!))
        });
        return;
      }
      const approveReportQaMatch = pathname.match(/^\/api\/report-qa\/([^/]+)\/approve$/);
      if (request.method === "POST" && approveReportQaMatch) {
        const body = approveReportQaInputSchema.parse(await readJson(request));
        json(response, 200, {
          review: reportQa.approve(
            decodeURIComponent(approveReportQaMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }
      const requestReportQaChangesMatch = pathname.match(
        /^\/api\/report-qa\/([^/]+)\/request-changes$/
      );
      if (request.method === "POST" && requestReportQaChangesMatch) {
        const body = requestReportQaChangesInputSchema.parse(await readJson(request));
        json(response, 200, {
          review: reportQa.requestChanges(
            decodeURIComponent(requestReportQaChangesMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }
      const generateReportExportMatch = pathname.match(
        /^\/api\/reports\/([^/]+)\/exports\/generate$/
      );
      if (request.method === "POST" && generateReportExportMatch) {
        reviewerSchema.parse(await readJson(request));
        json(response, 201, {
          bundle: await reportExports.generate(
            decodeURIComponent(generateReportExportMatch[1]!),
            authenticated!.operator
          )
        });
        return;
      }
      const reportExportMatch = pathname.match(/^\/api\/report-exports\/([^/]+)$/);
      if (request.method === "GET" && reportExportMatch) {
        json(response, 200, {
          bundle: reportExports.get(decodeURIComponent(reportExportMatch[1]!))
        });
        return;
      }
      const approveReportExportMatch = pathname.match(
        /^\/api\/report-exports\/([^/]+)\/approve$/
      );
      if (request.method === "POST" && approveReportExportMatch) {
        const body = approveReportExportInputSchema.parse(await readJson(request));
        json(response, 200, {
          bundle: reportExports.approve(
            decodeURIComponent(approveReportExportMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }
      const requestReportExportChangesMatch = pathname.match(
        /^\/api\/report-exports\/([^/]+)\/request-changes$/
      );
      if (request.method === "POST" && requestReportExportChangesMatch) {
        const body = requestReportExportChangesInputSchema.parse(await readJson(request));
        json(response, 200, {
          bundle: reportExports.requestChanges(
            decodeURIComponent(requestReportExportChangesMatch[1]!),
            body,
            authenticated!.operator
          )
        });
        return;
      }
      const reportExportOutputMatch = pathname.match(
        /^\/api\/report-exports\/([^/]+)\/outputs\/(pdf|docx)$/
      );
      if (request.method === "GET" && reportExportOutputMatch) {
        const unknownQuery = [...url.searchParams.keys()].some((key) => key !== "download");
        const download = url.searchParams.get("download");
        if (unknownQuery || (download !== null && download !== "1")) {
          throw new Error("SCHEMA_INVALID");
        }
        const bundleId = decodeURIComponent(reportExportOutputMatch[1]!);
        const format = reportExportOutputMatch[2]!;
        const output = reportExports.output(bundleId, format);
        const disposition = download === "1" ? "attachment" : "inline";
        response.writeHead(200, {
          "Content-Type": output.mediaType,
          "Content-Length": String(output.bytes.byteLength),
          "Content-Disposition": `${disposition}; filename="war-room-${output.artifactId}.${format}"`
        });
        response.end(output.bytes);
        return;
      }
      const reportOutputMatch = pathname.match(/^\/api\/reports\/([^/]+)\/outputs\/(json|html)$/);
      if (request.method === "GET" && reportOutputMatch) {
        const unknownQuery = [...url.searchParams.keys()].some((key) => key !== "download");
        const download = url.searchParams.get("download");
        if (unknownQuery || (download !== null && download !== "1")) throw new Error("SCHEMA_INVALID");
        const snapshotId = decodeURIComponent(reportOutputMatch[1]!);
        const format = reportOutputMatch[2] as "json" | "html";
        const output = reports.output(snapshotId, format);
        const extension = format === "json" ? "json" : "html";
        const disposition = download === "1" ? "attachment" : "inline";
        response.writeHead(200, {
          "Content-Type": `${output.mediaType}; charset=utf-8`,
          "Content-Length": String(output.bytes.byteLength),
          "Content-Disposition": `${disposition}; filename="war-room-${output.artifactId}.${extension}"`
        });
        response.end(output.bytes);
        return;
      }
      const generateReportMatch = pathname.match(/^\/api\/reports\/([^/]+)\/generate$/);
      if (request.method === "POST" && generateReportMatch) {
        reportGenerationSchema.parse(await readJson(request));
        const snapshotId = decodeURIComponent(generateReportMatch[1]!);
        json(response, 200, { outputs: reports.generate(snapshotId) });
        return;
      }

      if (request.method === "GET" && pathname === "/api/system/audit") {
        const head = database
          .prepare("SELECT sequence, occurred_at, event_type, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 100")
          .all();
        json(response, 200, { verification: audit.verify(), events: head });
        return;
      }

      if (request.method === "GET" && pathname === "/api/system/diagnostics") {
        json(response, 200, { diagnostics: supportDiagnostics.collect() });
        return;
      }

      if (request.method === "GET" && pathname === "/api/system/model") {
        json(response, 200, {
          health: await model.health(),
          capabilities: modelProvider.capabilities(),
          invocations: model.listInvocations()
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/system/executor") {
        const status = versionExecution
          ? await versionExecution.status()
          : {
              available: false,
              versionProofEnabled: false,
              executionEnabled: false,
              binaryHashVerified: false,
              configHashVerified: false
            };
        json(response, 200, {
          available: status.available,
          versionProofEnabled: status.versionProofEnabled,
          capabilityId: MCPWN_VERSION_CAPABILITY,
          activeExecutions: versionExecution?.activeCount() ?? 0,
          activeTargetExecutions: targetExecution?.activeCount() ?? 0,
          targetExecutionEnabled: Boolean(targetExecution),
          lifecycle: lifecycles.summary(),
          startupOrphansRecovered: recoveredExecutions.length,
          status
        });
        return;
      }

      if (request.method === "GET" && pathname === "/api/system/executions") {
        json(response, 200, {
          summary: lifecycles.summary(),
          executions: lifecycles.list()
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/executor/version") {
        versionExecutionSchema.parse(await readJson(request));
        if (!versionExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        json(response, 201, await versionExecution.execute(authenticated!.operator));
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/service-version/execute") {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = targetExecutionSchema.parse(await readJson(request));
        json(response, 201, { execution: await targetExecution.execute(body.approvalId, authenticated!.operator) });
        return;
      }

      if (request.method === "POST" && pathname === "/api/target/execute") {
        if (!targetExecution) throw new Error("EXECUTOR_UNAVAILABLE");
        const body = targetExecutionSchema.parse(await readJson(request));
        json(response, 201, { execution: await targetExecution.execute(body.approvalId, authenticated!.operator) });
        return;
      }

      if (request.method === "POST" && pathname === "/api/model/plan") {
        controls.assertReady();
        const body = modelPlanSchema.parse(await readJson(request));
        const requestId = randomUUID();
        const controller = new AbortController();
        activeModelRequests.set(requestId, controller);
        try {
          controls.assertReady();
          json(response, 201, await model.createPlan({ ...body, signal: controller.signal }));
        } finally {
          activeModelRequests.delete(requestId);
        }
        return;
      }

      if (request.method === "GET" && !pathname.startsWith("/api/") && options.webRoot && serveStatic(options.webRoot, pathname, response)) {
        return;
      }

      json(response, 404, { error: "not_found" });
    } catch (error) {
      const failure = publicError(error);
      json(response, failure.status, { error: failure.code });
    }
  });
  server.on("close", () => database.close());
  return server;
}

export function startServer(options: ServerOptions = {}) {
  const configuredSecret = options.bootstrapSecret ?? process.env.WAR_ROOM_OPERATOR_BOOTSTRAP;
  const bootstrapSecret = configuredSecret ?? OperatorSessionService.generateBootstrapSecret();
  if (!configuredSecret) {
    console.warn(`WAR-R00M per-launch operator bootstrap secret: ${bootstrapSecret}`);
  }
  return buildServer({ ...options, bootstrapSecret }).listen(port, host, () => {
    console.log(`WAR-R00M listening on http://${host}:${port}`);
  });
}
