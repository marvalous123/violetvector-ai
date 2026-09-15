import type { DatabaseSync } from "node:sqlite";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";

const COUNTED_TABLES = [
  ["missions", "missions"],
  ["runs", "runs"],
  ["artifacts", "evidenceArtifacts"],
  ["findings", "findings"],
  ["report_snapshots", "reportSnapshots"],
  ["endpoint_identities", "endpointIdentities"],
  ["endpoint_identity_renewals", "endpointIdentityRenewals"],
  ["endpoint_fact_batches", "endpointFactBatches"],
  ["endpoint_live_correlation_runs", "liveCorrelationRuns"],
  ["engagement_test_plans", "testPlans"]
] as const;
const MAX_EVIDENCE_FILES = 500;
const MAX_EVIDENCE_BYTES = 32 * 1024 * 1024;

export interface SupportDiagnostics {
  readonly generatedAt: string;
  readonly product: {
    readonly name: "VioletVector AI";
    readonly version: "0.1.0";
    readonly edition: "starter" | "professional";
  };
  readonly runtime: {
    readonly node: string;
    readonly platform: string;
    readonly architecture: string;
    readonly loopbackOnly: true;
  };
  readonly integrity: {
    readonly databaseQuickCheck: boolean;
    readonly audit: ReturnType<AuditService["verify"]>;
    readonly evidenceTotal: number;
    readonly evidenceChecked: number;
    readonly evidenceValid: number;
    readonly evidenceInvalid: number;
    readonly evidenceComplete: boolean;
  };
  readonly records: Readonly<Record<string, number>>;
  readonly storage: {
    readonly databaseConfigured: boolean;
    readonly evidenceStoreConfigured: boolean;
    readonly pathsDisclosed: false;
  };
  readonly safeToShare: true;
  readonly limitations: readonly string[];
}

export class SupportDiagnosticsService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly audit: AuditService,
    private readonly evidence: EvidenceService,
    private readonly productEdition: "starter" | "professional",
    private readonly persistentStorageConfigured: boolean
  ) {}

  collect(now = new Date()): SupportDiagnostics {
    const quickCheck = this.database.prepare("PRAGMA quick_check").get() as Record<string, unknown>;
    const databaseQuickCheck = Object.values(quickCheck).some((value) => value === "ok");
    const evidenceTotal = (
      this.database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number }
    ).count;
    const artifacts = this.database
      .prepare("SELECT id, size_bytes FROM artifacts ORDER BY id LIMIT ?")
      .all(MAX_EVIDENCE_FILES) as unknown as Array<{ id: string; size_bytes: number }>;
    let evidenceValid = 0;
    let evidenceChecked = 0;
    let evidenceBytes = 0;
    for (const artifact of artifacts) {
      if (artifact.size_bytes < 0 || evidenceBytes + artifact.size_bytes > MAX_EVIDENCE_BYTES) break;
      evidenceBytes += artifact.size_bytes;
      evidenceChecked += 1;
      if (this.evidence.verify(artifact.id)) evidenceValid += 1;
    }
    const records: Record<string, number> = {};
    for (const [table, label] of COUNTED_TABLES) {
      const row = this.database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number };
      records[label] = row.count;
    }
    return {
      generatedAt: now.toISOString(),
      product: {
        name: "VioletVector AI",
        version: "0.1.0",
        edition: this.productEdition
      },
      runtime: {
        node: process.versions.node,
        platform: process.platform,
        architecture: process.arch,
        loopbackOnly: true
      },
      integrity: {
        databaseQuickCheck,
        audit: this.audit.verify(),
        evidenceTotal,
        evidenceChecked,
        evidenceValid,
        evidenceInvalid: evidenceChecked - evidenceValid,
        evidenceComplete: evidenceChecked === evidenceTotal
      },
      records,
      storage: {
        databaseConfigured: this.persistentStorageConfigured,
        evidenceStoreConfigured: this.persistentStorageConfigured,
        pathsDisclosed: false
      },
      safeToShare: true,
      limitations: [
        "This redacted snapshot contains counts and integrity state, not secrets, target addresses, evidence content or filesystem paths.",
        `Evidence verification is capped at ${MAX_EVIDENCE_FILES} files and ${MAX_EVIDENCE_BYTES} bytes per request; larger stores are reported as partial.`,
        "A healthy snapshot does not prove that an assessed target is secure."
      ]
    };
  }
}
