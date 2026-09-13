import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash } from "../domain/stable-json.js";
import type { EvidenceService } from "./evidence-service.js";
import { RemediationService, type RetestOutcome } from "./remediation-service.js";

const comparisonInputSchema = z
  .object({
    missionId: z.string().uuid(),
    originalRunId: z.string().uuid(),
    retestRunId: z.string().uuid()
  })
  .strict();

const searchKindSchema = z.enum(["test-plan", "procedure", "run", "evidence", "finding", "remediation"]);
export const missionSearchInputSchema = z
  .object({
    missionId: z.string().uuid(),
    query: z.string().trim().min(2).max(80),
    kinds: z.array(searchKindSchema).min(1).max(6).optional(),
    limit: z.number().int().min(1).max(50).default(25)
  })
  .strict();

interface RunRow {
  id: string;
  mission_id: string;
  parent_run_id: string | null;
  lineage_type: "original" | "replay" | "retest" | null;
  status: string;
  created_at: string;
  updated_at: string;
  capability_id: string | null;
  proposal_hash: string | null;
  proposal_json: string | null;
  target_id: string | null;
  risk_tier: string | null;
}

interface RunEvidence {
  readonly artifactId: string;
  readonly observationId: string;
  readonly sha256: string;
  readonly capturedAt: string;
  readonly integrityValid: boolean;
}

interface FindingRow {
  id: string;
  title: string;
  status: string;
}

export interface RunComparisonFinding {
  readonly findingId: string;
  readonly title: string;
  readonly currentStatus: string;
  readonly originalEvidencePresent: boolean;
  readonly retestEvidencePresent: boolean;
  readonly assessment:
    | "explicit-remediated"
    | "explicit-persists"
    | "explicit-regressed"
    | "explicit-inconclusive"
    | "observed-in-both"
    | "original-only-not-assessed"
    | "retest-only-observation";
  readonly explicitOutcome: RetestOutcome | null;
  readonly explicitOutcomeSummary: string | null;
  readonly supportingRetestArtifactIds: readonly string[];
}

export interface OriginalRetestComparison {
  readonly missionId: string;
  readonly original: {
    readonly runId: string;
    readonly status: string;
    readonly capabilityId: string | null;
    readonly proposalHash: string | null;
    readonly proposalIntegrityValid: boolean;
    readonly evidence: readonly RunEvidence[];
  };
  readonly retest: {
    readonly runId: string;
    readonly parentRunId: string;
    readonly status: string;
    readonly capabilityId: string | null;
    readonly proposalHash: string | null;
    readonly proposalIntegrityValid: boolean;
    readonly evidence: readonly RunEvidence[];
  };
  readonly configurationEquivalent: boolean;
  readonly evidenceHashComparison: {
    readonly shared: readonly string[];
    readonly originalOnly: readonly string[];
    readonly retestOnly: readonly string[];
  };
  readonly findings: readonly RunComparisonFinding[];
  readonly claimLimitation: string;
}

export interface MissionSearchResult {
  readonly kind: z.infer<typeof searchKindSchema>;
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly status: string | null;
  readonly occurredAt: string;
}

export interface MissionSearchResponse {
  readonly missionId: string;
  readonly query: string;
  readonly limit: number;
  readonly returned: number;
  readonly truncated: boolean;
  readonly results: readonly MissionSearchResult[];
}

const allSearchKinds = searchKindSchema.options;

function proposalConfigurationHash(row: RunRow): string | null {
  if (!row.proposal_json) return null;
  try {
    const parsed = JSON.parse(row.proposal_json) as Record<string, unknown>;
    const configuration = { ...parsed };
    delete configuration.proposalId;
    delete configuration.runId;
    return canonicalHash(configuration);
  } catch {
    return null;
  }
}

function proposalIntegrityValid(row: RunRow): boolean {
  if (!row.proposal_json || !row.proposal_hash) return false;
  try {
    return canonicalHash(JSON.parse(row.proposal_json)) === row.proposal_hash;
  } catch {
    return false;
  }
}

function escapeLike(value: string): string {
  return value.replaceAll("!", "!!").replaceAll("%", "!%").replaceAll("_", "!_");
}

export class MissionComparisonSearchService {
  private readonly remediation: RemediationService;

  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    remediation?: RemediationService
  ) {
    this.remediation = remediation ?? new RemediationService(database, evidence);
  }

  compare(inputValue: z.input<typeof comparisonInputSchema>, now = new Date()): OriginalRetestComparison {
    const input = comparisonInputSchema.parse(inputValue);
    this.assertMission(input.missionId);
    if (input.originalRunId === input.retestRunId) throw new Error("COMPARISON_RUNS_MUST_DIFFER");
    const original = this.getRun(input.originalRunId, input.missionId);
    const retest = this.getRun(input.retestRunId, input.missionId);
    if (retest.lineage_type !== "retest" || retest.parent_run_id !== original.id) {
      throw new Error("COMPARISON_RETEST_LINEAGE_INVALID");
    }
    const originalEvidence = this.runEvidence(original.id, input.missionId);
    const retestEvidence = this.runEvidence(retest.id, input.missionId);
    const originalHashes = new Set(
      originalEvidence.filter((item) => item.integrityValid).map((item) => item.sha256)
    );
    const retestHashes = new Set(
      retestEvidence.filter((item) => item.integrityValid).map((item) => item.sha256)
    );
    const shared = [...originalHashes].filter((hash) => retestHashes.has(hash)).sort();
    const originalOnly = [...originalHashes].filter((hash) => !retestHashes.has(hash)).sort();
    const retestOnly = [...retestHashes].filter((hash) => !originalHashes.has(hash)).sort();

    const originalFindings = this.findingsForRun(original.id, input.missionId);
    const retestFindings = this.findingsForRun(retest.id, input.missionId);
    const findingIds = new Set([...originalFindings.keys(), ...retestFindings.keys()]);
    const findings = [...findingIds]
      .sort()
      .map((findingId): RunComparisonFinding => {
        const finding = originalFindings.get(findingId) ?? retestFindings.get(findingId)!;
        const explicit = this.explicitRetestOutcome(findingId, retest.id, now);
        const originalEvidencePresent = originalFindings.has(findingId);
        const retestEvidencePresent = retestFindings.has(findingId);
        let assessment: RunComparisonFinding["assessment"];
        if (explicit) assessment = `explicit-${explicit.outcome}` as RunComparisonFinding["assessment"];
        else if (originalEvidencePresent && retestEvidencePresent) assessment = "observed-in-both";
        else if (originalEvidencePresent) assessment = "original-only-not-assessed";
        else assessment = "retest-only-observation";
        return {
          findingId,
          title: finding.title,
          currentStatus: finding.status,
          originalEvidencePresent,
          retestEvidencePresent,
          assessment,
          explicitOutcome: explicit?.outcome ?? null,
          explicitOutcomeSummary: explicit?.summary ?? null,
          supportingRetestArtifactIds: explicit?.artifactIds ?? []
        };
      });

    return {
      missionId: input.missionId,
      original: {
        runId: original.id,
        status: original.status,
        capabilityId: original.capability_id,
        proposalHash: original.proposal_hash,
        proposalIntegrityValid: proposalIntegrityValid(original),
        evidence: originalEvidence
      },
      retest: {
        runId: retest.id,
        parentRunId: original.id,
        status: retest.status,
        capabilityId: retest.capability_id,
        proposalHash: retest.proposal_hash,
        proposalIntegrityValid: proposalIntegrityValid(retest),
        evidence: retestEvidence
      },
      configurationEquivalent:
        original.capability_id !== null &&
        original.capability_id === retest.capability_id &&
        proposalConfigurationHash(original) !== null &&
        proposalConfigurationHash(original) === proposalConfigurationHash(retest),
      evidenceHashComparison: { shared, originalOnly, retestOnly },
      findings,
      claimLimitation:
        "This comparison describes stored run lineage, verified evidence hashes and explicit reviewed remediation outcomes. A missing finding, empty result or successful run does not establish that the target is secure or that remediation succeeded."
    };
  }

  search(inputValue: z.input<typeof missionSearchInputSchema>): MissionSearchResponse {
    const input = missionSearchInputSchema.parse(inputValue);
    this.assertMission(input.missionId);
    const kinds = new Set(input.kinds ?? allSearchKinds);
    const pattern = `%${escapeLike(input.query.toLowerCase())}%`;
    const candidates: MissionSearchResult[] = [];
    const candidateLimit = Math.min(input.limit + 1, 51);

    if (kinds.has("test-plan")) {
      const rows = this.database
        .prepare(
          `SELECT id, title, objective, version, created_at
           FROM engagement_test_plans
           WHERE mission_id = ?
             AND (lower(title) LIKE ? ESCAPE '!' OR lower(objective) LIKE ? ESCAPE '!')
           ORDER BY version DESC LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          title: string;
          objective: string;
          version: number;
          created_at: string;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "test-plan" as const,
          id: row.id,
          title: row.title,
          detail: row.objective,
          status: `version-${row.version}`,
          occurredAt: row.created_at
        }))
      );
    }

    if (kinds.has("procedure")) {
      const rows = this.database
        .prepare(
          `SELECT procedure.id, procedure.title, procedure.objective, procedure.rationale,
                  procedure.state, procedure.created_at
           FROM test_plan_procedures procedure
           JOIN engagement_test_plans plan ON plan.id = procedure.plan_id
           WHERE plan.mission_id = ?
             AND (
               lower(procedure.procedure_key) LIKE ? ESCAPE '!'
               OR lower(procedure.title) LIKE ? ESCAPE '!'
               OR lower(procedure.objective) LIKE ? ESCAPE '!'
               OR lower(procedure.rationale) LIKE ? ESCAPE '!'
             )
           ORDER BY plan.version DESC, procedure.ordinal LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          title: string;
          objective: string;
          rationale: string;
          state: string;
          created_at: string;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "procedure" as const,
          id: row.id,
          title: row.title,
          detail: `${row.objective} Rationale: ${row.rationale}`,
          status: row.state,
          occurredAt: row.created_at
        }))
      );
    }

    if (kinds.has("run")) {
      const rows = this.database
        .prepare(
          `SELECT run.id, run.status, run.created_at, proposal.capability_id
           FROM runs run
           LEFT JOIN proposals proposal ON proposal.run_id = run.id
           WHERE run.mission_id = ?
             AND (
               lower(run.id) LIKE ? ESCAPE '!'
               OR lower(run.status) LIKE ? ESCAPE '!'
               OR lower(COALESCE(proposal.capability_id, '')) LIKE ? ESCAPE '!'
             )
           ORDER BY run.created_at DESC LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          status: string;
          created_at: string;
          capability_id: string | null;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "run" as const,
          id: row.id,
          title: row.capability_id ?? "Mission run",
          detail: `Stored run ${row.id}`,
          status: row.status,
          occurredAt: row.created_at
        }))
      );
    }

    if (kinds.has("evidence")) {
      const rows = this.database
        .prepare(
          `SELECT DISTINCT artifact.id, artifact.sha256, artifact.media_type,
                  observation.recorded_at
           FROM evidence_observations observation
           JOIN artifacts artifact ON artifact.id = observation.artifact_id
           WHERE observation.mission_id = ?
             AND (
               lower(artifact.sha256) LIKE ? ESCAPE '!'
               OR lower(artifact.media_type) LIKE ? ESCAPE '!'
             )
           ORDER BY observation.recorded_at DESC LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          sha256: string;
          media_type: string;
          recorded_at: string;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "evidence" as const,
          id: row.id,
          title: row.sha256,
          detail: row.media_type,
          status: this.evidence.verify(row.id) ? "verified" : "integrity-failed",
          occurredAt: row.recorded_at
        }))
      );
    }

    if (kinds.has("finding")) {
      const rows = this.database
        .prepare(
          `SELECT finding.id, finding.title, finding.status, finding.updated_at,
                  revision.description, revision.remediation
           FROM findings finding
           LEFT JOIN finding_revisions revision ON revision.id = (
             SELECT id FROM finding_revisions
             WHERE finding_id = finding.id ORDER BY revision DESC LIMIT 1
           )
           WHERE finding.mission_id = ?
             AND (
               lower(finding.title) LIKE ? ESCAPE '!'
               OR lower(COALESCE(revision.description, '')) LIKE ? ESCAPE '!'
               OR lower(COALESCE(revision.remediation, '')) LIKE ? ESCAPE '!'
             )
           ORDER BY finding.updated_at DESC LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          title: string;
          status: string;
          updated_at: string;
          description: string | null;
          remediation: string | null;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "finding" as const,
          id: row.id,
          title: row.title,
          detail: row.description ?? "No accepted description.",
          status: row.status,
          occurredAt: row.updated_at
        }))
      );
    }

    if (kinds.has("remediation")) {
      const rows = this.database
        .prepare(
          `SELECT remediation.id, remediation.created_at, finding.title, finding.status
           FROM remediation_records remediation
           JOIN findings finding ON finding.id = remediation.finding_id
           WHERE remediation.mission_id = ?
             AND (
               lower(remediation.id) LIKE ? ESCAPE '!'
               OR lower(finding.title) LIKE ? ESCAPE '!'
               OR lower(finding.status) LIKE ? ESCAPE '!'
             )
           ORDER BY remediation.created_at DESC LIMIT ?`
        )
        .all(input.missionId, pattern, pattern, pattern, candidateLimit) as unknown as Array<{
          id: string;
          created_at: string;
          title: string;
          status: string;
        }>;
      candidates.push(
        ...rows.map((row) => ({
          kind: "remediation" as const,
          id: row.id,
          title: row.title,
          detail: "Immutable remediation workflow record",
          status: row.status,
          occurredAt: row.created_at
        }))
      );
    }

    candidates.sort(
      (left, right) =>
        right.occurredAt.localeCompare(left.occurredAt) ||
        left.kind.localeCompare(right.kind) ||
        left.id.localeCompare(right.id)
    );
    const truncated = candidates.length > input.limit;
    const results = candidates.slice(0, input.limit);
    return {
      missionId: input.missionId,
      query: input.query,
      limit: input.limit,
      returned: results.length,
      truncated,
      results
    };
  }

  private assertMission(missionId: string): void {
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
  }

  private getRun(runId: string, missionId: string): RunRow {
    const row = this.database
      .prepare(
        `SELECT run.*, proposal.capability_id, proposal.proposal_hash,
                proposal.proposal_json, proposal.target_id, proposal.risk_tier
         FROM runs run
         LEFT JOIN proposals proposal ON proposal.id = (
           SELECT id FROM proposals WHERE run_id = run.id ORDER BY created_at DESC LIMIT 1
         )
         WHERE run.id = ?`
      )
      .get(runId) as unknown as RunRow | undefined;
    if (!row) throw new Error("COMPARISON_RUN_NOT_FOUND");
    if (row.mission_id !== missionId) throw new Error("COMPARISON_RUN_MISSION_MISMATCH");
    return row;
  }

  private runEvidence(runId: string, missionId: string): RunEvidence[] {
    const rows = this.database
      .prepare(
        `SELECT observation.id AS observation_id, observation.artifact_id,
                observation.captured_at, artifact.sha256
         FROM evidence_observations observation
         JOIN artifacts artifact ON artifact.id = observation.artifact_id
         WHERE observation.run_id = ? AND observation.mission_id = ?
         ORDER BY observation.recorded_at, observation.id
         LIMIT 500`
      )
      .all(runId, missionId) as unknown as Array<{
        observation_id: string;
        artifact_id: string;
        captured_at: string;
        sha256: string;
      }>;
    return rows.map((row) => ({
      artifactId: row.artifact_id,
      observationId: row.observation_id,
      sha256: row.sha256,
      capturedAt: row.captured_at,
      integrityValid:
        this.evidence.verify(row.artifact_id) &&
        this.evidence.verifyObservation(row.observation_id, row.artifact_id, missionId)
    }));
  }

  private findingsForRun(runId: string, missionId: string): Map<string, FindingRow> {
    const rows = this.database
      .prepare(
        `SELECT finding.id, finding.title, finding.status,
                citation.artifact_id, citation.observation_id
         FROM findings finding
         JOIN finding_revisions revision ON revision.finding_id = finding.id
         JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
         JOIN evidence_observations observation
           ON observation.id = citation.observation_id
          AND observation.artifact_id = citation.artifact_id
         WHERE finding.mission_id = ?
           AND observation.mission_id = ?
           AND observation.run_id = ?
         ORDER BY finding.id, citation.artifact_id
         LIMIT 500`
      )
      .all(missionId, missionId, runId) as unknown as Array<
        FindingRow & { artifact_id: string; observation_id: string }
      >;
    const verified = rows.filter(
      (row) =>
        this.evidence.verify(row.artifact_id) &&
        this.evidence.verifyObservation(row.observation_id, row.artifact_id, missionId)
    );
    return new Map(verified.map((row) => [row.id, { id: row.id, title: row.title, status: row.status }]));
  }

  private explicitRetestOutcome(
    findingId: string,
    retestRunId: string,
    now: Date
  ): { outcome: RetestOutcome; summary: string; artifactIds: string[] } | null {
    let remediation;
    try {
      remediation = this.remediation.getForFinding(findingId, now);
    } catch (error) {
      if (error instanceof Error && error.message === "REMEDIATION_NOT_FOUND") return null;
      throw error;
    }
    const matching = remediation.retests.filter(
      (retest) =>
        retest.outcome &&
        retest.evidence.some((reference) => {
          const row = this.database
            .prepare(
              `SELECT run_id FROM evidence_observations
               WHERE id = ? AND artifact_id = ? AND mission_id = ?`
            )
            .get(reference.observationId, reference.artifactId, remediation.missionId) as
            | { run_id: string | null }
            | undefined;
          return row?.run_id === retestRunId;
        })
    );
    const latest = matching.at(-1);
    if (!latest?.outcome || !latest.summary) return null;
    return {
      outcome: latest.outcome,
      summary: latest.summary,
      artifactIds: latest.evidence.map((reference) => reference.artifactId).sort()
    };
  }
}
