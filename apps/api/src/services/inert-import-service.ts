import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { TextDecoder } from "node:util";
import { canonicalHash, sha256, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceObservationRow, EvidenceService } from "./evidence-service.js";

export const INERT_SARIF_PARSER_ID = "sarif-2.1.0-inert" as const;
export const INERT_SARIF_PARSER_VERSION = "1.0.0" as const;
export const INERT_SARIF_LIMITS = Object.freeze({
  maxBytes: 2 * 1024 * 1024,
  maxRuns: 16,
  maxResults: 500,
  maxRulesPerRun: 1_000,
  maxLocationsPerResult: 32,
  maxMessageCharacters: 32_768,
  maxUriCharacters: 4_096
});

type JsonRecord = Record<string, unknown>;
type SarifLevel = "none" | "note" | "warning" | "error";
type SarifKind = "fail" | "pass" | "review" | "open" | "notApplicable" | "informational";
type SarifBaselineState = "new" | "unchanged" | "updated" | "absent";

interface CandidateKey {
  readonly schemaVersion: 1;
  readonly parserId: typeof INERT_SARIF_PARSER_ID;
  readonly parserVersion: typeof INERT_SARIF_PARSER_VERSION;
  readonly toolName: string;
  readonly ruleId: string;
  readonly kind: SarifKind;
  readonly location: {
    readonly uriHash: string | null;
    readonly startLine: number | null;
    readonly startColumn: number | null;
  };
  readonly locationlessNarrativeHash: string | null;
}

export interface NormalizedImportObservation {
  readonly schemaVersion: 1;
  readonly verification: "unverified";
  readonly parser: {
    readonly id: typeof INERT_SARIF_PARSER_ID;
    readonly version: typeof INERT_SARIF_PARSER_VERSION;
  };
  readonly source: {
    readonly sourceArtifactSha256: string;
    readonly runIndex: number;
    readonly resultIndex: number;
  };
  readonly toolName: string;
  readonly ruleId: string;
  readonly level: SarifLevel;
  readonly kind: SarifKind;
  readonly baselineState: SarifBaselineState | null;
  readonly location: {
    readonly uriHash: string | null;
    readonly startLine: number | null;
    readonly startColumn: number | null;
  };
  readonly narrativeHash: string;
  readonly contentBoundary: {
    readonly originalRetainedAsEvidence: true;
    readonly narrativeNotNormalized: true;
    readonly locationNotResolved: true;
    readonly embeddedContentNotExecuted: true;
  };
}

interface ParsedObservation {
  readonly runIndex: number;
  readonly resultIndex: number;
  readonly fingerprint: string;
  readonly candidateKey: CandidateKey;
  readonly normalized: NormalizedImportObservation;
}

interface ParsedSarif {
  readonly observations: ParsedObservation[];
  readonly resultCount: number;
  readonly candidateCount: number;
}

interface ImportRow {
  id: string;
  mission_id: string;
  parent_import_id: string | null;
  source_artifact_id: string;
  source_observation_id: string;
  source_sha256: string;
  source_size_bytes: number;
  source_media_type: string;
  parser_id: string;
  parser_version: string;
  result_count: number;
  candidate_count: number;
  import_manifest_json: string;
  import_manifest_hash: string;
  imported_by: string;
  imported_at: string;
}

interface CandidateRow {
  id: string;
  mission_id: string;
  fingerprint: string;
  normalized_key_json: string;
  normalized_key_hash: string;
  status: "unverified";
  first_seen_import_id: string;
  created_at: string;
}

interface ObservationRow {
  id: string;
  import_id: string;
  candidate_id: string;
  mission_id: string;
  source_artifact_id: string;
  source_observation_id: string;
  run_index: number;
  result_index: number;
  normalized_json: string;
  normalized_hash: string;
  observed_at: string;
}

export interface InertImportRecord {
  readonly id: string;
  readonly missionId: string;
  readonly parentImportId: string | null;
  readonly sourceArtifactId: string;
  readonly sourceObservationId: string;
  readonly sourceSha256: string;
  readonly sourceSizeBytes: number;
  readonly parserId: typeof INERT_SARIF_PARSER_ID;
  readonly parserVersion: typeof INERT_SARIF_PARSER_VERSION;
  readonly resultCount: number;
  readonly candidateCount: number;
  readonly importedBy: string;
  readonly importedAt: string;
  readonly integrityValid: boolean;
}

export interface InertCandidateObservation {
  readonly id: string;
  readonly importId: string;
  readonly candidateId: string;
  readonly missionId: string;
  readonly fingerprint: string;
  readonly runIndex: number;
  readonly resultIndex: number;
  readonly normalized: NormalizedImportObservation;
  readonly integrityValid: boolean;
}

export interface ImportSarifOptions {
  readonly operator: string;
  readonly parentImportId?: string;
}

function record(value: unknown, errorCode: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(errorCode);
  return value as JsonRecord;
}

function boundedString(value: unknown, max: number, errorCode: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) throw new Error(errorCode);
  return value;
}

function optionalArray(value: unknown, max: number, errorCode: string): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max) throw new Error(errorCode);
  return value;
}

function optionalEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  fallback: T,
  errorCode: string
): T {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !allowed.includes(value as T)) throw new Error(errorCode);
  return value as T;
}

function optionalPositiveInteger(value: unknown, errorCode: string): number | null {
  if (value === undefined) return null;
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 10_000_000) {
    throw new Error(errorCode);
  }
  return value as number;
}

function safeMetadata(value: string, kind: "tool" | "rule"): string {
  const max = kind === "tool" ? 128 : 160;
  const pattern =
    kind === "tool"
      ? /^[A-Za-z0-9][A-Za-z0-9 ._+:/@()-]{0,127}$/
      : /^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,159}$/;
  const trimmed = value.trim();
  if (
    trimmed.length >= 1 &&
    trimmed.length <= max &&
    pattern.test(trimmed) &&
    !trimmed.includes("://")
  ) {
    return trimmed;
  }
  return `untrusted-${kind}-${sha256(value).slice(0, 32)}`;
}

function decodeJson(bytes: Buffer): unknown {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("SARIF_UTF8_INVALID");
  }
  const json = decoded.charCodeAt(0) === 0xfeff ? decoded.slice(1) : decoded;
  try {
    return JSON.parse(json) as unknown;
  } catch {
    throw new Error("SARIF_JSON_INVALID");
  }
}

function ruleIds(driver: JsonRecord): string[] {
  return optionalArray(driver.rules, INERT_SARIF_LIMITS.maxRulesPerRun, "SARIF_RULE_LIMIT_EXCEEDED").map(
    (entry) => {
      const rule = record(entry, "SARIF_RULE_INVALID");
      return safeMetadata(boundedString(rule.id, 512, "SARIF_RULE_ID_INVALID"), "rule");
    }
  );
}

function resultRuleId(result: JsonRecord, rules: readonly string[]): string {
  if (result.ruleId !== undefined) {
    return safeMetadata(boundedString(result.ruleId, 512, "SARIF_RULE_ID_INVALID"), "rule");
  }
  if (result.ruleIndex !== undefined) {
    if (!Number.isInteger(result.ruleIndex) || (result.ruleIndex as number) < 0) {
      throw new Error("SARIF_RULE_INDEX_INVALID");
    }
    const mapped = rules[result.ruleIndex as number];
    if (mapped) return mapped;
  }
  return "unmapped";
}

function resultMessageHash(result: JsonRecord): string {
  const message = record(result.message, "SARIF_MESSAGE_INVALID");
  const raw =
    typeof message.text === "string"
      ? message.text
      : typeof message.markdown === "string"
        ? message.markdown
        : null;
  if (raw === null || raw.length > INERT_SARIF_LIMITS.maxMessageCharacters) {
    throw new Error("SARIF_MESSAGE_INVALID");
  }
  return sha256(raw);
}

function resultLocation(result: JsonRecord): CandidateKey["location"] {
  const locations = optionalArray(
    result.locations,
    INERT_SARIF_LIMITS.maxLocationsPerResult,
    "SARIF_LOCATION_LIMIT_EXCEEDED"
  );
  if (locations.length === 0) return { uriHash: null, startLine: null, startColumn: null };
  const location = record(locations[0], "SARIF_LOCATION_INVALID");
  if (location.physicalLocation === undefined) {
    return { uriHash: null, startLine: null, startColumn: null };
  }
  const physical = record(location.physicalLocation, "SARIF_LOCATION_INVALID");
  let uriHash: string | null = null;
  if (physical.artifactLocation !== undefined) {
    const artifact = record(physical.artifactLocation, "SARIF_LOCATION_INVALID");
    if (artifact.uri !== undefined) {
      const uri = boundedString(
        artifact.uri,
        INERT_SARIF_LIMITS.maxUriCharacters,
        "SARIF_LOCATION_URI_INVALID"
      );
      const uriBaseId =
        artifact.uriBaseId === undefined
          ? ""
          : boundedString(artifact.uriBaseId, 256, "SARIF_LOCATION_URI_INVALID");
      uriHash = sha256(`${uriBaseId}\n${uri}`);
    }
  }
  let startLine: number | null = null;
  let startColumn: number | null = null;
  if (physical.region !== undefined) {
    const region = record(physical.region, "SARIF_LOCATION_INVALID");
    startLine = optionalPositiveInteger(region.startLine, "SARIF_LOCATION_REGION_INVALID");
    startColumn = optionalPositiveInteger(region.startColumn, "SARIF_LOCATION_REGION_INVALID");
  }
  return { uriHash, startLine, startColumn };
}

function parseSarif(bytes: Buffer, sourceArtifactSha256: string): ParsedSarif {
  const root = record(decodeJson(bytes), "SARIF_DOCUMENT_INVALID");
  if (root.version !== "2.1.0") throw new Error("SARIF_VERSION_UNSUPPORTED");
  const runs = optionalArray(root.runs, INERT_SARIF_LIMITS.maxRuns, "SARIF_RUN_LIMIT_EXCEEDED");
  if (runs.length < 1) throw new Error("SARIF_RUNS_REQUIRED");
  const observations: ParsedObservation[] = [];
  for (const [runIndex, runValue] of runs.entries()) {
    const run = record(runValue, "SARIF_RUN_INVALID");
    const tool = record(run.tool, "SARIF_TOOL_INVALID");
    const driver = record(tool.driver, "SARIF_TOOL_INVALID");
    const toolName = safeMetadata(boundedString(driver.name, 512, "SARIF_TOOL_NAME_INVALID"), "tool");
    const rules = ruleIds(driver);
    const results = optionalArray(run.results, INERT_SARIF_LIMITS.maxResults, "SARIF_RESULT_LIMIT_EXCEEDED");
    if (observations.length + results.length > INERT_SARIF_LIMITS.maxResults) {
      throw new Error("SARIF_RESULT_LIMIT_EXCEEDED");
    }
    for (const [resultIndex, resultValue] of results.entries()) {
      const result = record(resultValue, "SARIF_RESULT_INVALID");
      const ruleId = resultRuleId(result, rules);
      const level = optionalEnum(
        result.level,
        ["none", "note", "warning", "error"] as const,
        "warning",
        "SARIF_LEVEL_INVALID"
      );
      const kind = optionalEnum(
        result.kind,
        ["fail", "pass", "review", "open", "notApplicable", "informational"] as const,
        "fail",
        "SARIF_KIND_INVALID"
      );
      const baselineState =
        result.baselineState === undefined
          ? null
          : optionalEnum(
              result.baselineState,
              ["new", "unchanged", "updated", "absent"] as const,
              "new",
              "SARIF_BASELINE_STATE_INVALID"
            );
      const narrativeHash = resultMessageHash(result);
      const location = resultLocation(result);
      const candidateKey: CandidateKey = {
        schemaVersion: 1,
        parserId: INERT_SARIF_PARSER_ID,
        parserVersion: INERT_SARIF_PARSER_VERSION,
        toolName,
        ruleId,
        kind,
        location,
        locationlessNarrativeHash: location.uriHash === null ? narrativeHash : null
      };
      const normalized: NormalizedImportObservation = {
        schemaVersion: 1,
        verification: "unverified",
        parser: {
          id: INERT_SARIF_PARSER_ID,
          version: INERT_SARIF_PARSER_VERSION
        },
        source: {
          sourceArtifactSha256,
          runIndex,
          resultIndex
        },
        toolName,
        ruleId,
        level,
        kind,
        baselineState,
        location,
        narrativeHash,
        contentBoundary: {
          originalRetainedAsEvidence: true,
          narrativeNotNormalized: true,
          locationNotResolved: true,
          embeddedContentNotExecuted: true
        }
      };
      observations.push({
        runIndex,
        resultIndex,
        fingerprint: canonicalHash(candidateKey),
        candidateKey,
        normalized
      });
    }
  }
  return {
    observations,
    resultCount: observations.length,
    candidateCount: new Set(observations.map((item) => item.fingerprint)).size
  };
}

function exactNewSourceObservation(
  evidence: EvidenceService,
  artifactId: string,
  missionId: string,
  previousIds: ReadonlySet<string>
): EvidenceObservationRow {
  const added = evidence
    .observations(artifactId, missionId)
    .filter((observation) => !previousIds.has(observation.id));
  if (added.length !== 1) throw new Error("INERT_IMPORT_SOURCE_OBSERVATION_INVALID");
  return added[0]!;
}

export class InertImportService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly evidence: EvidenceService,
    private readonly audit: AuditService
  ) {}

  importSarif(
    missionId: string,
    content: string | Uint8Array,
    options: ImportSarifOptions,
    now = new Date()
  ): InertImportRecord {
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
    const operator = options.operator.trim();
    if (operator.length < 2 || operator.length > 120) throw new Error("OPERATOR_INVALID");
    const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);
    if (bytes.byteLength < 1 || bytes.byteLength > INERT_SARIF_LIMITS.maxBytes) {
      throw new Error("SARIF_BYTE_LIMIT_EXCEEDED");
    }
    const sourceSha256 = sha256(bytes);
    const parsed = parseSarif(bytes, sourceSha256);
    const parent = options.parentImportId
      ? (this.database.prepare("SELECT * FROM inert_imports WHERE id = ?").get(options.parentImportId) as
          | ImportRow
          | undefined)
      : undefined;
    if (options.parentImportId && !parent) throw new Error("INERT_IMPORT_PARENT_NOT_FOUND");
    if (parent && parent.mission_id !== missionId) throw new Error("INERT_IMPORT_PARENT_MISSION_MISMATCH");
    if (
      parent &&
      (parent.parser_id !== INERT_SARIF_PARSER_ID ||
        parent.parser_version !== INERT_SARIF_PARSER_VERSION)
    ) {
      throw new Error("INERT_IMPORT_PARENT_PARSER_MISMATCH");
    }

    const existingArtifact = this.database
      .prepare("SELECT id FROM artifacts WHERE sha256 = ?")
      .get(sourceSha256) as { id: string } | undefined;
    const priorObservationIds = new Set(
      existingArtifact
        ? this.evidence
            .observations(existingArtifact.id, missionId)
            .map((observation) => observation.id)
        : []
    );
    const artifact = this.evidence.seal(bytes, "application/sarif+json", {
      missionId,
      capturedAt: now,
      provenance: {
        sourceType: "inert-sarif-import",
        parserId: INERT_SARIF_PARSER_ID,
        parserVersion: INERT_SARIF_PARSER_VERSION,
        sourceSha256,
        resultCount: parsed.resultCount
      }
    });
    if (
      artifact.sha256 !== sourceSha256 ||
      artifact.size_bytes !== bytes.byteLength ||
      !this.evidence.verify(artifact.id)
    ) {
      throw new Error("INERT_IMPORT_SOURCE_ARTIFACT_INVALID");
    }
    const sourceObservation = exactNewSourceObservation(
      this.evidence,
      artifact.id,
      missionId,
      priorObservationIds
    );
    const importId = randomUUID();
    const importedAt = now.toISOString();
    const manifest = {
      schemaVersion: 1,
      importId,
      missionId,
      parentImportId: parent?.id ?? null,
      sourceArtifactId: artifact.id,
      sourceObservationId: sourceObservation.id,
      sourceSha256,
      sourceSizeBytes: bytes.byteLength,
      sourceMediaType: "application/sarif+json",
      parserId: INERT_SARIF_PARSER_ID,
      parserVersion: INERT_SARIF_PARSER_VERSION,
      resultCount: parsed.resultCount,
      candidateCount: parsed.candidateCount,
      importedBy: operator,
      importedAt
    };
    const manifestJson = stableJson(manifest);
    const manifestHash = canonicalHash(manifest);

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO inert_imports(
             id, mission_id, parent_import_id, source_artifact_id, source_observation_id,
             source_sha256, source_size_bytes, source_media_type, parser_id, parser_version,
             result_count, candidate_count, import_manifest_json, import_manifest_hash,
             imported_by, imported_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'application/sarif+json', ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          importId,
          missionId,
          parent?.id ?? null,
          artifact.id,
          sourceObservation.id,
          sourceSha256,
          bytes.byteLength,
          INERT_SARIF_PARSER_ID,
          INERT_SARIF_PARSER_VERSION,
          parsed.resultCount,
          parsed.candidateCount,
          manifestJson,
          manifestHash,
          operator,
          importedAt
        );

      const candidateIds = new Map<string, string>();
      for (const observation of parsed.observations) {
        let candidateId = candidateIds.get(observation.fingerprint);
        if (!candidateId) {
          const keyJson = stableJson(observation.candidateKey);
          const existing = this.database
            .prepare(
              `SELECT * FROM inert_import_candidates
               WHERE mission_id = ? AND fingerprint = ?`
            )
            .get(missionId, observation.fingerprint) as CandidateRow | undefined;
          if (
            existing &&
            (existing.normalized_key_hash !== observation.fingerprint ||
              existing.normalized_key_json !== keyJson)
          ) {
            throw new Error("INERT_IMPORT_FINGERPRINT_CONFLICT");
          }
          candidateId = existing?.id ?? randomUUID();
          if (!existing) {
            this.database
              .prepare(
                `INSERT INTO inert_import_candidates(
                   id, mission_id, fingerprint, normalized_key_json, normalized_key_hash,
                   status, first_seen_import_id, created_at
                 ) VALUES (?, ?, ?, ?, ?, 'unverified', ?, ?)`
              )
              .run(
                candidateId,
                missionId,
                observation.fingerprint,
                keyJson,
                observation.fingerprint,
                importId,
                importedAt
              );
          }
          candidateIds.set(observation.fingerprint, candidateId);
        }
        const normalizedJson = stableJson(observation.normalized);
        if (Buffer.byteLength(normalizedJson, "utf8") > 8_192) {
          throw new Error("INERT_IMPORT_NORMALIZED_RESULT_TOO_LARGE");
        }
        this.database
          .prepare(
            `INSERT INTO inert_import_observations(
               id, import_id, candidate_id, mission_id, source_artifact_id,
               source_observation_id, run_index, result_index,
               normalized_json, normalized_hash, observed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            randomUUID(),
            importId,
            candidateId,
            missionId,
            artifact.id,
            sourceObservation.id,
            observation.runIndex,
            observation.resultIndex,
            normalizedJson,
            canonicalHash(observation.normalized),
            importedAt
          );
      }
      this.audit.append(
        "inert_import.completed",
        {
          importId,
          missionId,
          parentImportId: parent?.id ?? null,
          sourceArtifactId: artifact.id,
          sourceObservationId: sourceObservation.id,
          sourceSha256,
          parserId: INERT_SARIF_PARSER_ID,
          parserVersion: INERT_SARIF_PARSER_VERSION,
          resultCount: parsed.resultCount,
          candidateCount: parsed.candidateCount,
          manifestHash,
          operator
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(importId);
  }

  get(id: string): InertImportRecord {
    const row = this.database.prepare("SELECT * FROM inert_imports WHERE id = ?").get(id) as
      | ImportRow
      | undefined;
    if (!row) throw new Error("INERT_IMPORT_NOT_FOUND");
    const integrityValid = (() => {
      try {
        return (
          canonicalHash(JSON.parse(row.import_manifest_json)) === row.import_manifest_hash &&
          this.evidence.verify(row.source_artifact_id) &&
          this.evidence.verifyObservation(
            row.source_observation_id,
            row.source_artifact_id,
            row.mission_id
          )
        );
      } catch {
        return false;
      }
    })();
    return {
      id: row.id,
      missionId: row.mission_id,
      parentImportId: row.parent_import_id,
      sourceArtifactId: row.source_artifact_id,
      sourceObservationId: row.source_observation_id,
      sourceSha256: row.source_sha256,
      sourceSizeBytes: row.source_size_bytes,
      parserId: INERT_SARIF_PARSER_ID,
      parserVersion: INERT_SARIF_PARSER_VERSION,
      resultCount: row.result_count,
      candidateCount: row.candidate_count,
      importedBy: row.imported_by,
      importedAt: row.imported_at,
      integrityValid
    };
  }

  lineage(id: string): InertImportRecord[] {
    const lineage: InertImportRecord[] = [];
    const seen = new Set<string>();
    let currentId: string | null = id;
    while (currentId) {
      if (seen.has(currentId) || lineage.length >= 100) throw new Error("INERT_IMPORT_LINEAGE_INVALID");
      seen.add(currentId);
      const current = this.get(currentId);
      lineage.push(current);
      currentId = current.parentImportId;
    }
    const missionIds = new Set(lineage.map((item) => item.missionId));
    if (missionIds.size !== 1) throw new Error("INERT_IMPORT_LINEAGE_INVALID");
    return lineage;
  }

  observationsForCandidate(missionId: string, fingerprint: string): InertCandidateObservation[] {
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error("INERT_IMPORT_FINGERPRINT_INVALID");
    const candidate = this.database
      .prepare(
        `SELECT * FROM inert_import_candidates
         WHERE mission_id = ? AND fingerprint = ?`
      )
      .get(missionId, fingerprint) as CandidateRow | undefined;
    if (!candidate) return [];
    const rows = this.database
      .prepare(
        `SELECT observation.*
         FROM inert_import_observations observation
         WHERE observation.candidate_id = ? AND observation.mission_id = ?
         ORDER BY observation.observed_at, observation.id`
      )
      .all(candidate.id, missionId) as unknown as ObservationRow[];
    return rows.map((row) => {
      let normalized: NormalizedImportObservation;
      let integrityValid = false;
      try {
        normalized = JSON.parse(row.normalized_json) as NormalizedImportObservation;
        integrityValid =
          canonicalHash(normalized) === row.normalized_hash &&
          row.source_artifact_id === this.get(row.import_id).sourceArtifactId &&
          this.evidence.verifyObservation(
            row.source_observation_id,
            row.source_artifact_id,
            row.mission_id
          );
      } catch {
        normalized = {
          schemaVersion: 1,
          verification: "unverified",
          parser: { id: INERT_SARIF_PARSER_ID, version: INERT_SARIF_PARSER_VERSION },
          source: {
            sourceArtifactSha256: "0".repeat(64),
            runIndex: row.run_index,
            resultIndex: row.result_index
          },
          toolName: "invalid",
          ruleId: "invalid",
          level: "none",
          kind: "review",
          baselineState: null,
          location: { uriHash: null, startLine: null, startColumn: null },
          narrativeHash: "0".repeat(64),
          contentBoundary: {
            originalRetainedAsEvidence: true,
            narrativeNotNormalized: true,
            locationNotResolved: true,
            embeddedContentNotExecuted: true
          }
        };
      }
      return {
        id: row.id,
        importId: row.import_id,
        candidateId: row.candidate_id,
        missionId: row.mission_id,
        fingerprint: candidate.fingerprint,
        runIndex: row.run_index,
        resultIndex: row.result_index,
        normalized,
        integrityValid
      };
    });
  }
}
