import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { openDatabase } from "../db/database.js";
import { AuditService } from "./audit-service.js";
import { EvidenceService } from "./evidence-service.js";
import { MissionService } from "./mission-service.js";
import { SupportDiagnosticsService } from "./support-diagnostics-service.js";

describe("redacted support diagnostics", () => {
  it("reports local integrity and counts without disclosing paths or evidence", () => {
    const database = openDatabase();
    const audit = new AuditService(database);
    const evidence = new EvidenceService(database, mkdtempSync(join(tmpdir(), "war-room-support-")), audit);
    new MissionService(database, audit).createMission("Support fixture");
    evidence.seal("bounded fixture", "text/plain");
    const diagnostics = new SupportDiagnosticsService(database, audit, evidence, "professional", true)
      .collect(new Date("2026-07-19T16:00:00.000Z"));

    assert.equal(diagnostics.generatedAt, "2026-07-19T16:00:00.000Z");
    assert.equal(diagnostics.integrity.databaseQuickCheck, true);
    assert.equal(diagnostics.integrity.audit.valid, true);
    assert.equal(diagnostics.integrity.evidenceTotal, 1);
    assert.equal(diagnostics.integrity.evidenceChecked, 1);
    assert.equal(diagnostics.integrity.evidenceInvalid, 0);
    assert.equal(diagnostics.integrity.evidenceComplete, true);
    assert.equal(diagnostics.records.missions, 1);
    assert.equal(diagnostics.safeToShare, true);
    assert.doesNotMatch(JSON.stringify(diagnostics), /war-room-support|bounded fixture|[A-Z]:\\/i);
    database.close();
  });
});
