import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { applyHashedMigration, openDatabase } from "./database.js";

describe("initial database migration", () => {
  it("creates the mission and scope foundation with foreign keys enabled", () => {
    const database = openDatabase();
    const tables = database
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all()
      .map((row) => (row as { name: string }).name);
    for (const table of ["missions", "scope_versions", "targets", "scope_targets", "authorization_records"]) {
      assert.ok(tables.includes(table), `missing table ${table}`);
    }
    assert.ok(tables.includes("blue_detection_runs"), "missing table blue_detection_runs");
    for (const table of [
      "endpoint_enrollment_challenges",
      "endpoint_identities",
      "endpoint_telemetry_batches",
      "endpoint_public_keys",
      "endpoint_identity_renewals",
      "endpoint_capability_snapshots",
      "endpoint_fact_batches",
      "endpoint_minimized_facts",
      "endpoint_fact_stream_heads",
      "endpoint_live_correlation_runs",
      "endpoint_live_blue_alerts",
      "schema_migrations",
      "remediation_records",
      "remediation_events",
      "inert_imports",
      "inert_import_candidates",
      "inert_import_observations",
      "mission_profiles",
      "guided_demo_instances",
      "engagement_test_plans",
      "test_plan_procedures",
      "test_plan_procedure_evidence",
      "report_qa_reviews",
      "report_qa_events",
      "report_export_bundles",
      "report_export_qa_events",
      "operational_benchmarks",
      "operational_benchmark_events",
      "operational_benchmark_scope_bindings"
    ]) {
      assert.ok(tables.includes(table), `missing table ${table}`);
    }
    assert.equal((database.prepare("PRAGMA foreign_keys").get() as { foreign_keys: number }).foreign_keys, 1);
    assert.equal(
      database.prepare("PRAGMA foreign_key_check").all().length,
      0,
      "migrations must preserve every foreign-key binding"
    );
    const migrations = database
      .prepare("SELECT name, sha256 FROM schema_migrations ORDER BY name")
      .all() as Array<{ name: string; sha256: string }>;
    assert.equal(migrations.at(-1)?.name, "029_remediation_retest_approval_provenance.sql");
    assert.equal(migrations.every((migration) => /^[a-f0-9]{64}$/.test(migration.sha256)), true);
    const capabilityForeignKeys = database
      .prepare("PRAGMA foreign_key_list(endpoint_fact_batches)")
      .all() as Array<{ table: string }>;
    assert.equal(
      capabilityForeignKeys.some((foreignKey) => foreignKey.table === "endpoint_capability_snapshots"),
      true
    );
    database.close();
  });

  it("records migration hashes and fails closed if applied history drifts", () => {
    const root = mkdtempSync(join(tmpdir(), "war-room-migrations-"));
    const path = join(root, "war-room.sqlite");
    const database = openDatabase(path);
    database
      .prepare("UPDATE schema_migrations SET sha256 = ? WHERE name = ?")
      .run("0".repeat(64), "001_initial.sql");
    database.close();
    assert.throws(
      () => openDatabase(path),
      /MIGRATION_HASH_MISMATCH:001_initial\.sql/
    );
  });

  it("rolls back an ordinary migration and its hash record as one unit", () => {
    const database = new DatabaseSync(":memory:");
    database.exec(`
      CREATE TABLE schema_migrations (
        name TEXT PRIMARY KEY,
        sha256 TEXT NOT NULL,
        applied_at TEXT NOT NULL
      )
    `);
    assert.throws(
      () => applyHashedMigration(
        database,
        "999_deliberate_failure.sql",
        "CREATE TABLE must_rollback(id TEXT PRIMARY KEY); INSERT INTO missing_table VALUES (1);",
        "f".repeat(64),
        new Date("2026-07-22T12:00:00.000Z")
      )
    );
    assert.equal(
      database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'must_rollback'").get(),
      undefined
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get() as { count: number }).count,
      0
    );
    database.close();
  });

  it("rolls back a self-transaction migration and its hash record as one unit", () => {
    const database = new DatabaseSync(":memory:");
    database.exec(`
      PRAGMA foreign_keys = OFF;
      CREATE TABLE schema_migrations (
        name TEXT PRIMARY KEY,
        sha256 TEXT NOT NULL,
        applied_at TEXT NOT NULL
      )
    `);
    assert.throws(
      () => applyHashedMigration(
        database,
        "998_deliberate_self_transaction_failure.sql",
        `
          PRAGMA foreign_keys = OFF;
          BEGIN IMMEDIATE;
          CREATE TABLE must_also_rollback(id TEXT PRIMARY KEY);
          INSERT INTO missing_table VALUES (1);
          COMMIT;
          PRAGMA foreign_keys = ON;
        `,
        "e".repeat(64),
        new Date("2026-07-22T12:00:00.000Z")
      )
    );
    assert.equal(
      database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'must_also_rollback'").get(),
      undefined
    );
    assert.equal(
      (database.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get() as { count: number }).count,
      0
    );
    assert.equal((database.prepare("PRAGMA foreign_keys").get() as { foreign_keys: number }).foreign_keys, 1);
    database.close();
  });
});
