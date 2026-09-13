import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const here = dirname(fileURLToPath(import.meta.url));

function splitLeadingPragmas(sql: string): { pragmas: string; body: string } {
  const match = sql.match(/^(?:\s*PRAGMA[^\r\n]*;\s*)+/i);
  return match
    ? { pragmas: match[0], body: sql.slice(match[0].length) }
    : { pragmas: "", body: sql };
}

function unwrapExplicitTransaction(sql: string): {
  leadingPragmas: string;
  body: string;
  trailingStatements: string;
} | undefined {
  const { pragmas: leadingPragmas, body: afterPragmas } = splitLeadingPragmas(sql);
  const begin = afterPragmas.match(/^\s*BEGIN(?:\s+(?:DEFERRED|IMMEDIATE|EXCLUSIVE))?\s*;\s*/i);
  if (!begin) return undefined;
  const afterBegin = afterPragmas.slice(begin[0].length);
  const commits = [...afterBegin.matchAll(/\bCOMMIT\s*;/gi)];
  const commit = commits.at(-1);
  if (!commit || commit.index === undefined) {
    throw new Error("MIGRATION_TRANSACTION_INVALID");
  }
  return {
    leadingPragmas,
    body: afterBegin.slice(0, commit.index),
    trailingStatements: afterBegin.slice(commit.index + commit[0].length)
  };
}

export function applyHashedMigration(
  database: DatabaseSync,
  name: string,
  sql: string,
  sha256: string,
  appliedAt = new Date()
): void {
  const explicit = unwrapExplicitTransaction(sql);
  const ordinary = splitLeadingPragmas(sql);
  const leadingPragmas = explicit?.leadingPragmas ?? ordinary.pragmas;
  const body = explicit?.body ?? ordinary.body;
  if (leadingPragmas) database.exec(leadingPragmas);
  database.exec("BEGIN IMMEDIATE");
  try {
    database.exec(body);
    database
      .prepare("INSERT INTO schema_migrations(name, sha256, applied_at) VALUES (?, ?, ?)")
      .run(name, sha256, appliedAt.toISOString());
    database.exec("COMMIT");
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  } finally {
    if (explicit?.trailingStatements.trim()) {
      database.exec(explicit.trailingStatements);
    }
  }
}

export function openDatabase(path = ":memory:"): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
      applied_at TEXT NOT NULL
    )
  `);
  const migrationsPath = join(here, "migrations");
  const migrations = readdirSync(migrationsPath)
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
  try {
    for (const migration of migrations) {
      const sql = readFileSync(join(migrationsPath, migration), "utf8");
      const sha256 = createHash("sha256").update(sql, "utf8").digest("hex");
      const existing = database
        .prepare("SELECT sha256 FROM schema_migrations WHERE name = ?")
        .get(migration) as { sha256: string } | undefined;
      if (existing) {
        if (existing.sha256 !== sha256) {
          throw new Error(`MIGRATION_HASH_MISMATCH:${migration}`);
        }
        continue;
      }
      applyHashedMigration(database, migration, sql, sha256);
    }
  } catch (error) {
    database.close();
    throw error;
  }
  return database;
}
