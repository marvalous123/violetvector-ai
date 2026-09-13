PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'scope_validated', 'ready', 'active', 'complete', 'closed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_versions (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  version INTEGER NOT NULL,
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, version)
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  canonical_address TEXT NOT NULL,
  address_family TEXT NOT NULL CHECK (address_family IN ('ipv4', 'ipv6')),
  classification TEXT NOT NULL,
  UNIQUE (canonical_address)
);

CREATE TABLE IF NOT EXISTS scope_targets (
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id),
  target_id TEXT NOT NULL REFERENCES targets(id),
  isolated_private_target_approved INTEGER NOT NULL DEFAULT 0 CHECK (isolated_private_target_approved IN (0, 1)),
  PRIMARY KEY (scope_version_id, target_id)
);

CREATE TABLE IF NOT EXISTS authorization_records (
  id TEXT PRIMARY KEY,
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id),
  statement TEXT NOT NULL,
  attachment_sha256 TEXT,
  recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  proposal_id TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
  reason TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  decided_at TEXT NOT NULL
);
