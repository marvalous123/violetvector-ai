CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  media_type TEXT NOT NULL,
  storage_name TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  sealed_at TEXT NOT NULL,
  source_event_id TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  status TEXT NOT NULL CHECK (status IN ('candidate', 'unverified', 'confirmed', 'accepted', 'retest_pending', 'remediated', 'persists')),
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_revisions (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  revision INTEGER NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  description TEXT NOT NULL,
  remediation TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
  created_at TEXT NOT NULL,
  UNIQUE (finding_id, revision)
);

CREATE TABLE IF NOT EXISTS finding_evidence (
  finding_revision_id TEXT NOT NULL REFERENCES finding_revisions(id),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  PRIMARY KEY (finding_revision_id, artifact_id)
);

CREATE TABLE IF NOT EXISTS report_snapshots (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  snapshot_json TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL UNIQUE,
  template_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('frozen', 'generated', 'blocked')),
  frozen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_outputs (
  id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES report_snapshots(id),
  format TEXT NOT NULL CHECK (format IN ('json', 'html')),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  generated_at TEXT NOT NULL,
  UNIQUE (snapshot_id, format)
);
