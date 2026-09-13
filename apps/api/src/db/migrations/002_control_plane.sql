CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  parent_run_id TEXT REFERENCES runs(id),
  lineage_type TEXT CHECK (lineage_type IN ('original', 'replay', 'retest')),
  status TEXT NOT NULL CHECK (status IN ('queued', 'awaiting_approval', 'armed', 'running', 'succeeded', 'failed', 'stop_requested', 'phase1_halted', 'draining', 'stopped', 'stop_incomplete')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  run_id TEXT REFERENCES runs(id),
  target_id TEXT NOT NULL REFERENCES targets(id),
  capability_id TEXT NOT NULL,
  risk_tier TEXT NOT NULL CHECK (risk_tier IN ('T0', 'T1', 'T2', 'T3')),
  proposal_json TEXT NOT NULL,
  proposal_hash TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  tool_schema_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES proposals(id),
  proposal_hash TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  tool_schema_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked', 'consumed', 'superseded')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  consumed_at TEXT,
  decision_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_live_approval_per_proposal
ON approval_requests(proposal_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  occurred_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS run_budgets (
  run_id TEXT PRIMARY KEY REFERENCES runs(id),
  wall_time_ms_limit INTEGER NOT NULL CHECK (wall_time_ms_limit > 0),
  tool_time_ms_limit INTEGER NOT NULL CHECK (tool_time_ms_limit > 0),
  model_tokens_limit INTEGER NOT NULL CHECK (model_tokens_limit > 0),
  output_bytes_limit INTEGER NOT NULL CHECK (output_bytes_limit > 0),
  request_count_limit INTEGER NOT NULL CHECK (request_count_limit > 0)
);

CREATE TABLE IF NOT EXISTS usage_ledger (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  wall_time_ms INTEGER NOT NULL DEFAULT 0 CHECK (wall_time_ms >= 0),
  tool_time_ms INTEGER NOT NULL DEFAULT 0 CHECK (tool_time_ms >= 0),
  model_tokens INTEGER NOT NULL DEFAULT 0 CHECK (model_tokens >= 0),
  output_bytes INTEGER NOT NULL DEFAULT 0 CHECK (output_bytes >= 0),
  request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  recorded_at TEXT NOT NULL,
  reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emergency_stop_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('ready', 'stop_requested', 'phase1_halted', 'draining', 'stopped', 'stop_incomplete')),
  requested_at TEXT,
  requested_by TEXT,
  reason TEXT,
  updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO emergency_stop_state(id, state, updated_at)
VALUES (1, 'ready', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
