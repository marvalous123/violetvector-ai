CREATE TABLE IF NOT EXISTS operational_benchmarks (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  started_by TEXT NOT NULL CHECK (length(started_by) BETWEEN 2 AND 120),
  start_note TEXT NOT NULL CHECK (length(start_note) BETWEEN 10 AND 4000),
  started_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operational_benchmarks_mission
  ON operational_benchmarks(mission_id, started_at, id);

CREATE TABLE IF NOT EXISTS operational_benchmark_events (
  id TEXT PRIMARY KEY,
  benchmark_id TEXT NOT NULL REFERENCES operational_benchmarks(id),
  sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 100),
  event_type TEXT NOT NULL CHECK (event_type IN ('milestone', 'completed')),
  payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 32768),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 2 AND 120),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL CHECK (length(previous_event_hash) = 64),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
  UNIQUE (benchmark_id, sequence)
);

CREATE TRIGGER IF NOT EXISTS operational_benchmark_event_sequence_guard
BEFORE INSERT ON operational_benchmark_events
WHEN NEW.sequence <> (
  SELECT COALESCE(MAX(sequence), 0) + 1
  FROM operational_benchmark_events
  WHERE benchmark_id = NEW.benchmark_id
)
OR NEW.previous_event_hash <> COALESCE(
  (
    SELECT event_hash
    FROM operational_benchmark_events
    WHERE benchmark_id = NEW.benchmark_id
    ORDER BY sequence DESC LIMIT 1
  ),
  '0000000000000000000000000000000000000000000000000000000000000000'
)
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_EVENT_CHAIN_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS operational_benchmarks_immutable_update
BEFORE UPDATE ON operational_benchmarks
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS operational_benchmarks_immutable_delete
BEFORE DELETE ON operational_benchmarks
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS operational_benchmark_events_immutable_update
BEFORE UPDATE ON operational_benchmark_events
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_EVENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS operational_benchmark_events_immutable_delete
BEFORE DELETE ON operational_benchmark_events
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_EVENT_IMMUTABLE');
END;
