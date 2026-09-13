CREATE TABLE IF NOT EXISTS report_qa_reviews (
  id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL UNIQUE REFERENCES report_snapshots(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) = 64),
  opened_by TEXT NOT NULL CHECK (length(opened_by) BETWEEN 2 AND 120),
  opened_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_report_qa_reviews_mission
  ON report_qa_reviews(mission_id, opened_at, id);

CREATE TABLE IF NOT EXISTS report_qa_events (
  id TEXT PRIMARY KEY,
  review_id TEXT NOT NULL REFERENCES report_qa_reviews(id),
  sequence INTEGER NOT NULL CHECK (sequence >= 1 AND sequence <= 100),
  event_type TEXT NOT NULL CHECK (
    event_type IN ('opened', 'changes-requested', 'approved')
  ),
  payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 32768),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 2 AND 120),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL CHECK (length(previous_event_hash) = 64),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
  UNIQUE (review_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_report_qa_events_review
  ON report_qa_events(review_id, sequence);

CREATE TRIGGER IF NOT EXISTS report_qa_snapshot_binding_guard
BEFORE INSERT ON report_qa_reviews
WHEN NOT EXISTS (
  SELECT 1
  FROM report_snapshots snapshot
  WHERE snapshot.id = NEW.snapshot_id
    AND snapshot.mission_id = NEW.mission_id
    AND snapshot.snapshot_hash = NEW.snapshot_hash
    AND snapshot.status = 'generated'
)
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_SNAPSHOT_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS report_qa_event_sequence_guard
BEFORE INSERT ON report_qa_events
WHEN NEW.sequence <> (
  SELECT COALESCE(MAX(sequence), 0) + 1
  FROM report_qa_events
  WHERE review_id = NEW.review_id
)
OR NEW.previous_event_hash <> COALESCE(
  (
    SELECT event_hash
    FROM report_qa_events
    WHERE review_id = NEW.review_id
    ORDER BY sequence DESC
    LIMIT 1
  ),
  '0000000000000000000000000000000000000000000000000000000000000000'
)
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_EVENT_CHAIN_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS report_qa_reviews_immutable_update
BEFORE UPDATE ON report_qa_reviews
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_REVIEW_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_qa_reviews_immutable_delete
BEFORE DELETE ON report_qa_reviews
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_REVIEW_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_qa_events_immutable_update
BEFORE UPDATE ON report_qa_events
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_EVENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_qa_events_immutable_delete
BEFORE DELETE ON report_qa_events
BEGIN
  SELECT RAISE(ABORT, 'REPORT_QA_EVENT_IMMUTABLE');
END;
