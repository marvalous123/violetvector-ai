CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_approval_fresh_guard
BEFORE INSERT ON remediation_direct_retest_bindings
WHEN NOT EXISTS (
  SELECT 1
  FROM remediation_records record
  JOIN runs retest
    ON retest.id = NEW.retest_run_id
   AND retest.mission_id = record.mission_id
   AND retest.status = 'awaiting_approval'
  JOIN run_scope_bindings run_scope ON run_scope.run_id = retest.id
  JOIN proposals proposal
    ON proposal.id = NEW.proposal_id
   AND proposal.run_id = retest.id
   AND proposal.mission_id = record.mission_id
  JOIN approval_requests approval
    ON approval.id = NEW.approval_id
   AND approval.proposal_id = proposal.id
   AND approval.proposal_hash = proposal.proposal_hash
   AND approval.policy_version = proposal.policy_version
   AND approval.tool_schema_hash = proposal.tool_schema_hash
   AND approval.status = 'pending'
  JOIN approval_execution_bindings execution_binding
    ON execution_binding.approval_id = approval.id
   AND execution_binding.run_id = retest.id
   AND execution_binding.mission_id = record.mission_id
   AND execution_binding.scope_version_id = run_scope.scope_version_id
   AND execution_binding.target_id = proposal.target_id
  JOIN safety_epochs safety
    ON safety.id = 1
   AND safety.epoch = execution_binding.safety_epoch
  JOIN emergency_stop_state stop
    ON stop.id = 1
   AND stop.state = 'ready'
  WHERE record.id = NEW.remediation_id
    AND approval.requested_at <= NEW.bound_at
    AND NEW.bound_at < approval.expires_at
    AND execution_binding.authorization_starts_at <= NEW.bound_at
    AND NEW.bound_at < execution_binding.authorization_expires_at
    AND run_scope.scope_version_id = (
      SELECT id FROM scope_versions
      WHERE mission_id = record.mission_id
      ORDER BY version DESC LIMIT 1
    )
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_APPROVAL_NOT_FRESH');
END;

CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_consumed_evidence_guard
BEFORE INSERT ON remediation_evidence_links
WHEN NEW.purpose = 'retest'
 AND EXISTS (
  SELECT 1
  FROM remediation_events event
  JOIN remediation_records record ON record.id = event.remediation_id
  JOIN finding_revisions revision ON revision.finding_id = record.finding_id
  JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
  JOIN evidence_observations source_observation ON source_observation.id = citation.observation_id
  WHERE event.id = NEW.remediation_event_id
    AND source_observation.run_id IS NOT NULL
 )
 AND NOT EXISTS (
  SELECT 1
  FROM remediation_events outcome_event
  JOIN remediation_direct_retest_bindings binding
    ON binding.remediation_id = outcome_event.remediation_id
   AND binding.request_id = json_extract(outcome_event.payload_json, '$.requestId')
  JOIN approval_requests approval
    ON approval.id = binding.approval_id
   AND approval.proposal_id = binding.proposal_id
   AND approval.status = 'consumed'
   AND approval.consumed_at IS NOT NULL
   AND binding.bound_at <= approval.consumed_at
   AND approval.requested_at <= approval.consumed_at
   AND approval.consumed_at < approval.expires_at
  JOIN approval_execution_bindings execution_binding
    ON execution_binding.approval_id = approval.id
   AND execution_binding.run_id = binding.retest_run_id
  JOIN evidence_observations observation
    ON observation.id = NEW.observation_id
   AND observation.artifact_id = NEW.artifact_id
   AND observation.mission_id = execution_binding.mission_id
   AND observation.run_id = binding.retest_run_id
  JOIN execution_lifecycles lifecycle
    ON lifecycle.id = observation.source_event_id
   AND lifecycle.mission_id = observation.mission_id
   AND lifecycle.run_id = observation.run_id
   AND lifecycle.status = 'succeeded'
  WHERE outcome_event.id = NEW.remediation_event_id
    AND json_extract(observation.provenance_json, '$.source.sourceType') = 'restricted-target-execution'
    AND json_extract(observation.provenance_json, '$.source.approvalId') = binding.approval_id
    AND json_extract(observation.provenance_json, '$.source.executionId') = observation.source_event_id
 )
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_APPROVAL_EVIDENCE_INVALID');
END;
