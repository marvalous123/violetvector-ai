import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { actionProposalSchema, evaluateProposal, getCapabilitySchemaHash } from "@war-room/policy";
import type { ActionProposal } from "@war-room/policy";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import { AuditService } from "./audit-service.js";
import { MissionService } from "./mission-service.js";

export interface ApprovalRow {
  id: string;
  proposal_id: string;
  proposal_hash: string;
  policy_version: string;
  tool_schema_hash: string;
  status: "pending" | "approved" | "denied" | "expired" | "revoked" | "consumed" | "superseded";
  requested_at: string;
  expires_at: string;
  decided_at: string | null;
  decided_by: string | null;
  consumed_at: string | null;
  decision_note: string | null;
}

interface ExecutionBinding {
  run_id: string;
  mission_id: string;
  scope_version_id: string;
  target_id: string;
  canonical_target: string;
  authorization_starts_at: string;
  authorization_expires_at: string;
  capability_schema_hash: string;
  safety_epoch: number;
  wall_time_ms_limit: number;
  tool_time_ms_limit: number;
  model_tokens_limit: number;
  output_bytes_limit: number;
  request_count_limit: number;
  wall_time_ms_used: number;
  tool_time_ms_used: number;
  model_tokens_used: number;
  output_bytes_used: number;
  request_count_used: number;
  proposal_id: string;
  stored_proposal_hash: string;
  stored_mission_id: string;
  stored_run_id: string;
  stored_target_id: string;
  stored_capability_id: string;
  stored_proposal_json: string;
  stored_policy_version: string;
  stored_tool_schema_hash: string;
  approval_policy_version: string;
  approval_tool_schema_hash: string;
  decided_by: string;
}

const liveRunStatuses = ["queued", "awaiting_approval", "armed", "running"];

export class ApprovalService {
  private readonly audit: AuditService;

  constructor(private readonly database: DatabaseSync, audit?: AuditService) {
    this.audit = audit ?? new AuditService(database);
  }

  request(input: { proposal: ActionProposal; ttlMs?: number; now?: Date }): ApprovalRow {
    const proposal = actionProposalSchema.parse(input.proposal);
    const now = input.now ?? new Date();
    const ttlMs = input.ttlMs ?? 5 * 60_000;
    if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 15 * 60_000) throw new Error("APPROVAL_TTL_INVALID");

    const context = this.database.prepare(
      `SELECT r.mission_id, r.status, rsb.scope_version_id, sv.starts_at, sv.expires_at,
              sv.policy_version, t.canonical_address,
              b.wall_time_ms_limit, b.tool_time_ms_limit, b.model_tokens_limit,
              b.output_bytes_limit, b.request_count_limit,
              COALESCE(SUM(u.wall_time_ms), 0) AS wall_time_ms,
              COALESCE(SUM(u.tool_time_ms), 0) AS tool_time_ms,
              COALESCE(SUM(u.model_tokens), 0) AS model_tokens,
              COALESCE(SUM(u.output_bytes), 0) AS output_bytes,
              COALESCE(SUM(u.request_count), 0) AS request_count
       FROM runs r
       JOIN run_scope_bindings rsb ON rsb.run_id = r.id
       JOIN scope_versions sv ON sv.id = rsb.scope_version_id
       JOIN scope_targets st ON st.scope_version_id = sv.id AND st.target_id = ?
       JOIN targets t ON t.id = st.target_id
       JOIN run_budgets b ON b.run_id = r.id
       LEFT JOIN usage_ledger u ON u.run_id = r.id
       WHERE r.id = ?
       GROUP BY r.id`
    ).get(proposal.targetId, proposal.runId) as Record<string, string | number> | undefined;
    if (!context) throw new Error("APPROVAL_RUN_BINDING_NOT_FOUND");
    if (context.mission_id !== proposal.missionId) throw new Error("APPROVAL_RUN_MISSION_MISMATCH");
    if (!liveRunStatuses.includes(String(context.status))) throw new Error("APPROVAL_RUN_NOT_LIVE");

    const latest = this.database.prepare(
      "SELECT id FROM scope_versions WHERE mission_id = ? ORDER BY version DESC LIMIT 1"
    ).get(proposal.missionId) as { id: string } | undefined;
    if (!latest || latest.id !== context.scope_version_id) throw new Error("APPROVAL_RUN_SCOPE_STALE");

    const scope = new MissionService(this.database, this.audit).getScopeVersion(String(context.scope_version_id));
    const decision = evaluateProposal({ proposal, scope, now });
    if (decision.effect !== "REQUIRE_APPROVAL") throw new Error(`APPROVAL_NOT_AVAILABLE:${decision.reason}`);
    if (proposal.timeoutMs > Number(context.tool_time_ms_limit) - Number(context.tool_time_ms)) {
      throw new Error("APPROVAL_RUN_TOOL_BUDGET_INSUFFICIENT");
    }
    if (proposal.maxOutputBytes > Number(context.output_bytes_limit) - Number(context.output_bytes)) {
      throw new Error("APPROVAL_RUN_OUTPUT_BUDGET_INSUFFICIENT");
    }
    if (Number(context.request_count) >= Number(context.request_count_limit)) {
      throw new Error("APPROVAL_RUN_REQUEST_BUDGET_EXHAUSTED");
    }

    const schemaHash = getCapabilitySchemaHash(proposal.capabilityId);
    const proposalHash = canonicalHash(proposal);
    const requestId = randomUUID();
    const requestedAt = now.toISOString();
    const expiresAt = new Date(Math.min(now.valueOf() + ttlMs, Date.parse(String(context.expires_at)))).toISOString();
    if (Date.parse(expiresAt) - now.valueOf() < 1_000) throw new Error("APPROVAL_AUTHORIZATION_WINDOW_TOO_SHORT");

    this.database.exec("BEGIN IMMEDIATE");
    try {
      const stop = this.database.prepare(
        "SELECT es.state, se.epoch FROM emergency_stop_state es CROSS JOIN safety_epochs se WHERE es.id = 1 AND se.id = 1"
      ).get() as { state: string; epoch: number };
      if (stop.state !== "ready") throw new Error("EMERGENCY_STOP_ACTIVE");
      this.database.prepare(
        `INSERT INTO proposals(
           id, mission_id, run_id, target_id, capability_id, risk_tier, proposal_json, proposal_hash,
           policy_version, tool_schema_hash, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        proposal.proposalId, proposal.missionId, proposal.runId, proposal.targetId, proposal.capabilityId,
        proposal.riskTier, stableJson(proposal), proposalHash, scope.policyVersion, schemaHash, requestedAt
      );
      this.database.prepare(
        `INSERT INTO approval_requests(
           id, proposal_id, proposal_hash, policy_version, tool_schema_hash, status, requested_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
      ).run(requestId, proposal.proposalId, proposalHash, scope.policyVersion, schemaHash, requestedAt, expiresAt);
      this.database.prepare(
        "INSERT INTO approval_scope_bindings(approval_id, scope_version_id) VALUES (?, ?)"
      ).run(requestId, scope.scopeVersionId);
      this.database.prepare(
        `INSERT INTO approval_execution_bindings(
           approval_id, run_id, mission_id, scope_version_id, target_id, canonical_target,
           authorization_starts_at, authorization_expires_at, capability_schema_hash, safety_epoch,
           wall_time_ms_limit, tool_time_ms_limit, model_tokens_limit, output_bytes_limit, request_count_limit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        requestId, proposal.runId, proposal.missionId, scope.scopeVersionId, proposal.targetId,
        String(context.canonical_address), scope.startsAt, scope.expiresAt, schemaHash, stop.epoch,
        Number(context.wall_time_ms_limit), Number(context.tool_time_ms_limit), Number(context.model_tokens_limit),
        Number(context.output_bytes_limit), Number(context.request_count_limit)
      );
      this.database.prepare(
        "UPDATE runs SET status = 'awaiting_approval', updated_at = ? WHERE id = ? AND status = 'queued'"
      ).run(requestedAt, proposal.runId);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    this.audit.append("approval.requested", {
      approvalId: requestId, proposalId: proposal.proposalId, runId: proposal.runId,
      proposalHash, scopeVersionId: scope.scopeVersionId, capabilitySchemaHash: schemaHash, expiresAt
    }, now);
    return this.get(requestId);
  }

  get(id: string): ApprovalRow {
    const row = this.database.prepare("SELECT * FROM approval_requests WHERE id = ?").get(id) as unknown as ApprovalRow | undefined;
    if (!row) throw new Error("APPROVAL_NOT_FOUND");
    return row;
  }

  assertPendingExactExecutionBinding(
    input: { approvalId: string; proposalId: string; runId: string; missionId: string },
    now = new Date()
  ): void {
    const approval = this.get(input.approvalId);
    if (approval.status !== "pending") throw new Error("APPROVAL_NOT_PENDING");
    const requestedAt = new Date(approval.requested_at);
    const expiresAt = new Date(approval.expires_at);
    if (
      !Number.isFinite(requestedAt.valueOf()) ||
      !Number.isFinite(expiresAt.valueOf()) ||
      now < requestedAt ||
      now >= expiresAt
    ) {
      throw new Error("APPROVAL_NOT_FRESH");
    }
    const binding = this.assertBindingLive(input.approvalId, now);
    let proposal: ActionProposal;
    try {
      proposal = actionProposalSchema.parse(JSON.parse(binding.stored_proposal_json));
    } catch {
      throw new Error("APPROVAL_STORED_PROPOSAL_MISMATCH");
    }
    const proposalHash = canonicalHash(proposal);
    if (approval.proposal_hash !== proposalHash) throw new Error("APPROVAL_BINDING_MISMATCH");
    const scope = new MissionService(this.database, this.audit).getScopeVersion(binding.scope_version_id);
    const schemaHash = getCapabilitySchemaHash(proposal.capabilityId);
    this.assertExactProposalBinding(binding, approval, proposal, proposalHash, scope.policyVersion, schemaHash);
    this.assertExecutionBudgetAvailable(binding, proposal);
    if (
      proposal.proposalId !== input.proposalId ||
      proposal.runId !== input.runId ||
      proposal.missionId !== input.missionId
    ) {
      throw new Error("APPROVAL_EXECUTION_IDENTITY_MISMATCH");
    }
  }

  approve(id: string, operator: string, note = "", now = new Date()): ApprovalRow {
    const approval = this.get(id);
    if (approval.status !== "pending") throw new Error("APPROVAL_NOT_PENDING");
    if (now >= new Date(approval.expires_at)) {
      this.database.prepare("UPDATE approval_requests SET status = 'expired' WHERE id = ?").run(id);
      throw new Error("APPROVAL_EXPIRED");
    }
    if (operator.trim().length < 2) throw new Error("OPERATOR_INVALID");
    this.assertBindingLive(id, now);
    this.database.prepare(
      `UPDATE approval_requests SET status = 'approved', decided_at = ?, decided_by = ?, decision_note = ?
       WHERE id = ? AND status = 'pending'`
    ).run(now.toISOString(), operator.trim(), note.trim(), id);
    this.audit.append("approval.approved", { approvalId: id, operator: operator.trim() }, now);
    return this.get(id);
  }

  deny(id: string, operator: string, note: string, now = new Date()): ApprovalRow {
    const approval = this.get(id);
    if (approval.status !== "pending") throw new Error("APPROVAL_NOT_PENDING");
    if (operator.trim().length < 2) throw new Error("OPERATOR_INVALID");
    this.database.prepare(
      `UPDATE approval_requests SET status = 'denied', decided_at = ?, decided_by = ?, decision_note = ?
       WHERE id = ? AND status = 'pending'`
    ).run(now.toISOString(), operator.trim(), note.trim(), id);
    this.audit.append("approval.denied", { approvalId: id, operator: operator.trim(), note: note.trim() }, now);
    return this.get(id);
  }

  consume(input: { approvalId: string; proposal: ActionProposal; now?: Date }): ApprovalRow {
    return this.consumeForExecution(input);
  }

  /**
   * Atomically exchanges one exact, fresh approval for a running run.
   *
   * This is the final deterministic gate an executor adapter must call before it
   * starts a target-bearing process. A successful return means the approval is
   * consumed, the run is running, and the complete authorization binding is in
   * the audit chain in the same database transaction.
   */
  consumeForExecution(input: { approvalId: string; proposal: ActionProposal; now?: Date }): ApprovalRow {
    const now = input.now ?? new Date();
    const approval = this.get(input.approvalId);
    if (approval.status !== "approved") throw new Error("APPROVAL_NOT_APPROVED");
    if (now >= new Date(approval.expires_at)) {
      this.database.prepare("UPDATE approval_requests SET status = 'expired' WHERE id = ?").run(input.approvalId);
      throw new Error("APPROVAL_EXPIRED");
    }
    const proposal = actionProposalSchema.parse(input.proposal);
    const proposalHash = canonicalHash(proposal);
    if (proposalHash !== approval.proposal_hash) throw new Error("APPROVAL_BINDING_MISMATCH");

    this.database.exec("BEGIN IMMEDIATE");
    try {
      const lockedApproval = this.get(input.approvalId);
      if (lockedApproval.status !== "approved") throw new Error("APPROVAL_CONSUME_RACE");
      if (now >= new Date(lockedApproval.expires_at)) throw new Error("APPROVAL_EXPIRED");
      if (lockedApproval.proposal_hash !== proposalHash) throw new Error("APPROVAL_BINDING_MISMATCH");

      const binding = this.assertBindingLive(input.approvalId, now);
      const scope = new MissionService(this.database, this.audit).getScopeVersion(binding.scope_version_id);
      const decision = evaluateProposal({ proposal, scope, now });
      if (decision.effect !== "REQUIRE_APPROVAL") throw new Error(`APPROVAL_REEVALUATION_DENIED:${decision.reason}`);
      const currentSchemaHash = getCapabilitySchemaHash(proposal.capabilityId);
      if (currentSchemaHash !== binding.capability_schema_hash) {
        throw new Error("APPROVAL_CAPABILITY_SCHEMA_STALE");
      }
      this.assertExactProposalBinding(binding, lockedApproval, proposal, proposalHash, scope.policyVersion, currentSchemaHash);
      this.assertExecutionBudgetAvailable(binding, proposal);

      const result = this.database.prepare(
        `UPDATE approval_requests SET status = 'consumed', consumed_at = ?
         WHERE id = ? AND status = 'approved'`
      ).run(now.toISOString(), input.approvalId);
      if (result.changes !== 1) throw new Error("APPROVAL_CONSUME_RACE");
      const runResult = this.database.prepare(
        "UPDATE runs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'awaiting_approval'"
      ).run(now.toISOString(), binding.run_id);
      if (runResult.changes !== 1) throw new Error("APPROVAL_RUN_TRANSITION_RACE");
      this.audit.append("approval.consumed", {
        approvalId: input.approvalId,
        proposalId: proposal.proposalId,
        proposalHash,
        runId: binding.run_id,
        missionId: binding.mission_id,
        scopeVersionId: binding.scope_version_id,
        targetId: binding.target_id,
        canonicalTarget: binding.canonical_target,
        capabilityId: proposal.capabilityId,
        capabilitySchemaHash: binding.capability_schema_hash,
        policyVersion: scope.policyVersion,
        safetyEpoch: binding.safety_epoch,
        approvedBy: binding.decided_by,
        authorizationExpiresAt: lockedApproval.expires_at,
        budget: {
          limits: {
            wallTimeMs: binding.wall_time_ms_limit,
            toolTimeMs: binding.tool_time_ms_limit,
            modelTokens: binding.model_tokens_limit,
            outputBytes: binding.output_bytes_limit,
            requestCount: binding.request_count_limit
          },
          usedBeforeExecution: {
            wallTimeMs: binding.wall_time_ms_used,
            toolTimeMs: binding.tool_time_ms_used,
            modelTokens: binding.model_tokens_used,
            outputBytes: binding.output_bytes_used,
            requestCount: binding.request_count_used
          },
          reservedForExecution: {
            wallTimeMs: proposal.timeoutMs,
            toolTimeMs: proposal.timeoutMs,
            outputBytes: proposal.maxOutputBytes,
            requestCount: 1
          }
        },
        runStatus: "running"
      }, now);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(input.approvalId);
  }

  private assertExactProposalBinding(
    binding: ExecutionBinding,
    approval: ApprovalRow,
    proposal: ActionProposal,
    proposalHash: string,
    policyVersion: string,
    schemaHash: string
  ): void {
    if (
      binding.proposal_id !== proposal.proposalId ||
      binding.stored_proposal_hash !== proposalHash ||
      binding.stored_proposal_json !== stableJson(proposal)
    ) {
      throw new Error("APPROVAL_STORED_PROPOSAL_MISMATCH");
    }
    if (
      binding.stored_mission_id !== proposal.missionId ||
      binding.stored_run_id !== proposal.runId ||
      binding.stored_target_id !== proposal.targetId ||
      binding.stored_capability_id !== proposal.capabilityId ||
      binding.mission_id !== proposal.missionId ||
      binding.run_id !== proposal.runId ||
      binding.target_id !== proposal.targetId
    ) {
      throw new Error("APPROVAL_EXECUTION_IDENTITY_MISMATCH");
    }
    if (
      approval.policy_version !== policyVersion ||
      approval.tool_schema_hash !== schemaHash ||
      binding.approval_policy_version !== policyVersion ||
      binding.approval_tool_schema_hash !== schemaHash ||
      binding.stored_policy_version !== policyVersion ||
      binding.stored_tool_schema_hash !== schemaHash
    ) {
      throw new Error("APPROVAL_POLICY_OR_SCHEMA_STALE");
    }
  }

  private assertExecutionBudgetAvailable(binding: ExecutionBinding, proposal: ActionProposal): void {
    if (proposal.timeoutMs > binding.wall_time_ms_limit - binding.wall_time_ms_used) {
      throw new Error("APPROVAL_RUN_WALL_BUDGET_INSUFFICIENT");
    }
    if (proposal.timeoutMs > binding.tool_time_ms_limit - binding.tool_time_ms_used) {
      throw new Error("APPROVAL_RUN_TOOL_BUDGET_INSUFFICIENT");
    }
    if (proposal.maxOutputBytes > binding.output_bytes_limit - binding.output_bytes_used) {
      throw new Error("APPROVAL_RUN_OUTPUT_BUDGET_INSUFFICIENT");
    }
    if (binding.request_count_used >= binding.request_count_limit) {
      throw new Error("APPROVAL_RUN_REQUEST_BUDGET_EXHAUSTED");
    }
  }

  private assertBindingLive(approvalId: string, now: Date): ExecutionBinding {
    const binding = this.database.prepare(
      `SELECT aeb.*, r.status AS run_status, rsb.scope_version_id AS run_scope_version_id,
              t.canonical_address, se.epoch AS current_epoch, es.state AS stop_state,
              p.id AS proposal_id, p.proposal_hash AS stored_proposal_hash,
              p.mission_id AS stored_mission_id, p.run_id AS stored_run_id,
              p.target_id AS stored_target_id, p.capability_id AS stored_capability_id,
              p.proposal_json AS stored_proposal_json, p.policy_version AS stored_policy_version,
              p.tool_schema_hash AS stored_tool_schema_hash,
              ar.policy_version AS approval_policy_version,
              ar.tool_schema_hash AS approval_tool_schema_hash,
              ar.decided_by,
              b.wall_time_ms_limit AS current_wall_time_ms_limit,
              b.tool_time_ms_limit AS current_tool_time_ms_limit,
              b.model_tokens_limit AS current_model_tokens_limit,
              b.output_bytes_limit AS current_output_bytes_limit,
              b.request_count_limit AS current_request_count_limit,
              COALESCE((SELECT SUM(u.wall_time_ms) FROM usage_ledger u WHERE u.run_id = r.id), 0) AS wall_time_ms_used,
              COALESCE((SELECT SUM(u.tool_time_ms) FROM usage_ledger u WHERE u.run_id = r.id), 0) AS tool_time_ms_used,
              COALESCE((SELECT SUM(u.model_tokens) FROM usage_ledger u WHERE u.run_id = r.id), 0) AS model_tokens_used,
              COALESCE((SELECT SUM(u.output_bytes) FROM usage_ledger u WHERE u.run_id = r.id), 0) AS output_bytes_used,
              COALESCE((SELECT SUM(u.request_count) FROM usage_ledger u WHERE u.run_id = r.id), 0) AS request_count_used
       FROM approval_execution_bindings aeb
       JOIN approval_requests ar ON ar.id = aeb.approval_id
       JOIN proposals p ON p.id = ar.proposal_id
       JOIN runs r ON r.id = aeb.run_id
       JOIN run_scope_bindings rsb ON rsb.run_id = r.id
       JOIN scope_targets st ON st.scope_version_id = aeb.scope_version_id AND st.target_id = aeb.target_id
       JOIN targets t ON t.id = aeb.target_id
       JOIN run_budgets b ON b.run_id = r.id
       CROSS JOIN safety_epochs se
       CROSS JOIN emergency_stop_state es
       WHERE aeb.approval_id = ? AND se.id = 1 AND es.id = 1`
    ).get(approvalId) as (ExecutionBinding & Record<string, string | number>) | undefined;
    if (!binding) throw new Error("APPROVAL_EXECUTION_BINDING_MISSING");
    if (binding.stop_state !== "ready" || binding.safety_epoch !== binding.current_epoch) {
      throw new Error("EMERGENCY_STOP_ACTIVE_OR_STALE");
    }
    if (binding.run_status !== "awaiting_approval") throw new Error("APPROVAL_RUN_NOT_AWAITING_APPROVAL");
    if (binding.run_scope_version_id !== binding.scope_version_id) throw new Error("APPROVAL_RUN_SCOPE_MISMATCH");
    const latest = this.database.prepare(
      "SELECT id FROM scope_versions WHERE mission_id = ? ORDER BY version DESC LIMIT 1"
    ).get(binding.mission_id) as { id: string } | undefined;
    if (!latest || latest.id !== binding.scope_version_id) throw new Error("APPROVAL_SCOPE_STALE");
    if (now < new Date(binding.authorization_starts_at) || now >= new Date(binding.authorization_expires_at)) {
      throw new Error("APPROVAL_AUTHORIZATION_WINDOW_INACTIVE");
    }
    if (binding.canonical_address !== binding.canonical_target) throw new Error("APPROVAL_TARGET_BINDING_MISMATCH");
    for (const name of ["wall_time_ms_limit", "tool_time_ms_limit", "model_tokens_limit", "output_bytes_limit", "request_count_limit"] as const) {
      if (binding[name] !== binding[`current_${name}`]) throw new Error("APPROVAL_BUDGET_BINDING_MISMATCH");
    }
    return binding;
  }
}
