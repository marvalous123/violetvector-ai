import {
  brokerExecutionRequestSchema, capabilityCatalogue, type BrokerExecutionRequest
} from "./schemas.js";
import { digestApproval, digestExecutionBinding, digestProposal } from "./canonical.js";

export class ExecutionContractError extends Error {
  constructor(
    readonly code:
      | "INVALID_REQUEST"
      | "PROPOSAL_DIGEST_MISMATCH"
      | "APPROVAL_DIGEST_MISMATCH"
      | "APPROVAL_BINDING_MISMATCH"
      | "APPROVAL_EXPIRED"
      | "TARGET_RESOLUTION_MISMATCH"
      | "CAPABILITY_RISK_MISMATCH",
    message: string
  ) {
    super(message);
    this.name = "ExecutionContractError";
  }
}

export function validateBrokerExecutionRequest(input: unknown, now = new Date()): BrokerExecutionRequest {
  const parsed = brokerExecutionRequestSchema.safeParse(input);
  if (!parsed.success) {
    throw new ExecutionContractError("INVALID_REQUEST", "Execution request failed strict schema validation");
  }
  const request = parsed.data;
  if (digestProposal(request.proposal) !== request.proposalDigest) {
    throw new ExecutionContractError("PROPOSAL_DIGEST_MISMATCH", "Proposal digest does not match canonical proposal");
  }
  if (digestApproval(request.approval) !== request.approvalDigest) {
    throw new ExecutionContractError("APPROVAL_DIGEST_MISMATCH", "Approval digest does not match canonical approval");
  }
  if (
    request.approval.proposalDigest !== request.proposalDigest ||
    request.approval.missionId !== request.proposal.missionId ||
    request.approval.targetId !== request.proposal.targetId ||
    request.approval.capabilityId !== request.proposal.capabilityId
  ) {
    throw new ExecutionContractError("APPROVAL_BINDING_MISMATCH", "Approval is not bound to this exact proposal");
  }
  if (Date.parse(request.approval.expiresAt) <= now.getTime()) {
    throw new ExecutionContractError("APPROVAL_EXPIRED", "Approval has expired");
  }
  if (request.target.targetId !== request.proposal.targetId) {
    throw new ExecutionContractError("TARGET_RESOLUTION_MISMATCH", "Resolved target is not the proposed target ID");
  }
  if (request.approval.executionBindingDigest !== digestExecutionBinding({
    target: request.target,
    limits: request.limits
  })) {
    throw new ExecutionContractError(
      "APPROVAL_BINDING_MISMATCH",
      "Approval is not bound to this exact resolved target and execution limits"
    );
  }
  if (!["T1", "T2"].includes(capabilityCatalogue[request.proposal.capabilityId].riskTier)) {
    throw new ExecutionContractError("CAPABILITY_RISK_MISMATCH", "Capability catalogue risk metadata is invalid");
  }
  return request;
}
