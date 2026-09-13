import { actionProposalSchema, capabilityDefinitions, scopeSchema } from "./schemas.js";
import { canonicalizeTarget, TargetParseError } from "./target.js";
import type { ActionProposal, Scope, TargetRecord } from "./schemas.js";

export type PolicyReasonCode =
  | "ALLOW_T0"
  | "APPROVAL_REQUIRED_T1"
  | "INVALID_PROPOSAL"
  | "INVALID_SCOPE"
  | "MISSION_MISMATCH"
  | "SCOPE_NOT_ACTIVE"
  | "TARGET_NOT_IN_SCOPE"
  | "TARGET_INVALID"
  | "TARGET_RESERVED_DENIED"
  | "PRIVATE_TARGET_NOT_ISOLATED"
  | "RISK_TIER_MISMATCH"
  | "CAPABILITY_DENIED";

export interface PolicyDecision {
  effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: PolicyReasonCode;
  message: string;
  canonicalTarget?: string;
  policyVersion?: string;
}

function deny(reason: PolicyReasonCode, message: string, scope?: Scope): PolicyDecision {
  return { effect: "DENY", reason, message, ...(scope ? { policyVersion: scope.policyVersion } : {}) };
}

function resolveTarget(scope: Scope, targetId: string): TargetRecord | undefined {
  return scope.targets.find((target) => target.id === targetId);
}

export function evaluateProposal(input: {
  proposal: ActionProposal;
  scope: Scope;
  now?: Date;
}): PolicyDecision {
  const proposalResult = actionProposalSchema.safeParse(input.proposal);
  if (!proposalResult.success) return deny("INVALID_PROPOSAL", "Proposal failed strict schema validation");
  const scopeResult = scopeSchema.safeParse(input.scope);
  if (!scopeResult.success) return deny("INVALID_SCOPE", "Scope failed strict schema validation");

  const proposal = proposalResult.data;
  const scope = scopeResult.data;
  if (proposal.missionId !== scope.missionId) {
    return deny("MISSION_MISMATCH", "Proposal mission does not match the active scope", scope);
  }

  const now = input.now ?? new Date();
  if (now < new Date(scope.startsAt) || now >= new Date(scope.expiresAt)) {
    return deny("SCOPE_NOT_ACTIVE", "The authorization window is not active", scope);
  }

  if (proposal.capabilityId === "planning.note") {
    if (proposal.riskTier !== "T0") return deny("RISK_TIER_MISMATCH", "Planning is a T0 capability", scope);
    return { effect: "ALLOW", reason: "ALLOW_T0", message: "Non-executing planning action allowed", policyVersion: scope.policyVersion };
  }

  if (proposal.capabilityId !== "network.discovery" &&
      proposal.capabilityId !== "network.service-version" &&
      proposal.capabilityId !== "network.tcp-port-discovery" &&
      proposal.capabilityId !== "network.tcp-port-state" &&
      proposal.capabilityId !== "web.http-metadata" &&
      proposal.capabilityId !== "tls.certificate-metadata" &&
      proposal.capabilityId !== "tls.cipher-enumeration") {
    return deny("CAPABILITY_DENIED", "Capability is not enabled by this policy", scope);
  }
  const expectedRisk = capabilityDefinitions[proposal.capabilityId].riskTier;
  if (proposal.riskTier !== expectedRisk) {
    return deny("RISK_TIER_MISMATCH", `Capability must be classified ${expectedRisk}`, scope);
  }

  const target = resolveTarget(scope, proposal.targetId);
  if (!target) return deny("TARGET_NOT_IN_SCOPE", "Target ID is not present in the active scope", scope);

  try {
    const canonical = canonicalizeTarget(target.address);
    if (canonical.classification === "private" && !target.isolatedPrivateTargetApproved) {
      return deny("PRIVATE_TARGET_NOT_ISOLATED", "Private target lacks an explicit isolation approval", scope);
    }
    if (canonical.classification !== "public" && canonical.classification !== "private") {
      return deny("TARGET_RESERVED_DENIED", `Target class ${canonical.classification} is denied`, scope);
    }
    return {
      effect: "REQUIRE_APPROVAL",
      reason: "APPROVAL_REQUIRED_T1",
      message: "Exact scoped T1 action requires a fresh parameter-bound approval",
      canonicalTarget: canonical.address,
      policyVersion: scope.policyVersion
    };
  } catch (error) {
    const message = error instanceof TargetParseError ? error.message : "Target parsing failed";
    return deny("TARGET_INVALID", message, scope);
  }
}
