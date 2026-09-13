import { createHash } from "node:crypto";
import {
  canonicalApprovalBindingSchema,
  canonicalProposalBindingSchema,
  capabilityCatalogue,
  executionBindingSchema,
  EXECUTOR_CONTRACT_VERSION,
  type CanonicalApprovalBinding,
  type CanonicalProposalBinding,
  type ExecutionBinding
} from "./schemas.js";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

export function digestProposal(value: CanonicalProposalBinding): string {
  return sha256Canonical(canonicalProposalBindingSchema.parse(value));
}

export function digestApproval(value: CanonicalApprovalBinding): string {
  return sha256Canonical(canonicalApprovalBindingSchema.parse(value));
}

export function digestExecutionBinding(value: ExecutionBinding): string {
  return sha256Canonical(executionBindingSchema.parse(value));
}

export const EXECUTOR_SCHEMA_HASH = sha256Canonical({
  contractVersion: EXECUTOR_CONTRACT_VERSION,
  capabilityCatalogue
});
