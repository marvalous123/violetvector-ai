import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  digestApproval,
  digestExecutionBinding,
  digestProposal,
  EXECUTOR_CONTRACT_VERSION,
  NMAP_HTTP_METADATA_CAPABILITY,
  NMAP_TCP_PORT_DISCOVERY_CAPABILITY,
  NMAP_TCP_PORT_STATE_CAPABILITY,
  NMAP_TCP_SERVICE_VERSION_CAPABILITY,
  NMAP_TLS_CERTIFICATE_CAPABILITY,
  NMAP_TLS_CIPHERS_CAPABILITY,
  NmapTcpExecutionError,
  NmapTcpExecutor,
  type BrokerExecutionRequest,
  type CanonicalApprovalBinding,
  type CanonicalProposalBinding,
  type NmapTcpAdapterConfig,
  type NmapTcpExecutionResult
} from "@war-room/executor-contract";
import { actionProposalSchema, type ActionProposal } from "@war-room/policy";
import { stableJson } from "../domain/stable-json.js";
import type { ApprovalService } from "./approval-service.js";
import type { AuditService } from "./audit-service.js";
import type { EvidenceService } from "./evidence-service.js";
import type { ExecutionLifecycleService } from "./execution-lifecycle-service.js";
import { MissionService } from "./mission-service.js";
import type { RunControlService } from "./run-control-service.js";
import type { RedmiIsolationAttestation, TargetIsolationVerifier } from "./redmi-isolation-service.js";

const SERVICE_VERSION_TIMEOUT_MS = 15_000;
const ALL_TCP_DISCOVERY_TIMEOUT_MS = 120_000;
const TARGET_OUTPUT_BYTES = 262_144;
const TARGET_EVIDENCE_BYTES = 327_680;
const ISOLATION_APPROVAL_TIMEOUT_MS = 50_000;

export type TargetProfileCapabilityId =
  | "network.tcp-port-state"
  | "web.http-metadata"
  | "tls.certificate-metadata"
  | "tls.cipher-enumeration";

const TARGET_PROFILE_SPECS = Object.freeze({
  "network.tcp-port-state": Object.freeze({
    executorCapabilityId: NMAP_TCP_PORT_STATE_CAPABILITY,
    riskTier: "T1",
    timeoutMs: 20_000,
    maxPorts: 16,
    profile: "low-noise",
    usageReason: "restricted-target-low-noise-port-state"
  }),
  "web.http-metadata": Object.freeze({
    executorCapabilityId: NMAP_HTTP_METADATA_CAPABILITY,
    riskTier: "T1",
    timeoutMs: 30_000,
    maxPorts: 4,
    profile: "headers-title",
    usageReason: "restricted-target-http-metadata"
  }),
  "tls.certificate-metadata": Object.freeze({
    executorCapabilityId: NMAP_TLS_CERTIFICATE_CAPABILITY,
    riskTier: "T1",
    timeoutMs: 30_000,
    maxPorts: 4,
    profile: "certificate",
    usageReason: "restricted-target-tls-certificate"
  }),
  "tls.cipher-enumeration": Object.freeze({
    executorCapabilityId: NMAP_TLS_CIPHERS_CAPABILITY,
    riskTier: "T2",
    timeoutMs: 60_000,
    maxPorts: 2,
    profile: "cipher-posture",
    usageReason: "restricted-target-tls-ciphers"
  })
} as const);

export interface TargetApprovalRequest {
  readonly missionId: string;
  readonly ports: readonly number[];
  readonly intensity: number;
}

export interface TargetProfileApprovalRequest {
  readonly missionId: string;
  readonly capabilityId: TargetProfileCapabilityId;
  readonly ports: readonly number[];
}

export interface TargetExecutionResult {
  readonly executionId: string;
  readonly runId: string;
  readonly approvalId: string;
  readonly capabilityId:
    | typeof NMAP_TCP_SERVICE_VERSION_CAPABILITY
    | typeof NMAP_TCP_PORT_DISCOVERY_CAPABILITY
    | typeof NMAP_TCP_PORT_STATE_CAPABILITY
    | typeof NMAP_HTTP_METADATA_CAPABILITY
    | typeof NMAP_TLS_CERTIFICATE_CAPABILITY
    | typeof NMAP_TLS_CIPHERS_CAPABILITY;
  readonly targetAddress: string;
  readonly ports?: readonly number[];
  readonly outputBytes: number;
  readonly durationMs: number;
  readonly artifact: { readonly id: string; readonly sha256: string; readonly size_bytes: number; readonly media_type: string };
  readonly completedAt: string;
}

interface StoredExecutionBinding {
  approval_id: string;
  expires_at: string;
  decided_at: string;
  decided_by: string;
  proposal_json: string;
  policy_version: string;
  canonical_address: string;
  scope_version_id: string;
}

interface RetestLineage {
  readonly parentRunId: string;
  readonly lineageType: "retest";
}

export type TargetExecutorFactory = (
  config: NmapTcpAdapterConfig
) => {
  execute(
    request: BrokerExecutionRequest,
    options?: { readonly signal?: AbortSignal }
  ): Promise<NmapTcpExecutionResult>;
};

export function executorOperatorId(operator: string): string {
  return `operator:${createHash("sha256").update(operator.trim(), "utf8").digest("hex").slice(0, 32)}`;
}

export class TargetExecutionService {
  private readonly active = new Map<string, AbortController>();
  private executionLease = false;

  constructor(
    private readonly database: DatabaseSync,
    private readonly isolation: TargetIsolationVerifier,
    private readonly controls: RunControlService,
    private readonly approvals: ApprovalService,
    private readonly evidence: EvidenceService,
    private readonly lifecycles: ExecutionLifecycleService,
    private readonly audit: AuditService,
    private readonly createExecutor: TargetExecutorFactory = (config) =>
      new NmapTcpExecutor(config),
    private readonly isolationTimeoutMs = ISOLATION_APPROVAL_TIMEOUT_MS
  ) {}

  private async verifyIsolation(): Promise<RedmiIsolationAttestation> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error("ISOLATION_VERIFICATION_TIMED_OUT")),
        this.isolationTimeoutMs
      );
    });
    try {
      return await Promise.race([this.isolation.verify(), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  activeCount(): number {
    return this.active.size;
  }

  abortAll(): number {
    for (const controller of this.active.values()) controller.abort();
    return this.active.size;
  }

  async requestApproval(input: TargetApprovalRequest, operator: string, lineage?: RetestLineage) {
    this.controls.assertReady();
    const mission = new MissionService(this.database, this.audit).getMission(input.missionId);
    if (mission.status !== "scope_validated") throw new Error("MISSION_NOT_RUNNABLE");
    const scope = new MissionService(this.database, this.audit).getLatestScope(input.missionId);
    const now = new Date();
    this.assertScopeActive(scope.startsAt, scope.expiresAt, now);
    if (scope.targets.length !== 1) throw new Error("TARGET_SCOPE_MUST_BE_EXACT");
    const target = scope.targets[0]!;
    const attestation = await this.verifyIsolation();
    if (target.address !== attestation.targetAddress || !target.isolatedPrivateTargetApproved) {
      throw new Error("TARGET_ISOLATION_MISMATCH");
    }
    const ports = [...input.ports].sort((left, right) => left - right);
    const proposalInput = {
      proposalId: randomUUID(),
      missionId: input.missionId,
      runId: this.controls.createRun({
        missionId: input.missionId,
        budget: {
          wallTimeMsLimit: 30_000,
          toolTimeMsLimit: 30_000,
          modelTokensLimit: 1,
          outputBytesLimit: TARGET_OUTPUT_BYTES,
          requestCountLimit: 1
        },
        ...(lineage ?? {}),
        now
      }),
      targetId: target.id,
      capabilityId: "network.service-version" as const,
      riskTier: "T1" as const,
      timeoutMs: SERVICE_VERSION_TIMEOUT_MS,
      maxOutputBytes: TARGET_OUTPUT_BYTES,
      parameters: { ports, transport: "tcp" as const, intensity: input.intensity }
    };
    const proposal = actionProposalSchema.parse(proposalInput);
    if (proposal.capabilityId !== "network.service-version") throw new Error("CAPABILITY_NOT_SUPPORTED");
    const approval = this.approvals.request({ proposal, ttlMs: 10 * 60_000 });
    this.audit.append("target.approval.prepared", {
      approvalId: approval.id,
      proposalId: proposal.proposalId,
      runId: proposal.runId,
      missionId: proposal.missionId,
      targetId: proposal.targetId,
      canonicalTarget: attestation.targetAddress,
      ports,
      intensity: proposal.parameters.intensity,
      isolationVerificationId: attestation.verificationId,
      lineageType: lineage?.lineageType ?? "original",
      parentRunId: lineage?.parentRunId ?? null,
      requestedBy: operator
    });
    return { approval, proposal, isolation: attestation };
  }

  async requestAllTcpApproval(missionId: string, operator: string, lineage?: RetestLineage) {
    this.controls.assertReady();
    const mission = new MissionService(this.database, this.audit).getMission(missionId);
    if (mission.status !== "scope_validated") throw new Error("MISSION_NOT_RUNNABLE");
    const scope = new MissionService(this.database, this.audit).getLatestScope(missionId);
    const now = new Date();
    this.assertScopeActive(scope.startsAt, scope.expiresAt, now);
    if (scope.targets.length !== 1) throw new Error("TARGET_SCOPE_MUST_BE_EXACT");
    const target = scope.targets[0]!;
    const attestation = await this.verifyIsolation();
    if (target.address !== attestation.targetAddress || !target.isolatedPrivateTargetApproved) {
      throw new Error("TARGET_ISOLATION_MISMATCH");
    }
    const proposal = actionProposalSchema.parse({
      proposalId: randomUUID(),
      missionId,
      runId: this.controls.createRun({
        missionId,
        budget: {
          wallTimeMsLimit: ALL_TCP_DISCOVERY_TIMEOUT_MS,
          toolTimeMsLimit: ALL_TCP_DISCOVERY_TIMEOUT_MS,
          modelTokensLimit: 1,
          outputBytesLimit: TARGET_OUTPUT_BYTES,
          requestCountLimit: 1
        },
        ...(lineage ?? {}),
        now
      }),
      targetId: target.id,
      capabilityId: "network.tcp-port-discovery",
      riskTier: "T1",
      timeoutMs: ALL_TCP_DISCOVERY_TIMEOUT_MS,
      maxOutputBytes: TARGET_OUTPUT_BYTES,
      parameters: { profile: "all-tcp", maxRate: 1_000 }
    });
    if (proposal.capabilityId !== "network.tcp-port-discovery") throw new Error("CAPABILITY_NOT_SUPPORTED");
    const approval = this.approvals.request({ proposal, ttlMs: 10 * 60_000 });
    this.audit.append("target.approval.prepared", {
      approvalId: approval.id,
      proposalId: proposal.proposalId,
      runId: proposal.runId,
      missionId: proposal.missionId,
      targetId: proposal.targetId,
      canonicalTarget: attestation.targetAddress,
      profile: proposal.parameters.profile,
      maxRate: proposal.parameters.maxRate,
      isolationVerificationId: attestation.verificationId,
      lineageType: lineage?.lineageType ?? "original",
      parentRunId: lineage?.parentRunId ?? null,
      requestedBy: operator
    });
    return { approval, proposal, isolation: attestation };
  }

  async requestProfileApproval(input: TargetProfileApprovalRequest, operator: string, lineage?: RetestLineage) {
    const spec = TARGET_PROFILE_SPECS[input.capabilityId];
    const ports = [...input.ports].sort((left, right) => left - right);
    if (ports.length < 1 ||
        ports.length > spec.maxPorts ||
        ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535) ||
        new Set(ports).size !== ports.length) {
      throw new Error("TARGET_PROFILE_PORTS_INVALID");
    }

    this.controls.assertReady();
    const mission = new MissionService(this.database, this.audit).getMission(input.missionId);
    if (mission.status !== "scope_validated") throw new Error("MISSION_NOT_RUNNABLE");
    const scope = new MissionService(this.database, this.audit).getLatestScope(input.missionId);
    const now = new Date();
    this.assertScopeActive(scope.startsAt, scope.expiresAt, now);
    if (scope.targets.length !== 1) throw new Error("TARGET_SCOPE_MUST_BE_EXACT");
    const target = scope.targets[0]!;
    const attestation = await this.verifyIsolation();
    if (target.address !== attestation.targetAddress || !target.isolatedPrivateTargetApproved) {
      throw new Error("TARGET_ISOLATION_MISMATCH");
    }
    const proposal = actionProposalSchema.parse({
      proposalId: randomUUID(),
      missionId: input.missionId,
      runId: this.controls.createRun({
        missionId: input.missionId,
        budget: {
          wallTimeMsLimit: spec.timeoutMs,
          toolTimeMsLimit: spec.timeoutMs,
          modelTokensLimit: 1,
          outputBytesLimit: TARGET_OUTPUT_BYTES,
          requestCountLimit: 1
        },
        ...(lineage ?? {}),
        now
      }),
      targetId: target.id,
      capabilityId: input.capabilityId,
      riskTier: spec.riskTier,
      timeoutMs: spec.timeoutMs,
      maxOutputBytes: TARGET_OUTPUT_BYTES,
      parameters: { ports, transport: "tcp", profile: spec.profile }
    });
    if (proposal.capabilityId !== input.capabilityId) throw new Error("CAPABILITY_NOT_SUPPORTED");
    const approval = this.approvals.request({ proposal, ttlMs: 10 * 60_000 });
    this.audit.append("target.approval.prepared", {
      approvalId: approval.id,
      proposalId: proposal.proposalId,
      runId: proposal.runId,
      missionId: proposal.missionId,
      targetId: proposal.targetId,
      canonicalTarget: attestation.targetAddress,
      capabilityId: proposal.capabilityId,
      ports,
      profile: spec.profile,
      riskTier: spec.riskTier,
      isolationVerificationId: attestation.verificationId,
      lineageType: lineage?.lineageType ?? "original",
      parentRunId: lineage?.parentRunId ?? null,
      requestedBy: operator
    });
    return { approval, proposal, isolation: attestation };
  }

  async requestRetestApproval(parentRunId: string, operator: string) {
    this.controls.assertReady();
    const parent = this.database
      .prepare(
        `SELECT r.id, r.mission_id, r.status, p.proposal_json, t.canonical_address
         FROM runs r
         JOIN proposals p ON p.run_id = r.id
         JOIN targets t ON t.id = p.target_id
         WHERE r.id = ?
         ORDER BY p.created_at DESC LIMIT 1`
      )
      .get(parentRunId) as
      | {
          id: string;
          mission_id: string;
          status: string;
          proposal_json: string;
          canonical_address: string;
        }
      | undefined;
    if (!parent) throw new Error("RETEST_PARENT_NOT_FOUND");
    if (parent.status !== "succeeded") throw new Error("RETEST_PARENT_NOT_COMPLETE");
    const original = actionProposalSchema.parse(JSON.parse(parent.proposal_json));
    if (
      original.capabilityId !== "network.service-version" &&
      original.capabilityId !== "network.tcp-port-discovery" &&
      original.capabilityId !== "network.tcp-port-state" &&
      original.capabilityId !== "web.http-metadata" &&
      original.capabilityId !== "tls.certificate-metadata" &&
      original.capabilityId !== "tls.cipher-enumeration"
    ) {
      throw new Error("RETEST_CAPABILITY_NOT_SUPPORTED");
    }
    const currentScope = new MissionService(this.database, this.audit).getLatestScope(parent.mission_id);
    const now = new Date();
    this.assertScopeActive(currentScope.startsAt, currentScope.expiresAt, now);
    if (
      currentScope.targets.length !== 1 ||
      currentScope.targets[0]!.address !== parent.canonical_address
    ) {
      throw new Error("RETEST_TARGET_CHANGED");
    }
    const lineage: RetestLineage = { parentRunId, lineageType: "retest" };
    let prepared;
    if (original.capabilityId === "network.service-version") {
      prepared = await this.requestApproval(
            {
              missionId: parent.mission_id,
              ports: original.parameters.ports,
              intensity: original.parameters.intensity
            },
            operator,
            lineage
          );
    } else if (original.capabilityId === "network.tcp-port-discovery") {
      prepared = await this.requestAllTcpApproval(parent.mission_id, operator, lineage);
    } else {
      prepared = await this.requestProfileApproval({
        missionId: parent.mission_id,
        capabilityId: original.capabilityId,
        ports: original.parameters.ports
      }, operator, lineage);
    }
    this.audit.append("target.retest.prepared", {
      parentRunId,
      retestRunId: prepared.proposal.runId,
      missionId: parent.mission_id,
      capabilityId: original.capabilityId,
      requestedBy: operator
    });
    return prepared;
  }

  async execute(approvalId: string, operator: string): Promise<TargetExecutionResult> {
    if (this.executionLease) throw new Error("TARGET_EXECUTION_BUSY");
    this.executionLease = true;
    try {
      return await this.executeLeased(approvalId, operator);
    } finally {
      this.executionLease = false;
    }
  }

  private async executeLeased(approvalId: string, operator: string): Promise<TargetExecutionResult> {
    this.controls.assertReady();
    const binding = this.loadBinding(approvalId);
    if (binding.decided_by !== operator) throw new Error("APPROVAL_OPERATOR_MISMATCH");
    const policyProposal = actionProposalSchema.parse(JSON.parse(binding.proposal_json));
    if (policyProposal.capabilityId !== "network.service-version" &&
        policyProposal.capabilityId !== "network.tcp-port-discovery" &&
        policyProposal.capabilityId !== "network.tcp-port-state" &&
        policyProposal.capabilityId !== "web.http-metadata" &&
        policyProposal.capabilityId !== "tls.certificate-metadata" &&
        policyProposal.capabilityId !== "tls.cipher-enumeration") {
      throw new Error("CAPABILITY_NOT_SUPPORTED");
    }
    const executionSpec =
      policyProposal.capabilityId === "network.service-version"
        ? {
            executorCapabilityId: NMAP_TCP_SERVICE_VERSION_CAPABILITY,
            timeoutMs: SERVICE_VERSION_TIMEOUT_MS,
            usageReason: "restricted-target-service-version"
          }
        : policyProposal.capabilityId === "network.tcp-port-discovery"
          ? {
              executorCapabilityId: NMAP_TCP_PORT_DISCOVERY_CAPABILITY,
              timeoutMs: ALL_TCP_DISCOVERY_TIMEOUT_MS,
              usageReason: "restricted-target-all-tcp-discovery"
            }
          : TARGET_PROFILE_SPECS[policyProposal.capabilityId];
    const executorCapabilityId = executionSpec.executorCapabilityId;
    const timeoutMs = executionSpec.timeoutMs;
    const attestation = await this.verifyIsolation();
    if (binding.canonical_address !== attestation.targetAddress) throw new Error("TARGET_ISOLATION_MISMATCH");
    const now = new Date();
    const lifecycle = this.lifecycles.create({
      capabilityId: executorCapabilityId,
      operator,
      missionId: policyProposal.missionId,
      runId: policyProposal.runId,
      binarySha256: attestation.imageId.slice("sha256:".length)
    }, now);
    const request = this.buildBrokerRequest(policyProposal, binding, attestation, lifecycle.id, now);
    const executor = this.createExecutor({
      distro: "kali-linux",
      dockerExecutable: "/usr/bin/docker",
      imageReference: attestation.imageId,
      isolatedNetwork: attestation.networkName,
      executionEnabled: true,
      isolation: {
        verified: true,
        exactTargetAddress: attestation.targetAddress,
        verificationId: attestation.verificationId
      },
      timeoutMs,
      maxStdoutBytes: TARGET_OUTPUT_BYTES - 32_768,
      maxStderrBytes: 32_768
    });
    const controller = new AbortController();
    this.active.set(lifecycle.id, controller);
    try {
      this.lifecycles.transition(lifecycle.id, "starting");
      this.approvals.consumeForExecution({ approvalId, proposal: policyProposal, now });
      this.lifecycles.transition(lifecycle.id, "running");
      const result = await executor.execute(request, { signal: controller.signal });
      if (
        controller.signal.aborted ||
        this.controls.getStopState().state !== "ready"
      ) {
        throw new NmapTcpExecutionError(
          "CANCELLED",
          "Restricted target execution completed during emergency stop"
        );
      }
      const completedAt = new Date();
      const evidencePayload = stableJson({
          schemaVersion: 1,
          capabilityId: executorCapabilityId,
          targetAddress: attestation.targetAddress,
          parameters: policyProposal.parameters,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode
        });
      if (Buffer.byteLength(evidencePayload, "utf8") > request.limits.maxEvidenceBytes) {
        throw new NmapTcpExecutionError("OUTPUT_LIMIT_EXCEEDED", "Restricted target evidence exceeded its limit");
      }
      const artifact = this.evidence.seal(
        evidencePayload,
        "application/json",
        {
          missionId: policyProposal.missionId,
          runId: policyProposal.runId,
          sourceEventId: lifecycle.id,
          provenance: {
            sourceType: "restricted-target-execution",
            executionId: lifecycle.id,
            approvalId,
            isolationVerificationId: attestation.verificationId,
            imageId: attestation.imageId
          }
        }
      );
      this.controls.recordUsage(policyProposal.runId, {
        wallTimeMs: result.durationMs,
        toolTimeMs: result.durationMs,
        outputBytes: result.outputBytes,
        requestCount: 1
      }, executionSpec.usageReason, completedAt);
      const runTransition = this.database.prepare(
        "UPDATE runs SET status = 'succeeded', updated_at = ? WHERE id = ? AND status = 'running'"
      ).run(completedAt.toISOString(), policyProposal.runId);
      if (Number(runTransition.changes) !== 1) {
        throw new Error("RUN_TERMINAL_TRANSITION_RACE");
      }
      this.lifecycles.transition(lifecycle.id, "succeeded", { now: completedAt });
      this.audit.append("target.execution.completed", {
        executionId: lifecycle.id,
        approvalId,
        runId: policyProposal.runId,
        artifactId: artifact.id,
        artifactSha256: artifact.sha256,
        outputBytes: result.outputBytes,
        durationMs: result.durationMs
      }, completedAt);
      return {
        executionId: lifecycle.id,
        runId: policyProposal.runId,
        approvalId,
        capabilityId: executorCapabilityId,
        targetAddress: attestation.targetAddress,
        ...("ports" in policyProposal.parameters ? { ports: policyProposal.parameters.ports } : {}),
        outputBytes: result.outputBytes,
        durationMs: result.durationMs,
        artifact,
        completedAt: completedAt.toISOString()
      };
    } catch (error) {
      const failedAt = new Date();
      const cancelled = error instanceof NmapTcpExecutionError && error.code === "CANCELLED";
      const current = this.lifecycles.get(lifecycle.id);
      if (cancelled && current.status === "running") {
        this.lifecycles.transition(lifecycle.id, "cancel_requested", { now: failedAt });
        this.lifecycles.transition(lifecycle.id, "cancelled", { now: failedAt });
      } else if (["starting", "running", "cancel_requested"].includes(current.status)) {
        const reasonCode =
          error instanceof NmapTcpExecutionError
            ? error.code
            : "INTERNAL_ERROR";
        this.lifecycles.transition(lifecycle.id, "failed", { reasonCode, now: failedAt });
      }
      this.database.prepare(
        "UPDATE runs SET status = 'failed', updated_at = ? WHERE id = ? AND status = 'running'"
      ).run(failedAt.toISOString(), policyProposal.runId);
      throw error;
    } finally {
      this.active.delete(lifecycle.id);
    }
  }

  private loadBinding(approvalId: string): StoredExecutionBinding {
    const row = this.database.prepare(
      `SELECT ar.id AS approval_id, ar.expires_at, ar.decided_at, ar.decided_by,
              p.proposal_json, p.policy_version, t.canonical_address, asb.scope_version_id
       FROM approval_requests ar
       JOIN proposals p ON p.id = ar.proposal_id
       JOIN targets t ON t.id = p.target_id
       JOIN approval_scope_bindings asb ON asb.approval_id = ar.id
       WHERE ar.id = ? AND ar.status = 'approved'`
    ).get(approvalId) as unknown as StoredExecutionBinding | undefined;
    if (!row || !row.decided_at || !row.decided_by) throw new Error("APPROVAL_NOT_APPROVED");
    return row;
  }

  private assertScopeActive(startsAt: string, expiresAt: string, now: Date): void {
    if (now < new Date(startsAt) || now >= new Date(expiresAt)) {
      throw new Error("RUN_SCOPE_NOT_ACTIVE");
    }
  }

  private buildBrokerRequest(
    proposal: Extract<ActionProposal, {
      capabilityId:
        | "network.service-version"
        | "network.tcp-port-discovery"
        | "network.tcp-port-state"
        | "web.http-metadata"
        | "tls.certificate-metadata"
        | "tls.cipher-enumeration";
    }>,
    binding: StoredExecutionBinding,
    attestation: RedmiIsolationAttestation,
    executionId: string,
    now: Date
  ): BrokerExecutionRequest {
    const commonProposal = {
      contractVersion: EXECUTOR_CONTRACT_VERSION,
      proposalId: proposal.proposalId,
      missionId: proposal.missionId,
      targetId: proposal.targetId,
      policyVersion: binding.policy_version,
      requestedBy: "war-room-operator",
      requestedAt: now.toISOString()
    };
    let canonicalProposal: CanonicalProposalBinding;
    switch (proposal.capabilityId) {
      case "network.service-version":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_TCP_SERVICE_VERSION_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
      case "network.tcp-port-discovery":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_TCP_PORT_DISCOVERY_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
      case "network.tcp-port-state":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_TCP_PORT_STATE_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
      case "web.http-metadata":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_HTTP_METADATA_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
      case "tls.certificate-metadata":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_TLS_CERTIFICATE_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
      case "tls.cipher-enumeration":
        canonicalProposal = {
          ...commonProposal,
          capabilityId: NMAP_TLS_CIPHERS_CAPABILITY,
          parameters: proposal.parameters
        };
        break;
    }
    const proposalDigest = digestProposal(canonicalProposal);
    const target = {
      targetId: proposal.targetId,
      canonicalAddress: attestation.targetAddress,
      addressFamily: "ipv4" as const,
      resolutionSource: "scope-registry" as const,
      scopeRevision: binding.scope_version_id,
      resolvedAt: attestation.verifiedAt
    };
    const limits = {
      timeoutMs: proposal.timeoutMs,
      maxOutputBytes: proposal.maxOutputBytes,
      maxEvidenceBytes: TARGET_EVIDENCE_BYTES
    };
    const canonicalApproval: CanonicalApprovalBinding = {
      contractVersion: EXECUTOR_CONTRACT_VERSION,
      approvalId: binding.approval_id,
      proposalDigest,
      executionBindingDigest: digestExecutionBinding({ target, limits }),
      missionId: proposal.missionId,
      targetId: proposal.targetId,
      capabilityId: canonicalProposal.capabilityId,
      approvedBy: executorOperatorId(binding.decided_by),
      approvedAt: binding.decided_at,
      expiresAt: binding.expires_at,
      maxUses: 1
    };
    return {
      executionId,
      proposal: canonicalProposal,
      proposalDigest,
      approval: canonicalApproval,
      approvalDigest: digestApproval(canonicalApproval),
      target,
      limits,
      submittedAt: now.toISOString()
    };
  }
}
