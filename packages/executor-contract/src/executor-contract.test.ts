import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adapterHealthSchema,
  brokerExecutionRequestSchema,
  capabilityCatalogue,
  canonicalProposalBindingSchema,
  digestApproval,
  digestExecutionBinding,
  digestProposal,
  EXECUTOR_SCHEMA_HASH,
  ExecutionContractError,
  FakeExecutor,
  outputChunkSchema,
  resolvedTargetSchema,
  validateBrokerExecutionRequest,
  type BrokerExecutionRequest,
  type CanonicalApprovalBinding,
  type CanonicalProposalBinding,
  type LifecycleEvent
} from "./index.js";

const proposal: CanonicalProposalBinding = {
  contractVersion: "executor-contract.v2",
  proposalId: "proposal-1",
  missionId: "mission-1",
  targetId: "target-1",
  policyVersion: "policy-v1",
  requestedBy: "operator-1",
  requestedAt: "2026-01-01T00:00:00.000Z",
  capabilityId: "mcpwn.nmap.service-version.v1",
  parameters: { ports: [22, 443], transport: "tcp", intensity: 2 }
};

function request(overrides: Partial<BrokerExecutionRequest> = {}): BrokerExecutionRequest {
  const proposalDigest = digestProposal(proposal);
  const target = {
    targetId: "target-1",
    canonicalAddress: "192.0.2.25",
    addressFamily: "ipv4" as const,
    resolutionSource: "scope-registry" as const,
    scopeRevision: "scope-revision-7",
    resolvedAt: "2026-01-01T00:00:00.000Z"
  };
  const limits = { timeoutMs: 1_000, maxOutputBytes: 64, maxEvidenceBytes: 4_096 };
  const approval: CanonicalApprovalBinding = {
    contractVersion: "executor-contract.v2",
    approvalId: "approval-1",
    proposalDigest,
    executionBindingDigest: digestExecutionBinding({ target, limits }),
    missionId: proposal.missionId,
    targetId: proposal.targetId,
    capabilityId: proposal.capabilityId,
    approvedBy: "operator-1",
    approvedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-01-01T00:10:00.000Z",
    maxUses: 1
  };
  return {
    executionId: "execution-1",
    proposal,
    proposalDigest,
    approval,
    approvalDigest: digestApproval(approval),
    target,
    limits,
    submittedAt: "2026-01-01T00:00:01.000Z",
    ...overrides
  };
}

async function collect(events: AsyncIterable<LifecycleEvent>): Promise<LifecycleEvent[]> {
  const result: LifecycleEvent[] = [];
  for await (const event of events) result.push(event);
  return result;
}

describe("fixed capability and strict parameter contracts", () => {
  it("exposes only a closed, versioned capability catalogue", () => {
    assert.deepEqual(Object.keys(capabilityCatalogue), [
      "mcpwn.nmap.host-discovery.v1",
      "mcpwn.nmap.service-version.v1",
      "mcpwn.nmap.tcp-port-discovery.v1",
      "mcpwn.nmap.tcp-port-state.v1",
      "mcpwn.nmap.http-metadata.v1",
      "mcpwn.nmap.tls-certificate.v1",
      "mcpwn.nmap.tls-ciphers.v1"
    ]);
    assert.equal(Object.isFrozen(capabilityCatalogue), true);
  });

  it("rejects generic tools, commands, raw arguments and extra destinations", () => {
    for (const extra of [
      { toolName: "nmap" },
      { command: "nmap 192.168.1.1" },
      { args: ["--script", "vuln"] },
      { destination: "192.168.1.1" }
    ]) {
      assert.equal(canonicalProposalBindingSchema.safeParse({ ...proposal, ...extra }).success, false);
    }
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      capabilityId: "nmap",
      parameters: proposal.parameters
    }).success, false);
  });

  it("enforces capability-specific, bounded parameters", () => {
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      parameters: { ports: [22, 22], transport: "tcp", intensity: 2 }
    }).success, false);
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      parameters: { ports: [22], transport: "tcp", intensity: 2, extraArgs: "-A" }
    }).success, false);
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      capabilityId: "mcpwn.nmap.host-discovery.v1",
      parameters: { probe: "tcp-syn" }
    }).success, false);
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      capabilityId: "mcpwn.nmap.tcp-port-discovery.v1",
      parameters: { profile: "all-tcp", maxRate: 2_000 }
    }).success, false);
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      capabilityId: "mcpwn.nmap.http-metadata.v1",
      parameters: { ports: [80], transport: "tcp", profile: "headers-title", script: "vuln" }
    }).success, false);
    assert.equal(canonicalProposalBindingSchema.safeParse({
      ...proposal,
      capabilityId: "mcpwn.nmap.tls-ciphers.v1",
      parameters: { ports: [443, 8443, 9443], transport: "tcp", profile: "cipher-posture" }
    }).success, false);
  });

  it("requires a backend scope-registry resolution and matching address family", () => {
    assert.equal(resolvedTargetSchema.safeParse(request().target).success, true);
    assert.equal(resolvedTargetSchema.safeParse({
      ...request().target, resolutionSource: "model"
    }).success, false);
    assert.equal(resolvedTargetSchema.safeParse({
      ...request().target, addressFamily: "ipv6"
    }).success, false);
  });
});

describe("canonical approval binding", () => {
  it("produces stable digests independent of object key insertion order", () => {
    const reordered = {
      parameters: proposal.parameters,
      requestedAt: proposal.requestedAt,
      requestedBy: proposal.requestedBy,
      policyVersion: proposal.policyVersion,
      targetId: proposal.targetId,
      missionId: proposal.missionId,
      proposalId: proposal.proposalId,
      capabilityId: proposal.capabilityId,
      contractVersion: proposal.contractVersion
    } as CanonicalProposalBinding;
    assert.equal(digestProposal(reordered), digestProposal(proposal));
    assert.match(EXECUTOR_SCHEMA_HASH, /^[a-f0-9]{64}$/);
  });

  it("accepts an exact, unexpired proposal/approval/target binding", () => {
    assert.deepEqual(
      validateBrokerExecutionRequest(request(), new Date("2026-01-01T00:00:02.000Z")),
      request()
    );
  });

  it("denies proposal mutation after approval", () => {
    const mutated = {
      ...request(),
      proposal: { ...proposal, parameters: { ports: [80], transport: "tcp", intensity: 2 } }
    } as BrokerExecutionRequest;
    assert.throws(
      () => validateBrokerExecutionRequest(mutated, new Date("2026-01-01T00:00:02.000Z")),
      (error: unknown) => error instanceof ExecutionContractError &&
        error.code === "PROPOSAL_DIGEST_MISMATCH"
    );

    const approvalDigestDrift = request();
    approvalDigestDrift.approval.approvedBy = "other-operator";
    assert.throws(
      () => validateBrokerExecutionRequest(
        approvalDigestDrift,
        new Date("2026-01-01T00:00:02.000Z")
      ),
      (error: unknown) => error instanceof ExecutionContractError &&
        error.code === "APPROVAL_DIGEST_MISMATCH"
    );
  });

  it("denies a rebound target, expired approval, and unknown request fields", () => {
    assert.throws(
      () => validateBrokerExecutionRequest({
        ...request(), target: { ...request().target, targetId: "target-2" }
      }, new Date("2026-01-01T00:00:02.000Z")),
      (error: unknown) => error instanceof ExecutionContractError &&
        error.code === "TARGET_RESOLUTION_MISMATCH"
    );
    assert.throws(
      () => validateBrokerExecutionRequest(request(), new Date("2026-01-01T00:10:00.000Z")),
      (error: unknown) => error instanceof ExecutionContractError &&
        error.code === "APPROVAL_EXPIRED"
    );

    for (const approvalMutation of [
      { proposalDigest: "f".repeat(64) },
      { missionId: "mission-2" },
      { targetId: "target-2" },
      { capabilityId: "mcpwn.nmap.host-discovery.v1" as const }
    ]) {
      const base = request();
      const approval = { ...base.approval, ...approvalMutation };
      const rebound = {
        ...base,
        approval,
        approvalDigest: digestApproval(approval)
      };
      assert.throws(
        () => validateBrokerExecutionRequest(
          rebound,
          new Date("2026-01-01T00:00:02.000Z")
        ),
        (error: unknown) => error instanceof ExecutionContractError &&
          error.code === "APPROVAL_BINDING_MISMATCH"
      );
    }

    for (const rebound of [
      {
        ...request(),
        target: { ...request().target, canonicalAddress: "192.0.2.26" }
      },
      {
        ...request(),
        target: { ...request().target, scopeRevision: "scope-revision-8" }
      },
      {
        ...request(),
        limits: { ...request().limits, timeoutMs: 2_000 }
      }
    ]) {
      assert.throws(
        () => validateBrokerExecutionRequest(
          rebound,
          new Date("2026-01-01T00:00:02.000Z")
        ),
        (error: unknown) => error instanceof ExecutionContractError &&
          error.code === "APPROVAL_BINDING_MISMATCH"
      );
    }

    assert.equal(brokerExecutionRequestSchema.safeParse({ ...request(), rawCommand: "nmap" }).success, false);
    assert.equal(brokerExecutionRequestSchema.safeParse({
      ...request(),
      approval: { ...request().approval, maxUses: 2 }
    }).success, false);
    for (const limits of [
      { timeoutMs: 120_001, maxOutputBytes: 64, maxEvidenceBytes: 4_096 },
      { timeoutMs: 1_000, maxOutputBytes: 1_000_001, maxEvidenceBytes: 4_096 },
      { timeoutMs: 1_000, maxOutputBytes: 64, maxEvidenceBytes: 5_000_001 }
    ]) {
      assert.equal(brokerExecutionRequestSchema.safeParse({
        ...request(),
        limits
      }).success, false);
    }
  });
});

describe("bounded lifecycle and fake executor", () => {
  it("rejects inaccurate or oversized output chunks", () => {
    const chunk = {
      sequence: 0, stream: "stdout", encoding: "utf8",
      content: "£", contentBytes: 1, cumulativeOutputBytes: 1, truncated: false
    };
    assert.equal(outputChunkSchema.safeParse(chunk).success, false);
    assert.equal(outputChunkSchema.safeParse({
      ...chunk, content: "x".repeat(16_385), contentBytes: 16_385,
      cumulativeOutputBytes: 16_385
    }).success, false);
  });

  it("reports health with schema identity and execution disabled", async () => {
    const fake = new FakeExecutor();
    const health = await fake.health();
    assert.equal(adapterHealthSchema.safeParse(health).success, true);
    assert.equal(health.schemaHash, EXECUTOR_SCHEMA_HASH);
    assert.equal(health.executionEnabled, false);
    assert.equal(fake.didSpawnProcess, false);
    assert.equal(fake.didOpenNetworkConnection, false);
  });

  it("emits deterministic success, evidence and bounded output events", async () => {
    const fake = new FakeExecutor({
      "proposal-1": { outcome: "success", output: ["hello", "x".repeat(100)] }
    });
    const events = await collect((await fake.start(request())).events);
    assert.deepEqual(events.map((event) => event.type), [
      "accepted", "started", "output", "output", "evidence_stored", "completed"
    ]);
    const outputs = events.filter((event) => event.type === "output");
    assert.equal(outputs[1]?.chunk.truncated, true);
    assert.equal(outputs[1]?.chunk.cumulativeOutputBytes, 64);
    const completed = events.at(-1);
    assert.equal(completed?.type, "completed");
    if (completed?.type === "completed") assert.equal(completed.outputBytes, 64);
  });

  it("emits deterministic timeout without evidence", async () => {
    const fake = new FakeExecutor({ "proposal-1": { outcome: "timeout", output: ["partial"] } });
    const events = await collect((await fake.start(request())).events);
    assert.deepEqual(events.map((event) => event.type), ["accepted", "started", "output", "timed_out"]);
  });

  it("supports cancellation and idempotent terminal cancellation", async () => {
    const fake = new FakeExecutor({ "proposal-1": { outcome: "await-cancel", output: ["partial"] } });
    const handle = await fake.start(request());
    assert.equal((await handle.cancel("emergency-stop")).status, "cancel-requested");
    assert.equal((await handle.cancel("operator")).status, "already-terminal");
    const events = await collect(handle.events);
    assert.deepEqual(events.map((event) => event.type), ["accepted", "started", "output", "cancelled"]);
    assert.equal(events.at(-1)?.type === "cancelled" && events.at(-1)?.reason, "emergency-stop");
  });
});
