import assert from "node:assert/strict";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { digestApproval, digestExecutionBinding, digestProposal } from "./canonical.js";
import { NmapTcpExecutionError, NmapTcpExecutor } from "./nmap-tcp-executor.js";
import {
  EXECUTOR_CONTRACT_VERSION,
  type BrokerExecutionRequest,
  type CanonicalApprovalBinding,
  type CanonicalProposalBinding
} from "./schemas.js";
import { ExecutionContractError } from "./validate.js";
import { WSL_DOCKER_EXECUTABLE } from "./trusted-executables.js";

const IMAGE = "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3";

function request(): BrokerExecutionRequest {
  const proposal: CanonicalProposalBinding = {
    contractVersion: EXECUTOR_CONTRACT_VERSION,
    proposalId: "proposal-1",
    missionId: "mission-1",
    targetId: "redmi-1",
    policyVersion: "policy-v1",
    requestedBy: "operator",
    requestedAt: "2026-07-18T12:00:00.000Z",
    capabilityId: "mcpwn.nmap.service-version.v1",
    parameters: { ports: [80, 443], transport: "tcp", intensity: 1 }
  };
  const proposalDigest = digestProposal(proposal);
  const target = {
    targetId: proposal.targetId,
    canonicalAddress: "192.168.42.129",
    addressFamily: "ipv4" as const,
    resolutionSource: "scope-registry" as const,
    scopeRevision: "scope-1",
    resolvedAt: "2026-07-18T12:00:01.000Z"
  };
  const limits = { timeoutMs: 15_000, maxOutputBytes: 4096, maxEvidenceBytes: 4096 };
  const approval: CanonicalApprovalBinding = {
    contractVersion: EXECUTOR_CONTRACT_VERSION,
    approvalId: "approval-1",
    proposalDigest,
    executionBindingDigest: digestExecutionBinding({ target, limits }),
    missionId: proposal.missionId,
    targetId: proposal.targetId,
    capabilityId: proposal.capabilityId,
    approvedBy: "operator",
    approvedAt: "2026-07-18T12:00:01.000Z",
    expiresAt: "2026-07-18T12:10:00.000Z",
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
    submittedAt: "2026-07-18T12:00:02.000Z"
  };
}

function fakeChild() {
  const emitter = new EventEmitter();
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let killed = false;
  const child = emitter as unknown as ChildProcessWithoutNullStreams;
  Object.defineProperties(child, {
    stdin: { value: stdin },
    stdout: { value: stdout },
    stderr: { value: stderr },
    killed: { get: () => killed }
  });
  child.kill = (() => {
    killed = true;
    return true;
  }) as ChildProcessWithoutNullStreams["kill"];
  return { child, emitter, stdout, stderr, wasKilled: () => killed };
}

const config = {
  distro: "kali-linux",
  dockerExecutable: WSL_DOCKER_EXECUTABLE,
  imageReference: IMAGE,
  isolatedNetwork: "war-room-redmi-isolated",
  executionEnabled: true,
  isolation: {
    verified: true,
    exactTargetAddress: "192.168.42.129",
    verificationId: "redmi:test"
  },
  timeoutMs: 15_000,
  maxStdoutBytes: 4096,
  maxStderrBytes: 4096
};

describe("NmapTcpExecutor", () => {
  it("validates approval expiry against the executor clock before spawning", async () => {
    let spawnCount = 0;
    const spawnProcess = (() => {
      spawnCount += 1;
      return fakeChild().child;
    }) as ConstructorParameters<typeof NmapTcpExecutor>[1];
    const executor = new NmapTcpExecutor(
      config,
      spawnProcess,
      () => new Date("2026-07-18T12:10:00.000Z")
    );

    await assert.rejects(
      executor.execute(request()),
      (error: unknown) => error instanceof ExecutionContractError &&
        error.code === "APPROVAL_EXPIRED"
    );
    assert.equal(spawnCount, 0);
  });

  it("captures bounded output from the already-compiled direct argv", async () => {
    const fake = fakeChild();
    let capturedArgs: readonly string[] = [];
    const spawnProcess = ((_command: string, args: readonly string[]) => {
      capturedArgs = args;
      return fake.child;
    }) as ConstructorParameters<typeof NmapTcpExecutor>[1];
    const times = [
      new Date("2026-07-18T12:00:02.000Z"),
      new Date("2026-07-18T12:00:02.007Z")
    ];
    const executor = new NmapTcpExecutor(config, spawnProcess, () => times.shift()!);
    const pending = executor.execute(request());
    fake.stdout.write("<nmaprun/>");
    fake.stderr.write("bounded warning");
    fake.emitter.emit("close", 0);
    const result = await pending;
    assert.equal(result.stdout, "<nmaprun/>");
    assert.equal(result.stderr, "bounded warning");
    assert.equal(result.durationMs, 7);
    assert.deepEqual(capturedArgs.slice(-3), ["-oX", "-", "192.168.42.129"]);
    assert.equal(capturedArgs.includes("--network"), true);
    assert.equal(capturedArgs.includes("war-room-redmi-isolated"), true);
  });

  it("kills the child when the emergency AbortSignal fires", async () => {
    const fake = fakeChild();
    const spawnProcess = (() => fake.child) as ConstructorParameters<typeof NmapTcpExecutor>[1];
    let cleanupName = "";
    const executor = new NmapTcpExecutor(
      config,
      spawnProcess,
      () => new Date("2026-07-18T12:00:02.000Z"),
      async (invocation) => { cleanupName = invocation.containerName; }
    );
    const controller = new AbortController();
    const pending = executor.execute(request(), { signal: controller.signal });
    controller.abort();
    await assert.rejects(
      pending,
      (error: unknown) => error instanceof NmapTcpExecutionError && error.code === "CANCELLED"
    );
    assert.equal(fake.wasKilled(), true);
    assert.match(cleanupName, /^war-room-[a-f0-9]{24}$/);
  });

  it("enforces the combined stdout and stderr output budget", async () => {
    const fake = fakeChild();
    const spawnProcess = (() => fake.child) as ConstructorParameters<typeof NmapTcpExecutor>[1];
    let cleaned = false;
    const executor = new NmapTcpExecutor(
      config,
      spawnProcess,
      () => new Date("2026-07-18T12:00:02.000Z"),
      async () => { cleaned = true; }
    );
    const baseRequest = request();
    const limits = { ...baseRequest.limits, maxOutputBytes: 10 };
    const approval = {
      ...baseRequest.approval,
      executionBindingDigest: digestExecutionBinding({ target: baseRequest.target, limits })
    };
    const bounded = {
      ...baseRequest,
      limits,
      approval,
      approvalDigest: digestApproval(approval)
    };
    const pending = executor.execute(bounded);
    fake.stdout.write("123456");
    fake.stderr.write("78901");
    await assert.rejects(
      pending,
      (error: unknown) => error instanceof NmapTcpExecutionError && error.code === "OUTPUT_LIMIT_EXCEEDED"
    );
    assert.equal(fake.wasKilled(), true);
    assert.equal(cleaned, true);
  });
});
