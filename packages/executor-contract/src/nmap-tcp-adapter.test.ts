import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  compileNmapTcpInvocation,
  digestApproval,
  digestExecutionBinding,
  digestProposal,
  NmapTcpAdapterContractError,
  nmapTcpAdapterConfigSchema,
  WINDOWS_WSL_EXECUTABLE,
  WSL_DOCKER_EXECUTABLE,
  type BrokerExecutionRequest,
  type CanonicalApprovalBinding,
  type CanonicalProposalBinding,
  type NmapTcpAdapterConfig
} from "./index.js";

const IMAGE = `war-room/nmap@sha256:${"a".repeat(64)}`;
const LOCAL_IMAGE_ID = `sha256:${"b".repeat(64)}`;

const proposal: CanonicalProposalBinding = {
  contractVersion: "executor-contract.v2",
  proposalId: "proposal-nmap-1",
  missionId: "mission-1",
  targetId: "redmi-1",
  policyVersion: "policy-v1",
  requestedBy: "operator-1",
  requestedAt: "2026-07-17T10:00:00.000Z",
  capabilityId: "mcpwn.nmap.service-version.v1",
  parameters: { ports: [443, 22], transport: "tcp", intensity: 2 }
};

function request(overrides: Partial<BrokerExecutionRequest> = {}): BrokerExecutionRequest {
  const proposalDigest = digestProposal(proposal);
  const target = {
    targetId: "redmi-1",
    canonicalAddress: "192.0.2.25",
    addressFamily: "ipv4" as const,
    resolutionSource: "scope-registry" as const,
    scopeRevision: "scope-7",
    resolvedAt: "2026-07-17T10:00:00.000Z"
  };
  const limits = { timeoutMs: 12_000, maxOutputBytes: 32_768, maxEvidenceBytes: 65_536 };
  const approval: CanonicalApprovalBinding = {
    contractVersion: "executor-contract.v2",
    approvalId: "approval-nmap-1",
    proposalDigest,
    executionBindingDigest: digestExecutionBinding({ target, limits }),
    missionId: proposal.missionId,
    targetId: proposal.targetId,
    capabilityId: proposal.capabilityId,
    approvedBy: "operator-1",
    approvedAt: "2026-07-17T10:00:00.000Z",
    expiresAt: "2026-07-17T10:10:00.000Z",
    maxUses: 1
  };
  return {
    executionId: "execution-nmap-1",
    proposal,
    proposalDigest,
    approval,
    approvalDigest: digestApproval(approval),
    target,
    limits,
    submittedAt: "2026-07-17T10:00:01.000Z",
    ...overrides
  };
}

function requestFor(boundProposal: CanonicalProposalBinding, timeoutMs: number): BrokerExecutionRequest {
  const proposalDigest = digestProposal(boundProposal);
  const base = request();
  const limits = { timeoutMs, maxOutputBytes: 32_768, maxEvidenceBytes: 65_536 };
  const approval: CanonicalApprovalBinding = {
    contractVersion: "executor-contract.v2",
    approvalId: `approval-${boundProposal.proposalId}`,
    proposalDigest,
    executionBindingDigest: digestExecutionBinding({ target: base.target, limits }),
    missionId: boundProposal.missionId,
    targetId: boundProposal.targetId,
    capabilityId: boundProposal.capabilityId,
    approvedBy: "operator-1",
    approvedAt: "2026-07-17T10:00:00.000Z",
    expiresAt: "2026-07-17T10:10:00.000Z",
    maxUses: 1
  };
  return {
    ...base,
    executionId: `execution-${boundProposal.proposalId}`,
    proposal: boundProposal,
    proposalDigest,
    approval,
    approvalDigest: digestApproval(approval),
    limits
  };
}

function config(overrides: Partial<NmapTcpAdapterConfig> = {}): NmapTcpAdapterConfig {
  return {
    distro: "kali-linux",
    dockerExecutable: WSL_DOCKER_EXECUTABLE,
    imageReference: IMAGE,
    isolatedNetwork: "war-room-redmi-isolated",
    executionEnabled: false,
    isolation: {
      verified: false,
      exactTargetAddress: null,
      verificationId: null
    },
    timeoutMs: 15_000,
    maxStdoutBytes: 65_536,
    maxStderrBytes: 16_384,
    ...overrides
  };
}

describe("exact-target Nmap TCP adapter contract", () => {
  it("is disabled until a complete exact-target isolation verification exists", () => {
    assert.throws(
      () => compileNmapTcpInvocation(request(), config(), new Date("2026-07-17T10:00:02.000Z")),
      (error: unknown) => error instanceof NmapTcpAdapterContractError &&
        error.code === "EXECUTION_DISABLED"
    );
    assert.equal(nmapTcpAdapterConfigSchema.safeParse(config({
      executionEnabled: true
    })).success, false);
  });

  it("compiles one digest-pinned direct WSL/Docker argv with fixed Nmap flags", () => {
    const invocation = compileNmapTcpInvocation(
      request(),
      config({
        executionEnabled: true,
        isolation: {
          verified: true,
          exactTargetAddress: "192.0.2.25",
          verificationId: "isolation-proof-1"
        }
      }),
      new Date("2026-07-17T10:00:02.000Z")
    );

    assert.equal(invocation.executable, WINDOWS_WSL_EXECUTABLE);
    assert.deepEqual(invocation.spawnOptions, { shell: false, windowsHide: true });
    assert.equal(invocation.imageReference, IMAGE);
    assert.equal(invocation.timeoutMs, 12_000);
    assert.equal(invocation.maxStdoutBytes, 32_768);
    assert.equal(invocation.maxStderrBytes, 16_384);
    assert.deepEqual(invocation.args, [
      "--distribution", "kali-linux",
      "--exec", WSL_DOCKER_EXECUTABLE,
      "run",
      "--rm",
      "--name", invocation.containerName,
      "--pull=never",
      "--network", "war-room-redmi-isolated",
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt", "no-new-privileges",
      "--user", "65534:65534",
      "--pids-limit", "64",
      "--memory", "128m",
      "--cpus", "0.5",
      "--entrypoint", "/usr/bin/nmap",
      IMAGE,
      "-n",
      "-Pn",
      "-sT",
      "-sV",
      "--version-intensity", "2",
      "--max-retries", "1",
      "--host-timeout", "12000ms",
      "-p", "22,443",
      "-oX", "-",
      "192.0.2.25"
    ]);
    assert.match(invocation.containerName, /^war-room-[a-f0-9]{24}$/);

    assert.equal(nmapTcpAdapterConfigSchema.safeParse(config({
      imageReference: LOCAL_IMAGE_ID
    })).success, true);
  });

  it("compiles the all-TCP profile without service, UDP, script or raw argument controls", () => {
    const discoveryProposal: CanonicalProposalBinding = {
      ...proposal,
      proposalId: "proposal-all-tcp-1",
      capabilityId: "mcpwn.nmap.tcp-port-discovery.v1",
      parameters: { profile: "all-tcp", maxRate: 1_000 }
    };
    const proposalDigest = digestProposal(discoveryProposal);
    const base = request();
    const limits = { timeoutMs: 120_000, maxOutputBytes: 32_768, maxEvidenceBytes: 65_536 };
    const approval: CanonicalApprovalBinding = {
      contractVersion: "executor-contract.v2",
      approvalId: "approval-all-tcp-1",
      proposalDigest,
      executionBindingDigest: digestExecutionBinding({ target: base.target, limits }),
      missionId: discoveryProposal.missionId,
      targetId: discoveryProposal.targetId,
      capabilityId: discoveryProposal.capabilityId,
      approvedBy: "operator-1",
      approvedAt: "2026-07-17T10:00:00.000Z",
      expiresAt: "2026-07-17T10:10:00.000Z",
      maxUses: 1
    };
    const discoveryRequest: BrokerExecutionRequest = {
      ...base,
      executionId: "execution-all-tcp-1",
      proposal: discoveryProposal,
      proposalDigest,
      approval,
      approvalDigest: digestApproval(approval),
      limits
    };
    const invocation = compileNmapTcpInvocation(
      discoveryRequest,
      config({
        executionEnabled: true,
        timeoutMs: 120_000,
        isolation: {
          verified: true,
          exactTargetAddress: "192.0.2.25",
          verificationId: "isolation-proof-all-tcp"
        }
      }),
      new Date("2026-07-17T10:00:02.000Z")
    );
    assert.deepEqual(invocation.args.slice(-16), [
      IMAGE,
      "-n",
      "-Pn",
      "-sT",
      "-T3",
      "--max-rate", "1000",
      "--max-retries", "0",
      "--host-timeout", "120000ms",
      "-p-",
      "--open",
      "-oX", "-",
      "192.0.2.25"
    ]);
    assert.equal(invocation.args.includes("-sV"), false);
    assert.equal(invocation.args.includes("-sU"), false);
    assert.equal(invocation.args.includes("--script"), false);
  });

  it("compiles only the fixed low-noise and allowlisted metadata profiles", () => {
    const cases: Array<{
      proposal: CanonicalProposalBinding;
      timeoutMs: number;
      required: string[];
      forbidden: string[];
    }> = [
      {
        proposal: {
          ...proposal,
          proposalId: "low-noise",
          capabilityId: "mcpwn.nmap.tcp-port-state.v1",
          parameters: { ports: [443, 22], transport: "tcp", profile: "low-noise" }
        },
        timeoutMs: 20_000,
        required: ["--max-rate", "20", "--scan-delay", "250ms", "--reason", "22,443"],
        forbidden: ["--script", "-sV"]
      },
      {
        proposal: {
          ...proposal,
          proposalId: "http-metadata",
          capabilityId: "mcpwn.nmap.http-metadata.v1",
          parameters: { ports: [8080, 80], transport: "tcp", profile: "headers-title" }
        },
        timeoutMs: 30_000,
        required: ["--script", "http-title,http-headers", "80,8080"],
        forbidden: ["vuln", "--script-args"]
      },
      {
        proposal: {
          ...proposal,
          proposalId: "tls-certificate",
          capabilityId: "mcpwn.nmap.tls-certificate.v1",
          parameters: { ports: [443], transport: "tcp", profile: "certificate" }
        },
        timeoutMs: 30_000,
        required: ["--script", "ssl-cert", "443"],
        forbidden: ["ssl-enum-ciphers", "--script-args"]
      },
      {
        proposal: {
          ...proposal,
          proposalId: "tls-ciphers",
          capabilityId: "mcpwn.nmap.tls-ciphers.v1",
          parameters: { ports: [8443, 443], transport: "tcp", profile: "cipher-posture" }
        },
        timeoutMs: 60_000,
        required: ["--script", "ssl-enum-ciphers", "443,8443"],
        forbidden: ["vuln", "--script-args"]
      }
    ];
    for (const item of cases) {
      const invocation = compileNmapTcpInvocation(
        requestFor(item.proposal, item.timeoutMs),
        config({
          executionEnabled: true,
          timeoutMs: item.timeoutMs,
          isolation: {
            verified: true,
            exactTargetAddress: "192.0.2.25",
            verificationId: `isolation-${item.proposal.proposalId}`
          }
        }),
        new Date("2026-07-17T10:00:02.000Z")
      );
      for (const value of item.required) assert.equal(invocation.args.includes(value), true, value);
      for (const value of item.forbidden) assert.equal(invocation.args.includes(value), false, value);
      assert.equal(invocation.args.at(-1), "192.0.2.25");
      assert.equal(invocation.timeoutMs, item.timeoutMs);
    }
  });

  it("rejects unpinned images, target mismatches, subnets, URLs, UDP, scripts and excessive bounds", () => {
    for (const imageReference of ["war-room/nmap:latest", "sha256:a", `war-room/nmap@sha256:${"A".repeat(64)}`]) {
      assert.equal(nmapTcpAdapterConfigSchema.safeParse(config({ imageReference })).success, false);
    }

    const enabled = config({
      executionEnabled: true,
      isolation: {
        verified: true,
        exactTargetAddress: "192.0.2.26",
        verificationId: "isolation-proof-1"
      }
    });
    assert.throws(
      () => compileNmapTcpInvocation(request(), enabled, new Date("2026-07-17T10:00:02.000Z")),
      (error: unknown) => error instanceof NmapTcpAdapterContractError &&
        error.code === "TARGET_ISOLATION_MISMATCH"
    );

    for (const canonicalAddress of ["192.0.2.0/24", "https://192.0.2.25", "192.000.2.25"]) {
      const mutated = { ...request(), target: { ...request().target, canonicalAddress } };
      assert.throws(() => compileNmapTcpInvocation(
        mutated,
        config({
          executionEnabled: true,
          isolation: {
            verified: true,
            exactTargetAddress: "192.0.2.25",
            verificationId: "isolation-proof-1"
          }
        }),
        new Date("2026-07-17T10:00:02.000Z")
      ));
    }

    for (const parameters of [
      { ...proposal.parameters, transport: "udp" },
      { ...proposal.parameters, intensity: 3 },
      { ...proposal.parameters, scripts: ["vuln"] },
      { ...proposal.parameters, args: ["-A"] },
      { ...proposal.parameters, ports: Array.from({ length: 33 }, (_, index) => index + 1) }
    ]) {
      const mutatedProposal = { ...proposal, parameters };
      assert.throws(() => digestProposal(mutatedProposal as CanonicalProposalBinding));
    }
  });
});
