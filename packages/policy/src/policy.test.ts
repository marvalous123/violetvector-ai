import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluateProposal } from "./policy.js";
import { actionProposalSchema, getCapabilitySchemaHash } from "./schemas.js";
import { canonicalizeTarget, TargetParseError } from "./target.js";
import { classifyTargetRange } from "./target-range.js";
import type { ActionProposal, Scope } from "./schemas.js";

const now = new Date("2026-07-16T12:00:00.000Z");

function scope(address = "8.8.8.8", isolatedPrivateTargetApproved = false): Scope {
  return {
    scopeVersionId: "scope-v1",
    missionId: "mission-1",
    startsAt: "2026-07-16T11:00:00.000Z",
    expiresAt: "2026-07-16T13:00:00.000Z",
    policyVersion: "policy-v1",
    targets: [{ id: "target-1", address, isolatedPrivateTargetApproved }]
  };
}

function proposal(overrides: Partial<ActionProposal> = {}): ActionProposal {
  return {
    proposalId: "proposal-1",
    missionId: "mission-1",
    runId: "run-1",
    targetId: "target-1",
    capabilityId: "network.discovery",
    riskTier: "T1",
    parameters: { profile: "version-only" },
    timeoutMs: 5_000,
    maxOutputBytes: 32_768,
    ...overrides
  };
}

describe("canonicalizeTarget", () => {
  for (const address of ["127.0.0.1", "169.254.1.2", "224.0.0.1", "0.0.0.0", "100.64.0.1"]) {
    it(`classifies non-public address ${address}`, () => {
      assert.notEqual(canonicalizeTarget(address).classification, "public");
    });
  }

  for (const address of ["127.1", "2130706433", "0177.0.0.1", "127.00.0.1", "example.com", "https://1.2.3.4"]) {
    it(`rejects ambiguous target ${address}`, () => {
      assert.throws(() => canonicalizeTarget(address), TargetParseError);
    });
  }

  it("rejects CIDR and IPv4-mapped IPv6", () => {
    assert.throws(() => canonicalizeTarget("192.168.1.0/24"), /CIDR/);
    assert.throws(() => canonicalizeTarget("::ffff:192.168.1.7"), /mapped/);
  });

  it("normalizes public IPv6 and classifies unique-local IPv6 as private", () => {
    assert.deepEqual(canonicalizeTarget("2606:4700:4700:0:0:0:0:1111"), {
      address: "2606:4700:4700:0:0:0:0:1111",
      family: "ipv6",
      classification: "public"
    });
    assert.equal(canonicalizeTarget("fd00::7").classification, "private");
    assert.equal(canonicalizeTarget("::1").classification, "loopback");
  });

  it("keeps a generated boundary corpus out of the public target class", () => {
    const reservedRanges = [
      ["10.0.0.0", "private"],
      ["10.255.255.255", "private"],
      ["172.16.0.0", "private"],
      ["172.31.255.255", "private"],
      ["192.168.0.0", "private"],
      ["192.168.255.255", "private"],
      ["100.64.0.0", "carrier-grade"],
      ["100.127.255.255", "carrier-grade"],
      ["127.0.0.0", "loopback"],
      ["127.255.255.255", "loopback"],
      ["169.254.0.0", "link-local"],
      ["169.254.255.255", "link-local"],
      ["224.0.0.0", "multicast"],
      ["239.255.255.255", "multicast"],
      ["0.0.0.0", "unspecified"],
      ["255.255.255.255", "broadcast"],
      ["192.0.2.1", "reserved"],
      ["fc00::", "private"],
      ["fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "private"],
      ["fe80::1", "link-local"],
      ["ff02::1", "multicast"]
    ] as const;

    for (const [address, expected] of reservedRanges) {
      assert.equal(canonicalizeTarget(address).classification, expected, address);
    }

    for (const address of [" 8.8.8.8", "8.8.8.8 ", "08.8.8.8", "8.008.8.8", "8.8.8.008", "8.8.8.8\u0000"]) {
      assert.throws(() => canonicalizeTarget(address), TargetParseError, address);
    }
    assert.equal(classifyTargetRange("futureIpaddrRange"), "reserved");
  });
});

describe("evaluateProposal", () => {
  it("requires approval for an exact active public target", () => {
    assert.deepEqual(evaluateProposal({ proposal: proposal(), scope: scope(), now }), {
      effect: "REQUIRE_APPROVAL",
      reason: "APPROVAL_REQUIRED_T1",
      message: "Exact scoped T1 action requires a fresh parameter-bound approval",
      canonicalTarget: "8.8.8.8",
      policyVersion: "policy-v1"
    });
  });

  it("denies an unknown target ID", () => {
    assert.equal(evaluateProposal({ proposal: proposal({ targetId: "invented" }), scope: scope(), now }).reason, "TARGET_NOT_IN_SCOPE");

    const multipleTargets = scope();
    multipleTargets.targets.push({
      id: "target-2",
      address: "1.1.1.1",
      isolatedPrivateTargetApproved: false
    });
    assert.equal(
      evaluateProposal({
        proposal: proposal({ targetId: "target-2" }),
        scope: multipleTargets,
        now
      }).canonicalTarget,
      "1.1.1.1"
    );

    const duplicateTargetIds = scope();
    duplicateTargetIds.targets.push({
      id: "target-1",
      address: "1.1.1.1",
      isolatedPrivateTargetApproved: false
    });
    assert.equal(
      evaluateProposal({ proposal: proposal(), scope: duplicateTargetIds, now }).reason,
      "INVALID_SCOPE"
    );
  });

  it("denies private scope unless isolation was explicitly approved", () => {
    assert.equal(evaluateProposal({ proposal: proposal(), scope: scope("192.168.50.4"), now }).reason, "PRIVATE_TARGET_NOT_ISOLATED");
    assert.equal(evaluateProposal({ proposal: proposal(), scope: scope("192.168.50.4", true), now }).effect, "REQUIRE_APPROVAL");
  });

  it("still denies loopback, link-local and Tailscale ranges when isolation is set", () => {
    for (const address of ["127.0.0.1", "169.254.5.5", "100.64.0.1"]) {
      assert.equal(evaluateProposal({ proposal: proposal(), scope: scope(address, true), now }).reason, "TARGET_RESERVED_DENIED");
    }
  });

  it("denies expired scope and mismatched mission", () => {
    assert.equal(evaluateProposal({ proposal: proposal(), scope: scope(), now: new Date("2026-07-16T14:00:00Z") }).reason, "SCOPE_NOT_ACTIVE");
    assert.equal(evaluateProposal({
      proposal: proposal(),
      scope: scope(),
      now: new Date("2026-07-16T13:00:00Z")
    }).reason, "SCOPE_NOT_ACTIVE");
    assert.equal(evaluateProposal({
      proposal: proposal(),
      scope: scope(),
      now: new Date("2026-07-16T11:00:00Z")
    }).effect, "REQUIRE_APPROVAL");
    assert.equal(evaluateProposal({ proposal: proposal({ missionId: "other" }), scope: scope(), now }).reason, "MISSION_MISMATCH");
  });

  it("denies a future authorization window and risk-tier downgrade", () => {
    assert.equal(
      evaluateProposal({ proposal: proposal(), scope: scope(), now: new Date("2026-07-16T10:00:00Z") }).reason,
      "SCOPE_NOT_ACTIVE"
    );
    assert.equal(evaluateProposal({ proposal: proposal({ riskTier: "T0" }), scope: scope(), now }).reason, "RISK_TIER_MISMATCH");
  });

  it("fails closed on unknown proposal properties", () => {
    const poisoned = { ...proposal(), destination: "192.168.1.1" } as ActionProposal;
    assert.equal(evaluateProposal({ proposal: poisoned, scope: scope(), now }).reason, "INVALID_PROPOSAL");
  });

  it("uses closed capability parameters and a deterministic backend schema identity", () => {
    assert.equal(actionProposalSchema.safeParse({
      ...proposal(), parameters: { profile: "version-only", extraArgs: "-A" }
    }).success, false);
    assert.equal(actionProposalSchema.safeParse({
      ...proposal(), parameters: { profile: "arbitrary" }
    }).success, false);
    assert.match(getCapabilitySchemaHash("network.discovery"), /^[a-f0-9]{64}$/);
    assert.equal(
      getCapabilitySchemaHash("network.discovery"),
      getCapabilitySchemaHash("network.discovery")
    );
  });

  it("allows only bounded TCP service-version parameters for the disabled T1 adapter", () => {
    const bounded: ActionProposal = {
      ...proposal(),
      capabilityId: "network.service-version",
      parameters: { ports: [22, 443], transport: "tcp", intensity: 2 }
    };
    assert.equal(evaluateProposal({ proposal: bounded, scope: scope(), now }).effect, "REQUIRE_APPROVAL");
    assert.match(getCapabilitySchemaHash("network.service-version"), /^[a-f0-9]{64}$/);
    for (const parameters of [
      { ports: [22, 22], transport: "tcp", intensity: 1 },
      { ports: [22], transport: "udp", intensity: 1 },
      { ports: [22], transport: "tcp", intensity: 3 },
      { ports: [22], transport: "tcp", intensity: 1, args: ["-A"] },
      { ports: Array.from({ length: 33 }, (_, index) => index + 1), transport: "tcp", intensity: 1 }
    ]) {
      assert.equal(actionProposalSchema.safeParse({ ...bounded, parameters }).success, false);
    }
  });

  it("allows only the fixed all-TCP discovery profile and rate", () => {
    const bounded: ActionProposal = {
      ...proposal(),
      capabilityId: "network.tcp-port-discovery",
      timeoutMs: 120_000,
      parameters: { profile: "all-tcp", maxRate: 1_000 }
    };
    assert.equal(evaluateProposal({ proposal: bounded, scope: scope(), now }).effect, "REQUIRE_APPROVAL");
    assert.match(getCapabilitySchemaHash("network.tcp-port-discovery"), /^[a-f0-9]{64}$/);
    for (const parameters of [
      { profile: "top-ports", maxRate: 1_000 },
      { profile: "all-tcp", maxRate: 2_000 },
      { profile: "all-tcp", maxRate: 1_000, udp: true },
      { profile: "all-tcp", maxRate: 1_000, args: ["-A"] }
    ]) {
      assert.equal(actionProposalSchema.safeParse({ ...bounded, parameters }).success, false);
    }
  });

  it("enforces fixed low-noise, HTTP, certificate, and T2 cipher profiles", () => {
    const profiles: Array<{
      capabilityId: ActionProposal["capabilityId"];
      riskTier: ActionProposal["riskTier"];
      parameters: Record<string, unknown>;
    }> = [
      {
        capabilityId: "network.tcp-port-state",
        riskTier: "T1",
        parameters: { ports: [22, 443], transport: "tcp", profile: "low-noise" }
      },
      {
        capabilityId: "web.http-metadata",
        riskTier: "T1",
        parameters: { ports: [80, 443], transport: "tcp", profile: "headers-title" }
      },
      {
        capabilityId: "tls.certificate-metadata",
        riskTier: "T1",
        parameters: { ports: [443], transport: "tcp", profile: "certificate" }
      },
      {
        capabilityId: "tls.cipher-enumeration",
        riskTier: "T2",
        parameters: { ports: [443], transport: "tcp", profile: "cipher-posture" }
      }
    ];
    for (const profile of profiles) {
      const bounded = actionProposalSchema.parse({
        ...proposal(),
        capabilityId: profile.capabilityId,
        riskTier: profile.riskTier,
        parameters: profile.parameters
      });
      assert.equal(evaluateProposal({ proposal: bounded, scope: scope(), now }).effect, "REQUIRE_APPROVAL");
      assert.match(getCapabilitySchemaHash(profile.capabilityId), /^[a-f0-9]{64}$/);
      assert.equal(actionProposalSchema.safeParse({
        ...bounded,
        parameters: { ...profile.parameters, script: "vuln" }
      }).success, false);
    }

    const cipher = actionProposalSchema.parse({
      ...proposal(),
      capabilityId: "tls.cipher-enumeration",
      riskTier: "T2",
      parameters: { ports: [443], transport: "tcp", profile: "cipher-posture" }
    });
    assert.equal(
      evaluateProposal({ proposal: { ...cipher, riskTier: "T1" }, scope: scope(), now }).reason,
      "RISK_TIER_MISMATCH"
    );
    assert.equal(actionProposalSchema.safeParse({
      ...cipher,
      parameters: { ports: [443, 8443, 9443], transport: "tcp", profile: "cipher-posture" }
    }).success, false);
  });
});
