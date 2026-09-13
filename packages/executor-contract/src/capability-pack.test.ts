import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { capabilityPackManifestSchema, validateCapabilityPackManifest } from "./capability-pack.js";

const hash = "a".repeat(64);
const safePack = {
  manifestVersion: "war-room-capability-pack.v1",
  packId: "example.http-posture",
  name: "Example HTTP posture",
  version: "1.0.0",
  capabilityId: "local.example.http-posture.v1",
  adapterId: "example-http-posture",
  riskTier: "T1",
  approvalPolicy: "fresh-single-use",
  targetRequired: true,
  destructive: false,
  parameterSchemaHash: hash,
  sourceHash: hash,
  permissions: {
    network: "exact-target",
    process: "reviewed-adapter",
    filesystem: "evidence-only",
    credentialAccess: false,
    payloadExecution: false,
    evasionControls: false
  },
  limits: {
    timeoutMs: 10_000,
    maxOutputBytes: 32_768,
    maxEvidenceBytes: 65_536,
    maxRequests: 1
  },
  evidenceMediaTypes: ["application/json"]
};

describe("capability pack manifest", () => {
  it("accepts a reviewed exact-target pack with closed permissions and budgets", () => {
    const parsed = validateCapabilityPackManifest(safePack);
    assert.equal(parsed.capabilityId, "local.example.http-posture.v1");
    assert.equal(parsed.destructive, false);
  });

  it("rejects arbitrary code, unsafe permissions, unknown fields, and unapproved target access", () => {
    for (const mutation of [
      { command: "powershell.exe" },
      { script: "Invoke-Expression" },
      { payload: "base64" },
      { destructive: true },
      { permissions: { ...safePack.permissions, credentialAccess: true } },
      { permissions: { ...safePack.permissions, payloadExecution: true } },
      { permissions: { ...safePack.permissions, evasionControls: true } },
      { permissions: { ...safePack.permissions, commandChannel: true } },
      { permissions: { ...safePack.permissions, network: "none" } },
      { limits: { ...safePack.limits, timeoutMs: 120_001 } },
      { limits: { ...safePack.limits, maxOutputBytes: 1_000_001 } },
      { limits: { ...safePack.limits, maxEvidenceBytes: 5_000_001 } },
      { limits: { ...safePack.limits, maxRequests: 17 } },
      { limits: { ...safePack.limits, unbounded: true } },
      { approvalPolicy: "none" },
      { targetRequired: false }
    ]) {
      const candidate = {
        ...safePack,
        ...mutation
      };
      assert.equal(capabilityPackManifestSchema.safeParse(candidate).success, false);
    }
  });

  it("keeps T0 packs offline and process-free", () => {
    assert.equal(capabilityPackManifestSchema.safeParse({
      ...safePack,
      riskTier: "T0",
      approvalPolicy: "none",
      targetRequired: false,
      permissions: {
        ...safePack.permissions,
        network: "none",
        process: "none",
        filesystem: "evidence-only"
      }
    }).success, true);
    assert.equal(capabilityPackManifestSchema.safeParse({
      ...safePack,
      riskTier: "T0",
      approvalPolicy: "none",
      targetRequired: false
    }).success, false);
    assert.equal(capabilityPackManifestSchema.safeParse({
      ...safePack,
      riskTier: "T0",
      approvalPolicy: "none",
      targetRequired: false,
      permissions: {
        ...safePack.permissions,
        network: "none",
        process: "reviewed-adapter"
      }
    }).success, false);
  });
});
