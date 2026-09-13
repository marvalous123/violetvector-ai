import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { capabilityDefinitions } from "@war-room/policy";
import { buildCapabilityCatalogue } from "./capability-catalogue.js";

describe("operator capability catalogue", () => {
  it("is unique, non-destructive, and fail-closed when execution is unavailable", () => {
    const catalogue = buildCapabilityCatalogue({
      targetExecutionEnabled: false,
      versionProofEnabled: false,
      emergencyStopState: "ready",
      edition: "professional"
    });
    assert.equal(new Set(catalogue.map((item) => item.id)).size, catalogue.length);
    for (const capabilityId of Object.keys(capabilityDefinitions)) {
      assert.equal(catalogue.some((item) => item.id === capabilityId), true, capabilityId);
    }
    assert.equal(catalogue.every((item) => item.destructive === false), true);
    assert.equal(
      catalogue.filter((item) => item.targetRequired).every((item) => item.status !== "enabled"),
      true
    );
    assert.equal(
      catalogue.filter((item) => item.status === "enabled").every((item) => item.riskTier === "T0"),
      true
    );
  });

  it("enables only wired target profiles and disables them during emergency stop", () => {
    const ready = buildCapabilityCatalogue({
      targetExecutionEnabled: true,
      versionProofEnabled: true,
      emergencyStopState: "ready",
      edition: "professional"
    });
    assert.equal(ready.find((item) => item.id === "network.tcp-port-state")?.status, "enabled");
    assert.equal(ready.find((item) => item.id === "tls.cipher-enumeration")?.riskTier, "T2");
    assert.equal(ready.find((item) => item.id === "simulation.credential-canary")?.status, "enabled");
    assert.equal(ready.find((item) => item.id === "simulation.inert-payload-triage")?.minimumEdition, "starter");

    const stopped = buildCapabilityCatalogue({
      targetExecutionEnabled: true,
      versionProofEnabled: true,
      emergencyStopState: "stop_requested",
      edition: "professional"
    });
    assert.equal(
      stopped.filter((item) => item.targetRequired).every((item) => item.status !== "enabled"),
      true
    );
  });

  it("keeps Starter safe while reserving advanced profiles for Professional", () => {
    const starter = buildCapabilityCatalogue({
      targetExecutionEnabled: true,
      versionProofEnabled: true,
      emergencyStopState: "ready",
      edition: "starter"
    });
    assert.equal(starter.find((item) => item.id === "network.tcp-port-state")?.status, "enabled");
    assert.equal(starter.find((item) => item.id === "network.service-version")?.status, "enabled");
    assert.equal(starter.find((item) => item.id === "simulation.evasion-detection")?.status, "enabled");
    assert.equal(starter.find((item) => item.id === "web.http-metadata")?.status, "unavailable");
    assert.equal(starter.find((item) => item.id === "network.tcp-port-discovery")?.status, "unavailable");
  });
});
