import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertExactRedmiFirewall,
  parseExactUsbRoute,
  RedmiIsolationService,
  type WslRunner
} from "./redmi-isolation-service.js";

describe("exact Redmi USB route parsing", () => {
  it("accepts a direct exact-target route with a dynamic USB source address", () => {
    assert.deepEqual(
      parseExactUsbRoute(
        "192.168.42.129 dev eth5 src 192.168.42.132 uid 1000\n    cache"
      ),
      { interfaceName: "eth5", sourceAddress: "192.168.42.132" }
    );
  });

  it("rejects gateways, other targets, other subnets, and the target as source", () => {
    for (const route of [
      "192.168.42.129 via 192.168.0.1 dev eth4 src 192.168.0.124",
      "192.168.42.130 dev eth5 src 192.168.42.132",
      "192.168.42.129 dev eth5 src 192.168.41.132",
      "192.168.42.129 dev eth5 src 192.168.42.129"
    ]) {
      assert.throws(() => parseExactUsbRoute(route), /ISOLATION_ROUTE_MISMATCH/);
    }
  });
});

describe("exact Redmi firewall parsing", () => {
  const safeDockerUser = [
    "-N DOCKER-USER",
    "-A DOCKER-USER -i wr15-redmi -j WAR_ROOM_REDMI",
    "-A DOCKER-USER -j RETURN"
  ].join("\n");
  const safeRedmi = [
    "-N WAR_ROOM_REDMI",
    "-A WAR_ROOM_REDMI -d 192.168.42.129/32 -o eth5 -p tcp -j ACCEPT",
    "-A WAR_ROOM_REDMI -j DROP"
  ].join("\n");

  it("accepts only the first unique bridge jump and exact ordered target chain", () => {
    assert.doesNotThrow(() => assertExactRedmiFirewall(safeDockerUser, safeRedmi, "eth5"));
  });

  it("rejects bypasses, duplicates, extra rules, wrong interfaces, and reordered rules", () => {
    for (const [dockerUser, redmi, device] of [
      [`-N DOCKER-USER\n-A DOCKER-USER -i wr15-redmi -j ACCEPT\n${safeDockerUser}`, safeRedmi, "eth5"],
      [`${safeDockerUser}\n-A DOCKER-USER -i wr15-redmi -j WAR_ROOM_REDMI`, safeRedmi, "eth5"],
      [safeDockerUser, `${safeRedmi}\n-A WAR_ROOM_REDMI -j ACCEPT`, "eth5"],
      [safeDockerUser, safeRedmi.replace("-o eth5", "-o eth4"), "eth5"],
      [safeDockerUser, [
        "-N WAR_ROOM_REDMI",
        "-A WAR_ROOM_REDMI -j DROP",
        "-A WAR_ROOM_REDMI -d 192.168.42.129/32 -o eth5 -p tcp -j ACCEPT"
      ].join("\n"), "eth5"],
      [safeDockerUser, safeRedmi, "docker0"]
    ] as const) {
      assert.throws(() => assertExactRedmiFirewall(dockerUser, redmi, device), /ISOLATION_FIREWALL_MISMATCH/);
    }
  });
});

describe("bounded Redmi isolation verification", () => {
  it("runs the complete exact check with one shared deadline", async () => {
    const outputs = [
      `${"a".repeat(64)}|wr15-redmi|172.30.15.0/28|0`,
      "192.168.42.129 dev eth5 src 192.168.42.1 uid 1000\n    cache",
      "8: eth5 inet 192.168.42.1/24 brd 192.168.42.255 scope global eth5",
      "-N DOCKER-USER\n-A DOCKER-USER -i wr15-redmi -j WAR_ROOM_REDMI\n-A DOCKER-USER -j RETURN",
      "-N WAR_ROOM_REDMI\n-A WAR_ROOM_REDMI -d 192.168.42.129/32 -o eth5 -p tcp -j ACCEPT\n-A WAR_ROOM_REDMI -j DROP",
      "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3"
    ];
    const calls: Array<{
      args: readonly string[];
      timeoutMs: number | undefined;
      signal: AbortSignal | undefined;
    }> = [];
    const runner: WslRunner = async (args, timeoutMs, signal) => {
      calls.push({ args, timeoutMs, signal });
      return outputs[calls.length - 1]!;
    };

    const result = await new RedmiIsolationService(runner, 1_000).verify();

    assert.equal(result.targetAddress, "192.168.42.129");
    assert.equal(result.sourceAddress, "192.168.42.1");
    assert.equal(result.interfaceName, "eth5");
    assert.equal(calls.length, 6);
    assert.equal(calls.every((call) => call.timeoutMs === 20_000), true);
    assert.equal(calls.every((call) => call.signal instanceof AbortSignal), true);
    assert.deepEqual(calls[0]!.args.slice(0, 4), ["--exec", "/usr/bin/docker", "network", "inspect"]);
  });

  it("fails closed at the whole-verification deadline and starts no later check", async () => {
    let calls = 0;
    const runner: WslRunner = async (_args, _timeoutMs, signal) => {
      calls += 1;
      return await new Promise<string>((_resolve, reject) => {
        signal?.addEventListener(
          "abort",
          () => reject(new Error("ISOLATION_VERIFICATION_TIMED_OUT")),
          { once: true }
        );
      });
    };

    await assert.rejects(
      new RedmiIsolationService(runner, 10).verify(),
      /ISOLATION_VERIFICATION_TIMED_OUT/
    );
    assert.equal(calls, 1);
  });
});
