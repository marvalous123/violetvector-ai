import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import {
  MCPWN_VERSION_CAPABILITY,
  McpwnVersionBroker,
  McpwnVersionBrokerError,
  type McpwnVersionBrokerOptions
} from "./mcpwn-version-broker.js";
import { WINDOWS_WSL_EXECUTABLE } from "./trusted-executables.js";

const BINARY_HASH = "a".repeat(64);
const CONFIG_HASH = "b".repeat(64);

function options(overrides: Partial<McpwnVersionBrokerOptions> = {}): McpwnVersionBrokerOptions {
  return {
    distro: "kali-linux",
    linuxWorkingDirectory: "/opt/war-room",
    binary: {
      hostPath: "\\\\wsl.localhost\\kali-linux\\opt\\war-room\\mcpwn",
      linuxPath: "/opt/war-room/mcpwn",
      expectedSha256: BINARY_HASH
    },
    config: {
      hostPath: "\\\\wsl.localhost\\kali-linux\\opt\\war-room\\mcpwn.yaml",
      linuxPath: "/opt/war-room/mcpwn.yaml",
      expectedSha256: CONFIG_HASH
    },
    timeoutMs: 1_000,
    maxStdoutBytes: 4_096,
    maxStderrBytes: 1_024,
    ...overrides
  };
}

class FakeChild extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  killed = false;
  killSignal: NodeJS.Signals | number | undefined;

  kill(signal?: NodeJS.Signals | number): boolean {
    this.killed = true;
    this.killSignal = signal;
    return true;
  }
}

function asChild(child: FakeChild): ChildProcessWithoutNullStreams {
  return child as unknown as ChildProcessWithoutNullStreams;
}

function protocolChild(): FakeChild {
  const child = new FakeChild();
  let input = "";
  child.stdin.on("data", (chunk) => {
    input += chunk.toString();
    const lines = input.split("\n");
    input = lines.pop() ?? "";
    for (const line of lines) {
      const request = JSON.parse(line) as { id?: number; method?: string };
      if (request.id === 1) {
        child.stdout.write('{"jsonrpc":"2.0","id":1,');
        queueMicrotask(() => child.stdout.write('"result":{"protocolVersion":"2025-06-18"}}\r\n'));
      }
      if (request.id === 2 && request.method === "tools/call") {
        child.stdout.write(`${JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          result: { content: [{ type: "text", text: "Nmap version 7.99" }], isError: false }
        })}\n`);
      }
    }
  });
  return child;
}

function dependencies(child: FakeChild, onSpawn?: (
  executable: string,
  args: readonly string[],
  spawnOptions: object
) => void) {
  return {
    hashFile: async (path: string) => path.endsWith("mcpwn.yaml") ? CONFIG_HASH : BINARY_HASH,
    spawnProcess: (executable: string, args: readonly string[], spawnOptions: object) => {
      onSpawn?.(executable, args, spawnOptions);
      return asChild(child);
    },
    now: (() => {
      const times = [
        new Date("2026-07-17T10:00:00.000Z"),
        new Date("2026-07-17T10:00:00.025Z")
      ];
      return () => times.shift() ?? new Date("2026-07-17T10:00:00.025Z");
    })(),
    createExecutionId: () => "version-proof-1"
  };
}

describe("McpwnVersionBroker", () => {
  it("executes only the fixed version tool through direct wsl argv", async () => {
    const child = protocolChild();
    let spawnRecord: { executable: string; args: readonly string[]; options: object } | undefined;
    const broker = new McpwnVersionBroker(options(), dependencies(
      child,
      (executable, args, spawnOptions) => {
        spawnRecord = { executable, args, options: spawnOptions };
      }
    ));

    const result = await broker.executeVersion();

    assert.equal(result.capabilityId, MCPWN_VERSION_CAPABILITY);
    assert.equal(result.executionId, "version-proof-1");
    assert.equal(result.durationMs, 25);
    assert.equal(result.output, "Nmap version 7.99");
    assert.equal(result.outputBytes, 17);
    assert.equal(result.binarySha256, BINARY_HASH);
    assert.equal(result.configSha256, CONFIG_HASH);
    assert.deepEqual(spawnRecord, {
      executable: WINDOWS_WSL_EXECUTABLE,
      args: [
        "--distribution", "kali-linux",
        "--cd", "/opt/war-room",
        "--exec", "/opt/war-room/mcpwn"
      ],
      options: { shell: false, windowsHide: true }
    });
    assert.equal(child.killed, true);
    assert.equal(child.killSignal, "SIGKILL");
  });

  it("rejects unknown capabilities, caller args, targets, and parameters before spawn", async () => {
    let spawnCount = 0;
    const broker = new McpwnVersionBroker(options(), dependencies(
      protocolChild(),
      () => { spawnCount += 1; }
    ));
    const denied = [
      { capabilityId: "mcpwn.nmap.service-version.v1", parameters: {} },
      { capabilityId: MCPWN_VERSION_CAPABILITY, parameters: { args: ["-A"] } },
      { capabilityId: MCPWN_VERSION_CAPABILITY, parameters: {}, target: "192.168.1.1" },
      { capabilityId: MCPWN_VERSION_CAPABILITY, parameters: {}, command: "id" }
    ];
    for (const request of denied) {
      await assert.rejects(
        broker.execute(request),
        (error: unknown) => error instanceof McpwnVersionBrokerError && error.code === "INVALID_REQUEST"
      );
    }
    assert.equal(spawnCount, 0);
  });

  it("does not spawn when either pinned artifact hash differs", async () => {
    let spawnCount = 0;
    const broker = new McpwnVersionBroker(options(), {
      hashFile: async (path) => path.endsWith("mcpwn.yaml") ? "c".repeat(64) : BINARY_HASH,
      spawnProcess: () => {
        spawnCount += 1;
        return asChild(protocolChild());
      }
    });
    assert.deepEqual(await broker.status(), {
      available: false,
      versionProofEnabled: false,
      executionEnabled: false,
      binaryHashVerified: false,
      configHashVerified: false
    });
    await assert.rejects(
      broker.executeVersion(),
      (error: unknown) => error instanceof McpwnVersionBrokerError &&
        error.code === "ARTIFACT_HASH_MISMATCH"
    );
    assert.equal(spawnCount, 0);
  });

  it("kills the MCPwn process when the AbortSignal is cancelled", async () => {
    const child = new FakeChild();
    const broker = new McpwnVersionBroker(options(), dependencies(child));
    const controller = new AbortController();
    const pending = broker.executeVersion({ signal: controller.signal });
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await assert.rejects(
      pending,
      (error: unknown) => error instanceof McpwnVersionBrokerError && error.code === "CANCELLED"
    );
    assert.equal(child.killed, true);
  });

  it("kills on malformed JSON and output limits", async () => {
    const malformed = new FakeChild();
    const malformedBroker = new McpwnVersionBroker(options(), dependencies(malformed));
    const malformedPending = malformedBroker.executeVersion();
    await new Promise((resolve) => setImmediate(resolve));
    malformed.stdout.write("not-json\n");
    await assert.rejects(
      malformedPending,
      (error: unknown) => error instanceof McpwnVersionBrokerError && error.code === "PROTOCOL_ERROR"
    );
    assert.equal(malformed.killed, true);

    const noisy = new FakeChild();
    const noisyBroker = new McpwnVersionBroker(
      options({ maxStderrBytes: 4 }),
      dependencies(noisy)
    );
    const noisyPending = noisyBroker.executeVersion();
    await new Promise((resolve) => setImmediate(resolve));
    noisy.stderr.write("12345");
    await assert.rejects(
      noisyPending,
      (error: unknown) => error instanceof McpwnVersionBrokerError &&
        error.code === "OUTPUT_LIMIT_EXCEEDED"
    );
    assert.equal(noisy.killed, true);
  });

  it("enforces a hard timeout and the sibling configuration layout", async () => {
    assert.throws(
      () => new McpwnVersionBroker(options({
        config: {
          ...options().config,
          linuxPath: "/tmp/attacker.yaml"
        }
      })),
      (error: unknown) => error instanceof McpwnVersionBrokerError &&
        error.code === "INVALID_CONFIGURATION"
    );
    assert.throws(
      () => new McpwnVersionBroker(options({
        binary: {
          ...options().binary,
          hostPath: "\\\\wsl.localhost\\kali-linux\\tmp\\different-mcpwn"
        }
      })),
      (error: unknown) => error instanceof McpwnVersionBrokerError &&
        error.code === "INVALID_CONFIGURATION"
    );

    const child = new FakeChild();
    const broker = new McpwnVersionBroker(options({ timeoutMs: 100 }), dependencies(child));
    await assert.rejects(
      broker.executeVersion(),
      (error: unknown) => error instanceof McpwnVersionBrokerError && error.code === "TIMED_OUT"
    );
    assert.equal(child.killed, true);
  });
});
