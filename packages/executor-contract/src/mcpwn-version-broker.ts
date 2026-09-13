import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { spawn, type ChildProcessWithoutNullStreams, type SpawnOptionsWithoutStdio } from "node:child_process";
import { posix, win32 } from "node:path";
import { z } from "zod";
import { WINDOWS_WSL_EXECUTABLE } from "./trusted-executables.js";

export const MCPWN_VERSION_CAPABILITY = "mcpwn.version.v1" as const;
const MCPWN_VERSION_TOOL = "nmap_version" as const;
const MAX_TIMEOUT_MS = 15_000;
const MAX_STREAM_BYTES = 65_536;

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const artifactSchema = z.object({
  hostPath: z.string().min(1),
  linuxPath: z.string().min(1).startsWith("/"),
  expectedSha256: sha256Schema
}).strict();

export const mcpwnVersionRequestSchema = z.object({
  capabilityId: z.literal(MCPWN_VERSION_CAPABILITY),
  parameters: z.object({}).strict()
}).strict();

const optionsSchema = z.object({
  distro: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._-]+$/),
  linuxWorkingDirectory: z.string().min(1).startsWith("/"),
  binary: artifactSchema,
  config: artifactSchema,
  timeoutMs: z.number().int().min(100).max(MAX_TIMEOUT_MS),
  maxStdoutBytes: z.number().int().min(1).max(MAX_STREAM_BYTES),
  maxStderrBytes: z.number().int().min(1).max(MAX_STREAM_BYTES)
}).strict().superRefine((value, context) => {
  if (posix.basename(value.config.linuxPath) !== "mcpwn.yaml" ||
      posix.dirname(value.config.linuxPath) !== posix.dirname(value.binary.linuxPath)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "MCPwn loads only a sibling mcpwn.yaml; pinned paths must match that layout"
    });
  }
  if (value.linuxWorkingDirectory !== posix.dirname(value.binary.linuxPath)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "The fixed working directory must contain the pinned MCPwn binary"
    });
  }
  if (value.binary.hostPath !== wslHostPath(value.distro, value.binary.linuxPath)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["binary", "hostPath"],
      message: "The hashed Windows path must name the exact WSL binary that will execute"
    });
  }
  if (value.config.hostPath !== wslHostPath(value.distro, value.config.linuxPath)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["config", "hostPath"],
      message: "The hashed Windows path must name the exact WSL configuration that MCPwn will load"
    });
  }
});

const toolResultSchema = z.object({
  content: z.array(z.object({
    type: z.literal("text"),
    text: z.string()
  }).passthrough()).min(1).max(16),
  isError: z.boolean().optional()
}).passthrough();

function wslHostPath(distro: string, linuxPath: string): string {
  return win32.join(
    `\\\\wsl.localhost\\${distro}`,
    ...linuxPath.split("/").filter(Boolean)
  );
}

export type McpwnVersionRequest = z.infer<typeof mcpwnVersionRequestSchema>;
export type McpwnPinnedArtifact = z.infer<typeof artifactSchema>;

export interface McpwnVersionBrokerOptions {
  readonly distro: string;
  readonly linuxWorkingDirectory: string;
  readonly binary: McpwnPinnedArtifact;
  readonly config: McpwnPinnedArtifact;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
}

export interface VersionExecutorStatus {
  readonly available: boolean;
  readonly versionProofEnabled: boolean;
  readonly executionEnabled: false;
  readonly binaryHashVerified: boolean;
  readonly configHashVerified: boolean;
}

export interface VersionExecutionResult {
  readonly capabilityId: typeof MCPWN_VERSION_CAPABILITY;
  readonly executionId: string;
  readonly output: string;
  readonly outputBytes: number;
  readonly durationMs: number;
  readonly binarySha256: string;
  readonly configSha256: string;
  readonly completedAt: string;
}

export interface VersionOnlyExecutor {
  status(): Promise<VersionExecutorStatus>;
  executeVersion(options?: { readonly signal?: AbortSignal }): Promise<VersionExecutionResult>;
}

export class McpwnVersionBrokerError extends Error {
  constructor(
    readonly code:
      | "INVALID_REQUEST"
      | "INVALID_CONFIGURATION"
      | "ARTIFACT_HASH_MISMATCH"
      | "ARTIFACT_NOT_REGULAR_FILE"
      | "ARTIFACT_UNAVAILABLE"
      | "SPAWN_FAILED"
      | "PROTOCOL_ERROR"
      | "OUTPUT_LIMIT_EXCEEDED"
      | "TIMED_OUT"
      | "CANCELLED",
    message: string
  ) {
    super(message);
    this.name = "McpwnVersionBrokerError";
  }
}

type SpawnMcpwn = (
  executable: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio
) => ChildProcessWithoutNullStreams;

interface BrokerDependencies {
  readonly spawnProcess?: SpawnMcpwn;
  readonly hashFile?: (path: string) => Promise<string>;
  readonly now?: () => Date;
  readonly createExecutionId?: () => string;
}

async function sha256File(path: string): Promise<string> {
  const metadata = await stat(path);
  if (!metadata.isFile()) {
    throw new McpwnVersionBrokerError("ARTIFACT_NOT_REGULAR_FILE", "Pinned artifact is not a regular file");
  }
  return await new Promise<string>((resolve, reject) => {
    const hash = createHash("sha256");
    const input = createReadStream(path);
    input.on("data", (chunk) => hash.update(chunk));
    input.once("error", reject);
    input.once("end", () => resolve(hash.digest("hex")));
  });
}

function protocolId(message: unknown): string | number | undefined {
  if (typeof message !== "object" || message === null) return undefined;
  const id = Reflect.get(message, "id");
  return typeof id === "string" || typeof id === "number" ? id : undefined;
}

function protocolValue(message: unknown, key: "error" | "result"): unknown {
  return typeof message === "object" && message !== null ? Reflect.get(message, key) : undefined;
}

/**
 * Tiny MCPwn boundary exposing only the fixed, argument-free version proof.
 * It cannot accept a target, tool name, command, or operating-system argv.
 */
export class McpwnVersionBroker implements VersionOnlyExecutor {
  readonly #options: z.infer<typeof optionsSchema>;
  readonly #spawnProcess: SpawnMcpwn;
  readonly #hashFile: (path: string) => Promise<string>;
  readonly #now: () => Date;
  readonly #createExecutionId: () => string;

  constructor(options: McpwnVersionBrokerOptions, dependencies: BrokerDependencies = {}) {
    const parsed = optionsSchema.safeParse(options);
    if (!parsed.success) {
      throw new McpwnVersionBrokerError("INVALID_CONFIGURATION", "Invalid MCPwn version broker configuration");
    }
    this.#options = parsed.data;
    this.#spawnProcess = dependencies.spawnProcess ?? spawn;
    this.#hashFile = dependencies.hashFile ?? sha256File;
    this.#now = dependencies.now ?? (() => new Date());
    this.#createExecutionId = dependencies.createExecutionId ?? randomUUID;
  }

  async status(): Promise<VersionExecutorStatus> {
    try {
      await this.#verifyArtifacts();
      return {
        available: true,
        versionProofEnabled: true,
        executionEnabled: false,
        binaryHashVerified: true,
        configHashVerified: true
      };
    } catch {
      return {
        available: false,
        versionProofEnabled: false,
        executionEnabled: false,
        binaryHashVerified: false,
        configHashVerified: false
      };
    }
  }

  async executeVersion(options: { readonly signal?: AbortSignal } = {}): Promise<VersionExecutionResult> {
    return await this.execute(
      { capabilityId: MCPWN_VERSION_CAPABILITY, parameters: {} },
      options.signal
    );
  }

  async execute(request: unknown, signal?: AbortSignal): Promise<VersionExecutionResult> {
    if (!mcpwnVersionRequestSchema.safeParse(request).success) {
      throw new McpwnVersionBrokerError("INVALID_REQUEST", "Only mcpwn.version.v1 with empty parameters is allowed");
    }
    if (signal?.aborted) {
      throw new McpwnVersionBrokerError("CANCELLED", "MCPwn version check was cancelled");
    }
    const startedAt = this.#now();
    const hashes = await this.#verifyArtifacts();
    if (signal?.aborted) {
      throw new McpwnVersionBrokerError("CANCELLED", "MCPwn version check was cancelled");
    }
    const protocol = await this.#runProtocol(signal);
    const completedAt = this.#now();
    return {
      capabilityId: MCPWN_VERSION_CAPABILITY,
      executionId: this.#createExecutionId(),
      output: protocol.result,
      outputBytes: protocol.outputBytes,
      durationMs: Math.max(0, completedAt.getTime() - startedAt.getTime()),
      binarySha256: hashes.binarySha256,
      configSha256: hashes.configSha256,
      completedAt: completedAt.toISOString()
    };
  }

  async #verifyArtifacts(): Promise<{ binarySha256: string; configSha256: string }> {
    let binarySha256: string;
    let configSha256: string;
    try {
      [binarySha256, configSha256] = await Promise.all([
        this.#hashFile(this.#options.binary.hostPath),
        this.#hashFile(this.#options.config.hostPath)
      ]);
    } catch (error) {
      if (error instanceof McpwnVersionBrokerError) throw error;
      throw new McpwnVersionBrokerError("ARTIFACT_UNAVAILABLE", "Pinned MCPwn artifact is unavailable");
    }
    if (binarySha256 !== this.#options.binary.expectedSha256 ||
        configSha256 !== this.#options.config.expectedSha256) {
      throw new McpwnVersionBrokerError("ARTIFACT_HASH_MISMATCH", "Pinned MCPwn artifact hash mismatch");
    }
    return { binarySha256, configSha256 };
  }

  async #runProtocol(signal?: AbortSignal): Promise<{ result: string; outputBytes: number }> {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = this.#spawnProcess(WINDOWS_WSL_EXECUTABLE, [
        "--distribution", this.#options.distro,
        "--cd", this.#options.linuxWorkingDirectory,
        "--exec", this.#options.binary.linuxPath
      ], { shell: false, windowsHide: true });
    } catch {
      throw new McpwnVersionBrokerError("SPAWN_FAILED", "Unable to start the pinned MCPwn process");
    }

    return await new Promise((resolve, reject) => {
      let settled = false;
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let lineBuffer = "";
      let phase: "initialize" | "call" = "initialize";

      const terminate = (): void => {
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
        if (!child.killed) child.kill("SIGKILL");
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      const fail = (error: McpwnVersionBrokerError): void => {
        if (settled) return;
        settled = true;
        cleanup();
        terminate();
        reject(error);
      };
      const succeed = (result: string): void => {
        if (settled) return;
        settled = true;
        cleanup();
        child.stdin.end();
        terminate();
        resolve({ result, outputBytes: Buffer.byteLength(result, "utf8") });
      };
      const writeJson = (message: unknown): void => {
        child.stdin.write(`${JSON.stringify(message)}\n`);
      };
      const handleLine = (line: string): void => {
        if (line.trim() === "") return;
        let message: unknown;
        try {
          message = JSON.parse(line);
        } catch {
          fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn returned malformed JSON"));
          return;
        }
        if (typeof message !== "object" || message === null ||
            Reflect.get(message, "jsonrpc") !== "2.0") {
          fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn returned an invalid JSON-RPC response"));
          return;
        }
        if (protocolValue(message, "error") !== undefined) {
          fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn returned a JSON-RPC error"));
          return;
        }
        const id = protocolId(message);
        if (phase === "initialize" && id === 1) {
          if (protocolValue(message, "result") === undefined) {
            fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn initialize response has no result"));
            return;
          }
          phase = "call";
          writeJson({ jsonrpc: "2.0", method: "notifications/initialized" });
          writeJson({
            jsonrpc: "2.0", id: 2, method: "tools/call",
            params: { name: MCPWN_VERSION_TOOL, arguments: {} }
          });
        } else if (phase === "call" && id === 2) {
          const result = toolResultSchema.safeParse(protocolValue(message, "result"));
          if (!result.success || result.data.isError === true) {
            fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn tool response is invalid or failed"));
            return;
          }
          succeed(result.data.content.map((item) => item.text).join("\n"));
        }
      };
      const onAbort = (): void => {
        fail(new McpwnVersionBrokerError("CANCELLED", "MCPwn version check was cancelled"));
      };
      const timer = setTimeout(() => {
        fail(new McpwnVersionBrokerError("TIMED_OUT", "MCPwn version check timed out"));
      }, this.#options.timeoutMs);

      signal?.addEventListener("abort", onAbort, { once: true });
      child.once("error", () => {
        fail(new McpwnVersionBrokerError("SPAWN_FAILED", "Unable to start the pinned MCPwn process"));
      });
      child.once("exit", () => {
        if (!settled) fail(new McpwnVersionBrokerError("PROTOCOL_ERROR", "MCPwn exited before completion"));
      });
      child.stderr.on("data", (chunk: Buffer | string) => {
        stderrBytes += Buffer.byteLength(chunk);
        if (stderrBytes > this.#options.maxStderrBytes) {
          fail(new McpwnVersionBrokerError("OUTPUT_LIMIT_EXCEEDED", "MCPwn stderr limit exceeded"));
        }
      });
      child.stdout.on("data", (chunk: Buffer | string) => {
        stdoutBytes += Buffer.byteLength(chunk);
        if (stdoutBytes > this.#options.maxStdoutBytes) {
          fail(new McpwnVersionBrokerError("OUTPUT_LIMIT_EXCEEDED", "MCPwn stdout limit exceeded"));
          return;
        }
        lineBuffer += chunk.toString();
        let newline = lineBuffer.indexOf("\n");
        while (newline >= 0 && !settled) {
          const line = lineBuffer.slice(0, newline).replace(/\r$/, "");
          lineBuffer = lineBuffer.slice(newline + 1);
          handleLine(line);
          newline = lineBuffer.indexOf("\n");
        }
      });

      writeJson({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: {
          protocolVersion: "2025-06-18", capabilities: {},
          clientInfo: { name: "war-room-version-broker", version: "1.0.0" }
        }
      });
    });
  }
}
