import {
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptionsWithoutStdio
} from "node:child_process";
import type { BrokerExecutionRequest } from "./schemas.js";
import {
  compileNmapTcpInvocation,
  type NmapTcpAdapterConfig,
  type NmapTcpInvocation
} from "./nmap-tcp-adapter.js";
import { WSL_DOCKER_EXECUTABLE } from "./trusted-executables.js";

export interface NmapTcpExecutionResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly outputBytes: number;
  readonly durationMs: number;
  readonly exitCode: number;
  readonly invocation: NmapTcpInvocation;
}

export class NmapTcpExecutionError extends Error {
  constructor(
    readonly code:
      | "SPAWN_FAILED"
      | "PROCESS_FAILED"
      | "OUTPUT_LIMIT_EXCEEDED"
      | "TIMED_OUT"
      | "CANCELLED",
    message: string
  ) {
    super(message);
    this.name = "NmapTcpExecutionError";
  }
}

type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio
) => ChildProcessWithoutNullStreams;

type CleanupContainer = (invocation: NmapTcpInvocation) => Promise<void>;

async function removeDockerContainer(invocation: NmapTcpInvocation): Promise<void> {
  await new Promise<void>((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(invocation.executable, [
        "--distribution", invocation.distro,
        "--exec", WSL_DOCKER_EXECUTABLE, "rm", "--force", invocation.containerName
      ], { shell: false, windowsHide: true, stdio: "ignore" });
    } catch {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 3_000);
    child.once("error", () => {
      clearTimeout(timer);
      resolve();
    });
    child.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

export class NmapTcpExecutor {
  constructor(
    private readonly config: NmapTcpAdapterConfig,
    private readonly spawnProcess: SpawnProcess = spawn,
    private readonly now: () => Date = () => new Date(),
    private readonly cleanupContainer: CleanupContainer = removeDockerContainer
  ) {}

  async execute(
    request: BrokerExecutionRequest,
    options: { readonly signal?: AbortSignal } = {}
  ): Promise<NmapTcpExecutionResult> {
    const startedAt = this.now();
    const invocation = compileNmapTcpInvocation(request, this.config, startedAt);
    if (options.signal?.aborted) throw new NmapTcpExecutionError("CANCELLED", "Target execution was cancelled");
    let child: ChildProcessWithoutNullStreams;
    try {
      child = this.spawnProcess(invocation.executable, [...invocation.args], invocation.spawnOptions);
    } catch {
      throw new NmapTcpExecutionError("SPAWN_FAILED", "Unable to start the restricted target adapter");
    }

    return await new Promise<NmapTcpExecutionResult>((resolve, reject) => {
      let settled = false;
      let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      let totalOutputBytes = 0;
      const terminate = (): void => {
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
        if (!child.killed) child.kill("SIGKILL");
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
      };
      const fail = (error: NmapTcpExecutionError): void => {
        if (settled) return;
        settled = true;
        cleanup();
        terminate();
        void this.cleanupContainer(invocation).finally(() => reject(error));
      };
      const append = (
        current: Buffer<ArrayBufferLike>,
        chunk: Buffer | string,
        limit: number
      ): Buffer<ArrayBufferLike> => {
        if (settled) return current;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const next = Buffer.concat([current, bytes]);
        if (next.byteLength > limit || totalOutputBytes + bytes.byteLength > request.limits.maxOutputBytes) {
          fail(new NmapTcpExecutionError("OUTPUT_LIMIT_EXCEEDED", "Restricted target output exceeded its limit"));
          return current;
        }
        totalOutputBytes += bytes.byteLength;
        return next;
      };
      const onAbort = (): void =>
        fail(new NmapTcpExecutionError("CANCELLED", "Target execution was cancelled"));
      const timer = setTimeout(
        () => fail(new NmapTcpExecutionError("TIMED_OUT", "Restricted target execution timed out")),
        invocation.timeoutMs
      );

      options.signal?.addEventListener("abort", onAbort, { once: true });
      child.once("error", () =>
        fail(new NmapTcpExecutionError("SPAWN_FAILED", "Unable to start the restricted target adapter"))
      );
      child.stdout.on("data", (chunk: Buffer | string) => {
        stdout = append(stdout, chunk, invocation.maxStdoutBytes);
      });
      child.stderr.on("data", (chunk: Buffer | string) => {
        stderr = append(stderr, chunk, invocation.maxStderrBytes);
      });
      child.once("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          fail(new NmapTcpExecutionError("PROCESS_FAILED", `Restricted target adapter exited with code ${code ?? -1}`));
          return;
        }
        settled = true;
        cleanup();
        const durationMs = Math.max(0, this.now().getTime() - startedAt.getTime());
        resolve({
          stdout: stdout.toString("utf8"),
          stderr: stderr.toString("utf8"),
          outputBytes: stdout.byteLength + stderr.byteLength,
          durationMs,
          exitCode: 0,
          invocation
        });
      });
    });
  }
}
