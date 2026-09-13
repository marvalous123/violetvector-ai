import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  WINDOWS_WSL_EXECUTABLE,
  WSL_DOCKER_EXECUTABLE,
  WSL_IP_EXECUTABLE
} from "@war-room/executor-contract";

export interface RedmiIsolationAttestation {
  readonly verificationId: string;
  readonly targetAddress: "192.168.42.129";
  readonly sourceAddress: string;
  readonly interfaceName: string;
  readonly networkName: "war-room-redmi-isolated";
  readonly bridgeName: "wr15-redmi";
  readonly imageId: "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3";
  readonly verifiedAt: string;
}

export interface TargetIsolationVerifier {
  verify(): Promise<RedmiIsolationAttestation>;
}

const DISTRO = "kali-linux";
const TARGET = "192.168.42.129";
const NETWORK = "war-room-redmi-isolated";
const BRIDGE = "wr15-redmi";
const SUBNET = "172.30.15.0/28";
const IMAGE = "sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3";
const WSL_COMMAND_TIMEOUT_MS = 20_000;
const ISOLATION_VERIFICATION_TIMEOUT_MS = 45_000;
const WSL_OUTPUT_LIMIT_BYTES = 16_384;

export function parseExactUsbRoute(route: string): { sourceAddress: string; interfaceName: string } {
  const match = route.trim().match(
    /^192\.168\.42\.129 dev (eth[0-9]+) src (192\.168\.42\.([0-9]{1,3}))(?:\s|$)/
  );
  if (!match) throw new Error("ISOLATION_ROUTE_MISMATCH");
  const sourceOctet = Number(match[3]);
  if (!Number.isInteger(sourceOctet) || sourceOctet < 1 || sourceOctet > 254 || sourceOctet === 129) {
    throw new Error("ISOLATION_ROUTE_MISMATCH");
  }
  return { interfaceName: match[1]!, sourceAddress: match[2]! };
}

export function assertExactRedmiFirewall(
  dockerUserRules: string,
  redmiRules: string,
  interfaceName: string
): void {
  if (!/^eth[0-9]+$/.test(interfaceName)) throw new Error("ISOLATION_FIREWALL_MISMATCH");
  const jump = `-A DOCKER-USER -i ${BRIDGE} -j WAR_ROOM_REDMI`;
  const dockerRules = dockerUserRules.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("-A "));
  const bridgeRules = dockerRules.filter((line) => line.includes(`-i ${BRIDGE}`) || line.includes(`-o ${BRIDGE}`));
  if (dockerRules[0] !== jump || bridgeRules.length !== 1 || bridgeRules[0] !== jump) {
    throw new Error("ISOLATION_FIREWALL_MISMATCH");
  }

  const exactChain = [
    `-A WAR_ROOM_REDMI -d ${TARGET}/32 -o ${interfaceName} -p tcp -j ACCEPT`,
    "-A WAR_ROOM_REDMI -j DROP"
  ];
  const actualChain = redmiRules.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("-A "));
  if (actualChain.length !== exactChain.length ||
      actualChain.some((line, index) => line !== exactChain[index])) {
    throw new Error("ISOLATION_FIREWALL_MISMATCH");
  }
}

export type WslRunner = (
  args: readonly string[],
  timeoutMs?: number,
  signal?: AbortSignal
) => Promise<string>;

function runWsl(
  args: readonly string[],
  timeoutMs = WSL_COMMAND_TIMEOUT_MS,
  signal?: AbortSignal
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(WINDOWS_WSL_EXECUTABLE, ["--distribution", DISTRO, ...args], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let terminatingError: Error | undefined;
    let terminationFallback: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      clearTimeout(timer);
      if (terminationFallback) clearTimeout(terminationFallback);
      signal?.removeEventListener("abort", onAbort);
    };
    const rejectOnce = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const terminate = (error: Error) => {
      if (settled || terminatingError) return;
      terminatingError = error;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      if (!child.killed && child.kill("SIGKILL")) {
        terminationFallback = setTimeout(() => rejectOnce(error), 2_000);
        return;
      }
      rejectOnce(error);
    };
    const onAbort = () => terminate(new Error("ISOLATION_VERIFICATION_TIMED_OUT"));
    const timer = setTimeout(() => {
      terminate(new Error("ISOLATION_VERIFICATION_TIMED_OUT"));
    }, timeoutMs);
    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
      if (Buffer.byteLength(stdout, "utf8") > WSL_OUTPUT_LIMIT_BYTES) {
        terminate(new Error("ISOLATION_VERIFICATION_OUTPUT_LIMIT_EXCEEDED"));
      }
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
      if (Buffer.byteLength(stderr, "utf8") > WSL_OUTPUT_LIMIT_BYTES) {
        terminate(new Error("ISOLATION_VERIFICATION_OUTPUT_LIMIT_EXCEEDED"));
      }
    });
    child.once("error", () => {
      rejectOnce(terminatingError ?? new Error("ISOLATION_VERIFIER_UNAVAILABLE"));
    });
    child.once("close", (code) => {
      if (settled) return;
      if (terminatingError) {
        rejectOnce(terminatingError);
        return;
      }
      settled = true;
      cleanup();
      if (code !== 0) {
        reject(new Error(`ISOLATION_VERIFICATION_FAILED:${stderr.trim().slice(0, 200)}`));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

export class RedmiIsolationService implements TargetIsolationVerifier {
  constructor(
    private readonly runner: WslRunner = runWsl,
    private readonly verificationTimeoutMs = ISOLATION_VERIFICATION_TIMEOUT_MS
  ) {}

  async verify(): Promise<RedmiIsolationAttestation> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("ISOLATION_VERIFICATION_TIMED_OUT"));
      }, this.verificationTimeoutMs);
    });
    try {
      return await Promise.race([this.verifyWithinDeadline(controller.signal), deadline]);
    } finally {
      if (timer) clearTimeout(timer);
      controller.abort();
    }
  }

  private async verifyWithinDeadline(signal: AbortSignal): Promise<RedmiIsolationAttestation> {
    const run = (args: readonly string[]) => this.runner(args, WSL_COMMAND_TIMEOUT_MS, signal);
    const network = await run([
      "--exec", WSL_DOCKER_EXECUTABLE, "network", "inspect", NETWORK,
      "--format", '{{.Id}}|{{index .Options "com.docker.network.bridge.name"}}|{{(index .IPAM.Config 0).Subnet}}|{{len .Containers}}'
    ]);
    const [networkId, bridge, subnet, containers] = network.split("|");
    if (!/^[a-f0-9]{64}$/.test(networkId ?? "") ||
        bridge !== BRIDGE ||
        subnet !== SUBNET ||
        containers !== "0") {
      throw new Error("ISOLATION_NETWORK_MISMATCH");
    }

    const route = await run(["--exec", WSL_IP_EXECUTABLE, "-4", "route", "get", TARGET]);
    const { interfaceName, sourceAddress } = parseExactUsbRoute(route);
    const address = await run(["--exec", WSL_IP_EXECUTABLE, "-4", "-o", "addr", "show", "dev", interfaceName, "scope", "global"]);
    if (!new RegExp(`\\binet ${sourceAddress.replaceAll(".", "\\.")}/24\\b`).test(address)) {
      throw new Error("ISOLATION_ROUTE_MISMATCH");
    }

    const dockerUserRules = await run([
      "--user", "root", "--exec", "/usr/sbin/iptables", "-S", "DOCKER-USER"
    ]);
    const redmiRules = await run([
      "--user", "root", "--exec", "/usr/sbin/iptables", "-S", "WAR_ROOM_REDMI"
    ]);
    assertExactRedmiFirewall(dockerUserRules, redmiRules, interfaceName);

    const image = await run(["--exec", WSL_DOCKER_EXECUTABLE, "image", "inspect", IMAGE, "--format", "{{.Id}}"]);
    if (image !== IMAGE) throw new Error("ISOLATION_IMAGE_MISMATCH");

    const verifiedAt = new Date().toISOString();
    const verificationId = `redmi:${createHash("sha256")
      .update([networkId, route, image, verifiedAt].join("|"), "utf8")
      .digest("hex")
      .slice(0, 32)}`;
    return {
      verificationId,
      targetAddress: TARGET,
      sourceAddress,
      interfaceName,
      networkName: NETWORK,
      bridgeName: BRIDGE,
      imageId: IMAGE,
      verifiedAt
    };
  }
}
