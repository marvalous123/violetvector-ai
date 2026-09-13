import type { SpawnOptionsWithoutStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { isIPv4 } from "node:net";
import { z } from "zod";
import type { BrokerExecutionRequest } from "./schemas.js";
import { validateBrokerExecutionRequest } from "./validate.js";
import { WINDOWS_WSL_EXECUTABLE, WSL_DOCKER_EXECUTABLE } from "./trusted-executables.js";

export const NMAP_TCP_SERVICE_VERSION_CAPABILITY = "mcpwn.nmap.service-version.v1" as const;
export const NMAP_TCP_PORT_DISCOVERY_CAPABILITY = "mcpwn.nmap.tcp-port-discovery.v1" as const;
export const NMAP_TCP_PORT_STATE_CAPABILITY = "mcpwn.nmap.tcp-port-state.v1" as const;
export const NMAP_HTTP_METADATA_CAPABILITY = "mcpwn.nmap.http-metadata.v1" as const;
export const NMAP_TLS_CERTIFICATE_CAPABILITY = "mcpwn.nmap.tls-certificate.v1" as const;
export const NMAP_TLS_CIPHERS_CAPABILITY = "mcpwn.nmap.tls-ciphers.v1" as const;
export const MAX_NMAP_TCP_PORTS = 32;
export const MAX_NMAP_VERSION_INTENSITY = 2;
export const MAX_NMAP_TIMEOUT_MS = 120_000;
export const MAX_NMAP_STREAM_BYTES = 262_144;

const repositoryDigestPattern = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$/;
const localImageIdPattern = /^sha256:[a-f0-9]{64}$/;
const imageReferenceSchema = z.string().refine(
  (value) => repositoryDigestPattern.test(value) || localImageIdPattern.test(value),
  "container image must be an immutable repository digest or local sha256 image ID"
);

const canonicalIpv4Schema = z.string().superRefine((address, context) => {
  const octets = address.split(".");
  const canonical = octets.length === 4 &&
    octets.every((octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
  if (!canonical || !isIPv4(address)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "target must be one canonical IPv4 address" });
  }
});

export const nmapTcpAdapterConfigSchema = z.object({
  distro: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._-]+$/),
  dockerExecutable: z.literal(WSL_DOCKER_EXECUTABLE),
  imageReference: imageReferenceSchema,
  isolatedNetwork: z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/),
  executionEnabled: z.boolean(),
  isolation: z.object({
    verified: z.boolean(),
    exactTargetAddress: canonicalIpv4Schema.nullable(),
    verificationId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/).nullable()
  }).strict(),
  timeoutMs: z.number().int().min(100).max(MAX_NMAP_TIMEOUT_MS),
  maxStdoutBytes: z.number().int().min(1).max(MAX_NMAP_STREAM_BYTES),
  maxStderrBytes: z.number().int().min(1).max(MAX_NMAP_STREAM_BYTES)
}).strict().superRefine((config, context) => {
  if (config.executionEnabled &&
      (!config.isolation.verified ||
       config.isolation.exactTargetAddress === null ||
       config.isolation.verificationId === null)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "execution cannot be enabled until exact-target isolation is verified"
    });
  }
  if (!config.isolation.verified &&
      (config.isolation.exactTargetAddress !== null || config.isolation.verificationId !== null)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "unverified isolation cannot bind target metadata"
    });
  }
});

export type NmapTcpAdapterConfig = z.infer<typeof nmapTcpAdapterConfigSchema>;

export interface NmapTcpInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly spawnOptions: Readonly<Pick<SpawnOptionsWithoutStdio, "shell" | "windowsHide">>;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  readonly imageReference: string;
  readonly isolationVerificationId: string;
  readonly containerName: string;
  readonly distro: string;
}

export class NmapTcpAdapterContractError extends Error {
  constructor(
    readonly code:
      | "INVALID_CONFIGURATION"
      | "EXECUTION_DISABLED"
      | "ISOLATION_NOT_VERIFIED"
      | "CAPABILITY_NOT_SUPPORTED"
      | "TARGET_NOT_EXACT_IPV4"
      | "TARGET_ISOLATION_MISMATCH",
    message: string
  ) {
    super(message);
    this.name = "NmapTcpAdapterContractError";
  }
}

/**
 * Produces the only permitted process invocation for the first target-facing
 * capability. It does not spawn a process. The eventual executor must apply
 * the returned timeout and stream limits while using these argv unchanged.
 */
export function compileNmapTcpInvocation(
  input: BrokerExecutionRequest,
  configInput: NmapTcpAdapterConfig,
  now = new Date()
): NmapTcpInvocation {
  const parsedConfig = nmapTcpAdapterConfigSchema.safeParse(configInput);
  if (!parsedConfig.success) {
    throw new NmapTcpAdapterContractError("INVALID_CONFIGURATION", "Invalid Nmap adapter configuration");
  }
  const config = parsedConfig.data;
  if (!config.executionEnabled) {
    throw new NmapTcpAdapterContractError("EXECUTION_DISABLED", "Target-facing Nmap execution is disabled");
  }
  if (!config.isolation.verified ||
      config.isolation.exactTargetAddress === null ||
      config.isolation.verificationId === null) {
    throw new NmapTcpAdapterContractError("ISOLATION_NOT_VERIFIED", "Target isolation has not been verified");
  }

  const request = validateBrokerExecutionRequest(input, now);
  if (request.proposal.capabilityId !== NMAP_TCP_SERVICE_VERSION_CAPABILITY &&
      request.proposal.capabilityId !== NMAP_TCP_PORT_DISCOVERY_CAPABILITY &&
      request.proposal.capabilityId !== NMAP_TCP_PORT_STATE_CAPABILITY &&
      request.proposal.capabilityId !== NMAP_HTTP_METADATA_CAPABILITY &&
      request.proposal.capabilityId !== NMAP_TLS_CERTIFICATE_CAPABILITY &&
      request.proposal.capabilityId !== NMAP_TLS_CIPHERS_CAPABILITY) {
    throw new NmapTcpAdapterContractError(
      "CAPABILITY_NOT_SUPPORTED",
      "Only fixed exact-target TCP capabilities are supported"
    );
  }
  if (request.target.addressFamily !== "ipv4" ||
      !canonicalIpv4Schema.safeParse(request.target.canonicalAddress).success) {
    throw new NmapTcpAdapterContractError("TARGET_NOT_EXACT_IPV4", "Target must be one canonical IPv4 address");
  }
  if (request.target.canonicalAddress !== config.isolation.exactTargetAddress) {
    throw new NmapTcpAdapterContractError(
      "TARGET_ISOLATION_MISMATCH",
      "Resolved target does not match the isolation verification"
    );
  }

  const timeoutMs = Math.min(config.timeoutMs, request.limits.timeoutMs);
  const maxStdoutBytes = Math.min(config.maxStdoutBytes, request.limits.maxOutputBytes);
  const maxStderrBytes = Math.min(config.maxStderrBytes, request.limits.maxOutputBytes);
  const containerName = `war-room-${createHash("sha256")
    .update(request.executionId, "utf8")
    .digest("hex")
    .slice(0, 24)}`;
  let fixedNmapArgs: string[];
  switch (request.proposal.capabilityId) {
    case NMAP_TCP_SERVICE_VERSION_CAPABILITY:
      fixedNmapArgs = [
          "-n",
          "-Pn",
          "-sT",
          "-sV",
          "--version-intensity", String(request.proposal.parameters.intensity),
          "--max-retries", "1",
          "--host-timeout", `${timeoutMs}ms`,
          "-p", [...request.proposal.parameters.ports].sort((left, right) => left - right).join(","),
          "-oX", "-"
        ];
      break;
    case NMAP_TCP_PORT_DISCOVERY_CAPABILITY:
      fixedNmapArgs = [
          "-n",
          "-Pn",
          "-sT",
          "-T3",
          "--max-rate", String(request.proposal.parameters.maxRate),
          "--max-retries", "0",
          "--host-timeout", `${timeoutMs}ms`,
          "-p-",
          "--open",
          "-oX", "-"
        ];
      break;
    case NMAP_TCP_PORT_STATE_CAPABILITY:
      fixedNmapArgs = [
        "-n",
        "-Pn",
        "-sT",
        "-T2",
        "--max-rate", "20",
        "--scan-delay", "250ms",
        "--max-retries", "0",
        "--host-timeout", `${timeoutMs}ms`,
        "-p", [...request.proposal.parameters.ports].sort((left, right) => left - right).join(","),
        "--reason",
        "-oX", "-"
      ];
      break;
    case NMAP_HTTP_METADATA_CAPABILITY:
      fixedNmapArgs = [
        "-n",
        "-Pn",
        "-sT",
        "-sV",
        "--version-intensity", "1",
        "--max-retries", "1",
        "--host-timeout", `${timeoutMs}ms`,
        "-p", [...request.proposal.parameters.ports].sort((left, right) => left - right).join(","),
        "--script", "http-title,http-headers",
        "-oX", "-"
      ];
      break;
    case NMAP_TLS_CERTIFICATE_CAPABILITY:
      fixedNmapArgs = [
        "-n",
        "-Pn",
        "-sT",
        "-sV",
        "--version-intensity", "1",
        "--max-retries", "1",
        "--host-timeout", `${timeoutMs}ms`,
        "-p", [...request.proposal.parameters.ports].sort((left, right) => left - right).join(","),
        "--script", "ssl-cert",
        "-oX", "-"
      ];
      break;
    case NMAP_TLS_CIPHERS_CAPABILITY:
      fixedNmapArgs = [
        "-n",
        "-Pn",
        "-sT",
        "-sV",
        "--version-intensity", "1",
        "--max-retries", "1",
        "--host-timeout", `${timeoutMs}ms`,
        "-p", [...request.proposal.parameters.ports].sort((left, right) => left - right).join(","),
        "--script", "ssl-enum-ciphers",
        "-oX", "-"
      ];
      break;
    default:
      throw new NmapTcpAdapterContractError(
        "CAPABILITY_NOT_SUPPORTED",
        "Only fixed exact-target TCP capabilities are supported"
      );
  }
  return {
    executable: WINDOWS_WSL_EXECUTABLE,
    args: [
      "--distribution", config.distro,
      "--exec", config.dockerExecutable,
      "run",
      "--rm",
      "--name", containerName,
      "--pull=never",
      "--network", config.isolatedNetwork,
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt", "no-new-privileges",
      "--user", "65534:65534",
      "--pids-limit", "64",
      "--memory", "128m",
      "--cpus", "0.5",
      "--entrypoint", "/usr/bin/nmap",
      config.imageReference,
      ...fixedNmapArgs,
      request.target.canonicalAddress
    ],
    spawnOptions: { shell: false, windowsHide: true },
    timeoutMs,
    maxStdoutBytes,
    maxStderrBytes,
    imageReference: config.imageReference,
    isolationVerificationId: config.isolation.verificationId,
    containerName,
    distro: config.distro
  };
}
