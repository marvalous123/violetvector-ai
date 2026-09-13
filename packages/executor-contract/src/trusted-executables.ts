import { win32 } from "node:path";

const configuredSystemRoot = process.env.SystemRoot;
const trustedSystemRoot = configuredSystemRoot && /^[A-Za-z]:\\Windows$/i.test(configuredSystemRoot)
  ? configuredSystemRoot
  : String.raw`C:\Windows`;

export const WINDOWS_WSL_EXECUTABLE = win32.join(trustedSystemRoot, "System32", "wsl.exe");
export const WSL_DOCKER_EXECUTABLE = "/usr/bin/docker" as const;
export const WSL_IP_EXECUTABLE = "/usr/sbin/ip" as const;
