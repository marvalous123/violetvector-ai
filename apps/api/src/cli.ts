import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, win32 } from "node:path";
import { McpwnVersionBroker } from "@war-room/executor-contract";
import { startServer } from "./server.js";
import { OperatorSessionService } from "./services/operator-session-service.js";
import { RedmiIsolationService } from "./services/redmi-isolation-service.js";

const dataRoot = process.env.WAR_ROOM_DATA_ROOT ?? join(homedir(), ".war-room-project15");
const kaliDistro = "kali-linux";
const binaryLinuxPath = "/home/kali/.local/share/war-room-project15/runtime/mcpwn-version/mcpwn";
const configLinuxPath = "/home/kali/.local/share/war-room-project15/runtime/mcpwn-version/mcpwn.yaml";
const wslHostPath = (linuxPath: string): string =>
  win32.join(`\\\\wsl.localhost\\${kaliDistro}`, ...linuxPath.split("/").filter(Boolean));
mkdirSync(join(dataRoot, "evidence"), { recursive: true });
const configuredBootstrapSecret = process.env.WAR_ROOM_OPERATOR_BOOTSTRAP;
const bootstrapSecret = configuredBootstrapSecret ?? OperatorSessionService.generateBootstrapSecret();
if (!configuredBootstrapSecret) {
  console.log(`VioletVector AI per-launch bootstrap secret: ${bootstrapSecret}`);
}

const executor =
  process.env.WAR_ROOM_MCPWN_VERSION_ENABLED === "0"
    ? undefined
    : new McpwnVersionBroker({
        distro: kaliDistro,
        linuxWorkingDirectory: "/home/kali/.local/share/war-room-project15/runtime/mcpwn-version",
        binary: {
          hostPath: wslHostPath(binaryLinuxPath),
          linuxPath: binaryLinuxPath,
          expectedSha256: "178d7a7cd254789ee8f197b54b38f3baa5146fd5a515b640999c69bcb51b5e12"
        },
        config: {
          hostPath: wslHostPath(configLinuxPath),
          linuxPath: configLinuxPath,
          expectedSha256: "d94bb971a14632c5107c5e13f2389d530f2cd658e714011a2cee05896bd26b7b"
        },
        timeoutMs: 15_000,
        maxStdoutBytes: 65_536,
        maxStderrBytes: 65_536
      });
const targetIsolationVerifier =
  process.env.WAR_ROOM_REDMI_EXECUTION_ENABLED === "0"
    ? undefined
    : new RedmiIsolationService();

startServer({
  databasePath: join(dataRoot, "war-room.sqlite"),
  evidenceRoot: join(dataRoot, "evidence"),
  bootstrapSecret,
  ...(executor ? { executor } : {}),
  ...(targetIsolationVerifier ? { targetIsolationVerifier } : {}),
  ...(process.env.WAR_ROOM_WEB_ROOT ? { webRoot: process.env.WAR_ROOM_WEB_ROOT } : {})
});
