import { createHash, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  lstatSync,
  realpathSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import {
  verifyWindowsExternalKeyPair,
  WINDOWS_SENSOR_KEY_SIDS
} from "./windows-key-protection.js";

function isInside(child: string, parent: string): boolean {
  const candidate = relative(resolve(parent), resolve(child));
  return candidate === "" || (!candidate.startsWith("..") && !isAbsolute(candidate));
}

function requireAbsoluteOutside(
  path: string,
  projectRoot: string,
  runtimeRoot: string,
  label: string
): string {
  if (!isAbsolute(path)) throw new Error(`${label}_MUST_BE_ABSOLUTE`);
  const resolved = resolve(path);
  if (isInside(resolved, projectRoot) || isInside(resolved, runtimeRoot)) {
    throw new Error(`${label}_LOCATION_FORBIDDEN`);
  }
  return resolved;
}

const [
  operation,
  privateKeyPathInput,
  descriptorPathInput,
  projectRootInput,
  runtimeRootInput
] = process.argv.slice(2);
if (
  !operation ||
  !privateKeyPathInput ||
  !descriptorPathInput ||
  !projectRootInput ||
  !runtimeRootInput ||
  process.argv.length !== 7
) {
  throw new Error("WINDOWS_KEY_PROVISION_ARGUMENTS_INVALID");
}
if (!isAbsolute(projectRootInput) || !isAbsolute(runtimeRootInput)) {
  throw new Error("WINDOWS_KEY_PROVISION_ROOT_INVALID");
}
const privateKeyPath = requireAbsoluteOutside(
  privateKeyPathInput,
  projectRootInput,
  runtimeRootInput,
  "WINDOWS_PRIVATE_KEY"
);
const descriptorPath = requireAbsoluteOutside(
  descriptorPathInput,
  projectRootInput,
  runtimeRootInput,
  "WINDOWS_KEY_DESCRIPTOR"
);
if (privateKeyPath === descriptorPath) throw new Error("WINDOWS_KEY_OUTPUT_COLLISION");

if (operation === "generate") {
  if (existsSync(privateKeyPath) || existsSync(descriptorPath)) {
    throw new Error("WINDOWS_KEY_ALREADY_EXISTS");
  }
  const privateParentInput = dirname(privateKeyPath);
  const descriptorParentInput = dirname(descriptorPath);
  if (
    lstatSync(privateParentInput).isSymbolicLink() ||
    lstatSync(descriptorParentInput).isSymbolicLink()
  ) {
    throw new Error("WINDOWS_KEY_PARENT_INVALID");
  }
  const privateParent = realpathSync(privateParentInput);
  const descriptorParent = realpathSync(descriptorParentInput);
  if (
    !isInside(privateKeyPath, privateParent) ||
    !isInside(descriptorPath, descriptorParent)
  ) {
    throw new Error("WINDOWS_KEY_PARENT_INVALID");
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const encodedPrivateKey = privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKeySpki = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(encodedPrivateKey) || !Buffer.isBuffer(publicKeySpki)) {
    throw new Error("WINDOWS_KEY_GENERATION_FAILED");
  }
  try {
    writeFileSync(privateKeyPath, encodedPrivateKey, {
      flag: "wx",
      mode: 0o600
    });
    writeFileSync(
      descriptorPath,
      `${JSON.stringify({
        schemaVersion: 1,
        algorithm: "ed25519",
        publicKeyFormat: "spki-der",
        publicKeySpkiBase64: publicKeySpki.toString("base64"),
        certificateFingerprintSha256: createHash("sha256")
          .update(publicKeySpki)
          .digest("hex"),
        serviceIdentitySid: WINDOWS_SENSOR_KEY_SIDS.localService,
        privateKeyPersistence: "external-windows-acl-protected",
        createdAt: new Date().toISOString()
      }, null, 2)}\n`,
      { flag: "wx", encoding: "utf8" }
    );
  } catch (error) {
    if (existsSync(privateKeyPath)) rmSync(privateKeyPath);
    if (existsSync(descriptorPath)) rmSync(descriptorPath);
    throw error;
  } finally {
    encodedPrivateKey.fill(0);
    publicKeySpki.fill(0);
  }
  console.log(JSON.stringify({ generated: true, descriptorPath }));
} else if (operation === "verify") {
  for (const outputPath of [privateKeyPath, descriptorPath]) {
    const pathInfo = lstatSync(outputPath);
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
      throw new Error("WINDOWS_KEY_PATH_INVALID");
    }
    const resolvedOutputPath = realpathSync(outputPath);
    if (
      isInside(resolvedOutputPath, projectRootInput) ||
      isInside(resolvedOutputPath, runtimeRootInput)
    ) {
      throw new Error("WINDOWS_KEY_LOCATION_FORBIDDEN");
    }
  }
  const descriptor = verifyWindowsExternalKeyPair(privateKeyPath, descriptorPath);
  console.log(JSON.stringify({
    verified: true,
    certificateFingerprintSha256: descriptor.certificateFingerprintSha256
  }));
} else {
  throw new Error("WINDOWS_KEY_PROVISION_OPERATION_INVALID");
}
