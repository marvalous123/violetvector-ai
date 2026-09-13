import { createHash, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync
} from "node:fs";
import { isAbsolute } from "node:path";

const SYSTEM_SID = "S-1-5-18";
const LOCAL_SERVICE_SID = "S-1-5-19";
const ADMINISTRATORS_SID = "S-1-5-32-544";
const SID = /^S-\d(?:-\d+)+$/;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const MAX_DESCRIPTOR_BYTES = 8 * 1024;
const DESCRIPTOR_KEYS = [
  "algorithm",
  "certificateFingerprintSha256",
  "createdAt",
  "privateKeyPersistence",
  "publicKeyFormat",
  "publicKeySpkiBase64",
  "schemaVersion",
  "serviceIdentitySid"
] as const;

export interface WindowsAclRule {
  readonly sid: string;
  readonly access: "Allow" | "Deny";
  readonly rights: string;
  readonly inherited: boolean;
}

export interface WindowsAclSnapshot {
  readonly protected: boolean;
  readonly ownerSid: string;
  readonly rules: readonly WindowsAclRule[];
}

export interface WindowsExternalKeyDescriptor {
  readonly schemaVersion: 1;
  readonly algorithm: "ed25519";
  readonly publicKeyFormat: "spki-der";
  readonly publicKeySpkiBase64: string;
  readonly certificateFingerprintSha256: string;
  readonly serviceIdentitySid: string;
  readonly privateKeyPersistence: "external-windows-acl-protected";
  readonly createdAt: string;
}

export type WindowsAclQuery = (absolutePath: string) => WindowsAclSnapshot;

function parseSnapshot(value: unknown): WindowsAclSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("WINDOWS_KEY_ACL_RESPONSE_INVALID");
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.protected !== "boolean" ||
    typeof candidate.ownerSid !== "string" ||
    !SID.test(candidate.ownerSid) ||
    !Array.isArray(candidate.rules)
  ) {
    throw new Error("WINDOWS_KEY_ACL_RESPONSE_INVALID");
  }
  const rules = candidate.rules.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("WINDOWS_KEY_ACL_RESPONSE_INVALID");
    }
    const rule = entry as Record<string, unknown>;
    if (
      typeof rule.sid !== "string" ||
      !SID.test(rule.sid) ||
      (rule.access !== "Allow" && rule.access !== "Deny") ||
      typeof rule.rights !== "string" ||
      typeof rule.inherited !== "boolean"
    ) {
      throw new Error("WINDOWS_KEY_ACL_RESPONSE_INVALID");
    }
    return {
      sid: rule.sid,
      access: rule.access,
      rights: rule.rights,
      inherited: rule.inherited
    } satisfies WindowsAclRule;
  });
  return {
    protected: candidate.protected,
    ownerSid: candidate.ownerSid,
    rules
  };
}

export const queryWindowsAcl: WindowsAclQuery = (absolutePath) => {
  if (process.platform !== "win32") throw new Error("WINDOWS_KEY_ACL_PLATFORM_REQUIRED");
  const powershell = `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
  const fixedQuery = [
    "$ErrorActionPreference='Stop'",
    "$acl=Get-Acl -LiteralPath $args[0]",
    "$rules=@($acl.Access | ForEach-Object {",
    "[pscustomobject]@{sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;",
    "access=$_.AccessControlType.ToString();rights=$_.FileSystemRights.ToString();inherited=$_.IsInherited}",
    "})",
    "$owner=$acl.Owner.Translate([System.Security.Principal.SecurityIdentifier]).Value",
    "[Console]::Out.Write(([pscustomobject]@{protected=$acl.AreAccessRulesProtected;ownerSid=$owner;rules=$rules}|ConvertTo-Json -Compress -Depth 4))"
  ].join(";");
  const result = spawnSync(
    powershell,
    ["-NoProfile", "-NonInteractive", "-Command", fixedQuery, absolutePath],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 5_000,
      maxBuffer: 64 * 1024
    }
  );
  if (result.error || result.status !== 0 || !result.stdout) {
    throw new Error("WINDOWS_KEY_ACL_QUERY_FAILED");
  }
  try {
    return parseSnapshot(JSON.parse(result.stdout));
  } catch {
    throw new Error("WINDOWS_KEY_ACL_RESPONSE_INVALID");
  }
};

export function assertWindowsPrivateKeyProtection(
  privateKeyPath: string,
  queryAcl: WindowsAclQuery = queryWindowsAcl,
  serviceSid = LOCAL_SERVICE_SID
): true {
  if (!isAbsolute(privateKeyPath)) throw new Error("WINDOWS_KEY_PATH_NOT_ABSOLUTE");
  if (!SID.test(serviceSid)) throw new Error("WINDOWS_KEY_SERVICE_SID_INVALID");
  const pathInfo = lstatSync(privateKeyPath);
  if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
    throw new Error("WINDOWS_KEY_PATH_INVALID");
  }
  const resolved = realpathSync(privateKeyPath);
  const acl = parseSnapshot(queryAcl(resolved));
  if (!acl.protected) throw new Error("WINDOWS_KEY_ACL_INHERITANCE_ENABLED");
  if (acl.ownerSid !== SYSTEM_SID && acl.ownerSid !== ADMINISTRATORS_SID) {
    throw new Error("WINDOWS_KEY_ACL_OWNER_INVALID");
  }
  const allowedSids = new Set([SYSTEM_SID, ADMINISTRATORS_SID, serviceSid]);
  if (
    acl.rules.length < 3 ||
    acl.rules.some(
      (rule) =>
        rule.access !== "Allow" ||
        rule.inherited ||
        !allowedSids.has(rule.sid)
    )
  ) {
    throw new Error("WINDOWS_KEY_ACL_RULE_INVALID");
  }
  for (const sid of allowedSids) {
    if (!acl.rules.some((rule) => rule.sid === sid)) {
      throw new Error("WINDOWS_KEY_ACL_PRINCIPAL_MISSING");
    }
  }
  for (const rule of acl.rules.filter((entry) => entry.sid === serviceSid)) {
    if (
      !/Read/i.test(rule.rights) ||
      /(Write|Modify|FullControl|Delete|TakeOwnership|ChangePermissions)/i.test(rule.rights)
    ) {
      throw new Error("WINDOWS_KEY_ACL_SERVICE_RIGHTS_INVALID");
    }
  }
  for (const sid of [SYSTEM_SID, ADMINISTRATORS_SID]) {
    if (
      !acl.rules
        .filter((rule) => rule.sid === sid)
        .some((rule) => /FullControl/i.test(rule.rights))
    ) {
      throw new Error("WINDOWS_KEY_ACL_ADMIN_RIGHTS_INVALID");
    }
  }
  return true;
}

function parseDescriptor(value: unknown): WindowsExternalKeyDescriptor {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("WINDOWS_KEY_DESCRIPTOR_INVALID");
  }
  const descriptor = value as Record<string, unknown>;
  if (
    Object.keys(descriptor).sort().join("|") !==
      [...DESCRIPTOR_KEYS].sort().join("|") ||
    descriptor.schemaVersion !== 1 ||
    descriptor.algorithm !== "ed25519" ||
    descriptor.publicKeyFormat !== "spki-der" ||
    typeof descriptor.publicKeySpkiBase64 !== "string" ||
    typeof descriptor.certificateFingerprintSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(descriptor.certificateFingerprintSha256) ||
    descriptor.serviceIdentitySid !== LOCAL_SERVICE_SID ||
    descriptor.privateKeyPersistence !== "external-windows-acl-protected" ||
    typeof descriptor.createdAt !== "string"
  ) {
    throw new Error("WINDOWS_KEY_DESCRIPTOR_INVALID");
  }
  const publicKeySpki = Buffer.from(descriptor.publicKeySpkiBase64, "base64");
  if (
    publicKeySpki.length === 0 ||
    publicKeySpki.toString("base64") !== descriptor.publicKeySpkiBase64
  ) {
    throw new Error("WINDOWS_KEY_DESCRIPTOR_INVALID");
  }
  const createdAt = new Date(descriptor.createdAt);
  if (
    !Number.isFinite(createdAt.valueOf()) ||
    createdAt.toISOString() !== descriptor.createdAt
  ) {
    throw new Error("WINDOWS_KEY_DESCRIPTOR_INVALID");
  }
  return descriptor as unknown as WindowsExternalKeyDescriptor;
}

export function verifyWindowsExternalKeyPair(
  privateKeyPath: string,
  descriptorPath: string,
  queryAcl: WindowsAclQuery = queryWindowsAcl
): WindowsExternalKeyDescriptor {
  if (!isAbsolute(descriptorPath)) {
    throw new Error("WINDOWS_KEY_DESCRIPTOR_PATH_NOT_ABSOLUTE");
  }
  assertWindowsPrivateKeyProtection(privateKeyPath, queryAcl);
  assertWindowsPrivateKeyProtection(descriptorPath, queryAcl);
  const resolvedPrivateKeyPath = realpathSync(privateKeyPath);
  const resolvedDescriptorPath = realpathSync(descriptorPath);
  if (
    statSync(resolvedPrivateKeyPath).size > MAX_PRIVATE_KEY_BYTES ||
    statSync(resolvedDescriptorPath).size > MAX_DESCRIPTOR_BYTES
  ) {
    throw new Error("WINDOWS_KEY_FILE_TOO_LARGE");
  }
  const privateKeyBytes = readFileSync(resolvedPrivateKeyPath);
  try {
    const descriptor = parseDescriptor(
      JSON.parse(readFileSync(resolvedDescriptorPath, "utf8"))
    );
    const publicKey = createPublicKey(privateKeyBytes);
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new Error("WINDOWS_KEY_ALGORITHM_INVALID");
    }
    const publicKeySpki = publicKey.export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(publicKeySpki)) {
      throw new Error("WINDOWS_KEY_PUBLIC_EXPORT_INVALID");
    }
    const expectedSpkiBase64 = publicKeySpki.toString("base64");
    const expectedFingerprint = createHash("sha256")
      .update(publicKeySpki)
      .digest("hex");
    publicKeySpki.fill(0);
    if (
      descriptor.publicKeySpkiBase64 !== expectedSpkiBase64 ||
      descriptor.certificateFingerprintSha256 !== expectedFingerprint
    ) {
      throw new Error("WINDOWS_KEY_DESCRIPTOR_MISMATCH");
    }
    return descriptor;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("WINDOWS_KEY_")
    ) {
      throw error;
    }
    throw new Error("WINDOWS_KEY_DESCRIPTOR_INVALID", { cause: error });
  } finally {
    privateKeyBytes.fill(0);
  }
}

export const WINDOWS_SENSOR_KEY_SIDS = {
  system: SYSTEM_SID,
  localService: LOCAL_SERVICE_SID,
  administrators: ADMINISTRATORS_SID
} as const;
