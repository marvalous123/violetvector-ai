import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  assertWindowsPrivateKeyProtection,
  verifyWindowsExternalKeyPair,
  WINDOWS_SENSOR_KEY_SIDS,
  type WindowsAclSnapshot
} from "./windows-key-protection.js";

function fixture(): {
  path: string;
  descriptorPath: string;
  acl: WindowsAclSnapshot;
} {
  const root = mkdtempSync(join(tmpdir(), "war-room-windows-key-"));
  const path = join(root, "identity.key");
  const descriptorPath = join(root, "identity-public.json");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey.export({ format: "der", type: "spki" });
  writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }));
  writeFileSync(
    descriptorPath,
    JSON.stringify({
      schemaVersion: 1,
      algorithm: "ed25519",
      publicKeyFormat: "spki-der",
      publicKeySpkiBase64: publicKeySpki.toString("base64"),
      certificateFingerprintSha256: createHash("sha256")
        .update(publicKeySpki)
        .digest("hex"),
      serviceIdentitySid: WINDOWS_SENSOR_KEY_SIDS.localService,
      privateKeyPersistence: "external-windows-acl-protected",
      createdAt: "2026-07-19T12:00:00.000Z"
    })
  );
  return {
    path,
    descriptorPath,
    acl: {
      protected: true,
      ownerSid: WINDOWS_SENSOR_KEY_SIDS.administrators,
      rules: [
        {
          sid: WINDOWS_SENSOR_KEY_SIDS.system,
          access: "Allow",
          rights: "FullControl",
          inherited: false
        },
        {
          sid: WINDOWS_SENSOR_KEY_SIDS.administrators,
          access: "Allow",
          rights: "FullControl",
          inherited: false
        },
        {
          sid: WINDOWS_SENSOR_KEY_SIDS.localService,
          access: "Allow",
          rights: "ReadAndExecute, Synchronize",
          inherited: false
        }
      ]
    }
  };
}

describe("Windows sensor private-key ACL boundary", () => {
  it("accepts only a protected SYSTEM, Administrators and read-only LocalService ACL", () => {
    const { path, acl } = fixture();
    assert.equal(assertWindowsPrivateKeyProtection(path, () => acl), true);
  });

  it("rejects inheritance, unknown principals, write access and bad owners", () => {
    const { path, acl } = fixture();
    assert.throws(
      () => assertWindowsPrivateKeyProtection(path, () => ({ ...acl, protected: false })),
      /WINDOWS_KEY_ACL_INHERITANCE_ENABLED/
    );
    assert.throws(
      () =>
        assertWindowsPrivateKeyProtection(path, () => ({
          ...acl,
          rules: [
            ...acl.rules,
            {
              sid: "S-1-1-0",
              access: "Allow",
              rights: "Read",
              inherited: false
            }
          ]
        })),
      /WINDOWS_KEY_ACL_RULE_INVALID/
    );
    assert.throws(
      () =>
        assertWindowsPrivateKeyProtection(path, () => ({
          ...acl,
          rules: acl.rules.map((rule) =>
            rule.sid === WINDOWS_SENSOR_KEY_SIDS.localService
              ? { ...rule, rights: "Modify, Synchronize" }
              : rule
          )
        })),
      /WINDOWS_KEY_ACL_SERVICE_RIGHTS_INVALID/
    );
    assert.throws(
      () =>
        assertWindowsPrivateKeyProtection(path, () => ({
          ...acl,
          ownerSid: WINDOWS_SENSOR_KEY_SIDS.localService
        })),
      /WINDOWS_KEY_ACL_OWNER_INVALID/
    );
  });

  it("binds the protected descriptor to the exact Ed25519 private key", () => {
    const valid = fixture();
    const descriptor = verifyWindowsExternalKeyPair(
      valid.path,
      valid.descriptorPath,
      () => valid.acl
    );
    assert.equal(descriptor.algorithm, "ed25519");

    const mismatched = fixture();
    const other = fixture();
    writeFileSync(
      mismatched.descriptorPath,
      JSON.stringify({
        ...verifyWindowsExternalKeyPair(
          other.path,
          other.descriptorPath,
          () => other.acl
        )
      })
    );
    assert.throws(
      () =>
        verifyWindowsExternalKeyPair(
          mismatched.path,
          mismatched.descriptorPath,
          () => mismatched.acl
        ),
      /WINDOWS_KEY_DESCRIPTOR_MISMATCH/
    );
  });
});
