import {
  constants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync
} from "node:fs";
import { type AuditHeadProtectedDocumentV1 } from "./audit-head-checkpoint-contract.js";
import { verifyAuditHeadProtectedDocumentV1 } from "./audit-head-checkpoint-proof.js";

export const AUDIT_HEAD_PROTECTED_STATE_PATH =
  "C:\\ProgramData\\Project15 Audit Head\\Protected\\audit-head-state-v1.json" as const;
export const AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES = 8192 as const;

function fail(code: string): never {
  throw new Error(code);
}

export function parseAuditHeadProtectedDocumentBytesV1(
  bytes: Uint8Array | Buffer,
  expectedSignerPublicKeyFingerprintSha256: string
): AuditHeadProtectedDocumentV1 {
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES
  ) {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  if (
    bytes.byteLength >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  let text: string;
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    text = decoder.decode(bytes);
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  if (
    document === null ||
    typeof document !== "object" ||
    Array.isArray(document)
  ) {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  return verifyAuditHeadProtectedDocumentV1({
    document,
    expectedSignerPublicKeyFingerprintSha256
  });
}

export function readAuditHeadProtectedDocumentV1(input: {
  expectedSignerPublicKeyFingerprintSha256: string;
}): AuditHeadProtectedDocumentV1 {
  const path = AUDIT_HEAD_PROTECTED_STATE_PATH;
  let pathState;
  try {
    pathState = lstatSync(path);
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return fail("AUDIT_HEAD_PROTECTED_FILE_MISSING");
    }
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  if (
    !pathState.isFile() ||
    pathState.isSymbolicLink() ||
    (typeof pathState.nlink === "number" && pathState.nlink !== 1) ||
    pathState.size < 1 ||
    pathState.size > AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES
  ) {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  try {
    const resolvedPath = realpathSync.native(path);
    if (resolvedPath.toLowerCase() !== path.toLowerCase()) {
      return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
    }
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  const noFollow =
    "O_NOFOLLOW" in constants
      ? (constants as typeof constants & { O_NOFOLLOW: number }).O_NOFOLLOW
      : 0;

  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
  } catch {
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  }

  try {
    const before = fstatSync(descriptor);
    if (
      !before.isFile() ||
      pathState.dev !== before.dev ||
      pathState.ino !== before.ino ||
      pathState.size !== before.size ||
      before.size < 1 ||
      before.size > AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES ||
      (typeof before.nlink === "number" && before.nlink !== 1)
    ) {
      return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
    }

    const buffer = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < before.size) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        offset,
        before.size - offset,
        offset
      );
      if (bytesRead < 1) {
        return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
      }
      offset += bytesRead;
    }

    const after = fstatSync(descriptor);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs
    ) {
      return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
    }

    return parseAuditHeadProtectedDocumentBytesV1(
      buffer,
      input.expectedSignerPublicKeyFingerprintSha256
    );
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("AUDIT_HEAD_")
    ) {
      throw error;
    }
    return fail("AUDIT_HEAD_PROTECTED_FILE_INVALID");
  } finally {
    closeSync(descriptor);
  }
}
