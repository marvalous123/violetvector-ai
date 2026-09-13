import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";
import { stableJson, sha256 } from "../domain/stable-json.js";
import {
  AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
  AUDIT_HEAD_GENESIS_HASH,
  AUDIT_HEAD_KEY_PERSISTENCE_V1,
  AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
  AUDIT_HEAD_SIGNER_ALGORITHM_V1,
  AUDIT_HEAD_SIGNER_PROFILE_V1,
  auditHeadCheckpointHashV1,
  type AuditHeadCheckpointCoreV1,
  type AuditHeadProtectedDocumentV1
} from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES,
  AUDIT_HEAD_PROTECTED_STATE_PATH,
  parseAuditHeadProtectedDocumentBytesV1
} from "./audit-head-protected-file.js";

const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = keys.publicKey.export({ format: "der", type: "spki" });
const fingerprint = createHash("sha256").update(spki).digest("hex");
const chainId = sha256(`project15.audit-head-chain.v1\n${fingerprint}`);

function validProtectedDocument(sequence = 1): AuditHeadProtectedDocumentV1 {
  const core: AuditHeadCheckpointCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
    chainId,
    priorSequence: 0,
    priorEventHash: AUDIT_HEAD_GENESIS_HASH,
    priorCheckpointHash: AUDIT_HEAD_GENESIS_HASH,
    sequence,
    eventHash: "a".repeat(64),
    signerProfile: AUDIT_HEAD_SIGNER_PROFILE_V1,
    signerAlgorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
    signerPublicKeyFingerprintSha256: fingerprint
  };
  const payload = stableJson(core);
  const signatureBase64 = sign("sha256", Buffer.from(payload, "utf8"), {
    key: keys.privateKey,
    dsaEncoding: "ieee-p1363"
  }).toString("base64");

  return {
    signer: {
      profile: AUDIT_HEAD_SIGNER_PROFILE_V1,
      chainId,
      algorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
      publicKeyFormat: AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
      publicKeySpkiBase64: spki.toString("base64"),
      publicKeyFingerprintSha256: fingerprint,
      keyPersistence: AUDIT_HEAD_KEY_PERSISTENCE_V1
    },
    checkpoint: {
      ...core,
      checkpointHash: auditHeadCheckpointHashV1(core),
      signatureBase64
    }
  };
}

describe("audit-head-protected-file adapter", () => {
  it("defines exact fixed production path and size limits", () => {
    assert.equal(
      AUDIT_HEAD_PROTECTED_STATE_PATH,
      "C:\\ProgramData\\Project15 Audit Head\\Protected\\audit-head-state-v1.json"
    );
    assert.equal(AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES, 8192);
  });

  it("parses and verifies a valid canonical UTF-8 protected document byte stream", () => {
    const doc = validProtectedDocument();
    const bytes = Buffer.from(JSON.stringify(doc), "utf8");
    const parsed = parseAuditHeadProtectedDocumentBytesV1(bytes, fingerprint);
    assert.deepEqual(parsed, doc);
  });

  it("rejects empty bytes and oversized bytes", () => {
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(new Uint8Array(0), fingerprint),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );

    const oversized = new Uint8Array(AUDIT_HEAD_MAXIMUM_PROTECTED_STATE_BYTES + 1);
    oversized.fill(0x20);
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(oversized, fingerprint),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );
  });

  it("rejects UTF-8 BOM prefix", () => {
    const doc = validProtectedDocument();
    const docBytes = Buffer.from(JSON.stringify(doc), "utf8");
    const bomBytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), docBytes]);
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(bomBytes, fingerprint),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );
  });

  it("rejects non-UTF-8 invalid byte sequences", () => {
    const invalidUtf8 = Buffer.from([0x80, 0x81, 0x82, 0xff]);
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(invalidUtf8, fingerprint),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );
  });

  it("rejects malformed or non-object JSON payloads", () => {
    assert.throws(
      () =>
        parseAuditHeadProtectedDocumentBytesV1(
          Buffer.from("{not-valid-json", "utf8"),
          fingerprint
        ),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );

    assert.throws(
      () =>
        parseAuditHeadProtectedDocumentBytesV1(
          Buffer.from("null", "utf8"),
          fingerprint
        ),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );

    assert.throws(
      () =>
        parseAuditHeadProtectedDocumentBytesV1(
          Buffer.from("[1, 2, 3]", "utf8"),
          fingerprint
        ),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );

    assert.throws(
      () =>
        parseAuditHeadProtectedDocumentBytesV1(
          Buffer.from('"just a string"', "utf8"),
          fingerprint
        ),
      /AUDIT_HEAD_PROTECTED_FILE_INVALID/
    );
  });

  it("rejects pinned signer fingerprint mismatch", () => {
    const doc = validProtectedDocument();
    const bytes = Buffer.from(JSON.stringify(doc), "utf8");
    const wrongFingerprint = "f".repeat(64);
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(bytes, wrongFingerprint),
      /AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH/
    );
  });

  it("rejects corrupted signature or tampered checkpoint", () => {
    const doc = validProtectedDocument();
    doc.checkpoint.eventHash = "b".repeat(64);
    const bytes = Buffer.from(JSON.stringify(doc), "utf8");
    assert.throws(
      () => parseAuditHeadProtectedDocumentBytesV1(bytes, fingerprint),
      /AUDIT_HEAD_PROTECTED_SIGNATURE_INVALID/
    );
  });
});
