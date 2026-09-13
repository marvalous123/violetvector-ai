import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { sha256, stableJson } from "../domain/stable-json.js";

const GENESIS_HASH = "0".repeat(64);

interface AuditRow {
  sequence: number;
  id: string;
  occurred_at: string;
  event_type: string;
  payload_json: string;
  previous_hash: string;
  event_hash: string;
}

export interface AuditVerification {
  valid: boolean;
  eventsChecked: number;
  brokenAtSequence?: number;
}

function eventHash(previousHash: string, occurredAt: string, eventType: string, payloadJson: string): string {
  return sha256(`${previousHash}\n${occurredAt}\n${eventType}\n${payloadJson}`);
}

export class AuditService {
  private cachedVerification: AuditVerification;

  constructor(private readonly database: DatabaseSync) {
    this.cachedVerification = this.verifyFull();
  }

  append(eventType: string, payload: unknown, occurredAt = new Date()): AuditRow {
    const last = this.database
      .prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
      .get() as { event_hash: string } | undefined;
    const previousHash = last?.event_hash ?? GENESIS_HASH;
    const timestamp = occurredAt.toISOString();
    const payloadJson = stableJson(payload);
    const hash = eventHash(previousHash, timestamp, eventType, payloadJson);
    const id = randomUUID();
    this.database
      .prepare(
        `INSERT INTO audit_events(id, occurred_at, event_type, payload_json, previous_hash, event_hash)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(id, timestamp, eventType, payloadJson, previousHash, hash);
    const row = this.database.prepare("SELECT * FROM audit_events WHERE id = ?").get(id) as unknown as AuditRow;
    if (this.cachedVerification.valid) {
      this.cachedVerification = { valid: true, eventsChecked: row.sequence };
    }
    return row;
  }

  verify(): AuditVerification {
    this.cachedVerification = this.verifyFull();
    return { ...this.cachedVerification };
  }

  status(): AuditVerification {
    return { ...this.cachedVerification };
  }

  private verifyFull(): AuditVerification {
    const rows = this.database.prepare("SELECT * FROM audit_events ORDER BY sequence").all() as unknown as AuditRow[];
    if (rows.length === 0) {
      const state = this.database.prepare(
        `SELECT
           (SELECT COUNT(*) FROM missions) +
           (SELECT COUNT(*) FROM runs) +
           (SELECT COUNT(*) FROM artifacts) +
           (SELECT COUNT(*) FROM findings) +
           (SELECT COUNT(*) FROM endpoint_identities) AS count`
      ).get() as { count: number };
      if (state.count > 0) return { valid: false, eventsChecked: 0, brokenAtSequence: 1 };
    }
    let previousHash = GENESIS_HASH;
    for (const row of rows) {
      const expected = eventHash(previousHash, row.occurred_at, row.event_type, row.payload_json);
      if (row.previous_hash !== previousHash || row.event_hash !== expected) {
        return { valid: false, eventsChecked: row.sequence - 1, brokenAtSequence: row.sequence };
      }
      previousHash = row.event_hash;
    }
    return { valid: true, eventsChecked: rows.length };
  }
}
