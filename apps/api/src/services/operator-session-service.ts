import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const OPERATOR_SESSION_COOKIE = "war_room_session";

export interface OperatorSession {
  operator: string;
  csrfToken: string;
  tabCapability: string;
  expiresAt: string;
}

interface StoredSession {
  operator: string;
  csrfHash: Buffer;
  tabCapabilityHash: Buffer;
  createdAtMs: number;
  lastSeenAtMs: number;
}

export interface OperatorSessionOptions {
  idleTtlMs?: number;
  absoluteTtlMs?: number;
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function token(): string {
  return randomBytes(32).toString("base64url");
}

export class OperatorSessionService {
  readonly #bootstrapHash: Buffer;
  readonly #csrfKey = randomBytes(32);
  readonly #sessions = new Map<string, StoredSession>();
  readonly #idleTtlMs: number;
  readonly #absoluteTtlMs: number;

  constructor(bootstrapSecret: string, options: OperatorSessionOptions = {}) {
    if (bootstrapSecret.length < 24) throw new Error("BOOTSTRAP_SECRET_INVALID");
    this.#bootstrapHash = digest(bootstrapSecret);
    this.#idleTtlMs = options.idleTtlMs ?? 30 * 60_000;
    this.#absoluteTtlMs = options.absoluteTtlMs ?? 8 * 60 * 60_000;
    if (this.#idleTtlMs < 1_000 || this.#absoluteTtlMs < this.#idleTtlMs) {
      throw new Error("SESSION_TTL_INVALID");
    }
  }

  static generateBootstrapSecret(): string {
    return token();
  }

  unlock(bootstrapSecret: string, operator: string, now = new Date()): {
    cookieValue: string;
    session: OperatorSession;
  } {
    const suppliedHash = digest(bootstrapSecret);
    if (!timingSafeEqual(suppliedHash, this.#bootstrapHash)) throw new Error("SESSION_UNLOCK_FAILED");
    const cleanOperator = operator.trim();
    if (cleanOperator.length < 2 || cleanOperator.length > 120) throw new Error("OPERATOR_INVALID");
    const cookieValue = token();
    const tabCapability = token();
    const csrfToken = this.#csrfFor(cookieValue);
    const timestamp = now.valueOf();
    this.#sessions.set(digest(cookieValue).toString("hex"), {
      operator: cleanOperator,
      csrfHash: digest(csrfToken),
      tabCapabilityHash: digest(tabCapability),
      createdAtMs: timestamp,
      lastSeenAtMs: timestamp
    });
    return {
      cookieValue,
      session: {
        operator: cleanOperator,
        csrfToken,
        tabCapability,
        expiresAt: new Date(timestamp + this.#idleTtlMs).toISOString()
      }
    };
  }

  current(cookieHeader: string | undefined, tabCapability: string | undefined, now = new Date()): OperatorSession | null {
    const cookieValue = parseSessionCookie(cookieHeader);
    if (!cookieValue) return null;
    const stored = this.#get(cookieValue, now);
    this.#assertTabCapability(stored, tabCapability);
    const csrfToken = this.#csrfFor(cookieValue);
    stored.lastSeenAtMs = now.valueOf();
    return {
      operator: stored.operator,
      csrfToken,
      tabCapability: tabCapability!,
      expiresAt: this.#expiry(stored).toISOString()
    };
  }

  authorize(
    cookieHeader: string | undefined,
    csrfToken: string | undefined,
    tabCapability: string | undefined,
    now = new Date()
  ): { operator: string } {
    const cookieValue = parseSessionCookie(cookieHeader);
    if (!cookieValue) throw new Error("SESSION_REQUIRED");
    const stored = this.#get(cookieValue, now);
    this.#assertTabCapability(stored, tabCapability);
    if (!csrfToken || !timingSafeEqual(digest(csrfToken), stored.csrfHash)) throw new Error("CSRF_INVALID");
    stored.lastSeenAtMs = now.valueOf();
    return { operator: stored.operator };
  }

  authenticate(cookieHeader: string | undefined, tabCapability: string | undefined, now = new Date()): { operator: string } {
    const cookieValue = parseSessionCookie(cookieHeader);
    if (!cookieValue) throw new Error("SESSION_REQUIRED");
    const stored = this.#get(cookieValue, now);
    this.#assertTabCapability(stored, tabCapability);
    stored.lastSeenAtMs = now.valueOf();
    return { operator: stored.operator };
  }

  logout(cookieHeader: string | undefined, tabCapability: string | undefined): void {
    const cookieValue = parseSessionCookie(cookieHeader);
    if (!cookieValue) throw new Error("SESSION_REQUIRED");
    const key = digest(cookieValue).toString("hex");
    const stored = this.#sessions.get(key);
    if (!stored) throw new Error("SESSION_REQUIRED");
    this.#assertTabCapability(stored, tabCapability);
    this.#sessions.delete(key);
  }

  #get(cookieValue: string, now: Date): StoredSession {
    const key = digest(cookieValue).toString("hex");
    const stored = this.#sessions.get(key);
    if (!stored) throw new Error("SESSION_REQUIRED");
    if (now.valueOf() >= this.#expiry(stored).valueOf()) {
      this.#sessions.delete(key);
      throw new Error("SESSION_EXPIRED");
    }
    return stored;
  }

  #expiry(stored: StoredSession): Date {
    return new Date(
      Math.min(stored.lastSeenAtMs + this.#idleTtlMs, stored.createdAtMs + this.#absoluteTtlMs)
    );
  }

  #assertTabCapability(stored: StoredSession, supplied: string | undefined): void {
    if (!supplied || !/^[A-Za-z0-9_-]{40,64}$/.test(supplied) ||
        !timingSafeEqual(digest(supplied), stored.tabCapabilityHash)) {
      throw new Error("TAB_CAPABILITY_INVALID");
    }
  }

  #csrfFor(cookieValue: string): string {
    return createHmac("sha256", this.#csrfKey).update(cookieValue, "utf8").digest("base64url");
  }
}

export function parseSessionCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  const matches = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${OPERATOR_SESSION_COOKIE}=`));
  if (matches.length > 1) throw new Error("SESSION_COOKIE_INVALID");
  if (matches.length === 0) return null;
  const value = matches[0]!.slice(OPERATOR_SESSION_COOKIE.length + 1);
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(value)) throw new Error("SESSION_COOKIE_INVALID");
  return value;
}
