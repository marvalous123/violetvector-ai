import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { OPERATOR_SESSION_COOKIE, OperatorSessionService, parseSessionCookie } from "./operator-session-service.js";

const secret = "test-bootstrap-secret-that-is-long-enough";
const now = new Date("2026-07-17T12:00:00.000Z");

describe("operator session service", () => {
  it("stores opaque hashed credentials and authorizes the matching CSRF token", () => {
    const service = new OperatorSessionService(secret);
    const unlocked = service.unlock(secret, "local operator", now);
    const cookie = `${OPERATOR_SESSION_COOKIE}=${unlocked.cookieValue}`;
    assert.equal(
      service.authorize(cookie, unlocked.session.csrfToken, unlocked.session.tabCapability, now).operator,
      "local operator"
    );
    assert.throws(
      () => service.authorize(cookie, "wrong-token", unlocked.session.tabCapability, now),
      /CSRF_INVALID/
    );
    assert.throws(
      () => service.authenticate(cookie, "wrong-tab-capability", now),
      /TAB_CAPABILITY_INVALID/
    );
  });

  it("returns the same derived CSRF token on session refresh", () => {
    const service = new OperatorSessionService(secret);
    const unlocked = service.unlock(secret, "operator", now);
    const cookie = `${OPERATOR_SESSION_COOKIE}=${unlocked.cookieValue}`;
    const refreshed = service.current(cookie, unlocked.session.tabCapability, now);
    assert.ok(refreshed);
    assert.equal(refreshed.csrfToken, unlocked.session.csrfToken);
    assert.equal(service.authorize(cookie, unlocked.session.csrfToken, unlocked.session.tabCapability, now).operator, "operator");
    assert.equal(service.authorize(cookie, refreshed.csrfToken, refreshed.tabCapability, now).operator, "operator");
  });

  it("expires idle sessions and rejects duplicate cookies", () => {
    const service = new OperatorSessionService(secret, { idleTtlMs: 1_000, absoluteTtlMs: 2_000 });
    const unlocked = service.unlock(secret, "operator", now);
    const cookie = `${OPERATOR_SESSION_COOKIE}=${unlocked.cookieValue}`;
    assert.throws(
      () => service.authenticate(cookie, unlocked.session.tabCapability, new Date(now.valueOf() + 1_001)),
      /SESSION_EXPIRED/
    );
    assert.throws(() => parseSessionCookie(`${cookie}; ${cookie}`), /SESSION_COOKIE_INVALID/);
  });

  it("rejects an invalid bootstrap secret and invalidates logout", () => {
    const service = new OperatorSessionService(secret);
    assert.throws(() => service.unlock("not-the-bootstrap-secret", "operator", now), /SESSION_UNLOCK_FAILED/);
    const unlocked = service.unlock(secret, "operator", now);
    const cookie = `${OPERATOR_SESSION_COOKIE}=${unlocked.cookieValue}`;
    service.logout(cookie, unlocked.session.tabCapability);
    assert.throws(() => service.authenticate(cookie, unlocked.session.tabCapability, now), /SESSION_REQUIRED/);
  });
});
