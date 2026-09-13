import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { canonicalizeTarget } from "@war-room/policy";
import type { Scope } from "@war-room/policy";
import { AuditService } from "./audit-service.js";

interface TargetInput {
  address: string;
  isolatedPrivateTargetApproved?: boolean;
}

interface CreateScopeInput {
  missionId: string;
  startsAt: string;
  expiresAt: string;
  policyVersion: string;
  authorizationStatement: string;
  authorizationAttachmentSha256?: string;
  targets: TargetInput[];
}

interface MissionRow {
  id: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export class MissionService {
  private readonly audit: AuditService;

  constructor(private readonly database: DatabaseSync, audit?: AuditService) {
    this.audit = audit ?? new AuditService(database);
  }

  createMission(name: string, now = new Date()): MissionRow {
    const cleanName = name.trim();
    if (cleanName.length < 3 || cleanName.length > 120) throw new Error("MISSION_NAME_INVALID");
    const id = randomUUID();
    const timestamp = now.toISOString();
    this.database
      .prepare("INSERT INTO missions(id, name, status, created_at, updated_at) VALUES (?, ?, 'draft', ?, ?)")
      .run(id, cleanName, timestamp, timestamp);
    this.audit.append("mission.created", { missionId: id, name: cleanName }, now);
    return this.getMission(id);
  }

  getMission(id: string): MissionRow {
    const row = this.database.prepare("SELECT * FROM missions WHERE id = ?").get(id) as unknown as MissionRow | undefined;
    if (!row) throw new Error("MISSION_NOT_FOUND");
    return row;
  }

  listMissions(): MissionRow[] {
    return this.database.prepare("SELECT * FROM missions ORDER BY created_at DESC").all() as unknown as MissionRow[];
  }

  createScopeVersion(input: CreateScopeInput, now = new Date()): Scope {
    const mission = this.getMission(input.missionId);
    if (!['draft', 'scope_validated'].includes(mission.status)) throw new Error("MISSION_SCOPE_LOCKED");
    if (input.authorizationStatement.trim().length < 12) throw new Error("AUTHORIZATION_STATEMENT_REQUIRED");
    if (input.targets.length < 1 || input.targets.length > 16) throw new Error("TARGET_COUNT_INVALID");
    const startsAt = new Date(input.startsAt);
    const expiresAt = new Date(input.expiresAt);
    if (!Number.isFinite(startsAt.valueOf()) || !Number.isFinite(expiresAt.valueOf()) || startsAt >= expiresAt) {
      throw new Error("SCOPE_WINDOW_INVALID");
    }

    const canonicalTargets = input.targets.map((target) => ({
      ...canonicalizeTarget(target.address),
      isolatedPrivateTargetApproved: target.isolatedPrivateTargetApproved ?? false
    }));
    for (const target of canonicalTargets) {
      if (target.classification === "private" && !target.isolatedPrivateTargetApproved) {
        throw new Error("PRIVATE_TARGET_ISOLATION_REQUIRED");
      }
      if (target.classification !== "public" && target.classification !== "private") {
        throw new Error(`TARGET_CLASS_DENIED:${target.classification}`);
      }
    }
    if (new Set(canonicalTargets.map((target) => target.address)).size !== canonicalTargets.length) {
      throw new Error("DUPLICATE_TARGET");
    }

    const scopeVersionId = randomUUID();
    const authorizationId = randomUUID();
    const timestamp = now.toISOString();
    const versionRow = this.database
      .prepare("SELECT COALESCE(MAX(version), 0) + 1 AS version FROM scope_versions WHERE mission_id = ?")
      .get(input.missionId) as { version: number };

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO scope_versions(id, mission_id, version, starts_at, expires_at, policy_version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(scopeVersionId, input.missionId, versionRow.version, startsAt.toISOString(), expiresAt.toISOString(), input.policyVersion, timestamp);

      for (const target of canonicalTargets) {
        const existing = this.database
          .prepare("SELECT id FROM targets WHERE canonical_address = ?")
          .get(target.address) as { id: string } | undefined;
        const targetId = existing?.id ?? randomUUID();
        if (!existing) {
          this.database
            .prepare("INSERT INTO targets(id, canonical_address, address_family, classification) VALUES (?, ?, ?, ?)")
            .run(targetId, target.address, target.family, target.classification);
        }
        this.database
          .prepare(
            `INSERT INTO scope_targets(scope_version_id, target_id, isolated_private_target_approved)
             VALUES (?, ?, ?)`
          )
          .run(scopeVersionId, targetId, target.isolatedPrivateTargetApproved ? 1 : 0);
      }

      this.database
        .prepare(
          `INSERT INTO authorization_records(id, scope_version_id, statement, attachment_sha256, recorded_at)
           VALUES (?, ?, ?, ?, ?)`
        )
        .run(
          authorizationId,
          scopeVersionId,
          input.authorizationStatement.trim(),
          input.authorizationAttachmentSha256 ?? null,
          timestamp
        );
      this.database
        .prepare("UPDATE missions SET status = 'scope_validated', updated_at = ? WHERE id = ?")
        .run(timestamp, input.missionId);
      this.database.prepare(
        `UPDATE approval_requests
         SET status = 'revoked', decided_at = ?, decided_by = 'system',
             decision_note = 'Scope replacement invalidated approval'
         WHERE status IN ('pending', 'approved')
           AND id IN (
             SELECT approval_id FROM approval_execution_bindings
             WHERE mission_id = ? AND scope_version_id <> ?
           )`
      ).run(timestamp, input.missionId, scopeVersionId);
      this.database.prepare(
        `UPDATE runs SET status = 'failed', updated_at = ?
         WHERE mission_id = ? AND status IN ('queued', 'awaiting_approval', 'armed')
           AND id IN (
             SELECT run_id FROM run_scope_bindings WHERE scope_version_id <> ?
           )`
      ).run(timestamp, input.missionId, scopeVersionId);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    this.audit.append(
      "scope.version.created",
      { missionId: input.missionId, scopeVersionId, version: versionRow.version, targetCount: canonicalTargets.length },
      now
    );
    return this.getScopeVersion(scopeVersionId);
  }

  getScopeVersion(scopeVersionId: string): Scope {
    const version = this.database
      .prepare("SELECT * FROM scope_versions WHERE id = ?")
      .get(scopeVersionId) as Record<string, unknown> | undefined;
    if (!version) throw new Error("SCOPE_NOT_FOUND");
    const targets = this.database
      .prepare(
        `SELECT t.id, t.canonical_address AS address, st.isolated_private_target_approved AS isolated
         FROM scope_targets st JOIN targets t ON t.id = st.target_id
         WHERE st.scope_version_id = ? ORDER BY t.canonical_address`
      )
      .all(scopeVersionId) as unknown as Array<{ id: string; address: string; isolated: number }>;
    return {
      scopeVersionId: String(version.id),
      missionId: String(version.mission_id),
      startsAt: String(version.starts_at),
      expiresAt: String(version.expires_at),
      policyVersion: String(version.policy_version),
      targets: targets.map((target) => ({
        id: target.id,
        address: target.address,
        isolatedPrivateTargetApproved: target.isolated === 1
      }))
    };
  }

  getLatestScope(missionId: string): Scope {
    const row = this.database
      .prepare("SELECT id FROM scope_versions WHERE mission_id = ? ORDER BY version DESC LIMIT 1")
      .get(missionId) as { id: string } | undefined;
    if (!row) throw new Error("SCOPE_NOT_FOUND");
    return this.getScopeVersion(row.id);
  }
}
