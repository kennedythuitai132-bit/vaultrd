import { query } from "../config/db.js";
import { logger } from "./logger.js";
import type { AuditAction, AuditStatus } from "../types/index.js";

export interface AuditInput {
  userId?: number | null;
  username?: string | null;
  action: AuditAction;
  resourceType?: string;
  resourceId?: number;
  status: AuditStatus;
  ip?: string;
  userAgent?: string;
  details?: Record<string, unknown>;
}

export async function writeAudit(input: AuditInput): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_logs
        (user_id, username, action, resource_type, resource_id, status, ip_address, user_agent, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        input.userId ?? null,
        input.username ?? null,
        input.action,
        input.resourceType ?? null,
        input.resourceId ?? null,
        input.status,
        input.ip ?? null,
        input.userAgent ?? null,
        JSON.stringify(input.details ?? {}),
      ]
    );
  } catch (err) {
    logger.error("[audit] failed to write audit log", { error: String(err) });
  }
}

export interface AlertInput {
  alertType: string;
  severity: "low" | "medium" | "high";
  title: string;
  description?: string;
  relatedUser?: string;
  ip?: string;
  details?: Record<string, unknown>;
}

export async function raiseAlert(input: AlertInput): Promise<void> {
  try {
    await query(
      `INSERT INTO security_alerts
        (alert_type, severity, title, description, related_user, ip_address, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        input.alertType,
        input.severity,
        input.title,
        input.description ?? null,
        input.relatedUser ?? null,
        input.ip ?? null,
        JSON.stringify(input.details ?? {}),
      ]
    );
    logger.warn("[alert] raised: " + input.alertType + " / " + input.title);
  } catch (err) {
    logger.error("[alert] failed to raise alert", { error: String(err) });
  }
}
