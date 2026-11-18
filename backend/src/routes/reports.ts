import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";

export const reportsRouter = Router();

reportsRouter.get("/summary", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const stats = await query<{
    login_success: string; login_failed: string; mfa_failed: string;
    file_uploaded: string; file_downloaded: string;
    open_alerts: string; resolved_alerts: string;
    users_total: string; users_active: string; files_total: string;
  }>(`
    SELECT
      (SELECT COUNT(*)::text FROM audit_logs WHERE action='login_success') AS login_success,
      (SELECT COUNT(*)::text FROM audit_logs WHERE action='login_failed') AS login_failed,
      (SELECT COUNT(*)::text FROM audit_logs WHERE action='mfa_failed') AS mfa_failed,
      (SELECT COUNT(*)::text FROM audit_logs WHERE action='file_uploaded' AND status='success') AS file_uploaded,
      (SELECT COUNT(*)::text FROM audit_logs WHERE action='file_downloaded' AND status='success') AS file_downloaded,
      (SELECT COUNT(*)::text FROM security_alerts WHERE status='open') AS open_alerts,
      (SELECT COUNT(*)::text FROM security_alerts WHERE status='resolved') AS resolved_alerts,
      (SELECT COUNT(*)::text FROM users) AS users_total,
      (SELECT COUNT(*)::text FROM users WHERE is_active=TRUE) AS users_active,
      (SELECT COUNT(*)::text FROM research_files WHERE is_deleted=FALSE) AS files_total
  `);

  const topUsers = await query<{ username: string; cnt: string }>(
    "SELECT username, COUNT(*)::text AS cnt FROM audit_logs WHERE username IS NOT NULL GROUP BY username ORDER BY COUNT(*) DESC LIMIT 10"
  );

  const byAction = await query<{ action: string; cnt: string }>(
    "SELECT action, COUNT(*)::text AS cnt FROM audit_logs GROUP BY action ORDER BY COUNT(*) DESC"
  );

  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "reports_viewed", status: "success", ip: req.ip });
  res.json({
    ok: true,
    summary: stats.rows[0],
    top_users: topUsers.rows,
    by_action: byAction.rows,
  });
});
