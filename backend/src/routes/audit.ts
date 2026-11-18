import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";

export const auditRouter = Router();

auditRouter.get("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { action, status, username, limit } = req.query as Record<string, string | undefined>;
  const lim = Math.min(Number(limit) || 200, 1000);
  const conds: string[] = [];
  const params: unknown[] = [];
  let p = 1;
  if (action) { conds.push("action = $" + p++); params.push(action); }
  if (status) { conds.push("status = $" + p++); params.push(status); }
  if (username) { conds.push("LOWER(username) = LOWER($" + p++ + ")"); params.push(username); }
  const where = conds.length ? "WHERE " + conds.join(" AND ") : "";
  const { rows } = await query(
    "SELECT id, user_id, username, action, resource_type, resource_id, status, ip_address, user_agent, details, created_at FROM audit_logs " + where + " ORDER BY created_at DESC LIMIT " + lim,
    params
  );
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "audit_viewed", status: "success", ip: req.ip, details: { count: rows.length } });
  res.json({ ok: true, logs: rows });
});
