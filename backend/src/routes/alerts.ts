import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";

export const alertsRouter = Router();

alertsRouter.get("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { status } = req.query as { status?: string };
  const where = status ? "WHERE status = $1" : "";
  const params = status ? [status] : [];
  const { rows } = await query(
    "SELECT id, alert_type, severity, status, title, description, related_user, ip_address, details, resolved_by, resolved_at, created_at FROM security_alerts " + where + " ORDER BY created_at DESC LIMIT 500",
    params
  );
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "alerts_viewed", status: "success", ip: req.ip, details: { count: rows.length } });
  res.json({ ok: true, alerts: rows });
});

alertsRouter.patch("/:id/resolve", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }
  const { rows } = await query<{ status: string }>("SELECT status FROM security_alerts WHERE id = $1", [id]);
  if (!rows[0]) {
    res.status(404).json({ ok: false, error: "Alert not found" });
    return;
  }
  await query(
    "UPDATE security_alerts SET status = 'resolved', resolved_by = $1, resolved_at = NOW() WHERE id = $2",
    [req.user!.id, id]
  );
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "alert_resolved", resourceType: "alert", resourceId: id, status: "success", ip: req.ip });
  res.json({ ok: true });
});
