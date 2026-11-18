import { Router, type Request, type Response } from "express";
import bcrypt from "bcrypt";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { writeAudit } from "../utils/audit.js";

export const settingsRouter = Router();

settingsRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  let { rows } = await query("SELECT * FROM user_settings WHERE user_id = $1", [user.id]);
  if (!rows[0]) {
    await query("INSERT INTO user_settings (user_id) VALUES ($1)", [user.id]);
    ({ rows } = await query("SELECT * FROM user_settings WHERE user_id = $1", [user.id]));
  }
  res.json({ ok: true, settings: rows[0] });
});

settingsRouter.patch("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { theme, email_notifications, security_alerts } = req.body || {};
  await query(
    "UPDATE user_settings SET theme = COALESCE($1,theme), email_notifications = COALESCE($2,email_notifications), security_alerts = COALESCE($3,security_alerts), updated_at = NOW() WHERE user_id = $4",
    [theme || null, email_notifications, security_alerts, user.id]
  );
  res.json({ ok: true });
});

settingsRouter.patch("/profile", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { full_name, email } = req.body || {};
  await query("UPDATE users SET full_name = COALESCE($1,full_name), email = COALESCE($2,email) WHERE id = $3", [full_name || null, email || null, user.id]);
  res.json({ ok: true });
});

settingsRouter.patch("/password", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) { res.status(400).json({ ok: false, error: "current and new password required" }); return; }
  if (new_password.length < 8) { res.status(400).json({ ok: false, error: "Password must be 8+ chars" }); return; }
  const { rows } = await query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [user.id]);
  const row = rows[0];
  if (!row) { res.status(404).json({ ok: false, error: "User not found" }); return; }
  const ok = await bcrypt.compare(current_password, row.password_hash);
  if (!ok) { res.status(401).json({ ok: false, error: "Current password is incorrect" }); return; }
  const hash = await bcrypt.hash(new_password, 12);
  await query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, user.id]);
  await writeAudit({ userId: user.id, username: user.username, action: "logout", status: "success", ip: req.ip, details: { action: "password_changed" } });
  res.json({ ok: true });
});
