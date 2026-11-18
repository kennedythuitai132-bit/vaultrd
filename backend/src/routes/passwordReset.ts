import { Router, type Request, type Response } from "express";
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { query } from "../config/db.js";

export const passwordResetRouter = Router();

// Request a reset (returns token — in production, email it)
passwordResetRouter.post("/request", async (req: Request, res: Response) => {
  const { email } = req.body || {};
  if (!email) { res.status(400).json({ ok: false, error: "email required" }); return; }
  const { rows } = await query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [email]);
  if (!rows[0]) { res.json({ ok: true, message: "If that email exists, a reset link was generated" }); return; }
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
  await query("INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1,$2,$3)", [rows[0].id, token, expiresAt]);
  // In production: send email. For demo, return token directly:
  console.log("[password-reset] token for " + email + ": " + token);
  res.json({ ok: true, token, expires_at: expiresAt, message: "Reset token generated (check server console for demo)" });
});

// Complete reset
passwordResetRouter.post("/confirm", async (req: Request, res: Response) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) { res.status(400).json({ ok: false, error: "token and new_password required" }); return; }
  if (new_password.length < 8) { res.status(400).json({ ok: false, error: "Password must be 8+ chars" }); return; }
  const { rows } = await query(
    "SELECT * FROM password_resets WHERE token = $1 AND used = FALSE AND expires_at > NOW()",
    [token]
  );
  if (!rows[0]) { res.status(400).json({ ok: false, error: "Invalid or expired token" }); return; }
  const hash = await bcrypt.hash(new_password, 12);
  await query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, rows[0].user_id]);
  await query("UPDATE password_resets SET used = TRUE WHERE id = $1", [rows[0].id]);
  res.json({ ok: true, message: "Password updated. You can now sign in." });
});
