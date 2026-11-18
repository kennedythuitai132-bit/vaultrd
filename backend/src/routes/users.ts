import { Router, type Request, type Response } from "express";
import bcrypt from "bcrypt";
import { query } from "../config/db.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import type { Role } from "../types/index.js";

export const usersRouter = Router();

// GET /api/users — list (admin only)
usersRouter.get("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { rows } = await query(
    "SELECT id, username, email, full_name, role, is_active, is_approved, last_login_at, created_at FROM users ORDER BY id ASC"
  );
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_updated", status: "success", ip: req.ip, details: { list: true } });
  res.json({ ok: true, users: rows });
});

// POST /api/users — create (admin only)
usersRouter.post("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { username, email, full_name, role, password } = (req.body ?? {}) as {
    username?: string; email?: string; full_name?: string; role?: Role; password?: string;
  };
  if (!username || !email || !full_name || !role || !password) {
    res.status(400).json({ ok: false, error: "username, email, full_name, role, password required" });
    return;
  }
  if (!["admin", "researcher", "viewer"].includes(role)) {
    res.status(400).json({ ok: false, error: "Invalid role" });
    return;
  }
  if (password.length < 8) {
    res.status(400).json({ ok: false, error: "Password must be >= 8 chars" });
    return;
  }
  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await query<{ id: number }>(
      `INSERT INTO users (username, email, full_name, password_hash, role, is_active)
       VALUES ($1, $2, $3, $4, $5, TRUE) RETURNING id`,
      [username, email, full_name, hash, role]
    );
    const created = rows[0];
    if (!created) {
      res.status(500).json({ ok: false, error: "Failed to create user" });
      return;
    }
    await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_created", resourceType: "user", resourceId: created.id, status: "success", ip: req.ip, details: { new_username: username, role } });
    res.status(201).json({ ok: true, id: created.id });
  } catch (err) {
    res.status(400).json({ ok: false, error: "Create failed (duplicate username/email?)", detail: String(err) });
  }
});

// PATCH /api/users/:id/approve — approve a pending signup (admin only)
usersRouter.patch("/:id/approve", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }
  const { rows } = await query<{ username: string }>("SELECT username FROM users WHERE id = $1", [id]);
  const target = rows[0];
  if (!target) { res.status(404).json({ ok: false, error: "User not found" }); return; }
  await query("UPDATE users SET is_approved = TRUE WHERE id = $1", [id]);
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "signup_approved", resourceType: "user", resourceId: id, status: "success", ip: req.ip, details: { approved: target.username } });
  res.json({ ok: true });
});
// PATCH /api/users/:id — activate/deactivate or change role (admin only)
usersRouter.patch("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }
  const { is_active, role } = (req.body ?? {}) as { is_active?: boolean; role?: Role };
  if (is_active === undefined && role === undefined) {
    res.status(400).json({ ok: false, error: "is_active or role required" });
    return;
  }
  if (role !== undefined && !["admin", "researcher", "viewer"].includes(role)) {
    res.status(400).json({ ok: false, error: "Invalid role" });
    return;
  }
  if (id === req.user!.id && is_active === false) {
    res.status(400).json({ ok: false, error: "Cannot deactivate yourself" });
    return;
  }
  const sets: string[] = [];
  const params: unknown[] = [];
  let p = 1;
  if (is_active !== undefined) { sets.push("is_active = $" + p++); params.push(is_active); }
  if (role !== undefined) { sets.push("role = $" + p++); params.push(role); }
  params.push(id);
  await query("UPDATE users SET " + sets.join(", ") + " WHERE id = $" + p, params);
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_updated", resourceType: "user", resourceId: id, status: "success", ip: req.ip, details: { is_active, role } });
  res.json({ ok: true });
});
