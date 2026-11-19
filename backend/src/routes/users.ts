import { Router, type Request, type Response } from "express";
import bcrypt from "bcrypt";
import { query } from "../config/db.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import type { Role } from "../types/index.js";

export const usersRouter = Router();

// GET /api/users - list with departments (admin only)
usersRouter.get("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { rows } = await query(`
    SELECT u.id, u.username, u.email, u.full_name, u.role, u.is_active, u.is_approved,
           u.last_login_at, u.created_at,
           COALESCE(json_agg(json_build_object('id', d.id, 'name', d.name, 'code', d.code))
                    FILTER (WHERE d.id IS NOT NULL), '[]') AS departments
    FROM users u
    LEFT JOIN user_departments ud ON ud.user_id = u.id
    LEFT JOIN departments d ON d.id = ud.department_id
    GROUP BY u.id
    ORDER BY u.id ASC
  `);
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_updated", status: "success", ip: req.ip, details: { list: true } });
  res.json({ ok: true, users: rows });
});

// POST /api/users - create (admin only). department_id required for researcher/viewer.
usersRouter.post("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { username, email, full_name, role, password, department_id } = (req.body ?? {}) as {
    username?: string; email?: string; full_name?: string; role?: Role; password?: string; department_id?: number | string | null;
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
  const deptId = department_id ? Number(department_id) : null;
  if (role !== "admin" && !deptId) {
    res.status(400).json({ ok: false, error: "Please assign a department to this user" });
    return;
  }
  if (deptId) {
    const d = await query("SELECT id FROM departments WHERE id = $1", [deptId]);
    if (!d.rows[0]) { res.status(400).json({ ok: false, error: "Department not found" }); return; }
  }
  const hash = await bcrypt.hash(password, 12);
  let createdId: number | null = null;
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
    createdId = created.id;
    if (deptId) {
      await query(
        "INSERT INTO user_departments (user_id, department_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        [created.id, deptId]
      );
    }
    createdId = null; // everything succeeded, nothing to roll back
    await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_created", resourceType: "user", resourceId: created.id, status: "success", ip: req.ip, details: { new_username: username, role, department_id: deptId } });
    res.status(201).json({ ok: true, id: created.id });
  } catch (err) {
    if (createdId) { await query("DELETE FROM users WHERE id = $1", [createdId]).catch(() => undefined); }
    res.status(400).json({ ok: false, error: "Create failed (duplicate username/email?)", detail: String(err) });
  }
});

// PATCH /api/users/:id/approve
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

// PATCH /api/users/:id - activate/deactivate, change role, reassign department
usersRouter.patch("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }
  const { is_active, role, department_id } = (req.body ?? {}) as { is_active?: boolean; role?: Role; department_id?: number | string };
  if (is_active === undefined && role === undefined && department_id === undefined) {
    res.status(400).json({ ok: false, error: "is_active, role or department_id required" });
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
  let deptId: number | null = null;
  if (department_id !== undefined) {
    deptId = Number(department_id);
    if (!Number.isInteger(deptId) || deptId <= 0) { res.status(400).json({ ok: false, error: "Invalid department_id" }); return; }
    const d = await query("SELECT id FROM departments WHERE id = $1", [deptId]);
    if (!d.rows[0]) { res.status(400).json({ ok: false, error: "Department not found" }); return; }
  }
  const sets: string[] = [];
  const params: unknown[] = [];
  let p = 1;
  if (is_active !== undefined) { sets.push("is_active = $" + p++); params.push(is_active); }
  if (role !== undefined) { sets.push("role = $" + p++); params.push(role); }
  if (sets.length) {
    params.push(id);
    await query("UPDATE users SET " + sets.join(", ") + " WHERE id = $" + p, params);
  }
  if (deptId !== null) {
    // keep memberships for departments this user heads, replace the rest
    await query(
      "DELETE FROM user_departments WHERE user_id = $1 AND department_id NOT IN (SELECT id FROM departments WHERE head_user_id = $1)",
      [id]
    );
    await query("INSERT INTO user_departments (user_id, department_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [id, deptId]);
  }
  await writeAudit({ userId: req.user!.id, username: req.user!.username, action: "user_updated", resourceType: "user", resourceId: id, status: "success", ip: req.ip, details: { is_active, role, department_id } });
  res.json({ ok: true });
});