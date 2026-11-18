import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";

export const departmentsRouter = Router();

departmentsRouter.get("/", authenticate, async (_req: Request, res: Response) => {
  const { rows } = await query(`
    SELECT d.*, u.username AS head_username,
      (SELECT COUNT(*)::int FROM user_departments ud WHERE ud.department_id = d.id) AS member_count
    FROM departments d
    LEFT JOIN users u ON u.id = d.head_user_id
    ORDER BY d.name ASC
  `);
  res.json({ ok: true, departments: rows });
});

departmentsRouter.post("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { name, code, head_user_id, description } = req.body || {};
  if (!name) { res.status(400).json({ ok: false, error: "name required" }); return; }
  try {
    const { rows } = await query(
      "INSERT INTO departments (name, code, head_user_id, description) VALUES ($1,$2,$3,$4) RETURNING *",
      [name, code || null, head_user_id || null, description || null]
    );
    res.status(201).json({ ok: true, department: rows[0] });
  } catch (e) { res.status(400).json({ ok: false, error: "Duplicate name or invalid data" }); }
});

departmentsRouter.patch("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const { name, code, head_user_id, description } = req.body || {};
  await query(
    "UPDATE departments SET name = COALESCE($1,name), code = COALESCE($2,code), head_user_id = COALESCE($3,head_user_id), description = COALESCE($4,description) WHERE id = $5",
    [name || null, code || null, head_user_id || null, description || null, id]
  );
  res.json({ ok: true });
});

departmentsRouter.delete("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  await query("DELETE FROM departments WHERE id = $1", [Number(req.params.id)]);
  res.json({ ok: true });
});
