import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import { getUserDepartmentIds } from "../utils/departments.js";

export const departmentsRouter = Router();

// GET /api/departments - admin sees all, others see only their own departments
departmentsRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  let where = "";
  const params: unknown[] = [];
  if (user.role !== "admin") {
    const ids = await getUserDepartmentIds(user.id);
    where = "WHERE d.id = ANY($1::bigint[])";
    params.push(ids);
  }
  const { rows } = await query(
    `SELECT d.*, u.username AS head_username, u.full_name AS head_name,
       (SELECT COUNT(*)::int FROM user_departments ud WHERE ud.department_id = d.id) AS member_count
     FROM departments d
     LEFT JOIN users u ON u.id = d.head_user_id
     ${where}
     ORDER BY d.name ASC`,
    params
  );
  res.json({ ok: true, departments: rows });
});

// GET /api/departments/:id/members (admin)
departmentsRouter.get("/:id/members", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) { res.status(400).json({ ok: false, error: "Invalid id" }); return; }
  const { rows } = await query(
    `SELECT u.id, u.username, u.full_name, u.role
     FROM user_departments ud JOIN users u ON u.id = ud.user_id
     WHERE ud.department_id = $1 ORDER BY u.username`,
    [id]
  );
  res.json({ ok: true, members: rows });
});

// POST /api/departments - name, code and head are required; head becomes a member
departmentsRouter.post("/", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const { name, code, head_user_id, description } = req.body || {};
  const headId = Number(head_user_id);
  if (!name || !code || !Number.isInteger(headId) || headId <= 0) {
    res.status(400).json({ ok: false, error: "name, code and head_user_id are required" });
    return;
  }
  try {
    const head = await query("SELECT id FROM users WHERE id = $1", [headId]);
    if (!head.rows[0]) { res.status(400).json({ ok: false, error: "Head user not found" }); return; }
    const { rows } = await query(
      "INSERT INTO departments (name, code, head_user_id, description) VALUES ($1,$2,$3,$4) RETURNING *",
      [name, code, headId, description || null]
    );
    const dept = rows[0];
    await query(
      "INSERT INTO user_departments (user_id, department_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [headId, dept.id]
    );
    res.status(201).json({ ok: true, department: dept });
  } catch (e) {
    res.status(400).json({ ok: false, error: "Duplicate name or invalid data" });
  }
});

departmentsRouter.patch("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) { res.status(400).json({ ok: false, error: "Invalid id" }); return; }
  const { name, code, head_user_id, description } = req.body || {};
  await query(
    "UPDATE departments SET name = COALESCE($1,name), code = COALESCE($2,code), head_user_id = COALESCE($3,head_user_id), description = COALESCE($4,description) WHERE id = $5",
    [name || null, code || null, head_user_id || null, description || null, id]
  );
  if (head_user_id) {
    await query(
      "INSERT INTO user_departments (user_id, department_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [Number(head_user_id), id]
    );
  }
  res.json({ ok: true });
});

departmentsRouter.delete("/:id", authenticate, requireRole("admin"), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) { res.status(400).json({ ok: false, error: "Invalid id" }); return; }
  await query("DELETE FROM user_departments WHERE department_id = $1", [id]);
  await query("DELETE FROM departments WHERE id = $1", [id]);
  res.json({ ok: true });
});