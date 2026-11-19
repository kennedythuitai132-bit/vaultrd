import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { getUserDepartmentIds, resolveDepartment } from "../utils/departments.js";

export const grantsRouter = Router();

// GET /api/grants - admin sees all, others see grants in their departments
grantsRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const base = "SELECT g.*, d.name AS department_name FROM grants g LEFT JOIN departments d ON d.id = g.department_id";
  if (user.role === "admin") {
    const { rows } = await query(base + " ORDER BY g.created_at DESC");
    res.json({ ok: true, grants: rows });
    return;
  }
  const deptIds = await getUserDepartmentIds(user.id);
  const { rows } = await query(
    base + " WHERE ((g.department_id IS NULL AND g.owner_id = $1) OR g.department_id = ANY($2::bigint[])) ORDER BY g.created_at DESC",
    [user.id, deptIds]
  );
  res.json({ ok: true, grants: rows });
});

grantsRouter.post("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { title, funder, amount, currency, status, deadline, lead_researcher, description, department_id } = req.body || {};
  if (!title || !funder) { res.status(400).json({ ok: false, error: "title and funder required" }); return; }
  const dept = await resolveDepartment(user, department_id);
  if (!dept.ok) { res.status(dept.status).json({ ok: false, error: dept.error }); return; }
  const { rows } = await query(
    `INSERT INTO grants (owner_id, title, funder, amount, currency, status, deadline, lead_researcher, description, department_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [user.id, title, funder, amount || 0, currency || "KES", status || "pending", deadline || null, lead_researcher || null, description || null, dept.departmentId]
  );
  res.status(201).json({ ok: true, grant: rows[0] });
});

grantsRouter.delete("/:id", authenticate, async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const user = req.user!;
  const { rows } = await query("SELECT owner_id FROM grants WHERE id = $1", [id]);
  if (!rows[0]) { res.status(404).json({ ok: false, error: "Not found" }); return; }
  if (user.role !== "admin" && Number(rows[0].owner_id) !== user.id) { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  await query("DELETE FROM grants WHERE id = $1", [id]);
  res.json({ ok: true });
});