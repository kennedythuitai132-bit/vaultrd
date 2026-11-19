import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { getUserDepartmentIds } from "../utils/departments.js";

export const catalogueRouter = Router();

// GET /api/catalogue - admin sees all, others see only items in their departments (plus their own)
catalogueRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { q, dept } = req.query as { q?: string; dept?: string };
  let sql = `SELECT rc.*, d.name AS department_name, u.username AS publisher
             FROM research_catalogue rc
             LEFT JOIN departments d ON d.id = rc.department_id
             LEFT JOIN users u ON u.id = rc.published_by
             WHERE rc.is_published = TRUE`;
  const params: unknown[] = [];
  let p = 1;

  if (user.role !== "admin") {
    const deptIds = await getUserDepartmentIds(user.id);
    sql += ` AND (rc.department_id = ANY($${p}::bigint[]) OR rc.published_by = $${p + 1})`;
    params.push(deptIds, user.id);
    p += 2;
  }
  if (q) {
    sql += ` AND (rc.title ILIKE $${p} OR rc.abstract ILIKE $${p} OR rc.keywords ILIKE $${p})`;
    params.push("%" + q + "%");
    p++;
  }
  if (dept && Number.isInteger(Number(dept))) {
    sql += ` AND rc.department_id = $${p}`;
    params.push(Number(dept));
    p++;
  }
  sql += " ORDER BY rc.created_at DESC LIMIT 200";
  const { rows } = await query(sql, params);
  res.json({ ok: true, items: rows });
});

// POST /api/catalogue/publish/:fileId - owner or admin; item inherits the file's department
catalogueRouter.post("/publish/:fileId", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const fileId = Number(req.params.fileId);
  if (!Number.isInteger(fileId) || fileId <= 0) { res.status(400).json({ ok: false, error: "Invalid file id" }); return; }
  const { title, abstract, keywords, department_id } = req.body || {};

  const { rows: fr } = await query<{ title: string; owner_id: number | string; department_id: number | string | null }>(
    "SELECT title, owner_id, department_id FROM research_files WHERE id = $1 AND is_deleted = FALSE",
    [fileId]
  );
  const f = fr[0];
  if (!f || (user.role !== "admin" && Number(f.owner_id) !== user.id)) {
    res.status(404).json({ ok: false, error: "File not found or not yours" });
    return;
  }

  let deptId: number | null = f.department_id !== null && f.department_id !== undefined ? Number(f.department_id) : null;
  if (user.role === "admin" && department_id) {
    const d = await query("SELECT id FROM departments WHERE id = $1", [Number(department_id)]);
    if (!d.rows[0]) { res.status(400).json({ ok: false, error: "Department not found" }); return; }
    deptId = Number(department_id);
  }

  const { rows } = await query(
    `INSERT INTO research_catalogue (file_id, published_by, title, abstract, keywords, department_id)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [fileId, user.id, title || f.title, abstract || null, keywords || null, deptId]
  );
  await query("UPDATE research_files SET is_published = TRUE WHERE id = $1", [fileId]);
  res.status(201).json({ ok: true, item: rows[0] });
});