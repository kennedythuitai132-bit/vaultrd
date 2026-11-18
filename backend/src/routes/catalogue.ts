import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const catalogueRouter = Router();

catalogueRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const { q, dept } = req.query as { q?: string; dept?: string };
  let sql = `SELECT rc.*, d.name AS department_name, u.username AS publisher
             FROM research_catalogue rc
             LEFT JOIN departments d ON d.id = rc.department_id
             LEFT JOIN users u ON u.id = rc.published_by
             WHERE rc.is_published = TRUE`;
  const params: unknown[] = [];
  let p = 1;
  if (q) { sql += ` AND (rc.title ILIKE $${p} OR rc.abstract ILIKE $${p} OR rc.keywords ILIKE $${p})`; params.push("%" + q + "%"); p++; }
  if (dept) { sql += ` AND rc.department_id = $${p}`; params.push(Number(dept)); }
  sql += " ORDER BY rc.created_at DESC LIMIT 200";
  const { rows } = await query(sql, params);
  res.json({ ok: true, items: rows });
});

catalogueRouter.post("/publish/:fileId", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const fileId = Number(req.params.fileId);
  const { title, abstract, keywords, department_id } = req.body || {};
  const { rows: fr } = await query("SELECT title FROM research_files WHERE id = $1 AND owner_id = $2", [fileId, user.id]);
  if (!fr[0]) { res.status(404).json({ ok: false, error: "File not found or not yours" }); return; }
  const { rows } = await query(
    `INSERT INTO research_catalogue (file_id, published_by, title, abstract, keywords, department_id)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [fileId, user.id, title || fr[0].title, abstract || null, keywords || null, department_id || null]
  );
  await query("UPDATE research_files SET is_published = TRUE WHERE id = $1", [fileId]);
  res.status(201).json({ ok: true, item: rows[0] });
});
