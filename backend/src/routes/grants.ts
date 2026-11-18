import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const grantsRouter = Router();

grantsRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const sql = user.role === "admin"
    ? "SELECT * FROM grants ORDER BY created_at DESC"
    : "SELECT * FROM grants WHERE owner_id = $1 ORDER BY created_at DESC";
  const { rows } = await query(sql, user.role === "admin" ? [] : [user.id]);
  res.json({ ok: true, grants: rows });
});

grantsRouter.post("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { title, funder, amount, currency, status, deadline, lead_researcher, description } = req.body || {};
  if (!title || !funder) { res.status(400).json({ ok: false, error: "title and funder required" }); return; }
  const { rows } = await query(
    `INSERT INTO grants (owner_id, title, funder, amount, currency, status, deadline, lead_researcher, description)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [user.id, title, funder, amount || 0, currency || "KES", status || "pending", deadline || null, lead_researcher || null, description || null]
  );
  res.status(201).json({ ok: true, grant: rows[0] });
});

grantsRouter.delete("/:id", authenticate, async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  const user = req.user!;
  const { rows } = await query("SELECT owner_id FROM grants WHERE id = $1", [id]);
  if (!rows[0]) { res.status(404).json({ ok: false, error: "Not found" }); return; }
  if (user.role !== "admin" && rows[0].owner_id !== user.id) { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  await query("DELETE FROM grants WHERE id = $1", [id]);
  res.json({ ok: true });
});
