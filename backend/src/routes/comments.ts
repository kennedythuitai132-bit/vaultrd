import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const commentsRouter = Router();

commentsRouter.get("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  const { rows } = await query(
    "SELECT c.*, u.username, u.full_name FROM file_comments c JOIN users u ON u.id = c.user_id WHERE c.file_id = $1 ORDER BY c.created_at DESC",
    [fileId]
  );
  res.json({ ok: true, comments: rows });
});

commentsRouter.post("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  const user = req.user!;
  const { body } = req.body || {};
  if (!body || body.trim().length === 0) { res.status(400).json({ ok: false, error: "body required" }); return; }
  const { rows } = await query(
    "INSERT INTO file_comments (file_id, user_id, body) VALUES ($1,$2,$3) RETURNING *",
    [fileId, user.id, body.trim()]
  );
  res.status(201).json({ ok: true, comment: rows[0] });
});
