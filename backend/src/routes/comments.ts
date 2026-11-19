import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { checkFileAccess } from "../utils/fileAccess.js";

export const commentsRouter = Router();

commentsRouter.get("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  if (!Number.isInteger(fileId) || fileId <= 0) { res.status(400).json({ ok: false, error: "Invalid file id" }); return; }
  const access = await checkFileAccess(req.user!, fileId);
  if (access === "notfound") { res.status(404).json({ ok: false, error: "File not found" }); return; }
  if (access === "forbidden") { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  const { rows } = await query(
    "SELECT c.*, u.username, u.full_name FROM file_comments c JOIN users u ON u.id = c.user_id WHERE c.file_id = $1 ORDER BY c.created_at DESC",
    [fileId]
  );
  res.json({ ok: true, comments: rows });
});

commentsRouter.post("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  const user = req.user!;
  if (!Number.isInteger(fileId) || fileId <= 0) { res.status(400).json({ ok: false, error: "Invalid file id" }); return; }
  const { body } = req.body || {};
  if (typeof body !== "string" || body.trim().length === 0) { res.status(400).json({ ok: false, error: "body required" }); return; }
  if (body.length > 2000) { res.status(400).json({ ok: false, error: "Comment too long (max 2000 chars)" }); return; }
  const access = await checkFileAccess(user, fileId);
  if (access === "notfound") { res.status(404).json({ ok: false, error: "File not found" }); return; }
  if (access === "forbidden") { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  const { rows } = await query(
    "INSERT INTO file_comments (file_id, user_id, body) VALUES ($1,$2,$3) RETURNING *",
    [fileId, user.id, body.trim()]
  );
  res.status(201).json({ ok: true, comment: rows[0] });
});