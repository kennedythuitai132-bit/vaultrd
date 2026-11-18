import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const versionsRouter = Router();

versionsRouter.get("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  const { rows } = await query(
    "SELECT fv.*, u.username AS uploader FROM file_versions fv LEFT JOIN users u ON u.id = fv.uploaded_by WHERE fv.file_id = $1 ORDER BY fv.version_number DESC",
    [fileId]
  );
  res.json({ ok: true, versions: rows });
});
