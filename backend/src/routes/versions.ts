import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { checkFileAccess } from "../utils/fileAccess.js";

export const versionsRouter = Router();

versionsRouter.get("/:fileId", authenticate, async (req: Request, res: Response) => {
  const fileId = Number(req.params.fileId);
  if (!Number.isInteger(fileId) || fileId <= 0) { res.status(400).json({ ok: false, error: "Invalid file id" }); return; }
  const access = await checkFileAccess(req.user!, fileId);
  if (access === "notfound") { res.status(404).json({ ok: false, error: "File not found" }); return; }
  if (access === "forbidden") { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  const { rows } = await query(
    "SELECT fv.*, u.username AS uploader FROM file_versions fv LEFT JOIN users u ON u.id = fv.uploaded_by WHERE fv.file_id = $1 ORDER BY fv.version_number DESC",
    [fileId]
  );
  res.json({ ok: true, versions: rows });
});