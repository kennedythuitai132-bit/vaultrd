import { Router, type Request, type Response } from "express";
import multer from "multer";
import { query } from "../config/db.js";
import { encryptBuffer, decryptBuffer, sha256Hex } from "../utils/crypto.js";
import { uploadToBucket, downloadFromBucket, deleteFromBucket } from "../utils/supabase.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import type { ResearchFile } from "../types/index.js";

export const filesRouter = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// POST /api/files — upload + encrypt (researcher + admin)
filesRouter.post(
  "/",
  authenticate,
  requireRole("admin", "researcher"),
  upload.single("file"),
  async (req: Request, res: Response) => {
    const user = req.user!;
    const file = req.file;
    const { title, project_code, description } = (req.body ?? {}) as {
      title?: string;
      project_code?: string;
      description?: string;
    };
    const ip = req.ip;
    const ua = req.headers["user-agent"];

    if (!file) {
      res.status(400).json({ ok: false, error: "file required (form field name: file)" });
      return;
    }
    if (!title || !project_code) {
      res.status(400).json({ ok: false, error: "title and project_code required" });
      return;
    }

    const original = file.buffer;
    const checksum = sha256Hex(original);
    const enc = encryptBuffer(original);
    const storagePath = user.id + "/" + Date.now() + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");

    try {
      await uploadToBucket(storagePath, enc.ciphertext, "application/octet-stream");
    } catch (err) {
      await writeAudit({ userId: user.id, username: user.username, action: "file_uploaded", status: "failure", ip, userAgent: ua, details: { error: String(err) } });
      res.status(500).json({ ok: false, error: "Storage upload failed" });
      return;
    }

    const { rows } = await query<ResearchFile>(
      `INSERT INTO research_files
        (owner_id, title, project_code, description, original_name, mime_type, size_bytes, storage_path, checksum_sha256, iv, auth_tag)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, owner_id, title, project_code, description, original_name, mime_type, size_bytes, storage_path, checksum_sha256, is_deleted, created_at, updated_at`,
      [
        user.id,
        title,
        project_code,
        description ?? null,
        file.originalname,
        file.mimetype,
        original.length,
        storagePath,
        checksum,
        enc.iv,
        enc.authTag,
      ]
    );

    const created = rows[0];
    if (!created) {
      res.status(500).json({ ok: false, error: "Failed to save file metadata" });
      return;
    }
    await writeAudit({
      userId: user.id,
      username: user.username,
      action: "file_uploaded",
      resourceType: "file",
      resourceId: created.id,
      status: "success",
      ip,
      userAgent: ua,
      details: { title, project_code, size: original.length, checksum },
    });

    res.status(201).json({ ok: true, file: created });
  }
);

// GET /api/files — role-filtered list
filesRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  let sql = "SELECT * FROM research_files WHERE is_deleted = FALSE";
  const params: unknown[] = [];

  if (user.role !== "admin") {
    sql += " AND owner_id = $1";
    params.push(user.id);
  }
  sql += " ORDER BY created_at DESC LIMIT 200";

  const { rows } = await query<ResearchFile & { owner_username?: string }>(sql, params);

  await writeAudit({ userId: user.id, username: user.username, action: "file_listed", resourceType: "file", status: "success", ip, userAgent: ua, details: { count: rows.length, role: user.role } });
  res.json({ ok: true, files: rows });
});

// GET /api/files/:id/download — authz + decrypt
filesRouter.get("/:id/download", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const id = Number(req.params.id);
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }

  const { rows } = await query<ResearchFile & { iv: string; auth_tag: string }>(
    "SELECT * FROM research_files WHERE id = $1 AND is_deleted = FALSE",
    [id]
  );
  const f = rows[0];
  if (!f) {
    res.status(404).json({ ok: false, error: "File not found" });
    return;
  }
  if (user.role !== "admin" && f.owner_id !== user.id) {
    await writeAudit({ userId: user.id, username: user.username, action: "file_downloaded", resourceType: "file", resourceId: id, status: "failure", ip, userAgent: ua, details: { reason: "forbidden" } });
    res.status(403).json({ ok: false, error: "Forbidden" });
    return;
  }

  try {
    const ciphertext = await downloadFromBucket(f.storage_path);
    const plaintext = decryptBuffer({ ciphertext, iv: f.iv, authTag: f.auth_tag });
    const checksumOk = sha256Hex(plaintext) === f.checksum_sha256;

    await writeAudit({
      userId: user.id,
      username: user.username,
      action: "file_downloaded",
      resourceType: "file",
      resourceId: id,
      status: "success",
      ip,
      userAgent: ua,
      details: { checksum_ok: checksumOk, size: plaintext.length },
    });

    res.setHeader("Content-Type", f.mime_type);
    res.setHeader("Content-Disposition", 'attachment; filename="' + f.original_name.replace(/"/g, "") + '"');
    res.setHeader("Content-Length", String(plaintext.length));
    res.send(plaintext);
  } catch (err) {
    await writeAudit({ userId: user.id, username: user.username, action: "file_downloaded", resourceType: "file", resourceId: id, status: "failure", ip, userAgent: ua, details: { error: String(err) } });
    res.status(500).json({ ok: false, error: "Download failed" });
  }
});

// DELETE /api/files/:id — soft delete (owner or admin)
filesRouter.delete("/:id", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const id = Number(req.params.id);
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }

  const { rows } = await query<ResearchFile>("SELECT * FROM research_files WHERE id = $1 AND is_deleted = FALSE", [id]);
  const f = rows[0];
  if (!f) {
    res.status(404).json({ ok: false, error: "File not found" });
    return;
  }
  if (user.role !== "admin" && f.owner_id !== user.id) {
    res.status(403).json({ ok: false, error: "Forbidden" });
    return;
  }

  try { await deleteFromBucket(f.storage_path); } catch { /* soft-delete tolerant */ }
  await query("UPDATE research_files SET is_deleted = TRUE WHERE id = $1", [id]);
  await writeAudit({ userId: user.id, username: user.username, action: "file_deleted", resourceType: "file", resourceId: id, status: "success", ip, userAgent: ua });
  res.json({ ok: true });
});
