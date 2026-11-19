import { Router, type Request, type Response } from "express";
import multer from "multer";
import { query } from "../config/db.js";
import { encryptBuffer, decryptBuffer, sha256Hex } from "../utils/crypto.js";
import { uploadToBucket, downloadFromBucket, deleteFromBucket } from "../utils/supabase.js";
import { writeAudit } from "../utils/audit.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import { getUserDepartmentIds, resolveDepartment } from "../utils/departments.js";
import type { ResearchFile } from "../types/index.js";

export const filesRouter = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

type FileRow = ResearchFile & { iv: string; auth_tag: string; department_id: number | string | null };

// admin: everything. others: files in their departments (files with no department stay owner-only).
function canAccess(role: string, userId: number, deptIds: number[], f: FileRow): boolean {
  if (role === "admin") return true;
  if (f.department_id !== null && f.department_id !== undefined) return deptIds.includes(Number(f.department_id));
  return Number(f.owner_id) === userId;
}

// POST /api/files - upload + encrypt (researcher + admin), stamped with a department
filesRouter.post(
  "/",
  authenticate,
  requireRole("admin", "researcher"),
  upload.single("file"),
  async (req: Request, res: Response) => {
    const user = req.user!;
    const file = req.file;
    const { title, project_code, description, department_id } = (req.body ?? {}) as {
      title?: string;
      project_code?: string;
      description?: string;
      department_id?: string;
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

    const dept = await resolveDepartment(user, department_id);
    if (!dept.ok) {
      res.status(dept.status).json({ ok: false, error: dept.error });
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
        (owner_id, title, project_code, description, original_name, mime_type, size_bytes, storage_path, checksum_sha256, iv, auth_tag, department_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING id, owner_id, department_id, title, project_code, description, original_name, mime_type, size_bytes, storage_path, checksum_sha256, is_deleted, created_at, updated_at`,
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
        dept.departmentId,
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
      details: { title, project_code, size: original.length, checksum, department_id: dept.departmentId },
    });

    res.status(201).json({ ok: true, file: created });
  }
);

// GET /api/files - department-filtered list
filesRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  let sql =
    `SELECT f.id, f.owner_id, f.department_id, f.title, f.project_code, f.description, f.original_name,
            f.mime_type, f.size_bytes, f.checksum_sha256, f.is_deleted, f.created_at, f.updated_at,
            d.name AS department_name, u.username AS owner_username
     FROM research_files f
     LEFT JOIN departments d ON d.id = f.department_id
     LEFT JOIN users u ON u.id = f.owner_id
     WHERE f.is_deleted = FALSE`;
  const params: unknown[] = [];

  if (user.role !== "admin") {
    const deptIds = await getUserDepartmentIds(user.id);
    sql += " AND ((f.department_id IS NULL AND f.owner_id = $1) OR f.department_id = ANY($2::bigint[]))";
    params.push(user.id, deptIds);
  }
  sql += " ORDER BY f.created_at DESC LIMIT 200";

  const { rows } = await query(sql, params);

  await writeAudit({ userId: user.id, username: user.username, action: "file_listed", resourceType: "file", status: "success", ip, userAgent: ua, details: { count: rows.length, role: user.role } });
  res.json({ ok: true, files: rows });
});

// GET /api/files/:id/download - authz + decrypt
filesRouter.get("/:id/download", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const id = Number(req.params.id);
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ ok: false, error: "Invalid id" });
    return;
  }

  const { rows } = await query<FileRow>(
    "SELECT * FROM research_files WHERE id = $1 AND is_deleted = FALSE",
    [id]
  );
  const f = rows[0];
  if (!f) {
    res.status(404).json({ ok: false, error: "File not found" });
    return;
  }
  const deptIds = user.role === "admin" ? [] : await getUserDepartmentIds(user.id);
  if (!canAccess(user.role, user.id, deptIds, f)) {
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

// DELETE /api/files/:id - soft delete (owner or admin)
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
  if (user.role !== "admin" && Number(f.owner_id) !== user.id) {
    res.status(403).json({ ok: false, error: "Forbidden" });
    return;
  }

  try { await deleteFromBucket(f.storage_path); } catch { /* soft-delete tolerant */ }
  await query("UPDATE research_files SET is_deleted = TRUE WHERE id = $1", [id]);
  await writeAudit({ userId: user.id, username: user.username, action: "file_deleted", resourceType: "file", resourceId: id, status: "success", ip, userAgent: ua });
  res.json({ ok: true });
});