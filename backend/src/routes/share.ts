import { Router, type Request, type Response } from "express";
import crypto from "node:crypto";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";
import { downloadFromBucket } from "../utils/supabase.js";
import { decryptBuffer } from "../utils/crypto.js";

export const shareRouter = Router();

// Authenticated: create a share link (file owner or admin)
shareRouter.post("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { file_id, hours } = req.body || {};
  const fileId = Number(file_id);
  if (!Number.isInteger(fileId) || fileId <= 0) { res.status(400).json({ ok: false, error: "file_id required" }); return; }
  const fileRow = await query("SELECT * FROM research_files WHERE id = $1 AND is_deleted = FALSE", [fileId]);
  if (!fileRow.rows[0]) { res.status(404).json({ ok: false, error: "File not found" }); return; }
  const f = fileRow.rows[0];
  if (user.role !== "admin" && Number(f.owner_id) !== user.id) { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  const token = crypto.randomBytes(32).toString("hex");
  const h = Math.min(Math.max(Number(hours) || 24, 1), 168); // 1 hour to 7 days
  const expiresAt = new Date(Date.now() + h * 3600 * 1000).toISOString();
  await query(
    "INSERT INTO share_links (file_id, token, created_by, expires_at) VALUES ($1,$2,$3,$4)",
    [fileId, token, user.id, expiresAt]
  );
  res.status(201).json({ ok: true, token, expires_at: expiresAt, url: "/api/share/" + token });
});

// List links: admin sees all, others see their own
shareRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const sql = user.role === "admin"
    ? "SELECT sl.*, rf.title FROM share_links sl JOIN research_files rf ON rf.id = sl.file_id ORDER BY sl.created_at DESC LIMIT 100"
    : "SELECT sl.*, rf.title FROM share_links sl JOIN research_files rf ON rf.id = sl.file_id WHERE sl.created_by = $1 ORDER BY sl.created_at DESC LIMIT 100";
  const { rows } = await query(sql, user.role === "admin" ? [] : [user.id]);
  res.json({ ok: true, links: rows });
});

// Revoke: only the creator or an admin (previously any logged-in user could revoke any link)
shareRouter.delete("/:id", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) { res.status(400).json({ ok: false, error: "Invalid id" }); return; }
  const { rows } = await query("SELECT created_by FROM share_links WHERE id = $1", [id]);
  if (!rows[0]) { res.status(404).json({ ok: false, error: "Link not found" }); return; }
  if (user.role !== "admin" && Number(rows[0].created_by) !== user.id) { res.status(403).json({ ok: false, error: "Forbidden" }); return; }
  await query("UPDATE share_links SET is_revoked = TRUE WHERE id = $1", [id]);
  res.json({ ok: true });
});

// Public: download via share token (no auth)
shareRouter.get("/:token", async (req: Request, res: Response) => {
  const { rows } = await query(
    `SELECT sl.*, rf.storage_path, rf.mime_type, rf.original_name, rf.iv, rf.auth_tag, rf.checksum_sha256
     FROM share_links sl JOIN research_files rf ON rf.id = sl.file_id
     WHERE sl.token = $1 AND rf.is_deleted = FALSE`,
    [req.params.token]
  );
  const link = rows[0];
  if (!link || link.is_revoked) { res.status(404).json({ ok: false, error: "Link not found" }); return; }
  if (new Date(link.expires_at) < new Date()) { res.status(410).json({ ok: false, error: "Link expired" }); return; }
  try {
    const ciphertext = await downloadFromBucket(link.storage_path);
    const plaintext = decryptBuffer({ ciphertext, iv: link.iv, authTag: link.auth_tag });
    await query("UPDATE share_links SET download_count = download_count + 1 WHERE id = $1", [link.id]);
    res.setHeader("Content-Type", link.mime_type);
    res.setHeader("Content-Disposition", `attachment; filename="${link.original_name.replace(/"/g, "")}"`);
    res.setHeader("Content-Length", String(plaintext.length));
    res.send(plaintext);
  } catch (e) { res.status(500).json({ ok: false, error: "Download failed" }); }
});