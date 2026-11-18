import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const notificationsRouter = Router();

notificationsRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { rows } = await query(
    "SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100",
    [user.id]
  );
  const { rows: cnt } = await query<{ n: string }>(
    "SELECT COUNT(*)::text AS n FROM notifications WHERE user_id = $1 AND is_read = FALSE",
    [user.id]
  );
  res.json({ ok: true, notifications: rows, unread: Number(cnt[0]?.n || 0) });
});

notificationsRouter.patch("/:id/read", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  await query("UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2", [Number(req.params.id), user.id]);
  res.json({ ok: true });
});

notificationsRouter.post("/read-all", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  await query("UPDATE notifications SET is_read = TRUE WHERE user_id = $1", [user.id]);
  res.json({ ok: true });
});
