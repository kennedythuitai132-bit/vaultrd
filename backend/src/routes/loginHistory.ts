import { Router, type Request, type Response } from "express";
import { query } from "../config/db.js";
import { authenticate } from "../middleware/auth.js";

export const loginHistoryRouter = Router();

loginHistoryRouter.get("/", authenticate, async (req: Request, res: Response) => {
  const user = req.user!;
  const { rows } = await query(
    "SELECT * FROM login_history WHERE user_id = $1 ORDER BY logged_in_at DESC LIMIT 50",
    [user.id]
  );
  res.json({ ok: true, history: rows });
});
